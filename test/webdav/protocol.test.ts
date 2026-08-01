/**
 * The WebDAV wire, on its own: no driver, no socket, no session.
 *
 * Three kinds of fact live here, and they are checked against different
 * sources:
 *
 * - **RFC 4918's grammars** — `Depth`, `Overwrite`, `Destination`, `Timeout`,
 *   `Lock-Token`, the `If` header's disjunction-of-conjunctions, the three
 *   request bodies, and the response documents. The section is named at the
 *   assertion wherever the rule is not obvious from the shape.
 * - **The path mapping**, in both directions and round-tripped. This is the
 *   security-relevant half: a target that escapes the driver root, a segment
 *   holding an encoded separator, and a malformed escape each have a pinned
 *   answer.
 * - **Totality.** Every parser answers a `DavFault` or a value; none of them
 *   throw anything else, whatever they are given.
 *
 * Fixtures give every field a distinct value (`AGENTS.md`), and no literal
 * control character appears in this file.
 */

import { describe, expect, it } from "vitest";
import { statusLine, STATUS_TEXT, statusOf } from "../../src/webdav/constants.ts";
import { DavLockTable } from "../../src/webdav/locks.ts";
import {
  activeLockNode,
  collectBody,
  DavFault,
  encodeErrorDocument,
  encodeLockResponse,
  encodeMultistatus,
  faultResponse,
  formatLockToken,
  hrefOf,
  isDavFault,
  lockDiscoveryNode,
  parseDepth,
  parseDestination,
  parseIf,
  parseLockInfo,
  parseLockToken,
  parseOverwrite,
  parsePropfind,
  parseProppatch,
  parseTargetPath,
  parseTimeout,
  refuse,
  statusOfError,
  submittedTokens,
  supportedLockNode,
} from "../../src/webdav/protocol.ts";
import { xmlDocument } from "../../src/xml.ts";

/** The status a call refused with, or `undefined` if it did not refuse. */
function refusedWith(fn: () => unknown): number | undefined {
  try {
    fn();
  } catch (error) {
    return isDavFault(error) ? error.status : undefined;
  }
  return undefined;
}

const utf8 = (text: string): Uint8Array => Buffer.from(text, "utf8");

// ---------------------------------------------------------------------------
// paths and hrefs
// ---------------------------------------------------------------------------

describe("parseTargetPath", () => {
  it("decodes one segment at a time", () => {
    expect(parseTargetPath("/a%20b/c%C3%A9")).toBe("/a b/cé");
  });

  it("drops the query and the fragment", () => {
    expect(parseTargetPath("/a?b=c")).toBe("/a");
    expect(parseTargetPath("/a#b")).toBe("/a");
  });

  it("collapses empty segments and normalizes", () => {
    expect(parseTargetPath("//a//b/")).toBe("/a/b");
    expect(parseTargetPath("/")).toBe("/");
    expect(parseTargetPath("/a/./b")).toBe("/a/b");
  });

  it("clamps `..` at the root rather than escaping it", () => {
    /* `normalizePath`'s rule, and the reason there is no traversal check
       anywhere in the session: there is nothing above `/` to reach. */
    expect(parseTargetPath("/../etc/passwd")).toBe("/etc/passwd");
    expect(parseTargetPath("/%2e%2e/%2e%2e/etc")).toBe("/etc");
    expect(parseTargetPath("/a/../../b")).toBe("/b");
  });

  it("refuses an encoded separator rather than reading it as one", () => {
    /* The difference from the S3 gateway: an S3 key may contain a `/`, a POSIX
       name may not, so `%2F` is a resource this server does not have. */
    expect(refusedWith(() => parseTargetPath("/a%2Fb"))).toBe(400);
  });

  it("refuses a malformed escape, a NUL and a target that is not a path", () => {
    for (const target of ["/a%", "/a%zz", "/a%C3%28", "/a%00b", "a/b", "http://x/y", "*"]) {
      expect(
        refusedWith(() => parseTargetPath(target)),
        target,
      ).toBe(400);
    }
  });
});

describe("hrefOf", () => {
  it("encodes each segment and marks a collection with a trailing slash", () => {
    expect(hrefOf("/a b/c", false)).toBe("/a%20b/c");
    expect(hrefOf("/a b/c", true)).toBe("/a%20b/c/");
    expect(hrefOf("/", true)).toBe("/");
    expect(hrefOf("/", false)).toBe("/");
  });

  it("encodes the characters that would otherwise re-parse as syntax", () => {
    expect(hrefOf("/a?b", false)).toBe("/a%3Fb");
    expect(hrefOf("/a#b", false)).toBe("/a%23b");
    expect(hrefOf("/a%b", false)).toBe("/a%25b");
  });

  it("round-trips every name a driver can hold", () => {
    for (const name of ["plain", "a b", "café", "a?b", "a#b", "a%2Fb", "a;b", "a&b", "'"]) {
      expect(parseTargetPath(hrefOf(`/dir/${name}`, false)), name).toBe(`/dir/${name}`);
    }
  });
});

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

describe("parseDepth", () => {
  it("reads the three legal values, case-insensitively", () => {
    expect(parseDepth("0", 1)).toBe(0);
    expect(parseDepth("1", 0)).toBe(1);
    expect(parseDepth("Infinity", 0)).toBe("infinity");
    expect(parseDepth(" infinity ", 0)).toBe("infinity");
  });

  it("uses the caller's default only when the header is absent", () => {
    expect(parseDepth(undefined, "infinity")).toBe("infinity");
    expect(parseDepth("2", 1)).toBeUndefined();
    expect(parseDepth("", 1)).toBeUndefined();
  });
});

describe("parseOverwrite", () => {
  it("defaults to T and reads both flags", () => {
    expect(parseOverwrite(undefined)).toBe(true);
    expect(parseOverwrite("T")).toBe(true);
    expect(parseOverwrite("f")).toBe(false);
    expect(parseOverwrite("yes")).toBeUndefined();
  });
});

describe("parseDestination", () => {
  it("takes an absolute URI on the same origin", () => {
    expect(parseDestination("http://dav.example:8080/a%20b", "dav.example:8080")).toBe("/a b");
    expect(parseDestination("http://DAV.example/a", "dav.example")).toBe("/a");
  });

  it("takes an absolute path, which is what several clients send", () => {
    expect(parseDestination("/a/b", "dav.example")).toBe("/a/b");
  });

  it("refuses another origin with 502, per §9.9.4", () => {
    expect(refusedWith(() => parseDestination("http://elsewhere/a", "dav.example"))).toBe(502);
    /* No `Host` to compare against: the authority cannot be checked, so it is
       not assumed to be local. */
    expect(refusedWith(() => parseDestination("http://dav.example/a", undefined))).toBe(502);
  });

  it("refuses a missing or unparseable header with 400", () => {
    expect(refusedWith(() => parseDestination(undefined, "x"))).toBe(400);
    expect(refusedWith(() => parseDestination("   ", "x"))).toBe(400);
    expect(refusedWith(() => parseDestination("not a uri", "x"))).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// request bodies
// ---------------------------------------------------------------------------

describe("collectBody", () => {
  it("joins the chunks and copies each one", async () => {
    const buffer = Buffer.from("abcd", "utf8");
    const body = (async function* () {
      yield buffer.subarray(0, 2);
      yield buffer.subarray(2);
    })();
    const collected = await collectBody(body);
    buffer.fill(0x2e);
    // The copy is what survives the caller reusing its buffer.
    expect(Buffer.from(collected).toString("utf8")).toBe("abcd");
  });

  it("refuses a body over the budget with 413", async () => {
    const body = (async function* () {
      yield utf8("0123456789");
    })();
    await expect(collectBody(body, 4)).rejects.toBeInstanceOf(DavFault);
  });
});

describe("parsePropfind", () => {
  it("reads an empty body as allprop, which §9.1 requires", () => {
    expect(parsePropfind(new Uint8Array(0))).toEqual({ kind: "allprop" });
  });

  it("reads the three forms whatever prefix they use", () => {
    expect(parsePropfind(utf8(`<propfind xmlns="DAV:"><allprop/></propfind>`))).toEqual({
      kind: "allprop",
    });
    expect(parsePropfind(utf8(`<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>`))).toEqual({
      kind: "propname",
    });
    expect(
      parsePropfind(
        utf8(
          `<?xml version="1.0" encoding="utf-8"?>` +
            `<zz:propfind xmlns:zz="DAV:"><zz:prop><zz:getetag/><zz:resourcetype/></zz:prop></zz:propfind>`,
        ),
      ),
    ).toEqual({ kind: "prop", names: ["getetag", "resourcetype"] });
  });

  it("keeps each name once, in request order", () => {
    expect(
      parsePropfind(utf8(`<propfind xmlns="DAV:"><prop><a/><b/><a/></prop></propfind>`)),
    ).toEqual({ kind: "prop", names: ["a", "b"] });
  });

  it("refuses a body that is not a propfind", () => {
    for (const body of [
      `<propertyupdate xmlns="DAV:"/>`,
      `<propfind xmlns="DAV:"></propfind>`,
      `<propfind`,
      `<!DOCTYPE x><propfind xmlns="DAV:"><allprop/></propfind>`,
    ]) {
      expect(
        refusedWith(() => parsePropfind(utf8(body))),
        body,
      ).toBe(400);
    }
  });
});

describe("parseProppatch", () => {
  it("keeps both lists, because the reply must name every property", () => {
    expect(
      parseProppatch(
        utf8(
          `<D:propertyupdate xmlns:D="DAV:">` +
            `<D:set><D:prop><D:displayname>x</D:displayname></D:prop></D:set>` +
            `<D:remove><D:prop><Z:mine xmlns:Z="urn:z"/></D:prop></D:remove>` +
            `</D:propertyupdate>`,
        ),
      ),
    ).toEqual({ set: [{ name: "displayname", text: "x" }], remove: ["mine"] });
  });

  it("ignores a set child that is not a prop, and a child that is neither set nor remove", () => {
    expect(
      parseProppatch(
        utf8(
          `<propertyupdate xmlns="DAV:"><set><whatever/>` +
            `<prop><displayname>v</displayname></prop></set></propertyupdate>`,
        ),
      ),
    ).toEqual({ set: [{ name: "displayname", text: "v" }], remove: [] });
  });

  it("ignores a child that is neither set nor remove", () => {
    expect(
      parseProppatch(
        utf8(
          `<propertyupdate xmlns="DAV:"><whatever/>` +
            `<set><prop><displayname/></prop></set></propertyupdate>`,
        ),
      ),
    ).toEqual({ set: [{ name: "displayname", text: "" }], remove: [] });
  });

  it("refuses a body naming nothing", () => {
    expect(refusedWith(() => parseProppatch(utf8(`<propertyupdate xmlns="DAV:"/>`)))).toBe(400);
    expect(
      refusedWith(() =>
        parseProppatch(utf8(`<propertyupdate xmlns="DAV:"><set/></propertyupdate>`)),
      ),
    ).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// refusals and documents
// ---------------------------------------------------------------------------

describe("statusOfError", () => {
  it("takes a fault's own status", () => {
    expect(statusOfError(refuse(423))).toBe(423);
  });

  it("maps a driver errno through the table", () => {
    expect(statusOfError(Object.assign(new Error("x"), { code: "ENOENT" }))).toBe(404);
    expect(statusOfError(Object.assign(new Error("x"), { code: "ENOTEMPTY" }))).toBe(409);
    expect(statusOfError(Object.assign(new Error("x"), { code: "ENOSPC" }))).toBe(507);
  });

  it("answers 500 for anything it cannot name", () => {
    expect(statusOfError(new Error("x"))).toBe(500);
    expect(statusOfError("nonsense")).toBe(500);
    expect(statusOfError(undefined)).toBe(500);
    expect(statusOf("EWHAT")).toBe(500);
  });
});

describe("faultResponse", () => {
  it("carries the fault's extra headers and no body", () => {
    const reply = faultResponse(refuse(405, { headers: { allow: "GET" } }));
    expect(reply).toEqual({
      status: 405,
      headers: { allow: "GET", "content-length": "0" },
    });
  });

  it("renders an error document when there is a condition to carry", () => {
    const reply = faultResponse(refuse(403, { condition: "propfind-finite-depth" }));
    expect(reply.status).toBe(403);
    expect(Buffer.from(reply.body as Uint8Array).toString("utf8")).toBe(
      `<?xml version="1.0" encoding="UTF-8"?>` +
        `<error xmlns="DAV:"><propfind-finite-depth></propfind-finite-depth></error>`,
    );
    expect(reply.headers["content-length"]).toBe(String((reply.body as Uint8Array).byteLength));
  });
});

describe("encodeMultistatus", () => {
  it("writes a propstat response", () => {
    expect(
      encodeMultistatus([
        {
          href: "/a%20b",
          propstat: [
            { status: 200, props: [{ name: "getcontentlength", text: 11 }] },
            { status: 404, props: [{ name: "missing" }] },
          ],
        },
      ]),
    ).toBe(
      `<?xml version="1.0" encoding="UTF-8"?><multistatus xmlns="DAV:"><response>` +
        `<href>/a%20b</href>` +
        `<propstat><prop><getcontentlength>11</getcontentlength></prop>` +
        `<status>HTTP/1.1 200 OK</status></propstat>` +
        `<propstat><prop><missing></missing></prop>` +
        `<status>HTTP/1.1 404 Not Found</status></propstat>` +
        `</response></multistatus>`,
    );
  });

  it("writes a bare-status response, which is what a partial DELETE answers", () => {
    expect(encodeMultistatus([{ href: "/x/", status: 403 }])).toContain(
      `<href>/x/</href><status>HTTP/1.1 403 Forbidden</status>`,
    );
  });

  it("escapes an href rather than letting a name close an element", () => {
    /* The href is built by `hrefOf`, which percent-encodes — this is the second
       line of defence, and the one that holds if a caller ever passes a raw
       name. */
    expect(encodeMultistatus([{ href: "/a<b>&c", status: 200 }])).toContain(
      `<href>/a&lt;b&gt;&amp;c</href>`,
    );
  });

  it("carries a condition inside the propstat that needs one", () => {
    expect(
      encodeMultistatus([
        {
          href: "/x",
          propstat: [{ status: 403, props: [], condition: "cannot-modify-protected-property" }],
        },
      ]),
    ).toContain(
      `<status>HTTP/1.1 403 Forbidden</status>` +
        `<error><cannot-modify-protected-property></cannot-modify-protected-property></error>`,
    );
  });
});

describe("statusLine", () => {
  it("names every status this server can send", () => {
    expect(statusLine(207)).toBe("HTTP/1.1 207 Multi-Status");
    expect(statusLine(507)).toBe("HTTP/1.1 507 Insufficient Storage");
    for (const status of Object.keys(STATUS_TEXT)) {
      expect(statusLine(Number(status))).toMatch(/^HTTP\/1\.1 \d{3} \S/);
    }
  });

  it("still renders a status with no phrase", () => {
    expect(statusLine(499)).toBe("HTTP/1.1 499");
  });
});

describe("encodeErrorDocument", () => {
  it("is a DAV:-namespaced error with one condition", () => {
    expect(encodeErrorDocument("lock-token-submitted")).toBe(
      `<?xml version="1.0" encoding="UTF-8"?>` +
        `<error xmlns="DAV:"><lock-token-submitted></lock-token-submitted></error>`,
    );
  });
});

// ---------------------------------------------------------------------------
// the locking headers
// ---------------------------------------------------------------------------

describe("parseTimeout", () => {
  it("reads the first TimeType of §10.7's list", () => {
    expect(parseTimeout("Second-3600")).toBe(3600);
    expect(parseTimeout("Infinite")).toBe("infinite");
    expect(parseTimeout("second-90")).toBe(90);
    // §9.10.7's own header: the first entry is the one that is read.
    expect(parseTimeout("Infinite, Second-4100000000")).toBe("infinite");
    expect(parseTimeout(" Second-5 , Infinite ")).toBe(5);
  });

  it("ignores an absent or unreadable suggestion rather than refusing it", () => {
    /* §6.6 makes the value a suggestion the server may ignore entirely, so a
       malformed one is one more thing to ignore. */
    for (const value of [undefined, "", "Seconds-30", "Second-", "Second-1x", "forever"]) {
      expect(parseTimeout(value), JSON.stringify(value)).toBeUndefined();
    }
  });
});

describe("the Lock-Token header", () => {
  it("is a Coded-URL in both directions (§10.5)", () => {
    expect(parseLockToken("<urn:uuid:e71d4fae-5dec-22d6-fea5-00a0c91e6be4>")).toBe(
      "urn:uuid:e71d4fae-5dec-22d6-fea5-00a0c91e6be4",
    );
    expect(parseLockToken(" <urn:uuid:a> ")).toBe("urn:uuid:a");
    expect(formatLockToken("urn:uuid:a")).toBe("<urn:uuid:a>");
  });

  it("is undefined for anything that is not one", () => {
    for (const value of [undefined, "", "urn:uuid:a", "<a", "a>", "<>", "<a><b>"]) {
      expect(parseLockToken(value), JSON.stringify(value)).toBeUndefined();
    }
  });
});

describe("parseIf", () => {
  const host = "example.com";

  it("reads §10.4.6's no-tag production as OR over AND", () => {
    expect(parseIf(`(<urn:uuid:181d4fae> ["I am an ETag"]) (["I am another ETag"])`, host)).toEqual(
      [
        {
          resource: undefined,
          foreign: false,
          conditions: [
            { negated: false, token: "urn:uuid:181d4fae" },
            { negated: false, etag: `"I am an ETag"` },
          ],
        },
        {
          resource: undefined,
          foreign: false,
          conditions: [{ negated: false, etag: `"I am another ETag"` }],
        },
      ],
    );
  });

  it("applies Not to the one condition after it (§10.4.7)", () => {
    expect(parseIf(`(Not <urn:uuid:181d4fae> <urn:uuid:58f202ac>)`, host)?.[0]?.conditions).toEqual(
      [
        { negated: true, token: "urn:uuid:181d4fae" },
        { negated: false, token: "urn:uuid:58f202ac" },
      ],
    );
  });

  it("carries a Resource-Tag forward to every list until the next one", () => {
    const lists = parseIf(`</one> (<urn:uuid:a>) (<urn:uuid:b>) </two/deep> (<urn:uuid:c>)`, host);
    expect(lists?.map((list) => [list.resource, list.conditions[0]?.token])).toEqual([
      ["/one", "urn:uuid:a"],
      ["/one", "urn:uuid:b"],
      ["/two/deep", "urn:uuid:c"],
    ]);
  });

  it("takes an absolute URI on this origin, and decodes it per segment", () => {
    expect(parseIf(`<http://example.com/a%20b> (<urn:uuid:a>)`, host)?.[0]?.resource).toBe("/a b");
  });

  it("marks another origin foreign rather than refusing it (§10.4.4)", () => {
    /* A URL this server does not serve is a resource whose state it cannot
       know, which is the "handling unmapped URLs" case rather than an error. */
    for (const tag of ["http://elsewhere.example/x", "not a uri", "http:"]) {
      const list = parseIf(`<${tag}> (<urn:uuid:a>)`, host)?.[0];
      expect(list, tag).toMatchObject({ resource: undefined, foreign: true });
    }
    // No `Host` to compare against: an absolute URI cannot be shown to be local.
    expect(parseIf(`<http://example.com/x> (<urn:uuid:a>)`, undefined)?.[0]?.foreign).toBe(true);
  });

  it("accepts tagged and untagged lists in one header", () => {
    /* §10.4.2 says they cannot be mixed, and says why it costs nothing to read
       one that does: an untagged list is shorthand for a tagged one naming the
       request URI. */
    expect(
      parseIf(`(<urn:uuid:a>) </x> (<urn:uuid:b>)`, host)?.map((list) => list.resource),
    ).toEqual([undefined, "/x"]);
  });

  it("keeps an entity tag as it was sent, weakness marker and brackets included", () => {
    const lists = parseIf(`(<urn:uuid:a> [W/"weak"]) ([")]("])`, host);
    expect(lists?.[0]?.conditions[1]).toEqual({ negated: false, etag: `W/"weak"` });
    // A `]` inside the quoted value does not end the tag.
    expect(lists?.[1]?.conditions[0]).toEqual({ negated: false, etag: `")]("` });
  });

  it("is undefined for anything that is not §10.4.2's grammar", () => {
    for (const value of [
      "",
      "   ",
      "(<urn:uuid:a>",
      "()",
      "<urn:uuid:a>",
      "(<urn:uuid:a)",
      "(garbage)",
      `(["unterminated)`,
      "<no-close (<urn:uuid:a>)",
      "<unterminated",
    ]) {
      expect(parseIf(value, host), JSON.stringify(value)).toBeUndefined();
    }
  });

  it("submits every positive state token, once, and never a negated one", () => {
    /* §10.4.1: a token counts as submitted whatever the list evaluated to —
       but `Not <token>` asserts the resource is *not* held by it, which is the
       opposite of a claim, and is what makes §10.4.8's `(Not <DAV:no-lock>)`
       idiom a tautology rather than a claim on a lock. */
    const lists = parseIf(
      `(<urn:uuid:a> ["etag"]) (<urn:uuid:a>) </x> (<urn:uuid:b>) (Not <DAV:no-lock>)`,
      host,
    );
    expect(submittedTokens(lists ?? [])).toEqual(["urn:uuid:a", "urn:uuid:b"]);
  });
});

// ---------------------------------------------------------------------------
// the lock bodies and documents
// ---------------------------------------------------------------------------

describe("parseLockInfo", () => {
  const lockinfo = (inner: string): Uint8Array =>
    utf8(`<D:lockinfo xmlns:D="DAV:">${inner}</D:lockinfo>`);

  it("reads §9.10.7's request", () => {
    expect(
      parseLockInfo(
        lockinfo(
          `<D:lockscope><D:exclusive/></D:lockscope>` +
            `<D:locktype><D:write/></D:locktype>` +
            `<D:owner><D:href>http://example.org/~ejw/contact.html</D:href></D:owner>`,
        ),
      ),
    ).toEqual({
      exclusive: true,
      owner: {
        name: "owner",
        text: undefined,
        children: [{ name: "href", text: "http://example.org/~ejw/contact.html", children: [] }],
      },
    });
  });

  it("reads a shared lock, and an owner that is text", () => {
    expect(
      parseLockInfo(
        lockinfo(
          `<D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype>` +
            `<D:owner>Ada Lovelace</D:owner>`,
        ),
      ),
    ).toEqual({
      exclusive: false,
      owner: { name: "owner", text: "Ada Lovelace", children: [] },
    });
  });

  it("is undefined for the empty body that means refresh (§7.7)", () => {
    expect(parseLockInfo(new Uint8Array(0))).toBeUndefined();
  });

  it("refuses a scope or a type this server has no meaning for", () => {
    expect(
      refusedWith(() => parseLockInfo(lockinfo(`<D:lockscope><D:sideways/></D:lockscope>`))),
    ).toBe(400);
    expect(
      refusedWith(() =>
        parseLockInfo(
          lockinfo(`<D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:read/></D:locktype>`),
        ),
      ),
    ).toBe(400);
    expect(refusedWith(() => parseLockInfo(utf8("<propfind/>")))).toBe(400);
    expect(refusedWith(() => parseLockInfo(utf8("<lockinfo")))).toBe(400);
  });
});

describe("the lock documents", () => {
  const now = 1_700_000_000_000;
  const table = new DavLockTable({ newToken: () => "urn:uuid:fixed-token" });
  const grant = table.create(
    {
      path: "/a b/notes",
      collection: true,
      depth: "infinity",
      exclusive: true,
      owner: { name: "owner", children: [{ name: "href", text: "mailto:ada@example.com" }] },
      timeoutSeconds: 120,
    },
    now,
  );
  const lock = grant.kind === "granted" ? grant.lock : undefined;

  it("writes §14.1's children in the DTD's order", () => {
    expect(xmlDocument(activeLockNode(lock!, now + 5000))).toBe(
      `<?xml version="1.0" encoding="UTF-8"?>` +
        `<activelock>` +
        `<lockscope><exclusive></exclusive></lockscope>` +
        `<locktype><write></write></locktype>` +
        `<depth>infinity</depth>` +
        `<owner><href>mailto:ada@example.com</href></owner>` +
        `<timeout>Second-115</timeout>` +
        `<locktoken><href>urn:uuid:fixed-token</href></locktoken>` +
        `<lockroot><href>/a%20b/notes/</href></lockroot>` +
        `</activelock>`,
    );
  });

  it("is the whole §9.10.1 body: a prop holding one lockdiscovery", () => {
    expect(encodeLockResponse(lock!, now)).toBe(
      `<?xml version="1.0" encoding="UTF-8"?>` +
        `<prop xmlns="DAV:"><lockdiscovery>${xmlDocument(activeLockNode(lock!, now)).slice(
          `<?xml version="1.0" encoding="UTF-8"?>`.length,
        )}</lockdiscovery></prop>`,
    );
  });

  it("is an empty lockdiscovery when nothing is locked (§15.8)", () => {
    expect(xmlDocument(lockDiscoveryNode([], now))).toContain(`<lockdiscovery></lockdiscovery>`);
  });

  it("advertises exactly the two lock entries §15.10 defines", () => {
    expect(xmlDocument(supportedLockNode())).toBe(
      `<?xml version="1.0" encoding="UTF-8"?>` +
        `<supportedlock>` +
        `<lockentry><lockscope><exclusive></exclusive></lockscope>` +
        `<locktype><write></write></locktype></lockentry>` +
        `<lockentry><lockscope><shared></shared></lockscope>` +
        `<locktype><write></write></locktype></lockentry>` +
        `</supportedlock>`,
    );
  });

  it("names the locked resource inside the condition (§7.5.2, §16)", () => {
    expect(encodeErrorDocument("lock-token-submitted", ["/locked/"])).toBe(
      `<?xml version="1.0" encoding="UTF-8"?>` +
        `<error xmlns="DAV:"><lock-token-submitted><href>/locked/</href>` +
        `</lock-token-submitted></error>`,
    );
  });
});
