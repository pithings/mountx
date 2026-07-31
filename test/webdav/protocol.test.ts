/**
 * The WebDAV wire, on its own: no driver, no socket, no session.
 *
 * Three kinds of fact live here, and they are checked against different
 * sources:
 *
 * - **RFC 4918's grammars** — `Depth`, `Overwrite`, `Destination`, the two
 *   request bodies, and the two response documents. The section is named at the
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
import {
  collectBody,
  DavFault,
  encodeErrorDocument,
  encodeMultistatus,
  faultResponse,
  hrefOf,
  isDavFault,
  parseDepth,
  parseDestination,
  parseOverwrite,
  parsePropfind,
  parseProppatch,
  parseTargetPath,
  refuse,
  statusOfError,
} from "../../src/webdav/protocol.ts";

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
    ).toEqual({ set: ["displayname"], remove: ["mine"] });
  });

  it("ignores a child that is neither set nor remove", () => {
    expect(
      parseProppatch(
        utf8(
          `<propertyupdate xmlns="DAV:"><whatever/>` +
            `<set><prop><displayname/></prop></set></propertyupdate>`,
        ),
      ),
    ).toEqual({ set: ["displayname"], remove: [] });
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
