/**
 * The shared XML codec's own contract: namespaces, in both directions.
 *
 * `test/s3/xml.test.ts` drives the rest of this module — the character rules,
 * the goldens, the caps, the hostile bodies and the fuzzer — through the two S3
 * grammars, which is where those properties are worth checking because that is
 * where a real body arrives. What is here is what only became this module's
 * when WebDAV started reading it: prefix resolution, scoping, and the `xmlns`
 * the serializer writes. **Namespaces in XML 1.0** is the source; the rule is
 * named at the assertion where the shape does not give it away.
 *
 * The two protocols read different halves of a parsed name, so both halves are
 * asserted at every case rather than whichever one the rule is about.
 */

import { describe, expect, it } from "vitest";
import { parseXml, XML_PREFIX_NS, xmlDocument, type ParsedElement } from "../src/xml.ts";

const DAV = "DAV:";
const WIN32 = "urn:schemas-microsoft-com:";

/** Every element of a tree as `ns|name`, depth first, so a case reads in one line. */
function names(element: ParsedElement): string[] {
  return [`${element.ns}|${element.name}`, ...element.children.flatMap((child) => names(child))];
}

/** The one child at this path, by local name. */
function child(element: ParsedElement, ...path: string[]): ParsedElement {
  let at = element;
  for (const name of path) {
    const found = at.children.find((candidate) => candidate.name === name);
    expect(found, `no <${name}> under <${at.name}>`).toBeDefined();
    at = found as ParsedElement;
  }
  return at;
}

// ---------------------------------------------------------------------------
// resolving
// ---------------------------------------------------------------------------

describe("namespaces, coming in", () => {
  it("reads a default declaration and a prefix as the same element", () => {
    const prefixed = parseXml(`<D:propfind xmlns:D="DAV:"><D:prop/></D:propfind>`);
    const defaulted = parseXml(`<propfind xmlns="DAV:"><prop/></propfind>`);
    expect(names(prefixed)).toEqual(["DAV:|propfind", "DAV:|prop"]);
    expect(names(defaulted)).toEqual(names(prefixed));
  });

  it("binds a prefix declared in the same start tag as the name that uses it", () => {
    /* The declaration is read after the name it applies to, which is why the
       element cannot be built until the whole start tag has been. */
    expect(names(parseXml(`<D:prop xmlns:D="DAV:"/>`))).toEqual(["DAV:|prop"]);
  });

  it("keeps two properties with one local name apart by namespace", () => {
    const root = parseXml(
      `<prop xmlns="DAV:" xmlns:Z="${WIN32}">` +
        `<getlastmodified/><Z:getlastmodified/>` +
        `</prop>`,
    );
    expect(names(root)).toEqual(["DAV:|prop", "DAV:|getlastmodified", `${WIN32}|getlastmodified`]);
  });

  it("scopes a declaration to its own element and that element's children", () => {
    const root = parseXml(
      `<multistatus xmlns="DAV:">` +
        `<response><prop xmlns="${WIN32}"><a/></prop></response>` +
        `<response><prop><b/></prop></response>` +
        `</multistatus>`,
    );
    // The second `<response>` is a sibling of the redeclaration, not a child.
    expect(names(root)).toEqual([
      "DAV:|multistatus",
      "DAV:|response",
      `${WIN32}|prop`,
      `${WIN32}|a`,
      "DAV:|response",
      "DAV:|prop",
      "DAV:|b",
    ]);
  });

  it("undeclares the default namespace with an empty value", () => {
    const root = parseXml(`<prop xmlns="DAV:"><bare xmlns=""><under/></bare></prop>`);
    expect(names(root)).toEqual(["DAV:|prop", "|bare", "|under"]);
  });

  it("unbinds a prefix given an empty value", () => {
    const root = parseXml(`<a xmlns:Z="DAV:"><b xmlns:Z=""><Z:c/></b><Z:d/></a>`);
    expect(child(root, "b", "c").ns).toBe("");
    expect(child(root, "d").ns).toBe(DAV);
  });

  it("puts an unbound prefix in no namespace rather than refusing the body", () => {
    /* Namespaces in XML makes this an error; here it is the safe reading —
       "not one of ours" — and the local name still arrives, which is what a
       404 propstat has to name. See `parseXml`. */
    const root = parseXml(`<propfind xmlns="DAV:"><prop><Z:Win32CreationTime/></prop></propfind>`);
    const property = child(root, "prop", "Win32CreationTime");
    expect(property.ns).toBe("");
    expect(property.name).toBe("Win32CreationTime");
  });

  it("binds `xml` without a declaration and refuses to let it be rebound", () => {
    const root = parseXml(`<a xmlns:xml="urn:not-this"><xml:lang/></a>`);
    expect(child(root, "lang").ns).toBe(XML_PREFIX_NS);
  });

  it("ignores `xmlns:xmlns`, which declares nothing", () => {
    const root = parseXml(`<a xmlns:xmlns="urn:not-this"><xmlns:b/></a>`);
    expect(child(root, "b").ns).toBe("");
  });

  it("resolves a value carrying an entity, which is where the URI is built", () => {
    const root = parseXml(`<a xmlns:Z="urn:a&amp;b"><Z:c/></a>`);
    expect(child(root, "c").ns).toBe("urn:a&b");
  });

  it("leaves an element with no declaration anywhere in no namespace", () => {
    // Every S3 grammar, and the reason S3 matches on the local name alone.
    expect(names(parseXml(`<Delete><Object><Key>k</Key></Object></Delete>`))).toEqual([
      "|Delete",
      "|Object",
      "|Key",
    ]);
  });

  it("still drops the prefix from the local name", () => {
    // What `src/s3/xml.ts` has always matched on, unchanged by any of the above.
    expect(parseXml(`<s3:Delete xmlns:s3="urn:x"/>`).name).toBe("Delete");
  });
});

// ---------------------------------------------------------------------------
// writing
// ---------------------------------------------------------------------------

describe("namespaces, going out", () => {
  it("writes the root's namespace and lets every child inherit it", () => {
    expect(
      xmlDocument({ name: "multistatus", children: [{ name: "response" }] }, { xmlns: DAV }),
    ).toContain(`<multistatus xmlns="DAV:"><response></response></multistatus>`);
  });

  it("declares a child that is in another namespace, and only that child", () => {
    const document = xmlDocument(
      {
        name: "prop",
        children: [
          { name: "getlastmodified" },
          { name: "Win32CreationTime", ns: WIN32 },
          { name: "getetag" },
        ],
      },
      { xmlns: DAV },
    );
    expect(document).toContain(
      `<getlastmodified></getlastmodified>` +
        `<Win32CreationTime xmlns="${WIN32}"></Win32CreationTime>` +
        `<getetag></getetag>`,
    );
  });

  it("carries a declared namespace down to the children of that element", () => {
    expect(
      xmlDocument(
        { name: "prop", children: [{ name: "outer", ns: WIN32, children: [{ name: "inner" }] }] },
        { xmlns: DAV },
      ),
    ).toContain(`<outer xmlns="${WIN32}"><inner></inner></outer>`);
  });

  it("writes nothing for a namespace that is already the default", () => {
    expect(
      xmlDocument({ name: "prop", children: [{ name: "getetag", ns: DAV }] }, { xmlns: DAV }),
    ).toContain(`<prop xmlns="DAV:"><getetag></getetag></prop>`);
  });

  it("undeclares with an empty xmlns for an element in no namespace", () => {
    /* A property named with an unbound prefix comes back in no namespace, and
       saying so takes `xmlns=""` — writing it bare would put it in `DAV:` and
       claim the client asked about a property it did not. */
    expect(
      xmlDocument({ name: "prop", children: [{ name: "Win32", ns: "" }] }, { xmlns: DAV }),
    ).toContain(`<Win32 xmlns=""></Win32>`);
  });

  it("escapes a namespace URI like any other value", () => {
    expect(xmlDocument({ name: "a", children: [{ name: "b", ns: `urn:x&y` }] })).toContain(
      `<b xmlns="urn:x&amp;y">`,
    );
  });

  it("round-trips every pair it wrote", () => {
    const document = xmlDocument(
      {
        name: "multistatus",
        children: [
          { name: "inherited" },
          { name: "foreign", ns: WIN32, children: [{ name: "under" }] },
          { name: "none", ns: "" },
        ],
      },
      { xmlns: DAV },
    );
    expect(names(parseXml(document))).toEqual([
      "DAV:|multistatus",
      "DAV:|inherited",
      `${WIN32}|foreign`,
      `${WIN32}|under`,
      "|none",
    ]);
  });
});
