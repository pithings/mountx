/**
 * The XML the two HTTP transports share: a builder for the documents they
 * produce and a bounded parser for the bodies they accept.
 *
 * All of it is XML 1.0 and Namespaces in XML 1.0, none of it is S3's or
 * WebDAV's, and it lives here for the same reason `src/http.ts` holds RFC
 * 9110's dates and entity tags: a format transcribed twice is a format that
 * will be transcribed differently twice (`AGENTS.md`, invariants 6 and 7).
 * `src/s3/xml.ts` holds the S3 documents built on this and re-exports every
 * symbol below, so `mountx/s3`'s surface is unchanged; `src/webdav/protocol.ts`
 * imports from here directly.
 *
 * **This is not a general XML library and must not grow into one.** Both
 * transports send a fixed set of small documents and accept a fixed set of
 * small grammars, so what is here is a serializer and a recursive-descent
 * parser bounded in every dimension a hostile body can push on. Anything
 * neither protocol can send has no reason to be parseable, and every feature
 * left out is one that cannot be turned against a server. It grows for a
 * document one of the two actually receives, and for nothing else.
 *
 * ## Namespaces, in both directions
 *
 * A prefix is **resolved, not dropped**: the parser tracks the `xmlns` and
 * `xmlns:*` declarations in scope and reports each element as the pair
 * Namespaces in XML defines it to be — a local name and a namespace URI, `""`
 * for none. `<D:prop xmlns:D="DAV:">` and `<prop xmlns="DAV:">` are the same
 * element, and `<Z:prop xmlns:Z="urn:example">` is a different one. A caller
 * reads whichever field its protocol identifies elements by, which is not the
 * same choice for the two here — see {@link ParsedElement}.
 *
 * Going out, an element carries its namespace as a **default declaration**
 * rather than a prefix (`<multistatus xmlns="DAV:">` with unprefixed children),
 * which is the same document to a namespace-aware reader and needs no prefix
 * table on either side. {@link XmlNode.ns} says when to write one.
 *
 * ## One notion of a valid character, applied in both directions
 *
 * XML 1.0 cannot carry every code point, and the values reaching this module
 * are the least trustworthy in the system: object keys and resource names are
 * arbitrary UTF-8, header values arrive latin-1-decoded (so C1 controls appear
 * as real characters), and the S3 gateway's `quote()` truncates a refusal
 * detail at a fixed character count — which can cut an astral pair in half and
 * hand `<Message>` a lone surrogate.
 *
 * {@link isXmlChar} is the single answer to "can this character exist in a
 * document here", and both halves use it:
 *
 * - The **encoder replaces** what it rejects with U+FFFD. It never throws: an
 *   error response that cannot encode is a request with no reply at all, which
 *   is the one failure mode a server must not have (`AGENTS.md`: exactly one
 *   well-formed reply per request).
 * - The **parser refuses** a document containing one, whether it arrived raw or
 *   as a numeric character reference. `&#0;` is a refusal, never a NUL in a key.
 *
 * Together those give the property worth having: **every name the parser
 * accepts is a name the encoder emits unchanged.** A round trip through this
 * codec is exact or it does not happen.
 *
 * What {@link isXmlChar} rejects, and why each one is here:
 *
 * - **C0 controls except tab, LF and CR** — not `Char` in XML 1.0 at all.
 * - **DEL and the C1 controls (U+007F–U+009F)** — legal `Char` in XML 1.0 and
 *   illegal in XML 1.1, rejected by real parsers either way, and the exact
 *   range a latin-1-decoded header byte lands in.
 * - **Lone surrogates (U+D800–U+DFFF)** — not characters; see `quote()` above.
 *   A well-formed pair is a single code point here and passes untouched.
 *   Iteration is by code point precisely so that it can.
 * - **U+*FFFE and U+*FFFF in every plane** — U+FFFE/U+FFFF are excluded from
 *   `Char`, and the rule is applied uniformly across planes rather than only to
 *   plane 0. That is stricter than XML 1.0 for U+1FFFE and friends; the cost is
 *   a noncharacter nobody sends, and the gain is one predicate with no plane
 *   special case in it.
 *
 * CR is escaped as `&#13;` rather than emitted raw, because an XML parser
 * normalizes line endings in content: a raw CR in a name would come back as LF
 * and the round-trip property above would be a lie. AWS does the same — the
 * `DeleteObjects` examples show a key with a CR in it written `&#13;`.
 *
 * The reverse half of that rule is a **deliberate deviation from XML 1.0
 * §2.11**: this parser does *not* normalize CR and CRLF in its input to LF. A
 * conformant parser would, and doing so would silently rewrite any name
 * containing one — which is the same corruption the `&#13;` escape exists to
 * prevent, arriving from the other direction. A client that means CR sends
 * `&#13;` and gets CR; a client that sends a raw CR gets a raw CR. The
 * normalizing behavior is unreachable for the documents either protocol
 * defines, since none of them is line-oriented.
 *
 * ## Everything here is pure
 *
 * No I/O, no clock, no `Date`: timestamps arrive as strings already formatted
 * by the caller. Encoding is deterministic — the same input is the same bytes,
 * always, with no whitespace between elements and nothing that depends on
 * object key order.
 */

// ---------------------------------------------------------------------------
// characters
// ---------------------------------------------------------------------------

/** U+FFFD, what the encoder puts where a character cannot go. */
export const XML_REPLACEMENT = String.fromCodePoint(0xff_fd);

/**
 * Can this code point appear in a document this codec produces or accepts? See
 * the module docs for the four exclusions and the reason for each.
 */
export function isXmlChar(code: number): boolean {
  if (code < 0x20) {
    return code === 0x09 || code === 0x0a || code === 0x0d;
  }
  if (code < 0x7f) {
    return true;
  }
  if (code <= 0x9f) {
    return false;
  }
  if (code >= 0xd8_00 && code <= 0xdf_ff) {
    return false;
  }
  return (code & 0xff_fe) !== 0xff_fe;
}

/**
 * Text content, made safe to place between two tags: the five markup
 * characters escaped, CR escaped so line-ending normalization cannot eat it,
 * and anything {@link isXmlChar} rejects replaced with {@link XML_REPLACEMENT}.
 *
 * The **only** place this codec escapes anything. Never throws.
 */
export function escapeXmlText(value: string): string {
  let escaped = "";
  for (const character of value) {
    switch (character) {
      case "&": {
        escaped += "&amp;";
        continue;
      }
      case "<": {
        escaped += "&lt;";
        continue;
      }
      case ">": {
        escaped += "&gt;";
        continue;
      }
      case '"': {
        escaped += "&quot;";
        continue;
      }
      case "'": {
        escaped += "&apos;";
        continue;
      }
      case "\r": {
        escaped += "&#13;";
        continue;
      }
      default: {
        break;
      }
    }
    /* `for...of` over a string yields code points, so a well-formed surrogate
       pair arrives as one character and survives; a lone surrogate arrives on
       its own and is replaced. */
    escaped += isXmlChar(character.codePointAt(0) ?? 0) ? character : XML_REPLACEMENT;
  }
  return escaped;
}

// ---------------------------------------------------------------------------
// the document builder
// ---------------------------------------------------------------------------

/** The declaration every response starts with. */
export const XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8"?>';

/** What an element can hold as text. Rendered with `String()`, escaped once. */
export type XmlText = string | number | bigint | boolean;

/**
 * One element of a response document.
 *
 * `name` is always a literal from the calling module — never client data — so
 * it is emitted verbatim and unvalidated; that is what keeps the encoder total.
 * An element with both `text` and `children` writes the text first, a shape no
 * S3 document has and no caller here produces.
 *
 * `children` accepts `undefined` entries so an optional element can be written
 * as one conditional expression and dropped by the serializer, which is what
 * keeps the output deterministic without a mutable array anywhere.
 */
export interface XmlNode {
  name: string;
  /**
   * The namespace this element is in.
   *
   * **Omitted means inherit**, which is what every element of a document with
   * one namespace wants and is why nothing already written here carries the
   * field. Set it and the serializer writes a `xmlns` on this element when it
   * differs from the enclosing default — including `xmlns=""` for an element in
   * **no** namespace inside one that has a default.
   *
   * Declared as a default namespace rather than with a generated prefix, so
   * there is no prefix table, no collision to resolve and no name that means
   * one thing at the root and another six elements down. `<Win32CreationTime
   * xmlns="urn:schemas-microsoft-com:"/>` is that property, unambiguously, and
   * a namespace-aware client reads it as the same node either spelling would
   * have produced.
   */
  ns?: string;
  text?: XmlText;
  children?: readonly (XmlNode | undefined)[];
}

function renderText(value: XmlText): string {
  return typeof value === "string" ? value : String(value);
}

function renderElement(node: XmlNode, inherited: string): string {
  const declaring = node.ns !== undefined && node.ns !== inherited;
  const ns = declaring ? (node.ns as string) : inherited;
  let inner = node.text === undefined ? "" : escapeXmlText(renderText(node.text));
  for (const child of node.children ?? []) {
    if (child !== undefined) {
      inner += renderElement(child, ns);
    }
  }
  const attributes = declaring ? ` xmlns="${escapeXmlText(ns)}"` : "";
  return `<${node.name}${attributes}>${inner}</${node.name}>`;
}

/**
 * A whole document: the declaration, then the root element, with no whitespace
 * anywhere between them.
 *
 * `xmlns` is the root's namespace, and is shorthand for setting `ns` on it —
 * the spelling every caller here already used, kept because a document with one
 * namespace should not have to say so on the node. It wins over the root's own
 * `ns` if both are given.
 */
export function xmlDocument(root: XmlNode, options: { xmlns?: string } = {}): string {
  const node = options.xmlns === undefined ? root : { ...root, ns: options.xmlns };
  return XML_DECLARATION + renderElement(node, "");
}

// ---------------------------------------------------------------------------
// the parser
// ---------------------------------------------------------------------------

/**
 * Why a body was refused. Every one of these is a name a caller can turn into
 * an error code without reading the message — S3's `MalformedXML` for the
 * structural ones, `EntityTooLarge` for `too-large`, and so on.
 */
export type XmlRefusal =
  | "too-large"
  | "encoding"
  | "invalid-character"
  | "malformed"
  | "doctype"
  | "entity"
  | "depth"
  | "too-many-elements"
  | "unexpected-root"
  | "missing-field"
  | "duplicate-field"
  | "invalid-field";

/**
 * A request body could not be parsed.
 *
 * The **only** error type this module's parsers throw, which is what makes them
 * fuzzable: a caller that catches `XmlError` and nothing else has covered every
 * failure mode of this layer. Same contract as `XdrError` in `src/nfs/xdr.ts`
 * and `ProtocolError` on the FUSE side.
 *
 * `code` still reads `ERR_S3_XML` now that WebDAV throws it too. It is the
 * value `mountx/s3` has published since the gateway shipped, and a name a
 * consumer may already be matching on; renaming it to fit a second caller would
 * be a breaking change bought for a cosmetic gain. The `reason` is what a
 * caller branches on either way.
 */
export class XmlError extends Error {
  readonly code = "ERR_S3_XML";
  readonly reason: XmlRefusal;
  /** Character offset the failure was detected at, when meaningful. */
  readonly offset: number | undefined;

  constructor(reason: XmlRefusal, message: string, offset?: number) {
    super(message);
    this.name = "XmlError";
    this.reason = reason;
    this.offset = offset;
  }
}

/** Is this an {@link XmlError}? */
export function isXmlError(error: unknown): error is XmlError {
  return error instanceof XmlError;
}

/**
 * Default byte budget, 4 MiB. Generous for every body either parser accepts —
 * a 1000-key `DeleteObjects` runs to about a megabyte at S3's own key limit —
 * and callers pass the request's `Content-Length` cap instead of relying on it.
 */
export const XML_MAX_BYTES = 4 * 1024 * 1024;

/** Deepest element nesting. Every accepted grammar is a handful deep. */
export const XML_MAX_DEPTH = 32;

/**
 * The ceiling a caller's `maxDepth` is clamped to, whatever it asks for.
 *
 * `#element` recurses, so the depth cap is what keeps a nested body off the
 * JavaScript stack — which makes an *unbounded* `maxDepth` a hole in the "throws
 * `XmlError` and nothing else" contract: hand this a `maxDepth` of a few
 * thousand and a deep enough body and the throw is a `RangeError` from the
 * engine, not a refusal. 256 is an order of magnitude below where any Node
 * default stack gives out, and two orders above the deepest body either
 * protocol defines.
 */
export const XML_MAX_DEPTH_CEILING = 256;

/**
 * Most elements one body may contain. A `CompleteMultipartUpload` listing the
 * maximum 10 000 parts is 30 001 elements, so the cap sits well above it and
 * still bounds the tree an attacker can make the parser build.
 */
export const XML_MAX_ELEMENTS = 100_000;

/** The three caps, all optional. */
export interface XmlParseLimits {
  /**
   * Longest body accepted, in bytes (in UTF-16 code units for a string input,
   * which is never more than the byte count). Defaults to {@link XML_MAX_BYTES};
   * a server passes the `Content-Length` cap it is willing to buffer.
   */
  maxBytes?: number;
  /**
   * Defaults to {@link XML_MAX_DEPTH}, and is clamped to
   * {@link XML_MAX_DEPTH_CEILING} however large a number is passed: this cap
   * stands between a hostile body and the stack, so it is not a caller's to
   * raise without limit.
   */
  maxDepth?: number;
  /** Defaults to {@link XML_MAX_ELEMENTS}. */
  maxElements?: number;
}

/**
 * One parsed element: its **local** name, the namespace that name is in, its
 * text content, and its children.
 *
 * The two name fields are separate on purpose, and a caller reads whichever its
 * protocol identifies elements by. S3 reads `name` alone — `s3:Delete`,
 * `<Delete xmlns="…">` and a bare `<Delete>` are one element to it, which is
 * what AWS's namespace-less grammars and its SDKs require. WebDAV reads both,
 * because a property name in RFC 4918 *is* the pair and two properties with the
 * same local name in different namespaces are two different properties.
 *
 * Text is the concatenation of every text run and CDATA section directly inside
 * the element; for the leaves these grammars read, that is the value. Mixed
 * content is not a thing either protocol sends and not a thing this parser
 * models beyond this.
 */
export interface ParsedElement {
  /** The local name: the part after the prefix, which is dropped from it. */
  name: string;
  /**
   * The namespace URI {@link name} is in, resolved against the `xmlns`
   * declarations in scope — `""` for an element in no namespace. See
   * {@link parseXml} for what an unbound prefix does.
   */
  ns: string;
  text: string;
  children: ParsedElement[];
}

/** A prefix bound to a namespace URI. `prefix` is `""` for the default one. */
interface NamespaceDeclaration {
  prefix: string;
  uri: string;
}

/** The declarations in scope at one element: prefix → URI. */
type Namespaces = ReadonlyMap<string, string>;

/**
 * The one binding every document has without declaring it (Namespaces in XML
 * §3): `xml` is always this URI, and it may not be rebound.
 */
export const XML_PREFIX_NS = "http://www.w3.org/XML/1998/namespace";

/** What is in scope before the root element declares anything. */
const ROOT_NAMESPACES: Namespaces = new Map([["xml", XML_PREFIX_NS]]);

/**
 * The scope inside an element that declared these, or the enclosing scope
 * unchanged when it declared none — which is the common case and allocates
 * nothing.
 *
 * `xmlns:foo=""` **unbinds** `foo`. XML 1.0 namespaces makes that an error and
 * XML 1.1 makes it legal; unbinding is what both then agree the *intent* is,
 * and it lands in the same place as an unbound prefix, so there is nothing to
 * gain by refusing it. `xmlns:xmlns` is not a declaration and `xml` may not be
 * rebound: both are ignored rather than refused, for the reason in
 * {@link parseXml}.
 */
function scopeWith(
  inherited: Namespaces,
  declarations: NamespaceDeclaration[] | undefined,
): Namespaces {
  if (declarations === undefined) {
    return inherited;
  }
  const scope = new Map(inherited);
  for (const { prefix, uri } of declarations) {
    if (prefix === "xmlns" || prefix === "xml") {
      continue;
    }
    if (uri === "") {
      scope.delete(prefix);
    } else {
      scope.set(prefix, uri);
    }
  }
  return scope;
}

/**
 * The namespace a qname resolves to in this scope, `""` for none.
 *
 * The prefix is split off at the **same** colon {@link localName} splits at, so
 * the two halves of a name always describe the same split. For a well-formed
 * QName there is at most one colon and the question does not arise; for `a:b:c`
 * — which no protocol here sends and XML does not define — the pair stays
 * consistent rather than each half reading a different name out of it.
 */
function namespaceOf(qname: string, scope: Namespaces): string {
  const colon = qname.lastIndexOf(":");
  return scope.get(colon === -1 ? "" : qname.slice(0, colon)) ?? "";
}

/**
 * `fatal: true`, which is the opposite of what the rest of this project does
 * with a name off the wire — and the difference is deliberate.
 *
 * A FUSE or NFS name that is not valid UTF-8 is decoded lossily because the
 * name is really *bytes* and the caller already knows which file it means. An
 * HTTP request body is not: `<Key>` is the only identification of the object,
 * so a byte that silently becomes U+FFFD is a `DeleteObjects` that deletes a
 * different key than the one asked for, or misses the one it named. There is no
 * safe guess, so there is no guess — a body that is not UTF-8 is refused, the
 * same posture `drivers/unstorage.ts` takes with a key it cannot represent.
 */
const decoder = new TextDecoder("utf8", { fatal: true });

/**
 * First offset holding a character {@link isXmlChar} rejects, or `-1`.
 *
 * Run once over the whole body before parsing, which is what lets every later
 * step assume its text is emittable: a raw NUL, a latin-1 C1 control or a lone
 * surrogate is refused here rather than surviving into a name.
 */
function findInvalidChar(text: string): number {
  for (let at = 0; at < text.length; at++) {
    const code = text.codePointAt(at) as number;
    if (!isXmlChar(code)) {
      return at;
    }
    if (code > 0xff_ff) {
      at++;
    }
  }
  return -1;
}

/**
 * Bytes to text, bounded and copied.
 *
 * `TextDecoder.decode` produces a fresh string, so nothing downstream holds a
 * view of the caller's buffer (`AGENTS.md`: decoders copy what they keep) and
 * the server may reuse it the moment this returns.
 */
function bodyText(input: Uint8Array | string, maxBytes: number): string {
  const size = typeof input === "string" ? input.length : input.byteLength;
  if (size > maxBytes) {
    throw new XmlError("too-large", `body is ${size} bytes, over the ${maxBytes}-byte budget`);
  }
  let text: string;
  if (typeof input === "string") {
    text = input;
  } else {
    try {
      text = decoder.decode(input);
    } catch {
      /* The only thing a fatal decoder throws, and it carries no offset worth
         repeating — see the decoder's own docs for why this is a refusal. */
      throw new XmlError("encoding", "body is not valid UTF-8");
    }
  }
  /* A BOM is legal in front of a UTF-8 document and is not part of it. */
  const body = text.charCodeAt(0) === 0xfe_ff ? text.slice(1) : text;
  const invalid = findInvalidChar(body);
  if (invalid !== -1) {
    throw new XmlError("invalid-character", "body contains a character XML cannot carry", invalid);
  }
  return body;
}

/**
 * One cap, made a number the parser can rely on: anything that is not a finite
 * number takes the default, and a `ceiling` is enforced whatever was asked
 * for. The guard is `Number.isFinite`, not an `NaN` check, because a caller
 * that ignores the types can hand this an object or a string whose coercion
 * inside `Math.min` is `NaN` — and a comparison against `NaN` is always false,
 * so a cap that stayed `NaN` would be no cap at all, which for `maxDepth` is
 * the difference between a refusal and a `RangeError` out of the stack.
 */
function capOf(asked: number | undefined, fallback: number, ceiling = Number.MAX_SAFE_INTEGER) {
  return Math.min(Number.isFinite(asked) ? (asked as number) : fallback, ceiling);
}

const SPACE = new Set([0x20, 0x09, 0x0a, 0x0d]);

function isNameStart(code: number): boolean {
  return (
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x5f ||
    code === 0x3a ||
    code >= 0x80
  );
}

function isNameChar(code: number): boolean {
  return isNameStart(code) || (code >= 0x30 && code <= 0x39) || code === 0x2d || code === 0x2e;
}

/**
 * A recursive-descent parser over the subset of XML these protocols send.
 *
 * What it accepts: an optional declaration, comments and processing
 * instructions anywhere they are legal, namespace prefixes (resolved against
 * the declarations in scope), the five predefined entities, numeric character
 * references, CDATA sections, and attributes (parsed for well-formedness, then
 * discarded — `xmlns` and `xmlns:*` are the only ones whose values are kept).
 *
 * What it refuses, by construction rather than by check: **there is no DTD
 * subsystem**. `<!DOCTYPE` is a refusal wherever it appears and no other `<!`
 * markup declaration is recognized, so an entity can only ever be one of the
 * five predefined names or a numeric reference. Billion laughs has nothing to
 * expand and XXE has nothing to resolve.
 *
 * Every loop advances or throws, and the content loop asserts that it did:
 * a parser that hangs on hostile input is as bad as one that crashes.
 */
class XmlParser {
  readonly #text: string;
  readonly #maxDepth: number;
  readonly #maxElements: number;
  #at = 0;
  #elements = 0;

  constructor(text: string, limits: XmlParseLimits) {
    this.#text = text;
    this.#maxDepth = capOf(limits.maxDepth, XML_MAX_DEPTH, XML_MAX_DEPTH_CEILING);
    this.#maxElements = capOf(limits.maxElements, XML_MAX_ELEMENTS);
  }

  #fail(reason: XmlRefusal, message: string): XmlError {
    return new XmlError(reason, message, this.#at);
  }

  #starts(prefix: string): boolean {
    return this.#text.startsWith(prefix, this.#at);
  }

  #skipSpace(): void {
    while (SPACE.has(this.#text.charCodeAt(this.#at))) {
      this.#at++;
    }
  }

  /** Comments, processing instructions and whitespace, in any order. */
  #skipMisc(): void {
    for (;;) {
      this.#skipSpace();
      if (this.#starts("<!--")) {
        this.#skipComment();
        continue;
      }
      if (this.#starts("<?")) {
        this.#skipProcessingInstruction();
        continue;
      }
      if (this.#starts("<!")) {
        throw this.#markupRefusal();
      }
      return;
    }
  }

  #skipComment(): void {
    const end = this.#text.indexOf("-->", this.#at + 4);
    if (end === -1) {
      throw this.#fail("malformed", "unterminated comment");
    }
    this.#at = end + 3;
  }

  #skipProcessingInstruction(): void {
    const end = this.#text.indexOf("?>", this.#at + 2);
    if (end === -1) {
      throw this.#fail("malformed", "unterminated processing instruction");
    }
    this.#at = end + 2;
  }

  /**
   * `<!` is either a DOCTYPE — named, because it is the interesting refusal —
   * or another markup declaration this parser has no subsystem for. Both are
   * refused; neither is skipped.
   */
  #markupRefusal(): XmlError {
    return this.#text.slice(this.#at, this.#at + 9).toUpperCase() === "<!DOCTYPE"
      ? this.#fail("doctype", "a DOCTYPE declaration is never processed")
      : this.#fail("malformed", "unsupported markup declaration");
  }

  #qname(): string {
    const start = this.#at;
    if (!isNameStart(this.#text.charCodeAt(this.#at))) {
      throw this.#fail("malformed", "expected an element or attribute name");
    }
    this.#at++;
    while (isNameChar(this.#text.charCodeAt(this.#at))) {
      this.#at++;
    }
    return this.#text.slice(start, this.#at);
  }

  /**
   * One attribute, and the namespace declaration it was if it was one.
   *
   * Every attribute is parsed for well-formedness, exactly as before; the
   * **value** is kept only for `xmlns` and `xmlns:*`, which are the only
   * attributes either grammar reads. A body full of long attribute values still
   * costs this parser the scan and no allocation.
   */
  #attribute(): NamespaceDeclaration | undefined {
    const qname = this.#qname();
    const declaring = qname === "xmlns" || qname.startsWith("xmlns:");
    this.#skipSpace();
    if (this.#text.charCodeAt(this.#at) !== 0x3d) {
      throw this.#fail("malformed", "expected = after an attribute name");
    }
    this.#at++;
    this.#skipSpace();
    const quote = this.#text.charCodeAt(this.#at);
    if (quote !== 0x22 && quote !== 0x27) {
      throw this.#fail("malformed", "attribute value is not quoted");
    }
    this.#at++;
    let uri = "";
    for (;;) {
      const start = this.#at;
      for (;;) {
        const code = this.#text.charCodeAt(this.#at);
        if (Number.isNaN(code)) {
          throw this.#fail("malformed", "unterminated attribute value");
        }
        if (code === quote || code === 0x26) {
          break;
        }
        if (code === 0x3c) {
          throw this.#fail("malformed", "< in an attribute value");
        }
        this.#at++;
      }
      if (declaring) {
        uri += this.#text.slice(start, this.#at);
      }
      if (this.#text.charCodeAt(this.#at) === quote) {
        this.#at++;
        return declaring ? { prefix: qname === "xmlns" ? "" : qname.slice(6), uri } : undefined;
      }
      const resolved = this.#entity();
      if (declaring) {
        uri += resolved;
      }
    }
  }

  /**
   * At `&`; consumes through `;` and answers what it stood for.
   *
   * The accepted grammar, exactly: `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`,
   * `&#D;` where `D` is 1–10 decimal digits, and `&#xH;`/`&#XH;` where `H` is
   * 1–10 hexadecimal digits in either case. Ten digits in **both** forms, so
   * leading zeros are tolerated to the same depth whichever radix a client
   * wrote — a rule that differed between the two would refuse `&#x0000041;`
   * while accepting `&#0000065;`, which is the same character. Anything the
   * digits add up to is then range-checked, so the width is only a scan bound.
   */
  #entity(): string {
    const semicolon = this.#text.indexOf(";", this.#at + 1);
    /* `&` + `#x` + ten digits, and no further: an unterminated `&` in a
       megabyte of text must not scan the whole megabyte. */
    if (semicolon === -1 || semicolon - this.#at > 13) {
      throw this.#fail("entity", "unterminated entity reference");
    }
    const body = this.#text.slice(this.#at + 1, semicolon);
    this.#at = semicolon + 1;
    switch (body) {
      case "amp": {
        return "&";
      }
      case "lt": {
        return "<";
      }
      case "gt": {
        return ">";
      }
      case "quot": {
        return '"';
      }
      case "apos": {
        return "'";
      }
      default: {
        break;
      }
    }
    if (!body.startsWith("#")) {
      throw this.#fail("entity", `&${body}; is not one of the five predefined entities`);
    }
    const hex = body.startsWith("#x") || body.startsWith("#X");
    const digits = body.slice(hex ? 2 : 1);
    const shaped = hex ? /^[\da-f]{1,10}$/i.test(digits) : /^\d{1,10}$/.test(digits);
    if (!shaped) {
      throw this.#fail("entity", `&${body}; is not a character reference`);
    }
    const code = Number.parseInt(digits, hex ? 16 : 10);
    /* Deliberately the encoder's predicate, not XML's: see the module docs.
       `&#0;` is refused here rather than becoming a NUL in an object key. */
    if (code > 0x10_ff_ff || !isXmlChar(code)) {
      throw this.#fail("entity", `&${body}; is not a character this codec carries`);
    }
    return String.fromCodePoint(code);
  }

  /** Text up to the next `<`, entities resolved. Always consumes something. */
  #textRun(): string {
    let text = "";
    for (;;) {
      const start = this.#at;
      while (this.#at < this.#text.length) {
        const code = this.#text.charCodeAt(this.#at);
        if (code === 0x3c || code === 0x26) {
          break;
        }
        this.#at++;
      }
      text += this.#text.slice(start, this.#at);
      if (this.#text.charCodeAt(this.#at) !== 0x26) {
        return text;
      }
      text += this.#entity();
    }
  }

  /**
   * The element is built **after** its start tag is read, because a declaration
   * anywhere in that tag binds the element's own prefix: `<D:prop xmlns:D="…">`
   * is in `DAV:`, and a parser that resolved the name before reaching the
   * attribute would have said it was in no namespace.
   */
  #element(depth: number, inherited: Namespaces): ParsedElement {
    if (depth > this.#maxDepth) {
      throw this.#fail("depth", `nested deeper than ${this.#maxDepth} elements`);
    }
    this.#elements++;
    if (this.#elements > this.#maxElements) {
      throw this.#fail("too-many-elements", `body has more than ${this.#maxElements} elements`);
    }
    this.#at++;
    const qname = this.#qname();
    let declarations: NamespaceDeclaration[] | undefined;
    let empty = false;
    for (;;) {
      const spaced = SPACE.has(this.#text.charCodeAt(this.#at));
      this.#skipSpace();
      const code = this.#text.charCodeAt(this.#at);
      if (code === 0x3e) {
        this.#at++;
        break;
      }
      if (code === 0x2f) {
        if (this.#text.charCodeAt(this.#at + 1) !== 0x3e) {
          throw this.#fail("malformed", "expected /> to close an empty element");
        }
        this.#at += 2;
        empty = true;
        break;
      }
      if (Number.isNaN(code)) {
        throw this.#fail("malformed", `unterminated <${qname}> start tag`);
      }
      if (!spaced) {
        throw this.#fail("malformed", "expected whitespace before an attribute");
      }
      const declaration = this.#attribute();
      if (declaration !== undefined) {
        (declarations ??= []).push(declaration);
      }
    }
    const scope = scopeWith(inherited, declarations);
    const element: ParsedElement = {
      name: localName(qname),
      ns: namespaceOf(qname, scope),
      text: "",
      children: [],
    };
    if (!empty) {
      this.#content(element, qname, depth, scope);
    }
    return element;
  }

  #content(element: ParsedElement, qname: string, depth: number, scope: Namespaces): void {
    for (;;) {
      const before = this.#at;
      if (this.#at >= this.#text.length) {
        throw this.#fail("malformed", `unterminated <${qname}>`);
      }
      if (this.#starts("</")) {
        this.#at += 2;
        const closing = this.#qname();
        this.#skipSpace();
        if (this.#text.charCodeAt(this.#at) !== 0x3e) {
          throw this.#fail("malformed", `unterminated </${closing}>`);
        }
        this.#at++;
        if (closing !== qname) {
          throw this.#fail("malformed", `</${closing}> closes <${qname}>`);
        }
        return;
      } else if (this.#starts("<!--")) {
        this.#skipComment();
      } else if (this.#starts("<![CDATA[")) {
        const end = this.#text.indexOf("]]>", this.#at + 9);
        if (end === -1) {
          throw this.#fail("malformed", "unterminated CDATA section");
        }
        element.text += this.#text.slice(this.#at + 9, end);
        this.#at = end + 3;
      } else if (this.#starts("<!")) {
        throw this.#markupRefusal();
      } else if (this.#starts("<?")) {
        this.#skipProcessingInstruction();
      } else if (this.#text.charCodeAt(this.#at) === 0x3c) {
        element.children.push(this.#element(depth + 1, scope));
      } else {
        element.text += this.#textRun();
      }
      /* Insurance, not logic: every branch above consumes at least one
         character today, and this is what keeps a future one from turning a
         malformed body into a spinning event loop. */
      if (this.#at === before) {
        throw this.#fail("malformed", "the parser made no progress");
      }
    }
  }

  parse(): ParsedElement {
    this.#skipMisc();
    if (this.#text.charCodeAt(this.#at) !== 0x3c) {
      throw this.#fail("malformed", "no root element");
    }
    const root = this.#element(1, ROOT_NAMESPACES);
    this.#skipMisc();
    if (this.#at < this.#text.length) {
      throw this.#fail("malformed", "trailing content after the root element");
    }
    return root;
  }
}

/** `s3:Delete` is `Delete`; {@link namespaceOf} takes the other half. */
function localName(qname: string): string {
  const colon = qname.lastIndexOf(":");
  return colon === -1 ? qname : qname.slice(colon + 1);
}

/**
 * Parse a bounded XML document to its element tree. Throws {@link XmlError} and
 * nothing else, for any input at all.
 *
 * **An unbound prefix is not a refusal.** Namespaces in XML makes one an error;
 * here the element is reported in no namespace instead, which for both
 * protocols means "not one of ours" — the safe reading, and the one that
 * arrives at the same answer as refusing without the collateral. Refusing would
 * be a new way for an S3 body to fail, on a path where prefixes have been
 * dropped unresolved since the gateway shipped and a client that never declared
 * one has always been answered; a WebDAV `PROPFIND` naming a property under an
 * undeclared prefix gets a `404` for a property this server does not have,
 * which is true.
 */
export function parseXml(input: Uint8Array | string, limits: XmlParseLimits = {}): ParsedElement {
  return new XmlParser(bodyText(input, capOf(limits.maxBytes, XML_MAX_BYTES)), limits).parse();
}
