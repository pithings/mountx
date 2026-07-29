/**
 * The S3 protocol's XML, both directions — and **only** the S3 protocol's XML.
 *
 * This is not a general XML library and must not grow into one. S3 sends a
 * fixed set of small documents and accepts exactly two, so what is here is a
 * builder for the eight responses this gateway produces and a bounded parser
 * for the two request bodies it takes. Anything an S3 client cannot send has no
 * reason to be parseable, and every feature left out is one that cannot be
 * turned against the server.
 *
 * Transcribed from the **Amazon S3 API Reference**: the "Response Syntax" and
 * "Examples" blocks of `ListBuckets`, `ListObjectsV2`, `DeleteObjects`,
 * `CopyObject`, `CreateMultipartUpload`, `CompleteMultipartUpload` and
 * `ListParts`, plus the "Error responses" page for `<Error>`. Each encoder
 * names its page; the goldens in `test/s3/xml.test.ts` name them again beside
 * the bytes.
 *
 * ## One notion of a valid character, applied in both directions
 *
 * XML 1.0 cannot carry every code point, and the values reaching this module
 * are the least trustworthy in the system: object keys are arbitrary UTF-8,
 * header values arrive latin-1-decoded (so C1 controls appear as real
 * characters), and `sigv4.ts`'s `quote()` truncates a refusal detail at a fixed
 * character count — which can cut an astral pair in half and hand `<Message>` a
 * lone surrogate.
 *
 * {@link isXmlChar} is the single answer to "can this character exist in an S3
 * document", and both halves use it:
 *
 * - The **encoder replaces** what it rejects with U+FFFD. It never throws: an
 *   error response that cannot encode is a request with no reply at all, which
 *   is the one failure mode a gateway must not have (`AGENTS.md`: exactly one
 *   well-formed reply per request).
 * - The **parser refuses** a document containing one, whether it arrived raw or
 *   as a numeric character reference. `&#0;` is a refusal, never a NUL in a key.
 *
 * Together those give the property worth having: **every key the parser accepts
 * is a key the encoder emits unchanged.** A round trip through this codec is
 * exact or it does not happen.
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
 * normalizes line endings in content: a raw CR in a key would come back as LF
 * and the round-trip property above would be a lie. AWS does the same — the
 * `DeleteObjects` examples show a key with a CR in it written `&#13;`.
 *
 * The reverse half of that rule is a **deliberate deviation from XML 1.0
 * §2.11**: this parser does *not* normalize CR and CRLF in its input to LF. A
 * conformant parser would, and doing so would silently rewrite any key
 * containing one — which is the same corruption the `&#13;` escape exists to
 * prevent, arriving from the other direction. A client that means CR sends
 * `&#13;` and gets CR; a client that sends a raw CR gets a raw CR. The
 * normalizing behavior is unreachable for the documents S3 defines, since none
 * of them is line-oriented.
 *
 * ## Everything here is pure
 *
 * No I/O, no clock, no `Date`: timestamps arrive as strings already formatted
 * by the caller. Encoding is deterministic — the same input is the same bytes,
 * always, with no whitespace between elements and nothing that depends on
 * object key order.
 */

import { MAX_PARTS } from "./constants.ts";

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

/** The namespace AWS puts on every S3 result document except `<Error>`. */
export const S3_XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/";

/** The declaration every response starts with. */
export const XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8"?>';

/** What an element can hold as text. Rendered with `String()`, escaped once. */
export type XmlText = string | number | bigint | boolean;

/**
 * One element of a response document.
 *
 * `name` is always a literal from this module — never client data — so it is
 * emitted verbatim and unvalidated; that is what keeps the encoder total. An
 * element with both `text` and `children` writes the text first, a shape no S3
 * document has and no caller here produces.
 *
 * `children` accepts `undefined` entries so an optional element can be written
 * as one conditional expression and dropped by the serializer, which is what
 * keeps the output deterministic without a mutable array anywhere.
 */
export interface XmlNode {
  name: string;
  text?: XmlText;
  children?: readonly (XmlNode | undefined)[];
}

function renderText(value: XmlText): string {
  return typeof value === "string" ? value : String(value);
}

function renderElement(node: XmlNode, attributes = ""): string {
  let inner = node.text === undefined ? "" : escapeXmlText(renderText(node.text));
  for (const child of node.children ?? []) {
    if (child !== undefined) {
      inner += renderElement(child);
    }
  }
  return `<${node.name}${attributes}>${inner}</${node.name}>`;
}

/**
 * A whole document: the declaration, then the root element, with no whitespace
 * anywhere between them. `xmlns` is written on the root when given.
 */
export function xmlDocument(root: XmlNode, options: { xmlns?: string } = {}): string {
  const attributes = options.xmlns === undefined ? "" : ` xmlns="${escapeXmlText(options.xmlns)}"`;
  return XML_DECLARATION + renderElement(root, attributes);
}

/** An element that exists only when its value does. */
function optionalNode(name: string, text: XmlText | undefined): XmlNode | undefined {
  return text === undefined ? undefined : { name, text };
}

// ---------------------------------------------------------------------------
// the response documents
// ---------------------------------------------------------------------------

/** An `<Owner>` or `<Initiator>` block. */
export interface S3Owner {
  id: string;
  displayName?: string;
}

function ownerNode(name: string, owner: S3Owner | undefined): XmlNode | undefined {
  return owner === undefined
    ? undefined
    : {
        name,
        children: [{ name: "ID", text: owner.id }, optionalNode("DisplayName", owner.displayName)],
      };
}

/**
 * The error document (S3 API Reference, "Error responses").
 *
 * The one document with **no** `xmlns`: AWS sends `<Error>` bare, and a client
 * matching on the namespace would be matching on something S3 never sends.
 */
export interface S3ErrorDocument {
  /** The `<Code>`, e.g. `NoSuchKey` — `constants.ts` owns the table of them. */
  code: string;
  message: string;
  /** The bucket/key the request named, when there is one. */
  resource?: string;
  requestId?: string;
  hostId?: string;
}

export function encodeS3ErrorDocument(error: S3ErrorDocument): string {
  return xmlDocument({
    name: "Error",
    children: [
      { name: "Code", text: error.code },
      { name: "Message", text: error.message },
      optionalNode("Resource", error.resource),
      optionalNode("RequestId", error.requestId),
      optionalNode("HostId", error.hostId),
    ],
  });
}

/** One `<Bucket>` of a `ListBuckets` reply. */
export interface S3BucketEntry {
  name: string;
  /** ISO 8601, formatted by the caller — this module owns no clock. */
  creationDate: string;
}

/** `ListBuckets` (S3 API Reference, `ListBuckets` → Examples). */
export interface ListAllMyBucketsResult {
  owner?: S3Owner;
  buckets: readonly S3BucketEntry[];
}

export function encodeListAllMyBucketsResult(result: ListAllMyBucketsResult): string {
  return xmlDocument(
    {
      name: "ListAllMyBucketsResult",
      children: [
        ownerNode("Owner", result.owner),
        {
          name: "Buckets",
          children: result.buckets.map((bucket) => ({
            name: "Bucket",
            children: [
              { name: "Name", text: bucket.name },
              { name: "CreationDate", text: bucket.creationDate },
            ],
          })),
        },
      ],
    },
    { xmlns: S3_XMLNS },
  );
}

/** One `<Contents>` entry of a `ListObjectsV2` reply. */
export interface S3ObjectEntry {
  key: string;
  /** ISO 8601, formatted by the caller. */
  lastModified: string;
  /** Quoted, as S3 sends it: the quotes are part of the value. */
  etag: string;
  size: number | bigint;
  storageClass?: string;
  owner?: S3Owner;
}

/**
 * `ListObjectsV2` (S3 API Reference, `ListObjectsV2` → Examples).
 *
 * Element order follows the reference's *example* responses rather than its
 * "Response Syntax" block, which lists the members in an order S3 itself does
 * not send. Read off the examples: `Name`, `Prefix`, then the cursor echoes
 * `ContinuationToken`, `NextContinuationToken` and `StartAfter`, then
 * `KeyCount`, `MaxKeys`, then `Delimiter`, then `IsTruncated`, then the
 * `Contents` and `CommonPrefixes` entries.
 *
 * `EncodingType` has no example to read an order off — it rides beside
 * `Delimiter`, the other echo of a request parameter. It is emitted when the
 * caller asks for it; **URL-encoding the keys themselves is the session's
 * job**, not this module's.
 */
export interface ListBucketResult {
  name: string;
  /** Always emitted, empty when the request had none — as S3 does. */
  prefix?: string;
  continuationToken?: string;
  nextContinuationToken?: string;
  startAfter?: string;
  keyCount: number;
  maxKeys: number;
  delimiter?: string;
  encodingType?: string;
  isTruncated: boolean;
  contents: readonly S3ObjectEntry[];
  commonPrefixes?: readonly string[];
}

export function encodeListBucketResult(result: ListBucketResult): string {
  return xmlDocument(
    {
      name: "ListBucketResult",
      children: [
        { name: "Name", text: result.name },
        { name: "Prefix", text: result.prefix ?? "" },
        optionalNode("ContinuationToken", result.continuationToken),
        optionalNode("NextContinuationToken", result.nextContinuationToken),
        optionalNode("StartAfter", result.startAfter),
        { name: "KeyCount", text: result.keyCount },
        { name: "MaxKeys", text: result.maxKeys },
        optionalNode("Delimiter", result.delimiter),
        optionalNode("EncodingType", result.encodingType),
        { name: "IsTruncated", text: result.isTruncated },
        ...result.contents.map((entry) => ({
          name: "Contents",
          children: [
            { name: "Key", text: entry.key },
            { name: "LastModified", text: entry.lastModified },
            { name: "ETag", text: entry.etag },
            { name: "Size", text: entry.size },
            optionalNode("StorageClass", entry.storageClass),
            ownerNode("Owner", entry.owner),
          ],
        })),
        ...(result.commonPrefixes ?? []).map((prefix) => ({
          name: "CommonPrefixes",
          children: [{ name: "Prefix", text: prefix }],
        })),
      ],
    },
    { xmlns: S3_XMLNS },
  );
}

/** One key `DeleteObjects` removed. */
export interface DeletedEntry {
  key: string;
}

/** One key `DeleteObjects` could not remove. */
export interface DeleteErrorEntry {
  key: string;
  code: string;
  message: string;
}

/** `DeleteObjects` (S3 API Reference, `DeleteObjects` → Examples). */
export interface DeleteResult {
  deleted: readonly DeletedEntry[];
  errors: readonly DeleteErrorEntry[];
}

export function encodeDeleteResult(result: DeleteResult): string {
  return xmlDocument(
    {
      name: "DeleteResult",
      children: [
        ...result.deleted.map((entry) => ({
          name: "Deleted",
          children: [{ name: "Key", text: entry.key }],
        })),
        ...result.errors.map((entry) => ({
          name: "Error",
          children: [
            { name: "Key", text: entry.key },
            { name: "Code", text: entry.code },
            { name: "Message", text: entry.message },
          ],
        })),
      ],
    },
    { xmlns: S3_XMLNS },
  );
}

/**
 * `CopyObject` (S3 API Reference, `CopyObject` → Examples).
 *
 * The reference's example shows the element bare — no declaration and no
 * `xmlns` — where real S3 sends both, as it does for every other result
 * document. What is followed here is the wire, not the sample: the values and
 * their order are the reference's, the framing is what a client actually
 * receives.
 */
export interface CopyObjectResult {
  lastModified: string;
  etag: string;
}

export function encodeCopyObjectResult(result: CopyObjectResult): string {
  return xmlDocument(
    {
      name: "CopyObjectResult",
      children: [
        { name: "LastModified", text: result.lastModified },
        { name: "ETag", text: result.etag },
      ],
    },
    { xmlns: S3_XMLNS },
  );
}

/** `CreateMultipartUpload` (S3 API Reference, `CreateMultipartUpload`). */
export interface InitiateMultipartUploadResult {
  bucket: string;
  key: string;
  uploadId: string;
}

export function encodeInitiateMultipartUploadResult(result: InitiateMultipartUploadResult): string {
  return xmlDocument(
    {
      name: "InitiateMultipartUploadResult",
      children: [
        { name: "Bucket", text: result.bucket },
        { name: "Key", text: result.key },
        { name: "UploadId", text: result.uploadId },
      ],
    },
    { xmlns: S3_XMLNS },
  );
}

/** `CompleteMultipartUpload` (S3 API Reference, `CompleteMultipartUpload`). */
export interface CompleteMultipartUploadResult {
  location: string;
  bucket: string;
  key: string;
  etag: string;
}

export function encodeCompleteMultipartUploadResult(result: CompleteMultipartUploadResult): string {
  return xmlDocument(
    {
      name: "CompleteMultipartUploadResult",
      children: [
        { name: "Location", text: result.location },
        { name: "Bucket", text: result.bucket },
        { name: "Key", text: result.key },
        { name: "ETag", text: result.etag },
      ],
    },
    { xmlns: S3_XMLNS },
  );
}

/** One `<Part>` of a `ListParts` reply. */
export interface S3PartEntry {
  partNumber: number;
  lastModified: string;
  etag: string;
  size: number | bigint;
}

/** `ListParts` (S3 API Reference, `ListParts` → Examples). */
export interface ListPartsResult {
  bucket: string;
  key: string;
  uploadId: string;
  initiator?: S3Owner;
  owner?: S3Owner;
  storageClass?: string;
  partNumberMarker: number;
  nextPartNumberMarker?: number;
  maxParts: number;
  isTruncated: boolean;
  parts: readonly S3PartEntry[];
}

export function encodeListPartsResult(result: ListPartsResult): string {
  return xmlDocument(
    {
      name: "ListPartsResult",
      children: [
        { name: "Bucket", text: result.bucket },
        { name: "Key", text: result.key },
        { name: "UploadId", text: result.uploadId },
        ownerNode("Initiator", result.initiator),
        ownerNode("Owner", result.owner),
        optionalNode("StorageClass", result.storageClass),
        { name: "PartNumberMarker", text: result.partNumberMarker },
        optionalNode("NextPartNumberMarker", result.nextPartNumberMarker),
        { name: "MaxParts", text: result.maxParts },
        { name: "IsTruncated", text: result.isTruncated },
        ...result.parts.map((part) => ({
          name: "Part",
          children: [
            { name: "PartNumber", text: part.partNumber },
            { name: "LastModified", text: part.lastModified },
            { name: "ETag", text: part.etag },
            { name: "Size", text: part.size },
          ],
        })),
      ],
    },
    { xmlns: S3_XMLNS },
  );
}

// ---------------------------------------------------------------------------
// the parser
// ---------------------------------------------------------------------------

/**
 * Why a body was refused. Every one of these is a name a caller can turn into
 * an S3 error code without reading the message — `MalformedXML` for the
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
 * Default byte budget, 4 MiB. Generous for both bodies this parser accepts —
 * a 1000-key `DeleteObjects` runs to about a megabyte at S3's own key limit —
 * and callers pass the request's `Content-Length` cap instead of relying on it.
 */
export const XML_MAX_BYTES = 4 * 1024 * 1024;

/** Deepest element nesting. Both accepted grammars are three deep. */
export const XML_MAX_DEPTH = 32;

/**
 * The ceiling a caller's `maxDepth` is clamped to, whatever it asks for.
 *
 * `#element` recurses, so the depth cap is what keeps a nested body off the
 * JavaScript stack — which makes an *unbounded* `maxDepth` a hole in the "throws
 * `XmlError` and nothing else" contract: hand this a `maxDepth` of a few
 * thousand and a deep enough body and the throw is a `RangeError` from the
 * engine, not a refusal. 256 is an order of magnitude below where any Node
 * default stack gives out, and three orders above the deepest body S3 defines.
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
   * the server passes the `Content-Length` cap it is willing to buffer.
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
 * One parsed element: its **local** name (any namespace prefix is dropped), its
 * text content, and its children.
 *
 * Text is the concatenation of every text run and CDATA section directly inside
 * the element; for the leaves these grammars read, that is the value. Mixed
 * content is not a thing S3 sends and not a thing this parser models beyond
 * this.
 */
export interface ParsedElement {
  name: string;
  text: string;
  children: ParsedElement[];
}

/**
 * `fatal: true`, which is the opposite of what the rest of this project does
 * with a name off the wire — and the difference is deliberate.
 *
 * A FUSE or NFS name that is not valid UTF-8 is decoded lossily because the
 * name is really *bytes* and the caller already knows which file it means. An
 * S3 body is not: `<Key>` is the only identification of the object, so a byte
 * that silently becomes U+FFFD is a `DeleteObjects` that deletes a different
 * key than the one asked for, or misses the one it named. There is no safe
 * guess, so there is no guess — a body that is not UTF-8 is refused, the same
 * posture `drivers/unstorage.ts` takes with a key it cannot represent.
 */
const decoder = new TextDecoder("utf8", { fatal: true });

/**
 * First offset holding a character {@link isXmlChar} rejects, or `-1`.
 *
 * Run once over the whole body before parsing, which is what lets every later
 * step assume its text is emittable: a raw NUL, a latin-1 C1 control or a lone
 * surrogate is refused here rather than surviving into a key.
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
 * A recursive-descent parser over the subset of XML an S3 client sends.
 *
 * What it accepts: an optional declaration, comments and processing
 * instructions anywhere they are legal, namespace prefixes (dropped), the five
 * predefined entities, numeric character references, CDATA sections, and
 * attributes (parsed for well-formedness, then discarded — the only one S3
 * bodies carry is `xmlns`).
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

  /** Well-formedness only: the value is parsed and thrown away. */
  #attribute(): void {
    this.#qname();
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
    for (;;) {
      const code = this.#text.charCodeAt(this.#at);
      if (Number.isNaN(code)) {
        throw this.#fail("malformed", "unterminated attribute value");
      }
      if (code === quote) {
        this.#at++;
        return;
      }
      if (code === 0x3c) {
        throw this.#fail("malformed", "< in an attribute value");
      }
      if (code === 0x26) {
        this.#entity();
        continue;
      }
      this.#at++;
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

  #element(depth: number): ParsedElement {
    if (depth > this.#maxDepth) {
      throw this.#fail("depth", `nested deeper than ${this.#maxDepth} elements`);
    }
    this.#elements++;
    if (this.#elements > this.#maxElements) {
      throw this.#fail("too-many-elements", `body has more than ${this.#maxElements} elements`);
    }
    this.#at++;
    const qname = this.#qname();
    const element: ParsedElement = { name: localName(qname), text: "", children: [] };
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
        return element;
      }
      if (Number.isNaN(code)) {
        throw this.#fail("malformed", `unterminated <${qname}> start tag`);
      }
      if (!spaced) {
        throw this.#fail("malformed", "expected whitespace before an attribute");
      }
      this.#attribute();
    }
    this.#content(element, qname, depth);
    return element;
  }

  #content(element: ParsedElement, qname: string, depth: number): void {
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
        element.children.push(this.#element(depth + 1));
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
    const root = this.#element(1);
    this.#skipMisc();
    if (this.#at < this.#text.length) {
      throw this.#fail("malformed", "trailing content after the root element");
    }
    return root;
  }
}

/** `s3:Delete` is `Delete`: prefixes are dropped, not resolved. */
function localName(qname: string): string {
  const colon = qname.lastIndexOf(":");
  return colon === -1 ? qname : qname.slice(colon + 1);
}

/**
 * Parse a bounded XML document to its element tree. Throws {@link XmlError} and
 * nothing else, for any input at all.
 */
export function parseXml(input: Uint8Array | string, limits: XmlParseLimits = {}): ParsedElement {
  return new XmlParser(bodyText(input, capOf(limits.maxBytes, XML_MAX_BYTES)), limits).parse();
}

// ---------------------------------------------------------------------------
// the two request bodies
// ---------------------------------------------------------------------------

function requireRoot(root: ParsedElement, name: string): void {
  if (root.name !== name) {
    throw new XmlError("unexpected-root", `expected a <${name}> body, found <${root.name}>`);
  }
}

function childrenNamed(element: ParsedElement, name: string): ParsedElement[] {
  return element.children.filter((child) => child.name === name);
}

/**
 * The one child with this name.
 *
 * Missing and duplicated are both refusals: unknown elements are skipped
 * because SDKs add fields over time, but two `<Key>` elements in one `<Object>`
 * is a body whose meaning nobody agrees on, and guessing which one wins is how
 * a gateway deletes the wrong object.
 */
function requireOne(element: ParsedElement, name: string, where: string): ParsedElement {
  const matches = childrenNamed(element, name);
  const only = matches[0];
  if (only === undefined) {
    throw new XmlError("missing-field", `${where} has no <${name}>`);
  }
  if (matches.length > 1) {
    throw new XmlError("duplicate-field", `${where} has ${matches.length} <${name}> elements`);
  }
  return only;
}

function optionalOne(element: ParsedElement, name: string, where: string): string | undefined {
  const matches = childrenNamed(element, name);
  if (matches.length > 1) {
    throw new XmlError("duplicate-field", `${where} has ${matches.length} <${name}> elements`);
  }
  return matches[0]?.text;
}

/** ASCII whitespace only, so that a key's own U+00A0 is never trimmed off it. */
function trim(value: string): string {
  return value.replaceAll(/^[ \t\r\n]+|[ \t\r\n]+$/g, "");
}

/** One `<Object>` of a `DeleteObjects` body. */
export interface DeleteObjectsEntry {
  /**
   * The key, **verbatim**: not trimmed, because a leading or trailing space is
   * a legal part of an S3 key and trimming it would delete a different object
   * than the one asked for.
   */
  key: string;
  /** Parsed because clients send it; this gateway has no versioning. */
  versionId?: string;
}

/** A parsed `DeleteObjects` request body. */
export interface DeleteObjectsRequest {
  objects: readonly DeleteObjectsEntry[];
  /** `<Quiet>`: report only the failures. Absent means `false`. */
  quiet: boolean;
}

function parseBoolean(value: string, where: string): boolean {
  switch (trim(value).toLowerCase()) {
    case "true":
    case "1": {
      return true;
    }
    case "false":
    case "0": {
      return false;
    }
    default: {
      throw new XmlError("invalid-field", `${where} is not a boolean`);
    }
  }
}

/**
 * `<Delete><Object><Key>…</Key></Object>…<Quiet>…</Quiet></Delete>`, the
 * `DeleteObjects` request body (S3 API Reference, `DeleteObjects`).
 *
 * The object count is bounded by the element cap rather than by S3's own
 * 1000-per-request limit: that limit is a policy the session enforces with a
 * proper S3 error, not a fact about the grammar.
 */
export function parseDeleteObjects(
  input: Uint8Array | string,
  limits: XmlParseLimits = {},
): DeleteObjectsRequest {
  const root = parseXml(input, limits);
  requireRoot(root, "Delete");
  const objects = childrenNamed(root, "Object").map((object) => {
    const versionId = optionalOne(object, "VersionId", "<Object>");
    const entry: DeleteObjectsEntry = { key: requireOne(object, "Key", "<Object>").text };
    return versionId === undefined ? entry : { ...entry, versionId: trim(versionId) };
  });
  if (objects.length === 0) {
    throw new XmlError("missing-field", "<Delete> has no <Object> elements");
  }
  const quiet = optionalOne(root, "Quiet", "<Delete>");
  return { objects, quiet: quiet === undefined ? false : parseBoolean(quiet, "<Quiet>") };
}

/** One `<Part>` of a `CompleteMultipartUpload` body. */
export interface CompletedPart {
  partNumber: number;
  /**
   * The ETag **exactly as it arrived**, quotes included — clients send
   * `"abc-1"` and the session compares against what it handed out. Only
   * surrounding whitespace is removed, so that a pretty-printed body works.
   */
  etag: string;
}

/** A parsed `CompleteMultipartUpload` request body. */
export interface CompleteMultipartUploadRequest {
  parts: readonly CompletedPart[];
}

/**
 * `<CompleteMultipartUpload><Part><PartNumber>…</PartNumber><ETag>…</ETag>
 * </Part>…</CompleteMultipartUpload>` (S3 API Reference,
 * `CompleteMultipartUpload`).
 *
 * Part *numbers* are range-checked here because `1..MAX_PARTS` is a fact about
 * the protocol. Part *order* is not: "ascending, no gaps that matter" is the
 * session's rule to enforce against the parts it actually staged, and it needs
 * the list as sent to say what was wrong.
 *
 * A `<PartNumber>` is 1–10 decimal digits with optional surrounding whitespace,
 * and then a value in `1..MAX_PARTS` — the width is deliberately far wider than
 * the range so that leading zeros are tolerated rather than turned into a
 * refusal that reads as "not a number", the same rule `#entity()` applies to a
 * character reference. No sign, no decimal point, no exponent: `1e3` is not a
 * part number, whatever `Number()` would make of it.
 */
export function parseCompleteMultipartUpload(
  input: Uint8Array | string,
  limits: XmlParseLimits = {},
): CompleteMultipartUploadRequest {
  const root = parseXml(input, limits);
  requireRoot(root, "CompleteMultipartUpload");
  const elements = childrenNamed(root, "Part");
  if (elements.length === 0) {
    throw new XmlError("missing-field", "<CompleteMultipartUpload> has no <Part> elements");
  }
  if (elements.length > MAX_PARTS) {
    throw new XmlError("invalid-field", `more than ${MAX_PARTS} parts`);
  }
  const parts = elements.map((part) => {
    const number = trim(requireOne(part, "PartNumber", "<Part>").text);
    if (!/^\d{1,10}$/.test(number)) {
      throw new XmlError("invalid-field", "<PartNumber> is not a number");
    }
    const partNumber = Number(number);
    if (partNumber < 1 || partNumber > MAX_PARTS) {
      throw new XmlError("invalid-field", `<PartNumber> ${partNumber} is outside 1..${MAX_PARTS}`);
    }
    const etag = trim(requireOne(part, "ETag", "<Part>").text);
    if (etag === "") {
      throw new XmlError("invalid-field", "<ETag> is empty");
    }
    return { partNumber, etag };
  });
  return { parts };
}
