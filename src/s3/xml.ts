/**
 * The S3 protocol's XML, both directions — and **only** the S3 protocol's XML.
 *
 * The codec underneath is `src/xml.ts`, shared with `mountx/webdav`: the
 * character rules, the document builder and the bounded parser live there, and
 * every symbol of that module is re-exported at the bottom of this one so
 * `mountx/s3`'s surface is unchanged and the gateway still reads as though it
 * owned them. What is left here is what only S3 has — a builder for the eight
 * responses this gateway produces and a reader for the two request bodies it
 * takes. Anything an S3 client cannot send has no reason to be parseable, and
 * every feature left out is one that cannot be turned against the server.
 *
 * Transcribed from the **Amazon S3 API Reference**: the "Response Syntax" and
 * "Examples" blocks of `ListBuckets`, `ListObjectsV2`, `DeleteObjects`,
 * `CopyObject`, `CreateMultipartUpload`, `CompleteMultipartUpload` and
 * `ListParts`, plus the "Error responses" page for `<Error>`. Each encoder
 * names its page; the goldens in `test/s3/xml.test.ts` name them again beside
 * the bytes.
 *
 * **Namespaces are not read here.** `src/xml.ts` resolves them and reports
 * both, and every match below is on the *local* name alone — `s3:Delete`,
 * `<Delete xmlns="…">` and a bare `<Delete>` are one element to this file.
 * That is what S3 clients rely on: AWS publishes these grammars without a
 * namespace and SDKs send them three different ways. WebDAV, whose property
 * names *are* namespace-qualified, reads the other field.
 *
 * Everything here is pure: no I/O, no clock, no `Date`. Timestamps arrive as
 * strings already formatted by the caller, and encoding is deterministic — the
 * same input is the same bytes, always.
 */

import {
  parseXml,
  XmlError,
  xmlDocument,
  type ParsedElement,
  type XmlNode,
  type XmlParseLimits,
  type XmlText,
} from "../xml.ts";
import { MAX_PARTS } from "./constants.ts";

/** The namespace AWS puts on every S3 result document except `<Error>`. */
export const S3_XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/";

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

// ---------------------------------------------------------------------------
// the codec underneath
// ---------------------------------------------------------------------------

/*
 * Re-exported so that this file is still the whole of the S3 gateway's XML as
 * far as the rest of `src/s3/` and `test/s3/` are concerned — the same
 * treatment `src/s3/protocol.ts` gives `src/http.ts`. `src/s3/index.ts` then
 * publishes the S3 half and keeps the generic primitives internal.
 */
export {
  escapeXmlText,
  isXmlChar,
  isXmlError,
  parseXml,
  XML_DECLARATION,
  XML_MAX_BYTES,
  XML_MAX_DEPTH,
  XML_MAX_DEPTH_CEILING,
  XML_MAX_ELEMENTS,
  XML_REPLACEMENT,
  XmlError,
  xmlDocument,
  type ParsedElement,
  type XmlNode,
  type XmlParseLimits,
  type XmlRefusal,
  type XmlText,
} from "../xml.ts";
