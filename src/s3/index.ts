/**
 * The S3 gateway: `mountx/s3`.
 *
 * A transport over the same `FsDriver`, and the one that is not a
 * mount: it serves the driver to an S3 client (`rclone`, the AWS CLI, an SDK,
 * a presigned URL in a browser) over HTTP, path-style, one bucket per driver.
 * Nothing here produces a mountpoint, which is why it is deliberately outside
 * `mountx/auto` — see `.agents/s3-plan.md`.
 *
 * Layered the way the other two transports are:
 *
 * - `constants.ts` — the errno → S3 error table, and the protocol's limits.
 * - `sigv4.ts` — AWS Signature Version 4, signed *and* verified: the canonical
 *   request, the signing key, the header and presigned-query forms.
 * - `xml.ts` — the response documents and the two request bodies, encoded and
 *   parsed, both bounded.
 * - `chunked.ts` — the `aws-chunked` /
 *   `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` framing, with per-chunk signatures.
 * - `protocol.ts` — pure request parsing and routing: URL to (bucket, key), the
 *   operation table, `Range` and the conditional headers, the error documents.
 * - `session.ts` — a request in, a reply out, over one or more drivers, with no
 *   socket anywhere.
 * - `server.ts` — the socket, and the only file that imports `node:http`.
 *
 * Everything except the last runs with no listener and no privileges, which is
 * what makes the whole protocol testable from a JS client built out of these
 * same codecs.
 */

export * from "./chunked.ts";
export * from "./constants.ts";
export * from "./protocol.ts";
export * from "./server.ts";
export * from "./session.ts";
export * from "./sigv4.ts";
// Everything from `xml.ts` **except** the generic XML layer it is built on
// (`XML_REPLACEMENT`, `isXmlChar`, `escapeXmlText`, `XmlText`, `XmlNode`,
// `xmlDocument`, `parseXml`, `ParsedElement`). Those are this module's
// primitives rather than anything a consumer of an S3 gateway composes with —
// the same treatment, and the same reason, as the sub-struct helpers `mountx/nfs`
// leaves out of its own index. They are still exported from `src/s3/xml.ts` for
// the tests.
export {
  type CompletedPart,
  type CompleteMultipartUploadRequest,
  type CompleteMultipartUploadResult,
  type CopyObjectResult,
  type DeletedEntry,
  type DeleteErrorEntry,
  type DeleteObjectsEntry,
  type DeleteObjectsRequest,
  type DeleteResult,
  encodeCompleteMultipartUploadResult,
  encodeCopyObjectResult,
  encodeDeleteResult,
  encodeInitiateMultipartUploadResult,
  encodeListAllMyBucketsResult,
  encodeListBucketResult,
  encodeListPartsResult,
  encodeS3ErrorDocument,
  type InitiateMultipartUploadResult,
  isXmlError,
  type ListAllMyBucketsResult,
  type ListBucketResult,
  type ListPartsResult,
  parseCompleteMultipartUpload,
  parseDeleteObjects,
  type S3BucketEntry,
  type S3ErrorDocument,
  type S3ObjectEntry,
  type S3Owner,
  type S3PartEntry,
  S3_XMLNS,
  XML_DECLARATION,
  XML_MAX_BYTES,
  XML_MAX_DEPTH,
  XML_MAX_DEPTH_CEILING,
  XML_MAX_ELEMENTS,
  XmlError,
  type XmlParseLimits,
  type XmlRefusal,
} from "./xml.ts";
