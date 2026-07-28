/**
 * S3 wire constants: the errno → S3 error mapping, and the protocol's limits.
 *
 * There is no RFC for S3. Everything here is transcribed from Amazon's own
 * published documentation and named where it is used:
 *
 * - **Amazon S3 API Reference, "Error responses"** — the `<Code>` strings and
 *   the HTTP status each one is returned with. Every code below appears on
 *   that page; nothing is invented, and where POSIX has a condition S3 has no
 *   name for, the comment says so and says which real code was chosen instead.
 * - **Amazon S3 User Guide, "Uploading and copying objects using multipart
 *   upload"** — the part-size and part-count limits.
 * - **Amazon S3 User Guide, "Creating object key names"** — the 1024-byte key
 *   limit.
 * - **AWS SigV4 specification** — the two payload-hash sentinels.
 *
 * Real clients (rclone, curl, the AWS SDKs) are oracles for this transport,
 * never sources: what they accept is evidence, what Amazon documents is the
 * fact.
 */

import type { ErrnoCode } from "../errors.ts";

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/** One row of the error table: the S3 `<Code>` and the status it rides on. */
export interface S3Error {
  /** The `<Code>` element of the XML error document, e.g. `NoSuchKey`. */
  code: string;
  /** The HTTP status S3 returns that code with. */
  status: number;
}

/**
 * The answer for anything this table has no row for.
 *
 * `InternalError` is the only safe default, and for the same reason `errnoOf()`
 * defaults to `EIO`: a request that gets no well-formed reply is worse than one
 * that gets an imprecise one, and S3 documents 500 as retryable.
 */
export const S3_INTERNAL_ERROR: S3Error = { code: "InternalError", status: 500 };

/**
 * Every errno a driver can throw, mapped to the S3 error a client should see.
 *
 * Typed as a total `Record<ErrnoCode, S3Error>` on purpose: adding an errno to
 * `src/errors.ts` should fail the typecheck here until somebody decides what S3
 * calls it, rather than silently falling through to `InternalError`.
 *
 * The judgment calls, and why:
 *
 * - **`ENOTEMPTY` → `BucketNotEmpty` (409).** S3 has exactly one code meaning
 *   "you cannot delete that, something is still inside it", and this is it. A
 *   directory is the prefix analogue of a bucket, so the code reads true even
 *   though the resource is not literally a bucket; the status is the part
 *   clients act on, and 409 is what the plan requires.
 * - **`EISDIR` → `InvalidRequest` (400).** The key names a prefix, not an
 *   object; the request is wrong as written, and no amount of retrying or
 *   re-authenticating changes that.
 * - **`ENOTDIR` → `NoSuchKey` (404).** A path component that is a file means
 *   the key *cannot* exist in this tree — "no such key" is the honest answer,
 *   not a server-side fault.
 * - **`EROFS` → `AccessDenied` (403).** Exactly what S3 answers for a write a
 *   bucket policy forbids, which is what a read-only driver is; clients treat
 *   403 as permanent, which is correct here.
 * - **`ENOSPC` / `EDQUOT` / `ENOMEM` → `ServiceUnavailable` (503).** S3 buckets
 *   do not fill up and S3 servers do not run out of memory, so there is no code
 *   for either. 503 is the only documented status meaning "the server cannot
 *   take this write right now", and it is the one that makes clients back off
 *   instead of corrupting their retry state. `ENOMEM` shares the row because it
 *   is the same event seen from the other resource: transient, the server's
 *   fault, and worth retrying.
 * - **`EAGAIN` / `EMFILE` / `ENFILE` → `SlowDown` (503).** Descriptor and
 *   resource exhaustion is backpressure, and `SlowDown` is S3's word for it.
 * - **`EEXIST` / `EBUSY` → `OperationAborted` (409).** S3's generic conflict:
 *   "a conflicting conditional operation is currently in progress against this
 *   resource".
 * - **`ESTALE` → `NoSuchKey` (404).** The object the handle named is gone.
 * - **`ENAMETOOLONG` → `KeyTooLongError` (400).** S3's own name for it.
 * - **`ERANGE`** stays `InternalError`: a *driver* reporting `ERANGE` is not
 *   the same event as a bad `Range` header, and the session answers the latter
 *   with `InvalidRange` (416) itself rather than routing it through here.
 */
export const ERRNO_S3_ERRORS: Record<ErrnoCode, S3Error> = {
  EPERM: { code: "AccessDenied", status: 403 },
  ENOENT: { code: "NoSuchKey", status: 404 },
  EINTR: S3_INTERNAL_ERROR,
  EIO: S3_INTERNAL_ERROR,
  ENXIO: S3_INTERNAL_ERROR,
  EBADF: S3_INTERNAL_ERROR,
  EAGAIN: { code: "SlowDown", status: 503 },
  ENOMEM: { code: "ServiceUnavailable", status: 503 },
  EACCES: { code: "AccessDenied", status: 403 },
  EBUSY: { code: "OperationAborted", status: 409 },
  EEXIST: { code: "OperationAborted", status: 409 },
  EXDEV: S3_INTERNAL_ERROR,
  ENODEV: S3_INTERNAL_ERROR,
  ENOTDIR: { code: "NoSuchKey", status: 404 },
  EISDIR: { code: "InvalidRequest", status: 400 },
  EINVAL: { code: "InvalidArgument", status: 400 },
  ENFILE: { code: "SlowDown", status: 503 },
  EMFILE: { code: "SlowDown", status: 503 },
  EFBIG: { code: "EntityTooLarge", status: 400 },
  ENOSPC: { code: "ServiceUnavailable", status: 503 },
  ESPIPE: S3_INTERNAL_ERROR,
  EROFS: { code: "AccessDenied", status: 403 },
  EMLINK: S3_INTERNAL_ERROR,
  ERANGE: S3_INTERNAL_ERROR,
  ENAMETOOLONG: { code: "KeyTooLongError", status: 400 },
  ENOSYS: { code: "NotImplemented", status: 501 },
  ENOTEMPTY: { code: "BucketNotEmpty", status: 409 },
  ELOOP: S3_INTERNAL_ERROR,
  ENODATA: S3_INTERNAL_ERROR,
  EPROTO: S3_INTERNAL_ERROR,
  EOVERFLOW: S3_INTERNAL_ERROR,
  ENOTSUP: { code: "NotImplemented", status: 501 },
  ESTALE: { code: "NoSuchKey", status: 404 },
  EDQUOT: { code: "ServiceUnavailable", status: 503 },
};

/**
 * The S3 error for an errno name. Total: anything unrecognized — including
 * `undefined`, and including a `code` a driver invented — answers
 * `InternalError`.
 *
 * ```ts
 * s3ErrorOf("ENOENT"); // { code: "NoSuchKey", status: 404 }
 * s3ErrorOf("EWEIRD"); // { code: "InternalError", status: 500 }
 * ```
 */
export function s3ErrorOf(code: string | undefined): S3Error {
  if (code !== undefined && Object.hasOwn(ERRNO_S3_ERRORS, code)) {
    return ERRNO_S3_ERRORS[code as ErrnoCode];
  }
  return S3_INTERNAL_ERROR;
}

// ---------------------------------------------------------------------------
// protocol limits
// ---------------------------------------------------------------------------

/**
 * `ListObjectsV2`'s `MaxKeys`: both the default when the client sends none and
 * the ceiling when it asks for more (S3 API Reference, `ListObjectsV2`).
 */
export const MAX_KEYS = 1000;

/**
 * Smallest multipart part, 5 MiB — every part except the last must reach it
 * (S3 User Guide, multipart upload limits).
 */
export const MIN_PART_SIZE = 5 * 1024 * 1024;

/** Largest multipart part, 5 GiB. */
export const MAX_PART_SIZE = 5 * 1024 * 1024 * 1024;

/** Most parts in one multipart upload; part numbers run `1..MAX_PARTS`. */
export const MAX_PARTS = 10_000;

/**
 * Longest object key, **in UTF-8 bytes** rather than characters (S3 User
 * Guide, "Creating object key names").
 */
export const MAX_KEY_BYTES = 1024;

/**
 * Bucket-root prefix the multipart machinery stages parts under, as
 * `.mountx-multipart/<uploadId>/<part-N>`.
 *
 * Not an S3 fact — it is this gateway's, and the session keeps it invisible to
 * every S3 operation (404 on direct access, skipped in listings) so that a
 * bucket never appears to contain it.
 */
export const MULTIPART_PREFIX = ".mountx-multipart";

// ---------------------------------------------------------------------------
// payload-hash sentinels (AWS SigV4 specification)
// ---------------------------------------------------------------------------

/**
 * `x-amz-content-sha256` when the client declines to hash the body — the value
 * every presigned URL carries, and what a client sends over TLS to avoid
 * buffering an upload twice.
 */
export const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

/**
 * `x-amz-content-sha256` for a body framed as `aws-chunked`, each chunk
 * carrying its own signature (SigV4 streaming specification). The framing
 * decoder lives in `chunked.ts`.
 */
export const STREAMING_PAYLOAD = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
