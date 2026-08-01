/**
 * WebDAV's constants, transcribed from **RFC 4918** (and RFC 9110 for the
 * status codes it reuses).
 *
 * Two tables and a handful of literals. The table that matters is
 * {@link ERRNO_STATUS}: it is typed **total** over `ErrnoCode`, the same shape
 * and for the same reason as `src/s3/constants.ts`'s `ERRNO_S3_ERRORS` — a new
 * errno in `src/errors.ts` is a type error here rather than an `EIO` a client
 * sees as `500` and nobody notices.
 *
 * Nothing here is guessed from what a client happens to accept: every status is
 * the one the RFC names for that situation, and where the RFC leaves a choice
 * (`MAY be 405`) the choice is written down at the entry.
 */

import type { ErrnoCode } from "../errors.ts";

// ---------------------------------------------------------------------------
// the protocol's literals
// ---------------------------------------------------------------------------

/**
 * The one XML namespace WebDAV defines (RFC 4918 §14, §21).
 *
 * It is `DAV:`, with the colon and with no trailing slash — an unusual URI, and
 * one that a client comparing namespace strings rather than parsing them will
 * only match spelled exactly this way.
 */
export const DAV_NS = "DAV:";

/**
 * The `DAV` response header this server sends: **classes 1, 2 and 3**
 * (RFC 4918 §10.1, §18).
 *
 * Class 1 is "everything in RFC 4918 except locking". Class 2 is `LOCK` and
 * `UNLOCK` — the write locks of §6 and §7, both scopes, both depths, with the
 * `If` header (§10.4) enforcing them. Class 3 is "this server is RFC 4918
 * rather than RFC 2518", which is a statement about the *revision* and is
 * independent of locking.
 *
 * Every one of those is answered rather than claimed: `supportedlock` lists the
 * two lock entries §15.10 defines, `lockdiscovery` reports the locks that
 * really are held, and a mutating request without the token it needs is `423`.
 * That is the "capabilities are declared-or-inferred, never faked" rule
 * (`AGENTS.md`, invariant 5) applied to a protocol header — which is why this
 * said `1, 3` until the locks underneath it existed.
 */
export const DAV_COMPLIANCE = "1, 2, 3";

/**
 * The header Microsoft's WebDAV redirector looks for before it will treat an
 * origin as a DAV share rather than a web site.
 *
 * Not in RFC 4918 — it is Microsoft's, and it is answered because the cost is
 * one header and the alternative is a client that never sends a second request.
 */
export const MS_AUTHOR_VIA = "DAV";

/** Every method this server implements, in `Allow`-header order. */
export const WEBDAV_METHODS = [
  "OPTIONS",
  "HEAD",
  "GET",
  "PUT",
  "DELETE",
  "MKCOL",
  "COPY",
  "MOVE",
  "PROPFIND",
  "PROPPATCH",
  "LOCK",
  "UNLOCK",
] as const;

/** One of {@link WEBDAV_METHODS}. */
export type WebdavMethod = (typeof WEBDAV_METHODS)[number];

/** The `Allow` header, built once. */
export const ALLOW_HEADER = WEBDAV_METHODS.join(", ");

/**
 * The content type of every non-collection resource this server serves.
 *
 * Not stored and not sniffed, exactly as in the S3 gateway: a driver holds
 * bytes, not media types, and guessing one from a file extension is a guess
 * that shows up as a browser rendering a text file as a download or the other
 * way round. A client that needs a type knows the name it asked for.
 */
export const RESOURCE_CONTENT_TYPE = "application/octet-stream";

/**
 * The content type reported for a collection: `httpd/unix-directory`.
 *
 * A convention rather than a standard — Apache's `mod_dav` set it, and every
 * WebDAV client since has recognised it — and the honest answer is that a
 * collection has no body at all (`GET` of one is `405` here). It is answered
 * because `getcontenttype` on a collection is a property clients ask for, and
 * the alternative is a `404` propstat for something the server does know.
 */
export const COLLECTION_CONTENT_TYPE = "httpd/unix-directory";

/** The content type of every `multistatus` and `error` document. */
export const XML_CONTENT_TYPE = 'application/xml; charset="utf-8"';

/**
 * Largest request body this server will parse as XML (`PROPFIND`,
 * `PROPPATCH`), in bytes. 256 KiB.
 *
 * Far below the XML parser's own 4 MiB budget, because both grammars here are a
 * short list of property names: a megabyte of `<prop>` is not a request any
 * client makes, and the body is buffered before it is parsed.
 */
export const MAX_XML_BYTES = 256 * 1024;

/** Bytes per positional read when streaming a `GET`. 128 KiB, as in `mountx/s3`. */
export const READ_CHUNK_BYTES = 128 * 1024;

// ---------------------------------------------------------------------------
// locking
// ---------------------------------------------------------------------------

/**
 * The URI scheme every lock token this server mints is written in
 * (RFC 4918 §6.5, RFC 4122 §3).
 *
 * §6.5 requires a token to be unique "across all resources for all time" and
 * *encourages* `urn:uuid:` over the older `opaquelocktoken:` scheme of
 * RFC 2518 — so that is what is here, and it is also the form every example in
 * §9.10 and §10.4 uses. A client must not interpret it either way (§6.5).
 */
export const LOCK_TOKEN_PREFIX = "urn:uuid:";

/**
 * The lease a lock gets when the client asks for nothing, in seconds. Ten
 * minutes.
 *
 * §6.6 leaves the number entirely to the server ("the lifetime is suggested by
 * the client ... but the server ultimately chooses the timeout value"), so what
 * decides it is what a lock costs when its holder disappears: **this server has
 * no administrative interface, and no principal but the one in
 * `credentials`**, so a lock nobody unlocks is a resource nobody can write
 * until it lapses. Ten minutes is long enough to edit a document through and
 * short enough that a crashed client is not a locked share for the afternoon.
 * A client that wants longer refreshes (§9.10.2), which is the mechanism the
 * RFC provides for exactly this.
 */
export const DEFAULT_LOCK_TIMEOUT_SECONDS = 600;

/**
 * The longest lease this server grants, in seconds. One hour.
 *
 * The cap is what `Timeout: Infinite` becomes — §6.6 lets a server choose, and
 * an unbounded lock here would be unbreakable for the reason above. §10.7 caps
 * the *header's* value at 2^32-1; this is a policy well inside it, and the
 * granted value always goes back in the reply's `timeout` element so a client
 * never has to guess what it got.
 */
export const MAX_LOCK_TIMEOUT_SECONDS = 3600;

/**
 * Most locks one table holds at once. 4096.
 *
 * Locking is the one part of this protocol where a client leaves something
 * behind on the server, so it is the one part with a bound. Expired locks are
 * swept before the cap is consulted, so this is reached only by live locks —
 * four thousand of them, which is far past any real client and far short of a
 * memory problem. Past it a `LOCK` is `503`, which says "not now" rather than
 * "never" and is the truthful shape of a full table.
 */
export const MAX_LOCKS = 4096;

// ---------------------------------------------------------------------------
// status codes
// ---------------------------------------------------------------------------

/**
 * Reason phrases for every status this server sends.
 *
 * It needs them for more than the status line: a `propstat` carries a whole
 * `Status-Line` as element text (RFC 4918 §14.28), so `HTTP/1.1 404 Not Found`
 * is a *value this module produces* rather than something `node:http` writes.
 *
 * `207`, `423` and `507` are RFC 4918's own (§11.1, §11.3, §11.5); `508` is
 * RFC 5842's; the rest are RFC 9110 §15.
 */
export const STATUS_TEXT: Record<number, string> = {
  200: "OK",
  201: "Created",
  204: "No Content",
  206: "Partial Content",
  207: "Multi-Status",
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  409: "Conflict",
  412: "Precondition Failed",
  413: "Content Too Large",
  414: "URI Too Long",
  415: "Unsupported Media Type",
  416: "Range Not Satisfiable",
  423: "Locked",
  424: "Failed Dependency",
  500: "Internal Server Error",
  501: "Not Implemented",
  502: "Bad Gateway",
  503: "Service Unavailable",
  507: "Insufficient Storage",
  508: "Loop Detected",
};

/**
 * A `Status-Line` for a `propstat` or a `response`: `HTTP/1.1 200 OK`.
 *
 * A status with no phrase in {@link STATUS_TEXT} is still rendered — the
 * grammar's `reason-phrase` may be empty — rather than throwing inside a reply
 * that is already half built.
 */
export function statusLine(status: number): string {
  const phrase = STATUS_TEXT[status];
  return phrase === undefined ? `HTTP/1.1 ${status}` : `HTTP/1.1 ${status} ${phrase}`;
}

/**
 * Every errno a driver can throw, as the status a WebDAV client is owed.
 *
 * Total over `ErrnoCode` by type, so `src/errors.ts` and this table cannot
 * drift. The entries that are a judgement rather than a lookup:
 *
 * - **`EEXIST` → 409**, not 405. `MKCOL` on an existing collection is 405
 *   (§9.3.1) and the session answers that case itself, before any driver call;
 *   an `EEXIST` that reaches here came from somewhere else, where "the state of
 *   the destination is wrong for this request" is the general answer.
 * - **`ENOTDIR` → 409**, which is §9.7.1's own case: a `PUT` whose parent is
 *   not a collection is a `Conflict`, not a `Not Found`.
 * - **`EXDEV` → 502.** §9.9.4 gives `502` to a `MOVE` whose destination is
 *   somewhere this server cannot write, and a cross-device rename is exactly
 *   that seen from the driver.
 * - **`ELOOP` → 508.** RFC 5842 §7.2 defines `Loop Detected` for a request that
 *   walked into a cycle; a symlink loop is one.
 * - **`ENOSPC` / `EDQUOT` / `EFBIG` → 507 / 507 / 413.** The first two are the
 *   store having no room (§11.5); `EFBIG` is *this* resource being too big,
 *   which is a fact about the request body.
 * - **`ENOSYS` / `ENOTSUP` → 501.** A driver without `rename` really has not
 *   implemented `MOVE`, and 501 is the answer that says so without blaming the
 *   client.
 * - **`ENXIO` → 403.** The memory driver answers it for a FIFO or a device
 *   node, which is a resource WebDAV can name and cannot transfer.
 */
export const ERRNO_STATUS: Record<ErrnoCode, number> = {
  EPERM: 403,
  ENOENT: 404,
  EINTR: 500,
  EIO: 500,
  ENXIO: 403,
  EBADF: 500,
  EAGAIN: 503,
  ENOMEM: 503,
  EACCES: 403,
  EBUSY: 409,
  EEXIST: 409,
  EXDEV: 502,
  ENODEV: 404,
  ENOTDIR: 409,
  EISDIR: 405,
  EINVAL: 400,
  ENFILE: 503,
  EMFILE: 503,
  EFBIG: 413,
  ENOSPC: 507,
  ESPIPE: 500,
  EROFS: 403,
  EMLINK: 403,
  ERANGE: 500,
  ENAMETOOLONG: 414,
  ENOSYS: 501,
  ENOTEMPTY: 409,
  ELOOP: 508,
  ENODATA: 404,
  EPROTO: 500,
  EOVERFLOW: 500,
  ENOTSUP: 501,
  ESTALE: 404,
  EDQUOT: 507,
};

/** The status an unrecognized failure gets: `500`, never a guess. */
export const UNKNOWN_STATUS = 500;

/**
 * The status for any error a driver throws, by its `code`.
 *
 * Anything without a `code` this table knows is `500` — the same posture as
 * `errnoOf()`'s `EIO` default, and for the same reason: an unmapped failure is
 * the server's, not the client's.
 */
export function statusOf(code: string | undefined): number {
  return code !== undefined && code in ERRNO_STATUS
    ? (ERRNO_STATUS[code as ErrnoCode] as number)
    : UNKNOWN_STATUS;
}
