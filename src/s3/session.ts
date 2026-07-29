/**
 * The S3 session: one HTTP request in, one S3 reply out, and no socket.
 *
 * The S3 analogue of `src/nfs/session.ts` and `src/fuse/session.ts`, with the
 * same rules — it touches no network, it never rejects, and every thrown value
 * becomes exactly one well-formed S3 reply. `node:http` appears only in
 * `server.ts`, which is much smaller.
 *
 * What is different, and it is the reason this file exists rather than another
 * `handleCall(bytes)`:
 *
 * - **The boundary streams.** {@link S3Session.handleRequest} takes a head and
 *   an `AsyncIterable<Uint8Array>` body and answers a response whose body may
 *   itself be an `AsyncIterable` (plan decision, "Session boundary is
 *   streaming"). An object is not a message: buffering a 5 GiB `PUT` to parse
 *   it, or a 5 GiB `GET` to answer it, is not a thing a gateway may do.
 * - **This layer orchestrates; it does not parse.** Routing, key validation,
 *   `Range`, the conditional headers, the error documents and the three refusal
 *   bridges all live in `protocol.ts`, and the signature, XML and `aws-chunked`
 *   codecs in their own files. What is here is the part that needs a driver: an
 *   operation's *semantics*.
 * - **The impure defaults are two, and they are named.** `options.now` defaults
 *   to `Date.now` and `options.requestId` to `crypto.randomBytes`. Every module
 *   below this one takes its clock and its randomness as arguments, on purpose;
 *   this is the boundary where both have to enter, because SigV4 skew and
 *   `Last-Modified` are facts about now, and a request id has to be unique
 *   across processes. Pass both in a test and the session is deterministic
 *   again.
 *
 * Sources, as everywhere in `src/s3/`: the **Amazon S3 API Reference** for what
 * each operation answers, and **RFC 9110** for the HTTP it answers it over.
 * Real clients (rclone, curl, the AWS SDKs) are oracles, never sources.
 *
 * ## The decisions this file makes
 *
 * Written down because each of them is a place a client could see a difference
 * from Amazon's own service:
 *
 * - **ETag** is derived, never a fake MD5: the first 32 hex characters of
 *   sha256 over `dev:ino:size:mtimeMs`, suffixed `-1` (plan decision;
 *   {@link objectETag}). The multipart-shaped suffix is the signal that it is
 *   not an MD5 of the bytes, which is what makes it honest rather than wrong.
 * - **`PUT` writes the object in place**, with no temporary file and no rename.
 *   The driver interface has no atomic-create primitive, `rename` is optional
 *   and only *declared* atomic (`FsCapabilities.atomicRename`), and a staging
 *   copy would have to live somewhere a listing can see. So: a reader arriving
 *   mid-`PUT` can see a partial object, and a `PUT` that fails mid-body leaves
 *   a partial object where a whole one used to be. What is guaranteed is the
 *   *first* byte: the destination is not opened — so an existing object is not
 *   truncated and a new one is not created — until the first payload byte has
 *   arrived and, for a signed `aws-chunked` body, verified. An upload rejected
 *   *at or before its first byte* therefore leaves the bucket exactly as it
 *   was; one rejected later leaves what had been written by then, which is what
 *   {@link S3Session} documents on `#writeObject` in full.
 * - **`If-Range` is implemented** (RFC 9110 §13.1.5): a matching validator
 *   keeps the `Range`, a non-matching one drops it and answers the whole object
 *   with `200`, which is what the RFC requires and what makes a resumed
 *   download safe.
 * - **`encoding-type=url` is implemented**, because rclone asks for it. Keys,
 *   prefixes, the delimiter and `StartAfter` are percent-encoded with the
 *   RFC 3986 rules `sigv4.ts` already carries ({@link uriEncode}), separators
 *   included. The continuation tokens are **not** encoded: they are already
 *   base64 of this gateway's own making, and no SDK decodes them.
 * - **`Content-MD5` is verified** when a `DeleteObjects` body carries one
 *   (`BadDigest` on a mismatch) and ignored when it does not.
 * - **`ListBuckets` dates** come from a `stat` of each driver's root, falling
 *   back to the epoch for a driver that cannot answer one. Nothing here records
 *   when a bucket was configured, and inventing a "now" would make every
 *   listing differ from the last.
 * - **The owner is synthetic and constant** ({@link SYNTHETIC_OWNER}). There
 *   are no users in a driver, so there is no identity to report; it is emitted
 *   only where S3's schema requires an owner, and on `Contents` only when the
 *   request asked (`fetch-owner=true`).
 *
 * ## Empty-directory markers, worked through
 *
 * A directory is a prefix, so a directory with children needs no object of its
 * own — its children *are* the listing. An **empty** directory has no children
 * to stand for it, and would vanish from a listing entirely, which is why the
 * plan gives it a marker: an empty directory `d` lists as a zero-byte object
 * with key `d/`. That is exactly the object `PUT d/` creates and `DELETE d/`
 * removes, so `sync` can recreate the tree.
 *
 * With `delimiter=/` the same rule reads differently, and both readings agree
 * once the marker is treated as a real key. Given a bucket holding `a/b.txt`
 * and an empty directory `e`:
 *
 * - `?list-type=2&delimiter=/` — keys are `a/b.txt` and `e/`. Both contain a
 *   `/` after the (empty) prefix, so both group: `CommonPrefixes` are `a/` and
 *   `e/`, and `Contents` is empty. An empty directory is a common prefix here,
 *   like any other directory.
 * - `?list-type=2&delimiter=/&prefix=e/` — the key `e/` has nothing after the
 *   prefix, so it does not group: `Contents` is the single row `e/`, size 0.
 *   This is the case a client uses to ask "is this directory there?", and it is
 *   why the marker exists.
 * - `?list-type=2` (no delimiter) — `Contents` is `a/b.txt` then `e/`, in
 *   effective-key order.
 *
 * The rule, in one sentence: **a directory is listed as a marker object exactly
 * when it has no entries of its own**, and the delimiter then groups that
 * marker key like any other key.
 *
 * ## Ordering
 *
 * S3 orders keys by their UTF-8 bytes. A plain JavaScript `<` orders by UTF-16
 * code units, which disagrees above the BMP, so every comparison here goes
 * through {@link compareKeys}. Within a directory the comparison is on the
 * **effective key** — `name` for a file, `name + "/"` for a directory (plan
 * decision) — because that is what makes a depth-first walk emit full keys in
 * order: `a.txt` < `a/b` < `a0` only if the directory `a` sorts as `a/`.
 *
 * ## Copy-what-you-keep
 *
 * The head is strings, which are immutable, and `protocol.ts` returns fresh
 * ones. The body is bytes, and there are exactly three things done with them:
 *
 * - **Buffered** (a `DeleteObjects` document): every chunk is copied on the way
 *   into the accumulator ({@link copyBytes}), because a chunk is retained past
 *   the `await` that produced it and `Buffer.prototype.slice` is a view.
 * - **Written** (a `PUT` body): each chunk is handed to `handle.write()` and
 *   **awaited before the iterator advances**, so the driver is done with the
 *   bytes before the source can reuse the buffer. Nothing is retained, so
 *   nothing is copied.
 * - **Decoded** (an `aws-chunked` body): `chunked.ts` copies every byte it
 *   retains, which its own contract guarantees.
 *
 * On the way out, the `GET` generator allocates a fresh buffer for every read
 * and never yields the same one twice.
 */

import { createHash, randomBytes } from "node:crypto";
import { createLoopback, type Loopback } from "../harness.ts";
import { dirname } from "../path.ts";
import type { DirentLike, FileHandleLike, FsDriver, StatsLike } from "../types.ts";
import { decodeAwsChunked, isChunkedError, type ChunkedSignature } from "./chunked.ts";
import { MULTIPART_PREFIX, s3ErrorOf } from "./constants.ts";
import {
  bodyMode,
  chunkedRefusalError,
  evaluateConditionals,
  formatETag,
  formatHttpDate,
  formatIsoDate,
  formatMetaMtime,
  formatUnsatisfiedRange,
  headerValue,
  isAnswered,
  isRefusal,
  isStagingKey,
  META_MTIME_HEADER,
  objectResponseHeaders,
  parseContentLengths,
  parseHttpDate,
  parseMetaMtime,
  parseObjectKey,
  parseRange,
  parseRequestTarget,
  routeRequest,
  s3Error,
  s3ErrorResponse,
  S3_ERRORS,
  sigv4RefusalError,
  XML_CONTENT_TYPE,
  xmlRefusalError,
  type S3ErrorName,
  type S3ErrorSpec,
  type S3ObjectTarget,
  type S3Request,
  type S3StreamResponse,
} from "./protocol.ts";
import {
  formatAmzDate,
  isPresigned,
  parseAuthorizationHeader,
  uriEncode,
  verifyRequest,
  type HeaderEntry,
  type SigV4Credentials,
  type SigV4Verified,
} from "./sigv4.ts";
import {
  encodeCopyObjectResult,
  encodeDeleteResult,
  encodeListAllMyBucketsResult,
  encodeListBucketResult,
  isXmlError,
  parseDeleteObjects,
  XML_MAX_BYTES,
  type DeletedEntry,
  type DeleteErrorEntry,
  type S3ObjectEntry,
  type S3Owner,
} from "./xml.ts";

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

/**
 * How much of an object one positional read asks for, 128 KiB.
 *
 * Big enough that a large `GET` is not a syscall storm, small enough that a
 * range of a few bytes costs a buffer of a few bytes (the read is clamped to
 * what is left), and small enough that abandoning a download frees its memory
 * immediately.
 */
export const READ_CHUNK_BYTES = 128 * 1024;

/**
 * The owner every document that needs one reports.
 *
 * Synthetic, constant, and the same in every bucket: a driver has no users, so
 * there is no identity to look up. The two fields are deliberately different
 * strings so that a fixture cannot pass with them transposed.
 */
export const SYNTHETIC_OWNER: S3Owner = { id: "mountx-gateway", displayName: "mountx" };

/** The storage class every object reports (S3 API Reference: the default). */
export const STORAGE_CLASS = "STANDARD";

/**
 * Most keys one `DeleteObjects` request may name (S3 API Reference,
 * `DeleteObjects`: "The request can contain a list of up to 1000 keys").
 *
 * A body naming more is `MalformedXML`, which is what S3 answers — the
 * document does not validate against the published schema.
 */
export const MAX_DELETE_KEYS = 1000;

/**
 * The region a `HeadBucket` reports when the gateway was configured with none.
 *
 * `us-east-1` is the conventional answer for an S3-compatible server that has
 * no regions: it is the value S3's own API documents as the default, and a
 * client that reads it and re-signs for that region is still accepted, because
 * a gateway with no `region` option accepts every scope.
 */
const DEFAULT_REGION = "us-east-1";

/** `<CreationDate>` for a bucket whose driver cannot `stat` its own root. */
const EPOCH_ISO = formatIsoDate(0);

/**
 * A body with no bytes in it, for a request that has none.
 *
 * Written as an iterator rather than an empty `async function*` so that the
 * "a generator that never yields" lint has nothing to say about it.
 */
const NO_BODY: AsyncIterable<Uint8Array> = {
  [Symbol.asyncIterator]: () => ({
    next: async () => ({ done: true as const, value: undefined }),
  }),
};

// ---------------------------------------------------------------------------
// keys, tokens and tags
// ---------------------------------------------------------------------------

/**
 * Compare two keys the way S3 orders them: by **UTF-8 bytes**.
 *
 * Not `a < b`, which compares UTF-16 code units and puts every astral character
 * (`U+1F600`, encoded as a surrogate pair) *before* `U+E000..U+FFFF` where UTF-8
 * puts it after. A bucket holding one emoji-named key would page in an order no
 * client could resume from.
 */
export function compareKeys(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/**
 * Can this `ListObjectsV2` prefix match any key at all?
 *
 * A prefix is a **literal string match against keys**, not a path — S3 does not
 * resolve it, and neither may this. Every key this gateway will answer for is
 * one `parseObjectKey()` accepted, so a prefix that no such key can begin with
 * matches nothing, and the honest answer is an empty listing: `200`, `KeyCount`
 * `0`, no error (S3 answers an unmatched prefix exactly that way).
 *
 * Saying so **before** a driver path is derived is the point, and it is what
 * makes the walk's key discipline hold. The two things a non-canonical prefix
 * did when it reached the walk:
 *
 * - **`prefix=/`** (or `./`, `../`, `a/../`) derived a `dirKey` that is not the
 *   empty string, which turned off the bucket-root check that hides the
 *   multipart staging directory — so the staging subtree listed, against the
 *   plan's invisibility decision. The loopback harness normalizes `/./` and
 *   `/../` on the way to the driver, so the walk was reading a directory its
 *   own `dirKey` did not name.
 * - **`prefix=empty//`** listed a marker object keyed `empty//`, a key that
 *   `parseObjectKey()` refuses — so a client could read a key out of a listing
 *   that a `GET` of the same key answers `400` for.
 *
 * The rules are `parseObjectKey()`'s, applied to a string that may stop in the
 * middle of a name: no leading `/`, no empty interior segment, no **complete**
 * `.` or `..` segment, no NUL. The final segment of a prefix is a partial
 * name, not a segment, so a trailing `.` or `..` stays listable — `.` is a
 * legitimate prefix of every dotfile (`.hidden`, `.mountx-multipart2`), and
 * only `./` closes the segment and makes it impossible. A **trailing** empty
 * segment is fine too — that is the directory marker, `photos/`. The staging prefix is folded in here as well: a prefix
 * *inside* the staging subtree matches nothing, while the bare
 * `.mountx-multipart` falls through to the walk, where the root-level skip
 * hides that one directory and leaves neighbours like `.mountx-multipart2`
 * listed like any other key.
 */
function listablePrefix(prefix: string): boolean {
  if (prefix === "") {
    return true;
  }
  if (prefix.startsWith(`${MULTIPART_PREFIX}/`)) {
    return false;
  }
  if (prefix.startsWith("/") || prefix.includes("//") || prefix.includes("\0")) {
    return false;
  }
  return !prefix
    .split("/")
    .slice(0, -1)
    .some((segment) => segment === "." || segment === "..");
}

/**
 * The continuation token for a page that ended at `key`: base64 of the key
 * (plan decision — an opaque, stateless `start-after` cursor).
 *
 * Stateless is the point. Nothing is remembered between pages, so a client may
 * resume hours later, from another connection, against a tree that has changed
 * underneath it, and still get a listing that is sorted and complete for
 * everything that did not move.
 */
export function encodeContinuationToken(key: string): string {
  return Buffer.from(key, "utf8").toString("base64");
}

/**
 * Read a continuation token back, or `undefined` for one this gateway did not
 * mint. The round trip is re-checked rather than trusted, because `Buffer`'s
 * base64 decoder accepts almost anything: without the check, `?continuation-
 * token=hello` would silently resume from a key nobody asked for.
 */
export function decodeContinuationToken(token: string): string | undefined {
  const key = Buffer.from(token, "base64").toString("utf8");
  return encodeContinuationToken(key) === token ? key : undefined;
}

/**
 * The ETag of an object, derived from its `stat` (plan decision).
 *
 * The first 32 hex characters of sha256 over `dev:ino:size:mtimeMs`, suffixed
 * `-1`. It is **not** an MD5 of the bytes and does not pretend to be: the
 * `-N` suffix is S3's own shape for a multipart object's ETag, which every
 * client already knows is not a content hash, so a client that would have
 * verified an MD5 falls back to size and modification time instead of
 * verifying something false.
 *
 * Cheap — it hashes 40-odd bytes of metadata, never the object — and stable:
 * two `GET`s of an unchanged object agree, and any write that changes the size
 * or the timestamp changes it.
 */
export function objectETag(stats: StatsLike): string {
  const digest = createHash("sha256")
    .update(`${stats.dev}:${stats.ino}:${stats.size}:${stats.mtimeMs}`, "utf8")
    .digest("hex");
  return `${digest.slice(0, 32)}-1`;
}

/** A private copy of some bytes. `Buffer.prototype.slice` is a view, not this. */
function copyBytes(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out;
}

/** The `code` of a thrown value, when it has a string one. */
function errorCode(error: unknown): string | undefined {
  if (typeof error === "object" && error !== null) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string") {
      return code;
    }
  }
  return undefined;
}

/** Does this errno mean "there is nothing at that path"? */
function isAbsent(error: unknown): boolean {
  const code = errorCode(error);
  return code === "ENOENT" || code === "ENOTDIR";
}

// ---------------------------------------------------------------------------
// errors carried out of a handler
// ---------------------------------------------------------------------------

/**
 * An S3 error thrown from inside an operation, for the one reply to render.
 *
 * Handlers `throw` instead of returning a response wherever the refusal is
 * several calls deep — the single-reply discipline is kept by the catch in
 * {@link S3Session.handleRequest}, which every path goes through.
 */
class S3ErrorThrown extends Error {
  readonly spec: S3ErrorSpec;

  constructor(spec: S3ErrorSpec) {
    super(spec.message);
    this.name = "S3ErrorThrown";
    this.spec = spec;
  }
}

function refuse(name: S3ErrorName, message?: string): S3ErrorThrown {
  return new S3ErrorThrown(s3Error(name, message));
}

/**
 * The request body's *source* failed — the client hung up, the socket died,
 * the test's generator threw.
 *
 * Deliberately its own type: `chunked.ts` documents that a `ChunkedError` means
 * the framing was wrong, and blaming the framing for a dropped connection would
 * send the reader hunting for a decoder bug that is not there. Mapped to
 * `IncompleteBody`, which is what S3 answers when the promised bytes do not all
 * arrive.
 */
class BodySourceError extends Error {
  constructor(override readonly cause: unknown) {
    super("the request body ended before the request did");
    this.name = "BodySourceError";
  }
}

/**
 * The body, with a source failure named as one.
 *
 * Wrapped *inside* every other layer, so a `ChunkedError` from the decoder
 * above it stays a `ChunkedError`.
 */
async function* guardSource(source: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array> {
  const iterator = source[Symbol.asyncIterator]();
  for (;;) {
    let step: IteratorResult<Uint8Array>;
    try {
      step = await iterator.next();
    } catch (error) {
      throw new BodySourceError(error);
    }
    if (step.done === true) {
      return;
    }
    yield step.value;
  }
}

// ---------------------------------------------------------------------------
// options
// ---------------------------------------------------------------------------

/** One request, as the transport hands it over. */
export interface S3RequestHead {
  /** The HTTP method, uppercase. */
  method: string;
  /** The raw request target: `/bucket/key?list-type=2`, still encoded. */
  target: string;
  /** Headers in wire order, repeats included, names in whatever case arrived. */
  headers: readonly HeaderEntry[];
}

export interface S3SessionOptions {
  /**
   * The one credential pair this gateway accepts. **Present means every
   * request is verified** — header and presigned forms both — and an unsigned
   * one is `AccessDenied`. Absent means signatures are parsed by whoever needs
   * them and never checked, which is only safe on a loopback bind (the plan's
   * auth decision, enforced in `server.ts`).
   */
  credentials?: SigV4Credentials;
  /** Region the credential scope must name. Omitted accepts any. */
  region?: string;
  /**
   * The clock, in milliseconds. One of the two impure defaults in this file
   * (`Date.now`; the other is `requestId`): SigV4 skew and the timestamps in
   * a reply are facts about now, and this is the boundary where a real clock
   * has to enter. Pass one and the clock is deterministic.
   */
  now?: () => number;
  /** The `x-amz-request-id` minter. Default: 16 random bytes, hex. */
  requestId?: () => string;
  /**
   * Largest object one `PUT` may store, in decoded bytes. **Default
   * unlimited**, because a gateway in front of a disk has no business
   * inventing a smaller limit than the disk's; a driver that runs out answers
   * `ENOSPC`, which is already `ServiceUnavailable`. Set it and a body over the
   * cap is `EntityTooLarge`.
   */
  maxBodyBytes?: number;
  /**
   * Largest XML request document accepted (`DeleteObjects`). Default
   * {@link XML_MAX_BYTES}, the parser's own budget.
   */
  maxXmlBytes?: number;
  /** Bytes per positional read when streaming a `GET`. Default {@link READ_CHUNK_BYTES}. */
  readChunkBytes?: number;
  /** Run the reply-exactly-once assertions. Default on outside production. */
  debug?: boolean;
  /** Called for every request that ends in an error reply. */
  onError?: (error: unknown, head: S3RequestHead | undefined) => void;
  /** Called when a dev-mode assertion fails. Default: collect in `assertions`. */
  onAssertion?: (message: string) => void;
}

/** Counters, all cheap, all useful in a test. */
export interface S3SessionStats {
  /** Requests handed to {@link S3Session.handleRequest}. */
  requests: number;
  /** Replies produced (successful or not). */
  replies: number;
  /** Of which replies carrying an S3 error document. */
  errors: number;
  /** Per-operation counts, keyed by `S3OpName`. */
  operations: Map<string, number>;
  /** Dev-mode assertion failures. Must be zero. */
  assertions: number;
}

/** One entry of a listing, before it becomes a `Contents` or a `CommonPrefixes`. */
interface ListEntry {
  /** The full key: `a/b.txt` for a file, `a/` for a directory. */
  key: string;
  /** The driver path it came from. */
  path: string;
  /** A `CommonPrefixes` row, rather than an object. */
  prefix: boolean;
}

// ---------------------------------------------------------------------------
// the session
// ---------------------------------------------------------------------------

/**
 * An S3 gateway over one or more drivers, with no socket.
 *
 * ```ts
 * const session = new S3Session({ mountx: createMemoryDriver() });
 * const response = await session.handleRequest(
 *   { method: "GET", target: "/mountx/hello.txt", headers: [] },
 * );
 * ```
 *
 * The bucket map is canonical: `createS3Server()`'s single-driver shorthand is
 * widened into one before it reaches here, so there is one bucket lookup in the
 * codebase and one place `NoSuchBucket` comes from.
 */
export class S3Session {
  /** The drivers, each wrapped so paths are normalized and gaps answer `ENOSYS`. */
  readonly buckets: Map<string, Loopback>;
  readonly options: S3SessionOptions;
  readonly stats: S3SessionStats = {
    requests: 0,
    replies: 0,
    errors: 0,
    operations: new Map(),
    assertions: 0,
  };
  /** Dev-mode assertion failures, in order. Empty in a healthy session. */
  readonly assertions: string[] = [];

  readonly #now: () => number;
  readonly #requestId: () => string;
  readonly #readChunkBytes: number;
  readonly #maxXmlBytes: number;
  readonly #debug: boolean;
  /**
   * Requests that have not been answered yet, by internal ticket.
   *
   * **Not by `x-amz-request-id`.** That id is the client-visible one and comes
   * from `options.requestId`, which a caller may pin to a constant — at which
   * point tracking by id would report every concurrent request as a duplicate
   * of the last, an assertion failure about the session's own test fixture. The
   * ticket is this session's, monotonic, and never repeats, so what the set
   * asserts is what it is for: one reply per request, and no request answered
   * twice.
   */
  readonly #inflight = new Set<number>();
  #nextTicket = 1;

  constructor(buckets: Record<string, FsDriver>, options: S3SessionOptions = {}) {
    this.buckets = new Map(
      Object.entries(buckets).map(([name, driver]) => [name, createLoopback(driver)]),
    );
    this.options = options;
    this.#now = options.now ?? Date.now;
    this.#requestId = options.requestId ?? (() => randomBytes(16).toString("hex"));
    this.#readChunkBytes = options.readChunkBytes ?? READ_CHUNK_BYTES;
    this.#maxXmlBytes = options.maxXmlBytes ?? XML_MAX_BYTES;
    this.#debug = options.debug ?? process.env.NODE_ENV !== "production";
  }

  /** The bucket names, in listing order. */
  get bucketNames(): string[] {
    return [...this.buckets.keys()].sort((a, b) => compareKeys(a, b));
  }

  /**
   * Answer one request. **Never rejects**, and produces exactly one reply.
   *
   * `head` is read across awaits and must not be mutated while the promise is
   * outstanding; everything the session keeps out of the body is copied (see
   * the module docs).
   *
   * A `HEAD` reply carries the headers of the `GET` it stands for — including
   * `Content-Length` — and no body, which is HTTP's rule (RFC 9110 §9.3.2)
   * rather than anything about S3.
   */
  async handleRequest(
    head: S3RequestHead,
    body: AsyncIterable<Uint8Array> = NO_BODY,
  ): Promise<S3StreamResponse> {
    this.stats.requests++;
    const requestId = this.#requestId();
    const ticket = this.#nextTicket++;
    if (this.#debug) {
      this.#inflight.add(ticket);
    }
    let response: S3StreamResponse | undefined;
    try {
      response = await this.#dispatch(head, body, requestId);
    } catch (error) {
      response = this.#fail(error, head, requestId);
    }
    /* v8 ignore next 3 -- structurally unreachable: one `handleRequest` call
       answers once. The assertion is what makes that structural rather than
       assumed, the way the FUSE session tracks its `unique`. */
    if (this.#debug && !this.#inflight.delete(ticket)) {
      this.#assert(`${head.method} ${head.target} was answered twice`);
    }
    /* v8 ignore next 4 -- `#dispatch` returns a response or throws, and the
       catch above answers everything it throws. The assertion is the point: if
       that ever stops being true, a caller must not be left waiting. */
    if (response === undefined) {
      this.#assert(`${head.method} ${head.target} produced no reply`);
      response = s3ErrorResponse(s3Error("InternalError"), { requestId });
    }
    this.stats.replies++;
    if (response.status >= 400) {
      this.stats.errors++;
    }
    return head.method === "HEAD" && response.body !== undefined
      ? { status: response.status, headers: response.headers }
      : response;
  }

  // -------------------------------------------------------------------------
  // dispatch
  // -------------------------------------------------------------------------

  async #dispatch(
    head: S3RequestHead,
    body: AsyncIterable<Uint8Array>,
    requestId: string,
  ): Promise<S3StreamResponse> {
    const parsed = parseRequestTarget(head.target);
    if (!parsed.ok) {
      return this.#error(parsed.error, requestId);
    }
    const target = parsed.target;
    const auth = this.#authorize(head, target.path, target.query);
    if (!auth.ok) {
      this.options.onError?.(auth.detail, head);
      return this.#error(auth.error, requestId, target.path);
    }
    const route = routeRequest(head.method, target.path, target.query, head.headers);
    if (isRefusal(route)) {
      return this.#error(route.error, requestId, route.resource);
    }
    if (isAnswered(route)) {
      /* The router's own reply: a `DELETE` under the staging prefix, answered
         `204` so that the prefix looks like the empty space it pretends to be. */
      this.#count("Answered");
      return { status: route.status, headers: this.#headers(requestId) };
    }
    this.#count(route.op);
    /* One bucket lookup for the whole gateway. Every route but `ListBuckets`
       names a bucket, and an unknown one is `NoSuchBucket` before any handler
       gets to decide something else. */
    let driver: Loopback | undefined;
    if ("bucket" in route) {
      driver = this.buckets.get(route.bucket);
      if (driver === undefined) {
        return this.#error(s3Error("NoSuchBucket"), requestId, target.path);
      }
    }
    const bucket = driver as Loopback;
    switch (route.op) {
      case "ListBuckets": {
        return await this.#listBuckets(requestId);
      }
      case "HeadBucket": {
        /* `x-amz-bucket-region` is the one header a client looks for here, and
           `us-east-1` is what an S3-compatible server with no region of its own
           reports (this gateway accepts every region when none is configured —
           see `sigv4.ts` on why there is nothing for a region to select). */
        return {
          status: 200,
          headers: {
            ...this.#headers(requestId),
            "x-amz-bucket-region": this.options.region ?? DEFAULT_REGION,
          },
        };
      }
      case "ListObjectsV2": {
        return await this.#listObjects(bucket, route, requestId);
      }
      case "GetObject":
      case "HeadObject": {
        return await this.#getObject(bucket, route, head, requestId);
      }
      case "PutObject": {
        return await this.#putObject(bucket, route, head, body, auth.verified, requestId);
      }
      case "CopyObject": {
        return await this.#copyObject(bucket, route, head, requestId);
      }
      case "DeleteObject": {
        return await this.#deleteObject(bucket, route, requestId);
      }
      case "DeleteObjects": {
        return await this.#deleteObjects(bucket, head, body, auth.verified, requestId);
      }
      default: {
        /* The five multipart operations. Step 6 fills them in; until then they
           are refused the way every other unimplemented operation is, rather
           than half-answered. */
        return this.#error(
          s3Error("NotImplemented", `${route.op} is not implemented by this gateway.`),
          requestId,
          target.path,
        );
      }
    }
  }

  #count(op: string): void {
    this.stats.operations.set(op, (this.stats.operations.get(op) ?? 0) + 1);
  }

  /* v8 ignore next 6 -- both call sites are structurally unreachable (see
     `handleRequest`); this is the reporting half of an assertion that exists so
     that "exactly one reply per request" is checked rather than assumed. */
  #assert(message: string): void {
    this.stats.assertions++;
    this.assertions.push(message);
    this.options.onAssertion?.(message);
  }

  /** The headers every reply carries. */
  #headers(requestId: string): Record<string, string> {
    return { "x-amz-request-id": requestId };
  }

  /** Render an S3 error document. */
  #error(error: S3ErrorSpec, requestId: string, resource?: string): S3StreamResponse {
    return s3ErrorResponse(error, { requestId, resource });
  }

  /**
   * Turn any thrown value into the one reply.
   *
   * The last line of defence, and it takes no chances: an unrecognized value is
   * `InternalError`, exactly as `s3ErrorOf` maps an unrecognized errno, because
   * a request that gets no reply is worse than one that gets an imprecise one.
   */
  #fail(error: unknown, head: S3RequestHead, requestId: string): S3StreamResponse {
    try {
      this.options.onError?.(error, head);
    } catch {
      // A logger is never allowed to cost a reply.
    }
    return this.#error(specOf(error), requestId);
  }

  // -------------------------------------------------------------------------
  // authentication
  // -------------------------------------------------------------------------

  /**
   * Verify the request's signature, when this gateway has credentials.
   *
   * Without them nothing is checked — the plan's posture, and `server.ts`
   * refuses a non-loopback bind in that configuration. With them, both forms
   * are verified through `sigv4.ts` and a refusal becomes the S3 error
   * `protocol.ts`'s table names for it, in the spelling that matches the form
   * the signature arrived in.
   *
   * The refusal's `detail` is handed to `onError` rather than to the client:
   * Amazon's own message is what a client matches on, and the detail is for
   * whoever is reading the logs.
   */
  #authorize(
    head: S3RequestHead,
    path: string,
    query: readonly { name: string; value: string }[],
  ):
    | { ok: true; verified: SigV4Verified | undefined }
    | { ok: false; error: S3ErrorSpec; detail: string } {
    const credentials = this.options.credentials;
    if (credentials === undefined) {
      return { ok: true, verified: undefined };
    }
    const result = verifyRequest({
      method: head.method,
      path,
      query,
      headers: head.headers,
      credentials,
      now: this.#now(),
      region: this.options.region,
    });
    if (result.ok) {
      return { ok: true, verified: result };
    }
    return {
      ok: false,
      error: sigv4RefusalError(result.reason, isPresigned(query) ? "presigned" : "header"),
      detail: result.detail,
    };
  }

  // -------------------------------------------------------------------------
  // GET / HEAD
  // -------------------------------------------------------------------------

  async #getObject(
    driver: Loopback,
    route: S3ObjectTarget,
    head: S3RequestHead,
    requestId: string,
  ): Promise<S3StreamResponse> {
    const stats = await this.#statObject(driver, route);
    const etag = objectETag(stats);
    const conditional = evaluateConditionals(
      { etag, mtimeMs: stats.mtimeMs },
      head.headers,
      head.method,
    );
    if (conditional.status === 412) {
      return this.#error(s3Error("PreconditionFailed"), requestId, `/${route.bucket}/${route.key}`);
    }
    if (conditional.status === 304) {
      return {
        status: 304,
        headers: {
          ...this.#headers(requestId),
          etag: formatETag(etag),
          "last-modified": formatHttpDate(stats.mtimeMs),
          [META_MTIME_HEADER]: formatMetaMtime(stats.mtimeMs),
        },
      };
    }
    /* A directory answers as the zero-byte marker object it lists as: there is
       nothing to read and nothing to range over. */
    const size = route.directory ? 0 : stats.size;
    const range = this.#rangeOf(head, stats, etag, size);
    if (range.kind === "unsatisfiable") {
      const response = this.#error(
        s3Error("InvalidRange"),
        requestId,
        `/${route.bucket}/${route.key}`,
      );
      response.headers["content-range"] = formatUnsatisfiedRange(size);
      return response;
    }
    const start = range.kind === "range" ? range.start : 0;
    const length = range.kind === "range" ? range.length : size;
    const headers = {
      ...this.#headers(requestId),
      ...objectResponseHeaders({
        etag,
        size: length,
        mtimeMs: stats.mtimeMs,
        contentRange:
          range.kind === "range" ? { start: range.start, end: range.end, total: size } : undefined,
      }),
    };
    const status = range.kind === "range" ? 206 : 200;
    if (length === 0 || head.method === "HEAD") {
      /* No body, and — for `HEAD` — no `open` either. A `HEAD` carries the
         `GET`'s headers and none of its bytes, so opening the object here would
         hand a stream to a caller that is about to drop it, and the descriptor
         with it. The headers above are already the ones a `GET` would send,
         `Content-Length` and any `Content-Range` included. */
      return { status, headers };
    }
    /* Opened here rather than inside the generator, so that a failure to open
       is an S3 error instead of a stream that dies after the status line. The
       generator owns the handle from now on and closes it in a `finally`,
       which runs on early abandonment too (`generator.return()`). */
    const handle = await driver.open(route.path, "r");
    return { status, headers, body: streamHandle(handle, start, length, this.#readChunkBytes) };
  }

  /**
   * `stat` the object a key names, with the directory conventions applied.
   *
   * The four cases, and they are all `NoSuchKey` when they disagree, because S3
   * has no object at that key however the tree got that way:
   *
   * - `a/b` on a file — the object.
   * - `a/b/` on a directory — the marker object for an empty directory, and the
   *   same answer for a directory with children (a client asking for `a/b/`
   *   gets a zero-byte object either way, which is what `PUT a/b/` made).
   * - `a/b` on a *directory* — S3 has no such object; the key is `a/b/`.
   * - `a/b/` on a *file* — likewise, the other way round.
   */
  async #statObject(driver: Loopback, route: S3ObjectTarget): Promise<StatsLike> {
    const stats = await driver.stat(route.path).catch((error: unknown) => {
      throw isAbsent(error) ? refuse("NoSuchKey") : error;
    });
    if (route.directory ? !stats.isDirectory() : !stats.isFile()) {
      throw refuse("NoSuchKey");
    }
    return stats;
  }

  /**
   * What `Range` asks for, once `If-Range` has had its say (RFC 9110 §13.1.5).
   *
   * `If-Range` makes a resumed download safe: the client sends the validator it
   * had, and a server whose copy has changed since must send the **whole**
   * object rather than a range of the new bytes glued onto the old ones. A
   * validator that does not match therefore drops the `Range` entirely — `200`,
   * the full object — which is the RFC's own wording ("if the validator does
   * not match, the server MUST ignore the Range header field").
   *
   * The comparison is strong on both sides: a `W/` tag never matches, and a
   * date matches only the same second (`HTTP-date` has no finer resolution).
   * `If-Range` without a `Range` is ignored, as §13.1.5 requires.
   */
  #rangeOf(
    head: S3RequestHead,
    stats: StatsLike,
    etag: string,
    size: number,
  ): ReturnType<typeof parseRange> {
    const range = headerValue(head.headers, "range");
    if (range === undefined) {
      return { kind: "full" };
    }
    const ifRange = headerValue(head.headers, "if-range");
    if (ifRange !== undefined && !ifRangeMatches(ifRange, etag, stats.mtimeMs)) {
      return { kind: "full" };
    }
    return parseRange(range, size);
  }

  // -------------------------------------------------------------------------
  // PUT
  // -------------------------------------------------------------------------

  async #putObject(
    driver: Loopback,
    route: S3ObjectTarget,
    head: S3RequestHead,
    body: AsyncIterable<Uint8Array>,
    verified: SigV4Verified | undefined,
    requestId: string,
  ): Promise<S3StreamResponse> {
    /* A `x-amz-meta-mtime` that is not a number is **ignored, not refused**
       (`parseMetaMtime` answers `undefined` and the object keeps the time it
       was written at). rclone and its lookalikes write this header from
       whatever their backend had; a bad one costs a timestamp, while a 400
       would fail an upload after the bytes were sent — and S3 itself stores
       user metadata without ever reading it. Pinned by a test. */
    const mtime = parseMetaMtime(headerValue(head.headers, META_MTIME_HEADER));
    if (route.directory) {
      return await this.#putDirectory(driver, route, body, mtime, requestId);
    }
    const source = this.#objectBody(head, body, verified);
    const lengths = this.#lengths(head);
    if (source.framing === "identity" && lengths.contentLength === undefined) {
      /* S3 answers 411 for a `PUT` whose length it cannot know, and so does
         this: an `aws-chunked` body frames its own end, an identity body does
         not, and a driver write loop with no idea how much is coming is how a
         truncated upload becomes a stored object. */
      throw refuse("MissingContentLength");
    }
    const written = await this.#writeObject(driver, route.path, source.bytes);
    if (source.framing === "identity" && written !== lengths.contentLength) {
      throw refuse(
        "IncompleteBody",
        `The request body was ${written} bytes, not the declared ${lengths.contentLength}.`,
      );
    }
    await this.#applyMtime(driver, route.path, mtime);
    const stats = await driver.stat(route.path);
    return {
      status: 200,
      headers: {
        ...this.#headers(requestId),
        etag: formatETag(objectETag(stats)),
        "content-length": "0",
      },
    };
  }

  /**
   * `PUT key/` — the directory marker (plan decision): `mkdir -p`, and `200`
   * for a directory that was already there, which is what makes a client's
   * repeated `sync` idempotent.
   *
   * The body must be empty. S3 would store whatever bytes came with a key
   * ending in `/`; here that key *is* the directory, so bytes would have
   * nowhere to go, and silently dropping them is the one thing a storage
   * gateway may never do.
   */
  async #putDirectory(
    driver: Loopback,
    route: S3ObjectTarget,
    body: AsyncIterable<Uint8Array>,
    mtime: number | undefined,
    requestId: string,
  ): Promise<S3StreamResponse> {
    for await (const chunk of guardSource(body)) {
      if (chunk.byteLength > 0) {
        throw refuse(
          "InvalidRequest",
          "A key ending in / names a directory and its body must be empty.",
        );
      }
    }
    await driver.mkdir(route.path, { recursive: true });
    await this.#applyMtime(driver, route.path, mtime);
    const stats = await driver.stat(route.path);
    return {
      status: 200,
      headers: {
        ...this.#headers(requestId),
        etag: formatETag(objectETag(stats)),
        "content-length": "0",
      },
    };
  }

  /**
   * Stream a body into the object, and answer how many bytes it held.
   *
   * The destination is opened **lazily**, at the first byte that survives
   * decoding. That is the whole of this gateway's write atomicity and it is
   * worth being precise about (see the module docs): a `PUT` whose first chunk
   * fails its signature, or whose framing is wrong from the start, leaves the
   * bucket untouched — no truncated object, no empty one created. A failure
   * *after* the first chunk leaves a partial object, because there is no
   * temporary file and no rename here.
   *
   * Each chunk is written with an `await` before the iterator advances, so the
   * driver is done with the buffer before the source can reuse it — which is
   * why nothing is copied on this path.
   */
  async #writeObject(
    driver: Loopback,
    path: string,
    source: AsyncIterable<Uint8Array>,
  ): Promise<number> {
    const cap = this.options.maxBodyBytes;
    let handle: FileHandleLike | undefined;
    let written = 0;
    try {
      for await (const chunk of source) {
        if (chunk.byteLength === 0) {
          continue;
        }
        if (cap !== undefined && written + chunk.byteLength > cap) {
          throw refuse("EntityTooLarge");
        }
        handle ??= await this.#openForWrite(driver, path);
        await handle.write(chunk, 0, chunk.byteLength, written);
        written += chunk.byteLength;
      }
      // A zero-byte object is still an object.
      handle ??= await this.#openForWrite(driver, path);
    } finally {
      await handle?.close();
    }
    return written;
  }

  /**
   * Open an object for writing, creating the prefix it names if it is not a
   * directory yet.
   *
   * **A prefix is not a directory in S3**, and no client creates one: `PUT
   * photos/2024/june.jpg` into an empty bucket is the ordinary case, not an
   * error, and every tool from rclone to the AWS CLI expects it to work. A
   * driver has directories, so the gateway makes them.
   *
   * The `open` is tried **first** and the `mkdir` happens only on `ENOENT`, for
   * three reasons: the common case costs no extra driver call, a read-only
   * driver with no `mkdir` still serves the keys whose prefixes exist, and the
   * lazy-open guarantee is untouched (nothing is created until a byte of the
   * body has survived decoding).
   *
   * A *file* on a component of the prefix does not reach the `mkdir` at all —
   * the first `open` answers `ENOTDIR`, which `constants.ts` maps to
   * `NoSuchKey`, the honest answer for a key that cannot exist in this tree.
   * `EEXIST` from the `mkdir` is therefore the race — something put a file
   * there between the two calls — and it is swallowed so that the retried
   * `open` reports that same `ENOTDIR`, rather than the `mkdir`'s `EEXIST`,
   * which would answer `OperationAborted` (409) and describe a conflict that is
   * not what happened.
   */
  async #openForWrite(driver: Loopback, path: string): Promise<FileHandleLike> {
    try {
      return await driver.open(path, "w", 0o666);
    } catch (error) {
      const parent = dirname(path);
      if (errorCode(error) !== "ENOENT" || parent === "/") {
        throw error;
      }
      await driver.mkdir(parent, { recursive: true }).catch((failure: unknown) => {
        if (errorCode(failure) !== "EEXIST") {
          throw failure;
        }
      });
      return await driver.open(path, "w", 0o666);
    }
  }

  /**
   * The object bytes inside whatever framing the request used.
   *
   * `identity` is the body itself. `aws-chunked` goes through `chunked.ts`,
   * with the chain material recovered from the request `sigv4.ts` already
   * verified — the seed is the request's own signature, which is exactly what
   * the streaming specification chains from.
   *
   * A signed body arriving at a session with **no credentials** is decoded as
   * an unsigned one: there is no secret to check the chunk signatures against,
   * and refusing would make an unauthenticated gateway reject the AWS CLI's
   * default upload. The framing is still enforced.
   */
  #objectBody(
    head: S3RequestHead,
    body: AsyncIterable<Uint8Array>,
    verified: SigV4Verified | undefined,
  ): { framing: "identity" | "aws-chunked"; bytes: AsyncIterable<Uint8Array> } {
    const guarded = guardSource(body);
    const mode = bodyMode(head.headers);
    if (mode.framing === "identity") {
      return { framing: "identity", bytes: guarded };
    }
    const lengths = this.#lengths(head);
    const trailer = headerValue(head.headers, "x-amz-trailer");
    const trailers =
      trailer === undefined
        ? []
        : trailer
            .split(",")
            .map((name) => name.trim().toLowerCase())
            .filter((name) => name !== "");
    return {
      framing: "aws-chunked",
      bytes: decodeAwsChunked(guarded, {
        signature: mode.signedChunks ? this.#chunkedSignature(head, verified) : undefined,
        trailers,
        decodedLength: lengths.decodedContentLength,
      }),
    };
  }

  /** The chain material for a signed `aws-chunked` body, when there is any. */
  #chunkedSignature(
    head: S3RequestHead,
    verified: SigV4Verified | undefined,
  ): ChunkedSignature | undefined {
    const credentials = this.options.credentials;
    if (credentials === undefined || verified === undefined || verified.form !== "header") {
      return undefined;
    }
    /* `verified.form === "header"` means the request carried an `Authorization`
       header that parsed once already, so the fallbacks below are unreachable —
       and they fail closed rather than open: an empty seed makes every chunk
       signature mismatch, where answering `undefined` here would decode a
       signed body as an unsigned one. */
    const parsed = parseAuthorizationHeader(headerValue(head.headers, "authorization") ?? "");
    return {
      seed: parsed?.signature ?? "",
      amzDate: formatAmzDate(verified.timestamp),
      scope: verified.scope,
      secretAccessKey: credentials.secretAccessKey,
    };
  }

  #lengths(head: S3RequestHead): { contentLength?: number; decodedContentLength?: number } {
    const parsed = parseContentLengths(head.headers);
    if (!parsed.ok) {
      throw new S3ErrorThrown(parsed.error);
    }
    return parsed.lengths;
  }

  /**
   * `x-amz-meta-mtime` → `utimes` (plan decision, rclone's convention).
   *
   * Quiet when the driver has no `times` capability: a driver that cannot store
   * a timestamp is not thereby broken, and failing the upload over it would
   * make every `rclone copy` onto such a driver fail after writing the bytes.
   */
  async #applyMtime(driver: Loopback, path: string, mtime: number | undefined): Promise<void> {
    if (mtime === undefined || !driver.capabilities.times) {
      return;
    }
    const at = new Date(mtime);
    await driver.utimes(path, at, at);
  }

  // -------------------------------------------------------------------------
  // DELETE
  // -------------------------------------------------------------------------

  async #deleteObject(
    driver: Loopback,
    route: S3ObjectTarget,
    requestId: string,
  ): Promise<S3StreamResponse> {
    await this.#deleteKey(driver, route.path, route.directory);
    return { status: 204, headers: this.#headers(requestId) };
  }

  /**
   * Remove what a key names, and succeed when there was nothing there.
   *
   * S3's `DeleteObject` answers `204` for a key that does not exist — deleting
   * nothing *is* the requested end state — so the three errnos that mean "there
   * is no object at that key" resolve rather than throw:
   *
   * - `ENOENT` — nothing there.
   * - `ENOTDIR` — a path component is a file, so the key cannot exist; also
   *   what `rmdir` answers for `DELETE a/` when `a` is a file, and there is no
   *   object `a/` either way.
   * - `EISDIR` — `unlink` on a directory. There is no *object* `a` when `a` is
   *   a directory; the object is `a/`, and `DELETE a/` is the request that
   *   removes it. Answering `204` here says "there was no such object", which
   *   is true, rather than destroying a subtree the client did not name.
   *
   * `ENOTEMPTY` is left to throw: it becomes `BucketNotEmpty` (409), which is
   * the one code S3 has for "something is still inside it".
   */
  async #deleteKey(driver: Loopback, path: string, directory: boolean): Promise<void> {
    try {
      await (directory ? driver.rmdir(path) : driver.unlink(path));
    } catch (error) {
      const code = errorCode(error);
      if (code === "ENOENT" || code === "ENOTDIR" || code === "EISDIR") {
        return;
      }
      throw error;
    }
  }

  /**
   * `DeleteObjects`: one document in, one result document out.
   *
   * Per-key failures are reported per key and **never fail the request** — that
   * is the operation's whole purpose. `Quiet` reports only the failures, as S3
   * does. A key naming the staging prefix is answered the way an absent key is
   * (invisibility, per the multipart decision): reported deleted, since that is
   * what `DELETE` on it answers.
   */
  async #deleteObjects(
    driver: Loopback,
    head: S3RequestHead,
    body: AsyncIterable<Uint8Array>,
    verified: SigV4Verified | undefined,
    requestId: string,
  ): Promise<S3StreamResponse> {
    const document = await this.#readDocument(head, body, verified);
    const request = parseDeleteObjects(document, { maxBytes: this.#maxXmlBytes });
    if (request.objects.length > MAX_DELETE_KEYS) {
      throw refuse(
        "MalformedXML",
        `The request names ${request.objects.length} keys; at most ${MAX_DELETE_KEYS} are allowed.`,
      );
    }
    const deleted: DeletedEntry[] = [];
    const errors: DeleteErrorEntry[] = [];
    for (const object of request.objects) {
      if (isStagingKey(object.key)) {
        deleted.push({ key: object.key });
        continue;
      }
      const parsed = parseObjectKey(object.key);
      if (!parsed.ok) {
        errors.push({ key: object.key, code: parsed.error.code, message: parsed.error.message });
        continue;
      }
      try {
        await this.#deleteKey(driver, parsed.key.path, parsed.key.directory);
        deleted.push({ key: object.key });
      } catch (error) {
        this.options.onError?.(error, head);
        const spec = specOf(error);
        errors.push({ key: object.key, code: spec.code, message: spec.message });
      }
    }
    return this.#xml(
      encodeDeleteResult({ deleted: request.quiet ? [] : deleted, errors }),
      requestId,
    );
  }

  // -------------------------------------------------------------------------
  // CopyObject
  // -------------------------------------------------------------------------

  /**
   * `PUT` with `x-amz-copy-source`: a server-side copy.
   *
   * All four `x-amz-copy-source-if-*` conditionals are honoured, evaluated
   * against the *source* with RFC 9110 §13.2.2's precedence — the same
   * evaluator `GET` uses, handed the headers with their prefix stripped, and
   * the request's own method, so a matching `if-none-match` is `412` rather
   * than the `304` a safe method would get. A copy is not a read.
   *
   * `x-amz-metadata-directive` decides one thing here, because
   * `x-amz-meta-mtime` is the only metadata this gateway stores: `COPY`
   * preserves the source's modification time, `REPLACE` takes the request's
   * `x-amz-meta-mtime` and otherwise leaves the copy stamped now.
   *
   * There is no `copyFile` in `FsDriver` (it is not part of the
   * `node:fs/promises` subset), so the bytes go through the same streamed read
   * and write a `GET` and a `PUT` would use.
   */
  async #copyObject(
    driver: Loopback,
    route: S3Request & { op: "CopyObject" },
    head: S3RequestHead,
    requestId: string,
  ): Promise<S3StreamResponse> {
    if (route.directory) {
      throw refuse("InvalidRequest", "A copy destination must not be a directory key.");
    }
    const sourceDriver = this.buckets.get(route.source.bucket);
    if (sourceDriver === undefined) {
      throw refuse("NoSuchBucket");
    }
    if (
      route.metadataDirective === "COPY" &&
      route.source.bucket === route.bucket &&
      route.source.key === route.key
    ) {
      /* S3's own refusal, verbatim from the `CopyObject` reference. */
      throw refuse(
        "InvalidRequest",
        "This copy request is illegal because it is trying to copy an object to itself " +
          "without changing the object's metadata, storage class, website redirect location " +
          "or encryption attributes.",
      );
    }
    const stats = await this.#statObject(sourceDriver, route.source);
    /* Evaluated as if the method were safe, then collapsed: S3 answers `412`
       for all four `x-amz-copy-source-if-*` conditionals, including the two
       RFC 9110 §13.2.2 only evaluates for `GET`/`HEAD`. Passing the request's
       own `PUT` would silently drop `if-modified-since`, which is one of the
       four this gateway promises to honour. */
    const conditional = evaluateConditionals(
      { etag: objectETag(stats), mtimeMs: stats.mtimeMs },
      copySourceConditionals(head.headers),
      "GET",
    );
    if (conditional.status !== 200) {
      throw refuse("PreconditionFailed");
    }
    const inPlace = route.source.bucket === route.bucket && route.source.key === route.key;
    if (!inPlace) {
      /* A copy onto itself is only legal with `REPLACE`, and then it changes
         metadata alone — S3 does not rewrite the bytes and neither may this:
         opening the destination truncates the file the source handle is
         reading, which would empty the object it was asked to keep. */
      const handle = await sourceDriver.open(route.source.path, "r");
      await this.#writeObject(
        driver,
        route.path,
        streamHandle(handle, 0, stats.size, this.#readChunkBytes),
      );
    }
    const mtime =
      route.metadataDirective === "COPY"
        ? stats.mtimeMs
        : parseMetaMtime(headerValue(head.headers, META_MTIME_HEADER));
    await this.#applyMtime(driver, route.path, mtime);
    const copied = await driver.stat(route.path);
    return this.#xml(
      encodeCopyObjectResult({
        lastModified: formatIsoDate(copied.mtimeMs),
        etag: formatETag(objectETag(copied)),
      }),
      requestId,
    );
  }

  // -------------------------------------------------------------------------
  // ListBuckets
  // -------------------------------------------------------------------------

  /**
   * Every configured bucket, in key order.
   *
   * `CreationDate` is the driver root's modification time — the closest thing a
   * filesystem has to "when did this bucket appear" — and the epoch for a
   * driver whose root cannot be stat'ed. Not `now`: a listing that changes
   * every time it is asked for is worse than one that is honestly approximate.
   */
  async #listBuckets(requestId: string): Promise<S3StreamResponse> {
    const buckets = [];
    for (const name of this.bucketNames) {
      const driver = this.buckets.get(name) as Loopback;
      const stats = await driver.stat("/").catch(() => undefined);
      buckets.push({
        name,
        creationDate: stats === undefined ? EPOCH_ISO : formatIsoDate(stats.mtimeMs),
      });
    }
    return this.#xml(encodeListAllMyBucketsResult({ owner: SYNTHETIC_OWNER, buckets }), requestId);
  }

  // -------------------------------------------------------------------------
  // ListObjectsV2
  // -------------------------------------------------------------------------

  async #listObjects(
    driver: Loopback,
    route: S3Request & { op: "ListObjectsV2" },
    requestId: string,
  ): Promise<S3StreamResponse> {
    let after: string | undefined;
    if (route.continuationToken !== undefined) {
      after = decodeContinuationToken(route.continuationToken);
      if (after === undefined) {
        throw refuse("InvalidArgument", "The continuation token provided is incorrect");
      }
    } else {
      after = route.startAfter;
    }
    const contents: S3ObjectEntry[] = [];
    const commonPrefixes: string[] = [];
    let truncated = false;
    let cursor: string | undefined;
    /* Only a prefix a key could actually begin with reaches a driver path —
       see {@link listablePrefix}, which is also where the staging subtree is
       ruled out. Zero `max-keys` reads nothing at all: see below. */
    if (route.maxKeys > 0 && listablePrefix(route.prefix)) {
      const source =
        route.delimiter === undefined
          ? this.#walk(driver, "/", "", route.prefix, after)
          : this.#listLevel(driver, route.prefix, after);
      for await (const entry of source) {
        if (contents.length + commonPrefixes.length === route.maxKeys) {
          truncated = true;
          break;
        }
        /* The cursor is the last key *considered*, not the last one emitted: an
           object that vanished between the `readdir` and its `stat` still has
           to be stepped past, or the next page starts where this one did. */
        cursor = entry.key;
        if (entry.prefix) {
          commonPrefixes.push(entry.key);
          continue;
        }
        const stats = await driver.stat(entry.path).catch(() => undefined);
        if (stats === undefined) {
          continue;
        }
        contents.push({
          key: entry.key,
          lastModified: formatIsoDate(stats.mtimeMs),
          etag: formatETag(objectETag(stats)),
          size: entry.key.endsWith("/") ? 0 : stats.size,
          storageClass: STORAGE_CLASS,
          owner: route.fetchOwner ? SYNTHETIC_OWNER : undefined,
        });
      }
    }
    const encode = (value: string): string =>
      route.encodingType === "url" ? uriEncode(value) : value;
    return this.#xml(
      encodeListBucketResult({
        name: route.bucket,
        prefix: encode(route.prefix),
        continuationToken: route.continuationToken,
        nextContinuationToken:
          truncated && cursor !== undefined ? encodeContinuationToken(cursor) : undefined,
        startAfter: route.startAfter === undefined ? undefined : encode(route.startAfter),
        keyCount: contents.length + commonPrefixes.length,
        maxKeys: route.maxKeys,
        delimiter: route.delimiter === undefined ? undefined : encode(route.delimiter),
        encodingType: route.encodingType,
        isTruncated: truncated,
        contents: contents.map((entry) => ({ ...entry, key: encode(entry.key) })),
        commonPrefixes: commonPrefixes.map((prefix) => encode(prefix)),
      }),
      requestId,
    );
  }

  /**
   * The no-delimiter walk: a sorted depth-first traversal that emits full keys
   * in S3's order.
   *
   * Three filters run at every level, and each one is a pruning rule rather
   * than a post-hoc test, because a listing of a deep tree must not read the
   * subtrees it is going to discard:
   *
   * - **The prefix.** A file is kept when its key starts with the prefix. A
   *   directory is descended into when *either* everything under it matches
   *   (`d` starts with the prefix) *or* the prefix reaches into it (the prefix
   *   starts with `d`). That second case is what makes a prefix that does not
   *   align to a directory boundary work: `prefix=pho` descends into `photos/`
   *   because `pho` is a prefix of neither more nor less than that.
   * - **The cursor.** Keys under a directory `d` all begin with `d`, so if the
   *   cursor is past `d` and not inside it, the whole subtree is behind the
   *   cursor and is never opened. If the cursor *is* inside it, the walk
   *   descends and resumes mid-directory — which is what makes a token taken
   *   anywhere, including between a directory's children, resume exactly there.
   * - **The staging prefix**, at the bucket root only, where it lives. Never
   *   listed, at any depth (plan decision).
   *
   * The recursion starts at the deepest directory the prefix names, so
   * `prefix=photos/2024/ju` reads `/photos/2024` and nothing above it.
   */
  async *#walk(
    driver: Loopback,
    dirPath: string,
    dirKey: string,
    prefix: string,
    after: string | undefined,
  ): AsyncGenerator<ListEntry> {
    if (dirKey === "") {
      /* The first call: jump to the deepest directory that can hold the
         prefix, so the walk never reads the tree above it. */
      const slash = prefix.lastIndexOf("/");
      if (slash !== -1) {
        const startKey = prefix.slice(0, slash + 1);
        yield* this.#walk(driver, `/${startKey.slice(0, -1)}`, startKey, prefix, after);
        return;
      }
    }
    const entries = await this.#readdir(driver, dirPath);
    if (entries === undefined) {
      return;
    }
    if (entries.length === 0) {
      /* An empty directory is a marker object; the bucket root is not an
         object at all, so it never produces one. */
      if (
        dirKey !== "" &&
        dirKey.startsWith(prefix) &&
        (after === undefined || compareKeys(dirKey, after) > 0)
      ) {
        yield { key: dirKey, path: dirPath, prefix: false };
      }
      return;
    }
    for (const entry of sortEntries(entries, dirKey, dirKey === "")) {
      if (entry.directory) {
        if (!(entry.key.startsWith(prefix) || prefix.startsWith(entry.key))) {
          continue;
        }
        if (
          after !== undefined &&
          !after.startsWith(entry.key) &&
          compareKeys(after, entry.key) >= 0
        ) {
          continue;
        }
        yield* this.#walk(driver, entry.path, entry.key, prefix, after);
        continue;
      }
      if (!entry.key.startsWith(prefix)) {
        continue;
      }
      if (after !== undefined && compareKeys(entry.key, after) <= 0) {
        continue;
      }
      yield { key: entry.key, path: entry.path, prefix: false };
    }
  }

  /**
   * The `delimiter=/` listing: one `readdir` of the directory the prefix names.
   *
   * The prefix splits at its last `/` into a directory to read and a partial
   * name to filter by (`photos/2024/ju` reads `/photos/2024` and keeps names
   * starting with `ju`), which is the same alignment rule the walk uses and the
   * reason a prefix that stops mid-name works here too.
   *
   * Every subdirectory is one `CommonPrefixes` row, whether or not it is empty:
   * an empty directory's marker key `d/` has a `/` after the listed prefix, so
   * the delimiter groups it exactly like the keys of a non-empty one. The one
   * place the marker shows up as `Contents` is a listing whose prefix *is* that
   * directory (`prefix=e/`), where the key has nothing left to group on — see
   * the worked example in the module docs.
   */
  async *#listLevel(
    driver: Loopback,
    prefix: string,
    after: string | undefined,
  ): AsyncGenerator<ListEntry> {
    const slash = prefix.lastIndexOf("/");
    const dirKey = slash === -1 ? "" : prefix.slice(0, slash + 1);
    const namePrefix = prefix.slice(dirKey.length);
    const dirPath = dirKey === "" ? "/" : `/${dirKey.slice(0, -1)}`;
    const entries = await this.#readdir(driver, dirPath);
    if (entries === undefined) {
      return;
    }
    if (entries.length === 0) {
      if (
        namePrefix === "" &&
        dirKey !== "" &&
        (after === undefined || compareKeys(dirKey, after) > 0)
      ) {
        yield { key: dirKey, path: dirPath, prefix: false };
      }
      return;
    }
    for (const entry of sortEntries(entries, dirKey, dirKey === "")) {
      if (!entry.name.startsWith(namePrefix)) {
        continue;
      }
      if (after !== undefined && compareKeys(entry.key, after) <= 0) {
        continue;
      }
      yield { key: entry.key, path: entry.path, prefix: entry.directory };
    }
  }

  /**
   * A directory's entries, or `undefined` when the path is not a directory.
   *
   * The difference matters: an empty listing means "an empty directory", which
   * is a marker object, and `undefined` means "no such directory", which is
   * nothing at all. A prefix naming neither is an empty listing, not an error —
   * S3 has no opinion about a prefix that matches nothing.
   */
  async #readdir(driver: Loopback, path: string): Promise<DirentLike[] | undefined> {
    try {
      return await driver.readdir(path, { withFileTypes: true });
    } catch (error) {
      if (isAbsent(error)) {
        return undefined;
      }
      throw error;
    }
  }

  // -------------------------------------------------------------------------
  // bodies and documents
  // -------------------------------------------------------------------------

  /**
   * Read a request document into memory, bounded twice: by `Content-Length`
   * before a byte is read, and by the running total while it is.
   *
   * Every chunk is copied on the way in — it is retained past the `await` that
   * produced it, and `Buffer.prototype.slice` is a view (`AGENTS.md`: this
   * exact mistake corrupted an NFS `WRITE` payload once already).
   *
   * The body goes through the same framing pipeline a `PUT` uses, because a
   * signed client sends `aws-chunked` for a `POST ?delete` too.
   */
  async #readDocument(
    head: S3RequestHead,
    body: AsyncIterable<Uint8Array>,
    verified: SigV4Verified | undefined,
  ): Promise<Uint8Array> {
    const lengths = this.#lengths(head);
    if (lengths.contentLength !== undefined && lengths.contentLength > this.#maxXmlBytes) {
      throw refuse("MaxMessageLengthExceeded");
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    for await (const chunk of this.#objectBody(head, body, verified).bytes) {
      total += chunk.byteLength;
      if (total > this.#maxXmlBytes) {
        throw refuse("MaxMessageLengthExceeded");
      }
      chunks.push(copyBytes(chunk));
    }
    const document = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      document.set(chunk, offset);
      offset += chunk.byteLength;
    }
    this.#checkContentMd5(head, document);
    return document;
  }

  /**
   * `Content-MD5`, when the client sent one: base64 of the MD5 of the body it
   * says it sent (S3 API Reference — required by the SDKs for `DeleteObjects`).
   *
   * Verified rather than ignored, because it is one hash of a bounded document
   * and it is the client's own check that its request arrived intact. A
   * mismatch is `BadDigest`, S3's own code for it. Absent is fine: nothing
   * requires it here, and an object's integrity is the transport's job.
   */
  #checkContentMd5(head: S3RequestHead, document: Uint8Array): void {
    const expected = headerValue(head.headers, "content-md5");
    if (expected === undefined) {
      return;
    }
    const actual = createHash("md5").update(document).digest("base64");
    if (actual !== expected.trim()) {
      throw refuse("BadDigest");
    }
  }

  /** An XML document, as a reply. */
  #xml(document: string, requestId: string): S3StreamResponse {
    const body = Buffer.from(document, "utf8");
    return {
      status: 200,
      headers: {
        ...this.#headers(requestId),
        "content-type": XML_CONTENT_TYPE,
        "content-length": String(body.byteLength),
      },
      body,
    };
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** One directory entry, with the key it contributes to a listing. */
interface SortedEntry {
  name: string;
  /** The full key: `a/b.txt` for a file, `a/b/` for a directory. */
  key: string;
  path: string;
  directory: boolean;
}

/**
 * A directory's entries in **effective-key order** (plan decision): `name` for
 * a file, `name + "/"` for a directory.
 *
 * Not a plain name sort, and this is the case that proves it: with entries
 * `a.txt`, `a` (a directory holding `b`) and `a0`, the full keys are `a.txt`,
 * `a/b` and `a0`, whose byte order is `a.txt` < `a/b` < `a0` — because `.`
 * (0x2E) < `/` (0x2F) < `0` (0x30). Sorting the *names* would put `a` first and
 * emit `a/b` before `a.txt`, which is a listing no client can page through.
 *
 * Only regular files and directories are listed. A symlink, a FIFO or a socket
 * is not an S3 object and is not a prefix either, so it is skipped rather than
 * reported as something it is not — the same posture as a capability that is
 * refused rather than faked.
 */
function sortEntries(entries: DirentLike[], dirKey: string, root: boolean): SortedEntry[] {
  const sorted: SortedEntry[] = [];
  for (const entry of entries) {
    if (root && entry.name === MULTIPART_PREFIX) {
      // The staging area is invisible to every S3 operation.
      continue;
    }
    const directory = entry.isDirectory();
    if (!directory && !entry.isFile()) {
      continue;
    }
    sorted.push({
      name: entry.name,
      key: `${dirKey}${entry.name}${directory ? "/" : ""}`,
      path: `${dirKey === "" ? "" : `/${dirKey.slice(0, -1)}`}/${entry.name}`,
      directory,
    });
  }
  return sorted.sort((a, b) => compareKeys(a.key, b.key));
}

/**
 * Read `length` bytes from `start` through an open handle, in bounded pieces,
 * and close it when the consumer is done — including when the consumer walks
 * away early, which is what the `finally` of a generator is for.
 *
 * A **fresh buffer per read**: handing the same buffer to two `yield`s would
 * hand a consumer bytes that change under it as soon as it awaits anything, and
 * a client would receive one chunk of the object twice. A read that comes up
 * short (the file shrank under the stream) ends the body rather than looping.
 */
async function* streamHandle(
  handle: FileHandleLike,
  start: number,
  length: number,
  chunkBytes: number,
): AsyncGenerator<Uint8Array> {
  try {
    let position = start;
    let remaining = length;
    while (remaining > 0) {
      const size = Math.min(chunkBytes, remaining);
      const buffer = new Uint8Array(size);
      const { bytesRead } = await handle.read(buffer, 0, size, position);
      if (bytesRead <= 0) {
        return;
      }
      yield bytesRead === size ? buffer : buffer.subarray(0, bytesRead);
      position += bytesRead;
      remaining -= bytesRead;
    }
  } finally {
    await handle.close();
  }
}

/**
 * `If-Range` (RFC 9110 §13.1.5): does the client's validator still describe
 * this object?
 *
 * An entity tag is compared **strongly** — a `W/` tag can never match, because
 * a weak validator does not promise the bytes are identical — and a date
 * matches only the same second, which is all an `HTTP-date` can express.
 */
function ifRangeMatches(value: string, etag: string, mtimeMs: number): boolean {
  const trimmed = value.trim();
  if (trimmed.startsWith("W/")) {
    return false;
  }
  if (trimmed.startsWith(`"`)) {
    return trimmed === formatETag(etag);
  }
  const at = parseHttpDate(trimmed);
  return at !== undefined && Math.floor(mtimeMs / 1000) === Math.floor(at / 1000);
}

/**
 * The `x-amz-copy-source-if-*` headers, renamed to the `if-*` ones
 * `evaluateConditionals` reads.
 *
 * A rename rather than a second evaluator: `CopyObject`'s four conditionals are
 * the HTTP four, applied to the source instead of the target, and RFC 9110
 * §13.2.2's precedence between them is the same precedence.
 */
function copySourceConditionals(headers: readonly HeaderEntry[]): HeaderEntry[] {
  const prefix = "x-amz-copy-source-if-";
  const mapped: HeaderEntry[] = [];
  for (const header of headers) {
    const name = header.name.toLowerCase();
    if (name.startsWith(prefix)) {
      mapped.push({ name: `if-${name.slice(prefix.length)}`, value: header.value });
    }
  }
  return mapped;
}

/**
 * Any thrown value, as the S3 error one reply can be built from.
 *
 * The order is the order of specificity: an error this session raised on
 * purpose, then each codec's own error type, then a driver's errno through the
 * table in `constants.ts`, then `InternalError` for everything else. Total by
 * construction — every branch produces a spec, and the last one catches values
 * that are not even errors.
 */
function specOf(error: unknown): S3ErrorSpec {
  if (error instanceof S3ErrorThrown) {
    return error.spec;
  }
  if (isChunkedError(error)) {
    return chunkedRefusalError(error.reason, error.message);
  }
  if (isXmlError(error)) {
    return xmlRefusalError(error.reason, error.message);
  }
  if (error instanceof BodySourceError) {
    return s3Error("IncompleteBody");
  }
  const code = errorCode(error);
  if (code !== undefined) {
    const mapped = s3ErrorOf(code);
    const row = Object.values(S3_ERRORS).find((spec) => spec.code === mapped.code);
    /* v8 ignore next 3 -- `test/s3/protocol.test.ts` asserts every code the
       errno table can produce has a row here; this is the branch that must
       exist if that ever stops being true. */
    if (row === undefined) {
      return s3Error("InternalError");
    }
    return { code: row.code, status: row.status, message: row.message };
  }
  return s3Error("InternalError");
}
