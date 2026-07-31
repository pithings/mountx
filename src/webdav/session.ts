/**
 * The WebDAV session: one HTTP request in, one WebDAV reply out, and no socket.
 *
 * The same contract as every other session in this package (`AGENTS.md`,
 * invariant 9): {@link WebdavSession.handleRequest} never rejects, and every
 * thrown value becomes exactly one well-formed reply. `node:http` appears only
 * in `server.ts`. What is different from the mount transports is what is
 * *absent*: HTTP carries no handle table and no per-connection state, so there
 * is no `PathLock` here and no subtree rewrite on `MOVE` — a request resolves
 * its own paths and is done with them before it answers. That is the same
 * reason `mountx/s3` has neither.
 *
 * ## What this server implements, exactly
 *
 * **RFC 4918 classes 1, 2 and 3.** `OPTIONS`, `HEAD`, `GET`, `PUT`, `DELETE`,
 * `MKCOL`, `COPY`, `MOVE`, `PROPFIND`, `PROPPATCH`, `LOCK` and `UNLOCK`, over
 * one driver.
 *
 * Class 2 is the write locks of §6 and §7 — both scopes, both depths, leases
 * that lapse, and the *locked empty resource* a `LOCK` on an unmapped URL
 * creates (§7.3). The table behind them is `src/webdav/locks.ts`, which is
 * pure, synchronous and clockless; this file is where the clock enters
 * (`options.now`) and where a lock meets a driver. `supportedlock` and
 * `lockdiscovery` report what is really granted and really held, which is what
 * makes the `DAV: 1, 2, 3` header a statement rather than a claim
 * (`AGENTS.md`, invariant 5).
 *
 * The deliberate gaps, each because the driver interface has no answer for them
 * rather than because they were forgotten:
 *
 * - **No dead properties.** A driver stores bytes and inode metadata; there is
 *   nowhere to keep an arbitrary XML property without inventing a sidecar file
 *   that would then show up in every listing. `PROPPATCH` therefore answers
 *   `403 cannot-modify-protected-property` for everything, which is the
 *   truthful answer for a server whose properties are all live and all derived.
 * - **No conditional requests.** `If-Match`, `If-None-Match` and the two date
 *   forms are ignored rather than half-honoured — RFC 4918's own `If` (§10.4)
 *   is answered, and RFC 9110's four are not. `mountx/s3` implements them over
 *   the same derived ETag; they arrive here next.
 * - **`GET` of a collection is `405`.** A collection has no body in RFC 4918;
 *   the HTML index other servers answer with is a user interface, and
 *   `PROPFIND` is the protocol's own way to list one.
 *
 * ## Locks, and what a token is for
 *
 * A lock is state a *client* left behind: it survives the connection, the
 * request and — up to its lease — the client itself. Three rules of §6 and §7
 * are worth having in front of you, because each one is a place this file does
 * something that looks surprising:
 *
 * - **A lock never follows its resource** (§7.6). A `MOVE` of a lock root
 *   destroys the lock rather than carrying it, because §6.1 point 8 deletes any
 *   lock whose root became unmapped — so `#discardUnmapped` runs after every
 *   `DELETE`, `MOVE` and `COPY`, and checks each root rather than assuming it.
 * - **A lock on an unmapped URL creates a real, empty file** (§7.3), which
 *   outlives the lock. RFC 2518's lock-null resources are the alternative that
 *   §7.3 permits and this server does not implement: a resource that is neither
 *   present nor absent has no representation in a driver that stores files.
 * - **The token is the whole of ownership.** There is one principal here at
 *   most (`credentials`), so §6.4's "check that the authenticated principal
 *   matches the lock creator" reduces to holding the token — which is why
 *   `UNLOCK` needs nothing else, and why a token in an `If` header is proof.
 *
 * ## The `If` header, and the three refusals
 *
 * `If` (§10.4) is the other half of locking: it is how a request proves it
 * holds a lock, and §10.4.1 insists its two purposes stay separate — it is a
 * *precondition* that can fail, and it is a *submission* of every token in it
 * whether or not the condition that carried them was true. `#guard` does both,
 * once per request, and hands the mutating methods what was submitted.
 *
 * Which refusal a client gets says which of the two failed, and getting that
 * pair the wrong way round is the classic way to make a WebDAV client retry
 * forever:
 *
 * - **`412`** — the header was there and every state list evaluated false
 *   (§10.4.1). The client's state is stale; re-reading the resource is what
 *   fixes it.
 * - **`423` with `lock-token-submitted`** — the request would change a
 *   write-locked resource and did not carry that lock's token (§7.5.2). The
 *   `href`s name the lock roots in the way, which §16 requires and which saves
 *   the client a `PROPFIND` for `lockdiscovery`.
 * - **`207` with a `423` inside it** — the lock in the way is on a *member* of
 *   the tree the request named, not on the resource it named. §9.6.1 wants a
 *   multistatus for a failure on some other resource, and its own example is
 *   this one; nothing is deleted or moved when that happens.
 *
 * `GET`, `HEAD`, `PROPFIND` and `OPTIONS` are not lock-protected at all — §7 is
 * explicit that "all other HTTP/WebDAV methods defined so far — GET in
 * particular — function independently of a write lock" — but an `If` header on
 * one of them is still a precondition, because §10.4 puts no method restriction
 * on it.
 *
 * ## Symbolic links: followed for bytes, never walked
 *
 * WebDAV has no way to name a link, so a link is the resource it points at —
 * `GET`, `PROPFIND` and a `stat` for properties all follow one. The two
 * **recursive** operations do not, and both would be destructive if they did:
 *
 * - **`DELETE` removes the link**, which is why `#delete` takes an `lstat` and
 *   `#deleteTree` recurses on the `readdir` dirent rather than on a fresh
 *   `stat`. Following a link to a collection would empty out whatever it points
 *   at and leave the entry the client actually named sitting there.
 * - **`COPY` reports a link to a collection (`403`) rather than descending into
 *   it.** A link back to any ancestor makes the walk revisit a subtree it is
 *   still writing into, and each pass creates the next one; there is no depth at
 *   which that stops being wrong. A link to a *file* is followed and its bytes
 *   are copied, because that cannot recur.
 *
 * ## The properties this server has
 *
 * All live, all derived from one `stat` or from the lock table, and none of
 * them stored: `creationdate`, `displayname`, `getcontentlength`,
 * `getcontenttype`, `getetag`, `getlastmodified`, `resourcetype`,
 * `supportedlock` (the two entries §15.10 defines) and `lockdiscovery` (the
 * locks covering the resource, indirect ones included). RFC 4331's
 * `quota-available-bytes` and `quota-used-bytes` are answered from `statfs`
 * when a driver has one, and only when a request names them: RFC 4331 §3 keeps
 * them out of `allprop`, and a driver without `statfs` answers `ENOSYS`, which
 * is a `404` propstat rather than an invented number.
 *
 * The ETag is derived from the same inputs as the S3 gateway's — sha256 over
 * `dev:ino:size:mtimeMs`, first 32 hex characters — without its
 * multipart-shaped `-1` suffix, which is an S3 spelling and means nothing here.
 * It is a strong validator in the RFC 9110 sense as far as the driver's own
 * metadata goes: two writes within one millisecond that leave the size
 * unchanged are indistinguishable to it, which is the same resolution limit
 * `getlastmodified` has.
 *
 * ## Atomicity, stated rather than implied
 *
 * `PUT` writes in place, with no temporary file and no rename, for the reasons
 * `src/s3/session.ts` sets out at length: the driver interface has no atomic
 * create, `rename` is optional and only *declared* atomic, and a staging copy
 * would be visible to every listing. The destination is opened at the **first
 * byte of the body**, so a `PUT` refused before then leaves the resource
 * exactly as it was; one that dies mid-body leaves what had been written. A
 * `COPY` of a tree is not a transaction either — what succeeded stays — which
 * is why a partial one answers `207` naming each failure rather than a single
 * status that would describe neither half.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { createLoopback, type Loopback } from "../harness.ts";
import {
  etagMatchesWeakly,
  formatETag,
  formatHttpDate,
  formatIsoDate,
  parseETagList,
  parseRange,
} from "../http.ts";
import { basename, dirname, isPathInside, joinPath } from "../path.ts";
import type { FileHandleLike, FsDriver, StatsLike } from "../types.ts";
import type { XmlNode } from "../s3/xml.ts";
import {
  ALLOW_HEADER,
  COLLECTION_CONTENT_TYPE,
  DAV_COMPLIANCE,
  MAX_XML_BYTES,
  MS_AUTHOR_VIA,
  READ_CHUNK_BYTES,
  RESOURCE_CONTENT_TYPE,
} from "./constants.ts";
import { DavLockTable, type DavLock, type DavLockTableOptions, type LockDepth } from "./locks.ts";
import {
  collectBody,
  encodeLockResponse,
  encodeMultistatus,
  faultResponse,
  formatLockToken,
  hrefOf,
  lockDiscoveryNode,
  NO_BODY,
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
  xmlBody,
  type DavFault,
  type Depth,
  type IfCondition,
  type IfList,
  type MultistatusEntry,
  type Propstat,
  type WebdavRequestHead,
  type WebdavResponse,
} from "./protocol.ts";

// ---------------------------------------------------------------------------
// properties
// ---------------------------------------------------------------------------

/**
 * The properties an `allprop` request answers with, in document order.
 *
 * RFC 4918 §9.1 lets a server leave expensive properties out of `allprop`;
 * every one of these comes from a `stat` this session has already taken, so
 * none are left out. RFC 4331's quota pair is **not** here, which §3 of that
 * RFC requires.
 */
export const ALLPROP_NAMES = [
  "creationdate",
  "displayname",
  "getcontentlength",
  "getcontenttype",
  "getetag",
  "getlastmodified",
  "resourcetype",
  "supportedlock",
  "lockdiscovery",
] as const;

/** The two RFC 4331 quota properties, answered only when a request names them. */
export const QUOTA_NAMES = ["quota-available-bytes", "quota-used-bytes"] as const;

/**
 * The ETag for a resource: sha256 over `dev:ino:size:mtimeMs`, first 32 hex
 * characters.
 *
 * The same inputs as `mountx/s3`'s derived ETag, without the `-1` suffix that
 * makes an S3 client read it as a multipart tag. Derived rather than a digest
 * of the bytes: hashing a 5 GiB resource to answer a `PROPFIND` is not a thing
 * a server may do, and every input here is metadata the `stat` already carried.
 */
export function resourceETag(stats: StatsLike): string {
  return createHash("sha256")
    .update(`${stats.dev}:${stats.ino}:${stats.size}:${stats.mtimeMs}`)
    .digest("hex")
    .slice(0, 32);
}

// ---------------------------------------------------------------------------
// options
// ---------------------------------------------------------------------------

/** A username and password for HTTP Basic authentication (RFC 7617). */
export interface WebdavCredentials {
  username: string;
  password: string;
}

export interface WebdavSessionOptions {
  /**
   * The one credential pair this server accepts. **Present means every request
   * is authenticated**; absent means every request is served, which is only
   * safe on a loopback bind and is what `server.ts` enforces.
   *
   * Basic over plain HTTP sends the password recoverably on every request. That
   * is WebDAV's own default — it is the scheme every client implements — and it
   * is the caller's job to put TLS or a loopback in front of it.
   */
  credentials?: WebdavCredentials;
  /** The realm named in `WWW-Authenticate`. Default `mountx`. */
  realm?: string;
  /** Bytes per positional read when streaming a `GET`. Default {@link READ_CHUNK_BYTES}. */
  readChunkBytes?: number;
  /** Largest XML request body accepted. Default {@link MAX_XML_BYTES}. */
  maxXmlBytes?: number;
  /**
   * Largest `PUT` body accepted, in bytes. **Default unlimited** — a gateway in
   * front of a disk has no business inventing a smaller limit than the disk's,
   * and a driver that runs out answers `ENOSPC`, which is already `507`.
   */
  maxBodyBytes?: number;
  /**
   * The clock, in milliseconds. Default `Date.now`.
   *
   * The **one** impure default in this file, and the same boundary
   * `S3SessionOptions.now` draws: a lock's lease is a fact about now, and every
   * module below this one — `src/http.ts`, `src/webdav/locks.ts` — takes its
   * time as an argument on purpose. Pass one and a whole lock lifecycle,
   * expiry included, is deterministic.
   */
  now?: () => number;
  /**
   * Lock-table policy: the default and maximum lease, the cap on live locks,
   * and the token minter. See `src/webdav/locks.ts` for what each one costs.
   */
  locks?: DavLockTableOptions;
  /** Run the reply-exactly-once assertions. Default on outside production. */
  debug?: boolean;
  /** Called for every request that ends in an error reply. */
  onError?: (error: unknown, head: WebdavRequestHead | undefined) => void;
  /** Called when a dev-mode assertion fails. Default: collect in `assertions`. */
  onAssertion?: (message: string) => void;
}

/** Counters, all cheap, all useful in a test. */
export interface WebdavSessionStats {
  /** Requests handed to {@link WebdavSession.handleRequest}. */
  requests: number;
  /** Replies produced (successful or not). */
  replies: number;
  /** Of which replies with a `4xx` or `5xx` status. */
  errors: number;
  /** Per-method counts. */
  methods: Map<string, number>;
  /** Dev-mode assertion failures. Must be zero. */
  assertions: number;
}

/** One resource a recursive walk could not deal with. */
interface Failure {
  path: string;
  collection: boolean;
  status: number;
}

/**
 * What one request knows before it touches the driver: when it is being
 * answered, and which lock tokens its `If` header submitted (§10.4.1).
 *
 * Built once per request in `#guard` and threaded through the mutating methods
 * rather than recomputed, so that a `MOVE` weighing a lock at its source and
 * another at its destination reads both against one moment — a lease that
 * lapsed between the two checks would otherwise make the same request answer
 * two different things about itself.
 */
interface Guard {
  now: number;
  submitted: Set<string>;
  /**
   * The lists themselves, kept only for the one method that evaluates them
   * itself: `LOCK` has a `412` of its own with a §16 condition on it
   * (`lock-token-matches-request-uri`), and it is a better answer than the bare
   * one §10.4 gives, so a refresh decides the order — is there a lock here at
   * all, and only then, is the header true.
   */
  lists: readonly IfList[] | undefined;
}

/** The state an `If` condition is matched against (§10.4.4). */
interface ResourceState {
  /** Every lock token whose scope covers the resource. */
  tokens: readonly string[];
  /** Its entity tag, or `undefined` for a collection and for nothing at all. */
  etag: string | undefined;
}

/**
 * A resource this server cannot say anything about: an unmapped URL, or a
 * tagged list naming another origin.
 *
 * §10.4.4 makes both the same case — "treat as if the URL identified a resource
 * that exists but does not have the specified state" — so every plain condition
 * against it is false and every negated one is true.
 */
const UNKNOWN_RESOURCE: ResourceState = { tokens: [], etag: undefined };

/**
 * Does the resource have the state this condition describes, `Not` aside?
 *
 * A **state token** matches when it is one of the resource's, which for a lock
 * token means "the resource is anywhere in the scope of the lock" (§10.4.4).
 * An **entity tag** matches under RFC 9110 §8.8.3.2's *weak* comparison, which
 * §10.4.4 explicitly leaves to the server ("servers MUST use either the weak or
 * the strong comparison function"): §10.4.9's own example carries `[W/"A weak
 * ETag"]` and expects it to match, and every tag this server mints is strong,
 * so the weak function is the one that reads the RFC's examples the way they
 * are written.
 */
function matchesCondition(condition: IfCondition, state: ResourceState): boolean {
  if (condition.token !== undefined) {
    return state.tokens.includes(condition.token);
  }
  return (
    state.etag !== undefined &&
    condition.etag !== undefined &&
    etagMatchesWeakly(parseETagList(condition.etag), state.etag)
  );
}

// ---------------------------------------------------------------------------
// the session
// ---------------------------------------------------------------------------

/**
 * A WebDAV server over one driver, with no socket.
 *
 * ```ts
 * const session = new WebdavSession(createMemoryDriver());
 * const reply = await session.handleRequest({
 *   method: "PROPFIND",
 *   target: "/",
 *   headers: { depth: "1" },
 * });
 * ```
 */
export class WebdavSession {
  /** The driver, wrapped so paths are normalized and gaps answer `ENOSYS`. */
  readonly driver: Loopback;
  /**
   * Every write lock this share holds (RFC 4918 §6).
   *
   * Public because it is the only server state a caller can reasonably want to
   * see — how many locks are out, and on what — and because a test that drives
   * the lease has to be able to read it. It is the session's own: HTTP gives
   * every request the same session, so unlike 9P's table there is no second
   * connection to share it with.
   */
  readonly locks: DavLockTable;
  readonly options: WebdavSessionOptions;
  readonly stats: WebdavSessionStats = {
    requests: 0,
    replies: 0,
    errors: 0,
    methods: new Map(),
    assertions: 0,
  };
  /** Dev-mode assertion failures, in order. Empty in a healthy session. */
  readonly assertions: string[] = [];

  readonly #readChunkBytes: number;
  readonly #maxXmlBytes: number;
  readonly #now: () => number;
  readonly #debug: boolean;
  /** Requests not answered yet, by internal ticket — see `S3Session`'s. */
  readonly #inflight = new Set<number>();
  #nextTicket = 1;

  constructor(driver: FsDriver, options: WebdavSessionOptions = {}) {
    this.driver = createLoopback(driver);
    this.options = options;
    this.#readChunkBytes = options.readChunkBytes ?? READ_CHUNK_BYTES;
    this.#maxXmlBytes = options.maxXmlBytes ?? MAX_XML_BYTES;
    this.#now = options.now ?? Date.now;
    this.locks = new DavLockTable(options.locks);
    this.#debug = options.debug ?? process.env.NODE_ENV !== "production";
  }

  /**
   * Answer one request. **Never rejects**, and produces exactly one reply.
   *
   * A `HEAD` reply carries the headers of the `GET` it stands for —
   * `Content-Length` included — and no body, which is RFC 9110 §9.3.2 rather
   * than anything WebDAV says.
   */
  async handleRequest(
    head: WebdavRequestHead,
    body: AsyncIterable<Uint8Array> = NO_BODY,
  ): Promise<WebdavResponse> {
    this.stats.requests++;
    const ticket = this.#nextTicket++;
    if (this.#debug) {
      this.#inflight.add(ticket);
    }
    let response: WebdavResponse | undefined;
    try {
      response = await this.#dispatch(head, body);
    } catch (error) {
      this.options.onError?.(error, head);
      response = faultResponse(error);
    }
    /* v8 ignore next 3 -- structurally unreachable: one `handleRequest` call
       answers once. The assertion is what makes that structural. */
    if (this.#debug && !this.#inflight.delete(ticket)) {
      this.#assert(`${head.method} ${head.target} was answered twice`);
    }
    /* v8 ignore next 4 -- `#dispatch` returns or throws, and the catch answers
       everything it throws. The assertion is the point: if that ever stops
       being true, a caller must not be left waiting. */
    if (response === undefined) {
      this.#assert(`${head.method} ${head.target} produced no reply`);
      response = { status: 500, headers: { "content-length": "0" } };
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
    head: WebdavRequestHead,
    body: AsyncIterable<Uint8Array>,
  ): Promise<WebdavResponse> {
    const method = head.method.toUpperCase();
    this.#count(method);
    const unauthorized = this.#authorize(head);
    if (unauthorized !== undefined) {
      return unauthorized;
    }
    /* `OPTIONS *` asks about the server rather than about a resource (RFC 9110
       §9.3.7), so it is answered before the target is read as a path — which is
       what `*` is not. */
    if (method === "OPTIONS") {
      return this.#options();
    }
    const path = parseTargetPath(head.target);
    /* The `If` header is evaluated here, once, for every method that names a
       resource — §10.4 puts no method restriction on it, and a `GET` whose
       state lists all fail is as much a `412` as a `PUT`'s. What the *guard*
       carries on to the mutating methods is the other half of §10.4.1: which
       tokens were submitted. */
    const guard = await this.#guard(head, path, method !== "LOCK");
    switch (method) {
      case "GET":
      case "HEAD": {
        return await this.#get(head, path);
      }
      case "PUT": {
        return await this.#put(head, path, body, guard);
      }
      case "DELETE": {
        return await this.#delete(head, path, guard);
      }
      case "MKCOL": {
        return await this.#mkcol(path, body, guard);
      }
      case "COPY":
      case "MOVE": {
        return await this.#copyOrMove(head, path, method === "MOVE", guard);
      }
      case "PROPFIND": {
        return await this.#propfind(head, path, body, guard);
      }
      case "PROPPATCH": {
        return await this.#proppatch(path, body, guard);
      }
      case "LOCK": {
        return await this.#lock(head, path, body, guard);
      }
      case "UNLOCK": {
        return this.#unlock(head, path);
      }
      default: {
        /* `REPORT`, `PATCH`, `SEARCH`, anything else: the `Allow` header is the
           honest list, and a client reading it learns what this server has
           without having to parse the `DAV` header. */
        throw refuse(405, { headers: { allow: ALLOW_HEADER } });
      }
    }
  }

  #count(method: string): void {
    this.stats.methods.set(method, (this.stats.methods.get(method) ?? 0) + 1);
  }

  #assert(message: string): void {
    this.stats.assertions++;
    this.assertions.push(message);
    this.options.onAssertion?.(message);
  }

  /**
   * `401` for a request that did not prove who it is, or `undefined` to carry
   * on.
   *
   * Basic (RFC 7617), and only Basic: it is what every WebDAV client
   * implements, and a Digest implementation would need server state this
   * session deliberately does not keep. The comparison is over sha256 digests
   * rather than the strings, so it is constant-time in the *content* and
   * carries no length to time — `timingSafeEqual` requires equal lengths, and
   * padding to reach that is what leaks the length.
   */
  #authorize(head: WebdavRequestHead): WebdavResponse | undefined {
    const credentials = this.options.credentials;
    if (credentials === undefined) {
      return undefined;
    }
    const header = head.headers["authorization"];
    const supplied = header === undefined ? undefined : parseBasic(header);
    const expected = `${credentials.username}:${credentials.password}`;
    if (supplied !== undefined && digestEquals(supplied, expected)) {
      return undefined;
    }
    this.options.onError?.(refuse(401), head);
    const realm = (this.options.realm ?? "mountx").replaceAll(/["\\]/g, "");
    return {
      status: 401,
      headers: {
        "www-authenticate": `Basic realm="${realm}", charset="UTF-8"`,
        "content-length": "0",
      },
    };
  }

  // -------------------------------------------------------------------------
  // OPTIONS
  // -------------------------------------------------------------------------

  /**
   * What this server is, in headers (RFC 4918 §8.1, §10.1).
   *
   * Answered without touching the driver and without resolving the target: a
   * client sends `OPTIONS` to decide whether to speak WebDAV at all, and
   * failing it with a `404` for a path that does not exist yet — which is
   * exactly what a client about to `PUT` is asking about — would end the
   * conversation before it started.
   */
  #options(): WebdavResponse {
    return {
      status: 200,
      headers: {
        dav: DAV_COMPLIANCE,
        allow: ALLOW_HEADER,
        "ms-author-via": MS_AUTHOR_VIA,
        "accept-ranges": "bytes",
        "content-length": "0",
      },
    };
  }

  // -------------------------------------------------------------------------
  // GET / HEAD
  // -------------------------------------------------------------------------

  async #get(head: WebdavRequestHead, path: string): Promise<WebdavResponse> {
    const stats = await this.#stat(path);
    if (stats.isDirectory()) {
      throw refuse(405, {
        headers: { allow: ALLOW_HEADER },
        message: "a collection has no body; use PROPFIND to list it",
      });
    }
    if (!stats.isFile()) {
      /* A FIFO, a socket or a device node — nameable in a driver, and not
         something HTTP can transfer. The memory driver is the one that makes
         these reachable at all (`mountx.mknod`). */
      throw refuse(403, { message: "that resource is not a regular file" });
    }
    const range = parseRange(head.headers["range"], stats.size);
    const headers = this.#resourceHeaders(stats);
    if (range.kind === "unsatisfiable") {
      throw refuse(416, { headers: { "content-range": `bytes */${stats.size}` } });
    }
    const start = range.kind === "range" ? range.start : 0;
    const length = range.kind === "range" ? range.length : stats.size;
    headers["content-length"] = String(length);
    if (range.kind === "range") {
      headers["content-range"] = `bytes ${range.start}-${range.end}/${stats.size}`;
    }
    const status = range.kind === "range" ? 206 : 200;
    if (length === 0 || head.method.toUpperCase() === "HEAD") {
      /* No body, and — for `HEAD` — no `open` either: the headers above are
         already the ones a `GET` would send, and opening here would hand a
         descriptor to a reply that is about to drop it. */
      return { status, headers };
    }
    /* Opened here rather than inside the generator so that a failure to open is
       a status rather than a stream that dies after the status line. The
       generator owns the handle and closes it in a `finally`, which runs when a
       consumer that has *started* it abandons it — see `server.ts`. */
    const handle = await this.driver.open(path, "r");
    return { status, headers, body: streamHandle(handle, start, length, this.#readChunkBytes) };
  }

  /** The headers every resource reply carries, `Content-Length` aside. */
  #resourceHeaders(stats: StatsLike): Record<string, string> {
    return {
      "content-type": RESOURCE_CONTENT_TYPE,
      "last-modified": formatHttpDate(stats.mtimeMs),
      etag: formatETag(resourceETag(stats)),
      "accept-ranges": "bytes",
    };
  }

  // -------------------------------------------------------------------------
  // PUT
  // -------------------------------------------------------------------------

  /**
   * Store a resource (RFC 4918 §9.7).
   *
   * `201` when it did not exist, `204` when it replaced one. The two refusals
   * that are the protocol's rather than the driver's: a `PUT` onto an existing
   * collection is `405` (§9.7.2), and a `PUT` whose parent is not a collection
   * — missing, or a resource — is `409` (§9.7.1), never the `404` a plain HTTP
   * server would answer.
   *
   * `Content-Range` is `400`: RFC 9110 §14.2 forbids a server from acting on
   * one in a `PUT`, and a client that sent it wanted a partial write that this
   * would silently turn into a truncating whole-resource one.
   */
  async #put(
    head: WebdavRequestHead,
    path: string,
    body: AsyncIterable<Uint8Array>,
    guard: Guard,
  ): Promise<WebdavResponse> {
    if (head.headers["content-range"] !== undefined) {
      throw refuse(400, { message: "Content-Range is not allowed on a PUT (RFC 9110 §14.2)" });
    }
    if (path === "/") {
      throw refuse(405, { headers: { allow: ALLOW_HEADER } });
    }
    const existing = await this.#statOrAbsent(path);
    if (existing?.isDirectory() === true) {
      throw refuse(405, { headers: { allow: ALLOW_HEADER } });
    }
    await this.#requireCollection(dirname(path));
    /* A `PUT` over an existing resource changes that resource; one that creates
       a resource also changes its parent's membership (§7.4), and the parent's
       own depth-0 lock protects exactly that. */
    this.#requireWritable(path, guard, { membership: existing === undefined });
    await this.#write(path, body);
    const stats = await this.#statOrAbsent(path);
    const headers: Record<string, string> = { "content-length": "0" };
    if (stats !== undefined) {
      headers["etag"] = formatETag(resourceETag(stats));
      headers["last-modified"] = formatHttpDate(stats.mtimeMs);
    }
    return { status: existing === undefined ? 201 : 204, headers };
  }

  /**
   * Stream a body into a resource, and answer how many bytes it held.
   *
   * The destination is opened at the **first byte**, which is where this
   * server's whole write atomicity lives (see the module docs). Each chunk is
   * awaited into the driver before the iterator advances, so the transport's
   * buffer is free the moment `write` returns and nothing is copied on this
   * path.
   */
  async #write(path: string, source: AsyncIterable<Uint8Array>): Promise<number> {
    const cap = this.options.maxBodyBytes;
    let handle: FileHandleLike | undefined;
    let written = 0;
    try {
      for await (const chunk of source) {
        if (chunk.byteLength === 0) {
          continue;
        }
        if (cap !== undefined && written + chunk.byteLength > cap) {
          throw refuse(413, { message: `the request body is over the ${cap}-byte budget` });
        }
        handle ??= await this.driver.open(path, "w", 0o666);
        await handle.write(chunk, 0, chunk.byteLength, written);
        written += chunk.byteLength;
      }
      // An empty resource is still a resource.
      handle ??= await this.driver.open(path, "w", 0o666);
    } finally {
      await handle?.close();
    }
    return written;
  }

  // -------------------------------------------------------------------------
  // DELETE
  // -------------------------------------------------------------------------

  /**
   * Remove a resource or a whole collection (RFC 4918 §9.6).
   *
   * `Depth` on a collection must be `infinity` — §9.6.1 has no partial delete —
   * and the header's absence means `infinity` too. `Depth: 0` on a collection
   * is therefore `400`, and on a non-collection every depth is fine because
   * there is nothing under it either way.
   *
   * A delete that fails partway answers `207` naming each resource that would
   * not go, which is §9.6.1's own shape: a single status would describe neither
   * what was removed nor what is left. A clean delete answers `204` with no
   * body — §9.6 is explicit that a `multistatus` must not be sent when
   * everything worked.
   */
  async #delete(head: WebdavRequestHead, path: string, guard: Guard): Promise<WebdavResponse> {
    if (path === "/") {
      throw refuse(403, { message: "the root collection is the share itself" });
    }
    /* `lstat`, not `stat`, and this is the one place in this file where the
       difference is destructive rather than cosmetic: a symbolic link to a
       collection would otherwise answer `isDirectory()`, and the recursive
       delete below would empty out whatever it points at instead of removing
       the one entry the client named. `DELETE` removes the link. */
    const stats = await this.#linkStat(path);
    const depth = parseDepth(head.headers["depth"], "infinity");
    if (depth === undefined) {
      throw refuse(400, { message: "Depth must be 0, 1 or infinity" });
    }
    if (stats.isDirectory() && depth !== "infinity") {
      throw refuse(400, { message: "DELETE of a collection is Depth: infinity" });
    }
    /* Removing an internal member is a change to the parent collection (§7.4),
       so both the resource's own locks and the parent's are in the way. */
    this.#requireWritable(path, guard, { membership: true });
    const locked = this.#lockedMembers(path, guard);
    if (locked.length > 0) {
      /* A locked member is a failure on a resource other than the request URI,
         which §9.6.1 answers with a multistatus — its own example is "a
         response with status 423 (Locked) if an internal resource was locked".
         Nothing has been deleted at this point: a tree that cannot go whole is
         not one to start taking apart. */
      return this.#multistatus(locked);
    }
    if (!stats.isDirectory()) {
      await this.driver.unlink(path);
      await this.#discardUnmapped(path, this.#now());
      return { status: 204, headers: { "content-length": "0" } };
    }
    const failures = await this.#deleteTree(path);
    /* Whatever went, went: the locks rooted on it die with it (§6.1 point 8),
       and a partial delete leaves the locks whose roots survived. */
    await this.#discardUnmapped(path, this.#now());
    return failures.length === 0
      ? { status: 204, headers: { "content-length": "0" } }
      : this.#multistatus(failures);
  }

  /**
   * Depth-first removal, collecting what would not go.
   *
   * A child that fails does **not** stop the walk: the client is owed the whole
   * picture, and the parent is then left in place because a directory with
   * survivors cannot be removed anyway. "Already gone" is success at every step
   * — a concurrent delete of the same tree is not a failure of this one.
   *
   * The recursion turns on the **dirent**, which describes the entry rather
   * than what it points at, so a symbolic link to a collection is unlinked here
   * and never walked into. That is the same rule the `lstat` in `#delete`
   * applies at the top of the tree.
   */
  async #deleteTree(path: string): Promise<Failure[]> {
    const failures: Failure[] = [];
    let entries;
    try {
      entries = await this.driver.readdir(path, { withFileTypes: true });
    } catch (error) {
      if (isAbsent(error)) {
        return failures;
      }
      failures.push({ path, collection: true, status: statusOfError(error) });
      return failures;
    }
    for (const entry of entries) {
      const child = joinPath(path, entry.name);
      if (entry.isDirectory()) {
        failures.push(...(await this.#deleteTree(child)));
        continue;
      }
      try {
        await this.driver.unlink(child);
      } catch (error) {
        if (!isAbsent(error)) {
          failures.push({ path: child, collection: false, status: statusOfError(error) });
        }
      }
    }
    if (failures.length > 0) {
      /* Something under it survived, so the collection itself cannot go. Not
         reported as its own failure: the client already has the reason, one
         level down, and a `409 ENOTEMPTY` on top of it would name a consequence
         rather than a cause. */
      return failures;
    }
    try {
      await this.driver.rmdir(path);
    } catch (error) {
      if (!isAbsent(error)) {
        failures.push({ path, collection: true, status: statusOfError(error) });
      }
    }
    return failures;
  }

  // -------------------------------------------------------------------------
  // MKCOL
  // -------------------------------------------------------------------------

  /**
   * Create a collection (RFC 4918 §9.3).
   *
   * The three refusals §9.3.1 names, and they are all answered here rather than
   * left to the driver's errno: a body is `415` (this server defines no
   * extended `MKCOL`), an existing resource of any kind is `405`, and a missing
   * or non-collection parent is `409`.
   */
  async #mkcol(
    path: string,
    body: AsyncIterable<Uint8Array>,
    guard: Guard,
  ): Promise<WebdavResponse> {
    const content = await collectBody(body, this.#maxXmlBytes);
    if (content.byteLength > 0) {
      throw refuse(415, { message: "this server defines no MKCOL request body" });
    }
    if (path === "/" || (await this.#statOrAbsent(path)) !== undefined) {
      throw refuse(405, { headers: { allow: ALLOW_HEADER } });
    }
    await this.#requireCollection(dirname(path));
    // A new internal member of the parent collection (§7.4).
    this.#requireWritable(path, guard, { membership: true });
    await this.driver.mkdir(path);
    return { status: 201, headers: { "content-length": "0" } };
  }

  // -------------------------------------------------------------------------
  // COPY / MOVE
  // -------------------------------------------------------------------------

  /**
   * Copy or move a resource (RFC 4918 §9.8, §9.9).
   *
   * One method with a flag because every rule but the last is shared: the
   * `Destination` and `Overwrite` headers, the same-resource refusal, the
   * "destination inside the source" refusal, the parent check, and the
   * overwrite's own `DELETE`. What differs is the ending — `rename` for a
   * `MOVE`, a recursive byte copy for a `COPY` — and the legal depths: §9.9.2
   * gives `MOVE` `infinity` only, while `COPY` also takes `0`, which copies a
   * collection without its members.
   *
   * `201` when the destination was created, `204` when it replaced something,
   * which is §9.8.5's table.
   */
  async #copyOrMove(
    head: WebdavRequestHead,
    path: string,
    move: boolean,
    guard: Guard,
  ): Promise<WebdavResponse> {
    const destination = parseDestination(head.headers["destination"], head.headers["host"]);
    const overwrite = parseOverwrite(head.headers["overwrite"]);
    if (overwrite === undefined) {
      throw refuse(400, { message: "Overwrite must be T or F" });
    }
    const depth = this.#transferDepth(head.headers["depth"], move);
    const stats = await this.#stat(path);
    if (path === "/") {
      /* Checked before the two §9.8.5 refusals below rather than after, even
         though the second would catch it — every destination is "inside" the
         root — because the reason a client needs is this one: the share's own
         root is not a resource this server will move or copy away. */
      throw refuse(403, { message: "the root collection is the share itself" });
    }
    if (destination === path) {
      /* §9.8.5 and §9.9.5: the source and the destination are the same
         resource. `403` rather than a no-op, because a client that asked for
         this has a bug the no-op would hide. */
      throw refuse(403, { message: "the destination is the source" });
    }
    if (stats.isDirectory() && isPathInside(destination, path)) {
      /* Copying or moving a collection into itself is the one shape that cannot
         terminate: every level copied becomes another level to copy. §9.8.5 and
         §9.9.5 both make it a `403`. */
      throw refuse(403, { message: "the destination is inside the source collection" });
    }
    await this.#requireCollection(dirname(destination));
    const existing = await this.#statOrAbsent(destination);
    /* §7.5.1's example, stated as a rule: "even though both the source and
       destination are locked, only one lock token must be submitted (the one
       for the lock on the destination) ... because the source resource is not
       modified by a COPY". A `MOVE` modifies both ends, so it needs both. */
    if (move) {
      this.#requireWritable(path, guard, { membership: true });
    }
    this.#requireWritable(destination, guard, { membership: existing === undefined });
    const locked = [
      ...(move ? this.#lockedMembers(path, guard) : []),
      ...(existing === undefined ? [] : this.#lockedMembers(destination, guard)),
    ];
    if (locked.length > 0) {
      // A locked member at either end, named the way §9.6.1 names one.
      return this.#multistatus(locked);
    }
    if (existing !== undefined) {
      if (!overwrite) {
        throw refuse(412, { message: "the destination exists and Overwrite is F" });
      }
      /* §9.8.4: an overwriting COPY or MOVE performs a `DELETE` with
         `Depth: infinity` on the destination first, so the result is the source
         and nothing of what used to be there. */
      const failures = existing.isDirectory()
        ? await this.#deleteTree(destination)
        : await this.#unlinkOne(destination);
      if (failures.length > 0) {
        return this.#multistatus(failures);
      }
    }
    if (move) {
      await this.driver.rename(path, destination);
      /* §7.6: the lock does not travel with the resource. The source's locks
         are unmapped and die (§6.1 point 8); at the destination only a lock
         root the move did not recreate does. */
      const at = this.#now();
      await this.#discardUnmapped(path, at);
      await this.#discardUnmapped(destination, at);
      return { status: existing === undefined ? 201 : 204, headers: { "content-length": "0" } };
    }
    const failures = await this.#copyTree(path, destination, stats, depth === "infinity");
    // The source keeps every lock it had (§7.6: "a COPY ... MUST NOT duplicate any write locks").
    await this.#discardUnmapped(destination, this.#now());
    return failures.length > 0
      ? this.#multistatus(failures)
      : { status: existing === undefined ? 201 : 204, headers: { "content-length": "0" } };
  }

  /** The legal depths for `COPY` (`0` or `infinity`) and `MOVE` (`infinity`). */
  #transferDepth(value: string | undefined, move: boolean): Depth {
    const depth = parseDepth(value, "infinity");
    if (depth === undefined || depth === 1 || (move && depth !== "infinity")) {
      throw refuse(400, {
        message: move ? "MOVE is Depth: infinity" : "COPY is Depth: 0 or infinity",
      });
    }
    return depth;
  }

  /**
   * Copy one resource or one tree, collecting what would not copy.
   *
   * A collection copied with `Depth: 0` is created empty, which is §9.8.3's
   * own wording. Nothing about the source's metadata is carried over: mode,
   * ownership and timestamps are the destination's own, because RFC 4918 §9.8.2
   * makes only *dead* properties a copy's business and this server has none —
   * and the driver interface has no way to set them at create time anyway.
   */
  async #copyTree(
    source: string,
    destination: string,
    stats: StatsLike,
    deep: boolean,
  ): Promise<Failure[]> {
    if (!stats.isDirectory()) {
      if (!stats.isFile()) {
        return [{ path: source, collection: false, status: 403 }];
      }
      try {
        await this.#copyFile(source, destination, stats.size);
      } catch (error) {
        return [{ path: source, collection: false, status: statusOfError(error) }];
      }
      return [];
    }
    try {
      await this.driver.mkdir(destination);
    } catch (error) {
      return [{ path: source, collection: true, status: statusOfError(error) }];
    }
    if (!deep) {
      return [];
    }
    const failures: Failure[] = [];
    const entries = await this.driver.readdir(source, { withFileTypes: true });
    for (const entry of entries) {
      const child = joinPath(source, entry.name);
      const target = joinPath(destination, entry.name);
      const childStats = await this.#statOrAbsent(child);
      if (childStats === undefined) {
        // It went away between the listing and the copy; there is nothing to copy.
        continue;
      }
      if (entry.isSymbolicLink() && childStats.isDirectory()) {
        /* A link to a collection is reported, not walked. Following one is how
           a copy fails to terminate: a link back to any ancestor makes the
           walk revisit a subtree it is still writing into, and each pass
           creates the next one. A link to a *file* is followed — its bytes are
           copied — because that cannot recur. */
        failures.push({ path: child, collection: true, status: 403 });
        continue;
      }
      failures.push(...(await this.#copyTree(child, target, childStats, true)));
    }
    return failures;
  }

  /** Copy one file's bytes, a bounded chunk at a time. */
  async #copyFile(source: string, destination: string, size: number): Promise<void> {
    const from = await this.driver.open(source, "r");
    try {
      const to = await this.driver.open(destination, "w", 0o666);
      try {
        let position = 0;
        while (position < size) {
          const chunk = new Uint8Array(Math.min(this.#readChunkBytes, size - position));
          const { bytesRead } = await from.read(chunk, 0, chunk.byteLength, position);
          if (bytesRead <= 0) {
            /* The source shrank under the copy — a driver the host also has
               open can do that. What was read is what there is. */
            break;
          }
          await to.write(chunk, 0, bytesRead, position);
          position += bytesRead;
        }
      } finally {
        await to.close();
      }
    } finally {
      await from.close();
    }
  }

  /** `unlink` one resource, as the zero-or-one failure list the callers want. */
  async #unlinkOne(path: string): Promise<Failure[]> {
    try {
      await this.driver.unlink(path);
    } catch (error) {
      if (!isAbsent(error)) {
        return [{ path, collection: false, status: statusOfError(error) }];
      }
    }
    return [];
  }

  // -------------------------------------------------------------------------
  // PROPFIND
  // -------------------------------------------------------------------------

  /**
   * Read properties (RFC 4918 §9.1).
   *
   * `Depth` defaults to `infinity` when the header is absent, which §9.1
   * requires — and `infinity` is refused with `403
   * <propfind-finite-depth/>`, which §9.1 explicitly allows a server to do and
   * which is the only responsible answer for a driver that may be backed by a
   * network store: a client that means "list this collection" sends `Depth: 1`,
   * and one that omits the header gets told so in a form it can act on.
   *
   * A child that vanishes between the listing and its `stat` is left out
   * rather than reported: it is not a resource this `PROPFIND` can describe,
   * and it was gone before the reply was written.
   */
  async #propfind(
    head: WebdavRequestHead,
    path: string,
    body: AsyncIterable<Uint8Array>,
    guard: Guard,
  ): Promise<WebdavResponse> {
    const depth = parseDepth(head.headers["depth"], "infinity");
    if (depth === undefined) {
      throw refuse(400, { message: "Depth must be 0, 1 or infinity" });
    }
    if (depth === "infinity") {
      throw refuse(403, { condition: "propfind-finite-depth" });
    }
    const request = parsePropfind(await collectBody(body, this.#maxXmlBytes));
    const stats = await this.#stat(path);
    /* One `now` for the whole document, and it is the request's own: two
       resources described by one reply must not report leases read off two
       different clocks. */
    const now = guard.now;
    const entries: MultistatusEntry[] = [
      {
        href: hrefOf(path, stats.isDirectory()),
        propstat: await this.#propstats(path, stats, request, now),
      },
    ];
    if (depth === 1 && stats.isDirectory()) {
      for (const entry of await this.driver.readdir(path, { withFileTypes: true })) {
        const child = joinPath(path, entry.name);
        const childStats = await this.#statOrAbsent(child);
        if (childStats === undefined) {
          continue;
        }
        entries.push({
          href: hrefOf(child, childStats.isDirectory()),
          propstat: await this.#propstats(child, childStats, request, now),
        });
      }
    }
    return xmlBody(207, encodeMultistatus(entries));
  }

  /**
   * The `propstat` blocks for one resource: what was asked for and found, then
   * what was asked for and is not here.
   *
   * **A `404` block appears only for a request that named names.** `allprop`
   * and `propname` ask for whatever the server has, so a property this resource
   * does not have — `getcontentlength` on a collection, which §15.4 defines as
   * the `Content-Length` of a `GET` that this server answers `405` — is simply
   * left out rather than reported missing. Naming it explicitly is a different
   * question, with a different answer, and that one gets its `404`.
   *
   * `propname` answers names with no values, which is what §9.1's third form is
   * for; it is built from the same lookup as the values, so it can never
   * advertise a property the resource would not then produce.
   */
  async #propstats(
    path: string,
    stats: StatsLike,
    request: ReturnType<typeof parsePropfind>,
    now: number,
  ): Promise<Propstat[]> {
    const explicit = request.kind === "prop";
    const names = explicit ? request.names : [...ALLPROP_NAMES];
    const found: XmlNode[] = [];
    const missing: XmlNode[] = [];
    for (const name of names) {
      const node = await this.#property(name, path, stats, now);
      if (node === undefined) {
        if (explicit) {
          missing.push({ name });
        }
        continue;
      }
      found.push(request.kind === "propname" ? { name } : node);
    }
    const propstats: Propstat[] = [];
    if (found.length > 0 || missing.length === 0) {
      propstats.push({ status: 200, props: found });
    }
    if (missing.length > 0) {
      propstats.push({ status: 404, props: missing });
    }
    return propstats;
  }

  /**
   * One live property, or `undefined` for one this server does not have.
   *
   * Everything but the quota pair comes off the `stat` that has already been
   * taken. `getcontentlength` and `getetag` are answered for non-collections
   * only: RFC 4918 §15.4 defines the first as the `Content-Length` a `GET`
   * would carry, and a `GET` of a collection here is `405`.
   */
  async #property(
    name: string,
    path: string,
    stats: StatsLike,
    now: number,
  ): Promise<XmlNode | undefined> {
    const collection = stats.isDirectory();
    switch (name) {
      case "creationdate": {
        return { name, text: formatIsoDate(stats.birthtimeMs) };
      }
      case "displayname": {
        /* The root has no name of its own — `basename("/")` answers `"/"`,
           which is a path rather than a description — so it displays as
           nothing, which is what §15.2 leaves a server to send when there is
           nothing to display. */
        return { name, text: path === "/" ? "" : basename(path) };
      }
      case "getcontentlength": {
        return collection ? undefined : { name, text: String(stats.size) };
      }
      case "getcontenttype": {
        return { name, text: collection ? COLLECTION_CONTENT_TYPE : RESOURCE_CONTENT_TYPE };
      }
      case "getetag": {
        return collection ? undefined : { name, text: formatETag(resourceETag(stats)) };
      }
      case "getlastmodified": {
        return { name, text: formatHttpDate(stats.mtimeMs) };
      }
      case "resourcetype": {
        return { name, children: collection ? [{ name: "collection" }] : [] };
      }
      case "supportedlock": {
        /* The same two entries for every resource, collection or not: what a
           `LOCK` here accepts does not depend on what it is aimed at (§15.10). */
        return supportedLockNode();
      }
      case "lockdiscovery": {
        /* Every lock whose scope covers this resource, which includes the
           depth-infinity one rooted above it — §15.8 describes "the active
           locks on a resource", and an indirectly locked member is locked.
           Empty, with the element still sent, when there are none. */
        return lockDiscoveryNode(this.locks.covering(path, now), now);
      }
      case "quota-available-bytes":
      case "quota-used-bytes": {
        return await this.#quota(name, path);
      }
      default: {
        return undefined;
      }
    }
  }

  /**
   * RFC 4331's quota pair, from `statfs`.
   *
   * `available` is what this caller could still write (`bavail`, the
   * unprivileged figure, not `bfree`); `used` is total minus free. A driver
   * without `statfs` answers `ENOSYS` and the property is simply not here —
   * a `404` propstat, never a zero, because "no quota information" and "no
   * space left" are different answers and a client acts on them differently.
   */
  async #quota(name: string, path: string): Promise<XmlNode | undefined> {
    try {
      const statfs = await this.driver.statfs(path);
      const size = BigInt(Math.trunc(statfs.bsize));
      const value =
        name === "quota-available-bytes"
          ? BigInt(Math.trunc(statfs.bavail)) * size
          : (BigInt(Math.trunc(statfs.blocks)) - BigInt(Math.trunc(statfs.bfree))) * size;
      return { name, text: value < 0n ? 0n : value };
    } catch {
      /* `ENOSYS` from a driver without `statfs`, and anything else a driver
         answers: either way this server has no quota to report, and a `404`
         propstat says exactly that. */
      return undefined;
    }
  }

  // -------------------------------------------------------------------------
  // PROPPATCH
  // -------------------------------------------------------------------------

  /**
   * Refuse to write properties, in the form §9.2 requires.
   *
   * Every property in the request is named in the reply with `403` and the
   * `cannot-modify-protected-property` condition (§16), because every property
   * this server has is a live one derived from the driver's own metadata and
   * there is nowhere to put a dead one (see the module docs). The status is a
   * `207` rather than a plain `403`: §9.2 requires the per-property form
   * whenever the request named more than nothing, and a client that sent one
   * property it could have set alongside one it could not needs to see which
   * was which.
   */
  async #proppatch(
    path: string,
    body: AsyncIterable<Uint8Array>,
    guard: Guard,
  ): Promise<WebdavResponse> {
    const request = parseProppatch(await collectBody(body, this.#maxXmlBytes));
    const stats = await this.#stat(path);
    // §7's list of what a write lock covers names PROPPATCH explicitly.
    this.#requireWritable(path, guard);
    const names = [...request.set, ...request.remove];
    return xmlBody(
      207,
      encodeMultistatus([
        {
          href: hrefOf(path, stats.isDirectory()),
          propstat: [
            {
              status: 403,
              props: names.map((name) => ({ name })),
              condition: "cannot-modify-protected-property",
            },
          ],
        },
      ]),
    );
  }

  // -------------------------------------------------------------------------
  // the If header, and the locks it unlocks
  // -------------------------------------------------------------------------

  /**
   * Evaluate the `If` header and collect what it submitted (RFC 4918 §10.4).
   *
   * §10.4.1 gives the header two purposes and insists they are separate, and
   * this method is where that separation lives:
   *
   * 1. **A precondition.** Every list is evaluated; if the header has lists and
   *    none of them is true, the request is `412` and nothing else happens.
   * 2. **A submission.** Every state token in it counts as submitted "whatever
   *    the condition it expressed was found to be true" — so the tokens survive
   *    an evaluation the client did not need, which is what §10.4.8's
   *    `(Not <DAV:no-lock>)` idiom is for.
   *
   * @throws {DavFault} `400` for a header that is not the grammar, `412` for
   * one that evaluated to false.
   */
  async #guard(head: WebdavRequestHead, path: string, evaluate: boolean): Promise<Guard> {
    const now = this.#now();
    const lists = this.#ifLists(head);
    if (lists === undefined) {
      return { now, submitted: new Set(), lists: undefined };
    }
    const guard: Guard = { now, submitted: new Set(submittedTokens(lists)), lists };
    if (evaluate) {
      await this.#requireIf(guard, path);
    }
    return guard;
  }

  /**
   * The precondition half of §10.4.1, on its own: `412` unless some list is
   * true.
   *
   * Separate from {@link WebdavSession.#guard} because `LOCK` calls it at a
   * different moment — see {@link Guard.lists} — and idempotent, since a header
   * that is true stays true within one request.
   *
   * @throws {DavFault} `412`.
   */
  async #requireIf(guard: Guard, path: string): Promise<void> {
    if (guard.lists !== undefined && !(await this.#evaluateIf(guard.lists, path, guard.now))) {
      throw refuse(412, { message: "the If header's state lists all evaluated to false" });
    }
  }

  /**
   * Is any list true? A list is true when **every** condition in it is
   * (§10.4.3: conjunction inside a list, disjunction between them).
   *
   * The state of each resource is read at most once per request, because a
   * header naming the same resource in three lists is one `stat`, not three —
   * and because two lists about one resource must not be evaluated against two
   * different views of it.
   */
  async #evaluateIf(lists: readonly IfList[], path: string, now: number): Promise<boolean> {
    const states = new Map<string, ResourceState>();
    for (const list of lists) {
      const state = list.foreign
        ? UNKNOWN_RESOURCE
        : await this.#resourceState(list.resource ?? path, states, now);
      let all = true;
      for (const condition of list.conditions) {
        if (matchesCondition(condition, state) === condition.negated) {
          all = false;
          break;
        }
      }
      if (all) {
        return true;
      }
    }
    /* v8 ignore next 2 -- `parseIf` never answers an empty list array, so this
       loop always ran at least once; the `false` is the honest fallthrough. */
    return false;
  }

  /**
   * What an `If` condition can be matched against: the tokens on the resource
   * and its entity tag.
   *
   * §10.4.4's "handling unmapped URLs" rule is the reason both halves are
   * optional rather than an error: a URL with nothing at it is treated "as if
   * the URL identified a resource that exists but does not have the specified
   * state", so it has no tokens and no tag, every plain condition against it is
   * false, and every negated one is true. A **collection** has no entity tag
   * here for the same reason `getetag` is not one of its properties — §15.4
   * defines it against a `GET` this server answers `405` — while its lock
   * tokens are as real as any resource's.
   */
  async #resourceState(
    path: string,
    cache: Map<string, ResourceState>,
    now: number,
  ): Promise<ResourceState> {
    const cached = cache.get(path);
    if (cached !== undefined) {
      return cached;
    }
    const stats = await this.#statOrAbsent(path);
    const state: ResourceState = {
      tokens: this.locks.covering(path, now).map((lock) => lock.token),
      etag:
        stats === undefined || stats.isDirectory() ? undefined : formatETag(resourceETag(stats)),
    };
    cache.set(path, state);
    return state;
  }

  /**
   * Refuse a request that would change a write-locked resource without the
   * token for it (RFC 4918 §7, §7.5).
   *
   * "Clients MUST submit a lock-token they are authorized to use in any request
   * that modifies a write-locked resource ... or the method MUST fail." What
   * counts as modifying is §7's list, and it has two shapes, which is what
   * `membership` selects:
   *
   * - **The resource itself** — its bytes or its properties. Every lock
   *   covering it applies, the depth-infinity one rooted three levels up
   *   included (§6.1 point 4).
   * - **Its parent's membership** — a request that *creates* or *removes* an
   *   internal member of a collection (§7.4: "DELETE a collection's direct
   *   internal member ... PUT or MKCOL request that would create a new internal
   *   member"). A depth-**0** lock on the parent protects that and nothing else,
   *   which is exactly the case a coverage test on the member alone would miss.
   *
   * The refusal is §7.5.2's: `423` with `lock-token-submitted` naming the roots
   * that stopped it, because "it can be difficult for the client to find out
   * which locked resource made the request fail".
   *
   * @throws {DavFault} `423`.
   */
  #requireWritable(path: string, guard: Guard, options: { membership?: boolean } = {}): void {
    const blocking = this.locks
      .covering(path, guard.now)
      .filter((lock) => !guard.submitted.has(lock.token));
    if (options.membership === true && path !== "/") {
      for (const lock of this.locks.covering(dirname(path), guard.now)) {
        if (!guard.submitted.has(lock.token) && !blocking.includes(lock)) {
          blocking.push(lock);
        }
      }
    }
    if (blocking.length > 0) {
      throw refuse(423, {
        condition: "lock-token-submitted",
        hrefs: blocking.map((lock) => hrefOf(lock.path, lock.collection)),
        message: `${path} is write-locked and no token for it was submitted`,
      });
    }
  }

  /**
   * The members of a tree that are separately locked, as `207` entries.
   *
   * A lock rooted *below* the request URI is a failure on a **different**
   * resource, and §9.6.1 answers those with a multistatus rather than a status:
   * "the Multi-Status body could include a response with status 423 (Locked) if
   * an internal resource was locked". A lock covering the request URI itself is
   * not one of these — that one is {@link WebdavSession.#requireWritable}'s
   * plain `423`, which is what §7.5.2's example shows.
   */
  #lockedMembers(path: string, guard: Guard): Failure[] {
    return this.locks
      .within(path, guard.now)
      .filter((lock) => lock.path !== path && !guard.submitted.has(lock.token))
      .map((lock) => ({ path: lock.path, collection: lock.collection, status: 423 }));
  }

  // -------------------------------------------------------------------------
  // LOCK / UNLOCK
  // -------------------------------------------------------------------------

  /**
   * Take a write lock, or refresh one (RFC 4918 §9.10).
   *
   * The body decides which: one that holds a `lockinfo` creates a lock, and an
   * **empty** one refreshes the lock its `If` header names (§7.7 — "a server
   * receiving a LOCK request with no body MUST NOT create a new lock"). The
   * two share almost nothing, so they are two methods below this one.
   *
   * `200` for a lock on a resource that was there, `201` for one on a URL that
   * was not — §7.3's *locked empty resource*, a real empty file created by this
   * request that outlives the lock, because "clients must therefore be
   * responsible for cleaning up their own mess". RFC 2518's lock-null resources
   * are the alternative §7.3 permits and are deliberately not implemented: a
   * resource that is neither there nor absent has no representation in a driver
   * that stores files.
   */
  async #lock(
    head: WebdavRequestHead,
    path: string,
    body: AsyncIterable<Uint8Array>,
    guard: Guard,
  ): Promise<WebdavResponse> {
    const info = parseLockInfo(await collectBody(body, this.#maxXmlBytes));
    const now = guard.now;
    const timeout = parseTimeout(head.headers["timeout"]);
    if (info === undefined) {
      return await this.#refreshLock(path, timeout, guard);
    }
    await this.#requireIf(guard, path);
    /* §9.10.3: `0` or `infinity` and nothing else — `1` is a depth the lock
       model has no meaning for — and an absent header is `infinity`. */
    const depth = parseDepth(head.headers["depth"], "infinity");
    if (depth === undefined || depth === 1) {
      throw refuse(400, { message: "LOCK is Depth: 0 or infinity (RFC 4918 §9.10.3)" });
    }
    const existing = await this.#statOrAbsent(path);
    /* The conflict is checked before the empty resource is created, so a
       refused LOCK on an unmapped URL leaves the namespace as it found it. The
       authoritative check is still the one inside `create` — it is the one with
       no `await` between the test and the grant. */
    const blocking = this.locks.conflict(path, depth as LockDepth, info.exclusive, now);
    if (blocking !== undefined) {
      throw this.#conflictingLock(blocking);
    }
    const collection = existing?.isDirectory() ?? false;
    if (existing === undefined) {
      /* §9.10.6's `409`: "a resource cannot be created at the destination until
         one or more intermediate collections have been created. The server MUST
         NOT create those intermediate collections automatically." */
      await this.#requireCollection(dirname(path));
      /* The empty resource §7.3 creates is a new internal member of its parent,
         so a lock on that collection has to be submitted for it (§7.4). The
         lock being *taken* is judged by the compatibility table alone
         (§9.10.5), which the conflict check above is. */
      this.#requireWritable(path, guard, { membership: true });
      await (await this.driver.open(path, "w", 0o666)).close();
    }
    const grant = this.locks.create(
      {
        path,
        collection,
        depth: depth as LockDepth,
        exclusive: info.exclusive,
        owner: info.owner,
        timeoutSeconds: timeout,
      },
      now,
    );
    if (grant.kind === "conflict") {
      /* Lost a race with another request between the check above and here. The
         empty resource a `201` would have created stays, which is §7.3's own
         rule that it "SHOULD NOT disappear when its lock goes away". */
      throw this.#conflictingLock(grant.lock);
    }
    if (grant.kind === "full") {
      throw refuse(503, { message: "this share is holding as many locks as it will hold" });
    }
    return xmlBody(existing === undefined ? 201 : 200, encodeLockResponse(grant.lock, now), {
      "lock-token": formatLockToken(grant.lock.token),
    });
  }

  /**
   * Restart a lock's lease (RFC 4918 §9.10.2).
   *
   * The request names the lock in its `If` header and nowhere else — "this
   * request MUST NOT have a body and it MUST specify which lock to refresh by
   * using the 'If' header with a single lock token" — so a refresh with no `If`
   * is a `400`, and one whose token names no lock **whose scope covers this
   * URL** is the `412 lock-token-matches-request-uri` §9.10.6 defines for
   * exactly that ("the Request-URI did not fall within the scope of the lock
   * identified by the token ... or the lock could have disappeared, or the
   * token may be invalid" — one status for all three, because the client's next
   * move is the same).
   *
   * `Depth` is ignored, which §9.10.2 requires. There is no `Lock-Token`
   * response header: §9.10.2 says it "is not returned in the response for a
   * successful refresh", since no token was created.
   */
  async #refreshLock(
    path: string,
    timeout: number | "infinite" | undefined,
    guard: Guard,
  ): Promise<WebdavResponse> {
    const now = guard.now;
    if (guard.lists === undefined) {
      throw refuse(400, { message: "a LOCK with no body refreshes a lock and needs an If header" });
    }
    /* The first submitted token that names a live lock covering this URL. More
       than one is a request §9.10.2 does not define ("only one lock may be
       refreshed at a time"); refreshing the first is the reading that does
       something rather than nothing, and a client that meant the other one gets
       a `timeout` element saying which lock it actually refreshed. */
    for (const token of guard.submitted) {
      const lock = this.locks.find(token, now);
      if (lock !== undefined && DavLockTable.inScope(lock, path)) {
        /* The header named a lock that is really here; now it has to be true as
           a precondition as well (§10.4.1's two purposes, in the order that
           gives each refusal its own reason). */
        await this.#requireIf(guard, path);
        const refreshed = this.locks.refresh(token, timeout, now);
        /* v8 ignore next 3 -- `find` just answered for this token and nothing
           awaits in between, so `refresh` cannot miss it. */
        if (refreshed === undefined) {
          break;
        }
        return xmlBody(200, encodeLockResponse(refreshed, now));
      }
    }
    throw refuse(412, { condition: "lock-token-matches-request-uri" });
  }

  /**
   * Delete a lock (RFC 4918 §9.11).
   *
   * The token comes from the `Lock-Token` header rather than from `If`, which
   * §9.11 notes is inconsistent with every other state-changing method and is
   * the protocol's own choice. `204` on success — "rather than 200 OK, since
   * 200 OK would imply a response body" — `400` when no token was provided, and
   * `409 lock-token-matches-request-uri` when the token names no live lock or
   * names one whose scope does not cover this URL.
   *
   * Unlocking is not itself lock-protected: a client holding the token *is* the
   * proof, and requiring the same token twice — once in `Lock-Token` and once
   * in `If` — is not something §9.11 asks for.
   */
  #unlock(head: WebdavRequestHead, path: string): WebdavResponse {
    const token = parseLockToken(head.headers["lock-token"]);
    if (token === undefined) {
      throw refuse(400, { message: "UNLOCK needs a Lock-Token header holding a Coded-URL" });
    }
    const now = this.#now();
    const lock = this.locks.find(token, now);
    if (lock === undefined || !DavLockTable.inScope(lock, path)) {
      throw refuse(409, { condition: "lock-token-matches-request-uri" });
    }
    this.locks.remove(token);
    return { status: 204, headers: { "content-length": "0" } };
  }

  /** The `423` a conflicting lock earns, naming the lock that is in the way. */
  #conflictingLock(lock: DavLock): DavFault {
    /* §16 on `no-conflicting-lock`: "a lock can be in conflict although the
       resource to which the request was directed is only indirectly locked. In
       this case, the precondition code can be used to inform the client about
       the resource that is the root of the conflicting lock, avoiding a
       separate lookup of the lockdiscovery property." */
    return refuse(423, {
      condition: "no-conflicting-lock",
      hrefs: [hrefOf(lock.path, lock.collection)],
      message: `${lock.path} is already locked`,
    });
  }

  /**
   * The `If` header's lists, or `undefined` when there is no header.
   *
   * @throws {DavFault} `400` for a header that is not §10.4.2's grammar.
   */
  #ifLists(head: WebdavRequestHead): IfList[] | undefined {
    const header = head.headers["if"];
    if (header === undefined) {
      return undefined;
    }
    const lists = parseIf(header, head.headers["host"]);
    if (lists === undefined) {
      throw refuse(400, { message: "the If header is not RFC 4918 §10.4.2's grammar" });
    }
    return lists;
  }

  /**
   * Delete every lock under `path` whose root stopped existing (§6.1 point 8).
   *
   * "If a request causes the lock-root of any lock to become an unmapped URL,
   * then the lock MUST also be deleted by that request" — so a `DELETE` and the
   * source side of a `MOVE` destroy the locks they unmap, and a lock never
   * follows its resource (§7.6).
   *
   * The roots are **checked rather than assumed**, with one `stat` per lock
   * under the path and none at all in the overwhelmingly common case of no
   * locks there. That is what makes the same helper right at both ends of a
   * `MOVE`: at the source every root really has gone, while at an overwritten
   * destination the root itself was remapped by this very request — §7.6's "if
   * there is an existing lock at the destination, the server MUST add the moved
   * resource to the destination lock scope" — and only the members that were
   * not recreated are unmapped.
   */
  async #discardUnmapped(path: string, now: number): Promise<void> {
    for (const lock of this.locks.within(path, now)) {
      if ((await this.#statOrAbsent(lock.path)) === undefined) {
        this.locks.remove(lock.token);
      }
    }
  }

  // -------------------------------------------------------------------------
  // shared driver calls
  // -------------------------------------------------------------------------

  /**
   * `stat`, with "nothing there" as a `404`.
   *
   * `stat` rather than `lstat` throughout: WebDAV has no symbolic link, so a
   * link is the resource it points at — the same choice `mountx/s3` makes, and
   * the reason a dangling one is a `404` rather than a resource with no body.
   */
  async #stat(path: string): Promise<StatsLike> {
    try {
      return await this.driver.stat(path);
    } catch (error) {
      throw isAbsent(error) ? refuse(404) : error;
    }
  }

  /**
   * `lstat`, with `stat` as the fallback and "nothing there" as a `404`.
   *
   * `lstat` is optional on `FsDriver`, so a driver without one answers `ENOSYS`
   * through the loopback and gets the following `stat` instead — which is
   * exactly right, because a driver with no `lstat` has no symbolic links for
   * the distinction to matter to.
   */
  async #linkStat(path: string): Promise<StatsLike> {
    try {
      return await this.driver.lstat(path);
    } catch (error) {
      if (errorCode(error) !== "ENOSYS") {
        throw isAbsent(error) ? refuse(404) : error;
      }
    }
    return await this.#stat(path);
  }

  /** `stat`, with "nothing there" as `undefined`. */
  async #statOrAbsent(path: string): Promise<StatsLike | undefined> {
    try {
      return await this.driver.stat(path);
    } catch (error) {
      if (isAbsent(error)) {
        return undefined;
      }
      throw error;
    }
  }

  /**
   * The parent a write needs: it must exist and it must be a collection.
   *
   * `409 Conflict` for both, which is §9.7.1's answer and the one place a
   * WebDAV server most visibly differs from a plain HTTP one — this server does
   * **not** create intermediate collections the way `mountx/s3` conjures a
   * prefix, because in WebDAV the client is the one that says `MKCOL`.
   */
  async #requireCollection(path: string): Promise<void> {
    const stats = await this.#statOrAbsent(path);
    if (stats === undefined || !stats.isDirectory()) {
      throw refuse(409, { message: `${path} is not a collection` });
    }
  }

  /** A `207` naming each resource a recursive operation could not deal with. */
  #multistatus(failures: readonly Failure[]): WebdavResponse {
    return xmlBody(
      207,
      encodeMultistatus(
        failures.map((failure) => ({
          href: hrefOf(failure.path, failure.collection),
          status: failure.status,
        })),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** An error's POSIX `code`, if it has one. */
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

/**
 * The `user:password` inside a `Basic` credential, or `undefined` for anything
 * that is not one.
 *
 * The base64 is decoded strictly — node accepts sloppy base64 and would turn a
 * malformed header into a wrong-but-plausible string — and the result is
 * compared whole, so a password containing a colon works and a username
 * containing one cannot exist, which is RFC 7617 §2's own rule.
 */
function parseBasic(header: string): string | undefined {
  const match = /^Basic +([A-Za-z0-9+/]+={0,2})$/.exec(header.trim());
  if (match === null) {
    return undefined;
  }
  const decoded = Buffer.from(match[1] as string, "base64");
  if (decoded.toString("base64").replace(/=+$/, "") !== (match[1] as string).replace(/=+$/, "")) {
    return undefined;
  }
  const text = decoded.toString("utf8");
  return text.includes(":") ? text : undefined;
}

/**
 * Are these two strings equal, without telling a timer how far they matched?
 *
 * Both are hashed first so the comparison is over two 32-byte buffers whatever
 * the inputs were: `timingSafeEqual` throws on a length mismatch, and comparing
 * the strings directly would leak the credential's length through that throw.
 */
function digestEquals(supplied: string, expected: string): boolean {
  const left = createHash("sha256").update(supplied, "utf8").digest();
  const right = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(left, right);
}

/**
 * Read `length` bytes from `start`, a bounded chunk at a time, and close the
 * handle when the consumer is done with it — including the consumer that walks
 * away mid-download, whose `return()` runs this `finally`.
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
