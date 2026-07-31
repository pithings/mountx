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
 * ## What "minimal" means here, exactly
 *
 * **Class 1 of RFC 4918, complete; class 2 absent.** `OPTIONS`, `HEAD`, `GET`,
 * `PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`, `PROPFIND` and `PROPPATCH` are
 * implemented against the driver. `LOCK` and `UNLOCK` are not, the `DAV` header
 * says `1, 3` rather than `1, 2, 3`, and the two methods answer `405` with an
 * `Allow` listing what is really there — declared-or-inferred, never faked
 * (`AGENTS.md`, invariant 5).
 *
 * That is a decision with a visible cost, so it is written down rather than
 * discovered: **macOS's `mount_webdav` mounts a class-1 share read-only**, and
 * the Windows redirector is unhappy in its own ways. A client that speaks the
 * protocol rather than the mount — `rclone`, `curl`, `cadaver`, a browser, most
 * Linux clients under `davfs2` — reads and writes normally. Locking is the next
 * piece of work, not an oversight; see `.agents/roadmap.md`.
 *
 * The other deliberate gaps, each because the driver interface has no answer
 * for them rather than because they were forgotten:
 *
 * - **No dead properties.** A driver stores bytes and inode metadata; there is
 *   nowhere to keep an arbitrary XML property without inventing a sidecar file
 *   that would then show up in every listing. `PROPPATCH` therefore answers
 *   `403 cannot-modify-protected-property` for everything, which is the
 *   truthful answer for a server whose properties are all live and all derived.
 * - **No conditional requests.** `If`, `If-Match`, `If-None-Match` and the two
 *   date forms are ignored rather than half-honoured. `mountx/s3` implements
 *   RFC 9110's four; doing the same here without `LOCK` would leave `If` — the
 *   one WebDAV adds, and the one that exists to carry lock tokens — as the
 *   conspicuous hole. They arrive together.
 * - **`GET` of a collection is `405`.** A collection has no body in RFC 4918;
 *   the HTML index other servers answer with is a user interface, and
 *   `PROPFIND` is the protocol's own way to list one.
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
 * All live, all derived from one `stat`, and none of them stored:
 * `creationdate`, `displayname`, `getcontentlength`, `getcontenttype`,
 * `getetag`, `getlastmodified`, `resourcetype`, `supportedlock` (empty — see
 * above) and `lockdiscovery` (empty, and always will be). RFC 4331's
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
import { formatETag, formatHttpDate, formatIsoDate, parseRange } from "../http.ts";
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
import {
  collectBody,
  encodeMultistatus,
  faultResponse,
  hrefOf,
  NO_BODY,
  parseDepth,
  parseDestination,
  parseOverwrite,
  parsePropfind,
  parseProppatch,
  parseTargetPath,
  refuse,
  statusOfError,
  xmlBody,
  type Depth,
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
  readonly #debug: boolean;
  /** Requests not answered yet, by internal ticket — see `S3Session`'s. */
  readonly #inflight = new Set<number>();
  #nextTicket = 1;

  constructor(driver: FsDriver, options: WebdavSessionOptions = {}) {
    this.driver = createLoopback(driver);
    this.options = options;
    this.#readChunkBytes = options.readChunkBytes ?? READ_CHUNK_BYTES;
    this.#maxXmlBytes = options.maxXmlBytes ?? MAX_XML_BYTES;
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
    switch (method) {
      case "GET":
      case "HEAD": {
        return await this.#get(head, path);
      }
      case "PUT": {
        return await this.#put(head, path, body);
      }
      case "DELETE": {
        return await this.#delete(head, path);
      }
      case "MKCOL": {
        return await this.#mkcol(path, body);
      }
      case "COPY":
      case "MOVE": {
        return await this.#copyOrMove(head, path, method === "MOVE");
      }
      case "PROPFIND": {
        return await this.#propfind(head, path, body);
      }
      case "PROPPATCH": {
        return await this.#proppatch(path, body);
      }
      default: {
        /* Everything else, `LOCK` and `UNLOCK` included: the `Allow` header is
           the honest list, and a client reading it learns this is a class-1
           server without having to parse the `DAV` header. */
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
  async #delete(head: WebdavRequestHead, path: string): Promise<WebdavResponse> {
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
    if (!stats.isDirectory()) {
      await this.driver.unlink(path);
      return { status: 204, headers: { "content-length": "0" } };
    }
    const failures = await this.#deleteTree(path);
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
  async #mkcol(path: string, body: AsyncIterable<Uint8Array>): Promise<WebdavResponse> {
    const content = await collectBody(body, this.#maxXmlBytes);
    if (content.byteLength > 0) {
      throw refuse(415, { message: "this server defines no MKCOL request body" });
    }
    if (path === "/" || (await this.#statOrAbsent(path)) !== undefined) {
      throw refuse(405, { headers: { allow: ALLOW_HEADER } });
    }
    await this.#requireCollection(dirname(path));
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
  async #copyOrMove(head: WebdavRequestHead, path: string, move: boolean): Promise<WebdavResponse> {
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
      return { status: existing === undefined ? 201 : 204, headers: { "content-length": "0" } };
    }
    const failures = await this.#copyTree(path, destination, stats, depth === "infinity");
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
    const entries: MultistatusEntry[] = [
      {
        href: hrefOf(path, stats.isDirectory()),
        propstat: await this.#propstats(path, stats, request),
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
          propstat: await this.#propstats(child, childStats, request),
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
  ): Promise<Propstat[]> {
    const explicit = request.kind === "prop";
    const names = explicit ? request.names : [...ALLPROP_NAMES];
    const found: XmlNode[] = [];
    const missing: XmlNode[] = [];
    for (const name of names) {
      const node = await this.#property(name, path, stats);
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
  async #property(name: string, path: string, stats: StatsLike): Promise<XmlNode | undefined> {
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
      case "supportedlock":
      case "lockdiscovery": {
        /* Both empty, and both truthful: no lock type is supported and no lock
           is ever held. Sending them at all is what tells a client it need not
           ask. */
        return { name };
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
  async #proppatch(path: string, body: AsyncIterable<Uint8Array>): Promise<WebdavResponse> {
    const request = parseProppatch(await collectBody(body, this.#maxXmlBytes));
    const stats = await this.#stat(path);
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
