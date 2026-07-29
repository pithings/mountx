/**
 * The S3 gateway's socket: `node:http`, and the only file in this package that
 * imports it.
 *
 * Everything below — SigV4, the XML documents, the `aws-chunked` decoder, the
 * router, the session — is a request in and a reply out, which is why all of it
 * is testable with no listener and no client. This file is where HTTP finally
 * happens: request line and headers in, status and headers out, and a body that
 * may be a stream in either direction.
 *
 * ```ts
 * import { createS3Server } from "mountx/s3";
 * import { createMemoryDriver } from "mountx/drivers/memory";
 *
 * await using server = await createS3Server(createMemoryDriver()).listen();
 * // aws --endpoint-url $url s3 ls s3://mountx
 * ```
 *
 * ## Two call shapes, one discriminant
 *
 * `createS3Server(driver)` serves one bucket; `createS3Server({ buckets: { … } })`
 * serves several. They are told apart by the three methods an `FsDriver` is
 * *required* to have — `stat`, `readdir`, `open` (`src/types.ts`) — and not by
 * the presence of a `buckets` key, which a driver could in principle carry. A
 * value with those three is a driver; a value with a `buckets` object is a map;
 * anything else is a `TypeError` at construction rather than a `NoSuchBucket`
 * at the first request.
 *
 * ## Who may connect
 *
 * The gateway's authentication is SigV4, and SigV4 is only authentication when
 * there is a secret to verify against. So:
 *
 * - **No `credentials`** — every request is served unverified, and the bind is
 *   **loopback-only**. A non-loopback `host` is refused by
 *   {@link createS3Server} itself, before a socket exists, with an
 *   {@link S3BindError}. That includes the unspecified addresses `0.0.0.0` and
 *   `::`, which are the dangerous ones: they bind *every* interface, so a
 *   gateway that meant "just me" would be exporting the driver to the network.
 * - **With `credentials`** — every request is verified, and any `host` is
 *   allowed. The refusal is about the missing secret, not about the address.
 *
 * The rule is deliberately a **literal** one: `localhost`, `::1`, and any
 * `127.x.y.z` (plus their `::ffff:` IPv4-mapped spellings). Nothing here
 * resolves a name — a lookup would make a configuration check depend on DNS and
 * on the moment it ran — so a hostname that happens to point at 127.0.0.1 is
 * still refused, and `localhost` is accepted on the convention rather than on a
 * resolver's word. An operator who has repointed `localhost` in `/etc/hosts`
 * has moved the boundary themselves.
 *
 * ## Bodies
 *
 * Requests stream in: `IncomingMessage` *is* an `AsyncIterable<Buffer>`, so it
 * is handed to the session as it stands. The zero-copy contract is the
 * session's and it holds here (`session.ts`, "Copy-what-you-keep"): a body it
 * buffers is copied chunk by chunk on the way in, and a body it writes is
 * awaited into the driver before the iterator advances, so nothing outlives the
 * buffer it arrived in.
 *
 * Replies stream out with backpressure — `write()` returning `false` is waited
 * on — and a client that walks away mid-download ends the iteration and calls
 * the body's `return()`, which is what closes the file handle the `GET`
 * generator opened. A body that does not match the `Content-Length` above it
 * takes the connection with it rather than leaving a message HTTP cannot
 * terminate; see `#outOfFrame`.
 *
 * ## `Expect: 100-continue`
 *
 * Left to `node:http`, which answers `100 Continue` automatically when no
 * `checkContinue` listener is registered. Registering one that always continues
 * would be the same behaviour written out; refusing a body before reading it is
 * something this gateway cannot do anyway, since whether a `PUT` is acceptable
 * is not known until its key has been routed.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { Socket } from "node:net";
import type { FsDriver } from "../types.ts";
import {
  isValidBucketName,
  parseUnsignedInteger,
  s3Error,
  s3ErrorResponse,
  type S3StreamResponse,
} from "./protocol.ts";
import { S3Session, type S3RequestHead, type S3SessionOptions } from "./session.ts";
import type { HeaderEntry } from "./sigv4.ts";

/**
 * The bucket a single-driver server serves when `bucket` is not given.
 *
 * Named after the package because the name is part of every URL a client will
 * write down, and a bucket called `default` says nothing about whose it is.
 */
export const DEFAULT_BUCKET = "mountx";

/** The address a gateway binds when `host` is not given. */
export const DEFAULT_HOST = "127.0.0.1";

/**
 * How long {@link S3Server.close} lets in-flight responses finish, in
 * milliseconds. Five seconds.
 *
 * A deadline rather than a wait: a client streaming a 5 GiB `GET` over a slow
 * link would otherwise hold the process open for as long as it liked, and a
 * `close()` that never returns is worse than a download that ends early.
 */
export const DEFAULT_DRAIN_TIMEOUT = 5000;

/**
 * How often `close()` sweeps connections that have gone idle, in milliseconds.
 *
 * The backstop rather than the mechanism: a reply finishing already triggers a
 * sweep (`#respond`), and this is what catches a connection that became idle
 * for a reason nothing else reported.
 */
const IDLE_SWEEP_MS = 25;

// ---------------------------------------------------------------------------
// the bind refusal
// ---------------------------------------------------------------------------

/**
 * A bind this gateway will not perform.
 *
 * The **only** error type {@link createS3Server} throws for an address, which
 * is what makes it catchable by name: `code` is stable, the class is exported,
 * and {@link isS3BindError} is the guard. Same shape as `XmlError` and
 * `ChunkedError` below it.
 */
export class S3BindError extends Error {
  readonly code = "ERR_S3_BIND";
  /** The host that was refused, exactly as it was passed. */
  readonly host: string;

  constructor(host: string, message: string) {
    super(message);
    this.name = "S3BindError";
    this.host = host;
  }
}

/** Is this an {@link S3BindError}? */
export function isS3BindError(error: unknown): error is S3BindError {
  return error instanceof S3BindError;
}

/**
 * Is this address literally a loopback address?
 *
 * Literally: no lookup, no resolver, no `/etc/hosts`. `localhost` is accepted
 * on the convention, `::1` and every `127.x.y.z` on the address, and the
 * `::ffff:` IPv4-mapped spelling of the latter because that is how a dual-stack
 * listener writes it. Everything else — including the empty string, `0.0.0.0`
 * and `::`, which bind every interface — is not.
 */
export function isLoopbackHost(host: string): boolean {
  const lower = host.toLowerCase();
  // Brackets come as a pair or not at all: `[::1]` is a spelling, `::1]` is a
  // typo, and a typo must not be read as the address it nearly is.
  const bare = /^\[(.*)]$/.exec(lower)?.[1] ?? lower;
  if (bare === "localhost" || bare === "::1") {
    return true;
  }
  if (bare.startsWith("::ffff:")) {
    return isLoopbackHost(bare.slice(7));
  }
  const octets = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(bare);
  return octets !== null && octets.slice(1).every((octet) => Number(octet) <= 255);
}

/**
 * Why this host may not be bound without credentials, or `undefined` if it may.
 *
 * Pure, and separate from the throw, the way `elevationRefusal()` and
 * `ownershipRefusal()` are in the two mount transports: the sentence a user
 * reads is a fact about the configuration and is worth testing on its own.
 */
export function loopbackRefusal(host: string, credentials: boolean): string | undefined {
  if (credentials || isLoopbackHost(host)) {
    return undefined;
  }
  const unspecified = host === "" || host === "0.0.0.0" || host === "::" || host === "[::]";
  return (
    `mountx: refusing to bind an S3 gateway to ${host === "" ? "every interface" : host} ` +
    `with no credentials configured. ` +
    (unspecified
      ? `That address binds every interface, so the driver would be readable and writable ` +
        `by anything that can reach this machine. `
      : `That address is reachable from outside this machine, and an unauthenticated ` +
        `gateway would serve the driver to whatever finds it. `) +
    `Pass \`credentials: { accessKeyId, secretAccessKey }\` to bind it, or leave \`host\` ` +
    `at ${DEFAULT_HOST}.`
  );
}

// ---------------------------------------------------------------------------
// options and the server
// ---------------------------------------------------------------------------

/** The several-bucket call shape: `createS3Server({ buckets: { name: driver } })`. */
export interface S3BucketMap {
  /** Bucket name to driver. Path-style URLs only, so the name is a path segment. */
  buckets: Record<string, FsDriver>;
}

/** What {@link createS3Server} accepts: one driver, or a map of them. */
export type S3Source = FsDriver | S3BucketMap;

export interface S3ServerOptions extends S3SessionOptions {
  /**
   * The bucket name for the **single-driver** call shape. Default
   * {@link DEFAULT_BUCKET}. Ignored — and meaningless — when a bucket map is
   * passed, which names its own.
   */
  bucket?: string;
  /** Address to bind. Default {@link DEFAULT_HOST}. See the module docs on what
   * a non-loopback one requires. */
  host?: string;
  /**
   * Port to listen on. Default `0` — an ephemeral port, which {@link
   * S3Server.port} then reports.
   *
   * Not 9000, not 4566, not any of the ports an S3-compatible server is
   * conventionally found on: a library that squats a well-known port by default
   * fails in the least useful way possible, at `listen()`, on the machine that
   * already runs the real thing. Ask for one when you want one.
   */
  port?: number;
  /** How long {@link S3Server.close} waits for in-flight responses, in
   * milliseconds. Default {@link DEFAULT_DRAIN_TIMEOUT}. */
  drainTimeout?: number;
  /** Called for transport-level failures: a socket error, a reply that could
   * not be written. */
  onTransportError?: (error: unknown, peer: string | undefined) => void;
}

/** A running (or runnable) S3 gateway. */
export interface S3Server extends AsyncDisposable {
  /** The session answering for it — its `stats` and its bucket table. */
  readonly session: S3Session;
  /** The address it is bound to. */
  readonly host: string;
  /** The port it is listening on, or the requested one before {@link
   * S3Server.listen} (`0` for an ephemeral port). */
  readonly port: number;
  /** The endpoint URL, with an IPv6 host bracketed. Meaningful once {@link
   * S3Server.listen} has resolved. */
  readonly url: string;
  /** The bucket names it serves, in listing order. */
  readonly buckets: string[];
  /** Open connections. */
  readonly connections: number;
  /** Start listening. Resolves once the port is bound. Idempotent. */
  listen(): Promise<S3Server>;
  /**
   * Stop accepting, let in-flight responses finish (bounded by
   * `drainTimeout`), drop every connection, then sweep the multipart staging
   * area. Idempotent.
   */
  close(): Promise<void>;
}

class S3ServerImpl implements S3Server {
  readonly session: S3Session;
  readonly host: string;

  readonly #options: S3ServerOptions;
  readonly #server: Server;
  readonly #drainTimeout: number;
  /** Every open connection. */
  readonly #sockets = new Set<Socket>();
  /**
   * Connections with a reply still on them, by how many.
   *
   * The count rather than a flag because HTTP/1.1 allows pipelining: two
   * requests can be outstanding on one socket, and a socket is only idle when
   * the last of them has been answered.
   */
  readonly #busy = new Map<Socket, number>();
  #draining = false;
  #port: number;
  #listening: Promise<S3Server> | undefined;
  #closed: Promise<void> | undefined;

  constructor(buckets: Record<string, FsDriver>, options: S3ServerOptions) {
    this.#options = options;
    this.session = new S3Session(buckets, options);
    this.host = options.host ?? DEFAULT_HOST;
    this.#port = options.port ?? 0;
    this.#drainTimeout = options.drainTimeout ?? DEFAULT_DRAIN_TIMEOUT;
    this.#server = createServer((request, response) => {
      void this.#respond(request, response);
    });
    this.#server.on("error", (error) => this.#report(error, undefined));
    this.#server.on("connection", (socket) => {
      this.#sockets.add(socket);
      socket.on("close", () => {
        this.#sockets.delete(socket);
        this.#busy.delete(socket);
      });
      if (this.#draining) {
        // Arrived after `close()` began; it will never be answered.
        socket.destroy();
      }
    });
  }

  get port(): number {
    return this.#port;
  }

  get url(): string {
    return `http://${this.host.includes(":") ? `[${this.host}]` : this.host}:${this.#port}`;
  }

  get buckets(): string[] {
    return this.session.bucketNames;
  }

  get connections(): number {
    return this.#sockets.size;
  }

  listen(): Promise<S3Server> {
    this.#listening ??= new Promise<S3Server>((resolve, reject) => {
      const onError = (error: unknown): void => reject(error as Error);
      this.#server.once("error", onError);
      this.#server.listen({ port: this.#port, host: this.host }, () => {
        this.#server.off("error", onError);
        const address = this.#server.address();
        /* v8 ignore next 3 -- a listening TCP server always reports an object;
           the narrowing is what `address()`'s union requires. */
        if (address !== null && typeof address === "object") {
          this.#port = address.port;
        }
        resolve(this);
      });
    });
    return this.#listening;
  }

  close(): Promise<void> {
    this.#closed ??= this.#close();
    return this.#closed;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  /**
   * Shut down in the order that makes each step mean something: stop accepting,
   * let what is in flight finish, drop what is left, then sweep staging.
   *
   * The sweep goes **last** because it is the only step that touches a driver,
   * and an `UploadPart` still writing while it ran would leave exactly the
   * debris it is there to remove.
   */
  async #close(): Promise<void> {
    if (this.#listening !== undefined) {
      await this.#drain();
    }
    await this.session.close();
  }

  /**
   * Stop accepting, drop every connection that is not answering something, and
   * wait for the ones that are — up to `drainTimeout`.
   *
   * `server.close()` on its own resolves only when the **last** connection is
   * gone, and a keep-alive client's connection outlives any wait worth making,
   * so the idle ones have to be dropped explicitly. That is what
   * `closeIdleConnections()` is for, and it is not enough: a connection that
   * has been accepted but has not sent a request yet — the one an HTTP agent
   * opens to replace a socket it just dropped — is not "idle" to it, and
   * `close()` then waits out the whole deadline for a client that was never
   * going to say anything. So idleness is tracked here instead, per socket and
   * by whether a reply is still owed on it, which is a question this file
   * already knows the answer to. `closeAllConnections()` is still node's, at
   * the deadline, where "everything, now" is exactly the semantics wanted.
   */
  #drain(): Promise<void> {
    return new Promise<void>((resolve) => {
      let settled = false;
      const done = (): void => {
        if (settled) {
          return;
        }
        settled = true;
        clearInterval(sweep);
        clearTimeout(deadline);
        resolve();
      };
      this.#draining = true;
      this.#server.close(() => done());
      /* Now, again as each reply finishes (`#respond`), and on a timer as the
         backstop for anything neither of those two saw. */
      this.#dropIdle();
      const sweep = setInterval(() => this.#dropIdle(), IDLE_SWEEP_MS);
      const deadline = setTimeout(() => {
        /* Out of patience: whatever is still streaming is cut. The sockets are
           destroyed synchronously here, so there is nothing left to wait for. */
        this.#server.closeAllConnections();
        done();
      }, this.#drainTimeout);
      sweep.unref();
      deadline.unref();
    });
  }

  /** Destroy every connection with no reply outstanding on it. */
  #dropIdle(): void {
    for (const socket of this.#sockets) {
      if (!this.#busy.has(socket)) {
        socket.destroy();
      }
    }
  }

  #report(error: unknown, peer: string | undefined): void {
    this.#options.onTransportError?.(error, peer);
  }

  async #respond(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const socket = request.socket;
    const peer = socket.remoteAddress;
    /* A client that vanishes mid-request makes both of these emit rather than
       throw, and an unhandled `error` event on either would take the process
       with it. */
    request.on("error", (error: unknown) => this.#report(error, peer));
    response.on("error", (error: unknown) => this.#report(error, peer));
    /* This socket owes a reply from here until the response is finished *or*
       the connection dies, which is what `close` covers and `finish` does not
       (see `#drain`). */
    this.#busy.set(socket, (this.#busy.get(socket) ?? 0) + 1);
    response.on("close", () => {
      const left = (this.#busy.get(socket) ?? 1) - 1;
      if (left > 0) {
        this.#busy.set(socket, left);
      } else {
        this.#busy.delete(socket);
        if (this.#draining) {
          this.#dropIdle();
        }
      }
    });
    const head = {
      method: (request.method ?? "GET").toUpperCase(),
      target: request.url ?? "/",
      headers: headerEntries(request.rawHeaders),
    };
    let reply: S3StreamResponse;
    try {
      reply = await this.session.handleRequest(head, request);
    } catch (error) {
      /* v8 ignore start -- `handleRequest` is documented never to reject, and
         asserts it of itself. This is the same guard `src/nfs/server.ts` keeps
         for `handleCall`: a broken invariant becomes one bad reply rather than
         a dead process. (`ignore start`/`stop` rather than `ignore next N`,
         which counts its lines from the comment and so covers one statement
         fewer than it reads as.) */
      this.#report(error, peer);
      reply = s3ErrorResponse(s3Error("InternalError"));
      /* v8 ignore stop */
    }
    await this.#write(response, reply, head, peer);
  }

  /**
   * A body that did not match the `Content-Length` above it kills the
   * connection. Answers whether it did.
   *
   * **The one failure a reply cannot survive quietly.** `ServerResponse` does
   * not check this itself (`strictContentLength` is off by default), so a body
   * that ends short leaves a message HTTP cannot terminate: a client with no
   * pipelining waits for the missing bytes forever — and waits *unwatched*,
   * because the socket goes idle here the moment the reply is "finished", so
   * `close()`'s deadline never applies to it — and a keep-alive client reads
   * the **next** reply as the tail of this one. Both are worse than a broken
   * connection, which is at least an answer, and `destroy()` is the same
   * posture as the catch below.
   *
   * It is reachable without a bug in this package: `streamHandle` ends the body
   * on a short read (`session.ts`), which is what a file truncated by another
   * process between the `stat` that set the length and the reads that fill it
   * looks like — a TOCTOU the passthrough driver is exposed to by definition.
   */
  #outOfFrame(
    response: ServerResponse,
    head: S3RequestHead,
    declared: number | undefined,
    written: number,
    peer: string | undefined,
  ): boolean {
    if (declared === undefined || written === declared) {
      return false;
    }
    this.#report(
      new Error(
        `mountx: the reply to ${head.method} ${head.target} declared ${declared} bytes and ` +
          `produced ${written}. The connection was closed rather than left out of frame — the ` +
          `object changed size under the request.`,
      ),
      peer,
    );
    response.destroy();
    return true;
  }

  /** Write one reply, streaming its body if that is what it is. */
  async #write(
    response: ServerResponse,
    reply: S3StreamResponse,
    head: S3RequestHead,
    peer: string | undefined,
  ): Promise<void> {
    const body = reply.body;
    if (response.destroyed || response.writableEnded) {
      // The client is already gone. Close the body so its handle goes with it.
      await closeBody(body);
      return;
    }
    response.statusCode = reply.status;
    for (const [name, value] of Object.entries(reply.headers)) {
      response.setHeader(name, value);
    }
    const declared = declaredLength(reply.headers);
    if (body === undefined) {
      /* No body to count. A `HEAD` gets here with a `Content-Length` it is
         required to state and required not to fill (RFC 9110 §9.3.2), and node
         knows not to frame it as a body. */
      response.end();
      return;
    }
    if (body instanceof Uint8Array) {
      if (this.#outOfFrame(response, head, declared, body.byteLength, peer)) {
        return;
      }
      response.end(Buffer.from(body.buffer, body.byteOffset, body.byteLength));
      return;
    }
    const iterator = body[Symbol.asyncIterator]();
    let written = 0;
    try {
      for (;;) {
        const step = await iterator.next();
        if (step.done === true) {
          break;
        }
        /* Checked *after* the read rather than before the write, because a read
           is where the abort usually lands: one chunk is the most this can
           fetch for a client that is no longer there. */
        if (response.destroyed || response.writableEnded) {
          return;
        }
        written += step.value.byteLength;
        if (!response.write(step.value) && !(await drained(response))) {
          return;
        }
        if (declared !== undefined && written > declared) {
          // Already past the length promised; reading more only makes it worse.
          break;
        }
      }
      if (this.#outOfFrame(response, head, declared, written, peer)) {
        return;
      }
      response.end();
    } catch (error) {
      /* v8 ignore start -- the only body that streams is the `GET` generator,
         whose reads are already the session's to fail. If one ever does, the
         status line is long gone and the truthful answer is a broken
         connection rather than a second reply. */
      this.#report(error, peer);
      response.destroy();
      /* v8 ignore stop */
    } finally {
      /* The `GET` generator closes its file handle in a `finally`, which runs
         on `return()` — this is the call that releases the descriptor of an
         abandoned download. */
      await endIterator(iterator);
    }
  }
}

/** The `Content-Length` a reply states, if it states one. */
function declaredLength(headers: Record<string, string>): number | undefined {
  const value = headers["content-length"];
  return value === undefined ? undefined : parseUnsignedInteger(value);
}

/**
 * Wait for a `drain`, and answer whether writing may continue.
 *
 * `false` for a response that closed or errored while we waited, which is a
 * client that stopped listening: there is no drain coming, and a plain
 * `once(response, "drain")` would wait for it anyway.
 */
function drained(response: ServerResponse): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const settle = (value: boolean): void => {
      response.off("drain", onDrain);
      response.off("close", onGone);
      response.off("error", onGone);
      resolve(value);
    };
    const onDrain = (): void => settle(true);
    const onGone = (): void => settle(false);
    response.once("drain", onDrain);
    response.once("close", onGone);
    response.once("error", onGone);
  });
}

/**
 * End a body nobody is going to read, releasing whatever it holds.
 *
 * **Stepped once before it is closed**, and that is not a nicety: a generator
 * suspended at its *start* runs no `finally` on `return()` — its body never
 * began — so a `GET` reply that was built and then never written would close
 * nothing, and the file handle the session opened before building it would
 * leak. One `next()` puts the generator inside its `try`, and the `return()`
 * after it runs the `finally` that closes the handle. The cost is a single
 * bounded read of an object nobody will receive, once per abandoned request.
 */
async function closeBody(body: S3StreamResponse["body"]): Promise<void> {
  if (body === undefined || body instanceof Uint8Array) {
    return;
  }
  const iterator = body[Symbol.asyncIterator]();
  try {
    await iterator.next();
  } catch {
    // A body that fails on its first step has already unwound its own `finally`.
  }
  await endIterator(iterator);
}

/**
 * Close an iterator and swallow whatever that costs.
 *
 * A `return()` that fails has already done the part that mattered — the
 * generator's `finally` ran — and the reply it belongs to is either sent or
 * unsendable, so there is nowhere for the failure to go but a report the caller
 * did not ask for.
 */
async function endIterator(iterator: AsyncIterator<Uint8Array>): Promise<void> {
  try {
    await iterator.return?.();
  } catch {
    // Deliberately ignored; see above.
  }
}

/**
 * `rawHeaders` — wire order, repeats included, case as it arrived — into the
 * entries the session reads.
 *
 * `request.headers` would be wrong twice over: it lowercases names, which is
 * harmless, and it *combines or drops* repeats, which is not. SigV4 signs the
 * headers as they were sent.
 */
function headerEntries(raw: readonly string[]): HeaderEntry[] {
  const entries: HeaderEntry[] = [];
  for (let index = 0; index + 1 < raw.length; index += 2) {
    entries.push({ name: raw[index] as string, value: raw[index + 1] as string });
  }
  return entries;
}

// ---------------------------------------------------------------------------
// the entry point
// ---------------------------------------------------------------------------

/**
 * Is this the bucket-map call shape rather than a driver?
 *
 * The question is answered on the **driver** side: `stat`, `readdir` and `open`
 * are the three methods `FsDriver` requires, so a value carrying all three is a
 * driver whatever else it carries. Only then is `buckets` looked at, which is
 * why a driver that happens to have a `buckets` property still mounts as one.
 */
function isBucketMap(source: S3Source): source is S3BucketMap {
  if (isDriver(source)) {
    return false;
  }
  const candidate = source as Partial<S3BucketMap>;
  return typeof candidate.buckets === "object" && candidate.buckets !== null;
}

/** The three methods `FsDriver` requires, all present. See {@link isBucketMap}. */
function isDriver(source: S3Source): source is FsDriver {
  const candidate = source as Partial<FsDriver>;
  return (
    typeof candidate.stat === "function" &&
    typeof candidate.readdir === "function" &&
    typeof candidate.open === "function"
  );
}

/**
 * Serve one driver, or several, over the S3 API.
 *
 * ```ts
 * const one = createS3Server(driver, { bucket: "photos" });
 * const many = createS3Server({ buckets: { photos: driver, notes: other } });
 * ```
 *
 * Returns immediately; nothing is bound until {@link S3Server.listen}. What
 * *is* checked here is the configuration — the bind rule (see the module docs)
 * and the bucket names — because a refusal that waits for `listen()` is a
 * refusal that has already opened a socket, and an unroutable bucket name is a
 * server that answers `NoSuchBucket` to its own operator forever.
 *
 * @throws {S3BindError} for a non-loopback `host` with no `credentials`.
 * @throws {TypeError} for a value that is neither a driver nor a bucket map,
 * or for a bucket name that cannot be a URL path segment.
 */
export function createS3Server(source: S3Source, options: S3ServerOptions = {}): S3Server {
  let buckets: Record<string, FsDriver>;
  if (isBucketMap(source)) {
    buckets = { ...source.buckets };
  } else if (isDriver(source)) {
    buckets = { [options.bucket ?? DEFAULT_BUCKET]: source };
  } else {
    throw new TypeError(
      `mountx: createS3Server() takes an FsDriver (with \`stat\`, \`readdir\` and \`open\`) ` +
        `or \`{ buckets: { name: driver } }\`, and was given neither.`,
    );
  }
  for (const name of Object.keys(buckets)) {
    if (!isValidBucketName(name)) {
      throw new TypeError(
        `mountx: ${JSON.stringify(name)} cannot be a bucket name — a path-style S3 URL ` +
          `carries it as one path segment, so it cannot be empty, \`.\`, \`..\`, longer than ` +
          `255 characters, or contain a slash, a backslash or a control character.`,
      );
    }
  }
  const host = options.host ?? DEFAULT_HOST;
  const refusal = loopbackRefusal(host, options.credentials !== undefined);
  if (refusal !== undefined) {
    throw new S3BindError(host, refusal);
  }
  return new S3ServerImpl(buckets, options);
}
