/**
 * The WebDAV server's socket: `node:http`, and the only file in `src/webdav/`
 * that imports it.
 *
 * Everything below it — the documents, the header grammars, the session — is a
 * request in and a reply out, which is what makes the whole protocol testable
 * with no listener and no client. This file is where HTTP happens: request line
 * and headers in, status and headers out, and a body that may be a stream in
 * either direction.
 *
 * ```ts
 * import { createWebdavServer } from "mountx/webdav";
 * import { createMemoryDriver } from "mountx/drivers/memory";
 *
 * await using server = await createWebdavServer(createMemoryDriver()).listen();
 * // rclone ls :webdav: --webdav-url $url
 * ```
 *
 * ## Who may connect
 *
 * The same rule as the S3 gateway's, for the same reason and with the same
 * literal-address check (`src/s3/server.ts` sets out the reasoning in full):
 *
 * - **No `credentials`** — every request is served unauthenticated, and the
 *   bind is **loopback-only**. A non-loopback `host` is refused by
 *   {@link createWebdavServer} itself, before a socket exists, with a
 *   {@link WebdavBindError}. That includes `0.0.0.0` and `::`, which are the
 *   dangerous ones: they bind *every* interface.
 * - **With `credentials`** — every request is authenticated with HTTP Basic,
 *   and any `host` is allowed. Basic sends a recoverable password on every
 *   request, so anything but a trusted network wants TLS in front — this server
 *   speaks plain HTTP and does not pretend otherwise.
 *
 * ## Bodies
 *
 * Requests stream in: `IncomingMessage` *is* an `AsyncIterable<Buffer>`, so it
 * is handed to the session as it stands, and a body the session buffers is
 * copied chunk by chunk on the way in (`AGENTS.md`, invariant 12). A body the
 * session did **not** read — a `DELETE` that carried one, a request refused
 * before its body mattered — is drained here rather than left in the socket,
 * because an unread body and a keep-alive connection cannot both survive.
 *
 * Replies stream out with backpressure, and a client that walks away
 * mid-download ends the iteration and calls the body's `return()`, which is
 * what closes the file handle the `GET` generator opened. A body that does not
 * match its `Content-Length` takes the connection with it rather than leaving a
 * message HTTP cannot terminate — see `#outOfFrame`, which is
 * `src/s3/server.ts`'s and is here for the same reason: `ServerResponse` does
 * not check this itself, and a short body wedges the client or, worse, gets
 * read as the head of the next reply.
 *
 * ## Not one file with `src/s3/server.ts`
 *
 * The two are the same shape — track connections, drain on `close()`, write one
 * reply — and they are deliberately not shared yet: the bind refusal's wording,
 * the error reply a failed handler falls back to, and the authentication are
 * each transport's own, and unifying two implementations tends to produce a
 * parameterised third. If a fourth HTTP-shaped transport appears, this is the
 * duplication to remove first (`.agents/roadmap.md`).
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { Socket } from "node:net";
import type { FsDriver } from "../types.ts";
import { faultResponse, type WebdavResponse } from "./protocol.ts";
import { WebdavSession, type WebdavSessionOptions } from "./session.ts";

/** The address a server binds when `host` is not given. */
export const DEFAULT_HOST = "127.0.0.1";

/**
 * How long {@link WebdavServer.close} lets in-flight responses finish, in
 * milliseconds. Five seconds — a deadline rather than a wait, because a client
 * streaming a large `GET` over a slow link would otherwise hold the process
 * open for as long as it liked.
 */
export const DEFAULT_DRAIN_TIMEOUT = 5000;

/** How often `close()` sweeps connections that have gone idle, in milliseconds. */
const IDLE_SWEEP_MS = 25;

// ---------------------------------------------------------------------------
// the bind refusal
// ---------------------------------------------------------------------------

/**
 * A bind this server will not perform.
 *
 * The **only** error type {@link createWebdavServer} throws for an address,
 * which is what makes it catchable by name. Same shape as `S3BindError`.
 */
export class WebdavBindError extends Error {
  readonly code = "ERR_WEBDAV_BIND";
  /** The host that was refused, exactly as it was passed. */
  readonly host: string;

  constructor(host: string, message: string) {
    super(message);
    this.name = "WebdavBindError";
    this.host = host;
  }
}

/** Is this a {@link WebdavBindError}? */
export function isWebdavBindError(error: unknown): error is WebdavBindError {
  return error instanceof WebdavBindError;
}

/**
 * Is this address literally a loopback address?
 *
 * Literally: no lookup, no resolver, no `/etc/hosts`. `localhost` on the
 * convention, `::1` and every `127.x.y.z` on the address, and the `::ffff:`
 * IPv4-mapped spelling because that is how a dual-stack listener writes it.
 * Everything else — including the empty string, `0.0.0.0` and `::` — is not.
 */
export function isLoopbackHost(host: string): boolean {
  const lower = host.toLowerCase();
  // Brackets come as a pair or not at all: `[::1]` is a spelling, `::1]` is a typo.
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
 * Pure, and separate from the throw — the same treatment as
 * `loopbackRefusal()`, `elevationRefusal()` and `ownershipRefusal()` elsewhere
 * in this package: the sentence a user reads is a fact about the configuration
 * and is worth testing on its own.
 */
export function bindRefusal(host: string, credentials: boolean): string | undefined {
  if (credentials || isLoopbackHost(host)) {
    return undefined;
  }
  const unspecified = host === "" || host === "0.0.0.0" || host === "::" || host === "[::]";
  return (
    `mountx: refusing to bind a WebDAV server to ${host === "" ? "every interface" : host} ` +
    `with no credentials configured. ` +
    (unspecified
      ? `That address binds every interface, so the driver would be readable and writable ` +
        `by anything that can reach this machine. `
      : `That address is reachable from outside this machine, and an unauthenticated ` +
        `share would serve the driver to whatever finds it. `) +
    `Pass \`credentials: { username, password }\` to bind it, or leave \`host\` at ` +
    `${DEFAULT_HOST}.`
  );
}

// ---------------------------------------------------------------------------
// options and the server
// ---------------------------------------------------------------------------

export interface WebdavServerOptions extends WebdavSessionOptions {
  /** Address to bind. Default {@link DEFAULT_HOST}. See the module docs on what
   * a non-loopback one requires. */
  host?: string;
  /**
   * Port to listen on. Default `0` — an ephemeral port, which
   * {@link WebdavServer.port} then reports.
   *
   * Not 80, not 8080: a library that squats a well-known port by default fails
   * in the least useful way possible, on the machine that already runs
   * something there.
   */
  port?: number;
  /** How long {@link WebdavServer.close} waits for in-flight responses, in
   * milliseconds. Default {@link DEFAULT_DRAIN_TIMEOUT}. */
  drainTimeout?: number;
  /** Called for transport-level failures: a socket error, a reply that could
   * not be written. */
  onTransportError?: (error: unknown, peer: string | undefined) => void;
}

/** A running (or runnable) WebDAV server. */
export interface WebdavServer extends AsyncDisposable {
  /** The session answering for it — its `stats` and its driver. */
  readonly session: WebdavSession;
  /** The address it is bound to. */
  readonly host: string;
  /** The port it is listening on, or the requested one before
   * {@link WebdavServer.listen} (`0` for an ephemeral port). */
  readonly port: number;
  /** The share's URL, with an IPv6 host bracketed. Meaningful once
   * {@link WebdavServer.listen} has resolved. */
  readonly url: string;
  /** Open connections. */
  readonly connections: number;
  /** Start listening. Resolves once the port is bound. Idempotent. */
  listen(): Promise<WebdavServer>;
  /**
   * Stop accepting, let in-flight responses finish (bounded by
   * `drainTimeout`), then drop every connection. Idempotent.
   */
  close(): Promise<void>;
}

class WebdavServerImpl implements WebdavServer {
  readonly session: WebdavSession;
  readonly host: string;

  readonly #options: WebdavServerOptions;
  readonly #server: Server;
  readonly #drainTimeout: number;
  /** Every open connection. */
  readonly #sockets = new Set<Socket>();
  /**
   * Connections with a reply still on them, by how many — a count rather than a
   * flag because HTTP/1.1 allows pipelining, and a socket is idle only when the
   * last outstanding reply has been answered.
   */
  readonly #busy = new Map<Socket, number>();
  #draining = false;
  #port: number;
  #listening: Promise<WebdavServer> | undefined;
  #closed: Promise<void> | undefined;

  constructor(driver: FsDriver, options: WebdavServerOptions) {
    this.#options = options;
    this.session = new WebdavSession(driver, options);
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

  get connections(): number {
    return this.#sockets.size;
  }

  listen(): Promise<WebdavServer> {
    this.#listening ??= new Promise<WebdavServer>((resolve, reject) => {
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

  async #close(): Promise<void> {
    if (this.#listening !== undefined) {
      await this.#drain();
    }
  }

  /**
   * Stop accepting, drop every connection that is not answering something, and
   * wait for the ones that are — up to `drainTimeout`.
   *
   * Idleness is tracked here rather than left to `closeIdleConnections()`,
   * which does not count a connection that has been accepted but has not sent a
   * request yet — the socket an HTTP agent opens to replace one it just dropped
   * — and so makes `close()` wait out the whole deadline for a client that was
   * never going to say anything. `closeAllConnections()` is still node's, at
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
      headers: request.headers as Readonly<Record<string, string | undefined>>,
    };
    let reply: WebdavResponse;
    try {
      reply = await this.session.handleRequest(head, request);
    } catch (error) {
      /* v8 ignore start -- `handleRequest` is documented never to reject, and
         asserts it of itself. The guard is the same one `src/nfs/server.ts`
         keeps for `handleCall`: a broken invariant becomes one bad reply rather
         than a dead process. */
      this.#report(error, peer);
      reply = faultResponse(error);
      /* v8 ignore stop */
    }
    /* Whatever the session did or did not read, the rest of the body has to
       leave the socket before the next request can be framed on it. */
    request.resume();
    await this.#write(response, reply, head.method, head.target, peer);
  }

  /**
   * A body that did not match the `Content-Length` above it kills the
   * connection. Answers whether it did. See `src/s3/server.ts`'s `#outOfFrame`,
   * which this is, for the full reasoning: a short body wedges a client that
   * does not pipeline and is read as the head of the next reply by one that
   * does, and both are worse than a broken connection.
   *
   * Reachable without a bug here: `streamHandle` ends the body on a short read,
   * which is what a file truncated by another process between the `stat` that
   * set the length and the reads that fill it looks like.
   */
  #outOfFrame(
    response: ServerResponse,
    method: string,
    target: string,
    declared: number | undefined,
    written: number,
    peer: string | undefined,
  ): boolean {
    if (declared === undefined || written === declared) {
      return false;
    }
    this.#report(
      new Error(
        `mountx: the reply to ${method} ${target} declared ${declared} bytes and produced ` +
          `${written}. The connection was closed rather than left out of frame — the resource ` +
          `changed size under the request.`,
      ),
      peer,
    );
    response.destroy();
    return true;
  }

  /** Write one reply, streaming its body if that is what it is. */
  async #write(
    response: ServerResponse,
    reply: WebdavResponse,
    method: string,
    target: string,
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
      /* No body to count. A `HEAD` gets here with the `Content-Length` it is
         required to state and required not to fill (RFC 9110 §9.3.2), and node
         knows not to frame it as a body. */
      response.end();
      return;
    }
    if (body instanceof Uint8Array) {
      if (this.#outOfFrame(response, method, target, declared, body.byteLength, peer)) {
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
           is where an abort usually lands: one chunk is the most this can fetch
           for a client that is no longer there. */
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
      if (this.#outOfFrame(response, method, target, declared, written, peer)) {
        return;
      }
      response.end();
    } catch (error) {
      /* v8 ignore start -- the only body that streams is the `GET` generator,
         whose reads are the session's to fail. If one ever does, the status
         line is long gone and the truthful answer is a broken connection rather
         than a second reply. */
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
  if (value === undefined || !/^\d+$/.test(value)) {
    return undefined;
  }
  return Number(value);
}

/**
 * Wait for a `drain`, and answer whether writing may continue.
 *
 * `false` for a response that closed or errored while we waited — a client that
 * stopped listening, for which no drain is coming.
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
 * **Stepped once before it is closed**: a generator suspended at its *start*
 * runs no `finally` on `return()` — its body never began — so a `GET` reply
 * that was built and then never written would close nothing and leak the
 * descriptor the session opened. One `next()` puts the generator inside its
 * `try`, and the `return()` after it runs the `finally`.
 */
async function closeBody(body: WebdavResponse["body"]): Promise<void> {
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
 * Close an iterator and swallow whatever that costs: the part that mattered —
 * the generator's `finally` — has already run, and the reply is either sent or
 * unsendable.
 */
async function endIterator(iterator: AsyncIterator<Uint8Array>): Promise<void> {
  try {
    await iterator.return?.();
  } catch {
    // Deliberately ignored; see above.
  }
}

// ---------------------------------------------------------------------------
// the entry point
// ---------------------------------------------------------------------------

/**
 * Serve one driver over WebDAV.
 *
 * ```ts
 * const server = createWebdavServer(driver, {
 *   credentials: { username: "ada", password: "…" },
 *   host: "0.0.0.0",
 * });
 * ```
 *
 * Returns immediately; nothing is bound until {@link WebdavServer.listen}. What
 * *is* checked here is the bind rule (see the module docs), because a refusal
 * that waits for `listen()` is a refusal that has already opened a socket.
 *
 * @throws {WebdavBindError} for a non-loopback `host` with no `credentials`.
 * @throws {TypeError} for a value that is not an `FsDriver`.
 */
export function createWebdavServer(
  driver: FsDriver,
  options: WebdavServerOptions = {},
): WebdavServer {
  if (
    typeof driver?.stat !== "function" ||
    typeof driver.readdir !== "function" ||
    typeof driver.open !== "function"
  ) {
    throw new TypeError(
      `mountx: createWebdavServer() takes an FsDriver (with \`stat\`, \`readdir\` and ` +
        `\`open\`), and was given something else.`,
    );
  }
  const host = options.host ?? DEFAULT_HOST;
  const refusal = bindRefusal(host, options.credentials !== undefined);
  if (refusal !== undefined) {
    throw new WebdavBindError(host, refusal);
  }
  return new WebdavServerImpl(driver, options);
}
