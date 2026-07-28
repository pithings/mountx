/**
 * The NFS transport: a TCP socket, record marking, and the session behind it.
 *
 * Everything below this file — XDR, RPC, the NFS and MOUNT programs, the handle
 * table — is bytes in and bytes out, which is why all of it is testable with no
 * kernel and no root. This is the only part that opens a socket.
 *
 * ```ts
 * import { createNfsServer } from "unimount/nfs";
 * import { createMemoryDriver } from "unimount/drivers/memory";
 *
 * await using server = await createNfsServer(createMemoryDriver()).listen();
 * // sudo mount -t nfs -o vers=3,tcp,port=<p>,mountport=<p>,nolock 127.0.0.1:/ /mnt
 * ```
 *
 * **One port, no portmapper.** Both programs are answered on the same socket
 * and the mount command is told so with `port=` *and* `mountport=`, which is
 * what removes the need for `rpcbind` on port 111 — one fewer privileged
 * listener, and a whole class of "port 111 is already taken" failures with it
 * (IDEA.md, "NFSv3 loopback").
 *
 * **Who may connect.** The server binds `127.0.0.1` and, by default, closes any
 * connection from an address that is not a loopback address. NFSv3's own
 * authentication is `AUTH_SYS` — a uid the client simply asserts — so the
 * socket is the security boundary, and that is a deliberate choice rather than
 * an oversight: see the note at the top of `rpc.ts`. `allowRemote` exists for
 * the case where something in front of the server is doing the access control,
 * and it should be reached for with that in mind.
 */

import * as net from "node:net";
import type { FsDriver } from "../types.ts";
import { RecordAssembler, frameRecord } from "./rpc.ts";
import { NfsSession, type NfsSessionOptions } from "./session.ts";
import { isXdrError } from "./xdr.ts";

/** The registered NFS port. Nothing enforces it; it is simply what clients expect. */
export const DEFAULT_NFS_PORT = 2049;

/** Addresses that count as loopback. */
function isLoopback(address: string | undefined): boolean {
  if (address === undefined) {
    return false;
  }
  // `::ffff:127.0.0.1` is how a dual-stack listener reports an IPv4 peer.
  const bare = address.startsWith("::ffff:") ? address.slice(7) : address;
  return bare === "::1" || bare === "127.0.0.1" || bare.startsWith("127.");
}

export interface NfsServerOptions extends NfsSessionOptions {
  /** Port to listen on. Default `0` — an ephemeral port, which `port` then reports. */
  port?: number;
  /** Address to bind. Default `"127.0.0.1"`. */
  host?: string;
  /**
   * Accept connections from addresses that are not loopback. Default `false`.
   *
   * Turning this on exports the driver to whatever can reach the socket, with
   * NFSv3's authentication, which is to say none. See the module docs.
   */
  allowRemote?: boolean;
  /**
   * Largest RPC record accepted, in bytes. Default 8 MiB.
   *
   * A record larger than this cannot be a mistake — the biggest legal one is a
   * `WRITE` of `wtmax` plus headers — so the connection is closed rather than
   * the record skipped: there is no way to resynchronize a record-marked
   * stream once a length is not to be believed.
   */
  maxRecord?: number;
  /** Called for transport-level failures: a bad record, a socket error. */
  onTransportError?: (error: unknown, peer: string | undefined) => void;
}

/** A running (or runnable) NFS server. */
export interface NfsServer extends AsyncDisposable {
  /** The session answering for it — its `stats`, `handles` and mount list. */
  readonly session: NfsSession;
  /** The port it is listening on, or `0` before {@link NfsServer.listen}. */
  readonly port: number;
  /** The address it is bound to. */
  readonly host: string;
  /** Open connections. */
  readonly connections: number;
  /** Start listening. Resolves once the port is bound. Idempotent. */
  listen(): Promise<NfsServer>;
  /**
   * Stop listening, drop every connection and destroy the session.
   *
   * Idempotent, and it does **not** wait for clients to go away politely: a
   * mounted NFS client keeps its connection open forever, so a close that
   * waited for it would never return.
   */
  close(): Promise<void>;
}

class NfsServerImpl implements NfsServer {
  readonly session: NfsSession;
  readonly host: string;

  readonly #options: NfsServerOptions;
  readonly #server: net.Server;
  readonly #sockets = new Set<net.Socket>();
  #port: number;
  #listening: Promise<NfsServer> | undefined;
  #closed: Promise<void> | undefined;

  constructor(driver: FsDriver, options: NfsServerOptions) {
    this.#options = options;
    this.session = new NfsSession(driver, options);
    this.host = options.host ?? "127.0.0.1";
    this.#port = options.port ?? 0;
    this.#server = net.createServer({ noDelay: true }, (socket) => this.#accept(socket));
    this.#server.on("error", (error) => this.#report(error, undefined));
  }

  get port(): number {
    return this.#port;
  }

  get connections(): number {
    return this.#sockets.size;
  }

  listen(): Promise<NfsServer> {
    this.#listening ??= new Promise<NfsServer>((resolve, reject) => {
      const onError = (error: unknown): void => reject(error as Error);
      this.#server.once("error", onError);
      this.#server.listen({ port: this.#port, host: this.host }, () => {
        this.#server.off("error", onError);
        const address = this.#server.address();
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
    await new Promise<void>((resolve) => {
      this.#server.close(() => resolve());
      // Every connected client is dropped explicitly: `server.close()` only
      // stops accepting, and an NFS client's connection outlives any timeout
      // worth waiting for.
      for (const socket of this.#sockets) {
        socket.destroy();
      }
      this.#sockets.clear();
    });
    await this.session.destroy();
  }

  #report(error: unknown, peer: string | undefined): void {
    this.#options.onTransportError?.(error, peer);
  }

  #accept(socket: net.Socket): void {
    const peer = socket.remoteAddress;
    if (this.#options.allowRemote !== true && !isLoopback(peer)) {
      this.#report(
        new Error(
          `unimount: refused an NFS connection from ${peer ?? "an unknown address"} — ` +
            `this server is loopback-only. Pass \`allowRemote: true\` if something in front ` +
            `of it is doing the access control.`,
        ),
        peer,
      );
      socket.destroy();
      return;
    }
    this.#sockets.add(socket);
    const assembler = new RecordAssembler(this.#options.maxRecord);
    /**
     * Replies are serialized per connection.
     *
     * RPC over TCP allows them in any order — every reply carries its `xid` —
     * but two concurrent handlers writing into the same socket would interleave
     * *fragments*, which no client can recover from. The requests themselves
     * still run concurrently; only the writes are ordered.
     */
    let writing: Promise<void> = Promise.resolve();

    socket.on("data", (chunk: Buffer) => {
      let records: Uint8Array[];
      try {
        records = assembler.push(chunk);
      } catch (error) {
        // A record length we cannot believe: there is no resynchronizing a
        // record-marked stream, so the connection goes.
        this.#report(error, peer);
        socket.destroy();
        return;
      }
      for (const record of records) {
        const answered = this.session.handleCall(record, { peer }).catch((error: unknown) => {
          /* v8 ignore next 3 -- `handleCall` is documented never to reject;
               this keeps a broken invariant from killing the process. */
          this.#report(error, peer);
          return null;
        });
        writing = writing
          .then(async () => {
            const reply = await answered;
            if (reply !== null && !socket.destroyed) {
              socket.write(frameRecord(reply));
            }
          })
          /* v8 ignore next 5 -- nothing above can reject (`handleCall` is
             caught, and a write to a dead socket emits rather than throws).
             The catch is what keeps one failure from poisoning the chain and
             silently swallowing every later reply on this connection. */
          .catch((error: unknown) => {
            this.#report(error, peer);
          });
      }
    });

    socket.on("error", (error: unknown) => {
      // ECONNRESET is what a client that stopped caring looks like; it is not
      // worth a report, and it is not an error for the server.
      if (!isXdrError(error) && (error as NodeJS.ErrnoException).code !== "ECONNRESET") {
        this.#report(error, peer);
      }
      socket.destroy();
    });
    socket.on("close", () => {
      this.#sockets.delete(socket);
    });
  }
}

/**
 * Serve `driver` over NFSv3.
 *
 * Returns immediately; nothing is bound until {@link NfsServer.listen}.
 */
export function createNfsServer(driver: FsDriver, options: NfsServerOptions = {}): NfsServer {
  return new NfsServerImpl(driver, options);
}
