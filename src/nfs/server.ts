/**
 * The NFS transport: a TCP socket, record marking, and the session behind it.
 *
 * Everything below this file — XDR, RPC, the NFS and MOUNT programs, the handle
 * table — is bytes in and bytes out, which is why all of it is testable with no
 * kernel and no root. This is the only part that opens a socket.
 *
 * ```ts
 * import { createNfsServer } from "mountx/nfs";
 * import { createMemoryDriver } from "mountx/drivers/memory";
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

/**
 * Requests a connection answers at once before the rest wait their turn.
 *
 * Sixty-four is not `src/9p/server.ts`'s sixteen, and the difference is the
 * protocol rather than a preference. NFSv4.1 counter-offers `ca_maxrequests`
 * up to `maxForeSlots` — 64 by default — and a conforming client is entitled
 * to keep every slot it was granted busy; a window under that number would
 * throttle traffic this server itself said it would take. NFSv3 has no slot
 * table on the wire, but the Linux client's `sunrpc.tcp_slot_table_entries`
 * grows dynamically and lands in the same range, so one number covers both.
 *
 * Named for the transport rather than borrowing 9P's `DEFAULT_MAX_IN_FLIGHT`,
 * the way {@link DEFAULT_NFS_PORT} is named beside 9P's `DEFAULT_P9_PORT`:
 * `mountx/9p` and `mountx/nfs` are two public subpaths, and one identifier
 * meaning 16 on one and 64 on the other is a difference an import cannot show.
 * The *option* is `maxInFlight` on both, because there the interface says which.
 *
 * What it buys is the bound: replies alive at once are `maxInFlight` × the
 * largest one, so with the default 1 MiB `rtmax`/`wtmax` a connection holds at
 * most ~64 MiB of answers rather than however many 1 MiB `READ`s a client felt
 * like pipelining — 10 GB from 10k of them, before this existed. Records
 * parsed but not yet dispatched wait at wire size: 108 bytes for a v3 `READ`
 * call framed with this server's 20-byte handle, 180 for the NFSv4.1
 * `SEQUENCE`+`PUTFH`+`READ` COMPOUND that carries the same read.
 */
export const DEFAULT_NFS_MAX_IN_FLIGHT = 64;

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
  /**
   * Requests dispatched at once per connection, before the rest wait. Default
   * {@link DEFAULT_NFS_MAX_IN_FLIGHT}.
   *
   * This is what bounds *memory*. {@link NfsServerOptions.maxRecord} bounds one
   * record; nothing bounded how many were being answered at once, and a client
   * that pipelines is not doing anything unusual — RPC over TCP matches replies
   * by `xid` and NFSv4.1 hands out a slot table precisely so a client will fill
   * it. Ten thousand pipelined 1 MiB `READ`s cost the client **1.03 MiB** of
   * wire on v3 (a framed `READ` call is 108 bytes with this server's 20-byte
   * handle) or **1.72 MiB** on 4.1 (180 bytes for the `SEQUENCE`+`PUTFH`+`READ`
   * COMPOUND), and cost this server ten gigabytes of replies — a ~10,000×
   * amplification either way. With a window, the replies alive at once are
   * bounded by `maxInFlight` × the largest one, and the records waiting their
   * turn cost their wire size and nothing more.
   *
   * It is not an ordering knob: replies still go out in completion order,
   * matched by `xid` (and on 4.1 additionally by `(session, slot, sequence)`),
   * so a slow call never delays a fast one behind it.
   */
  maxInFlight?: number;
  /** Called for transport-level failures: a bad record, a socket error. */
  onTransportError?: (error: unknown, peer: string | undefined) => void;
}

/**
 * One client, the socket, and the shared session behind it.
 *
 * Unlike 9P — where fids are per-connection state, so `src/9p/server.ts` builds
 * a session per stream — NFS is stateless on v3 and keyed by client id on v4.1,
 * so every connection here is answered by the *one* {@link NfsSession} the
 * server owns. What is per-connection is the framing and the flow control, and
 * that is all this class is.
 *
 * **Replies go out in completion order**, not request order. RPC over TCP is
 * explicitly an out-of-order protocol — every reply carries the `xid` of the
 * call it answers, and NFSv4.1 additionally matches `(session, slot,
 * sequenceid)` — so a slow `READ` must not hold up the `GETATTR` behind it. The
 * chain here orders only the `write`: it is appended to when a reply is
 * *produced*, never awaited from inside itself. Ordering the await instead
 * collapsed every in-flight call to the latency of the slowest — with the
 * default `soft,timeo=50,retrans=2` that manufactures retransmits — and it
 * bought nothing, because each reply is one contiguous `frameRecord()` buffer
 * handed to one `socket.write()` and Node's writable queue never interleaves
 * chunks from separate `write()` calls.
 *
 * **Reading is paused, not buffered.** A connection that is congested — the
 * socket full, or {@link NfsServerOptions.maxInFlight} calls already being
 * answered — stops reading, so what is outstanding is bounded by what has been
 * dispatched rather than by what a client felt like sending. Records parsed but
 * not yet dispatched wait as records, at wire size.
 *
 * **Framing.** Every `data` chunk is pushed into this connection's
 * `RecordAssembler`, which copies out whole records, and each one is dispatched
 * *without* being awaited — the transport half of the zero-copy contract, the
 * session half being that it decodes and copies what it keeps before its first
 * `await`.
 *
 * **A half-close is a reset, not a flush** — the same rule
 * {@link NfsServer.close} states for the server end, said here for the client
 * end. `end` on the socket stops this connection: the records it has parsed and
 * not dispatched are dropped, and replies still being computed are not written.
 * Nothing is lost that could have been kept, because `net.Server` runs with
 * `allowHalfOpen: false` — Node ends the writable side the moment the readable
 * one ends, so anything not already handed to `write()` had nowhere to go
 * regardless. No NFS client half-closes mid-request; a peer that sends FIN with
 * calls outstanding has stopped caring about their answers, and the honest
 * reading of that is that the connection is over.
 */
class NfsConnection {
  readonly #socket: net.Socket;
  readonly #peer: string | undefined;
  readonly #session: NfsSession;
  readonly #assembler: RecordAssembler;
  readonly #report: (error: unknown, peer: string | undefined) => void;
  /** How many calls may be in flight before the rest wait. */
  readonly #window: number;
  /** Records parsed but not dispatched: what a congested connection holds, at wire size. */
  readonly #records: Uint8Array[] = [];
  /** Whoever is waiting for `drain`. Released by the event, or by teardown. */
  #drainers: (() => void)[] = [];
  /** The reply write chain: one at a time, in the order the replies were produced. */
  #writing: Promise<void> = Promise.resolve();
  /** Dispatched and not yet handed to the socket. */
  #inflight = 0;
  /** The socket said it was full and has not drained since. */
  #congested = false;
  /** *We* paused the socket, so only we resume it. */
  #paused = false;
  /** Set by teardown: no more records are read, and no more replies are written. */
  #stopped = false;

  constructor(
    socket: net.Socket,
    session: NfsSession,
    options: NfsServerOptions,
    report: (error: unknown, peer: string | undefined) => void,
  ) {
    this.#socket = socket;
    this.#peer = socket.remoteAddress;
    this.#session = session;
    this.#assembler = new RecordAssembler(options.maxRecord);
    this.#report = report;
    this.#window = Math.max(1, Math.trunc(options.maxInFlight ?? DEFAULT_NFS_MAX_IN_FLIGHT));

    socket.on("data", (chunk: Buffer) => this.#feed(chunk));
    socket.on("drain", () => this.#drain());
    // A half-close and a close take the one path: see the note on this class.
    socket.on("end", () => this.#stop());
    socket.on("close", () => this.#stop());
    socket.on("error", (error: unknown) => {
      // ECONNRESET is what a client that stopped caring looks like; it is not
      // worth a report, and it is not an error for the server.
      if (!isXdrError(error) && (error as NodeJS.ErrnoException).code !== "ECONNRESET") {
        this.#report(error, this.#peer);
      }
      this.#stop();
      socket.destroy();
    });
  }

  /** Nothing more is read or written, and nothing stays parked on a `drain` that is not coming. */
  #stop(): void {
    this.#stopped = true;
    this.#records.length = 0;
    this.#release();
  }

  /** One delivery from the socket: records out, then as many as may be dispatched. */
  #feed(chunk: Uint8Array): void {
    if (this.#stopped) {
      return;
    }
    let records: Uint8Array[];
    try {
      records = this.#assembler.push(chunk);
    } catch (error) {
      // A record length we cannot believe: there is no resynchronizing a
      // record-marked stream, so the connection goes.
      this.#report(error, this.#peer);
      this.#stop();
      this.#socket.destroy();
      return;
    }
    for (const record of records) {
      this.#records.push(record);
    }
    this.#pump();
  }

  /**
   * Dispatch what there is room for, and read only while there is room.
   *
   * The two bounds are the window and the socket: a connection with
   * {@link NfsServerOptions.maxInFlight} calls being answered, or one whose
   * socket is full, holds its parsed records instead of turning them into
   * replies, and stops reading instead of parsing more.
   */
  #pump(): void {
    while (
      !this.#stopped &&
      !this.#congested &&
      this.#inflight < this.#window &&
      this.#records.length > 0
    ) {
      this.#dispatch(this.#records.shift()!);
    }
    if (this.#stopped) {
      return;
    }
    if (this.#congested || this.#inflight >= this.#window || this.#records.length > 0) {
      this.#pauseReads();
    } else {
      this.#resumeReads();
    }
  }

  /**
   * Answer one record, without awaiting it.
   *
   * The await would be the transport half of the zero-copy contract broken:
   * `#feed` must return so the socket can deliver the next chunk. Calls
   * therefore run concurrently — up to the window — which is the whole reason
   * RPC carries an `xid`.
   */
  #dispatch(record: Uint8Array): void {
    this.#inflight++;
    const answered = this.#session
      .handleCall(record, { peer: this.#peer })
      .catch((error: unknown) => {
        /* v8 ignore next 3 -- `handleCall` is documented never to reject;
             this keeps a broken invariant from killing the process. */
        this.#report(error, this.#peer);
        return null;
      });
    void answered
      .then((reply) => {
        // Appended when the reply is *produced*, so the chain is in completion
        // order; `#send` is what makes it one write at a time.
        this.#writing = this.#writing.then(() => this.#send(reply));
        return this.#writing;
      })
      /* v8 ignore next 6 -- nothing above can reject (`handleCall` is caught,
         `#send` handles its own failures, and a write to a dead socket emits
         rather than throws). The catch is what keeps one failure from poisoning
         the chain and silently swallowing every later reply on this connection.
         The window is deliberately not credited back: the connection is going
         away, and a double count would be worse than a forgotten one. */
      .catch((error: unknown) => {
        this.#report(error, this.#peer);
        this.#stop();
        this.#socket.destroy();
      });
  }

  /**
   * Hand one reply to the socket, and wait there if the socket is full.
   *
   * Serializing the writes is what bounds the queue: a reply is only written
   * when the previous one either fit or has drained, so the socket holds about
   * its high-water mark plus one record no matter how many calls arrived
   * together. `write()` itself is never awaited into the *dispatch* path —
   * calls keep being answered concurrently — only the write-back is ordered.
   */
  async #send(reply: Uint8Array | null): Promise<void> {
    try {
      if (
        reply !== null &&
        !this.#stopped &&
        !this.#socket.destroyed &&
        !this.#socket.writableEnded &&
        !this.#socket.write(frameRecord(reply))
      ) {
        this.#congested = true;
        this.#pauseReads();
        await new Promise<void>((resolve) => this.#drainers.push(resolve));
      }
      /* v8 ignore next 5 -- a `net.Socket` reports a failed write through
         `error` rather than by throwing, so this is unreachable over TCP; it
         exists because a throw here would reject the write chain, and the
         `finally` below is what keeps the window from leaking either way. */
    } catch (error) {
      this.#report(error, this.#peer);
      this.#stop();
      this.#socket.destroy();
    } finally {
      this.#inflight--;
      this.#pump();
    }
  }

  /** The socket has room again: wake the write chain and start reading. */
  #drain(): void {
    this.#congested = false;
    this.#release();
    this.#pump();
  }

  /** Wake everything parked on `drain`, whether or not one is coming. */
  #release(): void {
    const waiting = this.#drainers;
    this.#drainers = [];
    for (const resolve of waiting) {
      resolve();
    }
  }

  #pauseReads(): void {
    if (!this.#paused) {
      this.#paused = true;
      this.#socket.pause();
    }
  }

  #resumeReads(): void {
    if (this.#paused) {
      this.#paused = false;
      this.#socket.resume();
    }
  }
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
          `mountx: refused an NFS connection from ${peer ?? "an unknown address"} — ` +
            `this server is loopback-only. Pass \`allowRemote: true\` if something in front ` +
            `of it is doing the access control.`,
        ),
        peer,
      );
      socket.destroy();
      return;
    }
    this.#sockets.add(socket);
    // Framing and flow control are per-connection; the session is not. The
    // connection registers its own handlers and needs no keeping hold of — it
    // lives as long as the socket's listeners do.
    new NfsConnection(socket, this.session, this.#options, (error, from) =>
      this.#report(error, from),
    );
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
