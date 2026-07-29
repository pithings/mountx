/**
 * The 9P transport: a stream, per-connection framing, and a session behind each.
 *
 * Everything under `src/9p/` — the wire primitives, the codecs, the fid table,
 * the session — is bytes in and bytes out, which is why all of it is testable
 * with no kernel and no root. This is the only file there that opens a socket,
 * exactly as `src/nfs/server.ts` is for NFS.
 *
 * ```ts
 * import { createP9Server } from "mountx/9p";
 * import { createMemoryDriver } from "mountx/drivers/memory";
 *
 * await using server = await createP9Server(createMemoryDriver()).listen();
 * // sudo mount -t 9p -o trans=tcp,port=<p>,version=9p2000.L 127.0.0.1 /mnt
 * ```
 *
 * **Three ways in, one way through.** A TCP listener, a unix-socket listener
 * and {@link P9Server.attach} — an already-connected `Duplex`, which is what
 * `mount9p()`'s socketpair will hand over — differ only in how the stream is
 * obtained. Past that they are the same code: one {@link P9Session} and one
 * `P9FrameAssembler` per connection, and no knowledge anywhere of which of the
 * three produced the stream.
 *
 * **One session per connection.** Fids are per-connection state in 9P — the
 * kernel's client allocates them from its own IDR and they mean nothing to
 * anybody else — so two clients get two sessions, two fid tables and two
 * negotiated `msize`s over the *one* driver they share. Two consequences worth
 * saying out loud, because the second is a real limitation:
 *
 * - Each session holds its own `PathLock`, so a rename is serialized against
 *   other work on the same connection and **not** against a second client's.
 *   The lock exists to keep one client's path map consistent under its own
 *   traffic; two clients renaming the same subtree concurrently race in the
 *   driver, the way two processes racing on a local filesystem do.
 * - `Tlock`/`Tgetlock` grant unconditionally (see `P9Session`), which is honest
 *   for the local `trans=fd` mount this transport exists for — one client, and
 *   the client kernel doing its own POSIX-lock bookkeeping — and is *not*
 *   honest once a second client is attached. Serving several clients is
 *   supported here; byte-range locking between them is not.
 *
 * **Who may connect.** A TCP listener binds `127.0.0.1` and drops any
 * connection from an address that is not loopback, because 9P's only
 * authentication is the `uname`/`n_uname` a client asserts in `Tattach` — the
 * socket is the security boundary. `allowRemote` exists for the case where
 * something in front of the server is doing the access control (the VM-guest
 * case: `trans=tcp` from a guest against the host). A unix-socket listener is
 * held to the rule in {@link P9ServerOptions.path}.
 */

import { chmod, stat, unlink } from "node:fs/promises";
import * as net from "node:net";
import { dirname, resolve as resolvePath } from "node:path";
import type { Duplex } from "node:stream";
import type { FsDriver } from "../types.ts";
import { P9FrameAssembler, P9_DEFAULT_MAX_FRAME } from "./protocol.ts";
import { P9Session, type P9SessionOptions } from "./session.ts";

/**
 * The port `mount -t 9p -o trans=tcp` uses when no `port=` is given.
 *
 * Nothing here enforces it — the default is an ephemeral port — but it is what
 * `v9fs`'s `trans=tcp` reaches for (`P9_PORT` in `include/net/9p/9p.h`).
 */
export const DEFAULT_P9_PORT = 564;

/** The mode a unix socket is given once bound. Owner read/write, nobody else. */
export const DEFAULT_SOCKET_MODE = 0o600;

/**
 * Requests a connection answers at once before the rest wait their turn.
 *
 * Sixteen is enough that a client's ordinary pipelining never touches it — the
 * kernel's own `p9_client` keeps a handful of requests outstanding per mount —
 * and small enough that the replies alive at once stay a few `msize`s rather
 * than however many requests fit in a single delivery.
 */
export const DEFAULT_MAX_IN_FLIGHT = 16;

/** Addresses that count as loopback. */
function isLoopback(address: string | undefined): boolean {
  if (address === undefined) {
    return false;
  }
  // `::ffff:127.0.0.1` is how a dual-stack listener reports an IPv4 peer.
  const bare = address.startsWith("::ffff:") ? address.slice(7) : address;
  return bare === "::1" || bare === "127.0.0.1" || bare.startsWith("127.");
}

/** How a connection is named in an {@link P9ServerOptions.onTransportError} report. */
function peerOf(stream: Duplex, fallback: string | undefined): string | undefined {
  const socket = stream as Partial<net.Socket>;
  if (typeof socket.remoteAddress === "string") {
    return socket.remotePort === undefined
      ? socket.remoteAddress
      : `${socket.remoteAddress}:${socket.remotePort}`;
  }
  return fallback;
}

/**
 * Say goodbye on a stream: EOF to the peer, and nothing more read from it.
 *
 * A socket is destroyed — `destroySoon()` (flush, then destroy) when there is
 * time for it, `destroy()` when there is not — because the connection is ours
 * to end and a peer that stopped reading must not be able to hold a shutdown
 * open.
 *
 * A `Duplex` that is *not* a socket — the stream pair an embedder or a test
 * hands to {@link P9Server.attach} — gets its write side ended and its read
 * side paused, and is **not** destroyed. Two reasons. It was not this server's
 * to create, so it is not this server's to tear down; and a composed stream
 * (`Duplex.from`) treats a destroy with its read half still live as an abort
 * and reports `ABORT_ERR` for a shutdown nobody went wrong in. `end()` is the
 * part that matters either way: EOF is how a 9P connection says it is over.
 */
function endStream(stream: Duplex, hard: boolean): void {
  if (stream.destroyed) {
    return;
  }
  const socket = stream as Duplex & { destroySoon?: () => void };
  if (typeof socket.destroySoon === "function") {
    if (hard) {
      stream.destroy();
    } else {
      socket.destroySoon();
    }
    return;
  }
  stream.pause();
  if (!stream.writableEnded) {
    stream.end();
  }
}

export interface P9ServerOptions extends P9SessionOptions {
  /**
   * TCP port to listen on. Default `0` — an ephemeral port, which
   * {@link P9Server.port} then reports.
   */
  port?: number;
  /** Address to bind. Default `"127.0.0.1"`. */
  host?: string;
  /**
   * Listen on a unix socket at this path instead of a TCP port.
   *
   * **What is enforced.** The socket is `chmod`ed to
   * {@link P9ServerOptions.socketMode} (`0600`) the moment it is bound, and
   * before that the *directory* it will live in is required to be owned by this
   * process's uid with no group or other bits at all — `0700`, what `mkdtemp`
   * gives you. Both are refusals: a directory that fails the check throws out
   * of {@link P9Server.listen} rather than warning and continuing.
   *
   * **Why the directory and not just the socket.** Linux checks write
   * permission on a socket's inode at `connect(2)`, so the mode is a real gate
   * — but there is a window between `bind(2)` and the `chmod`, and Node offers
   * no way to bind with a mode. A directory another user cannot search closes
   * that window ahead of time, which is the only race-free half of this.
   *
   * **What is advisory.** Root ignores both. A directory whose mode changes
   * after the check is not re-checked. And socket-mode enforcement is a
   * property of the host kernel rather than of POSIX — it is Linux's behaviour,
   * which is the platform 9P mounts on.
   *
   * Set {@link P9ServerOptions.allowSharedDirectory} when something else is
   * doing the access control and the directory rule is in the way.
   */
  path?: string;
  /**
   * Accept TCP connections from addresses that are not loopback. Default
   * `false`. See the module docs: 9P authenticates nothing.
   */
  allowRemote?: boolean;
  /** Mode applied to a unix socket once bound. Default {@link DEFAULT_SOCKET_MODE}. */
  socketMode?: number;
  /** Skip the directory check described in {@link P9ServerOptions.path}. Default `false`. */
  allowSharedDirectory?: boolean;
  /**
   * Largest frame accepted **before** `Tversion`, in bytes. Default
   * {@link P9_DEFAULT_MAX_FRAME}.
   *
   * A 9P stream's only structure is a 32-bit size field, so a reassembler needs
   * a bound before anybody has negotiated one. It bounds *only* that window:
   * once a connection agrees an `msize`, the assembler is set to that instead —
   * raised as readily as lowered, since a session whose `msize` cap is above
   * this default is entitled to the frames it just agreed to. **The steady-state
   * bound is therefore `msize`, not this**, so an operator who wants to cap what
   * a client can send should set {@link P9SessionOptions.msize}; `maxFrame` only
   * decides how much an unnegotiated peer can ask this process to allocate.
   *
   * How much a client can pipeline ahead of its own `Rversion` — where the old
   * limit still applies — depends on how the deliveries fall, not on the
   * protocol: everything already parsed when the reply is produced was bounded
   * by `maxFrame`.
   */
  maxFrame?: number;
  /**
   * Requests dispatched at once per connection, before the rest wait. Default
   * {@link DEFAULT_MAX_IN_FLIGHT}.
   *
   * This is what bounds *memory*, and it needs to exist because one delivery can
   * carry thousands of requests: 2,800 `Tread`s fit in 64 KiB of wire and, all
   * dispatched at once, answer with up to `msize` each — gigabytes of replies
   * from a burst that cost the client nothing to send. With a window, the
   * replies alive at any moment are bounded by `maxInFlight × msize`, and the
   * frames waiting their turn cost their wire size and nothing more.
   *
   * Requests are dispatched in arrival order, so `Tflush` still finds the tag it
   * names either in flight or already answered; nothing about the protocol's
   * ordering depends on the window's size.
   */
  maxInFlight?: number;
  /** Called for transport-level failures: a framing error, a socket error. */
  onTransportError?: (error: unknown, peer: string | undefined) => void;
}

/**
 * One client, its session, and the stream between them.
 *
 * **Framing.** Every `data` chunk is pushed into this connection's
 * `P9FrameAssembler`, which copies out whole frames — so the socket's buffer is
 * free to be re-armed the moment the handler returns, and each frame handed to
 * `handleCall` is already this connection's own memory. That is the transport
 * half of the zero-copy contract; the session half is that it decodes and
 * copies everything it keeps before its first `await`, which is why a frame is
 * dispatched *without* being awaited.
 *
 * **Replies go out in completion order**, not request order. 9P is explicitly
 * an out-of-order protocol — a reply carries the `tag` of the request it
 * answers and `p9_client_rpc()` matches on it — so a slow `Tread` does not hold
 * up the `Tgetattr` behind it. The writes themselves are serialized: one reply
 * is handed to the stream at a time, and if the stream says it is full the next
 * one waits for `drain`. That is what bounds the write queue to roughly its own
 * high-water mark plus one frame, however many requests a single delivery
 * carried; without it, a burst is answered into a queue that grows to the sum of
 * every reply in it. Each reply is still one `write()` call, so two of them
 * cannot interleave their bytes.
 *
 * **Reading is paused, not buffered.** A connection that is congested — the
 * stream full, or {@link P9ServerOptions.maxInFlight} requests already being
 * answered — stops reading its stream, so what is outstanding is bounded by
 * what has already been dispatched rather than by what a client felt like
 * sending. Frames parsed but not yet dispatched wait as frames, at wire size.
 *
 * **The `msize` bound.** The assembler starts at
 * {@link P9ServerOptions.maxFrame} and is set to the session's negotiated
 * `msize` as soon as a reply has been produced — the earliest moment the
 * negotiated value exists, since `Tversion`'s answer is where it is set.
 */
export interface P9Connection {
  /** The session answering this connection, and nobody else's. */
  readonly session: P9Session;
  /** The stream it is being served over. */
  readonly stream: Duplex;
  /** `address:port`, the socket path, or `undefined` for an attached stream. */
  readonly peer: string | undefined;
  /**
   * Resolves once this connection is really gone.
   *
   * For a stream this server owns — anything it accepted, and any socket handed
   * to {@link P9Server.attach} — that means the session has been destroyed
   * *and* the stream has emitted `close`, so the descriptor is no longer open.
   * That is the useful signal for a mount: EOF is how a 9P connection ends
   * (there is no `Tdestroy` and no analogue of `FUSE_DESTROY`), and a mount
   * tearing down wants to know the fd went with it.
   *
   * For a stream this server does not own — see {@link P9Server.attach} — it
   * resolves once the session is destroyed and this end has been ended, since
   * whether the stream ever closes is up to whoever made it.
   */
  readonly closed: Promise<void>;
  /** End the stream and destroy the session. Idempotent. */
  close(): Promise<void>;
}

/** A running (or runnable) 9P server. */
export interface P9Server extends AsyncDisposable {
  /** The options it was made with, as given. */
  readonly options: P9ServerOptions;
  /** The address it binds. Meaningless for a unix-socket server. */
  readonly host: string;
  /** The port it is listening on, or `0` before {@link P9Server.listen}. */
  readonly port: number;
  /** The unix socket path it listens on, if it is that kind of server. */
  readonly path: string | undefined;
  /** Live connections, in the order they arrived. */
  readonly clients: readonly P9Connection[];
  /** How many of them there are. */
  readonly connections: number;
  /** Whatever `net.Server.address()` says: an `AddressInfo`, a path, or `null`. */
  address(): net.AddressInfo | string | null;
  /** Start listening. Resolves once the port or path is bound. Idempotent. */
  listen(): Promise<P9Server>;
  /**
   * Serve an already-connected stream — a socketpair end, a pipe, a test
   * double. The connection is live before this returns.
   *
   * A stream may be attached once; attaching the same one twice throws.
   *
   * `own` decides who destroys it, and defaults to whether it looks like a
   * socket (a `destroySoon` method — which the socketpair end `mount9p()` will
   * hand over does have). An owned stream is destroyed on teardown, and
   * {@link P9Connection.closed} waits for its `close`; a stream this server
   * does not own is only *ended*, because a `Duplex` somebody else composed is
   * theirs to take apart — destroying one whose read half is still live is how
   * you get an `ABORT_ERR` out of a shutdown that went fine.
   */
  attach(stream: Duplex, options?: { peer?: string; own?: boolean }): P9Connection;
  /**
   * Stop listening, drop every connection and destroy every session.
   *
   * Idempotent, and it does **not** wait for clients to go away politely: a
   * mounted 9P client keeps its connection open for as long as the mount
   * exists, so a close that waited for it would never return. Every socket this
   * server ever accepted is destroyed outright — tracked until its own `close`
   * event rather than until its session came down, because `net.Server.close()`
   * waits for each accepted socket and a peer that sent `FIN` and then stopped
   * reading would otherwise hold this open forever. That is what keeps it
   * bounded with no deadline of its own. Unmount ordering is `mount9p()`'s
   * problem, not this one's.
   */
  close(): Promise<void>;
}

/** What a connection needs from the server that made it, and nothing else. */
interface ConnectionHost {
  options: P9ServerOptions;
  driver: FsDriver;
  stream: Duplex;
  peer: string | undefined;
  /** Is this stream ours to destroy? See {@link P9Server.attach}. */
  owned: boolean;
  report: (error: unknown) => void;
  gone: () => void;
}

class P9ConnectionImpl implements P9Connection {
  readonly session: P9Session;
  readonly stream: Duplex;
  readonly peer: string | undefined;
  readonly closed: Promise<void>;

  readonly #host: ConnectionHost;
  readonly #assembler: P9FrameAssembler;
  readonly #owned: boolean;
  /** How many requests may be in flight before the rest wait. */
  readonly #window: number;
  /** Resolves when the stream emits `close`; only awaited for a stream we own. */
  readonly #streamClosed: Promise<void>;
  /** Frames parsed but not dispatched: what a congested connection holds, at wire size. */
  readonly #frames: Uint8Array[] = [];
  /** Whoever is waiting for `drain`. Released by the event, or by teardown. */
  #drainers: (() => void)[] = [];
  /** The reply write chain: one at a time, in the order the replies were produced. */
  #writing: Promise<void> = Promise.resolve();
  /** Dispatched and not yet handed to the stream. */
  #inflight = 0;
  /** The stream said it was full and has not drained since. */
  #congested = false;
  /** *We* paused the stream — an embedder's own pause is not ours to undo. */
  #paused = false;
  #settle!: () => void;
  #ending: Promise<void> | undefined;
  /** Set by teardown: no more frames are read, and no more replies are written. */
  #stopped = false;

  constructor(host: ConnectionHost) {
    this.#host = host;
    this.stream = host.stream;
    this.peer = host.peer;
    this.#owned = host.owned;
    this.session = new P9Session(host.driver, host.options);
    this.#assembler = new P9FrameAssembler(host.options.maxFrame ?? P9_DEFAULT_MAX_FRAME);
    this.#window = Math.max(1, Math.trunc(host.options.maxInFlight ?? DEFAULT_MAX_IN_FLIGHT));
    this.#streamClosed = this.stream.closed
      ? Promise.resolve()
      : new Promise<void>((resolve) => {
          this.stream.once("close", () => resolve());
        });
    this.closed = new Promise<void>((settle) => {
      this.#settle = settle;
    });

    const stream = this.stream;
    stream.on("data", (chunk: Buffer) => this.#feed(chunk));
    stream.on("drain", () => this.#drain());
    // EOF, an error and the stream's own end all mean the same thing here, and
    // `close()` is idempotent, so all three simply take the one path.
    stream.on("end", () => void this.close());
    stream.on("close", () => void this.close());
    stream.on("error", (error: unknown) => {
      // A client that stopped caring resets or breaks the pipe; neither is an
      // error for this server, and neither is worth a report.
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ECONNRESET" && code !== "EPIPE") {
        this.#host.report(error);
      }
      void this.close();
    });
  }

  close(): Promise<void> {
    this.#ending ??= this.#close();
    return this.#ending;
  }

  /**
   * The same, without the flush: for a server shutting down.
   *
   * Destroying an owned stream first makes {@link close}'s polite goodbye a
   * no-op, so the ordering is "the socket is gone, now wait for the session".
   */
  drop(): Promise<void> {
    this.#stopped = true;
    this.#release();
    if (this.#owned && !this.stream.destroyed) {
      this.stream.destroy();
    }
    return this.close();
  }

  async #close(): Promise<void> {
    this.#stopped = true;
    this.#frames.length = 0;
    // Anything parked on `drain` is woken now: the drain it is waiting for may
    // never come, and a write chain that never settles is a leak.
    this.#release();
    endStream(this.stream, false);
    try {
      // There is no `Tdestroy`: teardown belongs to whoever notices the stream
      // ended. Idempotent, and safe with requests in flight — a request that
      // crosses it is discarded by the session's generation counter.
      await this.session.destroy();
      /* v8 ignore next 4 -- `destroy()` reports driver `close()` failures
         through `onError` rather than throwing; this is what keeps a teardown
         that surprises us from becoming an unhandled rejection out of an
         event handler. */
    } catch (error) {
      this.#host.report(error);
    } finally {
      if (this.#owned) {
        // The flush an owned stream gets is however long the session took to
        // come down. Past that the descriptor goes: `destroySoon()` waits for a
        // peer to read, a half-closed peer that stopped reading never does, and
        // `net.Server.close()` is waiting on this socket.
        if (!this.stream.destroyed) {
          this.stream.destroy();
        }
        await this.#streamClosed;
      }
      this.#host.gone();
      this.#settle();
    }
  }

  /** One delivery from the stream: frames out, then as many as may be dispatched. */
  #feed(chunk: Uint8Array): void {
    if (this.#stopped) {
      return;
    }
    let frames: Uint8Array[];
    try {
      frames = this.#assembler.push(chunk);
    } catch (error) {
      // A framing error latches, and it is terminal for the connection rather
      // than for the frame: `size` is the only structure a 9P stream has, so
      // once one is not to be believed there is no offset at which parsing
      // could resume. The session's own errors are replies; this is not one.
      this.#host.report(error);
      void this.close();
      return;
    }
    for (const frame of frames) {
      this.#frames.push(frame);
    }
    this.#pump();
  }

  /**
   * Dispatch what there is room for, and read only while there is room.
   *
   * The two bounds are the window and the stream: a connection with
   * {@link P9ServerOptions.maxInFlight} requests being answered, or one whose
   * stream is full, holds its parsed frames instead of turning them into
   * replies, and stops reading its stream instead of parsing more. Frames wait
   * at wire size — 23 bytes for a `Tread` — where replies would wait at up to
   * `msize` each.
   *
   * Dispatch is in arrival order, which is what keeps `Tflush` meaningful: the
   * request a `Tflush` names was sent before it, so it is dispatched before it,
   * so the session finds the tag in flight rather than unknown.
   */
  #pump(): void {
    while (
      !this.#stopped &&
      !this.#congested &&
      this.#inflight < this.#window &&
      this.#frames.length > 0
    ) {
      this.#dispatch(this.#frames.shift()!);
    }
    if (this.#stopped) {
      return;
    }
    if (this.#congested || this.#inflight >= this.#window || this.#frames.length > 0) {
      this.#pauseReads();
    } else {
      this.#resumeReads();
    }
  }

  /**
   * Answer one frame, without awaiting it.
   *
   * The await would be the transport half of the zero-copy contract broken:
   * `#feed` must return so the stream can deliver the next chunk. Requests
   * therefore run concurrently — up to the window — which is the whole reason
   * 9P carries tags.
   */
  #dispatch(frame: Uint8Array): void {
    this.#inflight++;
    const answered = this.session.handleCall(frame).catch((error: unknown) => {
      /* v8 ignore next 3 -- `handleCall` is documented never to reject; this
         keeps a broken invariant from becoming an unhandled rejection. */
      this.#host.report(error);
      return null;
    });
    void answered
      .then((reply) => {
        // Appended when the reply is *produced*, so the chain is in completion
        // order; `#send` is what makes it one write at a time.
        this.#writing = this.#writing.then(() => this.#send(reply));
        return this.#writing;
      })
      .catch((error: unknown) => {
        /* v8 ignore next 4 -- `#send` handles its own failures and the chain
           never rejects, so nothing should reach here; it exists because a
           rejection nobody catches out of an event handler is a dead process,
           which is the catch `src/nfs/server.ts` carries for the same reason.
           The window is deliberately not credited back: the connection is going
           away, and a double count would be worse than a forgotten one. */
        this.#host.report(error);
        void this.close();
      });
  }

  /**
   * Hand one reply to the stream, and wait there if the stream is full.
   *
   * Serializing the writes is what bounds the queue: a reply is only written
   * when the previous one either fit or has drained, so the stream holds about
   * its high-water mark plus one frame no matter how many requests arrived
   * together. `write()` itself is never awaited into the *dispatch* path —
   * requests keep being answered concurrently — only the write-back is ordered.
   */
  async #send(reply: Uint8Array | null): Promise<void> {
    try {
      this.#tune();
      if (
        reply !== null &&
        !this.#stopped &&
        !this.stream.destroyed &&
        !this.stream.writableEnded &&
        !this.stream.write(reply)
      ) {
        this.#congested = true;
        this.#pauseReads();
        await new Promise<void>((resolve) => this.#drainers.push(resolve));
      }
    } catch (error) {
      // A `write()` that throws is a stream refusing to carry this connection —
      // an embedder's `Duplex`, most likely. There is nothing to retry.
      this.#host.report(error);
      void this.close();
    } finally {
      this.#inflight--;
      this.#pump();
    }
  }

  /** The stream has room again: wake the write chain and start reading. */
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
      this.stream.pause();
    }
  }

  /** Resume only what we paused: an embedder's own `pause()` is not ours to undo. */
  #resumeReads(): void {
    if (this.#paused) {
      this.#paused = false;
      this.stream.resume();
    }
  }

  /**
   * Set the frame limit to whatever `msize` the session has agreed.
   *
   * Cheap enough to do before every reply, and doing it there rather than only
   * after `Rversion` means a re-negotiation — `Tversion` may arrive at any time
   * and resets the session — is picked up by the same three lines.
   */
  #tune(): void {
    const msize = this.session.msize;
    if (msize !== undefined && msize !== this.#assembler.limit) {
      this.#assembler.limit = msize;
    }
  }
}

class P9ServerImpl implements P9Server {
  readonly options: P9ServerOptions;
  readonly host: string;
  readonly path: string | undefined;

  readonly #driver: FsDriver;
  readonly #server: net.Server;
  readonly #connections = new Set<P9ConnectionImpl>();
  /** Every attached stream, so the same one cannot be attached twice. */
  readonly #streams = new Set<Duplex>();
  /**
   * Streams this server must destroy, held until each one's own `close` event.
   *
   * Deliberately *not* the connection set: a connection is forgotten when its
   * session comes down, which can happen while its socket is still open with a
   * write queue on it, and `net.Server.close()` waits for exactly those.
   */
  readonly #owned = new Set<Duplex>();
  #port: number;
  #bound = false;
  #listening: Promise<P9Server> | undefined;
  #closed: Promise<void> | undefined;

  constructor(driver: FsDriver, options: P9ServerOptions) {
    if (options.path !== undefined && (options.port !== undefined || options.host !== undefined)) {
      throw new Error(
        `mountx: a 9P server listens on a unix socket or on a TCP port, not both — ` +
          `\`path\` was given with \`${options.port === undefined ? "host" : "port"}\`.`,
      );
    }
    this.#driver = driver;
    this.options = options;
    this.host = options.host ?? "127.0.0.1";
    this.path = options.path;
    this.#port = options.port ?? 0;
    this.#server = net.createServer({ noDelay: true }, (socket) => this.#accept(socket));
    this.#server.on("error", (error) => this.#report(error, undefined));
  }

  get port(): number {
    return this.#port;
  }

  get clients(): readonly P9Connection[] {
    return [...this.#connections];
  }

  get connections(): number {
    return this.#connections.size;
  }

  address(): net.AddressInfo | string | null {
    return this.#server.address();
  }

  listen(): Promise<P9Server> {
    this.#listening ??= this.#listen();
    return this.#listening;
  }

  close(): Promise<void> {
    this.#closed ??= this.#close();
    return this.#closed;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  attach(stream: Duplex, options: { peer?: string; own?: boolean } = {}): P9Connection {
    if (this.#closed !== undefined) {
      throw new Error("mountx: this 9P server is closed and cannot take another connection.");
    }
    if (this.#streams.has(stream)) {
      throw new Error(
        "mountx: that stream is already attached to this 9P server — a second session on " +
          "the same stream would read every other frame and answer into the same wire.",
      );
    }
    const peer = options.peer ?? peerOf(stream, this.path);
    // A socket is ours to destroy; anything else belongs to whoever composed it.
    const own = options.own ?? typeof (stream as Partial<net.Socket>).destroySoon === "function";
    this.#streams.add(stream);
    if (own) {
      this.#owned.add(stream);
      stream.once("close", () => this.#owned.delete(stream));
    }
    const connection: P9ConnectionImpl = new P9ConnectionImpl({
      options: this.options,
      driver: this.#driver,
      stream,
      peer,
      owned: own,
      report: (error) => this.#report(error, peer),
      gone: () => {
        this.#connections.delete(connection);
        this.#streams.delete(stream);
      },
    });
    this.#connections.add(connection);
    return connection;
  }

  #report(error: unknown, peer: string | undefined): void {
    this.options.onTransportError?.(error, peer);
  }

  async #listen(): Promise<P9Server> {
    if (this.path !== undefined) {
      await this.#checkDirectory(this.path);
    }
    await new Promise<void>((resolve, reject) => {
      const onError = (error: unknown): void => reject(error as Error);
      this.#server.once("error", onError);
      const target =
        this.path === undefined ? { port: this.#port, host: this.host } : { path: this.path };
      this.#server.listen(target, () => {
        this.#server.off("error", onError);
        resolve();
      });
    });
    this.#bound = true;
    const address = this.#server.address();
    if (address !== null && typeof address === "object") {
      this.#port = address.port;
    }
    if (this.path !== undefined) {
      // Between `bind` and here another local user could have connected; the
      // directory check above is what actually closes that window, and this is
      // what keeps the socket unreachable afterwards. See `options.path`.
      await chmod(this.path, this.options.socketMode ?? DEFAULT_SOCKET_MODE);
    }
    return this;
  }

  /**
   * Refuse a socket path whose directory anybody else can reach into.
   *
   * The mode is the whole check — `0700` and ours — because a directory another
   * user cannot search is the only bound that holds from before the socket
   * exists. See {@link P9ServerOptions.path} for what this does and does not
   * promise.
   */
  async #checkDirectory(socketPath: string): Promise<void> {
    if (this.options.allowSharedDirectory === true) {
      return;
    }
    const directory = dirname(resolvePath(socketPath));
    const info = await stat(directory);
    const uid = process.getuid?.();
    const shared = (info.mode & 0o077) !== 0;
    const foreign = uid !== undefined && info.uid !== uid;
    if (shared || foreign) {
      throw new Error(
        `mountx: refusing to put a 9P socket in ${directory} — it is ` +
          `${shared ? `mode 0${(info.mode & 0o777).toString(8)}` : `owned by uid ${info.uid}`}, ` +
          `and 9P authenticates nothing, so any local user who can reach the socket has the ` +
          `whole export. Use a directory you own with mode 0700 (\`mkdir -m 700\`, or a ` +
          `\`mkdtemp\` one), or pass \`allowSharedDirectory: true\` if something else is doing ` +
          `the access control.`,
      );
    }
  }

  #accept(socket: net.Socket): void {
    // Only a TCP listener has an address to judge: a unix peer has none, and it
    // passed the filesystem's check before it ever got here.
    if (this.path === undefined && this.options.allowRemote !== true) {
      const peer = socket.remoteAddress;
      if (!isLoopback(peer)) {
        this.#report(
          new Error(
            `mountx: refused a 9P connection from ${peer ?? "an unknown address"} — ` +
              `this server is loopback-only. Pass \`allowRemote: true\` if something in front ` +
              `of it is doing the access control.`,
          ),
          peer,
        );
        socket.destroy();
        return;
      }
    }
    try {
      this.attach(socket);
      /* v8 ignore next 5 -- `attach` refuses a closed server and a stream it
         already has, neither of which an accepted socket can be; the guard is
         here because this runs inside an event handler, where a throw is an
         uncaught exception rather than a rejected promise. */
    } catch (error) {
      this.#report(error, socket.remoteAddress);
      socket.destroy();
    }
  }

  async #close(): Promise<void> {
    const connections = [...this.#connections];
    const owned = [...this.#owned];
    await new Promise<void>((resolve) => {
      // `net.Server.close()` calls back only once every accepted socket is
      // gone, so everything is dropped in the same turn rather than awaited
      // first — otherwise this would wait for a client that never leaves. A
      // server that was never listening calls back with an error, which is
      // exactly as done as this needs it to be.
      this.#server.close(() => resolve());
      // Sockets first, and by identity rather than through the connections:
      // a session that has already come down leaves its socket behind, and
      // that socket is one of the ones being waited for above.
      for (const stream of owned) {
        stream.destroy();
      }
      for (const connection of connections) {
        void connection.drop();
      }
    });
    await Promise.all(connections.map((connection) => connection.close()));
    this.#connections.clear();
    this.#streams.clear();
    this.#owned.clear();
    if (this.path !== undefined && this.#bound) {
      // Node unlinks a unix socket it bound, but only when the close was clean;
      // this is the leftover case, and it is guarded by `#bound` so a listen
      // that failed with `EADDRINUSE` never deletes somebody else's socket.
      await unlink(this.path).catch(() => {});
    }
  }
}

/**
 * Serve `driver` over 9P2000.L.
 *
 * Returns immediately; nothing is bound until {@link P9Server.listen}, and
 * {@link P9Server.attach} needs no listener at all.
 */
export function createP9Server(driver: FsDriver, options: P9ServerOptions = {}): P9Server {
  return new P9ServerImpl(driver, options);
}
