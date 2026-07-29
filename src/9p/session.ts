/**
 * The 9P2000.L session: one framed message in, one framed message out.
 *
 * The same contract `NfsSession` and `FuseSession` carry, and for the same
 * reasons: {@link P9Session.handleCall} takes bytes and resolves to bytes, it
 * touches **no I/O**, it never rejects, and every thrown driver error becomes
 * an `Rlerror` rather than a dropped reply. The socket is `server.ts`'s job.
 *
 * What 9P makes different, and it is most of the design:
 *
 * - **There is a session, and this is it.** NFSv3 is stateless and FUSE is
 *   owned by the kernel; 9P is neither. The client names a path once, gets a
 *   *fid* for it, reuses that fid, and clunks it when it is done — so the
 *   server's state is the fid table (`fids.ts`) and it lives exactly as long as
 *   the connection. Nothing here survives a `Tversion`, which is the protocol's
 *   own reset.
 * - **Version comes first, always.** `p9_client_version()` is the first thing
 *   the kernel sends and nothing else is legal until it is answered, so every
 *   other request before it is refused with `EPROTO`. Until then there is no
 *   `msize`, and without an `msize` there is no bound on a reply.
 * - **Errors are Linux errnos, unmapped.** `Rlerror` carries a positive errno,
 *   which is exactly what `src/errors.ts` already holds, so this is the one
 *   transport with no status-mapping layer at all: `errnoOf()` is the whole of
 *   it, and an error it does not recognize becomes `EIO`.
 * - **`Tflush` is the only ordering rule in the protocol.** It is answered only
 *   once the request it names has settled — see {@link P9Session.handleCall}.
 *
 * **What `qid.path` costs, and what `useDriverIno` therefore does not buy.**
 * `Rgetattr` has no `st_ino` field: v9fs derives the inode number from
 * `qid.path` (`v9fs_qid2ino()`), so a driver's own `ino` has nowhere to go on
 * this wire and the number userspace sees is always the one `FidTable`
 * allocated. `useDriverIno` still matters — it selects the *identity key* the
 * table memoizes a `qid.path` under, so with it on two hardlinks are one file
 * to the client and with it off they are two — but unlike FUSE and NFS, where
 * the option changes a field on the wire, here it only changes which files
 * share a number. See `fids.ts`'s `qidPathFor`.
 *
 * This step implements version, attach, walk, clunk, getattr, statfs, readdir
 * and flush. Every other message answers `Rlerror ENOTSUP` from one `default`,
 * which is a legal thing for a 9P server to do and is what the legacy 9P2000
 * opcodes will keep answering forever.
 */

import { errnoOf, fsError } from "../errors.ts";
import { createLoopback, type Loopback } from "../harness.ts";
import { PathLock } from "../lock.ts";
import { joinPath } from "../path.ts";
import { S_IFDIR, S_IFMT, type FsDriver, type StatsLike } from "../types.ts";
import {
  P9_GETATTR_BASIC,
  P9_GETATTR_BTIME,
  P9_MIN_MSIZE,
  P9_NOFID,
  P9_RATTACH,
  P9_RCLUNK,
  P9_RFLUSH,
  P9_RGETATTR,
  P9_RLERROR,
  P9_READDIRHDRSZ,
  P9_RREADDIR,
  P9_RSTATFS,
  P9_RVERSION,
  P9_RWALK,
  P9_TATTACH,
  P9_TAUTH,
  P9_TCLUNK,
  P9_TFLUSH,
  P9_TGETATTR,
  P9_TREADDIR,
  P9_TSTATFS,
  P9_TVERSION,
  P9_TWALK,
  P9_VERSION_DOTL,
  P9_VERSION_UNKNOWN,
  V9FS_MAGIC,
  messageName,
} from "./constants.ts";
import { FidTable, walkStep, type Fid } from "./fids.ts";
import {
  P9DirentPacker,
  encodeMessage,
  readFidRequest,
  readHeader,
  readTattach,
  readTauth,
  readTflush,
  readTgetattr,
  readTreaddir,
  readTversion,
  readTwalk,
  writeRattach,
  writeRgetattr,
  writeRlerror,
  writeRreaddir,
  writeRstatfs,
  writeRversion,
  writeRwalk,
  type P9Header,
  type P9Time,
  type Rgetattr,
  type Tattach,
  type Tgetattr,
  type Treaddir,
  type Tversion,
  type Twalk,
} from "./protocol.ts";
import { P9Error, P9Reader, isP9Error, type P9Qid, type P9Writer } from "./wire.ts";

/**
 * The largest `msize` this server agrees to, and the ceiling the negotiated one
 * is clamped against.
 *
 * Deliberately the same number as `P9_DEFAULT_MAX_FRAME`, which is what a frame
 * assembler allows *before* anything has been negotiated: if the ceiling here
 * were the larger of the two, a client could agree an `msize` whose frames the
 * assembler would then refuse to reassemble.
 */
export const DEFAULT_MSIZE = 1024 * 1024;

/** Bytes in one path component, and the `namelen` every `Rstatfs` reports. */
const NAME_MAX = 255;

/**
 * `n_uname` when the client has no numeric uid to offer.
 *
 * `p9_client_attach()` sends `from_kuid(&init_user_ns, n_uname)`, and an
 * `INVALID_UID` comes out of that as `(uid_t)-1` — which is what a mount in
 * `access=<uname>` mode sends. It is a sentinel, never a uid.
 */
const NO_NUNAME = 0xff_ff_ff_ff;

/**
 * The `DT_*` byte for a mode.
 *
 * POSIX's own relation, `(st_mode & S_IFMT) >> 12`, which is what
 * `src/fuse/protocol.ts`'s `direntType()` computes as well. Written out rather
 * than imported so `src/9p/` does not pull the FUSE codec in behind one
 * arithmetic expression, and derived rather than transcribed so there is no
 * second copy of the `DT_*` table to drift.
 */
function direntType(mode: number): number {
  return (mode & S_IFMT) >> 12;
}

function toUnsigned(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.trunc(value)) >>> 0 : 0;
}

function toBigUint(value: number): bigint {
  return Number.isFinite(value) ? BigInt(Math.max(0, Math.trunc(value))) : 0n;
}

/** Milliseconds since the epoch as 9P's `sec[8] nsec[8]` pair. */
function splitMs(ms: number): P9Time {
  if (!Number.isFinite(ms) || ms <= 0) {
    return { sec: 0n, nsec: 0n };
  }
  const sec = Math.floor(ms / 1000);
  const nsec = Math.min(999_999_999, Math.max(0, Math.round((ms - sec * 1000) * 1e6)));
  return { sec: BigInt(sec), nsec: BigInt(nsec) };
}

/**
 * Who a fid belongs to, as far as `Tattach` said.
 *
 * v9fs's default `access=user` sends one `Tattach` per user that touches the
 * mount, and every fid walked from it inherits the attach — so this is the
 * 9P spelling of the `AUTH_SYS` credentials `NfsSession` reads off each call.
 * Nothing in this step acts on it; it is recorded because the ownership claim
 * that needs it (`#claim` in the other two sessions: `lchown` a freshly created
 * file to whoever asked for it) belongs with `Tlcreate`/`Tmkdir`, in step 5,
 * and by then the attach it came from is long gone.
 */
export interface P9User {
  /** `uname` — a name, and empty whenever `uid` is set. */
  uname: string;
  /** `n_uname`, or `undefined` when the client sent the `(uid_t)-1` sentinel. */
  uid: number | undefined;
  /** The `aname` this fid's tree was attached with. */
  aname: string;
}

export interface P9SessionOptions {
  /**
   * Identify files by the driver's `(dev, ino)`, so hardlinks share a
   * `qid.path`. Default `true`.
   *
   * Read the module docs before reaching for this: on 9P it does *not* change
   * the inode number userspace sees, because `Rgetattr` has no field for one.
   */
  useDriverIno?: boolean;
  /**
   * Ceiling on the negotiated `msize`. Default {@link DEFAULT_MSIZE}.
   *
   * The negotiated value is `min(client's proposal, this)`, never more than the
   * client asked for, and a result under {@link P9_MIN_MSIZE} fails the
   * negotiation outright.
   */
  msize?: number;
  /**
   * Refuse every mutating request with `EROFS`. Default `false`.
   *
   * Nothing in this step mutates anything — version, attach, walk, clunk,
   * getattr, statfs, readdir and flush are all readers — so it is recorded and
   * has nothing yet to refuse. Step 5 brings the messages it applies to.
   */
  readOnly?: boolean;
  /**
   * `chown` a newly created entry to the attaching user. Default `true`.
   *
   * Recorded for the same reason {@link P9User} is: the creating messages
   * arrive in step 5, and the option has to exist before them so the attach
   * that answers "which user?" is being kept from the start.
   */
  claimOwnership?: boolean;
  /** Run the reply-exactly-once assertions. Default on outside production. */
  debug?: boolean;
  /** Called when a dev-mode assertion fails. Default: collect in `assertions`. */
  onAssertion?: (message: string) => void;
  /** Called for every request answered with an `Rlerror`, and every dropped frame. */
  onError?: (error: unknown, header: P9Header | undefined) => void;
}

/** Counters, all cheap, all useful in a test. */
export interface P9SessionStats {
  /** Frames handed to {@link P9Session.handleCall}. */
  requests: number;
  /** Replies produced (successful or not). */
  replies: number;
  /** Of which `Rlerror`. */
  errors: number;
  /** Frames too damaged to address a reply to. */
  dropped: number;
  /** `Tflush` messages that found their `oldtag` in flight and waited for it. */
  flushed: number;
  /** Dev-mode assertion failures. Must be zero. */
  assertions: number;
  /** Per-message counts, keyed by protocol name (`"Twalk"`). */
  messages: Map<string, number>;
}

/**
 * A 9P2000.L server over a driver, with no socket.
 *
 * ```ts
 * const session = new P9Session(createMemoryDriver());
 * const reply = await session.handleCall(frameBytes); // Uint8Array | null
 * ```
 */
export class P9Session {
  /** The driver, wrapped so paths are normalized and gaps answer `ENOSYS`. */
  readonly driver: Loopback;
  readonly options: P9SessionOptions;
  /**
   * fid → path and open state, for the life of this connection.
   *
   * Snapshots a directory as its **names**, dots included: a `Treaddir` has to
   * stat every entry it packs anyway (a packed dirent carries a qid, and a qid
   * needs the file's identity and mtime), so keeping the driver's `Dirent`
   * objects alive for the whole paging run would buy nothing and cost a
   * directory's worth of them.
   */
  readonly fids: FidTable<string>;
  readonly stats: P9SessionStats = {
    requests: 0,
    replies: 0,
    errors: 0,
    dropped: 0,
    flushed: 0,
    assertions: 0,
    messages: new Map(),
  };
  /** Dev-mode assertion failures, in order. Empty in a healthy session. */
  readonly assertions: string[] = [];

  readonly #users = new Map<number, P9User>();
  /** tag → the reply being produced for it; what `Tflush` waits on. */
  readonly #inflight = new Map<number, Promise<Uint8Array>>();
  readonly #lock = new PathLock();
  readonly #debug: boolean;
  /** The negotiated `msize`; `0` until `Tversion`, and again after a reset. */
  #msize = 0;
  /**
   * Bumped by every {@link P9Session.destroy} and every `Tversion` reset.
   *
   * A request that crosses one has been overtaken by the protocol's own
   * "aborts all outstanding I/O": the fids it resolved are clunked, the `msize`
   * it was going to answer within is gone, and the reply it built describes a
   * session that no longer exists. `#run` snapshots this before dispatching and
   * refuses to hand back a reply from an older one — see {@link #stale}.
   */
  #generation = 0;
  #destroyed = false;

  constructor(driver: FsDriver, options: P9SessionOptions = {}) {
    this.driver = createLoopback(driver);
    this.options = options;
    this.fids = new FidTable<string>({ useDriverIno: options.useDriverIno });
    this.#debug = options.debug ?? process.env.NODE_ENV !== "production";
  }

  /**
   * The negotiated `msize`, or `undefined` before a successful `Tversion`.
   *
   * The transport reads this to lower its frame assembler's limit onto the
   * value the two ends just agreed, which is the only bound a 9P stream has.
   */
  get msize(): number | undefined {
    return this.#msize === 0 ? undefined : this.#msize;
  }

  /** The dialect in force, or `undefined` before a successful `Tversion`. */
  get version(): string | undefined {
    return this.#msize === 0 ? undefined : P9_VERSION_DOTL;
  }

  /**
   * How many times the session has been reset, by `Tversion` or by teardown.
   *
   * Only interesting to a test; the session itself uses it to tell a reply that
   * is still wanted from one that has been overtaken.
   */
  get generation(): number {
    return this.#generation;
  }

  /** Requests still being answered. `Tflush` is never among them. */
  get inflight(): number {
    return this.#inflight.size;
  }

  get destroyed(): boolean {
    return this.#destroyed;
  }

  /** The user a fid was attached as, or `undefined` for a fid we do not have. */
  userFor(fid: number): P9User | undefined {
    return this.#users.get(fid);
  }

  // -------------------------------------------------------------------------
  // lifecycle
  // -------------------------------------------------------------------------

  /**
   * Answer one complete frame.
   *
   * Resolves to the encoded reply, or `null` for a frame that cannot be
   * answered at all — one too short to hold a header, or one whose `size` field
   * disagrees with the bytes delivered. Both mean there is no tag worth
   * addressing a reply to: the second is the first symptom of a desynchronized
   * stream, and putting a reply on a stream whose framing is already wrong just
   * moves the confusion. **Never rejects.**
   *
   * `bytes` is decoded — and everything retained from it copied — before the
   * first `await`, so the caller may re-arm the buffer as soon as this returns.
   *
   * **Tags.** One reply per tag, exactly, and a tag that is already in flight is
   * a protocol error: the kernel allocates tags from its own IDR and frees one
   * only when its reply arrives, so a duplicate is a broken client or a
   * desynchronized stream. It is answered `EPROTO` rather than dropped, because
   * a client that has lost track of its tags is better served by an error than
   * by silence.
   *
   * **`Tflush`.** The reply is sent only once the request named by `oldtag` has
   * settled, because the client frees `oldtag` the moment `Rflush` arrives and
   * a reply landing after that would be addressed to a tag that has been reused.
   * The flushed request still runs to completion and still gets its own reply
   * first — the simplest compliant behavior, and one `p9_client_flush()`
   * expects (it leaves `oldtag` valid until `Rflush` comes back). An `oldtag`
   * that is not in flight is answered immediately. A `Tflush` is itself never
   * registered as in-flight, which is what makes a flush-of-a-flush impossible
   * to deadlock on: there is no cycle to wait around.
   */
  async handleCall(bytes: Uint8Array): Promise<Uint8Array | null> {
    this.stats.requests++;
    let header: P9Header;
    let body: P9Reader;
    try {
      const reader = new P9Reader(bytes);
      header = readHeader(reader);
      if (header.size !== bytes.byteLength) {
        throw new P9Error(
          `${messageName(header.type)} says ${header.size} bytes but the frame is ${bytes.byteLength}`,
        );
      }
      body = reader;
    } catch (error) {
      this.stats.dropped++;
      this.#report(error, undefined);
      return null;
    }
    const name = messageName(header.type);
    this.stats.messages.set(name, (this.stats.messages.get(name) ?? 0) + 1);

    if (header.type === P9_TFLUSH) {
      // Never registered, and so never duplicate-checked either: a `Tflush` that
      // could be found in the map would be a `Tflush` another one could wait on,
      // and two of those waiting on each other is a deadlock with no cycle to
      // break. Nothing is lost — a flush holds no fid and resolves no path.
      return this.#run(header, body);
    }
    if (this.#inflight.has(header.tag)) {
      this.#assert(`tag ${header.tag} is already in flight (${name})`);
      return this.#error(
        header,
        fsError("EPROTO", { message: `EPROTO: tag ${header.tag} is already in flight` }),
      );
    }
    // `#run` decodes the body in its synchronous prologue and only then awaits,
    // so the registration below happens before anything can observe the tag —
    // and before the frame is touched again.
    const pending = this.#run(header, body);
    this.#inflight.set(header.tag, pending);
    try {
      return await pending;
    } finally {
      this.#inflight.delete(header.tag);
    }
  }

  /**
   * Tear the session down: close every open handle and drop every fid.
   *
   * **The transport must call this itself.** 9P has no `Tdestroy` and no
   * analogue of `FUSE_DESTROY` — a connection ends when the socket does — so
   * teardown belongs to whoever notices the stream hit EOF. Idempotent, and
   * safe with requests in flight.
   */
  async destroy(): Promise<void> {
    this.#destroyed = true;
    await this.#reset();
  }

  /**
   * Drop every fid, closing whatever they had open.
   *
   * Both `Tversion` and {@link destroy} land here: the protocol says a version
   * exchange "aborts all outstanding I/O and clunks all fids", so a re-version
   * is a teardown that happens to be followed by more traffic.
   */
  async #reset(): Promise<void> {
    this.#generation++;
    const open = this.fids.openHandles();
    this.fids.clear();
    this.#users.clear();
    this.#msize = 0;
    for (const { handle } of open) {
      try {
        await handle.close();
      } catch (error) {
        this.#report(error, undefined);
      }
    }
  }

  // -------------------------------------------------------------------------
  // dispatch
  // -------------------------------------------------------------------------

  /**
   * Answer one message, turning anything thrown into an `Rlerror`.
   *
   * The generation snapshot is the second half of the `#destroyed` gate in
   * {@link #dispatch}: that one catches a request that *arrives* after a
   * teardown, this one catches a request that was already parked in a driver
   * when the teardown happened. Without it a `Treaddir` sitting in `readdir()`
   * across a `Tversion` would come back describing fids the reset had already
   * clunked, and — before the budget was captured up front — sized against an
   * `msize` that no longer existed.
   */
  async #run(header: P9Header, body: P9Reader): Promise<Uint8Array> {
    // `Tversion` is exempt, because it *is* the reset: its own bump is not
    // something that overtook it. Two concurrent ones cannot slip past that,
    // since both carry `P9_NOTAG` and the duplicate-tag check above refuses the
    // second.
    const overtakeable = header.type !== P9_TVERSION;
    const generation = this.#generation;
    let reply: Uint8Array;
    try {
      reply = await this.#dispatch(header, body);
      if (overtakeable && generation !== this.#generation) {
        throw this.#stale(header);
      }
    } catch (error) {
      return this.#error(header, error);
    }
    this.stats.replies++;
    return reply;
  }

  /**
   * The error for a reply the session moved on from while it was being built.
   *
   * `ENODEV` once {@link P9Session.destroy} has run, which is the answer the
   * FUSE session gives for the same situation — the connection this reply was
   * for is gone. `EIO` for a live session that merely re-versioned: the request
   * really was aborted, which is what the version exchange is defined to do,
   * and `EIO` is what an aborted I/O reports. Either way the client has been
   * told to start over, so neither is a surprise to it.
   */
  #stale(header: P9Header): Error {
    const what = messageName(header.type);
    return this.#destroyed
      ? fsError("ENODEV", { message: `ENODEV: ${what} outlived the session` })
      : fsError("EIO", { message: `EIO: ${what} was aborted by a Tversion reset` });
  }

  /**
   * Decode one body, insisting nothing is left over.
   *
   * A body we cannot parse is answered `EINVAL` rather than the `EIO` that a
   * `P9Error` would otherwise fall through `errnoOf` into: it is a malformed
   * request, not a failed one, and the FUSE session says the same thing the
   * same way. Trailing bytes count as malformed for the reason `decodeMessage`
   * refuses a mismatched `size` — a message with something after it is one we
   * have misread, and reading past it desynchronizes everything behind it.
   */
  #decode<T>(header: P9Header, body: P9Reader, read: (reader: P9Reader) => T): T {
    const what = messageName(header.type);
    try {
      const value = read(body);
      body.end(what);
      return value;
    } catch (error) {
      if (isP9Error(error)) {
        throw fsError("EINVAL", {
          message: `EINVAL: undecodable ${what}: ${error.message}`,
          cause: error,
        });
      }
      /* v8 ignore next 2 -- the codecs throw nothing else; this is the rethrow
         that keeps a surprise from being reported as a malformed request. */
      throw error;
    }
  }

  /**
   * Decode a body and hand it to its handler.
   *
   * Every case decodes **before** it awaits anything, so nothing that outlives
   * the call is a view of the caller's buffer: the handlers below take decoded
   * structs and never see a reader.
   */
  async #dispatch(header: P9Header, body: P9Reader): Promise<Uint8Array> {
    if (this.#destroyed) {
      throw fsError("ENODEV", { message: "ENODEV: the 9P session has been torn down" });
    }
    if (header.type !== P9_TVERSION && this.#msize === 0) {
      throw fsError("EPROTO", {
        message: `EPROTO: ${messageName(header.type)} before Tversion`,
      });
    }
    switch (header.type) {
      case P9_TVERSION: {
        return this.#version(header, this.#decode(header, body, readTversion));
      }
      case P9_TFLUSH: {
        return this.#flush(header, this.#decode(header, body, readTflush).oldtag);
      }
      case P9_TAUTH: {
        // Decoded only so it can be refused precisely: the v6.12 client has no
        // `p9_client_auth()` and always attaches with `afid = P9_NOFID`, so
        // nothing that speaks to this server will ever send one.
        this.#decode(header, body, readTauth);
        throw fsError("ENOTSUP", { message: "ENOTSUP: this server has no authentication file" });
      }
      case P9_TATTACH: {
        const request = this.#decode(header, body, readTattach);
        return this.#read(() => this.#attach(header, request));
      }
      case P9_TWALK: {
        const request = this.#decode(header, body, readTwalk);
        return this.#read(() => this.#walk(header, request));
      }
      case P9_TCLUNK: {
        return this.#clunk(header, this.#decode(header, body, readFidRequest).fid);
      }
      case P9_TGETATTR: {
        const request = this.#decode(header, body, readTgetattr);
        return this.#read(() => this.#getattr(header, request));
      }
      case P9_TSTATFS: {
        const fid = this.#decode(header, body, readFidRequest).fid;
        return this.#read(() => this.#statfs(header, fid));
      }
      case P9_TREADDIR: {
        const request = this.#decode(header, body, readTreaddir);
        // The budget is fixed *here*, in the synchronous prologue, and not in
        // the handler: `msize` is session state that a reset can take away
        // while the driver is still listing the directory, and a budget read
        // afterwards would be sized against a session that no longer exists.
        const budget = Math.min(request.count >>> 0, Math.max(0, this.#msize - P9_READDIRHDRSZ));
        return this.#read(() => this.#readdir(header, request, budget));
      }
      default: {
        // Every message this step does not implement, the four legacy 9P2000
        // ones it never will, and anything that is not a message at all. Step 5
        // replaces the first group; the rest keep this answer.
        throw fsError("ENOTSUP", {
          message: `ENOTSUP: ${messageName(header.type)} is not supported`,
        });
      }
    }
  }

  /**
   * Run a handler as a reader.
   *
   * There is no writer yet — every message in this step resolves paths and
   * mutates nothing — so the lock is uncontended by construction. It is here
   * rather than in step 5 because the *readers* are what a writer has to be
   * serialized against, and adding them retroactively is how one gets missed.
   * `Tclunk` stays outside it: it resolves no path, and the driver `close()` it
   * may do is exactly the kind of unbounded wait the lock's own docs say to
   * keep out.
   */
  #read(fn: () => Promise<Uint8Array>): Promise<Uint8Array> {
    return this.#lock.read(fn);
  }

  /**
   * Frame a reply for this message's tag.
   *
   * Deliberately does *not* count it: a reply is counted when it is handed back
   * (`#run`, `#error`), not when it is encoded, because a reply built by a
   * request that a reset overtook is thrown away — see {@link #stale}.
   */
  #framed(
    header: P9Header,
    type: number,
    write?: (writer: P9Writer) => void,
    capacity?: number,
  ): Uint8Array {
    return encodeMessage(type, header.tag, write, capacity);
  }

  /**
   * Turn any thrown value into an `Rlerror`.
   *
   * The last line of defence, and the one encode in this session that cannot
   * fail: `errnoOf` is total — anything it does not recognize is `EIO` — and an
   * `Rlerror` is an eleven-byte frame with a single masked `u32` in it, so
   * there is no overflow and no allocation to go wrong. That is why there is no
   * fallback here; a guard around something that cannot throw is a guard nobody
   * can ever check.
   */
  #error(header: P9Header, error: unknown): Uint8Array {
    this.stats.replies++;
    this.stats.errors++;
    this.#report(error, header);
    return this.#framed(header, P9_RLERROR, (writer) =>
      writeRlerror(writer, { ecode: errnoOf(error) }),
    );
  }

  /** Hand an error to whoever is listening. A logger never costs a reply. */
  #report(error: unknown, header: P9Header | undefined): void {
    try {
      this.options.onError?.(error, header);
    } catch {
      // Deliberately swallowed; see above.
    }
  }

  #assert(message: string): void {
    if (!this.#debug) {
      return;
    }
    this.stats.assertions++;
    this.assertions.push(message);
    this.options.onAssertion?.(message);
  }

  // -------------------------------------------------------------------------
  // version
  // -------------------------------------------------------------------------

  /**
   * `Tversion` — agree a dialect and an `msize`, and reset everything else.
   *
   * The reset is unconditional and comes first, because the protocol's own
   * words are that a version exchange "aborts all outstanding I/O and clunks
   * all fids"; a client that re-versions is starting over whether or not the
   * new proposal is one this server can meet.
   *
   * There are two ways to say no and they are the same way: an unrecognized
   * dialect and an `msize` too small to carry a message both answer `Rversion`
   * with `"unknown"` and leave the session unnegotiated. Neither answers
   * `Rlerror` — `Tversion` is the one request whose failure the protocol spells
   * out as a normal reply, and the client that reads it (`p9_client_version()`)
   * would report the same failed mount either way. The `msize` field still
   * carries the clamped value, so the number is visible even when the string is
   * the refusal.
   */
  async #version(header: P9Header, request: Tversion): Promise<Uint8Array> {
    await this.#reset();
    const ceiling = Math.trunc(this.options.msize ?? DEFAULT_MSIZE);
    const msize = Math.min(request.msize >>> 0, ceiling);
    const agreed = request.version === P9_VERSION_DOTL && msize >= P9_MIN_MSIZE;
    if (agreed) {
      this.#msize = msize;
    }
    return this.#framed(header, P9_RVERSION, (writer) =>
      writeRversion(writer, {
        msize,
        version: agreed ? P9_VERSION_DOTL : P9_VERSION_UNKNOWN,
      }),
    );
  }

  // -------------------------------------------------------------------------
  // attach and the fid lifecycle
  // -------------------------------------------------------------------------

  /**
   * `Tattach` — bind `fid` to the root of the tree `aname` names.
   *
   * `aname` is empty or `/` for the whole export, which is what a mount with no
   * `aname=` option sends; anything else names a **subtree**, and is attached
   * there if it exists and is a directory. That is what the option is for, it
   * costs one `lstat`, and `src/path.ts` clamps `..` so no `aname` can name
   * anything outside the driver's root.
   *
   * `afid` must be {@link P9_NOFID}. Anything else says the client believes it
   * authenticated, and since `Tauth` is refused with `ENOTSUP` the only honest
   * answer to the fid it would have produced is the same one.
   */
  async #attach(header: P9Header, request: Tattach): Promise<Uint8Array> {
    if (request.afid !== P9_NOFID) {
      throw fsError("ENOTSUP", {
        message: `ENOTSUP: afid ${request.afid} names an auth file, and this server has none`,
      });
    }
    const path = joinPath("/", request.aname);
    const stats = await this.#statOf(path);
    if ((stats.mode & S_IFMT) !== S_IFDIR) {
      throw fsError("ENOTDIR", { syscall: "attach", path });
    }
    // Stat first, create second: a failed attach must leave no fid behind, and
    // `create` is the one step here that cannot fail after the driver has
    // spoken (it refuses a fid already in use, which is the client's bug).
    const entry = this.fids.create(request.fid, path);
    this.#users.set(entry.fid, {
      uname: request.uname,
      uid: request.nUname === NO_NUNAME ? undefined : request.nUname,
      aname: request.aname,
    });
    const qid = this.fids.qidFor(stats, path);
    return this.#framed(header, P9_RATTACH, (writer) => writeRattach(writer, { qid }));
  }

  /**
   * `Twalk` — descend from `fid` through the names, binding `newfid` to where
   * it lands.
   *
   * The partial-walk rule is the whole message. A walk that resolves every name
   * installs `newfid` and answers one qid per name. A walk that fails on its
   * **first** name answers `Rlerror`. A walk that fails on any later name
   * answers `Rwalk` with the qids it did gather, installs nothing, and leaves
   * `fid` untouched — which is how the client learns exactly how far it got and
   * why `newfid` is only bound once the last name has resolved.
   *
   * `P9_MAXWELEM` is a protocol limit rather than a policy: the client
   * splits a longer path into consecutive walks itself, each one an ordinary
   * independent request starting from the fid the last one produced — so a
   * sixteen-name walk followed by another is not a special case, it is what a
   * deep path looks like. Nothing enforces the limit here because `readTwalk`
   * already refuses a longer count, which makes an over-long `Twalk` a
   * malformed request (`EINVAL`) rather than a failed one.
   *
   * Walking from an **open** fid is refused. 9P forbids it outright — an open
   * fid names a file being read or written, not a place to walk from — and the
   * fid table deliberately leaves the enforcement here, where the open state is
   * interpreted.
   */
  async #walk(header: P9Header, request: Twalk): Promise<Uint8Array> {
    const source = this.fids.require(request.fid);
    if (source.open !== undefined) {
      throw fsError("EINVAL", {
        message: `EINVAL: fid ${request.fid} is open, and an open fid cannot be walked`,
      });
    }
    // Checked up front as well as by `clone` below, so that a walk which is
    // *both* short and aimed at a live fid reports the client's real mistake
    // rather than a partial result it would then misread.
    if (request.newfid !== request.fid && this.fids.get(request.newfid) !== undefined) {
      throw fsError("EINVAL", { message: `EINVAL: fid ${request.newfid} is already in use` });
    }

    const wqids: P9Qid[] = [];
    let path = source.path;
    for (const [index, name] of request.wnames.entries()) {
      let next: string;
      let stats: StatsLike;
      try {
        next = walkStep(path, name);
        stats = await this.#statOf(next);
      } catch (error) {
        if (index === 0) {
          throw error;
        }
        break;
      }
      wqids.push(this.fids.qidFor(stats, next));
      path = next;
    }

    if (wqids.length === request.wnames.length) {
      // `clone` is a no-op for the in-place walk (`newfid == fid`), and the
      // path assignment below is what moves either one — after every name has
      // resolved, never during.
      const target = this.fids.clone(request.fid, request.newfid);
      target.path = path;
      const user = this.#users.get(request.fid);
      if (user !== undefined) {
        this.#users.set(request.newfid, user);
      }
    }
    return this.#framed(
      header,
      P9_RWALK,
      (writer) => writeRwalk(writer, { wqids }),
      16 + wqids.length * 13,
    );
  }

  /**
   * `Tclunk` — forget the fid and close whatever it had open.
   *
   * Answered `Rclunk` even when the driver's `close()` fails, because the fid is
   * gone either way and the client will not send another: `p9_client_clunk()`
   * destroys its side "even after a failed clunk". Reporting the failure as an
   * `Rlerror` would leave the two ends disagreeing about whether the fid still
   * exists, so it goes to `onError` instead.
   */
  async #clunk(header: P9Header, fid: number): Promise<Uint8Array> {
    const entry = this.fids.clunk(fid);
    this.#users.delete(fid);
    const handle = entry.open?.handle;
    entry.open = undefined;
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch (error) {
        this.#report(error, header);
      }
    }
    return this.#framed(header, P9_RCLUNK);
  }

  // -------------------------------------------------------------------------
  // attributes
  // -------------------------------------------------------------------------

  /**
   * `lstat`, falling back to `stat` for drivers that have no `lstat`.
   *
   * A fid names a file, and a file can be a symlink — the attributes owed are
   * the link's own, never its target's.
   */
  async #statOf(path: string): Promise<StatsLike> {
    try {
      return await this.driver.lstat(path);
    } catch (error) {
      if ((error as { code?: string }).code === "ENOSYS") {
        return this.driver.stat(path);
      }
      throw error;
    }
  }

  /**
   * `Tgetattr` — `stat(2)` for a fid, filtered through the client's mask.
   *
   * `valid` is what was actually filled, which is the request mask intersected
   * with what a `StatsLike` can answer: everything in `P9_GETATTR_BASIC`, plus
   * `BTIME` when the driver reported a birth time to put in it. `GEN` and
   * `DATA_VERSION` are never claimed — the fields go out as zero, and a client
   * that reads them without checking `valid` is reading a field this server
   * says it did not set.
   *
   * There is no `st_ino` on this wire; see the module docs. The mask bit named
   * `INO` describes the qid, which is always filled.
   */
  async #getattr(header: P9Header, request: Tgetattr): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    const stats = await this.#statOf(entry.path);
    const attr = this.#attrOf(this.fids.qidFor(stats, entry.path), stats, request.requestMask);
    return this.#framed(header, P9_RGETATTR, (writer) => writeRgetattr(writer, attr), 192);
  }

  #attrOf(qid: P9Qid, stats: StatsLike, requestMask: bigint): Rgetattr {
    // The bit and the fields are decided by the same test, on the driver's own
    // number rather than on the seconds it splits into: a birth time inside the
    // first second of the epoch is still a birth time, and claiming `BTIME` for
    // a zeroed pair — or zeroing a pair we then claim — would be a reply that
    // disagrees with itself.
    const born = Number.isFinite(stats.birthtimeMs) && stats.birthtimeMs > 0;
    const btime = born ? splitMs(stats.birthtimeMs) : { sec: 0n, nsec: 0n };
    const served = P9_GETATTR_BASIC | (born ? P9_GETATTR_BTIME : 0n);
    return {
      valid: requestMask & served,
      qid,
      mode: toUnsigned(stats.mode),
      uid: toUnsigned(stats.uid),
      gid: toUnsigned(stats.gid),
      // Verbatim, zero included: `nlink == 0` is how a filesystem says an inode
      // has no names left and is alive only because something holds it open.
      nlink: toBigUint(stats.nlink),
      rdev: toBigUint(stats.rdev),
      size: toBigUint(stats.size),
      blksize: toBigUint(stats.blksize),
      blocks: toBigUint(stats.blocks),
      atime: splitMs(stats.atimeMs),
      mtime: splitMs(stats.mtimeMs),
      ctime: splitMs(stats.ctimeMs),
      btime,
      gen: 0n,
      dataVersion: 0n,
    };
  }

  /**
   * `Tstatfs` — `statvfs(3)` for the filesystem behind a fid.
   *
   * Refused with `ENOSYS` unless the driver declares `statfs`, rather than
   * inventing plausible numbers: a capability is declared or inferred, never
   * faked, and `df` reporting a filesystem size nobody chose is worse than `df`
   * reporting that it cannot tell.
   *
   * Two fields are the server's rather than the driver's. `type` is the driver's
   * own magic number when it has one, and {@link V9FS_MAGIC} when it does not —
   * `v9fs_statfs()` copies it into `f_type` verbatim, so a zero would leave
   * userspace unable to name the filesystem at all. `fsid` is `0`: there is
   * exactly one filesystem per session and nothing stable to identify it with,
   * and a number invented per connection would look meaningful while colliding
   * as readily as zero does.
   */
  async #statfs(header: P9Header, fid: number): Promise<Uint8Array> {
    const entry = this.fids.require(fid);
    if (!this.driver.capabilities.statfs) {
      throw fsError("ENOSYS", { syscall: "statfs", path: entry.path });
    }
    const stats = await this.driver.statfs(entry.path);
    return this.#framed(
      header,
      P9_RSTATFS,
      (writer) =>
        writeRstatfs(writer, {
          type: toUnsigned(stats.type) || V9FS_MAGIC,
          bsize: Math.max(1, toUnsigned(stats.bsize) || 4096),
          blocks: toBigUint(stats.blocks),
          bfree: toBigUint(stats.bfree),
          bavail: toBigUint(stats.bavail),
          files: toBigUint(stats.files),
          ffree: toBigUint(stats.ffree),
          fsid: 0n,
          namelen: NAME_MAX,
        }),
      80,
    );
  }

  // -------------------------------------------------------------------------
  // readdir
  // -------------------------------------------------------------------------

  /**
   * The listing a `Treaddir` run pages over: `.`, `..`, then the driver's names.
   *
   * **The dots are the server's job.** `v9fs_dir_readdir_dotl()` (v6.12) never
   * calls `dir_emit_dots()` — it emits exactly what the server packed — so a
   * directory served without them has no `.` and no `..`, and `cd ..` inside
   * the mount stops working. diod supplies them because it is reading a real
   * directory with `readdir(3)`, which includes them; we synthesize them, and
   * `..` resolves through `src/path.ts`, so at the root it is the root.
   */
  async #list(path: string): Promise<string[]> {
    // `withFileTypes: true` is the driver interface's only `readdir` mode — see
    // `ReaddirOptions` — so the `Dirent`s arrive whether or not they are wanted,
    // and they are not: a packed dirent carries a qid, a qid needs the file's
    // identity and mtime, and the `lstat` that answers those answers the type
    // byte too. Only the names are kept, so a big directory costs strings.
    const entries = await this.driver.readdir(path, { withFileTypes: true });
    return [".", "..", ...entries.map((entry) => entry.name)];
  }

  /**
   * The open state a `Treaddir` needs.
   *
   * 9P requires a fid to have been opened before it can be read, and this is
   * where that check belongs. **Step 5 completes it**: `Tlopen` does not exist
   * yet, so there is no way for a client to open anything, and refusing every
   * unopened fid here would leave `Treaddir` unreachable and untested for a
   * whole step. Until then an unopened fid naming a directory is read, and the
   * driver's own `ENOTDIR` covers a fid naming something else.
   *
   * What is already exact is the half that will survive: a fid opened as a
   * *file* is refused here and now, because `Tread` — not `Treaddir` — is what
   * that fid is for, and that refusal does not depend on `Tlopen` existing.
   */
  #requireDirectory(entry: Fid<string>): void {
    if (entry.open !== undefined && !entry.open.directory) {
      throw fsError("ENOTDIR", {
        message: `ENOTDIR: fid ${entry.fid} was opened as a file`,
        path: entry.path,
      });
    }
  }

  /**
   * `Treaddir` — one page of a directory.
   *
   * The offsets are cookies this server mints, one-based so that `0` keeps its
   * protocol meaning of "start over": an entry carries the offset that resumes
   * *after* it, and the fid table records each one as it is packed.
   *
   * What that buys, exactly: an offset **this fid has not been shown since its
   * last snapshot** is `EINVAL`, rather than a guess that would silently skip
   * or repeat files. What it does not buy is detecting a *rewind*. The cookies
   * are indices, so a re-listing mints the same numbers again, and an offset
   * from before an `offset == 0` is accepted whenever the new listing is at
   * least as long — it names the same position in a directory that has since
   * changed under it. That is the ordinary readdir race every path-based server
   * has and no cookie scheme without a per-snapshot nonce can close; what is
   * enforced is the bound, and a stale offset past the end of the new listing
   * is refused like any other offset the fid was never given.
   *
   * Every packed entry costs an `lstat`, because a packed dirent carries a qid
   * and a qid is the file's identity and mtime. An entry that has vanished
   * between the snapshot and now is skipped rather than failing the page — it
   * is gone, and the client is about to be told so by everything else.
   *
   * The byte budget is the client's `count`, clamped to what the negotiated
   * `msize` can carry, and computed by the caller before the first `await`; a
   * `count` too small for even one entry is `EINVAL`, because an empty reply is
   * how this message spells end-of-directory and answering one would truncate
   * the listing instead of paging it.
   */
  async #readdir(header: P9Header, request: Treaddir, budget: number): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    this.#requireDirectory(entry);
    const dir = entry.path;
    let page = this.fids.resume(entry, request.offset);
    if (page === undefined) {
      page = this.fids.snapshot(entry, await this.#list(dir));
    }

    const packer = new P9DirentPacker(budget);
    let index = page.index;
    for (; index < page.entries.length; index++) {
      const name = page.entries[index]!;
      const child = joinPath(dir, name);
      let stats: StatsLike;
      try {
        stats = await this.#statOf(child);
      } catch {
        continue;
      }
      const offset = BigInt(index + 1);
      let packed: boolean;
      try {
        packed = packer.add({
          qid: this.fids.qidFor(stats, child),
          offset,
          type: direntType(stats.mode),
          name,
        });
      } catch (error) {
        // The packer refuses a name a 16-bit count cannot describe, and it
        // refuses it by throwing rather than by answering "does not fit": no
        // reply will ever hold it, so paging past it would drop the file from
        // the directory silently and forever.
        throw isP9Error(error)
          ? fsError("ENAMETOOLONG", { syscall: "readdir", path: child, cause: error })
          : error;
      }
      if (!packed) {
        break;
      }
      this.fids.noteOffset(entry, offset, index + 1);
    }
    if (packer.count === 0 && index < page.entries.length) {
      throw fsError("EINVAL", {
        message: `EINVAL: count ${request.count} has no room for a single entry`,
        path: dir,
      });
    }
    return this.#framed(
      header,
      P9_RREADDIR,
      (writer) => writeRreaddir(writer, { data: packer.bytes() }),
      packer.size + 16,
    );
  }

  // -------------------------------------------------------------------------
  // flush
  // -------------------------------------------------------------------------

  /** `Tflush` — answered once `oldtag` has settled. See {@link handleCall}. */
  async #flush(header: P9Header, oldtag: number): Promise<Uint8Array> {
    const pending = this.#inflight.get(oldtag);
    if (pending !== undefined) {
      this.stats.flushed++;
      // `allSettled` rather than a bare `await`: the reply being waited on is
      // not this request's, so a failure in it must not become this one's.
      await Promise.allSettled([pending]);
    }
    return this.#framed(header, P9_RFLUSH);
  }
}
