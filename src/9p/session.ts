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
 * Every 9P2000.L message is answered here. What is left in the `default` is the
 * four legacy 9P2000 opcodes the .L dialect replaced (`Topen`, `Tcreate`,
 * `Tstat`, `Twstat`), `Tlerror`/`Terror`, which are never sent in either
 * dialect, and anything that is not a message at all: `Rlerror ENOTSUP`, which
 * is a legal thing for a 9P server to say and what those will keep hearing.
 *
 * **The two `open(2)` namespaces cross here too.** `Tlopen.flags` and
 * `Tlcreate.flags` are the Linux kernel's, exactly like `fuse_open_in.flags`,
 * and a driver resolves flags against the *host* — so the crossing is
 * `src/fuse/flags.ts`'s `driverOpenFlags()`, imported rather than copied. That
 * is a deliberate dependency from `src/9p/` onto `src/fuse/`: the translation
 * is a fact about Linux's `O_*` and the host's, not about either transport,
 * and a second copy of it is a second copy to get wrong. The wire's `O_*`
 * values come from `src/fuse/constants.ts` for the same reason — they are
 * transcribed once, from `include/uapi/linux/fcntl.h`, and 9P's wire is the
 * same kernel's.
 */

import { constants } from "node:fs";
import { errnoOf, fsError } from "../errors.ts";
import { driverOpenFlags, reopenFlags } from "../fuse/flags.ts";
import { createLoopback, type Loopback } from "../harness.ts";
import { PathLock } from "../lock.ts";
import { joinPath } from "../path.ts";
import {
  S_IFDIR,
  S_IFMT,
  S_IFREG,
  type FileHandleLike,
  type FsDriver,
  type StatsLike,
} from "../types.ts";
import { O_ACCMODE, O_CREAT, O_RDONLY, O_TRUNC } from "../fuse/constants.ts";
import {
  P9_DOTL_AT_REMOVEDIR,
  P9_GETATTR_BASIC,
  P9_GETATTR_BTIME,
  P9_IOHDRSZ,
  P9_LOCK_TYPE_UNLCK,
  P9_MIN_MSIZE,
  P9_NOFID,
  P9_QTSYMLINK,
  P9_RATTACH,
  P9_RCLUNK,
  P9_RFLUSH,
  P9_RFSYNC,
  P9_RGETATTR,
  P9_RGETLOCK,
  P9_RLCREATE,
  P9_RLERROR,
  P9_RLINK,
  P9_RLOCK,
  P9_RLOPEN,
  P9_RMKDIR,
  P9_RMKNOD,
  P9_READDIRHDRSZ,
  P9_RREAD,
  P9_RREADDIR,
  P9_RREADLINK,
  P9_RREMOVE,
  P9_RRENAME,
  P9_RRENAMEAT,
  P9_RSETATTR,
  P9_RSTATFS,
  P9_RSYMLINK,
  P9_RUNLINKAT,
  P9_RVERSION,
  P9_RWALK,
  P9_RWRITE,
  P9_SETATTR_ATIME,
  P9_SETATTR_ATIME_SET,
  P9_SETATTR_GID,
  P9_SETATTR_MODE,
  P9_SETATTR_MTIME,
  P9_SETATTR_MTIME_SET,
  P9_SETATTR_SIZE,
  P9_SETATTR_UID,
  P9_TATTACH,
  P9_TAUTH,
  P9_TCLUNK,
  P9_TFLUSH,
  P9_TFSYNC,
  P9_TGETATTR,
  P9_TGETLOCK,
  P9_TLCREATE,
  P9_TLINK,
  P9_TLOCK,
  P9_TLOPEN,
  P9_TMKDIR,
  P9_TMKNOD,
  P9_TREAD,
  P9_TREADDIR,
  P9_TREADLINK,
  P9_TREMOVE,
  P9_TRENAME,
  P9_TRENAMEAT,
  P9_TSETATTR,
  P9_TSTATFS,
  P9_TSYMLINK,
  P9_TUNLINKAT,
  P9_TVERSION,
  P9_TWALK,
  P9_TWRITE,
  P9_TXATTRCREATE,
  P9_TXATTRWALK,
  P9_VERSION_DOTL,
  P9_VERSION_UNKNOWN,
  V9FS_MAGIC,
  messageName,
} from "./constants.ts";
import { FidTable, qidVersion, walkStep, type Fid, type FidOpenState } from "./fids.ts";
import { P9LockTable, type P9LockClient } from "./locks.ts";
import {
  P9DirentPacker,
  encodeMessage,
  readFidRequest,
  readHeader,
  readTattach,
  readTauth,
  readTflush,
  readTfsync,
  readTgetattr,
  readTgetlock,
  readTlcreate,
  readTlink,
  readTlock,
  readTlopen,
  readTmkdir,
  readTmknod,
  readTread,
  readTreaddir,
  readTrename,
  readTrenameat,
  readTsetattr,
  readTsymlink,
  readTunlinkat,
  readTversion,
  readTwalk,
  readTwrite,
  writeRattach,
  writeRgetattr,
  writeRgetlock,
  writeRlerror,
  writeRlock,
  writeRlopen,
  writeRread,
  writeRreaddir,
  writeRreadlink,
  writeRstatfs,
  writeRversion,
  writeRwalk,
  writeRwrite,
  writeQidReply,
  type P9Header,
  type P9Time,
  type Rgetattr,
  type Tattach,
  type Tfsync,
  type Tgetattr,
  type Tgetlock,
  type Tlcreate,
  type Tlink,
  type Tlock,
  type Tlopen,
  type Tmkdir,
  type Tmknod,
  type Tread,
  type Treaddir,
  type Trename,
  type Trenameat,
  type Tsetattr,
  type Tsymlink,
  type Tunlinkat,
  type Tversion,
  type Twalk,
  type Twrite,
} from "./protocol.ts";
import {
  P9Error,
  P9Reader,
  isP9Error,
  stringByteLength,
  type P9Qid,
  type P9Writer,
} from "./wire.ts";

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
 * `(gid_t)-1` in a create message: "no group to give this to".
 *
 * The same sentinel as {@link NO_NUNAME} and for the same reason — v9fs sends
 * `from_kgid(&init_user_ns, gid)`, and an `INVALID_GID` comes out of that as
 * `(gid_t)-1`, which is also POSIX's "leave the group alone" for `chown(2)`.
 */
const NO_NGID = 0xff_ff_ff_ff;

/**
 * The largest byte offset a `Tread`/`Twrite`/`Tsetattr` may name.
 *
 * The wire field is a `u64` and the driver interface takes a `number`, so the
 * ceiling is where a JS integer stops being exact. Beyond it the offset cannot
 * be represented, and rounding one silently would read or write somewhere the
 * client did not ask for — `EINVAL` says so instead.
 */
const MAX_OFFSET = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * The one refusal that is allocated once, because it is sent constantly.
 *
 * Linux probes `security.*` on every write to a file it has no cached xattr
 * answer for, so `Txattrwalk` outnumbers every other message on a busy mount
 * even though nothing in the driver interface can answer one. The body is not
 * decoded and the error is not rebuilt: neither is needed to say no, and both
 * would allocate on the hottest path this server has.
 *
 * Sharing one `Error` instance is safe because nothing mutates it — the session
 * reads its `code` through `errnoOf()` and hands the value to `onError`.
 */
const XATTR_UNSUPPORTED = fsError("ENOTSUP", {
  message: "ENOTSUP: this server has no extended attributes",
});

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
 * It is what `#claim` gives a freshly created file to: the creating messages
 * carry a `gid` of their own but no uid at all, because the only place a 9P
 * connection ever says who it is, is the `Tattach` every fid descends from.
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
   * The byte-range lock table `Tlock`/`Tgetlock` answer from. Default: a
   * private one, holding nothing but this session's own ranges.
   *
   * Locks are the one piece of state that is **not** per connection — a lock
   * exists to be seen by another client, and every client has a connection of
   * its own — so `createP9Server` builds one table and hands the same one to
   * every session it makes. A session constructed by hand gets its own, which
   * is the single-client `mount9p()` case: nothing else can be in it, so every
   * request is granted. See `locks.ts`.
   */
  locks?: P9LockTable;
  /**
   * Refuse every mutating request with `EROFS`. Default `false`.
   *
   * "Mutating" includes a `Tlopen` that asks for write access, `O_CREAT` or
   * `O_TRUNC` — refusing the write and allowing the open that promised it would
   * leave the client holding a descriptor whose every use fails, where `EROFS`
   * at `open(2)` is exactly what a read-only mount gives userspace.
   *
   * `Tremove` is the one message this cannot make harmless: the protocol clunks
   * its fid whether or not the removal succeeds (see {@link P9Session}'s
   * `#remove`), so a refused `Tremove` still costs the client its fid.
   */
  readOnly?: boolean;
  /**
   * `chown` a newly created entry to the attaching user. Default `true`.
   *
   * The driver creates everything as the server process, so without this a file
   * created by uid 1000 comes back owned by whoever is running the server and
   * then fails every permission check its own creator makes. Quiet when the
   * driver cannot express ownership — see `#claim`.
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
  /**
   * This connection's handle on the byte-range lock table — `Tlock` and
   * `Tgetlock`, and the releases that keep a dead client from holding a range
   * forever.
   *
   * Not to be confused with `#lock`, the {@link PathLock} that serializes this
   * session's path resolution against its own renames. Different thing, and the
   * reason this one is named in the plural: see `locks.ts`.
   */
  readonly locks: P9LockClient;
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
    this.locks = (options.locks ?? new P9LockTable()).client();
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
   *
   * The byte-range locks go with the fids, and they must: the table can outlive
   * this session (it is shared with every other connection to the same server),
   * so a range left behind by a client that has gone would deny that file to
   * everybody with nothing left able to release it. Released synchronously,
   * before the first `await` below, so nothing can be granted into the gap.
   */
  async #reset(): Promise<void> {
    this.#generation++;
    const open = this.fids.openHandles();
    this.fids.clear();
    this.locks.releaseAll();
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
   * for is gone. `EIO` for a live session: the request really was aborted, and
   * `EIO` is what an aborted I/O reports. Either way the client has been told
   * to start over, so neither is a surprise to it.
   *
   * The `EIO` message names both things that can have happened, because the
   * error is raised from two places and cannot tell them apart: a `Tversion`
   * reset (which clunks every fid and bumps the generation) and a plain
   * `Tclunk`/`Tremove` that released *this* request's fid while it was parked in
   * the driver — same outcome, no generation change, and blaming a version
   * exchange that never happened would send a reader looking for the wrong bug.
   */
  #stale(header: P9Header): Error {
    const what = messageName(header.type);
    return this.#destroyed
      ? fsError("ENODEV", { message: `ENODEV: ${what} outlived the session` })
      : fsError("EIO", {
          message: `EIO: ${what} was aborted — the session was reset or its fid was released`,
        });
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
      case P9_TLOPEN: {
        const request = this.#decode(header, body, readTlopen);
        return this.#read(() => this.#lopen(header, request));
      }
      case P9_TLCREATE: {
        const request = this.#decode(header, body, readTlcreate);
        return this.#read(() => this.#lcreate(header, request));
      }
      case P9_TREAD: {
        const request = this.#decode(header, body, readTread);
        // Captured in the prologue for `Treaddir`'s reason, and dispatched
        // *outside* the path lock for `PathLock`'s: a read is the request a
        // driver can park on for an unbounded time, and it resolves nothing in
        // the path map. Only the re-open a `handles: false` driver needs takes
        // the reader lock, and only around the open itself (`#withHandle`).
        const budget = Math.min(request.count >>> 0, Math.max(0, this.#msize - P9_IOHDRSZ));
        return this.#readFile(header, request, budget);
      }
      case P9_TWRITE: {
        // `readTwrite` copies the payload, so nothing here is a view of the
        // caller's buffer once the prologue is over.
        return this.#write(header, this.#decode(header, body, readTwrite));
      }
      case P9_TFSYNC: {
        return this.#fsync(header, this.#decode(header, body, readTfsync));
      }
      case P9_TSETATTR: {
        const request = this.#decode(header, body, readTsetattr);
        return this.#read(() => this.#setattr(header, request));
      }
      case P9_TMKDIR: {
        const request = this.#decode(header, body, readTmkdir);
        return this.#read(() => this.#mkdir(header, request));
      }
      case P9_TSYMLINK: {
        const request = this.#decode(header, body, readTsymlink);
        return this.#read(() => this.#symlink(header, request));
      }
      case P9_TMKNOD: {
        const request = this.#decode(header, body, readTmknod);
        return this.#read(() => this.#mknod(header, request));
      }
      case P9_TLINK: {
        const request = this.#decode(header, body, readTlink);
        return this.#read(() => this.#link(header, request));
      }
      case P9_TREADLINK: {
        const fid = this.#decode(header, body, readFidRequest).fid;
        return this.#read(() => this.#readlink(header, fid));
      }
      case P9_TRENAME: {
        const request = this.#decode(header, body, readTrename);
        // The only writer, in both transports and for the same reason: a rename
        // rewrites paths it did not resolve itself. See `src/lock.ts`.
        return this.#lock.write(() => this.#rename(header, request));
      }
      case P9_TRENAMEAT: {
        const request = this.#decode(header, body, readTrenameat);
        return this.#lock.write(() => this.#renameat(header, request));
      }
      case P9_TUNLINKAT: {
        const request = this.#decode(header, body, readTunlinkat);
        return this.#read(() => this.#unlinkat(header, request));
      }
      case P9_TREMOVE: {
        const fid = this.#decode(header, body, readFidRequest).fid;
        return this.#read(() => this.#remove(header, fid));
      }
      case P9_TXATTRWALK:
      case P9_TXATTRCREATE: {
        // Refused without decoding the body; see {@link XATTR_UNSUPPORTED}.
        throw XATTR_UNSUPPORTED;
      }
      case P9_TLOCK: {
        // Named for the `fcntl(2)` commands they are, because `#lock` is
        // already the path lock and a `#lock` that is not one would be a trap.
        return this.#setlk(header, this.#decode(header, body, readTlock));
      }
      case P9_TGETLOCK: {
        return this.#getlk(header, this.#decode(header, body, readTgetlock));
      }
      default: {
        // The four legacy 9P2000 opcodes .L replaced (`Topen`, `Tcreate`,
        // `Tstat`, `Twstat`), the two error types nobody sends, and anything
        // that is not a message at all. This answer is permanent.
        throw fsError("ENOTSUP", {
          message: `ENOTSUP: ${messageName(header.type)} is not supported`,
        });
      }
    }
  }

  /**
   * Run a handler as a reader: concurrent with every other reader, and
   * serialized against `Trename`/`Trenameat`, the only writers.
   *
   * Everything that resolves a path is a reader. Four messages are deliberately
   * outside it: `Tclunk` and `Tflush` resolve nothing, and `Tread`/`Twrite` are
   * where a driver can park for an unbounded time — the lock's own docs say to
   * keep those out, and they name no path either (the re-open a `handles: false`
   * driver needs takes the reader lock for itself, around the open alone).
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
    // `#reset()` awaits every driver `close()`, so a `destroy()` can land while
    // this negotiation is parked inside it. Restoring an `msize` afterwards
    // would leave a torn-down session reporting a live one; the request gate in
    // `#dispatch` refuses everything either way, but a getter that contradicts
    // `destroyed` is a lie a reader has to disprove.
    if (agreed && !this.#destroyed) {
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
   *
   * The fid's byte-range locks go with it. The client's own kernel already
   * unlocks before it closes (`locks_remove_posix()` sends a `Tlock UNLCK`), so
   * this is the guard rather than the mechanism — but a fid is the only handle
   * on a lock this end has, and one that survived its fid could never be
   * released.
   */
  async #clunk(header: P9Header, fid: number): Promise<Uint8Array> {
    const entry = this.fids.clunk(fid);
    this.locks.releaseFid(fid);
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
   *
   * **An open fid is answered as an `fstat`**; see {@link #fidAttributes}.
   */
  async #getattr(header: P9Header, request: Tgetattr): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    const { qid, stats } = await this.#fidAttributes(entry);
    const attr = this.#attrOf(qid, stats, request.requestMask);
    return this.#framed(header, P9_RGETATTR, (writer) => writeRgetattr(writer, attr), 192);
  }

  /**
   * What a fid's attributes are, and which identity describes them.
   *
   * A fid is the 9P spelling of an open file description: it keeps naming its
   * file after the name it was opened from is gone, and after another file has
   * taken that name. So a fid holding a driver handle is answered from the
   * **handle** — `fstat`, not `stat` — which is what lets `unlink` on an open
   * file keep working (`Tread` already serves it, since it holds the same
   * handle) and is the one thing this transport has over NFSv3's statelessness.
   *
   * Two rules keep that from corrupting identity, and both were reproduced
   * before they were rules.
   *
   * - **The identity is pinned, never re-derived.** It comes from
   *   {@link FidOpenState.qid}, snapshotted by the `Tlopen`/`Tlcreate` that
   *   opened this fid. {@link FidTable.qidFor} does not merely read the
   *   path→identity map, it *writes* it, so calling it here would re-attach an
   *   identity to a path `#released` has just detached — and the next file
   *   created at that name would inherit the dead one's `qid.path`, which is
   *   exactly the aliasing `release()` exists to prevent. `src/fuse/session.ts`
   *   has the same discipline from the other side: a nodeid is fixed at
   *   `LOOKUP` and never re-derived from a later `GETATTR`. Only `version` is
   *   recomputed, because it is the file's mtime — a change token rather than
   *   an identity — and a pinned one would hide every write from the client's
   *   cache check.
   * - **A symlink is answered from its path.** `Tlopen` on a fid naming a
   *   symlink opens the link's *target* (only a directory is special-cased), so
   *   its handle describes a different file than the fid does: reporting from
   *   it would give the target's mode and size under the link's qid.
   *
   * Everything else — an unopened fid, a directory (which opens nothing), a
   * `handles: false` fid, and a driver whose handles answer `ENOSYS` — resolves
   * the path, as it always did. `qidFor` is therefore only ever fed attributes
   * that came *from* that path, which is the invariant underneath both rules.
   */
  async #fidAttributes(entry: Fid<string>): Promise<{ qid: P9Qid; stats: StatsLike }> {
    const open = entry.open;
    const pinned = open?.qid;
    const handle = open?.handle;
    if (handle !== undefined && pinned !== undefined && (pinned.type & P9_QTSYMLINK) === 0) {
      let stats: StatsLike | undefined;
      try {
        stats = await handle.stat();
      } catch (error) {
        // A driver whose handles cannot stat has nothing to add and the path
        // answers instead. Any *other* failure is this fid's real answer.
        if ((error as { code?: string }).code !== "ENOSYS") {
          throw error;
        }
      }
      if (stats !== undefined) {
        return { qid: { type: pinned.type, version: qidVersion(stats), path: pinned.path }, stats };
      }
    }
    const stats = await this.#statOf(entry.path);
    return { qid: this.fids.qidFor(stats, entry.path), stats };
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
   * 9P requires a fid to have been opened before it can be read, so an unopened
   * one is `EBADF` — the errno Linux gives for I/O on a descriptor that is not
   * one, and the same answer {@link FidTable.require} gives for a fid that was
   * never issued. A fid opened as a *file* is `ENOTDIR`: it names something a
   * `Tread` can read and a `Treaddir` cannot, which is what `readdir(3)` on a
   * plain file reports.
   */
  #requireDirectory(entry: Fid<string>): FidOpenState {
    const open = this.#requireOpen(entry, "readdir");
    if (!open.directory) {
      throw fsError("ENOTDIR", {
        message: `ENOTDIR: fid ${entry.fid} was opened as a file`,
        path: entry.path,
      });
    }
    return open;
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
  // names, offsets, ownership
  // -------------------------------------------------------------------------

  /**
   * The path a `name` in the directory `parent` names.
   *
   * `walkStep` already refuses the three things that are not names at all — an
   * empty element, one with a separator in it, one with a NUL — and this adds
   * the two more a *create or remove* target has to satisfy: `.` and `..` name
   * directories that already exist rather than entries to make or unmake, and a
   * name longer than `NAME_MAX` **bytes** is one no filesystem will take. The
   * count is of bytes and not characters for the reason `Rstatfs.namelen` is:
   * the limit a kernel enforces is on the encoded name.
   */
  #childOf(parent: Fid<string>, name: string, syscall: string): string {
    if (name === "." || name === "..") {
      throw fsError("EINVAL", {
        syscall,
        message: `EINVAL: '${name}' is not an entry name`,
        path: parent.path,
      });
    }
    if (stringByteLength(name) > NAME_MAX) {
      throw fsError("ENAMETOOLONG", { syscall, message: `ENAMETOOLONG: entry name '${name}'` });
    }
    return walkStep(parent.path, name);
  }

  /** A 64-bit wire offset as a `number`, or `EINVAL`. See {@link MAX_OFFSET}. */
  #offset(value: bigint, syscall: string): number {
    if (value < 0n || value > MAX_OFFSET) {
      throw fsError("EINVAL", { syscall, message: `EINVAL: offset ${value} is out of range` });
    }
    return Number(value);
  }

  /**
   * Refuse a mutating request on a read-only session.
   *
   * The gate is the session option and not `driver.capabilities.readOnly`: a
   * driver that cannot write says so by throwing, one method at a time, and a
   * capability describing the driver is not a licence to refuse on its behalf.
   * `readOnly` is declared-only now — it used to be inferred from the absence
   * of `unlink`/`mkdir`/`rename`, and gating here would then have answered
   * `EROFS` for a driver that merely had no `rename` — but the conclusion does
   * not depend on that: a driver may declare `readOnly: false` and still refuse
   * an individual write, and only the driver knows which.
   * See {@link P9SessionOptions.readOnly}.
   *
   * Every caller checks its fids **first**, so a request that is both malformed
   * and forbidden reports the client's own mistake — `EBADF` for a fid this
   * connection never issued is information the client can act on, where `EROFS`
   * would send it looking at the wrong thing.
   */
  #requireWritable(syscall: string, path?: string): void {
    if (this.options.readOnly === true) {
      throw fsError("EROFS", {
        syscall,
        path,
        message: `EROFS: ${syscall} on a read-only 9P export`,
      });
    }
  }

  /**
   * Give a newly created entry to whoever asked for it.
   *
   * `NfsSession.#claim`'s stance, with the credentials gathered from the two
   * places 9P keeps them: the uid from the `Tattach` this fid descends from
   * (`p9_client_attach()` sends it once per user, and every walk inherits it),
   * the gid from the create message itself, which is the one credential 9P
   * repeats per request.
   *
   * **Set-gid inheritance is deliberately absent here, and is not a gap.** The
   * rule the NFS sessions apply (`../ownership.ts`) is applied by the *client*
   * on this wire: `v9fs_get_fsgid_for_create()` hands `Tmkdir`/`Tcreate`/
   * `Tsymlink`/`Tmknod` the parent's gid when the parent is set-gid, and
   * `v9fs_vfs_mkdir_dotl()` sets `S_ISGID` in the mode it sends. So the `gid`
   * below already *is* the inherited group, and the mode `#mkdir` passes
   * through already carries the bit — applying the rule a second time here
   * would be the server disagreeing with the kernel that computed it.
   *
   * Best effort, deliberately. A driver with no `lchown` (`ENOSYS`), or one not
   * privileged enough to hand ownership away (`EPERM`/`ENOTSUP`), is not
   * thereby broken — it is a driver with no concept of ownership, and failing
   * the create it just completed would be the wrong answer to that. Skipped
   * outright when the caller *is* the server process, which is the common case
   * and worth one driver round trip.
   */
  async #claim(path: string, fid: number, gid: number): Promise<void> {
    if (this.options.claimOwnership === false) {
      return;
    }
    const uid = this.#users.get(fid)?.uid ?? -1;
    const wanted = gid === NO_NGID ? -1 : gid;
    if (uid === -1 && wanted === -1) {
      return;
    }
    if (uid === (process.getuid?.() ?? -1) && wanted === (process.getgid?.() ?? -1)) {
      return;
    }
    try {
      // `-1` is POSIX for "leave this one alone", inherited from `node:fs`.
      await this.driver.lchown(path, uid, wanted);
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code !== "ENOSYS" && code !== "EPERM" && code !== "ENOTSUP") {
        throw error;
      }
    }
  }

  /** Stat a path a create just produced, and answer the qid that describes it. */
  async #qidOf(path: string): Promise<P9Qid> {
    return this.fids.qidFor(await this.#statOf(path), path);
  }

  /** A reply that is nothing but a qid: `Rmkdir`, `Rsymlink`, `Rmknod`. */
  #qidReply(header: P9Header, type: number, qid: P9Qid): Uint8Array {
    return this.#framed(header, type, (writer) => writeQidReply(writer, { qid }), 32);
  }

  // -------------------------------------------------------------------------
  // open state
  // -------------------------------------------------------------------------

  /**
   * The open state of a fid, or `EBADF`.
   *
   * A fid with no {@link FidOpenState} has never been through `Tlopen` or
   * `Tlcreate`, and 9P has no operation that reads or writes one: the client is
   * required to open before it does I/O, exactly as it is required to `open(2)`
   * before it `read(2)`s, and `EBADF` is what the kernel says for the same
   * mistake made with a descriptor.
   */
  #requireOpen(entry: Fid<string>, syscall: string): FidOpenState {
    if (entry.open === undefined) {
      throw fsError("EBADF", {
        syscall,
        path: entry.path,
        message: `EBADF: fid ${entry.fid} has not been opened`,
      });
    }
    return entry.open;
  }

  /** The open state of a fid opened as a *file*, or `EBADF`/`EISDIR`. */
  #requireFile(entry: Fid<string>, syscall: string): FidOpenState {
    const open = this.#requireOpen(entry, syscall);
    if (open.directory) {
      // What `read(2)` and `write(2)` answer for a directory descriptor, and
      // what v9fs's `p9_client_read()` callers expect: a directory is read with
      // `Treaddir` and written not at all.
      throw fsError("EISDIR", { syscall, path: entry.path });
    }
    return open;
  }

  /**
   * Run something with a real `FileHandle`.
   *
   * `src/fuse/session.ts`'s `#withHandle`, and the same two cases: a driver
   * that declares `handles` gets the one `Tlopen` opened, and one that does not
   * gets a fresh open per operation from the fid's path — correct for
   * everything 9P does, since every `Tread` and `Twrite` carries an explicit
   * offset, and the honest degradation for a driver with no per-open state.
   *
   * The re-open resolves a path, so it takes the reader lock — for the resolve
   * and the open only, never for the operation itself. Without it a concurrent
   * `Trename` could move the file between the two and fail a perfectly valid
   * fid with `ENOENT`.
   */
  async #withHandle<T>(
    entry: Fid<string>,
    open: FidOpenState,
    fn: (handle: FileHandleLike) => Promise<T>,
  ): Promise<T> {
    if (open.handle !== undefined) {
      return fn(open.handle);
    }
    const handle = await this.#lock.read(async () => this.driver.open(entry.path, open.flags));
    try {
      return await fn(handle);
    } finally {
      await this.#closeQuietly(handle);
    }
  }

  /**
   * Close a handle the client does not know about.
   *
   * Failing here is a diagnostic, never an errno: the request it belongs to has
   * already done its work, and the only close a client is entitled to hear
   * about is the one its own `Tclunk` asked for.
   */
  async #closeQuietly(handle: FileHandleLike): Promise<void> {
    try {
      await handle.close();
    } catch (error) {
      this.#report(error, undefined);
    }
  }

  /**
   * The fid is still exactly what this request's prologue saw, or the open it
   * just performed has been overtaken and must be unwound.
   *
   * **Two races, one check, and both are reachable from a single connection.**
   *
   * - *The fid went away.* A `Tversion`, a `destroy()`, a `Tclunk` or a
   *   `Tremove` drops the entry while `driver.open()` is still running; `#run`
   *   would discard the reply, but the handle would already be stored on an
   *   object nothing can reach and would never be closed. Answered with
   *   {@link P9Session.#stale}.
   * - *The fid was opened by somebody else.* Two `Tlopen`s (or two `Tlcreate`s)
   *   naming the same fid arrive before either finishes: both pass the
   *   prologue's "not open yet" test, both open, and the second assignment
   *   overwrites the first — leaking a descriptor for the life of the
   *   connection, since a `Tclunk` can only ever close the handle it finds.
   *   `p9_client_open()` never does this (v9fs serializes per fid), but
   *   `createP9Server` will accept frames from anything that connects, so the
   *   leak is a hostile client away and unbounded.
   *
   * `EBUSY` for the second, deliberately distinct from the `EINVAL` an ordinary
   * double-open gets: that one is a client that forgot it had opened the fid,
   * this one is a client racing itself, and a server that reported them
   * identically would make the difference invisible in exactly the case where it
   * matters. The loser closes what it opened — the caller's `catch` does that —
   * so the winner's handle is the only one left.
   *
   * `path` is `Tlcreate`'s extra half: the fid it started from must still name
   * the directory it named, because a create moves the fid, and a loser that
   * only checked `open` would still overwrite the winner's path.
   */
  #ensureOpenable(entry: Fid<string>, header: P9Header, path?: string): void {
    if (this.fids.get(entry.fid) !== entry) {
      throw this.#stale(header);
    }
    if (entry.open !== undefined || (path !== undefined && entry.path !== path)) {
      throw fsError("EBUSY", {
        message: `EBUSY: fid ${entry.fid} was opened by another request in flight`,
        path: entry.path,
      });
    }
  }

  /**
   * Does an open ask to change anything? `O_WRONLY`, `O_RDWR`, `O_CREAT`,
   * `O_TRUNC` — in the **wire's** namespace, which is the Linux kernel's.
   */
  #writeIntent(wireFlags: number): boolean {
    return (wireFlags & O_ACCMODE) !== O_RDONLY || (wireFlags & (O_CREAT | O_TRUNC)) !== 0;
  }

  // -------------------------------------------------------------------------
  // Tlopen / Tlcreate
  // -------------------------------------------------------------------------

  /**
   * `Tlopen` — prepare an already-walked fid for I/O.
   *
   * **A directory is opened without asking the driver.** `node:fs/promises` has
   * no `opendir`-shaped entry point in `FsDriver` — `readdir` takes a path — so
   * a `driver.open()` on a directory would produce a handle nothing here would
   * ever use, and drivers disagree about whether it succeeds at all (`node:fs`
   * gives an `fd`, the memory driver gives a handle, others answer `EISDIR`).
   * What the open owes the client is the *check*, and an `lstat` is the check:
   * it is what says the fid names a directory, and it is what `Treaddir` needs
   * a moment later anyway. `src/fuse/session.ts`'s `OPENDIR` decides the *other*
   * way and is not a precedent here: the VFS refuses `O_DIRECTORY` on a regular
   * file before FUSE is ever asked, so the check there was second-guessing
   * attributes that server had itself supplied. 9P has no VFS in front of it —
   * the check is this server's to make or skip. `NfsSession` never faces the
   * question, because NFSv3 has no open.
   *
   * **`iounit` is `0`**, which the protocol defines as "no preference" and
   * `p9_client_open()` reads as `msize - P9_IOHDRSZ`. That is exactly the bound
   * this server would compute anyway (`Tread`'s budget is the same expression),
   * so naming a smaller number would only cost round trips, and naming a larger
   * one would invite a `Twrite` that cannot be framed. A driver with a
   * preferred block size has nowhere to say so in `FsDriver`, so there is
   * nothing better to report and nothing invented.
   *
   * Opening a fid twice is `EINVAL` when the client has already been told about
   * the first open, and `EBUSY` when the two opens overlap — see
   * {@link P9Session.#ensureOpenable}, which is also what keeps the loser's
   * handle from leaking. An open fid names a file being read or written;
   * `p9_client_open()` never opens one twice.
   */
  async #lopen(header: P9Header, request: Tlopen): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    if (entry.open !== undefined) {
      throw fsError("EINVAL", { message: `EINVAL: fid ${request.fid} is already open` });
    }
    if (this.#writeIntent(request.flags)) {
      this.#requireWritable("open", entry.path);
    }
    // `request.flags` is the kernel's namespace, so it is inspected with the
    // kernel's constants above and translated here; the identity on Linux.
    const flags = driverOpenFlags(request.flags);
    let stats = await this.#statOf(entry.path);
    if ((stats.mode & S_IFMT) === S_IFDIR) {
      if (this.#writeIntent(request.flags)) {
        throw fsError("EISDIR", { syscall: "open", path: entry.path });
      }
      this.#ensureOpenable(entry, header);
      // Nothing one-shot survives to a re-open, and for a directory nothing
      // re-opens at all — `Treaddir` reads the path. `reopenFlags()` is applied
      // anyway so the field means one thing on every fid.
      entry.open = { flags: reopenFlags(flags), handle: undefined, directory: true };
    } else {
      const handle = await this.driver.open(entry.path, flags);
      const keep = this.driver.capabilities.handles;
      if (!keep) {
        // No per-open state to keep, but the open still had to happen: it is
        // what reports `ENOENT`, `EACCES` and the rest.
        await this.#closeQuietly(handle);
      }
      try {
        if ((request.flags & O_TRUNC) !== 0) {
          // The open just changed the file, so the qid the client will cache
          // against has to describe it *afterwards*: `qid.version` is the mtime,
          // and one taken before the truncation names the file that is gone.
          // Linux never reaches this — `do_dentry_open()` clears `O_CREAT`,
          // `O_EXCL`, `O_NOCTTY` and `O_TRUNC` out of `f_flags` before
          // `v9fs_file_open()` ever maps them, so a `Tlopen` from v9fs carries
          // none of the three — but any other client may send it, and a stale
          // version is a cache the client will not invalidate.
          stats = await this.#statOf(entry.path);
        }
        this.#ensureOpenable(entry, header);
      } catch (error) {
        if (keep) {
          await this.#closeQuietly(handle);
        }
        throw error;
      }
      entry.open = {
        // The creation flags acted once, at this open; a re-open standing in
        // for it must not repeat them. See `src/fuse/flags.ts`.
        flags: reopenFlags(flags),
        handle: keep ? handle : undefined,
        directory: false,
      };
    }
    entry.iounit = 0;
    // Derived from the *final* `stats`, so an `O_TRUNC` open pins the file it
    // leaves behind rather than the one it emptied — and pinned on the open
    // state, which is what `Tgetattr` answers with once the path is gone.
    const qid = this.fids.qidFor(stats, entry.path);
    entry.open.qid = qid;
    return this.#framed(
      header,
      P9_RLOPEN,
      (writer) => writeRlopen(writer, { qid, iounit: entry.iounit }),
      32,
    );
  }

  /**
   * `Tlcreate` — create a **regular file** under the directory `fid` names, and
   * leave the fid naming the file.
   *
   * That hand-over is the message's whole shape: the parent's fid is spent, so
   * `v9fs_vfs_atomic_open_dotl()` always clones one before creating. It happens
   * here only on success, and through {@link Fid.path}'s setter, so a failed
   * create leaves the fid exactly where it was — pointing at the directory,
   * unopened, and with any readdir cursor it held intact (a cursor is dropped
   * only when the path really moves).
   *
   * **`O_CREAT` is or-ed in unconditionally**, and that is belt and braces
   * rather than a correction: `v9fs_open_to_dotl_flags()` *does* map it
   * (`dotl_oflag_map` pairs `O_CREAT` with `P9_DOTL_CREATE`, and `P9L_MODE_MASK`
   * keeps the bit), so the kernel sends it — but creating is what this message
   * *means*, there is no reading of `Tlcreate` under which the file should not
   * be created, and a client that left the bit out would otherwise get `ENOENT`
   * for the one request that cannot fail that way. `O_EXCL` is the client's
   * alone and passes through untouched, which is what makes
   * `open(O_CREAT|O_EXCL)` fail with `EEXIST` over the wire the way it does
   * locally.
   *
   * Two `Tlcreate`s racing on one fid are refused like two `Tlopen`s — see
   * {@link P9Session.#ensureOpenable}. The loser's *file* is not removed: the
   * create really happened, and unlinking it would be this server deleting a
   * path some other request may already have opened.
   */
  async #lcreate(header: P9Header, request: Tlcreate): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    if (entry.open !== undefined) {
      throw fsError("EINVAL", {
        message: `EINVAL: fid ${request.fid} is open, and an open fid cannot create`,
      });
    }
    this.#requireWritable("open", entry.path);
    const parent = entry.path;
    const path = this.#childOf(entry, request.name, "open");
    const flags = driverOpenFlags(request.flags) | constants.O_CREAT;
    const handle = await this.driver.open(path, flags, request.mode & 0o7777);
    const keep = this.driver.capabilities.handles;
    if (!keep) {
      await this.#closeQuietly(handle);
    }
    let qid: P9Qid;
    try {
      await this.#claim(path, request.fid, request.gid);
      qid = await this.#qidOf(path);
      this.#ensureOpenable(entry, header, parent);
    } catch (error) {
      // The file exists but we cannot describe it, so there is no open fid to
      // hand back and nothing that would ever clunk this handle.
      if (keep) {
        await this.#closeQuietly(handle);
      }
      throw error;
    }
    entry.path = path;
    entry.open = {
      flags: reopenFlags(flags),
      handle: keep ? handle : undefined,
      directory: false,
      // The qid this create just computed, pinned for the life of the open —
      // the identity `Tgetattr` answers with once the path stops resolving.
      qid,
    };
    entry.iounit = 0;
    return this.#framed(
      header,
      P9_RLCREATE,
      (writer) => writeRlopen(writer, { qid, iounit: entry.iounit }),
      32,
    );
  }

  // -------------------------------------------------------------------------
  // Tread / Twrite / Tfsync
  // -------------------------------------------------------------------------

  /**
   * `Tread` — bytes at an offset, from a fid opened as a file.
   *
   * `count` is clamped to what the negotiated `msize` can frame, computed
   * before the first `await` (see the dispatch). A short read is the driver's
   * answer, not an error: fewer bytes than asked for is how a file says it
   * ended, and zero of them is how it says the offset is past the end. A
   * zero-length read is legal and answers an empty `Rread`.
   */
  async #readFile(header: P9Header, request: Tread, budget: number): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    const open = this.#requireFile(entry, "read");
    const offset = this.#offset(request.offset, "read");
    const size = Math.min(request.count >>> 0, budget);
    const buffer = new Uint8Array(size);
    const { bytesRead } = await this.#withHandle(entry, open, (handle) =>
      handle.read(buffer, 0, size, offset),
    );
    const data = buffer.subarray(0, Math.min(size, Math.max(0, bytesRead)));
    return this.#framed(
      header,
      P9_RREAD,
      (writer) => writeRread(writer, { data }),
      data.byteLength + 16,
    );
  }

  /**
   * `Twrite` — bytes at an offset, to a fid opened as a file.
   *
   * The payload arrived inside an `msize`-bounded frame, so there is nothing to
   * clamp; `readTwrite` already copied it, so there is nothing to copy either —
   * copying it twice is the mistake this codebase has made once, and the
   * decoder is where it was fixed.
   *
   * "Bounded" is the transport's guarantee and not this method's:
   * `P9FrameAssembler` refuses any frame larger than its `limit`, which the
   * transport lowers onto the negotiated `msize` (see {@link P9Session.msize}),
   * and it refuses it before a byte reaches here. So an over-budget `Twrite`
   * cannot arrive through a socket at all; only a test calling
   * {@link P9Session.handleCall} directly can present one, and what it gets is
   * the write it asked for.
   */
  async #write(header: P9Header, request: Twrite): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    const open = this.#requireFile(entry, "write");
    this.#requireWritable("write", entry.path);
    const offset = this.#offset(request.offset, "write");
    const { bytesWritten } = await this.#withHandle(entry, open, (handle) =>
      handle.write(request.data, 0, request.data.byteLength, offset),
    );
    return this.#framed(
      header,
      P9_RWRITE,
      (writer) => writeRwrite(writer, { count: Math.max(0, bytesWritten) }),
      16,
    );
  }

  /**
   * `Tfsync` — flush what the fid has open.
   *
   * `datasync` picks `FileHandle.datasync()` and falls back to `sync()`, which
   * is `src/fuse/session.ts`'s `FSYNC` exactly: a driver that only implements
   * one of the two flushes more than asked, never less.
   *
   * **A `handles: false` driver still gets a real flush**, because `#withHandle`
   * re-opens the path for it and syncs *that* handle. It is FUSE's choice and
   * it is the useful one: for a driver whose state lives in the file rather
   * than in the handle (the `node:fs` passthrough, most obviously) an `fsync`
   * on a fresh descriptor for the same file is the same syscall on the same
   * inode. Answering a bare success instead would be quietly telling a client
   * its data is durable when nothing was asked to make it so.
   *
   * A directory fid is a success with no work: there is nothing open to flush,
   * and `fsync(2)` on a directory is a promise about the *entries*, which the
   * driver interface cannot express and no driver here buffers.
   */
  async #fsync(header: P9Header, request: Tfsync): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    const open = this.#requireOpen(entry, "fsync");
    if (!open.directory) {
      await this.#withHandle(entry, open, async (handle) => {
        const flush = request.datasync === 0 ? handle.sync : (handle.datasync ?? handle.sync);
        await flush?.call(handle);
      });
    }
    return this.#framed(header, P9_RFSYNC);
  }

  // -------------------------------------------------------------------------
  // Tsetattr
  // -------------------------------------------------------------------------

  /**
   * `Tsetattr` — the `P9_SETATTR_*` bitmask, applied one bit at a time.
   *
   * The order is `src/fuse/session.ts`'s `SETATTR`, and it is the order a shell
   * would have issued them in: mode and ownership first, then the size, then
   * the timestamps — so an explicit `mtime` in the same message wins over the
   * one the truncate just set.
   *
   * **`P9_SETATTR_CTIME` is accepted and does nothing**, deliberately. The
   * kernel really does send it — `v9fs_mapped_iattr_valid()` maps `ATTR_CTIME`,
   * and the VFS sets `ATTR_CTIME` on nearly every `notify_change()` — but the
   * message carries no ctime *value* (there is no field for one: the bit can
   * only ever mean "now"), and POSIX already says a ctime is stamped by the
   * metadata change itself. So every driver that stored the `chmod` or the
   * `chown` in the same request has already done what the bit asks, and no
   * driver has an interface to do it separately. Refusing the bit would fail
   * almost every `chmod` on the mount; honoring it separately is impossible;
   * ignoring it is both correct and what diod does.
   *
   * `uid` and `gid` are read only when their own bits are set — the `(uid_t)-1`
   * convention `chown(2)` uses does not apply on this wire, the mask does the
   * saying — and the value passed for the one that is absent is `-1`, which is
   * where that convention *does* live, in the driver call.
   */
  async #setattr(header: P9Header, request: Tsetattr): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    const { valid } = request;
    const path = entry.path;
    this.#requireWritable("setattr", path);
    // Only a *real* handle: a `handles: false` fid has nothing to truncate
    // through, and re-opening one to truncate it would repeat the open's flags
    // for no gain over `truncate(path)`.
    const handle = entry.open?.handle;

    if ((valid & P9_SETATTR_MODE) !== 0) {
      await this.driver.chmod(path, request.mode & 0o7777);
    }
    if ((valid & (P9_SETATTR_UID | P9_SETATTR_GID)) !== 0) {
      const uid = (valid & P9_SETATTR_UID) === 0 ? -1 : request.uid;
      const gid = (valid & P9_SETATTR_GID) === 0 ? -1 : request.gid;
      await this.#nofollow(
        () => this.driver.lchown(path, uid, gid),
        () => this.driver.chown(path, uid, gid),
      );
    }
    if ((valid & P9_SETATTR_SIZE) !== 0) {
      const size = this.#offset(request.size, "truncate");
      await (handle === undefined ? this.driver.truncate(path, size) : handle.truncate(size));
    }
    if ((valid & (P9_SETATTR_ATIME | P9_SETATTR_MTIME)) !== 0) {
      await this.#setTimes(path, request);
    }
    return this.#framed(header, P9_RSETATTR);
  }

  /**
   * The time half of a `Tsetattr`.
   *
   * A time bit *without* its `_SET` companion means "use the server's clock"
   * and the value in the message is then ignored — the one place 9P's setattr
   * differs in shape from FUSE's, which spends two bits on the same idea
   * (`FATTR_ATIME` plus `FATTR_ATIME_NOW`). `utimes` sets both stamps at once,
   * so a request naming only one has to read the other back first.
   *
   * Nanoseconds survive only through the `mountx.utimens` extension:
   * `fs.utimes` takes float seconds and loses them, and 9P is the transport
   * that would otherwise carry them intact.
   */
  async #setTimes(path: string, request: Tsetattr): Promise<void> {
    const { valid } = request;
    const wantAtime = (valid & P9_SETATTR_ATIME) !== 0;
    const wantMtime = (valid & P9_SETATTR_MTIME) !== 0;
    const nowNs = BigInt(Math.round(Date.now() * 1e6));
    let current: StatsLike | undefined;
    if (!wantAtime || !wantMtime) {
      current = await this.#statOf(path);
    }
    const chosen = (
      want: boolean,
      set: boolean,
      time: P9Time,
      fallbackMs: number | undefined,
    ): bigint => {
      if (!want) {
        return BigInt(Math.round(Math.max(0, fallbackMs ?? 0) * 1e6));
      }
      return set ? time.sec * 1_000_000_000n + time.nsec : nowNs;
    };
    const atimeNs = chosen(
      wantAtime,
      (valid & P9_SETATTR_ATIME_SET) !== 0,
      request.atime,
      current?.atimeMs,
    );
    const mtimeNs = chosen(
      wantMtime,
      (valid & P9_SETATTR_MTIME_SET) !== 0,
      request.mtime,
      current?.mtimeMs,
    );

    const utimens = this.driver.mountx?.utimens;
    if (utimens !== undefined) {
      await utimens.call(this.driver.mountx, path, atimeNs, mtimeNs);
      return;
    }
    const [atime, mtime] = [Number(atimeNs) / 1e9, Number(mtimeNs) / 1e9];
    await this.#nofollow(
      () => this.driver.lutimes(path, atime, mtime),
      () => this.driver.utimes(path, atime, mtime),
    );
  }

  /**
   * Prefer the `AT_SYMLINK_NOFOLLOW` form of a metadata call.
   *
   * A fid names a file, and that file can be a symlink — the client resolves
   * symlinks itself, so anything reaching this server is already the final
   * component. Following it would stamp the target instead, which is wrong when
   * the target exists and `ENOENT` when it does not. Both FUSE and NFS carry
   * this for the same reason; `tar -xp` is the case that found it, since it
   * restores a symlink before whatever it points at and then stamps it.
   */
  async #nofollow<T>(preferred: () => Promise<T>, following: () => Promise<T>): Promise<T> {
    try {
      return await preferred();
    } catch (error) {
      if ((error as { code?: string }).code === "ENOSYS") {
        return following();
      }
      throw error;
    }
  }

  // -------------------------------------------------------------------------
  // creating things: mkdir, symlink, mknod, link, readlink
  // -------------------------------------------------------------------------

  async #mkdir(header: P9Header, request: Tmkdir): Promise<Uint8Array> {
    const parent = this.fids.require(request.dfid);
    this.#requireWritable("mkdir", parent.path);
    const path = this.#childOf(parent, request.name, "mkdir");
    await this.driver.mkdir(path, { mode: request.mode & 0o7777 });
    await this.#claim(path, request.dfid, request.gid);
    return this.#qidReply(header, P9_RMKDIR, await this.#qidOf(path));
  }

  /**
   * `Tsymlink`. The target is opaque — never resolved, never normalized: it may
   * be relative, and it means whatever it means when something walks through it.
   */
  async #symlink(header: P9Header, request: Tsymlink): Promise<Uint8Array> {
    const parent = this.fids.require(request.dfid);
    this.#requireWritable("symlink", parent.path);
    const path = this.#childOf(parent, request.name, "symlink");
    await this.driver.symlink(request.symtgt, path);
    await this.#claim(path, request.dfid, request.gid);
    return this.#qidReply(header, P9_RSYMLINK, await this.#qidOf(path));
  }

  /**
   * `Tmknod` — a device, fifo or socket node.
   *
   * `mountx.mknod` when the driver declares it, `ENOSYS` when it does not, and
   * one fallback in between that is `src/fuse/session.ts`'s: a `mode` naming a
   * *regular* file (or naming no type at all) is an `open(O_CREAT|O_EXCL)`,
   * because that is a thing every driver can do and `mknod(path, S_IFREG)` is
   * how a few tools still create an empty file.
   *
   * `major`/`minor` arrive as separate fields and are packed into the single
   * `dev` the extension takes the way `NfsSession` packs a `specdata3` — one
   * packing across the project, since nothing implements the extension yet and
   * two would be a difference nobody could act on.
   *
   * The flags this fallback originates are the **host's**, not the wire's: they
   * are ours rather than the client's, so no translation applies to them.
   */
  async #mknod(header: P9Header, request: Tmknod): Promise<Uint8Array> {
    const parent = this.fids.require(request.dfid);
    this.#requireWritable("mknod", parent.path);
    const path = this.#childOf(parent, request.name, "mknod");
    const mknod = this.driver.mountx?.mknod;
    if (mknod !== undefined) {
      await mknod.call(
        this.driver.mountx,
        path,
        request.mode,
        (request.major << 8) | request.minor,
      );
    } else if ((request.mode & S_IFMT) === S_IFREG || (request.mode & S_IFMT) === 0) {
      const handle = await this.driver.open(
        path,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
        request.mode & 0o7777,
      );
      await this.#closeQuietly(handle);
    } else {
      throw fsError("ENOSYS", { syscall: "mknod", path });
    }
    await this.#claim(path, request.dfid, request.gid);
    return this.#qidReply(header, P9_RMKNOD, await this.#qidOf(path));
  }

  /**
   * `Tlink` — one file, one more name.
   *
   * No `#claim`: a hardlink creates no inode, so there is no ownership to give
   * away — the file it names already belongs to whoever made it. `Rlink` is
   * bodyless for the same reason there is no qid to report.
   */
  async #link(header: P9Header, request: Tlink): Promise<Uint8Array> {
    const existing = this.fids.require(request.fid);
    const parent = this.fids.require(request.dfid);
    this.#requireWritable("link", parent.path);
    const path = this.#childOf(parent, request.name, "link");
    await this.driver.link(existing.path, path);
    return this.#framed(header, P9_RLINK);
  }

  /** `Treadlink` — the link's contents, verbatim. */
  async #readlink(header: P9Header, fid: number): Promise<Uint8Array> {
    const entry = this.fids.require(fid);
    const target = await this.driver.readlink(entry.path);
    return this.#framed(
      header,
      P9_RREADLINK,
      (writer) => writeRreadlink(writer, { target }),
      target.length * 3 + 16,
    );
  }

  // -------------------------------------------------------------------------
  // moving and removing: rename, renameat, unlinkat, remove
  // -------------------------------------------------------------------------

  /**
   * The rename both messages perform: move the tree, then move the fids.
   *
   * {@link FidTable.remap} is what keeps a client's open fids working across a
   * rename it did not perform — `mv` on a directory somebody is reading is not
   * exotic — and it is also what drops the identities under the *destination*,
   * whose files have just been replaced. That release is remap's, not this
   * caller's: doing it here as well would detach an identity the remap has
   * already rebound to the moved file.
   *
   * The byte-range locks move too, and table-wide rather than per session: the
   * file that moved is the same file to every client holding a range on it, and
   * a range left under the old name would guard whatever is created there next.
   *
   * Runs as the path lock's writer; see the dispatch.
   */
  async #renameTo(from: string, to: string): Promise<void> {
    await this.driver.rename(from, to);
    this.fids.remap(from, to);
    this.locks.renamed(from, to);
  }

  /** `Trename` — move what `fid` names to `name` under `dfid`. */
  async #rename(header: P9Header, request: Trename): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    const parent = this.fids.require(request.dfid);
    this.#requireWritable("rename", entry.path);
    await this.#renameTo(entry.path, this.#childOf(parent, request.name, "rename"));
    return this.#framed(header, P9_RRENAME);
  }

  /** `Trenameat` — the `renameat(2)` shape: two directories and two names. */
  async #renameat(header: P9Header, request: Trenameat): Promise<Uint8Array> {
    const oldDir = this.fids.require(request.olddirfid);
    const newDir = this.fids.require(request.newdirfid);
    this.#requireWritable("rename", oldDir.path);
    await this.#renameTo(
      this.#childOf(oldDir, request.oldname, "rename"),
      this.#childOf(newDir, request.newname, "rename"),
    );
    return this.#framed(header, P9_RRENAMEAT);
  }

  /**
   * `Tunlinkat` — `unlink`, or `rmdir` with `AT_REMOVEDIR`.
   *
   * The fid a client may hold on the removed file is **not** clunked: that is
   * `Tremove`'s job and this message's whole point of difference. What is
   * dropped is the *identity* — see `#released`.
   */
  async #unlinkat(header: P9Header, request: Tunlinkat): Promise<Uint8Array> {
    const directory = (request.flags & P9_DOTL_AT_REMOVEDIR) !== 0;
    const syscall = directory ? "rmdir" : "unlink";
    const parent = this.fids.require(request.dirfid);
    this.#requireWritable(syscall, parent.path);
    const path = this.#childOf(parent, request.name, syscall);
    await (directory ? this.driver.rmdir(path) : this.driver.unlink(path));
    this.#released(path);
    return this.#framed(header, P9_RUNLINKAT);
  }

  /**
   * `Tremove` — remove what the fid names, **and clunk it either way**.
   *
   * The clunk is unconditional and it is the protocol's rule, not a
   * simplification: 9P2000's `remove(5)` says the fid is clunked even if the
   * remove fails, and `p9_client_remove()` (v6.12) destroys its side of the fid
   * in the `error:` path as readily as in the successful one. A server that
   * kept the fid on failure would be holding one the client has already
   * forgotten, and nothing would ever come to clunk it. So the fid goes first,
   * synchronously, before anything can throw.
   *
   * Which call to make is the server's to work out — the message says "remove",
   * not "unlink" or "rmdir" — so it costs one `lstat`.
   */
  async #remove(header: P9Header, fid: number): Promise<Uint8Array> {
    const entry = this.fids.clunk(fid);
    this.locks.releaseFid(fid);
    this.#users.delete(fid);
    const handle = entry.open?.handle;
    entry.open = undefined;
    if (handle !== undefined) {
      await this.#closeQuietly(handle);
    }
    this.#requireWritable("remove", entry.path);
    const stats = await this.#statOf(entry.path);
    const directory = (stats.mode & S_IFMT) === S_IFDIR;
    await (directory ? this.driver.rmdir(entry.path) : this.driver.unlink(entry.path));
    this.#released(entry.path);
    return this.#framed(header, P9_RREMOVE);
  }

  /**
   * A path stopped existing: forget the `qid.path` bound to it.
   *
   * Without this a path that is removed and created again inherits the dead
   * file's identity, and the client — which caches pages and dentries against
   * `qid.path` — serves the old file's data for the new one. `FidTable.release`
   * keeps a hardlinked file's identity until its last name goes, so this is
   * safe to call for every removal.
   *
   * The byte ranges granted under that name go too, for the same reason in the
   * other direction: the lock table's only name for a file is its path, so a
   * range left under a name that has been reused would deny a file its holder
   * never locked. See `locks.ts` for what that costs the holder.
   */
  #released(path: string): void {
    this.fids.release(path);
    this.locks.released(path);
  }

  // -------------------------------------------------------------------------
  // locks
  // -------------------------------------------------------------------------

  /**
   * `Tlock` — take, upgrade, downgrade or release a byte range.
   *
   * The decision this reply makes is only ever about *another* client. The
   * client's own kernel does the POSIX-lock bookkeeping for its own processes —
   * `fs/9p` calls `locks_lock_file_wait()` before it ever sends a `Tlock` — so
   * a mount with one client behind it observes real locking whatever this says,
   * which is why the table starts empty per session and only a shared one (a
   * `createP9Server` with two connections on it) can ever refuse anything. See
   * `locks.ts` for who owns a range and why a conflict is `P9_LOCK_BLOCKED`
   * rather than a wait.
   *
   * Two fields of `Tlock` are deliberately not read. `flags` carries
   * `P9_LOCK_FLAGS_BLOCK`, which says what the client will do with a `BLOCKED`
   * answer (sleep and ask again) rather than asking the server to wait, and
   * `P9_LOCK_FLAGS_RECLAIM`, which the v6.12 client never sets and which there
   * is nothing here to reclaim against — no state survives a restart, so a
   * reclaim is served as an ordinary request rather than answered
   * `P9_LOCK_GRACE`. The fid is required, so a lock on a fid that does not
   * exist is still the client's bug and still `EBADF`; it need not be *open*,
   * because the only thing this needs from it is the path it names.
   *
   * Synchronous the whole way through — the table awaits nothing — so this runs
   * outside the path lock without a rename being able to move the path out from
   * under it mid-request.
   */
  async #setlk(header: P9Header, request: Tlock): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    const status = this.locks.lock({
      path: entry.path,
      fid: request.fid,
      type: request.type,
      start: request.start,
      length: request.length,
      procId: request.procId,
      clientId: request.clientId,
    });
    return this.#framed(header, P9_RLOCK, (writer) => writeRlock(writer, { status }), 16);
  }

  /**
   * `Tgetlock` — the lock that would deny this range, if there is one.
   *
   * A conflict answers with the holder's own type, range and identity, which is
   * the only way one client learns another exists: `p9_client_getlock_dotl()`
   * copies all of it into the caller's `flock`, with `l_pid` taken from
   * `proc_id`. No conflict answers `P9_LOCK_TYPE_UNLCK` and echoes the
   * request's own fields back, because that is what the client reads for "the
   * lock could be placed" and a reply that invented a range would describe a
   * lock nobody holds.
   */
  async #getlk(header: P9Header, request: Tgetlock): Promise<Uint8Array> {
    const entry = this.fids.require(request.fid);
    const conflict = this.locks.getlock({
      path: entry.path,
      fid: request.fid,
      type: request.type,
      start: request.start,
      length: request.length,
      procId: request.procId,
      clientId: request.clientId,
    });
    return this.#framed(
      header,
      P9_RGETLOCK,
      (writer) =>
        writeRgetlock(
          writer,
          conflict ?? {
            type: P9_LOCK_TYPE_UNLCK,
            start: request.start,
            length: request.length,
            procId: request.procId,
            clientId: request.clientId,
          },
        ),
      48,
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
