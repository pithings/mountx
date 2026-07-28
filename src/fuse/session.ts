/**
 * The FUSE session: bytes in, bytes out.
 *
 * This is the layer between the wire protocol and the driver interface, and it
 * owns everything IDEA.md lists under "What the library owns" — the `INIT`
 * handshake, the inode table and its lookup refcounting, the path↔inode map,
 * the file-handle table, readdir paging, and errno discipline.
 *
 * It touches **no I/O**: {@link FuseSession.handleMessage} takes one encoded
 * request and resolves to one encoded reply (or `null` for the two opcodes the
 * kernel does not want an answer to). The transport that carries those bytes
 * to and from `/dev/fuse` is a separate, much smaller thing — which is what
 * makes the whole session testable against a synthetic kernel, on any OS, with
 * no mount.
 *
 * Two invariants are load-bearing enough to state up front:
 *
 * - **Exactly one reply per request.** Every handler runs inside a catch-all
 *   that turns any thrown value into a negative errno (`errnoOf`, unknown →
 *   `EIO`). A request that never gets a reply is an unkillable `D`-state
 *   process, which is the worst failure mode in the system; a dev-mode
 *   assertion tracks it per `unique`.
 * - **`handleMessage` never rejects and never throws.** A malformed message
 *   that cannot even yield a `unique` is dropped; anything past that point is
 *   answered.
 *
 * Concurrency: the kernel keeps many requests in flight, so `handleMessage` may
 * be called again before an earlier call settles. Nothing is serialized by
 * default. The one exception is `RENAME`, which rewrites a whole subtree of the
 * path map and so takes a writer lock that concurrent path resolution waits on;
 * everything else runs as a reader. See {@link PathLock}.
 */

import { constants } from "node:fs";
import { fsError } from "../errors.ts";
import { createLoopback, type Loopback } from "../harness.ts";
import { PathLock } from "../lock.ts";
import { joinPath } from "../path.ts";
import type { DirentLike, FileHandleLike, FsDriver, StatsLike } from "../types.ts";
import {
  S_IFBLK,
  S_IFCHR,
  S_IFDIR,
  S_IFIFO,
  S_IFLNK,
  S_IFMT,
  S_IFREG,
  S_IFSOCK,
} from "../types.ts";
import {
  DT_UNKNOWN,
  FATTR_ATIME,
  FATTR_ATIME_NOW,
  FATTR_FH,
  FATTR_GID,
  FATTR_MODE,
  FATTR_MTIME,
  FATTR_MTIME_NOW,
  FATTR_SIZE,
  FATTR_UID,
  FOPEN_KEEP_CACHE,
  FUSE_BATCH_FORGET,
  FUSE_CREATE,
  FUSE_DEFAULT_MAX_PAGES_PER_REQ,
  FUSE_DESTROY,
  FUSE_FLUSH,
  FUSE_FORGET,
  FUSE_FSYNC,
  FUSE_FSYNC_FDATASYNC,
  FUSE_FSYNCDIR,
  FUSE_GETATTR,
  FUSE_GETATTR_FH,
  FUSE_INIT,
  FUSE_INTERRUPT,
  FUSE_LINK,
  FUSE_LOOKUP,
  FUSE_MKDIR,
  FUSE_MKNOD,
  FUSE_NOTIFY_REPLY,
  FUSE_OPEN,
  FUSE_OPENDIR,
  FUSE_PAGE_SIZE,
  FUSE_READ,
  FUSE_READDIR,
  FUSE_READDIRPLUS,
  FUSE_READLINK,
  FUSE_RELEASE,
  FUSE_RELEASEDIR,
  FUSE_RENAME,
  FUSE_RENAME2,
  FUSE_RMDIR,
  FUSE_SETATTR,
  FUSE_STATFS,
  FUSE_SYMLINK,
  FUSE_UNLINK,
  FUSE_WRITE,
  O_TRUNC,
  opcodeName,
} from "./constants.ts";
import { negotiateInit, type InitPreferences, type NegotiatedSession } from "./init.ts";
import { INODE_GENERATION, InodeTable, type Inode } from "./inodes.ts";
import {
  encodeNotifyInvalEntry,
  encodeNotifyInvalInode,
  type FuseNotifyInvalEntryOut,
  type FuseNotifyInvalInodeOut,
} from "./notify.ts";
import {
  decodeInHeader,
  decodeRequest,
  direntPlusSize,
  direntSize,
  direntType,
  DirentPacker,
  encodeErrorReply,
  encodeErrorReplyFor,
  encodeReply,
  encodeReplyFor,
  nameByteLength,
  type FuseAttr,
  type FuseAttrOut,
  type FuseBatchForgetIn,
  type FuseCreateIn,
  type FuseCreateOut,
  type FuseEntryOut,
  type FuseFlushIn,
  type FuseForgetIn,
  type FuseFsyncIn,
  type FuseGetattrIn,
  type FuseInHeader,
  type FuseInitIn,
  type FuseKstatfs,
  type FuseLinkIn,
  type FuseMkdirIn,
  type FuseMknodIn,
  type FuseNameIn,
  type FuseOpenIn,
  type FuseOpenOut,
  type FuseReadIn,
  type FuseReleaseIn,
  type FuseRename2In,
  type FuseRenameIn,
  type FuseRequest,
  type FuseSetattrIn,
  type FuseSymlinkIn,
  type FuseWriteIn,
  type FuseWriteOut,
  type ProtocolContext,
} from "./protocol.ts";

/**
 * Cache lifetimes handed to the kernel, in seconds.
 *
 * Generous on purpose (IDEA.md, "Performance"): a mount whose only writer is
 * the driver behind it can hold entries and attributes for a long time, and the
 * saving beats any JS-side optimization. A driver over storage that *other*
 * writers touch — the `node:fs` passthrough, say — should lower these, or
 * invalidate explicitly with {@link FuseSession.notifyInvalInode}.
 */
export const DEFAULT_ATTR_TIMEOUT = 10;
export const DEFAULT_ENTRY_TIMEOUT = 10;

/** `RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT` — none supported. */
const RENAME_FLAGS_UNSUPPORTED = 0b111;

export interface FuseSessionOptions {
  /** Passed to `negotiateInit` when the kernel's `FUSE_INIT` arrives. */
  init?: InitPreferences;
  /** Seconds the kernel may cache attributes. Default {@link DEFAULT_ATTR_TIMEOUT}. */
  attrTimeout?: number;
  /** Seconds the kernel may cache name→inode. Default {@link DEFAULT_ENTRY_TIMEOUT}. */
  entryTimeout?: number;
  /** Reply `FOPEN_KEEP_CACHE`, so the kernel keeps page cache across opens. Default `true`. */
  keepCache?: boolean;
  /**
   * Seconds the kernel may cache a *failed* lookup, as a `nodeid: 0` entry
   * rather than `-ENOENT`.
   *
   * **Default `0`, i.e. off**, which is also libfuse's default. It is a real
   * saving for a build that stats hundreds of missing headers, and a real
   * hazard for any driver whose storage has other writers: a file created out
   * of band stays invisible for the whole timeout. Opt in per mount.
   */
  negativeTimeout?: number;
  /** Identify files by the driver's `(dev, ino)`, so hardlinks share a nodeid. Default `true`. */
  useDriverIno?: boolean;
  /** Run the reply-exactly-once assertions. Default on outside production. */
  debug?: boolean;
  /** Called for every request that ends in an error reply. */
  onError?: (error: unknown, request: FuseRequest | undefined) => void;
  /** Called when a dev-mode assertion fails. Default: collect in `assertions`. */
  onAssertion?: (message: string) => void;
}

/** Counters, all of them cheap, all of them useful in a test. */
export interface SessionStats {
  /** Messages handed to {@link FuseSession.handleMessage}. */
  requests: number;
  /** Replies produced (successful or not). */
  replies: number;
  /** Of which negative-errno replies. */
  errors: number;
  /** Requests the kernel wants no answer to (`FORGET`, `BATCH_FORGET`). */
  noReply: number;
  /** Messages too malformed to even carry a `unique`, so silently dropped. */
  dropped: number;
  /** Dev-mode assertion failures. Must be zero. */
  assertions: number;
}

/** One entry of an open directory's snapshot. */
interface SnapshotEntry {
  name: string;
  /** `DT_*`. */
  type: number;
}

/** Per-`OPENDIR` state: the listing is snapshotted so offsets stay stable. */
interface DirState {
  /** Taken lazily, and again whenever the kernel rewinds to offset 0. */
  entries: SnapshotEntry[] | undefined;
}

/** One entry of the file-handle table. */
interface OpenFile {
  fh: bigint;
  inode: Inode;
  /** Raw `O_*` flags the kernel opened with. */
  flags: number;
  /**
   * Real per-open state, when the driver has any. `undefined` means the driver
   * does not declare `handles`, and every operation re-opens from the path.
   */
  handle: FileHandleLike | undefined;
  dir: DirState | undefined;
}

function splitSeconds(seconds: number): { sec: bigint; nsec: number } {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return { sec: 0n, nsec: 0 };
  }
  const whole = Math.floor(seconds);
  return {
    sec: BigInt(whole),
    nsec: Math.min(999_999_999, Math.round((seconds - whole) * 1e9)),
  };
}

/** Milliseconds-since-epoch (possibly fractional) to POSIX seconds + nanoseconds. */
function splitMs(ms: number): { sec: bigint; nsec: number } {
  if (!Number.isFinite(ms)) {
    return { sec: 0n, nsec: 0 };
  }
  const sec = Math.floor(ms / 1000);
  const nsec = Math.min(999_999_999, Math.max(0, Math.round((ms - sec * 1000) * 1e6)));
  return { sec: BigInt(sec), nsec };
}

function toUnsigned(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.trunc(value)) >>> 0 : 0;
}

function toBigUint(value: number): bigint {
  return Number.isFinite(value) ? BigInt(Math.max(0, Math.trunc(value))) : 0n;
}

/** A 64-bit wire offset as a `number`, or `EINVAL` when it cannot be one. */
function toOffset(value: bigint, syscall: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw fsError("EINVAL", { syscall, message: `EINVAL: offset ${value} is out of range` });
  }
  return Number(value);
}

/** `DT_*` for a `Dirent`, which is all a plain `READDIR` needs. */
function direntTypeOf(entry: DirentLike): number {
  if (entry.isFile()) {
    return direntType(S_IFREG);
  }
  if (entry.isDirectory()) {
    return direntType(S_IFDIR);
  }
  if (entry.isSymbolicLink()) {
    return direntType(S_IFLNK);
  }
  if (entry.isFIFO()) {
    return direntType(S_IFIFO);
  }
  if (entry.isSocket()) {
    return direntType(S_IFSOCK);
  }
  if (entry.isBlockDevice()) {
    return direntType(S_IFBLK);
  }
  if (entry.isCharacterDevice()) {
    return direntType(S_IFCHR);
  }
  return DT_UNKNOWN;
}

/** A name the kernel should never send, and that must never reach a driver. */
/**
 * Bytes in one path component, and the `namelen` every `STATFS` reply carries.
 *
 * The kernel does **not** enforce this for us: `fuse_lookup_name` only rejects
 * names longer than `FUSE_NAME_MAX` (1024), on the assumption that the server
 * knows its own limit. So a driver with no limit of its own — an in-memory one,
 * say — will happily create a 300-byte name that the same mount then reports as
 * impossible in `statfs`, and `chmod` on a too-long name answers `ENOENT` where
 * POSIX says `ENAMETOOLONG` (found by pjdfstest, every `02.t`). Enforcing it
 * here is what makes the two answers agree; a driver whose own limit is lower
 * still gets to say so first.
 */
const NAME_MAX = 255;

function checkName(name: string, syscall: string): string {
  if (name.length === 0 || name.includes("/") || name === "." || name === "..") {
    throw fsError("EINVAL", { syscall, message: `EINVAL: bad entry name '${name}'` });
  }
  if (nameByteLength(name) > NAME_MAX) {
    throw fsError("ENAMETOOLONG", { syscall, message: `ENAMETOOLONG: entry name '${name}'` });
  }
  return name;
}

const ZERO_ATTR: FuseAttr = {
  ino: 0n,
  size: 0n,
  blocks: 0n,
  atime: 0n,
  mtime: 0n,
  ctime: 0n,
  atimensec: 0,
  mtimensec: 0,
  ctimensec: 0,
  mode: 0,
  nlink: 0,
  uid: 0,
  gid: 0,
  rdev: 0,
  blksize: 0,
  flags: 0,
};

/**
 * A `fuse_entry_out` the kernel will ignore: `nodeid == 0` means "no attributes
 * for this name", and the kernel neither caches it nor counts a lookup for it.
 * That is exactly what `.` and `..` want in a `READDIRPLUS` page.
 */
const IGNORED_ENTRY: FuseEntryOut = {
  nodeid: 0n,
  generation: 0n,
  entryValid: 0n,
  attrValid: 0n,
  entryValidNsec: 0,
  attrValidNsec: 0,
  attr: ZERO_ATTR,
};

/**
 * A FUSE session over a driver.
 *
 * ```ts
 * const session = new FuseSession(createMemoryDriver());
 * const reply = await session.handleMessage(requestBytes); // Uint8Array | null
 * ```
 */
export class FuseSession {
  /** The driver, wrapped so paths are normalized and gaps answer `ENOSYS`. */
  readonly driver: Loopback;
  readonly options: FuseSessionOptions;
  readonly stats: SessionStats = {
    requests: 0,
    replies: 0,
    errors: 0,
    noReply: 0,
    dropped: 0,
    assertions: 0,
  };
  /** Dev-mode assertion failures, in order. Empty in a healthy session. */
  readonly assertions: string[] = [];

  readonly #inodes: InodeTable;
  readonly #files = new Map<bigint, OpenFile>();
  readonly #inflight = new Set<bigint>();
  readonly #lock = new PathLock();
  readonly #debug: boolean;
  #negotiated: NegotiatedSession | undefined;
  #destroyed = false;
  #nextFh = 1n;

  constructor(driver: FsDriver, options: FuseSessionOptions = {}) {
    this.driver = createLoopback(driver);
    this.options = options;
    this.#inodes = new InodeTable({ useDriverIno: options.useDriverIno });
    this.#debug = options.debug ?? process.env.NODE_ENV !== "production";
  }

  /** What `FUSE_INIT` agreed on, or `undefined` before the handshake. */
  get negotiated(): NegotiatedSession | undefined {
    return this.#negotiated;
  }

  /** The codec context for this session (7.41 defaults before `INIT`). */
  get protocol(): ProtocolContext | undefined {
    return this.#negotiated?.protocol;
  }

  /** `true` once `FUSE_DESTROY` arrived or {@link destroy} was called. */
  get destroyed(): boolean {
    return this.#destroyed;
  }

  /** The inode table, for tests and for transports that want to notify. */
  get inodes(): InodeTable {
    return this.#inodes;
  }

  /** Open file and directory handles. */
  get openHandles(): number {
    return this.#files.size;
  }

  // -------------------------------------------------------------------------
  // notifications
  // -------------------------------------------------------------------------

  /**
   * Encode a `FUSE_NOTIFY_INVAL_INODE` message for the transport to write.
   *
   * Nothing is wired to this yet — it exists so the notify path is designed
   * with the session rather than bolted onto the transport later.
   */
  notifyInvalInode(ino: bigint, off = -1n, len = 0n): Uint8Array {
    return encodeNotifyInvalInode({ ino, off, len } satisfies FuseNotifyInvalInodeOut);
  }

  /** Encode a `FUSE_NOTIFY_INVAL_ENTRY` message for the transport to write. */
  notifyInvalEntry(parent: bigint, name: string, flags = 0): Uint8Array {
    return encodeNotifyInvalEntry({ parent, name, flags } satisfies FuseNotifyInvalEntryOut);
  }

  // -------------------------------------------------------------------------
  // lifecycle
  // -------------------------------------------------------------------------

  /**
   * Handle one encoded request.
   *
   * Resolves to the encoded reply, or `null` when the kernel wants none
   * (`FORGET`, `BATCH_FORGET`, `NOTIFY_REPLY`) or the message was too damaged
   * to answer. **Never rejects.**
   */
  async handleMessage(message: Uint8Array): Promise<Uint8Array | null> {
    this.stats.requests++;
    let header: FuseInHeader;
    try {
      header = decodeInHeader(message);
    } catch {
      this.stats.dropped++;
      return null;
    }
    // `unique == 0` marks a notification, server → kernel. A "request" carrying
    // it cannot be answered: the reply would read as a notification.
    if (header.unique === 0n || header.len > message.length) {
      this.stats.dropped++;
      return null;
    }
    if (header.opcode === FUSE_FORGET || header.opcode === FUSE_BATCH_FORGET) {
      return this.#handleNoReply(message, header);
    }
    // The kernel's answer to its own `notify_retrieve`; libfuse does not reply
    // to it either. We never send one, so this is belt and braces.
    if (header.opcode === FUSE_NOTIFY_REPLY) {
      this.stats.noReply++;
      return null;
    }

    if (this.#debug && this.#inflight.has(header.unique)) {
      this.#assert(`unique ${header.unique} is already in flight (${opcodeName(header.opcode)})`);
    }
    this.#inflight.add(header.unique);
    try {
      let request: FuseRequest;
      try {
        request = decodeRequest(message, this.protocol);
      } catch {
        // A body we cannot parse is the kernel's problem, not a reason to hang
        // the mount: answer, and let it decide.
        return this.#fail(
          header.unique,
          fsError("EINVAL", { message: "EINVAL: undecodable request body" }),
          undefined,
        );
      }
      let reply: Uint8Array | null;
      try {
        reply = await this.#dispatch(request);
      } catch (error) {
        return this.#fail(header.unique, error, request);
      }
      /* v8 ignore next 4 -- unreachable by construction: every branch of
         `#dispatch` returns bytes. The assertion is the point — if that ever
         stops being true, the mount hangs rather than merely failing. */
      if (reply === null) {
        this.#assert(`${opcodeName(header.opcode)} produced no reply`);
        return this.#fail(header.unique, fsError("EIO"), request);
      }
      this.stats.replies++;
      return reply;
    } finally {
      this.#inflight.delete(header.unique);
    }
  }

  /**
   * Tear the session down: close every open handle and drop every inode.
   *
   * **The transport must call this itself.** A `-t fuse` mount never receives
   * `FUSE_DESTROY` — `fuse_init_fs_context` sets `ctx->destroy` only for
   * `fuseblk`, so an ordinary `umount(8)` simply stops the device (verified
   * against a live mount, where `STATFS` was the last opcode seen). Teardown
   * therefore belongs to whoever notices the `/dev/fuse` fd hit EOF or
   * `ENODEV`.
   *
   * Idempotent, safe to call concurrently with requests in flight, and safe to
   * call whether or not `DESTROY` ever arrived.
   */
  async destroy(): Promise<void> {
    this.#destroyed = true;
    const files = [...this.#files.values()];
    this.#files.clear();
    for (const file of files) {
      try {
        await file.handle?.close();
      } catch (error) {
        this.options.onError?.(error, undefined);
      }
    }
    this.#inodes.clear();
  }

  // -------------------------------------------------------------------------
  // dispatch
  // -------------------------------------------------------------------------

  async #dispatch(request: FuseRequest): Promise<Uint8Array | null> {
    const { opcode, unique } = request.header;
    if (opcode === FUSE_INIT) {
      return this.#init(request);
    }
    // libfuse answers anything before the handshake `-EIO`, and so do we: the
    // codecs cannot know which struct layout to use until `INIT` says.
    if (this.#negotiated === undefined) {
      return encodeErrorReply(unique, "EIO");
    }
    if (this.#destroyed) {
      return encodeErrorReply(unique, "ENODEV");
    }

    switch (opcode) {
      // Only a `fuseblk` mount ever sends this; a plain `-t fuse` umount just
      // stops the device, and the transport calls `destroy()` on EOF instead.
      // Handled anyway because answering it is one line and *not* answering it
      // blocks `umount` forever on the mounts that do send it.
      case FUSE_DESTROY: {
        this.#destroyed = true;
        await this.destroy();
        return encodeReply(unique);
      }
      // `INTERRUPT` gets the cheap correct answer: `-ENOSYS` tells the kernel
      // to stop sending them (IDEA.md). Real cancellation is a later feature.
      case FUSE_INTERRUPT: {
        return encodeErrorReply(unique, "ENOSYS");
      }
      case FUSE_LOOKUP: {
        return this.#read(() => this.#lookup(request));
      }
      case FUSE_GETATTR: {
        return this.#read(() => this.#getattr(request));
      }
      case FUSE_SETATTR: {
        return this.#read(() => this.#setattr(request));
      }
      case FUSE_READLINK: {
        return this.#read(async () =>
          encodeReplyFor(
            unique,
            opcode,
            { target: await this.driver.readlink(this.#pathOf(request)) },
            this.protocol,
          ),
        );
      }
      case FUSE_SYMLINK: {
        return this.#read(() => this.#symlink(request));
      }
      case FUSE_MKNOD: {
        return this.#read(() => this.#mknod(request));
      }
      case FUSE_MKDIR: {
        return this.#read(() => this.#mkdir(request));
      }
      case FUSE_UNLINK: {
        return this.#read(() => this.#remove(request, false));
      }
      case FUSE_RMDIR: {
        return this.#read(() => this.#remove(request, true));
      }
      case FUSE_RENAME:
      case FUSE_RENAME2: {
        return this.#lock.write(() => this.#rename(request));
      }
      case FUSE_LINK: {
        return this.#read(() => this.#link(request));
      }
      case FUSE_OPEN: {
        return this.#read(() => this.#open(request));
      }
      case FUSE_CREATE: {
        return this.#read(() => this.#create(request));
      }
      case FUSE_OPENDIR: {
        return this.#read(() => this.#opendir(request));
      }
      // READ and WRITE deliberately run outside the lock: they are the two
      // requests a driver can block on for an unbounded time, and holding a
      // reader across one would let a single stuck read freeze every rename,
      // and with it the mount. They reach the path map only through
      // `#withHandle`'s re-open for drivers with no per-open state, which takes
      // the reader lock for that step on its own.
      case FUSE_READ: {
        return this.#readFile(request);
      }
      case FUSE_WRITE: {
        return this.#write(request);
      }
      case FUSE_READDIR:
      case FUSE_READDIRPLUS: {
        return this.#read(() => this.#readdir(request, opcode === FUSE_READDIRPLUS));
      }
      case FUSE_RELEASE:
      case FUSE_RELEASEDIR: {
        return this.#release(request);
      }
      case FUSE_FLUSH: {
        // Nothing to do: `flush` is not `fsync`, and a driver's write is
        // already durable by the time it resolves. Answering success (rather
        // than `ENOSYS`) keeps `close(2)` error reporting available later.
        this.#requireFile((request.body as FuseFlushIn).fh, false);
        return encodeReply(unique);
      }
      case FUSE_FSYNC:
      case FUSE_FSYNCDIR: {
        return this.#fsync(request);
      }
      case FUSE_STATFS: {
        return this.#read(() => this.#statfs(request));
      }
      // Everything else is honestly unimplemented, and `-ENOSYS` is how a FUSE
      // server says so — the kernel stops asking. That covers locks, xattr,
      // ioctl, poll, lseek, fallocate, any opcode with no codec in this build,
      // and `ACCESS`: the mount asks the kernel to enforce mode bits
      // (`default_permissions`), so the driver never makes access decisions.
      default: {
        return encodeErrorReply(unique, "ENOSYS");
      }
    }
  }

  /** `FORGET` / `BATCH_FORGET`: bookkeeping only, and never a reply. */
  #handleNoReply(message: Uint8Array, header: FuseInHeader): null {
    this.stats.noReply++;
    let request: FuseRequest;
    try {
      request = decodeRequest(message, this.protocol);
    } catch {
      // Nothing to answer and nothing to account for: a `FORGET` we cannot
      // parse just means the kernel keeps a reference we would have dropped.
      return null;
    }
    if (header.opcode === FUSE_FORGET) {
      const { nlookup } = request.body as FuseForgetIn;
      this.#inodes.forget(header.nodeid, nlookup);
    } else {
      for (const forget of (request.body as FuseBatchForgetIn).forgets) {
        this.#inodes.forget(forget.nodeid, forget.nlookup);
      }
    }
    return null;
  }

  /** Run a handler as a reader: concurrent with everything but `RENAME`. */
  #read(fn: () => Promise<Uint8Array>): Promise<Uint8Array> {
    return this.#lock.read(fn);
  }

  /**
   * Turn any thrown value into a negative-errno reply.
   *
   * The last line of defence, so it takes no chances: `errnoOf` maps anything
   * it does not recognise to `EIO`, and even the encoding is guarded — a
   * failure *here* would be the one that hangs the mount.
   */
  #fail(unique: bigint, error: unknown, request: FuseRequest | undefined): Uint8Array {
    this.stats.replies++;
    this.stats.errors++;
    try {
      this.options.onError?.(error, request);
    } catch {
      // A logger is never allowed to cost a reply.
    }
    try {
      return encodeErrorReplyFor(unique, error);
      /* v8 ignore next 3 -- `errnoOf` always yields a number the encoder
         accepts; this is the reply that must exist even if that changes. */
    } catch {
      return encodeErrorReply(unique, "EIO");
    }
  }

  #assert(message: string): void {
    this.stats.assertions++;
    this.assertions.push(message);
    this.options.onAssertion?.(message);
  }

  // -------------------------------------------------------------------------
  // paths and attributes
  // -------------------------------------------------------------------------

  /** The primary path of the request's nodeid. `ESTALE` if it is a ghost. */
  #pathOf(request: FuseRequest): string {
    return this.#inodes.requirePath(request.header.nodeid);
  }

  /** `<primary path of nodeid>/<name>`, with the name validated. */
  #childOf(nodeid: bigint, name: string, syscall: string): string {
    return joinPath(this.#inodes.requirePath(nodeid), checkName(name, syscall));
  }

  #attrOf(inode: Inode, stats: StatsLike): FuseAttr {
    const atime = splitMs(stats.atimeMs);
    const mtime = splitMs(stats.mtimeMs);
    const ctime = splitMs(stats.ctimeMs);
    return {
      // Report the driver's own inode number when it has one: userspace uses
      // `st_ino` to spot hardlinks, and our nodeid is keyed on it anyway.
      ino: stats.ino > 0 ? toBigUint(stats.ino) : inode.nodeid,
      size: toBigUint(stats.size),
      blocks: toBigUint(stats.blocks),
      atime: atime.sec,
      mtime: mtime.sec,
      ctime: ctime.sec,
      atimensec: atime.nsec,
      mtimensec: mtime.nsec,
      ctimensec: ctime.nsec,
      mode: toUnsigned(stats.mode),
      // Verbatim, **including zero**. `nlink == 0` is how a filesystem says
      // "this inode has no names left, and is only alive because something has
      // it open" — `clear_nlink()` on the kernel side, and what `fstat(2)` on
      // an unlinked-but-open fd is expected to report. Clamping it to 1 makes
      // the mount disagree with every real filesystem for the whole
      // `mkstemp`+`unlink` pattern (found by the differential suite).
      nlink: toUnsigned(stats.nlink),
      uid: toUnsigned(stats.uid),
      gid: toUnsigned(stats.gid),
      rdev: toUnsigned(stats.rdev),
      blksize: toUnsigned(stats.blksize),
      flags: 0,
    };
  }

  #attrOut(inode: Inode, stats: StatsLike): FuseAttrOut {
    const valid = splitSeconds(this.options.attrTimeout ?? DEFAULT_ATTR_TIMEOUT);
    return { attrValid: valid.sec, attrValidNsec: valid.nsec, attr: this.#attrOf(inode, stats) };
  }

  #entryOut(inode: Inode, stats: StatsLike): FuseEntryOut {
    const attr = splitSeconds(this.options.attrTimeout ?? DEFAULT_ATTR_TIMEOUT);
    const entry = splitSeconds(this.options.entryTimeout ?? DEFAULT_ENTRY_TIMEOUT);
    return {
      nodeid: inode.nodeid,
      generation: INODE_GENERATION,
      entryValid: entry.sec,
      entryValidNsec: entry.nsec,
      attrValid: attr.sec,
      attrValidNsec: attr.nsec,
      attr: this.#attrOf(inode, stats),
    };
  }

  /**
   * `lstat`, falling back to `stat` for drivers that have no `lstat`.
   *
   * A nodeid names an inode, and an inode can be a symlink — so the attributes
   * the kernel wants are the link's own, never its target's.
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
   * Stat a freshly created path, bind it, and count the lookup the reply hands
   * out. With a `header`, the new inode is given to whoever asked for it first.
   */
  async #bindEntry(path: string, header?: FuseInHeader): Promise<FuseEntryOut> {
    if (header !== undefined) {
      await this.#claim(path, header);
    }
    const stats = await this.#statOf(path);
    const inode = this.#inodes.acquire(this.#inodes.bind(path, stats));
    return this.#entryOut(inode, stats);
  }

  /**
   * Give a newly created inode to the process that asked for it.
   *
   * **The driver creates everything as itself, and that is wrong for every
   * caller but one.** A FUSE server runs as one user (root, here) while the
   * requests arriving on it come from all of them — `fuse_in_header` carries
   * the caller's `uid`/`gid` precisely so the server can act on their behalf.
   * Nothing in the `FsDriver` interface can express that, so a driver's
   * `mkdir` or `open(O_CREAT)` necessarily produces something owned by the
   * daemon; without this step, a file `mkdir`ed by user 1000 comes back owned
   * by root, and then `default_permissions` denies its own creator every
   * subsequent operation on it.
   *
   * The consequences of getting this wrong are not subtle, and they are not
   * confined to ownership: pjdfstest's `EACCES` and `EPERM` cases fail *en
   * masse* (`open/06.t`, `open/07.t`, `chmod/07.t`, `chown/07.t`), because a
   * permission check against the wrong owner is a permission check against the
   * wrong answer.
   *
   * Deliberately skipped when the caller *is* the daemon — the overwhelmingly
   * common case, and one extra driver round-trip per create is worth avoiding
   * — and deliberately quiet when the driver has no `lchown` (`ENOSYS`) or is
   * not privileged enough to hand ownership away (`EPERM`): a driver with no
   * concept of ownership is not thereby broken.
   *
   * Two things this does **not** do, both of which want the credentials to
   * reach the driver properly rather than more patching here: supplementary
   * groups (only `gid` is on the wire before `FUSE_EXT_GROUPS`), and the
   * set-gid directory rule that gives a new entry its parent's group.
   */
  async #claim(path: string, header: FuseInHeader): Promise<void> {
    const uid = process.getuid?.() ?? -1;
    const gid = process.getgid?.() ?? -1;
    if (header.uid === uid && header.gid === gid) {
      return;
    }
    try {
      await this.driver.lchown(path, header.uid, header.gid);
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code !== "ENOSYS" && code !== "EPERM" && code !== "ENOTSUP") {
        throw error;
      }
    }
  }

  // -------------------------------------------------------------------------
  // handshake
  // -------------------------------------------------------------------------

  #init(request: FuseRequest): Uint8Array {
    const { unique } = request.header;
    if (this.#negotiated !== undefined) {
      return encodeErrorReply(unique, "EIO");
    }
    const negotiation = negotiateInit(request.body as FuseInitIn, this.options.init);
    if (negotiation.status === "error") {
      return encodeErrorReply(unique, -negotiation.errno);
    }
    if (negotiation.status === "ok") {
      this.#negotiated = negotiation.session;
    }
    // A `retry` reply is deliberately encoded with no context: the session has
    // not agreed on a version yet, and `encodeInitOut` sizes itself from the
    // `minor` it carries.
    return encodeReplyFor(unique, FUSE_INIT, negotiation.reply);
  }

  // -------------------------------------------------------------------------
  // namespace operations
  // -------------------------------------------------------------------------

  async #lookup(request: FuseRequest): Promise<Uint8Array> {
    const path = this.#childOf(request.header.nodeid, (request.body as FuseNameIn).name, "lookup");
    let stats: StatsLike;
    try {
      stats = await this.#statOf(path);
    } catch (error) {
      const timeout = this.options.negativeTimeout ?? 0;
      if (timeout <= 0 || (error as { code?: string }).code !== "ENOENT") {
        throw error;
      }
      // A negative entry: `nodeid == 0` says "nothing here", and the kernel
      // caches *that* for `entry_valid` instead of asking again.
      const valid = splitSeconds(timeout);
      return encodeReplyFor(
        request.header.unique,
        FUSE_LOOKUP,
        { ...IGNORED_ENTRY, entryValid: valid.sec, entryValidNsec: valid.nsec },
        this.protocol,
      );
    }
    const inode = this.#inodes.acquire(this.#inodes.bind(path, stats));
    return encodeReplyFor(
      request.header.unique,
      FUSE_LOOKUP,
      this.#entryOut(inode, stats),
      this.protocol,
    );
  }

  async #getattr(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseGetattrIn;
    const inode = this.#inodes.require(request.header.nodeid);
    const handle = this.#handleFor(
      inode,
      (body.getattrFlags & FUSE_GETATTR_FH) === 0 ? undefined : body.fh,
    );
    const stats =
      handle === undefined ? await this.#statOf(this.#inodes.pathOf(inode)) : await handle.stat();
    return encodeReplyFor(
      request.header.unique,
      FUSE_GETATTR,
      this.#attrOut(inode, stats),
      this.protocol,
    );
  }

  async #setattr(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseSetattrIn;
    const inode = this.#inodes.require(request.header.nodeid);
    const { valid } = body;
    const handle = this.#handleFor(inode, (valid & FATTR_FH) === 0 ? undefined : body.fh);
    // Resolved lazily: an `ftruncate` on an unlinked-but-open file has no path
    // to offer, and must not be failed for wanting one.
    const path = (): string => this.#inodes.pathOf(inode);

    // Every valid bit applies, in the order a shell would have issued them:
    // ownership and mode first, then the size, then the timestamps — so an
    // explicit `mtime` wins over the one the truncate just set.
    if ((valid & FATTR_MODE) !== 0) {
      await this.driver.chmod(path(), body.mode & 0o7777);
    }
    if ((valid & (FATTR_UID | FATTR_GID)) !== 0) {
      // `-1` is POSIX for "leave this one alone", and every driver's `chown`
      // inherits that from `node:fs`.
      const [uid, gid] = [
        (valid & FATTR_UID) === 0 ? -1 : body.uid,
        (valid & FATTR_GID) === 0 ? -1 : body.gid,
      ];
      await this.#nofollow(
        () => this.driver.lchown(path(), uid, gid),
        () => this.driver.chown(path(), uid, gid),
      );
    }
    if ((valid & FATTR_SIZE) !== 0) {
      const size = toOffset(body.size, "truncate");
      if (handle === undefined) {
        await this.driver.truncate(path(), size);
      } else {
        await handle.truncate(size);
      }
    }
    if ((valid & (FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW)) !== 0) {
      await this.#setTimes(path(), body);
    }

    const stats = handle === undefined ? await this.#statOf(path()) : await handle.stat();
    return encodeReplyFor(
      request.header.unique,
      FUSE_SETATTR,
      this.#attrOut(inode, stats),
      this.protocol,
    );
  }

  /**
   * Apply the time half of a `SETATTR`.
   *
   * `utimes` sets both stamps at once, so a request that names only one has to
   * read the other back first. Nanoseconds survive only if the driver has the
   * `mountx.utimens` extension; `fs.utimes` takes float seconds and loses
   * them (IDEA.md).
   */
  async #setTimes(path: string, body: FuseSetattrIn): Promise<void> {
    const nowMs = Date.now();
    const wantAtime = (body.valid & (FATTR_ATIME | FATTR_ATIME_NOW)) !== 0;
    const wantMtime = (body.valid & (FATTR_MTIME | FATTR_MTIME_NOW)) !== 0;
    let current: StatsLike | undefined;
    if (!wantAtime || !wantMtime) {
      current = await this.#statOf(path);
    }
    const atimeNs =
      (body.valid & FATTR_ATIME_NOW) !== 0
        ? BigInt(Math.round(nowMs * 1e6))
        : (body.valid & FATTR_ATIME) !== 0
          ? body.atime * 1_000_000_000n + BigInt(body.atimensec)
          : BigInt(Math.round(current!.atimeMs * 1e6));
    const mtimeNs =
      (body.valid & FATTR_MTIME_NOW) !== 0
        ? BigInt(Math.round(nowMs * 1e6))
        : (body.valid & FATTR_MTIME) !== 0
          ? body.mtime * 1_000_000_000n + BigInt(body.mtimensec)
          : BigInt(Math.round(current!.mtimeMs * 1e6));

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
   * Prefer the `AT_SYMLINK_NOFOLLOW` form of a metadata call, and fall back to
   * the following one for drivers that have no `l*` variant.
   *
   * **A `SETATTR` names an inode, never a path to resolve.** The kernel has
   * already walked the path and is telling us which inode to change — and that
   * inode can be a symlink, because `lutimes(2)` and `lchown(2)` exist. Calling
   * the following variant sets the times on the symlink's *target* instead,
   * which is wrong when the target exists and fails with `ENOENT` when it does
   * not. That second case is not exotic: `tar -xp` restores a symlink before
   * the file it points at and then stamps it, so every archive with a
   * forward-pointing symlink in it failed to extract (found by recording a
   * `tar -x` transcript). For everything that is not a symlink the two calls
   * are identical, so this needs no type check and costs no `lstat`.
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

  async #symlink(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseSymlinkIn;
    const path = this.#childOf(request.header.nodeid, body.name, "symlink");
    await this.driver.symlink(body.target, path);
    return encodeReplyFor(
      request.header.unique,
      request.header.opcode,
      await this.#bindEntry(path, request.header),
      this.protocol,
    );
  }

  /**
   * `MKNOD` — which the kernel also uses for plain files when the filesystem
   * has answered `CREATE` with `-ENOSYS`, so the regular-file case is worth
   * synthesizing from `open`. Anything else needs the `mountx.mknod`
   * extension.
   */
  async #mknod(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseMknodIn;
    const path = this.#childOf(request.header.nodeid, body.name, "mknod");
    const mknod = this.driver.mountx?.mknod;
    if (mknod !== undefined) {
      await mknod.call(this.driver.mountx, path, body.mode, body.rdev);
    } else if ((body.mode & S_IFMT) === S_IFREG || (body.mode & S_IFMT) === 0) {
      // Flags this server *originates*, so they are the host's: the driver
      // resolves them against `node:fs`, not against the FUSE wire.
      const handle = await this.driver.open(
        path,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
        body.mode & 0o7777,
      );
      await handle.close();
    } else {
      throw fsError("ENOSYS", { syscall: "mknod", path });
    }
    return encodeReplyFor(
      request.header.unique,
      request.header.opcode,
      await this.#bindEntry(path, request.header),
      this.protocol,
    );
  }

  async #mkdir(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseMkdirIn;
    const path = this.#childOf(request.header.nodeid, body.name, "mkdir");
    // The umask is already folded into `mode` unless `FUSE_DONT_MASK` was
    // negotiated, which it is not.
    await this.driver.mkdir(path, { mode: body.mode & 0o7777 });
    return encodeReplyFor(
      request.header.unique,
      request.header.opcode,
      await this.#bindEntry(path, request.header),
      this.protocol,
    );
  }

  /**
   * `UNLINK` / `RMDIR`.
   *
   * The inode is deliberately *not* dropped: it keeps its nodeid, loses this
   * path, and survives — orphaned if that was its last name — until the kernel
   * says `FORGET`. That is what makes an unlinked-but-open file keep working.
   */
  async #remove(request: FuseRequest, directory: boolean): Promise<Uint8Array> {
    const path = this.#childOf(
      request.header.nodeid,
      (request.body as FuseNameIn).name,
      directory ? "rmdir" : "unlink",
    );
    await (directory ? this.driver.rmdir(path) : this.driver.unlink(path));
    this.#inodes.unbind(path);
    return encodeReply(request.header.unique);
  }

  /** `RENAME` / `RENAME2`. The one operation that holds the writer lock. */
  async #rename(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseRenameIn | FuseRename2In;
    if ((("flags" in body ? body.flags : 0) & RENAME_FLAGS_UNSUPPORTED) !== 0) {
      // `-ENOSYS` is what makes the kernel fall back to a plain rename where it
      // can, rather than failing the syscall outright.
      return encodeErrorReply(request.header.unique, "ENOSYS");
    }
    const from = this.#childOf(request.header.nodeid, body.oldName, "rename");
    const to = this.#childOf(body.newdir, body.newName, "rename");
    await this.driver.rename(from, to);
    this.#inodes.remap(from, to);
    return encodeReply(request.header.unique);
  }

  /**
   * `LINK`: one inode, one more path.
   *
   * The reply carries the *existing* nodeid — the kernel is linking a new name
   * onto an inode it already knows, and would double-count it otherwise. That
   * falls out of identifying inodes by the driver's `(dev, ino)`.
   */
  async #link(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseLinkIn;
    const existing = this.#inodes.requirePath(body.oldnodeid);
    const path = this.#childOf(request.header.nodeid, body.name, "link");
    await this.driver.link(existing, path);
    return encodeReplyFor(
      request.header.unique,
      request.header.opcode,
      await this.#bindEntry(path),
      this.protocol,
    );
  }

  async #statfs(request: FuseRequest): Promise<Uint8Array> {
    const inode = this.#inodes.get(request.header.nodeid) ?? this.#inodes.root;
    const path = inode.paths.values().next().value ?? "/";
    const stats = await this.driver.statfs(path);
    const kstatfs: FuseKstatfs = {
      blocks: toBigUint(stats.blocks),
      bfree: toBigUint(stats.bfree),
      bavail: toBigUint(stats.bavail),
      files: toBigUint(stats.files),
      ffree: toBigUint(stats.ffree),
      bsize: toUnsigned(stats.bsize) || 4096,
      namelen: NAME_MAX,
      frsize: toUnsigned(stats.bsize) || 4096,
    };
    return encodeReplyFor(request.header.unique, FUSE_STATFS, kstatfs, this.protocol);
  }

  // -------------------------------------------------------------------------
  // file handles
  // -------------------------------------------------------------------------

  #addFile(inode: Inode, flags: number, handle: FileHandleLike | undefined, dir = false): OpenFile {
    const file: OpenFile = {
      fh: this.#nextFh++,
      inode,
      flags,
      handle,
      dir: dir ? { entries: undefined } : undefined,
    };
    this.#files.set(file.fh, file);
    return file;
  }

  /**
   * The handle a stat-shaped request should go through, if any.
   *
   * Two cases, and the second is the one Linux forces:
   *
   * - the kernel named an `fh` (`FUSE_GETATTR_FH` / `FATTR_FH`), so it is
   *   asking about that open file;
   * - the inode has **no path left**. `fuse_getattr` and `fuse_setattr` are
   *   `inode_operations` hooks, so a plain `fstat(2)` or `ftruncate(2)` on an
   *   unlinked-but-open file arrives with *no* `fh` at all — and answering
   *   `ENOENT` there breaks the entire open-then-unlink idiom (`mkstemp` +
   *   `unlink`, `sort`, `TemporaryFile`, `exec 3<f; rm f; cat <&3`). Any live
   *   handle on the inode can still describe it, so use one.
   *
   * A path-reachable inode deliberately keeps using its path: it is the
   * authoritative name, and a hardlink may have several.
   */
  #handleFor(inode: Inode, fh: bigint | undefined): FileHandleLike | undefined {
    if (fh !== undefined) {
      const named = this.#files.get(fh);
      if (named?.handle !== undefined) {
        return named.handle;
      }
    }
    if (inode.paths.size > 0) {
      return undefined;
    }
    for (const file of this.#files.values()) {
      if (file.inode === inode && file.handle !== undefined) {
        return file.handle;
      }
    }
    return undefined;
  }

  #requireFile(fh: bigint, directory: boolean): OpenFile {
    const file = this.#files.get(fh);
    if (file === undefined || (file.dir !== undefined) !== directory) {
      throw fsError("EBADF", { message: `EBADF: unknown file handle ${fh}` });
    }
    return file;
  }

  /**
   * Run something with a real `FileHandle`.
   *
   * A driver that declares `handles` gets the one it opened. One that does not
   * gets a fresh open per operation from the path — correct for everything the
   * kernel does (every read and write carries an explicit offset), and the
   * honest degradation for a driver with no per-open state.
   */
  async #withHandle<T>(file: OpenFile, fn: (handle: FileHandleLike) => Promise<T>): Promise<T> {
    if (file.handle !== undefined) {
      return fn(file.handle);
    }
    // This *does* resolve a path, so it takes the reader lock — but only for
    // the resolve and the open, never for the operation itself. Without it a
    // concurrent `RENAME` could move the file between `pathOf` and `open` and
    // fail a perfectly valid `fh` with `ENOENT`.
    const handle = await this.#lock.read(async () =>
      this.driver.open(this.#inodes.pathOf(file.inode), file.flags),
    );
    try {
      return await fn(handle);
    } finally {
      await this.#closeQuietly(handle);
    }
  }

  /**
   * Close a handle the kernel does not know about.
   *
   * Failing here is a diagnostic, never an errno: the request it belongs to has
   * already done its work, and the only handle whose close the kernel is
   * entitled to hear about is the one it asked to `RELEASE`.
   */
  async #closeQuietly(handle: FileHandleLike): Promise<void> {
    try {
      await handle.close();
    } catch (error) {
      this.options.onError?.(error, undefined);
    }
  }

  #openFlags(): number {
    return (this.options.keepCache ?? true) ? FOPEN_KEEP_CACHE : 0;
  }

  async #open(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseOpenIn;
    const inode = this.#inodes.require(request.header.nodeid);
    const path = this.#inodes.pathOf(inode);
    // `body.flags` is the kernel's, so it is inspected with the kernel's
    // constants; it is forwarded to the driver as-is, which is exact on Linux
    // (the only host this transport mounts on) and the reason the O_* values
    // live in `constants.ts` rather than coming from `node:fs`.
    const handle = await this.driver.open(path, body.flags);
    // `FUSE_ATOMIC_O_TRUNC` is negotiated, so the kernel hands `O_TRUNC` over
    // and expects *us* to have applied it — but nothing in the driver contract
    // promises `open()` honours the flag. Doing it explicitly is idempotent for
    // the drivers that already did, and the difference between `> file` working
    // and silently keeping the old contents for the ones that did not.
    if ((body.flags & O_TRUNC) !== 0) {
      try {
        await handle.truncate(0);
      } catch (error) {
        // N.B. no fh has been handed out yet, so nothing will ever release
        // this handle — the open has to be unwound here or it leaks.
        await this.#closeQuietly(handle);
        throw error;
      }
    }
    const keep = this.driver.capabilities.handles;
    if (!keep) {
      // No per-open state to keep, but the open still had to happen: it is what
      // reports `ENOENT`, `EISDIR` and the permission errors.
      await this.#closeQuietly(handle);
    }
    const file = this.#addFile(inode, body.flags, keep ? handle : undefined);
    const reply: FuseOpenOut = { fh: file.fh, openFlags: this.#openFlags(), backingId: 0 };
    return encodeReplyFor(request.header.unique, FUSE_OPEN, reply, this.protocol);
  }

  async #create(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseCreateIn;
    const path = this.#childOf(request.header.nodeid, body.name, "open");
    const handle = await this.driver.open(path, body.flags, body.mode & 0o7777);
    const keep = this.driver.capabilities.handles;
    if (!keep) {
      await this.#closeQuietly(handle);
    }
    let entry: FuseEntryOut;
    try {
      entry = await this.#bindEntry(path, request.header);
    } catch (error) {
      // The file exists but we cannot describe it, so there is no fh to hand
      // over and nothing that would ever release this handle.
      if (keep) {
        await this.#closeQuietly(handle);
      }
      throw error;
    }
    const inode = this.#inodes.require(entry.nodeid);
    const file = this.#addFile(inode, body.flags, keep ? handle : undefined);
    const reply: FuseCreateOut = {
      entry,
      open: { fh: file.fh, openFlags: this.#openFlags(), backingId: 0 },
    };
    return encodeReplyFor(request.header.unique, FUSE_CREATE, reply, this.protocol);
  }

  async #opendir(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseOpenIn;
    const inode = this.#inodes.require(request.header.nodeid);
    const stats = await this.#statOf(this.#inodes.pathOf(inode));
    if (!stats.isDirectory()) {
      throw fsError("ENOTDIR", { syscall: "opendir", path: this.#inodes.pathOf(inode) });
    }
    const file = this.#addFile(inode, body.flags, undefined, true);
    const reply: FuseOpenOut = { fh: file.fh, openFlags: 0, backingId: 0 };
    return encodeReplyFor(request.header.unique, FUSE_OPENDIR, reply, this.protocol);
  }

  async #release(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseReleaseIn;
    const file = this.#requireFile(body.fh, request.header.opcode === FUSE_RELEASEDIR);
    // Freed before the close can fail: a handle the kernel has released must
    // never be reachable again, whatever the driver says on the way out.
    this.#files.delete(file.fh);
    await file.handle?.close();
    return encodeReply(request.header.unique);
  }

  async #fsync(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseFsyncIn;
    const file = this.#requireFile(body.fh, request.header.opcode === FUSE_FSYNCDIR);
    if (file.dir === undefined) {
      const dataOnly = (body.fsyncFlags & FUSE_FSYNC_FDATASYNC) !== 0;
      await this.#withHandle(file, async (handle) => {
        const flush = dataOnly ? (handle.datasync ?? handle.sync) : handle.sync;
        await flush?.call(handle);
      });
    }
    return encodeReply(request.header.unique);
  }

  // -------------------------------------------------------------------------
  // reads and writes
  // -------------------------------------------------------------------------

  /**
   * The largest reply the kernel will accept for a `READ` / `READDIR`.
   *
   * This is the **read** budget — `max_pages * PAGE_SIZE`, or the fixed 32-page
   * default when `FUSE_MAX_PAGES` was not negotiated. It only coincides with
   * `max_write` at our defaults, and clamping a read by `max_write` would
   * silently truncate a reply, which userspace reads as EOF.
   *
   * Clamping at all is what keeps a bogus `fuse_read_in.size` from being an
   * out-of-memory rather than a protocol error. There is no floor: the budget
   * is at least one page by construction, and every caller also takes the
   * minimum with the size the kernel actually asked for.
   */
  #readBudget(): number {
    const pages = this.#negotiated?.maxPages || FUSE_DEFAULT_MAX_PAGES_PER_REQ;
    return pages * FUSE_PAGE_SIZE;
  }

  async #readFile(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseReadIn;
    const file = this.#requireFile(body.fh, false);
    const size = Math.min(body.size, this.#readBudget());
    const offset = toOffset(body.offset, "read");
    const buffer = new Uint8Array(size);
    const { bytesRead } = await this.#withHandle(file, (handle) =>
      handle.read(buffer, 0, size, offset),
    );
    return encodeReply(request.header.unique, buffer.subarray(0, Math.max(0, bytesRead)));
  }

  async #write(request: FuseRequest): Promise<Uint8Array> {
    const body = request.body as FuseWriteIn;
    const file = this.#requireFile(body.fh, false);
    const offset = toOffset(body.offset, "write");
    const { bytesWritten } = await this.#withHandle(file, (handle) =>
      handle.write(body.data, 0, body.data.length, offset),
    );
    const reply: FuseWriteOut = { size: bytesWritten };
    return encodeReplyFor(request.header.unique, FUSE_WRITE, reply, this.protocol);
  }

  // -------------------------------------------------------------------------
  // readdir
  // -------------------------------------------------------------------------

  /**
   * Snapshot a directory listing.
   *
   * `fs.readdir` returns everything at once and the kernel wants a byte-limited
   * page from an offset, so the listing is frozen per open directory and the
   * offsets are indices into it — stable for as long as the kernel pages
   * through, and refreshed when it rewinds to zero.
   */
  async #snapshot(file: OpenFile): Promise<SnapshotEntry[]> {
    const path = this.#inodes.pathOf(file.inode);
    const entries = await this.driver.readdir(path, { withFileTypes: true });
    return [
      { name: ".", type: direntType(S_IFDIR) },
      { name: "..", type: direntType(S_IFDIR) },
      ...entries.map((entry) => ({ name: entry.name, type: direntTypeOf(entry) })),
    ];
  }

  async #readdir(request: FuseRequest, plus: boolean): Promise<Uint8Array> {
    const body = request.body as FuseReadIn;
    const file = this.#requireFile(body.fh, true);
    const dir = file.dir!;
    const start = toOffset(body.offset, "readdir");
    if (start === 0 || dir.entries === undefined) {
      dir.entries = await this.#snapshot(file);
    }
    const entries = dir.entries;
    const path = this.#inodes.pathOf(file.inode);
    const packer = new DirentPacker(Math.min(body.size, this.#readBudget()), {
      plus,
      ctx: this.protocol,
    });

    for (let index = start; index < entries.length; index++) {
      const entry = entries[index]!;
      const nameLength = nameByteLength(entry.name);
      const needed = plus ? direntPlusSize(nameLength, this.protocol) : direntSize(nameLength);
      // Measure before doing any work: an entry that will not fit must not
      // allocate a nodeid, and must be handed to the next page untouched.
      if (needed > packer.remaining) {
        break;
      }
      // `.` and `..` go out with `nodeid == 0`: the kernel skips them for cache
      // linking, so counting a lookup for them would leak one forever.
      if (entry.name === "." || entry.name === "..") {
        packer.add(
          { ino: file.inode.nodeid, off: BigInt(index + 1), type: entry.type, name: entry.name },
          plus ? IGNORED_ENTRY : undefined,
        );
        continue;
      }
      const childPath = joinPath(path, entry.name);
      let stats: StatsLike | undefined;
      try {
        stats = await this.#statOf(childPath);
      } catch {
        // The entry vanished between the snapshot and now. Report the name with
        // no identity rather than failing the whole page.
        stats = undefined;
      }
      if (stats === undefined) {
        packer.add(
          { ino: 0n, off: BigInt(index + 1), type: entry.type, name: entry.name },
          plus ? IGNORED_ENTRY : undefined,
        );
        continue;
      }
      const inode = this.#inodes.bind(childPath, stats);
      const dirent = {
        ino: stats.ino > 0 ? toBigUint(stats.ino) : inode.nodeid,
        off: BigInt(index + 1),
        type: direntType(stats.mode),
        name: entry.name,
      };
      packer.add(dirent, plus ? this.#entryOut(inode, stats) : undefined);
      if (plus) {
        // READDIRPLUS folds a LOOKUP into every entry it reports, so every
        // entry that made it into the page owes a FORGET later.
        this.#inodes.acquire(inode);
      }
    }
    return encodeReply(request.header.unique, packer.build());
  }
}

/** Create a session over a driver. */
export function createFuseSession(driver: FsDriver, options?: FuseSessionOptions): FuseSession {
  return new FuseSession(driver, options);
}
