/**
 * The NFS session: one RPC record in, one RPC record out.
 *
 * This is the NFS analogue of `src/fuse/session.ts`, and the same rules apply:
 * it touches **no I/O** ({@link Nfs3Session.handleCall} takes bytes and resolves
 * to bytes), it never rejects, and every thrown driver error becomes a legal
 * `nfsstat3` rather than a dropped reply. The socket that carries those bytes
 * is `server.ts`, which is much smaller.
 *
 * What is different, and it is most of the design:
 *
 * - **There is no session.** NFSv3 is stateless: no handshake, no `open`, no
 *   `release`, no `FORGET`. Every request carries a file handle, and the server
 *   must be able to answer one it has never seen in this connection. Handles
 *   therefore live in a table with no lifetime rule (`handles.ts`) rather than
 *   in a refcounted inode table.
 * - **Two programs, one dispatcher.** MOUNT v3 (100005) hands out the root
 *   handle; NFS v3 (100003) does everything else. Both are answered here, and
 *   `server.ts` puts them on one port so no portmapper is needed.
 * - **Post-operation attributes are not optional in practice.** Every reply
 *   carries the attributes the client needs to keep its cache honest, and every
 *   mutating reply carries `wcc_data` (the directory's attributes from *before*
 *   the operation, plus its attributes after). A server that omits them is
 *   legal and makes clients re-`GETATTR` everything.
 * - **Writes are always `FILE_SYNC`.** The driver interface has whole-file
 *   semantics and no writeback of its own, so a `WRITE` that has resolved is
 *   already as durable as the driver can make it. Claiming `UNSTABLE` and then
 *   answering `COMMIT` would be an elaborate way to describe the same
 *   guarantee, and it would let a client believe data is buffered on a server
 *   that is not buffering it. `COMMIT` still exists and still succeeds, because
 *   clients send it regardless.
 */

import { constants } from "node:fs";
import { fsError } from "../../errors.ts";
import { createLoopback, type Loopback } from "../../harness.ts";
import { PathLock } from "../../lock.ts";
import { claimNewEntry, type NewEntry, newEntryOwnership } from "../../ownership.ts";
import { dirname, joinPath, normalizePath } from "../../path.ts";
import type { FileHandleLike, FsDriver, StatsLike, TimeLike } from "../../types.ts";
import { S_IFDIR, S_IFLNK, S_IFMT } from "../../types.ts";
import {
  ACCESS3_DELETE,
  ACCESS3_EXECUTE,
  ACCESS3_EXTEND,
  ACCESS3_LOOKUP,
  ACCESS3_MODIFY,
  ACCESS3_READ,
  AUTH_NONE,
  AUTH_SYS,
  AUTH_TOOWEAK,
  CREATE_EXCLUSIVE,
  CREATE_GUARDED,
  DONT_CHANGE,
  FILE_SYNC,
  FSF3_CANSETTIME,
  FSF3_HOMOGENEOUS,
  FSF3_LINK,
  FSF3_SYMLINK,
  MNT3_OK,
  MNT3ERR_ACCES,
  MNT3ERR_IO,
  MNT3ERR_NAMETOOLONG,
  MNT3ERR_NOENT,
  MNT3ERR_NOTDIR,
  MNT3ERR_PERM,
  MNT3_PATHLEN,
  MOUNT_PROGRAM,
  MOUNT_V3,
  MOUNTPROC3_DUMP,
  MOUNTPROC3_EXPORT,
  MOUNTPROC3_MNT,
  MOUNTPROC3_NULL,
  MOUNTPROC3_UMNT,
  MOUNTPROC3_UMNTALL,
  NFS3_COOKIEVERFSIZE,
  NFS3_CREATEVERFSIZE,
  NFS3_OK,
  NFS3_WRITEVERFSIZE,
  NFS3ERR_BAD_COOKIE,
  NFS3ERR_EXIST,
  NFS3ERR_NOTSUPP,
  NFS3ERR_NOT_SYNC,
  NFS3ERR_TOOSMALL,
  NFS_PROGRAM,
  NFS_V3,
  NFSPROC3_ACCESS,
  NFSPROC3_COMMIT,
  NFSPROC3_CREATE,
  NFSPROC3_FSINFO,
  NFSPROC3_FSSTAT,
  NFSPROC3_GETATTR,
  NFSPROC3_LINK,
  NFSPROC3_LOOKUP,
  NFSPROC3_MKDIR,
  NFSPROC3_MKNOD,
  NFSPROC3_NULL,
  NFSPROC3_PATHCONF,
  NFSPROC3_READ,
  NFSPROC3_READDIR,
  NFSPROC3_READDIRPLUS,
  NFSPROC3_READLINK,
  NFSPROC3_REMOVE,
  NFSPROC3_RENAME,
  NFSPROC3_RMDIR,
  NFSPROC3_SETATTR,
  NFSPROC3_SYMLINK,
  NFSPROC3_WRITE,
  RPC_GARBAGE_ARGS,
  RPC_PROC_UNAVAIL,
  RPC_PROG_MISMATCH,
  RPC_PROG_UNAVAIL,
  RPC_SYSTEM_ERR,
  RPC_VERSION,
  SET_TO_CLIENT_TIME,
  SET_TO_SERVER_TIME,
  procedureName,
} from "./constants.ts";
import {
  DirectorySnapshots,
  FH_SIZE,
  FileHandleTable,
  cookieVerifier,
  sameVerifier,
  type HandleEntry,
} from "../handles.ts";
import {
  credentialsOf,
  decodeCall,
  encodeAcceptError,
  encodeAuthError,
  encodeRpcMismatch,
  type RpcCall,
  type RpcCredentials,
  writeAcceptedReplyHeader,
} from "../rpc.ts";
import {
  entryPlusSize,
  entrySize,
  fattrOf,
  fromTime,
  nfsStatusOf,
  readAccessArgs,
  readCommitArgs,
  readCreateArgs,
  readDirOp,
  readLinkArgs,
  readMkdirArgs,
  readMknodArgs,
  readReadArgs,
  readReaddirArgs,
  readReaddirplusArgs,
  readRenameArgs,
  readSetattrArgs,
  readSymlinkArgs,
  readWriteArgs,
  wccAttrOf,
  writeAccessRes,
  writeCommitRes,
  writeCreateRes,
  writeExportList,
  writeFsinfoRes,
  writeFsstatRes,
  writeGetattrRes,
  writeLinkRes,
  writeMountList,
  writeMountRes,
  writePathconfRes,
  writeReadRes,
  writeReaddirRes,
  writeReaddirplusRes,
  writeReadlinkRes,
  writeLookupRes,
  writeRenameRes,
  writeWccRes,
  writeWriteRes,
  type Entry3,
  type EntryPlus3,
  type Fattr3,
  type Sattr3,
  type WccAttr,
  type WccData,
} from "./protocol.ts";
import {
  type AccessRights,
  allowedAccess,
  ExclusiveCreates,
  MAX_OFFSET,
  modeBitsOfFtype,
  NAME_MAX,
  newSessionStats,
  type NfsRequestContext,
  type NfsSessionOptions,
  type NfsSessionStats,
  type NfsSharedState,
} from "../util.ts";
import { XdrReader, XdrWriter, isXdrError, stringByteLength } from "../xdr.ts";

// The session contract and the version-neutral helpers moved to `../util.ts`
// when the v4 session needed them; they are re-exported here so that
// `v3/session.ts` remains the import site it has always been.
export { MAX_OFFSET } from "../util.ts";
export type { NfsRequestContext, NfsSessionOptions, NfsSessionStats } from "../util.ts";

/** Largest `READ` this server will answer, and `FSINFO`'s `rtmax`. */
export const DEFAULT_RTMAX = 1024 * 1024;
/** Largest `WRITE` this server will accept, and `FSINFO`'s `wtmax`. */
export const DEFAULT_WTMAX = 1024 * 1024;
/** Preferred `READDIR` reply size, and `FSINFO`'s `dtpref`. */
export const DEFAULT_DTPREF = 32 * 1024;

/**
 * Starting size of the one buffer a reply is built in.
 *
 * Every fixed-shape reply this server sends fits: the largest is `FSINFO`'s at
 * 128 bytes on top of the 24-byte accepted-reply header. The three that do not
 * have a fixed shape — `READ`, `READDIR`, `READDIRPLUS` — call
 * `XdrWriter.ensure()` once they know what they are about to write, and are
 * allocated exactly once. That is the whole of it: sizing a reply writer by
 * procedure was guesswork that got `READ` wrong by three orders of magnitude.
 */
const REPLY_CAPACITY = 256;

/**
 * Everything a `READ3resok` carries besides the payload: `status`, a
 * `post_op_attr` (its `bool` plus a 84-byte `fattr3`), `count`, `eof`, and the
 * `data<>` length word — 104 bytes at most, plus three of alignment.
 *
 * Rounded up to a flat 128 rather than computed exactly, which is a trade worth
 * naming now that `XdrWriter.view()` means reserved-and-unused capacity is
 * *retained*: under-reserving costs the grow this constant exists to avoid, and
 * over-reserving costs bytes held until the reply flushes. At 24 bytes on a
 * reply of any size that is the right side to err on — unlike reserving from
 * the client's `rsize`, where the error is the whole request.
 */
const READ_RES_OVERHEAD = 128;

/**
 * How many entries of one `READDIR`/`READDIRPLUS` page are resolved at once.
 *
 * A page is bounded in *bytes*, not in entries: a client asking for the whole
 * `rtmax` can name tens of thousands of them in a single request. So neither
 * extreme is right — one driver call after another makes a 5000-entry `ls`
 * 5000 serialized round trips (and on a driver like `unstorage` that is 5000
 * sequential downloads), while firing all of them at once trades that for a
 * threadpool with tens of thousands of jobs queued on it. A fixed window makes
 * the page one batch, which is the shape the cost actually has.
 */
const PAGE_CONCURRENCY = 64;

/** Resolve one value per name, at most {@link PAGE_CONCURRENCY} in flight. */
async function mapPage<T, R>(
  items: readonly T[],
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = Array.from<R>({ length: items.length });
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const index = next++;
      out[index] = await fn(items[index]!, index);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PAGE_CONCURRENCY, items.length) }, worker));
  return out;
}

/** A `nfsstat3` carried out of a handler. */
class NfsStatusError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "NfsStatusError";
    this.status = status;
  }
}

/**
 * A procedure number neither program has.
 *
 * It has to unwind past the handlers rather than encode a reply in place: the
 * answer is an RPC-level `PROC_UNAVAIL`, not a procedure result, and only the
 * dispatcher knows it must *not* be wrapped in an accepted reply.
 */
class ProcedureUnavailable extends Error {
  constructor(program: number, procedure: number) {
    super(`no procedure ${procedure} in program ${program}`);
    this.name = "ProcedureUnavailable";
  }
}

/** One live MOUNT registration, for `DUMP`. */
interface MountRecord {
  hostname: string;
  directory: string;
}

/**
 * An NFSv3 + MOUNTv3 server over a driver, with no socket.
 *
 * ```ts
 * const session = new Nfs3Session(createMemoryDriver());
 * const reply = await session.handleCall(rpcRecordBytes); // Uint8Array | null
 * ```
 */
export class Nfs3Session {
  /** The driver, wrapped so paths are normalized and gaps answer `ENOSYS`. */
  readonly driver: Loopback;
  readonly options: NfsSessionOptions;
  readonly handles: FileHandleTable;
  readonly stats: NfsSessionStats;
  /**
   * The `writeverf3` every `WRITE` and `COMMIT` reply carries.
   *
   * Constant for the life of the server, and different for the next one: that
   * is the whole protocol — a client that sees it change knows the server
   * restarted and that anything it had not committed is gone. Ours never had
   * anything uncommitted (every write is `FILE_SYNC`), but the client is
   * entitled to check.
   */
  readonly writeVerifier: Uint8Array;

  readonly #snapshots: DirectorySnapshots;
  readonly #lock: PathLock;
  readonly #mounts: MountRecord[] = [];
  /** The verifiers of `CREATE` with `EXCLUSIVE` — see `../util.ts`. */
  readonly #exclusives: ExclusiveCreates;
  #destroyed = false;

  /**
   * `shared` is the router's: one handle table, one path lock, one stats object
   * and one exclusive-create table across every version this server speaks.
   * Left out — which is what this session's own tests do — each is constructed
   * here instead.
   */
  constructor(driver: FsDriver, options: NfsSessionOptions = {}, shared: NfsSharedState = {}) {
    this.driver = createLoopback(driver);
    this.options = options;
    this.stats = shared.stats ?? newSessionStats();
    this.#lock = shared.lock ?? new PathLock();
    this.handles =
      shared.handles ??
      new FileHandleTable({
        useDriverIno: options.useDriverIno,
        verifier: options.verifier,
      });
    // Derived from the handle table's boot verifier, so both change together.
    this.writeVerifier = this.handles.verifier.slice(0, NFS3_WRITEVERFSIZE);
    this.#snapshots = new DirectorySnapshots(options.snapshotCache);
    this.#exclusives = shared.exclusiveCreates ?? new ExclusiveCreates();
  }

  /** MOUNT registrations currently outstanding, in order. */
  get mounts(): readonly MountRecord[] {
    return this.#mounts;
  }

  get destroyed(): boolean {
    return this.#destroyed;
  }

  /**
   * Answer one RPC record.
   *
   * Resolves to the encoded reply, or `null` for a record too damaged to carry
   * an xid — there is nothing to address a reply to. **Never rejects.**
   *
   * What comes back is a **view of the one buffer this call built its reply
   * in**, not a copy: the caller owns it outright, and nothing here writes
   * to it again. `../xdr.ts`'s `XdrWriter.view()` states the rule the
   * sessions keep to earn that.
   *
   * A direct caller must not overwrite `message` while the promise is
   * outstanding; everything the session *keeps* — names, `WRITE` payloads,
   * file handles — is copied out of it by the decoders. The transport never
   * has to think about it: `../rpc.ts`'s `RecordAssembler` hands over a record
   * copied out of the socket's buffers rather than a view of them.
   */
  async handleCall(
    message: Uint8Array,
    context: NfsRequestContext = {},
  ): Promise<Uint8Array | null> {
    this.stats.requests++;
    let call: RpcCall;
    let args: XdrReader;
    try {
      ({ call, args } = decodeCall(message));
    } catch {
      this.stats.dropped++;
      return null;
    }
    try {
      const reply = await this.#dispatch(call, args, context);
      this.stats.replies++;
      return reply;
      /* v8 ignore next 8 -- the handlers already catch everything; this is the
         reply that must exist even if one of them ever stops doing so. */
    } catch (error) {
      this.options.onError?.(error, call);
      this.stats.replies++;
      this.stats.errors++;
      return encodeAcceptError(call.xid, RPC_SYSTEM_ERR);
    }
  }

  /** Drop every handle and cached listing. Idempotent. */
  async destroy(): Promise<void> {
    this.#destroyed = true;
    this.handles.clear();
    this.#snapshots.clear();
    this.#exclusives.clear();
    this.#mounts.length = 0;
    await Promise.resolve();
  }

  // -------------------------------------------------------------------------
  // dispatch
  // -------------------------------------------------------------------------

  async #dispatch(call: RpcCall, args: XdrReader, context: NfsRequestContext): Promise<Uint8Array> {
    if (call.rpcVersion !== RPC_VERSION) {
      return encodeRpcMismatch(call.xid);
    }
    // Parsed, never verified — see the note at the top of `rpc.ts`. Anything
    // other than the two flavors a v3 client sends by default is refused,
    // because accepting a credential we cannot even decode would be a lie.
    if (call.cred.flavor !== AUTH_NONE && call.cred.flavor !== AUTH_SYS) {
      return encodeAuthError(call.xid, AUTH_TOOWEAK);
    }
    if (call.program !== NFS_PROGRAM && call.program !== MOUNT_PROGRAM) {
      return encodeAcceptError(call.xid, RPC_PROG_UNAVAIL);
    }
    const wanted = call.program === NFS_PROGRAM ? NFS_V3 : MOUNT_V3;
    if (call.version !== wanted) {
      return encodeAcceptError(call.xid, RPC_PROG_MISMATCH, { low: wanted, high: wanted });
    }
    this.#count(call);

    const creds = credentialsOf(call.cred);
    // One buffer for the whole reply: the accepted-reply header goes in first
    // and the handler appends its results straight after it, so what comes back
    // is a view of a single buffer rather than three of them concatenated. A
    // handler that knows the size of what it is about to write — `READ` once
    // the driver has answered, `READDIR` once its page is chosen — says so with
    // `writer.ensure()` and it is allocated exactly once. Each of those sizes
    // from the bytes it *has*, never from the ceiling the client named: this
    // buffer is handed to the socket as a view, so unused capacity is retained
    // rather than dropped.
    const writer = new XdrWriter(REPLY_CAPACITY);
    writeAcceptedReplyHeader(writer, call.xid);
    try {
      if (call.program === NFS_PROGRAM) {
        await this.#nfs(call, args, creds, writer);
      } else {
        await this.#mount(call, args, context, writer);
      }
    } catch (error) {
      // Only two things reach here: a decoder failure (every procedure handler
      // turns a *driver* error into a status of its own) and a procedure number
      // that does not exist. Both are answered at the RPC level — and with a
      // *fresh* buffer, because an accepted reply's header is not an error
      // reply's and whatever the handler managed to write is not part of one.
      if (isXdrError(error)) {
        this.options.onError?.(error, call);
        this.stats.errors++;
        return encodeAcceptError(call.xid, RPC_GARBAGE_ARGS);
      }
      if (error instanceof ProcedureUnavailable) {
        this.stats.errors++;
        return encodeAcceptError(call.xid, RPC_PROC_UNAVAIL);
      }
      throw error;
    }
    // A view, not a copy: `writer` is this call's alone and nothing writes to
    // it after this point. See `XdrWriter.view()` for the rule in full.
    return writer.view();
  }

  #count(call: RpcCall): void {
    const key = `${call.program === NFS_PROGRAM ? "NFS" : "MOUNT"}:${procedureName(
      call.program,
      call.procedure,
    )}`;
    this.stats.procedures.set(key, (this.stats.procedures.get(key) ?? 0) + 1);
  }

  /** Note a non-OK status, and hand the error to whoever is listening. */
  #failed(status: number, error?: unknown): number {
    if (status !== NFS3_OK) {
      this.stats.errors++;
      if (error !== undefined) {
        this.options.onError?.(error, undefined);
      }
    }
    return status;
  }

  // -------------------------------------------------------------------------
  // the NFS program
  // -------------------------------------------------------------------------

  async #nfs(
    call: RpcCall,
    args: XdrReader,
    creds: RpcCredentials,
    writer: XdrWriter,
  ): Promise<void> {
    switch (call.procedure) {
      case NFSPROC3_NULL: {
        args.end("NULL arguments");
        return;
      }
      case NFSPROC3_GETATTR: {
        return this.#read(() => this.#getattr(args, writer));
      }
      case NFSPROC3_SETATTR: {
        return this.#read(() => this.#setattr(args, writer));
      }
      case NFSPROC3_LOOKUP: {
        return this.#read(() => this.#lookup(args, writer));
      }
      case NFSPROC3_ACCESS: {
        return this.#read(() => this.#access(args, creds, writer));
      }
      case NFSPROC3_READLINK: {
        return this.#read(() => this.#readlink(args, writer));
      }
      // READ and WRITE stay outside the lock: they are the two requests a
      // driver can block on for an unbounded time, and holding a reader across
      // one would let a single stuck read freeze every rename behind it.
      case NFSPROC3_READ: {
        return this.#readFile(args, writer);
      }
      case NFSPROC3_WRITE: {
        return this.#write(args, writer);
      }
      case NFSPROC3_CREATE: {
        return this.#read(() => this.#create(args, creds, writer));
      }
      case NFSPROC3_MKDIR: {
        return this.#read(() => this.#mkdir(args, creds, writer));
      }
      case NFSPROC3_SYMLINK: {
        return this.#read(() => this.#symlink(args, creds, writer));
      }
      case NFSPROC3_MKNOD: {
        return this.#read(() => this.#mknod(args, creds, writer));
      }
      case NFSPROC3_REMOVE: {
        return this.#read(() => this.#remove(args, false, writer));
      }
      case NFSPROC3_RMDIR: {
        return this.#read(() => this.#remove(args, true, writer));
      }
      case NFSPROC3_RENAME: {
        return this.#lock.write(() => this.#rename(args, writer));
      }
      case NFSPROC3_LINK: {
        return this.#read(() => this.#link(args, writer));
      }
      case NFSPROC3_READDIR: {
        return this.#read(() => this.#readdir(args, writer));
      }
      case NFSPROC3_READDIRPLUS: {
        return this.#read(() => this.#readdirplus(args, writer));
      }
      case NFSPROC3_FSSTAT: {
        return this.#read(() => this.#fsstat(args, writer));
      }
      case NFSPROC3_FSINFO: {
        return this.#read(() => this.#fsinfo(args, writer));
      }
      case NFSPROC3_PATHCONF: {
        return this.#read(() => this.#pathconf(args, writer));
      }
      case NFSPROC3_COMMIT: {
        return this.#read(() => this.#commit(args, writer));
      }
      default: {
        throw new ProcedureUnavailable(call.program, call.procedure);
      }
    }
  }

  /** Run a handler as a reader: concurrent with everything but `RENAME`. */
  #read(fn: () => Promise<void>): Promise<void> {
    return this.#lock.read(fn);
  }

  // -------------------------------------------------------------------------
  // paths, attributes and the pieces every reply repeats
  // -------------------------------------------------------------------------

  /** `lstat`, falling back to `stat` for drivers with no `lstat`. */
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

  /** Bind a path to a handle and describe it. */
  async #attrOf(path: string): Promise<{ entry: HandleEntry; attr: Fattr3; stats: StatsLike }> {
    const stats = await this.#statOf(path);
    const entry = this.handles.bind(path, stats);
    return { entry, attr: this.#fattr(entry, stats), stats };
  }

  #fattr(entry: HandleEntry, stats: StatsLike): Fattr3 {
    // The driver's own `ino` when it has one — userspace uses `fileid` to spot
    // hardlinks, and the handle is keyed on it anyway. `bind` just refreshed it
    // from these very `stats`, so the entry is the one place it is spelled.
    return fattrOf(stats, entry.fileid);
  }

  /**
   * `post_op_attr` for a path, or `undefined`.
   *
   * Deliberately swallows every failure: a `post_op_attr` is a hint, and a
   * reply that fails because the *hint* could not be produced would turn a
   * successful operation into an error.
   */
  async #postOp(path: string | undefined): Promise<Fattr3 | undefined> {
    if (path === undefined) {
      return undefined;
    }
    try {
      return (await this.#attrOf(path)).attr;
    } catch {
      return undefined;
    }
  }

  /** The `before` half of a `wcc_data`, taken before the operation runs. */
  async #preOp(path: string): Promise<WccAttr | undefined> {
    const stats = await this.#preOpStats(path);
    return stats === undefined ? undefined : wccAttrOf(stats);
  }

  /**
   * The whole `lstat` behind {@link Nfs3Session.#preOp}, for the creating
   * operations: they need the parent's mode and gid for set-gid inheritance
   * (`#claim`) as well as the three fields a `wcc_attr` keeps, and this is the
   * `lstat` they were already paying for.
   *
   * Swallows the failure for the same reason `#preOp` does — a `wcc_data` is a
   * hint — and an unreadable parent then inherits nothing, which is what a
   * parent with the bit clear does too.
   */
  async #preOpStats(path: string): Promise<StatsLike | undefined> {
    try {
      return await this.#statOf(path);
    } catch {
      return undefined;
    }
  }

  async #wcc(before: WccAttr | undefined, path: string): Promise<WccData> {
    return { before, after: await this.#postOp(path) };
  }

  /** The path a handle names, or `ESTALE`. */
  #pathOf(fh: Uint8Array): string {
    return this.handles.resolve(fh);
  }

  /**
   * Drop the cached listing of a directory whose names just changed.
   *
   * The rule this implements — which directories, and only which — is written
   * down once, on `DirectorySnapshots` in `../handles.ts`. A directory nothing
   * has ever listed has no entry to drop, which is why the lookup is allowed to
   * miss.
   */
  #invalidate(dir: string | undefined): void {
    const entry = dir === undefined ? undefined : this.handles.at(dir);
    if (entry !== undefined) {
      this.#snapshots.delete(entry.id);
    }
  }

  #checkName(name: string, syscall: string): string {
    if (name.length === 0 || name.includes("/") || name === "." || name === "..") {
      throw fsError("EINVAL", { syscall, message: `EINVAL: bad entry name '${name}'` });
    }
    if (stringByteLength(name) > NAME_MAX) {
      throw fsError("ENAMETOOLONG", { syscall, message: `ENAMETOOLONG: entry name '${name}'` });
    }
    return name;
  }

  /** A 64-bit wire offset as a `number`, or `EINVAL` when it cannot be one. */
  #offset(value: bigint, syscall: string): number {
    if (value < 0n || value > MAX_OFFSET) {
      throw fsError("EINVAL", { syscall, message: `EINVAL: offset ${value} is out of range` });
    }
    return Number(value);
  }

  #rtmax(): number {
    return this.options.rtmax ?? DEFAULT_RTMAX;
  }

  #wtmax(): number {
    return this.options.wtmax ?? DEFAULT_WTMAX;
  }

  // -------------------------------------------------------------------------
  // GETATTR / SETATTR
  // -------------------------------------------------------------------------

  async #getattr(args: XdrReader, writer: XdrWriter): Promise<void> {
    const fh = args.varOpaque(64, "nfs_fh3");
    args.end("GETATTR arguments");
    try {
      const { attr } = await this.#attrOf(this.#pathOf(fh));
      writeGetattrRes(writer, { status: NFS3_OK, attributes: attr });
    } catch (error) {
      writeGetattrRes(writer, {
        status: this.#failed(statusOf(error), error),
        attributes: undefined,
      });
    }
    return;
  }

  async #setattr(args: XdrReader, writer: XdrWriter): Promise<void> {
    const request = readSetattrArgs(args);
    args.end("SETATTR arguments");
    let path: string | undefined;
    let before: WccAttr | undefined;
    try {
      path = this.#pathOf(request.object);
      const stats = await this.#statOf(path);
      before = wccAttrOf(stats);
      // `sattr_guard3`: the client is saying "only if nothing has changed since
      // the ctime I saw". Comparing at whole-second granularity is what the
      // wire format allows.
      if (
        request.guard !== undefined &&
        request.guard.seconds !== Math.floor(stats.ctimeMs / 1000)
      ) {
        throw new NfsStatusError(NFS3ERR_NOT_SYNC, "SETATTR guard does not match the ctime");
      }
      await this.#applySattr(path, request.attributes, { current: stats });
      // §3.3.8's commit: this is the SETATTR an `EXCLUSIVE` create sends the
      // client back for, and once it has landed the client is not going to
      // retry the create. See `ExclusiveCreates` in `../util.ts`.
      this.#exclusives.forget(path);
      writeWccRes(writer, { status: NFS3_OK, wcc: await this.#wcc(before, path) });
    } catch (error) {
      writeWccRes(writer, {
        status: this.#failed(statusOf(error), error),
        wcc: { before, after: await this.#postOp(path) },
      });
    }
    return;
  }

  /**
   * Apply an `sattr3` to a path, in the order a shell would have issued it:
   * ownership and mode first, then the size, then the timestamps — so an
   * explicit `mtime` wins over the one the truncate just set.
   *
   * `current` is the stat the caller already took, when it has one.
   */
  async #applySattr(
    path: string,
    attr: Sattr3,
    options: { current?: StatsLike | undefined; symlink?: boolean } = {},
  ): Promise<void> {
    const current = options.current;
    const isLink = options.symlink === true || ((current?.mode ?? 0) & S_IFMT) === S_IFLNK;
    if (attr.mode !== undefined && !isLink) {
      await this.driver.chmod(path, attr.mode & 0o7777);
    }
    if (attr.uid !== undefined || attr.gid !== undefined) {
      // `-1` is POSIX for "leave this one alone", inherited from `node:fs`.
      await this.#nofollow(
        () => this.driver.lchown(path, attr.uid ?? -1, attr.gid ?? -1),
        () => this.driver.chown(path, attr.uid ?? -1, attr.gid ?? -1),
      );
    }
    if (attr.size !== undefined) {
      await this.driver.truncate(path, this.#offset(attr.size, "truncate"));
    }
    const wantAtime = (attr.atime?.how ?? DONT_CHANGE) !== DONT_CHANGE;
    const wantMtime = (attr.mtime?.how ?? DONT_CHANGE) !== DONT_CHANGE;
    if (!wantAtime && !wantMtime) {
      return;
    }
    // `utimes` sets both at once, so a request naming only one has to read the
    // other back — and after a truncate, read it back *fresh*.
    const now = Date.now();
    const needsCurrent = !wantAtime || !wantMtime;
    const stats = !needsCurrent
      ? undefined
      : current !== undefined && attr.size === undefined
        ? current
        : await this.#statOf(path);
    const pick = (set: typeof attr.atime, fallbackMs: number): TimeLike =>
      set?.how === SET_TO_SERVER_TIME
        ? now / 1000
        : set?.how === SET_TO_CLIENT_TIME
          ? fromTime(set.time ?? { seconds: 0, nseconds: 0 }) / 1000
          : fallbackMs / 1000;
    const atime = pick(attr.atime, stats?.atimeMs ?? now);
    const mtime = pick(attr.mtime, stats?.mtimeMs ?? now);
    await this.#nofollow(
      () => this.driver.lutimes(path, atime, mtime),
      () => this.driver.utimes(path, atime, mtime),
    );
  }

  /**
   * Prefer the `AT_SYMLINK_NOFOLLOW` form of a metadata call.
   *
   * A file handle names an object, and that object can be a symlink — the
   * client resolves symlinks itself, so anything that reaches the server is
   * already the final component. Following it here would stamp the target
   * instead, which is wrong when it exists and `ENOENT` when it does not.
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
  // LOOKUP / ACCESS / READLINK
  // -------------------------------------------------------------------------

  async #lookup(args: XdrReader, writer: XdrWriter): Promise<void> {
    const request = readDirOp(args);
    args.end("LOOKUP arguments");
    let dir: string | undefined;
    try {
      dir = this.#pathOf(request.dir);
      // `.` and `..` are the two names a client may legitimately look up and
      // that no other operation accepts. `..` at the root is the root, which is
      // what `normalizePath` already does.
      const path =
        request.name === "."
          ? dir
          : request.name === ".."
            ? dirname(dir)
            : joinPath(dir, this.#checkName(request.name, "lookup"));
      const { entry, attr } = await this.#attrOf(path);
      writeLookupRes(writer, {
        status: NFS3_OK,
        object: this.handles.encode(entry),
        objAttributes: attr,
        dirAttributes: await this.#postOp(dir),
      });
    } catch (error) {
      writeLookupRes(writer, {
        status: this.#failed(statusOf(error), error),
        object: undefined,
        objAttributes: undefined,
        dirAttributes: await this.#postOp(dir),
      });
    }
    return;
  }

  /**
   * `ACCESS`: what this caller could do, by mode bits.
   *
   * The client asks because it is about to make a permission decision and NFS
   * gives it nothing else to decide with. The answer is computed from the
   * driver's mode/uid/gid against the `AUTH_SYS` credentials, which is exactly
   * as trustworthy as `AUTH_SYS` — the real enforcement is the socket, and the
   * kernel's own checks once the share is mounted. A driver with no permission
   * model reports mode `0` for everything, and then this correctly says "no",
   * which is why the bits are only masked *down* from what was asked.
   */
  async #access(args: XdrReader, creds: RpcCredentials, writer: XdrWriter): Promise<void> {
    const request = readAccessArgs(args);
    args.end("ACCESS arguments");
    try {
      const { attr, stats } = await this.#attrOf(this.#pathOf(request.object));
      writeAccessRes(writer, {
        status: NFS3_OK,
        attributes: attr,
        access: request.access & accessBits3(allowedAccess(stats, creds)),
      });
    } catch (error) {
      writeAccessRes(writer, {
        status: this.#failed(statusOf(error), error),
        attributes: undefined,
        access: 0,
      });
    }
    return;
  }

  async #readlink(args: XdrReader, writer: XdrWriter): Promise<void> {
    const fh = args.varOpaque(64, "nfs_fh3");
    args.end("READLINK arguments");
    let path: string | undefined;
    try {
      path = this.#pathOf(fh);
      const target = await this.driver.readlink(path);
      writeReadlinkRes(writer, {
        status: NFS3_OK,
        attributes: await this.#postOp(path),
        target,
      });
    } catch (error) {
      writeReadlinkRes(writer, {
        status: this.#failed(statusOf(error), error),
        attributes: await this.#postOp(path),
        target: undefined,
      });
    }
    return;
  }

  // -------------------------------------------------------------------------
  // READ / WRITE / COMMIT
  // -------------------------------------------------------------------------

  /**
   * Open, act, close.
   *
   * A stateless protocol has nowhere to keep an open file: the client never
   * said `open` and will never say `close`, so every `READ` and `WRITE` is its
   * own open. That is the honest implementation and it is what the driver
   * interface can express; a handle cache keyed on the file handle is the
   * obvious optimization and it is a benchmark-milestone concern, not a v1 one.
   */
  async #withFile<T>(
    path: string,
    flags: number,
    fn: (handle: FileHandleLike) => Promise<T>,
  ): Promise<T> {
    const handle = await this.driver.open(path, flags);
    try {
      return await fn(handle);
    } finally {
      try {
        await handle.close();
      } catch (error) {
        this.options.onError?.(error, undefined);
      }
    }
  }

  async #readFile(args: XdrReader, writer: XdrWriter): Promise<void> {
    const request = readReadArgs(args);
    args.end("READ arguments");
    let path: string | undefined;
    try {
      path = this.#pathOf(request.file);
      const offset = this.#offset(request.offset, "read");
      const count = Math.min(request.count, this.#rtmax());
      const buffer = new Uint8Array(count);
      const { bytesRead } = await this.#withFile(path, constants.O_RDONLY, (handle) =>
        handle.read(buffer, 0, count, offset),
      );
      const read = Math.max(0, bytesRead);
      // Sized from what the file *gave*, not from what the client asked for,
      // and only once that is known. The two differ by the whole request on a
      // short read — a 1 MiB `rsize` against the last 200 bytes of a file — and
      // `handleCall` returns a view of this buffer, so the difference would be
      // held by the socket's write queue until the reply flushed rather than
      // freed at the end of the call.
      writer.ensure(read + READ_RES_OVERHEAD);
      const attributes = await this.#postOp(path);
      writeReadRes(writer, {
        status: NFS3_OK,
        attributes,
        count: read,
        // A short read is only EOF if the file really ends there; the client
        // uses this to stop asking, so guessing would truncate files.
        eof: attributes === undefined ? read < count : BigInt(offset + read) >= attributes.size,
        data: buffer.subarray(0, read),
      });
    } catch (error) {
      writeReadRes(writer, {
        status: this.#failed(statusOf(error), error),
        attributes: await this.#postOp(path),
        count: 0,
        eof: false,
        data: new Uint8Array(0),
      });
    }
    return;
  }

  async #write(args: XdrReader, writer: XdrWriter): Promise<void> {
    const request = readWriteArgs(args, this.#wtmax());
    args.end("WRITE arguments");
    let path: string | undefined;
    let before: WccAttr | undefined;
    try {
      path = this.#pathOf(request.file);
      before = await this.#preOp(path);
      const offset = this.#offset(request.offset, "write");
      const { bytesWritten } = await this.#withFile(path, constants.O_WRONLY, (handle) =>
        handle.write(request.data, 0, request.data.byteLength, offset),
      );
      writeWriteRes(writer, {
        status: NFS3_OK,
        wcc: await this.#wcc(before, path),
        count: bytesWritten,
        // Always `FILE_SYNC` — see the module docs.
        committed: FILE_SYNC,
        verf: this.writeVerifier,
      });
    } catch (error) {
      writeWriteRes(writer, {
        status: this.#failed(statusOf(error), error),
        wcc: { before, after: await this.#postOp(path) },
        count: 0,
        committed: FILE_SYNC,
        verf: this.writeVerifier,
      });
    }
    return;
  }

  /**
   * `COMMIT`: nothing to do, and it still has to be here.
   *
   * Every write this server acknowledged was already `FILE_SYNC`, so there is
   * never anything outstanding to flush. Clients send `COMMIT` anyway (on
   * close, on `fsync`, at the end of a writeback run), and a server that
   * answered `NFS3ERR_NOTSUPP` would make every one of those fail.
   */
  async #commit(args: XdrReader, writer: XdrWriter): Promise<void> {
    const request = readCommitArgs(args);
    args.end("COMMIT arguments");
    let path: string | undefined;
    let before: WccAttr | undefined;
    try {
      path = this.#pathOf(request.file);
      before = await this.#preOp(path);
      writeCommitRes(writer, {
        status: NFS3_OK,
        wcc: await this.#wcc(before, path),
        verf: this.writeVerifier,
      });
    } catch (error) {
      writeCommitRes(writer, {
        status: this.#failed(statusOf(error), error),
        wcc: { before, after: await this.#postOp(path) },
        verf: this.writeVerifier,
      });
    }
    return;
  }

  // -------------------------------------------------------------------------
  // creation
  // -------------------------------------------------------------------------

  /**
   * The reply every creating operation shares: the new handle, its attributes,
   * and the parent directory's weak cache consistency data.
   */
  async #created(
    writer: XdrWriter,
    dir: string,
    before: WccAttr | undefined,
    path: string,
  ): Promise<void> {
    const { entry, attr } = await this.#attrOf(path);
    writeCreateRes(writer, {
      status: NFS3_OK,
      obj: this.handles.encode(entry),
      objAttributes: attr,
      dirWcc: await this.#wcc(before, dir),
    });
  }

  async #createFailed(
    writer: XdrWriter,
    dir: string | undefined,
    before: WccAttr | undefined,
    error: unknown,
  ): Promise<void> {
    writeCreateRes(writer, {
      status: this.#failed(statusOf(error), error),
      obj: undefined,
      objAttributes: undefined,
      dirWcc: { before, after: await this.#postOp(dir) },
    });
  }

  /**
   * Give a newly created object to whoever asked for it.
   *
   * The same fix as the FUSE session's: the driver creates everything as the
   * server process, and without this a file created by uid 1000 comes back
   * owned by the server and then fails every permission check its own creator
   * makes. Skipped when the caller *is* the server, and quiet when the driver
   * cannot express ownership — both in `claimNewEntry`.
   *
   * The group is not simply the caller's: a set-gid parent hands its own down,
   * and a new directory takes the bit with it (`../../ownership.ts` has the
   * rule and where it comes from). That is why `parent` is threaded in from the
   * `lstat` `#preOpStats` already did for the reply's `wcc_data` rather than
   * stat'ed here — every creating operation in this file reads the parent
   * anyway, so the rule costs no extra round trip. It does cost a `chmod` when
   * a new directory has to take the bit, which is the one case that cannot be
   * folded into the create.
   */
  async #claim(path: string, creds: RpcCredentials, entry: NewEntry): Promise<void> {
    if (this.options.claimOwnership === false) {
      return;
    }
    await claimNewEntry(this.driver, path, newEntryOwnership(creds, entry));
  }

  async #create(args: XdrReader, creds: RpcCredentials, writer: XdrWriter): Promise<void> {
    const request = readCreateArgs(args);
    args.end("CREATE arguments");
    let dir: string | undefined;
    let before: WccAttr | undefined;
    try {
      dir = this.#pathOf(request.where.dir);
      const path = joinPath(dir, this.#checkName(request.where.name, "open"));
      const parent = await this.#preOpStats(dir);
      before = parent === undefined ? undefined : wccAttrOf(parent);
      if (request.mode === CREATE_EXCLUSIVE) {
        await this.#createExclusive(dir, path, request.verf, creds, parent);
        await this.#created(writer, dir, before, path);
        return;
      }
      const mode = (request.attributes?.mode ?? 0o666) & 0o7777;
      const flags =
        constants.O_WRONLY |
        constants.O_CREAT |
        (request.mode === CREATE_GUARDED ? constants.O_EXCL : 0);
      const handle = await this.driver.open(path, flags, mode);
      await handle.close();
      this.#invalidate(dir);
      await this.#claim(path, creds, { parent, directory: false, mode });
      // `UNCHECKED` over an existing file still applies the attributes, which
      // is how a client asks for `open(…, O_CREAT|O_TRUNC)` in one round trip.
      await this.#applySattr(path, { ...request.attributes, mode: undefined });
      await this.#created(writer, dir, before, path);
    } catch (error) {
      await this.#createFailed(writer, dir, before, error);
    }
    return;
  }

  /**
   * `CREATE` with `EXCLUSIVE` (§3.3.8): create it, or recognise the retry.
   *
   * The mode exists because a client cannot make a create idempotent by itself:
   * if the reply is lost, the resend cannot tell "I created it" from "someone
   * else did". So the client sends a verifier it made up, and the server
   * remembers which verifier created which file — a resend carrying the same
   * one is answered with the file it already made, and a *different* verifier
   * on the same name is the second client, which is the case that really is
   * `NFS3ERR_EXIST`.
   *
   * What "remembers" means here — a bounded table in memory, so a retry is
   * covered and a restart is not — is stated in full on `ExclusiveCreates` in
   * `../util.ts`. §3.3.8 would rather that were stable storage and offers
   * `NFS3ERR_NOTSUPP` to a server that cannot manage it, which is what this
   * answered before the table existed.
   *
   * There are **no attributes**: `createhow3`'s `EXCLUSIVE` arm carries the
   * verifier *instead of* an `sattr3`, and §3.3.8 has the client follow up with
   * a SETATTR carrying the ones it wanted — the same SETATTR that retires the
   * entry, since after it the client is no longer relying on the retry. The
   * file is therefore created with the mode `UNCHECKED` uses when the client
   * names none, and the client's SETATTR narrows it.
   */
  async #createExclusive(
    dir: string,
    path: string,
    verf: Uint8Array | undefined,
    creds: RpcCredentials,
    parent: StatsLike | undefined,
  ): Promise<void> {
    const verifier = verf ?? new Uint8Array(NFS3_CREATEVERFSIZE);
    let handle: FileHandleLike;
    try {
      handle = await this.driver.open(
        path,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
        0o666,
      );
    } catch (error) {
      if ((error as { code?: string }).code !== "EEXIST") {
        throw error;
      }
      if (this.#exclusives.match(path, verifier) === undefined) {
        throw new NfsStatusError(NFS3ERR_EXIST, "a different file already has that name");
      }
      // The duplicate of a request whose reply never arrived. Nothing to
      // create, nothing to invalidate, nothing to chown a second time — the
      // caller answers with the file this client already made.
      return;
    }
    await handle.close();
    this.#exclusives.set(path, verifier);
    this.#invalidate(dir);
    await this.#claim(path, creds, { parent, directory: false, mode: 0o666 });
  }

  async #mkdir(args: XdrReader, creds: RpcCredentials, writer: XdrWriter): Promise<void> {
    const request = readMkdirArgs(args);
    args.end("MKDIR arguments");
    let dir: string | undefined;
    let before: WccAttr | undefined;
    try {
      dir = this.#pathOf(request.where.dir);
      const path = joinPath(dir, this.#checkName(request.where.name, "mkdir"));
      const parent = await this.#preOpStats(dir);
      before = parent === undefined ? undefined : wccAttrOf(parent);
      const mode = (request.attributes.mode ?? 0o777) & 0o7777;
      await this.driver.mkdir(path, { mode });
      this.#invalidate(dir);
      await this.#claim(path, creds, { parent, directory: true, mode });
      await this.#applySattr(path, { ...request.attributes, mode: undefined });
      await this.#created(writer, dir, before, path);
    } catch (error) {
      await this.#createFailed(writer, dir, before, error);
    }
    return;
  }

  async #symlink(args: XdrReader, creds: RpcCredentials, writer: XdrWriter): Promise<void> {
    const request = readSymlinkArgs(args);
    args.end("SYMLINK arguments");
    let dir: string | undefined;
    let before: WccAttr | undefined;
    try {
      dir = this.#pathOf(request.where.dir);
      const path = joinPath(dir, this.#checkName(request.where.name, "symlink"));
      const parent = await this.#preOpStats(dir);
      before = parent === undefined ? undefined : wccAttrOf(parent);
      await this.driver.symlink(request.target, path);
      this.#invalidate(dir);
      // A symlink's own mode is 0o777 and not the client's to choose, so the
      // only half of the rule that can apply to one is the group.
      await this.#claim(path, creds, { parent, directory: false, mode: 0o777 });
      // A symlink has no mode of its own to set; times and ownership still do.
      await this.#applySattr(
        path,
        { ...request.attributes, mode: undefined, size: undefined },
        { symlink: true },
      );
      await this.#created(writer, dir, before, path);
    } catch (error) {
      await this.#createFailed(writer, dir, before, error);
    }
    return;
  }

  /**
   * `MKNOD` — `NFS3ERR_NOTSUPP` unless the driver has the `mountx.mknod`
   * extension.
   *
   * Device nodes, FIFOs and sockets are outside what `node:fs/promises` can
   * express, which is why they are an extension rather than a driver method;
   * the bundled memory driver implements it, and a driver that does not gets
   * the refusal above rather than a regular file wearing the wrong type.
   */
  async #mknod(args: XdrReader, creds: RpcCredentials, writer: XdrWriter): Promise<void> {
    const request = readMknodArgs(args);
    args.end("MKNOD arguments");
    let dir: string | undefined;
    let before: WccAttr | undefined;
    try {
      dir = this.#pathOf(request.where.dir);
      const path = joinPath(dir, this.#checkName(request.where.name, "mknod"));
      const parent = await this.#preOpStats(dir);
      before = parent === undefined ? undefined : wccAttrOf(parent);
      const mknod = this.driver.mountx?.mknod;
      if (mknod === undefined) {
        throw new NfsStatusError(NFS3ERR_NOTSUPP, "MKNOD needs the mountx.mknod extension");
      }
      const mode = (request.attributes?.mode ?? 0o666) & 0o7777;
      const rdev = ((request.spec?.major ?? 0) << 8) | (request.spec?.minor ?? 0);
      await mknod.call(this.driver.mountx, path, mode | modeBitsOfFtype(request.type), rdev);
      this.#invalidate(dir);
      await this.#claim(path, creds, { parent, directory: false, mode });
      await this.#created(writer, dir, before, path);
    } catch (error) {
      await this.#createFailed(writer, dir, before, error);
    }
    return;
  }

  // -------------------------------------------------------------------------
  // REMOVE / RMDIR / RENAME / LINK
  // -------------------------------------------------------------------------

  async #remove(args: XdrReader, directory: boolean, writer: XdrWriter): Promise<void> {
    const request = readDirOp(args);
    args.end(`${directory ? "RMDIR" : "REMOVE"} arguments`);
    let dir: string | undefined;
    let before: WccAttr | undefined;
    try {
      dir = this.#pathOf(request.dir);
      const path = joinPath(dir, this.#checkName(request.name, directory ? "rmdir" : "unlink"));
      before = await this.#preOp(dir);
      await (directory ? this.driver.rmdir(path) : this.driver.unlink(path));
      // The parent lost a name; a removed *directory* also stops being a thing
      // whose own cached listing means anything. See `../handles.ts`.
      this.#invalidate(dir);
      // The handle stops resolving: a client still holding it gets
      // `NFS3ERR_STALE`, which is what NFSv3 has instead of an
      // unlinked-but-open file.
      const entry = this.handles.unbind(path);
      if (entry !== undefined && directory) {
        this.#snapshots.delete(entry.id);
      }
      // Whatever appears at this name next is a different file, and must not
      // inherit the promise made about this one.
      this.#exclusives.forget(path);
      writeWccRes(writer, { status: NFS3_OK, wcc: await this.#wcc(before, dir) });
    } catch (error) {
      writeWccRes(writer, {
        status: this.#failed(statusOf(error), error),
        wcc: { before, after: await this.#postOp(dir) },
      });
    }
    return;
  }

  /** `RENAME`. The one operation that holds the writer lock. */
  async #rename(args: XdrReader, writer: XdrWriter): Promise<void> {
    const request = readRenameArgs(args);
    args.end("RENAME arguments");
    let fromDir: string | undefined;
    let toDir: string | undefined;
    let fromBefore: WccAttr | undefined;
    let toBefore: WccAttr | undefined;
    try {
      fromDir = this.#pathOf(request.from.dir);
      toDir = this.#pathOf(request.to.dir);
      const from = joinPath(fromDir, this.#checkName(request.from.name, "rename"));
      const to = joinPath(toDir, this.#checkName(request.to.name, "rename"));
      fromBefore = await this.#preOp(fromDir);
      toBefore = fromDir === toDir ? fromBefore : await this.#preOp(toDir);
      await this.driver.rename(from, to);
      // Handles are identity-keyed, so this is bookkeeping for the *paths*: the
      // client goes on using the handle it already has, for the file and for
      // everything below it if this was a directory.
      this.handles.remap(from, to);
      // The verifiers are keyed by *path*, and both of these paths now name
      // something else: `from` nothing, `to` the file that moved onto it (over
      // whatever was there). Neither promise survives the move.
      this.#exclusives.forget(from);
      this.#exclusives.forget(to);
      // Exactly two directories changed their names: the one that lost `from`
      // and the one that gained `to`. A directory that *moved* keeps its own
      // snapshot — same contents, and `remap` kept it the same entry — and no
      // unrelated directory is touched at all. See `../handles.ts`.
      this.#invalidate(fromDir);
      this.#invalidate(toDir);
      writeRenameRes(writer, {
        status: NFS3_OK,
        fromWcc: await this.#wcc(fromBefore, fromDir),
        toWcc: await this.#wcc(toBefore, toDir),
      });
    } catch (error) {
      writeRenameRes(writer, {
        status: this.#failed(statusOf(error), error),
        fromWcc: { before: fromBefore, after: await this.#postOp(fromDir) },
        toWcc: { before: toBefore, after: await this.#postOp(toDir) },
      });
    }
    return;
  }

  async #link(args: XdrReader, writer: XdrWriter): Promise<void> {
    const request = readLinkArgs(args);
    args.end("LINK arguments");
    let dir: string | undefined;
    let file: string | undefined;
    let before: WccAttr | undefined;
    try {
      file = this.#pathOf(request.file);
      dir = this.#pathOf(request.link.dir);
      const path = joinPath(dir, this.#checkName(request.link.name, "link"));
      before = await this.#preOp(dir);
      await this.driver.link(file, path);
      this.#invalidate(dir);
      // Same file, one more name: `bind` finds the existing entry by identity,
      // so the client's handle for the original keeps working and both names
      // resolve to it.
      await this.#attrOf(path);
      writeLinkRes(writer, {
        status: NFS3_OK,
        attributes: await this.#postOp(file),
        linkdirWcc: await this.#wcc(before, dir),
      });
    } catch (error) {
      writeLinkRes(writer, {
        status: this.#failed(statusOf(error), error),
        attributes: await this.#postOp(file),
        linkdirWcc: { before, after: await this.#postOp(dir) },
      });
    }
    return;
  }

  // -------------------------------------------------------------------------
  // READDIR / READDIRPLUS
  // -------------------------------------------------------------------------

  /**
   * The page of a directory a cookie names.
   *
   * `cookie == 0` starts a fresh snapshot; anything else resumes into the
   * snapshot the client's `cookieverf3` identifies. See `handles.ts` for why
   * the verifier is a content hash and what it costs when it does not match.
   */
  async #page(
    entry: HandleEntry,
    path: string,
    cookie: bigint,
    cookieverf: Uint8Array,
  ): Promise<{ names: readonly string[]; verf: Uint8Array; from: number }> {
    if (cookie === 0n) {
      const entries = await this.driver.readdir(path, { withFileTypes: true });
      const snapshot = this.#snapshots.set(
        entry.id,
        entries.map((dirent) => dirent.name),
      );
      return { names: snapshot.names, verf: snapshot.cookieverf, from: 0 };
    }
    let snapshot = this.#snapshots.get(entry.id);
    if (snapshot === undefined || !sameVerifier(snapshot.cookieverf, cookieverf)) {
      // Evicted, or from before something changed. Re-listing costs a driver
      // call and rescues every client whose directory simply has not moved.
      const entries = await this.driver.readdir(path, { withFileTypes: true });
      const names = entries.map((dirent) => dirent.name);
      if (!sameVerifier(cookieVerifier(names), cookieverf)) {
        throw new NfsStatusError(
          NFS3ERR_BAD_COOKIE,
          "the directory changed and the cookie no longer means anything",
        );
      }
      snapshot = this.#snapshots.set(entry.id, names);
    }
    const from = Number(cookie);
    if (cookie < 0n || from > snapshot.names.length) {
      throw new NfsStatusError(NFS3ERR_BAD_COOKIE, `cookie ${cookie} is past the end`);
    }
    return { names: snapshot.names, verf: snapshot.cookieverf, from };
  }

  async #readdir(args: XdrReader, writer: XdrWriter): Promise<void> {
    const request = readReaddirArgs(args);
    args.end("READDIR arguments");
    let path: string | undefined;
    try {
      const entry = this.handles.decode(request.dir);
      const dir = this.handles.pathOf(entry);
      path = dir;
      const page = await this.#page(entry, dir, request.cookie, request.cookieverf);
      // Reply overhead: status, post_op_attr, cookieverf, the list terminator
      // and eof. Generous, because underestimating it is a reply the client
      // rejects.
      const budget = Math.max(0, Math.min(request.count, this.#rtmax()) - 128);
      // Which names fit is decided from the names alone, so the whole page is
      // chosen before a single `fileid3` is asked for and then resolved as one
      // batch — rather than a driver round trip between each entry and the
      // next.
      const chosen: string[] = [];
      let used = 0;
      let index = page.from;
      for (; index < page.names.length; index++) {
        const name = page.names[index]!;
        const size = entrySize(stringByteLength(name));
        if (used + size > budget) {
          break;
        }
        used += size;
        chosen.push(name);
      }
      if (chosen.length === 0 && index < page.names.length) {
        throw new NfsStatusError(NFS3ERR_TOOSMALL, `count ${request.count} fits no entry`);
      }
      // `used` is the page that was chosen; `budget` is what the client would
      // have allowed. Reserving the second would leave the difference pinned in
      // the socket's write queue, because the reply goes out as a view of this
      // buffer — see `#readFile`, where the gap is far wider.
      writer.ensure(used + 128);
      const fileids = await mapPage(chosen, (name) => this.#fileid(dir, name));
      const entries: Entry3[] = chosen.map((name, offset) => ({
        fileid: fileids[offset]!,
        name,
        cookie: BigInt(page.from + offset + 1),
      }));
      writeReaddirRes(writer, {
        status: NFS3_OK,
        dirAttributes: await this.#postOp(path),
        cookieverf: page.verf,
        entries,
        eof: index >= page.names.length,
      });
    } catch (error) {
      writeReaddirRes(writer, {
        status: this.#failed(statusOf(error), error),
        dirAttributes: await this.#postOp(path),
        cookieverf: new Uint8Array(NFS3_COOKIEVERFSIZE),
        entries: [],
        eof: false,
      });
    }
    return;
  }

  async #readdirplus(args: XdrReader, writer: XdrWriter): Promise<void> {
    const request = readReaddirplusArgs(args);
    args.end("READDIRPLUS arguments");
    let path: string | undefined;
    try {
      const entry = this.handles.decode(request.dir);
      const dir = this.handles.pathOf(entry);
      path = dir;
      const page = await this.#page(entry, dir, request.cookie, request.cookieverf);
      // Two budgets, and both are the client's: `dircount` bounds the names and
      // cookies, `maxcount` the whole reply. Overrunning either is a reply the
      // client throws away. Both are decided from the names alone, so — as in
      // `#readdir` — the page is chosen first and its attributes fetched as one
      // batch rather than one round trip per entry.
      const dirBudget = Math.max(0, request.dircount - 128);
      const maxBudget = Math.max(0, Math.min(request.maxcount, this.#rtmax()) - 128);
      const chosen: string[] = [];
      let dirUsed = 0;
      let maxUsed = 0;
      let index = page.from;
      for (; index < page.names.length; index++) {
        const name = page.names[index]!;
        const nameBytes = stringByteLength(name);
        const dirSize = entrySize(nameBytes);
        const plusSize = entryPlusSize(nameBytes, FH_SIZE, true);
        if (dirUsed + dirSize > dirBudget || maxUsed + plusSize > maxBudget) {
          break;
        }
        dirUsed += dirSize;
        maxUsed += plusSize;
        chosen.push(name);
      }
      if (chosen.length === 0 && index < page.names.length) {
        throw new NfsStatusError(
          NFS3ERR_TOOSMALL,
          `dircount ${request.dircount} / maxcount ${request.maxcount} fits no entry`,
        );
      }
      // The page that was chosen, not the `maxcount` that bounded it — as in
      // `#readdir`, and for the same reason.
      writer.ensure(maxUsed + 128);
      const entries: EntryPlus3[] = await mapPage(chosen, async (name, offset) => {
        const child = joinPath(dir, name);
        const cookie = BigInt(page.from + offset + 1);
        let attributes: Fattr3 | undefined;
        let handle: Uint8Array | undefined;
        let fileid: bigint;
        try {
          const described = await this.#attrOf(child);
          attributes = described.attr;
          handle = this.handles.encode(described.entry);
          fileid = described.attr.fileid;
        } catch {
          // The entry vanished between the snapshot and now. Reporting the name
          // with no attributes is legal and beats failing the whole page.
          fileid = 0n;
        }
        return { fileid, name, cookie, attributes, handle };
      });
      writeReaddirplusRes(writer, {
        status: NFS3_OK,
        dirAttributes: await this.#postOp(path),
        cookieverf: page.verf,
        entries,
        eof: index >= page.names.length,
      });
    } catch (error) {
      writeReaddirplusRes(writer, {
        status: this.#failed(statusOf(error), error),
        dirAttributes: await this.#postOp(path),
        cookieverf: new Uint8Array(NFS3_COOKIEVERFSIZE),
        entries: [],
        eof: false,
      });
    }
    return;
  }

  /**
   * `fileid3` for a directory entry, without failing the page if it is gone.
   *
   * A child the handle table has already bound answers with **no driver call at
   * all**: `HandleEntry.fileid` is exactly what a fresh `lstat` would produce,
   * because a fresh `lstat` is where it came from. That is what makes listing a
   * directory the client has walked before cost nothing per name — the case a
   * shell loop or a `find` spends all its time in.
   *
   * What it gives up is one round of freshness: the number reported is the one
   * this server last saw rather than one it has just re-checked. That is the
   * right trade here and nowhere else. `fileid3` in a plain READDIR is
   * advisory — a client that needs attributes it can act on asks for
   * READDIRPLUS, which stats every entry and is left alone — and the *names*
   * being paged over are already a frozen snapshot, so nothing about this page
   * was current to begin with.
   */
  async #fileid(dir: string, name: string): Promise<bigint> {
    const child = joinPath(dir, name);
    const bound = this.handles.at(child);
    if (bound !== undefined) {
      return bound.fileid;
    }
    try {
      const stats = await this.#statOf(child);
      return this.handles.bind(child, stats).fileid;
    } catch {
      return 0n;
    }
  }

  // -------------------------------------------------------------------------
  // FSSTAT / FSINFO / PATHCONF
  // -------------------------------------------------------------------------

  async #fsstat(args: XdrReader, writer: XdrWriter): Promise<void> {
    const fh = args.varOpaque(64, "nfs_fh3");
    args.end("FSSTAT arguments");
    let path: string | undefined;
    try {
      path = this.#pathOf(fh);
      const stats = await this.driver.statfs(path);
      const bsize = BigInt(Math.max(1, Math.trunc(stats.bsize) || 4096));
      writeFsstatRes(writer, {
        status: NFS3_OK,
        attributes: await this.#postOp(path),
        tbytes: big(stats.blocks) * bsize,
        fbytes: big(stats.bfree) * bsize,
        abytes: big(stats.bavail) * bsize,
        tfiles: big(stats.files),
        ffiles: big(stats.ffree),
        afiles: big(stats.ffree),
        // Seconds for which these numbers are guaranteed not to change: never,
        // for a live filesystem.
        invarsec: 0,
      });
    } catch (error) {
      writeFsstatRes(writer, {
        status: this.#failed(statusOf(error), error),
        attributes: await this.#postOp(path),
        tbytes: 0n,
        fbytes: 0n,
        abytes: 0n,
        tfiles: 0n,
        ffiles: 0n,
        afiles: 0n,
        invarsec: 0,
      });
    }
    return;
  }

  async #fsinfo(args: XdrReader, writer: XdrWriter): Promise<void> {
    const fh = args.varOpaque(64, "nfs_fh3");
    args.end("FSINFO arguments");
    let path: string | undefined;
    try {
      path = this.#pathOf(fh);
      const capabilities = this.driver.capabilities;
      writeFsinfoRes(writer, {
        status: NFS3_OK,
        attributes: await this.#postOp(path),
        rtmax: this.#rtmax(),
        rtpref: this.#rtmax(),
        // Reads and writes are preferred in multiples of this. 4 KiB is the
        // page size every client is already aligned to.
        rtmult: 4096,
        wtmax: this.#wtmax(),
        wtpref: this.#wtmax(),
        wtmult: 4096,
        dtpref: DEFAULT_DTPREF,
        maxfilesize: MAX_OFFSET,
        // The driver's timestamps come from `Date`, so one millisecond is the
        // finest change a client can hope to observe. Claiming nanoseconds
        // would make a client believe two writes a microsecond apart are
        // distinguishable by mtime.
        timeDelta: { seconds: 0, nseconds: 1_000_000 },
        properties:
          FSF3_HOMOGENEOUS |
          (capabilities.hardlinks ? FSF3_LINK : 0) |
          (capabilities.symlinks ? FSF3_SYMLINK : 0) |
          (capabilities.times ? FSF3_CANSETTIME : 0),
      });
    } catch (error) {
      writeFsinfoRes(writer, {
        status: this.#failed(statusOf(error), error),
        attributes: undefined,
        rtmax: 0,
        rtpref: 0,
        rtmult: 0,
        wtmax: 0,
        wtpref: 0,
        wtmult: 0,
        dtpref: 0,
        maxfilesize: 0n,
        timeDelta: { seconds: 0, nseconds: 0 },
        properties: 0,
      });
    }
    return;
  }

  async #pathconf(args: XdrReader, writer: XdrWriter): Promise<void> {
    const fh = args.varOpaque(64, "nfs_fh3");
    args.end("PATHCONF arguments");
    let path: string | undefined;
    try {
      path = this.#pathOf(fh);
      writePathconfRes(writer, {
        status: NFS3_OK,
        attributes: await this.#postOp(path),
        linkmax: this.driver.capabilities.hardlinks ? 32_000 : 1,
        nameMax: NAME_MAX,
        // Names over `name_max` are refused, not silently truncated — which is
        // what `#checkName` does, so this is a statement of fact.
        noTrunc: true,
        chownRestricted: true,
        caseInsensitive: !this.driver.capabilities.caseSensitive,
        casePreserving: true,
      });
    } catch (error) {
      writePathconfRes(writer, {
        status: this.#failed(statusOf(error), error),
        attributes: undefined,
        linkmax: 0,
        nameMax: 0,
        noTrunc: false,
        chownRestricted: false,
        caseInsensitive: false,
        casePreserving: false,
      });
    }
    return;
  }

  // -------------------------------------------------------------------------
  // the MOUNT program
  // -------------------------------------------------------------------------

  async #mount(
    call: RpcCall,
    args: XdrReader,
    context: NfsRequestContext,
    writer: XdrWriter,
  ): Promise<void> {
    switch (call.procedure) {
      case MOUNTPROC3_NULL: {
        args.end("MOUNT NULL arguments");
        return;
      }
      case MOUNTPROC3_MNT: {
        const dirpath = args.string(MNT3_PATHLEN, "dirpath");
        args.end("MNT arguments");
        return this.#read(() => this.#mnt(dirpath, context, writer));
      }
      case MOUNTPROC3_DUMP: {
        args.end("DUMP arguments");
        writeMountList(writer, this.#mounts);
        return;
      }
      case MOUNTPROC3_UMNT: {
        const dirpath = normalizePath(args.string(MNT3_PATHLEN, "dirpath"));
        args.end("UMNT arguments");
        const host = context.peer ?? "localhost";
        const index = this.#mounts.findIndex(
          (record) => record.directory === dirpath && record.hostname === host,
        );
        if (index >= 0) {
          this.#mounts.splice(index, 1);
        }
        return;
      }
      case MOUNTPROC3_UMNTALL: {
        args.end("UMNTALL arguments");
        const host = context.peer ?? "localhost";
        for (let index = this.#mounts.length - 1; index >= 0; index--) {
          if (this.#mounts[index]!.hostname === host) {
            this.#mounts.splice(index, 1);
          }
        }
        return;
      }
      case MOUNTPROC3_EXPORT: {
        args.end("EXPORT arguments");
        // One export, the driver's root, available to anyone who can reach the
        // socket. The access list is empty because there is nothing to list:
        // this is a loopback server, and the socket is the boundary.
        writeExportList(writer, [{ directory: "/", groups: [] }]);
        return;
      }
      default: {
        throw new ProcedureUnavailable(call.program, call.procedure);
      }
    }
  }

  /**
   * `MNT`: hand out the handle for an exported directory.
   *
   * Any directory in the driver is exportable, so `127.0.0.1:/sub` works the
   * way it does on a real server. The reply also lists the auth flavors we
   * accept, which is what a client uses to pick one.
   *
   * There is no `MNT3ERR_NAMETOOLONG` check here, and that is not an omission:
   * the caller reads `dirpath` as `args.string(MNT3_PATHLEN, …)`, so an
   * over-long one never gets this far — it is an `XdrError` and the RPC layer
   * answers `GARBAGE_ARGS` before any of this runs. The status still exists in
   * {@link mountStatusOf}, where a driver's own `ENAMETOOLONG` reaches it.
   */
  async #mnt(dirpath: string, context: NfsRequestContext, writer: XdrWriter): Promise<void> {
    const path = normalizePath(dirpath);
    try {
      const { entry, stats } = await this.#attrOf(path);
      if ((stats.mode & S_IFMT) !== S_IFDIR) {
        throw fsError("ENOTDIR", { syscall: "mount", path });
      }
      this.#mounts.push({ hostname: context.peer ?? "localhost", directory: path });
      writeMountRes(writer, {
        status: MNT3_OK,
        fh: this.handles.encode(entry),
        authFlavors: [AUTH_NONE, AUTH_SYS],
      });
    } catch (error) {
      writeMountRes(writer, {
        status: this.#failed(mountStatusOf(error), error),
        fh: undefined,
        authFlavors: [],
      });
    }
    return;
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** The `nfsstat3` for anything a handler threw. */
function statusOf(error: unknown): number {
  return error instanceof NfsStatusError ? error.status : nfsStatusOf(error);
}

/** The `mountstat3` for anything `MNT` threw. MOUNT has its own, shorter list. */
function mountStatusOf(error: unknown): number {
  switch ((error as { code?: string } | undefined)?.code) {
    case "ENOENT":
    case "ESTALE": {
      return MNT3ERR_NOENT;
    }
    case "ENOTDIR": {
      return MNT3ERR_NOTDIR;
    }
    case "EACCES": {
      return MNT3ERR_ACCES;
    }
    case "EPERM": {
      return MNT3ERR_PERM;
    }
    case "ENAMETOOLONG": {
      return MNT3ERR_NAMETOOLONG;
    }
    /* v8 ignore next 3 -- every other driver failure is an I/O error as far as
       the MOUNT protocol is concerned. */
    default: {
      return MNT3ERR_IO;
    }
  }
}

function big(value: number): bigint {
  return Number.isFinite(value) ? BigInt(Math.max(0, Math.trunc(value))) : 0n;
}

/**
 * {@link allowedAccess}'s answer as `ACCESS3_*` bits.
 *
 * The permission decision itself is version-neutral and lives in `../util.ts`;
 * this is the half that is not — RFC 1813 §3.3.4's numbering, which the v4
 * session spells with its own `ACCESS4_*` constants from RFC 8881 §18.1.1.
 */
function accessBits3(rights: AccessRights): number {
  return (
    (rights.read ? ACCESS3_READ : 0) |
    (rights.lookup ? ACCESS3_LOOKUP : 0) |
    (rights.modify ? ACCESS3_MODIFY : 0) |
    (rights.extend ? ACCESS3_EXTEND : 0) |
    (rights.delete ? ACCESS3_DELETE : 0) |
    (rights.execute ? ACCESS3_EXECUTE : 0)
  );
}
