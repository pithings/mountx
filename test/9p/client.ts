/**
 * A minimal 9P2000.L client, built from the server's own codecs.
 *
 * The same Tier-1 trick `test/nfs/client.ts` plays: the codecs in
 * `src/9p/protocol.ts` are symmetric, so the client that drives the server can
 * be written in JavaScript — and the whole protocol runs in one process, with
 * no kernel, no mount and no root.
 *
 * It speaks to a {@link P9Transport}, which is any function from a framed
 * request to a framed reply. {@link P9Client.overSession} makes one out of a
 * `P9Session` directly, which is what the session tests use; step 7's server
 * tests will hand it a socket instead, and nothing here changes.
 *
 * Two things it deliberately does *not* do. It does not track a pending map
 * keyed by tag — a transport answers the frame it was handed, so the reply is
 * simply the result of the call — and it does not resolve paths: it speaks fids
 * and names, exactly like the wire. What it does do is check the reply's type
 * and tag, and turn an `Rlerror` into an error shaped like a `node:fs` one, so
 * a test can say `rejects.toThrow(...)` and mean it.
 */

import { ERRNO_CODES, fsError, type ErrnoCode, type FsError } from "../../src/errors.ts";
import {
  P9_IOHDRSZ,
  P9_NOFID,
  P9_NOTAG,
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
  P9_TATTACH,
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
  P9_GETATTR_ALL,
  P9_GETATTR_SIZE,
  P9_LOCK_TYPE_WRLCK,
  P9_QTDIR,
  P9_QTSYMLINK,
  P9_SETATTR_ATIME,
  P9_SETATTR_ATIME_SET,
  P9_SETATTR_GID,
  P9_SETATTR_MODE,
  P9_SETATTR_MTIME,
  P9_SETATTR_MTIME_SET,
  P9_SETATTR_SIZE,
  P9_SETATTR_UID,
  P9_DOTL_AT_REMOVEDIR,
  P9_VERSION_DOTL,
  messageName,
} from "../../src/9p/constants.ts";
import {
  encodeMessage,
  readDirents,
  readRattach,
  readRgetattr,
  readRgetlock,
  readRlcreate,
  readRlerror,
  readRlock,
  readRlopen,
  readRmkdir,
  readRread,
  readRreaddir,
  readRreadlink,
  readRwrite,
  readRstatfs,
  readRversion,
  readRwalk,
  readEmptyBody,
  readQidReply,
  writeFidRequest,
  writeTattach,
  writeTflush,
  writeTfsync,
  writeTgetattr,
  writeTgetlock,
  writeTlcreate,
  writeTlink,
  writeTlock,
  writeTlopen,
  writeTmkdir,
  writeTmknod,
  writeTread,
  writeTreaddir,
  writeTrename,
  writeTrenameat,
  writeTsetattr,
  writeTsymlink,
  writeTunlinkat,
  writeTversion,
  writeTwalk,
  writeTwrite,
  type P9Dirent,
  type P9Time,
  type Rgetattr,
  type Rgetlock,
  type Rlopen,
  type Rstatfs,
  type Rversion,
  type Tsetattr,
} from "../../src/9p/protocol.ts";
import type { P9Session } from "../../src/9p/session.ts";
import { P9Reader, type P9Qid, type P9Writer } from "../../src/9p/wire.ts";
import { parseOpenFlags, validatePosition, validateRange } from "../../src/drivers/handle.ts";
import {
  O_APPEND,
  O_CREAT,
  O_EXCL,
  O_RDONLY,
  O_RDWR,
  O_TRUNC,
  O_WRONLY,
} from "../../src/fuse/constants.ts";
import { basename, dirname, joinPath, normalizePath } from "../../src/path.ts";
import {
  S_IFBLK,
  S_IFCHR,
  S_IFDIR,
  S_IFIFO,
  S_IFLNK,
  S_IFMT,
  S_IFREG,
  S_IFSOCK,
  type DirentLike,
  type FileHandleLike,
  type FsDriver,
  type MkdirOptions,
  type ReadResult,
  type StatsFsLike,
  type StatsLike,
  type TimeLike,
  type WriteResult,
} from "../../src/types.ts";

/** Zero, as a `sec[8] nsec[8]` pair — the value every unset time field carries. */
const NO_TIME: P9Time = { sec: 0n, nsec: 0n };

/** Framed request in, framed reply out. A session, a socket, a fixture. */
export type P9Transport = (request: Uint8Array) => Promise<Uint8Array | null>;

/** The `msize` the client proposes unless a test says otherwise. */
export const CLIENT_MSIZE = 8192;

/** errno → code, the inverse of the table `Rlerror` puts on the wire. */
const CODE_BY_ERRNO = new Map<number, ErrnoCode>(
  Object.entries(ERRNO_CODES).map(([code, errno]) => [errno, code as ErrnoCode]),
);

/**
 * The error an `Rlerror` becomes.
 *
 * Shaped like a `node:fs` error whenever the errno is one `src/errors.ts`
 * names, because that is the whole point of 9P2000.L carrying errnos: what the
 * driver threw is what comes back. An errno outside the table keeps the number
 * and gets a synthetic code, rather than being flattened into `EIO` — a client
 * that hid the difference could not tell a server bug from a driver one.
 */
export function remoteError(ecode: number, what: string): FsError {
  const code = CODE_BY_ERRNO.get(ecode);
  if (code !== undefined) {
    return fsError(code, { message: `${code}: ${what} answered Rlerror ${ecode}` });
  }
  const error = new Error(`${what} answered Rlerror ${ecode}`) as FsError;
  error.code = `ERRNO_${ecode}`;
  error.errno = -ecode;
  return error;
}

/** A reply that is not the one asked for: wrong type, wrong tag, or absent. */
export class P9ProtocolError extends Error {
  readonly code = "ERR_9P_PROTOCOL";

  constructor(message: string) {
    super(message);
    this.name = "P9ProtocolError";
  }
}

/** One reply, decoded down to its header and a reader over the body. */
export interface P9Reply {
  type: number;
  tag: number;
  body: P9Reader;
}

/** The wire, plus one typed method per message this server answers. */
export class P9Client {
  readonly transport: P9Transport;
  /** What {@link P9Client.version} proposes by default. */
  msize = CLIENT_MSIZE;
  /** The `msize` the last successful {@link P9Client.version} agreed on. */
  negotiated: number | undefined;
  #tag = 0;

  constructor(transport: P9Transport) {
    this.transport = transport;
  }

  /** Drive a session directly — no socket, no framing, one call per message. */
  static overSession(session: P9Session): P9Client {
    return new P9Client((request) => session.handleCall(request));
  }

  /**
   * The next tag, wrapping at 16 bits and never {@link P9_NOTAG}.
   *
   * Tags are only recycled after their reply, exactly as the kernel's IDR
   * recycles them, so the duplicate-tag path is something a test has to ask for
   * on purpose.
   */
  nextTag(): number {
    this.#tag = (this.#tag + 1) & 0xff_ff;
    if (this.#tag === P9_NOTAG) {
      this.#tag = 0;
    }
    return this.#tag;
  }

  /** Send one message and get its reply, checking only the tag. */
  async send(
    type: number,
    tag: number,
    write?: (writer: P9Writer) => void,
    capacity?: number,
  ): Promise<P9Reply> {
    return this.sendFrame(encodeMessage(type, tag, write, capacity), tag, messageName(type));
  }

  /** Send bytes as they are — for the malformed frames the tests need. */
  async sendFrame(frame: Uint8Array, tag: number, what: string): Promise<P9Reply> {
    const reply = await this.transport(frame);
    if (reply === null) {
      throw new P9ProtocolError(`${what} was dropped without a reply`);
    }
    const reader = new P9Reader(reply);
    const size = reader.u32("size");
    if (size !== reply.byteLength) {
      throw new P9ProtocolError(`${what} reply says ${size} bytes but is ${reply.byteLength}`);
    }
    const replyType = reader.u8("type");
    const replyTag = reader.u16("tag");
    if (replyTag !== tag) {
      throw new P9ProtocolError(`${what} was tagged ${tag} but the reply is tagged ${replyTag}`);
    }
    return { type: replyType, tag: replyTag, body: reader };
  }

  /**
   * Send one message and insist on the matching reply type.
   *
   * An `Rlerror` throws {@link remoteError}; any other mismatch throws
   * {@link P9ProtocolError}, because a server answering `Rwalk` to a `Tgetattr`
   * is a bug no test should be able to read past.
   */
  async call(
    type: number,
    expected: number,
    write?: (writer: P9Writer) => void,
    options: { tag?: number; capacity?: number } = {},
  ): Promise<P9Reply> {
    const tag = options.tag ?? this.nextTag();
    const what = messageName(type);
    const reply = await this.send(type, tag, write, options.capacity);
    if (reply.type === P9_RLERROR && expected !== P9_RLERROR) {
      const { ecode } = readRlerror(reply.body);
      reply.body.end("Rlerror");
      throw remoteError(ecode, what);
    }
    if (reply.type !== expected) {
      throw new P9ProtocolError(
        `${what} was answered ${messageName(reply.type)}, not ${messageName(expected)}`,
      );
    }
    return reply;
  }

  // --- messages ---

  /**
   * `Tversion`. Records the agreed `msize` unless the server said `unknown`,
   * which is the one reply that is a refusal without being an error.
   */
  async version(msize = this.msize, version = P9_VERSION_DOTL): Promise<Rversion> {
    const reply = await this.call(
      P9_TVERSION,
      P9_RVERSION,
      (writer) => writeTversion(writer, { msize, version }),
      { tag: P9_NOTAG },
    );
    const agreed = readRversion(reply.body);
    reply.body.end("Rversion");
    this.negotiated = agreed.version === P9_VERSION_DOTL ? agreed.msize : undefined;
    return agreed;
  }

  async attach(
    fid: number,
    options: { afid?: number; uname?: string; aname?: string; nUname?: number } = {},
  ): Promise<P9Qid> {
    const reply = await this.call(P9_TATTACH, P9_RATTACH, (writer) =>
      writeTattach(writer, {
        fid,
        afid: options.afid ?? P9_NOFID,
        uname: options.uname ?? "",
        aname: options.aname ?? "",
        nUname: options.nUname ?? 0,
      }),
    );
    const { qid } = readRattach(reply.body);
    reply.body.end("Rattach");
    return qid;
  }

  async walk(fid: number, newfid: number, wnames: string[]): Promise<P9Qid[]> {
    const reply = await this.call(
      P9_TWALK,
      P9_RWALK,
      (writer) => writeTwalk(writer, { fid, newfid, wnames }),
      { capacity: 256 },
    );
    const { wqids } = readRwalk(reply.body);
    reply.body.end("Rwalk");
    return wqids;
  }

  async clunk(fid: number): Promise<void> {
    const reply = await this.call(P9_TCLUNK, P9_RCLUNK, (writer) =>
      writeFidRequest(writer, { fid }),
    );
    readEmptyBody(reply.body, "Rclunk");
  }

  async getattr(fid: number, requestMask = P9_GETATTR_ALL): Promise<Rgetattr> {
    const reply = await this.call(P9_TGETATTR, P9_RGETATTR, (writer) =>
      writeTgetattr(writer, { fid, requestMask }),
    );
    const attr = readRgetattr(reply.body);
    reply.body.end("Rgetattr");
    return attr;
  }

  async statfs(fid: number): Promise<Rstatfs> {
    const reply = await this.call(P9_TSTATFS, P9_RSTATFS, (writer) =>
      writeFidRequest(writer, { fid }),
    );
    const stats = readRstatfs(reply.body);
    reply.body.end("Rstatfs");
    return stats;
  }

  /**
   * `Treaddir`, unpacked. `count` defaults to what the negotiated `msize`
   * leaves for entries, which is what `p9_client_readdir()` clamps to.
   */
  async readdir(fid: number, offset: bigint, count?: number): Promise<P9Dirent[]> {
    const budget = count ?? (this.negotiated ?? this.msize) - P9_READDIRHDRSZ;
    const reply = await this.call(
      P9_TREADDIR,
      P9_RREADDIR,
      (writer) => writeTreaddir(writer, { fid, offset, count: budget }),
      { capacity: 32 },
    );
    const { data } = readRreaddir(reply.body);
    reply.body.end("Rreaddir");
    return readDirents(data);
  }

  /** Every entry of a directory, paged to exhaustion. */
  async readdirAll(fid: number, count?: number): Promise<P9Dirent[]> {
    const all: P9Dirent[] = [];
    let offset = 0n;
    for (;;) {
      const page = await this.readdir(fid, offset, count);
      if (page.length === 0) {
        return all;
      }
      all.push(...page);
      offset = page.at(-1)!.offset;
    }
  }

  // --- I/O ---

  /** `Tlopen`. `flags` is the **wire's** `O_*`, i.e. the Linux kernel's. */
  async lopen(fid: number, flags = 0): Promise<Rlopen> {
    const reply = await this.call(P9_TLOPEN, P9_RLOPEN, (writer) =>
      writeTlopen(writer, { fid, flags }),
    );
    const opened = readRlopen(reply.body);
    reply.body.end("Rlopen");
    return opened;
  }

  /** `Tlcreate` — the fid names the parent going in and the new file coming out. */
  async lcreate(
    fid: number,
    name: string,
    options: { flags?: number; mode?: number; gid?: number } = {},
  ): Promise<Rlopen> {
    const reply = await this.call(P9_TLCREATE, P9_RLCREATE, (writer) =>
      writeTlcreate(writer, {
        fid,
        name,
        flags: options.flags ?? 0,
        mode: options.mode ?? 0o644,
        gid: options.gid ?? 0,
      }),
    );
    const created = readRlcreate(reply.body);
    reply.body.end("Rlcreate");
    return created;
  }

  /**
   * `Tread`. `count` defaults to what the negotiated `msize` leaves for a
   * payload, which is what `p9_client_read_once()` clamps to.
   */
  async read(fid: number, offset: bigint, count?: number): Promise<Uint8Array> {
    const budget = count ?? (this.negotiated ?? this.msize) - P9_IOHDRSZ;
    const reply = await this.call(P9_TREAD, P9_RREAD, (writer) =>
      writeTread(writer, { fid, offset, count: budget }),
    );
    const { data } = readRread(reply.body);
    reply.body.end("Rread");
    return data;
  }

  /** `Tread` until the file ends, concatenated. */
  async readAll(fid: number, count?: number): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let offset = 0n;
    for (;;) {
      const chunk = await this.read(fid, offset, count);
      if (chunk.byteLength === 0) {
        break;
      }
      chunks.push(chunk);
      offset += BigInt(chunk.byteLength);
    }
    const all = new Uint8Array(Number(offset));
    let at = 0;
    for (const chunk of chunks) {
      all.set(chunk, at);
      at += chunk.byteLength;
    }
    return all;
  }

  /** `Twrite` — the byte count the server accepted. */
  async write(fid: number, offset: bigint, data: Uint8Array | string): Promise<number> {
    const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
    const reply = await this.call(
      P9_TWRITE,
      P9_RWRITE,
      (writer) => writeTwrite(writer, { fid, offset, data: bytes }),
      { capacity: bytes.byteLength + 32 },
    );
    const { count } = readRwrite(reply.body);
    reply.body.end("Rwrite");
    return count;
  }

  async fsync(fid: number, datasync = 0): Promise<void> {
    const reply = await this.call(P9_TFSYNC, P9_RFSYNC, (writer) =>
      writeTfsync(writer, { fid, datasync }),
    );
    readEmptyBody(reply.body, "Rfsync");
  }

  // --- attributes ---

  /**
   * `Tsetattr`. Everything but `valid` defaults to zero, exactly as the kernel
   * leaves the fields whose bits it did not set.
   */
  async setattr(
    fid: number,
    attr: Partial<Omit<Tsetattr, "fid">> & { valid: number },
  ): Promise<void> {
    const reply = await this.call(P9_TSETATTR, P9_RSETATTR, (writer) =>
      writeTsetattr(writer, {
        fid,
        valid: attr.valid,
        mode: attr.mode ?? 0,
        uid: attr.uid ?? 0,
        gid: attr.gid ?? 0,
        size: attr.size ?? 0n,
        atime: attr.atime ?? NO_TIME,
        mtime: attr.mtime ?? NO_TIME,
      }),
    );
    readEmptyBody(reply.body, "Rsetattr");
  }

  // --- namespace ---

  async mkdir(dfid: number, name: string, mode = 0o755, gid = 0): Promise<P9Qid> {
    const reply = await this.call(P9_TMKDIR, P9_RMKDIR, (writer) =>
      writeTmkdir(writer, { dfid, name, mode, gid }),
    );
    const { qid } = readRmkdir(reply.body);
    reply.body.end("Rmkdir");
    return qid;
  }

  async symlink(dfid: number, name: string, symtgt: string, gid = 0): Promise<P9Qid> {
    const reply = await this.call(P9_TSYMLINK, P9_RSYMLINK, (writer) =>
      writeTsymlink(writer, { dfid, name, symtgt, gid }),
    );
    const { qid } = readQidReply(reply.body);
    reply.body.end("Rsymlink");
    return qid;
  }

  async mknod(
    dfid: number,
    name: string,
    options: { mode?: number; major?: number; minor?: number; gid?: number } = {},
  ): Promise<P9Qid> {
    const reply = await this.call(P9_TMKNOD, P9_RMKNOD, (writer) =>
      writeTmknod(writer, {
        dfid,
        name,
        mode: options.mode ?? 0o644,
        major: options.major ?? 0,
        minor: options.minor ?? 0,
        gid: options.gid ?? 0,
      }),
    );
    const { qid } = readQidReply(reply.body);
    reply.body.end("Rmknod");
    return qid;
  }

  /** `Tlink` — note the order: the *directory* fid comes first. */
  async link(dfid: number, fid: number, name: string): Promise<void> {
    const reply = await this.call(P9_TLINK, P9_RLINK, (writer) =>
      writeTlink(writer, { dfid, fid, name }),
    );
    readEmptyBody(reply.body, "Rlink");
  }

  async readlink(fid: number): Promise<string> {
    const reply = await this.call(P9_TREADLINK, P9_RREADLINK, (writer) =>
      writeFidRequest(writer, { fid }),
    );
    const { target } = readRreadlink(reply.body);
    reply.body.end("Rreadlink");
    return target;
  }

  async rename(fid: number, dfid: number, name: string): Promise<void> {
    const reply = await this.call(P9_TRENAME, P9_RRENAME, (writer) =>
      writeTrename(writer, { fid, dfid, name }),
    );
    readEmptyBody(reply.body, "Rrename");
  }

  async renameat(
    olddirfid: number,
    oldname: string,
    newdirfid: number,
    newname: string,
  ): Promise<void> {
    const reply = await this.call(P9_TRENAMEAT, P9_RRENAMEAT, (writer) =>
      writeTrenameat(writer, { olddirfid, oldname, newdirfid, newname }),
    );
    readEmptyBody(reply.body, "Rrenameat");
  }

  /** `Tunlinkat`; `flags` is `P9_DOTL_AT_REMOVEDIR` or nothing. */
  async unlinkat(dirfid: number, name: string, flags = 0): Promise<void> {
    const reply = await this.call(P9_TUNLINKAT, P9_RUNLINKAT, (writer) =>
      writeTunlinkat(writer, { dirfid, name, flags }),
    );
    readEmptyBody(reply.body, "Runlinkat");
  }

  /** `Tremove` — removes the file **and** clunks the fid, success or not. */
  async remove(fid: number): Promise<void> {
    const reply = await this.call(P9_TREMOVE, P9_RREMOVE, (writer) =>
      writeFidRequest(writer, { fid }),
    );
    readEmptyBody(reply.body, "Rremove");
  }

  // --- locks ---

  /** `Tlock` — the `P9_LOCK_*` status the server answered. */
  async lock(
    fid: number,
    options: {
      type?: number;
      flags?: number;
      start?: bigint;
      length?: bigint;
      procId?: number;
      clientId?: string;
    } = {},
  ): Promise<number> {
    const reply = await this.call(P9_TLOCK, P9_RLOCK, (writer) =>
      writeTlock(writer, {
        fid,
        type: options.type ?? P9_LOCK_TYPE_WRLCK,
        flags: options.flags ?? 0,
        start: options.start ?? 0n,
        length: options.length ?? 0n,
        procId: options.procId ?? 1,
        clientId: options.clientId ?? "test-client",
      }),
    );
    const { status } = readRlock(reply.body);
    reply.body.end("Rlock");
    return status;
  }

  /** `Tgetlock` — the conflicting lock, or `P9_LOCK_TYPE_UNLCK` for none. */
  async getlock(
    fid: number,
    options: {
      type?: number;
      start?: bigint;
      length?: bigint;
      procId?: number;
      clientId?: string;
    } = {},
  ): Promise<Rgetlock> {
    const reply = await this.call(P9_TGETLOCK, P9_RGETLOCK, (writer) =>
      writeTgetlock(writer, {
        fid,
        type: options.type ?? P9_LOCK_TYPE_WRLCK,
        start: options.start ?? 0n,
        length: options.length ?? 0n,
        procId: options.procId ?? 1,
        clientId: options.clientId ?? "test-client",
      }),
    );
    const lock = readRgetlock(reply.body);
    reply.body.end("Rgetlock");
    return lock;
  }

  async flush(oldtag: number, options: { tag?: number } = {}): Promise<void> {
    const reply = await this.call(
      P9_TFLUSH,
      P9_RFLUSH,
      (writer) => writeTflush(writer, { oldtag }),
      options,
    );
    readEmptyBody(reply.body, "Rflush");
  }

  /** Send a message and return the `Rlerror` errno it must answer with. */
  async expectError(
    type: number,
    write?: (writer: P9Writer) => void,
    options: { tag?: number; capacity?: number } = {},
  ): Promise<number> {
    const reply = await this.call(type, P9_RLERROR, write, options);
    const { ecode } = readRlerror(reply.body);
    reply.body.end("Rlerror");
    return ecode;
  }
}

// ---------------------------------------------------------------------------
// the driver over a client
// ---------------------------------------------------------------------------

/**
 * `Rgetattr` as the `StatsLike` a driver has to return.
 *
 * **`ino` comes from `qid.path`**, and there is nowhere else it could come
 * from: `Rgetattr` has no `st_ino` field. That is not a gap in this decoder —
 * v9fs does exactly the same thing (`QID2INO()` in `fs/9p/v9fs.h`, used by
 * `v9fs_stat2inode_dotl()`), which is why `src/9p/session.ts` allocates a
 * `qid.path` per file and keys it on the driver's `(dev, ino)`: over this wire
 * the qid *is* the inode number, and two names for one file agree only because
 * the identity map made them.
 *
 * `dev` is `0` for the same reason in reverse: the wire has no field for it and
 * nothing may be invented, so every file on this mount shares a device — which
 * is what `stat(2)` reports for a real 9P mount as well.
 */
export function statsOf(attr: Rgetattr): StatsLike {
  const mode = attr.mode;
  const is = (bits: number): boolean => (mode & S_IFMT) === bits;
  return {
    dev: 0,
    ino: Number(attr.qid.path),
    mode,
    nlink: Number(attr.nlink),
    uid: attr.uid,
    gid: attr.gid,
    rdev: Number(attr.rdev),
    size: Number(attr.size),
    blksize: Number(attr.blksize),
    blocks: Number(attr.blocks),
    atimeMs: msOf(attr.atime),
    mtimeMs: msOf(attr.mtime),
    ctimeMs: msOf(attr.ctime),
    birthtimeMs: msOf(attr.btime),
    isFile: () => is(S_IFREG),
    isDirectory: () => is(S_IFDIR),
    isSymbolicLink: () => is(S_IFLNK),
    isBlockDevice: () => is(S_IFBLK),
    isCharacterDevice: () => is(S_IFCHR),
    isFIFO: () => is(S_IFIFO),
    isSocket: () => is(S_IFSOCK),
  };
}

/** Milliseconds from a `sec[8] nsec[8]` pair. */
function msOf(time: P9Time): number {
  return Number(time.sec) * 1000 + Number(time.nsec) / 1e6;
}

/** A `TimeLike` as the pair `Tsetattr` carries. */
function timeOf(value: TimeLike): P9Time {
  const ms = value instanceof Date ? value.getTime() : value * 1000;
  const sec = Math.floor(ms / 1000);
  return { sec: BigInt(sec), nsec: BigInt(Math.round((ms - sec * 1000) * 1e6)) };
}

/**
 * A dirent from what `Rreaddir` packs: a name and a `DT_*` byte.
 *
 * The byte is `(st_mode & S_IFMT) >> 12`, so the type predicates are the same
 * comparison shifted — no second stat, which is the point of packing it.
 */
function direntOf(name: string, type: number): DirentLike {
  const is = (bits: number): boolean => type === bits >> 12;
  return {
    name,
    isFile: () => is(S_IFREG),
    isDirectory: () => is(S_IFDIR),
    isSymbolicLink: () => is(S_IFLNK),
    isBlockDevice: () => is(S_IFBLK),
    isCharacterDevice: () => is(S_IFCHR),
    isFIFO: () => is(S_IFIFO),
    isSocket: () => is(S_IFSOCK),
  };
}

/**
 * Either `node:fs` flags namespace, as the **wire's** `O_*`.
 *
 * `Tlopen`/`Tlcreate` carry the Linux kernel's numbers (`src/9p/session.ts`
 * hands them to `driverOpenFlags()`, which is the identity on Linux), so a
 * client must send those and not the host's — the two disagree on macOS, where
 * `O_TRUNC` is Linux's `O_APPEND`. Going through `parseOpenFlags()` rather than
 * masking the host's bits is what makes that true from any host: it is the one
 * parser that already understands both `"wx+"` and `O_RDWR | O_CREAT`, and what
 * comes out of it is a decision, not a number in somebody's namespace.
 */
export function wireOpenFlags(flags: string | number, path = ""): number {
  const parsed = parseOpenFlags(flags, path);
  let wire = parsed.read && parsed.write ? O_RDWR : parsed.write ? O_WRONLY : O_RDONLY;
  if (parsed.create) {
    wire |= O_CREAT;
  }
  if (parsed.exclusive) {
    wire |= O_EXCL;
  }
  if (parsed.truncate) {
    wire |= O_TRUNC;
  }
  if (parsed.append) {
    wire |= O_APPEND;
  }
  return wire;
}

/** How many symlinks a resolution may traverse before it is a loop. */
const MAX_SYMLINKS = 40;

/** Where a path resolved to: a fid the caller owns, and the qid of the last step. */
interface Resolved {
  fid: number;
  /** `undefined` for the root, which no walk step produced a qid for. */
  qid: P9Qid | undefined;
}

/**
 * Fid numbers, handed out and taken back.
 *
 * Recycled through a free list rather than counted upwards forever, which is
 * what a real client does (the kernel's is an IDR) and what makes "a fid the
 * server still holds" a mistake this can actually make — a fid released before
 * its `Tclunk` succeeded would come back and be refused as already in use.
 * Only a *successful* clunk releases one, for exactly that reason.
 */
class FidPool {
  #next: number;
  readonly #free: number[] = [];

  constructor(first: number) {
    this.#next = first;
  }

  take(): number {
    const recycled = this.#free.pop();
    if (recycled !== undefined) {
      return recycled;
    }
    if (this.#next >= P9_NOFID) {
      throw new P9ProtocolError("the client ran out of fids");
    }
    return this.#next++;
  }

  release(fid: number): void {
    this.#free.push(fid);
  }
}

/**
 * `FsDriver` over a {@link P9Client}, which is what lets `test/conformance.ts`
 * run unmodified as the 9P column of the conformance matrix.
 *
 * Two things make this more than a method-per-method forwarding, and both are
 * what a real client does:
 *
 * - **Fids, not paths.** Every operation needs a fid pointing at its target, so
 *   every call here walks one out of the root fid and clunks it afterwards.
 *   Leaking one would be invisible to the suite and fatal to a long-lived
 *   mount, so the walk is the one piece with its own cleanup discipline.
 * - **Symlinks are the client's job.** `Twalk` reports a `P9_QTSYMLINK` qid and
 *   stops there; the resolution — `Treadlink`, re-root, re-walk, and the loop
 *   bound — happens on this side, exactly as the VFS does it above v9fs. A
 *   server that resolved links itself would break `lstat`.
 *
 * The walk is one name per `Twalk` rather than up to `P9_MAXWELEM` of them.
 * That is deliberate: a walk that fails on its *first* name answers `Rlerror`
 * and one that fails later answers a short `Rwalk`, so single-name walks make
 * every failure an error the driver interface can throw, and the partial-walk
 * rule stays where it is tested directly (`test/9p/session.test.ts`).
 *
 * **What this column does not drive**, because the driver interface has no way
 * to ask for it: `Trename` (the one-fid form — `rename()` maps onto
 * `Trenameat`, which is the shape `renameat(2)` and `node:fs` both have),
 * `Tremove` (`unlink`/`rmdir` are `Tunlinkat`; `Tremove` also clunks, which no
 * driver call means), `Tlock`/`Tgetlock`, `Txattrwalk`/`Txattrcreate`,
 * `Tflush`, `Tauth` and the legacy 9P2000 opcodes. All of those are covered
 * directly in `test/9p/session.test.ts` and `test/9p/session-fuzz.test.ts`;
 * none of them is skipped here to make a case pass.
 */
export function p9Driver(client: P9Client, root: number): FsDriver {
  const fids = new FidPool(root + 1);

  /** The payload one `Tread`/`Twrite` may carry under the negotiated `msize`. */
  const budget = (): number => Math.max(1, (client.negotiated ?? client.msize) - P9_IOHDRSZ);

  /** Clunk a fid and take its number back. */
  async function drop(fid: number): Promise<void> {
    await client.clunk(fid);
    fids.release(fid);
  }

  /** The same, for a cleanup path where the interesting error is elsewhere. */
  async function dropQuietly(fid: number): Promise<void> {
    try {
      await drop(fid);
    } catch {
      // A fid we cannot clunk is one the server has already forgotten (a failed
      // `Tlcreate` is the usual way); it is not recycled, and nothing here can
      // act on it.
    }
  }

  /** A fresh fid naming the same tree as the root, for a walk to start from. */
  async function fromRoot(): Promise<number> {
    const fid = fids.take();
    try {
      await client.walk(root, fid, []);
    } catch (error) {
      fids.release(fid);
      throw error;
    }
    return fid;
  }

  /** Resolve every component of `path`, following symlinks as `follow` says. */
  async function walkTo(path: string, follow: boolean, depth = 0): Promise<Resolved> {
    if (depth > MAX_SYMLINKS) {
      throw fsError("ELOOP", { syscall: "open", path });
    }
    const parts = normalizePath(path).split("/").filter(Boolean);
    let current: number | undefined = await fromRoot();
    let qid: P9Qid | undefined;
    try {
      for (const [index, name] of parts.entries()) {
        const next = fids.take();
        try {
          qid = (await client.walk(current, next, [name]))[0]!;
        } catch (error) {
          fids.release(next);
          throw error;
        }
        await dropQuietly(current);
        current = next;
        if ((qid.type & P9_QTSYMLINK) === 0 || (!follow && index === parts.length - 1)) {
          continue;
        }
        // The link is followed here rather than by the server: the target is
        // resolved against the directory the link lives in, the rest of the
        // path is appended to it, and the whole thing is walked again.
        const target = await client.readlink(current);
        const from = index === 0 ? "/" : `/${parts.slice(0, index).join("/")}`;
        const base = target.startsWith("/") ? normalizePath(target) : joinPath(from, target);
        const rest = parts.slice(index + 1).join("/");
        await dropQuietly(current);
        current = undefined;
        return await walkTo(rest === "" ? base : joinPath(base, rest), follow, depth + 1);
      }
    } catch (error) {
      if (current !== undefined) {
        await dropQuietly(current);
      }
      throw error;
    }
    return { fid: current, qid };
  }

  /** Resolve the *parent* of a path, plus the final name. */
  async function parentOf(path: string, syscall: string): Promise<{ fid: number; name: string }> {
    const normalized = normalizePath(path);
    if (normalized === "/") {
      throw fsError("EINVAL", { syscall, path });
    }
    const { fid } = await walkTo(dirname(normalized), true);
    return { fid, name: basename(normalized) };
  }

  /** Run something with the fid `path` resolves to, and clunk it afterwards. */
  async function withFid<T>(
    path: string,
    follow: boolean,
    fn: (fid: number) => Promise<T>,
  ): Promise<T> {
    const { fid } = await walkTo(path, follow);
    try {
      return await fn(fid);
    } finally {
      await dropQuietly(fid);
    }
  }

  /** The same for a path's parent: the directory fid and the name under it. */
  async function withParent<T>(
    path: string,
    syscall: string,
    fn: (fid: number, name: string) => Promise<T>,
  ): Promise<T> {
    const { fid, name } = await parentOf(path, syscall);
    try {
      return await fn(fid, name);
    } finally {
      await dropQuietly(fid);
    }
  }

  /** `Tsetattr` against a path, which is every metadata call here. */
  async function setattr(
    path: string,
    follow: boolean,
    attr: Partial<Omit<Tsetattr, "fid">> & { valid: number },
  ): Promise<void> {
    await withFid(path, follow, (fid) => client.setattr(fid, attr));
  }

  function ownership(uid: number, gid: number): Partial<Tsetattr> & { valid: number } {
    // 9P has no `(uid_t)-1`: the mask is what says which of the two to set, so
    // `chown(path, -1, gid)` leaves the uid bit clear rather than sending -1.
    let valid = 0;
    if (uid >= 0) {
      valid |= P9_SETATTR_UID;
    }
    if (gid >= 0) {
      valid |= P9_SETATTR_GID;
    }
    return { valid, uid: Math.max(0, uid), gid: Math.max(0, gid) };
  }

  function times(atime: TimeLike, mtime: TimeLike): Partial<Tsetattr> & { valid: number } {
    return {
      valid: P9_SETATTR_ATIME | P9_SETATTR_ATIME_SET | P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET,
      atime: timeOf(atime),
      mtime: timeOf(mtime),
    };
  }

  /**
   * A file handle over an open fid.
   *
   * Unlike the NFS client's, this is not a local fiction: the fid really is
   * open on the server, `close()` really is the `Tclunk` that closes the
   * driver's handle, and an unlinked file stays readable through it. What is
   * local is only the *position*, which is what `open(2)` keeps in the kernel
   * on a real mount — every 9P read and write carries an explicit offset.
   */
  function makeHandle(fid: number, wire: number): FileHandleLike {
    let position = 0;
    const append = (wire & O_APPEND) !== 0;
    return {
      async read(buffer, offset, length, at): Promise<ReadResult> {
        // One `Tread`, so a read larger than the negotiated `msize` leaves is a
        // *short* read rather than a loop — which is `read(2)`'s own contract
        // and what the NFS adapter does too; `Loopback.readFile` pages for it.
        const { start, count } = validateRange(buffer, offset, length, false);
        const explicit = validatePosition(at);
        const where = explicit ?? position;
        const data = await client.read(fid, BigInt(where), Math.min(count, budget()));
        buffer.set(data, start);
        if (explicit === undefined) {
          position = where + data.byteLength;
        }
        return { bytesRead: data.byteLength, buffer };
      },
      async write(buffer, offset, length, at): Promise<WriteResult> {
        const { start, count } = validateRange(buffer, offset, length, true);
        const explicit = validatePosition(at);
        let where = explicit ?? position;
        if (append) {
          // `O_APPEND` is resolved by whoever holds the position, and on a 9P
          // mount that is the client: `p9_client_write()` is handed an offset
          // the VFS already moved to the end of the file.
          where = Number((await client.getattr(fid, P9_GETATTR_SIZE)).size);
        }
        let written = 0;
        while (written < count) {
          const chunk = buffer.subarray(
            start + written,
            start + Math.min(count, written + budget()),
          );
          const sent = await client.write(fid, BigInt(where + written), chunk);
          if (sent === 0) {
            break;
          }
          written += sent;
        }
        if (explicit === undefined || append) {
          position = where + written;
        }
        return { bytesWritten: written, buffer };
      },
      async stat(): Promise<StatsLike> {
        return statsOf(await client.getattr(fid));
      },
      async truncate(length = 0): Promise<void> {
        await client.setattr(fid, { valid: P9_SETATTR_SIZE, size: BigInt(length) });
      },
      close: () => drop(fid),
      sync: () => client.fsync(fid, 0),
      datasync: () => client.fsync(fid, 1),
    };
  }

  return {
    // A fid is server-side open state that outlives the name it was opened
    // from, and `Trenameat` is one server operation.
    capabilities: { handles: true, atomicRename: true },

    async stat(path) {
      return withFid(path, true, async (fid) => statsOf(await client.getattr(fid)));
    },
    async lstat(path) {
      return withFid(path, false, async (fid) => statsOf(await client.getattr(fid)));
    },
    async statfs(path): Promise<StatsFsLike> {
      return withFid(path, true, async (fid) => {
        const stats = await client.statfs(fid);
        return {
          type: stats.type,
          bsize: stats.bsize,
          blocks: Number(stats.blocks),
          bfree: Number(stats.bfree),
          bavail: Number(stats.bavail),
          files: Number(stats.files),
          ffree: Number(stats.ffree),
        };
      });
    },

    /**
     * `Treaddir`, minus the dots.
     *
     * The server synthesizes `.` and `..` because `v9fs_dir_readdir_dotl()`
     * never emits them itself; a driver's `readdir` does not report them, so
     * this is where they come back off.
     */
    async readdir(path) {
      return withFid(path, true, async (fid) => {
        await client.lopen(fid, O_RDONLY);
        const entries = await client.readdirAll(fid);
        return entries
          .filter((entry) => entry.name !== "." && entry.name !== "..")
          .map((entry) => direntOf(entry.name, entry.type));
      });
    },

    async open(path, flags = "r", mode = 0o666) {
      const wire = wireOpenFlags(flags, path);
      if ((wire & O_CREAT) === 0) {
        const { fid } = await walkTo(path, true);
        try {
          await client.lopen(fid, wire);
        } catch (error) {
          await dropQuietly(fid);
          throw error;
        }
        return makeHandle(fid, wire);
      }
      // `Tlcreate` spends the parent's fid: it goes in naming the directory and
      // comes out naming the new file, open. That is why the kernel always
      // clones one first, and why this one is not clunked on success.
      const { fid, name } = await parentOf(path, "open");
      try {
        await client.lcreate(fid, name, { flags: wire, mode: mode & 0o7777 });
      } catch (error) {
        await dropQuietly(fid);
        throw error;
      }
      return makeHandle(fid, wire);
    },

    async mkdir(path, options: MkdirOptions = {}) {
      const mode = (options.mode ?? 0o777) & 0o7777;
      if (options.recursive !== true) {
        await withParent(path, "mkdir", (fid, name) => client.mkdir(fid, name, mode));
        return undefined;
      }
      // `recursive` is a client-side loop, as it is on every wire: there is no
      // such operation, and the kernel's `mkdir -p` is several `Tmkdir`s too.
      const parts = normalizePath(path).split("/").filter(Boolean);
      let dir = await fromRoot();
      let first: string | undefined;
      let walked = "";
      try {
        for (const [index, name] of parts.entries()) {
          walked = joinPath(walked, name);
          const child = fids.take();
          let qid: P9Qid | undefined;
          try {
            qid = (await client.walk(dir, child, [name]))[0]!;
          } catch {
            // Not there, or not reachable — either way the `Tmkdir` below is
            // what says which, and says it with the right errno.
            fids.release(child);
          }
          if (qid !== undefined) {
            if ((qid.type & P9_QTDIR) === 0) {
              await dropQuietly(child);
              // The last component existing as a non-directory is `EEXIST`;
              // anything *inside* one is `ENOTDIR`, which is what `node:fs`
              // reports and what the driver would have said.
              throw fsError(index === parts.length - 1 ? "EEXIST" : "ENOTDIR", {
                syscall: "mkdir",
                path: walked,
              });
            }
            await dropQuietly(dir);
            dir = child;
            continue;
          }
          await client.mkdir(dir, name, mode);
          first ??= walked;
          const made = fids.take();
          try {
            await client.walk(dir, made, [name]);
          } catch (error) {
            fids.release(made);
            throw error;
          }
          await dropQuietly(dir);
          dir = made;
        }
      } finally {
        await dropQuietly(dir);
      }
      return first;
    },

    async rmdir(path) {
      await withParent(path, "rmdir", (fid, name) =>
        client.unlinkat(fid, name, P9_DOTL_AT_REMOVEDIR),
      );
    },
    async unlink(path) {
      await withParent(path, "unlink", (fid, name) => client.unlinkat(fid, name, 0));
    },
    async rename(from, to) {
      await withParent(from, "rename", async (oldFid, oldName) => {
        await withParent(to, "rename", (newFid, newName) =>
          client.renameat(oldFid, oldName, newFid, newName),
        );
      });
    },
    async link(existing, path) {
      // `lstat` semantics: a hardlink to a symlink links the link itself.
      await withFid(existing, false, async (fid) => {
        await withParent(path, "link", (dfid, name) => client.link(dfid, fid, name));
      });
    },
    async symlink(target, path) {
      await withParent(path, "symlink", (fid, name) => client.symlink(fid, name, target));
    },
    async readlink(path) {
      return withFid(path, false, (fid) => client.readlink(fid));
    },

    async chmod(path, mode) {
      await setattr(path, true, { valid: P9_SETATTR_MODE, mode: mode & 0o7777 });
    },
    async chown(path, uid, gid) {
      await setattr(path, true, ownership(uid, gid));
    },
    async lchown(path, uid, gid) {
      await setattr(path, false, ownership(uid, gid));
    },
    async truncate(path, length = 0) {
      await setattr(path, true, { valid: P9_SETATTR_SIZE, size: BigInt(length) });
    },
    async utimes(path, atime, mtime) {
      await setattr(path, true, times(atime, mtime));
    },
    async lutimes(path, atime, mtime) {
      await setattr(path, false, times(atime, mtime));
    },
  };
}
