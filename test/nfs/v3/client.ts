/**
 * A minimal NFSv3 client, built from the server's own codecs.
 *
 * This is the Tier-1 trick IDEA.md names: because the XDR and RPC codecs are
 * symmetric, the client that exercises the server can be written in JavaScript
 * — so the entire protocol runs over a real socket, in one process, with **no
 * mount and no root**. It is the NFS counterpart of `test/fuse/synthetic-kernel.ts`.
 *
 * Two layers:
 *
 * - {@link NfsClient} — RPC over TCP with record marking, plus one typed method
 *   per procedure. Nothing about paths; it speaks file handles, like the wire.
 * - {@link nfsDriver} — an `FsDriver` over a client, which is what lets
 *   `test/conformance.ts` run unmodified as the NFS column of the conformance
 *   matrix. It resolves paths component by component and follows symlinks
 *   itself, because that is what an NFS client does: the server never sees a
 *   multi-component path and never resolves a link.
 */

import * as net from "node:net";
import { constants } from "node:fs";
import { fsError, rangeError, type ErrnoCode } from "../../../src/errors.ts";
import {
  ACCESS3_ALL,
  AUTH_SYS,
  CREATE_GUARDED,
  CREATE_UNCHECKED,
  FILE_SYNC,
  MOUNT_PROGRAM,
  MOUNT_V3,
  MOUNTPROC3_DUMP,
  MOUNTPROC3_EXPORT,
  MOUNTPROC3_MNT,
  MOUNTPROC3_NULL,
  MOUNTPROC3_UMNT,
  MOUNTPROC3_UMNTALL,
  NF3BLK,
  NF3CHR,
  NF3DIR,
  NF3FIFO,
  NF3LNK,
  NF3SOCK,
  NFS3_COOKIEVERFSIZE,
  NFS3_OK,
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
  SET_TO_CLIENT_TIME,
} from "../../../src/nfs/v3/constants.ts";
import {
  authSys,
  decodeReply,
  encodeCall,
  frameRecord,
  RecordAssembler,
  type OpaqueAuth,
} from "../../../src/nfs/rpc.ts";
import {
  errnoCodeOfStatus,
  fromTime,
  modeTypeOf,
  readAccessRes,
  readCommitRes,
  readCreateRes,
  readFsinfoRes,
  readFsstatRes,
  readGetattrRes,
  readLinkRes,
  readLookupRes,
  readMountList,
  readMountRes,
  readExportList,
  readPathconfRes,
  readReadRes,
  readReaddirRes,
  readReaddirplusRes,
  readReadlinkRes,
  readRenameRes,
  readWccRes,
  readWriteRes,
  statusName,
  toTime,
  writeAccessArgs,
  writeCommitArgs,
  writeCreateArgs,
  writeDirOp,
  writeLinkArgs,
  writeMkdirArgs,
  writeMknodArgs,
  writeReadArgs,
  writeReaddirArgs,
  writeReaddirplusArgs,
  writeRenameArgs,
  writeSetattrArgs,
  writeSymlinkArgs,
  writeWriteArgs,
  type Commit3res,
  type Entry3,
  type EntryPlus3,
  type Fattr3,
  type Fsinfo3res,
  type Fsstat3res,
  type Lookup3res,
  type Mountres3,
  type Pathconf3res,
  type Read3res,
  type Sattr3,
  type Write3res,
} from "../../../src/nfs/v3/protocol.ts";
import { XdrReader, XdrWriter, encodeXdr } from "../../../src/nfs/xdr.ts";
import { basename, dirname, joinPath, normalizePath } from "../../../src/path.ts";
import type {
  DirentLike,
  FileHandleLike,
  FsDriver,
  MkdirOptions,
  ReadResult,
  StatsFsLike,
  StatsLike,
  TimeLike,
  WriteResult,
} from "../../../src/types.ts";
import {
  S_IFBLK,
  S_IFCHR,
  S_IFDIR,
  S_IFIFO,
  S_IFLNK,
  S_IFMT,
  S_IFREG,
  S_IFSOCK,
} from "../../../src/types.ts";

/** An RPC that came back as anything other than an accepted success. */
export class RpcError extends Error {
  readonly code = "ERR_NFS_RPC";

  constructor(message: string) {
    super(message);
    this.name = "RpcError";
  }
}

export interface NfsClientOptions {
  port: number;
  host?: string;
  /** Credentials on every call. Default: `AUTH_SYS` for this process. */
  cred?: OpaqueAuth;
}

/** RPC over TCP, plus one method per NFSv3 and MOUNTv3 procedure. */
export class NfsClient {
  readonly #socket: net.Socket;
  readonly #assembler = new RecordAssembler();
  readonly #pending = new Map<
    number,
    { resolve: (reader: XdrReader) => void; reject: (error: unknown) => void }
  >();
  readonly #cred: OpaqueAuth;
  #xid = 1;
  #closed: Error | undefined;

  private constructor(socket: net.Socket, cred: OpaqueAuth) {
    this.#socket = socket;
    this.#cred = cred;
    socket.on("data", (chunk: Buffer) => this.#onData(chunk));
    socket.on("error", (error) => this.#fail(error));
    socket.on("close", () => this.#fail(new RpcError("the connection closed")));
  }

  static connect(options: NfsClientOptions): Promise<NfsClient> {
    return new Promise((resolve, reject) => {
      const socket = net.connect({ port: options.port, host: options.host ?? "127.0.0.1" });
      socket.setNoDelay(true);
      socket.once("error", reject);
      socket.once("connect", () => {
        socket.off("error", reject);
        resolve(new NfsClient(socket, options.cred ?? authSys()));
      });
    });
  }

  close(): void {
    this.#socket.destroy();
    this.#fail(new RpcError("the client was closed"));
  }

  /** Calls still waiting for a reply. */
  get pending(): number {
    return this.#pending.size;
  }

  #onData(chunk: Buffer): void {
    for (const record of this.#assembler.push(chunk)) {
      const { reply, results } = decodeReply(record);
      const waiter = this.#pending.get(reply.xid);
      if (waiter === undefined) {
        continue;
      }
      this.#pending.delete(reply.xid);
      if (reply.replyStat === 0 && reply.acceptStat === 0) {
        waiter.resolve(results);
      } else {
        waiter.reject(
          new RpcError(
            `RPC failed: reply_stat ${reply.replyStat}, accept_stat ${reply.acceptStat}, ` +
              `reject_stat ${reply.rejectStat}, auth_stat ${reply.authStat}`,
          ),
        );
      }
    }
  }

  #fail(error: unknown): void {
    this.#closed ??= error instanceof Error ? error : new RpcError(String(error));
    for (const waiter of this.#pending.values()) {
      waiter.reject(this.#closed);
    }
    this.#pending.clear();
  }

  /** One RPC. Resolves to a reader positioned at the results. */
  call(program: number, version: number, procedure: number, args?: Uint8Array): Promise<XdrReader> {
    if (this.#closed !== undefined) {
      return Promise.reject(this.#closed);
    }
    const xid = this.#xid++;
    const message = encodeCall({
      xid,
      program,
      version,
      procedure,
      cred: this.#cred,
      args,
    });
    return new Promise<XdrReader>((resolve, reject) => {
      this.#pending.set(xid, { resolve, reject });
      this.#socket.write(frameRecord(message));
    });
  }

  /** Send an arbitrary already-encoded RPC message, for the protocol tests. */
  sendRaw(message: Uint8Array, xid: number): Promise<XdrReader> {
    return new Promise<XdrReader>((resolve, reject) => {
      this.#pending.set(xid, { resolve, reject });
      this.#socket.write(frameRecord(message));
    });
  }

  /** Send pre-framed bytes and wait for a reply addressed to `xid`. */
  sendFramed(framed: Uint8Array, xid: number): Promise<XdrReader> {
    return new Promise<XdrReader>((resolve, reject) => {
      this.#pending.set(xid, { resolve, reject });
      this.#socket.write(framed);
    });
  }

  #nfs(procedure: number, args?: Uint8Array): Promise<XdrReader> {
    return this.call(NFS_PROGRAM, NFS_V3, procedure, args);
  }

  #mount(procedure: number, args?: Uint8Array): Promise<XdrReader> {
    return this.call(MOUNT_PROGRAM, MOUNT_V3, procedure, args);
  }

  // --- MOUNT ---

  async mountNull(): Promise<void> {
    (await this.#mount(MOUNTPROC3_NULL)).end("MOUNT NULL reply");
  }

  async mnt(dirpath: string): Promise<Mountres3> {
    const reader = await this.#mount(
      MOUNTPROC3_MNT,
      encodeXdr((w) => w.string(dirpath)),
    );
    const res = readMountRes(reader);
    reader.end("MNT reply");
    return res;
  }

  async umnt(dirpath: string): Promise<void> {
    (
      await this.#mount(
        MOUNTPROC3_UMNT,
        encodeXdr((w) => w.string(dirpath)),
      )
    ).end("UMNT reply");
  }

  async umntall(): Promise<void> {
    (await this.#mount(MOUNTPROC3_UMNTALL)).end("UMNTALL reply");
  }

  async dump(): Promise<{ hostname: string; directory: string }[]> {
    const reader = await this.#mount(MOUNTPROC3_DUMP);
    const list = readMountList(reader);
    reader.end("DUMP reply");
    return list;
  }

  async exports(): Promise<{ directory: string; groups: string[] }[]> {
    const reader = await this.#mount(MOUNTPROC3_EXPORT);
    const list = readExportList(reader);
    reader.end("EXPORT reply");
    return list;
  }

  // --- NFS ---

  async null(): Promise<void> {
    (await this.#nfs(NFSPROC3_NULL)).end("NULL reply");
  }

  async getattr(fh: Uint8Array): Promise<{ status: number; attributes: Fattr3 | undefined }> {
    const reader = await this.#nfs(
      NFSPROC3_GETATTR,
      encodeXdr((w) => w.varOpaque(fh)),
    );
    const res = readGetattrRes(reader);
    reader.end("GETATTR reply");
    return res;
  }

  async setattr(
    fh: Uint8Array,
    attributes: Sattr3,
    guard?: { seconds: number; nseconds: number },
  ): Promise<ReturnType<typeof readWccRes>> {
    const reader = await this.#nfs(
      NFSPROC3_SETATTR,
      encodeXdr((w) => writeSetattrArgs(w, { object: fh, attributes, guard })),
    );
    const res = readWccRes(reader);
    reader.end("SETATTR reply");
    return res;
  }

  async lookup(dir: Uint8Array, name: string): Promise<Lookup3res> {
    const reader = await this.#nfs(
      NFSPROC3_LOOKUP,
      encodeXdr((w) => writeDirOp(w, { dir, name })),
    );
    const res = readLookupRes(reader);
    reader.end("LOOKUP reply");
    return res;
  }

  async access(fh: Uint8Array, access = ACCESS3_ALL): Promise<ReturnType<typeof readAccessRes>> {
    const reader = await this.#nfs(
      NFSPROC3_ACCESS,
      encodeXdr((w) => writeAccessArgs(w, { object: fh, access })),
    );
    const res = readAccessRes(reader);
    reader.end("ACCESS reply");
    return res;
  }

  async readlink(fh: Uint8Array): Promise<ReturnType<typeof readReadlinkRes>> {
    const reader = await this.#nfs(
      NFSPROC3_READLINK,
      encodeXdr((w) => w.varOpaque(fh)),
    );
    const res = readReadlinkRes(reader);
    reader.end("READLINK reply");
    return res;
  }

  async read(fh: Uint8Array, offset: bigint, count: number): Promise<Read3res> {
    const reader = await this.#nfs(
      NFSPROC3_READ,
      encodeXdr((w) => writeReadArgs(w, { file: fh, offset, count })),
    );
    const res = readReadRes(reader);
    reader.end("READ reply");
    return res;
  }

  async write(
    fh: Uint8Array,
    offset: bigint,
    data: Uint8Array,
    stable = FILE_SYNC,
  ): Promise<Write3res> {
    const reader = await this.#nfs(
      NFSPROC3_WRITE,
      encodeXdr(
        (w) => writeWriteArgs(w, { file: fh, offset, count: data.byteLength, stable, data }),
        data.byteLength + 128,
      ),
    );
    const res = readWriteRes(reader);
    reader.end("WRITE reply");
    return res;
  }

  async create(
    dir: Uint8Array,
    name: string,
    mode: number,
    attributes: Sattr3 = {},
    verf?: Uint8Array,
  ): Promise<ReturnType<typeof readCreateRes>> {
    const reader = await this.#nfs(
      NFSPROC3_CREATE,
      encodeXdr((w) => writeCreateArgs(w, { where: { dir, name }, mode, attributes, verf })),
    );
    const res = readCreateRes(reader);
    reader.end("CREATE reply");
    return res;
  }

  async mkdir(
    dir: Uint8Array,
    name: string,
    attributes: Sattr3 = {},
  ): Promise<ReturnType<typeof readCreateRes>> {
    const reader = await this.#nfs(
      NFSPROC3_MKDIR,
      encodeXdr((w) => writeMkdirArgs(w, { where: { dir, name }, attributes })),
    );
    const res = readCreateRes(reader);
    reader.end("MKDIR reply");
    return res;
  }

  async symlink(
    dir: Uint8Array,
    name: string,
    target: string,
    attributes: Sattr3 = {},
  ): Promise<ReturnType<typeof readCreateRes>> {
    const reader = await this.#nfs(
      NFSPROC3_SYMLINK,
      encodeXdr((w) => writeSymlinkArgs(w, { where: { dir, name }, attributes, target })),
    );
    const res = readCreateRes(reader);
    reader.end("SYMLINK reply");
    return res;
  }

  async mknod(
    dir: Uint8Array,
    name: string,
    type: number,
    attributes: Sattr3 = {},
    spec?: { major: number; minor: number },
  ): Promise<ReturnType<typeof readCreateRes>> {
    const reader = await this.#nfs(
      NFSPROC3_MKNOD,
      encodeXdr((w) => writeMknodArgs(w, { where: { dir, name }, type, attributes, spec })),
    );
    const res = readCreateRes(reader);
    reader.end("MKNOD reply");
    return res;
  }

  async remove(dir: Uint8Array, name: string): Promise<ReturnType<typeof readWccRes>> {
    const reader = await this.#nfs(
      NFSPROC3_REMOVE,
      encodeXdr((w) => writeDirOp(w, { dir, name })),
    );
    const res = readWccRes(reader);
    reader.end("REMOVE reply");
    return res;
  }

  async rmdir(dir: Uint8Array, name: string): Promise<ReturnType<typeof readWccRes>> {
    const reader = await this.#nfs(
      NFSPROC3_RMDIR,
      encodeXdr((w) => writeDirOp(w, { dir, name })),
    );
    const res = readWccRes(reader);
    reader.end("RMDIR reply");
    return res;
  }

  async rename(
    fromDir: Uint8Array,
    fromName: string,
    toDir: Uint8Array,
    toName: string,
  ): Promise<ReturnType<typeof readRenameRes>> {
    const reader = await this.#nfs(
      NFSPROC3_RENAME,
      encodeXdr((w) =>
        writeRenameArgs(w, {
          from: { dir: fromDir, name: fromName },
          to: { dir: toDir, name: toName },
        }),
      ),
    );
    const res = readRenameRes(reader);
    reader.end("RENAME reply");
    return res;
  }

  async link(
    file: Uint8Array,
    dir: Uint8Array,
    name: string,
  ): Promise<ReturnType<typeof readLinkRes>> {
    const reader = await this.#nfs(
      NFSPROC3_LINK,
      encodeXdr((w) => writeLinkArgs(w, { file, link: { dir, name } })),
    );
    const res = readLinkRes(reader);
    reader.end("LINK reply");
    return res;
  }

  async readdir(
    dir: Uint8Array,
    cookie = 0n,
    cookieverf: Uint8Array = new Uint8Array(NFS3_COOKIEVERFSIZE),
    count = 8192,
  ): Promise<ReturnType<typeof readReaddirRes>> {
    const reader = await this.#nfs(
      NFSPROC3_READDIR,
      encodeXdr((w) => writeReaddirArgs(w, { dir, cookie, cookieverf, count })),
    );
    const res = readReaddirRes(reader);
    reader.end("READDIR reply");
    return res;
  }

  async readdirplus(
    dir: Uint8Array,
    cookie = 0n,
    cookieverf: Uint8Array = new Uint8Array(NFS3_COOKIEVERFSIZE),
    dircount = 8192,
    maxcount = 32_768,
  ): Promise<ReturnType<typeof readReaddirplusRes>> {
    const reader = await this.#nfs(
      NFSPROC3_READDIRPLUS,
      encodeXdr((w) => writeReaddirplusArgs(w, { dir, cookie, cookieverf, dircount, maxcount })),
    );
    const res = readReaddirplusRes(reader);
    reader.end("READDIRPLUS reply");
    return res;
  }

  async fsstat(fh: Uint8Array): Promise<Fsstat3res> {
    const reader = await this.#nfs(
      NFSPROC3_FSSTAT,
      encodeXdr((w) => w.varOpaque(fh)),
    );
    const res = readFsstatRes(reader);
    reader.end("FSSTAT reply");
    return res;
  }

  async fsinfo(fh: Uint8Array): Promise<Fsinfo3res> {
    const reader = await this.#nfs(
      NFSPROC3_FSINFO,
      encodeXdr((w) => w.varOpaque(fh)),
    );
    const res = readFsinfoRes(reader);
    reader.end("FSINFO reply");
    return res;
  }

  async pathconf(fh: Uint8Array): Promise<Pathconf3res> {
    const reader = await this.#nfs(
      NFSPROC3_PATHCONF,
      encodeXdr((w) => w.varOpaque(fh)),
    );
    const res = readPathconfRes(reader);
    reader.end("PATHCONF reply");
    return res;
  }

  async commit(fh: Uint8Array, offset = 0n, count = 0): Promise<Commit3res> {
    const reader = await this.#nfs(
      NFSPROC3_COMMIT,
      encodeXdr((w) => writeCommitArgs(w, { file: fh, offset, count })),
    );
    const res = readCommitRes(reader);
    reader.end("COMMIT reply");
    return res;
  }

  /** Every entry of a directory, paging through the cookies. */
  async readdirAll(dir: Uint8Array, count = 8192): Promise<Entry3[]> {
    const all: Entry3[] = [];
    let cookie = 0n;
    let verf: Uint8Array = new Uint8Array(NFS3_COOKIEVERFSIZE);
    for (;;) {
      const page = check(await this.readdir(dir, cookie, verf, count), "readdir");
      all.push(...page.entries);
      if (page.eof) {
        return all;
      }
      verf = page.cookieverf;
      cookie = page.entries.at(-1)!.cookie;
    }
  }

  /** Every entry of a directory with attributes, paging through the cookies. */
  async readdirplusAll(dir: Uint8Array, dircount = 8192, maxcount = 32_768): Promise<EntryPlus3[]> {
    const all: EntryPlus3[] = [];
    let cookie = 0n;
    let verf: Uint8Array = new Uint8Array(NFS3_COOKIEVERFSIZE);
    for (;;) {
      const page = check(await this.readdirplus(dir, cookie, verf, dircount, maxcount), "readdir");
      all.push(...page.entries);
      if (page.eof) {
        return all;
      }
      verf = page.cookieverf;
      cookie = page.entries.at(-1)!.cookie;
    }
  }
}

/** Throw a `node:fs`-shaped error unless the result succeeded. */
export function check<T extends { status: number }>(result: T, syscall: string, path?: string): T {
  if (result.status !== NFS3_OK) {
    throw fsError(errnoCodeOfStatus(result.status) as ErrnoCode, {
      syscall,
      path,
      cause: new Error(statusName(result.status)),
    });
  }
  return result;
}

// ---------------------------------------------------------------------------
// the driver over a client
// ---------------------------------------------------------------------------

/** A `fattr3` as the `StatsLike` a driver has to return. */
export function statsOf(attr: Fattr3): StatsLike {
  const mode = modeTypeOf(attr.type) | (attr.mode & 0o7777);
  const is = (bits: number): boolean => (mode & S_IFMT) === bits;
  return {
    dev: Number(attr.fsid),
    ino: Number(attr.fileid),
    mode,
    nlink: attr.nlink,
    uid: attr.uid,
    gid: attr.gid,
    rdev: (attr.rdev.major << 8) | attr.rdev.minor,
    size: Number(attr.size),
    blksize: 4096,
    blocks: Number(attr.used / 512n),
    atimeMs: fromTime(attr.atime),
    mtimeMs: fromTime(attr.mtime),
    ctimeMs: fromTime(attr.ctime),
    birthtimeMs: fromTime(attr.ctime),
    isFile: () => is(S_IFREG),
    isDirectory: () => is(S_IFDIR),
    isSymbolicLink: () => is(S_IFLNK),
    isBlockDevice: () => is(0o060_000),
    isCharacterDevice: () => is(0o020_000),
    isFIFO: () => is(0o010_000),
    isSocket: () => is(0o140_000),
  };
}

function direntOf(name: string, attr: Fattr3 | undefined): DirentLike {
  const stats = attr === undefined ? undefined : statsOf(attr);
  return {
    name,
    isFile: () => stats?.isFile() ?? false,
    isDirectory: () => stats?.isDirectory() ?? false,
    isSymbolicLink: () => stats?.isSymbolicLink() ?? false,
    isBlockDevice: () => stats?.isBlockDevice() ?? false,
    isCharacterDevice: () => stats?.isCharacterDevice() ?? false,
    isFIFO: () => stats?.isFIFO() ?? false,
    isSocket: () => stats?.isSocket() ?? false,
  };
}

function timeOf(value: TimeLike): { seconds: number; nseconds: number } {
  const ms = value instanceof Date ? value.getTime() : value * 1000;
  return toTime(ms);
}

/**
 * The `ftype3` a `mknod` mode is asking for — and a plain `Error` when it is
 * asking for something MKNOD has no way to say.
 *
 * `mknoddata3` switches on `ftype3` and MKNOD's four legal arms are BLK, CHR,
 * SOCK and FIFO (§3.3.11); the mode's `S_IFMT` reaches the wire *only* here,
 * because `sattr3.mode` is masked to `0o7777` on the way out and again by
 * `NfsSession.#mknod` on the way in. So a type outside those four cannot be
 * asked for over NFSv3 at all.
 *
 * What is thrown for one is deliberately **not** errno-shaped: no `code`, no
 * `errno`, nothing `rejects()` in the conformance suite could match. Invariant
 * 5 is the whole point — a client that answered `EPERM` for `S_IFDIR` here
 * would be inventing the refusal that the driver on the far side is supposed to
 * make, and the column would pass a case it never carried. The cases that need
 * it are gated on `mknod.anyType`, which this column does not claim; anyone who
 * un-gates one gets this, loudly, instead of a fabricated errno.
 */
function ftype3Of(mode: number): number {
  switch (mode & S_IFMT) {
    case S_IFBLK: {
      return NF3BLK;
    }
    case S_IFCHR: {
      return NF3CHR;
    }
    case S_IFSOCK: {
      return NF3SOCK;
    }
    case S_IFIFO: {
      return NF3FIFO;
    }
    default: {
      throw new Error(
        `NFSv3 MKNOD cannot ask for the type in mode 0o${mode.toString(8)}: ` +
          "`mknoddata3` has an arm for a block device, a character device, a socket " +
          "and a FIFO, and nothing else carries the type",
      );
    }
  }
}

/** How many symlinks a resolution may traverse before it is a loop. */
const MAX_SYMLINKS = 40;

interface Resolved {
  fh: Uint8Array;
  attr: Fattr3;
}

/**
 * `FsDriver` over an {@link NfsClient}.
 *
 * The path walking is the interesting part: NFS has no notion of a path with
 * more than one component and never resolves a symlink, so a client that wants
 * `stat("/a/b/c")` issues three `LOOKUP`s and does the link chasing itself.
 * Getting that wrong is how a real client would report `ENOENT` for a file that
 * exists, so it is worth having under the same conformance suite as everything
 * else.
 */
export function nfsDriver(client: NfsClient, root: Uint8Array): FsDriver {
  /** Resolve every component of `path`, following symlinks as `follow` says. */
  async function walk(path: string, follow: boolean, depth = 0): Promise<Resolved> {
    if (depth > MAX_SYMLINKS) {
      throw fsError("ELOOP", { syscall: "open", path });
    }
    const parts = normalizePath(path).split("/").filter(Boolean);
    let current: Resolved = {
      fh: root,
      attr: check(await client.getattr(root), "stat").attributes!,
    };
    for (const [index, name] of parts.entries()) {
      const last = index === parts.length - 1;
      const found = check(await client.lookup(current.fh, name), "lookup", path);
      let next: Resolved = { fh: found.object!, attr: found.objAttributes! };
      if (next.attr === undefined) {
        next = {
          fh: found.object!,
          attr: check(await client.getattr(found.object!), "stat").attributes!,
        };
      }
      if (next.attr.type === NF3LNK && (follow || !last)) {
        const target = check(await client.readlink(next.fh), "readlink", path).target!;
        const rest = parts.slice(index + 1).join("/");
        const base = target.startsWith("/")
          ? normalizePath(target)
          : joinPath(currentDir(parts, index), target);
        return walk(rest === "" ? base : joinPath(base, rest), follow, depth + 1);
      }
      current = next;
    }
    return current;
  }

  /** The directory `parts[index]` lives in, as an absolute path. */
  function currentDir(parts: string[], index: number): string {
    return index === 0 ? "/" : `/${parts.slice(0, index).join("/")}`;
  }

  /** Resolve the *parent* of a path, plus the final name. */
  async function parentOf(
    path: string,
    syscall: string,
  ): Promise<{ dir: Uint8Array; name: string }> {
    const normalized = normalizePath(path);
    if (normalized === "/") {
      throw fsError("EINVAL", { syscall, path });
    }
    const dir = await walk(dirname(normalized), true);
    if (dir.attr.type !== NF3DIR) {
      throw fsError("ENOTDIR", { syscall, path });
    }
    return { dir: dir.fh, name: basename(normalized) };
  }

  async function attrsOf(fh: Uint8Array): Promise<StatsLike> {
    return statsOf(check(await client.getattr(fh), "stat").attributes!);
  }

  function checkReadArgs(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): void {
    if (offset < 0 || offset > buffer.byteLength) {
      throw rangeError("offset", `>= 0 && <= ${buffer.byteLength}`, offset);
    }
    if (length < 0 || offset + length > buffer.byteLength) {
      throw rangeError("length", `>= 0 && <= ${buffer.byteLength - offset}`, length);
    }
    if (position < -1) {
      throw rangeError("position", ">= -1", position);
    }
  }

  /**
   * A file handle synthesized on the client.
   *
   * NFSv3 has no `open`, so this is entirely local state: the file handle, the
   * flags the caller asked for, and a read/write position. Which is exactly
   * what a real NFS client keeps, and exactly why `unlink` on an open file is
   * the one capability this transport loses.
   */
  function makeHandle(fh: Uint8Array, flags: number): FileHandleLike {
    let position = 0;
    const writable = (flags & constants.O_WRONLY) !== 0 || (flags & constants.O_RDWR) !== 0;
    const readable = (flags & constants.O_WRONLY) === 0;
    const append = (flags & constants.O_APPEND) !== 0;
    return {
      async read(buffer, offset = 0, length, at): Promise<ReadResult> {
        const start = offset ?? 0;
        const count = length ?? buffer.byteLength - start;
        const from = at ?? -1;
        checkReadArgs(buffer, start, count, from);
        if (!readable) {
          throw fsError("EBADF", { syscall: "read" });
        }
        const where = from === -1 ? position : from;
        const result = check(await client.read(fh, BigInt(where), count), "read");
        buffer.set(result.data, start);
        if (from === -1) {
          position = where + result.data.byteLength;
        }
        return { bytesRead: result.data.byteLength, buffer };
      },
      async write(buffer, offset = 0, length, at): Promise<WriteResult> {
        const start = offset ?? 0;
        const count = length ?? buffer.byteLength - start;
        const from = at ?? -1;
        checkReadArgs(buffer, start, count, from);
        if (!writable) {
          throw fsError("EBADF", { syscall: "write" });
        }
        let where = from === -1 ? position : from;
        if (append) {
          where = Number(check(await client.getattr(fh), "stat").attributes!.size);
        }
        const result = check(
          await client.write(fh, BigInt(where), buffer.subarray(start, start + count)),
          "write",
        );
        if (from === -1 || append) {
          position = where + result.count;
        }
        return { bytesWritten: result.count, buffer };
      },
      stat: () => attrsOf(fh),
      async truncate(length = 0): Promise<void> {
        check(await client.setattr(fh, { size: BigInt(length) }), "ftruncate");
      },
      async close(): Promise<void> {
        if (writable) {
          check(await client.commit(fh), "fsync");
        }
      },
      async sync(): Promise<void> {
        check(await client.commit(fh), "fsync");
      },
      async datasync(): Promise<void> {
        check(await client.commit(fh), "fdatasync");
      },
    };
  }

  return {
    // NFSv3 is stateless, so an open file has no server-side existence and
    // cannot survive `unlink`. `rename` is a single server operation, so it is
    // atomic in the sense the capability means. `extensions` is inferred from
    // the keys of `mountx` below, so it is not here.
    capabilities: { handles: false, atomicRename: true },

    mountx: {
      /**
       * MKNOD, which is the one place this adapter offers a `mountx.*` member
       * by name.
       *
       * It is not the extension crossing the wire — it is the wire operation
       * that already exists wearing the name the driver interface has for it.
       * What NFSv3 carries is a *type* and a *mode*, in separate fields: the
       * type in `ftype3` (see {@link ftype3Of}), the permission bits in
       * `sattr3.mode`, and `NfsSession.#mknod` puts the two back together for
       * the driver. So the four device-ish types route faithfully and nothing
       * else does, which is what `carries` in `./conformance.test.ts` says.
       *
       * `dev` comes apart the way `NfsSession.#mknod` puts it back together —
       * one 8-bit split across the project — which is what makes the round trip
       * through `specdata3`'s `major`/`minor` and back out of `fattr3.rdev`
       * worth testing at all. Every refusal the cases assert is the far side's,
       * arriving as an `nfsstat3`: nothing is decided here.
       */
      async mknod(path, mode, dev) {
        const type = ftype3Of(mode);
        const { dir, name } = await parentOf(path, "mknod");
        check(
          await client.mknod(
            dir,
            name,
            type,
            { mode: mode & 0o7777 },
            { major: dev >>> 8, minor: dev & 0xff },
          ),
          "mknod",
          path,
        );
      },
    },

    async stat(path) {
      return statsOf((await walk(path, true)).attr);
    },
    async lstat(path) {
      return statsOf((await walk(path, false)).attr);
    },
    async statfs(path): Promise<StatsFsLike> {
      const { fh } = await walk(path, true);
      const stats = check(await client.fsstat(fh), "statfs", path);
      const info = check(await client.fsinfo(fh), "statfs", path);
      const bsize = info.rtmult || 4096;
      return {
        type: 0x6969, // NFS_SUPER_MAGIC, as `statfs(2)` reports for an NFS mount.
        bsize,
        blocks: Number(stats.tbytes / BigInt(bsize)),
        bfree: Number(stats.fbytes / BigInt(bsize)),
        bavail: Number(stats.abytes / BigInt(bsize)),
        files: Number(stats.tfiles),
        ffree: Number(stats.ffiles),
      };
    },

    async readdir(path) {
      const { fh, attr } = await walk(path, true);
      if (attr.type !== NF3DIR) {
        throw fsError("ENOTDIR", { syscall: "scandir", path });
      }
      const entries = await client.readdirplusAll(fh);
      return entries.map((entry) => direntOf(entry.name, entry.attributes));
    },

    async open(path, flags = "r", mode = 0o666) {
      const numeric = typeof flags === "number" ? flags : flagsOf(flags);
      if ((numeric & constants.O_CREAT) === 0) {
        const target = await walk(path, true);
        const writing = (numeric & constants.O_WRONLY) !== 0 || (numeric & constants.O_RDWR) !== 0;
        if (target.attr.type === NF3DIR && writing) {
          throw fsError("EISDIR", { syscall: "open", path });
        }
        if ((numeric & constants.O_TRUNC) !== 0) {
          check(await client.setattr(target.fh, { size: 0n }), "open", path);
        }
        return makeHandle(target.fh, numeric);
      }
      const { dir, name } = await parentOf(path, "open");
      const attributes: Sattr3 = { mode: mode & 0o7777 };
      if ((numeric & constants.O_TRUNC) !== 0) {
        attributes.size = 0n;
      }
      const created = check(
        await client.create(
          dir,
          name,
          (numeric & constants.O_EXCL) !== 0 ? CREATE_GUARDED : CREATE_UNCHECKED,
          attributes,
        ),
        "open",
        path,
      );
      return makeHandle(created.obj!, numeric);
    },

    async mkdir(path, options: MkdirOptions = {}) {
      if (options.recursive !== true) {
        const { dir, name } = await parentOf(path, "mkdir");
        check(
          await client.mkdir(dir, name, { mode: (options.mode ?? 0o777) & 0o7777 }),
          "mkdir",
          path,
        );
        return undefined;
      }
      // `recursive` is a client-side loop: NFS has no such operation, which is
      // also true of the kernel's client.
      const parts = normalizePath(path).split("/").filter(Boolean);
      let dir = root;
      let first: string | undefined;
      let walked = "";
      for (const [index, name] of parts.entries()) {
        walked = joinPath(walked, name);
        const found = await client.lookup(dir, name);
        if (found.status === NFS3_OK) {
          if (found.objAttributes?.type !== NF3DIR) {
            // The last component already existing as a non-directory is
            // `EEXIST`; anything *inside* a non-directory is `ENOTDIR`, which
            // is what `node:fs` reports and what the driver would have said.
            throw fsError(index === parts.length - 1 ? "EEXIST" : "ENOTDIR", {
              syscall: "mkdir",
              path: walked,
            });
          }
          dir = found.object!;
          continue;
        }
        const made = check(
          await client.mkdir(dir, name, { mode: (options.mode ?? 0o777) & 0o7777 }),
          "mkdir",
          walked,
        );
        first ??= walked;
        dir = made.obj!;
      }
      return first;
    },

    async rmdir(path) {
      const { dir, name } = await parentOf(path, "rmdir");
      check(await client.rmdir(dir, name), "rmdir", path);
    },
    async unlink(path) {
      const { dir, name } = await parentOf(path, "unlink");
      check(await client.remove(dir, name), "unlink", path);
    },
    async rename(from, to) {
      const source = await parentOf(from, "rename");
      const destination = await parentOf(to, "rename");
      check(
        await client.rename(source.dir, source.name, destination.dir, destination.name),
        "rename",
        from,
      );
    },
    async link(existing, path) {
      const target = await walk(existing, false);
      const { dir, name } = await parentOf(path, "link");
      check(await client.link(target.fh, dir, name), "link", path);
    },
    async symlink(target, path) {
      const { dir, name } = await parentOf(path, "symlink");
      check(await client.symlink(dir, name, target), "symlink", path);
    },
    async readlink(path) {
      const { fh } = await walk(path, false);
      return check(await client.readlink(fh), "readlink", path).target!;
    },

    async chmod(path, mode) {
      const { fh } = await walk(path, true);
      check(await client.setattr(fh, { mode: mode & 0o7777 }), "chmod", path);
    },
    async chown(path, uid, gid) {
      const { fh } = await walk(path, true);
      check(await client.setattr(fh, ownership(uid, gid)), "chown", path);
    },
    async lchown(path, uid, gid) {
      const { fh } = await walk(path, false);
      check(await client.setattr(fh, ownership(uid, gid)), "lchown", path);
    },
    async truncate(path, length = 0) {
      const { fh } = await walk(path, true);
      check(await client.setattr(fh, { size: BigInt(length) }), "truncate", path);
    },
    async utimes(path, atime, mtime) {
      const { fh } = await walk(path, true);
      check(await client.setattr(fh, times(atime, mtime)), "utimes", path);
    },
    async lutimes(path, atime, mtime) {
      const { fh } = await walk(path, false);
      check(await client.setattr(fh, times(atime, mtime)), "lutimes", path);
    },
  };
}

function ownership(uid: number, gid: number): Sattr3 {
  return {
    uid: uid >= 0 ? uid : undefined,
    gid: gid >= 0 ? gid : undefined,
  };
}

function times(atime: TimeLike, mtime: TimeLike): Sattr3 {
  return {
    atime: { how: SET_TO_CLIENT_TIME, time: timeOf(atime) },
    mtime: { how: SET_TO_CLIENT_TIME, time: timeOf(mtime) },
  };
}

/** `node:fs`'s flag strings, as `O_*` bits. */
export function flagsOf(flags: string): number {
  switch (flags) {
    case "r": {
      return constants.O_RDONLY;
    }
    case "r+": {
      return constants.O_RDWR;
    }
    case "w": {
      return constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC;
    }
    case "wx": {
      return constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL;
    }
    case "w+": {
      return constants.O_RDWR | constants.O_CREAT | constants.O_TRUNC;
    }
    case "wx+": {
      return constants.O_RDWR | constants.O_CREAT | constants.O_EXCL;
    }
    case "a": {
      return constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND;
    }
    case "ax": {
      return constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_APPEND;
    }
    case "a+": {
      return constants.O_RDWR | constants.O_CREAT | constants.O_APPEND;
    }
    default: {
      throw new Error(`mountx test client: unsupported open flags ${JSON.stringify(flags)}`);
    }
  }
}

/** Encode a `sattr3` on its own, for the tests that build arguments by hand. */
export function sattr(attributes: Sattr3): Uint8Array {
  const writer = new XdrWriter(64);
  writeSetattrArgs(writer, { object: new Uint8Array(0), attributes, guard: undefined });
  return writer.bytes();
}

/** The `AUTH_SYS` credential the driver client uses, exported for the auth tests. */
export const CLIENT_CRED_FLAVOR = AUTH_SYS;
