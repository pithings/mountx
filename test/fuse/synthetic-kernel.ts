/**
 * A synthetic kernel: the other side of the session.
 *
 * This is the payoff of a symmetric protocol layer (IDEA.md, Tier 0) — the
 * encoders for everything the kernel sends and the decoders for everything the
 * server replies already exist, so "a kernel" is a few hundred lines of glue
 * that drives the whole session layer with no `/dev/fuse` anywhere.
 *
 * It keeps the two pieces of state a real kernel keeps and a session depends
 * on: a monotonic `unique` counter, and a per-nodeid tally of outstanding
 * lookups, so a test can say `forgetAll(nodeid)` and mean it.
 *
 * Not a `*.test.ts` file: it is imported by them.
 */

import { ERRNO_CODES, type ErrnoCode } from "../../src/errors.ts";
import {
  FUSE_BATCH_FORGET,
  FUSE_CREATE,
  FUSE_DESTROY,
  FUSE_FLUSH,
  FUSE_FORGET,
  FUSE_FSYNC,
  FUSE_FSYNCDIR,
  FUSE_GETATTR,
  FUSE_GETATTR_FH,
  FUSE_INIT,
  FUSE_INTERRUPT,
  FUSE_KERNEL_MINOR_VERSION,
  FUSE_KERNEL_VERSION,
  FUSE_LINK,
  FUSE_LOOKUP,
  FUSE_MKDIR,
  FUSE_MKNOD,
  FUSE_OPEN,
  FUSE_OPENDIR,
  FUSE_READ,
  FUSE_READDIR,
  FUSE_READDIRPLUS,
  FUSE_READLINK,
  FUSE_RELEASE,
  FUSE_RELEASEDIR,
  FUSE_RENAME,
  FUSE_RENAME2,
  FUSE_RMDIR,
  FUSE_ROOT_ID,
  FUSE_SETATTR,
  FUSE_STATFS,
  FUSE_SYMLINK,
  FUSE_UNLINK,
  FUSE_WRITE,
  opcodeName,
} from "../../src/fuse/constants.ts";
import { splitInitFlags } from "../../src/fuse/init.ts";
import {
  decodeReply,
  encodeRequest,
  type FuseAttrOut,
  type FuseCreateOut,
  type FuseDirentsOut,
  type FuseDirentsPlusOut,
  type FuseEntryOut,
  type FuseInitOut,
  type FuseKstatfs,
  type FuseOpenOut,
  type FuseRawData,
  type FuseReadlinkOut,
  type FuseSetattrIn,
  type FuseWriteOut,
  type ProtocolContext,
} from "../../src/fuse/protocol.ts";
import type { FuseSession } from "../../src/fuse/session.ts";

const ERRNO_NAMES = new Map<number, ErrnoCode>(
  Object.entries(ERRNO_CODES).map(([name, value]) => [value, name as ErrnoCode]),
);

/** A negative-errno reply, thrown so tests can `rejects.toMatchObject`. */
export class KernelError extends Error {
  /** Positive Linux errno. */
  readonly errno: number;
  /** POSIX name, or `UNKNOWN(n)`. */
  readonly code: string;

  constructor(opcode: number, error: number) {
    const errno = Math.abs(error);
    const code = ERRNO_NAMES.get(errno) ?? `UNKNOWN(${errno})`;
    super(`${opcodeName(opcode)} failed: ${code}`);
    this.name = "KernelError";
    this.errno = errno;
    this.code = code;
  }
}

/** What the wire actually carried back, error or not. */
export interface RawReply {
  /** Negative errno, or `0`. */
  error: number;
  unique: bigint;
  payload: Uint8Array;
  /** Decoded body, or `undefined` on an error reply. */
  body: unknown;
}

export interface SyntheticKernelOptions {
  uid?: number;
  gid?: number;
  pid?: number;
  /** Flags the "kernel" offers in `FUSE_INIT`. Default: everything. */
  initFlags?: bigint;
  minor?: number;
}

/** Every `FUSE_*` init flag defined at 7.41, i.e. a maximally capable kernel. */
export const ALL_INIT_FLAGS = (1n << 41n) - 1n;

const encoder = new TextEncoder();

export class SyntheticKernel {
  readonly session: FuseSession;
  readonly options: SyntheticKernelOptions;
  /** Outstanding lookups per nodeid, exactly as the kernel would count them. */
  readonly lookups = new Map<bigint, bigint>();
  /** Every reply seen, newest last — handy when a test wants the raw bytes. */
  readonly replies: RawReply[] = [];
  #unique = 1n;

  constructor(session: FuseSession, options: SyntheticKernelOptions = {}) {
    this.session = session;
    this.options = options;
  }

  get ctx(): ProtocolContext | undefined {
    return this.session.protocol;
  }

  /** The `unique` the next request will carry. */
  get nextUnique(): bigint {
    return this.#unique;
  }

  // --- plumbing ---

  /** Send one request and return whatever came back, errors included. */
  async raw(
    opcode: number,
    init: { nodeid?: bigint; body?: unknown; payload?: Uint8Array; unique?: bigint } = {},
  ): Promise<RawReply> {
    const unique = init.unique ?? this.#unique++;
    const message = encodeRequest(
      {
        opcode,
        unique,
        nodeid: init.nodeid ?? FUSE_ROOT_ID,
        uid: this.options.uid ?? 1000,
        gid: this.options.gid ?? 1000,
        pid: this.options.pid ?? 4242,
        body: init.body,
        payload: init.payload,
      },
      this.ctx,
    );
    const response = await this.session.handleMessage(message);
    if (response === null) {
      throw new Error(`${opcodeName(opcode)} got no reply`);
    }
    const reply = decodeReply(response, opcode, this.ctx);
    if (reply.header.unique !== unique) {
      throw new Error(
        `${opcodeName(opcode)} replied to unique ${reply.header.unique}, expected ${unique}`,
      );
    }
    const result: RawReply = {
      error: reply.header.error,
      unique,
      payload: reply.payload,
      body: reply.body,
    };
    this.replies.push(result);
    return result;
  }

  /** Send one request, throwing {@link KernelError} on a negative errno. */
  async call<T>(
    opcode: number,
    init: { nodeid?: bigint; body?: unknown; payload?: Uint8Array } = {},
  ): Promise<T> {
    const reply = await this.raw(opcode, init);
    if (reply.error !== 0) {
      throw new KernelError(opcode, reply.error);
    }
    return reply.body as T;
  }

  /** Send a request the kernel wants no answer to, and assert it gets none. */
  async send(opcode: number, init: { nodeid?: bigint; body?: unknown }): Promise<void> {
    const message = encodeRequest(
      {
        opcode,
        unique: this.#unique++,
        nodeid: init.nodeid ?? FUSE_ROOT_ID,
        uid: this.options.uid ?? 1000,
        gid: this.options.gid ?? 1000,
        pid: this.options.pid ?? 4242,
        body: init.body,
      },
      this.ctx,
    );
    const response = await this.session.handleMessage(message);
    if (response !== null) {
      throw new Error(`${opcodeName(opcode)} was answered, but wants no reply`);
    }
  }

  /** Feed arbitrary bytes straight in, as a hostile kernel would. */
  handleBytes(bytes: Uint8Array): Promise<Uint8Array | null> {
    return this.session.handleMessage(bytes);
  }

  // --- lookup accounting ---

  /** Record that the kernel now holds one more reference to `nodeid`. */
  counted(nodeid: bigint): void {
    if (nodeid !== 0n) {
      this.lookups.set(nodeid, (this.lookups.get(nodeid) ?? 0n) + 1n);
    }
  }

  /** Outstanding lookups this kernel believes it holds. */
  outstanding(nodeid: bigint): bigint {
    return this.lookups.get(nodeid) ?? 0n;
  }

  // --- handshake ---

  async init(
    overrides: { minor?: number; flags?: bigint; maxReadahead?: number } = {},
  ): Promise<FuseInitOut> {
    const flags = splitInitFlags(overrides.flags ?? this.options.initFlags ?? ALL_INIT_FLAGS);
    return this.call<FuseInitOut>(FUSE_INIT, {
      nodeid: 0n,
      body: {
        major: FUSE_KERNEL_VERSION,
        minor: overrides.minor ?? this.options.minor ?? FUSE_KERNEL_MINOR_VERSION,
        maxReadahead: overrides.maxReadahead ?? 128 * 1024,
        flags: flags.flags,
        flags2: flags.flags2,
      },
    });
  }

  destroy(): Promise<Record<string, never>> {
    return this.call(FUSE_DESTROY, { nodeid: 0n });
  }

  // --- namespace ---

  async lookup(parent: bigint, name: string): Promise<FuseEntryOut> {
    const entry = await this.call<FuseEntryOut>(FUSE_LOOKUP, { nodeid: parent, body: { name } });
    this.counted(entry.nodeid);
    return entry;
  }

  getattr(nodeid: bigint, fh?: bigint): Promise<FuseAttrOut> {
    return this.call(FUSE_GETATTR, {
      nodeid,
      body: {
        getattrFlags: fh === undefined ? 0 : FUSE_GETATTR_FH,
        fh: fh ?? 0n,
      },
    });
  }

  setattr(nodeid: bigint, body: Partial<FuseSetattrIn> & { valid: number }): Promise<FuseAttrOut> {
    return this.call(FUSE_SETATTR, {
      nodeid,
      body: {
        fh: 0n,
        size: 0n,
        lockOwner: 0n,
        atime: 0n,
        mtime: 0n,
        ctime: 0n,
        atimensec: 0,
        mtimensec: 0,
        ctimensec: 0,
        mode: 0,
        uid: 0,
        gid: 0,
        ...body,
      } satisfies FuseSetattrIn,
    });
  }

  async mkdir(parent: bigint, name: string, mode = 0o755): Promise<FuseEntryOut> {
    const entry = await this.call<FuseEntryOut>(FUSE_MKDIR, {
      nodeid: parent,
      body: { mode, umask: 0o022, name },
    });
    this.counted(entry.nodeid);
    return entry;
  }

  async mknod(parent: bigint, name: string, mode: number, rdev = 0): Promise<FuseEntryOut> {
    const entry = await this.call<FuseEntryOut>(FUSE_MKNOD, {
      nodeid: parent,
      body: { mode, rdev, umask: 0o022, name },
    });
    this.counted(entry.nodeid);
    return entry;
  }

  async symlink(parent: bigint, name: string, target: string): Promise<FuseEntryOut> {
    const entry = await this.call<FuseEntryOut>(FUSE_SYMLINK, {
      nodeid: parent,
      body: { name, target },
    });
    this.counted(entry.nodeid);
    return entry;
  }

  async readlink(nodeid: bigint): Promise<string> {
    const reply = await this.call<FuseReadlinkOut>(FUSE_READLINK, { nodeid, body: {} });
    return reply.target;
  }

  async link(oldnodeid: bigint, parent: bigint, name: string): Promise<FuseEntryOut> {
    const entry = await this.call<FuseEntryOut>(FUSE_LINK, {
      nodeid: parent,
      body: { oldnodeid, name },
    });
    this.counted(entry.nodeid);
    return entry;
  }

  unlink(parent: bigint, name: string): Promise<Record<string, never>> {
    return this.call(FUSE_UNLINK, { nodeid: parent, body: { name } });
  }

  rmdir(parent: bigint, name: string): Promise<Record<string, never>> {
    return this.call(FUSE_RMDIR, { nodeid: parent, body: { name } });
  }

  rename(
    parent: bigint,
    oldName: string,
    newdir: bigint,
    newName: string,
  ): Promise<Record<string, never>> {
    return this.call(FUSE_RENAME, { nodeid: parent, body: { newdir, oldName, newName } });
  }

  rename2(
    parent: bigint,
    oldName: string,
    newdir: bigint,
    newName: string,
    flags: number,
  ): Promise<RawReply> {
    return this.raw(FUSE_RENAME2, {
      nodeid: parent,
      body: { newdir, oldName, newName, flags },
    });
  }

  statfs(nodeid = FUSE_ROOT_ID): Promise<FuseKstatfs> {
    return this.call(FUSE_STATFS, { nodeid, body: {} });
  }

  // --- forget ---

  forget(nodeid: bigint, nlookup: bigint): Promise<void> {
    const held = this.outstanding(nodeid) - nlookup;
    if (held > 0n) {
      this.lookups.set(nodeid, held);
    } else {
      this.lookups.delete(nodeid);
    }
    return this.send(FUSE_FORGET, { nodeid, body: { nlookup } });
  }

  /** Give back every lookup this kernel is holding for `nodeid`. */
  forgetAll(nodeid: bigint): Promise<void> {
    return this.forget(nodeid, this.outstanding(nodeid));
  }

  batchForget(forgets: { nodeid: bigint; nlookup: bigint }[]): Promise<void> {
    for (const forget of forgets) {
      const held = this.outstanding(forget.nodeid) - forget.nlookup;
      if (held > 0n) {
        this.lookups.set(forget.nodeid, held);
      } else {
        this.lookups.delete(forget.nodeid);
      }
    }
    return this.send(FUSE_BATCH_FORGET, { nodeid: 0n, body: { forgets } });
  }

  // --- files ---

  open(nodeid: bigint, flags = 0): Promise<FuseOpenOut> {
    return this.call(FUSE_OPEN, { nodeid, body: { flags, openFlags: 0 } });
  }

  async create(parent: bigint, name: string, flags = 0o101, mode = 0o644): Promise<FuseCreateOut> {
    const reply = await this.call<FuseCreateOut>(FUSE_CREATE, {
      nodeid: parent,
      body: { flags, mode, umask: 0o022, openFlags: 0, name },
    });
    this.counted(reply.entry.nodeid);
    return reply;
  }

  async read(nodeid: bigint, fh: bigint, offset: number, size: number): Promise<Uint8Array> {
    const reply = await this.call<FuseRawData>(FUSE_READ, {
      nodeid,
      body: {
        fh,
        offset: BigInt(offset),
        size,
        readFlags: 0,
        lockOwner: 0n,
        flags: 0,
      },
    });
    return reply.data;
  }

  async write(
    nodeid: bigint,
    fh: bigint,
    offset: number,
    data: Uint8Array | string,
  ): Promise<number> {
    const bytes = typeof data === "string" ? encoder.encode(data) : data;
    const reply = await this.call<FuseWriteOut>(FUSE_WRITE, {
      nodeid,
      body: {
        fh,
        offset: BigInt(offset),
        size: bytes.length,
        writeFlags: 0,
        lockOwner: 0n,
        flags: 0,
        data: bytes,
      },
    });
    return reply.size;
  }

  flush(nodeid: bigint, fh: bigint): Promise<Record<string, never>> {
    return this.call(FUSE_FLUSH, { nodeid, body: { fh, lockOwner: 0n } });
  }

  fsync(nodeid: bigint, fh: bigint, dataOnly = false): Promise<Record<string, never>> {
    return this.call(FUSE_FSYNC, { nodeid, body: { fh, fsyncFlags: dataOnly ? 1 : 0 } });
  }

  fsyncdir(nodeid: bigint, fh: bigint): Promise<Record<string, never>> {
    return this.call(FUSE_FSYNCDIR, { nodeid, body: { fh, fsyncFlags: 0 } });
  }

  release(nodeid: bigint, fh: bigint, flags = 0): Promise<Record<string, never>> {
    return this.call(FUSE_RELEASE, {
      nodeid,
      body: { fh, flags, releaseFlags: 0, lockOwner: 0n },
    });
  }

  releasedir(nodeid: bigint, fh: bigint): Promise<Record<string, never>> {
    return this.call(FUSE_RELEASEDIR, {
      nodeid,
      body: { fh, flags: 0, releaseFlags: 0, lockOwner: 0n },
    });
  }

  // --- directories ---

  opendir(nodeid: bigint, flags = 0): Promise<FuseOpenOut> {
    return this.call(FUSE_OPENDIR, { nodeid, body: { flags, openFlags: 0 } });
  }

  readdir(nodeid: bigint, fh: bigint, offset: bigint, size = 4096): Promise<FuseDirentsOut> {
    return this.call(FUSE_READDIR, {
      nodeid,
      body: { fh, offset, size, readFlags: 0, lockOwner: 0n, flags: 0 },
    });
  }

  async readdirplus(
    nodeid: bigint,
    fh: bigint,
    offset: bigint,
    size = 4096,
  ): Promise<FuseDirentsPlusOut> {
    const reply = await this.call<FuseDirentsPlusOut>(FUSE_READDIRPLUS, {
      nodeid,
      body: { fh, offset, size, readFlags: 0, lockOwner: 0n, flags: 0 },
    });
    // The kernel counts a lookup for every entry it links, and skips the ones
    // with `nodeid == 0` (which is how `.` and `..` come back).
    for (const entry of reply.entries) {
      this.counted(entry.entry.nodeid);
    }
    return reply;
  }

  /** Page through a whole directory the way the kernel does. */
  async readdirAll(nodeid: bigint, fh: bigint, size = 4096, plus = false): Promise<string[]> {
    const names: string[] = [];
    let offset = 0n;
    for (let page = 0; page < 1000; page++) {
      const reply = plus
        ? await this.readdirplus(nodeid, fh, offset, size)
        : await this.readdir(nodeid, fh, offset, size);
      const entries = plus
        ? (reply as FuseDirentsPlusOut).entries.map((entry) => entry.dirent)
        : (reply as FuseDirentsOut).entries;
      if (entries.length === 0) {
        return names;
      }
      for (const entry of entries) {
        names.push(entry.name);
      }
      offset = entries.at(-1)!.off;
    }
    throw new Error("readdirAll did not terminate");
  }

  // --- misc ---

  interrupt(unique: bigint): Promise<RawReply> {
    return this.raw(FUSE_INTERRUPT, { nodeid: 0n, body: { unique } });
  }
}

/** Convenience for tests: `expect(await errnoName(promise)).toBe("ENOENT")`. */
export async function errnoName(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return "OK";
  } catch (error) {
    return error instanceof KernelError ? error.code : `threw ${String(error)}`;
  }
}
