/**
 * A seeded PRNG and message generators for the protocol property tests.
 *
 * Deterministic on purpose: a failing case is reproducible from its seed, and
 * CI never flakes. No dependency — the generator is twenty lines.
 */

import {
  FUSE_ACCESS,
  FUSE_BATCH_FORGET,
  FUSE_BMAP,
  FUSE_CREATE,
  FUSE_DESTROY,
  FUSE_FALLOCATE,
  FUSE_FLUSH,
  FUSE_FORGET,
  FUSE_FSYNC,
  FUSE_FSYNCDIR,
  FUSE_GETATTR,
  FUSE_GETLK,
  FUSE_GETXATTR,
  FUSE_INIT,
  FUSE_INTERRUPT,
  FUSE_LINK,
  FUSE_LISTXATTR,
  FUSE_LOOKUP,
  FUSE_LSEEK,
  FUSE_MKDIR,
  FUSE_MKNOD,
  FUSE_OPEN,
  FUSE_OPENDIR,
  FUSE_POLL,
  FUSE_READ,
  FUSE_READDIR,
  FUSE_READDIRPLUS,
  FUSE_READLINK,
  FUSE_RELEASE,
  FUSE_RELEASEDIR,
  FUSE_REMOVEXATTR,
  FUSE_RENAME,
  FUSE_RENAME2,
  FUSE_RMDIR,
  FUSE_SETATTR,
  FUSE_SETLK,
  FUSE_SETLKW,
  FUSE_SETXATTR,
  FUSE_STATFS,
  FUSE_SYMLINK,
  FUSE_UNLINK,
  FUSE_WRITE,
} from "../../src/fuse/constants.ts";
import type {
  FuseAttr,
  FuseAttrOut,
  FuseDirent,
  FuseDirentPlus,
  FuseEntryOut,
  FuseFileLock,
  FuseInHeader,
  FuseKstatfs,
  FuseOpenOut,
  ProtocolContext,
} from "../../src/fuse/protocol.ts";

/** `mulberry32`: 32 bits of state, good enough for shaking out codecs. */
export class Rng {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0;
  }

  /** Next uint32. */
  u32(): number {
    this.state = (this.state + 0x6d_2b_79_f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  }

  /** `[0, 1)`. */
  float(): number {
    return this.u32() / 0x1_00_00_00_00;
  }

  /** `[0, maxExclusive)`. */
  int(maxExclusive: number): number {
    return maxExclusive <= 0 ? 0 : this.u32() % maxExclusive;
  }

  /** `[min, max]`. */
  range(min: number, max: number): number {
    return min + this.int(max - min + 1);
  }

  bool(probability = 0.5): boolean {
    return this.float() < probability;
  }

  u16(): number {
    return this.u32() & 0xff_ff;
  }

  /** Unsigned 64-bit. Biased towards the interesting edges. */
  u64(): bigint {
    switch (this.int(8)) {
      case 0: {
        return 0n;
      }
      case 1: {
        return 1n;
      }
      case 2: {
        return 0xff_ff_ff_ff_ff_ff_ff_ffn;
      }
      case 3: {
        // Straddles the Number.MAX_SAFE_INTEGER boundary, where a `number`
        // representation would start losing bits.
        return (1n << 53n) + BigInt(this.int(1024));
      }
      default: {
        return (BigInt(this.u32()) << 32n) | BigInt(this.u32());
      }
    }
  }

  pick<T>(values: readonly T[]): T {
    return values[this.int(values.length)] as T;
  }

  bytes(length: number): Uint8Array {
    const value = new Uint8Array(length);
    for (let index = 0; index < length; index++) {
      value[index] = this.u32() & 0xff;
    }
    return value;
  }

  /**
   * A filename: valid UTF-8, no NUL. Multi-byte characters are included on
   * purpose — `namelen` is a byte count, not a code-unit count.
   */
  name(maxLength = 24): string {
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789._-+ éüλ字🙂";
    const characters = [...alphabet];
    let value = "";
    const length = this.range(1, Math.max(1, maxLength));
    for (let index = 0; index < length; index++) {
      value += this.pick(characters);
    }
    return value;
  }
}

/**
 * Latest layouts. Generators take a `ProtocolContext` and **zero every field
 * the wire cannot carry at that version**, because `decode(encode(x)) === x`
 * can only hold for values the layout can actually represent. Getting this
 * wrong is how a compat bug hides: see `fuse_attr.flags`, which is `padding`
 * before 7.32.
 */
const LATEST: ProtocolContext = { minor: 41, setxattrExt: false };

export function randomInHeader(rng: Rng): FuseInHeader {
  return {
    len: rng.range(40, 4096),
    opcode: rng.u32(),
    unique: rng.u64(),
    nodeid: rng.u64(),
    uid: rng.u32(),
    gid: rng.u32(),
    pid: rng.u32(),
    totalExtlen: rng.u16(),
  };
}

export function randomAttr(rng: Rng, ctx: ProtocolContext = LATEST): FuseAttr {
  return {
    ino: rng.u64(),
    size: rng.u64(),
    blocks: rng.u64(),
    atime: rng.u64(),
    mtime: rng.u64(),
    ctime: rng.u64(),
    atimensec: rng.u32(),
    mtimensec: rng.u32(),
    ctimensec: rng.u32(),
    mode: rng.u32(),
    nlink: rng.u32(),
    uid: rng.u32(),
    gid: rng.u32(),
    rdev: rng.u32(),
    blksize: ctx.minor >= 9 ? rng.u32() : 0,
    flags: ctx.minor >= 32 ? rng.u32() : 0,
  };
}

export function randomEntryOut(rng: Rng, ctx: ProtocolContext = LATEST): FuseEntryOut {
  return {
    nodeid: rng.u64(),
    generation: rng.u64(),
    entryValid: rng.u64(),
    attrValid: rng.u64(),
    entryValidNsec: rng.u32(),
    attrValidNsec: rng.u32(),
    attr: randomAttr(rng, ctx),
  };
}

export function randomAttrOut(rng: Rng, ctx: ProtocolContext = LATEST): FuseAttrOut {
  return { attrValid: rng.u64(), attrValidNsec: rng.u32(), attr: randomAttr(rng, ctx) };
}

export function randomOpenOut(rng: Rng, ctx: ProtocolContext = LATEST): FuseOpenOut {
  return {
    fh: rng.u64(),
    openFlags: rng.u32(),
    backingId: ctx.minor >= 40 ? rng.range(-2, 64) : 0,
  };
}

export function randomKstatfs(rng: Rng, ctx: ProtocolContext = LATEST): FuseKstatfs {
  return {
    blocks: rng.u64(),
    bfree: rng.u64(),
    bavail: rng.u64(),
    files: rng.u64(),
    ffree: rng.u64(),
    bsize: rng.u32(),
    namelen: rng.u32(),
    frsize: ctx.minor >= 4 ? rng.u32() : 0,
  };
}

export function randomFileLock(rng: Rng): FuseFileLock {
  return { start: rng.u64(), end: rng.u64(), type: rng.int(3), pid: rng.u32() };
}

export function randomDirent(rng: Rng): FuseDirent {
  return {
    ino: rng.u64(),
    off: rng.u64(),
    type: rng.pick([0, 1, 2, 4, 6, 8, 10, 12]),
    name: rng.name(),
  };
}

export function randomDirentPlus(rng: Rng, ctx: ProtocolContext = LATEST): FuseDirentPlus {
  return { entry: randomEntryOut(rng, ctx), dirent: randomDirent(rng) };
}

type Generator = (rng: Rng, ctx: ProtocolContext) => unknown;

const EMPTY: Generator = () => ({});

/** `fuse_read_in`, shared verbatim by READ, READDIR and READDIRPLUS. */
const randomReadIn: Generator = (rng, ctx) => ({
  fh: rng.u64(),
  offset: rng.u64(),
  size: rng.u32(),
  readFlags: rng.u32(),
  // 7.9 added lock_owner and the O_* flags of the open file.
  lockOwner: ctx.minor >= 9 ? rng.u64() : 0n,
  flags: ctx.minor >= 9 ? rng.u32() : 0,
});

/** A generator per opcode for the request direction. */
export const REQUEST_GENERATORS: ReadonlyMap<number, Generator> = new Map<number, Generator>([
  [FUSE_LOOKUP, (rng) => ({ name: rng.name() })],
  [FUSE_UNLINK, (rng) => ({ name: rng.name() })],
  [FUSE_RMDIR, (rng) => ({ name: rng.name() })],
  [FUSE_REMOVEXATTR, (rng) => ({ name: rng.name() })],
  [FUSE_FORGET, (rng) => ({ nlookup: rng.u64() })],
  [
    FUSE_BATCH_FORGET,
    (rng) => ({
      forgets: Array.from({ length: rng.int(8) }, () => ({
        nodeid: rng.u64(),
        nlookup: rng.u64(),
      })),
    }),
  ],
  [FUSE_GETATTR, (rng) => ({ getattrFlags: rng.u32(), fh: rng.u64() })],
  [
    FUSE_SETATTR,
    (rng) => ({
      valid: rng.u32(),
      fh: rng.u64(),
      size: rng.u64(),
      lockOwner: rng.u64(),
      atime: rng.u64(),
      mtime: rng.u64(),
      ctime: rng.u64(),
      atimensec: rng.u32(),
      mtimensec: rng.u32(),
      ctimensec: rng.u32(),
      mode: rng.u32(),
      uid: rng.u32(),
      gid: rng.u32(),
    }),
  ],
  [FUSE_READLINK, EMPTY],
  [FUSE_STATFS, EMPTY],
  [FUSE_DESTROY, EMPTY],
  [FUSE_SYMLINK, (rng) => ({ name: rng.name(), target: rng.name(48) })],
  [
    FUSE_MKNOD,
    (rng, ctx) => ({
      mode: rng.u32(),
      rdev: rng.u32(),
      umask: ctx.minor >= 12 ? rng.u16() : 0, // 7.12 added umask
      name: rng.name(),
    }),
  ],
  [FUSE_MKDIR, (rng) => ({ mode: rng.u32(), umask: rng.u16(), name: rng.name() })],
  [FUSE_RENAME, (rng) => ({ newdir: rng.u64(), oldName: rng.name(), newName: rng.name() })],
  [
    FUSE_RENAME2,
    (rng) => ({
      newdir: rng.u64(),
      flags: rng.u32(),
      oldName: rng.name(),
      newName: rng.name(),
    }),
  ],
  [FUSE_LINK, (rng) => ({ oldnodeid: rng.u64(), name: rng.name() })],
  [FUSE_OPEN, (rng) => ({ flags: rng.u32(), openFlags: rng.u32() })],
  [FUSE_OPENDIR, (rng) => ({ flags: rng.u32(), openFlags: rng.u32() })],
  [
    FUSE_CREATE,
    (rng, ctx) => ({
      flags: rng.u32(),
      mode: rng.u32(),
      // 7.12 added umask and open_flags.
      umask: ctx.minor >= 12 ? rng.u16() : 0,
      openFlags: ctx.minor >= 12 ? rng.u32() : 0,
      name: rng.name(),
    }),
  ],
  [FUSE_READ, randomReadIn],
  [FUSE_READDIR, randomReadIn],
  [FUSE_READDIRPLUS, randomReadIn],
  [
    FUSE_WRITE,
    (rng, ctx) => {
      const data = rng.bytes(rng.int(64));
      return {
        fh: rng.u64(),
        offset: rng.u64(),
        size: data.length,
        writeFlags: rng.u32(),
        // 7.9 added lock_owner and the O_* flags of the open file.
        lockOwner: ctx.minor >= 9 ? rng.u64() : 0n,
        flags: ctx.minor >= 9 ? rng.u32() : 0,
        data,
      };
    },
  ],
  [
    FUSE_RELEASE,
    (rng) => ({
      fh: rng.u64(),
      flags: rng.u32(),
      releaseFlags: rng.u32(),
      lockOwner: rng.u64(),
    }),
  ],
  [
    FUSE_RELEASEDIR,
    (rng) => ({
      fh: rng.u64(),
      flags: rng.u32(),
      releaseFlags: rng.u32(),
      lockOwner: rng.u64(),
    }),
  ],
  [FUSE_FSYNC, (rng) => ({ fh: rng.u64(), fsyncFlags: rng.u32() })],
  [FUSE_FSYNCDIR, (rng) => ({ fh: rng.u64(), fsyncFlags: rng.u32() })],
  [FUSE_FLUSH, (rng) => ({ fh: rng.u64(), lockOwner: rng.u64() })],
  [FUSE_ACCESS, (rng) => ({ mask: rng.u32() })],
  [
    FUSE_INIT,
    (rng) => ({
      major: 7,
      minor: rng.range(0, 60),
      maxReadahead: rng.u32(),
      flags: rng.u32(),
      flags2: rng.u32(),
    }),
  ],
  [FUSE_INTERRUPT, (rng) => ({ unique: rng.u64() })],
  [
    FUSE_SETXATTR,
    (rng, ctx) => ({
      flags: rng.u32(),
      setxattrFlags: ctx.setxattrExt ? rng.u32() : 0,
      name: rng.name(),
      value: rng.bytes(rng.int(32)),
    }),
  ],
  [FUSE_GETXATTR, (rng) => ({ size: rng.u32(), name: rng.name() })],
  [FUSE_LISTXATTR, (rng) => ({ size: rng.u32() })],
  [
    FUSE_FALLOCATE,
    (rng) => ({ fh: rng.u64(), offset: rng.u64(), length: rng.u64(), mode: rng.u32() }),
  ],
  [FUSE_LSEEK, (rng) => ({ fh: rng.u64(), offset: rng.u64(), whence: rng.int(5) })],
  [
    FUSE_GETLK,
    (rng) => ({ fh: rng.u64(), owner: rng.u64(), lk: randomFileLock(rng), lkFlags: rng.u32() }),
  ],
  [
    FUSE_SETLK,
    (rng) => ({ fh: rng.u64(), owner: rng.u64(), lk: randomFileLock(rng), lkFlags: rng.u32() }),
  ],
  [
    FUSE_SETLKW,
    (rng) => ({ fh: rng.u64(), owner: rng.u64(), lk: randomFileLock(rng), lkFlags: rng.u32() }),
  ],
  [FUSE_POLL, (rng) => ({ fh: rng.u64(), kh: rng.u64(), flags: rng.u32(), events: rng.u32() })],
  [FUSE_BMAP, (rng) => ({ block: rng.u64(), blocksize: rng.u32() })],
]);

/** A generator per opcode for the reply direction. */
export const REPLY_GENERATORS: ReadonlyMap<number, Generator> = new Map<number, Generator>([
  [FUSE_LOOKUP, randomEntryOut],
  [FUSE_SYMLINK, randomEntryOut],
  [FUSE_MKNOD, randomEntryOut],
  [FUSE_MKDIR, randomEntryOut],
  [FUSE_LINK, randomEntryOut],
  [FUSE_GETATTR, randomAttrOut],
  [FUSE_SETATTR, randomAttrOut],
  [FUSE_READLINK, (rng) => ({ target: rng.name(64) })],
  [FUSE_OPEN, randomOpenOut],
  [FUSE_OPENDIR, randomOpenOut],
  [FUSE_CREATE, (rng, ctx) => ({ entry: randomEntryOut(rng, ctx), open: randomOpenOut(rng, ctx) })],
  [FUSE_READ, (rng) => ({ data: rng.bytes(rng.int(128)) })],
  [FUSE_GETXATTR, (rng) => ({ data: rng.bytes(rng.int(64)) })],
  [FUSE_LISTXATTR, (rng) => ({ data: rng.bytes(rng.int(64)) })],
  [FUSE_WRITE, (rng) => ({ size: rng.u32() })],
  [FUSE_STATFS, randomKstatfs],
  [
    FUSE_READDIR,
    (rng) => ({ entries: Array.from({ length: rng.int(6) }, () => randomDirent(rng)) }),
  ],
  [
    FUSE_READDIRPLUS,
    (rng, ctx) => ({
      entries: Array.from({ length: rng.int(4) }, () => randomDirentPlus(rng, ctx)),
    }),
  ],
  [
    FUSE_INIT,
    // `fuse_init_out` announces the version it is laid out as, so its `minor`
    // *is* the context's: 8 bytes below 7.5, 24 below 7.23, 64 from 7.23.
    (rng, ctx) => {
      const full = ctx.minor >= 23;
      const post7_5 = ctx.minor >= 5;
      return {
        major: 7,
        minor: ctx.minor,
        maxReadahead: post7_5 ? rng.u32() : 0,
        flags: post7_5 ? rng.u32() : 0,
        maxBackground: post7_5 ? rng.u16() : 0,
        congestionThreshold: post7_5 ? rng.u16() : 0,
        maxWrite: post7_5 ? rng.u32() : 0,
        timeGran: full ? rng.u32() : 0,
        maxPages: full ? rng.u16() : 0,
        mapAlignment: full ? rng.u16() : 0,
        flags2: full ? rng.u32() : 0,
        maxStackDepth: full ? rng.u32() : 0,
      };
    },
  ],
  [FUSE_LSEEK, (rng) => ({ offset: rng.u64() })],
  [FUSE_GETLK, (rng) => ({ lk: randomFileLock(rng) })],
  [FUSE_POLL, (rng) => ({ revents: rng.u32() })],
  [FUSE_BMAP, (rng) => ({ block: rng.u64() })],
  // Status-only replies.
  [FUSE_FORGET, EMPTY],
  [FUSE_BATCH_FORGET, EMPTY],
  [FUSE_UNLINK, EMPTY],
  [FUSE_RMDIR, EMPTY],
  [FUSE_RENAME, EMPTY],
  [FUSE_RENAME2, EMPTY],
  [FUSE_RELEASE, EMPTY],
  [FUSE_RELEASEDIR, EMPTY],
  [FUSE_FSYNC, EMPTY],
  [FUSE_FSYNCDIR, EMPTY],
  [FUSE_FLUSH, EMPTY],
  [FUSE_ACCESS, EMPTY],
  [FUSE_DESTROY, EMPTY],
  [FUSE_INTERRUPT, EMPTY],
  [FUSE_SETXATTR, EMPTY],
  [FUSE_REMOVEXATTR, EMPTY],
  [FUSE_FALLOCATE, EMPTY],
  [FUSE_SETLK, EMPTY],
  [FUSE_SETLKW, EMPTY],
]);
