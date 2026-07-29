/**
 * `FUSE_INIT` negotiation — a pure function from what the kernel offered plus
 * what we want, to the reply and the session parameters every later message
 * depends on.
 *
 * Nothing here touches a device, so the whole handshake is unit-testable: feed
 * it an old kernel, a future kernel, a kernel without `FUSE_MAX_PAGES`, and
 * assert on the numbers.
 *
 * The defaults are the ones IDEA.md argues for, and they matter more than any
 * JS-side optimization: `max_write` of 1 MiB (which needs `FUSE_MAX_PAGES`),
 * `readdirplus` on, writeback cache **off** (it makes the kernel authoritative
 * for size and mtime and lets writes arrive after `release`), and a generous
 * background queue.
 */

import { ERRNO_CODES } from "../errors.ts";
import {
  FUSE_ASYNC_DIO,
  FUSE_ASYNC_READ,
  FUSE_ATOMIC_O_TRUNC,
  FUSE_AUTO_INVAL_DATA,
  FUSE_BIG_WRITES,
  FUSE_CACHE_SYMLINKS,
  FUSE_DEFAULT_MAX_PAGES_PER_REQ,
  FUSE_DO_READDIRPLUS,
  FUSE_EXPORT_SUPPORT,
  FUSE_FLOCK_LOCKS,
  FUSE_INIT_EXT,
  FUSE_KERNEL_MINOR_VERSION,
  FUSE_KERNEL_VERSION,
  FUSE_MAX_MAX_PAGES,
  FUSE_MAX_PAGES,
  FUSE_PAGE_SIZE,
  FUSE_PARALLEL_DIROPS,
  FUSE_POSIX_LOCKS,
  FUSE_READDIRPLUS_AUTO,
  FUSE_SETXATTR_EXT,
  FUSE_WRITEBACK_CACHE,
} from "./constants.ts";
import type { FuseInitIn, FuseInitOut, ProtocolContext } from "./protocol.ts";

/** Merge the wire's two `uint32_t` flag words into the single 64-bit space. */
export function joinInitFlags(flags: number, flags2: number): bigint {
  return (BigInt(flags >>> 0) & 0xff_ff_ff_ffn) | ((BigInt(flags2 >>> 0) & 0xff_ff_ff_ffn) << 32n);
}

/** Split the 64-bit flag space back into `flags` and `flags2`. */
export function splitInitFlags(flags: bigint): { flags: number; flags2: number } {
  const value = BigInt.asUintN(64, flags);
  return {
    flags: Number(value & 0xff_ff_ff_ffn),
    flags2: Number((value >> 32n) & 0xff_ff_ff_ffn),
  };
}

/**
 * Flags this server asks for by default.
 *
 * Deliberately absent:
 *
 * - `FUSE_WRITEBACK_CACHE` — the biggest single perf win and also the one that
 *   makes the kernel authoritative for size/mtime and lets writes land after
 *   `release`. Off until the differential suite says otherwise (IDEA.md).
 * - `FUSE_POSIX_LOCKS` / `FUSE_FLOCK_LOCKS` — v1 answers the lock ops `-ENOSYS`,
 *   so claiming remote locking would be a lie.
 * - `FUSE_NO_OPEN_SUPPORT` / `FUSE_NO_OPENDIR_SUPPORT` — zero-message opens
 *   throw away the per-open state the driver interface is built on.
 * - `FUSE_SECURITY_CTX` / `FUSE_CREATE_SUPP_GROUP` — both append extension
 *   blocks to create-shaped requests that nothing consumes yet.
 * - `FUSE_EXPORT_SUPPORT` — requires answering lookups of `.` and `..`.
 */
export const DEFAULT_WANTED_FLAGS =
  FUSE_ASYNC_READ |
  FUSE_ATOMIC_O_TRUNC |
  FUSE_BIG_WRITES |
  FUSE_AUTO_INVAL_DATA |
  FUSE_DO_READDIRPLUS |
  FUSE_READDIRPLUS_AUTO |
  FUSE_ASYNC_DIO |
  FUSE_PARALLEL_DIROPS |
  FUSE_MAX_PAGES |
  FUSE_SETXATTR_EXT;

/** 1 MiB, which is also `FUSE_MAX_MAX_PAGES * FUSE_PAGE_SIZE`. */
export const DEFAULT_MAX_WRITE = 1024 * 1024;

/** What the server would like. Every field has a defensible default. */
export interface InitPreferences {
  /** Highest minor version we implement. Default `FUSE_KERNEL_MINOR_VERSION`. */
  minor?: number;
  /** Default 1 MiB — needs `FUSE_MAX_PAGES`, else clamped to 128 KiB. */
  maxWrite?: number;
  /** Default: whatever the kernel offered. */
  maxReadahead?: number;
  /** Requests the kernel may have in flight. Default 64. */
  maxBackground?: number;
  /** Background depth at which the kernel throttles. Default 3/4 of `maxBackground`. */
  congestionThreshold?: number;
  /** Timestamp granularity in nanoseconds. Default 1. */
  timeGran?: number;
  /** Stacked-filesystem depth (7.40+). Default 0. */
  maxStackDepth?: number;
  /** `READDIRPLUS`: folds `LOOKUP` into `READDIR`. Default on. */
  readdirplus?: boolean;
  /** Kernel-side write buffering. Default **off** — see the note above. */
  writebackCache?: boolean;
  /** Let the kernel cache `READLINK` results. Default off. */
  cacheSymlinks?: boolean;
  /**
   * Replaces {@link DEFAULT_WANTED_FLAGS} wholesale.
   *
   * **There are deliberately no booleans for `FUSE_POSIX_LOCKS`,
   * `FUSE_FLOCK_LOCKS` or `FUSE_EXPORT_SUPPORT`.** All three negotiate work the
   * session cannot do — it answers `GETLK`/`SETLK`/`SETLKW` with `ENOSYS`, and
   * `checkName` rejects the two names (`.` and `..`) that `FUSE_EXPORT_SUPPORT`
   * requires a server to resolve — so their only reachable effect was to break
   * a mount. `posixLocks: true` was the worst of them: it stops the kernel
   * doing local `fcntl` locking and routes every lock to a server that refuses,
   * which is "capabilities are declared-or-inferred, never faked" defeated
   * through a public option. This field and {@link extraFlags} remain as the
   * deliberate escape hatch for anyone who knows better; nothing here will hand
   * out a footgun by name.
   */
  flags?: bigint;
  /** OR-ed onto the wanted set, after every other option. */
  extraFlags?: bigint;
  /** Cleared from the wanted set, after every other option. */
  withoutFlags?: bigint;
}

/** Everything downstream layers need to know about the agreed session. */
export interface NegotiatedSession {
  major: number;
  /** `min(kernel, ours)`. */
  minor: number;
  /** Flags both sides agreed on, in the joined 64-bit space. */
  flags: bigint;
  maxWrite: number;
  /** `0` when `FUSE_MAX_PAGES` was not agreed. */
  maxPages: number;
  maxReadahead: number;
  maxBackground: number;
  congestionThreshold: number;
  timeGran: number;
  readdirplus: boolean;
  writebackCache: boolean;
  atomicOTrunc: boolean;
  parallelDirops: boolean;
  /**
   * These three report what the kernel **agreed to**, and are kept even though
   * {@link InitPreferences} no longer offers a boolean to ask for any of them.
   * They are a different thing from an opt-in: a readback cannot fake a
   * capability, and it is exactly what someone reaching for the `flags` /
   * `extraFlags` escape hatch needs in order to find out whether their kernel
   * went along with it. At the defaults all three are `false`, because
   * {@link DEFAULT_WANTED_FLAGS} never asks.
   */
  posixLocks: boolean;
  flockLocks: boolean;
  cacheSymlinks: boolean;
  exportSupport: boolean;
  /** `FUSE_SETXATTR_EXT`: `fuse_setxattr_in` is 16 bytes rather than 8. */
  setxattrExt: boolean;
  /** The codec context every later message must be encoded/decoded with. */
  protocol: ProtocolContext;
}

/**
 * The outcome of a handshake.
 *
 * - `ok` — reply and start serving.
 * - `retry` — the kernel speaks a newer major; reply with ours and wait for it
 *   to send a second `INIT` at a major we understand (`fuse.h`, "Version
 *   negotiation").
 * - `error` — reply `-errno` and give up. Only happens for major < 7.
 */
export type InitNegotiation =
  | { status: "ok"; reply: FuseInitOut; session: NegotiatedSession }
  | { status: "retry"; reply: FuseInitOut }
  | { status: "error"; errno: number };

function clampU16(value: number): number {
  return Math.max(0, Math.min(0xff_ff, Math.trunc(value)));
}

function clampU32(value: number): number {
  return Math.max(0, Math.min(0xff_ff_ff_ff, Math.trunc(value)));
}

function emptyInitOut(major: number, minor: number): FuseInitOut {
  return {
    major,
    minor,
    maxReadahead: 0,
    flags: 0,
    maxBackground: 0,
    congestionThreshold: 0,
    maxWrite: 0,
    timeGran: 0,
    maxPages: 0,
    mapAlignment: 0,
    flags2: 0,
    maxStackDepth: 0,
  };
}

function wantedFlags(preferences: InitPreferences): bigint {
  let wanted = preferences.flags ?? DEFAULT_WANTED_FLAGS;
  const toggle = (flag: bigint, on: boolean | undefined): void => {
    if (on === true) {
      wanted |= flag;
    } else if (on === false) {
      wanted &= ~flag;
    }
  };
  if (preferences.readdirplus === false) {
    wanted &= ~(FUSE_DO_READDIRPLUS | FUSE_READDIRPLUS_AUTO);
  }
  toggle(FUSE_WRITEBACK_CACHE, preferences.writebackCache);
  toggle(FUSE_CACHE_SYMLINKS, preferences.cacheSymlinks);
  // No toggles for FUSE_POSIX_LOCKS / FUSE_FLOCK_LOCKS / FUSE_EXPORT_SUPPORT —
  // see `InitPreferences.flags`. `extraFlags` is the way in for someone who
  // means it.
  wanted |= preferences.extraFlags ?? 0n;
  wanted &= ~(preferences.withoutFlags ?? 0n);
  return BigInt.asUintN(64, wanted);
}

/**
 * Negotiate a session from the kernel's `FUSE_INIT` request.
 *
 * Pure: same inputs, same outputs, no I/O, no clock.
 */
export function negotiateInit(
  kernel: FuseInitIn,
  preferences: InitPreferences = {},
): InitNegotiation {
  const ourMinor = preferences.minor ?? FUSE_KERNEL_MINOR_VERSION;

  // fuse.h: "If the kernel supports a larger major version, then userspace
  // shall reply with the major version it supports, ignore the rest of the
  // INIT message and expect a new INIT message from the kernel."
  if (kernel.major > FUSE_KERNEL_VERSION) {
    return { status: "retry", reply: emptyInitOut(FUSE_KERNEL_VERSION, ourMinor) };
  }
  // A kernel older than 7.0 cannot be talked to at all.
  if (kernel.major < FUSE_KERNEL_VERSION) {
    return { status: "error", errno: ERRNO_CODES.EPROTO };
  }

  const minor = Math.min(kernel.minor, ourMinor);

  // flags2 only exists from 7.36, and only carries meaning when the kernel
  // opted into the extended handshake.
  const kernelFlags = joinInitFlags(
    kernel.flags,
    minor >= 36 && (kernel.flags & Number(FUSE_INIT_EXT)) !== 0 ? kernel.flags2 : 0,
  );
  let flags = wantedFlags(preferences) & kernelFlags;
  // Only claim flags2 bits if the kernel offered the extended form; otherwise
  // it would read our high bits as garbage.
  if (flags >> 32n !== 0n) {
    flags |= FUSE_INIT_EXT;
  } else {
    flags &= ~FUSE_INIT_EXT;
  }

  const maxPagesOk = minor >= 28 && (flags & FUSE_MAX_PAGES) !== 0n;
  let maxWrite = clampU32(preferences.maxWrite ?? DEFAULT_MAX_WRITE);
  let maxPages = 0;
  if (maxPagesOk) {
    // The kernel clamps max_pages to max_pages_limit (FUSE_MAX_MAX_PAGES, 256)
    // rather than rejecting the handshake, so the effective ceiling is 256 pages
    // == 1 MiB however much we ask for. Clamp here too, so the max_write this
    // session reports is the one the kernel will actually honour.
    maxPages = Math.min(FUSE_MAX_MAX_PAGES, Math.max(1, Math.ceil(maxWrite / FUSE_PAGE_SIZE)));
    maxWrite = Math.min(maxWrite, maxPages * FUSE_PAGE_SIZE);
  } else {
    flags &= ~FUSE_MAX_PAGES;
    maxWrite = Math.min(maxWrite, FUSE_DEFAULT_MAX_PAGES_PER_REQ * FUSE_PAGE_SIZE);
  }
  // The kernel floors max_write at one page; below 7.5 the field does not exist
  // at all and the kernel assumes exactly one page.
  maxWrite = minor < 5 ? FUSE_PAGE_SIZE : Math.max(FUSE_PAGE_SIZE, maxWrite);

  const maxReadahead =
    preferences.maxReadahead === undefined
      ? kernel.maxReadahead
      : Math.min(clampU32(preferences.maxReadahead), kernel.maxReadahead);

  const maxBackground = minor < 13 ? 0 : clampU16(preferences.maxBackground ?? 64);
  const congestionThreshold =
    minor < 13
      ? 0
      : clampU16(
          preferences.congestionThreshold ?? Math.max(1, Math.floor((maxBackground * 3) / 4)),
        );
  const timeGran = minor < 23 ? 0 : clampU32(preferences.timeGran ?? 1);
  const maxStackDepth = minor < 40 ? 0 : clampU32(preferences.maxStackDepth ?? 0);

  const split = splitInitFlags(flags);
  const reply: FuseInitOut = {
    major: FUSE_KERNEL_VERSION,
    minor,
    maxReadahead: clampU32(maxReadahead),
    flags: split.flags,
    maxBackground,
    congestionThreshold,
    maxWrite,
    timeGran,
    maxPages,
    mapAlignment: 0,
    flags2: minor >= 36 ? split.flags2 : 0,
    maxStackDepth,
  };

  const setxattrExt = (flags & FUSE_SETXATTR_EXT) !== 0n;
  const session: NegotiatedSession = {
    major: FUSE_KERNEL_VERSION,
    minor,
    flags,
    maxWrite,
    maxPages,
    maxReadahead: reply.maxReadahead,
    maxBackground,
    congestionThreshold,
    timeGran,
    readdirplus: (flags & FUSE_DO_READDIRPLUS) !== 0n,
    writebackCache: (flags & FUSE_WRITEBACK_CACHE) !== 0n,
    atomicOTrunc: (flags & FUSE_ATOMIC_O_TRUNC) !== 0n,
    parallelDirops: (flags & FUSE_PARALLEL_DIROPS) !== 0n,
    posixLocks: (flags & FUSE_POSIX_LOCKS) !== 0n,
    flockLocks: (flags & FUSE_FLOCK_LOCKS) !== 0n,
    cacheSymlinks: (flags & FUSE_CACHE_SYMLINKS) !== 0n,
    exportSupport: (flags & FUSE_EXPORT_SUPPORT) !== 0n,
    setxattrExt,
    protocol: { minor, setxattrExt },
  };

  return { status: "ok", reply, session };
}
