/**
 * The mountx driver interface.
 *
 * `FsDriver` is deliberately **a subset of `node:fs/promises`**, not a bespoke
 * interface: `node:fs/promises` itself is assignable to `FsDriver`, and so is
 * anything already shaped like it (`memfs`, `@zenfs/core`, `unfs`, ...).
 *
 * Everything is structural and minimal: `StatsLike`, `DirentLike`,
 * `StatsFsLike` and `FileHandleLike` are the smallest shapes the transports
 * need, and Node's own `Stats` / `Dirent` / `StatsFs` / `FileHandle` satisfy
 * them without adaptation.
 */

/** Minimal structural subset of `fs.Stats`. */
export interface StatsLike {
  dev: number;
  ino: number;
  /** File type bits (`S_IFMT`) plus permission bits. */
  mode: number;
  nlink: number;
  uid: number;
  gid: number;
  rdev: number;
  size: number;
  blksize: number;
  blocks: number;
  atimeMs: number;
  mtimeMs: number;
  ctimeMs: number;
  birthtimeMs: number;
  isFile(): boolean;
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
  isBlockDevice(): boolean;
  isCharacterDevice(): boolean;
  isFIFO(): boolean;
  isSocket(): boolean;
}

/** Minimal structural subset of `fs.StatsFs` (used for `statfs(2)` / `df`). */
export interface StatsFsLike {
  type: number;
  bsize: number;
  blocks: number;
  bfree: number;
  bavail: number;
  files: number;
  ffree: number;
}

/** Minimal structural subset of `fs.Dirent`. */
export interface DirentLike {
  name: string;
  parentPath?: string;
  isFile(): boolean;
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
  isBlockDevice(): boolean;
  isCharacterDevice(): boolean;
  isFIFO(): boolean;
  isSocket(): boolean;
}

export interface ReadResult {
  bytesRead: number;
  buffer: Uint8Array;
}

export interface WriteResult {
  bytesWritten: number;
  buffer: Uint8Array;
}

/** Minimal structural subset of `fs/promises.FileHandle`. */
export interface FileHandleLike {
  readonly fd?: number;
  read(
    buffer: Uint8Array,
    offset?: number | null,
    length?: number | null,
    position?: number | null,
  ): Promise<ReadResult>;
  write(
    buffer: Uint8Array,
    offset?: number | null,
    length?: number | null,
    position?: number | null,
  ): Promise<WriteResult>;
  stat(): Promise<StatsLike>;
  truncate(length?: number): Promise<void>;
  close(): Promise<void>;
  /** Flush data and metadata. Absent means the driver has nothing to flush. */
  sync?(): Promise<void>;
  /** Flush data only. Absent means the driver has nothing to flush. */
  datasync?(): Promise<void>;
}

export interface ReaddirOptions {
  withFileTypes: true;
}

export interface MkdirOptions {
  recursive?: boolean | undefined;
  mode?: number | undefined;
}

/** `fs`-compatible timestamp: seconds since epoch, or a `Date`. */
export type TimeLike = number | Date;

/**
 * What a driver can actually do.
 *
 * Transports adapt or answer `ENOTSUP`; silently faking a capability is how a
 * filesystem passes `ls` and corrupts data under `git`. Unset means "infer it"
 * (see `resolveCapabilities`), not "false" — except for `handles`,
 * `atomicRename`, `readOnly` and `durableWrites`, which no shape of a driver
 * establishes and which therefore default to `false` until they are claimed.
 */
export interface FsCapabilities {
  /** `open()` returns real per-open state that survives `unlink`. */
  handles?: boolean;
  /** `link()` works and `nlink` is counted. */
  hardlinks?: boolean;
  /** `symlink()` / `readlink()` work and `lstat` differs from `stat`. */
  symlinks?: boolean;
  /** Mode and ownership bits are stored and returned. */
  permissions?: boolean;
  /** `utimes()` is stored and returned. */
  times?: boolean;
  /** `truncate()` and `FileHandle.truncate()` work. */
  truncate?: boolean;
  /** `rename()` replaces the destination atomically. */
  atomicRename?: boolean;
  /** Names differing only in case are distinct entries. */
  caseSensitive?: boolean;
  /** `statfs()` returns meaningful numbers. */
  statfs?: boolean;
  /** Every mutating operation answers `EROFS`. Never inferred — say it. */
  readOnly?: boolean;
  /**
   * A write is **durable when its promise resolves**: nothing is buffered past
   * the resolution of `write()`/`truncate()`, so there is no error left for the
   * driver to discover at `close(2)` time.
   *
   * This is a statement about *when a failure can still be learned about*, not
   * about hardware — a memory driver satisfies it, and so does any driver whose
   * `write()` resolves only once the bytes are wherever it keeps them. A driver
   * that batches, queues or uploads in the background does **not**, however
   * quickly it resolves.
   *
   * **Never inferred — declare it.** No shape of a driver establishes it: every
   * driver has `write()` whether or not it defers the work behind it, and
   * `sync`/`datasync` being present says the opposite of nothing (a driver with
   * nothing to flush may still offer them as no-ops, as the memory driver
   * does). Unclaimed means no, and the default behaviour is unchanged.
   *
   * What claiming it buys, today, is one thing on one transport: `mountx/fuse`
   * stops answering `FLUSH`, the request the kernel sends on every `close(2)`
   * of an open file. It is 12.8% of the requests in a `bun install` workload
   * and the third-largest opcode by count. The trade is exactly the durability
   * statement above: a `FLUSH` reply is a driver's one chance to report a
   * deferred write failure to the process that closed the file, and a driver
   * that has nothing deferred has nothing to report there. Claim it falsely and
   * a write error is lost silently.
   *
   * Two things worth knowing before claiming it. The kernel ignores
   * `FOPEN_NOFLUSH` — one of the two mechanisms for declining `FLUSH` — when
   * `writeback_cache` was negotiated, so on a mount that turns that on the
   * saving may simply not appear (mountx leaves it off by default). And the
   * **semantics here are argued, not tested**: pjdfstest has no coverage for
   * deferred `close(2)` errors, so no suite in this repository will catch a
   * driver that claims this and should not have.
   */
  durableWrites?: boolean;
  /** Optional `mountx.*` extensions the driver implements. */
  extensions?: readonly (keyof MountxExtensions)[];
}

/**
 * The optional extension namespace for what `node:fs` genuinely does not
 * cover. Transports probe for each member and degrade without it.
 *
 * Both members are live. `mknod` is consumed by all three mount transports —
 * four sessions, counting NFSv3 and NFSv4.1 separately — and by none of them
 * is it optional decoration: without it every one of them can create a regular
 * file and nothing else. The S3 gateway is the transport that does not appear
 * here, and cannot: object storage has no way to name a FIFO or a device node.
 * `utimens` is consumed by the two wires that carry nanoseconds, FUSE's
 * `SETATTR` and 9P's `Tsetattr` (NFS's `SETATTR` carries them too, but its
 * sessions have not adopted the extension).
 *
 * Nothing here is speculative — the four `xattr` calls were, and were removed
 * rather than left as a surface with no consumer. Re-adding them is type-only,
 * and belongs with the session work that would answer the opcodes.
 *
 * Deliberately just the path-shaped gaps: locks, `fallocate`, `lseek` and
 * cache-invalidation notifies are per-open-file or session-scoped, so they get
 * designed with the session layer rather than guessed at here.
 */
export interface MountxExtensions {
  /** Nanosecond timestamps; `fs.utimes` takes float seconds and loses them. */
  utimens?(
    path: string,
    atimeNs: bigint,
    mtimeNs: bigint,
    options?: { followSymlinks?: boolean },
  ): Promise<void>;
  /** FIFOs, sockets and device nodes. */
  mknod?(path: string, mode: number, dev: number): Promise<void>;
}

/**
 * A filesystem driver.
 *
 * Only `stat`, `readdir` and `open` are required; every other method is
 * optional and **missing means the capability is absent** — the transport
 * answers `ENOSYS`/`ENOTSUP` rather than pretending.
 *
 * All paths are absolute, POSIX-style, normalized strings (see
 * `normalizePath`); the loopback harness and the session layer guarantee that.
 * Errors follow `node:fs` conventions: a POSIX `code` and a libuv-style
 * `errno` (see `fsError`).
 */
export interface FsDriver {
  /** What this driver supports. Omitted members are inferred. */
  readonly capabilities?: FsCapabilities;
  /** Optional non-`node:fs` extensions. */
  readonly mountx?: MountxExtensions;

  // --- core ---
  stat(path: string): Promise<StatsLike>;
  readdir(path: string, options: ReaddirOptions): Promise<DirentLike[]>;
  open(path: string, flags?: string | number, mode?: number): Promise<FileHandleLike>;

  // --- optional ---
  lstat?(path: string): Promise<StatsLike>;
  statfs?(path: string): Promise<StatsFsLike>;
  mkdir?(path: string, options?: MkdirOptions): Promise<string | undefined>;
  rmdir?(path: string): Promise<void>;
  unlink?(path: string): Promise<void>;
  rename?(oldPath: string, newPath: string): Promise<void>;
  link?(existingPath: string, newPath: string): Promise<void>;
  symlink?(target: string, path: string, type?: string | null): Promise<void>;
  readlink?(path: string): Promise<string>;
  chmod?(path: string, mode: number): Promise<void>;
  chown?(path: string, uid: number, gid: number): Promise<void>;
  lchown?(path: string, uid: number, gid: number): Promise<void>;
  truncate?(path: string, length?: number): Promise<void>;
  utimes?(path: string, atime: TimeLike, mtime: TimeLike): Promise<void>;
  lutimes?(path: string, atime: TimeLike, mtime: TimeLike): Promise<void>;
}

/**
 * A driver that implements every method (both bundled drivers do, and so does
 * `node:fs/promises`). Declaring capabilities stays optional.
 */
export type FullFsDriver = Required<Omit<FsDriver, "capabilities" | "mountx">> &
  Pick<FsDriver, "capabilities" | "mountx">;

/** Names of the optional `FsDriver` methods. */
export type FsDriverMethod = keyof {
  [K in keyof FsDriver as NonNullable<FsDriver[K]> extends (...args: never[]) => unknown
    ? K
    : never]: 1;
};

// --- file type bits (POSIX `S_IF*`) ---
export const S_IFMT = 0o170000;
export const S_IFREG = 0o100000;
export const S_IFDIR = 0o040000;
export const S_IFLNK = 0o120000;
export const S_IFBLK = 0o060000;
export const S_IFCHR = 0o020000;
export const S_IFIFO = 0o010000;
export const S_IFSOCK = 0o140000;

// --- the mode bits that are not permission bits (`inode(7)`) ---
/** Set-group-ID. On a directory it also means "children inherit my group". */
export const S_ISGID = 0o2000;
/** Group execute — the bit that makes set-group-ID mean something on a file. */
export const S_IXGRP = 0o0010;
