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
 * (see `resolveCapabilities`), not "false".
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
  /** Every mutating operation answers `EROFS`. */
  readOnly?: boolean;
  /** Optional `mountx.*` extensions the driver implements. */
  extensions?: readonly (keyof MountxExtensions)[];
}

/**
 * The optional extension namespace for what `node:fs` genuinely does not
 * cover. Transports probe for each member and degrade without it.
 *
 * Types only for now — no transport implements these yet. Deliberately just
 * the path-shaped gaps: locks, `fallocate`, `lseek` and cache-invalidation
 * notifies are per-open-file or session-scoped, so they get designed with the
 * session layer rather than guessed at here.
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
  getxattr?(path: string, name: string): Promise<Uint8Array>;
  setxattr?(path: string, name: string, value: Uint8Array, flags?: number): Promise<void>;
  listxattr?(path: string): Promise<string[]>;
  removexattr?(path: string, name: string): Promise<void>;
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
