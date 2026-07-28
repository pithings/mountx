/**
 * FUSE wire-protocol constants.
 *
 * Transcribed from the Linux kernel's `include/uapi/linux/fuse.h` at tag
 * **v6.12** (`FUSE_KERNEL_VERSION 7`, `FUSE_KERNEL_MINOR_VERSION 41`), which is
 * the protocol version the dev host's kernel speaks. Source of truth:
 * <https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/fuse.h>.
 *
 * Nothing here is guessed: every value and every struct offset in this
 * directory is copied from that file, and the struct layouts are reproduced as
 * comments next to their codecs in `protocol.ts`.
 */

/** Major protocol version. Only 7 exists. */
export const FUSE_KERNEL_VERSION = 7;

/** Highest minor version this implementation understands. */
export const FUSE_KERNEL_MINOR_VERSION = 41;

/** Node ID of the root inode. */
export const FUSE_ROOT_ID = 1n;

/** The kernel's read buffer is at least this large. */
export const FUSE_MIN_READ_BUFFER = 8192;

/**
 * Page size the `max_pages` negotiation is denominated in. The kernel uses its
 * own `PAGE_SIZE`; 4 KiB on every architecture mountx targets.
 */
export const FUSE_PAGE_SIZE = 4096;

/**
 * Kernel's ceiling on `fuse_init_out.max_pages` (`FUSE_MAX_MAX_PAGES` in
 * `fs/fuse/fuse_i.h`, the default `max_pages_limit`).
 *
 * A larger request is **clamped, not rejected** — `fs/fuse/inode.c` does
 * `min_t(unsigned, fc->max_pages_limit, max_t(unsigned, arg->max_pages, 1))`.
 * Clamping on our side too is what keeps the `max_write` we believe in equal to
 * the one the kernel will actually use.
 */
export const FUSE_MAX_MAX_PAGES = 256;

/**
 * Requests per page count when `FUSE_MAX_PAGES` was not negotiated
 * (`FUSE_DEFAULT_MAX_PAGES_PER_REQ`), i.e. a 128 KiB `max_write` ceiling.
 */
export const FUSE_DEFAULT_MAX_PAGES_PER_REQ = 32;

// --- opcodes (enum fuse_opcode) ---
export const FUSE_LOOKUP = 1;
export const FUSE_FORGET = 2; // no reply
export const FUSE_GETATTR = 3;
export const FUSE_SETATTR = 4;
export const FUSE_READLINK = 5;
export const FUSE_SYMLINK = 6;
export const FUSE_MKNOD = 8;
export const FUSE_MKDIR = 9;
export const FUSE_UNLINK = 10;
export const FUSE_RMDIR = 11;
export const FUSE_RENAME = 12;
export const FUSE_LINK = 13;
export const FUSE_OPEN = 14;
export const FUSE_READ = 15;
export const FUSE_WRITE = 16;
export const FUSE_STATFS = 17;
export const FUSE_RELEASE = 18;
export const FUSE_FSYNC = 20;
export const FUSE_SETXATTR = 21;
export const FUSE_GETXATTR = 22;
export const FUSE_LISTXATTR = 23;
export const FUSE_REMOVEXATTR = 24;
export const FUSE_FLUSH = 25;
export const FUSE_INIT = 26;
export const FUSE_OPENDIR = 27;
export const FUSE_READDIR = 28;
export const FUSE_RELEASEDIR = 29;
export const FUSE_FSYNCDIR = 30;
export const FUSE_GETLK = 31;
export const FUSE_SETLK = 32;
export const FUSE_SETLKW = 33;
export const FUSE_ACCESS = 34;
export const FUSE_CREATE = 35;
export const FUSE_INTERRUPT = 36;
export const FUSE_BMAP = 37;
export const FUSE_DESTROY = 38;
export const FUSE_IOCTL = 39;
export const FUSE_POLL = 40;
export const FUSE_NOTIFY_REPLY = 41;
export const FUSE_BATCH_FORGET = 42; // no reply
export const FUSE_FALLOCATE = 43;
export const FUSE_READDIRPLUS = 44;
export const FUSE_RENAME2 = 45;
export const FUSE_LSEEK = 46;
export const FUSE_COPY_FILE_RANGE = 47;
export const FUSE_SETUPMAPPING = 48;
export const FUSE_REMOVEMAPPING = 49;
export const FUSE_SYNCFS = 50;
export const FUSE_TMPFILE = 51;
export const FUSE_STATX = 52;
export const CUSE_INIT = 4096;

// --- notify codes (enum fuse_notify_code), sent server -> kernel ---
export const FUSE_NOTIFY_POLL = 1;
export const FUSE_NOTIFY_INVAL_INODE = 2;
export const FUSE_NOTIFY_INVAL_ENTRY = 3;
export const FUSE_NOTIFY_STORE = 4;
export const FUSE_NOTIFY_RETRIEVE = 5;
export const FUSE_NOTIFY_DELETE = 6;
export const FUSE_NOTIFY_RESEND = 7;

/** `fuse_out_header.unique` for a notification rather than a reply. */
export const FUSE_NOTIFY_UNIQUE = 0n;

// --- fuse_setattr_in.valid ---
export const FATTR_MODE = 1 << 0;
export const FATTR_UID = 1 << 1;
export const FATTR_GID = 1 << 2;
export const FATTR_SIZE = 1 << 3;
export const FATTR_ATIME = 1 << 4;
export const FATTR_MTIME = 1 << 5;
export const FATTR_FH = 1 << 6;
export const FATTR_ATIME_NOW = 1 << 7;
export const FATTR_MTIME_NOW = 1 << 8;
export const FATTR_LOCKOWNER = 1 << 9;
export const FATTR_CTIME = 1 << 10;
export const FATTR_KILL_SUIDGID = 1 << 11;

// --- fuse_open_out.open_flags ---
export const FOPEN_DIRECT_IO = 1 << 0;
export const FOPEN_KEEP_CACHE = 1 << 1;
export const FOPEN_NONSEEKABLE = 1 << 2;
export const FOPEN_CACHE_DIR = 1 << 3;
export const FOPEN_STREAM = 1 << 4;
export const FOPEN_NOFLUSH = 1 << 5;
export const FOPEN_PARALLEL_DIRECT_WRITES = 1 << 6;
export const FOPEN_PASSTHROUGH = 1 << 7;

/**
 * `INIT` request/reply flags.
 *
 * On the wire these are two `uint32_t` fields — `flags` (bits 0..31) and
 * `flags2` (bits 32..63, only from 7.36 and only when the kernel set
 * `FUSE_INIT_EXT`). They are **`bigint` here** because that is the only lossless
 * JS representation of the single 64-bit space the kernel documents, and
 * because bit 31 (`FUSE_INIT_RESERVED`) is not representable as a positive
 * `number` under `<<`. Use `splitInitFlags` / `joinInitFlags` to move between
 * the two representations.
 */
export const FUSE_ASYNC_READ = 1n << 0n;
export const FUSE_POSIX_LOCKS = 1n << 1n;
export const FUSE_FILE_OPS = 1n << 2n;
export const FUSE_ATOMIC_O_TRUNC = 1n << 3n;
export const FUSE_EXPORT_SUPPORT = 1n << 4n;
export const FUSE_BIG_WRITES = 1n << 5n;
export const FUSE_DONT_MASK = 1n << 6n;
export const FUSE_SPLICE_WRITE = 1n << 7n;
export const FUSE_SPLICE_MOVE = 1n << 8n;
export const FUSE_SPLICE_READ = 1n << 9n;
export const FUSE_FLOCK_LOCKS = 1n << 10n;
export const FUSE_HAS_IOCTL_DIR = 1n << 11n;
export const FUSE_AUTO_INVAL_DATA = 1n << 12n;
export const FUSE_DO_READDIRPLUS = 1n << 13n;
export const FUSE_READDIRPLUS_AUTO = 1n << 14n;
export const FUSE_ASYNC_DIO = 1n << 15n;
export const FUSE_WRITEBACK_CACHE = 1n << 16n;
export const FUSE_NO_OPEN_SUPPORT = 1n << 17n;
export const FUSE_PARALLEL_DIROPS = 1n << 18n;
export const FUSE_HANDLE_KILLPRIV = 1n << 19n;
export const FUSE_POSIX_ACL = 1n << 20n;
export const FUSE_ABORT_ERROR = 1n << 21n;
export const FUSE_MAX_PAGES = 1n << 22n;
export const FUSE_CACHE_SYMLINKS = 1n << 23n;
export const FUSE_NO_OPENDIR_SUPPORT = 1n << 24n;
export const FUSE_EXPLICIT_INVAL_DATA = 1n << 25n;
export const FUSE_MAP_ALIGNMENT = 1n << 26n;
export const FUSE_SUBMOUNTS = 1n << 27n;
export const FUSE_HANDLE_KILLPRIV_V2 = 1n << 28n;
export const FUSE_SETXATTR_EXT = 1n << 29n;
export const FUSE_INIT_EXT = 1n << 30n;
export const FUSE_INIT_RESERVED = 1n << 31n;
export const FUSE_SECURITY_CTX = 1n << 32n;
export const FUSE_HAS_INODE_DAX = 1n << 33n;
export const FUSE_CREATE_SUPP_GROUP = 1n << 34n;
export const FUSE_HAS_EXPIRE_ONLY = 1n << 35n;
export const FUSE_DIRECT_IO_ALLOW_MMAP = 1n << 36n;
export const FUSE_PASSTHROUGH = 1n << 37n;
export const FUSE_NO_EXPORT_SUPPORT = 1n << 38n;
export const FUSE_HAS_RESEND = 1n << 39n;
export const FUSE_ALLOW_IDMAP = 1n << 40n;

// --- fuse_release_in.release_flags ---
export const FUSE_RELEASE_FLUSH = 1 << 0;
export const FUSE_RELEASE_FLOCK_UNLOCK = 1 << 1;

/** `fuse_getattr_in.getattr_flags` */
export const FUSE_GETATTR_FH = 1 << 0;

/** `fuse_lk_in.lk_flags` */
export const FUSE_LK_FLOCK = 1 << 0;

// --- fuse_write_in.write_flags ---
export const FUSE_WRITE_CACHE = 1 << 0;
export const FUSE_WRITE_LOCKOWNER = 1 << 1;
export const FUSE_WRITE_KILL_SUIDGID = 1 << 2;

/** `fuse_read_in.read_flags` */
export const FUSE_READ_LOCKOWNER = 1 << 1;

/** `fuse_poll_in.flags` */
export const FUSE_POLL_SCHEDULE_NOTIFY = 1 << 0;

/** `fuse_fsync_in.fsync_flags` */
export const FUSE_FSYNC_FDATASYNC = 1 << 0;

// --- fuse_attr.flags (7.32+) ---
export const FUSE_ATTR_SUBMOUNT = 1 << 0;
export const FUSE_ATTR_DAX = 1 << 1;

/** `fuse_open_in.open_flags` / `fuse_create_in.open_flags` */
export const FUSE_OPEN_KILL_SUIDGID = 1 << 0;

/** `fuse_setxattr_in.setxattr_flags` (7.33+) */
export const FUSE_SETXATTR_ACL_KILL_SGID = 1 << 0;

/** `fuse_notify_inval_entry_out.flags` (7.38+) */
export const FUSE_EXPIRE_ONLY = 1 << 0;

/** High bit of `fuse_in_header.unique` marks a resent request (7.40+). */
export const FUSE_UNIQUE_RESEND = 1n << 63n;

/** `fuse_in_header.uid` / `.gid` when an idmapping could not be applied. */
export const FUSE_INVALID_UIDGID = 0xff_ff_ff_ff;

// --- enum fuse_ext_type (7.38+) ---
export const FUSE_MAX_NR_SECCTX = 31;
export const FUSE_EXT_GROUPS = 32;

// --- readdir entry types (`d_type`, POSIX `DT_*`) ---
export const DT_UNKNOWN = 0;
export const DT_FIFO = 1;
export const DT_CHR = 2;
export const DT_DIR = 4;
export const DT_BLK = 6;
export const DT_REG = 8;
export const DT_LNK = 10;
export const DT_SOCK = 12;

/**
 * `open(2)` flags **as they appear on the FUSE wire**.
 *
 * Not from `fuse.h` — these are Linux's `asm-generic/fcntl.h` values, and they
 * are transcribed here for the same reason everything else in this file is:
 * `fuse_open_in.flags` and `fuse_create_in.flags` carry whatever the *Linux*
 * kernel put there, whatever host the server happens to run on.
 *
 * **Do not substitute `node:fs`'s `constants.O_*` for these.** Those are the
 * host's values, and they disagree: macOS's `O_TRUNC` is `0o2000`, which is
 * Linux's `O_APPEND`, so a Tier-0 test run on macOS would read an append-open
 * as a truncating one. The converse also holds — flags this server *originates*
 * for a driver (`mountx.mknod`'s fallback, say) must use `node:fs`'s
 * constants, because the driver resolves them against the host.
 *
 * Only the bits the session actually inspects are listed.
 */
export const O_ACCMODE = 0o3;
export const O_RDONLY = 0o0;
export const O_WRONLY = 0o1;
export const O_RDWR = 0o2;
export const O_CREAT = 0o100;
export const O_EXCL = 0o200;
export const O_TRUNC = 0o1000;
export const O_APPEND = 0o2000;

/** `lseek(2)` whence values carried by `fuse_lseek_in.whence`. */
export const SEEK_SET = 0;
export const SEEK_CUR = 1;
export const SEEK_END = 2;
export const SEEK_DATA = 3;
export const SEEK_HOLE = 4;

// --- fuse_file_lock.type (`F_*LCK`) ---
export const F_RDLCK = 0;
export const F_WRLCK = 1;
export const F_UNLCK = 2;

/** `xattr` create/replace semantics (`fuse_setxattr_in.flags`). */
export const XATTR_CREATE = 1;
export const XATTR_REPLACE = 2;

// --- fixed struct sizes (see the layout comments in `protocol.ts`) ---
export const FUSE_IN_HEADER_SIZE = 40;
export const FUSE_OUT_HEADER_SIZE = 16;
export const FUSE_DIRENT_HEADER_SIZE = 24;
export const FUSE_INIT_OUT_SIZE = 64;
/** `fuse_init_out` before `flags`/`max_write` existed (< 7.5). */
export const FUSE_COMPAT_INIT_OUT_SIZE = 8;
/** `fuse_init_out` before `time_gran` and the reserved tail (< 7.23). */
export const FUSE_COMPAT_22_INIT_OUT_SIZE = 24;
/** `fuse_entry_out` when `fuse_attr` lacked `blksize`/`flags` (< 7.9). */
export const FUSE_COMPAT_ENTRY_OUT_SIZE = 120;
/** `fuse_attr_out` when `fuse_attr` lacked `blksize`/`flags` (< 7.9). */
export const FUSE_COMPAT_ATTR_OUT_SIZE = 96;
/** `fuse_kstatfs` before `frsize` (< 7.4). */
export const FUSE_COMPAT_STATFS_SIZE = 48;
/** `fuse_read_in` / `fuse_write_in` before `lock_owner`/`flags` (< 7.9). */
export const FUSE_COMPAT_WRITE_IN_SIZE = 24;
/** `fuse_mknod_in` / `fuse_create_in` before `umask` (< 7.12). */
export const FUSE_COMPAT_MKNOD_IN_SIZE = 8;
/** `fuse_setxattr_in` without `FUSE_SETXATTR_EXT`. */
export const FUSE_COMPAT_SETXATTR_IN_SIZE = 8;

/** Human-readable opcode names, for logs, dispatch tables and errors. */
export const OPCODE_NAMES: Readonly<Record<number, string>> = {
  [FUSE_LOOKUP]: "LOOKUP",
  [FUSE_FORGET]: "FORGET",
  [FUSE_GETATTR]: "GETATTR",
  [FUSE_SETATTR]: "SETATTR",
  [FUSE_READLINK]: "READLINK",
  [FUSE_SYMLINK]: "SYMLINK",
  [FUSE_MKNOD]: "MKNOD",
  [FUSE_MKDIR]: "MKDIR",
  [FUSE_UNLINK]: "UNLINK",
  [FUSE_RMDIR]: "RMDIR",
  [FUSE_RENAME]: "RENAME",
  [FUSE_LINK]: "LINK",
  [FUSE_OPEN]: "OPEN",
  [FUSE_READ]: "READ",
  [FUSE_WRITE]: "WRITE",
  [FUSE_STATFS]: "STATFS",
  [FUSE_RELEASE]: "RELEASE",
  [FUSE_FSYNC]: "FSYNC",
  [FUSE_SETXATTR]: "SETXATTR",
  [FUSE_GETXATTR]: "GETXATTR",
  [FUSE_LISTXATTR]: "LISTXATTR",
  [FUSE_REMOVEXATTR]: "REMOVEXATTR",
  [FUSE_FLUSH]: "FLUSH",
  [FUSE_INIT]: "INIT",
  [FUSE_OPENDIR]: "OPENDIR",
  [FUSE_READDIR]: "READDIR",
  [FUSE_RELEASEDIR]: "RELEASEDIR",
  [FUSE_FSYNCDIR]: "FSYNCDIR",
  [FUSE_GETLK]: "GETLK",
  [FUSE_SETLK]: "SETLK",
  [FUSE_SETLKW]: "SETLKW",
  [FUSE_ACCESS]: "ACCESS",
  [FUSE_CREATE]: "CREATE",
  [FUSE_INTERRUPT]: "INTERRUPT",
  [FUSE_BMAP]: "BMAP",
  [FUSE_DESTROY]: "DESTROY",
  [FUSE_IOCTL]: "IOCTL",
  [FUSE_POLL]: "POLL",
  [FUSE_NOTIFY_REPLY]: "NOTIFY_REPLY",
  [FUSE_BATCH_FORGET]: "BATCH_FORGET",
  [FUSE_FALLOCATE]: "FALLOCATE",
  [FUSE_READDIRPLUS]: "READDIRPLUS",
  [FUSE_RENAME2]: "RENAME2",
  [FUSE_LSEEK]: "LSEEK",
  [FUSE_COPY_FILE_RANGE]: "COPY_FILE_RANGE",
  [FUSE_SETUPMAPPING]: "SETUPMAPPING",
  [FUSE_REMOVEMAPPING]: "REMOVEMAPPING",
  [FUSE_SYNCFS]: "SYNCFS",
  [FUSE_TMPFILE]: "TMPFILE",
  [FUSE_STATX]: "STATX",
  [CUSE_INIT]: "CUSE_INIT",
};

/** `OPCODE_NAMES[opcode]`, or `UNKNOWN(<opcode>)`. */
export function opcodeName(opcode: number): string {
  return OPCODE_NAMES[opcode] ?? `UNKNOWN(${opcode})`;
}
