//! The kernel ABI the supervisor speaks, transcribed rather than imported.
//!
//! Every number and every struct in this file crosses a process boundary: the
//! syscall numbers select what the BPF filter traps, and the structs are
//! written into *another process's* memory. So the layouts have to be the
//! kernel's, not whatever this binary's libc believes — which is the same rule
//! `src/9p/constants.ts` and `src/fuse/constants.ts` are held to, met from the
//! other side. Sources are named per group and are all at tag **v6.12**, the
//! tag the rest of the repository transcribes from.
//!
//! The one thing deliberately *not* here is the errno table: it is transcribed
//! once in `src/errors.ts`, `Rlerror` carries those numbers verbatim, and the
//! handlers pass them straight back to the tracee. The few values below are the
//! ones the supervisor *originates* rather than forwards.

// ---------------------------------------------------------------------------
// Syscall numbers — arch/x86/entry/syscalls/syscall_64.tbl
//
// x86-64 only, and the filter refuses any other syscall table outright rather
// than reading these numbers against it (see `notify.zig`). arm64 would be a
// second table here, not a redesign.
// ---------------------------------------------------------------------------

pub const SYS = struct {
    pub const read = 0;
    pub const write = 1;
    pub const open = 2;
    pub const close = 3;
    pub const stat = 4;
    pub const fstat = 5;
    pub const lstat = 6;
    pub const lseek = 8;
    pub const mmap = 9;
    pub const dup2 = 33;
    pub const pread64 = 17;
    pub const pwrite64 = 18;
    pub const readv = 19;
    pub const writev = 20;
    pub const access = 21;
    pub const sendfile = 40;
    pub const fsync = 74;
    pub const fdatasync = 75;
    pub const truncate = 76;
    pub const ftruncate = 77;
    pub const getcwd = 79;
    pub const chdir = 80;
    pub const fchdir = 81;
    pub const rename = 82;
    pub const mkdir = 83;
    pub const rmdir = 84;
    pub const creat = 85;
    pub const link = 86;
    pub const unlink = 87;
    pub const symlink = 88;
    pub const readlink = 89;
    pub const chmod = 90;
    pub const fchmod = 91;
    pub const chown = 92;
    pub const fchown = 93;
    pub const lchown = 94;
    pub const utime = 132;
    pub const mknod = 133;
    pub const statfs = 137;
    pub const fstatfs = 138;
    pub const setxattr = 188;
    pub const lsetxattr = 189;
    pub const fsetxattr = 190;
    pub const getxattr = 191;
    pub const lgetxattr = 192;
    pub const fgetxattr = 193;
    pub const listxattr = 194;
    pub const llistxattr = 195;
    pub const flistxattr = 196;
    pub const removexattr = 197;
    pub const lremovexattr = 198;
    pub const fremovexattr = 199;
    pub const getdents64 = 217;
    pub const exit_group = 231;
    pub const utimes = 235;
    pub const openat = 257;
    pub const mkdirat = 258;
    pub const mknodat = 259;
    pub const fchownat = 260;
    pub const futimesat = 261;
    pub const newfstatat = 262;
    pub const unlinkat = 263;
    pub const renameat = 264;
    pub const linkat = 265;
    pub const symlinkat = 266;
    pub const readlinkat = 267;
    pub const fchmodat = 268;
    pub const faccessat = 269;
    pub const splice = 275;
    pub const utimensat = 280;
    pub const fallocate = 285;
    pub const preadv = 295;
    pub const pwritev = 296;
    pub const renameat2 = 316;
    pub const copy_file_range = 326;
    pub const preadv2 = 327;
    pub const pwritev2 = 328;
    pub const dup3 = 292;
    pub const statx = 332;
    pub const close_range = 436;
    pub const openat2 = 437;
    pub const faccessat2 = 439;
};

// ---------------------------------------------------------------------------
// open(2) flags — include/uapi/asm-generic/fcntl.h (x86-64 uses the generic set)
//
// This is the *kernel's* namespace, and it is also the one 9P2000.L's
// `Tlopen.flags` carries: the wire and the host are the same kernel here, so
// the flags cross to the driver untranslated, exactly as
// `src/9p/session.ts` documents for `driverOpenFlags()`.
// ---------------------------------------------------------------------------

pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0o0;
pub const O_WRONLY: u32 = 0o1;
pub const O_RDWR: u32 = 0o2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_NOCTTY: u32 = 0o400;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_NOFOLLOW: u32 = 0o400000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const O_PATH: u32 = 0o10000000;
pub const O_TMPFILE: u32 = 0o20000000;

// ---------------------------------------------------------------------------
// *at() flags — include/uapi/linux/fcntl.h
// ---------------------------------------------------------------------------

pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const AT_REMOVEDIR: u32 = 0x200;
pub const AT_SYMLINK_FOLLOW: u32 = 0x400;
pub const AT_EMPTY_PATH: u32 = 0x1000;
/// `faccessat2`'s only interesting flag; `AT_EACCESS` is the other and this
/// supervisor makes no distinction between real and effective ids.
pub const AT_EACCESS: u32 = 0x200;

// ---------------------------------------------------------------------------
// File modes — include/uapi/linux/stat.h
// ---------------------------------------------------------------------------

pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;

// ---------------------------------------------------------------------------
// Errno — the values `src/errors.ts` transcribes, for the ones this supervisor
// raises itself rather than forwarding from an `Rlerror`.
// ---------------------------------------------------------------------------

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EIO: i32 = 5;
pub const EBADF: i32 = 9;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EFAULT: i32 = 14;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENODEV: i32 = 19;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const EMFILE: i32 = 24;
pub const ESPIPE: i32 = 29;
pub const ERANGE: i32 = 34;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOSYS: i32 = 38;
pub const ELOOP: i32 = 40;
pub const EOVERFLOW: i32 = 75;
pub const ENOTSUP: i32 = 95;

// ---------------------------------------------------------------------------
// access(2) — include/uapi/linux/fcntl.h / unistd.h
// ---------------------------------------------------------------------------

pub const F_OK: u32 = 0;
pub const X_OK: u32 = 1;
pub const W_OK: u32 = 2;
pub const R_OK: u32 = 4;

// ---------------------------------------------------------------------------
// lseek(2) — include/uapi/linux/fs.h
// ---------------------------------------------------------------------------

pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

/// `mmap(2)`'s `MAP_ANONYMOUS` — include/uapi/asm-generic/mman-common.h.
pub const MAP_ANONYMOUS: u64 = 0x20;

/// `utimensat(2)`'s two sentinels — include/uapi/linux/stat.h.
pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

/// `d_type` values — include/uapi/linux/fs.h (`DT_*`), the same byte
/// `src/9p/protocol.ts` packs into a dirent.
pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;

// ---------------------------------------------------------------------------
// Structs written into tracee memory
// ---------------------------------------------------------------------------

/// `struct stat` as x86-64 Linux lays it out — arch/x86/include/uapi/asm/stat.h.
pub const Stat = extern struct {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: u64,
    st_atime_nsec: u64,
    st_mtime: u64,
    st_mtime_nsec: u64,
    st_ctime: u64,
    st_ctime_nsec: u64,
    __unused: [3]i64,
};

/// `struct statx` — include/uapi/linux/stat.h. Only the fields this supervisor
/// fills are named; the tail is zeroed.
pub const Statx = extern struct {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: Timestamp,
    stx_btime: Timestamp,
    stx_ctime: Timestamp,
    stx_mtime: Timestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    __spare2: u64,
    __spare3: [12]u64,

    pub const Timestamp = extern struct { sec: i64, nsec: u32, __pad: i32 };
};

/// `STATX_BASIC_STATS` — the fields a `struct stat` has.
pub const STATX_BASIC_STATS: u32 = 0x0000_07ff;

/// `struct statfs` on x86-64 — include/uapi/asm-generic/statfs.h with
/// `__statfs_word` as `__kernel_long_t`, so every field is 64 bits and the
/// whole struct is 120 bytes.
pub const Statfs = extern struct {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]i32,
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [4]i64,
};

/// `struct iovec` — include/uapi/linux/uio.h.
pub const Iovec = extern struct { base: u64, len: u64 };

/// `struct timespec` — include/uapi/linux/time.h.
pub const Timespec = extern struct { sec: i64, nsec: i64 };

/// `struct timeval`, for the legacy `utimes`/`futimesat`.
pub const Timeval = extern struct { sec: i64, usec: i64 };

/// `struct utimbuf`, for the legacy `utime`.
pub const Utimbuf = extern struct { actime: i64, modtime: i64 };

/// The header of a `struct linux_dirent64` — include/uapi/linux/fs.h. Variable
/// length, so `getdents64` builds it by hand: `d_ino[8] d_off[8] d_reclen[2]
/// d_type[1]` then the name and its NUL, padded to 8.
pub const DIRENT64_HEADER = 19;
