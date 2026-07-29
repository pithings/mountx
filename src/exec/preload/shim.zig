//! SPIKE B — an `LD_PRELOAD` interposer that serves an `FsDriver` over 9P.
//!
//! Built as a shared library and injected with `LD_PRELOAD`, this replaces
//! libc's filesystem entry points for one process tree. A call naming a path
//! under `$MOUNTX_ROOT` is answered from the 9P server on `$MOUNTX_9P_SOCK`;
//! everything else is forwarded to the real libc symbol and never touched.
//! No kernel mount, no namespace, no privileges, no `/dev/fuse`.
//!
//! **The honest shape of this approach is symbol coverage.** There is no
//! syscall boundary here — the boundary is glibc's exported ABI, and a program
//! reaches the kernel by any number of routes that do not cross it:
//!
//!   - A static binary has no dynamic loader, so `LD_PRELOAD` is never read.
//!   - A Go binary issues syscalls from its own runtime, with no symbol to
//!     interpose even when dynamically linked.
//!   - A setuid or setgid binary has `LD_PRELOAD` stripped by the loader.
//!   - glibc's *internal* calls do not go through the PLT: interposing
//!     `fstatat` does not catch glibc's own `stat()` reaching it, which is why
//!     `statx` is interposed here explicitly. Measured, not assumed — a shim
//!     without `statx` serves `cat` and is invisible to `ls` on glibc 2.43.
//!
//! The last of those is the one that makes this a maintenance surface rather
//! than a fixed cost: which symbol a program lands on is a property of the
//! glibc it was *built* against, so the set below is a moving target across
//! distributions in a way a syscall filter never is.
//!
//! Everything filesystem-shaped is settled on the far side of the socket by
//! `src/9p/session.ts`. This file resolves a path prefix, keeps an fd table,
//! and translates two data structures — `struct stat` and `struct dirent`.
//!
//! Spike scope: read, write, stat, and directory listing. No symlinks, no
//! `*at()` resolution against a real `dirfd`, no cwd tracking, no `mmap`,
//! no `exec` off the virtual tree.

const std = @import("std");
const p9 = @import("p9.zig");

const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("dlfcn.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("errno.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/xattr.h");
    @cInclude("dirent.h");
    @cInclude("stdio.h");
});

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const MAX_FD = 4096;

/// An fd this shim owns. The stored path is what makes `*at()` resolution
/// possible: `openat(fd, "name")` against one of our directory fds has to
/// become a walk from the root, and only the fd knows where it is.
const Entry = struct {
    used: bool = false,
    is_dir: bool = false,
    fid: u32 = 0,
    offset: u64 = 0,
    path_len: u16 = 0,
    path: [PATH_MAX]u8 = undefined,
};

/// Long enough for the trees a spike walks, short enough that the fd table
/// stays a megabyte of BSS rather than sixteen.
const PATH_MAX = 256;

fn setPath(e: *Entry, rel: []const u8) void {
    const n = if (rel.len > PATH_MAX) PATH_MAX else rel.len;
    @memcpy(e.path[0..n], rel[0..n]);
    e.path_len = @intCast(n);
}

fn entryPath(e: *const Entry) []const u8 {
    return e.path[0..e.path_len];
}

/// `<dir>/<name>` into a caller-owned buffer, for resolving a relative path
/// against one of our directory fds.
fn joinPath(out: []u8, dir: []const u8, name: []const u8) ?[]const u8 {
    if (dir.len + 1 + name.len > out.len) return null;
    @memcpy(out[0..dir.len], dir);
    out[dir.len] = '/';
    @memcpy(out[dir.len + 1 .. dir.len + 1 + name.len], name);
    return out[0 .. dir.len + 1 + name.len];
}

var client: p9.Client = .{};
var table: [MAX_FD]Entry = @splat(.{});
var root: []const u8 = &.{};
var ready: bool = false;
var broken: bool = false;

/// The magic at the head of a `DIR` this shim owns, so `readdir()` can tell
/// its own streams from glibc's without a registry.
const DIR_MAGIC: u64 = 0x6d6f_756e_7478_3970; // "mountx9p"

const DirStream = struct {
    magic: u64,
    fid: u32,
    fd: i32,
    cookie: u64,
    len: usize,
    at: usize,
    ent: c.struct_dirent,
    buf: [16 * 1024]u8,
};

fn setErrno(e: i32) void {
    c.__errno_location().* = e;
}

// ---------------------------------------------------------------------------
// Real symbols
// ---------------------------------------------------------------------------

fn next(comptime T: type, comptime name: [*:0]const u8) ?T {
    const sym = c.dlsym(c.RTLD_NEXT, name);
    if (sym == null) return null;
    return @ptrCast(@alignCast(sym));
}

const OpenatFn = *const fn (c_int, [*:0]const u8, c_int, c_uint) callconv(.c) c_int;
const CloseFn = *const fn (c_int) callconv(.c) c_int;
const ReadFn = *const fn (c_int, ?*anyopaque, usize) callconv(.c) isize;
const PreadFn = *const fn (c_int, ?*anyopaque, usize, i64) callconv(.c) isize;
const WriteFn = *const fn (c_int, ?*const anyopaque, usize) callconv(.c) isize;
const LseekFn = *const fn (c_int, i64, c_int) callconv(.c) i64;
const FstatatFn = *const fn (c_int, [*:0]const u8, ?*c.struct_stat, c_int) callconv(.c) c_int;
const StatxFn = *const fn (c_int, [*:0]const u8, c_int, c_uint, ?*c.struct_statx) callconv(.c) c_int;
const OpendirFn = *const fn ([*:0]const u8) callconv(.c) ?*c.DIR;
const ReaddirFn = *const fn (?*c.DIR) callconv(.c) ?*c.struct_dirent;
const ClosedirFn = *const fn (?*c.DIR) callconv(.c) c_int;
const DirfdFn = *const fn (?*c.DIR) callconv(.c) c_int;
const AccessFn = *const fn ([*:0]const u8, c_int) callconv(.c) c_int;

fn realOpenat() OpenatFn {
    return next(OpenatFn, "openat").?;
}

// ---------------------------------------------------------------------------
// Setup and path matching
// ---------------------------------------------------------------------------

fn cstr(p: [*:0]const u8) []const u8 {
    var n: usize = 0;
    while (p[n] != 0) n += 1;
    return p[0..n];
}

/// Connect on first use. Also the `fork()` guard: a child inherits both the
/// socket and this state, and two processes taking turns on one connection
/// with the tag always zero corrupts both, so a child reconnects instead.
fn ensure() bool {
    if (broken) return false;
    if (ready and !client.forked()) return true;
    if (ready and client.forked()) {
        // The parent still needs its socket; close only our copy, and drop
        // every fd mapping, since the fids behind them belong to the parent's
        // session and mean nothing on a fresh one.
        client.reset();
        for (&table) |*e| e.* = .{};
        ready = false;
    }
    const sock = c.getenv("MOUNTX_9P_SOCK") orelse {
        broken = true;
        return false;
    };
    const r = c.getenv("MOUNTX_ROOT") orelse {
        broken = true;
        return false;
    };
    root = cstr(r);
    if (root.len == 0 or root[0] != '/') {
        broken = true;
        return false;
    }
    client.connect(cstr(sock)) catch {
        broken = true;
        return false;
    };
    ready = true;
    return true;
}

/// The part of `path` below `$MOUNTX_ROOT`, or null when the path is not ours.
/// Absolute paths only — a spike, and cwd tracking is a whole subsystem.
fn under(path: [*:0]const u8) ?[]const u8 {
    if (!ensure()) return null;
    const p = cstr(path);
    if (p.len < root.len) return null;
    if (!std.mem.eql(u8, p[0..root.len], root)) return null;
    if (p.len == root.len) return p[p.len..];
    if (p[root.len] != '/') return null;
    return p[root.len..];
}

fn remote(err: p9.Error) c_int {
    switch (err) {
        p9.Error.Remote => setErrno(client.last_errno),
        else => {
            broken = true;
            setErrno(c.EIO);
        },
    }
    return -1;
}

/// A real fd number to hand back, so the program can `close()` it, `dup()` it
/// and see it in `/proc/self/fd` like any other. `/dev/null` is the cheapest
/// placeholder; nothing is ever read from it, and anything this shim fails to
/// interpose therefore reads EOF rather than another file's contents.
fn placeholder() c_int {
    return realOpenat()(c.AT_FDCWD, "/dev/null", c.O_RDONLY | c.O_CLOEXEC, 0);
}

fn slot(fd: c_int) ?*Entry {
    if (fd < 0 or fd >= MAX_FD) return null;
    const e = &table[@intCast(fd)];
    return if (e.used) e else null;
}

// ---------------------------------------------------------------------------
// stat translation
// ---------------------------------------------------------------------------

/// A stable made-up device number. Every file this shim reports shares it,
/// which is what makes `(st_dev, st_ino)` a working identity for a program
/// that dedupes by it — the ino half is the qid path, allocated by the fid
/// table on the server.
/// Kept under 256 on purpose. `statx` reports a major/minor pair that glibc
/// recomposes with `makedev()`, while `stat` reports one number; a value that
/// does not survive `makedev(0, n) == n` makes the two disagree, and a program
/// that stats a file and then fstats the descriptor concludes it was replaced
/// underneath it. Measured on the seccomp spike, fixed in both.
const FAKE_DEV: u64 = 0x78;

fn fillStat(a: p9.Attr, out: *c.struct_stat) void {
    const z: *[@sizeOf(c.struct_stat)]u8 = @ptrCast(out);
    @memset(z, 0);
    out.st_dev = FAKE_DEV;
    out.st_ino = a.qid.path;
    out.st_mode = a.mode;
    out.st_nlink = a.nlink;
    out.st_uid = a.uid;
    out.st_gid = a.gid;
    out.st_rdev = a.rdev;
    out.st_size = @intCast(a.size);
    out.st_blksize = @intCast(a.blksize);
    out.st_blocks = @intCast(a.blocks);
    out.st_atim.tv_sec = @intCast(a.atime_sec);
    out.st_atim.tv_nsec = @intCast(a.atime_nsec);
    out.st_mtim.tv_sec = @intCast(a.mtime_sec);
    out.st_mtim.tv_nsec = @intCast(a.mtime_nsec);
    out.st_ctim.tv_sec = @intCast(a.ctime_sec);
    out.st_ctim.tv_nsec = @intCast(a.ctime_nsec);
}

fn fillStatx(a: p9.Attr, out: *c.struct_statx) void {
    const z: *[@sizeOf(c.struct_statx)]u8 = @ptrCast(out);
    @memset(z, 0);
    // Claim exactly the basic set; a caller checking `stx_mask` gets an honest
    // answer about which fields were filled rather than a blanket 0xfff.
    out.stx_mask = c.STATX_BASIC_STATS;
    out.stx_blksize = @intCast(a.blksize);
    out.stx_nlink = @intCast(a.nlink);
    out.stx_uid = a.uid;
    out.stx_gid = a.gid;
    out.stx_mode = @intCast(a.mode);
    out.stx_ino = a.qid.path;
    out.stx_size = a.size;
    out.stx_blocks = a.blocks;
    out.stx_dev_major = 0;
    out.stx_dev_minor = @intCast(FAKE_DEV);
    out.stx_atime.tv_sec = @intCast(a.atime_sec);
    out.stx_atime.tv_nsec = @intCast(a.atime_nsec);
    out.stx_mtime.tv_sec = @intCast(a.mtime_sec);
    out.stx_mtime.tv_nsec = @intCast(a.mtime_nsec);
    out.stx_ctime.tv_sec = @intCast(a.ctime_sec);
    out.stx_ctime.tv_nsec = @intCast(a.ctime_nsec);
}

/// Walk, getattr, clunk. The one-shot stat every path-taking stat call is.
fn statPath(rel: []const u8, attr: *p9.Attr) c_int {
    const fid = client.walk(rel, null) catch |e| return remote(e);
    defer client.clunk(fid);
    attr.* = client.getattr(fid) catch |e| return remote(e);
    return 0;
}

// ---------------------------------------------------------------------------
// Interposed: open family
// ---------------------------------------------------------------------------

fn doOpen(rel: []const u8, flags: c_int, mode: c_uint) c_int {
    const wants_create = (flags & c.O_CREAT) != 0;
    var qid: p9.Qid = undefined;
    var fid: u32 = 0;
    if (wants_create) {
        // `Tlcreate` creates *within* a directory fid and leaves that fid
        // pointing at the new file, so the walk has to stop one short.
        var last_slash: usize = 0;
        var i: usize = 0;
        while (i < rel.len) : (i += 1) {
            if (rel[i] == '/') last_slash = i;
        }
        const dir = rel[0..last_slash];
        const name = rel[last_slash + 1 ..];
        if (name.len == 0) {
            setErrno(c.EISDIR);
            return -1;
        }
        const dir_fid = client.walk(dir, null) catch |e| return remote(e);
        _ = client.lcreate(dir_fid, name, @intCast(flags), mode) catch |e| {
            // EEXIST without O_EXCL means "open the one that is there".
            if (e == p9.Error.Remote and client.last_errno == c.EEXIST and (flags & c.O_EXCL) == 0) {
                client.clunk(dir_fid);
                return doOpen(rel, flags & ~@as(c_int, c.O_CREAT), mode);
            }
            client.clunk(dir_fid);
            return remote(e);
        };
        fid = dir_fid; // now the created file
    } else {
        fid = client.walk(rel, &qid) catch |e| return remote(e);
        if ((qid.qtype & p9.P9_QTDIR) != 0 and (flags & c.O_WRONLY) == 0 and (flags & c.O_RDWR) == 0) {
            // A directory opened read-only is legal and is what `fdopendir`
            // and `openat(O_DIRECTORY)` do.
            _ = client.lopen(fid, @intCast(flags)) catch |e| {
                client.clunk(fid);
                return remote(e);
            };
            const fd = placeholder();
            if (fd < 0 or fd >= MAX_FD) {
                client.clunk(fid);
                setErrno(c.EMFILE);
                return -1;
            }
            table[@intCast(fd)] = .{ .used = true, .is_dir = true, .fid = fid, .offset = 0 };
            setPath(&table[@intCast(fd)], rel);
            return fd;
        }
        _ = client.lopen(fid, @intCast(flags)) catch |e| {
            client.clunk(fid);
            return remote(e);
        };
    }
    const fd = placeholder();
    if (fd < 0 or fd >= MAX_FD) {
        client.clunk(fid);
        setErrno(c.EMFILE);
        return -1;
    }
    table[@intCast(fd)] = .{ .used = true, .is_dir = false, .fid = fid, .offset = 0 };
    setPath(&table[@intCast(fd)], rel);
    return fd;
}

export fn openat(atfd: c_int, path: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int {
    if (under(path)) |rel| {
        client.lock.acquire();
        defer client.lock.release();
        return doOpen(rel, flags, mode);
    }
    // A *relative* path against a directory fd this shim owns. Every modern
    // tree walker works this way — `find`, `du`, `cp -r`, `tar`, anything on
    // `fts` or `nftw` — because resolving each level against the parent's fd
    // is what makes a traversal immune to a rename underneath it. Without
    // this, the shim serves single files and cannot walk a directory at all.
    if (path[0] != '/') {
        if (slot(atfd)) |e| {
            if (e.is_dir) {
                var buf: [PATH_MAX * 2]u8 = undefined;
                const joined = joinPath(&buf, entryPath(e), cstr(path)) orelse {
                    setErrno(c.ENAMETOOLONG);
                    return -1;
                };
                client.lock.acquire();
                defer client.lock.release();
                return doOpen(joined, flags, mode);
            }
        }
    }
    return realOpenat()(atfd, path, flags, mode);
}

export fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int {
    return openat(c.AT_FDCWD, path, flags, mode);
}

export fn open64(path: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int {
    return openat(c.AT_FDCWD, path, flags, mode);
}

export fn openat64(atfd: c_int, path: [*:0]const u8, flags: c_int, mode: c_uint) callconv(.c) c_int {
    return openat(atfd, path, flags, mode);
}

/// The `_FORTIFY_SOURCE` forms. A program built with fortification calls these
/// instead, and a shim missing them is simply not there for that program.
export fn __open_2(path: [*:0]const u8, flags: c_int) callconv(.c) c_int {
    return openat(c.AT_FDCWD, path, flags, 0);
}

export fn __openat_2(atfd: c_int, path: [*:0]const u8, flags: c_int) callconv(.c) c_int {
    return openat(atfd, path, flags, 0);
}

// ---------------------------------------------------------------------------
// Interposed: fd operations
// ---------------------------------------------------------------------------

export fn close(fd: c_int) callconv(.c) c_int {
    if (slot(fd)) |e| {
        client.lock.acquire();
        client.clunk(e.fid);
        e.* = .{};
        client.lock.release();
    }
    return next(CloseFn, "close").?(fd);
}

export fn read(fd: c_int, buf: ?*anyopaque, count: usize) callconv(.c) isize {
    const e = slot(fd) orelse return next(ReadFn, "read").?(fd, buf, count);
    client.lock.acquire();
    defer client.lock.release();
    const dst: [*]u8 = @ptrCast(buf.?);
    const n = client.read(e.fid, e.offset, dst[0..count]) catch |err| return remote(err);
    e.offset += n;
    return @intCast(n);
}

export fn pread(fd: c_int, buf: ?*anyopaque, count: usize, off: i64) callconv(.c) isize {
    const e = slot(fd) orelse return next(PreadFn, "pread").?(fd, buf, count, off);
    client.lock.acquire();
    defer client.lock.release();
    const dst: [*]u8 = @ptrCast(buf.?);
    const n = client.read(e.fid, @intCast(off), dst[0..count]) catch |err| return remote(err);
    return @intCast(n);
}

export fn pread64(fd: c_int, buf: ?*anyopaque, count: usize, off: i64) callconv(.c) isize {
    return pread(fd, buf, count, off);
}

export fn write(fd: c_int, buf: ?*const anyopaque, count: usize) callconv(.c) isize {
    const e = slot(fd) orelse return next(WriteFn, "write").?(fd, buf, count);
    client.lock.acquire();
    defer client.lock.release();
    const src: [*]const u8 = @ptrCast(buf.?);
    const n = client.write(e.fid, e.offset, src[0..count]) catch |err| return remote(err);
    e.offset += n;
    return @intCast(n);
}

export fn lseek(fd: c_int, off: i64, whence: c_int) callconv(.c) i64 {
    const e = slot(fd) orelse return next(LseekFn, "lseek").?(fd, off, whence);
    client.lock.acquire();
    defer client.lock.release();
    var base: i64 = 0;
    switch (whence) {
        c.SEEK_SET => base = 0,
        c.SEEK_CUR => base = @intCast(e.offset),
        c.SEEK_END => {
            const a = client.getattr(e.fid) catch |err| return remote(err);
            base = @intCast(a.size);
        },
        else => {
            setErrno(c.EINVAL);
            return -1;
        },
    }
    const target = base + off;
    if (target < 0) {
        setErrno(c.EINVAL);
        return -1;
    }
    e.offset = @intCast(target);
    return target;
}

export fn lseek64(fd: c_int, off: i64, whence: c_int) callconv(.c) i64 {
    return lseek(fd, off, whence);
}

// ---------------------------------------------------------------------------
// Interposed: stat family
//
// Every one of these is a distinct symbol a program might land on, and which
// one it lands on is decided by the glibc it was compiled against, not by the
// one it runs against. `statx` is the load-bearing entry on glibc 2.33+: the
// public `stat()` reaches it *internally*, without a PLT hop, so interposing
// `stat` and `fstatat` alone leaves modern coreutils entirely unserved.
// ---------------------------------------------------------------------------

export fn fstatat(atfd: c_int, path: [*:0]const u8, out: ?*c.struct_stat, flags: c_int) callconv(.c) c_int {
    if (under(path)) |rel| {
        client.lock.acquire();
        defer client.lock.release();
        var a: p9.Attr = undefined;
        if (statPath(rel, &a) != 0) return -1;
        fillStat(a, out.?);
        return 0;
    }
    // The same `*at()` resolution `openat` does, for the same reason: a tree
    // walker stats each entry relative to the directory fd it is holding.
    if (path[0] != '/') {
        if (slot(atfd)) |e| {
            if (e.is_dir) {
                var buf: [PATH_MAX * 2]u8 = undefined;
                const joined = joinPath(&buf, entryPath(e), cstr(path)) orelse {
                    setErrno(c.ENAMETOOLONG);
                    return -1;
                };
                client.lock.acquire();
                defer client.lock.release();
                var a: p9.Attr = undefined;
                if (statPath(joined, &a) != 0) return -1;
                fillStat(a, out.?);
                return 0;
            }
            // `AT_EMPTY_PATH` on one of our fds: stat the fd itself.
            if ((flags & c.AT_EMPTY_PATH) != 0 and path[0] == 0) {
                return fstat(atfd, out);
            }
        }
    }
    return next(FstatatFn, "fstatat").?(atfd, path, out, flags);
}

export fn fstatat64(atfd: c_int, path: [*:0]const u8, out: ?*c.struct_stat, flags: c_int) callconv(.c) c_int {
    return fstatat(atfd, path, out, flags);
}

export fn stat(path: [*:0]const u8, out: ?*c.struct_stat) callconv(.c) c_int {
    return fstatat(c.AT_FDCWD, path, out, 0);
}

export fn stat64(path: [*:0]const u8, out: ?*c.struct_stat) callconv(.c) c_int {
    return fstatat(c.AT_FDCWD, path, out, 0);
}

export fn lstat(path: [*:0]const u8, out: ?*c.struct_stat) callconv(.c) c_int {
    return fstatat(c.AT_FDCWD, path, out, c.AT_SYMLINK_NOFOLLOW);
}

export fn lstat64(path: [*:0]const u8, out: ?*c.struct_stat) callconv(.c) c_int {
    return fstatat(c.AT_FDCWD, path, out, c.AT_SYMLINK_NOFOLLOW);
}

/// The pre-2.33 versioned forms. Harmless where they are unused, and the
/// difference between working and invisible on an older distribution.
export fn __xstat(_: c_int, path: [*:0]const u8, out: ?*c.struct_stat) callconv(.c) c_int {
    return fstatat(c.AT_FDCWD, path, out, 0);
}

export fn __lxstat(_: c_int, path: [*:0]const u8, out: ?*c.struct_stat) callconv(.c) c_int {
    return fstatat(c.AT_FDCWD, path, out, c.AT_SYMLINK_NOFOLLOW);
}

export fn __fxstatat(_: c_int, atfd: c_int, path: [*:0]const u8, out: ?*c.struct_stat, flags: c_int) callconv(.c) c_int {
    return fstatat(atfd, path, out, flags);
}

export fn statx(atfd: c_int, path: [*:0]const u8, flags: c_int, mask: c_uint, out: ?*c.struct_statx) callconv(.c) c_int {
    if (under(path)) |rel| {
        client.lock.acquire();
        defer client.lock.release();
        var a: p9.Attr = undefined;
        if (statPath(rel, &a) != 0) return -1;
        fillStatx(a, out.?);
        return 0;
    }
    // The `*at()` branch again — and this is the one that mattered. With it
    // missing, `find` and `du` reported "Not a directory" for *every* child of
    // a directory they had just listed correctly, because modern coreutils
    // reach `statx` rather than `fstatat` and the relative form never got
    // here. Three separate symbols (`openat`, `fstatat`, `statx`) need the
    // identical resolution, and missing any one of them fails differently.
    if (path[0] != '/') {
        if (slot(atfd)) |e| {
            if (e.is_dir) {
                var buf: [PATH_MAX * 2]u8 = undefined;
                const joined = joinPath(&buf, entryPath(e), cstr(path)) orelse {
                    setErrno(c.ENAMETOOLONG);
                    return -1;
                };
                client.lock.acquire();
                defer client.lock.release();
                var a: p9.Attr = undefined;
                if (statPath(joined, &a) != 0) return -1;
                fillStatx(a, out.?);
                return 0;
            }
            if (path[0] == 0) {
                // `AT_EMPTY_PATH`: statx of the fd itself.
                client.lock.acquire();
                defer client.lock.release();
                const a = client.getattr(e.fid) catch |err| return remote(err);
                fillStatx(a, out.?);
                return 0;
            }
        }
    }
    return next(StatxFn, "statx").?(atfd, path, flags, mask, out);
}

export fn fstat(fd: c_int, out: ?*c.struct_stat) callconv(.c) c_int {
    const e = slot(fd) orelse {
        const f = next(FstatatFn, "fstatat").?;
        return f(fd, "", out, c.AT_EMPTY_PATH);
    };
    client.lock.acquire();
    defer client.lock.release();
    const a = client.getattr(e.fid) catch |err| return remote(err);
    fillStat(a, out.?);
    return 0;
}

export fn fstat64(fd: c_int, out: ?*c.struct_stat) callconv(.c) c_int {
    return fstat(fd, out);
}

export fn __fxstat(_: c_int, fd: c_int, out: ?*c.struct_stat) callconv(.c) c_int {
    return fstat(fd, out);
}

export fn access(path: [*:0]const u8, mode: c_int) callconv(.c) c_int {
    if (under(path)) |rel| {
        client.lock.acquire();
        defer client.lock.release();
        var a: p9.Attr = undefined;
        // Existence only. Real permission checking would mean resolving the
        // caller's uid/gid against the mode here, which is `allowedAccess()`
        // on the NFS side and is not a thing a spike needs.
        return statPath(rel, &a);
    }
    return next(AccessFn, "access").?(path, mode);
}

export fn faccessat(atfd: c_int, path: [*:0]const u8, mode: c_int, flags: c_int) callconv(.c) c_int {
    _ = atfd;
    _ = flags;
    return access(path, mode);
}

// ---------------------------------------------------------------------------
// Interposed: directory streams
//
// `DIR` is opaque and its contents are glibc's, so a directory this shim
// serves has to be a `DIR` this shim allocated — there is no way to hand a
// buffer to glibc's own. The magic word at the head is how `readdir()` tells
// the two apart on a pointer it did not create.
// ---------------------------------------------------------------------------

/// Open a directory stream over a *registered* fd rather than a bare
/// placeholder.
///
/// The distinction is the difference between `find` working and not. A stream
/// built on an unregistered fd looks fine until the caller asks for `dirfd()`
/// and then walks with `openat(that_fd, "child")` — which is what `fts` does
/// for every level. That fd was not in the table, so the call fell through to
/// the real `openat`, resolved "child" against `/dev/null`, and answered
/// ENOTDIR. "find: '/mountx/docs': Not a directory", witnessed, after the
/// top level had already listed correctly.
///
/// Going through `doOpen` means the fd is in the table with its path, so
/// `dirfd()` hands back something the rest of this shim recognises. The fid
/// belongs to the fd, and `closedir` releases it by closing the fd.
fn opendirRel(rel: []const u8) ?*c.DIR {
    const fd = doOpen(rel, c.O_RDONLY | c.O_DIRECTORY, 0);
    if (fd < 0) return null;
    const e = slot(fd) orelse {
        setErrno(c.EIO);
        return null;
    };
    const raw = c.malloc(@sizeOf(DirStream)) orelse {
        client.clunk(e.fid);
        e.* = .{};
        _ = next(CloseFn, "close").?(fd);
        setErrno(c.ENOMEM);
        return null;
    };
    const ds: *DirStream = @ptrCast(@alignCast(raw));
    ds.magic = DIR_MAGIC;
    ds.fid = e.fid;
    ds.fd = fd;
    ds.cookie = 0;
    ds.len = 0;
    ds.at = 0;
    return @ptrCast(raw);
}

fn asOurs(dir: ?*c.DIR) ?*DirStream {
    const raw = dir orelse return null;
    const ds: *DirStream = @ptrCast(@alignCast(raw));
    return if (ds.magic == DIR_MAGIC) ds else null;
}

export fn opendir(path: [*:0]const u8) callconv(.c) ?*c.DIR {
    if (under(path)) |rel| {
        client.lock.acquire();
        defer client.lock.release();
        return opendirRel(rel);
    }
    return next(OpendirFn, "opendir").?(path);
}

export fn readdir(dir: ?*c.DIR) callconv(.c) ?*c.struct_dirent {
    const ds = asOurs(dir) orelse return next(ReaddirFn, "readdir").?(dir);
    client.lock.acquire();
    defer client.lock.release();
    if (ds.at >= ds.len) {
        ds.len = client.readdir(ds.fid, ds.cookie, &ds.buf) catch |e| {
            _ = remote(e);
            return null;
        };
        ds.at = 0;
        if (ds.len == 0) return null; // end of directory
    }
    // One packed entry: qid[13] offset[8] type[1] name[s], per writeDirent.
    var r = p9.Reader{ .buf = ds.buf[0..ds.len], .at = ds.at };
    const qid = p9.Qid.read(&r) catch return null;
    const offset = r.u64v() catch return null;
    const dtype = r.u8v() catch return null;
    const name = r.str() catch return null;
    ds.at = r.at;
    ds.cookie = offset;

    const z: *[@sizeOf(c.struct_dirent)]u8 = @ptrCast(&ds.ent);
    @memset(z, 0);
    ds.ent.d_ino = qid.path;
    ds.ent.d_off = @intCast(offset);
    ds.ent.d_reclen = @sizeOf(c.struct_dirent);
    ds.ent.d_type = dtype;
    const room = ds.ent.d_name.len - 1;
    const n = if (name.len > room) room else name.len;
    @memcpy(ds.ent.d_name[0..n], name[0..n]);
    ds.ent.d_name[n] = 0;
    return &ds.ent;
}

export fn readdir64(dir: ?*c.DIR) callconv(.c) ?*c.struct_dirent {
    return readdir(dir);
}

export fn closedir(dir: ?*c.DIR) callconv(.c) c_int {
    const ds = asOurs(dir) orelse return next(ClosedirFn, "closedir").?(dir);
    ds.magic = 0;
    // The fid belongs to the fd, so closing the fd through this shim's own
    // `close` clunks it exactly once. Clunking here as well would release a
    // fid the server may already have handed to somebody else.
    const fd = ds.fd;
    c.free(@ptrCast(ds));
    if (fd >= 0) return close(fd);
    return 0;
}

export fn rewinddir(dir: ?*c.DIR) callconv(.c) void {
    const ds = asOurs(dir) orelse return;
    ds.cookie = 0;
    ds.len = 0;
    ds.at = 0;
}

export fn dirfd(dir: ?*c.DIR) callconv(.c) c_int {
    const ds = asOurs(dir) orelse return next(DirfdFn, "dirfd").?(dir);
    return ds.fd;
}

// ---------------------------------------------------------------------------
// Interposed: stdio
//
// Measured, and the single most surprising result of this spike: `sha256sum`
// answered ENOENT on a path `cat` read fine. Its symbol table says why — it
// imports `fopen`, not `open`, and glibc's `fopen` reaches the kernel through
// an *internal* open that never crosses the PLT. A shim without an entry here
// is invisible to every stdio-based program, which is a very large share of
// them.
//
// The way out is to open the file through this shim's own `open` — which
// yields one of its placeholder fds — and hand that fd to the real `fdopen`.
// Whether that is enough depends on something not knowable from outside:
// whether glibc's `FILE` machinery reads its fd through the interposable
// `read` or through an internal one.
// ---------------------------------------------------------------------------

const FopenFn = *const fn ([*:0]const u8, [*:0]const u8) callconv(.c) ?*c.FILE;
const FdopenFn = *const fn (c_int, [*:0]const u8) callconv(.c) ?*c.FILE;

/// `"r"`, `"w+"`, `"rb"`, `"a"` … onto `O_*`. Only the modes that change which
/// syscall flags are needed; the stdio-side buffering flags are glibc's.
fn modeFlags(mode: [*:0]const u8) c_int {
    const m = cstr(mode);
    if (m.len == 0) return c.O_RDONLY;
    var plus = false;
    for (m) |ch| {
        if (ch == '+') plus = true;
    }
    return switch (m[0]) {
        'r' => if (plus) @as(c_int, c.O_RDWR) else @as(c_int, c.O_RDONLY),
        'w' => (if (plus) @as(c_int, c.O_RDWR) else @as(c_int, c.O_WRONLY)) | c.O_CREAT | c.O_TRUNC,
        'a' => (if (plus) @as(c_int, c.O_RDWR) else @as(c_int, c.O_WRONLY)) | c.O_CREAT | c.O_APPEND,
        else => c.O_RDONLY,
    };
}

/// Slurp `rel` over 9P into an anonymous in-memory file and return its fd.
///
/// This exists because of a measured failure, and the failure is worth keeping
/// written down. The obvious bridge — `open()` through this shim, then the real
/// `fdopen()` — *appears* to work: `fopen` succeeds and the program runs to
/// completion. It is also silently wrong. The fd this shim hands out is a
/// placeholder on `/dev/null`, glibc's `FILE` machinery reads it through an
/// internal read that never reaches this file's `read`, and the program gets a
/// clean EOF. `sha256sum` on a 3 MiB file returned the hash of the empty
/// string, exit status 0. Verified with `strace`: one `openat("/dev/null")`,
/// and the reads that followed went there.
///
/// A silent wrong answer is worse than the `ENOENT` it replaced, so the
/// placeholder is not good enough here: the fd stdio reads has to genuinely
/// hold the bytes. `memfd_create` is the cheapest fd that can.
///
/// The cost is exactly what it looks like: the whole file is copied into
/// memory at `fopen` time, so this is fine for a config file and wrong for a
/// large one, there is no laziness, and nothing is written back. Write modes
/// are therefore refused below rather than being served wrongly.
fn slurpToMemfd(rel: []const u8) c_int {
    const fid = client.walk(rel, null) catch |e| return remote(e);
    defer client.clunk(fid);
    _ = client.lopen(fid, c.O_RDONLY) catch |e| return remote(e);
    const mem = p9.syscall3(p9.SYS_memfd_create, @intFromPtr("mountx"), 0, 0);
    if (mem < 0) {
        setErrno(c.ENOMEM);
        return -1;
    }
    const fd: c_int = @intCast(mem);
    var buf: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const n = client.read(fid, offset, &buf) catch |e| {
            _ = next(CloseFn, "close").?(fd);
            return remote(e);
        };
        if (n == 0) break;
        var written: usize = 0;
        while (written < n) {
            const w = p9.syscall3(p9.SYS_write, @intCast(fd), @intFromPtr(&buf) + written, n - written);
            if (w <= 0) {
                _ = next(CloseFn, "close").?(fd);
                setErrno(c.EIO);
                return -1;
            }
            written += @intCast(w);
        }
        offset += n;
    }
    _ = p9.syscall3(p9.SYS_lseek, @intCast(fd), 0, 0); // SEEK_SET
    return fd;
}

export fn fopen(path: [*:0]const u8, mode: [*:0]const u8) callconv(.c) ?*c.FILE {
    if (under(path)) |rel| {
        const flags = modeFlags(mode);
        if ((flags & (c.O_WRONLY | c.O_RDWR)) != 0) {
            // A write-mode stdio stream would need write-back on `fclose`, and
            // there is no hook for it that does not mean owning `FILE` outright.
            // Refusing is the honest answer; serving it would lose the writes.
            setErrno(c.EACCES);
            return null;
        }
        client.lock.acquire();
        const fd = slurpToMemfd(rel);
        client.lock.release();
        if (fd < 0) return null;
        return next(FdopenFn, "fdopen").?(fd, mode);
    }
    return next(FopenFn, "fopen").?(path, mode);
}

export fn fopen64(path: [*:0]const u8, mode: [*:0]const u8) callconv(.c) ?*c.FILE {
    return fopen(path, mode);
}

// ---------------------------------------------------------------------------
// Interposed: extended attributes
//
// Not for functionality — the driver interface has no xattr surface — but so
// that a query about a path this shim owns is answered by this shim. Without
// these, `ls -l` asks the *real* filesystem about `/mountx/...`, gets ENOENT
// where it expected ENODATA, and prints every mode string with a trailing `?`
// as if it could not determine the file's security context. Witnessed.
// ---------------------------------------------------------------------------

const GetxattrFn = *const fn ([*:0]const u8, [*:0]const u8, ?*anyopaque, usize) callconv(.c) isize;
const ListxattrFn = *const fn ([*:0]const u8, ?[*]u8, usize) callconv(.c) isize;

export fn getxattr(path: [*:0]const u8, name: [*:0]const u8, value: ?*anyopaque, size: usize) callconv(.c) isize {
    if (under(path) != null) {
        setErrno(c.ENODATA);
        return -1;
    }
    return next(GetxattrFn, "getxattr").?(path, name, value, size);
}

export fn lgetxattr(path: [*:0]const u8, name: [*:0]const u8, value: ?*anyopaque, size: usize) callconv(.c) isize {
    if (under(path) != null) {
        setErrno(c.ENODATA);
        return -1;
    }
    return next(GetxattrFn, "lgetxattr").?(path, name, value, size);
}

export fn listxattr(path: [*:0]const u8, list: ?[*]u8, size: usize) callconv(.c) isize {
    if (under(path) != null) return 0;
    return next(ListxattrFn, "listxattr").?(path, list, size);
}

export fn llistxattr(path: [*:0]const u8, list: ?[*]u8, size: usize) callconv(.c) isize {
    if (under(path) != null) return 0;
    return next(ListxattrFn, "llistxattr").?(path, list, size);
}

// ---------------------------------------------------------------------------
// Interposed: the _FORTIFY_SOURCE read family
//
// The third instance of the same lesson, and the one that finally makes the
// pattern obvious. `tail -2` exited 0 and printed nothing: its symbol table
// imports `__read_chk`, not `read`. A program built with `-D_FORTIFY_SOURCE=2`
// — which is the default on Debian, Fedora and Ubuntu — lands on the checked
// variant of every function whose destination buffer size the compiler knows.
//
// So the surface this approach has to cover is not "the POSIX names". It is
// the POSIX names crossed with three independent axes: the `64` suffix (large
// file support), the `__*_chk` suffix (fortification), and the legacy
// `__xstat`-style versioned symbols — with which one a program lands on
// decided by the glibc it was *compiled* against.
// ---------------------------------------------------------------------------

export fn __read_chk(fd: c_int, buf: ?*anyopaque, count: usize, buflen: usize) callconv(.c) isize {
    if (count > buflen) {
        // What the fortified variant exists to do. Not our call to soften.
        setErrno(c.EINVAL);
        return -1;
    }
    return read(fd, buf, count);
}

export fn __pread_chk(fd: c_int, buf: ?*anyopaque, count: usize, off: i64, buflen: usize) callconv(.c) isize {
    if (count > buflen) {
        setErrno(c.EINVAL);
        return -1;
    }
    return pread(fd, buf, count, off);
}

export fn __pread64_chk(fd: c_int, buf: ?*anyopaque, count: usize, off: i64, buflen: usize) callconv(.c) isize {
    return __pread_chk(fd, buf, count, off, buflen);
}

// ---------------------------------------------------------------------------
// Interposed: fdopendir
//
// The symbol `find` died on. It opens a directory with `openat`, gets one of
// this shim's fds, and hands it to `fdopendir` — which, uninterposed, is
// glibc's, looks at a placeholder pointing at `/dev/null`, and answers
// ENOTDIR. "find: '/mountx': Not a directory", witnessed.
//
// The fd already carries the path that produced it, so this is a fresh walk
// rather than a fid handed between two owners. The stream takes over the fd:
// `closedir` owns it from here, which is what the contract says.
// ---------------------------------------------------------------------------

const FdopendirFn = *const fn (c_int) callconv(.c) ?*c.DIR;

export fn fdopendir(fd: c_int) callconv(.c) ?*c.DIR {
    const e = slot(fd) orelse return next(FdopendirFn, "fdopendir").?(fd);
    if (!e.is_dir) {
        setErrno(c.ENOTDIR);
        return null;
    }
    // `fdopendir` transfers ownership of `fd` to the stream, and the fd is
    // already registered with its fid and path — so the stream is built
    // directly on it rather than opening the same directory a second time.
    const raw = c.malloc(@sizeOf(DirStream)) orelse {
        setErrno(c.ENOMEM);
        return null;
    };
    const ds: *DirStream = @ptrCast(@alignCast(raw));
    ds.magic = DIR_MAGIC;
    ds.fid = e.fid;
    ds.fd = fd;
    ds.cookie = 0;
    ds.len = 0;
    ds.at = 0;
    return @ptrCast(raw);
}

// ---------------------------------------------------------------------------
// Interposed: fd duplication
//
// The last symbol family this spike needed, and the least obvious one. `du -a`
// and `find` listed a directory correctly and then answered ENOTDIR for every
// entry in it. The syscall trace explains it in one line:
//
//     openat(AT_FDCWD, "/tmp/mxreal", ...|O_DIRECTORY) = 3
//     getdents64(3, ...)
//     newfstatat(4, "hello.txt", ...)      <-- fd 4, not fd 3
//
// `fts` duplicates the directory fd before walking it. The duplicate is a real
// `dup` of this shim's `/dev/null` placeholder, so the table knew nothing
// about fd 4 and every relative call against it fell through to the real
// filesystem.
//
// **This is a semantic divergence, not just a fix.** POSIX says a duplicated
// fd *shares* the file offset with its original; seeking one seeks the other.
// The duplicate here gets its own fid and its own offset, because sharing
// would need refcounted fids and a shared offset cell. For a directory walk —
// the case that motivated this — nothing notices. For a program that dups a
// file fd and seeks on both, this is wrong, and it is the kind of wrong that
// shows up as data at the wrong offset rather than as an error.
// ---------------------------------------------------------------------------

const DupFn = *const fn (c_int) callconv(.c) c_int;
const Dup2Fn = *const fn (c_int, c_int) callconv(.c) c_int;
const Dup3Fn = *const fn (c_int, c_int, c_int) callconv(.c) c_int;
const FcntlFn = *const fn (c_int, c_int, usize) callconv(.c) c_int;

/// Give `newfd` its own fid for whatever `oldfd` names.
fn adoptDup(oldfd: c_int, newfd: c_int) void {
    const src = slot(oldfd) orelse return;
    if (newfd < 0 or newfd >= MAX_FD) return;
    client.lock.acquire();
    defer client.lock.release();
    const rel = entryPath(src);
    var qid: p9.Qid = undefined;
    const fid = client.walk(rel, &qid) catch return;
    _ = client.lopen(fid, c.O_RDONLY) catch {
        client.clunk(fid);
        return;
    };
    table[@intCast(newfd)] = .{
        .used = true,
        .is_dir = src.is_dir,
        .fid = fid,
        .offset = src.offset,
    };
    setPath(&table[@intCast(newfd)], rel);
}

export fn dup(oldfd: c_int) callconv(.c) c_int {
    const newfd = next(DupFn, "dup").?(oldfd);
    if (newfd >= 0) adoptDup(oldfd, newfd);
    return newfd;
}

export fn dup2(oldfd: c_int, newfd: c_int) callconv(.c) c_int {
    // The target may already be one of ours; releasing it first keeps the fid
    // table from leaking an entry nothing can reach any more.
    if (slot(newfd)) |e| {
        client.lock.acquire();
        client.clunk(e.fid);
        e.* = .{};
        client.lock.release();
    }
    const got = next(Dup2Fn, "dup2").?(oldfd, newfd);
    if (got >= 0) adoptDup(oldfd, got);
    return got;
}

export fn dup3(oldfd: c_int, newfd: c_int, flags: c_int) callconv(.c) c_int {
    if (slot(newfd)) |e| {
        client.lock.acquire();
        client.clunk(e.fid);
        e.* = .{};
        client.lock.release();
    }
    const got = next(Dup3Fn, "dup3").?(oldfd, newfd, flags);
    if (got >= 0) adoptDup(oldfd, got);
    return got;
}

/// `F_DUPFD`/`F_DUPFD_CLOEXEC` are `dup` wearing a different name, and `fts`
/// uses them. Declared with a fixed third argument rather than as a true
/// variadic: on the SysV x86-64 ABI the extra argument arrives in a register
/// either way, and every `fcntl` command takes at most one.
export fn fcntl(fd: c_int, cmd: c_int, arg: usize) callconv(.c) c_int {
    const got = next(FcntlFn, "fcntl").?(fd, cmd, arg);
    if (got >= 0 and (cmd == c.F_DUPFD or cmd == c.F_DUPFD_CLOEXEC)) adoptDup(fd, got);
    return got;
}

export fn fcntl64(fd: c_int, cmd: c_int, arg: usize) callconv(.c) c_int {
    return fcntl(fd, cmd, arg);
}
