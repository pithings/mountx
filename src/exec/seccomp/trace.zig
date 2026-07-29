//! `mountx-trace` — a seccomp user-notification supervisor over 9P.
//!
//! A BPF filter selects the filesystem syscalls and answers
//! `SECCOMP_RET_USER_NOTIF` for them; every other syscall the traced process
//! makes runs at full native speed, never leaving the kernel. This process
//! reads each trapped call off a listener fd, answers it out of a 9P client
//! against an unmodified `createP9Server()`, and sends the result back.
//!
//! Usage: `mountx-trace <9p-socket> <root-prefix> -- <command> [args...]`
//!
//! **Why this mechanism.** The boundary is the syscall ABI, not glibc's
//! exported symbols, so it does not care what the traced program is linked
//! against or whether it is linked at all: a static musl binary and a
//! no-libc raw-syscall binary are indistinguishable from `cat` here. And the
//! surface is *closed* — a finite set fixed by the kernel ABI, rather than one
//! that grows with each libc release.
//!
//! **What it is not.** There is no filesystem in this file. Every path
//! question — resolution, handle lifetimes, directory paging, error mapping —
//! is answered on the far side of the socket by `src/9p/session.ts`, which
//! already passes a conformance column. This is a wire adapter with a
//! descriptor table.
//!
//! ### The three things this owes the tracee
//!
//! 1. **Exactly one reply per notification.** Every handler returns a
//!    {@link Reply} and the loop sends it; no handler talks to the listener
//!    itself, so "answered twice" and "never answered" are both unrepresentable
//!    rather than merely avoided. A thrown 9P error becomes the errno the
//!    server put in its `Rlerror`, and anything else becomes `EIO`.
//! 2. **No silent success.** The spike answered `openat` by slurping the file
//!    into a `memfd` and injecting it, which made `write` land in a private
//!    copy that was then discarded — `dd conv=notrunc` reported success and
//!    changed nothing. Nothing here is backed by a `memfd`'s contents: the
//!    injected descriptor is an *empty* placeholder whose only job is to be a
//!    number the kernel agrees exists, and `read`/`write`/`lseek` against it
//!    are trapped and answered from the driver. Any operation on it that this
//!    supervisor does not implement fails loudly against an empty file rather
//!    than quietly succeeding against a stale one.
//! 3. **TOCTOU discipline.** `SECCOMP_IOCTL_NOTIF_ID_VALID` is checked *after*
//!    reading tracee memory and before acting on it, because a dead tracee's
//!    pid can be reused between the notification and the read.
//!
//! ### Known gaps, stated rather than hidden
//!
//! - **`mmap` of a file on the tree is refused with `ENODEV`.** The spike got
//!   working `mmap` for free because the injected descriptor really was a
//!   `memfd` holding the file; without the copy there is nothing for the kernel
//!   to map, and a `MAP_SHARED` mapping would have no way back to the driver.
//!   Refusing is the honest answer — a mapping of an empty placeholder would
//!   read as zeroes and write into nothing.
//! - **`execve` of a binary living on the tree does not work** and is not
//!   attempted: the kernel resolves the ELF itself, with no notification. It
//!   fails with `ENOENT` from the real filesystem, which is loud.
//! - **`sendfile`, `splice`, `copy_file_range` and `fallocate`** are refused on
//!   a virtual descriptor, with the errno that makes callers fall back to
//!   `read`/`write` rather than one that makes them give up.
//! - **An absolute symlink target is resolved against the virtual root**, not
//!   against the host's. The tree behaves like a chroot for its own links.
//! - **Extended attributes answer `ENOTSUP`**, which is what the 9P transport
//!   answers for `Txattrwalk` anyway.
//! - **A relative `execve` under a virtual working directory** resolves against
//!   the real one, because `chdir` into the tree is answered without the kernel
//!   ever changing this process's idea of where it is.

const std = @import("std");
const p9 = @import("p9");
const linux = @import("linux.zig");
const notify = @import("notify.zig");
const state = @import("state.zig");

const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("unistd.h");
    @cInclude("errno.h");
    @cInclude("stdlib.h");
    @cInclude("fcntl.h");
    @cInclude("sys/wait.h");
});

const SYS = linux.SYS;

/// The trapped set.
///
/// Read it as three groups. The **path** calls are here because they name
/// something that may live on the tree. The **descriptor** calls are here
/// because the descriptor this supervisor hands out is an empty placeholder —
/// leaving `read` untrapped would answer zero bytes and call it success, which
/// is the exact failure mode this file exists to remove. And `close` is here
/// because descriptor numbers are reused immediately, so a mapping that outlives
/// its descriptor shadows a live one.
///
/// `close` is the one that was impossible in the spike: the supervisor shared
/// its filter with the tracee and would have suspended itself. See `notify.zig`.
const TRAPPED = [_]u32{
    // descriptors
    SYS.read,      SYS.write,        SYS.close,           SYS.lseek,
    SYS.pread64,   SYS.pwrite64,     SYS.readv,           SYS.writev,
    SYS.preadv,    SYS.pwritev,      SYS.preadv2,         SYS.pwritev2,
    SYS.mmap,      SYS.getdents64,   SYS.fstat,           SYS.fsync,
    SYS.fdatasync, SYS.ftruncate,    SYS.fchmod,          SYS.fchown,
    SYS.fstatfs,   SYS.sendfile,     SYS.copy_file_range, SYS.splice,
    SYS.fallocate,  SYS.dup2,         SYS.dup3,            SYS.close_range,
    // opening
     SYS.open,         SYS.openat,          SYS.openat2,
    SYS.creat,
    // metadata by path
     SYS.stat,         SYS.lstat,           SYS.newfstatat,
    SYS.statx,     SYS.access,       SYS.faccessat,       SYS.faccessat2,
    SYS.statfs,    SYS.truncate,     SYS.chmod,           SYS.fchmodat,
    SYS.chown,     SYS.lchown,       SYS.fchownat,        SYS.utime,
    SYS.utimes,    SYS.futimesat,    SYS.utimensat,
    // the namespace
      SYS.mkdir,
    SYS.mkdirat,   SYS.rmdir,        SYS.unlink,          SYS.unlinkat,
    SYS.rename,    SYS.renameat,     SYS.renameat2,       SYS.link,
    SYS.linkat,    SYS.symlink,      SYS.symlinkat,       SYS.readlink,
    SYS.readlinkat, SYS.mknod,       SYS.mknodat,
    // where a process thinks it is
     SYS.getcwd,
    SYS.chdir,     SYS.fchdir,
    // extended attributes, refused rather than left to the real filesystem
     SYS.setxattr,     SYS.lsetxattr,
    SYS.fsetxattr, SYS.getxattr,     SYS.lgetxattr,       SYS.fgetxattr,
    SYS.listxattr, SYS.llistxattr,   SYS.flistxattr,      SYS.removexattr,
    SYS.lremovexattr, SYS.fremovexattr,
    // lifecycle
    SYS.exit_group,
};

/// The made-up device every file here reports, as a minor number with major 0.
///
/// Deliberately under 256 so `makedev(0, n) == n`. `statx` reports a
/// major/minor *pair* that glibc recomposes with `makedev()`, and a raw
/// `st_dev` of 0x6d78 against major 0 / minor 0x6d78 recomposes to 0x6d00078 —
/// so `stat` and `statx` disagreed, and `cp` refused with "skipping file … as it
/// was replaced while being copied". Keeping the minor inside 8 bits makes the
/// two forms agree by construction.
const FAKE_DEV_MINOR: u64 = 0x78;

/// How many links a resolution may traverse before it is a loop.
const MAX_SYMLINKS: u32 = 40;

var client: p9.Client = .{};
var root: []const u8 = &.{};
var tables: state.Tables = undefined;
var debug = false;
var self_uid: u32 = 0;
var self_gid: u32 = 0;

/// Scratch for file payloads. One notification is in flight at a time, so one
/// buffer is enough; see the concurrency note in `main`.
var scratch: [1 << 20]u8 = undefined;
var pathbuf: [4096]u8 = undefined;
var joinbuf: [4096]u8 = undefined;
var auxbuf: [4096]u8 = undefined;

fn dbg(comptime fmt: []const u8, args: anytype) void {
    if (!debug) return;
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "[trace] " ++ fmt ++ "\n", args) catch return;
    _ = c.write(2, msg.ptr, msg.len);
}

fn die(comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "mountx-trace: " ++ fmt ++ "\n", args) catch "mountx-trace: error\n";
    _ = c.write(2, msg.ptr, msg.len);
    c.exit(70);
}

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

/// What a handler decided. The loop turns exactly one of these into exactly one
/// message on the listener.
const Reply = union(enum) {
    /// The syscall succeeded with this return value.
    ret: i64,
    /// The syscall failed with this (positive) errno.
    err: i32,
    /// Not ours: let the kernel run it as it stands.
    cont: void,
    /// The notification is no longer valid — the tracee died under us. Nothing
    /// may be sent, and nothing needs to be.
    gone: void,
};

const ok: Reply = .{ .ret = 0 };

fn fail(errno: i32) Reply {
    return .{ .err = errno };
}

/// A 9P failure, as the errno the server put in its `Rlerror`.
///
/// 9P is the one transport in this repository with no status-mapping layer: the
/// number in an `Rlerror` is a positive Linux errno straight from
/// `src/errors.ts`, which is exactly what the tracee's `errno` wants. Anything
/// that is not a server error — a desynced stream, a dead socket — is `EIO`,
/// because there is no honest way to blame it on the file.
fn remote(err: p9.Error) Reply {
    return switch (err) {
        p9.Error.Remote => fail(if (client.last_errno > 0) client.last_errno else linux.EIO),
        else => fail(linux.EIO),
    };
}

// ---------------------------------------------------------------------------
// Which process is asking
// ---------------------------------------------------------------------------

const TgidEntry = struct { tid: i32, tgid: i32 };
var tgids: std.ArrayList(TgidEntry) = .empty;
var gpa: std.mem.Allocator = undefined;

/// The thread group a notification's thread belongs to.
///
/// `seccomp_notif.pid` is a *thread* id. Descriptors, the working directory and
/// the umask all belong to the thread group, so every table here is keyed on
/// the tgid — otherwise a second thread in the same process would find none of
/// the first one's descriptors. The mapping never changes for a given tid, so
/// it is cached; the first sight of a process is also where it inherits its
/// parent's virtual working directory, the way `fork` does.
fn tgidOf(tid: i32) i32 {
    for (tgids.items) |entry| {
        if (entry.tid == tid) return entry.tgid;
    }
    const info = notify.procInfo(tid) orelse return tid;
    tgids.append(gpa, .{ .tid = tid, .tgid = info.tgid }) catch {};
    _ = tables.inheritCwd(info.tgid, info.ppid) catch {};
    return info.tgid;
}

/// The tracee's umask, read fresh: it is process state that changes under us,
/// and applying the wrong one silently creates a file with the wrong mode.
fn umaskOf(tid: i32) u32 {
    const info = notify.procInfo(tid) orelse return 0;
    return info.umask;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// The part of an absolute path below the root prefix, or null.
fn under(path: []const u8) ?[]const u8 {
    if (path.len < root.len) return null;
    if (!std.mem.eql(u8, path[0..root.len], root)) return null;
    if (path.len == root.len) return path[path.len..];
    if (path[root.len] != '/') return null;
    return path[root.len..];
}

/// Where a path argument points.
const Target = union(enum) {
    /// A normalized path under the root, without a leading slash.
    inside: []const u8,
    /// Not ours; the kernel should run the syscall unchanged.
    outside: void,
    /// Ours, and already wrong.
    err: i32,
};

/// Resolve a path argument the way the kernel would: absolute against the root,
/// relative against a directory descriptor or the working directory.
///
/// The `*at()` branch is not an optimization — every tree walker resolves each
/// level against the parent's descriptor rather than by name, and without it
/// `find` and `du` report "Not a directory" for every entry of a directory they
/// have just listed.
///
/// When the process has a *virtual* working directory, a relative path is
/// resolved inside the tree and never falls through to the host: the real
/// working directory was deliberately left where it was (see `handleChdir`), so
/// letting the kernel resolve it would silently mean a different place.
fn resolveAt(pid: i32, dirfd: i32, raw: []const u8, out: []u8) Target {
    if (raw.len > 0 and raw[0] == '/') {
        const rel = under(raw) orelse return .outside;
        const norm = state.normalize(out, &.{rel}) orelse return .{ .err = linux.ENAMETOOLONG };
        return .{ .inside = norm };
    }
    if (dirfd == linux.AT_FDCWD) {
        const base = tables.cwd(pid) orelse return .outside;
        const norm = state.normalize(out, &.{ base, raw }) orelse
            return .{ .err = linux.ENAMETOOLONG };
        return .{ .inside = norm };
    }
    const index = lookupFd(pid, dirfd) orelse return .outside;
    const entry = tables.file(index);
    if (!entry.is_dir) return .{ .err = linux.ENOTDIR };
    const norm = state.normalize(out, &.{ entry.path, raw }) orelse
        return .{ .err = linux.ENAMETOOLONG };
    return .{ .inside = norm };
}

/// `(pid, fd)` → an open file description, following duplicates through
/// `/proc`. See `state.zig` for why identity comes from the object.
fn lookupFd(pid: i32, fd: i32) ?u32 {
    if (tables.lookup(pid, fd, null)) |index| return index;
    if (fd < 0) return null;
    var link: [256]u8 = undefined;
    const seen = notify.fdLink(pid, fd, &link) orelse return null;
    return tables.lookup(pid, fd, seen);
}

// ---------------------------------------------------------------------------
// Walking
// ---------------------------------------------------------------------------

const Walked = struct { fid: u32, qid: p9.Qid };

/// Resolve `path` to a fid, one component at a time, following symlinks here
/// rather than on the server.
///
/// That split is the protocol's: `Twalk` reports a `P9_QTSYMLINK` qid and stops
/// there, because a server that resolved links itself would have no way to
/// answer `lstat`. So the resolution — `Treadlink`, re-root, re-walk, and the
/// loop bound — happens on this side, exactly as the VFS does it above v9fs and
/// exactly as `test/9p/client.ts` does it for the conformance column.
///
/// The walk proceeds *in place* (`newfid == fid`), so a path of any depth costs
/// one fid rather than one per component.
fn walkTo(path: []const u8, follow: bool, depth: u32) p9.Error!Walked {
    if (depth > MAX_SYMLINKS) {
        client.last_errno = linux.ELOOP;
        return p9.Error.Remote;
    }
    var parts: [256][]const u8 = undefined;
    var count: usize = 0;
    var it = state.Split{ .s = path };
    while (it.next()) |name| {
        if (count == parts.len) {
            client.last_errno = linux.ENAMETOOLONG;
            return p9.Error.Remote;
        }
        parts[count] = name;
        count += 1;
    }

    const fid = client.allocFid();
    errdefer client.clunk(fid);
    try client.walkOnce(client.root_fid, fid, "", null, null);
    var qid: p9.Qid = .{ .qtype = p9.P9_QTDIR, .version = 0, .path = 0 };
    if (count == 0) {
        if (client.getattr(fid)) |attr| {
            qid = attr.qid;
        } else |err| return err;
        return .{ .fid = fid, .qid = qid };
    }

    // The components consumed so far, which is the directory a relative link
    // target is resolved against.
    var sofar: [4096]u8 = undefined;
    var sofar_len: usize = 0;
    for (parts[0..count], 0..) |name, index| {
        const before = sofar_len;
        try client.walkOnce(fid, fid, name, &qid, null);
        const last = index + 1 == count;
        if ((qid.qtype & p9.P9_QTSYMLINK) != 0 and (follow or !last)) {
            var target: [4096]u8 = undefined;
            const link = try client.readlink(fid, &target);
            client.clunk(fid);
            // An absolute target is resolved against the *virtual* root: the
            // tree is its own namespace here, and a link out of it has nowhere
            // to land, since this supervisor cannot hand the kernel a different
            // path than the one it was asked about.
            const base: []const u8 = if (link.len > 0 and link[0] == '/') "" else sofar[0..before];
            var rest: [4096]u8 = undefined;
            var rest_len: usize = 0;
            for (parts[index + 1 .. count]) |tail| {
                if (rest_len != 0) {
                    rest[rest_len] = '/';
                    rest_len += 1;
                }
                if (rest_len + tail.len > rest.len) {
                    client.last_errno = linux.ENAMETOOLONG;
                    return p9.Error.Remote;
                }
                @memcpy(rest[rest_len .. rest_len + tail.len], tail);
                rest_len += tail.len;
            }
            var next: [4096]u8 = undefined;
            const joined = state.normalize(&next, &.{ base, link, rest[0..rest_len] }) orelse {
                client.last_errno = linux.ENAMETOOLONG;
                return p9.Error.Remote;
            };
            return walkTo(joined, follow, depth + 1);
        }
        if (sofar_len != 0) {
            sofar[sofar_len] = '/';
            sofar_len += 1;
        }
        @memcpy(sofar[sofar_len .. sofar_len + name.len], name);
        sofar_len += name.len;
    }
    return .{ .fid = fid, .qid = qid };
}

/// The parent directory of `path` as a fid, plus the final name.
const Parented = struct { fid: u32, name: []const u8 };

fn parentOf(path: []const u8, out: []u8) p9.Error!Parented {
    const split = state.splitParent(path) orelse {
        // The root has no parent, so nothing can be created or removed at it.
        client.last_errno = linux.EBUSY;
        return p9.Error.Remote;
    };
    const walked = try walkTo(split[0], true, 0);
    if ((walked.qid.qtype & p9.P9_QTDIR) == 0) {
        client.clunk(walked.fid);
        client.last_errno = linux.ENOTDIR;
        return p9.Error.Remote;
    }
    if (split[1].len > out.len) {
        client.clunk(walked.fid);
        client.last_errno = linux.ENAMETOOLONG;
        return p9.Error.Remote;
    }
    @memcpy(out[0..split[1].len], split[1]);
    return .{ .fid = walked.fid, .name = out[0..split[1].len] };
}

// ---------------------------------------------------------------------------
// Open file descriptions
// ---------------------------------------------------------------------------

/// Make sure a file's 9P fid is live, re-opening it if a `close` released it.
///
/// A file description can outlive the last descriptor this supervisor *knows*
/// about: a shell opens a file, forks, the child `dup2`s it onto stdin and the
/// parent closes its copy, and the child's first read arrives against a
/// descriptor number nothing has bound yet. Rather than answer that from an
/// empty placeholder — which is the silent-wrong-answer failure this whole file
/// exists to remove — the description remembers its path, its access mode and
/// its offset, and is re-opened on demand. `O_TRUNC` and `O_CREAT` are
/// deliberately not part of what is remembered, for the reason
/// `src/fuse/flags.ts`'s `reopenFlags()` gives: repeating them on a re-open
/// empties the file or fails outright.
fn ensureOpen(index: u32) ?i32 {
    const entry = tables.file(index);
    if (entry.open) return null;
    const walked = walkTo(entry.path, true, 0) catch |err| {
        return if (err == p9.Error.Remote and client.last_errno > 0) client.last_errno else linux.EBADF;
    };
    _ = client.lopen(walked.fid, if (entry.is_dir) 0 else entry.flags & linux.O_ACCMODE) catch |err| {
        client.clunk(walked.fid);
        return if (err == p9.Error.Remote and client.last_errno > 0) client.last_errno else linux.EBADF;
    };
    entry.fid = walked.fid;
    entry.open = true;
    return null;
}

/// Let a file description go once nothing names it any more.
///
/// The 9P fid — the driver's actual open handle — is released here; the record
/// itself is kept, because a descriptor this supervisor never saw bound may
/// still resolve to it through `/proc` and need it re-opened. That is a bounded
/// amount of memory per distinct open, traded for never answering a live
/// descriptor from a dead one.
fn release(index: u32) void {
    const entry = tables.file(index);
    if (entry.refs != 0) return;
    if (entry.open) {
        client.clunk(entry.fid);
        entry.open = false;
    }
}

/// A placeholder descriptor for the tracee: a `memfd` with a unique name.
///
/// It holds nothing and is never read from. Its two jobs are to be a number the
/// kernel agrees exists — so `close`, `dup`, `fcntl` and `poll` behave — and to
/// carry an identity through `/proc/<pid>/fd/<n>` that survives `dup`, `fork`
/// and `exec`, which is how a duplicate is recognized without trapping `dup`.
///
/// It is a `memfd` and **not** an `open("/dev/null")`: in the spike, where the
/// supervisor shared its filter with the tracee, `open` was trapped and calling
/// it here suspended the supervisor waiting for a reply only it could send. The
/// supervisor carries no filter now, but the `memfd` stays for its identity.
fn placeholder(serial: u32) i32 {
    var namebuf: [32]u8 = undefined;
    const name = std.fmt.bufPrintZ(&namebuf, "mx-{d}", .{serial}) catch return -1;
    const rc = p9.syscall3(p9.SYS_memfd_create, @intFromPtr(name.ptr), 0, 0);
    if (rc < 0) return -1;
    return @intCast(rc);
}

/// Bind a freshly opened description to a descriptor in the tracee.
fn install(id: u64, pid: i32, index: u32) Reply {
    const entry = tables.file(index);
    const fd = placeholder(entry.serial);
    if (fd < 0) return fail(linux.EMFILE);
    defer _ = c.close(fd);
    const newfd = notify.addFd(id, fd);
    if (newfd < 0) return fail(linux.EIO);
    tables.bind(pid, newfd, index) catch return fail(linux.ENOMEM);
    return .{ .ret = newfd };
}

// ---------------------------------------------------------------------------
// stat
// ---------------------------------------------------------------------------

fn fillStat(a: p9.Attr) linux.Stat {
    var st = std.mem.zeroes(linux.Stat);
    st.st_dev = FAKE_DEV_MINOR;
    st.st_ino = a.qid.path;
    st.st_nlink = a.nlink;
    st.st_mode = a.mode;
    st.st_uid = a.uid;
    st.st_gid = a.gid;
    st.st_rdev = a.rdev;
    st.st_size = @intCast(a.size);
    st.st_blksize = @intCast(a.blksize);
    st.st_blocks = @intCast(a.blocks);
    st.st_atime = a.atime_sec;
    st.st_atime_nsec = a.atime_nsec;
    st.st_mtime = a.mtime_sec;
    st.st_mtime_nsec = a.mtime_nsec;
    st.st_ctime = a.ctime_sec;
    st.st_ctime_nsec = a.ctime_nsec;
    return st;
}

fn writeStat(id: u64, pid: i32, remote_addr: u64, a: p9.Attr) Reply {
    const st = fillStat(a);
    const bytes: [*]const u8 = @ptrCast(&st);
    if (!notify.stillValid(id)) return .gone;
    if (!notify.writeTracee(pid, remote_addr, bytes[0..@sizeOf(linux.Stat)])) {
        return fail(linux.EFAULT);
    }
    return ok;
}

fn writeStatx(id: u64, pid: i32, remote_addr: u64, a: p9.Attr) Reply {
    var stx = std.mem.zeroes(linux.Statx);
    stx.stx_mask = linux.STATX_BASIC_STATS;
    stx.stx_blksize = @intCast(a.blksize);
    stx.stx_nlink = @intCast(a.nlink);
    stx.stx_uid = a.uid;
    stx.stx_gid = a.gid;
    stx.stx_mode = @intCast(a.mode);
    stx.stx_ino = a.qid.path;
    stx.stx_size = a.size;
    stx.stx_blocks = a.blocks;
    stx.stx_dev_minor = FAKE_DEV_MINOR;
    stx.stx_dev_major = 0;
    stx.stx_atime = .{ .sec = @intCast(a.atime_sec), .nsec = @intCast(a.atime_nsec), .__pad = 0 };
    stx.stx_mtime = .{ .sec = @intCast(a.mtime_sec), .nsec = @intCast(a.mtime_nsec), .__pad = 0 };
    stx.stx_ctime = .{ .sec = @intCast(a.ctime_sec), .nsec = @intCast(a.ctime_nsec), .__pad = 0 };
    const bytes: [*]const u8 = @ptrCast(&stx);
    if (!notify.stillValid(id)) return .gone;
    if (!notify.writeTracee(pid, remote_addr, bytes[0..@sizeOf(linux.Statx)])) {
        return fail(linux.EFAULT);
    }
    return ok;
}

// ---------------------------------------------------------------------------
// One notification, unpacked
// ---------------------------------------------------------------------------

/// A notification with the two identities it carries kept apart: `tid` is the
/// thread whose memory is read, `pid` is the thread group whose descriptors and
/// working directory are consulted.
const Call = struct {
    id: u64,
    tid: i32,
    pid: i32,
    args: [6]u64,

    fn fd(self: *const Call, index: usize) i32 {
        return @bitCast(@as(u32, @truncate(self.args[index])));
    }

    fn word(self: *const Call, index: usize) u32 {
        return @truncate(self.args[index]);
    }

    /// A path argument, read out of the tracee and checked afterwards — never
    /// before, which is the whole point of `SECCOMP_IOCTL_NOTIF_ID_VALID`.
    fn path(self: *const Call, index: usize, into: []u8) ?[]const u8 {
        const raw = notify.readTraceePath(self.tid, self.args[index], into) orelse return null;
        if (!notify.stillValid(self.id)) return null;
        return raw;
    }
};

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

/// The flags a driver is allowed to see.
///
/// The access mode and nothing else. `O_CREAT`/`O_EXCL` are answered here by
/// `Tlcreate`; `O_TRUNC` is answered by an explicit `Tsetattr`, so a driver that
/// happens not to implement it cannot leave a `>` redirection silently
/// appending; and `O_APPEND` is resolved here too, because 9P's `Twrite` carries
/// an explicit offset and a driver that also honoured the flag would append
/// twice.
fn driverFlags(flags: u32) u32 {
    return flags & linux.O_ACCMODE;
}

fn openCommon(call: *const Call, dirfd: i32, path_index: usize, flags: u32, mode: u32) Reply {
    const raw = call.path(path_index, &pathbuf) orelse return .cont;
    const target = resolveAt(call.pid, dirfd, raw, &joinbuf);
    const rel = switch (target) {
        .outside => return .cont,
        .err => |e| return fail(e),
        .inside => |p| p,
    };
    // `O_EXCL` and `O_NOFOLLOW` both stop at the link rather than at its target,
    // which is what makes an exclusive open of a dangling symlink `EEXIST`
    // rather than a create.
    const nofollow = (flags & linux.O_NOFOLLOW) != 0 or
        ((flags & linux.O_EXCL) != 0 and (flags & linux.O_CREAT) != 0);
    const walked = walkTo(rel, !nofollow, 0) catch |err| {
        if (err != p9.Error.Remote or client.last_errno != linux.ENOENT) return remote(err);
        if ((flags & linux.O_CREAT) == 0) return remote(err);
        return create(call, rel, flags, mode);
    };
    const fid = walked.fid;
    const is_dir = (walked.qid.qtype & p9.P9_QTDIR) != 0;
    if ((flags & linux.O_CREAT) != 0 and (flags & linux.O_EXCL) != 0) {
        client.clunk(fid);
        return fail(linux.EEXIST);
    }
    if (is_dir and (flags & linux.O_ACCMODE) != linux.O_RDONLY) {
        client.clunk(fid);
        return fail(linux.EISDIR);
    }
    if (!is_dir and (flags & linux.O_DIRECTORY) != 0) {
        client.clunk(fid);
        return fail(linux.ENOTDIR);
    }
    _ = client.lopen(fid, if (is_dir) 0 else driverFlags(flags)) catch |err| {
        client.clunk(fid);
        return remote(err);
    };
    if (!is_dir and (flags & linux.O_TRUNC) != 0) {
        client.setattr(fid, p9.P9_SETATTR_SIZE, 0, 0, 0, 0, 0, 0, 0, 0) catch |err| {
            client.clunk(fid);
            return remote(err);
        };
    }
    return adopt(call, rel, fid, is_dir, flags);
}

/// The `O_CREAT` half: `Tlcreate` against the parent directory.
///
/// `Tlcreate` turns the *directory* fid it is given into the fid of the new
/// file, which is why the parent is walked onto a fid of its own and never
/// clunked separately on the success path.
fn create(call: *const Call, rel: []const u8, flags: u32, mode: u32) Reply {
    var namebuf: [256]u8 = undefined;
    const parent = parentOf(rel, &namebuf) catch |err| return remote(err);
    const masked = mode & ~umaskOf(call.tid) & 0o7777;
    _ = client.lcreate(parent.fid, parent.name, driverFlags(flags), masked) catch |err| {
        client.clunk(parent.fid);
        return remote(err);
    };
    return adopt(call, rel, parent.fid, false, flags);
}

/// Record a freshly opened fid and hand the tracee a descriptor for it.
fn adopt(call: *const Call, rel: []const u8, fid: u32, is_dir: bool, flags: u32) Reply {
    const index = tables.create(rel) catch {
        client.clunk(fid);
        return fail(linux.ENOMEM);
    };
    const entry = tables.file(index);
    entry.fid = fid;
    entry.open = true;
    entry.is_dir = is_dir;
    entry.flags = flags;
    entry.offset = 0;
    const reply = install(call.id, call.pid, index);
    switch (reply) {
        .ret => |value| {
            dbg("open {s} -> fd {d} serial {d}", .{ rel, value, entry.serial });
            return reply;
        },
        else => {
            client.clunk(fid);
            entry.open = false;
            return reply;
        },
    }
}

// ---------------------------------------------------------------------------
// Reading and writing
// ---------------------------------------------------------------------------

/// Everything a descriptor-based handler needs, or the reply that says why not.
const Held = union(enum) { file: u32, reply: Reply };

fn held(call: *const Call, fd: i32) Held {
    const index = lookupFd(call.pid, fd) orelse return .{ .reply = .cont };
    if (ensureOpen(index)) |errno| return .{ .reply = fail(errno) };
    return .{ .file = index };
}

/// One `Tread` loop into `scratch`. Short reads are honest: `read(2)` may return
/// fewer bytes than asked for, and inventing the rest would be a lie about the
/// file.
const ReadResult = union(enum) { got: usize, reply: Reply };

fn readInto(index: u32, offset: u64, want: usize) ReadResult {
    const entry = tables.file(index);
    var got: usize = 0;
    while (got < want) {
        const n = client.read(entry.fid, offset + got, scratch[got..want]) catch |err| {
            if (got == 0) return .{ .reply = remote(err) };
            break;
        };
        if (n == 0) break;
        got += n;
    }
    return .{ .got = got };
}

fn handleRead(call: *const Call, fd: i32, buf: u64, count: usize, at: ?u64) Reply {
    const index = switch (held(call, fd)) {
        .reply => |r| return r,
        .file => |i| i,
    };
    const entry = tables.file(index);
    if (entry.is_dir) return fail(linux.EISDIR);
    const offset = at orelse entry.offset;
    const want = @min(count, scratch.len);
    const got = switch (readInto(index, offset, want)) {
        .reply => |r| return r,
        .got => |n| n,
    };
    if (!notify.stillValid(call.id)) return .gone;
    if (!notify.writeTracee(call.tid, buf, scratch[0..got])) return fail(linux.EFAULT);
    if (at == null) entry.offset = offset + got;
    return .{ .ret = @intCast(got) };
}

fn handleWrite(call: *const Call, fd: i32, buf: u64, count: usize, at: ?u64) Reply {
    const index = switch (held(call, fd)) {
        .reply => |r| return r,
        .file => |i| i,
    };
    const entry = tables.file(index);
    if (entry.is_dir) return fail(linux.EBADF);
    var offset = at orelse entry.offset;
    // `O_APPEND` is resolved here rather than by the driver: `Twrite` carries an
    // explicit offset, so a driver honouring the flag as well would append the
    // payload to a position that was already the end.
    if (at == null and (entry.flags & linux.O_APPEND) != 0) {
        const attr = client.getattr(entry.fid) catch |err| return remote(err);
        offset = attr.size;
    }
    const want = @min(count, scratch.len);
    if (!notify.readTracee(call.tid, buf, scratch[0..want])) return fail(linux.EFAULT);
    if (!notify.stillValid(call.id)) return .gone;
    var done: usize = 0;
    while (done < want) {
        const n = client.write(entry.fid, offset + done, scratch[done..want]) catch |err| {
            if (done == 0) return remote(err);
            break;
        };
        if (n == 0) break;
        done += n;
    }
    if (at == null) entry.offset = offset + done;
    return .{ .ret = @intCast(done) };
}

/// `IOV_MAX`, from `include/uapi/linux/uio.h`.
const IOV_MAX = 1024;

fn readIovecs(call: *const Call, addr: u64, count: usize, into: []linux.Iovec) ?[]linux.Iovec {
    if (count > into.len) return null;
    const bytes: [*]u8 = @ptrCast(into.ptr);
    if (!notify.readTracee(call.tid, addr, bytes[0 .. count * @sizeOf(linux.Iovec)])) return null;
    return into[0..count];
}

fn handleReadv(call: *const Call, fd: i32, addr: u64, count: usize, at: ?u64) Reply {
    const index = switch (held(call, fd)) {
        .reply => |r| return r,
        .file => |i| i,
    };
    const entry = tables.file(index);
    if (entry.is_dir) return fail(linux.EISDIR);
    if (count > IOV_MAX) return fail(linux.EINVAL);
    var vectors: [IOV_MAX]linux.Iovec = undefined;
    const iov = readIovecs(call, addr, count, &vectors) orelse return fail(linux.EFAULT);
    if (!notify.stillValid(call.id)) return .gone;
    var offset = at orelse entry.offset;
    var total: usize = 0;
    for (iov) |vec| {
        const want = @min(@as(usize, @intCast(vec.len)), scratch.len);
        if (want == 0) continue;
        const got = switch (readInto(index, offset, want)) {
            .reply => |r| return if (total == 0) r else .{ .ret = @intCast(total) },
            .got => |n| n,
        };
        if (got == 0) break;
        if (!notify.writeTracee(call.tid, vec.base, scratch[0..got])) return fail(linux.EFAULT);
        total += got;
        offset += got;
        if (got < want) break;
    }
    if (at == null) entry.offset = offset;
    return .{ .ret = @intCast(total) };
}

fn handleWritev(call: *const Call, fd: i32, addr: u64, count: usize, at: ?u64) Reply {
    const index = switch (held(call, fd)) {
        .reply => |r| return r,
        .file => |i| i,
    };
    const entry = tables.file(index);
    if (entry.is_dir) return fail(linux.EBADF);
    if (count > IOV_MAX) return fail(linux.EINVAL);
    var vectors: [IOV_MAX]linux.Iovec = undefined;
    const iov = readIovecs(call, addr, count, &vectors) orelse return fail(linux.EFAULT);
    if (!notify.stillValid(call.id)) return .gone;
    var offset = at orelse entry.offset;
    if (at == null and (entry.flags & linux.O_APPEND) != 0) {
        const attr = client.getattr(entry.fid) catch |err| return remote(err);
        offset = attr.size;
    }
    var total: usize = 0;
    for (iov) |vec| {
        const want = @min(@as(usize, @intCast(vec.len)), scratch.len);
        if (want == 0) continue;
        if (!notify.readTracee(call.tid, vec.base, scratch[0..want])) return fail(linux.EFAULT);
        var done: usize = 0;
        while (done < want) {
            const n = client.write(entry.fid, offset + done, scratch[done..want]) catch |err| {
                if (total == 0 and done == 0) return remote(err);
                break;
            };
            if (n == 0) break;
            done += n;
        }
        total += done;
        offset += done;
        if (done < want) break;
    }
    if (at == null) entry.offset = offset;
    return .{ .ret = @intCast(total) };
}

fn handleLseek(call: *const Call) Reply {
    const index = switch (held(call, call.fd(0))) {
        .reply => |r| return r,
        .file => |i| i,
    };
    const entry = tables.file(index);
    const offset: i64 = @bitCast(call.args[1]);
    const whence = call.word(2);
    var target: i64 = undefined;
    switch (whence) {
        linux.SEEK_SET => target = offset,
        linux.SEEK_CUR => target = @as(i64, @intCast(entry.offset)) + offset,
        linux.SEEK_END => {
            const attr = client.getattr(entry.fid) catch |err| return remote(err);
            target = @as(i64, @intCast(attr.size)) + offset;
        },
        else => return fail(linux.EINVAL),
    }
    if (target < 0) return fail(linux.EINVAL);
    entry.offset = @intCast(target);
    // A directory's position is a `Treaddir` cookie rather than a byte offset,
    // and the only seek that means anything on one is a rewind.
    if (entry.is_dir and target == 0) entry.cookie = 0;
    return .{ .ret = target };
}

fn handleGetdents(call: *const Call) Reply {
    const index = switch (held(call, call.fd(0))) {
        .reply => |r| return r,
        .file => |i| i,
    };
    const entry = tables.file(index);
    if (!entry.is_dir) return fail(linux.ENOTDIR);
    const remote_addr = call.args[1];
    const cap: usize = @min(@as(usize, @truncate(call.args[2])), scratch.len / 2);

    var block: [32 * 1024]u8 = undefined;
    const got = client.readdir(entry.fid, entry.cookie, &block) catch |err| return remote(err);
    if (got == 0) return .{ .ret = 0 };

    var out: usize = 0;
    var reader = p9.Reader{ .buf = block[0..got] };
    while (reader.at < got) {
        const qid = p9.Qid.read(&reader) catch break;
        const offset = reader.u64v() catch break;
        const dtype = reader.u8v() catch break;
        const name = reader.str() catch break;
        const reclen = (linux.DIRENT64_HEADER + name.len + 1 + 7) & ~@as(usize, 7);
        if (out + reclen > cap) break;
        const record = scratch[out .. out + reclen];
        @memset(record, 0);
        std.mem.writeInt(u64, record[0..8], qid.path, .little);
        std.mem.writeInt(u64, record[8..16], offset, .little);
        std.mem.writeInt(u16, record[16..18], @intCast(reclen), .little);
        record[18] = dtype;
        @memcpy(record[19 .. 19 + name.len], name);
        out += reclen;
        entry.cookie = offset;
    }
    // Nothing fitted, and the caller's buffer is not big enough for the next
    // entry: `getdents64` says `EINVAL` for that rather than end-of-directory,
    // which a zero would mean.
    if (out == 0) return fail(linux.EINVAL);
    if (!notify.stillValid(call.id)) return .gone;
    if (!notify.writeTracee(call.tid, remote_addr, scratch[0..out])) return fail(linux.EFAULT);
    return .{ .ret = @intCast(out) };
}

// ---------------------------------------------------------------------------
// Metadata by path and by descriptor
// ---------------------------------------------------------------------------

/// The legacy `stat`/`lstat`, which name a path and a `struct stat` and nothing
/// else. Every fid taken here is clunked, including on the error path — a
/// leaked fid is a driver handle nothing will ever close.
fn handleStatPath(call: *const Call, dirfd: i32, path_index: usize, follow: bool, out: usize) Reply {
    const raw = call.path(path_index, &pathbuf) orelse return .cont;
    const target = resolveAt(call.pid, dirfd, raw, &joinbuf);
    const rel = switch (target) {
        .outside => return .cont,
        .err => |e| return fail(e),
        .inside => |p| p,
    };
    const walked = walkTo(rel, follow, 0) catch |err| return remote(err);
    defer client.clunk(walked.fid);
    const attr = client.getattr(walked.fid) catch |err| return remote(err);
    return writeStat(call.id, call.tid, call.args[out], attr);
}

fn handleFstat(call: *const Call) Reply {
    const index = switch (held(call, call.fd(0))) {
        .reply => |r| return r,
        .file => |i| i,
    };
    const attr = client.getattr(tables.file(index).fid) catch |err| return remote(err);
    return writeStat(call.id, call.tid, call.args[1], attr);
}

/// `newfstatat`, which is also `fstat` by another name when the path is empty
/// and `AT_EMPTY_PATH` is set — the form glibc's `fstat` actually uses.
fn handleNewfstatat(call: *const Call) Reply {
    const dirfd = call.fd(0);
    const flags = call.word(3);
    const raw = call.path(1, &pathbuf) orelse return .cont;
    if (raw.len == 0 and (flags & linux.AT_EMPTY_PATH) != 0) {
        const index = switch (held(call, dirfd)) {
            .reply => |r| return r,
            .file => |i| i,
        };
        const attr = client.getattr(tables.file(index).fid) catch |err| return remote(err);
        return writeStat(call.id, call.tid, call.args[2], attr);
    }
    const target = resolveAt(call.pid, dirfd, raw, &joinbuf);
    const rel = switch (target) {
        .outside => return .cont,
        .err => |e| return fail(e),
        .inside => |p| p,
    };
    const follow = (flags & linux.AT_SYMLINK_NOFOLLOW) == 0;
    const walked = walkTo(rel, follow, 0) catch |err| return remote(err);
    defer client.clunk(walked.fid);
    const attr = client.getattr(walked.fid) catch |err| return remote(err);
    return writeStat(call.id, call.tid, call.args[2], attr);
}

fn handleStatx(call: *const Call) Reply {
    const dirfd = call.fd(0);
    const flags = call.word(2);
    const raw = call.path(1, &pathbuf) orelse return .cont;
    var attr: p9.Attr = undefined;
    if (raw.len == 0 and (flags & linux.AT_EMPTY_PATH) != 0) {
        const index = switch (held(call, dirfd)) {
            .reply => |r| return r,
            .file => |i| i,
        };
        attr = client.getattr(tables.file(index).fid) catch |err| return remote(err);
    } else {
        const target = resolveAt(call.pid, dirfd, raw, &joinbuf);
        const rel = switch (target) {
            .outside => return .cont,
            .err => |e| return fail(e),
            .inside => |p| p,
        };
        const walked = walkTo(rel, (flags & linux.AT_SYMLINK_NOFOLLOW) == 0, 0) catch |err|
            return remote(err);
        defer client.clunk(walked.fid);
        attr = client.getattr(walked.fid) catch |err| return remote(err);
    }
    return writeStatx(call.id, call.tid, call.args[4], attr);
}

/// `Tsetattr` against a path, which is `chmod`, `chown`, `truncate` and
/// `utimensat` alike.
fn setattrPath(
    call: *const Call,
    dirfd: i32,
    path_index: usize,
    follow: bool,
    valid: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    atime_sec: u64,
    atime_nsec: u64,
    mtime_sec: u64,
    mtime_nsec: u64,
) Reply {
    const raw = call.path(path_index, &pathbuf) orelse return .cont;
    const target = resolveAt(call.pid, dirfd, raw, &joinbuf);
    const rel = switch (target) {
        .outside => return .cont,
        .err => |e| return fail(e),
        .inside => |p| p,
    };
    const walked = walkTo(rel, follow, 0) catch |err| return remote(err);
    defer client.clunk(walked.fid);
    client.setattr(
        walked.fid,
        valid,
        mode,
        uid,
        gid,
        size,
        atime_sec,
        atime_nsec,
        mtime_sec,
        mtime_nsec,
    ) catch |err| return remote(err);
    return ok;
}

fn setattrFd(
    call: *const Call,
    fd: i32,
    valid: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
) Reply {
    const index = switch (held(call, fd)) {
        .reply => |r| return r,
        .file => |i| i,
    };
    client.setattr(tables.file(index).fid, valid, mode, uid, gid, size, 0, 0, 0, 0) catch |err|
        return remote(err);
    return ok;
}

/// The `uid`/`gid` a `chown` actually asks for: `(uid_t) -1` means "leave it".
fn ownerBits(uid: u32, gid: u32) struct { u32, u32, u32 } {
    var valid: u32 = 0;
    if (uid != 0xffff_ffff) valid |= p9.P9_SETATTR_UID;
    if (gid != 0xffff_ffff) valid |= p9.P9_SETATTR_GID;
    return .{ valid, uid, gid };
}

/// `access(2)` — answered from the file's own mode bits against this process's
/// ids, which are the tracee's too.
fn accessAnswer(attr: p9.Attr, want: u32) Reply {
    if (want == linux.F_OK) return ok;
    var bits: u32 = undefined;
    if (attr.uid == self_uid) {
        bits = (attr.mode >> 6) & 7;
    } else if (attr.gid == self_gid) {
        bits = (attr.mode >> 3) & 7;
    } else {
        bits = attr.mode & 7;
    }
    var need: u32 = 0;
    if ((want & linux.R_OK) != 0) need |= 4;
    if ((want & linux.W_OK) != 0) need |= 2;
    if ((want & linux.X_OK) != 0) need |= 1;
    return if ((bits & need) == need) ok else fail(linux.EACCES);
}

fn handleAccess(call: *const Call, dirfd: i32, path_index: usize, mode_index: usize) Reply {
    const raw = call.path(path_index, &pathbuf) orelse return .cont;
    const target = resolveAt(call.pid, dirfd, raw, &joinbuf);
    const rel = switch (target) {
        .outside => return .cont,
        .err => |e| return fail(e),
        .inside => |p| p,
    };
    const walked = walkTo(rel, true, 0) catch |err| return remote(err);
    defer client.clunk(walked.fid);
    const attr = client.getattr(walked.fid) catch |err| return remote(err);
    return accessAnswer(attr, call.word(mode_index));
}

fn writeStatfs(call: *const Call, remote_addr: u64, got: p9.Client.Statfs) Reply {
    var out = std.mem.zeroes(linux.Statfs);
    out.f_type = @intCast(got.ftype);
    out.f_bsize = @intCast(got.bsize);
    out.f_blocks = got.blocks;
    out.f_bfree = got.bfree;
    out.f_bavail = got.bavail;
    out.f_files = got.files;
    out.f_ffree = got.ffree;
    out.f_fsid = .{ @bitCast(@as(u32, @truncate(got.fsid))), @bitCast(@as(u32, @truncate(got.fsid >> 32))) };
    out.f_namelen = @intCast(got.namelen);
    out.f_frsize = @intCast(got.bsize);
    const bytes: [*]const u8 = @ptrCast(&out);
    if (!notify.stillValid(call.id)) return .gone;
    if (!notify.writeTracee(call.tid, remote_addr, bytes[0..@sizeOf(linux.Statfs)])) {
        return fail(linux.EFAULT);
    }
    return ok;
}

// ---------------------------------------------------------------------------
// The namespace
// ---------------------------------------------------------------------------

/// Resolve a path to its parent directory fid and final name, for the calls
/// that create or remove a name rather than acting on what it points at.
const Named = union(enum) { at: Parented, reply: Reply };

fn namedAt(call: *const Call, dirfd: i32, path_index: usize, into: []u8) Named {
    const raw = call.path(path_index, &pathbuf) orelse return .{ .reply = .cont };
    const target = resolveAt(call.pid, dirfd, raw, &joinbuf);
    const rel = switch (target) {
        .outside => return .{ .reply = .cont },
        .err => |e| return .{ .reply = fail(e) },
        .inside => |p| p,
    };
    const parent = parentOf(rel, into) catch |err| return .{ .reply = remote(err) };
    return .{ .at = parent };
}

fn handleMkdir(call: *const Call, dirfd: i32, path_index: usize, mode_index: usize) Reply {
    var namebuf: [256]u8 = undefined;
    const parent = switch (namedAt(call, dirfd, path_index, &namebuf)) {
        .reply => |r| return r,
        .at => |p| p,
    };
    defer client.clunk(parent.fid);
    const mode = call.word(mode_index) & ~umaskOf(call.tid) & 0o7777;
    _ = client.mkdir(parent.fid, parent.name, mode, 0) catch |err| return remote(err);
    return ok;
}

fn handleUnlinkat(call: *const Call, dirfd: i32, path_index: usize, flags: u32) Reply {
    var namebuf: [256]u8 = undefined;
    const parent = switch (namedAt(call, dirfd, path_index, &namebuf)) {
        .reply => |r| return r,
        .at => |p| p,
    };
    defer client.clunk(parent.fid);
    client.unlinkat(parent.fid, parent.name, flags) catch |err| return remote(err);
    return ok;
}

fn handleMknod(call: *const Call, dirfd: i32, path_index: usize, mode: u32, dev: u64) Reply {
    var namebuf: [256]u8 = undefined;
    const parent = switch (namedAt(call, dirfd, path_index, &namebuf)) {
        .reply => |r| return r,
        .at => |p| p,
    };
    defer client.clunk(parent.fid);
    // `Tmknod` carries major and minor as separate words, which is the opposite
    // of `Rgetattr`'s single packed `rdev`.
    const major: u32 = @intCast((dev >> 8) & 0xfff);
    const minor: u32 = @intCast((dev & 0xff) | ((dev >> 12) & 0xfff_ff00));
    const masked = (mode & ~umaskOf(call.tid) & 0o7777) | (mode & linux.S_IFMT);
    _ = client.mknod(parent.fid, parent.name, masked, major, minor, 0) catch |err|
        return remote(err);
    return ok;
}

fn handleSymlink(call: *const Call, target_index: usize, dirfd: i32, path_index: usize) Reply {
    // The link's *contents* are opaque and are never resolved, so they are read
    // out of the tracee as a plain string rather than through `resolveAt`.
    const contents = call.path(target_index, &auxbuf) orelse return .cont;
    var namebuf: [256]u8 = undefined;
    const parent = switch (namedAt(call, dirfd, path_index, &namebuf)) {
        .reply => |r| return r,
        .at => |p| p,
    };
    defer client.clunk(parent.fid);
    _ = client.symlink(parent.fid, parent.name, contents, 0) catch |err| return remote(err);
    return ok;
}

fn handleReadlink(call: *const Call, dirfd: i32, path_index: usize, buf: u64, size: usize) Reply {
    const raw = call.path(path_index, &pathbuf) orelse return .cont;
    const target = resolveAt(call.pid, dirfd, raw, &joinbuf);
    const rel = switch (target) {
        .outside => return .cont,
        .err => |e| return fail(e),
        .inside => |p| p,
    };
    const walked = walkTo(rel, false, 0) catch |err| return remote(err);
    defer client.clunk(walked.fid);
    var link: [4096]u8 = undefined;
    const contents = client.readlink(walked.fid, &link) catch |err| return remote(err);
    const n = @min(contents.len, size);
    if (!notify.stillValid(call.id)) return .gone;
    if (!notify.writeTracee(call.tid, buf, contents[0..n])) return fail(linux.EFAULT);
    return .{ .ret = @intCast(n) };
}

/// `rename`, in the `renameat` shape every form reduces to.
///
/// A rename that would cross the boundary of the tree is `EXDEV` — which is the
/// truth: the two names are on different filesystems, and `mv` knows what to do
/// with that answer.
fn handleRename(call: *const Call, olddirfd: i32, old_index: usize, newdirfd: i32, new_index: usize) Reply {
    const old_raw = call.path(old_index, &pathbuf) orelse return .cont;
    var old_norm: [4096]u8 = undefined;
    const old_target = resolveAt(call.pid, olddirfd, old_raw, &old_norm);
    const new_raw = call.path(new_index, &auxbuf) orelse return .cont;
    const new_target = resolveAt(call.pid, newdirfd, new_raw, &joinbuf);
    switch (old_target) {
        .outside => return switch (new_target) {
            .inside => fail(linux.EXDEV),
            else => .cont,
        },
        .err => |e| return fail(e),
        .inside => {},
    }
    const old_rel = old_target.inside;
    const new_rel = switch (new_target) {
        .outside => return fail(linux.EXDEV),
        .err => |e| return fail(e),
        .inside => |p| p,
    };
    var old_name: [256]u8 = undefined;
    const old_parent = parentOf(old_rel, &old_name) catch |err| return remote(err);
    defer client.clunk(old_parent.fid);
    var new_name: [256]u8 = undefined;
    const new_parent = parentOf(new_rel, &new_name) catch |err| return remote(err);
    defer client.clunk(new_parent.fid);
    client.renameat(old_parent.fid, old_parent.name, new_parent.fid, new_parent.name) catch |err|
        return remote(err);
    // Open descriptions remember a path so a `close`d-then-resurrected one can
    // be re-opened; a rename moves what that path names, so they move with it.
    // The fids already held are unaffected — 9P keeps an open file attached
    // across a rename — but a description re-opened by its old name would find
    // nothing.
    repathSubtree(old_rel, new_rel);
    return ok;
}

fn repathSubtree(from: []const u8, to: []const u8) void {
    var buf: [4096]u8 = undefined;
    for (tables.files.items, 0..) |entry, index| {
        if (!entry.used) continue;
        const path = entry.path;
        const moved = std.mem.eql(u8, path, from);
        const inside = path.len > from.len and
            std.mem.startsWith(u8, path, from) and
            (from.len == 0 or path[from.len] == '/');
        if (!moved and !inside) continue;
        const tail = if (moved) "" else path[from.len..];
        if (to.len + tail.len > buf.len) continue;
        @memcpy(buf[0..to.len], to);
        @memcpy(buf[to.len .. to.len + tail.len], tail);
        tables.repath(@intCast(index), buf[0 .. to.len + tail.len]) catch {};
    }
}

fn handleLink(call: *const Call, olddirfd: i32, old_index: usize, newdirfd: i32, new_index: usize, flags: u32) Reply {
    const old_raw = call.path(old_index, &pathbuf) orelse return .cont;
    var old_norm: [4096]u8 = undefined;
    const old_target = resolveAt(call.pid, olddirfd, old_raw, &old_norm);
    const new_raw = call.path(new_index, &auxbuf) orelse return .cont;
    const new_target = resolveAt(call.pid, newdirfd, new_raw, &joinbuf);
    switch (old_target) {
        .outside => return switch (new_target) {
            .inside => fail(linux.EXDEV),
            else => .cont,
        },
        .err => |e| return fail(e),
        .inside => {},
    }
    const new_rel = switch (new_target) {
        .outside => return fail(linux.EXDEV),
        .err => |e| return fail(e),
        .inside => |p| p,
    };
    // `link(2)` does not follow the source symlink; `linkat` with
    // `AT_SYMLINK_FOLLOW` does.
    const walked = walkTo(old_target.inside, (flags & linux.AT_SYMLINK_FOLLOW) != 0, 0) catch |err|
        return remote(err);
    defer client.clunk(walked.fid);
    var namebuf: [256]u8 = undefined;
    const parent = parentOf(new_rel, &namebuf) catch |err| return remote(err);
    defer client.clunk(parent.fid);
    client.link(parent.fid, walked.fid, parent.name) catch |err| return remote(err);
    return ok;
}

// ---------------------------------------------------------------------------
// Where a process thinks it is
// ---------------------------------------------------------------------------

/// `chdir` into the tree is answered without the kernel ever moving.
///
/// There is nowhere for it to move *to* — the tree is not mounted — so the
/// working directory becomes a fact this supervisor keeps, and every relative
/// path from that process is resolved against it. The consequence is stated in
/// the file header: a relative `execve` (which no notification can redirect)
/// still resolves against the real working directory, which is wherever the
/// command started.
fn handleChdir(call: *const Call) Reply {
    const raw = call.path(0, &pathbuf) orelse return .cont;
    const target = resolveAt(call.pid, linux.AT_FDCWD, raw, &joinbuf);
    const rel = switch (target) {
        .outside => {
            tables.clearCwd(call.pid);
            return .cont;
        },
        .err => |e| return fail(e),
        .inside => |p| p,
    };
    const walked = walkTo(rel, true, 0) catch |err| return remote(err);
    defer client.clunk(walked.fid);
    if ((walked.qid.qtype & p9.P9_QTDIR) == 0) return fail(linux.ENOTDIR);
    tables.setCwd(call.pid, rel) catch return fail(linux.ENOMEM);
    return ok;
}

fn handleFchdir(call: *const Call) Reply {
    const index = lookupFd(call.pid, call.fd(0)) orelse {
        tables.clearCwd(call.pid);
        return .cont;
    };
    const entry = tables.file(index);
    if (!entry.is_dir) return fail(linux.ENOTDIR);
    tables.setCwd(call.pid, entry.path) catch return fail(linux.ENOMEM);
    return ok;
}

/// `getcwd(2)` returns the length *including* the terminating NUL, and `ERANGE`
/// when the buffer cannot hold it.
fn handleGetcwd(call: *const Call) Reply {
    const rel = tables.cwd(call.pid) orelse return .cont;
    var buf: [4096]u8 = undefined;
    var len: usize = 0;
    if (root.len + rel.len + 2 > buf.len) return fail(linux.ENAMETOOLONG);
    @memcpy(buf[0..root.len], root);
    len += root.len;
    if (rel.len != 0) {
        buf[len] = '/';
        len += 1;
        @memcpy(buf[len .. len + rel.len], rel);
        len += rel.len;
    }
    buf[len] = 0;
    len += 1;
    const size: usize = @truncate(call.args[1]);
    if (size < len) return fail(linux.ERANGE);
    if (!notify.stillValid(call.id)) return .gone;
    if (!notify.writeTracee(call.tid, call.args[0], buf[0..len])) return fail(linux.EFAULT);
    return .{ .ret = @intCast(len) };
}

// ---------------------------------------------------------------------------
// Times
// ---------------------------------------------------------------------------

/// The `Tsetattr` bits and values a `utimensat`-family call asks for.
///
/// `UTIME_NOW` and `UTIME_OMIT` are the two sentinels that make this more than
/// a copy: the first sets the bit without the `_SET` companion (which is 9P's
/// way of saying "now"), and the second sets no bit at all.
const Times = struct {
    valid: u32 = 0,
    atime_sec: u64 = 0,
    atime_nsec: u64 = 0,
    mtime_sec: u64 = 0,
    mtime_nsec: u64 = 0,
};

fn timesFromSpec(call: *const Call, addr: u64) ?Times {
    var out = Times{};
    if (addr == 0) {
        out.valid = p9.P9_SETATTR_ATIME | p9.P9_SETATTR_MTIME;
        return out;
    }
    var spec: [2]linux.Timespec = undefined;
    const bytes: [*]u8 = @ptrCast(&spec);
    if (!notify.readTracee(call.tid, addr, bytes[0 .. 2 * @sizeOf(linux.Timespec)])) return null;
    for (spec, 0..) |value, index| {
        const is_atime = index == 0;
        if (value.nsec == linux.UTIME_OMIT) continue;
        const bit: u32 = if (is_atime) p9.P9_SETATTR_ATIME else p9.P9_SETATTR_MTIME;
        out.valid |= bit;
        if (value.nsec == linux.UTIME_NOW) continue;
        out.valid |= if (is_atime) p9.P9_SETATTR_ATIME_SET else p9.P9_SETATTR_MTIME_SET;
        if (is_atime) {
            out.atime_sec = @intCast(value.sec);
            out.atime_nsec = @intCast(value.nsec);
        } else {
            out.mtime_sec = @intCast(value.sec);
            out.mtime_nsec = @intCast(value.nsec);
        }
    }
    return out;
}

/// The pre-`utimensat` forms, whose values are microseconds or whole seconds.
fn timesFromLegacy(call: *const Call, addr: u64, micro: bool) ?Times {
    var out = Times{};
    if (addr == 0) {
        out.valid = p9.P9_SETATTR_ATIME | p9.P9_SETATTR_MTIME;
        return out;
    }
    out.valid = p9.P9_SETATTR_ATIME | p9.P9_SETATTR_ATIME_SET |
        p9.P9_SETATTR_MTIME | p9.P9_SETATTR_MTIME_SET;
    if (micro) {
        var value: [2]linux.Timeval = undefined;
        const bytes: [*]u8 = @ptrCast(&value);
        if (!notify.readTracee(call.tid, addr, bytes[0 .. 2 * @sizeOf(linux.Timeval)])) return null;
        out.atime_sec = @intCast(value[0].sec);
        out.atime_nsec = @intCast(value[0].usec * 1000);
        out.mtime_sec = @intCast(value[1].sec);
        out.mtime_nsec = @intCast(value[1].usec * 1000);
    } else {
        var value: linux.Utimbuf = undefined;
        const bytes: [*]u8 = @ptrCast(&value);
        if (!notify.readTracee(call.tid, addr, bytes[0..@sizeOf(linux.Utimbuf)])) return null;
        out.atime_sec = @intCast(value.actime);
        out.mtime_sec = @intCast(value.modtime);
    }
    return out;
}

fn applyTimes(call: *const Call, dirfd: i32, path_index: usize, follow: bool, times: Times) Reply {
    return setattrPath(
        call,
        dirfd,
        path_index,
        follow,
        times.valid,
        0,
        0,
        0,
        0,
        times.atime_sec,
        times.atime_nsec,
        times.mtime_sec,
        times.mtime_nsec,
    );
}

// ---------------------------------------------------------------------------
// Descriptors this supervisor will not pretend about
// ---------------------------------------------------------------------------

/// Refuse an operation on a virtual descriptor, with the errno that makes a
/// caller fall back rather than give up.
///
/// `sendfile`, `splice` and `copy_file_range` would all otherwise run against
/// the empty placeholder and report a clean, confident, wrong answer — the
/// exact failure this design exists to remove. `EINVAL` and `EXDEV` are what
/// coreutils and glibc both take as "do it the long way", which they then do
/// through `read` and `write`, and those are answered properly.
fn refuseIfOurs(call: *const Call, fds: []const i32, errno: i32) Reply {
    for (fds) |fd| {
        if (lookupFd(call.pid, fd) != null) return fail(errno);
    }
    return .cont;
}

/// Extended attributes: refused on anything of ours, which is also what the 9P
/// transport answers for `Txattrwalk`.
fn refuseXattrPath(call: *const Call, path_index: usize) Reply {
    const raw = call.path(path_index, &pathbuf) orelse return .cont;
    return switch (resolveAt(call.pid, linux.AT_FDCWD, raw, &joinbuf)) {
        .outside => .cont,
        .err => |e| fail(e),
        .inside => fail(linux.ENOTSUP),
    };
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn dispatch(call: *const Call, nr: i32) Reply {
    return switch (nr) {
        // --- descriptors -----------------------------------------------------
        SYS.read => handleRead(call, call.fd(0), call.args[1], @truncate(call.args[2]), null),
        SYS.pread64 => handleRead(call, call.fd(0), call.args[1], @truncate(call.args[2]), call.args[3]),
        SYS.write => handleWrite(call, call.fd(0), call.args[1], @truncate(call.args[2]), null),
        SYS.pwrite64 => handleWrite(call, call.fd(0), call.args[1], @truncate(call.args[2]), call.args[3]),
        SYS.readv => handleReadv(call, call.fd(0), call.args[1], @truncate(call.args[2]), null),
        SYS.writev => handleWritev(call, call.fd(0), call.args[1], @truncate(call.args[2]), null),
        // `preadv`'s offset arrives as a low/high pair, and on a 64-bit kernel
        // `pos_from_hilo()` shifts the high half clean off the top — so the low
        // word *is* the offset. `preadv2` adds a flags word after it.
        SYS.preadv, SYS.preadv2 => handleReadv(call, call.fd(0), call.args[1], @truncate(call.args[2]), call.args[3]),
        SYS.pwritev, SYS.pwritev2 => handleWritev(call, call.fd(0), call.args[1], @truncate(call.args[2]), call.args[3]),
        SYS.lseek => handleLseek(call),
        SYS.getdents64 => handleGetdents(call),
        SYS.fstat => handleFstat(call),
        SYS.close => blk: {
            // Bookkeeping first, then the kernel really closes it: the number is
            // reused immediately, and a mapping that outlived its descriptor
            // shadowed a live one in the spike.
            //
            // The lookup is what binds a descriptor this supervisor never saw
            // created — a `dup` it could not observe — so that closing it
            // decrements the right reference count rather than none.
            tables.unbind(call.pid, call.fd(0));
            break :blk .cont;
        },
        // The two calls that replace a *live* descriptor number without a
        // `close` anybody can see. Everything else that hands out a number
        // (`open`, `dup`, `socket`, `fcntl(F_DUPFD)`) is given a free one by the
        // kernel, so only these can leave a binding pointing at the wrong file.
        SYS.dup2, SYS.dup3 => blk: {
            const oldfd = call.fd(0);
            const newfd = call.fd(1);
            if (oldfd != newfd) {
                tables.unbind(call.pid, newfd);
                if (lookupFd(call.pid, oldfd)) |index| tables.bind(call.pid, newfd, index) catch {};
            }
            break :blk .cont;
        },
        SYS.close_range => blk: {
            tables.unbindRange(call.pid, call.fd(0), call.fd(1));
            break :blk .cont;
        },
        SYS.mmap => blk: {
            const fd = call.fd(4);
            if (fd >= 0 and lookupFd(call.pid, fd) != null) break :blk fail(linux.ENODEV);
            break :blk .cont;
        },
        SYS.fsync => blk: {
            const index = switch (held(call, call.fd(0))) {
                .reply => |r| break :blk r,
                .file => |i| i,
            };
            client.fsync(tables.file(index).fid, 0) catch |err| break :blk remote(err);
            break :blk ok;
        },
        SYS.fdatasync => blk: {
            const index = switch (held(call, call.fd(0))) {
                .reply => |r| break :blk r,
                .file => |i| i,
            };
            client.fsync(tables.file(index).fid, 1) catch |err| break :blk remote(err);
            break :blk ok;
        },
        SYS.ftruncate => setattrFd(call, call.fd(0), p9.P9_SETATTR_SIZE, 0, 0, 0, call.args[1]),
        SYS.fchmod => setattrFd(call, call.fd(0), p9.P9_SETATTR_MODE, call.word(1) & 0o7777, 0, 0, 0),
        SYS.fchown => blk: {
            const bits = ownerBits(call.word(1), call.word(2));
            break :blk setattrFd(call, call.fd(0), bits[0], 0, bits[1], bits[2], 0);
        },
        SYS.fstatfs => blk: {
            const index = switch (held(call, call.fd(0))) {
                .reply => |r| break :blk r,
                .file => |i| i,
            };
            const got = client.statfs(tables.file(index).fid) catch |err| break :blk remote(err);
            break :blk writeStatfs(call, call.args[1], got);
        },
        SYS.sendfile => refuseIfOurs(call, &.{ call.fd(0), call.fd(1) }, linux.EINVAL),
        SYS.splice => refuseIfOurs(call, &.{ call.fd(0), call.fd(2) }, linux.EINVAL),
        SYS.copy_file_range => refuseIfOurs(call, &.{ call.fd(0), call.fd(2) }, linux.EXDEV),
        SYS.fallocate => refuseIfOurs(call, &.{call.fd(0)}, linux.ENOTSUP),

        // --- opening ---------------------------------------------------------
        SYS.open => openCommon(call, linux.AT_FDCWD, 0, call.word(1), call.word(2)),
        SYS.openat => openCommon(call, call.fd(0), 1, call.word(2), call.word(3)),
        SYS.creat => openCommon(
            call,
            linux.AT_FDCWD,
            0,
            linux.O_CREAT | linux.O_WRONLY | linux.O_TRUNC,
            call.word(1),
        ),
        // `openat2` takes a `struct open_how` this supervisor does not decode.
        // `ENOSYS` is the answer a pre-5.6 kernel gives and every caller has a
        // fallback for — which is `openat`, and that is answered properly.
        SYS.openat2 => blk: {
            const raw = call.path(1, &pathbuf) orelse break :blk .cont;
            break :blk switch (resolveAt(call.pid, call.fd(0), raw, &joinbuf)) {
                .outside => .cont,
                .err => |e| fail(e),
                .inside => fail(linux.ENOSYS),
            };
        },

        // --- metadata --------------------------------------------------------
        SYS.stat => handleStatPath(call, linux.AT_FDCWD, 0, true, 1),
        SYS.lstat => handleStatPath(call, linux.AT_FDCWD, 0, false, 1),
        SYS.newfstatat => handleNewfstatat(call),
        SYS.statx => handleStatx(call),
        SYS.access => handleAccess(call, linux.AT_FDCWD, 0, 1),
        SYS.faccessat, SYS.faccessat2 => handleAccess(call, call.fd(0), 1, 2),
        SYS.statfs => blk: {
            const raw = call.path(0, &pathbuf) orelse break :blk .cont;
            const target = resolveAt(call.pid, linux.AT_FDCWD, raw, &joinbuf);
            const rel = switch (target) {
                .outside => break :blk .cont,
                .err => |e| break :blk fail(e),
                .inside => |p| p,
            };
            const walked = walkTo(rel, true, 0) catch |err| break :blk remote(err);
            defer client.clunk(walked.fid);
            const got = client.statfs(walked.fid) catch |err| break :blk remote(err);
            break :blk writeStatfs(call, call.args[1], got);
        },
        SYS.truncate => setattrPath(call, linux.AT_FDCWD, 0, true, p9.P9_SETATTR_SIZE, 0, 0, 0, call.args[1], 0, 0, 0, 0),
        SYS.chmod => setattrPath(call, linux.AT_FDCWD, 0, true, p9.P9_SETATTR_MODE, call.word(1) & 0o7777, 0, 0, 0, 0, 0, 0, 0),
        SYS.fchmodat => setattrPath(
            call,
            call.fd(0),
            1,
            (call.word(3) & linux.AT_SYMLINK_NOFOLLOW) == 0,
            p9.P9_SETATTR_MODE,
            call.word(2) & 0o7777,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        SYS.chown, SYS.lchown => blk: {
            const bits = ownerBits(call.word(1), call.word(2));
            break :blk setattrPath(call, linux.AT_FDCWD, 0, nr == SYS.chown, bits[0], 0, bits[1], bits[2], 0, 0, 0, 0, 0);
        },
        SYS.fchownat => blk: {
            const bits = ownerBits(call.word(2), call.word(3));
            const follow = (call.word(4) & linux.AT_SYMLINK_NOFOLLOW) == 0;
            break :blk setattrPath(call, call.fd(0), 1, follow, bits[0], 0, bits[1], bits[2], 0, 0, 0, 0, 0);
        },
        SYS.utimensat => blk: {
            // A null path means the descriptor itself: this is `futimens`.
            if (call.args[1] == 0) {
                const index = switch (held(call, call.fd(0))) {
                    .reply => |r| break :blk r,
                    .file => |i| i,
                };
                const times = timesFromSpec(call, call.args[2]) orelse break :blk fail(linux.EFAULT);
                if (!notify.stillValid(call.id)) break :blk .gone;
                client.setattr(
                    tables.file(index).fid,
                    times.valid,
                    0,
                    0,
                    0,
                    0,
                    times.atime_sec,
                    times.atime_nsec,
                    times.mtime_sec,
                    times.mtime_nsec,
                ) catch |err| break :blk remote(err);
                break :blk ok;
            }
            const times = timesFromSpec(call, call.args[2]) orelse break :blk fail(linux.EFAULT);
            const follow = (call.word(3) & linux.AT_SYMLINK_NOFOLLOW) == 0;
            break :blk applyTimes(call, call.fd(0), 1, follow, times);
        },
        SYS.utimes => blk: {
            const times = timesFromLegacy(call, call.args[1], true) orelse break :blk fail(linux.EFAULT);
            break :blk applyTimes(call, linux.AT_FDCWD, 0, true, times);
        },
        SYS.utime => blk: {
            const times = timesFromLegacy(call, call.args[1], false) orelse break :blk fail(linux.EFAULT);
            break :blk applyTimes(call, linux.AT_FDCWD, 0, true, times);
        },
        SYS.futimesat => blk: {
            const times = timesFromLegacy(call, call.args[2], true) orelse break :blk fail(linux.EFAULT);
            break :blk applyTimes(call, call.fd(0), 1, true, times);
        },

        // --- the namespace ---------------------------------------------------
        SYS.mkdir => handleMkdir(call, linux.AT_FDCWD, 0, 1),
        SYS.mkdirat => handleMkdir(call, call.fd(0), 1, 2),
        SYS.rmdir => handleUnlinkat(call, linux.AT_FDCWD, 0, p9.P9_DOTL_AT_REMOVEDIR),
        SYS.unlink => handleUnlinkat(call, linux.AT_FDCWD, 0, 0),
        SYS.unlinkat => handleUnlinkat(
            call,
            call.fd(0),
            1,
            if ((call.word(2) & linux.AT_REMOVEDIR) != 0) p9.P9_DOTL_AT_REMOVEDIR else 0,
        ),
        SYS.rename => handleRename(call, linux.AT_FDCWD, 0, linux.AT_FDCWD, 1),
        SYS.renameat => handleRename(call, call.fd(0), 1, call.fd(2), 3),
        // `renameat2`'s flags are `RENAME_NOREPLACE`, `RENAME_EXCHANGE` and
        // `RENAME_WHITEOUT`, none of which 9P's `Trenameat` can express.
        // `EINVAL` is the documented "this filesystem does not support that",
        // and it is what makes `mv` fall back to the plain form.
        SYS.renameat2 => if (call.word(4) != 0)
            blk: {
                const raw = call.path(1, &pathbuf) orelse break :blk .cont;
                break :blk switch (resolveAt(call.pid, call.fd(0), raw, &joinbuf)) {
                    .outside => .cont,
                    .err => |e| fail(e),
                    .inside => fail(linux.EINVAL),
                };
            }
        else
            handleRename(call, call.fd(0), 1, call.fd(2), 3),
        SYS.link => handleLink(call, linux.AT_FDCWD, 0, linux.AT_FDCWD, 1, 0),
        SYS.linkat => handleLink(call, call.fd(0), 1, call.fd(2), 3, call.word(4)),
        SYS.symlink => handleSymlink(call, 0, linux.AT_FDCWD, 1),
        SYS.symlinkat => handleSymlink(call, 0, call.fd(1), 2),
        SYS.readlink => handleReadlink(call, linux.AT_FDCWD, 0, call.args[1], @truncate(call.args[2])),
        SYS.readlinkat => handleReadlink(call, call.fd(0), 1, call.args[2], @truncate(call.args[3])),
        SYS.mknod => handleMknod(call, linux.AT_FDCWD, 0, call.word(1), call.args[2]),
        SYS.mknodat => handleMknod(call, call.fd(0), 1, call.word(2), call.args[3]),

        // --- where a process thinks it is ------------------------------------
        SYS.getcwd => handleGetcwd(call),
        SYS.chdir => handleChdir(call),
        SYS.fchdir => handleFchdir(call),

        // --- extended attributes ---------------------------------------------
        SYS.setxattr, SYS.lsetxattr, SYS.getxattr, SYS.lgetxattr, SYS.listxattr, SYS.llistxattr, SYS.removexattr, SYS.lremovexattr => refuseXattrPath(call, 0),
        SYS.fsetxattr, SYS.fgetxattr, SYS.flistxattr, SYS.fremovexattr => refuseIfOurs(call, &.{call.fd(0)}, linux.ENOTSUP),

        // --- lifecycle -------------------------------------------------------
        SYS.exit_group => blk: {
            sweep(call.pid);
            break :blk .cont;
        },
        else => .cont,
    };
}

/// Everything a process was holding, released the moment it says it is leaving.
///
/// A tracee killed by a signal never reaches `exit_group`, which is what the
/// final sweep in `main` is for; between them, no fid outlives the process that
/// opened it by longer than the run.
fn sweep(pid: i32) void {
    tables.unbindAll(pid);
    tables.clearCwd(pid);
}

/// Clunk the fid of everything whose last descriptor went during this
/// notification. Draining after the handler rather than inside it keeps the
/// tables free of anything that has to speak 9P.
fn drainOrphans() void {
    for (tables.takeOrphans()) |index| release(index);
    tables.clearOrphans();
}

// ---------------------------------------------------------------------------

/// Entry point in C's shape rather than Zig's, because this binary links libc
/// and needs `argv` exactly as the kernel laid it out — it is passed straight
/// to `execvp` with only the leading arguments removed.
pub export fn main(argc: c_int, cargv: [*][*:0]u8) c_int {
    if (argc < 5) die("usage: trace <9p-socket> <root> -- <command> [args...]", .{});
    const sock = cargv[1];
    root = std.mem.span(@as([*:0]const u8, cargv[2]));
    if (!std.mem.eql(u8, std.mem.span(@as([*:0]const u8, cargv[3])), "--")) {
        die("expected -- before the command", .{});
    }
    const child_argv: [*:null]?[*:0]u8 = @ptrCast(cargv + 4);

    debug = c.getenv("MOUNTX_TRACE_DEBUG") != null;
    gpa = std.heap.c_allocator;
    tables = state.Tables.init(gpa);
    self_uid = c.getuid();
    self_gid = c.getgid();

    client.connect(std.mem.span(@as([*:0]const u8, sock))) catch
        die("could not connect to the 9P socket {s}", .{sock});
    // The tracee has no business holding the supervisor's connection open.
    _ = c.fcntl(client.fd, c.F_SETFD, @as(c_int, c.FD_CLOEXEC));

    const pair = notify.socketpair() catch die("socketpair failed", .{});

    const pid = c.fork();
    if (pid < 0) die("fork failed", .{});
    if (pid == 0) {
        // The child installs the filter on *itself* and hands the listener
        // back, so the supervisor carries no filter and may make any syscall it
        // likes — which is what makes `close`, `read` and `write` trappable at
        // all. Everything here happens before the first trapped syscall the
        // child makes, and `execvp` is not one.
        _ = c.close(pair[0]);
        const fd = notify.installFilter(&TRAPPED) catch
            die("could not install the seccomp filter", .{});
        _ = c.fcntl(fd, c.F_SETFD, @as(c_int, c.FD_CLOEXEC));
        notify.sendFd(pair[1], fd) catch die("could not hand the listener back", .{});
        _ = c.execvp(child_argv[0].?, @ptrCast(child_argv));
        die("could not exec {s}", .{child_argv[0].?});
    }

    _ = c.close(pair[1]);
    const fd = notify.recvFd(pair[0]) catch die("never received the seccomp listener", .{});
    _ = c.close(pair[0]);
    notify.setListener(fd);

    var status: c_int = 0;
    var reaped = false;
    var notif: notify.Notif = undefined;
    while (true) {
        // Poll rather than block in the ioctl, so a tracee that dies while
        // nothing is in flight is noticed. A grandchild that outlives the
        // command it was spawned from stops being served here, and its trapped
        // syscalls then fail with `ENOSYS` — loud, and the same thing that
        // happens to any process whose supervisor is gone.
        switch (notify.wait(200)) {
            .ready => {},
            .idle => {
                if (c.waitpid(pid, &status, c.WNOHANG) == pid) {
                    reaped = true;
                    break;
                }
                continue;
            },
            .failed => break,
        }
        if (!notify.receive(&notif)) {
            if (c.waitpid(pid, &status, c.WNOHANG) == pid) {
                reaped = true;
                break;
            }
            continue;
        }
        const tid: i32 = @intCast(notif.pid);
        const call = Call{
            .id = notif.id,
            .tid = tid,
            .pid = tgidOf(tid),
            .args = notif.data.args,
        };
        dbg("nr={d} tid={d} pid={d} args=({x},{x},{x})", .{
            notif.data.nr,
            call.tid,
            call.pid,
            call.args[0],
            call.args[1],
            call.args[2],
        });
        // Exactly one of these, for every notification, always.
        switch (dispatch(&call, notif.data.nr)) {
            .ret => |value| notify.respond(notif.id, value, 0),
            .err => |errno| notify.respond(notif.id, 0, -errno),
            .cont => notify.passthrough(notif.id),
            .gone => {},
        }
        drainOrphans();
    }

    // Whatever survived a signal rather than an `exit_group`.
    for (tables.files.items, 0..) |entry, index| {
        if (entry.used and entry.open) {
            tables.files.items[index].refs = 0;
            release(@intCast(index));
        }
    }
    if (!reaped) _ = c.waitpid(pid, &status, 0);
    return if ((status & 0x7f) == 0) (status >> 8) & 0xff else 128 + (status & 0x7f);
}
