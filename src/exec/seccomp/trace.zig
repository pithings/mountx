//! SPIKE C — seccomp user notification: `proot` done the modern way.
//!
//! A BPF filter selects a handful of filesystem syscalls and answers
//! `SECCOMP_RET_USER_NOTIF` for them; every other syscall the traced process
//! makes runs at full native speed, never leaving the kernel. The supervisor
//! reads each trapped call off a listener fd, answers it out of the same 9P
//! client spike B's `LD_PRELOAD` shim uses, and sends the result back.
//!
//! **Why this is the interesting one.** The boundary here is the syscall ABI,
//! not glibc's exported symbols — so it does not care what the traced program
//! is linked against, or whether it is linked at all. The static musl binary
//! and the raw-syscall binary that spike B cannot see are, to this mechanism,
//! indistinguishable from `cat`. And the surface is *closed*: there are five
//! syscalls that open a file, not five families times three suffixes times
//! whatever this distribution's glibc decided to route internally.
//!
//! Usage: `trace <9p-socket> <root-prefix> -- <command> [args...]`
//!
//! ### The design that avoids passing a file descriptor
//!
//! The usual shape of this is: fork, have the child install the filter, and
//! have it hand the listener fd back to the supervisor over `SCM_RIGHTS` —
//! which is precisely the `recvmsg` dance that needed a native addon for
//! `fusermount3`. It is avoidable here. A seccomp filter is *inherited across
//! fork and exec*, so this process installs the filter on itself, keeps the
//! listener, and forks: the child inherits the filter, its trapped syscalls
//! arrive on the listener this process already holds, and no descriptor ever
//! crosses a socket.
//!
//! The price is a rule this file has to keep: after the filter is installed,
//! **the supervisor must never make a trapped syscall itself**, because it
//! would be suspended waiting for a reply only it could send. That is why the
//! 9P connection is established *before* `installFilter()`, why `close` is not
//! in the trapped set, and why everything the loop does afterwards —
//! `ioctl`, `process_vm_readv`, `process_vm_writev`, `memfd_create`, `read`,
//! `write` — is deliberately outside it.
//!
//! ### What a file open turns into
//!
//! `SECCOMP_IOCTL_NOTIF_ADDFD` can install a descriptor from the supervisor
//! into the traced process, so an `openat` of a regular file is answered by
//! slurping the file over 9P into a `memfd` and injecting *that*. Everything
//! afterwards — `read`, `lseek`, `mmap`, `close` — then runs natively against
//! real kernel memory with no further interception at all, which is why those
//! syscalls are absent from the filter.
//!
//! The cost is stated rather than hidden: the whole file is copied into memory
//! at open time, and nothing is written back. A design that streamed instead
//! would have to trap `read`/`lseek` per fd and answer them the way
//! `getdents64` is answered below. Directories take exactly that route already,
//! because `getdents64` on a `memfd` is `ENOTDIR` no matter what is in it.

const std = @import("std");
const p9 = @import("p9");

const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("sys/ioctl.h");
    @cInclude("sys/prctl.h");
    @cInclude("sys/uio.h");
    @cInclude("sys/wait.h");
    @cInclude("linux/seccomp.h");
    @cInclude("linux/filter.h");
    @cInclude("unistd.h");
    @cInclude("errno.h");
    @cInclude("string.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("fcntl.h");
});

// ---------------------------------------------------------------------------
// Constants
//
// The ioctl numbers come from the kernel's own `linux/seccomp.h` through
// `@cImport`, computed by `_IOWR` rather than written down here. Two values
// cannot come that way and are transcribed instead, both from
// `linux/audit.h`: `AUDIT_ARCH_X86_64` overflows a C `int` and so does not
// survive translation, and the syscall numbers are the x86-64 table's.
// ---------------------------------------------------------------------------

/// `EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE` — 62 | 0x80000000 | 0x40000000.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

const SYS_openat: u32 = 257;
const SYS_newfstatat: u32 = 262;
const SYS_statx: u32 = 332;
const SYS_getdents64: u32 = 217;
/// `fstat` is its own syscall number on x86-64, not `newfstatat` with an empty
/// path — and glibc's `opendir` uses it to check that what it just opened is a
/// directory. Without it trapped, `opendir` saw the placeholder descriptor's
/// real type and answered ENOTDIR on a directory this supervisor had just
/// resolved successfully. Witnessed.
const SYS_fstat: u32 = 5;
/// The pre-`*at()` syscalls, which x86-64 still carries and musl still uses.
///
/// `probe-musl` — static, so linkage-blind interception should have been its
/// whole point — answered ENOENT with `openat` trapped and `open` not.
/// musl's `open()` issues `SYS_open` (2) directly wherever the architecture
/// defines it, and x86-64 does. So even a syscall-level boundary has more than
/// one door per operation; the difference from the `LD_PRELOAD` surface is
/// that this set is *finite and fixed by the kernel ABI*, rather than growing
/// with each libc release.
const SYS_open: u32 = 2;
const SYS_stat: u32 = 4;
const SYS_lstat: u32 = 6;

/// The trapped set. Small on purpose: everything not here runs natively, and
/// `close` is excluded because the supervisor calls it (see the header).
const TRAPPED = [_]u32{
    SYS_openat,  SYS_newfstatat, SYS_statx, SYS_getdents64,
    SYS_fstat,   SYS_open,       SYS_stat,  SYS_lstat,
};

const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: u32 = 0x1000;

/// BPF instruction classes, from `linux/bpf_common.h`.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
/// `offsetof(struct seccomp_data, ...)`.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

/// Opt-in tracing, because the interesting failures here are all "which
/// syscall did the program actually make, against which descriptor".
var debug = false;

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
// The filter
// ---------------------------------------------------------------------------

fn installFilter() i32 {
    var prog: [4 + TRAPPED.len + 2]c.struct_sock_filter = undefined;
    var n: usize = 0;
    // Refuse to interpret a syscall table that is not the one these numbers
    // belong to. A 32-bit call arriving on an x86-64 kernel has entirely
    // different numbers, and answering it as if it did not would be worse
    // than letting it through.
    prog[n] = .{ .code = BPF_LD_W_ABS, .jt = 0, .jf = 0, .k = OFF_ARCH };
    n += 1;
    prog[n] = .{ .code = BPF_JMP_JEQ_K, .jt = 1, .jf = 0, .k = AUDIT_ARCH_X86_64 };
    n += 1;
    prog[n] = .{ .code = BPF_RET_K, .jt = 0, .jf = 0, .k = c.SECCOMP_RET_ALLOW };
    n += 1;
    prog[n] = .{ .code = BPF_LD_W_ABS, .jt = 0, .jf = 0, .k = OFF_NR };
    n += 1;
    // Each comparison jumps forward to the single USER_NOTIF at the end; the
    // distance shrinks by one for each comparison already passed.
    const count: u8 = @intCast(TRAPPED.len);
    for (TRAPPED, 0..) |nr, i| {
        prog[n] = .{ .code = BPF_JMP_JEQ_K, .jt = count - @as(u8, @intCast(i)), .jf = 0, .k = nr };
        n += 1;
    }
    prog[n] = .{ .code = BPF_RET_K, .jt = 0, .jf = 0, .k = c.SECCOMP_RET_ALLOW };
    n += 1;
    prog[n] = .{ .code = BPF_RET_K, .jt = 0, .jf = 0, .k = c.SECCOMP_RET_USER_NOTIF };
    n += 1;

    const fprog = c.struct_sock_fprog{ .len = @intCast(n), .filter = &prog };
    // Without `no_new_privs` an unprivileged process may not install a filter
    // at all — the kernel's guard against using seccomp to confuse a setuid
    // binary it then execs. Setting it is also irreversible, which is fine
    // here: this process exists to be the supervisor and nothing else.
    if (c.prctl(c.PR_SET_NO_NEW_PRIVS, @as(c_ulong, 1), @as(c_ulong, 0), @as(c_ulong, 0), @as(c_ulong, 0)) != 0) {
        die("prctl(PR_SET_NO_NEW_PRIVS) failed: {s}", .{c.strerror(c.__errno_location().*)});
    }
    const rc = std.os.linux.syscall3(
        .seccomp,
        c.SECCOMP_SET_MODE_FILTER,
        c.SECCOMP_FILTER_FLAG_NEW_LISTENER,
        @intFromPtr(&fprog),
    );
    const signed: isize = @bitCast(rc);
    if (signed < 0) die("seccomp(SET_MODE_FILTER, NEW_LISTENER) failed: errno {d}", .{-signed});
    return @intCast(signed);
}

// ---------------------------------------------------------------------------
// Tracee memory
// ---------------------------------------------------------------------------

fn readTracee(pid: i32, remote: u64, into: []u8) bool {
    var liov = c.struct_iovec{ .iov_base = into.ptr, .iov_len = into.len };
    var riov = c.struct_iovec{ .iov_base = @ptrFromInt(remote), .iov_len = into.len };
    const n = c.process_vm_readv(pid, &liov, 1, &riov, 1, 0);
    return n == @as(isize, @intCast(into.len));
}

fn writeTracee(pid: i32, remote: u64, from: []const u8) bool {
    var liov = c.struct_iovec{ .iov_base = @constCast(from.ptr), .iov_len = from.len };
    var riov = c.struct_iovec{ .iov_base = @ptrFromInt(remote), .iov_len = from.len };
    const n = c.process_vm_writev(pid, &liov, 1, &riov, 1, 0);
    return n == @as(isize, @intCast(from.len));
}

/// A NUL-terminated string out of the tracee, one page-safe chunk at a time.
///
/// Reading a path from another process is the one genuinely delicate part of
/// this mechanism: the length is not known in advance and the address may sit
/// near the end of a mapping, so a single large read can fail for a string
/// that is perfectly valid. Hence the walk.
fn readTraceePath(pid: i32, remote: u64, into: []u8) ?[]const u8 {
    var got: usize = 0;
    while (got < into.len) {
        // **Clamp every read to the end of the current page.** A path can sit
        // anywhere, including the last few bytes of a mapping — an argv or
        // envp string lives at the very top of the stack — and
        // `process_vm_readv` fails the *whole* request if any part of it is
        // unmapped. Reading a fixed 64 bytes therefore fails intermittently
        // depending on where ASLR put the string, which is exactly how this
        // showed up: `probe-raw` opened two files fine and then could not
        // open a directory, because that one path happened to be the env
        // string near the stack top.
        const addr = remote + got;
        const to_page_end = 4096 - (addr & 0xfff);
        const chunk = @min(@min(@as(u64, 64), to_page_end), into.len - got);
        if (!readTracee(pid, addr, into[got .. got + chunk])) {
            if (got == 0) return null;
            break;
        }
        for (into[got .. got + chunk], got..) |ch, i| {
            if (ch == 0) return into[0..i];
        }
        got += chunk;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Supervisor state
// ---------------------------------------------------------------------------

var client: p9.Client = .{};
var root: []const u8 = &.{};
var listener: i32 = -1;

/// Directory fds handed to a tracee, so `getdents64` can be answered for them.
///
/// Leaked deliberately: `close` is not trapped (the supervisor calls it, and
/// trapping it would deadlock this process against itself), so nothing tells
/// us when a tracee lets one go. Bounded and fine for a spike; a shipping
/// version would trap `close` in a supervisor that does not share the fate of
/// its own filter.
const DirFd = struct {
    used: bool = false,
    is_dir: bool = false,
    pid: i32 = 0,
    fd: i32 = 0,
    fid: u32 = 0,
    serial: u32 = 0,
    cookie: u64 = 0,
    path_len: u16 = 0,
    path: [256]u8 = undefined,
};
var dirfds: [256]DirFd = @splat(.{});

fn trackFd(pid: i32, fd: i32, fid: u32, is_dir: bool, rel: []const u8) void {
    // Evict any stale entry for this exact descriptor **first**.
    //
    // `close` is not trapped (the supervisor calls it, and trapping it would
    // suspend this process against itself), so nothing tells us when a tracee
    // lets a descriptor go — and the kernel reuses the lowest free number
    // immediately. The result was a stale mapping shadowing a live one:
    //
    //     open /mountx        -> fd 4, tracked as a directory
    //     ...closed...
    //     open /mountx/hello.txt -> fd 4 again, tracked as a file
    //     fstat(4)            -> matched the *directory* entry first
    //
    // and `cp -r` correctly concluded that the file it had just stat'ed had
    // been replaced by a directory underneath it. Witnessed as
    // "skipping file '/mountx/hello.txt', as it was replaced while being
    // copied" with `fstat` reporting mode 40755 for a regular file.
    //
    // Evicting on reuse fixes the shadowing. It does not fix the leak: a
    // descriptor closed and never reused keeps its fid forever. That is the
    // real cost of leaving `close` untrapped, and the way out is a supervisor
    // that does not share a filter with the process it supervises.
    for (&dirfds) |*d| {
        if (d.used and d.pid == pid and d.fd == fd) {
            client.clunk(d.fid);
            d.* = .{};
        }
    }
    for (&dirfds) |*d| {
        if (!d.used) {
            d.* = .{ .used = true, .is_dir = is_dir, .pid = pid, .fd = fd, .fid = fid, .cookie = 0 };
            const n = @min(rel.len, d.path.len);
            @memcpy(d.path[0..n], rel[0..n]);
            d.path_len = @intCast(n);
            return;
        }
    }
}

fn trackedPath(d: *const DirFd) []const u8 {
    return d.path[0..d.path_len];
}

/// `<dir>/<name>`, for resolving a relative path against a tracked directory fd.
fn joinPath(out: []u8, dir: []const u8, name: []const u8) ?[]const u8 {
    if (dir.len + 1 + name.len > out.len) return null;
    @memcpy(out[0..dir.len], dir);
    out[dir.len] = '/';
    @memcpy(out[dir.len + 1 .. dir.len + 1 + name.len], name);
    return out[0 .. dir.len + 1 + name.len];
}

/// The path a notification names, resolved against a tracked directory fd when
/// the path is relative. Returns null when the call is not ours.
///
/// Needed for the identical reason spike B needed it: every tree walker
/// resolves each level against the parent's descriptor rather than by name.
/// Without it, `find` and `du` reported "Not a directory" for every entry of a
/// directory they had just listed.
fn resolve(pid: i32, dirfd: i32, raw: []const u8, out: []u8) ?[]const u8 {
    if (raw.len > 0 and raw[0] == '/') return under(raw);
    if (raw.len == 0) return null;
    const d = findDir(pid, dirfd) orelse return null;
    if (!d.is_dir) return null;
    return joinPath(out, trackedPath(d), raw);
}

/// Serial stamped into each injected `memfd`'s name, so a descriptor can be
/// identified by what it points at rather than by the number it was given.
var next_serial: u32 = 1;

fn findExact(pid: i32, fd: i32) ?*DirFd {
    for (&dirfds) |*d| {
        if (d.used and d.pid == pid and d.fd == fd) return d;
    }
    return null;
}

/// Which tracked descriptor is `(pid, fd)` — following duplicates.
///
/// The table records the fd number this supervisor injected, but a tracee is
/// free to `dup` it, and `fts` (so: `find`, `du`, `cp -r`) always does:
///
///     openat(AT_FDCWD, "/mountx", ...|O_DIRECTORY) = 3
///     newfstatat(4, "hello.txt", ...)      <-- fd 4, a dup of fd 3
///
/// Trapping `dup` does not help, because a notification cannot observe the fd
/// number the kernel is about to return. So identity comes from the object
/// instead of the number: every injected descriptor is a `memfd` with a unique
/// name, and `/proc/<pid>/fd/<n>` reads back as `/memfd:mx-<serial> (deleted)`
/// for the original and every duplicate alike. A hit is memoised so the walk
/// happens once per new descriptor rather than once per syscall.
fn findDir(pid: i32, fd: i32) ?*DirFd {
    if (findExact(pid, fd)) |d| return d;
    if (fd < 0) return null;
    var link: [128]u8 = undefined;
    var target: [128]u8 = undefined;
    const path = std.fmt.bufPrintZ(&link, "/proc/{d}/fd/{d}", .{ pid, fd }) catch return null;
    const n = c.readlink(path.ptr, &target, target.len);
    if (n <= 0) return null;
    const seen = target[0..@intCast(n)];
    const prefix = "/memfd:mx-";
    if (!std.mem.startsWith(u8, seen, prefix)) return null;
    var serial: u32 = 0;
    for (seen[prefix.len..]) |ch| {
        if (ch < '0' or ch > '9') break;
        serial = serial * 10 + (ch - '0');
    }
    for (&dirfds) |*d| {
        if (d.used and d.pid == pid and d.serial == serial) {
            // Memoise the duplicate under its own number.
            trackFd(pid, fd, d.fid, d.is_dir, trackedPath(d));
            if (findExact(pid, fd)) |copy| {
                copy.serial = serial;
                copy.cookie = d.cookie;
                return copy;
            }
            return d;
        }
    }
    return null;
}

/// The part of an absolute path below the root prefix, or null.
fn under(path: []const u8) ?[]const u8 {
    if (path.len < root.len) return null;
    if (!std.mem.eql(u8, path[0..root.len], root)) return null;
    if (path.len == root.len) return path[path.len..];
    if (path[root.len] != '/') return null;
    return path[root.len..];
}

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

/// `ioctl` by raw syscall rather than through libc.
///
/// The request numbers here have the high bit set (`SECCOMP_IOCTL_NOTIF_RECV`
/// is 0xc0502100), and the two libcs disagree about the parameter's type:
/// glibc's `ioctl` takes `unsigned long`, musl's takes `int`. Passing the
/// constant through libc therefore fails to compile against musl and would
/// sign-extend if forced. The syscall takes an unsigned long on every ABI, so
/// going straight to it is both portable and one fewer thing to reason about.
/// `ioctl` is not in the trapped set, so the supervisor may call it freely.
const SYS_ioctl = 16;

fn ioctl(fd: i32, request: u64, arg: usize) isize {
    return p9.syscall3(SYS_ioctl, @intCast(fd), @intCast(request), arg);
}

fn respond(id: u64, val: i64, err: i32) void {
    var resp = c.struct_seccomp_notif_resp{ .id = id, .val = val, .@"error" = err, .flags = 0 };
    _ = ioctl(listener, c.SECCOMP_IOCTL_NOTIF_SEND, @intFromPtr(&resp));
}

/// Let the kernel run the syscall as it stands. Used for everything the
/// supervisor decides is not its business.
fn passthrough(id: u64) void {
    var resp = c.struct_seccomp_notif_resp{
        .id = id,
        .val = 0,
        .@"error" = 0,
        .flags = c.SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    _ = ioctl(listener, c.SECCOMP_IOCTL_NOTIF_SEND, @intFromPtr(&resp));
}

/// Install `fd` into the tracee and return the number it landed on there.
fn addFd(id: u64, fd: i32) i32 {
    var req = c.struct_seccomp_notif_addfd{
        .id = id,
        .flags = 0,
        .srcfd = @intCast(fd),
        .newfd = 0,
        .newfd_flags = 0,
    };
    const got = ioctl(listener, c.SECCOMP_IOCTL_NOTIF_ADDFD, @intFromPtr(&req));
    return @intCast(got);
}

/// Still the same syscall we were notified about?
///
/// Between the notification arriving and this supervisor acting on it, the
/// traced thread can be killed and its pid reused — at which point every
/// address read out of "its" memory belongs to somebody else. This is the
/// check that makes reading tracee memory sound rather than probably-fine,
/// and it has to happen *after* the read, not before.
fn stillValid(id: u64) bool {
    var copy = id;
    return ioctl(listener, c.SECCOMP_IOCTL_NOTIF_ID_VALID, @intFromPtr(&copy)) == 0;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

var scratch: [1 << 20]u8 = undefined;
var pathbuf: [4096]u8 = undefined;

fn handleOpenat(notif: *const c.struct_seccomp_notif) void {
    openCommon(notif, notif.data.args[1]);
}

/// Legacy `open(path, flags, mode)` — the path is argument 0, not 1.
fn handleOpen(notif: *const c.struct_seccomp_notif) void {
    openCommon(notif, notif.data.args[0]);
}

fn openCommon(notif: *const c.struct_seccomp_notif, path_addr: u64) void {
    const pid: i32 = @intCast(notif.pid);
    const dirfd: i32 = @bitCast(@as(u32, @truncate(notif.data.args[0])));
    const raw = readTraceePath(pid, path_addr, &pathbuf) orelse return passthrough(notif.id);
    if (!stillValid(notif.id)) return;
    var joinbuf: [1024]u8 = undefined;
    // For legacy `open` the first argument is the path, not a dirfd; `resolve`
    // only consults `dirfd` for a *relative* path, and a legacy `open` with a
    // relative path is not something this spike claims either way.
    const rel = resolve(pid, dirfd, raw, &joinbuf) orelse return passthrough(notif.id);

    var qid: p9.Qid = undefined;
    const fid = client.walk(rel, &qid) catch return respond(notif.id, 0, -client.last_errno);

    if ((qid.qtype & p9.P9_QTDIR) != 0) {
        dbg("  dir: walked {s} fid={d}", .{ rel, fid });
        _ = client.lopen(fid, 0) catch {
            dbg("  dir: lopen failed errno={d}", .{client.last_errno});
            client.clunk(fid);
            return respond(notif.id, 0, -client.last_errno);
        };
        // A directory cannot usefully be a memfd — `getdents64` on one is
        // ENOTDIR whatever the contents — so the tracee gets a placeholder
        // descriptor and `getdents64` against it is trapped and answered
        // below.
        //
        // The placeholder is a `memfd` and **not** an `open("/dev/null")`,
        // which is what this originally was. `open` is `openat`, `openat` is
        // in the trapped set, and a supervisor that makes a trapped syscall
        // suspends itself waiting for a reply only it can send. Witnessed as a
        // total hang the moment anything opened a directory: the tracee had
        // already read two files correctly, and its output was still sitting
        // in a stdio buffer, so it looked like a failure much earlier than it
        // was. This is the rule in the file header, and this line is where it
        // was broken.
        const serial = next_serial;
        next_serial += 1;
        var namebuf: [32]u8 = undefined;
        const name = std.fmt.bufPrintZ(&namebuf, "mx-{d}", .{serial}) catch return respond(notif.id, 0, -c.EIO);
        const placeholder: i32 = blk: {
            const m = p9.syscall3(p9.SYS_memfd_create, @intFromPtr(name.ptr), 0, 0);
            if (m < 0) break :blk -1;
            break :blk @intCast(m);
        };
        if (placeholder < 0) {
            client.clunk(fid);
            return respond(notif.id, 0, -c.EMFILE);
        }
        dbg("  dir: placeholder={d} serial={d}", .{ placeholder, serial });
        const newfd = addFd(notif.id, placeholder);
        dbg("  dir: addfd -> {d}", .{newfd});
        _ = c.close(placeholder);
        if (newfd < 0) {
            client.clunk(fid);
            return respond(notif.id, 0, -c.EIO);
        }
        trackFd(pid, newfd, fid, true, rel);
        if (findExact(pid, newfd)) |d| d.serial = serial;
        return respond(notif.id, newfd, 0);
    }

    _ = client.lopen(fid, 0) catch {
        client.clunk(fid);
        return respond(notif.id, 0, -client.last_errno);
    };
    const serial = next_serial;
    next_serial += 1;
    var namebuf: [32]u8 = undefined;
    const name = std.fmt.bufPrintZ(&namebuf, "mx-{d}", .{serial}) catch {
        client.clunk(fid);
        return respond(notif.id, 0, -c.EIO);
    };
    const mem = p9.syscall3(p9.SYS_memfd_create, @intFromPtr(name.ptr), 0, 0);
    if (mem < 0) return respond(notif.id, 0, -c.ENOMEM);
    const memfd: i32 = @intCast(mem);
    defer _ = c.close(memfd);
    var offset: u64 = 0;
    while (true) {
        const got = client.read(fid, offset, &scratch) catch return respond(notif.id, 0, -c.EIO);
        if (got == 0) break;
        var written: usize = 0;
        while (written < got) {
            const w = c.write(memfd, scratch[written..].ptr, got - written);
            if (w <= 0) return respond(notif.id, 0, -c.EIO);
            written += @intCast(w);
        }
        offset += got;
    }
    _ = c.lseek(memfd, 0, c.SEEK_SET);
    const newfd = addFd(notif.id, memfd);
    if (newfd < 0) {
        client.clunk(fid);
        return respond(notif.id, 0, -c.EIO);
    }
    // The fid outlives the open so `fstat` on this descriptor can answer from
    // the driver rather than from the memfd. Without that, `cp` compares the
    // `stat` it did before opening against the `fstat` it does after, sees a
    // different inode and size-source, and refuses: "skipping file
    // '/mountx/hello.txt', as it was replaced while being copied". Witnessed —
    // and a good illustration that injecting a descriptor makes the *contents*
    // right while leaving the file's identity visibly wrong.
    trackFd(pid, newfd, fid, false, rel);
    if (findExact(pid, newfd)) |d| d.serial = serial;
    dbg("  -> open file {s} fd={d} serial={d}", .{ rel, newfd, serial });
    respond(notif.id, newfd, 0);
}

/// `struct stat` as x86-64 Linux lays it out. Transcribed from the kernel's
/// `arch/x86/include/uapi/asm/stat.h`, not from a host header, because these
/// bytes are written into *another process's* memory and the layout has to be
/// the kernel's rather than whatever this binary's libc believes.
const KernelStat = extern struct {
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

fn handleFstatat(notif: *const c.struct_seccomp_notif) void {
    const pid: i32 = @intCast(notif.pid);
    const dirfd: i32 = @bitCast(@as(u32, @truncate(notif.data.args[0])));
    const flags: u32 = @truncate(notif.data.args[3]);
    const raw = readTraceePath(pid, notif.data.args[1], &pathbuf) orelse return passthrough(notif.id);
    if (!stillValid(notif.id)) return;

    if (raw.len == 0 and (flags & AT_EMPTY_PATH) != 0) {
        // `fstat`-by-another-name against one of our descriptors.
        const d = findDir(pid, dirfd) orelse return passthrough(notif.id);
        const a = client.getattr(d.fid) catch return respond(notif.id, 0, -client.last_errno);
        return writeStat(notif, a);
    }
    var joinbuf: [1024]u8 = undefined;
    const rel = resolve(pid, dirfd, raw, &joinbuf) orelse return passthrough(notif.id);
    const fid = client.walk(rel, null) catch return respond(notif.id, 0, -client.last_errno);
    defer client.clunk(fid);
    const a = client.getattr(fid) catch return respond(notif.id, 0, -client.last_errno);
    writeStat(notif, a);
}

/// `fstat(fd, statbuf)` — a different argument shape from `newfstatat`, which
/// is the whole reason it needs a handler of its own rather than a case in one.
fn handleFstat(notif: *const c.struct_seccomp_notif) void {
    const pid: i32 = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.args[0])));
    const d = findDir(pid, fd) orelse return passthrough(notif.id);
    const a = client.getattr(d.fid) catch return respond(notif.id, 0, -client.last_errno);
    writeStatTo(notif, a, notif.data.args[1]);
}

fn writeStat(notif: *const c.struct_seccomp_notif, a: p9.Attr) void {
    writeStatTo(notif, a, notif.data.args[2]);
}

/// Legacy `stat(path, statbuf)` / `lstat(path, statbuf)`.
fn handleStat(notif: *const c.struct_seccomp_notif) void {
    const pid: i32 = @intCast(notif.pid);
    const raw = readTraceePath(pid, notif.data.args[0], &pathbuf) orelse return passthrough(notif.id);
    if (!stillValid(notif.id)) return;
    const rel = under(raw) orelse return passthrough(notif.id);
    const fid = client.walk(rel, null) catch return respond(notif.id, 0, -client.last_errno);
    defer client.clunk(fid);
    const a = client.getattr(fid) catch return respond(notif.id, 0, -client.last_errno);
    writeStatTo(notif, a, notif.data.args[1]);
}

fn writeStatTo(notif: *const c.struct_seccomp_notif, a: p9.Attr, remote: u64) void {
    dbg("  -> stat ino={d} size={d} mode={o}", .{ a.qid.path, a.size, a.mode });
    var st = std.mem.zeroes(KernelStat);
    // Must agree with what `handleStatx` reports, and `statx` reports a
    // major/minor *pair* that glibc recomposes with `makedev()`. A raw
    // `st_dev` of 0x6d78 against major 0 / minor 0x6d78 recomposes to
    // 0x6d00078, not 0x6d78 — so `cp` compared the `stat` it did before
    // opening against the `fstat` it did after, saw two different devices, and
    // refused: "skipping file ... as it was replaced while being copied".
    // Keeping the minor inside 8 bits makes `makedev(0, minor) == minor` and
    // the two paths agree by construction.
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
    const bytes: [*]const u8 = @ptrCast(&st);
    if (!stillValid(notif.id)) return;
    if (!writeTracee(@intCast(notif.pid), remote, bytes[0..@sizeOf(KernelStat)])) {
        return respond(notif.id, 0, -c.EFAULT);
    }
    respond(notif.id, 0, 0);
}

/// `struct statx`, from the kernel's `include/uapi/linux/stat.h`. Only the
/// fields this supervisor fills are named; the tail is zeroed.
const KernelStatx = extern struct {
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

    const Timestamp = extern struct { sec: i64, nsec: u32, __pad: i32 };
};

/// The made-up device every file here reports, as a minor number with major 0.
/// Deliberately under 256 so `makedev(0, n) == n` and the `stat` and `statx`
/// forms cannot disagree — see `writeStatTo`.
const FAKE_DEV_MINOR: u64 = 0x78;

/// `STATX_BASIC_STATS` — the fields a `struct stat` has.
const STATX_BASIC_STATS: u32 = 0x0000_07ff;

fn handleStatx(notif: *const c.struct_seccomp_notif) void {
    const pid: i32 = @intCast(notif.pid);
    const dirfd: i32 = @bitCast(@as(u32, @truncate(notif.data.args[0])));
    const flags: u32 = @truncate(notif.data.args[2]);
    const raw = readTraceePath(pid, notif.data.args[1], &pathbuf) orelse return passthrough(notif.id);
    if (!stillValid(notif.id)) return;

    var a: p9.Attr = undefined;
    if (raw.len == 0 and (flags & AT_EMPTY_PATH) != 0) {
        const d = findDir(pid, dirfd) orelse return passthrough(notif.id);
        a = client.getattr(d.fid) catch return respond(notif.id, 0, -client.last_errno);
    } else {
        var joinbuf: [1024]u8 = undefined;
        const rel = resolve(pid, dirfd, raw, &joinbuf) orelse return passthrough(notif.id);
        const fid = client.walk(rel, null) catch return respond(notif.id, 0, -client.last_errno);
        defer client.clunk(fid);
        a = client.getattr(fid) catch return respond(notif.id, 0, -client.last_errno);
    }

    var stx = std.mem.zeroes(KernelStatx);
    stx.stx_mask = STATX_BASIC_STATS;
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
    if (!stillValid(notif.id)) return;
    if (!writeTracee(pid, notif.data.args[4], bytes[0..@sizeOf(KernelStatx)])) {
        return respond(notif.id, 0, -c.EFAULT);
    }
    respond(notif.id, 0, 0);
}

/// `struct linux_dirent64` — the packed form `getdents64` writes. Variable
/// length, so it is built by hand rather than declared.
fn handleGetdents(notif: *const c.struct_seccomp_notif) void {
    const pid: i32 = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.args[0])));
    const d = findDir(pid, fd) orelse return passthrough(notif.id);
    if (!d.is_dir) return respond(notif.id, 0, -c.ENOTDIR);
    const remote = notif.data.args[1];
    const cap: usize = @min(@as(usize, @truncate(notif.data.args[2])), scratch.len / 2);

    var block: [32 * 1024]u8 = undefined;
    const got = client.readdir(d.fid, d.cookie, &block) catch return respond(notif.id, 0, -c.EIO);
    if (got == 0) return respond(notif.id, 0, 0); // end of directory

    var out: usize = 0;
    var r = p9.Reader{ .buf = block[0..got] };
    while (r.at < got) {
        const qid = p9.Qid.read(&r) catch break;
        const offset = r.u64v() catch break;
        const dtype = r.u8v() catch break;
        const name = r.str() catch break;
        // d_ino[8] d_off[8] d_reclen[2] d_type[1] d_name[] NUL, padded to 8.
        const reclen = (19 + name.len + 1 + 7) & ~@as(usize, 7);
        if (out + reclen > cap) break;
        const rec = scratch[out .. out + reclen];
        @memset(rec, 0);
        std.mem.writeInt(u64, rec[0..8], qid.path, .little);
        std.mem.writeInt(u64, rec[8..16], offset, .little);
        std.mem.writeInt(u16, rec[16..18], @intCast(reclen), .little);
        rec[18] = dtype;
        @memcpy(rec[19 .. 19 + name.len], name);
        out += reclen;
        d.cookie = offset;
    }
    if (out == 0) return respond(notif.id, 0, 0);
    if (!stillValid(notif.id)) return;
    if (!writeTracee(pid, remote, scratch[0..out])) return respond(notif.id, 0, -c.EFAULT);
    respond(notif.id, @intCast(out), 0);
}

// ---------------------------------------------------------------------------

/// Entry point in C's shape rather than Zig's, because this binary links libc
/// and needs `argv` exactly as the kernel laid it out — it is passed straight
/// to `execvp` with only the leading arguments removed.
pub export fn main(argc: c_int, cargv: [*][*:0]u8) c_int {
    // trace <9p-socket> <root> -- <command> [args...]
    if (argc < 5) die("usage: trace <9p-socket> <root> -- <command> [args...]", .{});
    const sock = cargv[1];
    root = std.mem.span(@as([*:0]const u8, cargv[2]));
    if (!std.mem.eql(u8, std.mem.span(@as([*:0]const u8, cargv[3])), "--")) {
        die("expected -- before the command", .{});
    }
    // `execvp` wants a NULL-terminated vector; argv already is one, so the
    // command's slice of it can be handed over as-is.
    const child_argv: [*:null]?[*:0]u8 = @ptrCast(cargv + 4);

    // Before the filter, deliberately: connecting afterwards would mean the
    // supervisor making syscalls under its own filter.
    client.connect(std.mem.span(@as([*:0]const u8, sock))) catch
        die("could not connect to the 9P socket {s}", .{sock});

    debug = c.getenv("MOUNTX_TRACE_DEBUG") != null;
    listener = installFilter();

    const pid = c.fork();
    if (pid < 0) die("fork failed", .{});
    if (pid == 0) {
        // Inherits the filter. Its trapped syscalls arrive on the listener the
        // parent is already holding — no descriptor is passed anywhere.
        _ = c.execvp(child_argv[0].?, @ptrCast(child_argv));
        die("could not exec {s}", .{child_argv[0].?});
    }

    var notif: c.struct_seccomp_notif = undefined;
    while (true) {
        // A dead tracee means the loop is done; check before blocking again.
        var status: c_int = 0;
        if (c.waitpid(pid, &status, c.WNOHANG) == pid) break;
        @memset(@as([*]u8, @ptrCast(&notif))[0..@sizeOf(c.struct_seccomp_notif)], 0);
        if (ioctl(listener, c.SECCOMP_IOCTL_NOTIF_RECV, @intFromPtr(&notif)) != 0) {
            const err = c.__errno_location().*;
            if (err == c.EINTR) continue;
            break; // ENOENT: the traced process is gone
        }
        dbg("nr={d} pid={d} args=({d},{x},{x})", .{ notif.data.nr, notif.pid, notif.data.args[0], notif.data.args[1], notif.data.args[2] });
        switch (notif.data.nr) {
            @as(c_int, @intCast(SYS_openat)) => handleOpenat(&notif),
            @as(c_int, @intCast(SYS_newfstatat)) => handleFstatat(&notif),
            @as(c_int, @intCast(SYS_statx)) => handleStatx(&notif),
            @as(c_int, @intCast(SYS_getdents64)) => handleGetdents(&notif),
            @as(c_int, @intCast(SYS_fstat)) => handleFstat(&notif),
            @as(c_int, @intCast(SYS_open)) => handleOpen(&notif),
            @as(c_int, @intCast(SYS_stat)), @as(c_int, @intCast(SYS_lstat)) => handleStat(&notif),
            else => passthrough(notif.id),
        }
    }

    var final: c_int = 0;
    _ = c.waitpid(pid, &final, 0);
    return if ((final & 0x7f) == 0) (final >> 8) & 0xff else 128 + (final & 0x7f);
}
