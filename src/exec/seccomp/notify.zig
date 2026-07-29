//! The seccomp user-notification mechanism itself: the filter, the listener,
//! and the two ways the supervisor touches a tracee (its memory and its
//! `/proc` entry).
//!
//! ### Why the listener now crosses a socket
//!
//! The spike installed the filter on the supervisor *itself* and forked,
//! because a seccomp filter is inherited across `fork` and `exec` and that
//! avoided passing a descriptor anywhere. It cost one rule the file had to
//! keep: **the supervisor may never make a trapped syscall**, since it would
//! suspend itself waiting for a reply only it could send. That rule is what
//! kept `close` out of the trapped set — and leaving `close` untrapped costs
//! correctness, not just memory: descriptor numbers are reused immediately, so
//! a stale mapping shadows a live one.
//!
//! So the shape is inverted here, into the one `native/src/main.zig` already
//! implements for `fusermount3`: **fork, have the *child* install the filter,
//! and hand the listener back over `SCM_RIGHTS`**. The supervisor then carries
//! no filter at all and may call anything, which is what makes trapping
//! `close`, `read`, `write`, `mmap` and the rest possible. The `cmsg`
//! arithmetic below is transcribed from `include/linux/socket.h`, exactly as it
//! is there — the kernel's own definitions rather than glibc's wrappers, since
//! this binary must build against musl too.

const std = @import("std");
const linux = std.os.linux;

const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("sys/ioctl.h");
    @cInclude("sys/prctl.h");
    @cInclude("linux/seccomp.h");
    @cInclude("linux/filter.h");
    @cInclude("errno.h");
});

pub const Notif = c.struct_seccomp_notif;
pub const NotifResp = c.struct_seccomp_notif_resp;
pub const NotifAddfd = c.struct_seccomp_notif_addfd;

/// `EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE` — 62 | 0x80000000 |
/// 0x40000000, from `linux/audit.h`. Transcribed rather than `@cImport`ed
/// because it overflows a C `int` and does not survive translation.
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// BPF instruction classes, from `linux/bpf_common.h`.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
/// `offsetof(struct seccomp_data, ...)`.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

/// `ioctl` by raw syscall rather than through libc.
///
/// The request numbers here have the high bit set (`SECCOMP_IOCTL_NOTIF_RECV`
/// is 0xc0502100) and the two libcs disagree about the parameter's type:
/// glibc's `ioctl` takes `unsigned long`, musl's takes `int`. Passing the
/// constant through libc therefore fails to compile against musl and would
/// sign-extend if forced. The syscall takes an unsigned long on every ABI.
const SYS_ioctl: usize = 16;

fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (n),
          [arg1] "{rdi}" (a1),
          [arg2] "{rsi}" (a2),
          [arg3] "{rdx}" (a3),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn ioctl(fd: i32, request: u64, arg: usize) isize {
    return syscall3(SYS_ioctl, @intCast(fd), @intCast(request), arg);
}

/// The listener, once the handshake below has delivered it.
var listener: i32 = -1;

pub fn setListener(fd: i32) void {
    listener = fd;
}

pub fn listenerFd() i32 {
    return listener;
}

// ---------------------------------------------------------------------------
// The filter
// ---------------------------------------------------------------------------

/// Build and install a filter trapping exactly `trapped`, and return the
/// listener. Called **in the child**, which then hands the listener back.
///
/// The arch check is first and refuses to interpret a syscall table that is not
/// the one these numbers belong to: a 32-bit call arriving on an x86-64 kernel
/// has entirely different numbers, and answering it as if it did not would be
/// worse than letting it through.
pub fn installFilter(trapped: []const u32) !i32 {
    var prog: [6 + 128]c.struct_sock_filter = undefined;
    if (trapped.len > 128) return error.TooManySyscalls;
    var n: usize = 0;
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
    const count: usize = trapped.len;
    for (trapped, 0..) |nr, i| {
        prog[n] = .{ .code = BPF_JMP_JEQ_K, .jt = @intCast(count - i), .jf = 0, .k = nr };
        n += 1;
    }
    prog[n] = .{ .code = BPF_RET_K, .jt = 0, .jf = 0, .k = c.SECCOMP_RET_ALLOW };
    n += 1;
    prog[n] = .{ .code = BPF_RET_K, .jt = 0, .jf = 0, .k = c.SECCOMP_RET_USER_NOTIF };
    n += 1;

    const fprog = c.struct_sock_fprog{ .len = @intCast(n), .filter = &prog };
    // Without `no_new_privs` an unprivileged process may not install a filter
    // at all — the kernel's guard against using seccomp to confuse a setuid
    // binary it then execs. Setting it is irreversible and inherited across
    // `exec`, which is exactly the intent: the traced command runs under it.
    if (c.prctl(c.PR_SET_NO_NEW_PRIVS, @as(c_ulong, 1), @as(c_ulong, 0), @as(c_ulong, 0), @as(c_ulong, 0)) != 0) {
        return error.NoNewPrivs;
    }
    const rc = linux.syscall3(
        .seccomp,
        c.SECCOMP_SET_MODE_FILTER,
        c.SECCOMP_FILTER_FLAG_NEW_LISTENER,
        @intFromPtr(&fprog),
    );
    const signed: isize = @bitCast(rc);
    if (signed < 0) return error.SeccompFailed;
    return @intCast(signed);
}

// ---------------------------------------------------------------------------
// cmsg(3) arithmetic — include/linux/socket.h, the same transcription
// `native/src/main.zig` carries for the `fusermount3` handshake.
// ---------------------------------------------------------------------------

const CMSG_ALIGNMENT = @sizeOf(usize);

fn cmsgAlign(length: usize) usize {
    return (length + CMSG_ALIGNMENT - 1) & ~@as(usize, CMSG_ALIGNMENT - 1);
}

const CMSG_DATA_OFFSET = cmsgAlign(@sizeOf(linux.cmsghdr));

fn cmsgLen(payload: usize) usize {
    return CMSG_DATA_OFFSET + payload;
}

fn cmsgSpace(payload: usize) usize {
    return CMSG_DATA_OFFSET + cmsgAlign(payload);
}

const ONE_FD_SPACE = cmsgSpace(@sizeOf(i32));

const ControlBuffer = extern struct {
    bytes: [ONE_FD_SPACE]u8 align(@alignOf(linux.cmsghdr)),

    fn header(self: *ControlBuffer) *linux.cmsghdr {
        return @ptrCast(&self.bytes);
    }

    fn payload(self: *ControlBuffer) *align(CMSG_ALIGNMENT) i32 {
        return @alignCast(@ptrCast(&self.bytes[CMSG_DATA_OFFSET]));
    }
};

/// `socketpair(AF_UNIX, SOCK_STREAM, 0)` — no `SOCK_CLOEXEC`, because the whole
/// point of this pair is that the forked child inherits its end.
pub fn socketpair() ![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return error.SocketPair;
    return fds;
}

/// One descriptor, one byte of payload. The byte is mandatory: `unix(7)` will
/// not carry ancillary data on an empty message.
pub fn sendFd(socket: i32, fd: i32) !void {
    var control: ControlBuffer = undefined;
    control.header().* = .{
        .len = cmsgLen(@sizeOf(i32)),
        .level = linux.SOL.SOCKET,
        .type = linux.SCM.RIGHTS,
    };
    control.payload().* = fd;

    var byte: u8 = 0;
    const iov = [1]std.posix.iovec_const{.{ .base = @ptrCast(&byte), .len = 1 }};
    const message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = cmsgLen(@sizeOf(i32)),
        .flags = 0,
    };
    while (true) {
        const rc = linux.sendmsg(socket, &message, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => return error.SendFd,
        }
    }
}

/// The other half. `MSG_CMSG_CLOEXEC` keeps the listener out of anything this
/// process spawns later.
pub fn recvFd(socket: i32) !i32 {
    var control: ControlBuffer = undefined;
    var byte: u8 = 0;
    var iov = [1]std.posix.iovec{.{ .base = @ptrCast(&byte), .len = 1 }};
    var message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = ONE_FD_SPACE,
        .flags = 0,
    };
    const received = while (true) {
        const rc = linux.recvmsg(socket, &message, linux.MSG.CMSG_CLOEXEC);
        switch (linux.errno(rc)) {
            .SUCCESS => break rc,
            .INTR => continue,
            else => return error.RecvFd,
        }
    };
    if (received == 0) return error.PeerClosed;
    if (message.flags & linux.MSG.CTRUNC != 0) return error.Truncated;
    if (message.controllen < cmsgLen(@sizeOf(i32))) return error.NoDescriptor;
    const header = control.header();
    if (header.level != linux.SOL.SOCKET or header.type != linux.SCM.RIGHTS) {
        return error.NotScmRights;
    }
    return control.payload().*;
}

// ---------------------------------------------------------------------------
// Talking to the listener
// ---------------------------------------------------------------------------

/// Block until a notification arrives, or until `timeout_ms` passes with none.
///
/// The spike blocked in `SECCOMP_IOCTL_NOTIF_RECV` and checked `waitpid` before
/// re-entering it, which cannot notice a tracee that dies while the supervisor
/// is parked inside the ioctl. Polling first makes the loop's exit condition
/// checkable on a timer without ever leaving a notification unanswered.
pub fn wait(timeout_ms: i32) enum { ready, idle, failed } {
    var fds = [1]linux.pollfd{.{ .fd = listener, .events = linux.POLL.IN, .revents = 0 }};
    const rc = linux.poll(&fds, 1, timeout_ms);
    return switch (linux.errno(rc)) {
        .SUCCESS => if (rc == 0) .idle else .ready,
        .INTR => .idle,
        else => .failed,
    };
}

/// Take the next notification. False means the listener is done: every tracee
/// that could have sent one is gone.
pub fn receive(notif: *Notif) bool {
    @memset(@as([*]u8, @ptrCast(notif))[0..@sizeOf(Notif)], 0);
    return ioctl(listener, c.SECCOMP_IOCTL_NOTIF_RECV, @intFromPtr(notif)) == 0;
}

/// Answer a notification with a return value or an errno. Exactly one of these
/// (or one `passthrough`) happens per notification, which is the errno
/// discipline `AGENTS.md` states, met at the syscall boundary.
pub fn respond(id: u64, val: i64, err: i32) void {
    var resp = NotifResp{ .id = id, .val = val, .@"error" = err, .flags = 0 };
    _ = ioctl(listener, c.SECCOMP_IOCTL_NOTIF_SEND, @intFromPtr(&resp));
}

/// Let the kernel run the syscall as it stands.
pub fn passthrough(id: u64) void {
    var resp = NotifResp{
        .id = id,
        .val = 0,
        .@"error" = 0,
        .flags = c.SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    _ = ioctl(listener, c.SECCOMP_IOCTL_NOTIF_SEND, @intFromPtr(&resp));
}

/// Install `fd` into the tracee and return the number it landed on there.
pub fn addFd(id: u64, fd: i32) i32 {
    var req = NotifAddfd{
        .id = id,
        .flags = 0,
        .srcfd = @intCast(fd),
        .newfd = 0,
        .newfd_flags = 0,
    };
    const got = ioctl(listener, c.SECCOMP_IOCTL_NOTIF_ADDFD, @intFromPtr(&req));
    if (got < 0) return -1;
    return @intCast(got);
}

/// Still the same syscall we were notified about?
///
/// Between the notification arriving and the supervisor acting on it, the
/// traced thread can be killed and its pid reused — at which point every
/// address read out of "its" memory belongs to somebody else. This is the check
/// that makes reading tracee memory sound rather than probably-fine, and it has
/// to happen *after* the read, not before.
pub fn stillValid(id: u64) bool {
    var copy = id;
    return ioctl(listener, c.SECCOMP_IOCTL_NOTIF_ID_VALID, @intFromPtr(&copy)) == 0;
}

// ---------------------------------------------------------------------------
// Tracee memory
// ---------------------------------------------------------------------------

pub fn readTracee(pid: i32, remote: u64, into: []u8) bool {
    if (into.len == 0) return true;
    const liov = [1]std.posix.iovec{.{ .base = into.ptr, .len = into.len }};
    const riov = [1]std.posix.iovec_const{.{ .base = @ptrFromInt(remote), .len = into.len }};
    const rc = linux.process_vm_readv(pid, &liov, &riov, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    return rc == into.len;
}

pub fn writeTracee(pid: i32, remote: u64, from: []const u8) bool {
    if (from.len == 0) return true;
    const liov = [1]std.posix.iovec_const{.{ .base = from.ptr, .len = from.len }};
    const riov = [1]std.posix.iovec_const{.{ .base = @ptrFromInt(remote), .len = from.len }};
    const rc = linux.process_vm_writev(pid, &liov, &riov, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    return rc == from.len;
}

/// A NUL-terminated string out of the tracee, one page-safe chunk at a time.
///
/// Reading a path from another process is the one genuinely delicate part of
/// this mechanism. **Every read is clamped to the end of the current page**: a
/// path can sit anywhere, including the last few bytes of a mapping — an argv
/// or envp string lives at the very top of the stack — and `process_vm_readv`
/// fails the *whole* request if any part of it is unmapped. Reading a fixed 64
/// bytes therefore fails intermittently depending on where ASLR put the string,
/// which is exactly how this showed up in the spike: a raw-syscall probe opened
/// two files fine and then could not open a directory.
pub fn readTraceePath(pid: i32, remote: u64, into: []u8) ?[]const u8 {
    if (remote == 0) return null;
    var got: usize = 0;
    while (got < into.len) {
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
// /proc, for the three things a notification does not carry
// ---------------------------------------------------------------------------

/// What `/proc/<tid>/status` answers about a thread.
pub const ProcInfo = struct {
    /// The thread group — i.e. the *process*, which is what owns descriptors.
    tgid: i32,
    ppid: i32,
    umask: u32,
};

fn readSmallFile(path: [:0]const u8, into: []u8) ?[]const u8 {
    const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    const handle: i32 = @intCast(fd);
    defer _ = linux.close(handle);
    var at: usize = 0;
    while (at < into.len) {
        const rc = linux.read(handle, into.ptr + at, into.len - at);
        if (linux.errno(rc) != .SUCCESS) return null;
        if (rc == 0) break;
        at += rc;
    }
    return into[0..at];
}

fn fieldValue(text: []const u8, name: []const u8) ?[]const u8 {
    var at: usize = 0;
    while (at < text.len) {
        const end = std.mem.indexOfScalarPos(u8, text, at, '\n') orelse text.len;
        const line = text[at..end];
        if (std.mem.startsWith(u8, line, name)) {
            var value = line[name.len..];
            while (value.len > 0 and (value[0] == ' ' or value[0] == '\t')) value = value[1..];
            return value;
        }
        at = end + 1;
    }
    return null;
}

fn parseInt(comptime T: type, text: []const u8, base: u8) ?T {
    var value: T = 0;
    var any = false;
    for (text) |ch| {
        const digit: u8 = switch (ch) {
            '0'...'9' => ch - '0',
            'a'...'f' => ch - 'a' + 10,
            'A'...'F' => ch - 'A' + 10,
            else => break,
        };
        if (digit >= base) break;
        value = value * base + digit;
        any = true;
    }
    return if (any) value else null;
}

/// `Tgid`, `PPid` and `Umask` in one read.
///
/// **`seccomp_notif.pid` is a thread id, not a process id** (the kernel fills it
/// with `task_pid_vnr`), and descriptors, the working directory and the umask
/// all belong to the *thread group*. A supervisor that keyed its tables on the
/// notification's `pid` would lose every descriptor the moment a second thread
/// touched it — which is precisely the multi-threaded tracee this has to serve.
pub fn procInfo(tid: i32) ?ProcInfo {
    var name: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&name, "/proc/{d}/status", .{tid}) catch return null;
    var buf: [4096]u8 = undefined;
    const text = readSmallFile(path, &buf) orelse return null;
    const tgid = parseInt(i32, fieldValue(text, "Tgid:") orelse return null, 10) orelse return null;
    const ppid = parseInt(i32, fieldValue(text, "PPid:") orelse "0", 10) orelse 0;
    const umask = if (fieldValue(text, "Umask:")) |value|
        parseInt(u32, value, 8) orelse 0
    else
        0;
    return .{ .tgid = tgid, .ppid = ppid, .umask = umask };
}

/// What `/proc/<pid>/fd/<n>` points at, for the descriptor-identity walk.
pub fn fdLink(pid: i32, fd: i32, into: []u8) ?[]const u8 {
    var name: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&name, "/proc/{d}/fd/{d}", .{ pid, fd }) catch return null;
    const rc = linux.readlink(path, into.ptr, into.len);
    if (linux.errno(rc) != .SUCCESS) return null;
    return into[0..rc];
}
