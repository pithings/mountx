//! The native part of rootless FUSE mounting, and deliberately nothing else.
//!
//! Unprivileged mounting on Linux goes through `fusermount3`, a setuid-root
//! helper that issues the `mount(2)` on your behalf and hands `/dev/fuse` back
//! **over `SCM_RIGHTS`**. Node cannot `recvmsg` a file descriptor. That single
//! gap is the entire reason this file exists, so it is the only thing in it:
//! three functions, no `fork`, no `execve`, no strings, no allocation.
//!
//! Spawning `fusermount3`, building its option string and every part of
//! teardown stay in JS, where they are readable and testable — see
//! `src/fuse/fusermount.ts`. Not forking from here also avoids forking a
//! multi-threaded Node process, which is the classic way to get an addon
//! subtly wrong.
//!
//! `sendFd` is not used by the library at all. It is here so the round trip
//! can be tested in one process with no `fusermount3`, no mountpoint and no
//! privileges — which is what keeps this file covered on hosts where rootless
//! mounting is impossible.

const std = @import("std");
const linux = std.os.linux;
const napi = @import("napi.zig");

/// No libc, so the default panic handler's stack-trace machinery is not
/// available. Say what happened on stderr and trap; a panic in here is a bug
/// in this file, not a condition anyone can recover from.
pub const panic = std.debug.FullPanic(struct {
    fn handler(message: []const u8, _: ?usize) noreturn {
        _ = linux.write(2, "mountx-native panic: ", 21);
        _ = linux.write(2, message.ptr, message.len);
        _ = linux.write(2, "\n", 1);
        @trap();
    }
}.handler);

// ---------------------------------------------------------------------------
// cmsg(3) arithmetic
// ---------------------------------------------------------------------------
//
// Transcribed from `include/linux/socket.h` (the kernel's own definitions, not
// glibc's wrappers). Alignment is `sizeof(size_t)`, so on 64-bit a `cmsghdr`
// is 16 bytes and one descriptor needs 20 bytes of payload in 24 of space.

const CMSG_ALIGNMENT = @sizeOf(usize);

fn cmsgAlign(length: usize) usize {
    return (length + CMSG_ALIGNMENT - 1) & ~@as(usize, CMSG_ALIGNMENT - 1);
}

/// `CMSG_ALIGN(sizeof(struct cmsghdr))` — where the payload starts.
const CMSG_DATA_OFFSET = cmsgAlign(@sizeOf(linux.cmsghdr));

/// `CMSG_LEN(n)` — the value that goes in `cmsg_len`.
fn cmsgLen(payload: usize) usize {
    return CMSG_DATA_OFFSET + payload;
}

/// `CMSG_SPACE(n)` — how much buffer one such message occupies.
fn cmsgSpace(payload: usize) usize {
    return CMSG_DATA_OFFSET + cmsgAlign(payload);
}

const ONE_FD_SPACE = cmsgSpace(@sizeOf(i32));

/// A control buffer aligned the way `cmsghdr` needs.
const ControlBuffer = extern struct {
    bytes: [ONE_FD_SPACE]u8 align(@alignOf(linux.cmsghdr)),

    fn header(self: *ControlBuffer) *linux.cmsghdr {
        return @ptrCast(&self.bytes);
    }

    fn payload(self: *ControlBuffer) *align(CMSG_ALIGNMENT) i32 {
        return @alignCast(@ptrCast(&self.bytes[CMSG_DATA_OFFSET]));
    }
};

// ---------------------------------------------------------------------------
// throwing
// ---------------------------------------------------------------------------

/// Throw a JS `Error` carrying `errno` and `syscall`.
///
/// The errno stays a raw positive number: `src/fuse/native.ts` turns it into a
/// `code` using `ERRNO_CODES` from `src/errors.ts`, so the one transcription of
/// the errno table in this repository stays the only one.
fn throwErrno(env: napi.Env, syscall: [:0]const u8, errno: u32) napi.Value {
    var buffer: [96]u8 = undefined;
    const text = std.fmt.bufPrint(
        &buffer,
        "mountx-native: {s} failed (errno {d})",
        .{ syscall, errno },
    ) catch syscall;
    var message: napi.Value = undefined;
    if (napi.napi_create_string_utf8(env, text.ptr, text.len, &message) != .ok) {
        return undefined_value(env);
    }
    var err: napi.Value = undefined;
    if (napi.napi_create_error(env, null, message, &err) != .ok) {
        return undefined_value(env);
    }
    var errno_value: napi.Value = undefined;
    if (napi.napi_create_int32(env, @intCast(errno), &errno_value) == .ok) {
        _ = napi.napi_set_named_property(env, err, "errno", errno_value);
    }
    var syscall_value: napi.Value = undefined;
    if (napi.napi_create_string_utf8(env, syscall.ptr, syscall.len, &syscall_value) == .ok) {
        _ = napi.napi_set_named_property(env, err, "syscall", syscall_value);
    }
    _ = napi.napi_throw(env, err);
    return undefined_value(env);
}

/// Throw a JS `Error` with no errno — for the failures that are not a syscall
/// saying no, but a peer behaving in a way no errno describes.
fn throwMessage(env: napi.Env, text: [:0]const u8) napi.Value {
    var message: napi.Value = undefined;
    if (napi.napi_create_string_utf8(env, text.ptr, text.len, &message) != .ok) {
        return undefined_value(env);
    }
    var err: napi.Value = undefined;
    if (napi.napi_create_error(env, null, message, &err) != .ok) {
        return undefined_value(env);
    }
    _ = napi.napi_throw(env, err);
    return undefined_value(env);
}

fn undefined_value(env: napi.Env) napi.Value {
    var result: napi.Value = undefined;
    // Nothing to do if even this fails: an exception is already pending, and
    // V8 ignores the return value of a callback that threw.
    _ = napi.napi_get_undefined(env, &result);
    return result;
}

/// Unpack exactly `count` int arguments, or throw and return null.
fn intArgs(
    env: napi.Env,
    info: napi.CallbackInfo,
    comptime count: usize,
) ?[count]i32 {
    var argv: [count]napi.Value = undefined;
    var argc: usize = count;
    if (napi.napi_get_cb_info(env, info, &argc, &argv, null, null) != .ok) {
        _ = throwMessage(env, "mountx-native: could not read arguments");
        return null;
    }
    // No arity check: Node-API fills every slot past the ones the caller
    // supplied with `undefined`, which fails the conversion below with a
    // better message than a count ever would.
    var out: [count]i32 = undefined;
    for (0..count) |index| {
        if (napi.napi_get_value_int32(env, argv[index], &out[index]) != .ok) {
            _ = throwMessage(env, "mountx-native: arguments must be numbers");
            return null;
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// the three functions
// ---------------------------------------------------------------------------

/// `socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)` → `[a, b]`.
///
/// `SOCK_CLOEXEC` is not an optimization. Both ends have to stay out of every
/// unrelated child this process spawns; the one child that needs an end gets
/// it explicitly, through the stdio map, which clears the flag on the copy it
/// makes.
fn socketpair(env: napi.Env, _: napi.CallbackInfo) callconv(.c) napi.Value {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |errno| return throwErrno(env, "socketpair", @intFromEnum(errno)),
    }
    var array: napi.Value = undefined;
    if (napi.napi_create_array_with_length(env, 2, &array) != .ok) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return throwMessage(env, "mountx-native: could not allocate the result array");
    }
    for (fds, 0..) |fd, index| {
        var value: napi.Value = undefined;
        _ = napi.napi_create_int32(env, fd, &value);
        _ = napi.napi_set_element(env, array, @intCast(index), value);
    }
    return array;
}

/// `sendFd(socket, fd)` — one descriptor, one byte of payload.
///
/// The byte is mandatory: `unix(7)` will not carry ancillary data on an empty
/// message. This mirrors `send_fd()` in libfuse's `util/fusermount.c`, which is
/// what the real sender does.
fn sendFd(env: napi.Env, info: napi.CallbackInfo) callconv(.c) napi.Value {
    const args = intArgs(env, info, 2) orelse return undefined_value(env);
    const socket = args[0];
    const fd = args[1];

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
            .SUCCESS => return undefined_value(env),
            .INTR => continue,
            else => |errno| return throwErrno(env, "sendmsg", @intFromEnum(errno)),
        }
    }
}

/// Close every descriptor the kernel installed at `start` and beyond.
///
/// Called on both the success and the truncated path, so it re-derives whether
/// there is a `SCM_RIGHTS` message here at all rather than assuming its caller
/// checked. `cmsg_len` is the kernel's, and it is clamped to the buffer rather
/// than trusted: the release build has bounds checks compiled out, so an
/// unclamped walk would hand `close(2)` whatever happened to follow on the
/// stack. The clamp is not reachable today — `controllen` bounds `cmsg_len` —
/// which is exactly why it should not depend on that staying true.
fn closeReceived(control: *ControlBuffer, controllen: usize, start: usize) void {
    if (controllen < cmsgLen(@sizeOf(i32))) return;
    const header = control.header();
    if (header.level != linux.SOL.SOCKET or header.type != linux.SCM.RIGHTS) return;
    const end = @min(header.len, ONE_FD_SPACE);
    var at = start;
    while (at + @sizeOf(i32) <= end) : (at += @sizeOf(i32)) {
        const spare: *align(1) const i32 = @ptrCast(&control.bytes[at]);
        _ = linux.close(spare.*);
    }
}

/// `recvFd(socket, timeoutMs)` → the descriptor, received `O_CLOEXEC`.
///
/// A negative timeout waits forever. The wait is a `poll(2)`, so the only
/// blocking `recvmsg` is one that already has a message queued for it — in the
/// intended sequence the sender has exited by the time this is called and the
/// descriptor is sitting in the socket buffer, so this does not block the event
/// loop at all.
///
/// `MSG_CMSG_CLOEXEC` is what keeps the crash-safety guarantee in
/// `src/fuse/mount.ts` true: the kernel tears a FUSE connection down when the
/// last reference to the `/dev/fuse` file goes away, and a descriptor that
/// leaked into some unrelated child would be exactly such a reference.
fn recvFd(env: napi.Env, info: napi.CallbackInfo) callconv(.c) napi.Value {
    const args = intArgs(env, info, 2) orelse return undefined_value(env);
    const socket = args[0];
    const timeout = args[1];

    var poll_fds = [1]linux.pollfd{.{ .fd = socket, .events = linux.POLL.IN, .revents = 0 }};
    while (true) {
        const rc = linux.poll(&poll_fds, 1, timeout);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) {
                    return throwMessage(env, "mountx-native: timed out waiting for a descriptor");
                }
            },
            // Retrying restarts the timeout. Signals are rare, the caller's
            // timeout is a backstop rather than a deadline, and the
            // alternative is clock arithmetic in a file that has no clock.
            .INTR => continue,
            else => |errno| return throwErrno(env, "poll", @intFromEnum(errno)),
        }
        break;
    }

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
            else => |errno| return throwErrno(env, "recvmsg", @intFromEnum(errno)),
        }
    };

    if (received == 0) {
        return throwMessage(env, "mountx-native: the peer closed without sending a descriptor");
    }
    // Truncation does *not* mean the descriptors are unreachable. The kernel's
    // `scm_detach_fds` installs as many as the buffer holds — here
    // `(ONE_FD_SPACE - CMSG_DATA_OFFSET) / 4`, so two — writes their numbers
    // into the control buffer, sets `cmsg_len` to cover exactly those, and only
    // then raises `MSG_CTRUNC` for the ones it dropped. The ones that arrived
    // are therefore named, and returning without closing them would pin
    // whatever they refer to for the life of the process — including, in the
    // case this exists for, a `/dev/fuse` connection with nothing serving it.
    if (message.flags & linux.MSG.CTRUNC != 0) {
        closeReceived(&control, message.controllen, CMSG_DATA_OFFSET);
        return throwMessage(env, "mountx-native: the descriptor was truncated in transit");
    }
    if (message.controllen < cmsgLen(@sizeOf(i32))) {
        return throwMessage(env, "mountx-native: the message carried no descriptor");
    }
    const header = control.header();
    if (header.level != linux.SOL.SOCKET or header.type != linux.SCM.RIGHTS) {
        return throwMessage(env, "mountx-native: the message carried something other than SCM_RIGHTS");
    }
    const fd = control.payload().*;
    // One descriptor is all `fusermount3` ever sends, but a peer that sent more
    // would leave the extras installed in this process with nothing naming
    // them. Close everything past the first.
    closeReceived(&control, message.controllen, CMSG_DATA_OFFSET + @sizeOf(i32));

    var result: napi.Value = undefined;
    if (napi.napi_create_int32(env, fd, &result) != .ok) {
        _ = linux.close(fd);
        return throwMessage(env, "mountx-native: could not return the descriptor");
    }
    return result;
}

// ---------------------------------------------------------------------------
// module registration
// ---------------------------------------------------------------------------

fn define(env: napi.Env, exports: napi.Value, comptime name: [:0]const u8, callback: napi.Callback) void {
    var value: napi.Value = undefined;
    if (napi.napi_create_function(env, name.ptr, napi.AUTO_LENGTH, callback, null, &value) != .ok) {
        return;
    }
    _ = napi.napi_set_named_property(env, exports, name.ptr, value);
}

export fn napi_register_module_v1(env: napi.Env, exports: napi.Value) napi.Value {
    define(env, exports, "socketpair", socketpair);
    define(env, exports, "sendFd", sendFd);
    define(env, exports, "recvFd", recvFd);
    return exports;
}
