//! SPIKE — a 9P2000.L client small enough to live inside an intercepted
//! process. Shared by spike B (the `LD_PRELOAD` interposer) and spike C (the
//! seccomp supervisor).
//!
//! **This file is the whole argument for the approach.** A syscall interceptor
//! that had to *implement* a filesystem would be reimplementing path
//! resolution, handle lifetimes, directory paging and error mapping — all of
//! which `src/9p/session.ts` already does, and already passes a conformance
//! column on. Speaking 9P instead makes the interceptor a *client*: it
//! translates one libc call into one or two 9P messages and translates the
//! answer back. Every filesystem question is settled on the far side of the
//! socket, in TypeScript, by code that is already tested.
//!
//! Constants and message layouts are transcribed from `src/9p/constants.ts`
//! and `src/9p/protocol.ts` in this repository, which are themselves
//! transcribed from the kernel's `include/net/9p/9p.h` at tag v6.12. Nothing
//! here is guessed and nothing is read out of a host header — the same rule
//! the TypeScript side is held to.
//!
//! Deliberately narrow for a spike: one request in flight at a time under a
//! spinlock, tag always zero, and read-mostly operations. That is enough to
//! answer the question the spikes exist to answer (can an intercepted process
//! be served at all, and by what) and nowhere near enough to ship.

// ---------------------------------------------------------------------------
// Raw syscalls.
//
// The client does its own socket I/O with `syscall` instructions rather than
// through libc, for one reason that is specific to spike B: the interposer
// *is* libc's `read`/`write` for the duration of this process, so a client
// calling `read()` on its own socket would re-enter the shim. Going straight
// to the kernel makes that structurally impossible rather than merely
// avoided.
// ---------------------------------------------------------------------------

pub const SYS_read = 0;
pub const SYS_write = 1;
pub const SYS_close = 3;
pub const SYS_lseek = 8;
pub const SYS_socket = 41;
pub const SYS_connect = 42;
pub const SYS_getpid = 39;
pub const SYS_memfd_create = 319;

pub fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (n),
          [arg1] "{rdi}" (a1),
          [arg2] "{rsi}" (a2),
          [arg3] "{rdx}" (a3),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

pub fn syscall0(n: usize) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (n),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

const AF_UNIX = 1;
const SOCK_STREAM = 1;

// ---------------------------------------------------------------------------
// Wire constants — transcribed from src/9p/constants.ts.
// ---------------------------------------------------------------------------

pub const P9_RLERROR = 7;
pub const P9_TSTATFS = 8;
pub const P9_TLOPEN = 12;
pub const P9_TLCREATE = 14;
pub const P9_TSYMLINK = 16;
pub const P9_TMKNOD = 18;
pub const P9_TRENAME = 20;
pub const P9_TREADLINK = 22;
pub const P9_TGETATTR = 24;
pub const P9_TSETATTR = 26;
pub const P9_TREADDIR = 40;
pub const P9_TFSYNC = 50;
pub const P9_TLINK = 70;
pub const P9_TMKDIR = 72;
pub const P9_TRENAMEAT = 74;
pub const P9_TUNLINKAT = 76;
pub const P9_TVERSION = 100;
pub const P9_TATTACH = 104;
pub const P9_TWALK = 110;
pub const P9_TREAD = 116;
pub const P9_TWRITE = 118;
pub const P9_TCLUNK = 120;

pub const P9_NOFID: u32 = 0xffff_ffff;
pub const P9_MAXWELEM = 16;
pub const P9_IOHDRSZ = 24;
/// `P9_GETATTR_BASIC` — everything a `struct stat` needs and nothing reserved.
pub const P9_GETATTR_BASIC: u64 = 0x0000_07ff;

/// `Tsetattr.valid` bits — `P9_ATTR_*` in the kernel's `fs/9p/vfs_inode_dotl.c`,
/// spelled after the field each one fills the way `src/9p/constants.ts` spells
/// them.
pub const P9_SETATTR_MODE: u32 = 1 << 0;
pub const P9_SETATTR_UID: u32 = 1 << 1;
pub const P9_SETATTR_GID: u32 = 1 << 2;
pub const P9_SETATTR_SIZE: u32 = 1 << 3;
pub const P9_SETATTR_ATIME: u32 = 1 << 4;
pub const P9_SETATTR_MTIME: u32 = 1 << 5;
pub const P9_SETATTR_CTIME: u32 = 1 << 6;
pub const P9_SETATTR_ATIME_SET: u32 = 1 << 7;
pub const P9_SETATTR_MTIME_SET: u32 = 1 << 8;

/// `Tunlinkat.flags` — the `AT_REMOVEDIR` of `unlinkat(2)`, and the only flag
/// the message carries.
pub const P9_DOTL_AT_REMOVEDIR: u32 = 0x200;

/// Qid type bits, the file-type half of a 9P identity.
pub const P9_QTDIR: u8 = 0x80;
pub const P9_QTSYMLINK: u8 = 0x02;

/// The kernel's own `DEFAULT_MSIZE` payload, matching what `mount9p()` picks.
pub const MSIZE: u32 = 128 * 1024 + P9_IOHDRSZ;

/// Header: `size[4] type[1] tag[2]`.
const HDR = 7;

// ---------------------------------------------------------------------------

pub const Error = error{
    Disconnected,
    Protocol,
    /// The server answered `Rlerror`; the errno is in `Client.last_errno`.
    Remote,
};

/// Little-endian, unaligned, the same shape as `src/9p/wire.ts`'s writer.
const Writer = struct {
    buf: []u8,
    at: usize = HDR,

    fn u8v(self: *Writer, v: u8) void {
        self.buf[self.at] = v;
        self.at += 1;
    }
    fn u16v(self: *Writer, v: u16) void {
        self.buf[self.at] = @truncate(v);
        self.buf[self.at + 1] = @truncate(v >> 8);
        self.at += 2;
    }
    fn u32v(self: *Writer, v: u32) void {
        var i: usize = 0;
        while (i < 4) : (i += 1) self.buf[self.at + i] = @truncate(v >> @intCast(i * 8));
        self.at += 4;
    }
    fn u64v(self: *Writer, v: u64) void {
        var i: usize = 0;
        while (i < 8) : (i += 1) self.buf[self.at + i] = @truncate(v >> @intCast(i * 8));
        self.at += 8;
    }
    fn str(self: *Writer, s: []const u8) void {
        self.u16v(@intCast(s.len));
        @memcpy(self.buf[self.at .. self.at + s.len], s);
        self.at += s.len;
    }
};

/// Bounds-checked in the sense that matters here: every read is against the
/// declared message length, and a short message answers `Protocol` rather than
/// reading into whatever the buffer held last time.
pub const Reader = struct {
    buf: []const u8,
    at: usize = 0,

    pub fn u8v(self: *Reader) Error!u8 {
        if (self.at + 1 > self.buf.len) return Error.Protocol;
        defer self.at += 1;
        return self.buf[self.at];
    }
    pub fn u16v(self: *Reader) Error!u16 {
        if (self.at + 2 > self.buf.len) return Error.Protocol;
        defer self.at += 2;
        return @as(u16, self.buf[self.at]) | (@as(u16, self.buf[self.at + 1]) << 8);
    }
    pub fn u32v(self: *Reader) Error!u32 {
        if (self.at + 4 > self.buf.len) return Error.Protocol;
        var v: u32 = 0;
        var i: usize = 0;
        while (i < 4) : (i += 1) v |= @as(u32, self.buf[self.at + i]) << @intCast(i * 8);
        self.at += 4;
        return v;
    }
    pub fn u64v(self: *Reader) Error!u64 {
        if (self.at + 8 > self.buf.len) return Error.Protocol;
        var v: u64 = 0;
        var i: usize = 0;
        while (i < 8) : (i += 1) v |= @as(u64, self.buf[self.at + i]) << @intCast(i * 8);
        self.at += 8;
        return v;
    }
    pub fn skip(self: *Reader, n: usize) Error!void {
        if (self.at + n > self.buf.len) return Error.Protocol;
        self.at += n;
    }
    pub fn str(self: *Reader) Error![]const u8 {
        const n = try self.u16v();
        if (self.at + n > self.buf.len) return Error.Protocol;
        defer self.at += n;
        return self.buf[self.at .. self.at + n];
    }
};

/// The 13 bytes of a qid: `type[1] version[4] path[8]`.
pub const Qid = struct {
    qtype: u8,
    version: u32,
    path: u64,

    pub fn read(r: *Reader) Error!Qid {
        return .{ .qtype = try r.u8v(), .version = try r.u32v(), .path = try r.u64v() };
    }
};

/// The subset of `Rgetattr` a `struct stat` is built from. Field order is
/// `src/9p/protocol.ts`'s `writeRgetattr`, which is where the widths that do
/// *not* match the C struct come from: `mode`/`uid`/`gid` are 32-bit while
/// `nlink`/`rdev`/`blksize`/`blocks` are 64.
pub const Attr = struct {
    qid: Qid,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    rdev: u64,
    size: u64,
    blksize: u64,
    blocks: u64,
    atime_sec: u64,
    mtime_sec: u64,
    ctime_sec: u64,
    atime_nsec: u64,
    mtime_nsec: u64,
    ctime_nsec: u64,
};

pub const Client = struct {
    fd: i32 = -1,
    msize: u32 = MSIZE,
    root_fid: u32 = 0,
    next_fid: u32 = 1,
    /// The errno from the most recent `Rlerror`, positive and Linux's, which
    /// is exactly what the shim needs to put in its own `errno`. 9P is the one
    /// transport in this repo with no status-mapping layer at all.
    last_errno: i32 = 0,
    /// Owning pid. `fork()` hands the child a copy of the socket, and two
    /// processes taking turns on one connection with the tag always zero is a
    /// corruption bug that only shows up under load. Checked per request.
    owner_pid: i32 = 0,
    lock: Lock = .{},
    /// Recycled fid numbers.
    ///
    /// A counter that only ever goes up is fine for a spike and wrong for a
    /// supervisor that outlives a `cp -r`: every walk takes a fid and every
    /// clunk gives one back, so without recycling a long run climbs towards
    /// `P9_NOFID` while the server holds nothing. The free list is fixed-size
    /// on purpose — this struct is embedded in a process that must not depend
    /// on an allocator — and overflowing it costs a fid number, not
    /// correctness.
    free: [256]u32 = undefined,
    free_len: usize = 0,
    buf: [MSIZE]u8 = undefined,

    pub fn connect(self: *Client, path: []const u8) Error!void {
        const fd = syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return Error.Disconnected;
        // `struct sockaddr_un`: family[2] path[108].
        var addr: [110]u8 = @splat(0);
        addr[0] = AF_UNIX;
        addr[1] = 0;
        if (path.len >= 107) return Error.Disconnected;
        @memcpy(addr[2 .. 2 + path.len], path);
        if (syscall3(SYS_connect, @intCast(fd), @intFromPtr(&addr), 2 + path.len + 1) < 0) {
            _ = syscall3(SYS_close, @intCast(fd), 0, 0);
            return Error.Disconnected;
        }
        self.fd = @intCast(fd);
        self.owner_pid = @intCast(syscall0(SYS_getpid));
        self.next_fid = 1;
        self.root_fid = 0;
        try self.version();
        try self.attach();
    }

    fn writeAll(self: *Client, bytes: []const u8) Error!void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = syscall3(SYS_write, @intCast(self.fd), @intFromPtr(bytes.ptr) + off, bytes.len - off);
            if (n <= 0) return Error.Disconnected;
            off += @intCast(n);
        }
    }

    fn readAll(self: *Client, into: []u8) Error!void {
        var off: usize = 0;
        while (off < into.len) {
            const n = syscall3(SYS_read, @intCast(self.fd), @intFromPtr(into.ptr) + off, into.len - off);
            if (n <= 0) return Error.Disconnected;
            off += @intCast(n);
        }
    }

    /// Send what the writer built, then read one whole reply into `buf`.
    /// Returns a reader positioned just past the header, and the reply type.
    fn roundTrip(self: *Client, w: *Writer, ttype: u8) Error!struct { Reader, u8 } {
        const size: u32 = @intCast(w.at);
        self.buf[0] = @truncate(size);
        self.buf[1] = @truncate(size >> 8);
        self.buf[2] = @truncate(size >> 16);
        self.buf[3] = @truncate(size >> 24);
        self.buf[4] = ttype;
        self.buf[5] = 0;
        self.buf[6] = 0;
        try self.writeAll(self.buf[0..w.at]);

        try self.readAll(self.buf[0..4]);
        var len: u32 = 0;
        var i: usize = 0;
        while (i < 4) : (i += 1) len |= @as(u32, self.buf[i]) << @intCast(i * 8);
        if (len < HDR or len > self.buf.len) return Error.Protocol;
        try self.readAll(self.buf[4..len]);
        const rtype = self.buf[4];
        var r = Reader{ .buf = self.buf[0..len], .at = HDR };
        if (rtype == P9_RLERROR) {
            self.last_errno = @intCast(try r.u32v());
            return Error.Remote;
        }
        // Every reply to `T` is `T + 1`; anything else is a desynced stream.
        if (rtype != ttype + 1) return Error.Protocol;
        return .{ r, rtype };
    }

    fn version(self: *Client) Error!void {
        var w = Writer{ .buf = &self.buf };
        w.u32v(MSIZE);
        w.str("9P2000.L");
        var got = try self.roundTrip(&w, P9_TVERSION);
        const negotiated = try got[0].u32v();
        const ver = try got[0].str();
        if (ver.len != 8 or ver[2] != '2') return Error.Protocol;
        self.msize = if (negotiated < MSIZE) negotiated else MSIZE;
    }

    fn attach(self: *Client) Error!void {
        var w = Writer{ .buf = &self.buf };
        w.u32v(self.root_fid);
        w.u32v(P9_NOFID);
        w.str("mountx");
        w.str("");
        w.u32v(0xffff_ffff);
        _ = try self.roundTrip(&w, P9_TATTACH);
    }

    pub fn allocFid(self: *Client) u32 {
        if (self.free_len > 0) {
            self.free_len -= 1;
            return self.free[self.free_len];
        }
        self.next_fid += 1;
        return self.next_fid;
    }

    /// Hand a fid number back, once the server has forgotten it.
    ///
    /// Only ever called after a `Tclunk`, because a number recycled while the
    /// server still holds it comes back as `EINVAL: fid already in use`.
    pub fn freeFid(self: *Client, fid: u32) void {
        if (self.free_len < self.free.len) {
            self.free[self.free_len] = fid;
            self.free_len += 1;
        }
    }

    /// One `Twalk` of at most `P9_MAXWELEM` names, `from` → `newfid`.
    ///
    /// Reports a *partial* walk as `ENOENT` rather than as a short reply: this
    /// client asked for a path, not a prefix, and `src/9p/session.ts` answers
    /// `Rwalk` with fewer qids rather than an error because that is the
    /// protocol's rule. `walked` is how many names actually resolved, which is
    /// what makes a caller able to tell "the first name failed" from "the
    /// fourth did" without a second round trip.
    pub fn walkOnce(
        self: *Client,
        from: u32,
        newfid: u32,
        path: []const u8,
        out_qid: ?*Qid,
        out_walked: ?*u16,
    ) Error!void {
        var w = Writer{ .buf = &self.buf };
        w.u32v(from);
        w.u32v(newfid);
        const count_at = w.at;
        w.u16v(0);
        var n: u16 = 0;
        var it = Split{ .s = path };
        while (it.next()) |part| {
            if (n >= P9_MAXWELEM) return Error.Protocol;
            w.str(part);
            n += 1;
        }
        self.buf[count_at] = @truncate(n);
        self.buf[count_at + 1] = @truncate(n >> 8);
        var got = try self.roundTrip(&w, P9_TWALK);
        const nwqid = try got[0].u16v();
        if (out_walked) |slot| slot.* = nwqid;
        var last: Qid = .{ .qtype = P9_QTDIR, .version = 0, .path = 0 };
        var i: u16 = 0;
        while (i < nwqid) : (i += 1) last = try Qid.read(&got[0]);
        if (nwqid != n) {
            self.last_errno = 2; // ENOENT
            return Error.Remote;
        }
        if (out_qid) |slot| slot.* = last;
    }

    /// Walk `path` (slash-separated, relative to the attach root) onto a fresh
    /// fid, in `P9_MAXWELEM`-sized steps. A zero-element walk clones the root
    /// fid, which is how the root itself is reached.
    ///
    /// The walk continues *in place* (`newfid == fid`) after the first step,
    /// which the protocol allows and the session treats as a clone onto
    /// itself — so a path of any depth costs one fid rather than one per 16
    /// components.
    pub fn walk(self: *Client, path: []const u8, out_qid: ?*Qid) Error!u32 {
        const newfid = self.allocFid();
        errdefer self.freeFid(newfid);
        var from = self.root_fid;
        var it = Split{ .s = path };
        var chunk: [P9_MAXWELEM]([]const u8) = undefined;
        var n: usize = 0;
        var any = false;
        var qid: Qid = .{ .qtype = P9_QTDIR, .version = 0, .path = 0 };
        while (true) {
            const part = it.next();
            if (part) |p| {
                chunk[n] = p;
                n += 1;
            }
            if (n == 0) break;
            if (part != null and n < P9_MAXWELEM) continue;
            // `chunk` holds slices of `path`, and `walkOnce` writes them into
            // the client buffer as it goes, so the join has to happen here
            // rather than by handing `walkOnce` a second path string.
            var joined: [4096]u8 = undefined;
            var at: usize = 0;
            for (chunk[0..n]) |p| {
                if (at != 0) {
                    joined[at] = '/';
                    at += 1;
                }
                if (at + p.len > joined.len) return Error.Protocol;
                @memcpy(joined[at .. at + p.len], p);
                at += p.len;
            }
            try self.walkOnce(from, newfid, joined[0..at], &qid, null);
            any = true;
            from = newfid;
            n = 0;
            if (part == null) break;
        }
        if (!any) {
            // The root itself: a zero-element walk, which clones the fid and
            // answers no qids at all — so the qid, if anybody wants one, has to
            // come from `Tgetattr` instead.
            try self.walkOnce(self.root_fid, newfid, "", null, null);
            if (out_qid != null) qid = try self.getattrQid(newfid);
        }
        if (out_qid) |slot| slot.* = qid;
        return newfid;
    }

    /// The qid of what a fid names, for the one caller that has no walk step to
    /// take it from.
    fn getattrQid(self: *Client, fid: u32) Error!Qid {
        const a = try self.getattr(fid);
        return a.qid;
    }

    pub fn clunk(self: *Client, fid: u32) void {
        var w = Writer{ .buf = &self.buf };
        w.u32v(fid);
        // Recycled only on success: a fid the server still holds comes back as
        // `EINVAL: fid already in use` on the next walk that draws it.
        if (self.roundTrip(&w, P9_TCLUNK)) |_| self.freeFid(fid) else |_| {}
    }

    pub fn getattr(self: *Client, fid: u32) Error!Attr {
        var w = Writer{ .buf = &self.buf };
        w.u32v(fid);
        w.u64v(P9_GETATTR_BASIC);
        const got = try self.roundTrip(&w, P9_TGETATTR);
        var r = got[0];
        _ = try r.u64v(); // valid
        const qid = try Qid.read(&r);
        const mode = try r.u32v();
        const uid = try r.u32v();
        const gid = try r.u32v();
        const nlink = try r.u64v();
        const rdev = try r.u64v();
        const size = try r.u64v();
        const blksize = try r.u64v();
        const blocks = try r.u64v();
        const atime_sec = try r.u64v();
        const atime_nsec = try r.u64v();
        const mtime_sec = try r.u64v();
        const mtime_nsec = try r.u64v();
        const ctime_sec = try r.u64v();
        const ctime_nsec = try r.u64v();
        return .{
            .qid = qid,
            .mode = mode,
            .uid = uid,
            .gid = gid,
            .nlink = nlink,
            .rdev = rdev,
            .size = size,
            .blksize = blksize,
            .blocks = blocks,
            .atime_sec = atime_sec,
            .atime_nsec = atime_nsec,
            .mtime_sec = mtime_sec,
            .mtime_nsec = mtime_nsec,
            .ctime_sec = ctime_sec,
            .ctime_nsec = ctime_nsec,
        };
    }

    pub fn lopen(self: *Client, fid: u32, flags: u32) Error!u32 {
        var w = Writer{ .buf = &self.buf };
        w.u32v(fid);
        w.u32v(flags);
        var got = try self.roundTrip(&w, P9_TLOPEN);
        _ = try Qid.read(&got[0]);
        return try got[0].u32v();
    }

    pub fn lcreate(self: *Client, dir_fid: u32, name: []const u8, flags: u32, mode: u32) Error!u32 {
        var w = Writer{ .buf = &self.buf };
        w.u32v(dir_fid);
        w.str(name);
        w.u32v(flags);
        w.u32v(mode);
        w.u32v(0);
        var got = try self.roundTrip(&w, P9_TLCREATE);
        _ = try Qid.read(&got[0]);
        return try got[0].u32v();
    }

    /// One `Tread`, capped at whatever the negotiated `msize` leaves room for.
    pub fn read(self: *Client, fid: u32, offset: u64, into: []u8) Error!usize {
        const room = self.msize - HDR - 4;
        const want: u32 = if (into.len > room) room else @intCast(into.len);
        var w = Writer{ .buf = &self.buf };
        w.u32v(fid);
        w.u64v(offset);
        w.u32v(want);
        var got = try self.roundTrip(&w, P9_TREAD);
        const count = try got[0].u32v();
        if (count > into.len) return Error.Protocol;
        try got[0].skip(count);
        @memcpy(into[0..count], self.buf[HDR + 4 .. HDR + 4 + count]);
        return count;
    }

    pub fn write(self: *Client, fid: u32, offset: u64, data: []const u8) Error!usize {
        const room = self.msize - HDR - 4 - 4 - 8;
        const want: usize = if (data.len > room) room else data.len;
        var w = Writer{ .buf = &self.buf };
        w.u32v(fid);
        w.u64v(offset);
        w.u32v(@intCast(want));
        @memcpy(self.buf[w.at .. w.at + want], data[0..want]);
        w.at += want;
        var got = try self.roundTrip(&w, P9_TWRITE);
        return try got[0].u32v();
    }

    /// One `Treaddir` block, copied out whole. The caller unpacks it — the
    /// entry format is `qid[13] offset[8] type[1] name[s]`, per
    /// `src/9p/protocol.ts`'s `writeDirent`.
    pub fn readdir(self: *Client, fid: u32, offset: u64, into: []u8) Error!usize {
        const room = self.msize - HDR - 4;
        const want: u32 = if (into.len > room) room else @intCast(into.len);
        var w = Writer{ .buf = &self.buf };
        w.u32v(fid);
        w.u64v(offset);
        w.u32v(want);
        var got = try self.roundTrip(&w, P9_TREADDIR);
        const count = try got[0].u32v();
        if (count > into.len) return Error.Protocol;
        @memcpy(into[0..count], self.buf[HDR + 4 .. HDR + 4 + count]);
        return count;
    }

    // -----------------------------------------------------------------------
    // Namespace mutation and metadata
    //
    // Every message below is transcribed from `src/9p/protocol.ts` — field
    // order, field width and all — and the reply of each is either a bare
    // header or a qid this client does not need, which is why most of them
    // answer `void`.
    // -----------------------------------------------------------------------

    /// `Tsetattr` — the one message behind `chmod`, `chown`, `truncate` and
    /// `utimensat` alike. `valid` says which of the fields that follow mean
    /// anything; there is no ctime *value*, only a bit asking for "now".
    pub fn setattr(
        self: *Client,
        fid: u32,
        valid: u32,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        atime_sec: u64,
        atime_nsec: u64,
        mtime_sec: u64,
        mtime_nsec: u64,
    ) Error!void {
        var w = Writer{ .buf = &self.buf };
        w.u32v(fid);
        w.u32v(valid);
        w.u32v(mode);
        w.u32v(uid);
        w.u32v(gid);
        w.u64v(size);
        w.u64v(atime_sec);
        w.u64v(atime_nsec);
        w.u64v(mtime_sec);
        w.u64v(mtime_nsec);
        _ = try self.roundTrip(&w, P9_TSETATTR);
    }

    pub fn mkdir(self: *Client, dfid: u32, name: []const u8, mode: u32, gid: u32) Error!Qid {
        var w = Writer{ .buf = &self.buf };
        w.u32v(dfid);
        w.str(name);
        w.u32v(mode);
        w.u32v(gid);
        var got = try self.roundTrip(&w, P9_TMKDIR);
        return try Qid.read(&got[0]);
    }

    /// `Tunlinkat` — `flags` carries exactly one bit, `P9_DOTL_AT_REMOVEDIR`:
    /// without it this is `unlink`, with it `rmdir`.
    pub fn unlinkat(self: *Client, dfid: u32, name: []const u8, flags: u32) Error!void {
        var w = Writer{ .buf = &self.buf };
        w.u32v(dfid);
        w.str(name);
        w.u32v(flags);
        _ = try self.roundTrip(&w, P9_TUNLINKAT);
    }

    pub fn renameat(
        self: *Client,
        olddirfid: u32,
        oldname: []const u8,
        newdirfid: u32,
        newname: []const u8,
    ) Error!void {
        var w = Writer{ .buf = &self.buf };
        w.u32v(olddirfid);
        w.str(oldname);
        w.u32v(newdirfid);
        w.str(newname);
        _ = try self.roundTrip(&w, P9_TRENAMEAT);
    }

    pub fn symlink(
        self: *Client,
        dfid: u32,
        name: []const u8,
        target: []const u8,
        gid: u32,
    ) Error!Qid {
        var w = Writer{ .buf = &self.buf };
        w.u32v(dfid);
        w.str(name);
        w.str(target);
        w.u32v(gid);
        var got = try self.roundTrip(&w, P9_TSYMLINK);
        return try Qid.read(&got[0]);
    }

    /// `Tlink` — note the order: the *directory* comes first here and second in
    /// `Trename`, which is real in `p9_client_link()` and pinned by byte
    /// fixtures on the TypeScript side.
    pub fn link(self: *Client, dfid: u32, fid: u32, name: []const u8) Error!void {
        var w = Writer{ .buf = &self.buf };
        w.u32v(dfid);
        w.u32v(fid);
        w.str(name);
        _ = try self.roundTrip(&w, P9_TLINK);
    }

    pub fn mknod(
        self: *Client,
        dfid: u32,
        name: []const u8,
        mode: u32,
        major: u32,
        minor: u32,
        gid: u32,
    ) Error!Qid {
        var w = Writer{ .buf = &self.buf };
        w.u32v(dfid);
        w.str(name);
        w.u32v(mode);
        w.u32v(major);
        w.u32v(minor);
        w.u32v(gid);
        var got = try self.roundTrip(&w, P9_TMKNOD);
        return try Qid.read(&got[0]);
    }

    /// `Treadlink` — the target, copied into `into`. Never resolved: what the
    /// link holds is what comes back.
    pub fn readlink(self: *Client, fid: u32, into: []u8) Error![]const u8 {
        var w = Writer{ .buf = &self.buf };
        w.u32v(fid);
        var got = try self.roundTrip(&w, P9_TREADLINK);
        const target = try got[0].str();
        if (target.len > into.len) return Error.Protocol;
        @memcpy(into[0..target.len], target);
        return into[0..target.len];
    }

    /// `Tfsync` — `datasync` non-zero asks for `fdatasync(2)` rather than
    /// `fsync(2)`.
    pub fn fsync(self: *Client, fid: u32, datasync: u32) Error!void {
        var w = Writer{ .buf = &self.buf };
        w.u32v(fid);
        w.u32v(datasync);
        _ = try self.roundTrip(&w, P9_TFSYNC);
    }

    /// `Rstatfs`, in the field order `src/9p/protocol.ts`'s `writeRstatfs` uses.
    pub const Statfs = struct {
        ftype: u32,
        bsize: u32,
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
        ffree: u64,
        fsid: u64,
        namelen: u32,
    };

    pub fn statfs(self: *Client, fid: u32) Error!Statfs {
        var w = Writer{ .buf = &self.buf };
        w.u32v(fid);
        const got = try self.roundTrip(&w, P9_TSTATFS);
        var r = got[0];
        return .{
            .ftype = try r.u32v(),
            .bsize = try r.u32v(),
            .blocks = try r.u64v(),
            .bfree = try r.u64v(),
            .bavail = try r.u64v(),
            .files = try r.u64v(),
            .ffree = try r.u64v(),
            .fsid = try r.u64v(),
            .namelen = try r.u32v(),
        };
    }

    /// True when this process is not the one that opened the socket, i.e. we
    /// are in a `fork()`ed child holding a copy of somebody else's connection.
    pub fn forked(self: *Client) bool {
        return self.fd >= 0 and self.owner_pid != @as(i32, @intCast(syscall0(SYS_getpid)));
    }

    pub fn reset(self: *Client) void {
        if (self.fd >= 0) _ = syscall3(SYS_close, @intCast(self.fd), 0, 0);
        self.fd = -1;
    }
};

/// Slash-separated path components, skipping empties so `/a//b/` walks `a`,`b`.
pub const Split = struct {
    s: []const u8,
    at: usize = 0,

    pub fn next(self: *Split) ?[]const u8 {
        while (self.at < self.s.len and self.s[self.at] == '/') self.at += 1;
        if (self.at >= self.s.len) return null;
        const start = self.at;
        while (self.at < self.s.len and self.s[self.at] != '/') self.at += 1;
        return self.s[start..self.at];
    }
};

/// A spinlock rather than a pthread mutex: the shim must not depend on libc
/// state that may not be initialised yet when the first interposed call
/// arrives, and contention here is a single-digit-microsecond round trip.
pub const Lock = struct {
    flag: @import("std").atomic.Value(bool) = .init(false),

    pub fn acquire(self: *Lock) void {
        while (self.flag.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            asm volatile ("pause");
        }
    }
    pub fn release(self: *Lock) void {
        self.flag.store(false, .release);
    }
};
