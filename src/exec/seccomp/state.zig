//! Everything the supervisor remembers between notifications: open file
//! descriptions, which descriptor in which process names which one, and where
//! each process thinks it is.
//!
//! Three properties this file exists to keep, all of them things the spike got
//! wrong or did not attempt:
//!
//! - **A descriptor is not an open file.** `dup`, `fork` and a shell
//!   redirection all give one open file description several `(pid, fd)` names,
//!   and POSIX says they share a file offset. So the offset lives on the
//!   {@link File}, never on the name, and the names are reference counts on it.
//! - **The tables grow.** The spike had a fixed 256-entry array and silently
//!   dropped the 257th descriptor. These are `ArrayList`s: the supervisor is a
//!   separate process from the tracee now, carries no filter of its own, and may
//!   allocate freely.
//! - **Identity survives what the supervisor cannot see.** A `dup` gives a new
//!   fd number without any syscall the filter traps usefully — a notification
//!   cannot observe the number the kernel is about to return — so identity comes
//!   from the *object*: every injected descriptor is a `memfd` with a unique
//!   name, and `/proc/<pid>/fd/<n>` reads back as `/memfd:mx-<serial>` for the
//!   original and every duplicate alike. {@link Tables.lookup} memoises the walk.

const std = @import("std");

/// One open file description: what `open(2)` created and `dup(2)` shares.
pub const File = struct {
    used: bool = false,
    /// Stamped into the placeholder `memfd`'s name, so a descriptor can be
    /// identified by what it points at rather than by the number it was given.
    serial: u32 = 0,
    /// The 9P fid, live while `open` is true.
    fid: u32 = 0,
    open: bool = false,
    /// The supervisor-side `memfd` that was injected, kept so a `dup` of the
    /// tracee's copy can be injected again. -1 once released.
    srcfd: i32 = -1,
    /// How many `(pid, fd)` names point here.
    refs: u32 = 0,
    is_dir: bool = false,
    /// The `O_*` the tracee opened with, in the kernel's namespace.
    flags: u32 = 0,
    /// The shared file offset. Shared, because `dup` shares it.
    offset: u64 = 0,
    /// `Treaddir`'s cursor, which is a cookie the server mints rather than a
    /// byte position.
    cookie: u64 = 0,
    /// Path under the root, without a leading slash. Owned.
    path: []u8 = &.{},
};

/// One name for a {@link File}: a descriptor number in a process.
const Name = struct {
    used: bool = false,
    /// The **thread group**, not the notification's thread id — descriptors
    /// belong to the process.
    pid: i32 = 0,
    fd: i32 = 0,
    file: u32 = 0,
};

/// Where a process thinks it is, when that is somewhere in the virtual tree.
const Cwd = struct {
    used: bool = false,
    pid: i32 = 0,
    /// Path under the root, without a leading slash. Owned.
    path: []u8 = &.{},
};

pub const Tables = struct {
    allocator: std.mem.Allocator,
    files: std.ArrayList(File) = .empty,
    names: std.ArrayList(Name) = .empty,
    cwds: std.ArrayList(Cwd) = .empty,
    /// Files whose last name has just gone, waiting for somebody who can speak
    /// 9P to clunk their fid. Releasing is not table work, and a table that
    /// tried to do it would need a client.
    orphans: std.ArrayList(u32) = .empty,
    next_serial: u32 = 1,

    pub fn init(allocator: std.mem.Allocator) Tables {
        return .{ .allocator = allocator };
    }

    pub fn file(self: *Tables, index: u32) *File {
        return &self.files.items[index];
    }

    /// A fresh open file description. The caller fills in the 9P fid and the
    /// placeholder descriptor; this hands back the index and the serial.
    pub fn create(self: *Tables, path: []const u8) !u32 {
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        const serial = self.next_serial;
        self.next_serial += 1;
        for (self.files.items, 0..) |*slot, index| {
            if (!slot.used) {
                slot.* = .{ .used = true, .serial = serial, .path = owned };
                return @intCast(index);
            }
        }
        try self.files.append(self.allocator, .{ .used = true, .serial = serial, .path = owned });
        return @intCast(self.files.items.len - 1);
    }

    /// Point `(pid, fd)` at `index`, evicting whatever used to have that name.
    ///
    /// Evicting first is not tidiness. The kernel reuses the lowest free
    /// descriptor number immediately, so without it a stale mapping shadows a
    /// live one: an `fstat` on a freshly opened file answered from the
    /// *directory* that previously held the number, and `cp -r` correctly
    /// concluded the file had been replaced underneath it. Witnessed in the
    /// spike, where `close` was untrapped and this was the only defence.
    pub fn bind(self: *Tables, pid: i32, fd: i32, index: u32) !void {
        // A live number can be replaced without a `close` this supervisor sees:
        // `dup2(fd, 5)` closes 5 implicitly. So binding evicts, and whatever
        // that orphaned goes on the queue like any other release.
        self.unbind(pid, fd);
        self.files.items[index].refs += 1;
        for (self.names.items) |*slot| {
            if (!slot.used) {
                slot.* = .{ .used = true, .pid = pid, .fd = fd, .file = index };
                return;
            }
        }
        self.names.append(self.allocator, .{
            .used = true,
            .pid = pid,
            .fd = fd,
            .file = index,
        }) catch |err| {
            self.files.items[index].refs -= 1;
            return err;
        };
    }

    /// Forget one name, queueing the file for release if that was its last.
    pub fn unbind(self: *Tables, pid: i32, fd: i32) void {
        for (self.names.items) |*slot| {
            if (slot.used and slot.pid == pid and slot.fd == fd) {
                const index = slot.file;
                slot.* = .{};
                self.dropRef(index);
                return;
            }
        }
    }

    /// Every name a process held, for the `exit_group` sweep.
    pub fn unbindAll(self: *Tables, pid: i32) void {
        for (self.names.items) |*slot| {
            if (slot.used and slot.pid == pid) {
                const index = slot.file;
                slot.* = .{};
                self.dropRef(index);
            }
        }
    }

    /// Every name in a descriptor range, for `close_range(2)`.
    pub fn unbindRange(self: *Tables, pid: i32, first: i32, last: i32) void {
        for (self.names.items) |*slot| {
            if (slot.used and slot.pid == pid and slot.fd >= first and slot.fd <= last) {
                const index = slot.file;
                slot.* = .{};
                self.dropRef(index);
            }
        }
    }

    fn dropRef(self: *Tables, index: u32) void {
        const entry = &self.files.items[index];
        if (entry.refs > 0) entry.refs -= 1;
        if (entry.refs == 0) self.orphans.append(self.allocator, index) catch {};
    }

    /// The queued releases, handed over and cleared.
    pub fn takeOrphans(self: *Tables) []const u32 {
        return self.orphans.items;
    }

    pub fn clearOrphans(self: *Tables) void {
        self.orphans.clearRetainingCapacity();
    }

    /// Drop a file entirely. The caller has already clunked its fid and closed
    /// its placeholder.
    pub fn destroy(self: *Tables, index: u32) void {
        const entry = &self.files.items[index];
        if (!entry.used) return;
        self.allocator.free(entry.path);
        entry.* = .{};
    }

    /// Which file is `(pid, fd)`, by name and then by object identity.
    ///
    /// The second half is what makes `dup` work without trapping it, and it is
    /// deliberately **not memoised**. Caching the answer under the new number
    /// looked like an obvious win and is a correctness bug: a shell running
    /// `echo hi > $ROOT/file` duplicates the virtual descriptor onto its
    /// standard output, and restores the real one afterwards with a `dup2` this
    /// supervisor cannot see as a replacement. A cached entry then claimed
    /// standard output for the rest of the run and every later `echo` vanished
    /// into the driver. Witnessed. Re-reading the link costs one `readlink`
    /// against an operation that is about to cost a 9P round trip, and it
    /// cannot go stale.
    ///
    /// The duplicate resolves to the *same* file, so it shares its offset —
    /// which is what `dup` is supposed to do and what the `LD_PRELOAD` spike
    /// could not manage at all.
    pub fn lookup(self: *Tables, pid: i32, fd: i32, link: ?[]const u8) ?u32 {
        for (self.names.items) |slot| {
            if (slot.used and slot.pid == pid and slot.fd == fd) return slot.file;
        }
        if (fd < 0) return null;
        const seen = link orelse return null;
        const prefix = "/memfd:mx-";
        if (!std.mem.startsWith(u8, seen, prefix)) return null;
        var serial: u32 = 0;
        for (seen[prefix.len..]) |ch| {
            if (ch < '0' or ch > '9') break;
            serial = serial * 10 + (ch - '0');
        }
        for (self.files.items, 0..) |entry, index| {
            if (entry.used and entry.serial == serial) return @intCast(index);
        }
        return null;
    }

    /// Rewrite a file's remembered path, after a rename moved it.
    pub fn repath(self: *Tables, index: u32, path: []const u8) !void {
        const owned = try self.allocator.dupe(u8, path);
        self.allocator.free(self.files.items[index].path);
        self.files.items[index].path = owned;
    }

    // -----------------------------------------------------------------------
    // The virtual working directory
    // -----------------------------------------------------------------------

    /// Where this process is inside the tree, or null when it is outside it.
    pub fn cwd(self: *Tables, pid: i32) ?[]const u8 {
        for (self.cwds.items) |slot| {
            if (slot.used and slot.pid == pid) return slot.path;
        }
        return null;
    }

    pub fn setCwd(self: *Tables, pid: i32, path: []const u8) !void {
        const owned = try self.allocator.dupe(u8, path);
        for (self.cwds.items) |*slot| {
            if (slot.used and slot.pid == pid) {
                self.allocator.free(slot.path);
                slot.path = owned;
                return;
            }
        }
        for (self.cwds.items) |*slot| {
            if (!slot.used) {
                slot.* = .{ .used = true, .pid = pid, .path = owned };
                return;
            }
        }
        self.cwds.append(self.allocator, .{ .used = true, .pid = pid, .path = owned }) catch |err| {
            self.allocator.free(owned);
            return err;
        };
    }

    pub fn clearCwd(self: *Tables, pid: i32) void {
        for (self.cwds.items) |*slot| {
            if (slot.used and slot.pid == pid) {
                self.allocator.free(slot.path);
                slot.* = .{};
            }
        }
    }

    /// A process that has never been seen inherits its parent's virtual cwd,
    /// which is what `fork` does with a working directory. The notification
    /// carries no parent, so it comes from `/proc/<pid>/status` — the same read
    /// that answers "which thread group is this".
    pub fn inheritCwd(self: *Tables, pid: i32, ppid: i32) !bool {
        if (self.cwd(pid) != null) return true;
        const parent = self.cwd(ppid) orelse return false;
        // `parent` points into the table this call is about to grow, so it is
        // copied before anything can move it.
        var buf: [4096]u8 = undefined;
        if (parent.len > buf.len) return false;
        @memcpy(buf[0..parent.len], parent);
        try self.setCwd(pid, buf[0..parent.len]);
        return true;
    }
};

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Slash-separated components, skipping empties so `/a//b/` yields `a`, `b`.
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

/// `parts` joined, with `.` dropped and `..` popped — **clamped at the root**,
/// the same rule `src/path.ts` holds every transport to. The result has no
/// leading slash: `""` is the root and `"a/b"` is a file in it.
///
/// Several parts rather than two because a symlink resolution joins three: the
/// directory the link lives in, the link's own target, and the components of
/// the original path that came after it.
pub fn normalize(out: []u8, parts: []const []const u8) ?[]const u8 {
    var len: usize = 0;
    var starts: [256]usize = undefined;
    var depth: usize = 0;
    for (parts) |part| {
        var it = Split{ .s = part };
        while (it.next()) |name| {
            if (name.len == 1 and name[0] == '.') continue;
            if (name.len == 2 and name[0] == '.' and name[1] == '.') {
                if (depth > 0) {
                    depth -= 1;
                    len = starts[depth];
                    if (len > 0) len -= 1;
                }
                continue;
            }
            if (depth >= starts.len) return null;
            if (len != 0) {
                if (len >= out.len) return null;
                out[len] = '/';
                len += 1;
            }
            starts[depth] = len;
            depth += 1;
            if (len + name.len > out.len) return null;
            @memcpy(out[len .. len + name.len], name);
            len += name.len;
        }
    }
    return out[0..len];
}

/// The parent and the final component of a normalized path. Null for the root,
/// which has neither.
pub fn splitParent(path: []const u8) ?struct { []const u8, []const u8 } {
    if (path.len == 0) return null;
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |at| {
        return .{ path[0..at], path[at + 1 ..] };
    }
    return .{ "", path };
}
