//! Cross-compiles the addon for every platform the prebuilts cover.
//!
//!   zig build --prefix prebuilt
//!
//! writes `prebuilt/mountx-<platform>-<arch>.node`, which is what
//! `src/fuse/native.ts` looks for and what is committed to the repository.
//! Both targets build from any host, which is the reason the native part is
//! Zig: there is no cross toolchain to install and no CI matrix to maintain.
//!
//! Node-API symbols are left undefined on purpose. An addon is a shared object
//! `dlopen`ed *into* Node, so `napi_*` resolves against the host process at
//! load time — linking anything is not merely unnecessary, it would bind the
//! result to one build of Node.

const std = @import("std");

const Prebuilt = struct {
    /// `${process.platform}-${process.arch}`, the name `native.ts` computes.
    name: []const u8,
    query: std.Target.Query,
};

const PREBUILTS = [_]Prebuilt{
    .{ .name = "linux-x64", .query = .{ .cpu_arch = .x86_64, .os_tag = .linux } },
    .{ .name = "linux-arm64", .query = .{ .cpu_arch = .aarch64, .os_tag = .linux } },
};

/// Not an option. The prebuilts are committed, so every rebuild has to produce
/// the same thing as the last one; and `ReleaseSmall` is the obvious mode for a
/// file that lives in git and does three syscalls.
const OPTIMIZE: std.builtin.OptimizeMode = .ReleaseSmall;

pub fn build(b: *std.Build) void {
    for (PREBUILTS) |prebuilt| {
        const module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = b.resolveTargetQuery(prebuilt.query),
            .optimize = OPTIMIZE,
            .link_libc = false,
            .strip = true,
        });
        const library = b.addLibrary(.{
            .name = "mountx",
            .root_module = module,
            .linkage = .dynamic,
        });
        library.linker_allow_shlib_undefined = true;
        const installed = b.addInstallFileWithDir(
            library.getEmittedBin(),
            .prefix,
            b.fmt("mountx-{s}.node", .{prebuilt.name}),
        );
        b.getInstallStep().dependOn(&installed.step);
    }
}
