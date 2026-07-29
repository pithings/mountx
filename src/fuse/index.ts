/**
 * The FUSE transport: `mountx/fuse`.
 *
 * The first transport over the `FsDriver` interface, and the only one the
 * kernel talks to directly. Layered the way all four transports are — this is
 * the one that set the shape:
 *
 * - `constants.ts` — opcodes and flags, transcribed from the kernel's
 *   `include/uapi/linux/fuse.h` (v6.12, protocol 7.41).
 * - `protocol.ts` — every struct encoded *and* decoded, plus framing and
 *   dirent packing; `notify.ts` — the two invalidation codecs; `init.ts` —
 *   `FUSE_INIT` negotiation, pure; `flags.ts` — the crossing between the
 *   wire's `O_*` and the host's.
 * - `inodes.ts` — the nodeid table: paths, `(dev, ino)` identity, lookup
 *   refcounts, subtree remap on rename.
 * - `session.ts` — bytes in, bytes out: the protocol over a driver, with no
 *   `/dev/fuse` anywhere. `record.ts` — the same traffic as a file, and a file
 *   replayed back through a session, with no kernel, no mount and no root.
 * - `mount.ts` — the mount itself: `/dev/fuse`, `mount(8)` or `fusermount3`,
 *   and the teardown state machine, with `fusermount.ts`, `exec.ts` and
 *   `native.ts` behind it. This is the one path here that opens a device,
 *   spawns a process or reaches the native addon, and re-exporting it is why
 *   importing `mountx/fuse` pulls `node:fs`, `node:fs/promises`, `node:path`,
 *   `node:child_process` and `#unfs/native` — the transport's own cost, paid on
 *   the transport's own subpath. The root `mountx` export reaches none of it.
 *
 * Everything except that last bullet runs on any OS with no privileges, which
 * is what makes the whole protocol testable with no kernel in the loop.
 * Low-level access is a documented feature — notifies, custom opcodes and
 * record/replay tooling all need it — which is why the codecs are on the public
 * subpath and not just behind `mount()`.
 */

export * from "./constants.ts";
export * from "./init.ts";
export * from "./inodes.ts";
export * from "./mount.ts";
export * from "./notify.ts";
export * from "./protocol.ts";
export * from "./record.ts";
export * from "./session.ts";
