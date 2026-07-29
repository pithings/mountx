/**
 * The 9P2000.L transport: `mountx/9p`.
 *
 * The third transport over the same `FsDriver`, and the one the Linux kernel
 * already has a client for. Layered the way the other two are:
 *
 * - `wire.ts` — the 9P primitives: a bounds-checked little-endian reader and
 *   writer, u64 as `bigint`, strings length-prefixed and unpadded.
 * - `constants.ts` — message types and masks, transcribed from the kernel's
 *   `include/net/9p/9p.h` (v6.12).
 * - `protocol.ts` — every 9P2000.L message encoded *and* decoded, plus framing
 *   (`P9FrameAssembler`) and dirent packing.
 * - `fids.ts` — the fid table: paths, open state, readdir cursors, qid identity.
 * - `session.ts` — bytes in, bytes out: the protocol over a driver, with no
 *   socket anywhere.
 * - `server.ts` — the socket (TCP, unix, or an attached duplex), and
 *   `mount.ts` — `mount -t 9p`.
 * - `probe.ts` — whether this host can mount at all, answered without loading
 *   any of the above.
 *
 * Everything except the last two runs on any OS with no privileges, which is
 * what makes the whole protocol testable by a JS client built from these same
 * codecs.
 */

export * from "./constants.ts";
export * from "./fids.ts";
// Everything from `mount.ts` **except** `parseMountTable`/`MountEntry`, which
// are Linux's mount-table format rather than anything a consumer of this
// package composes with. Same treatment, and same reason, as the NFS
// transport's: still exported from `mount.ts` itself for the tests.
export {
  live9pMounts,
  mount9p,
  type MountP9Options,
  P9_DEFAULT_MOUNT_MSIZE,
  P9_MAX_MOUNT_MSIZE,
  P9_UNIX_PATH_MAX,
  p9ClientProbe,
  type P9ClientProbe,
  type P9Mount,
  p9MountOptions,
  type P9MountTarget,
  type P9Platform,
  p9Platform,
  socketPathRefusal,
  tcpSourceRefusal,
  unmountAll9p,
} from "./mount.ts";
export * from "./protocol.ts";
export * from "./server.ts";
export * from "./session.ts";
export * from "./wire.ts";
