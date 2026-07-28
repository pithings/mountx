/**
 * The FUSE protocol layer: wire-format codecs and `FUSE_INIT` negotiation.
 *
 * Pure data transformation with no I/O, no syscalls and no mount — it runs on
 * any OS. This is a documented public layer (`unimount/fuse`), because
 * low-level access is a feature: notifies, custom opcodes and record/replay
 * tooling all need it.
 */

export * from "./constants.ts";
export * from "./init.ts";
export * from "./protocol.ts";
