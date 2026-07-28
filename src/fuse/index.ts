/**
 * The FUSE protocol layer: wire-format codecs and `FUSE_INIT` negotiation.
 *
 * Pure data transformation with no I/O, no syscalls and no mount — it runs on
 * any OS. This is a documented public layer (`unimount/fuse`), because
 * low-level access is a feature: notifies, custom opcodes and record/replay
 * tooling all need it.
 *
 * The session layer sits on top of the same codecs: it turns a driver into
 * something that answers FUSE messages, still without touching `/dev/fuse`.
 */

export * from "./constants.ts";
export * from "./init.ts";
export * from "./inodes.ts";
export * from "./notify.ts";
export * from "./protocol.ts";
export * from "./session.ts";
