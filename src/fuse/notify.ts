/**
 * Notifications — the messages that travel **server → kernel** unprompted.
 *
 * They are the reason the low-level layer is exported at all (IDEA.md): a
 * driver with a `watch` can invalidate the kernel's caches when something
 * changes underneath it, and nothing path-based can express that.
 *
 * On the wire a notification is an ordinary `fuse_out_header` with
 * `unique == 0` and `error` carrying the **positive** `FUSE_NOTIFY_*` code —
 * that is how `fuse_dev_do_write` tells a notification from a reply. Layouts
 * are from `include/uapi/linux/fuse.h` at v6.12, like the rest of this
 * directory.
 *
 * These are pure encoders: they hand back bytes, and the transport decides when
 * to write them.
 */

import {
  FUSE_NOTIFY_INVAL_ENTRY,
  FUSE_NOTIFY_INVAL_INODE,
  FUSE_NOTIFY_UNIQUE,
  FUSE_OUT_HEADER_SIZE,
} from "./constants.ts";
import { encodeOutHeader, ProtocolError } from "./protocol.ts";

/** `FUSE_NAME_MAX` — the kernel rejects a longer name in a notification. */
export const FUSE_NAME_MAX = 1024;

const textEncoder = new TextEncoder();

/**
 * ```c
 * struct fuse_notify_inval_inode_out { // 24 bytes
 *   uint64_t ino;                      //  0
 *   int64_t  off;                      //  8  negative: the whole mapping
 *   int64_t  len;                      // 16
 * };
 * ```
 */
export interface FuseNotifyInvalInodeOut {
  ino: bigint;
  /** First byte to drop, or a negative value for "everything". */
  off: bigint;
  /** Bytes to drop from `off`. */
  len: bigint;
}

/**
 * ```c
 * struct fuse_notify_inval_entry_out { // 16 bytes, then name + NUL
 *   uint64_t parent;                   //  0
 *   uint32_t namelen;                  //  8
 *   uint32_t flags;                    // 12  FUSE_EXPIRE_ONLY (7.38+)
 * };
 * ```
 */
export interface FuseNotifyInvalEntryOut {
  parent: bigint;
  name: string;
  /** `FUSE_EXPIRE_ONLY` to expire rather than invalidate (7.38+). */
  flags: number;
}

/** Frame a notification body: `fuse_out_header` with `unique = 0`. */
export function encodeNotify(code: number, body: Uint8Array): Uint8Array {
  const message = new Uint8Array(FUSE_OUT_HEADER_SIZE + body.length);
  message.set(encodeOutHeader({ len: message.length, error: code, unique: FUSE_NOTIFY_UNIQUE }));
  message.set(body, FUSE_OUT_HEADER_SIZE);
  return message;
}

/**
 * Drop the kernel's cached data (and attributes) for an inode.
 *
 * A negative `off` invalidates the whole mapping and the attributes, which is
 * what a driver wants after an out-of-band write it cannot describe.
 */
export function encodeNotifyInvalInode(value: FuseNotifyInvalInodeOut): Uint8Array {
  const body = new Uint8Array(24);
  const view = new DataView(body.buffer);
  view.setBigUint64(0, BigInt.asUintN(64, value.ino), true);
  view.setBigInt64(8, BigInt.asIntN(64, value.off), true);
  view.setBigInt64(16, BigInt.asIntN(64, value.len), true);
  return encodeNotify(FUSE_NOTIFY_INVAL_INODE, body);
}

/** Drop the kernel's cached `parent/name` dentry. */
export function encodeNotifyInvalEntry(value: FuseNotifyInvalEntryOut): Uint8Array {
  if (value.name.includes("\0")) {
    throw new ProtocolError("notify entry name contains a NUL byte");
  }
  const name = textEncoder.encode(value.name);
  if (name.length > FUSE_NAME_MAX) {
    throw new ProtocolError(
      `notify entry name is ${name.length} bytes, over FUSE_NAME_MAX (${FUSE_NAME_MAX})`,
    );
  }
  const body = new Uint8Array(16 + name.length + 1);
  const view = new DataView(body.buffer);
  view.setBigUint64(0, BigInt.asUintN(64, value.parent), true);
  view.setUint32(8, name.length, true);
  view.setUint32(12, value.flags, true);
  body.set(name, 16);
  return encodeNotify(FUSE_NOTIFY_INVAL_ENTRY, body);
}

/** A decoded notification: the `FUSE_NOTIFY_*` code and its body. */
export interface FuseNotification {
  code: number;
  body: Uint8Array;
}

/**
 * Split a notification back into code and body — the symmetry that lets the
 * synthetic kernel assert on what a session emits.
 */
export function decodeNotify(message: Uint8Array): FuseNotification {
  const view = new DataView(message.buffer, message.byteOffset, message.byteLength);
  if (message.length < FUSE_OUT_HEADER_SIZE) {
    throw new ProtocolError(`truncated notification: ${message.length} byte(s)`);
  }
  const len = view.getUint32(0, true);
  const code = view.getInt32(4, true);
  const unique = view.getBigUint64(8, true);
  if (unique !== FUSE_NOTIFY_UNIQUE) {
    throw new ProtocolError(`fuse_out_header.unique is ${unique}, not a notification`);
  }
  if (len > message.length) {
    throw new ProtocolError(
      `fuse_out_header.len is ${len} but only ${message.length} byte(s) were read`,
    );
  }
  return { code, body: message.slice(FUSE_OUT_HEADER_SIZE, len) };
}

/** Decode a `FUSE_NOTIFY_INVAL_INODE` body. */
export function decodeNotifyInvalInode(body: Uint8Array): FuseNotifyInvalInodeOut {
  if (body.length !== 24) {
    throw new ProtocolError(`fuse_notify_inval_inode_out is 24 bytes, got ${body.length}`);
  }
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  return {
    ino: view.getBigUint64(0, true),
    off: view.getBigInt64(8, true),
    len: view.getBigInt64(16, true),
  };
}

/** Decode a `FUSE_NOTIFY_INVAL_ENTRY` body. */
export function decodeNotifyInvalEntry(body: Uint8Array): FuseNotifyInvalEntryOut {
  if (body.length < 17) {
    throw new ProtocolError(`truncated fuse_notify_inval_entry_out: ${body.length} byte(s)`);
  }
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const parent = view.getBigUint64(0, true);
  const namelen = view.getUint32(8, true);
  const flags = view.getUint32(12, true);
  if (body.length !== 16 + namelen + 1) {
    throw new ProtocolError(
      `fuse_notify_inval_entry_out.namelen is ${namelen} but the body is ${body.length} byte(s)`,
    );
  }
  return { parent, name: new TextDecoder().decode(body.subarray(16, 16 + namelen)), flags };
}
