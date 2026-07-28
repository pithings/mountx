/**
 * FUSE wire-protocol codecs — pure data transformation, both directions.
 *
 * Every struct here is encoded *and* decoded. That symmetry is the point: the
 * synthetic kernel in the test suite encodes what a kernel would send and
 * decodes what the server replies, so the whole protocol layer is exercised on
 * any OS with no `/dev/fuse` and no mount.
 *
 * **Layouts come from the Linux kernel's `include/uapi/linux/fuse.h` at tag
 * v6.12** (protocol 7.41, the version this project's kernel speaks) —
 * <https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/fuse.h>.
 * Each codec carries the C declaration it implements, with byte offsets, so
 * nothing is guessed. Everything is little-endian; the FUSE device speaks
 * native endianness and the kernel refuses byte-swapped `INIT` outright
 * (`FUSE_INIT_BSWAP_RESERVED`), so a big-endian host is out of scope.
 *
 * Conventions, applied without exception:
 *
 * - **Every 64-bit field is a `bigint`; every 8/16/32-bit field is a `number`.**
 *   `nodeid`, `unique`, `fh`, `lock_owner` and offsets are opaque kernel tokens
 *   that genuinely use the full 64 bits (`FUSE_UNIQUE_RESEND` is bit 63), so
 *   `number` would silently corrupt them.
 * - **`padding` / `dummy` / `unused` fields are not modelled.** Encoders write
 *   zeroes; decoders skip them. That makes `decode(encode(x))` exactly `x`.
 * - **Decoding is total.** A truncated or malformed buffer throws
 *   {@link ProtocolError} and nothing else — never a `RangeError`, never silent
 *   garbage.
 * - **Decoders copy.** Byte payloads are `slice()`d out of the input so a
 *   transport can reuse its receive buffer.
 * - Names are decoded as UTF-8 `string`s (lossy for names that are not valid
 *   UTF-8 — see IDEA.md's note that keys are really bytes) and may not contain
 *   a NUL.
 */

import { ERRNO_CODES, errnoOf, type ErrnoCode } from "../errors.ts";
import {
  CUSE_INIT,
  FUSE_ACCESS,
  FUSE_BATCH_FORGET,
  FUSE_BMAP,
  FUSE_COMPAT_22_INIT_OUT_SIZE,
  FUSE_COMPAT_INIT_OUT_SIZE,
  FUSE_COMPAT_MKNOD_IN_SIZE,
  FUSE_COMPAT_SETXATTR_IN_SIZE,
  FUSE_COMPAT_WRITE_IN_SIZE,
  FUSE_COPY_FILE_RANGE,
  FUSE_CREATE,
  FUSE_DESTROY,
  FUSE_DIRENT_HEADER_SIZE,
  FUSE_FALLOCATE,
  FUSE_FLUSH,
  FUSE_FORGET,
  FUSE_FSYNC,
  FUSE_FSYNCDIR,
  FUSE_GETATTR,
  FUSE_GETLK,
  FUSE_GETXATTR,
  FUSE_IN_HEADER_SIZE,
  FUSE_INIT,
  FUSE_INIT_OUT_SIZE,
  FUSE_INTERRUPT,
  FUSE_IOCTL,
  FUSE_KERNEL_MINOR_VERSION,
  FUSE_LINK,
  FUSE_LISTXATTR,
  FUSE_LOOKUP,
  FUSE_LSEEK,
  FUSE_MKDIR,
  FUSE_MKNOD,
  FUSE_NOTIFY_REPLY,
  FUSE_OPEN,
  FUSE_OPENDIR,
  FUSE_OUT_HEADER_SIZE,
  FUSE_POLL,
  FUSE_READ,
  FUSE_READDIR,
  FUSE_READDIRPLUS,
  FUSE_READLINK,
  FUSE_RELEASE,
  FUSE_RELEASEDIR,
  FUSE_REMOVEMAPPING,
  FUSE_REMOVEXATTR,
  FUSE_RENAME,
  FUSE_RENAME2,
  FUSE_RMDIR,
  FUSE_SETATTR,
  FUSE_SETLK,
  FUSE_SETLKW,
  FUSE_SETUPMAPPING,
  FUSE_SETXATTR,
  FUSE_STATFS,
  FUSE_STATX,
  FUSE_SYMLINK,
  FUSE_SYNCFS,
  FUSE_TMPFILE,
  FUSE_UNLINK,
  FUSE_WRITE,
  opcodeName,
} from "./constants.ts";

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/**
 * A message could not be decoded (or encoded): truncated, malformed, or
 * describing more data than it carries.
 *
 * This is the **only** error type the codecs throw. A transport that catches
 * `ProtocolError` and nothing else has covered every failure mode of this
 * layer, which is what makes the decoder fuzzable.
 */
export class ProtocolError extends Error {
  readonly code = "ERR_FUSE_PROTOCOL";
  /** Byte offset the failure was detected at, when meaningful. */
  readonly offset: number | undefined;

  constructor(message: string, options: { offset?: number; cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "ProtocolError";
    this.offset = options.offset;
  }
}

/** Is this a {@link ProtocolError}? */
export function isProtocolError(error: unknown): error is ProtocolError {
  return error instanceof ProtocolError;
}

// ---------------------------------------------------------------------------
// version context
// ---------------------------------------------------------------------------

/**
 * What the codecs need to know about the negotiated session.
 *
 * A handful of structs changed shape across minor versions; the negotiated
 * minor decides which shape is on the wire. `FUSE_INIT` itself is exempt — it
 * is decoded from its own length, because negotiation has not happened yet.
 */
export interface ProtocolContext {
  /** Negotiated minor version (major is always 7). */
  readonly minor: number;
  /**
   * `FUSE_SETXATTR_EXT` was negotiated, so `fuse_setxattr_in` is 16 bytes
   * rather than 8.
   */
  readonly setxattrExt: boolean;
}

/** Latest layouts: protocol 7.41, no `FUSE_SETXATTR_EXT`. */
export const DEFAULT_PROTOCOL: ProtocolContext = {
  minor: FUSE_KERNEL_MINOR_VERSION,
  setxattrExt: false,
};

function ctxOf(ctx: ProtocolContext | undefined): ProtocolContext {
  return ctx ?? DEFAULT_PROTOCOL;
}

/** `sizeof(struct fuse_attr)` at a given minor version (7.9 added blksize). */
export function attrSize(minor: number): number {
  return minor >= 9 ? 88 : 80;
}

/** `sizeof(struct fuse_entry_out)` at a given minor version. */
export function entryOutSize(minor: number): number {
  return 40 + attrSize(minor);
}

/** `sizeof(struct fuse_attr_out)` at a given minor version. */
export function attrOutSize(minor: number): number {
  return 16 + attrSize(minor);
}

/** `sizeof(struct fuse_kstatfs)` at a given minor version (7.4 added frsize). */
export function kstatfsSize(minor: number): number {
  return minor >= 4 ? 80 : 48;
}

/** `sizeof(struct fuse_init_out)` at a given minor version. */
export function initOutSize(minor: number): number {
  if (minor < 5) {
    return FUSE_COMPAT_INIT_OUT_SIZE;
  }
  if (minor < 23) {
    return FUSE_COMPAT_22_INIT_OUT_SIZE;
  }
  return FUSE_INIT_OUT_SIZE;
}

/** `sizeof(struct fuse_read_in)` / `fuse_write_in` at a given minor version. */
export function readWriteInSize(minor: number): number {
  return minor >= 9 ? 40 : FUSE_COMPAT_WRITE_IN_SIZE;
}

// ---------------------------------------------------------------------------
// primitives
// ---------------------------------------------------------------------------

const textDecoder = new TextDecoder("utf-8");
const textEncoder = new TextEncoder();
const EMPTY_BYTES = new Uint8Array(0);

/** A cursor over a request/reply body. Every read is bounds-checked. */
class Reader {
  readonly bytes: Uint8Array;
  private readonly view: DataView;
  private readonly what: string;
  offset = 0;

  constructor(bytes: Uint8Array, what: string) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.what = what;
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  private take(size: number): number {
    const at = this.offset;
    if (at + size > this.bytes.length) {
      throw new ProtocolError(
        `truncated ${this.what}: need ${size} byte(s) at offset ${at}, have ${this.remaining}`,
        { offset: at },
      );
    }
    this.offset = at + size;
    return at;
  }

  u16(): number {
    return this.view.getUint16(this.take(2), true);
  }

  u32(): number {
    return this.view.getUint32(this.take(4), true);
  }

  i32(): number {
    return this.view.getInt32(this.take(4), true);
  }

  u64(): bigint {
    return this.view.getBigUint64(this.take(8), true);
  }

  /** Skip `size` padding bytes. */
  skip(size: number): void {
    this.take(size);
  }

  /** A copy of the next `size` bytes. */
  raw(size: number): Uint8Array {
    const at = this.take(size);
    return this.bytes.slice(at, at + size);
  }

  /** A NUL-terminated name. */
  name(): string {
    const { bytes } = this;
    let end = this.offset;
    while (end < bytes.length && bytes[end] !== 0) {
      end++;
    }
    if (end >= bytes.length) {
      throw new ProtocolError(`unterminated name in ${this.what} at offset ${this.offset}`, {
        offset: this.offset,
      });
    }
    const value = textDecoder.decode(bytes.subarray(this.offset, end));
    this.offset = end + 1;
    return value;
  }

  /** Everything left, as a string with no NUL terminator (`READLINK` reply). */
  restAsString(): string {
    const at = this.offset;
    this.offset = this.bytes.length;
    return textDecoder.decode(this.bytes.subarray(at));
  }

  /** Fail unless the body has been consumed to the byte. */
  end(): void {
    if (this.offset !== this.bytes.length) {
      throw new ProtocolError(
        `trailing bytes in ${this.what}: ${this.remaining} byte(s) after offset ${this.offset}`,
        { offset: this.offset },
      );
    }
  }
}

/** A fixed-size output buffer. Writers know their size before they start. */
class Writer {
  readonly bytes: Uint8Array;
  private readonly view: DataView;
  private offset = 0;

  constructor(size: number) {
    this.bytes = new Uint8Array(size);
    this.view = new DataView(this.bytes.buffer);
  }

  u16(value: number): void {
    this.view.setUint16(this.offset, value, true);
    this.offset += 2;
  }

  u32(value: number): void {
    this.view.setUint32(this.offset, value, true);
    this.offset += 4;
  }

  i32(value: number): void {
    this.view.setInt32(this.offset, value, true);
    this.offset += 4;
  }

  u64(value: bigint): void {
    // `asUintN` rather than letting `setBigUint64` throw: encoders must not be
    // a source of stray `RangeError`s either.
    this.view.setBigUint64(this.offset, BigInt.asUintN(64, value), true);
    this.offset += 8;
  }

  /** Zero `size` padding bytes (the buffer starts zeroed). */
  skip(size: number): void {
    this.offset += size;
  }

  raw(value: Uint8Array): void {
    this.bytes.set(value, this.offset);
    this.offset += value.length;
  }

  /** A NUL-terminated name. */
  name(value: Uint8Array): void {
    this.raw(value);
    this.offset += 1;
  }

  done(): Uint8Array {
    /* v8 ignore next 6 -- internal invariant: a size mismatch is a codec bug */
    if (this.offset !== this.bytes.length) {
      throw new ProtocolError(`encoder wrote ${this.offset} of ${this.bytes.length} byte(s)`, {
        offset: this.offset,
      });
    }
    return this.bytes;
  }
}

/** UTF-8 bytes of a name, rejecting the NUL that would terminate it early. */
function nameBytes(value: string, what: string): Uint8Array {
  if (value.includes("\0")) {
    throw new ProtocolError(`${what} contains a NUL byte`);
  }
  return textEncoder.encode(value);
}

function utf8Length(value: string): number {
  return textEncoder.encode(value).length;
}

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

/**
 * ```c
 * struct fuse_in_header {          // 40 bytes
 *   uint32_t len;                  //  0
 *   uint32_t opcode;               //  4
 *   uint64_t unique;               //  8
 *   uint64_t nodeid;               // 16
 *   uint32_t uid;                  // 24
 *   uint32_t gid;                  // 28
 *   uint32_t pid;                  // 32
 *   uint16_t total_extlen;         // 36  (7.38+; padding before that)
 *   uint16_t padding;              // 38
 * };
 * ```
 */
export interface FuseInHeader {
  /** Total message length including this header. */
  len: number;
  opcode: number;
  unique: bigint;
  nodeid: bigint;
  uid: number;
  gid: number;
  pid: number;
  /** Length of the trailing extension block, in 8-byte units (7.38+). */
  totalExtlen: number;
}

export function decodeInHeader(buffer: Uint8Array): FuseInHeader {
  const r = new Reader(buffer, "fuse_in_header");
  const header: FuseInHeader = {
    len: r.u32(),
    opcode: r.u32(),
    unique: r.u64(),
    nodeid: r.u64(),
    uid: r.u32(),
    gid: r.u32(),
    pid: r.u32(),
    totalExtlen: r.u16(),
  };
  r.skip(2);
  if (header.len < FUSE_IN_HEADER_SIZE) {
    throw new ProtocolError(
      `fuse_in_header.len is ${header.len}, below the ${FUSE_IN_HEADER_SIZE}-byte header`,
    );
  }
  return header;
}

export function encodeInHeader(header: FuseInHeader): Uint8Array {
  const w = new Writer(FUSE_IN_HEADER_SIZE);
  w.u32(header.len);
  w.u32(header.opcode);
  w.u64(header.unique);
  w.u64(header.nodeid);
  w.u32(header.uid);
  w.u32(header.gid);
  w.u32(header.pid);
  w.u16(header.totalExtlen);
  w.skip(2);
  return w.done();
}

/**
 * ```c
 * struct fuse_out_header {         // 16 bytes
 *   uint32_t len;                  //  0
 *   int32_t  error;                //  4  negative errno, or 0
 *   uint64_t unique;               //  8
 * };
 * ```
 */
export interface FuseOutHeader {
  len: number;
  /** Negative errno (`-ENOENT` is `-2`), or `0` on success. */
  error: number;
  unique: bigint;
}

export function decodeOutHeader(buffer: Uint8Array): FuseOutHeader {
  const r = new Reader(buffer, "fuse_out_header");
  const header: FuseOutHeader = { len: r.u32(), error: r.i32(), unique: r.u64() };
  if (header.len < FUSE_OUT_HEADER_SIZE) {
    throw new ProtocolError(
      `fuse_out_header.len is ${header.len}, below the ${FUSE_OUT_HEADER_SIZE}-byte header`,
    );
  }
  return header;
}

export function encodeOutHeader(header: FuseOutHeader): Uint8Array {
  const w = new Writer(FUSE_OUT_HEADER_SIZE);
  w.u32(header.len);
  w.i32(header.error);
  w.u64(header.unique);
  return w.done();
}

// ---------------------------------------------------------------------------
// errno on the wire
// ---------------------------------------------------------------------------

/**
 * The value `fuse_out_header.error` wants: a **negative** Linux errno.
 *
 * Accepts a POSIX name from `ERRNO_CODES`, or a raw number of either sign.
 */
export function fuseErrno(code: ErrnoCode | number): number {
  if (typeof code === "number") {
    return code > 0 ? -code : code;
  }
  const value = ERRNO_CODES[code];
  if (value === undefined) {
    throw new ProtocolError(`unknown errno code ${String(code)}`);
  }
  return -value;
}

/** A successful reply: `fuse_out_header` plus an optional body. */
export function encodeReply(unique: bigint, body?: Uint8Array): Uint8Array {
  const payload = body ?? EMPTY_BYTES;
  const message = new Uint8Array(FUSE_OUT_HEADER_SIZE + payload.length);
  message.set(encodeOutHeader({ len: message.length, error: 0, unique }));
  message.set(payload, FUSE_OUT_HEADER_SIZE);
  return message;
}

/** An error reply. The body is always empty; the kernel ignores one anyway. */
export function encodeErrorReply(unique: bigint, code: ErrnoCode | number): Uint8Array {
  return encodeOutHeader({ len: FUSE_OUT_HEADER_SIZE, error: fuseErrno(code), unique });
}

/**
 * An error reply for a *thrown* value, via `errnoOf` — the catch-all every
 * dispatch needs so a stray JS error becomes `-EIO` instead of a hung mount.
 */
export function encodeErrorReplyFor(unique: bigint, error: unknown): Uint8Array {
  return encodeErrorReply(unique, -errnoOf(error));
}

// ---------------------------------------------------------------------------
// shared structs
// ---------------------------------------------------------------------------

/**
 * ```c
 * struct fuse_attr {               // 88 bytes (80 before 7.9)
 *   uint64_t ino;                  //  0
 *   uint64_t size;                 //  8
 *   uint64_t blocks;               // 16
 *   uint64_t atime;                // 24
 *   uint64_t mtime;                // 32
 *   uint64_t ctime;                // 40
 *   uint32_t atimensec;            // 48
 *   uint32_t mtimensec;            // 52
 *   uint32_t ctimensec;            // 56
 *   uint32_t mode;                 // 60
 *   uint32_t nlink;                // 64
 *   uint32_t uid;                  // 68
 *   uint32_t gid;                  // 72
 *   uint32_t rdev;                 // 76
 *   uint32_t blksize;              // 80  (7.9+)
 *   uint32_t flags;                // 84  (7.32+; `padding` before that)
 * };
 * ```
 */
export interface FuseAttr {
  ino: bigint;
  size: bigint;
  blocks: bigint;
  atime: bigint;
  mtime: bigint;
  ctime: bigint;
  atimensec: number;
  mtimensec: number;
  ctimensec: number;
  /** `S_IFMT` type bits plus permission bits. */
  mode: number;
  nlink: number;
  uid: number;
  gid: number;
  rdev: number;
  /** 7.9+. Zero on older protocols. */
  blksize: number;
  /** `FUSE_ATTR_*`, 7.32+. Zero on older protocols. */
  flags: number;
}

function readAttr(r: Reader, minor: number): FuseAttr {
  const attr: FuseAttr = {
    ino: r.u64(),
    size: r.u64(),
    blocks: r.u64(),
    atime: r.u64(),
    mtime: r.u64(),
    ctime: r.u64(),
    atimensec: r.u32(),
    mtimensec: r.u32(),
    ctimensec: r.u32(),
    mode: r.u32(),
    nlink: r.u32(),
    uid: r.u32(),
    gid: r.u32(),
    rdev: r.u32(),
    blksize: 0,
    flags: 0,
  };
  if (minor >= 9) {
    attr.blksize = r.u32();
    // Before 7.32 this word is `padding`, not `flags`. Surfacing it as `flags`
    // would leak a reserved field into the session layer and break
    // `decode(encode(x)) === x` at 7.9..7.31, where the encoder writes zero.
    if (minor >= 32) {
      attr.flags = r.u32();
    } else {
      r.skip(4);
    }
  }
  return attr;
}

function writeAttr(w: Writer, attr: FuseAttr, minor: number): void {
  w.u64(attr.ino);
  w.u64(attr.size);
  w.u64(attr.blocks);
  w.u64(attr.atime);
  w.u64(attr.mtime);
  w.u64(attr.ctime);
  w.u32(attr.atimensec);
  w.u32(attr.mtimensec);
  w.u32(attr.ctimensec);
  w.u32(attr.mode);
  w.u32(attr.nlink);
  w.u32(attr.uid);
  w.u32(attr.gid);
  w.u32(attr.rdev);
  if (minor >= 9) {
    w.u32(attr.blksize);
    w.u32(minor >= 32 ? attr.flags : 0);
  }
}

/**
 * ```c
 * struct fuse_kstatfs {            // 80 bytes (48 before 7.4)
 *   uint64_t blocks;               //  0
 *   uint64_t bfree;                //  8
 *   uint64_t bavail;               // 16
 *   uint64_t files;                // 24
 *   uint64_t ffree;                // 32
 *   uint32_t bsize;                // 40
 *   uint32_t namelen;              // 44
 *   uint32_t frsize;               // 48  (7.4+)
 *   uint32_t padding;              // 52
 *   uint32_t spare[6];             // 56
 * };
 * ```
 */
export interface FuseKstatfs {
  blocks: bigint;
  bfree: bigint;
  bavail: bigint;
  files: bigint;
  ffree: bigint;
  bsize: number;
  namelen: number;
  /** 7.4+. Zero on older protocols. */
  frsize: number;
}

/**
 * ```c
 * struct fuse_file_lock {          // 24 bytes
 *   uint64_t start;                //  0
 *   uint64_t end;                  //  8
 *   uint32_t type;                 // 16  F_RDLCK / F_WRLCK / F_UNLCK
 *   uint32_t pid;                  // 20  tgid
 * };
 * ```
 */
export interface FuseFileLock {
  start: bigint;
  end: bigint;
  type: number;
  pid: number;
}

function readFileLock(r: Reader): FuseFileLock {
  return { start: r.u64(), end: r.u64(), type: r.u32(), pid: r.u32() };
}

function writeFileLock(w: Writer, lk: FuseFileLock): void {
  w.u64(lk.start);
  w.u64(lk.end);
  w.u32(lk.type);
  w.u32(lk.pid);
}

/**
 * ```c
 * struct fuse_entry_out {          // 128 bytes (120 before 7.9)
 *   uint64_t nodeid;               //  0
 *   uint64_t generation;           //  8
 *   uint64_t entry_valid;          // 16  seconds
 *   uint64_t attr_valid;           // 24  seconds
 *   uint32_t entry_valid_nsec;     // 32
 *   uint32_t attr_valid_nsec;      // 36
 *   struct fuse_attr attr;         // 40
 * };
 * ```
 */
export interface FuseEntryOut {
  nodeid: bigint;
  generation: bigint;
  entryValid: bigint;
  attrValid: bigint;
  entryValidNsec: number;
  attrValidNsec: number;
  attr: FuseAttr;
}

function readEntryOut(r: Reader, minor: number): FuseEntryOut {
  return {
    nodeid: r.u64(),
    generation: r.u64(),
    entryValid: r.u64(),
    attrValid: r.u64(),
    entryValidNsec: r.u32(),
    attrValidNsec: r.u32(),
    attr: readAttr(r, minor),
  };
}

function writeEntryOut(w: Writer, entry: FuseEntryOut, minor: number): void {
  w.u64(entry.nodeid);
  w.u64(entry.generation);
  w.u64(entry.entryValid);
  w.u64(entry.attrValid);
  w.u32(entry.entryValidNsec);
  w.u32(entry.attrValidNsec);
  writeAttr(w, entry.attr, minor);
}

export function decodeEntryOut(body: Uint8Array, ctx?: ProtocolContext): FuseEntryOut {
  const r = new Reader(body, "fuse_entry_out");
  const value = readEntryOut(r, ctxOf(ctx).minor);
  r.end();
  return value;
}

export function encodeEntryOut(entry: FuseEntryOut, ctx?: ProtocolContext): Uint8Array {
  const { minor } = ctxOf(ctx);
  const w = new Writer(entryOutSize(minor));
  writeEntryOut(w, entry, minor);
  return w.done();
}

/**
 * ```c
 * struct fuse_open_out {           // 16 bytes
 *   uint64_t fh;                   //  0
 *   uint32_t open_flags;           //  8  FOPEN_*
 *   int32_t  backing_id;           // 12  (7.40+; `padding` before that)
 * };
 * ```
 */
export interface FuseOpenOut {
  fh: bigint;
  /** `FOPEN_*`. */
  openFlags: number;
  /** `FUSE_PASSTHROUGH` backing fd id, 7.40+. Zero otherwise. */
  backingId: number;
}

function readOpenOut(r: Reader, minor: number): FuseOpenOut {
  const fh = r.u64();
  const openFlags = r.u32();
  const backingId = r.i32();
  return { fh, openFlags, backingId: minor >= 40 ? backingId : 0 };
}

function writeOpenOut(w: Writer, open: FuseOpenOut, minor: number): void {
  w.u64(open.fh);
  w.u32(open.openFlags);
  w.i32(minor >= 40 ? open.backingId : 0);
}

// ---------------------------------------------------------------------------
// per-opcode request and reply bodies
// ---------------------------------------------------------------------------

/** A body with no fields: `DESTROY`, `READLINK` and `STATFS` requests, and every reply that is just a status. */
export type FuseEmpty = Record<string, never>;

const EMPTY_VALUE: FuseEmpty = Object.freeze({});

function decodeEmpty(body: Uint8Array): FuseEmpty {
  if (body.length > 0) {
    throw new ProtocolError(`expected an empty body, got ${body.length} byte(s)`);
  }
  return EMPTY_VALUE;
}

function encodeEmpty(): Uint8Array {
  return EMPTY_BYTES;
}

/** A body that is nothing but bytes: `READ` replies, `WRITE`/xattr values. */
export interface FuseRawData {
  data: Uint8Array;
}

function decodeRawData(body: Uint8Array): FuseRawData {
  return { data: body.slice() };
}

function encodeRawData(value: FuseRawData): Uint8Array {
  return value.data;
}

/** A single NUL-terminated name: `LOOKUP`, `UNLINK`, `RMDIR`, `REMOVEXATTR`. */
export interface FuseNameIn {
  name: string;
}

function decodeNameIn(body: Uint8Array): FuseNameIn {
  const r = new Reader(body, "name");
  const name = r.name();
  r.end();
  return { name };
}

function encodeNameIn(value: FuseNameIn): Uint8Array {
  const name = nameBytes(value.name, "name");
  const w = new Writer(name.length + 1);
  w.name(name);
  return w.done();
}

/** `struct fuse_forget_in { uint64_t nlookup; }` */
export interface FuseForgetIn {
  nlookup: bigint;
}

/**
 * ```c
 * struct fuse_batch_forget_in { uint32_t count; uint32_t dummy; };
 * struct fuse_forget_one       { uint64_t nodeid; uint64_t nlookup; };
 * ```
 */
export interface FuseForgetOne {
  nodeid: bigint;
  nlookup: bigint;
}

export interface FuseBatchForgetIn {
  forgets: FuseForgetOne[];
}

/** `struct fuse_getattr_in { uint32_t getattr_flags; uint32_t dummy; uint64_t fh; }` */
export interface FuseGetattrIn {
  /** `FUSE_GETATTR_FH`. */
  getattrFlags: number;
  fh: bigint;
}

/** `struct fuse_attr_out { uint64_t attr_valid; uint32_t attr_valid_nsec; uint32_t dummy; struct fuse_attr attr; }` */
export interface FuseAttrOut {
  attrValid: bigint;
  attrValidNsec: number;
  attr: FuseAttr;
}

/**
 * ```c
 * struct fuse_setattr_in {         // 88 bytes
 *   uint32_t valid;                //  0  FATTR_*
 *   uint32_t padding;              //  4
 *   uint64_t fh;                   //  8
 *   uint64_t size;                 // 16
 *   uint64_t lock_owner;           // 24
 *   uint64_t atime;                // 32
 *   uint64_t mtime;                // 40
 *   uint64_t ctime;                // 48
 *   uint32_t atimensec;            // 56
 *   uint32_t mtimensec;            // 60
 *   uint32_t ctimensec;            // 64
 *   uint32_t mode;                 // 68
 *   uint32_t unused4;              // 72
 *   uint32_t uid;                  // 76
 *   uint32_t gid;                  // 80
 *   uint32_t unused5;              // 84
 * };
 * ```
 */
export interface FuseSetattrIn {
  /** `FATTR_*` — which of the fields below are meaningful. */
  valid: number;
  fh: bigint;
  size: bigint;
  lockOwner: bigint;
  atime: bigint;
  mtime: bigint;
  ctime: bigint;
  atimensec: number;
  mtimensec: number;
  ctimensec: number;
  mode: number;
  uid: number;
  gid: number;
}

/** `SYMLINK`: the entry name, then the (opaque, possibly relative) target. */
export interface FuseSymlinkIn {
  name: string;
  target: string;
}

/** `struct fuse_mknod_in { uint32_t mode, rdev, umask, padding; }` plus a name. */
export interface FuseMknodIn {
  mode: number;
  rdev: number;
  /** 7.12+. Zero on older protocols. */
  umask: number;
  name: string;
}

/** `struct fuse_mkdir_in { uint32_t mode, umask; }` plus a name. */
export interface FuseMkdirIn {
  mode: number;
  umask: number;
  name: string;
}

/** `struct fuse_rename_in { uint64_t newdir; }` plus two names. */
export interface FuseRenameIn {
  newdir: bigint;
  oldName: string;
  newName: string;
}

/** `struct fuse_rename2_in { uint64_t newdir; uint32_t flags, padding; }` plus two names. */
export interface FuseRename2In extends FuseRenameIn {
  /** `RENAME_NOREPLACE` / `RENAME_EXCHANGE` / `RENAME_WHITEOUT`. */
  flags: number;
}

/** `struct fuse_link_in { uint64_t oldnodeid; }` plus the new name. */
export interface FuseLinkIn {
  oldnodeid: bigint;
  name: string;
}

/** `struct fuse_open_in { uint32_t flags; uint32_t open_flags; }` */
export interface FuseOpenIn {
  /** Raw `O_*` flags as passed to `open(2)`. */
  flags: number;
  /** `FUSE_OPEN_KILL_SUIDGID`. */
  openFlags: number;
}

/** `struct fuse_create_in { uint32_t flags, mode, umask, open_flags; }` plus a name. */
export interface FuseCreateIn {
  flags: number;
  mode: number;
  /** 7.12+. Zero on older protocols. */
  umask: number;
  /** 7.12+. Zero on older protocols. */
  openFlags: number;
  name: string;
}

/** `CREATE` replies with `fuse_entry_out` immediately followed by `fuse_open_out`. */
export interface FuseCreateOut {
  entry: FuseEntryOut;
  open: FuseOpenOut;
}

/** `struct fuse_release_in { uint64_t fh; uint32_t flags, release_flags; uint64_t lock_owner; }` */
export interface FuseReleaseIn {
  fh: bigint;
  flags: number;
  /** `FUSE_RELEASE_*`. */
  releaseFlags: number;
  lockOwner: bigint;
}

/** `struct fuse_flush_in { uint64_t fh; uint32_t unused, padding; uint64_t lock_owner; }` */
export interface FuseFlushIn {
  fh: bigint;
  lockOwner: bigint;
}

/**
 * ```c
 * struct fuse_read_in {            // 40 bytes (24 before 7.9)
 *   uint64_t fh;                   //  0
 *   uint64_t offset;               //  8
 *   uint32_t size;                 // 16
 *   uint32_t read_flags;           // 20  FUSE_READ_LOCKOWNER
 *   uint64_t lock_owner;           // 24  (7.9+)
 *   uint32_t flags;                // 32  (7.9+) raw O_* of the open file
 *   uint32_t padding;              // 36
 * };
 * ```
 * `READDIR` and `READDIRPLUS` reuse it verbatim.
 */
export interface FuseReadIn {
  fh: bigint;
  offset: bigint;
  size: number;
  readFlags: number;
  lockOwner: bigint;
  flags: number;
}

/** `struct fuse_write_in` — same layout as `fuse_read_in` — plus the payload. */
export interface FuseWriteIn {
  fh: bigint;
  offset: bigint;
  /** Must equal `data.length`; encoders derive it, decoders validate it. */
  size: number;
  /** `FUSE_WRITE_*`. */
  writeFlags: number;
  lockOwner: bigint;
  flags: number;
  data: Uint8Array;
}

/** `struct fuse_write_out { uint32_t size; uint32_t padding; }` */
export interface FuseWriteOut {
  size: number;
}

/** `struct fuse_fsync_in { uint64_t fh; uint32_t fsync_flags, padding; }` */
export interface FuseFsyncIn {
  fh: bigint;
  /** `FUSE_FSYNC_FDATASYNC`. */
  fsyncFlags: number;
}

/** `struct fuse_setxattr_in { uint32_t size, flags[, setxattr_flags, padding]; }` plus a name and the value. */
export interface FuseSetxattrIn {
  /** `XATTR_CREATE` / `XATTR_REPLACE`. */
  flags: number;
  /** `FUSE_SETXATTR_ACL_KILL_SGID`; only present with `FUSE_SETXATTR_EXT`. */
  setxattrFlags: number;
  name: string;
  value: Uint8Array;
}

/** `struct fuse_getxattr_in { uint32_t size; uint32_t padding; }` plus a name for `GETXATTR`. */
export interface FuseGetxattrIn {
  /** Buffer the kernel offers. Zero means "reply with the size only". */
  size: number;
  name: string;
}

/** `LISTXATTR` carries the same struct with no name. */
export interface FuseListxattrIn {
  size: number;
}

/** `struct fuse_getxattr_out { uint32_t size; uint32_t padding; }` — the size-probe reply. */
export interface FuseGetxattrOut {
  size: number;
}

/** `struct fuse_lk_in { uint64_t fh, owner; struct fuse_file_lock lk; uint32_t lk_flags, padding; }` */
export interface FuseLkIn {
  fh: bigint;
  owner: bigint;
  lk: FuseFileLock;
  /** `FUSE_LK_FLOCK`. */
  lkFlags: number;
}

/** `struct fuse_lk_out { struct fuse_file_lock lk; }` */
export interface FuseLkOut {
  lk: FuseFileLock;
}

/** `struct fuse_access_in { uint32_t mask; uint32_t padding; }` */
export interface FuseAccessIn {
  /** `R_OK` / `W_OK` / `X_OK`. */
  mask: number;
}

/**
 * ```c
 * struct fuse_init_in {            // 64 bytes (16 before 7.36)
 *   uint32_t major;                //  0
 *   uint32_t minor;                //  4
 *   uint32_t max_readahead;        //  8
 *   uint32_t flags;                // 12
 *   uint32_t flags2;               // 16  (7.36+, only valid with FUSE_INIT_EXT)
 *   uint32_t unused[11];           // 20
 * };
 * ```
 * Decoded from its own length: negotiation has not happened yet, so there is no
 * negotiated minor to consult.
 */
export interface FuseInitIn {
  major: number;
  minor: number;
  maxReadahead: number;
  /** Low 32 `FUSE_*` bits, as an unsigned `number`. */
  flags: number;
  /** High 32 `FUSE_*` bits (7.36+). Zero on older protocols. */
  flags2: number;
}

/**
 * ```c
 * struct fuse_init_out {           // 64 bytes (24 before 7.23, 8 before 7.5)
 *   uint32_t major;                //  0
 *   uint32_t minor;                //  4
 *   uint32_t max_readahead;        //  8
 *   uint32_t flags;                // 12
 *   uint16_t max_background;       // 16
 *   uint16_t congestion_threshold; // 18
 *   uint32_t max_write;            // 20
 *   uint32_t time_gran;            // 24  (7.23+)
 *   uint16_t max_pages;            // 28  (7.28+)
 *   uint16_t map_alignment;        // 30  (7.31+)
 *   uint32_t flags2;               // 32  (7.36+)
 *   uint32_t max_stack_depth;      // 36  (7.40+)
 *   uint32_t unused[6];            // 40
 * };
 * ```
 */
export interface FuseInitOut {
  major: number;
  minor: number;
  maxReadahead: number;
  flags: number;
  maxBackground: number;
  congestionThreshold: number;
  maxWrite: number;
  timeGran: number;
  maxPages: number;
  mapAlignment: number;
  flags2: number;
  maxStackDepth: number;
}

/** `struct fuse_interrupt_in { uint64_t unique; }` */
export interface FuseInterruptIn {
  unique: bigint;
}

/** `struct fuse_poll_in { uint64_t fh, kh; uint32_t flags, events; }` */
export interface FusePollIn {
  fh: bigint;
  kh: bigint;
  /** `FUSE_POLL_SCHEDULE_NOTIFY`. */
  flags: number;
  events: number;
}

/** `struct fuse_poll_out { uint32_t revents; uint32_t padding; }` */
export interface FusePollOut {
  revents: number;
}

/** `struct fuse_fallocate_in { uint64_t fh, offset, length; uint32_t mode, padding; }` */
export interface FuseFallocateIn {
  fh: bigint;
  offset: bigint;
  length: bigint;
  /** `FALLOC_FL_*`. */
  mode: number;
}

/** `struct fuse_lseek_in { uint64_t fh, offset; uint32_t whence, padding; }` */
export interface FuseLseekIn {
  fh: bigint;
  offset: bigint;
  /** `SEEK_*`. */
  whence: number;
}

/** `struct fuse_lseek_out { uint64_t offset; }` */
export interface FuseLseekOut {
  offset: bigint;
}

/** `READLINK` replies with the raw target bytes and **no** NUL terminator. */
export interface FuseReadlinkOut {
  target: string;
}

/** `struct fuse_bmap_in { uint64_t block; uint32_t blocksize, padding; }` */
export interface FuseBmapIn {
  block: bigint;
  blocksize: number;
}

/** `struct fuse_bmap_out { uint64_t block; }` */
export interface FuseBmapOut {
  block: bigint;
}

// --- request codecs ---

function decodeForgetIn(body: Uint8Array): FuseForgetIn {
  const r = new Reader(body, "fuse_forget_in");
  const value = { nlookup: r.u64() };
  r.end();
  return value;
}

function encodeForgetIn(value: FuseForgetIn): Uint8Array {
  const w = new Writer(8);
  w.u64(value.nlookup);
  return w.done();
}

function decodeBatchForgetIn(body: Uint8Array): FuseBatchForgetIn {
  const r = new Reader(body, "fuse_batch_forget_in");
  const count = r.u32();
  r.skip(4);
  // Validate against what is actually here before allocating: `count` is
  // attacker-controlled from the decoder's point of view and 4 billion
  // 16-byte entries is an OOM, not a protocol error.
  if (count * 16 > r.remaining) {
    throw new ProtocolError(
      `fuse_batch_forget_in.count is ${count} but only ${r.remaining} byte(s) follow`,
    );
  }
  const forgets: FuseForgetOne[] = [];
  for (let index = 0; index < count; index++) {
    forgets.push({ nodeid: r.u64(), nlookup: r.u64() });
  }
  r.end();
  return { forgets };
}

function encodeBatchForgetIn(value: FuseBatchForgetIn): Uint8Array {
  const w = new Writer(8 + value.forgets.length * 16);
  w.u32(value.forgets.length);
  w.skip(4);
  for (const forget of value.forgets) {
    w.u64(forget.nodeid);
    w.u64(forget.nlookup);
  }
  return w.done();
}

function decodeGetattrIn(body: Uint8Array): FuseGetattrIn {
  const r = new Reader(body, "fuse_getattr_in");
  const getattrFlags = r.u32();
  r.skip(4);
  const fh = r.u64();
  r.end();
  return { getattrFlags, fh };
}

function encodeGetattrIn(value: FuseGetattrIn): Uint8Array {
  const w = new Writer(16);
  w.u32(value.getattrFlags);
  w.skip(4);
  w.u64(value.fh);
  return w.done();
}

function decodeSetattrIn(body: Uint8Array): FuseSetattrIn {
  const r = new Reader(body, "fuse_setattr_in");
  const valid = r.u32();
  r.skip(4);
  const value: FuseSetattrIn = {
    valid,
    fh: r.u64(),
    size: r.u64(),
    lockOwner: r.u64(),
    atime: r.u64(),
    mtime: r.u64(),
    ctime: r.u64(),
    atimensec: r.u32(),
    mtimensec: r.u32(),
    ctimensec: r.u32(),
    mode: r.u32(),
    uid: 0,
    gid: 0,
  };
  r.skip(4); // unused4
  value.uid = r.u32();
  value.gid = r.u32();
  r.skip(4); // unused5
  r.end();
  return value;
}

function encodeSetattrIn(value: FuseSetattrIn): Uint8Array {
  const w = new Writer(88);
  w.u32(value.valid);
  w.skip(4);
  w.u64(value.fh);
  w.u64(value.size);
  w.u64(value.lockOwner);
  w.u64(value.atime);
  w.u64(value.mtime);
  w.u64(value.ctime);
  w.u32(value.atimensec);
  w.u32(value.mtimensec);
  w.u32(value.ctimensec);
  w.u32(value.mode);
  w.skip(4);
  w.u32(value.uid);
  w.u32(value.gid);
  w.skip(4);
  return w.done();
}

function decodeSymlinkIn(body: Uint8Array): FuseSymlinkIn {
  const r = new Reader(body, "symlink");
  const name = r.name();
  const target = r.name();
  r.end();
  return { name, target };
}

function encodeSymlinkIn(value: FuseSymlinkIn): Uint8Array {
  const name = nameBytes(value.name, "symlink name");
  const target = nameBytes(value.target, "symlink target");
  const w = new Writer(name.length + target.length + 2);
  w.name(name);
  w.name(target);
  return w.done();
}

function decodeMknodIn(body: Uint8Array, ctx: ProtocolContext): FuseMknodIn {
  const r = new Reader(body, "fuse_mknod_in");
  const mode = r.u32();
  const rdev = r.u32();
  let umask = 0;
  if (ctx.minor >= 12) {
    umask = r.u32();
    r.skip(4);
  }
  const name = r.name();
  r.end();
  return { mode, rdev, umask, name };
}

function encodeMknodIn(value: FuseMknodIn, ctx: ProtocolContext): Uint8Array {
  const name = nameBytes(value.name, "mknod name");
  const head = ctx.minor >= 12 ? 16 : FUSE_COMPAT_MKNOD_IN_SIZE;
  const w = new Writer(head + name.length + 1);
  w.u32(value.mode);
  w.u32(value.rdev);
  if (ctx.minor >= 12) {
    w.u32(value.umask);
    w.skip(4);
  }
  w.name(name);
  return w.done();
}

function decodeMkdirIn(body: Uint8Array): FuseMkdirIn {
  const r = new Reader(body, "fuse_mkdir_in");
  const mode = r.u32();
  const umask = r.u32();
  const name = r.name();
  r.end();
  return { mode, umask, name };
}

function encodeMkdirIn(value: FuseMkdirIn): Uint8Array {
  const name = nameBytes(value.name, "mkdir name");
  const w = new Writer(8 + name.length + 1);
  w.u32(value.mode);
  w.u32(value.umask);
  w.name(name);
  return w.done();
}

function decodeRenameIn(body: Uint8Array): FuseRenameIn {
  const r = new Reader(body, "fuse_rename_in");
  const newdir = r.u64();
  const oldName = r.name();
  const newName = r.name();
  r.end();
  return { newdir, oldName, newName };
}

function encodeRenameIn(value: FuseRenameIn): Uint8Array {
  const oldName = nameBytes(value.oldName, "rename oldname");
  const newName = nameBytes(value.newName, "rename newname");
  const w = new Writer(8 + oldName.length + newName.length + 2);
  w.u64(value.newdir);
  w.name(oldName);
  w.name(newName);
  return w.done();
}

function decodeRename2In(body: Uint8Array): FuseRename2In {
  const r = new Reader(body, "fuse_rename2_in");
  const newdir = r.u64();
  const flags = r.u32();
  r.skip(4);
  const oldName = r.name();
  const newName = r.name();
  r.end();
  return { newdir, flags, oldName, newName };
}

function encodeRename2In(value: FuseRename2In): Uint8Array {
  const oldName = nameBytes(value.oldName, "rename2 oldname");
  const newName = nameBytes(value.newName, "rename2 newname");
  const w = new Writer(16 + oldName.length + newName.length + 2);
  w.u64(value.newdir);
  w.u32(value.flags);
  w.skip(4);
  w.name(oldName);
  w.name(newName);
  return w.done();
}

function decodeLinkIn(body: Uint8Array): FuseLinkIn {
  const r = new Reader(body, "fuse_link_in");
  const oldnodeid = r.u64();
  const name = r.name();
  r.end();
  return { oldnodeid, name };
}

function encodeLinkIn(value: FuseLinkIn): Uint8Array {
  const name = nameBytes(value.name, "link name");
  const w = new Writer(8 + name.length + 1);
  w.u64(value.oldnodeid);
  w.name(name);
  return w.done();
}

function decodeOpenIn(body: Uint8Array): FuseOpenIn {
  const r = new Reader(body, "fuse_open_in");
  const value = { flags: r.u32(), openFlags: r.u32() };
  r.end();
  return value;
}

function encodeOpenIn(value: FuseOpenIn): Uint8Array {
  const w = new Writer(8);
  w.u32(value.flags);
  w.u32(value.openFlags);
  return w.done();
}

function decodeCreateIn(body: Uint8Array, ctx: ProtocolContext): FuseCreateIn {
  const r = new Reader(body, "fuse_create_in");
  const flags = r.u32();
  const mode = r.u32();
  let umask = 0;
  let openFlags = 0;
  if (ctx.minor >= 12) {
    umask = r.u32();
    openFlags = r.u32();
  }
  const name = r.name();
  r.end();
  return { flags, mode, umask, openFlags, name };
}

function encodeCreateIn(value: FuseCreateIn, ctx: ProtocolContext): Uint8Array {
  const name = nameBytes(value.name, "create name");
  const head = ctx.minor >= 12 ? 16 : FUSE_COMPAT_MKNOD_IN_SIZE;
  const w = new Writer(head + name.length + 1);
  w.u32(value.flags);
  w.u32(value.mode);
  if (ctx.minor >= 12) {
    w.u32(value.umask);
    w.u32(value.openFlags);
  }
  w.name(name);
  return w.done();
}

function decodeReleaseIn(body: Uint8Array): FuseReleaseIn {
  const r = new Reader(body, "fuse_release_in");
  const value = {
    fh: r.u64(),
    flags: r.u32(),
    releaseFlags: r.u32(),
    lockOwner: r.u64(),
  };
  r.end();
  return value;
}

function encodeReleaseIn(value: FuseReleaseIn): Uint8Array {
  const w = new Writer(24);
  w.u64(value.fh);
  w.u32(value.flags);
  w.u32(value.releaseFlags);
  w.u64(value.lockOwner);
  return w.done();
}

function decodeFlushIn(body: Uint8Array): FuseFlushIn {
  const r = new Reader(body, "fuse_flush_in");
  const fh = r.u64();
  r.skip(8); // unused + padding
  const lockOwner = r.u64();
  r.end();
  return { fh, lockOwner };
}

function encodeFlushIn(value: FuseFlushIn): Uint8Array {
  const w = new Writer(24);
  w.u64(value.fh);
  w.skip(8);
  w.u64(value.lockOwner);
  return w.done();
}

function decodeReadIn(body: Uint8Array, ctx: ProtocolContext): FuseReadIn {
  const r = new Reader(body, "fuse_read_in");
  const value: FuseReadIn = {
    fh: r.u64(),
    offset: r.u64(),
    size: r.u32(),
    readFlags: r.u32(),
    lockOwner: 0n,
    flags: 0,
  };
  if (ctx.minor >= 9) {
    value.lockOwner = r.u64();
    value.flags = r.u32();
    r.skip(4);
  }
  r.end();
  return value;
}

function encodeReadIn(value: FuseReadIn, ctx: ProtocolContext): Uint8Array {
  const w = new Writer(readWriteInSize(ctx.minor));
  w.u64(value.fh);
  w.u64(value.offset);
  w.u32(value.size);
  w.u32(value.readFlags);
  if (ctx.minor >= 9) {
    w.u64(value.lockOwner);
    w.u32(value.flags);
    w.skip(4);
  }
  return w.done();
}

function decodeWriteIn(body: Uint8Array, ctx: ProtocolContext): FuseWriteIn {
  const r = new Reader(body, "fuse_write_in");
  const fh = r.u64();
  const offset = r.u64();
  const size = r.u32();
  const writeFlags = r.u32();
  let lockOwner = 0n;
  let flags = 0;
  if (ctx.minor >= 9) {
    lockOwner = r.u64();
    flags = r.u32();
    r.skip(4);
  }
  if (size > r.remaining) {
    throw new ProtocolError(
      `fuse_write_in.size is ${size} but only ${r.remaining} byte(s) of payload follow`,
    );
  }
  const data = r.raw(size);
  r.end();
  return { fh, offset, size, writeFlags, lockOwner, flags, data };
}

function encodeWriteIn(value: FuseWriteIn, ctx: ProtocolContext): Uint8Array {
  const head = readWriteInSize(ctx.minor);
  const w = new Writer(head + value.data.length);
  w.u64(value.fh);
  w.u64(value.offset);
  w.u32(value.data.length);
  w.u32(value.writeFlags);
  if (ctx.minor >= 9) {
    w.u64(value.lockOwner);
    w.u32(value.flags);
    w.skip(4);
  }
  w.raw(value.data);
  return w.done();
}

function decodeFsyncIn(body: Uint8Array): FuseFsyncIn {
  const r = new Reader(body, "fuse_fsync_in");
  const fh = r.u64();
  const fsyncFlags = r.u32();
  r.skip(4);
  r.end();
  return { fh, fsyncFlags };
}

function encodeFsyncIn(value: FuseFsyncIn): Uint8Array {
  const w = new Writer(16);
  w.u64(value.fh);
  w.u32(value.fsyncFlags);
  w.skip(4);
  return w.done();
}

function decodeSetxattrIn(body: Uint8Array, ctx: ProtocolContext): FuseSetxattrIn {
  const r = new Reader(body, "fuse_setxattr_in");
  const size = r.u32();
  const flags = r.u32();
  let setxattrFlags = 0;
  if (ctx.setxattrExt) {
    setxattrFlags = r.u32();
    r.skip(4);
  }
  const name = r.name();
  if (size > r.remaining) {
    throw new ProtocolError(
      `fuse_setxattr_in.size is ${size} but only ${r.remaining} byte(s) of value follow`,
    );
  }
  const value = r.raw(size);
  r.end();
  return { flags, setxattrFlags, name, value };
}

function encodeSetxattrIn(value: FuseSetxattrIn, ctx: ProtocolContext): Uint8Array {
  const name = nameBytes(value.name, "setxattr name");
  const head = ctx.setxattrExt ? 16 : FUSE_COMPAT_SETXATTR_IN_SIZE;
  const w = new Writer(head + name.length + 1 + value.value.length);
  w.u32(value.value.length);
  w.u32(value.flags);
  if (ctx.setxattrExt) {
    w.u32(value.setxattrFlags);
    w.skip(4);
  }
  w.name(name);
  w.raw(value.value);
  return w.done();
}

function decodeGetxattrIn(body: Uint8Array): FuseGetxattrIn {
  const r = new Reader(body, "fuse_getxattr_in");
  const size = r.u32();
  r.skip(4);
  const name = r.name();
  r.end();
  return { size, name };
}

function encodeGetxattrIn(value: FuseGetxattrIn): Uint8Array {
  const name = nameBytes(value.name, "getxattr name");
  const w = new Writer(8 + name.length + 1);
  w.u32(value.size);
  w.skip(4);
  w.name(name);
  return w.done();
}

function decodeListxattrIn(body: Uint8Array): FuseListxattrIn {
  const r = new Reader(body, "fuse_getxattr_in");
  const size = r.u32();
  r.skip(4);
  r.end();
  return { size };
}

function encodeListxattrIn(value: FuseListxattrIn): Uint8Array {
  const w = new Writer(8);
  w.u32(value.size);
  w.skip(4);
  return w.done();
}

function decodeLkIn(body: Uint8Array): FuseLkIn {
  const r = new Reader(body, "fuse_lk_in");
  const fh = r.u64();
  const owner = r.u64();
  const lk = readFileLock(r);
  const lkFlags = r.u32();
  r.skip(4);
  r.end();
  return { fh, owner, lk, lkFlags };
}

function encodeLkIn(value: FuseLkIn): Uint8Array {
  const w = new Writer(48);
  w.u64(value.fh);
  w.u64(value.owner);
  writeFileLock(w, value.lk);
  w.u32(value.lkFlags);
  w.skip(4);
  return w.done();
}

function decodeAccessIn(body: Uint8Array): FuseAccessIn {
  const r = new Reader(body, "fuse_access_in");
  const mask = r.u32();
  r.skip(4);
  r.end();
  return { mask };
}

function encodeAccessIn(value: FuseAccessIn): Uint8Array {
  const w = new Writer(8);
  w.u32(value.mask);
  w.skip(4);
  return w.done();
}

export function decodeInitIn(body: Uint8Array): FuseInitIn {
  const r = new Reader(body, "fuse_init_in");
  const value: FuseInitIn = {
    major: r.u32(),
    minor: r.u32(),
    maxReadahead: 0,
    flags: 0,
    flags2: 0,
  };
  // 7.0 and 7.1 sent only major/minor; 7.6 added max_readahead; 7.36 added
  // flags2 and the reserved tail. There is no negotiated version yet, so the
  // message's own length is the only thing that can decide.
  if (r.remaining >= 8) {
    value.maxReadahead = r.u32();
    value.flags = r.u32();
  }
  if (r.remaining >= 4) {
    value.flags2 = r.u32();
  }
  return value;
}

export function encodeInitIn(value: FuseInitIn): Uint8Array {
  // Always the full 7.36+ form: this is what a modern kernel sends, and a
  // decoder keyed on length reads the older forms fine.
  const w = new Writer(64);
  w.u32(value.major);
  w.u32(value.minor);
  w.u32(value.maxReadahead);
  w.u32(value.flags);
  w.u32(value.flags2);
  w.skip(44);
  return w.done();
}

function decodeInterruptIn(body: Uint8Array): FuseInterruptIn {
  const r = new Reader(body, "fuse_interrupt_in");
  const value = { unique: r.u64() };
  r.end();
  return value;
}

function encodeInterruptIn(value: FuseInterruptIn): Uint8Array {
  const w = new Writer(8);
  w.u64(value.unique);
  return w.done();
}

function decodePollIn(body: Uint8Array): FusePollIn {
  const r = new Reader(body, "fuse_poll_in");
  const value = { fh: r.u64(), kh: r.u64(), flags: r.u32(), events: r.u32() };
  r.end();
  return value;
}

function encodePollIn(value: FusePollIn): Uint8Array {
  const w = new Writer(24);
  w.u64(value.fh);
  w.u64(value.kh);
  w.u32(value.flags);
  w.u32(value.events);
  return w.done();
}

function decodeFallocateIn(body: Uint8Array): FuseFallocateIn {
  const r = new Reader(body, "fuse_fallocate_in");
  const fh = r.u64();
  const offset = r.u64();
  const length = r.u64();
  const mode = r.u32();
  r.skip(4);
  r.end();
  return { fh, offset, length, mode };
}

function encodeFallocateIn(value: FuseFallocateIn): Uint8Array {
  const w = new Writer(32);
  w.u64(value.fh);
  w.u64(value.offset);
  w.u64(value.length);
  w.u32(value.mode);
  w.skip(4);
  return w.done();
}

function decodeLseekIn(body: Uint8Array): FuseLseekIn {
  const r = new Reader(body, "fuse_lseek_in");
  const fh = r.u64();
  const offset = r.u64();
  const whence = r.u32();
  r.skip(4);
  r.end();
  return { fh, offset, whence };
}

function encodeLseekIn(value: FuseLseekIn): Uint8Array {
  const w = new Writer(24);
  w.u64(value.fh);
  w.u64(value.offset);
  w.u32(value.whence);
  w.skip(4);
  return w.done();
}

function decodeBmapIn(body: Uint8Array): FuseBmapIn {
  const r = new Reader(body, "fuse_bmap_in");
  const block = r.u64();
  const blocksize = r.u32();
  r.skip(4);
  r.end();
  return { block, blocksize };
}

function encodeBmapIn(value: FuseBmapIn): Uint8Array {
  const w = new Writer(16);
  w.u64(value.block);
  w.u32(value.blocksize);
  w.skip(4);
  return w.done();
}

// --- reply codecs ---

export function decodeAttrOut(body: Uint8Array, ctx?: ProtocolContext): FuseAttrOut {
  const { minor } = ctxOf(ctx);
  const r = new Reader(body, "fuse_attr_out");
  const attrValid = r.u64();
  const attrValidNsec = r.u32();
  r.skip(4);
  const attr = readAttr(r, minor);
  r.end();
  return { attrValid, attrValidNsec, attr };
}

export function encodeAttrOut(value: FuseAttrOut, ctx?: ProtocolContext): Uint8Array {
  const { minor } = ctxOf(ctx);
  const w = new Writer(attrOutSize(minor));
  w.u64(value.attrValid);
  w.u32(value.attrValidNsec);
  w.skip(4);
  writeAttr(w, value.attr, minor);
  return w.done();
}

export function decodeOpenOut(body: Uint8Array, ctx?: ProtocolContext): FuseOpenOut {
  const r = new Reader(body, "fuse_open_out");
  const value = readOpenOut(r, ctxOf(ctx).minor);
  r.end();
  return value;
}

export function encodeOpenOut(value: FuseOpenOut, ctx?: ProtocolContext): Uint8Array {
  const w = new Writer(16);
  writeOpenOut(w, value, ctxOf(ctx).minor);
  return w.done();
}

function decodeCreateOut(body: Uint8Array, ctx: ProtocolContext): FuseCreateOut {
  const r = new Reader(body, "fuse_entry_out + fuse_open_out");
  const entry = readEntryOut(r, ctx.minor);
  const open = readOpenOut(r, ctx.minor);
  r.end();
  return { entry, open };
}

function encodeCreateOut(value: FuseCreateOut, ctx: ProtocolContext): Uint8Array {
  const w = new Writer(entryOutSize(ctx.minor) + 16);
  writeEntryOut(w, value.entry, ctx.minor);
  writeOpenOut(w, value.open, ctx.minor);
  return w.done();
}

function decodeWriteOut(body: Uint8Array): FuseWriteOut {
  const r = new Reader(body, "fuse_write_out");
  const size = r.u32();
  r.skip(4);
  r.end();
  return { size };
}

function encodeWriteOut(value: FuseWriteOut): Uint8Array {
  const w = new Writer(8);
  w.u32(value.size);
  w.skip(4);
  return w.done();
}

export function decodeStatfsOut(body: Uint8Array, ctx?: ProtocolContext): FuseKstatfs {
  const { minor } = ctxOf(ctx);
  const r = new Reader(body, "fuse_statfs_out");
  const value: FuseKstatfs = {
    blocks: r.u64(),
    bfree: r.u64(),
    bavail: r.u64(),
    files: r.u64(),
    ffree: r.u64(),
    bsize: r.u32(),
    namelen: r.u32(),
    frsize: 0,
  };
  if (minor >= 4) {
    value.frsize = r.u32();
    r.skip(4 + 24); // padding + spare[6]
  }
  r.end();
  return value;
}

export function encodeStatfsOut(value: FuseKstatfs, ctx?: ProtocolContext): Uint8Array {
  const { minor } = ctxOf(ctx);
  const w = new Writer(kstatfsSize(minor));
  w.u64(value.blocks);
  w.u64(value.bfree);
  w.u64(value.bavail);
  w.u64(value.files);
  w.u64(value.ffree);
  w.u32(value.bsize);
  w.u32(value.namelen);
  if (minor >= 4) {
    w.u32(value.frsize);
    w.skip(4 + 24);
  }
  return w.done();
}

/**
 * The `GETXATTR`/`LISTXATTR` size-probe reply.
 *
 * The wire cannot distinguish this 8-byte struct from an 8-byte value, so the
 * generic `decodeReply` for those opcodes always returns raw data. Only the
 * caller that issued the request knows it asked for a size (`size === 0` in the
 * request), so it calls this explicitly.
 */
export function decodeGetxattrOut(body: Uint8Array): FuseGetxattrOut {
  const r = new Reader(body, "fuse_getxattr_out");
  const size = r.u32();
  r.skip(4);
  r.end();
  return { size };
}

export function encodeGetxattrOut(value: FuseGetxattrOut): Uint8Array {
  const w = new Writer(8);
  w.u32(value.size);
  w.skip(4);
  return w.done();
}

/** A `LISTXATTR` value reply: NUL-terminated names, back to back. */
export function encodeXattrNames(names: readonly string[]): Uint8Array {
  let size = 0;
  const encoded = names.map((name) => {
    const bytes = nameBytes(name, "xattr name");
    size += bytes.length + 1;
    return bytes;
  });
  const w = new Writer(size);
  for (const bytes of encoded) {
    w.name(bytes);
  }
  return w.done();
}

/** Split a `LISTXATTR` value reply back into names. */
export function decodeXattrNames(body: Uint8Array): string[] {
  const r = new Reader(body, "xattr name list");
  const names: string[] = [];
  while (r.remaining > 0) {
    names.push(r.name());
  }
  return names;
}

function decodeLkOut(body: Uint8Array): FuseLkOut {
  const r = new Reader(body, "fuse_lk_out");
  const lk = readFileLock(r);
  r.end();
  return { lk };
}

function encodeLkOut(value: FuseLkOut): Uint8Array {
  const w = new Writer(24);
  writeFileLock(w, value.lk);
  return w.done();
}

export function decodeInitOut(body: Uint8Array): FuseInitOut {
  const r = new Reader(body, "fuse_init_out");
  const value: FuseInitOut = {
    major: r.u32(),
    minor: r.u32(),
    maxReadahead: 0,
    flags: 0,
    maxBackground: 0,
    congestionThreshold: 0,
    maxWrite: 0,
    timeGran: 0,
    maxPages: 0,
    mapAlignment: 0,
    flags2: 0,
    maxStackDepth: 0,
  };
  if (r.remaining >= 8) {
    value.maxReadahead = r.u32();
    value.flags = r.u32();
  }
  if (r.remaining >= 8) {
    value.maxBackground = r.u16();
    value.congestionThreshold = r.u16();
    value.maxWrite = r.u32();
  }
  if (r.remaining >= 4) {
    value.timeGran = r.u32();
  }
  if (r.remaining >= 4) {
    value.maxPages = r.u16();
    value.mapAlignment = r.u16();
  }
  if (r.remaining >= 4) {
    value.flags2 = r.u32();
  }
  if (r.remaining >= 4) {
    value.maxStackDepth = r.u32();
  }
  return value;
}

/**
 * Encode `fuse_init_out` at the size its own `minor` implies: 8 bytes below
 * 7.5, 24 below 7.23, 64 from 7.23.
 *
 * **The size and the `minor` field come from one source — `value.minor`.** This
 * struct is the message that *announces* the negotiated version, so anything
 * else would let a reply claim one version and be laid out as another. A `ctx`
 * disagreeing with the value is a caller bug and throws rather than silently
 * picking a winner.
 */
export function encodeInitOut(value: FuseInitOut, ctx?: ProtocolContext): Uint8Array {
  if (ctx !== undefined && ctx.minor !== value.minor) {
    throw new ProtocolError(
      `fuse_init_out.minor is ${value.minor} but the session negotiated 7.${ctx.minor}`,
    );
  }
  const minor = value.minor;
  const w = new Writer(initOutSize(minor));
  w.u32(value.major);
  w.u32(value.minor);
  if (minor < 5) {
    return w.done();
  }
  w.u32(value.maxReadahead);
  w.u32(value.flags);
  w.u16(value.maxBackground);
  w.u16(value.congestionThreshold);
  w.u32(value.maxWrite);
  if (minor < 23) {
    return w.done();
  }
  w.u32(value.timeGran);
  w.u16(value.maxPages);
  w.u16(value.mapAlignment);
  w.u32(value.flags2);
  w.u32(value.maxStackDepth);
  w.skip(24);
  return w.done();
}

function decodePollOut(body: Uint8Array): FusePollOut {
  const r = new Reader(body, "fuse_poll_out");
  const revents = r.u32();
  r.skip(4);
  r.end();
  return { revents };
}

function encodePollOut(value: FusePollOut): Uint8Array {
  const w = new Writer(8);
  w.u32(value.revents);
  w.skip(4);
  return w.done();
}

function decodeLseekOut(body: Uint8Array): FuseLseekOut {
  const r = new Reader(body, "fuse_lseek_out");
  const value = { offset: r.u64() };
  r.end();
  return value;
}

function encodeLseekOut(value: FuseLseekOut): Uint8Array {
  const w = new Writer(8);
  w.u64(value.offset);
  return w.done();
}

function decodeBmapOut(body: Uint8Array): FuseBmapOut {
  const r = new Reader(body, "fuse_bmap_out");
  const value = { block: r.u64() };
  r.end();
  return value;
}

function encodeBmapOut(value: FuseBmapOut): Uint8Array {
  const w = new Writer(8);
  w.u64(value.block);
  return w.done();
}

function decodeReadlinkOut(body: Uint8Array): FuseReadlinkOut {
  const r = new Reader(body, "readlink target");
  return { target: r.restAsString() };
}

function encodeReadlinkOut(value: FuseReadlinkOut): Uint8Array {
  // No NUL terminator: the kernel takes the length from `fuse_out_header.len`.
  return nameBytes(value.target, "readlink target");
}

// ---------------------------------------------------------------------------
// dirents
// ---------------------------------------------------------------------------

/**
 * ```c
 * struct fuse_dirent {             // 24-byte header, then `namelen` name bytes
 *   uint64_t ino;                  //  0
 *   uint64_t off;                  //  8  cookie: where to resume *after* this
 *   uint32_t namelen;              // 16
 *   uint32_t type;                 // 20  DT_*
 *   char     name[];               // 24  no NUL, padded to an 8-byte boundary
 * };
 * ```
 */
export interface FuseDirent {
  ino: bigint;
  /**
   * The offset the kernel passes back in the *next* `READDIR` to resume after
   * this entry — not this entry's own position.
   */
  off: bigint;
  /** `DT_*`, i.e. `(mode & S_IFMT) >> 12`. */
  type: number;
  name: string;
}

/**
 * ```c
 * struct fuse_direntplus {
 *   struct fuse_entry_out entry_out;  //   0
 *   struct fuse_dirent    dirent;     // 128 (120 before 7.9)
 * };
 * ```
 */
export interface FuseDirentPlus {
  entry: FuseEntryOut;
  dirent: FuseDirent;
}

/** `FUSE_REC_ALIGN`: variable-length records sit on 8-byte boundaries. */
export function direntAlign(size: number): number {
  return (size + 7) & ~7;
}

/** `FUSE_DIRENT_SIZE`: bytes a `fuse_dirent` with this name occupies. */
export function direntSize(nameByteLength: number): number {
  return direntAlign(FUSE_DIRENT_HEADER_SIZE + nameByteLength);
}

/** `FUSE_DIRENTPLUS_SIZE`: bytes a `fuse_direntplus` with this name occupies. */
export function direntPlusSize(nameByteLength: number, ctx?: ProtocolContext): number {
  return direntAlign(entryOutSize(ctxOf(ctx).minor) + FUSE_DIRENT_HEADER_SIZE + nameByteLength);
}

/** `DT_*` for a `stat` mode: the file-type bits shifted down. */
export function direntType(mode: number): number {
  return (mode & 0o170000) >> 12;
}

export interface DirentPackerOptions {
  /** Pack `fuse_direntplus` (`READDIRPLUS`) rather than `fuse_dirent`. */
  plus?: boolean;
  ctx?: ProtocolContext;
}

/**
 * Fills a size-limited `READDIR` / `READDIRPLUS` reply buffer.
 *
 * The kernel hands over a byte budget (`fuse_read_in.size`) and a resume offset;
 * the server packs entries until `add` says no, replies with what fits, and
 * resumes at the `off` of the last entry that made it in. An entry that does not
 * fit is **not** partially written — `add` returns `false` and leaves the buffer
 * untouched, so the caller can hand the same entry to the next round.
 */
export class DirentPacker {
  /** Byte budget for this reply. */
  readonly maxSize: number;
  private readonly plus: boolean;
  private readonly ctx: ProtocolContext;
  private readonly chunks: Uint8Array[] = [];
  private used = 0;

  constructor(maxSize: number, options: DirentPackerOptions = {}) {
    this.maxSize = Math.max(0, Math.trunc(maxSize));
    this.plus = options.plus ?? false;
    this.ctx = ctxOf(options.ctx);
  }

  /** Bytes packed so far. */
  get size(): number {
    return this.used;
  }

  /** Entries packed so far. */
  get count(): number {
    return this.chunks.length;
  }

  /** Bytes still available. */
  get remaining(): number {
    return this.maxSize - this.used;
  }

  /**
   * Append an entry. Returns `false` (and changes nothing) if it does not fit.
   *
   * `entry` is required in `plus` mode and ignored otherwise.
   */
  add(dirent: FuseDirent, entry?: FuseEntryOut): boolean {
    if (this.plus && entry === undefined) {
      throw new ProtocolError("fuse_direntplus needs a fuse_entry_out");
    }
    const name = nameBytes(dirent.name, "dirent name");
    const headerSize = this.plus
      ? entryOutSize(this.ctx.minor) + FUSE_DIRENT_HEADER_SIZE
      : FUSE_DIRENT_HEADER_SIZE;
    const total = direntAlign(headerSize + name.length);
    if (this.used + total > this.maxSize) {
      return false;
    }
    const w = new Writer(total);
    if (entry !== undefined && this.plus) {
      writeEntryOut(w, entry, this.ctx.minor);
    }
    w.u64(dirent.ino);
    w.u64(dirent.off);
    w.u32(name.length);
    w.u32(dirent.type);
    w.raw(name);
    w.skip(total - headerSize - name.length); // zero padding to the 8-byte boundary
    this.chunks.push(w.done());
    this.used += total;
    return true;
  }

  /** The packed reply body. */
  build(): Uint8Array {
    const buffer = new Uint8Array(this.used);
    let offset = 0;
    for (const chunk of this.chunks) {
      buffer.set(chunk, offset);
      offset += chunk.length;
    }
    return buffer;
  }
}

/** Pack as many entries as fit into `maxSize`. */
export function packDirents(
  entries: Iterable<FuseDirent>,
  maxSize: number,
  ctx?: ProtocolContext,
): { buffer: Uint8Array; packed: number } {
  const packer = new DirentPacker(maxSize, { ctx });
  for (const dirent of entries) {
    if (!packer.add(dirent)) {
      break;
    }
  }
  return { buffer: packer.build(), packed: packer.count };
}

/** Pack as many `READDIRPLUS` entries as fit into `maxSize`. */
export function packDirentsPlus(
  entries: Iterable<FuseDirentPlus>,
  maxSize: number,
  ctx?: ProtocolContext,
): { buffer: Uint8Array; packed: number } {
  const packer = new DirentPacker(maxSize, { plus: true, ctx });
  for (const entry of entries) {
    if (!packer.add(entry.dirent, entry.entry)) {
      break;
    }
  }
  return { buffer: packer.build(), packed: packer.count };
}

function readDirent(r: Reader): FuseDirent {
  const ino = r.u64();
  const off = r.u64();
  const namelen = r.u32();
  const type = r.u32();
  if (namelen > r.remaining) {
    throw new ProtocolError(
      `fuse_dirent.namelen is ${namelen} but only ${r.remaining} byte(s) remain`,
      { offset: r.offset },
    );
  }
  const name = textDecoder.decode(r.bytes.subarray(r.offset, r.offset + namelen));
  r.skip(namelen);
  return { ino, off, type, name };
}

/** Unpack a `READDIR` reply body. */
export function unpackDirents(body: Uint8Array): FuseDirent[] {
  const r = new Reader(body, "fuse_dirent");
  const entries: FuseDirent[] = [];
  while (r.remaining > 0) {
    const start = r.offset;
    const dirent = readDirent(r);
    const padded = start + direntAlign(r.offset - start);
    if (padded > body.length) {
      throw new ProtocolError("fuse_dirent padding runs past the end of the buffer", {
        offset: r.offset,
      });
    }
    r.skip(padded - r.offset);
    entries.push(dirent);
  }
  return entries;
}

/** Unpack a `READDIRPLUS` reply body. */
export function unpackDirentsPlus(body: Uint8Array, ctx?: ProtocolContext): FuseDirentPlus[] {
  const { minor } = ctxOf(ctx);
  const r = new Reader(body, "fuse_direntplus");
  const entries: FuseDirentPlus[] = [];
  while (r.remaining > 0) {
    const start = r.offset;
    const entry = readEntryOut(r, minor);
    const dirent = readDirent(r);
    const padded = start + direntAlign(r.offset - start);
    if (padded > body.length) {
      throw new ProtocolError("fuse_direntplus padding runs past the end of the buffer", {
        offset: r.offset,
      });
    }
    r.skip(padded - r.offset);
    entries.push({ entry, dirent });
  }
  return entries;
}

/** A `READDIR` reply: the entries, already ordered. */
export interface FuseDirentsOut {
  entries: FuseDirent[];
}

/** A `READDIRPLUS` reply. */
export interface FuseDirentsPlusOut {
  entries: FuseDirentPlus[];
}

// ---------------------------------------------------------------------------
// opcode dispatch table
// ---------------------------------------------------------------------------

/**
 * One row of the opcode table: everything the session layer needs to handle an
 * opcode without a `switch`.
 *
 * The encode signatures take `never` so that concretely-typed encoders remain
 * assignable (parameters are contravariant) without an `any` anywhere. Call
 * them through {@link encodeRequestBody} / {@link encodeReplyBody}, which do the
 * single cast for you.
 */
export interface OpcodeSpec {
  readonly opcode: number;
  readonly name: string;
  /** Does the kernel expect a reply? `FORGET` and `BATCH_FORGET` do not. */
  readonly hasReply: boolean;
  decodeRequest(body: Uint8Array, ctx: ProtocolContext): unknown;
  encodeRequest(value: never, ctx: ProtocolContext): Uint8Array;
  decodeReply(body: Uint8Array, ctx: ProtocolContext): unknown;
  encodeReply(value: never, ctx: ProtocolContext): Uint8Array;
}

interface OpcodeDefinition<Req, Rep> {
  hasReply?: boolean;
  decodeRequest(body: Uint8Array, ctx: ProtocolContext): Req;
  encodeRequest(value: Req, ctx: ProtocolContext): Uint8Array;
  decodeReply(body: Uint8Array, ctx: ProtocolContext): Rep;
  encodeReply(value: Rep, ctx: ProtocolContext): Uint8Array;
}

function defineOp<Req, Rep>(opcode: number, definition: OpcodeDefinition<Req, Rep>): OpcodeSpec {
  return {
    opcode,
    name: opcodeName(opcode),
    hasReply: definition.hasReply ?? true,
    decodeRequest: definition.decodeRequest,
    encodeRequest: definition.encodeRequest,
    decodeReply: definition.decodeReply,
    encodeReply: definition.encodeReply,
  };
}

/** An op whose request has no body (`DESTROY`, `READLINK`, `STATFS`). */
function emptyRequest<Rep>(
  opcode: number,
  reply: Pick<OpcodeDefinition<FuseEmpty, Rep>, "decodeReply" | "encodeReply">,
): OpcodeSpec {
  return defineOp<FuseEmpty, Rep>(opcode, {
    decodeRequest: decodeEmpty,
    encodeRequest: encodeEmpty,
    ...reply,
  });
}

/** A reply that is nothing but a status. */
const statusReply = {
  decodeReply: decodeEmpty,
  encodeReply: encodeEmpty,
} as const;

/** A reply that is raw bytes. */
const rawReply = {
  decodeReply: decodeRawData,
  encodeReply: encodeRawData,
} as const;

const SPECS: readonly OpcodeSpec[] = [
  defineOp<FuseNameIn, FuseEntryOut>(FUSE_LOOKUP, {
    decodeRequest: decodeNameIn,
    encodeRequest: encodeNameIn,
    decodeReply: decodeEntryOut,
    encodeReply: encodeEntryOut,
  }),
  defineOp<FuseForgetIn, FuseEmpty>(FUSE_FORGET, {
    hasReply: false,
    decodeRequest: decodeForgetIn,
    encodeRequest: encodeForgetIn,
    ...statusReply,
  }),
  defineOp<FuseBatchForgetIn, FuseEmpty>(FUSE_BATCH_FORGET, {
    hasReply: false,
    decodeRequest: decodeBatchForgetIn,
    encodeRequest: encodeBatchForgetIn,
    ...statusReply,
  }),
  defineOp<FuseGetattrIn, FuseAttrOut>(FUSE_GETATTR, {
    decodeRequest: decodeGetattrIn,
    encodeRequest: encodeGetattrIn,
    decodeReply: decodeAttrOut,
    encodeReply: encodeAttrOut,
  }),
  defineOp<FuseSetattrIn, FuseAttrOut>(FUSE_SETATTR, {
    decodeRequest: decodeSetattrIn,
    encodeRequest: encodeSetattrIn,
    decodeReply: decodeAttrOut,
    encodeReply: encodeAttrOut,
  }),
  emptyRequest<FuseReadlinkOut>(FUSE_READLINK, {
    decodeReply: decodeReadlinkOut,
    encodeReply: encodeReadlinkOut,
  }),
  defineOp<FuseSymlinkIn, FuseEntryOut>(FUSE_SYMLINK, {
    decodeRequest: decodeSymlinkIn,
    encodeRequest: encodeSymlinkIn,
    decodeReply: decodeEntryOut,
    encodeReply: encodeEntryOut,
  }),
  defineOp<FuseMknodIn, FuseEntryOut>(FUSE_MKNOD, {
    decodeRequest: decodeMknodIn,
    encodeRequest: encodeMknodIn,
    decodeReply: decodeEntryOut,
    encodeReply: encodeEntryOut,
  }),
  defineOp<FuseMkdirIn, FuseEntryOut>(FUSE_MKDIR, {
    decodeRequest: decodeMkdirIn,
    encodeRequest: encodeMkdirIn,
    decodeReply: decodeEntryOut,
    encodeReply: encodeEntryOut,
  }),
  defineOp<FuseNameIn, FuseEmpty>(FUSE_UNLINK, {
    decodeRequest: decodeNameIn,
    encodeRequest: encodeNameIn,
    ...statusReply,
  }),
  defineOp<FuseNameIn, FuseEmpty>(FUSE_RMDIR, {
    decodeRequest: decodeNameIn,
    encodeRequest: encodeNameIn,
    ...statusReply,
  }),
  defineOp<FuseRenameIn, FuseEmpty>(FUSE_RENAME, {
    decodeRequest: decodeRenameIn,
    encodeRequest: encodeRenameIn,
    ...statusReply,
  }),
  defineOp<FuseRename2In, FuseEmpty>(FUSE_RENAME2, {
    decodeRequest: decodeRename2In,
    encodeRequest: encodeRename2In,
    ...statusReply,
  }),
  defineOp<FuseLinkIn, FuseEntryOut>(FUSE_LINK, {
    decodeRequest: decodeLinkIn,
    encodeRequest: encodeLinkIn,
    decodeReply: decodeEntryOut,
    encodeReply: encodeEntryOut,
  }),
  defineOp<FuseOpenIn, FuseOpenOut>(FUSE_OPEN, {
    decodeRequest: decodeOpenIn,
    encodeRequest: encodeOpenIn,
    decodeReply: decodeOpenOut,
    encodeReply: encodeOpenOut,
  }),
  defineOp<FuseOpenIn, FuseOpenOut>(FUSE_OPENDIR, {
    decodeRequest: decodeOpenIn,
    encodeRequest: encodeOpenIn,
    decodeReply: decodeOpenOut,
    encodeReply: encodeOpenOut,
  }),
  defineOp<FuseCreateIn, FuseCreateOut>(FUSE_CREATE, {
    decodeRequest: decodeCreateIn,
    encodeRequest: encodeCreateIn,
    decodeReply: decodeCreateOut,
    encodeReply: encodeCreateOut,
  }),
  defineOp<FuseReadIn, FuseRawData>(FUSE_READ, {
    decodeRequest: decodeReadIn,
    encodeRequest: encodeReadIn,
    ...rawReply,
  }),
  defineOp<FuseWriteIn, FuseWriteOut>(FUSE_WRITE, {
    decodeRequest: decodeWriteIn,
    encodeRequest: encodeWriteIn,
    decodeReply: decodeWriteOut,
    encodeReply: encodeWriteOut,
  }),
  defineOp<FuseReleaseIn, FuseEmpty>(FUSE_RELEASE, {
    decodeRequest: decodeReleaseIn,
    encodeRequest: encodeReleaseIn,
    ...statusReply,
  }),
  defineOp<FuseReleaseIn, FuseEmpty>(FUSE_RELEASEDIR, {
    decodeRequest: decodeReleaseIn,
    encodeRequest: encodeReleaseIn,
    ...statusReply,
  }),
  defineOp<FuseFsyncIn, FuseEmpty>(FUSE_FSYNC, {
    decodeRequest: decodeFsyncIn,
    encodeRequest: encodeFsyncIn,
    ...statusReply,
  }),
  defineOp<FuseFsyncIn, FuseEmpty>(FUSE_FSYNCDIR, {
    decodeRequest: decodeFsyncIn,
    encodeRequest: encodeFsyncIn,
    ...statusReply,
  }),
  defineOp<FuseFlushIn, FuseEmpty>(FUSE_FLUSH, {
    decodeRequest: decodeFlushIn,
    encodeRequest: encodeFlushIn,
    ...statusReply,
  }),
  defineOp<FuseReadIn, FuseDirentsOut>(FUSE_READDIR, {
    decodeRequest: decodeReadIn,
    encodeRequest: encodeReadIn,
    decodeReply: (body) => ({ entries: unpackDirents(body) }),
    // Unbounded on purpose: this row exists so the table is symmetric and the
    // round-trip tests can drive it. It ignores `fuse_read_in.size`, so a real
    // server must **not** reply through it — build the page with
    // `DirentPacker` (or `packDirents`) against the kernel's byte budget, or
    // the reply overruns the buffer the kernel offered.
    encodeReply: (value) => packDirents(value.entries, Number.MAX_SAFE_INTEGER).buffer,
  }),
  defineOp<FuseReadIn, FuseDirentsPlusOut>(FUSE_READDIRPLUS, {
    decodeRequest: decodeReadIn,
    encodeRequest: encodeReadIn,
    decodeReply: (body, ctx) => ({ entries: unpackDirentsPlus(body, ctx) }),
    // Symmetry and round-trip tests only — see the `FUSE_READDIR` note above.
    // Real replies go through `DirentPacker` / `packDirentsPlus`.
    encodeReply: (value, ctx) =>
      packDirentsPlus(value.entries, Number.MAX_SAFE_INTEGER, ctx).buffer,
  }),
  emptyRequest<FuseKstatfs>(FUSE_STATFS, {
    decodeReply: decodeStatfsOut,
    encodeReply: encodeStatfsOut,
  }),
  defineOp<FuseAccessIn, FuseEmpty>(FUSE_ACCESS, {
    decodeRequest: decodeAccessIn,
    encodeRequest: encodeAccessIn,
    ...statusReply,
  }),
  defineOp<FuseInitIn, FuseInitOut>(FUSE_INIT, {
    decodeRequest: decodeInitIn,
    encodeRequest: encodeInitIn,
    decodeReply: decodeInitOut,
    encodeReply: encodeInitOut,
  }),
  emptyRequest<FuseEmpty>(FUSE_DESTROY, statusReply),
  defineOp<FuseInterruptIn, FuseEmpty>(FUSE_INTERRUPT, {
    decodeRequest: decodeInterruptIn,
    encodeRequest: encodeInterruptIn,
    ...statusReply,
  }),
  defineOp<FuseSetxattrIn, FuseEmpty>(FUSE_SETXATTR, {
    decodeRequest: decodeSetxattrIn,
    encodeRequest: encodeSetxattrIn,
    ...statusReply,
  }),
  defineOp<FuseGetxattrIn, FuseRawData>(FUSE_GETXATTR, {
    decodeRequest: decodeGetxattrIn,
    encodeRequest: encodeGetxattrIn,
    ...rawReply,
  }),
  defineOp<FuseListxattrIn, FuseRawData>(FUSE_LISTXATTR, {
    decodeRequest: decodeListxattrIn,
    encodeRequest: encodeListxattrIn,
    ...rawReply,
  }),
  defineOp<FuseNameIn, FuseEmpty>(FUSE_REMOVEXATTR, {
    decodeRequest: decodeNameIn,
    encodeRequest: encodeNameIn,
    ...statusReply,
  }),
  defineOp<FuseFallocateIn, FuseEmpty>(FUSE_FALLOCATE, {
    decodeRequest: decodeFallocateIn,
    encodeRequest: encodeFallocateIn,
    ...statusReply,
  }),
  defineOp<FuseLseekIn, FuseLseekOut>(FUSE_LSEEK, {
    decodeRequest: decodeLseekIn,
    encodeRequest: encodeLseekIn,
    decodeReply: decodeLseekOut,
    encodeReply: encodeLseekOut,
  }),
  defineOp<FuseLkIn, FuseLkOut>(FUSE_GETLK, {
    decodeRequest: decodeLkIn,
    encodeRequest: encodeLkIn,
    decodeReply: decodeLkOut,
    encodeReply: encodeLkOut,
  }),
  defineOp<FuseLkIn, FuseEmpty>(FUSE_SETLK, {
    decodeRequest: decodeLkIn,
    encodeRequest: encodeLkIn,
    ...statusReply,
  }),
  defineOp<FuseLkIn, FuseEmpty>(FUSE_SETLKW, {
    decodeRequest: decodeLkIn,
    encodeRequest: encodeLkIn,
    ...statusReply,
  }),
  defineOp<FusePollIn, FusePollOut>(FUSE_POLL, {
    decodeRequest: decodePollIn,
    encodeRequest: encodePollIn,
    decodeReply: decodePollOut,
    encodeReply: encodePollOut,
  }),
  defineOp<FuseBmapIn, FuseBmapOut>(FUSE_BMAP, {
    decodeRequest: decodeBmapIn,
    encodeRequest: encodeBmapIn,
    decodeReply: decodeBmapOut,
    encodeReply: encodeBmapOut,
  }),
];

/**
 * opcode → codec. The session layer dispatches off this rather than a `switch`.
 *
 * Opcodes with no entry (`IOCTL`, `SETUPMAPPING`, `COPY_FILE_RANGE`, `STATX`,
 * `SYNCFS`, `TMPFILE`, `NOTIFY_REPLY`, `REMOVEMAPPING`, `CUSE_INIT`) are still
 * *decoded* by {@link decodeRequest} — header, name and raw payload — so an
 * unimplemented op is answered `-ENOSYS` rather than crashing the loop.
 */
export const OPCODES: ReadonlyMap<number, OpcodeSpec> = new Map(
  SPECS.map((spec) => [spec.opcode, spec]),
);

/** Opcodes this build knows a wire layout for, in ascending order. */
export const SUPPORTED_OPCODES: readonly number[] = SPECS.map((spec) => spec.opcode).sort(
  (a, b) => a - b,
);

/** Opcodes that are decoded as a raw payload and always answered `-ENOSYS`. */
export const UNIMPLEMENTED_OPCODES: readonly number[] = [
  FUSE_IOCTL,
  FUSE_NOTIFY_REPLY,
  FUSE_COPY_FILE_RANGE,
  FUSE_SETUPMAPPING,
  FUSE_REMOVEMAPPING,
  FUSE_SYNCFS,
  FUSE_TMPFILE,
  FUSE_STATX,
  CUSE_INIT,
];

function specOf(opcode: number): OpcodeSpec {
  const spec = OPCODES.get(opcode);
  if (spec === undefined) {
    throw new ProtocolError(`no codec for opcode ${opcodeName(opcode)}`);
  }
  return spec;
}

/** Decode an op's request body. Throws `ProtocolError` for unknown opcodes. */
export function decodeRequestBody(
  opcode: number,
  body: Uint8Array,
  ctx?: ProtocolContext,
): unknown {
  return specOf(opcode).decodeRequest(body, ctxOf(ctx));
}

/** Encode an op's request body (the synthetic-kernel direction). */
export function encodeRequestBody(
  opcode: number,
  value: unknown,
  ctx?: ProtocolContext,
): Uint8Array {
  const encode = specOf(opcode).encodeRequest as (v: unknown, c: ProtocolContext) => Uint8Array;
  return encode(value, ctxOf(ctx));
}

/** Decode an op's reply body. */
export function decodeReplyBody(opcode: number, body: Uint8Array, ctx?: ProtocolContext): unknown {
  return specOf(opcode).decodeReply(body, ctxOf(ctx));
}

/** Encode an op's reply body. */
export function encodeReplyBody(opcode: number, value: unknown, ctx?: ProtocolContext): Uint8Array {
  const encode = specOf(opcode).encodeReply as (v: unknown, c: ProtocolContext) => Uint8Array;
  return encode(value, ctxOf(ctx));
}

// ---------------------------------------------------------------------------
// whole messages
// ---------------------------------------------------------------------------

/** A decoded request: header, op payload, and the decoded body when known. */
export interface FuseRequest {
  header: FuseInHeader;
  /** Opcode name, or `UNKNOWN(<n>)`. */
  name: string;
  /** The op payload with the extension block stripped. */
  payload: Uint8Array;
  /** Request extensions (`total_extlen`, 7.38+), raw and undecoded. */
  extensions: Uint8Array;
  /** Decoded body, or `undefined` when no codec exists for the opcode. */
  body: unknown;
}

/**
 * Decode one complete request.
 *
 * `buffer` must hold at least `fuse_in_header.len` bytes; anything past that is
 * ignored, so a transport can pass its whole receive buffer.
 */
export function decodeRequest(buffer: Uint8Array, ctx?: ProtocolContext): FuseRequest {
  const header = decodeInHeader(buffer);
  if (header.len > buffer.length) {
    throw new ProtocolError(
      `fuse_in_header.len is ${header.len} but only ${buffer.length} byte(s) were read`,
    );
  }
  const extBytes = header.totalExtlen * 8;
  const bodyEnd = header.len - extBytes;
  if (bodyEnd < FUSE_IN_HEADER_SIZE) {
    throw new ProtocolError(
      `fuse_in_header.total_extlen is ${header.totalExtlen} (${extBytes} bytes), more than the ${
        header.len - FUSE_IN_HEADER_SIZE
      }-byte body`,
    );
  }
  const payload = buffer.subarray(FUSE_IN_HEADER_SIZE, bodyEnd);
  const extensions = buffer.slice(bodyEnd, header.len);
  const spec = OPCODES.get(header.opcode);
  return {
    header,
    name: opcodeName(header.opcode),
    payload: payload.slice(),
    extensions,
    body: spec === undefined ? undefined : spec.decodeRequest(payload, ctxOf(ctx)),
  };
}

/** What {@link encodeRequest} needs. `nodeid`/`uid`/`gid`/`pid` default to 0. */
export interface EncodeRequestInit {
  opcode: number;
  unique: bigint;
  nodeid?: bigint;
  uid?: number;
  gid?: number;
  pid?: number;
  /** Decoded body; encoded through the opcode table. */
  body?: unknown;
  /** Pre-encoded body. Used when `body` is absent (unknown opcodes). */
  payload?: Uint8Array;
  /** Request extensions, already 8-byte aligned (7.38+). */
  extensions?: Uint8Array;
}

/** Encode one complete request — what a kernel, or the synthetic one, sends. */
export function encodeRequest(init: EncodeRequestInit, ctx?: ProtocolContext): Uint8Array {
  const payload =
    init.body === undefined
      ? (init.payload ?? EMPTY_BYTES)
      : encodeRequestBody(init.opcode, init.body, ctx);
  const extensions = init.extensions ?? EMPTY_BYTES;
  if (extensions.length % 8 !== 0) {
    throw new ProtocolError(
      `request extensions must be a multiple of 8 bytes, got ${extensions.length}`,
    );
  }
  const len = FUSE_IN_HEADER_SIZE + payload.length + extensions.length;
  const message = new Uint8Array(len);
  message.set(
    encodeInHeader({
      len,
      opcode: init.opcode,
      unique: init.unique,
      nodeid: init.nodeid ?? 0n,
      uid: init.uid ?? 0,
      gid: init.gid ?? 0,
      pid: init.pid ?? 0,
      totalExtlen: extensions.length / 8,
    }),
  );
  message.set(payload, FUSE_IN_HEADER_SIZE);
  message.set(extensions, FUSE_IN_HEADER_SIZE + payload.length);
  return message;
}

/** A decoded reply. */
export interface FuseReply {
  header: FuseOutHeader;
  /** Raw reply body. Empty on an error reply. */
  payload: Uint8Array;
  /**
   * Decoded body, or `undefined` on an error reply / unknown opcode. Requires
   * the opcode, which the wire does not carry — the caller matched `unique`.
   */
  body: unknown;
}

/** Decode one complete reply, given the opcode its `unique` was issued for. */
export function decodeReply(buffer: Uint8Array, opcode: number, ctx?: ProtocolContext): FuseReply {
  const header = decodeOutHeader(buffer);
  if (header.len > buffer.length) {
    throw new ProtocolError(
      `fuse_out_header.len is ${header.len} but only ${buffer.length} byte(s) were read`,
    );
  }
  const payload = buffer.slice(FUSE_OUT_HEADER_SIZE, header.len);
  const spec = OPCODES.get(opcode);
  return {
    header,
    payload,
    body:
      header.error !== 0 || spec === undefined ? undefined : spec.decodeReply(payload, ctxOf(ctx)),
  };
}

/** Encode a complete successful reply for an opcode's decoded body. */
export function encodeReplyFor(
  unique: bigint,
  opcode: number,
  value: unknown,
  ctx?: ProtocolContext,
): Uint8Array {
  return encodeReply(unique, encodeReplyBody(opcode, value, ctx));
}

/** UTF-8 byte length of a name, for `direntSize` and buffer budgeting. */
export function nameByteLength(name: string): number {
  return utf8Length(name);
}
