/**
 * The 9P wire primitives: the codec everything else in `src/9p/` is built from.
 *
 * 9P's encoding is the simplest of the three transports here — a message is a
 * struct written field by field with no framing inside it — so this file is
 * small on purpose, and the rules it applies are absolute:
 *
 * - **Everything is little-endian and unaligned.** That is the protocol, not a
 *   choice: 9P was defined on a little-endian machine and never grew padding,
 *   so a `u8` followed by a `u32` occupies five bytes, not eight. This is the
 *   one respect in which 9P is the opposite of XDR (`src/nfs/xdr.ts`), which is
 *   big-endian and pads everything to four bytes — do not carry habits across.
 * - **Every 64-bit field is a `bigint`; every narrower one a `number`.** A qid
 *   path, an offset and a file length all use the full 64 bits, so a `number`
 *   would silently corrupt large files and collide inodes.
 * - **A string is `s[2]`: a `u16` byte count, then that many UTF-8 bytes.** No
 *   padding, no NUL terminator, and the count is bytes rather than characters.
 *   The 16-bit count is a hard structural ceiling — see {@link P9_MAX_STRING}.
 * - **Decoding is total.** A truncated or malformed buffer throws {@link P9Error}
 *   and nothing else — never a `RangeError`, never silent garbage. That is what
 *   keeps a hostile frame from taking a mounted filesystem down with it, and it
 *   is the property the fuzz suite attacks.
 * - **Decoders copy.** Byte payloads are copied out of the input so a server can
 *   reuse its receive buffer and nothing downstream ever holds a view of socket
 *   memory. The copy is spelled `Uint8Array.prototype.slice.call` deliberately:
 *   the input is very often a `Buffer`, and `Buffer.prototype.slice` **is
 *   `subarray`** — it does not copy. That exact trap corrupted the first FUSE
 *   transcripts (`src/fuse/record.ts`) and an NFS `WRITE` payload before it, and
 *   here it would hand a driver a window onto the connection's read buffer.
 * - **Every variable-length read is bounded.** A count read from the wire is an
 *   allocation an attacker chooses the size of; every reader here checks the
 *   count against the bytes actually present *before* it allocates, and takes an
 *   explicit maximum on top.
 */

/**
 * A message could not be decoded (or encoded): truncated, malformed, or
 * describing more data than it carries.
 *
 * This is the **only** error type the codecs throw, which is what makes them
 * fuzzable — the same contract `XdrError` has on the NFS side and
 * `ProtocolError` on the FUSE one.
 */
export class P9Error extends Error {
  readonly code = "ERR_9P_WIRE";
  /** Byte offset the failure was detected at, when meaningful. */
  readonly offset: number | undefined;

  constructor(message: string, options: { offset?: number; cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "P9Error";
    this.offset = options.offset;
  }
}

/** Is this a {@link P9Error}? */
export function isP9Error(error: unknown): error is P9Error {
  return error instanceof P9Error;
}

/**
 * A qid — 9P's file identity, `struct p9_qid` in `include/net/9p/9p.h`.
 *
 * `type` is a bitmask of the `P9_QT*` values, `version` a change counter the
 * client may cache on, and `path` a server-unique id, roughly an inode number.
 */
export interface P9Qid {
  /** `P9_QT*` bits. */
  type: number;
  /** Bumped on every modification; `0` means "never cache this". */
  version: number;
  /** Server-unique identity, the full 64 bits. */
  path: bigint;
}

/** Bytes a qid occupies: `type[1] version[4] path[8]`, unaligned. */
export const P9_QID_SIZE = 13;

/**
 * Ceiling on a string, and a structural one: the count field is 16 bits, so a
 * longer string cannot be expressed at all.
 */
export const P9_MAX_STRING = 0xff_ff;

/**
 * Default ceiling on a `count[4]`-prefixed byte blob.
 *
 * The negotiated `msize` is the real bound — no message may exceed it — but a
 * decoder is handed bytes before anyone has checked that, so it carries a blunt
 * guard of its own against a count field that says 4 GiB.
 */
export const P9_MAX_ITEM = 16 * 1024 * 1024;

/**
 * A genuine copy, whatever the input is.
 *
 * `bytes.slice()` would call `Buffer.prototype.slice` for a `Buffer` — which is
 * `subarray`, and returns a view. See the module docs.
 */
const copyBytes = (bytes: Uint8Array, start: number, end: number): Uint8Array =>
  Uint8Array.prototype.slice.call(bytes, start, end);

const encoder = new TextEncoder();
/** `fatal: false`: a name that is not valid UTF-8 becomes U+FFFD rather than throwing. */
const decoder = new TextDecoder("utf8");

/** A bounds-checked reader over one 9P message. */
export class P9Reader {
  readonly bytes: Uint8Array;
  #offset = 0;
  readonly #view: DataView;

  constructor(bytes: Uint8Array, offset = 0) {
    this.bytes = bytes;
    this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.#offset = offset;
  }

  /** Bytes consumed so far. */
  get offset(): number {
    return this.#offset;
  }

  /** Bytes left in the message. */
  get remaining(): number {
    return this.bytes.byteLength - this.#offset;
  }

  /** Are we exactly at the end? */
  get atEnd(): boolean {
    return this.#offset >= this.bytes.byteLength;
  }

  #need(count: number, what: string): number {
    if (count < 0 || this.remaining < count) {
      throw new P9Error(`truncated ${what}: need ${count} bytes, ${this.remaining} left`, {
        offset: this.#offset,
      });
    }
    const at = this.#offset;
    this.#offset += count;
    return at;
  }

  /** `type[1]` — a message type, a qid type, a lock type. */
  u8(what = "uint8"): number {
    return this.#view.getUint8(this.#need(1, what));
  }

  /** `tag[2]` / `nwname[2]` / a string's count. */
  u16(what = "uint16"): number {
    return this.#view.getUint16(this.#need(2, what), true);
  }

  /** `size[4]` / `fid[4]` / `mode[4]`. */
  u32(what = "uint32"): number {
    return this.#view.getUint32(this.#need(4, what), true);
  }

  /** `offset[8]` / `path[8]` / a getattr mask — always the full 64 bits. */
  u64(what = "uint64"): bigint {
    return this.#view.getBigUint64(this.#need(8, what), true);
  }

  /**
   * `s[2]` — a `u16` byte count then that many UTF-8 bytes.
   *
   * Decoded lossily: 9P names are really bytes (so are driver paths), and a
   * name that is not valid UTF-8 must not be able to throw its way out of a
   * decoder.
   */
  string(max = P9_MAX_STRING, what = "string"): string {
    const length = this.u16(`${what} length`);
    if (length > max) {
      throw new P9Error(`${what} is ${length} bytes, over the ${max}-byte limit`, {
        offset: this.#offset - 2,
      });
    }
    const at = this.#need(length, what);
    return decoder.decode(this.bytes.subarray(at, at + length));
  }

  /** `qid[13]` — `type[1] version[4] path[8]`. */
  qid(what = "qid"): P9Qid {
    return {
      type: this.u8(`${what} type`),
      version: this.u32(`${what} version`),
      path: this.u64(`${what} path`),
    };
  }

  /** `count[4] data[count]` — a Twrite or Rread payload. Copied. */
  blob(max = P9_MAX_ITEM, what = "data"): Uint8Array {
    const length = this.u32(`${what} count`);
    if (length > max) {
      throw new P9Error(`${what} is ${length} bytes, over the ${max}-byte limit`, {
        offset: this.#offset - 4,
      });
    }
    return this.raw(length, what);
  }

  /** Exactly `count` bytes, the length known from elsewhere. Copied. */
  raw(count: number, what = "bytes"): Uint8Array {
    const at = this.#need(count, what);
    return copyBytes(this.bytes, at, at + count);
  }

  /** Everything not yet read, copied. */
  rest(): Uint8Array {
    return this.raw(this.remaining, "rest");
  }

  /** Assert the message is fully consumed. */
  end(what = "message"): void {
    if (this.remaining !== 0) {
      throw new P9Error(`${what} has ${this.remaining} trailing bytes`, { offset: this.#offset });
    }
  }
}

/** A growable 9P writer. */
export class P9Writer {
  #bytes: Uint8Array;
  #view: DataView;
  #length = 0;

  constructor(capacity = 256) {
    this.#bytes = new Uint8Array(Math.max(16, capacity));
    this.#view = new DataView(this.#bytes.buffer);
  }

  /** Bytes written so far. */
  get length(): number {
    return this.#length;
  }

  #room(count: number): number {
    const needed = this.#length + count;
    if (needed > this.#bytes.byteLength) {
      let capacity = this.#bytes.byteLength * 2;
      while (capacity < needed) {
        capacity *= 2;
      }
      const grown = new Uint8Array(capacity);
      grown.set(this.#bytes.subarray(0, this.#length));
      this.#bytes = grown;
      this.#view = new DataView(grown.buffer);
    }
    const at = this.#length;
    this.#length = needed;
    return at;
  }

  // N.B. each of these takes the offset from `#room` into a local *before* it
  // touches `#view`. `this.#view.setUint32(this.#room(4), …)` evaluates
  // `this.#view` first and only then calls `#room` — which is precisely the call
  // that may replace it, so the write would land in the discarded buffer the
  // moment the writer grew. (`src/nfs/xdr.ts` carries the same note; the first
  // test to write past the initial capacity found it there.)
  u8(value: number): this {
    const at = this.#room(1);
    this.#view.setUint8(at, value & 0xff);
    return this;
  }

  u16(value: number): this {
    const at = this.#room(2);
    this.#view.setUint16(at, value & 0xff_ff, true);
    return this;
  }

  u32(value: number): this {
    const at = this.#room(4);
    this.#view.setUint32(at, value >>> 0, true);
    return this;
  }

  u64(value: bigint): this {
    const at = this.#room(8);
    this.#view.setBigUint64(at, BigInt.asUintN(64, value), true);
    return this;
  }

  /** `s[2]`, encoded UTF-8. */
  string(value: string): this {
    const encoded = encoder.encode(value);
    if (encoded.byteLength > P9_MAX_STRING) {
      // Not a truncation: a 16-bit count cannot describe it, so writing it at
      // all would produce a frame some other length's worth of bytes long.
      throw new P9Error(`string is ${encoded.byteLength} bytes, over the 16-bit count`);
    }
    this.u16(encoded.byteLength);
    return this.raw(encoded);
  }

  /** `qid[13]`. */
  qid(value: P9Qid): this {
    this.u8(value.type);
    this.u32(value.version);
    return this.u64(value.path);
  }

  /** `count[4] data[count]`. */
  blob(value: Uint8Array): this {
    this.u32(value.byteLength);
    return this.raw(value);
  }

  /** Bytes with no count of their own. */
  raw(value: Uint8Array): this {
    // Same ordering hazard as the scalar writers above: `#room` may replace
    // `#bytes`, so the offset comes first.
    const at = this.#room(value.byteLength);
    this.#bytes.set(value, at);
    return this;
  }

  /**
   * Overwrite a `u32` already written — how a framer fills in `size[4]` once it
   * knows how long the message turned out to be.
   */
  patchU32(at: number, value: number): this {
    if (at < 0 || at + 4 > this.#length) {
      throw new P9Error(`cannot patch 4 bytes at ${at} of ${this.#length}`, { offset: at });
    }
    this.#view.setUint32(at, value >>> 0, true);
    return this;
  }

  /** The message, copied out. */
  bytes(): Uint8Array {
    return this.#bytes.slice(0, this.#length);
  }
}

/** Encode with a fresh writer. */
export function encodeP9(write: (writer: P9Writer) => void, capacity?: number): Uint8Array {
  const writer = new P9Writer(capacity);
  write(writer);
  return writer.bytes();
}

/** Decode a whole message, insisting nothing is left over. */
export function decodeP9<T>(bytes: Uint8Array, read: (reader: P9Reader) => T, what?: string): T {
  const reader = new P9Reader(bytes);
  const value = read(reader);
  reader.end(what);
  return value;
}

/** Byte length of a UTF-8 string, for the size accounting readdir needs. */
export function stringByteLength(value: string): number {
  return encoder.encode(value).byteLength;
}
