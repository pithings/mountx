/**
 * XDR (RFC 4506): the codec primitives everything else in `src/nfs/` is built
 * from.
 *
 * Deliberately tiny and deliberately total. XDR has exactly four shapes worth
 * modelling — a 4-byte-aligned scalar, a counted byte string, an optional, and
 * an array — and every NFS struct is a literal transcription over them.
 *
 * Conventions, applied without exception (they mirror `src/fuse/protocol.ts`,
 * which is the same job for the other transport):
 *
 * - **Everything is big-endian.** That is XDR, not a choice.
 * - **Every 64-bit field is a `bigint`; every 32-bit one a `number`.** NFS uses
 *   the full 64 bits of `size3`, `offset3`, `cookie3` and `fileid3`, so a
 *   `number` would silently corrupt large files.
 * - **Decoding is total.** A truncated or malformed buffer throws
 *   {@link XdrError} and nothing else — never a `RangeError`, never silent
 *   garbage. That invariant is fuzzed, and it is what keeps a malformed RPC
 *   record from taking a mounted filesystem down with it.
 * - **Decoders copy.** Byte payloads are copied out of the input, so a server
 *   can reuse its receive buffer and nothing downstream ever holds a view of
 *   socket memory. The copy is spelled `Uint8Array.prototype.slice.call`
 *   deliberately: the input is very often a `Buffer`, and
 *   `Buffer.prototype.slice` **is `subarray`** — it does not copy. That exact
 *   trap corrupted the first FUSE transcripts (see `src/fuse/record.ts`), and
 *   here it would hand a driver a view of the socket's receive pool to store.
 * - **Every variable-length read is bounded.** An unchecked `count` read from
 *   the wire is an allocation an attacker chooses the size of; every reader
 *   here checks the count against the bytes actually present *before* it
 *   allocates, and the string/opaque readers take an explicit maximum on top.
 */

/**
 * A message could not be decoded (or encoded): truncated, malformed, or
 * describing more data than it carries.
 *
 * This is the **only** error type the codecs throw. A server that catches
 * `XdrError` and nothing else has covered every failure mode of this layer,
 * which is what makes the decoders fuzzable — the same contract
 * `ProtocolError` has on the FUSE side.
 */
export class XdrError extends Error {
  readonly code = "ERR_NFS_XDR";
  /** Byte offset the failure was detected at, when meaningful. */
  readonly offset: number | undefined;

  constructor(message: string, options: { offset?: number; cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "XdrError";
    this.offset = options.offset;
  }
}

/** Is this an {@link XdrError}? */
export function isXdrError(error: unknown): error is XdrError {
  return error instanceof XdrError;
}

/** XDR pads every item out to a multiple of four bytes. */
export function xdrPad(length: number): number {
  return (4 - (length % 4)) % 4;
}

/** Bytes an opaque of `length` occupies on the wire, padding included. */
export function xdrAlign(length: number): number {
  return length + xdrPad(length);
}

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

/**
 * Default ceiling on a counted item's length.
 *
 * Nothing in NFSv3 legitimately exceeds this in a single field — the largest is
 * a READ/WRITE payload, capped by the server's own `rtmax`/`wtmax` — so it is a
 * blunt but effective guard against a length field that says 4 GiB.
 */
export const XDR_MAX_ITEM = 16 * 1024 * 1024;

/** A bounds-checked reader over one XDR message. */
export class XdrReader {
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
      throw new XdrError(`truncated ${what}: need ${count} bytes, ${this.remaining} left`, {
        offset: this.#offset,
      });
    }
    const at = this.#offset;
    this.#offset += count;
    return at;
  }

  /** `unsigned int` / `enum` / `bool`'s underlying word. */
  u32(what = "uint32"): number {
    return this.#view.getUint32(this.#need(4, what), false);
  }

  /** `int` — signed, which a handful of RPC fields genuinely are. */
  i32(what = "int32"): number {
    return this.#view.getInt32(this.#need(4, what), false);
  }

  /** `unsigned hyper`. */
  u64(what = "uint64"): bigint {
    return this.#view.getBigUint64(this.#need(8, what), false);
  }

  /** `hyper`. */
  i64(what = "int64"): bigint {
    return this.#view.getBigInt64(this.#need(8, what), false);
  }

  /**
   * `bool`.
   *
   * XDR says a bool is 0 or 1 and nothing else; anything else is a malformed
   * message rather than a truthy value, and accepting it would let two peers
   * disagree about how many optional fields follow.
   */
  bool(what = "bool"): boolean {
    const value = this.u32(what);
    if (value > 1) {
      throw new XdrError(`invalid ${what}: ${value} is not 0 or 1`, { offset: this.#offset - 4 });
    }
    return value === 1;
  }

  /** `opaque[n]` — fixed length, padded. */
  fixedOpaque(length: number, what = "opaque"): Uint8Array {
    const at = this.#need(xdrAlign(length), what);
    return copyBytes(this.bytes, at, at + length);
  }

  /** `opaque<max>` — counted and padded. */
  varOpaque(max = XDR_MAX_ITEM, what = "opaque<>"): Uint8Array {
    const length = this.u32(`${what} length`);
    if (length > max) {
      throw new XdrError(`${what} is ${length} bytes, over the ${max}-byte limit`, {
        offset: this.#offset - 4,
      });
    }
    const at = this.#need(xdrAlign(length), what);
    return copyBytes(this.bytes, at, at + length);
  }

  /**
   * `string<max>`.
   *
   * Decoded as UTF-8, lossily: NFS names are really bytes (IDEA.md says the
   * same of driver paths), and a name that is not valid UTF-8 must not be able
   * to throw its way out of a decoder.
   */
  string(max = XDR_MAX_ITEM, what = "string<>"): string {
    return decoder.decode(this.varOpaque(max, what));
  }

  /** `type *item` / `union switch (bool)` — the XDR optional. */
  optional<T>(read: (reader: XdrReader) => T, what = "optional"): T | undefined {
    return this.bool(`${what} present`) ? read(this) : undefined;
  }

  /**
   * `item<max>` — a counted array.
   *
   * The count is checked against the bytes actually present before anything is
   * allocated: `read` may consume as little as four bytes per item, so a count
   * larger than a quarter of what is left cannot possibly be honest.
   */
  array<T>(read: (reader: XdrReader) => T, max = 1 << 20, what = "array"): T[] {
    const count = this.u32(`${what} count`);
    if (count > max || count > this.remaining / 4) {
      throw new XdrError(`${what} claims ${count} items, which cannot fit`, {
        offset: this.#offset - 4,
      });
    }
    const items: T[] = [];
    for (let index = 0; index < count; index++) {
      items.push(read(this));
    }
    return items;
  }

  /**
   * A linked list — `struct entry { …; entry *next; }`, how RFC 1813 spells
   * every list it has.
   *
   * `max` bounds it for the same reason {@link XdrReader.array} bounds its
   * count: a hostile stream of "yes, another one" would otherwise be unbounded.
   */
  list<T>(read: (reader: XdrReader) => T, max = 1 << 20, what = "list"): T[] {
    const items: T[] = [];
    while (this.bool(`${what} next`)) {
      if (items.length >= max) {
        throw new XdrError(`${what} is longer than ${max} items`, { offset: this.#offset });
      }
      items.push(read(this));
    }
    return items;
  }

  /** Everything not yet read, copied. */
  rest(): Uint8Array {
    const at = this.#need(this.remaining, "rest");
    return copyBytes(this.bytes, at, this.bytes.byteLength);
  }

  /** Assert the message is fully consumed. */
  end(what = "message"): void {
    if (this.remaining !== 0) {
      throw new XdrError(`${what} has ${this.remaining} trailing bytes`, { offset: this.#offset });
    }
  }
}

/** A growable XDR writer. */
export class XdrWriter {
  #bytes: Uint8Array;
  #view: DataView;
  #length = 0;

  constructor(capacity = 512) {
    this.#bytes = new Uint8Array(Math.max(16, capacity));
    this.#view = new DataView(this.#bytes.buffer);
  }

  /** Bytes written so far. */
  get length(): number {
    return this.#length;
  }

  /**
   * Make room for exactly `count` more bytes, writing none of them.
   *
   * Growth is otherwise geometric, so a writer that starts small and ends at a
   * megabyte copies about twice its final size getting there. A caller that
   * knows what it is about to write says so once and pays a single allocation.
   *
   * **Exactly**, not the next doubling — because {@link XdrWriter.view} hands
   * out the buffer rather than an exact-size copy of it, so whatever capacity
   * this leaves unused is retained for as long as the caller holds the view.
   * Doubling here would mean a 1 MiB reply pinning 2 MiB in a socket's write
   * queue. That also means this is for a caller that knows its **total**: call
   * it once, with the whole of what is coming. Calling it per item, in a loop,
   * is quadratic — that is what the geometric path exists for.
   */
  ensure(count: number): this {
    const needed = this.#length + count;
    if (needed > this.#bytes.byteLength) {
      this.#reallocate(needed);
    }
    return this;
  }

  /**
   * Discard everything written past `length`.
   *
   * For the one caller that has to encode a message to find out how big it is
   * and then encode a different one (NFSv4.1's `NFS4ERR_REP_TOO_BIG_TO_CACHE`,
   * §2.10.6.4). Rewriting a span is safe here because every writer below
   * covers every byte it claims — see {@link XdrWriter.fixedOpaque}, the only
   * one where that is not obvious.
   */
  truncate(length: number): this {
    if (length < 0 || length > this.#length) {
      throw new XdrError(`cannot truncate to ${length} bytes of ${this.#length} written`);
    }
    this.#length = length;
    return this;
  }

  /** Growth nobody predicted: double until it fits, so appending stays amortized O(1). */
  #grow(needed: number): void {
    let capacity = this.#bytes.byteLength * 2;
    while (capacity < needed) {
      capacity *= 2;
    }
    this.#reallocate(capacity);
  }

  #reallocate(capacity: number): void {
    const grown = new Uint8Array(capacity);
    grown.set(this.#bytes.subarray(0, this.#length));
    this.#bytes = grown;
    this.#view = new DataView(grown.buffer);
  }

  #room(count: number): number {
    const needed = this.#length + count;
    if (needed > this.#bytes.byteLength) {
      this.#grow(needed);
    }
    const at = this.#length;
    this.#length = needed;
    return at;
  }

  // N.B. each of these takes the offset from `#room` into a local *before* it
  // touches `#view`. `this.#view.setUint32(this.#room(4), …)` evaluates
  // `this.#view` first and only then calls `#room` — which is precisely the
  // call that may replace it, so the write would land in the discarded buffer
  // the moment the writer grew. (Found by the first test that wrote past the
  // initial capacity.)
  u32(value: number): this {
    const at = this.#room(4);
    this.#view.setUint32(at, value >>> 0, false);
    return this;
  }

  i32(value: number): this {
    const at = this.#room(4);
    this.#view.setInt32(at, value | 0, false);
    return this;
  }

  u64(value: bigint): this {
    const at = this.#room(8);
    this.#view.setBigUint64(at, BigInt.asUintN(64, value), false);
    return this;
  }

  i64(value: bigint): this {
    const at = this.#room(8);
    this.#view.setBigInt64(at, BigInt.asIntN(64, value), false);
    return this;
  }

  bool(value: boolean): this {
    return this.u32(value ? 1 : 0);
  }

  /**
   * `opaque[n]`: exactly `length` bytes (zero-filled if short), then padding.
   *
   * The two writes below cover the whole span between them — `set` takes
   * `[at, at + copied)` and the `fill` takes the rest — so nothing needs
   * pre-zeroing, and nothing here depends on what the buffer held before.
   * (It used to `fill` the whole span first and then overwrite most of it: a
   * second full pass over every `READ` payload the server sends, measured at
   * 15–20 µs per MiB, ~15% of `varOpaque`.) Keep that total-coverage property
   * if this is ever rearranged — {@link XdrWriter.truncate} lets a span be
   * written twice, so "the buffer is still zero here" is not available.
   */
  fixedOpaque(value: Uint8Array, length = value.byteLength): this {
    const size = xdrAlign(length);
    const at = this.#room(size);
    const copied = Math.min(value.byteLength, length);
    this.#bytes.set(value.subarray(0, copied), at);
    if (copied < size) {
      this.#bytes.fill(0, at + copied, at + size);
    }
    return this;
  }

  /** `opaque<>`: length, bytes, padding. */
  varOpaque(value: Uint8Array): this {
    this.u32(value.byteLength);
    return this.fixedOpaque(value);
  }

  /** `string<>`, encoded UTF-8. */
  string(value: string): this {
    return this.varOpaque(encoder.encode(value));
  }

  /** The XDR optional: a bool, then the value if there is one. */
  optional<T>(value: T | undefined, write: (writer: XdrWriter, value: T) => void): this {
    if (value === undefined) {
      return this.bool(false);
    }
    this.bool(true);
    write(this, value);
    return this;
  }

  /** `item<>`: a count, then the items. */
  array<T>(values: readonly T[], write: (writer: XdrWriter, value: T) => void): this {
    this.u32(values.length);
    for (const value of values) {
      write(this, value);
    }
    return this;
  }

  /** RFC 1813's linked list: `true`, item, …, `false`. */
  list<T>(values: readonly T[], write: (writer: XdrWriter, value: T) => void): this {
    for (const value of values) {
      this.bool(true);
      write(this, value);
    }
    return this.bool(false);
  }

  /** Raw bytes, already aligned by the caller. */
  raw(value: Uint8Array): this {
    // Same ordering hazard as the scalar writers above: `#room` may replace
    // `#bytes`, so the offset comes first.
    const at = this.#room(value.byteLength);
    this.#bytes.set(value, at);
    return this;
  }

  /** The message, copied out. */
  bytes(): Uint8Array {
    return this.#bytes.slice(0, this.#length);
  }

  /**
   * The message **without** copying it: a view of this writer's own buffer.
   *
   * The rule is ownership, and it is the mirror of the one `rpc.ts`'s
   * `RecordAssembler` follows on the way in. There a record is always copied,
   * because the buffer underneath it belongs to the socket and will be written
   * again. Here the buffer belongs to *this writer* and to nothing else, so
   * handing out a view is safe exactly when the writer is finished with:
   *
   * - **One writer per reply, never pooled or reused.** The sessions build one
   *   per call and drop it at `return`; two concurrent calls never share one.
   * - **No writing after `view()`.** Any `u32`/`raw`/`truncate` past that point
   *   rewrites bytes the caller is holding, and a grow would leave it holding
   *   the *old* buffer — silently stale rather than loudly wrong.
   *
   * When neither can be guaranteed, {@link XdrWriter.bytes} is the honest call.
   */
  view(): Uint8Array {
    return this.#bytes.subarray(0, this.#length);
  }
}

/** Encode with a fresh writer. */
export function encodeXdr(write: (writer: XdrWriter) => void, capacity?: number): Uint8Array {
  const writer = new XdrWriter(capacity);
  write(writer);
  return writer.bytes();
}

/** Decode a whole message, insisting nothing is left over. */
export function decodeXdr<T>(bytes: Uint8Array, read: (reader: XdrReader) => T, what?: string): T {
  const reader = new XdrReader(bytes);
  const value = read(reader);
  reader.end(what);
  return value;
}

/** Byte length of a UTF-8 string, for the size accounting READDIR needs. */
export function stringByteLength(value: string): number {
  return encoder.encode(value).byteLength;
}
