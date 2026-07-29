/**
 * `aws-chunked`: the framing an S3 client wraps a body in when it signs the
 * payload as a stream rather than hashing it up front.
 *
 * Transcribed from:
 *
 * - **Amazon S3 API Reference, "Signature Calculations for the Authorization
 *   Header: Transferring Payload in Multiple Chunks (Chunked Upload) (AWS
 *   Signature Version 4)"** (`sigv4-streaming.html`) — the frame layout, the
 *   per-chunk string to sign, and the worked 66560-byte example whose seed and
 *   three chunk signatures are the golden in `test/s3/chunked.test.ts`.
 * - **Amazon S3 API Reference, "Signature Calculations for the Authorization
 *   Header: Including Trailing Headers (Chunked Upload)"**
 *   (`sigv4-streaming-trailers.html`) — the trailing-header block, the
 *   `x-amz-trailer` declaration, and the `AWS4-HMAC-SHA256-TRAILER` string to
 *   sign.
 *
 * A body arrives as
 *
 * ```text
 * <hex-size>;chunk-signature=<64 hex>CRLF<size bytes>CRLF
 * ...
 * 0;chunk-signature=<64 hex>CRLF
 * [<trailer-name>:<value>CRLF ...]
 * [x-amz-trailer-signature:<64 hex>CRLF]
 * CRLF
 * ```
 *
 * and the three sentinels in `x-amz-content-sha256` say which of the three
 * shapes it is (`streamingPayloadKind()` reads them). `aws-chunked` also
 * appears as a bare `Content-Encoding` with no sentinel at all, which is the
 * unsigned shape without trailers; that combination is the caller's to
 * recognize, since it lives in a different header.
 *
 * **The chain.** Each chunk's signature is HMAC'd over the *previous*
 * signature, seeded by the request's own SigV4 signature — so a decoder needs
 * the seed (from `parseAuthorizationHeader(...).signature`), the request's
 * `x-amz-date` and its credential scope, all of which the request verification
 * in `sigv4.ts` has already produced. Nothing here reads a clock or a socket.
 *
 * **A signed chunk's bytes are released only after its signature verifies.**
 * The decoder allocates that chunk's declared size once — never more than
 * `maxFrame`, 8 MiB by default — fills it, hashes it, checks the chain, and only
 * then hands it over. Streaming it out as it arrived would be cheaper and would
 * mean a tampered upload had already reached the driver by the time the
 * signature failed, which is not a trade this transport makes.
 *
 * **An unsigned chunk streams straight through**, run by run, because there is
 * nothing to wait for: no signature covers it, so buffering it would buy
 * nothing and would put a ceiling on a body that clients send as a single
 * chunk. The honest consequence is that a caller can be handed bytes of a body
 * whose *framing* later turns out to be wrong — a size that never arrives, a
 * trailer that does not check, a length that misses `x-amz-decoded-content-
 * length`. Those still fail the request as a whole; what they cannot do is
 * un-hand the bytes. A session that must not half-write an object stages
 * unsigned uploads the way multipart does, rather than expecting this decoder
 * to hold an unbounded body for it.
 *
 * **Copy what you keep** (`AGENTS.md`). Every byte retained past a `write()` —
 * a partial header line, a payload run, a trailer line — is copied out of the
 * caller's buffer first, and every array handed back is freshly allocated. A
 * caller may reuse its input buffer the instant `write()` returns; `test/s3/
 * chunked.test.ts` overwrites it on purpose and checks the output.
 *
 * **Only `ChunkedError` escapes**, the same contract `XmlError` carries in
 * `xml.ts`: every malformed frame, bad hex, wrong signature, truncated stream
 * and byte past the end is a named refusal, and a decoder that has failed once
 * rethrows the same error forever rather than resynchronizing — there is no way
 * to resynchronize a signature chain.
 *
 * The one thing that promise does *not* cover is the body itself:
 * `decodeAwsChunked()` iterates a source the caller supplied, and a socket that
 * errors mid-body throws whatever the socket throws, straight through this
 * module. Catching `ChunkedError` covers every way a body can be *wrong*, not
 * every way reading it can fail.
 */

import { createHmac } from "node:crypto";
import {
  STREAMING_PAYLOAD,
  STREAMING_PAYLOAD_TRAILER,
  STREAMING_UNSIGNED_PAYLOAD_TRAILER,
} from "./constants.ts";
import {
  type CredentialScope,
  credentialScope,
  EMPTY_PAYLOAD_SHA256,
  sha256Hex,
  signaturesMatch,
  signingKey,
} from "./sigv4.ts";

// ---------------------------------------------------------------------------
// wire vocabulary
// ---------------------------------------------------------------------------

/** The chunk extension carrying a chunk's signature. */
export const CHUNK_SIGNATURE_PARAMETER = "chunk-signature";

/** The trailing header carrying the trailer block's signature. */
export const TRAILER_SIGNATURE_HEADER = "x-amz-trailer-signature";

/** Algorithm line of a chunk's string to sign. */
export const CHUNK_ALGORITHM = "AWS4-HMAC-SHA256-PAYLOAD";

/** Algorithm line of a trailer block's string to sign. */
export const TRAILER_ALGORITHM = "AWS4-HMAC-SHA256-TRAILER";

/** Which streaming shape a `x-amz-content-sha256` sentinel names. */
export interface StreamingPayloadKind {
  /** Do the chunks carry `chunk-signature=` extensions that must verify? */
  signed: boolean;
  /** May a trailing-header block follow the terminal chunk? */
  trailers: boolean;
}

/**
 * Read the three streaming sentinels, or answer `undefined` for anything else —
 * including `UNSIGNED-PAYLOAD` and a plain hex hash, neither of which is framed.
 *
 * A bare `Content-Encoding: aws-chunked` with no streaming sentinel is framed
 * but unsigned, and it is invisible here: it is a fact about a different header,
 * so the caller pairs `{ signed: false, trailers: false }` with it itself.
 */
export function streamingPayloadKind(value: string): StreamingPayloadKind | undefined {
  switch (value) {
    case STREAMING_PAYLOAD: {
      return { signed: true, trailers: false };
    }
    case STREAMING_PAYLOAD_TRAILER: {
      return { signed: true, trailers: true };
    }
    case STREAMING_UNSIGNED_PAYLOAD_TRAILER: {
      return { signed: false, trailers: true };
    }
    default: {
      return undefined;
    }
  }
}

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/**
 * Why a body was refused. Every one of these is a name the caller turns into an
 * S3 error code without reading a message, and the three groups map differently
 * on purpose:
 *
 * - `signature-mismatch` and `missing-signature` are `SignatureDoesNotMatch`
 *   (403) — the bytes were framed correctly and are not the client's to send.
 * - `truncated`, `length-mismatch` and `trailing-bytes` are `IncompleteBody`
 *   (400) — the body is not the length the request promised.
 * - `bad-size`, `malformed` and `trailer` are `InvalidRequest` /
 *   `MalformedTrailerError` (400) — the framing itself is wrong.
 * - `too-large` is `EntityTooLarge` (400): a frame over the cap.
 * - `internal` is `InternalError` (500) and should be unreachable; it exists so
 *   that "only a `ChunkedError` escapes" stays true even if an invariant here
 *   breaks, without a decoder bug being reported to the client as its own fault.
 */
export type ChunkedRefusal =
  | "bad-size"
  | "too-large"
  | "malformed"
  | "missing-signature"
  | "signature-mismatch"
  | "truncated"
  | "trailing-bytes"
  | "length-mismatch"
  | "trailer"
  | "internal";

/**
 * A chunked body could not be decoded.
 *
 * The **only** error type this module throws, which is what makes it fuzzable:
 * a caller that catches `ChunkedError` and nothing else has covered every
 * failure mode of this layer. Same contract as `XmlError` in `xml.ts` and
 * `XdrError` in `src/nfs/xdr.ts`.
 */
export class ChunkedError extends Error {
  readonly code = "ERR_S3_CHUNKED";
  readonly reason: ChunkedRefusal;
  /** How many encoded bytes had been consumed when the failure was detected. */
  readonly offset: number;

  constructor(reason: ChunkedRefusal, message: string, offset: number) {
    super(message);
    this.name = "ChunkedError";
    this.reason = reason;
    this.offset = offset;
  }
}

/** Is this a {@link ChunkedError}? */
export function isChunkedError(error: unknown): error is ChunkedError {
  return error instanceof ChunkedError;
}

// ---------------------------------------------------------------------------
// limits
// ---------------------------------------------------------------------------

/**
 * Largest payload a **signed** chunk may declare, 8 MiB.
 *
 * This is the decoder's memory bound, and it is a cap on signed frames only,
 * because those are the only ones buffered: a signed chunk is held whole while
 * its signature is checked, an unsigned one is streamed straight through and
 * costs nothing to declare large. Signing a chunk means hashing it, so a signed
 * client chunks small — 64 KiB in the documented example and in the AWS CLI,
 * 128 KiB in the AWS SDK for Java v1, 1 MiB in rclone — which puts the cap one
 * to two orders of magnitude above what anything sends.
 *
 * **The cap deliberately does not apply to unsigned chunks.** `aws-sdk-go-v2`
 * (which has sent a trailing checksum by default since v1.73) and rclone send
 * `STREAMING-UNSIGNED-PAYLOAD-TRAILER` with the *whole object* as one chunk, so
 * a frame cap on that path is a size limit on uploads wearing a memory limit's
 * clothes — MinIO shipped exactly that mistake at 16 MiB (minio/minio#21611).
 * What bounds an unsigned body is `decodedLength` and `maxDecodedBytes`, which
 * bound the thing that actually matters.
 */
export const CHUNKED_MAX_FRAME = 8 * 1024 * 1024;

/**
 * The ceiling on an *unsigned* chunk's declared size, which exists only so the
 * size stays an exact integer: nothing is buffered on that path, but
 * `#remaining` counts down in doubles, and a 16-digit hex size can name more
 * than 2**53. Six orders of magnitude above S3's own 5 GiB object limit.
 */
export const CHUNKED_MAX_DECLARED_SIZE = Number.MAX_SAFE_INTEGER;

/**
 * Longest chunk header line — `<hex-size>;chunk-signature=<64 hex>`.
 *
 * The longest one anything sends is 87 bytes; 256 leaves room for a chunk
 * extension nobody has invented yet and still bounds what an endless run of
 * `0`s can make the decoder hold.
 */
export const CHUNKED_MAX_HEADER_BYTES = 256;

/**
 * Largest trailing-header block, 16 KiB, counted over the whole block rather
 * than per line. S3's defined trailers are single checksums; the budget is for
 * a client that sends several.
 */
export const CHUNKED_MAX_TRAILER_BYTES = 16 * 1024;

/**
 * Most hex digits a chunk size may be written with.
 *
 * A 64-bit size is 16 digits, so this refuses only what could never be a size —
 * including a leading-zero run long enough to be a denial-of-service in the
 * parser, which the `maxFrame` check alone would not catch because its value
 * stays small.
 */
export const CHUNKED_MAX_HEX_DIGITS = 16;

/** The three caps, all optional. */
export interface ChunkedLimits {
  /**
   * Largest payload a **signed** chunk may declare — the buffer bound.
   * Defaults to {@link CHUNKED_MAX_FRAME}, and does not apply to unsigned
   * chunks, which are never buffered.
   */
  maxFrame?: number;
  /** Largest trailing-header block. Defaults to {@link CHUNKED_MAX_TRAILER_BYTES}. */
  maxTrailerBytes?: number;
  /**
   * Largest decoded body, independent of `decodedLength`. Defaults to no cap
   * beyond `decodedLength`, which is the check that matters — the session passes
   * whatever it is willing to write.
   */
  maxDecodedBytes?: number;
}

// ---------------------------------------------------------------------------
// signing
// ---------------------------------------------------------------------------

/**
 * What the chain needs, all of it recoverable from a request `sigv4.ts` has
 * already verified: `seed` is `parseAuthorizationHeader(...).signature`,
 * `amzDate` is `formatAmzDate(verified.timestamp)`, and `scope` is
 * `verified.scope`.
 */
export interface ChunkedSignature {
  /** The request's own SigV4 signature, 64 hex characters. */
  seed: string;
  /** The request's `x-amz-date`, `YYYYMMDDTHHMMSSZ`. */
  amzDate: string;
  scope: CredentialScope;
  secretAccessKey: string;
  /** A precomputed `signingKey(secretAccessKey, scope)`, when the caller has one. */
  key?: Uint8Array;
}

/** The signing key for a chain, derived once unless the caller supplied it. */
export function chunkedSigningKey(signature: ChunkedSignature): Uint8Array {
  return signature.key ?? signingKey(signature.secretAccessKey, signature.scope);
}

/**
 * One chunk's string to sign: the algorithm, the request timestamp, the
 * credential scope, the previous signature in the chain, the hash of an empty
 * string, and the hash of this chunk's payload.
 *
 * The empty-string hash is a fixed line, not a mistake: it is where a chunk's
 * own headers would be hashed, and a chunk has none.
 */
export function chunkStringToSign(
  signature: ChunkedSignature,
  previous: string,
  payloadHash: string,
): string {
  return [
    CHUNK_ALGORITHM,
    signature.amzDate,
    credentialScope(signature.scope),
    previous,
    EMPTY_PAYLOAD_SHA256,
    payloadHash,
  ].join("\n");
}

/**
 * The trailing-header block's string to sign. One line shorter than a chunk's:
 * there is no empty-headers line, and the last line hashes the block itself.
 */
export function trailerStringToSign(
  signature: ChunkedSignature,
  previous: string,
  trailerHash: string,
): string {
  return [
    TRAILER_ALGORITHM,
    signature.amzDate,
    credentialScope(signature.scope),
    previous,
    trailerHash,
  ].join("\n");
}

function hmacHex(key: Uint8Array, data: string): string {
  return createHmac("sha256", key).update(data, "utf8").digest("hex");
}

/** The signature a chunk carrying `payloadHash` must present. */
export function signChunk(
  signature: ChunkedSignature,
  previous: string,
  payloadHash: string,
): string {
  return hmacHex(chunkedSigningKey(signature), chunkStringToSign(signature, previous, payloadHash));
}

/** The signature a trailing-header block hashing to `trailerHash` must present. */
export function signTrailer(
  signature: ChunkedSignature,
  previous: string,
  trailerHash: string,
): string {
  return hmacHex(
    chunkedSigningKey(signature),
    trailerStringToSign(signature, previous, trailerHash),
  );
}

// ---------------------------------------------------------------------------
// the decoder
// ---------------------------------------------------------------------------

/** One trailing header, as it arrived: name lowercased, value trimmed. */
export interface ChunkedTrailer {
  name: string;
  value: string;
}

/** What a decoder needs to know about the request it is decoding the body of. */
export interface AwsChunkedParams {
  /**
   * The chain material. Omitted means unsigned framing: a `chunk-signature=`
   * extension is then ignored if one arrives, because the request said the
   * chunks are not signed and a decoder is not the place to change its mind.
   */
  signature?: ChunkedSignature;
  /**
   * The trailing headers the request declared in `x-amz-trailer`, in any case.
   *
   * Omitted or empty means **no trailer block is expected**, and one arriving is
   * refused as bytes past the end. When present, the block must carry exactly
   * this set — an undeclared trailer and a declared one that never arrives are
   * both refusals, which is what a client's own signature covers.
   */
  trailers?: readonly string[];
  /**
   * The request's `x-amz-decoded-content-length`. When present, a chunk that
   * would take the body past it is refused as soon as its header is read, and a
   * body that ends short of it is refused at `end()`.
   */
  decodedLength?: number;
  limits?: ChunkedLimits;
  /** Called once, with the verified trailing headers, when the block closes. */
  onTrailers?: (trailers: readonly ChunkedTrailer[]) => void;
}

const CR = 0x0d;
const LF = 0x0a;

/** `0-9a-fA-F` → value, or `-1`. */
function hexDigit(byte: number): number {
  if (byte >= 0x30 && byte <= 0x39) {
    return byte - 0x30;
  }
  if (byte >= 0x61 && byte <= 0x66) {
    return byte - 0x57;
  }
  if (byte >= 0x41 && byte <= 0x46) {
    return byte - 0x37;
  }
  return -1;
}

const SIGNATURE_HEX = /^[\da-f]{64}$/i;

/**
 * A growable byte buffer for one header or trailer line.
 *
 * Every byte pushed here is a byte copied out of the caller's buffer, which is
 * the whole point: a line can span any number of `write()` calls.
 */
class LineBuffer {
  #bytes = new Uint8Array(128);
  #length = 0;

  get length(): number {
    return this.#length;
  }

  push(byte: number): void {
    if (this.#length === this.#bytes.length) {
      const grown = new Uint8Array(this.#bytes.length * 2);
      grown.set(this.#bytes);
      this.#bytes = grown;
    }
    this.#bytes[this.#length] = byte;
    this.#length += 1;
  }

  /** The bytes so far, as a view — the buffer owns them and reuses them. */
  view(): Uint8Array {
    return this.#bytes.subarray(0, this.#length);
  }

  /**
   * The line as text, one character per byte (latin-1).
   *
   * Deliberately not UTF-8: a header line is ASCII, anything else in one is
   * hostile, and decoding byte for byte keeps a multi-byte sequence from
   * collapsing into a character that then compares equal to something.
   */
  text(): string {
    let out = "";
    for (let index = 0; index < this.#length; index++) {
      out += String.fromCharCode(this.#bytes[index] as number);
    }
    return out;
  }

  reset(): void {
    this.#length = 0;
  }
}

/** A private copy of `input[start .. start + length)`. */
function copyOf(input: Uint8Array, start: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  out.set(input.subarray(start, start + length));
  return out;
}

/** What the terminal chunk hashes. Never handed out, so sharing it is safe. */
const NO_BYTES = new Uint8Array(0);

type DecoderState =
  | "header"
  | "header-lf"
  | "payload"
  | "payload-cr"
  | "payload-lf"
  | "trailer"
  | "trailer-lf"
  | "epilogue";

/**
 * The incremental decoder: network bytes in, decoded payload out.
 *
 * `write()` may be handed one byte or a megabyte and the split may fall
 * anywhere — mid hex size, mid `chunk-signature=`, between a CR and its LF, mid
 * payload, mid trailer. `end()` says the stream is over and is the only place a
 * truncation or a length mismatch can be detected.
 *
 * ```ts
 * const decoder = new AwsChunkedDecoder({ signature, decodedLength });
 * for await (const bytes of body) {
 *   for (const payload of decoder.write(bytes)) await sink(payload);
 * }
 * decoder.end();
 * ```
 *
 * {@link decodeAwsChunked} is that loop, for a caller that wants an
 * `AsyncIterable` rather than the decoder object.
 */
export class AwsChunkedDecoder {
  readonly #signature: ChunkedSignature | undefined;
  readonly #key: Uint8Array | undefined;
  readonly #declared: readonly string[];
  readonly #decodedLength: number | undefined;
  readonly #maxFrame: number;
  readonly #maxTrailerBytes: number;
  readonly #maxDecodedBytes: number;
  readonly #onTrailers: ((trailers: readonly ChunkedTrailer[]) => void) | undefined;

  #state: DecoderState = "header";
  #line = new LineBuffer();
  /**
   * The signed chunk being read, allocated at its declared size the moment the
   * header names it, and `undefined` on the unsigned path where nothing is held.
   *
   * One allocation per chunk rather than one per `write()`: an attacker picks
   * the TCP segmentation, and a per-run array meant 8 MiB delivered a byte at a
   * time cost 1975 MiB of live typed-array headers — the byte content was
   * bounded by `maxFrame` and the object overhead was not.
   */
  #chunk: Uint8Array | undefined;
  #filled = 0;
  /** The declared size of the chunk being read; `0` marks the terminal one. */
  #size = 0;
  /** Payload bytes still to come for the chunk being read. */
  #remaining = 0;
  /** The `chunk-signature=` value of the chunk being read, when signed. */
  #chunkSignature = "";
  /** The previous link in the chain: the seed, then each chunk's signature. */
  #previous: string;
  /** Trailing-header lines, `name:value` and one LF each, as the client sent them. */
  #trailerBlock = new LineBuffer();
  #trailers: ChunkedTrailer[] = [];
  /** Encoded bytes consumed, which is what a `ChunkedError` reports as `offset`. */
  #offset = 0;
  /** Decoded payload bytes released or buffered so far. */
  #decoded = 0;
  /** Bytes of the one optional trailing CRLF that have arrived. */
  #epilogue = 0;
  #terminated = false;
  #ended = false;
  #failure: ChunkedError | undefined;

  constructor(params: AwsChunkedParams = {}) {
    this.#signature = params.signature;
    this.#previous = params.signature?.seed ?? "";
    if (params.signature !== undefined) {
      if (!SIGNATURE_HEX.test(params.signature.seed)) {
        throw new ChunkedError("malformed", "seed signature is not 64 hex characters", 0);
      }
      this.#key = chunkedSigningKey(params.signature);
    }
    this.#declared = [...new Set((params.trailers ?? []).map((name) => name.toLowerCase()))];
    this.#decodedLength = params.decodedLength;
    this.#maxFrame = params.limits?.maxFrame ?? CHUNKED_MAX_FRAME;
    this.#maxTrailerBytes = params.limits?.maxTrailerBytes ?? CHUNKED_MAX_TRAILER_BYTES;
    this.#maxDecodedBytes = params.limits?.maxDecodedBytes ?? Number.POSITIVE_INFINITY;
    this.#onTrailers = params.onTrailers;
  }

  /**
   * Decoded payload bytes consumed so far — released to the caller, or held in
   * a signed chunk whose signature has not been checked yet.
   */
  get decodedBytes(): number {
    return this.#decoded;
  }

  /** The verified trailing headers, once the block has closed. */
  get trailers(): readonly ChunkedTrailer[] {
    return this.#trailers;
  }

  /** Has the terminal zero-sized chunk been read and verified? */
  get terminated(): boolean {
    return this.#terminated;
  }

  /**
   * Feed network bytes in; get whatever decoded payload came out — one array
   * per signed chunk, one per run of an unsigned one.
   *
   * Each returned array is freshly allocated and aliases nothing — `bytes` may
   * be reused the moment this returns.
   */
  write(bytes: Uint8Array): Uint8Array[] {
    if (this.#failure !== undefined) {
      throw this.#failure;
    }
    if (this.#ended && bytes.byteLength > 0) {
      throw this.#store(this.#fail("trailing-bytes", "bytes arrived after the body ended"));
    }
    try {
      return this.#consume(bytes);
    } catch (error) {
      throw this.#store(error);
    }
  }

  /**
   * The stream is over. Refuses a body that stopped mid-frame, one that never
   * reached its terminal chunk, and one whose length is not what the request
   * declared. Idempotent.
   */
  end(): void {
    if (this.#failure !== undefined) {
      throw this.#failure;
    }
    if (this.#ended) {
      return;
    }
    try {
      this.#finish();
    } catch (error) {
      throw this.#store(error);
    }
    this.#ended = true;
  }

  // -------------------------------------------------------------------------

  #fail(reason: ChunkedRefusal, message: string): ChunkedError {
    return new ChunkedError(reason, message, this.#offset);
  }

  /**
   * Remember the failure and hand it back to be thrown. Anything that is not a
   * `ChunkedError` is an invariant of this file breaking rather than a client's
   * doing, and is renamed accordingly — the contract that only a `ChunkedError`
   * escapes is what every caller's error mapping is built on.
   */
  #store(error: unknown): ChunkedError {
    const failure =
      error instanceof ChunkedError
        ? error
        : this.#fail("internal", `decoder failed: ${String((error as Error)?.message ?? error)}`);
    this.#failure ??= failure;
    return this.#failure;
  }

  #consume(input: Uint8Array): Uint8Array[] {
    const out: Uint8Array[] = [];
    let index = 0;
    while (index < input.byteLength) {
      switch (this.#state) {
        case "header": {
          index = this.#scanLine(
            input,
            index,
            CHUNKED_MAX_HEADER_BYTES,
            "malformed",
            "chunk header",
          );
          break;
        }
        case "header-lf": {
          index = this.#expectLf(input, index, "chunk header");
          this.#beginChunk(out);
          break;
        }
        case "payload": {
          const take = Math.min(this.#remaining, input.byteLength - index);
          if (this.#chunk === undefined) {
            // Unsigned: nothing covers these bytes, so nothing is gained by
            // holding them and a whole-object chunk would be unholdable.
            out.push(copyOf(input, index, take));
          } else {
            this.#chunk.set(input.subarray(index, index + take), this.#filled);
            this.#filled += take;
          }
          this.#remaining -= take;
          this.#decoded += take;
          index += take;
          this.#offset += take;
          if (this.#remaining === 0) {
            this.#state = "payload-cr";
          }
          break;
        }
        case "payload-cr": {
          index = this.#expectCr(input, index, "chunk payload");
          break;
        }
        case "payload-lf": {
          index = this.#expectLf(input, index, "chunk payload");
          this.#finishChunk(out);
          break;
        }
        case "trailer": {
          index = this.#scanLine(
            input,
            index,
            this.#maxTrailerBytes - this.#trailerBlock.length,
            "too-large",
            "trailing header",
          );
          break;
        }
        case "trailer-lf": {
          index = this.#expectLf(input, index, "trailing header");
          this.#finishTrailerLine();
          break;
        }
        case "epilogue": {
          index = this.#epilogueByte(input, index);
          break;
        }
      }
    }
    return out;
  }

  /**
   * Copy bytes into `#line` until a CR, which moves to the matching `-lf`
   * state. A line longer than `limit` is refused rather than buffered.
   */
  #scanLine(
    input: Uint8Array,
    start: number,
    limit: number,
    reason: ChunkedRefusal,
    what: string,
  ): number {
    let index = start;
    while (index < input.byteLength) {
      const byte = input[index] as number;
      index += 1;
      this.#offset += 1;
      if (byte === CR) {
        this.#state = this.#state === "header" ? "header-lf" : "trailer-lf";
        return index;
      }
      if (this.#line.length >= limit) {
        throw this.#fail(reason, `${what} is longer than ${limit} bytes`);
      }
      this.#line.push(byte);
    }
    return index;
  }

  #expectCr(input: Uint8Array, index: number, what: string): number {
    const byte = input[index] as number;
    this.#offset += 1;
    if (byte !== CR) {
      throw this.#fail("malformed", `${what} is not followed by CRLF`);
    }
    this.#state = "payload-lf";
    return index + 1;
  }

  #expectLf(input: Uint8Array, index: number, what: string): number {
    const byte = input[index] as number;
    this.#offset += 1;
    if (byte !== LF) {
      throw this.#fail("malformed", `${what} has a CR that is not followed by LF`);
    }
    return index + 1;
  }

  /** Parse the completed header line and set up the chunk it describes. */
  #beginChunk(out: Uint8Array[]): void {
    const text = this.#line.text();
    this.#line.reset();
    const semicolon = text.indexOf(";");
    const sizeText = semicolon === -1 ? text : text.slice(0, semicolon);
    const size = this.#parseSize(sizeText);
    this.#chunkSignature = this.#parseChunkSignature(
      semicolon === -1 ? "" : text.slice(semicolon + 1),
    );
    if (this.#decodedLength !== undefined && this.#decoded + size > this.#decodedLength) {
      throw this.#fail(
        "length-mismatch",
        `chunk of ${size} bytes takes the body past the declared ${this.#decodedLength} bytes`,
      );
    }
    if (this.#decoded + size > this.#maxDecodedBytes) {
      throw this.#fail("too-large", `body is longer than ${this.#maxDecodedBytes} bytes`);
    }
    this.#size = size;
    this.#remaining = size;
    this.#filled = 0;
    if (size === 0) {
      // The terminal chunk has no payload and no CRLF of its own: what follows
      // is the trailing-header block, or the end of the body.
      this.#finishChunk(out);
      return;
    }
    // One allocation for the whole signed chunk; the unsigned path holds none.
    this.#chunk = this.#signature === undefined ? undefined : new Uint8Array(size);
    this.#state = "payload";
  }

  /**
   * The declared size, refused if it is not hex, is written with more digits
   * than a 64-bit number needs, or is over the cap for its kind — `maxFrame` for
   * a signed chunk, which is buffered, and only the exact-integer ceiling for an
   * unsigned one, which is not.
   */
  #parseSize(text: string): number {
    if (text.length === 0) {
      throw this.#fail("bad-size", "chunk header has no size");
    }
    if (text.length > CHUNKED_MAX_HEX_DIGITS) {
      throw this.#fail("bad-size", `chunk size is ${text.length} hex digits`);
    }
    const cap = this.#signature === undefined ? CHUNKED_MAX_DECLARED_SIZE : this.#maxFrame;
    let size = 0;
    for (let index = 0; index < text.length; index++) {
      const digit = hexDigit(text.charCodeAt(index));
      if (digit === -1) {
        throw this.#fail("bad-size", "chunk size is not hexadecimal");
      }
      size = size * 16 + digit;
      if (size > cap) {
        throw this.#fail("too-large", `chunk is larger than the ${cap}-byte cap`);
      }
    }
    return size;
  }

  /**
   * Pull `chunk-signature=` out of the chunk extensions. Required, and required
   * to be 64 hex characters, when the chunks are signed; ignored when they are
   * not.
   */
  #parseChunkSignature(extensions: string): string {
    if (this.#signature === undefined) {
      return "";
    }
    for (const parameter of extensions.split(";")) {
      const equals = parameter.indexOf("=");
      if (equals === -1) {
        continue;
      }
      if (parameter.slice(0, equals).trim().toLowerCase() !== CHUNK_SIGNATURE_PARAMETER) {
        continue;
      }
      const value = parameter.slice(equals + 1).trim();
      if (!SIGNATURE_HEX.test(value)) {
        throw this.#fail("malformed", `${CHUNK_SIGNATURE_PARAMETER} is not 64 hex characters`);
      }
      return value;
    }
    throw this.#fail("missing-signature", `chunk header has no ${CHUNK_SIGNATURE_PARAMETER}`);
  }

  /**
   * The chunk has finished arriving: verify it if it was signed, and release
   * the buffer it was held in. An unsigned chunk has already been released, run
   * by run, and there is nothing here for it but the chain of states.
   */
  #finishChunk(out: Uint8Array[]): void {
    const payload = this.#chunk;
    this.#chunk = undefined;
    this.#filled = 0;
    if (this.#signature !== undefined && this.#key !== undefined) {
      const expected = hmacHex(
        this.#key,
        chunkStringToSign(this.#signature, this.#previous, sha256Hex(payload ?? NO_BYTES)),
      );
      if (!signaturesMatch(expected, this.#chunkSignature)) {
        throw this.#fail("signature-mismatch", "chunk signature does not match");
      }
      // The computed one, not the client's: a chain link differing only in hex
      // case must not change what the next chunk has to sign.
      this.#previous = expected;
    }
    if (this.#size === 0) {
      this.#terminated = true;
      this.#state = this.#declared.length > 0 ? "trailer" : "epilogue";
      return;
    }
    if (payload !== undefined) {
      out.push(payload);
    }
    this.#state = "header";
  }

  /** A completed trailing-header line: a header, the block's signature, or the end. */
  #finishTrailerLine(): void {
    const raw = this.#line.view();
    const text = this.#line.text();
    const lower = text.toLowerCase();
    if (text.length === 0) {
      if (this.#signature !== undefined) {
        throw this.#fail("trailer", `trailer block ends before ${TRAILER_SIGNATURE_HEADER}`);
      }
      this.#closeTrailers();
      this.#line.reset();
      this.#state = "epilogue";
      return;
    }
    if (lower.startsWith(`${TRAILER_SIGNATURE_HEADER}:`)) {
      this.#verifyTrailerSignature(text.slice(TRAILER_SIGNATURE_HEADER.length + 1).trim());
      this.#closeTrailers();
      this.#line.reset();
      this.#state = "epilogue";
      return;
    }
    const colon = text.indexOf(":");
    if (colon <= 0) {
      throw this.#fail("trailer", "trailing header has no name");
    }
    const name = lower.slice(0, colon).trim();
    if (!this.#declared.includes(name)) {
      throw this.#fail("trailer", `trailing header ${name} was not declared in x-amz-trailer`);
    }
    if (this.#trailers.some((trailer) => trailer.name === name)) {
      throw this.#fail("trailer", `trailing header ${name} arrived twice`);
    }
    // Hashed exactly as it arrived, with the CRLF normalized to one LF: the
    // client signed the bytes it wrote, so trimming or lowercasing here would
    // refuse a signature that is correct.
    if (this.#trailerBlock.length + raw.byteLength + 1 > this.#maxTrailerBytes) {
      throw this.#fail("too-large", `trailer block is longer than ${this.#maxTrailerBytes} bytes`);
    }
    for (const byte of raw) {
      this.#trailerBlock.push(byte);
    }
    this.#trailerBlock.push(LF);
    this.#trailers.push({ name, value: text.slice(colon + 1).trim() });
    this.#line.reset();
    this.#state = "trailer";
  }

  #verifyTrailerSignature(value: string): void {
    if (this.#signature === undefined || this.#key === undefined) {
      throw this.#fail("trailer", `an unsigned body carries a ${TRAILER_SIGNATURE_HEADER}`);
    }
    if (!SIGNATURE_HEX.test(value)) {
      throw this.#fail("malformed", `${TRAILER_SIGNATURE_HEADER} is not 64 hex characters`);
    }
    const expected = hmacHex(
      this.#key,
      trailerStringToSign(this.#signature, this.#previous, sha256Hex(this.#trailerBlock.view())),
    );
    if (!signaturesMatch(expected, value)) {
      throw this.#fail("signature-mismatch", "trailer signature does not match");
    }
    this.#previous = expected;
  }

  /** Every declared trailer has to have arrived, which is what its signature covers. */
  #closeTrailers(): void {
    const missing = this.#declared.filter(
      (name) => !this.#trailers.some((trailer) => trailer.name === name),
    );
    if (missing.length > 0) {
      throw this.#fail("trailer", `declared trailing header ${missing[0]} never arrived`);
    }
    this.#onTrailers?.(this.#trailers);
  }

  /** At most one CRLF may follow the body, and nothing else may. */
  #epilogueByte(input: Uint8Array, index: number): number {
    const byte = input[index] as number;
    this.#offset += 1;
    const expected = this.#epilogue === 0 ? CR : LF;
    if (this.#epilogue >= 2 || byte !== expected) {
      throw this.#fail("trailing-bytes", "bytes follow the terminal chunk");
    }
    this.#epilogue += 1;
    return index + 1;
  }

  #finish(): void {
    if (!this.#terminated) {
      throw this.#fail("truncated", `body ends inside a chunk (state ${this.#state})`);
    }
    if (this.#state === "trailer") {
      if (this.#line.length > 0) {
        throw this.#fail("truncated", "trailing header has no CRLF");
      }
      if (this.#signature !== undefined) {
        throw this.#fail("truncated", `body ends before ${TRAILER_SIGNATURE_HEADER}`);
      }
      // Unsigned trailers: not every client sends the empty line that closes
      // the block, and the end of the body closes it just as well.
      this.#closeTrailers();
      this.#state = "epilogue";
    }
    if (this.#state !== "epilogue") {
      throw this.#fail("truncated", `body ends inside the trailer block (state ${this.#state})`);
    }
    if (this.#epilogue === 1) {
      throw this.#fail("truncated", "body ends between the final CR and its LF");
    }
    if (this.#decodedLength !== undefined && this.#decoded !== this.#decodedLength) {
      throw this.#fail(
        "length-mismatch",
        `body decoded to ${this.#decoded} bytes, not the declared ${this.#decodedLength}`,
      );
    }
  }
}

/**
 * The pull-through form: network chunks in, decoded payload out, which is what
 * the session's streaming boundary composes with
 * (`handleRequest(head, body: AsyncIterable<Uint8Array>)`).
 *
 * Trailing headers arrive through `params.onTrailers`; a caller that wants the
 * decoder object — its counters, its trailers afterwards — drives
 * {@link AwsChunkedDecoder} directly, which is all this does.
 */
export async function* decodeAwsChunked(
  source: AsyncIterable<Uint8Array>,
  params: AwsChunkedParams = {},
): AsyncGenerator<Uint8Array> {
  const decoder = new AwsChunkedDecoder(params);
  for await (const bytes of source) {
    for (const payload of decoder.write(bytes)) {
      yield payload;
    }
  }
  decoder.end();
}
