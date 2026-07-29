/**
 * The `aws-chunked` streaming decoder.
 *
 * **The golden is transcribed from the Amazon S3 API Reference**, "Signature
 * Calculations for the Authorization Header: Transferring Payload in Multiple
 * Chunks (Chunked Upload) (AWS Signature Version 4)" — the worked example that
 * uploads 66560 bytes of `a` as a 64 KiB chunk, a 1024-byte chunk and the
 * terminal zero chunk. Its request headers, its seed signature, its three chunk
 * signatures and its `Content-Length` are all below.
 *
 * **Where the values came from, stated plainly.** The live page is rendered by
 * JavaScript and could not be fetched while this was written, so the constants
 * were transcribed from memory of it and then *proved* by rederivation. They
 * have since been checked against the **Wayback Machine capture of
 * `sigv4-streaming.html`** (`web.archive.org/web/20260525133852`) — every
 * constant verbatim, the canonical request line for line — and the trailer
 * chain against the capture of `sigv4-streaming-trailers.html`.
 *
 * The rederivations stay, because they are what keeps the page honest about
 * `sigv4.ts` rather than only about this file:
 *
 * - `signature-of-the-documented-request` rebuilds the example's canonical
 *   request from its own headers and derives the seed with `src/s3/sigv4.ts`.
 *   It comes out equal to the documented seed, so the headers, the scope, the
 *   example secret key and `sigv4.ts` all agree.
 * - `the-documented-chunk-signature-chain` then chains the three chunk
 *   signatures off that seed with `chunkStringToSign()` and gets the three
 *   documented values.
 * - `the-documented-wire` reconstructs the body and asserts it is 66824 bytes,
 *   the example's `Content-Length`.
 *
 * Four independent numbers reproduced from one secret key, and a signer that
 * disagreed with Amazon anywhere would fail the first of them.
 *
 * The rest of the suite builds its own bodies with `buildBody()`, which signs
 * chunks with this module's own primitives — a round trip, not a golden.
 */

import { describe, expect, it, vi } from "vitest";

// The exhaustive sweeps here are O(n²) over the wire length (~2.7 s alone) and
// share the machine with the rclone oracle's subprocesses under `pnpm test`;
// the raised default is headroom against that load, not an expectation.
vi.setConfig({ testTimeout: 30_000 });

import {
  AwsChunkedDecoder,
  type AwsChunkedParams,
  type ChunkedError,
  type ChunkedSignature,
  type ChunkedTrailer,
  CHUNKED_MAX_FRAME,
  chunkStringToSign,
  decodeAwsChunked,
  isChunkedError,
  signChunk,
  signTrailer,
  streamingPayloadKind,
  trailerStringToSign,
} from "../../src/s3/chunked.ts";
import {
  STREAMING_PAYLOAD,
  STREAMING_PAYLOAD_TRAILER,
  STREAMING_UNSIGNED_PAYLOAD_TRAILER,
  UNSIGNED_PAYLOAD,
} from "../../src/s3/constants.ts";
import {
  canonicalRequest,
  type CredentialScope,
  sha256Hex,
  signatureOf,
  stringToSign,
} from "../../src/s3/sigv4.ts";
import { Rng } from "../fuse/random.ts";

// ---------------------------------------------------------------------------
// the documented example
// ---------------------------------------------------------------------------

/** The example credentials every AWS signing document uses. */
const DOC_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const DOC_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

const DOC_AMZ_DATE = "20130524T000000Z";
const DOC_SCOPE: CredentialScope = { date: "20130524", region: "us-east-1", service: "s3" };

/** `Authorization: ... Signature=` of the example request. */
const DOC_SEED_SIGNATURE = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";

/** `chunk-signature=` of the 65536-byte, the 1024-byte and the terminal chunk. */
const DOC_CHUNK_SIGNATURES = [
  "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
  "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
  "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
];

/** `x-amz-decoded-content-length` of the example request. */
const DOC_DECODED_LENGTH = 66_560;

/** `Content-Length` of the example request: the framed body. */
const DOC_CONTENT_LENGTH = 66_824;

const DOC_SIGNATURE: ChunkedSignature = {
  seed: DOC_SEED_SIGNATURE,
  amzDate: DOC_AMZ_DATE,
  scope: DOC_SCOPE,
  secretAccessKey: DOC_SECRET_KEY,
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const CRLF = "\r\n";

function ascii(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function filled(length: number, byte: number): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

/** Flip bits in place, which is what most of the tampering below is. */
function flip(bytes: Uint8Array, index: number, mask = 0x01): void {
  bytes[index] = (bytes[index] as number) ^ mask;
}

interface BuildOptions {
  /** Chain material. Omitted builds an unsigned body. */
  signature?: ChunkedSignature;
  trailers?: readonly ChunkedTrailer[];
  /** Uppercase the hex sizes, which a client is free to do. */
  uppercase?: boolean;
  /** Emit the CRLF that closes the body. Default `true`. */
  finalCrlf?: boolean;
  /** Replace the trailer block's signature with this, for the tampering cases. */
  trailerSignature?: string;
}

interface BuiltBody {
  bytes: Uint8Array;
  /** One entry per wire piece: each chunk frame, each trailer line, the epilogue. */
  frames: Uint8Array[];
  /** Every chunk signature in order, terminal chunk last. */
  signatures: string[];
  /** The decoded payload the body carries. */
  payload: Uint8Array;
}

/**
 * Build a wire body from its payload chunks, signing each one with the module's
 * own primitives. The terminal zero chunk is appended here, never passed in.
 */
function buildBody(payloads: readonly Uint8Array[], options: BuildOptions = {}): BuiltBody {
  const frames: Uint8Array[] = [];
  const signatures: string[] = [];
  let previous = options.signature?.seed ?? "";
  for (const payload of [...payloads, new Uint8Array(0)]) {
    const size = payload.byteLength.toString(16);
    let header = options.uppercase === true ? size.toUpperCase() : size;
    if (options.signature !== undefined) {
      const signature = signChunk(options.signature, previous, sha256Hex(payload));
      signatures.push(signature);
      previous = signature;
      header += `;chunk-signature=${signature}`;
    }
    frames.push(
      payload.byteLength === 0
        ? ascii(header + CRLF)
        : concat([ascii(header + CRLF), payload, ascii(CRLF)]),
    );
  }
  if (options.trailers !== undefined && options.trailers.length > 0) {
    let block = "";
    for (const trailer of options.trailers) {
      frames.push(ascii(`${trailer.name}:${trailer.value}${CRLF}`));
      block += `${trailer.name}:${trailer.value}\n`;
    }
    if (options.signature !== undefined) {
      const signature =
        options.trailerSignature ?? signTrailer(options.signature, previous, sha256Hex(block));
      frames.push(ascii(`x-amz-trailer-signature:${signature}${CRLF}`));
    }
  }
  if (options.finalCrlf !== false) {
    frames.push(ascii(CRLF));
  }
  return { bytes: concat(frames), frames, signatures, payload: concat(payloads) };
}

/** Feed a body in the given pieces and collect everything it decodes to. */
function decodeAll(pieces: readonly Uint8Array[], params: AwsChunkedParams): Uint8Array {
  const decoder = new AwsChunkedDecoder(params);
  const out: Uint8Array[] = [];
  for (const piece of pieces) {
    out.push(...decoder.write(piece));
  }
  decoder.end();
  return concat(out);
}

/** Split at the given offsets, which must be sorted. */
function pieces(bytes: Uint8Array, offsets: readonly number[]): Uint8Array[] {
  const out: Uint8Array[] = [];
  let start = 0;
  for (const offset of [...offsets, bytes.byteLength]) {
    out.push(bytes.subarray(start, offset));
    start = offset;
  }
  return out;
}

/** Run something that must refuse, and hand back the refusal. */
function refusal(run: () => void): ChunkedError {
  try {
    run();
  } catch (error) {
    if (!isChunkedError(error)) {
      throw error;
    }
    return error;
  }
  throw new Error("expected a ChunkedError, nothing was thrown");
}

/** The refusal a whole body produces, delivered in one piece. */
function refuseBody(bytes: Uint8Array, params: AwsChunkedParams): ChunkedError {
  return refusal(() => {
    decodeAll([bytes], params);
  });
}

const signedParams: AwsChunkedParams = { signature: DOC_SIGNATURE };

// ---------------------------------------------------------------------------

describe("streamingPayloadKind", () => {
  it("names the three streaming sentinels", () => {
    expect(streamingPayloadKind(STREAMING_PAYLOAD)).toEqual({ signed: true, trailers: false });
    expect(streamingPayloadKind(STREAMING_PAYLOAD_TRAILER)).toEqual({
      signed: true,
      trailers: true,
    });
    expect(streamingPayloadKind(STREAMING_UNSIGNED_PAYLOAD_TRAILER)).toEqual({
      signed: false,
      trailers: true,
    });
  });

  it("answers undefined for a payload hash that is not framed", () => {
    expect(streamingPayloadKind(UNSIGNED_PAYLOAD)).toBeUndefined();
    expect(streamingPayloadKind(sha256Hex("hello"))).toBeUndefined();
    expect(streamingPayloadKind("")).toBeUndefined();
  });
});

describe("the documented chunked upload", () => {
  const chunks = [filled(65_536, 0x61), filled(1024, 0x61)];

  it("derives the documented seed signature from the documented request", () => {
    /* The example request, header for header:
       PUT /examplebucket/chunkObject.txt, Host s3.amazonaws.com, storage class
       REDUCED_REDUNDANCY, the streaming sentinel, and the two lengths. */
    const canonical = canonicalRequest({
      method: "PUT",
      path: "/examplebucket/chunkObject.txt",
      query: [],
      headers: [
        { name: "Content-Encoding", value: "aws-chunked" },
        { name: "Content-Length", value: String(DOC_CONTENT_LENGTH) },
        { name: "Host", value: "s3.amazonaws.com" },
        { name: "x-amz-content-sha256", value: STREAMING_PAYLOAD },
        { name: "x-amz-date", value: DOC_AMZ_DATE },
        { name: "x-amz-decoded-content-length", value: String(DOC_DECODED_LENGTH) },
        { name: "x-amz-storage-class", value: "REDUCED_REDUNDANCY" },
      ],
      signedHeaders: [
        "content-encoding",
        "content-length",
        "host",
        "x-amz-content-sha256",
        "x-amz-date",
        "x-amz-decoded-content-length",
        "x-amz-storage-class",
      ],
      payloadHash: STREAMING_PAYLOAD,
    });
    const seed = signatureOf(
      DOC_SECRET_KEY,
      DOC_SCOPE,
      stringToSign(DOC_AMZ_DATE, DOC_SCOPE, canonical),
    );
    expect(seed).toBe(DOC_SEED_SIGNATURE);
    expect(DOC_SIGNATURE.secretAccessKey).toBe(DOC_SECRET_KEY);
    expect(DOC_ACCESS_KEY).toBe("AKIAIOSFODNN7EXAMPLE");
  });

  it("re-derives the documented chunk signature chain", () => {
    let previous = DOC_SEED_SIGNATURE;
    const derived: string[] = [];
    for (const payload of [...chunks, new Uint8Array(0)]) {
      const signature = signChunk(DOC_SIGNATURE, previous, sha256Hex(payload));
      derived.push(signature);
      previous = signature;
    }
    expect(derived).toEqual(DOC_CHUNK_SIGNATURES);
  });

  it("builds the chunk string to sign the documented way", () => {
    expect(chunkStringToSign(DOC_SIGNATURE, DOC_SEED_SIGNATURE, sha256Hex(chunks[0]!))).toBe(
      [
        "AWS4-HMAC-SHA256-PAYLOAD",
        DOC_AMZ_DATE,
        "20130524/us-east-1/s3/aws4_request",
        DOC_SEED_SIGNATURE,
        sha256Hex(""),
        sha256Hex(chunks[0]!),
      ].join("\n"),
    );
  });

  it("decodes the documented wire back to its 66560 bytes", () => {
    const body = buildBody(chunks, { signature: DOC_SIGNATURE });
    expect(body.signatures).toEqual(DOC_CHUNK_SIGNATURES);
    expect(body.bytes.byteLength).toBe(DOC_CONTENT_LENGTH);

    const decoder = new AwsChunkedDecoder({
      signature: DOC_SIGNATURE,
      decodedLength: DOC_DECODED_LENGTH,
    });
    const out = concat(decoder.write(body.bytes));
    decoder.end();
    expect(out.byteLength).toBe(DOC_DECODED_LENGTH);
    expect(out.every((byte) => byte === 0x61)).toBe(true);
    expect(decoder.decodedBytes).toBe(DOC_DECODED_LENGTH);
    expect(decoder.terminated).toBe(true);
    expect(decoder.trailers).toEqual([]);
  });

  it("starts the frame at the documented header shape", () => {
    const body = buildBody(chunks, { signature: DOC_SIGNATURE });
    const header = new TextDecoder().decode(body.frames[0]!.subarray(0, 88));
    expect(header).toBe(`10000;chunk-signature=${DOC_CHUNK_SIGNATURES[0]}${CRLF}`);
  });
});

describe("round trips", () => {
  it("decodes an empty payload", () => {
    const body = buildBody([], { signature: DOC_SIGNATURE });
    expect(decodeAll([body.bytes], { ...signedParams, decodedLength: 0 })).toEqual(
      new Uint8Array(0),
    );
  });

  it("decodes many chunks", () => {
    const payloads = [filled(1, 0x41), filled(17, 0x42), filled(4096, 0x43), filled(3, 0x44)];
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    expect(
      decodeAll([body.bytes], { ...signedParams, decodedLength: body.payload.byteLength }),
    ).toEqual(body.payload);
  });

  it("decodes single-byte chunks", () => {
    const payloads = Array.from({ length: 12 }, (_, index) => filled(1, 0x30 + index));
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    expect(decodeAll([body.bytes], signedParams)).toEqual(body.payload);
  });

  it("accepts uppercase hex sizes", () => {
    const payloads = [filled(0xab, 0x61), filled(0xcdef, 0x62)];
    const upper = buildBody(payloads, { signature: DOC_SIGNATURE, uppercase: true });
    const lower = buildBody(payloads, { signature: DOC_SIGNATURE });
    expect(upper.bytes).not.toEqual(lower.bytes);
    expect(decodeAll([upper.bytes], signedParams)).toEqual(upper.payload);
  });

  it("accepts a body with no trailing CRLF", () => {
    const body = buildBody([filled(9, 0x7a)], { signature: DOC_SIGNATURE, finalCrlf: false });
    expect(decodeAll([body.bytes], signedParams)).toEqual(body.payload);
  });

  it("decodes an unsigned body", () => {
    const payloads = [filled(64, 0x61), filled(5, 0x62)];
    const body = buildBody(payloads);
    expect(body.signatures).toEqual([]);
    expect(decodeAll([body.bytes], { decodedLength: 69 })).toEqual(body.payload);
  });

  it("ignores a chunk signature on an unsigned body", () => {
    const body = buildBody([filled(4, 0x61)], { signature: DOC_SIGNATURE });
    expect(decodeAll([body.bytes], {})).toEqual(body.payload);
  });

  it("verifies a signed trailer block", () => {
    const trailers = [{ name: "x-amz-checksum-crc32", value: "9jRczA==" }];
    const body = buildBody([filled(32, 0x61)], { signature: DOC_SIGNATURE, trailers });
    const seen: ChunkedTrailer[][] = [];
    const decoder = new AwsChunkedDecoder({
      signature: DOC_SIGNATURE,
      trailers: ["X-Amz-Checksum-Crc32"],
      onTrailers: (values) => seen.push([...values]),
    });
    const out = concat(decoder.write(body.bytes));
    decoder.end();
    expect(out).toEqual(body.payload);
    expect(decoder.trailers).toEqual(trailers);
    expect(seen).toEqual([trailers]);
  });

  it("builds the trailer string to sign one line shorter than a chunk's", () => {
    expect(
      trailerStringToSign(DOC_SIGNATURE, DOC_SEED_SIGNATURE, sha256Hex("x")).split("\n"),
    ).toEqual([
      "AWS4-HMAC-SHA256-TRAILER",
      DOC_AMZ_DATE,
      "20130524/us-east-1/s3/aws4_request",
      DOC_SEED_SIGNATURE,
      sha256Hex("x"),
    ]);
  });

  it("verifies several signed trailers", () => {
    const trailers = [
      { name: "x-amz-checksum-crc32", value: "9jRczA==" },
      { name: "x-amz-checksum-sha256", value: "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" },
    ];
    const body = buildBody([filled(8, 0x62)], { signature: DOC_SIGNATURE, trailers });
    const decoder = new AwsChunkedDecoder({
      signature: DOC_SIGNATURE,
      trailers: trailers.map((trailer) => trailer.name),
    });
    decoder.write(body.bytes);
    decoder.end();
    expect(decoder.trailers).toEqual(trailers);
  });

  it("frames an unsigned trailer block without verifying it", () => {
    const trailers = [{ name: "x-amz-checksum-crc32", value: "9jRczA==" }];
    const body = buildBody([filled(16, 0x63)], { trailers });
    const decoder = new AwsChunkedDecoder({ trailers: ["x-amz-checksum-crc32"] });
    const out = concat(decoder.write(body.bytes));
    decoder.end();
    expect(out).toEqual(body.payload);
    expect(decoder.trailers).toEqual(trailers);
  });

  it("decodes through the async-generator form", async () => {
    const payloads = [filled(100, 0x61), filled(200, 0x62)];
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    const seen: ChunkedTrailer[][] = [];
    async function* source(): AsyncGenerator<Uint8Array> {
      for (const piece of pieces(body.bytes, [1, 90, 91, 300])) {
        yield piece;
      }
    }
    const out: Uint8Array[] = [];
    for await (const payload of decodeAwsChunked(source(), {
      ...signedParams,
      decodedLength: 300,
      onTrailers: (values) => seen.push([...values]),
    })) {
      out.push(payload);
    }
    expect(concat(out)).toEqual(body.payload);
    expect(seen).toEqual([]);
  });

  it("releases one array per chunk", () => {
    const payloads = [filled(3, 0x61), filled(5, 0x62), filled(7, 0x63)];
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    const decoder = new AwsChunkedDecoder(signedParams);
    const out = decoder.write(body.bytes);
    decoder.end();
    expect(out.map((part) => part.byteLength)).toEqual([3, 5, 7]);
  });
});

describe("split boundaries", () => {
  const body = buildBody([filled(8, 0x61)], { signature: DOC_SIGNATURE });

  it("is a small body, so the sweep below is exhaustive", () => {
    // `8;chunk-signature=<64>` + CRLF + 8 + CRLF, then the terminal frame and
    // the closing CRLF: 94 + 84 + 2.
    expect(body.bytes.byteLength).toBe(180);
  });

  it("decodes the same body one byte at a time", () => {
    const single = Array.from({ length: body.bytes.byteLength }, (_, index) =>
      body.bytes.subarray(index, index + 1),
    );
    expect(decodeAll(single, signedParams)).toEqual(body.payload);
  });

  it("decodes the same at every single split position", () => {
    for (let offset = 0; offset <= body.bytes.byteLength; offset++) {
      expect(decodeAll(pieces(body.bytes, [offset]), signedParams)).toEqual(body.payload);
    }
  });

  it("decodes the same at every pair of split positions", () => {
    for (let first = 0; first <= body.bytes.byteLength; first++) {
      for (let second = first; second <= body.bytes.byteLength; second++) {
        expect(decodeAll(pieces(body.bytes, [first, second]), signedParams)).toEqual(body.payload);
      }
    }
  });

  it("decodes an unsigned body at every pair of split positions", () => {
    // The unsigned payload path releases runs instead of filling a buffer, so
    // it is a second state machine through the same states and gets its own
    // sweep. Multi-chunk, so a split can also land between two frames.
    const unsigned = buildBody([filled(3, 0x61), filled(5, 0x62)], {
      trailers: [{ name: "x-amz-checksum-crc32", value: "9jRczA==" }],
    });
    const params: AwsChunkedParams = { trailers: ["x-amz-checksum-crc32"], decodedLength: 8 };
    for (let first = 0; first <= unsigned.bytes.byteLength; first++) {
      for (let second = first; second <= unsigned.bytes.byteLength; second++) {
        expect(decodeAll(pieces(unsigned.bytes, [first, second]), params)).toEqual(
          unsigned.payload,
        );
      }
    }
  });

  it("decodes a larger body at random split points", () => {
    const rng = new Rng(0x5f3d_1e07);
    const large = buildBody(
      [filled(1, 0x41), filled(700, 0x42), filled(4093, 0x43), filled(64, 0x44)],
      {
        signature: DOC_SIGNATURE,
        trailers: [{ name: "x-amz-checksum-crc32", value: "9jRczA==" }],
      },
    );
    const params: AwsChunkedParams = {
      ...signedParams,
      trailers: ["x-amz-checksum-crc32"],
      decodedLength: large.payload.byteLength,
    };
    for (let round = 0; round < 200; round++) {
      const offsets = Array.from({ length: rng.range(1, 12) }, () =>
        rng.int(large.bytes.byteLength + 1),
      ).sort((left, right) => left - right);
      expect(decodeAll(pieces(large.bytes, offsets), params)).toEqual(large.payload);
    }
  });
});

describe("buffering", () => {
  it("holds one buffer per signed chunk, not one per write", () => {
    /* The case the buffer is preallocated for. An attacker picks the TCP
       segmentation, so "one retained array per `write()`" was a memory
       amplifier no frame cap bounded: byte at a time, an 8 MiB chunk held 1975
       MiB of live typed-array headers — 247 times its own size, with the *byte*
       content bounded all along. Preallocating at the declared size makes the
       chunk's footprint the chunk's size whatever the delivery looks like
       (measured 1.4 MiB for the megabyte below, outside vitest).

       Asserted as correctness rather than as a heap bound on purpose: the
       decoder allocates nothing per write now, but the caller's own per-write
       garbage — a subarray and a result array each time — is tens of megabytes
       here and is collected whenever V8 feels like it, which is not something
       to hang a CI failure on. What is deterministic is that this arrives
       whole, in one piece, having been held in one buffer. */
    const payload = filled(256 * 1024, 0x61);
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    const decoder = new AwsChunkedDecoder({ ...signedParams, decodedLength: payload.byteLength });
    const out: Uint8Array[] = [];
    for (let index = 0; index < body.bytes.byteLength; index++) {
      out.push(...decoder.write(body.bytes.subarray(index, index + 1)));
    }
    decoder.end();
    expect(out).toHaveLength(1);
    expect(out[0]).toEqual(payload);
    expect(decoder.decodedBytes).toBe(payload.byteLength);
  });

  it("releases a signed chunk only once it has verified", () => {
    const body = buildBody([filled(16, 0x61)], { signature: DOC_SIGNATURE });
    const decoder = new AwsChunkedDecoder(signedParams);
    // Header and every payload byte, but not the CRLF that ends the frame.
    expect(decoder.write(body.bytes.subarray(0, 101))).toEqual([]);
    expect(decoder.write(body.bytes.subarray(101))).toHaveLength(1);
    decoder.end();
  });

  it("streams an unsigned chunk out before its frame ends", () => {
    const body = buildBody([filled(16, 0x61)]);
    const decoder = new AwsChunkedDecoder({});
    // `10` + CRLF is 4 bytes: the rest of this is payload, and none of it is
    // covered by anything, so holding it would buy nothing.
    const early = decoder.write(body.bytes.subarray(0, 12));
    expect(concat(early)).toEqual(filled(8, 0x61));
    expect(concat(decoder.write(body.bytes.subarray(12)))).toEqual(filled(8, 0x61));
    decoder.end();
  });

  it("accepts an unsigned chunk larger than the signed frame cap", () => {
    // What aws-sdk-go-v2 and rclone send: the whole object as one unsigned
    // chunk. A frame cap here would be an upload size limit (minio/minio#21611).
    const payload = filled(CHUNKED_MAX_FRAME + 1024, 0x62);
    const body = buildBody([payload]);
    expect(decodeAll([body.bytes], { decodedLength: payload.byteLength }).byteLength).toBe(
      payload.byteLength,
    );
  });

  it("does not apply a lowered frame cap to an unsigned chunk", () => {
    const body = buildBody([filled(4096, 0x63)]);
    expect(decodeAll([body.bytes], { limits: { maxFrame: 8 } })).toEqual(body.payload);
  });

  it("still applies the frame cap to a signed chunk", () => {
    const header = `ffffffff;chunk-signature=${DOC_CHUNK_SIGNATURES[0]}${CRLF}`;
    const error = refuseBody(ascii(header), signedParams);
    expect(error.reason).toBe("too-large");
    expect(error.message).toContain(String(CHUNKED_MAX_FRAME));
  });

  it("refuses an unsigned size that is not an exact integer", () => {
    const error = refuseBody(ascii(`ffffffffffffffff${CRLF}`), {});
    expect(error.reason).toBe("too-large");
    expect(error.message).toContain(String(Number.MAX_SAFE_INTEGER));
  });

  it("still bounds an unsigned body by the decoded length", () => {
    const body = buildBody([filled(64, 0x61)]);
    expect(refuseBody(body.bytes, { decodedLength: 32 })).toMatchObject({
      reason: "length-mismatch",
    });
    expect(refuseBody(body.bytes, { limits: { maxDecodedBytes: 32 } })).toMatchObject({
      reason: "too-large",
    });
  });
});

describe("the zero-copy contract", () => {
  it("keeps its output when the caller overwrites the buffer it was given", () => {
    const payloads = [filled(40, 0x61), filled(40, 0x62)];
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    const decoder = new AwsChunkedDecoder(signedParams);
    const scratch = new Uint8Array(32);
    const out: Uint8Array[] = [];
    for (let offset = 0; offset < body.bytes.byteLength; offset += scratch.byteLength) {
      const piece = body.bytes.subarray(offset, offset + scratch.byteLength);
      scratch.set(piece);
      out.push(...decoder.write(scratch.subarray(0, piece.byteLength)));
      // Whatever the decoder kept has to be its own copy by now.
      scratch.fill(0xff);
    }
    decoder.end();
    expect(concat(out)).toEqual(body.payload);
  });

  it("hands back arrays that do not alias the input", () => {
    const body = buildBody([filled(6, 0x61)], { signature: DOC_SIGNATURE });
    const decoder = new AwsChunkedDecoder(signedParams);
    const out = decoder.write(body.bytes);
    decoder.end();
    for (const part of out) {
      expect(part.buffer).not.toBe(body.bytes.buffer);
    }
  });
});

describe("tampering", () => {
  const payloads = [filled(24, 0x61), filled(9, 0x62)];

  function tampered(mutate: (bytes: Uint8Array) => void): ChunkedError {
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    mutate(body.bytes);
    return refuseBody(body.bytes, signedParams);
  }

  it("refuses a flipped payload byte", () => {
    const error = tampered((bytes) => {
      flip(bytes, 100);
    });
    expect(error.reason).toBe("signature-mismatch");
  });

  it("refuses a flipped signature hex digit", () => {
    const error = tampered((bytes) => {
      bytes[40] = bytes[40] === 0x61 ? 0x62 : 0x61;
    });
    expect(error.reason).toBe("signature-mismatch");
  });

  it("refuses the right body under the wrong seed", () => {
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    const error = refuseBody(body.bytes, {
      signature: { ...DOC_SIGNATURE, seed: DOC_CHUNK_SIGNATURES[0]! },
    });
    expect(error.reason).toBe("signature-mismatch");
  });

  it("refuses the right body under the wrong secret", () => {
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    const error = refuseBody(body.bytes, {
      signature: { ...DOC_SIGNATURE, secretAccessKey: `${DOC_SECRET_KEY}x` },
    });
    expect(error.reason).toBe("signature-mismatch");
  });

  it("refuses the right body under the wrong date", () => {
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    const error = refuseBody(body.bytes, {
      signature: { ...DOC_SIGNATURE, amzDate: "20130524T000001Z" },
    });
    expect(error.reason).toBe("signature-mismatch");
  });

  it("refuses reordered chunks", () => {
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    const swapped = concat([body.frames[1]!, body.frames[0]!, body.frames[2]!, body.frames[3]!]);
    expect(refuseBody(swapped, signedParams).reason).toBe("signature-mismatch");
  });

  it("refuses a replayed chunk", () => {
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    const replayed = concat([
      body.frames[0]!,
      body.frames[0]!,
      body.frames[1]!,
      body.frames[2]!,
      body.frames[3]!,
    ]);
    expect(refuseBody(replayed, signedParams).reason).toBe("signature-mismatch");
  });

  it("refuses a tampered trailer signature", () => {
    const body = buildBody([filled(4, 0x61)], {
      signature: DOC_SIGNATURE,
      trailers: [{ name: "x-amz-checksum-crc32", value: "9jRczA==" }],
      trailerSignature: DOC_CHUNK_SIGNATURES[2],
    });
    const error = refuseBody(body.bytes, {
      ...signedParams,
      trailers: ["x-amz-checksum-crc32"],
    });
    expect(error.reason).toBe("signature-mismatch");
  });

  it("refuses a tampered trailer value", () => {
    const trailers = [{ name: "x-amz-checksum-crc32", value: "9jRczA==" }];
    const body = buildBody([filled(4, 0x61)], { signature: DOC_SIGNATURE, trailers });
    const at = body.bytes.byteLength - 4 - 64 - 26 - 2;
    body.bytes[at] = 0x41;
    const error = refuseBody(body.bytes, { ...signedParams, trailers: ["x-amz-checksum-crc32"] });
    expect(error.reason).toBe("signature-mismatch");
  });

  it("sticks to the first refusal", () => {
    const body = buildBody(payloads, { signature: DOC_SIGNATURE });
    flip(body.bytes, 100);
    const decoder = new AwsChunkedDecoder(signedParams);
    const first = refusal(() => {
      decoder.write(body.bytes);
    });
    const second = refusal(() => {
      decoder.write(new Uint8Array(4));
    });
    const third = refusal(() => {
      decoder.end();
    });
    expect(second).toBe(first);
    expect(third).toBe(first);
  });
});

describe("hostile framing", () => {
  const payload = filled(16, 0x61);

  it("refuses a size with no hex digits", () => {
    expect(
      refuseBody(ascii(`;chunk-signature=${DOC_CHUNK_SIGNATURES[0]}${CRLF}`), signedParams),
    ).toMatchObject({ reason: "bad-size" });
  });

  it("refuses a size that is not hexadecimal", () => {
    expect(
      refuseBody(ascii(`1g;chunk-signature=${DOC_CHUNK_SIGNATURES[0]}${CRLF}`), signedParams),
    ).toMatchObject({ reason: "bad-size" });
  });

  it("refuses a size of more than 16 hex digits", () => {
    const header = `00000000000000000010;chunk-signature=${DOC_CHUNK_SIGNATURES[0]}${CRLF}`;
    expect(refuseBody(ascii(header), signedParams)).toMatchObject({ reason: "bad-size" });
  });

  it("refuses a size over the frame cap", () => {
    const header = `ffffffffffffffff;chunk-signature=${DOC_CHUNK_SIGNATURES[0]}${CRLF}`;
    const error = refuseBody(ascii(header), signedParams);
    expect(error.reason).toBe("too-large");
    expect(error.message).toContain(String(CHUNKED_MAX_FRAME));
  });

  it("honours a lowered frame cap", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    expect(refuseBody(body.bytes, { ...signedParams, limits: { maxFrame: 8 } })).toMatchObject({
      reason: "too-large",
    });
  });

  it("refuses a chunk header longer than the cap", () => {
    const header = `10;${"x".repeat(400)}${CRLF}`;
    expect(refuseBody(ascii(header), signedParams)).toMatchObject({ reason: "malformed" });
  });

  /* A 16-byte payload frames as `10;chunk-signature=<64 hex>` (83 bytes), CRLF
     at 83..84, the payload at 85..100 and its CRLF at 101..102. */
  const HEADER_CR = 83;
  const PAYLOAD_CR = 101;

  it("refuses a header CR that is not followed by LF", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    body.bytes[HEADER_CR + 1] = 0x41;
    expect(refuseBody(body.bytes, signedParams)).toMatchObject({ reason: "malformed" });
  });

  it("refuses a header line that never ends", () => {
    expect(
      refuseBody(ascii(`10;chunk-signature=${DOC_CHUNK_SIGNATURES[0]}`), signedParams),
    ).toMatchObject({ reason: "truncated" });
  });

  it("refuses a payload that is not followed by CRLF", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    body.bytes[PAYLOAD_CR] = 0x61;
    expect(refuseBody(body.bytes, signedParams)).toMatchObject({ reason: "malformed" });
  });

  it("refuses a payload whose CR has no LF", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    body.bytes[PAYLOAD_CR + 1] = 0x61;
    expect(refuseBody(body.bytes, signedParams)).toMatchObject({ reason: "malformed" });
  });

  it("refuses a chunk whose declared payload never arrives", () => {
    const frames = buildBody([payload], { signature: DOC_SIGNATURE }).frames;
    expect(
      refuseBody(frames[0]!.subarray(0, frames[0]!.byteLength - 6), signedParams),
    ).toMatchObject({ reason: "truncated" });
  });

  it("refuses a declared size larger than what arrives", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    // `10` becomes `11`: the frame now runs one byte past its own payload.
    body.bytes[1] = 0x31;
    expect(refuseBody(body.bytes, signedParams)).toMatchObject({ reason: "malformed" });
  });

  it("refuses a declared size smaller than what arrives", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    // `10` becomes `0f`: the frame now ends one byte inside its own payload.
    body.bytes[0] = 0x30;
    body.bytes[1] = 0x66;
    expect(refuseBody(body.bytes, signedParams)).toMatchObject({ reason: "malformed" });
  });

  it("refuses a chunk with no signature when the body is signed", () => {
    const body = buildBody([payload]);
    expect(refuseBody(body.bytes, signedParams)).toMatchObject({ reason: "missing-signature" });
  });

  it("refuses a chunk signature that is not 64 hex characters", () => {
    const header = `10;chunk-signature=abc${CRLF}`;
    expect(refuseBody(ascii(header), signedParams)).toMatchObject({ reason: "malformed" });
  });

  it("refuses a chunk extension with no value", () => {
    const header = `10;chunk-signature${CRLF}`;
    expect(refuseBody(ascii(header), signedParams)).toMatchObject({ reason: "missing-signature" });
  });

  it("refuses garbage after the terminal chunk", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    const trailing = concat([body.bytes, ascii("x")]);
    expect(refuseBody(trailing, signedParams)).toMatchObject({ reason: "trailing-bytes" });
  });

  it("refuses a second CRLF after the terminal chunk", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    const trailing = concat([body.bytes, ascii(CRLF)]);
    expect(refuseBody(trailing, signedParams)).toMatchObject({ reason: "trailing-bytes" });
  });

  it("refuses another chunk after the terminal one", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    const extra = concat([body.bytes, body.frames[0]!]);
    expect(refuseBody(extra, signedParams)).toMatchObject({ reason: "trailing-bytes" });
  });

  it("refuses bytes written after end()", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    const decoder = new AwsChunkedDecoder(signedParams);
    decoder.write(body.bytes);
    decoder.end();
    decoder.end();
    expect(
      refusal(() => {
        decoder.write(ascii("x"));
      }).reason,
    ).toBe("trailing-bytes");
  });

  it("refuses a body that never reaches its terminal chunk", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    expect(refuseBody(body.frames[0]!, signedParams)).toMatchObject({ reason: "truncated" });
  });

  it("refuses truncation at every prefix but the two that are whole bodies", () => {
    const body = buildBody([filled(8, 0x61)], { signature: DOC_SIGNATURE });
    const total = body.bytes.byteLength;
    for (let length = 0; length < total; length++) {
      const prefix = body.bytes.subarray(0, length);
      if (length === total - 2) {
        // Everything but the optional trailing CRLF: a complete body.
        expect(decodeAll([prefix], signedParams)).toEqual(body.payload);
        continue;
      }
      expect(refuseBody(prefix, signedParams).reason).toBe("truncated");
    }
  });

  it("refuses a body shorter than x-amz-decoded-content-length", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    expect(refuseBody(body.bytes, { ...signedParams, decodedLength: 17 })).toMatchObject({
      reason: "length-mismatch",
    });
  });

  it("refuses a body longer than x-amz-decoded-content-length, at the header", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    const error = refuseBody(body.bytes, { ...signedParams, decodedLength: 15 });
    expect(error.reason).toBe("length-mismatch");
    // Refused from the header alone, before any payload byte was consumed.
    expect(error.offset).toBe(85);
  });

  it("refuses a body over an explicit decoded-byte cap", () => {
    const body = buildBody([payload], { signature: DOC_SIGNATURE });
    expect(
      refuseBody(body.bytes, { ...signedParams, limits: { maxDecodedBytes: 4 } }),
    ).toMatchObject({ reason: "too-large" });
  });

  it("refuses a seed signature that is not 64 hex characters", () => {
    expect(
      refusal(() => {
        const decoder = new AwsChunkedDecoder({ signature: { ...DOC_SIGNATURE, seed: "nope" } });
        expect(decoder).toBeUndefined();
      }).reason,
    ).toBe("malformed");
  });
});

describe("hostile trailers", () => {
  const trailers = [{ name: "x-amz-checksum-crc32", value: "9jRczA==" }];
  const declared = { trailers: ["x-amz-checksum-crc32"] };

  it("refuses a trailer block that was never declared", () => {
    const body = buildBody([filled(4, 0x61)], { signature: DOC_SIGNATURE, trailers });
    expect(refuseBody(body.bytes, signedParams)).toMatchObject({ reason: "trailing-bytes" });
  });

  it("refuses an undeclared trailing header", () => {
    const body = buildBody([filled(4, 0x61)], {
      signature: DOC_SIGNATURE,
      trailers: [{ name: "x-amz-checksum-sha1", value: "2jmj7l5rSw0yVb/vlWAYkK/YBwk=" }],
    });
    expect(refuseBody(body.bytes, { ...signedParams, ...declared })).toMatchObject({
      reason: "trailer",
    });
  });

  it("refuses a declared trailing header that never arrives", () => {
    const body = buildBody([filled(4, 0x61)], { signature: DOC_SIGNATURE, trailers });
    expect(
      refuseBody(body.bytes, {
        ...signedParams,
        trailers: ["x-amz-checksum-crc32", "x-amz-checksum-sha256"],
      }),
    ).toMatchObject({ reason: "trailer" });
  });

  it("refuses a repeated trailing header", () => {
    const body = buildBody([filled(4, 0x61)], {
      signature: DOC_SIGNATURE,
      trailers: [...trailers, ...trailers],
    });
    expect(refuseBody(body.bytes, { ...signedParams, ...declared })).toMatchObject({
      reason: "trailer",
    });
  });

  it("refuses a trailing header with no name", () => {
    const body = buildBody([filled(4, 0x61)], { signature: DOC_SIGNATURE });
    const broken = concat([
      body.frames[0]!,
      body.frames[1]!,
      ascii(`:novalue${CRLF}`),
      body.frames[2]!,
    ]);
    expect(refuseBody(broken, { ...signedParams, ...declared })).toMatchObject({
      reason: "trailer",
    });
  });

  it("refuses a trailer block over the byte budget", () => {
    const body = buildBody([filled(4, 0x61)], {
      signature: DOC_SIGNATURE,
      trailers: [{ name: "x-amz-checksum-crc32", value: "A".repeat(600) }],
    });
    expect(
      refuseBody(body.bytes, {
        ...signedParams,
        ...declared,
        limits: { maxTrailerBytes: 128 },
      }),
    ).toMatchObject({ reason: "too-large" });
  });

  it("refuses a trailer signature on an unsigned body", () => {
    const body = buildBody([filled(4, 0x61)], { signature: DOC_SIGNATURE, trailers });
    const decoder = new AwsChunkedDecoder(declared);
    expect(
      refusal(() => {
        decoder.write(body.bytes);
      }).reason,
    ).toBe("trailer");
  });

  it("refuses a trailer signature that is not 64 hex characters", () => {
    const body = buildBody([filled(4, 0x61)], {
      signature: DOC_SIGNATURE,
      trailers,
      trailerSignature: "short",
    });
    expect(refuseBody(body.bytes, { ...signedParams, ...declared })).toMatchObject({
      reason: "malformed",
    });
  });

  it("refuses a signed body whose trailer block just stops", () => {
    const body = buildBody([filled(4, 0x61)], { signature: DOC_SIGNATURE, trailers });
    const cut = body.bytes.subarray(0, body.bytes.byteLength - 4 - 64 - 26);
    expect(refuseBody(cut, { ...signedParams, ...declared })).toMatchObject({
      reason: "truncated",
    });
  });

  it("refuses a signed body that stops between the trailer and its signature", () => {
    const body = buildBody([filled(4, 0x61)], { signature: DOC_SIGNATURE, trailers });
    const cut = concat([body.frames[0]!, body.frames[1]!, body.frames[2]!]);
    expect(refuseBody(cut, { ...signedParams, ...declared })).toMatchObject({
      reason: "truncated",
    });
  });

  it("refuses a body that stops between a trailer's CR and its LF", () => {
    const body = buildBody([filled(4, 0x61)], { trailers });
    const line = body.frames[2]!;
    const cut = concat([body.frames[0]!, body.frames[1]!, line.subarray(0, line.byteLength - 1)]);
    expect(refuseBody(cut, declared)).toMatchObject({ reason: "truncated" });
  });

  it("refuses a trailer block that fills the budget exactly, LF included", () => {
    const body = buildBody([filled(4, 0x61)], { trailers: [{ name: "a", value: "b" }] });
    expect(
      refuseBody(body.bytes, { trailers: ["a"], limits: { maxTrailerBytes: 3 } }),
    ).toMatchObject({ reason: "too-large" });
  });

  it("refuses an unsigned trailer block that stops mid-line", () => {
    const body = buildBody([filled(4, 0x61)], { trailers });
    const cut = body.bytes.subarray(0, body.bytes.byteLength - 6);
    expect(refuseBody(cut, declared)).toMatchObject({ reason: "truncated" });
  });

  it("accepts an unsigned trailer block that ends without its empty line", () => {
    const body = buildBody([filled(4, 0x61)], { trailers, finalCrlf: false });
    const decoder = new AwsChunkedDecoder(declared);
    const out = concat(decoder.write(body.bytes));
    decoder.end();
    expect(out).toEqual(filled(4, 0x61));
    expect(decoder.trailers).toEqual(trailers);
  });
});

describe("fuzz", () => {
  const rng = new Rng(0x1234_abcd);
  const valid = buildBody([filled(3, 0x61), filled(64, 0x62)], {
    signature: DOC_SIGNATURE,
    trailers: [{ name: "x-amz-checksum-crc32", value: "9jRczA==" }],
  });
  const params: AwsChunkedParams = {
    ...signedParams,
    trailers: ["x-amz-checksum-crc32"],
    decodedLength: 67,
  };

  it("only ever throws a ChunkedError over mutated bodies", () => {
    for (let round = 0; round < 3000; round++) {
      const bytes = new Uint8Array(valid.bytes);
      for (let mutation = rng.range(1, 4); mutation > 0; mutation--) {
        switch (rng.int(3)) {
          case 0: {
            bytes[rng.int(bytes.byteLength)] = rng.int(256);
            break;
          }
          case 1: {
            flip(bytes, rng.int(bytes.byteLength), 1 << rng.int(8));
            break;
          }
          default: {
            bytes[rng.int(bytes.byteLength)] = rng.pick([0x0a, 0x0d, 0x3b, 0x30, 0x66]);
          }
        }
      }
      const offsets = Array.from({ length: rng.int(4) }, () => rng.int(bytes.byteLength + 1)).sort(
        (left, right) => left - right,
      );
      try {
        decodeAll(pieces(bytes, offsets), params);
      } catch (error) {
        if (!isChunkedError(error)) {
          throw error;
        }
      }
    }
  });

  it("only ever throws a ChunkedError over random bytes", () => {
    for (let round = 0; round < 2000; round++) {
      const bytes = rng.bytes(rng.int(128));
      try {
        decodeAll([bytes], rng.bool() ? params : {});
      } catch (error) {
        if (!isChunkedError(error)) {
          throw error;
        }
      }
    }
  });

  it("never hangs on a body of only separators", () => {
    for (const filler of [0x0d, 0x0a, 0x3b, 0x30]) {
      const error = refuseBody(filled(4096, filler), signedParams);
      expect(isChunkedError(error)).toBe(true);
    }
  });
});
