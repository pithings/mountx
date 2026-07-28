/**
 * Decoder fuzzing.
 *
 * The invariant under test is narrow and load-bearing: **only `ProtocolError`
 * escapes a decoder.** Anything else — a `RangeError` from a `DataView`, an
 * allocation blow-up from an unvalidated count, a `TypeError` from a missing
 * field — reaches the read/reply loop as an unhandled throw, and an unanswered
 * FUSE request is an unkillable `D`-state process.
 *
 * Deterministic: every case comes from a seeded PRNG, so a failure reproduces.
 */

import { describe, expect, it } from "vitest";
import { SUPPORTED_OPCODES } from "../../src/fuse/protocol.ts";
import {
  decodeInHeader,
  decodeInitIn,
  decodeInitOut,
  decodeOutHeader,
  decodeReply,
  decodeReplyBody,
  decodeRequest,
  decodeRequestBody,
  decodeXattrNames,
  encodeReplyBody,
  encodeRequest,
  encodeRequestBody,
  isProtocolError,
  unpackDirents,
  unpackDirentsPlus,
} from "../../src/fuse/protocol.ts";
import { REPLY_GENERATORS, REQUEST_GENERATORS, Rng } from "./random.ts";

/**
 * Run `decode` and insist that any failure is a `ProtocolError`.
 *
 * Returns whether the decode *succeeded*, so a test can assert that the fuzzer
 * actually reaches the decoders instead of bouncing off the first length check.
 */
function onlyProtocolErrors(what: string, decode: () => unknown): boolean {
  try {
    decode();
    return true;
  } catch (error) {
    if (isProtocolError(error)) {
      return false;
    }
    throw new Error(
      `${what} threw ${(error as Error)?.constructor?.name ?? typeof error}: ${
        (error as Error)?.message
      }`,
      { cause: error },
    );
  }
}

const ITERATIONS = 4000;

describe("random bytes", () => {
  // A header-only probe **by design**: uniformly random bytes essentially never
  // satisfy `fuse_in_header.len <= buffer.length`, so ~0 of these iterations
  // reach a struct decoder. That is the point — it proves the outermost framing
  // checks are total. The "structurally plausible headers" case below and the
  // whole mutation suite are what exercise the struct bodies.
  it("never escapes a non-ProtocolError from decodeRequest", () => {
    const rng = new Rng(0xf0_02_01);
    for (let round = 0; round < ITERATIONS; round++) {
      const bytes = rng.bytes(rng.int(160));
      onlyProtocolErrors(`decodeRequest(${bytes.length} random bytes)`, () => decodeRequest(bytes));
    }
  });

  it("never escapes a non-ProtocolError from a request body decoder", () => {
    const rng = new Rng(0xf0_02_02);
    for (let round = 0; round < ITERATIONS; round++) {
      const opcode = rng.pick(SUPPORTED_OPCODES);
      const bytes = rng.bytes(rng.int(128));
      onlyProtocolErrors(`decodeRequestBody(${opcode})`, () => decodeRequestBody(opcode, bytes));
    }
  });

  it("never escapes a non-ProtocolError from a reply body decoder", () => {
    const rng = new Rng(0xf0_02_03);
    for (let round = 0; round < ITERATIONS; round++) {
      const opcode = rng.pick(SUPPORTED_OPCODES);
      const bytes = rng.bytes(rng.int(400));
      onlyProtocolErrors(`decodeReplyBody(${opcode})`, () => decodeReplyBody(opcode, bytes));
    }
  });

  // `decodeReply` here is likewise mostly a framing probe; the others take
  // whatever bytes they are given and do reach their struct decoders.
  it("never escapes a non-ProtocolError from the headers, INIT or dirents", () => {
    const rng = new Rng(0xf0_02_04);
    for (let round = 0; round < ITERATIONS; round++) {
      const bytes = rng.bytes(rng.int(400));
      const opcode = rng.pick(SUPPORTED_OPCODES);
      onlyProtocolErrors("decodeInHeader", () => decodeInHeader(bytes));
      onlyProtocolErrors("decodeOutHeader", () => decodeOutHeader(bytes));
      onlyProtocolErrors("decodeReply", () => decodeReply(bytes, opcode));
      onlyProtocolErrors("decodeInitIn", () => decodeInitIn(bytes));
      onlyProtocolErrors("decodeInitOut", () => decodeInitOut(bytes));
      onlyProtocolErrors("unpackDirents", () => unpackDirents(bytes));
      onlyProtocolErrors("unpackDirentsPlus", () => unpackDirentsPlus(bytes));
      onlyProtocolErrors("decodeXattrNames", () => decodeXattrNames(bytes));
    }
  });

  it("survives structurally plausible headers with random bodies", () => {
    // A random body behind a *valid* header reaches deeper into the decoders
    // than uniformly random bytes, which almost always die at the length check.
    const rng = new Rng(0xf0_02_05);
    let decoded = 0;
    for (let round = 0; round < ITERATIONS; round++) {
      const opcode = rng.pick(SUPPORTED_OPCODES);
      const message = encodeRequest({
        opcode,
        unique: rng.u64(),
        nodeid: rng.u64(),
        payload: rng.bytes(rng.int(96)),
      });
      if (
        onlyProtocolErrors(`decodeRequest(valid header, opcode ${opcode})`, () =>
          decodeRequest(message),
        )
      ) {
        decoded++;
      }
    }
    // Some of these are valid messages by luck: the fuzzer is reaching past
    // the framing and into the struct decoders.
    expect(decoded).toBeGreaterThan(0);
  });
});

describe("mutated valid messages", () => {
  it("never escapes a non-ProtocolError from a mutated request", () => {
    const rng = new Rng(0xf0_02_06);
    let decoded = 0;
    for (let round = 0; round < ITERATIONS; round++) {
      const opcode = rng.pick(SUPPORTED_OPCODES);
      const generate = REQUEST_GENERATORS.get(opcode);
      const message = encodeRequest({
        opcode,
        unique: rng.u64(),
        nodeid: rng.u64(),
        body: generate?.(rng, { minor: 41, setxattrExt: false }),
      });
      mutate(rng, message);
      if (onlyProtocolErrors(`decodeRequest(mutated ${opcode})`, () => decodeRequest(message))) {
        decoded++;
      }
    }
    // A few flipped bytes usually leave a still-decodable message, which is
    // exactly the case that reaches deepest into the codecs.
    expect(decoded).toBeGreaterThan(ITERATIONS / 4);
  });

  it("never escapes a non-ProtocolError from a mutated reply", () => {
    const rng = new Rng(0xf0_02_07);
    for (let round = 0; round < ITERATIONS; round++) {
      const opcode = rng.pick(SUPPORTED_OPCODES);
      const generate = REPLY_GENERATORS.get(opcode);
      const body = encodeReplyBody(opcode, generate?.(rng, { minor: 41, setxattrExt: false }));
      mutate(rng, body);
      onlyProtocolErrors(`decodeReplyBody(mutated ${opcode})`, () => decodeReplyBody(opcode, body));
    }
  });

  it("never escapes a non-ProtocolError from a truncated request", () => {
    const rng = new Rng(0xf0_02_08);
    for (let round = 0; round < ITERATIONS; round++) {
      const opcode = rng.pick(SUPPORTED_OPCODES);
      const generate = REQUEST_GENERATORS.get(opcode);
      const message = encodeRequest({
        opcode,
        unique: 1n,
        nodeid: 1n,
        body: generate?.(rng, { minor: 41, setxattrExt: false }),
      });
      const cut = message.subarray(0, rng.int(message.length + 1));
      onlyProtocolErrors(`decodeRequest(truncated ${opcode})`, () => decodeRequest(cut));
    }
  });

  it("never escapes a non-ProtocolError when the negotiated version disagrees", () => {
    // Encoded at 7.41, decoded as an ancient kernel and vice versa: a real
    // hazard if negotiation and dispatch ever get out of step.
    const rng = new Rng(0xf0_02_09);
    const contexts = [
      { minor: 41, setxattrExt: false },
      { minor: 41, setxattrExt: true },
      { minor: 8, setxattrExt: false },
      { minor: 3, setxattrExt: true },
    ];
    for (let round = 0; round < ITERATIONS; round++) {
      const opcode = rng.pick(SUPPORTED_OPCODES);
      const encodeCtx = rng.pick(contexts);
      const decodeCtx = rng.pick(contexts);
      const request = encodeRequestBody(
        opcode,
        REQUEST_GENERATORS.get(opcode)?.(rng, encodeCtx),
        encodeCtx,
      );
      onlyProtocolErrors(`decodeRequestBody(${opcode}) across versions`, () =>
        decodeRequestBody(opcode, request, decodeCtx),
      );
      const reply = encodeReplyBody(
        opcode,
        REPLY_GENERATORS.get(opcode)?.(rng, encodeCtx),
        encodeCtx,
      );
      onlyProtocolErrors(`decodeReplyBody(${opcode}) across versions`, () =>
        decodeReplyBody(opcode, reply, decodeCtx),
      );
    }
  });
});

/** Flip a few bytes in place. */
function mutate(rng: Rng, bytes: Uint8Array): void {
  const edits = rng.range(1, 4);
  for (let index = 0; index < edits && bytes.length > 0; index++) {
    bytes[rng.int(bytes.length)] = rng.u32() & 0xff;
  }
}
