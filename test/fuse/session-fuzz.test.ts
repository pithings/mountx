/**
 * Session fuzzing.
 *
 * The decoder fuzz in `fuzz.test.ts` proves only `ProtocolError` escapes a
 * codec. This proves the thing that actually keeps a mountpoint alive: whatever
 * bytes arrive, **`handleMessage` never rejects, every request gets exactly one
 * reply, and the session keeps serving afterwards** (IDEA.md, Tier 0).
 *
 * A missing reply is an unkillable `D`-state process; an unhandled rejection in
 * the read loop is the same thing one tick later. Both are cheap to test for.
 *
 * Deterministic: every case comes from a seeded PRNG, so a failure reproduces.
 */

import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import {
  FUSE_BATCH_FORGET,
  FUSE_DESTROY,
  FUSE_FORGET,
  FUSE_IN_HEADER_SIZE,
  FUSE_NOTIFY_REPLY,
  FUSE_ROOT_ID,
  OPCODE_NAMES,
  opcodeName,
} from "../../src/fuse/constants.ts";
import { decodeOutHeader, encodeRequest, SUPPORTED_OPCODES } from "../../src/fuse/protocol.ts";
import { FuseSession } from "../../src/fuse/session.ts";
import { REQUEST_GENERATORS, Rng } from "./random.ts";
import { SyntheticKernel } from "./synthetic-kernel.ts";

const NO_REPLY = new Set([FUSE_FORGET, FUSE_BATCH_FORGET, FUSE_NOTIFY_REPLY]);
/**
 * `DESTROY` is excluded everywhere: answering it *is* the correct behaviour, and
 * a fuzzer that lands on it would be asserting that a shut-down session still
 * serves. The lifecycle is driven deliberately in `session.test.ts` instead.
 */
const ALL_OPCODES = Object.keys(OPCODE_NAMES)
  .map(Number)
  .filter((opcode) => opcode !== FUSE_DESTROY);
const FUZZ_OPCODES = SUPPORTED_OPCODES.filter((opcode) => opcode !== FUSE_DESTROY);
const ITERATIONS = 1500;

/** Every opcode name, so a failure says which one. */
function label(bytes: Uint8Array): string {
  if (bytes.length < 8) {
    return `${bytes.length} bytes`;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return `${opcodeName(view.getUint32(4, true))} (${bytes.length} bytes)`;
}

/**
 * Feed one message in and assert the contract:
 *
 * - the promise settles, and never rejects;
 * - a reply, if any, is a well-formed `fuse_out_header` answering *this*
 *   request's `unique`;
 * - `null` only happens for the opcodes that want no reply, or for a message
 *   too damaged to carry a `unique` at all.
 */
async function feed(session: FuseSession, bytes: Uint8Array): Promise<Uint8Array | null> {
  let reply: Uint8Array | null;
  try {
    reply = await session.handleMessage(bytes);
  } catch (error) {
    throw new Error(`handleMessage rejected for ${label(bytes)}: ${String(error)}`, {
      cause: error,
    });
  }
  if (reply === null) {
    return null;
  }
  const header = decodeOutHeader(reply);
  expect(header.len).toBe(reply.length);
  if (bytes.length >= FUSE_IN_HEADER_SIZE) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const opcode = view.getUint32(4, true);
    expect(header.unique).toBe(view.getBigUint64(8, true));
    expect(NO_REPLY.has(opcode)).toBe(false);
  }
  return reply;
}

async function mounted(): Promise<{ session: FuseSession; kernel: SyntheticKernel }> {
  const session = new FuseSession(createMemoryDriver());
  const kernel = new SyntheticKernel(session);
  await kernel.init();
  return { session, kernel };
}

/** The session still works after being hosed. */
async function stillAlive(kernel: SyntheticKernel): Promise<void> {
  const dir = await kernel.mkdir(FUSE_ROOT_ID, `survivor-${kernel.nextUnique}`);
  expect(dir.nodeid).toBeGreaterThan(FUSE_ROOT_ID);
  const attrs = await kernel.getattr(dir.nodeid);
  expect(attrs.attr.mode).toBeGreaterThan(0);
}

describe("random bytes", () => {
  it("survives uniformly random messages", async () => {
    const { session, kernel } = await mounted();
    const rng = new Rng(0x5e_55_10_01);
    for (let round = 0; round < ITERATIONS; round++) {
      await feed(session, rng.bytes(rng.int(200)));
    }
    expect(session.assertions).toEqual([]);
    await stillAlive(kernel);
  });

  it("survives plausible headers with garbage bodies", async () => {
    const { session, kernel } = await mounted();
    const rng = new Rng(0x5e_55_10_02);
    for (let round = 0; round < ITERATIONS; round++) {
      const body = rng.bytes(rng.int(96));
      const message = new Uint8Array(FUSE_IN_HEADER_SIZE + body.length);
      const view = new DataView(message.buffer);
      view.setUint32(0, message.length, true);
      view.setUint32(4, rng.pick(ALL_OPCODES), true);
      // A zero `unique` is legal input and must be dropped, not answered.
      view.setBigUint64(8, rng.bool(0.1) ? 0n : BigInt(round + 1), true);
      view.setBigUint64(16, rng.bool(0.5) ? FUSE_ROOT_ID : rng.u64(), true);
      message.set(body, FUSE_IN_HEADER_SIZE);
      await feed(session, message);
    }
    expect(session.assertions).toEqual([]);
    await stillAlive(kernel);
  });

  it("survives lies about the message length", async () => {
    const { session, kernel } = await mounted();
    const rng = new Rng(0x5e_55_10_03);
    for (let round = 0; round < ITERATIONS; round++) {
      const message = rng.bytes(rng.range(FUSE_IN_HEADER_SIZE, 120));
      const view = new DataView(message.buffer);
      view.setUint32(
        0,
        rng.pick([0, 1, 39, message.length, message.length + 1, 0xff_ff_ff_ff]),
        true,
      );
      view.setUint32(4, rng.pick(FUZZ_OPCODES), true);
      view.setBigUint64(8, BigInt(round + 1), true);
      await feed(session, message);
    }
    expect(session.assertions).toEqual([]);
    await stillAlive(kernel);
  });
});

describe("well-formed but hostile requests", () => {
  it("answers every generated request for every opcode exactly once", async () => {
    const { session, kernel } = await mounted();
    const rng = new Rng(0x5e_55_10_04);
    let answered = 0;
    for (let round = 0; round < ITERATIONS; round++) {
      const opcode = rng.pick(FUZZ_OPCODES);
      const generate = REQUEST_GENERATORS.get(opcode)!;
      let message: Uint8Array;
      try {
        message = encodeRequest(
          {
            opcode,
            unique: BigInt(round + 1),
            // Half the time a nodeid that exists, half the time a ghost.
            nodeid: rng.bool() ? FUSE_ROOT_ID : rng.u64(),
            body: generate(rng, session.protocol!),
          },
          session.protocol,
        );
      } catch {
        // The generator produced something the *encoder* rejects (a name with
        // a NUL, say). Not this test's business.
        continue;
      }
      const reply = await feed(session, message);
      if (reply !== null) {
        answered++;
      }
    }
    // The generators cover every opcode, so most rounds must have produced a
    // real reply — otherwise this test is passing by not testing anything.
    expect(answered).toBeGreaterThan(ITERATIONS / 2);
    expect(session.stats.replies + session.stats.noReply + session.stats.dropped).toBe(
      session.stats.requests,
    );
    expect(session.assertions).toEqual([]);
    await stillAlive(kernel);
  });

  it("survives mutated copies of valid requests", async () => {
    const { session, kernel } = await mounted();
    const rng = new Rng(0x5e_55_10_05);
    for (let round = 0; round < ITERATIONS; round++) {
      const opcode = rng.pick(FUZZ_OPCODES);
      let message: Uint8Array;
      try {
        message = encodeRequest(
          {
            opcode,
            unique: BigInt(round + 1),
            nodeid: FUSE_ROOT_ID,
            body: REQUEST_GENERATORS.get(opcode)!(rng, session.protocol!),
          },
          session.protocol,
        );
      } catch {
        continue;
      }
      // Flip a byte or three, anywhere including the header.
      for (let flip = rng.range(1, 3); flip > 0; flip--) {
        const at = rng.int(message.length);
        message[at] = (message[at]! ^ (1 << rng.int(8))) & 0xff;
      }
      await feed(session, message);
    }
    expect(session.assertions).toEqual([]);
    await stillAlive(kernel);
  });

  it("survives a storm of concurrent requests", async () => {
    const { session, kernel } = await mounted();
    const rng = new Rng(0x5e_55_10_06);
    const messages: Uint8Array[] = [];
    for (let index = 0; index < 400; index++) {
      const opcode = rng.pick(FUZZ_OPCODES);
      try {
        messages.push(
          encodeRequest(
            {
              opcode,
              unique: BigInt(index + 1),
              nodeid: rng.bool(0.75) ? FUSE_ROOT_ID : rng.u64(),
              body: REQUEST_GENERATORS.get(opcode)!(rng, session.protocol!),
            },
            session.protocol,
          ),
        );
      } catch {
        continue;
      }
    }
    // Nothing is awaited in between: this is the shape the kernel actually
    // produces, and the one that finds ordering bugs in the path map.
    const replies = await Promise.all(messages.map((message) => feed(session, message)));
    expect(replies).toHaveLength(messages.length);
    expect(session.assertions).toEqual([]);
    await stillAlive(kernel);
  });
});

describe("resource bounds", () => {
  it("does not allocate what a bogus READ size asks for", async () => {
    const { session, kernel } = await mounted();
    const file = await kernel.create(FUSE_ROOT_ID, "f", 0o102, 0o644);
    // 4 GiB, which would be an OOM rather than a protocol error if the size
    // were taken at face value.
    const data = await kernel.read(file.entry.nodeid, file.open.fh, 0, 0xff_ff_ff_ff);
    expect(data).toHaveLength(0);
    await kernel.release(file.entry.nodeid, file.open.fh);
    expect(session.assertions).toEqual([]);
  });

  it("rejects offsets a JS number cannot hold", async () => {
    const { session, kernel } = await mounted();
    const file = await kernel.create(FUSE_ROOT_ID, "f", 0o102, 0o644);
    await expect(
      kernel.read(file.entry.nodeid, file.open.fh, Number.MAX_SAFE_INTEGER * 4, 16),
    ).rejects.toMatchObject({ code: "EINVAL" });
    expect(session.assertions).toEqual([]);
  });
});

describe("the request the session never sees twice", () => {
  it("keeps no state for a request it dropped", async () => {
    const { session, kernel } = await mounted();
    const before = { ...session.stats };
    expect(await session.handleMessage(new Uint8Array(4))).toBeNull();
    expect(session.stats.dropped).toBe(before.dropped + 1);
    expect(session.stats.replies).toBe(before.replies);
    await stillAlive(kernel);
  });
});
