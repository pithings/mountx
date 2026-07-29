/**
 * Decoder fuzzing.
 *
 * The invariant is narrow and load-bearing, and it is the same one the FUSE
 * side fuzzes: **only `XdrError` escapes a decoder.** Anything else — a
 * `RangeError` out of a `DataView`, an allocation blow-up from an unvalidated
 * count, a `TypeError` from a field that was not there — reaches the socket
 * loop as an unhandled throw, and a server that dies on a malformed packet is a
 * mounted filesystem that dies with it.
 *
 * A second invariant covers the layer above: `NfsSession.handleCall` **never
 * rejects**, whatever bytes it is given. Every request either gets a reply or
 * is dropped for want of an xid.
 *
 * Deterministic: every case comes from a seeded PRNG, so a failure reproduces.
 */

import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../../src/drivers/memory.ts";
import { MOUNT_PROGRAM, MOUNT_V3, NFS_PROGRAM, NFS_V3 } from "../../../src/nfs/v3/constants.ts";
import {
  decodeAuthSys,
  decodeCall,
  decodeReply,
  encodeCall,
  frameFragments,
  RecordAssembler,
} from "../../../src/nfs/rpc.ts";
import {
  readAccessArgs,
  readAccessRes,
  readCommitArgs,
  readCommitRes,
  readCreateArgs,
  readCreateRes,
  readDirOp,
  readExportList,
  readFsinfoRes,
  readFsstatRes,
  readGetattrRes,
  readLinkArgs,
  readLinkRes,
  readLookupRes,
  readMkdirArgs,
  readMknodArgs,
  readMountList,
  readMountRes,
  readPathconfRes,
  readReadArgs,
  readReaddirArgs,
  readReaddirRes,
  readReaddirplusArgs,
  readReaddirplusRes,
  readReadRes,
  readReadlinkRes,
  readRenameArgs,
  readRenameRes,
  readSattr,
  readSetattrArgs,
  readSymlinkArgs,
  readWccRes,
  readWriteArgs,
  readWriteRes,
} from "../../../src/nfs/v3/protocol.ts";
import { NfsSession } from "../../../src/nfs/session.ts";
import { isXdrError, XdrReader } from "../../../src/nfs/xdr.ts";
import { Rng } from "../../fuse/random.ts";

const ITERATIONS = 3000;

/** Every argument/result decoder, by name, so a failure says which one. */
const DECODERS: [string, (reader: XdrReader) => unknown][] = [
  ["readDirOp", readDirOp],
  ["readSattr", readSattr],
  ["readSetattrArgs", readSetattrArgs],
  ["readAccessArgs", readAccessArgs],
  ["readReadArgs", readReadArgs],
  ["readWriteArgs", (reader) => readWriteArgs(reader)],
  ["readCreateArgs", readCreateArgs],
  ["readMkdirArgs", readMkdirArgs],
  ["readSymlinkArgs", readSymlinkArgs],
  ["readMknodArgs", readMknodArgs],
  ["readRenameArgs", readRenameArgs],
  ["readLinkArgs", readLinkArgs],
  ["readReaddirArgs", readReaddirArgs],
  ["readReaddirplusArgs", readReaddirplusArgs],
  ["readCommitArgs", readCommitArgs],
  ["readGetattrRes", readGetattrRes],
  ["readWccRes", readWccRes],
  ["readLookupRes", readLookupRes],
  ["readAccessRes", readAccessRes],
  ["readReadlinkRes", readReadlinkRes],
  ["readReadRes", (reader) => readReadRes(reader)],
  ["readWriteRes", readWriteRes],
  ["readCreateRes", readCreateRes],
  ["readRenameRes", readRenameRes],
  ["readLinkRes", readLinkRes],
  ["readReaddirRes", readReaddirRes],
  ["readReaddirplusRes", readReaddirplusRes],
  ["readFsstatRes", readFsstatRes],
  ["readFsinfoRes", readFsinfoRes],
  ["readPathconfRes", readPathconfRes],
  ["readCommitRes", readCommitRes],
  ["readMountRes", readMountRes],
  ["readMountList", readMountList],
  ["readExportList", readExportList],
];

/** Run `decode` and insist any failure is an `XdrError`. Returns whether it succeeded. */
function onlyXdrErrors(what: string, decode: () => unknown): boolean {
  try {
    decode();
    return true;
  } catch (error) {
    if (isXdrError(error)) {
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

function mutate(rng: Rng, bytes: Uint8Array): void {
  const edits = rng.range(1, 4);
  for (let index = 0; index < edits && bytes.length > 0; index++) {
    bytes[rng.int(bytes.length)] = rng.u32() & 0xff;
  }
}

describe("random bytes", () => {
  it("never escapes a non-XdrError from any struct decoder", () => {
    const rng = new Rng(0xbeef01);
    let decoded = 0;
    for (let round = 0; round < ITERATIONS; round++) {
      const [name, decode] = DECODERS[rng.int(DECODERS.length)]!;
      const bytes = rng.bytes(rng.int(200));
      if (
        onlyXdrErrors(`${name}(${bytes.length} random bytes)`, () => decode(new XdrReader(bytes)))
      ) {
        decoded++;
      }
    }
    // Some of these are valid by luck — the fuzzer is reaching past the first
    // length check and into the struct bodies.
    expect(decoded).toBeGreaterThan(0);
  });

  it("never escapes a non-XdrError from the RPC framing", () => {
    const rng = new Rng(0xbeef02);
    for (let round = 0; round < ITERATIONS; round++) {
      const bytes = rng.bytes(rng.int(120));
      onlyXdrErrors("decodeCall", () => decodeCall(bytes));
      onlyXdrErrors("decodeReply", () => decodeReply(bytes));
      onlyXdrErrors("decodeAuthSys", () => decodeAuthSys(bytes));
    }
  });

  it("never escapes a non-XdrError from the record assembler", () => {
    const rng = new Rng(0xbeef03);
    for (let round = 0; round < ITERATIONS; round++) {
      const assembler = new RecordAssembler(1 << 16);
      onlyXdrErrors("RecordAssembler", () => {
        // Two chunks, because a reassembler's interesting states are the ones
        // that span a delivery boundary.
        assembler.push(rng.bytes(rng.int(48)));
        assembler.push(rng.bytes(rng.int(48)));
      });
    }
  });

  it("reassembles anything it accepts back into the original bytes", () => {
    const rng = new Rng(0xbeef04);
    for (let round = 0; round < 500; round++) {
      const message = rng.bytes(rng.int(300));
      const framed = frameFragments(message, rng.range(1, 32));
      const assembler = new RecordAssembler();
      const out: Uint8Array[] = [];
      // Delivered in random-sized pieces, which is what a socket does.
      for (let at = 0; at < framed.length;) {
        const width = rng.range(1, 40);
        out.push(...assembler.push(framed.subarray(at, at + width)));
        at += width;
      }
      expect(out).toHaveLength(1);
      expect([...out[0]!]).toEqual([...message]);
    }
  });
});

describe("mutated valid messages", () => {
  it("never escapes a non-XdrError from a mutated or truncated call", () => {
    const rng = new Rng(0xbeef05);
    let decoded = 0;
    for (let round = 0; round < ITERATIONS; round++) {
      const message = encodeCall({
        xid: rng.u32(),
        program: rng.pick([NFS_PROGRAM, MOUNT_PROGRAM, 0]),
        version: rng.pick([NFS_V3, MOUNT_V3, 1]),
        procedure: rng.int(24),
        args: rng.bytes(rng.int(64)),
      });
      if (rng.bool()) {
        mutate(rng, message);
        if (onlyXdrErrors("decodeCall(mutated)", () => decodeCall(message))) {
          decoded++;
        }
      } else {
        const cut = message.subarray(0, rng.int(message.length + 1));
        onlyXdrErrors("decodeCall(truncated)", () => decodeCall(cut));
      }
    }
    // A few flipped bytes usually leave a still-decodable message, which is the
    // case that reaches deepest.
    expect(decoded).toBeGreaterThan(ITERATIONS / 8);
  });
});

describe("the session", () => {
  it("never rejects, whatever bytes arrive", async () => {
    const session = new NfsSession(createMemoryDriver());
    const rng = new Rng(0xbeef06);
    let answered = 0;
    for (let round = 0; round < 600; round++) {
      const record = rng.bool()
        ? rng.bytes(rng.int(160))
        : (() => {
            const message = encodeCall({
              xid: rng.u32() || 1,
              program: rng.pick([NFS_PROGRAM, MOUNT_PROGRAM, 999]),
              version: rng.pick([NFS_V3, 2]),
              procedure: rng.int(24),
              args: rng.bytes(rng.int(80)),
            });
            if (rng.bool()) {
              mutate(rng, message);
            }
            return message;
          })();
      const reply = await session.handleCall(record, { peer: "127.0.0.1" });
      if (reply !== null) {
        answered++;
        // Anything answered is a well-formed RPC reply, whatever it says.
        expect(() => decodeReply(reply)).not.toThrow();
      }
    }
    expect(answered).toBeGreaterThan(0);
    expect(session.stats.requests).toBe(600);
    expect(session.stats.replies + session.stats.dropped).toBe(600);
  });

  it("answers a well-formed call for every procedure number without throwing", async () => {
    const session = new NfsSession(createMemoryDriver());
    const rng = new Rng(0xbeef07);
    for (const program of [NFS_PROGRAM, MOUNT_PROGRAM]) {
      for (let procedure = 0; procedure < 25; procedure++) {
        const reply = await session.handleCall(
          encodeCall({
            xid: procedure + 1,
            program,
            version: 3,
            procedure,
            args: rng.bytes(rng.int(64)),
          }),
        );
        expect(reply).not.toBeNull();
        expect(() => decodeReply(reply!)).not.toThrow();
      }
    }
  });
});
