/**
 * Codec fuzzing.
 *
 * Two invariants, both narrow and both load-bearing.
 *
 * **Only `P9Error` escapes a decoder.** A `RangeError` out of a `DataView`, a
 * `TypeError` from a field that was not there, an allocation blow-up from an
 * unvalidated count — any of those reaches the connection loop as an unhandled
 * throw, and a server that dies on a malformed frame is a mounted filesystem
 * that dies with it. 9P makes this sharper than the other two transports:
 * `size[4]` is the *only* framing there is, so a lying length is not a
 * recoverable hiccup but the difference between a session and a wedge.
 *
 * **What a decoder returns, an encoder reproduces.** Every message round-trips
 * from random values, so a field that is read at the wrong width or in the
 * wrong order shows up here even when both halves are wrong together (the
 * fixtures in `golden.test.ts` are what catch *that*).
 *
 * Deterministic: every case comes from a seeded PRNG, so a failure reproduces.
 */

import { describe, expect, it } from "vitest";
import { P9_HDRSZ, P9_MAXWELEM, P9_TWALK, P9_TWRITE } from "../../src/9p/constants.ts";
import {
  P9DirentPacker,
  P9FrameAssembler,
  decodeMessage,
  decodeMessageAs,
  encodeMessage,
  readDirent,
  readDirents,
  readHeader,
  readRattach,
  readRauth,
  readRgetattr,
  readRgetlock,
  readRlerror,
  readRlock,
  readRlopen,
  readRread,
  readRreaddir,
  readRreadlink,
  readRstatfs,
  readRversion,
  readRwalk,
  readRwrite,
  readRxattrwalk,
  readTattach,
  readTauth,
  readTflush,
  readTfsync,
  readTgetattr,
  readTgetlock,
  readTlcreate,
  readTlink,
  readTlock,
  readTlopen,
  readTmkdir,
  readTmknod,
  readTread,
  readTreaddir,
  readTrename,
  readTrenameat,
  readTsetattr,
  readTsymlink,
  readTunlinkat,
  readTversion,
  readTwalk,
  readTwrite,
  readTxattrcreate,
  readTxattrwalk,
  writeDirent,
  writeRattach,
  writeRauth,
  writeRgetattr,
  writeRgetlock,
  writeRlerror,
  writeRlock,
  writeRlopen,
  writeRread,
  writeRreaddir,
  writeRreadlink,
  writeRstatfs,
  writeRversion,
  writeRwalk,
  writeRwrite,
  writeRxattrwalk,
  writeTattach,
  writeTauth,
  writeTflush,
  writeTfsync,
  writeTgetattr,
  writeTgetlock,
  writeTlcreate,
  writeTlink,
  writeTlock,
  writeTlopen,
  writeTmkdir,
  writeTmknod,
  writeTread,
  writeTreaddir,
  writeTrename,
  writeTrenameat,
  writeTsetattr,
  writeTsymlink,
  writeTunlinkat,
  writeTversion,
  writeTwalk,
  writeTwrite,
  writeTxattrcreate,
  writeTxattrwalk,
  type P9Dirent,
} from "../../src/9p/protocol.ts";
import { P9Error, P9Reader, P9Writer, isP9Error, type P9Qid } from "../../src/9p/wire.ts";
import { Rng } from "../fuse/random.ts";

const ITERATIONS = 3000;

// --- generators -------------------------------------------------------------

/** A pool with multi-byte characters in it: a name is bytes, not characters. */
const ALPHABET = [..."abcdefghijklmnopqrstuvwxyz0123456789._-", "é", "日", "🙂"];

function randomString(rng: Rng, maxLength = 12): string {
  let value = "";
  for (let index = rng.int(maxLength); index > 0; index--) {
    value += rng.pick(ALPHABET);
  }
  return value;
}

function randomQid(rng: Rng): P9Qid {
  return { type: rng.u32() & 0xff, version: rng.u32(), path: rng.u64() };
}

function randomTime(rng: Rng): { sec: bigint; nsec: bigint } {
  return { sec: rng.u64(), nsec: rng.u64() };
}

function randomDirent(rng: Rng): P9Dirent {
  return {
    qid: randomQid(rng),
    offset: rng.u64(),
    type: rng.u32() & 0xff,
    name: randomString(rng),
  };
}

interface RoundTrip {
  readonly name: string;
  readonly type: number;
  /** Build a random message, frame it, decode it, and hand both back. */
  run(rng: Rng): { sent: unknown; received: unknown; frame: Uint8Array };
}

function roundTrip<T>(
  name: string,
  type: number,
  make: (rng: Rng) => T,
  write: (writer: P9Writer, message: T) => void,
  read: (reader: P9Reader) => T,
): RoundTrip {
  return {
    name,
    type,
    run(rng) {
      const sent = make(rng);
      const frame = encodeMessage(
        type,
        rng.u16(),
        (writer) => write(writer, sent),
        rng.range(8, 64),
      );
      return { sent, received: decodeMessageAs(frame, read).value, frame };
    },
  };
}

const ROUND_TRIPS: RoundTrip[] = [
  roundTrip(
    "Tversion",
    100,
    (rng) => ({ msize: rng.u32(), version: randomString(rng) }),
    writeTversion,
    readTversion,
  ),
  roundTrip(
    "Rversion",
    101,
    (rng) => ({ msize: rng.u32(), version: randomString(rng) }),
    writeRversion,
    readRversion,
  ),
  roundTrip(
    "Tauth",
    102,
    (rng) => ({
      afid: rng.u32(),
      uname: randomString(rng),
      aname: randomString(rng),
      nUname: rng.u32(),
    }),
    writeTauth,
    readTauth,
  ),
  roundTrip("Rauth", 103, (rng) => ({ aqid: randomQid(rng) }), writeRauth, readRauth),
  roundTrip(
    "Tattach",
    104,
    (rng) => ({
      fid: rng.u32(),
      afid: rng.u32(),
      uname: randomString(rng),
      aname: randomString(rng),
      nUname: rng.u32(),
    }),
    writeTattach,
    readTattach,
  ),
  roundTrip("Rattach", 105, (rng) => ({ qid: randomQid(rng) }), writeRattach, readRattach),
  roundTrip("Rlerror", 7, (rng) => ({ ecode: rng.u32() }), writeRlerror, readRlerror),
  roundTrip("Tflush", 108, (rng) => ({ oldtag: rng.u16() }), writeTflush, readTflush),
  roundTrip(
    "Twalk",
    P9_TWALK,
    (rng) => ({
      fid: rng.u32(),
      newfid: rng.u32(),
      wnames: Array.from({ length: rng.int(P9_MAXWELEM + 1) }, () => randomString(rng)),
    }),
    writeTwalk,
    readTwalk,
  ),
  roundTrip(
    "Rwalk",
    111,
    (rng) => ({
      wqids: Array.from({ length: rng.int(P9_MAXWELEM + 1) }, () => randomQid(rng)),
    }),
    writeRwalk,
    readRwalk,
  ),
  roundTrip(
    "Tread",
    116,
    (rng) => ({ fid: rng.u32(), offset: rng.u64(), count: rng.u32() }),
    writeTread,
    readTread,
  ),
  roundTrip(
    "Rread",
    117,
    (rng) => ({ data: rng.bytes(rng.int(256)) }),
    writeRread,
    (reader) => readRread(reader),
  ),
  roundTrip(
    "Twrite",
    P9_TWRITE,
    (rng) => ({ fid: rng.u32(), offset: rng.u64(), data: rng.bytes(rng.int(256)) }),
    writeTwrite,
    (reader) => readTwrite(reader),
  ),
  roundTrip("Rwrite", 119, (rng) => ({ count: rng.u32() }), writeRwrite, readRwrite),
  roundTrip(
    "Rstatfs",
    9,
    (rng) => ({
      type: rng.u32(),
      bsize: rng.u32(),
      blocks: rng.u64(),
      bfree: rng.u64(),
      bavail: rng.u64(),
      files: rng.u64(),
      ffree: rng.u64(),
      fsid: rng.u64(),
      namelen: rng.u32(),
    }),
    writeRstatfs,
    readRstatfs,
  ),
  roundTrip("Tlopen", 12, (rng) => ({ fid: rng.u32(), flags: rng.u32() }), writeTlopen, readTlopen),
  roundTrip(
    "Rlopen",
    13,
    (rng) => ({ qid: randomQid(rng), iounit: rng.u32() }),
    writeRlopen,
    readRlopen,
  ),
  roundTrip(
    "Tlcreate",
    14,
    (rng) => ({
      fid: rng.u32(),
      name: randomString(rng),
      flags: rng.u32(),
      mode: rng.u32(),
      gid: rng.u32(),
    }),
    writeTlcreate,
    readTlcreate,
  ),
  roundTrip(
    "Tsymlink",
    16,
    (rng) => ({
      dfid: rng.u32(),
      name: randomString(rng),
      symtgt: randomString(rng, 32),
      gid: rng.u32(),
    }),
    writeTsymlink,
    readTsymlink,
  ),
  roundTrip(
    "Tmknod",
    18,
    (rng) => ({
      dfid: rng.u32(),
      name: randomString(rng),
      mode: rng.u32(),
      major: rng.u32(),
      minor: rng.u32(),
      gid: rng.u32(),
    }),
    writeTmknod,
    readTmknod,
  ),
  roundTrip(
    "Trename",
    20,
    (rng) => ({ fid: rng.u32(), dfid: rng.u32(), name: randomString(rng) }),
    writeTrename,
    readTrename,
  ),
  roundTrip(
    "Rreadlink",
    23,
    (rng) => ({ target: randomString(rng, 40) }),
    writeRreadlink,
    readRreadlink,
  ),
  roundTrip(
    "Tgetattr",
    24,
    (rng) => ({ fid: rng.u32(), requestMask: rng.u64() }),
    writeTgetattr,
    readTgetattr,
  ),
  roundTrip(
    "Rgetattr",
    25,
    (rng) => ({
      valid: rng.u64(),
      qid: randomQid(rng),
      mode: rng.u32(),
      uid: rng.u32(),
      gid: rng.u32(),
      nlink: rng.u64(),
      rdev: rng.u64(),
      size: rng.u64(),
      blksize: rng.u64(),
      blocks: rng.u64(),
      atime: randomTime(rng),
      mtime: randomTime(rng),
      ctime: randomTime(rng),
      btime: randomTime(rng),
      gen: rng.u64(),
      dataVersion: rng.u64(),
    }),
    writeRgetattr,
    readRgetattr,
  ),
  roundTrip(
    "Tsetattr",
    26,
    (rng) => ({
      fid: rng.u32(),
      valid: rng.u32(),
      mode: rng.u32(),
      uid: rng.u32(),
      gid: rng.u32(),
      size: rng.u64(),
      atime: randomTime(rng),
      mtime: randomTime(rng),
    }),
    writeTsetattr,
    readTsetattr,
  ),
  roundTrip(
    "Txattrwalk",
    30,
    (rng) => ({ fid: rng.u32(), newfid: rng.u32(), name: randomString(rng, 24) }),
    writeTxattrwalk,
    readTxattrwalk,
  ),
  roundTrip("Rxattrwalk", 31, (rng) => ({ size: rng.u64() }), writeRxattrwalk, readRxattrwalk),
  roundTrip(
    "Txattrcreate",
    32,
    (rng) => ({
      fid: rng.u32(),
      name: randomString(rng, 24),
      attrSize: rng.u64(),
      flags: rng.u32(),
    }),
    writeTxattrcreate,
    readTxattrcreate,
  ),
  roundTrip(
    "Treaddir",
    40,
    (rng) => ({ fid: rng.u32(), offset: rng.u64(), count: rng.u32() }),
    writeTreaddir,
    readTreaddir,
  ),
  roundTrip(
    "Rreaddir",
    41,
    (rng) => {
      const packer = new P9DirentPacker(rng.range(0, 512));
      for (let index = rng.int(8); index > 0; index--) {
        packer.add(randomDirent(rng));
      }
      return { data: packer.bytes() };
    },
    writeRreaddir,
    (reader) => readRreaddir(reader),
  ),
  roundTrip(
    "Tfsync",
    50,
    (rng) => ({ fid: rng.u32(), datasync: rng.u32() }),
    writeTfsync,
    readTfsync,
  ),
  roundTrip(
    "Tlock",
    52,
    (rng) => ({
      fid: rng.u32(),
      type: rng.u32() & 0xff,
      flags: rng.u32(),
      start: rng.u64(),
      length: rng.u64(),
      procId: rng.u32(),
      clientId: randomString(rng),
    }),
    writeTlock,
    readTlock,
  ),
  roundTrip("Rlock", 53, (rng) => ({ status: rng.u32() & 0xff }), writeRlock, readRlock),
  roundTrip(
    "Tgetlock",
    54,
    (rng) => ({
      fid: rng.u32(),
      type: rng.u32() & 0xff,
      start: rng.u64(),
      length: rng.u64(),
      procId: rng.u32(),
      clientId: randomString(rng),
    }),
    writeTgetlock,
    readTgetlock,
  ),
  roundTrip(
    "Rgetlock",
    55,
    (rng) => ({
      type: rng.u32() & 0xff,
      start: rng.u64(),
      length: rng.u64(),
      procId: rng.u32(),
      clientId: randomString(rng),
    }),
    writeRgetlock,
    readRgetlock,
  ),
  roundTrip(
    "Tlink",
    70,
    (rng) => ({ dfid: rng.u32(), fid: rng.u32(), name: randomString(rng) }),
    writeTlink,
    readTlink,
  ),
  roundTrip(
    "Tmkdir",
    72,
    (rng) => ({ dfid: rng.u32(), name: randomString(rng), mode: rng.u32(), gid: rng.u32() }),
    writeTmkdir,
    readTmkdir,
  ),
  roundTrip(
    "Trenameat",
    74,
    (rng) => ({
      olddirfid: rng.u32(),
      oldname: randomString(rng),
      newdirfid: rng.u32(),
      newname: randomString(rng),
    }),
    writeTrenameat,
    readTrenameat,
  ),
  roundTrip(
    "Tunlinkat",
    76,
    (rng) => ({ dirfid: rng.u32(), name: randomString(rng), flags: rng.u32() }),
    writeTunlinkat,
    readTunlinkat,
  ),
];

/** Every body decoder, by name, so a failure says which one. */
const DECODERS: [string, (reader: P9Reader) => unknown][] = [
  ["readHeader", readHeader],
  ["readTversion", readTversion],
  ["readRversion", readRversion],
  ["readTauth", readTauth],
  ["readRauth", readRauth],
  ["readTattach", readTattach],
  ["readRattach", readRattach],
  ["readRlerror", readRlerror],
  ["readTflush", readTflush],
  ["readTwalk", readTwalk],
  ["readRwalk", readRwalk],
  ["readTread", readTread],
  ["readRread", (reader) => readRread(reader)],
  ["readTwrite", (reader) => readTwrite(reader)],
  ["readRwrite", readRwrite],
  ["readRstatfs", readRstatfs],
  ["readTlopen", readTlopen],
  ["readRlopen", readRlopen],
  ["readTlcreate", readTlcreate],
  ["readTsymlink", readTsymlink],
  ["readTmknod", readTmknod],
  ["readTrename", readTrename],
  ["readRreadlink", readRreadlink],
  ["readTgetattr", readTgetattr],
  ["readRgetattr", readRgetattr],
  ["readTsetattr", readTsetattr],
  ["readTxattrwalk", readTxattrwalk],
  ["readRxattrwalk", readRxattrwalk],
  ["readTxattrcreate", readTxattrcreate],
  ["readTreaddir", readTreaddir],
  ["readRreaddir", (reader) => readRreaddir(reader)],
  ["readTfsync", readTfsync],
  ["readTlock", readTlock],
  ["readRlock", readRlock],
  ["readTgetlock", readTgetlock],
  ["readRgetlock", readRgetlock],
  ["readTlink", readTlink],
  ["readTmkdir", readTmkdir],
  ["readTrenameat", readTrenameat],
  ["readTunlinkat", readTunlinkat],
  ["readDirent", readDirent],
];

/** Run `decode` and insist any failure is a `P9Error`. Returns whether it succeeded. */
function onlyP9Errors(what: string, decode: () => unknown): boolean {
  try {
    decode();
    return true;
  } catch (error) {
    if (isP9Error(error)) {
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

// --- the suites -------------------------------------------------------------

describe("random values", () => {
  it("round-trips every message through a frame", () => {
    const rng = new Rng(0x9d_00_01);
    for (let round = 0; round < ITERATIONS; round++) {
      const message = ROUND_TRIPS[rng.int(ROUND_TRIPS.length)]!;
      const { sent, received, frame } = message.run(rng);
      expect(received, message.name).toEqual(sent);
      // And the frame it produced describes itself correctly.
      expect(decodeMessage(frame).size, message.name).toBe(frame.byteLength);
    }
  });

  it("round-trips packed dirents", () => {
    const rng = new Rng(0x9d_00_02);
    for (let round = 0; round < 500; round++) {
      const entries: P9Dirent[] = [];
      const writer = new P9Writer(16);
      for (let index = rng.range(1, 12); index > 0; index--) {
        const entry = randomDirent(rng);
        entries.push(entry);
        writeDirent(writer, entry);
      }
      expect(readDirents(writer.bytes())).toEqual(entries);
    }
  });
});

describe("random bytes", () => {
  it("never escapes a non-P9Error from any body decoder", () => {
    const rng = new Rng(0x9d_00_03);
    let decoded = 0;
    for (let round = 0; round < ITERATIONS; round++) {
      const [name, decode] = DECODERS[rng.int(DECODERS.length)]!;
      const bytes = rng.bytes(rng.int(200));
      if (
        onlyP9Errors(`${name}(${bytes.length} random bytes)`, () => decode(new P9Reader(bytes)))
      ) {
        decoded++;
      }
    }
    // Some are valid by luck, which is the fuzzer reaching past the first
    // length check and into the struct bodies.
    expect(decoded).toBeGreaterThan(0);
  });

  it("never escapes a non-P9Error from the framing", () => {
    const rng = new Rng(0x9d_00_04);
    for (let round = 0; round < ITERATIONS; round++) {
      const bytes = rng.bytes(rng.int(64));
      onlyP9Errors("decodeMessage", () => decodeMessage(bytes));
      onlyP9Errors("decodeMessageAs", () => decodeMessageAs(bytes, readTwalk));
    }
  });

  it("never escapes a non-P9Error from the frame assembler", () => {
    const rng = new Rng(0x9d_00_05);
    for (let round = 0; round < ITERATIONS; round++) {
      const assembler = new P9FrameAssembler(1 << 16);
      onlyP9Errors("P9FrameAssembler", () => {
        // Two deliveries, because a reassembler's interesting states are the
        // ones that span a boundary.
        assembler.push(rng.bytes(rng.int(48)));
        assembler.push(rng.bytes(rng.int(48)));
      });
    }
  });

  it("never escapes a non-P9Error from a mutated or truncated frame", () => {
    const rng = new Rng(0x9d_00_06);
    let decoded = 0;
    for (let round = 0; round < ITERATIONS; round++) {
      const message = ROUND_TRIPS[rng.int(ROUND_TRIPS.length)]!;
      const { frame } = message.run(rng);
      if (rng.bool()) {
        mutate(rng, frame);
        if (onlyP9Errors(`${message.name}(mutated)`, () => decodeMessage(frame))) {
          decoded++;
        }
      } else {
        const cut = frame.subarray(0, rng.int(frame.length + 1));
        onlyP9Errors(`${message.name}(truncated)`, () => decodeMessage(cut));
      }
    }
    // A few flipped bytes usually leave a frame that still parses, which is the
    // case that reaches deepest.
    expect(decoded).toBeGreaterThan(0);
  });
});

describe("hostile frames", () => {
  const body = (frame: Uint8Array): Uint8Array => frame.subarray(P9_HDRSZ);

  it("refuses a size field that lies in either direction", () => {
    const frame = encodeMessage(P9_TWRITE, 1, (writer) => {
      writeTwrite(writer, { fid: 1, offset: 0n, data: new Uint8Array(16) });
    });
    for (const lie of [
      0,
      1,
      P9_HDRSZ - 1,
      frame.byteLength - 1,
      frame.byteLength + 1,
      0xff_ff_ff_ff,
    ]) {
      const forged = Uint8Array.prototype.slice.call(frame);
      new DataView(forged.buffer).setUint32(0, lie, true);
      expect(() => decodeMessage(forged), `size = ${lie}`).toThrow(P9Error);
    }
  });

  it("refuses a payload count larger than the frame that carries it", () => {
    const frame = encodeMessage(P9_TWRITE, 1, (writer) => {
      writeTwrite(writer, { fid: 1, offset: 0n, data: new Uint8Array(8) });
    });
    // The count sits after fid[4] offset[8]; claim 4 GiB of payload behind it.
    new DataView(body(frame).buffer, body(frame).byteOffset).setUint32(12, 0xff_ff_ff_ff, true);
    expect(() => decodeMessageAs(frame, (reader) => readTwrite(reader))).toThrow(P9Error);
  });

  it("refuses nwname over P9_MAXWELEM before allocating for it", () => {
    for (const count of [P9_MAXWELEM + 1, 0x0f_ff, 0xff_ff]) {
      const forged = encodeMessage(P9_TWALK, 1, (writer) => {
        writer.u32(1);
        writer.u32(2);
        writer.u16(count);
      });
      expect(() => decodeMessageAs(forged, readTwalk), `nwname = ${count}`).toThrow(P9Error);
    }
  });

  it("refuses nwqid over P9_MAXWELEM", () => {
    const forged = encodeMessage(111, 1, (writer) => writer.u16(0xff_ff));
    expect(() => decodeMessageAs(forged, readRwalk)).toThrow(P9Error);
  });

  it("refuses a string whose count runs past the frame", () => {
    const forged = encodeMessage(23, 1, (writer) => {
      writer.u16(0xff_ff);
      writer.raw(new TextEncoder().encode("short"));
    });
    expect(() => decodeMessageAs(forged, readRreadlink)).toThrow(P9Error);
  });

  it("refuses to encode a string the 16-bit count cannot describe", () => {
    // Not a truncation: writing it would produce a frame whose `size` and whose
    // contents disagree, which is unrecoverable rather than merely wrong.
    expect(() =>
      encodeMessage(23, 1, (writer) => writeRreadlink(writer, { target: "x".repeat(70_000) })),
    ).toThrow(P9Error);
  });
});

describe("the frame assembler", () => {
  it("reassembles anything it accepts back into the original frames", () => {
    const rng = new Rng(0x9d_00_07);
    for (let round = 0; round < 400; round++) {
      const frames: Uint8Array[] = [];
      let total = 0;
      for (let index = rng.range(1, 5); index > 0; index--) {
        const message = ROUND_TRIPS[rng.int(ROUND_TRIPS.length)]!;
        const frame = message.run(rng).frame;
        frames.push(frame);
        total += frame.byteLength;
      }
      const stream = new Uint8Array(total);
      let at = 0;
      for (const frame of frames) {
        stream.set(frame, at);
        at += frame.byteLength;
      }

      const assembler = new P9FrameAssembler();
      const out: Uint8Array[] = [];
      // Delivered in random-sized pieces, which is what a socket does.
      for (let cursor = 0; cursor < stream.length;) {
        const width = rng.range(1, 40);
        out.push(...assembler.push(stream.subarray(cursor, cursor + width)));
        cursor += width;
      }
      expect(assembler.pending).toBe(0);
      expect(out.map((frame) => [...frame])).toEqual(frames.map((frame) => [...frame]));
    }
  });

  it("hands out copies, whatever the caller does with its buffer afterwards", () => {
    const rng = new Rng(0x9d_00_08);
    for (let round = 0; round < 200; round++) {
      const message = ROUND_TRIPS[rng.int(ROUND_TRIPS.length)]!;
      const frame = message.run(rng).frame;
      const expected = [...frame];
      const assembler = new P9FrameAssembler();
      // Split so that the assembler both buffers a partial frame and completes
      // one, then overwrite everything it was shown.
      const cut = rng.range(1, Math.max(1, frame.byteLength - 1));
      const head = Uint8Array.prototype.slice.call(frame, 0, cut);
      const tail = Uint8Array.prototype.slice.call(frame, cut);
      expect(assembler.push(head)).toEqual([]);
      const out = assembler.push(tail);
      head.fill(0xff);
      tail.fill(0xff);
      expect(out).toHaveLength(1);
      expect([...out[0]!], message.name).toEqual(expected);
    }
  });

  it("refuses an oversized size field without buffering the bytes behind it", () => {
    const assembler = new P9FrameAssembler(4096);
    const hostile = new Uint8Array(P9_HDRSZ);
    new DataView(hostile.buffer).setUint32(0, 0xff_ff_ff_ff, true);
    expect(() => assembler.push(hostile)).toThrow(P9Error);
    expect(assembler.pending).toBe(0);
  });

  it("refuses a size below the header, at any point in the stream", () => {
    const assembler = new P9FrameAssembler();
    const good = encodeMessage(P9_TWALK, 1, (writer) => {
      writeTwalk(writer, { fid: 1, newfid: 2, wnames: ["a"] });
    });
    const runt = new Uint8Array(P9_HDRSZ);
    new DataView(runt.buffer).setUint32(0, 3, true);
    const stream = new Uint8Array(good.byteLength + runt.byteLength);
    stream.set(good);
    stream.set(runt, good.byteLength);
    expect(() => assembler.push(stream)).toThrow(P9Error);
  });
});
