/**
 * 9P wire primitives.
 *
 * Tier 0: pure data transformation, no socket, no driver. Two invariants run
 * through every case here — a decoder either returns a value or throws
 * `P9Error`, and a decoder never returns a view of the bytes it was handed —
 * plus the byte-exactness the golden fixtures pin down. Every fixture gives
 * each field a distinct value on purpose: a transposed encoder/decoder pair
 * round-trips happily through mirrored values and only an all-distinct fixture
 * catches it.
 */

import { describe, expect, it } from "vitest";
import {
  MESSAGE_NAMES,
  messageName,
  P9_GETATTR_ALL,
  P9_GETATTR_BASIC,
  P9_GETATTR_BLOCKS,
  P9_GETATTR_MODE,
  P9_HDRSZ,
  P9_MAXWELEM,
  P9_NOFID,
  P9_NOTAG,
  P9_QTDIR,
  P9_QTFILE,
  P9_RLERROR,
  P9_SETATTR_MODE,
  P9_SETATTR_MTIME_SET,
  P9_TLERROR,
  P9_TVERSION,
  P9_TWSTAT,
} from "../../src/9p/constants.ts";
import {
  decodeP9,
  encodeP9,
  isP9Error,
  P9_MAX_ITEM,
  P9_MAX_STRING,
  P9_QID_SIZE,
  P9Error,
  P9Reader,
  P9Writer,
  stringByteLength,
} from "../../src/9p/wire.ts";

describe("scalars", () => {
  it("round-trips every width, little-endian, with no padding between them", () => {
    // All-distinct values, and deliberately widths that would align if 9P
    // padded — it does not, so the message is exactly 1 + 2 + 4 + 8 bytes.
    const bytes = encodeP9((writer) => {
      writer.u8(0x12);
      writer.u16(0x34_56);
      writer.u32(0x78_9a_bc_de);
      writer.u64(0x0f_1e_2d_3c_4b_5a_69_78n);
    });
    expect([...bytes]).toEqual([
      0x12, 0x56, 0x34, 0xde, 0xbc, 0x9a, 0x78, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    ]);

    const reader = new P9Reader(bytes);
    expect(reader.u8()).toBe(0x12);
    expect(reader.u16()).toBe(0x34_56);
    expect(reader.u32()).toBe(0x78_9a_bc_de);
    expect(reader.u64()).toBe(0x0f_1e_2d_3c_4b_5a_69_78n);
    reader.end();
  });

  it("keeps the top bit of every width unsigned", () => {
    const bytes = encodeP9((writer) => {
      writer.u8(0xff);
      writer.u16(0xff_fe);
      writer.u32(0xff_ff_ff_fd);
      writer.u64(0xff_ff_ff_ff_ff_ff_ff_fcn);
    });
    const reader = new P9Reader(bytes);
    expect(reader.u8()).toBe(0xff);
    expect(reader.u16()).toBe(0xff_fe);
    expect(reader.u32()).toBe(0xff_ff_ff_fd);
    expect(reader.u64()).toBe(0xff_ff_ff_ff_ff_ff_ff_fcn);
  });

  it("refuses to read past the end, at every width", () => {
    for (const [size, read] of [
      [1, (reader: P9Reader) => reader.u8()],
      [2, (reader: P9Reader) => reader.u16()],
      [4, (reader: P9Reader) => reader.u32()],
      [8, (reader: P9Reader) => reader.u64()],
    ] as const) {
      // One byte short of the width, every time.
      const reader = new P9Reader(new Uint8Array(size - 1));
      expect(() => read(reader)).toThrow(P9Error);
      // A failed read consumes nothing, so the next one fails the same way.
      expect(reader.offset).toBe(0);
    }
  });

  it("reports the offset it failed at", () => {
    const reader = new P9Reader(new Uint8Array(8));
    reader.u32();
    try {
      reader.u64();
      expect.unreachable();
    } catch (error) {
      expect(isP9Error(error)).toBe(true);
      expect((error as P9Error).offset).toBe(4);
      expect((error as P9Error).code).toBe("ERR_9P_WIRE");
    }
  });

  it("tracks how much is left", () => {
    const reader = new P9Reader(new Uint8Array(3));
    expect(reader.remaining).toBe(3);
    expect(reader.atEnd).toBe(false);
    reader.u16();
    expect(reader.remaining).toBe(1);
    reader.u8();
    expect(reader.atEnd).toBe(true);
  });
});

describe("strings", () => {
  it("writes a u16 byte count and nothing else — no padding, no terminator", () => {
    const bytes = encodeP9((writer) => writer.string("mnt"));
    expect([...bytes]).toEqual([0x03, 0x00, 0x6d, 0x6e, 0x74]);
    expect(decodeP9(bytes, (reader) => reader.string())).toBe("mnt");
  });

  it("counts bytes rather than characters", () => {
    // Five characters, seven UTF-8 bytes.
    const value = "héllø";
    expect(value.length).toBe(5);
    expect(stringByteLength(value)).toBe(7);
    const bytes = encodeP9((writer) => writer.string(value));
    expect(bytes.byteLength).toBe(2 + 7);
    expect(new DataView(bytes.buffer).getUint16(0, true)).toBe(7);
    expect(decodeP9(bytes, (reader) => reader.string())).toBe(value);
  });

  it("round-trips strings of every shape", () => {
    for (const value of ["", "a", "..", "héllo→ø", "x".repeat(1000)]) {
      expect(
        decodeP9(
          encodeP9((writer) => writer.string(value)),
          (reader) => reader.string(),
        ),
      ).toBe(value);
    }
  });

  it("decodes invalid UTF-8 lossily rather than throwing", () => {
    // A name that is bytes, not text — which real filesystems allow.
    const bytes = new Uint8Array([0x02, 0x00, 0xff, 0xfe]);
    expect(decodeP9(bytes, (reader) => reader.string())).toBe("��");
  });

  it("refuses a count with fewer bytes behind it than it claims", () => {
    const bytes = new Uint8Array([0x08, 0x00, 0x61, 0x62]);
    expect(() => decodeP9(bytes, (reader) => reader.string())).toThrow(P9Error);
  });

  it("refuses a string longer than the caller's limit", () => {
    const bytes = encodeP9((writer) => writer.string("abcdefgh"));
    expect(() => decodeP9(bytes, (reader) => reader.string(4))).toThrow(P9Error);
  });

  it("refuses to write a string a 16-bit count cannot describe", () => {
    const writer = new P9Writer();
    expect(() => writer.string("x".repeat(P9_MAX_STRING + 1))).toThrow(P9Error);
    // …and 65535 bytes exactly is fine.
    expect(() => new P9Writer().string("x".repeat(P9_MAX_STRING))).not.toThrow();
  });
});

describe("qids", () => {
  it("is thirteen unaligned bytes, little-endian throughout", () => {
    // Every field distinct, and the type is not the low byte of anything else.
    const qid = { type: P9_QTDIR, version: 0x12_34_56_78, path: 0x01_02_03_04_05_06_07_08n };
    const bytes = encodeP9((writer) => writer.qid(qid));
    expect(bytes.byteLength).toBe(P9_QID_SIZE);
    expect([...bytes]).toEqual([
      0x80, 0x78, 0x56, 0x34, 0x12, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    ]);
    expect(decodeP9(bytes, (reader) => reader.qid())).toEqual(qid);
  });

  it("carries a full 64-bit path", () => {
    const qid = { type: P9_QTFILE, version: 1, path: 0xff_ff_ff_ff_ff_ff_ff_fen };
    expect(
      decodeP9(
        encodeP9((writer) => writer.qid(qid)),
        (reader) => reader.qid(),
      ),
    ).toEqual(qid);
  });

  it("refuses a truncated qid", () => {
    const bytes = encodeP9((writer) => writer.qid({ type: 0, version: 0, path: 0n }));
    expect(() => decodeP9(bytes.subarray(0, 12), (reader) => reader.qid())).toThrow(P9Error);
  });
});

describe("byte blobs", () => {
  it("round-trips a counted payload", () => {
    for (const length of [0, 1, 7, 4096]) {
      const value = new Uint8Array(length).map((_, index) => (index * 7 + 3) & 0xff);
      const bytes = encodeP9((writer) => writer.blob(value));
      expect(bytes.byteLength).toBe(4 + length);
      expect([...decodeP9(bytes, (reader) => reader.blob())]).toEqual([...value]);
    }
  });

  it("refuses a count larger than the bytes behind it", () => {
    // Four bytes saying 4 GiB, with nothing after them.
    const bytes = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
    expect(() => decodeP9(bytes, (reader) => reader.blob(P9_MAX_ITEM))).toThrow(P9Error);
  });

  it("refuses a count over the caller's limit before allocating anything", () => {
    const bytes = encodeP9((writer) => writer.blob(new Uint8Array(64)));
    expect(() => decodeP9(bytes, (reader) => reader.blob(16))).toThrow(P9Error);
  });

  it("reads a fixed count and then the rest", () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const reader = new P9Reader(bytes);
    expect([...reader.raw(2)]).toEqual([1, 2]);
    expect([...reader.rest()]).toEqual([3, 4, 5]);
    expect(reader.atEnd).toBe(true);
    expect([...reader.rest()]).toEqual([]);
  });
});

describe("copy semantics", () => {
  it("copies, even out of a Buffer whose `slice` does not", () => {
    // `Buffer.prototype.slice` **is `subarray`** — it returns a view. A decoder
    // that used it would hand a driver a window onto the connection's read
    // buffer to keep, which is the exact trap that corrupted the first FUSE
    // transcripts (`src/fuse/record.ts`) and an NFS `WRITE` payload after it.
    const source = Buffer.from(
      encodeP9((writer) => {
        writer.blob(new Uint8Array([1, 2, 3, 4, 5]));
        writer.raw(new Uint8Array([6, 7]));
        writer.raw(new Uint8Array([8, 9, 10]));
      }),
    );
    // Sanity: this really is the aliasing kind of `slice`.
    expect(source.slice(0, 4).buffer).toBe(source.buffer);

    const reader = new P9Reader(source);
    const counted = reader.blob();
    const fixed = reader.raw(2);
    const rest = reader.rest();
    source.fill(0xee);

    expect([...counted]).toEqual([1, 2, 3, 4, 5]);
    expect([...fixed]).toEqual([6, 7]);
    expect([...rest]).toEqual([8, 9, 10]);
    for (const decoded of [counted, fixed, rest]) {
      expect(decoded.buffer).not.toBe(source.buffer);
    }
  });

  it("copies a string's bytes too", () => {
    const source = Buffer.from(encodeP9((writer) => writer.string("keep me")));
    const decoded = new P9Reader(source).string();
    source.fill(0);
    expect(decoded).toBe("keep me");
  });

  it("copies what the writer emits, so a later write cannot alter it", () => {
    const writer = new P9Writer();
    writer.u32(0xaa_bb_cc_dd);
    const first = writer.bytes();
    writer.u32(0x11_22_33_44);
    expect(first.byteLength).toBe(4);
    expect(writer.bytes().byteLength).toBe(8);
    expect([...first]).toEqual([0xdd, 0xcc, 0xbb, 0xaa]);
  });
});

describe("golden fixtures", () => {
  it("encodes a qid, a string and a u64 to exactly these bytes", () => {
    // Every field distinct, including every byte of the qid path and of the
    // trailing u64: a fixture built from repeated or mirrored values passes
    // even with the encoder and decoder fields transposed.
    const qid = { type: P9_QTDIR, version: 0x9a_bc_de_f0, path: 0x11_22_33_44_55_66_77_88n };
    const name = "mountx";
    const offset = 0x01_23_45_67_89_ab_cd_efn;

    const bytes = encodeP9((writer) => {
      writer.qid(qid);
      writer.string(name);
      writer.u64(offset);
    });

    expect([...bytes]).toEqual([
      // qid.type
      0x80,
      // qid.version, little-endian
      0xf0, 0xde, 0xbc, 0x9a,
      // qid.path, little-endian
      0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      // "mountx": count[2] then the bytes, no terminator
      0x06, 0x00, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x78,
      // offset, little-endian
      0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    ]);
    expect(bytes.byteLength).toBe(P9_QID_SIZE + 2 + 6 + 8);

    const decoded = decodeP9(bytes, (reader) => ({
      qid: reader.qid(),
      name: reader.string(),
      offset: reader.u64(),
    }));
    expect(decoded).toEqual({ qid, name, offset });
  });

  it("encodes a message header to exactly these bytes", () => {
    // `size[4] type[1] tag[2]` — the seven bytes every 9P message starts with,
    // all three fields distinct.
    const bytes = encodeP9((writer) => {
      writer.u32(0x00_00_00_13);
      writer.u8(P9_TVERSION);
      writer.u16(0x5a_a5);
    });
    expect([...bytes]).toEqual([0x13, 0x00, 0x00, 0x00, 100, 0xa5, 0x5a]);
    expect(bytes.byteLength).toBe(P9_HDRSZ);
  });

  it("patches a size in after the fact, which is how a framer works", () => {
    const writer = new P9Writer();
    writer.u32(0); // size, unknown until the body is written
    writer.u8(P9_RLERROR);
    writer.u16(0x0b_0c);
    writer.u32(2); // ecode: ENOENT
    writer.patchU32(0, writer.length);
    expect([...writer.bytes()]).toEqual([
      0x0b, 0x00, 0x00, 0x00, 7, 0x0c, 0x0b, 0x02, 0x00, 0x00, 0x00,
    ]);
    expect(() => writer.patchU32(writer.length - 2, 0)).toThrow(P9Error);
  });
});

describe("the writer", () => {
  it("grows past its initial capacity", () => {
    const writer = new P9Writer(16);
    for (let index = 0; index < 1000; index++) {
      writer.u32(index);
    }
    expect(writer.length).toBe(4000);
    const reader = new P9Reader(writer.bytes());
    for (let index = 0; index < 1000; index++) {
      expect(reader.u32()).toBe(index);
    }
    reader.end();
  });

  it("grows correctly when a single item is larger than the doubled capacity", () => {
    const writer = new P9Writer(16);
    const payload = new Uint8Array(5000).map((_, index) => index & 0xff);
    writer.u8(0x42);
    writer.blob(payload);
    const reader = new P9Reader(writer.bytes());
    expect(reader.u8()).toBe(0x42);
    expect([...reader.blob()]).toEqual([...payload]);
    reader.end();
  });

  it("insists a message is fully consumed", () => {
    const bytes = encodeP9((writer) => {
      writer.u32(1);
      writer.u32(2);
    });
    expect(() => decodeP9(bytes, (reader) => reader.u32())).toThrow(P9Error);
  });
});

describe("constants", () => {
  it("pairs every request with the reply one above it", () => {
    // The one structural rule of `enum p9_msg_t`: requests are even and
    // `R = T + 1`. A transposed transcription breaks it.
    for (const [value, name] of Object.entries(MESSAGE_NAMES)) {
      const type = Number(value);
      if (!name.startsWith("T")) {
        continue;
      }
      expect(type % 2, name).toBe(0);
      expect(MESSAGE_NAMES[type + 1], name).toBe(`R${name.slice(1)}`);
    }
  });

  it("spans the whole allocated range, legacy 9P2000 included", () => {
    expect(messageName(P9_TLERROR)).toBe("Tlerror");
    expect(messageName(P9_TWSTAT)).toBe("Twstat");
    expect(messageName(0)).toBe("UNKNOWN(0)");
    expect(Object.keys(MESSAGE_NAMES)).toHaveLength(68);
  });

  it("has the magic numbers the header defines", () => {
    expect(P9_NOTAG).toBe(0xff_ff);
    expect(P9_NOFID).toBe(0xff_ff_ff_ff);
    expect(P9_MAXWELEM).toBe(16);
    expect(P9_HDRSZ).toBe(7);
  });

  it("keeps the getattr aggregate masks equal to the bits they aggregate", () => {
    expect(P9_GETATTR_BASIC).toBe((P9_GETATTR_BLOCKS << 1n) - 1n);
    expect(P9_GETATTR_BASIC & P9_GETATTR_MODE).toBe(P9_GETATTR_MODE);
    expect(P9_GETATTR_ALL & P9_GETATTR_BASIC).toBe(P9_GETATTR_BASIC);
    expect(P9_GETATTR_ALL).toBe(0x3f_ffn);
  });

  it("keeps the setattr bits in the 32-bit space, unlike the getattr ones", () => {
    expect(P9_SETATTR_MODE).toBe(1);
    expect(P9_SETATTR_MTIME_SET).toBe(1 << 8);
    expect(typeof P9_SETATTR_MODE).toBe("number");
    expect(typeof P9_GETATTR_MODE).toBe("bigint");
  });
});
