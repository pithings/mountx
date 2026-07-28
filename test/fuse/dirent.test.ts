/**
 * Dirent packing: the size-limited buffer fill the kernel asks for, the
 * resume-from-offset semantics the session layer builds paging on, and the
 * 8-byte alignment that a single wrong byte turns into an unreadable directory.
 */

import { describe, expect, it } from "vitest";
import { DT_DIR, DT_LNK, DT_REG, FUSE_DIRENT_HEADER_SIZE } from "../../src/fuse/constants.ts";
import {
  DirentPacker,
  direntAlign,
  direntPlusSize,
  direntSize,
  direntType,
  entryOutSize,
  packDirents,
  packDirentsPlus,
  ProtocolError,
  unpackDirents,
  unpackDirentsPlus,
} from "../../src/fuse/protocol.ts";
import type { FuseDirent } from "../../src/fuse/protocol.ts";
import { randomDirent, randomDirentPlus, Rng } from "./random.ts";

function dirent(name: string, index: number, type = DT_REG): FuseDirent {
  return { ino: BigInt(index + 2), off: BigInt(index + 1), type, name };
}

describe("sizes and alignment", () => {
  it("rounds records up to 8 bytes", () => {
    expect(direntAlign(0)).toBe(0);
    expect(direntAlign(1)).toBe(8);
    expect(direntAlign(8)).toBe(8);
    expect(direntAlign(9)).toBe(16);
  });

  it("matches FUSE_DIRENT_SIZE", () => {
    // FUSE_NAME_OFFSET is 24; align8(24 + namelen).
    expect(FUSE_DIRENT_HEADER_SIZE).toBe(24);
    expect(direntSize(0)).toBe(24);
    expect(direntSize(1)).toBe(32);
    expect(direntSize(8)).toBe(32);
    expect(direntSize(9)).toBe(40);
    expect(direntSize(255)).toBe(280); // align8(279)
  });

  it("matches FUSE_DIRENTPLUS_SIZE", () => {
    expect(entryOutSize(41)).toBe(128);
    expect(direntPlusSize(1)).toBe(160); // align8(128 + 24 + 1)
    expect(direntPlusSize(8)).toBe(160);
    expect(direntPlusSize(9)).toBe(168);
    expect(direntPlusSize(255)).toBe(408); // align8(407)
    // Older protocols have a 120-byte fuse_entry_out.
    expect(direntPlusSize(1, { minor: 8, setxattrExt: false })).toBe(152);
  });

  it("derives DT_* from a stat mode", () => {
    expect(direntType(0o100_644)).toBe(DT_REG);
    expect(direntType(0o40_755)).toBe(DT_DIR);
    expect(direntType(0o120_777)).toBe(DT_LNK);
  });
});

describe("size-limited fill", () => {
  const names = Array.from({ length: 20 }, (_, index) => `entry-${index}`);

  it("stops when the budget runs out and leaves nothing half-written", () => {
    const entries = names.map((name, index) => dirent(name, index));
    // "entry-0".."entry-9" are 7 bytes, the rest 8; align8(24+7) = align8(24+8) = 32.
    const budget = 32 * 3 + 4;
    const { buffer, packed } = packDirents(entries, budget);
    expect(packed).toBe(3);
    expect(buffer.length).toBe(96);
    expect(buffer.length % 8).toBe(0);
    expect(unpackDirents(buffer).map((entry) => entry.name)).toEqual(names.slice(0, 3));
  });

  it("packs nothing into a zero budget", () => {
    const { buffer, packed } = packDirents([dirent("a", 0)], 0);
    expect(packed).toBe(0);
    expect(buffer.length).toBe(0);
    expect(unpackDirents(buffer)).toEqual([]);
  });

  it("packs nothing when the first entry alone does not fit", () => {
    const packer = new DirentPacker(direntSize(1) - 1);
    expect(packer.add(dirent("a", 0))).toBe(false);
    expect(packer.size).toBe(0);
    expect(packer.count).toBe(0);
    // The rejected entry is still packable into the next, larger buffer.
    const next = new DirentPacker(direntSize(1));
    expect(next.add(dirent("a", 0))).toBe(true);
    expect(next.remaining).toBe(0);
  });

  it("reports remaining budget", () => {
    const packer = new DirentPacker(1024);
    expect(packer.remaining).toBe(1024);
    packer.add(dirent("abc", 0));
    expect(packer.size).toBe(32);
    expect(packer.remaining).toBe(992);
  });

  it("resumes from the offset of the last entry that fit", () => {
    const entries = names.map((name, index) => dirent(name, index));
    const budget = 32 * 4;
    const first = packDirents(entries, budget);
    expect(first.packed).toBe(4);
    const unpacked = unpackDirents(first.buffer);
    // `off` is where to resume *after* this entry, so the next page starts at
    // the last entry's `off`.
    const resume = Number(unpacked.at(-1)?.off);
    expect(resume).toBe(4);
    const second = packDirents(entries.slice(resume), budget);
    expect(unpackDirents(second.buffer).map((entry) => entry.name)).toEqual(names.slice(4, 8));
  });
});

describe("alignment edge cases", () => {
  for (const length of [1, 2, 7, 8, 9, 15, 16, 17, 254, 255]) {
    it(`packs and unpacks a ${length}-character name`, () => {
      const name = "n".repeat(length);
      const entry = dirent(name, 0);
      const { buffer, packed } = packDirents([entry], 4096);
      expect(packed).toBe(1);
      expect(buffer.length).toBe(direntSize(length));
      expect(buffer.length % 8).toBe(0);
      // Padding must be zero — the kernel copies the whole record.
      expect([...buffer.subarray(24 + length)].every((byte) => byte === 0)).toBe(true);
      expect(unpackDirents(buffer)).toEqual([entry]);
    });
  }

  it("counts multi-byte names in bytes", () => {
    // "λ" is 2 bytes, "🙂" is 4: namelen is 6 even though the string is 3 UTF-16
    // code units long.
    const entry = dirent("λ🙂", 0);
    const { buffer } = packDirents([entry], 4096);
    expect(buffer.length).toBe(direntSize(6));
    expect(new DataView(buffer.buffer).getUint32(16, true)).toBe(6);
    expect(unpackDirents(buffer)).toEqual([entry]);
  });

  it("packs a run of names of every length back to back", () => {
    const entries = Array.from({ length: 40 }, (_, index) =>
      dirent("x".repeat(index + 1), index, index % 2 === 0 ? DT_REG : DT_DIR),
    );
    const { buffer, packed } = packDirents(entries, 1 << 20);
    expect(packed).toBe(40);
    expect(buffer.length % 8).toBe(0);
    expect(unpackDirents(buffer)).toEqual(entries);
  });
});

describe("readdirplus", () => {
  it("fills to the budget and round-trips", () => {
    const rng = new Rng(0xd1_4e_47);
    const entries = Array.from({ length: 32 }, () => randomDirentPlus(rng));
    const { buffer, packed } = packDirentsPlus(entries, 2048);
    expect(packed).toBeGreaterThan(0);
    expect(packed).toBeLessThan(32);
    expect(buffer.length).toBeLessThanOrEqual(2048);
    expect(unpackDirentsPlus(buffer)).toEqual(entries.slice(0, packed));
  });

  it("requires a fuse_entry_out", () => {
    const packer = new DirentPacker(4096, { plus: true });
    expect(() => packer.add(dirent("a", 0))).toThrow(ProtocolError);
  });

  it("uses the compat fuse_entry_out on old protocols", () => {
    const rng = new Rng(7);
    const ctx = { minor: 8, setxattrExt: false };
    const entry = randomDirentPlus(rng);
    entry.dirent.name = "ab";
    const { buffer } = packDirentsPlus([entry], 4096, ctx);
    expect(buffer.length).toBe(direntPlusSize(2, ctx));
    const [decoded] = unpackDirentsPlus(buffer, ctx);
    expect(decoded?.dirent).toEqual(entry.dirent);
    expect(decoded?.entry.attr.blksize).toBe(0); // absent before 7.9
  });
});

describe("unpacking is total", () => {
  it("rejects a namelen past the end of the buffer", () => {
    const { buffer } = packDirents([dirent("abc", 0)], 4096);
    new DataView(buffer.buffer).setUint32(16, 0xff_ff, true);
    expect(() => unpackDirents(buffer)).toThrow(ProtocolError);
  });

  it("rejects a truncated record", () => {
    const { buffer } = packDirents([dirent("abcdefgh", 0)], 4096);
    for (let length = 1; length < buffer.length; length++) {
      expect(() => unpackDirents(buffer.subarray(0, length))).toThrow(ProtocolError);
    }
  });

  it("rejects a record whose alignment padding was cut off", () => {
    // 24-byte header + a 1-byte name fits in 25 bytes, but the record is 32:
    // the entry decodes and the padding does not.
    const { buffer } = packDirents([dirent("a", 0)], 4096);
    expect(buffer.length).toBe(32);
    for (let length = 25; length < 32; length++) {
      expect(() => unpackDirents(buffer.subarray(0, length))).toThrow(ProtocolError);
    }
  });

  it("rejects a readdirplus record whose alignment padding was cut off", () => {
    const rng = new Rng(0xa1_16_4e);
    const entry = randomDirentPlus(rng);
    entry.dirent.name = "a";
    const { buffer } = packDirentsPlus([entry], 4096);
    expect(buffer.length).toBe(160);
    for (let length = 153; length < 160; length++) {
      expect(() => unpackDirentsPlus(buffer.subarray(0, length))).toThrow(ProtocolError);
    }
  });

  it("rejects a truncated readdirplus record", () => {
    const rng = new Rng(11);
    const { buffer } = packDirentsPlus([randomDirentPlus(rng)], 4096);
    for (let length = 1; length < buffer.length; length += 7) {
      expect(() => unpackDirentsPlus(buffer.subarray(0, length))).toThrow(ProtocolError);
    }
  });

  it("rejects a name containing NUL", () => {
    const packer = new DirentPacker(4096);
    expect(() => packer.add({ ino: 1n, off: 1n, type: DT_REG, name: "a\0b" })).toThrow(
      ProtocolError,
    );
  });

  it("round-trips randomized pages", () => {
    const rng = new Rng(0xd1_4e_48);
    for (let round = 0; round < 200; round++) {
      const entries = Array.from({ length: rng.int(12) }, () => randomDirent(rng));
      const { buffer, packed } = packDirents(entries, 1 << 20);
      expect(packed).toBe(entries.length);
      expect(unpackDirents(buffer)).toEqual(entries);
    }
  });
});
