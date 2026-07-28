/**
 * Golden byte fixtures.
 *
 * Every fixture is written out field by field with its offset, so a reviewer
 * can check it against `include/uapi/linux/fuse.h` (v6.12, protocol 7.41)
 * without running anything. These are the regression net for the wire format:
 * a round-trip test proves the codecs agree with each other, a golden fixture
 * proves they agree with the kernel.
 */

import { describe, expect, it } from "vitest";
import { DT_DIR, DT_REG, FUSE_INIT, FUSE_LOOKUP, FUSE_WRITE } from "../../src/fuse/constants.ts";
import {
  decodeInitIn,
  decodeInitOut,
  decodeRequest,
  decodeReply,
  encodeInitIn,
  encodeInitOut,
  encodeReply,
  encodeReplyFor,
  encodeRequest,
  packDirentsPlus,
  unpackDirentsPlus,
} from "../../src/fuse/protocol.ts";
import type { FuseAttr, FuseDirentPlus, FuseEntryOut } from "../../src/fuse/protocol.ts";

/** Build a fixture from `[what, hex]` rows. Whitespace in the hex is ignored. */
function fixture(...rows: Array<readonly [string, string]>): Uint8Array {
  const hex = rows.map(([, value]) => value.replaceAll(/\s/g, "")).join("");
  expect(hex.length % 2, "fixture has a half byte").toBe(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

const zeros = (count: number): string => "00".repeat(count);

/** 1 000 000 000 seconds — 0x3B9ACA00, little-endian in a `uint64_t`. */
const TIME_HEX = "00ca9a3b 00000000";

const REG_ATTR: FuseAttr = {
  ino: 2n,
  size: 13n,
  blocks: 1n,
  atime: 1_000_000_000n,
  mtime: 1_000_000_000n,
  ctime: 1_000_000_000n,
  atimensec: 0,
  mtimensec: 0,
  ctimensec: 0,
  mode: 0o100_644,
  nlink: 1,
  uid: 1000,
  gid: 1000,
  rdev: 0,
  blksize: 4096,
  flags: 0,
};

const REG_ATTR_HEX = [
  ["attr.ino = 2", "02000000 00000000"],
  ["attr.size = 13", "0d000000 00000000"],
  ["attr.blocks = 1", "01000000 00000000"],
  ["attr.atime = 1e9", TIME_HEX],
  ["attr.mtime = 1e9", TIME_HEX],
  ["attr.ctime = 1e9", TIME_HEX],
  ["attr.atimensec = 0", "00000000"],
  ["attr.mtimensec = 0", "00000000"],
  ["attr.ctimensec = 0", "00000000"],
  ["attr.mode = 0100644 (0x81a4)", "a4810000"],
  ["attr.nlink = 1", "01000000"],
  ["attr.uid = 1000 (0x3e8)", "e8030000"],
  ["attr.gid = 1000", "e8030000"],
  ["attr.rdev = 0", "00000000"],
  ["attr.blksize = 4096 (0x1000)", "00100000"],
  ["attr.flags = 0", "00000000"],
] as const;

describe("golden: FUSE_INIT", () => {
  // What a 7.41 kernel sends. `struct fuse_init_in` has been 64 bytes since
  // 7.36 (flags2 + uint32_t unused[11]).
  const request = fixture(
    ["in.len = 104 (40 + 64)", "68000000"],
    ["in.opcode = FUSE_INIT (26)", "1a000000"],
    ["in.unique = 2", "02000000 00000000"],
    ["in.nodeid = 0", "00000000 00000000"],
    ["in.uid = 0", "00000000"],
    ["in.gid = 0", "00000000"],
    ["in.pid = 0", "00000000"],
    ["in.total_extlen = 0", "0000"],
    ["in.padding", "0000"],
    ["init_in.major = 7", "07000000"],
    ["init_in.minor = 41 (0x29)", "29000000"],
    ["init_in.max_readahead = 131072 (0x20000)", "00000200"],
    ["init_in.flags = 0x3b", "3b000000"],
    ["init_in.flags2 = 0x1", "01000000"],
    ["init_in.unused[11]", zeros(44)],
  );

  const initIn = { major: 7, minor: 41, maxReadahead: 131_072, flags: 0x3b, flags2: 0x1 };

  it("encodes the request", () => {
    expect(encodeRequest({ opcode: FUSE_INIT, unique: 2n, body: initIn })).toEqual(request);
    expect(encodeInitIn(initIn).length).toBe(64);
  });

  it("decodes the request", () => {
    const decoded = decodeRequest(request);
    expect(decoded.header.len).toBe(104);
    expect(decoded.header.opcode).toBe(FUSE_INIT);
    expect(decoded.body).toEqual(initIn);
    expect(decodeInitIn(request.subarray(40))).toEqual(initIn);
  });

  // The reply for the mountx defaults: 1 MiB max_write via 256 max_pages,
  // 1 ns time granularity, 64 background requests.
  const reply = fixture(
    ["out.len = 80 (16 + 64)", "50000000"],
    ["out.error = 0", "00000000"],
    ["out.unique = 2", "02000000 00000000"],
    ["init_out.major = 7", "07000000"],
    ["init_out.minor = 41", "29000000"],
    ["init_out.max_readahead = 131072", "00000200"],
    ["init_out.flags = 0x3b", "3b000000"],
    ["init_out.max_background = 64", "4000"],
    ["init_out.congestion_threshold = 48", "3000"],
    ["init_out.max_write = 1048576 (0x100000)", "00001000"],
    ["init_out.time_gran = 1", "01000000"],
    ["init_out.max_pages = 256 (0x100)", "0001"],
    ["init_out.map_alignment = 0", "0000"],
    ["init_out.flags2 = 0", "00000000"],
    ["init_out.max_stack_depth = 0", "00000000"],
    ["init_out.unused[6]", zeros(24)],
  );

  const initOut = {
    major: 7,
    minor: 41,
    maxReadahead: 131_072,
    flags: 0x3b,
    maxBackground: 64,
    congestionThreshold: 48,
    maxWrite: 1024 * 1024,
    timeGran: 1,
    maxPages: 256,
    mapAlignment: 0,
    flags2: 0,
    maxStackDepth: 0,
  };

  it("encodes the reply", () => {
    expect(encodeReply(2n, encodeInitOut(initOut))).toEqual(reply);
  });

  it("decodes the reply", () => {
    expect(decodeReply(reply, FUSE_INIT).body).toEqual(initOut);
    expect(decodeInitOut(reply.subarray(16))).toEqual(initOut);
  });
});

describe("golden: FUSE_LOOKUP", () => {
  const request = fixture(
    ["in.len = 50 (40 + 10)", "32000000"],
    ["in.opcode = FUSE_LOOKUP (1)", "01000000"],
    ["in.unique = 3", "03000000 00000000"],
    ["in.nodeid = FUSE_ROOT_ID (1)", "01000000 00000000"],
    ["in.uid = 1000", "e8030000"],
    ["in.gid = 1000", "e8030000"],
    ["in.pid = 4242 (0x1092)", "92100000"],
    ["in.total_extlen = 0", "0000"],
    ["in.padding", "0000"],
    ['name = "readme.md"', "72 65 61 64 6d 65 2e 6d 64"],
    ["name NUL terminator", "00"],
  );

  it("encodes and decodes the request", () => {
    const message = encodeRequest({
      opcode: FUSE_LOOKUP,
      unique: 3n,
      nodeid: 1n,
      uid: 1000,
      gid: 1000,
      pid: 4242,
      body: { name: "readme.md" },
    });
    expect(message).toEqual(request);
    expect(decodeRequest(request).body).toEqual({ name: "readme.md" });
  });

  const entry: FuseEntryOut = {
    nodeid: 2n,
    generation: 1n,
    entryValid: 1n,
    attrValid: 1n,
    entryValidNsec: 0,
    attrValidNsec: 0,
    attr: REG_ATTR,
  };

  const reply = fixture(
    ["out.len = 144 (16 + 128)", "90000000"],
    ["out.error = 0", "00000000"],
    ["out.unique = 3", "03000000 00000000"],
    ["entry.nodeid = 2", "02000000 00000000"],
    ["entry.generation = 1", "01000000 00000000"],
    ["entry.entry_valid = 1", "01000000 00000000"],
    ["entry.attr_valid = 1", "01000000 00000000"],
    ["entry.entry_valid_nsec = 0", "00000000"],
    ["entry.attr_valid_nsec = 0", "00000000"],
    ...REG_ATTR_HEX,
  );

  it("encodes and decodes the fuse_entry_out reply", () => {
    expect(encodeReplyFor(3n, FUSE_LOOKUP, entry)).toEqual(reply);
    expect(decodeReply(reply, FUSE_LOOKUP).body).toEqual(entry);
  });
});

describe("golden: FUSE_GETATTR reply", () => {
  const dirAttr: FuseAttr = {
    ino: 1n,
    size: 4096n,
    blocks: 8n,
    atime: 1_000_000_000n,
    mtime: 1_000_000_000n,
    ctime: 1_000_000_000n,
    atimensec: 0,
    mtimensec: 0,
    ctimensec: 0,
    mode: 0o40_755,
    nlink: 2,
    uid: 0,
    gid: 0,
    rdev: 0,
    blksize: 4096,
    flags: 0,
  };

  const reply = fixture(
    ["out.len = 120 (16 + 104)", "78000000"],
    ["out.error = 0", "00000000"],
    ["out.unique = 4", "04000000 00000000"],
    ["attr_out.attr_valid = 1", "01000000 00000000"],
    ["attr_out.attr_valid_nsec = 0", "00000000"],
    ["attr_out.dummy", "00000000"],
    ["attr.ino = 1", "01000000 00000000"],
    ["attr.size = 4096", "00100000 00000000"],
    ["attr.blocks = 8", "08000000 00000000"],
    ["attr.atime = 1e9", TIME_HEX],
    ["attr.mtime = 1e9", TIME_HEX],
    ["attr.ctime = 1e9", TIME_HEX],
    ["attr.atimensec = 0", "00000000"],
    ["attr.mtimensec = 0", "00000000"],
    ["attr.ctimensec = 0", "00000000"],
    ["attr.mode = 040755 (0x41ed)", "ed410000"],
    ["attr.nlink = 2", "02000000"],
    ["attr.uid = 0", "00000000"],
    ["attr.gid = 0", "00000000"],
    ["attr.rdev = 0", "00000000"],
    ["attr.blksize = 4096", "00100000"],
    ["attr.flags = 0", "00000000"],
  );

  const attrOut = { attrValid: 1n, attrValidNsec: 0, attr: dirAttr };

  it("encodes and decodes fuse_attr_out", () => {
    expect(encodeReplyFor(4n, 3 /* FUSE_GETATTR */, attrOut)).toEqual(reply);
    expect(decodeReply(reply, 3).body).toEqual(attrOut);
  });
});

describe("golden: FUSE_READDIRPLUS page", () => {
  // Two entries. `fuse_direntplus` is fuse_entry_out (128) + fuse_dirent
  // header (24) + the name, rounded up to 8 bytes:
  //   "."    -> align8(128 + 24 + 1) = 160, 7 bytes of padding
  //   "file" -> align8(128 + 24 + 4) = 160, 4 bytes of padding
  const dotEntry: FuseEntryOut = {
    nodeid: 0n,
    generation: 0n,
    entryValid: 0n,
    attrValid: 0n,
    entryValidNsec: 0,
    attrValidNsec: 0,
    attr: {
      ino: 0n,
      size: 0n,
      blocks: 0n,
      atime: 0n,
      mtime: 0n,
      ctime: 0n,
      atimensec: 0,
      mtimensec: 0,
      ctimensec: 0,
      mode: 0,
      nlink: 0,
      uid: 0,
      gid: 0,
      rdev: 0,
      blksize: 0,
      flags: 0,
    },
  };

  const entries: FuseDirentPlus[] = [
    // "." is sent with a zeroed entry_out so the kernel does not take a
    // lookup reference on it.
    { entry: dotEntry, dirent: { ino: 1n, off: 1n, type: DT_DIR, name: "." } },
    {
      entry: {
        nodeid: 3n,
        generation: 0n,
        entryValid: 1n,
        attrValid: 1n,
        entryValidNsec: 0,
        attrValidNsec: 0,
        attr: { ...REG_ATTR, ino: 3n, size: 5n, uid: 0, gid: 0 },
      },
      dirent: { ino: 3n, off: 2n, type: DT_REG, name: "file" },
    },
  ];

  const page = fixture(
    ['[0] entry_out: all zero (no lookup ref for ".")', zeros(128)],
    ["[0] dirent.ino = 1", "01000000 00000000"],
    ["[0] dirent.off = 1 (resume cookie)", "01000000 00000000"],
    ["[0] dirent.namelen = 1", "01000000"],
    ["[0] dirent.type = DT_DIR (4)", "04000000"],
    ['[0] dirent.name = "."', "2e"],
    ["[0] padding to 160", zeros(7)],
    ["[1] entry.nodeid = 3", "03000000 00000000"],
    ["[1] entry.generation = 0", "00000000 00000000"],
    ["[1] entry.entry_valid = 1", "01000000 00000000"],
    ["[1] entry.attr_valid = 1", "01000000 00000000"],
    ["[1] entry.entry_valid_nsec = 0", "00000000"],
    ["[1] entry.attr_valid_nsec = 0", "00000000"],
    ["[1] attr.ino = 3", "03000000 00000000"],
    ["[1] attr.size = 5", "05000000 00000000"],
    ["[1] attr.blocks = 1", "01000000 00000000"],
    ["[1] attr.atime = 1e9", TIME_HEX],
    ["[1] attr.mtime = 1e9", TIME_HEX],
    ["[1] attr.ctime = 1e9", TIME_HEX],
    ["[1] attr.atimensec = 0", "00000000"],
    ["[1] attr.mtimensec = 0", "00000000"],
    ["[1] attr.ctimensec = 0", "00000000"],
    ["[1] attr.mode = 0100644", "a4810000"],
    ["[1] attr.nlink = 1", "01000000"],
    ["[1] attr.uid = 0", "00000000"],
    ["[1] attr.gid = 0", "00000000"],
    ["[1] attr.rdev = 0", "00000000"],
    ["[1] attr.blksize = 4096", "00100000"],
    ["[1] attr.flags = 0", "00000000"],
    ["[1] dirent.ino = 3", "03000000 00000000"],
    ["[1] dirent.off = 2", "02000000 00000000"],
    ["[1] dirent.namelen = 4", "04000000"],
    ["[1] dirent.type = DT_REG (8)", "08000000"],
    ['[1] dirent.name = "file"', "66 69 6c 65"],
    ["[1] padding to 160", zeros(4)],
  );

  it("packs the page", () => {
    expect(page.length).toBe(320);
    const { buffer, packed } = packDirentsPlus(entries, 4096);
    expect(packed).toBe(2);
    expect(buffer).toEqual(page);
  });

  it("unpacks the page", () => {
    expect(unpackDirentsPlus(page)).toEqual(entries);
  });
});

describe("golden: FUSE_WRITE with payload", () => {
  const request = fixture(
    ["in.len = 85 (40 + 40 + 5)", "55000000"],
    ["in.opcode = FUSE_WRITE (16)", "10000000"],
    ["in.unique = 5", "05000000 00000000"],
    ["in.nodeid = 3", "03000000 00000000"],
    ["in.uid = 1000", "e8030000"],
    ["in.gid = 1000", "e8030000"],
    ["in.pid = 4242", "92100000"],
    ["in.total_extlen = 0", "0000"],
    ["in.padding", "0000"],
    ["write_in.fh = 0x0102030405060708", "08070605 04030201"],
    ["write_in.offset = 4096", "00100000 00000000"],
    ["write_in.size = 5", "05000000"],
    ["write_in.write_flags = 0", "00000000"],
    ["write_in.lock_owner = 0", "00000000 00000000"],
    ["write_in.flags = 0100001 (O_WRONLY|O_LARGEFILE)", "01800000"],
    ["write_in.padding", "00000000"],
    ['payload = "hello"', "68 65 6c 6c 6f"],
  );

  const body = {
    fh: 0x01_02_03_04_05_06_07_08n,
    offset: 4096n,
    size: 5,
    writeFlags: 0,
    lockOwner: 0n,
    flags: 0o100_001,
    data: new TextEncoder().encode("hello"),
  };

  it("encodes the request", () => {
    expect(
      encodeRequest({
        opcode: FUSE_WRITE,
        unique: 5n,
        nodeid: 3n,
        uid: 1000,
        gid: 1000,
        pid: 4242,
        body,
      }),
    ).toEqual(request);
  });

  it("decodes the request", () => {
    const decoded = decodeRequest(request);
    expect(decoded.header.len).toBe(85);
    expect(decoded.body).toEqual(body);
  });

  it("encodes the fuse_write_out reply", () => {
    const reply = fixture(
      ["out.len = 24 (16 + 8)", "18000000"],
      ["out.error = 0", "00000000"],
      ["out.unique = 5", "05000000 00000000"],
      ["write_out.size = 5", "05000000"],
      ["write_out.padding", "00000000"],
    );
    expect(encodeReplyFor(5n, FUSE_WRITE, { size: 5 })).toEqual(reply);
    expect(decodeReply(reply, FUSE_WRITE).body).toEqual({ size: 5 });
  });
});
