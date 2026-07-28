/**
 * 9P2000.L message codecs.
 *
 * Tier 0: bytes in, bytes out, no socket and no driver. Every message is
 * encoded and decoded here — both are needed for real, because the Tier-1 test
 * client is built from the T-encoders and R-decoders and the session from their
 * inverses, so a codec that only one side uses does not exist in this file.
 *
 * A round-trip proves a codec agrees with *itself*, which a consistently
 * transposed pair also does; `golden.test.ts` pins the actual bytes down. What
 * this file adds on top is coverage — every message type, and the structural
 * rules around them (framing, `size` accounting, `P9_MAXWELEM`, dirent packing).
 * Field values are still all-distinct throughout, so a failure points at a
 * field rather than at "something moved".
 */

import { describe, expect, it } from "vitest";
import {
  MESSAGE_NAMES,
  P9_DOTL_AT_REMOVEDIR,
  P9_GETATTR_ALL,
  P9_GETATTR_BASIC,
  P9_HDRSZ,
  P9_LOCK_FLAGS_BLOCK,
  P9_LOCK_SUCCESS,
  P9_LOCK_TYPE_UNLCK,
  P9_LOCK_TYPE_WRLCK,
  P9_MAXWELEM,
  P9_NOFID,
  P9_NOTAG,
  P9_QTDIR,
  P9_QTFILE,
  P9_QTSYMLINK,
  P9_RATTACH,
  P9_RAUTH,
  P9_RCLUNK,
  P9_RCREATE,
  P9_RERROR,
  P9_RGETATTR,
  P9_RGETLOCK,
  P9_RLCREATE,
  P9_RLERROR,
  P9_RLOCK,
  P9_RLOPEN,
  P9_RMKDIR,
  P9_RMKNOD,
  P9_ROPEN,
  P9_RREAD,
  P9_RREADDIR,
  P9_RREADLINK,
  P9_RSTAT,
  P9_RSTATFS,
  P9_RSYMLINK,
  P9_RVERSION,
  P9_RWALK,
  P9_RWRITE,
  P9_RWSTAT,
  P9_RXATTRWALK,
  P9_SETATTR_MODE,
  P9_SETATTR_MTIME_SET,
  P9_TATTACH,
  P9_TAUTH,
  P9_TCLUNK,
  P9_TCREATE,
  P9_TERROR,
  P9_TFLUSH,
  P9_TFSYNC,
  P9_TGETATTR,
  P9_TGETLOCK,
  P9_TLCREATE,
  P9_TLERROR,
  P9_TLINK,
  P9_TLOCK,
  P9_TLOPEN,
  P9_TMKDIR,
  P9_TMKNOD,
  P9_TOPEN,
  P9_TREAD,
  P9_TREADDIR,
  P9_TREADLINK,
  P9_TREMOVE,
  P9_TRENAME,
  P9_TRENAMEAT,
  P9_TSETATTR,
  P9_TSTAT,
  P9_TSTATFS,
  P9_TSYMLINK,
  P9_TUNLINKAT,
  P9_TVERSION,
  P9_TWALK,
  P9_TWRITE,
  P9_TWSTAT,
  P9_TXATTRCREATE,
  P9_TXATTRWALK,
  messageName,
} from "../../src/9p/constants.ts";
import {
  EMPTY_BODY,
  P9DirentPacker,
  P9FrameAssembler,
  decodeMessage,
  decodeMessageAs,
  direntSize,
  encodeMessage,
  framesFrom,
  readDirent,
  readDirents,
  readEmptyBody,
  readFidRequest,
  readHeader,
  readRattach,
  readRauth,
  readRgetattr,
  readRgetlock,
  readRlcreate,
  readRlerror,
  readRlock,
  readRlopen,
  readRmkdir,
  readRmknod,
  readRread,
  readRreaddir,
  readRreadlink,
  readRstatfs,
  readRsymlink,
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
  writeFidRequest,
  writeRattach,
  writeRauth,
  writeRgetattr,
  writeRgetlock,
  writeRlcreate,
  writeRlerror,
  writeRlock,
  writeRlopen,
  writeRmkdir,
  writeRmknod,
  writeRread,
  writeRreaddir,
  writeRreadlink,
  writeRstatfs,
  writeRsymlink,
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
import { P9Error, P9Reader, P9Writer, type P9Qid } from "../../src/9p/wire.ts";

// --- fixtures every case draws distinct values from -------------------------

const DIR_QID: P9Qid = { type: P9_QTDIR, version: 0x00_00_12_34, path: 0x11_22_33_44_55_66_77_88n };
const FILE_QID: P9Qid = {
  type: P9_QTFILE,
  version: 0x00_00_ab_cd,
  path: 0x99_aa_bb_cc_dd_ee_ff_00n,
};
const LINK_QID: P9Qid = {
  type: P9_QTSYMLINK,
  version: 0x00_00_5a_5a,
  path: 0x01_02_03_04_05_06_07_08n,
};

const bytesOf = (text: string): Uint8Array => new TextEncoder().encode(text);

// --- the table --------------------------------------------------------------

interface MessageCase {
  readonly name: string;
  readonly type: number;
  readonly value: unknown;
  encode(tag: number): Uint8Array;
  decode(bytes: Uint8Array): unknown;
}

function messageCase<T>(
  type: number,
  value: T,
  write: (writer: P9Writer, message: T) => void,
  read: (reader: P9Reader) => T,
): MessageCase {
  return {
    name: messageName(type),
    type,
    value,
    encode: (tag) => encodeMessage(type, tag, (writer) => write(writer, value)),
    decode: (bytes) => decodeMessageAs(bytes, read).value,
  };
}

const CASES: MessageCase[] = [
  messageCase(P9_TVERSION, { msize: 131_072, version: "9P2000.L" }, writeTversion, readTversion),
  messageCase(P9_RVERSION, { msize: 65_536, version: "9P2000.L" }, writeRversion, readRversion),
  messageCase(
    P9_TAUTH,
    { afid: 0x0a_0b_0c_0d, uname: "pooya", aname: "/export", nUname: 1000 },
    writeTauth,
    readTauth,
  ),
  messageCase(P9_RAUTH, { aqid: LINK_QID }, writeRauth, readRauth),
  messageCase(
    P9_TATTACH,
    { fid: 0x00_00_00_01, afid: P9_NOFID, uname: "sys", aname: "/srv", nUname: 4321 },
    writeTattach,
    readTattach,
  ),
  messageCase(P9_RATTACH, { qid: DIR_QID }, writeRattach, readRattach),
  messageCase(P9_RLERROR, { ecode: 39 }, writeRlerror, readRlerror),
  messageCase(P9_TFLUSH, { oldtag: 0x12_34 }, writeTflush, readTflush),
  messageCase(
    P9_TWALK,
    { fid: 11, newfid: 22, wnames: ["usr", "local", "bin"] },
    writeTwalk,
    readTwalk,
  ),
  messageCase(P9_RWALK, { wqids: [DIR_QID, FILE_QID, LINK_QID] }, writeRwalk, readRwalk),
  messageCase(
    P9_TREAD,
    { fid: 33, offset: 0x00_00_00_01_00_00_10_00n, count: 0x00_00_80_00 },
    writeTread,
    readTread,
  ),
  messageCase(P9_RREAD, { data: bytesOf("hello\n") }, writeRread, (reader) => readRread(reader)),
  messageCase(
    P9_TWRITE,
    { fid: 44, offset: 0x00_00_00_00_00_00_01_23n, data: bytesOf("written bytes") },
    writeTwrite,
    (reader) => readTwrite(reader),
  ),
  messageCase(P9_RWRITE, { count: 13 }, writeRwrite, readRwrite),
  messageCase(P9_TCLUNK, { fid: 55 }, writeFidRequest, readFidRequest),
  messageCase(P9_TREMOVE, { fid: 66 }, writeFidRequest, readFidRequest),
  messageCase(P9_TSTATFS, { fid: 77 }, writeFidRequest, readFidRequest),
  messageCase(
    P9_RSTATFS,
    {
      type: 0x01_02_1997,
      bsize: 4096,
      blocks: 0x11_11n,
      bfree: 0x22_22n,
      bavail: 0x33_33n,
      files: 0x44_44n,
      ffree: 0x55_55n,
      fsid: 0x66_66n,
      namelen: 255,
    },
    writeRstatfs,
    readRstatfs,
  ),
  messageCase(P9_TLOPEN, { fid: 88, flags: 0x00_00_80_02 }, writeTlopen, readTlopen),
  messageCase(P9_RLOPEN, { qid: FILE_QID, iounit: 8192 }, writeRlopen, readRlopen),
  messageCase(
    P9_TLCREATE,
    { fid: 99, name: "created", flags: 0x00_00_82_41, mode: 0o100_644, gid: 501 },
    writeTlcreate,
    readTlcreate,
  ),
  messageCase(P9_RLCREATE, { qid: LINK_QID, iounit: 4096 }, writeRlcreate, readRlcreate),
  messageCase(
    P9_TSYMLINK,
    { dfid: 111, name: "newsymlink", symtgt: "/srv/newdir", gid: 502 },
    writeTsymlink,
    readTsymlink,
  ),
  messageCase(P9_RSYMLINK, { qid: LINK_QID }, writeRsymlink, readRsymlink),
  messageCase(
    P9_TMKNOD,
    { dfid: 122, name: "null", mode: 0o020_666, major: 1, minor: 3, gid: 503 },
    writeTmknod,
    readTmknod,
  ),
  messageCase(P9_RMKNOD, { qid: FILE_QID }, writeRmknod, readRmknod),
  messageCase(P9_TRENAME, { fid: 133, dfid: 144, name: "renamed" }, writeTrename, readTrename),
  messageCase(P9_TREADLINK, { fid: 155 }, writeFidRequest, readFidRequest),
  messageCase(P9_RREADLINK, { target: "/srv/newdir" }, writeRreadlink, readRreadlink),
  messageCase(P9_TGETATTR, { fid: 166, requestMask: P9_GETATTR_ALL }, writeTgetattr, readTgetattr),
  messageCase(
    P9_RGETATTR,
    {
      valid: P9_GETATTR_BASIC,
      qid: DIR_QID,
      mode: 0o040_755,
      uid: 500,
      gid: 501,
      nlink: 56n,
      rdev: 0x01_03n,
      size: 0x10_01n,
      blksize: 0x10_00n,
      blocks: 0x0a_68n,
      atime: { sec: 0x11_11n, nsec: 0x22_22n },
      mtime: { sec: 0x33_33n, nsec: 0x44_44n },
      ctime: { sec: 0x55_55n, nsec: 0x66_66n },
      btime: { sec: 0x77_77n, nsec: 0x88_88n },
      gen: 0x99_99n,
      dataVersion: 0xaa_aan,
    },
    writeRgetattr,
    readRgetattr,
  ),
  messageCase(
    P9_TSETATTR,
    {
      fid: 177,
      valid: P9_SETATTR_MODE | P9_SETATTR_MTIME_SET,
      mode: 0o000_400,
      uid: 504,
      gid: 505,
      size: 0xbe_efn,
      atime: { sec: 0xc0_c0n, nsec: 0xd0_d0n },
      mtime: { sec: 0xe0_e0n, nsec: 0xf0_f0n },
    },
    writeTsetattr,
    readTsetattr,
  ),
  messageCase(
    P9_TXATTRWALK,
    { fid: 188, newfid: 199, name: "security.capability" },
    writeTxattrwalk,
    readTxattrwalk,
  ),
  messageCase(P9_RXATTRWALK, { size: 0x12_34_56_78_9an }, writeRxattrwalk, readRxattrwalk),
  messageCase(
    P9_TXATTRCREATE,
    { fid: 200, name: "user.mountx", attrSize: 0x0f_f0n, flags: 1 },
    writeTxattrcreate,
    readTxattrcreate,
  ),
  messageCase(
    P9_TREADDIR,
    { fid: 211, offset: 0x7f_ff_ff_ffn, count: 65_488 },
    writeTreaddir,
    readTreaddir,
  ),
  messageCase(
    P9_RREADDIR,
    { data: bytesOf("not really entries, just a payload") },
    writeRreaddir,
    (reader) => readRreaddir(reader),
  ),
  messageCase(P9_TFSYNC, { fid: 222, datasync: 1 }, writeTfsync, readTfsync),
  messageCase(
    P9_TLOCK,
    {
      fid: 233,
      type: P9_LOCK_TYPE_WRLCK,
      flags: P9_LOCK_FLAGS_BLOCK,
      start: 0x77_77n,
      length: 0x88_88n,
      procId: 0x00_00_00_99,
      clientId: "node",
    },
    writeTlock,
    readTlock,
  ),
  messageCase(P9_RLOCK, { status: P9_LOCK_SUCCESS }, writeRlock, readRlock),
  messageCase(
    P9_TGETLOCK,
    {
      fid: 244,
      type: P9_LOCK_TYPE_WRLCK,
      start: 0xaa_aan,
      length: 0xbb_bbn,
      procId: 0x00_00_00_cc,
      clientId: "host",
    },
    writeTgetlock,
    readTgetlock,
  ),
  messageCase(
    P9_RGETLOCK,
    {
      type: P9_LOCK_TYPE_UNLCK,
      start: 0xdd_ddn,
      length: 0xee_een,
      procId: 0x00_00_00_ff,
      clientId: "other-host",
    },
    writeRgetlock,
    readRgetlock,
  ),
  messageCase(P9_TLINK, { dfid: 255, fid: 266, name: "hardlink" }, writeTlink, readTlink),
  messageCase(
    P9_TMKDIR,
    { dfid: 277, name: "newdir", mode: 0o040_700, gid: 506 },
    writeTmkdir,
    readTmkdir,
  ),
  messageCase(P9_RMKDIR, { qid: DIR_QID }, writeRmkdir, readRmkdir),
  messageCase(
    P9_TRENAMEAT,
    { olddirfid: 288, oldname: "before", newdirfid: 299, newname: "after" },
    writeTrenameat,
    readTrenameat,
  ),
  messageCase(
    P9_TUNLINKAT,
    { dirfid: 300, name: "doomed", flags: P9_DOTL_AT_REMOVEDIR },
    writeTunlinkat,
    readTunlinkat,
  ),
];

/**
 * The message types with no codec, and why: `Tlerror` and `Terror` are never
 * sent in either dialect, `Rerror` is 9P2000's string-valued failure reply that
 * 9P2000.L replaced with `Rlerror`, and the four remaining pairs are the
 * 9P2000 messages 9P2000.L replaced outright — a session recognizes them only
 * to answer `Rlerror ENOTSUP`, which needs no decoder.
 */
const NOT_SERVED = new Set([
  P9_TLERROR,
  P9_TERROR,
  P9_RERROR,
  P9_TOPEN,
  P9_ROPEN,
  P9_TCREATE,
  P9_RCREATE,
  P9_TSTAT,
  P9_RSTAT,
  P9_TWSTAT,
  P9_RWSTAT,
]);

describe("every message", () => {
  for (const testCase of CASES) {
    it(`${testCase.name} round-trips through a frame`, () => {
      const tag = 0x0b_0c;
      const frame = testCase.encode(tag);
      const message = decodeMessage(frame);
      expect(message.type).toBe(testCase.type);
      expect(message.tag).toBe(tag);
      expect(message.size).toBe(frame.byteLength);
      expect(testCase.decode(frame)).toEqual(testCase.value);
    });
  }

  it("covers every 9P2000.L message this server speaks", () => {
    // A message added to `constants.ts` with no codec here would otherwise sit
    // untested until a kernel sent one.
    const covered = [...new Set(CASES.map((testCase) => testCase.type)), ...EMPTY_BODY];
    expect(covered).toHaveLength(CASES.length + EMPTY_BODY.size);
    const expected = Object.keys(MESSAGE_NAMES)
      .map(Number)
      .filter((type) => !NOT_SERVED.has(type));
    expect([...covered].sort((a, b) => a - b)).toEqual(expected.sort((a, b) => a - b));
  });
});

describe("framing", () => {
  it("counts the size field in `size`", () => {
    // `p9_parse_header()` rejects anything under 7, and a bodyless message is
    // exactly 7 — the header, counting its own four bytes.
    const frame = encodeMessage(P9_RCLUNK, 1);
    expect(frame.byteLength).toBe(P9_HDRSZ);
    const header = readHeader(new P9Reader(frame));
    expect(header).toEqual({ size: P9_HDRSZ, type: P9_RCLUNK, tag: 1 });
  });

  it("backfills the size once the body is written", () => {
    const frame = encodeMessage(P9_RREADLINK, 7, (writer) => {
      writeRreadlink(writer, { target: "/a/rather/longer/target" });
    });
    // 7 header + 2 count + 23 bytes of path.
    expect(frame.byteLength).toBe(P9_HDRSZ + 2 + 23);
    expect(decodeMessage(frame).size).toBe(frame.byteLength);
  });

  it("grows past the initial capacity and still patches the right four bytes", () => {
    // The writer reallocates mid-message; `patchU32` must land in the buffer
    // that survived, not the one that was discarded.
    const target = "x".repeat(4096);
    const frame = encodeMessage(
      P9_RREADLINK,
      9,
      (writer) => {
        writeRreadlink(writer, { target });
      },
      16,
    );
    expect(decodeMessage(frame).size).toBe(frame.byteLength);
    expect(decodeMessageAs(frame, readRreadlink).value.target).toBe(target);
  });

  it("carries P9_NOTAG through unchanged", () => {
    const frame = encodeMessage(P9_TVERSION, P9_NOTAG, (writer) => {
      writeTversion(writer, { msize: 8192, version: "9P2000.L" });
    });
    expect(decodeMessage(frame).tag).toBe(P9_NOTAG);
  });

  it("refuses a frame whose size disagrees with the bytes present", () => {
    const frame = encodeMessage(P9_TCLUNK, 3, (writer) => writeFidRequest(writer, { fid: 1 }));
    expect(() => decodeMessage(frame.subarray(0, frame.byteLength - 1))).toThrow(P9Error);
    const padded = new Uint8Array(frame.byteLength + 1);
    padded.set(frame);
    expect(() => decodeMessage(padded)).toThrow(P9Error);
  });

  it("refuses a body with trailing bytes", () => {
    const frame = encodeMessage(P9_TCLUNK, 3, (writer) => {
      writeFidRequest(writer, { fid: 1 });
      writer.u32(0xdead_beef);
    });
    expect(() => decodeMessageAs(frame, readFidRequest)).toThrow(P9Error);
  });

  it("gives every bodyless reply a 7-byte frame and an empty body", () => {
    for (const type of EMPTY_BODY) {
      const frame = encodeMessage(type, 5);
      expect(frame.byteLength).toBe(P9_HDRSZ);
      const message = decodeMessage(frame);
      expect(message.type).toBe(type);
      expect(() => readEmptyBody(message.body, messageName(type))).not.toThrow();
    }
  });
});

describe("walk", () => {
  it("accepts exactly P9_MAXWELEM names", () => {
    const wnames = Array.from({ length: P9_MAXWELEM }, (_, index) => `d${index}`);
    const frame = encodeMessage(P9_TWALK, 1, (writer) => {
      writeTwalk(writer, { fid: 1, newfid: 2, wnames });
    });
    expect(decodeMessageAs(frame, readTwalk).value.wnames).toEqual(wnames);
  });

  it("refuses more than P9_MAXWELEM, encoding and decoding alike", () => {
    const wnames = Array.from({ length: P9_MAXWELEM + 1 }, (_, index) => `d${index}`);
    expect(() =>
      encodeMessage(P9_TWALK, 1, (writer) => writeTwalk(writer, { fid: 1, newfid: 2, wnames })),
    ).toThrow(P9Error);
    // Hand-built, because the encoder will not produce one: nwname = 17 with no
    // names behind it, which a decoder must refuse on the count alone.
    const hostile = encodeMessage(P9_TWALK, 1, (writer) => {
      writer.u32(1);
      writer.u32(2);
      writer.u16(P9_MAXWELEM + 1);
    });
    expect(() => decodeMessageAs(hostile, readTwalk)).toThrow(P9Error);
  });

  it("round-trips a clone — no names, no qids", () => {
    const frame = encodeMessage(P9_TWALK, 1, (writer) => {
      writeTwalk(writer, { fid: 1, newfid: 2, wnames: [] });
    });
    expect(decodeMessageAs(frame, readTwalk).value).toEqual({ fid: 1, newfid: 2, wnames: [] });
    const reply = encodeMessage(P9_RWALK, 1, (writer) => writeRwalk(writer, { wqids: [] }));
    expect(decodeMessageAs(reply, readRwalk).value).toEqual({ wqids: [] });
    expect(reply.byteLength).toBe(P9_HDRSZ + 2);
  });
});

describe("payload messages", () => {
  it("copies a Twrite payload out of the frame", () => {
    const data = bytesOf("mutate me");
    const frame = encodeMessage(P9_TWRITE, 1, (writer) => {
      writeTwrite(writer, { fid: 1, offset: 0n, data });
    });
    const decoded = decodeMessageAs(frame, (reader) => readTwrite(reader)).value;
    // The frame is the socket's memory as far as a session is concerned; a
    // decoder that returned a view would hand a driver a window onto it.
    frame.fill(0);
    expect([...decoded.data]).toEqual([...bytesOf("mutate me")]);
  });

  it("copies an Rread payload out of the frame", () => {
    const frame = encodeMessage(P9_RREAD, 1, (writer) => {
      writeRread(writer, { data: bytesOf("payload") });
    });
    const decoded = decodeMessageAs(frame, (reader) => readRread(reader)).value;
    frame.fill(0);
    expect([...decoded.data]).toEqual([...bytesOf("payload")]);
  });

  it("bounds a payload by the caller's maximum", () => {
    const frame = encodeMessage(P9_RREAD, 1, (writer) => {
      writeRread(writer, { data: new Uint8Array(64) });
    });
    expect(() => decodeMessageAs(frame, (reader) => readRread(reader, 32))).toThrow(P9Error);
  });

  it("round-trips an empty payload, which is how a read reports EOF", () => {
    const frame = encodeMessage(P9_RREAD, 1, (writer) => {
      writeRread(writer, { data: new Uint8Array(0) });
    });
    expect(decodeMessageAs(frame, (reader) => readRread(reader)).value.data.byteLength).toBe(0);
  });
});

describe("dirents", () => {
  const entries: P9Dirent[] = [
    { qid: DIR_QID, offset: 1n, type: 4, name: "." },
    { qid: FILE_QID, offset: 2n, type: 8, name: "hello.txt" },
    { qid: LINK_QID, offset: 3n, type: 10, name: "link" },
  ];

  it("round-trips one entry", () => {
    const writer = new P9Writer(64);
    writeDirent(writer, entries[1]!);
    const reader = new P9Reader(writer.bytes());
    expect(readDirent(reader)).toEqual(entries[1]);
    reader.end();
  });

  it("sizes an entry the way it packs it", () => {
    for (const entry of entries) {
      const writer = new P9Writer(64);
      writeDirent(writer, entry);
      expect(writer.length).toBe(direntSize(entry.name));
    }
    // The name's *bytes* count, not its characters.
    expect(direntSize("é")).toBe(direntSize("ab"));
  });

  it("packs and unpacks a run of entries", () => {
    const packer = new P9DirentPacker(1024);
    for (const entry of entries) {
      expect(packer.add(entry)).toBe(true);
    }
    expect(packer.count).toBe(3);
    expect(packer.size).toBe(entries.reduce((total, e) => total + direntSize(e.name), 0));
    expect(readDirents(packer.bytes())).toEqual(entries);
  });

  it("refuses an entry that does not fit, and changes nothing", () => {
    const budget = direntSize(entries[0]!.name) + direntSize(entries[1]!.name);
    const packer = new P9DirentPacker(budget);
    expect(packer.add(entries[0]!)).toBe(true);
    expect(packer.add(entries[1]!)).toBe(true);
    const before = packer.bytes();
    expect(packer.add(entries[2]!)).toBe(false);
    expect(packer.remaining).toBe(0);
    expect([...packer.bytes()]).toEqual([...before]);
    expect(readDirents(packer.bytes())).toEqual(entries.slice(0, 2));
  });

  it("leaves the block untouched when a name cannot be expressed on the wire", () => {
    // Regression: `writeDirent` lays down qid[13] offset[8] type[1] before it
    // reaches the name, so a name over the 16-bit count used to leave 22 orphan
    // bytes behind — corrupting not just the failed entry but every entry
    // already packed, since `readDirents` then cannot get past them.
    const packer = new P9DirentPacker(1024);
    expect(packer.add(entries[0]!)).toBe(true);
    const before = packer.bytes();
    const overlong = { ...entries[1]!, name: "n".repeat(70_000) };
    expect(() => packer.add(overlong)).toThrow(P9Error);
    expect(packer.size).toBe(before.byteLength);
    expect(packer.count).toBe(1);
    expect([...packer.bytes()]).toEqual([...before]);
    expect(readDirents(packer.bytes())).toEqual([entries[0]]);
  });

  it("throws for an unencodable name even where the budget would have said false", () => {
    // `false` means "ask again with a bigger budget", which no budget would fix
    // here — the file would vanish from the directory forever — so the
    // unencodable case is checked first and a session can answer ENAMETOOLONG.
    const packer = new P9DirentPacker(8);
    expect(packer.add(entries[0]!)).toBe(false);
    expect(() => packer.add({ ...entries[0]!, name: "n".repeat(70_000) })).toThrow(P9Error);
    expect(packer.size).toBe(0);
  });

  it("packs nothing into a zero budget", () => {
    const packer = new P9DirentPacker(0);
    expect(packer.add(entries[0]!)).toBe(false);
    expect(packer.bytes().byteLength).toBe(0);
    expect(readDirents(packer.bytes())).toEqual([]);
  });

  it("refuses a block whose last entry is cut short", () => {
    const packer = new P9DirentPacker(1024);
    packer.add(entries[0]!);
    packer.add(entries[1]!);
    const block = packer.bytes();
    expect(() => readDirents(block.subarray(0, block.byteLength - 3))).toThrow(P9Error);
  });

  it("travels inside an Rreaddir", () => {
    const packer = new P9DirentPacker(1024);
    for (const entry of entries) {
      packer.add(entry);
    }
    const frame = encodeMessage(P9_RREADDIR, 4, (writer) => {
      writeRreaddir(writer, { data: packer.bytes() });
    });
    const decoded = decodeMessageAs(frame, (reader) => readRreaddir(reader)).value;
    expect(readDirents(decoded.data)).toEqual(entries);
  });
});

describe("the frame assembler", () => {
  const frames = [
    encodeMessage(P9_TVERSION, P9_NOTAG, (writer) => {
      writeTversion(writer, { msize: 8192, version: "9P2000.L" });
    }),
    encodeMessage(P9_TCLUNK, 1, (writer) => writeFidRequest(writer, { fid: 7 })),
    encodeMessage(P9_TWRITE, 2, (writer) => {
      writeTwrite(writer, { fid: 7, offset: 9n, data: bytesOf("some bytes here") });
    }),
  ];
  const stream = (() => {
    const total = frames.reduce((sum, frame) => sum + frame.byteLength, 0);
    const all = new Uint8Array(total);
    let at = 0;
    for (const frame of frames) {
      all.set(frame, at);
      at += frame.byteLength;
    }
    return all;
  })();

  it("hands out whole frames from one delivery", () => {
    const assembler = new P9FrameAssembler();
    const out = assembler.push(stream);
    expect(out.map((frame) => [...frame])).toEqual(frames.map((frame) => [...frame]));
    expect(assembler.pending).toBe(0);
  });

  it("reassembles a stream delivered one byte at a time", () => {
    const assembler = new P9FrameAssembler();
    const out: Uint8Array[] = [];
    for (const byte of stream) {
      out.push(...assembler.push(Uint8Array.of(byte)));
    }
    expect(out.map((frame) => [...frame])).toEqual(frames.map((frame) => [...frame]));
    expect(assembler.pending).toBe(0);
  });

  it("copies, so a caller may reuse the buffer it fed in", () => {
    const assembler = new P9FrameAssembler();
    const chunk = Uint8Array.prototype.slice.call(stream);
    const out = assembler.push(chunk);
    chunk.fill(0xff);
    expect(out.map((frame) => [...frame])).toEqual(frames.map((frame) => [...frame]));
  });

  it("copies the partial frame it is holding as well", () => {
    const assembler = new P9FrameAssembler();
    const head = Uint8Array.prototype.slice.call(stream, 0, 5);
    expect(assembler.push(head)).toEqual([]);
    expect(assembler.pending).toBe(5);
    head.fill(0xff);
    const out = assembler.push(stream.subarray(5));
    expect(out.map((frame) => [...frame])).toEqual(frames.map((frame) => [...frame]));
  });

  it("refuses a frame larger than the limit, without buffering it", () => {
    const assembler = new P9FrameAssembler(64);
    const oversized = new Uint8Array(16);
    new DataView(oversized.buffer).setUint32(0, 1024, true);
    expect(() => assembler.push(oversized)).toThrow(P9Error);
  });

  it("refuses a size below the 7-byte header", () => {
    const assembler = new P9FrameAssembler();
    const runt = new Uint8Array(16);
    new DataView(runt.buffer).setUint32(0, 6, true);
    expect(() => assembler.push(runt)).toThrow(P9Error);
  });

  it("refuses a limit that could not hold a header", () => {
    expect(() => new P9FrameAssembler(P9_HDRSZ - 1)).toThrow(P9Error);
    const assembler = new P9FrameAssembler();
    expect(() => {
      assembler.limit = 0;
    }).toThrow(P9Error);
  });

  it("takes the negotiated msize mid-stream", () => {
    // Which is the whole reason `limit` is settable: `Tversion` arrives through
    // the assembler that then has to enforce what it negotiated.
    const assembler = new P9FrameAssembler(1024);
    expect(assembler.limit).toBe(1024);
    expect(assembler.push(frames[0]!)).toHaveLength(1);
    assembler.limit = frames[1]!.byteLength;
    expect(assembler.limit).toBe(frames[1]!.byteLength);
    expect(assembler.push(frames[1]!)).toHaveLength(1);
    expect(() => assembler.push(frames[2]!)).toThrow(P9Error);
  });

  it("drops a partial frame on reset", () => {
    const assembler = new P9FrameAssembler();
    assembler.push(stream.subarray(0, 5));
    expect(assembler.pending).toBe(5);
    assembler.reset();
    expect(assembler.pending).toBe(0);
    expect(assembler.failed).toBe(false);
  });

  it("latches a framing error: a good frame ahead of a bad one does not save it", () => {
    // Regression: `push` used to throw with the instance still usable — the
    // frames parsed earlier in the call were dropped, the chunk was dropped,
    // and `#buffer` still held the *previous* partial, so `pending` described a
    // stream position that no longer existed. There is no offset to resume at:
    // `size` is 9P's only structure, so one bad length desynchronizes the rest.
    const assembler = new P9FrameAssembler();
    const runt = new Uint8Array(P9_HDRSZ);
    new DataView(runt.buffer).setUint32(0, 3, true);
    const poisoned = new Uint8Array(frames[1]!.byteLength + runt.byteLength);
    poisoned.set(frames[1]!);
    poisoned.set(runt, frames[1]!.byteLength);

    expect(() => assembler.push(poisoned)).toThrow(P9Error);
    expect(assembler.failed).toBe(true);
    expect(assembler.pending).toBe(0);
    // Perfectly good bytes, and still refused — the stream is gone, not the frame.
    expect(() => assembler.push(frames[1]!)).toThrow(P9Error);
    expect(() => assembler.push(new Uint8Array(0))).toThrow(P9Error);
  });

  it("names the original failure in every later refusal", () => {
    const assembler = new P9FrameAssembler(64);
    const oversized = new Uint8Array(P9_HDRSZ);
    new DataView(oversized.buffer).setUint32(0, 4096, true);
    expect(() => assembler.push(oversized)).toThrow(/exceeds the 64-byte limit/);
    expect(() => assembler.push(frames[1]!)).toThrow(/unusable.*exceeds the 64-byte limit/);
  });

  it("comes back after reset, for the next connection", () => {
    const assembler = new P9FrameAssembler();
    const runt = new Uint8Array(P9_HDRSZ);
    new DataView(runt.buffer).setUint32(0, 3, true);
    expect(() => assembler.push(runt)).toThrow(P9Error);
    expect(assembler.failed).toBe(true);
    assembler.reset();
    expect(assembler.failed).toBe(false);
    const out = assembler.push(stream);
    expect(out.map((frame) => [...frame])).toEqual(frames.map((frame) => [...frame]));
  });

  it("streams frames out of an async source", async () => {
    async function* chunks(): AsyncGenerator<Uint8Array> {
      for (let at = 0; at < stream.byteLength; at += 7) {
        yield stream.subarray(at, at + 7);
      }
    }
    const out: Uint8Array[] = [];
    for await (const frame of framesFrom(chunks())) {
      out.push(frame);
    }
    expect(out.map((frame) => [...frame])).toEqual(frames.map((frame) => [...frame]));
  });

  it("shares an assembler with its caller, so msize can be lowered mid-stream", async () => {
    const assembler = new P9FrameAssembler();
    const out: Uint8Array[] = [];
    await expect(async () => {
      // One frame per delivery, so the limit set by the consumer applies to the
      // next `push` — which is the shape a session negotiating `msize` has.
      for await (const frame of framesFrom([frames[0]!, frames[2]!], assembler)) {
        out.push(frame);
        assembler.limit = P9_HDRSZ;
      }
    }).rejects.toThrow(P9Error);
    expect(out).toHaveLength(1);
  });
});
