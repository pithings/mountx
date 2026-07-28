/**
 * Hand-verified byte fixtures.
 *
 * The round-trip tests prove the codecs agree with *themselves*, which is
 * exactly the property a consistently wrong implementation also has. These
 * fixtures are written out by hand from RFC 5531 §9 and RFC 1813, word by
 * word, so they fail if the layout drifts even when both directions drift
 * together — the same job `test/fuse/golden.test.ts` does for the other
 * transport.
 *
 * Every expectation below is annotated with the XDR declaration it comes from
 * and the meaning of each 4-byte word.
 */

import { describe, expect, it } from "vitest";
import {
  AUTH_NONE,
  MOUNT_PROGRAM,
  MOUNT_V3,
  MOUNTPROC3_MNT,
  NFS_PROGRAM,
  NFS_V3,
  NFS3_OK,
  NFSPROC3_GETATTR,
  NFSPROC3_LOOKUP,
  NFSPROC3_NULL,
} from "../../src/nfs/constants.ts";
import {
  authSys,
  decodeCall,
  encodeAcceptedReply,
  encodeAuthError,
  encodeCall,
  frameRecord,
} from "../../src/nfs/rpc.ts";
import {
  readGetattrRes,
  writeDirOp,
  writeFsinfoRes,
  writeGetattrRes,
  writeMountRes,
  writeWccRes,
  type Fattr3,
} from "../../src/nfs/protocol.ts";
import { decodeXdr, encodeXdr } from "../../src/nfs/xdr.ts";

/** Bytes as lowercase hex, in 4-byte words, for a readable diff. */
function hex(bytes: Uint8Array): string {
  const words: string[] = [];
  for (let at = 0; at < bytes.byteLength; at += 4) {
    words.push(
      [...bytes.subarray(at, at + 4)].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
    );
  }
  return words.join(" ");
}

describe("RPC call framing", () => {
  it("encodes NFSPROC3_NULL with AUTH_NONE exactly as RFC 5531 §9 spells it", () => {
    const message = encodeCall({
      xid: 1,
      program: NFS_PROGRAM,
      version: NFS_V3,
      procedure: NFSPROC3_NULL,
    });
    expect(hex(message)).toBe(
      [
        "00000001", // xid = 1
        "00000000", // mtype = CALL (0)
        "00000002", // rpcvers = 2
        "000186a3", // prog = 100003 (NFS)
        "00000003", // vers = 3
        "00000000", // proc = 0 (NULL)
        "00000000", // cred.flavor = AUTH_NONE
        "00000000", // cred.body length = 0
        "00000000", // verf.flavor = AUTH_NONE
        "00000000", // verf.body length = 0
      ].join(" "),
    );
    expect(message.byteLength).toBe(40);
    expect(decodeCall(message).call.cred.flavor).toBe(AUTH_NONE);
  });

  it("puts the MOUNT program number on a MNT call", () => {
    const message = encodeCall({
      xid: 0x0a_0b_0c_0d,
      program: MOUNT_PROGRAM,
      version: MOUNT_V3,
      procedure: MOUNTPROC3_MNT,
      args: encodeXdr((writer) => writer.string("/")),
    });
    expect(hex(message)).toBe(
      [
        "0a0b0c0d", // xid
        "00000000", // CALL
        "00000002", // rpcvers 2
        "000186a5", // prog = 100005 (MOUNT)
        "00000003", // vers = 3
        "00000001", // proc = 1 (MNT)
        "00000000", // cred AUTH_NONE
        "00000000",
        "00000000", // verf AUTH_NONE
        "00000000",
        "00000001", // dirpath length = 1
        "2f000000", // "/" plus three bytes of XDR padding
      ].join(" "),
    );
  });

  it("encodes an AUTH_SYS credential the way RFC 5531 §8.2 does", () => {
    const message = encodeCall({
      xid: 2,
      program: NFS_PROGRAM,
      version: NFS_V3,
      procedure: NFSPROC3_NULL,
      cred: authSys(1000, 100, "host"),
    });
    // Body: stamp(4) + machinename(4 + 4) + uid(4) + gid(4) + gids count(4).
    expect(hex(message)).toBe(
      [
        "00000002", // xid
        "00000000", // CALL
        "00000002", // rpcvers
        "000186a3", // NFS
        "00000003", // v3
        "00000000", // NULL
        "00000001", // cred.flavor = AUTH_SYS
        "00000018", // cred.body length = 24
        "00000000", // stamp = 0
        "00000004", // machinename length = 4
        "686f7374", // "host"
        "000003e8", // uid = 1000
        "00000064", // gid = 100
        "00000000", // gids<16> count = 0
        "00000000", // verf.flavor = AUTH_NONE
        "00000000", // verf.body length = 0
      ].join(" "),
    );
  });
});

describe("RPC reply framing", () => {
  it("encodes an accepted, successful reply with no results", () => {
    expect(hex(encodeAcceptedReply(1))).toBe(
      [
        "00000001", // xid
        "00000001", // mtype = REPLY (1)
        "00000000", // reply_stat = MSG_ACCEPTED (0)
        "00000000", // verf.flavor = AUTH_NONE
        "00000000", // verf.body length = 0
        "00000000", // accept_stat = SUCCESS (0)
      ].join(" "),
    );
  });

  it("encodes a denied reply with an auth_stat", () => {
    expect(hex(encodeAuthError(3, 5))).toBe(
      [
        "00000003", // xid
        "00000001", // REPLY
        "00000001", // reply_stat = MSG_DENIED (1)
        "00000001", // reject_stat = AUTH_ERROR (1)
        "00000005", // auth_stat = AUTH_TOOWEAK (5)
      ].join(" "),
    );
  });
});

describe("record marking", () => {
  it("prefixes a record with a last-fragment header (RFC 5531 §11)", () => {
    const framed = frameRecord(
      encodeCall({ xid: 1, program: NFS_PROGRAM, version: NFS_V3, procedure: NFSPROC3_NULL }),
    );
    // 0x80000028: last-fragment bit set, length 0x28 = 40.
    expect(hex(framed.subarray(0, 4))).toBe("80000028");
    expect(framed.byteLength).toBe(44);
  });
});

describe("NFSv3 structures", () => {
  it("encodes LOOKUP3args as diropargs3", () => {
    // An asymmetric handle: a palindrome would survive being written backwards.
    const fh = new Uint8Array([0x55, 0x4e, 0x46, 0x53, 0xa1, 0xb2, 0xc3, 0xd4]);
    const bytes = encodeXdr((writer) => writeDirOp(writer, { dir: fh, name: "abc" }));
    expect(hex(bytes)).toBe(
      [
        "00000008", // nfs_fh3 length = 8
        "554e4653", // "UNFS"
        "a1b2c3d4", // the rest of the handle
        "00000003", // filename3 length = 3
        "61626300", // "abc" plus one byte of padding
      ].join(" "),
    );
  });

  /**
   * **Every field gets a distinct value, on purpose.**
   *
   * A fixture built from `uid: 0, gid: 0, size == used, fsid == fileid` is
   * satisfied by an encoder *and* decoder that transpose the same pair — the
   * bytes come out identical, the round-trip tests come out identical, and the
   * whole suite stays green while the wire format is wrong. (Verified: swapping
   * `uid`/`gid` in both directions passed 243/243 against the old fixture.)
   * Symmetric codecs cannot catch a symmetric mistake; only a fixture whose
   * words are all different can.
   */
  const GOLDEN_ATTR: Fattr3 = {
    type: 2, // NF3DIR
    mode: 0o751,
    nlink: 3,
    uid: 1000,
    gid: 100,
    size: 0x00_00_00_01_00_00_10_00n, // 4 GiB + 4096: both halves are non-zero
    used: 0x00_00_00_04_00_00_20_00n,
    rdev: { major: 13, minor: 9 },
    fsid: 0x01_02_03_04_05_06_07_08n,
    fileid: 0x11_22_33_44_55_66_77_88n,
    atime: { seconds: 1_700_000_000, nseconds: 123_456_789 },
    mtime: { seconds: 1_700_000_005, nseconds: 234_567_891 },
    ctime: { seconds: 1_700_000_010, nseconds: 345_678_912 },
  };

  /**
   * `struct fattr3` (RFC 1813 §2.5.4), transcribed field by field:
   *
   * ```
   * ftype3 type; mode3 mode; uint32 nlink; uid3 uid; gid3 gid;
   * size3 size; size3 used; specdata3 rdev; uint64 fsid; fileid3 fileid;
   * nfstime3 atime; nfstime3 mtime; nfstime3 ctime;
   * ```
   *
   * Each word below is that field's value written out in big-endian hex — not
   * produced by the encoder, which is the whole point.
   */
  const GOLDEN_ATTR_WORDS = [
    "00000002", // type = NF3DIR (2)
    "000001e9", // mode = 0751 — permission bits only, no S_IFMT
    "00000003", // nlink = 3
    "000003e8", // uid = 1000
    "00000064", // gid = 100
    "00000001",
    "00001000", // size = 0x100001000 (uint64, high word first)
    "00000004",
    "00002000", // used = 0x400002000
    "0000000d", // rdev.specdata1 = 13 (major)
    "00000009", // rdev.specdata2 = 9 (minor)
    "01020304",
    "05060708", // fsid = 0x0102030405060708
    "11223344",
    "55667788", // fileid = 0x1122334455667788
    "6553f100",
    "075bcd15", // atime = 1700000000 s, 123456789 ns
    "6553f105",
    "0dfb38d3", // mtime = 1700000005 s, 234567891 ns
    "6553f10a",
    "149aa440", // ctime = 1700000010 s, 345678912 ns
  ];

  it("gives every fattr3 word a distinct value, so a transposition cannot hide", () => {
    expect(GOLDEN_ATTR_WORDS).toHaveLength(21);
    expect(new Set(GOLDEN_ATTR_WORDS).size).toBe(21);
  });

  it("encodes a fattr3 as 21 words in RFC order", () => {
    const bytes = encodeXdr((writer) =>
      writeGetattrRes(writer, { status: NFS3_OK, attributes: GOLDEN_ATTR }),
    );
    expect(hex(bytes)).toBe(["00000000", ...GOLDEN_ATTR_WORDS].join(" "));
    // nfsstat3(4) + fattr3(84).
    expect(bytes.byteLength).toBe(88);
    // And the decoder reads back exactly what was put in — which on its own
    // proves nothing (see above), and together with the bytes proves both.
    expect(decodeXdr(bytes, readGetattrRes).attributes).toEqual(GOLDEN_ATTR);
  });

  it("encodes wcc_data with pre_op_attr's three fields in order", () => {
    // `struct wcc_attr { size3 size; nfstime3 mtime; nfstime3 ctime; }` — the
    // two timestamps are the pair most worth pinning, since transposing them
    // is invisible to any symmetric test.
    const bytes = encodeXdr((writer) =>
      writeWccRes(writer, {
        status: NFS3_OK,
        wcc: {
          before: {
            size: 0x00_00_00_02_00_00_00_ffn,
            mtime: { seconds: 1_600_000_001, nseconds: 11 },
            ctime: { seconds: 1_600_000_002, nseconds: 22 },
          },
          after: undefined,
        },
      }),
    );
    expect(hex(bytes)).toBe(
      [
        "00000000", // nfsstat3 = NFS3_OK
        "00000001", // pre_op_attr: attributes_follow = TRUE
        "00000002",
        "000000ff", // size = 0x2000000ff
        "5f5e1001",
        "0000000b", // mtime = 1600000001 s, 11 ns
        "5f5e1002",
        "00000016", // ctime = 1600000002 s, 22 ns
        "00000000", // post_op_attr: attributes_follow = FALSE
      ].join(" "),
    );
  });

  it("encodes FSINFO3resok's ten scalars in order", () => {
    // Every value distinct, for the same reason as `fattr3`: `rtmax`/`rtpref`
    // and `wtmax`/`wtpref` are adjacent same-typed pairs, which is exactly
    // where a transposition goes unnoticed.
    const bytes = encodeXdr((writer) =>
      writeFsinfoRes(writer, {
        status: NFS3_OK,
        attributes: undefined,
        rtmax: 0x00_10_00_00,
        rtpref: 0x00_08_00_00,
        rtmult: 4096,
        wtmax: 0x00_04_00_00,
        wtpref: 0x00_02_00_00,
        wtmult: 512,
        dtpref: 32_768,
        maxfilesize: 0x00_00_7f_ff_ff_ff_ff_ffn,
        timeDelta: { seconds: 0, nseconds: 1_000_000 },
        properties: 0x1b,
      }),
    );
    expect(hex(bytes)).toBe(
      [
        "00000000", // nfsstat3 = NFS3_OK
        "00000000", // post_op_attr: attributes_follow = FALSE
        "00100000", // rtmax
        "00080000", // rtpref
        "00001000", // rtmult
        "00040000", // wtmax
        "00020000", // wtpref
        "00000200", // wtmult
        "00008000", // dtpref
        "00007fff",
        "ffffffff", // maxfilesize (uint64)
        "00000000",
        "000f4240", // time_delta = 0 s, 1000000 ns
        "0000001b", // properties
      ].join(" "),
    );
  });

  it("encodes a successful mountres3 with its auth flavor list", () => {
    const bytes = encodeXdr((writer) =>
      writeMountRes(writer, {
        status: 0,
        fh: new Uint8Array([0x0a, 0x1b, 0x2c, 0x3d]),
        authFlavors: [0, 1],
      }),
    );
    expect(hex(bytes)).toBe(
      [
        "00000000", // mountstat3 = MNT3_OK
        "00000004", // fhandle3 length = 4
        "0a1b2c3d", // the handle
        "00000002", // auth_flavors<> count = 2
        "00000000", // AUTH_NONE
        "00000001", // AUTH_SYS
      ].join(" "),
    );
  });

  it("encodes a failed mountres3 as nothing but its status", () => {
    const bytes = encodeXdr((writer) =>
      writeMountRes(writer, { status: 20, fh: undefined, authFlavors: [] }),
    );
    expect(hex(bytes)).toBe("00000014"); // MNT3ERR_NOTDIR = 20
  });

  it("keeps the GETATTR procedure number at 1 and LOOKUP at 3", () => {
    // Cheap, and it is the sort of thing that silently breaks everything.
    expect(NFSPROC3_GETATTR).toBe(1);
    expect(NFSPROC3_LOOKUP).toBe(3);
  });
});
