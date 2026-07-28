/**
 * Hand-written byte fixtures for the 9P2000.L codecs.
 *
 * The round-trip suite proves the codecs agree with themselves, which is a
 * property a symmetrically wrong implementation also has: swap two fields in
 * both the encoder and the decoder and every round-trip still passes. These
 * fixtures are written out byte by byte from the layouts in diod's
 * `protocol.md` and the kernel's `net/9p/client.c` format strings, so they fail
 * when the layout drifts even if both halves drift together — the same job
 * `test/nfs/golden.test.ts` and `test/fuse/golden.test.ts` do for the other two
 * transports.
 *
 * **Every field in every fixture has a distinct value.** A fixture built from
 * zeroes and repeats passes with two fields transposed, which is the one bug
 * these tests exist to catch, so `uid` and `gid` differ by one, each timestamp
 * gets its own nibble pattern, and no two 64-bit fields share a value.
 *
 * The bytes are written little-endian and unaligned, because that is 9P: a
 * `u8` followed by a `u32` occupies five bytes. Each line below is one field,
 * annotated with its name and its decoded value.
 */

import { describe, expect, it } from "vitest";
import {
  P9_DOTL_AT_REMOVEDIR,
  P9_GETATTR_ALL,
  P9_GETATTR_BASIC,
  P9_LOCK_BLOCKED,
  P9_LOCK_FLAGS_RECLAIM,
  P9_LOCK_TYPE_UNLCK,
  P9_LOCK_TYPE_WRLCK,
  P9_NOFID,
  P9_NOTAG,
  P9_QTAUTH,
  P9_QTDIR,
  P9_QTFILE,
  P9_RATTACH,
  P9_RAUTH,
  P9_RCLUNK,
  P9_RGETATTR,
  P9_RGETLOCK,
  P9_RLERROR,
  P9_RLOCK,
  P9_RLOPEN,
  P9_RREAD,
  P9_RREADDIR,
  P9_RREADLINK,
  P9_RSTATFS,
  P9_RVERSION,
  P9_RWALK,
  P9_RWRITE,
  P9_RXATTRWALK,
  P9_SETATTR_MODE,
  P9_SETATTR_MTIME_SET,
  P9_TATTACH,
  P9_TAUTH,
  P9_TFLUSH,
  P9_TFSYNC,
  P9_TGETATTR,
  P9_TGETLOCK,
  P9_TLCREATE,
  P9_TLINK,
  P9_TLOCK,
  P9_TLOPEN,
  P9_TMKDIR,
  P9_TMKNOD,
  P9_TREAD,
  P9_TREADDIR,
  P9_TREADLINK,
  P9_TREMOVE,
  P9_TRENAME,
  P9_TRENAMEAT,
  P9_TSETATTR,
  P9_TSYMLINK,
  P9_TUNLINKAT,
  P9_TVERSION,
  P9_TWALK,
  P9_TWRITE,
  P9_TXATTRCREATE,
  P9_TXATTRWALK,
} from "../../src/9p/constants.ts";
import {
  P9DirentPacker,
  decodeMessage,
  decodeMessageAs,
  encodeMessage,
  readDirents,
  readRattach,
  readRgetattr,
  readRreaddir,
  readRstatfs,
  readTattach,
  readTlink,
  readTlock,
  readTrename,
  readTsetattr,
  readTversion,
  readTwalk,
  writeFidRequest,
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
} from "../../src/9p/protocol.ts";

/** Bytes as one lowercase hex string — the expectations are grouped by field. */
function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("9P2000 messages (the .L subset)", () => {
  it("encodes Tversion exactly as `size[4] Tversion tag[2] msize[4] version[s]`", () => {
    const frame = encodeMessage(P9_TVERSION, P9_NOTAG, (writer) => {
      writeTversion(writer, { msize: 8192, version: "9P2000.L" });
    });
    expect(hex(frame)).toBe(
      [
        "15000000", // size = 21, counting these four bytes
        "64", // type = 100 (Tversion)
        "ffff", // tag = P9_NOTAG
        "00200000", // msize = 8192
        "0800", // version length = 8
        "3950323030302e4c", // "9P2000.L"
      ].join(""),
    );
    expect(frame.byteLength).toBe(21);
    expect(decodeMessageAs(frame, readTversion).value).toEqual({
      msize: 8192,
      version: "9P2000.L",
    });
  });

  it("encodes Tattach as `fid[4] afid[4] uname[s] aname[s] n_uname[4]`", () => {
    // Kernel format "ddss?u": the `?` is "9P2000.u and .L only", and .L is the
    // only dialect served, so n_uname is always on the wire.
    const frame = encodeMessage(P9_TATTACH, 0x01_02, (writer) => {
      writeTattach(writer, {
        fid: 0x0a_0b_0c_0d,
        afid: P9_NOFID,
        uname: "sys",
        aname: "/srv",
        nUname: 1000,
      });
    });
    expect(hex(frame)).toBe(
      [
        "1e000000", // size = 30
        "68", // type = 104 (Tattach)
        "0201", // tag = 0x0102
        "0d0c0b0a", // fid = 0x0a0b0c0d, little-endian
        "ffffffff", // afid = P9_NOFID
        "0300", // uname length = 3
        "737973", // "sys"
        "0400", // aname length = 4
        "2f737276", // "/srv"
        "e8030000", // n_uname = 1000
      ].join(""),
    );
    expect(decodeMessageAs(frame, readTattach).value.nUname).toBe(1000);
  });

  it("encodes Twalk as `fid[4] newfid[4] nwname[2] nwname*(wname[s])`", () => {
    const frame = encodeMessage(P9_TWALK, 0x03_04, (writer) => {
      writeTwalk(writer, { fid: 5, newfid: 6, wnames: ["usr", "local"] });
    });
    expect(hex(frame)).toBe(
      [
        "1d000000", // size = 29
        "6e", // type = 110 (Twalk)
        "0403", // tag = 0x0304
        "05000000", // fid = 5
        "06000000", // newfid = 6
        "0200", // nwname = 2
        "0300", // wname[0] length = 3
        "757372", // "usr"
        "0500", // wname[1] length = 5
        "6c6f63616c", // "local"
      ].join(""),
    );
    expect(decodeMessageAs(frame, readTwalk).value.wnames).toEqual(["usr", "local"]);
  });

  it("encodes Rwalk as `nwqid[2] nwqid*(qid[13])` with no padding between qids", () => {
    const frame = encodeMessage(P9_RWALK, 0x03_04, (writer) => {
      writeRwalk(writer, {
        wqids: [
          { type: P9_QTDIR, version: 0x00_00_12_34, path: 0x11_22_33_44_55_66_77_88n },
          { type: P9_QTFILE, version: 0x00_00_ab_cd, path: 0x99_aa_bb_cc_dd_ee_ff_00n },
        ],
      });
    });
    expect(hex(frame)).toBe(
      [
        "23000000", // size = 35 (7 + 2 + 13 + 13)
        "6f", // type = 111 (Rwalk)
        "0403", // tag = 0x0304
        "0200", // nwqid = 2
        "80", // wqid[0].type = P9_QTDIR
        "34120000", // wqid[0].version = 0x1234
        "8877665544332211", // wqid[0].path = 0x1122334455667788
        "00", // wqid[1].type = P9_QTFILE
        "cdab0000", // wqid[1].version = 0xabcd
        "00ffeeddccbbaa99", // wqid[1].path = 0x99aabbccddeeff00
      ].join(""),
    );
    // 13 bytes each, not 16: a qid is `type[1] version[4] path[8]` unaligned.
    expect(frame.byteLength).toBe(7 + 2 + 26);
  });

  it("encodes Tread and Rread with the payload counted but not padded", () => {
    const request = encodeMessage(P9_TREAD, 0x07_08, (writer) => {
      writeTread(writer, { fid: 9, offset: 0x00_00_00_01_00_00_10_00n, count: 4096 });
    });
    expect(hex(request)).toBe(
      [
        "17000000", // size = 23
        "74", // type = 116 (Tread)
        "0807", // tag = 0x0708
        "09000000", // fid = 9
        "0010000001000000", // offset = 0x0000000100001000
        "00100000", // count = 4096
      ].join(""),
    );

    // The reply diod's own sample session shows for `cat /tmp/9/foo`.
    const reply = encodeMessage(P9_RREAD, 0x07_08, (writer) => {
      writeRread(writer, { data: new TextEncoder().encode("hello\n") });
    });
    expect(hex(reply)).toBe(
      [
        "11000000", // size = 17
        "75", // type = 117 (Rread)
        "0807", // tag = 0x0708
        "06000000", // count = 6
        "68656c6c6f0a", // "hello\n" — no padding, unlike XDR
      ].join(""),
    );
  });

  it("encodes Twrite with the count in front of the data", () => {
    const frame = encodeMessage(P9_TWRITE, 0x13_14, (writer) => {
      writeTwrite(writer, {
        fid: 0x15,
        offset: 0x00_00_00_00_00_00_01_23n,
        data: new TextEncoder().encode("hi"),
      });
    });
    expect(hex(frame)).toBe(
      [
        "19000000", // size = 25
        "76", // type = 118 (Twrite)
        "1413", // tag = 0x1314
        "15000000", // fid = 21
        "2301000000000000", // offset = 0x123
        "02000000", // count = 2
        "6869", // "hi"
      ].join(""),
    );
  });

  it("encodes Rversion and Rwrite, the replies that are one field", () => {
    const version = encodeMessage(P9_RVERSION, P9_NOTAG, (writer) => {
      writeRversion(writer, { msize: 4096, version: "9P2000.L" });
    });
    expect(hex(version)).toBe(
      [
        "15000000", // size = 21
        "65", // type = 101 (Rversion)
        "ffff", // tag = P9_NOTAG
        "00100000", // msize = 4096, negotiated down from the client's proposal
        "0800", // version length = 8
        "3950323030302e4c", // "9P2000.L"
      ].join(""),
    );

    const write = encodeMessage(P9_RWRITE, 0x13_14, (writer) => {
      writeRwrite(writer, { count: 2 });
    });
    expect(hex(write)).toBe(
      [
        "0b000000", // size = 11
        "77", // type = 119 (Rwrite)
        "1413", // tag = 0x1314
        "02000000", // count = 2 bytes actually written
      ].join(""),
    );
  });

  it("encodes Rattach as a bare qid — the shape Rmkdir, Rsymlink and Rmknod share", () => {
    const frame = encodeMessage(P9_RATTACH, 0x01_02, (writer) => {
      writeRattach(writer, {
        qid: { type: P9_QTDIR, version: 0x00_00_00_21, path: 0x00_00_00_00_00_2c_1f_acn },
      });
    });
    expect(hex(frame)).toBe(
      [
        "14000000", // size = 20 (7 + 13)
        "69", // type = 105 (Rattach)
        "0201", // tag = 0x0102
        "80", // qid.type = P9_QTDIR
        "21000000", // qid.version = 0x21
        "ac1f2c0000000000", // qid.path = 0x2c1fac
      ].join(""),
    );
    expect(decodeMessageAs(frame, readRattach).value.qid.path).toBe(0x2c_1f_acn);
  });

  it("encodes Tauth as `afid[4] uname[s] aname[s] n_uname[4]`, and Rauth as a qid", () => {
    // Diod's layout alone: the v6.12 kernel has no `p9_client_auth()` and
    // always attaches with afid = P9_NOFID, so nothing cross-checks this one.
    const request = encodeMessage(P9_TAUTH, 0x32_33, (writer) => {
      writeTauth(writer, { afid: 26, uname: "pooya", aname: "/export", nUname: 1001 });
    });
    expect(hex(request)).toBe(
      [
        "1f000000", // size = 31
        "66", // type = 102 (Tauth)
        "3332", // tag = 0x3233
        "1a000000", // afid = 26
        "0500", // uname length = 5
        "706f6f7961", // "pooya"
        "0700", // aname length = 7
        "2f6578706f7274", // "/export"
        "e9030000", // n_uname = 1001
      ].join(""),
    );

    const reply = encodeMessage(P9_RAUTH, 0x32_33, (writer) => {
      writeRauth(writer, {
        aqid: { type: P9_QTAUTH, version: 27, path: 0x12_34_56_78_90_ab_cd_efn },
      });
    });
    expect(hex(reply)).toBe(
      [
        "14000000", // size = 20
        "67", // type = 103 (Rauth)
        "3332", // tag = 0x3233
        "08", // aqid.type = P9_QTAUTH
        "1b000000", // aqid.version = 27
        "efcdab9078563412", // aqid.path = 0x1234567890abcdef
      ].join(""),
    );
  });

  it("encodes Tflush as one oldtag", () => {
    const frame = encodeMessage(P9_TFLUSH, 0x2c_2d, (writer) => {
      writeTflush(writer, { oldtag: 0x12_34 });
    });
    expect(hex(frame)).toBe(
      [
        "09000000", // size = 9
        "6c", // type = 108 (Tflush)
        "2d2c", // tag = 0x2c2d — the flush's own tag
        "3412", // oldtag = 0x1234 — the request being abandoned
      ].join(""),
    );
  });

  it("encodes Tremove and Treadlink, the one-fid requests", () => {
    // The same body as Tclunk and Tstatfs — `writeFidRequest` serves all four.
    const remove = encodeMessage(P9_TREMOVE, 0x2e_2f, (writer) => {
      writeFidRequest(writer, { fid: 24 });
    });
    expect(hex(remove)).toBe(
      [
        "0b000000", // size = 11
        "7a", // type = 122 (Tremove)
        "2f2e", // tag = 0x2e2f
        "18000000", // fid = 24
      ].join(""),
    );

    const readlink = encodeMessage(P9_TREADLINK, 0x30_31, (writer) => {
      writeFidRequest(writer, { fid: 25 });
    });
    expect(hex(readlink)).toBe(
      [
        "0b000000", // size = 11
        "16", // type = 22 (Treadlink)
        "3130", // tag = 0x3031
        "19000000", // fid = 25
      ].join(""),
    );

    const reply = encodeMessage(P9_RREADLINK, 0x30_31, (writer) => {
      writeRreadlink(writer, { target: "/srv/newdir" });
    });
    expect(hex(reply)).toBe(
      [
        "14000000", // size = 20
        "17", // type = 23 (Rreadlink)
        "3130", // tag = 0x3031
        "0b00", // target length = 11
        "2f7372762f6e6577646972", // "/srv/newdir"
      ].join(""),
    );
  });

  it("gives Rclunk a seven-byte frame — the header counting itself", () => {
    const frame = encodeMessage(P9_RCLUNK, 0x16_17);
    expect(hex(frame)).toBe(
      [
        "07000000", // size = 7 = P9_HDRSZ
        "79", // type = 121 (Rclunk)
        "1716", // tag = 0x1617
      ].join(""),
    );
    expect(decodeMessage(frame).body.remaining).toBe(0);
  });
});

describe("9P2000.L messages", () => {
  it("encodes Rlerror as a bare positive Linux errno", () => {
    const frame = encodeMessage(P9_RLERROR, 0x0d_0e, (writer) => {
      writeRlerror(writer, { ecode: 2 });
    });
    expect(hex(frame)).toBe(
      [
        "0b000000", // size = 11
        "07", // type = 7 (Rlerror)
        "0e0d", // tag = 0x0d0e
        "02000000", // ecode = 2 (ENOENT) — an errno, not a protocol status
      ].join(""),
    );
  });

  it("encodes Tlopen and Rlopen", () => {
    const request = encodeMessage(P9_TLOPEN, 0x05_06, (writer) => {
      writeTlopen(writer, { fid: 7, flags: 0x00_00_80_02 });
    });
    expect(hex(request)).toBe(
      [
        "0f000000", // size = 15
        "0c", // type = 12 (Tlopen)
        "0605", // tag = 0x0506
        "07000000", // fid = 7
        "02800000", // flags = 0x8002 (the kernel's O_RDWR|O_LARGEFILE)
      ].join(""),
    );

    const reply = encodeMessage(P9_RLOPEN, 0x05_06, (writer) => {
      writeRlopen(writer, {
        qid: { type: P9_QTFILE, version: 0x00_00_00_0b, path: 0x01_02_03_04_05_06_07_08n },
        iounit: 8192,
      });
    });
    expect(hex(reply)).toBe(
      [
        "18000000", // size = 24
        "0d", // type = 13 (Rlopen)
        "0605", // tag = 0x0506
        "00", // qid.type = P9_QTFILE
        "0b000000", // qid.version = 11
        "0807060504030201", // qid.path = 0x0102030405060708
        "00200000", // iounit = 8192
      ].join(""),
    );
  });

  it("encodes Tgetattr's request_mask as a 64-bit field", () => {
    const frame = encodeMessage(P9_TGETATTR, 0x09_0a, (writer) => {
      writeTgetattr(writer, { fid: 11, requestMask: P9_GETATTR_ALL });
    });
    expect(hex(frame)).toBe(
      [
        "13000000", // size = 19
        "18", // type = 24 (Tgetattr)
        "0a09", // tag = 0x090a
        "0b000000", // fid = 11
        "ff3f000000000000", // request_mask = P9_GETATTR_ALL (0x3fff), 8 bytes wide
      ].join(""),
    );
  });

  it("encodes Rgetattr's twenty fields at their real widths", () => {
    // The one message where a transposition is easy and invisible: `mode`,
    // `uid` and `gid` are 32-bit while `nlink`, `rdev`, `blksize` and `blocks`
    // are 64. Kernel format "A" = "qQdugqqqqqqqqqqqqqqq".
    const frame = encodeMessage(P9_RGETATTR, 0x09_0a, (writer) => {
      writeRgetattr(writer, {
        valid: P9_GETATTR_BASIC,
        qid: { type: P9_QTDIR, version: 0x00_00_12_34, path: 0x00_00_00_00_00_2c_1f_acn },
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
      });
    });
    expect(hex(frame)).toBe(
      [
        "a0000000", // size = 160 (7 + 8 + 13 + 12 + 15*8)
        "19", // type = 25 (Rgetattr)
        "0a09", // tag = 0x090a
        "ff07000000000000", // valid = P9_GETATTR_BASIC (0x7ff)
        "80", // qid.type = P9_QTDIR
        "34120000", // qid.version = 0x1234
        "ac1f2c0000000000", // qid.path = 0x2c1fac
        "ed410000", // mode = 0o040755, 4 bytes
        "f4010000", // uid = 500, 4 bytes
        "f5010000", // gid = 501, 4 bytes
        "3800000000000000", // nlink = 56, 8 bytes
        "0301000000000000", // rdev = 0x103
        "0110000000000000", // size = 0x1001
        "0010000000000000", // blksize = 0x1000
        "680a000000000000", // blocks = 0xa68
        "1111000000000000", // atime_sec
        "2222000000000000", // atime_nsec
        "3333000000000000", // mtime_sec
        "4444000000000000", // mtime_nsec
        "5555000000000000", // ctime_sec
        "6666000000000000", // ctime_nsec
        "7777000000000000", // btime_sec (reserved)
        "8888000000000000", // btime_nsec (reserved)
        "9999000000000000", // gen (reserved)
        "aaaa000000000000", // data_version (reserved)
      ].join(""),
    );
    expect(frame.byteLength).toBe(160);
    const decoded = decodeMessageAs(frame, readRgetattr).value;
    expect(decoded.uid).toBe(500);
    expect(decoded.gid).toBe(501);
    expect(decoded.nlink).toBe(56n);
  });

  it("packs Rreaddir entries as `qid[13] offset[8] type[1] name[s]`", () => {
    // Kernel `p9dirent_read()`, format "Qqbs". The `offset` is the cookie the
    // *next* Treaddir resumes from, so entry 0 carries entry 1's position.
    const packer = new P9DirentPacker(1024);
    packer.add({
      qid: { type: P9_QTDIR, version: 0x00_00_00_11, path: 0x22n },
      offset: 0x33n,
      type: 4, // DT_DIR
      name: ".",
    });
    packer.add({
      qid: { type: P9_QTFILE, version: 0x00_00_00_44, path: 0x55n },
      offset: 0x66n,
      type: 8, // DT_REG
      name: "foo",
    });
    const frame = encodeMessage(P9_RREADDIR, 0x0b_0c, (writer) => {
      writeRreaddir(writer, { data: packer.bytes() });
    });
    expect(hex(frame)).toBe(
      [
        "3f000000", // size = 63 (7 + 4 + 25 + 27)
        "29", // type = 41 (Rreaddir)
        "0c0b", // tag = 0x0b0c
        "34000000", // count = 52 bytes of entries
        // entry 0: 13 + 8 + 1 + 2 + 1 = 25 bytes
        "80", // qid.type = P9_QTDIR
        "11000000", // qid.version = 0x11
        "2200000000000000", // qid.path = 0x22
        "3300000000000000", // offset = 0x33
        "04", // type = DT_DIR
        "0100", // name length = 1
        "2e", // "."
        // entry 1: 13 + 8 + 1 + 2 + 3 = 27 bytes
        "00", // qid.type = P9_QTFILE
        "44000000", // qid.version = 0x44
        "5500000000000000", // qid.path = 0x55
        "6600000000000000", // offset = 0x66
        "08", // type = DT_REG
        "0300", // name length = 3
        "666f6f", // "foo"
      ].join(""),
    );
    const entries = readDirents(decodeMessageAs(frame, (r) => readRreaddir(r)).value.data);
    expect(entries).toHaveLength(2);
    expect(entries[1]!.name).toBe("foo");
    expect(entries[1]!.offset).toBe(0x66n);
  });

  it("encodes Tlock with `flags` where Tgetlock has nothing", () => {
    // The two messages are identical apart from those four bytes, which is
    // exactly the difference a copy-paste loses. Kernel formats: Tlock
    // "dbdqqds", Tgetlock "dbqqds".
    const lock = encodeMessage(P9_TLOCK, 0x0f_10, (writer) => {
      writeTlock(writer, {
        fid: 0x13,
        type: P9_LOCK_TYPE_WRLCK,
        flags: P9_LOCK_FLAGS_RECLAIM,
        start: 0x77n,
        length: 0x88n,
        procId: 0x99,
        clientId: "node",
      });
    });
    expect(hex(lock)).toBe(
      [
        "2a000000", // size = 42
        "34", // type = 52 (Tlock)
        "100f", // tag = 0x0f10
        "13000000", // fid = 19
        "01", // type = P9_LOCK_TYPE_WRLCK, one byte
        "02000000", // flags = 2 (P9_LOCK_FLAGS_RECLAIM) — absent from Tgetlock
        "7700000000000000", // start = 0x77
        "8800000000000000", // length = 0x88
        "99000000", // proc_id = 0x99
        "0400", // client_id length = 4
        "6e6f6465", // "node"
      ].join(""),
    );

    const getlock = encodeMessage(P9_TGETLOCK, 0x11_12, (writer) => {
      writeTgetlock(writer, {
        fid: 0x14,
        type: P9_LOCK_TYPE_WRLCK,
        start: 0xaan,
        length: 0xbbn,
        procId: 0xcc,
        clientId: "host",
      });
    });
    expect(hex(getlock)).toBe(
      [
        "26000000", // size = 38 — four bytes shorter than Tlock's 42
        "36", // type = 54 (Tgetlock)
        "1211", // tag = 0x1112
        "14000000", // fid = 20
        "01", // type = P9_LOCK_TYPE_WRLCK
        "aa00000000000000", // start = 0xaa (no flags field in between)
        "bb00000000000000", // length = 0xbb
        "cc000000", // proc_id = 0xcc
        "0400", // client_id length = 4
        "686f7374", // "host"
      ].join(""),
    );
    expect(lock.byteLength - getlock.byteLength).toBe(4);
    expect(decodeMessageAs(lock, readTlock).value.flags).toBe(2);
  });

  it("encodes Rlock as one status byte", () => {
    const frame = encodeMessage(P9_RLOCK, 0x0f_10, (writer) => {
      writeRlock(writer, { status: P9_LOCK_BLOCKED });
    });
    expect(hex(frame)).toBe(
      [
        "08000000", // size = 8 — a one-byte body, not a padded word
        "35", // type = 53 (Rlock)
        "100f", // tag = 0x0f10
        "01", // status = 1 (P9_LOCK_BLOCKED)
      ].join(""),
    );
  });

  it("encodes Rgetlock as Tgetlock without the fid", () => {
    // Kernel "bqqds" against Tgetlock's "dbqqds": the reply drops the leading
    // fid and keeps everything else, which is close enough to look like the
    // same struct and is not.
    const frame = encodeMessage(P9_RGETLOCK, 0x2a_2b, (writer) => {
      writeRgetlock(writer, {
        type: P9_LOCK_TYPE_UNLCK,
        start: 0xdd_ddn,
        length: 0xee_een,
        procId: 0xff,
        clientId: "other-host",
      });
    });
    expect(hex(frame)).toBe(
      [
        "28000000", // size = 40
        "37", // type = 55 (Rgetlock)
        "2b2a", // tag = 0x2a2b
        "02", // type = P9_LOCK_TYPE_UNLCK — "nothing is holding this"
        "dddd000000000000", // start = 0xdddd
        "eeee000000000000", // length = 0xeeee
        "ff000000", // proc_id = 0xff
        "0a00", // client_id length = 10
        "6f746865722d686f7374", // "other-host"
      ].join(""),
    );
  });

  it("encodes Rstatfs as `ddqqqqqqd` — six consecutive 64-bit counters", () => {
    // The most transposition-prone message in the protocol: six identically
    // shaped u64s in a row, bracketed by two u32s and closed by a third. Every
    // one gets its own nibble pattern.
    const frame = encodeMessage(P9_RSTATFS, 0x18_19, (writer) => {
      writeRstatfs(writer, {
        type: 0x01_02_19_97,
        bsize: 4096,
        blocks: 0x11_11n,
        bfree: 0x22_22n,
        bavail: 0x33_33n,
        files: 0x44_44n,
        ffree: 0x55_55n,
        fsid: 0x66_66n,
        namelen: 255,
      });
    });
    expect(hex(frame)).toBe(
      [
        "43000000", // size = 67 (7 + 4 + 4 + 6*8 + 4)
        "09", // type = 9 (Rstatfs)
        "1918", // tag = 0x1819
        "97190201", // type = 0x01021997 (V9FS_MAGIC)
        "00100000", // bsize = 4096
        "1111000000000000", // blocks
        "2222000000000000", // bfree
        "3333000000000000", // bavail
        "4444000000000000", // files
        "5555000000000000", // ffree
        "6666000000000000", // fsid
        "ff000000", // namelen = 255
      ].join(""),
    );
    const decoded = decodeMessageAs(frame, readRstatfs).value;
    expect(decoded.bavail).toBe(0x33_33n);
    expect(decoded.fsid).toBe(0x66_66n);
  });

  it("encodes Tsetattr's `I` composite as `ddugqqqqq`", () => {
    // The counterpart to Rgetattr's `A`, and deliberately unlike it: `valid` is
    // 32 bits here and 64 there, and there is no ctime value at all — the bit
    // asks for "now" and can ask for nothing else.
    const frame = encodeMessage(P9_TSETATTR, 0x1a_1b, (writer) => {
      writeTsetattr(writer, {
        fid: 12,
        valid: P9_SETATTR_MODE | P9_SETATTR_MTIME_SET,
        mode: 0o100_644,
        uid: 500,
        gid: 501,
        size: 0x12_34n,
        atime: { sec: 0x55_66n, nsec: 0x77_88n },
        mtime: { sec: 0x99_aan, nsec: 0xbb_ccn },
      });
    });
    expect(hex(frame)).toBe(
      [
        "43000000", // size = 67 (7 + 5*4 + 5*8)
        "1a", // type = 26 (Tsetattr)
        "1b1a", // tag = 0x1a1b
        "0c000000", // fid = 12
        "01010000", // valid = MODE|MTIME_SET (0x101), 4 bytes — not 8
        "a4810000", // mode = 0o100644
        "f4010000", // uid = 500
        "f5010000", // gid = 501
        "3412000000000000", // size = 0x1234
        "6655000000000000", // atime_sec
        "8877000000000000", // atime_nsec
        "aa99000000000000", // mtime_sec
        "ccbb000000000000", // mtime_nsec
      ].join(""),
    );
    expect(decodeMessageAs(frame, readTsetattr).value.valid).toBe(0x1_01);
  });

  it("puts the object first in Trename and the directory first in Tlink", () => {
    // Both are the kernel's `"dds"` and the two u32s are swapped between them
    // (`p9_client_rename()` sends fid then newdirfid; `p9_client_link()` sends
    // dfid then oldfid). A swap round-trips happily, so it is pinned here.
    const rename = encodeMessage(P9_TRENAME, 0x1c_1d, (writer) => {
      writeTrename(writer, { fid: 13, dfid: 14, name: "after" });
    });
    expect(hex(rename)).toBe(
      [
        "16000000", // size = 22
        "14", // type = 20 (Trename)
        "1d1c", // tag = 0x1c1d
        "0d000000", // fid = 13 — the object being renamed
        "0e000000", // dfid = 14 — its new parent directory
        "0500", // name length = 5
        "6166746572", // "after"
      ].join(""),
    );
    expect(decodeMessageAs(rename, readTrename).value).toEqual({
      fid: 13,
      dfid: 14,
      name: "after",
    });

    const link = encodeMessage(P9_TLINK, 0x1e_1f, (writer) => {
      writeTlink(writer, { dfid: 15, fid: 16, name: "hardlink" });
    });
    expect(hex(link)).toBe(
      [
        "19000000", // size = 25
        "46", // type = 70 (Tlink)
        "1f1e", // tag = 0x1e1f
        "0f000000", // dfid = 15 — the directory, first here
        "10000000", // fid = 16 — the link target, second
        "0800", // name length = 8
        "686172646c696e6b", // "hardlink"
      ].join(""),
    );
    expect(decodeMessageAs(link, readTlink).value).toEqual({
      dfid: 15,
      fid: 16,
      name: "hardlink",
    });
  });

  it("encodes Tlcreate as `dsddg` — name before flags, mode before gid", () => {
    const frame = encodeMessage(P9_TLCREATE, 0x20_21, (writer) => {
      writeTlcreate(writer, {
        fid: 17,
        name: "foo",
        flags: 0x00_00_82_41,
        mode: 0o100_644,
        gid: 502,
      });
    });
    expect(hex(frame)).toBe(
      [
        "1c000000", // size = 28
        "0e", // type = 14 (Tlcreate)
        "2120", // tag = 0x2021
        "11000000", // fid = 17 — the parent going in, the new file coming out
        "0300", // name length = 3
        "666f6f", // "foo"
        "41820000", // flags = 0x8241, the kernel's O_* namespace
        "a4810000", // mode = 0o100644
        "f6010000", // gid = 502
      ].join(""),
    );
  });

  it("encodes Tsymlink as `dssg` — two strings back to back", () => {
    const frame = encodeMessage(P9_TSYMLINK, 0x22_23, (writer) => {
      writeTsymlink(writer, {
        dfid: 18,
        name: "newsymlink",
        symtgt: "/srv/newdir",
        gid: 503,
      });
    });
    expect(hex(frame)).toBe(
      [
        "28000000", // size = 40
        "10", // type = 16 (Tsymlink)
        "2322", // tag = 0x2223
        "12000000", // dfid = 18
        "0a00", // name length = 10
        "6e657773796d6c696e6b", // "newsymlink"
        "0b00", // symtgt length = 11
        "2f7372762f6e6577646972", // "/srv/newdir" — never resolved by the server
        "f7010000", // gid = 503
      ].join(""),
    );
  });

  it("encodes Tmknod with major and minor as separate words", () => {
    // `dsdddg`: unlike Rgetattr's single rdev[8], mknod splits the device
    // number in two, and neither half is where a packed rdev would put it.
    const frame = encodeMessage(P9_TMKNOD, 0x24_25, (writer) => {
      writeTmknod(writer, {
        dfid: 19,
        name: "null",
        mode: 0o020_666,
        major: 1,
        minor: 3,
        gid: 504,
      });
    });
    expect(hex(frame)).toBe(
      [
        "21000000", // size = 33
        "12", // type = 18 (Tmknod)
        "2524", // tag = 0x2425
        "13000000", // dfid = 19
        "0400", // name length = 4
        "6e756c6c", // "null"
        "b6210000", // mode = 0o020666 (S_IFCHR | 0666)
        "01000000", // major = 1
        "03000000", // minor = 3
        "f8010000", // gid = 504
      ].join(""),
    );
  });

  it("encodes Tmkdir as `dsdg`", () => {
    const frame = encodeMessage(P9_TMKDIR, 0x38_39, (writer) => {
      writeTmkdir(writer, { dfid: 30, name: "newdir", mode: 0o040_700, gid: 505 });
    });
    expect(hex(frame)).toBe(
      [
        "1b000000", // size = 27
        "48", // type = 72 (Tmkdir)
        "3938", // tag = 0x3839
        "1e000000", // dfid = 30
        "0600", // name length = 6
        "6e6577646972", // "newdir"
        "c0410000", // mode = 0o040700
        "f9010000", // gid = 505
      ].join(""),
    );
  });

  it("encodes Trenameat as `dsds` — fid, name, fid, name", () => {
    const frame = encodeMessage(P9_TRENAMEAT, 0x26_27, (writer) => {
      writeTrenameat(writer, {
        olddirfid: 20,
        oldname: "before",
        newdirfid: 21,
        newname: "after",
      });
    });
    expect(hex(frame)).toBe(
      [
        "1e000000", // size = 30
        "4a", // type = 74 (Trenameat)
        "2726", // tag = 0x2627
        "14000000", // olddirfid = 20
        "0600", // oldname length = 6
        "6265666f7265", // "before"
        "15000000", // newdirfid = 21 — interleaved, not both fids up front
        "0500", // newname length = 5
        "6166746572", // "after"
      ].join(""),
    );
  });

  it("encodes Tunlinkat with AT_REMOVEDIR as its only flag", () => {
    const frame = encodeMessage(P9_TUNLINKAT, 0x3a_3b, (writer) => {
      writeTunlinkat(writer, { dirfid: 31, name: "doomed", flags: P9_DOTL_AT_REMOVEDIR });
    });
    expect(hex(frame)).toBe(
      [
        "17000000", // size = 23
        "4c", // type = 76 (Tunlinkat)
        "3b3a", // tag = 0x3a3b
        "1f000000", // dirfid = 31
        "0600", // name length = 6
        "646f6f6d6564", // "doomed"
        "00020000", // flags = 0x200 (AT_REMOVEDIR): this is an rmdir
      ].join(""),
    );
  });

  it("encodes Txattrwalk and Rxattrwalk", () => {
    const request = encodeMessage(P9_TXATTRWALK, 0x28_29, (writer) => {
      writeTxattrwalk(writer, { fid: 22, newfid: 23, name: "security.capability" });
    });
    expect(hex(request)).toBe(
      [
        "24000000", // size = 36
        "1e", // type = 30 (Txattrwalk)
        "2928", // tag = 0x2829
        "16000000", // fid = 22
        "17000000", // newfid = 23 — bound to the attribute, not to the file
        "1300", // name length = 19
        "7365637572697479", // "security"
        "2e", // "."
        "6361706162696c697479", // "capability"
      ].join(""),
    );

    const reply = encodeMessage(P9_RXATTRWALK, 0x28_29, (writer) => {
      writeRxattrwalk(writer, { size: 0x12_34_56_78_9an });
    });
    expect(hex(reply)).toBe(
      [
        "0f000000", // size = 15
        "1f", // type = 31 (Rxattrwalk)
        "2928", // tag = 0x2829
        "9a78563412000000", // size = 0x123456789a, 8 bytes wide
      ].join(""),
    );
  });

  it("encodes Txattrcreate as `dsqd` — the count before the flags", () => {
    const frame = encodeMessage(P9_TXATTRCREATE, 0x34_35, (writer) => {
      writeTxattrcreate(writer, {
        fid: 28,
        name: "user.mountx",
        attrSize: 0x0f_f0n,
        flags: 1,
      });
    });
    expect(hex(frame)).toBe(
      [
        "24000000", // size = 36
        "20", // type = 32 (Txattrcreate)
        "3534", // tag = 0x3435
        "1c000000", // fid = 28
        "0b00", // name length = 11
        "757365722e6d6f756e7478", // "user.mountx"
        "f00f000000000000", // attr_size = 0xff0 — 8 bytes, unlike flags
        "01000000", // flags = 1 (XATTR_CREATE)
      ].join(""),
    );
  });

  it("encodes Tfsync and Treaddir", () => {
    const fsync = encodeMessage(P9_TFSYNC, 0x36_37, (writer) => {
      writeTfsync(writer, { fid: 29, datasync: 1 });
    });
    expect(hex(fsync)).toBe(
      [
        "0f000000", // size = 15
        "32", // type = 50 (Tfsync)
        "3736", // tag = 0x3637
        "1d000000", // fid = 29
        "01000000", // datasync = 1 — fdatasync(2) rather than fsync(2)
      ].join(""),
    );

    // The second readdir of diod's sample session: a cookie, not a byte offset.
    const readdir = encodeMessage(P9_TREADDIR, 0x3c_3d, (writer) => {
      writeTreaddir(writer, { fid: 32, offset: 0x7f_ff_ff_ffn, count: 65_488 });
    });
    expect(hex(readdir)).toBe(
      [
        "17000000", // size = 23
        "28", // type = 40 (Treaddir)
        "3d3c", // tag = 0x3c3d
        "20000000", // fid = 32
        "ffffff7f00000000", // offset = 0x7fffffff, 8 bytes
        "d0ff0000", // count = 65488
      ].join(""),
    );
  });
});
