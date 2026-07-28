/**
 * NFSv3 struct codecs: round-trips, union arms, and the errno mapping.
 *
 * Tier 0. Every codec in `protocol.ts` is encoded and decoded here, because
 * that symmetry is what the Tier-1 client depends on: a struct that only
 * round-trips by accident would show up as a mysterious `GARBAGE_ARGS` from a
 * real kernel and nothing else.
 */

import { describe, expect, it } from "vitest";
import { ERRNO_CODES } from "../../src/errors.ts";
import {
  CREATE_EXCLUSIVE,
  CREATE_GUARDED,
  CREATE_UNCHECKED,
  DONT_CHANGE,
  FILE_SYNC,
  NF3BLK,
  NF3CHR,
  NF3DIR,
  NF3FIFO,
  NF3LNK,
  NF3REG,
  NF3SOCK,
  NFS3_OK,
  NFS3ERR_IO,
  NFS3ERR_NOENT,
  NFS3ERR_NOTSUPP,
  NFS3ERR_STALE,
  SET_TO_CLIENT_TIME,
  SET_TO_SERVER_TIME,
} from "../../src/nfs/constants.ts";
import {
  entryPlusSize,
  entrySize,
  errnoCodeOfStatus,
  errnoOfStatus,
  fattrOf,
  fromTime,
  ftypeOf,
  modeTypeOf,
  nfsStatusOf,
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
  readSetattrArgs,
  readSymlinkArgs,
  readWccRes,
  readWriteArgs,
  readWriteRes,
  statusName,
  toTime,
  wccAttrOf,
  writeAccessArgs,
  writeAccessRes,
  writeCommitArgs,
  writeCommitRes,
  writeCreateArgs,
  writeCreateRes,
  writeDirOp,
  writeExportList,
  writeFsinfoRes,
  writeFsstatRes,
  writeGetattrRes,
  writeLinkArgs,
  writeLinkRes,
  writeLookupRes,
  writeMkdirArgs,
  writeMknodArgs,
  writeMountList,
  writeMountRes,
  writePathconfRes,
  writeReadArgs,
  writeReadRes,
  writeReaddirRes,
  writeReaddirplusRes,
  writeReaddirArgs,
  writeReaddirplusArgs,
  writeReadlinkRes,
  writeRenameArgs,
  writeRenameRes,
  writeSetattrArgs,
  writeSymlinkArgs,
  writeWccRes,
  writeWriteArgs,
  writeWriteRes,
  type Fattr3,
  type WccData,
} from "../../src/nfs/protocol.ts";
import { decodeXdr, encodeXdr, XdrError } from "../../src/nfs/xdr.ts";
import { S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFREG, S_IFSOCK } from "../../src/types.ts";
import type { StatsLike } from "../../src/types.ts";

/** Encode with `write`, decode with `read`, and insist nothing was lost. */
function roundTrip<T>(
  write: (writer: import("../../src/nfs/xdr.ts").XdrWriter, value: T) => void,
  read: (reader: import("../../src/nfs/xdr.ts").XdrReader) => T,
  value: T,
): T {
  const bytes = encodeXdr((writer) => write(writer, value));
  expect(bytes.byteLength % 4).toBe(0);
  const decoded = decodeXdr(bytes, read);
  expect(decoded).toEqual(value);
  return decoded;
}

const FH = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
const VERF = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]);

const ATTR: Fattr3 = {
  type: NF3REG,
  mode: 0o644,
  nlink: 2,
  uid: 1000,
  gid: 100,
  size: 123_456_789_012n,
  used: 4096n,
  rdev: { major: 3, minor: 7 },
  fsid: 0x11_22_33_44n,
  fileid: 999n,
  atime: { seconds: 1_700_000_000, nseconds: 123_456_789 },
  mtime: { seconds: 1_700_000_001, nseconds: 2 },
  ctime: { seconds: 1_700_000_002, nseconds: 3 },
};

const WCC: WccData = {
  before: { size: 42n, mtime: { seconds: 1, nseconds: 2 }, ctime: { seconds: 3, nseconds: 4 } },
  after: ATTR,
};

describe("attributes", () => {
  it("round-trips a fattr3 and a wcc_data", () => {
    roundTrip(writeGetattrRes, readGetattrRes, { status: NFS3_OK, attributes: ATTR });
    roundTrip(writeWccRes, readWccRes, { status: NFS3_OK, wcc: WCC });
    roundTrip(writeWccRes, readWccRes, {
      status: NFS3ERR_NOENT,
      wcc: { before: undefined, after: undefined },
    });
  });

  it("maps every file type both ways", () => {
    const pairs: [number, number][] = [
      [S_IFREG, NF3REG],
      [S_IFDIR, NF3DIR],
      [S_IFLNK, NF3LNK],
      [S_IFCHR, NF3CHR],
      [S_IFSOCK, NF3SOCK],
      [S_IFIFO, NF3FIFO],
    ];
    for (const [mode, type] of pairs) {
      expect(ftypeOf(mode | 0o644)).toBe(type);
      expect(modeTypeOf(type)).toBe(mode);
    }
    // A driver reporting no type bits describes a regular file: `ftype3` has
    // no "unknown" and NF3REG is the only safe guess.
    expect(ftypeOf(0o644)).toBe(NF3REG);
    expect(modeTypeOf(0)).toBe(S_IFREG);
    expect(ftypeOf(0o060_000)).toBe(NF3BLK);
  });

  it("keeps the type bits out of fattr3.mode", () => {
    const stats = {
      dev: 7,
      ino: 11,
      mode: S_IFDIR | 0o755,
      nlink: 2,
      uid: 1,
      gid: 2,
      rdev: 0,
      size: 4096,
      blksize: 4096,
      blocks: 8,
      atimeMs: 1500,
      mtimeMs: 2500,
      ctimeMs: 3500,
    } as StatsLike;
    const attr = fattrOf(stats, 11n);
    // RFC 1813 §2.5.4 keeps the type in `ftype3`; a client ORs the two back
    // together. Sending S_IFMT in `mode` too is the classic interop bug.
    expect(attr.mode).toBe(0o755);
    expect(attr.type).toBe(NF3DIR);
    expect(attr.used).toBe(4096n);
    expect(attr.fsid).toBe(7n);
    expect(attr.mtime).toEqual({ seconds: 2, nseconds: 500_000_000 });
    expect(modeTypeOf(attr.type) | attr.mode).toBe(stats.mode);
  });

  it("falls back to the size when a driver reports no blocks", () => {
    const stats = { size: 10, blocks: 0, mode: 0o100_644 } as StatsLike;
    expect(fattrOf(stats, 1n).used).toBe(10n);
  });

  it("round-trips timestamps through nfstime3", () => {
    for (const ms of [0, 1, 1000, 1_700_000_000_123]) {
      expect(fromTime(toTime(ms))).toBeCloseTo(ms, 3);
    }
    // Nothing negative or non-finite reaches the wire.
    expect(toTime(-5)).toEqual({ seconds: 0, nseconds: 0 });
    expect(toTime(Number.NaN)).toEqual({ seconds: 0, nseconds: 0 });
  });

  it("takes a wcc_attr from a stat", () => {
    expect(wccAttrOf({ size: 5, mtimeMs: 1000, ctimeMs: 2000 } as StatsLike)).toEqual({
      size: 5n,
      mtime: { seconds: 1, nseconds: 0 },
      ctime: { seconds: 2, nseconds: 0 },
    });
  });
});

describe("sattr3", () => {
  it("round-trips every combination of set and unset fields", () => {
    roundTrip(writeSetattrArgs, readSetattrArgs, {
      object: FH,
      attributes: {
        mode: 0o600,
        uid: 1,
        gid: 2,
        size: 4096n,
        atime: { how: SET_TO_CLIENT_TIME, time: { seconds: 5, nseconds: 6 } },
        mtime: { how: SET_TO_SERVER_TIME },
      },
      guard: { seconds: 7, nseconds: 8 },
    });
    roundTrip(writeSetattrArgs, readSetattrArgs, {
      object: FH,
      attributes: {
        mode: undefined,
        uid: undefined,
        gid: undefined,
        size: undefined,
        atime: { how: DONT_CHANGE },
        mtime: { how: DONT_CHANGE },
      },
      guard: undefined,
    });
  });

  it("treats a missing set_atime as DONT_CHANGE", () => {
    const bytes = encodeXdr((writer) =>
      writeSetattrArgs(writer, {
        object: FH,
        attributes: {},
        guard: undefined,
      }),
    );
    const decoded = decodeXdr(bytes, readSetattrArgs);
    expect(decoded.attributes.atime).toEqual({ how: DONT_CHANGE });
    expect(decoded.attributes.mtime).toEqual({ how: DONT_CHANGE });
  });
});

describe("procedure arguments", () => {
  it("round-trips the simple ones", () => {
    roundTrip(writeDirOp, readDirOp, { dir: FH, name: "a file name" });
    roundTrip(writeAccessArgs, readAccessArgs, { object: FH, access: 0x3f });
    roundTrip(writeReadArgs, readReadArgs, { file: FH, offset: 1n << 40n, count: 65_536 });
    roundTrip(writeCommitArgs, readCommitArgs, { file: FH, offset: 8n, count: 16 });
    roundTrip(writeLinkArgs, readLinkArgs, { file: FH, link: { dir: FH, name: "alias" } });
    roundTrip(writeRenameArgs, readRenameArgs, {
      from: { dir: FH, name: "from" },
      to: { dir: FH, name: "to" },
    });
    roundTrip(writeMkdirArgs, readMkdirArgs, {
      where: { dir: FH, name: "dir" },
      attributes: { mode: 0o755, atime: { how: DONT_CHANGE }, mtime: { how: DONT_CHANGE } },
    });
    roundTrip(writeSymlinkArgs, readSymlinkArgs, {
      where: { dir: FH, name: "link" },
      attributes: { atime: { how: DONT_CHANGE }, mtime: { how: DONT_CHANGE } },
      target: "../elsewhere",
    });
    roundTrip(writeReaddirArgs, readReaddirArgs, {
      dir: FH,
      cookie: 12n,
      cookieverf: VERF,
      count: 4096,
    });
    roundTrip(writeReaddirplusArgs, readReaddirplusArgs, {
      dir: FH,
      cookie: 12n,
      cookieverf: VERF,
      dircount: 4096,
      maxcount: 32_768,
    });
  });

  it("round-trips a WRITE, and refuses one whose count disagrees with its data", () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    roundTrip(writeWriteArgs, readWriteArgs, {
      file: FH,
      offset: 99n,
      count: data.byteLength,
      stable: FILE_SYNC,
      data,
    });
    const lying = encodeXdr((writer) =>
      writeWriteArgs(writer, { file: FH, offset: 0n, count: 99, stable: FILE_SYNC, data }),
    );
    expect(() => decodeXdr(lying, (reader) => readWriteArgs(reader))).toThrow(XdrError);
  });

  it("round-trips all three CREATE modes, and only EXCLUSIVE carries a verifier", () => {
    for (const mode of [CREATE_UNCHECKED, CREATE_GUARDED]) {
      roundTrip(writeCreateArgs, readCreateArgs, {
        where: { dir: FH, name: "new" },
        mode,
        attributes: { mode: 0o644, atime: { how: DONT_CHANGE }, mtime: { how: DONT_CHANGE } },
        verf: undefined,
      });
    }
    roundTrip(writeCreateArgs, readCreateArgs, {
      where: { dir: FH, name: "new" },
      mode: CREATE_EXCLUSIVE,
      attributes: undefined,
      verf: VERF,
    });
  });

  it("round-trips every MKNOD union arm", () => {
    const attributes = { mode: 0o666, atime: { how: DONT_CHANGE }, mtime: { how: DONT_CHANGE } };
    for (const type of [NF3CHR, NF3BLK]) {
      roundTrip(writeMknodArgs, readMknodArgs, {
        where: { dir: FH, name: "node" },
        type,
        attributes,
        spec: { major: 1, minor: 3 },
      });
    }
    for (const type of [NF3SOCK, NF3FIFO]) {
      roundTrip(writeMknodArgs, readMknodArgs, {
        where: { dir: FH, name: "node" },
        type,
        attributes,
        spec: undefined,
      });
    }
    // Every other type selects the void arm: nothing follows the ftype3.
    roundTrip(writeMknodArgs, readMknodArgs, {
      where: { dir: FH, name: "node" },
      type: NF3REG,
      attributes: undefined,
      spec: undefined,
    });
  });
});

describe("procedure results", () => {
  it("round-trips LOOKUP, in both arms", () => {
    roundTrip(writeLookupRes, readLookupRes, {
      status: NFS3_OK,
      object: FH,
      objAttributes: ATTR,
      dirAttributes: ATTR,
    });
    roundTrip(writeLookupRes, readLookupRes, {
      status: NFS3ERR_NOENT,
      object: undefined,
      objAttributes: undefined,
      dirAttributes: ATTR,
    });
  });

  it("round-trips ACCESS, READLINK, READ, WRITE and COMMIT", () => {
    roundTrip(writeAccessRes, readAccessRes, { status: NFS3_OK, attributes: ATTR, access: 0x2f });
    roundTrip(writeReadlinkRes, readReadlinkRes, {
      status: NFS3_OK,
      attributes: ATTR,
      target: "target/../path",
    });
    const data = new Uint8Array([7, 7, 7]);
    roundTrip(writeReadRes, readReadRes, {
      status: NFS3_OK,
      attributes: ATTR,
      count: 3,
      eof: true,
      data,
    });
    roundTrip(writeWriteRes, readWriteRes, {
      status: NFS3_OK,
      wcc: WCC,
      count: 3,
      committed: FILE_SYNC,
      verf: VERF,
    });
    roundTrip(writeCommitRes, readCommitRes, { status: NFS3_OK, wcc: WCC, verf: VERF });
  });

  it("refuses a READ whose count disagrees with its data", () => {
    const bytes = encodeXdr((writer) => {
      writer.u32(NFS3_OK);
      writer.bool(false);
      writer.u32(9);
      writer.bool(true);
      writer.varOpaque(new Uint8Array(3));
    });
    expect(() => decodeXdr(bytes, (reader) => readReadRes(reader))).toThrow(XdrError);
  });

  it("round-trips the create-shaped results", () => {
    roundTrip(writeCreateRes, readCreateRes, {
      status: NFS3_OK,
      obj: FH,
      objAttributes: ATTR,
      dirWcc: WCC,
    });
    roundTrip(writeCreateRes, readCreateRes, {
      status: NFS3ERR_NOTSUPP,
      obj: undefined,
      objAttributes: undefined,
      dirWcc: WCC,
    });
    roundTrip(writeRenameRes, readRenameRes, { status: NFS3_OK, fromWcc: WCC, toWcc: WCC });
    roundTrip(writeLinkRes, readLinkRes, { status: NFS3_OK, attributes: ATTR, linkdirWcc: WCC });
  });

  it("round-trips READDIR and READDIRPLUS, including an empty listing", () => {
    roundTrip(writeReaddirRes, readReaddirRes, {
      status: NFS3_OK,
      dirAttributes: ATTR,
      cookieverf: VERF,
      entries: [
        { fileid: 2n, name: "a", cookie: 1n },
        { fileid: 3n, name: "bb", cookie: 2n },
      ],
      eof: true,
    });
    roundTrip(writeReaddirRes, readReaddirRes, {
      status: NFS3_OK,
      dirAttributes: undefined,
      cookieverf: VERF,
      entries: [],
      eof: false,
    });
    roundTrip(writeReaddirplusRes, readReaddirplusRes, {
      status: NFS3_OK,
      dirAttributes: ATTR,
      cookieverf: VERF,
      entries: [
        { fileid: 2n, name: "a", cookie: 1n, attributes: ATTR, handle: FH },
        { fileid: 3n, name: "b", cookie: 2n, attributes: undefined, handle: undefined },
      ],
      eof: true,
    });
  });

  it("sizes entries the way the encoder actually writes them", () => {
    const entries = [
      { fileid: 2n, name: "abc", cookie: 1n },
      { fileid: 3n, name: "de", cookie: 2n },
    ];
    const bytes = encodeXdr((writer) =>
      writeReaddirRes(writer, {
        status: NFS3_OK,
        dirAttributes: undefined,
        cookieverf: VERF,
        entries,
        eof: true,
      }),
    );
    // status(4) + post_op_attr(4) + cookieverf(8) + entries + terminator(4) + eof(4)
    const overhead = 4 + 4 + 8 + 4 + 4;
    expect(bytes.byteLength).toBe(overhead + entrySize(3) + entrySize(2));
    // The plus form adds a post_op_attr (bool + fattr3) and a post_op_fh3
    // (bool + counted opaque) per entry — and the same reply, encoded, agrees.
    expect(entryPlusSize(3, 20, true)).toBe(entrySize(3) + (4 + 84) + (4 + 4 + 20));
    const plus = encodeXdr((writer) =>
      writeReaddirplusRes(writer, {
        status: NFS3_OK,
        dirAttributes: undefined,
        cookieverf: VERF,
        entries: [{ fileid: 2n, name: "abc", cookie: 1n, attributes: ATTR, handle: FH }],
        eof: true,
      }),
    );
    expect(plus.byteLength).toBe(overhead + entryPlusSize(3, FH.byteLength, true));
  });

  it("round-trips FSSTAT, FSINFO and PATHCONF", () => {
    roundTrip(writeFsstatRes, readFsstatRes, {
      status: NFS3_OK,
      attributes: ATTR,
      tbytes: 1n << 40n,
      fbytes: 1n << 39n,
      abytes: 1n << 38n,
      tfiles: 1000n,
      ffiles: 999n,
      afiles: 998n,
      invarsec: 0,
    });
    roundTrip(writeFsinfoRes, readFsinfoRes, {
      status: NFS3_OK,
      attributes: ATTR,
      rtmax: 1 << 20,
      rtpref: 1 << 20,
      rtmult: 4096,
      wtmax: 1 << 20,
      wtpref: 1 << 20,
      wtmult: 4096,
      dtpref: 32_768,
      maxfilesize: 0x7f_ff_ff_ff_ff_ff_ff_ffn,
      timeDelta: { seconds: 0, nseconds: 1_000_000 },
      properties: 0x1b,
    });
    roundTrip(writePathconfRes, readPathconfRes, {
      status: NFS3_OK,
      attributes: ATTR,
      linkmax: 32_000,
      nameMax: 255,
      noTrunc: true,
      chownRestricted: true,
      caseInsensitive: false,
      casePreserving: true,
    });
  });

  it("round-trips the MOUNT protocol's results", () => {
    roundTrip(writeMountRes, readMountRes, { status: 0, fh: FH, authFlavors: [0, 1] });
    roundTrip(writeMountRes, readMountRes, { status: 20, fh: undefined, authFlavors: [] });
    roundTrip(writeMountList, readMountList, [
      { hostname: "127.0.0.1", directory: "/" },
      { hostname: "::1", directory: "/sub" },
    ]);
    roundTrip(writeExportList, readExportList, [
      { directory: "/", groups: [] },
      { directory: "/sub", groups: ["a", "b"] },
    ]);
  });
});

describe("errno mapping", () => {
  it("maps driver errors onto the statuses RFC 1813 allows", () => {
    expect(nfsStatusOf({ code: "ENOENT" })).toBe(NFS3ERR_NOENT);
    expect(nfsStatusOf({ code: "ESTALE" })).toBe(NFS3ERR_STALE);
    expect(nfsStatusOf({ code: "ENOSYS" })).toBe(NFS3ERR_NOTSUPP);
    // `ELOOP` has no NFSv3 status: symlink resolution is the client's job, so
    // a server never has a loop to report.
    expect(nfsStatusOf({ code: "ELOOP" })).toBe(22);
    // Anything unmapped is EIO, the only answer a client can always interpret.
    expect(nfsStatusOf(new Error("nope"))).toBe(5);
    expect(nfsStatusOf(undefined)).toBe(5);
  });

  it("does not mistake an Object.prototype key for a mapped errno", () => {
    // `code in ERRNO_TO_NFS` would find `Object.prototype.toString` and return
    // a *function*, which `writer.u32` coerces to 0 — a `NFS3_OK` status word
    // in front of a failure body, i.e. a decoder desync rather than a wrong
    // answer. Every one of these has to come out as the documented fallback.
    for (const code of ["toString", "constructor", "hasOwnProperty", "__proto__", "valueOf"]) {
      expect(nfsStatusOf({ code }), code).toBe(NFS3ERR_IO);
    }
  });

  it("maps statuses back to POSIX codes", () => {
    expect(errnoCodeOfStatus(NFS3ERR_NOENT)).toBe("ENOENT");
    expect(errnoCodeOfStatus(NFS3ERR_STALE)).toBe("ESTALE");
    // `BADHANDLE` and `STALE` are the same event as far as a client is concerned.
    expect(errnoCodeOfStatus(10_001)).toBe("ESTALE");
    expect(errnoCodeOfStatus(99_999)).toBe("EIO");
    expect(errnoOfStatus(NFS3ERR_NOENT)).toBe(ERRNO_CODES.ENOENT);
    expect(statusName(NFS3_OK)).toBe("NFS3_OK");
    expect(statusName(NFS3ERR_NOENT)).toBe("NFS3ERR(ENOENT)");
    expect(statusName(12_345)).toBe("nfsstat3 12345");
  });

  it("round-trips every mapped status through both directions", () => {
    for (const status of [1, 2, 5, 6, 13, 17, 18, 19, 20, 21, 22, 27, 28, 30, 31, 63, 66, 69, 70]) {
      expect(nfsStatusOf({ code: errnoCodeOfStatus(status) })).toBe(status);
    }
  });
});
