/**
 * NFSv4.1 struct codecs: round trips, union arms, the operation table, and what
 * a decoder does with bytes it should refuse.
 *
 * Tier 0, and the companion to `golden.test.ts`: the fixtures there pin the
 * *layout*, these pin the *behaviour*. Every codec in `src/nfs/v4/protocol.ts`
 * is encoded and decoded here, because that symmetry is what the Tier-1 client
 * will depend on — a struct that only round-trips by accident shows up as a
 * mysterious `NFS4ERR_BADXDR` from a real kernel and nothing else.
 *
 * The hostile-input block is the other half of the contract: **only `XdrError`
 * escapes a decoder**, and no length read off the wire becomes an allocation.
 */

import { describe, expect, it } from "vitest";
import {
  FATTR4_CHANGE,
  FATTR4_FILEID,
  FATTR4_MODE,
  FATTR4_SIZE,
  FATTR4_TIME_ACCESS_SET,
  NF4BLK,
  NF4CHR,
  NF4DIR,
  NF4FIFO,
  NF4LNK,
  NF4REG,
  NF4SOCK,
  NFS4_FHSIZE,
  NFS4_OK,
  NFS4ERR_BADHANDLE,
  NFS4ERR_IO,
  NFS4ERR_NOENT,
  NFS4ERR_NOTSUPP,
  OP_ACCESS,
  OP_COMMIT,
  OP_CREATE,
  OP_GETATTR,
  OP_GETFH,
  OP_ILLEGAL,
  OP_LINK,
  OP_LOOKUP,
  OP_LOOKUPP,
  OP_NVERIFY,
  OP_OPEN,
  OP_PUTFH,
  OP_PUTPUBFH,
  OP_PUTROOTFH,
  OP_READ,
  OP_READDIR,
  OP_READLINK,
  OP_REMOVE,
  OP_RENAME,
  OP_RESTOREFH,
  OP_SAVEFH,
  OP_SECINFO,
  OP_SECINFO_NO_NAME,
  OP_SEQUENCE,
  OP_SETATTR,
  OP_VERIFY,
  opName4,
  SECINFO_STYLE4_CURRENT_FH,
  SECINFO_STYLE4_PARENT,
  SET_TO_CLIENT_TIME4,
  SET_TO_SERVER_TIME4,
} from "../../../src/nfs/v4/constants.ts";
import { bitmapOf } from "../../../src/nfs/v4/attr.ts";
import {
  NFS4_MAX_COMPONENT,
  NFS4_MAX_COMPOUND_OPS,
  NFS4_MAX_SEC_OID,
  NFS4_MAX_TAG,
  OP_CODECS,
  opCodec4,
  readAccessArgs,
  readAccessRes,
  readArgop4,
  readChangeInfo,
  readCommitArgs,
  readCommitRes,
  readCompoundArgs,
  readCompoundRes,
  readCreateArgs,
  readCreateRes,
  readCreateType,
  readFattr4,
  readFh4,
  readGetattrArgs,
  readGetattrRes,
  readGetfhRes,
  readLinkArgs,
  readLinkRes,
  readLookupArgs,
  readPutfhArgs,
  readReaddirArgs,
  readReaddirRes,
  readReadlinkRes,
  readRemoveArgs,
  readRemoveRes,
  readRenameArgs,
  readRenameRes,
  readResop4,
  readSecInfo,
  readSecinfoArgs,
  readSecinfoNoNameArgs,
  readSecinfoRes,
  readSetattrArgs,
  readSetattrRes,
  readStateid,
  readStatusRes,
  readVerifyArgs,
  RPCSEC_GSS,
  writeAccessArgs,
  writeAccessRes,
  writeArgop4,
  writeChangeInfo,
  writeCommitArgs,
  writeCommitRes,
  writeCompoundArgs,
  writeCompoundRes,
  writeCreateArgs,
  writeCreateRes,
  writeCreateType,
  writeFattr4,
  writeFh4,
  writeGetattrArgs,
  writeGetattrRes,
  writeGetfhRes,
  writeLinkArgs,
  writeLinkRes,
  writeLookupArgs,
  writePutfhArgs,
  writeReaddirArgs,
  writeReaddirRes,
  writeReadlinkRes,
  writeRemoveArgs,
  writeRemoveRes,
  writeRenameArgs,
  writeRenameRes,
  writeResop4,
  writeSecInfo,
  writeSecinfoArgs,
  writeSecinfoNoNameArgs,
  writeSecinfoRes,
  writeSetattrArgs,
  writeSetattrRes,
  writeStateid,
  writeStatusRes,
  writeVerifyArgs,
  type Argop4,
  type Compound4args,
  type Fattr4,
  type Resop4,
  type Resop4Value,
} from "../../../src/nfs/v4/protocol.ts";
import { AUTH_NONE, AUTH_SYS } from "../../../src/nfs/rpc.ts";
import {
  decodeXdr,
  encodeXdr,
  isXdrError,
  XdrError,
  XdrReader,
  XdrWriter,
} from "../../../src/nfs/xdr.ts";
import { Rng } from "../../fuse/random.ts";

/** Encode with `write`, decode with `read`, and insist nothing was lost. */
function roundTrip<T>(
  write: (writer: XdrWriter, value: T) => void,
  read: (reader: XdrReader) => T,
  value: T,
): T {
  const bytes = encodeXdr((writer) => write(writer, value));
  expect(bytes.byteLength % 4).toBe(0);
  const decoded = decodeXdr(bytes, read);
  expect(decoded).toEqual(value);
  return decoded;
}

const FH = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05]);
const VERIFIER = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]);
const OTHER = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

const ATTRS: Fattr4 = {
  attrmask: bitmapOf([FATTR4_CHANGE, FATTR4_SIZE, FATTR4_MODE]),
  values: { change: 0x11_22_33_44_55_66_77_88n, size: 987_654_321n, mode: 0o755 },
  unsupported: [],
};

describe("base structs", () => {
  it("round-trips a stateid4", () => {
    roundTrip(writeStateid, readStateid, { seqid: 0x0d_0c_0b_0a, other: OTHER });
  });

  it("copies stateid4.other rather than viewing the record", () => {
    const bytes = encodeXdr((writer) => writeStateid(writer, { seqid: 1, other: OTHER }));
    const decoded = readStateid(new XdrReader(bytes));
    bytes.fill(0xff);
    expect([...decoded.other]).toEqual([...OTHER]);
  });

  it("round-trips a change_info4 in both atomicity arms", () => {
    roundTrip(writeChangeInfo, readChangeInfo, { atomic: true, before: 5n, after: 9n });
    roundTrip(writeChangeInfo, readChangeInfo, {
      atomic: false,
      before: 0xff_ff_ff_ff_ff_ff_ff_ffn,
      after: 0n,
    });
  });

  it("round-trips an nfs_fh4 and copies it", () => {
    const bytes = encodeXdr((writer) => writeFh4(writer, FH));
    const decoded = readFh4(new XdrReader(bytes));
    expect([...decoded]).toEqual([...FH]);
    bytes.fill(0);
    expect([...decoded]).toEqual([...FH]);
  });

  it("round-trips a fattr4 through the attribute codec", () => {
    roundTrip(writeFattr4, readFattr4, ATTRS);
  });

  it("carries a set-only attribute in an argument fattr4", () => {
    // `writeFattr4` allows everything the codec knows, not just what a GETATTR
    // may answer: `time_access_set` is write-only (section 5.5) and a SETATTR
    // argument is exactly where it belongs.
    roundTrip(writeFattr4, readFattr4, {
      attrmask: bitmapOf([FATTR4_TIME_ACCESS_SET]),
      values: {
        timeAccessSet: { how: SET_TO_CLIENT_TIME4, time: { seconds: -5n, nseconds: 1 } },
      },
      unsupported: [],
    });
  });

  it("round-trips a status-only result", () => {
    roundTrip(writeStatusRes, readStatusRes, { status: NFS4ERR_BADHANDLE });
    roundTrip(writeStatusRes, readStatusRes, { status: NFS4_OK });
  });
});

describe("createtype4 (section 18.4)", () => {
  it("carries linkdata for NF4LNK and specdata4 for the device types", () => {
    roundTrip(writeCreateType, readCreateType, { type: NF4LNK, linkdata: "../elsewhere" });
    roundTrip(writeCreateType, readCreateType, {
      type: NF4BLK,
      devdata: { major: 13, minor: 9 },
    });
    roundTrip(writeCreateType, readCreateType, {
      type: NF4CHR,
      devdata: { major: 0xff_ff_ff, minor: 0xff },
    });
  });

  it("carries nothing at all for the void arms", () => {
    for (const type of [NF4SOCK, NF4FIFO, NF4DIR]) {
      const bytes = encodeXdr((writer) => writeCreateType(writer, { type }));
      expect(bytes.byteLength, opName4(type)).toBe(4);
      expect(decodeXdr(bytes, readCreateType)).toEqual({ type });
    }
  });

  it("treats NF4REG as the default (void) arm — CREATE never makes a regular file", () => {
    // Section 18.4: a regular file is OPEN's job, because it needs a stateid.
    // The union's default arm is void and the server answers NFS4ERR_BADTYPE,
    // so the *codec* must read nothing and leave the message framed.
    const bytes = encodeXdr((writer) => writeCreateType(writer, { type: NF4REG }));
    expect(bytes.byteLength).toBe(4);
    expect(decodeXdr(bytes, readCreateType)).toEqual({ type: NF4REG });
  });
});

describe("encoders stay total when a union body is missing", () => {
  // The arm is chosen by the discriminant, not by which fields happen to be
  // set, so an encoder handed `{ type: NF4LNK }` with no `linkdata` still has
  // to write *something* there — the empty/zero value, never a short message
  // that would desync everything after it.
  it("writes an empty linktext4 and a zero specdata4", () => {
    expect(
      decodeXdr(
        encodeXdr((w) => writeCreateType(w, { type: NF4LNK })),
        readCreateType,
      ),
    ).toEqual({ type: NF4LNK, linkdata: "" });
    expect(
      decodeXdr(
        encodeXdr((w) => writeCreateType(w, { type: NF4CHR })),
        readCreateType,
      ),
    ).toEqual({ type: NF4CHR, devdata: { major: 0, minor: 0 } });
  });

  it("writes an empty attrset when CREATE succeeded but named none", () => {
    const cinfo = { atomic: true, before: 1n, after: 2n };
    expect(
      decodeXdr(
        encodeXdr((w) => writeCreateRes(w, { status: NFS4_OK, cinfo, attrset: undefined })),
        readCreateRes,
      ),
    ).toEqual({ status: NFS4_OK, cinfo, attrset: [] });
  });

  it("writes an empty rpcsec_gss_info for a bodiless RPCSEC_GSS flavor", () => {
    expect(
      decodeXdr(
        encodeXdr((w) => writeSecInfo(w, { flavor: RPCSEC_GSS })),
        readSecInfo,
      ),
    ).toEqual({ flavor: RPCSEC_GSS, info: { oid: new Uint8Array(0), qop: 0, service: 0 } });
  });
});

describe("secinfo4 (section 18.29)", () => {
  it("carries a body only under RPCSEC_GSS", () => {
    for (const flavor of [AUTH_NONE, AUTH_SYS, 42]) {
      const bytes = encodeXdr((writer) => writeSecInfo(writer, { flavor }));
      expect(bytes.byteLength, `flavor ${flavor}`).toBe(4);
      expect(decodeXdr(bytes, readSecInfo)).toEqual({ flavor });
    }
    roundTrip(writeSecInfo, readSecInfo, {
      flavor: RPCSEC_GSS,
      info: { oid: new Uint8Array([0x2a, 0x86, 0x48]), qop: 7, service: 3 },
    });
  });

  it("copies the mechanism OID out of the record", () => {
    const bytes = encodeXdr((writer) =>
      writeSecInfo(writer, {
        flavor: RPCSEC_GSS,
        info: { oid: new Uint8Array([1, 2, 3, 4]), qop: 1, service: 1 },
      }),
    );
    const decoded = readSecInfo(new XdrReader(bytes));
    bytes.fill(0);
    expect([...(decoded.info?.oid ?? [])]).toEqual([1, 2, 3, 4]);
  });
});

describe("per-operation round trips", () => {
  it("PUTFH / LOOKUP / SECINFO / SECINFO_NO_NAME arguments", () => {
    roundTrip(writePutfhArgs, readPutfhArgs, { object: FH });
    roundTrip(writeLookupArgs, readLookupArgs, { objname: "a name with spaces" });
    roundTrip(writeSecinfoArgs, readSecinfoArgs, { name: "secret" });
    roundTrip(writeSecinfoNoNameArgs, readSecinfoNoNameArgs, {
      style: SECINFO_STYLE4_CURRENT_FH,
    });
    roundTrip(writeSecinfoNoNameArgs, readSecinfoNoNameArgs, { style: SECINFO_STYLE4_PARENT });
  });

  it("GETATTR both ways", () => {
    roundTrip(writeGetattrArgs, readGetattrArgs, { attrRequest: bitmapOf([FATTR4_SIZE]) });
    roundTrip(writeGetattrArgs, readGetattrArgs, { attrRequest: [] });
    roundTrip(writeGetattrRes, readGetattrRes, { status: NFS4_OK, objAttributes: ATTRS });
    roundTrip(writeGetattrRes, readGetattrRes, {
      status: NFS4ERR_NOENT,
      objAttributes: undefined,
    });
  });

  it("GETFH both ways", () => {
    roundTrip(writeGetfhRes, readGetfhRes, { status: NFS4_OK, object: FH });
    roundTrip(writeGetfhRes, readGetfhRes, { status: NFS4ERR_BADHANDLE, object: undefined });
  });

  it("SETATTR both ways, with attrsset on either status", () => {
    roundTrip(writeSetattrArgs, readSetattrArgs, {
      stateid: { seqid: 3, other: OTHER },
      objAttributes: ATTRS,
    });
    roundTrip(writeSetattrRes, readSetattrRes, {
      status: NFS4_OK,
      attrsset: bitmapOf([FATTR4_SIZE, FATTR4_MODE]),
    });
    roundTrip(writeSetattrRes, readSetattrRes, {
      status: NFS4ERR_NOTSUPP,
      attrsset: bitmapOf([FATTR4_MODE]),
    });
    roundTrip(writeSetattrRes, readSetattrRes, { status: NFS4ERR_IO, attrsset: [] });
  });

  it("ACCESS both ways", () => {
    roundTrip(writeAccessArgs, readAccessArgs, { access: 0x3f });
    roundTrip(writeAccessRes, readAccessRes, { status: NFS4_OK, supported: 0x3f, access: 0x21 });
    roundTrip(writeAccessRes, readAccessRes, { status: NFS4ERR_IO, supported: 0, access: 0 });
  });

  it("READLINK both ways", () => {
    roundTrip(writeReadlinkRes, readReadlinkRes, { status: NFS4_OK, link: "/a/b/c" });
    roundTrip(writeReadlinkRes, readReadlinkRes, { status: NFS4_OK, link: "" });
    roundTrip(writeReadlinkRes, readReadlinkRes, { status: NFS4ERR_IO, link: undefined });
  });

  it("READDIR both ways, including an empty and a single-entry list", () => {
    roundTrip(writeReaddirArgs, readReaddirArgs, {
      cookie: 0n,
      cookieverf: new Uint8Array(8),
      dircount: 8192,
      maxcount: 32_768,
      attrRequest: bitmapOf([FATTR4_FILEID, FATTR4_SIZE]),
    });
    roundTrip(writeReaddirRes, readReaddirRes, {
      status: NFS4_OK,
      cookieverf: VERIFIER,
      reply: { entries: [], eof: true },
    });
    roundTrip(writeReaddirRes, readReaddirRes, {
      status: NFS4_OK,
      cookieverf: VERIFIER,
      reply: {
        entries: [
          { cookie: 1n, name: "one", attrs: ATTRS },
          { cookie: 0xff_ff_ff_ff_ff_ff_ff_ffn, name: "two", attrs: ATTRS },
        ],
        eof: false,
      },
    });
    roundTrip(writeReaddirRes, readReaddirRes, {
      status: NFS4ERR_NOENT,
      cookieverf: new Uint8Array(8),
      reply: { entries: [], eof: false },
    });
  });

  it("LINK / REMOVE / RENAME both ways", () => {
    roundTrip(writeLinkArgs, readLinkArgs, { newname: "link" });
    roundTrip(writeLinkRes, readLinkRes, {
      status: NFS4_OK,
      cinfo: { atomic: false, before: 1n, after: 2n },
    });
    roundTrip(writeLinkRes, readLinkRes, { status: NFS4ERR_IO, cinfo: undefined });

    roundTrip(writeRemoveArgs, readRemoveArgs, { target: "victim" });
    roundTrip(writeRemoveRes, readRemoveRes, {
      status: NFS4_OK,
      cinfo: { atomic: true, before: 7n, after: 8n },
    });
    roundTrip(writeRemoveRes, readRemoveRes, { status: NFS4ERR_NOENT, cinfo: undefined });

    roundTrip(writeRenameArgs, readRenameArgs, { oldname: "from", newname: "to" });
    roundTrip(writeRenameRes, readRenameRes, {
      status: NFS4_OK,
      sourceCinfo: { atomic: true, before: 1n, after: 2n },
      targetCinfo: { atomic: false, before: 3n, after: 4n },
    });
    roundTrip(writeRenameRes, readRenameRes, {
      status: NFS4ERR_IO,
      sourceCinfo: undefined,
      targetCinfo: undefined,
    });
  });

  it("CREATE both ways", () => {
    roundTrip(writeCreateArgs, readCreateArgs, {
      objtype: { type: NF4DIR },
      objname: "subdir",
      createattrs: {
        attrmask: bitmapOf([FATTR4_MODE]),
        values: { mode: 0o750 },
        unsupported: [],
      },
    });
    roundTrip(writeCreateRes, readCreateRes, {
      status: NFS4_OK,
      cinfo: { atomic: true, before: 10n, after: 11n },
      attrset: bitmapOf([FATTR4_MODE]),
    });
    roundTrip(writeCreateRes, readCreateRes, {
      status: NFS4ERR_IO,
      cinfo: undefined,
      attrset: undefined,
    });
  });

  it("COMMIT both ways", () => {
    roundTrip(writeCommitArgs, readCommitArgs, { offset: 0n, count: 0 });
    roundTrip(writeCommitArgs, readCommitArgs, {
      offset: 0xff_ff_ff_ff_ff_ff_ff_fen,
      count: 0xff_ff_ff_ff,
    });
    roundTrip(writeCommitRes, readCommitRes, { status: NFS4_OK, writeverf: VERIFIER });
    roundTrip(writeCommitRes, readCommitRes, {
      status: NFS4ERR_IO,
      writeverf: new Uint8Array(8),
    });
  });

  it("VERIFY / NVERIFY arguments are the same bare fattr4", () => {
    roundTrip(writeVerifyArgs, readVerifyArgs, { objAttributes: ATTRS });
    const bytes = encodeXdr((writer) => writeVerifyArgs(writer, { objAttributes: ATTRS }));
    expect(decodeXdr(bytes, readVerifyArgs)).toEqual({ objAttributes: ATTRS });
  });

  it("SECINFO results both ways", () => {
    roundTrip(writeSecinfoRes, readSecinfoRes, {
      status: NFS4_OK,
      flavors: [{ flavor: AUTH_SYS }, { flavor: AUTH_NONE }],
    });
    roundTrip(writeSecinfoRes, readSecinfoRes, { status: NFS4_OK, flavors: [] });
    roundTrip(writeSecinfoRes, readSecinfoRes, { status: NFS4ERR_NOENT, flavors: [] });
  });

  it("keeps SET_TO_SERVER_TIME4 bodiless inside a SETATTR fattr4", () => {
    roundTrip(writeSetattrArgs, readSetattrArgs, {
      stateid: { seqid: 0, other: new Uint8Array(12) },
      objAttributes: {
        attrmask: bitmapOf([FATTR4_TIME_ACCESS_SET]),
        values: { timeAccessSet: { how: SET_TO_SERVER_TIME4 } },
        unsupported: [],
      },
    });
  });
});

describe("the operation table", () => {
  /** Exactly the operations step 4 covers, in `nfs_opnum4` order. */
  const IMPLEMENTED = [
    OP_ACCESS,
    OP_COMMIT,
    OP_CREATE,
    OP_GETATTR,
    OP_GETFH,
    OP_LINK,
    OP_LOOKUP,
    OP_LOOKUPP,
    OP_NVERIFY,
    OP_PUTFH,
    OP_PUTPUBFH,
    OP_PUTROOTFH,
    OP_READDIR,
    OP_READLINK,
    OP_REMOVE,
    OP_RENAME,
    OP_RESTOREFH,
    OP_SAVEFH,
    OP_SECINFO,
    OP_SETATTR,
    OP_VERIFY,
    OP_SECINFO_NO_NAME,
    OP_ILLEGAL,
  ];

  /** The `nfs_argop4` arms RFC 5662 declares `void`. */
  const VOID_ARGS = [
    OP_GETFH,
    OP_LOOKUPP,
    OP_PUTPUBFH,
    OP_PUTROOTFH,
    OP_READLINK,
    OP_RESTOREFH,
    OP_SAVEFH,
    OP_ILLEGAL,
  ];

  it("carries every stateless operation and nothing else", () => {
    expect([...OP_CODECS.keys()].sort((a, b) => a - b)).toEqual(
      [...IMPLEMENTED].sort((a, b) => a - b),
    );
  });

  it("names each row after its opcode", () => {
    for (const [op, codec] of OP_CODECS) {
      expect(codec.op).toBe(op);
      expect(codec.name).toBe(opName4(op));
    }
  });

  it("leaves readArgs and writeArgs undefined exactly for the void arms", () => {
    for (const [op, codec] of OP_CODECS) {
      const isVoid = VOID_ARGS.includes(op);
      expect(codec.readArgs === undefined, opName4(op)).toBe(isVoid);
      expect(codec.writeArgs === undefined, opName4(op)).toBe(isVoid);
    }
  });

  it("points SECINFO_NO_NAME at SECINFO's result — they are the same typedef", () => {
    expect(opCodec4(OP_SECINFO_NO_NAME).readRes).toBe(opCodec4(OP_SECINFO).readRes);
    expect(opCodec4(OP_SECINFO_NO_NAME).writeRes).toBe(opCodec4(OP_SECINFO).writeRes);
  });

  it("refuses an operation it does not carry, naming it", () => {
    // Defined by NFSv4.1, not implemented here yet: the message has to say
    // which one, because "this table is half built" and "that opcode does not
    // exist" are different bugs.
    expect(() => opCodec4(OP_SEQUENCE)).toThrow(XdrError);
    expect(() => opCodec4(OP_SEQUENCE)).toThrow("OP_SEQUENCE");
    expect(() => opCodec4(OP_OPEN)).toThrow("OP_OPEN");
    expect(() => opCodec4(OP_READ)).toThrow("OP_READ");
    // Not an operation at all.
    expect(() => opCodec4(99)).toThrow("nfs_opnum4 99");
    expect(() => opCodec4(0)).toThrow("nfs_opnum4 0");
  });

  it("writes every failure as the opcode and the status, SETATTR excepted", () => {
    // Every result but SETATTR's is `union switch (nfsstat4)` with a void
    // default arm, so a failed operation is eight bytes on the wire.
    for (const op of OP_CODECS.keys()) {
      // SETATTR is the exception in both directions: its `attrsset` is present
      // whatever the status, so a failure still has to carry one.
      const res: Resop4Value =
        op === OP_SETATTR ? { status: NFS4ERR_IO, attrsset: [] } : { status: NFS4ERR_IO };
      const bytes = encodeXdr((writer) => writeResop4(writer, { op, res }));
      expect(bytes.byteLength, opName4(op)).toBe(op === OP_SETATTR ? 12 : 8);
      const decoded = decodeXdr(bytes, readResop4);
      expect(decoded.op, opName4(op)).toBe(op);
      expect(decoded.res.status, opName4(op)).toBe(NFS4ERR_IO);
    }
  });

  it("writes a void-argument operation as four bytes", () => {
    for (const op of VOID_ARGS) {
      const bytes = encodeXdr((writer) => writeArgop4(writer, { op, args: undefined }));
      expect(bytes.byteLength, opName4(op)).toBe(4);
      expect(decodeXdr(bytes, readArgop4)).toEqual({ op, args: undefined });
    }
  });

  it("refuses to write an operation that needs arguments without them", () => {
    expect(() =>
      encodeXdr((writer) => writeArgop4(writer, { op: OP_LOOKUP, args: undefined })),
    ).toThrow(XdrError);
    expect(() =>
      encodeXdr((writer) => writeArgop4(writer, { op: OP_LOOKUP, args: undefined })),
    ).toThrow("OP_LOOKUP");
  });

  it("round-trips an argop and a resop for every implemented operation", () => {
    const argops: Argop4[] = [
      { op: OP_ACCESS, args: { access: 1 } },
      { op: OP_COMMIT, args: { offset: 4n, count: 8 } },
      {
        op: OP_CREATE,
        args: {
          objtype: { type: NF4LNK, linkdata: "x" },
          objname: "y",
          createattrs: ATTRS,
        },
      },
      { op: OP_GETATTR, args: { attrRequest: bitmapOf([FATTR4_SIZE]) } },
      { op: OP_GETFH, args: undefined },
      { op: OP_LINK, args: { newname: "l" } },
      { op: OP_LOOKUP, args: { objname: "d" } },
      { op: OP_LOOKUPP, args: undefined },
      { op: OP_NVERIFY, args: { objAttributes: ATTRS } },
      { op: OP_PUTFH, args: { object: FH } },
      { op: OP_PUTPUBFH, args: undefined },
      { op: OP_PUTROOTFH, args: undefined },
      {
        op: OP_READDIR,
        args: {
          cookie: 2n,
          cookieverf: VERIFIER,
          dircount: 1,
          maxcount: 2,
          attrRequest: bitmapOf([FATTR4_FILEID]),
        },
      },
      { op: OP_READLINK, args: undefined },
      { op: OP_REMOVE, args: { target: "r" } },
      { op: OP_RENAME, args: { oldname: "o", newname: "n" } },
      { op: OP_RESTOREFH, args: undefined },
      { op: OP_SAVEFH, args: undefined },
      { op: OP_SECINFO, args: { name: "s" } },
      { op: OP_SECINFO_NO_NAME, args: { style: SECINFO_STYLE4_PARENT } },
      { op: OP_SETATTR, args: { stateid: { seqid: 1, other: OTHER }, objAttributes: ATTRS } },
      { op: OP_VERIFY, args: { objAttributes: ATTRS } },
      { op: OP_ILLEGAL, args: undefined },
    ];
    expect(argops.map((argop) => argop.op).sort((a, b) => a - b)).toEqual(
      [...OP_CODECS.keys()].sort((a, b) => a - b),
    );
    for (const argop of argops) {
      roundTrip(writeArgop4, readArgop4, argop);
    }

    const resops: Resop4[] = [
      { op: OP_ACCESS, res: { status: NFS4_OK, supported: 3, access: 1 } },
      { op: OP_COMMIT, res: { status: NFS4_OK, writeverf: VERIFIER } },
      {
        op: OP_CREATE,
        res: {
          status: NFS4_OK,
          cinfo: { atomic: true, before: 1n, after: 2n },
          attrset: bitmapOf([FATTR4_MODE]),
        },
      },
      { op: OP_GETATTR, res: { status: NFS4_OK, objAttributes: ATTRS } },
      { op: OP_GETFH, res: { status: NFS4_OK, object: FH } },
      { op: OP_LINK, res: { status: NFS4_OK, cinfo: { atomic: false, before: 3n, after: 4n } } },
      { op: OP_LOOKUP, res: { status: NFS4_OK } },
      { op: OP_LOOKUPP, res: { status: NFS4_OK } },
      { op: OP_NVERIFY, res: { status: NFS4_OK } },
      { op: OP_PUTFH, res: { status: NFS4_OK } },
      { op: OP_PUTPUBFH, res: { status: NFS4_OK } },
      { op: OP_PUTROOTFH, res: { status: NFS4_OK } },
      {
        op: OP_READDIR,
        res: {
          status: NFS4_OK,
          cookieverf: VERIFIER,
          reply: { entries: [{ cookie: 1n, name: "e", attrs: ATTRS }], eof: true },
        },
      },
      { op: OP_READLINK, res: { status: NFS4_OK, link: "target" } },
      { op: OP_REMOVE, res: { status: NFS4_OK, cinfo: { atomic: true, before: 5n, after: 6n } } },
      {
        op: OP_RENAME,
        res: {
          status: NFS4_OK,
          sourceCinfo: { atomic: true, before: 7n, after: 8n },
          targetCinfo: { atomic: false, before: 9n, after: 10n },
        },
      },
      { op: OP_RESTOREFH, res: { status: NFS4_OK } },
      { op: OP_SAVEFH, res: { status: NFS4_OK } },
      { op: OP_SECINFO, res: { status: NFS4_OK, flavors: [{ flavor: AUTH_SYS }] } },
      { op: OP_SECINFO_NO_NAME, res: { status: NFS4_OK, flavors: [{ flavor: AUTH_NONE }] } },
      { op: OP_SETATTR, res: { status: NFS4_OK, attrsset: bitmapOf([FATTR4_SIZE]) } },
      { op: OP_VERIFY, res: { status: NFS4_OK } },
      { op: OP_ILLEGAL, res: { status: NFS4ERR_NOTSUPP } },
    ];
    expect(resops.map((resop) => resop.op).sort((a, b) => a - b)).toEqual(
      [...OP_CODECS.keys()].sort((a, b) => a - b),
    );
    for (const resop of resops) {
      roundTrip(writeResop4, readResop4, resop);
    }
  });
});

describe("COMPOUND framing (section 16.2)", () => {
  const COMPOUND: Compound4args = {
    tag: "a tag",
    minorversion: 1,
    argarray: [
      { op: OP_PUTROOTFH, args: undefined },
      { op: OP_LOOKUP, args: { objname: "usr" } },
      { op: OP_LOOKUP, args: { objname: "share" } },
      { op: OP_GETATTR, args: { attrRequest: bitmapOf([FATTR4_SIZE, FATTR4_MODE]) } },
      { op: OP_GETFH, args: undefined },
    ],
  };

  it("round-trips a multi-operation COMPOUND4args", () => {
    roundTrip(writeCompoundArgs, readCompoundArgs, COMPOUND);
  });

  it("round-trips an empty argarray and an empty tag", () => {
    roundTrip(writeCompoundArgs, readCompoundArgs, {
      tag: "",
      minorversion: 1,
      argarray: [],
    });
  });

  it("keeps a minorversion it does not implement — that is the session's answer", () => {
    // A COMPOUND naming minor version 0 or 2 decodes fine and is refused with
    // NFS4ERR_MINOR_VERS_MISMATCH by the session (section 16.2.3), not here.
    for (const minorversion of [0, 2, 0xff_ff_ff_ff]) {
      const decoded = roundTrip(writeCompoundArgs, readCompoundArgs, {
        tag: "v",
        minorversion,
        argarray: [],
      });
      expect(decoded.minorversion).toBe(minorversion);
    }
  });

  it("round-trips a multi-operation COMPOUND4res that stops at a failure", () => {
    roundTrip(writeCompoundRes, readCompoundRes, {
      // Section 16.2.3: the compound's status is the last executed operation's.
      status: NFS4ERR_NOENT,
      tag: "a tag",
      resarray: [
        { op: OP_PUTROOTFH, res: { status: NFS4_OK } },
        { op: OP_LOOKUP, res: { status: NFS4_OK } },
        { op: OP_LOOKUP, res: { status: NFS4ERR_NOENT } },
      ],
    });
  });

  it("round-trips a COMPOUND4res with no results at all", () => {
    // What NFS4ERR_MINOR_VERS_MISMATCH looks like: a status and a zero-length
    // result array.
    roundTrip(writeCompoundRes, readCompoundRes, { status: 10_021, tag: "", resarray: [] });
  });
});

describe("hostile input", () => {
  /** Every proper prefix of `bytes` must be refused with an `XdrError`. */
  function everyTruncationFails(
    what: string,
    bytes: Uint8Array,
    read: (reader: XdrReader) => unknown,
  ): void {
    expect(bytes.byteLength % 4).toBe(0);
    for (let length = 0; length < bytes.byteLength; length += 4) {
      expect(
        () => decodeXdr(bytes.subarray(0, length), read),
        `${what} truncated to ${length} bytes`,
      ).toThrow(XdrError);
    }
  }

  it("refuses every truncation of a COMPOUND, in both directions", () => {
    everyTruncationFails(
      "COMPOUND4args",
      encodeXdr((writer) =>
        writeCompoundArgs(writer, {
          tag: "tag",
          minorversion: 1,
          argarray: [
            { op: OP_PUTFH, args: { object: FH } },
            { op: OP_GETATTR, args: { attrRequest: bitmapOf([FATTR4_SIZE]) } },
          ],
        }),
      ),
      readCompoundArgs,
    );
    everyTruncationFails(
      "COMPOUND4res",
      encodeXdr((writer) =>
        writeCompoundRes(writer, {
          status: NFS4_OK,
          tag: "tag",
          resarray: [
            { op: OP_PUTFH, res: { status: NFS4_OK } },
            { op: OP_GETFH, res: { status: NFS4_OK, object: FH } },
          ],
        }),
      ),
      readCompoundRes,
    );
  });

  it("refuses every truncation of the structs with variable-length bodies", () => {
    everyTruncationFails(
      "READDIR4res",
      encodeXdr((writer) =>
        writeReaddirRes(writer, {
          status: NFS4_OK,
          cookieverf: VERIFIER,
          reply: {
            entries: [
              { cookie: 1n, name: "one", attrs: ATTRS },
              { cookie: 2n, name: "two", attrs: ATTRS },
            ],
            eof: true,
          },
        }),
      ),
      readReaddirRes,
    );
    everyTruncationFails(
      "CREATE4args",
      encodeXdr((writer) =>
        writeCreateArgs(writer, {
          objtype: { type: NF4LNK, linkdata: "elsewhere" },
          objname: "name",
          createattrs: ATTRS,
        }),
      ),
      readCreateArgs,
    );
    everyTruncationFails(
      "SETATTR4args",
      encodeXdr((writer) =>
        writeSetattrArgs(writer, {
          stateid: { seqid: 1, other: OTHER },
          objAttributes: ATTRS,
        }),
      ),
      readSetattrArgs,
    );
    everyTruncationFails(
      "SECINFO4res",
      encodeXdr((writer) =>
        writeSecinfoRes(writer, {
          status: NFS4_OK,
          flavors: [
            { flavor: AUTH_SYS },
            { flavor: RPCSEC_GSS, info: { oid: new Uint8Array([1, 2, 3]), qop: 1, service: 2 } },
          ],
        }),
      ),
      readSecinfoRes,
    );
  });

  it("refuses a tag longer than the codec will hold", () => {
    // Only the length word is needed: the check happens before anything is
    // allocated, which is the point of it.
    const bytes = encodeXdr((writer) => writer.u32(NFS4_MAX_TAG + 1));
    expect(() => readCompoundArgs(new XdrReader(bytes))).toThrow(XdrError);
  });

  it("refuses a COMPOUND declaring more operations than it will hold", () => {
    // A count of 4097 with room for 4097 four-byte items: the *count* cap has
    // to fire, not the incidental "that cannot fit in these bytes" one.
    const count = NFS4_MAX_COMPOUND_OPS + 1;
    const bytes = encodeXdr((writer) => {
      writer.string("");
      writer.u32(1);
      writer.u32(count);
      writer.raw(new Uint8Array(count * 4));
    });
    expect(bytes.byteLength).toBe(12 + count * 4);
    expect(() => readCompoundArgs(new XdrReader(bytes))).toThrow(XdrError);
    // And the four-billion case, which cannot fit and must not be allocated.
    const absurd = encodeXdr((writer) => {
      writer.string("");
      writer.u32(1);
      writer.u32(0xff_ff_ff_ff);
    });
    expect(() => readCompoundArgs(new XdrReader(absurd))).toThrow(XdrError);
  });

  it("refuses an over-long filehandle, name, symlink target and OID", () => {
    expect(() => readPutfhArgs(new XdrReader(encodeXdr((w) => w.u32(NFS4_FHSIZE + 1))))).toThrow(
      XdrError,
    );
    expect(() =>
      readLookupArgs(new XdrReader(encodeXdr((w) => w.u32(NFS4_MAX_COMPONENT + 1)))),
    ).toThrow(XdrError);
    expect(() =>
      readSecInfo(
        new XdrReader(
          encodeXdr((w) => {
            w.u32(RPCSEC_GSS);
            w.u32(NFS4_MAX_SEC_OID + 1);
          }),
        ),
      ),
    ).toThrow(XdrError);
  });

  it("bounds an entry4 chain by the bytes it has, not by the client's say-so", () => {
    // A dirlist4 is a linked list: "another one follows" is a bool, and a
    // hostile stream of them has no count to check. What stops it is that every
    // entry consumes bytes — so the chain dies at the end of the message rather
    // than looping or allocating.
    const bytes = encodeXdr((writer) => {
      writer.u32(NFS4_OK);
      writer.fixedOpaque(VERIFIER, 8);
      for (let index = 0; index < 4096; index++) {
        writer.bool(true);
      }
    });
    expect(() => readReaddirRes(new XdrReader(bytes))).toThrow(XdrError);
  });

  it("refuses an unknown opcode in an argop and in a resop", () => {
    const argop = encodeXdr((writer) => writer.u32(99));
    expect(() => readArgop4(new XdrReader(argop))).toThrow("nfs_opnum4 99");
    expect(() => readResop4(new XdrReader(argop))).toThrow("nfs_opnum4 99");
    // Operation 2 is reserved and has never been defined for COMPOUND.
    const reserved = encodeXdr((writer) => writer.u32(2));
    expect(() => readArgop4(new XdrReader(reserved))).toThrow(XdrError);
  });

  it("lets only XdrError escape any decoder, on any bytes", () => {
    const decoders: [string, (reader: XdrReader) => unknown][] = [
      ["readStateid", readStateid],
      ["readChangeInfo", readChangeInfo],
      ["readFattr4", readFattr4],
      ["readCreateType", readCreateType],
      ["readSecInfo", readSecInfo],
      ["readAccessArgs", readAccessArgs],
      ["readAccessRes", readAccessRes],
      ["readCommitArgs", readCommitArgs],
      ["readCommitRes", readCommitRes],
      ["readCreateArgs", readCreateArgs],
      ["readCreateRes", readCreateRes],
      ["readGetattrArgs", readGetattrArgs],
      ["readGetattrRes", readGetattrRes],
      ["readGetfhRes", readGetfhRes],
      ["readLinkArgs", readLinkArgs],
      ["readLinkRes", readLinkRes],
      ["readLookupArgs", readLookupArgs],
      ["readPutfhArgs", readPutfhArgs],
      ["readReaddirArgs", readReaddirArgs],
      ["readReaddirRes", readReaddirRes],
      ["readReadlinkRes", readReadlinkRes],
      ["readRemoveArgs", readRemoveArgs],
      ["readRemoveRes", readRemoveRes],
      ["readRenameArgs", readRenameArgs],
      ["readRenameRes", readRenameRes],
      ["readSecinfoArgs", readSecinfoArgs],
      ["readSecinfoNoNameArgs", readSecinfoNoNameArgs],
      ["readSecinfoRes", readSecinfoRes],
      ["readSetattrArgs", readSetattrArgs],
      ["readSetattrRes", readSetattrRes],
      ["readStatusRes", readStatusRes],
      ["readVerifyArgs", readVerifyArgs],
      ["readArgop4", readArgop4],
      ["readResop4", readResop4],
      ["readCompoundArgs", readCompoundArgs],
      ["readCompoundRes", readCompoundRes],
    ];
    const rng = new Rng(0x4f_53_04);
    let decoded = 0;
    for (let round = 0; round < 4000; round++) {
      const [name, decode] = decoders[rng.int(decoders.length)]!;
      const bytes = rng.bytes(rng.int(160));
      try {
        decode(new XdrReader(bytes));
        decoded++;
      } catch (error) {
        if (!isXdrError(error)) {
          throw new Error(
            `${name} threw ${(error as Error)?.constructor?.name ?? typeof error}: ${
              (error as Error)?.message
            }`,
            { cause: error },
          );
        }
      }
    }
    // Some inputs are valid by luck, which is what proves the fuzzer reaches
    // past the first length check and into the struct bodies.
    expect(decoded).toBeGreaterThan(0);
  });
});
