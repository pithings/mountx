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
  CDFC4_FORE_OR_BOTH,
  CDFS4_BOTH,
  CLAIM_DELEG_CUR_FH,
  CLAIM_DELEG_PREV_FH,
  CLAIM_DELEGATE_CUR,
  CLAIM_DELEGATE_PREV,
  CLAIM_FH,
  CLAIM_NULL,
  CLAIM_PREVIOUS,
  DATA_SYNC4,
  EXCLUSIVE4,
  EXCLUSIVE4_1,
  FATTR4_CHANGE,
  FATTR4_FILEID,
  FATTR4_MODE,
  FATTR4_SIZE,
  FATTR4_TIME_ACCESS_SET,
  FILE_SYNC4,
  GUARDED4,
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
  NFS4_OPAQUE_LIMIT,
  NFS4ERR_DENIED,
  NFS4ERR_GRACE,
  NFS_LIMIT_BLOCKS,
  NFS_LIMIT_SIZE,
  OP_ACCESS,
  OP_BACKCHANNEL_CTL,
  OP_BIND_CONN_TO_SESSION,
  OP_CLOSE,
  OP_COMMIT,
  OP_CREATE,
  OP_CREATE_SESSION,
  OP_DELEGRETURN,
  OP_DESTROY_CLIENTID,
  OP_DESTROY_SESSION,
  OP_EXCHANGE_ID,
  OP_FREE_STATEID,
  OP_GETATTR,
  OP_GETDEVICEINFO,
  OP_GETFH,
  OP_ILLEGAL,
  OP_LAYOUTGET,
  OP_LINK,
  OP_LOCK,
  OP_LOCKT,
  OP_LOCKU,
  OP_LOOKUP,
  OP_LOOKUPP,
  OP_NVERIFY,
  OP_OPEN,
  OP_OPEN_DOWNGRADE,
  OP_OPENATTR,
  OP_PUTFH,
  OP_PUTPUBFH,
  OP_PUTROOTFH,
  OP_READ,
  OP_READDIR,
  OP_READLINK,
  OP_RECLAIM_COMPLETE,
  OP_REMOVE,
  OP_RENAME,
  OP_RESTOREFH,
  OP_SAVEFH,
  OP_SECINFO,
  OP_SECINFO_NO_NAME,
  OP_SEQUENCE,
  OP_SETATTR,
  OP_TEST_STATEID,
  OP_VERIFY,
  OP_WRITE,
  OPEN4_CREATE,
  OPEN4_NOCREATE,
  OPEN4_SHARE_ACCESS_BOTH,
  OPEN4_SHARE_ACCESS_READ,
  OPEN4_SHARE_DENY_NONE,
  OPEN4_SHARE_DENY_WRITE,
  OPEN_DELEGATE_NONE,
  OPEN_DELEGATE_NONE_EXT,
  OPEN_DELEGATE_READ,
  OPEN_DELEGATE_WRITE,
  opName4,
  READ_LT,
  SECINFO_STYLE4_CURRENT_FH,
  SECINFO_STYLE4_PARENT,
  SET_TO_CLIENT_TIME4,
  SET_TO_SERVER_TIME4,
  SP4_MACH_CRED,
  SP4_NONE,
  SP4_SSV,
  UNCHECKED4,
  UNSTABLE4,
  WND4_CONTENTION,
  WND4_NOT_WANTED,
  WND4_RESOURCE,
  WRITE_LT,
  WRITEW_LT,
} from "../../../src/nfs/v4/constants.ts";
import { bitmapOf } from "../../../src/nfs/v4/attr.ts";
import {
  NFS4_MAX_COMPONENT,
  NFS4_MAX_COMPOUND_OPS,
  NFS4_MAX_OPTIONAL_ONE,
  NFS4_MAX_SEC_OID,
  NFS4_MAX_SEC_PARMS,
  NFS4_MAX_TAG,
  NFS4_MAX_TEST_STATEIDS,
  OP_CODECS,
  opCodec4,
  readAccessArgs,
  readAccessRes,
  readArgop4,
  readAuthSysParms,
  readBackchannelCtlArgs,
  readBindConnToSessionArgs,
  readBindConnToSessionRes,
  readCallbackSecParms4,
  readChangeInfo,
  readChannelAttrs4,
  readClientOwner4,
  readCloseArgs,
  readCloseRes,
  readCommitArgs,
  readCommitRes,
  readCreateHow4,
  readCompoundArgs,
  readCompoundRes,
  readCreateArgs,
  readCreateRes,
  readCreateSessionArgs,
  readCreateSessionRes,
  readCreateType,
  readDestroyClientidArgs,
  readDestroySessionArgs,
  readExchangeIdArgs,
  readExchangeIdRes,
  readFattr4,
  readFh4,
  readFreeStateidArgs,
  readGetattrArgs,
  readGetattrRes,
  readGetfhRes,
  readGssCbHandles4,
  readImplId4,
  readLinkArgs,
  readLinkRes,
  readLock4denied,
  readLockArgs,
  readLocker4,
  readLockRes,
  readLocktArgs,
  readLocktRes,
  readLockuArgs,
  readLockuRes,
  readLookupArgs,
  readNfsace4,
  readOpenArgs,
  readOpenClaim4,
  readOpenDelegation4,
  readOpenDowngradeArgs,
  readOpenDowngradeRes,
  readOpenFlag4,
  readOpenNoneDelegation4,
  readOpenRes,
  readOpenToLockOwner4,
  readPutfhArgs,
  readReadArgs,
  readReaddirArgs,
  readReaddirRes,
  readReadlinkRes,
  readReadRes,
  readReclaimCompleteArgs,
  readRemoveArgs,
  readRemoveRes,
  readRenameArgs,
  readRenameRes,
  readResop4,
  readSecInfo,
  readSecinfoArgs,
  readSecinfoNoNameArgs,
  readSecinfoRes,
  readSequenceArgs,
  readSequenceRes,
  readServerOwner4,
  readSessionId4,
  readSetattrArgs,
  readSetattrRes,
  readSpaceLimit4,
  readSsvProtInfo4,
  readSsvSpParms4,
  readStateid,
  readStateOwner4,
  readStateProtect4a,
  readStateProtect4r,
  readStateProtectOps4,
  readStatusRes,
  readTestStateidArgs,
  readTestStateidRes,
  readVerifyArgs,
  readWriteArgs,
  readWriteRes,
  RPCSEC_GSS,
  writeAccessArgs,
  writeAccessRes,
  writeArgop4,
  writeBackchannelCtlArgs,
  writeBindConnToSessionArgs,
  writeBindConnToSessionRes,
  writeCallbackSecParms4,
  writeChangeInfo,
  writeChannelAttrs4,
  writeClientOwner4,
  writeCloseArgs,
  writeCloseRes,
  writeCommitArgs,
  writeCommitRes,
  writeCompoundArgs,
  writeCompoundRes,
  writeCreateArgs,
  writeCreateHow4,
  writeCreateRes,
  writeCreateSessionArgs,
  writeCreateSessionRes,
  writeCreateType,
  writeDestroyClientidArgs,
  writeDestroySessionArgs,
  writeExchangeIdArgs,
  writeExchangeIdRes,
  writeFattr4,
  writeFh4,
  writeFreeStateidArgs,
  writeGetattrArgs,
  writeGetattrRes,
  writeGetfhRes,
  writeGssCbHandles4,
  writeImplId4,
  writeLinkArgs,
  writeLinkRes,
  writeLock4denied,
  writeLockArgs,
  writeLocker4,
  writeLockRes,
  writeLocktArgs,
  writeLocktRes,
  writeLockuArgs,
  writeLockuRes,
  writeLookupArgs,
  writeNfsace4,
  writeOpenArgs,
  writeOpenClaim4,
  writeOpenDelegation4,
  writeOpenDowngradeArgs,
  writeOpenDowngradeRes,
  writeOpenFlag4,
  writeOpenNoneDelegation4,
  writeOpenRes,
  writeOpenToLockOwner4,
  writePutfhArgs,
  writeReadArgs,
  writeReaddirArgs,
  writeReaddirRes,
  writeReadlinkRes,
  writeReadRes,
  writeReclaimCompleteArgs,
  writeRemoveArgs,
  writeRemoveRes,
  writeRenameArgs,
  writeRenameRes,
  writeResop4,
  writeSecInfo,
  writeSecinfoArgs,
  writeSecinfoNoNameArgs,
  writeSecinfoRes,
  writeSequenceArgs,
  writeSequenceRes,
  writeServerOwner4,
  writeSessionId4,
  writeSetattrArgs,
  writeSetattrRes,
  writeSpaceLimit4,
  writeSsvProtInfo4,
  writeSsvSpParms4,
  writeStateid,
  writeStateOwner4,
  writeStateProtect4a,
  writeStateProtect4r,
  writeStateProtectOps4,
  writeStatusRes,
  writeTestStateidArgs,
  writeTestStateidRes,
  writeVerifyArgs,
  writeWriteArgs,
  writeWriteRes,
  type Argop4,
  type ChannelAttrs4,
  type Compound4args,
  type Fattr4,
  type Nfsace4,
  type Resop4,
  type Resop4Value,
  type StateOwner4,
  type Stateid4,
} from "../../../src/nfs/v4/protocol.ts";
import { AUTH_NONE, AUTH_SYS, decodeAuthSys, encodeAuthSys } from "../../../src/nfs/rpc.ts";
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

/** A `sessionid4` whose sixteen bytes are all different. */
const SESSIONID = new Uint8Array([
  0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
]);
const STATEID: Stateid4 = { seqid: 0x0d_0c_0b_0a, other: OTHER };
const OWNER: StateOwner4 = { clientid: 0x01_02_03_04_05_06_07_08n, owner: FH };
const ACE: Nfsace4 = { type: 1, flag: 2, accessMask: 3, who: "someone@example" };
const CHANNEL: ChannelAttrs4 = {
  headerpadsize: 1,
  maxrequestsize: 2,
  maxresponsesize: 3,
  maxresponsesizeCached: 4,
  maxoperations: 5,
  maxrequests: 6,
  rdmaIrd: [7],
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

describe("state base structs", () => {
  it("round-trips a sessionid4 and copies it", () => {
    const bytes = encodeXdr((writer) => writeSessionId4(writer, SESSIONID));
    // Fixed 16 bytes, no length word.
    expect(bytes.byteLength).toBe(16);
    const decoded = readSessionId4(new XdrReader(bytes));
    bytes.fill(0);
    expect([...decoded]).toEqual([...SESSIONID]);
  });

  it("pads a short sessionid4 out to sixteen bytes rather than writing a short one", () => {
    // The size is the declaration, not the value's length: a fifteen-byte
    // session ID must not shorten the record and desync what follows.
    const bytes = encodeXdr((writer) => writeSessionId4(writer, new Uint8Array([1, 2, 3])));
    expect(bytes.byteLength).toBe(16);
    expect([...readSessionId4(new XdrReader(bytes))]).toEqual([
      1,
      2,
      3,
      ...Array.from({ length: 13 }, () => 0),
    ]);
  });

  it("round-trips a state_owner4 and copies its owner", () => {
    roundTrip(writeStateOwner4, readStateOwner4, OWNER);
    const bytes = encodeXdr((writer) => writeStateOwner4(writer, OWNER));
    const decoded = readStateOwner4(new XdrReader(bytes));
    bytes.fill(0xff);
    expect([...decoded.owner]).toEqual([...FH]);
  });

  it("round-trips a client_owner4 and a server_owner4", () => {
    roundTrip(writeClientOwner4, readClientOwner4, { verifier: VERIFIER, ownerid: FH });
    roundTrip(writeServerOwner4, readServerOwner4, { minorId: 42n, majorId: FH });
  });

  it("round-trips an nfs_impl_id4, nfstime4 and all", () => {
    roundTrip(writeImplId4, readImplId4, {
      domain: "example.org",
      name: "mountx 0.0.1",
      // A negative `seconds` is legal: `nfstime4.seconds` is a signed hyper.
      date: { seconds: -3n, nseconds: 500_000_000 },
    });
  });

  it("round-trips an nfsace4", () => {
    roundTrip(writeNfsace4, readNfsace4, ACE);
  });

  it("round-trips a state_protect_ops4 — two bitmaps of *operation* numbers", () => {
    roundTrip(writeStateProtectOps4, readStateProtectOps4, {
      mustEnforce: bitmapOf([OP_CLOSE, OP_LOCK]),
      mustAllow: bitmapOf([OP_SEQUENCE]),
    });
  });

  it("round-trips a gss_cb_handles4 with differing handles", () => {
    roundTrip(writeGssCbHandles4, readGssCbHandles4, {
      service: 3,
      handleFromServer: new Uint8Array([1, 2, 3]),
      handleFromClient: new Uint8Array([4, 5, 6, 7]),
    });
  });

  it("round-trips a channel_attrs4 in both ca_rdma_ird arms", () => {
    roundTrip(writeChannelAttrs4, readChannelAttrs4, CHANNEL);
    roundTrip(writeChannelAttrs4, readChannelAttrs4, { ...CHANNEL, rdmaIrd: [] });
  });
});

describe("nfs_space_limit4 (section 18.16.1)", () => {
  it("carries a filesize or a block pair, by limitby", () => {
    roundTrip(writeSpaceLimit4, readSpaceLimit4, {
      limitby: NFS_LIMIT_SIZE,
      filesize: 0x01_02_03_04_05_06_07_08n,
    });
    roundTrip(writeSpaceLimit4, readSpaceLimit4, {
      limitby: NFS_LIMIT_BLOCKS,
      modBlocks: { numBlocks: 17, bytesPerBlock: 4096 },
    });
  });

  it("refuses an unknown limitby in both directions — the union has no default arm", () => {
    expect(() => encodeXdr((w) => writeSpaceLimit4(w, { limitby: 0 }))).toThrow(XdrError);
    expect(() => encodeXdr((w) => writeSpaceLimit4(w, { limitby: 3 }))).toThrow("limitby 3");
    expect(() =>
      decodeXdr(
        encodeXdr((w) => w.u32(0)),
        readSpaceLimit4,
      ),
    ).toThrow(XdrError);
    expect(() =>
      decodeXdr(
        encodeXdr((w) => w.u32(9)),
        readSpaceLimit4,
      ),
    ).toThrow("limitby 9");
  });
});

describe("callback_sec_parms4 (section 18.33.1)", () => {
  it("carries nothing for AUTH_NONE and an authsys_parms for AUTH_SYS", () => {
    const none = encodeXdr((writer) => writeCallbackSecParms4(writer, { secflavor: AUTH_NONE }));
    expect(none.byteLength).toBe(4);
    expect(decodeXdr(none, readCallbackSecParms4)).toEqual({ secflavor: AUTH_NONE });

    roundTrip(writeCallbackSecParms4, readCallbackSecParms4, {
      secflavor: AUTH_SYS,
      sysCred: {
        stamp: 0x11_22_33_44,
        machineName: "a machine",
        uid: 1000,
        gid: 1001,
        gids: [10, 20, 30],
      },
    });
  });

  it("carries gss_cb_handles4 for RPCSEC_GSS", () => {
    roundTrip(writeCallbackSecParms4, readCallbackSecParms4, {
      secflavor: RPCSEC_GSS,
      gssHandles: {
        service: 2,
        handleFromServer: new Uint8Array([0xa1]),
        handleFromClient: new Uint8Array([0xb1, 0xb2]),
      },
    });
  });

  it("writes the same authsys_parms bytes as ../rpc.ts does", () => {
    // The encode direction *is* `encodeAuthSys`; this pins that the decoder
    // beside it reads exactly those bytes back out of a stream.
    const cred = {
      stamp: 7,
      machineName: "host",
      uid: 501,
      gid: 20,
      gids: [1, 2],
    };
    const inline = encodeXdr((writer) =>
      writeCallbackSecParms4(writer, { secflavor: AUTH_SYS, sysCred: cred }),
    );
    expect([...inline.subarray(4)]).toEqual([...encodeAuthSys(cred)]);
    expect(decodeAuthSys(inline.subarray(4))).toEqual(cred);
    expect(readAuthSysParms(new XdrReader(inline, 4))).toEqual(cred);
  });

  it("refuses an unknown flavor in both directions", () => {
    expect(() => encodeXdr((w) => writeCallbackSecParms4(w, { secflavor: 42 }))).toThrow(
      "flavor 42",
    );
    expect(() =>
      decodeXdr(
        encodeXdr((w) => w.u32(42)),
        readCallbackSecParms4,
      ),
    ).toThrow(XdrError);
  });
});

describe("open unions (section 18.16)", () => {
  it("carries createhow4's four modes, UNCHECKED4 and GUARDED4 sharing one arm", () => {
    roundTrip(writeCreateHow4, readCreateHow4, { mode: UNCHECKED4, createattrs: ATTRS });
    roundTrip(writeCreateHow4, readCreateHow4, { mode: GUARDED4, createattrs: ATTRS });
    roundTrip(writeCreateHow4, readCreateHow4, { mode: EXCLUSIVE4, createverf: VERIFIER });
    roundTrip(writeCreateHow4, readCreateHow4, {
      mode: EXCLUSIVE4_1,
      createboth: { verf: VERIFIER, attrs: ATTRS },
    });
  });

  it("refuses an unknown createmode4 in both directions", () => {
    expect(() => encodeXdr((w) => writeCreateHow4(w, { mode: 4 }))).toThrow("mode 4");
    expect(() =>
      decodeXdr(
        encodeXdr((w) => w.u32(4)),
        readCreateHow4,
      ),
    ).toThrow(XdrError);
  });

  it("makes openflag4's non-CREATE arm four bytes — that default arm is real", () => {
    for (const opentype of [OPEN4_NOCREATE, 7]) {
      const bytes = encodeXdr((writer) => writeOpenFlag4(writer, { opentype }));
      expect(bytes.byteLength, `opentype ${opentype}`).toBe(4);
      expect(decodeXdr(bytes, readOpenFlag4)).toEqual({ opentype });
    }
    roundTrip(writeOpenFlag4, readOpenFlag4, {
      opentype: OPEN4_CREATE,
      how: { mode: UNCHECKED4, createattrs: ATTRS },
    });
  });

  it("carries all seven open_claim4 arms", () => {
    roundTrip(writeOpenClaim4, readOpenClaim4, { claim: CLAIM_NULL, file: "target" });
    roundTrip(writeOpenClaim4, readOpenClaim4, {
      claim: CLAIM_PREVIOUS,
      delegateType: OPEN_DELEGATE_READ,
    });
    roundTrip(writeOpenClaim4, readOpenClaim4, {
      claim: CLAIM_DELEGATE_CUR,
      delegateCurInfo: { delegateStateid: STATEID, file: "held" },
    });
    roundTrip(writeOpenClaim4, readOpenClaim4, {
      claim: CLAIM_DELEGATE_PREV,
      fileDelegatePrev: "was-held",
    });
    roundTrip(writeOpenClaim4, readOpenClaim4, {
      claim: CLAIM_DELEG_CUR_FH,
      ocDelegateStateid: STATEID,
    });
    // The two void arms: the file is the current filehandle.
    for (const claim of [CLAIM_FH, CLAIM_DELEG_PREV_FH]) {
      const bytes = encodeXdr((writer) => writeOpenClaim4(writer, { claim }));
      expect(bytes.byteLength, `claim ${claim}`).toBe(4);
      expect(decodeXdr(bytes, readOpenClaim4)).toEqual({ claim });
    }
  });

  it("refuses an unknown open_claim_type4 in both directions", () => {
    expect(() => encodeXdr((w) => writeOpenClaim4(w, { claim: 7 }))).toThrow("claim 7");
    expect(() =>
      decodeXdr(
        encodeXdr((w) => w.u32(7)),
        readOpenClaim4,
      ),
    ).toThrow(XdrError);
  });

  it("carries all four open_delegation4 arms", () => {
    const none = encodeXdr((writer) =>
      writeOpenDelegation4(writer, { delegationType: OPEN_DELEGATE_NONE }),
    );
    expect(none.byteLength).toBe(4);
    expect(decodeXdr(none, readOpenDelegation4)).toEqual({
      delegationType: OPEN_DELEGATE_NONE,
    });

    roundTrip(writeOpenDelegation4, readOpenDelegation4, {
      delegationType: OPEN_DELEGATE_READ,
      read: { stateid: STATEID, recall: true, permissions: ACE },
    });
    roundTrip(writeOpenDelegation4, readOpenDelegation4, {
      delegationType: OPEN_DELEGATE_WRITE,
      write: {
        stateid: STATEID,
        recall: false,
        spaceLimit: { limitby: NFS_LIMIT_BLOCKS, modBlocks: { numBlocks: 2, bytesPerBlock: 512 } },
        permissions: ACE,
      },
    });
    roundTrip(writeOpenDelegation4, readOpenDelegation4, {
      delegationType: OPEN_DELEGATE_NONE_EXT,
      whynone: { why: WND4_CONTENTION, serverWillPushDeleg: true },
    });
  });

  it("refuses an unknown open_delegation_type4 in both directions", () => {
    expect(() => encodeXdr((w) => writeOpenDelegation4(w, { delegationType: 4 }))).toThrow(
      "type 4",
    );
    expect(() =>
      decodeXdr(
        encodeXdr((w) => w.u32(4)),
        readOpenDelegation4,
      ),
    ).toThrow(XdrError);
  });

  it("gives open_none_delegation4 a bool for two reasons and nothing for the rest", () => {
    roundTrip(writeOpenNoneDelegation4, readOpenNoneDelegation4, {
      why: WND4_CONTENTION,
      serverWillPushDeleg: false,
    });
    roundTrip(writeOpenNoneDelegation4, readOpenNoneDelegation4, {
      why: WND4_RESOURCE,
      serverWillSignalAvail: true,
    });
    // Its default arm is declared, so an unrecognised reason is four bytes and
    // not an error — the opposite of the unions above.
    for (const why of [WND4_NOT_WANTED, 99]) {
      const bytes = encodeXdr((writer) => writeOpenNoneDelegation4(writer, { why }));
      expect(bytes.byteLength, `why ${why}`).toBe(4);
      expect(decodeXdr(bytes, readOpenNoneDelegation4)).toEqual({ why });
    }
  });
});

describe("locker4 (section 18.10.1)", () => {
  it("carries an open_to_lock_owner4 or an exist_lock_owner4, by a bool", () => {
    roundTrip(writeLocker4, readLocker4, {
      newLockOwner: true,
      openOwner: { openSeqid: 1, openStateid: STATEID, lockSeqid: 2, lockOwner: OWNER },
    });
    roundTrip(writeLocker4, readLocker4, {
      newLockOwner: false,
      lockOwner: { lockStateid: STATEID, lockSeqid: 3 },
    });
  });

  it("refuses a discriminant that is not a bool", () => {
    // No third arm to reject: `XdrReader.bool` refuses anything but 0 or 1
    // before the union is ever consulted.
    expect(() =>
      decodeXdr(
        encodeXdr((w) => w.u32(2)),
        readLocker4,
      ),
    ).toThrow(XdrError);
  });

  it("round-trips an open_to_lock_owner4 on its own", () => {
    roundTrip(writeOpenToLockOwner4, readOpenToLockOwner4, {
      openSeqid: 4,
      openStateid: STATEID,
      lockSeqid: 5,
      lockOwner: OWNER,
    });
  });

  it("round-trips a LOCK4denied", () => {
    roundTrip(writeLock4denied, readLock4denied, {
      offset: 100n,
      length: 200n,
      locktype: WRITEW_LT,
      owner: OWNER,
    });
  });
});

describe("state_protect4 (section 18.35)", () => {
  it("carries all three argument arms", () => {
    const none = encodeXdr((writer) => writeStateProtect4a(writer, { how: SP4_NONE }));
    expect(none.byteLength).toBe(4);
    expect(decodeXdr(none, readStateProtect4a)).toEqual({ how: SP4_NONE });

    roundTrip(writeStateProtect4a, readStateProtect4a, {
      how: SP4_MACH_CRED,
      machOps: { mustEnforce: bitmapOf([OP_CLOSE]), mustAllow: bitmapOf([OP_READ]) },
    });
    roundTrip(writeStateProtect4a, readStateProtect4a, {
      how: SP4_SSV,
      ssvParms: {
        ops: { mustEnforce: bitmapOf([OP_LOCK]), mustAllow: bitmapOf([OP_WRITE]) },
        hashAlgs: [new Uint8Array([1, 2])],
        encrAlgs: [new Uint8Array([3, 4, 5])],
        window: 60,
        numGssHandles: 2,
      },
    });
  });

  it("carries all three result arms", () => {
    const none = encodeXdr((writer) => writeStateProtect4r(writer, { how: SP4_NONE }));
    expect(none.byteLength).toBe(4);

    roundTrip(writeStateProtect4r, readStateProtect4r, {
      how: SP4_MACH_CRED,
      machOps: { mustEnforce: bitmapOf([OP_CLOSE]), mustAllow: bitmapOf([OP_READ]) },
    });
    roundTrip(writeStateProtect4r, readStateProtect4r, {
      how: SP4_SSV,
      ssvInfo: {
        ops: { mustEnforce: bitmapOf([OP_LOCK]), mustAllow: bitmapOf([OP_WRITE]) },
        hashAlg: 1,
        encrAlg: 2,
        ssvLen: 32,
        window: 60,
        handles: [new Uint8Array([9, 9, 9])],
      },
    });
  });

  it("refuses an unknown state_protect_how4 in both directions and both structs", () => {
    expect(() => encodeXdr((w) => writeStateProtect4a(w, { how: 3 }))).toThrow("spa_how 3");
    expect(() => encodeXdr((w) => writeStateProtect4r(w, { how: 3 }))).toThrow("spr_how 3");
    expect(() =>
      decodeXdr(
        encodeXdr((w) => w.u32(3)),
        readStateProtect4a,
      ),
    ).toThrow(XdrError);
    expect(() =>
      decodeXdr(
        encodeXdr((w) => w.u32(3)),
        readStateProtect4r,
      ),
    ).toThrow(XdrError);
  });

  it("round-trips the SSV parameter structs on their own", () => {
    roundTrip(writeSsvSpParms4, readSsvSpParms4, {
      ops: { mustEnforce: bitmapOf([OP_CLOSE]), mustAllow: [] },
      hashAlgs: [],
      encrAlgs: [],
      window: 7,
      numGssHandles: 8,
    });
    roundTrip(writeSsvProtInfo4, readSsvProtInfo4, {
      ops: { mustEnforce: [], mustAllow: bitmapOf([OP_OPEN]) },
      hashAlg: 1,
      encrAlg: 2,
      ssvLen: 3,
      window: 4,
      handles: [],
    });
  });
});

describe("state encoders stay total when a union body is missing", () => {
  it("writes a zero stateid where a known arm carries none", () => {
    const zero = { seqid: 0, other: new Uint8Array(12) };
    expect(
      decodeXdr(
        encodeXdr((w) => writeCloseRes(w, { status: NFS4_OK, openStateid: undefined })),
        readCloseRes,
      ),
    ).toEqual({ status: NFS4_OK, openStateid: zero });
    expect(
      decodeXdr(
        encodeXdr((w) => writeOpenClaim4(w, { claim: CLAIM_DELEG_CUR_FH })),
        readOpenClaim4,
      ),
    ).toEqual({ claim: CLAIM_DELEG_CUR_FH, ocDelegateStateid: zero });
  });

  it("writes an empty LOCK4denied for a NFS4ERR_DENIED that carries none", () => {
    expect(
      decodeXdr(
        encodeXdr((w) =>
          writeLockRes(w, { status: NFS4ERR_DENIED, lockStateid: undefined, denied: undefined }),
        ),
        readLockRes,
      ),
    ).toEqual({
      status: NFS4ERR_DENIED,
      lockStateid: undefined,
      denied: {
        offset: 0n,
        length: 0n,
        locktype: 0,
        owner: { clientid: 0n, owner: new Uint8Array(0) },
      },
    });
  });

  it("writes a NONE delegation and empty channel attributes for a bodiless success", () => {
    const open = decodeXdr(
      encodeXdr((w) =>
        writeOpenRes(w, {
          status: NFS4_OK,
          stateid: undefined,
          cinfo: undefined,
          rflags: 0,
          attrset: undefined,
          delegation: undefined,
        }),
      ),
      readOpenRes,
    );
    expect(open.delegation).toEqual({ delegationType: OPEN_DELEGATE_NONE });
    expect(open.attrset).toEqual([]);

    const session = decodeXdr(
      encodeXdr((w) =>
        writeCreateSessionRes(w, {
          status: NFS4_OK,
          sessionid: SESSIONID,
          sequence: 1,
          flags: 2,
          foreChanAttrs: undefined,
          backChanAttrs: undefined,
        }),
      ),
      readCreateSessionRes,
    );
    expect(session.foreChanAttrs).toEqual({
      headerpadsize: 0,
      maxrequestsize: 0,
      maxresponsesize: 0,
      maxresponsesizeCached: 0,
      maxoperations: 0,
      maxrequests: 0,
      rdmaIrd: [],
    });
  });
});

describe("state operation round trips", () => {
  it("READ and WRITE carry their payloads and copy them", () => {
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01]);
    roundTrip(writeReadArgs, readReadArgs, { stateid: STATEID, offset: 1n, count: 2 });
    roundTrip(writeReadRes, readReadRes, { status: NFS4_OK, eof: false, data });
    roundTrip(writeWriteArgs, readWriteArgs, {
      stateid: STATEID,
      offset: 3n,
      stable: UNSTABLE4,
      data,
    });
    roundTrip(writeWriteRes, readWriteRes, {
      status: NFS4_OK,
      count: 5,
      committed: FILE_SYNC4,
      writeverf: VERIFIER,
    });

    // Both payloads are copied out of the record, not viewed into it.
    const readBytes = encodeXdr((w) => writeReadRes(w, { status: NFS4_OK, eof: true, data }));
    const decodedRead = readReadRes(new XdrReader(readBytes));
    readBytes.fill(0);
    expect([...decodedRead.data]).toEqual([...data]);

    const writeBytes = encodeXdr((w) =>
      writeWriteArgs(w, { stateid: STATEID, offset: 0n, stable: UNSTABLE4, data }),
    );
    const decodedWrite = readWriteArgs(new XdrReader(writeBytes));
    writeBytes.fill(0);
    expect([...decodedWrite.data]).toEqual([...data]);
  });

  it("READ and WRITE take a payload cap, defaulting to XDR_MAX_ITEM", () => {
    // The honest limit is the session's `ca_maxrequestsize`; the codec takes
    // one so a caller that knows it can apply it, exactly as v3 does.
    const bytes = encodeXdr((writer) => {
      writer.u32(NFS4_OK);
      writer.bool(false);
      writer.u32(9);
      writer.raw(new Uint8Array(12));
    });
    expect(readReadRes(new XdrReader(bytes)).data.byteLength).toBe(9);
    expect(() => readReadRes(new XdrReader(bytes), 8)).toThrow(XdrError);
  });

  it("LOCK4res picks its arm by status, not by which field is set", () => {
    roundTrip(writeLockRes, readLockRes, {
      status: NFS4_OK,
      lockStateid: STATEID,
      denied: undefined,
    });
    roundTrip(writeLockRes, readLockRes, {
      status: NFS4ERR_DENIED,
      lockStateid: undefined,
      denied: { offset: 1n, length: 2n, locktype: READ_LT, owner: OWNER },
    });
    // Any other failure is the void arm: four bytes.
    const other = encodeXdr((writer) =>
      writeLockRes(writer, { status: NFS4ERR_GRACE, lockStateid: STATEID, denied: undefined }),
    );
    expect(other.byteLength).toBe(4);
    expect(decodeXdr(other, readLockRes)).toEqual({
      status: NFS4ERR_GRACE,
      lockStateid: undefined,
      denied: undefined,
    });
  });

  it("LOCKT4res is void on success and carries a body only when denied", () => {
    const ok = encodeXdr((writer) => writeLocktRes(writer, { status: NFS4_OK, denied: undefined }));
    expect(ok.byteLength).toBe(4);
    roundTrip(writeLocktRes, readLocktRes, {
      status: NFS4ERR_DENIED,
      denied: { offset: 3n, length: 4n, locktype: WRITE_LT, owner: OWNER },
    });
  });

  it("EXCHANGE_ID both ways, with and without an impl id", () => {
    roundTrip(writeExchangeIdArgs, readExchangeIdArgs, {
      clientowner: { verifier: VERIFIER, ownerid: FH },
      flags: 0x00_01_00_00,
      stateProtect: { how: SP4_NONE },
      clientImplId: [],
    });
    roundTrip(writeExchangeIdRes, readExchangeIdRes, {
      status: NFS4_OK,
      clientid: 1n,
      sequenceid: 2,
      flags: 3,
      stateProtect: { how: SP4_NONE },
      serverOwner: { minorId: 4n, majorId: FH },
      serverScope: new Uint8Array([5, 6]),
      serverImplId: [{ domain: "d", name: "n", date: { seconds: 7n, nseconds: 8 } }],
    });
    roundTrip(writeExchangeIdRes, readExchangeIdRes, {
      status: NFS4ERR_NOTSUPP,
      clientid: 0n,
      sequenceid: 0,
      flags: 0,
      stateProtect: undefined,
      serverOwner: undefined,
      serverScope: new Uint8Array(0),
      serverImplId: [],
    });
  });

  it("SEQUENCE both ways", () => {
    roundTrip(writeSequenceArgs, readSequenceArgs, {
      sessionid: SESSIONID,
      sequenceid: 1,
      slotid: 2,
      highestSlotid: 3,
      cachethis: false,
    });
    roundTrip(writeSequenceRes, readSequenceRes, {
      status: NFS4_OK,
      sessionid: SESSIONID,
      sequenceid: 4,
      slotid: 5,
      highestSlotid: 6,
      targetHighestSlotid: 7,
      statusFlags: 8,
    });
  });

  it("TEST_STATEID carries a list in each direction, including empty ones", () => {
    roundTrip(writeTestStateidArgs, readTestStateidArgs, { stateids: [] });
    roundTrip(writeTestStateidArgs, readTestStateidArgs, {
      stateids: [STATEID, { seqid: 1, other: OTHER }],
    });
    roundTrip(writeTestStateidRes, readTestStateidRes, { status: NFS4_OK, statusCodes: [] });
    roundTrip(writeTestStateidRes, readTestStateidRes, {
      status: NFS4_OK,
      statusCodes: [NFS4_OK, NFS4ERR_BADHANDLE, NFS4ERR_NOTSUPP],
    });
  });

  it("LOCKT and LOCKU arguments both ways", () => {
    roundTrip(writeLocktArgs, readLocktArgs, {
      locktype: WRITEW_LT,
      offset: 5n,
      length: 6n,
      owner: OWNER,
    });
    roundTrip(writeLockuArgs, readLockuArgs, {
      locktype: WRITE_LT,
      seqid: 7,
      lockStateid: STATEID,
      offset: 8n,
      length: 9n,
    });
    roundTrip(writeLockuRes, readLockuRes, { status: NFS4_OK, lockStateid: STATEID });
    roundTrip(writeLockuRes, readLockuRes, { status: NFS4ERR_GRACE, lockStateid: undefined });
    roundTrip(writeOpenDowngradeRes, readOpenDowngradeRes, {
      status: NFS4_OK,
      openStateid: STATEID,
    });
    roundTrip(writeOpenDowngradeRes, readOpenDowngradeRes, {
      status: NFS4ERR_NOTSUPP,
      openStateid: undefined,
    });
  });

  it("the small argument-only operations both ways", () => {
    roundTrip(writeCloseArgs, readCloseArgs, { seqid: 1, openStateid: STATEID });
    roundTrip(writeOpenDowngradeArgs, readOpenDowngradeArgs, {
      openStateid: STATEID,
      seqid: 2,
      shareAccess: OPEN4_SHARE_ACCESS_BOTH,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    });
    roundTrip(writeDestroySessionArgs, readDestroySessionArgs, { sessionid: SESSIONID });
    roundTrip(writeDestroyClientidArgs, readDestroyClientidArgs, { clientid: 9n });
    roundTrip(writeFreeStateidArgs, readFreeStateidArgs, { stateid: STATEID });
    roundTrip(writeReclaimCompleteArgs, readReclaimCompleteArgs, { oneFs: false });
    roundTrip(writeReclaimCompleteArgs, readReclaimCompleteArgs, { oneFs: true });
    roundTrip(writeBackchannelCtlArgs, readBackchannelCtlArgs, {
      cbProgram: 0x40_00_00_01,
      secParms: [],
    });
    roundTrip(writeBindConnToSessionArgs, readBindConnToSessionArgs, {
      sessionid: SESSIONID,
      dir: CDFC4_FORE_OR_BOTH,
      useConnInRdmaMode: true,
    });
    roundTrip(writeBindConnToSessionRes, readBindConnToSessionRes, {
      status: NFS4_OK,
      sessionid: SESSIONID,
      dir: CDFS4_BOTH,
      useConnInRdmaMode: false,
    });
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
  /**
   * Every operation the table carries, in `nfs_opnum4` order.
   *
   * The stateless ones and the state ones together — the whole set this server
   * answers. What is *not* here is as deliberate: the optional operations a
   * client may legally send and this server will never implement get
   * `NFS4ERR_NOTSUPP` from the session with no codec row involved, so a row
   * appearing for one of them would be the bug. {@link UNIMPLEMENTED} names a
   * representative few and the table is asserted to hold none of them.
   */
  const IMPLEMENTED = [
    OP_ACCESS,
    OP_CLOSE,
    OP_COMMIT,
    OP_CREATE,
    OP_GETATTR,
    OP_GETFH,
    OP_LINK,
    OP_LOCK,
    OP_LOCKT,
    OP_LOCKU,
    OP_LOOKUP,
    OP_LOOKUPP,
    OP_NVERIFY,
    OP_OPEN,
    OP_OPEN_DOWNGRADE,
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
    OP_SETATTR,
    OP_VERIFY,
    OP_WRITE,
    OP_BACKCHANNEL_CTL,
    OP_BIND_CONN_TO_SESSION,
    OP_EXCHANGE_ID,
    OP_CREATE_SESSION,
    OP_DESTROY_SESSION,
    OP_FREE_STATEID,
    OP_SECINFO_NO_NAME,
    OP_SEQUENCE,
    OP_TEST_STATEID,
    OP_DESTROY_CLIENTID,
    OP_RECLAIM_COMPLETE,
    OP_ILLEGAL,
  ];

  /** Operations NFSv4.1 defines that this server answers `NFS4ERR_NOTSUPP` for. */
  const UNIMPLEMENTED = [OP_DELEGRETURN, OP_OPENATTR, OP_GETDEVICEINFO, OP_LAYOUTGET];

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

  it("carries every implemented operation and nothing else", () => {
    expect([...OP_CODECS.keys()].sort((a, b) => a - b)).toEqual(
      [...IMPLEMENTED].sort((a, b) => a - b),
    );
  });

  it("carries no row for the operations answered with NFS4ERR_NOTSUPP", () => {
    // A row here would be worse than useless: the session's NOTSUPP path emits
    // a status-only resop and halts the compound precisely *because* the
    // arguments were never decoded, and a codec would invite it to keep going.
    for (const op of UNIMPLEMENTED) {
      expect(OP_CODECS.has(op), opName4(op)).toBe(false);
    }
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
    // Defined by NFSv4.1, deliberately absent: the message has to say which
    // one, because "this server does not support that" and "that opcode does
    // not exist" are different answers — the first is NFS4ERR_NOTSUPP and the
    // second NFS4ERR_OP_ILLEGAL.
    for (const op of UNIMPLEMENTED) {
      expect(() => opCodec4(op)).toThrow(XdrError);
      expect(() => opCodec4(op)).toThrow(opName4(op));
    }
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
      { op: OP_CLOSE, args: { seqid: 3, openStateid: STATEID } },
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
      {
        op: OP_LOCK,
        args: {
          locktype: WRITE_LT,
          reclaim: false,
          offset: 16n,
          length: 32n,
          locker: {
            newLockOwner: true,
            openOwner: {
              openSeqid: 1,
              openStateid: STATEID,
              lockSeqid: 2,
              lockOwner: OWNER,
            },
          },
        },
      },
      { op: OP_LOCKT, args: { locktype: READ_LT, offset: 1n, length: 2n, owner: OWNER } },
      {
        op: OP_LOCKU,
        args: { locktype: READ_LT, seqid: 4, lockStateid: STATEID, offset: 5n, length: 6n },
      },
      { op: OP_LOOKUP, args: { objname: "d" } },
      { op: OP_LOOKUPP, args: undefined },
      { op: OP_NVERIFY, args: { objAttributes: ATTRS } },
      {
        op: OP_OPEN,
        args: {
          seqid: 9,
          shareAccess: OPEN4_SHARE_ACCESS_READ,
          shareDeny: OPEN4_SHARE_DENY_NONE,
          owner: OWNER,
          openhow: { opentype: OPEN4_NOCREATE },
          claim: { claim: CLAIM_NULL, file: "f" },
        },
      },
      {
        op: OP_OPEN_DOWNGRADE,
        args: {
          openStateid: STATEID,
          seqid: 11,
          shareAccess: OPEN4_SHARE_ACCESS_READ,
          shareDeny: OPEN4_SHARE_DENY_WRITE,
        },
      },
      { op: OP_PUTFH, args: { object: FH } },
      { op: OP_PUTPUBFH, args: undefined },
      { op: OP_PUTROOTFH, args: undefined },
      { op: OP_READ, args: { stateid: STATEID, offset: 64n, count: 4096 } },
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
      {
        op: OP_WRITE,
        args: {
          stateid: STATEID,
          offset: 128n,
          stable: UNSTABLE4,
          data: new Uint8Array([1, 2, 3, 4, 5]),
        },
      },
      {
        op: OP_BACKCHANNEL_CTL,
        args: { cbProgram: 0x40_00_00_01, secParms: [{ secflavor: AUTH_NONE }] },
      },
      {
        op: OP_BIND_CONN_TO_SESSION,
        args: { sessionid: SESSIONID, dir: CDFC4_FORE_OR_BOTH, useConnInRdmaMode: false },
      },
      {
        op: OP_EXCHANGE_ID,
        args: {
          clientowner: { verifier: VERIFIER, ownerid: FH },
          flags: 0x00_01_00_00,
          stateProtect: { how: SP4_NONE },
          clientImplId: [
            { domain: "example.org", name: "mountx", date: { seconds: 7n, nseconds: 8 } },
          ],
        },
      },
      {
        op: OP_CREATE_SESSION,
        args: {
          clientid: 0x0a_0b_0c_0d_0e_0f_10_11n,
          sequence: 1,
          flags: 2,
          foreChanAttrs: CHANNEL,
          backChanAttrs: { ...CHANNEL, rdmaIrd: [] },
          cbProgram: 0x40_00_00_02,
          secParms: [{ secflavor: AUTH_NONE }],
        },
      },
      { op: OP_DESTROY_SESSION, args: { sessionid: SESSIONID } },
      { op: OP_FREE_STATEID, args: { stateid: STATEID } },
      {
        op: OP_SEQUENCE,
        args: {
          sessionid: SESSIONID,
          sequenceid: 12,
          slotid: 3,
          highestSlotid: 15,
          cachethis: true,
        },
      },
      { op: OP_TEST_STATEID, args: { stateids: [STATEID, { seqid: 2, other: OTHER }] } },
      { op: OP_DESTROY_CLIENTID, args: { clientid: 0x12_13_14_15_16_17_18_19n } },
      { op: OP_RECLAIM_COMPLETE, args: { oneFs: true } },
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
      { op: OP_CLOSE, res: { status: NFS4_OK, openStateid: STATEID } },
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
      // LOCK and LOCKT take their non-void *failure* arm here, which is the
      // shape a success-only fixture would never exercise.
      {
        op: OP_LOCK,
        res: {
          status: NFS4ERR_DENIED,
          lockStateid: undefined,
          denied: { offset: 7n, length: 8n, locktype: WRITE_LT, owner: OWNER },
        },
      },
      {
        op: OP_LOCKT,
        res: {
          status: NFS4ERR_DENIED,
          denied: { offset: 9n, length: 10n, locktype: READ_LT, owner: OWNER },
        },
      },
      { op: OP_LOCKU, res: { status: NFS4_OK, lockStateid: STATEID } },
      { op: OP_LOOKUP, res: { status: NFS4_OK } },
      { op: OP_LOOKUPP, res: { status: NFS4_OK } },
      { op: OP_NVERIFY, res: { status: NFS4_OK } },
      {
        op: OP_OPEN,
        res: {
          status: NFS4_OK,
          stateid: STATEID,
          cinfo: { atomic: true, before: 11n, after: 12n },
          rflags: 4,
          attrset: bitmapOf([FATTR4_SIZE]),
          delegation: { delegationType: OPEN_DELEGATE_NONE },
        },
      },
      { op: OP_OPEN_DOWNGRADE, res: { status: NFS4_OK, openStateid: STATEID } },
      { op: OP_PUTFH, res: { status: NFS4_OK } },
      { op: OP_PUTPUBFH, res: { status: NFS4_OK } },
      { op: OP_PUTROOTFH, res: { status: NFS4_OK } },
      {
        op: OP_READ,
        res: { status: NFS4_OK, eof: true, data: new Uint8Array([9, 8, 7]) },
      },
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
      {
        op: OP_WRITE,
        res: { status: NFS4_OK, count: 5, committed: DATA_SYNC4, writeverf: VERIFIER },
      },
      { op: OP_BACKCHANNEL_CTL, res: { status: NFS4_OK } },
      {
        op: OP_BIND_CONN_TO_SESSION,
        res: {
          status: NFS4_OK,
          sessionid: SESSIONID,
          dir: CDFS4_BOTH,
          useConnInRdmaMode: false,
        },
      },
      {
        op: OP_EXCHANGE_ID,
        res: {
          status: NFS4_OK,
          clientid: 0x21_22_23_24_25_26_27_28n,
          sequenceid: 1,
          flags: 0x00_01_00_00,
          stateProtect: { how: SP4_NONE },
          serverOwner: { minorId: 2n, majorId: FH },
          serverScope: new Uint8Array([0x31, 0x32]),
          serverImplId: [],
        },
      },
      {
        op: OP_CREATE_SESSION,
        res: {
          status: NFS4_OK,
          sessionid: SESSIONID,
          sequence: 1,
          flags: 2,
          foreChanAttrs: CHANNEL,
          backChanAttrs: { ...CHANNEL, rdmaIrd: [] },
        },
      },
      { op: OP_DESTROY_SESSION, res: { status: NFS4_OK } },
      { op: OP_FREE_STATEID, res: { status: NFS4_OK } },
      {
        op: OP_SEQUENCE,
        res: {
          status: NFS4_OK,
          sessionid: SESSIONID,
          sequenceid: 12,
          slotid: 3,
          highestSlotid: 15,
          targetHighestSlotid: 31,
          statusFlags: 0x00_00_01_00,
        },
      },
      { op: OP_TEST_STATEID, res: { status: NFS4_OK, statusCodes: [NFS4_OK, NFS4ERR_BADHANDLE] } },
      { op: OP_DESTROY_CLIENTID, res: { status: NFS4_OK } },
      { op: OP_RECLAIM_COMPLETE, res: { status: NFS4_OK } },
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

  it("refuses every truncation of the state operations", () => {
    everyTruncationFails(
      "EXCHANGE_ID4args",
      encodeXdr((writer) =>
        writeExchangeIdArgs(writer, {
          clientowner: { verifier: VERIFIER, ownerid: FH },
          flags: 0x00_01_00_00,
          stateProtect: {
            how: SP4_SSV,
            ssvParms: {
              ops: { mustEnforce: bitmapOf([OP_CLOSE]), mustAllow: bitmapOf([OP_READ]) },
              hashAlgs: [new Uint8Array([1, 2, 3])],
              encrAlgs: [new Uint8Array([4])],
              window: 5,
              numGssHandles: 6,
            },
          },
          clientImplId: [{ domain: "d", name: "n", date: { seconds: 7n, nseconds: 8 } }],
        }),
      ),
      readExchangeIdArgs,
    );
    everyTruncationFails(
      "EXCHANGE_ID4res",
      encodeXdr((writer) =>
        writeExchangeIdRes(writer, {
          status: NFS4_OK,
          clientid: 1n,
          sequenceid: 2,
          flags: 3,
          stateProtect: { how: SP4_NONE },
          serverOwner: { minorId: 4n, majorId: FH },
          serverScope: new Uint8Array([5, 6, 7]),
          serverImplId: [{ domain: "d", name: "n", date: { seconds: 8n, nseconds: 9 } }],
        }),
      ),
      readExchangeIdRes,
    );
    everyTruncationFails(
      "CREATE_SESSION4args",
      encodeXdr((writer) =>
        writeCreateSessionArgs(writer, {
          clientid: 1n,
          sequence: 2,
          flags: 3,
          foreChanAttrs: CHANNEL,
          backChanAttrs: { ...CHANNEL, rdmaIrd: [] },
          cbProgram: 4,
          secParms: [
            { secflavor: AUTH_NONE },
            {
              secflavor: AUTH_SYS,
              sysCred: { stamp: 5, machineName: "m", uid: 6, gid: 7, gids: [8] },
            },
          ],
        }),
      ),
      readCreateSessionArgs,
    );
    everyTruncationFails(
      "CREATE_SESSION4res",
      encodeXdr((writer) =>
        writeCreateSessionRes(writer, {
          status: NFS4_OK,
          sessionid: SESSIONID,
          sequence: 1,
          flags: 2,
          foreChanAttrs: CHANNEL,
          backChanAttrs: { ...CHANNEL, rdmaIrd: [] },
        }),
      ),
      readCreateSessionRes,
    );
    everyTruncationFails(
      "OPEN4args",
      encodeXdr((writer) =>
        writeOpenArgs(writer, {
          seqid: 1,
          shareAccess: OPEN4_SHARE_ACCESS_BOTH,
          shareDeny: OPEN4_SHARE_DENY_WRITE,
          owner: OWNER,
          openhow: {
            opentype: OPEN4_CREATE,
            how: { mode: EXCLUSIVE4_1, createboth: { verf: VERIFIER, attrs: ATTRS } },
          },
          claim: { claim: CLAIM_NULL, file: "target" },
        }),
      ),
      readOpenArgs,
    );
    everyTruncationFails(
      "OPEN4res",
      encodeXdr((writer) =>
        writeOpenRes(writer, {
          status: NFS4_OK,
          stateid: STATEID,
          cinfo: { atomic: true, before: 1n, after: 2n },
          rflags: 4,
          attrset: bitmapOf([FATTR4_SIZE]),
          delegation: {
            delegationType: OPEN_DELEGATE_WRITE,
            write: {
              stateid: { seqid: 3, other: OTHER },
              recall: false,
              spaceLimit: { limitby: NFS_LIMIT_SIZE, filesize: 5n },
              permissions: ACE,
            },
          },
        }),
      ),
      readOpenRes,
    );
    everyTruncationFails(
      "LOCK4args",
      encodeXdr((writer) =>
        writeLockArgs(writer, {
          locktype: WRITE_LT,
          reclaim: true,
          offset: 1n,
          length: 2n,
          locker: {
            newLockOwner: true,
            openOwner: { openSeqid: 3, openStateid: STATEID, lockSeqid: 4, lockOwner: OWNER },
          },
        }),
      ),
      readLockArgs,
    );
    everyTruncationFails(
      "LOCK4res (denied)",
      encodeXdr((writer) =>
        writeLockRes(writer, {
          status: NFS4ERR_DENIED,
          lockStateid: undefined,
          denied: { offset: 1n, length: 2n, locktype: READ_LT, owner: OWNER },
        }),
      ),
      readLockRes,
    );
    everyTruncationFails(
      "SEQUENCE4res",
      encodeXdr((writer) =>
        writeSequenceRes(writer, {
          status: NFS4_OK,
          sessionid: SESSIONID,
          sequenceid: 1,
          slotid: 2,
          highestSlotid: 3,
          targetHighestSlotid: 4,
          statusFlags: 5,
        }),
      ),
      readSequenceRes,
    );
    everyTruncationFails(
      "WRITE4args",
      encodeXdr((writer) =>
        writeWriteArgs(writer, {
          stateid: STATEID,
          offset: 1n,
          stable: UNSTABLE4,
          data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        }),
      ),
      readWriteArgs,
    );
    everyTruncationFails(
      "TEST_STATEID4args",
      encodeXdr((writer) =>
        writeTestStateidArgs(writer, { stateids: [STATEID, { seqid: 1, other: OTHER }] }),
      ),
      readTestStateidArgs,
    );
  });

  it("refuses lists longer than the codec will hold, before allocating", () => {
    // Only the count word is needed in each case: the check fires ahead of any
    // allocation, which is the whole point of having one.
    const overLong = (count: number, read: (reader: XdrReader) => unknown): void => {
      expect(() => read(new XdrReader(encodeXdr((w) => w.u32(count))))).toThrow(XdrError);
    };
    overLong(NFS4_MAX_TEST_STATEIDS + 1, readTestStateidArgs);
    overLong(0xff_ff_ff_ff, readTestStateidArgs);
    // The result's list sits behind a NFS4_OK status.
    expect(() =>
      readTestStateidRes(
        new XdrReader(
          encodeXdr((w) => {
            w.u32(NFS4_OK);
            w.u32(NFS4_MAX_TEST_STATEIDS + 1);
          }),
        ),
      ),
    ).toThrow(XdrError);
    // `bca_sec_parms<>` and the two `<1>` arrays.
    expect(() =>
      readBackchannelCtlArgs(
        new XdrReader(
          encodeXdr((w) => {
            w.u32(1);
            w.u32(NFS4_MAX_SEC_PARMS + 1);
          }),
        ),
      ),
    ).toThrow(XdrError);
    expect(() =>
      readChannelAttrs4(
        new XdrReader(
          encodeXdr((w) => {
            for (let word = 0; word < 6; word++) {
              w.u32(word);
            }
            w.u32(NFS4_MAX_OPTIONAL_ONE + 1);
            w.u32(1);
            w.u32(2);
          }),
        ),
      ),
    ).toThrow(XdrError);
  });

  it("refuses a WRITE payload longer than the cap it was given", () => {
    // The length word alone: four billion bytes must never be allocated, and
    // an explicit cap must fire even when the bytes are present.
    const header = (length: number) =>
      encodeXdr((w) => {
        writeStateid(w, STATEID);
        w.u64(0n);
        w.u32(UNSTABLE4);
        w.u32(length);
      });
    expect(() => readWriteArgs(new XdrReader(header(0xff_ff_ff_ff)))).toThrow(XdrError);
    const short = encodeXdr((w) => {
      w.raw(header(8));
      w.raw(new Uint8Array(8));
    });
    expect(readWriteArgs(new XdrReader(short)).data.byteLength).toBe(8);
    expect(() => readWriteArgs(new XdrReader(short), 4)).toThrow(XdrError);
  });

  it("refuses an over-long session-scoped opaque", () => {
    // `co_ownerid`, `so_major_id` and `state_owner4.owner` are all bounded by
    // NFS4_OPAQUE_LIMIT, and a sessionid4 that the record cannot hold.
    for (const read of [readClientOwner4, readServerOwner4]) {
      expect(() =>
        read(
          new XdrReader(
            encodeXdr((w) => {
              w.u64(0n); // verifier4's eight bytes, or so_minor_id
              w.u32(NFS4_OPAQUE_LIMIT + 1);
            }),
          ),
        ),
      ).toThrow(XdrError);
    }
    expect(() =>
      readStateOwner4(
        new XdrReader(
          encodeXdr((w) => {
            w.u64(0n);
            w.u32(NFS4_OPAQUE_LIMIT + 1);
          }),
        ),
      ),
    ).toThrow(XdrError);
    expect(() => readSessionId4(new XdrReader(new Uint8Array(15)))).toThrow(XdrError);
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
      ["readSessionId4", readSessionId4],
      ["readStateOwner4", readStateOwner4],
      ["readClientOwner4", readClientOwner4],
      ["readServerOwner4", readServerOwner4],
      ["readImplId4", readImplId4],
      ["readNfsace4", readNfsace4],
      ["readSpaceLimit4", readSpaceLimit4],
      ["readStateProtectOps4", readStateProtectOps4],
      ["readGssCbHandles4", readGssCbHandles4],
      ["readAuthSysParms", readAuthSysParms],
      ["readCallbackSecParms4", readCallbackSecParms4],
      ["readChannelAttrs4", readChannelAttrs4],
      ["readCreateHow4", readCreateHow4],
      ["readOpenFlag4", readOpenFlag4],
      ["readOpenClaim4", readOpenClaim4],
      ["readOpenNoneDelegation4", readOpenNoneDelegation4],
      ["readOpenDelegation4", readOpenDelegation4],
      ["readOpenToLockOwner4", readOpenToLockOwner4],
      ["readLocker4", readLocker4],
      ["readLock4denied", readLock4denied],
      ["readSsvSpParms4", readSsvSpParms4],
      ["readSsvProtInfo4", readSsvProtInfo4],
      ["readStateProtect4a", readStateProtect4a],
      ["readStateProtect4r", readStateProtect4r],
      ["readCloseArgs", readCloseArgs],
      ["readCloseRes", readCloseRes],
      ["readLockArgs", readLockArgs],
      ["readLockRes", readLockRes],
      ["readLocktArgs", readLocktArgs],
      ["readLocktRes", readLocktRes],
      ["readLockuArgs", readLockuArgs],
      ["readLockuRes", readLockuRes],
      ["readOpenArgs", readOpenArgs],
      ["readOpenRes", readOpenRes],
      ["readOpenDowngradeArgs", readOpenDowngradeArgs],
      ["readOpenDowngradeRes", readOpenDowngradeRes],
      ["readReadArgs", readReadArgs],
      ["readReadRes", readReadRes],
      ["readWriteArgs", readWriteArgs],
      ["readWriteRes", readWriteRes],
      ["readBackchannelCtlArgs", readBackchannelCtlArgs],
      ["readBindConnToSessionArgs", readBindConnToSessionArgs],
      ["readBindConnToSessionRes", readBindConnToSessionRes],
      ["readExchangeIdArgs", readExchangeIdArgs],
      ["readExchangeIdRes", readExchangeIdRes],
      ["readCreateSessionArgs", readCreateSessionArgs],
      ["readCreateSessionRes", readCreateSessionRes],
      ["readDestroySessionArgs", readDestroySessionArgs],
      ["readDestroyClientidArgs", readDestroyClientidArgs],
      ["readFreeStateidArgs", readFreeStateidArgs],
      ["readSequenceArgs", readSequenceArgs],
      ["readSequenceRes", readSequenceRes],
      ["readTestStateidArgs", readTestStateidArgs],
      ["readTestStateidRes", readTestStateidRes],
      ["readReclaimCompleteArgs", readReclaimCompleteArgs],
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
