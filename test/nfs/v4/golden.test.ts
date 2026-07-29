/**
 * Hand-verified byte fixtures for `src/nfs/v4/protocol.ts`.
 *
 * The round-trip tests in `protocol.test.ts` prove the codecs agree with
 * *themselves*, which is exactly the property a consistently wrong
 * implementation also has. Every expectation below is written out by hand from
 * RFC 5662's XDR (the normative description RFC 8881 §16.2 and §18 point at),
 * word by word, so a layout that drifts in both directions at once still fails
 * here — the same job `test/nfs/v3/golden.test.ts` does for NFSv3 and
 * `test/fuse/golden.test.ts` for the other transport.
 *
 * **Every field gets a distinct value, on purpose.** A fixture built from
 * repeated values is satisfied by an encoder *and* decoder that transpose the
 * same pair: the bytes come out identical, the round trips come out identical,
 * and the suite stays green while the wire format is wrong. {@link golden}
 * enforces that per fixture, and the only words allowed to repeat are the ones
 * named at the call site — XDR's own structure (a linked-list marker, a bitmap
 * word count) rather than a field, and `NFS4_OK`, which is zero and is on the
 * wire once per operation.
 */

import { describe, expect, it } from "vitest";
import {
  FATTR4_CHANGE,
  FATTR4_FILEID,
  FATTR4_MODE,
  FATTR4_NUMLINKS,
  FATTR4_OWNER,
  FATTR4_OWNER_GROUP,
  FATTR4_SIZE,
  FATTR4_TIME_MODIFY_SET,
  CDFC4_BACK_OR_BOTH,
  CDFS4_BOTH,
  CLAIM_FH,
  CLAIM_NULL,
  CREATE_SESSION4_FLAG_CONN_BACK_CHAN,
  CREATE_SESSION4_FLAG_PERSIST,
  DATA_SYNC4,
  EXCHGID4_FLAG_CONFIRMED_R,
  EXCHGID4_FLAG_USE_NON_PNFS,
  EXCLUSIVE4_1,
  FILE_SYNC4,
  NF4LNK,
  NFS4_OK,
  NFS4ERR_ACCESS,
  NFS4ERR_BAD_COOKIE,
  NFS4ERR_BADTYPE,
  NFS4ERR_INVAL,
  NFS4ERR_IO,
  NFS4ERR_MLINK,
  NFS4ERR_NOENT,
  NFS4ERR_NOT_SAME,
  NFS4ERR_BAD_STATEID,
  NFS4ERR_BADSESSION,
  NFS4ERR_CLIENTID_BUSY,
  NFS4ERR_COMPLETE_ALREADY,
  NFS4ERR_DENIED,
  NFS4ERR_EXPIRED,
  NFS4ERR_LOCKS_HELD,
  NFS4ERR_NOTEMPTY,
  NFS4ERR_OP_ILLEGAL,
  NFS4ERR_OPENMODE,
  NFS4ERR_SHARE_DENIED,
  NFS4ERR_SAME,
  NFS4ERR_STALE,
  NFS4ERR_WRONGSEC,
  NFS4ERR_XDEV,
  OP_GETFH,
  OP_LOOKUP,
  OP_PUTFH,
  OP_PUTROOTFH,
  OP_READ,
  OP_SEQUENCE,
  OPEN4_CREATE,
  OPEN4_RESULT_LOCKTYPE_POSIX,
  OPEN4_RESULT_MAY_NOTIFY_LOCK,
  OPEN4_SHARE_ACCESS_BOTH,
  OPEN4_SHARE_ACCESS_WRITE,
  OPEN4_SHARE_DENY_BOTH,
  OPEN4_SHARE_DENY_NONE,
  OPEN_DELEGATE_NONE,
  OPEN_DELEGATE_NONE_EXT,
  READ_LT,
  SECINFO_STYLE4_PARENT,
  SEQ4_STATUS_CB_PATH_DOWN_SESSION,
  SEQ4_STATUS_RESTART_RECLAIM_NEEDED,
  SET_TO_CLIENT_TIME4,
  SP4_NONE,
  UNCHECKED4,
  WND4_RESOURCE,
  WRITE_LT,
  WRITEW_LT,
} from "../../../src/nfs/v4/constants.ts";
import { bitmapOf } from "../../../src/nfs/v4/attr.ts";
import {
  readAccessArgs,
  readAccessRes,
  readBackchannelCtlArgs,
  readBindConnToSessionArgs,
  readBindConnToSessionRes,
  readCloseArgs,
  readCloseRes,
  readCommitArgs,
  readCommitRes,
  readCompoundArgs,
  readCompoundRes,
  readCreateSessionArgs,
  readCreateSessionRes,
  readDestroyClientidArgs,
  readDestroySessionArgs,
  readExchangeIdArgs,
  readExchangeIdRes,
  readFreeStateidArgs,
  readLockArgs,
  readLockRes,
  readLocktArgs,
  readLocktRes,
  readLockuArgs,
  readLockuRes,
  readOpenArgs,
  readOpenDowngradeArgs,
  readOpenDowngradeRes,
  readOpenRes,
  readReadArgs,
  readReadRes,
  readReclaimCompleteArgs,
  readSequenceArgs,
  readSequenceRes,
  readTestStateidArgs,
  readTestStateidRes,
  readWriteArgs,
  readWriteRes,
  readCreateArgs,
  readCreateRes,
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
  readSecinfoArgs,
  readSecinfoNoNameArgs,
  readSecinfoRes,
  readSetattrArgs,
  readSetattrRes,
  readStatusRes,
  readVerifyArgs,
  RPCSEC_GSS,
  writeAccessArgs,
  writeAccessRes,
  writeBackchannelCtlArgs,
  writeBindConnToSessionArgs,
  writeBindConnToSessionRes,
  writeCloseArgs,
  writeCloseRes,
  writeArgop4,
  writeCommitArgs,
  writeCommitRes,
  writeCompoundArgs,
  writeCompoundRes,
  writeCreateSessionArgs,
  writeCreateSessionRes,
  writeDestroyClientidArgs,
  writeDestroySessionArgs,
  writeExchangeIdArgs,
  writeExchangeIdRes,
  writeFreeStateidArgs,
  writeLockArgs,
  writeLockRes,
  writeLocktArgs,
  writeLocktRes,
  writeLockuArgs,
  writeLockuRes,
  writeOpenArgs,
  writeOpenDowngradeArgs,
  writeOpenDowngradeRes,
  writeOpenRes,
  writeReadArgs,
  writeReadRes,
  writeReclaimCompleteArgs,
  writeSequenceArgs,
  writeSequenceRes,
  writeTestStateidArgs,
  writeTestStateidRes,
  writeWriteArgs,
  writeWriteRes,
  writeCreateArgs,
  writeCreateRes,
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
  writeSecinfoArgs,
  writeSecinfoNoNameArgs,
  writeSecinfoRes,
  writeSetattrArgs,
  writeSetattrRes,
  writeStatusRes,
  writeVerifyArgs,
} from "../../../src/nfs/v4/protocol.ts";
import { AUTH_NONE, AUTH_SYS } from "../../../src/nfs/rpc.ts";
import { decodeXdr, encodeXdr, XdrReader, XdrWriter } from "../../../src/nfs/xdr.ts";

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

/**
 * Encode `value`, insist it is exactly `words`, and decode it back.
 *
 * Both directions in one call, plus the distinctness check the module docs
 * describe: any word that legitimately appears twice has to be named in
 * `repeats`, so a fixture cannot go quietly symmetric.
 */
function golden<T>(
  write: (writer: XdrWriter, value: T) => void,
  read: (reader: XdrReader) => T,
  value: T,
  words: readonly string[],
  repeats: readonly string[] = [],
): void {
  const bytes = encodeXdr((writer) => write(writer, value));
  expect(hex(bytes)).toBe(words.join(" "));
  expect(bytes.byteLength).toBe(words.length * 4);
  expect(decodeXdr(bytes, read)).toEqual(value);
  const fields = words.filter((word) => !repeats.includes(word));
  expect(new Set(fields).size, `repeated field word in ${fields.join(" ")}`).toBe(fields.length);
}

/** A handle whose halves differ, so writing it backwards cannot pass. */
const FH = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

/** A `sessionid4` — sixteen fixed bytes, four words, none of them alike. */
const SESSIONID = new Uint8Array([
  0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
]);

/** A `stateid4.other` — twelve fixed bytes, three words. */
const OTHER = new Uint8Array([
  0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
]);

/** A second one, so a fixture holding two stateids cannot transpose them. */
const OTHER_B = new Uint8Array([
  0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c,
]);

const STATEID = { seqid: 0x0a_0b_0c_0d, other: OTHER };

/** A `verifier4` — eight fixed bytes. */
const VERIFIER = new Uint8Array([0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88]);

/** A `state_owner4.owner` / `co_ownerid` — six bytes, so its length word is its own. */
const OWNERID = new Uint8Array([0x71, 0x72, 0x73, 0x74, 0x75, 0x76]);

/** A `state_owner4` whose every word differs. */
const OWNER = { clientid: 0x41_42_43_44_45_46_47_48n, owner: OWNERID };

describe("PUTFH (RFC 8881 section 18.19) and the status-only results", () => {
  it("encodes PUTFH4args as a counted nfs_fh4", () => {
    golden(writePutfhArgs, readPutfhArgs, { object: FH }, [
      "00000008", // nfs_fh4 length = 8
      "11223344", // the handle, first half
      "55667788", // and the second
    ]);
  });

  it("encodes PUTFH4res as nothing but its status", () => {
    // `struct PUTFH4res { nfsstat4 status; }` — PUTROOTFH, PUTPUBFH, SAVEFH,
    // RESTOREFH, LOOKUP, LOOKUPP, VERIFY, NVERIFY and ILLEGAL are the same
    // struct: they answer by moving the cursor, so there is nothing to send.
    golden(writeStatusRes, readStatusRes, { status: NFS4ERR_STALE }, [
      "00000046", // NFS4ERR_STALE = 70
    ]);
  });

  it("writes a void-argument operation as its opcode alone", () => {
    // `case OP_PUTROOTFH: void;` in `nfs_argop4` — four bytes and no body.
    const bytes = encodeXdr((writer) => writeArgop4(writer, { op: OP_PUTROOTFH, args: undefined }));
    expect(hex(bytes)).toBe("00000018"); // OP_PUTROOTFH = 24
  });
});

describe("LOOKUP (section 18.13)", () => {
  it("encodes LOOKUP4args as a bare component4", () => {
    golden(writeLookupArgs, readLookupArgs, { objname: "beta" }, [
      "00000004", // component4 length = 4
      "62657461", // "beta"
    ]);
  });

  it("encodes LOOKUP4res as a bare status", () => {
    golden(writeStatusRes, readStatusRes, { status: NFS4ERR_NOENT }, [
      "00000002", // NFS4ERR_NOENT = 2
    ]);
  });
});

describe("GETATTR (section 18.7)", () => {
  it("encodes GETATTR4args as a bitmap4 of attribute numbers", () => {
    golden(
      writeGetattrArgs,
      readGetattrArgs,
      { attrRequest: bitmapOf([FATTR4_SIZE, FATTR4_NUMLINKS]) },
      [
        "00000002", // bitmap4 count = 2 words
        "00000010", // word 0, bit 4 = size
        "00000008", // word 1, bit 3 = attribute 35 (numlinks)
      ],
    );
  });

  it("encodes GETATTR4resok's fattr4 as a bitmap and a packed attrlist4", () => {
    golden(
      writeGetattrRes,
      readGetattrRes,
      {
        status: NFS4_OK,
        objAttributes: {
          attrmask: bitmapOf([FATTR4_SIZE, FATTR4_NUMLINKS]),
          values: { size: 0x00_00_00_01_00_00_20_00n, numlinks: 7 },
          unsupported: [],
        },
      },
      [
        "00000000", // nfsstat4 = NFS4_OK
        "00000002", // attrmask count = 2 words
        "00000010", // word 0: size
        "00000008", // word 1: numlinks
        "0000000c", // attrlist4 length = 12
        "00000001",
        "00002000", // size = 0x100002000, ascending attribute order first
        "00000007", // numlinks = 7
      ],
    );
  });

  it("encodes a failed GETATTR4res as the status alone (the void arm)", () => {
    golden(writeGetattrRes, readGetattrRes, { status: NFS4ERR_NOENT, objAttributes: undefined }, [
      "00000002", // NFS4ERR_NOENT
    ]);
  });
});

describe("GETFH (section 18.8)", () => {
  it("encodes GETFH4resok's filehandle", () => {
    golden(
      writeGetfhRes,
      readGetfhRes,
      { status: NFS4_OK, object: new Uint8Array([0x5a, 0x5b, 0x5c, 0x5d, 0x6a, 0x6b, 0x6c, 0x6d]) },
      [
        "00000000", // NFS4_OK
        "00000008", // nfs_fh4 length = 8
        "5a5b5c5d",
        "6a6b6c6d",
      ],
    );
  });
});

describe("SETATTR (section 18.30)", () => {
  it("encodes SETATTR4args as a stateid4 then a fattr4", () => {
    golden(
      writeSetattrArgs,
      readSetattrArgs,
      {
        stateid: {
          seqid: 0x0a_0b_0c_0d,
          other: new Uint8Array([
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
          ]),
        },
        objAttributes: {
          attrmask: bitmapOf([FATTR4_SIZE, FATTR4_MODE, FATTR4_TIME_MODIFY_SET]),
          values: {
            size: 0x00_00_00_03_00_00_40_00n,
            mode: 0o640,
            timeModifySet: {
              how: SET_TO_CLIENT_TIME4,
              time: { seconds: 1_700_000_003n, nseconds: 123 },
            },
          },
          unsupported: [],
        },
      },
      [
        "0a0b0c0d", // stateid4.seqid
        "21222324", // stateid4.other[12]
        "25262728",
        "292a2b2c",
        "00000002", // attrmask count = 2 words
        "00000010", // word 0, bit 4 = size
        "00400002", // word 1, bits 1 and 22 = mode (33) and time_modify_set (54)
        "0000001c", // attrlist4 length = 28
        "00000003",
        "00004000", // size = 0x300004000
        "000001a0", // mode = 0640
        "00000001", // settime4.set_it = SET_TO_CLIENT_TIME4
        "00000000",
        "6553f103", // nfstime4.seconds = 1700000003, a *signed* 64-bit count
        "0000007b", // nfstime4.nseconds = 123
      ],
    );
  });

  it("carries attrsset on a failed SETATTR4res, because it is not a union", () => {
    // The one result in this file that is `struct { nfsstat4; bitmap4; }` and
    // not `union switch (nfsstat4)`: a SETATTR that failed part-way still has
    // to say what it managed to set (section 18.30.4), and a decoder that
    // skipped the bitmap here would desync the rest of the COMPOUND.
    golden(
      writeSetattrRes,
      readSetattrRes,
      { status: NFS4ERR_INVAL, attrsset: bitmapOf([FATTR4_SIZE]) },
      [
        "00000016", // NFS4ERR_INVAL = 22
        "00000001", // bitmap4 count = 1 word
        "00000010", // bit 4 = size was set before the failure
      ],
    );
  });

  it("carries attrsset on a successful SETATTR4res too", () => {
    golden(
      writeSetattrRes,
      readSetattrRes,
      { status: NFS4_OK, attrsset: bitmapOf([FATTR4_SIZE, FATTR4_NUMLINKS]) },
      [
        "00000000", // NFS4_OK
        "00000002", // bitmap4 count = 2 words
        "00000010", // word 0: size
        "00000008", // word 1: numlinks
      ],
    );
  });
});

describe("ACCESS (section 18.1)", () => {
  it("encodes ACCESS4args as one word of request bits", () => {
    golden(writeAccessArgs, readAccessArgs, { access: 0x23 }, [
      "00000023", // READ | LOOKUP | EXECUTE
    ]);
  });

  it("encodes ACCESS4resok's supported and access, in that order", () => {
    // The pair most worth pinning: two same-typed adjacent words that mean
    // different things, which is exactly where a transposition hides.
    golden(writeAccessRes, readAccessRes, { status: NFS4_OK, supported: 0x3f, access: 0x23 }, [
      "00000000", // NFS4_OK
      "0000003f", // supported = every bit evaluated
      "00000023", // access = the ones granted
    ]);
  });

  it("encodes a failed ACCESS4res as the status alone", () => {
    golden(writeAccessRes, readAccessRes, { status: NFS4ERR_ACCESS, supported: 0, access: 0 }, [
      "0000000d", // NFS4ERR_ACCESS = 13
    ]);
  });
});

describe("READLINK (section 18.24)", () => {
  it("encodes READLINK4resok's linktext4", () => {
    golden(writeReadlinkRes, readReadlinkRes, { status: NFS4_OK, link: "../target" }, [
      "00000000", // NFS4_OK
      "00000009", // linktext4 length = 9
      "2e2e2f74", // "../t"
      "61726765", // "arge"
      "74000000", // "t" plus three bytes of XDR padding
    ]);
  });

  it("encodes a failed READLINK4res as the status alone", () => {
    golden(writeReadlinkRes, readReadlinkRes, { status: NFS4ERR_INVAL, link: undefined }, [
      "00000016", // NFS4ERR_INVAL
    ]);
  });
});

describe("READDIR (section 18.23)", () => {
  it("encodes READDIR4args' five fields in RFC order", () => {
    golden(
      writeReaddirArgs,
      readReaddirArgs,
      {
        cookie: 0x00_00_00_02_00_00_00_07n,
        cookieverf: new Uint8Array([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]),
        dircount: 0x10_00,
        maxcount: 0x80_00,
        attrRequest: bitmapOf([FATTR4_FILEID]),
      },
      [
        "00000002",
        "00000007", // nfs_cookie4 = 0x200000007
        "31323334",
        "35363738", // verifier4 cookieverf[8]
        "00001000", // dircount — names and cookies only
        "00008000", // maxcount — the whole reply
        "00000001", // attr_request: 1 word
        "00100000", // bit 20 = fileid
      ],
    );
  });

  it("encodes dirlist4 as XDR's linked list, each entry carrying its own fattr4", () => {
    golden(
      writeReaddirRes,
      readReaddirRes,
      {
        status: NFS4_OK,
        cookieverf: new Uint8Array([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48]),
        reply: {
          entries: [
            {
              cookie: 0x00_00_00_03_00_00_00_09n,
              name: "ab",
              attrs: {
                attrmask: bitmapOf([FATTR4_FILEID]),
                values: { fileid: 0x00_00_00_0a_00_00_00_0bn },
                unsupported: [],
              },
            },
            {
              cookie: 0x00_00_00_04_00_00_00_11n,
              name: "cde",
              attrs: {
                attrmask: bitmapOf([FATTR4_FILEID]),
                values: { fileid: 0x00_00_00_0c_00_00_00_0dn },
                unsupported: [],
              },
            },
          ],
          eof: true,
        },
      },
      [
        "00000000", // NFS4_OK
        "41424344",
        "45464748", // READDIR4resok.cookieverf
        "00000001", // entry4 *nextentry: one follows
        "00000003",
        "00000009", // entry 1 cookie
        "00000002", // name length = 2
        "61620000", // "ab" plus padding
        "00000001", // attrmask count = 1 word
        "00100000", // bit 20 = fileid
        "00000008", // attrlist4 length = 8
        "0000000a",
        "0000000b", // fileid
        "00000001", // another entry follows
        "00000004",
        "00000011", // entry 2 cookie
        "00000003", // name length = 3
        "63646500", // "cde" plus padding
        "00000001", // attrmask count
        "00100000", // fileid again
        "00000008", // attrlist4 length
        "0000000c",
        "0000000d", // fileid
        "00000000", // no more entries
        "00000001", // dirlist4.eof = TRUE
      ],
      // The list markers, the two entries' identical attribute requests, and
      // the NFS4_OK/end-of-list zero are structure, not fields; every cookie,
      // name and fileid below them is distinct.
      ["00000001", "00000000", "00000003", "00000002", "00100000", "00000008"],
    );
  });

  it("encodes a failed READDIR4res as the status alone", () => {
    golden(
      writeReaddirRes,
      readReaddirRes,
      {
        status: NFS4ERR_BAD_COOKIE,
        cookieverf: new Uint8Array(8),
        reply: { entries: [], eof: false },
      },
      [
        "00002713", // NFS4ERR_BAD_COOKIE = 10003
      ],
    );
  });
});

describe("LINK (section 18.9) / REMOVE (18.25) / RENAME (18.26)", () => {
  it("encodes LINK4args as the new name alone — both objects are on the cursor", () => {
    golden(writeLinkArgs, readLinkArgs, { newname: "hard" }, [
      "00000004", // component4 length
      "68617264", // "hard"
    ]);
  });

  it("encodes LINK4resok's change_info4", () => {
    golden(
      writeLinkRes,
      readLinkRes,
      {
        status: NFS4_OK,
        cinfo: {
          atomic: true,
          before: 0x00_00_00_11_00_00_00_22n,
          after: 0x00_00_00_33_00_00_00_44n,
        },
      },
      [
        "00000000", // NFS4_OK
        "00000001", // change_info4.atomic = TRUE
        "00000011",
        "00000022", // before
        "00000033",
        "00000044", // after
      ],
    );
  });

  it("encodes a failed LINK4res as the status alone", () => {
    golden(writeLinkRes, readLinkRes, { status: NFS4ERR_MLINK, cinfo: undefined }, [
      "0000001f", // NFS4ERR_MLINK = 31
    ]);
  });

  it("encodes REMOVE4args and REMOVE4resok", () => {
    golden(writeRemoveArgs, readRemoveArgs, { target: "gone" }, [
      "00000004", // component4 length
      "676f6e65", // "gone"
    ]);
    golden(
      writeRemoveRes,
      readRemoveRes,
      {
        status: NFS4_OK,
        cinfo: {
          atomic: true,
          before: 0x00_00_01_23_00_00_04_56n,
          after: 0x00_00_07_89_00_00_0a_bcn,
        },
      },
      [
        "00000000", // NFS4_OK
        "00000001", // atomic
        "00000123",
        "00000456", // before
        "00000789",
        "00000abc", // after
      ],
    );
    golden(writeRemoveRes, readRemoveRes, { status: NFS4ERR_NOTEMPTY, cinfo: undefined }, [
      "00000042", // NFS4ERR_NOTEMPTY = 66
    ]);
  });

  it("encodes RENAME4args as oldname then newname", () => {
    golden(writeRenameArgs, readRenameArgs, { oldname: "old", newname: "newer" }, [
      "00000003", // oldname length = 3 (SAVED_FH is the source directory)
      "6f6c6400", // "old" plus padding
      "00000005", // newname length = 5 (CURRENT_FH is the target directory)
      "6e657765",
      "72000000", // "newer" plus padding
    ]);
  });

  it("encodes RENAME4resok's two change_info4s, source first", () => {
    golden(
      writeRenameRes,
      readRenameRes,
      {
        status: NFS4_OK,
        sourceCinfo: {
          atomic: true,
          before: 0x00_00_00_55_00_00_00_66n,
          after: 0x00_00_00_77_00_00_00_88n,
        },
        targetCinfo: {
          atomic: false,
          before: 0x00_00_00_99_00_00_00_aan,
          after: 0x00_00_00_bb_00_00_00_ccn,
        },
      },
      [
        "00000000", // NFS4_OK
        "00000001", // source_cinfo.atomic = TRUE
        "00000055",
        "00000066", // source before
        "00000077",
        "00000088", // source after
        "00000000", // target_cinfo.atomic = FALSE
        "00000099",
        "000000aa", // target before
        "000000bb",
        "000000cc", // target after
      ],
      // FALSE and NFS4_OK are both a zero word; every changeid4 is distinct.
      ["00000000"],
    );
  });

  it("encodes a failed RENAME4res as the status alone", () => {
    golden(
      writeRenameRes,
      readRenameRes,
      { status: NFS4ERR_XDEV, sourceCinfo: undefined, targetCinfo: undefined },
      [
        "00000012", // NFS4ERR_XDEV = 18
      ],
    );
  });
});

describe("CREATE (section 18.4)", () => {
  it("encodes CREATE4args with createtype4's NF4LNK arm", () => {
    golden(
      writeCreateArgs,
      readCreateArgs,
      {
        objtype: { type: NF4LNK, linkdata: "to/x" },
        objname: "lnk",
        createattrs: {
          attrmask: bitmapOf([FATTR4_MODE, FATTR4_OWNER]),
          values: { mode: 0o777, owner: "123456" },
          unsupported: [],
        },
      },
      [
        "00000005", // createtype4.type = NF4LNK
        "00000004", // linktext4 length = 4
        "746f2f78", // "to/x"
        "00000003", // objname length = 3
        "6c6e6b00", // "lnk" plus padding
        "00000002", // createattrs.attrmask count = 2 words
        "00000000", // word 0: nothing below attribute 32
        "00000012", // word 1, bits 1 and 4 = mode (33) and owner (36)
        "00000010", // attrlist4 length = 16
        "000001ff", // mode = 0777
        "00000006", // owner length = 6
        "31323334",
        "35360000", // "123456" plus padding
      ],
    );
  });

  it("encodes CREATE4resok's cinfo and attrset", () => {
    golden(
      writeCreateRes,
      readCreateRes,
      {
        status: NFS4_OK,
        cinfo: {
          atomic: true,
          before: 0x00_00_ab_cd_00_00_11_11n,
          after: 0x00_00_22_22_00_00_33_33n,
        },
        attrset: bitmapOf([FATTR4_SIZE, FATTR4_OWNER_GROUP]),
      },
      [
        "00000000", // NFS4_OK
        "00000001", // cinfo.atomic
        "0000abcd",
        "00001111", // before
        "00002222",
        "00003333", // after
        "00000002", // attrset count = 2 words
        "00000010", // word 0, bit 4 = size
        "00000020", // word 1, bit 5 = owner_group (37)
      ],
    );
  });

  it("encodes a failed CREATE4res as the status alone", () => {
    // NF4REG selects createtype4's default arm: CREATE never makes a regular
    // file — OPEN does — so a client that asks gets NFS4ERR_BADTYPE.
    golden(
      writeCreateRes,
      readCreateRes,
      { status: NFS4ERR_BADTYPE, cinfo: undefined, attrset: undefined },
      [
        "00002717", // NFS4ERR_BADTYPE = 10007
      ],
    );
  });
});

describe("COMMIT (section 18.3)", () => {
  it("encodes COMMIT4args as offset then count", () => {
    golden(
      writeCommitArgs,
      readCommitArgs,
      { offset: 0x00_00_00_07_00_00_10_00n, count: 0x00_04_00_00 },
      [
        "00000007",
        "00001000", // offset4 (uint64)
        "00040000", // count4
      ],
    );
  });

  it("encodes COMMIT4resok's writeverf", () => {
    golden(
      writeCommitRes,
      readCommitRes,
      {
        status: NFS4_OK,
        writeverf: new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]),
      },
      [
        "00000000", // NFS4_OK
        "deadbeef",
        "01020304", // verifier4[8]
      ],
    );
  });

  it("encodes a failed COMMIT4res as the status alone", () => {
    golden(writeCommitRes, readCommitRes, { status: NFS4ERR_IO, writeverf: new Uint8Array(8) }, [
      "00000005", // NFS4ERR_IO = 5
    ]);
  });
});

describe("VERIFY (section 18.31) / NVERIFY (18.15)", () => {
  const ARGS = {
    objAttributes: {
      attrmask: bitmapOf([FATTR4_CHANGE, FATTR4_SIZE]),
      values: { change: 0x11_22_33_44_55_66_77_88n, size: 0x00_00_00_09_00_00_0a_bcn },
      unsupported: [],
    },
  };

  const WORDS = [
    "00000001", // attrmask count = 1 word
    "00000018", // bits 3 and 4 = change and size
    "00000010", // attrlist4 length = 16
    "11223344",
    "55667788", // change
    "00000009",
    "00000abc", // size
  ];

  it("encodes VERIFY4args as a bare fattr4", () => {
    golden(writeVerifyArgs, readVerifyArgs, ARGS, WORDS);
  });

  it("encodes NVERIFY4args identically — the same struct, opposite sense", () => {
    // `struct NVERIFY4args` and `struct VERIFY4args` are the same declaration;
    // only the status they answer with differs.
    expect(hex(encodeXdr((writer) => writeVerifyArgs(writer, ARGS)))).toBe(WORDS.join(" "));
  });

  it("encodes the two results as bare statuses", () => {
    golden(writeStatusRes, readStatusRes, { status: NFS4ERR_NOT_SAME }, [
      "0000272b", // VERIFY: NFS4ERR_NOT_SAME = 10027
    ]);
    golden(writeStatusRes, readStatusRes, { status: NFS4ERR_SAME }, [
      "00002719", // NVERIFY: NFS4ERR_SAME = 10009
    ]);
  });
});

describe("SECINFO (section 18.29) / SECINFO_NO_NAME (18.45)", () => {
  it("encodes SECINFO4args as a component4", () => {
    golden(writeSecinfoArgs, readSecinfoArgs, { name: "sec" }, [
      "00000003", // component4 length
      "73656300", // "sec" plus padding
    ]);
  });

  it("encodes a flavor list, with rpcsec_gss_info only under RPCSEC_GSS", () => {
    // The union's body exists for flavor 6 alone (RFC 2203); AUTH_NONE and
    // AUTH_SYS are the bare number. This server never emits the GSS arm and
    // still has to decode it, so the fixture carries all three.
    golden(
      writeSecinfoRes,
      readSecinfoRes,
      {
        status: NFS4_OK,
        flavors: [
          { flavor: AUTH_NONE },
          { flavor: AUTH_SYS },
          {
            flavor: RPCSEC_GSS,
            info: {
              // The Kerberos V5 mechanism OID, 1.2.840.113554.1.2.2.
              oid: new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]),
              qop: 4,
              service: 2,
            },
          },
        ],
      },
      [
        "00000000", // NFS4_OK
        "00000003", // SECINFO4resok<> count = 3
        "00000000", // secinfo4.flavor = AUTH_NONE, void arm
        "00000001", // secinfo4.flavor = AUTH_SYS, void arm
        "00000006", // secinfo4.flavor = RPCSEC_GSS, and a body follows
        "00000009", // sec_oid4 length = 9
        "2a864886",
        "f7120102",
        "02000000", // the OID plus padding
        "00000004", // qop4
        "00000002", // rpc_gss_svc_t = RPC_GSS_SVC_INTEGRITY
      ],
      // AUTH_NONE is flavor zero and NFS4_OK is status zero.
      ["00000000"],
    );
  });

  it("encodes a failed SECINFO4res as the status alone", () => {
    golden(writeSecinfoRes, readSecinfoRes, { status: NFS4ERR_WRONGSEC, flavors: [] }, [
      "00002720", // NFS4ERR_WRONGSEC = 10016
    ]);
  });

  it("encodes SECINFO_NO_NAME4args as a bare secinfo_style4", () => {
    golden(writeSecinfoNoNameArgs, readSecinfoNoNameArgs, { style: SECINFO_STYLE4_PARENT }, [
      "00000001", // SECINFO_STYLE4_PARENT
    ]);
  });
});

describe("CLOSE (section 18.2) / OPEN_DOWNGRADE (18.18)", () => {
  it("encodes CLOSE4args as seqid then stateid4", () => {
    golden(writeCloseArgs, readCloseArgs, { seqid: 7, openStateid: STATEID }, [
      "00000007", // CLOSE4args.seqid — vestigial in 4.1, on the wire regardless
      "0a0b0c0d", // open_stateid.seqid
      "61626364",
      "65666768",
      "696a6b6c", // open_stateid.other[12]
    ]);
  });

  it("encodes CLOSE4res as a bare stateid4 on NFS4_OK, not a resok struct", () => {
    golden(writeCloseRes, readCloseRes, { status: NFS4_OK, openStateid: STATEID }, [
      "00000000", // NFS4_OK
      "0a0b0c0d",
      "61626364",
      "65666768",
      "696a6b6c",
    ]);
  });

  it("encodes a failed CLOSE4res as the status alone", () => {
    golden(writeCloseRes, readCloseRes, { status: NFS4ERR_EXPIRED, openStateid: undefined }, [
      "0000271b", // NFS4ERR_EXPIRED = 10011
    ]);
  });

  it("encodes OPEN_DOWNGRADE4args with the stateid *before* the seqid", () => {
    // The opposite order from CLOSE's, and both fields are the same size, so a
    // transposition here encodes to a message of the right length.
    golden(
      writeOpenDowngradeArgs,
      readOpenDowngradeArgs,
      {
        openStateid: STATEID,
        seqid: 9,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      },
      [
        "0a0b0c0d", // open_stateid.seqid — first
        "61626364",
        "65666768",
        "696a6b6c", // open_stateid.other[12]
        "00000009", // seqid — second
        "00000003", // share_access = OPEN4_SHARE_ACCESS_BOTH
        "00000000", // share_deny = OPEN4_SHARE_DENY_NONE
      ],
    );
  });

  it("encodes OPEN_DOWNGRADE4resok's stateid", () => {
    golden(writeOpenDowngradeRes, readOpenDowngradeRes, { status: NFS4_OK, openStateid: STATEID }, [
      "00000000",
      "0a0b0c0d",
      "61626364",
      "65666768",
      "696a6b6c",
    ]);
  });
});

describe("LOCK (section 18.10) / LOCKT (18.11) / LOCKU (18.12)", () => {
  it("encodes LOCK4args with locker4's new-owner arm", () => {
    golden(
      writeLockArgs,
      readLockArgs,
      {
        locktype: WRITEW_LT,
        reclaim: false,
        offset: 0x00_00_00_20_00_00_00_30n,
        length: 0x00_00_00_40_00_00_00_50n,
        locker: {
          newLockOwner: true,
          openOwner: {
            openSeqid: 0x11,
            openStateid: STATEID,
            lockSeqid: 0x12,
            lockOwner: OWNER,
          },
        },
      },
      [
        "00000004", // nfs_lock_type4 = WRITEW_LT
        "00000000", // reclaim = FALSE
        "00000020",
        "00000030", // offset4
        "00000040",
        "00000050", // length4
        "00000001", // locker4.new_lock_owner = TRUE
        "00000011", // open_to_lock_owner4.open_seqid
        "0a0b0c0d",
        "61626364",
        "65666768",
        "696a6b6c", // open_stateid
        "00000012", // lock_seqid
        "41424344",
        "45464748", // lock_owner.clientid
        "00000006", // lock_owner.owner<> length = 6
        "71727374",
        "75760000", // the owner, padded to a word
      ],
    );
  });

  it("encodes LOCK4args with locker4's existing-owner arm", () => {
    golden(
      writeLockArgs,
      readLockArgs,
      {
        locktype: READ_LT,
        reclaim: true,
        offset: 0x00_00_00_60_00_00_00_70n,
        length: 0x00_00_00_80_00_00_00_90n,
        locker: {
          newLockOwner: false,
          lockOwner: { lockStateid: STATEID, lockSeqid: 0x13 },
        },
      },
      [
        "00000001", // nfs_lock_type4 = READ_LT
        "00000001", // reclaim = TRUE
        "00000060",
        "00000070", // offset4
        "00000080",
        "00000090", // length4
        "00000000", // locker4.new_lock_owner = FALSE
        "0a0b0c0d",
        "61626364",
        "65666768",
        "696a6b6c", // exist_lock_owner4.lock_stateid
        "00000013", // lock_seqid
      ],
      // READ_LT is 1 and so is `reclaim = TRUE`; the FALSE discriminant is the
      // only zero.
      ["00000001"],
    );
  });

  it("encodes LOCK4resok's stateid", () => {
    golden(
      writeLockRes,
      readLockRes,
      { status: NFS4_OK, lockStateid: STATEID, denied: undefined },
      ["00000000", "0a0b0c0d", "61626364", "65666768", "696a6b6c"],
    );
  });

  it("encodes LOCK4res's NFS4ERR_DENIED arm — a failure that carries a body", () => {
    // The second non-void failure shape in the protocol after SETATTR's, and
    // unlike SETATTR's it is keyed to one specific status.
    golden(
      writeLockRes,
      readLockRes,
      {
        status: NFS4ERR_DENIED,
        lockStateid: undefined,
        denied: {
          offset: 0x00_00_00_60_00_00_00_70n,
          length: 0x00_00_00_80_00_00_00_90n,
          locktype: READ_LT,
          owner: OWNER,
        },
      },
      [
        "0000271a", // NFS4ERR_DENIED = 10010
        "00000060",
        "00000070", // LOCK4denied.offset
        "00000080",
        "00000090", // LOCK4denied.length
        "00000001", // LOCK4denied.locktype = READ_LT
        "41424344",
        "45464748", // owner.clientid
        "00000006", // owner.owner<> length
        "71727374",
        "75760000",
      ],
    );
  });

  it("encodes any other LOCK4res failure as the status alone (the void arm)", () => {
    golden(
      writeLockRes,
      readLockRes,
      { status: NFS4ERR_OPENMODE, lockStateid: undefined, denied: undefined },
      ["00002736"], // NFS4ERR_OPENMODE = 10038
    );
  });

  it("encodes LOCKT4args — no stateid, because it takes nothing", () => {
    golden(
      writeLocktArgs,
      readLocktArgs,
      {
        locktype: WRITE_LT,
        offset: 0x00_00_00_02_00_00_00_03n,
        length: 0x00_00_00_04_00_00_00_05n,
        owner: OWNER,
      },
      [
        "00000002", // nfs_lock_type4 = WRITE_LT
        "00000002", // offset, high word
        "00000003", // offset, low word
        "00000004",
        "00000005", // length4
        "41424344",
        "45464748", // owner.clientid
        "00000006", // owner.owner<> length
        "71727374",
        "75760000",
      ],
      // WRITE_LT is 2 and so is the offset's high word.
      ["00000002"],
    );
  });

  it("encodes LOCKT4res as the status alone on success — success is the void arm", () => {
    golden(writeLocktRes, readLocktRes, { status: NFS4_OK, denied: undefined }, ["00000000"]);
  });

  it("encodes LOCKT4res's denied body", () => {
    golden(
      writeLocktRes,
      readLocktRes,
      {
        status: NFS4ERR_DENIED,
        denied: {
          offset: 0x00_00_0a_00_00_00_0b_00n,
          length: 0x00_00_0c_00_00_00_0d_00n,
          locktype: WRITEW_LT,
          owner: OWNER,
        },
      },
      [
        "0000271a", // NFS4ERR_DENIED
        "00000a00",
        "00000b00",
        "00000c00",
        "00000d00",
        "00000004", // locktype = WRITEW_LT
        "41424344",
        "45464748",
        "00000006",
        "71727374",
        "75760000",
      ],
    );
  });

  it("encodes LOCKU4args in RFC field order", () => {
    golden(
      writeLockuArgs,
      readLockuArgs,
      {
        locktype: WRITE_LT,
        seqid: 0x13,
        lockStateid: STATEID,
        offset: 0x00_00_0a_00_00_00_0b_00n,
        length: 0x00_00_0c_00_00_00_0d_00n,
      },
      [
        "00000002", // nfs_lock_type4 = WRITE_LT
        "00000013", // seqid
        "0a0b0c0d",
        "61626364",
        "65666768",
        "696a6b6c", // lock_stateid
        "00000a00",
        "00000b00", // offset4
        "00000c00",
        "00000d00", // length4
      ],
    );
  });

  it("encodes LOCKU4res as a bare stateid on NFS4_OK", () => {
    golden(writeLockuRes, readLockuRes, { status: NFS4_OK, lockStateid: STATEID }, [
      "00000000",
      "0a0b0c0d",
      "61626364",
      "65666768",
      "696a6b6c",
    ]);
  });
});

describe("OPEN (section 18.16)", () => {
  it("encodes OPEN4args with CLAIM_NULL and an UNCHECKED4 create", () => {
    golden(
      writeOpenArgs,
      readOpenArgs,
      {
        seqid: 0x21,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: OPEN4_SHARE_DENY_NONE,
        owner: OWNER,
        openhow: {
          opentype: OPEN4_CREATE,
          how: {
            mode: UNCHECKED4,
            createattrs: {
              attrmask: bitmapOf([FATTR4_MODE]),
              values: { mode: 0o644 },
              unsupported: [],
            },
          },
        },
        claim: { claim: CLAIM_NULL, file: "newfile" },
      },
      [
        "00000021", // seqid
        "00000003", // share_access = OPEN4_SHARE_ACCESS_BOTH
        "00000000", // share_deny = OPEN4_SHARE_DENY_NONE
        "41424344",
        "45464748", // open_owner4.clientid
        "00000006", // open_owner4.owner<> length
        "71727374",
        "75760000",
        "00000001", // openflag4.opentype = OPEN4_CREATE
        "00000000", // createhow4.mode = UNCHECKED4
        "00000002", // createattrs.attrmask count = 2 words
        "00000000", // word 0 — mode is attribute 33, so nothing below 32
        "00000002", // word 1, bit 1 = attribute 33 (mode)
        "00000004", // attrlist4 length = 4
        "000001a4", // mode = 0o644
        "00000000", // open_claim4.claim = CLAIM_NULL
        "00000007", // component4 length = 7
        "6e657766",
        "696c6500", // "newfile", padded
      ],
      // Zero is SHARE_DENY_NONE, UNCHECKED4, the empty bitmap word and
      // CLAIM_NULL; two is the bitmap's word count and its word 1.
      ["00000000", "00000002"],
    );
  });

  it("encodes OPEN4args with EXCLUSIVE4_1 and the CLAIM_FH void arm", () => {
    // EXCLUSIVE4_1 is 4.1's replacement for EXCLUSIVE4: a verifier *and*
    // attributes, where EXCLUSIVE4 had to smuggle the verifier into a time
    // attribute and could set nothing.
    golden(
      writeOpenArgs,
      readOpenArgs,
      {
        seqid: 0x22,
        shareAccess: OPEN4_SHARE_ACCESS_WRITE,
        shareDeny: OPEN4_SHARE_DENY_BOTH,
        owner: { clientid: 0x01_02_03_04_05_06_07_08n, owner: OWNERID },
        openhow: {
          opentype: OPEN4_CREATE,
          how: {
            mode: EXCLUSIVE4_1,
            createboth: {
              verf: VERIFIER,
              attrs: {
                attrmask: bitmapOf([FATTR4_SIZE]),
                values: { size: 0x00_00_ab_cd_00_00_ef_01n },
                unsupported: [],
              },
            },
          },
        },
        claim: { claim: CLAIM_FH },
      },
      [
        "00000022", // seqid
        "00000002", // share_access = OPEN4_SHARE_ACCESS_WRITE
        "00000003", // share_deny = OPEN4_SHARE_DENY_BOTH
        "01020304",
        "05060708", // open_owner4.clientid
        "00000006", // owner<> length
        "71727374",
        "75760000",
        "00000001", // openflag4.opentype = OPEN4_CREATE
        "00000003", // createhow4.mode = EXCLUSIVE4_1
        "81828384",
        "85868788", // creatverfattr.cva_verf[8]
        "00000001", // cva_attrs.attrmask count = 1 word
        "00000010", // word 0, bit 4 = size
        "00000008", // attrlist4 length = 8
        "0000abcd",
        "0000ef01", // size
        "00000004", // open_claim4.claim = CLAIM_FH — a void arm, nothing follows
      ],
      // The 0..3 enums collide by construction: 3 is both SHARE_DENY_BOTH and
      // EXCLUSIVE4_1, 1 is both OPEN4_CREATE and the bitmap's word count.
      ["00000001", "00000003"],
    );
  });

  it("encodes OPEN4resok with the OPEN_DELEGATE_NONE arm", () => {
    golden(
      writeOpenRes,
      readOpenRes,
      {
        status: NFS4_OK,
        stateid: STATEID,
        cinfo: {
          atomic: true,
          before: 0x00_00_00_11_00_00_00_12n,
          after: 0x00_00_00_13_00_00_00_14n,
        },
        rflags: OPEN4_RESULT_LOCKTYPE_POSIX,
        attrset: bitmapOf([FATTR4_SIZE]),
        delegation: { delegationType: OPEN_DELEGATE_NONE },
      },
      [
        "00000000", // NFS4_OK
        "0a0b0c0d",
        "61626364",
        "65666768",
        "696a6b6c", // OPEN4resok.stateid
        "00000001", // cinfo.atomic = TRUE
        "00000011",
        "00000012", // cinfo.before
        "00000013",
        "00000014", // cinfo.after
        "00000004", // rflags = OPEN4_RESULT_LOCKTYPE_POSIX
        "00000001", // attrset count = 1 word
        "00000010", // word 0, bit 4 = size
        "00000000", // open_delegation4.delegation_type = OPEN_DELEGATE_NONE
      ],
      // Zero is NFS4_OK and OPEN_DELEGATE_NONE; one is `atomic` and the
      // bitmap's word count.
      ["00000000", "00000001"],
    );
  });

  it("encodes OPEN4resok with the OPEN_DELEGATE_NONE_EXT arm and a reason", () => {
    golden(
      writeOpenRes,
      readOpenRes,
      {
        status: NFS4_OK,
        stateid: STATEID,
        cinfo: {
          atomic: false,
          before: 0x00_00_00_21_00_00_00_22n,
          after: 0x00_00_00_23_00_00_00_24n,
        },
        rflags: OPEN4_RESULT_MAY_NOTIFY_LOCK,
        attrset: [],
        delegation: {
          delegationType: OPEN_DELEGATE_NONE_EXT,
          whynone: { why: WND4_RESOURCE, serverWillSignalAvail: true },
        },
      },
      [
        "00000000", // NFS4_OK
        "0a0b0c0d",
        "61626364",
        "65666768",
        "696a6b6c",
        "00000000", // cinfo.atomic = FALSE
        "00000021",
        "00000022",
        "00000023",
        "00000024",
        "00000020", // rflags = OPEN4_RESULT_MAY_NOTIFY_LOCK
        "00000000", // attrset count = 0 words — the empty bitmap
        "00000003", // delegation_type = OPEN_DELEGATE_NONE_EXT
        "00000002", // ond_why = WND4_RESOURCE
        "00000001", // ond_server_will_signal_avail = TRUE
      ],
      // Zero is NFS4_OK, `atomic = FALSE` and the empty bitmap's word count.
      ["00000000"],
    );
  });

  it("encodes a failed OPEN4res as the status alone", () => {
    golden(
      writeOpenRes,
      readOpenRes,
      {
        status: NFS4ERR_SHARE_DENIED,
        stateid: undefined,
        cinfo: undefined,
        rflags: 0,
        attrset: undefined,
        delegation: undefined,
      },
      ["0000271f"], // NFS4ERR_SHARE_DENIED = 10015
    );
  });
});

describe("READ (section 18.22) / WRITE (18.32)", () => {
  it("encodes READ4args as stateid, offset, count", () => {
    golden(
      writeReadArgs,
      readReadArgs,
      { stateid: STATEID, offset: 0x00_00_01_00_00_00_02_00n, count: 0x1000 },
      [
        "0a0b0c0d",
        "61626364",
        "65666768",
        "696a6b6c", // stateid4
        "00000100",
        "00000200", // offset4
        "00001000", // count4
      ],
    );
  });

  it("encodes READ4resok as eof *then* data, with no count word", () => {
    // Unlike NFSv3's READ there is no `count` beside the payload — the counted
    // opaque is the count — and `eof` comes first.
    golden(
      writeReadRes,
      readReadRes,
      { status: NFS4_OK, eof: true, data: new Uint8Array([0xc1, 0xc2, 0xc3]) },
      [
        "00000000", // NFS4_OK
        "00000001", // eof = TRUE
        "00000003", // data<> length = 3
        "c1c2c300", // three bytes and one pad byte
      ],
    );
  });

  it("encodes a failed READ4res as the status alone", () => {
    golden(
      writeReadRes,
      readReadRes,
      { status: NFS4ERR_OPENMODE, eof: false, data: new Uint8Array(0) },
      [
        "00002736", // NFS4ERR_OPENMODE = 10038
      ],
    );
  });

  it("encodes WRITE4args with a non-word-aligned payload, padding and all", () => {
    // Five bytes: the length word says 5 and three pad bytes follow, so the
    // next field starts on a word boundary. Getting this wrong desyncs
    // everything after the operation rather than corrupting the payload.
    golden(
      writeWriteArgs,
      readWriteArgs,
      {
        stateid: STATEID,
        offset: 0x00_00_03_00_00_00_04_00n,
        stable: DATA_SYNC4,
        data: new Uint8Array([0xd1, 0xd2, 0xd3, 0xd4, 0xd5]),
      },
      [
        "0a0b0c0d",
        "61626364",
        "65666768",
        "696a6b6c", // stateid4
        "00000300",
        "00000400", // offset4
        "00000001", // stable_how4 = DATA_SYNC4
        "00000005", // data<> length = 5
        "d1d2d3d4",
        "d5000000", // one byte and three of padding
      ],
    );
  });

  it("encodes WRITE4resok as count, committed, verifier", () => {
    golden(
      writeWriteRes,
      readWriteRes,
      { status: NFS4_OK, count: 5, committed: FILE_SYNC4, writeverf: VERIFIER },
      [
        "00000000", // NFS4_OK
        "00000005", // count4
        "00000002", // stable_how4 = FILE_SYNC4 — may be stronger than asked, never weaker
        "81828384",
        "85868788", // writeverf[8]
      ],
    );
  });
});

describe("BACKCHANNEL_CTL (section 18.33) / BIND_CONN_TO_SESSION (18.34)", () => {
  it("encodes BACKCHANNEL_CTL4args with a void and an AUTH_SYS sec parm", () => {
    golden(
      writeBackchannelCtlArgs,
      readBackchannelCtlArgs,
      {
        cbProgram: 0x40_00_00_01,
        secParms: [
          { secflavor: AUTH_NONE },
          {
            secflavor: AUTH_SYS,
            sysCred: {
              stamp: 0x11_22_33_44,
              machineName: "mntx",
              uid: 1000,
              gid: 1001,
              gids: [7, 8],
            },
          },
        ],
      },
      [
        "40000001", // bca_cb_program
        "00000002", // bca_sec_parms<> count = 2
        "00000000", // cb_secflavor = AUTH_NONE — the void arm
        "00000001", // cb_secflavor = AUTH_SYS
        "11223344", // authsys_parms.stamp
        "00000004", // machinename<255> length = 4
        "6d6e7478", // "mntx"
        "000003e8", // uid = 1000
        "000003e9", // gid = 1001
        "00000002", // gids<16> count = 2
        "00000007",
        "00000008", // the gids
      ],
      // Both twos are array counts, which is XDR's structure and not a field.
      ["00000002"],
    );
  });

  it("encodes BIND_CONN_TO_SESSION4args, and CDFC4_BACK_OR_BOTH is seven", () => {
    // The `_OR_BOTH` values are bit unions, not a continuing count: guessing
    // the next integer after CDFC4_FORE_OR_BOTH = 3 gives 4, and the answer
    // is 7.
    golden(
      writeBindConnToSessionArgs,
      readBindConnToSessionArgs,
      { sessionid: SESSIONID, dir: CDFC4_BACK_OR_BOTH, useConnInRdmaMode: false },
      [
        "51525354",
        "55565758",
        "595a5b5c",
        "5d5e5f60", // sessionid4[16]
        "00000007", // bctsa_dir = CDFC4_BACK_OR_BOTH
        "00000000", // bctsa_use_conn_in_rdma_mode = FALSE
      ],
    );
  });

  it("encodes BIND_CONN_TO_SESSION4resok, whose direction is a different enum", () => {
    golden(
      writeBindConnToSessionRes,
      readBindConnToSessionRes,
      { status: NFS4_OK, sessionid: SESSIONID, dir: CDFS4_BOTH, useConnInRdmaMode: true },
      [
        "00000000", // NFS4_OK
        "51525354",
        "55565758",
        "595a5b5c",
        "5d5e5f60",
        "00000003", // bctsr_dir = CDFS4_BOTH — channel_dir_from_server4, not _client4
        "00000001", // bctsr_use_conn_in_rdma_mode = TRUE
      ],
    );
  });
});

describe("EXCHANGE_ID (section 18.35)", () => {
  it("encodes EXCHANGE_ID4args with SP4_NONE's void arm and one impl id", () => {
    golden(
      writeExchangeIdArgs,
      readExchangeIdArgs,
      {
        clientowner: { verifier: VERIFIER, ownerid: OWNERID },
        flags: EXCHGID4_FLAG_USE_NON_PNFS,
        stateProtect: { how: SP4_NONE },
        clientImplId: [
          {
            domain: "mountx.dev",
            name: "mx",
            date: { seconds: 0x00_00_00_98_00_00_00_99n, nseconds: 0x7654 },
          },
        ],
      },
      [
        "81828384",
        "85868788", // client_owner4.co_verifier[8]
        "00000006", // co_ownerid<> length = 6
        "71727374",
        "75760000",
        "00010000", // eia_flags = EXCHGID4_FLAG_USE_NON_PNFS
        "00000000", // state_protect4_a.spa_how = SP4_NONE — void, nothing follows
        "00000001", // eia_client_impl_id<1> count = 1
        "0000000a", // nii_domain length = 10
        "6d6f756e",
        "74782e64",
        "65760000", // "mountx.dev", padded
        "00000002", // nii_name length = 2
        "6d780000", // "mx", padded
        "00000098",
        "00000099", // nii_date.seconds (a signed hyper)
        "00007654", // nii_date.nseconds
      ],
    );
  });

  it("encodes EXCHANGE_ID4resok", () => {
    golden(
      writeExchangeIdRes,
      readExchangeIdRes,
      {
        status: NFS4_OK,
        clientid: 0x01_02_03_04_05_06_07_08n,
        sequenceid: 0x31,
        // `>>> 0`: JavaScript's `|` yields a *signed* int32, so the top bit
        // makes it negative. The encoder writes the same four bytes either
        // way, and the decoder returns the unsigned value — so a fixture
        // holding the signed one round-trips to a different number.
        flags: (EXCHGID4_FLAG_USE_NON_PNFS | EXCHGID4_FLAG_CONFIRMED_R) >>> 0,
        stateProtect: { how: SP4_NONE },
        serverOwner: { minorId: 0x00_00_00_41_00_00_00_42n, majorId: OWNERID },
        serverScope: new Uint8Array([0x91, 0x92]),
        serverImplId: [],
      },
      [
        "00000000", // NFS4_OK
        "01020304",
        "05060708", // eir_clientid
        "00000031", // eir_sequenceid
        "80010000", // eir_flags = USE_NON_PNFS | CONFIRMED_R
        "00000000", // state_protect4_r.spr_how = SP4_NONE
        "00000041",
        "00000042", // server_owner4.so_minor_id
        "00000006", // so_major_id<> length = 6
        "71727374",
        "75760000",
        "00000002", // eir_server_scope<> length = 2
        "91920000", // the scope, padded
        "00000000", // eir_server_impl_id<1> count = 0
      ],
      // Zero is NFS4_OK, SP4_NONE and the empty impl-id array's count.
      ["00000000"],
    );
  });
});

describe("CREATE_SESSION (section 18.36) / DESTROY_SESSION (18.37)", () => {
  it("encodes CREATE_SESSION4args with distinct fore and back channel attributes", () => {
    // Six `count4`s in a row twice over: the fore and back attributes are the
    // same struct in adjacent positions, which is the transposition a fixture
    // built from matching values would never catch.
    golden(
      writeCreateSessionArgs,
      readCreateSessionArgs,
      {
        clientid: 0x01_02_03_04_05_06_07_08n,
        sequence: 0x31,
        flags: CREATE_SESSION4_FLAG_CONN_BACK_CHAN,
        foreChanAttrs: {
          headerpadsize: 0x11,
          maxrequestsize: 0x12,
          maxresponsesize: 0x13,
          maxresponsesizeCached: 0x14,
          maxoperations: 0x15,
          maxrequests: 0x16,
          rdmaIrd: [0x17],
        },
        backChanAttrs: {
          headerpadsize: 0x21,
          maxrequestsize: 0x22,
          maxresponsesize: 0x23,
          maxresponsesizeCached: 0x24,
          maxoperations: 0x25,
          maxrequests: 0x26,
          rdmaIrd: [],
        },
        cbProgram: 0x40_00_00_01,
        secParms: [{ secflavor: AUTH_NONE }],
      },
      [
        "01020304",
        "05060708", // csa_clientid
        "00000031", // csa_sequence
        "00000002", // csa_flags = CREATE_SESSION4_FLAG_CONN_BACK_CHAN
        "00000011", // fore: ca_headerpadsize
        "00000012", // ca_maxrequestsize
        "00000013", // ca_maxresponsesize
        "00000014", // ca_maxresponsesize_cached
        "00000015", // ca_maxoperations
        "00000016", // ca_maxrequests
        "00000001", // ca_rdma_ird<1> count = 1
        "00000017", // the one element
        "00000021", // back: ca_headerpadsize
        "00000022",
        "00000023",
        "00000024",
        "00000025",
        "00000026",
        "00000000", // back ca_rdma_ird<1> count = 0
        "40000001", // csa_cb_program
        "00000001", // csa_sec_parms<> count = 1
        "00000000", // cb_secflavor = AUTH_NONE
      ],
      // Two array counts of 1, and a zero that is both an empty array's count
      // and AUTH_NONE.
      ["00000000", "00000001"],
    );
  });

  it("encodes CREATE_SESSION4resok — the server's counter-offer", () => {
    golden(
      writeCreateSessionRes,
      readCreateSessionRes,
      {
        status: NFS4_OK,
        sessionid: SESSIONID,
        sequence: 0x31,
        flags: CREATE_SESSION4_FLAG_PERSIST,
        foreChanAttrs: {
          headerpadsize: 0x71,
          maxrequestsize: 0x72,
          maxresponsesize: 0x73,
          maxresponsesizeCached: 0x74,
          maxoperations: 0x75,
          maxrequests: 0x76,
          rdmaIrd: [],
        },
        backChanAttrs: {
          headerpadsize: 0x81,
          maxrequestsize: 0x82,
          maxresponsesize: 0x83,
          maxresponsesizeCached: 0x84,
          maxoperations: 0x85,
          maxrequests: 0x86,
          rdmaIrd: [0x87],
        },
      },
      [
        "00000000", // NFS4_OK
        "51525354",
        "55565758",
        "595a5b5c",
        "5d5e5f60", // csr_sessionid[16]
        "00000031", // csr_sequence
        "00000001", // csr_flags = CREATE_SESSION4_FLAG_PERSIST
        "00000071", // fore attributes
        "00000072",
        "00000073",
        "00000074",
        "00000075",
        "00000076",
        "00000000", // fore ca_rdma_ird count = 0
        "00000081", // back attributes
        "00000082",
        "00000083",
        "00000084",
        "00000085",
        "00000086",
        "00000001", // back ca_rdma_ird count = 1
        "00000087",
      ],
      // Zero is NFS4_OK and the fore channel's empty array; one is the flag
      // and the back channel's array count.
      ["00000000", "00000001"],
    );
  });

  it("encodes DESTROY_SESSION4args as a bare sessionid4", () => {
    golden(writeDestroySessionArgs, readDestroySessionArgs, { sessionid: SESSIONID }, [
      "51525354",
      "55565758",
      "595a5b5c",
      "5d5e5f60",
    ]);
  });

  it("encodes DESTROY_SESSION4res as a bare status", () => {
    golden(writeStatusRes, readStatusRes, { status: NFS4ERR_BADSESSION }, [
      "00002744", // NFS4ERR_BADSESSION = 10052
    ]);
  });
});

describe("FREE_STATEID (18.38) / TEST_STATEID (18.48) / DESTROY_CLIENTID (18.50) / RECLAIM_COMPLETE (18.51)", () => {
  it("encodes FREE_STATEID4args and its status-only result", () => {
    golden(writeFreeStateidArgs, readFreeStateidArgs, { stateid: STATEID }, [
      "0a0b0c0d",
      "61626364",
      "65666768",
      "696a6b6c",
    ]);
    golden(writeStatusRes, readStatusRes, { status: NFS4ERR_LOCKS_HELD }, [
      "00002735", // NFS4ERR_LOCKS_HELD = 10037
    ]);
  });

  it("encodes TEST_STATEID4args as a counted array of stateid4", () => {
    golden(
      writeTestStateidArgs,
      readTestStateidArgs,
      { stateids: [STATEID, { seqid: 0x0e_0f_10_11, other: OTHER_B }] },
      [
        "00000002", // ts_stateids<> count = 2
        "0a0b0c0d", // the first stateid
        "61626364",
        "65666768",
        "696a6b6c",
        "0e0f1011", // the second
        "91929394",
        "95969798",
        "999a9b9c",
      ],
    );
  });

  it("encodes TEST_STATEID4resok as a counted array of nfsstat4", () => {
    // The operation succeeds even when every stateid in it is invalid: each
    // verdict is an element, not the operation's own status.
    golden(
      writeTestStateidRes,
      readTestStateidRes,
      { status: NFS4_OK, statusCodes: [NFS4_OK, NFS4ERR_BAD_STATEID] },
      [
        "00000000", // TEST_STATEID4res.tsr_status = NFS4_OK
        "00000002", // tsr_status_codes<> count = 2
        "00000000", // the first stateid is valid
        "00002729", // NFS4ERR_BAD_STATEID = 10025
      ],
      // NFS4_OK is zero and is here as both the operation's status and a verdict.
      ["00000000"],
    );
  });

  it("encodes DESTROY_CLIENTID4args as a bare clientid4", () => {
    golden(
      writeDestroyClientidArgs,
      readDestroyClientidArgs,
      { clientid: 0x01_02_03_04_05_06_07_08n },
      ["01020304", "05060708"],
    );
    golden(writeStatusRes, readStatusRes, { status: NFS4ERR_CLIENTID_BUSY }, [
      "0000275a", // NFS4ERR_CLIENTID_BUSY = 10074
    ]);
  });

  it("encodes RECLAIM_COMPLETE4args as one bool, both ways round", () => {
    golden(writeReclaimCompleteArgs, readReclaimCompleteArgs, { oneFs: true }, [
      "00000001", // rca_one_fs = TRUE — the per-filesystem form, after a migration
    ]);
    golden(writeReclaimCompleteArgs, readReclaimCompleteArgs, { oneFs: false }, [
      "00000000", // rca_one_fs = FALSE — the global form every client must send
    ]);
    golden(writeStatusRes, readStatusRes, { status: NFS4ERR_COMPLETE_ALREADY }, [
      "00002746", // NFS4ERR_COMPLETE_ALREADY = 10054
    ]);
  });
});

describe("SEQUENCE (section 18.46)", () => {
  it("encodes SEQUENCE4args as the session, the sequence, two slots and a bool", () => {
    golden(
      writeSequenceArgs,
      readSequenceArgs,
      {
        sessionid: SESSIONID,
        sequenceid: 0x101,
        slotid: 5,
        highestSlotid: 0x0f,
        cachethis: true,
      },
      [
        "51525354",
        "55565758",
        "595a5b5c",
        "5d5e5f60", // sa_sessionid[16]
        "00000101", // sa_sequenceid
        "00000005", // sa_slotid
        "0000000f", // sa_highest_slotid
        "00000001", // sa_cachethis = TRUE
      ],
    );
  });

  it("encodes SEQUENCE4resok's three slot ids in RFC order", () => {
    // `sr_slotid`, `sr_highest_slotid` and `sr_target_highest_slotid` are the
    // same type in a row and mean different things — the last is the size the
    // server would like the client to move toward.
    golden(
      writeSequenceRes,
      readSequenceRes,
      {
        status: NFS4_OK,
        sessionid: SESSIONID,
        sequenceid: 0x101,
        slotid: 5,
        highestSlotid: 0x0f,
        targetHighestSlotid: 0x1f,
        statusFlags: SEQ4_STATUS_RESTART_RECLAIM_NEEDED,
      },
      [
        "00000000", // NFS4_OK
        "51525354",
        "55565758",
        "595a5b5c",
        "5d5e5f60", // sr_sessionid[16]
        "00000101", // sr_sequenceid
        "00000005", // sr_slotid
        "0000000f", // sr_highest_slotid
        "0000001f", // sr_target_highest_slotid
        "00000100", // sr_status_flags = SEQ4_STATUS_RESTART_RECLAIM_NEEDED
      ],
    );
  });
});

describe("ILLEGAL (section 18.52)", () => {
  it("encodes ILLEGAL4res as NFS4ERR_OP_ILLEGAL", () => {
    golden(writeStatusRes, readStatusRes, { status: NFS4ERR_OP_ILLEGAL }, [
      "0000273c", // NFS4ERR_OP_ILLEGAL = 10044, which is also OP_ILLEGAL
    ]);
  });
});

describe("COMPOUND (section 16.2)", () => {
  it("encodes COMPOUND4args as tag, minorversion and an argop array", () => {
    golden(
      writeCompoundArgs,
      readCompoundArgs,
      {
        tag: "mx",
        minorversion: 1,
        argarray: [
          { op: OP_PUTROOTFH, args: undefined },
          { op: OP_LOOKUP, args: { objname: "docs" } },
          { op: OP_GETFH, args: undefined },
        ],
      },
      [
        "00000002", // tag length = 2
        "6d780000", // "mx" plus padding
        "00000001", // minorversion = 1 (NFSv4.1)
        "00000003", // argarray<> count = 3
        "00000018", // argop = OP_PUTROOTFH (24), void arguments
        "0000000f", // argop = OP_LOOKUP (15)
        "00000004", // objname length = 4
        "646f6373", // "docs"
        "0000000a", // argop = OP_GETFH (10), void arguments
      ],
    );
  });

  it("encodes a state COMPOUND: SEQUENCE, PUTFH, READ", () => {
    // What every 4.1 read looks like on the wire. SEQUENCE must come first
    // (section 18.46.3), PUTFH sets the cursor, and READ names the stateid the
    // OPEN handed back.
    golden(
      writeCompoundArgs,
      readCompoundArgs,
      {
        tag: "io",
        minorversion: 1,
        argarray: [
          {
            op: OP_SEQUENCE,
            args: {
              sessionid: SESSIONID,
              sequenceid: 0x101,
              slotid: 5,
              highestSlotid: 0x0f,
              cachethis: false,
            },
          },
          { op: OP_PUTFH, args: { object: FH } },
          {
            op: OP_READ,
            args: { stateid: STATEID, offset: 0x00_00_01_00_00_00_02_00n, count: 0x1000 },
          },
        ],
      },
      [
        "00000002", // tag length = 2
        "696f0000", // "io", padded
        "00000001", // minorversion = 1
        "00000003", // argarray<> count = 3
        "00000035", // argop = OP_SEQUENCE (53)
        "51525354",
        "55565758",
        "595a5b5c",
        "5d5e5f60", // sa_sessionid[16]
        "00000101", // sa_sequenceid
        "00000005", // sa_slotid
        "0000000f", // sa_highest_slotid
        "00000000", // sa_cachethis = FALSE
        "00000016", // argop = OP_PUTFH (22)
        "00000008", // nfs_fh4 length = 8
        "11223344",
        "55667788", // the handle
        "00000019", // argop = OP_READ (25)
        "0a0b0c0d",
        "61626364",
        "65666768",
        "696a6b6c", // READ4args.stateid
        "00000100",
        "00000200", // offset4
        "00001000", // count4
      ],
    );
  });

  it("encodes the matching state COMPOUND4res", () => {
    golden(
      writeCompoundRes,
      readCompoundRes,
      {
        status: NFS4_OK,
        tag: "io",
        resarray: [
          {
            op: OP_SEQUENCE,
            res: {
              status: NFS4_OK,
              sessionid: SESSIONID,
              sequenceid: 0x101,
              slotid: 5,
              highestSlotid: 0x0f,
              targetHighestSlotid: 0x1f,
              statusFlags: SEQ4_STATUS_CB_PATH_DOWN_SESSION,
            },
          },
          { op: OP_PUTFH, res: { status: NFS4_OK } },
          {
            op: OP_READ,
            res: {
              status: NFS4_OK,
              eof: true,
              data: new Uint8Array([0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6]),
            },
          },
        ],
      },
      [
        "00000000", // COMPOUND4res.status — the last operation's
        "00000002", // tag length = 2
        "696f0000", // "io"
        "00000003", // resarray<> count = 3
        "00000035", // resop = OP_SEQUENCE (53)
        "00000000", // SEQUENCE4res.sr_status
        "51525354",
        "55565758",
        "595a5b5c",
        "5d5e5f60", // sr_sessionid[16]
        "00000101", // sr_sequenceid
        "00000005", // sr_slotid
        "0000000f", // sr_highest_slotid
        "0000001f", // sr_target_highest_slotid
        "00000200", // sr_status_flags = SEQ4_STATUS_CB_PATH_DOWN_SESSION
        "00000016", // resop = OP_PUTFH (22)
        "00000000", // PUTFH4res.status
        "00000019", // resop = OP_READ (25)
        "00000000", // READ4res.status
        "00000001", // eof = TRUE
        "00000006", // data<> length = 6
        "c1c2c3c4",
        "c5c60000", // six bytes and two of padding
      ],
      // NFS4_OK is zero, once per successful operation plus once for the
      // compound itself.
      ["00000000"],
    );
  });

  it("encodes COMPOUND4res as status, tag and a resop array", () => {
    golden(
      writeCompoundRes,
      readCompoundRes,
      {
        status: NFS4_OK,
        tag: "tag!",
        resarray: [
          { op: OP_PUTROOTFH, res: { status: NFS4_OK } },
          { op: OP_LOOKUP, res: { status: NFS4_OK } },
          {
            op: OP_GETFH,
            res: {
              status: NFS4_OK,
              object: new Uint8Array([0x5a, 0x5b, 0x5c, 0x5d, 0x6a, 0x6b, 0x6c, 0x6d]),
            },
          },
        ],
      },
      [
        "00000000", // COMPOUND4res.status — the last operation's, by definition
        "00000004", // tag length = 4
        "74616721", // "tag!"
        "00000003", // resarray<> count = 3
        "00000018", // resop = OP_PUTROOTFH
        "00000000", // PUTROOTFH4res.status
        "0000000f", // resop = OP_LOOKUP
        "00000000", // LOOKUP4res.status
        "0000000a", // resop = OP_GETFH
        "00000000", // GETFH4res.status
        "00000008", // nfs_fh4 length = 8
        "5a5b5c5d",
        "6a6b6c6d", // the handle
      ],
      // NFS4_OK is zero and appears once per successful operation plus once for
      // the compound itself; nothing else repeats.
      ["00000000"],
    );
  });
});
