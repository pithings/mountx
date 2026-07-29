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
  NFS4ERR_NOTEMPTY,
  NFS4ERR_OP_ILLEGAL,
  NFS4ERR_SAME,
  NFS4ERR_STALE,
  NFS4ERR_WRONGSEC,
  NFS4ERR_XDEV,
  OP_GETFH,
  OP_LOOKUP,
  OP_PUTROOTFH,
  SECINFO_STYLE4_PARENT,
  SET_TO_CLIENT_TIME4,
} from "../../../src/nfs/v4/constants.ts";
import { bitmapOf } from "../../../src/nfs/v4/attr.ts";
import {
  readAccessArgs,
  readAccessRes,
  readCommitArgs,
  readCommitRes,
  readCompoundArgs,
  readCompoundRes,
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
  writeArgop4,
  writeCommitArgs,
  writeCommitRes,
  writeCompoundArgs,
  writeCompoundRes,
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
