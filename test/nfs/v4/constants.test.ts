/**
 * Tier 0 for `src/nfs/v4/constants.ts`: the transcription itself.
 *
 * A constants file has one failure mode — a value that does not match the RFC —
 * and it is invisible until a real client refuses the reply. So the checks here
 * are of two kinds: spot-checks against RFC 8881 (and its XDR companion RFC
 * 5662) at *distinct, non-symmetric* points — first, last, and interior values
 * that share no digits — and whole-table shape assertions, which catch a
 * transposition or an omission that no individual spot-check would.
 */

import { describe, expect, it } from "vitest";
import { ERRNO_CODES } from "../../../src/errors.ts";
import * as v4 from "../../../src/nfs/v4/constants.ts";
import {
  ACCESS4_ALL,
  ACCESS4_DELETE,
  ACCESS4_EXECUTE,
  ACCESS4_READ,
  CLAIM_DELEG_PREV_FH,
  CLAIM_FH,
  CLAIM_NULL,
  CLAIM_PREVIOUS,
  CREATE_SESSION4_FLAG_CONN_BACK_CHAN,
  CREATE_SESSION4_FLAG_CONN_RDMA,
  CREATE_SESSION4_FLAG_PERSIST,
  errnoCodeOfStatus4,
  errnoOfStatus4,
  EXCHGID4_FLAG_CONFIRMED_R,
  EXCHGID4_FLAG_MASK_PNFS,
  EXCHGID4_FLAG_SUPP_MOVED_REFER,
  EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
  EXCHGID4_FLAG_USE_PNFS_MDS,
  EXCLUSIVE4_1,
  FATTR4_FILEHANDLE,
  FATTR4_FS_CHARSET_CAP,
  FATTR4_MAX,
  FATTR4_MODE,
  FATTR4_MOUNTED_ON_FILEID,
  FATTR4_RDATTR_ERROR,
  FATTR4_SIZE,
  FATTR4_SUPPATTR_EXCLCREAT,
  FATTR4_SUPPORTED_ATTRS,
  FATTR4_TIME_MODIFY,
  FATTR4_TYPE,
  FH4_PERSISTENT,
  FH4_VOL_RENAME,
  FH4_VOLATILE_ANY,
  GUARDED4,
  NF4ATTRDIR,
  NF4DIR,
  NF4LNK,
  NF4REG,
  NFS4_FHSIZE,
  NFS4_MAXFILELEN,
  NFS4_MAXFILEOFF,
  NFS4_MINOR_VERSION_1,
  NFS4_OK,
  NFS4_OPAQUE_LIMIT,
  NFS4_OTHER_SIZE,
  NFS4_PROGRAM,
  NFS4_SESSIONID_SIZE,
  NFS4_VERIFIER_SIZE,
  NFS4ERR_ACCESS,
  NFS4ERR_ATTRNOTSUPP,
  NFS4ERR_BADHANDLE,
  NFS4ERR_BADSLOT,
  NFS4ERR_DELAY,
  NFS4ERR_DELEG_REVOKED,
  NFS4ERR_DENIED,
  NFS4ERR_FHEXPIRED,
  NFS4ERR_FILE_OPEN,
  NFS4ERR_GRACE,
  NFS4ERR_INVAL,
  NFS4ERR_IO,
  NFS4ERR_NOENT,
  NFS4ERR_NOTSUPP,
  NFS4ERR_OP_ILLEGAL,
  NFS4ERR_PERM,
  NFS4ERR_SEQ_MISORDERED,
  NFS4ERR_STALE,
  NFS4ERR_SYMLINK,
  NFS4ERR_WRONGSEC,
  NFS_V4,
  nfs4StatusOf,
  OP_ACCESS,
  OP_CREATE_SESSION,
  OP_EXCHANGE_ID,
  OP_FIRST,
  OP_GETFH,
  OP_ILLEGAL,
  OP_LAST,
  OP_OPEN,
  OP_PUTROOTFH,
  OP_RECLAIM_COMPLETE,
  OP_RELEASE_LOCKOWNER,
  OP_SEQUENCE,
  OP_WRITE,
  OPEN4_CREATE,
  OPEN4_RESULT_CONFIRM,
  OPEN4_RESULT_MAY_NOTIFY_LOCK,
  OPEN4_SHARE_ACCESS_BOTH,
  OPEN4_SHARE_ACCESS_WANT_CANCEL,
  OPEN4_SHARE_ACCESS_WANT_DELEG_MASK,
  OPEN4_SHARE_ACCESS_WRITE,
  OPEN4_SHARE_DENY_BOTH,
  OPEN_DELEGATE_NONE_EXT,
  opName4,
  SEQ4_STATUS_CB_PATH_DOWN,
  SEQ4_STATUS_DEVID_DELETED,
  SEQ4_STATUS_RESTART_RECLAIM_NEEDED,
  SP4_NONE,
  SP4_SSV,
  status4Name,
  UNCHECKED4,
} from "../../../src/nfs/v4/constants.ts";

/** Every `export const` in the module whose name matches `prefix`. */
function constantsWith(prefix: string, exclude: readonly string[] = []): [string, number][] {
  return Object.entries(v4)
    .filter(
      ([name, value]) =>
        name.startsWith(prefix) && typeof value === "number" && !exclude.includes(name),
    )
    .map(([name, value]) => [name, value as number]);
}

describe("program and sizes (RFC 8881 section 3.1, RFC 5662 section 2)", () => {
  it("names the program, version and minor version", () => {
    expect(NFS4_PROGRAM).toBe(100_003);
    expect(NFS_V4).toBe(4);
    expect(NFS4_MINOR_VERSION_1).toBe(1);
  });

  it("transcribes the basic constants", () => {
    // All distinct on purpose: 128, 8, 1024, 16, 12 share no value, so a
    // transposed pair here cannot pass.
    expect(NFS4_FHSIZE).toBe(128);
    expect(NFS4_VERIFIER_SIZE).toBe(8);
    expect(NFS4_OPAQUE_LIMIT).toBe(1024);
    expect(NFS4_SESSIONID_SIZE).toBe(16);
    expect(NFS4_OTHER_SIZE).toBe(12);
    expect(NFS4_MAXFILELEN).toBe(2n ** 64n - 1n);
    expect(NFS4_MAXFILEOFF).toBe(NFS4_MAXFILELEN - 1n);
  });
});

describe("nfsstat4 (RFC 8881 section 15.1)", () => {
  it("spot-checks the POSIX-numbered statuses", () => {
    expect(NFS4_OK).toBe(0);
    expect(NFS4ERR_PERM).toBe(1);
    expect(NFS4ERR_NOENT).toBe(2);
    expect(NFS4ERR_ACCESS).toBe(13);
    expect(NFS4ERR_INVAL).toBe(22);
    expect(NFS4ERR_STALE).toBe(70);
  });

  it("spot-checks the NFSv4-only statuses at both ends and inside", () => {
    expect(NFS4ERR_BADHANDLE).toBe(10_001);
    expect(NFS4ERR_NOTSUPP).toBe(10_004);
    expect(NFS4ERR_DELAY).toBe(10_008);
    expect(NFS4ERR_SYMLINK).toBe(10_029);
    expect(NFS4ERR_OP_ILLEGAL).toBe(10_044);
    expect(NFS4ERR_BADSLOT).toBe(10_053);
    expect(NFS4ERR_SEQ_MISORDERED).toBe(10_063);
    expect(NFS4ERR_DELEG_REVOKED).toBe(10_087);
  });

  it("leaves 19 and 10002 and 10073 unallocated", () => {
    // 19 was NFS3ERR_NODEV and 10002 was NFS3ERR_NOT_SYNC; RFC 5662 asks that
    // no NFSv4 status reuse an NFSv3 number. 10073 is simply unused.
    const taken = new Set(constantsWith("NFS4ERR_").map(([, value]) => value));
    expect(taken.has(19)).toBe(false);
    expect(taken.has(10_002)).toBe(false);
    expect(taken.has(10_073)).toBe(false);
  });

  it("allocates every status number exactly once", () => {
    const statuses = constantsWith("NFS4ERR_");
    expect(new Set(statuses.map(([, value]) => value)).size).toBe(statuses.length);
    // 18 POSIX-numbered, then 10001 and the contiguous runs 10003..10072 and
    // 10074..10087.
    expect(statuses.length).toBe(18 + 1 + 70 + 14);
  });

  it("names every status as itself", () => {
    for (const [name, value] of [...constantsWith("NFS4ERR_"), ["NFS4_OK", NFS4_OK] as const]) {
      expect(status4Name(value), name).toBe(name);
    }
    expect(status4Name(12_345)).toBe("nfsstat4 12345");
  });
});

describe("nfs_opnum4 (RFC 8881 section 16.2.1)", () => {
  it("spot-checks the opcodes at both ends and inside", () => {
    expect(OP_ACCESS).toBe(3);
    expect(OP_GETFH).toBe(10);
    expect(OP_OPEN).toBe(18);
    expect(OP_PUTROOTFH).toBe(24);
    expect(OP_WRITE).toBe(38);
    expect(OP_RELEASE_LOCKOWNER).toBe(39);
    expect(OP_EXCHANGE_ID).toBe(42);
    expect(OP_CREATE_SESSION).toBe(43);
    expect(OP_SEQUENCE).toBe(53);
    expect(OP_RECLAIM_COMPLETE).toBe(58);
    expect(OP_ILLEGAL).toBe(10_044);
  });

  it("covers 3 through 58 with no gap and no repeat", () => {
    const ops = constantsWith("OP_", ["OP_FIRST", "OP_LAST", "OP_ILLEGAL"]);
    const numbers = ops.map(([, value]) => value).sort((a, b) => a - b);
    expect(numbers).toEqual(Array.from({ length: 56 }, (_, index) => index + 3));
    expect(OP_FIRST).toBe(3);
    expect(OP_LAST).toBe(58);
    // NFSv4.2's OP_ALLOCATE is 59; RFC 8881 does not define it and neither do we.
    expect(numbers.at(-1)).toBe(58);
  });

  it("names every opcode, and says so when it cannot", () => {
    expect(opName4(15)).toBe("OP_LOOKUP");
    expect(opName4(OP_ILLEGAL)).toBe("OP_ILLEGAL");
    for (const [name, value] of constantsWith("OP_", ["OP_FIRST", "OP_LAST"])) {
      expect(opName4(value), name).toBe(name);
    }
    expect(opName4(59)).toBe("nfs_opnum4 59");
    expect(opName4(0)).toBe("nfs_opnum4 0");
  });
});

describe("nfs_ftype4 (RFC 8881 section 5.8.1.2)", () => {
  it("transcribes the file types", () => {
    expect(NF4REG).toBe(1);
    expect(NF4DIR).toBe(2);
    expect(NF4LNK).toBe(5);
    expect(NF4ATTRDIR).toBe(8);
    const types = constantsWith("NF4");
    expect(types.map(([, value]) => value).sort((a, b) => a - b)).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8, 9,
    ]);
  });
});

describe("FATTR4 bit numbers (RFC 8881 sections 5.6 and 5.7)", () => {
  it("spot-checks bits from both tables, including the out-of-order ones", () => {
    expect(FATTR4_SUPPORTED_ATTRS).toBe(0);
    expect(FATTR4_TYPE).toBe(1);
    expect(FATTR4_SIZE).toBe(4);
    expect(FATTR4_RDATTR_ERROR).toBe(11);
    // REQUIRED, but numbered in the middle of the RECOMMENDED run.
    expect(FATTR4_FILEHANDLE).toBe(19);
    expect(FATTR4_MODE).toBe(33);
    expect(FATTR4_TIME_MODIFY).toBe(53);
    expect(FATTR4_MOUNTED_ON_FILEID).toBe(55);
    // The other out-of-order REQUIRED one, and the highest bit 4.1 defines.
    expect(FATTR4_SUPPATTR_EXCLCREAT).toBe(75);
    expect(FATTR4_FS_CHARSET_CAP).toBe(76);
    expect(FATTR4_MAX).toBe(76);
  });

  it("covers 0 through 76 with no gap and no repeat", () => {
    const attrs = constantsWith("FATTR4_", ["FATTR4_MAX"]);
    const numbers = attrs.map(([, value]) => value).sort((a, b) => a - b);
    expect(numbers).toEqual(Array.from({ length: 77 }, (_, index) => index));
  });
});

describe("flag words", () => {
  it("transcribes fh_expire_type (RFC 8881 section 4.2.3)", () => {
    // `FH4_PERSISTENT` is the absence of every other bit, not a bit of its own.
    expect(FH4_PERSISTENT).toBe(0);
    expect(FH4_VOLATILE_ANY).toBe(0x00_00_00_02);
    expect(FH4_VOL_RENAME).toBe(0x00_00_00_08);
  });

  it("transcribes ACCESS4 (RFC 8881 section 18.1.1)", () => {
    expect(ACCESS4_READ).toBe(0x00_00_00_01);
    expect(ACCESS4_DELETE).toBe(0x00_00_00_10);
    expect(ACCESS4_EXECUTE).toBe(0x00_00_00_20);
    expect(ACCESS4_ALL).toBe(0x00_00_00_3f);
  });

  it("transcribes the OPEN share and result flags (RFC 8881 section 18.16)", () => {
    expect(UNCHECKED4).toBe(0);
    expect(GUARDED4).toBe(1);
    expect(EXCLUSIVE4_1).toBe(3);
    expect(OPEN4_CREATE).toBe(1);
    expect(OPEN4_SHARE_ACCESS_WRITE).toBe(0x00_00_00_02);
    expect(OPEN4_SHARE_ACCESS_BOTH).toBe(0x00_00_00_03);
    expect(OPEN4_SHARE_DENY_BOTH).toBe(0x00_00_00_03);
    // The delegation "wants" live above the access bits in the same word.
    expect(OPEN4_SHARE_ACCESS_WANT_DELEG_MASK).toBe(0xff_00);
    expect(OPEN4_SHARE_ACCESS_WANT_CANCEL).toBe(0x05_00);
    expect(OPEN4_SHARE_ACCESS_WANT_CANCEL & OPEN4_SHARE_ACCESS_WANT_DELEG_MASK).toBe(
      OPEN4_SHARE_ACCESS_WANT_CANCEL,
    );
    // Result flags: note 0x10 is *not* allocated, so these are not contiguous.
    expect(OPEN4_RESULT_CONFIRM).toBe(0x00_00_00_02);
    expect(OPEN4_RESULT_MAY_NOTIFY_LOCK).toBe(0x00_00_00_20);
  });

  it("transcribes the OPEN claim and delegation types", () => {
    expect(CLAIM_NULL).toBe(0);
    expect(CLAIM_PREVIOUS).toBe(1);
    expect(CLAIM_FH).toBe(4);
    expect(CLAIM_DELEG_PREV_FH).toBe(6);
    expect(OPEN_DELEGATE_NONE_EXT).toBe(3);
  });

  it("transcribes EXCHANGE_ID (RFC 8881 section 18.35.1)", () => {
    expect(EXCHGID4_FLAG_SUPP_MOVED_REFER).toBe(0x00_00_00_01);
    expect(EXCHGID4_FLAG_USE_PNFS_MDS).toBe(0x00_02_00_00);
    // The mask covers exactly the three pNFS role bits.
    expect(EXCHGID4_FLAG_MASK_PNFS).toBe(0x00_07_00_00);
    expect(EXCHGID4_FLAG_USE_PNFS_MDS & EXCHGID4_FLAG_MASK_PNFS).toBe(EXCHGID4_FLAG_USE_PNFS_MDS);
    // The two high bits, one each way: `_A` is the client's, `_R` the server's.
    expect(EXCHGID4_FLAG_UPD_CONFIRMED_REC_A).toBe(0x40_00_00_00);
    expect(EXCHGID4_FLAG_CONFIRMED_R).toBe(0x80_00_00_00);
    expect(SP4_NONE).toBe(0);
    expect(SP4_SSV).toBe(2);
  });

  it("transcribes CREATE_SESSION and SEQUENCE flags (sections 18.36 and 18.46)", () => {
    expect(CREATE_SESSION4_FLAG_PERSIST).toBe(0x00_00_00_01);
    expect(CREATE_SESSION4_FLAG_CONN_BACK_CHAN).toBe(0x00_00_00_02);
    expect(CREATE_SESSION4_FLAG_CONN_RDMA).toBe(0x00_00_00_04);
    expect(SEQ4_STATUS_CB_PATH_DOWN).toBe(0x00_00_00_01);
    expect(SEQ4_STATUS_RESTART_RECLAIM_NEEDED).toBe(0x00_00_01_00);
    expect(SEQ4_STATUS_DEVID_DELETED).toBe(0x00_00_10_00);
  });

  it("gives every SEQ4 status flag a distinct single bit", () => {
    const flags = constantsWith("SEQ4_STATUS_").map(([, value]) => value);
    expect(new Set(flags).size).toBe(flags.length);
    for (const flag of flags) {
      expect(flag & (flag - 1)).toBe(0);
    }
    // 13 contiguous bits, 0x1 through 0x1000.
    expect(flags.reduce((all, flag) => all | flag, 0)).toBe(0x00_00_1f_ff);
  });
});

describe("errno mapping", () => {
  it("maps driver errors onto the statuses RFC 8881 allows", () => {
    expect(nfs4StatusOf({ code: "ENOENT" })).toBe(NFS4ERR_NOENT);
    expect(nfs4StatusOf({ code: "ESTALE" })).toBe(NFS4ERR_STALE);
    expect(nfs4StatusOf({ code: "ENOSYS" })).toBe(NFS4ERR_NOTSUPP);
    expect(nfs4StatusOf({ code: "ENOTSUP" })).toBe(NFS4ERR_NOTSUPP);
    // Unlike NFSv3, v4 has a status for a symlink in the way of a lookup.
    expect(nfs4StatusOf({ code: "ELOOP" })).toBe(NFS4ERR_SYMLINK);
    // `EAGAIN` is v4's DELAY, the successor to NFSv3's JUKEBOX.
    expect(nfs4StatusOf({ code: "EAGAIN" })).toBe(NFS4ERR_DELAY);
    // Status 19 does not exist in v4, so `ENODEV` has to fall back.
    expect(nfs4StatusOf({ code: "ENODEV" })).toBe(NFS4ERR_IO);
    // Anything unmapped is IO, the only answer a client can always interpret.
    expect(nfs4StatusOf(new Error("nope"))).toBe(NFS4ERR_IO);
    expect(nfs4StatusOf(undefined)).toBe(NFS4ERR_IO);
    expect(nfs4StatusOf({ code: "EWHATEVER" })).toBe(NFS4ERR_IO);
  });

  it("does not mistake an Object.prototype key for a mapped errno", () => {
    // `code in ERRNO_TO_NFS4` would find `Object.prototype.toString` and return
    // a *function*, which a writer coerces to 0 — an `NFS4_OK` status word in
    // front of a failure body, i.e. a decoder desync rather than a wrong answer.
    for (const code of ["toString", "constructor", "hasOwnProperty", "__proto__", "valueOf"]) {
      expect(nfs4StatusOf({ code }), code).toBe(NFS4ERR_IO);
    }
  });

  it("maps statuses back to POSIX codes", () => {
    expect(errnoCodeOfStatus4(NFS4ERR_NOENT)).toBe("ENOENT");
    expect(errnoCodeOfStatus4(NFS4ERR_STALE)).toBe("ESTALE");
    // Three ways of saying "that handle names nothing any more".
    expect(errnoCodeOfStatus4(NFS4ERR_BADHANDLE)).toBe("ESTALE");
    expect(errnoCodeOfStatus4(NFS4ERR_FHEXPIRED)).toBe("ESTALE");
    expect(errnoCodeOfStatus4(NFS4ERR_ATTRNOTSUPP)).toBe("ENOTSUP");
    expect(errnoCodeOfStatus4(NFS4ERR_WRONGSEC)).toBe("EACCES");
    expect(errnoCodeOfStatus4(NFS4ERR_FILE_OPEN)).toBe("EBUSY");
    // The "not now" family, all of which a POSIX caller sees as EAGAIN.
    expect(errnoCodeOfStatus4(NFS4ERR_DELAY)).toBe("EAGAIN");
    expect(errnoCodeOfStatus4(NFS4ERR_GRACE)).toBe("EAGAIN");
    expect(errnoCodeOfStatus4(NFS4ERR_DENIED)).toBe("EAGAIN");
    // The protocol-only statuses have no POSIX counterpart at all.
    expect(errnoCodeOfStatus4(NFS4ERR_BADSLOT)).toBe("EIO");
    expect(errnoCodeOfStatus4(99_999)).toBe("EIO");
    expect(errnoOfStatus4(NFS4ERR_NOENT)).toBe(ERRNO_CODES.ENOENT);
    expect(errnoOfStatus4(NFS4ERR_SYMLINK)).toBe(ERRNO_CODES.ELOOP);
    expect(errnoOfStatus4(NFS4ERR_BADSLOT)).toBe(ERRNO_CODES.EIO);
  });

  it("round-trips every status the forward map can produce", () => {
    for (const status of [
      NFS4ERR_PERM,
      NFS4ERR_NOENT,
      NFS4ERR_IO,
      6,
      NFS4ERR_ACCESS,
      17,
      18,
      20,
      21,
      NFS4ERR_INVAL,
      27,
      28,
      30,
      31,
      63,
      66,
      69,
      NFS4ERR_STALE,
      NFS4ERR_NOTSUPP,
      NFS4ERR_DELAY,
      NFS4ERR_SYMLINK,
    ]) {
      expect(nfs4StatusOf({ code: errnoCodeOfStatus4(status) }), status4Name(status)).toBe(status);
    }
  });
});
