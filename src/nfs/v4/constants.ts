/**
 * NFSv4.1 wire constants.
 *
 * Transcribed from **RFC 8881** — Network File System (NFS) Version 4 Minor
 * Version 1 Protocol — and, where RFC 8881's prose names a value without
 * writing the XDR down, from its own normative XDR companion **RFC 5662**
 * (NFSv4.1 XDR Description, reference [10] of RFC 8881). Both are frozen.
 *
 * Nothing here is guessed: each group repeats the declaration it comes from and
 * names the section it was copied out of, the same way `../v3/constants.ts`
 * cites RFC 1813. The ONC RPC v2 constants that frame every call live in
 * `../rpc.ts`, because they belong to no NFS version; this file is version 4
 * and nothing else, and imports nothing from `../v3/`.
 *
 * **Scope.** This server is 4.1-only: `SP4_NONE`, no delegations, no pNFS, no
 * RPCSEC_GSS. The enumerations below are still transcribed *whole* wherever
 * they are one coherent table — every `nfsstat4`, every `nfs_opnum4`, every
 * `FATTR4_*` bit number — because a codec has to *name* what arrives even when
 * the answer is `NFS4ERR_NOTSUPP`. Values that exist only in NFSv4.2 are not
 * here; RFC 8881 does not define them.
 *
 * Everything on the wire is **big-endian** (XDR).
 */

import { ERRNO_CODES, type ErrnoCode } from "../../errors.ts";

// ---------------------------------------------------------------------------
// program and version (RFC 5662 §2, `program NFS4_PROGRAM`)
// ---------------------------------------------------------------------------

/** NFS program number. The same 100003 every NFS version has ever used. */
export const NFS4_PROGRAM = 100_003;
/** `version NFS_V4`. The minor version travels inside COMPOUND, not here. */
export const NFS_V4 = 4;
/** `COMPOUND4args.minorversion` — the only one this server answers. */
export const NFS4_MINOR_VERSION_1 = 1;

/** NFSv4 procedure numbers (RFC 8881 §16). */
export const NFSPROC4_NULL = 0;
export const NFSPROC4_COMPOUND = 1;

// ---------------------------------------------------------------------------
// basic constants (RFC 8881 §3.1)
// ---------------------------------------------------------------------------

/** Longest file handle. Four times NFSv3's; ours is much shorter than either. */
export const NFS4_FHSIZE = 128;
/** Fixed size of a `verifier4`. */
export const NFS4_VERIFIER_SIZE = 8;
/** Longest "certain opaque information" — client/server owners and scopes. */
export const NFS4_OPAQUE_LIMIT = 1024;
/** Fixed size of a `sessionid4`. */
export const NFS4_SESSIONID_SIZE = 16;
/** Fixed size of `stateid4.other` (RFC 8881 §3.3.12). */
export const NFS4_OTHER_SIZE = 12;
/** Fixed size of a `deviceid4` (RFC 8881 §3.3.14). pNFS only; here to name it. */
export const NFS4_DEVICEID4_SIZE = 16;

/** `NFS4_MAXFILELEN` — the longest a regular file may be. */
export const NFS4_MAXFILELEN = 0xff_ff_ff_ff_ff_ff_ff_ffn;
/** `NFS4_MAXFILEOFF` — the highest offset into one, i.e. `MAXFILELEN - 1`. */
export const NFS4_MAXFILEOFF = 0xff_ff_ff_ff_ff_ff_ff_fen;

// ---------------------------------------------------------------------------
// nfsstat4 (RFC 8881 §15.1, table 11; XDR in RFC 5662 §2)
// ---------------------------------------------------------------------------

export const NFS4_OK = 0;
export const NFS4ERR_PERM = 1;
export const NFS4ERR_NOENT = 2;
export const NFS4ERR_IO = 5;
export const NFS4ERR_NXIO = 6;
export const NFS4ERR_ACCESS = 13;
export const NFS4ERR_EXIST = 17;
export const NFS4ERR_XDEV = 18;
// Value 19 is deliberately unallocated: it was NFS3ERR_NODEV, and RFC 5662
// asks that no NFSv4 status reuse an NFSv3 number with a different meaning.
export const NFS4ERR_NOTDIR = 20;
export const NFS4ERR_ISDIR = 21;
export const NFS4ERR_INVAL = 22;
export const NFS4ERR_FBIG = 27;
export const NFS4ERR_NOSPC = 28;
export const NFS4ERR_ROFS = 30;
export const NFS4ERR_MLINK = 31;
export const NFS4ERR_NAMETOOLONG = 63;
export const NFS4ERR_NOTEMPTY = 66;
export const NFS4ERR_DQUOT = 69;
export const NFS4ERR_STALE = 70;
export const NFS4ERR_BADHANDLE = 10_001;
export const NFS4ERR_BAD_COOKIE = 10_003;
export const NFS4ERR_NOTSUPP = 10_004;
export const NFS4ERR_TOOSMALL = 10_005;
export const NFS4ERR_SERVERFAULT = 10_006;
export const NFS4ERR_BADTYPE = 10_007;
export const NFS4ERR_DELAY = 10_008;
export const NFS4ERR_SAME = 10_009;
export const NFS4ERR_DENIED = 10_010;
export const NFS4ERR_EXPIRED = 10_011;
export const NFS4ERR_LOCKED = 10_012;
export const NFS4ERR_GRACE = 10_013;
export const NFS4ERR_FHEXPIRED = 10_014;
export const NFS4ERR_SHARE_DENIED = 10_015;
export const NFS4ERR_WRONGSEC = 10_016;
export const NFS4ERR_CLID_INUSE = 10_017;
/** Not a valid error in NFSv4.1 — transcribed so the decoder can name it. */
export const NFS4ERR_RESOURCE = 10_018;
export const NFS4ERR_MOVED = 10_019;
export const NFS4ERR_NOFILEHANDLE = 10_020;
export const NFS4ERR_MINOR_VERS_MISMATCH = 10_021;
export const NFS4ERR_STALE_CLIENTID = 10_022;
export const NFS4ERR_STALE_STATEID = 10_023;
export const NFS4ERR_OLD_STATEID = 10_024;
export const NFS4ERR_BAD_STATEID = 10_025;
export const NFS4ERR_BAD_SEQID = 10_026;
export const NFS4ERR_NOT_SAME = 10_027;
export const NFS4ERR_LOCK_RANGE = 10_028;
export const NFS4ERR_SYMLINK = 10_029;
export const NFS4ERR_RESTOREFH = 10_030;
export const NFS4ERR_LEASE_MOVED = 10_031;
export const NFS4ERR_ATTRNOTSUPP = 10_032;
export const NFS4ERR_NO_GRACE = 10_033;
export const NFS4ERR_RECLAIM_BAD = 10_034;
export const NFS4ERR_RECLAIM_CONFLICT = 10_035;
export const NFS4ERR_BADXDR = 10_036;
export const NFS4ERR_LOCKS_HELD = 10_037;
export const NFS4ERR_OPENMODE = 10_038;
export const NFS4ERR_BADOWNER = 10_039;
export const NFS4ERR_BADCHAR = 10_040;
export const NFS4ERR_BADNAME = 10_041;
export const NFS4ERR_BAD_RANGE = 10_042;
export const NFS4ERR_LOCK_NOTSUPP = 10_043;
export const NFS4ERR_OP_ILLEGAL = 10_044;
export const NFS4ERR_DEADLOCK = 10_045;
export const NFS4ERR_FILE_OPEN = 10_046;
export const NFS4ERR_ADMIN_REVOKED = 10_047;
export const NFS4ERR_CB_PATH_DOWN = 10_048;
// NFSv4.1 errors start here.
export const NFS4ERR_BADIOMODE = 10_049;
export const NFS4ERR_BADLAYOUT = 10_050;
export const NFS4ERR_BAD_SESSION_DIGEST = 10_051;
export const NFS4ERR_BADSESSION = 10_052;
export const NFS4ERR_BADSLOT = 10_053;
export const NFS4ERR_COMPLETE_ALREADY = 10_054;
export const NFS4ERR_CONN_NOT_BOUND_TO_SESSION = 10_055;
export const NFS4ERR_DELEG_ALREADY_WANTED = 10_056;
export const NFS4ERR_BACK_CHAN_BUSY = 10_057;
export const NFS4ERR_LAYOUTTRYLATER = 10_058;
export const NFS4ERR_LAYOUTUNAVAILABLE = 10_059;
export const NFS4ERR_NOMATCHING_LAYOUT = 10_060;
export const NFS4ERR_RECALLCONFLICT = 10_061;
export const NFS4ERR_UNKNOWN_LAYOUTTYPE = 10_062;
export const NFS4ERR_SEQ_MISORDERED = 10_063;
export const NFS4ERR_SEQUENCE_POS = 10_064;
export const NFS4ERR_REQ_TOO_BIG = 10_065;
export const NFS4ERR_REP_TOO_BIG = 10_066;
export const NFS4ERR_REP_TOO_BIG_TO_CACHE = 10_067;
export const NFS4ERR_RETRY_UNCACHED_REP = 10_068;
export const NFS4ERR_UNSAFE_COMPOUND = 10_069;
export const NFS4ERR_TOO_MANY_OPS = 10_070;
export const NFS4ERR_OP_NOT_IN_SESSION = 10_071;
export const NFS4ERR_HASH_ALG_UNSUPP = 10_072;
// Error 10073 is unused.
export const NFS4ERR_CLIENTID_BUSY = 10_074;
export const NFS4ERR_PNFS_IO_HOLE = 10_075;
export const NFS4ERR_SEQ_FALSE_RETRY = 10_076;
export const NFS4ERR_BAD_HIGH_SLOT = 10_077;
export const NFS4ERR_DEADSESSION = 10_078;
export const NFS4ERR_ENCR_ALG_UNSUPP = 10_079;
export const NFS4ERR_PNFS_NO_LAYOUT = 10_080;
export const NFS4ERR_NOT_ONLY_OP = 10_081;
export const NFS4ERR_WRONG_CRED = 10_082;
export const NFS4ERR_WRONG_TYPE = 10_083;
export const NFS4ERR_DIRDELEG_UNAVAIL = 10_084;
export const NFS4ERR_REJECT_DELEG = 10_085;
export const NFS4ERR_RETURNCONFLICT = 10_086;
export const NFS4ERR_DELEG_REVOKED = 10_087;

// ---------------------------------------------------------------------------
// nfs_opnum4 (RFC 8881 §16.2.1)
// ---------------------------------------------------------------------------
//
// Operations 0, 1 and 2 are not defined for COMPOUND (RFC 8881 §16.2, and RFC
// 7530 §16.2.3 for 4.0 — none of the three ever existed in either minor
// version); numbering starts at 3. Five of the pre-4.1 operations are
// "mandatory not-to-implement" in 4.1 — OPEN_CONFIRM, RENEW, SETCLIENTID,
// SETCLIENTID_CONFIRM and RELEASE_LOCKOWNER — and are transcribed anyway, since
// a client that sends one has to be told `NFS4ERR_NOTSUPP` rather than met with
// silence.

export const OP_ACCESS = 3;
export const OP_CLOSE = 4;
export const OP_COMMIT = 5;
export const OP_CREATE = 6;
export const OP_DELEGPURGE = 7;
export const OP_DELEGRETURN = 8;
export const OP_GETATTR = 9;
export const OP_GETFH = 10;
export const OP_LINK = 11;
export const OP_LOCK = 12;
export const OP_LOCKT = 13;
export const OP_LOCKU = 14;
export const OP_LOOKUP = 15;
export const OP_LOOKUPP = 16;
export const OP_NVERIFY = 17;
export const OP_OPEN = 18;
export const OP_OPENATTR = 19;
/** Mandatory not-to-implement in 4.1. */
export const OP_OPEN_CONFIRM = 20;
export const OP_OPEN_DOWNGRADE = 21;
export const OP_PUTFH = 22;
export const OP_PUTPUBFH = 23;
export const OP_PUTROOTFH = 24;
export const OP_READ = 25;
export const OP_READDIR = 26;
export const OP_READLINK = 27;
export const OP_REMOVE = 28;
export const OP_RENAME = 29;
/** Mandatory not-to-implement in 4.1. */
export const OP_RENEW = 30;
export const OP_RESTOREFH = 31;
export const OP_SAVEFH = 32;
export const OP_SECINFO = 33;
export const OP_SETATTR = 34;
/** Mandatory not-to-implement in 4.1. */
export const OP_SETCLIENTID = 35;
/** Mandatory not-to-implement in 4.1. */
export const OP_SETCLIENTID_CONFIRM = 36;
export const OP_VERIFY = 37;
export const OP_WRITE = 38;
/** Mandatory not-to-implement in 4.1. */
export const OP_RELEASE_LOCKOWNER = 39;
// New operations for NFSv4.1.
export const OP_BACKCHANNEL_CTL = 40;
export const OP_BIND_CONN_TO_SESSION = 41;
export const OP_EXCHANGE_ID = 42;
export const OP_CREATE_SESSION = 43;
export const OP_DESTROY_SESSION = 44;
export const OP_FREE_STATEID = 45;
export const OP_GET_DIR_DELEGATION = 46;
export const OP_GETDEVICEINFO = 47;
export const OP_GETDEVICELIST = 48;
export const OP_LAYOUTCOMMIT = 49;
export const OP_LAYOUTGET = 50;
export const OP_LAYOUTRETURN = 51;
export const OP_SECINFO_NO_NAME = 52;
export const OP_SEQUENCE = 53;
export const OP_SET_SSV = 54;
export const OP_TEST_STATEID = 55;
export const OP_WANT_DELEGATION = 56;
export const OP_DESTROY_CLIENTID = 57;
export const OP_RECLAIM_COMPLETE = 58;
/** Not an operation: what a server echoes for an opcode it cannot name. */
export const OP_ILLEGAL = 10_044;

/** The contiguous range of real operations, for a "is this an opcode" test. */
export const OP_FIRST = OP_ACCESS;
export const OP_LAST = OP_RECLAIM_COMPLETE;

const OP_NAMES: Record<number, string> = {
  [OP_ACCESS]: "ACCESS",
  [OP_CLOSE]: "CLOSE",
  [OP_COMMIT]: "COMMIT",
  [OP_CREATE]: "CREATE",
  [OP_DELEGPURGE]: "DELEGPURGE",
  [OP_DELEGRETURN]: "DELEGRETURN",
  [OP_GETATTR]: "GETATTR",
  [OP_GETFH]: "GETFH",
  [OP_LINK]: "LINK",
  [OP_LOCK]: "LOCK",
  [OP_LOCKT]: "LOCKT",
  [OP_LOCKU]: "LOCKU",
  [OP_LOOKUP]: "LOOKUP",
  [OP_LOOKUPP]: "LOOKUPP",
  [OP_NVERIFY]: "NVERIFY",
  [OP_OPEN]: "OPEN",
  [OP_OPENATTR]: "OPENATTR",
  [OP_OPEN_CONFIRM]: "OPEN_CONFIRM",
  [OP_OPEN_DOWNGRADE]: "OPEN_DOWNGRADE",
  [OP_PUTFH]: "PUTFH",
  [OP_PUTPUBFH]: "PUTPUBFH",
  [OP_PUTROOTFH]: "PUTROOTFH",
  [OP_READ]: "READ",
  [OP_READDIR]: "READDIR",
  [OP_READLINK]: "READLINK",
  [OP_REMOVE]: "REMOVE",
  [OP_RENAME]: "RENAME",
  [OP_RENEW]: "RENEW",
  [OP_RESTOREFH]: "RESTOREFH",
  [OP_SAVEFH]: "SAVEFH",
  [OP_SECINFO]: "SECINFO",
  [OP_SETATTR]: "SETATTR",
  [OP_SETCLIENTID]: "SETCLIENTID",
  [OP_SETCLIENTID_CONFIRM]: "SETCLIENTID_CONFIRM",
  [OP_VERIFY]: "VERIFY",
  [OP_WRITE]: "WRITE",
  [OP_RELEASE_LOCKOWNER]: "RELEASE_LOCKOWNER",
  [OP_BACKCHANNEL_CTL]: "BACKCHANNEL_CTL",
  [OP_BIND_CONN_TO_SESSION]: "BIND_CONN_TO_SESSION",
  [OP_EXCHANGE_ID]: "EXCHANGE_ID",
  [OP_CREATE_SESSION]: "CREATE_SESSION",
  [OP_DESTROY_SESSION]: "DESTROY_SESSION",
  [OP_FREE_STATEID]: "FREE_STATEID",
  [OP_GET_DIR_DELEGATION]: "GET_DIR_DELEGATION",
  [OP_GETDEVICEINFO]: "GETDEVICEINFO",
  [OP_GETDEVICELIST]: "GETDEVICELIST",
  [OP_LAYOUTCOMMIT]: "LAYOUTCOMMIT",
  [OP_LAYOUTGET]: "LAYOUTGET",
  [OP_LAYOUTRETURN]: "LAYOUTRETURN",
  [OP_SECINFO_NO_NAME]: "SECINFO_NO_NAME",
  [OP_SEQUENCE]: "SEQUENCE",
  [OP_SET_SSV]: "SET_SSV",
  [OP_TEST_STATEID]: "TEST_STATEID",
  [OP_WANT_DELEGATION]: "WANT_DELEGATION",
  [OP_DESTROY_CLIENTID]: "DESTROY_CLIENTID",
  [OP_RECLAIM_COMPLETE]: "RECLAIM_COMPLETE",
  [OP_ILLEGAL]: "ILLEGAL",
};

/** `OP_LOOKUP`, `OP_ILLEGAL`, or `nfs_opnum4 99` for something unnamed. */
export function opName4(op: number): string {
  const name = OP_NAMES[op];
  return name === undefined ? `nfs_opnum4 ${op}` : `OP_${name}`;
}

// ---------------------------------------------------------------------------
// nfs_ftype4 (RFC 8881 §5.8.1.2; XDR in RFC 5662 §2)
// ---------------------------------------------------------------------------

export const NF4REG = 1;
export const NF4DIR = 2;
export const NF4BLK = 3;
export const NF4CHR = 4;
export const NF4LNK = 5;
export const NF4SOCK = 6;
export const NF4FIFO = 7;
/** Named attribute directory. Unsupported here; declared so it can be refused. */
export const NF4ATTRDIR = 8;
/** Named attribute. Same. */
export const NF4NAMEDATTR = 9;

// ---------------------------------------------------------------------------
// FATTR4 bit numbers (RFC 8881 §5.6 and §5.7; XDR in RFC 5662 §2)
// ---------------------------------------------------------------------------
//
// These are *bit positions* in a `bitmap4`, not masks: attribute `n` is bit
// `n % 32` of word `n / 32`. Numbering is one flat space shared by the REQUIRED
// attributes (§5.6) and the RECOMMENDED ones (§5.7), which is why the two
// tables interleave — `filehandle` is 19 and `suppattr_exclcreat` is 75, both
// REQUIRED, with RECOMMENDED numbers on either side.

// REQUIRED (RFC 8881 §5.6, table 4).
export const FATTR4_SUPPORTED_ATTRS = 0;
export const FATTR4_TYPE = 1;
export const FATTR4_FH_EXPIRE_TYPE = 2;
export const FATTR4_CHANGE = 3;
export const FATTR4_SIZE = 4;
export const FATTR4_LINK_SUPPORT = 5;
export const FATTR4_SYMLINK_SUPPORT = 6;
export const FATTR4_NAMED_ATTR = 7;
export const FATTR4_FSID = 8;
export const FATTR4_UNIQUE_HANDLES = 9;
export const FATTR4_LEASE_TIME = 10;
export const FATTR4_RDATTR_ERROR = 11;
export const FATTR4_FILEHANDLE = 19;
export const FATTR4_SUPPATTR_EXCLCREAT = 75;

// RECOMMENDED (RFC 8881 §5.7, table 5).
export const FATTR4_ACL = 12;
export const FATTR4_ACLSUPPORT = 13;
export const FATTR4_ARCHIVE = 14;
export const FATTR4_CANSETTIME = 15;
export const FATTR4_CASE_INSENSITIVE = 16;
export const FATTR4_CASE_PRESERVING = 17;
export const FATTR4_CHOWN_RESTRICTED = 18;
export const FATTR4_FILEID = 20;
export const FATTR4_FILES_AVAIL = 21;
export const FATTR4_FILES_FREE = 22;
export const FATTR4_FILES_TOTAL = 23;
export const FATTR4_FS_LOCATIONS = 24;
export const FATTR4_HIDDEN = 25;
export const FATTR4_HOMOGENEOUS = 26;
export const FATTR4_MAXFILESIZE = 27;
export const FATTR4_MAXLINK = 28;
export const FATTR4_MAXNAME = 29;
export const FATTR4_MAXREAD = 30;
export const FATTR4_MAXWRITE = 31;
export const FATTR4_MIMETYPE = 32;
export const FATTR4_MODE = 33;
export const FATTR4_NO_TRUNC = 34;
export const FATTR4_NUMLINKS = 35;
export const FATTR4_OWNER = 36;
export const FATTR4_OWNER_GROUP = 37;
export const FATTR4_QUOTA_AVAIL_HARD = 38;
export const FATTR4_QUOTA_AVAIL_SOFT = 39;
export const FATTR4_QUOTA_USED = 40;
export const FATTR4_RAWDEV = 41;
export const FATTR4_SPACE_AVAIL = 42;
export const FATTR4_SPACE_FREE = 43;
export const FATTR4_SPACE_TOTAL = 44;
export const FATTR4_SPACE_USED = 45;
export const FATTR4_SYSTEM = 46;
export const FATTR4_TIME_ACCESS = 47;
export const FATTR4_TIME_ACCESS_SET = 48;
export const FATTR4_TIME_BACKUP = 49;
export const FATTR4_TIME_CREATE = 50;
export const FATTR4_TIME_DELTA = 51;
export const FATTR4_TIME_METADATA = 52;
export const FATTR4_TIME_MODIFY = 53;
export const FATTR4_TIME_MODIFY_SET = 54;
export const FATTR4_MOUNTED_ON_FILEID = 55;
// New in NFSv4.1.
export const FATTR4_DIR_NOTIF_DELAY = 56;
export const FATTR4_DIRENT_NOTIF_DELAY = 57;
export const FATTR4_DACL = 58;
export const FATTR4_SACL = 59;
export const FATTR4_CHANGE_POLICY = 60;
export const FATTR4_FS_STATUS = 61;
export const FATTR4_FS_LAYOUT_TYPES = 62;
export const FATTR4_LAYOUT_HINT = 63;
export const FATTR4_LAYOUT_TYPES = 64;
export const FATTR4_LAYOUT_BLKSIZE = 65;
export const FATTR4_LAYOUT_ALIGNMENT = 66;
export const FATTR4_FS_LOCATIONS_INFO = 67;
export const FATTR4_MDSTHRESHOLD = 68;
export const FATTR4_RETENTION_GET = 69;
export const FATTR4_RETENTION_SET = 70;
export const FATTR4_RETENTEVT_GET = 71;
export const FATTR4_RETENTEVT_SET = 72;
export const FATTR4_RETENTION_HOLD = 73;
export const FATTR4_MODE_SET_MASKED = 74;
export const FATTR4_FS_CHARSET_CAP = 76;

/** The highest attribute number NFSv4.1 defines, and so the widest bitmap. */
export const FATTR4_MAX = FATTR4_FS_CHARSET_CAP;

// ---------------------------------------------------------------------------
// fattr4_fh_expire_type (RFC 8881 §4.2.3; XDR in RFC 5662 §2)
// ---------------------------------------------------------------------------

/** Not a bit: the *absence* of every bit below. Our handles are persistent. */
export const FH4_PERSISTENT = 0x00_00_00_00;
export const FH4_NOEXPIRE_WITH_OPEN = 0x00_00_00_01;
export const FH4_VOLATILE_ANY = 0x00_00_00_02;
export const FH4_VOL_MIGRATION = 0x00_00_00_04;
export const FH4_VOL_RENAME = 0x00_00_00_08;

// ---------------------------------------------------------------------------
// fattr4_aclsupport (RFC 8881 §6.2.1.2; XDR in RFC 5662 §2)
// ---------------------------------------------------------------------------

export const ACL4_SUPPORT_ALLOW_ACL = 0x00_00_00_01;
export const ACL4_SUPPORT_DENY_ACL = 0x00_00_00_02;
export const ACL4_SUPPORT_AUDIT_ACL = 0x00_00_00_04;
export const ACL4_SUPPORT_ALARM_ACL = 0x00_00_00_08;

// ---------------------------------------------------------------------------
// ACCESS4 request/reply bits (RFC 8881 §18.1.1)
// ---------------------------------------------------------------------------

export const ACCESS4_READ = 0x00_00_00_01;
export const ACCESS4_LOOKUP = 0x00_00_00_02;
export const ACCESS4_MODIFY = 0x00_00_00_04;
export const ACCESS4_EXTEND = 0x00_00_00_08;
export const ACCESS4_DELETE = 0x00_00_00_10;
export const ACCESS4_EXECUTE = 0x00_00_00_20;
export const ACCESS4_ALL =
  ACCESS4_READ |
  ACCESS4_LOOKUP |
  ACCESS4_MODIFY |
  ACCESS4_EXTEND |
  ACCESS4_DELETE |
  ACCESS4_EXECUTE;

// ---------------------------------------------------------------------------
// time_how4 (RFC 8881 §3.3.2)
// ---------------------------------------------------------------------------

export const SET_TO_SERVER_TIME4 = 0;
export const SET_TO_CLIENT_TIME4 = 1;

// ---------------------------------------------------------------------------
// stable_how4 (RFC 8881 §18.32.1)
// ---------------------------------------------------------------------------

export const UNSTABLE4 = 0;
export const DATA_SYNC4 = 1;
export const FILE_SYNC4 = 2;

// ---------------------------------------------------------------------------
// secinfo_style4 (RFC 8881 §18.45.1)
// ---------------------------------------------------------------------------

/** `enum secinfo_style4` — which object SECINFO_NO_NAME is asking about. */
export const SECINFO_STYLE4_CURRENT_FH = 0;
export const SECINFO_STYLE4_PARENT = 1;

// ---------------------------------------------------------------------------
// OPEN (RFC 8881 §18.16.1 arguments, §18.16.2 results)
// ---------------------------------------------------------------------------

/** `enum createmode4`. `EXCLUSIVE4` is deprecated in 4.1 in favor of the `_1`. */
export const UNCHECKED4 = 0;
export const GUARDED4 = 1;
export const EXCLUSIVE4 = 2;
export const EXCLUSIVE4_1 = 3;

/** `enum opentype4`. */
export const OPEN4_NOCREATE = 0;
export const OPEN4_CREATE = 1;

/** Share access and deny constants for the OPEN argument. */
export const OPEN4_SHARE_ACCESS_READ = 0x00_00_00_01;
export const OPEN4_SHARE_ACCESS_WRITE = 0x00_00_00_02;
export const OPEN4_SHARE_ACCESS_BOTH = 0x00_00_00_03;
export const OPEN4_SHARE_DENY_NONE = 0x00_00_00_00;
export const OPEN4_SHARE_DENY_READ = 0x00_00_00_01;
export const OPEN4_SHARE_DENY_WRITE = 0x00_00_00_02;
export const OPEN4_SHARE_DENY_BOTH = 0x00_00_00_03;

/** Delegation wants, carried in the high bits of the same `share_access` word. */
export const OPEN4_SHARE_ACCESS_WANT_DELEG_MASK = 0xff_00;
export const OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE = 0x00_00;
export const OPEN4_SHARE_ACCESS_WANT_READ_DELEG = 0x01_00;
export const OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG = 0x02_00;
export const OPEN4_SHARE_ACCESS_WANT_ANY_DELEG = 0x03_00;
export const OPEN4_SHARE_ACCESS_WANT_NO_DELEG = 0x04_00;
export const OPEN4_SHARE_ACCESS_WANT_CANCEL = 0x05_00;
export const OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL = 0x01_00_00;
export const OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED = 0x02_00_00;

/** `OPEN4resok.rflags`. `CONFIRM` is NFSv4.0's and must never be set in 4.1. */
export const OPEN4_RESULT_CONFIRM = 0x00_00_00_02;
export const OPEN4_RESULT_LOCKTYPE_POSIX = 0x00_00_00_04;
export const OPEN4_RESULT_PRESERVE_UNLINKED = 0x00_00_00_08;
export const OPEN4_RESULT_MAY_NOTIFY_LOCK = 0x00_00_00_20;

/** `enum open_delegation_type4`. This server always answers `NONE`. */
export const OPEN_DELEGATE_NONE = 0;
export const OPEN_DELEGATE_READ = 1;
export const OPEN_DELEGATE_WRITE = 2;
export const OPEN_DELEGATE_NONE_EXT = 3;

/** `enum why_no_delegation4`, the reason carried by `OPEN_DELEGATE_NONE_EXT`. */
export const WND4_NOT_WANTED = 0;
export const WND4_CONTENTION = 1;
export const WND4_RESOURCE = 2;
export const WND4_NOT_SUPP_FTYPE = 3;
export const WND4_WRITE_DELEG_NOT_SUPP_FTYPE = 4;
export const WND4_NOT_SUPP_UPGRADE = 5;
export const WND4_NOT_SUPP_DOWNGRADE = 6;
export const WND4_CANCELLED = 7;
export const WND4_IS_DIR = 8;

/** `enum open_claim_type4`. The last three are new to 4.1. */
export const CLAIM_NULL = 0;
export const CLAIM_PREVIOUS = 1;
export const CLAIM_DELEGATE_CUR = 2;
export const CLAIM_DELEGATE_PREV = 3;
export const CLAIM_FH = 4;
export const CLAIM_DELEG_CUR_FH = 5;
export const CLAIM_DELEG_PREV_FH = 6;

// ---------------------------------------------------------------------------
// EXCHANGE_ID (RFC 8881 §18.35.1)
// ---------------------------------------------------------------------------

export const EXCHGID4_FLAG_SUPP_MOVED_REFER = 0x00_00_00_01;
export const EXCHGID4_FLAG_SUPP_MOVED_MIGR = 0x00_00_00_02;
export const EXCHGID4_FLAG_BIND_PRINC_STATEID = 0x00_00_01_00;
export const EXCHGID4_FLAG_USE_NON_PNFS = 0x00_01_00_00;
export const EXCHGID4_FLAG_USE_PNFS_MDS = 0x00_02_00_00;
export const EXCHGID4_FLAG_USE_PNFS_DS = 0x00_04_00_00;
export const EXCHGID4_FLAG_MASK_PNFS = 0x00_07_00_00;
/** Set by the *client* to update a confirmed record. */
export const EXCHGID4_FLAG_UPD_CONFIRMED_REC_A = 0x40_00_00_00;
/** Set by the *server* to say the client ID is confirmed. */
export const EXCHGID4_FLAG_CONFIRMED_R = 0x80_00_00_00;

/** `enum state_protect_how4`. This server offers `SP4_NONE` and nothing else. */
export const SP4_NONE = 0;
export const SP4_MACH_CRED = 1;
export const SP4_SSV = 2;

// ---------------------------------------------------------------------------
// CREATE_SESSION (RFC 8881 §18.36.1)
// ---------------------------------------------------------------------------

export const CREATE_SESSION4_FLAG_PERSIST = 0x00_00_00_01;
export const CREATE_SESSION4_FLAG_CONN_BACK_CHAN = 0x00_00_00_02;
export const CREATE_SESSION4_FLAG_CONN_RDMA = 0x00_00_00_04;

// ---------------------------------------------------------------------------
// SEQUENCE status flags (RFC 8881 §18.46.2)
// ---------------------------------------------------------------------------

export const SEQ4_STATUS_CB_PATH_DOWN = 0x00_00_00_01;
export const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING = 0x00_00_00_02;
export const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED = 0x00_00_00_04;
export const SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED = 0x00_00_00_08;
export const SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED = 0x00_00_00_10;
export const SEQ4_STATUS_ADMIN_STATE_REVOKED = 0x00_00_00_20;
export const SEQ4_STATUS_RECALLABLE_STATE_REVOKED = 0x00_00_00_40;
export const SEQ4_STATUS_LEASE_MOVED = 0x00_00_00_80;
export const SEQ4_STATUS_RESTART_RECLAIM_NEEDED = 0x00_00_01_00;
export const SEQ4_STATUS_CB_PATH_DOWN_SESSION = 0x00_00_02_00;
export const SEQ4_STATUS_BACKCHANNEL_FAULT = 0x00_00_04_00;
export const SEQ4_STATUS_DEVID_CHANGED = 0x00_00_08_00;
export const SEQ4_STATUS_DEVID_DELETED = 0x00_00_10_00;

// ---------------------------------------------------------------------------
// errno mapping
// ---------------------------------------------------------------------------

/**
 * `nfsstat4` for a driver error.
 *
 * RFC 8881 §15.1 fixes the set of statuses a v4 server may return, and it is
 * *not* "any errno": a client that receives a status outside the list is
 * entitled to treat the reply as garbage. Anything unmapped becomes
 * `NFS4ERR_IO`, the same fallback `../v3/protocol.ts` uses and for the same
 * reason — a reply the client cannot interpret is worse than a
 * wrong-but-legal one.
 */
const ERRNO_TO_NFS4: Partial<Record<ErrnoCode, number>> = {
  EPERM: NFS4ERR_PERM,
  ENOENT: NFS4ERR_NOENT,
  EIO: NFS4ERR_IO,
  ENXIO: NFS4ERR_NXIO,
  EACCES: NFS4ERR_ACCESS,
  EEXIST: NFS4ERR_EXIST,
  EXDEV: NFS4ERR_XDEV,
  // NFSv3's `NODEV` was status 19, and NFSv4 leaves 19 unallocated rather than
  // give an old number a new meaning — so there is no `ENODEV` to send, and the
  // documented fallback is the honest answer.
  ENODEV: NFS4ERR_IO,
  ENOTDIR: NFS4ERR_NOTDIR,
  EISDIR: NFS4ERR_ISDIR,
  EINVAL: NFS4ERR_INVAL,
  EFBIG: NFS4ERR_FBIG,
  ENOSPC: NFS4ERR_NOSPC,
  EROFS: NFS4ERR_ROFS,
  EMLINK: NFS4ERR_MLINK,
  ENAMETOOLONG: NFS4ERR_NAMETOOLONG,
  ENOTEMPTY: NFS4ERR_NOTEMPTY,
  EDQUOT: NFS4ERR_DQUOT,
  ESTALE: NFS4ERR_STALE,
  ENOSYS: NFS4ERR_NOTSUPP,
  ENOTSUP: NFS4ERR_NOTSUPP,
  // Unlike NFSv3, v4 *has* a status for "you walked into a symlink": the client
  // resolves the link itself and retries, which is exactly what a driver
  // reporting `ELOOP` wants it to do.
  ELOOP: NFS4ERR_SYMLINK,
  // `NFS4ERR_DELAY` is v4's "busy, come back", the successor to v3's JUKEBOX.
  EAGAIN: NFS4ERR_DELAY,
};

/** The `nfsstat4` to answer a thrown driver error with. */
export function nfs4StatusOf(error: unknown): number {
  if (typeof error === "object" && error !== null) {
    const code = (error as { code?: unknown }).code;
    // `Object.hasOwn`, not `in`: `in` also matches `Object.prototype`, so an
    // error with `code: "toString"` would look up a *function* and encode it
    // as status 0 — a success header in front of a failure body, which is a
    // decoder desync rather than a wrong answer.
    if (typeof code === "string" && Object.hasOwn(ERRNO_TO_NFS4, code)) {
      return ERRNO_TO_NFS4[code as ErrnoCode] ?? NFS4ERR_IO;
    }
  }
  return NFS4ERR_IO;
}

/**
 * The reverse direction, for a client turning a status into an error.
 *
 * Most of NFSv4.1's statuses describe the *protocol* — stateids, clientids,
 * sessions, slots, layouts, COMPOUND framing — and have no POSIX counterpart at
 * all; those fall through to `EIO`, which is what a caller who cannot retry
 * should see. Only the ones with an honest counterpart are listed, and each
 * non-obvious choice says why.
 */
const NFS4_TO_ERRNO = new Map<number, ErrnoCode>([
  [NFS4ERR_PERM, "EPERM"],
  [NFS4ERR_NOENT, "ENOENT"],
  [NFS4ERR_IO, "EIO"],
  [NFS4ERR_NXIO, "ENXIO"],
  [NFS4ERR_ACCESS, "EACCES"],
  [NFS4ERR_EXIST, "EEXIST"],
  [NFS4ERR_XDEV, "EXDEV"],
  [NFS4ERR_NOTDIR, "ENOTDIR"],
  [NFS4ERR_ISDIR, "EISDIR"],
  [NFS4ERR_INVAL, "EINVAL"],
  [NFS4ERR_FBIG, "EFBIG"],
  [NFS4ERR_NOSPC, "ENOSPC"],
  [NFS4ERR_ROFS, "EROFS"],
  [NFS4ERR_MLINK, "EMLINK"],
  [NFS4ERR_NAMETOOLONG, "ENAMETOOLONG"],
  [NFS4ERR_NOTEMPTY, "ENOTEMPTY"],
  [NFS4ERR_DQUOT, "EDQUOT"],
  [NFS4ERR_STALE, "ESTALE"],
  // Three ways of saying "that handle names nothing any more".
  [NFS4ERR_BADHANDLE, "ESTALE"],
  [NFS4ERR_FHEXPIRED, "ESTALE"],
  [NFS4ERR_NOTSUPP, "ENOTSUP"],
  [NFS4ERR_ATTRNOTSUPP, "ENOTSUP"],
  [NFS4ERR_SERVERFAULT, "EIO"],
  // "That type is not valid for CREATE" is an argument the caller got wrong.
  [NFS4ERR_BADTYPE, "EINVAL"],
  // The path crossed a symlink the client must resolve; `ELOOP` is the only
  // POSIX code that names a symlink in the way of a lookup.
  [NFS4ERR_SYMLINK, "ELOOP"],
  // A security flavor the export will not accept reads as a denial, not a fault.
  [NFS4ERR_WRONGSEC, "EACCES"],
  [NFS4ERR_SHARE_DENIED, "EACCES"],
  // The three "not now, try again" statuses. POSIX has one answer for all of
  // them, and it is the one `fcntl` locking already uses.
  [NFS4ERR_DELAY, "EAGAIN"],
  [NFS4ERR_GRACE, "EAGAIN"],
  [NFS4ERR_DENIED, "EAGAIN"],
  [NFS4ERR_LOCKED, "EAGAIN"],
  // Refused because something else still holds the object open.
  [NFS4ERR_FILE_OPEN, "EBUSY"],
  [NFS4ERR_LOCKS_HELD, "EBUSY"],
  [NFS4ERR_CLIENTID_BUSY, "EBUSY"],
  [NFS4ERR_BACK_CHAN_BUSY, "EBUSY"],
]);

/** The POSIX code a client should report for an `nfsstat4`. */
export function errnoCodeOfStatus4(status: number): ErrnoCode {
  return NFS4_TO_ERRNO.get(status) ?? "EIO";
}

/** Positive Linux errno for an `nfsstat4`, for anything that wants a number. */
export function errnoOfStatus4(status: number): number {
  return ERRNO_CODES[errnoCodeOfStatus4(status)];
}

const STATUS4_NAMES: Record<number, string> = {
  [NFS4_OK]: "NFS4_OK",
  [NFS4ERR_PERM]: "NFS4ERR_PERM",
  [NFS4ERR_NOENT]: "NFS4ERR_NOENT",
  [NFS4ERR_IO]: "NFS4ERR_IO",
  [NFS4ERR_NXIO]: "NFS4ERR_NXIO",
  [NFS4ERR_ACCESS]: "NFS4ERR_ACCESS",
  [NFS4ERR_EXIST]: "NFS4ERR_EXIST",
  [NFS4ERR_XDEV]: "NFS4ERR_XDEV",
  [NFS4ERR_NOTDIR]: "NFS4ERR_NOTDIR",
  [NFS4ERR_ISDIR]: "NFS4ERR_ISDIR",
  [NFS4ERR_INVAL]: "NFS4ERR_INVAL",
  [NFS4ERR_FBIG]: "NFS4ERR_FBIG",
  [NFS4ERR_NOSPC]: "NFS4ERR_NOSPC",
  [NFS4ERR_ROFS]: "NFS4ERR_ROFS",
  [NFS4ERR_MLINK]: "NFS4ERR_MLINK",
  [NFS4ERR_NAMETOOLONG]: "NFS4ERR_NAMETOOLONG",
  [NFS4ERR_NOTEMPTY]: "NFS4ERR_NOTEMPTY",
  [NFS4ERR_DQUOT]: "NFS4ERR_DQUOT",
  [NFS4ERR_STALE]: "NFS4ERR_STALE",
  [NFS4ERR_BADHANDLE]: "NFS4ERR_BADHANDLE",
  [NFS4ERR_BAD_COOKIE]: "NFS4ERR_BAD_COOKIE",
  [NFS4ERR_NOTSUPP]: "NFS4ERR_NOTSUPP",
  [NFS4ERR_TOOSMALL]: "NFS4ERR_TOOSMALL",
  [NFS4ERR_SERVERFAULT]: "NFS4ERR_SERVERFAULT",
  [NFS4ERR_BADTYPE]: "NFS4ERR_BADTYPE",
  [NFS4ERR_DELAY]: "NFS4ERR_DELAY",
  [NFS4ERR_SAME]: "NFS4ERR_SAME",
  [NFS4ERR_DENIED]: "NFS4ERR_DENIED",
  [NFS4ERR_EXPIRED]: "NFS4ERR_EXPIRED",
  [NFS4ERR_LOCKED]: "NFS4ERR_LOCKED",
  [NFS4ERR_GRACE]: "NFS4ERR_GRACE",
  [NFS4ERR_FHEXPIRED]: "NFS4ERR_FHEXPIRED",
  [NFS4ERR_SHARE_DENIED]: "NFS4ERR_SHARE_DENIED",
  [NFS4ERR_WRONGSEC]: "NFS4ERR_WRONGSEC",
  [NFS4ERR_CLID_INUSE]: "NFS4ERR_CLID_INUSE",
  [NFS4ERR_RESOURCE]: "NFS4ERR_RESOURCE",
  [NFS4ERR_MOVED]: "NFS4ERR_MOVED",
  [NFS4ERR_NOFILEHANDLE]: "NFS4ERR_NOFILEHANDLE",
  [NFS4ERR_MINOR_VERS_MISMATCH]: "NFS4ERR_MINOR_VERS_MISMATCH",
  [NFS4ERR_STALE_CLIENTID]: "NFS4ERR_STALE_CLIENTID",
  [NFS4ERR_STALE_STATEID]: "NFS4ERR_STALE_STATEID",
  [NFS4ERR_OLD_STATEID]: "NFS4ERR_OLD_STATEID",
  [NFS4ERR_BAD_STATEID]: "NFS4ERR_BAD_STATEID",
  [NFS4ERR_BAD_SEQID]: "NFS4ERR_BAD_SEQID",
  [NFS4ERR_NOT_SAME]: "NFS4ERR_NOT_SAME",
  [NFS4ERR_LOCK_RANGE]: "NFS4ERR_LOCK_RANGE",
  [NFS4ERR_SYMLINK]: "NFS4ERR_SYMLINK",
  [NFS4ERR_RESTOREFH]: "NFS4ERR_RESTOREFH",
  [NFS4ERR_LEASE_MOVED]: "NFS4ERR_LEASE_MOVED",
  [NFS4ERR_ATTRNOTSUPP]: "NFS4ERR_ATTRNOTSUPP",
  [NFS4ERR_NO_GRACE]: "NFS4ERR_NO_GRACE",
  [NFS4ERR_RECLAIM_BAD]: "NFS4ERR_RECLAIM_BAD",
  [NFS4ERR_RECLAIM_CONFLICT]: "NFS4ERR_RECLAIM_CONFLICT",
  [NFS4ERR_BADXDR]: "NFS4ERR_BADXDR",
  [NFS4ERR_LOCKS_HELD]: "NFS4ERR_LOCKS_HELD",
  [NFS4ERR_OPENMODE]: "NFS4ERR_OPENMODE",
  [NFS4ERR_BADOWNER]: "NFS4ERR_BADOWNER",
  [NFS4ERR_BADCHAR]: "NFS4ERR_BADCHAR",
  [NFS4ERR_BADNAME]: "NFS4ERR_BADNAME",
  [NFS4ERR_BAD_RANGE]: "NFS4ERR_BAD_RANGE",
  [NFS4ERR_LOCK_NOTSUPP]: "NFS4ERR_LOCK_NOTSUPP",
  [NFS4ERR_OP_ILLEGAL]: "NFS4ERR_OP_ILLEGAL",
  [NFS4ERR_DEADLOCK]: "NFS4ERR_DEADLOCK",
  [NFS4ERR_FILE_OPEN]: "NFS4ERR_FILE_OPEN",
  [NFS4ERR_ADMIN_REVOKED]: "NFS4ERR_ADMIN_REVOKED",
  [NFS4ERR_CB_PATH_DOWN]: "NFS4ERR_CB_PATH_DOWN",
  [NFS4ERR_BADIOMODE]: "NFS4ERR_BADIOMODE",
  [NFS4ERR_BADLAYOUT]: "NFS4ERR_BADLAYOUT",
  [NFS4ERR_BAD_SESSION_DIGEST]: "NFS4ERR_BAD_SESSION_DIGEST",
  [NFS4ERR_BADSESSION]: "NFS4ERR_BADSESSION",
  [NFS4ERR_BADSLOT]: "NFS4ERR_BADSLOT",
  [NFS4ERR_COMPLETE_ALREADY]: "NFS4ERR_COMPLETE_ALREADY",
  [NFS4ERR_CONN_NOT_BOUND_TO_SESSION]: "NFS4ERR_CONN_NOT_BOUND_TO_SESSION",
  [NFS4ERR_DELEG_ALREADY_WANTED]: "NFS4ERR_DELEG_ALREADY_WANTED",
  [NFS4ERR_BACK_CHAN_BUSY]: "NFS4ERR_BACK_CHAN_BUSY",
  [NFS4ERR_LAYOUTTRYLATER]: "NFS4ERR_LAYOUTTRYLATER",
  [NFS4ERR_LAYOUTUNAVAILABLE]: "NFS4ERR_LAYOUTUNAVAILABLE",
  [NFS4ERR_NOMATCHING_LAYOUT]: "NFS4ERR_NOMATCHING_LAYOUT",
  [NFS4ERR_RECALLCONFLICT]: "NFS4ERR_RECALLCONFLICT",
  [NFS4ERR_UNKNOWN_LAYOUTTYPE]: "NFS4ERR_UNKNOWN_LAYOUTTYPE",
  [NFS4ERR_SEQ_MISORDERED]: "NFS4ERR_SEQ_MISORDERED",
  [NFS4ERR_SEQUENCE_POS]: "NFS4ERR_SEQUENCE_POS",
  [NFS4ERR_REQ_TOO_BIG]: "NFS4ERR_REQ_TOO_BIG",
  [NFS4ERR_REP_TOO_BIG]: "NFS4ERR_REP_TOO_BIG",
  [NFS4ERR_REP_TOO_BIG_TO_CACHE]: "NFS4ERR_REP_TOO_BIG_TO_CACHE",
  [NFS4ERR_RETRY_UNCACHED_REP]: "NFS4ERR_RETRY_UNCACHED_REP",
  [NFS4ERR_UNSAFE_COMPOUND]: "NFS4ERR_UNSAFE_COMPOUND",
  [NFS4ERR_TOO_MANY_OPS]: "NFS4ERR_TOO_MANY_OPS",
  [NFS4ERR_OP_NOT_IN_SESSION]: "NFS4ERR_OP_NOT_IN_SESSION",
  [NFS4ERR_HASH_ALG_UNSUPP]: "NFS4ERR_HASH_ALG_UNSUPP",
  [NFS4ERR_CLIENTID_BUSY]: "NFS4ERR_CLIENTID_BUSY",
  [NFS4ERR_PNFS_IO_HOLE]: "NFS4ERR_PNFS_IO_HOLE",
  [NFS4ERR_SEQ_FALSE_RETRY]: "NFS4ERR_SEQ_FALSE_RETRY",
  [NFS4ERR_BAD_HIGH_SLOT]: "NFS4ERR_BAD_HIGH_SLOT",
  [NFS4ERR_DEADSESSION]: "NFS4ERR_DEADSESSION",
  [NFS4ERR_ENCR_ALG_UNSUPP]: "NFS4ERR_ENCR_ALG_UNSUPP",
  [NFS4ERR_PNFS_NO_LAYOUT]: "NFS4ERR_PNFS_NO_LAYOUT",
  [NFS4ERR_NOT_ONLY_OP]: "NFS4ERR_NOT_ONLY_OP",
  [NFS4ERR_WRONG_CRED]: "NFS4ERR_WRONG_CRED",
  [NFS4ERR_WRONG_TYPE]: "NFS4ERR_WRONG_TYPE",
  [NFS4ERR_DIRDELEG_UNAVAIL]: "NFS4ERR_DIRDELEG_UNAVAIL",
  [NFS4ERR_REJECT_DELEG]: "NFS4ERR_REJECT_DELEG",
  [NFS4ERR_RETURNCONFLICT]: "NFS4ERR_RETURNCONFLICT",
  [NFS4ERR_DELEG_REVOKED]: "NFS4ERR_DELEG_REVOKED",
};

/**
 * Name of an `nfsstat4`, for error messages.
 *
 * Unlike v3's `statusName`, this reads the status's *own* name out of a table
 * rather than deriving one from the errno map: NFSv4.1 has some seventy-five
 * statuses and most of them collapse onto `EIO`, so a derived name would call
 * `NFS4ERR_BADSLOT` and `NFS4ERR_SEQ_MISORDERED` the same thing.
 */
export function status4Name(status: number): string {
  return STATUS4_NAMES[status] ?? `nfsstat4 ${status}`;
}
