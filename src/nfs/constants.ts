/**
 * ONC RPC and NFSv3 wire constants.
 *
 * Transcribed from the two RFCs, which are frozen and were frozen before this
 * project started:
 *
 * - **RFC 5531** — RPC: Remote Procedure Call Protocol Specification Version 2
 *   (the ONC RPC v2 message format, auth flavors and reply statuses).
 * - **RFC 1813** — NFS Version 3 Protocol Specification, including its
 *   appendix I, the MOUNT version 3 protocol.
 *
 * Nothing here is guessed; each group repeats the XDR declaration it comes
 * from, and every codec in `protocol.ts` / `rpc.ts` names the section it
 * implements. Everything on the wire is **big-endian** (XDR), which is the one
 * respect in which this transport is the opposite of the FUSE one.
 */

// ---------------------------------------------------------------------------
// ONC RPC v2 (RFC 5531 §9)
// ---------------------------------------------------------------------------

/** The only RPC version that exists. */
export const RPC_VERSION = 2;

/** `enum msg_type`. */
export const RPC_CALL = 0;
export const RPC_REPLY = 1;

/** `enum reply_stat`. */
export const MSG_ACCEPTED = 0;
export const MSG_DENIED = 1;

/** `enum accept_stat`. */
export const RPC_SUCCESS = 0;
export const RPC_PROG_UNAVAIL = 1;
export const RPC_PROG_MISMATCH = 2;
export const RPC_PROC_UNAVAIL = 3;
export const RPC_GARBAGE_ARGS = 4;
export const RPC_SYSTEM_ERR = 5;

/** `enum reject_stat`. */
export const RPC_MISMATCH = 0;
export const RPC_AUTH_ERROR = 1;

/** `enum auth_stat`. */
export const AUTH_OK = 0;
export const AUTH_BADCRED = 1;
export const AUTH_REJECTEDCRED = 2;
export const AUTH_BADVERF = 3;
export const AUTH_REJECTEDVERF = 4;
export const AUTH_TOOWEAK = 5;
export const AUTH_INVALIDRESP = 6;
export const AUTH_FAILED = 7;

/** `enum auth_flavor`. `AUTH_SYS` is `AUTH_UNIX`'s modern name. */
export const AUTH_NONE = 0;
export const AUTH_SYS = 1;
export const AUTH_SHORT = 2;

/** Longest `opaque_auth` body (RFC 5531: `opaque body<400>`). */
export const RPC_MAX_AUTH_BYTES = 400;

/** Record-marking fragment header: high bit is "last fragment". */
export const RM_LAST_FRAGMENT = 0x80_00_00_00;
/** Low 31 bits of a record-marking header are the fragment length. */
export const RM_LENGTH_MASK = 0x7f_ff_ff_ff;

// ---------------------------------------------------------------------------
// programs
// ---------------------------------------------------------------------------

/** NFS program number and the only version this server speaks. */
export const NFS_PROGRAM = 100_003;
export const NFS_V3 = 3;

/** MOUNT program number and version (RFC 1813 appendix I). */
export const MOUNT_PROGRAM = 100_005;
export const MOUNT_V3 = 3;

/** NFSv3 procedure numbers (RFC 1813 §3). */
export const NFSPROC3_NULL = 0;
export const NFSPROC3_GETATTR = 1;
export const NFSPROC3_SETATTR = 2;
export const NFSPROC3_LOOKUP = 3;
export const NFSPROC3_ACCESS = 4;
export const NFSPROC3_READLINK = 5;
export const NFSPROC3_READ = 6;
export const NFSPROC3_WRITE = 7;
export const NFSPROC3_CREATE = 8;
export const NFSPROC3_MKDIR = 9;
export const NFSPROC3_SYMLINK = 10;
export const NFSPROC3_MKNOD = 11;
export const NFSPROC3_REMOVE = 12;
export const NFSPROC3_RMDIR = 13;
export const NFSPROC3_RENAME = 14;
export const NFSPROC3_LINK = 15;
export const NFSPROC3_READDIR = 16;
export const NFSPROC3_READDIRPLUS = 17;
export const NFSPROC3_FSSTAT = 18;
export const NFSPROC3_FSINFO = 19;
export const NFSPROC3_PATHCONF = 20;
export const NFSPROC3_COMMIT = 21;

/** MOUNT v3 procedure numbers (RFC 1813 appendix I §5). */
export const MOUNTPROC3_NULL = 0;
export const MOUNTPROC3_MNT = 1;
export const MOUNTPROC3_DUMP = 2;
export const MOUNTPROC3_UMNT = 3;
export const MOUNTPROC3_UMNTALL = 4;
export const MOUNTPROC3_EXPORT = 5;

/** Human-readable procedure names, for errors and test output. */
const NFS_PROC_NAMES: Record<number, string> = {
  [NFSPROC3_NULL]: "NULL",
  [NFSPROC3_GETATTR]: "GETATTR",
  [NFSPROC3_SETATTR]: "SETATTR",
  [NFSPROC3_LOOKUP]: "LOOKUP",
  [NFSPROC3_ACCESS]: "ACCESS",
  [NFSPROC3_READLINK]: "READLINK",
  [NFSPROC3_READ]: "READ",
  [NFSPROC3_WRITE]: "WRITE",
  [NFSPROC3_CREATE]: "CREATE",
  [NFSPROC3_MKDIR]: "MKDIR",
  [NFSPROC3_SYMLINK]: "SYMLINK",
  [NFSPROC3_MKNOD]: "MKNOD",
  [NFSPROC3_REMOVE]: "REMOVE",
  [NFSPROC3_RMDIR]: "RMDIR",
  [NFSPROC3_RENAME]: "RENAME",
  [NFSPROC3_LINK]: "LINK",
  [NFSPROC3_READDIR]: "READDIR",
  [NFSPROC3_READDIRPLUS]: "READDIRPLUS",
  [NFSPROC3_FSSTAT]: "FSSTAT",
  [NFSPROC3_FSINFO]: "FSINFO",
  [NFSPROC3_PATHCONF]: "PATHCONF",
  [NFSPROC3_COMMIT]: "COMMIT",
};

const MOUNT_PROC_NAMES: Record<number, string> = {
  [MOUNTPROC3_NULL]: "NULL",
  [MOUNTPROC3_MNT]: "MNT",
  [MOUNTPROC3_DUMP]: "DUMP",
  [MOUNTPROC3_UMNT]: "UMNT",
  [MOUNTPROC3_UMNTALL]: "UMNTALL",
  [MOUNTPROC3_EXPORT]: "EXPORT",
};

/** `NFSPROC3_LOOKUP`, `MOUNTPROC3_MNT`, or `prog 100003 proc 99`. */
export function procedureName(program: number, procedure: number): string {
  if (program === NFS_PROGRAM) {
    return NFS_PROC_NAMES[procedure] ?? `NFSPROC3_${procedure}`;
  }
  if (program === MOUNT_PROGRAM) {
    return MOUNT_PROC_NAMES[procedure] ?? `MOUNTPROC3_${procedure}`;
  }
  return `prog ${program} proc ${procedure}`;
}

// ---------------------------------------------------------------------------
// NFSv3 sizes and limits (RFC 1813 §2.4)
// ---------------------------------------------------------------------------

/** Longest file handle. Ours is much shorter; the client must not assume so. */
export const NFS3_FHSIZE = 64;
export const NFS3_COOKIEVERFSIZE = 8;
export const NFS3_CREATEVERFSIZE = 8;
export const NFS3_WRITEVERFSIZE = 8;
/** MOUNT's own `FHSIZE3` and `MNTPATHLEN`. */
export const MNT3_FHSIZE = 64;
export const MNT3_PATHLEN = 1024;
export const MNT3_NAMELEN = 255;

// ---------------------------------------------------------------------------
// nfsstat3 (RFC 1813 §2.6)
// ---------------------------------------------------------------------------

export const NFS3_OK = 0;
export const NFS3ERR_PERM = 1;
export const NFS3ERR_NOENT = 2;
export const NFS3ERR_IO = 5;
export const NFS3ERR_NXIO = 6;
export const NFS3ERR_ACCES = 13;
export const NFS3ERR_EXIST = 17;
export const NFS3ERR_XDEV = 18;
export const NFS3ERR_NODEV = 19;
export const NFS3ERR_NOTDIR = 20;
export const NFS3ERR_ISDIR = 21;
export const NFS3ERR_INVAL = 22;
export const NFS3ERR_FBIG = 27;
export const NFS3ERR_NOSPC = 28;
export const NFS3ERR_ROFS = 30;
export const NFS3ERR_MLINK = 31;
export const NFS3ERR_NAMETOOLONG = 63;
export const NFS3ERR_NOTEMPTY = 66;
export const NFS3ERR_DQUOT = 69;
export const NFS3ERR_STALE = 70;
export const NFS3ERR_REMOTE = 71;
export const NFS3ERR_BADHANDLE = 10_001;
export const NFS3ERR_NOT_SYNC = 10_002;
export const NFS3ERR_BAD_COOKIE = 10_003;
export const NFS3ERR_NOTSUPP = 10_004;
export const NFS3ERR_TOOSMALL = 10_005;
export const NFS3ERR_SERVERFAULT = 10_006;
export const NFS3ERR_BADTYPE = 10_007;
export const NFS3ERR_JUKEBOX = 10_008;

/** `enum ftype3`. */
export const NF3REG = 1;
export const NF3DIR = 2;
export const NF3BLK = 3;
export const NF3CHR = 4;
export const NF3LNK = 5;
export const NF3SOCK = 6;
export const NF3FIFO = 7;

/** `enum stable_how`. */
export const UNSTABLE = 0;
export const DATA_SYNC = 1;
export const FILE_SYNC = 2;

/** `enum createmode3`. */
export const CREATE_UNCHECKED = 0;
export const CREATE_GUARDED = 1;
export const CREATE_EXCLUSIVE = 2;

/** `enum time_how`. */
export const DONT_CHANGE = 0;
export const SET_TO_SERVER_TIME = 1;
export const SET_TO_CLIENT_TIME = 2;

/** ACCESS3 request/reply bits (RFC 1813 §3.3.4). */
export const ACCESS3_READ = 0x00_01;
export const ACCESS3_LOOKUP = 0x00_02;
export const ACCESS3_MODIFY = 0x00_04;
export const ACCESS3_EXTEND = 0x00_08;
export const ACCESS3_DELETE = 0x00_10;
export const ACCESS3_EXECUTE = 0x00_20;
export const ACCESS3_ALL =
  ACCESS3_READ |
  ACCESS3_LOOKUP |
  ACCESS3_MODIFY |
  ACCESS3_EXTEND |
  ACCESS3_DELETE |
  ACCESS3_EXECUTE;

/** FSINFO `properties` bits (RFC 1813 §3.3.19). */
export const FSF3_LINK = 0x00_01;
export const FSF3_SYMLINK = 0x00_02;
export const FSF3_HOMOGENEOUS = 0x00_08;
export const FSF3_CANSETTIME = 0x00_10;

// ---------------------------------------------------------------------------
// mountstat3 (RFC 1813 appendix I §5.1.4)
// ---------------------------------------------------------------------------

export const MNT3_OK = 0;
export const MNT3ERR_PERM = 1;
export const MNT3ERR_NOENT = 2;
export const MNT3ERR_IO = 5;
export const MNT3ERR_ACCES = 13;
export const MNT3ERR_NOTDIR = 20;
export const MNT3ERR_INVAL = 22;
export const MNT3ERR_NAMETOOLONG = 63;
export const MNT3ERR_NOTSUPP = 10_004;
export const MNT3ERR_SERVERFAULT = 10_006;
