/**
 * 9P wire-protocol constants.
 *
 * Transcribed from the Linux kernel's `include/net/9p/9p.h` at tag **v6.12** —
 * the same tag `src/fuse/constants.ts` transcribes `fuse.h` from, so the two
 * transports describe one kernel. Source of truth:
 * <https://github.com/torvalds/linux/blob/v6.12/include/net/9p/9p.h>.
 *
 * One group is **not** in that header: the setattr valid-mask bits, which the
 * kernel keeps as `P9_ATTR_*` in `fs/9p/vfs_inode_dotl.c` (v6.12, the
 * `#define`s above `v9fs_mapped_iattr_valid()`). They are spelled
 * `P9_SETATTR_*` here, after the field they fill; the getattr mask *is* in the
 * header, as `P9_STATS_*`, and is spelled `P9_GETATTR_*` for the same reason.
 * Both renamings are naming only — every value below is the kernel's.
 *
 * Nothing is guessed and nothing is borrowed from a host header: this is a
 * server for the Linux client, so the values that matter are the ones that
 * client compiles in. `9p2000.L` is the only dialect served, but the legacy
 * 9P2000 message types are transcribed too — a session has to *recognize* them
 * to refuse them with `Rlerror ENOTSUP` rather than answer a walk with silence.
 */

// ---------------------------------------------------------------------------
// Message types (enum p9_msg_t)
//
// Every request is even and its reply is the next value up, without exception.
// The gaps are real: 9P2000.L kept 9P2000's numbering — including the types it
// replaced, which stay allocated so a server can recognize and refuse them —
// and slotted its own messages into the ranges 9P2000 never used.
// ---------------------------------------------------------------------------

/** Never sent — 9P2000.L has no `Tlerror`, only the reply. */
export const P9_TLERROR = 6;
/** Reply to any failed 9P2000.L request; carries a positive Linux errno. */
export const P9_RLERROR = 7;
export const P9_TSTATFS = 8;
export const P9_RSTATFS = 9;
export const P9_TLOPEN = 12;
export const P9_RLOPEN = 13;
export const P9_TLCREATE = 14;
export const P9_RLCREATE = 15;
export const P9_TSYMLINK = 16;
export const P9_RSYMLINK = 17;
export const P9_TMKNOD = 18;
export const P9_RMKNOD = 19;
export const P9_TRENAME = 20;
export const P9_RRENAME = 21;
export const P9_TREADLINK = 22;
export const P9_RREADLINK = 23;
export const P9_TGETATTR = 24;
export const P9_RGETATTR = 25;
export const P9_TSETATTR = 26;
export const P9_RSETATTR = 27;
export const P9_TXATTRWALK = 30;
export const P9_RXATTRWALK = 31;
export const P9_TXATTRCREATE = 32;
export const P9_RXATTRCREATE = 33;
export const P9_TREADDIR = 40;
export const P9_RREADDIR = 41;
export const P9_TFSYNC = 50;
export const P9_RFSYNC = 51;
export const P9_TLOCK = 52;
export const P9_RLOCK = 53;
export const P9_TGETLOCK = 54;
export const P9_RGETLOCK = 55;
export const P9_TLINK = 70;
export const P9_RLINK = 71;
export const P9_TMKDIR = 72;
export const P9_RMKDIR = 73;
export const P9_TRENAMEAT = 74;
export const P9_RRENAMEAT = 75;
export const P9_TUNLINKAT = 76;
export const P9_RUNLINKAT = 77;
export const P9_TVERSION = 100;
export const P9_RVERSION = 101;
export const P9_TAUTH = 102;
export const P9_RAUTH = 103;
export const P9_TATTACH = 104;
export const P9_RATTACH = 105;

// --- 9P2000 (and 9P2000.u), served only to be refused ---

/** Never sent, in either dialect. */
export const P9_TERROR = 106;
/** The 9P2000 error reply — a string, where 9P2000.L uses `Rlerror`'s errno. */
export const P9_RERROR = 107;
export const P9_TFLUSH = 108;
export const P9_RFLUSH = 109;
export const P9_TWALK = 110;
export const P9_RWALK = 111;
export const P9_TOPEN = 112;
export const P9_ROPEN = 113;
export const P9_TCREATE = 114;
export const P9_RCREATE = 115;
export const P9_TREAD = 116;
export const P9_RREAD = 117;
export const P9_TWRITE = 118;
export const P9_RWRITE = 119;
export const P9_TCLUNK = 120;
export const P9_RCLUNK = 121;
export const P9_TREMOVE = 122;
export const P9_RREMOVE = 123;
export const P9_TSTAT = 124;
export const P9_RSTAT = 125;
export const P9_TWSTAT = 126;
export const P9_RWSTAT = 127;

// `Tflush`, `Twalk`, `Tread`, `Twrite`, `Tclunk` and `Tremove` are in that
// block because their numbers predate 9P2000.L, not because they are legacy:
// the .L dialect keeps them unchanged and this server answers all six. The
// four it refuses are `Topen`, `Tcreate`, `Tstat` and `Twstat`, replaced by
// `Tlopen`, `Tlcreate`, `Tgetattr` and `Tsetattr`.

/**
 * Human-readable message names, for logs, dispatch tables and errors.
 *
 * Written the way the protocol documentation spells them (`Tversion`, not
 * `P9_TVERSION`), because that is what a `tshark` dissector or a kernel trace
 * prints beside them.
 */
export const MESSAGE_NAMES: Readonly<Record<number, string>> = {
  [P9_TLERROR]: "Tlerror",
  [P9_RLERROR]: "Rlerror",
  [P9_TSTATFS]: "Tstatfs",
  [P9_RSTATFS]: "Rstatfs",
  [P9_TLOPEN]: "Tlopen",
  [P9_RLOPEN]: "Rlopen",
  [P9_TLCREATE]: "Tlcreate",
  [P9_RLCREATE]: "Rlcreate",
  [P9_TSYMLINK]: "Tsymlink",
  [P9_RSYMLINK]: "Rsymlink",
  [P9_TMKNOD]: "Tmknod",
  [P9_RMKNOD]: "Rmknod",
  [P9_TRENAME]: "Trename",
  [P9_RRENAME]: "Rrename",
  [P9_TREADLINK]: "Treadlink",
  [P9_RREADLINK]: "Rreadlink",
  [P9_TGETATTR]: "Tgetattr",
  [P9_RGETATTR]: "Rgetattr",
  [P9_TSETATTR]: "Tsetattr",
  [P9_RSETATTR]: "Rsetattr",
  [P9_TXATTRWALK]: "Txattrwalk",
  [P9_RXATTRWALK]: "Rxattrwalk",
  [P9_TXATTRCREATE]: "Txattrcreate",
  [P9_RXATTRCREATE]: "Rxattrcreate",
  [P9_TREADDIR]: "Treaddir",
  [P9_RREADDIR]: "Rreaddir",
  [P9_TFSYNC]: "Tfsync",
  [P9_RFSYNC]: "Rfsync",
  [P9_TLOCK]: "Tlock",
  [P9_RLOCK]: "Rlock",
  [P9_TGETLOCK]: "Tgetlock",
  [P9_RGETLOCK]: "Rgetlock",
  [P9_TLINK]: "Tlink",
  [P9_RLINK]: "Rlink",
  [P9_TMKDIR]: "Tmkdir",
  [P9_RMKDIR]: "Rmkdir",
  [P9_TRENAMEAT]: "Trenameat",
  [P9_RRENAMEAT]: "Rrenameat",
  [P9_TUNLINKAT]: "Tunlinkat",
  [P9_RUNLINKAT]: "Runlinkat",
  [P9_TVERSION]: "Tversion",
  [P9_RVERSION]: "Rversion",
  [P9_TAUTH]: "Tauth",
  [P9_RAUTH]: "Rauth",
  [P9_TATTACH]: "Tattach",
  [P9_RATTACH]: "Rattach",
  [P9_TERROR]: "Terror",
  [P9_RERROR]: "Rerror",
  [P9_TFLUSH]: "Tflush",
  [P9_RFLUSH]: "Rflush",
  [P9_TWALK]: "Twalk",
  [P9_RWALK]: "Rwalk",
  [P9_TOPEN]: "Topen",
  [P9_ROPEN]: "Ropen",
  [P9_TCREATE]: "Tcreate",
  [P9_RCREATE]: "Rcreate",
  [P9_TREAD]: "Tread",
  [P9_RREAD]: "Rread",
  [P9_TWRITE]: "Twrite",
  [P9_RWRITE]: "Rwrite",
  [P9_TCLUNK]: "Tclunk",
  [P9_RCLUNK]: "Rclunk",
  [P9_TREMOVE]: "Tremove",
  [P9_RREMOVE]: "Rremove",
  [P9_TSTAT]: "Tstat",
  [P9_RSTAT]: "Rstat",
  [P9_TWSTAT]: "Twstat",
  [P9_RWSTAT]: "Rwstat",
};

/** `MESSAGE_NAMES[type]`, or `UNKNOWN(<type>)`. */
export function messageName(type: number): string {
  return MESSAGE_NAMES[type] ?? `UNKNOWN(${type})`;
}

// ---------------------------------------------------------------------------
// getattr request mask / result mask (P9_STATS_* in the header)
//
// `Tgetattr.request_mask` and `Rgetattr.valid` are both 64-bit, hence `bigint`:
// the wire field has room for bits nobody has defined yet, and a `number` would
// be a lie about the width even while the defined bits fit in it.
// ---------------------------------------------------------------------------

export const P9_GETATTR_MODE = 0x00_00_00_01n;
export const P9_GETATTR_NLINK = 0x00_00_00_02n;
export const P9_GETATTR_UID = 0x00_00_00_04n;
export const P9_GETATTR_GID = 0x00_00_00_08n;
export const P9_GETATTR_RDEV = 0x00_00_00_10n;
export const P9_GETATTR_ATIME = 0x00_00_00_20n;
export const P9_GETATTR_MTIME = 0x00_00_00_40n;
export const P9_GETATTR_CTIME = 0x00_00_00_80n;
export const P9_GETATTR_INO = 0x00_00_01_00n;
export const P9_GETATTR_SIZE = 0x00_00_02_00n;
export const P9_GETATTR_BLOCKS = 0x00_00_04_00n;
export const P9_GETATTR_BTIME = 0x00_00_08_00n;
export const P9_GETATTR_GEN = 0x00_00_10_00n;
export const P9_GETATTR_DATA_VERSION = 0x00_00_20_00n;

/** Everything up to and including `BLOCKS` — what a `stat(2)` needs. */
export const P9_GETATTR_BASIC = 0x00_00_07_ffn;
/** Every defined bit, `BTIME`/`GEN`/`DATA_VERSION` included. */
export const P9_GETATTR_ALL = 0x00_00_3f_ffn;

// ---------------------------------------------------------------------------
// setattr valid mask (P9_ATTR_* in `fs/9p/vfs_inode_dotl.c`)
//
// `Tsetattr.valid` is 32-bit, so these stay `number`s. The set mirrors Linux's
// own `ATTR_*` (`include/linux/fs.h`) one for one, which is what the kernel's
// `v9fs_mapped_iattr_valid()` translation table says.
// ---------------------------------------------------------------------------

export const P9_SETATTR_MODE = 1 << 0;
export const P9_SETATTR_UID = 1 << 1;
export const P9_SETATTR_GID = 1 << 2;
export const P9_SETATTR_SIZE = 1 << 3;
/** Set atime — to *now* unless `ATIME_SET` says otherwise. */
export const P9_SETATTR_ATIME = 1 << 4;
/** Set mtime — to *now* unless `MTIME_SET` says otherwise. */
export const P9_SETATTR_MTIME = 1 << 5;
export const P9_SETATTR_CTIME = 1 << 6;
/** The atime in the message is the value to use, rather than "now". */
export const P9_SETATTR_ATIME_SET = 1 << 7;
/** The mtime in the message is the value to use, rather than "now". */
export const P9_SETATTR_MTIME_SET = 1 << 8;

// ---------------------------------------------------------------------------
// Locks (Tlock / Tgetlock)
// ---------------------------------------------------------------------------

/** `p9_flock.type` / `p9_getlock.type`, the `F_*LCK` values by another name. */
export const P9_LOCK_TYPE_RDLCK = 0;
export const P9_LOCK_TYPE_WRLCK = 1;
export const P9_LOCK_TYPE_UNLCK = 2;

/** `Rlock.status`. */
export const P9_LOCK_SUCCESS = 0;
export const P9_LOCK_BLOCKED = 1;
export const P9_LOCK_ERROR = 2;
export const P9_LOCK_GRACE = 3;

/** `p9_flock.flags`. */
export const P9_LOCK_FLAGS_BLOCK = 1;
export const P9_LOCK_FLAGS_RECLAIM = 2;

// ---------------------------------------------------------------------------
// qid types (enum p9_qid_t)
//
// A qid's type is the top byte of the 9P permission word, which is why these
// are bits rather than an enumeration — but for a .L server only `QTDIR`,
// `QTSYMLINK` and `QTFILE` ever get set.
// ---------------------------------------------------------------------------

export const P9_QTDIR = 0x80;
export const P9_QTAPPEND = 0x40;
export const P9_QTEXCL = 0x20;
export const P9_QTMOUNT = 0x10;
export const P9_QTAUTH = 0x08;
export const P9_QTTMP = 0x04;
export const P9_QTSYMLINK = 0x02;
export const P9_QTLINK = 0x01;
/** Not a bit: a plain file is the absence of every other type. */
export const P9_QTFILE = 0x00;

// ---------------------------------------------------------------------------
// Magic numbers and sizes
// ---------------------------------------------------------------------------

/** `Tversion`'s tag: the one exchange that has no transaction to belong to. */
export const P9_NOTAG = 0xff_ff;

/** "No fid" — `Tattach`'s `afid` when there is no auth file, and `Tauth`'s. */
export const P9_NOFID = 0xff_ff_ff_ff;

/** Most path elements one `Twalk` may carry; a longer path takes several. */
export const P9_MAXWELEM = 16;

/** Every message begins `size[4] type[1] tag[2]`. */
export const P9_HDRSZ = 7;

/** Room the header of a `Twrite`/`Rread` needs on top of its payload. */
export const P9_IOHDRSZ = 24;

/** Room the header of an `Rreaddir` needs on top of its entries. */
export const P9_READDIRHDRSZ = 24;

/**
 * `Tunlinkat.flags` — the `AT_REMOVEDIR` of `unlinkat(2)`, and the only flag
 * the message carries. Without it the request is an `unlink`, with it an
 * `rmdir`.
 */
export const P9_DOTL_AT_REMOVEDIR = 0x200;

// ---------------------------------------------------------------------------
// Values the wire carries that `9p.h` does not hold
//
// Four more transcriptions, each from the file that owns it rather than from
// the header the rest of this module comes from. They are here and not in the
// session because they are facts about the protocol — what a version string
// looks like, what a client refuses — and not policy the session invents.
// ---------------------------------------------------------------------------

/**
 * The dialect string, **exactly as it appears on the wire**.
 *
 * From `p9_client_version()` in `net/9p/client.c` (v6.12), which sends
 * `"9P2000.L"` and matches the reply with `strncmp(version, "9P2000.L", 8)`.
 *
 * Note the capital `P`: the *mount option* is spelled `version=9p2000.L`
 * (`get_protocol_version()` in `fs/9p/v9fs.c` accepts `9p2000.L` and
 * `9p2000.l`), and the plan and docs use that spelling, but nothing with a
 * lowercase `p` is ever put on a socket. The comparison here is exact and
 * case-sensitive because there is exactly one string the kernel sends.
 */
export const P9_VERSION_DOTL = "9P2000.L";

/**
 * The reply that means "I do not speak that" — from the 9P2000 specification
 * (`version(5)`), and the string `p9_client_version()` falls off the end of its
 * comparison chain into (`-EREMOTEIO`). It is a normal `Rversion`, never an
 * error reply.
 */
export const P9_VERSION_UNKNOWN = "unknown";

/**
 * The smallest `msize` the Linux client will work with.
 *
 * `net/9p/client.c` (v6.12) enforces `4096` in three places — `parse_opts()`,
 * `p9_client_create()` and, the one that binds a *server*,
 * `p9_client_version()`: "server returned a msize < 4096". So a negotiation
 * that lands below this is one the client will refuse whatever we say, which is
 * why the session refuses it first.
 */
export const P9_MIN_MSIZE = 4096;

/**
 * `f_type` for a 9P mount — `V9FS_MAGIC` in `include/uapi/linux/magic.h`.
 *
 * `v9fs_statfs()` copies `Rstatfs.type` into `statfs(2)`'s `f_type` verbatim, so
 * this is what userspace sees for a driver with no magic number of its own.
 */
export const V9FS_MAGIC = 0x01_02_19_97;
