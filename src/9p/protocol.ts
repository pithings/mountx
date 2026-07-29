/**
 * 9P2000.L message codecs and framing — every message, both directions.
 *
 * Each message is encoded *and* decoded, the same symmetry `src/nfs/protocol.ts`
 * and `src/fuse/protocol.ts` carry: the Tier-1 JS test client is built from the
 * T-encoders and R-decoders here, the session from their inverses, so the whole
 * server can be driven over a socket with no kernel, no mount and no root.
 *
 * **Wire authority.** Field order and width come from the Linux kernel's
 * `net/9p/client.c` at tag **v6.12** — every `p9_client_rpc()` call there names
 * its message's exact layout as a format string (`"dqd"` is `u32 u64 u32`,
 * `"s"` a `u16`-counted string, `"Q"` a qid, and so on; the letters are decoded
 * in `net/9p/protocol.c`'s `p9pdu_vreadf`/`p9pdu_vwritef`). diod's `protocol.md`
 * is the prose reference and is quoted above each codec, because a struct
 * diagram reads better than a format string. Where the two disagree the kernel
 * wins — it is the only client this server has. Numbers come from
 * `./constants.ts` and are never re-derived here.
 *
 * The one message the v6.12 client never sends is `Tauth`: `p9_client_attach()`
 * always passes `P9_NOFID` and there is no `p9_client_auth()`, so `Tauth`'s
 * layout below is diod's alone. Everything else was cross-checked and no
 * disagreement was found.
 *
 * **Naming.** Types are spelled the way the protocol spells them (`Tlopen`,
 * `Rgetattr`), for the same reason `src/nfs/protocol.ts` uses `Read3args` — a
 * packet trace, the kernel's debug output and this file should all say the same
 * word. The framing layer, which has no protocol name of its own, takes the
 * repository's `P9` prefix.
 *
 * **Framing.** A message is `size[4] type[1] tag[2]` then a body, with `size`
 * counting *itself* — so a bodyless message is 7 bytes and `size` is 7. The
 * kernel checks exactly that (`p9_parse_header()` rejects `r_size < 7` and any
 * `r_size` that disagrees with the bytes it received), and so does
 * {@link decodeMessage}.
 *
 * Conventions are `wire.ts`'s: little-endian, unaligned, 64-bit fields as
 * `bigint`, decoding total — only {@link P9Error} escapes a decoder — and every
 * decoder copies the bytes it retains.
 */

import {
  P9_HDRSZ,
  P9_MAXWELEM,
  P9_RCLUNK,
  P9_RFLUSH,
  P9_RFSYNC,
  P9_RLINK,
  P9_RREMOVE,
  P9_RRENAME,
  P9_RRENAMEAT,
  P9_RSETATTR,
  P9_RUNLINKAT,
  P9_RXATTRCREATE,
  messageName,
} from "./constants.ts";
import {
  P9_MAX_ITEM,
  P9_MAX_STRING,
  P9_QID_SIZE,
  P9Error,
  P9Reader,
  P9Writer,
  isP9Error,
  stringByteLength,
  type P9Qid,
} from "./wire.ts";

// ---------------------------------------------------------------------------
// framing
// ---------------------------------------------------------------------------

/**
 * A blunt ceiling on one frame, used until `Tversion` settles the real one.
 *
 * This is **not** a transcribed constant — the protocol has no maximum, only
 * whatever `msize` the two ends agree on. It exists because a reassembler reads
 * a 32-bit length field off a socket before anybody has negotiated anything,
 * and `0xffffffff` must not become an allocation. A session lowers it to the
 * negotiated `msize` (see {@link P9FrameAssembler.limit}) as soon as it has one.
 */
export const P9_DEFAULT_MAX_FRAME = 1024 * 1024;

/** `size[4] type[1] tag[2]` — the header every message begins with. */
export interface P9Header {
  /** Total frame length **including these four bytes**. */
  size: number;
  /** `P9_T*`/`P9_R*`. */
  type: number;
  /** Transaction id; `P9_NOTAG` for `Tversion`. */
  tag: number;
}

/** One decoded frame: its header, and a reader positioned at the body. */
export interface P9Message extends P9Header {
  /** Reader over the frame, already past the 7-byte header. */
  body: P9Reader;
}

/** Read `size[4] type[1] tag[2]`. Does not validate `size` against anything. */
export function readHeader(reader: P9Reader): P9Header {
  return {
    size: reader.u32("size"),
    type: reader.u8("type"),
    tag: reader.u16("tag"),
  };
}

/**
 * Write a header with `size` already known.
 *
 * Callers that do not know the size yet write a placeholder and backfill it —
 * which is what {@link encodeMessage} does, and the reason `P9Writer` has
 * `patchU32`.
 */
export function writeHeader(writer: P9Writer, header: P9Header): void {
  writer.u32(header.size);
  writer.u8(header.type);
  writer.u16(header.tag);
}

/**
 * Frame one message: header, body, and `size` backfilled from what the body
 * turned out to be.
 *
 * Omitting `write` produces a bodyless message — `Rclunk` and the eight other
 * replies in {@link EMPTY_BODY} — which is a 7-byte frame, not an empty one.
 */
export function encodeMessage(
  type: number,
  tag: number,
  write?: (writer: P9Writer) => void,
  capacity = 128,
): Uint8Array {
  const writer = new P9Writer(capacity);
  writeHeader(writer, { size: 0, type, tag });
  write?.(writer);
  const size = writer.length;
  if (size > 0xff_ff_ff_ff) {
    throw new P9Error(`${messageName(type)} is ${size} bytes, over the 32-bit size field`);
  }
  writer.patchU32(0, size);
  return writer.bytes();
}

/**
 * Split one complete frame into its header and body.
 *
 * `bytes` must be exactly one frame: the `size` field is checked against the
 * length delivered, the way `p9_parse_header()` checks it, because a `size` that
 * disagrees with the bytes present is the first symptom of a desynchronized
 * stream and answering it as if it were fine turns one bad frame into every
 * later one.
 */
export function decodeMessage(bytes: Uint8Array): P9Message {
  const reader = new P9Reader(bytes);
  const header = readHeader(reader);
  if (header.size !== bytes.byteLength) {
    throw new P9Error(
      `${messageName(header.type)} says ${header.size} bytes but the frame is ${bytes.byteLength}`,
    );
  }
  return { ...header, body: reader };
}

/** Decode a frame and its body in one call, insisting the body is fully consumed. */
export function decodeMessageAs<T>(
  bytes: Uint8Array,
  read: (reader: P9Reader) => T,
): P9Header & { value: T } {
  const { body, ...header } = decodeMessage(bytes);
  const value = read(body);
  body.end(messageName(header.type));
  return { ...header, value };
}

/**
 * The replies whose body is empty — `size[4] type[1] tag[2]` and nothing else.
 *
 * Listed rather than given nine identical no-op codec pairs, so that a reader
 * asking "where is `writeRclunk`?" finds the answer instead of a function that
 * does nothing.
 */
export const EMPTY_BODY: ReadonlySet<number> = new Set([
  P9_RFLUSH,
  P9_RCLUNK,
  P9_RREMOVE,
  P9_RRENAME,
  P9_RSETATTR,
  P9_RXATTRCREATE,
  P9_RFSYNC,
  P9_RLINK,
  P9_RRENAMEAT,
  P9_RUNLINKAT,
]);

/** Assert a bodyless message really is bodyless. */
export function readEmptyBody(reader: P9Reader, what = "message"): void {
  reader.end(what);
}

// ---------------------------------------------------------------------------
// shared field groups
// ---------------------------------------------------------------------------

/**
 * A timestamp as 9P2000.L carries one: `sec[8] nsec[8]`, both unsigned.
 *
 * Nanosecond resolution is one of the three differences diod's `protocol.md`
 * lists between `Rgetattr` and `struct stat`, and the pair is *two* 64-bit
 * fields rather than the packed `timespec` a C programmer expects.
 */
export interface P9Time {
  sec: bigint;
  nsec: bigint;
}

export function writeTime(writer: P9Writer, time: P9Time): void {
  writer.u64(time.sec);
  writer.u64(time.nsec);
}

export function readTime(reader: P9Reader, what = "time"): P9Time {
  return { sec: reader.u64(`${what}_sec`), nsec: reader.u64(`${what}_nsec`) };
}

/**
 * Bound `nwname[2]` / `nwqid[2]`.
 *
 * `P9_MAXWELEM` is a real protocol limit rather than a defensive one — the
 * client splits a longer path into several walks — so refusing a larger count
 * is both correct and, incidentally, what keeps a 65535-element array out of a
 * decoder.
 */
function checkElementCount(count: number, what: string): number {
  if (count > P9_MAXWELEM) {
    throw new P9Error(`${what} is ${count}, over the ${P9_MAXWELEM}-element limit`);
  }
  return count;
}

function readElementCount(reader: P9Reader, what: string): number {
  return checkElementCount(reader.u16(what), what);
}

// ---------------------------------------------------------------------------
// version (Tversion "ds" / Rversion "ds")
//
//   size[4] Tversion tag[2] msize[4] version[s]
//   size[4] Rversion tag[2] msize[4] version[s]
// ---------------------------------------------------------------------------

/**
 * `Tversion`/`Rversion` — the one exchange with no transaction, tagged
 * `P9_NOTAG`.
 *
 * The reply's `msize` is the smaller of the two proposals and the reply's
 * `version` is `"9P2000.L"` or the literal `"unknown"`. The v6.12 client also
 * refuses any `msize` under 4096 outright (`p9_client_version()`), which is a
 * server-side policy note rather than a codec one.
 */
export interface Tversion {
  msize: number;
  version: string;
}

/** Same shape as {@link Tversion}; kept distinct so a signature says which way. */
export type Rversion = Tversion;

export function writeTversion(writer: P9Writer, message: Tversion): void {
  writer.u32(message.msize);
  writer.string(message.version);
}

export function readTversion(reader: P9Reader): Tversion {
  return { msize: reader.u32("msize"), version: reader.string(undefined, "version") };
}

export const writeRversion = writeTversion;
export const readRversion = readTversion;

// ---------------------------------------------------------------------------
// auth (diod only — see the module docs)
//
//   size[4] Tauth tag[2] afid[4] uname[s] aname[s] n_uname[4]
//   size[4] Rauth tag[2] aqid[13]
// ---------------------------------------------------------------------------

/**
 * `Tauth` — begin an authentication handshake.
 *
 * The layout is diod's: the v6.12 kernel client has no `p9_client_auth()` at
 * all and always attaches with `afid = P9_NOFID`, so nothing this server talks
 * to will send one. It is decoded anyway because a message a server cannot read
 * is a message it cannot refuse politely.
 */
export interface Tauth {
  afid: number;
  uname: string;
  aname: string;
  /** Numeric uid, preferred over `uname` unless it is `~0`. */
  nUname: number;
}

export interface Rauth {
  aqid: P9Qid;
}

export function writeTauth(writer: P9Writer, message: Tauth): void {
  writer.u32(message.afid);
  writer.string(message.uname);
  writer.string(message.aname);
  writer.u32(message.nUname);
}

export function readTauth(reader: P9Reader): Tauth {
  return {
    afid: reader.u32("afid"),
    uname: reader.string(undefined, "uname"),
    aname: reader.string(undefined, "aname"),
    nUname: reader.u32("n_uname"),
  };
}

export function writeRauth(writer: P9Writer, message: Rauth): void {
  writer.qid(message.aqid);
}

export function readRauth(reader: P9Reader): Rauth {
  return { aqid: reader.qid("aqid") };
}

// ---------------------------------------------------------------------------
// attach (Tattach "ddss?u" / Rattach "Q")
//
//   size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s] n_uname[4]
//   size[4] Rattach tag[2] qid[13]
// ---------------------------------------------------------------------------

/**
 * `Tattach` — introduce a user and bind `fid` to the root of `aname`.
 *
 * The kernel's format is `"ddss?u"`: the `?` means "only in 9P2000.u and
 * 9P2000.L", and since `9p2000.L` is the only dialect served, `n_uname` is
 * always present. In v9fs's default `access=user` mode one of these arrives per
 * user that touches the mount, which is why `nUname` matters and `uname` mostly
 * does not.
 */
export interface Tattach {
  fid: number;
  /** `P9_NOFID` when there was no `Tauth`, which is always, for Linux. */
  afid: number;
  uname: string;
  aname: string;
  nUname: number;
}

export interface Rattach {
  qid: P9Qid;
}

export function writeTattach(writer: P9Writer, message: Tattach): void {
  writer.u32(message.fid);
  writer.u32(message.afid);
  writer.string(message.uname);
  writer.string(message.aname);
  writer.u32(message.nUname);
}

export function readTattach(reader: P9Reader): Tattach {
  return {
    fid: reader.u32("fid"),
    afid: reader.u32("afid"),
    uname: reader.string(undefined, "uname"),
    aname: reader.string(undefined, "aname"),
    nUname: reader.u32("n_uname"),
  };
}

export function writeRattach(writer: P9Writer, message: Rattach): void {
  writer.qid(message.qid);
}

export function readRattach(reader: P9Reader): Rattach {
  return { qid: reader.qid("qid") };
}

// ---------------------------------------------------------------------------
// lerror (Rlerror "d")
//
//   size[4] Rlerror tag[2] ecode[4]
// ---------------------------------------------------------------------------

/**
 * `Rlerror` — the failure reply for every 9P2000.L request. There is no
 * `Tlerror`.
 *
 * `ecode` is a **positive Linux errno**, not a protocol-private status: this is
 * the one place in the three transports where `src/errors.ts`'s table goes on
 * the wire unchanged, with no mapping layer. `errnoOf()` from `src/errors.ts`
 * produces the field, unknown errors included (they become `EIO`).
 */
export interface Rlerror {
  ecode: number;
}

export function writeRlerror(writer: P9Writer, message: Rlerror): void {
  writer.u32(message.ecode);
}

export function readRlerror(reader: P9Reader): Rlerror {
  return { ecode: reader.u32("ecode") };
}

// ---------------------------------------------------------------------------
// flush (Tflush "w")
//
//   size[4] Tflush tag[2] oldtag[2]
//   size[4] Rflush tag[2]
// ---------------------------------------------------------------------------

/**
 * `Tflush` — abandon the in-flight request tagged `oldtag`.
 *
 * The reply is bodyless and carries the ordering rule instead of any data: it
 * may only be sent once `oldtag` has itself been answered or abandoned, because
 * the client frees the tag the moment `Rflush` arrives.
 */
export interface Tflush {
  oldtag: number;
}

export function writeTflush(writer: P9Writer, message: Tflush): void {
  writer.u16(message.oldtag);
}

export function readTflush(reader: P9Reader): Tflush {
  return { oldtag: reader.u16("oldtag") };
}

// ---------------------------------------------------------------------------
// walk (Twalk "ddT" / Rwalk "R")
//
//   size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
//   size[4] Rwalk tag[2] nwqid[2] nwqid*(wqid[13])
// ---------------------------------------------------------------------------

/**
 * `Twalk` — descend from `fid` through `wnames`, binding the result to `newfid`.
 *
 * `wnames` empty is a clone, which is how v9fs gets a second fid on a file it
 * is about to open. At most {@link P9_MAXWELEM} names fit in one walk; a longer
 * path is several walks, and the client does that splitting itself.
 */
export interface Twalk {
  fid: number;
  newfid: number;
  wnames: string[];
}

/**
 * `Rwalk` — one qid per name successfully walked.
 *
 * A short `wqids` is not an error: it means the walk stopped part-way, and the
 * client learns how far it got from the count. Only a walk that fails on its
 * *first* element answers `Rlerror` instead.
 */
export interface Rwalk {
  wqids: P9Qid[];
}

export function writeTwalk(writer: P9Writer, message: Twalk): void {
  writer.u32(message.fid);
  writer.u32(message.newfid);
  writer.u16(checkElementCount(message.wnames.length, "nwname"));
  for (const name of message.wnames) {
    writer.string(name);
  }
}

export function readTwalk(reader: P9Reader): Twalk {
  const fid = reader.u32("fid");
  const newfid = reader.u32("newfid");
  const count = readElementCount(reader, "nwname");
  const wnames: string[] = [];
  for (let index = 0; index < count; index++) {
    wnames.push(reader.string(undefined, `wname[${index}]`));
  }
  return { fid, newfid, wnames };
}

export function writeRwalk(writer: P9Writer, message: Rwalk): void {
  writer.u16(checkElementCount(message.wqids.length, "nwqid"));
  for (const qid of message.wqids) {
    writer.qid(qid);
  }
}

export function readRwalk(reader: P9Reader): Rwalk {
  const count = readElementCount(reader, "nwqid");
  const wqids: P9Qid[] = [];
  for (let index = 0; index < count; index++) {
    wqids.push(reader.qid(`wqid[${index}]`));
  }
  return { wqids };
}

// ---------------------------------------------------------------------------
// read / write (Tread "dqd", Rread "D", Twrite "dqV", Rwrite "d")
//
//   size[4] Tread tag[2] fid[4] offset[8] count[4]
//   size[4] Rread tag[2] count[4] data[count]
//   size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]
//   size[4] Rwrite tag[2] count[4]
// ---------------------------------------------------------------------------

/**
 * `Tread` — read `count` bytes at `offset`.
 *
 * Under 9P2000.L this is never used on a directory: that is `Treaddir`'s job,
 * and a `Tread` on a directory is an error rather than a stream of `struct
 * dirent`.
 */
export interface Tread {
  fid: number;
  offset: bigint;
  count: number;
}

/** `Rread` — `count` is `data.byteLength`, so it is not carried separately. */
export interface Rread {
  data: Uint8Array;
}

export function writeTread(writer: P9Writer, message: Tread): void {
  writer.u32(message.fid);
  writer.u64(message.offset);
  writer.u32(message.count);
}

export function readTread(reader: P9Reader): Tread {
  return {
    fid: reader.u32("fid"),
    offset: reader.u64("offset"),
    count: reader.u32("count"),
  };
}

export function writeRread(writer: P9Writer, message: Rread): void {
  writer.blob(message.data);
}

/** Decodes the payload as a **copy** — see `wire.ts` on `Buffer.prototype.slice`. */
export function readRread(reader: P9Reader, max = P9_MAX_ITEM): Rread {
  return { data: reader.blob(max, "read data") };
}

export interface Twrite {
  fid: number;
  offset: bigint;
  data: Uint8Array;
}

export interface Rwrite {
  /** Bytes actually written, which may be fewer than were offered. */
  count: number;
}

export function writeTwrite(writer: P9Writer, message: Twrite): void {
  writer.u32(message.fid);
  writer.u64(message.offset);
  writer.blob(message.data);
}

/** Decodes the payload as a **copy**, so a session may hold it across an await. */
export function readTwrite(reader: P9Reader, max = P9_MAX_ITEM): Twrite {
  return {
    fid: reader.u32("fid"),
    offset: reader.u64("offset"),
    data: reader.blob(max, "write data"),
  };
}

export function writeRwrite(writer: P9Writer, message: Rwrite): void {
  writer.u32(message.count);
}

export function readRwrite(reader: P9Reader): Rwrite {
  return { count: reader.u32("count") };
}

// ---------------------------------------------------------------------------
// clunk / remove (both "d", both answered bodyless)
//
//   size[4] Tclunk tag[2] fid[4]        size[4] Rclunk tag[2]
//   size[4] Tremove tag[2] fid[4]       size[4] Rremove tag[2]
// ---------------------------------------------------------------------------

/**
 * A request whose whole body is one fid: `Tclunk`, `Tremove`, `Tstatfs` and
 * `Treadlink`.
 *
 * One shape rather than four identical ones — this is the only place 9P repeats
 * a struct exactly, and naming it keeps four codec pairs from being copies.
 */
export interface FidRequest {
  fid: number;
}

export function writeFidRequest(writer: P9Writer, message: FidRequest): void {
  writer.u32(message.fid);
}

export function readFidRequest(reader: P9Reader): FidRequest {
  return { fid: reader.u32("fid") };
}

export const writeTclunk = writeFidRequest;
export const readTclunk = readFidRequest;
export const writeTremove = writeFidRequest;
export const readTremove = readFidRequest;

// ---------------------------------------------------------------------------
// statfs (Tstatfs "d" / Rstatfs "ddqqqqqqd")
//
//   size[4] Tstatfs tag[2] fid[4]
//   size[4] Rstatfs tag[2] type[4] bsize[4] blocks[8] bfree[8] bavail[8]
//                          files[8] ffree[8] fsid[8] namelen[4]
// ---------------------------------------------------------------------------

/** `Rstatfs` — `statvfs(3)` for the filesystem containing the fid. */
export interface Rstatfs {
  /** Filesystem magic (`f_type`); v9fs reports it to `statfs(2)` verbatim. */
  type: number;
  bsize: number;
  blocks: bigint;
  bfree: bigint;
  bavail: bigint;
  files: bigint;
  ffree: bigint;
  fsid: bigint;
  namelen: number;
}

export const writeTstatfs = writeFidRequest;
export const readTstatfs = readFidRequest;

export function writeRstatfs(writer: P9Writer, message: Rstatfs): void {
  writer.u32(message.type);
  writer.u32(message.bsize);
  writer.u64(message.blocks);
  writer.u64(message.bfree);
  writer.u64(message.bavail);
  writer.u64(message.files);
  writer.u64(message.ffree);
  writer.u64(message.fsid);
  writer.u32(message.namelen);
}

export function readRstatfs(reader: P9Reader): Rstatfs {
  return {
    type: reader.u32("type"),
    bsize: reader.u32("bsize"),
    blocks: reader.u64("blocks"),
    bfree: reader.u64("bfree"),
    bavail: reader.u64("bavail"),
    files: reader.u64("files"),
    ffree: reader.u64("ffree"),
    fsid: reader.u64("fsid"),
    namelen: reader.u32("namelen"),
  };
}

// ---------------------------------------------------------------------------
// lopen / lcreate (Tlopen "dd", Rlopen "Qd", Tlcreate "dsddg", Rlcreate "Qd")
//
//   size[4] Tlopen tag[2] fid[4] flags[4]
//   size[4] Rlopen tag[2] qid[13] iounit[4]
//   size[4] Tlcreate tag[2] fid[4] name[s] flags[4] mode[4] gid[4]
//   size[4] Rlcreate tag[2] qid[13] iounit[4]
// ---------------------------------------------------------------------------

/**
 * `Tlopen` — prepare an already-walked fid for I/O.
 *
 * `flags` is the **Linux kernel's** `O_*` namespace, exactly like FUSE's
 * `fuse_open_in.flags`; a driver resolves its flags against the host, so the
 * crossing is `src/fuse/flags.ts`'s job and not the codec's.
 */
export interface Tlopen {
  fid: number;
  flags: number;
}

/**
 * `Rlopen`/`Rlcreate` — the opened file's qid and its preferred I/O size.
 *
 * `iounit` of `0` means "no preference", which is what diod's sample session
 * shows for a directory, and leaves the client bounded by `msize` alone.
 */
export interface Rlopen {
  qid: P9Qid;
  iounit: number;
}

export function writeTlopen(writer: P9Writer, message: Tlopen): void {
  writer.u32(message.fid);
  writer.u32(message.flags);
}

export function readTlopen(reader: P9Reader): Tlopen {
  return { fid: reader.u32("fid"), flags: reader.u32("flags") };
}

export function writeRlopen(writer: P9Writer, message: Rlopen): void {
  writer.qid(message.qid);
  writer.u32(message.iounit);
}

export function readRlopen(reader: P9Reader): Rlopen {
  return { qid: reader.qid("qid"), iounit: reader.u32("iounit") };
}

/**
 * `Tlcreate` — create a regular file in the directory `fid` **and open it**.
 *
 * `fid` is the parent going in and the new file coming out, which is why v9fs
 * always clones a fid before creating: the parent's fid would otherwise be
 * spent. `gid` is the caller's effective group, supplied because the server
 * cannot ask.
 */
export interface Tlcreate {
  /** The parent directory on the way in; the created file on the way out. */
  fid: number;
  name: string;
  /** Linux `open(2)` flags. */
  flags: number;
  /** Linux `creat(2)` mode bits. */
  mode: number;
  gid: number;
}

/** Same shape as {@link Rlopen}. */
export type Rlcreate = Rlopen;

export function writeTlcreate(writer: P9Writer, message: Tlcreate): void {
  writer.u32(message.fid);
  writer.string(message.name);
  writer.u32(message.flags);
  writer.u32(message.mode);
  writer.u32(message.gid);
}

export function readTlcreate(reader: P9Reader): Tlcreate {
  return {
    fid: reader.u32("fid"),
    name: reader.string(undefined, "name"),
    flags: reader.u32("flags"),
    mode: reader.u32("mode"),
    gid: reader.u32("gid"),
  };
}

export const writeRlcreate = writeRlopen;
export const readRlcreate = readRlopen;

// ---------------------------------------------------------------------------
// symlink / mknod / mkdir (Tsymlink "dssg", Tmknod "dsdddg", Tmkdir "dsdg")
//
//   size[4] Tsymlink tag[2] fid[4] name[s] symtgt[s] gid[4]
//   size[4] Rsymlink tag[2] qid[13]
//   size[4] Tmknod tag[2] dfid[4] name[s] mode[4] major[4] minor[4] gid[4]
//   size[4] Rmknod tag[2] qid[13]
//   size[4] Tmkdir tag[2] dfid[4] name[s] mode[4] gid[4]
//   size[4] Rmkdir tag[2] qid[13]
// ---------------------------------------------------------------------------

/**
 * A reply that is nothing but the created object's qid: `Rsymlink`, `Rmknod`
 * and `Rmkdir`. (`Rattach` has the same shape but a different meaning, so it
 * keeps its own name.)
 */
export interface QidReply {
  qid: P9Qid;
}

export function writeQidReply(writer: P9Writer, message: QidReply): void {
  writer.qid(message.qid);
}

export function readQidReply(reader: P9Reader): QidReply {
  return { qid: reader.qid("qid") };
}

/** `Tsymlink` — create `name` in directory `dfid`, pointing at `symtgt`. */
export interface Tsymlink {
  dfid: number;
  name: string;
  /** The link's contents; never resolved by the server. */
  symtgt: string;
  gid: number;
}

export function writeTsymlink(writer: P9Writer, message: Tsymlink): void {
  writer.u32(message.dfid);
  writer.string(message.name);
  writer.string(message.symtgt);
  writer.u32(message.gid);
}

export function readTsymlink(reader: P9Reader): Tsymlink {
  return {
    dfid: reader.u32("dfid"),
    name: reader.string(undefined, "name"),
    symtgt: reader.string(undefined, "symtgt"),
    gid: reader.u32("gid"),
  };
}

export const writeRsymlink = writeQidReply;
export const readRsymlink = readQidReply;

/**
 * `Tmknod` — create a device, fifo or socket node.
 *
 * `major`/`minor` are separate `u32` fields rather than one packed `rdev`,
 * which is the opposite of `Rgetattr`'s single `rdev[8]`.
 */
export interface Tmknod {
  dfid: number;
  name: string;
  /** Linux `mknod(2)` mode bits, node type included. */
  mode: number;
  major: number;
  minor: number;
  gid: number;
}

export function writeTmknod(writer: P9Writer, message: Tmknod): void {
  writer.u32(message.dfid);
  writer.string(message.name);
  writer.u32(message.mode);
  writer.u32(message.major);
  writer.u32(message.minor);
  writer.u32(message.gid);
}

export function readTmknod(reader: P9Reader): Tmknod {
  return {
    dfid: reader.u32("dfid"),
    name: reader.string(undefined, "name"),
    mode: reader.u32("mode"),
    major: reader.u32("major"),
    minor: reader.u32("minor"),
    gid: reader.u32("gid"),
  };
}

export const writeRmknod = writeQidReply;
export const readRmknod = readQidReply;

/** `Tmkdir` — create directory `name` under `dfid`. */
export interface Tmkdir {
  dfid: number;
  name: string;
  /** Linux `mkdir(2)` mode bits. */
  mode: number;
  gid: number;
}

export function writeTmkdir(writer: P9Writer, message: Tmkdir): void {
  writer.u32(message.dfid);
  writer.string(message.name);
  writer.u32(message.mode);
  writer.u32(message.gid);
}

export function readTmkdir(reader: P9Reader): Tmkdir {
  return {
    dfid: reader.u32("dfid"),
    name: reader.string(undefined, "name"),
    mode: reader.u32("mode"),
    gid: reader.u32("gid"),
  };
}

export const writeRmkdir = writeQidReply;
export const readRmkdir = readQidReply;

// ---------------------------------------------------------------------------
// rename / renameat / unlinkat / link
//
//   size[4] Trename tag[2] fid[4] dfid[4] name[s]
//   size[4] Trenameat tag[2] olddirfid[4] oldname[s] newdirfid[4] newname[s]
//   size[4] Tunlinkat tag[2] dirfid[4] name[s] flags[4]
//   size[4] Tlink tag[2] dfid[4] fid[4] name[s]
// ---------------------------------------------------------------------------

/**
 * `Trename` (kernel `"dds"`) — move the object `fid` names to `name` under
 * `dfid`.
 *
 * Superseded by `Trenameat`, which needs no fid on the object itself; a client
 * that gets `ENOTSUPP` for `Trenameat` falls back to this.
 */
export interface Trename {
  /** The object being renamed. */
  fid: number;
  /** Its new parent directory. */
  dfid: number;
  name: string;
}

export function writeTrename(writer: P9Writer, message: Trename): void {
  writer.u32(message.fid);
  writer.u32(message.dfid);
  writer.string(message.name);
}

export function readTrename(reader: P9Reader): Trename {
  return {
    fid: reader.u32("fid"),
    dfid: reader.u32("dfid"),
    name: reader.string(undefined, "name"),
  };
}

/** `Trenameat` (kernel `"dsds"`) — the `renameat(2)` shape, directories and names. */
export interface Trenameat {
  olddirfid: number;
  oldname: string;
  newdirfid: number;
  newname: string;
}

export function writeTrenameat(writer: P9Writer, message: Trenameat): void {
  writer.u32(message.olddirfid);
  writer.string(message.oldname);
  writer.u32(message.newdirfid);
  writer.string(message.newname);
}

export function readTrenameat(reader: P9Reader): Trenameat {
  return {
    olddirfid: reader.u32("olddirfid"),
    oldname: reader.string(undefined, "oldname"),
    newdirfid: reader.u32("newdirfid"),
    newname: reader.string(undefined, "newname"),
  };
}

/**
 * `Tunlinkat` (kernel `"dsd"`) — unlink `name` from `dirfid`.
 *
 * `flags` carries exactly one bit, `P9_DOTL_AT_REMOVEDIR`: without it this is
 * `unlink`, with it `rmdir`. The named fid, if the client holds one, is *not*
 * clunked.
 */
export interface Tunlinkat {
  dirfid: number;
  name: string;
  flags: number;
}

export function writeTunlinkat(writer: P9Writer, message: Tunlinkat): void {
  writer.u32(message.dirfid);
  writer.string(message.name);
  writer.u32(message.flags);
}

export function readTunlinkat(reader: P9Reader): Tunlinkat {
  return {
    dirfid: reader.u32("dirfid"),
    name: reader.string(undefined, "name"),
    flags: reader.u32("flags"),
  };
}

/**
 * `Tlink` (kernel `"dds"`) — hard-link the object `fid` names as `name` in
 * directory `dfid`.
 *
 * Note the order: the *directory* comes first here and second in `Trename`,
 * though both are the kernel's `"dds"`. That asymmetry is real in diod and in
 * `p9_client_link()`/`p9_client_rename()` alike, and since a swap round-trips
 * happily it is pinned by byte fixtures instead — `test/9p/golden.test.ts`
 * spells both messages out with the two fids given different values.
 */
export interface Tlink {
  dfid: number;
  fid: number;
  name: string;
}

export function writeTlink(writer: P9Writer, message: Tlink): void {
  writer.u32(message.dfid);
  writer.u32(message.fid);
  writer.string(message.name);
}

export function readTlink(reader: P9Reader): Tlink {
  return {
    dfid: reader.u32("dfid"),
    fid: reader.u32("fid"),
    name: reader.string(undefined, "name"),
  };
}

// ---------------------------------------------------------------------------
// readlink (Treadlink "d" / Rreadlink "s")
//
//   size[4] Treadlink tag[2] fid[4]
//   size[4] Rreadlink tag[2] target[s]
// ---------------------------------------------------------------------------

export interface Rreadlink {
  target: string;
}

export const writeTreadlink = writeFidRequest;
export const readTreadlink = readFidRequest;

export function writeRreadlink(writer: P9Writer, message: Rreadlink): void {
  writer.string(message.target);
}

export function readRreadlink(reader: P9Reader): Rreadlink {
  return { target: reader.string(undefined, "target") };
}

// ---------------------------------------------------------------------------
// getattr (Tgetattr "dq" / Rgetattr "A" = "qQdugqqqqqqqqqqqqqqq")
//
//   size[4] Tgetattr tag[2] fid[4] request_mask[8]
//   size[4] Rgetattr tag[2] valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8]
//                    rdev[8] size[8] blksize[8] blocks[8]
//                    atime_sec[8] atime_nsec[8] mtime_sec[8] mtime_nsec[8]
//                    ctime_sec[8] ctime_nsec[8] btime_sec[8] btime_nsec[8]
//                    gen[8] data_version[8]
// ---------------------------------------------------------------------------

/**
 * `Tgetattr` — `requestMask` is a `P9_GETATTR_*` set and 64 bits wide, so it is
 * a `bigint` even though every defined bit fits in 14 of them.
 */
export interface Tgetattr {
  fid: number;
  requestMask: bigint;
}

/**
 * `Rgetattr` — `struct stat` minus `st_dev`, with `st_ino` folded into the
 * qid's path and every timestamp widened to a second/nanosecond pair.
 *
 * `valid` says which fields the server actually filled in, and need not equal
 * the request mask: answering fewer is legal, answering more is a courtesy.
 * `btime`, `gen` and `dataVersion` are reserved — the fields exist on the wire
 * and nothing sets them.
 *
 * Widths are worth reading twice, because the C struct's are not these: `mode`,
 * `uid` and `gid` are 32-bit while `nlink`, `rdev`, `blksize` and `blocks` are
 * all 64.
 */
export interface Rgetattr {
  valid: bigint;
  qid: P9Qid;
  mode: number;
  uid: number;
  gid: number;
  nlink: bigint;
  rdev: bigint;
  size: bigint;
  blksize: bigint;
  blocks: bigint;
  atime: P9Time;
  mtime: P9Time;
  ctime: P9Time;
  /** Reserved: creation time, which Linux has no interface for. */
  btime: P9Time;
  /** Reserved. */
  gen: bigint;
  /** Reserved. */
  dataVersion: bigint;
}

export function writeTgetattr(writer: P9Writer, message: Tgetattr): void {
  writer.u32(message.fid);
  writer.u64(message.requestMask);
}

export function readTgetattr(reader: P9Reader): Tgetattr {
  return { fid: reader.u32("fid"), requestMask: reader.u64("request_mask") };
}

export function writeRgetattr(writer: P9Writer, message: Rgetattr): void {
  writer.u64(message.valid);
  writer.qid(message.qid);
  writer.u32(message.mode);
  writer.u32(message.uid);
  writer.u32(message.gid);
  writer.u64(message.nlink);
  writer.u64(message.rdev);
  writer.u64(message.size);
  writer.u64(message.blksize);
  writer.u64(message.blocks);
  writeTime(writer, message.atime);
  writeTime(writer, message.mtime);
  writeTime(writer, message.ctime);
  writeTime(writer, message.btime);
  writer.u64(message.gen);
  writer.u64(message.dataVersion);
}

export function readRgetattr(reader: P9Reader): Rgetattr {
  return {
    valid: reader.u64("valid"),
    qid: reader.qid("qid"),
    mode: reader.u32("mode"),
    uid: reader.u32("uid"),
    gid: reader.u32("gid"),
    nlink: reader.u64("nlink"),
    rdev: reader.u64("rdev"),
    size: reader.u64("size"),
    blksize: reader.u64("blksize"),
    blocks: reader.u64("blocks"),
    atime: readTime(reader, "atime"),
    mtime: readTime(reader, "mtime"),
    ctime: readTime(reader, "ctime"),
    btime: readTime(reader, "btime"),
    gen: reader.u64("gen"),
    dataVersion: reader.u64("data_version"),
  };
}

// ---------------------------------------------------------------------------
// setattr (Tsetattr "dI", I = "ddugqqqqq")
//
//   size[4] Tsetattr tag[2] fid[4] valid[4] mode[4] uid[4] gid[4] size[8]
//                    atime_sec[8] atime_nsec[8] mtime_sec[8] mtime_nsec[8]
//   size[4] Rsetattr tag[2]
// ---------------------------------------------------------------------------

/**
 * `Tsetattr` — the `P9_SETATTR_*` bitmask and the values it selects.
 *
 * Two asymmetries with `Tgetattr` matter. `valid` is **32 bits** here and 64
 * there, and the bit sets are unrelated (`P9_SETATTR_*` mirrors Linux's
 * `ATTR_*`, `P9_GETATTR_*` does not). And a time bit *without* its `_SET`
 * companion means "use the server's clock" — the value in the message is then
 * ignored rather than merely redundant.
 *
 * There is no `ctime` value: `P9_SETATTR_CTIME` asks for "now" and can ask for
 * nothing else.
 */
export interface Tsetattr {
  fid: number;
  valid: number;
  mode: number;
  uid: number;
  gid: number;
  size: bigint;
  atime: P9Time;
  mtime: P9Time;
}

export function writeTsetattr(writer: P9Writer, message: Tsetattr): void {
  writer.u32(message.fid);
  writer.u32(message.valid);
  writer.u32(message.mode);
  writer.u32(message.uid);
  writer.u32(message.gid);
  writer.u64(message.size);
  writeTime(writer, message.atime);
  writeTime(writer, message.mtime);
}

export function readTsetattr(reader: P9Reader): Tsetattr {
  return {
    fid: reader.u32("fid"),
    valid: reader.u32("valid"),
    mode: reader.u32("mode"),
    uid: reader.u32("uid"),
    gid: reader.u32("gid"),
    size: reader.u64("size"),
    atime: readTime(reader, "atime"),
    mtime: readTime(reader, "mtime"),
  };
}

// ---------------------------------------------------------------------------
// xattrwalk / xattrcreate (Txattrwalk "dds", Rxattrwalk "q", Txattrcreate "dsqd")
//
//   size[4] Txattrwalk tag[2] fid[4] newfid[4] name[s]
//   size[4] Rxattrwalk tag[2] size[8]
//   size[4] Txattrcreate tag[2] fid[4] name[s] attr_size[8] flags[4]
//   size[4] Rxattrcreate tag[2]
// ---------------------------------------------------------------------------

/**
 * `Txattrwalk` — bind `newfid` to the xattr `name` of `fid`, so it can be read
 * with `Tread`. An empty `name` asks for the *list* of attributes instead.
 *
 * Linux probes `security.*` on writes, so this arrives far more often than an
 * application using xattrs would suggest — which is why the refusal path is a
 * hot one worth keeping cheap.
 */
export interface Txattrwalk {
  fid: number;
  newfid: number;
  name: string;
}

/** `Rxattrwalk` — the attribute's length, which the client then reads. */
export interface Rxattrwalk {
  size: bigint;
}

export function writeTxattrwalk(writer: P9Writer, message: Txattrwalk): void {
  writer.u32(message.fid);
  writer.u32(message.newfid);
  writer.string(message.name);
}

export function readTxattrwalk(reader: P9Reader): Txattrwalk {
  return {
    fid: reader.u32("fid"),
    newfid: reader.u32("newfid"),
    name: reader.string(undefined, "name"),
  };
}

export function writeRxattrwalk(writer: P9Writer, message: Rxattrwalk): void {
  writer.u64(message.size);
}

export function readRxattrwalk(reader: P9Reader): Rxattrwalk {
  return { size: reader.u64("size") };
}

/**
 * `Txattrcreate` — turn `fid` into a write handle for the xattr `name`.
 *
 * The store does not happen here: the client writes `attrSize` bytes and the
 * server commits on the `Tclunk`, refusing if the byte count did not match.
 * `flags` is `setxattr(2)`'s, i.e. `XATTR_CREATE`/`XATTR_REPLACE`.
 */
export interface Txattrcreate {
  fid: number;
  name: string;
  attrSize: bigint;
  flags: number;
}

export function writeTxattrcreate(writer: P9Writer, message: Txattrcreate): void {
  writer.u32(message.fid);
  writer.string(message.name);
  writer.u64(message.attrSize);
  writer.u32(message.flags);
}

export function readTxattrcreate(reader: P9Reader): Txattrcreate {
  return {
    fid: reader.u32("fid"),
    name: reader.string(undefined, "name"),
    attrSize: reader.u64("attr_size"),
    flags: reader.u32("flags"),
  };
}

// ---------------------------------------------------------------------------
// readdir (Treaddir "dqd" / Rreaddir "D")
//
//   size[4] Treaddir tag[2] fid[4] offset[8] count[4]
//   size[4] Rreaddir tag[2] count[4] data[count]
//
// with data a packed run of: qid[13] offset[8] type[1] name[s]
// (kernel `p9dirent_read()`, format "Qqbs")
// ---------------------------------------------------------------------------

/**
 * `Treaddir` — `offset` is `0` on the first call and thereafter the `offset`
 * carried by the *last entry* of the previous reply, not a byte position.
 */
export interface Treaddir {
  fid: number;
  offset: bigint;
  count: number;
}

/** `Rreaddir` — packed entries; an empty `data` means end of directory. */
export interface Rreaddir {
  data: Uint8Array;
}

export function writeTreaddir(writer: P9Writer, message: Treaddir): void {
  writer.u32(message.fid);
  writer.u64(message.offset);
  writer.u32(message.count);
}

export function readTreaddir(reader: P9Reader): Treaddir {
  return {
    fid: reader.u32("fid"),
    offset: reader.u64("offset"),
    count: reader.u32("count"),
  };
}

export function writeRreaddir(writer: P9Writer, message: Rreaddir): void {
  writer.blob(message.data);
}

/** Decodes the entry block as a **copy**; unpack it with {@link readDirents}. */
export function readRreaddir(reader: P9Reader, max = P9_MAX_ITEM): Rreaddir {
  return { data: reader.blob(max, "readdir data") };
}

/**
 * One packed directory entry: `qid[13] offset[8] type[1] name[s]`.
 *
 * `offset` is the cookie the *next* `Treaddir` resumes from, so it belongs to
 * the entry after this one, not to this one. `type` is a `DT_*` value — the
 * same byte `readdir(3)` reports as `d_type` — and lets a client answer
 * `ls -F` without a `Tgetattr` per name.
 */
export interface P9Dirent {
  qid: P9Qid;
  offset: bigint;
  type: number;
  name: string;
}

/** Bytes one entry will occupy, for the size accounting a packer must do. */
export function direntSize(name: string): number {
  return P9_QID_SIZE + 8 + 1 + 2 + stringByteLength(name);
}

export function writeDirent(writer: P9Writer, dirent: P9Dirent): void {
  writer.qid(dirent.qid);
  writer.u64(dirent.offset);
  writer.u8(dirent.type);
  writer.string(dirent.name);
}

export function readDirent(reader: P9Reader): P9Dirent {
  return {
    qid: reader.qid("dirent qid"),
    offset: reader.u64("dirent offset"),
    type: reader.u8("dirent type"),
    name: reader.string(undefined, "dirent name"),
  };
}

/**
 * Unpack an `Rreaddir` block.
 *
 * Total, like every decoder here: a block whose last entry is cut short throws
 * rather than returning the entries before it, because a client that silently
 * dropped the tail would resume from a stale cookie and skip files.
 */
export function readDirents(data: Uint8Array): P9Dirent[] {
  const reader = new P9Reader(data);
  const dirents: P9Dirent[] = [];
  while (!reader.atEnd) {
    dirents.push(readDirent(reader));
  }
  return dirents;
}

/**
 * Pack entries into an `Rreaddir` block, stopping at a byte budget.
 *
 * The budget is the client's `count`, and overshooting it is not a truncation
 * the client can recover from — it re-reads from the last cookie it saw, so an
 * entry that half-fits must not be written at all. Same contract as
 * `src/fuse/protocol.ts`'s `DirentPacker`: {@link add} returns `false` and
 * changes nothing.
 *
 * "Changes nothing" is absolute, and it is why the name is measured before a
 * single byte is written: `writeDirent` lays down `qid[13] offset[8] type[1]`
 * *before* it reaches the name, so a name the wire cannot express would leave
 * 22 bytes of orphan behind and turn the whole block — every entry already
 * packed included — into something no decoder can read.
 */
export class P9DirentPacker {
  /** Byte budget for this reply. */
  readonly maxSize: number;
  readonly #writer = new P9Writer(256);
  #count = 0;

  constructor(maxSize: number) {
    this.maxSize = Math.max(0, Math.trunc(maxSize));
  }

  /** Bytes packed so far. */
  get size(): number {
    return this.#writer.length;
  }

  /** Entries packed so far. */
  get count(): number {
    return this.#count;
  }

  /** Bytes still available. */
  get remaining(): number {
    return this.maxSize - this.#writer.length;
  }

  /**
   * Append an entry; `false` (and no change) if it does not fit the budget.
   *
   * A name over {@link P9_MAX_STRING} bytes **throws** rather than answering
   * `false`, and the distinction is deliberate: `false` means "not in this
   * reply, ask again", which is a thing a client acts on by paging. A name the
   * protocol cannot express is never going to fit any reply, so answering
   * `false` would drop the file from the directory silently and forever, where
   * throwing lets the session answer `Rlerror ENAMETOOLONG`. Either way the
   * block is untouched — the check happens before anything is written.
   */
  add(dirent: P9Dirent): boolean {
    const nameBytes = stringByteLength(dirent.name);
    if (nameBytes > P9_MAX_STRING) {
      throw new P9Error(
        `dirent name is ${nameBytes} bytes, over the 16-bit count; it cannot be sent at all`,
      );
    }
    if (P9_QID_SIZE + 8 + 1 + 2 + nameBytes > this.remaining) {
      return false;
    }
    writeDirent(this.#writer, dirent);
    this.#count++;
    return true;
  }

  /** The packed block. */
  bytes(): Uint8Array {
    return this.#writer.bytes();
  }
}

// ---------------------------------------------------------------------------
// fsync (Tfsync "dd")
//
//   size[4] Tfsync tag[2] fid[4] datasync[4]
//   size[4] Rfsync tag[2]
// ---------------------------------------------------------------------------

/** `Tfsync` — `datasync` non-zero is `fdatasync(2)` rather than `fsync(2)`. */
export interface Tfsync {
  fid: number;
  datasync: number;
}

export function writeTfsync(writer: P9Writer, message: Tfsync): void {
  writer.u32(message.fid);
  writer.u32(message.datasync);
}

export function readTfsync(reader: P9Reader): Tfsync {
  return { fid: reader.u32("fid"), datasync: reader.u32("datasync") };
}

// ---------------------------------------------------------------------------
// lock / getlock (Tlock "dbdqqds", Rlock "b", Tgetlock "dbqqds", Rgetlock "bqqds")
//
//   size[4] Tlock tag[2] fid[4] type[1] flags[4] start[8] length[8]
//                        proc_id[4] client_id[s]
//   size[4] Rlock tag[2] status[1]
//   size[4] Tgetlock tag[2] fid[4] type[1] start[8] length[8]
//                           proc_id[4] client_id[s]
//   size[4] Rgetlock tag[2] type[1] start[8] length[8] proc_id[4] client_id[s]
// ---------------------------------------------------------------------------

/**
 * `Tlock` — `fcntl(F_SETLK)` on the wire.
 *
 * Note the field `Tgetlock` does *not* have: `flags`, sitting between `type`
 * and `start`. The two messages are otherwise identical, which is exactly the
 * shape a copy-paste error survives, so they get separate codecs.
 *
 * `clientId` is the client's nodename — v9fs sends `utsname()->nodename` — and
 * exists so a server can tell two clients' locks apart. A blocking
 * `fcntl(F_SETLKW)` reaches the server as `P9_LOCK_FLAGS_BLOCK` and a polling
 * loop over `P9_LOCK_BLOCKED` replies, not as a request the server may park on.
 */
export interface Tlock {
  fid: number;
  /** `P9_LOCK_TYPE_*`. */
  type: number;
  /** `P9_LOCK_FLAGS_*`. */
  flags: number;
  start: bigint;
  length: bigint;
  procId: number;
  clientId: string;
}

/** `Rlock` — a `P9_LOCK_*` status, not an errno. */
export interface Rlock {
  status: number;
}

export function writeTlock(writer: P9Writer, message: Tlock): void {
  writer.u32(message.fid);
  writer.u8(message.type);
  writer.u32(message.flags);
  writer.u64(message.start);
  writer.u64(message.length);
  writer.u32(message.procId);
  writer.string(message.clientId);
}

export function readTlock(reader: P9Reader): Tlock {
  return {
    fid: reader.u32("fid"),
    type: reader.u8("type"),
    flags: reader.u32("flags"),
    start: reader.u64("start"),
    length: reader.u64("length"),
    procId: reader.u32("proc_id"),
    clientId: reader.string(undefined, "client_id"),
  };
}

export function writeRlock(writer: P9Writer, message: Rlock): void {
  writer.u8(message.status);
}

export function readRlock(reader: P9Reader): Rlock {
  return { status: reader.u8("status") };
}

/** `Tgetlock` — `fcntl(F_GETLK)`: like {@link Tlock} but with no `flags`. */
export interface Tgetlock {
  fid: number;
  type: number;
  start: bigint;
  length: bigint;
  procId: number;
  clientId: string;
}

/**
 * `Rgetlock` — the conflicting lock, or `P9_LOCK_TYPE_UNLCK` for "none".
 *
 * The reply repeats the request's fields *without* the fid, so it is not the
 * same struct however much it looks like one.
 */
export interface Rgetlock {
  type: number;
  start: bigint;
  length: bigint;
  procId: number;
  clientId: string;
}

export function writeTgetlock(writer: P9Writer, message: Tgetlock): void {
  writer.u32(message.fid);
  writer.u8(message.type);
  writer.u64(message.start);
  writer.u64(message.length);
  writer.u32(message.procId);
  writer.string(message.clientId);
}

export function readTgetlock(reader: P9Reader): Tgetlock {
  return {
    fid: reader.u32("fid"),
    type: reader.u8("type"),
    start: reader.u64("start"),
    length: reader.u64("length"),
    procId: reader.u32("proc_id"),
    clientId: reader.string(undefined, "client_id"),
  };
}

export function writeRgetlock(writer: P9Writer, message: Rgetlock): void {
  writer.u8(message.type);
  writer.u64(message.start);
  writer.u64(message.length);
  writer.u32(message.procId);
  writer.string(message.clientId);
}

export function readRgetlock(reader: P9Reader): Rgetlock {
  return {
    type: reader.u8("type"),
    start: reader.u64("start"),
    length: reader.u64("length"),
    procId: reader.u32("proc_id"),
    clientId: reader.string(undefined, "client_id"),
  };
}

// ---------------------------------------------------------------------------
// stream reassembly
// ---------------------------------------------------------------------------

const EMPTY = new Uint8Array(0);

/** A genuine copy, whatever the input is — `Buffer.prototype.slice` is a view. */
const copyBytes = (bytes: Uint8Array, start: number, end: number): Uint8Array =>
  Uint8Array.prototype.slice.call(bytes, start, end);

/**
 * The receiving half of framing: stream bytes in, whole messages out.
 *
 * 9P over a stream has no framing beyond the `size` field itself, so a
 * reassembler has exactly one thing to be paranoid about and it is a big one: a
 * `size` is an allocation an attacker picks the size of. Every frame is checked
 * against {@link limit} *before* anything is kept, and a `size` under
 * {@link P9_HDRSZ} is refused outright — the kernel's own `p9_parse_header()`
 * refuses `r_size < 7` for the same reason, that a header claiming to be
 * shorter than a header makes the stream unresynchronizable.
 *
 * Unlike `src/nfs/rpc.ts`'s `RecordAssembler`, **every frame handed out is a
 * copy**, and so is the partial frame held between deliveries. The NFS one gets
 * away with views because its server hands each record straight to decoders
 * that copy what they retain; here a session may keep a whole frame across an
 * `await` (a `Twrite` payload is decoded from it), so the framing layer owns
 * the copy instead of hoping every future caller remembers to.
 *
 * **A framing error is terminal, not per-frame.** `size` is the only structure
 * a 9P stream has, so once one is not to be believed there is no offset at
 * which parsing can resume — every later byte is at an unknown position. The
 * assembler therefore *latches*: the first failure poisons it, every later
 * {@link push} throws, and the buffered bytes are dropped rather than left
 * describing a position that no longer exists. A caller that catches
 * {@link P9Error} must close the connection; {@link reset} exists for reusing
 * the object on a *new* one, not for carrying on with the old.
 */
export class P9FrameAssembler {
  /**
   * Scratch for the bytes of a frame that has not all arrived yet.
   *
   * A *compacting* buffer — live bytes are `[#start, #end)`, the space before
   * `#start` is reusable, and it grows geometrically — rather than a fresh
   * concatenation per delivery. The difference is not academic: a peer that
   * dribbles a frame a byte at a time made the old shape re-copy everything it
   * held on every `push`, which is quadratic in the frame size and, since this
   * class now faces arbitrary TCP peers, a way to spend the event loop from the
   * other end of a socket. Copying each delivery in once and each frame out
   * once is linear.
   */
  #buffer: Uint8Array = EMPTY;
  /** First live byte in {@link #buffer}. */
  #start = 0;
  /** One past the last live byte. */
  #end = 0;
  #limit: number;
  /** Set by the first failure; every later `push` refuses. */
  #failure: P9Error | undefined;

  constructor(limit = P9_DEFAULT_MAX_FRAME) {
    this.#limit = P9FrameAssembler.#checkLimit(limit);
  }

  static #checkLimit(limit: number): number {
    if (!Number.isFinite(limit) || limit < P9_HDRSZ) {
      throw new P9Error(`frame limit ${limit} is below the ${P9_HDRSZ}-byte header`);
    }
    return Math.trunc(limit);
  }

  /**
   * Largest frame accepted — the negotiated `msize` once there is one.
   *
   * Settable because `msize` is not known until `Tversion` has been answered,
   * and that answer arrives through this very assembler.
   */
  get limit(): number {
    return this.#limit;
  }

  set limit(value: number) {
    this.#limit = P9FrameAssembler.#checkLimit(value);
  }

  /** Bytes held for a partially received frame; `0` once a failure has latched. */
  get pending(): number {
    return this.#end - this.#start;
  }

  /** Has a framing error latched? The stream is unusable until {@link reset}. */
  get failed(): boolean {
    return this.#failure !== undefined;
  }

  /**
   * Feed a delivery in; get whatever complete frames came out.
   *
   * The caller may reuse `chunk` the moment this returns: nothing kept here is
   * a view of it.
   *
   * Throws once and then keeps throwing — see the class docs. Frames parsed
   * earlier in the *same* call are discarded along with everything else,
   * because handing them over would imply the stream behind them is still
   * being read, and it is not.
   */
  push(chunk: Uint8Array): Uint8Array[] {
    if (this.#failure !== undefined) {
      throw new P9Error(`frame stream is unusable: ${this.#failure.message}`, {
        cause: this.#failure,
      });
    }
    try {
      return this.#parse(chunk);
    } catch (error) {
      this.#failure = isP9Error(error)
        ? error
        : new P9Error(`framing failed: ${String(error)}`, { cause: error });
      this.#drop();
      throw error;
    }
  }

  /**
   * Frames out of one delivery.
   *
   * Two paths, and the difference between them is one copy per byte. With
   * nothing held over, the frames are cut straight out of `chunk` — the copy
   * they are made of is the only one. With a partial frame held, the delivery
   * is appended to the scratch buffer first and the frames come out of that.
   * The common case on a socket is the first one.
   */
  #parse(chunk: Uint8Array): Uint8Array[] {
    const frames: Uint8Array[] = [];
    if (this.#end === this.#start) {
      let at = 0;
      for (;;) {
        if (chunk.byteLength - at < P9_HDRSZ) {
          break;
        }
        const size = this.#sizeAt(readSize(chunk, at), at);
        if (chunk.byteLength - at < size) {
          break;
        }
        frames.push(copyBytes(chunk, at, at + size));
        at += size;
      }
      if (at < chunk.byteLength) {
        // The remainder is copied rather than kept as a view: `chunk` may be a
        // socket buffer the transport re-arms as soon as this call returns.
        this.#append(chunk.subarray(at));
      }
      return frames;
    }

    this.#append(chunk);
    for (;;) {
      if (this.#end - this.#start < P9_HDRSZ) {
        break;
      }
      const size = this.#sizeAt(readSize(this.#buffer, this.#start), 0);
      if (this.#end - this.#start < size) {
        break;
      }
      frames.push(copyBytes(this.#buffer, this.#start, this.#start + size));
      this.#start += size;
    }
    if (this.#start === this.#end) {
      this.#start = 0;
      this.#end = 0;
    }
    return frames;
  }

  /** The two things a `size` field has to be, before it is believed. */
  #sizeAt(size: number, offset: number): number {
    if (size < P9_HDRSZ) {
      throw new P9Error(`frame size ${size} is below the ${P9_HDRSZ}-byte header`, { offset });
    }
    if (size > this.#limit) {
      throw new P9Error(`frame of ${size} bytes exceeds the ${this.#limit}-byte limit`, { offset });
    }
    return size;
  }

  /** Copy `bytes` in behind whatever is already held, compacting or growing. */
  #append(bytes: Uint8Array): void {
    const live = this.#end - this.#start;
    const needed = live + bytes.byteLength;
    if (needed > this.#buffer.byteLength) {
      let capacity = Math.max(this.#buffer.byteLength, 1024);
      while (capacity < needed) {
        capacity *= 2;
      }
      const grown = new Uint8Array(capacity);
      grown.set(this.#buffer.subarray(this.#start, this.#end));
      this.#buffer = grown;
      this.#start = 0;
      this.#end = live;
    } else if (this.#end + bytes.byteLength > this.#buffer.byteLength) {
      // It fits, just not where it is: slide the live bytes back to the front.
      this.#buffer.copyWithin(0, this.#start, this.#end);
      this.#start = 0;
      this.#end = live;
    }
    this.#buffer.set(bytes, this.#end);
    this.#end += bytes.byteLength;
  }

  /** Forget the partial frame, and the memory it was held in. */
  #drop(): void {
    this.#buffer = EMPTY;
    this.#start = 0;
    this.#end = 0;
  }

  /**
   * Drop any partial frame and clear a latched failure.
   *
   * For tearing a connection down, or for reusing the object on the next one —
   * *not* for continuing after a framing error, which cannot be done.
   */
  reset(): void {
    this.#drop();
    this.#failure = undefined;
  }
}

function readSize(bytes: Uint8Array, at: number): number {
  return (
    (bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16) | (bytes[at + 3]! << 24)) >>> 0
  );
}

/**
 * Frames from a stream of deliveries — a socket, a fixture, an array of chunks.
 *
 * Pass an `assembler` to keep hold of it, which a session must do: the
 * negotiated `msize` arrives mid-stream and has to be applied to the same
 * assembler that is reading the rest of it.
 */
export async function* framesFrom(
  source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
  assembler: P9FrameAssembler = new P9FrameAssembler(),
): AsyncGenerator<Uint8Array, void, undefined> {
  for await (const chunk of source) {
    yield* assembler.push(chunk);
  }
}
