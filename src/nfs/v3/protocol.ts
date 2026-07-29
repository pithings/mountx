/**
 * NFSv3 wire-format codecs — a literal transcription of RFC 1813, both
 * directions.
 *
 * Every argument and result struct is encoded *and* decoded. That symmetry is
 * the same trick the FUSE layer uses: the Tier-1 test client is built from
 * these exact functions, so the whole server can be driven through a real
 * socket with no kernel, no mount and no root.
 *
 * The protocol is frozen — RFC 1813 is from 1995 and nothing will be added to
 * it — so this file is deliberately boring and repetitive. Each codec carries
 * the XDR declaration it implements, copied from the RFC, and there is no
 * abstraction over the union arms beyond the handful of result shapes the
 * protocol genuinely repeats (a `wcc_data`-only result, a "created object"
 * result, and the `post_op_attr` every failure carries).
 *
 * Conventions: as in `xdr.ts` — big-endian, 64-bit fields are `bigint`,
 * decoding is total and only throws {@link XdrError}.
 */

import { ERRNO_CODES, type ErrnoCode } from "../../errors.ts";
import type { StatsLike } from "../../types.ts";
import {
  S_IFBLK,
  S_IFCHR,
  S_IFDIR,
  S_IFIFO,
  S_IFLNK,
  S_IFMT,
  S_IFREG,
  S_IFSOCK,
} from "../../types.ts";
import {
  CREATE_EXCLUSIVE,
  DONT_CHANGE,
  NF3BLK,
  NF3CHR,
  NF3DIR,
  NF3FIFO,
  NF3LNK,
  NF3REG,
  NF3SOCK,
  NFS3_COOKIEVERFSIZE,
  NFS3_CREATEVERFSIZE,
  NFS3_FHSIZE,
  NFS3_OK,
  NFS3_WRITEVERFSIZE,
  NFS3ERR_ACCES,
  NFS3ERR_BADHANDLE,
  NFS3ERR_DQUOT,
  NFS3ERR_EXIST,
  NFS3ERR_FBIG,
  NFS3ERR_INVAL,
  NFS3ERR_IO,
  NFS3ERR_ISDIR,
  NFS3ERR_MLINK,
  NFS3ERR_NAMETOOLONG,
  NFS3ERR_NODEV,
  NFS3ERR_NOENT,
  NFS3ERR_NOSPC,
  NFS3ERR_NOTDIR,
  NFS3ERR_NOTEMPTY,
  NFS3ERR_NOTSUPP,
  NFS3ERR_NXIO,
  NFS3ERR_PERM,
  NFS3ERR_ROFS,
  NFS3ERR_SERVERFAULT,
  NFS3ERR_STALE,
  NFS3ERR_XDEV,
  SET_TO_CLIENT_TIME,
} from "./constants.ts";
import { XdrError, XdrReader, XdrWriter, xdrAlign } from "../xdr.ts";

// ---------------------------------------------------------------------------
// errno mapping
// ---------------------------------------------------------------------------

/**
 * `nfsstat3` for a driver error.
 *
 * RFC 1813 §2.6 fixes the set of statuses a v3 server may return, and it is
 * *not* "any errno": a client that receives a status outside the list is
 * entitled to treat the reply as garbage. Anything unmapped becomes
 * `NFS3ERR_IO`, for the same reason the FUSE session falls back to `EIO` —
 * a reply the client cannot interpret is worse than a wrong-but-legal one.
 */
const ERRNO_TO_NFS: Partial<Record<ErrnoCode, number>> = {
  EPERM: NFS3ERR_PERM,
  ENOENT: NFS3ERR_NOENT,
  EIO: NFS3ERR_IO,
  ENXIO: NFS3ERR_NXIO,
  EACCES: NFS3ERR_ACCES,
  EEXIST: NFS3ERR_EXIST,
  EXDEV: NFS3ERR_XDEV,
  ENODEV: NFS3ERR_NODEV,
  ENOTDIR: NFS3ERR_NOTDIR,
  EISDIR: NFS3ERR_ISDIR,
  EINVAL: NFS3ERR_INVAL,
  EFBIG: NFS3ERR_FBIG,
  ENOSPC: NFS3ERR_NOSPC,
  EROFS: NFS3ERR_ROFS,
  EMLINK: NFS3ERR_MLINK,
  ENAMETOOLONG: NFS3ERR_NAMETOOLONG,
  ENOTEMPTY: NFS3ERR_NOTEMPTY,
  EDQUOT: NFS3ERR_DQUOT,
  ESTALE: NFS3ERR_STALE,
  ENOSYS: NFS3ERR_NOTSUPP,
  ENOTSUP: NFS3ERR_NOTSUPP,
  // No `ELOOP` in NFSv3: symlink resolution is the *client's* job, so a server
  // never has a loop to report. A driver that resolves paths itself and hits
  // one gets the nearest legal answer.
  ELOOP: NFS3ERR_INVAL,
};

/** The `nfsstat3` to answer a thrown driver error with. */
export function nfsStatusOf(error: unknown): number {
  if (typeof error === "object" && error !== null) {
    const code = (error as { code?: unknown }).code;
    // `Object.hasOwn`, not `in`: `in` also matches `Object.prototype`, so an
    // error with `code: "toString"` would look up a *function* and encode it
    // as status 0 — a success header in front of a failure body, which is a
    // decoder desync rather than a wrong answer.
    if (typeof code === "string" && Object.hasOwn(ERRNO_TO_NFS, code)) {
      return ERRNO_TO_NFS[code as ErrnoCode] ?? NFS3ERR_IO;
    }
  }
  return NFS3ERR_IO;
}

const NFS_TO_ERRNO = new Map<number, ErrnoCode>([
  [NFS3ERR_PERM, "EPERM"],
  [NFS3ERR_NOENT, "ENOENT"],
  [NFS3ERR_IO, "EIO"],
  [NFS3ERR_NXIO, "ENXIO"],
  [NFS3ERR_ACCES, "EACCES"],
  [NFS3ERR_EXIST, "EEXIST"],
  [NFS3ERR_XDEV, "EXDEV"],
  [NFS3ERR_NODEV, "ENODEV"],
  [NFS3ERR_NOTDIR, "ENOTDIR"],
  [NFS3ERR_ISDIR, "EISDIR"],
  [NFS3ERR_INVAL, "EINVAL"],
  [NFS3ERR_FBIG, "EFBIG"],
  [NFS3ERR_NOSPC, "ENOSPC"],
  [NFS3ERR_ROFS, "EROFS"],
  [NFS3ERR_MLINK, "EMLINK"],
  [NFS3ERR_NAMETOOLONG, "ENAMETOOLONG"],
  [NFS3ERR_NOTEMPTY, "ENOTEMPTY"],
  [NFS3ERR_DQUOT, "EDQUOT"],
  [NFS3ERR_STALE, "ESTALE"],
  [NFS3ERR_BADHANDLE, "ESTALE"],
  [NFS3ERR_NOTSUPP, "ENOTSUP"],
  [NFS3ERR_SERVERFAULT, "EIO"],
]);

/** The POSIX code a client should report for an `nfsstat3`. */
export function errnoCodeOfStatus(status: number): ErrnoCode {
  return NFS_TO_ERRNO.get(status) ?? "EIO";
}

/** Name of an `nfsstat3`, for error messages. */
export function statusName(status: number): string {
  if (status === NFS3_OK) {
    return "NFS3_OK";
  }
  const code = NFS_TO_ERRNO.get(status);
  return code === undefined ? `nfsstat3 ${status}` : `NFS3ERR(${code})`;
}

/** Positive Linux errno for an `nfsstat3`, for anything that wants a number. */
export function errnoOfStatus(status: number): number {
  return ERRNO_CODES[errnoCodeOfStatus(status)];
}

// ---------------------------------------------------------------------------
// basic types (RFC 1813 §2.5)
// ---------------------------------------------------------------------------

/** `struct nfstime3 { uint32 seconds; uint32 nseconds; }`. */
export interface NfsTime3 {
  seconds: number;
  nseconds: number;
}

/** `struct specdata3 { uint32 specdata1; uint32 specdata2; }` — a `rdev`. */
export interface SpecData3 {
  major: number;
  minor: number;
}

/** `struct fattr3` (RFC 1813 §2.5.4). */
export interface Fattr3 {
  /** `ftype3`. */
  type: number;
  mode: number;
  nlink: number;
  uid: number;
  gid: number;
  size: bigint;
  /** Bytes actually consumed on the server. */
  used: bigint;
  rdev: SpecData3;
  fsid: bigint;
  fileid: bigint;
  atime: NfsTime3;
  mtime: NfsTime3;
  ctime: NfsTime3;
}

/** `struct wcc_attr` — the three fields a client caches a directory by. */
export interface WccAttr {
  size: bigint;
  mtime: NfsTime3;
  ctime: NfsTime3;
}

/**
 * `struct wcc_data { pre_op_attr before; post_op_attr after; }`.
 *
 * The whole point of NFSv3's weak cache consistency: a client that saw
 * `before` matching its cached attributes knows its cache was current when the
 * operation ran, so it can apply `after` instead of throwing the cache away.
 * Omitting either half is legal and costs the client a re-read, which is why
 * every mutating operation here fills both in when it can.
 */
export interface WccData {
  before: WccAttr | undefined;
  after: Fattr3 | undefined;
}

export function writeTime(writer: XdrWriter, time: NfsTime3): void {
  writer.u32(time.seconds);
  writer.u32(time.nseconds);
}

export function readTime(reader: XdrReader, what = "nfstime3"): NfsTime3 {
  return { seconds: reader.u32(`${what}.seconds`), nseconds: reader.u32(`${what}.nseconds`) };
}

export function writeSpecData(writer: XdrWriter, spec: SpecData3): void {
  writer.u32(spec.major);
  writer.u32(spec.minor);
}

export function readSpecData(reader: XdrReader): SpecData3 {
  return { major: reader.u32("specdata3.major"), minor: reader.u32("specdata3.minor") };
}

export function writeFattr(writer: XdrWriter, attr: Fattr3): void {
  writer.u32(attr.type);
  writer.u32(attr.mode);
  writer.u32(attr.nlink);
  writer.u32(attr.uid);
  writer.u32(attr.gid);
  writer.u64(attr.size);
  writer.u64(attr.used);
  writeSpecData(writer, attr.rdev);
  writer.u64(attr.fsid);
  writer.u64(attr.fileid);
  writeTime(writer, attr.atime);
  writeTime(writer, attr.mtime);
  writeTime(writer, attr.ctime);
}

export function readFattr(reader: XdrReader): Fattr3 {
  return {
    type: reader.u32("fattr3.type"),
    mode: reader.u32("fattr3.mode"),
    nlink: reader.u32("fattr3.nlink"),
    uid: reader.u32("fattr3.uid"),
    gid: reader.u32("fattr3.gid"),
    size: reader.u64("fattr3.size"),
    used: reader.u64("fattr3.used"),
    rdev: readSpecData(reader),
    fsid: reader.u64("fattr3.fsid"),
    fileid: reader.u64("fattr3.fileid"),
    atime: readTime(reader, "fattr3.atime"),
    mtime: readTime(reader, "fattr3.mtime"),
    ctime: readTime(reader, "fattr3.ctime"),
  };
}

/** `post_op_attr` — an optional `fattr3`. */
export function writePostOpAttr(writer: XdrWriter, attr: Fattr3 | undefined): void {
  writer.optional(attr, writeFattr);
}

export function readPostOpAttr(reader: XdrReader): Fattr3 | undefined {
  return reader.optional(readFattr, "post_op_attr");
}

/** `post_op_fh3` — an optional file handle. */
export function writePostOpFh(writer: XdrWriter, fh: Uint8Array | undefined): void {
  writer.optional(fh, (w, value) => w.varOpaque(value));
}

export function readPostOpFh(reader: XdrReader): Uint8Array | undefined {
  return reader.optional((r) => r.varOpaque(NFS3_FHSIZE, "nfs_fh3"), "post_op_fh3");
}

export function writeWccData(writer: XdrWriter, wcc: WccData): void {
  writer.optional(wcc.before, (w, before) => {
    w.u64(before.size);
    writeTime(w, before.mtime);
    writeTime(w, before.ctime);
  });
  writePostOpAttr(writer, wcc.after);
}

export function readWccData(reader: XdrReader): WccData {
  return {
    before: reader.optional(
      (r) => ({
        size: r.u64("wcc_attr.size"),
        mtime: readTime(r, "wcc_attr.mtime"),
        ctime: readTime(r, "wcc_attr.ctime"),
      }),
      "pre_op_attr",
    ),
    after: readPostOpAttr(reader),
  };
}

/** The `wcc_attr` half of a `wcc_data`, from a stat taken before the operation. */
export function wccAttrOf(stats: StatsLike): WccAttr {
  return {
    size: toU64(stats.size),
    mtime: toTime(stats.mtimeMs),
    ctime: toTime(stats.ctimeMs),
  };
}

/** `struct sattr3` — every field independently settable. */
export interface SetTime3 {
  /** `time_how`. */
  how: number;
  /** Only present for `SET_TO_CLIENT_TIME`. */
  time?: NfsTime3 | undefined;
}

export interface Sattr3 {
  mode?: number | undefined;
  uid?: number | undefined;
  gid?: number | undefined;
  size?: bigint | undefined;
  /** Decoding always yields one; encoding treats a missing one as `DONT_CHANGE`. */
  atime?: SetTime3 | undefined;
  mtime?: SetTime3 | undefined;
}

export function writeSattr(writer: XdrWriter, attr: Sattr3): void {
  writer.optional(attr.mode, (w, mode) => w.u32(mode));
  writer.optional(attr.uid, (w, uid) => w.u32(uid));
  writer.optional(attr.gid, (w, gid) => w.u32(gid));
  writer.optional(attr.size, (w, size) => w.u64(size));
  for (const set of [attr.atime, attr.mtime]) {
    const how = set?.how ?? DONT_CHANGE;
    writer.u32(how);
    if (how === SET_TO_CLIENT_TIME) {
      writeTime(writer, set?.time ?? { seconds: 0, nseconds: 0 });
    }
  }
}

export function readSattr(reader: XdrReader): Sattr3 {
  const readSet = (what: string): SetTime3 => {
    const how = reader.u32(`${what}.how`);
    // `SET_TO_CLIENT_TIME` is the only arm with a body.
    return how === SET_TO_CLIENT_TIME ? { how, time: readTime(reader, what) } : { how };
  };
  return {
    mode: reader.optional((r) => r.u32("sattr3.mode"), "set_mode3"),
    uid: reader.optional((r) => r.u32("sattr3.uid"), "set_uid3"),
    gid: reader.optional((r) => r.u32("sattr3.gid"), "set_gid3"),
    size: reader.optional((r) => r.u64("sattr3.size"), "set_size3"),
    atime: readSet("sattr3.atime"),
    mtime: readSet("sattr3.mtime"),
  };
}

/** `struct diropargs3 { nfs_fh3 dir; filename3 name; }`. */
export interface DirOpArgs {
  dir: Uint8Array;
  name: string;
}

export function writeDirOp(writer: XdrWriter, args: DirOpArgs): void {
  writer.varOpaque(args.dir);
  writer.string(args.name);
}

export function readDirOp(reader: XdrReader): DirOpArgs {
  return {
    dir: reader.varOpaque(NFS3_FHSIZE, "nfs_fh3"),
    name: reader.string(1024, "filename3"),
  };
}

// ---------------------------------------------------------------------------
// attribute conversion
// ---------------------------------------------------------------------------

function toU32(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.trunc(value)) >>> 0 : 0;
}

function toU64(value: number): bigint {
  return Number.isFinite(value) ? BigInt(Math.max(0, Math.trunc(value))) : 0n;
}

/** Milliseconds since the epoch → `nfstime3`. */
export function toTime(ms: number): NfsTime3 {
  if (!Number.isFinite(ms) || ms < 0) {
    return { seconds: 0, nseconds: 0 };
  }
  const seconds = Math.floor(ms / 1000);
  return {
    seconds: toU32(seconds),
    nseconds: Math.min(999_999_999, Math.max(0, Math.round((ms - seconds * 1000) * 1e6))),
  };
}

/** `nfstime3` → milliseconds since the epoch. */
export function fromTime(time: NfsTime3): number {
  return time.seconds * 1000 + time.nseconds / 1e6;
}

/** `ftype3` for a POSIX mode. */
export function ftypeOf(mode: number): number {
  switch (mode & S_IFMT) {
    case S_IFREG: {
      return NF3REG;
    }
    case S_IFDIR: {
      return NF3DIR;
    }
    case S_IFLNK: {
      return NF3LNK;
    }
    case S_IFBLK: {
      return NF3BLK;
    }
    case S_IFCHR: {
      return NF3CHR;
    }
    case S_IFSOCK: {
      return NF3SOCK;
    }
    case S_IFIFO: {
      return NF3FIFO;
    }
    default: {
      // A driver that reports no type bits at all is describing a regular
      // file; `ftype3` has no "unknown", and NF3REG is the only safe guess.
      return NF3REG;
    }
  }
}

/** The `S_IF*` bits for an `ftype3` — the inverse, for a client's `Stats`. */
export function modeTypeOf(type: number): number {
  switch (type) {
    case NF3DIR: {
      return S_IFDIR;
    }
    case NF3LNK: {
      return S_IFLNK;
    }
    case NF3BLK: {
      return S_IFBLK;
    }
    case NF3CHR: {
      return S_IFCHR;
    }
    case NF3SOCK: {
      return S_IFSOCK;
    }
    case NF3FIFO: {
      return S_IFIFO;
    }
    default: {
      return S_IFREG;
    }
  }
}

/**
 * A driver's `StatsLike` as a `fattr3`.
 *
 * `mode` on the wire is **permission bits only** — RFC 1813 §2.5.4 keeps the
 * type in its own `ftype3` field, and a Linux client `or`s the two back
 * together. Sending the `S_IFMT` bits in `mode` as well is a classic
 * interop bug: it produces files whose type the client sees twice, and
 * whose mode it reports with impossible high bits.
 */
export function fattrOf(stats: StatsLike, fileid: bigint): Fattr3 {
  return {
    type: ftypeOf(stats.mode),
    mode: toU32(stats.mode) & 0o7777,
    nlink: toU32(stats.nlink),
    uid: toU32(stats.uid),
    gid: toU32(stats.gid),
    size: toU64(stats.size),
    // `used` is the space actually consumed. `blocks` is in 512-byte units, as
    // in `stat(2)`; a driver that reports none gets its size back.
    used: stats.blocks > 0 ? toU64(stats.blocks) * 512n : toU64(stats.size),
    rdev: { major: (toU32(stats.rdev) >>> 8) & 0xff_ff_ff, minor: toU32(stats.rdev) & 0xff },
    fsid: toU64(stats.dev),
    fileid,
    atime: toTime(stats.atimeMs),
    mtime: toTime(stats.mtimeMs),
    ctime: toTime(stats.ctimeMs),
  };
}

// ---------------------------------------------------------------------------
// result shapes the protocol repeats
// ---------------------------------------------------------------------------

/** A result whose only content is a `wcc_data` — SETATTR, REMOVE, RMDIR. */
export interface WccRes {
  status: number;
  wcc: WccData;
}

export function writeWccRes(writer: XdrWriter, res: WccRes): void {
  writer.u32(res.status);
  writeWccData(writer, res.wcc);
}

export function readWccRes(reader: XdrReader): WccRes {
  return { status: reader.u32("nfsstat3"), wcc: readWccData(reader) };
}

/** CREATE / MKDIR / SYMLINK / MKNOD all reply with this. */
export interface CreateRes {
  status: number;
  obj: Uint8Array | undefined;
  objAttributes: Fattr3 | undefined;
  dirWcc: WccData;
}

export function writeCreateRes(writer: XdrWriter, res: CreateRes): void {
  writer.u32(res.status);
  if (res.status === NFS3_OK) {
    writePostOpFh(writer, res.obj);
    writePostOpAttr(writer, res.objAttributes);
  }
  writeWccData(writer, res.dirWcc);
}

export function readCreateRes(reader: XdrReader): CreateRes {
  const status = reader.u32("nfsstat3");
  if (status !== NFS3_OK) {
    return { status, obj: undefined, objAttributes: undefined, dirWcc: readWccData(reader) };
  }
  return {
    status,
    obj: readPostOpFh(reader),
    objAttributes: readPostOpAttr(reader),
    dirWcc: readWccData(reader),
  };
}

// ---------------------------------------------------------------------------
// GETATTR (§3.3.1)
// ---------------------------------------------------------------------------

export interface Getattr3res {
  status: number;
  attributes: Fattr3 | undefined;
}

export function writeGetattrRes(writer: XdrWriter, res: Getattr3res): void {
  writer.u32(res.status);
  if (res.status === NFS3_OK) {
    writeFattr(writer, res.attributes!);
  }
}

export function readGetattrRes(reader: XdrReader): Getattr3res {
  const status = reader.u32("nfsstat3");
  return { status, attributes: status === NFS3_OK ? readFattr(reader) : undefined };
}

// ---------------------------------------------------------------------------
// SETATTR (§3.3.2)
// ---------------------------------------------------------------------------

export interface Setattr3args {
  object: Uint8Array;
  attributes: Sattr3;
  /** `sattr_guard3`: apply only if `ctime` still matches. */
  guard: NfsTime3 | undefined;
}

export function writeSetattrArgs(writer: XdrWriter, args: Setattr3args): void {
  writer.varOpaque(args.object);
  writeSattr(writer, args.attributes);
  writer.optional(args.guard, writeTime);
}

export function readSetattrArgs(reader: XdrReader): Setattr3args {
  return {
    object: reader.varOpaque(NFS3_FHSIZE, "nfs_fh3"),
    attributes: readSattr(reader),
    guard: reader.optional((r) => readTime(r, "guard ctime"), "sattr_guard3"),
  };
}

// ---------------------------------------------------------------------------
// LOOKUP (§3.3.3)
// ---------------------------------------------------------------------------

export interface Lookup3res {
  status: number;
  object: Uint8Array | undefined;
  objAttributes: Fattr3 | undefined;
  dirAttributes: Fattr3 | undefined;
}

export function writeLookupRes(writer: XdrWriter, res: Lookup3res): void {
  writer.u32(res.status);
  if (res.status === NFS3_OK) {
    writer.varOpaque(res.object!);
    writePostOpAttr(writer, res.objAttributes);
  }
  writePostOpAttr(writer, res.dirAttributes);
}

export function readLookupRes(reader: XdrReader): Lookup3res {
  const status = reader.u32("nfsstat3");
  if (status !== NFS3_OK) {
    return {
      status,
      object: undefined,
      objAttributes: undefined,
      dirAttributes: readPostOpAttr(reader),
    };
  }
  return {
    status,
    object: reader.varOpaque(NFS3_FHSIZE, "nfs_fh3"),
    objAttributes: readPostOpAttr(reader),
    dirAttributes: readPostOpAttr(reader),
  };
}

// ---------------------------------------------------------------------------
// ACCESS (§3.3.4)
// ---------------------------------------------------------------------------

export interface Access3args {
  object: Uint8Array;
  access: number;
}

export interface Access3res {
  status: number;
  attributes: Fattr3 | undefined;
  access: number;
}

export function writeAccessArgs(writer: XdrWriter, args: Access3args): void {
  writer.varOpaque(args.object);
  writer.u32(args.access);
}

export function readAccessArgs(reader: XdrReader): Access3args {
  return {
    object: reader.varOpaque(NFS3_FHSIZE, "nfs_fh3"),
    access: reader.u32("access"),
  };
}

export function writeAccessRes(writer: XdrWriter, res: Access3res): void {
  writer.u32(res.status);
  writePostOpAttr(writer, res.attributes);
  if (res.status === NFS3_OK) {
    writer.u32(res.access);
  }
}

export function readAccessRes(reader: XdrReader): Access3res {
  const status = reader.u32("nfsstat3");
  const attributes = readPostOpAttr(reader);
  return { status, attributes, access: status === NFS3_OK ? reader.u32("access") : 0 };
}

// ---------------------------------------------------------------------------
// READLINK (§3.3.5)
// ---------------------------------------------------------------------------

export interface Readlink3res {
  status: number;
  attributes: Fattr3 | undefined;
  target: string | undefined;
}

export function writeReadlinkRes(writer: XdrWriter, res: Readlink3res): void {
  writer.u32(res.status);
  writePostOpAttr(writer, res.attributes);
  if (res.status === NFS3_OK) {
    writer.string(res.target!);
  }
}

export function readReadlinkRes(reader: XdrReader): Readlink3res {
  const status = reader.u32("nfsstat3");
  const attributes = readPostOpAttr(reader);
  return {
    status,
    attributes,
    target: status === NFS3_OK ? reader.string(4096, "nfspath3") : undefined,
  };
}

// ---------------------------------------------------------------------------
// READ (§3.3.6)
// ---------------------------------------------------------------------------

export interface Read3args {
  file: Uint8Array;
  offset: bigint;
  count: number;
}

export interface Read3res {
  status: number;
  attributes: Fattr3 | undefined;
  count: number;
  eof: boolean;
  data: Uint8Array;
}

export function writeReadArgs(writer: XdrWriter, args: Read3args): void {
  writer.varOpaque(args.file);
  writer.u64(args.offset);
  writer.u32(args.count);
}

export function readReadArgs(reader: XdrReader): Read3args {
  return {
    file: reader.varOpaque(NFS3_FHSIZE, "nfs_fh3"),
    offset: reader.u64("offset3"),
    count: reader.u32("count3"),
  };
}

export function writeReadRes(writer: XdrWriter, res: Read3res): void {
  writer.u32(res.status);
  writePostOpAttr(writer, res.attributes);
  if (res.status === NFS3_OK) {
    writer.u32(res.count);
    writer.bool(res.eof);
    writer.varOpaque(res.data);
  }
}

export function readReadRes(reader: XdrReader, max?: number): Read3res {
  const status = reader.u32("nfsstat3");
  const attributes = readPostOpAttr(reader);
  if (status !== NFS3_OK) {
    return { status, attributes, count: 0, eof: false, data: new Uint8Array(0) };
  }
  const count = reader.u32("count3");
  const eof = reader.bool("eof");
  const data = reader.varOpaque(max, "read data");
  if (data.byteLength !== count) {
    throw new XdrError(`READ says ${count} bytes but carries ${data.byteLength}`);
  }
  return { status, attributes, count, eof, data };
}

// ---------------------------------------------------------------------------
// WRITE (§3.3.7)
// ---------------------------------------------------------------------------

export interface Write3args {
  file: Uint8Array;
  offset: bigint;
  count: number;
  /** `stable_how`. */
  stable: number;
  data: Uint8Array;
}

export interface Write3res {
  status: number;
  wcc: WccData;
  count: number;
  committed: number;
  verf: Uint8Array;
}

export function writeWriteArgs(writer: XdrWriter, args: Write3args): void {
  writer.varOpaque(args.file);
  writer.u64(args.offset);
  writer.u32(args.count);
  writer.u32(args.stable);
  writer.varOpaque(args.data);
}

export function readWriteArgs(reader: XdrReader, max?: number): Write3args {
  const args = {
    file: reader.varOpaque(NFS3_FHSIZE, "nfs_fh3"),
    offset: reader.u64("offset3"),
    count: reader.u32("count3"),
    stable: reader.u32("stable_how"),
    data: reader.varOpaque(max, "write data"),
  };
  if (args.data.byteLength !== args.count) {
    throw new XdrError(`WRITE says ${args.count} bytes but carries ${args.data.byteLength}`);
  }
  return args;
}

export function writeWriteRes(writer: XdrWriter, res: Write3res): void {
  writer.u32(res.status);
  writeWccData(writer, res.wcc);
  if (res.status === NFS3_OK) {
    writer.u32(res.count);
    writer.u32(res.committed);
    writer.fixedOpaque(res.verf, NFS3_WRITEVERFSIZE);
  }
}

export function readWriteRes(reader: XdrReader): Write3res {
  const status = reader.u32("nfsstat3");
  const wcc = readWccData(reader);
  if (status !== NFS3_OK) {
    return { status, wcc, count: 0, committed: 0, verf: new Uint8Array(NFS3_WRITEVERFSIZE) };
  }
  return {
    status,
    wcc,
    count: reader.u32("count3"),
    committed: reader.u32("committed"),
    verf: reader.fixedOpaque(NFS3_WRITEVERFSIZE, "writeverf3"),
  };
}

// ---------------------------------------------------------------------------
// CREATE (§3.3.8)
// ---------------------------------------------------------------------------

export interface Create3args {
  where: DirOpArgs;
  /** `createmode3`. */
  mode: number;
  /** `UNCHECKED` / `GUARDED`. */
  attributes: Sattr3 | undefined;
  /** `EXCLUSIVE`. */
  verf: Uint8Array | undefined;
}

export function writeCreateArgs(writer: XdrWriter, args: Create3args): void {
  writeDirOp(writer, args.where);
  writer.u32(args.mode);
  if (args.mode === CREATE_EXCLUSIVE) {
    writer.fixedOpaque(args.verf ?? new Uint8Array(NFS3_CREATEVERFSIZE), NFS3_CREATEVERFSIZE);
  } else {
    writeSattr(writer, args.attributes ?? {});
  }
}

export function readCreateArgs(reader: XdrReader): Create3args {
  const where = readDirOp(reader);
  const mode = reader.u32("createmode3");
  if (mode === CREATE_EXCLUSIVE) {
    return {
      where,
      mode,
      attributes: undefined,
      verf: reader.fixedOpaque(NFS3_CREATEVERFSIZE, "createverf3"),
    };
  }
  return { where, mode, attributes: readSattr(reader), verf: undefined };
}

// ---------------------------------------------------------------------------
// MKDIR (§3.3.9) / SYMLINK (§3.3.10) / MKNOD (§3.3.11)
// ---------------------------------------------------------------------------

export interface Mkdir3args {
  where: DirOpArgs;
  attributes: Sattr3;
}

export function writeMkdirArgs(writer: XdrWriter, args: Mkdir3args): void {
  writeDirOp(writer, args.where);
  writeSattr(writer, args.attributes);
}

export function readMkdirArgs(reader: XdrReader): Mkdir3args {
  return { where: readDirOp(reader), attributes: readSattr(reader) };
}

export interface Symlink3args {
  where: DirOpArgs;
  attributes: Sattr3;
  target: string;
}

export function writeSymlinkArgs(writer: XdrWriter, args: Symlink3args): void {
  writeDirOp(writer, args.where);
  writeSattr(writer, args.attributes);
  writer.string(args.target);
}

export function readSymlinkArgs(reader: XdrReader): Symlink3args {
  return {
    where: readDirOp(reader),
    attributes: readSattr(reader),
    target: reader.string(4096, "nfspath3"),
  };
}

export interface Mknod3args {
  where: DirOpArgs;
  /** `ftype3`. */
  type: number;
  attributes: Sattr3 | undefined;
  /** Only for `NF3CHR` / `NF3BLK`. */
  spec: SpecData3 | undefined;
}

export function writeMknodArgs(writer: XdrWriter, args: Mknod3args): void {
  writeDirOp(writer, args.where);
  writer.u32(args.type);
  if (args.type === NF3CHR || args.type === NF3BLK) {
    writeSattr(writer, args.attributes ?? {});
    writeSpecData(writer, args.spec ?? { major: 0, minor: 0 });
  } else if (args.type === NF3SOCK || args.type === NF3FIFO) {
    writeSattr(writer, args.attributes ?? {});
  }
}

export function readMknodArgs(reader: XdrReader): Mknod3args {
  const where = readDirOp(reader);
  const type = reader.u32("ftype3");
  if (type === NF3CHR || type === NF3BLK) {
    return { where, type, attributes: readSattr(reader), spec: readSpecData(reader) };
  }
  if (type === NF3SOCK || type === NF3FIFO) {
    return { where, type, attributes: readSattr(reader), spec: undefined };
  }
  // Every other `ftype3` selects the void arm: nothing follows.
  return { where, type, attributes: undefined, spec: undefined };
}

// ---------------------------------------------------------------------------
// RENAME (§3.3.14) / LINK (§3.3.15)
// ---------------------------------------------------------------------------

export interface Rename3args {
  from: DirOpArgs;
  to: DirOpArgs;
}

export interface Rename3res {
  status: number;
  fromWcc: WccData;
  toWcc: WccData;
}

export function writeRenameArgs(writer: XdrWriter, args: Rename3args): void {
  writeDirOp(writer, args.from);
  writeDirOp(writer, args.to);
}

export function readRenameArgs(reader: XdrReader): Rename3args {
  return { from: readDirOp(reader), to: readDirOp(reader) };
}

export function writeRenameRes(writer: XdrWriter, res: Rename3res): void {
  writer.u32(res.status);
  writeWccData(writer, res.fromWcc);
  writeWccData(writer, res.toWcc);
}

export function readRenameRes(reader: XdrReader): Rename3res {
  return {
    status: reader.u32("nfsstat3"),
    fromWcc: readWccData(reader),
    toWcc: readWccData(reader),
  };
}

export interface Link3args {
  file: Uint8Array;
  link: DirOpArgs;
}

export interface Link3res {
  status: number;
  attributes: Fattr3 | undefined;
  linkdirWcc: WccData;
}

export function writeLinkArgs(writer: XdrWriter, args: Link3args): void {
  writer.varOpaque(args.file);
  writeDirOp(writer, args.link);
}

export function readLinkArgs(reader: XdrReader): Link3args {
  return { file: reader.varOpaque(NFS3_FHSIZE, "nfs_fh3"), link: readDirOp(reader) };
}

export function writeLinkRes(writer: XdrWriter, res: Link3res): void {
  writer.u32(res.status);
  writePostOpAttr(writer, res.attributes);
  writeWccData(writer, res.linkdirWcc);
}

export function readLinkRes(reader: XdrReader): Link3res {
  return {
    status: reader.u32("nfsstat3"),
    attributes: readPostOpAttr(reader),
    linkdirWcc: readWccData(reader),
  };
}

// ---------------------------------------------------------------------------
// READDIR (§3.3.16) / READDIRPLUS (§3.3.17)
// ---------------------------------------------------------------------------

export interface Readdir3args {
  dir: Uint8Array;
  cookie: bigint;
  cookieverf: Uint8Array;
  count: number;
}

export interface Entry3 {
  fileid: bigint;
  name: string;
  cookie: bigint;
}

export interface Readdir3res {
  status: number;
  dirAttributes: Fattr3 | undefined;
  cookieverf: Uint8Array;
  entries: Entry3[];
  eof: boolean;
}

export function writeReaddirArgs(writer: XdrWriter, args: Readdir3args): void {
  writer.varOpaque(args.dir);
  writer.u64(args.cookie);
  writer.fixedOpaque(args.cookieverf, NFS3_COOKIEVERFSIZE);
  writer.u32(args.count);
}

export function readReaddirArgs(reader: XdrReader): Readdir3args {
  return {
    dir: reader.varOpaque(NFS3_FHSIZE, "nfs_fh3"),
    cookie: reader.u64("cookie3"),
    cookieverf: reader.fixedOpaque(NFS3_COOKIEVERFSIZE, "cookieverf3"),
    count: reader.u32("count3"),
  };
}

export function writeReaddirRes(writer: XdrWriter, res: Readdir3res): void {
  writer.u32(res.status);
  writePostOpAttr(writer, res.dirAttributes);
  if (res.status !== NFS3_OK) {
    return;
  }
  writer.fixedOpaque(res.cookieverf, NFS3_COOKIEVERFSIZE);
  writer.list(res.entries, (w, entry) => {
    w.u64(entry.fileid);
    w.string(entry.name);
    w.u64(entry.cookie);
  });
  writer.bool(res.eof);
}

export function readReaddirRes(reader: XdrReader): Readdir3res {
  const status = reader.u32("nfsstat3");
  const dirAttributes = readPostOpAttr(reader);
  if (status !== NFS3_OK) {
    return {
      status,
      dirAttributes,
      cookieverf: new Uint8Array(NFS3_COOKIEVERFSIZE),
      entries: [],
      eof: false,
    };
  }
  const cookieverf = reader.fixedOpaque(NFS3_COOKIEVERFSIZE, "cookieverf3");
  const entries = reader.list<Entry3>(
    (r) => ({
      fileid: r.u64("entry3.fileid"),
      name: r.string(1024, "entry3.name"),
      cookie: r.u64("entry3.cookie"),
    }),
    1 << 20,
    "dirlist3",
  );
  return { status, dirAttributes, cookieverf, entries, eof: reader.bool("eof") };
}

export interface Readdirplus3args {
  dir: Uint8Array;
  cookie: bigint;
  cookieverf: Uint8Array;
  /** Bytes of directory information (names and cookies) the client will take. */
  dircount: number;
  /** Bytes of the whole reply the client will take. */
  maxcount: number;
}

export interface EntryPlus3 extends Entry3 {
  attributes: Fattr3 | undefined;
  handle: Uint8Array | undefined;
}

export interface Readdirplus3res {
  status: number;
  dirAttributes: Fattr3 | undefined;
  cookieverf: Uint8Array;
  entries: EntryPlus3[];
  eof: boolean;
}

export function writeReaddirplusArgs(writer: XdrWriter, args: Readdirplus3args): void {
  writer.varOpaque(args.dir);
  writer.u64(args.cookie);
  writer.fixedOpaque(args.cookieverf, NFS3_COOKIEVERFSIZE);
  writer.u32(args.dircount);
  writer.u32(args.maxcount);
}

export function readReaddirplusArgs(reader: XdrReader): Readdirplus3args {
  return {
    dir: reader.varOpaque(NFS3_FHSIZE, "nfs_fh3"),
    cookie: reader.u64("cookie3"),
    cookieverf: reader.fixedOpaque(NFS3_COOKIEVERFSIZE, "cookieverf3"),
    dircount: reader.u32("dircount"),
    maxcount: reader.u32("maxcount"),
  };
}

export function writeReaddirplusRes(writer: XdrWriter, res: Readdirplus3res): void {
  writer.u32(res.status);
  writePostOpAttr(writer, res.dirAttributes);
  if (res.status !== NFS3_OK) {
    return;
  }
  writer.fixedOpaque(res.cookieverf, NFS3_COOKIEVERFSIZE);
  writer.list(res.entries, (w, entry) => {
    w.u64(entry.fileid);
    w.string(entry.name);
    w.u64(entry.cookie);
    writePostOpAttr(w, entry.attributes);
    writePostOpFh(w, entry.handle);
  });
  writer.bool(res.eof);
}

export function readReaddirplusRes(reader: XdrReader): Readdirplus3res {
  const status = reader.u32("nfsstat3");
  const dirAttributes = readPostOpAttr(reader);
  if (status !== NFS3_OK) {
    return {
      status,
      dirAttributes,
      cookieverf: new Uint8Array(NFS3_COOKIEVERFSIZE),
      entries: [],
      eof: false,
    };
  }
  const cookieverf = reader.fixedOpaque(NFS3_COOKIEVERFSIZE, "cookieverf3");
  const entries = reader.list<EntryPlus3>(
    (r) => ({
      fileid: r.u64("entryplus3.fileid"),
      name: r.string(1024, "entryplus3.name"),
      cookie: r.u64("entryplus3.cookie"),
      attributes: readPostOpAttr(r),
      handle: readPostOpFh(r),
    }),
    1 << 20,
    "dirlistplus3",
  );
  return { status, dirAttributes, cookieverf, entries, eof: reader.bool("eof") };
}

/** `fattr3` is fixed width: 21 four-byte words. */
export const FATTR3_SIZE = 84;

/** Bytes one `entry3` occupies on the wire, for READDIR's `count` budget. */
export function entrySize(nameBytes: number): number {
  // bool(next) + fileid(8) + name(4 + padded) + cookie(8)
  return 4 + 8 + 4 + xdrAlign(nameBytes) + 8;
}

/** Bytes one `entryplus3` occupies, given its attributes and handle. */
export function entryPlusSize(nameBytes: number, fhBytes: number, hasAttrs: boolean): number {
  // entry3 + post_op_attr + post_op_fh3
  return entrySize(nameBytes) + (hasAttrs ? 4 + FATTR3_SIZE : 4) + 4 + (4 + xdrAlign(fhBytes));
}

// ---------------------------------------------------------------------------
// FSSTAT (§3.3.18) / FSINFO (§3.3.19) / PATHCONF (§3.3.20) / COMMIT (§3.3.21)
// ---------------------------------------------------------------------------

export interface Fsstat3res {
  status: number;
  attributes: Fattr3 | undefined;
  tbytes: bigint;
  fbytes: bigint;
  abytes: bigint;
  tfiles: bigint;
  ffiles: bigint;
  afiles: bigint;
  invarsec: number;
}

export function writeFsstatRes(writer: XdrWriter, res: Fsstat3res): void {
  writer.u32(res.status);
  writePostOpAttr(writer, res.attributes);
  if (res.status !== NFS3_OK) {
    return;
  }
  writer.u64(res.tbytes);
  writer.u64(res.fbytes);
  writer.u64(res.abytes);
  writer.u64(res.tfiles);
  writer.u64(res.ffiles);
  writer.u64(res.afiles);
  writer.u32(res.invarsec);
}

export function readFsstatRes(reader: XdrReader): Fsstat3res {
  const status = reader.u32("nfsstat3");
  const attributes = readPostOpAttr(reader);
  const empty = {
    status,
    attributes,
    tbytes: 0n,
    fbytes: 0n,
    abytes: 0n,
    tfiles: 0n,
    ffiles: 0n,
    afiles: 0n,
    invarsec: 0,
  };
  if (status !== NFS3_OK) {
    return empty;
  }
  return {
    ...empty,
    tbytes: reader.u64("tbytes"),
    fbytes: reader.u64("fbytes"),
    abytes: reader.u64("abytes"),
    tfiles: reader.u64("tfiles"),
    ffiles: reader.u64("ffiles"),
    afiles: reader.u64("afiles"),
    invarsec: reader.u32("invarsec"),
  };
}

export interface Fsinfo3res {
  status: number;
  attributes: Fattr3 | undefined;
  rtmax: number;
  rtpref: number;
  rtmult: number;
  wtmax: number;
  wtpref: number;
  wtmult: number;
  dtpref: number;
  maxfilesize: bigint;
  timeDelta: NfsTime3;
  properties: number;
}

export function writeFsinfoRes(writer: XdrWriter, res: Fsinfo3res): void {
  writer.u32(res.status);
  writePostOpAttr(writer, res.attributes);
  if (res.status !== NFS3_OK) {
    return;
  }
  writer.u32(res.rtmax);
  writer.u32(res.rtpref);
  writer.u32(res.rtmult);
  writer.u32(res.wtmax);
  writer.u32(res.wtpref);
  writer.u32(res.wtmult);
  writer.u32(res.dtpref);
  writer.u64(res.maxfilesize);
  writeTime(writer, res.timeDelta);
  writer.u32(res.properties);
}

export function readFsinfoRes(reader: XdrReader): Fsinfo3res {
  const status = reader.u32("nfsstat3");
  const attributes = readPostOpAttr(reader);
  const empty = {
    status,
    attributes,
    rtmax: 0,
    rtpref: 0,
    rtmult: 0,
    wtmax: 0,
    wtpref: 0,
    wtmult: 0,
    dtpref: 0,
    maxfilesize: 0n,
    timeDelta: { seconds: 0, nseconds: 0 },
    properties: 0,
  };
  if (status !== NFS3_OK) {
    return empty;
  }
  return {
    ...empty,
    rtmax: reader.u32("rtmax"),
    rtpref: reader.u32("rtpref"),
    rtmult: reader.u32("rtmult"),
    wtmax: reader.u32("wtmax"),
    wtpref: reader.u32("wtpref"),
    wtmult: reader.u32("wtmult"),
    dtpref: reader.u32("dtpref"),
    maxfilesize: reader.u64("maxfilesize"),
    timeDelta: readTime(reader, "time_delta"),
    properties: reader.u32("properties"),
  };
}

export interface Pathconf3res {
  status: number;
  attributes: Fattr3 | undefined;
  linkmax: number;
  nameMax: number;
  noTrunc: boolean;
  chownRestricted: boolean;
  caseInsensitive: boolean;
  casePreserving: boolean;
}

export function writePathconfRes(writer: XdrWriter, res: Pathconf3res): void {
  writer.u32(res.status);
  writePostOpAttr(writer, res.attributes);
  if (res.status !== NFS3_OK) {
    return;
  }
  writer.u32(res.linkmax);
  writer.u32(res.nameMax);
  writer.bool(res.noTrunc);
  writer.bool(res.chownRestricted);
  writer.bool(res.caseInsensitive);
  writer.bool(res.casePreserving);
}

export function readPathconfRes(reader: XdrReader): Pathconf3res {
  const status = reader.u32("nfsstat3");
  const attributes = readPostOpAttr(reader);
  const empty = {
    status,
    attributes,
    linkmax: 0,
    nameMax: 0,
    noTrunc: false,
    chownRestricted: false,
    caseInsensitive: false,
    casePreserving: false,
  };
  if (status !== NFS3_OK) {
    return empty;
  }
  return {
    ...empty,
    linkmax: reader.u32("linkmax"),
    nameMax: reader.u32("name_max"),
    noTrunc: reader.bool("no_trunc"),
    chownRestricted: reader.bool("chown_restricted"),
    caseInsensitive: reader.bool("case_insensitive"),
    casePreserving: reader.bool("case_preserving"),
  };
}

export interface Commit3args {
  file: Uint8Array;
  offset: bigint;
  count: number;
}

export interface Commit3res {
  status: number;
  wcc: WccData;
  verf: Uint8Array;
}

export function writeCommitArgs(writer: XdrWriter, args: Commit3args): void {
  writer.varOpaque(args.file);
  writer.u64(args.offset);
  writer.u32(args.count);
}

export function readCommitArgs(reader: XdrReader): Commit3args {
  return {
    file: reader.varOpaque(NFS3_FHSIZE, "nfs_fh3"),
    offset: reader.u64("offset3"),
    count: reader.u32("count3"),
  };
}

export function writeCommitRes(writer: XdrWriter, res: Commit3res): void {
  writer.u32(res.status);
  writeWccData(writer, res.wcc);
  if (res.status === NFS3_OK) {
    writer.fixedOpaque(res.verf, NFS3_WRITEVERFSIZE);
  }
}

export function readCommitRes(reader: XdrReader): Commit3res {
  const status = reader.u32("nfsstat3");
  const wcc = readWccData(reader);
  return {
    status,
    wcc,
    verf:
      status === NFS3_OK
        ? reader.fixedOpaque(NFS3_WRITEVERFSIZE, "writeverf3")
        : new Uint8Array(NFS3_WRITEVERFSIZE),
  };
}

// ---------------------------------------------------------------------------
// MOUNT v3 (RFC 1813 appendix I)
// ---------------------------------------------------------------------------

export interface Mountres3 {
  /** `mountstat3`. */
  status: number;
  fh: Uint8Array | undefined;
  authFlavors: number[];
}

export function writeMountRes(writer: XdrWriter, res: Mountres3): void {
  writer.u32(res.status);
  if (res.status === 0) {
    writer.varOpaque(res.fh!);
    writer.array(res.authFlavors, (w, flavor) => w.u32(flavor));
  }
}

export function readMountRes(reader: XdrReader): Mountres3 {
  const status = reader.u32("mountstat3");
  if (status !== 0) {
    return { status, fh: undefined, authFlavors: [] };
  }
  return {
    status,
    fh: reader.varOpaque(NFS3_FHSIZE, "fhandle3"),
    authFlavors: reader.array((r) => r.u32("auth_flavor"), 64, "auth_flavors"),
  };
}

/** One `mountbody` of a DUMP reply: who has what mounted. */
export interface MountEntry3 {
  hostname: string;
  directory: string;
}

export function writeMountList(writer: XdrWriter, entries: readonly MountEntry3[]): void {
  writer.list(entries, (w, entry) => {
    w.string(entry.hostname);
    w.string(entry.directory);
  });
}

export function readMountList(reader: XdrReader): MountEntry3[] {
  return reader.list<MountEntry3>(
    (r) => ({
      hostname: r.string(255, "ml_hostname"),
      directory: r.string(1024, "ml_directory"),
    }),
    1 << 16,
    "mountlist",
  );
}

/** One `exportnode` of an EXPORT reply. */
export interface ExportEntry3 {
  directory: string;
  groups: string[];
}

export function writeExportList(writer: XdrWriter, entries: readonly ExportEntry3[]): void {
  writer.list(entries, (w, entry) => {
    w.string(entry.directory);
    w.list(entry.groups, (gw, group) => gw.string(group));
  });
}

export function readExportList(reader: XdrReader): ExportEntry3[] {
  return reader.list<ExportEntry3>(
    (r) => ({
      directory: r.string(1024, "ex_dir"),
      groups: r.list((gr) => gr.string(255, "gr_name"), 1 << 12, "groups"),
    }),
    1 << 16,
    "exports",
  );
}
