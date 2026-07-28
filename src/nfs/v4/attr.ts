/**
 * NFSv4.1 attributes: the `bitmap4` and the `fattr4` container, both
 * directions.
 *
 * NFSv4 replaced NFSv3's fixed `fattr3` struct with a *sparse* one: a counted
 * bitmap says which attributes are present, and a single opaque byte string
 * carries their values back to back, in ascending attribute-number order
 * (RFC 8881 §3.3.7, §18.7.3). There is no per-attribute tag and no per-attribute
 * length, so the bitmap is the only thing that says how to parse the bytes —
 * which has two consequences this file is built around:
 *
 * - **An attribute we cannot name stops the walk.** With no length prefix there
 *   is nothing to skip. {@link decodeFattr} therefore decodes the bits it knows
 *   up to the first one it does not, and reports the rest in
 *   {@link DecodedFattr4.unsupported} so the session can answer
 *   `NFS4ERR_ATTRNOTSUPP` (SETATTR) rather than guess. It is safe to stop
 *   mid-way because `attr_vals` is itself an `opaque<>`: the outer message stays
 *   framed however little of the list we read.
 * - **A reply carries only what it can answer.** {@link encodeFattr} writes
 *   `requested ∩ supported ∩ available`, and GETATTR is *required* to drop the
 *   rest silently — §18.7.3 says the server "MUST NOT return the attribute value
 *   and MUST NOT set the attribute bit in the result bitmap", and §15.1.15.1
 *   says GETATTR MUST NOT answer `NFS4ERR_ATTRNOTSUPP`. Omission is the protocol
 *   here, not a shortcut.
 *
 * Wire types are transcribed from RFC 8881 §5.6 (table 4, REQUIRED) and §5.7
 * (table 5, RECOMMENDED), with the XDR from RFC 5662 §2 where the tables name a
 * type without spelling it: `fsid4` is two `uint64_t`, `specdata4` two
 * `uint32_t`, `nfstime4` an `int64_t` second count plus a `uint32_t` nanosecond
 * one — **not** NFSv3's two `uint32_t`s, so nothing here is shared with
 * `../v3/protocol.ts` even where the shape rhymes.
 *
 * Conventions are `../xdr.ts`'s: big-endian, 64-bit fields are `bigint`,
 * decoding is total and throws only {@link XdrError}, and every retained byte
 * string is copied by the reader that produced it.
 *
 * ACLs (`acl`, `dacl`, `sacl`) are out of scope: `nfsace4` has no counterpart in
 * the driver interface, so the bits are neither advertised nor decoded.
 */

import type { StatsFsLike, StatsLike } from "../../types.ts";
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
  FATTR4_CHANGE,
  FATTR4_FH_EXPIRE_TYPE,
  FATTR4_FILEHANDLE,
  FATTR4_FILEID,
  FATTR4_FILES_AVAIL,
  FATTR4_FILES_FREE,
  FATTR4_FILES_TOTAL,
  FATTR4_FSID,
  FATTR4_LEASE_TIME,
  FATTR4_LINK_SUPPORT,
  FATTR4_MAXFILESIZE,
  FATTR4_MAXLINK,
  FATTR4_MAXNAME,
  FATTR4_MAXREAD,
  FATTR4_MAXWRITE,
  FATTR4_MODE,
  FATTR4_NAMED_ATTR,
  FATTR4_NUMLINKS,
  FATTR4_OWNER,
  FATTR4_OWNER_GROUP,
  FATTR4_RAWDEV,
  FATTR4_RDATTR_ERROR,
  FATTR4_SIZE,
  FATTR4_SPACE_AVAIL,
  FATTR4_SPACE_FREE,
  FATTR4_SPACE_TOTAL,
  FATTR4_SPACE_USED,
  FATTR4_SUPPORTED_ATTRS,
  FATTR4_SYMLINK_SUPPORT,
  FATTR4_TIME_ACCESS,
  FATTR4_TIME_ACCESS_SET,
  FATTR4_TIME_DELTA,
  FATTR4_TIME_METADATA,
  FATTR4_TIME_MODIFY,
  FATTR4_TIME_MODIFY_SET,
  FATTR4_TYPE,
  FATTR4_UNIQUE_HANDLES,
  NF4BLK,
  NF4CHR,
  NF4DIR,
  NF4FIFO,
  NF4LNK,
  NF4REG,
  NF4SOCK,
  NFS4_FHSIZE,
  SET_TO_CLIENT_TIME4,
} from "./constants.ts";
import { XdrError, XdrReader, XdrWriter } from "../xdr.ts";

// ---------------------------------------------------------------------------
// bitmap4 (RFC 8881 §3.3.7)
// ---------------------------------------------------------------------------

/**
 * A `bitmap4`: **the 32-bit words as they travel**, low word first.
 *
 * ```
 *                   0            1
 * +-----------+-----------+-----------+--
 * |  count    | 31  ..  0 | 63  .. 32 |
 * +-----------+-----------+-----------+--
 * ```
 *
 * The alternative — an array of set bit numbers — was rejected for three
 * reasons. Membership, which is what every caller actually asks (`is bit 33
 * set?`), is one shift and one mask here and a scan or a `Set` allocation
 * there. Word count is information: a request naming an attribute this server
 * has never heard of arrives as a third or fourth word, and the words
 * representation carries it through a decode/encode round trip byte for byte
 * rather than inventing a normal form. And it is the wire shape, which is the
 * house rule for every other codec in `src/nfs/`.
 *
 * Bit `n` is bit `n % 32` of word `n / 32`; {@link bitmapBits} converts to bit
 * numbers where iteration is what a caller wants.
 */
export type Bitmap4 = readonly number[];

/**
 * Longest `bitmap4` accepted, in words.
 *
 * RFC 8881's own attributes end at 76 — three words — and NFSv4.2 adds a
 * fourth. Sixteen is a blunt ceiling in the spirit of `XDR_MAX_ITEM`: far above
 * anything a real client sends, and low enough that a count read off the wire
 * cannot become an allocation.
 */
export const NFS4_MAX_BITMAP_WORDS = 16;

/**
 * Longest `attrlist4` accepted.
 *
 * Every attribute this codec knows is a scalar, a timestamp, a filehandle or a
 * short string, so a full `fattr4` is a few hundred bytes; 64 KiB leaves room
 * for an attribute we do not know and still bounds the read.
 */
export const NFS4_MAX_ATTRLIST = 64 * 1024;

/** Longest `owner`/`owner_group` string accepted; a `user@domain` is far shorter. */
export const NFS4_MAX_OWNER = 1024;

/** `bitmap4` — a counted array of words, kept exactly as it arrived. */
export function readBitmap(reader: XdrReader, what = "bitmap4"): number[] {
  return reader.array((r) => r.u32(`${what} word`), NFS4_MAX_BITMAP_WORDS, what);
}

/** `bitmap4` — the count, then the words. */
export function writeBitmap(writer: XdrWriter, bitmap: Bitmap4): void {
  writer.array(bitmap, (w, word) => w.u32(word));
}

/**
 * A bitmap holding exactly `bits`.
 *
 * Trailing zero words are dropped, so a bitmap this builds is the shortest one
 * that carries its bits — which is what a reply should be. Bitmaps that came
 * off the wire keep their own width instead (see {@link readBitmap}).
 */
export function bitmapOf(bits: Iterable<number>): number[] {
  const words: number[] = [];
  for (const bit of bits) {
    if (!Number.isInteger(bit) || bit < 0 || bit >= NFS4_MAX_BITMAP_WORDS * 32) {
      throw new XdrError(`bitmap4 cannot carry attribute ${bit}`);
    }
    const index = bit >>> 5;
    while (words.length <= index) {
      words.push(0);
    }
    // `1 << 31` is negative as a JS number; `>>> 0` puts the word back in the
    // unsigned range the writer expects.
    words[index] = ((words[index] ?? 0) | (1 << (bit & 31))) >>> 0;
  }
  while (words.length > 0 && words[words.length - 1] === 0) {
    words.pop();
  }
  return words;
}

/** Is attribute `bit` set? Words beyond the array read as zero, as XDR intends. */
export function bitmapHas(bitmap: Bitmap4, bit: number): boolean {
  return (((bitmap[bit >>> 5] ?? 0) >>> (bit & 31)) & 1) === 1;
}

/** The set attribute numbers, ascending — the order `attr_vals` is packed in. */
export function bitmapBits(bitmap: Bitmap4): number[] {
  const bits: number[] = [];
  for (let index = 0; index < bitmap.length; index++) {
    const word = bitmap[index] ?? 0;
    if (word === 0) {
      continue;
    }
    for (let bit = 0; bit < 32; bit++) {
      if (((word >>> bit) & 1) === 1) {
        bits.push(index * 32 + bit);
      }
    }
  }
  return bits;
}

/** The bits in both bitmaps. */
export function bitmapIntersection(left: Bitmap4, right: Bitmap4): number[] {
  return bitmapOf(bitmapBits(left).filter((bit) => bitmapHas(right, bit)));
}

/** The bits in `left` that are not in `right`. */
export function bitmapDifference(left: Bitmap4, right: Bitmap4): number[] {
  return bitmapOf(bitmapBits(left).filter((bit) => !bitmapHas(right, bit)));
}

/** Is nothing set? A bitmap of all-zero words counts as empty. */
export function bitmapIsEmpty(bitmap: Bitmap4): boolean {
  return bitmap.every((word) => word === 0);
}

// ---------------------------------------------------------------------------
// attribute value types (RFC 5662 §2)
// ---------------------------------------------------------------------------

/**
 * `struct nfstime4 { int64_t seconds; uint32_t nseconds; }`.
 *
 * Deliberately not NFSv3's `nfstime3`, which is two `uint32_t`s: v4 widened
 * seconds to a *signed* 64-bit count, so it can name times before 1970 and
 * after 2106, and a codec that reused v3's would be wrong in both directions.
 */
export interface NfsTime4 {
  seconds: bigint;
  nseconds: number;
}

/** `struct fsid4 { uint64_t major; uint64_t minor; }` (RFC 5662 §2). */
export interface Fsid4 {
  major: bigint;
  minor: bigint;
}

/** `struct specdata4 { uint32_t specdata1; uint32_t specdata2; }` — a `rdev`. */
export interface SpecData4 {
  major: number;
  minor: number;
}

/**
 * `union settime4 switch (time_how4 set_it)`: a `nfstime4` for
 * `SET_TO_CLIENT_TIME4`, nothing for `SET_TO_SERVER_TIME4` (or any other
 * value, which selects the `default: void` arm).
 */
export interface SetTime4 {
  /** `time_how4`. */
  how: number;
  /** Present only for `SET_TO_CLIENT_TIME4`. */
  time?: NfsTime4 | undefined;
}

export function writeTime4(writer: XdrWriter, time: NfsTime4): void {
  writer.i64(time.seconds);
  writer.u32(time.nseconds);
}

export function readTime4(reader: XdrReader, what = "nfstime4"): NfsTime4 {
  return { seconds: reader.i64(`${what}.seconds`), nseconds: reader.u32(`${what}.nseconds`) };
}

export function writeFsid4(writer: XdrWriter, fsid: Fsid4): void {
  writer.u64(fsid.major);
  writer.u64(fsid.minor);
}

export function readFsid4(reader: XdrReader): Fsid4 {
  return { major: reader.u64("fsid4.major"), minor: reader.u64("fsid4.minor") };
}

export function writeSpecData4(writer: XdrWriter, spec: SpecData4): void {
  writer.u32(spec.major);
  writer.u32(spec.minor);
}

export function readSpecData4(reader: XdrReader): SpecData4 {
  return { major: reader.u32("specdata4.specdata1"), minor: reader.u32("specdata4.specdata2") };
}

export function writeSetTime4(writer: XdrWriter, set: SetTime4): void {
  writer.u32(set.how);
  if (set.how === SET_TO_CLIENT_TIME4) {
    writeTime4(writer, set.time ?? { seconds: 0n, nseconds: 0 });
  }
}

export function readSetTime4(reader: XdrReader, what = "settime4"): SetTime4 {
  const how = reader.u32(`${what}.set_it`);
  // `SET_TO_CLIENT_TIME4` is the only arm with a body; everything else, known
  // or not, selects `default: void`. A `set_it` that is neither 0 nor 1 is a
  // decision for the session (`NFS4ERR_INVAL`), not a decode failure.
  return how === SET_TO_CLIENT_TIME4 ? { how, time: readTime4(reader, what) } : { how };
}

// ---------------------------------------------------------------------------
// scalar conversion
// ---------------------------------------------------------------------------

function toU32(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.trunc(value)) >>> 0 : 0;
}

function toU64(value: number): bigint {
  return Number.isFinite(value) ? BigInt(Math.max(0, Math.trunc(value))) : 0n;
}

/**
 * Milliseconds since the epoch → `nfstime4`.
 *
 * `seconds` is signed here, so a timestamp before 1970 survives instead of
 * clamping to zero the way `nfstime3` has to.
 */
export function toTime4(ms: number): NfsTime4 {
  if (!Number.isFinite(ms)) {
    return { seconds: 0n, nseconds: 0 };
  }
  const seconds = Math.floor(ms / 1000);
  const nseconds = Math.round((ms - seconds * 1000) * 1e6);
  return {
    seconds: BigInt(seconds),
    nseconds: Math.min(999_999_999, Math.max(0, nseconds)),
  };
}

/** `nfstime4` → milliseconds since the epoch. */
export function fromTime4(time: NfsTime4): number {
  return Number(time.seconds) * 1000 + time.nseconds / 1e6;
}

/** `nfs_ftype4` for a POSIX mode (RFC 8881 §5.8.1.2). */
export function ftype4Of(mode: number): number {
  switch (mode & S_IFMT) {
    case S_IFREG: {
      return NF4REG;
    }
    case S_IFDIR: {
      return NF4DIR;
    }
    case S_IFLNK: {
      return NF4LNK;
    }
    case S_IFBLK: {
      return NF4BLK;
    }
    case S_IFCHR: {
      return NF4CHR;
    }
    case S_IFSOCK: {
      return NF4SOCK;
    }
    case S_IFIFO: {
      return NF4FIFO;
    }
    default: {
      // No type bits at all describes a regular file; `nfs_ftype4` has no
      // "unknown" member, and NF4REG is the only safe answer.
      return NF4REG;
    }
  }
}

/** The `S_IF*` bits for an `nfs_ftype4` — the inverse, for a client's `Stats`. */
export function modeType4Of(type: number): number {
  switch (type) {
    case NF4DIR: {
      return S_IFDIR;
    }
    case NF4LNK: {
      return S_IFLNK;
    }
    case NF4BLK: {
      return S_IFBLK;
    }
    case NF4CHR: {
      return S_IFCHR;
    }
    case NF4SOCK: {
      return S_IFSOCK;
    }
    case NF4FIFO: {
      return S_IFIFO;
    }
    default: {
      return S_IFREG;
    }
  }
}

/**
 * A uid or gid as the numeric `owner` string NFSv4 allows.
 *
 * RFC 8881 §5.9: "owner and group strings that consist of decimal numeric
 * values with no leading zeros can be given a special interpretation", meaning
 * the NFSv3 uid or gid with that value. `String(number)` produces exactly that
 * form. Whether to *use* it — rather than `user@domain` from a name service —
 * is ID-mapping policy and lives with the session, not here.
 */
export function numericOwner(id: number): string {
  return String(toU32(id));
}

/**
 * The uid or gid a numeric `owner` string names, or `undefined` if it is not
 * one.
 *
 * Strict about the form §5.9 defines: decimal digits, no leading zeros, and
 * inside the 32 bits an NFSv3 uid had. Anything else — `"root"`,
 * `"user@example.org"`, `"007"` — is a name for the session to map or refuse
 * with `NFS4ERR_BADOWNER`.
 */
export function parseNumericOwner(owner: string): number | undefined {
  if (!/^(?:0|[1-9]\d*)$/.test(owner)) {
    return undefined;
  }
  const id = Number(owner);
  return id > 0xff_ff_ff_ff ? undefined : id;
}

// ---------------------------------------------------------------------------
// fattr4 values
// ---------------------------------------------------------------------------

/**
 * The attributes this codec can carry, all optional: a `fattr4` is by
 * construction a *subset*, and "absent" is the protocol's own answer for an
 * attribute a server does not have.
 *
 * Keys are the RFC's names in the house's camelCase (the way `Pathconf3res`
 * spells `name_max` as `nameMax`); the RFC spelling stays on each codec, where
 * it also becomes the `what` in a decode error.
 */
export interface Fattr4Values {
  /** 0 — the bit vector of everything supported for this object (§5.8.1.1). */
  supportedAttrs?: Bitmap4 | undefined;
  /** 1 — `nfs_ftype4`. */
  type?: number | undefined;
  /** 2 — `FH4_*`; zero (`FH4_PERSISTENT`) for handles that never expire. */
  fhExpireType?: number | undefined;
  /** 3 — opaque to the client; only "differs after a change" is promised. */
  change?: bigint | undefined;
  /** 4 — size in bytes. */
  size?: bigint | undefined;
  /** 5 — the filesystem supports hard links. */
  linkSupport?: boolean | undefined;
  /** 6 — the filesystem supports symbolic links. */
  symlinkSupport?: boolean | undefined;
  /** 7 — this object has a non-empty named attribute directory. */
  namedAttr?: boolean | undefined;
  /** 8 — filesystem identity, major and minor. */
  fsid?: Fsid4 | undefined;
  /** 9 — distinct handles are guaranteed to be distinct objects. */
  uniqueHandles?: boolean | undefined;
  /** 10 — lease duration in seconds. */
  leaseTime?: number | undefined;
  /** 11 — the `nfsstat4` a READDIR hit while reading this entry's attributes. */
  rdattrError?: number | undefined;
  /** 19 — this object's filehandle. */
  filehandle?: Uint8Array | undefined;
  /** 20 — file serial number. */
  fileid?: bigint | undefined;
  /** 21/22/23 — inodes available, free, total. */
  filesAvail?: bigint | undefined;
  filesFree?: bigint | undefined;
  filesTotal?: bigint | undefined;
  /** 27 — largest file this server will name. */
  maxfilesize?: bigint | undefined;
  /** 28 — largest link count. */
  maxlink?: number | undefined;
  /** 29 — longest name component. */
  maxname?: number | undefined;
  /** 30/31 — largest READ answered and WRITE accepted. */
  maxread?: bigint | undefined;
  maxwrite?: bigint | undefined;
  /** 33 — `mode4`: permission bits only, the type lives in `type`. */
  mode?: number | undefined;
  /** 35 — hard link count. */
  numlinks?: number | undefined;
  /** 36/37 — `utf8str_mixed`; see {@link numericOwner}. */
  owner?: string | undefined;
  ownerGroup?: string | undefined;
  /** 41 — device number, for NF4BLK and NF4CHR. */
  rawdev?: SpecData4 | undefined;
  /** 42/43/44/45 — bytes available, free, total, and used by this object. */
  spaceAvail?: bigint | undefined;
  spaceFree?: bigint | undefined;
  spaceTotal?: bigint | undefined;
  spaceUsed?: bigint | undefined;
  /** 47 — last access. */
  timeAccess?: NfsTime4 | undefined;
  /** 48 — SETATTR only: set the last access time. */
  timeAccessSet?: SetTime4 | undefined;
  /** 51 — smallest useful time granularity. */
  timeDelta?: NfsTime4 | undefined;
  /** 52 — last metadata change (POSIX `ctime`). */
  timeMetadata?: NfsTime4 | undefined;
  /** 53 — last data modification (POSIX `mtime`). */
  timeModify?: NfsTime4 | undefined;
  /** 54 — SETATTR only: set the last modification time. */
  timeModifySet?: SetTime4 | undefined;
}

/** Every shape an attribute value can take. */
type Fattr4Value = NonNullable<Fattr4Values[keyof Fattr4Values]>;

interface AttrCodec {
  /** Attribute number — its bit in a `bitmap4`. */
  readonly bit: number;
  /** The RFC's name, for decode errors and for grepping a table against §5.7. */
  readonly name: string;
  readonly key: keyof Fattr4Values;
  readonly read: (reader: XdrReader) => Fattr4Value;
  readonly write: (writer: XdrWriter, value: Fattr4Value) => void;
}

/**
 * One row of the table, type-checked against {@link Fattr4Values} at the point
 * of definition.
 *
 * The single cast is on `write`: a writer for one attribute takes that
 * attribute's type, which under `strictFunctionTypes` is not assignable to a
 * writer of the union. Erasing it here keeps the table homogeneous while every
 * `read`/`write` pair below is still checked against the key it names.
 */
function attr<K extends keyof Fattr4Values>(
  bit: number,
  name: string,
  key: K,
  read: (reader: XdrReader) => NonNullable<Fattr4Values[K]>,
  write: (writer: XdrWriter, value: NonNullable<Fattr4Values[K]>) => void,
): AttrCodec {
  return { bit, name, key, read, write: write as AttrCodec["write"] };
}

/**
 * Every attribute this codec knows, **in ascending bit order** — which is the
 * order `attr_vals` is packed in, so encoding is one walk down this table.
 *
 * Types come from RFC 8881 table 4 (§5.6) and table 5 (§5.7); each row repeats
 * the RFC's name so the table can be read straight against them.
 */
const ATTR_CODECS: readonly AttrCodec[] = [
  attr(
    FATTR4_SUPPORTED_ATTRS,
    "supported_attrs",
    "supportedAttrs",
    (r) => readBitmap(r, "fattr4_supported_attrs"),
    writeBitmap,
  ),
  attr(
    FATTR4_TYPE,
    "type",
    "type",
    (r) => r.u32("fattr4_type"),
    (w, value) => w.u32(value),
  ),
  attr(
    FATTR4_FH_EXPIRE_TYPE,
    "fh_expire_type",
    "fhExpireType",
    (r) => r.u32("fattr4_fh_expire_type"),
    (w, value) => w.u32(value),
  ),
  attr(
    FATTR4_CHANGE,
    "change",
    "change",
    (r) => r.u64("fattr4_change"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_SIZE,
    "size",
    "size",
    (r) => r.u64("fattr4_size"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_LINK_SUPPORT,
    "link_support",
    "linkSupport",
    (r) => r.bool("fattr4_link_support"),
    (w, value) => w.bool(value),
  ),
  attr(
    FATTR4_SYMLINK_SUPPORT,
    "symlink_support",
    "symlinkSupport",
    (r) => r.bool("fattr4_symlink_support"),
    (w, value) => w.bool(value),
  ),
  attr(
    FATTR4_NAMED_ATTR,
    "named_attr",
    "namedAttr",
    (r) => r.bool("fattr4_named_attr"),
    (w, value) => w.bool(value),
  ),
  attr(FATTR4_FSID, "fsid", "fsid", readFsid4, writeFsid4),
  attr(
    FATTR4_UNIQUE_HANDLES,
    "unique_handles",
    "uniqueHandles",
    (r) => r.bool("fattr4_unique_handles"),
    (w, value) => w.bool(value),
  ),
  attr(
    FATTR4_LEASE_TIME,
    "lease_time",
    "leaseTime",
    (r) => r.u32("fattr4_lease_time"),
    (w, value) => w.u32(value),
  ),
  attr(
    FATTR4_RDATTR_ERROR,
    "rdattr_error",
    "rdattrError",
    (r) => r.u32("fattr4_rdattr_error"),
    (w, value) => w.u32(value),
  ),
  attr(
    FATTR4_FILEHANDLE,
    "filehandle",
    "filehandle",
    // `varOpaque` copies, so nothing downstream holds a view of the record.
    (r) => r.varOpaque(NFS4_FHSIZE, "fattr4_filehandle"),
    (w, value) => w.varOpaque(value),
  ),
  attr(
    FATTR4_FILEID,
    "fileid",
    "fileid",
    (r) => r.u64("fattr4_fileid"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_FILES_AVAIL,
    "files_avail",
    "filesAvail",
    (r) => r.u64("fattr4_files_avail"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_FILES_FREE,
    "files_free",
    "filesFree",
    (r) => r.u64("fattr4_files_free"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_FILES_TOTAL,
    "files_total",
    "filesTotal",
    (r) => r.u64("fattr4_files_total"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_MAXFILESIZE,
    "maxfilesize",
    "maxfilesize",
    (r) => r.u64("fattr4_maxfilesize"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_MAXLINK,
    "maxlink",
    "maxlink",
    (r) => r.u32("fattr4_maxlink"),
    (w, value) => w.u32(value),
  ),
  attr(
    FATTR4_MAXNAME,
    "maxname",
    "maxname",
    (r) => r.u32("fattr4_maxname"),
    (w, value) => w.u32(value),
  ),
  // `maxread` and `maxwrite` are `uint64_t`, not the `count4` their NFSv3
  // cousins `rtmax`/`wtmax` are (RFC 8881 §5.7, table 5).
  attr(
    FATTR4_MAXREAD,
    "maxread",
    "maxread",
    (r) => r.u64("fattr4_maxread"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_MAXWRITE,
    "maxwrite",
    "maxwrite",
    (r) => r.u64("fattr4_maxwrite"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_MODE,
    "mode",
    "mode",
    (r) => r.u32("fattr4_mode"),
    (w, value) => w.u32(value),
  ),
  attr(
    FATTR4_NUMLINKS,
    "numlinks",
    "numlinks",
    (r) => r.u32("fattr4_numlinks"),
    (w, value) => w.u32(value),
  ),
  attr(
    FATTR4_OWNER,
    "owner",
    "owner",
    (r) => r.string(NFS4_MAX_OWNER, "fattr4_owner"),
    (w, value) => w.string(value),
  ),
  attr(
    FATTR4_OWNER_GROUP,
    "owner_group",
    "ownerGroup",
    (r) => r.string(NFS4_MAX_OWNER, "fattr4_owner_group"),
    (w, value) => w.string(value),
  ),
  attr(FATTR4_RAWDEV, "rawdev", "rawdev", readSpecData4, writeSpecData4),
  attr(
    FATTR4_SPACE_AVAIL,
    "space_avail",
    "spaceAvail",
    (r) => r.u64("fattr4_space_avail"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_SPACE_FREE,
    "space_free",
    "spaceFree",
    (r) => r.u64("fattr4_space_free"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_SPACE_TOTAL,
    "space_total",
    "spaceTotal",
    (r) => r.u64("fattr4_space_total"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_SPACE_USED,
    "space_used",
    "spaceUsed",
    (r) => r.u64("fattr4_space_used"),
    (w, value) => w.u64(value),
  ),
  attr(
    FATTR4_TIME_ACCESS,
    "time_access",
    "timeAccess",
    (r) => readTime4(r, "fattr4_time_access"),
    writeTime4,
  ),
  attr(
    FATTR4_TIME_ACCESS_SET,
    "time_access_set",
    "timeAccessSet",
    (r) => readSetTime4(r, "fattr4_time_access_set"),
    writeSetTime4,
  ),
  attr(
    FATTR4_TIME_DELTA,
    "time_delta",
    "timeDelta",
    (r) => readTime4(r, "fattr4_time_delta"),
    writeTime4,
  ),
  attr(
    FATTR4_TIME_METADATA,
    "time_metadata",
    "timeMetadata",
    (r) => readTime4(r, "fattr4_time_metadata"),
    writeTime4,
  ),
  attr(
    FATTR4_TIME_MODIFY,
    "time_modify",
    "timeModify",
    (r) => readTime4(r, "fattr4_time_modify"),
    writeTime4,
  ),
  attr(
    FATTR4_TIME_MODIFY_SET,
    "time_modify_set",
    "timeModifySet",
    (r) => readSetTime4(r, "fattr4_time_modify_set"),
    writeSetTime4,
  ),
];

const CODEC_BY_BIT = new Map<number, AttrCodec>(ATTR_CODECS.map((codec) => [codec.bit, codec]));

/** The attribute numbers this codec can encode and decode, ascending. */
export const KNOWN_ATTRS: Bitmap4 = bitmapOf(ATTR_CODECS.map((codec) => codec.bit));

/**
 * What `supported_attrs` (bit 0) advertises: everything this server can answer
 * or accept for any object.
 *
 * Every bit is here because the driver interface can answer it truthfully, and
 * the ones left out are left out for a reason:
 *
 * - `supported_attrs` (0) — this bitmap itself; REQUIRED.
 * - `type` (1) — from `StatsLike.mode`'s `S_IFMT` bits.
 * - `fh_expire_type` (2) — the handle table's handles are persistent for the
 *   life of the server, which is `FH4_PERSISTENT`.
 * - `change` (3) — see {@link changeOf}.
 * - `size` (4) — `StatsLike.size`, and settable through `truncate`.
 * - `link_support` (5), `symlink_support` (6) — `FsCapabilities.hardlinks` and
 *   `.symlinks`; declared-or-inferred, never assumed.
 * - `named_attr` (7) — always FALSE: no driver has named attribute
 *   directories, and saying so is an answer, not a gap.
 * - `fsid` (8) — `StatsLike.dev`.
 * - `unique_handles` (9) — the handle table maps one path to one handle.
 * - `lease_time` (10) — the session's own lease length; REQUIRED.
 * - `rdattr_error` (11) — REQUIRED, and the only way READDIR can report a
 *   per-entry failure without failing the whole call.
 * - `filehandle` (19) — REQUIRED; what makes READDIR-with-handles possible.
 * - `fileid` (20) — `StatsLike.ino`.
 * - `files_avail`/`files_free`/`files_total` (21/22/23) and
 *   `space_avail`/`space_free`/`space_total` (42/43/44) — from `statfs`, the
 *   same numbers NFSv3's FSSTAT reports.
 * - `maxfilesize` (27), `maxlink` (28), `maxname` (29), `maxread` (30),
 *   `maxwrite` (31) — the server's own limits, NFSv3's FSINFO/PATHCONF answers
 *   under new names.
 * - `mode` (33) — permission bits, settable through `chmod`.
 * - `numlinks` (35) — `StatsLike.nlink`.
 * - `owner`/`owner_group` (36/37) — `StatsLike.uid`/`.gid`, settable through
 *   `chown`.
 * - `rawdev` (41) — `StatsLike.rdev`.
 * - `space_used` (45) — `StatsLike.blocks`.
 * - `time_access` (47), `time_metadata` (52), `time_modify` (53) — atime,
 *   ctime and mtime.
 * - `time_access_set` (48), `time_modify_set` (54) — settable through
 *   `utimes`. They are write-only (§5.5), and are advertised anyway because
 *   `supported_attrs` is how a client decides whether SETATTR of a time is
 *   worth sending; {@link GETABLE_ATTRS} is what a GETATTR reply may contain.
 * - `time_delta` (51) — one millisecond, the finest difference a `Date`-based
 *   driver can express.
 *
 * Deliberately absent: `acl`/`aclsupport`/`dacl`/`sacl` (no `nfsace4` in the
 * driver interface), `suppattr_exclcreat` (75) (answering it commits to an
 * attribute set for `EXCLUSIVE4_1` creation, which is the OPEN step's call —
 * and a REQUIRED attribute omitted is legal to a GETATTR, which simply drops
 * it), `mounted_on_fileid` (55) (we export one filesystem with nothing mounted
 * inside it, so it could only ever repeat `fileid`), `time_create` (50) (a
 * driver with no birth time would answer "the epoch", which is worse than
 * absent), the quota trio (38/39/40) (`statfs` reports no quota), `archive`,
 * `hidden`, `system`, `mimetype` (no such concept in `FsDriver`), and every
 * pNFS, layout, retention and notification attribute (56..74, 76).
 */
export const SUPPORTED_ATTRS: Bitmap4 = bitmapOf([
  FATTR4_SUPPORTED_ATTRS,
  FATTR4_TYPE,
  FATTR4_FH_EXPIRE_TYPE,
  FATTR4_CHANGE,
  FATTR4_SIZE,
  FATTR4_LINK_SUPPORT,
  FATTR4_SYMLINK_SUPPORT,
  FATTR4_NAMED_ATTR,
  FATTR4_FSID,
  FATTR4_UNIQUE_HANDLES,
  FATTR4_LEASE_TIME,
  FATTR4_RDATTR_ERROR,
  FATTR4_FILEHANDLE,
  FATTR4_FILEID,
  FATTR4_FILES_AVAIL,
  FATTR4_FILES_FREE,
  FATTR4_FILES_TOTAL,
  FATTR4_MAXFILESIZE,
  FATTR4_MAXLINK,
  FATTR4_MAXNAME,
  FATTR4_MAXREAD,
  FATTR4_MAXWRITE,
  FATTR4_MODE,
  FATTR4_NUMLINKS,
  FATTR4_OWNER,
  FATTR4_OWNER_GROUP,
  FATTR4_RAWDEV,
  FATTR4_SPACE_AVAIL,
  FATTR4_SPACE_FREE,
  FATTR4_SPACE_TOTAL,
  FATTR4_SPACE_USED,
  FATTR4_TIME_ACCESS,
  FATTR4_TIME_ACCESS_SET,
  FATTR4_TIME_DELTA,
  FATTR4_TIME_METADATA,
  FATTR4_TIME_MODIFY,
  FATTR4_TIME_MODIFY_SET,
]);

/**
 * The write-only attributes (RFC 8881 §5.5): SETATTR may set them, GETATTR
 * **MUST NOT** return them and must answer `NFS4ERR_INVAL` if one is requested.
 * Named here so the session can make that check from the same table the codec
 * uses.
 */
export const SET_ONLY_ATTRS: Bitmap4 = bitmapOf([FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET]);

/**
 * What a GETATTR reply may contain: {@link SUPPORTED_ATTRS} without the
 * write-only pair. This is {@link encodeFattr}'s default, so a set-only
 * attribute cannot reach a reply by accident.
 */
export const GETABLE_ATTRS: Bitmap4 = bitmapDifference(SUPPORTED_ATTRS, SET_ONLY_ATTRS);

/**
 * What a SETATTR may change — the `R W` and `W` rows of RFC 8881 tables 4 and 5
 * that this server supports. A supported attribute outside this set is
 * read-only, which §5.5 says answers `NFS4ERR_INVAL` rather than
 * `NFS4ERR_ATTRNOTSUPP`.
 */
export const SETTABLE_ATTRS: Bitmap4 = bitmapOf([
  FATTR4_SIZE,
  FATTR4_MODE,
  FATTR4_OWNER,
  FATTR4_OWNER_GROUP,
  FATTR4_TIME_ACCESS_SET,
  FATTR4_TIME_MODIFY_SET,
]);

/**
 * Assign one decoded value.
 *
 * The one cast on the decode path, and the mirror of the one in {@link attr}:
 * the table is homogeneous by construction, so the key and the value it carries
 * are only related through the row they came from.
 */
function setValue(values: Fattr4Values, key: keyof Fattr4Values, value: Fattr4Value): void {
  (values as Record<string, Fattr4Value>)[key] = value;
}

/** What a `fattr4` decoded to, plus what stopped it. */
export interface DecodedFattr4 {
  /** The `attrmask` exactly as it arrived, words and all. */
  attrmask: number[];
  /** Every attribute decoded, up to the first bit this codec does not know. */
  values: Fattr4Values;
  /**
   * Set bits with no codec here, ascending.
   *
   * Non-empty means the walk **stopped** at `unsupported[0]` — an attribute
   * value has no length prefix, so there is nothing to skip past — and that
   * `values` holds only the attributes numbered below it. For SETATTR that is
   * `NFS4ERR_ATTRNOTSUPP` (§18.30.4); for VERIFY/NVERIFY the same, since a
   * comparison against a value we cannot parse is not a comparison.
   */
  unsupported: number[];
}

/**
 * `struct fattr4 { bitmap4 attrmask; attrlist4 attr_vals; }`.
 *
 * `attr_vals` is an `opaque<>`, so it is read (and copied) whole before the
 * walk: whatever the bitmap turns out to say, the enclosing message stays
 * framed, and a short list fails inside this function rather than desyncing the
 * operation after it.
 */
export function decodeFattr(reader: XdrReader, what = "fattr4"): DecodedFattr4 {
  const attrmask = readBitmap(reader, `${what}.attrmask`);
  const list = new XdrReader(reader.varOpaque(NFS4_MAX_ATTRLIST, `${what}.attr_vals`));
  const values: Fattr4Values = {};
  const unsupported: number[] = [];
  for (const bit of bitmapBits(attrmask)) {
    const codec = CODEC_BY_BIT.get(bit);
    if (codec === undefined) {
      unsupported.push(bit);
      continue;
    }
    // Everything after the first unknown attribute is unparseable, known bit or
    // not; the bits are still worth reporting, the bytes are not readable.
    if (unsupported.length === 0) {
      setValue(values, codec.key, codec.read(list));
    }
  }
  if (unsupported.length === 0) {
    list.end(`${what}.attr_vals`);
  }
  return { attrmask, values, unsupported };
}

/**
 * Encode a `fattr4` answering `requested`.
 *
 * Writes `requested ∩ supported ∩ available` — where "available" is a key
 * present in `values` — then the values themselves in ascending attribute
 * order. A requested attribute that is unsupported or missing is simply left
 * out of both halves, which is what RFC 8881 §18.7.3 requires of GETATTR.
 *
 * `supported` defaults to {@link GETABLE_ATTRS}, the reply direction. A client
 * building a SETATTR argument passes {@link SETTABLE_ATTRS} instead.
 *
 * Returns the bitmap actually written, which is what SETATTR echoes as
 * `attrsset`.
 */
export function encodeFattr(
  writer: XdrWriter,
  requested: Bitmap4,
  values: Fattr4Values,
  supported: Bitmap4 = GETABLE_ATTRS,
): number[] {
  const present: number[] = [];
  const list = new XdrWriter(256);
  // `ATTR_CODECS` is in ascending bit order, so one pass down it packs
  // `attr_vals` in the order §3.3.7 requires.
  for (const codec of ATTR_CODECS) {
    if (!bitmapHas(requested, codec.bit) || !bitmapHas(supported, codec.bit)) {
      continue;
    }
    const value = values[codec.key];
    if (value === undefined) {
      continue;
    }
    present.push(codec.bit);
    codec.write(list, value);
  }
  const attrmask = bitmapOf(present);
  writeBitmap(writer, attrmask);
  writer.varOpaque(list.bytes());
  return attrmask;
}

// ---------------------------------------------------------------------------
// the driver bridge
// ---------------------------------------------------------------------------

/**
 * `change` (bit 3) for a driver's stats: the later of mtime and ctime, in
 * nanoseconds since the epoch.
 *
 * RFC 8881 §5.8.1.4 lets a server answer with `time_metadata` "only if the file
 * system object cannot be updated more frequently than the resolution of
 * time_metadata", and the value is otherwise opaque — a client only ever asks
 * whether it differs from the one it cached. POSIX `ctime` moves for both data
 * and metadata changes, so it is the honest source; the `max` with mtime covers
 * a driver that maintains mtime and not ctime.
 *
 * The resolution this can distinguish is the driver's, one millisecond (which
 * is what `time_delta` says), not the nanosecond the units suggest: two writes
 * inside the same millisecond produce the same `change`. That is a property of
 * `StatsLike`'s `Date`-based timestamps and is declared rather than papered
 * over.
 */
export function changeOf(stats: StatsLike): bigint {
  const time = toTime4(Math.max(stats.mtimeMs, stats.ctimeMs));
  // Wrapped here rather than by the writer: `changeid4` is a `uint64_t`, and a
  // pre-1970 timestamp makes this product negative. The wrap is injective, and
  // the value is opaque to the client, so nothing is lost — but returning the
  // signed form would mean the `change` this computes and the `change` a client
  // decodes are different bigints for the same file.
  return BigInt.asUintN(64, time.seconds * 1_000_000_000n + BigInt(time.nseconds));
}

/** Extra facts a `StatsLike` cannot carry, for {@link fattr4Of}. */
export interface Fattr4ObjectOptions {
  /**
   * `fileid` (bit 20). Defaults to `stats.ino`, which together with the `fsid`
   * taken from `stats.dev` is the `(dev, ino)` pair that identifies the object.
   */
  fileid?: bigint | undefined;
  /** `filehandle` (bit 19) — the handle the session knows this object by. */
  filehandle?: Uint8Array | undefined;
  /** `fsid` (bit 8), when the session exports one identity for the whole mount. */
  fsid?: Fsid4 | undefined;
}

/**
 * A driver's `StatsLike` as the per-object half of a `fattr4`.
 *
 * Per-*filesystem* attributes (`supported_attrs`, the capability booleans, the
 * `statfs` numbers, the limits) are not here: they do not come from a stat, and
 * the session merges them in. See {@link fattr4FsOf} for the `statfs` ones.
 *
 * `mode` on the wire is **permission bits only** — RFC 8881 keeps the type in
 * its own `type` attribute (§5.8.1.2), exactly as `fattr3` keeps it in
 * `ftype3` — and sending `S_IFMT` bits along with it is the classic interop
 * bug it is there.
 */
export function fattr4Of(stats: StatsLike, options: Fattr4ObjectOptions = {}): Fattr4Values {
  const rdev = toU32(stats.rdev);
  return {
    type: ftype4Of(stats.mode),
    change: changeOf(stats),
    size: toU64(stats.size),
    fsid: options.fsid ?? { major: toU64(stats.dev), minor: 0n },
    fileid: options.fileid ?? toU64(stats.ino),
    filehandle: options.filehandle,
    mode: toU32(stats.mode) & 0o7777,
    numlinks: toU32(stats.nlink),
    owner: numericOwner(stats.uid),
    ownerGroup: numericOwner(stats.gid),
    // The same 8-bit split `../v3/protocol.ts` uses for `specdata3`: the two
    // transports hand a driver's `rdev` to a client the same way or a device
    // node changes number when the transport does.
    rawdev: { major: (rdev >>> 8) & 0xff_ff_ff, minor: rdev & 0xff },
    // Bytes actually consumed. `blocks` is in 512-byte units, as in `stat(2)`;
    // a driver that reports none gets its size back.
    spaceUsed: stats.blocks > 0 ? toU64(stats.blocks) * 512n : toU64(stats.size),
    timeAccess: toTime4(stats.atimeMs),
    timeMetadata: toTime4(stats.ctimeMs),
    timeModify: toTime4(stats.mtimeMs),
  };
}

/**
 * A driver's `StatsFsLike` as the `files_*` and `space_*` attributes.
 *
 * The same arithmetic NFSv3's FSSTAT does: block counts times the block size
 * for the byte totals, and `ffree` for both "free" and "available" inodes,
 * because `StatsFsLike` has no separate reservation for the privileged.
 */
export function fattr4FsOf(stats: StatsFsLike): Fattr4Values {
  const bsize = BigInt(Math.max(1, Math.trunc(stats.bsize) || 4096));
  return {
    filesAvail: toU64(stats.ffree),
    filesFree: toU64(stats.ffree),
    filesTotal: toU64(stats.files),
    spaceAvail: toU64(stats.bavail) * bsize,
    spaceFree: toU64(stats.bfree) * bsize,
    spaceTotal: toU64(stats.blocks) * bsize,
  };
}
