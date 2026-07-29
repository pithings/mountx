/**
 * NFSv4.1 COMPOUND framing and the stateless operations — a literal
 * transcription of RFC 8881 §16.2 and §18, both directions.
 *
 * Every argument and result struct is encoded *and* decoded, the same symmetry
 * `../v3/protocol.ts` keeps and for the same reason: the Tier-1 test client is
 * built from these exact functions, so the whole server can be driven through a
 * real socket with no kernel, no mount and no root.
 *
 * The XDR comes from **RFC 5662** (NFSv4.1 XDR Description), which is RFC
 * 8881's normative companion and the only place the wire layout is written
 * down; each codec repeats the declaration it implements and names the RFC 8881
 * section that describes it. Nothing is guessed and nothing is borrowed from a
 * host header.
 *
 * ## What NFSv4 changed, and what this file is shaped by
 *
 * NFSv3 was one RPC procedure per operation with the object named in every
 * argument. NFSv4 is **one** procedure, COMPOUND, carrying an array of
 * operations that run against a *current filehandle* the earlier operations in
 * the same array set (§16.2.3.1.1). So the arguments here are conspicuously
 * short — LOOKUP is a name and nothing else — and the `[CURRENT_FH: …]`
 * comments RFC 5662 puts in each struct are reproduced, because they are the
 * only record of what an operation actually acts on.
 *
 * Three consequences run through the file:
 *
 * - **A result is a union on `nfsstat4`.** Most ops carry a body only on
 *   `NFS4_OK` and nothing at all otherwise; a handful differ, and each says so
 *   where it is defined. `SETATTR4res` is the one that is not a union at all —
 *   it carries `attrsset` on *every* status, because a partially applied
 *   SETATTR has to say what it managed to set (§18.30.3).
 * - **The op number is on the wire twice**, once in `nfs_argop4` and once in
 *   `nfs_resop4`, and a client matches them up positionally. {@link Argop4} and
 *   {@link Resop4} keep the opcode beside the struct for exactly that reason.
 * - **Decoding an operation needs its opcode first.** There is no length prefix
 *   on an operation, so an opcode with no codec here is the end of the message:
 *   {@link opCodec4} throws {@link XdrError} naming the op rather than guessing
 *   how many bytes to skip.
 *
 * ## The codec table
 *
 * {@link OP_CODECS} maps `nfs_opnum4` → {@link OpCodec4}, one row per
 * operation, holding all four directions (`readArgs`/`writeArgs`/`readRes`/
 * `writeRes`). {@link readCompoundArgs} and friends do nothing but walk it.
 * Ops whose arguments are the XDR `void` arm — GETFH, LOOKUPP, PUTPUBFH,
 * PUTROOTFH, READLINK, RESTOREFH, SAVEFH, ILLEGAL — have `readArgs`/`writeArgs`
 * of `undefined`, which is the void arm and not a gap.
 *
 * **This file is built in two halves.** The stateless operations are here; the
 * state ones (EXCHANGE_ID, CREATE_SESSION, SEQUENCE, OPEN, READ, WRITE, LOCK,
 * …) are added to this same table, as more rows and more structs, and nothing
 * else has to change. Until they are, an opcode this table does not carry is a
 * decode failure that names the operation — `no codec for OP_SEQUENCE` — which
 * is what a half-built table should say, rather than a silent desync.
 *
 * Conventions: as in `../xdr.ts` — big-endian, 64-bit fields are `bigint`,
 * decoding is total and throws only {@link XdrError}, and every retained byte
 * string is copied by the reader that produced it.
 */

import {
  NF4BLK,
  NF4CHR,
  NF4LNK,
  NFS4_FHSIZE,
  NFS4_OK,
  NFS4_OTHER_SIZE,
  NFS4_VERIFIER_SIZE,
  OP_ACCESS,
  OP_COMMIT,
  OP_CREATE,
  OP_GETATTR,
  OP_GETFH,
  OP_ILLEGAL,
  OP_LINK,
  OP_LOOKUP,
  OP_LOOKUPP,
  OP_NVERIFY,
  OP_PUTFH,
  OP_PUTPUBFH,
  OP_PUTROOTFH,
  OP_READDIR,
  OP_READLINK,
  OP_REMOVE,
  OP_RENAME,
  OP_RESTOREFH,
  OP_SAVEFH,
  OP_SECINFO,
  OP_SECINFO_NO_NAME,
  OP_SETATTR,
  OP_VERIFY,
  opName4,
} from "./constants.ts";
import {
  decodeFattr,
  encodeFattr,
  KNOWN_ATTRS,
  readBitmap,
  readSpecData4,
  writeBitmap,
  writeSpecData4,
  type Bitmap4,
  type Fattr4Values,
  type SpecData4,
} from "./attr.ts";
import { XdrError, XdrReader, XdrWriter } from "../xdr.ts";

// ---------------------------------------------------------------------------
// decode limits
// ---------------------------------------------------------------------------
//
// Every one of these bounds an allocation whose size an attacker picks, which
// is the same job `XDR_MAX_ITEM` does in `../xdr.ts`. They are *codec* limits,
// deliberately loose: what a client may actually send is the session's
// `ca_maxoperations`/`ca_maxrequestsize` policy (RFC 8881 §18.36.3), answered
// with `NFS4ERR_TOO_MANY_OPS`/`NFS4ERR_REQ_TOO_BIG` rather than a decode
// failure. A codec that allocated from a hostile length before the session ever
// saw the request would make that policy unreachable.

/**
 * Longest COMPOUND `tag` accepted.
 *
 * RFC 8881 §16.2.3 leaves the tag entirely to the implementor — it exists for
 * packet sniffers — so there is no protocol maximum to transcribe. A kilobyte
 * is far past any debugging string and far below an allocation worth making.
 */
export const NFS4_MAX_TAG = 1024;

/**
 * Most operations one COMPOUND may carry, at decode time.
 *
 * The real limit is `ca_maxoperations`, negotiated per session and much
 * smaller. This is the allocation bound underneath it; `XdrReader.array` also
 * refuses any count that cannot fit in the bytes present, so a four-billion-op
 * array fails on the shorter of the two.
 */
export const NFS4_MAX_COMPOUND_OPS = 4096;

/** Longest `component4` (a single name). Matches the bound v3 puts on `filename3`. */
export const NFS4_MAX_COMPONENT = 1024;

/** Longest `linktext4` — a symlink target, bounded like v3's `nfspath3`. */
export const NFS4_MAX_LINKTEXT = 4096;

/** Most `entry4`s decoded from one READDIR reply. */
export const NFS4_MAX_READDIR_ENTRIES = 1 << 20;

/** Most `secinfo4` flavors in a SECINFO reply; v3 bounds `auth_flavors` the same. */
export const NFS4_MAX_SECINFO = 64;

/** Longest `sec_oid4` — a GSS mechanism OID is a handful of bytes. */
export const NFS4_MAX_SEC_OID = 1024;

/**
 * RPCSEC_GSS's `auth_flavor` (RFC 2203 §3), the value `secinfo4` switches on.
 *
 * RFC 5662 writes it as a comment above the union rather than a constant, and
 * it is the one flavor number this file needs. It is not an NFSv4 constant, so
 * it does not belong in `./constants.ts`; the natural home is `../rpc.ts`'s
 * `auth_flavor` list, but `../index.ts` re-exports that module wholesale and
 * NFSv4 is not on the public surface yet. It lives here, beside its only use,
 * until the surface question is settled.
 */
export const RPCSEC_GSS = 6;

// ---------------------------------------------------------------------------
// basic types (RFC 5662 §2)
// ---------------------------------------------------------------------------

/**
 * `struct stateid4 { uint32_t seqid; opaque other[12]; }` (RFC 8881 §3.3.12).
 *
 * Carried by SETATTR here, and by every open, lock and I/O operation the second
 * half of this file adds — which is why it is a base struct rather than part of
 * SETATTR's.
 */
export interface Stateid4 {
  seqid: number;
  /** `other[12]` — opaque to the client, the server's own state identity. */
  other: Uint8Array;
}

export function writeStateid(writer: XdrWriter, stateid: Stateid4): void {
  writer.u32(stateid.seqid);
  writer.fixedOpaque(stateid.other, NFS4_OTHER_SIZE);
}

export function readStateid(reader: XdrReader, what = "stateid4"): Stateid4 {
  return {
    seqid: reader.u32(`${what}.seqid`),
    // `fixedOpaque` copies; nothing downstream holds a view of the record.
    other: reader.fixedOpaque(NFS4_OTHER_SIZE, `${what}.other`),
  };
}

/**
 * `struct change_info4 { bool atomic; changeid4 before; changeid4 after; }`.
 *
 * NFSv4's answer to NFSv3's `wcc_data`, and a narrower one: instead of the
 * directory's whole pre- and post-operation attributes it carries only the
 * opaque `change` attribute either side, plus whether the pair was sampled
 * atomically with the operation (RFC 8881 §3.3.8). A client that saw `before`
 * matching its cache knows the cache was current, exactly as in v3.
 */
export interface ChangeInfo4 {
  atomic: boolean;
  before: bigint;
  after: bigint;
}

export function writeChangeInfo(writer: XdrWriter, cinfo: ChangeInfo4): void {
  writer.bool(cinfo.atomic);
  writer.u64(cinfo.before);
  writer.u64(cinfo.after);
}

export function readChangeInfo(reader: XdrReader, what = "change_info4"): ChangeInfo4 {
  return {
    atomic: reader.bool(`${what}.atomic`),
    before: reader.u64(`${what}.before`),
    after: reader.u64(`${what}.after`),
  };
}

/** `nfs_fh4` — `opaque<NFS4_FHSIZE>`, four times the room NFSv3's handle had. */
export function writeFh4(writer: XdrWriter, fh: Uint8Array): void {
  writer.varOpaque(fh);
}

export function readFh4(reader: XdrReader, what = "nfs_fh4"): Uint8Array {
  return reader.varOpaque(NFS4_FHSIZE, what);
}

/** `verifier4` — `opaque[NFS4_VERIFIER_SIZE]`, fixed at eight bytes. */
export function writeVerifier4(writer: XdrWriter, verifier: Uint8Array): void {
  writer.fixedOpaque(verifier, NFS4_VERIFIER_SIZE);
}

export function readVerifier4(reader: XdrReader, what = "verifier4"): Uint8Array {
  return reader.fixedOpaque(NFS4_VERIFIER_SIZE, what);
}

/** `component4` — one path element, `utf8str_cs`. */
export function readComponent4(reader: XdrReader, what = "component4"): string {
  return reader.string(NFS4_MAX_COMPONENT, what);
}

/**
 * `struct fattr4 { bitmap4 attrmask; attrlist4 attr_vals; }`, as an operation
 * carries it.
 *
 * The codec itself is `./attr.ts`'s; this is the shape the operations hold it
 * in. `attrmask` on the decode side is the mask exactly as it arrived, and on
 * the encode side is what to write — {@link writeFattr4} still intersects it
 * with what it has values for, so a mask can never claim an attribute the
 * `attr_vals` does not carry.
 */
export interface Fattr4 {
  attrmask: Bitmap4;
  values: Fattr4Values;
  /**
   * Decode only: set bits with no codec, ascending. Non-empty means the walk
   * stopped at the first of them and `values` holds only what was numbered
   * below it — see `./attr.ts`. Encoders ignore this field.
   */
  unsupported: number[];
}

/**
 * Write a `fattr4`.
 *
 * `supported` defaults to {@link KNOWN_ATTRS}, everything this codec can
 * write — which is the right ceiling for an *argument* (SETATTR needs the
 * set-only `time_*_set` pair, which `GETABLE_ATTRS` excludes). A reply's mask
 * is the session's to compute, from `GETABLE_ATTRS`.
 */
export function writeFattr4(
  writer: XdrWriter,
  attr: Fattr4,
  supported: Bitmap4 = KNOWN_ATTRS,
): void {
  encodeFattr(writer, attr.attrmask, attr.values, supported);
}

export function readFattr4(reader: XdrReader, what = "fattr4"): Fattr4 {
  return decodeFattr(reader, what);
}

/**
 * The result shape RFC 5662 spells `struct XXX4res { nfsstat4 status; }` — a
 * status and nothing else, whether it succeeded or not.
 *
 * Ten operations share it, which is what makes NFSv4's current-filehandle model
 * cheap: PUTFH, PUTPUBFH, PUTROOTFH, SAVEFH, RESTOREFH, LOOKUP and LOOKUPP all
 * answer by *changing the cursor*, so there is nothing to send back;
 * VERIFY/NVERIFY answer by the status alone; and ILLEGAL is a status by
 * definition.
 */
export interface Status4res {
  status: number;
}

export function writeStatusRes(writer: XdrWriter, res: Status4res): void {
  writer.u32(res.status);
}

export function readStatusRes(reader: XdrReader, what = "nfsstat4"): Status4res {
  return { status: reader.u32(what) };
}

// ---------------------------------------------------------------------------
// ACCESS (RFC 8881 §18.1)
// ---------------------------------------------------------------------------

/** `struct ACCESS4args { [CURRENT_FH: object] uint32_t access; }`. */
export interface Access4args {
  access: number;
}

/**
 * `union ACCESS4res switch (nfsstat4 status) { case NFS4_OK: ACCESS4resok; default: void; }`,
 * where `ACCESS4resok` is `{ uint32_t supported; uint32_t access; }`.
 *
 * The two words are not the same question: `supported` is which of the
 * requested bits the server was able to *evaluate*, `access` which of those it
 * grants. A server that cannot answer for a bit clears it in both.
 */
export interface Access4res {
  status: number;
  supported: number;
  access: number;
}

export function writeAccessArgs(writer: XdrWriter, args: Access4args): void {
  writer.u32(args.access);
}

export function readAccessArgs(reader: XdrReader): Access4args {
  return { access: reader.u32("ACCESS4args.access") };
}

export function writeAccessRes(writer: XdrWriter, res: Access4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writer.u32(res.supported);
    writer.u32(res.access);
  }
}

export function readAccessRes(reader: XdrReader): Access4res {
  const status = reader.u32("ACCESS4res.status");
  if (status !== NFS4_OK) {
    return { status, supported: 0, access: 0 };
  }
  return {
    status,
    supported: reader.u32("ACCESS4resok.supported"),
    access: reader.u32("ACCESS4resok.access"),
  };
}

// ---------------------------------------------------------------------------
// COMMIT (RFC 8881 §18.3)
// ---------------------------------------------------------------------------

/** `struct COMMIT4args { [CURRENT_FH: file] offset4 offset; count4 count; }`. */
export interface Commit4args {
  offset: bigint;
  count: number;
}

/** `union COMMIT4res` — `COMMIT4resok { verifier4 writeverf; }` on `NFS4_OK`. */
export interface Commit4res {
  status: number;
  writeverf: Uint8Array;
}

export function writeCommitArgs(writer: XdrWriter, args: Commit4args): void {
  writer.u64(args.offset);
  writer.u32(args.count);
}

export function readCommitArgs(reader: XdrReader): Commit4args {
  return {
    offset: reader.u64("COMMIT4args.offset"),
    count: reader.u32("COMMIT4args.count"),
  };
}

export function writeCommitRes(writer: XdrWriter, res: Commit4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeVerifier4(writer, res.writeverf);
  }
}

export function readCommitRes(reader: XdrReader): Commit4res {
  const status = reader.u32("COMMIT4res.status");
  return {
    status,
    writeverf:
      status === NFS4_OK
        ? readVerifier4(reader, "COMMIT4resok.writeverf")
        : new Uint8Array(NFS4_VERIFIER_SIZE),
  };
}

// ---------------------------------------------------------------------------
// CREATE (RFC 8881 §18.4)
// ---------------------------------------------------------------------------

/**
 * `union createtype4 switch (nfs_ftype4 type)`: `linktext4 linkdata` for
 * `NF4LNK`, `specdata4 devdata` for `NF4BLK`/`NF4CHR`, and `void` for
 * `NF4SOCK`/`NF4FIFO`/`NF4DIR` — and for everything else, which RFC 5662
 * annotates "server should return NFS4ERR_BADTYPE".
 *
 * **CREATE never makes a regular file.** That is OPEN's job in NFSv4 (§18.16),
 * because a new file needs a stateid; `NF4REG` here selects the default arm and
 * is a `NFS4ERR_BADTYPE`, not an oversight.
 */
export interface CreateType4 {
  /** `nfs_ftype4`. */
  type: number;
  /** `NF4LNK` only. */
  linkdata?: string | undefined;
  /** `NF4BLK` / `NF4CHR` only. */
  devdata?: SpecData4 | undefined;
}

/**
 * ```
 * struct CREATE4args {
 *         [CURRENT_FH: directory for creation]
 *         createtype4     objtype;
 *         component4      objname;
 *         fattr4          createattrs;
 * };
 * ```
 */
export interface Create4args {
  objtype: CreateType4;
  objname: string;
  createattrs: Fattr4;
}

/**
 * `union CREATE4res` — on `NFS4_OK`, `CREATE4resok { change_info4 cinfo;
 * bitmap4 attrset; }` and a new current filehandle (the created object).
 *
 * `attrset` is which of `createattrs` were actually applied, which is how a
 * client learns that the mode it asked for was ignored.
 */
export interface Create4res {
  status: number;
  cinfo: ChangeInfo4 | undefined;
  attrset: Bitmap4 | undefined;
}

export function writeCreateType(writer: XdrWriter, objtype: CreateType4): void {
  writer.u32(objtype.type);
  if (objtype.type === NF4LNK) {
    writer.string(objtype.linkdata ?? "");
  } else if (objtype.type === NF4BLK || objtype.type === NF4CHR) {
    writeSpecData4(writer, objtype.devdata ?? { major: 0, minor: 0 });
  }
  // Every other `nfs_ftype4` selects a void arm: nothing follows.
}

export function readCreateType(reader: XdrReader): CreateType4 {
  const type = reader.u32("createtype4.type");
  if (type === NF4LNK) {
    return { type, linkdata: reader.string(NFS4_MAX_LINKTEXT, "createtype4.linkdata") };
  }
  if (type === NF4BLK || type === NF4CHR) {
    return { type, devdata: readSpecData4(reader) };
  }
  return { type };
}

export function writeCreateArgs(writer: XdrWriter, args: Create4args): void {
  writeCreateType(writer, args.objtype);
  writer.string(args.objname);
  writeFattr4(writer, args.createattrs);
}

export function readCreateArgs(reader: XdrReader): Create4args {
  return {
    objtype: readCreateType(reader),
    objname: readComponent4(reader, "CREATE4args.objname"),
    createattrs: readFattr4(reader, "CREATE4args.createattrs"),
  };
}

export function writeCreateRes(writer: XdrWriter, res: Create4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeChangeInfo(writer, res.cinfo!);
    writeBitmap(writer, res.attrset ?? []);
  }
}

export function readCreateRes(reader: XdrReader): Create4res {
  const status = reader.u32("CREATE4res.status");
  if (status !== NFS4_OK) {
    return { status, cinfo: undefined, attrset: undefined };
  }
  return {
    status,
    cinfo: readChangeInfo(reader, "CREATE4resok.cinfo"),
    attrset: readBitmap(reader, "CREATE4resok.attrset"),
  };
}

// ---------------------------------------------------------------------------
// GETATTR (RFC 8881 §18.7)
// ---------------------------------------------------------------------------

/** `struct GETATTR4args { [CURRENT_FH: object] bitmap4 attr_request; }`. */
export interface Getattr4args {
  attrRequest: Bitmap4;
}

/** `union GETATTR4res` — `GETATTR4resok { fattr4 obj_attributes; }` on `NFS4_OK`. */
export interface Getattr4res {
  status: number;
  objAttributes: Fattr4 | undefined;
}

export function writeGetattrArgs(writer: XdrWriter, args: Getattr4args): void {
  writeBitmap(writer, args.attrRequest);
}

export function readGetattrArgs(reader: XdrReader): Getattr4args {
  return { attrRequest: readBitmap(reader, "GETATTR4args.attr_request") };
}

export function writeGetattrRes(writer: XdrWriter, res: Getattr4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeFattr4(writer, res.objAttributes!);
  }
}

export function readGetattrRes(reader: XdrReader): Getattr4res {
  const status = reader.u32("GETATTR4res.status");
  return {
    status,
    objAttributes:
      status === NFS4_OK ? readFattr4(reader, "GETATTR4resok.obj_attributes") : undefined,
  };
}

// ---------------------------------------------------------------------------
// GETFH (RFC 8881 §18.8)
// ---------------------------------------------------------------------------

/**
 * `union GETFH4res` — `GETFH4resok { nfs_fh4 object; }` on `NFS4_OK`.
 *
 * The arguments are the `void` arm of `nfs_argop4`: GETFH asks for the current
 * filehandle, and "current" is the whole argument.
 */
export interface Getfh4res {
  status: number;
  object: Uint8Array | undefined;
}

export function writeGetfhRes(writer: XdrWriter, res: Getfh4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeFh4(writer, res.object!);
  }
}

export function readGetfhRes(reader: XdrReader): Getfh4res {
  const status = reader.u32("GETFH4res.status");
  return {
    status,
    object: status === NFS4_OK ? readFh4(reader, "GETFH4resok.object") : undefined,
  };
}

// ---------------------------------------------------------------------------
// LINK (RFC 8881 §18.9)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct LINK4args {
 *         [SAVED_FH: source object]
 *         [CURRENT_FH: target directory]
 *         component4      newname;
 * };
 * ```
 *
 * Both objects come from the cursor: SAVEFH puts the file in the saved slot,
 * PUTFH the directory in the current one, and the name is all that is left.
 */
export interface Link4args {
  newname: string;
}

/** `union LINK4res` — `LINK4resok { change_info4 cinfo; }` on `NFS4_OK`. */
export interface Link4res {
  status: number;
  cinfo: ChangeInfo4 | undefined;
}

export function writeLinkArgs(writer: XdrWriter, args: Link4args): void {
  writer.string(args.newname);
}

export function readLinkArgs(reader: XdrReader): Link4args {
  return { newname: readComponent4(reader, "LINK4args.newname") };
}

export function writeLinkRes(writer: XdrWriter, res: Link4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeChangeInfo(writer, res.cinfo!);
  }
}

export function readLinkRes(reader: XdrReader): Link4res {
  const status = reader.u32("LINK4res.status");
  return {
    status,
    cinfo: status === NFS4_OK ? readChangeInfo(reader, "LINK4resok.cinfo") : undefined,
  };
}

// ---------------------------------------------------------------------------
// LOOKUP (RFC 8881 §18.13) / LOOKUPP (§18.14)
// ---------------------------------------------------------------------------

/** `struct LOOKUP4args { [CURRENT_FH: directory] component4 objname; }`. */
export interface Lookup4args {
  objname: string;
}

/** `struct LOOKUP4res { [New CURRENT_FH: object] nfsstat4 status; }`. */
export type Lookup4res = Status4res;

/**
 * `struct LOOKUPP4res { [new CURRENT_FH: parent directory] nfsstat4 status; }`.
 *
 * LOOKUPP takes the `void` arm: ".." needs no name.
 */
export type Lookupp4res = Status4res;

export function writeLookupArgs(writer: XdrWriter, args: Lookup4args): void {
  writer.string(args.objname);
}

export function readLookupArgs(reader: XdrReader): Lookup4args {
  return { objname: readComponent4(reader, "LOOKUP4args.objname") };
}

// ---------------------------------------------------------------------------
// VERIFY (RFC 8881 §18.31) / NVERIFY (§18.15)
// ---------------------------------------------------------------------------

/**
 * `struct VERIFY4args { [CURRENT_FH: object] fattr4 obj_attributes; }`,
 * and `NVERIFY4args` is the same struct.
 *
 * A bare `fattr4`, used as a *comparison*: VERIFY answers `NFS4ERR_NOT_SAME`
 * if the object's attributes differ from these, NVERIFY `NFS4ERR_SAME` if they
 * match — so a client can make the rest of a COMPOUND conditional on a
 * still-current cache without a second round trip.
 */
export interface Verify4args {
  objAttributes: Fattr4;
}

/** `struct NVERIFY4args` — the same shape, opposite sense. */
export type Nverify4args = Verify4args;

/** `struct VERIFY4res { nfsstat4 status; }` — and `NVERIFY4res` likewise. */
export type Verify4res = Status4res;
export type Nverify4res = Status4res;

export function writeVerifyArgs(writer: XdrWriter, args: Verify4args): void {
  writeFattr4(writer, args.objAttributes);
}

export function readVerifyArgs(reader: XdrReader): Verify4args {
  return { objAttributes: readFattr4(reader, "VERIFY4args.obj_attributes") };
}

// ---------------------------------------------------------------------------
// PUTFH (RFC 8881 §18.19) / PUTPUBFH (§18.20) / PUTROOTFH (§18.21)
// ---------------------------------------------------------------------------

/** `struct PUTFH4args { nfs_fh4 object; }` — the one op that names a handle. */
export interface Putfh4args {
  object: Uint8Array;
}

/** `struct PUTFH4res { nfsstat4 status; }`; on `NFS4_OK` the argument is now CURRENT_FH. */
export type Putfh4res = Status4res;
/** `struct PUTPUBFH4res` — void arguments, and the public filehandle becomes current. */
export type Putpubfh4res = Status4res;
/** `struct PUTROOTFH4res` — void arguments, and the root filehandle becomes current. */
export type Putrootfh4res = Status4res;

export function writePutfhArgs(writer: XdrWriter, args: Putfh4args): void {
  writeFh4(writer, args.object);
}

export function readPutfhArgs(reader: XdrReader): Putfh4args {
  return { object: readFh4(reader, "PUTFH4args.object") };
}

// ---------------------------------------------------------------------------
// READDIR (RFC 8881 §18.23)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct READDIR4args {
 *         [CURRENT_FH: directory]
 *         nfs_cookie4     cookie;
 *         verifier4       cookieverf;
 *         count4          dircount;
 *         count4          maxcount;
 *         bitmap4         attr_request;
 * };
 * ```
 *
 * NFSv3 had two calls, READDIR and READDIRPLUS; NFSv4 has one, and
 * `attr_request` is the difference — an empty bitmap is a plain readdir, a
 * populated one is READDIRPLUS. `dircount` budgets the names and cookies alone,
 * `maxcount` the whole reply.
 */
export interface Readdir4args {
  cookie: bigint;
  cookieverf: Uint8Array;
  dircount: number;
  maxcount: number;
  attrRequest: Bitmap4;
}

/**
 * ```
 * struct entry4 {
 *         nfs_cookie4     cookie;
 *         component4      name;
 *         fattr4          attrs;
 *         entry4          *nextentry;
 * };
 * ```
 *
 * The `*nextentry` pointer is XDR's linked list — a bool before each entry and
 * a `false` to end it — which is what `XdrReader.list`/`XdrWriter.list` speak.
 * A per-entry failure travels *inside* `attrs`, as the `rdattr_error`
 * attribute, so one unreadable entry does not fail the call.
 */
export interface Entry4 {
  cookie: bigint;
  name: string;
  attrs: Fattr4;
}

/** `struct dirlist4 { entry4 *entries; bool eof; }`. */
export interface DirList4 {
  entries: Entry4[];
  eof: boolean;
}

/** `union READDIR4res` — `READDIR4resok { verifier4 cookieverf; dirlist4 reply; }` on `NFS4_OK`. */
export interface Readdir4res {
  status: number;
  cookieverf: Uint8Array;
  reply: DirList4;
}

export function writeReaddirArgs(writer: XdrWriter, args: Readdir4args): void {
  writer.u64(args.cookie);
  writeVerifier4(writer, args.cookieverf);
  writer.u32(args.dircount);
  writer.u32(args.maxcount);
  writeBitmap(writer, args.attrRequest);
}

export function readReaddirArgs(reader: XdrReader): Readdir4args {
  return {
    cookie: reader.u64("READDIR4args.cookie"),
    cookieverf: readVerifier4(reader, "READDIR4args.cookieverf"),
    dircount: reader.u32("READDIR4args.dircount"),
    maxcount: reader.u32("READDIR4args.maxcount"),
    attrRequest: readBitmap(reader, "READDIR4args.attr_request"),
  };
}

export function writeReaddirRes(writer: XdrWriter, res: Readdir4res): void {
  writer.u32(res.status);
  if (res.status !== NFS4_OK) {
    return;
  }
  writeVerifier4(writer, res.cookieverf);
  writer.list(res.reply.entries, (w, entry) => {
    w.u64(entry.cookie);
    w.string(entry.name);
    writeFattr4(w, entry.attrs);
  });
  writer.bool(res.reply.eof);
}

export function readReaddirRes(reader: XdrReader): Readdir4res {
  const status = reader.u32("READDIR4res.status");
  if (status !== NFS4_OK) {
    return {
      status,
      cookieverf: new Uint8Array(NFS4_VERIFIER_SIZE),
      reply: { entries: [], eof: false },
    };
  }
  const cookieverf = readVerifier4(reader, "READDIR4resok.cookieverf");
  const entries = reader.list<Entry4>(
    (r) => ({
      cookie: r.u64("entry4.cookie"),
      name: readComponent4(r, "entry4.name"),
      attrs: readFattr4(r, "entry4.attrs"),
    }),
    NFS4_MAX_READDIR_ENTRIES,
    "dirlist4",
  );
  return { status, cookieverf, reply: { entries, eof: reader.bool("dirlist4.eof") } };
}

// ---------------------------------------------------------------------------
// READLINK (RFC 8881 §18.24)
// ---------------------------------------------------------------------------

/**
 * `union READLINK4res` — `READLINK4resok { linktext4 link; }` on `NFS4_OK`.
 *
 * Void arguments: the link is the current filehandle.
 */
export interface Readlink4res {
  status: number;
  link: string | undefined;
}

export function writeReadlinkRes(writer: XdrWriter, res: Readlink4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writer.string(res.link!);
  }
}

export function readReadlinkRes(reader: XdrReader): Readlink4res {
  const status = reader.u32("READLINK4res.status");
  return {
    status,
    link: status === NFS4_OK ? reader.string(NFS4_MAX_LINKTEXT, "READLINK4resok.link") : undefined,
  };
}

// ---------------------------------------------------------------------------
// REMOVE (RFC 8881 §18.25)
// ---------------------------------------------------------------------------

/**
 * `struct REMOVE4args { [CURRENT_FH: directory] component4 target; }`.
 *
 * One operation for both of NFSv3's REMOVE and RMDIR: the type of the target
 * decides, not the opcode.
 */
export interface Remove4args {
  target: string;
}

/** `union REMOVE4res` — `REMOVE4resok { change_info4 cinfo; }` on `NFS4_OK`. */
export interface Remove4res {
  status: number;
  cinfo: ChangeInfo4 | undefined;
}

export function writeRemoveArgs(writer: XdrWriter, args: Remove4args): void {
  writer.string(args.target);
}

export function readRemoveArgs(reader: XdrReader): Remove4args {
  return { target: readComponent4(reader, "REMOVE4args.target") };
}

export function writeRemoveRes(writer: XdrWriter, res: Remove4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeChangeInfo(writer, res.cinfo!);
  }
}

export function readRemoveRes(reader: XdrReader): Remove4res {
  const status = reader.u32("REMOVE4res.status");
  return {
    status,
    cinfo: status === NFS4_OK ? readChangeInfo(reader, "REMOVE4resok.cinfo") : undefined,
  };
}

// ---------------------------------------------------------------------------
// RENAME (RFC 8881 §18.26)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct RENAME4args {
 *         [SAVED_FH: source directory]
 *         component4      oldname;
 *         [CURRENT_FH: target directory]
 *         component4      newname;
 * };
 * ```
 */
export interface Rename4args {
  oldname: string;
  newname: string;
}

/**
 * `union RENAME4res` — on `NFS4_OK`, `RENAME4resok { change_info4
 * source_cinfo; change_info4 target_cinfo; }`.
 *
 * Two `change_info4`s because two directories changed, and they are *not*
 * interchangeable: source first, target second.
 */
export interface Rename4res {
  status: number;
  sourceCinfo: ChangeInfo4 | undefined;
  targetCinfo: ChangeInfo4 | undefined;
}

export function writeRenameArgs(writer: XdrWriter, args: Rename4args): void {
  writer.string(args.oldname);
  writer.string(args.newname);
}

export function readRenameArgs(reader: XdrReader): Rename4args {
  return {
    oldname: readComponent4(reader, "RENAME4args.oldname"),
    newname: readComponent4(reader, "RENAME4args.newname"),
  };
}

export function writeRenameRes(writer: XdrWriter, res: Rename4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeChangeInfo(writer, res.sourceCinfo!);
    writeChangeInfo(writer, res.targetCinfo!);
  }
}

export function readRenameRes(reader: XdrReader): Rename4res {
  const status = reader.u32("RENAME4res.status");
  if (status !== NFS4_OK) {
    return { status, sourceCinfo: undefined, targetCinfo: undefined };
  }
  return {
    status,
    sourceCinfo: readChangeInfo(reader, "RENAME4resok.source_cinfo"),
    targetCinfo: readChangeInfo(reader, "RENAME4resok.target_cinfo"),
  };
}

// ---------------------------------------------------------------------------
// RESTOREFH (RFC 8881 §18.27) / SAVEFH (§18.28)
// ---------------------------------------------------------------------------

/** `struct RESTOREFH4res { nfsstat4 status; }` — void arguments; saved becomes current. */
export type Restorefh4res = Status4res;
/** `struct SAVEFH4res { nfsstat4 status; }` — void arguments; current becomes saved. */
export type Savefh4res = Status4res;

// ---------------------------------------------------------------------------
// SECINFO (RFC 8881 §18.29) / SECINFO_NO_NAME (§18.45)
// ---------------------------------------------------------------------------

/** `struct SECINFO4args { [CURRENT_FH: directory] component4 name; }`. */
export interface Secinfo4args {
  name: string;
}

/**
 * `struct rpcsec_gss_info { sec_oid4 oid; qop4 qop; rpc_gss_svc_t service; }`
 * (RFC 5662 §2, from RFC 2203).
 */
export interface RpcsecGssInfo {
  oid: Uint8Array;
  qop: number;
  service: number;
}

/**
 * `union secinfo4 switch (uint32_t flavor) { case RPCSEC_GSS:
 * rpcsec_gss_info flavor_info; default: void; }`.
 *
 * The body exists **only** under {@link RPCSEC_GSS}; `AUTH_NONE` and `AUTH_SYS`
 * are the bare flavor number. This server never emits the GSS arm — RPCSEC_GSS
 * is out of scope — and still has to decode it, because a SECINFO reply from
 * any other server may carry it and the Tier-1 client reads those with this
 * same function.
 */
export interface SecInfo4 {
  flavor: number;
  /** Present only when `flavor` is `RPCSEC_GSS`. */
  info?: RpcsecGssInfo | undefined;
}

/**
 * `union SECINFO4res` — on `NFS4_OK`, `SECINFO4resok`, which is
 * `typedef secinfo4 SECINFO4resok<>`: a counted array and nothing wrapping it.
 *
 * `SECINFO_NO_NAME4res` is `typedef SECINFO4res` — the same struct, byte for
 * byte, which is why the table below points both ops at these two functions.
 */
export interface Secinfo4res {
  status: number;
  flavors: SecInfo4[];
}

/** `typedef secinfo_style4 SECINFO_NO_NAME4args` — a bare enum on the wire. */
export interface SecinfoNoName4args {
  /** `secinfo_style4`: `SECINFO_STYLE4_CURRENT_FH` or `SECINFO_STYLE4_PARENT`. */
  style: number;
}

/** `typedef SECINFO4res SECINFO_NO_NAME4res`. */
export type SecinfoNoName4res = Secinfo4res;

export function writeSecinfoArgs(writer: XdrWriter, args: Secinfo4args): void {
  writer.string(args.name);
}

export function readSecinfoArgs(reader: XdrReader): Secinfo4args {
  return { name: readComponent4(reader, "SECINFO4args.name") };
}

export function writeSecInfo(writer: XdrWriter, secinfo: SecInfo4): void {
  writer.u32(secinfo.flavor);
  if (secinfo.flavor === RPCSEC_GSS) {
    const info = secinfo.info ?? { oid: new Uint8Array(0), qop: 0, service: 0 };
    writer.varOpaque(info.oid);
    writer.u32(info.qop);
    writer.u32(info.service);
  }
}

export function readSecInfo(reader: XdrReader): SecInfo4 {
  const flavor = reader.u32("secinfo4.flavor");
  if (flavor !== RPCSEC_GSS) {
    return { flavor };
  }
  return {
    flavor,
    info: {
      // `varOpaque` copies, so the OID does not point into the record.
      oid: reader.varOpaque(NFS4_MAX_SEC_OID, "rpcsec_gss_info.oid"),
      qop: reader.u32("rpcsec_gss_info.qop"),
      service: reader.u32("rpcsec_gss_info.service"),
    },
  };
}

export function writeSecinfoRes(writer: XdrWriter, res: Secinfo4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writer.array(res.flavors, writeSecInfo);
  }
}

export function readSecinfoRes(reader: XdrReader): Secinfo4res {
  const status = reader.u32("SECINFO4res.status");
  return {
    status,
    flavors: status === NFS4_OK ? reader.array(readSecInfo, NFS4_MAX_SECINFO, "SECINFO4resok") : [],
  };
}

export function writeSecinfoNoNameArgs(writer: XdrWriter, args: SecinfoNoName4args): void {
  writer.u32(args.style);
}

export function readSecinfoNoNameArgs(reader: XdrReader): SecinfoNoName4args {
  return { style: reader.u32("SECINFO_NO_NAME4args.style") };
}

// ---------------------------------------------------------------------------
// SETATTR (RFC 8881 §18.30)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct SETATTR4args {
 *         [CURRENT_FH: target object]
 *         stateid4        stateid;
 *         fattr4          obj_attributes;
 * };
 * ```
 *
 * The stateid is there for one attribute: `size`. Truncating a file is a write,
 * so it needs the open state that authorizes one; every other attribute is set
 * with the anonymous stateid.
 */
export interface Setattr4args {
  stateid: Stateid4;
  objAttributes: Fattr4;
}

/**
 * `struct SETATTR4res { nfsstat4 status; bitmap4 attrsset; }`.
 *
 * **Not a union.** Alone among the operations here, SETATTR carries its body on
 * *every* status, because a SETATTR that failed part-way still has to say which
 * attributes it managed to set (RFC 8881 §18.30.3) — a client that assumed
 * "error means nothing changed" would keep a stale cache. A decoder that
 * skipped `attrsset` on failure would desync the rest of the COMPOUND.
 */
export interface Setattr4res {
  status: number;
  attrsset: Bitmap4;
}

export function writeSetattrArgs(writer: XdrWriter, args: Setattr4args): void {
  writeStateid(writer, args.stateid);
  writeFattr4(writer, args.objAttributes);
}

export function readSetattrArgs(reader: XdrReader): Setattr4args {
  return {
    stateid: readStateid(reader, "SETATTR4args.stateid"),
    objAttributes: readFattr4(reader, "SETATTR4args.obj_attributes"),
  };
}

export function writeSetattrRes(writer: XdrWriter, res: Setattr4res): void {
  writer.u32(res.status);
  writeBitmap(writer, res.attrsset);
}

export function readSetattrRes(reader: XdrReader): Setattr4res {
  return {
    status: reader.u32("SETATTR4res.status"),
    attrsset: readBitmap(reader, "SETATTR4res.attrsset"),
  };
}

// ---------------------------------------------------------------------------
// ILLEGAL (RFC 8881 §18.52)
// ---------------------------------------------------------------------------

/**
 * `struct ILLEGAL4res { nfsstat4 status; }`, with void arguments.
 *
 * Not an operation a client sends: it is what a *server* echoes for an opcode
 * outside the legal range, with `NFS4ERR_OP_ILLEGAL` (§16.2.3). It is in the
 * table because the `nfs_argop4` union does have an `OP_ILLEGAL: void` arm, so
 * a client that sends 10044 deliberately gets decoded and answered rather than
 * dropped.
 */
export type Illegal4res = Status4res;

// ---------------------------------------------------------------------------
// the operation table
// ---------------------------------------------------------------------------

/** Every argument struct this table can carry. */
export type Argop4Value =
  | Access4args
  | Commit4args
  | Create4args
  | Getattr4args
  | Link4args
  | Lookup4args
  | Putfh4args
  | Readdir4args
  | Remove4args
  | Rename4args
  | Secinfo4args
  | SecinfoNoName4args
  | Setattr4args
  | Verify4args;

/** Every result struct this table can carry. Each one starts with its `status`. */
export type Resop4Value =
  | Access4res
  | Commit4res
  | Create4res
  | Getattr4res
  | Getfh4res
  | Link4res
  | Readdir4res
  | Readlink4res
  | Remove4res
  | Rename4res
  | Secinfo4res
  | Setattr4res
  | Status4res;

/**
 * One operation's four codecs.
 *
 * `readArgs`/`writeArgs` are `undefined` for the operations whose `nfs_argop4`
 * arm is `void`. That is the arm, not a missing implementation: `writeArgop4`
 * writes the opcode and stops, and `readArgop4` reads the opcode and stops.
 */
export interface OpCodec4 {
  /** `nfs_opnum4`. */
  readonly op: number;
  /** `OP_LOOKUP`, for error messages. */
  readonly name: string;
  readonly readArgs: ((reader: XdrReader) => Argop4Value) | undefined;
  readonly writeArgs: ((writer: XdrWriter, args: Argop4Value) => void) | undefined;
  readonly readRes: (reader: XdrReader) => Resop4Value;
  readonly writeRes: (writer: XdrWriter, res: Resop4Value) => void;
}

/**
 * One row of the table, type-checked against its own structs at the point of
 * definition.
 *
 * The casts are on the two *writers*, and are the same erasure `./attr.ts`'s
 * `attr()` needs: a writer for one operation takes that operation's struct,
 * which under `strictFunctionTypes` is not assignable to a writer of the union.
 * The readers need none — they *return* a member of the union.
 */
function op4<A extends Argop4Value, R extends Resop4Value>(
  op: number,
  args: { read: (reader: XdrReader) => A; write: (writer: XdrWriter, args: A) => void } | undefined,
  res: { read: (reader: XdrReader) => R; write: (writer: XdrWriter, res: R) => void },
): OpCodec4 {
  return {
    op,
    name: opName4(op),
    readArgs: args?.read,
    writeArgs: args?.write as OpCodec4["writeArgs"],
    readRes: res.read,
    writeRes: res.write as OpCodec4["writeRes"],
  };
}

/** The status-only result, as a table row's `res` half. */
const STATUS_RES = { read: readStatusRes, write: writeStatusRes };

/**
 * Every operation this file implements, in `nfs_opnum4` order.
 *
 * The state operations join this list; nothing else changes when they do.
 */
const OP_CODEC_LIST: readonly OpCodec4[] = [
  op4(
    OP_ACCESS,
    { read: readAccessArgs, write: writeAccessArgs },
    { read: readAccessRes, write: writeAccessRes },
  ),
  op4(
    OP_COMMIT,
    { read: readCommitArgs, write: writeCommitArgs },
    { read: readCommitRes, write: writeCommitRes },
  ),
  op4(
    OP_CREATE,
    { read: readCreateArgs, write: writeCreateArgs },
    { read: readCreateRes, write: writeCreateRes },
  ),
  op4(
    OP_GETATTR,
    { read: readGetattrArgs, write: writeGetattrArgs },
    { read: readGetattrRes, write: writeGetattrRes },
  ),
  // GETFH: `case OP_GETFH: void;` in `nfs_argop4`.
  op4(OP_GETFH, undefined, { read: readGetfhRes, write: writeGetfhRes }),
  op4(
    OP_LINK,
    { read: readLinkArgs, write: writeLinkArgs },
    { read: readLinkRes, write: writeLinkRes },
  ),
  op4(OP_LOOKUP, { read: readLookupArgs, write: writeLookupArgs }, STATUS_RES),
  op4(OP_LOOKUPP, undefined, STATUS_RES),
  op4(OP_NVERIFY, { read: readVerifyArgs, write: writeVerifyArgs }, STATUS_RES),
  op4(OP_PUTFH, { read: readPutfhArgs, write: writePutfhArgs }, STATUS_RES),
  op4(OP_PUTPUBFH, undefined, STATUS_RES),
  op4(OP_PUTROOTFH, undefined, STATUS_RES),
  op4(
    OP_READDIR,
    { read: readReaddirArgs, write: writeReaddirArgs },
    { read: readReaddirRes, write: writeReaddirRes },
  ),
  op4(OP_READLINK, undefined, { read: readReadlinkRes, write: writeReadlinkRes }),
  op4(
    OP_REMOVE,
    { read: readRemoveArgs, write: writeRemoveArgs },
    { read: readRemoveRes, write: writeRemoveRes },
  ),
  op4(
    OP_RENAME,
    { read: readRenameArgs, write: writeRenameArgs },
    { read: readRenameRes, write: writeRenameRes },
  ),
  op4(OP_RESTOREFH, undefined, STATUS_RES),
  op4(OP_SAVEFH, undefined, STATUS_RES),
  op4(
    OP_SECINFO,
    { read: readSecinfoArgs, write: writeSecinfoArgs },
    { read: readSecinfoRes, write: writeSecinfoRes },
  ),
  op4(
    OP_SETATTR,
    { read: readSetattrArgs, write: writeSetattrArgs },
    { read: readSetattrRes, write: writeSetattrRes },
  ),
  op4(OP_VERIFY, { read: readVerifyArgs, write: writeVerifyArgs }, STATUS_RES),
  op4(
    OP_SECINFO_NO_NAME,
    { read: readSecinfoNoNameArgs, write: writeSecinfoNoNameArgs },
    // `typedef SECINFO4res SECINFO_NO_NAME4res` — the same bytes, so the same
    // pair of functions.
    { read: readSecinfoRes, write: writeSecinfoRes },
  ),
  // ILLEGAL: void arguments, a bare status back.
  op4(OP_ILLEGAL, undefined, STATUS_RES),
];

/** `nfs_opnum4` → its codecs. */
export const OP_CODECS: ReadonlyMap<number, OpCodec4> = new Map(
  OP_CODEC_LIST.map((codec) => [codec.op, codec]),
);

/**
 * The codecs for an opcode.
 *
 * Throws {@link XdrError} naming the operation for anything this table does not
 * carry — an opcode NFSv4.1 defines but this file has not reached yet, and an
 * opcode that is not an operation at all. Both are the end of the message
 * either way: an operation carries no length, so there is nothing to skip.
 */
export function opCodec4(op: number): OpCodec4 {
  const codec = OP_CODECS.get(op);
  if (codec === undefined) {
    throw new XdrError(`no codec for ${opName4(op)}`);
  }
  return codec;
}

// ---------------------------------------------------------------------------
// COMPOUND (RFC 8881 §16.2)
// ---------------------------------------------------------------------------

/**
 * `union nfs_argop4 switch (nfs_opnum4 argop)` — one operation's opcode and
 * arguments.
 *
 * `args` is `undefined` exactly when the opcode's arm is `void`.
 */
export interface Argop4 {
  op: number;
  args: Argop4Value | undefined;
}

/** `union nfs_resop4 switch (nfs_opnum4 resop)` — one operation's opcode and result. */
export interface Resop4 {
  op: number;
  res: Resop4Value;
}

/**
 * ```
 * struct COMPOUND4args {
 *         utf8str_cs      tag;
 *         uint32_t        minorversion;
 *         nfs_argop4      argarray<>;
 * };
 * ```
 *
 * `minorversion` is 1 for NFSv4.1 and is the *only* place the minor version
 * appears — the RPC header says version 4 and no more (RFC 8881 §16.2.3).
 */
export interface Compound4args {
  tag: string;
  minorversion: number;
  argarray: Argop4[];
}

/**
 * ```
 * struct COMPOUND4res {
 *         nfsstat4        status;
 *         utf8str_cs      tag;
 *         nfs_resop4      resarray<>;
 * };
 * ```
 *
 * `status` is the status of the *last* operation executed, which is the failing
 * one when the array stops early; `resarray` holds only the operations that
 * ran. The tag SHOULD be the one the request carried.
 */
export interface Compound4res {
  status: number;
  tag: string;
  resarray: Resop4[];
}

export function writeArgop4(writer: XdrWriter, argop: Argop4): void {
  const codec = opCodec4(argop.op);
  writer.u32(argop.op);
  if (codec.writeArgs === undefined) {
    return;
  }
  if (argop.args === undefined) {
    throw new XdrError(`${codec.name} takes arguments, and none were given`);
  }
  codec.writeArgs(writer, argop.args);
}

export function readArgop4(reader: XdrReader): Argop4 {
  const op = reader.u32("nfs_argop4.argop");
  const codec = opCodec4(op);
  return { op, args: codec.readArgs?.(reader) };
}

export function writeResop4(writer: XdrWriter, resop: Resop4): void {
  const codec = opCodec4(resop.op);
  writer.u32(resop.op);
  codec.writeRes(writer, resop.res);
}

export function readResop4(reader: XdrReader): Resop4 {
  const op = reader.u32("nfs_resop4.resop");
  const codec = opCodec4(op);
  return { op, res: codec.readRes(reader) };
}

export function writeCompoundArgs(writer: XdrWriter, args: Compound4args): void {
  writer.string(args.tag);
  writer.u32(args.minorversion);
  writer.array(args.argarray, writeArgop4);
}

export function readCompoundArgs(reader: XdrReader): Compound4args {
  return {
    tag: reader.string(NFS4_MAX_TAG, "COMPOUND4args.tag"),
    minorversion: reader.u32("COMPOUND4args.minorversion"),
    argarray: reader.array(readArgop4, NFS4_MAX_COMPOUND_OPS, "COMPOUND4args.argarray"),
  };
}

export function writeCompoundRes(writer: XdrWriter, res: Compound4res): void {
  writer.u32(res.status);
  writer.string(res.tag);
  writer.array(res.resarray, writeResop4);
}

export function readCompoundRes(reader: XdrReader): Compound4res {
  return {
    status: reader.u32("COMPOUND4res.status"),
    tag: reader.string(NFS4_MAX_TAG, "COMPOUND4res.tag"),
    resarray: reader.array(readResop4, NFS4_MAX_COMPOUND_OPS, "COMPOUND4res.resarray"),
  };
}
