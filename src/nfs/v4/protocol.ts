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
 *   `NFS4_OK` and nothing at all otherwise; three do not, and each says so
 *   where it is defined. `SETATTR4res` is not a union at all — it carries
 *   `attrsset` on *every* status, because a partially applied SETATTR has to
 *   say what it managed to set (§18.30.3). `LOCK4res` and `LOCKT4res` name a
 *   second case arm, `NFS4ERR_DENIED`, carrying the `LOCK4denied` that
 *   describes the conflicting lock (§18.10.2, §18.11.2). A decoder that
 *   assumed "not `NFS4_OK`, so nothing follows" would desync the rest of the
 *   COMPOUND on all three.
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
 * The table holds the stateless operations *and* the state ones — EXCHANGE_ID,
 * CREATE_SESSION, SEQUENCE, OPEN, READ, WRITE, LOCK and the rest. It does not
 * hold the optional operations this server will never implement (DELEGRETURN,
 * OPENATTR, GETDEVICEINFO, the LAYOUT family, …); see {@link OP_CODEC_LIST} for
 * why that absence is the design and not a gap.
 *
 * **A union with no `default` arm refuses an unknown discriminant**, in both
 * directions, with {@link XdrError}. XDR says an unmatched discriminant in such
 * a union is a malformed message, and several of the unions below are written
 * that way on purpose — `createhow4`, `open_claim4`, `open_delegation4`,
 * `nfs_space_limit4`, `state_protect4_a`/`_r`, `callback_sec_parms4`. Guessing a
 * void arm for them would silently swallow the rest of the operation. The
 * unions that *do* declare a default (`openflag4`, `open_none_delegation4`,
 * `createtype4`, `secinfo4`) read and write nothing for it, which is the arm.
 *
 * Conventions: as in `../xdr.ts` — big-endian, 64-bit fields are `bigint`,
 * decoding is total and throws only {@link XdrError}, and every retained byte
 * string is copied by the reader that produced it.
 */

import {
  CLAIM_DELEG_CUR_FH,
  CLAIM_DELEG_PREV_FH,
  CLAIM_DELEGATE_CUR,
  CLAIM_DELEGATE_PREV,
  CLAIM_FH,
  CLAIM_NULL,
  CLAIM_PREVIOUS,
  EXCLUSIVE4,
  EXCLUSIVE4_1,
  GUARDED4,
  NF4BLK,
  NF4CHR,
  NF4LNK,
  NFS4_FHSIZE,
  NFS4_OK,
  NFS4_OPAQUE_LIMIT,
  NFS4_OTHER_SIZE,
  NFS4_SESSIONID_SIZE,
  NFS4_VERIFIER_SIZE,
  NFS4ERR_DENIED,
  NFS_LIMIT_BLOCKS,
  NFS_LIMIT_SIZE,
  OP_ACCESS,
  OP_BACKCHANNEL_CTL,
  OP_BIND_CONN_TO_SESSION,
  OP_CLOSE,
  OP_COMMIT,
  OP_CREATE,
  OP_CREATE_SESSION,
  OP_DESTROY_CLIENTID,
  OP_DESTROY_SESSION,
  OP_EXCHANGE_ID,
  OP_FREE_STATEID,
  OP_GETATTR,
  OP_GETFH,
  OP_ILLEGAL,
  OP_LINK,
  OP_LOCK,
  OP_LOCKT,
  OP_LOCKU,
  OP_LOOKUP,
  OP_LOOKUPP,
  OP_NVERIFY,
  OP_OPEN,
  OP_OPEN_DOWNGRADE,
  OP_PUTFH,
  OP_PUTPUBFH,
  OP_PUTROOTFH,
  OP_READ,
  OP_READDIR,
  OP_READLINK,
  OP_RECLAIM_COMPLETE,
  OP_REMOVE,
  OP_RENAME,
  OP_RESTOREFH,
  OP_SAVEFH,
  OP_SECINFO,
  OP_SECINFO_NO_NAME,
  OP_SEQUENCE,
  OP_SETATTR,
  OP_TEST_STATEID,
  OP_VERIFY,
  OP_WRITE,
  OPEN4_CREATE,
  OPEN_DELEGATE_NONE,
  OPEN_DELEGATE_NONE_EXT,
  OPEN_DELEGATE_READ,
  OPEN_DELEGATE_WRITE,
  opName4,
  SP4_MACH_CRED,
  SP4_NONE,
  SP4_SSV,
  UNCHECKED4,
  WND4_CONTENTION,
  WND4_RESOURCE,
} from "./constants.ts";
import {
  decodeFattr,
  encodeFattr,
  KNOWN_ATTRS,
  NFS4_MAX_OWNER,
  readBitmap,
  readSpecData4,
  readTime4,
  writeBitmap,
  writeSpecData4,
  writeTime4,
  type Bitmap4,
  type Fattr4Values,
  type NfsTime4,
  type SpecData4,
} from "./attr.ts";
import { AUTH_NONE, AUTH_SYS, encodeAuthSys, type AuthSysParams } from "../rpc.ts";
import { XDR_MAX_ITEM, XdrError, XdrReader, XdrWriter } from "../xdr.ts";

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
 * Most `callback_sec_parms4`s in one CREATE_SESSION or BACKCHANNEL_CTL.
 *
 * `csa_sec_parms<>` and `bca_sec_parms<>` are unbounded in the XDR; a client
 * offering the backchannel more than a handful of flavors is describing a
 * configuration nobody has, and each entry can carry an `authsys_parms` with a
 * machine name and sixteen gids behind it.
 */
export const NFS4_MAX_SEC_PARMS = 16;

/**
 * Most stateids in one TEST_STATEID, in both directions.
 *
 * `ts_stateids<>` and `tsr_status_codes<>` are unbounded too, and this is the
 * one place a client hands the server a list whose only cost is the list.
 * `XdrReader.array` also refuses a count larger than the bytes present can
 * hold, so a four-billion-entry claim dies on the shorter of the two.
 */
export const NFS4_MAX_TEST_STATEIDS = 4096;

/** Longest `gsshandle4_t` — an RPCSEC_GSS context handle. */
export const NFS4_MAX_GSS_HANDLE = 1024;

/** Most `gsshandle4_t`s in an `ssv_prot_info4`, and most SSV algorithm OIDs. */
export const NFS4_MAX_SSV_LIST = 64;

/**
 * `nfs_impl_id4<1>` and `ca_rdma_ird<1>` — arrays the XDR bounds at one.
 *
 * Both are XDR's way of spelling "optional, but not with the optional's
 * pointer": zero elements or one, never two. The bound is the declaration, so
 * a two-element array is a malformed message and not a policy choice.
 */
export const NFS4_MAX_OPTIONAL_ONE = 1;

/**
 * Longest `machinename` in an `authsys_parms` (RFC 5531 Appendix A: `string
 * machinename<255>`).
 *
 * An RPC constant rather than an NFS one, and the same bound `../rpc.ts`'s
 * `decodeAuthSys` applies — see {@link readAuthSysParms} for why the decode is
 * repeated here at all.
 */
export const NFS4_MAX_MACHINE_NAME = 255;

/** `gids<16>` in an `authsys_parms` (RFC 5531 Appendix A). */
export const NFS4_MAX_AUTHSYS_GIDS = 16;

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

/**
 * `typedef opaque sessionid4[NFS4_SESSIONID_SIZE]` (RFC 8881 §3.2) — sixteen
 * bytes, fixed, and the identity every 4.1 request carries.
 *
 * Fixed rather than counted, so there is no length word: a client that sent
 * fifteen bytes would desync the operation after it, which is why the size is
 * transcribed rather than taken from the value being written.
 */
export function writeSessionId4(writer: XdrWriter, sessionid: Uint8Array): void {
  writer.fixedOpaque(sessionid, NFS4_SESSIONID_SIZE);
}

export function readSessionId4(reader: XdrReader, what = "sessionid4"): Uint8Array {
  // `fixedOpaque` copies; a session ID outlives the record it arrived in.
  return reader.fixedOpaque(NFS4_SESSIONID_SIZE, what);
}

/**
 * `struct state_owner4 { clientid4 clientid; opaque owner<NFS4_OPAQUE_LIMIT>; }`
 * (RFC 8881 §3.3.10).
 *
 * The client's own name for a piece of state, and opaque to the server in the
 * strong sense: two `state_owner4`s are the same owner exactly when both fields
 * match byte for byte. `open_owner4` and `lock_owner4` are typedefs of it
 * (§3.3.10.1, §3.3.10.2) and are the same bytes on the wire.
 */
export interface StateOwner4 {
  clientid: bigint;
  owner: Uint8Array;
}

/** `typedef state_owner4 open_owner4` (RFC 8881 §3.3.10.1). */
export type OpenOwner4 = StateOwner4;
/** `typedef state_owner4 lock_owner4` (RFC 8881 §3.3.10.2). */
export type LockOwner4 = StateOwner4;

export function writeStateOwner4(writer: XdrWriter, owner: StateOwner4): void {
  writer.u64(owner.clientid);
  writer.varOpaque(owner.owner);
}

export function readStateOwner4(reader: XdrReader, what = "state_owner4"): StateOwner4 {
  return {
    clientid: reader.u64(`${what}.clientid`),
    // `varOpaque` copies: an owner is a map key the session keeps.
    owner: reader.varOpaque(NFS4_OPAQUE_LIMIT, `${what}.owner`),
  };
}

/**
 * `struct client_owner4 { verifier4 co_verifier; opaque co_ownerid<NFS4_OPAQUE_LIMIT>; }`
 * (RFC 8881 §2.4).
 *
 * The pair that identifies a *client*, as opposed to the `clientid4` shorthand
 * the server hands back for it: `co_ownerid` is stable across restarts and
 * `co_verifier` is not, so a matching ownerid with a new verifier is how a
 * server recognises the same client having rebooted.
 */
export interface ClientOwner4 {
  verifier: Uint8Array;
  ownerid: Uint8Array;
}

export function writeClientOwner4(writer: XdrWriter, owner: ClientOwner4): void {
  writeVerifier4(writer, owner.verifier);
  writer.varOpaque(owner.ownerid);
}

export function readClientOwner4(reader: XdrReader, what = "client_owner4"): ClientOwner4 {
  return {
    verifier: readVerifier4(reader, `${what}.co_verifier`),
    ownerid: reader.varOpaque(NFS4_OPAQUE_LIMIT, `${what}.co_ownerid`),
  };
}

/**
 * `struct server_owner4 { uint64_t so_minor_id; opaque so_major_id<NFS4_OPAQUE_LIMIT>; }`
 * (RFC 8881 §2.5).
 *
 * The mirror image, sent back by EXCHANGE_ID. Two servers with the same
 * `so_major_id` are the same storage and may be trunked; the `so_minor_id`
 * distinguishes network endpoints within it.
 */
export interface ServerOwner4 {
  minorId: bigint;
  majorId: Uint8Array;
}

export function writeServerOwner4(writer: XdrWriter, owner: ServerOwner4): void {
  writer.u64(owner.minorId);
  writer.varOpaque(owner.majorId);
}

export function readServerOwner4(reader: XdrReader, what = "server_owner4"): ServerOwner4 {
  return {
    minorId: reader.u64(`${what}.so_minor_id`),
    majorId: reader.varOpaque(NFS4_OPAQUE_LIMIT, `${what}.so_major_id`),
  };
}

/**
 * `struct nfs_impl_id4 { utf8str_cis nii_domain; utf8str_cs nii_name; nfstime4 nii_date; }`
 * (RFC 8881 §3.3.21).
 *
 * Purely informational — "who wrote this implementation, and when". RFC 8881
 * §18.35.3 is explicit that the two peers "MUST NOT interpret this
 * implementation identity information in a way that affects how the
 * implementation interacts with its peer", so it is a diagnostic string and
 * never a compatibility switch. It is on the wire in exactly two places, both
 * `<1>`-bounded arrays inside EXCHANGE_ID.
 */
export interface NfsImplId4 {
  domain: string;
  name: string;
  date: NfsTime4;
}

export function writeImplId4(writer: XdrWriter, implId: NfsImplId4): void {
  writer.string(implId.domain);
  writer.string(implId.name);
  writeTime4(writer, implId.date);
}

export function readImplId4(reader: XdrReader, what = "nfs_impl_id4"): NfsImplId4 {
  return {
    domain: reader.string(NFS4_MAX_OWNER, `${what}.nii_domain`),
    name: reader.string(NFS4_MAX_OWNER, `${what}.nii_name`),
    date: readTime4(reader, `${what}.nii_date`),
  };
}

/**
 * `struct nfsace4 { acetype4 type; aceflag4 flag; acemask4 access_mask; utf8str_mixed who; }`
 * (RFC 8881 §6.2.1).
 *
 * One access control entry, transcribed because `open_read_delegation4` and
 * `open_write_delegation4` embed one — not because this server has ACLs. It
 * declares no `acl` attribute (see `./attr.ts`) and issues no delegations, so
 * the only ACE it will ever write is the empty one a `NONE` delegation does not
 * even reach. The struct is here so the Tier-1 client can *read* a delegation
 * from a server that grants them.
 */
export interface Nfsace4 {
  /** `acetype4` — ALLOW, DENY, AUDIT or ALARM. */
  type: number;
  /** `aceflag4` — inheritance and audit bits. */
  flag: number;
  /** `acemask4` — the permission bits. */
  accessMask: number;
  /** `utf8str_mixed` — a user, a group, or one of the special names like `EVERYONE@`. */
  who: string;
}

export function writeNfsace4(writer: XdrWriter, ace: Nfsace4): void {
  writer.u32(ace.type);
  writer.u32(ace.flag);
  writer.u32(ace.accessMask);
  writer.string(ace.who);
}

export function readNfsace4(reader: XdrReader, what = "nfsace4"): Nfsace4 {
  return {
    type: reader.u32(`${what}.type`),
    flag: reader.u32(`${what}.flag`),
    accessMask: reader.u32(`${what}.access_mask`),
    who: reader.string(NFS4_MAX_OWNER, `${what}.who`),
  };
}

/** `struct nfs_modified_limit4 { uint32_t num_blocks; uint32_t bytes_per_block; }`. */
export interface NfsModifiedLimit4 {
  numBlocks: number;
  bytesPerBlock: number;
}

/**
 * ```
 * union nfs_space_limit4 switch (limit_by4 limitby) {
 *  case NFS_LIMIT_SIZE:    uint64_t            filesize;
 *  case NFS_LIMIT_BLOCKS:  nfs_modified_limit4 mod_blocks;
 * };
 * ```
 * (RFC 8881 §18.16.1, used by §18.16.2's `open_write_delegation4`.)
 *
 * **No default arm.** A `limitby` outside the pair is a malformed message, and
 * both directions say so rather than inventing a void arm — see the module
 * docs. That matters more here than elsewhere: this union sits in the middle of
 * an OPEN result, so swallowing it would take the `permissions` ACE after it
 * and everything past that.
 */
export interface NfsSpaceLimit4 {
  /** `limit_by4`. */
  limitby: number;
  /** `NFS_LIMIT_SIZE` only. */
  filesize?: bigint | undefined;
  /** `NFS_LIMIT_BLOCKS` only. */
  modBlocks?: NfsModifiedLimit4 | undefined;
}

export function writeSpaceLimit4(writer: XdrWriter, limit: NfsSpaceLimit4): void {
  writer.u32(limit.limitby);
  if (limit.limitby === NFS_LIMIT_SIZE) {
    writer.u64(limit.filesize ?? 0n);
  } else if (limit.limitby === NFS_LIMIT_BLOCKS) {
    const blocks = limit.modBlocks ?? { numBlocks: 0, bytesPerBlock: 0 };
    writer.u32(blocks.numBlocks);
    writer.u32(blocks.bytesPerBlock);
  } else {
    throw new XdrError(`nfs_space_limit4 has no arm for limitby ${limit.limitby}`);
  }
}

export function readSpaceLimit4(reader: XdrReader, what = "nfs_space_limit4"): NfsSpaceLimit4 {
  const limitby = reader.u32(`${what}.limitby`);
  if (limitby === NFS_LIMIT_SIZE) {
    return { limitby, filesize: reader.u64(`${what}.filesize`) };
  }
  if (limitby === NFS_LIMIT_BLOCKS) {
    return {
      limitby,
      modBlocks: {
        numBlocks: reader.u32("nfs_modified_limit4.num_blocks"),
        bytesPerBlock: reader.u32("nfs_modified_limit4.bytes_per_block"),
      },
    };
  }
  throw new XdrError(`${what} has no arm for limitby ${limitby}`);
}

/**
 * `struct state_protect_ops4 { bitmap4 spo_must_enforce; bitmap4 spo_must_allow; }`
 * (RFC 8881 §18.35.1).
 *
 * Two bitmaps *of operation numbers*, not of attributes — the only place in the
 * protocol a `bitmap4` means something other than a `fattr4` mask. They say
 * which operations must be sent with the machine credential and which may be
 * sent with any credential, and they are carried by the two state-protection
 * arms this server refuses.
 */
export interface StateProtectOps4 {
  mustEnforce: Bitmap4;
  mustAllow: Bitmap4;
}

export function writeStateProtectOps4(writer: XdrWriter, ops: StateProtectOps4): void {
  writeBitmap(writer, ops.mustEnforce);
  writeBitmap(writer, ops.mustAllow);
}

export function readStateProtectOps4(
  reader: XdrReader,
  what = "state_protect_ops4",
): StateProtectOps4 {
  return {
    mustEnforce: readBitmap(reader, `${what}.spo_must_enforce`),
    mustAllow: readBitmap(reader, `${what}.spo_must_allow`),
  };
}

/**
 * `struct gss_cb_handles4 { rpc_gss_svc_t gcbp_service; gsshandle4_t
 * gcbp_handle_from_server; gsshandle4_t gcbp_handle_from_client; }`
 * (RFC 8881 §18.33.1).
 */
export interface GssCbHandles4 {
  /** `rpc_gss_svc_t` (RFC 2203). */
  service: number;
  handleFromServer: Uint8Array;
  handleFromClient: Uint8Array;
}

export function writeGssCbHandles4(writer: XdrWriter, handles: GssCbHandles4): void {
  writer.u32(handles.service);
  writer.varOpaque(handles.handleFromServer);
  writer.varOpaque(handles.handleFromClient);
}

export function readGssCbHandles4(reader: XdrReader, what = "gss_cb_handles4"): GssCbHandles4 {
  return {
    service: reader.u32(`${what}.gcbp_service`),
    handleFromServer: reader.varOpaque(NFS4_MAX_GSS_HANDLE, `${what}.gcbp_handle_from_server`),
    handleFromClient: reader.varOpaque(NFS4_MAX_GSS_HANDLE, `${what}.gcbp_handle_from_client`),
  };
}

/**
 * `struct authsys_parms` (RFC 5531 Appendix A), read from the middle of a COMPOUND.
 *
 * The struct is `../rpc.ts`'s — {@link AuthSysParams} is imported, and the
 * *encode* direction below calls its `encodeAuthSys` verbatim, so there is one
 * transcription of the layout and not two. The decode direction cannot be
 * shared: `decodeAuthSys` takes a complete `Uint8Array`, because in RPC an
 * `authsys_parms` arrives inside a counted `opaque_auth.body` that gives it its
 * length. Here it is inline in `callback_sec_parms4` with no length in front of
 * it, so it has to be consumed field by field from the COMPOUND's own reader —
 * the same bytes, a different framing.
 */
export function readAuthSysParms(reader: XdrReader, what = "authsys_parms"): AuthSysParams {
  return {
    stamp: reader.u32(`${what}.stamp`),
    machineName: reader.string(NFS4_MAX_MACHINE_NAME, `${what}.machinename`),
    uid: reader.u32(`${what}.uid`),
    gid: reader.u32(`${what}.gid`),
    gids: reader.array((r) => r.u32("gid"), NFS4_MAX_AUTHSYS_GIDS, `${what}.gids`),
  };
}

/**
 * ```
 * union callback_sec_parms4 switch (uint32_t cb_secflavor) {
 *  case AUTH_NONE:   void;
 *  case AUTH_SYS:    authsys_parms   cbsp_sys_cred;
 *  case RPCSEC_GSS:  gss_cb_handles4 cbsp_gss_handles;
 * };
 * ```
 * (RFC 8881 §18.33.1.)
 *
 * How the client tells the server to authenticate itself on the *back* channel.
 * This server has no back channel — it grants no delegations and sends no
 * callbacks — but CREATE_SESSION carries an array of these whatever it does
 * with them, so the codec has to walk every arm to reach the operations after
 * it. **No default arm**: an unknown flavor is a malformed message.
 */
export interface CallbackSecParms4 {
  /** An RPC `auth_flavor`: `AUTH_NONE`, `AUTH_SYS` or {@link RPCSEC_GSS}. */
  secflavor: number;
  /** `AUTH_SYS` only. */
  sysCred?: AuthSysParams | undefined;
  /** `RPCSEC_GSS` only. */
  gssHandles?: GssCbHandles4 | undefined;
}

export function writeCallbackSecParms4(writer: XdrWriter, parms: CallbackSecParms4): void {
  writer.u32(parms.secflavor);
  if (parms.secflavor === AUTH_NONE) {
    return;
  }
  if (parms.secflavor === AUTH_SYS) {
    // `../rpc.ts`'s encoder, byte for byte: the struct has one transcription.
    // It is self-delimiting once written, so appending it raw is exact.
    writer.raw(
      encodeAuthSys(parms.sysCred ?? { stamp: 0, machineName: "", uid: 0, gid: 0, gids: [] }),
    );
    return;
  }
  if (parms.secflavor === RPCSEC_GSS) {
    writeGssCbHandles4(
      writer,
      parms.gssHandles ?? {
        service: 0,
        handleFromServer: new Uint8Array(0),
        handleFromClient: new Uint8Array(0),
      },
    );
    return;
  }
  throw new XdrError(`callback_sec_parms4 has no arm for flavor ${parms.secflavor}`);
}

export function readCallbackSecParms4(reader: XdrReader): CallbackSecParms4 {
  const secflavor = reader.u32("callback_sec_parms4.cb_secflavor");
  if (secflavor === AUTH_NONE) {
    return { secflavor };
  }
  if (secflavor === AUTH_SYS) {
    return { secflavor, sysCred: readAuthSysParms(reader, "cbsp_sys_cred") };
  }
  if (secflavor === RPCSEC_GSS) {
    return { secflavor, gssHandles: readGssCbHandles4(reader, "cbsp_gss_handles") };
  }
  throw new XdrError(`callback_sec_parms4 has no arm for flavor ${secflavor}`);
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

// ===========================================================================
// state operations
// ===========================================================================
//
// Everything below needs a client ID, a session or a stateid to mean anything,
// which is what separates it from the operations above. They are in
// `nfs_opnum4` order.
//
// The zero stateid is the one value written for a *missing* union body. XDR
// unions here are chosen by their discriminant, never by which fields happen to
// be set, so an encoder handed a known arm with no body still writes the arm's
// zero value rather than a short message that would desync everything after it.

const ZERO_STATEID: Stateid4 = { seqid: 0, other: new Uint8Array(NFS4_OTHER_SIZE) };

// ---------------------------------------------------------------------------
// CLOSE (RFC 8881 §18.2)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct CLOSE4args {
 *         [CURRENT_FH: object]
 *         seqid4          seqid;
 *         stateid4        open_stateid;
 * };
 * ```
 *
 * `seqid` is NFSv4.0's per-owner sequence number, and in 4.1 it is dead: "the
 * argument seqid MAY have any value, and the server MUST ignore seqid"
 * (§18.2.3). It stays on the wire because the struct did not change; a session
 * that validated it would refuse legal requests.
 */
export interface Close4args {
  seqid: number;
  openStateid: Stateid4;
}

/**
 * `union CLOSE4res` — `stateid4 open_stateid` on `NFS4_OK`, void otherwise.
 *
 * Note the arm is a bare `stateid4`, not a `resok4` struct wrapping one. The
 * stateid it returns is deprecated and of no use to the client (§18.2.4); it is
 * still four-plus-twelve bytes that have to be written or the COMPOUND desyncs.
 */
export interface Close4res {
  status: number;
  openStateid: Stateid4 | undefined;
}

export function writeCloseArgs(writer: XdrWriter, args: Close4args): void {
  writer.u32(args.seqid);
  writeStateid(writer, args.openStateid);
}

export function readCloseArgs(reader: XdrReader): Close4args {
  return {
    seqid: reader.u32("CLOSE4args.seqid"),
    openStateid: readStateid(reader, "CLOSE4args.open_stateid"),
  };
}

export function writeCloseRes(writer: XdrWriter, res: Close4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeStateid(writer, res.openStateid ?? ZERO_STATEID);
  }
}

export function readCloseRes(reader: XdrReader): Close4res {
  const status = reader.u32("CLOSE4res.status");
  return {
    status,
    openStateid: status === NFS4_OK ? readStateid(reader, "CLOSE4res.open_stateid") : undefined,
  };
}

// ---------------------------------------------------------------------------
// LOCK (RFC 8881 §18.10) / LOCKT (§18.11) / LOCKU (§18.12)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct open_to_lock_owner4 {
 *         seqid4          open_seqid;
 *         stateid4        open_stateid;
 *         seqid4          lock_seqid;
 *         lock_owner4     lock_owner;
 * };
 * ```
 * (RFC 8881 §3.3.11.)
 *
 * The *first* lock a lock-owner takes on an open file: it names the open state
 * it is derived from, and the server answers with a fresh lock stateid.
 */
export interface OpenToLockOwner4 {
  openSeqid: number;
  openStateid: Stateid4;
  lockSeqid: number;
  lockOwner: LockOwner4;
}

/** `struct exist_lock_owner4 { stateid4 lock_stateid; seqid4 lock_seqid; }` — every lock after the first. */
export interface ExistLockOwner4 {
  lockStateid: Stateid4;
  lockSeqid: number;
}

/**
 * ```
 * union locker4 switch (bool new_lock_owner) {
 *  case TRUE:      open_to_lock_owner4     open_owner;
 *  case FALSE:     exist_lock_owner4       lock_owner;
 * };
 * ```
 *
 * The one union in the protocol discriminated by a plain `bool`, so it has no
 * unknown-arm case at all: `XdrReader.bool` already refuses anything but 0 or 1.
 *
 * **Four of the fields inside it are decoration.** §18.10.3 lists what a client
 * MAY set to any value and the server MUST ignore: `open_owner.lock_owner.
 * clientid` — because the real client ID comes from the session ID in the
 * COMPOUND's SEQUENCE — plus `open_owner.open_seqid`, `open_owner.lock_seqid`
 * and `lock_owner.lock_seqid`, the NFSv4.0 sequencing that 4.1's slots
 * replaced. They stay on the wire because the struct did not change, and a
 * session that validated any of them would refuse legal requests.
 */
export interface Locker4 {
  newLockOwner: boolean;
  /** `new_lock_owner == TRUE`. */
  openOwner?: OpenToLockOwner4 | undefined;
  /** `new_lock_owner == FALSE`. */
  lockOwner?: ExistLockOwner4 | undefined;
}

/**
 * `struct LOCK4denied { offset4 offset; length4 length; nfs_lock_type4
 * locktype; lock_owner4 owner; }` (RFC 8881 §18.10.2).
 *
 * The conflicting lock, described. LOCKT's whole purpose is to get one of these
 * back.
 *
 * `owner.clientid` here is **load-bearing, and the server MUST set it**: it is
 * "the actual client associated with the conflicting lock, whether this is the
 * client ID associated with the current session or a different one" (§18.10.3,
 * and §18.11.3 for LOCKT). So this is the one field in the protocol through
 * which a client learns *another* client's identity, and it is the exact
 * opposite of the `clientid` rule on the argument side — see {@link Locker4}
 * and {@link Lockt4args}, where the server must ignore what it is sent.
 */
export interface Lock4denied {
  offset: bigint;
  length: bigint;
  locktype: number;
  owner: LockOwner4;
}

/**
 * ```
 * struct LOCK4args {
 *         [CURRENT_FH: file]
 *         nfs_lock_type4  locktype;
 *         bool            reclaim;
 *         offset4         offset;
 *         length4         length;
 *         locker4         locker;
 * };
 * ```
 */
export interface Lock4args {
  locktype: number;
  reclaim: boolean;
  offset: bigint;
  length: bigint;
  locker: Locker4;
}

/**
 * ```
 * union LOCK4res switch (nfsstat4 status) {
 *  case NFS4_OK:          LOCK4resok     resok4;
 *  case NFS4ERR_DENIED:   LOCK4denied    denied;
 *  default:               void;
 * };
 * ```
 *
 * **Three arms, not two.** A denied lock is a *failure* that still carries a
 * body, the second such shape in this file after SETATTR's — and unlike
 * SETATTR's it is selected by one specific status, so both directions have to
 * test for `NFS4ERR_DENIED` by name.
 */
export interface Lock4res {
  status: number;
  /** `NFS4_OK` — `LOCK4resok { stateid4 lock_stateid; }`. */
  lockStateid: Stateid4 | undefined;
  /** `NFS4ERR_DENIED`. */
  denied: Lock4denied | undefined;
}

/**
 * ```
 * struct LOCKT4args {
 *         [CURRENT_FH: file]
 *         nfs_lock_type4  locktype;
 *         offset4         offset;
 *         length4         length;
 *         lock_owner4     owner;
 * };
 * ```
 *
 * No stateid and no seqid: LOCKT takes nothing and changes nothing, so there is
 * no state for it to name.
 *
 * `owner.clientid` is the one that *is* here and still does not count: §18.11.3
 * says a client MAY set it to any value and the server MUST ignore it, deriving
 * the client ID from the session ID in the COMPOUND's SEQUENCE instead. Note
 * the field of the same name coming back in {@link Lock4denied} is the
 * opposite — there the server MUST fill in the conflicting lock's real owner.
 */
export interface Lockt4args {
  locktype: number;
  offset: bigint;
  length: bigint;
  owner: LockOwner4;
}

/**
 * ```
 * union LOCKT4res switch (nfsstat4 status) {
 *  case NFS4ERR_DENIED:   LOCK4denied    denied;
 *  case NFS4_OK:          void;
 *  default:               void;
 * };
 * ```
 *
 * Success is the *void* arm here — "no conflicting lock" is the whole answer —
 * and the only body belongs to the failure. Note RFC 5662 writes `NFS4ERR_DENIED`
 * first; the order of case arms in XDR is not the order on the wire, and the
 * discriminant decides.
 */
export interface Lockt4res {
  status: number;
  denied: Lock4denied | undefined;
}

/**
 * ```
 * struct LOCKU4args {
 *         [CURRENT_FH: file]
 *         nfs_lock_type4  locktype;
 *         seqid4          seqid;
 *         stateid4        lock_stateid;
 *         offset4         offset;
 *         length4         length;
 * };
 * ```
 */
export interface Locku4args {
  locktype: number;
  seqid: number;
  lockStateid: Stateid4;
  offset: bigint;
  length: bigint;
}

/** `union LOCKU4res` — `stateid4 lock_stateid` on `NFS4_OK`, bare like CLOSE's. */
export interface Locku4res {
  status: number;
  lockStateid: Stateid4 | undefined;
}

export function writeOpenToLockOwner4(writer: XdrWriter, owner: OpenToLockOwner4): void {
  writer.u32(owner.openSeqid);
  writeStateid(writer, owner.openStateid);
  writer.u32(owner.lockSeqid);
  writeStateOwner4(writer, owner.lockOwner);
}

export function readOpenToLockOwner4(reader: XdrReader): OpenToLockOwner4 {
  return {
    openSeqid: reader.u32("open_to_lock_owner4.open_seqid"),
    openStateid: readStateid(reader, "open_to_lock_owner4.open_stateid"),
    lockSeqid: reader.u32("open_to_lock_owner4.lock_seqid"),
    lockOwner: readStateOwner4(reader, "open_to_lock_owner4.lock_owner"),
  };
}

export function writeLocker4(writer: XdrWriter, locker: Locker4): void {
  writer.bool(locker.newLockOwner);
  if (locker.newLockOwner) {
    writeOpenToLockOwner4(
      writer,
      locker.openOwner ?? {
        openSeqid: 0,
        openStateid: ZERO_STATEID,
        lockSeqid: 0,
        lockOwner: { clientid: 0n, owner: new Uint8Array(0) },
      },
    );
    return;
  }
  const existing = locker.lockOwner ?? { lockStateid: ZERO_STATEID, lockSeqid: 0 };
  writeStateid(writer, existing.lockStateid);
  writer.u32(existing.lockSeqid);
}

export function readLocker4(reader: XdrReader): Locker4 {
  // `bool` refuses anything but 0 or 1, so there is no third arm to reject.
  if (reader.bool("locker4.new_lock_owner")) {
    return { newLockOwner: true, openOwner: readOpenToLockOwner4(reader) };
  }
  return {
    newLockOwner: false,
    lockOwner: {
      lockStateid: readStateid(reader, "exist_lock_owner4.lock_stateid"),
      lockSeqid: reader.u32("exist_lock_owner4.lock_seqid"),
    },
  };
}

export function writeLock4denied(writer: XdrWriter, denied: Lock4denied): void {
  writer.u64(denied.offset);
  writer.u64(denied.length);
  writer.u32(denied.locktype);
  writeStateOwner4(writer, denied.owner);
}

export function readLock4denied(reader: XdrReader, what = "LOCK4denied"): Lock4denied {
  return {
    offset: reader.u64(`${what}.offset`),
    length: reader.u64(`${what}.length`),
    locktype: reader.u32(`${what}.locktype`),
    owner: readStateOwner4(reader, `${what}.owner`),
  };
}

/** The `LOCK4denied` written when a `NFS4ERR_DENIED` result carries none. */
const NO_LOCK_DENIED: Lock4denied = {
  offset: 0n,
  length: 0n,
  locktype: 0,
  owner: { clientid: 0n, owner: new Uint8Array(0) },
};

export function writeLockArgs(writer: XdrWriter, args: Lock4args): void {
  writer.u32(args.locktype);
  writer.bool(args.reclaim);
  writer.u64(args.offset);
  writer.u64(args.length);
  writeLocker4(writer, args.locker);
}

export function readLockArgs(reader: XdrReader): Lock4args {
  return {
    locktype: reader.u32("LOCK4args.locktype"),
    reclaim: reader.bool("LOCK4args.reclaim"),
    offset: reader.u64("LOCK4args.offset"),
    length: reader.u64("LOCK4args.length"),
    locker: readLocker4(reader),
  };
}

export function writeLockRes(writer: XdrWriter, res: Lock4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeStateid(writer, res.lockStateid ?? ZERO_STATEID);
  } else if (res.status === NFS4ERR_DENIED) {
    writeLock4denied(writer, res.denied ?? NO_LOCK_DENIED);
  }
}

export function readLockRes(reader: XdrReader): Lock4res {
  const status = reader.u32("LOCK4res.status");
  if (status === NFS4_OK) {
    return {
      status,
      lockStateid: readStateid(reader, "LOCK4resok.lock_stateid"),
      denied: undefined,
    };
  }
  if (status === NFS4ERR_DENIED) {
    return { status, lockStateid: undefined, denied: readLock4denied(reader) };
  }
  return { status, lockStateid: undefined, denied: undefined };
}

export function writeLocktArgs(writer: XdrWriter, args: Lockt4args): void {
  writer.u32(args.locktype);
  writer.u64(args.offset);
  writer.u64(args.length);
  writeStateOwner4(writer, args.owner);
}

export function readLocktArgs(reader: XdrReader): Lockt4args {
  return {
    locktype: reader.u32("LOCKT4args.locktype"),
    offset: reader.u64("LOCKT4args.offset"),
    length: reader.u64("LOCKT4args.length"),
    owner: readStateOwner4(reader, "LOCKT4args.owner"),
  };
}

export function writeLocktRes(writer: XdrWriter, res: Lockt4res): void {
  writer.u32(res.status);
  if (res.status === NFS4ERR_DENIED) {
    writeLock4denied(writer, res.denied ?? NO_LOCK_DENIED);
  }
}

export function readLocktRes(reader: XdrReader): Lockt4res {
  const status = reader.u32("LOCKT4res.status");
  return {
    status,
    denied: status === NFS4ERR_DENIED ? readLock4denied(reader) : undefined,
  };
}

export function writeLockuArgs(writer: XdrWriter, args: Locku4args): void {
  writer.u32(args.locktype);
  writer.u32(args.seqid);
  writeStateid(writer, args.lockStateid);
  writer.u64(args.offset);
  writer.u64(args.length);
}

export function readLockuArgs(reader: XdrReader): Locku4args {
  return {
    locktype: reader.u32("LOCKU4args.locktype"),
    seqid: reader.u32("LOCKU4args.seqid"),
    lockStateid: readStateid(reader, "LOCKU4args.lock_stateid"),
    offset: reader.u64("LOCKU4args.offset"),
    length: reader.u64("LOCKU4args.length"),
  };
}

export function writeLockuRes(writer: XdrWriter, res: Locku4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeStateid(writer, res.lockStateid ?? ZERO_STATEID);
  }
}

export function readLockuRes(reader: XdrReader): Locku4res {
  const status = reader.u32("LOCKU4res.status");
  return {
    status,
    lockStateid: status === NFS4_OK ? readStateid(reader, "LOCKU4res.lock_stateid") : undefined,
  };
}

// ---------------------------------------------------------------------------
// OPEN (RFC 8881 §18.16)
// ---------------------------------------------------------------------------

/**
 * `struct creatverfattr { verifier4 cva_verf; fattr4 cva_attrs; }` — the
 * `EXCLUSIVE4_1` create body.
 *
 * 4.1's replacement for `EXCLUSIVE4`, which had to smuggle its verifier into a
 * time attribute and could therefore not set attributes at all. Here the
 * verifier and the attributes travel side by side.
 */
export interface CreatVerfAttr4 {
  verf: Uint8Array;
  attrs: Fattr4;
}

/**
 * ```
 * union createhow4 switch (createmode4 mode) {
 *  case UNCHECKED4:
 *  case GUARDED4:          fattr4         createattrs;
 *  case EXCLUSIVE4:        verifier4      createverf;
 *  case EXCLUSIVE4_1:      creatverfattr  ch_createboth;
 * };
 * ```
 *
 * **No default arm**: a `mode` outside the four is a malformed message. Note
 * `UNCHECKED4` and `GUARDED4` are two labels on one arm — they differ in what
 * the *server* does about an existing file, not in what is on the wire.
 */
export interface CreateHow4 {
  /** `createmode4`. */
  mode: number;
  /** `UNCHECKED4` / `GUARDED4`. */
  createattrs?: Fattr4 | undefined;
  /** `EXCLUSIVE4`. */
  createverf?: Uint8Array | undefined;
  /** `EXCLUSIVE4_1`. */
  createboth?: CreatVerfAttr4 | undefined;
}

/**
 * `union openflag4 switch (opentype4 opentype) { case OPEN4_CREATE: createhow4
 * how; default: void; }`.
 *
 * The default arm is real here — `OPEN4_NOCREATE` selects it — so an unknown
 * `opentype` reads and writes nothing rather than failing. That is the
 * declaration, and it is what lets a plain open be four bytes.
 */
export interface OpenFlag4 {
  /** `opentype4`. */
  opentype: number;
  /** `OPEN4_CREATE` only. */
  how?: CreateHow4 | undefined;
}

/** `struct open_claim_delegate_cur4 { stateid4 delegate_stateid; component4 file; }`. */
export interface OpenClaimDelegateCur4 {
  delegateStateid: Stateid4;
  file: string;
}

/**
 * `union open_claim4 switch (open_claim_type4 claim)` (RFC 8881 §18.16.1), all
 * seven arms:
 *
 * | claim | body | current filehandle |
 * | --- | --- | --- |
 * | `CLAIM_NULL` | `component4 file` | directory |
 * | `CLAIM_PREVIOUS` | `open_delegation_type4 delegate_type` | file being reclaimed |
 * | `CLAIM_DELEGATE_CUR` | `open_claim_delegate_cur4` | directory |
 * | `CLAIM_DELEGATE_PREV` | `component4 file_delegate_prev` | directory |
 * | `CLAIM_FH` | void | file to open |
 * | `CLAIM_DELEG_CUR_FH` | `stateid4 oc_delegate_stateid` | file to open |
 * | `CLAIM_DELEG_PREV_FH` | void | file to open |
 *
 * This server answers only `CLAIM_NULL` and `CLAIM_FH` — it grants no
 * delegations, so nothing can reclaim one — and still decodes all seven,
 * because refusing an arm has to happen with a status and not a desync.
 *
 * **No default arm**: an unknown claim is a malformed message. The three `_FH`
 * claims are new to 4.1 and are the reason `CLAIM_FH`'s void arm is not a
 * mistake: the file is the current filehandle, so there is nothing to name.
 */
export interface OpenClaim4 {
  /** `open_claim_type4`. */
  claim: number;
  /** `CLAIM_NULL`. */
  file?: string | undefined;
  /** `CLAIM_PREVIOUS` — an `open_delegation_type4`. */
  delegateType?: number | undefined;
  /** `CLAIM_DELEGATE_CUR`. */
  delegateCurInfo?: OpenClaimDelegateCur4 | undefined;
  /** `CLAIM_DELEGATE_PREV`. */
  fileDelegatePrev?: string | undefined;
  /** `CLAIM_DELEG_CUR_FH`. */
  ocDelegateStateid?: Stateid4 | undefined;
}

/**
 * ```
 * struct OPEN4args {
 *         [CURRENT_FH: see claim]
 *         seqid4          seqid;
 *         uint32_t        share_access;
 *         uint32_t        share_deny;
 *         open_owner4     owner;
 *         openflag4       openhow;
 *         open_claim4     claim;
 * };
 * ```
 *
 * `seqid` is vestigial in 4.1 exactly as CLOSE's is. `share_access` carries two
 * things in one word: the low bits are the access mode, and the
 * `OPEN4_SHARE_ACCESS_WANT_*` bits above them are the delegation the client
 * would like — which is why a server that ignores delegations must still mask
 * rather than compare.
 */
export interface Open4args {
  seqid: number;
  shareAccess: number;
  shareDeny: number;
  owner: OpenOwner4;
  openhow: OpenFlag4;
  claim: OpenClaim4;
}

/** `struct open_read_delegation4 { stateid4 stateid; bool recall; nfsace4 permissions; }`. */
export interface OpenReadDelegation4 {
  stateid: Stateid4;
  recall: boolean;
  permissions: Nfsace4;
}

/**
 * `struct open_write_delegation4 { stateid4 stateid; bool recall;
 * nfs_space_limit4 space_limit; nfsace4 permissions; }`.
 *
 * A write delegation carries a space limit the read one does not: the client
 * may buffer writes locally until crossing it.
 */
export interface OpenWriteDelegation4 {
  stateid: Stateid4;
  recall: boolean;
  spaceLimit: NfsSpaceLimit4;
  permissions: Nfsace4;
}

/**
 * ```
 * union open_none_delegation4 switch (why_no_delegation4 ond_why) {
 *  case WND4_CONTENTION:   bool ond_server_will_push_deleg;
 *  case WND4_RESOURCE:     bool ond_server_will_signal_avail;
 *  default:                void;
 * };
 * ```
 *
 * New to 4.1, and the reason `OPEN_DELEGATE_NONE_EXT` exists beside plain
 * `OPEN_DELEGATE_NONE`: a client that asked for a delegation and did not get
 * one can be told *why*, and in two of the nine cases whether to expect one
 * later. This union does have a default arm, so the other seven reasons are
 * four bytes.
 */
export interface OpenNoneDelegation4 {
  /** `why_no_delegation4`. */
  why: number;
  /** `WND4_CONTENTION`. */
  serverWillPushDeleg?: boolean | undefined;
  /** `WND4_RESOURCE`. */
  serverWillSignalAvail?: boolean | undefined;
}

/**
 * ```
 * union open_delegation4 switch (open_delegation_type4 delegation_type) {
 *  case OPEN_DELEGATE_NONE:      void;
 *  case OPEN_DELEGATE_READ:      open_read_delegation4  read;
 *  case OPEN_DELEGATE_WRITE:     open_write_delegation4 write;
 *  case OPEN_DELEGATE_NONE_EXT:  open_none_delegation4  od_whynone;
 * };
 * ```
 *
 * **No default arm.** This server always answers `OPEN_DELEGATE_NONE` — four
 * bytes, no body — and decodes the other three for the Tier-1 client's sake.
 */
export interface OpenDelegation4 {
  /** `open_delegation_type4`. */
  delegationType: number;
  /** `OPEN_DELEGATE_READ`. */
  read?: OpenReadDelegation4 | undefined;
  /** `OPEN_DELEGATE_WRITE`. */
  write?: OpenWriteDelegation4 | undefined;
  /** `OPEN_DELEGATE_NONE_EXT`. */
  whynone?: OpenNoneDelegation4 | undefined;
}

/**
 * ```
 * struct OPEN4resok {
 *         stateid4        stateid;
 *         change_info4    cinfo;
 *         uint32_t        rflags;
 *         bitmap4         attrset;
 *         open_delegation4 delegation;
 * };
 * ```
 * with `[New CURRENT_FH: opened file]` on `NFS4_OK`, and void otherwise.
 *
 * `cinfo` describes the *directory*, and is meaningful only when the OPEN
 * created something; `attrset` is which of `createattrs` were applied, the same
 * question CREATE's answers. `rflags` must never carry `OPEN4_RESULT_CONFIRM`
 * in 4.1 — OPEN_CONFIRM does not exist here.
 */
export interface Open4res {
  status: number;
  stateid: Stateid4 | undefined;
  cinfo: ChangeInfo4 | undefined;
  rflags: number;
  attrset: Bitmap4 | undefined;
  delegation: OpenDelegation4 | undefined;
}

export function writeCreateHow4(writer: XdrWriter, how: CreateHow4): void {
  writer.u32(how.mode);
  if (how.mode === UNCHECKED4 || how.mode === GUARDED4) {
    writeFattr4(writer, how.createattrs ?? { attrmask: [], values: {}, unsupported: [] });
    return;
  }
  if (how.mode === EXCLUSIVE4) {
    writeVerifier4(writer, how.createverf ?? new Uint8Array(NFS4_VERIFIER_SIZE));
    return;
  }
  if (how.mode === EXCLUSIVE4_1) {
    const both = how.createboth ?? {
      verf: new Uint8Array(NFS4_VERIFIER_SIZE),
      attrs: { attrmask: [], values: {}, unsupported: [] },
    };
    writeVerifier4(writer, both.verf);
    writeFattr4(writer, both.attrs);
    return;
  }
  throw new XdrError(`createhow4 has no arm for mode ${how.mode}`);
}

export function readCreateHow4(reader: XdrReader): CreateHow4 {
  const mode = reader.u32("createhow4.mode");
  if (mode === UNCHECKED4 || mode === GUARDED4) {
    return { mode, createattrs: readFattr4(reader, "createhow4.createattrs") };
  }
  if (mode === EXCLUSIVE4) {
    return { mode, createverf: readVerifier4(reader, "createhow4.createverf") };
  }
  if (mode === EXCLUSIVE4_1) {
    return {
      mode,
      createboth: {
        verf: readVerifier4(reader, "creatverfattr.cva_verf"),
        attrs: readFattr4(reader, "creatverfattr.cva_attrs"),
      },
    };
  }
  throw new XdrError(`createhow4 has no arm for mode ${mode}`);
}

export function writeOpenFlag4(writer: XdrWriter, openhow: OpenFlag4): void {
  writer.u32(openhow.opentype);
  if (openhow.opentype === OPEN4_CREATE) {
    writeCreateHow4(writer, openhow.how ?? { mode: UNCHECKED4 });
  }
  // Every other `opentype4` is the default (void) arm: nothing follows.
}

export function readOpenFlag4(reader: XdrReader): OpenFlag4 {
  const opentype = reader.u32("openflag4.opentype");
  if (opentype === OPEN4_CREATE) {
    return { opentype, how: readCreateHow4(reader) };
  }
  return { opentype };
}

export function writeOpenClaim4(writer: XdrWriter, claim: OpenClaim4): void {
  writer.u32(claim.claim);
  switch (claim.claim) {
    case CLAIM_NULL: {
      writer.string(claim.file ?? "");
      return;
    }
    case CLAIM_PREVIOUS: {
      writer.u32(claim.delegateType ?? 0);
      return;
    }
    case CLAIM_DELEGATE_CUR: {
      const info = claim.delegateCurInfo ?? { delegateStateid: ZERO_STATEID, file: "" };
      writeStateid(writer, info.delegateStateid);
      writer.string(info.file);
      return;
    }
    case CLAIM_DELEGATE_PREV: {
      writer.string(claim.fileDelegatePrev ?? "");
      return;
    }
    case CLAIM_FH:
    case CLAIM_DELEG_PREV_FH: {
      // Void arms: the file is the current filehandle.
      return;
    }
    case CLAIM_DELEG_CUR_FH: {
      writeStateid(writer, claim.ocDelegateStateid ?? ZERO_STATEID);
      return;
    }
    default: {
      throw new XdrError(`open_claim4 has no arm for claim ${claim.claim}`);
    }
  }
}

export function readOpenClaim4(reader: XdrReader): OpenClaim4 {
  const claim = reader.u32("open_claim4.claim");
  switch (claim) {
    case CLAIM_NULL: {
      return { claim, file: readComponent4(reader, "open_claim4.file") };
    }
    case CLAIM_PREVIOUS: {
      return { claim, delegateType: reader.u32("open_claim4.delegate_type") };
    }
    case CLAIM_DELEGATE_CUR: {
      return {
        claim,
        delegateCurInfo: {
          delegateStateid: readStateid(reader, "open_claim_delegate_cur4.delegate_stateid"),
          file: readComponent4(reader, "open_claim_delegate_cur4.file"),
        },
      };
    }
    case CLAIM_DELEGATE_PREV: {
      return {
        claim,
        fileDelegatePrev: readComponent4(reader, "open_claim4.file_delegate_prev"),
      };
    }
    case CLAIM_FH:
    case CLAIM_DELEG_PREV_FH: {
      return { claim };
    }
    case CLAIM_DELEG_CUR_FH: {
      return { claim, ocDelegateStateid: readStateid(reader, "open_claim4.oc_delegate_stateid") };
    }
    default: {
      throw new XdrError(`open_claim4 has no arm for claim ${claim}`);
    }
  }
}

export function writeOpenNoneDelegation4(writer: XdrWriter, none: OpenNoneDelegation4): void {
  writer.u32(none.why);
  if (none.why === WND4_CONTENTION) {
    writer.bool(none.serverWillPushDeleg ?? false);
  } else if (none.why === WND4_RESOURCE) {
    writer.bool(none.serverWillSignalAvail ?? false);
  }
  // Every other `why_no_delegation4` is the default (void) arm.
}

export function readOpenNoneDelegation4(reader: XdrReader): OpenNoneDelegation4 {
  const why = reader.u32("open_none_delegation4.ond_why");
  if (why === WND4_CONTENTION) {
    return { why, serverWillPushDeleg: reader.bool("ond_server_will_push_deleg") };
  }
  if (why === WND4_RESOURCE) {
    return { why, serverWillSignalAvail: reader.bool("ond_server_will_signal_avail") };
  }
  return { why };
}

/** The `nfsace4` written for a delegation arm that carries none. */
const NO_ACE: Nfsace4 = { type: 0, flag: 0, accessMask: 0, who: "" };

export function writeOpenDelegation4(writer: XdrWriter, delegation: OpenDelegation4): void {
  writer.u32(delegation.delegationType);
  switch (delegation.delegationType) {
    case OPEN_DELEGATE_READ: {
      const read = delegation.read ?? {
        stateid: ZERO_STATEID,
        recall: false,
        permissions: NO_ACE,
      };
      writeStateid(writer, read.stateid);
      writer.bool(read.recall);
      writeNfsace4(writer, read.permissions);
      return;
    }
    case OPEN_DELEGATE_WRITE: {
      const write = delegation.write ?? {
        stateid: ZERO_STATEID,
        recall: false,
        spaceLimit: { limitby: NFS_LIMIT_SIZE, filesize: 0n },
        permissions: NO_ACE,
      };
      writeStateid(writer, write.stateid);
      writer.bool(write.recall);
      writeSpaceLimit4(writer, write.spaceLimit);
      writeNfsace4(writer, write.permissions);
      return;
    }
    case OPEN_DELEGATE_NONE_EXT: {
      writeOpenNoneDelegation4(writer, delegation.whynone ?? { why: 0 });
      return;
    }
    case OPEN_DELEGATE_NONE: {
      // The void arm, and what this server always sends.
      return;
    }
    default: {
      throw new XdrError(`open_delegation4 has no arm for type ${delegation.delegationType}`);
    }
  }
}

export function readOpenDelegation4(reader: XdrReader): OpenDelegation4 {
  const delegationType = reader.u32("open_delegation4.delegation_type");
  switch (delegationType) {
    case OPEN_DELEGATE_NONE: {
      return { delegationType };
    }
    case OPEN_DELEGATE_READ: {
      return {
        delegationType,
        read: {
          stateid: readStateid(reader, "open_read_delegation4.stateid"),
          recall: reader.bool("open_read_delegation4.recall"),
          permissions: readNfsace4(reader, "open_read_delegation4.permissions"),
        },
      };
    }
    case OPEN_DELEGATE_WRITE: {
      return {
        delegationType,
        write: {
          stateid: readStateid(reader, "open_write_delegation4.stateid"),
          recall: reader.bool("open_write_delegation4.recall"),
          spaceLimit: readSpaceLimit4(reader, "open_write_delegation4.space_limit"),
          permissions: readNfsace4(reader, "open_write_delegation4.permissions"),
        },
      };
    }
    case OPEN_DELEGATE_NONE_EXT: {
      return { delegationType, whynone: readOpenNoneDelegation4(reader) };
    }
    default: {
      throw new XdrError(`open_delegation4 has no arm for type ${delegationType}`);
    }
  }
}

export function writeOpenArgs(writer: XdrWriter, args: Open4args): void {
  writer.u32(args.seqid);
  writer.u32(args.shareAccess);
  writer.u32(args.shareDeny);
  writeStateOwner4(writer, args.owner);
  writeOpenFlag4(writer, args.openhow);
  writeOpenClaim4(writer, args.claim);
}

export function readOpenArgs(reader: XdrReader): Open4args {
  return {
    seqid: reader.u32("OPEN4args.seqid"),
    shareAccess: reader.u32("OPEN4args.share_access"),
    shareDeny: reader.u32("OPEN4args.share_deny"),
    owner: readStateOwner4(reader, "OPEN4args.owner"),
    openhow: readOpenFlag4(reader),
    claim: readOpenClaim4(reader),
  };
}

export function writeOpenRes(writer: XdrWriter, res: Open4res): void {
  writer.u32(res.status);
  if (res.status !== NFS4_OK) {
    return;
  }
  writeStateid(writer, res.stateid ?? ZERO_STATEID);
  writeChangeInfo(writer, res.cinfo ?? { atomic: false, before: 0n, after: 0n });
  writer.u32(res.rflags);
  writeBitmap(writer, res.attrset ?? []);
  writeOpenDelegation4(writer, res.delegation ?? { delegationType: OPEN_DELEGATE_NONE });
}

export function readOpenRes(reader: XdrReader): Open4res {
  const status = reader.u32("OPEN4res.status");
  if (status !== NFS4_OK) {
    return {
      status,
      stateid: undefined,
      cinfo: undefined,
      rflags: 0,
      attrset: undefined,
      delegation: undefined,
    };
  }
  return {
    status,
    stateid: readStateid(reader, "OPEN4resok.stateid"),
    cinfo: readChangeInfo(reader, "OPEN4resok.cinfo"),
    rflags: reader.u32("OPEN4resok.rflags"),
    attrset: readBitmap(reader, "OPEN4resok.attrset"),
    delegation: readOpenDelegation4(reader),
  };
}

// ---------------------------------------------------------------------------
// OPEN_DOWNGRADE (RFC 8881 §18.18)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct OPEN_DOWNGRADE4args {
 *         [CURRENT_FH: opened file]
 *         stateid4        open_stateid;
 *         seqid4          seqid;
 *         uint32_t        share_access;
 *         uint32_t        share_deny;
 * };
 * ```
 *
 * Note the field order: the stateid comes *before* the seqid here and after it
 * in CLOSE. Both are `uint32_t`-then-`stateid4` sized, so a transposition
 * encodes to the same length and decodes to garbage — which is exactly what the
 * all-distinct golden fixtures exist to catch.
 */
export interface OpenDowngrade4args {
  openStateid: Stateid4;
  seqid: number;
  shareAccess: number;
  shareDeny: number;
}

/** `union OPEN_DOWNGRADE4res` — `OPEN_DOWNGRADE4resok { stateid4 open_stateid; }` on `NFS4_OK`. */
export interface OpenDowngrade4res {
  status: number;
  openStateid: Stateid4 | undefined;
}

export function writeOpenDowngradeArgs(writer: XdrWriter, args: OpenDowngrade4args): void {
  writeStateid(writer, args.openStateid);
  writer.u32(args.seqid);
  writer.u32(args.shareAccess);
  writer.u32(args.shareDeny);
}

export function readOpenDowngradeArgs(reader: XdrReader): OpenDowngrade4args {
  return {
    openStateid: readStateid(reader, "OPEN_DOWNGRADE4args.open_stateid"),
    seqid: reader.u32("OPEN_DOWNGRADE4args.seqid"),
    shareAccess: reader.u32("OPEN_DOWNGRADE4args.share_access"),
    shareDeny: reader.u32("OPEN_DOWNGRADE4args.share_deny"),
  };
}

export function writeOpenDowngradeRes(writer: XdrWriter, res: OpenDowngrade4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeStateid(writer, res.openStateid ?? ZERO_STATEID);
  }
}

export function readOpenDowngradeRes(reader: XdrReader): OpenDowngrade4res {
  const status = reader.u32("OPEN_DOWNGRADE4res.status");
  return {
    status,
    openStateid:
      status === NFS4_OK ? readStateid(reader, "OPEN_DOWNGRADE4resok.open_stateid") : undefined,
  };
}

// ---------------------------------------------------------------------------
// READ (RFC 8881 §18.22)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct READ4args {
 *         [CURRENT_FH: file]
 *         stateid4        stateid;
 *         offset4         offset;
 *         count4          count;
 * };
 * ```
 */
export interface Read4args {
  stateid: Stateid4;
  offset: bigint;
  count: number;
}

/**
 * `union READ4res` — `READ4resok { bool eof; opaque data<>; }` on `NFS4_OK`.
 *
 * Unlike NFSv3's, there is **no `count` field**: the counted `data<>` is the
 * count, so there is no pair for the two to disagree about and no cross-check
 * to make. `eof` comes first, which is easy to write in the wrong order and
 * impossible to notice without a byte fixture.
 */
export interface Read4res {
  status: number;
  eof: boolean;
  data: Uint8Array;
}

export function writeReadArgs(writer: XdrWriter, args: Read4args): void {
  writeStateid(writer, args.stateid);
  writer.u64(args.offset);
  writer.u32(args.count);
}

export function readReadArgs(reader: XdrReader): Read4args {
  return {
    stateid: readStateid(reader, "READ4args.stateid"),
    offset: reader.u64("READ4args.offset"),
    count: reader.u32("READ4args.count"),
  };
}

export function writeReadRes(writer: XdrWriter, res: Read4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writer.bool(res.eof);
    writer.varOpaque(res.data);
  }
}

/**
 * Decode a READ result.
 *
 * `max` bounds the payload, exactly as `../v3/protocol.ts`'s `readReadRes` does
 * and for the same reason: the honest ceiling is the session's `maxread`, which
 * the codec does not know, so it takes one and falls back to `XDR_MAX_ITEM`.
 * The table below calls it with none.
 */
export function readReadRes(reader: XdrReader, max = XDR_MAX_ITEM): Read4res {
  const status = reader.u32("READ4res.status");
  if (status !== NFS4_OK) {
    return { status, eof: false, data: new Uint8Array(0) };
  }
  return {
    status,
    eof: reader.bool("READ4resok.eof"),
    // `varOpaque` copies: the payload outlives the receive buffer.
    data: reader.varOpaque(max, "READ4resok.data"),
  };
}

// ---------------------------------------------------------------------------
// WRITE (RFC 8881 §18.32)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct WRITE4args {
 *         [CURRENT_FH: file]
 *         stateid4        stateid;
 *         offset4         offset;
 *         stable_how4     stable;
 *         opaque          data<>;
 * };
 * ```
 *
 * Same simplification as READ: no `count` beside the payload. `stable` is
 * `UNSTABLE4`, `DATA_SYNC4` or `FILE_SYNC4`, and the reply says which of them
 * the server actually achieved.
 */
export interface Write4args {
  stateid: Stateid4;
  offset: bigint;
  /** `stable_how4`. */
  stable: number;
  data: Uint8Array;
}

/**
 * `union WRITE4res` — on `NFS4_OK`, `WRITE4resok { count4 count; stable_how4
 * committed; verifier4 writeverf; }`.
 *
 * `committed` may be *stronger* than the `stable` that was asked for but never
 * weaker, and `writeverf` is how a client detects a server restart between an
 * unstable WRITE and its COMMIT: a changed verifier means the data is gone and
 * must be written again.
 */
export interface Write4res {
  status: number;
  count: number;
  committed: number;
  writeverf: Uint8Array;
}

export function writeWriteArgs(writer: XdrWriter, args: Write4args): void {
  writeStateid(writer, args.stateid);
  writer.u64(args.offset);
  writer.u32(args.stable);
  writer.varOpaque(args.data);
}

/** Decode WRITE arguments; `max` bounds the payload, as in {@link readReadRes}. */
export function readWriteArgs(reader: XdrReader, max = XDR_MAX_ITEM): Write4args {
  return {
    stateid: readStateid(reader, "WRITE4args.stateid"),
    offset: reader.u64("WRITE4args.offset"),
    stable: reader.u32("WRITE4args.stable"),
    // `varOpaque` copies — the bytes are handed to a driver and kept.
    data: reader.varOpaque(max, "WRITE4args.data"),
  };
}

export function writeWriteRes(writer: XdrWriter, res: Write4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writer.u32(res.count);
    writer.u32(res.committed);
    writeVerifier4(writer, res.writeverf);
  }
}

export function readWriteRes(reader: XdrReader): Write4res {
  const status = reader.u32("WRITE4res.status");
  if (status !== NFS4_OK) {
    return { status, count: 0, committed: 0, writeverf: new Uint8Array(NFS4_VERIFIER_SIZE) };
  }
  return {
    status,
    count: reader.u32("WRITE4resok.count"),
    committed: reader.u32("WRITE4resok.committed"),
    writeverf: readVerifier4(reader, "WRITE4resok.writeverf"),
  };
}

// ---------------------------------------------------------------------------
// BACKCHANNEL_CTL (RFC 8881 §18.33)
// ---------------------------------------------------------------------------

/**
 * `struct BACKCHANNEL_CTL4args { uint32_t bca_cb_program;
 * callback_sec_parms4 bca_sec_parms<>; }`.
 *
 * Re-points the back channel of an existing session. This server has none, so
 * the answer is a status; the arguments are still decoded in full, because the
 * operations after it in the COMPOUND have to be reachable.
 */
export interface BackchannelCtl4args {
  cbProgram: number;
  secParms: CallbackSecParms4[];
}

/** `struct BACKCHANNEL_CTL4res { nfsstat4 bcr_status; }`. */
export type BackchannelCtl4res = Status4res;

export function writeBackchannelCtlArgs(writer: XdrWriter, args: BackchannelCtl4args): void {
  writer.u32(args.cbProgram);
  writer.array(args.secParms, writeCallbackSecParms4);
}

export function readBackchannelCtlArgs(reader: XdrReader): BackchannelCtl4args {
  return {
    cbProgram: reader.u32("BACKCHANNEL_CTL4args.bca_cb_program"),
    secParms: reader.array(
      readCallbackSecParms4,
      NFS4_MAX_SEC_PARMS,
      "BACKCHANNEL_CTL4args.bca_sec_parms",
    ),
  };
}

// ---------------------------------------------------------------------------
// BIND_CONN_TO_SESSION (RFC 8881 §18.34)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct BIND_CONN_TO_SESSION4args {
 *  sessionid4                bctsa_sessid;
 *  channel_dir_from_client4  bctsa_dir;
 *  bool                      bctsa_use_conn_in_rdma_mode;
 * };
 * ```
 *
 * How a *second* connection joins an existing session — trunking, or a
 * reconnect after the first died. The direction enums are plain fields rather
 * than union discriminants, so an unrecognised one decodes fine and is the
 * session's `NFS4ERR_INVAL` to give.
 */
export interface BindConnToSession4args {
  sessionid: Uint8Array;
  /** `channel_dir_from_client4`. */
  dir: number;
  useConnInRdmaMode: boolean;
}

/**
 * `union BIND_CONN_TO_SESSION4res` — on `NFS4_OK`,
 * `BIND_CONN_TO_SESSION4resok { sessionid4 bctsr_sessid;
 * channel_dir_from_server4 bctsr_dir; bool bctsr_use_conn_in_rdma_mode; }`.
 *
 * `bctsr_dir` is a *different enum* from the argument's, with different values:
 * the client asks with `CDFC4_*` and the server answers with `CDFS4_*`. Same
 * shape, same position, unrelated numbering.
 */
export interface BindConnToSession4res {
  status: number;
  sessionid: Uint8Array;
  /** `channel_dir_from_server4`. */
  dir: number;
  useConnInRdmaMode: boolean;
}

export function writeBindConnToSessionArgs(writer: XdrWriter, args: BindConnToSession4args): void {
  writeSessionId4(writer, args.sessionid);
  writer.u32(args.dir);
  writer.bool(args.useConnInRdmaMode);
}

export function readBindConnToSessionArgs(reader: XdrReader): BindConnToSession4args {
  return {
    sessionid: readSessionId4(reader, "BIND_CONN_TO_SESSION4args.bctsa_sessid"),
    dir: reader.u32("BIND_CONN_TO_SESSION4args.bctsa_dir"),
    useConnInRdmaMode: reader.bool("BIND_CONN_TO_SESSION4args.bctsa_use_conn_in_rdma_mode"),
  };
}

export function writeBindConnToSessionRes(writer: XdrWriter, res: BindConnToSession4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writeSessionId4(writer, res.sessionid);
    writer.u32(res.dir);
    writer.bool(res.useConnInRdmaMode);
  }
}

export function readBindConnToSessionRes(reader: XdrReader): BindConnToSession4res {
  const status = reader.u32("BIND_CONN_TO_SESSION4res.bctsr_status");
  if (status !== NFS4_OK) {
    return {
      status,
      sessionid: new Uint8Array(NFS4_SESSIONID_SIZE),
      dir: 0,
      useConnInRdmaMode: false,
    };
  }
  return {
    status,
    sessionid: readSessionId4(reader, "BIND_CONN_TO_SESSION4resok.bctsr_sessid"),
    dir: reader.u32("BIND_CONN_TO_SESSION4resok.bctsr_dir"),
    useConnInRdmaMode: reader.bool("BIND_CONN_TO_SESSION4resok.bctsr_use_conn_in_rdma_mode"),
  };
}

// ---------------------------------------------------------------------------
// EXCHANGE_ID (RFC 8881 §18.35)
// ---------------------------------------------------------------------------

/**
 * `struct ssv_sp_parms4` (RFC 8881 §18.35.1) — what `SP4_SSV` asks for.
 *
 * The SSV (secret state verifier) scheme lets a client protect state-changing
 * operations with a shared key rather than a machine credential. This server
 * offers `SP4_NONE` and refuses the rest with a status; the codec carries all
 * three arms because refusing an offer means decoding it first.
 */
export interface SsvSpParms4 {
  ops: StateProtectOps4;
  /** `sec_oid4 ssp_hash_algs<>`. */
  hashAlgs: Uint8Array[];
  /** `sec_oid4 ssp_encr_algs<>`. */
  encrAlgs: Uint8Array[];
  window: number;
  numGssHandles: number;
}

/** `struct ssv_prot_info4` (RFC 8881 §18.35.2) — what a server granting `SP4_SSV` answers. */
export interface SsvProtInfo4 {
  ops: StateProtectOps4;
  hashAlg: number;
  encrAlg: number;
  ssvLen: number;
  window: number;
  /** `gsshandle4_t spi_handles<>`. */
  handles: Uint8Array[];
}

/**
 * ```
 * union state_protect4_a switch (state_protect_how4 spa_how) {
 *  case SP4_NONE:        void;
 *  case SP4_MACH_CRED:   state_protect_ops4  spa_mach_ops;
 *  case SP4_SSV:         ssv_sp_parms4       spa_ssv_parms;
 * };
 * ```
 *
 * **No default arm**: an unknown `spa_how` is a malformed message.
 */
export interface StateProtect4a {
  /** `state_protect_how4`. */
  how: number;
  /** `SP4_MACH_CRED`. */
  machOps?: StateProtectOps4 | undefined;
  /** `SP4_SSV`. */
  ssvParms?: SsvSpParms4 | undefined;
}

/** `union state_protect4_r` — the same three arms, `ssv_prot_info4` on `SP4_SSV`. */
export interface StateProtect4r {
  /** `state_protect_how4`. */
  how: number;
  /** `SP4_MACH_CRED`. */
  machOps?: StateProtectOps4 | undefined;
  /** `SP4_SSV`. */
  ssvInfo?: SsvProtInfo4 | undefined;
}

/**
 * ```
 * struct EXCHANGE_ID4args {
 *         client_owner4           eia_clientowner;
 *         uint32_t                eia_flags;
 *         state_protect4_a        eia_state_protect;
 *         nfs_impl_id4            eia_client_impl_id<1>;
 * };
 * ```
 *
 * The first operation of any 4.1 conversation: it trades a `client_owner4` for
 * a `clientid4`, and everything stateful hangs off that. It takes no
 * filehandle, and it is one of the five operations §18.46.3 allows to open a
 * COMPOUND with no SEQUENCE in front of it.
 */
export interface ExchangeId4args {
  clientowner: ClientOwner4;
  flags: number;
  stateProtect: StateProtect4a;
  /** `<1>` — zero or one, never more. */
  clientImplId: NfsImplId4[];
}

/**
 * ```
 * struct EXCHANGE_ID4resok {
 *  clientid4        eir_clientid;
 *  sequenceid4      eir_sequenceid;
 *  uint32_t         eir_flags;
 *  state_protect4_r eir_state_protect;
 *  server_owner4    eir_server_owner;
 *  opaque           eir_server_scope<NFS4_OPAQUE_LIMIT>;
 *  nfs_impl_id4     eir_server_impl_id<1>;
 * };
 * ```
 * on `NFS4_OK`, void otherwise.
 *
 * `eir_sequenceid` seeds the *client ID's* sequence, not a slot's:
 * CREATE_SESSION echoes it back and the server uses the pair to detect a
 * replayed session creation.
 */
export interface ExchangeId4res {
  status: number;
  clientid: bigint;
  sequenceid: number;
  flags: number;
  stateProtect: StateProtect4r | undefined;
  serverOwner: ServerOwner4 | undefined;
  serverScope: Uint8Array;
  serverImplId: NfsImplId4[];
}

export function writeSsvSpParms4(writer: XdrWriter, parms: SsvSpParms4): void {
  writeStateProtectOps4(writer, parms.ops);
  writer.array(parms.hashAlgs, (w, oid) => w.varOpaque(oid));
  writer.array(parms.encrAlgs, (w, oid) => w.varOpaque(oid));
  writer.u32(parms.window);
  writer.u32(parms.numGssHandles);
}

export function readSsvSpParms4(reader: XdrReader): SsvSpParms4 {
  return {
    ops: readStateProtectOps4(reader, "ssv_sp_parms4.ssp_ops"),
    hashAlgs: reader.array(
      (r) => r.varOpaque(NFS4_MAX_SEC_OID, "ssp_hash_algs"),
      NFS4_MAX_SSV_LIST,
      "ssv_sp_parms4.ssp_hash_algs",
    ),
    encrAlgs: reader.array(
      (r) => r.varOpaque(NFS4_MAX_SEC_OID, "ssp_encr_algs"),
      NFS4_MAX_SSV_LIST,
      "ssv_sp_parms4.ssp_encr_algs",
    ),
    window: reader.u32("ssv_sp_parms4.ssp_window"),
    numGssHandles: reader.u32("ssv_sp_parms4.ssp_num_gss_handles"),
  };
}

export function writeSsvProtInfo4(writer: XdrWriter, info: SsvProtInfo4): void {
  writeStateProtectOps4(writer, info.ops);
  writer.u32(info.hashAlg);
  writer.u32(info.encrAlg);
  writer.u32(info.ssvLen);
  writer.u32(info.window);
  writer.array(info.handles, (w, handle) => w.varOpaque(handle));
}

export function readSsvProtInfo4(reader: XdrReader): SsvProtInfo4 {
  return {
    ops: readStateProtectOps4(reader, "ssv_prot_info4.spi_ops"),
    hashAlg: reader.u32("ssv_prot_info4.spi_hash_alg"),
    encrAlg: reader.u32("ssv_prot_info4.spi_encr_alg"),
    ssvLen: reader.u32("ssv_prot_info4.spi_ssv_len"),
    window: reader.u32("ssv_prot_info4.spi_window"),
    handles: reader.array(
      (r) => r.varOpaque(NFS4_MAX_GSS_HANDLE, "spi_handles"),
      NFS4_MAX_SSV_LIST,
      "ssv_prot_info4.spi_handles",
    ),
  };
}

/** The `state_protect_ops4` written for a `SP4_MACH_CRED` arm carrying none. */
const NO_PROTECT_OPS: StateProtectOps4 = { mustEnforce: [], mustAllow: [] };

export function writeStateProtect4a(writer: XdrWriter, protect: StateProtect4a): void {
  writer.u32(protect.how);
  if (protect.how === SP4_NONE) {
    return;
  }
  if (protect.how === SP4_MACH_CRED) {
    writeStateProtectOps4(writer, protect.machOps ?? NO_PROTECT_OPS);
    return;
  }
  if (protect.how === SP4_SSV) {
    writeSsvSpParms4(
      writer,
      protect.ssvParms ?? {
        ops: NO_PROTECT_OPS,
        hashAlgs: [],
        encrAlgs: [],
        window: 0,
        numGssHandles: 0,
      },
    );
    return;
  }
  throw new XdrError(`state_protect4_a has no arm for spa_how ${protect.how}`);
}

export function readStateProtect4a(reader: XdrReader): StateProtect4a {
  const how = reader.u32("state_protect4_a.spa_how");
  if (how === SP4_NONE) {
    return { how };
  }
  if (how === SP4_MACH_CRED) {
    return { how, machOps: readStateProtectOps4(reader, "spa_mach_ops") };
  }
  if (how === SP4_SSV) {
    return { how, ssvParms: readSsvSpParms4(reader) };
  }
  throw new XdrError(`state_protect4_a has no arm for spa_how ${how}`);
}

export function writeStateProtect4r(writer: XdrWriter, protect: StateProtect4r): void {
  writer.u32(protect.how);
  if (protect.how === SP4_NONE) {
    return;
  }
  if (protect.how === SP4_MACH_CRED) {
    writeStateProtectOps4(writer, protect.machOps ?? NO_PROTECT_OPS);
    return;
  }
  if (protect.how === SP4_SSV) {
    writeSsvProtInfo4(
      writer,
      protect.ssvInfo ?? {
        ops: NO_PROTECT_OPS,
        hashAlg: 0,
        encrAlg: 0,
        ssvLen: 0,
        window: 0,
        handles: [],
      },
    );
    return;
  }
  throw new XdrError(`state_protect4_r has no arm for spr_how ${protect.how}`);
}

export function readStateProtect4r(reader: XdrReader): StateProtect4r {
  const how = reader.u32("state_protect4_r.spr_how");
  if (how === SP4_NONE) {
    return { how };
  }
  if (how === SP4_MACH_CRED) {
    return { how, machOps: readStateProtectOps4(reader, "spr_mach_ops") };
  }
  if (how === SP4_SSV) {
    return { how, ssvInfo: readSsvProtInfo4(reader) };
  }
  throw new XdrError(`state_protect4_r has no arm for spr_how ${how}`);
}

export function writeExchangeIdArgs(writer: XdrWriter, args: ExchangeId4args): void {
  writeClientOwner4(writer, args.clientowner);
  writer.u32(args.flags);
  writeStateProtect4a(writer, args.stateProtect);
  writer.array(args.clientImplId, writeImplId4);
}

export function readExchangeIdArgs(reader: XdrReader): ExchangeId4args {
  return {
    clientowner: readClientOwner4(reader, "EXCHANGE_ID4args.eia_clientowner"),
    flags: reader.u32("EXCHANGE_ID4args.eia_flags"),
    stateProtect: readStateProtect4a(reader),
    clientImplId: reader.array(
      readImplId4,
      NFS4_MAX_OPTIONAL_ONE,
      "EXCHANGE_ID4args.eia_client_impl_id",
    ),
  };
}

export function writeExchangeIdRes(writer: XdrWriter, res: ExchangeId4res): void {
  writer.u32(res.status);
  if (res.status !== NFS4_OK) {
    return;
  }
  writer.u64(res.clientid);
  writer.u32(res.sequenceid);
  writer.u32(res.flags);
  writeStateProtect4r(writer, res.stateProtect ?? { how: SP4_NONE });
  writeServerOwner4(writer, res.serverOwner ?? { minorId: 0n, majorId: new Uint8Array(0) });
  writer.varOpaque(res.serverScope);
  writer.array(res.serverImplId, writeImplId4);
}

export function readExchangeIdRes(reader: XdrReader): ExchangeId4res {
  const status = reader.u32("EXCHANGE_ID4res.eir_status");
  if (status !== NFS4_OK) {
    return {
      status,
      clientid: 0n,
      sequenceid: 0,
      flags: 0,
      stateProtect: undefined,
      serverOwner: undefined,
      serverScope: new Uint8Array(0),
      serverImplId: [],
    };
  }
  return {
    status,
    clientid: reader.u64("EXCHANGE_ID4resok.eir_clientid"),
    sequenceid: reader.u32("EXCHANGE_ID4resok.eir_sequenceid"),
    flags: reader.u32("EXCHANGE_ID4resok.eir_flags"),
    stateProtect: readStateProtect4r(reader),
    serverOwner: readServerOwner4(reader, "EXCHANGE_ID4resok.eir_server_owner"),
    serverScope: reader.varOpaque(NFS4_OPAQUE_LIMIT, "EXCHANGE_ID4resok.eir_server_scope"),
    serverImplId: reader.array(
      readImplId4,
      NFS4_MAX_OPTIONAL_ONE,
      "EXCHANGE_ID4resok.eir_server_impl_id",
    ),
  };
}

// ---------------------------------------------------------------------------
// CREATE_SESSION (RFC 8881 §18.36)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct channel_attrs4 {
 *         count4          ca_headerpadsize;
 *         count4          ca_maxrequestsize;
 *         count4          ca_maxresponsesize;
 *         count4          ca_maxresponsesize_cached;
 *         count4          ca_maxoperations;
 *         count4          ca_maxrequests;
 *         uint32_t        ca_rdma_ird<1>;
 * };
 * ```
 *
 * The negotiated size limits of one channel, and where the *real* bounds on a
 * COMPOUND come from — `ca_maxoperations` and `ca_maxrequestsize` are what the
 * decode limits at the top of this file sit underneath. Six counts of the same
 * type in a row, which is precisely the struct a transposed pair hides in.
 */
export interface ChannelAttrs4 {
  headerpadsize: number;
  maxrequestsize: number;
  maxresponsesize: number;
  maxresponsesizeCached: number;
  maxoperations: number;
  maxrequests: number;
  /** `<1>` — zero or one. */
  rdmaIrd: number[];
}

/**
 * ```
 * struct CREATE_SESSION4args {
 *         clientid4               csa_clientid;
 *         sequenceid4             csa_sequence;
 *         uint32_t                csa_flags;
 *         channel_attrs4          csa_fore_chan_attrs;
 *         channel_attrs4          csa_back_chan_attrs;
 *         uint32_t                csa_cb_program;
 *         callback_sec_parms4     csa_sec_parms<>;
 * };
 * ```
 *
 * Two `channel_attrs4` in a row, fore then back, and they are not
 * interchangeable — the fore channel is the client's requests and the back one
 * the server's callbacks.
 */
export interface CreateSession4args {
  clientid: bigint;
  sequence: number;
  flags: number;
  foreChanAttrs: ChannelAttrs4;
  backChanAttrs: ChannelAttrs4;
  cbProgram: number;
  secParms: CallbackSecParms4[];
}

/**
 * ```
 * struct CREATE_SESSION4resok {
 *         sessionid4              csr_sessionid;
 *         sequenceid4             csr_sequence;
 *         uint32_t                csr_flags;
 *         channel_attrs4          csr_fore_chan_attrs;
 *         channel_attrs4          csr_back_chan_attrs;
 * };
 * ```
 * on `NFS4_OK`, void otherwise.
 *
 * The returned attributes are the server's *counter-offer*, and every one of
 * them may be smaller than what was asked for; the client has to use these and
 * not the ones it sent (§18.36.3).
 */
export interface CreateSession4res {
  status: number;
  sessionid: Uint8Array;
  sequence: number;
  flags: number;
  foreChanAttrs: ChannelAttrs4 | undefined;
  backChanAttrs: ChannelAttrs4 | undefined;
}

export function writeChannelAttrs4(writer: XdrWriter, attrs: ChannelAttrs4): void {
  writer.u32(attrs.headerpadsize);
  writer.u32(attrs.maxrequestsize);
  writer.u32(attrs.maxresponsesize);
  writer.u32(attrs.maxresponsesizeCached);
  writer.u32(attrs.maxoperations);
  writer.u32(attrs.maxrequests);
  writer.array(attrs.rdmaIrd, (w, ird) => w.u32(ird));
}

export function readChannelAttrs4(reader: XdrReader, what = "channel_attrs4"): ChannelAttrs4 {
  return {
    headerpadsize: reader.u32(`${what}.ca_headerpadsize`),
    maxrequestsize: reader.u32(`${what}.ca_maxrequestsize`),
    maxresponsesize: reader.u32(`${what}.ca_maxresponsesize`),
    maxresponsesizeCached: reader.u32(`${what}.ca_maxresponsesize_cached`),
    maxoperations: reader.u32(`${what}.ca_maxoperations`),
    maxrequests: reader.u32(`${what}.ca_maxrequests`),
    rdmaIrd: reader.array(
      (r) => r.u32("ca_rdma_ird"),
      NFS4_MAX_OPTIONAL_ONE,
      `${what}.ca_rdma_ird`,
    ),
  };
}

/** The `channel_attrs4` written for a successful result that carries none. */
const NO_CHANNEL_ATTRS: ChannelAttrs4 = {
  headerpadsize: 0,
  maxrequestsize: 0,
  maxresponsesize: 0,
  maxresponsesizeCached: 0,
  maxoperations: 0,
  maxrequests: 0,
  rdmaIrd: [],
};

export function writeCreateSessionArgs(writer: XdrWriter, args: CreateSession4args): void {
  writer.u64(args.clientid);
  writer.u32(args.sequence);
  writer.u32(args.flags);
  writeChannelAttrs4(writer, args.foreChanAttrs);
  writeChannelAttrs4(writer, args.backChanAttrs);
  writer.u32(args.cbProgram);
  writer.array(args.secParms, writeCallbackSecParms4);
}

export function readCreateSessionArgs(reader: XdrReader): CreateSession4args {
  return {
    clientid: reader.u64("CREATE_SESSION4args.csa_clientid"),
    sequence: reader.u32("CREATE_SESSION4args.csa_sequence"),
    flags: reader.u32("CREATE_SESSION4args.csa_flags"),
    foreChanAttrs: readChannelAttrs4(reader, "csa_fore_chan_attrs"),
    backChanAttrs: readChannelAttrs4(reader, "csa_back_chan_attrs"),
    cbProgram: reader.u32("CREATE_SESSION4args.csa_cb_program"),
    secParms: reader.array(
      readCallbackSecParms4,
      NFS4_MAX_SEC_PARMS,
      "CREATE_SESSION4args.csa_sec_parms",
    ),
  };
}

export function writeCreateSessionRes(writer: XdrWriter, res: CreateSession4res): void {
  writer.u32(res.status);
  if (res.status !== NFS4_OK) {
    return;
  }
  writeSessionId4(writer, res.sessionid);
  writer.u32(res.sequence);
  writer.u32(res.flags);
  writeChannelAttrs4(writer, res.foreChanAttrs ?? NO_CHANNEL_ATTRS);
  writeChannelAttrs4(writer, res.backChanAttrs ?? NO_CHANNEL_ATTRS);
}

export function readCreateSessionRes(reader: XdrReader): CreateSession4res {
  const status = reader.u32("CREATE_SESSION4res.csr_status");
  if (status !== NFS4_OK) {
    return {
      status,
      sessionid: new Uint8Array(NFS4_SESSIONID_SIZE),
      sequence: 0,
      flags: 0,
      foreChanAttrs: undefined,
      backChanAttrs: undefined,
    };
  }
  return {
    status,
    sessionid: readSessionId4(reader, "CREATE_SESSION4resok.csr_sessionid"),
    sequence: reader.u32("CREATE_SESSION4resok.csr_sequence"),
    flags: reader.u32("CREATE_SESSION4resok.csr_flags"),
    foreChanAttrs: readChannelAttrs4(reader, "csr_fore_chan_attrs"),
    backChanAttrs: readChannelAttrs4(reader, "csr_back_chan_attrs"),
  };
}

// ---------------------------------------------------------------------------
// DESTROY_SESSION (RFC 8881 §18.37) / DESTROY_CLIENTID (§18.50)
// ---------------------------------------------------------------------------

/** `struct DESTROY_SESSION4args { sessionid4 dsa_sessionid; }`. */
export interface DestroySession4args {
  sessionid: Uint8Array;
}

/** `struct DESTROY_SESSION4res { nfsstat4 dsr_status; }`. */
export type DestroySession4res = Status4res;

/** `struct DESTROY_CLIENTID4args { clientid4 dca_clientid; }`. */
export interface DestroyClientid4args {
  clientid: bigint;
}

/** `struct DESTROY_CLIENTID4res { nfsstat4 dcr_status; }`. */
export type DestroyClientid4res = Status4res;

export function writeDestroySessionArgs(writer: XdrWriter, args: DestroySession4args): void {
  writeSessionId4(writer, args.sessionid);
}

export function readDestroySessionArgs(reader: XdrReader): DestroySession4args {
  return { sessionid: readSessionId4(reader, "DESTROY_SESSION4args.dsa_sessionid") };
}

export function writeDestroyClientidArgs(writer: XdrWriter, args: DestroyClientid4args): void {
  writer.u64(args.clientid);
}

export function readDestroyClientidArgs(reader: XdrReader): DestroyClientid4args {
  return { clientid: reader.u64("DESTROY_CLIENTID4args.dca_clientid") };
}

// ---------------------------------------------------------------------------
// FREE_STATEID (RFC 8881 §18.38)
// ---------------------------------------------------------------------------

/** `struct FREE_STATEID4args { stateid4 fsa_stateid; }`. */
export interface FreeStateid4args {
  stateid: Stateid4;
}

/** `struct FREE_STATEID4res { nfsstat4 fsr_status; }`. */
export type FreeStateid4res = Status4res;

export function writeFreeStateidArgs(writer: XdrWriter, args: FreeStateid4args): void {
  writeStateid(writer, args.stateid);
}

export function readFreeStateidArgs(reader: XdrReader): FreeStateid4args {
  return { stateid: readStateid(reader, "FREE_STATEID4args.fsa_stateid") };
}

// ---------------------------------------------------------------------------
// SEQUENCE (RFC 8881 §18.46)
// ---------------------------------------------------------------------------

/**
 * ```
 * struct SEQUENCE4args {
 *         sessionid4     sa_sessionid;
 *         sequenceid4    sa_sequenceid;
 *         slotid4        sa_slotid;
 *         slotid4        sa_highest_slotid;
 *         bool           sa_cachethis;
 * };
 * ```
 *
 * The operation that makes NFSv4.1 exactly-once: a request occupies a *slot*,
 * and the `(slot, sequence)` pair lets the server recognise a retransmission
 * and replay its cached reply instead of executing twice.
 *
 * §18.46.3 puts it two ways, and both matter to a session: SEQUENCE **must be
 * first** when it appears at all (`NFS4ERR_SEQUENCE_POS` otherwise), and the
 * only operations allowed to be first *without* it are SEQUENCE itself,
 * BIND_CONN_TO_SESSION, EXCHANGE_ID, CREATE_SESSION and DESTROY_SESSION — the
 * five that establish or repair the session a slot would otherwise live in.
 */
export interface Sequence4args {
  sessionid: Uint8Array;
  sequenceid: number;
  slotid: number;
  highestSlotid: number;
  cachethis: boolean;
}

/**
 * ```
 * struct SEQUENCE4resok {
 *         sessionid4      sr_sessionid;
 *         sequenceid4     sr_sequenceid;
 *         slotid4         sr_slotid;
 *         slotid4         sr_highest_slotid;
 *         slotid4         sr_target_highest_slotid;
 *         uint32_t        sr_status_flags;
 * };
 * ```
 * on `NFS4_OK`, void otherwise.
 *
 * Three consecutive `slotid4`s, and they mean three different things:
 * `sr_highest_slotid` is the largest the server will accept *now*,
 * `sr_target_highest_slotid` the size it would like the client to move toward.
 * `sr_status_flags` is the `SEQ4_STATUS_*` word — the channel by which a server
 * reports revoked state, an expired lease or a dead back channel without being
 * asked.
 */
export interface Sequence4res {
  status: number;
  sessionid: Uint8Array;
  sequenceid: number;
  slotid: number;
  highestSlotid: number;
  targetHighestSlotid: number;
  statusFlags: number;
}

export function writeSequenceArgs(writer: XdrWriter, args: Sequence4args): void {
  writeSessionId4(writer, args.sessionid);
  writer.u32(args.sequenceid);
  writer.u32(args.slotid);
  writer.u32(args.highestSlotid);
  writer.bool(args.cachethis);
}

export function readSequenceArgs(reader: XdrReader): Sequence4args {
  return {
    sessionid: readSessionId4(reader, "SEQUENCE4args.sa_sessionid"),
    sequenceid: reader.u32("SEQUENCE4args.sa_sequenceid"),
    slotid: reader.u32("SEQUENCE4args.sa_slotid"),
    highestSlotid: reader.u32("SEQUENCE4args.sa_highest_slotid"),
    cachethis: reader.bool("SEQUENCE4args.sa_cachethis"),
  };
}

export function writeSequenceRes(writer: XdrWriter, res: Sequence4res): void {
  writer.u32(res.status);
  if (res.status !== NFS4_OK) {
    return;
  }
  writeSessionId4(writer, res.sessionid);
  writer.u32(res.sequenceid);
  writer.u32(res.slotid);
  writer.u32(res.highestSlotid);
  writer.u32(res.targetHighestSlotid);
  writer.u32(res.statusFlags);
}

export function readSequenceRes(reader: XdrReader): Sequence4res {
  const status = reader.u32("SEQUENCE4res.sr_status");
  if (status !== NFS4_OK) {
    return {
      status,
      sessionid: new Uint8Array(NFS4_SESSIONID_SIZE),
      sequenceid: 0,
      slotid: 0,
      highestSlotid: 0,
      targetHighestSlotid: 0,
      statusFlags: 0,
    };
  }
  return {
    status,
    sessionid: readSessionId4(reader, "SEQUENCE4resok.sr_sessionid"),
    sequenceid: reader.u32("SEQUENCE4resok.sr_sequenceid"),
    slotid: reader.u32("SEQUENCE4resok.sr_slotid"),
    highestSlotid: reader.u32("SEQUENCE4resok.sr_highest_slotid"),
    targetHighestSlotid: reader.u32("SEQUENCE4resok.sr_target_highest_slotid"),
    statusFlags: reader.u32("SEQUENCE4resok.sr_status_flags"),
  };
}

// ---------------------------------------------------------------------------
// TEST_STATEID (RFC 8881 §18.48)
// ---------------------------------------------------------------------------

/** `struct TEST_STATEID4args { stateid4 ts_stateids<>; }`. */
export interface TestStateid4args {
  stateids: Stateid4[];
}

/**
 * `union TEST_STATEID4res` — `TEST_STATEID4resok { nfsstat4
 * tsr_status_codes<>; }` on `NFS4_OK`, void otherwise.
 *
 * A list in and a list of statuses out, positionally matched: the operation
 * succeeds even when every stateid in it is invalid, and each verdict is an
 * element rather than the operation's own status.
 */
export interface TestStateid4res {
  status: number;
  statusCodes: number[];
}

export function writeTestStateidArgs(writer: XdrWriter, args: TestStateid4args): void {
  writer.array(args.stateids, writeStateid);
}

export function readTestStateidArgs(reader: XdrReader): TestStateid4args {
  return {
    stateids: reader.array(
      (r) => readStateid(r, "ts_stateids"),
      NFS4_MAX_TEST_STATEIDS,
      "TEST_STATEID4args.ts_stateids",
    ),
  };
}

export function writeTestStateidRes(writer: XdrWriter, res: TestStateid4res): void {
  writer.u32(res.status);
  if (res.status === NFS4_OK) {
    writer.array(res.statusCodes, (w, code) => w.u32(code));
  }
}

export function readTestStateidRes(reader: XdrReader): TestStateid4res {
  const status = reader.u32("TEST_STATEID4res.tsr_status");
  return {
    status,
    statusCodes:
      status === NFS4_OK
        ? reader.array(
            (r) => r.u32("tsr_status_codes"),
            NFS4_MAX_TEST_STATEIDS,
            "TEST_STATEID4resok.tsr_status_codes",
          )
        : [],
  };
}

// ---------------------------------------------------------------------------
// RECLAIM_COMPLETE (RFC 8881 §18.51)
// ---------------------------------------------------------------------------

/**
 * `struct RECLAIM_COMPLETE4args { bool rca_one_fs; }`.
 *
 * One bool, and the two values mean different operations: `FALSE` is the global
 * "I have finished reclaiming everything" a client must send before its first
 * non-reclaim lock, and `TRUE` is the per-filesystem form used after a
 * migration, which needs a current filehandle (§18.51.3).
 */
export interface ReclaimComplete4args {
  oneFs: boolean;
}

/** `struct RECLAIM_COMPLETE4res { nfsstat4 rcr_status; }`. */
export type ReclaimComplete4res = Status4res;

export function writeReclaimCompleteArgs(writer: XdrWriter, args: ReclaimComplete4args): void {
  writer.bool(args.oneFs);
}

export function readReclaimCompleteArgs(reader: XdrReader): ReclaimComplete4args {
  return { oneFs: reader.bool("RECLAIM_COMPLETE4args.rca_one_fs") };
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
  | BackchannelCtl4args
  | BindConnToSession4args
  | Close4args
  | Commit4args
  | Create4args
  | CreateSession4args
  | DestroyClientid4args
  | DestroySession4args
  | ExchangeId4args
  | FreeStateid4args
  | Getattr4args
  | Link4args
  | Lock4args
  | Lockt4args
  | Locku4args
  | Lookup4args
  | Open4args
  | OpenDowngrade4args
  | Putfh4args
  | Read4args
  | Readdir4args
  | ReclaimComplete4args
  | Remove4args
  | Rename4args
  | Secinfo4args
  | SecinfoNoName4args
  | Sequence4args
  | Setattr4args
  | TestStateid4args
  | Verify4args
  | Write4args;

/** Every result struct this table can carry. Each one starts with its `status`. */
export type Resop4Value =
  | Access4res
  | BindConnToSession4res
  | Close4res
  | Commit4res
  | Create4res
  | CreateSession4res
  | ExchangeId4res
  | Getattr4res
  | Getfh4res
  | Link4res
  | Lock4res
  | Lockt4res
  | Locku4res
  | Open4res
  | OpenDowngrade4res
  | Read4res
  | Readdir4res
  | Readlink4res
  | Remove4res
  | Rename4res
  | Secinfo4res
  | Sequence4res
  | Setattr4res
  | Status4res
  | TestStateid4res
  | Write4res;

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
 * ## What is deliberately absent
 *
 * NFSv4.1 defines operations this server will never implement — DELEGRETURN,
 * OPENATTR, GETDEVICEINFO, the LAYOUT family, DELEGPURGE, GET_DIR_DELEGATION,
 * SET_SSV, WANT_DELEGATION, and the four NFSv4.0 leftovers (OPEN_CONFIRM,
 * RENEW, SETCLIENTID, SETCLIENTID_CONFIRM, RELEASE_LOCKOWNER) that are illegal
 * in 4.1 anyway. **They have no rows here, and that is the design.**
 *
 * The answer to one of them is `NFS4ERR_NOTSUPP`, and a status is all a
 * `union XXX4res switch (nfsstat4)` carries on a failure — so the session
 * (`./session.ts`) can emit the resop with {@link writeStatusRes} without any
 * per-operation knowledge, and must then **halt the COMPOUND**: RFC 8881
 * §16.2.3 says processing stops at the first failing operation, and the
 * arguments of the unsupported operation were never decoded, so there is no
 * safe offset to resume from. An operation carries no length prefix; the
 * undecodable bytes after the opcode are simply not walked, which is only
 * sound because nothing after them is walked either.
 *
 * That is why {@link opCodec4} throws {@link XdrError} naming the operation
 * rather than returning a status-only row: "I do not support this" is the
 * session's answer to give, at the point it can also stop, and a decoder that
 * quietly skipped ahead would desync instead.
 */
const OP_CODEC_LIST: readonly OpCodec4[] = [
  op4(
    OP_ACCESS,
    { read: readAccessArgs, write: writeAccessArgs },
    { read: readAccessRes, write: writeAccessRes },
  ),
  op4(
    OP_CLOSE,
    { read: readCloseArgs, write: writeCloseArgs },
    { read: readCloseRes, write: writeCloseRes },
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
  op4(
    OP_LOCK,
    { read: readLockArgs, write: writeLockArgs },
    { read: readLockRes, write: writeLockRes },
  ),
  op4(
    OP_LOCKT,
    { read: readLocktArgs, write: writeLocktArgs },
    { read: readLocktRes, write: writeLocktRes },
  ),
  op4(
    OP_LOCKU,
    { read: readLockuArgs, write: writeLockuArgs },
    { read: readLockuRes, write: writeLockuRes },
  ),
  op4(OP_LOOKUP, { read: readLookupArgs, write: writeLookupArgs }, STATUS_RES),
  op4(OP_LOOKUPP, undefined, STATUS_RES),
  op4(OP_NVERIFY, { read: readVerifyArgs, write: writeVerifyArgs }, STATUS_RES),
  op4(
    OP_OPEN,
    { read: readOpenArgs, write: writeOpenArgs },
    { read: readOpenRes, write: writeOpenRes },
  ),
  op4(
    OP_OPEN_DOWNGRADE,
    { read: readOpenDowngradeArgs, write: writeOpenDowngradeArgs },
    { read: readOpenDowngradeRes, write: writeOpenDowngradeRes },
  ),
  op4(OP_PUTFH, { read: readPutfhArgs, write: writePutfhArgs }, STATUS_RES),
  op4(OP_PUTPUBFH, undefined, STATUS_RES),
  op4(OP_PUTROOTFH, undefined, STATUS_RES),
  op4(
    OP_READ,
    // Both payload readers take an optional cap and default to `XDR_MAX_ITEM`;
    // the honest per-session limit is `ca_maxrequestsize`, applied above this.
    { read: readReadArgs, write: writeReadArgs },
    { read: readReadRes, write: writeReadRes },
  ),
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
    OP_WRITE,
    { read: readWriteArgs, write: writeWriteArgs },
    { read: readWriteRes, write: writeWriteRes },
  ),
  op4(
    OP_BACKCHANNEL_CTL,
    { read: readBackchannelCtlArgs, write: writeBackchannelCtlArgs },
    STATUS_RES,
  ),
  op4(
    OP_BIND_CONN_TO_SESSION,
    { read: readBindConnToSessionArgs, write: writeBindConnToSessionArgs },
    { read: readBindConnToSessionRes, write: writeBindConnToSessionRes },
  ),
  op4(
    OP_EXCHANGE_ID,
    { read: readExchangeIdArgs, write: writeExchangeIdArgs },
    { read: readExchangeIdRes, write: writeExchangeIdRes },
  ),
  op4(
    OP_CREATE_SESSION,
    { read: readCreateSessionArgs, write: writeCreateSessionArgs },
    { read: readCreateSessionRes, write: writeCreateSessionRes },
  ),
  op4(
    OP_DESTROY_SESSION,
    { read: readDestroySessionArgs, write: writeDestroySessionArgs },
    STATUS_RES,
  ),
  op4(OP_FREE_STATEID, { read: readFreeStateidArgs, write: writeFreeStateidArgs }, STATUS_RES),
  op4(
    OP_SECINFO_NO_NAME,
    { read: readSecinfoNoNameArgs, write: writeSecinfoNoNameArgs },
    // `typedef SECINFO4res SECINFO_NO_NAME4res` — the same bytes, so the same
    // pair of functions.
    { read: readSecinfoRes, write: writeSecinfoRes },
  ),
  op4(
    OP_SEQUENCE,
    { read: readSequenceArgs, write: writeSequenceArgs },
    { read: readSequenceRes, write: writeSequenceRes },
  ),
  op4(
    OP_TEST_STATEID,
    { read: readTestStateidArgs, write: writeTestStateidArgs },
    { read: readTestStateidRes, write: writeTestStateidRes },
  ),
  op4(
    OP_DESTROY_CLIENTID,
    { read: readDestroyClientidArgs, write: writeDestroyClientidArgs },
    STATUS_RES,
  ),
  op4(
    OP_RECLAIM_COMPLETE,
    { read: readReclaimCompleteArgs, write: writeReclaimCompleteArgs },
    STATUS_RES,
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
