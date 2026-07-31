/**
 * The NFSv4.1 session: one RPC record in, one RPC record out.
 *
 * The v3 session's job with a different shape. It touches **no I/O**
 * ({@link Nfs4Session.handleCall} takes bytes and resolves to bytes), it never
 * rejects, and every thrown driver error becomes a legal `nfsstat4` rather than
 * a dropped reply. What changes is everything above that line:
 *
 * - **One procedure, many operations.** NFSv4 has exactly two procedures, NULL
 *   and COMPOUND (RFC 8881 §16). A COMPOUND is an array of operations executed
 *   in order against a *cursor* — the current filehandle and the saved
 *   filehandle — and it stops at the first operation whose status is not
 *   `NFS4_OK` (§16.2.3). The compound's own status is the last executed
 *   operation's.
 * - **There is a session.** A 4.1 COMPOUND opens with SEQUENCE, which names a
 *   `(session, slot, sequence)` triple; a retransmission on the same slot and
 *   sequence is answered from the slot's reply cache instead of being executed
 *   again. `./state.ts` owns that decision; this file owns the bytes.
 * - **No `wcc_data`.** A mutating operation answers with `change_info4` — the
 *   directory's opaque `change` attribute before and after — and this server
 *   sets `atomic: FALSE`, because it samples the two with separate driver
 *   calls and saying otherwise would be a claim it cannot keep (§3.3.8).
 *
 * ## Open state, and who owns the driver's file handles
 *
 * `./state.ts` decides what the protocol permits and holds no file: it knows an
 * open by an opaque `fileKey`, which here is the identity `../handles.ts`
 * assigned the object. What an open *is* on the driver side — one
 * `FileHandleLike`, opened with the union of the access bits the open state
 * carries — is this file's, and the two are kept in step from one direction
 * only: a driver handle exists exactly while the open state that named it does.
 * CLOSE is the ordinary end of one; the others (lease expiry, DESTROY_CLIENTID,
 * a swept client) never reach an operation handler at all, so
 * `Nfs4StateOptions.onOpenReleased` hands them over and
 * {@link Nfs4Session.destroy} sweeps whatever is still open when the server
 * stops. I/O carrying an anonymous or bypass stateid names no open state and so
 * opens and closes its own handle per request, which is what `../v3/session.ts`
 * does for every request it answers.
 *
 * That the `fileKey` is a handle-table entry id has one consequence running the
 * other way: an entry the table evicted would come back under a *new* id, and
 * the same file would then carry two `FileState`s that cannot see each other —
 * a share reservation quietly stopping being enforced. So this file **pins** an
 * entry for exactly as long as `./state.ts` holds state for its key
 * (`onFileRetained`/`onFileReleased` → `#pinFile`/`#unpinFile`), and the cap in
 * `../handles.ts` is soft as a result.
 *
 * ## The current stateid
 *
 * A COMPOUND's cursor carries a stateid beside the two filehandles
 * (§16.2.3.1.2). An operation that returns one sets it, an operation that sets
 * the current filehandle without returning one clears it to the all-zeros
 * value, SAVEFH and RESTOREFH move both halves together, and the special
 * stateid `(seqid 1, other 0)` in an argument means "whatever that is now".
 * `./state.ts` classifies the special values and leaves this substitution to
 * this file, because it is the COMPOUND that knows the answer.
 *
 * ## Errno discipline, amended for COMPOUND
 *
 * One reply per *compound*. A thrown value becomes a status: an errno-shaped
 * error is mapped by `./constants.ts`'s table, an {@link XdrError} that escapes
 * a per-operation decode is `NFS4ERR_BADXDR`, and anything else — a `TypeError`
 * from a bug in here — is `NFS4ERR_SERVERFAULT` rather than a plausible-looking
 * I/O error. A retried `(session, slot, sequence)` returns the **cached** bytes
 * and re-runs nothing.
 *
 * ## The zero-copy contract, amended for the replay cache
 *
 * The whole COMPOUND is decoded — and every retained byte copied, which is
 * `../xdr.ts`'s standing rule — before the first `await`, so the transport may
 * re-arm its receive buffer as soon as `handleCall` returns its promise. The
 * new spot is the reply: what `Nfs4State.cacheReply` stores is the encoded
 * **`COMPOUND4res` only**, never the RPC header in front of it, because a
 * retransmission may legitimately carry a different `xid` and the cached body
 * has to be wrappable in a fresh one.
 */

import { constants } from "node:fs";
import { ERRNO_CODES, fsError } from "../../errors.ts";
import { createLoopback, type Loopback } from "../../harness.ts";
import { PathLock } from "../../lock.ts";
import { claimNewEntry, type NewEntry, newEntryOwnership } from "../../ownership.ts";
import { dirname, joinPath } from "../../path.ts";
import type { FileHandleLike, FsDriver, StatsLike, TimeLike } from "../../types.ts";
import { S_IFDIR, S_IFLNK, S_IFMT, S_IFREG } from "../../types.ts";
import {
  cookieVerifier,
  DirectorySnapshots,
  FileHandleTable,
  type HandleEntry,
  sameVerifier,
} from "../handles.ts";
import {
  ACCEPTED_REPLY_HEADER_SIZE,
  AUTH_NONE,
  AUTH_SYS,
  AUTH_TOOWEAK,
  credentialsOf,
  decodeCall,
  encodeAcceptError,
  encodeAcceptedReply,
  encodeAuthError,
  encodeRpcMismatch,
  RPC_GARBAGE_ARGS,
  RPC_PROC_UNAVAIL,
  RPC_PROG_MISMATCH,
  RPC_PROG_UNAVAIL,
  RPC_SYSTEM_ERR,
  RPC_VERSION,
  writeAcceptedReplyHeader,
  type RpcCall,
  type RpcCredentials,
} from "../rpc.ts";
import {
  type AccessRights,
  allowedAccess,
  ExclusiveCreates,
  MAX_OFFSET,
  modeBitsOfFtype,
  NAME_MAX,
  newSessionStats,
  type Nfs4IdMap,
  type NfsRequestContext,
  type NfsSessionOptions,
  type NfsSessionStats,
  type NfsSharedState,
} from "../util.ts";
import { isXdrError, stringByteLength, XdrError, XdrReader, XdrWriter, xdrAlign } from "../xdr.ts";
import {
  type Bitmap4,
  bitmapDifference,
  bitmapHas,
  bitmapIntersection,
  bitmapIsEmpty,
  bitmapOf,
  changeOf,
  encodeFattr,
  type Fattr4Values,
  fattr4FsOf,
  fattr4Of,
  fromTime4,
  numericOwner,
  parseNumericOwner,
  SET_ONLY_ATTRS,
  SETTABLE_ATTRS,
  SUPPORTED_ATTRS,
  type SetTime4,
} from "./attr.ts";
import {
  ACCESS4_ALL,
  ACCESS4_DELETE,
  ACCESS4_EXECUTE,
  ACCESS4_EXTEND,
  ACCESS4_LOOKUP,
  ACCESS4_MODIFY,
  ACCESS4_READ,
  CDFC4_FORE,
  CDFC4_FORE_OR_BOTH,
  CDFS4_FORE,
  CLAIM_DELEG_CUR_FH,
  CLAIM_DELEG_PREV_FH,
  CLAIM_DELEGATE_CUR,
  CLAIM_DELEGATE_PREV,
  CLAIM_FH,
  CLAIM_NULL,
  CLAIM_PREVIOUS,
  EXCLUSIVE4,
  EXCLUSIVE4_1,
  FATTR4_FILES_AVAIL,
  FATTR4_FILES_FREE,
  FATTR4_FILES_TOTAL,
  FATTR4_MODE,
  FATTR4_OWNER,
  FATTR4_OWNER_GROUP,
  FATTR4_RDATTR_ERROR,
  FATTR4_SIZE,
  FATTR4_SPACE_AVAIL,
  FATTR4_SPACE_FREE,
  FATTR4_SPACE_TOTAL,
  FATTR4_TIME_ACCESS_SET,
  FATTR4_TIME_MODIFY_SET,
  FH4_PERSISTENT,
  FILE_SYNC4,
  GUARDED4,
  NF4ATTRDIR,
  NF4BLK,
  NF4CHR,
  NF4DIR,
  NF4FIFO,
  NF4LNK,
  NF4NAMEDATTR,
  NF4REG,
  NF4SOCK,
  NFS4_MINOR_VERSION_1,
  NFS4_OK,
  NFS4_OTHER_SIZE,
  NFS4_PROGRAM,
  NFS4_VERIFIER_SIZE,
  NFS4ERR_ATTRNOTSUPP,
  NFS4ERR_BAD_COOKIE,
  NFS4ERR_BAD_STATEID,
  NFS4ERR_BADNAME,
  NFS4ERR_BADOWNER,
  NFS4ERR_BADSESSION,
  NFS4ERR_BADTYPE,
  NFS4ERR_BADXDR,
  NFS4ERR_EXIST,
  NFS4ERR_INVAL,
  NFS4ERR_ISDIR,
  NFS4ERR_MINOR_VERS_MISMATCH,
  NFS4ERR_NOENT,
  NFS4ERR_NOFILEHANDLE,
  NFS4ERR_NOT_ONLY_OP,
  NFS4ERR_NOT_SAME,
  NFS4ERR_NOTDIR,
  NFS4ERR_NOTSUPP,
  NFS4ERR_OP_ILLEGAL,
  NFS4ERR_OP_NOT_IN_SESSION,
  NFS4ERR_OPENMODE,
  NFS4ERR_REP_TOO_BIG_TO_CACHE,
  NFS4ERR_SAME,
  NFS4ERR_SEQUENCE_POS,
  NFS4ERR_SERVERFAULT,
  NFS4ERR_SYMLINK,
  NFS4ERR_TOO_MANY_OPS,
  NFS4ERR_TOOSMALL,
  NFS4ERR_WRONG_TYPE,
  NFS_V4,
  NFSPROC4_COMPOUND,
  NFSPROC4_NULL,
  nfs4StatusOf,
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
  OP_FIRST,
  OP_FREE_STATEID,
  OP_GETATTR,
  OP_GETFH,
  OP_ILLEGAL,
  OP_LAST,
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
  OPEN_DELEGATE_NONE,
  OPEN_DELEGATE_NONE_EXT,
  OPEN4_CREATE,
  OPEN4_RESULT_LOCKTYPE_POSIX,
  OPEN4_SHARE_ACCESS_READ,
  OPEN4_SHARE_ACCESS_WANT_CANCEL,
  OPEN4_SHARE_ACCESS_WANT_DELEG_MASK,
  OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
  OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED,
  OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL,
  OPEN4_SHARE_ACCESS_WRITE,
  opName4,
  SECINFO_STYLE4_CURRENT_FH,
  SECINFO_STYLE4_PARENT,
  SET_TO_CLIENT_TIME4,
  SET_TO_SERVER_TIME4,
  SP4_NONE,
  WND4_CANCELLED,
  WND4_NOT_WANTED,
  WND4_RESOURCE,
} from "./constants.ts";
import {
  type Access4args,
  type Access4res,
  type Argop4Value,
  type BackchannelCtl4args,
  type BindConnToSession4args,
  type BindConnToSession4res,
  type ChangeInfo4,
  type Close4args,
  type Close4res,
  type Commit4res,
  type Compound4res,
  type Create4args,
  type Create4res,
  type CreateHow4,
  type CreateSession4args,
  type CreateSession4res,
  type DestroyClientid4args,
  type DestroySession4args,
  type Entry4,
  type ExchangeId4args,
  type ExchangeId4res,
  type Fattr4,
  type FreeStateid4args,
  type Getattr4args,
  type Getattr4res,
  type Getfh4res,
  type Link4args,
  type Link4res,
  type Lock4args,
  type Lock4res,
  type Lockt4args,
  type Lockt4res,
  type Locku4args,
  type Locku4res,
  type Lookup4args,
  NFS4_MAX_COMPOUND_OPS,
  NFS4_MAX_TAG,
  OP_CODECS,
  type Open4args,
  type Open4res,
  type OpenDelegation4,
  type OpenDowngrade4args,
  type OpenDowngrade4res,
  type Putfh4args,
  type Read4args,
  type Read4res,
  type Readdir4args,
  type Readdir4res,
  type Readlink4res,
  type ReclaimComplete4args,
  type Remove4args,
  type Remove4res,
  type Rename4args,
  type Rename4res,
  type Resop4,
  type Resop4Value,
  type Secinfo4args,
  type Secinfo4res,
  type SecinfoNoName4args,
  type Sequence4args,
  type Setattr4args,
  type Setattr4res,
  type Stateid4,
  type Status4res,
  type TestStateid4args,
  type TestStateid4res,
  type Verify4args,
  type Write4args,
  type Write4res,
} from "./protocol.ts";
import { type LockRequest, Nfs4State, type SlotTicket, specialStateid } from "./state.ts";

/** Largest `READ` this server will answer, and the `maxread` attribute. */
export const DEFAULT_MAXREAD = 1024 * 1024;
/** Largest `WRITE` this server will accept, and the `maxwrite` attribute. */
export const DEFAULT_MAXWRITE = 1024 * 1024;

/**
 * The largest `argarray` this server will look at before it knows the session.
 *
 * A COMPOUND that never reaches SEQUENCE has no negotiated `ca_maxoperations`
 * to be measured against, so it is measured against the ceiling this server
 * would ever counter-offer. Past that the answer is `NFS4ERR_TOO_MANY_OPS`
 * (§18.36.3, §15.1.3.11) with an empty `resarray` — nothing executed.
 */
const DEFAULT_MAX_OPERATIONS = 64;

/**
 * `maxlink`, when the driver has hard links at all.
 *
 * The same number `../v3/session.ts` reports as `PATHCONF.linkmax`, and for the
 * same reason: no driver enforces a link count, so this is a statement about
 * what a client should not bother exceeding rather than a limit anything here
 * checks.
 */
const MAX_LINK = 32_000;

/**
 * The lowest cookie this server hands out (RFC 8881 §18.23.3).
 *
 * "For READDIR results, cookie values of zero, one, and two SHOULD NOT be
 * returned" — zero means "start" and one and two are reserved for the `.` and
 * `..` a UNIX client splices in locally. So the snapshot index `n` is cookie
 * `n + 3`, and a cookie of 1 or 2 coming back the other way is
 * `NFS4ERR_BAD_COOKIE` rather than an index.
 */
const COOKIE_BASE = 3n;

/**
 * How many entries of one READDIR page are resolved at once.
 *
 * The same reasoning as `../v3/session.ts`'s constant of the same name, and it
 * bites harder here: a v4 READDIR is v3's READDIR *and* READDIRPLUS in one
 * operation, so every entry costs an `lstat` whatever the client asked for. A
 * page is bounded in bytes rather than in entries, so neither one-at-a-time
 * (5000 serialized round trips for a 5000-entry `ls`) nor all-at-once (a
 * threadpool with tens of thousands of jobs on it) is the right shape; a fixed
 * window is.
 */
const PAGE_CONCURRENCY = 64;

/**
 * The smallest a `fattr4` can encode to: an empty counted `bitmap4` and an
 * empty `attrlist4`, four bytes each (`./attr.ts`'s `encodeFattr`).
 *
 * Used as a floor when READDIR needs to bound a batch it has not fetched yet.
 * A floor can only *over*-count how many entries fit, which is the safe
 * direction: the budget loop still decides, and an over-count costs at most a
 * second batch rather than a short page.
 */
const MIN_FATTR4_SIZE = 8;

/** Resolve one value per name, at most {@link PAGE_CONCURRENCY} in flight. */
async function mapPage<T, R>(
  items: readonly T[],
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = Array.from<R>({ length: items.length });
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const index = next++;
      out[index] = await fn(items[index]!, index);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PAGE_CONCURRENCY, items.length) }, worker));
  return out;
}

/**
 * The `statfs` family: the six attributes that come from `driver.statfs` and
 * from nowhere else.
 *
 * Named so that a driver with no `statfs` can have them dropped from
 * `supported_attrs` outright, rather than advertised and then silently omitted
 * from every reply — declared-or-inferred, never faked.
 */
const STATFS_ATTRS: Bitmap4 = bitmapOf([
  FATTR4_FILES_AVAIL,
  FATTR4_FILES_FREE,
  FATTR4_FILES_TOTAL,
  FATTR4_SPACE_AVAIL,
  FATTR4_SPACE_FREE,
  FATTR4_SPACE_TOTAL,
]);

/** The pair of write-only time attributes, dropped when the driver has no `utimes`. */
const TIME_SET_ATTRS: Bitmap4 = bitmapOf([FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET]);

/**
 * The operations that may open a COMPOUND with no SEQUENCE in front of them
 * (RFC 8881 §18.46.3).
 *
 * §18.46.3 names five — SEQUENCE, BIND_CONN_TO_SESSION, EXCHANGE_ID,
 * CREATE_SESSION and DESTROY_SESSION — and everything else at the head of a
 * COMPOUND is `NFS4ERR_OP_NOT_IN_SESSION`. DESTROY_CLIENTID is the sixth, and
 * it is here on §18.50.3's authority rather than §18.46.3's: "If
 * DESTROY_CLIENTID is not prefixed by SEQUENCE, it MUST be the only operation
 * in the COMPOUND request (otherwise, the server MUST return
 * NFS4ERR_NOT_ONLY_OP)" — a sentence that has no meaning unless a session-less
 * DESTROY_CLIENTID is legal. §15.2's `NFS4ERR_NOT_ONLY_OP` row lists exactly
 * these five non-SEQUENCE operations, which is the same set from the other
 * direction.
 */
const SESSIONLESS_OPS: ReadonlySet<number> = new Set([
  OP_BIND_CONN_TO_SESSION,
  OP_CREATE_SESSION,
  OP_DESTROY_CLIENTID,
  OP_DESTROY_SESSION,
  OP_EXCHANGE_ID,
]);

/**
 * Every `OPEN4_SHARE_ACCESS_WANT_*` bit a `share_access` may carry.
 *
 * The five mutually exclusive delegation wishes named by
 * `OPEN4_SHARE_ACCESS_WANT_DELEG_MASK`, plus the two standalone flags
 * §18.16.3 lists beside them, which live outside it. Same set `./state.ts`
 * masks off before reading the access mode, for the same reason.
 */
const SHARE_ACCESS_WANT_MASK =
  OPEN4_SHARE_ACCESS_WANT_DELEG_MASK |
  OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED |
  OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL;

/**
 * The all-zero stateid: "no current stateid", and the anonymous stateid a
 * client may send (RFC 8881 §8.2.3).
 *
 * A fresh object each time, because a `Cursor` hands it out and a caller could
 * otherwise be handed something another compound is holding.
 */
function zeroStateid(): Stateid4 {
  return { seqid: 0, other: new Uint8Array(NFS4_OTHER_SIZE) };
}

/**
 * The `open_delegation4` for an OPEN this server will not delegate — which is
 * every OPEN (RFC 8881 §18.16.3).
 *
 * Two shapes, and which one is owed depends on what the client asked for. "If
 * the server supports the new _WANT_ flags and the client sends one or more of
 * the new flags, then in the event the server does not return a delegation, it
 * MUST return a delegation type of OPEN_DELEGATE_NONE_EXT" with an `ond_why`;
 * a client that set none of them is answered with the plain
 * `OPEN_DELEGATE_NONE`, which is four bytes and no body.
 *
 * "One or more of the new flags" is read as *any* of the seven, including the
 * two standalone ones that sit outside `OPEN4_SHARE_ACCESS_WANT_DELEG_MASK` —
 * a client that sent one of those and got a bare `OPEN_DELEGATE_NONE` would
 * have to guess.
 *
 * The three reasons this server can honestly give are the three the client's
 * own request selects:
 *
 * - `OPEN4_SHARE_ACCESS_WANT_NO_DELEG` → `WND4_NOT_WANTED`, which §18.16.3
 *   defines as exactly that: "The client specified
 *   OPEN4_SHARE_ACCESS_WANT_NO_DELEG."
 * - `OPEN4_SHARE_ACCESS_WANT_CANCEL` → `WND4_CANCELLED`, "the client specified
 *   OPEN4_SHARE_ACCESS_WANT_CANCEL and now any 'want' for this file object is
 *   cancelled" — true here in the vacuous way, since this server registers no
 *   wants to cancel.
 * - a wish for a read, write or any delegation → `WND4_RESOURCE`, "resource
 *   limitations prevent the server from granting a delegation", with
 *   `ond_server_will_signal_avail` FALSE because a TRUE there is a promise to
 *   send `CB_RECALLABLE_OBJ_AVAIL` later and there is no back channel to send
 *   it on.
 */
function noDelegation(shareAccess: number): OpenDelegation4 {
  if ((shareAccess & SHARE_ACCESS_WANT_MASK) === 0) {
    return { delegationType: OPEN_DELEGATE_NONE };
  }
  const want = shareAccess & OPEN4_SHARE_ACCESS_WANT_DELEG_MASK;
  const why =
    want === OPEN4_SHARE_ACCESS_WANT_NO_DELEG
      ? WND4_NOT_WANTED
      : want === OPEN4_SHARE_ACCESS_WANT_CANCEL
        ? WND4_CANCELLED
        : WND4_RESOURCE;
  return {
    delegationType: OPEN_DELEGATE_NONE_EXT,
    // Written only on the `WND4_RESOURCE` arm; the others are void.
    whynone: { why, serverWillSignalAvail: false },
  };
}

/** An `nfsstat4` carried out of a handler. */
class Nfs4StatusError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "Nfs4StatusError";
    this.status = status;
  }
}

/**
 * A procedure number the NFSv4 program does not have.
 *
 * Unwinds past the handlers for the same reason `../v3/session.ts`'s does: the
 * answer is an RPC-level `PROC_UNAVAIL`, not a procedure result.
 */
class ProcedureUnavailable extends Error {
  constructor(procedure: number) {
    super(`no procedure ${procedure} in the NFSv4 program`);
    this.name = "ProcedureUnavailable";
  }
}

/** The `nfsstat4` for anything a handler threw. */
function statusOf(error: unknown): number {
  if (error instanceof Nfs4StatusError) {
    return error.status;
  }
  if (isXdrError(error)) {
    return NFS4ERR_BADXDR;
  }
  const code = (error as { code?: unknown } | undefined)?.code;
  if (typeof code === "string" && Object.hasOwn(ERRNO_CODES, code)) {
    return nfs4StatusOf(error);
  }
  // Not an errno at all — a bug in here, not a filesystem outcome. §15.1.1.6:
  // "An error occurred on the server that does not map to any of the specific
  // legal NFSv4.1 protocol error values."
  return NFS4ERR_SERVERFAULT;
}

/**
 * The result body for an operation that failed.
 *
 * Every `union XXX4res switch (nfsstat4)` carries nothing but the status on a
 * non-`NFS4_OK` arm, so one status word is the whole body — with exactly one
 * exception, SETATTR, which is a plain struct and carries `attrsset` on every
 * status (RFC 8881 §18.30.2).
 */
function failureRes(op: number, status: number): Resop4Value {
  return op === OP_SETATTR ? { status, attrsset: [] } : { status };
}

/** {@link failureRes} as a whole resop. */
function statusResop(op: number, status: number): Resop4 {
  return { op, res: failureRes(op, status) };
}

/**
 * Encode a `COMPOUND4res`.
 *
 * Deliberately not `writeCompoundRes` from `./protocol.ts`: that resolves every
 * resop through `opCodec4`, which throws for an operation with no codec row —
 * and a status-only resop for exactly such an operation is how this session
 * answers `NFS4ERR_NOTSUPP` (the step-5 contract). The fallback below is sound
 * for the same reason {@link failureRes} is: a failed `XXX4res` is one status
 * word, whatever the operation.
 */
function writeCompoundRes(writer: XdrWriter, res: Compound4res): void {
  writer.u32(res.status);
  writer.string(res.tag);
  writer.u32(res.resarray.length);
  for (const resop of res.resarray) {
    writer.u32(resop.op);
    const codec = OP_CODECS.get(resop.op);
    if (codec === undefined) {
      writer.u32((resop.res as Status4res).status);
    } else {
      codec.writeRes(writer, resop.res);
    }
  }
}

/** A resop with no bulk on it, generously: the largest is a full `GETATTR`. */
const RESOP_ALLOWANCE = 256;

/**
 * A starting size for the buffer one COMPOUND reply is built in.
 *
 * `new XdrWriter(512)` for every compound meant a 1 MiB `READ` doubling its way
 * up from 512 bytes — eleven grow-and-copies, about 2 MiB of `memcpy` to
 * deliver 1 MiB. The encoder cannot ask the *request* how big its answer will
 * be, because it never sees the request; but the results are in hand by then,
 * so it can ask them.
 *
 * **This covers `READ` and nothing else, deliberately.** `READ4resok.data` is
 * the one result whose bulk is a byte string already sized — and sized by what
 * the driver *returned*, not by what the client asked for, which is the
 * distinction that matters (see `XdrWriter.ensure`). The other bulky results
 * are not: `READDIR4resok` carries an entry list, `READLINK4resok` a string,
 * `GETATTR4resok` an attribute set, and the encoded length of each is not known
 * without encoding it. Guessing generously would be worse than not guessing,
 * because {@link Nfs4Session.#reply} hands the socket a **view** of this buffer
 * — so capacity reserved and not used stays pinned in the write queue, where
 * unpredicted geometric growth merely costs a copy and lands within 2× of the
 * bytes actually written. A 32 KiB `READDIR` doubling six times from here is
 * the accepted price of not over-reserving on every compound that is not one.
 */
function compoundCapacity(tag: string, resarray: readonly Resop4[]): number {
  let capacity =
    ACCEPTED_REPLY_HEADER_SIZE + 12 + xdrAlign(stringByteLength(tag)) + RESOP_ALLOWANCE;
  for (const resop of resarray) {
    const data = resop.op === OP_READ ? (resop.res as Read4res).data : undefined;
    capacity += RESOP_ALLOWANCE + (data === undefined ? 0 : xdrAlign(data.byteLength));
  }
  return capacity;
}

/** One `nfs_resop4` as bytes, so a reply can be measured before it is built. */
function resopSize(resop: Resop4): number {
  const writer = new XdrWriter(64);
  writer.u32(resop.op);
  const codec = OP_CODECS.get(resop.op);
  if (codec === undefined) {
    writer.u32((resop.res as Status4res).status);
  } else {
    codec.writeRes(writer, resop.res);
  }
  return writer.length;
}

/**
 * The `resarray` for a reply too big to cache, or `undefined` when there is no
 * such reply to build (RFC 8881 §2.10.6.4).
 *
 * The result at the chosen index is replaced by the bare
 * `NFS4ERR_REP_TOO_BIG_TO_CACHE` status and the ones after it are dropped,
 * which is the reply §2.10.6.4 describes ("the server may return
 * NFS4ERR_REP_TOO_BIG_TO_CACHE on the tenth operation ... the server will have
 * cached a reply that contains results for ten of the eleven requested
 * operations").
 *
 * The index is the first result that overruns `cap` — but only if the *rebuilt*
 * reply then fits, which is not the same test: the replacement is itself four
 * or twelve bytes (SETATTR's `attrsset` is on every arm), so a prefix that ends
 * within a few bytes of the cap has to give up a result that did fit. Failing
 * to check that is how the status meant to make the reply cacheable produces
 * one that is still too big, and the MUST in the same paragraph — "then the
 * reply MUST be cached if sa_cachethis or csa_cachethis is TRUE" — is missed by
 * a handful of bytes. Dropping further back is sound because the reply carrying
 * this status *is* cached: a retransmission gets these same bytes rather than
 * re-running the operations whose results went.
 *
 * `undefined` when no index works — the leading SEQUENCE plus one status word
 * already exceeds `cap`. The status cannot go on the SEQUENCE itself
 * (§2.10.6.1.2: "The replier MUST NOT modify the reply cache entry for the slot
 * whenever an error is returned from SEQUENCE"), so there is nowhere to put it;
 * the whole reply goes out uncached and the retry answers
 * `NFS4ERR_RETRY_UNCACHED_REP`.
 */
function trimForCache(tag: string, resarray: readonly Resop4[], cap: number): Resop4[] | undefined {
  // `COMPOUND4res` overhead: the status, the counted tag, and the result count.
  const base = 4 + 4 + xdrAlign(stringByteLength(tag)) + 4;
  // `before[index]` is the size of everything preceding that result.
  const before: number[] = [];
  let used = base;
  for (const resop of resarray) {
    before.push(used);
    used += resopSize(resop);
  }
  let over = -1;
  for (let index = 0; index < resarray.length; index++) {
    if (before[index]! + resopSize(resarray[index]!) > cap) {
      over = index;
      break;
    }
  }
  /* v8 ignore next 3 -- unreachable: the caller measured the same encoding and
     found it over the cap, so some result must cross it here too. */
  if (over < 0) {
    return undefined;
  }
  for (let index = over; index >= 1; index--) {
    const replacement = statusResop(resarray[index]!.op, NFS4ERR_REP_TOO_BIG_TO_CACHE);
    if (before[index]! + resopSize(replacement) <= cap) {
      return [...resarray.slice(0, index), replacement];
    }
  }
  return undefined;
}

/** Are two byte strings the same bytes? */
function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  for (let index = 0; index < left.byteLength; index++) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

/** An opaque as a Map key: lowercase hex, the same shape `./state.ts` uses. */
function hexOf(bytes: Uint8Array): string {
  let key = "";
  for (const byte of bytes) {
    key += byte.toString(16).padStart(2, "0");
  }
  return key;
}

/** A `sessionid4` as a Map key. */
function sessionKey(sessionid: Uint8Array): string {
  return hexOf(sessionid);
}

/**
 * A stateid's `other` as a Map key.
 *
 * The one string this file and `./state.ts` have to agree on, and they agree by
 * both hexing the same twelve bytes rather than by passing a key across: the
 * `onOpenReleased` hook hands over `other` itself.
 */
function stateKey(other: Uint8Array): string {
  return hexOf(other);
}

/**
 * The handle entry id a `fileKey` names — the inverse of `#fileKey`.
 *
 * `undefined` for anything that is not one of those keys, which is the reclaim
 * arm's `""` and nothing else. Written as a test rather than a `try`, because
 * `BigInt("0x")` throwing is not the reason this returns `undefined`.
 */
function entryIdOf(fileKey: string): bigint | undefined {
  return /^[\da-f]+$/.test(fileKey) ? BigInt(`0x${fileKey}`) : undefined;
}

/** {@link allowedAccess}'s answer as `ACCESS4_*` bits (RFC 8881 §18.1.1). */
function accessBits4(rights: AccessRights): number {
  return (
    (rights.read ? ACCESS4_READ : 0) |
    (rights.lookup ? ACCESS4_LOOKUP : 0) |
    (rights.modify ? ACCESS4_MODIFY : 0) |
    (rights.extend ? ACCESS4_EXTEND : 0) |
    (rights.delete ? ACCESS4_DELETE : 0) |
    (rights.execute ? ACCESS4_EXECUTE : 0)
  );
}

/** One decoded operation: its opcode and, unless its `nfs_argop4` arm is void, its arguments. */
interface DecodedOp {
  op: number;
  args: Argop4Value | undefined;
}

/**
 * Where a COMPOUND's argument array stopped being readable, and why.
 *
 * An `nfs_argop4` carries no length, so there is nothing to skip past an
 * operation this file cannot decode: the walk stops, the operation gets its own
 * status-only resop, and the compound halts (RFC 8881 §16.2.3, and the note on
 * `OP_CODEC_LIST` in `./protocol.ts`).
 */
interface DecodeHalt {
  /** The opcode to echo. `OP_ILLEGAL` when the request's own opcode was out of range. */
  op: number;
  status: number;
}

/** The whole COMPOUND, decoded and copied, before anything is awaited. */
interface DecodedCompound {
  tag: string;
  /** The declared `argarray` length, which exceeds `ops.length` when the walk halted. */
  count: number;
  ops: DecodedOp[];
  halt: DecodeHalt | undefined;
}

/**
 * One driver file handle, held open for as long as the open state that named
 * it (RFC 8881 §9.1.1).
 *
 * `flags` is what it was opened with — the host's `O_*`, not the wire's: this
 * server *originates* them from `share_access`, so there is no namespace
 * crossing here and nothing to translate.
 */
interface OpenHandle {
  handle: FileHandleLike;
  /** Host `open(2)` flags. Widened by re-opening when an OPEN upgrades the access. */
  flags: number;
  /** The path it was opened on, for the re-open an upgrade needs. */
  path: string;
}

/** The cursor a COMPOUND is executed against (RFC 8881 §16.2.3.1.1), plus its context. */
interface Cursor {
  /** The current filehandle, as wire bytes. `undefined` is `NFS4ERR_NOFILEHANDLE`. */
  currentFh: Uint8Array | undefined;
  savedFh: Uint8Array | undefined;
  /** The current stateid (§16.2.3.1.2). All-zeros until an operation sets one. */
  currentStateid: Stateid4;
  savedStateid: Stateid4;
  creds: RpcCredentials;
  /** The client ID the enclosing SEQUENCE belongs to, when there is one. */
  clientid: bigint | undefined;
  /** The session the enclosing SEQUENCE rides, so DESTROY_SESSION can recognise it. */
  ownSession: string | undefined;
  /** The compound destroyed the session it rides; its reply must not be cached. */
  destroyedOwnSession: boolean;
}

/**
 * An NFSv4.1 server over a driver, with no socket.
 *
 * ```ts
 * const session = new Nfs4Session(createMemoryDriver());
 * const reply = await session.handleCall(rpcRecordBytes); // Uint8Array | null
 * ```
 */
export class Nfs4Session {
  /** The driver, wrapped so paths are normalized and gaps answer `ENOSYS`. */
  readonly driver: Loopback;
  readonly options: NfsSessionOptions;
  readonly handles: FileHandleTable;
  readonly stats: NfsSessionStats;
  /** The NFSv4.1 state machine: clients, sessions, slots, stateids, locks. */
  readonly state: Nfs4State;
  /**
   * The `verifier4` every `WRITE` and `COMMIT` reply carries.
   *
   * Constant for the life of the server and different for the next one, which
   * is the whole protocol: a client that sees it change knows the server
   * restarted (RFC 8881 §18.3.3).
   */
  readonly writeVerifier: Uint8Array;

  readonly #snapshots: DirectorySnapshots;
  readonly #lock: PathLock;
  /**
   * Each live session's negotiated `ca_maxoperations`.
   *
   * Kept here rather than asked of `./state.ts`, which does not publish a
   * session's channel attributes: CREATE_SESSION's own result carries the
   * counter-offer, so recording it as it goes out costs nothing and is what
   * makes §18.36.3's `NFS4ERR_TOO_MANY_OPS` a per-session check instead of a
   * server-wide one.
   */
  readonly #maxOpsBySession = new Map<string, number>();
  readonly #maxOperations: number;
  readonly #idmap: Nfs4IdMap | undefined;
  /**
   * One driver handle per live open state, keyed by the stateid's `other`.
   *
   * The key is the hex of the twelve `other` bytes, which is also how
   * `./state.ts` keys its own table — the two never exchange the string, they
   * exchange the bytes, so the only thing that has to agree is that hex of the
   * same bytes is the same key.
   */
  readonly #openHandles = new Map<string, OpenHandle>();
  /**
   * Open states `./state.ts` has dropped whose driver handle is still open.
   *
   * Filled synchronously by the `onOpenReleased` hook — which fires in the
   * middle of a table walk and cannot await anything — and drained after every
   * operation. CLOSE therefore has no special path: it drops the state, the
   * hook queues the handle, and the drain closes it before the reply is
   * encoded.
   */
  readonly #released: string[] = [];
  /**
   * The `fileKey`s whose handle entry this session is holding pinned.
   *
   * `../handles.ts` evicts least-recently-used entries under a cap, and this
   * file keys every open and every byte-range lock by *entry id* — so an
   * evicted entry would be looked up again under a new id and the same file
   * would end up with two `FileState`s that cannot see each other, silently
   * dropping a share reservation. `./state.ts` reports the exact span in which
   * a key means something (`onFileRetained`/`onFileReleased`), and this set is
   * the record of the pins taken for it: it makes the pins idempotent per key,
   * and it is what `destroy()` hands back so a session teardown cannot leave an
   * entry pinned for the rest of the table's life.
   */
  readonly #pinnedFiles = new Set<string>();
  /** The verifiers of OPEN with `EXCLUSIVE4`/`EXCLUSIVE4_1` — see `../util.ts`. */
  readonly #exclusives: ExclusiveCreates;
  #destroyed = false;

  /**
   * `shared` is the router's — see `../util.ts`. Left out, this session makes
   * its own handle table, lock, counters and exclusive-create table, which is
   * what its own tests do.
   */
  constructor(driver: FsDriver, options: NfsSessionOptions = {}, shared: NfsSharedState = {}) {
    this.driver = createLoopback(driver);
    this.options = options;
    this.stats = shared.stats ?? newSessionStats();
    this.#lock = shared.lock ?? new PathLock();
    this.handles =
      shared.handles ??
      new FileHandleTable({
        useDriverIno: options.useDriverIno,
        verifier: options.verifier,
      });
    this.writeVerifier = this.handles.verifier.slice(0, NFS4_VERIFIER_SIZE);
    this.#snapshots = new DirectorySnapshots(options.snapshotCache);
    this.#exclusives = shared.exclusiveCreates ?? new ExclusiveCreates();
    // The ID map is this file's, not the state table's — see `../util.ts`.
    const { idmap, ...knobs } = options.nfs4 ?? {};
    this.#idmap = idmap;
    this.state = new Nfs4State({
      ...knobs,
      onOpenReleased: (other) => this.#released.push(stateKey(other)),
      onFileRetained: (fileKey) => this.#pinFile(fileKey),
      onFileReleased: (fileKey) => this.#unpinFile(fileKey),
    });
    this.#maxOperations = Math.max(1, options.nfs4?.maxOperations ?? DEFAULT_MAX_OPERATIONS);
  }

  get destroyed(): boolean {
    return this.#destroyed;
  }

  /**
   * Answer one RPC record.
   *
   * Resolves to the encoded reply, or `null` for a record too damaged to carry
   * an xid — there is nothing to address a reply to. **Never rejects.**
   *
   * What comes back is a **view of the one buffer this call built its reply
   * in**, not a copy: the caller owns it outright, and nothing here writes
   * to it again. `../xdr.ts`'s `XdrWriter.view()` states the rule the
   * sessions keep to earn that.
   *
   * A direct caller must not overwrite `message` while the promise is
   * outstanding; everything this session *keeps* — names, file handles,
   * session IDs — is copied out of it by the decoders, and the whole COMPOUND
   * is decoded before the first await. The transport never has to think about
   * it: `../rpc.ts`'s `RecordAssembler` hands over a record copied out of the
   * socket's buffers rather than a view of them.
   */
  async handleCall(
    message: Uint8Array,
    _context: NfsRequestContext = {},
  ): Promise<Uint8Array | null> {
    this.stats.requests++;
    let call: RpcCall;
    let args: XdrReader;
    try {
      ({ call, args } = decodeCall(message));
    } catch {
      this.stats.dropped++;
      return null;
    }
    try {
      const reply = await this.#dispatch(call, args);
      this.stats.replies++;
      return reply;
      /* v8 ignore next 8 -- the compound loop already catches everything; this
         is the reply that must exist even if it ever stops doing so. */
    } catch (error) {
      this.options.onError?.(error, call);
      this.stats.replies++;
      this.stats.errors++;
      return encodeAcceptError(call.xid, RPC_SYSTEM_ERR);
    }
  }

  /**
   * Drop every cached listing, release every pinned handle entry, close every
   * driver handle still held open, and stop. Idempotent. File *handles* (the
   * wire kind) are the router's.
   *
   * The pins have to go here precisely *because* the table is the router's:
   * this session's state dies with it, but the entries it was holding against
   * eviction do not, and a pin nobody can ever release again is an entry the
   * cap can never reclaim.
   *
   * The driver handles are this session's own: an open state that is still
   * open when the server stops has nobody left to CLOSE it, and a driver whose
   * handles hold buffers — `mountx/drivers/unstorage` writes back on the last
   * `close` — would otherwise lose the writes. A failure to close is reported
   * and swallowed, exactly as `../v3/session.ts` treats one.
   */
  async destroy(): Promise<void> {
    this.#destroyed = true;
    this.#snapshots.clear();
    this.#exclusives.clear();
    this.#maxOpsBySession.clear();
    // Not through `#unpinFile`: the whole set goes at once here, so it is
    // emptied in one step rather than deleted from under its own iterator.
    for (const fileKey of this.#pinnedFiles) {
      this.handles.unpin(entryIdOf(fileKey)!);
    }
    this.#pinnedFiles.clear();
    const open = [...this.#openHandles.keys(), ...this.#released];
    this.#released.length = 0;
    for (const key of open) {
      await this.#closeHandle(key);
    }
  }

  // -------------------------------------------------------------------------
  // driver handles, one per open state
  // -------------------------------------------------------------------------

  /** Host `open(2)` flags for a `share_access` (RFC 8881 §18.16.3). */
  #openFlags(access: number): number {
    const read = (access & OPEN4_SHARE_ACCESS_READ) !== 0;
    const write = (access & OPEN4_SHARE_ACCESS_WRITE) !== 0;
    if (read && write) {
      return constants.O_RDWR;
    }
    return write ? constants.O_WRONLY : constants.O_RDONLY;
  }

  /**
   * Give an open state the driver handle its access bits call for.
   *
   * An OPEN that upgrades an existing open (§9.9 "the result is to 'OR'
   * together the new share and deny status together with the existing status")
   * gets a *wider* handle by re-opening: the driver interface has no way to add
   * an access mode to an open handle, and keeping the narrow one would answer
   * the client's newly granted WRITE with `EBADF` from the driver.
   */
  async #bindHandle(key: string, path: string, access: number): Promise<void> {
    const flags = this.#openFlags(access);
    const existing = this.#openHandles.get(key);
    if (existing !== undefined && existing.flags === flags) {
      return;
    }
    const handle = await this.driver.open(path, flags);
    this.#openHandles.set(key, { handle, flags, path });
    if (existing !== undefined) {
      await this.#close(existing.handle);
    }
  }

  /** Close and forget the driver handle an open state was holding. */
  async #closeHandle(key: string): Promise<void> {
    const open = this.#openHandles.get(key);
    if (open === undefined) {
      return;
    }
    this.#openHandles.delete(key);
    await this.#close(open.handle);
  }

  /** Close every handle `./state.ts` has released since the last drain. */
  async #drainReleased(): Promise<void> {
    while (this.#released.length > 0) {
      await this.#closeHandle(this.#released.shift()!);
    }
  }

  /** `close`, with the failure reported rather than thrown — as in `../v3/session.ts`. */
  async #close(handle: FileHandleLike): Promise<void> {
    try {
      await handle.close();
    } catch (error) {
      this.options.onError?.(error, undefined);
    }
  }

  /**
   * Open, act, close — for I/O that names no open state.
   *
   * The same shape `../v3/session.ts` uses for every READ and WRITE it answers,
   * and for the same reason: an anonymous or bypass stateid says there is no
   * open to borrow a handle from, so this request is the whole lifetime of one.
   */
  async #withFile<T>(
    path: string,
    flags: number,
    fn: (handle: FileHandleLike) => Promise<T>,
  ): Promise<T> {
    const handle = await this.driver.open(path, flags);
    try {
      return await fn(handle);
    } finally {
      await this.#close(handle);
    }
  }

  // -------------------------------------------------------------------------
  // the RPC layer
  // -------------------------------------------------------------------------

  async #dispatch(call: RpcCall, args: XdrReader): Promise<Uint8Array> {
    if (call.rpcVersion !== RPC_VERSION) {
      return encodeRpcMismatch(call.xid);
    }
    // Parsed, never verified — see the note at the top of `../rpc.ts`. NFSv4.1
    // mandates RPCSEC_GSS support for a general-purpose server; this one speaks
    // the two flavors it can actually decode and refuses the rest rather than
    // accepting a credential it cannot read.
    if (call.cred.flavor !== AUTH_NONE && call.cred.flavor !== AUTH_SYS) {
      return encodeAuthError(call.xid, AUTH_TOOWEAK);
    }
    if (call.program !== NFS4_PROGRAM) {
      return encodeAcceptError(call.xid, RPC_PROG_UNAVAIL);
    }
    if (call.version !== NFS_V4) {
      return encodeAcceptError(call.xid, RPC_PROG_MISMATCH, { low: NFS_V4, high: NFS_V4 });
    }
    this.#count(call.procedure);

    try {
      switch (call.procedure) {
        case NFSPROC4_NULL: {
          args.end("NULL arguments");
          return encodeAcceptedReply(call.xid);
        }
        case NFSPROC4_COMPOUND: {
          return await this.#compound(call, args);
        }
        default: {
          throw new ProcedureUnavailable(call.procedure);
        }
      }
    } catch (error) {
      // Only two things reach here: a decode failure the compound loop chose
      // not to answer with a status (§16.2.3's "traditional one-pass XDR
      // decode ... the RPC XDR decode error would be returned"), and a
      // procedure that does not exist.
      if (isXdrError(error)) {
        this.options.onError?.(error, call);
        this.stats.errors++;
        return encodeAcceptError(call.xid, RPC_GARBAGE_ARGS);
      }
      if (error instanceof ProcedureUnavailable) {
        this.stats.errors++;
        return encodeAcceptError(call.xid, RPC_PROC_UNAVAIL);
      }
      throw error;
    }
  }

  #count(procedure: number): void {
    const key = `NFS4:${procedure === NFSPROC4_NULL ? "NULL" : procedure === NFSPROC4_COMPOUND ? "COMPOUND" : procedure}`;
    this.stats.procedures.set(key, (this.stats.procedures.get(key) ?? 0) + 1);
  }

  /** Note a non-OK compound status, and hand the error to whoever is listening. */
  #failed(status: number, error?: unknown): number {
    if (status !== NFS4_OK) {
      this.stats.errors++;
      if (error !== undefined) {
        this.options.onError?.(error, undefined);
      }
    }
    return status;
  }

  // -------------------------------------------------------------------------
  // COMPOUND (RFC 8881 §16.2)
  // -------------------------------------------------------------------------

  /**
   * Decode a whole `COMPOUND4args`, stopping at the first operation this file
   * cannot read.
   *
   * Synchronous and total: everything the compound keeps is copied here, before
   * the first `await`, which is the zero-copy contract. `tag` and
   * `minorversion` are read by the caller, because
   * `NFS4ERR_MINOR_VERS_MISMATCH` "takes precedence over all other errors"
   * (§16.2.3) and so must be answered before the argument array is even looked
   * at.
   */
  #decodeOps(args: XdrReader, tag: string): DecodedCompound {
    const count = args.u32("COMPOUND4args.argarray count");
    // The same bound `XdrReader.array` applies, restated because the count is
    // read here rather than there: the shortest operation is one word.
    if (count > NFS4_MAX_COMPOUND_OPS || count > args.remaining / 4) {
      throw new XdrError(`COMPOUND4args.argarray claims ${count} operations, which cannot fit`);
    }
    if (count > this.#maxOperations) {
      // Past the ceiling this server would ever counter-offer, so past every
      // session's `ca_maxoperations` too. Nothing is decoded and nothing runs;
      // the caller answers `NFS4ERR_TOO_MANY_OPS`.
      return { tag, count, ops: [], halt: undefined };
    }
    const ops: DecodedOp[] = [];
    let halt: DecodeHalt | undefined;
    for (let index = 0; index < count; index++) {
      const op = args.u32("nfs_argop4.argop");
      if ((op < OP_FIRST || op > OP_LAST) && op !== OP_ILLEGAL) {
        // §16.2.3: "the server's response will encode the opcode OP_ILLEGAL
        // rather than the illegal opcode of the request".
        halt = { op: OP_ILLEGAL, status: NFS4ERR_OP_ILLEGAL };
        break;
      }
      const codec = OP_CODECS.get(op);
      if (codec === undefined) {
        // A real NFSv4.1 operation with no codec row — DELEGRETURN, OPENATTR,
        // the LAYOUT family, the NFSv4.0 leftovers. `NFS4ERR_NOTSUPP` and stop.
        halt = { op, status: NFS4ERR_NOTSUPP };
        break;
      }
      ops.push({ op, args: codec.readArgs?.(args) });
    }
    if (halt === undefined) {
      args.end("COMPOUND arguments");
    }
    return { tag, count, ops, halt };
  }

  async #compound(call: RpcCall, args: XdrReader): Promise<Uint8Array> {
    const tag = args.string(NFS4_MAX_TAG, "COMPOUND4args.tag");
    const minorversion = args.u32("COMPOUND4args.minorversion");
    if (minorversion !== NFS4_MINOR_VERSION_1) {
      // §16.2.3: "the server MUST return an error of NFS4ERR_MINOR_VERS_MISMATCH
      // and a zero-length resultdata array", and that error "takes precedence
      // over all other errors" — so the argument array is not decoded at all.
      return this.#reply(call, tag, this.#failed(NFS4ERR_MINOR_VERS_MISMATCH), []);
    }
    const request = this.#decodeOps(args, tag);
    if (request.count > this.#maxOperations) {
      return this.#reply(call, tag, this.#failed(NFS4ERR_TOO_MANY_OPS), []);
    }
    const first = request.ops[0] ?? (request.halt === undefined ? undefined : request.halt);
    const firstOp = first?.op;

    if (firstOp === undefined) {
      // Nothing to execute, and nothing to be wrong about: §16.2.3 conditions
      // the status on "if the results array length is non-zero".
      return this.#reply(call, tag, NFS4_OK, []);
    }
    if (firstOp === OP_ILLEGAL) {
      // Not an operation, in the first position — either an opcode outside the
      // legal range (which {@link Nfs4Session.#decodeOps} rewrites to
      // `OP_ILLEGAL`, per §16.2.3: "the server's response will encode the
      // opcode OP_ILLEGAL rather than the illegal opcode of the request") or a
      // client sending 10044 outright, which decodes as a real op because the
      // `nfs_argop4` union does have a void `OP_ILLEGAL` arm. The two are the
      // same event and §18.52.4 says so — the answer is `ILLEGAL4res` "just as
      // it would be with any other invalid operation code" — so they take one
      // path here rather than one of them falling through to the session rules
      // below.
      //
      // The status is fixed: §18.52.3, "The status field of ILLEGAL4res MUST be
      // set to NFS4ERR_OP_ILLEGAL", and §15.2's ILLEGAL row admits only that
      // and `NFS4ERR_BADXDR`. It therefore outranks §18.46.3's position rule,
      // which is a rule about *operations*: there is nothing here to ask
      // whether it may open a session-less COMPOUND. A first operation that is
      // real but unimplemented — DELEGRETURN, say — is a different case and
      // still answers `NFS4ERR_OP_NOT_IN_SESSION`.
      return this.#halted(call, tag, [statusResop(OP_ILLEGAL, NFS4ERR_OP_ILLEGAL)]);
    }
    if (firstOp !== OP_SEQUENCE) {
      if (!SESSIONLESS_OPS.has(firstOp)) {
        return this.#halted(call, tag, [statusResop(firstOp, NFS4ERR_OP_NOT_IN_SESSION)]);
      }
      if (request.count !== 1) {
        // §18.35.3, §18.36.3, §18.37.3, §18.50.3 and §18.34.3 all say the same
        // thing of their own operation: without a leading SEQUENCE it must be
        // the only one in the COMPOUND.
        return this.#halted(call, tag, [statusResop(firstOp, NFS4ERR_NOT_ONLY_OP)]);
      }
      const resarray: Resop4[] = [];
      const executed = await this.#execute(call, request, 0, resarray, undefined);
      return this.#reply(call, tag, executed.status, resarray);
    }

    const seq = request.ops[0]!.args as Sequence4args;
    if (request.count > this.#maxOpsFor(seq.sessionid)) {
      // §18.36.3, on `ca_maxoperations`: "After the session is created, if a
      // requester sends a COMPOUND or CB_COMPOUND with more operations than
      // ca_maxoperations, the replier MUST return NFS4ERR_TOO_MANY_OPS".
      // Answered before anything runs, so the slot is untouched.
      return this.#reply(call, tag, this.#failed(NFS4ERR_TOO_MANY_OPS), []);
    }

    const outcome = this.state.sequence(seq);
    // A SEQUENCE can revoke a lapsed lease before a single operation runs
    // (§8.4.3), and the driver handles those opens held go with them.
    await this.#drainReleased();
    switch (outcome.kind) {
      case "error": {
        // §2.10.6.1.2: a SEQUENCE that failed leaves the slot alone, so there
        // is nothing to cache and nothing was executed.
        return this.#halted(call, tag, [statusResop(OP_SEQUENCE, outcome.status)]);
      }
      case "replay": {
        // The cached bytes are a whole `COMPOUND4res` and nothing more — a
        // retransmission may carry a new xid, so the RPC header is always
        // fresh. `./state.ts` owns the array; it is written into a new reply
        // buffer and never mutated.
        return encodeAcceptedReply(call.xid, outcome.bytes);
      }
      case "replay-uncached": {
        const resarray: Resop4[] = [{ op: OP_SEQUENCE, res: outcome.sequence }];
        // §2.10.6.1.3: `NFS4ERR_RETRY_UNCACHED_REP` is never the answer to the
        // leading SEQUENCE itself; it goes on the operation after it.
        const next = request.ops[1]?.op ?? request.halt?.op;
        if (next === undefined) {
          return this.#reply(call, tag, NFS4_OK, resarray);
        }
        resarray.push(statusResop(next, outcome.opStatus));
        return this.#halted(call, tag, resarray);
      }
      case "new": {
        const resarray: Resop4[] = [{ op: OP_SEQUENCE, res: outcome.sequence }];
        const executed = await this.#execute(call, request, 1, resarray, outcome.clientid, seq);
        return this.#cachedReply(call, tag, executed.status, resarray, outcome, executed.cacheable);
      }
    }
  }

  /** The negotiated `ca_maxoperations` for a session, or the pre-session ceiling. */
  #maxOpsFor(sessionid: Uint8Array): number {
    return this.#maxOpsBySession.get(sessionKey(sessionid)) ?? this.#maxOperations;
  }

  /** A reply whose last resop already carries the compound's status. */
  #halted(call: RpcCall, tag: string, resarray: Resop4[]): Uint8Array {
    const status = (resarray[resarray.length - 1]!.res as Status4res).status;
    return this.#reply(call, tag, this.#failed(status), resarray);
  }

  /**
   * One COMPOUND reply, built in one buffer.
   *
   * The accepted-reply header goes in first and the `COMPOUND4res` straight
   * after it, so what comes back is a view of a single writer rather than two
   * buffers concatenated. Nothing writes to it once this returns — see
   * `XdrWriter.view()` for the rule that makes the view safe to hand out.
   */
  #reply(call: RpcCall, tag: string, status: number, resarray: Resop4[]): Uint8Array {
    const reply = new XdrWriter(compoundCapacity(tag, resarray));
    writeAcceptedReplyHeader(reply, call.xid);
    writeCompoundRes(reply, { status, tag, resarray });
    return reply.view();
  }

  /**
   * Run the operations from `from` onward over one cursor, appending to
   * `resarray`.
   *
   * Halts at the first non-`NFS4_OK` status (§16.2.3), and then at the decode
   * halt if the array reached one. `cacheable` is false when the compound
   * destroyed the session it rides — there is no slot to cache into any more,
   * and §18.37.3 warns the client to expect exactly that.
   */
  async #execute(
    call: RpcCall,
    request: DecodedCompound,
    from: number,
    resarray: Resop4[],
    clientid: bigint | undefined,
    seq?: Sequence4args,
  ): Promise<{ status: number; cacheable: boolean }> {
    const cursor: Cursor = {
      currentFh: undefined,
      savedFh: undefined,
      currentStateid: zeroStateid(),
      savedStateid: zeroStateid(),
      creds: credentialsOf(call.cred),
      clientid,
      ownSession: seq === undefined ? undefined : sessionKey(seq.sessionid),
      destroyedOwnSession: false,
    };
    let status = resarray.length === 0 ? NFS4_OK : (resarray[0]!.res as Status4res).status;
    let halted = false;
    for (let index = from; index < request.ops.length; index++) {
      const resop = await this.#operation(request.ops[index]!, cursor);
      // Whatever that operation ended — a CLOSE, or a lease sweep it triggered
      // — the driver handles go here, before the next one runs.
      await this.#drainReleased();
      resarray.push(resop);
      status = (resop.res as Status4res).status;
      if (status !== NFS4_OK) {
        halted = true;
        break;
      }
    }
    if (!halted && request.halt !== undefined) {
      resarray.push(statusResop(request.halt.op, request.halt.status));
      status = request.halt.status;
    }
    this.#failed(status);
    return { status, cacheable: !cursor.destroyedOwnSession };
  }

  /**
   * Encode, cache and frame the reply to a COMPOUND that rode a slot.
   *
   * The one place `NFS4ERR_REP_TOO_BIG_TO_CACHE` can be decided, because it is
   * a fact about the *encoded* reply: §2.10.6.4, "If the reply exceeds
   * ca_maxresponsesize_cached (and sa_cachethis ... is TRUE), then the server
   * MUST return NFS4ERR_REP_TOO_BIG_TO_CACHE. Even if
   * NFS4ERR_REP_TOO_BIG_TO_CACHE ... is returned on an operation other than the
   * first operation (SEQUENCE ...), then the reply MUST be cached if
   * sa_cachethis ... is TRUE." So the over-sized reply is *replaced* by a
   * shorter one carrying that status on the operation that overran, everything
   * already executed is kept — the section's own worked example has a RENAME
   * five operations back that must not be run twice — and it is that shorter
   * reply which is both sent and cached.
   */
  #cachedReply(
    call: RpcCall,
    tag: string,
    status: number,
    resarray: Resop4[],
    outcome: { ticket: SlotTicket; cachethis: boolean },
    cacheable: boolean,
  ): Uint8Array {
    const cache = outcome.cachethis && cacheable;
    let results = resarray;
    const reply = new XdrWriter(compoundCapacity(tag, resarray));
    writeAcceptedReplyHeader(reply, call.xid);
    writeCompoundRes(reply, { status, tag, resarray: results });
    if (cache && reply.length - ACCEPTED_REPLY_HEADER_SIZE > outcome.ticket.maxCachedBytes) {
      const trimmed = trimForCache(tag, results, outcome.ticket.maxCachedBytes);
      if (trimmed !== undefined) {
        results = trimmed;
        status = this.#failed(NFS4ERR_REP_TOO_BIG_TO_CACHE);
        // The shorter reply replaces the over-sized one in the same buffer:
        // rewinding to the RPC header and encoding again is what the second
        // `encodeCompoundRes` was doing, minus a second allocation.
        reply.truncate(ACCEPTED_REPLY_HEADER_SIZE);
        writeCompoundRes(reply, { status, tag, resarray: results });
      }
    }
    const framed = reply.view();
    // The ticket is handed back whether or not there are bytes to store —
    // `./state.ts` needs to know the request finished either way. What it is
    // handed is a *view* of this reply, which is safe because `cacheReply`
    // copies on insert. That asymmetry is one-way: it hands its copy back
    // **uncopied** on replay, which is why the replay path above wraps those
    // bytes with `encodeAcceptedReply` — a fresh buffer — instead of appending
    // to a writer that already holds them.
    this.state.cacheReply(
      outcome.ticket,
      cache ? framed.subarray(ACCEPTED_REPLY_HEADER_SIZE) : undefined,
    );
    return framed;
  }

  /**
   * One operation, and the promise that it produces exactly one resop.
   *
   * Every driver failure and every deliberate refusal comes back as a status
   * here, which is what makes "one reply per compound" hold: nothing below this
   * point can reject.
   */
  async #operation(entry: DecodedOp, cursor: Cursor): Promise<Resop4> {
    try {
      // RENAME is the writer, exactly as in v3: it is the one operation that
      // rewrites paths it did not resolve itself. Everything else is a reader,
      // taken per operation rather than per compound so a RENAME later in the
      // same compound is not waiting on a lock it already holds.
      const res =
        entry.op === OP_RENAME
          ? await this.#lock.write(() => this.#run(entry, cursor))
          : await this.#lock.read(() => this.#run(entry, cursor));
      return { op: entry.op, res };
    } catch (error) {
      const status = statusOf(error);
      this.options.onError?.(error, undefined);
      return { op: entry.op, res: failureRes(entry.op, status) };
    }
  }

  async #run(entry: DecodedOp, cursor: Cursor): Promise<Resop4Value> {
    switch (entry.op) {
      case OP_ACCESS: {
        return this.#access(entry.args as Access4args, cursor);
      }
      case OP_BACKCHANNEL_CTL: {
        return this.#backchannelCtl(entry.args as BackchannelCtl4args);
      }
      case OP_BIND_CONN_TO_SESSION: {
        return this.#bindConnToSession(entry.args as BindConnToSession4args);
      }
      case OP_CLOSE: {
        return this.#closeOp(entry.args as Close4args, cursor);
      }
      case OP_COMMIT: {
        return this.#commit(cursor);
      }
      case OP_CREATE: {
        return this.#create(entry.args as Create4args, cursor);
      }
      case OP_CREATE_SESSION: {
        return this.#createSession(entry.args as CreateSession4args);
      }
      case OP_DESTROY_CLIENTID: {
        return this.#destroyClientid(entry.args as DestroyClientid4args, cursor);
      }
      case OP_DESTROY_SESSION: {
        return this.#destroySession(entry.args as DestroySession4args, cursor);
      }
      case OP_EXCHANGE_ID: {
        return this.#exchangeId(entry.args as ExchangeId4args);
      }
      case OP_FREE_STATEID: {
        return this.#freeStateid(entry.args as FreeStateid4args, cursor);
      }
      case OP_GETATTR: {
        return this.#getattr(entry.args as Getattr4args, cursor);
      }
      case OP_GETFH: {
        return this.#getfh(cursor);
      }
      case OP_ILLEGAL: {
        // §18.52.3: a client that sends 10044 deliberately is answered rather
        // than dropped, with the status the opcode means.
        return { status: NFS4ERR_OP_ILLEGAL };
      }
      case OP_LINK: {
        return this.#link(entry.args as Link4args, cursor);
      }
      case OP_LOCK: {
        return this.#lockOp(entry.args as Lock4args, cursor);
      }
      case OP_LOCKT: {
        return this.#lockt(entry.args as Lockt4args, cursor);
      }
      case OP_LOCKU: {
        return this.#locku(entry.args as Locku4args, cursor);
      }
      case OP_LOOKUP: {
        return this.#lookup(entry.args as Lookup4args, cursor);
      }
      case OP_LOOKUPP: {
        return this.#lookupp(cursor);
      }
      case OP_NVERIFY: {
        return this.#verify(entry.args as Verify4args, cursor, false);
      }
      case OP_OPEN: {
        return this.#open(entry.args as Open4args, cursor);
      }
      case OP_OPEN_DOWNGRADE: {
        return this.#openDowngrade(entry.args as OpenDowngrade4args, cursor);
      }
      case OP_PUTFH: {
        return this.#putfh(entry.args as Putfh4args, cursor);
      }
      case OP_PUTPUBFH:
      case OP_PUTROOTFH: {
        // §18.20.3: "The public filehandle and the root filehandle ... SHOULD
        // be equivalent." This server exports one tree from its root and has
        // nothing else to point a public filehandle at, so they are the same
        // handle and PUTPUBFH is PUTROOTFH.
        cursor.currentFh = this.handles.encode(this.handles.root);
        cursor.currentStateid = zeroStateid();
        return { status: NFS4_OK };
      }
      case OP_READ: {
        return this.#read(entry.args as Read4args, cursor);
      }
      case OP_READDIR: {
        return this.#readdir(entry.args as Readdir4args, cursor);
      }
      case OP_READLINK: {
        return this.#readlink(cursor);
      }
      case OP_RECLAIM_COMPLETE: {
        return this.#reclaimComplete(entry.args as ReclaimComplete4args, cursor);
      }
      case OP_REMOVE: {
        return this.#remove(entry.args as Remove4args, cursor);
      }
      case OP_RENAME: {
        return this.#rename(entry.args as Rename4args, cursor);
      }
      case OP_RESTOREFH: {
        // **Not** `NFS4ERR_RESTOREFH`, which is what NFSv4.0 answered here.
        // §18.27.3: "If there is no saved filehandle, then the server will
        // return the error NFS4ERR_NOFILEHANDLE", and §15.1.16.4 says of
        // NFS4ERR_RESTOREFH itself that "in NFSv4.1, this error has been
        // superseded by NFS4ERR_NOFILEHANDLE" — §15.2's RESTOREFH row lists
        // only the latter.
        // "The SAVEFH and RESTOREFH operations will save and restore both the
        // current filehandle and the current stateid as a set" (§16.2.3.1.2).
        cursor.currentFh = this.#requireSaved(cursor);
        cursor.currentStateid = cursor.savedStateid;
        return { status: NFS4_OK };
      }
      case OP_SAVEFH: {
        cursor.savedFh = this.#requireCurrent(cursor);
        cursor.savedStateid = cursor.currentStateid;
        return { status: NFS4_OK };
      }
      case OP_SECINFO: {
        return this.#secinfo(entry.args as Secinfo4args, cursor);
      }
      case OP_SECINFO_NO_NAME: {
        return this.#secinfoNoName(entry.args as SecinfoNoName4args, cursor);
      }
      case OP_SEQUENCE: {
        // Reached only past position zero: the leading one is consumed before
        // the loop starts. §18.46.3: "The error NFS4ERR_SEQUENCE_POS will be
        // returned when it is found in any position in a COMPOUND beyond the
        // first."
        return { status: NFS4ERR_SEQUENCE_POS };
      }
      case OP_SETATTR: {
        return this.#setattr(entry.args as Setattr4args, cursor);
      }
      case OP_TEST_STATEID: {
        return this.#testStateid(entry.args as TestStateid4args, cursor);
      }
      case OP_VERIFY: {
        return this.#verify(entry.args as Verify4args, cursor, true);
      }
      case OP_WRITE: {
        return this.#write(entry.args as Write4args, cursor);
      }
      /* v8 ignore next 4 -- unreachable: the decoder rejects every opcode that
         is neither in the codec table nor handled above. */
      default: {
        throw new Nfs4StatusError(NFS4ERR_SERVERFAULT, `no handler for ${opName4(entry.op)}`);
      }
    }
  }

  // -------------------------------------------------------------------------
  // the cursor, paths and attributes
  // -------------------------------------------------------------------------

  /** The current filehandle, or `NFS4ERR_NOFILEHANDLE` (§15.1.2.5). */
  #requireCurrent(cursor: Cursor): Uint8Array {
    if (cursor.currentFh === undefined) {
      throw new Nfs4StatusError(NFS4ERR_NOFILEHANDLE, "no current filehandle");
    }
    return cursor.currentFh;
  }

  /**
   * The path the current filehandle names.
   *
   * Resolved per operation rather than cached across the compound, so a RENAME
   * earlier in the same COMPOUND is reflected in what a later operation
   * touches — a handle names a *file*, and its path is whatever the table says
   * now.
   */
  #pathOfCurrent(cursor: Cursor): string {
    return this.handles.resolve(this.#requireCurrent(cursor));
  }

  /** The saved filehandle, or `NFS4ERR_NOFILEHANDLE` (§15.1.2.5, §18.27.3). */
  #requireSaved(cursor: Cursor): Uint8Array {
    if (cursor.savedFh === undefined) {
      throw new Nfs4StatusError(NFS4ERR_NOFILEHANDLE, "no saved filehandle");
    }
    return cursor.savedFh;
  }

  #pathOfSaved(cursor: Cursor): string {
    return this.handles.resolve(this.#requireSaved(cursor));
  }

  /** `lstat`, falling back to `stat` for drivers with no `lstat`. */
  async #statOf(path: string): Promise<StatsLike> {
    try {
      return await this.driver.lstat(path);
    } catch (error) {
      if ((error as { code?: string }).code === "ENOSYS") {
        return this.driver.stat(path);
      }
      throw error;
    }
  }

  /** Bind a path to a handle and describe it. */
  async #bind(path: string): Promise<{ entry: HandleEntry; stats: StatsLike }> {
    const stats = await this.#statOf(path);
    return { entry: this.handles.bind(path, stats), stats };
  }

  /**
   * Drop the cached listing of a directory whose names just changed.
   *
   * The rule this implements — which directories, and only which — is written
   * down once, on `DirectorySnapshots` in `../handles.ts`, and `../v3/session.ts`
   * has the same helper against the same cache. A directory nothing has ever
   * listed has no entry to drop, which is why the lookup is allowed to miss.
   */
  #invalidate(dir: string): void {
    const entry = this.handles.at(dir);
    if (entry !== undefined) {
      this.#snapshots.delete(entry.id);
    }
  }

  /**
   * A component name, checked the way `../v3/session.ts` checks one.
   *
   * `.` and `..` are refused here where v3 accepts them in LOOKUP: NFSv4 has
   * LOOKUPP for the parent and no name for "here", so both are
   * `NFS4ERR_BADNAME` (§15.2 lists it for LOOKUP, LINK, REMOVE, RENAME and
   * CREATE). A zero-length name is `NFS4ERR_INVAL`, which §18.13.3 names
   * explicitly.
   */
  #checkName(name: string): string {
    if (name.length === 0) {
      throw new Nfs4StatusError(NFS4ERR_INVAL, "component4 is empty");
    }
    if (name.includes("/") || name === "." || name === "..") {
      throw new Nfs4StatusError(NFS4ERR_BADNAME, `component4 '${name}' is not a name`);
    }
    if (stringByteLength(name) > NAME_MAX) {
      throw fsError("ENAMETOOLONG", { message: `ENAMETOOLONG: entry name '${name}'` });
    }
    return name;
  }

  #maxread(): number {
    return this.options.rtmax ?? DEFAULT_MAXREAD;
  }

  #maxwrite(): number {
    return this.options.wtmax ?? DEFAULT_MAXWRITE;
  }

  /**
   * What `supported_attrs` advertises, capability-honestly.
   *
   * `./attr.ts`'s `SUPPORTED_ATTRS` is what the *codec* can carry; this is what
   * this driver can actually answer. The `statfs` family goes when the driver
   * has no `statfs`, and the two write-only time attributes go when it has no
   * `utimes` — advertising either and then omitting it from every reply would
   * be the kind of quiet pretending the capability rule exists to stop.
   */
  #supportedAttrs(): Bitmap4 {
    let supported = SUPPORTED_ATTRS;
    if (!this.driver.capabilities.statfs) {
      supported = bitmapDifference(supported, STATFS_ATTRS);
    }
    if (!this.driver.capabilities.times) {
      supported = bitmapDifference(supported, TIME_SET_ATTRS);
    }
    return supported;
  }

  /** What a GETATTR or READDIR reply may contain: {@link Nfs4Session.#supportedAttrs} minus the write-only pair. */
  #getableAttrs(): Bitmap4 {
    return bitmapDifference(this.#supportedAttrs(), SET_ONLY_ATTRS);
  }

  /** The per-filesystem half of a `fattr4`: the same answers for every object. */
  #filesystemValues(): Fattr4Values {
    const capabilities = this.driver.capabilities;
    return {
      supportedAttrs: this.#supportedAttrs(),
      // The handle table hands out handles that live as long as the server, and
      // `FH4_PERSISTENT` is the *absence* of every expiry bit (§4.2.3).
      fhExpireType: FH4_PERSISTENT,
      linkSupport: capabilities.hardlinks,
      symlinkSupport: capabilities.symlinks,
      // No driver has named attribute directories, and saying so is an answer.
      namedAttr: false,
      // One path maps to one handle, and one handle to one object (§5.8.1.10).
      uniqueHandles: true,
      leaseTime: this.state.leaseSeconds,
      maxfilesize: MAX_OFFSET,
      maxlink: capabilities.hardlinks ? MAX_LINK : 1,
      maxname: NAME_MAX,
      maxread: BigInt(this.#maxread()),
      maxwrite: BigInt(this.#maxwrite()),
      // The driver's timestamps come from `Date`, so one millisecond is the
      // finest change a client can hope to observe.
      timeDelta: { seconds: 0n, nseconds: 1_000_000 },
    };
  }

  /**
   * The six `statfs`-derived attribute values, or an empty set.
   *
   * `driver.statfs` is called only when the request actually asks for one of
   * the six attributes that need it, and a failure answers with nothing rather
   * than failing the operation — the six bits are then simply absent from the
   * reply bitmap, which §18.7.3 makes the protocol's own answer for an
   * attribute a server cannot produce.
   *
   * Separate from {@link Nfs4Session.#valuesFor} because these six are the only
   * ones that are **not** about the object named: they describe the filesystem
   * it is on, and every entry of a directory is on the same one. That is what
   * lets a READDIR page ask once and reuse the answer for every name, instead
   * of a `statfs` per name — which with the memory driver is a whole-tree walk
   * per name, and on a driver with none is nothing but a failed call and an
   * `onError` per name.
   */
  async #statfsValues(path: string, requested: Bitmap4): Promise<Fattr4Values> {
    if (
      !this.driver.capabilities.statfs ||
      bitmapIsEmpty(bitmapIntersection(requested, STATFS_ATTRS))
    ) {
      return {};
    }
    try {
      return fattr4FsOf(await this.driver.statfs(path));
    } catch (error) {
      this.options.onError?.(error, undefined);
      return {};
    }
  }

  /**
   * Every attribute value this server has for one object.
   *
   * `fsValues` is {@link Nfs4Session.#statfsValues}' answer when the caller has
   * already got one for this filesystem; omitting it asks for a fresh one.
   */
  async #valuesFor(
    path: string,
    requested: Bitmap4,
    fsValues?: Fattr4Values | undefined,
  ): Promise<Fattr4Values> {
    const { entry, stats } = await this.#bind(path);
    const values: Fattr4Values = {
      ...this.#filesystemValues(),
      ...fattr4Of(stats, {
        // The driver's own `ino` when it offered one, kept on the entry by the
        // `bind` two lines up and spelled once, in `../handles.ts`.
        fileid: entry.fileid,
        filehandle: this.handles.encode(entry),
      }),
      owner: this.#ownerName(stats.uid, false),
      ownerGroup: this.#ownerName(stats.gid, true),
    };
    return Object.assign(values, fsValues ?? (await this.#statfsValues(path, requested)));
  }

  // -------------------------------------------------------------------------
  // the filehandle cursor
  // -------------------------------------------------------------------------

  /**
   * PUTFH (§18.19).
   *
   * A handle the table does not know is `NFS4ERR_STALE` — one of the two
   * §15.2 allows here, the other being `NFS4ERR_BADHANDLE` — because from a
   * client's point of view a handle it may no longer use and one that was never
   * ours are the same event, and `NFS4ERR_STALE` is the one it knows how to
   * recover from. See `../handles.ts`.
   *
   * **Where that error lands is deliberate.** This decodes and does not
   * resolve, so a handle to a file whose last name is gone used to reach the
   * *next* operation in the COMPOUND before failing there. Now that the table
   * drops an entry with no names, PUTFH itself is where it fails. Both are
   * legal — §15.2 lists `NFS4ERR_STALE` on PUTFH's own row — and failing at the
   * operation that names the dead handle is the more useful of the two: the
   * client is told which handle to drop, rather than being told that the GETATTR
   * it happened to put after it went wrong.
   */
  #putfh(args: Putfh4args, cursor: Cursor): Status4res {
    cursor.currentFh = this.handles.encode(this.handles.decode(args.object));
    // "If an operation sets the current filehandle but does not return a
    // stateid, the current stateid MUST be set to the all-zeros special
    // stateid" (§16.2.3.1.2).
    cursor.currentStateid = zeroStateid();
    return { status: NFS4_OK };
  }

  #getfh(cursor: Cursor): Getfh4res {
    return { status: NFS4_OK, object: this.#requireCurrent(cursor) };
  }

  async #lookup(args: Lookup4args, cursor: Cursor): Promise<Status4res> {
    const dir = this.#pathOfCurrent(cursor);
    const path = joinPath(dir, this.#checkName(args.objname));
    const { entry } = await this.#bind(path);
    cursor.currentFh = this.handles.encode(entry);
    cursor.currentStateid = zeroStateid();
    return { status: NFS4_OK };
  }

  /**
   * LOOKUPP (§18.14).
   *
   * "If there is no parent directory, an NFS4ERR_NOENT error must be returned.
   * Therefore, NFS4ERR_NOENT will be returned by the server when the current
   * filehandle is at the root or top of the server's file tree." The current
   * object must also be a directory, which is `NFS4ERR_NOTDIR` — and is checked
   * here rather than left to the driver, because `dirname` of a file's path is
   * a perfectly good directory and would otherwise succeed.
   */
  async #lookupp(cursor: Cursor): Promise<Status4res> {
    const path = this.#pathOfCurrent(cursor);
    const stats = await this.#statOf(path);
    if ((stats.mode & S_IFMT) !== S_IFDIR) {
      return { status: NFS4ERR_NOTDIR };
    }
    if (path === "/") {
      return { status: NFS4ERR_NOENT };
    }
    const { entry } = await this.#bind(dirname(path));
    cursor.currentFh = this.handles.encode(entry);
    cursor.currentStateid = zeroStateid();
    return { status: NFS4_OK };
  }

  // -------------------------------------------------------------------------
  // GETATTR / SETATTR / ACCESS / READLINK
  // -------------------------------------------------------------------------

  /**
   * GETATTR (§18.7).
   *
   * A requested attribute this server does not support is dropped from both the
   * reply bitmap and the values — §18.7.3 requires exactly that and §15.1.15.1
   * forbids `NFS4ERR_ATTRNOTSUPP` here. A requested *write-only* attribute is
   * different: §5.5 says "if a client attempts to set a get-only attribute or
   * get a set-only attributes, the server MUST return NFS4ERR_INVAL".
   */
  async #getattr(args: Getattr4args, cursor: Cursor): Promise<Getattr4res> {
    const path = this.#pathOfCurrent(cursor);
    if (!bitmapIsEmpty(bitmapIntersection(args.attrRequest, SET_ONLY_ATTRS))) {
      return { status: NFS4ERR_INVAL, objAttributes: undefined };
    }
    const attrmask = bitmapIntersection(args.attrRequest, this.#getableAttrs());
    const values = await this.#valuesFor(path, attrmask);
    return {
      status: NFS4_OK,
      objAttributes: { attrmask, values, unsupported: [] },
    };
  }

  /**
   * Split a requested `fattr4` mask into what may be set and what may not.
   *
   * Two refusals, and §5.5 and §18.30.4 give them different statuses: an
   * attribute this server does not support at all is `NFS4ERR_ATTRNOTSUPP`
   * ("If the server does not support an attribute as requested by the client,
   * the server SHOULD return NFS4ERR_ATTRNOTSUPP"), while one it supports but
   * cannot be *set* is get-only, and §5.5 makes that `NFS4ERR_INVAL`.
   */
  #settableOrRefuse(attr: Fattr4): void {
    const supported = this.#supportedAttrs();
    if (attr.unsupported.length > 0 || !bitmapIsEmpty(bitmapDifference(attr.attrmask, supported))) {
      throw new Nfs4StatusError(NFS4ERR_ATTRNOTSUPP, "fattr4 names an unsupported attribute");
    }
    if (!bitmapIsEmpty(bitmapDifference(attr.attrmask, SETTABLE_ATTRS))) {
      throw new Nfs4StatusError(NFS4ERR_INVAL, "fattr4 names a read-only attribute");
    }
  }

  /**
   * SETATTR (§18.30).
   *
   * The stateid is validated **only when the request sets `size`**, which is
   * the shape §18.30.3 gives it: "The stateid argument for SETATTR is used to
   * provide byte-range locking context that is necessary for SETATTR requests
   * that set the size attribute. Since setting the size attribute modifies the
   * file's data, it has the same locking requirements as a corresponding
   * WRITE." So a size change goes through the same check a WRITE does —
   * `NFS4ERR_OPENMODE` for an open that does not allow writing, `NFS4ERR_LOCKED`
   * for an anonymous or bypass stateid against a `OPEN4_SHARE_DENY_WRITE`
   * reservation, which the same paragraph calls out ("Any SETATTR that sets the
   * size attribute is incompatible with a share reservation that specifies
   * OPEN4_SHARE_DENY_WRITE") — and everything else ignores it, on the same
   * section's "when the file size attribute is not set, the special stateid
   * consisting of all bits equal to zero MAY be passed". The truncate itself
   * goes through the path rather than an open handle, so what the check buys is
   * the permission, not a descriptor.
   *
   * `attrsset` is the mask of what was actually applied, on success *and* on
   * failure — §18.30.3: "On either success or failure of the operation, the
   * server will return the attrsset bitmask to represent what (if any)
   * attributes were successfully set" — and §18.30.4 adds the two invariants
   * this keeps: it "MUST NOT include attribute bits not requested to be set by
   * the client", and "if the attribute masks in the request and reply are
   * equal, the status field in the reply MUST be NFS4_OK".
   *
   * The two *whole-request* refusals above happen before anything is touched,
   * so they answer with an empty `attrsset` — a subset of the request, as
   * §18.30.3 requires. Only a driver failure part-way through produces a
   * genuinely partial one, which is the case §18.30.4 calls out ("A failed
   * SETATTR may partially change a file's attributes").
   */
  async #setattr(args: Setattr4args, cursor: Cursor): Promise<Setattr4res> {
    const { path, fileKey } = this.#target(cursor);
    try {
      this.#settableOrRefuse(args.objAttributes);
      if (args.objAttributes.values.size !== undefined) {
        this.#ioStateid(args.stateid, cursor, fileKey, true);
      }
    } catch (error) {
      return { status: statusOf(error), attrsset: [] };
    }
    const applied = await this.#applyAttrs(path, args.objAttributes);
    if (applied.status === NFS4_OK) {
      // §18.16.4's commit: this is the SETATTR an exclusive create sends the
      // client back for, and once it has landed the client is not going to
      // retry the OPEN. See `ExclusiveCreates` in `../util.ts`.
      this.#exclusives.forget(path);
    }
    return { status: applied.status, attrsset: bitmapOf(applied.bits) };
  }

  /**
   * Apply a decoded `fattr4` to a path, in the order a shell would have issued
   * it: mode, then ownership, then size, then the timestamps — so an explicit
   * `time_modify_set` wins over the one the truncate just set.
   *
   * Never throws: it stops at the first driver failure and reports both the
   * status and the bits that landed before it.
   */
  async #applyAttrs(
    path: string,
    attr: Fattr4,
    options: { skipSize?: boolean; symlink?: boolean } = {},
  ): Promise<{ status: number; bits: number[] }> {
    const bits: number[] = [];
    const values = attr.values;
    try {
      const isLink = options.symlink === true;
      if (values.mode !== undefined && !isLink) {
        await this.driver.chmod(path, values.mode & 0o7777);
        bits.push(FATTR4_MODE);
      }
      if (values.owner !== undefined || values.ownerGroup !== undefined) {
        // §5.9's numeric fast path, then whatever ID map was configured.
        const uid = values.owner === undefined ? -1 : this.#ownerId(values.owner, false);
        const gid = values.ownerGroup === undefined ? -1 : this.#ownerId(values.ownerGroup, true);
        await this.#nofollow(
          () => this.driver.lchown(path, uid, gid),
          () => this.driver.chown(path, uid, gid),
        );
        if (values.owner !== undefined) {
          bits.push(FATTR4_OWNER);
        }
        if (values.ownerGroup !== undefined) {
          bits.push(FATTR4_OWNER_GROUP);
        }
      }
      if (values.size !== undefined && options.skipSize !== true) {
        await this.driver.truncate(path, this.#offset(values.size));
        bits.push(FATTR4_SIZE);
      }
      const applied = await this.#applyTimes(path, values, isLink);
      bits.push(...applied);
      return { status: NFS4_OK, bits };
    } catch (error) {
      this.options.onError?.(error, undefined);
      return { status: statusOf(error), bits };
    }
  }

  /** The two `time_*_set` attributes, which `utimes` can only set as a pair. */
  async #applyTimes(path: string, values: Fattr4Values, isLink: boolean): Promise<number[]> {
    const wantAtime = values.timeAccessSet !== undefined;
    const wantMtime = values.timeModifySet !== undefined;
    if (!wantAtime && !wantMtime) {
      return [];
    }
    const now = Date.now();
    // `utimes` sets both at once, so a request naming only one has to read the
    // other back — and after a truncate, read it back *fresh*.
    const stats = wantAtime && wantMtime ? undefined : await this.#statOf(path);
    const pick = (set: SetTime4 | undefined, fallbackMs: number): TimeLike => {
      if (set === undefined) {
        return fallbackMs / 1000;
      }
      if (set.how === SET_TO_SERVER_TIME4) {
        return now / 1000;
      }
      if (set.how !== SET_TO_CLIENT_TIME4) {
        // `settime4` has a `default: void` arm, so the decoder accepts any
        // `set_it`; a value that is neither of the two is the session's
        // `NFS4ERR_INVAL` to give (§3.3.2).
        throw new Nfs4StatusError(NFS4ERR_INVAL, `settime4.set_it ${set.how} is not a time_how4`);
      }
      return fromTime4(set.time ?? { seconds: 0n, nseconds: 0 }) / 1000;
    };
    const atime = pick(values.timeAccessSet, stats?.atimeMs ?? now);
    const mtime = pick(values.timeModifySet, stats?.mtimeMs ?? now);
    if (isLink) {
      await this.driver.lutimes(path, atime, mtime);
    } else {
      await this.#nofollow(
        () => this.driver.lutimes(path, atime, mtime),
        () => this.driver.utimes(path, atime, mtime),
      );
    }
    const bits: number[] = [];
    if (wantAtime) {
      bits.push(FATTR4_TIME_ACCESS_SET);
    }
    if (wantMtime) {
      bits.push(FATTR4_TIME_MODIFY_SET);
    }
    return bits;
  }

  /**
   * A uid or gid as the `owner`/`owner_group` string to put on the wire (§5.9).
   *
   * Without an ID map this is the numeric form and nothing else — "owner and
   * group strings that consist of decimal numeric values with no leading zeros
   * can be given a special interpretation" — which is also what a map that has
   * no answer for this id falls back to, since §5.9 defines the unqualified
   * string as meaning exactly "no translation was available at the sender".
   * A name that came back without an `@` is qualified with the configured
   * domain, because a bare name is that "no translation" signal and would be
   * read as one by the client.
   */
  #ownerName(id: number, group: boolean): string {
    const name = this.#idmap?.nameOf?.(id, group);
    if (name === undefined || name.length === 0) {
      return numericOwner(id);
    }
    const domain = this.#idmap?.domain;
    return name.includes("@") || domain === undefined || domain.length === 0
      ? name
      : `${name}@${domain}`;
  }

  /**
   * A `utf8str_mixed` owner as a uid or gid (§5.9).
   *
   * §5.9's numeric form first, then the ID map, then `NFS4ERR_BADOWNER` —
   * "servers that do not provide support for all possible values of the owner
   * and owner_group attributes SHOULD return an error (NFS4ERR_BADOWNER) when a
   * string is presented that has no translation". §15.2 lists that status for
   * all three operations that can carry an owner in: SETATTR, CREATE and OPEN.
   *
   * With a domain configured, the string must be qualified with *that* domain
   * and nothing else, and the suffix is stripped before the map is asked — so a
   * map is written against local names. Both halves of that are §5.9's: "a
   * server may treat other domains as having no valid translations", and an
   * unqualified string is by definition untranslatable, since "the absence of
   * the @ from the owner or owner_group attribute signifies that no translation
   * was available at the sender and that the receiver of the attribute should
   * not use that string as a basis for translation into its own internal
   * format". With no domain configured there is nothing to check a suffix
   * against, so the string goes to the map exactly as it arrived and the map is
   * the whole policy.
   *
   * The numeric form is accepted even when the map could name the same id,
   * where §5.9 has a SHOULD the other way ("a server SHOULD return an
   * NFS4ERR_BADOWNER error when there is a valid translation for the user or
   * owner designated in this way", so that a client cannot bypass translation
   * by sending numbers). That is deliberate: this server's own GETATTR answers
   * with numbers whenever the map has nothing to say, so refusing them coming
   * back would refuse a client that is echoing what it was told.
   */
  #ownerId(owner: string, group: boolean): number {
    const numeric = parseNumericOwner(owner);
    if (numeric !== undefined) {
      return numeric;
    }
    const domain = this.#idmap?.domain;
    let name = owner;
    if (domain !== undefined && domain.length > 0) {
      const at = owner.lastIndexOf("@");
      if (at < 0 || owner.slice(at + 1) !== domain) {
        throw new Nfs4StatusError(NFS4ERR_BADOWNER, `owner '${owner}' is not in the served domain`);
      }
      name = owner.slice(0, at);
    }
    const id = this.#idmap?.idOf?.(name, group);
    if (id === undefined) {
      throw new Nfs4StatusError(NFS4ERR_BADOWNER, `owner '${owner}' has no translation`);
    }
    return id;
  }

  /**
   * Prefer the `AT_SYMLINK_NOFOLLOW` form of a metadata call.
   *
   * A file handle names an object, and that object can be a symlink — the
   * client resolves symlinks itself, so anything that reaches the server is
   * already the final component. Following it here would stamp the target
   * instead.
   */
  async #nofollow<T>(preferred: () => Promise<T>, following: () => Promise<T>): Promise<T> {
    try {
      return await preferred();
    } catch (error) {
      if ((error as { code?: string }).code === "ENOSYS") {
        return following();
      }
      throw error;
    }
  }

  /** A 64-bit wire offset as a `number`, or `NFS4ERR_INVAL` when it cannot be one. */
  #offset(value: bigint): number {
    if (value > MAX_OFFSET) {
      throw new Nfs4StatusError(NFS4ERR_INVAL, `offset ${value} is out of range`);
    }
    return Number(value);
  }

  /**
   * ACCESS (§18.1).
   *
   * `supported` is which of the requested bits this server could evaluate and
   * `access` which of those it grants, and §18.1.3 bounds both: neither "MUST
   * NOT contain more values than originally set in the request's access field",
   * and access must not exceed supported. A bit outside `ACCESS4_ALL` is one
   * this server cannot evaluate, so it is absent from both.
   */
  async #access(args: Access4args, cursor: Cursor): Promise<Access4res> {
    const stats = await this.#statOf(this.#pathOfCurrent(cursor));
    const supported = args.access & ACCESS4_ALL;
    return {
      status: NFS4_OK,
      supported,
      access: supported & accessBits4(allowedAccess(stats, cursor.creds)),
    };
  }

  async #readlink(cursor: Cursor): Promise<Readlink4res> {
    const link = await this.driver.readlink(this.#pathOfCurrent(cursor));
    return { status: NFS4_OK, link };
  }

  /**
   * COMMIT (§18.3).
   *
   * There is never anything outstanding to flush: this server has no write
   * cache, so every WRITE it acknowledges is already as durable as the driver
   * can make it and answers `FILE_SYNC4`. Clients send COMMIT anyway — on
   * close, on `fsync`, at the end of a writeback run — so it succeeds, and the
   * current filehandle is resolved first because a COMMIT on a stale handle is
   * still an error the client needs to see.
   */
  async #commit(cursor: Cursor): Promise<Commit4res> {
    const path = this.#pathOfCurrent(cursor);
    await this.#statOf(path);
    return { status: NFS4_OK, writeverf: this.writeVerifier };
  }

  // -------------------------------------------------------------------------
  // VERIFY / NVERIFY (RFC 8881 §18.31, §18.15)
  // -------------------------------------------------------------------------

  /**
   * Compare an object's attributes with the ones the client assumed.
   *
   * The comparison is over encoded bytes, and deliberately: both sides go
   * through `./attr.ts`'s one encoder with the same mask, so "the same value"
   * means the same thing it means on the wire, and a type this file never has
   * to unpack cannot be compared wrongly.
   *
   * The two refusals are §18.31.4's, and they are different errors: a
   * RECOMMENDED attribute this server does not support is
   * `NFS4ERR_ATTRNOTSUPP`, while "when the attribute rdattr_error or any
   * set-only attribute (e.g., time_modify_set) is specified, the error
   * NFS4ERR_INVAL is returned".
   */
  async #verify(args: Verify4args, cursor: Cursor, verify: boolean): Promise<Status4res> {
    const path = this.#pathOfCurrent(cursor);
    const attr = args.objAttributes;
    if (
      !bitmapIsEmpty(bitmapIntersection(attr.attrmask, SET_ONLY_ATTRS)) ||
      bitmapHas(attr.attrmask, FATTR4_RDATTR_ERROR)
    ) {
      return { status: NFS4ERR_INVAL };
    }
    if (
      attr.unsupported.length > 0 ||
      !bitmapIsEmpty(bitmapDifference(attr.attrmask, this.#supportedAttrs()))
    ) {
      return { status: NFS4ERR_ATTRNOTSUPP };
    }
    const values = await this.#valuesFor(path, attr.attrmask);
    const getable = this.#getableAttrs();
    const ours = new XdrWriter(256);
    encodeFattr(ours, attr.attrmask, values, getable);
    const theirs = new XdrWriter(256);
    encodeFattr(theirs, attr.attrmask, attr.values, getable);
    const same = sameBytes(ours.bytes(), theirs.bytes());
    if (verify) {
      // §18.31.3: "If any of the attributes do not match, then the error
      // NFS4ERR_NOT_SAME must be returned."
      return { status: same ? NFS4_OK : NFS4ERR_NOT_SAME };
    }
    // §18.15.3, the mirror image: NVERIFY succeeds when they differ.
    return { status: same ? NFS4ERR_SAME : NFS4_OK };
  }

  // -------------------------------------------------------------------------
  // CREATE / REMOVE / RENAME / LINK
  // -------------------------------------------------------------------------

  /** The `change` attribute of a directory, or `0` if it cannot be read. */
  async #changeOf(path: string): Promise<bigint> {
    try {
      return changeOf(await this.#statOf(path));
    } catch {
      return 0n;
    }
  }

  /**
   * `change_info4` for a directory the operation just changed.
   *
   * `atomic` is always FALSE, and honestly so: the two `change` values come
   * from two separate driver calls either side of the operation, so they were
   * not "obtained atomically with respect to" it in §3.3.8's sense. Claiming
   * otherwise would let a client trust a cache it should re-read.
   */
  #cinfo(before: bigint, after: bigint): ChangeInfo4 {
    return { atomic: false, before, after };
  }

  /**
   * Give a newly created object to whoever asked for it.
   *
   * §18.4.3 puts the requirement plainly — a server whose file system requires
   * an owner "MUST derive the owner ... typically ... from the principal
   * indicated in the RPC credentials of the call". Without it a file created by
   * uid 1000 comes back owned by the server and then fails every permission
   * check its own creator makes. Quiet when the driver cannot express
   * ownership, which is not the same as broken — that, and the skip when the
   * caller *is* the server, are in `claimNewEntry`.
   *
   * The *group* is not derived from the principal alone: §18.4.3's "MUST
   * derive" is about the owner, and the group a set-gid parent hands down is
   * the parent's (`../../ownership.ts` has the rule and where it comes from).
   * `parent` is therefore threaded in from the `stat` the caller already took —
   * CREATE reads the parent to check it is a directory, OPEN to build its
   * `change_info4` — so the rule adds no round trip of its own. A new directory
   * taking the set-gid bit does cost an `lstat` and a `chmod`, which is the one
   * part of it that cannot be folded into the create: the mode the create asked
   * for is not the mode it got (`../../ownership.ts` on the umask), so the bit
   * goes on top of what the driver actually made.
   */
  async #claim(path: string, creds: RpcCredentials, entry: NewEntry): Promise<void> {
    if (this.options.claimOwnership === false) {
      return;
    }
    await claimNewEntry(this.driver, path, newEntryOwnership(creds, entry));
  }

  /**
   * CREATE (§18.4): everything but a regular file.
   *
   * "The OPEN operation MUST be used to create a regular file or a named
   * attribute", so `NF4REG` — and the two named-attribute types with it —
   * selects `createtype4`'s default arm and is `NFS4ERR_BADTYPE`, not an
   * oversight. The types the driver interface cannot express go through the
   * `mountx.mknod` extension, and a type this driver cannot make — a device
   * node with no extension behind it, a symlink on a driver with none — is
   * `NFS4ERR_BADTYPE` rather than a pretence: §15.1.4.1 defines that status as
   * covering "because the type is not supported by the server", which is the
   * capability answer stated in the protocol's own words.
   *
   * On success the new object becomes the current filehandle.
   */
  async #create(args: Create4args, cursor: Cursor): Promise<Create4res> {
    const dir = this.#pathOfCurrent(cursor);
    const parent = await this.#statOf(dir);
    if ((parent.mode & S_IFMT) !== S_IFDIR) {
      return { status: NFS4ERR_NOTDIR, cinfo: undefined, attrset: undefined };
    }
    const path = joinPath(dir, this.#checkName(args.objname));
    const type = args.objtype.type;
    if (type === NF4REG || type === NF4ATTRDIR || type === NF4NAMEDATTR) {
      return { status: NFS4ERR_BADTYPE, cinfo: undefined, attrset: undefined };
    }
    this.#settableOrRefuse(args.createattrs);
    const before = changeOf(parent);
    const mode = (args.createattrs.values.mode ?? 0o777) & 0o7777;

    switch (type) {
      case NF4DIR: {
        await this.driver.mkdir(path, { mode });
        break;
      }
      case NF4LNK: {
        if (!this.driver.capabilities.symlinks) {
          // §15.1.4.1 defines `NFS4ERR_BADTYPE` as covering exactly this: "an
          // attempt was made to create an object with an inappropriate type
          // specified to CREATE ... because the type is not supported by the
          // server". §15.2's CREATE row lists it, and does not list
          // `NFS4ERR_NOTSUPP`.
          return { status: NFS4ERR_BADTYPE, cinfo: undefined, attrset: undefined };
        }
        await this.driver.symlink(args.objtype.linkdata ?? "", path);
        break;
      }
      case NF4BLK:
      case NF4CHR:
      case NF4FIFO:
      case NF4SOCK: {
        const mknod = this.driver.mountx?.mknod;
        if (mknod === undefined) {
          // §15.1.4.1 again: a type this server cannot create is BADTYPE by
          // definition, whatever the reason it cannot.
          return { status: NFS4ERR_BADTYPE, cinfo: undefined, attrset: undefined };
        }
        const dev = args.objtype.devdata ?? { major: 0, minor: 0 };
        // The same 8-bit split `./attr.ts` uses to take a `rawdev` apart.
        await mknod.call(
          this.driver.mountx,
          path,
          mode | modeBitsOfFtype(type),
          ((dev.major << 8) | (dev.minor & 0xff)) >>> 0,
        );
        break;
      }
      /* v8 ignore next 3 -- every `nfs_ftype4` is covered above; an unnamed one
         was already refused as NFS4ERR_BADTYPE. */
      default: {
        return { status: NFS4ERR_BADTYPE, cinfo: undefined, attrset: undefined };
      }
    }

    this.#invalidate(dir);
    // A symlink's mode is 0o777 and not the client's to choose — `createattrs`
    // never reached `symlink` — so the mode named here is the one the object
    // really has.
    await this.#claim(path, cursor.creds, {
      parent,
      directory: type === NF4DIR,
      mode: type === NF4LNK ? 0o777 : mode,
    });
    // `mkdir` already took the mode; a symlink has none to take. `size` is not
    // a writable attribute of any of these types, so it is neither applied nor
    // reported (§18.4.3, "any writable attribute valid for the object type").
    const applied = await this.#applyAttrs(
      path,
      { ...args.createattrs, values: { ...args.createattrs.values, mode: undefined } },
      { skipSize: true, symlink: type === NF4LNK },
    );
    // `mkdir` and `mknod` both took the mode as an argument, so it *was* set
    // even though `#applyAttrs` never saw it; a symlink has no mode to set and
    // must not claim one.
    const bits =
      type !== NF4LNK && args.createattrs.values.mode !== undefined
        ? [FATTR4_MODE, ...applied.bits]
        : applied.bits;
    const { entry } = await this.#bind(path);
    cursor.currentFh = this.handles.encode(entry);
    cursor.currentStateid = zeroStateid();
    return {
      status: applied.status,
      cinfo: this.#cinfo(before, await this.#changeOf(dir)),
      attrset: bitmapOf(bits),
    };
  }

  /**
   * REMOVE (§18.25): NFSv3's REMOVE and RMDIR in one operation.
   *
   * "The type of the target decides, not the opcode" — so the entry is stat'ed
   * to pick between `rmdir` and `unlink`, and a non-empty directory reaches the
   * client as `NFS4ERR_NOTEMPTY` through the driver's own `ENOTEMPTY`.
   */
  async #remove(args: Remove4args, cursor: Cursor): Promise<Remove4res> {
    const dir = this.#pathOfCurrent(cursor);
    const path = joinPath(dir, this.#checkName(args.target));
    const before = await this.#changeOf(dir);
    const stats = await this.#statOf(path);
    const directory = (stats.mode & S_IFMT) === S_IFDIR;
    await (directory ? this.driver.rmdir(path) : this.driver.unlink(path));
    // The parent lost a name; a removed *directory* also stops being a thing
    // whose own cached listing means anything. See `../handles.ts`.
    this.#invalidate(dir);
    // The handle stops resolving: a client still holding it gets
    // `NFS4ERR_STALE`, which is what this server has instead of an
    // unlinked-but-open file.
    const entry = this.handles.unbind(path);
    if (entry !== undefined && directory) {
      this.#snapshots.delete(entry.id);
    }
    // Whatever appears at this name next is a different object, and must not
    // inherit the promise made about this one.
    this.#exclusives.forget(path);
    return { status: NFS4_OK, cinfo: this.#cinfo(before, await this.#changeOf(dir)) };
  }

  /**
   * RENAME (§18.26). The one operation that holds the writer lock.
   *
   * The source directory is the **saved** filehandle and the target the current
   * one, and the two `change_info4`s are in that order too — source first.
   */
  async #rename(args: Rename4args, cursor: Cursor): Promise<Rename4res> {
    const fromDir = this.#pathOfSaved(cursor);
    const toDir = this.#pathOfCurrent(cursor);
    const from = joinPath(fromDir, this.#checkName(args.oldname));
    const to = joinPath(toDir, this.#checkName(args.newname));
    const sourceBefore = await this.#changeOf(fromDir);
    const targetBefore = fromDir === toDir ? sourceBefore : await this.#changeOf(toDir);
    await this.driver.rename(from, to);
    // Handles are identity-keyed, so this is bookkeeping for the *paths*: the
    // client goes on using the handle it already has, for the object and for
    // everything below it if this was a directory.
    this.handles.remap(from, to);
    // The verifiers are keyed by *path*, and both of these paths now name
    // something else: `from` nothing, `to` the object that moved onto it (over
    // whatever was there). Neither promise survives the move.
    this.#exclusives.forget(from);
    this.#exclusives.forget(to);
    // Exactly two directories changed their names: the one that lost `from` and
    // the one that gained `to`. A directory that *moved* keeps its own snapshot
    // — same contents, and `remap` kept it the same entry — and no unrelated
    // directory is touched at all. See `../handles.ts`.
    this.#invalidate(fromDir);
    this.#invalidate(toDir);
    const sourceAfter = await this.#changeOf(fromDir);
    return {
      status: NFS4_OK,
      sourceCinfo: this.#cinfo(sourceBefore, sourceAfter),
      targetCinfo: this.#cinfo(
        targetBefore,
        fromDir === toDir ? sourceAfter : await this.#changeOf(toDir),
      ),
    };
  }

  /**
   * LINK (§18.9): the **saved** filehandle is the object, the current one the
   * directory to link it into.
   */
  async #link(args: Link4args, cursor: Cursor): Promise<Link4res> {
    const file = this.#pathOfSaved(cursor);
    const dir = this.#pathOfCurrent(cursor);
    const path = joinPath(dir, this.#checkName(args.newname));
    const before = await this.#changeOf(dir);
    await this.driver.link(file, path);
    this.#invalidate(dir);
    // Same object, one more name: `bind` finds the existing entry by identity,
    // so the client's handle for the original keeps working.
    await this.#bind(path);
    return { status: NFS4_OK, cinfo: this.#cinfo(before, await this.#changeOf(dir)) };
  }

  // -------------------------------------------------------------------------
  // READDIR (RFC 8881 §18.23)
  // -------------------------------------------------------------------------

  /**
   * The page of a directory a cookie names.
   *
   * The snapshot machinery is `../handles.ts`'s, shared with v3, and so is the
   * reasoning: a cookie has to still mean the same entry seconds later and
   * possibly on another connection, so the listing is frozen and the
   * `cookieverf` says *which* freeze. Two things are v4's own — cookies start
   * at {@link COOKIE_BASE}, and a verifier that no longer matches is
   * `NFS4ERR_NOT_SAME` rather than v3's `NFS3ERR_BAD_COOKIE` (§18.23.3: "If the
   * server determines that the cookieverf is no longer valid for the directory,
   * the error NFS4ERR_NOT_SAME must be returned").
   */
  async #page(
    entry: HandleEntry,
    path: string,
    cookie: bigint,
    cookieverf: Uint8Array,
  ): Promise<{ names: readonly string[]; verf: Uint8Array; from: number }> {
    if (cookie === 0n) {
      const entries = await this.driver.readdir(path, { withFileTypes: true });
      const snapshot = this.#snapshots.set(
        entry.id,
        entries.map((dirent) => dirent.name),
      );
      return { names: snapshot.names, verf: snapshot.cookieverf, from: 0 };
    }
    if (cookie < COOKIE_BASE) {
      // Cookies 1 and 2 are reserved for the `.` and `..` a client splices in
      // locally (§18.23.3); this server never issued one, so it cannot resume.
      throw new Nfs4StatusError(NFS4ERR_BAD_COOKIE, `cookie ${cookie} is reserved`);
    }
    let snapshot = this.#snapshots.get(entry.id);
    if (snapshot === undefined || !sameVerifier(snapshot.cookieverf, cookieverf)) {
      // Evicted, or from before something changed. Re-listing costs a driver
      // call and rescues every client whose directory simply has not moved.
      const entries = await this.driver.readdir(path, { withFileTypes: true });
      const names = entries.map((dirent) => dirent.name);
      if (!sameVerifier(cookieVerifier(names), cookieverf)) {
        throw new Nfs4StatusError(
          NFS4ERR_NOT_SAME,
          "the directory changed and the cookieverf no longer matches",
        );
      }
      snapshot = this.#snapshots.set(entry.id, names);
    }
    const from = Number(cookie - COOKIE_BASE) + 1;
    if (from > snapshot.names.length) {
      throw new Nfs4StatusError(NFS4ERR_BAD_COOKIE, `cookie ${cookie} is past the end`);
    }
    return { names: snapshot.names, verf: snapshot.cookieverf, from };
  }

  /**
   * READDIR (§18.23): one operation where NFSv3 had two.
   *
   * `attr_request` is the whole difference — an empty bitmap is a plain
   * readdir, a populated one is READDIRPLUS — and both budgets are the
   * client's: `dircount` bounds the names and cookies alone, `maxcount` the
   * whole `READDIR4resok`. Overrunning either is a reply the client throws
   * away, and fitting no entry at all inside `maxcount` is `NFS4ERR_TOOSMALL`,
   * which §18.23.3 makes a MUST.
   *
   * A per-entry failure is `rdattr_error`, and only if the client asked for it:
   * "Obviously, the client must request the fattr4_rdattr_error attribute for
   * this method to work properly. If the client does not request the attribute,
   * the server has no choice but to return failure for the entire READDIR
   * operation."
   */
  async #readdir(args: Readdir4args, cursor: Cursor): Promise<Readdir4res> {
    const handle = this.#requireCurrent(cursor);
    const dirEntry = this.handles.decode(handle);
    const path = this.handles.pathOf(dirEntry);
    if (!bitmapIsEmpty(bitmapIntersection(args.attrRequest, SET_ONLY_ATTRS))) {
      // §5.5 again: a set-only attribute cannot be retrieved, here either.
      return {
        status: NFS4ERR_INVAL,
        cookieverf: args.cookieverf,
        reply: { entries: [], eof: false },
      };
    }
    const page = await this.#page(dirEntry, path, args.cookie, args.cookieverf);
    const getable = this.#getableAttrs();
    const attrmask = bitmapIntersection(args.attrRequest, getable);
    const wantsRdattrError = bitmapHas(args.attrRequest, FATTR4_RDATTR_ERROR);

    // The two budgets are not the same kind of thing, and treating them alike
    // is the classic way to answer a legal request with nothing.
    //
    // `maxcount` is the hard one: it "represents the maximum total size of all
    // of the data being returned within the READDIR4resok structure and
    // includes the XDR overhead", and it is the *only* one `NFS4ERR_TOOSMALL`
    // hangs off — "If the server is unable to return a single directory entry
    // within the maxcount limit, the error NFS4ERR_TOOSMALL MUST be returned"
    // (§18.23.3). So the reply overhead — opcode, status, cookieverf, the list
    // terminator and eof — is reserved out of this one, generously, because
    // underestimating it is a reply the client rejects.
    //
    // `dircount` is "a hint of the maximum number of bytes of directory
    // information", covering the names and cookies alone (§18.23.3). It carries
    // no reply overhead, so nothing is reserved out of it; zero means *no hint
    // at all* — "If dircount is zero, the server bounds the reply's size based
    // on the request's maxcount field" (§18.23.4) — and a hint never costs a
    // client the whole page, so it is only consulted once an entry is already
    // in hand.
    const dirBudget = args.dircount;
    const maxBudget = Math.max(0, Math.min(args.maxcount, this.#maxread()) - 128);
    // Asked once for the whole page: the six `statfs` attributes describe the
    // filesystem every entry is on, not the entry.
    const fsValues = await this.#statfsValues(path, attrmask);
    // One scratch writer for the page, not one per entry. Each entry's encoded
    // size is the *delta* it adds to this writer, so measuring costs a single
    // geometrically-grown buffer instead of a 256-byte allocation per name —
    // and the bytes are thrown away either way, because the reply is encoded
    // from `entries` once the page is settled.
    const scratch = new XdrWriter(Math.min(maxBudget, 8192));
    const entries: Entry4[] = [];
    let dirUsed = 0;
    let maxUsed = 0;
    let index = page.from;
    // Entries are fetched a batch at a time. They cannot be chosen from the
    // names alone the way `../v3/session.ts`'s can — `maxcount` counts encoded
    // attributes, so an entry has to be *fetched* before it is known whether it
    // fits — but fetching them one at a time is one driver round trip per name
    // with nothing overlapping. So: fetch a batch concurrently, then run the
    // budget over it, and stop at the first entry that does not fit.
    //
    // How big a batch is the whole difficulty, because fetching an entry the
    // page has no room for is work thrown away *and* a handle-table entry
    // minted for a name that is never returned. Two bounds, and the batch takes
    // the smaller:
    //
    // - `floorRoom` needs no driver call at all: every entry costs its
    //   `dircount` size — which is a function of the name — plus at least
    //   `MIN_FATTR4_SIZE`. Walking the names with that floor can only
    //   over-count, and it is the only bound available for the **first** batch
    //   of a page, which is exactly where a fixed window would over-fetch the
    //   whole window against a small `maxcount`.
    // - the running average of the entries already measured, which is far
    //   tighter once there is anything to average.
    const floorRoom = (): number => {
      let count = 0;
      let dir = dirUsed;
      let max = maxUsed;
      // Capped at the window, because that is all the caller can use.
      for (let at = index; at < page.names.length && count < PAGE_CONCURRENCY; at++) {
        const dirSize = 4 + 8 + 4 + xdrAlign(stringByteLength(page.names[at]!));
        max += dirSize + MIN_FATTR4_SIZE;
        dir += dirSize;
        if (max > maxBudget || (dirBudget > 0 && dir > dirBudget)) {
          break;
        }
        count++;
      }
      // One over, because the entry that does *not* fit is what ends the page
      // and it has to be fetched to be measured. Landing exactly on the last
      // one that fits would cost an extra round trip to discover that.
      return count + 1;
    };
    while (index < page.names.length) {
      let room = floorRoom();
      if (entries.length > 0) {
        let average = Math.ceil(((maxBudget - maxUsed) * entries.length) / maxUsed);
        if (dirBudget > 0) {
          average = Math.min(
            average,
            Math.ceil(((dirBudget - dirUsed) * entries.length) / dirUsed),
          );
        }
        room = Math.min(room, Math.max(1, average) + 1);
      }
      const batch = page.names.slice(index, index + Math.min(PAGE_CONCURRENCY, room));
      const fetched = await mapPage(batch, (name) =>
        this.#entryAttrs(path, name, attrmask, wantsRdattrError, fsValues),
      );
      let accepted = 0;
      for (; accepted < fetched.length; accepted++) {
        const name = batch[accepted]!;
        const attrs = fetched[accepted]!;
        // `nextentry` bool, cookie, and the counted name: what §18.23.3 says
        // `dircount` measures ("the total length of the names of the directory
        // entries and the cookie value for these entries").
        const dirSize = 4 + 8 + 4 + xdrAlign(stringByteLength(name));
        const before = scratch.length;
        encodeFattr(scratch, attrs.attrmask, attrs.values, getable);
        const entrySize = dirSize + (scratch.length - before);
        if (maxUsed + entrySize > maxBudget) {
          // The hard limit. Breaking here with nothing in hand is the one case
          // that owes the client `NFS4ERR_TOOSMALL`.
          break;
        }
        if (entries.length > 0 && dirBudget > 0 && dirUsed + dirSize > dirBudget) {
          // The hint, and only ever after a first entry: a single name longer
          // than the whole hint still goes out when `maxcount` has room for it,
          // because a hint that could empty a page would not be one.
          break;
        }
        dirUsed += dirSize;
        maxUsed += entrySize;
        entries.push({ cookie: BigInt(index + accepted) + COOKIE_BASE, name, attrs });
      }
      index += accepted;
      if (accepted < batch.length) {
        break;
      }
    }
    if (entries.length === 0 && index < page.names.length) {
      return {
        status: NFS4ERR_TOOSMALL,
        cookieverf: page.verf,
        reply: { entries: [], eof: false },
      };
    }
    return {
      status: NFS4_OK,
      cookieverf: page.verf,
      reply: { entries, eof: index >= page.names.length },
    };
  }

  /**
   * One directory entry's attributes, with §18.23.3's per-entry failure rule.
   *
   * A stat that fails answers with `rdattr_error` alone when the client asked
   * for bit 11, and re-throws otherwise — which fails the whole READDIR, and is
   * what the RFC says a server has "no choice but" to do.
   */
  async #entryAttrs(
    dir: string,
    name: string,
    attrmask: Bitmap4,
    wantsRdattrError: boolean,
    fsValues: Fattr4Values,
  ): Promise<Fattr4> {
    const child = joinPath(dir, name);
    try {
      const values = await this.#valuesFor(child, attrmask, fsValues);
      if (wantsRdattrError) {
        values.rdattrError = NFS4_OK;
      }
      return { attrmask, values, unsupported: [] };
    } catch (error) {
      if (!wantsRdattrError) {
        throw error;
      }
      return {
        attrmask: bitmapOf([FATTR4_RDATTR_ERROR]),
        values: { rdattrError: statusOf(error) },
        unsupported: [],
      };
    }
  }

  // -------------------------------------------------------------------------
  // stateids, and the open state behind them (RFC 8881 §8.2, §9.1.2)
  // -------------------------------------------------------------------------

  /** The client ID the enclosing SEQUENCE belongs to. */
  #clientid(cursor: Cursor): bigint {
    /* v8 ignore next 4 -- unreachable: every operation that asks is one that
       needs a session, and a COMPOUND whose first operation is not SEQUENCE has
       already been answered with NFS4ERR_OP_NOT_IN_SESSION. */
    if (cursor.clientid === undefined) {
      throw new Nfs4StatusError(NFS4ERR_OP_NOT_IN_SESSION, "no SEQUENCE, so no client ID");
    }
    return cursor.clientid;
  }

  /**
   * The opaque `./state.ts` knows an object by.
   *
   * The handle table's identity, so two names for one file — a hard link, a
   * path reached twice — are one key, which is what §9.9's share reservations
   * need in order to coalesce at all.
   */
  #fileKey(entry: HandleEntry): string {
    return entry.id.toString(16);
  }

  /**
   * Hold the handle entry a `fileKey` names against LRU eviction, for as long
   * as `./state.ts` has state on that file.
   *
   * The key is hex of an entry id and nothing else, so it inverts — which is
   * the only reason this can be driven by the state table, which knows nothing
   * about handles. A key that is not one is ignored rather than refused: the
   * reclaim arm of {@link Nfs4Session.#open} passes `""` deliberately, having
   * no file to name, and a `FileState` is never created for it.
   *
   * Idempotent per key, and paired with {@link Nfs4Session.#unpinFile} through
   * `#pinnedFiles`, so an unpin can only ever release a pin this session took.
   */
  #pinFile(fileKey: string): void {
    const id = entryIdOf(fileKey);
    if (id === undefined || this.#pinnedFiles.has(fileKey)) {
      return;
    }
    this.#pinnedFiles.add(fileKey);
    this.handles.pin(id);
  }

  /** Release {@link Nfs4Session.#pinFile}'s pin, if this session took one. */
  #unpinFile(fileKey: string): void {
    if (!this.#pinnedFiles.delete(fileKey)) {
      return;
    }
    this.handles.unpin(entryIdOf(fileKey)!);
  }

  /** The current filehandle as the pair a stateful operation needs. */
  #target(cursor: Cursor): { path: string; fileKey: string; entry: HandleEntry } {
    const entry = this.handles.decode(this.#requireCurrent(cursor));
    return { path: this.handles.pathOf(entry), fileKey: this.#fileKey(entry), entry };
  }

  /**
   * The type check READ, WRITE, LOCK, LOCKT and LOCKU all owe.
   *
   * Five sections say it in the same three sentences (§18.22.3, §18.32.3,
   * §18.10.3, §18.11.3, §18.12.3), and OPEN — "OPEN - Open a Regular File" —
   * owes it too, on §15.2's row for it rather than on a sentence of its own:
   * "If the current filehandle is not an
   * ordinary file, an error will be returned to the client. In the case that
   * the current filehandle represents an object of type NF4DIR, NFS4ERR_ISDIR
   * is returned. If the current filehandle designates a symbolic link,
   * NFS4ERR_SYMLINK is returned. In all other cases, NFS4ERR_WRONG_TYPE is
   * returned."
   */
  #requireRegular(stats: StatsLike): void {
    const type = stats.mode & S_IFMT;
    if (type === S_IFREG) {
      return;
    }
    if (type === S_IFDIR) {
      throw new Nfs4StatusError(NFS4ERR_ISDIR, "the current filehandle is a directory");
    }
    if (type === S_IFLNK) {
      throw new Nfs4StatusError(NFS4ERR_SYMLINK, "the current filehandle is a symbolic link");
    }
    throw new Nfs4StatusError(NFS4ERR_WRONG_TYPE, "the current filehandle is not an ordinary file");
  }

  /**
   * Substitute the current stateid for `(seqid 1, other 0)` (§8.2.3,
   * §16.2.3.1.2).
   *
   * "The stateid passed to the operation in place of the special value has its
   * 'seqid' value set to zero, except when the current stateid is used by the
   * operation CLOSE or OPEN_DOWNGRADE" — which is what `keepSeqid` selects. A
   * COMPOUND that has returned no stateid, or whose last one was itself
   * special, is `NFS4ERR_BAD_STATEID`: §8.2.3 makes both a MUST, and Figure 6
   * is the second case drawn out.
   */
  #resolveStateid(stateid: Stateid4, cursor: Cursor, keepSeqid = false): Stateid4 {
    if (specialStateid(stateid) !== "current") {
      return stateid;
    }
    const current = cursor.currentStateid;
    if (specialStateid(current) !== "normal") {
      throw new Nfs4StatusError(
        NFS4ERR_BAD_STATEID,
        "the current stateid is not one this COMPOUND returned",
      );
    }
    return keepSeqid ? current : { seqid: 0, other: current.other };
  }

  /**
   * Validate an I/O stateid, and say which open state's driver handle to use.
   *
   * §9.1.2 is the whole rule, and it is not symmetric. For a WRITE — and for a
   * SETATTR that sets size, which "has the same locking requirements as a
   * corresponding WRITE" — "the server MUST verify that the access mode allows
   * writing and MUST return an NFS4ERR_OPENMODE error if it does not". For a
   * READ the check is a MAY, and this server takes it: enforcing it is what
   * lets the share-reservation check be skipped for an open stateid, since
   * "the existence of OPEN for OPEN4_SHARE_ACCESS_READ guarantees that no
   * conflicting share reservation can exist".
   *
   * The two special stateids that reach here name no open, so they are checked
   * against the reservations instead ({@link Nfs4State.shareDenies}), with one
   * asymmetry that is §8.2.3's: the all-ones stateid is a **READ** bypass —
   * "when used in READ, the server MAY grant access, even if access would
   * normally be denied" — while "when this value is used in WRITE or SETATTR,
   * it is treated like the anonymous value", which §18.32.3 restates as a MUST
   * NOT bypass.
   *
   * Answers the key of the driver handle to do the I/O through, or `undefined`
   * when the caller should open one of its own.
   */
  #ioStateid(
    stateid: Stateid4,
    cursor: Cursor,
    fileKey: string,
    write: boolean,
  ): string | undefined {
    const clientid = this.#clientid(cursor);
    const resolved = this.#resolveStateid(stateid, cursor);
    const checked = this.state.checkStateid({ clientid, stateid: resolved, fileKey });
    if (checked.status !== NFS4_OK) {
      throw new Nfs4StatusError(checked.status, "the stateid is not one this file has");
    }
    const wanted = write ? OPEN4_SHARE_ACCESS_WRITE : OPEN4_SHARE_ACCESS_READ;
    if (checked.kind === "open" || checked.kind === "lock") {
      if (((checked.access ?? 0) & wanted) === 0) {
        throw new Nfs4StatusError(
          NFS4ERR_OPENMODE,
          `the open does not allow ${write ? "writing" : "reading"}`,
        );
      }
      // A lock stateid borrows the handle of the open it was derived from
      // (§9.1.1): the bytes are the same file and the access mode is the
      // open's, so a second handle would be a second copy of one open.
      return checked.openStateid === undefined ? undefined : stateKey(checked.openStateid.other);
    }
    if (!(checked.kind === "bypass" && !write)) {
      const denied = this.state.shareDenies(fileKey, wanted, clientid);
      if (denied !== NFS4_OK) {
        throw new Nfs4StatusError(denied, "a share reservation denies this I/O");
      }
    }
    return undefined;
  }

  /** Do the I/O through the open state's handle, or through one opened for it. */
  async #io<T>(
    key: string | undefined,
    path: string,
    flags: number,
    fn: (handle: FileHandleLike) => Promise<T>,
  ): Promise<T> {
    const open = key === undefined ? undefined : this.#openHandles.get(key);
    return open === undefined ? this.#withFile(path, flags, fn) : fn(open.handle);
  }

  // -------------------------------------------------------------------------
  // OPEN (RFC 8881 §18.16) / OPEN_DOWNGRADE (§18.18) / CLOSE (§18.2)
  // -------------------------------------------------------------------------

  /**
   * OPEN (§18.16): the only way to create a regular file, and the only way to
   * get a stateid for one.
   *
   * Four of the seven claims are refused, and each with the status its own
   * facts produce rather than a blanket one — §15.2's OPEN row has no
   * `NFS4ERR_NOTSUPP` to give:
   *
   * - `CLAIM_PREVIOUS`, `CLAIM_DELEGATE_PREV` and `CLAIM_DELEG_PREV_FH` are
   *   reclaims of state from before a restart, and this server keeps none, so
   *   they go to `./state.ts` as reclaims and come back `NFS4ERR_NO_GRACE`
   *   (§15.1.9.3's "there is no active grace period" and "the client making the
   *   request has no current role in reclaiming locks", both true here).
   * - `CLAIM_DELEGATE_CUR` and `CLAIM_DELEG_CUR_FH` name a delegation stateid,
   *   and this server has never issued one, so the stateid is checked like any
   *   other and answers `NFS4ERR_BAD_STATEID`. A stateid that *does* exist but
   *   is an open rather than a delegation gets the same status, on §8.2.4's
   *   "valid in general but ... not appropriate to the context in which the
   *   stateid is used".
   *
   * Exclusive create is served, out of a table in memory that covers a retry
   * and not a restart — {@link Nfs4Session.#openCreateExclusive} below, and
   * `ExclusiveCreates` in `../util.ts` for what that does and does not promise.
   * §18.16.4 offers the other answer ("if the server cannot support exclusive
   * create semantics, possibly because of the requirement to commit the
   * verifier to stable storage, it should fail the OPEN request with the error
   * NFS4ERR_NOTSUPP") and this file would not have been able to give it: §15.2's
   * OPEN row and §15.4's `NFS4ERR_NOTSUPP` row — the two normative error
   * tables, agreeing from both directions — do not admit that status for OPEN.
   *
   * On success the opened file becomes the current filehandle ("upon success
   * ... the current filehandle is replaced by that of the created or existing
   * object") and the returned stateid becomes the current stateid.
   */
  async #open(args: Open4args, cursor: Cursor): Promise<Open4res> {
    const clientid = this.#clientid(cursor);
    const refused = (status: number): Open4res => ({
      status,
      stateid: undefined,
      cinfo: undefined,
      rflags: 0,
      attrset: undefined,
      delegation: undefined,
    });
    const claim = args.claim.claim;
    const create = args.openhow.opentype === OPEN4_CREATE;
    if (
      create &&
      claim !== CLAIM_NULL &&
      claim !== CLAIM_DELEGATE_CUR &&
      claim !== CLAIM_DELEGATE_PREV
    ) {
      // §18.16.3: "If opentype is OPEN4_CREATE, then the claim field ... MUST
      // be one of CLAIM_NULL, CLAIM_DELEGATE_CUR, or CLAIM_DELEGATE_PREV,
      // because these claim methods include a component of a file name."
      return refused(NFS4ERR_INVAL);
    }
    if (
      claim === CLAIM_PREVIOUS ||
      claim === CLAIM_DELEGATE_PREV ||
      claim === CLAIM_DELEG_PREV_FH
    ) {
      // The file is never resolved: `./state.ts` refuses every reclaim before
      // it looks at one, so naming it would be work done to be thrown away.
      return refused(
        this.state.open({
          clientid,
          owner: args.owner.owner,
          fileKey: "",
          shareAccess: args.shareAccess,
          shareDeny: args.shareDeny,
          reclaim: true,
        }).status,
      );
    }
    if (claim === CLAIM_DELEGATE_CUR || claim === CLAIM_DELEG_CUR_FH) {
      const stateid =
        claim === CLAIM_DELEGATE_CUR
          ? args.claim.delegateCurInfo!.delegateStateid
          : args.claim.ocDelegateStateid!;
      const checked = this.state.checkStateid({ clientid, stateid });
      return refused(checked.status === NFS4_OK ? NFS4ERR_BAD_STATEID : checked.status);
    }

    // CLAIM_NULL names the file inside the current directory; CLAIM_FH *is* the
    // file, which is what a Linux client sends to re-open one it already has.
    let dir: string | undefined;
    let before = 0n;
    let path: string;
    // Kept for `#openCreate`: a creating OPEN always names its file inside a
    // directory (the CLAIM_FH arm above is refused for one), and set-gid
    // inheritance is decided from the parent this already read.
    let parent: StatsLike | undefined;
    if (claim === CLAIM_FH) {
      path = this.#pathOfCurrent(cursor);
    } else {
      dir = this.#pathOfCurrent(cursor);
      parent = await this.#statOf(dir);
      if ((parent.mode & S_IFMT) !== S_IFDIR) {
        return refused(NFS4ERR_NOTDIR);
      }
      before = changeOf(parent);
      path = joinPath(dir, this.#checkName(args.claim.file ?? ""));
    }

    const attrset: number[] = [];
    if (create) {
      const refusal = await this.#openCreate(args, path, cursor, attrset, parent);
      if (refusal !== undefined) {
        return refused(refusal);
      }
      if (dir !== undefined) {
        // A creating OPEN may or may not have added a name — `UNCHECKED4` over
        // a file that already exists does not — and the rule in `../handles.ts`
        // is deliberately conservative about exactly this case.
        this.#invalidate(dir);
      }
    }

    const { entry, stats } = await this.#bind(path);
    this.#requireRegular(stats);
    const result = this.state.open({
      clientid,
      // §18.16.3, of the `clientid` inside `open_owner4`: "The client can set
      // the clientid field to any value and the server MUST ignore it.
      // Instead, the server MUST derive the client ID from the session ID of
      // the SEQUENCE operation of the COMPOUND request."
      owner: args.owner.owner,
      fileKey: this.#fileKey(entry),
      shareAccess: args.shareAccess,
      shareDeny: args.shareDeny,
    });
    if (result.status !== NFS4_OK) {
      return refused(result.status);
    }
    const stateid = result.stateid!;
    // The access the *state* now carries, which after an upgrade is the union
    // of this OPEN's and the earlier one's (§9.9).
    const access = this.state.checkStateid({ clientid, stateid, want: "open" }).access ?? 0;
    try {
      await this.#bindHandle(stateKey(stateid.other), path, access);
    } catch (error) {
      if (result.upgraded !== true) {
        // A stateid whose file could not be opened is state the client would
        // only find out about on its first READ. Undo it; an upgrade has no
        // clean undo (the earlier open's bits are already merged in) and keeps
        // the handle it had.
        this.state.close({ clientid, stateid });
      }
      throw error;
    }
    cursor.currentFh = this.handles.encode(entry);
    cursor.currentStateid = stateid;
    return {
      status: NFS4_OK,
      stateid,
      // "For the target directory, the server returns change_info4 information
      // in cinfo" — and CLAIM_FH has no target directory to describe.
      cinfo:
        dir === undefined ? this.#cinfo(0n, 0n) : this.#cinfo(before, await this.#changeOf(dir)),
      // §18.16.3 rules `OPEN4_RESULT_CONFIRM` out ("deprecated and MUST NOT be
      // returned by an NFSv4.1 server") and offers three others. Only
      // `OPEN4_RESULT_LOCKTYPE_POSIX` is true of this server: `./state.ts`
      // splits, merges, upgrades and downgrades byte ranges POSIX-style and
      // never answers `NFS4ERR_LOCK_RANGE` or `NFS4ERR_LOCK_NOTSUPP`.
      // `OPEN4_RESULT_PRESERVE_UNLINKED` would be a lie — a REMOVE here unbinds
      // the handle and the open file goes with it — and
      // `OPEN4_RESULT_MAY_NOTIFY_LOCK` promises a callback on a back channel
      // that does not exist.
      rflags: OPEN4_RESULT_LOCKTYPE_POSIX,
      attrset: bitmapOf(attrset),
      delegation: noDelegation(args.shareAccess),
    };
  }

  /**
   * The create half of an OPEN: `UNCHECKED4` and `GUARDED4` (§18.16.3), with
   * the two exclusive modes handed on to
   * {@link Nfs4Session.#openCreateExclusive}.
   *
   * Answers `undefined` when the file is there to be opened, or the status that
   * refuses the whole OPEN. `attrset` is filled with what was actually applied,
   * which is the honest version of "an attribute mask signifying which
   * attributes were successfully set for the object".
   *
   * Whether the file already existed is decided by `O_EXCL` rather than by a
   * `stat` first, so that GUARDED4's "the server checks for the presence of a
   * duplicate object by name before performing the create" is one driver call
   * and not a race. UNCHECKED4 over an existing file then does what §18.16.3
   * says and no more: "the attributes specified by createattrs are not used,
   * except that when createattrs specifies the size attribute with a size of
   * zero, the existing file is truncated".
   */
  async #openCreate(
    args: Open4args,
    path: string,
    cursor: Cursor,
    attrset: number[],
    parent: StatsLike | undefined,
  ): Promise<number | undefined> {
    const how = args.openhow.how!;
    if (how.mode === EXCLUSIVE4 || how.mode === EXCLUSIVE4_1) {
      return this.#openCreateExclusive(how, path, cursor, attrset, parent);
    }
    const attrs = how.createattrs!;
    this.#settableOrRefuse(attrs);
    const mode = (attrs.values.mode ?? 0o666) & 0o7777;
    const created = await this.#createFile(path, mode);
    if (!created) {
      if (how.mode === GUARDED4) {
        // "If a duplicate exists, NFS4ERR_EXIST is returned."
        return NFS4ERR_EXIST;
      }
      if (attrs.values.size === 0n) {
        await this.driver.truncate(path, 0);
        attrset.push(FATTR4_SIZE);
      }
      return undefined;
    }
    await this.#claim(path, cursor.creds, { parent, directory: false, mode });
    // The mode went in as `open`'s third argument, so `#applyAttrs` must not
    // see it — and must see everything else, size included: a create names the
    // initial state of a file that did not exist a moment ago.
    const applied = await this.#applyAttrs(path, {
      ...attrs,
      values: { ...attrs.values, mode: undefined },
    });
    if (applied.status !== NFS4_OK) {
      // `OPEN4res` has no arm for a partial success, so the bits that did land
      // cannot be reported alongside a failure the way SETATTR's can. The file
      // stays created, which is what §18.16.4's warning to client implementors
      // is about.
      return applied.status;
    }
    if (attrs.values.mode !== undefined) {
      attrset.push(FATTR4_MODE);
    }
    attrset.push(...applied.bits);
    return undefined;
  }

  /**
   * The other create half: `EXCLUSIVE4` and `EXCLUSIVE4_1` (§18.16.3).
   *
   * Both exist for one reason — a client cannot make a create idempotent by
   * itself, because a lost reply leaves it unable to tell "I created it" from
   * "someone else did". So it sends a verifier it made up, the server remembers
   * which verifier created which file, and the resend carrying that same
   * verifier is answered with the file it already made. A *different* verifier
   * on the same name is a second client, and that is the case that really is
   * `NFS4ERR_EXIST`.
   *
   * What "remembers" means — a bounded table in memory, so a retransmission is
   * covered and a restart is not — is stated in full on `ExclusiveCreates` in
   * `../util.ts`.
   *
   * The two modes differ only in what travels beside the verifier. `EXCLUSIVE4`
   * carries nothing else, so the file is created with the mode `UNCHECKED4`
   * uses when the client names none and §18.16.4's follow-up SETATTR sets the
   * rest. `EXCLUSIVE4_1` carries `creatverfattr`, whose `cva_attrs` are applied
   * and reported in `attrset` exactly as `createattrs` are on the other path —
   * and are checked against the same supported/settable sets, which is the
   * answer this server would give for `suppattr_exclcreat` (75) if it
   * advertised it: the verifier lives beside the file rather than *in* one of
   * its attributes, so no attribute is reserved and every settable one may be
   * named here. That attribute stays out of `SUPPORTED_ATTRS` (`./attr.ts`
   * says why), so a client sees the omission and sends what it would have sent
   * anyway.
   *
   * The `attrset` is remembered with the verifier, so the reply to a resend
   * carries the same set the lost one did rather than an empty one.
   *
   * §18.16.3's one refusal of `EXCLUSIVE4` — "if the client ID is
   * pNFS-enabled, or the session is persistent, the server MUST return
   * NFS4ERR_INVAL" — cannot arise: this server grants no `csa_flags` at all
   * (`./state.ts` on CREATE_SESSION), so no session is persistent, and there
   * is no pNFS here to enable. A check for it would be unreachable code
   * describing a state the server cannot enter.
   */
  async #openCreateExclusive(
    how: CreateHow4,
    path: string,
    cursor: Cursor,
    attrset: number[],
    parent: StatsLike | undefined,
  ): Promise<number | undefined> {
    const exclusive4 = how.mode === EXCLUSIVE4;
    const verifier = exclusive4 ? how.createverf! : how.createboth!.verf;
    const attrs = exclusive4 ? undefined : how.createboth!.attrs;
    if (attrs !== undefined) {
      this.#settableOrRefuse(attrs);
    }
    const mode = (attrs?.values.mode ?? 0o666) & 0o7777;
    // Recorded from inside the create, before it awaits anything else: the
    // duplicate these two modes exist for is a *retransmission*, sent because
    // the reply was lost, and it therefore arrives while the original is still
    // in flight. A verifier recorded after the `#claim` and `#applyAttrs`
    // below is one the duplicate looks for, does not find, and is answered
    // `NFS4ERR_EXIST` for, by the very create that succeeded. It goes in with
    // no `attrset`, and is rewritten with the real one further down — an
    // under-reported `attrset` is the case §18.16.4 already tells client
    // implementors to check for and follow with a SETATTR, whereas an `EXIST`
    // for one's own file is not recoverable at all.
    const created = await this.#createFile(path, mode, () => this.#exclusives.set(path, verifier));
    if (!created) {
      const remembered = this.#exclusives.match(path, verifier);
      if (remembered === undefined) {
        return NFS4ERR_EXIST;
      }
      // The duplicate of a request whose reply never arrived: same file, same
      // answer. The OPEN below it proceeds as it did the first time.
      attrset.push(...remembered.attrset);
      return undefined;
    }
    await this.#claim(path, cursor.creds, { parent, directory: false, mode });
    const bits: number[] = [];
    let status = NFS4_OK;
    if (attrs !== undefined) {
      // The mode went in as `open`'s third argument, so `#applyAttrs` must not
      // see it — and must see everything else, size included.
      const applied = await this.#applyAttrs(path, {
        ...attrs,
        values: { ...attrs.values, mode: undefined },
      });
      if (attrs.values.mode !== undefined) {
        bits.push(FATTR4_MODE);
      }
      bits.push(...applied.bits);
      status = applied.status;
    }
    // Re-recorded, now that there are bits to record, and still recorded when
    // an attribute failed to land: the file exists and this verifier is what
    // made it, so a resend must be recognised either way — and it is answered
    // with the bits that *did* land, which is the partial `attrset` §18.16.4
    // tells client implementors to check for.
    this.#exclusives.set(path, verifier, bits);
    attrset.push(...bits);
    return status === NFS4_OK ? undefined : status;
  }

  /**
   * Create a file, answering whether it was this call that created it.
   *
   * `onCreated` runs after the create wins and before the `close()`, i.e.
   * before this function's next `await` — the only place a concurrent
   * duplicate cannot already have overtaken. `#openCreateExclusive` records
   * its verifier there and says why.
   */
  async #createFile(path: string, mode: number, onCreated?: () => void): Promise<boolean> {
    let handle: FileHandleLike;
    try {
      handle = await this.driver.open(
        path,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        mode,
      );
    } catch (error) {
      if ((error as { code?: string }).code === "EEXIST") {
        return false;
      }
      throw error;
    }
    onCreated?.();
    await this.#close(handle);
    return true;
  }

  /**
   * OPEN_DOWNGRADE (§18.18): narrow what an open holds.
   *
   * The **state** narrows and the driver handle does not. Keeping the wider
   * handle open is a server-side detail with no protocol visibility — every
   * subsequent I/O is checked against the access bits `./state.ts` now carries,
   * so a downgraded-to-read-only open answers `NFS4ERR_OPENMODE` to a WRITE
   * whatever the descriptor underneath could do — and re-opening narrower would
   * spend a driver call to lose the one thing an open handle is for.
   */
  #openDowngrade(args: OpenDowngrade4args, cursor: Cursor): OpenDowngrade4res {
    const clientid = this.#clientid(cursor);
    const { fileKey } = this.#target(cursor);
    const stateid = this.#resolveStateid(args.openStateid, cursor, true);
    // The stateid has to name state on *this* file (§8.2.4); `openDowngrade`
    // itself takes no filehandle, so the tie is made here.
    const checked = this.state.checkStateid({ clientid, stateid, fileKey, want: "open" });
    if (checked.status !== NFS4_OK) {
      return { status: checked.status, openStateid: undefined };
    }
    const result = this.state.openDowngrade({
      clientid,
      stateid,
      shareAccess: args.shareAccess,
      shareDeny: args.shareDeny,
    });
    if (result.status !== NFS4_OK) {
      return { status: result.status, openStateid: undefined };
    }
    cursor.currentStateid = result.stateid!;
    return { status: NFS4_OK, openStateid: result.stateid };
  }

  /**
   * CLOSE (§18.2): release the share reservations one open stateid stands for.
   *
   * The driver handle is not closed here. `./state.ts` drops the open state and
   * the `onOpenReleased` hook queues the handle, which
   * {@link Nfs4Session.#execute} closes before the next operation runs — so
   * CLOSE, a revoked lease and a swept client all end a driver handle by the
   * same path, and there is only one of them to get right.
   *
   * `NFS4ERR_LOCKS_HELD` comes from the state table: "the server MUST return
   * failure if any locks would exist after the CLOSE".
   */
  #closeOp(args: Close4args, cursor: Cursor): Close4res {
    const clientid = this.#clientid(cursor);
    const { fileKey } = this.#target(cursor);
    // §18.2.3: "The argument seqid MAY have any value, and the server MUST
    // ignore seqid" — `args.seqid` is decoded and dropped on the floor.
    const stateid = this.#resolveStateid(args.openStateid, cursor, true);
    const checked = this.state.checkStateid({ clientid, stateid, fileKey, want: "open" });
    if (checked.status !== NFS4_OK) {
      return { status: checked.status, openStateid: undefined };
    }
    const result = this.state.close({ clientid, stateid });
    if (result.status !== NFS4_OK) {
      return { status: result.status, openStateid: undefined };
    }
    // §18.2.4: the returned stateid is deprecated and is deliberately the
    // invalid special one, "to help find any uses of this stateid by clients".
    // It is still a stateid the operation returned, so §16.2.3.1.2 makes it the
    // current one — and being special, it fails the next `(1, 0)` outright.
    cursor.currentStateid = result.stateid!;
    return { status: NFS4_OK, openStateid: result.stateid };
  }

  // -------------------------------------------------------------------------
  // READ (RFC 8881 §18.22) / WRITE (§18.32)
  // -------------------------------------------------------------------------

  /**
   * READ (§18.22).
   *
   * `eof` is computed against the size the file has *after* the read rather
   * than before it, because that is the question §18.22.3 asks — "if offset +
   * count is equal to the size of the file ... eof is returned as TRUE" — and a
   * concurrent truncate between the two would otherwise make the answer a
   * statement about a file that no longer exists. A read starting at or past
   * the end is `NFS4_OK` with no data and `eof` TRUE, and so is every read of
   * an empty file.
   */
  async #read(args: Read4args, cursor: Cursor): Promise<Read4res> {
    const { path, fileKey } = this.#target(cursor);
    this.#requireRegular(await this.#statOf(path));
    const key = this.#ioStateid(args.stateid, cursor, fileKey, false);
    const offset = this.#offset(args.offset);
    // "The server may choose to return fewer bytes than specified by the
    // client": the ceiling is the `maxread` this server advertises.
    const count = Math.min(args.count, this.#maxread());
    const buffer = new Uint8Array(count);
    const { bytesRead } = await this.#io(key, path, constants.O_RDONLY, (handle) =>
      handle.read(buffer, 0, count, offset),
    );
    const read = Math.max(0, bytesRead);
    const size = (await this.#statOf(path)).size;
    return {
      status: NFS4_OK,
      eof: offset + read >= size,
      data: buffer.subarray(0, read),
    };
  }

  /**
   * WRITE (§18.32).
   *
   * `committed` is always `FILE_SYNC4`, which Table 20 makes a legal answer to
   * all three `stable_how4` values and which this server can honestly give: a
   * driver's `write` resolves when the bytes are as durable as that driver can
   * make them, and there is no write cache in front of it. The same claim
   * `../v3/session.ts` makes, and the reason COMMIT here has nothing to do.
   */
  async #write(args: Write4args, cursor: Cursor): Promise<Write4res> {
    const { path, fileKey } = this.#target(cursor);
    this.#requireRegular(await this.#statOf(path));
    const key = this.#ioStateid(args.stateid, cursor, fileKey, true);
    const offset = this.#offset(args.offset);
    // "The server MAY write fewer bytes than requested by the client", which is
    // what a payload past the advertised `maxwrite` gets — the count in the
    // reply tells the client where to resume.
    const length = Math.min(args.data.byteLength, this.#maxwrite());
    const { bytesWritten } = await this.#io(key, path, constants.O_WRONLY, (handle) =>
      handle.write(args.data, 0, length, offset),
    );
    return {
      status: NFS4_OK,
      count: bytesWritten,
      committed: FILE_SYNC4,
      writeverf: this.writeVerifier,
    };
  }

  // -------------------------------------------------------------------------
  // LOCK (RFC 8881 §18.10) / LOCKT (§18.11) / LOCKU (§18.12)
  // -------------------------------------------------------------------------

  /**
   * LOCK (§18.10): take a byte range, or learn who holds it.
   *
   * Thin over `./state.ts`, which owns the range arithmetic, the conflict rule
   * and the reclaim refusal. What this file adds is the three things the state
   * table cannot know: which file the current filehandle is, that it is an
   * ordinary one, and what the `locker4` union's two arms mean once the fields
   * §18.10.3 orders the server to ignore have been dropped — the open-owner's
   * `clientid` and all three v4.0-era seqids.
   *
   * A denial carries `LOCK4denied`, whose `owner.clientid` is "the actual
   * client associated with the conflicting lock, whether this is the client ID
   * associated with the current session or a different one"; `./state.ts`
   * fills it in from the holder's own record and it is written out verbatim.
   */
  async #lockOp(args: Lock4args, cursor: Cursor): Promise<Lock4res> {
    const clientid = this.#clientid(cursor);
    const { path, fileKey } = this.#target(cursor);
    this.#requireRegular(await this.#statOf(path));
    const request: LockRequest = {
      clientid,
      fileKey,
      locktype: args.locktype,
      offset: args.offset,
      length: args.length,
      reclaim: args.reclaim,
    };
    if (args.locker.newLockOwner) {
      const arm = args.locker.openOwner!;
      request.openStateid = this.#resolveStateid(arm.openStateid, cursor);
      request.lockOwner = arm.lockOwner.owner;
    } else {
      request.lockStateid = this.#resolveStateid(args.locker.lockOwner!.lockStateid, cursor);
    }
    const result = this.state.lock(request);
    if (result.status === NFS4_OK) {
      cursor.currentStateid = result.stateid!;
    }
    return { status: result.status, lockStateid: result.stateid, denied: result.denied };
  }

  /** LOCKT (§18.11): would a lock be granted? Nothing is taken and nothing is returned but the answer. */
  async #lockt(args: Lockt4args, cursor: Cursor): Promise<Lockt4res> {
    const clientid = this.#clientid(cursor);
    const { path, fileKey } = this.#target(cursor);
    this.#requireRegular(await this.#statOf(path));
    const result = this.state.lockt({
      clientid,
      fileKey,
      locktype: args.locktype,
      offset: args.offset,
      length: args.length,
      // §18.11.3: the `clientid` beside it "MAY be set to any value by the
      // client and MUST be ignored by the server".
      owner: args.owner.owner,
    });
    return { status: result.status, denied: result.denied };
  }

  /** LOCKU (§18.12): release exactly the given range. */
  async #locku(args: Locku4args, cursor: Cursor): Promise<Locku4res> {
    const clientid = this.#clientid(cursor);
    const { path, fileKey } = this.#target(cursor);
    this.#requireRegular(await this.#statOf(path));
    const result = this.state.locku({
      clientid,
      fileKey,
      lockStateid: this.#resolveStateid(args.lockStateid, cursor),
      offset: args.offset,
      length: args.length,
    });
    if (result.status === NFS4_OK) {
      cursor.currentStateid = result.stateid!;
    }
    return { status: result.status, lockStateid: result.stateid };
  }

  // -------------------------------------------------------------------------
  // SECINFO (RFC 8881 §18.29) / SECINFO_NO_NAME (§18.45)
  // -------------------------------------------------------------------------

  /**
   * The flavors this server accepts, most preferred first.
   *
   * The same two the RPC dispatcher above will take, in the order §18.29.3 asks
   * for ("an order corresponding to the server's preferences"): `AUTH_SYS`
   * first because it at least carries a uid to answer ACCESS with, `AUTH_NONE`
   * second because it is still accepted. RPCSEC_GSS is out of scope, so no
   * `rpcsec_gss_info` triple is ever emitted.
   */
  #flavors(): Secinfo4res {
    return { status: NFS4_OK, flavors: [{ flavor: AUTH_SYS }, { flavor: AUTH_NONE }] };
  }

  /**
   * SECINFO (§18.29).
   *
   * "SECINFO should apply the same access methodology used for LOOKUP when
   * evaluating the name", so the name is resolved and a failure is reported the
   * way LOOKUP would report it. Then the cursor side effect, which is easy to
   * miss and is a 4.1 change: "On success, the current filehandle is consumed
   * ... and if the next operation after SECINFO tries to use the current
   * filehandle, that operation will fail with the status NFS4ERR_NOFILEHANDLE."
   */
  async #secinfo(args: Secinfo4args, cursor: Cursor): Promise<Secinfo4res> {
    const dir = this.#pathOfCurrent(cursor);
    await this.#bind(joinPath(dir, this.#checkName(args.name)));
    cursor.currentFh = undefined;
    cursor.currentStateid = zeroStateid();
    return this.#flavors();
  }

  /** SECINFO_NO_NAME (§18.45): the same answer about the current object or its parent. */
  async #secinfoNoName(args: SecinfoNoName4args, cursor: Cursor): Promise<Secinfo4res> {
    const path = this.#pathOfCurrent(cursor);
    if (args.style === SECINFO_STYLE4_PARENT) {
      if (path === "/") {
        // "If SECINFO_STYLE4_PARENT is specified and there is no parent
        // directory, SECINFO_NO_NAME MUST return NFS4ERR_NOENT."
        return { status: NFS4ERR_NOENT, flavors: [] };
      }
      await this.#bind(dirname(path));
    } else if (args.style === SECINFO_STYLE4_CURRENT_FH) {
      await this.#statOf(path);
    } else {
      return { status: NFS4ERR_INVAL, flavors: [] };
    }
    cursor.currentFh = undefined;
    cursor.currentStateid = zeroStateid();
    return this.#flavors();
  }

  // -------------------------------------------------------------------------
  // the session and client-ID operations, which `./state.ts` answers
  // -------------------------------------------------------------------------

  /**
   * EXCHANGE_ID (§18.35).
   *
   * `SP4_NONE` and nothing else. §18.35.3 has both of the other schemes require
   * the EXCHANGE_ID itself to arrive "with RPCSEC_GSS as the security flavor",
   * which the RPC dispatcher above has already refused with `AUTH_TOOWEAK` —
   * so a `spa_how` that reaches here at all is inconsistent with its own
   * credential, and `NFS4ERR_INVAL` is what §15.2's EXCHANGE_ID row offers for
   * that (it does **not** list `NFS4ERR_NOTSUPP`).
   */
  #exchangeId(args: ExchangeId4args): ExchangeId4res {
    const refused = (status: number): ExchangeId4res => ({
      status,
      clientid: 0n,
      sequenceid: 0,
      flags: 0,
      stateProtect: undefined,
      serverOwner: undefined,
      serverScope: new Uint8Array(0),
      serverImplId: [],
    });
    if (args.stateProtect.how !== SP4_NONE) {
      return refused(NFS4ERR_INVAL);
    }
    const result = this.state.exchangeId({
      ownerid: args.clientowner.ownerid,
      verifier: args.clientowner.verifier,
      flags: args.flags,
    });
    if (result.status !== NFS4_OK) {
      return refused(result.status);
    }
    return {
      status: NFS4_OK,
      clientid: result.clientid,
      sequenceid: result.sequenceid,
      flags: result.flags,
      stateProtect: { how: SP4_NONE },
      // One server, one endpoint, and no trunking to advertise: the major id is
      // this server's boot verifier, which is what makes two instances distinct
      // (§2.5).
      serverOwner: { minorId: 0n, majorId: this.handles.verifier.slice(0, 8) },
      serverScope: this.handles.verifier.slice(0, 8),
      serverImplId: [],
    };
  }

  /** CREATE_SESSION (§18.36), plus the `ca_maxoperations` this file has to remember. */
  #createSession(args: CreateSession4args): CreateSession4res {
    const result = this.state.createSession({
      clientid: args.clientid,
      sequence: args.sequence,
      flags: args.flags,
      foreChanAttrs: args.foreChanAttrs,
      backChanAttrs: args.backChanAttrs,
    });
    if (result.status === NFS4_OK && result.foreChanAttrs !== undefined) {
      this.#maxOpsBySession.set(sessionKey(result.sessionid), result.foreChanAttrs.maxoperations);
    }
    return {
      status: result.status,
      sessionid: result.sessionid,
      sequence: result.sequence,
      flags: result.flags,
      foreChanAttrs: result.foreChanAttrs,
      backChanAttrs: result.backChanAttrs,
    };
  }

  /**
   * DESTROY_SESSION (§18.37).
   *
   * A COMPOUND is allowed to destroy the very session it rides, as long as it
   * is the final operation. That is handled by *noting* it rather than by
   * unwinding: `./state.ts` has already dropped the slot table, so the reply
   * this compound is still building must not be cached into it, and
   * {@link Nfs4Session.#execute} checks the flag before handing bytes back.
   */
  #destroySession(args: DestroySession4args, cursor: Cursor): Status4res {
    const key = sessionKey(args.sessionid);
    const result = this.state.destroySession(args.sessionid);
    if (result.status === NFS4_OK) {
      this.#maxOpsBySession.delete(key);
      if (key === cursor.ownSession) {
        cursor.destroyedOwnSession = true;
      }
    }
    return result;
  }

  /** DESTROY_CLIENTID (§18.50): refused for the client the enclosing SEQUENCE belongs to. */
  #destroyClientid(args: DestroyClientid4args, cursor: Cursor): Status4res {
    return this.state.destroyClientid(args.clientid, { sessionClientid: cursor.clientid });
  }

  /**
   * BIND_CONN_TO_SESSION (§18.34).
   *
   * With `SP4_NONE` a client "is not required to use BIND_CONN_TO_SESSION to
   * associate the connection with the session, unless the client wishes to
   * associate the connection with the backchannel" — and this server has no
   * backchannel, because it grants no delegations and never sets
   * `CREATE_SESSION4_FLAG_CONN_BACK_CHAN`. So a fore-channel request is
   * acknowledged and a backchannel one is refused with `NFS4ERR_INVAL` rather
   * than answered with a `CDFS4_BACK` that would be a lie: §18.34.3 requires
   * `CDFC4_BACK` to be answered with `CDFS4_BACK`, and there is no such channel
   * to bind.
   */
  #bindConnToSession(args: BindConnToSession4args): BindConnToSession4res {
    const refused = (status: number): BindConnToSession4res => ({
      status,
      sessionid: args.sessionid,
      dir: 0,
      useConnInRdmaMode: false,
    });
    if (this.state.clientOfSession(args.sessionid) === undefined) {
      return refused(NFS4ERR_BADSESSION);
    }
    // A backchannel request (CDFC4_BACK, CDFC4_BACK_OR_BOTH) and a direction
    // that is not a `channel_dir_from_client4` at all land in the same place,
    // for different reasons that have the same answer.
    if (args.dir !== CDFC4_FORE && args.dir !== CDFC4_FORE_OR_BOTH) {
      return refused(NFS4ERR_INVAL);
    }
    return {
      status: NFS4_OK,
      sessionid: args.sessionid,
      // "If the client specified CDFC4_FORE, the server MUST return CDFS4_FORE.
      // ... If the client specified CDFC4_FORE_OR_BOTH, the server MUST return
      // CDFS4_FORE or CDFS4_BOTH." Both land on CDFS4_FORE here.
      dir: CDFS4_FORE,
      // No RDMA on a TCP socket.
      useConnInRdmaMode: false,
    };
  }

  /**
   * BACKCHANNEL_CTL (§18.33): there is no back channel to re-point.
   *
   * `NFS4ERR_NOTSUPP` is not among §15.2's valid errors for this operation, and
   * `NFS4ERR_INVAL` is — which is also the truthful one, since the arguments
   * name a callback program for a channel that was never created.
   */
  #backchannelCtl(_args: BackchannelCtl4args): Status4res {
    return { status: NFS4ERR_INVAL };
  }

  /** RECLAIM_COMPLETE (§18.51). There is nothing to reclaim; see `./state.ts`. */
  #reclaimComplete(args: ReclaimComplete4args, cursor: Cursor): Status4res {
    if (cursor.clientid === undefined) {
      /* v8 ignore next 2 -- unreachable: RECLAIM_COMPLETE is not session-less,
         so the compound already answered NFS4ERR_OP_NOT_IN_SESSION. */
      return { status: NFS4ERR_OP_NOT_IN_SESSION };
    }
    return this.state.reclaimComplete(cursor.clientid, args.oneFs);
  }

  /** TEST_STATEID (§18.48): the operation succeeds whatever the verdicts are. */
  #testStateid(args: TestStateid4args, cursor: Cursor): TestStateid4res {
    if (cursor.clientid === undefined) {
      /* v8 ignore next 2 -- as for RECLAIM_COMPLETE. */
      return { status: NFS4ERR_OP_NOT_IN_SESSION, statusCodes: [] };
    }
    return {
      status: NFS4_OK,
      statusCodes: this.state.testStateid(cursor.clientid, args.stateids),
    };
  }

  /** FREE_STATEID (§18.38): how a client acknowledges revoked state. */
  #freeStateid(args: FreeStateid4args, cursor: Cursor): Status4res {
    if (cursor.clientid === undefined) {
      /* v8 ignore next 2 -- as for RECLAIM_COMPLETE. */
      return { status: NFS4ERR_OP_NOT_IN_SESSION };
    }
    return this.state.freeStateid(cursor.clientid, args.stateid);
  }
}

/** Create an NFSv4.1 session over a driver. */
export function createNfs4Session(
  driver: FsDriver,
  options?: NfsSessionOptions,
  shared?: NfsSharedState,
): Nfs4Session {
  return new Nfs4Session(driver, options, shared);
}
