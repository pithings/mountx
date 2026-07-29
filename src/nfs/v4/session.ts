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
 * ## What this step implements
 *
 * Everything in the namespace: the filehandle cursor, LOOKUP/LOOKUPP, GETATTR,
 * SETATTR, ACCESS, READLINK, READDIR, CREATE, REMOVE, RENAME, LINK, COMMIT,
 * VERIFY/NVERIFY, SECINFO/SECINFO_NO_NAME, and the session and client-ID
 * operations that `./state.ts` answers.
 *
 * **OPEN, OPEN_DOWNGRADE, CLOSE, READ, WRITE, LOCK, LOCKT and LOCKU answer
 * `NFS4ERR_NOTSUPP`** and halt the compound. Their codecs exist — their
 * arguments are decoded in full, so the operations after them stay reachable in
 * principle — and only the handlers are pending; they arrive with the open and
 * lock state wiring. Every such site says so.
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

import { ERRNO_CODES, fsError } from "../../errors.ts";
import { createLoopback, type Loopback } from "../../harness.ts";
import { PathLock } from "../../lock.ts";
import { dirname, joinPath } from "../../path.ts";
import type { FsDriver, StatsLike, TimeLike } from "../../types.ts";
import { S_IFDIR, S_IFMT } from "../../types.ts";
import {
  cookieVerifier,
  DirectorySnapshots,
  FileHandleTable,
  type HandleEntry,
  sameVerifier,
} from "../handles.ts";
import {
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
  type RpcCall,
  type RpcCredentials,
} from "../rpc.ts";
import {
  type AccessRights,
  allowedAccess,
  MAX_OFFSET,
  modeBitsOfFtype,
  NAME_MAX,
  newSessionStats,
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
  NFS4_PROGRAM,
  NFS4_VERIFIER_SIZE,
  NFS4ERR_ATTRNOTSUPP,
  NFS4ERR_BAD_COOKIE,
  NFS4ERR_BADNAME,
  NFS4ERR_BADOWNER,
  NFS4ERR_BADSESSION,
  NFS4ERR_BADTYPE,
  NFS4ERR_BADXDR,
  NFS4ERR_INVAL,
  NFS4ERR_MINOR_VERS_MISMATCH,
  NFS4ERR_NOENT,
  NFS4ERR_NOFILEHANDLE,
  NFS4ERR_NOT_ONLY_OP,
  NFS4ERR_NOT_SAME,
  NFS4ERR_NOTDIR,
  NFS4ERR_NOTSUPP,
  NFS4ERR_OP_ILLEGAL,
  NFS4ERR_OP_NOT_IN_SESSION,
  NFS4ERR_SAME,
  NFS4ERR_SEQUENCE_POS,
  NFS4ERR_SERVERFAULT,
  NFS4ERR_TOO_MANY_OPS,
  NFS4ERR_TOOSMALL,
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
  opName4,
  SECINFO_STYLE4_CURRENT_FH,
  SECINFO_STYLE4_PARENT,
  SET_TO_CLIENT_TIME4,
  SET_TO_SERVER_TIME4,
  SP4_NONE,
} from "./constants.ts";
import {
  type Access4args,
  type Access4res,
  type Argop4Value,
  type BackchannelCtl4args,
  type BindConnToSession4args,
  type BindConnToSession4res,
  type ChangeInfo4,
  type Commit4res,
  type Compound4res,
  type Create4args,
  type Create4res,
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
  type Lookup4args,
  NFS4_MAX_COMPOUND_OPS,
  NFS4_MAX_TAG,
  OP_CODECS,
  type Putfh4args,
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
  type Status4res,
  type TestStateid4args,
  type TestStateid4res,
  type Verify4args,
} from "./protocol.ts";
import { Nfs4State } from "./state.ts";

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
 * The eight operations whose handlers arrive with the open and lock state.
 *
 * Their codecs are complete, so their arguments *are* decoded and the compound
 * could go on; they answer `NFS4ERR_NOTSUPP` and halt, which is the same shape
 * a client sees for an optional operation this server does not implement.
 */
const PENDING_STATE_OPS: ReadonlySet<number> = new Set([
  OP_CLOSE,
  OP_LOCK,
  OP_LOCKT,
  OP_LOCKU,
  OP_OPEN,
  OP_OPEN_DOWNGRADE,
  OP_READ,
  OP_WRITE,
]);

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
function encodeCompoundRes(res: Compound4res): Uint8Array {
  const writer = new XdrWriter(512);
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
  return writer.bytes();
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

/** A `sessionid4` as a Map key. */
function sessionKey(sessionid: Uint8Array): string {
  let key = "";
  for (const byte of sessionid) {
    key += byte.toString(16).padStart(2, "0");
  }
  return key;
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

/** The cursor a COMPOUND is executed against (RFC 8881 §16.2.3.1.1), plus its context. */
interface Cursor {
  /** The current filehandle, as wire bytes. `undefined` is `NFS4ERR_NOFILEHANDLE`. */
  currentFh: Uint8Array | undefined;
  savedFh: Uint8Array | undefined;
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
  #destroyed = false;

  /**
   * `shared` is the router's — see `../util.ts`. Left out, this session makes
   * its own handle table, lock and counters, which is what its own tests do.
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
    this.state = new Nfs4State({ ...options.nfs4 });
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
   * `message` is read across awaits and must not be overwritten while the
   * promise is outstanding; everything this session *keeps* — names, file
   * handles, session IDs — is copied out of it by the decoders, and the whole
   * COMPOUND is decoded before the first await.
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

  /** Drop every cached listing, and stop. Idempotent. Handles are the router's. */
  async destroy(): Promise<void> {
    this.#destroyed = true;
    this.#snapshots.clear();
    this.#maxOpsBySession.clear();
    await Promise.resolve();
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
      return (await this.#execute(call, request, 0, [], undefined)).reply;
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
        const bytes = await this.#execute(call, request, 1, resarray, outcome.clientid, seq);
        // The ticket is handed back whether or not there are bytes to store —
        // `./state.ts` needs to know the request finished either way.
        this.state.cacheReply(outcome.ticket, outcome.cachethis ? bytes.body : undefined);
        return bytes.reply;
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

  #reply(call: RpcCall, tag: string, status: number, resarray: Resop4[]): Uint8Array {
    return encodeAcceptedReply(call.xid, encodeCompoundRes({ status, tag, resarray }));
  }

  /**
   * Run the operations from `from` onward over one cursor.
   *
   * Halts at the first non-`NFS4_OK` status (§16.2.3), and then at the decode
   * halt if the array reached one. Returns both the encoded `COMPOUND4res`
   * (which is what a slot caches) and the framed reply.
   */
  async #execute(
    call: RpcCall,
    request: DecodedCompound,
    from: number,
    resarray: Resop4[],
    clientid: bigint | undefined,
    seq?: Sequence4args,
  ): Promise<{ body: Uint8Array | undefined; reply: Uint8Array }> {
    const cursor: Cursor = {
      currentFh: undefined,
      savedFh: undefined,
      creds: credentialsOf(call.cred),
      clientid,
      ownSession: seq === undefined ? undefined : sessionKey(seq.sessionid),
      destroyedOwnSession: false,
    };
    let status = resarray.length === 0 ? NFS4_OK : (resarray[0]!.res as Status4res).status;
    let halted = false;
    for (let index = from; index < request.ops.length; index++) {
      const resop = await this.#operation(request.ops[index]!, cursor);
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
    const body = encodeCompoundRes({ status, tag: request.tag, resarray });
    // A compound that destroyed the session it rides has no slot to cache into
    // any more, and §18.37.3 warns the client to expect exactly that.
    return {
      body: cursor.destroyedOwnSession ? undefined : body,
      reply: encodeAcceptedReply(call.xid, body),
    };
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
      case OP_LOOKUP: {
        return this.#lookup(entry.args as Lookup4args, cursor);
      }
      case OP_LOOKUPP: {
        return this.#lookupp(cursor);
      }
      case OP_NVERIFY: {
        return this.#verify(entry.args as Verify4args, cursor, false);
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
        return { status: NFS4_OK };
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
        cursor.currentFh = this.#requireSaved(cursor);
        return { status: NFS4_OK };
      }
      case OP_SAVEFH: {
        cursor.savedFh = this.#requireCurrent(cursor);
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
      default: {
        // The eight operations whose handlers arrive with the open and lock
        // state wiring. Their arguments were decoded, so this is a refusal
        // rather than a desync — see {@link PENDING_STATE_OPS}.
        /* v8 ignore next 3 -- unreachable: the decoder rejects every opcode
           that is neither in the codec table nor handled above. */
        if (!PENDING_STATE_OPS.has(entry.op)) {
          throw new Nfs4StatusError(NFS4ERR_SERVERFAULT, `no handler for ${opName4(entry.op)}`);
        }
        return { status: NFS4ERR_NOTSUPP };
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

  /** The `fileid` for an object: the driver's own `ino` when it has one. */
  #fileid(entry: HandleEntry, stats: StatsLike): bigint {
    return stats.ino > 0 ? BigInt(Math.trunc(stats.ino)) : entry.id;
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
   * Every attribute value this server has for one object.
   *
   * `driver.statfs` is called only when the request actually asks for one of
   * the six attributes that need it, and a failure omits those six rather than
   * failing the operation — the rest of the answer is still true.
   */
  async #valuesFor(path: string, requested: Bitmap4): Promise<Fattr4Values> {
    const { entry, stats } = await this.#bind(path);
    const values: Fattr4Values = {
      ...this.#filesystemValues(),
      ...fattr4Of(stats, {
        fileid: this.#fileid(entry, stats),
        filehandle: this.handles.encode(entry),
      }),
    };
    if (
      this.driver.capabilities.statfs &&
      !bitmapIsEmpty(bitmapIntersection(requested, STATFS_ATTRS))
    ) {
      try {
        Object.assign(values, fattr4FsOf(await this.driver.statfs(path)));
      } catch (error) {
        // The six `statfs` bits are simply absent from the reply bitmap, which
        // §18.7.3 makes the protocol's own answer for an attribute a server
        // cannot produce.
        this.options.onError?.(error, undefined);
      }
    }
    return values;
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
   */
  #putfh(args: Putfh4args, cursor: Cursor): Status4res {
    cursor.currentFh = this.handles.encode(this.handles.decode(args.object));
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
   * The stateid is decoded and **not yet validated**: it exists to carry the
   * byte-range locking context a `size` change needs (§18.30.3), and there is
   * no open or lock state to check it against until that wiring lands.
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
    const path = this.#pathOfCurrent(cursor);
    try {
      this.#settableOrRefuse(args.objAttributes);
    } catch (error) {
      return { status: statusOf(error), attrsset: [] };
    }
    const applied = await this.#applyAttrs(path, args.objAttributes);
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
        // The numeric-string fast path of §5.9; a `name@domain` owner needs an
        // ID map, which arrives with the open and lock wiring.
        const uid = values.owner === undefined ? -1 : this.#ownerId(values.owner);
        const gid = values.ownerGroup === undefined ? -1 : this.#ownerId(values.ownerGroup);
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
   * A `utf8str_mixed` owner as a uid or gid.
   *
   * Only §5.9's numeric form for now — "owner and group strings that consist of
   * decimal numeric values with no leading zeros can be given a special
   * interpretation" — and anything else is `NFS4ERR_BADOWNER`, which §15.2
   * lists for SETATTR and which is the honest answer from a server with no name
   * service. A real `name@domain` map arrives with the ID-mapping step.
   */
  #ownerId(owner: string): number {
    const id = parseNumericOwner(owner);
    if (id === undefined) {
      throw new Nfs4StatusError(NFS4ERR_BADOWNER, `owner '${owner}' is not a numeric id`);
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
   * ownership, which is not the same as broken.
   */
  async #claim(path: string, creds: RpcCredentials): Promise<void> {
    if (this.options.claimOwnership === false || creds.uid === undefined) {
      return;
    }
    if (creds.uid === (process.getuid?.() ?? -1) && creds.gid === (process.getgid?.() ?? -1)) {
      return;
    }
    try {
      await this.driver.lchown(path, creds.uid, creds.gid ?? -1);
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code !== "ENOSYS" && code !== "EPERM" && code !== "ENOTSUP") {
        throw error;
      }
    }
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

    await this.#claim(path, cursor.creds);
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
    // The handle keeps existing and stops resolving: a client still holding it
    // gets `NFS4ERR_STALE`, which is what this server has instead of an
    // unlinked-but-open file.
    const entry = this.handles.unbind(path);
    if (entry !== undefined && directory) {
      this.#snapshots.delete(entry.id);
    }
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
    this.#snapshots.clear();
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
    const entries: Entry4[] = [];
    let dirUsed = 0;
    let maxUsed = 0;
    let index = page.from;
    for (; index < page.names.length; index++) {
      const name = page.names[index]!;
      // `nextentry` bool, cookie, and the counted name: what §18.23.3 says
      // `dircount` measures ("the total length of the names of the directory
      // entries and the cookie value for these entries").
      const dirSize = 4 + 8 + 4 + xdrAlign(stringByteLength(name));
      const attrs = await this.#entryAttrs(path, name, attrmask, wantsRdattrError);
      const scratch = new XdrWriter(256);
      encodeFattr(scratch, attrs.attrmask, attrs.values, getable);
      const entrySize = dirSize + scratch.length;
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
      entries.push({ cookie: BigInt(index) + COOKIE_BASE, name, attrs });
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
  ): Promise<Fattr4> {
    const child = joinPath(dir, name);
    try {
      const values = await this.#valuesFor(child, attrmask);
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
