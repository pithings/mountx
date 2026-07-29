/**
 * A minimal NFSv4.1 client, built from the server's own codecs.
 *
 * The same Tier-1 trick `../v3/client.ts` plays, one version up: the XDR, RPC
 * and COMPOUND codecs are symmetric, so the client that exercises the server
 * can be written in JavaScript — the whole protocol runs over a real socket, in
 * one process, with **no mount and no root**.
 *
 * What changes at 4.1 is that the client is no longer stateless, and that is
 * most of this file:
 *
 * - **A session, not a mount.** There is no MOUNT program to ask for the root
 *   handle; `PUTROOTFH` is the root handle. Before any of that, though,
 *   `EXCHANGE_ID` trades a `client_owner4` for a `clientid4`, `CREATE_SESSION`
 *   turns that into a session with a fore-channel slot table, and
 *   `RECLAIM_COMPLETE` says the client has no locks to reclaim — without which
 *   every OPEN answers `NFS4ERR_GRACE` (§18.51.3). {@link Nfs4Client.establish}
 *   is those three.
 * - **A slot table, not an xid.** Exactly-once semantics at 4.1 come from
 *   (session, slot, sequence ID), and the RPC xid means nothing to it: a
 *   retransmission is the *same slot and sequence ID* under whatever xid, and
 *   the server answers it from the slot's reply cache. {@link Nfs4Client.compound}
 *   allocates a slot and advances its sequence ID; {@link Nfs4Client.resendLast}
 *   and the explicit `slot`/`seqid` options are how a test forces the
 *   retransmission that proves the cache.
 * - **A cursor, not a handle per argument.** Every operation acts on the
 *   current filehandle the ones before it left behind, so each helper below
 *   builds a `PUTFH`-led COMPOUND rather than passing a handle to one call.
 *
 * Statuses come back as `node:fs`-shaped errors the way v3's do — see
 * {@link check4} — with the `nfsstat4` itself attached, so a caller can assert
 * on either.
 *
 * This file speaks filehandles, like the wire, with one exception: the
 * path-walk helpers ({@link Nfs4Client.walk}, {@link Nfs4Client.open}) resolve
 * a path component by component, because that is the one thing a client must do
 * for itself.
 */

import * as net from "node:net";
import { constants } from "node:fs";
import { fsError, type ErrnoCode, type FsError } from "../../../src/errors.ts";
import {
  authSys,
  decodeReply,
  encodeCall,
  frameRecord,
  RecordAssembler,
  type OpaqueAuth,
} from "../../../src/nfs/rpc.ts";
import { bitmapOf, type Bitmap4, type Fattr4Values } from "../../../src/nfs/v4/attr.ts";
import {
  ACCESS4_ALL,
  CLAIM_NULL,
  errnoCodeOfStatus4,
  FATTR4_CHANGE,
  FATTR4_FILEID,
  FATTR4_FILES_AVAIL,
  FATTR4_FILES_FREE,
  FATTR4_FILES_TOTAL,
  FATTR4_FSID,
  FATTR4_LEASE_TIME,
  FATTR4_MAXNAME,
  FATTR4_MAXREAD,
  FATTR4_MAXWRITE,
  FATTR4_MODE,
  FATTR4_NUMLINKS,
  FATTR4_OWNER,
  FATTR4_OWNER_GROUP,
  FATTR4_RAWDEV,
  FATTR4_SIZE,
  FATTR4_SPACE_AVAIL,
  FATTR4_SPACE_FREE,
  FATTR4_SPACE_TOTAL,
  FATTR4_SPACE_USED,
  FATTR4_TIME_ACCESS,
  FATTR4_TIME_ACCESS_SET,
  FATTR4_TIME_METADATA,
  FATTR4_TIME_MODIFY,
  FATTR4_TIME_MODIFY_SET,
  FATTR4_TYPE,
  FILE_SYNC4,
  GUARDED4,
  NF4DIR,
  NF4LNK,
  NFS4_OK,
  NFS4_PROGRAM,
  NFS4_VERIFIER_SIZE,
  NFS_V4,
  NFSPROC4_COMPOUND,
  NFSPROC4_NULL,
  OPEN4_CREATE,
  OPEN4_NOCREATE,
  OPEN4_SHARE_ACCESS_BOTH,
  OPEN4_SHARE_ACCESS_READ,
  OPEN4_SHARE_ACCESS_WRITE,
  OPEN4_SHARE_DENY_NONE,
  OP_ACCESS,
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
  OP_PUTROOTFH,
  OP_READ,
  OP_READDIR,
  OP_READLINK,
  OP_RECLAIM_COMPLETE,
  OP_REMOVE,
  OP_RENAME,
  OP_SAVEFH,
  OP_SECINFO,
  OP_SEQUENCE,
  OP_SETATTR,
  OP_TEST_STATEID,
  OP_VERIFY,
  OP_WRITE,
  SP4_NONE,
  status4Name,
  UNCHECKED4,
  WRITE_LT,
} from "../../../src/nfs/v4/constants.ts";
import {
  readCompoundRes,
  writeCompoundArgs,
  type Access4res,
  type Argop4,
  type Argop4Value,
  type ChannelAttrs4,
  type ChangeInfo4,
  type Close4res,
  type Commit4res,
  type Compound4res,
  type Create4res,
  type CreateSession4res,
  type Entry4,
  type ExchangeId4res,
  type Fattr4,
  type Getattr4res,
  type Getfh4res,
  type Link4res,
  type Lock4denied,
  type Lock4res,
  type Lockt4res,
  type Locku4res,
  type Open4res,
  type OpenDowngrade4res,
  type Read4res,
  type Readdir4res,
  type Readlink4res,
  type Remove4res,
  type Rename4res,
  type Resop4,
  type Secinfo4res,
  type Sequence4res,
  type Setattr4res,
  type Stateid4,
  type Status4res,
  type TestStateid4res,
  type Write4res,
} from "../../../src/nfs/v4/protocol.ts";
import { XdrWriter, type XdrReader } from "../../../src/nfs/xdr.ts";
import { basename, dirname, normalizePath } from "../../../src/path.ts";

const encoder = new TextEncoder();

/**
 * Distinguishes the default `co_ownerid` of two clients in one process.
 *
 * A `client_owner4` two clients share is one client to the server: the second
 * EXCHANGE_ID would replace the first's record (§18.35.4) rather than mint a
 * second, and a test that meant to open two clients would be debugging that
 * instead.
 */
let nextOwnerid = 1;

/** Distinguishes one `co_verifier` from the next; see {@link freshVerifier}. */
let nextVerifier = 1;

/**
 * A `verifier4` no other client in this process has used.
 *
 * The pair (`co_ownerid`, `co_verifier`) is what §18.35.4 reads as identity: a
 * repeat of *both* is the same client asking again — answered from the client
 * ID's one-entry reply cache — and a new verifier under an old ownerid is that
 * client having rebooted, which discards its state and mints a session. Two
 * clients in one process must therefore differ in one of the two, and the
 * re-establishing client must differ from its own past self.
 */
function freshVerifier(): Uint8Array {
  const bytes = new Uint8Array(NFS4_VERIFIER_SIZE);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(nextVerifier++), false);
  return bytes;
}

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/** An RPC that came back as anything other than an accepted success. */
export class Rpc4Error extends Error {
  readonly code = "ERR_NFS_RPC";

  constructor(message: string) {
    super(message);
    this.name = "Rpc4Error";
  }
}

/** A `node:fs`-shaped error that also carries the `nfsstat4` it came from. */
export interface Nfs4StatusError extends FsError {
  readonly status: number;
}

/**
 * The error for an `nfsstat4`.
 *
 * The shape is `../v3/client.ts`'s — a `node:fs` error whose `cause` names the
 * protocol status — so the conformance suite can read `code` the same way for
 * both versions. The numeric `status` is attached as well, because a v4 test
 * that wants to pin `NFS4ERR_SHARE_DENIED` rather than the `EACCES` it maps to
 * has no other way to see it.
 */
export function nfs4Error(status: number, syscall: string, path?: string): Nfs4StatusError {
  const error = fsError(errnoCodeOfStatus4(status) as ErrnoCode, {
    syscall,
    path,
    cause: new Error(status4Name(status)),
  });
  return Object.assign(error, { status });
}

/** Throw unless the result succeeded. The v4 mirror of v3's `check`. */
export function check4<T extends { status: number }>(result: T, syscall: string, path?: string): T {
  if (result.status !== NFS4_OK) {
    throw nfs4Error(result.status, syscall, path);
  }
  return result;
}

/**
 * Throw unless the whole COMPOUND succeeded.
 *
 * `COMPOUND4res.status` is the status of the last operation that ran, so it is
 * the one worth reporting: the array stops at the first failure.
 */
export function checkCompound(
  reply: Compound4reply,
  syscall: string,
  path?: string,
): Compound4reply {
  if (reply.status !== NFS4_OK) {
    throw nfs4Error(reply.status, syscall, path);
  }
  return reply;
}

/**
 * The result for an operation, found by opcode rather than by position.
 *
 * The compounds below vary in how many operations it takes to reach the file,
 * and counting them into an index is how a caller ends up reading the wrong
 * operation's result.
 */
export function resFor<T>(reply: Compound4res, op: number): T {
  const found = reply.resarray.find((entry) => entry.op === op);
  if (found === undefined) {
    throw new Rpc4Error(`no result for opcode ${op} in a ${reply.resarray.length}-op reply`);
  }
  return found.res as T;
}

// ---------------------------------------------------------------------------
// the client
// ---------------------------------------------------------------------------

/** `nfs_argop4`, with the void arm spelled out. */
export function op(opnum: number, args?: Argop4Value): Argop4 {
  return { op: opnum, args };
}

/** Make `fh` the current filehandle. */
export function putfh(fh: Uint8Array): Argop4 {
  return op(OP_PUTFH, { object: fh });
}

/** A `fattr4` argument: a mask, its values, and the empty decode-only field. */
export function fattr(attrmask: Bitmap4, values: Fattr4Values = {}): Fattr4 {
  return { attrmask, values, unsupported: [] };
}

/**
 * The attributes {@link Nfs4Client.getattr} asks for when nothing else is said:
 * everything a `stat(2)` needs, and nothing per-filesystem.
 */
export const OBJECT_ATTRS: Bitmap4 = bitmapOf([
  FATTR4_TYPE,
  FATTR4_CHANGE,
  FATTR4_SIZE,
  FATTR4_FSID,
  FATTR4_FILEID,
  FATTR4_MODE,
  FATTR4_NUMLINKS,
  FATTR4_OWNER,
  FATTR4_OWNER_GROUP,
  FATTR4_RAWDEV,
  FATTR4_SPACE_USED,
  FATTR4_TIME_ACCESS,
  FATTR4_TIME_METADATA,
  FATTR4_TIME_MODIFY,
]);

/** The per-filesystem attributes — what NFSv3 would have asked FSSTAT and FSINFO for. */
export const FS_ATTRS: Bitmap4 = bitmapOf([
  FATTR4_LEASE_TIME,
  FATTR4_FILES_AVAIL,
  FATTR4_FILES_FREE,
  FATTR4_FILES_TOTAL,
  FATTR4_MAXNAME,
  FATTR4_MAXREAD,
  FATTR4_MAXWRITE,
  FATTR4_SPACE_AVAIL,
  FATTR4_SPACE_FREE,
  FATTR4_SPACE_TOTAL,
]);

/**
 * Which bit each settable attribute lives at, so `{ mode: 0o644 }` can become a
 * mask without the caller spelling one.
 *
 * Exactly the six rows of `attr.ts`'s `SETTABLE_ATTRS`, which is the set a
 * SETATTR may carry; anything else is read-only (§5.5) and gets
 * `NFS4ERR_INVAL`. A test that wants to send a mask this table cannot build
 * passes `bits` to {@link Nfs4Client.setattr} instead.
 */
const SETTABLE_BITS: readonly (readonly [keyof Fattr4Values, number])[] = [
  ["size", FATTR4_SIZE],
  ["mode", FATTR4_MODE],
  ["owner", FATTR4_OWNER],
  ["ownerGroup", FATTR4_OWNER_GROUP],
  ["timeAccessSet", FATTR4_TIME_ACCESS_SET],
  ["timeModifySet", FATTR4_TIME_MODIFY_SET],
];

/** The mask for the settable attributes present in `values`. */
export function settableMask(values: Fattr4Values): Bitmap4 {
  return bitmapOf(SETTABLE_BITS.filter(([key]) => values[key] !== undefined).map(([, bit]) => bit));
}

/** The anonymous stateid (§8.2.3): I/O with no open behind it. */
export const ANONYMOUS_STATEID: Stateid4 = { seqid: 0, other: new Uint8Array(12) };

/** The all-ones READ-bypass stateid (§8.2.3). */
export const BYPASS_STATEID: Stateid4 = {
  seqid: 0xff_ff_ff_ff,
  other: new Uint8Array(12).fill(0xff),
};

/** What the client offers for the fore channel, and the ceiling for the back one. */
export const DEFAULT_CHANNEL: ChannelAttrs4 = {
  headerpadsize: 0,
  maxrequestsize: 1024 * 1024,
  maxresponsesize: 1024 * 1024,
  maxresponsesizeCached: 64 * 1024,
  maxoperations: 32,
  maxrequests: 8,
  rdmaIrd: [],
};

export interface Nfs4ClientOptions {
  port: number;
  host?: string;
  /** Credentials on every call. Default: `AUTH_SYS` for this process. */
  cred?: OpaqueAuth;
  /** `client_owner4.co_ownerid`. Two clients must not share one. */
  ownerid?: string;
  /**
   * `client_owner4.co_verifier` — a reboot marker. Default: one no other client
   * in this process shares.
   *
   * This is the *initial* verifier only: a re-{@link Nfs4Client.establish} after
   * a lost session mints a fresh one, because repeating the pair would be a
   * retry rather than the reboot it means.
   */
  verifier?: Uint8Array;
  /** What to offer as `csa_fore_chan_attrs`. The server counter-offers. */
  channel?: Partial<ChannelAttrs4>;
}

/** A COMPOUND reply: the decoded struct, plus what a replay test needs. */
export interface Compound4reply extends Compound4res {
  /**
   * The encoded `COMPOUND4res`, past the RPC header — a copy.
   *
   * This is what the slot's reply cache holds, and comparing two of them is how
   * a retransmission is proven to have been *replayed* rather than re-run. The
   * RPC header is excluded deliberately: its xid is the one part a replay is
   * allowed to differ in.
   */
  body: Uint8Array;
  /** The slot this request rode, when it carried a SEQUENCE. */
  slot: number | undefined;
  /** The sequence ID it carried. */
  seqid: number | undefined;
  /** The RPC xid, so a test can prove two replies were addressed differently. */
  xid: number;
}

export interface CompoundOptions {
  /** `COMPOUND4args.tag`. */
  tag?: string;
  /** `COMPOUND4args.minorversion`. Default 1. */
  minorversion?: number;
  /** The RPC xid. Default: the next one. */
  xid?: number;
  /**
   * Prefix a SEQUENCE. Default: true once {@link Nfs4Client.establish} has run.
   *
   * `false` is for the five operations §18.46.3 lets a COMPOUND open with —
   * EXCHANGE_ID, CREATE_SESSION, DESTROY_SESSION, DESTROY_CLIENTID,
   * BIND_CONN_TO_SESSION — and for the tests that check the rule itself.
   */
  sequence?: boolean;
  /**
   * The slot to ride, instead of allocating a free one.
   *
   * Naming one is the escape hatch a retransmission needs: with `seqid` it
   * reproduces a request exactly, which is what the server's reply cache keys
   * on. Nothing about the client's own slot bookkeeping moves when it is used.
   */
  slot?: number;
  /** The sequence ID to send. Default: the slot's next, or its last when `slot` is named. */
  seqid?: number;
  /** `sa_cachethis`. Default false — a reply is only replayable if this was true. */
  cachethis?: boolean;
  /** `sa_highest_slotid`. Default: the top of the negotiated table. */
  highestSlotid?: number;
}

/** One fore-channel slot. */
interface Slot {
  readonly id: number;
  /** The last sequence ID the server accepted on it. */
  seqid: number;
  busy: boolean;
}

/** What {@link Nfs4Client.establish} settled. */
export interface Nfs4SessionInfo {
  clientid: bigint;
  sessionid: Uint8Array;
  /** The server's counter-offer, which is what binds — not what was asked for. */
  foreChanAttrs: ChannelAttrs4;
}

/** A path resolved to a filehandle, and the attributes asked for on the way. */
export interface Resolved4 {
  fh: Uint8Array;
  attrs: Fattr4Values;
}

/** RPC over TCP, a 4.1 session, and one method per operation this server runs. */
export class Nfs4Client {
  readonly #socket: net.Socket;
  readonly #assembler = new RecordAssembler();
  readonly #pending = new Map<
    number,
    { resolve: (reader: XdrReader) => void; reject: (error: unknown) => void }
  >();
  readonly #cred: OpaqueAuth;
  readonly #ownerid: string;
  #verifier: Uint8Array;
  readonly #channel: ChannelAttrs4;
  readonly #waiters: (() => void)[] = [];
  #slots: Slot[] = [];
  #session: Nfs4SessionInfo | undefined;
  #last: { argarray: Argop4[]; tag: string; slot: number; seqid: number } | undefined;
  #owners = 0;
  #establishments = 0;
  #xid = 1;
  #closed: Error | undefined;

  private constructor(socket: net.Socket, options: Nfs4ClientOptions) {
    this.#socket = socket;
    this.#cred = options.cred ?? authSys();
    this.#ownerid = options.ownerid ?? `mountx-test-${process.pid}-${nextOwnerid++}`;
    this.#verifier = options.verifier ?? freshVerifier();
    this.#channel = { ...DEFAULT_CHANNEL, ...options.channel };
    socket.on("data", (chunk: Buffer) => this.#onData(chunk));
    socket.on("error", (error) => this.#fail(error));
    socket.on("close", () => this.#fail(new Rpc4Error("the connection closed")));
  }

  /** Connect the socket. Nothing is negotiated yet. */
  static connect(options: Nfs4ClientOptions): Promise<Nfs4Client> {
    return new Promise((resolve, reject) => {
      const socket = net.connect({ port: options.port, host: options.host ?? "127.0.0.1" });
      socket.setNoDelay(true);
      socket.once("error", reject);
      socket.once("connect", () => {
        socket.off("error", reject);
        resolve(new Nfs4Client(socket, options));
      });
    });
  }

  /** Connect and {@link Nfs4Client.establish} — the usual entry point. */
  static async open(options: Nfs4ClientOptions): Promise<Nfs4Client> {
    const client = await Nfs4Client.connect(options);
    try {
      await client.establish();
    } catch (error) {
      client.close();
      throw error;
    }
    return client;
  }

  close(): void {
    this.#socket.destroy();
    this.#fail(new Rpc4Error("the client was closed"));
  }

  /** Calls still waiting for a reply. */
  get pending(): number {
    return this.#pending.size;
  }

  /** Is there a session to send a SEQUENCE on? */
  get hasSession(): boolean {
    return this.#session !== undefined;
  }

  /** The session, once {@link Nfs4Client.establish} has run. */
  get session(): Nfs4SessionInfo {
    if (this.#session === undefined) {
      throw new Rpc4Error("no session: call establish() first");
    }
    return this.#session;
  }

  /** The negotiated `ca_maxoperations`, which bounds every compound built here. */
  get maxOperations(): number {
    return this.#session?.foreChanAttrs.maxoperations ?? this.#channel.maxoperations;
  }

  /** The fore-channel slot table, as `(slot, last sequence ID)` pairs. */
  get slots(): readonly { id: number; seqid: number; busy: boolean }[] {
    return this.#slots.map((slot) => ({ ...slot }));
  }

  // --- the RPC layer -------------------------------------------------------

  #onData(chunk: Buffer): void {
    for (const record of this.#assembler.push(chunk)) {
      const { reply, results } = decodeReply(record);
      const waiter = this.#pending.get(reply.xid);
      if (waiter === undefined) {
        continue;
      }
      this.#pending.delete(reply.xid);
      if (reply.replyStat === 0 && reply.acceptStat === 0) {
        waiter.resolve(results);
      } else {
        waiter.reject(
          new Rpc4Error(
            `RPC failed: reply_stat ${reply.replyStat}, accept_stat ${reply.acceptStat}, ` +
              `reject_stat ${reply.rejectStat}, auth_stat ${reply.authStat}`,
          ),
        );
      }
    }
  }

  #fail(error: unknown): void {
    this.#closed ??= error instanceof Error ? error : new Rpc4Error(String(error));
    for (const waiter of this.#pending.values()) {
      waiter.reject(this.#closed);
    }
    this.#pending.clear();
  }

  /** One RPC. Resolves to a reader positioned at the results. */
  call(
    program: number,
    version: number,
    procedure: number,
    args?: Uint8Array,
    xid = this.#xid++,
  ): Promise<XdrReader> {
    if (this.#closed !== undefined) {
      return Promise.reject(this.#closed);
    }
    const message = encodeCall({
      xid,
      program,
      version,
      procedure,
      cred: this.#cred,
      args,
    });
    return this.sendRaw(message, xid);
  }

  /** Send an already-encoded RPC message and wait for the reply addressed to `xid`. */
  sendRaw(message: Uint8Array, xid: number): Promise<XdrReader> {
    return new Promise<XdrReader>((resolve, reject) => {
      this.#pending.set(xid, { resolve, reject });
      this.#socket.write(frameRecord(message));
    });
  }

  /** NFSPROC4_NULL — the ping every RPC program answers. */
  async null(): Promise<void> {
    (await this.call(NFS4_PROGRAM, NFS_V4, NFSPROC4_NULL)).end("NFS4 NULL reply");
  }

  // --- COMPOUND and the slot table ----------------------------------------

  /**
   * Send a COMPOUND.
   *
   * With a session up, a SEQUENCE is prefixed and a free slot allocated; the
   * `slot`/`seqid` options bypass that, which is what a forced retransmission
   * needs. The slot's sequence ID only advances when the reply says the server
   * accepted it — a compound refused before SEQUENCE ran (`NFS4ERR_TOO_MANY_OPS`)
   * or refused by it (`NFS4ERR_SEQ_MISORDERED`) leaves the slot untouched at
   * the server, and a client that advanced anyway would desynchronize itself.
   *
   * The reply is decoded with the codec table's own `readCompoundRes`, which is
   * the point of having both directions in one place. Its one limit is an
   * opcode with no codec row: `writeCompoundArgs` cannot send one either, so
   * nothing this client asks for can come back in a shape it cannot read.
   */
  async compound(ops: readonly Argop4[], options: CompoundOptions = {}): Promise<Compound4reply> {
    const withSequence = options.sequence ?? this.#session !== undefined;
    if (!withSequence) {
      return this.#send([...ops], options, undefined, undefined);
    }
    if (options.slot !== undefined) {
      const slot = this.#slots[options.slot];
      const seqid = options.seqid ?? slot?.seqid ?? 1;
      return this.#sendSequenced([...ops], options, options.slot, seqid);
    }
    const slot = await this.#acquire();
    try {
      const seqid = options.seqid ?? slot.seqid + 1;
      const reply = await this.#sendSequenced([...ops], options, slot.id, seqid);
      if (accepted(reply)) {
        slot.seqid = seqid;
      }
      return reply;
    } finally {
      slot.busy = false;
      this.#waiters.shift()?.();
    }
  }

  /**
   * Resend the last SEQUENCE-carrying compound verbatim, under a fresh xid.
   *
   * The same (session, slot, sequence ID) is by definition a retransmission,
   * and §2.10.6.1 makes the server answer it from the slot's reply cache rather
   * than re-running the operations — provided the original asked for
   * `cachethis`. Nothing in the client's slot table moves.
   */
  async resendLast(): Promise<Compound4reply> {
    const last = this.#last;
    if (last === undefined) {
      throw new Rpc4Error("nothing to resend: no sequenced compound has been sent");
    }
    return this.#send(last.argarray, { tag: last.tag }, last.slot, last.seqid);
  }

  /** Build the SEQUENCE, remember it for {@link Nfs4Client.resendLast}, and send. */
  #sendSequenced(
    ops: Argop4[],
    options: CompoundOptions,
    slot: number,
    seqid: number,
  ): Promise<Compound4reply> {
    const session = this.session;
    const argarray: Argop4[] = [
      op(OP_SEQUENCE, {
        sessionid: session.sessionid,
        sequenceid: seqid,
        slotid: slot,
        highestSlotid: options.highestSlotid ?? Math.max(0, this.#slots.length - 1),
        cachethis: options.cachethis ?? false,
      }),
      ...ops,
    ];
    this.#last = { argarray, tag: options.tag ?? "", slot, seqid };
    return this.#send(argarray, options, slot, seqid);
  }

  async #send(
    argarray: Argop4[],
    options: CompoundOptions,
    slot: number | undefined,
    seqid: number | undefined,
  ): Promise<Compound4reply> {
    const writer = new XdrWriter(1024);
    writeCompoundArgs(writer, {
      tag: options.tag ?? "",
      minorversion: options.minorversion ?? 1,
      argarray,
    });
    const xid = options.xid ?? this.#xid++;
    const results = await this.call(NFS4_PROGRAM, NFS_V4, NFSPROC4_COMPOUND, writer.bytes(), xid);
    // `slice` copies, which is what makes the body safe to keep past the
    // decode below — and comparing two of them is the whole point of it.
    const body = results.bytes.slice(results.offset);
    const compound = readCompoundRes(results);
    results.end("COMPOUND4res");
    return { ...compound, body, slot, seqid, xid };
  }

  /** The first free slot, waiting for one if every slot is in flight. */
  async #acquire(): Promise<Slot> {
    for (;;) {
      const free = this.#slots.find((slot) => !slot.busy);
      if (free !== undefined) {
        free.busy = true;
        return free;
      }
      await new Promise<void>((resolve) => this.#waiters.push(resolve));
    }
  }

  // --- session establishment ----------------------------------------------

  /**
   * EXCHANGE_ID, CREATE_SESSION, RECLAIM_COMPLETE — everything before the first
   * OPEN.
   *
   * A client holds **one session at a time**, and calling this on a live one is
   * refused rather than attempted: the same `client_owner4` would be a retry to
   * §18.35.4, so EXCHANGE_ID and CREATE_SESSION would come back from the client
   * ID's reply cache naming the session that already exists, and the
   * RECLAIM_COMPLETE behind them would ride a slot table that was rebuilt from
   * zero into a server that remembers it — `NFS4ERR_RETRY_UNCACHED_REP`, with
   * nothing naming the cause.
   *
   * Establishing *again* after the session is gone works, and mints a fresh
   * `co_verifier` to say so: that is the client having rebooted (§18.35.4), and
   * it is what makes the server discard the old record instead of replaying it.
   *
   * A failure leaves no session behind, whichever of the three operations it
   * came from — including the last, which runs with `#session` already set
   * because it needs a SEQUENCE to ride.
   */
  async establish(): Promise<Nfs4SessionInfo> {
    if (this.#session !== undefined) {
      throw new Rpc4Error(
        "already established — a client holds one session at a time; " +
          "destroySession() first, or open a second client",
      );
    }
    if (this.#establishments > 0) {
      this.#verifier = freshVerifier();
    }
    this.#establishments += 1;
    this.#slots = [];
    this.#last = undefined;
    try {
      const exchanged = check4(await this.exchangeId(), "connect");
      const created = check4(
        await this.createSession(exchanged.clientid, exchanged.sequenceid),
        "connect",
      );
      const foreChanAttrs = created.foreChanAttrs!;
      this.#session = { clientid: exchanged.clientid, sessionid: created.sessionid, foreChanAttrs };
      this.#slots = Array.from({ length: foreChanAttrs.maxrequests }, (_unused, id) => ({
        id,
        seqid: 0,
        busy: false,
      }));
      await this.reclaimComplete();
      return this.#session;
    } catch (error) {
      this.#session = undefined;
      this.#slots = [];
      this.#last = undefined;
      throw error;
    }
  }

  /** EXCHANGE_ID (§18.35), SP4_NONE, no implementation ID. */
  async exchangeId(): Promise<ExchangeId4res> {
    const reply = await this.compound(
      [
        op(OP_EXCHANGE_ID, {
          clientowner: { verifier: this.#verifier, ownerid: encoder.encode(this.#ownerid) },
          flags: 0,
          stateProtect: { how: SP4_NONE },
          clientImplId: [],
        }),
      ],
      { sequence: false, tag: "exchange_id" },
    );
    return resFor<ExchangeId4res>(reply, OP_EXCHANGE_ID);
  }

  /** CREATE_SESSION (§18.36). `sequence` is the EXCHANGE_ID's `eir_sequenceid`. */
  async createSession(clientid: bigint, sequence: number): Promise<CreateSession4res> {
    const reply = await this.compound(
      [
        op(OP_CREATE_SESSION, {
          clientid,
          sequence,
          flags: 0,
          foreChanAttrs: this.#channel,
          backChanAttrs: this.#channel,
          cbProgram: 0,
          secParms: [],
        }),
      ],
      { sequence: false, tag: "create_session" },
    );
    return resFor<CreateSession4res>(reply, OP_CREATE_SESSION);
  }

  /**
   * RECLAIM_COMPLETE (§18.51) with `rca_one_fs` FALSE.
   *
   * Mandatory even with nothing to reclaim: until it arrives every
   * lock-obtaining operation answers `NFS4ERR_GRACE`.
   */
  async reclaimComplete(): Promise<void> {
    checkCompound(
      await this.compound([op(OP_RECLAIM_COMPLETE, { oneFs: false })], {
        tag: "reclaim_complete",
      }),
      "connect",
    );
  }

  /**
   * A bare SEQUENCE.
   *
   * The lease is renewed by SEQUENCE and by nothing else (§8.3), so every
   * compound this client sends already keeps it alive; this is for a client
   * that has been idle and wants to say so.
   */
  renew(): Promise<Compound4reply> {
    return this.compound([], { tag: "renew" });
  }

  /** DESTROY_SESSION (§18.37), riding the session it destroys. */
  async destroySession(): Promise<Compound4reply> {
    const sessionid = this.session.sessionid;
    const reply = await this.compound([op(OP_DESTROY_SESSION, { sessionid })], {
      tag: "destroy_session",
    });
    if (reply.status === NFS4_OK) {
      this.#session = undefined;
      this.#slots = [];
      this.#last = undefined;
    }
    return reply;
  }

  /** DESTROY_CLIENTID (§18.50) — outside any session, which is where it belongs. */
  destroyClientid(clientid: bigint): Promise<Compound4reply> {
    return this.compound([op(OP_DESTROY_CLIENTID, { clientid })], {
      sequence: false,
      tag: "destroy_clientid",
    });
  }

  // --- the namespace -------------------------------------------------------

  /** The root filehandle: PUTROOTFH, then GETFH. */
  async rootFh(): Promise<Uint8Array> {
    const reply = checkCompound(
      await this.compound([op(OP_PUTROOTFH), op(OP_GETFH)], { tag: "root" }),
      "lookup",
      "/",
    );
    return resFor<Getfh4res>(reply, OP_GETFH).object!;
  }

  /**
   * Resolve an absolute path to a filehandle.
   *
   * PUTROOTFH and one LOOKUP per component, batched into as few COMPOUNDs as
   * `ca_maxoperations` allows — which is the whole reason NFSv4 has compounds.
   * Symbolic links are **not** followed: the server never resolves one and this
   * client does not either, so a caller that wants `stat` rather than `lstat`
   * semantics chases them itself.
   */
  async walk(path: string, attrRequest: Bitmap4 = []): Promise<Resolved4> {
    const names = normalizePath(path).split("/").filter(Boolean);
    // Room for the leading SEQUENCE/PUTFH pair, the trailing GETFH, and the
    // optional GETATTR.
    const batch = Math.max(1, this.maxOperations - 4);
    let lead: Argop4 = op(OP_PUTROOTFH);
    let index = 0;
    for (;;) {
      const chunk = names.slice(index, index + batch);
      index += chunk.length;
      const last = index >= names.length;
      const ops: Argop4[] = [lead];
      for (const name of chunk) {
        ops.push(op(OP_LOOKUP, { objname: name }));
      }
      ops.push(op(OP_GETFH));
      if (last && attrRequest.length > 0) {
        ops.push(op(OP_GETATTR, { attrRequest }));
      }
      const reply = checkCompound(await this.compound(ops, { tag: "walk" }), "lookup", path);
      const fh = resFor<Getfh4res>(reply, OP_GETFH).object!;
      if (last) {
        return {
          fh,
          attrs:
            attrRequest.length > 0
              ? resFor<Getattr4res>(reply, OP_GETATTR).objAttributes!.values
              : {},
        };
      }
      lead = putfh(fh);
    }
  }

  /** One LOOKUP under `dir`, answering with the filehandle it landed on. */
  async lookup(dir: Uint8Array, name: string): Promise<Uint8Array> {
    const reply = checkCompound(
      await this.compound([putfh(dir), op(OP_LOOKUP, { objname: name }), op(OP_GETFH)], {
        tag: "lookup",
      }),
      "lookup",
      name,
    );
    return resFor<Getfh4res>(reply, OP_GETFH).object!;
  }

  /** LOOKUPP — the parent of `fh`. */
  async lookupp(fh: Uint8Array): Promise<Uint8Array> {
    const reply = checkCompound(
      await this.compound([putfh(fh), op(OP_LOOKUPP), op(OP_GETFH)], { tag: "lookupp" }),
      "lookup",
    );
    return resFor<Getfh4res>(reply, OP_GETFH).object!;
  }

  /** GETATTR. Defaults to {@link OBJECT_ATTRS}. */
  async getattr(fh: Uint8Array, attrRequest: Bitmap4 = OBJECT_ATTRS): Promise<Fattr4Values> {
    const reply = checkCompound(
      await this.compound([putfh(fh), op(OP_GETATTR, { attrRequest })], { tag: "getattr" }),
      "stat",
    );
    return resFor<Getattr4res>(reply, OP_GETATTR).objAttributes!.values;
  }

  /** The per-filesystem attributes — NFSv3's FSSTAT and FSINFO in one call. */
  statfs(fh: Uint8Array): Promise<Fattr4Values> {
    return this.getattr(fh, FS_ATTRS);
  }

  /**
   * SETATTR, answering with the `attrsset` the server echoes.
   *
   * The mask defaults to {@link settableMask} of the values given; `bits` sends
   * one that was built by hand, which is how a test reaches an attribute the
   * table above deliberately cannot name.
   */
  async setattr(
    fh: Uint8Array,
    values: Fattr4Values,
    options: { bits?: Bitmap4; stateid?: Stateid4; path?: string } = {},
  ): Promise<Setattr4res> {
    const reply = checkCompound(
      await this.compound(
        [
          putfh(fh),
          op(OP_SETATTR, {
            stateid: options.stateid ?? ANONYMOUS_STATEID,
            objAttributes: fattr(options.bits ?? settableMask(values), values),
          }),
        ],
        { tag: "setattr" },
      ),
      "chmod",
      options.path,
    );
    return resFor<Setattr4res>(reply, OP_SETATTR);
  }

  /** ACCESS — which of `mask`'s bits this credential really has. */
  async access(fh: Uint8Array, mask = ACCESS4_ALL): Promise<Access4res> {
    const reply = checkCompound(
      await this.compound([putfh(fh), op(OP_ACCESS, { access: mask })], { tag: "access" }),
      "access",
    );
    return resFor<Access4res>(reply, OP_ACCESS);
  }

  /** READLINK. */
  async readlink(fh: Uint8Array): Promise<string> {
    const reply = checkCompound(
      await this.compound([putfh(fh), op(OP_READLINK)], { tag: "readlink" }),
      "readlink",
    );
    return resFor<Readlink4res>(reply, OP_READLINK).link!;
  }

  /**
   * VERIFY / NVERIFY, answering with the status rather than throwing.
   *
   * `NFS4_OK` and `NFS4ERR_NOT_SAME` (or `NFS4ERR_SAME`) are both *answers*
   * here, not failures, which is the one place where a non-OK compound status
   * is the point of the call.
   */
  async verify(fh: Uint8Array, attrs: Fattr4, negated = false): Promise<number> {
    const reply = await this.compound(
      [putfh(fh), op(negated ? OP_NVERIFY : OP_VERIFY, { objAttributes: attrs })],
      { tag: negated ? "nverify" : "verify" },
    );
    return reply.status;
  }

  /** SECINFO — the auth flavors `name` under `dir` may be reached with. */
  async secinfo(dir: Uint8Array, name: string): Promise<Secinfo4res> {
    const reply = checkCompound(
      await this.compound([putfh(dir), op(OP_SECINFO, { name })], { tag: "secinfo" }),
      "lookup",
      name,
    );
    return resFor<Secinfo4res>(reply, OP_SECINFO);
  }

  // --- mutating the namespace ---------------------------------------------

  /**
   * CREATE — the non-regular objects.
   *
   * NFSv4 has no MKDIR, SYMLINK or MKNOD: one operation makes everything that
   * is not an ordinary file, and an ordinary file is made by OPEN instead.
   */
  async create(
    dir: Uint8Array,
    name: string,
    objtype: { type: number; linkdata?: string; devdata?: { major: number; minor: number } },
    values: Fattr4Values = {},
    bits: Bitmap4 = settableMask(values),
  ): Promise<{ fh: Uint8Array; cinfo: ChangeInfo4; attrset: Bitmap4 }> {
    const reply = checkCompound(
      await this.compound(
        [
          putfh(dir),
          op(OP_CREATE, { objtype, objname: name, createattrs: fattr(bits, values) }),
          op(OP_GETFH),
        ],
        { tag: "create" },
      ),
      "mkdir",
      name,
    );
    const created = resFor<Create4res>(reply, OP_CREATE);
    return {
      fh: resFor<Getfh4res>(reply, OP_GETFH).object!,
      cinfo: created.cinfo!,
      attrset: created.attrset!,
    };
  }

  /** CREATE of an `NF4DIR`. */
  mkdir(dir: Uint8Array, name: string, mode = 0o777): Promise<{ fh: Uint8Array }> {
    return this.create(dir, name, { type: NF4DIR }, { mode: mode & 0o7777 });
  }

  /** CREATE of an `NF4LNK`. */
  symlink(dir: Uint8Array, name: string, target: string): Promise<{ fh: Uint8Array }> {
    return this.create(dir, name, { type: NF4LNK, linkdata: target });
  }

  /** CREATE of a device or a named pipe, `type` being an `nfs_ftype4`. */
  mknod(
    dir: Uint8Array,
    name: string,
    type: number,
    options: { mode?: number; major?: number; minor?: number } = {},
  ): Promise<{ fh: Uint8Array }> {
    return this.create(
      dir,
      name,
      {
        type,
        devdata: { major: options.major ?? 0, minor: options.minor ?? 0 },
      },
      options.mode === undefined ? {} : { mode: options.mode & 0o7777 },
    );
  }

  /** REMOVE — `unlink` and `rmdir` at once, as v4 has only the one operation. */
  async remove(dir: Uint8Array, name: string): Promise<Remove4res> {
    const reply = checkCompound(
      await this.compound([putfh(dir), op(OP_REMOVE, { target: name })], { tag: "remove" }),
      "unlink",
      name,
    );
    return resFor<Remove4res>(reply, OP_REMOVE);
  }

  /** RENAME, which needs both directories on the cursor: SAVEFH then PUTFH. */
  async rename(
    fromDir: Uint8Array,
    fromName: string,
    toDir: Uint8Array,
    toName: string,
  ): Promise<Rename4res> {
    const reply = checkCompound(
      await this.compound(
        [
          putfh(fromDir),
          op(OP_SAVEFH),
          putfh(toDir),
          op(OP_RENAME, { oldname: fromName, newname: toName }),
        ],
        { tag: "rename" },
      ),
      "rename",
      fromName,
    );
    return resFor<Rename4res>(reply, OP_RENAME);
  }

  /** LINK — the source on the saved filehandle, the directory on the current one. */
  async link(file: Uint8Array, dir: Uint8Array, name: string): Promise<ChangeInfo4> {
    const reply = checkCompound(
      await this.compound(
        [putfh(file), op(OP_SAVEFH), putfh(dir), op(OP_LINK, { newname: name })],
        { tag: "link" },
      ),
      "link",
      name,
    );
    return resFor<Link4res>(reply, OP_LINK).cinfo!;
  }

  // --- READDIR -------------------------------------------------------------

  /** One READDIR page. */
  async readdir(
    dir: Uint8Array,
    options: {
      cookie?: bigint;
      cookieverf?: Uint8Array;
      dircount?: number;
      maxcount?: number;
      attrRequest?: Bitmap4;
    } = {},
  ): Promise<Readdir4res> {
    const reply = checkCompound(
      await this.compound(
        [
          putfh(dir),
          op(OP_READDIR, {
            cookie: options.cookie ?? 0n,
            cookieverf: options.cookieverf ?? new Uint8Array(NFS4_VERIFIER_SIZE),
            dircount: options.dircount ?? 4096,
            maxcount: options.maxcount ?? 8192,
            attrRequest: options.attrRequest ?? [],
          }),
        ],
        { tag: "readdir" },
      ),
      "scandir",
    );
    return resFor<Readdir4res>(reply, OP_READDIR);
  }

  /** Every entry of a directory, paging through the cookies. */
  async readdirAll(
    dir: Uint8Array,
    options: { attrRequest?: Bitmap4; dircount?: number; maxcount?: number } = {},
  ): Promise<Entry4[]> {
    const all: Entry4[] = [];
    let cookie = 0n;
    let cookieverf: Uint8Array = new Uint8Array(NFS4_VERIFIER_SIZE);
    for (;;) {
      const page = await this.readdir(dir, { ...options, cookie, cookieverf });
      all.push(...page.reply.entries);
      if (page.reply.eof) {
        return all;
      }
      const last = page.reply.entries.at(-1);
      if (last === undefined) {
        // Not eof and not an entry either: there is no cookie to advance to, so
        // looping would spin forever on a server bug rather than report one.
        throw new Rpc4Error("READDIR returned an empty page without eof");
      }
      cookieverf = page.cookieverf;
      cookie = last.cookie;
    }
  }

  // --- OPEN, I/O and locks --------------------------------------------------

  /**
   * OPEN a file by path, creating it if the flags say so.
   *
   * The open-owner is this client's business, not the caller's: each call gets
   * a fresh one, so two opens of the same file behave like two file
   * descriptors rather than silently unioning into one stateid.
   */
  async open(path: string, flags: string | number = "r", mode = 0o666): Promise<Nfs4File> {
    const numeric = typeof flags === "number" ? flags : openFlagsOf(flags);
    const normalized = normalizePath(path);
    const dir = await this.walk(dirname(normalized));
    return this.openAt(dir.fh, basename(normalized), {
      access: shareAccessOf(numeric),
      create: (numeric & constants.O_CREAT) !== 0,
      exclusive: (numeric & constants.O_EXCL) !== 0,
      truncate: (numeric & constants.O_TRUNC) !== 0,
      mode,
      path: normalized,
    });
  }

  /** OPEN `name` under `dir`, the operation itself. */
  async openAt(
    dir: Uint8Array,
    name: string,
    options: {
      access?: number;
      deny?: number;
      create?: boolean;
      exclusive?: boolean;
      truncate?: boolean;
      mode?: number;
      owner?: Uint8Array;
      path?: string;
    } = {},
  ): Promise<Nfs4File> {
    const access = options.access ?? OPEN4_SHARE_ACCESS_READ;
    const values: Fattr4Values = {};
    if (options.create === true) {
      values.mode = (options.mode ?? 0o666) & 0o7777;
      if (options.truncate === true) {
        values.size = 0n;
      }
    }
    const openhow =
      options.create === true
        ? {
            opentype: OPEN4_CREATE,
            how: {
              mode: options.exclusive === true ? GUARDED4 : UNCHECKED4,
              createattrs: fattr(settableMask(values), values),
            },
          }
        : { opentype: OPEN4_NOCREATE };
    const owner = options.owner ?? encoder.encode(`open-owner-${this.#owners++}`);
    const reply = checkCompound(
      await this.compound(
        [
          putfh(dir),
          op(OP_OPEN, {
            // §18.16.3: the seqid and the owner's clientid are both ignored at
            // 4.1. Zero is what a 4.1 client sends.
            seqid: 0,
            shareAccess: access,
            shareDeny: options.deny ?? OPEN4_SHARE_DENY_NONE,
            owner: { clientid: 0n, owner },
            openhow,
            claim: { claim: CLAIM_NULL, file: name },
          }),
          op(OP_GETFH),
        ],
        { tag: "open", cachethis: true },
      ),
      "open",
      options.path ?? name,
    );
    const opened = resFor<Open4res>(reply, OP_OPEN);
    const file = new Nfs4File(
      this,
      resFor<Getfh4res>(reply, OP_GETFH).object!,
      opened.stateid!,
      access,
      owner,
    );
    if (options.truncate === true && options.create !== true) {
      await this.setattr(file.fh, { size: 0n }, { stateid: file.stateid, path: options.path });
    }
    return file;
  }

  /** CLOSE. The stateid it answers with is the invalid special one (§18.2.4). */
  async closeFile(fh: Uint8Array, stateid: Stateid4): Promise<Close4res> {
    const reply = checkCompound(
      await this.compound([putfh(fh), op(OP_CLOSE, { seqid: 0, openStateid: stateid })], {
        tag: "close",
        cachethis: true,
      }),
      "close",
    );
    return resFor<Close4res>(reply, OP_CLOSE);
  }

  /** OPEN_DOWNGRADE — narrow an open's share bits, never widen them. */
  async openDowngrade(
    fh: Uint8Array,
    stateid: Stateid4,
    shareAccess: number,
    shareDeny = OPEN4_SHARE_DENY_NONE,
  ): Promise<Stateid4> {
    const reply = checkCompound(
      await this.compound(
        [
          putfh(fh),
          op(OP_OPEN_DOWNGRADE, { openStateid: stateid, seqid: 0, shareAccess, shareDeny }),
        ],
        { tag: "open_downgrade" },
      ),
      "open",
    );
    return resFor<OpenDowngrade4res>(reply, OP_OPEN_DOWNGRADE).openStateid!;
  }

  /** READ. */
  async read(
    fh: Uint8Array,
    offset: bigint,
    count: number,
    stateid: Stateid4 = ANONYMOUS_STATEID,
  ): Promise<Read4res> {
    const reply = checkCompound(
      await this.compound([putfh(fh), op(OP_READ, { stateid, offset, count })], { tag: "read" }),
      "read",
    );
    return resFor<Read4res>(reply, OP_READ);
  }

  /** WRITE. The server MAY take fewer bytes than offered, so the count is the answer. */
  async write(
    fh: Uint8Array,
    offset: bigint,
    data: Uint8Array,
    stateid: Stateid4 = ANONYMOUS_STATEID,
    stable = FILE_SYNC4,
  ): Promise<Write4res> {
    const reply = checkCompound(
      await this.compound([putfh(fh), op(OP_WRITE, { stateid, offset, stable, data })], {
        tag: "write",
      }),
      "write",
    );
    return resFor<Write4res>(reply, OP_WRITE);
  }

  /** COMMIT — `count` 0 meaning "to the end of the file" (§18.3.3). */
  async commit(fh: Uint8Array, offset = 0n, count = 0): Promise<Commit4res> {
    const reply = checkCompound(
      await this.compound([putfh(fh), op(OP_COMMIT, { offset, count })], { tag: "commit" }),
      "fsync",
    );
    return resFor<Commit4res>(reply, OP_COMMIT);
  }

  /**
   * LOCK with `new_lock_owner` TRUE — the first lock a lock-owner takes.
   *
   * The three seqids §18.10.3 orders the server to ignore go out as zero, and
   * the owner's clientid with them: they are 4.0 fields with no meaning here.
   */
  async lock(
    fh: Uint8Array,
    options: {
      openStateid: Stateid4;
      owner: Uint8Array;
      locktype?: number;
      offset?: bigint;
      length?: bigint;
      reclaim?: boolean;
    },
  ): Promise<Lock4res> {
    const reply = await this.compound(
      [
        putfh(fh),
        op(OP_LOCK, {
          locktype: options.locktype ?? WRITE_LT,
          reclaim: options.reclaim ?? false,
          offset: options.offset ?? 0n,
          length: options.length ?? 0xff_ff_ff_ff_ff_ff_ff_ffn,
          locker: {
            newLockOwner: true,
            openOwner: {
              openSeqid: 0,
              openStateid: options.openStateid,
              lockSeqid: 0,
              lockOwner: { clientid: 0n, owner: options.owner },
            },
          },
        }),
      ],
      { tag: "lock", cachethis: true },
    );
    return resFor<Lock4res>(reply, OP_LOCK);
  }

  /** LOCK with `new_lock_owner` FALSE — a lock-owner that already holds one. */
  async lockMore(
    fh: Uint8Array,
    options: {
      lockStateid: Stateid4;
      locktype?: number;
      offset?: bigint;
      length?: bigint;
    },
  ): Promise<Lock4res> {
    const reply = await this.compound(
      [
        putfh(fh),
        op(OP_LOCK, {
          locktype: options.locktype ?? WRITE_LT,
          reclaim: false,
          offset: options.offset ?? 0n,
          length: options.length ?? 0xff_ff_ff_ff_ff_ff_ff_ffn,
          locker: {
            newLockOwner: false,
            lockOwner: { lockStateid: options.lockStateid, lockSeqid: 0 },
          },
        }),
      ],
      { tag: "lock", cachethis: true },
    );
    return resFor<Lock4res>(reply, OP_LOCK);
  }

  /** LOCKT — would this lock be granted? `undefined` means yes. */
  async lockt(
    fh: Uint8Array,
    options: { owner: Uint8Array; locktype?: number; offset?: bigint; length?: bigint },
  ): Promise<Lock4denied | undefined> {
    const reply = await this.compound(
      [
        putfh(fh),
        op(OP_LOCKT, {
          locktype: options.locktype ?? WRITE_LT,
          offset: options.offset ?? 0n,
          length: options.length ?? 0xff_ff_ff_ff_ff_ff_ff_ffn,
          owner: { clientid: 0n, owner: options.owner },
        }),
      ],
      { tag: "lockt" },
    );
    const res = resFor<Lockt4res>(reply, OP_LOCKT);
    if (res.status === NFS4_OK) {
      return undefined;
    }
    if (res.denied !== undefined) {
      return res.denied;
    }
    throw nfs4Error(res.status, "lock");
  }

  /** LOCKU. */
  async locku(
    fh: Uint8Array,
    options: { lockStateid: Stateid4; locktype?: number; offset?: bigint; length?: bigint },
  ): Promise<Stateid4> {
    const reply = checkCompound(
      await this.compound(
        [
          putfh(fh),
          op(OP_LOCKU, {
            locktype: options.locktype ?? WRITE_LT,
            seqid: 0,
            lockStateid: options.lockStateid,
            offset: options.offset ?? 0n,
            length: options.length ?? 0xff_ff_ff_ff_ff_ff_ff_ffn,
          }),
        ],
        { tag: "locku", cachethis: true },
      ),
      "lock",
    );
    return resFor<Locku4res>(reply, OP_LOCKU).lockStateid!;
  }

  /** TEST_STATEID — one status per stateid offered, in order. */
  async testStateid(stateids: Stateid4[]): Promise<number[]> {
    const reply = checkCompound(
      await this.compound([op(OP_TEST_STATEID, { stateids })], { tag: "test_stateid" }),
      "fstat",
    );
    return resFor<TestStateid4res>(reply, OP_TEST_STATEID).statusCodes;
  }

  /** FREE_STATEID. */
  async freeStateid(stateid: Stateid4): Promise<number> {
    const reply = await this.compound([op(OP_FREE_STATEID, { stateid })], { tag: "free_stateid" });
    return resFor<Status4res>(reply, OP_FREE_STATEID).status;
  }
}

/** Did the server accept the SEQUENCE and therefore advance the slot? */
function accepted(reply: Compound4reply): boolean {
  const first: Resop4 | undefined = reply.resarray[0];
  return (
    first !== undefined &&
    first.op === OP_SEQUENCE &&
    (first.res as Sequence4res).status === NFS4_OK
  );
}

// ---------------------------------------------------------------------------
// an open file
// ---------------------------------------------------------------------------

/**
 * One OPEN's worth of state: the filehandle, the stateid, and a position.
 *
 * The stateid is not constant — every OPEN of the same file by the same owner
 * bumps its `seqid`, and CLOSE invalidates it — so it is held here rather than
 * copied out, and I/O through this object always sends the current one.
 */
export class Nfs4File {
  #position = 0n;
  #closed = false;
  #lockStateid: Stateid4 | undefined;

  constructor(
    readonly client: Nfs4Client,
    readonly fh: Uint8Array,
    public stateid: Stateid4,
    public access: number,
    /** The open-owner behind it, reused as this file's lock-owner. */
    readonly owner: Uint8Array,
  ) {}

  /** Where a positional read or write will land next. */
  get position(): bigint {
    return this.#position;
  }

  set position(offset: bigint) {
    this.#position = offset;
  }

  get closed(): boolean {
    return this.#closed;
  }

  /** The lock stateid this file holds, once it has taken a lock. */
  get lockStateid(): Stateid4 | undefined {
    return this.#lockStateid;
  }

  /** READ, advancing the position unless `at` names one. */
  async read(count: number, at?: bigint): Promise<Read4res> {
    const offset = at ?? this.#position;
    const result = await this.client.read(this.fh, offset, count, this.stateid);
    if (at === undefined) {
      this.#position = offset + BigInt(result.data.byteLength);
    }
    return result;
  }

  /** WRITE, advancing the position unless `at` names one. */
  async write(data: Uint8Array, at?: bigint, stable = FILE_SYNC4): Promise<Write4res> {
    const offset = at ?? this.#position;
    const result = await this.client.write(this.fh, offset, data, this.stateid, stable);
    if (at === undefined) {
      this.#position = offset + BigInt(result.count);
    }
    return result;
  }

  /** GETATTR on the open file. */
  stat(attrRequest?: Bitmap4): Promise<Fattr4Values> {
    return this.client.getattr(this.fh, attrRequest);
  }

  /** SETATTR of `size`, through this open's stateid. */
  async truncate(size = 0n): Promise<void> {
    await this.client.setattr(this.fh, { size }, { stateid: this.stateid });
  }

  /** COMMIT. */
  async sync(): Promise<void> {
    await this.client.commit(this.fh);
  }

  /** OPEN_DOWNGRADE, keeping the stateid this object sends. */
  async downgrade(shareAccess: number, shareDeny = OPEN4_SHARE_DENY_NONE): Promise<void> {
    this.stateid = await this.client.openDowngrade(this.fh, this.stateid, shareAccess, shareDeny);
    this.access = shareAccess;
  }

  /**
   * LOCK a byte range, picking the right `locker4` arm.
   *
   * The first lock this file takes establishes its lock-owner from the open
   * stateid; every later one rides the lock stateid that came back, which is
   * the `new_lock_owner == FALSE` arm.
   */
  async lock(
    options: { locktype?: number; offset?: bigint; length?: bigint } = {},
  ): Promise<Lock4res> {
    const result =
      this.#lockStateid === undefined
        ? await this.client.lock(this.fh, {
            ...options,
            openStateid: this.stateid,
            owner: this.owner,
          })
        : await this.client.lockMore(this.fh, { ...options, lockStateid: this.#lockStateid });
    if (result.status === NFS4_OK) {
      this.#lockStateid = result.lockStateid!;
    }
    return result;
  }

  /** LOCKT against this file's own lock-owner. */
  testLock(
    options: { locktype?: number; offset?: bigint; length?: bigint } = {},
  ): Promise<Lock4denied | undefined> {
    return this.client.lockt(this.fh, { ...options, owner: this.owner });
  }

  /** LOCKU of a range this file holds. */
  async unlock(
    options: { locktype?: number; offset?: bigint; length?: bigint } = {},
  ): Promise<void> {
    if (this.#lockStateid === undefined) {
      throw new Rpc4Error("no lock to release");
    }
    this.#lockStateid = await this.client.locku(this.fh, {
      ...options,
      lockStateid: this.#lockStateid,
    });
  }

  /** CLOSE. Idempotent, so a `finally` can call it without checking. */
  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.stateid = (await this.client.closeFile(this.fh, this.stateid)).openStateid!;
  }
}

// ---------------------------------------------------------------------------
// flags
// ---------------------------------------------------------------------------

/** `node:fs`'s flag strings, as `O_*` bits. */
export function openFlagsOf(flags: string): number {
  switch (flags) {
    case "r": {
      return constants.O_RDONLY;
    }
    case "r+": {
      return constants.O_RDWR;
    }
    case "w": {
      return constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC;
    }
    case "wx": {
      return constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL;
    }
    case "w+": {
      return constants.O_RDWR | constants.O_CREAT | constants.O_TRUNC;
    }
    case "wx+": {
      return constants.O_RDWR | constants.O_CREAT | constants.O_EXCL;
    }
    case "a": {
      return constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND;
    }
    case "ax": {
      return constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_APPEND;
    }
    case "a+": {
      return constants.O_RDWR | constants.O_CREAT | constants.O_APPEND;
    }
    default: {
      throw new Error(`mountx test client: unsupported open flags ${JSON.stringify(flags)}`);
    }
  }
}

/**
 * `O_*` as `OPEN4_SHARE_ACCESS_*`.
 *
 * The two namespaces are unrelated: `O_RDONLY` is zero and
 * `OPEN4_SHARE_ACCESS_READ` is one, so this is a translation and not a mask.
 */
export function shareAccessOf(flags: number): number {
  if ((flags & constants.O_RDWR) !== 0) {
    return OPEN4_SHARE_ACCESS_BOTH;
  }
  return (flags & constants.O_WRONLY) === 0 ? OPEN4_SHARE_ACCESS_READ : OPEN4_SHARE_ACCESS_WRITE;
}
