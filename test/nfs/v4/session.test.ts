/**
 * Tier 0 for `src/nfs/v4/session.ts`: COMPOUND dispatch driven with encoded
 * bytes over the memory driver.
 *
 * Everything here goes in and comes out as an RPC record, because that is the
 * only way to prove the decoder, the dispatcher and the encoder meet in the
 * middle — a test that called the handlers directly would pass with a codec
 * that never framed anything.
 *
 * Two habits are load-bearing:
 *
 * - **The replay cache is proved by a counter, not by a status.** A
 *   retransmission is only correct if the driver-call counter *does not move*
 *   and the `COMPOUND4res` bytes come back identical. A server that re-executed
 *   and happened to produce the same reply would pass a byte comparison alone,
 *   so both halves are asserted. The same counter proves that a halted COMPOUND
 *   really stopped rather than running on and discarding results.
 * - **The reply is read with a tolerant decoder.** `readCompoundRes` resolves
 *   every resop through `opCodec4`, which throws for an operation with no codec
 *   row — and a status-only resop for exactly such an operation is what a
 *   `NFS4ERR_NOTSUPP` answer looks like. {@link readReply} mirrors the
 *   session's own encoder instead.
 */

import { afterEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../../src/drivers/memory.ts";
import { fsError } from "../../../src/errors.ts";
import {
  AUTH_SYS,
  authSys,
  decodeReply,
  encodeAuthSys,
  encodeCall,
  MSG_ACCEPTED,
  type OpaqueAuth,
  RPC_PROC_UNAVAIL,
  RPC_SUCCESS,
} from "../../../src/nfs/rpc.ts";
import { NfsSession } from "../../../src/nfs/session.ts";
import type { FileHandleLike, FsDriver, FullFsDriver } from "../../../src/types.ts";
import { S_IFIFO } from "../../../src/types.ts";
import {
  bitmapHas,
  bitmapOf,
  type Fattr4Values,
  fromTime4,
  type NfsTime4,
  writeBitmap,
} from "../../../src/nfs/v4/attr.ts";
import {
  ACCESS4_ALL,
  ACCESS4_EXECUTE,
  ACCESS4_LOOKUP,
  ACCESS4_MODIFY,
  ACCESS4_READ,
  CLAIM_DELEG_CUR_FH,
  CLAIM_DELEG_PREV_FH,
  CLAIM_DELEGATE_CUR,
  CLAIM_FH,
  CLAIM_NULL,
  CLAIM_PREVIOUS,
  EXCLUSIVE4,
  EXCLUSIVE4_1,
  FATTR4_CHANGE,
  FATTR4_FILEID,
  FATTR4_MODE,
  FATTR4_NUMLINKS,
  FATTR4_OWNER,
  FATTR4_RAWDEV,
  FATTR4_RDATTR_ERROR,
  FATTR4_SIZE,
  FATTR4_SPACE_TOTAL,
  FATTR4_OWNER_GROUP,
  FATTR4_SUPPORTED_ATTRS,
  FILE_SYNC4,
  GUARDED4,
  FATTR4_TIME_ACCESS_SET,
  FATTR4_TIME_MODIFY,
  FATTR4_TIME_MODIFY_SET,
  FATTR4_TYPE,
  NF4CHR,
  NF4DIR,
  NF4FIFO,
  NF4LNK,
  NF4REG,
  NFS4_OK,
  NFS4_PROGRAM,
  NFS4ERR_ATTRNOTSUPP,
  NFS4ERR_BAD_STATEID,
  NFS4ERR_BADOWNER,
  NFS4ERR_BADTYPE,
  NFS4ERR_DENIED,
  NFS4ERR_EXIST,
  NFS4ERR_GRACE,
  NFS4ERR_INVAL,
  NFS4ERR_ISDIR,
  NFS4ERR_LOCKED,
  NFS4ERR_LOCKS_HELD,
  NFS4ERR_NO_GRACE,
  NFS4ERR_OLD_STATEID,
  NFS4ERR_OPENMODE,
  NFS4ERR_REP_TOO_BIG_TO_CACHE,
  NFS4ERR_SHARE_DENIED,
  NFS4ERR_SYMLINK,
  NFS4ERR_WRONG_TYPE,
  NFS4ERR_MINOR_VERS_MISMATCH,
  NFS4ERR_NOENT,
  NFS4ERR_NOFILEHANDLE,
  NFS4ERR_NOT_ONLY_OP,
  NFS4ERR_NOT_SAME,
  NFS4ERR_NOTDIR,
  NFS4ERR_NOTEMPTY,
  NFS4ERR_NOTSUPP,
  NFS4ERR_OP_ILLEGAL,
  NFS4ERR_OP_NOT_IN_SESSION,
  NFS4ERR_SAME,
  NFS4ERR_SEQ_MISORDERED,
  NFS4ERR_SEQUENCE_POS,
  NFS4ERR_TOO_MANY_OPS,
  NFS_V4,
  NFSPROC4_COMPOUND,
  NFSPROC4_NULL,
  OP_ACCESS,
  OP_CLOSE,
  OP_CREATE,
  OP_CREATE_SESSION,
  OP_DELEGRETURN,
  OP_EXCHANGE_ID,
  OP_GETATTR,
  OP_GETFH,
  OP_LINK,
  OP_LOCKT,
  OP_LOCKU,
  OP_LOOKUP,
  OP_LOOKUPP,
  OP_NVERIFY,
  OP_OPEN,
  OP_OPEN_DOWNGRADE,
  OP_PUTFH,
  OP_PUTROOTFH,
  OP_LOCK,
  OP_READ,
  OP_READDIR,
  OP_READLINK,
  OP_RECLAIM_COMPLETE,
  OP_REMOVE,
  OP_RENAME,
  OP_RESTOREFH,
  OP_SAVEFH,
  OP_SECINFO,
  OP_SEQUENCE,
  OP_SETATTR,
  OP_VERIFY,
  OP_WRITE,
  OPEN_DELEGATE_NONE,
  OPEN_DELEGATE_NONE_EXT,
  OPEN4_CREATE,
  OPEN4_NOCREATE,
  OPEN4_RESULT_LOCKTYPE_POSIX,
  OPEN4_SHARE_ACCESS_BOTH,
  OPEN4_SHARE_ACCESS_READ,
  OPEN4_SHARE_ACCESS_WANT_CANCEL,
  OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
  OPEN4_SHARE_ACCESS_WANT_READ_DELEG,
  OPEN4_SHARE_ACCESS_WRITE,
  OPEN4_SHARE_DENY_NONE,
  OPEN4_SHARE_DENY_READ,
  OPEN4_SHARE_DENY_WRITE,
  READ_LT,
  SET_TO_CLIENT_TIME4,
  SP4_NONE,
  UNCHECKED4,
  UNSTABLE4,
  WND4_CANCELLED,
  WND4_NOT_WANTED,
  WND4_RESOURCE,
  WRITE_LT,
} from "../../../src/nfs/v4/constants.ts";
import {
  type Access4res,
  type ChannelAttrs4,
  type Compound4res,
  type Create4res,
  type CreateType4,
  type CreateSession4res,
  type ExchangeId4res,
  type Getattr4res,
  type Getfh4res,
  type Lock4res,
  type Lockt4res,
  type Locku4res,
  type Open4res,
  type OpenDowngrade4res,
  type Read4res,
  NFS4_MAX_TAG,
  OP_CODECS,
  type Readdir4res,
  type Readlink4res,
  type Remove4res,
  type Rename4res,
  type Resop4,
  type Secinfo4res,
  type Sequence4res,
  type Close4res,
  type Setattr4res,
  type Stateid4,
  type Status4res,
  type Write4res,
} from "../../../src/nfs/v4/protocol.ts";
import { Nfs4Session } from "../../../src/nfs/v4/session.ts";
import { XdrWriter } from "../../../src/nfs/xdr.ts";
import { createLoopback } from "../../../src/harness.ts";
import { createNfsServer, type NfsServer } from "../../../src/nfs/server.ts";
import { withoutExtensions } from "../../no-extensions.ts";
import { CREATE_EXCLUSIVE, NFS3ERR_EXIST } from "../../../src/nfs/v3/constants.ts";
import { check as check3, NfsClient as Nfs3Client, nfsDriver } from "../v3/client.ts";
import {
  type Compound4reply,
  fattr,
  Nfs4Client,
  type Nfs4ClientOptions,
  OBJECT_ATTRS,
  op as argop,
  resFor as resFor4,
} from "./client.ts";

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

/**
 * One operation to encode.
 *
 * `args` is `undefined` for a void `nfs_argop4` arm. `raw` bypasses the codec
 * entirely, which is how a `fattr4` naming an attribute this server does not
 * support gets onto the wire at all — `encodeFattr` intersects the mask it is
 * given with what it can write, so an unsupported bit can only be *sent* by
 * hand.
 */
interface Op {
  op: number;
  args?: unknown;
  raw?: Uint8Array;
}

/** `bitmap4` + `attrlist4`, with no intersection applied. */
function rawFattr(writer: XdrWriter, bits: number[], values: Uint8Array): void {
  writeBitmap(writer, bitmapOf(bits));
  writer.varOpaque(values);
}

/** A `fattr4` with a hand-built mask, as an operation's whole argument body. */
function rawFattrArgs(bits: number[], values: Uint8Array, stateid = false): Uint8Array {
  const writer = new XdrWriter(64);
  if (stateid) {
    writer.u32(0);
    writer.fixedOpaque(new Uint8Array(12), 12);
  }
  rawFattr(writer, bits, values);
  return writer.bytes();
}

let nextXid = 1;

/**
 * Encode a COMPOUND call.
 *
 * Deliberately not `writeCompoundArgs`: an opcode with no codec row (a
 * DELEGRETURN, an opnum that is not an operation at all) has to be *sendable*
 * for the halt paths to be testable, and that function throws instead.
 */
function compoundCall(
  ops: Op[],
  options: {
    tag?: string;
    minorversion?: number;
    xid?: number;
    count?: number;
    cred?: OpaqueAuth;
  } = {},
): { xid: number; bytes: Uint8Array } {
  const writer = new XdrWriter(512);
  writer.string(options.tag ?? "");
  writer.u32(options.minorversion ?? 1);
  writer.u32(options.count ?? ops.length);
  for (const entry of ops) {
    writer.u32(entry.op);
    if (entry.raw !== undefined) {
      writer.raw(entry.raw);
      continue;
    }
    const codec = OP_CODECS.get(entry.op);
    if (codec?.writeArgs !== undefined && entry.args !== undefined) {
      codec.writeArgs(writer, entry.args as never);
    }
  }
  const xid = options.xid ?? nextXid++;
  return {
    xid,
    bytes: encodeCall({
      xid,
      program: NFS4_PROGRAM,
      version: NFS_V4,
      procedure: NFSPROC4_COMPOUND,
      cred: options.cred ?? authSys(1000, 1000),
      args: writer.bytes(),
    }),
  };
}

/** A `COMPOUND4res` plus the raw body, which is what a slot caches. */
interface Reply {
  acceptStat: number | undefined;
  compound: Compound4res;
  /** The encoded `COMPOUND4res`, past the RPC header. */
  body: Uint8Array;
}

/** The mirror of the session's own tolerant encoder. */
function readReply(bytes: Uint8Array): Reply {
  const { reply, results } = decodeReply(bytes);
  expect(reply.replyStat).toBe(MSG_ACCEPTED);
  if (reply.acceptStat !== RPC_SUCCESS) {
    return {
      acceptStat: reply.acceptStat,
      compound: { status: NFS4_OK, tag: "", resarray: [] },
      body: new Uint8Array(0),
    };
  }
  const body = bytes.slice(results.offset);
  const status = results.u32("COMPOUND4res.status");
  const tag = results.string(NFS4_MAX_TAG, "COMPOUND4res.tag");
  const count = results.u32("COMPOUND4res.resarray count");
  const resarray: Resop4[] = [];
  for (let index = 0; index < count; index++) {
    const op = results.u32("nfs_resop4.resop");
    const codec = OP_CODECS.get(op);
    resarray.push({
      op,
      res: codec === undefined ? { status: results.u32("nfsstat4") } : codec.readRes(results),
    });
  }
  results.end("COMPOUND4res");
  return { acceptStat: reply.acceptStat, compound: { status, tag, resarray }, body };
}

/** The status of the resop at `index`, whatever its shape. */
function statusAt(reply: Reply, index: number): number {
  return (reply.compound.resarray[index]!.res as Status4res).status;
}

/**
 * The result for an operation, found by opcode rather than by position.
 *
 * The compounds below vary in how many operations it takes to reach the file,
 * and counting them into an index is how a test ends up asserting against the
 * wrong operation's result and passing.
 */
function resFor<T>(reply: Reply, op: number): T {
  const found = reply.compound.resarray.find((entry) => entry.op === op);
  expect(found, `no result for opcode ${op}`).toBeDefined();
  return found!.res as T;
}

/** {@link resFor}'s status. */
function statusFor(reply: Reply, op: number): number {
  return resFor<Status4res>(reply, op).status;
}

/** The `fattr4` values of the compound's GETATTR. */
function attrsFor(reply: Reply): Fattr4Values {
  const res = resFor<Getattr4res>(reply, OP_GETATTR);
  expect(res.status).toBe(NFS4_OK);
  return res.objAttributes!.values;
}

/** UTF-8 bytes, for the READ and WRITE payloads. */
function b(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Count every driver method call, so "did this run?" is answerable. */
function counting(driver: FsDriver): { driver: FsDriver; counts: Map<string, number> } {
  const counts = new Map<string, number>();
  const proxy = new Proxy(driver, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver) as unknown;
      if (typeof value !== "function") {
        return value;
      }
      return (...args: unknown[]) => {
        const key = String(property);
        counts.set(key, (counts.get(key) ?? 0) + 1);
        return (value as (...rest: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return { driver: proxy as FsDriver, counts };
}

const CHANNEL: ChannelAttrs4 = {
  headerpadsize: 0,
  maxrequestsize: 65_536,
  maxresponsesize: 65_536,
  maxresponsesizeCached: 16_384,
  maxoperations: 16,
  maxrequests: 4,
  rdmaIrd: [],
};

/**
 * A session with one client registered and one 4.1 session open, plus the slot
 * bookkeeping every subsequent COMPOUND needs.
 */
class Client {
  sessionid: Uint8Array = new Uint8Array(16);
  slotSeqid = 0;
  clientid = 0n;

  constructor(
    readonly session: Nfs4Session,
    /** The credential every compound this client sends carries. */
    readonly cred?: OpaqueAuth,
  ) {}

  static async open(
    session: Nfs4Session,
    ownerid = "test-client",
    cred?: OpaqueAuth,
  ): Promise<Client> {
    const client = new Client(session, cred);
    const exchange = await client.send([
      {
        op: OP_EXCHANGE_ID,
        args: {
          clientowner: {
            verifier: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
            ownerid: new TextEncoder().encode(ownerid),
          },
          flags: 0,
          stateProtect: { how: SP4_NONE },
          clientImplId: [],
        },
      },
    ]);
    const exchangeRes = exchange.compound.resarray[0]!.res as ExchangeId4res;
    expect(exchangeRes.status).toBe(NFS4_OK);
    client.clientid = exchangeRes.clientid;

    const created = await client.send([
      {
        op: OP_CREATE_SESSION,
        args: {
          clientid: exchangeRes.clientid,
          sequence: exchangeRes.sequenceid,
          flags: 0,
          foreChanAttrs: CHANNEL,
          backChanAttrs: CHANNEL,
          cbProgram: 0,
          secParms: [],
        },
      },
    ]);
    const createdRes = created.compound.resarray[0]!.res as CreateSession4res;
    expect(createdRes.status).toBe(NFS4_OK);
    client.sessionid = createdRes.sessionid;
    return client;
  }

  /** A raw compound, with no SEQUENCE prepended. */
  async send(ops: Op[], options: Parameters<typeof compoundCall>[1] = {}): Promise<Reply> {
    const { bytes } = compoundCall(ops, { cred: this.cred, ...options });
    const reply = await this.session.handleCall(bytes);
    expect(reply).not.toBeNull();
    return readReply(reply!);
  }

  /** The SEQUENCE argument for the next request on slot 0. */
  sequence(options: { cachethis?: boolean; slotid?: number; sequenceid?: number } = {}): Op {
    return {
      op: OP_SEQUENCE,
      args: {
        sessionid: this.sessionid,
        sequenceid: options.sequenceid ?? this.slotSeqid + 1,
        slotid: options.slotid ?? 0,
        highestSlotid: 0,
        cachethis: options.cachethis ?? false,
      },
    };
  }

  /** A compound led by a fresh SEQUENCE, advancing the slot. */
  async run(ops: Op[], options: { cachethis?: boolean } = {}): Promise<Reply> {
    this.slotSeqid += 1;
    return this.send([
      this.sequence({ cachethis: options.cachethis, sequenceid: this.slotSeqid }),
      ...ops,
    ]);
  }
}

/** A driver with a populated tree, for the namespace tests. */
async function populated(): Promise<FullFsDriver> {
  const driver = createMemoryDriver();
  await driver.mkdir("/dir");
  const file = await driver.open("/dir/file", "w");
  await file.write(new TextEncoder().encode("hello"), 0, 5, 0);
  await file.close();
  await driver.mkdir("/dir/sub");
  await driver.symlink("./file", "/dir/link");
  return driver;
}

/** A decodable EXCHANGE_ID, for the compounds that only care about its position. */
const EXCHANGE_ID_OP: Op = {
  op: OP_EXCHANGE_ID,
  args: {
    clientowner: { verifier: new Uint8Array(8), ownerid: Uint8Array.from([7]) },
    flags: 0,
    stateProtect: { how: SP4_NONE },
    clientImplId: [],
  },
};

/** Look up `/dir` and leave it as the current filehandle. */
const TO_DIR: Op[] = [{ op: OP_PUTROOTFH }, { op: OP_LOOKUP, args: { objname: "dir" } }];

const GETATTR = (bits: number[]): Op => ({ op: OP_GETATTR, args: { attrRequest: bitmapOf(bits) } });

/**
 * `/dir`'s `change` attribute, read in a compound of its own.
 *
 * `change` has the driver's millisecond resolution — `time_delta` says so — so
 * "did it move?" is not a question a test may ask of two samples taken inside
 * one operation. What *is* deterministic is where each half of a
 * `change_info4` came from, and that is what the mutating tests below assert:
 * `before` equals the value observable before the operation and `after` the
 * value observable after it.
 */
async function changeOfPath(client: Client, to: Op[] = TO_DIR): Promise<bigint> {
  const reply = await client.run([...to, GETATTR([FATTR4_CHANGE])]);
  expect(reply.compound.status).toBe(NFS4_OK);
  return attrsOf(reply, to.length + 1).change!;
}

/** `/dir`'s `change`, the directory most of the mutating tests work in. */
function dirChange(client: Client): Promise<bigint> {
  return changeOfPath(client);
}

/** The root's `change`, for the second half of a RENAME's pair. */
function rootChange(client: Client): Promise<bigint> {
  return changeOfPath(client, [{ op: OP_PUTROOTFH }]);
}

/** The decoded attribute values of a GETATTR resop. */
function attrsOf(reply: Reply, index: number): Fattr4Values {
  const res = reply.compound.resarray[index]!.res as Getattr4res;
  expect(res.status).toBe(NFS4_OK);
  return res.objAttributes!.values;
}

// ---------------------------------------------------------------------------
// the RPC layer
// ---------------------------------------------------------------------------

describe("the NFSv4 RPC layer", () => {
  it("answers NULL with an empty accepted reply", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const bytes = encodeCall({
      xid: 7,
      program: NFS4_PROGRAM,
      version: NFS_V4,
      procedure: NFSPROC4_NULL,
    });
    const { reply, results } = decodeReply((await session.handleCall(bytes))!);
    expect(reply.acceptStat).toBe(RPC_SUCCESS);
    expect(results.remaining).toBe(0);
    expect(session.stats.procedures.get("NFS4:NULL")).toBe(1);
  });

  it("refuses a procedure the program does not have", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const bytes = encodeCall({
      xid: 8,
      program: NFS4_PROGRAM,
      version: NFS_V4,
      procedure: 9,
    });
    const { reply } = decodeReply((await session.handleCall(bytes))!);
    expect(reply.acceptStat).toBe(RPC_PROC_UNAVAIL);
  });

  it("drops a record too damaged to address a reply to", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    expect(await session.handleCall(Uint8Array.from([1, 2, 3]))).toBeNull();
    expect(session.stats.dropped).toBe(1);
    expect(session.stats.replies).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// COMPOUND framing
// ---------------------------------------------------------------------------

describe("COMPOUND framing", () => {
  for (const minorversion of [0, 2]) {
    it(`refuses minorversion ${minorversion} with an empty resarray`, async () => {
      const session = new Nfs4Session(createMemoryDriver());
      const reply = await new Client(session).send([{ op: OP_PUTROOTFH }], {
        minorversion,
        tag: "mine",
      });
      // §16.2.3: the status, the tag, and "a zero-length resultdata array".
      expect(reply.compound).toEqual({
        status: NFS4ERR_MINOR_VERS_MISMATCH,
        tag: "mine",
        resarray: [],
      });
    });
  }

  it("does not decode the argument array at all when the minor version is wrong", async () => {
    // §16.2.3: "the NFS4ERR_MINOR_VERS_MISMATCH error takes precedence over all
    // other errors" — including the illegal opcode that follows it here.
    const session = new Nfs4Session(createMemoryDriver());
    const reply = await new Client(session).send([{ op: 4242 }], { minorversion: 0 });
    expect(reply.compound.status).toBe(NFS4ERR_MINOR_VERS_MISMATCH);
  });

  it("answers a zero-operation compound with NFS4_OK", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const reply = await new Client(session).send([], { tag: "empty" });
    expect(reply.compound).toEqual({ status: NFS4_OK, tag: "empty", resarray: [] });
  });

  it("echoes the request's tag", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const client = await Client.open(session);
    const reply = await client.run([{ op: OP_PUTROOTFH }]);
    expect(reply.compound.tag).toBe("");
  });

  it("refuses more operations than the session negotiated", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const client = await Client.open(session);
    client.slotSeqid += 1;
    // `CHANNEL.maxoperations` is 16; nothing is executed and the slot is
    // untouched (§2.10.6.4, §15.1.3.11).
    const ops: Op[] = [client.sequence({ sequenceid: client.slotSeqid })];
    for (let index = 0; index < 20; index++) {
      ops.push({ op: OP_PUTROOTFH });
    }
    const reply = await client.send(ops);
    expect(reply.compound.status).toBe(NFS4ERR_TOO_MANY_OPS);
    expect(reply.compound.resarray).toEqual([]);
    // The slot never moved: the same sequence ID is still the next one.
    client.slotSeqid -= 1;
    const after = await client.run([{ op: OP_PUTROOTFH }]);
    expect(after.compound.status).toBe(NFS4_OK);
  });

  it("refuses a pre-session compound past the absolute ceiling", async () => {
    const session = new Nfs4Session(createMemoryDriver(), { nfs4: { maxOperations: 4 } });
    const reply = await new Client(session).send([
      EXCHANGE_ID_OP,
      { op: OP_PUTROOTFH },
      { op: OP_PUTROOTFH },
      { op: OP_PUTROOTFH },
      { op: OP_PUTROOTFH },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_TOO_MANY_OPS);
  });

  it("answers an undecodable argument array with GARBAGE_ARGS", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    // A count of five with one operation's worth of bytes behind it.
    const reply = await new Client(session).send([{ op: OP_PUTROOTFH }], { count: 5 });
    expect(reply.acceptStat).toBe(4); // RPC_GARBAGE_ARGS
  });
});

// ---------------------------------------------------------------------------
// the session rules
// ---------------------------------------------------------------------------

describe("SEQUENCE and the session rules", () => {
  it("walks EXCHANGE_ID, CREATE_SESSION and SEQUENCE to NFS4_OK", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const client = await Client.open(session);
    expect(client.clientid).not.toBe(0n);
    expect(session.state.sessionCount).toBe(1);

    const reply = await client.run([{ op: OP_PUTROOTFH }]);
    expect(reply.compound.status).toBe(NFS4_OK);
    const sequence = reply.compound.resarray[0]!.res as Sequence4res;
    expect(sequence.status).toBe(NFS4_OK);
    expect([...sequence.sessionid]).toEqual([...client.sessionid]);
    expect(sequence.sequenceid).toBe(client.slotSeqid);
    expect(sequence.slotid).toBe(0);
  });

  it("refuses a non-exempt operation with no SEQUENCE in front of it", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const reply = await new Client(session).send([{ op: OP_PUTROOTFH }, { op: OP_GETFH }]);
    expect(reply.compound.status).toBe(NFS4ERR_OP_NOT_IN_SESSION);
    expect(reply.compound.resarray).toHaveLength(1);
    expect(reply.compound.resarray[0]!.op).toBe(OP_PUTROOTFH);
  });

  it("refuses an exempt operation that is not the only one", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const reply = await new Client(session).send([EXCHANGE_ID_OP, { op: OP_GETFH }]);
    expect(reply.compound.status).toBe(NFS4ERR_NOT_ONLY_OP);
    expect(reply.compound.resarray[0]!.op).toBe(OP_EXCHANGE_ID);
  });

  it("refuses a SEQUENCE past the first position", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const client = await Client.open(session);
    const reply = await client.run([client.sequence({ sequenceid: client.slotSeqid })]);
    expect(reply.compound.status).toBe(NFS4ERR_SEQUENCE_POS);
    expect(reply.compound.resarray).toHaveLength(2);
    expect(statusAt(reply, 0)).toBe(NFS4_OK);
  });

  it("answers a misordered sequence ID with SEQ_MISORDERED and nothing else", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const client = await Client.open(session);
    await client.run([{ op: OP_PUTROOTFH }]);
    const reply = await client.send([
      client.sequence({ sequenceid: client.slotSeqid + 5 }),
      { op: OP_PUTROOTFH },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_SEQ_MISORDERED);
    expect(reply.compound.resarray).toHaveLength(1);
  });

  it("replays a cached reply byte for byte, without re-executing", async () => {
    const { driver, counts } = counting(await populated());
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);

    const ops = [...TO_DIR, GETATTR([FATTR4_TYPE, FATTR4_SIZE])];
    const first = await client.run(ops, { cachethis: true });
    expect(first.compound.status).toBe(NFS4_OK);
    const lstats = counts.get("lstat") ?? 0;
    expect(lstats).toBeGreaterThan(0);

    // The same slot and the same sequence ID: a retransmission.
    const again = await client.send(
      [client.sequence({ sequenceid: client.slotSeqid, cachethis: true }), ...ops],
      { xid: 999_999 },
    );
    // Byte-identical past the RPC header, which is the only part allowed to
    // differ — the xid above is deliberately not the first request's.
    expect([...again.body]).toEqual([...first.body]);
    // And proven-once: the driver was not touched again.
    expect(counts.get("lstat")).toBe(lstats);
  });

  it("answers a retry of an uncached reply on the operation after SEQUENCE", async () => {
    const { driver, counts } = counting(await populated());
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    await client.run(TO_DIR); // cachethis: false
    const lstats = counts.get("lstat") ?? 0;

    const reply = await client.send([client.sequence({ sequenceid: client.slotSeqid }), ...TO_DIR]);
    // §2.10.6.1.3: never on the leading SEQUENCE itself.
    expect(statusAt(reply, 0)).toBe(NFS4_OK);
    expect(statusAt(reply, 1)).toBe(10_068); // NFS4ERR_RETRY_UNCACHED_REP
    expect(reply.compound.resarray).toHaveLength(2);
    expect(counts.get("lstat")).toBe(lstats);
  });

  it("lets a compound destroy the session it rides", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const client = await Client.open(session);
    const reply = await client.run(
      [{ op: 44, args: { sessionid: client.sessionid } }], // OP_DESTROY_SESSION
      { cachethis: true },
    );
    expect(reply.compound.status).toBe(NFS4_OK);
    expect(session.state.sessionCount).toBe(0);
    // The slot table is gone, so a retransmission is a new (and failing)
    // request rather than a replay of a cache that no longer exists — §18.37.3
    // warns the client to expect exactly that.
    const retry = await client.send([
      client.sequence({ sequenceid: client.slotSeqid }),
      { op: OP_PUTROOTFH },
    ]);
    expect(retry.compound.status).toBe(10_052); // NFS4ERR_BADSESSION
  });
});

// ---------------------------------------------------------------------------
// unknown and unimplemented operations
// ---------------------------------------------------------------------------

describe("operations this server does not run", () => {
  it("echoes OP_ILLEGAL for an opcode outside the legal range", async () => {
    const { driver, counts } = counting(createMemoryDriver());
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    const reply = await client.run([{ op: OP_PUTROOTFH }, { op: 4242 }, { op: OP_GETFH }]);
    // §16.2.3: "the server's response will encode the opcode OP_ILLEGAL rather
    // than the illegal opcode of the request."
    expect(reply.compound.status).toBe(NFS4ERR_OP_ILLEGAL);
    expect(reply.compound.resarray).toHaveLength(3);
    expect(reply.compound.resarray[2]!.op).toBe(10_044);
    expect(statusAt(reply, 2)).toBe(NFS4ERR_OP_ILLEGAL);
    expect(counts.get("lstat")).toBeUndefined();
  });

  it("answers an illegal opcode before it asks about session position", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    // No SEQUENCE, and the only operation is not an operation at all. §16.2.3's
    // OP_ILLEGAL wins over §18.46.3's NFS4ERR_OP_NOT_IN_SESSION, which is a
    // rule about operations.
    const reply = await new Client(session).send([{ op: 4242 }]);
    expect(reply.compound.status).toBe(NFS4ERR_OP_ILLEGAL);
    expect(reply.compound.resarray).toHaveLength(1);
    expect(reply.compound.resarray[0]!.op).toBe(10_044);
    expect(statusAt(reply, 0)).toBe(NFS4ERR_OP_ILLEGAL);
  });

  it("still answers a known-but-unimplemented first operation with OP_NOT_IN_SESSION", async () => {
    // The other half of the same rule: DELEGRETURN *is* an operation, so
    // §18.46.3's position rule reaches it.
    const session = new Nfs4Session(createMemoryDriver());
    const reply = await new Client(session).send([{ op: OP_DELEGRETURN }]);
    expect(reply.compound.status).toBe(NFS4ERR_OP_NOT_IN_SESSION);
    expect(reply.compound.resarray[0]!.op).toBe(OP_DELEGRETURN);
  });

  it("answers an explicit OP_ILLEGAL the same way, in a session", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const client = await Client.open(session);
    const reply = await client.run([{ op: 10_044 }]);
    expect(reply.compound.status).toBe(NFS4ERR_OP_ILLEGAL);
    expect(reply.compound.resarray[1]!.op).toBe(10_044);
    expect(statusAt(reply, 1)).toBe(NFS4ERR_OP_ILLEGAL);
  });

  it("answers an explicit OP_ILLEGAL the same way with no session either", async () => {
    // Opcode 10044 *has* a codec row — `nfs_argop4` carries a void OP_ILLEGAL
    // arm — so it decodes as a real operation rather than as a decode halt.
    // §18.52.4 makes that the same event as an out-of-range opcode ("just as it
    // would be with any other invalid operation code"), and §18.52.3 fixes the
    // status: it must not come out as NFS4ERR_OP_NOT_IN_SESSION.
    const session = new Nfs4Session(createMemoryDriver());
    const reply = await new Client(session).send([{ op: 10_044 }]);
    expect(reply.compound.status).toBe(NFS4ERR_OP_ILLEGAL);
    expect(reply.compound.resarray).toHaveLength(1);
    expect(reply.compound.resarray[0]!.op).toBe(10_044);
    expect(statusAt(reply, 0)).toBe(NFS4ERR_OP_ILLEGAL);
  });

  it("halts the compound at a known operation with no codec", async () => {
    const { driver, counts } = counting(await populated());
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_DELEGRETURN },
      GETATTR([FATTR4_SIZE]),
      { op: OP_REMOVE, args: { target: "file" } },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_NOTSUPP);
    // SEQUENCE, PUTROOTFH, LOOKUP, DELEGRETURN — and nothing after it.
    expect(reply.compound.resarray).toHaveLength(4);
    expect(reply.compound.resarray[3]!.op).toBe(OP_DELEGRETURN);
    // Proven by the counter, not by the reply: the REMOVE never ran.
    expect(counts.get("unlink")).toBeUndefined();
    expect(await driver.stat("/dir/file")).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// the filehandle cursor
// ---------------------------------------------------------------------------

describe("the filehandle cursor", () => {
  it("walks PUTROOTFH, LOOKUP, GETATTR and GETFH", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([
      { op: OP_PUTROOTFH },
      { op: OP_LOOKUP, args: { objname: "dir" } },
      { op: OP_LOOKUP, args: { objname: "file" } },
      GETATTR([FATTR4_TYPE, FATTR4_SIZE, FATTR4_NUMLINKS]),
      { op: OP_GETFH },
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    const values = attrsOf(reply, 4);
    expect(values.type).toBe(NF4REG);
    expect(values.size).toBe(5n);
    expect(values.numlinks).toBe(1);
    const fh = (reply.compound.resarray[5]!.res as Getfh4res).object!;
    expect(fh.byteLength).toBe(20);

    // And that handle names the same object through PUTFH.
    const second = await client.run([
      { op: OP_PUTFH, args: { object: fh } },
      GETATTR([FATTR4_SIZE]),
    ]);
    expect(attrsOf(second, 2).size).toBe(5n);
  });

  it("saves and restores the cursor", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_SAVEFH },
      { op: OP_LOOKUP, args: { objname: "file" } },
      GETATTR([FATTR4_TYPE]),
      { op: OP_RESTOREFH },
      GETATTR([FATTR4_TYPE]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    expect(attrsOf(reply, 5).type).toBe(NF4REG);
    expect(attrsOf(reply, 7).type).toBe(NF4DIR);
  });

  it("answers a bare RESTOREFH with NFS4ERR_NOFILEHANDLE", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const client = await Client.open(session);
    const reply = await client.run([{ op: OP_RESTOREFH }]);
    // §18.27.3, and §15.1.16.4 on NFS4ERR_RESTOREFH: "in NFSv4.1, this error
    // has been superseded by NFS4ERR_NOFILEHANDLE". §15.2's RESTOREFH row
    // lists only the latter.
    expect(reply.compound.status).toBe(NFS4ERR_NOFILEHANDLE);
  });

  it("answers an operation with no current filehandle", async () => {
    const session = new Nfs4Session(createMemoryDriver());
    const client = await Client.open(session);
    const reply = await client.run([{ op: OP_GETFH }]);
    expect(reply.compound.status).toBe(NFS4ERR_NOFILEHANDLE);
  });

  it("answers LOOKUP of a missing name with NOENT and LOOKUP through a file with NOTDIR", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    expect(
      (await client.run([...TO_DIR, { op: OP_LOOKUP, args: { objname: "nope" } }])).compound.status,
    ).toBe(NFS4ERR_NOENT);
    const throughFile = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "file" } },
      { op: OP_LOOKUP, args: { objname: "x" } },
    ]);
    expect(throughFile.compound.status).toBe(NFS4ERR_NOTDIR);
  });

  it("refuses a name that is not a component", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    expect(
      (await client.run([...TO_DIR, { op: OP_LOOKUP, args: { objname: "" } }])).compound.status,
    ).toBe(NFS4ERR_INVAL);
    expect(
      (await client.run([...TO_DIR, { op: OP_LOOKUP, args: { objname: ".." } }])).compound.status,
    ).toBe(
      10_041, // NFS4ERR_BADNAME
    );
  });

  it("walks LOOKUPP up, and refuses it at the root", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const up = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "sub" } },
      { op: OP_LOOKUPP },
      { op: OP_GETFH },
      { op: OP_LOOKUPP },
      { op: OP_GETFH },
    ]);
    expect(up.compound.status).toBe(NFS4_OK);
    // §18.14.3: LOOKUPP at the root is NFS4ERR_NOENT.
    const atRoot = await client.run([{ op: OP_PUTROOTFH }, { op: OP_LOOKUPP }]);
    expect(atRoot.compound.status).toBe(NFS4ERR_NOENT);
    // And on something that is not a directory, NFS4ERR_NOTDIR.
    const onFile = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "file" } },
      { op: OP_LOOKUPP },
    ]);
    expect(onFile.compound.status).toBe(NFS4ERR_NOTDIR);
  });
});

// ---------------------------------------------------------------------------
// attributes
// ---------------------------------------------------------------------------

describe("GETATTR", () => {
  it("returns only the requested attributes it supports", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([...TO_DIR, GETATTR([FATTR4_TYPE, FATTR4_CHANGE, 63])]);
    const res = reply.compound.resarray[3]!.res as Getattr4res;
    // Attribute 63 is `layout_hint`, which this server does not support: it is
    // dropped from both halves rather than answered (§18.7.3).
    expect(bitmapHas(res.objAttributes!.attrmask, FATTR4_TYPE)).toBe(true);
    expect(bitmapHas(res.objAttributes!.attrmask, 63)).toBe(false);
    expect(res.objAttributes!.values.type).toBe(NF4DIR);
  });

  it("refuses a request for a write-only attribute", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    // §5.5: "If a client attempts to set a get-only attribute or get a set-only
    // attributes, the server MUST return NFS4ERR_INVAL."
    const reply = await client.run([...TO_DIR, GETATTR([FATTR4_TIME_MODIFY_SET])]);
    expect(reply.compound.status).toBe(NFS4ERR_INVAL);
  });

  it("omits the statfs family when the driver has no statfs", async () => {
    const base = await populated();
    const withStatfs = new Nfs4Session(base);
    const client = await Client.open(withStatfs);
    const present = await client.run([...TO_DIR, GETATTR([FATTR4_SPACE_TOTAL])]);
    expect(attrsOf(present, 3).spaceTotal).toBeGreaterThan(0n);

    const noStatfs = new Nfs4Session({ ...base, statfs: undefined } as FsDriver);
    const other = await Client.open(noStatfs);
    const absent = await other.run([...TO_DIR, GETATTR([FATTR4_SPACE_TOTAL, FATTR4_TYPE])]);
    const res = absent.compound.resarray[3]!.res as Getattr4res;
    expect(res.status).toBe(NFS4_OK);
    expect(bitmapHas(res.objAttributes!.attrmask, FATTR4_SPACE_TOTAL)).toBe(false);
    expect(res.objAttributes!.values.spaceTotal).toBeUndefined();
    // And `supported_attrs` says so, rather than advertising what it drops.
    const supported = await other.run([...TO_DIR, GETATTR([FATTR4_SUPPORTED_ATTRS])]);
    expect(bitmapHas(attrsOf(supported, 3).supportedAttrs!, FATTR4_SPACE_TOTAL)).toBe(false);
  });
});

describe("SETATTR", () => {
  it("applies mode, size and the timestamps", async () => {
    const driver = await populated();
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    const when: NfsTime4 = { seconds: 1_000_000_000n, nseconds: 0 };
    const attrmask = bitmapOf([FATTR4_SIZE, FATTR4_MODE, FATTR4_TIME_MODIFY_SET]);
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "file" } },
      {
        op: OP_SETATTR,
        args: {
          stateid: { seqid: 0, other: new Uint8Array(12) },
          objAttributes: {
            attrmask,
            values: {
              size: 3n,
              mode: 0o640,
              timeModifySet: { how: SET_TO_CLIENT_TIME4, time: when },
            },
            unsupported: [],
          },
        },
      },
      GETATTR([FATTR4_SIZE, FATTR4_MODE, FATTR4_TIME_MODIFY]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    const set = reply.compound.resarray[4]!.res as Setattr4res;
    // §18.30.4: "If the attribute masks in the request and reply are equal, the
    // status field in the reply MUST be NFS4_OK."
    expect([...set.attrsset]).toEqual([...attrmask]);
    const values = attrsOf(reply, 5);
    expect(values.size).toBe(3n);
    expect(values.mode).toBe(0o640);
    expect(Math.round(fromTime4(values.timeModify!) / 1000)).toBe(1_000_000_000);
  });

  it("refuses an unsupported attribute with an empty attrsset", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    // Attribute 12 is `acl`, which this server does not support at all — and
    // which the decoder therefore stops at, since an attribute value carries no
    // length to skip past.
    const modeWord = new XdrWriter(8).u32(0o600).bytes();
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "file" } },
      { op: OP_SETATTR, raw: rawFattrArgs([12, FATTR4_MODE], modeWord, true) },
      GETATTR([FATTR4_MODE]),
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_ATTRNOTSUPP);
    const set = reply.compound.resarray[4]!.res as Setattr4res;
    // §18.30.3: `attrsset` is a subset of the request's mask, and nothing was
    // applied because the refusal is checked before anything is touched.
    expect([...set.attrsset]).toEqual([]);
    // Which the file itself confirms: the mode is untouched.
    const after = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "file" } },
      GETATTR([FATTR4_MODE]),
    ]);
    expect(attrsOf(after, 4).mode).not.toBe(0o600);
  });

  it("refuses a read-only attribute with NFS4ERR_INVAL", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      {
        op: OP_SETATTR,
        args: {
          stateid: { seqid: 0, other: new Uint8Array(12) },
          objAttributes: {
            attrmask: bitmapOf([FATTR4_FILEID]),
            values: { fileid: 7n },
            unsupported: [],
          },
        },
      },
    ]);
    // §5.5: a get-only attribute in a SETATTR is NFS4ERR_INVAL, not ATTRNOTSUPP.
    expect(reply.compound.status).toBe(NFS4ERR_INVAL);
  });

  it("refuses a non-numeric owner with NFS4ERR_BADOWNER", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      {
        op: OP_SETATTR,
        args: {
          stateid: { seqid: 0, other: new Uint8Array(12) },
          objAttributes: {
            attrmask: bitmapOf([FATTR4_OWNER]),
            values: { owner: "alice@example.org" },
            unsupported: [],
          },
        },
      },
    ]);
    expect(reply.compound.status).toBe(10_039); // NFS4ERR_BADOWNER
  });
});

describe("VERIFY and NVERIFY", () => {
  it("compares the named attributes, both directions", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const attrmask = bitmapOf([FATTR4_SIZE]);
    const same = { attrmask, values: { size: 5n }, unsupported: [] };
    const different = { attrmask, values: { size: 6n }, unsupported: [] };
    const toFile: Op[] = [...TO_DIR, { op: OP_LOOKUP, args: { objname: "file" } }];

    expect(
      (await client.run([...toFile, { op: OP_VERIFY, args: { objAttributes: same } }])).compound
        .status,
    ).toBe(NFS4_OK);
    expect(
      (await client.run([...toFile, { op: OP_VERIFY, args: { objAttributes: different } }]))
        .compound.status,
    ).toBe(NFS4ERR_NOT_SAME);
    expect(
      (await client.run([...toFile, { op: OP_NVERIFY, args: { objAttributes: different } }]))
        .compound.status,
    ).toBe(NFS4_OK);
    expect(
      (await client.run([...toFile, { op: OP_NVERIFY, args: { objAttributes: same } }])).compound
        .status,
    ).toBe(NFS4ERR_SAME);
  });

  it("refuses rdattr_error and the set-only attributes", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    for (const bit of [FATTR4_RDATTR_ERROR, FATTR4_TIME_ACCESS_SET]) {
      // One word of value: a zero `nfsstat4` for bit 11, a `SET_TO_SERVER_TIME4`
      // discriminant with no body for bit 48.
      const reply = await client.run([
        ...TO_DIR,
        { op: OP_VERIFY, raw: rawFattrArgs([bit], new XdrWriter(8).u32(0).bytes()) },
      ]);
      // §18.31.4: "When the attribute rdattr_error or any set-only attribute
      // ... is specified, the error NFS4ERR_INVAL is returned to the client."
      expect(reply.compound.status).toBe(NFS4ERR_INVAL);
    }
  });

  it("refuses an attribute it does not support with ATTRNOTSUPP", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_VERIFY, raw: rawFattrArgs([12], new Uint8Array(0)) },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_ATTRNOTSUPP);
  });
});

// ---------------------------------------------------------------------------
// ACCESS, READLINK, SECINFO
// ---------------------------------------------------------------------------

describe("ACCESS", () => {
  it("masks the requested bits down to what the mode allows", async () => {
    const driver = await populated();
    await driver.chmod("/dir/file", 0o400);
    await driver.chown("/dir/file", 1000, 1000);
    const session = new Nfs4Session(driver);
    const client = await Client.open(session); // AUTH_SYS uid 1000
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "file" } },
      { op: OP_ACCESS, args: { access: ACCESS4_ALL } },
    ]);
    const res = reply.compound.resarray[4]!.res as Access4res;
    expect(res.status).toBe(NFS4_OK);
    // §18.1.3: neither field may carry more than the request did, and access
    // may not exceed supported.
    expect(res.supported).toBe(ACCESS4_ALL);
    expect(res.access & ACCESS4_READ).toBe(ACCESS4_READ);
    expect(res.access & ACCESS4_MODIFY).toBe(0);
    expect(res.access & ACCESS4_EXECUTE).toBe(0);
    expect(res.access & ~res.supported).toBe(0);
  });

  it("never reports a bit the request did not ask for", async () => {
    const driver = await populated();
    await driver.chmod("/dir", 0o755);
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_ACCESS, args: { access: ACCESS4_LOOKUP } },
    ]);
    const res = reply.compound.resarray[3]!.res as Access4res;
    expect(res.supported).toBe(ACCESS4_LOOKUP);
    expect(res.access).toBe(ACCESS4_LOOKUP);
  });
});

describe("READLINK and SECINFO", () => {
  it("reads a symlink through the cursor", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "link" } },
      { op: OP_READLINK },
    ]);
    expect((reply.compound.resarray[4]!.res as Readlink4res).link).toBe("./file");
  });

  it("consumes the current filehandle (§18.29.3)", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_SECINFO, args: { name: "file" } },
      { op: OP_GETFH },
    ]);
    const secinfo = reply.compound.resarray[3]!.res as Secinfo4res;
    expect(secinfo.status).toBe(NFS4_OK);
    expect(secinfo.flavors.map((entry) => entry.flavor)).toEqual([1, 0]); // AUTH_SYS, AUTH_NONE
    // "if the next operation after SECINFO tries to use the current filehandle,
    // that operation will fail with the status NFS4ERR_NOFILEHANDLE."
    expect(reply.compound.status).toBe(NFS4ERR_NOFILEHANDLE);
    expect(statusAt(reply, 4)).toBe(NFS4ERR_NOFILEHANDLE);
  });
});

// ---------------------------------------------------------------------------
// the mutating operations
// ---------------------------------------------------------------------------

describe("CREATE", () => {
  it("makes a directory and a symlink, and reports change_info", async () => {
    const driver = await populated();
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    const before = await dirChange(client);
    const reply = await client.run([
      ...TO_DIR,
      {
        op: OP_CREATE,
        args: {
          objtype: { type: NF4DIR },
          objname: "made",
          createattrs: {
            attrmask: bitmapOf([FATTR4_MODE]),
            values: { mode: 0o750 },
            unsupported: [],
          },
        },
      },
      GETATTR([FATTR4_TYPE, FATTR4_MODE]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    const created = reply.compound.resarray[3]!.res as Create4res;
    // `atomic` is FALSE and stays FALSE: the two samples come from two separate
    // driver calls, so §3.3.8's "obtained atomically" is not something this
    // server may claim.
    expect(created.cinfo!.atomic).toBe(false);
    // `before` is the value the previous compound saw, `after` the one the next
    // compound sees — which pins both halves without asking a millisecond-
    // resolution counter to have moved inside one operation.
    expect(created.cinfo!.before).toBe(before);
    expect(created.cinfo!.after).toBe(await dirChange(client));
    expect(bitmapHas(created.attrset!, FATTR4_MODE)).toBe(true);
    // The new object is the current filehandle (§18.4.3).
    expect(attrsOf(reply, 4).type).toBe(NF4DIR);
    expect(attrsOf(reply, 4).mode).toBe(0o750);

    const link = await client.run([
      ...TO_DIR,
      {
        op: OP_CREATE,
        args: {
          objtype: { type: NF4LNK, linkdata: "/elsewhere" },
          objname: "made-link",
          createattrs: { attrmask: [], values: {}, unsupported: [] },
        },
      },
      { op: OP_READLINK },
    ]);
    expect(link.compound.status).toBe(NFS4_OK);
    expect((link.compound.resarray[4]!.res as Readlink4res).link).toBe("/elsewhere");
  });

  it("refuses a regular file, which is OPEN's job", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      {
        op: OP_CREATE,
        args: {
          objtype: { type: NF4REG },
          objname: "nope",
          createattrs: { attrmask: [], values: {}, unsupported: [] },
        },
      },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_BADTYPE);
  });

  it("refuses a device node without the mknod extension", async () => {
    // The memory driver has the extension, so the refusal is tested against one
    // with it taken off — the case below is the other half.
    const session = new Nfs4Session(withoutExtensions(await populated()));
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      {
        op: OP_CREATE,
        args: {
          objtype: { type: 7, devdata: undefined }, // NF4FIFO
          objname: "fifo",
          createattrs: { attrmask: [], values: {}, unsupported: [] },
        },
      },
    ]);
    // §15.1.4.1: NFS4ERR_BADTYPE covers "because the type is not supported by
    // the server", and §15.2's CREATE row does not list NFS4ERR_NOTSUPP.
    expect(reply.compound.status).toBe(NFS4ERR_BADTYPE);
  });

  it("creates a FIFO and a character device through the mknod extension", async () => {
    const driver = await populated();
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    const create = (objtype: CreateType4, objname: string, mode: number): Op => ({
      op: OP_CREATE,
      args: {
        objtype,
        objname,
        createattrs: { attrmask: bitmapOf([FATTR4_MODE]), values: { mode }, unsupported: [] },
      },
    });

    const fifo = await client.run([...TO_DIR, create({ type: NF4FIFO }, "fifo", 0o644)]);
    expect(fifo.compound.status).toBe(NFS4_OK);
    const device = await client.run([
      ...TO_DIR,
      create({ type: NF4CHR, devdata: { major: 1, minor: 3 } }, "null", 0o666),
    ]);
    expect(device.compound.status).toBe(NFS4_OK);

    // What the driver holds: the type in `mode`, the device number in `rdev`.
    const made = await driver.lstat("/dir/fifo");
    expect(made.isFIFO()).toBe(true);
    expect(made.mode & 0o7777).toBe(0o644);
    const special = await driver.lstat("/dir/null");
    expect(special.isCharacterDevice()).toBe(true);
    expect(special.rdev).toBe((1 << 8) | 3);

    // ...and what a client reads back, which is where `rawdev` is assembled.
    const attrs = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "null" } },
      GETATTR([FATTR4_TYPE, FATTR4_RAWDEV]),
    ]);
    expect(attrs.compound.status).toBe(NFS4_OK);
    const values = attrsFor(attrs);
    expect(values.type).toBe(NF4CHR);
    expect(values.rawdev).toEqual({ major: 1, minor: 3 });
  });

  it("refuses a symlink when the driver has none", async () => {
    const base = await populated();
    const noSymlinks: FsDriver = {
      ...base,
      symlink: undefined,
      readlink: undefined,
      capabilities: { ...base.capabilities, symlinks: false },
    };
    const session = new Nfs4Session(noSymlinks);
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      {
        op: OP_CREATE,
        args: {
          objtype: { type: NF4LNK, linkdata: "/elsewhere" },
          objname: "nope",
          createattrs: { attrmask: [], values: {}, unsupported: [] },
        },
      },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_BADTYPE);
  });
});

describe("REMOVE, RENAME and LINK", () => {
  it("removes a file and a directory, and refuses a non-empty one", async () => {
    const driver = await populated();
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);

    const notEmpty = await client.run([
      { op: OP_PUTROOTFH },
      { op: OP_REMOVE, args: { target: "dir" } },
    ]);
    expect(notEmpty.compound.status).toBe(NFS4ERR_NOTEMPTY);

    const removed = await client.run([...TO_DIR, { op: OP_REMOVE, args: { target: "file" } }]);
    expect(removed.compound.status).toBe(NFS4_OK);
    const cinfo = (removed.compound.resarray[3]!.res as Remove4res).cinfo!;
    expect(cinfo.atomic).toBe(false);
    expect(cinfo.after).toBe(await dirChange(client));
    await expect(driver.stat("/dir/file")).rejects.toThrow();

    const rmdir = await client.run([...TO_DIR, { op: OP_REMOVE, args: { target: "sub" } }]);
    expect(rmdir.compound.status).toBe(NFS4_OK);
  });

  it("renames between directories and reports source then target", async () => {
    const driver = await populated();
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    const sourceChange = await dirChange(client);
    const targetChange = await rootChange(client);

    const reply = await client.run([
      ...TO_DIR,
      { op: OP_SAVEFH },
      { op: OP_PUTROOTFH },
      { op: OP_RENAME, args: { oldname: "file", newname: "moved" } },
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    const res = reply.compound.resarray[5]!.res as Rename4res;
    // Source first, target second (§18.26.2), and the source's `before` is the
    // `change` this same test read a moment ago.
    expect(res.sourceCinfo!.before).toBe(sourceChange);
    expect(res.sourceCinfo!.after).toBe(await dirChange(client));
    expect(res.sourceCinfo!.atomic).toBe(false);
    // ...and the target's pair is the *root's*, read the same way. Pinning each
    // struct to its own directory is what catches a transposed pair, which
    // comparing the two to each other could not do — `/dir` and `/` can
    // legitimately share a `change` value at millisecond resolution.
    expect(res.targetCinfo!.before).toBe(targetChange);
    expect(res.targetCinfo!.after).toBe(await rootChange(client));
    expect(res.targetCinfo!.atomic).toBe(false);
    expect(await driver.stat("/moved")).toBeDefined();
  });

  it("links an object into another directory", async () => {
    const driver = await populated();
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "file" } },
      { op: OP_SAVEFH },
      { op: OP_PUTROOTFH },
      { op: OP_LINK, args: { newname: "hard" } },
      { op: OP_LOOKUP, args: { objname: "hard" } },
      GETATTR([FATTR4_NUMLINKS]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    expect(attrsOf(reply, 8).numlinks).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// READDIR
// ---------------------------------------------------------------------------

describe("READDIR", () => {
  const readdir = (
    cookie: bigint,
    cookieverf: Uint8Array,
    maxcount: number,
    bits: number[],
  ): Op => ({
    op: OP_READDIR,
    args: { cookie, cookieverf, dircount: 4096, maxcount, attrRequest: bitmapOf(bits) },
  });

  it("pages through a directory with cookies", async () => {
    const driver = createMemoryDriver();
    for (let index = 0; index < 12; index++) {
      await driver.mkdir(`/entry-${index}`);
    }
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);

    const names: string[] = [];
    let cookie = 0n;
    let cookieverf: Uint8Array = new Uint8Array(8);
    let pages = 0;
    for (;;) {
      const reply = await client.run([
        { op: OP_PUTROOTFH },
        readdir(cookie, cookieverf, 400, [FATTR4_TYPE, FATTR4_FILEID]),
      ]);
      expect(reply.compound.status).toBe(NFS4_OK);
      const res = reply.compound.resarray[2]!.res as Readdir4res;
      pages += 1;
      for (const entry of res.reply.entries) {
        // §18.23.3 reserves cookies 0, 1 and 2.
        expect(entry.cookie).toBeGreaterThanOrEqual(3n);
        expect(entry.attrs.values.type).toBe(NF4DIR);
        names.push(entry.name);
        cookie = entry.cookie;
      }
      cookieverf = res.cookieverf;
      if (res.reply.eof) {
        break;
      }
      expect(res.reply.entries.length).toBeGreaterThan(0);
    }
    expect(pages).toBeGreaterThan(1);
    expect(names).toHaveLength(12);
    expect(new Set(names).size).toBe(12);
  });

  /**
   * What a page costs the driver.
   *
   * v4 folds v3's READDIR and READDIRPLUS into one operation, so every entry
   * costs an `lstat` whatever the client asked for — and they used to be
   * awaited one after another, with a `driver.statfs` per entry on top whenever
   * the request named any of the six `statfs` attributes. With the memory
   * driver that second one is a whole-tree walk per name.
   */
  it("resolves a page concurrently and asks the filesystem about itself once", async () => {
    const base = createMemoryDriver();
    for (let index = 0; index < 40; index++) {
      await base.mkdir(`/entry-${String(index).padStart(3, "0")}`);
    }
    let lstats = 0;
    let statfs = 0;
    let inFlight = 0;
    let peak = 0;
    const counted: FsDriver = {
      ...base,
      async lstat(path) {
        lstats++;
        inFlight++;
        peak = Math.max(peak, inFlight);
        try {
          return await base.lstat(path);
        } finally {
          inFlight--;
        }
      },
      async statfs(path) {
        statfs++;
        return base.statfs(path);
      },
    };
    const session = new Nfs4Session(counted);
    const client = await Client.open(session);
    const reply = await client.run([
      { op: OP_PUTROOTFH },
      readdir(0n, new Uint8Array(8), 1 << 20, [FATTR4_TYPE, FATTR4_FILEID, FATTR4_SPACE_TOTAL]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    const res = reply.compound.resarray[2]!.res as Readdir4res;
    expect(res.reply.entries).toHaveLength(40);
    expect(res.reply.eof).toBe(true);
    // On base this peaks at exactly 1 — one entry's `lstat` awaited before the
    // next one starts.
    expect(peak).toBeGreaterThan(1);
    // And one `statfs` for the whole page. On base, one per entry.
    expect(statfs).toBe(1);
    expect(lstats).toBeGreaterThanOrEqual(40);
  });

  /**
   * The snapshot invalidation rule, stated on `DirectorySnapshots` in
   * `src/nfs/handles.ts` and obeyed identically by both versions.
   *
   * It used to be two contradictory halves: RENAME threw away *every* cached
   * listing in the server, and CREATE threw away none — so a resuming client
   * was served names from before a create it had itself asked for, under a
   * verifier that still matched and gave it no way to tell.
   */
  it("drops the cached listing of a directory it changed, and of no other", async () => {
    const driver = createMemoryDriver();
    await driver.mkdir("/dir");
    for (let index = 0; index < 12; index++) {
      await driver.mkdir(`/dir/e${String(index).padStart(2, "0")}`);
    }
    await driver.mkdir("/other");
    await driver.mkdir("/other/a");
    let readdirs = 0;
    const counted: FsDriver = {
      ...driver,
      async readdir(path, options) {
        readdirs++;
        return driver.readdir(path, options as never) as never;
      },
    };
    const session = new Nfs4Session(counted);
    const client = await Client.open(session);
    const handleOf = async (name: string): Promise<Uint8Array> => {
      const reply = await client.run([
        { op: OP_PUTROOTFH },
        { op: OP_LOOKUP, args: { objname: name } },
        { op: OP_GETFH },
      ]);
      expect(reply.compound.status).toBe(NFS4_OK);
      return (reply.compound.resarray[3]!.res as Getfh4res).object!;
    };
    const dir = await handleOf("dir");
    const other = await handleOf("other");
    const putDir = { op: OP_PUTFH, args: { object: dir } };

    const first = await client.run([putDir, readdir(0n, new Uint8Array(8), 400, [])]);
    expect(first.compound.status).toBe(NFS4_OK);
    const page = first.compound.resarray[2]!.res as Readdir4res;
    expect(page.reply.eof).toBe(false);
    const cookie = page.reply.entries.at(-1)!.cookie;

    // A rename somewhere else entirely. `/dir`'s paging is untouched by it.
    const before = readdirs;
    const renamed = await client.run([
      { op: OP_PUTFH, args: { object: other } },
      { op: OP_SAVEFH },
      { op: OP_PUTFH, args: { object: other } },
      { op: OP_RENAME, args: { oldname: "a", newname: "b" } },
    ]);
    expect(renamed.compound.status).toBe(NFS4_OK);
    const resumed = await client.run([putDir, readdir(cookie, page.cookieverf, 4096, [])]);
    expect(resumed.compound.status).toBe(NFS4_OK);
    expect((resumed.compound.resarray[2]!.res as Readdir4res).reply.entries.length).toBeGreaterThan(
      0,
    );
    // Straight out of the cache: RENAME used to `clear()` every snapshot in the
    // server, so an unrelated `mv` made this directory re-list itself from the
    // driver to prove the client's cookie still meant something.
    expect(readdirs - before).toBe(0);

    // A CREATE *in* the directory being paged is the other half of the rule:
    // the snapshot goes, and the client is told its cookie means nothing rather
    // than handed a listing from before the create.
    const created = await client.run([
      putDir,
      {
        op: OP_CREATE,
        args: {
          objtype: { type: NF4DIR },
          objname: "zzz",
          createattrs: { attrmask: [], values: {}, unsupported: [] },
        },
      },
    ]);
    expect(created.compound.status).toBe(NFS4_OK);
    const stale = await client.run([putDir, readdir(cookie, page.cookieverf, 4096, [])]);
    expect(stale.compound.status).toBe(NFS4ERR_NOT_SAME);
  });

  /**
   * The other half of "resolve the page as a batch": how big a batch to ask
   * for.
   *
   * A fixed window is only right when the page has room for at least that many
   * entries. A client with a small `maxcount` — this test, and any test client
   * — fits three or four per page, so a blind 64 fetches sixty of them to throw
   * away, mints a handle-table entry for each, and re-fetches them on the next
   * page. That is up to 64x the driver work of the one-at-a-time loop this
   * batching replaced, in the one case it is supposed to help.
   *
   * So the first batch of every page is bounded from the *names alone*: an
   * entry costs at least its `dircount` size plus the smallest `fattr4` that
   * can encode, and neither needs a driver call.
   */
  it("does not over-fetch the first batch of a page with room for a few entries", async () => {
    const base = createMemoryDriver();
    for (let index = 0; index < 40; index++) {
      await base.mkdir(`/e${String(index).padStart(2, "0")}`);
    }
    let lstats = 0;
    const counted: FsDriver = {
      ...base,
      async lstat(path) {
        lstats++;
        return base.lstat(path);
      },
    };
    const session = new Nfs4Session(counted);
    const client = await Client.open(session);

    const names: string[] = [];
    let cookie = 0n;
    let cookieverf: Uint8Array = new Uint8Array(8);
    let pages = 0;
    for (;;) {
      const reply = await client.run([
        { op: OP_PUTROOTFH },
        readdir(cookie, cookieverf, 260, [FATTR4_TYPE]),
      ]);
      expect(reply.compound.status).toBe(NFS4_OK);
      const res = reply.compound.resarray[2]!.res as Readdir4res;
      pages++;
      for (const entry of res.reply.entries) {
        names.push(entry.name);
        cookie = entry.cookie;
      }
      cookieverf = res.cookieverf;
      if (res.reply.eof) {
        break;
      }
      expect(res.reply.entries.length).toBeGreaterThan(0);
    }
    expect(names).toHaveLength(40);
    // Small pages, so there are many of them — which is what makes the
    // per-page over-fetch visible at all.
    expect(pages).toBeGreaterThan(8);
    // Every entry is stat'ed once for the page it lands on, plus the one entry
    // per page that proves the page is full and is re-fetched by the next.
    // With a fixed 64-entry first batch this is ~7x higher.
    expect(lstats).toBeLessThan(2 * 40);
  });

  it("answers a cookieverf that no longer matches with NOT_SAME", async () => {
    const driver = await populated();
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    const first = await client.run([...TO_DIR, readdir(0n, new Uint8Array(8), 4096, [])]);
    const res = first.compound.resarray[3]!.res as Readdir4res;
    const cookie = res.reply.entries[0]!.cookie;
    expect(res.reply.eof).toBe(true);

    await driver.mkdir("/dir/changed");
    // Resuming with a verifier that is neither the cached snapshot's nor the
    // re-listed directory's: §18.23.3 makes that NFS4ERR_NOT_SAME.
    const stale = await client.run([
      ...TO_DIR,
      readdir(cookie, Uint8Array.from([9, 9, 9, 9, 9, 9, 9, 9]), 4096, []),
    ]);
    expect(stale.compound.status).toBe(NFS4ERR_NOT_SAME);
  });

  it("reserves cookies 1 and 2", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([...TO_DIR, readdir(2n, new Uint8Array(8), 400, [])]);
    expect(reply.compound.status).toBe(10_003); // NFS4ERR_BAD_COOKIE
  });

  it("answers a maxcount that fits no entry with TOOSMALL", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const reply = await client.run([...TO_DIR, readdir(0n, new Uint8Array(8), 130, [])]);
    // §18.23.3 ties the MUST to `maxcount` and to nothing else.
    expect(reply.compound.status).toBe(10_005); // NFS4ERR_TOOSMALL
  });

  it("ignores dircount entirely when it is zero", async () => {
    const driver = createMemoryDriver();
    for (let index = 0; index < 8; index++) {
      await driver.mkdir(`/entry-${index}`);
    }
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    // §18.23.4: "If dircount is zero, the server bounds the reply's size based
    // on the request's maxcount field."
    const reply = await client.run([
      { op: OP_PUTROOTFH },
      {
        op: OP_READDIR,
        args: {
          cookie: 0n,
          cookieverf: new Uint8Array(8),
          dircount: 0,
          maxcount: 8192,
          attrRequest: bitmapOf([FATTR4_TYPE]),
        },
      },
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    const res = reply.compound.resarray[2]!.res as Readdir4res;
    expect(res.reply.entries).toHaveLength(8);
    expect(res.reply.eof).toBe(true);
  });

  it("treats a tiny dircount as the hint it is, not as a limit", async () => {
    const session = new Nfs4Session(await populated());
    const client = await Client.open(session);
    const hinted = async (dircount: number): Promise<Readdir4res> => {
      const reply = await client.run([
        ...TO_DIR,
        {
          op: OP_READDIR,
          args: {
            cookie: 0n,
            cookieverf: new Uint8Array(8),
            dircount,
            maxcount: 8192,
            attrRequest: [],
          },
        },
      ]);
      expect(reply.compound.status).toBe(NFS4_OK);
      return reply.compound.resarray[3]!.res as Readdir4res;
    };
    // `/dir` holds three entries. A dircount far below one entry's
    // names-and-cookies cost, with ample maxcount: §18.23.3 calls dircount "a
    // hint", so the page is *short* rather than empty — and emphatically not
    // NFS4ERR_TOOSMALL, whose MUST is tied to maxcount alone.
    for (const dircount of [1, 8]) {
      const res = await hinted(dircount);
      expect(res.reply.entries).toHaveLength(1);
      expect(res.reply.eof).toBe(false);
    }
    // A hint with room for the whole directory bounds nothing.
    const roomy = await hinted(4096);
    expect(roomy.reply.entries).toHaveLength(3);
    expect(roomy.reply.eof).toBe(true);
  });

  it("pages a whole directory through a dircount hint", async () => {
    const driver = createMemoryDriver();
    for (let index = 0; index < 6; index++) {
      await driver.mkdir(`/entry-${index}`);
    }
    const session = new Nfs4Session(driver);
    const client = await Client.open(session);
    const names: string[] = [];
    let cookie = 0n;
    let cookieverf: Uint8Array = new Uint8Array(8);
    for (;;) {
      const reply = await client.run([
        { op: OP_PUTROOTFH },
        {
          op: OP_READDIR,
          args: { cookie, cookieverf, dircount: 1, maxcount: 8192, attrRequest: [] },
        },
      ]);
      expect(reply.compound.status).toBe(NFS4_OK);
      const res = reply.compound.resarray[2]!.res as Readdir4res;
      expect(res.reply.entries).toHaveLength(1);
      names.push(res.reply.entries[0]!.name);
      cookie = res.reply.entries[0]!.cookie;
      cookieverf = res.cookieverf;
      if (res.reply.eof) {
        break;
      }
    }
    expect(names).toHaveLength(6);
    expect(new Set(names).size).toBe(6);
  });

  it("reports a failing entry as rdattr_error when the client asked for it", async () => {
    const base = await populated();
    const broken: FsDriver = {
      ...base,
      async lstat(path) {
        if (path === "/dir/file") {
          throw fsError("EIO", { syscall: "lstat", path });
        }
        return base.lstat(path);
      },
      async stat(path) {
        if (path === "/dir/file") {
          throw fsError("EIO", { syscall: "stat", path });
        }
        return base.stat(path);
      },
    };
    const session = new Nfs4Session(broken);
    const client = await Client.open(session);
    const withBit = await client.run([
      ...TO_DIR,
      readdir(0n, new Uint8Array(8), 4096, [FATTR4_TYPE, FATTR4_RDATTR_ERROR]),
    ]);
    expect(withBit.compound.status).toBe(NFS4_OK);
    const entries = (withBit.compound.resarray[3]!.res as Readdir4res).reply.entries;
    const failed = entries.find((entry) => entry.name === "file")!;
    expect(failed.attrs.values.rdattrError).toBe(5); // NFS4ERR_IO
    expect(failed.attrs.values.type).toBeUndefined();
    // The entries that could be read still carry a zero `rdattr_error`.
    expect(entries.find((entry) => entry.name === "sub")!.attrs.values.rdattrError).toBe(NFS4_OK);

    // Without bit 11 the server "has no choice but to return failure for the
    // entire READDIR operation" (§18.23.3).
    const withoutBit = await client.run([
      ...TO_DIR,
      readdir(0n, new Uint8Array(8), 4096, [FATTR4_TYPE]),
    ]);
    expect(withoutBit.compound.status).toBe(5); // NFS4ERR_IO
  });
});

// ---------------------------------------------------------------------------
// the router
// ---------------------------------------------------------------------------

describe("the version router", () => {
  it("hands a vers-4 record to the v4 session", async () => {
    const session = new NfsSession(await populated());
    const client = await Client.open(session.v4);
    // Same session object, but every record above went through `session.v4`
    // directly. This one goes through the facade's own peek.
    const { bytes } = compoundCall([
      client.sequence({ sequenceid: ++client.slotSeqid }),
      { op: OP_PUTROOTFH },
      { op: OP_GETFH },
    ]);
    const reply = readReply((await session.handleCall(bytes))!);
    expect(reply.compound.status).toBe(NFS4_OK);
    expect((reply.compound.resarray[2]!.res as Getfh4res).object).toBeDefined();
  });

  it("shares one handle table across the versions", async () => {
    const session = new NfsSession(await populated());
    const client = await Client.open(session.v4);
    const reply = await client.run([...TO_DIR, { op: OP_GETFH }]);
    const fh = (reply.compound.resarray[3]!.res as Getfh4res).object!;
    // The router's table is the one the v4 session bound the path into.
    expect(session.handles.resolve(fh)).toBe("/dir");
    expect(session.v3.handles).toBe(session.handles);
  });

  it("counts both versions in one stats object", async () => {
    const session = new NfsSession(createMemoryDriver());
    await Client.open(session.v4);
    expect(session.stats.requests).toBeGreaterThan(0);
    expect(session.stats.procedures.get("NFS4:COMPOUND")).toBe(2);
    await session.destroy();
    expect(session.destroyed).toBe(true);
    expect(session.v4.destroyed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// OPEN / CLOSE / OPEN_DOWNGRADE, READ / WRITE, LOCK / LOCKT / LOCKU
// ---------------------------------------------------------------------------

/**
 * A client that has finished reclaiming.
 *
 * §18.51.3 makes this mandatory rather than tidy: a client "MUST send a
 * RECLAIM_COMPLETE with rca_one_fs set to FALSE" before its first non-reclaim
 * lock-obtaining operation "even if there are no locks to reclaim", and the
 * server answers `NFS4ERR_GRACE` until it does — which is a case of its own
 * below.
 */
async function ready(
  session: Nfs4Session,
  ownerid = "test-client",
  cred?: OpaqueAuth,
): Promise<Client> {
  const client = await Client.open(session, ownerid, cred);
  const done = await client.run([{ op: OP_RECLAIM_COMPLETE, args: { oneFs: false } }]);
  expect(done.compound.status).toBe(NFS4_OK);
  return client;
}

interface OpenOptions {
  name?: string;
  access?: number;
  deny?: number;
  owner?: number;
  openhow?: unknown;
  claim?: unknown;
}

/** An OPEN operation, with this suite's defaults: read-only, deny nothing, `/dir/file`. */
function OPEN(options: OpenOptions = {}): Op {
  return {
    op: OP_OPEN,
    args: {
      // §18.16.3: "The 'seqid' field of the request is not used in NFSv4.1, but
      // it MAY be any value and the server MUST ignore it" — so a value that
      // would be wrong in 4.0 goes out deliberately.
      seqid: 77,
      shareAccess: options.access ?? OPEN4_SHARE_ACCESS_READ,
      shareDeny: options.deny ?? OPEN4_SHARE_DENY_NONE,
      // The clientid here is the one §18.16.3 orders the server to ignore.
      owner: { clientid: 0xdead_beefn, owner: Uint8Array.from([options.owner ?? 1]) },
      openhow: options.openhow ?? { opentype: OPEN4_NOCREATE },
      claim: options.claim ?? { claim: CLAIM_NULL, file: options.name ?? "file" },
    },
  };
}

/** `createhow4` for the two create modes this server implements. */
function createHow(mode: number, attrs: { bits?: number[]; values?: Fattr4Values } = {}): unknown {
  return {
    opentype: OPEN4_CREATE,
    how: {
      mode,
      createattrs: {
        attrmask: bitmapOf(attrs.bits ?? []),
        values: attrs.values ?? {},
        unsupported: [],
      },
    },
  };
}

/**
 * `createhow4` for the two exclusive modes: `EXCLUSIVE4` carries the verifier
 * alone, `EXCLUSIVE4_1` carries it beside a `cva_attrs` the other modes would
 * have sent as `createattrs`.
 */
function exclusiveHow(
  mode: number,
  verf: Uint8Array,
  attrs?: { bits?: number[]; values?: Fattr4Values },
): unknown {
  return {
    opentype: OPEN4_CREATE,
    how:
      mode === EXCLUSIVE4
        ? { mode, createverf: verf }
        : {
            mode,
            createboth: {
              verf,
              attrs: {
                attrmask: bitmapOf(attrs?.bits ?? []),
                values: attrs?.values ?? {},
                unsupported: [],
              },
            },
          },
  };
}

/** One client's verifier: eight bytes it made up, and keeps resending. */
const VERIFIER = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
/** A second client's, for the same name. */
const OTHER_VERIFIER = Uint8Array.from([9, 9, 9, 9, 9, 9, 9, 9]);

/** Open `/dir/file` and hand back the stateid, with the file as the current FH. */
async function opened(client: Client, options: OpenOptions = {}): Promise<Stateid4> {
  const reply = await client.run([...TO_DIR, OPEN(options)]);
  expect(reply.compound.status).toBe(NFS4_OK);
  return resFor<Open4res>(reply, OP_OPEN).stateid!;
}

/** A stateid whose seqid is one behind — the `NFS4ERR_OLD_STATEID` shape. */
function oneBehind(stateid: Stateid4): Stateid4 {
  return { seqid: stateid.seqid - 1, other: stateid.other };
}

const ANONYMOUS: Stateid4 = { seqid: 0, other: new Uint8Array(12) };
const BYPASS: Stateid4 = { seqid: 0xff_ff_ff_ff, other: new Uint8Array(12).fill(0xff) };
const CURRENT: Stateid4 = { seqid: 1, other: new Uint8Array(12) };

/**
 * A driver that counts the file handles opened through it and closed again.
 *
 * The plain method counter cannot see this: `close` is a method of the
 * `FileHandleLike` the driver *returns*, not of the driver, so the handle has
 * to be wrapped as it goes past.
 */
function tracked(driver: FullFsDriver): {
  driver: FsDriver;
  handles: { opened: number; closed: number };
} {
  const handles = { opened: 0, closed: 0 };
  const wrap = (handle: FileHandleLike): FileHandleLike =>
    new Proxy(handle, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver) as unknown;
        if (typeof value !== "function") {
          return value;
        }
        if (property === "close") {
          return async () => {
            handles.closed++;
            await (value as () => Promise<void>).call(target);
          };
        }
        return (value as (...args: unknown[]) => unknown).bind(target);
      },
    });
  const proxy = new Proxy(driver, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver) as unknown;
      if (typeof value !== "function") {
        return value;
      }
      if (property === "open") {
        return async (...args: unknown[]) => {
          const handle = (await (value as (...rest: unknown[]) => Promise<FileHandleLike>).apply(
            target,
            args,
          )) as FileHandleLike;
          handles.opened++;
          return wrap(handle);
        };
      }
      return (value as (...args: unknown[]) => unknown).bind(target);
    },
  });
  return { driver: proxy as FsDriver, handles };
}

describe("OPEN", () => {
  it("opens an existing file, sets the current filehandle to it, and grants no delegation", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const reply = await client.run([...TO_DIR, OPEN(), { op: OP_GETFH }, GETATTR([FATTR4_SIZE])]);
    expect(reply.compound.status).toBe(NFS4_OK);
    const open = resFor<Open4res>(reply, OP_OPEN);
    // §18.16.3: "Upon success ... the current filehandle is replaced by that of
    // the created or existing object", which the GETATTR after it proves — the
    // current FH was `/dir` before the OPEN and the size is `/dir/file`'s.
    expect(session.handles.resolve(resFor<Getfh4res>(reply, OP_GETFH).object!)).toBe("/dir/file");
    expect(attrsFor(reply).size).toBe(5n);
    // §8.2.2: a new set of locks comes back with a seqid of one.
    expect(open.stateid!.seqid).toBe(1);
    // §18.16.3 rules OPEN4_RESULT_CONFIRM out for 4.1 and this server claims
    // only POSIX byte-range semantics.
    expect(open.rflags).toBe(OPEN4_RESULT_LOCKTYPE_POSIX);
    // The client asked for no delegation either way, so the plain NONE arm.
    expect(open.delegation!.delegationType).toBe(OPEN_DELEGATE_NONE);
    expect(open.attrset).toEqual([]);
  });

  it("creates with UNCHECKED4, reports only the attributes it set, and moves the directory's change", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const before = await changeOfPath(client);
    const reply = await client.run([
      ...TO_DIR,
      OPEN({
        name: "made",
        access: OPEN4_SHARE_ACCESS_BOTH,
        openhow: createHow(UNCHECKED4, { bits: [FATTR4_MODE], values: { mode: 0o640 } }),
      }),
      GETATTR([FATTR4_MODE, FATTR4_SIZE]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    const open = resFor<Open4res>(reply, OP_OPEN);
    expect(attrsFor(reply).mode).toBe(0o640);
    // Honest `attrset`: the mode went in as `open`'s argument and is reported;
    // nothing else was asked for, so nothing else is claimed.
    expect(open.attrset).toEqual(bitmapOf([FATTR4_MODE]));
    expect(open.cinfo!.before).toBe(before);
    expect(open.cinfo!.after).toBe(await changeOfPath(client));
    expect(open.cinfo!.atomic).toBe(false);
  });

  it("truncates an existing file on UNCHECKED4 with size zero, and applies nothing else", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const reply = await client.run([
      ...TO_DIR,
      OPEN({
        access: OPEN4_SHARE_ACCESS_BOTH,
        openhow: createHow(UNCHECKED4, {
          bits: [FATTR4_SIZE, FATTR4_MODE],
          values: { size: 0n, mode: 0o600 },
        }),
      }),
      GETATTR([FATTR4_SIZE, FATTR4_MODE]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    const values = attrsFor(reply);
    // §18.16.3: "When an UNCHECKED4 create encounters an existing file, the
    // attributes specified by createattrs are not used, except that when
    // createattrs specifies the size attribute with a size of zero, the
    // existing file is truncated."
    expect(values.size).toBe(0n);
    expect(values.mode).not.toBe(0o600);
    expect(resFor<Open4res>(reply, OP_OPEN).attrset).toEqual(bitmapOf([FATTR4_SIZE]));
  });

  it("refuses GUARDED4 over an existing file with NFS4ERR_EXIST, and creates when there is none", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const clash = await client.run([...TO_DIR, OPEN({ openhow: createHow(GUARDED4) })]);
    // §18.16.3: "If GUARDED4 is specified, the server checks for the presence
    // of a duplicate object by name before performing the create. If a
    // duplicate exists, NFS4ERR_EXIST is returned."
    expect(clash.compound.status).toBe(NFS4ERR_EXIST);

    const fresh = await client.run([
      ...TO_DIR,
      OPEN({ name: "guarded", openhow: createHow(GUARDED4) }),
    ]);
    expect(fresh.compound.status).toBe(NFS4_OK);
  });

  it("re-opens the current filehandle with CLAIM_FH", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const first = await client.run([...TO_DIR, { op: OP_LOOKUP, args: { objname: "file" } }]);
    expect(first.compound.status).toBe(NFS4_OK);
    // The file is the current filehandle, and CLAIM_FH names nothing else —
    // which is what a Linux client sends when it re-opens a file it has.
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "file" } },
      OPEN({ claim: { claim: CLAIM_FH } }),
      { op: OP_GETFH },
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    expect(session.handles.resolve(resFor<Getfh4res>(reply, OP_GETFH).object!)).toBe("/dir/file");
    // No target directory, so nothing to say about one.
    expect(resFor<Open4res>(reply, OP_OPEN).cinfo).toEqual({
      atomic: false,
      before: 0n,
      after: 0n,
    });
  });

  it("refuses a create whose claim carries no name with NFS4ERR_INVAL", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    // §18.16.3: "If opentype is OPEN4_CREATE, then the claim field ... MUST be
    // one of CLAIM_NULL, CLAIM_DELEGATE_CUR, or CLAIM_DELEGATE_PREV, because
    // these claim methods include a component of a file name."
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "file" } },
      OPEN({ claim: { claim: CLAIM_FH }, openhow: createHow(UNCHECKED4) }),
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_INVAL);
  });

  /**
   * §18.16.3's exclusive create, in both its shapes. The point of the mode is
   * that a client cannot make a create idempotent by itself: a lost reply
   * leaves it unable to tell "I created it" from "someone else did", so it
   * sends a verifier and the server remembers which verifier made which file.
   * `ExclusiveCreates` in `src/nfs/util.ts` states what that memory does and
   * does not cover — a retransmission, not a restart.
   */
  it("creates with either exclusive mode and answers the retry with the same file", async () => {
    for (const mode of [EXCLUSIVE4, EXCLUSIVE4_1]) {
      const session = new Nfs4Session(await populated());
      const client = await ready(session);
      const first = await client.run([
        ...TO_DIR,
        OPEN({ name: "exclusive", openhow: exclusiveHow(mode, VERIFIER) }),
        { op: OP_GETFH },
      ]);
      expect(first.compound.status).toBe(NFS4_OK);
      const created = resFor<Getfh4res>(first, OP_GETFH).object!;
      expect(session.handles.resolve(created)).toBe("/dir/exclusive");

      // The duplicate of a request whose reply never arrived: `NFS4_OK` and
      // the same file, where `GUARDED4` would now say NFS4ERR_EXIST.
      const retry = await client.run([
        ...TO_DIR,
        OPEN({ name: "exclusive", owner: 2, openhow: exclusiveHow(mode, VERIFIER) }),
        { op: OP_GETFH },
      ]);
      expect(retry.compound.status).toBe(NFS4_OK);
      expect([...resFor<Getfh4res>(retry, OP_GETFH).object!]).toEqual([...created]);

      // A different verifier on the same name is a *second client*, which is
      // the one case that really is NFS4ERR_EXIST.
      const rival = await client.run([
        ...TO_DIR,
        OPEN({ name: "exclusive", owner: 3, openhow: exclusiveHow(mode, OTHER_VERIFIER) }),
      ]);
      expect(rival.compound.status).toBe(NFS4ERR_EXIST);
    }
  });

  it("applies EXCLUSIVE4_1's cva_attrs and replays the same attrset", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const how = exclusiveHow(EXCLUSIVE4_1, VERIFIER, {
      bits: [FATTR4_MODE, FATTR4_SIZE],
      values: { mode: 0o640, size: 0n },
    });
    const reply = await client.run([
      ...TO_DIR,
      OPEN({ name: "both", access: OPEN4_SHARE_ACCESS_BOTH, openhow: how }),
      GETATTR([FATTR4_MODE]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    expect(attrsFor(reply).mode).toBe(0o640);
    // The same "which attributes were successfully set" answer the other two
    // create modes give — `creatverfattr` is the only difference on the wire.
    const attrset = resFor<Open4res>(reply, OP_OPEN).attrset;
    expect(attrset).toEqual(bitmapOf([FATTR4_MODE, FATTR4_SIZE]));

    // And the replay carries the set the lost reply carried, not an empty one.
    const retry = await client.run([
      ...TO_DIR,
      OPEN({ name: "both", owner: 2, access: OPEN4_SHARE_ACCESS_BOTH, openhow: how }),
    ]);
    expect(retry.compound.status).toBe(NFS4_OK);
    expect(resFor<Open4res>(retry, OP_OPEN).attrset).toEqual(attrset);

    // `EXCLUSIVE4` has no attributes to report, and reports none.
    const bare = await client.run([
      ...TO_DIR,
      OPEN({ name: "bare", openhow: exclusiveHow(EXCLUSIVE4, VERIFIER) }),
    ]);
    expect(bare.compound.status).toBe(NFS4_OK);
    expect(resFor<Open4res>(bare, OP_OPEN).attrset).toEqual(bitmapOf([]));
  });

  it("refuses an unsettable cva_attrs the way createattrs is refused", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    // Nothing is reserved to hold the verifier, so what may be named here is
    // exactly what SETATTR may name — and `fileid` is read-only in both.
    const reply = await client.run([
      ...TO_DIR,
      OPEN({
        name: "readonly-attr",
        openhow: exclusiveHow(EXCLUSIVE4_1, VERIFIER, {
          bits: [FATTR4_FILEID],
          values: { fileid: 7n },
        }),
      }),
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_INVAL);
    await expect(session.driver.stat("/dir/readonly-attr")).rejects.toThrow();
  });

  it("forgets the verifier once SETATTR commits it, or the name stops meaning that file", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const create = (name: string, owner: number): Op[] => [
      ...TO_DIR,
      OPEN({ name, owner, openhow: exclusiveHow(EXCLUSIVE4, VERIFIER) }),
    ];

    // The follow-up §18.16.4 sends the client back for. After it, the client
    // is not retrying the OPEN, and the entry has nothing left to protect.
    expect((await client.run(create("committed", 1))).compound.status).toBe(NFS4_OK);
    const set = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "committed" } },
      {
        op: OP_SETATTR,
        args: {
          stateid: ANONYMOUS,
          objAttributes: {
            attrmask: bitmapOf([FATTR4_MODE]),
            values: { mode: 0o600 },
            unsupported: [],
          },
        },
      },
    ]);
    expect(set.compound.status).toBe(NFS4_OK);
    expect((await client.run(create("committed", 2))).compound.status).toBe(NFS4ERR_EXIST);

    // Removed and re-created by somebody else: the name is a different file
    // now, and the promise made about the first one must not cover it.
    expect((await client.run(create("recycled", 3))).compound.status).toBe(NFS4_OK);
    const removed = await client.run([...TO_DIR, { op: OP_REMOVE, args: { target: "recycled" } }]);
    expect(removed.compound.status).toBe(NFS4_OK);
    const replaced = await client.run([
      ...TO_DIR,
      OPEN({ name: "recycled", owner: 4, openhow: createHow(UNCHECKED4) }),
    ]);
    expect(replaced.compound.status).toBe(NFS4_OK);
    expect((await client.run(create("recycled", 5))).compound.status).toBe(NFS4ERR_EXIST);
  });

  it("answers a reclaim with NFS4ERR_NO_GRACE, whichever claim asks", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    for (const claim of [
      { claim: CLAIM_PREVIOUS, delegateType: 0 },
      { claim: CLAIM_DELEG_PREV_FH },
    ]) {
      const reply = await client.run([...TO_DIR, OPEN({ claim })]);
      // §15.1.9.3: no active grace period, and no role in reclaiming locks.
      expect(reply.compound.status).toBe(NFS4ERR_NO_GRACE);
    }
  });

  it("answers a delegation claim with NFS4ERR_BAD_STATEID, having granted none", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const held = await opened(client);
    for (const claim of [
      { claim: CLAIM_DELEGATE_CUR, delegateCurInfo: { delegateStateid: ANONYMOUS, file: "file" } },
      // Even a stateid this server *did* issue is not a delegation: §8.2.4's
      // "valid in general but ... not appropriate to the context".
      { claim: CLAIM_DELEG_CUR_FH, ocDelegateStateid: held },
    ]) {
      const reply = await client.run([...TO_DIR, OPEN({ claim })]);
      expect(reply.compound.status).toBe(NFS4ERR_BAD_STATEID);
    }
  });

  it("tells a client that wanted a delegation why it has none", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const asked = await client.run([
      ...TO_DIR,
      OPEN({ access: OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG }),
    ]);
    const wanted = resFor<Open4res>(asked, OP_OPEN).delegation!;
    // §18.16.3: a client that sends a _WANT_ flag and gets no delegation "MUST"
    // be answered with OPEN_DELEGATE_NONE_EXT and a reason.
    expect(wanted.delegationType).toBe(OPEN_DELEGATE_NONE_EXT);
    expect(wanted.whynone).toEqual({ why: WND4_RESOURCE, serverWillSignalAvail: false });

    const declined = await client.run([
      ...TO_DIR,
      OPEN({
        owner: 2,
        access: OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
      }),
    ]);
    expect(resFor<Open4res>(declined, OP_OPEN).delegation!.whynone!.why).toBe(WND4_NOT_WANTED);

    const cancelled = await client.run([
      ...TO_DIR,
      OPEN({ owner: 3, access: OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_CANCEL }),
    ]);
    // §18.16.3: "the client specified OPEN4_SHARE_ACCESS_WANT_CANCEL and now
    // any 'want' for this file object is cancelled" — vacuously true of a
    // server that registers no wants. (The prose spells the reason
    // WND4_CANCELED and the XDR spells it WND4_CANCELLED; the constant follows
    // the XDR.)
    expect(resFor<Open4res>(cancelled, OP_OPEN).delegation!.whynone!.why).toBe(WND4_CANCELLED);
  });

  it("refuses a conflicting share reservation across two clients", async () => {
    const session = new Nfs4Session(await populated());
    const first = await ready(session, "client-a");
    const second = await ready(session, "client-b");
    const held = await first.run([
      ...TO_DIR,
      OPEN({ access: OPEN4_SHARE_ACCESS_READ, deny: OPEN4_SHARE_DENY_WRITE }),
    ]);
    expect(held.compound.status).toBe(NFS4_OK);

    const clash = await second.run([...TO_DIR, OPEN({ access: OPEN4_SHARE_ACCESS_WRITE })]);
    expect(clash.compound.status).toBe(NFS4ERR_SHARE_DENIED);
    // The other direction: a deny the first open's own access contradicts.
    const other = await second.run([
      ...TO_DIR,
      OPEN({ access: OPEN4_SHARE_ACCESS_READ, deny: OPEN4_SHARE_DENY_READ }),
    ]);
    expect(other.compound.status).toBe(NFS4ERR_SHARE_DENIED);
  });

  it("unions the access of a second OPEN by the same owner, keeping one stateid", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const first = await opened(client, { access: OPEN4_SHARE_ACCESS_READ });
    const second = await opened(client, { access: OPEN4_SHARE_ACCESS_WRITE });
    // §18.16.3: "the stateid returned as an 'other' field that matches that of
    // the previous open while the 'seqid' field is incremented".
    expect([...second.other]).toEqual([...first.other]);
    expect(second.seqid).toBe(first.seqid + 1);
    // And the union is real: a WRITE through it is allowed where the first
    // open alone would have been NFS4ERR_OPENMODE.
    const written = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "file" } },
      { op: OP_WRITE, args: { stateid: second, offset: 0n, stable: FILE_SYNC4, data: b("Z") } },
    ]);
    expect(written.compound.status).toBe(NFS4_OK);
  });

  it("answers an OPEN before RECLAIM_COMPLETE with NFS4ERR_GRACE", async () => {
    const session = new Nfs4Session(await populated());
    // Deliberately *not* `ready`: no RECLAIM_COMPLETE has been sent.
    const client = await Client.open(session);
    const reply = await client.run([...TO_DIR, OPEN()]);
    // §18.51.3: "If non-reclaim locking operations are done before the
    // RECLAIM_COMPLETE, an NFS4ERR_GRACE error will be returned."
    expect(reply.compound.status).toBe(NFS4ERR_GRACE);
  });

  it("refuses to open a directory", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const reply = await client.run([...TO_DIR, OPEN({ name: "sub" })]);
    expect(reply.compound.status).toBe(NFS4ERR_ISDIR);
  });
});

describe("READ and WRITE", () => {
  /** Open `/dir/file` for both, leaving it as the current filehandle. */
  async function readWrite(client: Client): Promise<Stateid4> {
    return opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
  }

  /** `PUTFH`-free preamble: walk to the file so the current FH is it. */
  const TO_FILE: Op[] = [...TO_DIR, { op: OP_LOOKUP, args: { objname: "file" } }];

  it("writes and reads the bytes back through an open stateid", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const stateid = await readWrite(client);
    const written = await client.run([
      ...TO_FILE,
      { op: OP_WRITE, args: { stateid, offset: 1n, stable: UNSTABLE4, data: b("XY") } },
    ]);
    expect(written.compound.status).toBe(NFS4_OK);
    const write = resFor<Write4res>(written, OP_WRITE);
    expect(write.count).toBe(2);
    // Table 20 allows a stronger `committed` than the `stable` asked for, and
    // every driver write is already durable — the claim `../v3/session.ts` makes.
    expect(write.committed).toBe(FILE_SYNC4);
    expect([...write.writeverf]).toEqual([...session.writeVerifier]);

    const read = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid, offset: 0n, count: 5 } },
    ]);
    const got = resFor<Read4res>(read, OP_READ);
    expect(new TextDecoder().decode(got.data)).toBe("hXYlo");
    expect(got.eof).toBe(true);
  });

  it("is exact about eof at the boundaries", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const stateid = await readWrite(client);
    const cases: [number, number, string, boolean][] = [
      // §18.22.3: eof is TRUE when offset + count reaches the size, and a read
      // starting at or past the end returns nothing with eof TRUE.
      [0, 4, "hell", false],
      [0, 5, "hello", true],
      [4, 1, "o", true],
      [5, 4, "", true],
      [9, 4, "", true],
      [5, 0, "", true],
    ];
    for (const [offset, count, data, eof] of cases) {
      const reply = await client.run([
        ...TO_FILE,
        { op: OP_READ, args: { stateid, offset: BigInt(offset), count } },
      ]);
      const read = resFor<Read4res>(reply, OP_READ);
      expect([new TextDecoder().decode(read.data), read.eof]).toEqual([data, eof]);
    }
  });

  it("refuses I/O the open mode does not sanction", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const readOnly = await opened(client, { access: OPEN4_SHARE_ACCESS_READ });
    const write = await client.run([
      ...TO_FILE,
      { op: OP_WRITE, args: { stateid: readOnly, offset: 0n, stable: FILE_SYNC4, data: b("!") } },
    ]);
    // §9.1.2 makes this a MUST for WRITE-type operations.
    expect(write.compound.status).toBe(NFS4ERR_OPENMODE);

    const writeOnly = await opened(client, { owner: 2, access: OPEN4_SHARE_ACCESS_WRITE });
    const read = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid: writeOnly, offset: 0n, count: 1 } },
    ]);
    // For READ the check is §9.1.2's MAY ("the server may perform the
    // corresponding check on the access mode, or it may choose to allow READ on
    // OPENs for OPEN4_SHARE_ACCESS_WRITE"), and this server takes it — which is
    // what lets it skip the share-reservation check for an open stateid.
    expect(read.compound.status).toBe(NFS4ERR_OPENMODE);
  });

  it("refuses a stateid it never issued, and one whose seqid is behind", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const stateid = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const upgraded = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    expect(upgraded.seqid).toBe(stateid.seqid + 1);

    const bogus = await client.run([
      ...TO_FILE,
      {
        op: OP_READ,
        args: { stateid: { seqid: 1, other: new Uint8Array(12).fill(7) }, offset: 0n, count: 1 },
      },
    ]);
    expect(bogus.compound.status).toBe(NFS4ERR_BAD_STATEID);

    const stale = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid: oneBehind(upgraded), offset: 0n, count: 1 } },
    ]);
    expect(stale.compound.status).toBe(NFS4ERR_OLD_STATEID);
  });

  it("refuses I/O on something that is not an ordinary file", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const stateid = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "sub" } },
      { op: OP_READ, args: { stateid, offset: 0n, count: 1 } },
    ]);
    // The type check comes first: §18.22.3's "in the case that the current
    // filehandle represents an object of type NF4DIR, NFS4ERR_ISDIR".
    expect(reply.compound.status).toBe(NFS4ERR_ISDIR);

    const link = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "link" } },
      { op: OP_READ, args: { stateid, offset: 0n, count: 1 } },
    ]);
    expect(link.compound.status).toBe(NFS4ERR_SYMLINK);
  });

  it("answers NFS4ERR_WRONG_TYPE for I/O on something that is neither of those", async () => {
    // The rule has three arms — directory, symlink, and everything else — and
    // a real FIFO is what reaches the third.
    const driver = await populated();
    await driver.mountx!.mknod!("/dir/fifo", S_IFIFO | 0o644, 0);
    const client = await ready(new Nfs4Session(driver));
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_LOOKUP, args: { objname: "fifo" } },
      { op: OP_READ, args: { stateid: ANONYMOUS, offset: 0n, count: 1 } },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_WRONG_TYPE);
  });

  it("serves anonymous I/O, and refuses it against a share reservation", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const plain = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid: ANONYMOUS, offset: 0n, count: 5 } },
    ]);
    expect(plain.compound.status).toBe(NFS4_OK);
    expect(new TextDecoder().decode(resFor<Read4res>(plain, OP_READ).data)).toBe("hello");

    const other = await ready(session, "client-b");
    expect(
      (
        await other.run([
          ...TO_DIR,
          OPEN({ access: OPEN4_SHARE_ACCESS_READ, deny: OPEN4_SHARE_DENY_READ }),
        ])
      ).compound.status,
    ).toBe(NFS4_OK);

    const denied = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid: ANONYMOUS, offset: 0n, count: 5 } },
    ]);
    // §9.1.2: "when the OPEN denies READ or WRITE operations, that denial
    // results in such operations being rejected with error NFS4ERR_LOCKED".
    expect(denied.compound.status).toBe(NFS4ERR_LOCKED);

    const bypassed = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid: BYPASS, offset: 0n, count: 5 } },
    ]);
    // §8.2.3: the all-ones stateid is a READ bypass — "when used in READ, the
    // server MAY grant access, even if access would normally be denied".
    expect(bypassed.compound.status).toBe(NFS4_OK);
  });

  it("gives the all-ones stateid no bypass on a WRITE", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const other = await ready(session, "client-b");
    expect(
      (
        await other.run([
          ...TO_DIR,
          OPEN({ access: OPEN4_SHARE_ACCESS_WRITE, deny: OPEN4_SHARE_DENY_WRITE }),
        ])
      ).compound.status,
    ).toBe(NFS4_OK);
    const reply = await client.run([
      ...TO_FILE,
      { op: OP_WRITE, args: { stateid: BYPASS, offset: 0n, stable: FILE_SYNC4, data: b("!") } },
    ]);
    // §18.32.3: "For a WRITE with a stateid value of all bits equal to 1, the
    // server MUST NOT allow the WRITE operation to bypass locking checks at the
    // server and otherwise is treated as if a stateid of all bits equal to zero
    // were used."
    expect(reply.compound.status).toBe(NFS4ERR_LOCKED);
  });

  it("clamps a READ to maxread and a WRITE to maxwrite", async () => {
    const session = new Nfs4Session(await populated(), { rtmax: 3, wtmax: 2 });
    const client = await ready(session);
    const stateid = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const written = await client.run([
      ...TO_FILE,
      { op: OP_WRITE, args: { stateid, offset: 0n, stable: FILE_SYNC4, data: b("ABCDE") } },
    ]);
    // "The server MAY write fewer bytes than requested by the client."
    expect(resFor<Write4res>(written, OP_WRITE).count).toBe(2);

    const read = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid, offset: 0n, count: 5 } },
    ]);
    const got = resFor<Read4res>(read, OP_READ);
    expect(new TextDecoder().decode(got.data)).toBe("ABl");
    expect(got.eof).toBe(false);
  });

  it("refuses an offset past what a driver can name", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const stateid = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const reply = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid, offset: 2n ** 63n, count: 1 } },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_INVAL);
  });
});

describe("CLOSE and OPEN_DOWNGRADE", () => {
  const TO_FILE: Op[] = [...TO_DIR, { op: OP_LOOKUP, args: { objname: "file" } }];

  it("closes an open, and answers the invalid special stateid", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const stateid = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const reply = await client.run([
      ...TO_FILE,
      { op: OP_CLOSE, args: { seqid: 99, openStateid: stateid } },
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    // §18.2.4: "the server SHOULD return the invalid special stateid (the
    // 'other' value is zero and the 'seqid' field is NFS4_UINT32_MAX)".
    const closed = resFor<Close4res>(reply, OP_CLOSE).openStateid!;
    expect(closed.seqid).toBe(0xff_ff_ff_ff);
    expect([...closed.other]).toEqual(Array.from({ length: 12 }, () => 0));

    const again = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid, offset: 0n, count: 1 } },
    ]);
    expect(again.compound.status).toBe(NFS4ERR_BAD_STATEID);
  });

  it("narrows the state on OPEN_DOWNGRADE, and refuses a widening one", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const stateid = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const down = await client.run([
      ...TO_FILE,
      {
        op: OP_OPEN_DOWNGRADE,
        args: {
          openStateid: stateid,
          seqid: 4,
          shareAccess: OPEN4_SHARE_ACCESS_READ,
          shareDeny: OPEN4_SHARE_DENY_NONE,
        },
      },
    ]);
    expect(down.compound.status).toBe(NFS4_OK);
    const narrowed = resFor<OpenDowngrade4res>(down, OP_OPEN_DOWNGRADE).openStateid!;
    expect(narrowed.seqid).toBe(stateid.seqid + 1);

    const write = await client.run([
      ...TO_FILE,
      {
        op: OP_WRITE,
        args: { stateid: narrowed, offset: 0n, stable: FILE_SYNC4, data: b("!") },
      },
    ]);
    // The driver handle behind it is still the wide one; what a WRITE is
    // checked against is the state, and the state narrowed.
    expect(write.compound.status).toBe(NFS4ERR_OPENMODE);

    const up = await client.run([
      ...TO_FILE,
      {
        op: OP_OPEN_DOWNGRADE,
        args: {
          openStateid: narrowed,
          seqid: 5,
          shareAccess: OPEN4_SHARE_ACCESS_BOTH,
          shareDeny: OPEN4_SHARE_DENY_NONE,
        },
      },
    ]);
    // §18.18.3: the bits SHOULD be a subset of those already granted, and this
    // server takes the SHOULD rather than granting an upgrade through the one
    // operation whose name says it cannot.
    expect(up.compound.status).toBe(NFS4ERR_INVAL);
  });

  it("refuses a CLOSE whose stateid names another file", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const stateid = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const reply = await client.run([
      ...TO_DIR,
      { op: OP_CLOSE, args: { seqid: 1, openStateid: stateid } },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_BAD_STATEID);
  });
});

describe("byte-range locks", () => {
  const TO_FILE: Op[] = [...TO_DIR, { op: OP_LOOKUP, args: { objname: "file" } }];

  /** A LOCK taking a new lock-owner off an open stateid. */
  function LOCK(
    openStateid: Stateid4,
    options: { type?: number; offset?: bigint; length?: bigint; owner?: number } = {},
  ): Op {
    return {
      op: OP_LOCK,
      args: {
        locktype: options.type ?? WRITE_LT,
        reclaim: false,
        offset: options.offset ?? 0n,
        length: options.length ?? 10n,
        locker: {
          newLockOwner: true,
          openOwner: {
            // The three seqids and the owner's clientid are the fields
            // §18.10.3 orders the server to ignore; they go out wrong on
            // purpose.
            openSeqid: 41,
            openStateid,
            lockSeqid: 42,
            lockOwner: { clientid: 0xdead_beefn, owner: Uint8Array.from([options.owner ?? 5]) },
          },
        },
      },
    };
  }

  it("grants a lock, releases exactly the range, and lets CLOSE through afterwards", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const open = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const locked = await client.run([...TO_FILE, LOCK(open)]);
    expect(locked.compound.status).toBe(NFS4_OK);
    const lockStateid = resFor<Lock4res>(locked, OP_LOCK).lockStateid!;
    expect(lockStateid.seqid).toBe(1);

    const held = await client.run([
      ...TO_FILE,
      { op: OP_CLOSE, args: { seqid: 1, openStateid: open } },
    ]);
    // §9.8, via §18.2.3: "The server MUST return failure if any locks would
    // exist after the CLOSE."
    expect(held.compound.status).toBe(NFS4ERR_LOCKS_HELD);

    const unlocked = await client.run([
      ...TO_FILE,
      {
        op: OP_LOCKU,
        args: { locktype: WRITE_LT, seqid: 8, lockStateid, offset: 0n, length: 10n },
      },
    ]);
    expect(unlocked.compound.status).toBe(NFS4_OK);
    expect(resFor<Locku4res>(unlocked, OP_LOCKU).lockStateid!.seqid).toBe(2);

    const closed = await client.run([
      ...TO_FILE,
      { op: OP_CLOSE, args: { seqid: 1, openStateid: open } },
    ]);
    expect(closed.compound.status).toBe(NFS4_OK);
  });

  it("denies a conflicting lock and names the holder's real client ID", async () => {
    const session = new Nfs4Session(await populated());
    const holder = await ready(session, "client-a");
    const rival = await ready(session, "client-b");
    const open = await opened(holder, { access: OPEN4_SHARE_ACCESS_BOTH });
    expect((await holder.run([...TO_FILE, LOCK(open, { owner: 5 })])).compound.status).toBe(
      NFS4_OK,
    );

    const rivalOpen = await opened(rival, { access: OPEN4_SHARE_ACCESS_BOTH });
    const denied = await rival.run([...TO_FILE, LOCK(rivalOpen, { owner: 6, offset: 4n })]);
    expect(denied.compound.status).toBe(NFS4ERR_DENIED);
    const body = resFor<Lock4res>(denied, OP_LOCK).denied!;
    // §18.10.3: "if the server returns NFS4ERR_DENIED, it MUST set the clientid
    // field of the owner field of the denied field" — to "the actual client
    // associated with the conflicting lock", which is the *other* client here.
    expect(body.owner.clientid).toBe(holder.clientid);
    expect(body.owner.clientid).not.toBe(rival.clientid);
    expect([...body.owner.owner]).toEqual([5]);
    expect(body).toMatchObject({ offset: 0n, length: 10n, locktype: WRITE_LT });

    const test = await rival.run([
      ...TO_FILE,
      {
        op: OP_LOCKT,
        args: {
          locktype: WRITE_LT,
          offset: 4n,
          length: 2n,
          owner: { clientid: 0xdead_beefn, owner: Uint8Array.from([6]) },
        },
      },
    ]);
    expect(test.compound.status).toBe(NFS4ERR_DENIED);
    expect(resFor<Lockt4res>(test, OP_LOCKT).denied!.owner.clientid).toBe(holder.clientid);

    const clear = await rival.run([
      ...TO_FILE,
      {
        op: OP_LOCKT,
        args: {
          locktype: WRITE_LT,
          offset: 20n,
          length: 2n,
          owner: { clientid: 0n, owner: Uint8Array.from([6]) },
        },
      },
    ]);
    // §18.11.3: "If no lock is held, nothing other than NFS4_OK is returned."
    expect(clear.compound.status).toBe(NFS4_OK);
    expect(resFor<Lockt4res>(clear, OP_LOCKT).denied).toBeUndefined();
  });

  it("lets a WRITE through another owner's lock, because the locks are advisory", async () => {
    // The locks this server grants are advisory in §9.1.2's sense: they "only
    // prevent the granting of conflicting lock requests and have no effect on
    // READs or WRITEs". So the thing a competing byte range blocks is the LOCK
    // — proved above — and *not* the I/O, which is what this checks. A server
    // implementing mandatory locking would answer NFS4ERR_LOCKED here instead.
    const session = new Nfs4Session(await populated());
    const holder = await ready(session, "client-a");
    const rival = await ready(session, "client-b");
    const open = await opened(holder, { access: OPEN4_SHARE_ACCESS_BOTH });
    expect((await holder.run([...TO_FILE, LOCK(open)])).compound.status).toBe(NFS4_OK);

    const rivalOpen = await opened(rival, { access: OPEN4_SHARE_ACCESS_BOTH });
    const written = await rival.run([
      ...TO_FILE,
      { op: OP_WRITE, args: { stateid: rivalOpen, offset: 0n, stable: FILE_SYNC4, data: b("Q") } },
    ]);
    expect(written.compound.status).toBe(NFS4_OK);
  });

  it("does I/O through a lock stateid, on the open's own handle", async () => {
    const { driver, handles } = tracked(await populated());
    const session = new Nfs4Session(driver);
    const client = await ready(session);
    const open = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const openedHandles = handles.opened;
    const locked = await client.run([...TO_FILE, LOCK(open)]);
    const lockStateid = resFor<Lock4res>(locked, OP_LOCK).lockStateid!;

    const reply = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid: lockStateid, offset: 0n, count: 5 } },
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    // §9.1.2: a lock stateid's access mode is the open's — and so is its handle.
    expect(handles.opened).toBe(openedHandles);
  });

  it("refuses a reclaiming LOCK with NFS4ERR_NO_GRACE", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const open = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const reply = await client.run([
      ...TO_FILE,
      {
        op: OP_LOCK,
        args: {
          locktype: READ_LT,
          reclaim: true,
          offset: 0n,
          length: 1n,
          locker: {
            newLockOwner: true,
            openOwner: {
              openSeqid: 0,
              openStateid: open,
              lockSeqid: 0,
              lockOwner: { clientid: 0n, owner: Uint8Array.from([5]) },
            },
          },
        },
      },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_NO_GRACE);
  });

  it("refuses a lock on a directory", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const open = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const reply = await client.run([...TO_DIR, LOCK(open)]);
    expect(reply.compound.status).toBe(NFS4ERR_ISDIR);
  });
});

describe("the current stateid", () => {
  const TO_FILE: Op[] = [...TO_DIR, { op: OP_LOOKUP, args: { objname: "file" } }];

  it("passes the stateid an OPEN returned to the READ after it", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    // §16.2.3.1.2, Figure 4: the OPEN sets the current stateid and the READ's
    // (seqid 1, other 0) means "that one".
    const reply = await client.run([
      ...TO_DIR,
      OPEN({ access: OPEN4_SHARE_ACCESS_BOTH }),
      { op: OP_READ, args: { stateid: CURRENT, offset: 0n, count: 5 } },
      { op: OP_CLOSE, args: { seqid: 1, openStateid: CURRENT } },
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    expect(new TextDecoder().decode(resFor<Read4res>(reply, OP_READ).data)).toBe("hello");
    expect(statusFor(reply, OP_CLOSE)).toBe(NFS4_OK);
  });

  it("refuses the current stateid when no operation has returned one", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    // §16.2.3.1.2, Figure 6: a LOOKUP sets the current filehandle and clears
    // the stateid to (0, 0), which is not a stateid to substitute.
    const reply = await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid: CURRENT, offset: 0n, count: 1 } },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_BAD_STATEID);
  });

  it("saves and restores the stateid with the filehandle", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const reply = await client.run([
      ...TO_DIR,
      OPEN({ access: OPEN4_SHARE_ACCESS_BOTH }),
      { op: OP_SAVEFH },
      ...TO_DIR,
      { op: OP_RESTOREFH },
      { op: OP_READ, args: { stateid: CURRENT, offset: 0n, count: 5 } },
    ]);
    // "The SAVEFH and RESTOREFH operations will save and restore both the
    // current filehandle and the current stateid as a set."
    expect(reply.compound.status).toBe(NFS4_OK);
    expect(new TextDecoder().decode(resFor<Read4res>(reply, OP_READ).data)).toBe("hello");
  });
});

describe("SETATTR with a stateid", () => {
  const TO_FILE: Op[] = [...TO_DIR, { op: OP_LOOKUP, args: { objname: "file" } }];

  /** SETATTR of `size`, which is the only attribute the stateid governs. */
  function TRUNCATE(stateid: Stateid4, size = 0n): Op {
    return {
      op: OP_SETATTR,
      args: {
        stateid,
        objAttributes: {
          attrmask: bitmapOf([FATTR4_SIZE]),
          values: { size },
          unsupported: [],
        },
      },
    };
  }

  it("accepts a valid open stateid and the anonymous one", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const stateid = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const sized = await client.run([...TO_FILE, TRUNCATE(stateid, 2n), GETATTR([FATTR4_SIZE])]);
    expect(sized.compound.status).toBe(NFS4_OK);
    expect(attrsFor(sized).size).toBe(2n);
    // §18.30.3: "When the file size attribute is not set, the special stateid
    // consisting of all bits equal to zero MAY be passed" — and when it *is*
    // set, the anonymous stateid is still legal so long as no reservation
    // denies the write.
    expect((await client.run([...TO_FILE, TRUNCATE(ANONYMOUS, 1n)])).compound.status).toBe(NFS4_OK);
  });

  it("refuses a size change the stateid does not sanction", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const readOnly = await opened(client, { access: OPEN4_SHARE_ACCESS_READ });
    // §9.1.2: a SETATTR that sets size "has the same locking requirements as a
    // corresponding WRITE", so the MUST applies.
    expect((await client.run([...TO_FILE, TRUNCATE(readOnly)])).compound.status).toBe(
      NFS4ERR_OPENMODE,
    );

    const both = await opened(client, { owner: 2, access: OPEN4_SHARE_ACCESS_BOTH });
    const upgraded = await opened(client, { owner: 2, access: OPEN4_SHARE_ACCESS_BOTH });
    expect(upgraded.seqid).toBe(both.seqid + 1);
    expect((await client.run([...TO_FILE, TRUNCATE(oneBehind(upgraded))])).compound.status).toBe(
      NFS4ERR_OLD_STATEID,
    );
  });

  it("ignores the stateid when the request does not set size", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const reply = await client.run([
      ...TO_FILE,
      {
        op: OP_SETATTR,
        args: {
          // A stateid this server never issued, which a size change would
          // refuse — §18.30.3 leaves it unexamined when size is absent.
          stateid: { seqid: 3, other: new Uint8Array(12).fill(9) },
          objAttributes: {
            attrmask: bitmapOf([FATTR4_MODE]),
            values: { mode: 0o604 },
            unsupported: [],
          },
        },
      },
      GETATTR([FATTR4_MODE]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    expect(attrsFor(reply).mode).toBe(0o604);
  });
});

describe("owner and owner_group mapping", () => {
  const TO_FILE: Op[] = [...TO_DIR, { op: OP_LOOKUP, args: { objname: "file" } }];

  /** A tiny two-entry name service, both directions. */
  const users: Record<number, string> = { 1000: "alice" };
  const groups: Record<number, string> = { 20: "staff" };
  const userIds: Record<string, number> = { alice: 1000 };
  const groupIds: Record<string, number> = { staff: 20 };
  const idmap = {
    domain: "example.org",
    nameOf: (id: number, group: boolean): string | undefined => (group ? groups[id] : users[id]),
    idOf: (name: string, group: boolean): number | undefined =>
      group ? groupIds[name] : userIds[name],
  };

  it("answers with numeric strings when nothing is configured", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const reply = await client.run([...TO_FILE, GETATTR([FATTR4_OWNER, FATTR4_OWNER_GROUP])]);
    const values = attrsFor(reply);
    // §5.9's NFSv3 compatibility form, which is all a server with no name
    // service can honestly say.
    expect(values.owner).toMatch(/^\d+$/);
    expect(values.ownerGroup).toMatch(/^\d+$/);
  });

  it("qualifies a mapped name with the configured domain, and maps it back", async () => {
    const session = new Nfs4Session(await populated(), { nfs4: { idmap } });
    const client = await ready(session);
    const set = await client.run([
      ...TO_FILE,
      {
        op: OP_SETATTR,
        args: {
          stateid: ANONYMOUS,
          objAttributes: {
            attrmask: bitmapOf([FATTR4_OWNER, FATTR4_OWNER_GROUP]),
            values: { owner: "alice@example.org", ownerGroup: "staff@example.org" },
            unsupported: [],
          },
        },
      },
      GETATTR([FATTR4_OWNER, FATTR4_OWNER_GROUP]),
    ]);
    expect(set.compound.status).toBe(NFS4_OK);
    expect(resFor<Setattr4res>(set, OP_SETATTR).attrsset).toEqual(
      bitmapOf([FATTR4_OWNER, FATTR4_OWNER_GROUP]),
    );
    const values = attrsFor(set);
    expect(values.owner).toBe("alice@example.org");
    expect(values.ownerGroup).toBe("staff@example.org");
    expect((await session.driver.stat("/dir/file")).uid).toBe(1000);
  });

  it("still takes the numeric form, and falls back to it for an unmapped id", async () => {
    const session = new Nfs4Session(await populated(), { nfs4: { idmap } });
    const client = await ready(session);
    const reply = await client.run([
      ...TO_FILE,
      {
        op: OP_SETATTR,
        args: {
          stateid: ANONYMOUS,
          objAttributes: {
            attrmask: bitmapOf([FATTR4_OWNER]),
            values: { owner: "4242" },
            unsupported: [],
          },
        },
      },
      GETATTR([FATTR4_OWNER]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    // The map has no name for 4242, so §5.9's unqualified numeric form comes
    // back — "the absence of the @ ... signifies that no translation was
    // available at the sender".
    expect(attrsFor(reply).owner).toBe("4242");
  });

  it("refuses a name it cannot map, and a domain it does not serve", async () => {
    const session = new Nfs4Session(await populated(), { nfs4: { idmap } });
    const client = await ready(session);
    // In order: a local name the map does not know, a domain this server does
    // not serve, and an unqualified string — which §5.9 defines as meaning "no
    // translation was available at the sender", never as a name to look up.
    for (const owner of ["nobody@example.org", "alice@elsewhere.example", "alice"]) {
      const reply = await client.run([
        ...TO_FILE,
        {
          op: OP_SETATTR,
          args: {
            stateid: ANONYMOUS,
            objAttributes: {
              attrmask: bitmapOf([FATTR4_OWNER]),
              values: { owner },
              unsupported: [],
            },
          },
        },
      ]);
      // §5.9: "Servers that do not provide support for all possible values of
      // the owner and owner_group attributes SHOULD return an error
      // (NFS4ERR_BADOWNER) when a string is presented that has no translation."
      expect(reply.compound.status).toBe(NFS4ERR_BADOWNER);
    }
  });

  it("refuses an unmappable owner in an OPEN's createattrs", async () => {
    const session = new Nfs4Session(await populated(), { nfs4: { idmap } });
    const client = await ready(session);
    const reply = await client.run([
      ...TO_DIR,
      OPEN({
        name: "owned",
        access: OPEN4_SHARE_ACCESS_BOTH,
        openhow: createHow(UNCHECKED4, {
          bits: [FATTR4_OWNER],
          values: { owner: "nobody@example.org" },
        }),
      }),
    ]);
    // §15.2 lists NFS4ERR_BADOWNER for OPEN as well as for SETATTR and CREATE.
    expect(reply.compound.status).toBe(NFS4ERR_BADOWNER);
  });
});

describe("driver handles", () => {
  const TO_FILE: Op[] = [...TO_DIR, { op: OP_LOOKUP, args: { objname: "file" } }];

  it("holds one open handle per open state, and closes it on CLOSE", async () => {
    const { driver, handles } = tracked(await populated());
    const session = new Nfs4Session(driver);
    const client = await ready(session);
    const stateid = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    expect(handles.opened - handles.closed).toBe(1);

    // Every READ and WRITE goes through that one handle: nothing is opened.
    const opens = handles.opened;
    await client.run([
      ...TO_FILE,
      { op: OP_WRITE, args: { stateid, offset: 0n, stable: FILE_SYNC4, data: b("Z") } },
      { op: OP_READ, args: { stateid, offset: 0n, count: 5 } },
    ]);
    expect(handles.opened).toBe(opens);

    const closed = await client.run([
      ...TO_FILE,
      { op: OP_CLOSE, args: { seqid: 1, openStateid: stateid } },
    ]);
    expect(closed.compound.status).toBe(NFS4_OK);
    expect(handles.opened).toBe(handles.closed);
  });

  it("opens one of its own for anonymous I/O, and closes it again", async () => {
    const { driver, handles } = tracked(await populated());
    const session = new Nfs4Session(driver);
    const client = await ready(session);
    await client.run([
      ...TO_FILE,
      { op: OP_READ, args: { stateid: ANONYMOUS, offset: 0n, count: 5 } },
    ]);
    expect(handles.opened).toBe(1);
    expect(handles.closed).toBe(1);
  });

  it("re-opens wider when an OPEN upgrades the access", async () => {
    const { driver, handles } = tracked(await populated());
    const session = new Nfs4Session(driver);
    const client = await ready(session);
    await opened(client, { access: OPEN4_SHARE_ACCESS_READ });
    const stateid = await opened(client, { access: OPEN4_SHARE_ACCESS_WRITE });
    // The narrow handle went as the wide one arrived, and there is still one.
    expect(handles.opened - handles.closed).toBe(1);
    const written = await client.run([
      ...TO_FILE,
      { op: OP_WRITE, args: { stateid, offset: 0n, stable: FILE_SYNC4, data: b("Z") } },
    ]);
    expect(written.compound.status).toBe(NFS4_OK);
  });

  it("closes what an expired lease revoked", async () => {
    let now = 0;
    const { driver, handles } = tracked(await populated());
    const session = new Nfs4Session(driver, {
      nfs4: { now: () => now, leaseSeconds: 1 },
    });
    const client = await ready(session);
    await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    expect(handles.opened - handles.closed).toBe(1);

    // The lease lapses, and the next SEQUENCE revokes what it was holding
    // (§8.4.3) — which reaches this file through `onOpenReleased`.
    now = 10_000;
    const after = await client.run([{ op: OP_PUTROOTFH }]);
    expect(after.compound.status).toBe(NFS4_OK);
    expect(handles.opened).toBe(handles.closed);
  });

  it("closes stragglers on destroy()", async () => {
    const { driver, handles } = tracked(await populated());
    const session = new Nfs4Session(driver);
    const client = await ready(session);
    await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    expect(handles.opened - handles.closed).toBe(1);
    await session.destroy();
    expect(handles.opened).toBe(handles.closed);
    // Idempotent: a second destroy has nothing left to close.
    await session.destroy();
    expect(handles.opened).toBe(handles.closed);
  });
});

describe("a reply too big to cache", () => {
  it("answers NFS4ERR_REP_TOO_BIG_TO_CACHE on the operation that overran, and caches that", async () => {
    const { driver, counts } = counting(await populated());
    // A cache that fits the SEQUENCE and the PUTROOTFH but not a GETATTR.
    const session = new Nfs4Session(driver, { nfs4: { maxCachedResponseSize: 96 } });
    const client = await Client.open(session);
    const ops: Op[] = [
      { op: OP_PUTROOTFH },
      GETATTR([FATTR4_SUPPORTED_ATTRS, FATTR4_CHANGE, FATTR4_SIZE, FATTR4_MODE, FATTR4_OWNER]),
      { op: OP_GETFH },
    ];
    const reply = await client.run(ops, { cachethis: true });
    // §2.10.6.4: "If the reply exceeds ca_maxresponsesize_cached (and
    // sa_cachethis ... is TRUE), then the server MUST return
    // NFS4ERR_REP_TOO_BIG_TO_CACHE."
    expect(reply.compound.status).toBe(NFS4ERR_REP_TOO_BIG_TO_CACHE);
    // SEQUENCE, PUTROOTFH, and the GETATTR carrying the status — the GETFH
    // after it is gone with the rest of the over-sized reply.
    expect(reply.compound.resarray).toHaveLength(3);
    expect(reply.compound.resarray[2]!.op).toBe(OP_GETATTR);
    expect(statusAt(reply, 2)).toBe(NFS4ERR_REP_TOO_BIG_TO_CACHE);

    // "...then the reply MUST be cached if sa_cachethis ... is TRUE": the
    // retransmission replays those exact bytes and re-runs nothing.
    const before = counts.get("lstat") ?? 0;
    const retry = await client.send([
      client.sequence({ cachethis: true, sequenceid: client.slotSeqid }),
      ...ops,
    ]);
    expect([...retry.body]).toEqual([...reply.body]);
    expect(counts.get("lstat") ?? 0).toBe(before);
  });

  it("gives up a result that fits when the status word would not, at the exact band", async () => {
    // The trim has to leave a reply that is *itself* within the cap, and the
    // replacement status word is not free. These two caps are the band where
    // the overrunning result (the READ) cannot be the one replaced — the reply
    // would come out over the cap by a few bytes, and §2.10.6.4's "then the
    // reply MUST be cached if sa_cachethis ... is TRUE" would be missed for
    // want of them — so the PUTFH before it, whose own result fitted, is what
    // carries the status instead.
    for (const cap of [64, 70]) {
      const { driver, counts } = counting(await populated());
      const session = new Nfs4Session(driver, { nfs4: { maxCachedResponseSize: cap } });
      const client = await Client.open(session);
      const found = await client.run([
        ...TO_DIR,
        { op: OP_LOOKUP, args: { objname: "file" } },
        { op: OP_GETFH },
      ]);
      const fh = resFor<Getfh4res>(found, OP_GETFH).object!;

      const ops: Op[] = [
        { op: OP_PUTFH, args: { object: fh } },
        { op: OP_READ, args: { stateid: ANONYMOUS, offset: 0n, count: 2048 } },
      ];
      const reply = await client.run(ops, { cachethis: true });
      expect(reply.compound.status).toBe(NFS4ERR_REP_TOO_BIG_TO_CACHE);
      expect(reply.compound.resarray).toHaveLength(2);
      expect(reply.compound.resarray[1]!.op).toBe(OP_PUTFH);
      expect(statusAt(reply, 1)).toBe(NFS4ERR_REP_TOO_BIG_TO_CACHE);
      // The reply that carries the status is small enough to be the one cached,
      // which is the whole point of trimming it.
      expect(reply.body.byteLength).toBeLessThanOrEqual(cap);

      const before = counts.get("open") ?? 0;
      const retry = await client.send([
        client.sequence({ cachethis: true, sequenceid: client.slotSeqid }),
        ...ops,
      ]);
      expect([...retry.body]).toEqual([...reply.body]);
      expect(counts.get("open") ?? 0).toBe(before);
    }
  });

  it("leaves a reply the client did not ask to cache alone", async () => {
    const session = new Nfs4Session(await populated(), { nfs4: { maxCachedResponseSize: 96 } });
    const client = await Client.open(session);
    const reply = await client.run([
      { op: OP_PUTROOTFH },
      GETATTR([FATTR4_SUPPORTED_ATTRS, FATTR4_CHANGE, FATTR4_SIZE, FATTR4_MODE, FATTR4_OWNER]),
    ]);
    // No `sa_cachethis`, so §2.10.6.4's rule does not apply and the whole
    // answer goes out.
    expect(reply.compound.status).toBe(NFS4_OK);
    expect(reply.compound.resarray).toHaveLength(3);
  });
});

describe("OPEN, the awkward paths", () => {
  const TO_FILE: Op[] = [...TO_DIR, { op: OP_LOOKUP, args: { objname: "file" } }];

  it("refuses a CLAIM_NULL whose current filehandle is not a directory", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const reply = await client.run([...TO_FILE, OPEN({ name: "under-a-file" })]);
    expect(reply.compound.status).toBe(NFS4ERR_NOTDIR);
  });

  it("leaves no open state behind when the driver refuses the handle", async () => {
    const base = await populated();
    // Everything works except `open`, which is the one call an OPEN makes
    // *after* `./state.ts` has already granted the share reservation.
    const driver = new Proxy(base, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver) as unknown;
        if (property === "open") {
          return () => Promise.reject(fsError("EACCES", { message: "EACCES: open" }));
        }
        return typeof value === "function"
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value;
      },
    }) as FsDriver;
    const session = new Nfs4Session(driver);
    const client = await ready(session);

    const plain = await client.run([...TO_DIR, OPEN()]);
    expect(plain.compound.status).toBe(13); // NFS4ERR_ACCESS
    // A stateid whose file could not be opened would only be found out about
    // on the client's first READ.
    expect(session.state.stateCount).toBe(0);

    const creating = await client.run([
      ...TO_DIR,
      OPEN({ name: "never", openhow: createHow(UNCHECKED4) }),
    ]);
    expect(creating.compound.status).toBe(13);
    expect(session.state.stateCount).toBe(0);
  });

  it("refuses an OPEN_DOWNGRADE of a stateid it never issued", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const reply = await client.run([
      ...TO_FILE,
      {
        op: OP_OPEN_DOWNGRADE,
        args: {
          openStateid: { seqid: 1, other: new Uint8Array(12).fill(3) },
          seqid: 1,
          shareAccess: OPEN4_SHARE_ACCESS_READ,
          shareDeny: OPEN4_SHARE_DENY_NONE,
        },
      },
    ]);
    expect(reply.compound.status).toBe(NFS4ERR_BAD_STATEID);
  });

  it("takes a second range through an established lock stateid", async () => {
    const session = new Nfs4Session(await populated());
    const client = await ready(session);
    const open = await opened(client, { access: OPEN4_SHARE_ACCESS_BOTH });
    const first = await client.run([
      ...TO_FILE,
      {
        op: OP_LOCK,
        args: {
          locktype: WRITE_LT,
          reclaim: false,
          offset: 0n,
          length: 4n,
          locker: {
            newLockOwner: true,
            openOwner: {
              openSeqid: 0,
              openStateid: open,
              lockSeqid: 0,
              lockOwner: { clientid: 0n, owner: Uint8Array.from([5]) },
            },
          },
        },
      },
    ]);
    const lockStateid = resFor<Lock4res>(first, OP_LOCK).lockStateid!;

    const second = await client.run([
      ...TO_FILE,
      {
        op: OP_LOCK,
        args: {
          locktype: WRITE_LT,
          reclaim: false,
          offset: 8n,
          length: 4n,
          // The `new_lock_owner == FALSE` arm: an established lock-owner named
          // by its stateid, with a `lock_seqid` the server must ignore.
          locker: { newLockOwner: false, lockOwner: { lockStateid, lockSeqid: 99 } },
        },
      },
    ]);
    expect(second.compound.status).toBe(NFS4_OK);
    expect(resFor<Lock4res>(second, OP_LOCK).lockStateid!.seqid).toBe(lockStateid.seqid + 1);
  });
});

// ---------------------------------------------------------------------------
// the Tier-1 client, over a real socket
// ---------------------------------------------------------------------------

/**
 * Everything above drives `Nfs4Session.handleCall` directly with encoded bytes.
 * This block puts a socket in the middle: `createNfsServer` on one side,
 * `./client.ts` on the other, and the record marking, the framing and the
 * connection lifetime between them.
 *
 * Three things are only visible from here:
 *
 * - **Replay is a transport property.** The in-process test above proves the
 *   slot cache; this one proves it survives being addressed by a *different
 *   RPC xid* on a live connection, which is what a retransmission actually is.
 * - **Both versions share one server.** The router, the `FileHandleTable` and
 *   the driver are one object each, and the only way to show a v3 and a v4
 *   conversation do not tread on each other is to hold both at once.
 * - **Teardown terminates.** A server closed under a connected client, and a
 *   client whose socket dies, are the two shapes a hang takes.
 */
describe("the v4 client over a real socket", () => {
  const servers: NfsServer[] = [];
  const clients: { close: () => void }[] = [];

  afterEach(async () => {
    for (const client of clients.splice(0)) {
      client.close();
    }
    for (const server of servers.splice(0)) {
      await server.close();
    }
  });

  /** A listening server over `driver`, closed by the hook above. */
  async function serve(driver: FsDriver = createMemoryDriver()): Promise<NfsServer> {
    const server = createNfsServer(driver);
    await server.listen();
    servers.push(server);
    return server;
  }

  /** A connected, established v4 client, closed by the hook above. */
  async function connect(
    server: NfsServer,
    options: Partial<Nfs4ClientOptions> = {},
  ): Promise<Nfs4Client> {
    const client = await Nfs4Client.open({ ...options, port: server.port });
    clients.push(client);
    return client;
  }

  /** A connected v3 client that has mounted `/`, plus that root handle. */
  async function connect3(server: NfsServer): Promise<{ client: Nfs3Client; root: Uint8Array }> {
    const client = await Nfs3Client.connect({ port: server.port });
    clients.push(client);
    const mounted = check3(await client.mnt("/"), "mount");
    return { client, root: mounted.fh! };
  }

  it("walks the handshake to a session, a slot table and a root filehandle", async () => {
    const server = await serve();
    const client = await connect(server);

    expect(client.session.clientid).not.toBe(0n);
    expect(client.session.sessionid).toHaveLength(16);
    // The slot table is sized by the server's counter-offer, not by the offer:
    // §18.36.3 makes every returned attribute the binding one.
    expect(client.slots).toHaveLength(client.session.foreChanAttrs.maxrequests);
    expect(client.slots.every((slot) => slot.seqid >= 0 && !slot.busy)).toBe(true);
    expect(server.session.stats.procedures.get("NFS4:COMPOUND")).toBeGreaterThan(0);

    const root = await client.rootFh();
    expect(root.byteLength).toBeGreaterThan(0);
    const attrs = await client.getattr(root, bitmapOf([FATTR4_TYPE]));
    expect(attrs.type).toBe(NF4DIR);
  });

  it("takes a file through its whole life: create, write, read, size, close", async () => {
    const driver = createMemoryDriver();
    const server = await serve(driver);
    const client = await connect(server);
    const root = await client.rootFh();
    await client.mkdir(root, "dir");

    const file = await client.open("/dir/hello", "w+");
    const written = await file.write(b("hello world"));
    expect(written.count).toBe(11);
    expect(written.committed).toBe(FILE_SYNC4);

    file.position = 0n;
    const read = await file.read(64);
    expect(new TextDecoder().decode(read.data)).toBe("hello world");
    expect(read.eof).toBe(true);

    expect((await file.stat(bitmapOf([FATTR4_SIZE]))).size).toBe(11n);
    const held = file.stateid;
    await file.close();
    // §18.2.4's invalid special stateid, and no I/O through the old one after.
    expect(file.stateid.seqid).toBe(0xff_ff_ff_ff);
    await expect(client.read(file.fh, 0n, 1, held)).rejects.toMatchObject({
      status: NFS4ERR_BAD_STATEID,
    });

    // The bytes are on the driver, not merely in a reply.
    expect(new TextDecoder().decode(await createLoopback(driver).readFile("/dir/hello"))).toBe(
      "hello world",
    );
  });

  it("resolves a path with PUTROOTFH and a LOOKUP chain, and reports a missing one", async () => {
    const server = await serve();
    const client = await connect(server);
    const root = await client.rootFh();
    const { fh: a } = await client.mkdir(root, "a");
    const { fh: bee } = await client.mkdir(a, "b");
    await client.mkdir(bee, "c");

    const walked = await client.walk("/a/b/c", bitmapOf([FATTR4_TYPE, FATTR4_FILEID]));
    expect(walked.attrs.type).toBe(NF4DIR);
    // The same object the component-by-component route reaches.
    const stepped = await client.lookup(await client.lookup(a, "b"), "c");
    expect([...walked.fh]).toEqual([...stepped]);
    expect(walked.attrs.fileid).toBe((await client.getattr(stepped)).fileid);

    await expect(client.walk("/a/b/missing")).rejects.toMatchObject({
      code: "ENOENT",
      status: NFS4ERR_NOENT,
    });
  });

  it("lists a directory by paging READDIR to eof", async () => {
    const driver = createMemoryDriver();
    for (let index = 0; index < 12; index++) {
      await driver.mkdir(`/entry-${index}`);
    }
    const server = await serve(driver);
    const client = await connect(server);
    const root = await client.rootFh();

    // A maxcount far below the whole listing, so eof is reached by paging.
    const entries = await client.readdirAll(root, {
      maxcount: 512,
      dircount: 128,
      attrRequest: bitmapOf([FATTR4_TYPE]),
    });
    expect(entries.map((entry) => entry.name).sort()).toEqual(
      Array.from({ length: 12 }, (_unused, index) => `entry-${index}`).sort(),
    );
    expect(new Set(entries.map((entry) => entry.cookie)).size).toBe(12);
    expect(entries.every((entry) => entry.attrs.values.type === NF4DIR)).toBe(true);
  });

  it("replays a cached reply byte for byte over the socket, without re-executing", async () => {
    const { driver, counts } = counting(await populated());
    const server = await serve(driver);
    const client = await connect(server);

    const ops = [
      argop(OP_PUTROOTFH),
      argop(OP_LOOKUP, { objname: "dir" }),
      argop(OP_GETATTR, { attrRequest: bitmapOf([FATTR4_TYPE, FATTR4_SIZE]) }),
    ];
    const first = await client.compound(ops, { cachethis: true, tag: "replayed" });
    expect(first.status).toBe(NFS4_OK);
    const lstats = counts.get("lstat") ?? 0;
    expect(lstats).toBeGreaterThan(0);

    // The same session, slot and sequence ID under a *different* xid: the
    // definition of a retransmission, and the only thing the server keys on.
    const again = await client.resendLast();
    expect(again.xid).not.toBe(first.xid);
    expect(again.slot).toBe(first.slot);
    expect(again.seqid).toBe(first.seqid);
    expect([...again.body]).toEqual([...first.body]);
    // Byte-identical alone would also pass for a server that re-ran the
    // operations and got the same answer; the counter is what rules that out.
    expect(counts.get("lstat")).toBe(lstats);

    // The other half of the escape hatch: an explicitly named slot and
    // sequence ID, built from scratch rather than resent.
    const explicit = await client.compound(ops, {
      slot: first.slot,
      seqid: first.seqid,
      cachethis: true,
      tag: "replayed",
    });
    expect([...explicit.body]).toEqual([...first.body]);
    expect(counts.get("lstat")).toBe(lstats);

    // And the client's own bookkeeping never moved, so the next request is
    // still in sequence.
    expect(client.slots[first.slot!]!.seqid).toBe(first.seqid);
    expect((await client.compound(ops)).status).toBe(NFS4_OK);
  });

  it("answers the retry of an uncached reply on the operation after SEQUENCE", async () => {
    const { driver, counts } = counting(await populated());
    const server = await serve(driver);
    const client = await connect(server);

    const first = await client.compound(
      [argop(OP_PUTROOTFH), argop(OP_LOOKUP, { objname: "dir" })],
      { cachethis: false },
    );
    expect(first.status).toBe(NFS4_OK);
    const lstats = counts.get("lstat") ?? 0;

    const retry = await client.resendLast();
    // §2.10.6.1.3: the refusal never lands on the leading SEQUENCE itself.
    expect((retry.resarray[0]!.res as Sequence4res).status).toBe(NFS4_OK);
    expect((retry.resarray[1]!.res as Status4res).status).toBe(10_068); // RETRY_UNCACHED_REP
    expect(retry.resarray).toHaveLength(2);
    expect(counts.get("lstat")).toBe(lstats);
  });

  it("takes a byte-range lock that a second client can see and then cannot", async () => {
    const server = await serve(await populated());
    const holder = await connect(server);
    const rival = await connect(server);

    const file = await holder.open("/dir/file", "r+");
    const locked = await file.lock({ locktype: WRITE_LT, offset: 0n, length: 4n });
    expect(locked.status).toBe(NFS4_OK);

    const denied = await rival.lockt(file.fh, {
      owner: new TextEncoder().encode("rival"),
      locktype: WRITE_LT,
      offset: 2n,
      length: 4n,
    });
    // §18.11.3 and §18.10.3: the conflict names the holder's real client ID.
    expect(denied?.owner.clientid).toBe(holder.session.clientid);

    await file.unlock({ locktype: WRITE_LT, offset: 0n, length: 4n });
    expect(
      await rival.lockt(file.fh, {
        owner: new TextEncoder().encode("rival"),
        locktype: WRITE_LT,
        offset: 2n,
        length: 4n,
      }),
    ).toBeUndefined();
    await file.close();
  });

  it("serves a v3 client and a v4 client on one server, over one driver", async () => {
    const server = await serve();
    const v3 = await connect3(server);
    const v4 = await connect(server);
    const v3fs = createLoopback(nfsDriver(v3.client, v3.root));
    const root = await v4.rootFh();

    // One handle table behind both programs: MOUNT's root and PUTROOTFH's are
    // the same bytes because they name the same driver path.
    expect([...root]).toEqual([...v3.root]);

    // v3 writes it, v4 reads it back through its own session.
    await v3fs.writeFile("/shared.txt", "from v3");
    const shared = await v4.walk("/shared.txt", bitmapOf([FATTR4_SIZE]));
    expect(shared.attrs.size).toBe(7n);
    const read = await v4.read(shared.fh, 0n, 32);
    expect(new TextDecoder().decode(read.data)).toBe("from v3");

    // ...and the other way, through a v4 OPEN this time.
    const file = await v4.open("/from-v4.txt", "w");
    await file.write(b("from v4"));
    await file.close();
    expect(new TextDecoder().decode(await v3fs.readFile("/from-v4.txt"))).toBe("from v4");

    // Interleaved, on both sockets at once. Each round writes a file per
    // version and reads the other version's back, so a reply delivered to the
    // wrong connection could not go unnoticed.
    for (let round = 0; round < 4; round++) {
      const [, made] = await Promise.all([
        v3fs.writeFile(`/v3-${round}.txt`, `three-${round}`),
        (async () => {
          const handle = await v4.open(`/v4-${round}.txt`, "w");
          await handle.write(b(`four-${round}`));
          await handle.close();
          return handle;
        })(),
      ]);
      expect(made.closed).toBe(true);
      const [fromV3, fromV4] = await Promise.all([
        v4.walk(`/v3-${round}.txt`, bitmapOf([FATTR4_SIZE])),
        v3fs.readFile(`/v4-${round}.txt`),
      ]);
      expect(Number(fromV3.attrs.size)).toBe(`three-${round}`.length);
      expect(new TextDecoder().decode(fromV4)).toBe(`four-${round}`);
    }

    // Both programs answered on the one socket pair, and the stats say so.
    expect(server.session.stats.procedures.get("NFS4:COMPOUND")).toBeGreaterThan(0);
    expect(server.session.stats.procedures.get("NFS:WRITE")).toBeGreaterThan(0);
    expect(server.session.stats.procedures.get("MOUNT:MNT")).toBe(1);
  });

  /**
   * The exclusive-create verifiers are the router's, like the handle table:
   * one server on one port, so the same request must get the same answer
   * whichever version carried it. A client that created over v3 and retries
   * over v4 has not changed its mind about anything.
   */
  it("recognises a v3 exclusive create retried over v4, from one table", async () => {
    const server = await serve();
    const v3 = await connect3(server);
    const v4 = await connect(server);
    const root = await v4.rootFh();

    const created = check3(
      await v3.client.create(v3.root, "excl", CREATE_EXCLUSIVE, {}, VERIFIER),
      "create",
    );
    const retried = await v4.openAt(root, "excl", {
      create: true,
      verifier: VERIFIER,
      access: OPEN4_SHARE_ACCESS_BOTH,
    });
    expect([...retried.fh]).toEqual([...created.obj!]);
    // v3's `EXCLUSIVE` carried no attributes, so none were applied and the
    // replay says so rather than claiming this OPEN's `cva_attrs` landed.
    await retried.close();

    // And a second client's verifier is refused on the same name, again
    // whichever version asks.
    await expect(
      v4.openAt(root, "excl", { create: true, verifier: OTHER_VERIFIER }),
    ).rejects.toThrow();
    expect(
      (await v3.client.create(v3.root, "excl", CREATE_EXCLUSIVE, {}, OTHER_VERIFIER)).status,
    ).toBe(NFS3ERR_EXIST);
  });

  it("destroys its session and leaves the next request without one", async () => {
    const server = await serve();
    const client = await connect(server);
    const sessionid = client.session.sessionid;

    const destroyed = await client.destroySession();
    expect(destroyed.status).toBe(NFS4_OK);
    expect(server.session.stats.dropped).toBe(0);

    // The slot table went with it, so the next SEQUENCE on it has nowhere to
    // land — §18.37.3 tells the client to expect exactly that.
    const orphaned = await client.compound(
      [
        argop(OP_SEQUENCE, {
          sessionid,
          sequenceid: 1,
          slotid: 0,
          highestSlotid: 0,
          cachethis: false,
        }),
        argop(OP_PUTROOTFH),
      ],
      { sequence: false },
    );
    expect(orphaned.status).toBe(10_052); // NFS4ERR_BADSESSION

    // A fresh handshake on the same connection works, which is what a client
    // that lost its session does next.
    const again = await Nfs4Client.open({ port: server.port });
    clients.push(again);
    expect((await again.renew()).status).toBe(NFS4_OK);
  });

  it("closes the server under a live client without hanging", async () => {
    const server = await serve();
    const client = await connect(server);
    expect((await client.renew()).status).toBe(NFS4_OK);
    expect(server.connections).toBe(1);

    // `close()` drops every connection rather than waiting for it: a mounted
    // client never goes away politely. If that were not true this line would
    // never return, which is the assertion.
    await server.close();
    expect(server.connections).toBe(0);

    // And the client learns, rather than parking a promise forever.
    await expect(client.renew()).rejects.toThrow();
  });

  it("keeps one compound's results addressable by opcode, whatever the shape", async () => {
    const server = await serve(await populated());
    const client = await connect(server);
    // A single compound doing the whole of `stat("/dir/file")`, which is the
    // reason NFSv4 has compounds at all: four operations, one round trip.
    const reply: Compound4reply = await client.compound(
      [
        argop(OP_PUTROOTFH),
        argop(OP_LOOKUP, { objname: "dir" }),
        argop(OP_LOOKUP, { objname: "file" }),
        argop(OP_GETFH),
        argop(OP_GETATTR, { attrRequest: OBJECT_ATTRS }),
      ],
      { tag: "stat" },
    );
    expect(reply.status).toBe(NFS4_OK);
    expect(reply.tag).toBe("stat");
    // SEQUENCE plus the five above.
    expect(reply.resarray).toHaveLength(6);
    const attrs = (reply.resarray[5]!.res as Getattr4res).objAttributes!.values;
    expect(attrs.size).toBe(5n);
    expect(attrs.numlinks).toBe(1);
    expect(server.session.handles.resolve((reply.resarray[4]!.res as Getfh4res).object!)).toBe(
      "/dir/file",
    );
  });

  it("covers the rest of the operation surface the conformance column will need", async () => {
    const server = await serve(await populated());
    const client = await connect(server);
    const root = await client.rootFh();
    const dir = await client.lookup(root, "dir");

    // ACCESS, LOOKUPP, SECINFO.
    expect((await client.access(dir)).access & ACCESS4_LOOKUP).toBe(ACCESS4_LOOKUP);
    expect([...(await client.lookupp(dir))]).toEqual([...root]);
    expect((await client.secinfo(dir, "file")).flavors.map((entry) => entry.flavor)).toEqual([
      1, 0,
    ]);

    // CREATE makes everything that is not an ordinary file, and READLINK reads
    // one of them back.
    const { fh: made } = await client.mkdir(dir, "made", 0o750);
    expect((await client.getattr(made, bitmapOf([FATTR4_MODE]))).mode).toBe(0o750);
    await client.symlink(dir, "made-link", "./file");
    expect(await client.readlink(await client.lookup(dir, "made-link"))).toBe("./file");

    // LINK, RENAME, REMOVE — counted on the link count of the file all three
    // touch, which is the one number that cannot be right by accident.
    const file = await client.lookup(dir, "file");
    await client.link(file, root, "hard");
    expect((await client.getattr(file, bitmapOf([FATTR4_NUMLINKS]))).numlinks).toBe(2);
    await client.rename(root, "hard", root, "moved");
    await client.remove(root, "moved");
    expect((await client.getattr(file, bitmapOf([FATTR4_NUMLINKS]))).numlinks).toBe(1);

    // SETATTR out, GETATTR back, and VERIFY/NVERIFY comparing against both.
    const set = await client.setattr(file, { mode: 0o640 });
    expect(bitmapHas(set.attrsset, FATTR4_MODE)).toBe(true);
    expect((await client.getattr(file, bitmapOf([FATTR4_MODE]))).mode).toBe(0o640);
    const same = fattr(bitmapOf([FATTR4_MODE]), { mode: 0o640 });
    const different = fattr(bitmapOf([FATTR4_MODE]), { mode: 0o600 });
    expect(await client.verify(file, same)).toBe(NFS4_OK);
    expect(await client.verify(file, different)).toBe(NFS4ERR_NOT_SAME);
    expect(await client.verify(file, different, true)).toBe(NFS4_OK);
    expect(await client.verify(file, same, true)).toBe(NFS4ERR_SAME);

    // COMMIT, and the per-filesystem attributes that stand in for FSSTAT/FSINFO.
    expect((await client.commit(file)).writeverf).toHaveLength(8);
    const fs = await client.statfs(root);
    expect(fs.maxread).toBeGreaterThan(0n);
    expect(fs.maxname).toBeGreaterThan(0);
    expect(fs.spaceTotal).toBeGreaterThan(0n);

    // TEST_STATEID, OPEN_DOWNGRADE and FREE_STATEID around a real open.
    const handle = await client.openAt(dir, "file", { access: OPEN4_SHARE_ACCESS_BOTH });
    expect(await client.testStateid([handle.stateid])).toEqual([NFS4_OK]);
    await handle.downgrade(OPEN4_SHARE_ACCESS_READ);
    expect(handle.access).toBe(OPEN4_SHARE_ACCESS_READ);
    // §18.38.3: the stateid is still held, so there is nothing to free.
    expect(await client.freeStateid(handle.stateid)).toBe(NFS4ERR_LOCKS_HELD);
    await handle.close();
    await handle.close(); // idempotent, so a `finally` need not check
  });

  it("refuses a second establish() on a live session by name", async () => {
    const server = await serve();
    const client = await connect(server);
    const sessionid = client.session.sessionid;

    // The failure this replaces was silent: the same `client_owner4` reads as a
    // retry to §18.35.4, so both handshake operations come back from the client
    // ID's reply cache naming the session that already exists, and the
    // RECLAIM_COMPLETE behind them lands on a slot table rebuilt from zero —
    // NFS4ERR_RETRY_UNCACHED_REP, with nothing saying why.
    await expect(client.establish()).rejects.toThrow(/already established/);
    // And it is a refusal, not a half-attempt: the session is untouched.
    expect([...client.session.sessionid]).toEqual([...sessionid]);
    expect((await client.renew()).status).toBe(NFS4_OK);
  });

  it("establishes again after losing its session, as a reboot rather than a retry", async () => {
    const server = await serve(await populated());
    const client = await connect(server);
    const first = client.session;

    expect((await client.destroySession()).status).toBe(NFS4_OK);
    expect(client.hasSession).toBe(false);

    const second = await client.establish();
    // A fresh `co_verifier` under the same `co_ownerid` is §18.35.4's reboot:
    // the server discards the old record and mints a session rather than
    // replaying the one that just went away.
    expect([...second.sessionid]).not.toEqual([...first.sessionid]);
    expect(client.hasSession).toBe(true);
    // And it is a working session, not just a different number: the slot table
    // was rebuilt, so the only sequence ID spent on it is the new handshake's
    // RECLAIM_COMPLETE. The old table had spent two — the first handshake's
    // RECLAIM_COMPLETE and the DESTROY_SESSION — so a table carried over would
    // ask for 3 here and the server would answer SEQ_MISORDERED.
    expect(client.slots[0]!.seqid).toBe(1);
    const reply = await client.compound([argop(OP_PUTROOTFH), argop(OP_GETFH)], { tag: "after" });
    expect(reply.status).toBe(NFS4_OK);
    expect((reply.resarray[0]!.res as Sequence4res).sequenceid).toBe(2);
    expect(server.session.handles.resolve(resFor4<Getfh4res>(reply, OP_GETFH).object!)).toBe("/");
    expect((await client.walk("/dir", bitmapOf([FATTR4_TYPE]))).attrs.type).toBe(NF4DIR);
  });

  it("leaves no session behind when the handshake fails past CREATE_SESSION", async () => {
    const server = await serve();
    // `ca_maxoperations` 1 is a session that cannot carry SEQUENCE plus
    // anything — so CREATE_SESSION succeeds and the RECLAIM_COMPLETE behind it
    // is refused, which is the one failure that happens with `#session` already
    // set (it needs a SEQUENCE to ride).
    const client = await Nfs4Client.connect({ port: server.port, channel: { maxoperations: 1 } });
    clients.push(client);
    await expect(client.establish()).rejects.toMatchObject({ status: NFS4ERR_TOO_MANY_OPS });

    expect(client.hasSession).toBe(false);
    expect(() => client.session).toThrow(/no session/);
    expect(client.slots).toEqual([]);
    await expect(client.resendLast()).rejects.toThrow(/nothing to resend/);

    // ...and the client is still usable: a retry with a workable offer works,
    // which it could not if the failed attempt had left state behind.
    const workable = await connect(server);
    expect((await workable.renew()).status).toBe(NFS4_OK);
  });

  it("reads two clients sharing a co_ownerid as a reboot, not a replayed handshake", async () => {
    const server = await serve();
    const first = await connect(server, { ownerid: "shared" });
    const second = await connect(server, { ownerid: "shared" });

    // The default `co_verifier` differs per client, so the pair §18.35.4 reads
    // as identity does too: the second client is the first having rebooted,
    // which is a new session — not the reply-cache replay (and unexplained
    // NFS4ERR_RETRY_UNCACHED_REP) that a shared verifier would have produced.
    expect([...second.session.sessionid]).not.toEqual([...first.session.sessionid]);
    expect((await second.renew()).status).toBe(NFS4_OK);
    // And the first client's state was discarded with its record, which is what
    // a reboot means and is a status that names the cause.
    expect((await first.renew()).status).toBe(10_052); // NFS4ERR_BADSESSION
  });
});

/**
 * The rule in `src/ownership.ts`, driven through CREATE and a creating OPEN.
 *
 * §18.4.3 has the server "derive the owner ... from the principal indicated in
 * the RPC credentials of the call", and says nothing about the group, because
 * the group is not the principal's to give: a set-gid parent hands its own
 * down, and a new directory takes the bit with it. The fixture is built through
 * the driver rather than through the server, so the setup is not itself subject
 * to the rule under test.
 */
describe("set-gid inheritance", () => {
  const TEAM = 4000;
  /** A caller in no group the fixture uses, so every group below is inherited. */
  const OUTSIDER = credential(4242, 4343);
  /** The same caller, with the team in its supplementary list (`AUTH_SYS` gids). */
  const MEMBER = credential(4242, 4343, [7, TEAM]);

  function credential(uid: number, gid: number, gids: number[] = []): OpaqueAuth {
    // `authSys()` always sends an empty `gids`, and the supplementary list is
    // exactly what one half of the rule turns on.
    return {
      flavor: AUTH_SYS,
      body: encodeAuthSys({ stamp: 0, machineName: "test", uid, gid, gids }),
    };
  }

  /** `/team` is set-gid and owned by group 4000; `/plain` is an ordinary one. */
  async function fixture(): Promise<FullFsDriver> {
    const driver = createMemoryDriver();
    await driver.mkdir("/team");
    await driver.chown("/team", 500, TEAM);
    await driver.chmod("/team", 0o2775);
    await driver.mkdir("/plain");
    return driver;
  }

  async function serving(
    options: { cred?: OpaqueAuth; claimOwnership?: boolean } = {},
  ): Promise<{ session: Nfs4Session; client: Client }> {
    const session = new Nfs4Session(await fixture(), {
      claimOwnership: options.claimOwnership,
    });
    return { session, client: await ready(session, "test-client", options.cred ?? OUTSIDER) };
  }

  const TO_TEAM: Op[] = [{ op: OP_PUTROOTFH }, { op: OP_LOOKUP, args: { objname: "team" } }];
  const TO_PLAIN: Op[] = [{ op: OP_PUTROOTFH }, { op: OP_LOOKUP, args: { objname: "plain" } }];

  it("gives a file created by OPEN the parent's group and the caller the ownership", async () => {
    const { session, client } = await serving();
    const reply = await client.run([
      ...TO_TEAM,
      OPEN({
        name: "f",
        access: OPEN4_SHARE_ACCESS_BOTH,
        openhow: createHow(UNCHECKED4, { bits: [FATTR4_MODE], values: { mode: 0o644 } }),
      }),
      GETATTR([FATTR4_OWNER, FATTR4_OWNER_GROUP]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    // §5.9's numeric form, since nothing is idmapped here.
    expect(attrsFor(reply)).toMatchObject({ owner: "4242", ownerGroup: String(TEAM) });
    expect(await session.driver.lstat("/team/f")).toMatchObject({ uid: 4242, gid: TEAM });
  });

  it("inherits on the exclusive create paths as well", async () => {
    const { session, client } = await serving();
    for (const [mode, name] of [
      [EXCLUSIVE4, "one"],
      [EXCLUSIVE4_1, "two"],
    ] as const) {
      const reply = await client.run([
        ...TO_TEAM,
        OPEN({
          name,
          access: OPEN4_SHARE_ACCESS_BOTH,
          openhow: exclusiveHow(mode, VERIFIER),
        }),
      ]);
      expect(reply.compound.status).toBe(NFS4_OK);
      expect((await session.driver.lstat(`/team/${name}`)).gid).toBe(TEAM);
    }
  });

  it("gives a new directory the group *and* the set-gid bit", async () => {
    const { session, client } = await serving();
    const reply = await client.run([
      ...TO_TEAM,
      {
        op: OP_CREATE,
        args: {
          objtype: { type: NF4DIR },
          objname: "sub",
          createattrs: {
            attrmask: bitmapOf([FATTR4_MODE]),
            values: { mode: 0o750 },
            unsupported: [],
          },
        },
      },
      GETATTR([FATTR4_MODE, FATTR4_OWNER_GROUP]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    // `inode(7)`: "newly created subdirectories inherit the set-group-ID bit",
    // which is what makes the rule apply to a whole tree rather than one level.
    expect(attrsFor(reply)).toMatchObject({ mode: 0o2750, ownerGroup: String(TEAM) });
    // A symlink takes the group and keeps its own 0o777 — nothing was chmod'ed
    // through the link.
    const link = await client.run([
      ...TO_TEAM,
      {
        op: OP_CREATE,
        args: {
          objtype: { type: NF4LNK, linkdata: "./f" },
          objname: "l",
          createattrs: { attrmask: [], values: {}, unsupported: [] },
        },
      },
    ]);
    expect(link.compound.status).toBe(NFS4_OK);
    expect(await session.driver.lstat("/team/l")).toMatchObject({ gid: TEAM, mode: 0o120777 });
  });

  it("gives the caller's own group in an ordinary directory", async () => {
    const { session, client } = await serving();
    const reply = await client.run([
      ...TO_PLAIN,
      {
        op: OP_CREATE,
        args: {
          objtype: { type: NF4DIR },
          objname: "sub",
          createattrs: {
            attrmask: bitmapOf([FATTR4_MODE]),
            values: { mode: 0o750 },
            unsupported: [],
          },
        },
      },
      GETATTR([FATTR4_MODE, FATTR4_OWNER_GROUP]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    // No parent bit, nothing to inherit: the mode is the one that was asked for.
    expect(attrsFor(reply)).toMatchObject({ mode: 0o750, ownerGroup: "4343" });
    expect((await session.driver.lstat("/plain/sub")).gid).toBe(4343);
  });

  it("clears set-gid on a new executable the creator has no claim to that group", async () => {
    const outsider = await serving();
    const reply = await outsider.client.run([
      ...TO_TEAM,
      OPEN({
        name: "run",
        access: OPEN4_SHARE_ACCESS_BOTH,
        openhow: createHow(UNCHECKED4, { bits: [FATTR4_MODE], values: { mode: 0o2775 } }),
      }),
      GETATTR([FATTR4_MODE]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    // A set-gid executable is a way to *run as* a group, so one may not be made
    // for a group its creator is not in — `inode_init_owner()`, and the reason
    // the supplementary list is on the wire at all.
    expect(attrsFor(reply).mode).toBe(0o775);

    const member = await serving({ cred: MEMBER });
    const kept = await member.client.run([
      ...TO_TEAM,
      OPEN({
        name: "run",
        access: OPEN4_SHARE_ACCESS_BOTH,
        openhow: createHow(UNCHECKED4, { bits: [FATTR4_MODE], values: { mode: 0o2775 } }),
      }),
      GETATTR([FATTR4_MODE]),
    ]);
    expect(kept.compound.status).toBe(NFS4_OK);
    expect(attrsFor(kept).mode).toBe(0o2775);
  });

  it("does not claim at all with claimOwnership off", async () => {
    const { session, client } = await serving({ claimOwnership: false });
    const reply = await client.run([
      ...TO_TEAM,
      {
        op: OP_CREATE,
        args: {
          objtype: { type: NF4DIR },
          objname: "sub",
          createattrs: {
            attrmask: bitmapOf([FATTR4_MODE]),
            values: { mode: 0o750 },
            unsupported: [],
          },
        },
      },
      GETATTR([FATTR4_MODE]),
    ]);
    expect(reply.compound.status).toBe(NFS4_OK);
    // Whatever the driver did on its own: no bit added, no group inherited.
    expect(attrsFor(reply).mode).toBe(0o750);
    expect((await session.driver.lstat("/team/sub")).gid).toBe(process.getgid?.() ?? 0);
  });
});
