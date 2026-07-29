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

import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../../src/drivers/memory.ts";
import { fsError } from "../../../src/errors.ts";
import {
  authSys,
  decodeReply,
  encodeCall,
  MSG_ACCEPTED,
  RPC_PROC_UNAVAIL,
  RPC_SUCCESS,
} from "../../../src/nfs/rpc.ts";
import { NfsSession } from "../../../src/nfs/session.ts";
import type { FsDriver, FullFsDriver } from "../../../src/types.ts";
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
  FATTR4_CHANGE,
  FATTR4_FILEID,
  FATTR4_MODE,
  FATTR4_NUMLINKS,
  FATTR4_OWNER,
  FATTR4_RDATTR_ERROR,
  FATTR4_SIZE,
  FATTR4_SPACE_TOTAL,
  FATTR4_SUPPORTED_ATTRS,
  FATTR4_TIME_ACCESS_SET,
  FATTR4_TIME_MODIFY,
  FATTR4_TIME_MODIFY_SET,
  FATTR4_TYPE,
  NF4DIR,
  NF4LNK,
  NF4REG,
  NFS4_OK,
  NFS4_PROGRAM,
  NFS4ERR_ATTRNOTSUPP,
  NFS4ERR_BADTYPE,
  NFS4ERR_INVAL,
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
  OP_READ,
  OP_READDIR,
  OP_READLINK,
  OP_REMOVE,
  OP_RENAME,
  OP_RESTOREFH,
  OP_SAVEFH,
  OP_SECINFO,
  OP_SEQUENCE,
  OP_SETATTR,
  OP_VERIFY,
  OP_WRITE,
  SET_TO_CLIENT_TIME4,
  SP4_NONE,
} from "../../../src/nfs/v4/constants.ts";
import {
  type Access4res,
  type ChannelAttrs4,
  type Compound4res,
  type Create4res,
  type CreateSession4res,
  type ExchangeId4res,
  type Getattr4res,
  type Getfh4res,
  NFS4_MAX_TAG,
  OP_CODECS,
  type Readdir4res,
  type Readlink4res,
  type Remove4res,
  type Rename4res,
  type Resop4,
  type Secinfo4res,
  type Sequence4res,
  type Setattr4res,
  type Status4res,
} from "../../../src/nfs/v4/protocol.ts";
import { Nfs4Session } from "../../../src/nfs/v4/session.ts";
import { XdrWriter } from "../../../src/nfs/xdr.ts";

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
  options: { tag?: string; minorversion?: number; xid?: number; count?: number } = {},
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
      cred: authSys(1000, 1000),
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

  constructor(readonly session: Nfs4Session) {}

  static async open(session: Nfs4Session, ownerid = "test-client"): Promise<Client> {
    const client = new Client(session);
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
    const { bytes } = compoundCall(ops, options);
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

  const ANON = { seqid: 0, other: new Uint8Array(12) };
  for (const [name, entry] of [
    [
      "OPEN",
      {
        op: OP_OPEN,
        args: {
          seqid: 1,
          shareAccess: 1,
          shareDeny: 0,
          owner: { clientid: 0n, owner: Uint8Array.from([1]) },
          openhow: { opentype: 0 },
          claim: { claim: 0, file: "file" },
        },
      },
    ],
    ["READ", { op: OP_READ, args: { stateid: ANON, offset: 0n, count: 4 } }],
    [
      "WRITE",
      { op: OP_WRITE, args: { stateid: ANON, offset: 0n, stable: 2, data: new Uint8Array(1) } },
    ],
    ["CLOSE", { op: OP_CLOSE, args: { seqid: 1, openStateid: ANON } }],
    [
      "OPEN_DOWNGRADE",
      {
        op: OP_OPEN_DOWNGRADE,
        args: { openStateid: ANON, seqid: 1, shareAccess: 1, shareDeny: 0 },
      },
    ],
    [
      "LOCKT",
      {
        op: OP_LOCKT,
        args: {
          locktype: 1,
          offset: 0n,
          length: 1n,
          owner: { clientid: 0n, owner: Uint8Array.from([2]) },
        },
      },
    ],
    [
      "LOCKU",
      {
        op: OP_LOCKU,
        args: { locktype: 1, seqid: 1, lockStateid: ANON, offset: 0n, length: 1n },
      },
    ],
  ] as [string, Op][]) {
    it(`answers ${name} with NFS4ERR_NOTSUPP for now`, async () => {
      const { driver, counts } = counting(await populated());
      const session = new Nfs4Session(driver);
      const client = await Client.open(session);
      // The arguments are decoded in full — only the handler is pending — and
      // the compound halts there, which the trailing GETFH proves.
      const reply = await client.run([...TO_DIR, entry, { op: OP_GETFH }]);
      expect(reply.compound.status).toBe(NFS4ERR_NOTSUPP);
      expect(reply.compound.resarray).toHaveLength(4);
      expect(counts.get("open")).toBeUndefined();
    });
  }
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
    const session = new Nfs4Session(await populated());
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
