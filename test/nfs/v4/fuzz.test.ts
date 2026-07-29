/**
 * COMPOUND fuzzing.
 *
 * `../v3/fuzz.test.ts` fuzzes a protocol whose unit is one procedure call;
 * NFSv4.1's unit is a COMPOUND, and that is what makes this a different test
 * rather than the same one with new constants. A v4 request is a *list* of
 * operations sharing a filehandle cursor, a saved filehandle, a session, a slot
 * and a sequence ID — so the interesting damage is structural: an operation
 * spliced in where nothing set the cursor, a SEQUENCE that is no longer first,
 * a slot that does not exist, an operation number no version ever defined. Byte
 * flips find the decoders; op splices find the dispatcher.
 *
 * Three invariants, and they are the ones that keep a mounted filesystem alive
 * when something on the wire is wrong:
 *
 * - **`handleCall` never rejects**, whatever bytes arrive. A thrown value that
 *   escapes it reaches the socket loop, and a server that dies on a malformed
 *   packet is a mount that dies with it.
 * - **Exactly one answer per record**: a reply, or a drop for want of an xid,
 *   and `requests === replies + dropped` across the whole run.
 * - **Every reply is a well-formed RPC reply**, whatever it says. A reply the
 *   client cannot decode is worse than an error status, because it desynchronizes
 *   the record stream.
 *
 * And one more that only the socket sees: a connection either answers or closes
 * *cleanly*, and the server behind it is still serving afterwards.
 *
 * The corpus is harvested from a live session rather than invented — real
 * session ID, real slot table, real filehandles, a real stateid — because a
 * seed the server refuses at the front door never reaches the code this is
 * about. Deterministic: every case comes from a seeded PRNG, so a failure
 * reproduces.
 */

import * as net from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../../src/drivers/memory.ts";
import { bitmapOf } from "../../../src/nfs/v4/attr.ts";
import { decodeReply, encodeCall, frameRecord, RecordAssembler } from "../../../src/nfs/rpc.ts";
import { createNfsServer, type NfsServer } from "../../../src/nfs/server.ts";
import {
  ACCESS4_ALL,
  CLAIM_NULL,
  FATTR4_MODE,
  FATTR4_SIZE,
  FATTR4_TYPE,
  FILE_SYNC4,
  NF4DIR,
  NF4LNK,
  NFS4_OK,
  NFS4_PROGRAM,
  NFS4_VERIFIER_SIZE,
  NFS_V4,
  NFSPROC4_COMPOUND,
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
  OP_SEQUENCE,
  OP_SETATTR,
  OP_TEST_STATEID,
  OP_VERIFY,
  OP_WRITE,
  OPEN4_NOCREATE,
  OPEN4_SHARE_ACCESS_BOTH,
  OPEN4_SHARE_DENY_NONE,
  READ_LT,
  SP4_NONE,
  WRITE_LT,
} from "../../../src/nfs/v4/constants.ts";
import { type Argop4, OP_CODECS, writeArgop4 } from "../../../src/nfs/v4/protocol.ts";
import { XdrWriter } from "../../../src/nfs/xdr.ts";
import { Rng } from "../../fuse/random.ts";
import { DEFAULT_CHANNEL, fattr, Nfs4Client, op, putfh, settableMask } from "./client.ts";

/** Rounds per fuzzing loop. */
const ITERATIONS = 500;

/** No single record may take longer than this to answer. A hang fails here first. */
const ROUND_BUDGET_MS = 5000;

const encoder = new TextEncoder();

/** The wire values a seed compound is built from, harvested from a live session. */
interface Corpus {
  sessionid: Uint8Array;
  clientid: bigint;
  slots: number;
  root: Uint8Array;
  dir: Uint8Array;
  file: Uint8Array;
  link: Uint8Array;
  stateid: { seqid: number; other: Uint8Array };
}

/** A named list of operations to damage; `sequence` says whether one leads it. */
interface Seed {
  name: string;
  sequence: boolean;
  ops: Argop4[];
}

/**
 * Every seed compound, spanning the operation surface this server answers.
 *
 * Grouped the way RFC 8881 groups them — the handshake that has no session yet,
 * the namespace, I/O, and locks — because those are the four places a COMPOUND
 * can go wrong for entirely different reasons.
 */
function seedsOf(corpus: Corpus): Seed[] {
  const { root, dir, file, link, stateid } = corpus;
  const owner = encoder.encode("fuzz-owner");
  const bogusStateid = { seqid: 7, other: new Uint8Array(12).fill(0xa5) };
  const bogusSessionid = new Uint8Array(16).fill(0x5a);
  const mask = bitmapOf([FATTR4_TYPE, FATTR4_SIZE, FATTR4_MODE]);
  const seed = (name: string, ops: Argop4[], sequence = true): Seed => ({ name, sequence, ops });

  return [
    // --- the handshake: the five operations §18.46.3 allows outside a session.
    seed(
      "EXCHANGE_ID",
      [
        op(OP_EXCHANGE_ID, {
          clientowner: {
            verifier: new Uint8Array(NFS4_VERIFIER_SIZE).fill(3),
            ownerid: encoder.encode("fuzz-client"),
          },
          flags: 0,
          stateProtect: { how: SP4_NONE },
          clientImplId: [],
        }),
      ],
      false,
    ),
    seed(
      "CREATE_SESSION",
      [
        op(OP_CREATE_SESSION, {
          clientid: corpus.clientid,
          sequence: 1,
          flags: 0,
          foreChanAttrs: DEFAULT_CHANNEL,
          backChanAttrs: DEFAULT_CHANNEL,
          cbProgram: 0x40_00_00_01,
          secParms: [],
        }),
      ],
      false,
    ),
    // A *bogus* session ID and client ID on purpose: these two destroy what they
    // name, and the fuzzing session is the one thing every later round needs.
    seed("DESTROY_SESSION", [op(OP_DESTROY_SESSION, { sessionid: bogusSessionid })], false),
    seed(
      "DESTROY_CLIENTID",
      [op(OP_DESTROY_CLIENTID, { clientid: corpus.clientid ^ 0xff_ffn })],
      false,
    ),
    seed("RECLAIM_COMPLETE", [op(OP_RECLAIM_COMPLETE, { oneFs: false })]),
    seed("SEQUENCE alone", []),

    // --- the namespace.
    seed("PUTROOTFH GETFH GETATTR", [
      op(OP_PUTROOTFH),
      op(OP_GETFH),
      op(OP_GETATTR, { attrRequest: mask }),
    ]),
    seed("PUTPUBFH", [op(OP_PUTPUBFH), op(OP_GETFH)]),
    seed("LOOKUP GETFH GETATTR", [
      putfh(dir),
      op(OP_LOOKUP, { objname: "file" }),
      op(OP_GETFH),
      op(OP_GETATTR, { attrRequest: mask }),
    ]),
    seed("LOOKUPP", [putfh(dir), op(OP_LOOKUPP), op(OP_GETFH)]),
    seed("SAVEFH RESTOREFH", [
      putfh(dir),
      op(OP_SAVEFH),
      putfh(root),
      op(OP_RESTOREFH),
      op(OP_GETFH),
    ]),
    seed("READDIR", [
      putfh(dir),
      op(OP_READDIR, {
        cookie: 0n,
        cookieverf: new Uint8Array(NFS4_VERIFIER_SIZE),
        dircount: 512,
        maxcount: 2048,
        attrRequest: mask,
      }),
    ]),
    seed("READLINK", [putfh(link), op(OP_READLINK)]),
    seed("ACCESS", [putfh(file), op(OP_ACCESS, { access: ACCESS4_ALL })]),
    seed("SETATTR", [
      putfh(file),
      op(OP_SETATTR, {
        stateid: { seqid: 0, other: new Uint8Array(12) },
        objAttributes: fattr(settableMask({ mode: 0o640 }), { mode: 0o640 }),
      }),
    ]),
    seed("VERIFY", [
      putfh(file),
      op(OP_VERIFY, { objAttributes: fattr(bitmapOf([FATTR4_SIZE]), { size: 11n }) }),
    ]),
    seed("NVERIFY", [
      putfh(file),
      op(OP_NVERIFY, { objAttributes: fattr(bitmapOf([FATTR4_SIZE]), { size: 0n }) }),
    ]),
    seed("SECINFO", [putfh(dir), op(OP_SECINFO, { name: "file" })]),
    seed("COMMIT", [putfh(file), op(OP_COMMIT, { offset: 0n, count: 0 })]),
    seed("CREATE a directory", [
      putfh(dir),
      op(OP_CREATE, {
        objtype: { type: NF4DIR },
        objname: "made",
        createattrs: fattr(settableMask({ mode: 0o755 }), { mode: 0o755 }),
      }),
      op(OP_GETFH),
    ]),
    seed("CREATE a symlink", [
      putfh(dir),
      op(OP_CREATE, {
        objtype: { type: NF4LNK, linkdata: "file" },
        objname: "made-link",
        createattrs: fattr([], {}),
      }),
    ]),
    seed("REMOVE", [putfh(dir), op(OP_REMOVE, { target: "made" })]),
    seed("RENAME", [
      putfh(dir),
      op(OP_SAVEFH),
      putfh(dir),
      op(OP_RENAME, { oldname: "made-link", newname: "moved-link" }),
    ]),
    seed("LINK", [putfh(file), op(OP_SAVEFH), putfh(dir), op(OP_LINK, { newname: "alias" })]),

    // --- I/O.
    seed("OPEN GETFH", [
      putfh(dir),
      op(OP_OPEN, {
        seqid: 0,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: OPEN4_SHARE_DENY_NONE,
        owner: { clientid: 0n, owner },
        openhow: { opentype: OPEN4_NOCREATE },
        claim: { claim: CLAIM_NULL, file: "file" },
      }),
      op(OP_GETFH),
    ]),
    seed("READ", [putfh(file), op(OP_READ, { stateid, offset: 0n, count: 64 })]),
    seed("WRITE", [
      putfh(file),
      op(OP_WRITE, {
        stateid,
        offset: 0n,
        stable: FILE_SYNC4,
        data: encoder.encode("fuzzed bytes"),
      }),
    ]),
    seed("CLOSE", [putfh(file), op(OP_CLOSE, { seqid: 0, openStateid: bogusStateid })]),
    seed("OPEN_DOWNGRADE", [
      putfh(file),
      op(OP_OPEN_DOWNGRADE, {
        openStateid: bogusStateid,
        seqid: 0,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }),
    ]),

    // --- locks.
    seed("LOCK", [
      putfh(file),
      op(OP_LOCK, {
        locktype: WRITE_LT,
        reclaim: false,
        offset: 0n,
        length: 8n,
        locker: {
          newLockOwner: true,
          openOwner: {
            openSeqid: 0,
            openStateid: stateid,
            lockSeqid: 0,
            lockOwner: { clientid: 0n, owner },
          },
        },
      }),
    ]),
    seed("LOCKT", [
      putfh(file),
      op(OP_LOCKT, {
        locktype: READ_LT,
        offset: 0n,
        length: 8n,
        owner: { clientid: 0n, owner },
      }),
    ]),
    seed("LOCKU", [
      putfh(file),
      op(OP_LOCKU, {
        locktype: WRITE_LT,
        seqid: 0,
        lockStateid: bogusStateid,
        offset: 0n,
        length: 8n,
      }),
    ]),
    seed("TEST_STATEID", [op(OP_TEST_STATEID, { stateids: [stateid, bogusStateid] })]),
    seed("FREE_STATEID", [op(OP_FREE_STATEID, { stateid: bogusStateid })]),
    seed("ILLEGAL", [op(OP_ILLEGAL)]),
  ];
}

/** Operations with no arguments, safe to splice anywhere a structural mutation wants one. */
const SPLICEABLE: readonly number[] = [
  OP_PUTROOTFH,
  OP_PUTPUBFH,
  OP_GETFH,
  OP_SAVEFH,
  OP_RESTOREFH,
  OP_LOOKUPP,
  OP_READLINK,
  OP_ILLEGAL,
];

/** Every operation number the codec table can encode, for the opnum mutations. */
const ENCODABLE = [...OP_CODECS.keys()];

/**
 * Operation numbers that reach the dispatcher through no codec at all.
 *
 * `writeArgop4` refuses an operation it has no row for — which is the codec
 * table doing its job — so the only way to send one is to write the word
 * directly. That is the whole point: an opcode the server knows but does not
 * implement (the LAYOUT family, OPENATTR, DELEGRETURN), one no version ever
 * defined, and §18.52's `OP_ILLEGAL` itself.
 */
const RAW_OPNUMS: readonly number[] = [
  0, 1, 2, 3, 39, 40, 44, 47, 50, 51, 52, 53, 57, 58, 59, 60, 10_043, 10_044, 10_045, 0xff_ff_ff_ff,
];

/** Words a length, count or discriminant is most likely to go wrong as. */
const NASTY_WORDS: readonly number[] = [
  0, 1, 2, 3, 0x7f_ff_ff_ff, 0x80_00_00_00, 0xff_ff_ff_fe, 0xff_ff_ff_ff, 0x00_01_00_00,
];

/** Splice, drop, duplicate and reorder — the mutations that only a *list* has. */
function mutateOps(rng: Rng, ops: readonly Argop4[]): Argop4[] {
  const out = [...ops];
  const edits = rng.range(1, 3);
  for (let edit = 0; edit < edits; edit++) {
    switch (rng.int(6)) {
      case 0: {
        // Splice in an argument-less operation, where nothing set the cursor for it.
        out.splice(rng.int(out.length + 1), 0, op(rng.pick(SPLICEABLE)));
        break;
      }
      case 1: {
        if (out.length > 0) {
          out.splice(rng.int(out.length), 1);
        }
        break;
      }
      case 2: {
        if (out.length > 0) {
          const index = rng.int(out.length);
          out.splice(index, 0, out[index]!);
        }
        break;
      }
      case 3: {
        if (out.length > 1) {
          const left = rng.int(out.length);
          const right = rng.int(out.length);
          [out[left], out[right]] = [out[right]!, out[left]!];
        }
        break;
      }
      case 4: {
        // Somebody else's arguments under this operation number — the
        // discriminant and the body disagreeing, which is what a confused
        // client sends. Only between two operations that take *no* arguments,
        // because `writeArgop4` refuses a mismatch and refusing is its job; the
        // interesting mismatch is made on the encoded bytes instead
        // ({@link swapOpnum}), where the server is the one that has to cope.
        if (out.length > 0) {
          const index = rng.int(out.length);
          if (out[index]!.args === undefined) {
            out[index] = op(rng.pick(SPLICEABLE));
          }
        }
        break;
      }
      default: {
        out.length = rng.int(out.length + 1);
        break;
      }
    }
  }
  return out;
}

/** Flip bytes, rewrite words, truncate, extend — the mutations any record has. */
function mutateBytes(rng: Rng, bytes: Uint8Array): Uint8Array {
  switch (rng.int(4)) {
    case 0: {
      const out = bytes.slice();
      const edits = rng.range(1, 4);
      for (let edit = 0; edit < edits && out.length > 0; edit++) {
        out[rng.int(out.length)] = rng.u32() & 0xff;
      }
      return out;
    }
    case 1: {
      // A whole word, aligned: a length, a count or a discriminant, which is
      // where a decoder either bounds-checks or allocates the heap away.
      const out = bytes.slice();
      const words = Math.floor(out.length / 4);
      if (words > 0) {
        new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(
          rng.int(words) * 4,
          rng.pick(NASTY_WORDS),
          false,
        );
      }
      return out;
    }
    case 2: {
      return bytes.slice(0, rng.int(bytes.length + 1));
    }
    default: {
      const extra = rng.bytes(rng.range(1, 24));
      const out = new Uint8Array(bytes.length + extra.length);
      out.set(bytes);
      out.set(extra, bytes.length);
      return out;
    }
  }
}

/** Wrap COMPOUND arguments in an RPC call record. */
function callRecord(xid: number, args: Uint8Array): Uint8Array {
  return encodeCall({
    xid,
    program: NFS4_PROGRAM,
    version: NFS_V4,
    procedure: NFSPROC4_COMPOUND,
    args,
  });
}

/** What a reply says about the SEQUENCE that led it, if it led one. */
interface ReplyShape {
  /** `COMPOUND4res.status`. */
  status: number;
  /** Whether the first result is a SEQUENCE the server accepted. */
  sequenced: boolean;
}

/**
 * Decode just enough of a reply to keep the slot table in step.
 *
 * Deliberately not `readCompoundRes`: it resolves every result through the
 * codec table and throws for an operation with no row — and a status-only
 * result for exactly such an operation is what a `NFS4ERR_NOTSUPP` answer is.
 * The head of a `COMPOUND4res` is fixed, and the head is all this needs.
 */
function shapeOf(reply: Uint8Array): ReplyShape | undefined {
  const { reply: header, results } = decodeReply(reply);
  if (header.replyStat !== 0 || header.acceptStat !== 0) {
    return undefined;
  }
  const status = results.u32("COMPOUND4res.status");
  results.string(undefined, "COMPOUND4res.tag");
  const count = results.u32("COMPOUND4res.resarray count");
  if (count === 0) {
    return { status, sequenced: false };
  }
  const first = results.u32("nfs_resop4.resop");
  const firstStatus = results.u32("nfs_resop4.status");
  return { status, sequenced: first === OP_SEQUENCE && firstStatus === NFS4_OK };
}

describe("the NFSv4.1 session", () => {
  let server: NfsServer;
  let client: Nfs4Client;
  let corpus: Corpus;
  let seeds: Seed[];

  beforeAll(async () => {
    const driver = createMemoryDriver();
    await driver.mkdir("/dir");
    const handle = await driver.open("/dir/file", "w");
    await handle.write(encoder.encode("fuzzed data"), 0, 11, 0);
    await handle.close();
    await driver.symlink("file", "/dir/link");

    server = createNfsServer(driver);
    await server.listen();
    client = await Nfs4Client.open({ port: server.port, channel: { maxrequests: 16 } });
    const root = await client.rootFh();
    const dir = await client.lookup(root, "dir");
    const file = await client.lookup(dir, "file");
    const link = await client.lookup(dir, "link");
    const open = await client.openAt(dir, "file", { access: OPEN4_SHARE_ACCESS_BOTH });
    corpus = {
      sessionid: client.session.sessionid,
      clientid: client.session.clientid,
      slots: client.session.foreChanAttrs.maxrequests,
      root,
      dir,
      file,
      link,
      stateid: open.stateid,
    };
    seeds = seedsOf(corpus);
  });

  afterAll(async () => {
    client.close();
    await server.close();
  });

  /**
   * Send `record` and hold it to the three invariants.
   *
   * Everything below funnels through here, so "never rejects", "one answer" and
   * "the answer decodes" are checked once for every byte string this file
   * invents.
   */
  async function answer(record: Uint8Array): Promise<{ answered: boolean; shape?: ReplyShape }> {
    const started = Date.now();
    let reply: Uint8Array | null;
    try {
      reply = await server.session.handleCall(record, { peer: "127.0.0.1" });
    } catch (error) {
      throw new Error(
        `handleCall rejected with ${(error as Error)?.constructor?.name ?? typeof error}: ${
          (error as Error)?.message
        }`,
        { cause: error },
      );
    }
    expect(Date.now() - started).toBeLessThan(ROUND_BUDGET_MS);
    if (reply === null) {
      return { answered: false };
    }
    // A reply nobody can decode desynchronizes the stream, so this is as
    // load-bearing as the status inside it. An RPC-level refusal —
    // `GARBAGE_ARGS` for a record the COMPOUND decoder could not read — is a
    // perfectly good answer with no `COMPOUND4res` behind it, which is what the
    // absent shape means.
    return { answered: true, shape: shapeOf(reply) };
  }

  /**
   * Build one fuzzed record, in whichever of the four shapes `rng` picks.
   *
   * `seqidFor` hands out the next sequence ID for a slot; a request the server
   * accepted is what advances it, which is exactly the client's own rule.
   */
  function build(
    rng: Rng,
    slot: number,
    seqid: number,
  ): { record: Uint8Array; sequenced: boolean } {
    const seed = rng.pick(seeds);
    const sequence: Argop4 = op(OP_SEQUENCE, {
      sessionid: corpus.sessionid,
      sequenceid: seqid,
      slotid: slot,
      highestSlotid: corpus.slots - 1,
      cachethis: rng.bool(0.25),
    });
    const ops = rng.bool(0.7) ? mutateOps(rng, seed.ops) : [...seed.ops];
    const argarray = seed.sequence ? [sequence, ...ops] : ops;

    // The argarray is written a row at a time rather than through
    // `writeCompoundArgs`, for two mutations that need the layout: a count word
    // that disagrees with what follows it, and an operation number rewritten
    // over a body of the wrong shape.
    const writer = new XdrWriter(1024);
    writer.string(`fuzz-${seed.name}`);
    // Minor version 1 is the only one this server serves; the others are the
    // refusal §16.2.3 owes a 4.0 client, and they must not be a crash.
    writer.u32(rng.bool(0.85) ? 1 : rng.pick([0, 2, 0xff_ff_ff_ff]));
    const raw = rng.bool(0.15) ? rng.range(1, 3) : 0;
    const declared = argarray.length + raw;
    writer.u32(rng.bool(0.9) ? declared : rng.pick(NASTY_WORDS));
    const opnumAt: number[] = [];
    for (const argop of argarray) {
      opnumAt.push(writer.length);
      writeArgop4(writer, argop);
    }
    // Operation numbers nothing can encode, written straight into the argarray:
    // the only way to reach an opcode with no codec row (the LAYOUT family,
    // OPENATTR, DELEGRETURN) or one no version ever defined.
    for (let index = 0; index < raw; index++) {
      writer.u32(rng.pick(RAW_OPNUMS));
    }
    const args = writer.bytes();
    if (opnumAt.length > 0 && rng.bool(0.2)) {
      // The discriminant perturbation: this operation's body, that operation's
      // number. Made here rather than in `mutateOps` because `writeArgop4`
      // refuses to encode the mismatch, and refusing is exactly its job.
      new DataView(args.buffer, args.byteOffset, args.byteLength).setUint32(
        rng.pick(opnumAt),
        rng.bool() ? rng.pick(ENCODABLE) : rng.pick(RAW_OPNUMS),
        false,
      );
    }

    const record = callRecord(rng.u32() || 1, args);
    return {
      record: rng.bool(0.5) ? mutateBytes(rng, record) : record,
      sequenced: seed.sequence,
    };
  }

  it(
    "answers every mutated compound exactly once, and never rejects",
    { timeout: 120_000 },
    async () => {
      const rng = new Rng(0x4f_53_11);
      const before = { ...server.session.stats };
      const next = Array.from({ length: corpus.slots }, () => 1);
      let executed = 0;
      let replied = 0;

      for (let round = 0; round < ITERATIONS; round++) {
        const slot = rng.int(corpus.slots);
        const { record, sequenced } = build(rng, slot, next[slot]!);
        const { answered, shape } = await answer(record);
        if (answered) {
          replied++;
        }
        if (sequenced && shape?.sequenced === true) {
          // The server took it, so its slot advanced and ours must too.
          next[slot]! += 1;
          executed++;
        }
      }

      expect(replied).toBeGreaterThan(0);
      // The fuzzer is reaching *past* the session checks and into the operations
      // for a good share of the rounds, which is what makes the rest of it mean
      // anything. Without this the suite would pass on a server that refused
      // every record at the door.
      expect(executed).toBeGreaterThan(ITERATIONS / 8);
      const after = server.session.stats;
      expect(after.requests - before.requests).toBe(ITERATIONS);
      expect(after.replies - before.replies + (after.dropped - before.dropped)).toBe(ITERATIONS);
    },
  );

  it(
    "answers random bytes addressed to the v4 program the same way",
    { timeout: 120_000 },
    async () => {
      const rng = new Rng(0x4f_53_12);
      const before = { ...server.session.stats };
      let replied = 0;
      for (let round = 0; round < ITERATIONS; round++) {
        // Half of them are routed to v4 by a real RPC header, so the garbage
        // lands inside the COMPOUND decoder rather than in front of it.
        const record = rng.bool()
          ? callRecord(rng.u32() || 1, rng.bytes(rng.int(160)))
          : rng.bytes(rng.int(200));
        if ((await answer(record)).answered) {
          replied++;
        }
      }
      expect(replied).toBeGreaterThan(0);
      const after = server.session.stats;
      expect(after.requests - before.requests).toBe(ITERATIONS);
      expect(after.replies - before.replies + (after.dropped - before.dropped)).toBe(ITERATIONS);
    },
  );
});

describe("the NFSv4.1 server, over a socket", () => {
  /**
   * The same records, through the transport.
   *
   * What only this can see: the record marking in front of `handleCall`, the
   * per-connection write ordering behind it, and the one legitimate way a
   * server may answer nothing — closing the connection, which `server.ts` does
   * for a record length it cannot believe because a record-marked stream cannot
   * be resynchronized. Either is fine; a wedged connection and a dead server
   * are not.
   */
  it(
    "either answers or closes cleanly, and is still serving afterwards",
    { timeout: 120_000 },
    async () => {
      const driver = createMemoryDriver();
      const seeded = await driver.open("/f", "w");
      await seeded.write(encoder.encode("x"), 0, 1, 0);
      await seeded.close();
      const server = createNfsServer(driver);
      await server.listen();
      const rng = new Rng(0x4f_53_13);
      const replies: Uint8Array[] = [];
      let closes = 0;

      try {
        for (let round = 0; round < 120; round++) {
          const assembler = new RecordAssembler();
          const socket = net.connect({ port: server.port, host: "127.0.0.1" });
          const done = new Promise<void>((resolve, reject) => {
            socket.once("connect", resolve);
            socket.once("error", reject);
          });
          await done;
          socket.on("data", (chunk: Buffer) => {
            for (const record of assembler.push(chunk)) {
              replies.push(record);
            }
          });

          // A framed record, a deliberately over-long fragment header, or bytes
          // that are not a record at all.
          const payload = rng.bool()
            ? frameRecord(callRecord(rng.u32() || 1, rng.bytes(rng.int(120))))
            : rng.bytes(rng.range(1, 64));
          socket.write(payload);

          // A connection the server kept is one that answered (or is thinking
          // about it); a connection it dropped is the other legal outcome. The
          // wait is short because neither takes long, and nothing below depends
          // on which of the two happened — only that it was one of them.
          const closed = new Promise<boolean>((resolve) => {
            const timer = setTimeout(() => resolve(false), 25);
            socket.once("close", () => {
              clearTimeout(timer);
              resolve(true);
            });
          });
          if (await closed) {
            closes++;
          }
          socket.destroy();
        }

        // Whatever came back is a well-formed RPC reply, whatever it says.
        for (const reply of replies) {
          expect(() => decodeReply(reply)).not.toThrow();
        }
        expect(replies.length + closes).toBeGreaterThan(0);

        // And the server survived all of it: a fresh client can still establish
        // a session and read a file through it.
        const client = await Nfs4Client.open({ port: server.port });
        try {
          const root = await client.rootFh();
          const walked = await client.walk("/f", bitmapOf([FATTR4_TYPE, FATTR4_SIZE]));
          expect(walked.attrs.size).toBe(1n);
          expect(root.byteLength).toBeGreaterThan(0);
        } finally {
          client.close();
        }
      } finally {
        await server.close();
      }
    },
  );
});
