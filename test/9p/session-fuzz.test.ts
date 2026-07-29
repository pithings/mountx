/**
 * Session fuzzing.
 *
 * The codec fuzz in `fuzz.test.ts` proves only `P9Error` escapes a decoder.
 * This proves the thing that actually keeps a mount alive: whatever bytes
 * arrive, **`handleCall` never rejects, every frame is accounted for by exactly
 * one reply or one drop, and the session keeps serving afterwards**.
 *
 * 9P makes the accounting sharper than the other two transports. There is no
 * "no reply expected" message — every `T` has an `R`, `Tflush` included — so
 * the ledger is total: `requests === replies + dropped`, always, with `dropped`
 * reserved for a frame too damaged to carry a tag worth answering. A missing
 * reply is a client blocked forever on a tag the server has forgotten; a second
 * reply for one tag is worse, because the client will have recycled it and will
 * hand the answer to a different request.
 *
 * Four hostilities, in the order they get harder to survive:
 *
 * 1. bytes that are not messages at all;
 * 2. well-framed messages of every type with garbage bodies;
 * 3. frames whose `size` field lies about their length — the one 9P-specific
 *    disaster, since `size[4]` is the *only* framing a 9P stream has;
 * 4. well-formed requests with hostile arguments, fired concurrently and
 *    interleaved with `Tflush` and the re-version that clunks everything.
 *
 * Underneath all four: a counting driver, so a handle the session opened and
 * did not close shows up as a number rather than as a slow leak nobody sees.
 *
 * Deterministic: every case comes from a seeded PRNG, so a failure reproduces.
 */

import { describe, expect, it } from "vitest";
import {
  MESSAGE_NAMES,
  P9_DOTL_AT_REMOVEDIR,
  P9_GETATTR_ALL,
  P9_HDRSZ,
  P9_IOHDRSZ,
  P9_MAXWELEM,
  P9_NOFID,
  P9_NOTAG,
  P9_READDIRHDRSZ,
  P9_RLERROR,
  P9_SETATTR_ATIME,
  P9_SETATTR_ATIME_SET,
  P9_SETATTR_CTIME,
  P9_SETATTR_GID,
  P9_SETATTR_MODE,
  P9_SETATTR_MTIME,
  P9_SETATTR_MTIME_SET,
  P9_SETATTR_SIZE,
  P9_SETATTR_UID,
  P9_TATTACH,
  P9_TCLUNK,
  P9_TFLUSH,
  P9_TFSYNC,
  P9_TGETATTR,
  P9_TGETLOCK,
  P9_TLCREATE,
  P9_TLINK,
  P9_TLOCK,
  P9_TLOPEN,
  P9_TMKDIR,
  P9_TMKNOD,
  P9_TREAD,
  P9_TREADDIR,
  P9_TREADLINK,
  P9_TREMOVE,
  P9_TRENAME,
  P9_TRENAMEAT,
  P9_TSETATTR,
  P9_TSTATFS,
  P9_TSYMLINK,
  P9_TUNLINKAT,
  P9_TVERSION,
  P9_TWALK,
  P9_TWRITE,
  P9_TXATTRCREATE,
  P9_TXATTRWALK,
  P9_VERSION_DOTL,
  messageName,
} from "../../src/9p/constants.ts";
import {
  encodeMessage,
  readHeader,
  writeFidRequest,
  writeTattach,
  writeTflush,
  writeTfsync,
  writeTgetattr,
  writeTgetlock,
  writeTlcreate,
  writeTlink,
  writeTlock,
  writeTlopen,
  writeTmkdir,
  writeTmknod,
  writeTread,
  writeTreaddir,
  writeTrename,
  writeTrenameat,
  writeTsetattr,
  writeTsymlink,
  writeTunlinkat,
  writeTversion,
  writeTwalk,
  writeTwrite,
  writeTxattrcreate,
  writeTxattrwalk,
} from "../../src/9p/protocol.ts";
import { P9Session } from "../../src/9p/session.ts";
import { P9Reader, type P9Writer } from "../../src/9p/wire.ts";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import type { FileHandleLike, FsDriver } from "../../src/types.ts";
import { Rng } from "../fuse/random.ts";
import { P9Client } from "./client.ts";

const ITERATIONS = 1200;

/** The `msize` every session here negotiates: small enough that clamping shows. */
const MSIZE = 8192;

/** Every message type the protocol names, including the ones this server refuses. */
const ALL_TYPES = Object.keys(MESSAGE_NAMES).map(Number);

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

/**
 * A memory driver that counts the handles it hands out.
 *
 * The leak this is here for is invisible from the wire: a `Tlopen` that stores
 * its handle where nothing can reach it answers `Rlopen` exactly as a healthy
 * one does, and the descriptor stays open until the process ends. Counting is
 * the only way to see it, and `opens === closes` after a `destroy()` is the
 * whole assertion.
 *
 * A second `close()` on one handle counts once: the session is entitled to be
 * defensive, and what is being counted is handles left open, not calls made.
 */
function counting(): {
  driver: FsDriver;
  /** Handles opened and not yet closed. Zero after a clean teardown. */
  live: () => number;
  opened: () => number;
} {
  const memory = createMemoryDriver();
  let opens = 0;
  let closes = 0;
  return {
    driver: {
      ...memory,
      async open(path, flags, mode): Promise<FileHandleLike> {
        const handle = await memory.open!(path, flags, mode);
        opens++;
        let closed = false;
        return {
          read: (buffer, offset, length, position) => handle.read(buffer, offset, length, position),
          write: (buffer, offset, length, position) =>
            handle.write(buffer, offset, length, position),
          stat: () => handle.stat(),
          truncate: (length) => handle.truncate(length),
          async sync(): Promise<void> {
            await handle.sync?.();
          },
          async datasync(): Promise<void> {
            await handle.datasync?.();
          },
          async close(): Promise<void> {
            if (!closed) {
              closed = true;
              closes++;
            }
            await handle.close();
          },
        };
      },
    },
    live: () => opens - closes,
    opened: () => opens,
  };
}

interface Harness {
  session: P9Session;
  client: P9Client;
  handles: ReturnType<typeof counting>;
}

/** A session over a counting driver, versioned, attached, and populated. */
async function served(options: { populate?: boolean } = {}): Promise<Harness> {
  const handles = counting();
  const session = new P9Session(handles.driver, { msize: MSIZE });
  const client = P9Client.overSession(session);
  client.msize = MSIZE;
  await client.version();
  await client.attach(0);
  if (options.populate !== false) {
    // A small tree, so the storms below have live fids to hit as well as dead
    // ones: a fuzzer that only ever names fid 4000 tests `EBADF` and nothing.
    await client.mkdir(0, "dir");
    const file = await client.walk(0, 1, []);
    expect(file).toEqual([]);
    await client.lcreate(1, "file", { flags: 0o2, mode: 0o644 });
    await client.write(1, 0n, "0123456789");
    await client.clunk(1);
    await client.walk(0, 2, ["dir"]);
    await client.walk(0, 3, ["file"]);
    await client.lopen(3, 0);
  }
  return { session, client, handles };
}

/** The ledger, which is total: every frame is one reply or one drop. */
function accounted(session: P9Session): void {
  expect(session.stats.requests).toBe(session.stats.replies + session.stats.dropped);
  expect(session.inflight).toBe(0);
}

/** Every message name, so a failure says which one. */
function label(bytes: Uint8Array): string {
  if (bytes.byteLength < P9_HDRSZ) {
    return `${bytes.byteLength} bytes`;
  }
  return `${messageName(bytes[4]!)} (${bytes.byteLength} bytes)`;
}

/**
 * Feed one frame in and assert the contract:
 *
 * - the promise settles, and never rejects;
 * - a reply, if any, is a well-formed frame whose `size` is its own length,
 *   addressed to the tag that was sent;
 * - the reply is either this message's own `R` — which is always `type + 1`,
 *   the numbering 9P has kept since 9P2000 — or an `Rlerror`. Nothing else is
 *   an answer to the question that was asked.
 */
async function feed(session: P9Session, bytes: Uint8Array): Promise<Uint8Array | null> {
  let reply: Uint8Array | null;
  try {
    reply = await session.handleCall(bytes);
  } catch (error) {
    throw new Error(`handleCall rejected for ${label(bytes)}: ${String(error)}`, { cause: error });
  }
  if (reply === null) {
    return null;
  }
  const header = readHeader(new P9Reader(reply));
  expect(header.size).toBe(reply.byteLength);
  if (bytes.byteLength >= P9_HDRSZ) {
    const request = readHeader(new P9Reader(bytes));
    if (request.size === bytes.byteLength) {
      expect(header.tag).toBe(request.tag);
      expect([P9_RLERROR, request.type + 1]).toContain(header.type);
    }
  }
  return reply;
}

/** The session still works after being hosed. */
async function stillAlive(harness: Harness): Promise<void> {
  const { client } = harness;
  // A fresh version exchange is the one thing that always works: it resets
  // whatever the fuzzer left behind, which is what the protocol says it does.
  await client.version(MSIZE);
  await client.attach(40);
  const qid = await client.mkdir(40, `survivor-${harness.session.stats.requests}`);
  expect(qid.path).toBeGreaterThan(0n);
  await client.clunk(40);
}

// ---------------------------------------------------------------------------
// request generators
// ---------------------------------------------------------------------------

/** A fid, biased towards the ones the harness made live. */
function someFid(rng: Rng): number {
  switch (rng.int(8)) {
    case 0: {
      return P9_NOFID;
    }
    case 1: {
      return rng.u32();
    }
    default: {
      return rng.int(6);
    }
  }
}

/** A name, biased towards the ones that mean something to a filesystem. */
function someName(rng: Rng): string {
  switch (rng.int(10)) {
    case 0: {
      return "";
    }
    case 1: {
      return ".";
    }
    case 2: {
      return "..";
    }
    case 3: {
      return "a/b";
    }
    case 4: {
      return "x".repeat(rng.range(250, 300));
    }
    case 5: {
      return rng.pick(["dir", "file"]);
    }
    default: {
      return rng.name(12);
    }
  }
}

/** An offset, biased towards the edges a 64-bit field has and a `number` has not. */
function someOffset(rng: Rng): bigint {
  return rng.bool(0.5) ? BigInt(rng.int(16_384)) : rng.u64();
}

interface Generated {
  type: number;
  write: (writer: P9Writer) => void;
  capacity?: number;
}

/**
 * One valid encoding per message, with hostile arguments.
 *
 * Every one of these decodes cleanly — that is the point. The codec fuzz
 * already covers bodies that do not, and what is left is the harder half: a
 * request the session must *interpret*, naming a fid that may not exist, at an
 * offset no `number` can hold, with a name no filesystem will take.
 */
const OPERATIONS: readonly ((rng: Rng) => Generated)[] = [
  (rng) => ({
    type: P9_TATTACH,
    write: (w) => {
      writeTattach(w, {
        fid: someFid(rng),
        afid: rng.bool(0.8) ? P9_NOFID : someFid(rng),
        uname: rng.name(8),
        aname: rng.pick(["", "/", "/dir", "/file", "../..", someName(rng)]),
        nUname: rng.bool(0.5) ? 0xff_ff_ff_ff : rng.u32(),
      });
    },
  }),
  (rng) => ({
    type: P9_TWALK,
    write: (w) => {
      const wnames: string[] = [];
      for (let index = rng.int(P9_MAXWELEM + 1); index > 0; index--) {
        wnames.push(someName(rng));
      }
      writeTwalk(w, { fid: someFid(rng), newfid: someFid(rng), wnames });
    },
    capacity: 4096,
  }),
  (rng) => ({ type: P9_TCLUNK, write: (w) => writeFidRequest(w, { fid: someFid(rng) }) }),
  (rng) => ({ type: P9_TSTATFS, write: (w) => writeFidRequest(w, { fid: someFid(rng) }) }),
  (rng) => ({ type: P9_TREADLINK, write: (w) => writeFidRequest(w, { fid: someFid(rng) }) }),
  (rng) => ({ type: P9_TREMOVE, write: (w) => writeFidRequest(w, { fid: someFid(rng) }) }),
  (rng) => ({
    type: P9_TGETATTR,
    write: (w) => {
      writeTgetattr(w, {
        fid: someFid(rng),
        requestMask: rng.bool(0.5) ? P9_GETATTR_ALL : rng.u64(),
      });
    },
  }),
  (rng) => ({
    type: P9_TSETATTR,
    write: (w) => {
      const bits = [
        P9_SETATTR_MODE,
        P9_SETATTR_UID,
        P9_SETATTR_GID,
        P9_SETATTR_SIZE,
        P9_SETATTR_ATIME,
        P9_SETATTR_ATIME_SET,
        P9_SETATTR_MTIME,
        P9_SETATTR_MTIME_SET,
        P9_SETATTR_CTIME,
      ];
      let valid = 0;
      for (const bit of bits) {
        if (rng.bool(0.3)) {
          valid |= bit;
        }
      }
      writeTsetattr(w, {
        fid: someFid(rng),
        valid,
        mode: rng.u32(),
        uid: rng.u32(),
        gid: rng.u32(),
        size: someOffset(rng),
        atime: { sec: someOffset(rng), nsec: someOffset(rng) },
        mtime: { sec: someOffset(rng), nsec: someOffset(rng) },
      });
    },
  }),
  (rng) => ({
    type: P9_TLOPEN,
    write: (w) =>
      writeTlopen(w, { fid: someFid(rng), flags: rng.bool(0.5) ? rng.int(4) : rng.u32() }),
  }),
  (rng) => ({
    type: P9_TLCREATE,
    write: (w) => {
      writeTlcreate(w, {
        fid: someFid(rng),
        name: someName(rng),
        flags: rng.bool(0.5) ? rng.int(4) : rng.u32(),
        mode: rng.u32(),
        gid: rng.u32(),
      });
    },
    capacity: 512,
  }),
  (rng) => ({
    type: P9_TREAD,
    write: (w) => {
      writeTread(w, {
        fid: someFid(rng),
        offset: someOffset(rng),
        count: rng.bool(0.5) ? rng.int(64) : rng.u32(),
      });
    },
  }),
  (rng) => ({
    type: P9_TWRITE,
    write: (w) => {
      writeTwrite(w, {
        fid: someFid(rng),
        offset: someOffset(rng),
        data: rng.bytes(rng.int(64)),
      });
    },
    capacity: 256,
  }),
  (rng) => ({
    type: P9_TREADDIR,
    write: (w) => {
      writeTreaddir(w, {
        fid: someFid(rng),
        offset: someOffset(rng),
        count: rng.bool(0.5) ? rng.int(512) : rng.u32(),
      });
    },
  }),
  (rng) => ({
    type: P9_TFSYNC,
    write: (w) => writeTfsync(w, { fid: someFid(rng), datasync: rng.int(2) }),
  }),
  (rng) => ({
    type: P9_TMKDIR,
    write: (w) => {
      writeTmkdir(w, {
        dfid: someFid(rng),
        name: someName(rng),
        mode: rng.u32(),
        gid: rng.u32(),
      });
    },
    capacity: 512,
  }),
  (rng) => ({
    type: P9_TSYMLINK,
    write: (w) => {
      writeTsymlink(w, {
        dfid: someFid(rng),
        name: someName(rng),
        symtgt: someName(rng),
        gid: rng.u32(),
      });
    },
    capacity: 1024,
  }),
  (rng) => ({
    type: P9_TMKNOD,
    write: (w) => {
      writeTmknod(w, {
        dfid: someFid(rng),
        name: someName(rng),
        mode: rng.u32(),
        major: rng.u32(),
        minor: rng.u32(),
        gid: rng.u32(),
      });
    },
    capacity: 512,
  }),
  (rng) => ({
    type: P9_TLINK,
    write: (w) => writeTlink(w, { dfid: someFid(rng), fid: someFid(rng), name: someName(rng) }),
    capacity: 512,
  }),
  (rng) => ({
    type: P9_TRENAME,
    write: (w) => writeTrename(w, { fid: someFid(rng), dfid: someFid(rng), name: someName(rng) }),
    capacity: 512,
  }),
  (rng) => ({
    type: P9_TRENAMEAT,
    write: (w) => {
      writeTrenameat(w, {
        olddirfid: someFid(rng),
        oldname: someName(rng),
        newdirfid: someFid(rng),
        newname: someName(rng),
      });
    },
    capacity: 1024,
  }),
  (rng) => ({
    type: P9_TUNLINKAT,
    write: (w) => {
      writeTunlinkat(w, {
        dirfid: someFid(rng),
        name: someName(rng),
        flags: rng.bool(0.5) ? P9_DOTL_AT_REMOVEDIR : rng.u32(),
      });
    },
    capacity: 512,
  }),
  (rng) => ({
    type: P9_TXATTRWALK,
    write: (w) =>
      writeTxattrwalk(w, { fid: someFid(rng), newfid: someFid(rng), name: someName(rng) }),
    capacity: 512,
  }),
  (rng) => ({
    type: P9_TXATTRCREATE,
    write: (w) => {
      writeTxattrcreate(w, {
        fid: someFid(rng),
        name: someName(rng),
        attrSize: someOffset(rng),
        flags: rng.u32(),
      });
    },
    capacity: 512,
  }),
  (rng) => ({
    type: P9_TLOCK,
    write: (w) => {
      writeTlock(w, {
        fid: someFid(rng),
        type: rng.int(4),
        flags: rng.u32(),
        start: someOffset(rng),
        length: someOffset(rng),
        procId: rng.u32(),
        clientId: rng.name(8),
      });
    },
    capacity: 256,
  }),
  (rng) => ({
    type: P9_TGETLOCK,
    write: (w) => {
      writeTgetlock(w, {
        fid: someFid(rng),
        type: rng.int(4),
        start: someOffset(rng),
        length: someOffset(rng),
        procId: rng.u32(),
        clientId: rng.name(8),
      });
    },
    capacity: 256,
  }),
];

/**
 * `Tversion`, kept out of {@link OPERATIONS} rather than filtered back out of
 * it: every `Tversion` carries `P9_NOTAG`, so two in one wave are two requests
 * sharing a tag — the duplicate the session is *right* to refuse with `EPROTO`,
 * and a self-inflicted one that would say nothing about concurrency. The
 * sequential cases draw from both pools; the concurrent ones inject exactly one
 * version exchange per wave, deliberately.
 */
const VERSIONS: (rng: Rng) => Generated = (rng) => ({
  type: P9_TVERSION,
  write: (w) => {
    writeTversion(w, {
      msize: rng.bool(0.5) ? MSIZE : rng.u32(),
      version: rng.pick([P9_VERSION_DOTL, "9P2000", "9P2000.u", "", "unknown"]),
    });
  },
});

/** One generated request, framed under `tag`. */
function request(rng: Rng, tag: number, options: { versions?: boolean } = {}): Uint8Array {
  const pool = options.versions === false ? OPERATIONS : [VERSIONS, ...OPERATIONS];
  const generated = rng.pick(pool)(rng);
  const chosen = generated.type === P9_TVERSION ? P9_NOTAG : tag;
  return encodeMessage(generated.type, chosen, generated.write, generated.capacity);
}

// ---------------------------------------------------------------------------
// bytes that are not messages
// ---------------------------------------------------------------------------

describe("random bytes", () => {
  it("survives uniformly random frames", async () => {
    const harness = await served();
    const rng = new Rng(0x9e_55_10_01);
    for (let round = 0; round < ITERATIONS; round++) {
      await feed(harness.session, rng.bytes(rng.int(64)));
    }
    expect(harness.session.assertions).toEqual([]);
    accounted(harness.session);
    await stillAlive(harness);
  });

  it("survives plausible headers with garbage bodies", async () => {
    const harness = await served();
    const rng = new Rng(0x9e_55_10_02);
    for (let round = 0; round < ITERATIONS; round++) {
      const body = rng.bytes(rng.int(48));
      const frame = new Uint8Array(P9_HDRSZ + body.byteLength);
      const view = new DataView(frame.buffer);
      view.setUint32(0, frame.byteLength, true);
      frame[4] = rng.pick(ALL_TYPES);
      view.setUint16(5, rng.bool(0.2) ? P9_NOTAG : rng.int(64), true);
      frame.set(body, P9_HDRSZ);
      const reply = await feed(harness.session, frame);
      // A well-framed message always has a tag to answer, so it is always
      // answered: `null` is reserved for a frame that cannot carry one.
      expect(reply).not.toBeNull();
    }
    expect(harness.session.assertions).toEqual([]);
    accounted(harness.session);
    await stillAlive(harness);
  });

  /**
   * The 9P-specific disaster.
   *
   * `size[4]` is the only framing a 9P stream has, so a frame whose length
   * field disagrees with the bytes delivered means the stream is already
   * desynchronized — everything after it is being read at the wrong offset.
   * The session answers nothing at all, deliberately: a reply put on a stream
   * whose framing is wrong just moves the confusion, and the tag it would be
   * addressed to was read from bytes that are not a header.
   */
  it("drops frames whose size field lies, without answering them", async () => {
    const harness = await served();
    const rng = new Rng(0x9e_55_10_03);
    const before = harness.session.stats.replies;
    for (let round = 0; round < ITERATIONS; round++) {
      const frame = encodeMessage(P9_TGETATTR, rng.int(64), (w) =>
        writeTgetattr(w, { fid: someFid(rng), requestMask: P9_GETATTR_ALL }),
      );
      const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
      view.setUint32(0, rng.bool(0.5) ? rng.u32() : frame.byteLength + rng.range(1, 8), true);
      expect(await feed(harness.session, frame)).toBeNull();
    }
    expect(harness.session.stats.replies).toBe(before);
    expect(harness.session.stats.dropped).toBe(ITERATIONS);
    expect(harness.session.assertions).toEqual([]);
    accounted(harness.session);
    await stillAlive(harness);
  });

  it("answers a frame too short to hold a header with nothing", async () => {
    const harness = await served();
    for (let length = 0; length < P9_HDRSZ; length++) {
      expect(await feed(harness.session, new Uint8Array(length))).toBeNull();
    }
    accounted(harness.session);
  });
});

// ---------------------------------------------------------------------------
// well-formed requests, hostile arguments
// ---------------------------------------------------------------------------

describe("hostile requests", () => {
  it("answers every generated request exactly once", async () => {
    const harness = await served();
    const rng = new Rng(0x9e_55_10_04);
    for (let round = 0; round < ITERATIONS; round++) {
      const reply = await feed(harness.session, request(rng, round & 0x7f_ff));
      expect(reply).not.toBeNull();
    }
    expect(harness.session.assertions).toEqual([]);
    accounted(harness.session);
    await stillAlive(harness);
  });

  /**
   * The same requests, all in flight at once.
   *
   * Concurrency is where a path-based server goes wrong: a `Trenameat` rewrites
   * paths that other requests resolved before it and will use after it, a
   * `Tclunk` releases a fid another request is parked on, and a `Tversion`
   * takes the whole session away from both. Every one of those is reachable
   * here, and the ledger has to balance regardless.
   *
   * Tags are unique within a wave. A duplicate tag *in flight* is a protocol
   * error the session answers `EPROTO` and records an assertion for — which is
   * correct, and is tested deliberately in `session.test.ts`; letting the
   * fuzzer produce one would only make `assertions` meaningless here.
   */
  it("survives storms of concurrent requests", async () => {
    const harness = await served();
    const rng = new Rng(0x9e_55_10_05);
    let tag = 0;
    for (let wave = 0; wave < 60; wave++) {
      const frames: Uint8Array[] = [];
      for (let index = 0; index < 12; index++) {
        frames.push(request(rng, tag++ & 0x7f_ff, { versions: false }));
      }
      if (rng.bool(0.15)) {
        // The reset, mid-wave: it clunks every fid and aborts every request
        // that has not finished, which is what makes the stale-reply path run.
        frames.push(
          encodeMessage(P9_TVERSION, P9_NOTAG, (w) =>
            writeTversion(w, { msize: MSIZE, version: P9_VERSION_DOTL }),
          ),
        );
      }
      if (rng.bool(0.4)) {
        // A flush for a tag in this wave: sometimes live, sometimes long gone.
        frames.push(
          encodeMessage(P9_TFLUSH, tag++ & 0x7f_ff, (w) =>
            writeTflush(w, { oldtag: rng.bool(0.5) ? (tag - 3) & 0x7f_ff : rng.u16() }),
          ),
        );
      }
      const replies = await Promise.all(frames.map((frame) => feed(harness.session, frame)));
      for (const reply of replies) {
        expect(reply).not.toBeNull();
      }
      accounted(harness.session);
      // Re-attach whatever the last reset took away, so the next wave has live
      // fids again rather than degenerating into an `EBADF` machine.
      if (harness.session.msize === undefined) {
        await harness.client.version(MSIZE);
      }
      if (harness.session.fids.size === 0) {
        await harness.client.attach(0);
      }
    }
    expect(harness.session.assertions).toEqual([]);
    accounted(harness.session);
    await stillAlive(harness);
  });

  /**
   * Every handle the session opened is closed by the time it is torn down.
   *
   * Both halves matter. `live() === 0` after `destroy()` is the leak check; the
   * `opened()` assertion is what keeps it honest, since a storm that never
   * managed to open anything would satisfy the first trivially.
   */
  it("leaves no driver handle open after destroy", async () => {
    const harness = await served();
    const rng = new Rng(0x9e_55_10_06);
    for (let wave = 0; wave < 40; wave++) {
      const frames: Uint8Array[] = [];
      for (let index = 0; index < 8; index++) {
        frames.push(request(rng, (wave * 8 + index) & 0x7f_ff, { versions: false }));
      }
      await Promise.all(frames.map((frame) => feed(harness.session, frame)));
      if (harness.session.fids.size === 0) {
        await harness.client.attach(0);
      }
    }
    // Plus a handle the fuzzer definitely did not close, so teardown has work.
    await harness.client.walk(0, 9, ["file"]).catch(() => undefined);
    await harness.client.lopen(9, 0).catch(() => undefined);

    await harness.session.destroy();
    expect(harness.handles.opened()).toBeGreaterThan(0);
    expect(harness.handles.live()).toBe(0);
    expect(harness.session.fids.size).toBe(0);
    expect(harness.session.assertions).toEqual([]);
    accounted(harness.session);
  });

  /**
   * A fid opened twice, concurrently, leaks nothing.
   *
   * The narrow case the counting driver exists for: both requests pass the
   * "not open yet" test in their prologue, both open, and only one assignment
   * survives. The loser has to close what it opened, and `live()` is what says
   * it did.
   */
  it("closes the handle of an open that lost a race", async () => {
    const harness = await served();
    const before = harness.handles.opened();
    // The harness leaves one fid open on purpose, so the interesting number is
    // the *change*: a leak is a handle this test opened and did not close.
    const baseline = harness.handles.live();
    for (let round = 0; round < 25; round++) {
      await harness.client.walk(0, 10, ["file"]);
      const opens = [
        feed(
          harness.session,
          encodeMessage(P9_TLOPEN, 100, (w) => writeTlopen(w, { fid: 10, flags: 0 })),
        ),
        feed(
          harness.session,
          encodeMessage(P9_TLOPEN, 101, (w) => writeTlopen(w, { fid: 10, flags: 0 })),
        ),
      ];
      await Promise.all(opens);
      await harness.client.clunk(10);
    }
    expect(harness.handles.opened()).toBeGreaterThan(before);
    expect(harness.handles.live()).toBe(baseline);
    expect(harness.session.assertions).toEqual([]);
    accounted(harness.session);
  });
});

// ---------------------------------------------------------------------------
// resource bounds
// ---------------------------------------------------------------------------

describe("resource bounds", () => {
  it("does not allocate what a bogus Tread count asks for", async () => {
    const harness = await served();
    const reply = await feed(
      harness.session,
      encodeMessage(P9_TREAD, 1, (w) =>
        writeTread(w, { fid: 3, offset: 0n, count: 0xff_ff_ff_ff }),
      ),
    );
    // Clamped to what the negotiated `msize` can frame, never to what was
    // asked: a `count` of 4 GiB is a client bug, not an allocation request.
    expect(reply!.byteLength).toBeLessThanOrEqual(MSIZE);
    expect(reply!.byteLength).toBeLessThanOrEqual(MSIZE - P9_IOHDRSZ + 16);
    accounted(harness.session);
  });

  it("does not allocate what a bogus Treaddir count asks for", async () => {
    const harness = await served();
    await harness.client.walk(0, 11, ["dir"]);
    await harness.client.lopen(11, 0);
    const reply = await feed(
      harness.session,
      encodeMessage(P9_TREADDIR, 2, (w) =>
        writeTreaddir(w, { fid: 11, offset: 0n, count: 0xff_ff_ff_ff }),
      ),
    );
    expect(reply!.byteLength).toBeLessThanOrEqual(MSIZE - P9_READDIRHDRSZ + 32);
    accounted(harness.session);
  });

  it("refuses offsets a JS number cannot hold", async () => {
    const harness = await served();
    const huge = (1n << 62n) + 7n;
    expect(
      await harness.client.expectError(P9_TREAD, (w) =>
        writeTread(w, { fid: 3, offset: huge, count: 16 }),
      ),
    ).toBe(22);
    expect(
      await harness.client.expectError(P9_TWRITE, (w) =>
        writeTwrite(w, { fid: 3, offset: huge, data: new Uint8Array(4) }),
      ),
    ).toBe(22);
    accounted(harness.session);
  });
});
