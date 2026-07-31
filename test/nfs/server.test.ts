/**
 * Tier 0 for the socket in `src/nfs/server.ts`: framing is elsewhere, flow
 * control is here.
 *
 * Two properties, both invisible to every other NFS test because every other
 * one drives calls that finish immediately:
 *
 * - **Replies go out in completion order.** RPC over TCP matches a reply to its
 *   call by `xid` (NFSv4.1 additionally by `(session, slot, sequenceid)`), so a
 *   slow call must not delay a fast one issued after it. The reply chain that
 *   used to `await` each answer from inside itself collapsed every in-flight
 *   call to the latency of the slowest — two concurrent `GETATTR`s, one of them
 *   behind a 1.5 s driver, *both* finished at 1502 ms.
 * - **Nothing is unbounded.** `maxRecord` bounds one record; `maxInFlight`
 *   bounds how many are being answered at once, and a connection at the window
 *   stops reading rather than parsing a client's whole burst into replies.
 *
 * Both are driven over a real socket, because both are properties of the
 * transport rather than of a session: `handleCall` is bytes in and bytes out
 * and cannot observe either one.
 *
 * **No wall clock anywhere.** Flow control is timing-*adjacent* and these tests
 * are not: a slow driver is a driver parked on a promise this file resolves,
 * never a `setTimeout`, so "the fast reply came back first" is a fact about
 * order rather than about milliseconds. Every wait here is either a promise the
 * gate hands out ({@link gated}), a promise the reply counter hands out, or a
 * count of event-loop turns ({@link turns}) — all three of which a loaded host
 * makes slower without making them false, which a duration does not. There is
 * no `setTimeout`, no `expect.poll` and no wall-clock threshold in the file;
 * the only deadline is vitest's own per-test timeout.
 */

import { once } from "node:events";
import * as net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { createLoopback } from "../../src/harness.ts";
import { authSys, encodeCall, frameRecord, RecordAssembler } from "../../src/nfs/rpc.ts";
import {
  createNfsServer,
  DEFAULT_NFS_MAX_IN_FLIGHT,
  type NfsServer,
  type NfsServerOptions,
} from "../../src/nfs/server.ts";
import {
  NFS3_OK,
  NFS3ERR_STALE,
  NFS_PROGRAM,
  NFS_V3,
  NFSPROC3_GETATTR,
  NFSPROC3_READ,
} from "../../src/nfs/v3/constants.ts";
import { writeReadArgs } from "../../src/nfs/v3/protocol.ts";
import { XdrWriter } from "../../src/nfs/xdr.ts";
import type { FsDriver } from "../../src/types.ts";
import { check, NfsClient } from "./v3/client.ts";

const servers: NfsServer[] = [];
const clients: NfsClient[] = [];
const rawSockets: net.Socket[] = [];

afterEach(async () => {
  for (const socket of rawSockets.splice(0)) {
    socket.destroy();
  }
  for (const client of clients.splice(0)) {
    client.close();
  }
  for (const server of servers.splice(0)) {
    await server.close();
  }
});

/**
 * Yield the event loop `count` times.
 *
 * The unit an "and then nothing else happened" assertion is measured in here,
 * in place of a sleep. `setImmediate` fires in the check phase, *after* the
 * poll phase where a socket's reads and writes are serviced, so one turn is one
 * whole opportunity for the server to take a chunk off the wire, dispatch it
 * and answer it. That is a currency load cannot devalue: a busy host makes each
 * turn take longer in milliseconds, it does not make fewer things happen inside
 * one. A `setTimeout` is the opposite — its 300 ms buys less and less work as
 * the host gets busier, which is exactly how a green test becomes a flaky one.
 */
async function turns(count: number): Promise<void> {
  for (let index = 0; index < count; index++) {
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
  }
}

/** Wrap every method of a driver, keeping it a driver. */
function wrap(base: FsDriver, before: (path: unknown) => Promise<void> | undefined): FsDriver {
  return new Proxy(base, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver) as unknown;
      if (typeof value !== "function") {
        return value;
      }
      return async (...args: unknown[]) => {
        await before(args[0]);
        return (value as (...rest: unknown[]) => unknown).apply(target, args);
      };
    },
  }) as FsDriver;
}

interface Gate {
  /** The driver to serve. */
  driver: FsDriver;
  /** Calls the driver has been given since the last {@link Gate.shut}/{@link Gate.reset}. */
  seen: () => number;
  /** Of those, the ones held rather than answered. */
  parked: () => number;
  /** Resolves once `seen()` reaches `count`. The way this file waits for the server to act. */
  reaches: (count: number) => Promise<void>;
  /** Hold every matching call from here on, and zero the counters. */
  shut: () => void;
  /** Zero the counters without changing whether the gate is shut. */
  reset: () => void;
  /** Answer everything held, and everything after it. */
  open: () => void;
}

/**
 * A driver with a gate on it: open to begin with, shut on demand.
 *
 * This is what replaces a slow driver. A call that "takes a long time" is a
 * call parked on a promise nothing resolves until the test says so, which makes
 * every ordering question in this file decidable rather than probable — "the
 * fast reply arrived while the slow call was still in the driver" is checked by
 * looking at the gate, not at a clock.
 */
function gated(base: FsDriver, matches: (path: unknown) => boolean = () => true): Gate {
  let closed = false;
  let seen = 0;
  let parked = 0;
  let waiters: (() => void)[] = [];
  let marks: { need: number; resolve: () => void }[] = [];
  const driver = wrap(base, (path) => {
    seen++;
    marks = marks.filter((mark) => {
      if (seen < mark.need) {
        return true;
      }
      mark.resolve();
      return false;
    });
    if (!closed || !matches(path)) {
      return undefined;
    }
    parked++;
    return new Promise<void>((resolve) => waiters.push(resolve));
  });
  const reset = (): void => {
    seen = 0;
    parked = 0;
  };
  return {
    driver,
    seen: () => seen,
    parked: () => parked,
    reset,
    reaches: (count) =>
      seen >= count
        ? Promise.resolve()
        : new Promise<void>((resolve) => {
            marks.push({ need: count, resolve });
          }),
    shut: () => {
      closed = true;
      reset();
    },
    open: () => {
      closed = false;
      const waiting = waiters;
      waiters = [];
      for (const resolve of waiting) {
        resolve();
      }
    },
  };
}

async function serve(driver: FsDriver, options: NfsServerOptions = {}): Promise<NfsServer> {
  const server = await createNfsServer(driver, options).listen();
  servers.push(server);
  return server;
}

async function connect(server: NfsServer): Promise<NfsClient> {
  const client = await NfsClient.connect({ port: server.port });
  clients.push(client);
  return client;
}

// ---------------------------------------------------------------------------

describe("reply ordering", () => {
  it("does not make a fast call wait for a slow one on the same connection", async () => {
    // The shape this test exists for: with the reply chain awaiting each answer
    // from inside itself, the fast `GETATTR` could not be answered until the
    // slow one ahead of it had been — measured at 1502 ms for both, against a
    // driver that took 1.5 s on one path. Here the slow path is *held* instead
    // of slow, so the assertion is that the fast reply arrives while the slow
    // call is still inside the driver, with no duration involved at all.
    const base = createMemoryDriver();
    const loopback = createLoopback(base);
    await loopback.writeFile("/slow.txt", "s");
    await loopback.writeFile("/fast.txt", "f");
    const gate = gated(base, (path) => typeof path === "string" && path.includes("slow"));
    const server = await serve(gate.driver);
    const client = await connect(server);

    const root = check(await client.mnt("/"), "mnt").fh!;
    const slow = check(await client.lookup(root, "slow.txt"), "lookup").object!;
    const fast = check(await client.lookup(root, "fast.txt"), "lookup").object!;

    gate.shut();
    let slowSettled = false;
    const slowCall = client.getattr(slow);
    const settle = (): void => {
      slowSettled = true;
    };
    slowCall.then(settle, settle);

    // The slow call is inside the driver before the fast one is even sent, so
    // what follows is head-of-line blocking or nothing.
    await gate.reaches(1);
    const fastResult = await client.getattr(fast);

    expect(fastResult.status).toBe(0);
    expect(slowSettled).toBe(false);
    expect(gate.parked()).toBe(1);

    gate.open();
    expect((await slowCall).status).toBe(0);
  }, 30_000);

  it("answers a burst in completion order and loses none of it", async () => {
    // Out-of-order replies are only correct if every one still arrives and is
    // still matched to its own call. Ten held calls, then ten that can be
    // answered: all ten answers come back with all ten holds still outstanding,
    // and the held ten arrive intact afterwards.
    const base = createMemoryDriver();
    const loopback = createLoopback(base);
    const slowNames: string[] = [];
    const fastNames: string[] = [];
    for (let index = 0; index < 10; index++) {
      slowNames.push(`/slow-${index}.txt`);
      fastNames.push(`/fast-${index}.txt`);
    }
    for (const name of [...slowNames, ...fastNames]) {
      await loopback.writeFile(name, name);
    }
    const gate = gated(base, (path) => typeof path === "string" && path.includes("slow"));
    const server = await serve(gate.driver);
    const client = await connect(server);
    const root = check(await client.mnt("/"), "mnt").fh!;
    const handles = new Map<string, Uint8Array>();
    for (const name of [...slowNames, ...fastNames]) {
      handles.set(name, check(await client.lookup(root, name.slice(1)), "lookup").object!);
    }

    gate.shut();
    const settled: string[] = [];
    const slowCalls = slowNames.map((name) => {
      const call = client.getattr(handles.get(name)!);
      const settle = (): void => {
        settled.push(name);
      };
      call.then(settle, settle);
      return call;
    });

    // Every held call is in the driver before a single answerable one is sent.
    await gate.reaches(slowNames.length);
    const fastCalls = fastNames.map(async (name) => {
      const result = await client.getattr(handles.get(name)!);
      settled.push(name);
      return result;
    });
    for (const result of await Promise.all(fastCalls)) {
      expect(result.status).toBe(0);
    }

    expect(gate.parked()).toBe(slowNames.length);
    expect(new Set(settled)).toEqual(new Set(fastNames));

    gate.open();
    for (const result of await Promise.all(slowCalls)) {
      expect(result.status).toBe(0);
    }
    expect(new Set(settled).size).toBe(slowNames.length + fastNames.length);
  }, 30_000);
});

// ---------------------------------------------------------------------------

describe("the handle table bound", () => {
  it("evicts a handle the client stopped using, and says `ESTALE` about it", async () => {
    // The third bound, and the only one that is off by default: `maxRecord`
    // bounds one record and `maxInFlight` bounds the answers in flight, but the
    // handle table grows for the *life of the server*, one entry per path a
    // client has a name for, and no NFS message ever says a name is finished
    // with. What a cap costs is here rather than in `handles.test.ts`, because
    // it is a cost paid by a client rather than by the table: a handle it kept
    // stops working, and the recovery is the ordinary `ESTALE` one.
    const driver = createMemoryDriver();
    const loopback = createLoopback(driver);
    for (let index = 0; index < 8; index++) {
      await loopback.writeFile(`/f${index}.txt`, "x");
    }
    // The root plus two files, which the walk below overruns immediately.
    const server = await serve(driver, { maxHandles: 3 });
    const client = await connect(server);

    const root = check(await client.mnt("/"), "mnt").fh!;
    const kept = check(await client.lookup(root, "f0.txt"), "lookup").object!;
    expect((await client.getattr(kept)).status).toBe(NFS3_OK);

    for (let index = 1; index < 8; index++) {
      check(await client.lookup(root, `f${index}.txt`), "lookup");
    }

    // The client still holds the handle; the server does not.
    expect((await client.getattr(kept)).status).toBe(NFS3ERR_STALE);
    // And the recovery a Linux client already performs for `ESTALE` — drop the
    // dentry, look the name up again — gets it a working handle back.
    const again = check(await client.lookup(root, "f0.txt"), "lookup").object!;
    expect((await client.getattr(again)).status).toBe(NFS3_OK);
    // The root is in that three, and is never the one evicted.
    expect(server.session.handles.size).toBe(3);
    expect((await client.getattr(root)).status).toBe(NFS3_OK);
  }, 30_000);

  it("keeps every handle it ever handed out when no cap is asked for", async () => {
    const driver = createMemoryDriver();
    const loopback = createLoopback(driver);
    for (let index = 0; index < 8; index++) {
      await loopback.writeFile(`/f${index}.txt`, "x");
    }
    const server = await serve(driver);
    const client = await connect(server);

    const root = check(await client.mnt("/"), "mnt").fh!;
    const kept = check(await client.lookup(root, "f0.txt"), "lookup").object!;
    for (let index = 1; index < 8; index++) {
      check(await client.lookup(root, `f${index}.txt`), "lookup");
    }

    expect((await client.getattr(kept)).status).toBe(NFS3_OK);
    expect(server.session.handles.size).toBe(9);
  }, 30_000);
});

// ---------------------------------------------------------------------------

describe("flow control", () => {
  /** One framed `GETATTR` call. */
  function getattrCall(xid: number, fh: Uint8Array): Uint8Array {
    return frameRecord(
      encodeCall({
        xid,
        program: NFS_PROGRAM,
        version: NFS_V3,
        procedure: NFSPROC3_GETATTR,
        cred: authSys(),
        args: new XdrWriter(64).varOpaque(fh).bytes(),
      }),
    );
  }

  /** One framed `READ` call. */
  function readCall(xid: number, fh: Uint8Array, offset: bigint, count: number): Uint8Array {
    const args = new XdrWriter(64);
    writeReadArgs(args, { file: fh, offset, count });
    return frameRecord(
      encodeCall({
        xid,
        program: NFS_PROGRAM,
        version: NFS_V3,
        procedure: NFSPROC3_READ,
        cred: authSys(),
        args: args.bytes(),
      }),
    );
  }

  interface Raw {
    socket: net.Socket;
    /** Replies parsed off the wire so far. */
    replies: () => number;
    /** Resolves once `replies()` reaches `count`. */
    awaits: (count: number) => Promise<void>;
  }

  /**
   * A second connection to the same server that counts replies and never reads
   * politely on anybody's behalf — the client half of a pipelining burst.
   */
  async function rawConnect(server: NfsServer): Promise<Raw> {
    const socket = net.connect({ port: server.port, host: "127.0.0.1" });
    socket.setNoDelay(true);
    await new Promise<void>((resolve, reject) => {
      socket.once("connect", () => resolve());
      socket.once("error", reject);
    });
    rawSockets.push(socket);
    const assembler = new RecordAssembler();
    let replies = 0;
    let marks: { need: number; resolve: () => void }[] = [];
    socket.on("data", (chunk: Buffer) => {
      replies += assembler.push(chunk).length;
      marks = marks.filter((mark) => {
        if (replies < mark.need) {
          return true;
        }
        mark.resolve();
        return false;
      });
    });
    return {
      socket,
      replies: () => replies,
      awaits: (count) =>
        replies >= count
          ? Promise.resolve()
          : new Promise<void>((resolve) => {
              marks.push({ need: count, resolve });
            }),
    };
  }

  it("dispatches at most `maxInFlight` calls at once", async () => {
    const base = createMemoryDriver();
    await createLoopback(base).writeFile("/f.txt", "f");
    const gate = gated(base);
    const server = await serve(gate.driver);
    // The handle comes from this server's own table, so it is taken while the
    // gate is still open.
    const client = await connect(server);
    const root = check(await client.mnt("/"), "mnt").fh!;

    const raw = await rawConnect(server);
    const before = server.session.stats.requests;
    gate.shut();

    const asked = 400;
    const burst: Uint8Array[] = [];
    for (let index = 0; index < asked; index++) {
      burst.push(getattrCall(1000 + index, root));
    }
    raw.socket.write(Buffer.concat(burst.map((record) => Buffer.from(record))));

    // The window fills, and then nothing frees a slot — so however many event
    // loop turns pass, a sixty-fifth call cannot reach the driver.
    await gate.reaches(DEFAULT_NFS_MAX_IN_FLIGHT);
    await turns(500);
    expect(gate.parked()).toBe(DEFAULT_NFS_MAX_IN_FLIGHT);
    expect(server.session.stats.requests - before).toBe(DEFAULT_NFS_MAX_IN_FLIGHT);
    expect(raw.replies()).toBe(0);

    // And it picks up where it left off: every call is answered once the driver
    // does, none of them lost to the pause.
    gate.open();
    await raw.awaits(asked);
    expect(server.session.stats.requests - before).toBe(asked);
  }, 60_000);

  it("honours a `maxInFlight` of one", async () => {
    const base = createMemoryDriver();
    await createLoopback(base).writeFile("/f.txt", "f");
    const gate = gated(base);
    const server = await serve(gate.driver, { maxInFlight: 1 });
    const client = await connect(server);
    const root = check(await client.mnt("/"), "mnt").fh!;

    const raw = await rawConnect(server);
    const before = server.session.stats.requests;
    gate.shut();

    const asked = 50;
    const burst: Uint8Array[] = [];
    for (let index = 0; index < asked; index++) {
      burst.push(getattrCall(2000 + index, root));
    }
    raw.socket.write(Buffer.concat(burst.map((record) => Buffer.from(record))));

    await gate.reaches(1);
    await turns(500);
    expect(gate.parked()).toBe(1);
    expect(server.session.stats.requests - before).toBe(1);

    gate.open();
    await raw.awaits(asked);
  }, 60_000);

  it("stops reading its socket while it is at the window", async () => {
    // The bound is only real if it reaches the *socket*: a connection that
    // parsed a client's whole burst and merely dispatched it slowly would show
    // the same in-flight count while still holding every record. So this
    // asserts the two things that tell those cases apart — a 16 MiB write that
    // has not completed while the window is full, and records still arriving
    // off the wire once it empties.
    const base = createMemoryDriver();
    await createLoopback(base).writeFile("/f.txt", "f");
    const gate = gated(base);
    const server = await serve(gate.driver);
    const client = await connect(server);
    const root = check(await client.mnt("/"), "mnt").fh!;

    const raw = await rawConnect(server);
    gate.shut();

    // Comfortably more than the two kernel buffers plus everything Node holds,
    // so a server that keeps reading finishes it and a server that stops cannot.
    const one = getattrCall(3000, root);
    const copies = Math.ceil((16 * 1024 * 1024) / one.length);
    const burst = Buffer.alloc(one.length * copies);
    for (let index = 0; index < copies; index++) {
      burst.set(one, index * one.length);
    }

    let drained = false;
    raw.socket.once("drain", () => {
      drained = true;
    });
    expect(raw.socket.write(burst)).toBe(false);

    // Two thousand turns of the loop after the window filled, with the socket
    // readable the whole time: a server still reading would have taken all
    // 16 MiB in a fraction of them, since one turn is up to a 64 KiB chunk and
    // 16 MiB is 256 of those.
    await gate.reaches(DEFAULT_NFS_MAX_IN_FLIGHT);
    await turns(2000);
    // `drain` has not fired and the write has not completed: Node reports the
    // whole outstanding `write()` in `writableLength` until libuv has handed
    // every byte of it to the kernel, so a non-zero value here is precisely
    // "the server did not consume the burst".
    expect(drained).toBe(false);
    expect(raw.socket.writableLength).toBeGreaterThan(0);

    // Reading resumes once the work does, and the gate can say so without a
    // clock. The records parsed before the pause came from one delivery — a
    // 64 KiB chunk, ~600 of them at 108 bytes each — because `#pump` pauses
    // synchronously inside the first `data` handler. So reaching five thousand
    // driver calls is half a megabyte of records that can only have come off
    // the socket after it was resumed. If it never resumed this waits forever
    // and the test times out, which is the failure this is here to produce.
    gate.open();
    await gate.reaches(5000);
    expect(gate.seen()).toBeGreaterThanOrEqual(5000);
  }, 120_000);

  it("treats a client's half-close as a reset, not a flush", async () => {
    // Written down rather than discovered: `end` stops the connection, so a
    // call still being answered when FIN arrives is not written back. Node runs
    // `net.Server` with `allowHalfOpen: false` and ends the writable side at
    // that same moment, so nothing that had not already reached `write()` could
    // have gone out either way — and no NFS client half-closes mid-request.
    const base = createMemoryDriver();
    await createLoopback(base).writeFile("/f.txt", "f");
    const gate = gated(base);
    const server = await serve(gate.driver);
    const client = await connect(server);
    const root = check(await client.mnt("/"), "mnt").fh!;

    const raw = await rawConnect(server);
    gate.shut();
    raw.socket.write(Buffer.from(getattrCall(5000, root)));
    await gate.reaches(1);

    // FIN with the call still in the driver. `close` on this socket is the
    // whole exchange finished — our FIN, the server's, and the descriptor gone
    // — so once it fires there is nothing left that could carry a reply.
    // (`once` rejects if the socket errors first; an error is also the end of
    // this connection, which is all this is waiting for.)
    const closed = once(raw.socket, "close").catch(() => undefined);
    raw.socket.end();
    await closed;

    gate.open();
    await turns(500);
    expect(raw.replies()).toBe(0);
  }, 60_000);

  it("waits for `drain` rather than queueing replies at a client that stopped reading", async () => {
    // The other half of the bound, and the one the write-up costed: 1 MiB
    // `READ`s pipelined by a client that never reads its socket. Serializing
    // the writes is what makes the queue its own high-water mark plus a reply
    // instead of the sum of every answer in flight — and the connection stops
    // reading while it is parked there, so the client cannot get further ahead.
    const size = 1024 * 1024;
    const base = createMemoryDriver();
    await createLoopback(base).writeFile("/big.bin", new Uint8Array(size).fill(0x5a));
    const gate = gated(base);
    const server = await serve(gate.driver);
    const client = await connect(server);
    const root = check(await client.mnt("/"), "mnt").fh!;
    const fh = check(await client.lookup(root, "big.bin"), "lookup").object!;

    const raw = await rawConnect(server);
    raw.socket.pause();
    const before = server.session.stats.requests;
    // The gate stays open here — it is only being used to count driver calls,
    // which is how this test knows the window filled without watching a clock.
    gate.reset();

    const asked = 200;
    const burst: Uint8Array[] = [];
    for (let index = 0; index < asked; index++) {
      burst.push(readCall(4000 + index, fh, 0n, size));
    }
    raw.socket.write(Buffer.concat(burst.map((record) => Buffer.from(record))));

    // The client is not reading, so the socket fills and the server parks on
    // `drain` with the rest of the burst still unread — 200 MiB of answers a
    // client asked for with 36 KiB of wire.
    await gate.reaches(DEFAULT_NFS_MAX_IN_FLIGHT);
    await turns(500);
    expect(raw.replies()).toBe(0);
    // The window is on what is *in flight*, so the running total is the window
    // plus however many replies the two kernel buffers swallowed before the
    // socket said no — a handful of megabytes, so a handful of 1 MiB answers.
    // Nowhere near the 200 the client asked for, which is the point.
    const dispatched = server.session.stats.requests - before;
    expect(dispatched).toBeLessThanOrEqual(DEFAULT_NFS_MAX_IN_FLIGHT + 32);
    expect(dispatched).toBeLessThan(asked);

    // Nothing was dropped: it all arrives once the client reads again.
    raw.socket.resume();
    await raw.awaits(asked);
  }, 120_000);
});
