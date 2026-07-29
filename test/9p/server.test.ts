/**
 * The 9P server: the same session, now with a socket in front of it.
 *
 * Everything the session answers is already pinned by `session.test.ts` and the
 * conformance column, both of which hand it frames in memory. What this file is
 * for is the layer those cannot see: real deliveries arriving split and merged
 * however the kernel felt like it, one assembler and one session per
 * connection, the negotiated `msize` becoming the frame limit, and a connection
 * dying — of a framing error, of `close()`, of EOF — without taking its
 * neighbour with it.
 *
 * The client is the Tier-1 one from `client.ts`, driven over a transport built
 * here out of a `Duplex`: it writes a frame and waits for the next whole frame
 * to come back. That makes it request-response sequential, which is all a
 * client has to be — the *server* answers concurrently, and the two-connection
 * cases below are what prove it.
 */

import { once } from "node:events";
import { chmod, mkdtemp, rm, stat } from "node:fs/promises";
import * as net from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex, PassThrough, duplexPair } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import {
  P9_GETATTR_BASIC,
  P9_IOHDRSZ,
  P9_NOTAG,
  P9_RGETATTR,
  P9_RLOPEN,
  P9_TGETATTR,
  P9_TLOPEN,
  P9_TREAD,
  P9_TVERSION,
  P9_TWRITE,
  P9_VERSION_DOTL,
} from "../../src/9p/constants.ts";
import {
  P9FrameAssembler,
  decodeMessage,
  encodeMessage,
  writeTgetattr,
  writeTlopen,
  writeTread,
  writeTversion,
  writeTwrite,
} from "../../src/9p/protocol.ts";
import { DEFAULT_MAX_IN_FLIGHT, createP9Server, type P9Server } from "../../src/9p/server.ts";
import type { P9Session } from "../../src/9p/session.ts";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { createLoopback, type Loopback } from "../../src/harness.ts";
import { O_RDONLY } from "../../src/fuse/constants.ts";
import type { FileHandleLike, FsDriver } from "../../src/types.ts";
import { CLIENT_MSIZE, P9Client, p9Driver } from "./client.ts";

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

/** A client, the stream under it, and the two facts a test needs about it. */
interface Spoken {
  client: P9Client;
  stream: Duplex;
  /** Resolves when the stream is fully closed, whoever closed it. */
  closed: Promise<void>;
  /**
   * The next `count` frames off the wire, in arrival order.
   *
   * For the cases the client cannot express, because it is sequential by
   * design: several requests in flight at once, and the order their replies
   * come back in.
   */
  collect(count: number): Promise<Uint8Array[]>;
  /** Drop the connection from this end. */
  end(): Promise<void>;
}

/**
 * A {@link P9Client} over a real stream.
 *
 * The client's transport is "one frame in, one frame out", so this is the whole
 * of it: write the request, reassemble deliveries until a frame comes out, hand
 * it back. A connection that dies rejects the request waiting on it — which is
 * exactly what the framing-error and `msize` cases below assert.
 */
function speak(stream: Duplex): Spoken {
  const assembler = new P9FrameAssembler();
  const ready: Uint8Array[] = [];
  let waiting:
    | { resolve: (frame: Uint8Array) => void; reject: (error: unknown) => void }
    | undefined;
  let failure: Error | undefined;

  const fail = (error: Error): void => {
    failure ??= error;
    const pending = waiting;
    waiting = undefined;
    pending?.reject(failure);
  };

  stream.on("data", (chunk: Buffer) => {
    try {
      for (const frame of assembler.push(chunk)) {
        const pending = waiting;
        if (pending === undefined) {
          ready.push(frame);
        } else {
          waiting = undefined;
          pending.resolve(frame);
        }
      }
    } catch (error) {
      fail(error as Error);
    }
  });
  stream.on("error", (error: Error) => fail(error));
  stream.on("close", () => fail(new Error("the connection closed before a reply arrived")));

  const next = (): Promise<Uint8Array> =>
    new Promise<Uint8Array>((resolve, reject) => {
      const frame = ready.shift();
      if (frame !== undefined) {
        resolve(frame);
      } else if (failure !== undefined) {
        reject(failure);
      } else {
        waiting = { resolve, reject };
      }
    });

  const client = new P9Client(async (request) => {
    if (failure !== undefined) {
      throw failure;
    }
    stream.write(request);
    return await next();
  });

  const closed = stream.closed ? Promise.resolve() : once(stream, "close").then(() => undefined);
  return {
    client,
    stream,
    closed,
    async collect(count) {
      const frames: Uint8Array[] = [];
      for (let taken = 0; taken < count; taken++) {
        frames.push(await next());
      }
      return frames;
    },
    async end() {
      if (!stream.destroyed) {
        stream.destroy();
      }
      await closed;
    },
  };
}

/** Servers and streams to take down whatever the test did. */
const servers: P9Server[] = [];
const spoken: Spoken[] = [];
/** Every session a test spoke to, checked for assertion failures on the way out. */
const sessions: P9Session[] = [];
/** Directories a unix-socket test made. */
const directories: string[] = [];

afterEach(async () => {
  for (const connection of spoken.splice(0)) {
    await connection.end();
  }
  for (const server of servers.splice(0)) {
    await server.close();
  }
  for (const session of sessions.splice(0)) {
    // The exactly-one-reply bookkeeping, for every request that crossed a real
    // socket rather than a function call.
    expect(session.assertions).toEqual([]);
    expect(session.stats.requests).toBe(session.stats.replies + session.stats.dropped);
  }
  for (const directory of directories.splice(0)) {
    await rm(directory, { recursive: true, force: true });
  }
});

/** What the transport complained about, in order. */
type Reports = { error: unknown; peer: string | undefined }[];

/** A server nobody has to remember to close. */
function serve(driver: FsDriver, options: Parameters<typeof createP9Server>[1] = {}): P9Server {
  const server = createP9Server(driver, options);
  servers.push(server);
  return server;
}

/** Connect to `server` over whichever kind of socket it is listening on. */
async function connect(server: P9Server): Promise<Spoken> {
  const socket = net.connect(
    server.path === undefined ? { port: server.port, host: "127.0.0.1" } : { path: server.path },
  );
  await once(socket, "connect");
  const connection = speak(socket);
  spoken.push(connection);
  return connection;
}

/** Version, attach, and a driver-shaped view of the export over the wire. */
async function ready(connection: Spoken, root = 0): Promise<Loopback> {
  const version = await connection.client.version();
  expect(version.version).toBe(P9_VERSION_DOTL);
  await connection.client.attach(root);
  return createLoopback(p9Driver(connection.client, root));
}

/** Remember a connection's session so `afterEach` can check its bookkeeping. */
function watch(server: P9Server): P9Session[] {
  const found = server.clients.map((client) => client.session);
  sessions.push(...found);
  return found;
}

/** A driver that counts the handles it hands out and the ones it gets back. */
function countingDriver(): { driver: FsDriver; counts: { opens: number; closes: number } } {
  const base = createMemoryDriver();
  const counts = { opens: 0, closes: 0 };
  return {
    counts,
    driver: {
      ...base,
      async open(path: string, flags?: string | number, mode?: number): Promise<FileHandleLike> {
        const handle = await base.open(path, flags, mode);
        counts.opens++;
        return {
          ...handle,
          async close() {
            counts.closes++;
            await handle.close();
          },
        };
      },
    },
  };
}

/** An `msize` big enough that a real socket's buffers cannot hide a queue. */
const BIG_MSIZE = 256 * 1024;

/** Deterministic bytes — a fixed seed, so a failure reproduces. */
function pattern(size: number, seed: number): Uint8Array {
  const bytes = new Uint8Array(size);
  let state = seed >>> 0;
  for (let index = 0; index < size; index++) {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    bytes[index] = state >>> 24;
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

describe("over TCP", () => {
  it("answers a client over a real socket", async () => {
    const server = serve(createMemoryDriver());
    await server.listen();
    expect(server.port).toBeGreaterThan(0);
    const address = server.address();
    expect(address).toMatchObject({ address: "127.0.0.1", port: server.port });
    expect(server.path).toBeUndefined();

    const connection = await connect(server);
    const fs = await ready(connection);
    await fs.mkdir("/notes");
    await fs.writeFile("/notes/hello.txt", "hello over TCP");
    expect(new TextDecoder().decode(await fs.readFile("/notes/hello.txt"))).toBe("hello over TCP");
    expect(
      (await fs.readdir("/notes", { withFileTypes: true })).map((entry) => entry.name),
    ).toEqual(["hello.txt"]);
    expect((await fs.stat("/notes/hello.txt")).size).toBe(14);

    expect(server.connections).toBe(1);
    const [session] = watch(server);
    expect(session?.msize).toBe(CLIENT_MSIZE);
    expect(session?.version).toBe(P9_VERSION_DOTL);
  });

  it("gives every connection its own session and fid table", async () => {
    const server = serve(createMemoryDriver());
    await server.listen();

    const first = await connect(server);
    const second = await connect(server);
    const one = await ready(first);
    const two = await ready(second);

    // Interleaved on purpose: each write lands between the other's.
    await one.writeFile("/one.txt", "1");
    await two.writeFile("/two.txt", "22");
    await one.writeFile("/one-again.txt", "111");
    await two.writeFile("/two-again.txt", "2222");
    expect(
      (await one.readdir("/", { withFileTypes: true })).map((entry) => entry.name).sort(),
    ).toEqual(["one-again.txt", "one.txt", "two-again.txt", "two.txt"]);

    // The same fid number on both connections, naming different files: a fid is
    // per-connection state, and this is the assertion that says so.
    await first.client.walk(0, 500, ["one.txt"]);
    await second.client.walk(0, 500, ["two-again.txt"]);
    expect(Number((await first.client.getattr(500)).size)).toBe(1);
    expect(Number((await second.client.getattr(500)).size)).toBe(4);

    expect(server.connections).toBe(2);
    const [a, b] = watch(server);
    expect(a).not.toBe(b);
  });

  it("answers requests concurrently, replying in completion order", async () => {
    // The transport dispatches each frame without awaiting it, so a slow
    // request cannot hold up a fast one behind it — which is what 9P's tags are
    // for, and the half of the zero-copy contract that lives in the server.
    const base = createMemoryDriver();
    const server = serve({
      ...base,
      async open(path: string, flags?: string | number, mode?: number) {
        if (path === "/slow.txt") {
          await new Promise((resolve) => setTimeout(resolve, 40));
        }
        return base.open(path, flags, mode);
      },
    });
    await server.listen();
    const connection = await connect(server);
    const fs = await ready(connection);
    await fs.writeFile("/slow.txt", "opening this file takes a while");
    await connection.client.walk(0, 600, ["slow.txt"]);
    watch(server);

    // Both frames in one delivery, too: a chunk carrying more than one message
    // is the ordinary case on a socket and the one a per-delivery loop has to
    // get right.
    const slow = encodeMessage(P9_TLOPEN, 11, (writer) =>
      writeTlopen(writer, { fid: 600, flags: O_RDONLY }),
    );
    const quick = encodeMessage(P9_TGETATTR, 12, (writer) =>
      writeTgetattr(writer, { fid: 0, requestMask: P9_GETATTR_BASIC }),
    );
    const both = new Uint8Array(slow.byteLength + quick.byteLength);
    both.set(slow);
    both.set(quick, slow.byteLength);
    connection.stream.write(both);

    const replies = (await connection.collect(2)).map((frame) => decodeMessage(frame));
    expect(replies.map((reply) => reply.tag)).toEqual([12, 11]);
    expect(replies.map((reply) => reply.type)).toEqual([P9_RGETATTR, P9_RLOPEN]);
  });

  // Needs an address on this host that is not `127.x`: a container with only a
  // loopback interface cannot ask the question, and skips rather than pretend
  // it has answered it.
  const external = Object.values(networkInterfaces())
    .flat()
    .find((entry) => entry !== undefined && entry.family === "IPv4" && !entry.internal);

  it.skipIf(external === undefined)("drops a connection that is not from loopback", async () => {
    const address = external!.address;
    const reports: Reports = [];
    const server = serve(createMemoryDriver(), {
      host: "0.0.0.0",
      onTransportError: (error, peer) => reports.push({ error, peer }),
    });
    await server.listen();

    const socket = net.connect({ port: server.port, host: address, localAddress: address });
    await once(socket, "connect");
    await once(socket, "close");

    expect(server.connections).toBe(0);
    expect(reports).toHaveLength(1);
    expect((reports[0]!.error as Error).message).toMatch(/loopback-only/);
    expect(reports[0]!.peer).toBe(address);
  });

  it("reports a port it cannot have", async () => {
    const taken = serve(createMemoryDriver());
    await taken.listen();
    const clash = serve(createMemoryDriver(), { port: taken.port });
    await expect(clash.listen()).rejects.toMatchObject({ code: "EADDRINUSE" });
  });

  it("kills only the connection whose framing broke", async () => {
    const reports: Reports = [];
    const server = serve(createMemoryDriver(), {
      onTransportError: (error, peer) => reports.push({ error, peer }),
    });
    await server.listen();

    const broken = await connect(server);
    const healthy = await connect(server);
    const doomed = await ready(broken);
    const survivor = await ready(healthy);
    await doomed.writeFile("/before.txt", "written before the garbage");
    watch(server);

    // `size` = 1, which is shorter than the 7-byte header: the one length a 9P
    // stream can never resynchronize from.
    broken.stream.write(Uint8Array.from([1, 0, 0, 0, 0, 0, 0]));
    await broken.closed;

    expect(reports).toHaveLength(1);
    const complaint = reports[0]!;
    expect((complaint.error as Error).message).toMatch(/below the 7-byte header/);
    expect(complaint.peer).toMatch(/127\.0\.0\.1/);
    expect(server.connections).toBe(1);

    // The survivor never noticed.
    expect(new TextDecoder().decode(await survivor.readFile("/before.txt"))).toBe(
      "written before the garbage",
    );
    await survivor.writeFile("/after.txt", "still serving");
    expect(
      (await survivor.readdir("/", { withFileTypes: true })).map((entry) => entry.name).sort(),
    ).toEqual(["after.txt", "before.txt"]);
  });

  it("carries a payload far larger than one frame", async () => {
    const server = serve(createMemoryDriver());
    await server.listen();
    const connection = await connect(server);
    const fs = await ready(connection);
    watch(server);

    // 256 KiB over an 8 KiB `msize`: dozens of frames, and every TCP delivery
    // boundary in between falling wherever the kernel puts it.
    const data = pattern(256 * 1024, 0x9d_1a_2b);
    await fs.writeFile("/big.bin", data);
    const read = await fs.readFile("/big.bin");
    expect(read.byteLength).toBe(data.byteLength);
    expect(Buffer.compare(Buffer.from(read), Buffer.from(data))).toBe(0);
  });

  it("refuses a frame larger than the negotiated msize", async () => {
    const reports: Reports = [];
    const server = serve(createMemoryDriver(), {
      onTransportError: (error, peer) => reports.push({ error, peer }),
    });
    await server.listen();

    const loud = await connect(server);
    const quiet = await connect(server);
    const noisy = await ready(loud);
    const calm = await ready(quiet);
    await noisy.writeFile("/f.txt", "");
    watch(server);

    // The `Tversion` above settled `msize` at 8 KiB, and the server lowered its
    // assembler onto it; this frame is over that and under the pre-negotiation
    // default, so only the negotiated bound can refuse it.
    await loud.client.walk(0, 400, ["f.txt"]);
    const oversized = encodeMessage(
      P9_TWRITE,
      42,
      (writer) => writeTwrite(writer, { fid: 400, offset: 0n, data: pattern(CLIENT_MSIZE, 7) }),
      CLIENT_MSIZE + 64,
    );
    expect(oversized.byteLength).toBeGreaterThan(CLIENT_MSIZE);
    await expect(loud.client.sendFrame(oversized, 42, "Twrite")).rejects.toThrow();
    await loud.closed;

    expect(reports).toHaveLength(1);
    expect((reports[0]!.error as Error).message).toMatch(
      new RegExp(`exceeds the ${CLIENT_MSIZE}-byte limit`),
    );
    expect(server.connections).toBe(1);
    await calm.writeFile("/still-here.txt", "yes");
    expect(new TextDecoder().decode(await calm.readFile("/still-here.txt"))).toBe("yes");
  });
});

// ---------------------------------------------------------------------------
// unix sockets
// ---------------------------------------------------------------------------

describe("over a unix socket", () => {
  /** A private directory, which is what the socket rule asks for. */
  async function privateDirectory(): Promise<string> {
    // `mkdtemp` makes it 0700 already; the chmod is what makes that a fact of
    // this test rather than of the platform.
    const directory = await mkdtemp(join(tmpdir(), "mountx-9p-sock-"));
    directories.push(directory);
    await chmod(directory, 0o700);
    return directory;
  }

  it("serves a socket, with a mode no other user can connect through", async () => {
    const directory = await privateDirectory();
    const path = join(directory, "9p.sock");
    const server = serve(createMemoryDriver(), { path });
    await server.listen();
    expect(server.path).toBe(path);
    expect(server.address()).toBe(path);

    const info = await stat(path);
    expect(info.mode & 0o777).toBe(0o600);

    const connection = await connect(server);
    const fs = await ready(connection);
    await fs.writeFile("/over-a-socket.txt", "hello over a unix socket");
    expect(new TextDecoder().decode(await fs.readFile("/over-a-socket.txt"))).toBe(
      "hello over a unix socket",
    );
    watch(server);
  });

  it("takes the socket file away when it closes", async () => {
    const directory = await privateDirectory();
    const path = join(directory, "gone.sock");
    const server = serve(createMemoryDriver(), { path });
    await server.listen();
    await stat(path);
    // Through the disposer, which is the `await using` form the docs show.
    await server[Symbol.asyncDispose]();
    await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("refuses a directory another local user can reach into", async () => {
    const directory = await privateDirectory();
    await chmod(directory, 0o755);
    const server = serve(createMemoryDriver(), { path: join(directory, "exposed.sock") });
    await expect(server.listen()).rejects.toThrow(/mode 0755/);
    // Nothing was bound, so nothing is listening.
    expect(server.address()).toBeNull();
  });

  it("lets the directory rule be waived on purpose", async () => {
    const directory = await privateDirectory();
    await chmod(directory, 0o755);
    const path = join(directory, "shared.sock");
    const server = serve(createMemoryDriver(), { path, allowSharedDirectory: true });
    await server.listen();
    const connection = await connect(server);
    const fs = await ready(connection);
    expect(await fs.readdir("/", { withFileTypes: true })).toEqual([]);
    watch(server);
    // The socket's own mode is still applied: it is the half that does not
    // depend on the directory.
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("refuses to be given both a socket path and a port", () => {
    expect(() => createP9Server(createMemoryDriver(), { path: "/tmp/x.sock", port: 5640 })).toThrow(
      /not both/,
    );
  });
});

// ---------------------------------------------------------------------------
// attach()
// ---------------------------------------------------------------------------

describe("attach()", () => {
  it("serves a socket somebody else accepted", async () => {
    // The `mount9p()` seam: a connected socket arrives from elsewhere — there,
    // one end of a socketpair — and the server never listened for it.
    const server = serve(createMemoryDriver());
    const listener = net.createServer({ noDelay: true });
    listener.listen(0, "127.0.0.1");
    await once(listener, "listening");
    const address = listener.address() as net.AddressInfo;

    const client = net.connect({ port: address.port, host: "127.0.0.1" });
    const [arrival] = await Promise.all([once(listener, "connection"), once(client, "connect")]);
    const accepted = arrival[0] as net.Socket;
    listener.close();

    const connection = server.attach(accepted, { peer: "socketpair" });
    expect(connection.peer).toBe("socketpair");
    expect(server.connections).toBe(1);

    const spokenTo = speak(client);
    spoken.push(spokenTo);
    const fs = await ready(spokenTo);
    await fs.writeFile("/attached.txt", "served over an attached socket");
    expect(new TextDecoder().decode(await fs.readFile("/attached.txt"))).toBe(
      "served over an attached socket",
    );
    sessions.push(connection.session);

    await connection.close();
    await connection.closed;
    expect(connection.session.destroyed).toBe(true);
    expect(server.connections).toBe(0);
  });

  it("bounds the write queue and the work in flight under one huge delivery", async () => {
    // The shape that made this necessary: 2,800 `Tread`s fit in 64 KiB of wire,
    // and answering all of them at once queued 2.93 GB of `Rread` (RSS 6 GB) —
    // a 45,557x amplification a client paid nothing for. Two bounds now hold it.
    // The queue: replies are written one at a time and the next one waits for
    // `drain`, so the stream holds its own high-water mark plus a frame. The
    // work: only `maxInFlight` requests are dispatched, so the rest wait as
    // *frames*, at 23 bytes each, instead of as replies at `msize` each.
    //
    // A stream pair with a tiny buffer, because that is what makes both bounds
    // observable: on a loopback socket the kernel absorbs megabytes before
    // `write()` ever says no (the TCP case is measured in "closes promptly...").
    const server = serve(createMemoryDriver());
    const [serverSide, clientSide] = duplexPair({ highWaterMark: 512 });
    const connection = server.attach(serverSide, { peer: "backpressure" });
    const spokenTo = speak(clientSide);
    const fs = await ready(spokenTo);
    await fs.writeFile("/big.bin", pattern(CLIENT_MSIZE - 1024, 11));
    await spokenTo.client.walk(0, 700, ["big.bin"]);
    await spokenTo.client.lopen(700, O_RDONLY);
    sessions.push(connection.session);
    const before = connection.session.stats.requests;

    // One delivery, 500 requests, and a peer that stops reading.
    clientSide.pause();
    const asked = 500;
    const burst: Uint8Array[] = [];
    for (let index = 0; index < asked; index++) {
      burst.push(
        encodeMessage(P9_TREAD, 100 + index, (writer) =>
          writeTread(writer, { fid: 700, offset: 0n, count: CLIENT_MSIZE - P9_IOHDRSZ }),
        ),
      );
    }
    let peak = 0;
    const sampler = setInterval(() => {
      peak = Math.max(peak, serverSide.writableLength);
    }, 1);
    clientSide.write(Buffer.concat(burst.map((frame) => Buffer.from(frame))));
    await expect.poll(() => serverSide.isPaused(), { timeout: 10_000 }).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 50));
    clearInterval(sampler);

    expect(peak).toBeLessThanOrEqual(512 + CLIENT_MSIZE + 1024);
    const dispatched = connection.session.stats.requests - before;
    expect(dispatched).toBeLessThanOrEqual(DEFAULT_MAX_IN_FLIGHT + 4);
    expect(dispatched).toBeLessThan(asked);

    // And it picks up where it left off once the peer drains it: every reply
    // arrives, in order, none of them lost to the pause.
    clientSide.resume();
    const replies = await spokenTo.collect(asked);
    expect(replies.map((frame) => decodeMessage(frame).tag)).toEqual(
      Array.from({ length: asked }, (_, index) => 100 + index),
    );
    await expect.poll(() => serverSide.isPaused()).toBe(false);
    await connection.close();
  }, 30_000);

  it("keeps a stream whose write() throws from taking the process with it", async () => {
    // An embedder's `Duplex` can refuse a reply, and a rejection out of the
    // reply chain with nobody catching it is a dead process under Node's
    // defaults. `src/nfs/server.ts` carries the same catch for the same reason.
    const reports: Reports = [];
    const server = serve(createMemoryDriver(), {
      onTransportError: (error, peer) => reports.push({ error, peer }),
    });
    const hostile = new Duplex({
      read() {},
      write(_chunk, _encoding, callback) {
        callback();
      },
    });
    Object.defineProperty(hostile, "write", {
      value: () => {
        throw new Error("this stream refuses to carry a reply");
      },
    });

    const connection = server.attach(hostile, { peer: "hostile", own: false });
    sessions.push(connection.session);
    hostile.push(
      encodeMessage(P9_TVERSION, P9_NOTAG, (writer) =>
        writeTversion(writer, { msize: CLIENT_MSIZE, version: P9_VERSION_DOTL }),
      ),
    );
    await connection.closed;

    expect(reports).toHaveLength(1);
    expect((reports[0]!.error as Error).message).toMatch(/refuses to carry a reply/);
    expect(reports[0]!.peer).toBe("hostile");
    expect(connection.session.destroyed).toBe(true);
    expect(server.connections).toBe(0);
  });

  it("refuses to attach the same stream twice", () => {
    const server = serve(createMemoryDriver());
    const [serverSide] = duplexPair();
    const connection = server.attach(serverSide);
    sessions.push(connection.session);
    expect(() => server.attach(serverSide)).toThrow(/already attached/);
    expect(server.connections).toBe(1);
  });

  it("serves a duplex that is not a socket at all", async () => {
    const server = serve(createMemoryDriver());
    const [serverSide, clientSide] = duplexPair();

    const connection = server.attach(serverSide);
    const spokenTo = speak(clientSide);
    const fs = await ready(spokenTo);
    await fs.writeFile("/streamed.txt", "no socket involved");
    expect(new TextDecoder().decode(await fs.readFile("/streamed.txt"))).toBe("no socket involved");
    sessions.push(connection.session);

    // A stream this server did not create is not destroyed by it — the write
    // side is ended, which is the EOF that tells the peer the connection is
    // over, and the only part that is this server's to say.
    const sawEof = once(clientSide, "end");
    await connection.close();
    await sawEof;
    expect(connection.session.destroyed).toBe(true);
    expect(serverSide.destroyed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// teardown
// ---------------------------------------------------------------------------

describe("teardown", () => {
  it("destroys every session when the server closes", async () => {
    const { driver, counts } = countingDriver();
    const server = serve(driver);
    await server.listen();
    const connection = await connect(server);
    const fs = await ready(connection);
    await fs.writeFile("/held.txt", "open across the close");
    // A fid left open on purpose: what `close()` has to get back.
    await connection.client.walk(0, 300, ["held.txt"]);
    await connection.client.lopen(300, O_RDONLY);
    const [session] = watch(server);
    expect(counts.opens).toBeGreaterThan(counts.closes);

    await server.close();

    expect(counts.closes).toBe(counts.opens);
    expect(session?.destroyed).toBe(true);
    expect(server.connections).toBe(0);
    expect(server.address()).toBeNull();
    await connection.closed;
    // Nothing else may be attached to a closed server.
    expect(() => server.attach(new PassThrough())).toThrow(/closed/);
  });

  it("closes promptly when a half-closed peer stops reading", async () => {
    // The case a polite `destroySoon()` cannot survive: the client sends FIN
    // and then never reads another byte, so the flush it is waiting for never
    // happens — and `net.Server.close()` is waiting for that same socket. The
    // socket has to be tracked until *its* close, not until its session came
    // down, and destroyed outright when the server goes.
    const server = serve(createMemoryDriver(), { msize: BIG_MSIZE });
    await server.listen();
    const connection = await connect(server);
    connection.client.msize = BIG_MSIZE;
    const fs = await ready(connection);
    await fs.writeFile("/big.bin", pattern(BIG_MSIZE - 1024, 21));
    await connection.client.walk(0, 800, ["big.bin"]);
    await connection.client.lopen(800, O_RDONLY);
    const [live] = server.clients;
    watch(server);

    // Ask for far more than this peer will ever take, and stop reading.
    connection.stream.pause();
    const burst: Uint8Array[] = [];
    for (let index = 0; index < 300; index++) {
      burst.push(
        encodeMessage(P9_TREAD, 100 + index, (writer) =>
          writeTread(writer, { fid: 800, offset: 0n, count: BIG_MSIZE - P9_IOHDRSZ }),
        ),
      );
    }
    let peak = 0;
    const sampler = setInterval(() => {
      peak = Math.max(peak, live!.stream.writableLength);
    }, 1);
    connection.stream.write(Buffer.concat(burst.map((frame) => Buffer.from(frame))));
    // Wait for a queue to actually exist: with none, any close would look fast.
    await expect.poll(() => live!.stream.writableLength, { timeout: 15_000 }).toBeGreaterThan(0);
    clearInterval(sampler);
    // Even on a real socket, where the kernel absorbs megabytes before saying
    // no, what *this process* holds is one frame's worth.
    expect(peak).toBeLessThanOrEqual(BIG_MSIZE + 64 * 1024);

    // FIN, with the queue still unread. The session comes down on EOF, and
    // the socket must go with it: `closed` resolving while the descriptor is
    // still open is exactly what left `net.Server.close()` waiting forever.
    connection.stream.end();
    await live!.closed;
    expect(live!.session.destroyed).toBe(true);
    expect(live!.stream.destroyed).toBe(true);
    expect(server.connections).toBe(0);

    const started = performance.now();
    await server.close();
    expect(performance.now() - started).toBeLessThan(5000);
  }, 30_000);

  it("takes a reset from the client without calling it an error", async () => {
    const reports: Reports = [];
    const { driver, counts } = countingDriver();
    const server = serve(driver, {
      onTransportError: (error, peer) => reports.push({ error, peer }),
    });
    await server.listen();
    const connection = await connect(server);
    const fs = await ready(connection);
    await fs.writeFile("/held.txt", "reset while this is open");
    await connection.client.walk(0, 302, ["held.txt"]);
    await connection.client.lopen(302, O_RDONLY);
    const [live] = server.clients;
    sessions.push(live!.session);

    // A client that dies rather than leaves: `ECONNRESET` is what that looks
    // like from here, and it is not this server's problem to report.
    (connection.stream as net.Socket).resetAndDestroy();
    await live!.closed;

    expect(reports).toEqual([]);
    expect(live!.session.destroyed).toBe(true);
    expect(counts.closes).toBe(counts.opens);
    expect(server.connections).toBe(0);
  });

  it("destroys the session when the client goes away", async () => {
    const { driver, counts } = countingDriver();
    const server = serve(driver);
    await server.listen();
    const connection = await connect(server);
    const fs = await ready(connection);
    await fs.writeFile("/held.txt", "open when the client vanishes");
    await connection.client.walk(0, 301, ["held.txt"]);
    await connection.client.lopen(301, O_RDONLY);
    const [live] = server.clients;
    const session = live!.session;
    sessions.push(session);
    expect(counts.opens).toBeGreaterThan(counts.closes);

    // EOF is the only way a 9P connection ends: there is no `Tdestroy`, so this
    // is what has to reach `session.destroy()`.
    connection.stream.end();
    await live!.closed;

    expect(session.destroyed).toBe(true);
    expect(counts.closes).toBe(counts.opens);
    expect(server.connections).toBe(0);
  });
});
