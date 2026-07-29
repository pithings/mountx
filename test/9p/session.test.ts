/**
 * The 9P session: everything that has no `node:fs` equivalent.
 *
 * The conformance column (step 6) will prove the *filesystem* semantics survive
 * the trip. This file goes at what only 9P has: the version handshake and the
 * reset it performs, fids and their lifetime, the partial-walk rule, the qid a
 * client caches everything against, readdir cookies and the dots the kernel
 * does not synthesize, `Tflush` ordering, and the errno discipline underneath
 * all of it.
 *
 * Driven through the Tier-1 JS client, which speaks the same codecs from the
 * other side — so every assertion here is one an encoder and a decoder had to
 * agree on.
 */

import { afterEach, describe, expect, it } from "vitest";
import {
  P9_GETATTR_ALL,
  P9_GETATTR_BASIC,
  P9_GETATTR_BTIME,
  P9_GETATTR_MODE,
  P9_GETATTR_SIZE,
  P9_MAXWELEM,
  P9_MIN_MSIZE,
  P9_NOFID,
  P9_NOTAG,
  P9_QTDIR,
  P9_QTFILE,
  P9_QTSYMLINK,
  P9_RGETATTR,
  P9_RLERROR,
  P9_TAUTH,
  P9_TGETATTR,
  P9_TOPEN,
  P9_TREADDIR,
  P9_TVERSION,
  P9_TWALK,
  P9_VERSION_DOTL,
  P9_VERSION_UNKNOWN,
  V9FS_MAGIC,
} from "../../src/9p/constants.ts";
import {
  encodeMessage,
  readRlerror,
  writeTgetattr,
  writeTreaddir,
  writeTversion,
} from "../../src/9p/protocol.ts";
import { DEFAULT_MSIZE, P9Session, type P9SessionOptions } from "../../src/9p/session.ts";
import type { P9Writer } from "../../src/9p/wire.ts";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { ERRNO_CODES } from "../../src/errors.ts";
import { createLoopback, type Loopback } from "../../src/harness.ts";
import { S_IFLNK, S_IFMT, S_IFREG, type DirentLike, type FsDriver } from "../../src/types.ts";
import { P9Client } from "./client.ts";

/** `DT_*`, which is `(mode & S_IFMT) >> 12`. */
const DT_DIR = 4;
const DT_REG = 8;
const DT_LNK = 10;

interface Harness {
  session: P9Session;
  client: P9Client;
  fs: Loopback;
}

const sessions: P9Session[] = [];

afterEach(async () => {
  for (const session of sessions.splice(0)) {
    expect(session.assertions).toEqual([]);
    await session.destroy();
  }
});

/** A session and a client, with nothing negotiated yet. */
function raw(driver: FsDriver = createMemoryDriver(), options: P9SessionOptions = {}): Harness {
  const session = new P9Session(driver, options);
  sessions.push(session);
  return { session, client: P9Client.overSession(session), fs: createLoopback(driver) };
}

/** The same, versioned and attached at `/` on fid 0. */
async function serve(
  driver: FsDriver = createMemoryDriver(),
  options: P9SessionOptions = {},
): Promise<Harness> {
  const harness = raw(driver, options);
  await harness.client.version();
  await harness.client.attach(0);
  return harness;
}

/** The `code` an awaited call rejected with. */
async function codeOfRejection(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    return (error as { code?: string }).code ?? "no code";
  }
  throw new Error("expected a rejection");
}

/** A `DirentLike` for a name a driver reports but cannot stat. */
function ghost(name: string): DirentLike {
  return {
    name,
    isFile: () => true,
    isDirectory: () => false,
    isSymbolicLink: () => false,
    isBlockDevice: () => false,
    isCharacterDevice: () => false,
    isFIFO: () => false,
    isSocket: () => false,
  };
}

/** A driver whose `lstat` parks on a gate once the test opens it. */
function gated(): { driver: FsDriver; block: () => void; release: () => void } {
  const memory = createMemoryDriver();
  let gate: Promise<void> | undefined;
  let open!: () => void;
  return {
    driver: {
      ...memory,
      async lstat(path) {
        if (gate !== undefined) {
          await gate;
        }
        return memory.lstat(path);
      },
    },
    block: () => {
      gate = new Promise<void>((resolve) => {
        open = resolve;
      });
    },
    release: () => open(),
  };
}

describe("Tversion", () => {
  it("agrees on 9P2000.L and the smaller of the two msizes", async () => {
    const { client, session } = raw();
    expect(await client.version(8192)).toEqual({ msize: 8192, version: P9_VERSION_DOTL });
    expect(session.msize).toBe(8192);
    expect(session.version).toBe(P9_VERSION_DOTL);
  });

  it("clamps in both directions: the client's proposal and the server's ceiling", async () => {
    const big = raw();
    expect((await big.client.version(64 * 1024 * 1024)).msize).toBe(DEFAULT_MSIZE);

    const small = raw(createMemoryDriver(), { msize: 16 * 1024 });
    expect((await small.client.version(64 * 1024 * 1024)).msize).toBe(16 * 1024);
    expect((await small.client.version(8192)).msize).toBe(8192);
  });

  it("answers 'unknown' for a dialect it does not speak, and stays unnegotiated", async () => {
    const { client, session } = raw();
    expect((await client.version(8192, "9P2000")).version).toBe(P9_VERSION_UNKNOWN);
    expect(session.msize).toBeUndefined();
    expect(session.version).toBeUndefined();
    // Lowercase is the *mount option*'s spelling, never the wire's.
    expect((await client.version(8192, "9p2000.L")).version).toBe(P9_VERSION_UNKNOWN);
  });

  it("refuses an msize the client itself would reject, and says so as 'unknown'", async () => {
    const { client, session } = raw();
    const refused = await client.version(P9_MIN_MSIZE - 1);
    expect(refused.version).toBe(P9_VERSION_UNKNOWN);
    // The number still goes out, so the reason is visible even though the
    // protocol has no way to name it.
    expect(refused.msize).toBe(P9_MIN_MSIZE - 1);
    expect(session.msize).toBeUndefined();
    expect((await client.version(P9_MIN_MSIZE)).version).toBe(P9_VERSION_DOTL);
  });

  it("refuses everything else until it has been answered", async () => {
    const { client } = raw();
    expect(await codeOfRejection(client.attach(0))).toBe("EPROTO");
    expect(await codeOfRejection(client.getattr(0))).toBe("EPROTO");
    await client.version();
    await client.attach(0);
  });

  it("resets the session: every fid is clunked and every handle closed", async () => {
    let closed = 0;
    const memory = createMemoryDriver();
    const driver: FsDriver = {
      ...memory,
      async open(path, flags, mode) {
        const handle = await memory.open(path, flags, mode);
        return {
          ...handle,
          async close() {
            closed++;
            await handle.close();
          },
        };
      },
    };
    const { client, session, fs } = raw(driver);
    await client.version();
    await client.attach(0);
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    // Step 5 brings `Tlopen`; the state it will leave is set here by hand, so
    // that the reset has a handle to close.
    session.fids.require(1).open = {
      flags: 0,
      handle: await driver.open("/file", "r"),
      directory: false,
    };
    expect(session.fids.size).toBe(2);

    // A close that fails during the reset is reported, never raised: the fids
    // are gone whatever the driver thinks.
    session.fids.require(0).open = {
      flags: 0,
      directory: true,
      handle: {
        ...(await driver.open("/file", "r")),
        close: () => Promise.reject(new Error("no")),
      },
    };

    const before = closed;
    await client.version();
    expect(session.fids.size).toBe(0);
    expect(closed).toBe(before + 1);
    // The session is negotiated again, so the root fid is not "too early" — it
    // is simply gone, and the client has to attach afresh.
    expect(await codeOfRejection(client.getattr(0))).toBe("EBADF");
    await client.attach(0);
  });
});

describe("Tattach", () => {
  it("binds a fid to the root for an empty or '/' aname", async () => {
    const { client } = await serve();
    const qid = await client.attach(1, { aname: "/" });
    expect(qid.type).toBe(P9_QTDIR);
    // The same file, so the same identity — the client caches on `qid.path`.
    expect(qid.path).toBe((await client.getattr(0)).qid.path);
    expect(qid.path).toBeGreaterThan(0n);
  });

  it("attaches at a subtree when aname names one, and clamps '..'", async () => {
    const { client, fs } = await serve();
    await fs.mkdir("/sub");
    const [walked] = await client.walk(0, 1, ["sub"]);
    expect((await client.attach(2, { aname: "/sub" })).path).toBe(walked!.path);
    // `..` is lexical and clamped at the root by `src/path.ts`, so no aname can
    // name anything outside the driver.
    expect((await client.attach(3, { aname: "/../.." })).path).toBe(
      (await client.getattr(0)).qid.path,
    );
  });

  it("refuses an aname that is missing or is not a directory", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "x");
    expect(await codeOfRejection(client.attach(1, { aname: "/missing" }))).toBe("ENOENT");
    expect(await codeOfRejection(client.attach(2, { aname: "/file" }))).toBe("ENOTDIR");
    // A refused attach leaves no fid behind.
    expect(await codeOfRejection(client.getattr(1))).toBe("EBADF");
  });

  it("insists on P9_NOFID as the afid, and refuses Tauth outright", async () => {
    const { client } = await serve();
    expect(await codeOfRejection(client.attach(1, { afid: 7 }))).toBe("ENOTSUP");
    const ecode = await client.expectError(P9_TAUTH, (writer) => {
      writer.u32(P9_NOFID).string("me").string("/").u32(1000);
    });
    expect(ecode).toBe(ERRNO_CODES.ENOTSUP);
  });

  it("refuses a fid that is already in use", async () => {
    const { client } = await serve();
    expect(await codeOfRejection(client.attach(0))).toBe("EINVAL");
  });

  it("records the attaching user, and every walked fid inherits it", async () => {
    const { client, session } = await serve();
    await client.attach(1, { uname: "ada", aname: "/", nUname: 1000 });
    expect(session.userFor(1)).toEqual({ uname: "ada", uid: 1000, aname: "/" });
    await client.walk(1, 2, []);
    expect(session.userFor(2)).toEqual({ uname: "ada", uid: 1000, aname: "/" });
    await client.clunk(2);
    expect(session.userFor(2)).toBeUndefined();
    // `(uid_t)-1` is the sentinel for "no numeric uid", not a uid.
    await client.attach(3, { uname: "ada", nUname: 0xff_ff_ff_ff });
    expect(session.userFor(3)?.uid).toBeUndefined();
  });
});

describe("Twalk", () => {
  it("clones a fid with no names, and does not stat to do it", async () => {
    let stats = 0;
    const memory = createMemoryDriver();
    const { client } = await serve({
      ...memory,
      async lstat(path) {
        stats++;
        return memory.lstat(path);
      },
    });
    const before = stats;
    expect(await client.walk(0, 1, [])).toEqual([]);
    expect(stats).toBe(before);
    // The clone names the same file.
    expect((await client.getattr(1)).qid.path).toBe((await client.getattr(0)).qid.path);
  });

  it("answers one qid per name, each the intermediate's own", async () => {
    const { client, fs } = await serve();
    await fs.mkdir("/a");
    await fs.mkdir("/a/b");
    await fs.writeFile("/a/b/c", "hello");
    const qids = await client.walk(0, 1, ["a", "b", "c"]);
    expect(qids).toHaveLength(3);
    expect(qids.map((qid) => qid.type)).toEqual([P9_QTDIR, P9_QTDIR, P9_QTFILE]);
    expect(qids[0]!.path).toBe((await client.walk(0, 2, ["a"]))[0]!.path);
    expect(qids[1]!.path).toBe((await client.walk(0, 3, ["a", "b"]))[1]!.path);
  });

  it("answers Rlerror when the first name fails, and a short Rwalk when a later one does", async () => {
    const { client, fs } = await serve();
    await fs.mkdir("/a");
    expect(await codeOfRejection(client.walk(0, 1, ["missing", "b"]))).toBe("ENOENT");
    // Two names, one qid: the client learns exactly how far it got.
    expect(await client.walk(0, 1, ["a", "missing"])).toHaveLength(1);
    // ... and `newfid` was not installed ...
    expect(await codeOfRejection(client.getattr(1))).toBe("EBADF");
    // ... and `fid` did not move.
    expect((await client.getattr(0)).qid.type).toBe(P9_QTDIR);
  });

  it("leaves an in-place walk where it was when it fails part-way", async () => {
    const { client, fs } = await serve();
    await fs.mkdir("/a");
    await client.walk(0, 1, ["a"]);
    expect(await client.walk(1, 1, ["..", "missing"])).toHaveLength(1);
    // Still `/a`, not `/`: the path is only assigned once every name resolves.
    expect((await client.getattr(1)).qid.path).toBe((await client.walk(0, 2, ["a"]))[0]!.path);
  });

  it("clamps '..' at the root", async () => {
    const { client } = await serve();
    const root = await client.getattr(0);
    const qids = await client.walk(0, 1, ["..", "..", ".."]);
    expect(qids.map((qid) => qid.path)).toEqual([root.qid.path, root.qid.path, root.qid.path]);
  });

  it("refuses a newfid that is already in use, even when the walk would be short", async () => {
    const { client, fs } = await serve();
    await fs.mkdir("/a");
    await client.walk(0, 1, ["a"]);
    expect(await codeOfRejection(client.walk(0, 1, ["a"]))).toBe("EINVAL");
    // The dup is the client's real mistake, so it wins over the partial walk.
    expect(await codeOfRejection(client.walk(0, 1, ["a", "missing"]))).toBe("EINVAL");
  });

  it("refuses a walk from an open fid", async () => {
    const { client, session, fs } = await serve();
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    session.fids.require(1).open = { flags: 0, handle: undefined, directory: false };
    expect(await codeOfRejection(client.walk(1, 2, []))).toBe("EINVAL");
  });

  it("refuses a name that is not a name, and a walk over the element limit", async () => {
    const { client } = await serve();
    expect(await codeOfRejection(client.walk(0, 1, ["a/b"]))).toBe("EINVAL");
    expect(await codeOfRejection(client.walk(0, 1, [""]))).toBe("EINVAL");
    // The codec refuses to *encode* more than `P9_MAXWELEM`, so this frame is
    // built by hand — and the decoder refuses it, which is a malformed request
    // rather than a failed one.
    const names = Array.from({ length: P9_MAXWELEM + 1 }, (_, index) => `n${index}`);
    const ecode = await client.expectError(P9_TWALK, (writer) => {
      writer.u32(0).u32(1).u16(names.length);
      for (const name of names) {
        writer.string(name);
      }
    });
    expect(ecode).toBe(ERRNO_CODES.EINVAL);
  });

  it("refuses a fid it never issued", async () => {
    const { client } = await serve();
    expect(await codeOfRejection(client.walk(9, 10, []))).toBe("EBADF");
    expect(await codeOfRejection(client.walk(P9_NOFID, 1, []))).toBe("EBADF");
  });
});

describe("Tclunk", () => {
  it("drops the fid, and refuses a second clunk of it", async () => {
    const { client, session } = await serve();
    await client.walk(0, 1, []);
    expect(session.fids.size).toBe(2);
    await client.clunk(1);
    expect(session.fids.size).toBe(1);
    expect(await codeOfRejection(client.clunk(1))).toBe("EBADF");
  });

  it("succeeds even when the driver's close fails, and reports it instead", async () => {
    const errors: unknown[] = [];
    const { client, session } = raw(createMemoryDriver(), {
      onError: (error) => errors.push(error),
    });
    await client.version();
    await client.attach(0);
    const rejects = (): Promise<never> => Promise.reject(new Error("close failed"));
    session.fids.require(0).open = {
      flags: 0,
      directory: true,
      handle: {
        read: rejects,
        write: rejects,
        stat: rejects,
        truncate: rejects,
        close: rejects,
      },
    };
    await client.clunk(0);
    expect(session.fids.size).toBe(0);
    expect((errors.at(-1) as Error).message).toBe("close failed");
  });
});

describe("Tgetattr", () => {
  it("fills what a StatsLike can answer, and claims only that", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "hello");
    await client.walk(0, 1, ["file"]);
    const attr = await client.getattr(1, P9_GETATTR_ALL);
    // Everything in BASIC, plus BTIME because the memory driver has a birth
    // time. Never GEN or DATA_VERSION: the fields go out as zero and `valid`
    // says so.
    expect(attr.valid).toBe(P9_GETATTR_BASIC | P9_GETATTR_BTIME);
    expect(attr.gen).toBe(0n);
    expect(attr.dataVersion).toBe(0n);
    expect(attr.size).toBe(5n);
    expect(attr.nlink).toBe(1n);
    expect(attr.mode & S_IFMT).toBe(S_IFREG);
    expect(attr.qid.type).toBe(P9_QTFILE);
    expect(attr.mtime.sec).toBeGreaterThan(0n);
    expect(attr.blksize).toBe(4096n);
  });

  it("honours the request mask", async () => {
    const { client } = await serve();
    expect((await client.getattr(0, P9_GETATTR_MODE)).valid).toBe(P9_GETATTR_MODE);
    expect((await client.getattr(0, P9_GETATTR_MODE | P9_GETATTR_SIZE)).valid).toBe(
      P9_GETATTR_MODE | P9_GETATTR_SIZE,
    );
    // A bit nobody has defined is not claimed either.
    expect((await client.getattr(0, 1n << 40n)).valid).toBe(0n);
  });

  it("falls back to stat for a driver with no lstat at all", async () => {
    const memory = createMemoryDriver();
    const { lstat: _dropped, ...withoutLstat } = memory;
    const { client, fs } = await serve(withoutLstat);
    await fs.writeFile("/file", "hello");
    await client.walk(0, 1, ["file"]);
    expect((await client.getattr(1)).size).toBe(5n);
  });

  it("does not claim BTIME for a driver with no birth time", async () => {
    const memory = createMemoryDriver();
    const { client } = await serve({
      ...memory,
      async lstat(path) {
        return { ...(await memory.lstat(path)), birthtimeMs: 0 };
      },
    });
    expect((await client.getattr(0)).valid).toBe(P9_GETATTR_BASIC);
  });

  it("reports the qid type for each kind of file, and lstats rather than stats", async () => {
    const { client, fs } = await serve();
    await fs.mkdir("/dir");
    await fs.writeFile("/file", "x");
    await fs.symlink("/file", "/link");
    const [dir] = await client.walk(0, 1, ["dir"]);
    const [file] = await client.walk(0, 2, ["file"]);
    const [link] = await client.walk(0, 3, ["link"]);
    expect([dir!.type, file!.type, link!.type]).toEqual([P9_QTDIR, P9_QTFILE, P9_QTSYMLINK]);
    // A fid on a symlink describes the link, never its target.
    expect((await client.getattr(3)).mode & S_IFMT).toBe(S_IFLNK);
  });

  it("gives hardlinks one qid.path, or two when the driver is not trusted for it", async () => {
    const shared = await serve();
    await shared.fs.writeFile("/one", "x");
    await shared.fs.link("/one", "/two");
    expect((await shared.client.walk(0, 1, ["one"]))[0]!.path).toBe(
      (await shared.client.walk(0, 2, ["two"]))[0]!.path,
    );

    // `useDriverIno: false` is the honest answer when a driver cannot identify
    // a file: two names, two identities. It changes nothing else on this wire —
    // `Rgetattr` has no `st_ino` field, so the driver's own number never
    // travels either way.
    const split = await serve(createMemoryDriver(), { useDriverIno: false });
    await split.fs.writeFile("/one", "x");
    await split.fs.link("/one", "/two");
    expect((await split.client.walk(0, 1, ["one"]))[0]!.path).not.toBe(
      (await split.client.walk(0, 2, ["two"]))[0]!.path,
    );
  });
});

describe("Tstatfs", () => {
  it("reports the driver's numbers, its magic, and a namelen", async () => {
    const { client, fs } = await serve();
    const expected = await fs.statfs("/");
    const reply = await client.statfs(0);
    expect(reply.type).toBe(expected.type);
    expect(reply.bsize).toBe(expected.bsize);
    expect(reply.blocks).toBe(BigInt(expected.blocks));
    expect(reply.bfree).toBe(BigInt(expected.bfree));
    expect(reply.namelen).toBe(255);
    // One filesystem per session, and nothing stable to name it with.
    expect(reply.fsid).toBe(0n);
  });

  it("falls back to V9FS_MAGIC for a driver with no magic of its own", async () => {
    const memory = createMemoryDriver();
    const { client } = await serve({
      ...memory,
      async statfs(path) {
        return { ...(await memory.statfs(path)), type: 0, bsize: 0 };
      },
    });
    const reply = await client.statfs(0);
    expect(reply.type).toBe(V9FS_MAGIC);
    expect(reply.bsize).toBe(4096);
  });

  it("answers ENOSYS when the driver does not declare statfs", async () => {
    const memory = createMemoryDriver();
    const { client } = await serve({
      ...memory,
      capabilities: { ...memory.capabilities, statfs: false },
    });
    expect(await codeOfRejection(client.statfs(0))).toBe("ENOSYS");
  });
});

describe("Treaddir", () => {
  /** A `/dir` of `count` files, walked onto fid 1. */
  async function populated(count = 6, options: P9SessionOptions = {}): Promise<Harness> {
    const harness = await serve(createMemoryDriver(), options);
    await harness.fs.mkdir("/dir");
    for (let index = 0; index < count; index++) {
      await harness.fs.writeFile(`/dir/f${index}`, "x");
    }
    await harness.client.walk(0, 1, ["dir"]);
    return harness;
  }

  it("puts '.' and '..' first, because the kernel does not synthesize them", async () => {
    const { client } = await populated(2);
    const entries = await client.readdirAll(1);
    expect(entries.map((entry) => entry.name)).toEqual([".", "..", "f0", "f1"]);
    expect(entries[0]!.type).toBe(DT_DIR);
    expect(entries[1]!.type).toBe(DT_DIR);
    expect(entries[2]!.type).toBe(DT_REG);
    // `..` of a subdirectory is its parent.
    expect(entries[1]!.qid.path).toBe((await client.getattr(0)).qid.path);
  });

  it("reports the dirent type for each kind of file", async () => {
    const { client, fs } = await serve();
    await fs.mkdir("/dir");
    await fs.writeFile("/dir/file", "x");
    await fs.symlink("/dir/file", "/dir/link");
    await client.walk(0, 1, ["dir"]);
    const types = new Map(
      (await client.readdirAll(1)).map((entry) => [entry.name, entry.type] as const),
    );
    expect(types.get("file")).toBe(DT_REG);
    expect(types.get("link")).toBe(DT_LNK);
  });

  it("pages: a small count forces several Treaddirs, and the offsets resume", async () => {
    const { client } = await populated(8);
    const pages: number[] = [];
    const names: string[] = [];
    let offset = 0n;
    for (;;) {
      const page = await client.readdir(1, offset, 64);
      if (page.length === 0) {
        break;
      }
      pages.push(page.length);
      names.push(...page.map((entry) => entry.name));
      offset = page.at(-1)!.offset;
    }
    expect(pages.length).toBeGreaterThan(2);
    expect(names).toEqual([".", "..", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"]);
    // Offsets are one-based cookies, so `0` keeps its "start over" meaning.
    expect(offset).toBe(10n);
  });

  it("resumes from any offset it handed out, not only the last of a page", async () => {
    const { client } = await populated(4);
    const first = await client.readdir(1, 0n);
    expect(first.map((entry) => entry.name)).toEqual([".", "..", "f0", "f1", "f2", "f3"]);
    // The cookie on `..` resumes at `f0`.
    expect((await client.readdir(1, first[1]!.offset)).map((entry) => entry.name)).toEqual([
      "f0",
      "f1",
      "f2",
      "f3",
    ]);
  });

  it("re-lists at offset 0, and refuses an offset the new listing has no room for", async () => {
    const { client, fs } = await populated(4);
    const first = await client.readdir(1, 0n);
    const stale = first.at(-1)!.offset;
    expect(stale).toBe(6n);
    await fs.unlink("/dir/f2");
    await fs.unlink("/dir/f3");

    const again = await client.readdir(1, 0n);
    expect(again.map((entry) => entry.name)).toEqual([".", "..", "f0", "f1"]);
    expect(await codeOfRejection(client.readdir(1, stale))).toBe("EINVAL");
  });

  it("refuses an offset this fid was never given", async () => {
    const { client } = await populated(2);
    expect(await codeOfRejection(client.readdir(1, 7n))).toBe("EINVAL");
    await client.readdir(1, 0n);
    // An offset from *another* fid is just as meaningless.
    await client.walk(0, 2, ["dir"]);
    expect(await codeOfRejection(client.readdir(2, 3n))).toBe("EINVAL");
  });

  it("refuses a count with no room for a single entry", async () => {
    const { client } = await populated(1);
    expect(await codeOfRejection(client.readdir(1, 0n, 8))).toBe("EINVAL");
    // Zero entries *and* nothing left is the end of the directory, not an error.
    const all = await client.readdirAll(1);
    expect(await client.readdir(1, all.at(-1)!.offset, 8)).toEqual([]);
  });

  it("clamps the count to what the negotiated msize can carry", async () => {
    const { client } = await populated(200, { msize: P9_MIN_MSIZE });
    // The client asks for a megabyte; the reply still fits inside the 4 KiB the
    // two ends agreed on, and paging still terminates.
    expect((await client.readdir(1, 0n, 1024 * 1024)).length).toBeLessThan(202);
    expect(await client.readdirAll(1)).toHaveLength(202);
  });

  it("skips an entry that vanished between the snapshot and the page", async () => {
    const memory = createMemoryDriver();
    await memory.mkdir("/dir");
    await (await memory.open("/dir/real", "w")).close();
    const { client } = await serve({
      ...memory,
      async readdir(path, options) {
        const entries = await memory.readdir(path, options);
        return path === "/dir" ? [...entries, ghost("ghost")] : entries;
      },
    });
    await client.walk(0, 1, ["dir"]);
    expect((await client.readdirAll(1)).map((entry) => entry.name)).toEqual([".", "..", "real"]);
  });

  it("answers ENAMETOOLONG for a name the wire cannot express", async () => {
    const memory = createMemoryDriver();
    await memory.mkdir("/dir");
    const { client } = await serve({
      ...memory,
      async readdir(path, options) {
        const entries = await memory.readdir(path, options);
        return path === "/dir" ? [...entries, ghost("x".repeat(70_000))] : entries;
      },
      async lstat(path) {
        // The over-long name has to *stat* for the packer to be reached at all.
        return memory.lstat(path.length > 1000 ? "/dir" : path);
      },
    });
    await client.walk(0, 1, ["dir"]);
    expect(await codeOfRejection(client.readdir(1, 0n))).toBe("ENAMETOOLONG");
  });

  it("refuses a fid opened as a file, and one naming something that is not a directory", async () => {
    const { client, session, fs } = await serve();
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    expect(await codeOfRejection(client.readdir(1, 0n))).toBe("ENOTDIR");
    session.fids.require(1).open = { flags: 0, handle: undefined, directory: false };
    expect(await codeOfRejection(client.readdir(1, 0n))).toBe("ENOTDIR");
  });
});

describe("Tflush", () => {
  it("answers immediately for a tag that is not in flight", async () => {
    const { client, session } = await serve();
    await client.flush(1234);
    expect(session.stats.flushed).toBe(0);
  });

  it("waits for the request it names, which still gets its own reply first", async () => {
    const gate = gated();
    const { client } = await serve(gate.driver);
    gate.block();

    const order: string[] = [];
    const tag = client.nextTag();
    const slow = client
      .send(P9_TGETATTR, tag, (writer) => writeTgetattr(writer, { fid: 0, requestMask: 0n }))
      .then(() => order.push("reply"));
    const flushed = client.flush(tag).then(() => order.push("flush"));

    // Neither has finished: the flush is parked on the request it named.
    await Promise.resolve();
    expect(order).toEqual([]);
    gate.release();
    await Promise.all([slow, flushed]);
    expect(order).toEqual(["reply", "flush"]);
  });

  it("never blocks on another Tflush, so a flush of a flush cannot deadlock", async () => {
    const { client, session } = await serve();
    // A `Tflush` is never registered as in-flight, so this one is answered as
    // an unknown oldtag rather than waiting for itself.
    const tag = client.nextTag();
    await client.flush(tag, { tag });
    expect(session.stats.flushed).toBe(0);
    expect(session.inflight).toBe(0);
  });

  it("counts the flushes that actually waited", async () => {
    const gate = gated();
    const { client, session } = await serve(gate.driver);
    gate.block();
    const tag = client.nextTag();
    const slow = client.send(P9_TGETATTR, tag, (writer) =>
      writeTgetattr(writer, { fid: 0, requestMask: 0n }),
    );
    const flushed = client.flush(tag);
    gate.release();
    await Promise.all([slow, flushed]);
    expect(session.stats.flushed).toBe(1);
  });
});

describe("errno discipline", () => {
  it("answers ENOTSUP for a message it does not implement, legacy or unknown", async () => {
    const { client } = await serve();
    expect(await client.expectError(P9_TOPEN, (writer) => writer.u32(0).u8(0))).toBe(
      ERRNO_CODES.ENOTSUP,
    );
    expect(await client.expectError(200, (writer) => writer.u32(0))).toBe(ERRNO_CODES.ENOTSUP);
  });

  it("puts the driver's own errno on the wire, unmapped", async () => {
    const memory = createMemoryDriver();
    const { client } = await serve({
      ...memory,
      async lstat(path) {
        if (path === "/denied") {
          throw Object.assign(new Error("EACCES: permission denied"), {
            code: "EACCES",
            errno: -13,
          });
        }
        return memory.lstat(path);
      },
    });
    expect(await codeOfRejection(client.walk(0, 1, ["denied"]))).toBe("EACCES");
  });

  it("answers EIO for an error with no errno to read", async () => {
    const memory = createMemoryDriver();
    const { client } = await serve({
      ...memory,
      async lstat(path) {
        if (path === "/boom") {
          throw new Error("something went wrong");
        }
        return memory.lstat(path);
      },
    });
    expect(await codeOfRejection(client.walk(0, 1, ["boom"]))).toBe("EIO");
  });

  it("answers EINVAL for a body it cannot decode", async () => {
    const { client } = await serve();
    // `Tgetattr` is `fid[4] request_mask[8]`; this one stops after the fid.
    expect(await client.expectError(P9_TGETATTR, (writer) => writer.u32(0))).toBe(
      ERRNO_CODES.EINVAL,
    );
    // Trailing bytes are just as malformed as missing ones.
    expect(
      await client.expectError(P9_TGETATTR, (writer) => {
        writer.u32(0).u64(0n).u8(9);
      }),
    ).toBe(ERRNO_CODES.EINVAL);
  });

  it("drops a frame it cannot address a reply to", async () => {
    const { session } = await serve();
    expect(await session.handleCall(new Uint8Array([1, 2, 3]))).toBeNull();
    // A `size` that disagrees with the bytes delivered: the stream is already
    // desynchronized, and a reply would only move the confusion.
    const frame = encodeMessage(P9_TVERSION, P9_NOTAG, (writer) =>
      writeTversion(writer, { msize: 8192, version: P9_VERSION_DOTL }),
    );
    frame[0] = 0xff;
    expect(await session.handleCall(frame)).toBeNull();
    expect(session.stats.dropped).toBe(2);
  });

  it("refuses a tag that is already in flight, and says so exactly once", async () => {
    const gate = gated();
    const { client, session } = await serve(gate.driver);
    gate.block();
    const tag = client.nextTag();
    const encode = (writer: P9Writer): void => writeTgetattr(writer, { fid: 0, requestMask: 0n });
    const first = client.send(P9_TGETATTR, tag, encode);
    const second = client.send(P9_TGETATTR, tag, encode);
    expect((await second).type).toBe(P9_RLERROR);
    gate.release();
    expect((await first).type).toBe(P9_RGETATTR);
    expect(session.assertions).toEqual([`tag ${tag} is already in flight (Tgetattr)`]);
    session.assertions.length = 0;
  });

  it("still refuses the duplicate with the assertions turned off", async () => {
    const gate = gated();
    const { client, session } = await serve(gate.driver, { debug: false });
    gate.block();
    const tag = client.nextTag();
    const encode = (writer: P9Writer): void => writeTgetattr(writer, { fid: 0, requestMask: 0n });
    const first = client.send(P9_TGETATTR, tag, encode);
    expect((await client.send(P9_TGETATTR, tag, encode)).type).toBe(P9_RLERROR);
    gate.release();
    await first;
    expect(session.assertions).toEqual([]);
  });

  it("never puts a NaN on the wire", async () => {
    const memory = createMemoryDriver();
    const { client } = await serve({
      ...memory,
      async lstat(path) {
        return {
          ...(await memory.lstat(path)),
          size: Number.NaN,
          nlink: Number.NaN,
          atimeMs: Number.NaN,
          birthtimeMs: Number.POSITIVE_INFINITY,
        };
      },
    });
    const attr = await client.getattr(0);
    expect(attr.size).toBe(0n);
    expect(attr.nlink).toBe(0n);
    expect(attr.atime).toEqual({ sec: 0n, nsec: 0n });
    // An infinite birth time is no birth time: the bit and the fields agree.
    expect(attr.btime).toEqual({ sec: 0n, nsec: 0n });
    expect(attr.valid & P9_GETATTR_BTIME).toBe(0n);
  });

  it("answers ENODEV once the session has been torn down", async () => {
    const { client, session } = await serve();
    expect(session.destroyed).toBe(false);
    await session.destroy();
    expect(session.destroyed).toBe(true);
    expect(await codeOfRejection(client.getattr(0))).toBe("ENODEV");
    // Idempotent.
    await session.destroy();
  });

  it("answers ENODEV for a request that was already parked when destroy() ran", async () => {
    const gate = gated();
    const { client, session } = await serve(gate.driver);
    gate.block();
    const tag = client.nextTag();
    const parked = client.send(P9_TGETATTR, tag, (writer) =>
      writeTgetattr(writer, { fid: 0, requestMask: 0n }),
    );
    await session.destroy();
    gate.release();
    const reply = await parked;
    expect(reply.type).toBe(P9_RLERROR);
    expect(readRlerror(reply.body).ecode).toBe(ERRNO_CODES.ENODEV);
  });

  it("aborts a request that a Tversion reset ran out from under it", async () => {
    const gate = gated();
    const { client, session } = await serve(gate.driver);
    gate.block();
    const tag = client.nextTag();
    const parked = client.send(P9_TGETATTR, tag, (writer) =>
      writeTgetattr(writer, { fid: 0, requestMask: 0n }),
    );
    // The version exchange "aborts all outstanding I/O and clunks all fids",
    // and this request resolved a fid that no longer exists.
    await client.version();
    expect(session.generation).toBe(2);
    gate.release();
    const reply = await parked;
    expect(reply.type).toBe(P9_RLERROR);
    expect(readRlerror(reply.body).ecode).toBe(ERRNO_CODES.EIO);
    // The discarded reply was never counted as one.
    expect(session.stats.replies).toBe(session.stats.requests);
  });

  it("never answers a readdir that was parked across a reset, whatever its size", async () => {
    const gate = gated();
    const { client, session, fs } = await serve(gate.driver);
    await fs.mkdir("/dir");
    for (let index = 0; index < 40; index++) {
      await fs.writeFile(`/dir/f${index}`, "x");
    }
    await client.walk(0, 1, ["dir"]);

    gate.block();
    const tag = client.nextTag();
    const parked = client.send(P9_TREADDIR, tag, (writer) =>
      writeTreaddir(writer, { fid: 1, offset: 0n, count: 100 }),
    );
    await session.destroy();
    gate.release();
    const reply = await parked;
    // Not a 40-entry `Rreaddir` sized against an msize that no longer exists —
    // an over-msize frame is what `p9_conn_cancel()` kills the connection for.
    expect(reply.type).toBe(P9_RLERROR);
    expect(readRlerror(reply.body).ecode).toBe(ERRNO_CODES.ENODEV);
  });

  it("replies exactly once per request, counted", async () => {
    const { client, session } = await serve();
    await client.walk(0, 1, []);
    await client.getattr(1);
    await client.clunk(1);
    await client.flush(99);
    expect(session.stats.replies).toBe(session.stats.requests);
    expect(session.stats.errors).toBe(0);
    expect(session.stats.messages.get("Twalk")).toBe(1);
    expect(session.inflight).toBe(0);
  });
});
