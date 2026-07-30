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
  P9_DOTL_AT_REMOVEDIR,
  P9_GETATTR_ALL,
  P9_GETATTR_BASIC,
  P9_GETATTR_BTIME,
  P9_GETATTR_MODE,
  P9_GETATTR_SIZE,
  P9_IOHDRSZ,
  P9_LOCK_SUCCESS,
  P9_LOCK_TYPE_UNLCK,
  P9_LOCK_TYPE_WRLCK,
  P9_MAXWELEM,
  P9_MIN_MSIZE,
  P9_NOFID,
  P9_NOTAG,
  P9_QTDIR,
  P9_QTFILE,
  P9_QTSYMLINK,
  P9_RGETATTR,
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
  P9_TAUTH,
  P9_TCREATE,
  P9_TGETATTR,
  P9_TLOPEN,
  P9_TOPEN,
  P9_TREADDIR,
  P9_TSTAT,
  P9_TVERSION,
  P9_TWALK,
  P9_TWRITE,
  P9_TWSTAT,
  P9_TXATTRCREATE,
  P9_TXATTRWALK,
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
  writeTlopen,
  writeTwrite,
  writeTxattrcreate,
  writeTxattrwalk,
} from "../../src/9p/protocol.ts";
import { DEFAULT_MSIZE, P9Session, type P9SessionOptions } from "../../src/9p/session.ts";
import type { P9Writer } from "../../src/9p/wire.ts";
import { O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY } from "../../src/fuse/constants.ts";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { ERRNO_CODES, fsError } from "../../src/errors.ts";
import { createLoopback, type Loopback } from "../../src/harness.ts";
import {
  S_IFCHR,
  S_IFLNK,
  S_IFMT,
  S_IFREG,
  type DirentLike,
  type FileHandleLike,
  type FsDriver,
} from "../../src/types.ts";
import { withoutExtensions } from "../no-extensions.ts";
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

/**
 * The same memory driver, declaring no per-open state.
 *
 * Every read, write and fsync then re-opens from the path, which is the model
 * `handles: false` drivers get and the one that has to survive a rename and
 * must never repeat the creation flags. Same underlying store, so `fs` in the
 * harness still sees what the session wrote.
 */
function pathOnly(): FsDriver {
  const base = createMemoryDriver();
  return { ...base, capabilities: { ...base.capabilities, handles: false } };
}

/**
 * A memory driver whose open handles refuse to `stat()`.
 *
 * `FileHandleLike.stat` is not optional, so "no `fstat`" can only ever be a
 * driver that has one and answers `ENOSYS` — which is the case the fallback in
 * `#getattr` has to tell apart from a handle that failed for a real reason.
 */
function handleStatFails(error: unknown): FsDriver {
  const memory = createMemoryDriver();
  return {
    ...memory,
    async open(path, flags, mode): Promise<FileHandleLike> {
      const handle = await memory.open!(path, flags, mode);
      return {
        read: (buffer, offset, length, position) => handle.read(buffer, offset, length, position),
        write: (buffer, offset, length, position) => handle.write(buffer, offset, length, position),
        stat: () => Promise.reject(error),
        truncate: (length) => handle.truncate(length),
        close: () => handle.close(),
      };
    },
  };
}

/** The two open models every I/O test runs against. */
const columns: [string, () => FsDriver][] = [
  ["handles", () => createMemoryDriver()],
  ["no handles", pathOnly],
];

const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);
const encode = (text: string): Uint8Array => new TextEncoder().encode(text);

/** A driver whose handles record every flush, and can be built without any. */
function flushing(options: { handles?: boolean; flushable?: boolean } = {}): {
  driver: FsDriver;
  calls: string[];
} {
  const memory = createMemoryDriver();
  const calls: string[] = [];
  return {
    calls,
    driver: {
      ...memory,
      capabilities: { ...memory.capabilities, handles: options.handles ?? true },
      async open(path, flags, mode) {
        const handle = await memory.open(path, flags, mode);
        return options.flushable === false
          ? { ...handle, sync: undefined, datasync: undefined }
          : {
              ...handle,
              async sync() {
                calls.push("sync");
              },
              async datasync() {
                calls.push("datasync");
              },
            };
      },
    },
  };
}

/** A driver whose handle `write` parks on a gate once the test opens it. */
function gatedWrite(): { driver: FsDriver; block: () => void; release: () => void } {
  const memory = createMemoryDriver();
  let gate: Promise<void> | undefined;
  let open!: () => void;
  return {
    driver: {
      ...memory,
      async open(path, flags, mode) {
        const handle = await memory.open(path, flags, mode);
        const write: FileHandleLike["write"] = async (buffer, offset, length, position) => {
          if (gate !== undefined) {
            await gate;
          }
          return handle.write(buffer, offset, length, position);
        };
        return { ...handle, write };
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

  /**
   * `Tgetattr` is `fstat`, and a fid outlives the name it was opened from.
   *
   * Found by the conformance column: the suite's "keeps an open handle readable
   * after unlink" case reads fine through the fid — `Tread` uses the handle —
   * and then asks for the size, which a path-based stat cannot answer because
   * the path is gone. Answering it through the handle is what makes 9P's
   * stateful opens worth the `["fuse", "9p", "nfs"]` preference order.
   */
  it("falls back to the fid's handle, so an unlinked open file still answers", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/doomed", "still here");
    await client.walk(0, 1, ["doomed"]);
    // A second fid on the same file, deliberately left unopened: it has only
    // the path, and the path is what the removal takes away.
    await client.walk(0, 2, ["doomed"]);
    await client.lopen(1, O_RDONLY);
    await client.unlinkat(0, "doomed", 0);

    await expect(fs.stat("/doomed")).rejects.toMatchObject({ code: "ENOENT" });
    expect(decode(await client.read(1, 0n))).toBe("still here");
    expect((await client.getattr(1)).size).toBe(10n);
    expect(await codeOfRejection(client.getattr(2))).toBe("ENOENT");
  });

  /**
   * The fallback answers with the identity the open pinned, and binds nothing.
   *
   * Two ways to get this wrong, one for each `useDriverIno` mode, and both are
   * the same mistake: `qidFor` *writes* the path→identity map, so calling it
   * with the open file's attributes re-attaches an identity to a path that
   * `#released` has just detached. With the driver's `(dev, ino)` trusted, the
   * open fid's own `qid.path` churns under a client that derives `i_ino` from
   * it; without it, the next file created at that name inherits the dead one's
   * identity and the client serves the old file's cached pages for it.
   */
  for (const useDriverIno of [true, false]) {
    it(`keeps an unlinked open fid's identity to itself (useDriverIno: ${useDriverIno})`, async () => {
      const { client, fs } = await serve(createMemoryDriver(), { useDriverIno });
      await fs.writeFile("/doomed", "still here");
      const [before] = await client.walk(0, 1, ["doomed"]);
      await client.lopen(1, O_RDONLY);
      await client.unlinkat(0, "doomed", 0);

      const attr = await client.getattr(1);
      expect(attr.size).toBe(10n);
      expect(attr.qid.path).toBe(before!.path);

      // The name is free, so a file created at it is a different file — which
      // is what `FidTable.release` is for and what a re-bind would have undone.
      await fs.writeFile("/doomed", "new");
      expect((await client.walk(0, 2, ["doomed"]))[0]!.path).not.toBe(before!.path);
      // And none of it moved the open fid.
      expect((await client.getattr(1)).qid.path).toBe(before!.path);
    });
  }

  /**
   * A `Tlopen` on a symlink opens its **target** — only a directory is special
   * cased — so the handle is a handle on a different file than the fid names.
   * Answering the fid from it would report the target's mode and bind the
   * link's path to the target's identity: one `qid.path`, two files, which
   * `fids.ts` calls the worse half of getting identity wrong.
   */
  it("answers a fid on a symlink from the link, not from what the open followed", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/target", "payload");
    await fs.symlink("target", "/link");
    const [link] = await client.walk(0, 1, ["link"]);
    const [target] = await client.walk(0, 2, ["target"]);
    expect(link!.type).toBe(P9_QTSYMLINK);
    expect(link!.path).not.toBe(target!.path);

    await client.lopen(1, O_RDONLY);
    const attr = await client.getattr(1);
    expect(attr.mode & S_IFMT).toBe(S_IFLNK);
    expect(attr.size).toBe(6n);
    expect(attr.qid.path).toBe(link!.path);

    // And the map still says the two are different files, in both directions.
    const [again] = await client.walk(0, 3, ["link"]);
    expect(again!.path).toBe(link!.path);
    expect(again!.type).toBe(P9_QTSYMLINK);
    expect((await client.getattr(2)).qid.path).toBe(target!.path);
  });

  it("re-resolves the path for a fid with no handle to stat", async () => {
    // A `handles: false` driver keeps nothing per open, so the path is the only
    // answer there is — and a directory fid never opened a handle at all.
    const { client, fs } = await serve(pathOnly());
    await fs.writeFile("/file", "hello");
    await client.walk(0, 1, ["file"]);
    await client.lopen(1, O_RDONLY);
    expect((await client.getattr(1)).size).toBe(5n);
    await client.walk(0, 2, []);
    expect((await client.getattr(2)).mode & S_IFMT).toBe(0o40_000);
  });

  it("reports the path's own error when the handle cannot stat either", async () => {
    // `ENOSYS` is a driver with no `fstat` to offer, so the answer is the one
    // the path gave: the file really is gone.
    const { client, fs } = await serve(handleStatFails(fsError("ENOSYS", { syscall: "fstat" })));
    await fs.writeFile("/doomed", "x");
    await client.walk(0, 1, ["doomed"]);
    await client.lopen(1, O_RDONLY);
    await client.unlinkat(0, "doomed", 0);
    expect(await codeOfRejection(client.getattr(1))).toBe("ENOENT");
  });

  it("reports the handle's own error when it has one", async () => {
    // Anything else is this fid's real answer and goes out as itself, rather
    // than being flattened into the path's `ENOENT`.
    const { client, fs } = await serve(handleStatFails(fsError("EACCES", { syscall: "fstat" })));
    await fs.writeFile("/doomed", "x");
    await client.walk(0, 1, ["doomed"]);
    await client.lopen(1, O_RDONLY);
    await client.unlinkat(0, "doomed", 0);
    expect(await codeOfRejection(client.getattr(1))).toBe("EACCES");
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
    // A `Treaddir` needs an opened fid, exactly as `readdir(3)` needs an open
    // directory: `Tlopen` is what says the fid names one.
    await harness.client.lopen(1);
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
    await client.lopen(1);
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
    await client.lopen(2);
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
    await client.lopen(1);
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
    await client.lopen(1);
    expect(await codeOfRejection(client.readdir(1, 0n))).toBe("ENAMETOOLONG");
  });

  it("refuses an unopened fid, and one opened as a file", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    // Never opened: `EBADF`, the same answer `read(2)` gives for a descriptor
    // that is not one.
    expect(await codeOfRejection(client.readdir(1, 0n))).toBe("EBADF");
    await client.lopen(1);
    // Opened, but as a file — which is what `Tread` is for.
    expect(await codeOfRejection(client.readdir(1, 0n))).toBe("ENOTDIR");
    // A directory fid that was never opened is refused just as flatly.
    await fs.mkdir("/dir");
    await client.walk(0, 2, ["dir"]);
    expect(await codeOfRejection(client.readdir(2, 0n))).toBe("EBADF");
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
    await client.lopen(1);

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

describe("Tlopen", () => {
  it("opens a file and reports iounit 0, which means 'use the msize'", async () => {
    const { client, session, fs } = await serve();
    await fs.writeFile("/file", "hello");
    await client.walk(0, 1, ["file"]);
    const opened = await client.lopen(1, O_RDONLY);
    // `p9_client_open()` reads 0 as `msize - P9_IOHDRSZ`, which is the same
    // bound `Tread` computes, so there is nothing better to claim.
    expect(opened.iounit).toBe(0);
    expect(opened.qid.type).toBe(P9_QTFILE);
    expect(opened.qid.path).toBe((await client.getattr(1)).qid.path);
    expect(session.fids.require(1).open?.directory).toBe(false);
  });

  it("keeps the driver's handle only when the driver declares one", async () => {
    const kept = await serve();
    await kept.fs.writeFile("/file", "x");
    await kept.client.walk(0, 1, ["file"]);
    await kept.client.lopen(1, O_RDONLY);
    expect(kept.session.fids.require(1).open?.handle).toBeDefined();

    const none = await serve(pathOnly());
    await none.fs.writeFile("/file", "x");
    await none.client.walk(0, 1, ["file"]);
    await none.client.lopen(1, O_RDONLY);
    // Opened and closed again: the open is what reports ENOENT and EACCES, and
    // there is no per-open state worth keeping.
    expect(none.session.fids.require(1).open?.handle).toBeUndefined();
    expect(none.session.fids.require(1).open?.flags).toBeDefined();
  });

  it("opens a directory without asking the driver to open anything", async () => {
    const memory = createMemoryDriver();
    let opens = 0;
    const { client, fs } = await serve({
      ...memory,
      async open(path, flags, mode) {
        opens++;
        return memory.open(path, flags, mode);
      },
    });
    await fs.mkdir("/dir");
    await client.walk(0, 1, ["dir"]);
    const opened = await client.lopen(1, O_RDONLY);
    expect(opened.qid.type).toBe(P9_QTDIR);
    expect(opens).toBe(0);
    // And the fid is now readable as a directory.
    expect((await client.readdirAll(1)).map((entry) => entry.name)).toEqual([".", ".."]);
  });

  it("refuses a write-mode open of a directory with EISDIR", async () => {
    const { client, fs } = await serve();
    await fs.mkdir("/dir");
    await client.walk(0, 1, ["dir"]);
    expect(await codeOfRejection(client.lopen(1, O_WRONLY))).toBe("EISDIR");
    expect(await codeOfRejection(client.lopen(1, O_RDWR))).toBe("EISDIR");
    await client.lopen(1, O_RDONLY);
  });

  it("refuses a second open of the same fid", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    await client.lopen(1, O_RDONLY);
    expect(await codeOfRejection(client.lopen(1, O_RDONLY))).toBe("EINVAL");
    // And an open fid still cannot be walked.
    expect(await codeOfRejection(client.walk(1, 2, []))).toBe("EINVAL");
  });

  it("applies O_TRUNC on the way in, once", async () => {
    for (const [, make] of columns) {
      const { client, fs } = await serve(make());
      await fs.writeFile("/file", "hello");
      await client.walk(0, 1, ["file"]);
      await client.lopen(1, O_RDWR | O_TRUNC);
      expect((await client.getattr(1)).size).toBe(0n);
      expect(await client.write(1, 0n, "hi")).toBe(2);
      // The truncation is *not* repeated by the re-open a `handles: false`
      // driver does per operation — that is what `reopenFlags()` is for.
      expect(decode(await fs.readFile("/file"))).toBe("hi");
    }
  });

  it("refuses a write-mode open on a read-only session", async () => {
    const { client, fs } = await serve(createMemoryDriver(), { readOnly: true });
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    expect(await codeOfRejection(client.lopen(1, O_WRONLY))).toBe("EROFS");
    expect(await codeOfRejection(client.lopen(1, O_RDWR))).toBe("EROFS");
    expect(await codeOfRejection(client.lopen(1, O_RDONLY | O_TRUNC))).toBe("EROFS");
    expect(await codeOfRejection(client.lopen(1, O_RDONLY | O_CREAT))).toBe("EROFS");
    // Reading is still allowed, and the refusals left the fid unopened.
    await client.lopen(1, O_RDONLY);
    expect(decode(await client.read(1, 0n))).toBe("x");
  });

  it("refuses a fid it has never issued", async () => {
    const { client } = await serve();
    expect(await codeOfRejection(client.lopen(7, O_RDONLY))).toBe("EBADF");
  });
});

describe("Tlcreate", () => {
  it("creates the file and leaves the fid naming it, open", async () => {
    for (const [, make] of columns) {
      const { client, session, fs } = await serve(make());
      await client.walk(0, 1, []);
      const created = await client.lcreate(1, "new", { flags: O_RDWR, mode: 0o640 });
      expect(created.qid.type).toBe(P9_QTFILE);
      expect(created.iounit).toBe(0);
      // The parent's fid is spent: it names the child now, which is why v9fs
      // always clones a fid before creating.
      expect(session.fids.require(1).path).toBe("/new");
      expect(await client.write(1, 0n, "hi")).toBe(2);
      expect(decode(await fs.readFile("/new"))).toBe("hi");
      expect((await client.getattr(1)).mode & 0o777).toBe(0o640);
    }
  });

  it("passes O_EXCL through, and a failed create leaves the fid alone", async () => {
    const { client, session, fs } = await serve();
    await fs.writeFile("/exists", "x");
    await client.walk(0, 1, []);
    expect(await codeOfRejection(client.lcreate(1, "exists", { flags: O_RDWR | O_EXCL }))).toBe(
      "EEXIST",
    );
    // Still the directory, still unopened — so it can go on being a parent.
    expect(session.fids.require(1).path).toBe("/");
    expect(session.fids.require(1).open).toBeUndefined();
    await client.lcreate(1, "other", { flags: O_RDWR });
    expect(session.fids.require(1).path).toBe("/other");
  });

  it("creates over an existing file without O_EXCL, keeping its identity", async () => {
    const { client, fs } = await serve(createMemoryDriver(), { useDriverIno: false });
    await fs.writeFile("/file", "hello");
    await client.walk(0, 1, ["file"]);
    const before = (await client.getattr(1)).qid.path;
    await client.clunk(1);

    await client.walk(0, 2, []);
    await client.lcreate(2, "file", { flags: O_RDWR });
    // `O_CREAT` over something that exists replaces nothing, so the file the
    // client is caching against is the same file.
    expect((await client.getattr(2)).qid.path).toBe(before);
    expect(decode(await fs.readFile("/file"))).toBe("hello");
  });

  it("gives the new file to the attaching user and the request's group", async () => {
    const { client } = raw();
    await client.version();
    await client.attach(0, { nUname: 4242 });
    await client.walk(0, 1, []);
    await client.lcreate(1, "owned", { gid: 77 });
    const attr = await client.getattr(1);
    expect(attr.uid).toBe(4242);
    expect(attr.gid).toBe(77);
  });

  it("claims nothing when the client sent no uid and no gid", async () => {
    const { client } = raw();
    await client.version();
    // `(uid_t)-1` is what an `access=<uname>` mount sends: a sentinel, not a uid.
    await client.attach(0, { uname: "someone", nUname: 0xff_ff_ff_ff });
    await client.walk(0, 1, []);
    await client.lcreate(1, "unclaimed", { gid: 0xff_ff_ff_ff });
    expect((await client.getattr(1)).uid).not.toBe(0xff_ff_ff_ff);
  });

  it("does not claim at all with claimOwnership off", async () => {
    const { client } = raw(createMemoryDriver(), { claimOwnership: false });
    await client.version();
    await client.attach(0, { nUname: 4242 });
    await client.walk(0, 1, []);
    await client.lcreate(1, "owned", { gid: 77 });
    const attr = await client.getattr(1);
    expect(attr.uid).not.toBe(4242);
    expect(attr.gid).not.toBe(77);
  });

  it("survives a driver with no lchown at all", async () => {
    const memory = createMemoryDriver();
    const { lchown: _lchown, chown: _chown, ...rest } = memory;
    const { client } = raw(rest as FsDriver);
    await client.version();
    await client.attach(0, { nUname: 4242 });
    await client.walk(0, 1, []);
    // ENOSYS from the harness is tolerated: a driver with no concept of
    // ownership is not thereby broken.
    await client.lcreate(1, "owned", { gid: 77 });
    expect((await client.getattr(1)).uid).not.toBe(4242);
  });

  it("refuses a name that is not one", async () => {
    const { client } = await serve();
    await client.walk(0, 1, []);
    expect(await codeOfRejection(client.lcreate(1, "."))).toBe("EINVAL");
    expect(await codeOfRejection(client.lcreate(1, ".."))).toBe("EINVAL");
    expect(await codeOfRejection(client.lcreate(1, "a/b"))).toBe("EINVAL");
    expect(await codeOfRejection(client.lcreate(1, ""))).toBe("EINVAL");
    expect(await codeOfRejection(client.lcreate(1, "x".repeat(256)))).toBe("ENAMETOOLONG");
  });

  it("refuses an open fid, and a read-only session", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    await client.lopen(1, O_RDONLY);
    expect(await codeOfRejection(client.lcreate(1, "child"))).toBe("EINVAL");

    const ro = await serve(createMemoryDriver(), { readOnly: true });
    await ro.client.walk(0, 1, []);
    expect(await codeOfRejection(ro.client.lcreate(1, "nope"))).toBe("EROFS");
  });
});

for (const [label, make] of columns) {
  describe(`Tread and Twrite (${label})`, () => {
    /** `/file` holding `hello world`, opened read-write on fid 1. */
    async function opened(options: P9SessionOptions = {}): Promise<Harness> {
      const harness = await serve(make(), options);
      await harness.fs.writeFile("/file", "hello world");
      await harness.client.walk(0, 1, ["file"]);
      await harness.client.lopen(1, O_RDWR);
      return harness;
    }

    it("reads and writes at an offset", async () => {
      const { client, fs } = await opened();
      expect(decode(await client.read(1, 0n))).toBe("hello world");
      expect(decode(await client.read(1, 6n))).toBe("world");
      expect(await client.write(1, 6n, "WORLD")).toBe(5);
      expect(decode(await fs.readFile("/file"))).toBe("hello WORLD");
      // Writing past the end extends the file, as a positional write does.
      expect(await client.write(1, 13n, "!")).toBe(1);
      expect((await client.getattr(1)).size).toBe(14n);
    });

    it("reads short at the end and nothing past it, and zero of nothing", async () => {
      const { client } = await opened();
      expect(decode(await client.read(1, 8n, 100))).toBe("rld");
      expect(await client.read(1, 11n)).toHaveLength(0);
      expect(await client.read(1, 99n)).toHaveLength(0);
      // A zero-length read and a zero-length write are both legal.
      expect(await client.read(1, 0n, 0)).toHaveLength(0);
      expect(await client.write(1, 0n, new Uint8Array(0))).toBe(0);
    });

    it("clamps a read to what the negotiated msize can frame", async () => {
      const harness = await serve(make(), { msize: P9_MIN_MSIZE });
      await harness.fs.writeFile("/big", "x".repeat(10_000));
      await harness.client.walk(0, 1, ["big"]);
      await harness.client.lopen(1, O_RDONLY);
      const page = await harness.client.read(1, 0n, 1024 * 1024);
      expect(page).toHaveLength(P9_MIN_MSIZE - P9_IOHDRSZ);
      // Whole file, paged.
      expect(await harness.client.readAll(1, 1024 * 1024)).toHaveLength(10_000);
    });

    it("refuses a directory fid, an unopened fid and an impossible offset", async () => {
      const { client, fs } = await opened();
      await fs.mkdir("/dir");
      await client.walk(0, 2, ["dir"]);
      await client.lopen(2, O_RDONLY);
      expect(await codeOfRejection(client.read(2, 0n))).toBe("EISDIR");
      expect(await codeOfRejection(client.write(2, 0n, "x"))).toBe("EISDIR");

      await client.walk(0, 3, ["file"]);
      expect(await codeOfRejection(client.read(3, 0n))).toBe("EBADF");
      expect(await codeOfRejection(client.write(3, 0n, "x"))).toBe("EBADF");

      // A u64 offset a JS integer cannot hold exactly.
      expect(await codeOfRejection(client.read(1, 2n ** 60n))).toBe("EINVAL");
      expect(await codeOfRejection(client.write(1, 2n ** 60n, "x"))).toBe("EINVAL");
    });

    it("never repeats the creation flags on a re-open", async () => {
      const { client, fs } = await serve(make());
      await client.walk(0, 1, []);
      await client.lcreate(1, "fresh", { flags: O_RDWR | O_EXCL | O_TRUNC });
      // With `O_EXCL` repeated this is `EEXIST`; with `O_TRUNC` repeated the
      // first write is thrown away. Both are `reopenFlags()`'s job.
      expect(await client.write(1, 0n, "hello")).toBe(5);
      expect(await client.write(1, 5n, " world")).toBe(6);
      expect(decode(await fs.readFile("/fresh"))).toBe("hello world");
      expect(decode(await client.readAll(1))).toBe("hello world");
    });
  });
}

describe("Tread and Twrite: the read-only session lets a read-only open through", () => {
  it("still refuses the write that follows", async () => {
    const { client, fs } = await serve(createMemoryDriver(), { readOnly: true });
    await fs.writeFile("/file", "hello");
    await client.walk(0, 1, ["file"]);
    await client.lopen(1, O_RDONLY);
    expect(await codeOfRejection(client.write(1, 0n, "x"))).toBe("EROFS");
  });
});

describe("Tfsync", () => {
  async function openedFile(driver: FsDriver): Promise<Harness> {
    const harness = await serve(driver);
    await harness.fs.writeFile("/file", "x");
    await harness.client.walk(0, 1, ["file"]);
    await harness.client.lopen(1, O_RDWR);
    return harness;
  }

  it("flushes data and metadata, or data alone with datasync", async () => {
    const { driver, calls } = flushing();
    const { client } = await openedFile(driver);
    await client.fsync(1, 0);
    expect(calls).toEqual(["sync"]);
    await client.fsync(1, 1);
    expect(calls).toEqual(["sync", "datasync"]);
  });

  it("flushes for a driver with no per-open state too, through a re-open", async () => {
    const { driver, calls } = flushing({ handles: false });
    const { client } = await openedFile(driver);
    await client.fsync(1, 0);
    // FUSE's choice, and the useful one: for a driver whose state is in the
    // file rather than the handle, an fsync on a fresh descriptor for the same
    // file is the same syscall on the same inode.
    expect(calls).toEqual(["sync"]);
  });

  it("falls back to sync when the driver has no datasync", async () => {
    const memory = createMemoryDriver();
    const calls: string[] = [];
    const { client } = await openedFile({
      ...memory,
      async open(path, flags, mode) {
        const handle = await memory.open(path, flags, mode);
        return {
          ...handle,
          datasync: undefined,
          async sync() {
            calls.push("sync");
          },
        };
      },
    });
    await client.fsync(1, 1);
    expect(calls).toEqual(["sync"]);
  });

  it("succeeds for a driver that can flush nothing at all", async () => {
    const { driver } = flushing({ flushable: false });
    const { client, session } = await openedFile(driver);
    await client.fsync(1, 0);
    await client.fsync(1, 1);
    expect(session.stats.errors).toBe(0);
  });

  it("is a success with no work on a directory fid, and EBADF on an unopened one", async () => {
    const { driver, calls } = flushing();
    const { client, fs } = await serve(driver);
    await fs.mkdir("/dir");
    await client.walk(0, 1, ["dir"]);
    await client.lopen(1, O_RDONLY);
    await client.fsync(1, 0);
    expect(calls).toEqual([]);

    await client.walk(0, 2, ["dir"]);
    expect(await codeOfRejection(client.fsync(2, 0))).toBe("EBADF");
  });
});

describe("Tsetattr", () => {
  /** `/file` holding `hello`, walked onto fid 1 and not opened. */
  async function file(options: P9SessionOptions = {}): Promise<Harness> {
    const harness = await serve(createMemoryDriver(), options);
    await harness.fs.writeFile("/file", "hello");
    await harness.client.walk(0, 1, ["file"]);
    return harness;
  }

  it("MODE chmods", async () => {
    const { client } = await file();
    await client.setattr(1, { valid: P9_SETATTR_MODE, mode: 0o604 });
    const attr = await client.getattr(1);
    expect(attr.mode & 0o7777).toBe(0o604);
    // The type bits are the file's, not the client's.
    expect(attr.mode & S_IFMT).toBe(S_IFREG);
  });

  it("UID and GID are read only when their own bits are set", async () => {
    const { client } = await file();
    await client.setattr(1, { valid: P9_SETATTR_UID, uid: 31, gid: 99 });
    expect((await client.getattr(1)).uid).toBe(31);
    // The gid was in the message but its bit was not: the mask does the saying,
    // and `(u32)-1` is not a convention on this wire.
    expect((await client.getattr(1)).gid).not.toBe(99);

    await client.setattr(1, { valid: P9_SETATTR_GID, gid: 99 });
    expect((await client.getattr(1)).gid).toBe(99);
    expect((await client.getattr(1)).uid).toBe(31);

    await client.setattr(1, { valid: P9_SETATTR_UID | P9_SETATTR_GID, uid: 5, gid: 6 });
    const both = await client.getattr(1);
    expect([both.uid, both.gid]).toEqual([5, 6]);
  });

  it("SIZE truncates, by path and through an open handle alike", async () => {
    for (const [, make] of columns) {
      const { client } = await serve(make());
      await client.walk(0, 1, []);
      await client.lcreate(1, "f", { flags: O_RDWR });
      await client.write(1, 0n, "hello world");
      await client.setattr(1, { valid: P9_SETATTR_SIZE, size: 5n });
      expect((await client.getattr(1)).size).toBe(5n);
      expect(decode(await client.readAll(1))).toBe("hello");
      // And growing it back is the same call.
      await client.setattr(1, { valid: P9_SETATTR_SIZE, size: 8n });
      expect((await client.getattr(1)).size).toBe(8n);
    }
  });

  it("a time bit without its _SET companion means 'now'", async () => {
    const { client } = await file();
    const before = BigInt(Math.floor(Date.now() / 1000));
    await client.setattr(1, {
      valid: P9_SETATTR_ATIME | P9_SETATTR_MTIME,
      // Values that would be visible if the server used them.
      atime: { sec: 5n, nsec: 0n },
      mtime: { sec: 5n, nsec: 0n },
    });
    const attr = await client.getattr(1);
    expect(attr.atime.sec).toBeGreaterThanOrEqual(before);
    expect(attr.mtime.sec).toBeGreaterThanOrEqual(before);
  });

  it("_SET uses the value in the message, to the nanosecond the driver keeps", async () => {
    const { client } = await file();
    await client.setattr(1, {
      valid: P9_SETATTR_ATIME | P9_SETATTR_ATIME_SET | P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET,
      atime: { sec: 1_000n, nsec: 500_000_000n },
      mtime: { sec: 2_000n, nsec: 250_000_000n },
    });
    const attr = await client.getattr(1);
    expect(attr.atime).toEqual({ sec: 1_000n, nsec: 500_000_000n });
    expect(attr.mtime).toEqual({ sec: 2_000n, nsec: 250_000_000n });
  });

  it("sets only the stamp it was asked for, reading the other back", async () => {
    const { client } = await file();
    await client.setattr(1, {
      valid: P9_SETATTR_ATIME | P9_SETATTR_ATIME_SET | P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET,
      atime: { sec: 1_000n, nsec: 0n },
      mtime: { sec: 2_000n, nsec: 0n },
    });
    await client.setattr(1, {
      valid: P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET,
      mtime: { sec: 3_000n, nsec: 0n },
    });
    const attr = await client.getattr(1);
    expect(attr.mtime.sec).toBe(3_000n);
    // `utimes` sets both at once, so the atime had to be read back first.
    expect(attr.atime.sec).toBe(1_000n);
  });

  it("applies the size before the times, so an explicit mtime wins", async () => {
    const { client } = await file();
    await client.setattr(1, {
      valid: P9_SETATTR_SIZE | P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET,
      size: 2n,
      mtime: { sec: 4_000n, nsec: 0n },
    });
    const attr = await client.getattr(1);
    expect(attr.size).toBe(2n);
    expect(attr.mtime.sec).toBe(4_000n);
  });

  it("accepts CTIME and does nothing with it", async () => {
    const { client } = await file();
    const before = await client.getattr(1);
    // The kernel sends this bit on nearly every setattr, and the message has no
    // ctime field to honour: refusing it would fail almost every chmod.
    await client.setattr(1, { valid: P9_SETATTR_CTIME });
    const after = await client.getattr(1);
    expect(after.mode).toBe(before.mode);
    expect(after.size).toBe(before.size);
    // Together with a bit that does something, the other bit still lands.
    await client.setattr(1, { valid: P9_SETATTR_CTIME | P9_SETATTR_MODE, mode: 0o600 });
    expect((await client.getattr(1)).mode & 0o777).toBe(0o600);
  });

  it("refuses everything on a read-only session, and an unknown fid always", async () => {
    const { client } = await file({ readOnly: true });
    expect(await codeOfRejection(client.setattr(1, { valid: P9_SETATTR_MODE, mode: 0o600 }))).toBe(
      "EROFS",
    );
    const writable = await file();
    expect(
      await codeOfRejection(writable.client.setattr(9, { valid: P9_SETATTR_MODE, mode: 0o600 })),
    ).toBe("EBADF");
  });
});

describe("Tmkdir, Tsymlink, Treadlink, Tlink and Tmknod", () => {
  it("mkdir: a directory qid and the mode asked for", async () => {
    const { client, fs } = await serve();
    const qid = await client.mkdir(0, "made", 0o751);
    expect(qid.type).toBe(P9_QTDIR);
    const stats = await fs.lstat("/made");
    expect(stats.mode & 0o777).toBe(0o751);
    await client.walk(0, 1, ["made"]);
    expect((await client.getattr(1)).qid.path).toBe(qid.path);
  });

  it("symlink and readlink round-trip a target nobody resolved", async () => {
    const { client } = await serve();
    const qid = await client.symlink(0, "link", "../elsewhere/target");
    expect(qid.type).toBe(P9_QTSYMLINK);
    await client.walk(0, 1, ["link"]);
    // Read back verbatim: relative, unnormalized, and not followed.
    expect(await client.readlink(1)).toBe("../elsewhere/target");
    expect((await client.getattr(1)).mode & S_IFMT).toBe(S_IFLNK);
  });

  it("readlink refuses something that is not a link", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    expect(await codeOfRejection(client.readlink(1))).toBe("EINVAL");
  });

  it("link: one file, two names, one identity", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "hello");
    await client.walk(0, 1, ["file"]);
    await client.link(0, 1, "other");
    await client.walk(0, 2, ["other"]);
    const [first, second] = [await client.getattr(1), await client.getattr(2)];
    expect(second.qid.path).toBe(first.qid.path);
    expect(second.nlink).toBe(2n);
    expect(decode(await fs.readFile("/other"))).toBe("hello");
  });

  it("mknod: a regular file through the fallback, ENOSYS for a device", async () => {
    // The fallback is for a driver with no extension; the memory driver has
    // one, and the case below covers that path.
    const { client, fs } = await serve(withoutExtensions(createMemoryDriver()));
    const qid = await client.mknod(0, "plain", { mode: S_IFREG | 0o600 });
    expect(qid.type).toBe(P9_QTFILE);
    expect((await fs.lstat("/plain")).mode & 0o777).toBe(0o600);
    // A device node is outside what `node:fs/promises` can express, and saying
    // so is the whole implementation.
    expect(
      await codeOfRejection(client.mknod(0, "dev", { mode: S_IFCHR | 0o600, major: 5, minor: 3 })),
    ).toBe("ENOSYS");
  });

  it("mknod: uses the mountx.mknod extension when the driver has one", async () => {
    const memory = createMemoryDriver();
    const made: { path: string; mode: number; dev: number }[] = [];
    const { client } = await serve({
      ...memory,
      mountx: {
        async mknod(path, mode, dev) {
          made.push({ path, mode, dev });
          await (await memory.open(path, "w")).close();
        },
      },
    });
    await client.mknod(0, "dev", { mode: S_IFCHR | 0o600, major: 5, minor: 3 });
    expect(made).toEqual([{ path: "/dev", mode: S_IFCHR | 0o600, dev: (5 << 8) | 3 }]);
  });

  it("claims ownership of every kind of thing it creates", async () => {
    const { client } = raw();
    await client.version();
    await client.attach(0, { nUname: 4242 });
    await client.mkdir(0, "dir", 0o755, 77);
    await client.symlink(0, "link", "target", 77);
    await client.mknod(0, "plain", { mode: S_IFREG | 0o600, gid: 77 });
    for (const [index, name] of ["dir", "link", "plain"].entries()) {
      await client.walk(0, index + 1, [name]);
      const attr = await client.getattr(index + 1);
      expect([name, attr.uid, attr.gid]).toEqual([name, 4242, 77]);
    }
  });

  it("refuses all of them on a read-only session", async () => {
    const { client, fs } = await serve(createMemoryDriver(), { readOnly: true });
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    expect(await codeOfRejection(client.mkdir(0, "dir"))).toBe("EROFS");
    expect(await codeOfRejection(client.symlink(0, "link", "target"))).toBe("EROFS");
    expect(await codeOfRejection(client.mknod(0, "node", { mode: S_IFREG }))).toBe("EROFS");
    expect(await codeOfRejection(client.link(0, 1, "other"))).toBe("EROFS");
    // Reading a link is not a mutation.
    await fs.symlink("target", "/link");
    await client.walk(0, 2, ["link"]);
    expect(await client.readlink(2)).toBe("target");
  });
});

describe("Trename, Trenameat, Tunlinkat and Tremove", () => {
  it("renames, and an open fid under the moved directory goes on reading", async () => {
    for (const [, make] of columns) {
      const { client, session, fs } = await serve(make());
      await fs.mkdir("/dir");
      await fs.writeFile("/dir/file", "hello");
      await client.walk(0, 1, ["dir", "file"]);
      await client.lopen(1, O_RDWR);
      await client.walk(0, 2, ["dir"]);

      await client.rename(2, 0, "moved");
      // The client goes on using the fids it holds, with no idea anything
      // moved — which is what `FidTable.remap` is for.
      expect(session.fids.require(1).path).toBe("/moved/file");
      expect(session.fids.require(2).path).toBe("/moved");
      expect(decode(await client.read(1, 0n))).toBe("hello");
      expect(await client.write(1, 5n, "!")).toBe(1);
      expect(decode(await fs.readFile("/moved/file"))).toBe("hello!");
    }
  });

  it("renameat moves between two directories", async () => {
    const { client, fs } = await serve();
    await fs.mkdir("/from");
    await fs.mkdir("/to");
    await fs.writeFile("/from/file", "x");
    await client.walk(0, 1, ["from"]);
    await client.walk(0, 2, ["to"]);
    await client.renameat(1, "file", 2, "renamed");
    expect(decode(await fs.readFile("/to/renamed"))).toBe("x");
    expect(await codeOfRejection(fs.lstat("/from/file"))).toBe("ENOENT");
  });

  it("drops the identity of a destination a rename replaced", async () => {
    const { client, session, fs } = await serve(createMemoryDriver(), { useDriverIno: false });
    await fs.writeFile("/a", "a");
    await fs.writeFile("/b", "b");
    await client.walk(0, 1, ["a"]);
    await client.walk(0, 2, ["b"]);
    const [aId, bId] = [(await client.getattr(1)).qid.path, (await client.getattr(2)).qid.path];
    expect(aId).not.toBe(bId);
    expect(session.fids.qidPathCount).toBe(3);

    await client.rename(1, 0, "b");
    // The fid that named `/a` names `/b` now and kept its identity, so the
    // client's dentry survives the move; the file that used to be at `/b` is
    // gone, and `remap` released the id it was cached under — released there
    // and not here, which is why `#renameTo` does not call `release` itself.
    expect((await client.getattr(1)).qid.path).toBe(aId);
    expect((await client.getattr(2)).qid.path).toBe(aId);
    expect(session.fids.qidPathCount).toBe(2);
  });

  it("unlinkat: a file without the flag, a directory with it", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "x");
    await fs.mkdir("/dir");
    await client.unlinkat(0, "file");
    await client.unlinkat(0, "dir", P9_DOTL_AT_REMOVEDIR);
    expect((await fs.readdir("/", { withFileTypes: true })).map((entry) => entry.name)).toEqual([]);
  });

  it("unlinkat refuses the wrong kind, and a read-only session", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "x");
    await fs.mkdir("/dir");
    expect(await codeOfRejection(client.unlinkat(0, "file", P9_DOTL_AT_REMOVEDIR))).toBe("ENOTDIR");
    expect(await codeOfRejection(client.unlinkat(0, "dir"))).not.toBe("no code");
    expect(await codeOfRejection(client.unlinkat(0, "missing"))).toBe("ENOENT");

    const ro = await serve(createMemoryDriver(), { readOnly: true });
    await ro.fs.writeFile("/file", "x");
    expect(await codeOfRejection(ro.client.unlinkat(0, "file"))).toBe("EROFS");
  });

  it("unlinkat does not clunk a fid on the file it removed", async () => {
    const { client, session, fs } = await serve();
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    await client.unlinkat(0, "file");
    // `Tremove` clunks; `Tunlinkat` does not — that is the difference between
    // the two messages.
    expect(session.fids.get(1)).toBeDefined();
    await client.clunk(1);
  });

  it("remove works out whether it is an unlink or an rmdir", async () => {
    const { client, session, fs } = await serve();
    await fs.writeFile("/file", "x");
    await fs.mkdir("/dir");
    await client.walk(0, 1, ["file"]);
    await client.walk(0, 2, ["dir"]);
    await client.remove(1);
    await client.remove(2);
    expect(session.fids.fids()).toEqual([0]);
    expect((await fs.readdir("/", { withFileTypes: true })).map((entry) => entry.name)).toEqual([]);
  });

  it("clunks the fid even when the removal fails", async () => {
    const { client, session, fs } = await serve();
    await fs.mkdir("/dir");
    await fs.writeFile("/dir/keep", "x");
    await client.walk(0, 1, ["dir"]);
    // `p9_client_remove()` destroys its side of the fid in the error path as
    // readily as in the successful one, so a server that kept it would be
    // holding a fid nothing will ever come to clunk.
    expect(await codeOfRejection(client.remove(1))).not.toBe("no code");
    expect(session.fids.get(1)).toBeUndefined();
    expect(await codeOfRejection(client.clunk(1))).toBe("EBADF");
    // The file is still there.
    expect(decode(await fs.readFile("/dir/keep"))).toBe("x");
  });

  it("clunks the fid on a read-only session too, and still refuses", async () => {
    const { client, session, fs } = await serve(createMemoryDriver(), { readOnly: true });
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    expect(await codeOfRejection(client.remove(1))).toBe("EROFS");
    expect(session.fids.get(1)).toBeUndefined();
  });

  it("closes what the removed fid had open", async () => {
    const memory = createMemoryDriver();
    let closed = 0;
    const { client, fs } = await serve({
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
    });
    await fs.writeFile("/file", "x");
    // The harness wrote through the same driver, so count from here.
    closed = 0;
    await client.walk(0, 1, ["file"]);
    await client.lopen(1, O_RDONLY);
    await client.remove(1);
    expect(closed).toBe(1);
  });

  it("gives a recreated path a fresh identity, after both removals", async () => {
    for (const remove of ["remove", "unlinkat"] as const) {
      // `useDriverIno: false` is the case that proves it: identity is then the
      // path alone, so without `FidTable.release` the new file would inherit
      // the dead one's `qid.path` and the client would serve its cached pages.
      const { client, session, fs } = await serve(createMemoryDriver(), { useDriverIno: false });
      await fs.writeFile("/file", "old");
      await client.walk(0, 1, ["file"]);
      const before = (await client.getattr(1)).qid.path;
      const held = session.fids.qidPathCount;

      if (remove === "remove") {
        await client.remove(1);
      } else {
        await client.unlinkat(0, "file");
        await client.clunk(1);
      }
      expect(session.fids.qidPathCount).toBe(held - 1);

      await fs.writeFile("/file", "new");
      await client.walk(0, 2, ["file"]);
      expect((await client.getattr(2)).qid.path).not.toBe(before);
    }
  });
});

describe("Txattrwalk, Txattrcreate, Tlock and Tgetlock", () => {
  it("refuses both xattr messages without decoding either", async () => {
    const { client, session } = await serve();
    expect(
      await client.expectError(P9_TXATTRWALK, (writer) =>
        writeTxattrwalk(writer, { fid: 0, newfid: 1, name: "security.capability" }),
      ),
    ).toBe(ERRNO_CODES.ENOTSUP);
    expect(
      await client.expectError(P9_TXATTRCREATE, (writer) =>
        writeTxattrcreate(writer, { fid: 0, name: "user.x", attrSize: 4n, flags: 0 }),
      ),
    ).toBe(ERRNO_CODES.ENOTSUP);
    // A body that is not one of those messages at all is refused just as fast:
    // the answer never looks, which is what keeps this hot path cheap.
    expect(await client.expectError(P9_TXATTRWALK)).toBe(ERRNO_CODES.ENOTSUP);
    // And no fid was bound on the way past.
    expect(session.fids.get(1)).toBeUndefined();
  });

  it("grants every lock and reports nothing locked", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    await client.lopen(1, O_RDWR);
    expect(await client.lock(1, { type: P9_LOCK_TYPE_WRLCK })).toBe(P9_LOCK_SUCCESS);
    expect(await client.lock(1, { type: P9_LOCK_TYPE_UNLCK })).toBe(P9_LOCK_SUCCESS);
    // The client kernel does the POSIX-lock bookkeeping for its own processes;
    // there is no second client for this reply to protect anything from.
    expect(
      await client.getlock(1, { start: 4n, length: 16n, procId: 99, clientId: "somebody" }),
    ).toEqual({
      type: P9_LOCK_TYPE_UNLCK,
      start: 4n,
      length: 16n,
      procId: 99,
      clientId: "somebody",
    });
  });

  it("still refuses a fid it never issued", async () => {
    const { client } = await serve();
    expect(await codeOfRejection(client.lock(9))).toBe("EBADF");
    expect(await codeOfRejection(client.getlock(9))).toBe("EBADF");
  });

  it("refuses the four legacy 9P2000 opcodes forever", async () => {
    const { client } = await serve();
    for (const type of [P9_TOPEN, P9_TCREATE, P9_TSTAT, P9_TWSTAT]) {
      expect(await client.expectError(type, (writer) => writer.u32(0))).toBe(ERRNO_CODES.ENOTSUP);
    }
  });
});

describe("Tflush over I/O", () => {
  it("settles a flush of an in-flight Twrite, and the write still lands first", async () => {
    const gate = gatedWrite();
    const { client, fs } = await serve(gate.driver);
    await client.walk(0, 1, []);
    await client.lcreate(1, "file", { flags: O_RDWR });
    gate.block();

    const order: string[] = [];
    const tag = client.nextTag();
    const slow = client
      .send(
        P9_TWRITE,
        tag,
        (writer) => writeTwrite(writer, { fid: 1, offset: 0n, data: encode("hello") }),
        64,
      )
      .then(() => order.push("reply"));
    const flushed = client.flush(tag).then(() => order.push("flush"));

    await Promise.resolve();
    expect(order).toEqual([]);
    gate.release();
    await Promise.all([slow, flushed]);
    // The flushed request runs to completion and answers first: the client
    // frees `oldtag` the moment `Rflush` arrives, so a reply after it would be
    // addressed to a tag that has been reused.
    expect(order).toEqual(["reply", "flush"]);
    expect(decode(await fs.readFile("/file"))).toBe("hello");
  });
});

describe("the parts that only go wrong under a driver that misbehaves", () => {
  it("falls back to chown and utimes for a driver with no l* variants", async () => {
    const memory = createMemoryDriver();
    const { lchown: _lchown, lutimes: _lutimes, ...rest } = memory;
    const { client } = await serve(rest as FsDriver);
    await client.walk(0, 1, []);
    await client.lcreate(1, "file", { flags: O_RDWR });
    await client.setattr(1, { valid: P9_SETATTR_UID | P9_SETATTR_GID, uid: 12, gid: 34 });
    await client.setattr(1, {
      valid: P9_SETATTR_ATIME | P9_SETATTR_ATIME_SET | P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET,
      atime: { sec: 11n, nsec: 0n },
      mtime: { sec: 22n, nsec: 0n },
    });
    const attr = await client.getattr(1);
    expect([attr.uid, attr.gid]).toEqual([12, 34]);
    expect([attr.atime.sec, attr.mtime.sec]).toEqual([11n, 22n]);
  });

  it("prefers mountx.utimens, which is the only way nanoseconds survive", async () => {
    const memory = createMemoryDriver();
    const stamped: { path: string; atimeNs: bigint; mtimeNs: bigint }[] = [];
    const { client } = await serve({
      ...memory,
      mountx: {
        async utimens(path, atimeNs, mtimeNs) {
          stamped.push({ path, atimeNs, mtimeNs });
        },
      },
    });
    await client.walk(0, 1, []);
    await client.lcreate(1, "file", { flags: O_RDWR });
    await client.setattr(1, {
      valid: P9_SETATTR_ATIME | P9_SETATTR_ATIME_SET | P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET,
      atime: { sec: 7n, nsec: 123_456_789n },
      mtime: { sec: 8n, nsec: 987_654_321n },
    });
    // `fs.utimes` takes float seconds and loses these; the extension does not.
    expect(stamped).toEqual([{ path: "/file", atimeNs: 7_123_456_789n, mtimeNs: 8_987_654_321n }]);
  });

  it("skips the ownership claim when the caller is the server itself", async () => {
    const memory = createMemoryDriver();
    let claims = 0;
    const driver: FsDriver = {
      ...memory,
      async lchown(path, uid, gid) {
        claims++;
        return memory.lchown!(path, uid, gid);
      },
    };
    const { client } = raw(driver);
    await client.version();
    await client.attach(0, { nUname: process.getuid?.() ?? 0 });
    await client.mkdir(0, "mine", 0o755, process.getgid?.() ?? 0);
    // One driver round trip saved on the overwhelmingly common case.
    expect(claims).toBe(0);
  });

  it("fails the create when lchown fails for a reason that is not about ownership", async () => {
    const memory = createMemoryDriver();
    const { client } = raw({
      ...memory,
      async lchown() {
        throw Object.assign(new Error("EIO: i/o error"), { code: "EIO", errno: -5 });
      },
    });
    await client.version();
    await client.attach(0, { nUname: 4242 });
    // ENOSYS, EPERM and ENOTSUP are tolerated; a driver falling over is not.
    expect(await codeOfRejection(client.mkdir(0, "dir", 0o755, 77))).toBe("EIO");
  });

  it("closes the handle of an open a teardown overtook", async () => {
    const memory = createMemoryDriver();
    let closed = 0;
    let gate: Promise<void> | undefined;
    let release!: () => void;
    const { client, session, fs } = await serve({
      ...memory,
      async open(path, flags, mode) {
        const handle = await memory.open(path, flags, mode);
        if (gate !== undefined) {
          await gate;
        }
        return {
          ...handle,
          async close() {
            closed++;
            await handle.close();
          },
        };
      },
    });
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    closed = 0;
    gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const tag = client.nextTag();
    const parked = client.send(P9_TLOPEN, tag, (writer) =>
      writeTlopen(writer, { fid: 1, flags: O_RDONLY }),
    );
    await session.destroy();
    release();
    const reply = await parked;
    expect(reply.type).toBe(P9_RLERROR);
    expect(readRlerror(reply.body).ecode).toBe(ERRNO_CODES.ENODEV);
    // The fid it would have been stored on is gone, so the handle had to be
    // closed here or it would never be closed at all.
    expect(closed).toBe(1);
  });

  it("closes the handle of a create it could not describe", async () => {
    const memory = createMemoryDriver();
    let closed = 0;
    const { client } = await serve({
      ...memory,
      async lstat(path) {
        if (path === "/doomed") {
          throw Object.assign(new Error("EIO: i/o error"), { code: "EIO", errno: -5 });
        }
        return memory.lstat!(path);
      },
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
    });
    await client.walk(0, 1, []);
    expect(await codeOfRejection(client.lcreate(1, "doomed", { flags: O_RDWR }))).toBe("EIO");
    expect(closed).toBe(1);
  });

  it("reports a real chown failure instead of falling back to the following form", async () => {
    const memory = createMemoryDriver();
    const { client, fs } = await serve({
      ...memory,
      async lchown() {
        throw Object.assign(new Error("EPERM: operation not permitted"), {
          code: "EPERM",
          errno: -1,
        });
      },
    });
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    // Only `ENOSYS` means "this driver has no such method"; everything else is
    // an answer, and answering it twice would be answering the wrong question.
    expect(await codeOfRejection(client.setattr(1, { valid: P9_SETATTR_UID, uid: 3 }))).toBe(
      "EPERM",
    );
  });

  it("does not fail a request because a close it did not promise failed", async () => {
    const memory = createMemoryDriver();
    const errors: unknown[] = [];
    const { client, fs } = await serve(
      {
        ...memory,
        capabilities: { ...memory.capabilities, handles: false },
        async open(path, flags, mode) {
          const handle = await memory.open(path, flags, mode);
          return {
            ...handle,
            async close() {
              await handle.close();
              throw Object.assign(new Error("EIO: i/o error"), { code: "EIO", errno: -5 });
            },
          };
        },
      },
      { onError: (error) => errors.push(error) },
    );
    await fs.writeFile("/file", "hello").catch(() => undefined);
    await client.walk(0, 1, ["file"]);
    await client.lopen(1, O_RDONLY);
    // A `handles: false` read opens and closes per operation; the close is a
    // diagnostic, never this request's errno.
    expect(decode(await client.read(1, 0n))).toBe("hello");
    expect(errors.length).toBeGreaterThan(0);
  });
});

describe("two requests racing on one fid", () => {
  /**
   * A driver whose `open` parks on a gate and whose handles count their closes.
   *
   * The whole point is to hold two `Tlopen`s (or two `Tlcreate`s) inside the
   * driver at once, which is what `p9_client_open()` never does and what a
   * server accepting frames from anything on a socket cannot rule out.
   */
  function gatedOpen(): {
    driver: FsDriver;
    opens: number;
    closes: number;
    block: () => void;
    release: () => void;
    counts: () => { opens: number; closes: number };
  } {
    const memory = createMemoryDriver();
    let opens = 0;
    let closes = 0;
    let gate: Promise<void> | undefined;
    let open!: () => void;
    return {
      get opens() {
        return opens;
      },
      get closes() {
        return closes;
      },
      counts: () => ({ opens, closes }),
      driver: {
        ...memory,
        async open(path, flags, mode) {
          const handle = await memory.open(path, flags, mode);
          opens++;
          if (gate !== undefined) {
            await gate;
          }
          return {
            ...handle,
            async close() {
              closes++;
              await handle.close();
            },
          };
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

  /** Let both parked requests reach the driver before the gate opens. */
  const settle = async (): Promise<void> => {
    for (let index = 0; index < 20; index++) {
      await Promise.resolve();
    }
  };

  it("Tlopen: exactly one wins, and the loser's handle is closed, not leaked", async () => {
    const gate = gatedOpen();
    const { client, session, fs } = await serve(gate.driver);
    await fs.writeFile("/file", "hello");
    await client.walk(0, 1, ["file"]);
    // The harness wrote through the same driver, so count from here.
    const before = gate.counts();
    gate.block();

    const both = Promise.allSettled([client.lopen(1, O_RDONLY), client.lopen(1, O_RDONLY)]);
    await settle();
    const opened = gate.counts().opens - before.opens;
    gate.release();
    const [first, second] = await both;

    // Both reached the driver — that is the race being reproduced.
    expect(opened).toBe(2);
    const won = [first, second].filter((result) => result.status === "fulfilled");
    const lost = [first, second].filter((result) => result.status === "rejected");
    expect(won).toHaveLength(1);
    expect(lost).toHaveLength(1);
    expect((lost[0] as PromiseRejectedResult).reason.code).toBe("EBUSY");
    // The loser closed what it opened rather than overwriting the winner's
    // state and stranding a descriptor for the life of the connection.
    expect(gate.counts().closes - before.closes).toBe(1);
    expect(session.fids.require(1).open?.handle).toBeDefined();

    await client.clunk(1);
    expect(gate.counts().closes - before.closes).toBe(2);
    await session.destroy();
    // Nothing was left for teardown to find, which is the leak this guards.
    expect(gate.counts().opens - before.opens).toBe(2);
    expect(gate.counts().closes - before.closes).toBe(2);
  });

  it("Tlcreate: one winner, one path, no leaked handle", async () => {
    const gate = gatedOpen();
    const { client, session, fs } = await serve(gate.driver);
    await client.walk(0, 1, []);
    gate.block();

    const both = Promise.allSettled([
      client.lcreate(1, "one", { flags: O_RDWR }),
      client.lcreate(1, "two", { flags: O_RDWR }),
    ]);
    await settle();
    gate.release();
    const results = await both;

    const won = results.filter((result) => result.status === "fulfilled");
    expect(gate.counts().opens).toBe(2);
    expect(won).toHaveLength(1);
    expect(
      (results.find((result) => result.status === "rejected") as PromiseRejectedResult).reason.code,
    ).toBe("EBUSY");
    // The fid moved exactly once: a loser that only checked `open` would still
    // have overwritten the winner's path.
    const entry = session.fids.require(1);
    expect(["/one", "/two"]).toContain(entry.path);
    expect(entry.open?.handle).toBeDefined();
    expect(gate.counts().closes).toBe(1);
    // Both files exist, and that is honest: the loser's create really happened,
    // and unlinking it would delete a path another request may already hold.
    expect(
      (await fs.readdir("/", { withFileTypes: true })).map((item) => item.name).sort(),
    ).toEqual(["one", "two"]);

    await client.clunk(1);
    expect(gate.counts()).toEqual({ opens: 2, closes: 2 });
  });

  it("a fid clunked out from under a parked open is refused, and says what happened", async () => {
    const gate = gatedOpen();
    const reported: unknown[] = [];
    const { client, session, fs } = await serve(gate.driver, {
      onError: (error) => reported.push(error),
    });
    await fs.writeFile("/file", "x");
    await client.walk(0, 1, ["file"]);
    const before = gate.counts();
    gate.block();

    const parked = client.lopen(1, O_RDONLY);
    await settle();
    // No `Tversion` anywhere: the fid was simply released while the open was in
    // flight, and the error must not blame a reset that never happened.
    await client.clunk(1);
    gate.release();
    expect(await codeOfRejection(parked)).toBe("EIO");
    expect(session.generation).toBe(1);
    // The wire carries an errno and nothing else, so the sentence only exists
    // on this side — which is exactly where a reader looking for the cause is.
    expect((reported.at(-1) as Error).message).toMatch(
      /aborted — the session was reset or its fid was released/,
    );
    // Opened, then closed by the unwind: a fid nobody holds cannot clunk it.
    expect(gate.counts().opens - before.opens).toBe(1);
    expect(gate.counts().closes - before.closes).toBe(1);
  });
});

describe("Rlopen's qid describes the file after the open, not before", () => {
  it("re-stats when O_TRUNC could have changed it", async () => {
    const memory = createMemoryDriver();
    const { client, fs } = await serve({
      ...memory,
      async open(path, flags, mode) {
        const handle = await memory.open(path, flags, mode);
        // Stand in for a driver whose open mutates the file: a distinctive
        // mtime, which is exactly what `qid.version` carries.
        await memory.utimes!(path, 5_000, 5_000);
        return handle;
      },
    });
    await fs.writeFile("/file", "hello");
    await client.walk(0, 1, ["file"]);
    const opened = await client.lopen(1, O_RDWR | O_TRUNC);
    // Not the version from before the truncation: a client caches pages against
    // `(qid.path, qid.version)` and would never invalidate a stale one.
    expect(opened.qid.version).toBe(5_000_000);
    expect(opened.qid.version).toBe((await client.getattr(1)).qid.version);
  });

  it("costs no extra stat when the flags cannot change anything", async () => {
    const memory = createMemoryDriver();
    let stats = 0;
    const { client, fs } = await serve({
      ...memory,
      async lstat(path) {
        stats++;
        return memory.lstat!(path);
      },
    });
    await fs.writeFile("/file", "hello");
    await client.walk(0, 1, ["file"]);
    stats = 0;
    await client.lopen(1, O_RDONLY);
    expect(stats).toBe(1);
  });
});
