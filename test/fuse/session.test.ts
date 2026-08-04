/**
 * The session layer, driven end to end by a synthetic kernel.
 *
 * These are the sequences where the real bugs live (IDEA.md, Tier 0): `FORGET`
 * refcounting, rename subtree remap, unlink-while-open, hardlink aliasing,
 * readdir paging. No `/dev/fuse`, no mount, no root.
 */

import { constants } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { createNodeFsDriver } from "../../src/drivers/node-fs.ts";
import { ERRNO_CODES } from "../../src/errors.ts";
import { createLoopback } from "../../src/harness.ts";
import {
  FATTR_ATIME,
  FATTR_MODE,
  FATTR_MTIME,
  FATTR_SIZE,
  FOPEN_KEEP_CACHE,
  FOPEN_NOFLUSH,
  FUSE_FLUSH,
  FUSE_GETATTR,
  FUSE_INIT,
  FUSE_LOOKUP,
  FUSE_NOTIFY_INVAL_ENTRY,
  FUSE_NOTIFY_INVAL_INODE,
  FUSE_ROOT_ID,
  O_CREAT,
  O_EXCL,
  O_RDWR,
  O_TRUNC,
  O_WRONLY,
} from "../../src/fuse/constants.ts";
import {
  decodeNotify,
  decodeNotifyInvalEntry,
  decodeNotifyInvalInode,
} from "../../src/fuse/notify.ts";
import {
  DirentPacker,
  encodeReply,
  encodeRequest,
  type FuseEntryOut,
  type FuseInitOut,
} from "../../src/fuse/protocol.ts";
import {
  createFuseSession,
  DEFAULT_FLUSH_MECHANISM,
  FuseSession,
  type FuseSessionOptions,
} from "../../src/fuse/session.ts";
import { S_IFDIR, S_IFMT, S_IFREG, type FsDriver, type StatsLike } from "../../src/types.ts";
import { withoutExtensions } from "../no-extensions.ts";
import { KernelError, SyntheticKernel, type RawReply } from "./synthetic-kernel.ts";

/**
 * Flags handed to `kernel` are the **wire's** — `constants.ts`'s transcribed
 * `O_*`, not `node:fs`'s — because that is what a Linux kernel would have put
 * in `fuse_open_in.flags`, whatever host this suite runs on. A driver written
 * *inside* a test is the other side of `flags.ts` and uses `node:fs`'s.
 */
const O_CREAT_RDWR = O_CREAT | O_RDWR;
const decoder = new TextDecoder();

interface Mounted {
  session: FuseSession;
  kernel: SyntheticKernel;
}

function makeSession(driver?: FsDriver, options?: FuseSessionOptions): Mounted {
  const session = new FuseSession(driver ?? createMemoryDriver(), options);
  return { session, kernel: new SyntheticKernel(session) };
}

async function mount(driver?: FsDriver, options?: FuseSessionOptions): Promise<Mounted> {
  const mounted = makeSession(driver, options);
  await mounted.kernel.init();
  return mounted;
}

/**
 * The invariant that matters most: every request was answered exactly once, and
 * no dev-mode assertion fired.
 */
function expectHealthy(session: FuseSession): void {
  expect(session.assertions).toEqual([]);
  const { requests, replies, noReply, dropped } = session.stats;
  expect(replies + noReply + dropped).toBe(requests);
}

describe("handshake", () => {
  it("negotiates INIT and remembers the session", async () => {
    const { session, kernel } = makeSession();
    expect(session.negotiated).toBeUndefined();
    const reply = await kernel.init();

    expect(reply.major).toBe(7);
    expect(reply.minor).toBe(41);
    expect(reply.maxWrite).toBe(1024 * 1024);
    expect(session.negotiated?.readdirplus).toBe(true);
    expect(session.negotiated?.writebackCache).toBe(false);
    expect(session.protocol).toEqual({ minor: 41, setxattrExt: true });
    expectHealthy(session);
  });

  it("answers -EIO to anything before INIT", async () => {
    const { session, kernel } = makeSession();
    const reply = await kernel.raw(FUSE_GETATTR, {
      nodeid: FUSE_ROOT_ID,
      body: { getattrFlags: 0, fh: 0n },
    });
    expect(reply.error).toBe(-ERRNO_CODES.EIO);
    expectHealthy(session);
  });

  it("answers -EIO to a second INIT", async () => {
    const { kernel } = await mount();
    await expect(kernel.init()).rejects.toMatchObject({ code: "EIO" });
  });

  it("marks the session dead on DESTROY and answers -ENODEV after", async () => {
    const { session, kernel } = await mount();
    await kernel.destroy();
    expect(session.destroyed).toBe(true);
    const reply = await kernel.raw(FUSE_GETATTR, {
      nodeid: FUSE_ROOT_ID,
      body: { getattrFlags: 0, fh: 0n },
    });
    expect(reply.error).toBe(-ERRNO_CODES.ENODEV);
    expectHealthy(session);
  });
});

describe("the full mount sequence", () => {
  it("runs INIT → getattr → mkdir → create → write → read → release → unlink → forget → destroy", async () => {
    const { session, kernel } = await mount();

    const root = await kernel.getattr(FUSE_ROOT_ID);
    expect(root.attr.mode & S_IFMT).toBe(S_IFDIR);
    expect(root.attr.ino).toBeGreaterThan(0n);
    expect(root.attrValid).toBe(10n);

    const dir = await kernel.mkdir(FUSE_ROOT_ID, "docs", 0o755);
    expect(dir.nodeid).toBeGreaterThan(FUSE_ROOT_ID);
    expect(dir.attr.mode & S_IFMT).toBe(S_IFDIR);
    expect(dir.entryValid).toBe(10n);

    const created = await kernel.create(dir.nodeid, "hello.txt", O_CREAT_RDWR, 0o644);
    expect(created.entry.attr.mode & S_IFMT).toBe(S_IFREG);
    expect(created.entry.attr.size).toBe(0n);
    const fh = created.open.fh;

    expect(await kernel.write(created.entry.nodeid, fh, 0, "hello ")).toBe(6);
    expect(await kernel.write(created.entry.nodeid, fh, 6, "world")).toBe(5);

    const data = await kernel.read(created.entry.nodeid, fh, 0, 4096);
    expect(decoder.decode(data)).toBe("hello world");

    // A short read at the end of the file, which is how the kernel learns EOF.
    expect(await kernel.read(created.entry.nodeid, fh, 9, 4096)).toHaveLength(2);

    const attr = await kernel.getattr(created.entry.nodeid, fh);
    expect(attr.attr.size).toBe(11n);

    await kernel.flush(created.entry.nodeid, fh);
    await kernel.fsync(created.entry.nodeid, fh);
    await kernel.release(created.entry.nodeid, fh);
    expect(session.openHandles).toBe(0);

    await kernel.unlink(dir.nodeid, "hello.txt");
    await expect(kernel.lookup(dir.nodeid, "hello.txt")).rejects.toMatchObject({ code: "ENOENT" });

    // The inode outlives the name, and only the FORGET drops it.
    expect(session.inodes.get(created.entry.nodeid)).toBeDefined();
    await kernel.forgetAll(created.entry.nodeid);
    expect(session.inodes.get(created.entry.nodeid)).toBeUndefined();

    await kernel.rmdir(FUSE_ROOT_ID, "docs");
    await kernel.forgetAll(dir.nodeid);

    await kernel.destroy();
    expect(session.destroyed).toBe(true);
    expectHealthy(session);
  });

  it("reports statfs", async () => {
    const { session, kernel } = await mount();
    const statfs = await kernel.statfs();
    expect(statfs.bsize).toBe(4096);
    expect(statfs.namelen).toBe(255);
    expect(statfs.blocks).toBeGreaterThan(0n);
    expectHealthy(session);
  });

  it("reads and writes symlinks", async () => {
    const { session, kernel } = await mount();
    await kernel.create(FUSE_ROOT_ID, "target", O_CREAT_RDWR, 0o644);
    const link = await kernel.symlink(FUSE_ROOT_ID, "link", "target");
    expect(link.attr.mode & S_IFMT).toBe(0o120_000);
    expect(await kernel.readlink(link.nodeid)).toBe("target");
    expectHealthy(session);
  });

  it("refuses a name longer than the NAME_MAX it advertises", async () => {
    // The kernel does *not* filter these: `fuse_lookup_name` only rejects names
    // over `FUSE_NAME_MAX` (1024) and leaves the real limit to the server. So a
    // driver with no limit of its own — the in-memory one — would happily
    // create a name that the same mount's `STATFS` calls impossible, and
    // `chmod` on one would answer `ENOENT` instead of `ENAMETOOLONG`.
    const { session, kernel } = await mount();
    const longest = "n".repeat(255);
    const tooLong = "n".repeat(256);

    // 255 bytes is fine, in both directions.
    await kernel.mkdir(FUSE_ROOT_ID, longest);
    expect((await kernel.lookup(FUSE_ROOT_ID, longest)).attr.mode & S_IFMT).toBe(0o040_000);

    for (const call of [
      kernel.lookup(FUSE_ROOT_ID, tooLong),
      kernel.mkdir(FUSE_ROOT_ID, tooLong),
      kernel.create(FUSE_ROOT_ID, tooLong, O_CREAT_RDWR, 0o644),
      kernel.symlink(FUSE_ROOT_ID, tooLong, "target"),
      kernel.unlink(FUSE_ROOT_ID, tooLong),
    ]) {
      await expect(call).rejects.toMatchObject({ code: "ENAMETOOLONG" });
    }

    // A byte count, not a character count: 128 two-byte characters are 256
    // bytes and must be refused just the same.
    await expect(kernel.mkdir(FUSE_ROOT_ID, "é".repeat(128))).rejects.toMatchObject({
      code: "ENAMETOOLONG",
    });
    // ...and 127 of them, at 254 bytes, are not.
    await kernel.mkdir(FUSE_ROOT_ID, "é".repeat(127));

    // The limit refused above is the one the mount reports.
    expect((await kernel.statfs(FUSE_ROOT_ID)).namelen).toBe(255);
    expectHealthy(session);
  });

  it("synthesizes MKNOD for regular files", async () => {
    // Without the extension, which is what this fallback is for — the memory
    // driver has one, and the case below is where that path is tested.
    const { session, kernel } = await mount(withoutExtensions(createMemoryDriver()));
    const entry = await kernel.mknod(FUSE_ROOT_ID, "node", S_IFREG | 0o600);
    expect(entry.attr.mode & S_IFMT).toBe(S_IFREG);
    // A FIFO needs the `mountx.mknod` extension, and says so.
    await expect(kernel.mknod(FUSE_ROOT_ID, "fifo", 0o010_600)).rejects.toMatchObject({
      code: "ENOSYS",
    });
    expectHealthy(session);
  });
});

describe("FORGET refcounting", () => {
  it("only drops an inode when the count reaches zero", async () => {
    const { session, kernel } = await mount();
    await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);

    const first = await kernel.lookup(FUSE_ROOT_ID, "f");
    const second = await kernel.lookup(FUSE_ROOT_ID, "f");
    expect(second.nodeid).toBe(first.nodeid);
    // One CREATE plus two LOOKUPs.
    expect(kernel.outstanding(first.nodeid)).toBe(3n);
    expect(session.inodes.get(first.nodeid)?.nlookup).toBe(3n);

    await kernel.forget(first.nodeid, 1n);
    expect(session.inodes.get(first.nodeid)?.nlookup).toBe(2n);
    await expect(kernel.getattr(first.nodeid)).resolves.toBeDefined();

    await kernel.forget(first.nodeid, 2n);
    expect(session.inodes.get(first.nodeid)).toBeUndefined();

    // A nodeid the session has forgotten is a ghost, and the answer is ESTALE.
    await expect(kernel.getattr(first.nodeid)).rejects.toMatchObject({ code: "ESTALE" });
    await expect(kernel.lookup(first.nodeid, "x")).rejects.toMatchObject({ code: "ESTALE" });
    expectHealthy(session);
  });

  it("ignores FORGET for the root and for unknown nodeids", async () => {
    const { session, kernel } = await mount();
    await kernel.forget(FUSE_ROOT_ID, 1n);
    await kernel.forget(9999n, 1n);
    await expect(kernel.getattr(FUSE_ROOT_ID)).resolves.toBeDefined();
    expectHealthy(session);
  });

  it("handles BATCH_FORGET", async () => {
    const { session, kernel } = await mount();
    const a = await kernel.create(FUSE_ROOT_ID, "a", O_CREAT_RDWR, 0o644);
    const b = await kernel.create(FUSE_ROOT_ID, "b", O_CREAT_RDWR, 0o644);
    await kernel.batchForget([
      { nodeid: a.entry.nodeid, nlookup: 1n },
      { nodeid: b.entry.nodeid, nlookup: 1n },
    ]);
    expect(session.inodes.get(a.entry.nodeid)).toBeUndefined();
    expect(session.inodes.get(b.entry.nodeid)).toBeUndefined();
    expectHealthy(session);
  });

  it("never replies to FORGET", async () => {
    const { session, kernel } = await mount();
    const before = session.stats.replies;
    await kernel.forget(1234n, 1n);
    await kernel.batchForget([{ nodeid: 1234n, nlookup: 1n }]);
    expect(session.stats.replies).toBe(before);
    expect(session.stats.noReply).toBe(2);
    expectHealthy(session);
  });
});

describe("rename", () => {
  it("remaps a whole subtree, keeping every nodeid valid", async () => {
    const { session, kernel } = await mount();
    const a = await kernel.mkdir(FUSE_ROOT_ID, "a");
    const b = await kernel.mkdir(a.nodeid, "b");
    const c = await kernel.create(b.nodeid, "c.txt", O_CREAT_RDWR, 0o644);
    await kernel.write(c.entry.nodeid, c.open.fh, 0, "payload");

    await kernel.rename(FUSE_ROOT_ID, "a", FUSE_ROOT_ID, "x");

    // Every nodeid the kernel holds keeps working, at its new path.
    expect(session.inodes.pathOf(session.inodes.get(a.nodeid)!)).toBe("/x");
    expect(session.inodes.pathOf(session.inodes.get(b.nodeid)!)).toBe("/x/b");
    expect(session.inodes.pathOf(session.inodes.get(c.entry.nodeid)!)).toBe("/x/b/c.txt");
    await expect(kernel.getattr(b.nodeid)).resolves.toBeDefined();
    expect(decoder.decode(await kernel.read(c.entry.nodeid, c.open.fh, 0, 64))).toBe("payload");

    // The old name is gone; the new one resolves to the same inode.
    await expect(kernel.lookup(FUSE_ROOT_ID, "a")).rejects.toMatchObject({ code: "ENOENT" });
    const moved = await kernel.lookup(FUSE_ROOT_ID, "x");
    expect(moved.nodeid).toBe(a.nodeid);
    expect((await kernel.lookup(moved.nodeid, "b")).nodeid).toBe(b.nodeid);

    // And a nodeid that has been forgotten is still ESTALE, not resurrected.
    await kernel.release(c.entry.nodeid, c.open.fh);
    await kernel.forgetAll(c.entry.nodeid);
    await expect(kernel.getattr(c.entry.nodeid)).rejects.toMatchObject({ code: "ESTALE" });
    expectHealthy(session);
  });

  it("drops the inode the destination used to hold", async () => {
    const { session, kernel } = await mount();
    const from = await kernel.create(FUSE_ROOT_ID, "from", O_CREAT_RDWR, 0o644);
    const to = await kernel.create(FUSE_ROOT_ID, "to", O_CREAT_RDWR, 0o644);
    await kernel.release(from.entry.nodeid, from.open.fh);
    await kernel.release(to.entry.nodeid, to.open.fh);

    await kernel.rename(FUSE_ROOT_ID, "from", FUSE_ROOT_ID, "to");

    expect(session.inodes.pathOf(session.inodes.get(from.entry.nodeid)!)).toBe("/to");
    // The overwritten inode is orphaned but not forgotten: it has no path left.
    expect(session.inodes.get(to.entry.nodeid)?.paths.size).toBe(0);
    await expect(kernel.getattr(to.entry.nodeid)).rejects.toMatchObject({ code: "ENOENT" });
    expectHealthy(session);
  });

  it("answers -ENOSYS to RENAME2 with flags", async () => {
    const { session, kernel } = await mount();
    await kernel.create(FUSE_ROOT_ID, "one", O_CREAT_RDWR, 0o644);
    const noreplace = await kernel.rename2(FUSE_ROOT_ID, "one", FUSE_ROOT_ID, "two", 1);
    expect(noreplace.error).toBe(-ERRNO_CODES.ENOSYS);
    const plain = await kernel.rename2(FUSE_ROOT_ID, "one", FUSE_ROOT_ID, "two", 0);
    expect(plain.error).toBe(0);
    expectHealthy(session);
  });

  it("serializes a rename against concurrent lookups", async () => {
    const { session, kernel } = await mount();
    const dir = await kernel.mkdir(FUSE_ROOT_ID, "dir");
    await kernel.create(dir.nodeid, "file", O_CREAT_RDWR, 0o644);

    // Fire both without awaiting in between, exactly as the kernel would.
    const [renamed, looked] = await Promise.allSettled([
      kernel.rename(FUSE_ROOT_ID, "dir", FUSE_ROOT_ID, "moved"),
      kernel.lookup(dir.nodeid, "file"),
    ]);
    expect(renamed.status).toBe("fulfilled");
    // Either order is legal; what is not legal is a path map that disagrees
    // with itself afterwards.
    if (looked.status === "fulfilled") {
      expect(session.inodes.pathOf(session.inodes.get(looked.value.nodeid)!)).toBe("/moved/file");
    }
    expect(session.inodes.pathOf(session.inodes.get(dir.nodeid)!)).toBe("/moved");
    expect(await kernel.readdirAll(FUSE_ROOT_ID, (await kernel.opendir(FUSE_ROOT_ID)).fh)).toEqual([
      ".",
      "..",
      "moved",
    ]);
    expectHealthy(session);
  });
});

describe("unlink while open", () => {
  it("keeps the handle working and drops the inode only at FORGET", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "doomed", O_CREAT_RDWR, 0o644);
    const { fh } = file.open;
    const nodeid = file.entry.nodeid;
    await kernel.write(nodeid, fh, 0, "still here");

    await kernel.unlink(FUSE_ROOT_ID, "doomed");

    // Orphaned: no path, but very much alive.
    expect(session.inodes.get(nodeid)?.paths.size).toBe(0);
    expect(decoder.decode(await kernel.read(nodeid, fh, 0, 64))).toBe("still here");
    expect(await kernel.write(nodeid, fh, 10, "!")).toBe(1);
    expect(decoder.decode(await kernel.read(nodeid, fh, 0, 64))).toBe("still here!");
    // `fstat` still works — both when the kernel names the handle and, far more
    // importantly, when it does not. `fuse_getattr` is an `inode_operations`
    // hook, so a plain `fstat(2)` carries no fh at all.
    expect((await kernel.getattr(nodeid, fh)).attr.size).toBe(11n);
    expect((await kernel.getattr(nodeid)).attr.size).toBe(11n);

    await kernel.release(nodeid, fh);
    expect(session.openHandles).toBe(0);
    expect(session.inodes.get(nodeid)).toBeDefined();
    await kernel.forgetAll(nodeid);
    expect(session.inodes.get(nodeid)).toBeUndefined();
    expectHealthy(session);
  });

  it("answers -EBADF for a released handle", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.release(file.entry.nodeid, file.open.fh);
    await expect(kernel.read(file.entry.nodeid, file.open.fh, 0, 16)).rejects.toMatchObject({
      code: "EBADF",
    });
    expectHealthy(session);
  });
});

describe("hardlinks", () => {
  it("gives both names one inode, and counts nlink", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "one", O_CREAT_RDWR, 0o644);
    await kernel.write(file.entry.nodeid, file.open.fh, 0, "shared");
    await kernel.release(file.entry.nodeid, file.open.fh);
    const nodeid = file.entry.nodeid;

    const linked = await kernel.link(nodeid, FUSE_ROOT_ID, "two");
    // The kernel requires LINK to answer with the *existing* nodeid.
    expect(linked.nodeid).toBe(nodeid);
    expect(linked.attr.nlink).toBe(2);
    expect((await kernel.lookup(FUSE_ROOT_ID, "two")).nodeid).toBe(nodeid);
    expect((await kernel.lookup(FUSE_ROOT_ID, "one")).nodeid).toBe(nodeid);
    expect(session.inodes.get(nodeid)?.paths.size).toBe(2);

    // Unlinking one name leaves the other, and the inode keeps a path.
    await kernel.unlink(FUSE_ROOT_ID, "one");
    expect([...session.inodes.get(nodeid)!.paths]).toEqual(["/two"]);
    expect((await kernel.getattr(nodeid)).attr.nlink).toBe(1);

    const open = await kernel.open(nodeid, O_RDWR);
    expect(decoder.decode(await kernel.read(nodeid, open.fh, 0, 64))).toBe("shared");
    await kernel.release(nodeid, open.fh);
    expectHealthy(session);
  });
});

describe("readdir", () => {
  const names = Array.from({ length: 40 }, (_, index) => `entry-${String(index).padStart(3, "0")}`);

  async function populate(kernel: SyntheticKernel): Promise<bigint> {
    const dir = await kernel.mkdir(FUSE_ROOT_ID, "many");
    for (const name of names) {
      const created = await kernel.create(dir.nodeid, name, O_CREAT_RDWR, 0o644);
      await kernel.release(created.entry.nodeid, created.open.fh);
      await kernel.forgetAll(created.entry.nodeid);
    }
    return dir.nodeid;
  }

  it("pages a plain READDIR with stable offsets", async () => {
    const { session, kernel } = await mount();
    const dir = await populate(kernel);
    const { fh } = await kernel.opendir(dir);

    const first = await kernel.readdir(dir, fh, 0n, 256);
    expect(first.entries.length).toBeGreaterThan(0);
    expect(first.entries.length).toBeLessThan(names.length);
    expect(first.entries[0]!.name).toBe(".");
    expect(first.entries[1]!.name).toBe("..");
    // Offsets are "resume after this entry", and strictly increasing.
    expect(first.entries.map((entry) => entry.off)).toEqual(
      first.entries.map((_, index) => BigInt(index + 1)),
    );

    // Resuming from the last offset picks up exactly where it left off.
    const second = await kernel.readdir(dir, fh, first.entries.at(-1)!.off, 256);
    expect(second.entries[0]!.name).toBe(names[first.entries.length - 2]);

    const all = await kernel.readdirAll(dir, fh, 256);
    expect(all).toEqual([".", "..", ...names]);
    // Every entry has a real inode number, so `readdir(3)` will not skip it.
    const page = await kernel.readdir(dir, fh, 2n, 4096);
    expect(page.entries.every((entry) => entry.ino > 0n)).toBe(true);

    await kernel.releasedir(dir, fh);
    expectHealthy(session);
  });

  it("mints no inodes for a plain READDIR", async () => {
    // A `fuse_dirent.ino` is a fileid, not a nodeid: the kernel never links it
    // into a dentry, so an inode minted here would sit at `nlookup == 0n` and
    // `InodeTable.forget` — the only thing that deletes from `byNodeid` — could
    // never name it. A `find` over a large tree used to retain one per file for
    // the life of the mount. On base this grows by `names.length`.
    const { session, kernel } = await mount();
    const dir = await populate(kernel);
    const before = session.inodes.size;

    const { fh } = await kernel.opendir(dir);
    expect(await kernel.readdirAll(dir, fh, 256)).toEqual([".", "..", ...names]);
    await kernel.releasedir(dir, fh);

    expect(session.inodes.size).toBe(before);
    // Nothing unforgettable was left behind either: every tracked inode is
    // either the root, reachable by path, or owed a FORGET the kernel can send.
    for (const nodeid of session.inodes.nodeids()) {
      const inode = session.inodes.get(nodeid)!;
      expect(inode.nlookup > 0n || inode.paths.size > 0).toBe(true);
    }
    expectHealthy(session);
  });

  it("reports the driver's own st_ino, so ls -i agrees with stat", async () => {
    // The fileid packed into a dirent is byte for byte what `#attrOf` puts in
    // `fuse_attr.ino`. If they ever diverge, `ls -i` and `stat` disagree about
    // the same file — which is exactly what packing a nodeid would have done.
    const { session, kernel } = await mount();
    const dir = await populate(kernel);
    const { fh } = await kernel.opendir(dir);
    const page = await kernel.readdir(dir, fh, 2n, 4096);
    expect(page.entries.length).toBeGreaterThan(0);

    for (const entry of page.entries) {
      const looked = await kernel.lookup(dir, entry.name);
      expect(entry.ino).toBe(looked.attr.ino);
      await kernel.forgetAll(looked.nodeid);
    }
    await kernel.releasedir(dir, fh);
    expectHealthy(session);
  });

  it("never advances past an entry the packer refused", async () => {
    // The loop pre-computes `needed > packer.remaining` for the ordering it
    // documents, but `DirentPacker.add` is the authority — and on base its
    // answer was discarded at all three call sites. If the two ever disagree,
    // the entry is silently dropped while `off` advances past it: a directory
    // entry that never appears in `ls`, with no error anywhere.
    //
    // Forced here by making `add` refuse exactly once, for one name.
    const { session, kernel } = await mount();
    const dir = await populate(kernel);
    const { fh } = await kernel.opendir(dir);

    const victim = names[3]!;
    const real = DirentPacker.prototype.add;
    let refused = false;
    const spy = vi
      .spyOn(DirentPacker.prototype, "add")
      .mockImplementation(function (this: DirentPacker, dirent, entry) {
        if (!refused && dirent.name === victim) {
          refused = true;
          return false;
        }
        return real.call(this, dirent, entry);
      });
    try {
      expect(await kernel.readdirAll(dir, fh, 4096)).toEqual([".", "..", ...names]);
    } finally {
      spy.mockRestore();
    }
    expect(refused).toBe(true);

    await kernel.releasedir(dir, fh);
    expectHealthy(session);
  });

  it("folds a lookup into every READDIRPLUS entry except . and ..", async () => {
    const { session, kernel } = await mount();
    const dir = await populate(kernel);
    const { fh } = await kernel.opendir(dir);

    const seen: string[] = [];
    let offset = 0n;
    let pages = 0;
    for (;;) {
      const page = await kernel.readdirplus(dir, fh, offset, 512);
      if (page.entries.length === 0) {
        break;
      }
      pages++;
      for (const entry of page.entries) {
        seen.push(entry.dirent.name);
        if (entry.dirent.name === "." || entry.dirent.name === "..") {
          // `nodeid == 0` is how a server says "no attributes"; the kernel
          // neither caches these nor counts a lookup for them.
          expect(entry.entry.nodeid).toBe(0n);
        } else {
          expect(entry.entry.nodeid).toBeGreaterThan(0n);
          expect(entry.entry.attr.mode & S_IFMT).toBe(S_IFREG);
          expect(entry.entry.attrValid).toBe(10n);
        }
      }
      offset = page.entries.at(-1)!.dirent.off;
    }
    expect(pages).toBeGreaterThan(1);
    expect(seen).toEqual([".", "..", ...names]);

    // Every entry the kernel linked owes exactly one FORGET, and the session
    // agrees on the count.
    for (const [nodeid, count] of kernel.lookups) {
      if (nodeid !== dir) {
        expect(session.inodes.get(nodeid)?.nlookup).toBe(count);
        expect(count).toBe(1n);
      }
    }
    await kernel.releasedir(dir, fh);
    expectHealthy(session);
  });

  it("re-snapshots when the kernel rewinds to offset 0", async () => {
    const { session, kernel } = await mount();
    const dir = await kernel.mkdir(FUSE_ROOT_ID, "d");
    const { fh } = await kernel.opendir(dir.nodeid);
    expect(await kernel.readdirAll(dir.nodeid, fh)).toEqual([".", ".."]);

    const created = await kernel.create(dir.nodeid, "new", O_CREAT_RDWR, 0o644);
    await kernel.release(created.entry.nodeid, created.open.fh);
    expect(await kernel.readdirAll(dir.nodeid, fh)).toEqual([".", "..", "new"]);
    await kernel.releasedir(dir.nodeid, fh);
    expectHealthy(session);
  });

  it("answers -ENOTDIR at the first READDIR on a file, and -EBADF for a mismatched handle", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    // `ENOTDIR` used to arrive from `OPENDIR` itself, which paid a driver
    // `lstat` on every `opendir(3)` to re-check a type the kernel had taken
    // from attributes this server supplied. `OPENDIR` now just allocates a
    // handle, and the rejection moved one message later to the first `READDIR`
    // — the call that genuinely needs a directory, and the authority on whether
    // it has one. Nothing observable is lost: the VFS refuses `O_DIRECTORY` on
    // a regular file before FUSE is ever asked, so a real kernel never gets
    // here, and a caller that does still cannot read a single entry.
    const dirFh = await kernel.opendir(file.entry.nodeid);
    await expect(kernel.readdir(file.entry.nodeid, dirFh.fh, 0n)).rejects.toMatchObject({
      code: "ENOTDIR",
    });
    await kernel.releasedir(file.entry.nodeid, dirFh.fh);
    // A directory handle is not a file handle, and vice versa.
    await expect(kernel.read(file.entry.nodeid, file.open.fh + 99n, 0, 8)).rejects.toMatchObject({
      code: "EBADF",
    });
    const dir = await kernel.opendir(FUSE_ROOT_ID);
    await expect(kernel.read(FUSE_ROOT_ID, dir.fh, 0, 8)).rejects.toMatchObject({ code: "EBADF" });
    await expect(kernel.readdir(FUSE_ROOT_ID, file.open.fh, 0n)).rejects.toMatchObject({
      code: "EBADF",
    });
    expectHealthy(session);
  });
});

describe("SETATTR", () => {
  it("applies size, mode and times from one message", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.write(file.entry.nodeid, file.open.fh, 0, "0123456789");
    await kernel.release(file.entry.nodeid, file.open.fh);

    const attr = await kernel.setattr(file.entry.nodeid, {
      valid: FATTR_SIZE | FATTR_MODE | FATTR_ATIME | FATTR_MTIME,
      size: 4n,
      mode: S_IFREG | 0o600,
      atime: 1_000_000n,
      atimensec: 250_000_000,
      mtime: 2_000_000n,
      mtimensec: 500_000_000,
    });

    expect(attr.attr.size).toBe(4n);
    expect(attr.attr.mode & 0o7777).toBe(0o600);
    expect(attr.attr.atime).toBe(1_000_000n);
    expect(attr.attr.mtime).toBe(2_000_000n);
    expect(attr.attr.mtimensec).toBe(500_000_000);

    const open = await kernel.open(file.entry.nodeid, O_RDWR);
    expect(decoder.decode(await kernel.read(file.entry.nodeid, open.fh, 0, 64))).toBe("0123");
    await kernel.release(file.entry.nodeid, open.fh);
    expectHealthy(session);
  });

  it("sets only the timestamp it was asked to, keeping the other", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.release(file.entry.nodeid, file.open.fh);
    const before = await kernel.getattr(file.entry.nodeid);

    const after = await kernel.setattr(file.entry.nodeid, {
      valid: FATTR_MTIME,
      mtime: 1_234_567n,
    });
    expect(after.attr.mtime).toBe(1_234_567n);
    expect(after.attr.atime).toBe(before.attr.atime);
    expectHealthy(session);
  });

  it("round-trips a pre-1970 timestamp", async () => {
    // `fuse_setattr_in.atime`/`.mtime` are a POSIX `tv_sec`, which is signed —
    // `touch -d 1960-01-01` is an ordinary thing to do. The decoder reads the
    // field as `u64` (correctly: the same field is unsigned in the *reply*
    // direction), so the session has to restore the sign before multiplying.
    // On base this came back 128 s off.
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.release(file.entry.nodeid, file.open.fh);

    const seconds = -315_619_200n; // 1960-01-01T00:00:00Z
    const attr = await kernel.setattr(file.entry.nodeid, {
      valid: FATTR_ATIME | FATTR_MTIME,
      atime: seconds,
      atimensec: 0,
      mtime: seconds,
      mtimensec: 0,
    });

    // `fuse_attr.atime` is unsigned on the wire; the kernel reads it back as a
    // signed `tv_sec`, which is what `BigInt.asIntN` does here.
    expect(BigInt.asIntN(64, attr.attr.mtime)).toBe(seconds);
    expect(BigInt.asIntN(64, attr.attr.atime)).toBe(seconds);
    const again = await kernel.getattr(file.entry.nodeid);
    expect(BigInt.asIntN(64, again.attr.mtime)).toBe(seconds);
    expectHealthy(session);
  });

  it("hands mountx.utimens a signed nanosecond value", async () => {
    // The extension takes nanoseconds as a `bigint`, so an unsigned read did
    // not merely lose 128 s here — it handed the driver ~1.8e28 ns.
    const seen: { atime: bigint; mtime: bigint }[] = [];
    const base = createMemoryDriver();
    const driver: FsDriver = {
      ...base,
      mountx: {
        ...base.mountx,
        utimens: async (_path: string, atime: bigint, mtime: bigint) => {
          seen.push({ atime, mtime });
        },
      },
    };
    const { session, kernel } = await mount(driver);
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.release(file.entry.nodeid, file.open.fh);

    await kernel.setattr(file.entry.nodeid, {
      valid: FATTR_ATIME | FATTR_MTIME,
      atime: -315_619_200n,
      atimensec: 250_000_000,
      mtime: -1n,
      mtimensec: 0,
    });

    expect(seen).toEqual([
      { atime: -315_619_200n * 1_000_000_000n + 250_000_000n, mtime: -1_000_000_000n },
    ]);
    expectHealthy(session);
  });

  it("truncates through the file handle when the kernel supplies one", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.write(file.entry.nodeid, file.open.fh, 0, "abcdef");
    await kernel.unlink(FUSE_ROOT_ID, "f");

    // No path left — the handle is the only way through, which is exactly the
    // case `ftruncate` on an unlinked file exercises.
    const attr = await kernel.setattr(file.entry.nodeid, {
      valid: FATTR_SIZE | (1 << 6),
      fh: file.open.fh,
      size: 2n,
    });
    expect(attr.attr.size).toBe(2n);
    await kernel.release(file.entry.nodeid, file.open.fh);
    expectHealthy(session);
  });
});

describe("errno discipline", () => {
  /** A driver that fails one method, however it likes. */
  function failing(method: string, error: unknown): FsDriver {
    const base = createMemoryDriver();
    return {
      ...base,
      [method]: async () => {
        throw error;
      },
    } as FsDriver;
  }

  it("maps node:fs-shaped errors onto the wire", async () => {
    for (const code of ["ENOENT", "EACCES", "EPERM", "ENOTDIR"] as const) {
      const error = Object.assign(new Error(code), { code, errno: -ERRNO_CODES[code] });
      const { session, kernel } = await mount(failing("lstat", error));
      const reply = await kernel.raw(FUSE_LOOKUP, { nodeid: FUSE_ROOT_ID, body: { name: "x" } });
      expect(reply.error).toBe(-ERRNO_CODES[code]);
      expect(reply.payload).toHaveLength(0);
      expectHealthy(session);
    }
  });

  it("maps anything else to -EIO", async () => {
    for (const thrown of [
      new Error("kaboom"),
      new TypeError("undefined is not a function"),
      "a string, thrown",
      null,
      { nope: true },
    ]) {
      const { session, kernel } = await mount(failing("lstat", thrown));
      const reply = await kernel.raw(FUSE_LOOKUP, { nodeid: FUSE_ROOT_ID, body: { name: "x" } });
      expect(reply.error).toBe(-ERRNO_CODES.EIO);
      expect(session.stats.errors).toBe(1);
      expectHealthy(session);
    }
  });

  it("reports errors through onError exactly once per failed request", async () => {
    const seen: unknown[] = [];
    const error = Object.assign(new Error("nope"), { code: "EACCES", errno: -13 });
    const { session, kernel } = await mount(failing("mkdir", error), {
      onError: (thrown) => seen.push(thrown),
    });
    await expect(kernel.mkdir(FUSE_ROOT_ID, "d")).rejects.toBeInstanceOf(KernelError);
    expect(seen).toEqual([error]);
    expectHealthy(session);
  });

  it("answers ENOSYS for a method the driver does not have", async () => {
    const base = createMemoryDriver();
    const { stat, readdir, open } = base;
    const { session, kernel } = await mount({
      stat,
      readdir,
      open,
      capabilities: { handles: true },
    });
    await expect(kernel.mkdir(FUSE_ROOT_ID, "d")).rejects.toMatchObject({ code: "ENOSYS" });
    await expect(kernel.symlink(FUSE_ROOT_ID, "l", "t")).rejects.toMatchObject({ code: "ENOSYS" });
    expectHealthy(session);
  });

  it("rejects names the kernel should never send", async () => {
    const { session, kernel } = await mount();
    for (const name of ["", ".", "..", "a/b"]) {
      const reply = await kernel.raw(FUSE_LOOKUP, { nodeid: FUSE_ROOT_ID, body: { name } });
      expect(reply.error).toBe(-ERRNO_CODES.EINVAL);
    }
    expectHealthy(session);
  });
});

describe("unimplemented opcodes", () => {
  it("answers -ENOSYS to INTERRUPT", async () => {
    const { session, kernel } = await mount();
    const reply = await kernel.interrupt(41n);
    expect(reply.error).toBe(-ERRNO_CODES.ENOSYS);
    expectHealthy(session);
  });

  it("answers -ENOSYS to opcodes it has no codec for", async () => {
    const { session, kernel } = await mount();
    for (const opcode of [39 /* IOCTL */, 52 /* STATX */, 1234 /* nonsense */]) {
      const reply = await kernel.raw(opcode, { payload: new Uint8Array(8) });
      expect(reply.error).toBe(-ERRNO_CODES.ENOSYS);
    }
    expectHealthy(session);
  });

  it("answers -ENOSYS to the ops v1 does not implement", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    for (const [opcode, body] of [
      [34, { mask: 4 }], // ACCESS
      [22, { size: 0, name: "user.x" }], // GETXATTR
      [23, { size: 0 }], // LISTXATTR
      [46, { fh: file.open.fh, offset: 0n, whence: 3 }], // LSEEK
      [43, { fh: file.open.fh, offset: 0n, length: 8n, mode: 0 }], // FALLOCATE
    ] as const) {
      const reply = await kernel.raw(opcode, { nodeid: file.entry.nodeid, body });
      expect(reply.error).toBe(-ERRNO_CODES.ENOSYS);
    }
    expectHealthy(session);
  });
});

describe("notifications", () => {
  it("encodes notify_inval_inode", async () => {
    const { session } = await mount();
    const message = session.notifyInvalInode(7n, -1n, 0n);
    const notification = decodeNotify(message);
    expect(notification.code).toBe(FUSE_NOTIFY_INVAL_INODE);
    expect(decodeNotifyInvalInode(notification.body)).toEqual({ ino: 7n, off: -1n, len: 0n });
  });

  it("encodes notify_inval_entry", async () => {
    const { session } = await mount();
    const message = session.notifyInvalEntry(FUSE_ROOT_ID, "gone");
    const notification = decodeNotify(message);
    expect(notification.code).toBe(FUSE_NOTIFY_INVAL_ENTRY);
    expect(decodeNotifyInvalEntry(notification.body)).toEqual({
      parent: FUSE_ROOT_ID,
      name: "gone",
      flags: 0,
    });
  });

  it("refuses a name the kernel would reject", async () => {
    const { session } = await mount();
    expect(() => session.notifyInvalEntry(1n, "x".repeat(2000))).toThrow(/FUSE_NAME_MAX/);
    expect(() => session.notifyInvalEntry(1n, "a\0b")).toThrow(/NUL/);
  });

  it("decodes only what is really a notification", async () => {
    const { session } = await mount();
    // A reply, not a notification: `unique` is non-zero.
    const reply = encodeReply(7n);
    expect(() => decodeNotify(reply)).toThrow(/not a notification/);
    expect(() => decodeNotify(new Uint8Array(8))).toThrow(/truncated/);

    const message = session.notifyInvalInode(1n);
    expect(() => decodeNotify(message.subarray(0, 20))).toThrow(/only 20 byte/);
    expect(() => decodeNotifyInvalInode(new Uint8Array(8))).toThrow(/24 bytes/);
    expect(() => decodeNotifyInvalEntry(new Uint8Array(8))).toThrow(/truncated/);
    expect(() => decodeNotifyInvalEntry(new Uint8Array(20))).toThrow(/namelen/);
  });
});

describe("drivers without per-open state", () => {
  it("synthesizes a handle per operation", async () => {
    // Same in-memory store, but declaring no `handles` capability — so the
    // session must re-open from the path for every read and write.
    const base = createMemoryDriver();
    const driver: FsDriver = { ...base, capabilities: { handles: false, atomicRename: true } };
    const { session, kernel } = await mount(driver);
    expect(session.driver.capabilities.handles).toBe(false);

    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    expect(await kernel.write(file.entry.nodeid, file.open.fh, 0, "synthetic")).toBe(9);
    expect(decoder.decode(await kernel.read(file.entry.nodeid, file.open.fh, 0, 64))).toBe(
      "synthetic",
    );
    await kernel.release(file.entry.nodeid, file.open.fh);

    // An open of something missing still fails at OPEN time.
    await expect(kernel.open(999n)).rejects.toMatchObject({ code: "ESTALE" });
    expectHealthy(session);
  });
});

describe("teardown", () => {
  it("closes every open handle", async () => {
    let closed = 0;
    const base = createMemoryDriver();
    const driver: FsDriver = {
      ...base,
      async open(path, flags, mode) {
        const handle = await base.open(path, flags, mode);
        return {
          ...handle,
          read: handle.read.bind(handle),
          write: handle.write.bind(handle),
          stat: handle.stat.bind(handle),
          truncate: handle.truncate.bind(handle),
          async close() {
            closed++;
            await handle.close();
          },
        };
      },
    };
    const { session, kernel } = await mount(driver);
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    expect(session.openHandles).toBe(1);
    await session.destroy();
    expect(closed).toBe(1);
    expect(session.openHandles).toBe(0);
    expect(session.inodes.size).toBe(1);
    void file;
  });

  it("is idempotent", async () => {
    const { session } = await mount();
    await session.destroy();
    await session.destroy();
    expect(session.destroyed).toBe(true);
  });
});

describe("node:fs passthrough smoke test", () => {
  let root: string | undefined;

  afterEach(async () => {
    if (root !== undefined) {
      await rm(root, { recursive: true, force: true });
      root = undefined;
    }
  });

  it("runs the same sequence against a real directory", async () => {
    root = await mkdtemp(join(tmpdir(), "mountx-session-"));
    const { session, kernel } = await mount(createNodeFsDriver(root), { attrTimeout: 1 });

    const dir = await kernel.mkdir(FUSE_ROOT_ID, "sub", 0o755);
    const file = await kernel.create(dir.nodeid, "file.txt", O_CREAT_RDWR, 0o644);
    expect(await kernel.write(file.entry.nodeid, file.open.fh, 0, "on disk")).toBe(7);
    expect(decoder.decode(await kernel.read(file.entry.nodeid, file.open.fh, 0, 64))).toBe(
      "on disk",
    );
    await kernel.fsync(file.entry.nodeid, file.open.fh);
    await kernel.release(file.entry.nodeid, file.open.fh);

    const opened = await kernel.opendir(dir.nodeid);
    expect(await kernel.readdirAll(dir.nodeid, opened.fh, 4096, true)).toEqual([
      ".",
      "..",
      "file.txt",
    ]);
    await kernel.releasedir(dir.nodeid, opened.fh);

    // Hardlinks over a real filesystem: identity comes from the host's `ino`.
    const linked = await kernel.link(file.entry.nodeid, FUSE_ROOT_ID, "same.txt");
    expect(linked.nodeid).toBe(file.entry.nodeid);
    expect(linked.attr.nlink).toBe(2);

    await kernel.rename(dir.nodeid, "file.txt", FUSE_ROOT_ID, "moved.txt");
    expect(session.inodes.pathOf(session.inodes.get(file.entry.nodeid)!)).toMatch(
      /^\/(moved|same)\.txt$/,
    );

    const statfs = await kernel.statfs();
    expect(statfs.blocks).toBeGreaterThan(0n);

    await kernel.unlink(FUSE_ROOT_ID, "moved.txt");
    await kernel.unlink(FUSE_ROOT_ID, "same.txt");
    await kernel.rmdir(FUSE_ROOT_ID, "sub");
    await kernel.destroy();
    expectHealthy(session);
  });
});

describe("concurrency", () => {
  it("handles many in-flight requests without serializing them", async () => {
    const { session, kernel } = await mount();
    const entries = await Promise.all(
      Array.from({ length: 32 }, (_, index) =>
        kernel.create(FUSE_ROOT_ID, `p${index}`, O_CREAT_RDWR, 0o644),
      ),
    );
    const written = await Promise.all(
      entries.map((entry, index) =>
        kernel.write(entry.entry.nodeid, entry.open.fh, 0, `#${index}`),
      ),
    );
    expect(written.every((bytes) => bytes >= 2)).toBe(true);

    const read = await Promise.all(
      entries.map((entry) => kernel.read(entry.entry.nodeid, entry.open.fh, 0, 16)),
    );
    expect(read.map((bytes) => decoder.decode(bytes))).toEqual(
      entries.map((_, index) => `#${index}`),
    );

    await Promise.all(entries.map((entry) => kernel.release(entry.entry.nodeid, entry.open.fh)));
    // 32 distinct nodeids, all distinct paths.
    const nodeids = new Set(entries.map((entry) => entry.entry.nodeid));
    expect(nodeids.size).toBe(32);
    expectHealthy(session);
  });

  it("answers every request exactly once under a mixed load", async () => {
    const { session, kernel } = await mount();
    const dir = await kernel.mkdir(FUSE_ROOT_ID, "mixed");
    const file: FuseEntryOut = (await kernel.create(dir.nodeid, "f", O_CREAT_RDWR, 0o644)).entry;
    const before = session.stats.requests;

    await Promise.all([
      kernel.getattr(FUSE_ROOT_ID),
      kernel.getattr(dir.nodeid),
      kernel.lookup(dir.nodeid, "f"),
      kernel.statfs(),
      kernel.rename(dir.nodeid, "f", dir.nodeid, "g"),
      kernel.getattr(file.nodeid),
      kernel.opendir(dir.nodeid),
    ]);

    expect(session.stats.requests - before).toBe(7);
    expectHealthy(session);
  });
});

describe("malformed input", () => {
  it("drops a message with no usable header", async () => {
    const { session } = await mount();
    for (const bytes of [new Uint8Array(0), new Uint8Array(8), new Uint8Array(39)]) {
      expect(await session.handleMessage(bytes)).toBeNull();
    }
    expect(session.stats.dropped).toBe(3);
    expectHealthy(session);
  });

  it("drops a message whose unique is zero, which would read as a notification", async () => {
    const { session } = await mount();
    const message = encodeRequest({ opcode: FUSE_LOOKUP, unique: 0n, body: { name: "x" } });
    expect(await session.handleMessage(message)).toBeNull();
    expectHealthy(session);
  });

  it("answers -EINVAL when the body cannot be decoded", async () => {
    const { session, kernel } = await mount();
    // A LOOKUP whose name is not NUL-terminated.
    const reply = await kernel.raw(FUSE_LOOKUP, {
      nodeid: FUSE_ROOT_ID,
      payload: new Uint8Array([0x61, 0x62]),
    });
    expect(reply.error).toBe(-ERRNO_CODES.EINVAL);
    expectHealthy(session);
  });

  it("notices a duplicated unique still in flight", async () => {
    const { session, kernel } = await mount();
    const message = encodeRequest(
      { opcode: FUSE_GETATTR, unique: 7n, nodeid: FUSE_ROOT_ID, body: { getattrFlags: 0, fh: 0n } },
      session.protocol,
    );
    const [first, second] = await Promise.all([
      session.handleMessage(message),
      session.handleMessage(message),
    ]);
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(session.assertions).toHaveLength(1);
    expect(session.assertions[0]).toMatch(/already in flight/);
    void kernel;
  });
});

describe("driver quirks", () => {
  /** Resolve-on-demand, for tests that need to hold an operation open. */
  function gate(): { promise: Promise<void>; open: () => void } {
    let open!: () => void;
    const promise = new Promise<void>((resolve) => {
      open = resolve;
    });
    return { promise, open };
  }

  const tick = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

  /** Just enough of a directory for a driver that only answers about `/`. */
  function dirStats(): StatsLike {
    const always = (): boolean => false;
    return {
      dev: 0,
      ino: 1,
      mode: S_IFDIR | 0o755,
      nlink: 2,
      uid: 0,
      gid: 0,
      rdev: 0,
      size: 4096,
      blksize: 4096,
      blocks: 8,
      atimeMs: 0,
      mtimeMs: 0,
      ctimeMs: 0,
      birthtimeMs: 0,
      isFile: always,
      isDirectory: () => true,
      isSymbolicLink: always,
      isBlockDevice: always,
      isCharacterDevice: always,
      isFIFO: always,
      isSocket: always,
    };
  }

  it("falls back to stat for a driver with no lstat", async () => {
    const base = createMemoryDriver();
    const { lstat, ...withoutLstat } = base;
    void lstat;
    const { session, kernel } = await mount(withoutLstat as FsDriver);
    const dir = await kernel.mkdir(FUSE_ROOT_ID, "d");
    expect((await kernel.getattr(dir.nodeid)).attr.mode & S_IFMT).toBe(S_IFDIR);
    expectHealthy(session);
  });

  it("uses mountx.utimens when the driver has it", async () => {
    const base = createMemoryDriver();
    const seen: bigint[] = [];
    const driver: FsDriver = {
      ...base,
      mountx: {
        async utimens(_path, atimeNs, mtimeNs) {
          seen.push(atimeNs, mtimeNs);
        },
      },
    };
    const { session, kernel } = await mount(driver);
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.release(file.entry.nodeid, file.open.fh);
    await kernel.setattr(file.entry.nodeid, {
      valid: FATTR_ATIME | FATTR_MTIME,
      atime: 5n,
      atimensec: 123,
      mtime: 6n,
      mtimensec: 456,
    });
    // Nanoseconds survive, which is the whole point of the extension.
    expect(seen).toEqual([5_000_000_123n, 6_000_000_456n]);
    expectHealthy(session);
  });

  it("uses mountx.mknod when the driver has it", async () => {
    const base = createMemoryDriver();
    const calls: [string, number, number][] = [];
    const driver: FsDriver = {
      ...base,
      mountx: {
        async mknod(path, mode, dev) {
          calls.push([path, mode, dev]);
          await base.open(path, "wx", mode & 0o7777).then((handle) => handle.close());
        },
      },
    };
    const { session, kernel } = await mount(driver);
    await kernel.mknod(FUSE_ROOT_ID, "fifo", 0o010_600, 0);
    expect(calls).toEqual([["/fifo", 0o010_600, 0]]);
    expectHealthy(session);
  });

  it("maps every file type in a readdir listing", async () => {
    const types = [
      "File",
      "Directory",
      "SymbolicLink",
      "FIFO",
      "Socket",
      "BlockDevice",
      "CharacterDevice",
      "Unknown",
    ] as const;
    const driver: FsDriver = {
      stat: createMemoryDriver().stat,
      open: createMemoryDriver().open,
      async readdir() {
        return types.map((type) => ({
          name: type,
          isFile: () => type === "File",
          isDirectory: () => type === "Directory",
          isSymbolicLink: () => type === "SymbolicLink",
          isFIFO: () => type === "FIFO",
          isSocket: () => type === "Socket",
          isBlockDevice: () => type === "BlockDevice",
          isCharacterDevice: () => type === "CharacterDevice",
        }));
      },
      async lstat(path) {
        if (path === "/") {
          return dirStats();
        }
        // Every child "vanishes": no stat, so the page reports the name with no
        // identity rather than failing outright.
        throw Object.assign(new Error("ENOENT"), { code: "ENOENT", errno: -2 });
      },
    };
    const { session, kernel } = await mount(driver);
    const opened = await kernel.opendir(FUSE_ROOT_ID);
    const page = await kernel.readdir(FUSE_ROOT_ID, opened.fh, 0n, 4096);
    const seen = new Map(page.entries.map((entry) => [entry.name, entry.type]));
    // DT_REG 8, DT_DIR 4, DT_LNK 10, DT_FIFO 1, DT_SOCK 12, DT_BLK 6, DT_CHR 2.
    expect(seen.get("File")).toBe(8);
    expect(seen.get("Directory")).toBe(4);
    expect(seen.get("SymbolicLink")).toBe(10);
    expect(seen.get("FIFO")).toBe(1);
    expect(seen.get("Socket")).toBe(12);
    expect(seen.get("BlockDevice")).toBe(6);
    expect(seen.get("CharacterDevice")).toBe(2);
    expect(seen.get("Unknown")).toBe(0);
    expect(seen.get(".")).toBe(4);
    // A vanished entry gets `ino: 0` and, under READDIRPLUS, no nodeid.
    const plus = await kernel.readdirplus(FUSE_ROOT_ID, opened.fh, 0n, 8192);
    expect(plus.entries.every((entry) => entry.entry.nodeid === 0n)).toBe(true);
    expectHealthy(session);
  });

  it("makes a reader wait for a rename in flight", async () => {
    const base = createMemoryDriver();
    const held = gate();
    const driver: FsDriver = {
      ...base,
      async rename(from, to) {
        await held.promise;
        return base.rename(from, to);
      },
    };
    const { session, kernel } = await mount(driver);
    const dir = await kernel.mkdir(FUSE_ROOT_ID, "dir");
    await kernel.create(dir.nodeid, "file", O_CREAT_RDWR, 0o644);

    const renaming = kernel.rename(FUSE_ROOT_ID, "dir", FUSE_ROOT_ID, "moved");
    await tick();
    let done = false;
    const looking = kernel.lookup(dir.nodeid, "file").finally(() => {
      done = true;
    });
    await tick();
    // The rename holds the writer lock, so the lookup cannot have resolved a
    // path yet — which is exactly what stops it binding a stale one.
    expect(done).toBe(false);

    held.open();
    await renaming;
    const found = await looking;
    expect(session.inodes.pathOf(session.inodes.get(found.nodeid)!)).toBe("/moved/file");
    expectHealthy(session);
  });

  it("honours a zero attr timeout", async () => {
    const { session, kernel } = await mount(undefined, { attrTimeout: 0, entryTimeout: 0.5 });
    const attr = await kernel.getattr(FUSE_ROOT_ID);
    expect(attr.attrValid).toBe(0n);
    expect(attr.attrValidNsec).toBe(0);
    const entry = await kernel.mkdir(FUSE_ROOT_ID, "d");
    expect(entry.entryValid).toBe(0n);
    expect(entry.entryValidNsec).toBe(500_000_000);
    expectHealthy(session);
  });

  it("opens through a driver with no per-open state", async () => {
    const base = createMemoryDriver();
    const driver: FsDriver = { ...base, capabilities: { handles: false } };
    const { session, kernel } = await mount(driver);
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.release(file.entry.nodeid, file.open.fh);
    const opened = await kernel.open(file.entry.nodeid, O_RDWR);
    expect(await kernel.write(file.entry.nodeid, opened.fh, 0, "reopened")).toBe(8);
    await kernel.fsync(file.entry.nodeid, opened.fh, true);
    await kernel.release(file.entry.nodeid, opened.fh);
    expectHealthy(session);
  });

  it("is constructible through the factory", async () => {
    const session = createFuseSession(createMemoryDriver(), { keepCache: false });
    const kernel = new SyntheticKernel(session);
    await kernel.init();
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    expect(file.open.openFlags).toBe(0);
    expectHealthy(session);
  });
});

/**
 * `FLUSH`, and the two ways a driver that declares `durableWrites` can decline
 * to be asked about it.
 *
 * The point of every case here is the *exactly*: neither mechanism may appear
 * for a driver that has not claimed the capability, and neither may appear for
 * the wrong mechanism — a mount that asked for `FOPEN_NOFLUSH` and got a
 * `-ENOSYS` instead would be a different promise about `close(2)` than the one
 * it made. Both are checked in both directions.
 */
describe("declining FLUSH", () => {
  /** The memory driver, with the one claim this file is about added. */
  function durableDriver(): FsDriver {
    const base = createMemoryDriver();
    return { ...base, capabilities: { ...base.capabilities, durableWrites: true } };
  }

  function flush(kernel: SyntheticKernel, nodeid: bigint, fh: bigint): Promise<RawReply> {
    return kernel.raw(FUSE_FLUSH, { nodeid, body: { fh, lockOwner: 0n } });
  }

  it("answers FLUSH, with no FOPEN_NOFLUSH, when the capability is absent", async () => {
    // Both mechanisms named explicitly: the option is not the opt-in, and on
    // its own it must change nothing at all.
    for (const flushMechanism of [undefined, "enosys", "noflush"] as const) {
      const { session, kernel } = await mount(undefined, { flushMechanism });
      const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
      expect(file.open.openFlags).toBe(FOPEN_KEEP_CACHE);
      const reply = await flush(kernel, file.entry.nodeid, file.open.fh);
      expect(reply.error).toBe(0);
      expectHealthy(session);
    }
  });

  it("answers -ENOSYS once the driver claims durableWrites", async () => {
    const { session, kernel } = await mount(durableDriver(), { flushMechanism: "enosys" });
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    // The other mechanism is not also applied: one lever, not two.
    expect(file.open.openFlags).toBe(FOPEN_KEEP_CACHE);
    const reply = await flush(kernel, file.entry.nodeid, file.open.fh);
    expect(reply.error).toBe(-ERRNO_CODES.ENOSYS);
    // Still a working file afterwards: this says nothing about the fh.
    expect(await kernel.write(file.entry.nodeid, file.open.fh, 0, "still open")).toBe(10);
    await kernel.release(file.entry.nodeid, file.open.fh);
    expectHealthy(session);
  });

  it("is the default mechanism", async () => {
    expect(DEFAULT_FLUSH_MECHANISM).toBe("enosys");
    const { session, kernel } = await mount(durableDriver());
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    expect(file.open.openFlags).toBe(FOPEN_KEEP_CACHE);
    expect((await flush(kernel, file.entry.nodeid, file.open.fh)).error).toBe(-ERRNO_CODES.ENOSYS);
    expectHealthy(session);
  });

  it("answers -ENOSYS for an unknown fh, where success would answer -EBADF", async () => {
    // `-ENOSYS` is about the opcode, so it cannot be conditional on the fh:
    // an `EBADF` here is not "unimplemented", and the kernel would go on
    // sending `FLUSH` for the life of the mount.
    const declined = await mount(durableDriver(), { flushMechanism: "enosys" });
    expect((await flush(declined.kernel, FUSE_ROOT_ID, 4242n)).error).toBe(-ERRNO_CODES.ENOSYS);
    expectHealthy(declined.session);

    const answered = await mount();
    expect((await flush(answered.kernel, FUSE_ROOT_ID, 4242n)).error).toBe(-ERRNO_CODES.EBADF);
    expectHealthy(answered.session);
  });

  it("sets FOPEN_NOFLUSH on OPEN and CREATE, and on neither a directory nor FLUSH itself", async () => {
    const { session, kernel } = await mount(durableDriver(), { flushMechanism: "noflush" });
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    expect(file.open.openFlags).toBe(FOPEN_KEEP_CACHE | FOPEN_NOFLUSH);
    await kernel.release(file.entry.nodeid, file.open.fh);

    const opened = await kernel.open(file.entry.nodeid, O_RDWR);
    expect(opened.openFlags).toBe(FOPEN_KEEP_CACHE | FOPEN_NOFLUSH);
    // The kernel decides on its own not to send `FLUSH`; if one arrives anyway
    // — an older kernel, or `writeback_cache` — it is still answered.
    expect((await flush(kernel, file.entry.nodeid, opened.fh)).error).toBe(0);
    await kernel.release(file.entry.nodeid, opened.fh);

    const dir = await kernel.mkdir(FUSE_ROOT_ID, "d");
    const handle = await kernel.opendir(dir.nodeid);
    expect(handle.openFlags).toBe(0);
    await kernel.releasedir(dir.nodeid, handle.fh);
    expectHealthy(session);
  });

  it("keeps FOPEN_NOFLUSH off a kernel older than 7.35", async () => {
    for (const [minor, expected] of [
      [34, FOPEN_KEEP_CACHE],
      [35, FOPEN_KEEP_CACHE | FOPEN_NOFLUSH],
    ] as const) {
      const { session, kernel } = makeSession(durableDriver(), { flushMechanism: "noflush" });
      await kernel.init({ minor });
      const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
      expect(file.open.openFlags).toBe(expected);
      expectHealthy(session);
    }
  });

  it("leaves keepCache: false alone in either mechanism", async () => {
    const noflush = await mount(durableDriver(), {
      flushMechanism: "noflush",
      keepCache: false,
    });
    const one = await noflush.kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    expect(one.open.openFlags).toBe(FOPEN_NOFLUSH);

    const enosys = await mount(durableDriver(), { flushMechanism: "enosys", keepCache: false });
    const two = await enosys.kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    expect(two.open.openFlags).toBe(0);
    expectHealthy(noflush.session);
    expectHealthy(enosys.session);
  });

  it("resolves the capability as declared-only", () => {
    // Nothing about a driver's shape may switch this on: the memory driver has
    // `sync` and `datasync` on every handle and still resolves `false`.
    expect(createLoopback(createMemoryDriver()).capabilities.durableWrites).toBe(false);
    expect(createLoopback(durableDriver()).capabilities.durableWrites).toBe(true);
  });
});

describe("version negotiation over the wire", () => {
  it("asks a newer kernel to try again, then serves the second INIT", async () => {
    const { session, kernel } = makeSession();
    // A kernel speaking a major we do not know is answered with ours and
    // nothing else; the session stays un-negotiated until a usable INIT lands.
    const retry = await kernel.call<FuseInitOut>(FUSE_INIT, {
      nodeid: 0n,
      body: { major: 8, minor: 0, maxReadahead: 0, flags: 0, flags2: 0 },
    });
    expect(retry.major).toBe(7);
    expect(session.negotiated).toBeUndefined();

    const agreed = await kernel.init();
    expect(agreed.minor).toBe(41);
    expect(session.negotiated).toBeDefined();
    expectHealthy(session);
  });

  it("serves a kernel whose minor is below our own", async () => {
    // Regression: the `INIT` reply was encoded with no protocol context, which
    // `encodeReplyBody` reads as 7.41, and `encodeInitOut` refuses a context
    // that disagrees with the `minor` in the value — so *every* handshake that
    // settled below 7.41 came back `-EIO` and the mount never started.
    const { session, kernel } = makeSession();
    const reply = await kernel.init({ minor: 34 });
    expect(reply.minor).toBe(34);
    expect(session.protocol?.minor).toBe(34);
    const entry = await kernel.mkdir(FUSE_ROOT_ID, "d");
    expect(entry.nodeid).not.toBe(0n);
    expectHealthy(session);
  });

  it("refuses a kernel older than 7.0", async () => {
    const { session, kernel } = makeSession();
    const reply = await kernel.raw(FUSE_INIT, {
      nodeid: 0n,
      body: { major: 6, minor: 9, maxReadahead: 0, flags: 0, flags2: 0 },
    });
    expect(reply.error).toBe(-ERRNO_CODES.EPROTO);
    expect(session.negotiated).toBeUndefined();
    expectHealthy(session);
  });
});

describe("defensive paths", () => {
  it("survives a driver that reports nonsense timestamps", async () => {
    const base = createMemoryDriver();
    const driver: FsDriver = {
      ...base,
      async lstat(path) {
        return {
          ...(await base.lstat(path)),
          atimeMs: Number.NaN,
          mtimeMs: Number.POSITIVE_INFINITY,
        };
      },
    };
    const { session, kernel } = await mount(driver);
    // `BigInt(NaN)` throws, so a naive conversion would turn every getattr into
    // an EIO. Both stamps land on the epoch instead.
    const attr = await kernel.getattr(FUSE_ROOT_ID);
    expect(attr.attr.atime).toBe(0n);
    expect(attr.attr.mtime).toBe(0n);
    expect(attr.attr.atimensec).toBe(0);
    expectHealthy(session);
  });

  it("still replies when the error logger itself throws", async () => {
    const base = createMemoryDriver();
    const driver: FsDriver = {
      ...base,
      async mkdir() {
        throw Object.assign(new Error("no"), { code: "EACCES", errno: -13 });
      },
    };
    const { session, kernel } = await mount(driver, {
      onError: () => {
        throw new Error("the logger is broken too");
      },
    });
    await expect(kernel.mkdir(FUSE_ROOT_ID, "d")).rejects.toMatchObject({ code: "EACCES" });
    expectHealthy(session);
  });

  it("rolls the open back when the entry cannot be bound after CREATE", async () => {
    const base = createMemoryDriver();
    let closed = 0;
    const driver: FsDriver = {
      ...base,
      async open(path, flags, mode) {
        const handle = await base.open(path, flags, mode);
        return {
          ...handle,
          read: handle.read.bind(handle),
          write: handle.write.bind(handle),
          stat: handle.stat.bind(handle),
          truncate: handle.truncate.bind(handle),
          async close() {
            closed++;
            await handle.close();
          },
        };
      },
      async lstat(path) {
        if (path === "/doomed") {
          throw Object.assign(new Error("gone"), { code: "ENOENT", errno: -2 });
        }
        return base.lstat(path);
      },
    };
    const { session, kernel } = await mount(driver);
    await expect(kernel.create(FUSE_ROOT_ID, "doomed", O_CREAT_RDWR, 0o644)).rejects.toMatchObject({
      code: "ENOENT",
    });
    // No leaked handle, and no half-registered fh.
    expect(closed).toBe(1);
    expect(session.openHandles).toBe(0);
    expectHealthy(session);
  });

  it("reports, but does not fail on, a close that throws", async () => {
    const base = createMemoryDriver();
    const seen: unknown[] = [];
    const driver: FsDriver = {
      ...base,
      capabilities: { handles: false },
      async open(path, flags, mode) {
        const handle = await base.open(path, flags, mode);
        return {
          ...handle,
          read: handle.read.bind(handle),
          write: handle.write.bind(handle),
          stat: handle.stat.bind(handle),
          truncate: handle.truncate.bind(handle),
          async close() {
            throw new Error("close failed");
          },
        };
      },
    };
    const { session, kernel } = await mount(driver, { onError: (error) => seen.push(error) });
    // Even the CREATE's own probe-open cannot be closed, and the request still
    // succeeds: a failed close is a diagnostic, not a reason to fail the write.
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    expect(await kernel.write(file.entry.nodeid, file.open.fh, 0, "written")).toBe(7);
    expect(seen.length).toBeGreaterThan(0);
    expectHealthy(session);
  });

  it("swallows close failures during teardown", async () => {
    const base = createMemoryDriver();
    const seen: unknown[] = [];
    const driver: FsDriver = {
      ...base,
      async open(path, flags, mode) {
        const handle = await base.open(path, flags, mode);
        return {
          ...handle,
          read: handle.read.bind(handle),
          write: handle.write.bind(handle),
          stat: handle.stat.bind(handle),
          truncate: handle.truncate.bind(handle),
          async close() {
            throw new Error("close failed");
          },
        };
      },
    };
    const { session, kernel } = await mount(driver, { onError: (error) => seen.push(error) });
    await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await expect(session.destroy()).resolves.toBeUndefined();
    expect(seen).toHaveLength(1);
    expect(session.openHandles).toBe(0);
  });
});

describe("the open-then-unlink idiom", () => {
  /**
   * `exec 3<f; rm f; cat <&3` — and `mkstemp` + `unlink`, and `sort`, and
   * `tempfile.TemporaryFile`. Linux's `fuse_getattr` / `fuse_setattr` are
   * `inode_operations` hooks: a plain `fstat(2)` or `ftruncate(2)` on the open
   * fd arrives with **no** `FUSE_GETATTR_FH` / `FATTR_FH` and no usable path,
   * so answering `ENOENT` there breaks all of them.
   */
  it("answers a bare GETATTR through the open handle", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "tmp", O_CREAT_RDWR, 0o600);
    const nodeid = file.entry.nodeid;
    await kernel.write(nodeid, file.open.fh, 0, "0123456789");
    await kernel.unlink(FUSE_ROOT_ID, "tmp");
    expect(session.inodes.get(nodeid)?.paths.size).toBe(0);

    // No FH flag, no path — and it must still work.
    const attr = await kernel.getattr(nodeid);
    expect(attr.attr.size).toBe(10n);
    expect(attr.attr.mode & S_IFMT).toBe(S_IFREG);

    await kernel.release(nodeid, file.open.fh);
    // Once the last handle is gone there is genuinely nothing left to stat.
    await expect(kernel.getattr(nodeid)).rejects.toMatchObject({ code: "ENOENT" });
    expectHealthy(session);
  });

  it("answers a bare SETATTR size through the open handle", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "tmp", O_CREAT_RDWR, 0o600);
    const nodeid = file.entry.nodeid;
    await kernel.write(nodeid, file.open.fh, 0, "0123456789");
    await kernel.unlink(FUSE_ROOT_ID, "tmp");

    // `ftruncate(fd, 4)` with no FATTR_FH, which is what the kernel sends.
    const attr = await kernel.setattr(nodeid, { valid: FATTR_SIZE, size: 4n });
    expect(attr.attr.size).toBe(4n);
    expect(decoder.decode(await kernel.read(nodeid, file.open.fh, 0, 64))).toBe("0123");

    await kernel.release(nodeid, file.open.fh);
    expectHealthy(session);
  });

  it("does not let a stale handle shadow a path that still exists", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "one", O_CREAT_RDWR, 0o644);
    const nodeid = file.entry.nodeid;
    await kernel.link(nodeid, FUSE_ROOT_ID, "two");
    await kernel.unlink(FUSE_ROOT_ID, "one");
    // Still reachable by `/two`, so the path stays authoritative: `nlink` comes
    // from the namespace, and a handle would not know about the second name.
    expect((await kernel.getattr(nodeid)).attr.nlink).toBe(1);
    expect(session.inodes.pathOf(session.inodes.get(nodeid)!)).toBe("/two");
    await kernel.release(nodeid, file.open.fh);
    expectHealthy(session);
  });
});

describe("O_TRUNC", () => {
  it("empties an existing file on open", async () => {
    const { session, kernel } = await mount();
    const created = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.write(created.entry.nodeid, created.open.fh, 0, "old contents");
    await kernel.release(created.entry.nodeid, created.open.fh);

    // `> f`: the kernel hands O_TRUNC over because FUSE_ATOMIC_O_TRUNC is
    // negotiated, and expects the file to be empty by the time OPEN replies.
    const opened = await kernel.open(created.entry.nodeid, O_WRONLY | O_TRUNC);
    expect((await kernel.getattr(created.entry.nodeid)).attr.size).toBe(0n);
    await kernel.release(created.entry.nodeid, opened.fh);
    expectHealthy(session);
  });

  it("empties it even for a driver whose open ignores the flag", async () => {
    const base = createMemoryDriver();
    const driver: FsDriver = {
      ...base,
      // Strips O_TRUNC on the way through, as a driver that never thought
      // about it would. `node:fs`'s O_TRUNC, not the wire's: this is a driver,
      // and the session has already translated.
      open: (path, flags, mode) =>
        base.open(path, typeof flags === "number" ? flags & ~constants.O_TRUNC : flags, mode),
    };
    const { session, kernel } = await mount(driver);
    const created = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.write(created.entry.nodeid, created.open.fh, 0, "old contents");
    await kernel.release(created.entry.nodeid, created.open.fh);

    const opened = await kernel.open(created.entry.nodeid, O_RDWR | O_TRUNC);
    expect((await kernel.getattr(created.entry.nodeid)).attr.size).toBe(0n);
    await kernel.release(created.entry.nodeid, opened.fh);
    expectHealthy(session);
  });
});

/**
 * A driver with no per-open state re-opens from the path for every operation,
 * so what it re-opens *with* is data. The creation flags acted once, at the
 * open the kernel holds the `fh` for; carrying them into a re-open makes every
 * subsequent operation redo them.
 */
describe("re-open, for a driver with no per-open state", () => {
  const pathOnly = (): FsDriver => {
    const base = createMemoryDriver();
    return { ...base, capabilities: { ...base.capabilities, handles: false } };
  };

  it("does not repeat O_EXCL, which would fail every write to a new file", async () => {
    const { session, kernel } = await mount(pathOnly());
    const created = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT | O_EXCL | O_RDWR, 0o644);
    expect(await kernel.write(created.entry.nodeid, created.open.fh, 0, "hello")).toBe(5);
    await kernel.release(created.entry.nodeid, created.open.fh);
    expectHealthy(session);
  });

  it("does not repeat O_TRUNC, which would empty the file before every write", async () => {
    const { session, kernel } = await mount(pathOnly());
    const created = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.release(created.entry.nodeid, created.open.fh);

    const opened = await kernel.open(created.entry.nodeid, O_WRONLY | O_TRUNC);
    await kernel.write(created.entry.nodeid, opened.fh, 0, "aaaa");
    await kernel.write(created.entry.nodeid, opened.fh, 4, "bbbb");
    await kernel.release(created.entry.nodeid, opened.fh);

    const reader = await kernel.open(created.entry.nodeid, O_RDWR);
    const bytes = await kernel.read(created.entry.nodeid, reader.fh, 0, 16);
    expect(decoder.decode(bytes)).toBe("aaaabbbb");
    await kernel.release(created.entry.nodeid, reader.fh);
    expectHealthy(session);
  });

  it("still truncates once, at the open that asked for it", async () => {
    const { session, kernel } = await mount(pathOnly());
    const created = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.write(created.entry.nodeid, created.open.fh, 0, "old contents");
    await kernel.release(created.entry.nodeid, created.open.fh);

    const opened = await kernel.open(created.entry.nodeid, O_WRONLY | O_TRUNC);
    expect((await kernel.getattr(created.entry.nodeid)).attr.size).toBe(0n);
    await kernel.release(created.entry.nodeid, opened.fh);
    expectHealthy(session);
  });
});

describe("negative lookups", () => {
  it("answers ENOENT by default, so an out-of-band create shows up at once", async () => {
    const { session, kernel } = await mount();
    await expect(kernel.lookup(FUSE_ROOT_ID, "missing")).rejects.toMatchObject({ code: "ENOENT" });
    expectHealthy(session);
  });

  it("caches the miss when a timeout is configured", async () => {
    const { session, kernel } = await mount(undefined, { negativeTimeout: 2.5 });
    const reply = await kernel.raw(FUSE_LOOKUP, {
      nodeid: FUSE_ROOT_ID,
      body: { name: "missing" },
    });
    expect(reply.error).toBe(0);
    const entry = reply.body as FuseEntryOut;
    // `nodeid: 0` is "nothing here"; the kernel caches that for entry_valid.
    expect(entry.nodeid).toBe(0n);
    expect(entry.entryValid).toBe(2n);
    expect(entry.entryValidNsec).toBe(500_000_000);
    // No inode was minted for a file that does not exist.
    expect(session.inodes.size).toBe(1);

    // Anything that is not "not found" is still a real error.
    await expect(kernel.lookup(999n, "x")).rejects.toMatchObject({ code: "ESTALE" });
    expectHealthy(session);
  });
});

describe("read budget", () => {
  it("clamps a reply to the negotiated page budget, not to max_write", async () => {
    // One page of max_write, so max_pages is 1 and the read budget with it.
    const { session, kernel } = await mount(undefined, { init: { maxWrite: 4096 } });
    expect(session.negotiated?.maxPages).toBe(1);

    const file = await kernel.create(FUSE_ROOT_ID, "big", O_CREAT_RDWR, 0o644);
    const payload = new Uint8Array(16 * 1024).fill(0x61);
    await kernel.write(file.entry.nodeid, file.open.fh, 0, payload);

    const page = await kernel.read(file.entry.nodeid, file.open.fh, 0, 64 * 1024);
    expect(page).toHaveLength(4096);
    // Resuming picks up exactly where the budget cut it off — a short reply is
    // a budget, never an EOF.
    const next = await kernel.read(file.entry.nodeid, file.open.fh, 4096, 64 * 1024);
    expect(next).toHaveLength(4096);
    await kernel.release(file.entry.nodeid, file.open.fh);
    expectHealthy(session);
  });

  it("uses the full 256 pages at the defaults", async () => {
    const { session, kernel } = await mount();
    expect(session.negotiated?.maxPages).toBe(256);
    const file = await kernel.create(FUSE_ROOT_ID, "big", O_CREAT_RDWR, 0o644);
    await kernel.write(file.entry.nodeid, file.open.fh, 0, new Uint8Array(300 * 1024).fill(1));
    const all = await kernel.read(file.entry.nodeid, file.open.fh, 0, 4 * 1024 * 1024);
    expect(all).toHaveLength(300 * 1024);
    await kernel.release(file.entry.nodeid, file.open.fh);
    expectHealthy(session);
  });
});

describe("teardown without DESTROY", () => {
  /**
   * A `-t fuse` mount never sends `FUSE_DESTROY` — it is `fuseblk`-only — so
   * `umount(8)` just stops the device and the transport calls `destroy()` when
   * the fd hits EOF. That path has to be as complete as the DESTROY one.
   */
  it("cleans up when the transport tears down instead of the kernel", async () => {
    const { session, kernel } = await mount();
    const file = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.lookup(FUSE_ROOT_ID, "f");
    expect(session.destroyed).toBe(false);
    expect(session.openHandles).toBe(1);

    // No DESTROY ever arrives; the transport notices EOF and says so.
    await session.destroy();

    expect(session.destroyed).toBe(true);
    expect(session.openHandles).toBe(0);
    expect(session.inodes.size).toBe(1);
    // Anything still in the kernel's pipeline is answered, not dropped.
    const late = await kernel.raw(FUSE_GETATTR, {
      nodeid: file.entry.nodeid,
      body: { getattrFlags: 0, fh: 0n },
    });
    expect(late.error).toBe(-ERRNO_CODES.ENODEV);
    await expect(session.destroy()).resolves.toBeUndefined();
    expectHealthy(session);
  });
});

describe("fix regressions", () => {
  /** Wrap a memory driver's handles, overriding whichever methods a test needs. */
  function wrapHandles(
    base: ReturnType<typeof createMemoryDriver>,
    override: (handle: Awaited<ReturnType<typeof base.open>>) => Record<string, unknown>,
  ): FsDriver {
    return {
      ...base,
      async open(path, flags, mode) {
        const handle = await base.open(path, flags, mode);
        return {
          ...handle,
          read: handle.read.bind(handle),
          write: handle.write.bind(handle),
          stat: handle.stat.bind(handle),
          truncate: handle.truncate.bind(handle),
          close: handle.close.bind(handle),
          ...override(handle),
        } as Awaited<ReturnType<typeof base.open>>;
      },
    };
  }

  it("does not leak the handle when an O_TRUNC open cannot truncate", async () => {
    const base = createMemoryDriver();
    let closed = 0;
    const driver = wrapHandles(base, (handle) => ({
      truncate: async () => {
        throw Object.assign(new Error("nope"), { code: "EACCES", errno: -13 });
      },
      close: async () => {
        closed++;
        await handle.close();
      },
    }));
    const { session, kernel } = await mount(driver);
    const created = await kernel.create(FUSE_ROOT_ID, "f", O_CREAT_RDWR, 0o644);
    await kernel.release(created.entry.nodeid, created.open.fh);
    const before = closed;

    await expect(kernel.open(created.entry.nodeid, O_WRONLY | O_TRUNC)).rejects.toMatchObject({
      code: "EACCES",
    });

    // The open never yielded an fh, so nothing would ever have released it.
    expect(closed).toBe(before + 1);
    expect(session.openHandles).toBe(0);
    expectHealthy(session);
  });

  it("does not fail a valid fh because a rename was in flight", async () => {
    // `handles: false`, so every read re-opens by path — the one place a data
    // op still touches the path map.
    const base = createMemoryDriver();
    let held: (() => void) | undefined;
    const opening = new Promise<void>((resolve) => {
      held = resolve;
    });
    let gateOpens = false;
    const driver: FsDriver = {
      ...base,
      capabilities: { handles: false },
      async open(path, flags, mode) {
        if (gateOpens) {
          await opening;
        }
        return base.open(path, flags, mode);
      },
    };
    const { session, kernel } = await mount(driver);
    const dir = await kernel.mkdir(FUSE_ROOT_ID, "dir");
    const file = await kernel.create(dir.nodeid, "f", O_CREAT_RDWR, 0o644);
    await kernel.write(file.entry.nodeid, file.open.fh, 0, "payload");

    gateOpens = true;
    const reading = kernel.read(file.entry.nodeid, file.open.fh, 0, 64);
    await new Promise((resolve) => setImmediate(resolve));
    // The read is parked inside the driver's open, holding the reader lock.
    const renaming = kernel.rename(FUSE_ROOT_ID, "dir", FUSE_ROOT_ID, "moved");
    await new Promise((resolve) => setImmediate(resolve));

    held!();
    expect(decoder.decode(await reading)).toBe("payload");
    await renaming;
    expect(session.inodes.pathOf(session.inodes.get(file.entry.nodeid)!)).toBe("/moved/f");
    expectHealthy(session);
  });
});
