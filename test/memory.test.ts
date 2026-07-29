import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import { createLoopback } from "../src/harness.ts";

describe("memory driver", () => {
  it("applies umask and ownership options", async () => {
    const fs = createLoopback(createMemoryDriver({ uid: 501, gid: 20, umask: 0o077 }));
    await fs.mkdir("/dir");
    await fs.writeFile("/file", "x");
    const dir = await fs.stat("/dir");
    const file = await fs.stat("/file");
    expect(dir.mode & 0o777).toBe(0o700);
    expect(file.mode & 0o777).toBe(0o600);
    expect(file.uid).toBe(501);
    expect(file.gid).toBe(20);
  });

  it("applies no umask unless one is asked for", async () => {
    // The default is `0`, and that is a decision rather than an oversight: a
    // umask belongs to a process, and under a mount the kernel has already
    // applied the *caller's* before the mode reaches `FUSE_MKDIR`/`FUSE_CREATE`.
    // Masking again used the daemon's value and produced modes nobody asked
    // for — `create f 04777` arriving as `04755` (pjdfstest `chmod/12.t`).
    const fs = createLoopback(createMemoryDriver());
    await fs.mkdir("/dir", { mode: 0o755 });
    await fs.mkdir("/wide", { mode: 0o777 });
    const handle = await fs.open("/file", "w", 0o666);
    await handle.close();
    expect((await fs.stat("/dir")).mode & 0o777).toBe(0o755);
    expect((await fs.stat("/wide")).mode & 0o777).toBe(0o777);
    expect((await fs.stat("/file")).mode & 0o777).toBe(0o666);
  });

  it("rejects a file larger than memory with EFBIG, not EIO", async () => {
    // `new Uint8Array(1e15)` throws a `RangeError`, which a transport can only
    // turn into `EIO` — an errno that tells the caller nothing. Every
    // filesystem has a maximum file size and says `EFBIG` past it.
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/f", "x");
    await expect(fs.truncate("/f", 1e15)).rejects.toMatchObject({ code: "EFBIG" });
    const handle = await fs.open("/f", "r+");
    await expect(handle.truncate(1e15)).rejects.toMatchObject({ code: "EFBIG" });
    await handle.close();
    // ...and the file it refused to grow is untouched.
    expect((await fs.stat("/f")).size).toBe(1);
  });

  it("counts directory links", async () => {
    const fs = createLoopback(createMemoryDriver());
    expect((await fs.stat("/")).nlink).toBe(2);
    await fs.mkdir("/a");
    await fs.mkdir("/b");
    expect((await fs.stat("/")).nlink).toBe(4);
    await fs.rmdir("/b");
    expect((await fs.stat("/")).nlink).toBe(3);
  });

  it("accounts for used blocks in statfs", async () => {
    const fs = createLoopback(createMemoryDriver());
    const before = await fs.statfs("/");
    await fs.writeFile("/file", "x".repeat(64 * 1024));
    const after = await fs.statfs("/");
    expect(before.bfree - after.bfree).toBe(16);
    expect(after.ffree).toBe(before.ffree - 1);
  });

  it("keeps the statfs totals in step with every mutation", async () => {
    // `statfs` answers from running counters rather than a whole-tree walk, so
    // the risk moved from cost to drift: every path that adds a node, drops the
    // last entry naming one, or changes a file's length has to be accounted
    // for. Each step below is checked against what the walk would have said.
    const fs = createLoopback(createMemoryDriver());
    const used = async (): Promise<{ blocks: number; nodes: number }> => {
      const stats = await fs.statfs("/");
      return { blocks: stats.blocks - stats.bfree, nodes: stats.files - stats.ffree };
    };
    // The root: one node, one block.
    expect(await used()).toEqual({ blocks: 1, nodes: 1 });

    await fs.mkdir("/d");
    await fs.writeFile("/d/f", "x".repeat(8192));
    expect(await used()).toEqual({ blocks: 4, nodes: 3 });

    // Shrinking gives the blocks back; growing through a handle takes them.
    await fs.truncate("/d/f", 0);
    expect(await used()).toEqual({ blocks: 2, nodes: 3 });
    const handle = await fs.open("/d/f", "r+");
    await handle.write(new Uint8Array(4096), 0, 4096, 0);
    expect(await used()).toEqual({ blocks: 3, nodes: 3 });

    // A second link is not a second node, and dropping one of two frees nothing.
    await fs.link("/d/f", "/hard");
    expect(await used()).toEqual({ blocks: 3, nodes: 3 });
    await fs.unlink("/hard");
    expect(await used()).toEqual({ blocks: 3, nodes: 3 });

    // Unlinked but still open: gone from the tree, so gone from `statfs` —
    // which is exactly what walking the tree from the root answered too.
    await fs.unlink("/d/f");
    expect(await used()).toEqual({ blocks: 2, nodes: 2 });
    await handle.truncate(1_000_000);
    expect(await used()).toEqual({ blocks: 2, nodes: 2 });
    await handle.close();

    // Renaming moves a node without creating one; renaming *over* one frees it.
    await fs.writeFile("/a", "aa");
    await fs.writeFile("/b", "bb");
    expect(await used()).toEqual({ blocks: 4, nodes: 4 });
    await fs.rename("/a", "/b");
    expect(await used()).toEqual({ blocks: 3, nodes: 3 });

    await fs.unlink("/b");
    await fs.rmdir("/d");
    expect(await used()).toEqual({ blocks: 1, nodes: 1 });
  });

  it("rejects invalid open flags and removing the root", async () => {
    const fs = createLoopback(createMemoryDriver());
    await expect(fs.open("/f", "nonsense")).rejects.toMatchObject({ code: "EINVAL" });
    await expect(fs.rmdir("/")).rejects.toMatchObject({ code: "EBUSY" });
  });

  it("rejects an inherited property as open flags", async () => {
    // The flag table was an object literal, so `"toString"` resolved to a
    // *function* off `Object.prototype` and `"__proto__"` to the prototype
    // itself — neither `undefined`, so neither was rejected. The handle that
    // came back had `read`/`write`/`create` all `undefined` and answered
    // `EBADF` to everything instead of the open failing.
    const fs = createLoopback(createMemoryDriver());
    for (const flags of ["toString", "__proto__", "constructor", "hasOwnProperty", "valueOf"]) {
      await expect(fs.open("/f", flags)).rejects.toMatchObject({ code: "EINVAL" });
    }
  });

  it("rejects an empty symlink target instead of aliasing the parent", async () => {
    // POSIX has no empty pathname; `symlink(2)` rejects it in `getname()` and
    // `node:fs` answers `ENOENT`. Stored, it collapsed on the walk and made the
    // link a live alias for its own parent directory — `/d/l` listed itself,
    // and a walker descended `/d/l/l/l/...` for 40 levels before `ELOOP`.
    const fs = createLoopback(createMemoryDriver());
    await fs.mkdir("/d");
    await expect(fs.symlink("", "/d/l")).rejects.toMatchObject({ code: "ENOENT" });
    // ...and `ENOENT` beats `EEXIST`, the way `node:fs` orders the two.
    await fs.writeFile("/d/taken", "x");
    await expect(fs.symlink("", "/d/taken")).rejects.toMatchObject({ code: "ENOENT" });
    expect((await fs.readdir("/d", { withFileTypes: true })).map((entry) => entry.name)).toEqual([
      "taken",
    ]);
  });

  it("validates read/write arguments the way node:fs does", async () => {
    // Every case here was run against `node:fs/promises` first; the two agree
    // except where noted.
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/f", "abcdefgh");
    const handle = await fs.open("/f", "r+");
    const buffer = new Uint8Array(4);

    // A zero-length read past the end of the buffer copies nothing and says so.
    // The out-of-range guard was `write`-only, so this fell through to the
    // remaining-bytes bound and compared `0` against a *negative* remainder.
    expect(await handle.read(buffer, 10, 0)).toMatchObject({ bytesRead: 0 });
    expect(await handle.read(buffer, 4, 0)).toMatchObject({ bytesRead: 0 });
    // A non-zero length past the end is still an error, reported against
    // `length` — which is `node:fs`'s own choice of parameter, not a mistake.
    await expect(handle.read(buffer, 10, 1)).rejects.toMatchObject({ code: "ERR_OUT_OF_RANGE" });
    await expect(handle.read(buffer, 10)).rejects.toMatchObject({ code: "ERR_OUT_OF_RANGE" });
    // `write` rejects the offset itself, before any length is considered.
    await expect(handle.write(buffer, 10, 0)).rejects.toMatchObject({
      code: "ERR_OUT_OF_RANGE",
      message: /"offset"/,
    });

    // A fractional position used to be carried straight through, and came back
    // out as a fractional `bytesRead` — `3.5` — which then flows into whatever
    // added it to an offset.
    for (const position of [1.5, -0.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      await expect(handle.read(buffer, 0, 4, position)).rejects.toMatchObject({
        code: "ERR_OUT_OF_RANGE",
        message: /"position"/,
      });
      // `node:fs` does not validate a *write* position at all; this driver
      // does, because a fractional one reaches the resize path.
      await expect(handle.write(buffer, 0, 4, position)).rejects.toMatchObject({
        code: "ERR_OUT_OF_RANGE",
      });
    }
    // ...and the ordinary sentinels still mean "wherever the handle is".
    expect(await handle.read(buffer, 0, 4, -1)).toMatchObject({ bytesRead: 4 });
    expect(await handle.read(buffer, 0, 4, null)).toMatchObject({ bytesRead: 4 });

    // A fractional offset or length is rejected too. `node:fs` agrees on the
    // offset; on the length its JavaScript layer lets one through to a C++
    // `CHECK(args[3]->IsInt32())` that aborts the process, so there is no
    // behaviour to match, only one to refuse to copy.
    await expect(handle.read(buffer, 1.5, 1)).rejects.toMatchObject({
      code: "ERR_OUT_OF_RANGE",
      message: /"offset"/,
    });
    await expect(handle.read(buffer, 0, 1.5)).rejects.toMatchObject({
      code: "ERR_OUT_OF_RANGE",
      message: /"length"/,
    });
    await handle.close();
    expect((await fs.stat("/f")).size).toBe(8);
  });

  it("keeps hard-linked content and metadata in sync", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/a", "one");
    await fs.link("/a", "/b");
    await fs.chmod("/b", 0o600);
    expect((await fs.stat("/a")).mode & 0o777).toBe(0o600);
    await fs.truncate("/b", 1);
    expect((await fs.stat("/a")).size).toBe(1);
  });

  it("survives a rename over a hard link", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/a", "one");
    await fs.link("/a", "/b");
    await fs.writeFile("/c", "two");
    await fs.rename("/c", "/b");
    expect((await fs.stat("/a")).nlink).toBe(1);
    expect((await fs.stat("/b")).nlink).toBe(1);
  });
});
