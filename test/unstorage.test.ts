/**
 * What the conformance suite cannot see about the unstorage driver: the key
 * mapping itself, and what happens to a store that already has data in it.
 *
 * The POSIX behaviour is covered by the conformance column in
 * `drivers.test.ts`; everything here is about the seam between a tree and a
 * flat key space.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createStorage, prefixStorage } from "unstorage";
import fsLiteStorageDriver from "unstorage/drivers/fs-lite";
import memoryStorageDriver from "unstorage/drivers/memory";
import { createUnstorageDriver } from "../src/drivers/unstorage.ts";
import { createLoopback } from "../src/harness.ts";
import type { Loopback } from "../src/harness.ts";
import type { Storage } from "unstorage";

const decoder = new TextDecoder();

function setup(options?: Parameters<typeof createUnstorageDriver>[1]): {
  fs: Loopback;
  storage: Storage;
} {
  const storage = createStorage();
  return { fs: createLoopback(createUnstorageDriver(storage, options)), storage };
}

function setupFailingWrites(): {
  fs: Loopback;
  storage: Storage;
  failNextWrite: () => void;
} {
  const backing = memoryStorageDriver();
  let fail = false;
  const storage = createStorage({
    driver: {
      ...backing,
      async setItemRaw(key, value, options) {
        if (fail) {
          fail = false;
          throw new Error("transient write failure");
        }
        await backing.setItemRaw!(key, value, options);
      },
    },
  });
  return {
    fs: createLoopback(createUnstorageDriver(storage)),
    storage,
    failNextWrite: () => {
      fail = true;
    },
  };
}

const read = async (fs: Loopback, path: string): Promise<string> =>
  decoder.decode(await fs.readFile(path));

/** What the store holds, as text. Files written through the driver are bytes. */
const stored = async (storage: Storage, key: string): Promise<string> =>
  decoder.decode((await storage.getItemRaw(key)) as Uint8Array);

const names = async (fs: Loopback, path: string): Promise<string[]> =>
  (await fs.readdir(path, { withFileTypes: true })).map((entry) => entry.name).sort();

describe("unstorage driver: keys", () => {
  it("maps a path onto the colon-separated key unstorage expects", async () => {
    const { fs, storage } = setup();
    await fs.mkdir("/a/b", { recursive: true });
    await fs.writeFile("/a/b/c.txt", "hello");

    expect(await storage.getKeys()).toEqual(["a:b:c.txt"]);
    expect(await stored(storage, "a:b:c.txt")).toBe("hello");

    // And the same key reached the other way round is the same file.
    await storage.setItemRaw("a:b:d.txt", new TextEncoder().encode("there"));
    expect(await read(fs, "/a/b/d.txt")).toBe("there");
  });

  it("stores bytes, not a stringified buffer", async () => {
    const { fs, storage } = setup();
    await fs.writeFile("/binary", new Uint8Array([0, 1, 254, 255]));
    expect([...((await storage.getItemRaw("binary")) as Uint8Array)]).toEqual([0, 1, 254, 255]);
    expect([...(await fs.readFile("/binary"))]).toEqual([0, 1, 254, 255]);
  });

  /**
   * The three characters unstorage's own `normalizeKey` would eat. Each one is
   * a silent corruption if it is allowed through, which is why the driver
   * refuses rather than mangling.
   */
  it.each([
    ["a colon", "/a:b"],
    ["a question mark", "/a?b"],
    ["a trailing dollar", "/meta$"],
  ])("rejects %s in a name with EINVAL", async (_label, path) => {
    const { fs } = setup();
    await expect(fs.writeFile(path, "x")).rejects.toMatchObject({ code: "EINVAL" });
    await expect(fs.stat(path)).rejects.toMatchObject({ code: "EINVAL" });
    await expect(fs.mkdir(path)).rejects.toMatchObject({ code: "EINVAL" });
  });

  it("leaves an unstorage metadata key out of the tree entirely", async () => {
    const { fs, storage } = setup();
    await storage.setItem("note", "text");
    await storage.setMeta("note", { author: "someone" });

    // `note$` exists in the store, and is neither listed nor reachable.
    expect((await storage.getKeys()).length).toBeGreaterThan(0);
    expect(await names(fs, "/")).toEqual(["note"]);
  });
});

describe("unstorage driver: an existing store", () => {
  it("mounts a flat key space as a tree", async () => {
    const storage = createStorage();
    await storage.setItem("readme.md", "# hi");
    await storage.setItem("src:index.ts", "export {};");
    await storage.setItem("src:lib:util.ts", "export {};");
    const fs = createLoopback(createUnstorageDriver(storage));

    expect(await names(fs, "/")).toEqual(["readme.md", "src"]);
    expect(await names(fs, "/src")).toEqual(["index.ts", "lib"]);
    expect(await names(fs, "/src/lib")).toEqual(["util.ts"]);

    const entries = await fs.readdir("/src", { withFileTypes: true });
    const lib = entries.find((entry) => entry.name === "lib")!;
    expect(lib.isDirectory()).toBe(true);
    expect(lib.parentPath).toBe("/src");
    expect(entries.find((entry) => entry.name === "index.ts")!.isFile()).toBe(true);

    expect((await fs.stat("/src")).isDirectory()).toBe(true);
    expect(await read(fs, "/src/lib/util.ts")).toBe("export {};");
  });

  it("renders a value that is not bytes as text", async () => {
    const storage = createStorage();
    await storage.setItemRaw("config", { port: 3000 });
    await storage.setItemRaw("greeting", "plain");
    const fs = createLoopback(createUnstorageDriver(storage));

    expect(await read(fs, "/config")).toBe('{"port":3000}');
    expect(await read(fs, "/greeting")).toBe("plain");
    expect((await fs.stat("/config")).size).toBe('{"port":3000}'.length);
  });

  /**
   * A key that is also a prefix has no tree that represents it. The key wins,
   * and every answer has to agree on that — a `stat` saying "file" while a
   * `readdir` said "directory" is worse than either answer alone.
   */
  it("answers consistently when a key is also a prefix", async () => {
    const storage = createStorage();
    await storage.setItem("a", "value");
    await storage.setItem("a:b", "shadowed");
    const fs = createLoopback(createUnstorageDriver(storage));

    expect((await fs.stat("/a")).isFile()).toBe(true);
    const entries = await fs.readdir("/", { withFileTypes: true });
    expect(entries.map((entry) => entry.name)).toEqual(["a"]);
    expect(entries[0]!.isFile()).toBe(true);
    await expect(fs.readdir("/a", { withFileTypes: true })).rejects.toMatchObject({
      code: "ENOTDIR",
    });
    await expect(fs.stat("/a/b")).rejects.toMatchObject({ code: "ENOTDIR" });
  });

  it("serves a subtree through prefixStorage", async () => {
    const storage = createStorage();
    await storage.setItem("keep:one", "1");
    await storage.setItem("other:two", "2");
    const fs = createLoopback(createUnstorageDriver(prefixStorage(storage, "keep")));

    expect(await names(fs, "/")).toEqual(["one"]);
    await fs.writeFile("/three", "3");
    expect(await stored(storage, "keep:three")).toBe("3");
  });

  it("takes size and mtime from the underlying driver's metadata", async () => {
    const mtime = new Date(1_700_000_000_000);
    const storage = createStorage({
      driver: {
        ...memoryStorageDriver(),
        getMeta: () => ({ mtime, size: 1234 }),
      },
    });
    await storage.setItem("f", "four");
    const fs = createLoopback(createUnstorageDriver(storage));

    const stats = await fs.stat("/f");
    // Reported rather than measured: the point is that the value is not fetched.
    expect(stats.size).toBe(1234);
    expect(stats.mtimeMs).toBe(mtime.getTime());
  });
});

describe("unstorage driver: directories", () => {
  it("keeps an empty directory only in this process, and a populated one for real", async () => {
    const storage = createStorage();
    const first = createLoopback(createUnstorageDriver(storage));
    await first.mkdir("/empty");
    await first.mkdir("/full");
    await first.writeFile("/full/f", "x");

    expect((await first.stat("/empty")).isDirectory()).toBe(true);

    // A second driver over the same store is a stand-in for a restart.
    const second = createLoopback(createUnstorageDriver(storage));
    expect(await names(second, "/")).toEqual(["full"]);
    await expect(second.stat("/empty")).rejects.toMatchObject({ code: "ENOENT" });
    expect((await second.stat("/full")).isDirectory()).toBe(true);
  });

  it("writes nothing to the store to mark a directory", async () => {
    const { fs, storage } = setup();
    await fs.mkdir("/a/b/c", { recursive: true });
    expect(await storage.getKeys()).toEqual([]);
  });

  it("moves every key under a renamed directory", async () => {
    const { fs, storage } = setup();
    await fs.mkdir("/from/inner", { recursive: true });
    await fs.writeFile("/from/one", "1");
    await fs.writeFile("/from/inner/two", "2");

    await fs.rename("/from", "/to");

    expect((await storage.getKeys()).sort()).toEqual(["to:inner:two", "to:one"]);
    expect(await read(fs, "/to/inner/two")).toBe("2");
    await expect(fs.stat("/from")).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("unstorage driver: handles", () => {
  it("shares one buffer between handles on the same path", async () => {
    const { fs, storage } = setup();
    await fs.writeFile("/f", "aaaa");

    const writer = await fs.open("/f", "r+");
    const reader = await fs.open("/f", "r");
    await writer.write(new TextEncoder().encode("bb"), 0, 2, 0);

    // Visible to the other handle and to `stat` before anything is flushed...
    const buffer = new Uint8Array(4);
    await reader.read(buffer, 0, 4, 0);
    expect(decoder.decode(buffer)).toBe("bbaa");
    expect((await fs.stat("/f")).size).toBe(4);
    // ...and not yet in the store.
    expect(await stored(storage, "f")).toBe("aaaa");

    // `sync` is what a mount's FSYNC reaches, so the write-back is not only a
    // close-time thing.
    await writer.sync!();
    expect(await stored(storage, "f")).toBe("bbaa");
    await writer.close();
    await reader.close();
  });

  it("writes back on the last close", async () => {
    const { fs, storage } = setup();
    const handle = await fs.open("/f", "w");
    await handle.write(new TextEncoder().encode("data"), 0, 4, 0);
    expect(await stored(storage, "f")).toBe("");
    await handle.close();
    expect(await stored(storage, "f")).toBe("data");
  });

  it("creates the key at open, not at the first write", async () => {
    const { fs, storage } = setup();
    const handle = await fs.open("/new", "w");
    expect(await storage.hasItem("new")).toBe(true);
    await handle.close();
  });

  it("keeps an unlinked file readable and never writes it back", async () => {
    const { fs, storage } = setup();
    await fs.writeFile("/doomed", "still here");
    const handle = await fs.open("/doomed", "r+");
    await fs.unlink("/doomed");

    const buffer = new Uint8Array(10);
    const { bytesRead } = await handle.read(buffer, 0, 10, 0);
    expect(decoder.decode(buffer.subarray(0, bytesRead))).toBe("still here");
    expect((await handle.stat()).size).toBe(10);

    await handle.write(new TextEncoder().encode("x"), 0, 1, 0);
    await handle.close();

    // The write went to a file that no longer exists, and did not resurrect it.
    expect(await storage.hasItem("doomed")).toBe(false);
  });

  it("does not write a replaced destination back over the file that arrived", async () => {
    const { fs, storage } = setup();
    await fs.writeFile("/source", "source");
    await fs.writeFile("/target", "target");
    const handle = await fs.open("/target", "r+");

    await fs.rename("/source", "/target");
    await handle.write(new TextEncoder().encode("zzzzzz"), 0, 6, 0);
    await handle.close();

    expect(await read(fs, "/target")).toBe("source");
    expect(await storage.hasItem("source")).toBe(false);
  });

  it("writes an open file back only at its renamed key", async () => {
    const { fs, storage } = setup();
    await fs.writeFile("/from", "aaaa");
    const handle = await fs.open("/from", "r+");
    await handle.write(new TextEncoder().encode("bb"), 0, 2, 0);
    await fs.rename("/from", "/to");
    await handle.write(new TextEncoder().encode("cc"), 0, 2, 2);
    await handle.close();

    expect(await storage.hasItem("from")).toBe(false);
    expect(await stored(storage, "to")).toBe("bbcc");
  });

  it("retries dirty data after a failed last close", async () => {
    const { fs, storage, failNextWrite } = setupFailingWrites();
    await fs.writeFile("/f", "aaaa");
    const handle = await fs.open("/f", "r+");
    await handle.write(new TextEncoder().encode("bbbb"), 0, 4, 0);

    failNextWrite();
    await expect(handle.close()).rejects.toThrow("transient write failure");
    expect(await stored(storage, "f")).toBe("aaaa");

    const retry = await fs.open("/f", "r+");
    await retry.sync!();
    await retry.close();
    expect(await stored(storage, "f")).toBe("bbbb");
  });

  it("persists path truncation after a failed last close", async () => {
    const { fs, storage, failNextWrite } = setupFailingWrites();
    await fs.writeFile("/f", "aaaa");
    const handle = await fs.open("/f", "r+");
    await handle.write(new TextEncoder().encode("bbbb"), 0, 4, 0);

    failNextWrite();
    await expect(handle.close()).rejects.toThrow("transient write failure");
    await fs.truncate("/f", 2);

    expect(await stored(storage, "f")).toBe("bb");
    const fresh = createLoopback(createUnstorageDriver(storage));
    expect(await read(fresh, "/f")).toBe("bb");
  });

  it("keeps a concurrent write dirty while a flush is pending", async () => {
    const backing = memoryStorageDriver();
    let delayNextWrite = false;
    let reached!: () => void;
    let resume!: () => void;
    const pending = new Promise<void>((resolve) => {
      reached = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      resume = resolve;
    });
    const storage = createStorage({
      driver: {
        ...backing,
        async setItemRaw(key, value, options) {
          if (delayNextWrite) {
            delayNextWrite = false;
            reached();
            await gate;
          }
          await backing.setItemRaw!(key, value, options);
        },
      },
    });
    const fs = createLoopback(createUnstorageDriver(storage));
    await fs.writeFile("/f", "aaaa");
    const first = await fs.open("/f", "r+");
    const second = await fs.open("/f", "r+");
    await first.write(new TextEncoder().encode("bbbb"), 0, 4, 0);

    delayNextWrite = true;
    const syncing = first.sync!();
    await pending;
    await second.write(new TextEncoder().encode("cccc"), 0, 4, 0);
    resume();
    await syncing;
    await first.close();
    await second.close();

    expect(await stored(storage, "f")).toBe("cccc");
  });

  it("does not keep a clean buffer after a renamed file closes", async () => {
    const { fs, storage } = setup();
    await fs.writeFile("/from", "old");
    const handle = await fs.open("/from", "r");
    await fs.rename("/from", "/to");
    await handle.close();

    await storage.setItemRaw("to", new TextEncoder().encode("fresh"));
    expect(await read(fs, "/to")).toBe("fresh");
  });

  it("persists a renamed open file through a fresh fs-lite driver", async () => {
    const root = await mkdtemp(join(tmpdir(), "mountx-unstorage-"));
    try {
      const firstStorage = createStorage({ driver: fsLiteStorageDriver({ base: root }) });
      const first = createLoopback(createUnstorageDriver(firstStorage));
      await first.writeFile("/from", "aaaa");
      const handle = await first.open("/from", "r+");
      await handle.write(new TextEncoder().encode("bb"), 0, 2, 0);
      await first.rename("/from", "/to");
      await handle.write(new TextEncoder().encode("cc"), 0, 2, 2);
      await handle.close();

      const freshStorage = createStorage({ driver: fsLiteStorageDriver({ base: root }) });
      const fresh = createLoopback(createUnstorageDriver(freshStorage));
      await expect(fresh.stat("/from")).rejects.toMatchObject({ code: "ENOENT" });
      expect(await read(fresh, "/to")).toBe("bbcc");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("unstorage driver: read-only", () => {
  it("answers EROFS to everything that would write, and reads as usual", async () => {
    const storage = createStorage();
    await storage.setItem("f", "content");
    const fs = createLoopback(createUnstorageDriver(storage, { readOnly: true }));

    expect(await read(fs, "/f")).toBe("content");
    expect(fs.capabilities.readOnly).toBe(true);

    for (const attempt of [
      fs.open("/f", "w"),
      fs.open("/new", "a"),
      fs.mkdir("/dir"),
      fs.rmdir("/dir"),
      fs.unlink("/f"),
      fs.rename("/f", "/g"),
      fs.truncate("/f", 0),
      fs.chmod("/f", 0o600),
      fs.chown("/f", 0, 0),
      fs.utimes("/f", 1, 1),
    ]) {
      await expect(attempt).rejects.toMatchObject({ code: "EROFS" });
    }
    expect(await storage.getItem("f")).toBe("content");
  });
});

describe("unstorage driver: capabilities", () => {
  it("declares what a key-value store can and cannot do", () => {
    const { fs } = setup();
    expect(fs.capabilities).toMatchObject({
      handles: true,
      permissions: true,
      times: true,
      truncate: true,
      caseSensitive: true,
      readOnly: false,
      // A copy and a delete, and no way to link or symlink a key.
      atomicRename: false,
      hardlinks: false,
      symlinks: false,
      statfs: false,
    });
  });

  it("answers ENOSYS for what it does not implement", async () => {
    const { fs } = setup();
    await fs.writeFile("/f", "x");
    for (const attempt of [
      fs.link("/f", "/g"),
      fs.symlink("f", "/g"),
      fs.readlink("/f"),
      fs.statfs("/"),
    ]) {
      await expect(attempt).rejects.toMatchObject({ code: "ENOSYS" });
    }
  });

  it("keeps permissions and timestamps for the life of the driver", async () => {
    const { fs, storage } = setup();
    await fs.writeFile("/f", "x");
    await fs.chmod("/f", 0o600);
    await fs.utimes("/f", new Date(1000), new Date(2000));

    const stats = await fs.stat("/f");
    expect(stats.mode & 0o777).toBe(0o600);
    expect(stats.mtimeMs).toBe(2000);

    // Nothing of it reached the store, and a fresh driver is back to defaults.
    const fresh = createLoopback(createUnstorageDriver(storage));
    expect((await fresh.stat("/f")).mode & 0o777).toBe(0o644);
  });
});
