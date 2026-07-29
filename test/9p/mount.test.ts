/**
 * Tier 2: a real `mount -t 9p -o trans=unix` of a JavaScript driver.
 *
 * ```sh
 * pnpm test:9p:mount     # under sudo; `pnpm test:root` runs it too
 * ```
 *
 * Skips itself unless the host can actually mount 9P: Linux, root, and `9p` in
 * `/proc/filesystems` — see {@link p9ClientProbe}, which is the same gate
 * `mount9p()` refuses on. The kernel client is not something this project can
 * provide, and plenty of hosts (containers with no module tree; every macOS)
 * cannot acquire one, which is exactly why the Tier-1 column exists:
 * `test/9p/conformance.test.ts` runs the same protocol end to end with a
 * JavaScript client and needs nothing at all.
 *
 * **No threadpool gate here, unlike the FUSE and NFS suites.** Those need
 * `UV_THREADPOOL_SIZE` raised because a `/dev/fuse` read parks a pool thread —
 * or, on macOS, because an unprivileged mount would otherwise happen during a
 * plain `pnpm test`. Neither applies: this server answers from the *event loop*
 * over a socket, so an asynchronous `fs` call against our own mountpoint cannot
 * starve the thing that has to answer it, and root is required, so a plain
 * `pnpm test` can never reach the mounting half of this file. (`test/root.sh`
 * raises the pool anyway; nothing here depends on it.)
 *
 * Two hazards do remain, and the workload respects both. Anything *synchronous*
 * against the mountpoint — `readFileSync`, `execFileSync` — blocks the one
 * thread that could reply. And `spawn(…, { cwd })` with a `cwd` inside the
 * mountpoint deadlocks in `uv_spawn`, which blocks the parent's main thread
 * until the child has `chdir`ed and exec'd.
 */

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { mount9p, p9ClientProbe, type P9Mount, parseMountTable } from "../../src/9p/mount.ts";
import { createMemoryDriver } from "../../src/drivers/memory.ts";

const probe = p9ClientProbe();

/**
 * Is anything mounted at `target`, and as what?
 *
 * Reads the table itself rather than asking `src/9p/mount.ts`: an assertion
 * that shared the transport's reader would pass on a table the two of them
 * agreed to misread together. Only the format parsing is shared.
 */
function mountTypeAt(target: string): string | undefined {
  const entries = parseMountTable(readFileSync("/proc/self/mounts", "utf8"));
  return entries.filter((entry) => entry.target === target).pop()?.type;
}

/** Run a command to completion, away from the mountpoint. */
function run(command: string, args: string[]): Promise<{ status: number | null; out: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      out += chunk;
    });
    child.once("error", reject);
    child.once("close", (status) => resolve({ status, out }));
  });
}

describe.skipIf(!probe.usable)("mount9p", () => {
  const mounted: P9Mount[] = [];
  const scratch: string[] = [];

  async function mount(): Promise<{ mount: P9Mount; at: string }> {
    const at = await fs.mkdtemp(join(tmpdir(), "mountx-9p-mnt-"));
    scratch.push(at);
    const handle = await mount9p(createMemoryDriver(), at);
    mounted.push(handle);
    return { mount: handle, at: handle.mountpoint };
  }

  afterEach(async () => {
    for (const handle of mounted.splice(0)) {
      await handle.unmount().catch(() => {});
    }
    for (const path of scratch.splice(0)) {
      await fs.rm(path, { recursive: true, force: true }).catch(() => {});
    }
  });

  it("mounts, appears in the mount table as 9p, and unmounts", async () => {
    const { mount: handle, at } = await mount();
    expect(handle.trans).toBe("unix");
    expect(mountTypeAt(at)).toBe("9p");
    // The source is the socket, in a directory nobody else can reach into.
    expect(handle.source.endsWith("/9p.sock")).toBe(true);
    expect(handle.active).toBe(true);
    await handle.unmount();
    expect(handle.active).toBe(false);
    expect(mountTypeAt(at)).toBeUndefined();
    // And the private directory went with it.
    await expect(fs.stat(handle.source)).rejects.toMatchObject({ code: "ENOENT" });
  }, 60_000);

  it("serves a whole workload through the kernel", async () => {
    const { at } = await mount();
    const path = (name: string): string => join(at, name);

    // --- create, read, write ---
    await fs.mkdir(path("dir"));
    await fs.mkdir(path("dir/nested"));
    await fs.writeFile(path("dir/nested/file.txt"), "hello from JavaScript");
    expect(await fs.readFile(path("dir/nested/file.txt"), "utf8")).toBe("hello from JavaScript");
    expect((await fs.stat(path("dir/nested/file.txt"))).size).toBe(21);
    expect((await fs.stat(path("dir"))).isDirectory()).toBe(true);

    // --- positional I/O through one handle ---
    const handle = await fs.open(path("dir/data"), "w+");
    await handle.write(Buffer.from("0123456789"), 0, 10, 0);
    await handle.write(Buffer.from("ab"), 0, 2, 3);
    const buffer = Buffer.alloc(4);
    await handle.read(buffer, 0, 4, 2);
    expect(buffer.toString()).toBe("2ab5");
    await handle.close();

    // --- something bigger than one msize, so it pages ---
    const big = Buffer.alloc(400_000, "x");
    await fs.writeFile(path("dir/big"), big);
    expect((await fs.readFile(path("dir/big"))).equals(big)).toBe(true);

    // --- rename, hardlink, symlink ---
    await fs.rename(path("dir/nested/file.txt"), path("dir/renamed.txt"));
    await expect(fs.stat(path("dir/nested/file.txt"))).rejects.toMatchObject({ code: "ENOENT" });
    await fs.link(path("dir/renamed.txt"), path("dir/alias.txt"));
    expect((await fs.stat(path("dir/alias.txt"))).nlink).toBe(2);
    await fs.symlink("renamed.txt", path("dir/link.txt"));
    expect(await fs.readlink(path("dir/link.txt"))).toBe("renamed.txt");
    expect((await fs.lstat(path("dir/link.txt"))).isSymbolicLink()).toBe(true);
    expect(await fs.readFile(path("dir/link.txt"), "utf8")).toContain("JavaScript");

    // --- metadata ---
    await fs.chmod(path("dir/renamed.txt"), 0o600);
    expect((await fs.stat(path("dir/renamed.txt"))).mode & 0o777).toBe(0o600);
    await fs.utimes(path("dir/renamed.txt"), new Date(1000), new Date(2000));
    expect((await fs.stat(path("dir/renamed.txt"))).mtimeMs).toBe(2000);
    await fs.truncate(path("dir/data"), 4);
    expect((await fs.stat(path("dir/data"))).size).toBe(4);

    // --- statfs ---
    const stats = await fs.statfs(at);
    expect(stats.bsize).toBeGreaterThan(0);
    expect(stats.blocks).toBeGreaterThan(0);

    // --- readdir, including enough entries to page ---
    await fs.mkdir(path("many"));
    for (let index = 0; index < 120; index++) {
      await fs.writeFile(path(`many/f${String(index).padStart(3, "0")}`), "x");
    }
    const entries = await fs.readdir(path("many"), { withFileTypes: true });
    expect(entries).toHaveLength(120);
    expect(entries.every((entry) => entry.isFile())).toBe(true);
    // And through a separate process, which is what a real client looks like.
    const listed = await run("ls", ["-1", path("many")]);
    expect(listed.status).toBe(0);
    expect(listed.out.trim().split("\n")).toHaveLength(120);

    // --- errno cases ---
    await expect(fs.stat(path("nope"))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(fs.readdir(path("dir/data"))).rejects.toMatchObject({ code: "ENOTDIR" });
    await expect(fs.rmdir(path("dir"))).rejects.toMatchObject({ code: "ENOTEMPTY" });
    await expect(fs.unlink(path("dir"))).rejects.toMatchObject({ code: "EISDIR" });
    await expect(fs.mkdir(path("dir"))).rejects.toMatchObject({ code: "EEXIST" });

    // --- removal, sequentially: `fs.rm` recursive fans out. ---
    async function empty(directory: string): Promise<void> {
      for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
        const child = join(directory, entry.name);
        if (entry.isDirectory()) {
          await empty(child);
          await fs.rmdir(child);
        } else {
          await fs.unlink(child);
        }
      }
    }
    for (const directory of [path("many"), path("dir")]) {
      await empty(directory);
      await fs.rmdir(directory);
    }
    expect(await fs.readdir(at)).toEqual([]);
  }, 180_000);

  it("refuses to stack a second mount on the same point", async () => {
    const { at } = await mount();
    // This process's own registry.
    await expect(mount9p(createMemoryDriver(), at)).rejects.toThrow(/already mounted/);
  }, 60_000);

  it("notices somebody else's umount and shuts itself down", async () => {
    const { mount: handle, at } = await mount();
    await fs.writeFile(join(at, "f"), "x");
    // The other direction of unmount detection: 9P has no `Tdestroy`, so the
    // connection ending is the only signal there is.
    const result = await run("umount", [at]);
    expect(result.status).toBe(0);
    await handle.connection.closed;
    await handle.closed;
    expect(handle.active).toBe(false);
    expect(handle.server.connections).toBe(0);
    // And a redundant unmount afterwards is a no-op rather than an error.
    await handle.unmount();
  }, 60_000);

  it("leaves nothing behind over repeated mounts", async () => {
    const points: string[] = [];
    for (let round = 0; round < 3; round++) {
      const { mount: handle, at } = await mount();
      points.push(at);
      await fs.writeFile(join(at, `round-${round}`), "x");
      expect(await fs.readdir(at)).toEqual([`round-${round}`]);
      await handle.unmount();
      expect(mountTypeAt(at)).toBeUndefined();
    }
    // Every mount torn down, and no 9p entry left at any of the three points —
    // which is the leak a stacked or a forgotten mount would show up as.
    const table = parseMountTable(readFileSync("/proc/self/mounts", "utf8"));
    expect(table.filter((entry) => entry.type === "9p" && points.includes(entry.target))).toEqual(
      [],
    );
  }, 120_000);

  it("mounts read-only when asked", async () => {
    const at = await fs.mkdtemp(join(tmpdir(), "mountx-9p-mnt-"));
    scratch.push(at);
    const handle = await mount9p(createMemoryDriver(), at, { readOnly: true });
    mounted.push(handle);
    await expect(fs.writeFile(join(handle.mountpoint, "nope"), "x")).rejects.toMatchObject({
      code: "EROFS",
    });
  }, 60_000);
});

describe.skipIf(probe.usable)("without a 9P client", () => {
  it("says what is missing rather than failing at mount(8)", async () => {
    expect(probe.reason).toBeTruthy();
    await expect(mount9p(createMemoryDriver(), tmpdir())).rejects.toThrow(/cannot mount 9P here/);
  });

  it("still probes without throwing", () => {
    expect(typeof probe.usable).toBe("boolean");
    expect(typeof probe.kernel).toBe("boolean");
    expect(typeof probe.root).toBe("boolean");
  });
});
