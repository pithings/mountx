/**
 * Tier 2: a real `mount -t nfs 127.0.0.1:/` of a JavaScript driver.
 *
 * ```sh
 * pnpm test:nfs:mount
 * ```
 *
 * Skips itself unless the host can actually mount NFS — root, plus a kernel
 * NFS *client* and the `/sbin/mount.nfs` helper from `nfs-utils`. Neither of
 * those is something this project can provide, and the dev container it was
 * written in has neither (see `.agents/environment.md`), which is exactly why
 * the Tier-1 column exists: `test/nfs/conformance.test.ts` runs the same
 * protocol end to end with a JavaScript client and needs nothing at all.
 *
 * **Serving a mount and using it from the same process** is much safer here
 * than it is under FUSE, and it is worth knowing why: the NFS server answers
 * from the *event loop*, not from a threadpool thread, so an asynchronous `fs`
 * call against your own mountpoint cannot starve the thing that has to answer
 * it. Two hazards remain, and the workload below respects both — anything
 * *synchronous* (`readFileSync`, `execFileSync`) blocks the one thread that
 * could reply, and `spawn(…, { cwd })` inside the mountpoint deadlocks in
 * `uv_spawn` for the same reason it does under FUSE.
 */

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { mountNfs, nfsClientProbe, type NfsMount } from "../../src/nfs/mount.ts";

const probe = nfsClientProbe();

/** Is anything mounted at `target`, according to the only source that knows? */
function isMounted(target: string): boolean {
  return readFileSync("/proc/self/mounts", "utf8")
    .split("\n")
    .some((line) => line.split(" ")[1] === target);
}

/** Run a command with no `cwd` inside the mountpoint — see the module docs. */
function run(command: string, args: string[]): Promise<{ status: number | null; out: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => (out += chunk));
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => (out += chunk));
    child.once("error", reject);
    child.once("close", (status) => resolve({ status, out }));
  });
}

describe.skipIf(!probe.usable)("a real NFS mount", () => {
  const mounts: NfsMount[] = [];
  const directories: string[] = [];

  afterEach(async () => {
    for (const mounted of mounts.splice(0)) {
      await mounted.unmount().catch(() => {
        // The assertions on leaks live in the tests; here cleanup is what matters.
      });
    }
    for (const directory of directories.splice(0)) {
      await fs.rm(directory, { recursive: true, force: true }).catch(() => {});
    }
  });

  async function mountpoint(): Promise<string> {
    const path = await fs.mkdtemp(join(tmpdir(), "mountx-nfs-mnt-"));
    directories.push(path);
    return path;
  }

  async function mount(): Promise<{ at: string; mounted: NfsMount }> {
    const at = await mountpoint();
    const mounted = await mountNfs(createMemoryDriver(), at);
    mounts.push(mounted);
    return { at, mounted };
  }

  it("mounts, appears in /proc/self/mounts, and unmounts clean", async () => {
    const { at, mounted } = await mount();
    expect(isMounted(at)).toBe(true);
    expect(mounted.source).toBe("127.0.0.1:/");
    expect(mounted.port).toBeGreaterThan(0);

    await mounted.unmount();
    expect(isMounted(at)).toBe(false);
    expect(mounted.active).toBe(false);
    // Idempotent, and the server went down with it.
    await mounted.unmount();
    expect(mounted.server.connections).toBe(0);
    expect(mounted.server.session.destroyed).toBe(true);
  }, 60_000);

  it("carries a real workload", async () => {
    const { at } = await mount();
    const path = (name: string): string => join(at, name);

    // --- directories and files ---
    await fs.mkdir(path("dir/nested"), { recursive: true });
    await fs.writeFile(path("dir/nested/file.txt"), "hello from a JavaScript filesystem");
    expect(await fs.readFile(path("dir/nested/file.txt"), "utf8")).toBe(
      "hello from a JavaScript filesystem",
    );

    // --- partial writes and reads at an offset ---
    const handle = await fs.open(path("dir/data"), "w+");
    await handle.write(Buffer.from("0123456789"), 0, 10, 0);
    await handle.write(Buffer.from("ab"), 0, 2, 3);
    const buffer = Buffer.alloc(4);
    await handle.read(buffer, 0, 4, 2);
    expect(buffer.toString()).toBe("2ab5");
    await handle.close();

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
    for (const entry of entries) {
      await fs.unlink(path(`many/${entry.name}`));
    }
    await fs.rmdir(path("many"));
    for (const name of ["renamed.txt", "alias.txt", "link.txt", "data"]) {
      await fs.unlink(path(`dir/${name}`));
    }
    await fs.rmdir(path("dir/nested"));
    await fs.rmdir(path("dir"));
    expect(await fs.readdir(at)).toEqual([]);
  }, 120_000);

  it("refuses to stack a second mount on the same point", async () => {
    const { at } = await mount();
    await expect(mountNfs(createMemoryDriver(), at)).rejects.toThrow(/already mounted/);
  }, 60_000);

  it("reports statfs through the mount", async () => {
    const { at } = await mount();
    const stats = await fs.statfs(at);
    expect(stats.bsize).toBeGreaterThan(0);
    expect(stats.blocks).toBeGreaterThan(0);
  }, 60_000);
});

describe.skipIf(probe.usable)("without an NFS client", () => {
  it("says what is missing rather than failing at mount(8)", async () => {
    expect(probe.reason).toBeTruthy();
    await expect(mountNfs(createMemoryDriver(), tmpdir())).rejects.toThrow(/cannot mount NFS here/);
  });

  it("still probes without throwing", () => {
    expect(typeof probe.usable).toBe("boolean");
    expect(typeof probe.kernel).toBe("boolean");
    expect(typeof probe.root).toBe("boolean");
  });
});
