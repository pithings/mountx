/**
 * Tier 2: a real mountpoint.
 *
 * Everything here needs `/dev/fuse`, root, and a kernel, so the whole suite
 * skips itself when it does not have them and `pnpm test` stays green for
 * everyone else. To actually run it:
 *
 * ```sh
 * pnpm test:mount
 * # which is: sudo env UV_THREADPOOL_SIZE=32 "$(which node)" \
 * #             node_modules/vitest/vitest.mjs run test/fuse/mount.test.ts
 * ```
 *
 * `sudo` needs the absolute path to node because root's PATH does not have the
 * version manager's shims on it, and `UV_THREADPOOL_SIZE` is raised because
 * this process is on *both* sides of every request: a `writeFile` against our
 * own mountpoint parks a threadpool thread until the request it generated has
 * been served, and the `node:fs` driver needs threads of its own to serve it.
 * Four is enough for the library; it is not enough to also be its own client.
 *
 * The same fact constrains how the tests are written, and it is worth stating
 * because it looks like an arbitrary style rule until it costs an afternoon: no
 * call in here may fan out over the mountpoint. `fs.rm(dir, { recursive: true })`
 * on a 200-entry directory issues 200 concurrent unlinks, every one of which
 * parks a pool thread waiting for a reply from *this* process — and once the
 * pool is full there is no thread left to read the next request. The main
 * thread sits in `epoll_wait` with nothing to do while thirty threads wait in
 * `request_wait_answer` forever. {@link removeAll} walks a tree one entry at a
 * time for exactly this reason. See the note in `src/fuse/mount.ts`.
 *
 * The one thing this file must never do is leave a mountpoint behind, so every
 * mount goes through {@link openMount} and is torn down in `afterEach` whether
 * the test passed, failed or threw.
 */

import { execFile, spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import {
  appendFile,
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  readlink,
  rename,
  rm,
  rmdir,
  stat,
  statfs,
  symlink,
  truncate,
  unlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { createNodeFsDriver } from "../../src/drivers/node-fs.ts";
import { FUSE_CREATE, FUSE_ROOT_ID, FUSE_WRITE } from "../../src/fuse/constants.ts";
import { liveMounts, mount, type Mount, type MountOptions } from "../../src/fuse/mount.ts";
import { encodeRequest, type FuseWriteIn } from "../../src/fuse/protocol.ts";
import { FuseSession } from "../../src/fuse/session.ts";
import type { FsDriver } from "../../src/types.ts";
import { SyntheticKernel } from "./synthetic-kernel.ts";

const exec = promisify(execFile);
// FUSE needs Linux as well as root: on macOS `mount()` refuses outright
// (macFUSE is a different protocol), so the suite skips rather than errors.
const isRoot = (process.getuid?.() ?? -1) === 0 && process.platform === "linux";
/** Real mounts are slow enough that vitest's 5s default is a coin flip. */
const SLOW = 60_000;

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * The contract the transport's zero-copy read path rests on, checked without a
 * kernel because it is a property of the *session*.
 *
 * A reader hands `handleMessage` a view of the buffer it is about to re-arm, so
 * the session must have copied everything it needs — headers, names, and the
 * `WRITE` payload — before its first `await`. If that ever stops being true the
 * symptom is corrupted file data under concurrent writes, which is a miserable
 * thing to debug from a mountpoint; here it is one assertion.
 */
describe("the session decodes before it awaits", () => {
  it("lets a transport reuse the buffer as soon as handleMessage returns", async () => {
    const driver = createMemoryDriver();
    const session = new FuseSession(driver);
    const kernel = new SyntheticKernel(session);
    await kernel.init();
    // `O_CREAT | O_RDWR`, so the same handle can read the payload back.
    const created = await kernel.create(FUSE_ROOT_ID, "reuse.txt", 0o102);

    const payload = Buffer.from("the buffer is the transport's again", "utf8");
    const message = encodeRequest(
      {
        opcode: FUSE_WRITE,
        unique: 4242n,
        nodeid: created.entry.nodeid,
        body: {
          fh: created.open.fh,
          offset: 0n,
          size: payload.length,
          writeFlags: 0,
          lockOwner: 0n,
          flags: 0,
          data: payload,
        } satisfies FuseWriteIn,
      },
      session.protocol,
    );

    // Exactly what the read loop does: one buffer, a view of the message in it,
    // and the buffer scribbled over the instant the call returns.
    const buffer = Buffer.allocUnsafe(message.length + 64);
    buffer.set(message);
    const pending = session.handleMessage(buffer.subarray(0, message.length));
    buffer.fill(0xaa);

    expect(await pending).not.toBeNull();
    expect(await kernel.read(created.entry.nodeid, created.open.fh, 0, payload.length)).toEqual(
      new Uint8Array(payload),
    );
    expect(session.assertions).toEqual([]);
  });

  it("copies names out of the buffer too, not just payloads", async () => {
    // Names are the other thing that arrives as bytes in the shared buffer, and
    // a name read after the buffer was re-armed would create a file called
    // something no one asked for.
    const session = new FuseSession(createMemoryDriver());
    const kernel = new SyntheticKernel(session);
    await kernel.init();

    const message = encodeRequest(
      {
        opcode: FUSE_CREATE,
        unique: 7n,
        nodeid: FUSE_ROOT_ID,
        body: { flags: 0o102, mode: 0o644, umask: 0o022, openFlags: 0, name: "named.txt" },
      },
      session.protocol,
    );
    const buffer = Buffer.allocUnsafe(message.length + 64);
    buffer.set(message);
    const pending = session.handleMessage(buffer.subarray(0, message.length));
    buffer.fill(0xaa);

    expect(await pending).not.toBeNull();
    expect(
      await kernel.readdirAll(FUSE_ROOT_ID, (await kernel.opendir(FUSE_ROOT_ID)).fh),
    ).toContain("named.txt");
    expect(session.assertions).toEqual([]);
  });
});

interface Mounted {
  mount: Mount;
  /** The mountpoint. */
  path: string;
}

describe.skipIf(!isRoot)("mount(driver, mountpoint)", () => {
  const open_: Mounted[] = [];
  const sandboxes: string[] = [];
  const daemons: ChildProcess[] = [];

  async function sandbox(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "mountx-"));
    sandboxes.push(dir);
    return dir;
  }

  async function openMount(driver: FsDriver, options: MountOptions = {}): Promise<Mounted> {
    const path = join(await sandbox(), "mnt");
    await mkdir(path);
    const mounted = { mount: await mount(driver, path, options), path };
    open_.push(mounted);
    return mounted;
  }

  afterEach(async () => {
    for (const mounted of open_.splice(0)) {
      await mounted.mount.unmount().catch(() => {
        // Reported by the assertions below; the cleanup is what matters.
      });
    }
    for (const child of daemons.splice(0)) {
      if (child.exitCode === null && child.signalCode === null) {
        // Killing it is enough: the connection dies with the last reference to
        // the fd, and the mountpoint stops being wedged even if the table entry
        // outlives it.
        child.kill("SIGKILL");
        await new Promise((resolve) => child.once("close", resolve));
      }
    }
    for (const dir of sandboxes.splice(0)) {
      // Never recurse into something still mounted: `rm -r` is concurrent, and
      // a live mountpoint would take the whole threadpool with it.
      if (mountedPaths().some((path) => path === dir || path.startsWith(`${dir}/`))) {
        continue;
      }
      await rm(dir, { recursive: true, force: true });
    }
    expect(mountedPaths().filter((path) => path.includes("mountx-"))).toEqual([]);
    expect(liveMounts()).toEqual([]);
  });

  /** Every mountpoint the kernel currently has, from `/proc/self/mounts`. */
  function mountedPaths(): string[] {
    return readFileSync("/proc/self/mounts", "utf8")
      .split("\n")
      .map((line) => line.split(" ")[1] ?? "")
      .filter((path) => path !== "");
  }

  /**
   * `rm -r`, one syscall at a time.
   *
   * Node's own recursive `rm` is concurrent, which is a deadlock against a
   * mountpoint this process is serving — see the note at the top of the file.
   */
  async function removeAll(path: string): Promise<void> {
    const info = await lstat(path);
    if (!info.isDirectory()) {
      await unlink(path);
      return;
    }
    for (const entry of await readdir(path)) {
      await removeAll(join(path, entry));
    }
    await rmdir(path);
  }

  /** What the session should look like once a mount has been torn down. */
  function expectCleanTeardown(mounted: Mounted): void {
    const { session } = mounted.mount;
    expect(session.destroyed).toBe(true);
    expect(session.openHandles).toBe(0);
    // `clear()` leaves the root and nothing else: no leaked nodeids, no leaked
    // paths, which is the table back at its baseline.
    expect(session.inodes.size).toBe(1);
    expect(session.inodes.pathCount).toBe(1);
    expect(session.assertions).toEqual([]);
    expect(session.stats.assertions).toBe(0);
    expect(session.stats.dropped).toBe(0);
    expect(mounted.mount.active).toBe(false);
    expect(mountedPaths()).not.toContain(mounted.path);
  }

  // ---------------------------------------------------------------------------
  // the workload, run against both drivers
  // ---------------------------------------------------------------------------

  /**
   * One pass over everything a filesystem is expected to do, driven entirely
   * through the kernel. The driver never learns it is under FUSE, which is the
   * whole claim of the library — so the same function has to pass for both.
   */
  async function workload(mnt: string): Promise<void> {
    expect(await readdir(mnt)).toEqual([]);

    // --- directories, files, and the basic read/write shapes ---
    await mkdir(join(mnt, "dir"));
    await mkdir(join(mnt, "dir", "nested"), { recursive: false });
    await writeFile(join(mnt, "dir", "file.txt"), "hello");
    expect(await readFile(join(mnt, "dir", "file.txt"), "utf8")).toBe("hello");
    await appendFile(join(mnt, "dir", "file.txt"), " world");
    expect(await readFile(join(mnt, "dir", "file.txt"), "utf8")).toBe("hello world");
    await truncate(join(mnt, "dir", "file.txt"), 5);
    expect(await readFile(join(mnt, "dir", "file.txt"), "utf8")).toBe("hello");
    expect((await readdir(join(mnt, "dir"))).sort()).toEqual(["file.txt", "nested"]);

    // A write bigger than one `max_write`, so the kernel has to split it.
    const big = Buffer.alloc(3 * 1024 * 1024, 0x5a);
    await writeFile(join(mnt, "big.bin"), big);
    expect(Buffer.compare(await readFile(join(mnt, "big.bin")), big)).toBe(0);
    await unlink(join(mnt, "big.bin"));

    // --- hardlinks: one inode, two names, and the kernel agrees ---
    await link(join(mnt, "dir", "file.txt"), join(mnt, "dir", "hard.txt"));
    const [original, hard] = [
      await stat(join(mnt, "dir", "file.txt")),
      await stat(join(mnt, "dir", "hard.txt")),
    ];
    expect(hard.ino).toBe(original.ino);
    expect(hard.nlink).toBe(2);
    await unlink(join(mnt, "dir", "hard.txt"));
    expect((await stat(join(mnt, "dir", "file.txt"))).nlink).toBe(1);

    // --- symlinks ---
    await symlink("dir/file.txt", join(mnt, "link"));
    expect(await readlink(join(mnt, "link"))).toBe("dir/file.txt");
    expect((await lstat(join(mnt, "link"))).isSymbolicLink()).toBe(true);
    expect(await readFile(join(mnt, "link"), "utf8")).toBe("hello");

    // --- unlink while open: the mkstemp pattern, and the one every naive
    //     path-based driver gets wrong ---
    const handle = await open(join(mnt, "doomed.txt"), "w+");
    try {
      await handle.write("still here", 0);
      await unlink(join(mnt, "doomed.txt"));
      await expect(stat(join(mnt, "doomed.txt"))).rejects.toMatchObject({ code: "ENOENT" });
      // `fstat` and `ftruncate` on the open fd arrive with no file handle in
      // the request, so the session has to find the inode another way.
      expect((await handle.stat()).size).toBe(10);
      await handle.truncate(4);
      expect((await handle.stat()).size).toBe(4);
      expect((await handle.readFile("utf8")).toString()).toBe("stil");
    } finally {
      await handle.close();
    }

    // --- rename a populated directory: the subtree remap ---
    await rename(join(mnt, "dir"), join(mnt, "moved"));
    expect(await readFile(join(mnt, "moved", "file.txt"), "utf8")).toBe("hello");
    expect((await readdir(join(mnt, "moved"))).sort()).toEqual(["file.txt", "nested"]);
    await expect(stat(join(mnt, "dir"))).rejects.toMatchObject({ code: "ENOENT" });

    // --- a directory too big for one READDIR round ---
    await mkdir(join(mnt, "many"));
    const names = Array.from({ length: 200 }, (_, i) => `entry-${String(i).padStart(3, "0")}`);
    for (const name of names) {
      await writeFile(join(mnt, "many", name), name);
    }
    expect((await readdir(join(mnt, "many"))).sort()).toEqual(names);
    // ...and again with the types, which is the `readdirplus` path.
    const dirents = await readdir(join(mnt, "many"), { withFileTypes: true });
    expect(dirents).toHaveLength(200);
    expect(dirents.every((entry) => entry.isFile())).toBe(true);

    // --- statfs ---
    const fsStat = await statfs(mnt);
    expect(fsStat.bsize).toBeGreaterThan(0);
    expect(fsStat.blocks).toBeGreaterThan(0n);

    // --- metadata ---
    await chmod(join(mnt, "moved", "file.txt"), 0o600);
    expect((await stat(join(mnt, "moved", "file.txt"))).mode & 0o777).toBe(0o600);
    const when = new Date(Date.UTC(2001, 0, 1, 12, 0, 0));
    await utimes(join(mnt, "moved", "file.txt"), when, when);
    expect((await stat(join(mnt, "moved", "file.txt"))).mtime.getTime()).toBe(when.getTime());

    // --- errnos the kernel must see unchanged ---
    await expect(stat(join(mnt, "nope"))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(rmdir(join(mnt, "moved"))).rejects.toMatchObject({ code: "ENOTEMPTY" });
    await expect(mkdir(join(mnt, "moved"))).rejects.toMatchObject({ code: "EEXIST" });
    await expect(readFile(join(mnt, "moved"))).rejects.toMatchObject({ code: "EISDIR" });
    await expect(readdir(join(mnt, "moved", "file.txt"))).rejects.toMatchObject({
      code: "ENOTDIR",
    });

    // --- concurrent writers: eight files at once, each big enough to be
    //     several requests, all of which interleave in the session ---
    const blobs = Array.from({ length: 8 }, (_, i) => Buffer.alloc(128 * 1024, 0x40 + i));
    await Promise.all(
      blobs.map((blob, i) => writeFile(join(mnt, "many", `concurrent-${i}`), blob)),
    );
    for (const [i, blob] of blobs.entries()) {
      expect(Buffer.compare(await readFile(join(mnt, "many", `concurrent-${i}`)), blob)).toBe(0);
    }

    // --- and clean up after ourselves, which is also the delete path ---
    await removeAll(join(mnt, "many"));
    await removeAll(join(mnt, "moved"));
    await unlink(join(mnt, "link"));
    expect(await readdir(mnt)).toEqual([]);
  }

  it(
    "serves the whole workload from the memory driver",
    async () => {
      const reported: unknown[] = [];
      const mounted = await openMount(createMemoryDriver(), {
        onTransportError: (error) => reported.push(error),
      });
      await workload(mounted.path);
      await mounted.mount.unmount();
      expectCleanTeardown(mounted);
      // Nothing on the transport is supposed to go wrong in a healthy mount,
      // including during teardown: `onTransportError` staying silent through
      // the whole workload is the assertion.
      expect(reported.map((error) => errorText(error))).toEqual([]);
      // Every message is accounted for: answered, or one of the two the kernel
      // wants no answer to (`FORGET`, `BATCH_FORGET`). Nothing dropped.
      const { requests, replies, noReply, dropped } = mounted.mount.session.stats;
      expect(requests).toBeGreaterThan(100);
      expect(noReply).toBeGreaterThan(0);
      expect(replies + noReply + dropped).toBe(requests);
    },
    SLOW,
  );

  it(
    "serves the whole workload from the node:fs passthrough",
    async () => {
      const root = await sandbox();
      // Four readers rather than the default two, so the multi-reader path is
      // exercised too — safe here only because `test:mount` raises
      // `UV_THREADPOOL_SIZE`, which is the whole point of that variable.
      const mounted = await openMount(createNodeFsDriver(root), {
        fsname: "mountx-passthrough",
        readers: 4,
      });
      await workload(mounted.path);
      // The oracle: whatever the kernel did through the mount is on the disk.
      expect(await readdir(root)).toEqual([]);
      await mounted.mount.unmount();
      expectCleanTeardown(mounted);
    },
    SLOW,
  );

  // ---------------------------------------------------------------------------
  // the mount itself
  // ---------------------------------------------------------------------------

  it("shows up in the mount table with the fsname and subtype it was given", async () => {
    const mounted = await openMount(createMemoryDriver(), {
      fsname: "mountx-memory",
      subtype: "memfs",
    });
    const table = readFileSync("/proc/self/mounts", "utf8")
      .split("\n")
      .find((line) => line.split(" ")[1] === mounted.path);
    expect(table).toBeDefined();
    const [source, , type] = table!.split(" ");
    expect(source).toBe("mountx-memory");
    expect(type).toBe("fuse.memfs");
    // `default_permissions` is on unless asked otherwise: the kernel enforces
    // mode bits, so drivers never make access decisions.
    expect(table).toContain("default_permissions");
    expect(mounted.mount.session.negotiated?.maxWrite).toBe(1024 * 1024);
    expect(mounted.mount.fd).toBeGreaterThan(2);
  });

  it("rejects a mountpoint that is missing or not a directory", async () => {
    const dir = await sandbox();
    await expect(mount(createMemoryDriver(), join(dir, "nothing"))).rejects.toThrow(/not usable/);
    await writeFile(join(dir, "file"), "");
    await expect(mount(createMemoryDriver(), join(dir, "file"))).rejects.toThrow(/not a directory/);
    expect(liveMounts()).toEqual([]);
  });

  it("refuses a driver whose root is not a directory", async () => {
    const driver = createMemoryDriver();
    const dir = await sandbox();
    // A driver that answers `stat("/")` with a regular file cannot be mounted:
    // `rootmode` would disagree with the kernel's own root inode.
    const broken: FsDriver = {
      ...driver,
      stat: async (path: string) => {
        const stats = await driver.stat!(path);
        return path === "/" ? { ...stats, mode: 0o100_644 } : stats;
      },
    } as FsDriver;
    await expect(mount(broken, dir)).rejects.toThrow(/root must be a directory/);
  });

  it("rejects an fsname or subtype that would inject mount options", async () => {
    const dir = await sandbox();
    // `-o fd=…,…,fsname` is one comma-separated string, so a comma here is not
    // a quoting nuisance, it is an extra mount option.
    await expect(mount(createMemoryDriver(), dir, { fsname: "evil,allow_other" })).rejects.toThrow(
      /`fsname` may not contain a comma/,
    );
    await expect(mount(createMemoryDriver(), dir, { subtype: "a=b" })).rejects.toThrow(
      /`subtype` may not contain a comma/,
    );
    expect(liveMounts()).toEqual([]);
  });

  it(
    "passes ro, allow_other and max_read through to the kernel",
    async () => {
      const mounted = await openMount(createMemoryDriver(), {
        readOnly: true,
        allowOther: true,
        maxRead: 65_536,
      });
      const options =
        readFileSync("/proc/self/mounts", "utf8")
          .split("\n")
          .find((line) => line.split(" ")[1] === mounted.path)
          ?.split(" ")[3] ?? "";
      expect(options.split(",")).toContain("ro");
      expect(options.split(",")).toContain("allow_other");
      expect(options).toContain("max_read=65536");
      // `ro` is enforced by the kernel, so the driver never even hears about it.
      await expect(writeFile(join(mounted.path, "nope"), "x")).rejects.toMatchObject({
        code: "EROFS",
      });
      expect(await readdir(mounted.path)).toEqual([]);
    },
    SLOW,
  );

  it(
    "installs one pair of signal handlers, and none at all when asked not to",
    async () => {
      const before = {
        SIGINT: process.listenerCount("SIGINT"),
        SIGTERM: process.listenerCount("SIGTERM"),
      };
      const quiet = await openMount(createMemoryDriver(), { signals: false });
      expect(process.listenerCount("SIGINT")).toBe(before.SIGINT);
      expect(process.listenerCount("SIGTERM")).toBe(before.SIGTERM);

      const loud = await openMount(createMemoryDriver());
      const alsoLoud = await openMount(createMemoryDriver());
      expect(process.listenerCount("SIGINT")).toBe(before.SIGINT + 1);
      expect(process.listenerCount("SIGTERM")).toBe(before.SIGTERM + 1);

      // ...and they come off with the last mount, not the first.
      await loud.mount.unmount();
      expect(process.listenerCount("SIGTERM")).toBe(before.SIGTERM + 1);
      await alsoLoud.mount.unmount();
      await quiet.mount.unmount();
      expect(process.listenerCount("SIGINT")).toBe(before.SIGINT);
      expect(process.listenerCount("SIGTERM")).toBe(before.SIGTERM);
    },
    SLOW,
  );

  it(
    "defaults a nonsense `readers` rather than mounting something that answers nothing",
    async () => {
      // `Math.trunc(NaN)` is `NaN`, which would loop zero times: a mount with no
      // readers hangs in `INIT` and then times out with no clue why.
      const mounted = await openMount(createMemoryDriver(), {
        readers: Number.NaN as number,
      });
      await writeFile(join(mounted.path, "served"), "yes");
      expect(await readdir(mounted.path)).toEqual(["served"]);
    },
    SLOW,
  );

  // ---------------------------------------------------------------------------
  // teardown, from both directions
  // ---------------------------------------------------------------------------

  it(
    "notices an external umount and tears itself down",
    async () => {
      const mounted = await openMount(createMemoryDriver());
      await writeFile(join(mounted.path, "a"), "a");
      expect(mounted.mount.active).toBe(true);

      // Somebody else's umount. The kernel aborts the connection, every
      // outstanding read returns ENODEV, and the transport has to do the rest
      // on its own — a `-t fuse` mount never sends FUSE_DESTROY.
      await exec("umount", [mounted.path]);
      await mounted.mount.closed;
      expectCleanTeardown(mounted);
      expect(liveMounts()).toEqual([]);

      // And unmounting something already gone is a no-op, not an error.
      await mounted.mount.unmount();
    },
    SLOW,
  );

  it(
    "forces the connection down when a wedged driver stalls the unmount",
    async () => {
      // `umount(8)` quiesces the filesystem before detaching it, and the last
      // thing it asks for is `STATFS`. A driver that never answers it blocks
      // `umount` in `D` state — and with it every caller of `unmount()`, which
      // is the failure this deadline exists for.
      const driver = createMemoryDriver();
      const wedged: FsDriver = { ...driver, statfs: () => new Promise(() => {}) };
      const reported: unknown[] = [];
      const mounted = await openMount(wedged, {
        unmountTimeout: 1000,
        onTransportError: (error) => reported.push(error),
      });
      await writeFile(join(mounted.path, "a"), "a");

      const started = Date.now();
      await expect(mounted.mount.unmount()).rejects.toThrow(/did not finish within 1000ms/);
      // It gave up on time, rather than on the driver.
      expect(Date.now() - started).toBeLessThan(20_000);
      expect(reported.map((error) => errorText(error)).join("\n")).toMatch(/did not finish/);

      // And the force actually worked: `umount -f` aborts the connection
      // through `fuse_umount_begin`, which fails every request in flight, so
      // the parked reads come back and the ordinary teardown runs.
      await mounted.mount.closed;
      expect(mounted.mount.active).toBe(false);
      expect(mounted.mount.session.destroyed).toBe(true);
      expect(mountedPaths()).not.toContain(mounted.path);
      expect(liveMounts()).toEqual([]);
    },
    SLOW,
  );

  it(
    "is safe to unmount twice, concurrently or in sequence",
    async () => {
      const mounted = await openMount(createMemoryDriver());
      await writeFile(join(mounted.path, "a"), "a");
      await Promise.all([mounted.mount.unmount(), mounted.mount.unmount()]);
      await mounted.mount.unmount();
      expectCleanTeardown(mounted);
    },
    SLOW,
  );

  it(
    "unmounts through `await using`",
    async () => {
      const path = join(await sandbox(), "mnt");
      await mkdir(path);
      let session;
      {
        await using mounted = await mount(createMemoryDriver(), path);
        session = mounted.session;
        await writeFile(join(path, "a"), "a");
      }
      expect(session.destroyed).toBe(true);
      expect(mountedPaths()).not.toContain(path);
    },
    SLOW,
  );

  /**
   * A separate process that mounts and then does nothing.
   *
   * Some things can only be observed from outside the process that owns the
   * mount: what a signal does to it, and what another process sees when it
   * tries to mount over it.
   */
  async function startDaemon(path: string): Promise<{
    child: ChildProcess;
    exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  }> {
    const script = join(await sandbox(), "daemon.mjs");
    const source = (name: string) =>
      JSON.stringify(new URL(`../../src/${name}`, import.meta.url).pathname);
    await writeFile(
      script,
      [
        `import { mount } from ${source("fuse/mount.ts")};`,
        `import { createMemoryDriver } from ${source("drivers/memory.ts")};`,
        `await mount(createMemoryDriver(), ${JSON.stringify(path)});`,
        `process.stdout.write("ready\\n");`,
      ].join("\n"),
    );

    const child = spawn(process.execPath, [script], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    daemons.push(child);
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (resolve) => {
        child.once("close", (code, signal) => resolve({ code, signal }));
      },
    );
    let stderr = "";
    child.stderr!.setEncoding("utf8");
    child.stderr!.on("data", (chunk: string) => {
      stderr += chunk;
    });
    await new Promise<void>((resolve, reject) => {
      child.stdout!.setEncoding("utf8");
      child.stdout!.on("data", (chunk: string) => {
        if (chunk.includes("ready")) {
          resolve();
        }
      });
      child.once("close", () => reject(new Error(`daemon exited early: ${stderr}`)));
    });
    return { child, exited };
  }

  it(
    "unmounts on SIGTERM, from a process that only knows how to mount",
    async () => {
      const path = join(await sandbox(), "mnt");
      await mkdir(path);
      const { child, exited } = await startDaemon(path);
      expect(mountedPaths()).toContain(path);

      child.kill("SIGTERM");
      const result = await exited;
      // The handler unmounts, then re-raises so the exit status stays honest.
      // (It cannot call `process.exit()`: that joins the threadpool, where the
      // reads are parked, and never returns.)
      expect(result.signal).toBe("SIGTERM");
      expect(mountedPaths()).not.toContain(path);
    },
    SLOW,
  );

  it(
    "refuses to stack a mount on a mountpoint that already has one",
    async () => {
      // Linux would allow it, and then `umount` would detach the *top* one:
      // the second mount's teardown would kill the first mount's connection
      // and then wait forever for its own.
      const mounted = await openMount(createMemoryDriver());
      await expect(mount(createMemoryDriver(), mounted.path)).rejects.toThrow(
        /already mounted by this process/,
      );
      expect(liveMounts()).toHaveLength(1);
      // The first mount is untouched by the refusal.
      await writeFile(join(mounted.path, "still-works"), "yes");
      expect(await readdir(mounted.path)).toEqual(["still-works"]);
    },
    SLOW,
  );

  it(
    "refuses to stack a mount on someone else's FUSE mountpoint",
    async () => {
      const path = join(await sandbox(), "mnt");
      await mkdir(path);
      const { child, exited } = await startDaemon(path);
      // Nothing in `liveMounts()` here — this branch is the mount table's.
      await expect(mount(createMemoryDriver(), path)).rejects.toThrow(
        /already has a FUSE filesystem/,
      );
      expect(liveMounts()).toEqual([]);
      child.kill("SIGTERM");
      await exited;
      expect(mountedPaths()).not.toContain(path);
    },
    SLOW,
  );

  // ---------------------------------------------------------------------------
  // notifies
  // ---------------------------------------------------------------------------

  it(
    "invalidates kernel caches on request",
    async () => {
      const driver = createMemoryDriver();
      const mounted = await openMount(driver, { attrTimeout: 3600, entryTimeout: 3600 });
      const file = join(mounted.path, "watched.txt");
      await writeFile(file, "first");

      // Read through an fd we keep open: a fresh `open()` gives the kernel an
      // excuse to revalidate (`FUSE_AUTO_INVAL_DATA`), and then nothing is
      // stale and there is nothing to prove. The content stays the same length
      // for the same reason — a changed size would be visible in `getattr`.
      const reader = await open(file, "r");
      /** Always from offset 0: a `FileHandle` remembers its position. */
      const readBack = async (): Promise<string> => {
        const into = Buffer.alloc(5);
        await reader.read(into, 0, 5, 0);
        return into.toString("utf8");
      };
      try {
        expect(await readBack()).toBe("first");

        // Now change it behind the kernel's back, exactly as a driver with
        // another writer would. The page cache is entitled to keep the old
        // bytes, and does.
        const handle = await driver.open!("/watched.txt", "r+", 0o644);
        await handle.write(Buffer.from("fresh"), 0, 5, 0);
        await handle.close();
        expect(await readBack()).toBe("first");

        const inode = mounted.mount.session.inodes.at("/watched.txt");
        expect(inode).toBeDefined();
        // `off = 0, len = 0` is "the whole file", which also drops the
        // attributes. This is the call `watch` + notify is built on.
        mounted.mount.notifyInvalInode(inode!.nodeid, 0n, 0n);
        // The kernel handles a notify asynchronously; give it a moment.
        await new Promise((resolve) => setTimeout(resolve, 50));
        expect(await readBack()).toBe("fresh");

        // Entry invalidation has nothing directly observable to prove here (a
        // negative lookup is not cached by default), but it must be accepted
        // and must not upset the mount.
        mounted.mount.notifyInvalEntry(FUSE_ROOT_ID, "watched.txt");
        await new Promise((resolve) => setTimeout(resolve, 50));
        expect(await readdir(mounted.path)).toEqual(["watched.txt"]);
      } finally {
        await reader.close();
      }

      await unlink(file);
      await mounted.mount.unmount();
      expectCleanTeardown(mounted);
    },
    SLOW,
  );
});
