/**
 * Tier 2: a real **kernel mount** of a JavaScript driver over WebDAV.
 *
 * ```sh
 * pnpm test:webdav:mount     # under sudo; `pnpm test:root` runs it too
 * ```
 *
 * `test/webdav/oracle.test.ts` already drives a foreign client — but `rclone`
 * and `curl` speak the *protocol*, and this transport's claim is bigger than
 * that: `src/webdav/index.ts` calls it the unprivileged, zero-native-code path
 * to a mountpoint. Nothing tested that. This file does: `mount.davfs` puts the
 * Linux kernel's VFS in front of the server and the workload below is ordinary
 * syscalls — `mkdir`, `open`, `read`, `write`, `rename`, `unlink`, `rmdir`,
 * `stat` — issued by `node:fs` and by `ls` in a separate process, with no
 * WebDAV vocabulary anywhere in it. What that catches and the protocol tests
 * cannot is everything a client only does when a kernel is asking: a `PROPFIND`
 * per `getattr`, a `GET` because a page was faulted rather than because a test
 * asked for bytes, a `PUT` on `close(2)`, and every one of them against paths
 * the VFS chose the escaping of.
 *
 * ## Why `davfs2` and not `rclone mount`
 *
 * Both produce a kernel mount, and `davfs2` is the stronger evidence by two
 * facts. It is the configuration `src/webdav/session.ts` names when it writes
 * down what class 1 costs — so this file is the check on that sentence — and it
 * has no VFS layer of its own translating a general object model onto WebDAV:
 * `mount.davfs` *is* a WebDAV client, and what it puts on the wire is what a
 * kernel asked it for. It also needs no `rclone` remote and no configuration
 * file outside the one written here.
 *
 * The cost is `sudo`. `mount.davfs` is setuid root, but it refuses an
 * unprivileged caller unless the mountpoint is already in `/etc/fstab` and the
 * caller is in the `davfs2` group — neither of which a test may arrange — so
 * this column is root-only, exactly like `test/9p/mount.test.ts`. That is a
 * fact about `davfs2`'s privilege model, not about the server: the share
 * itself is served by an ordinary user's process over an ordinary TCP socket.
 *
 * ## What the `DAV` header buys, measured twice
 *
 * `mount.davfs` sends `OPTIONS` first and believes the answer, so this suite has
 * seen both sides of the class-2 line and neither is a guess:
 *
 * - Against **class 1** — what this server advertised before locking landed — it
 *   printed `the server does not support locks` and mounted **read-write
 *   anyway**, sending not one `LOCK`. macOS's `mount_webdav` is the client that
 *   insists on class 2; this one never did. The observation is kept because it
 *   is the evidence behind that distinction, and it is recorded in
 *   `.agents/environment.md` where a historical fact belongs.
 * - Against **class 2**, which is what it reads today, it takes a lock per write
 *   and releases it. That is not decoration: it means the workload below drives
 *   `LOCK`, the `If` header and `UNLOCK` from a real kernel client rather than
 *   from a `fetch` this repository wrote, which is the one thing no other test
 *   here can claim. `#locks` asserts it, so a regression that silently stopped
 *   advertising class 2 would fail this file rather than pass it quietly.
 *
 * Either way `use_locks` stays at its `davfs2` default of on: the point is what
 * a real client does when it is not told what to do.
 *
 * ## `davfs2` is a caching client, and the assertions are shaped around it
 *
 * Its cache sits between the kernel and the protocol, which cuts both ways:
 *
 * - A `write` returns once the bytes are in the cache; the `PUT` follows on
 *   `close(2)`, asynchronously. So every driver-side check goes through
 *   {@link settle}, a **bounded** poll — measured at 1–3 ms on the host in
 *   `.agents/environment.md`, given fifteen seconds here.
 * - A `read` of a file this mount just wrote is answered from the cache and
 *   never reaches the server, so it proves nothing about `GET`. The read path
 *   is therefore tested the other way round, through `mountShare`'s `seed`
 *   hook: the tree is written to the driver with `node:fs` **before** the mount
 *   exists, so the only way its bytes can appear on the mountpoint is over the
 *   wire.
 *
 * Both directions are checked on the driver's own side with `node:fs` against a
 * `node-fs` driver over a `mkdtemp` directory, so "what landed" is a real tree
 * and not this repository's opinion of one.
 *
 * ## Hazards this file respects
 *
 * **Nothing synchronous against the mountpoint.** The server answers from this
 * process's event loop, and `mount.davfs` is a separate process that will not
 * answer the kernel until the server has answered it — so a `readFileSync` on
 * the mountpoint blocks the only thread that could end the request it is
 * waiting for. Same rule as `test/nfs/mount.test.ts` and `test/9p/mount.test.ts`,
 * and `spawn(…, { cwd })` inside the mountpoint is out for the same reason.
 *
 * **Teardown is `umount -i`, deliberately.** The `-i` skips `/sbin/umount.davfs`,
 * which unmounts and then polls until the `mount.davfs` daemon leaves the
 * process table — a wait that never ends in a container whose pid 1 does not
 * reap orphans, and one this suite has no business inheriting. `umount -i`
 * issues the same `umount(2)`, returns in single-digit milliseconds, and the
 * daemon exits on its own when `/dev/fuse` closes. Every unmount is bounded by
 * {@link UNMOUNT_TIMEOUT} and runs in an `afterEach` whatever the test did, and
 * `davfs2`'s per-mount cache directory is removed with it — see
 * {@link forgetCache}, which is the one leak `umount -i` does leave.
 *
 * No literal control character appears in this file (`AGENTS.md`, invariant 22).
 */

import { spawn } from "node:child_process";
import { accessSync, constants as fsConstants, readFileSync } from "node:fs";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, delimiter, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createNodeFsDriver } from "../../src/drivers/node-fs.ts";
import { createWebdavServer, type WebdavServer } from "../../src/webdav/server.ts";

// ---------------------------------------------------------------------------
// the probe
// ---------------------------------------------------------------------------

/**
 * Where `mount.davfs` lives when it is not on `PATH`.
 *
 * It is a `sbin` binary, and `sbin` is not on an ordinary user's `PATH` on
 * every distribution — so a probe that only walked `PATH` would report "no
 * client" on a host that has one, which is the failure mode that makes a
 * skipping suite worthless.
 */
const HELPER_PATHS = ["/sbin/mount.davfs", "/usr/sbin/mount.davfs"];

/** Where `davfs2` keeps the per-mount caches it does not remove itself. */
const CACHE_ROOT = "/var/cache/davfs2";

/** What {@link davfsClientProbe} found. */
interface DavfsProbe {
  /** Can this host actually mount a WebDAV share? */
  readonly usable: boolean;
  /** Why not, when it cannot. Always set when `usable` is `false`. */
  readonly reason?: string;
  /** The `mount.davfs` this host has, if it has one. */
  readonly helper?: string;
  /** Is this process root? `mount.davfs` needs it — see the module docs. */
  readonly root: boolean;
  /** Does the kernel have FUSE, which is what `davfs2` mounts through? */
  readonly kernel: boolean;
}

/**
 * Find an executable, `PATH` first and then a list of absolute fallbacks.
 *
 * Synchronous, because a `describe.skipIf` needs its answer at collection time
 * — the same reason `test/webdav/oracle.test.ts` resolves `rclone` this way.
 */
function findExecutable(name: string, extra: readonly string[] = []): string | undefined {
  const onPath = (process.env["PATH"] ?? "")
    .split(delimiter)
    .map((directory) => join(directory, name));
  for (const candidate of [...onPath, ...extra]) {
    try {
      accessSync(candidate, fsConstants.X_OK);
      return candidate;
    } catch {
      // Not here, or not executable by us. Keep looking.
    }
  }
  return undefined;
}

/**
 * Can this host mount a WebDAV share, and if not, what is missing?
 *
 * The same shape and the same contract as `nfsClientProbe()` and
 * `p9ClientProbe()`: it never throws, it names one missing thing, and a suite
 * gated on it skips rather than reddens. It lives here rather than in
 * `src/webdav/` on purpose — `mountx/webdav` is not in `mountx/auto` and never
 * mounts anything itself, so there is nothing for the transport to probe.
 */
function davfsClientProbe(): DavfsProbe {
  const root = (process.getuid?.() ?? -1) === 0;
  if (process.platform !== "linux") {
    return {
      usable: false,
      root,
      kernel: false,
      reason: `mount.davfs is a Linux client and this host is ${process.platform}.`,
    };
  }
  let kernel = false;
  try {
    kernel =
      /^nodev\s+fuse$/m.test(readFileSync("/proc/filesystems", "utf8")) &&
      accessSync("/dev/fuse", fsConstants.F_OK) === undefined;
  } catch {
    kernel = false;
  }
  const helper = findExecutable("mount.davfs", HELPER_PATHS);
  if (helper === undefined) {
    return {
      usable: false,
      root,
      kernel,
      reason: `no mount.davfs on this host; install the davfs2 package to run this column.`,
    };
  }
  if (!kernel) {
    return {
      usable: false,
      root,
      kernel,
      reason: `davfs2 mounts through FUSE, and this kernel has no fuse filesystem or no /dev/fuse.`,
    };
  }
  if (!root) {
    return {
      usable: false,
      root,
      kernel,
      helper,
      reason:
        `mount.davfs refuses an unprivileged caller unless the mountpoint is in /etc/fstab ` +
        `and the caller is in the davfs2 group, so this column needs root.`,
    };
  }
  return { usable: true, root, kernel, helper };
}

const probe = davfsClientProbe();

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/** Longest any one spawn may take, in milliseconds. */
const SPAWN_TIMEOUT = 30_000;
/** Longest an unmount may take before it is treated as wedged. */
const UNMOUNT_TIMEOUT = 20_000;
/** Longest {@link settle} waits for a `PUT` to reach the driver. */
const SETTLE_TIMEOUT = 15_000;
/** How often {@link settle} looks again. */
const SETTLE_INTERVAL = 25;

const USERNAME = "ada";
const PASSWORD = "a pass:word";

/**
 * The `davfs2` configuration every mount here is given, as a file.
 *
 * Passed with `-o conf=`, so `/etc/davfs2/davfs2.conf` is neither read for
 * these mounts nor written to — a developer's own settings are left alone, and
 * the run is the same as CI's. Four settings, each for a reason:
 *
 * - `ask_auth` — whether a missing password is prompted for. `0` for the
 *   unauthenticated shares, so a mount can never sit waiting on a terminal.
 * - `delay_upload 0` — upload as soon as the file is closed instead of sitting
 *   on it. It does not make the `PUT` synchronous (hence {@link settle}); it
 *   stops the wait being the default ten seconds.
 * - `dir_refresh` / `file_refresh` — how long a listing and a `stat` are
 *   trusted, in seconds. One, so a driver-side change is visible within a
 *   {@link settle} rather than within a minute.
 *
 * **`use_locks` is deliberately absent**, left at the `davfs2` default of on, so
 * what the client does about locking is the client's decision and not this
 * file's instruction. It read `DAV: 1, 3` and wrote without locks; it reads
 * `DAV: 1, 2, 3` and takes one per write. Both were measured — see the module
 * docs — and the second is asserted.
 */
function davfsConfig(askAuth: boolean): string {
  return [
    `ask_auth ${askAuth ? 1 : 0}`,
    `delay_upload 0`,
    `dir_refresh 1`,
    `file_refresh 1`,
    ``,
  ].join("\n");
}

/** Deterministic bytes that are not all the same, so a truncation cannot pass. */
function seeded(size: number): Buffer {
  const bytes = Buffer.alloc(size);
  for (let index = 0; index < size; index++) {
    bytes[index] = (index * 31 + (index >> 11)) & 0xff;
  }
  return bytes;
}

/** What `run` reports: the exit status and both streams, interleaved. */
interface Ran {
  readonly status: number | null;
  readonly out: string;
}

/**
 * Run a command to completion, bounded, with no `cwd` inside the mountpoint.
 *
 * The bound is the point: `mount.davfs` against a server that never answers
 * would otherwise hang a suite rather than fail it. A child still running at
 * the deadline is killed and its exit reported as whatever the signal made it.
 */
function run(
  command: string,
  args: readonly string[],
  options: { stdin?: string; timeout?: number } = {},
): Promise<Ran> {
  return new Promise<Ran>((resolve, reject) => {
    const child = spawn(command, [...args], {
      stdio: [options.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      timeout: options.timeout ?? SPAWN_TIMEOUT,
      killSignal: "SIGKILL",
    });
    let out = "";
    for (const stream of [child.stdout, child.stderr]) {
      stream?.setEncoding("utf8");
      stream?.on("data", (chunk: string) => {
        out += chunk;
      });
    }
    if (options.stdin !== undefined) {
      child.stdin?.end(options.stdin);
    }
    child.once("error", reject);
    child.once("close", (status) => resolve({ status, out }));
  });
}

/**
 * Wait, bounded, for something to become true on the driver's side.
 *
 * Answers whether it did rather than throwing, so a caller can assert on the
 * value and get vitest's own diff instead of a timeout with no detail. See the
 * module docs on why a driver-side check needs one of these at all.
 */
async function settle(check: () => Promise<boolean>, timeout = SETTLE_TIMEOUT): Promise<boolean> {
  const deadline = Date.now() + timeout;
  for (;;) {
    if (await check().catch(() => false)) {
      return true;
    }
    if (Date.now() >= deadline) {
      return false;
    }
    await new Promise((resolve) => setTimeout(resolve, SETTLE_INTERVAL));
  }
}

/** Every mount table entry, as `(source, target, type)`. */
function mountTable(): { source: string; target: string; type: string }[] {
  return readFileSync("/proc/self/mounts", "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => {
      const [source = "", target = "", type = ""] = line.split(" ");
      /* `/proc/self/mounts` escapes a space in a path as `\040`; the mountpoints
         here are `mkdtemp` names with none, but reading the field correctly
         costs one replace and makes the assertion mean what it says. */
      return { source, target: target.replaceAll("\\040", " "), type };
    });
}

/** What is mounted at `target`, or `undefined` when nothing is. */
function mountedAt(target: string): { source: string; type: string } | undefined {
  return mountTable().findLast((entry) => entry.target === target);
}

/**
 * Remove the cache `davfs2` keeps for a mountpoint that is gone.
 *
 * `umount.davfs` would have done this; `umount -i` does not run it (see the
 * module docs), so it is done here rather than left to accumulate a copy of
 * every byte the suite ever wrote. The directory is named
 * `<host>+<mountpoint with the slashes turned into dashes>+<owner>`, so the
 * `mkdtemp` basename identifies ours exactly and nobody else's. Best-effort in
 * every direction: a host that keeps its caches somewhere else, or does not let
 * us read this, simply has nothing to clean.
 */
async function forgetCache(mountpoint: string): Promise<void> {
  const mine = basename(mountpoint);
  const entries = await fs.readdir(CACHE_ROOT).catch(() => [] as string[]);
  for (const entry of entries.filter((name) => name.includes(mine))) {
    await fs.rm(join(CACHE_ROOT, entry), { recursive: true, force: true }).catch(() => {});
  }
}

/** One mounted share: the kernel's side, the driver's side, and the server between. */
interface Share {
  /** The mountpoint, where the kernel serves it. */
  readonly at: string;
  /** The `node-fs` driver's root: what the driver holds, on a real disk. */
  readonly root: string;
  /** The server in this process, answering `mount.davfs`. */
  readonly server: WebdavServer;
  /** Unmount, bounded. Idempotent, and safe on a share that never mounted. */
  unmount(): Promise<void>;
}

// ---------------------------------------------------------------------------
// the suite
// ---------------------------------------------------------------------------

describe.skipIf(!probe.usable)("a real WebDAV mount", () => {
  const shares: Share[] = [];
  const scratch: string[] = [];

  /** A temp directory this file made, removed at the end whatever happened. */
  async function scratchDir(prefix: string): Promise<string> {
    const path = await fs.mkdtemp(join(tmpdir(), prefix));
    scratch.push(path);
    return path;
  }

  /**
   * Serve a fresh `node-fs` driver and mount it, with the driver's tree seeded
   * *before* the mount exists.
   *
   * The seeding order is what makes the read path meaningful — see the module
   * docs — and a fresh mountpoint per mount is what makes `davfs2`'s cache
   * fresh, since the cache is keyed by the mountpoint's path.
   */
  async function mountShare(
    options: {
      credentials?: { username: string; password: string };
      /** Typed on the helper's stdin, for a share that asks for a password. */
      stdin?: string;
      seed?: (root: string) => Promise<void>;
    } = {},
  ): Promise<{ share: Share; mount: Ran }> {
    const root = await scratchDir("mountx-webdav-root-");
    const at = await scratchDir("mountx-webdav-mnt-");
    const config = join(await scratchDir("mountx-webdav-conf-"), "davfs2.conf");
    await fs.writeFile(config, davfsConfig(options.stdin !== undefined));
    await options.seed?.(root);

    const server = createWebdavServer(createNodeFsDriver(root), {
      credentials: options.credentials,
    });
    await server.listen();

    let unmounted: Promise<void> | undefined;
    const share: Share = {
      at,
      root,
      server,
      unmount: () => {
        unmounted ??= (async () => {
          if (mountedAt(at) !== undefined) {
            await run("umount", ["-i", at], { timeout: UNMOUNT_TIMEOUT });
          }
          await forgetCache(at);
        })();
        return unmounted;
      },
    };
    shares.push(share);

    const credentialOptions =
      options.credentials === undefined ? `` : `,username=${options.credentials.username}`;
    const mount = await run(
      probe.helper as string,
      [
        `${server.url}/`,
        at,
        "-o",
        `conf=${config},rw,uid=${process.getuid?.() ?? 0},gid=${process.getgid?.() ?? 0}` +
          credentialOptions,
      ],
      { stdin: options.stdin },
    );
    return { share, mount };
  }

  /** {@link mountShare}, asserting that the mount actually happened. */
  async function mounted(
    options: Parameters<typeof mountShare>[0] = {},
  ): Promise<Share & { path: (name: string) => string }> {
    const { share, mount } = await mountShare(options);
    expect(mount.status, `mount.davfs failed: ${mount.out}`).toBe(0);
    return { ...share, path: (name: string) => join(share.at, name) };
  }

  /**
   * Teardown, and it runs whether the test passed, failed or threw.
   *
   * Unmount first and remove afterwards, in that order: a `rm -rf` over a live
   * mountpoint would walk into the share and delete the driver's contents
   * through the kernel, which is a slow way to lose the evidence.
   */
  afterEach(async () => {
    for (const share of shares.splice(0)) {
      await share.unmount().catch(() => {});
      await share.server.close().catch(() => {});
    }
    for (const path of scratch.splice(0)) {
      await fs.rm(path, { recursive: true, force: true }).catch(() => {});
    }
  });

  it("mounts, appears in the mount table, and unmounts clean", async () => {
    const share = await mounted();
    const entry = mountedAt(share.at);
    /* `davfs2` mounts through FUSE and names the share as its source, so the
       line proves both halves: a real kernel filesystem, fed by this server. */
    expect(entry?.type).toBe("fuse");
    expect(entry?.source).toBe(`${share.server.url}/`);

    await share.unmount();
    expect(mountedAt(share.at)).toBeUndefined();
    // The mountpoint is a plain empty directory again, not a stale entry.
    expect(await fs.readdir(share.at)).toEqual([]);
    // Idempotent: a second unmount is a no-op rather than an error.
    await share.unmount();
    expect(mountedAt(share.at)).toBeUndefined();
  }, 60_000);

  it("carries an ordinary filesystem workload onto the driver", async () => {
    const share = await mounted();
    const { path, root } = share;

    // --- a tree, made one syscall at a time ---
    await fs.mkdir(path("dir"));
    await fs.mkdir(path("dir/nested"));
    expect((await fs.stat(path("dir/nested"))).isDirectory()).toBe(true);
    expect((await fs.stat(join(root, "dir/nested"))).isDirectory()).toBe(true);

    // --- bytes, seeded so a truncation cannot pass ---
    const small = seeded(4096);
    await fs.writeFile(path("dir/nested/file.bin"), small);
    expect((await fs.readFile(path("dir/nested/file.bin"))).equals(small)).toBe(true);
    expect(
      await settle(async () =>
        (await fs.readFile(join(root, "dir/nested/file.bin"))).equals(small),
      ),
      "the PUT never reached the driver",
    ).toBe(true);

    // --- big enough to span several reads and writes ---
    const big = seeded(1024 * 1024);
    await fs.writeFile(path("big.bin"), big);
    expect(
      await settle(async () => (await fs.readFile(join(root, "big.bin"))).equals(big)),
      "the large PUT never reached the driver intact",
    ).toBe(true);

    // --- names the escaping has to survive ---
    const spaced = "a name with spaces.txt";
    const unicode = "naïve-¥.txt";
    await fs.writeFile(path(spaced), "spaced");
    await fs.writeFile(path(unicode), "unicode");
    expect(
      await settle(async () => (await fs.readFile(join(root, spaced), "utf8")) === "spaced"),
    ).toBe(true);
    expect(
      await settle(async () => (await fs.readFile(join(root, unicode), "utf8")) === "unicode"),
    ).toBe(true);

    // --- sizes and mtimes, on both sides ---
    const throughMount = await fs.stat(path("big.bin"));
    const onDriver = await fs.stat(join(root, "big.bin"));
    expect(throughMount.size).toBe(big.byteLength);
    expect(onDriver.size).toBe(big.byteLength);
    /* `getlastmodified` is an HTTP date, so the mount's view of an mtime is the
       driver's rounded down to the second; a second of slack on top of that for
       the round trip itself. */
    expect(Math.abs(throughMount.mtimeMs - onDriver.mtimeMs)).toBeLessThan(2000);

    // --- rename ---
    await fs.rename(path("dir/nested/file.bin"), path("dir/renamed.bin"));
    await expect(fs.stat(path("dir/nested/file.bin"))).rejects.toMatchObject({ code: "ENOENT" });
    expect(
      await settle(async () => (await fs.readFile(join(root, "dir/renamed.bin"))).equals(small)),
      "the MOVE never reached the driver",
    ).toBe(true);
    await expect(fs.stat(join(root, "dir/nested/file.bin"))).rejects.toMatchObject({
      code: "ENOENT",
    });

    // --- the errors a kernel expects for the shapes it refuses ---
    await expect(fs.stat(path("nope"))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(fs.readdir(path("big.bin"))).rejects.toMatchObject({ code: "ENOTDIR" });
    await expect(fs.rmdir(path("dir"))).rejects.toMatchObject({ code: "ENOTEMPTY" });
    await expect(fs.mkdir(path("dir"))).rejects.toMatchObject({ code: "EEXIST" });

    // --- unlink and rmdir, down to an empty share ---
    await fs.unlink(path("dir/renamed.bin"));
    await fs.rmdir(path("dir/nested"));
    await fs.rmdir(path("dir"));
    expect(
      await settle(async () => (await fs.readdir(root)).includes("dir") === false),
      "the DELETE never reached the driver",
    ).toBe(true);
    for (const name of ["big.bin", spaced, unicode]) {
      await fs.unlink(path(name));
    }
    expect(await settle(async () => (await fs.readdir(root)).length === 0)).toBe(true);
  }, 120_000);

  it("takes and releases a lock, because the server advertises class 2", async () => {
    /* The one thing no other test in this package can claim: `LOCK`, the `If`
       header that carries its token, and `UNLOCK`, driven by a real kernel
       client that decided on its own to send them — `use_locks` is left at its
       default, so the only reason davfs2 locks here is the `DAV: 1, 2, 3` it
       read from `OPTIONS`. Asserted rather than described, so that a server
       which quietly stopped advertising class 2 fails this file: davfs2 would
       go back to writing without a lock, which is what it did before locking
       landed (see the module docs). */
    const share = await mounted();
    await fs.writeFile(share.path("locked.txt"), "written through the kernel");
    expect(
      await settle(async () =>
        (await fs.readFile(join(share.root, "locked.txt"), "utf8")).startsWith("written"),
      ),
      "the write to reach the driver",
    ).toBe(true);

    const methods = share.server.session.stats.methods;
    expect(methods.get("LOCK") ?? 0).toBeGreaterThan(0);
    expect(methods.get("UNLOCK") ?? 0).toBe(methods.get("LOCK") ?? 0);
    /* Every one of them succeeded: a `423` would mean the client's own token
       was not accepted back, which is the failure this pairing exists to
       catch. */
    expect(share.server.session.stats.errors).toBe(0);
    expect(share.server.session.assertions).toEqual([]);
  });

  it("reads back what the driver already held, byte for byte", async () => {
    /* The other direction, and the one `davfs2`'s cache cannot fake: every one
       of these files existed on the driver before the mount did, so a byte on
       the mountpoint arrived over the wire. */
    const spaced = "a name with spaces.bin";
    const unicode = "yen-¥.bin";
    const blob = seeded(1024 * 1024);
    const share = await mounted({
      seed: async (root) => {
        await fs.mkdir(join(root, "held/deeper"), { recursive: true });
        await fs.writeFile(join(root, "held/deeper", spaced), blob);
        await fs.writeFile(join(root, "held", unicode), "held on the driver");
        for (let index = 0; index < 40; index++) {
          await fs.writeFile(join(root, "held", `f${String(index).padStart(3, "0")}`), "x");
        }
      },
    });
    const { path } = share;

    expect((await fs.readFile(path(join("held/deeper", spaced)))).equals(blob)).toBe(true);
    expect(await fs.readFile(path(join("held", unicode)), "utf8")).toBe("held on the driver");
    expect((await fs.stat(path(join("held/deeper", spaced)))).size).toBe(blob.byteLength);

    // A listing big enough that it is not one lucky entry, through `readdir`…
    const entries = await fs.readdir(path("held"), { withFileTypes: true });
    expect(entries.filter((entry) => entry.isFile())).toHaveLength(41);
    expect(entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name)).toEqual([
      "deeper",
    ]);
    // …and through a separate process, which is what a real client looks like.
    const listed = await run("ls", ["-1", path("held")]);
    expect(listed.status).toBe(0);
    expect(listed.out.trim().split("\n")).toHaveLength(42);

    // Reading a partial range rather than the whole resource.
    const handle = await fs.open(path(join("held/deeper", spaced)), "r");
    try {
      const buffer = Buffer.alloc(64);
      await handle.read(buffer, 0, 64, 512 * 1024);
      expect(buffer.equals(blob.subarray(512 * 1024, 512 * 1024 + 64))).toBe(true);
    } finally {
      await handle.close();
    }
  }, 120_000);

  it("mounts a share behind HTTP Basic, and refuses the wrong password", async () => {
    const credentials = { username: USERNAME, password: PASSWORD };
    const share = await mounted({
      credentials,
      stdin: `${PASSWORD}\n`,
      seed: (root) => fs.writeFile(join(root, "secret.txt"), "only for ada"),
    });
    expect(await fs.readFile(share.path("secret.txt"), "utf8")).toBe("only for ada");

    /* And the refusal is the server's, not the client's guess: `mount.davfs`
       only learns it by being handed a 401 with a Basic challenge on it. */
    const wrong = await mountShare({ credentials, stdin: `not the password\n` });
    expect(wrong.mount.status).not.toBe(0);
    expect(wrong.mount.out).toContain("Basic");
    expect(mountedAt(wrong.share.at)).toBeUndefined();
  }, 120_000);

  it("unmounts cleanly even after the server has gone", async () => {
    /* The worst outcome this suite could have is a mount that outlives the run,
       so the case that would cause one is a case. Unlike a wedged FUSE mount,
       nothing here needs `umount -f` or an abort through `fusectl`: `davfs2`
       fails the request rather than parking on it, and a plain `umount -i`
       still returns. */
    const share = await mounted({
      seed: (root) => fs.writeFile(join(root, "before.txt"), "written while the server lived"),
    });
    expect(await fs.readFile(share.path("before.txt"), "utf8")).toBe(
      "written while the server lived",
    );

    await share.server.close();
    // A read the cache cannot answer now fails; what matters is that it *fails*.
    await expect(fs.readFile(share.path("gone.txt"))).rejects.toThrow();

    await share.unmount();
    expect(mountedAt(share.at)).toBeUndefined();
    expect(await fs.readdir(share.at)).toEqual([]);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// the other side of the gate
// ---------------------------------------------------------------------------

describe.skipIf(probe.usable)("without a WebDAV mount client", () => {
  it("says what is missing rather than skipping silently", () => {
    expect(probe.reason).toBeTruthy();
    expect(probe.usable).toBe(false);
  });

  it("still probes without throwing", () => {
    expect(typeof probe.usable).toBe("boolean");
    expect(typeof probe.root).toBe("boolean");
    expect(typeof probe.kernel).toBe("boolean");
  });
});
