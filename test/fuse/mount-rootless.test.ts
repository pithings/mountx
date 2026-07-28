/**
 * Tier 2, without root — which is the whole point of the file.
 *
 * ```sh
 * pnpm test:rootless
 * ```
 *
 * Everything here needs `fusermount3`, the native addon and a kernel, and
 * skips itself when it does not have them, so `pnpm test` stays green on a
 * host with no FUSE at all. It deliberately does **not** re-test the
 * filesystem: `conformance-mount.test.ts` does that, and once the descriptor
 * is in hand there is no code left that knows how it was obtained. What is
 * left to prove is everything that *is* different — who mounted, with which
 * options, and how it comes down again.
 *
 * The same no-fan-out rule as `mount.test.ts` applies, for the same reason:
 * this process is on both sides of every request, so a single `rm -r` over the
 * mountpoint would park the threadpool threads the read loop needs. Nothing
 * here touches the mountpoint synchronously either — `execFileSync` against
 * your own mount is an instant deadlock, not a slow one.
 */

import { execFile, spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { rootlessProbe } from "../../src/fuse/fusermount.ts";
import { liveMounts, mount, type Mount, type MountOptions } from "../../src/fuse/mount.ts";
import type { FsDriver } from "../../src/types.ts";

const exec = promisify(execFile);
const probe = rootlessProbe();
const asUser = (process.getuid?.() ?? -1) !== 0;
/** Real mounts are slow enough that vitest's 5s default is a coin flip. */
const SLOW = 60_000;

/**
 * Has someone raised the threadpool for us?
 *
 * Unlike every other Tier-2 suite this one *could* run in a plain `pnpm test`
 * — it needs no root — and that is exactly why it refuses to. On the default
 * pool of four, with the read loop holding two and vitest running other files
 * that do their own `fs` work alongside, a mount that serves itself is one
 * unlucky schedule away from a deadlock that looks like a hang, not a failure.
 * `pnpm test:rootless` sets the variable; nothing else has to know why.
 */
const POOL = Number.parseInt(process.env.UV_THREADPOOL_SIZE ?? "", 10);
const roomToRun = Number.isFinite(POOL) && POOL >= 8;

/**
 * Does `/etc/fuse.conf` let unprivileged mounts use `allow_other`?
 *
 * Distributions ship the line commented out, so the interesting assertion is
 * the refusal — but a host that has enabled it is not broken, it is configured,
 * and the test that expects a refusal has to skip rather than fail.
 */
function allowOtherPermitted(): boolean {
  try {
    return /^\s*user_allow_other\s*$/m.test(readFileSync("/etc/fuse.conf", "utf8"));
  } catch {
    return false;
  }
}

interface Mounted {
  mount: Mount;
  path: string;
}

describe.skipIf(!asUser || !probe.usable || !roomToRun)(
  `mounting as an ordinary user${probe.usable ? "" : ` (unavailable: ${probe.reason})`}`,
  () => {
    const open_: Mounted[] = [];
    const sandboxes: string[] = [];
    const daemons: ChildProcess[] = [];

    async function sandbox(): Promise<string> {
      const dir = await mkdtemp(join(tmpdir(), "mountx-rootless-"));
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
          child.kill("SIGKILL");
          await new Promise((resolve) => child.once("close", resolve));
        }
      }
      for (const dir of sandboxes.splice(0)) {
        // Never recurse into something still mounted: `rm -r` is concurrent,
        // and a live mountpoint would take the whole threadpool with it.
        if (
          mountEntries().some((entry) => entry.target === dir || entry.target.startsWith(`${dir}/`))
        ) {
          continue;
        }
        await rm(dir, { recursive: true, force: true });
      }
      expect(mountEntries().filter((entry) => entry.target.includes("mountx-rootless"))).toEqual(
        [],
      );
      expect(liveMounts()).toEqual([]);
    });

    /** `/proc/self/mounts`, parsed. */
    function mountEntries(): Array<{
      source: string;
      target: string;
      type: string;
      options: string;
    }> {
      return readFileSync("/proc/self/mounts", "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => {
          const [source = "", target = "", type = "", options = ""] = line.split(" ");
          return { source, target, type, options };
        });
    }

    function entryAt(path: string): ReturnType<typeof mountEntries>[number] | undefined {
      return mountEntries().find((entry) => entry.target === path);
    }

    it(
      "comes up as a fuse mount owned by the calling user",
      async () => {
        const { path } = await openMount(createMemoryDriver(), { fsname: "rootless-demo" });
        const entry = entryAt(path);
        expect(entry).toBeDefined();
        const { source, type, options } = entry!;

        // `fsname=` is how the source is named when `fusermount3` does the
        // mounting; there is no source argument to give it.
        expect(source).toBe("rootless-demo");
        expect(type).toBe("fuse");
        expect(options).toContain(`user_id=${process.getuid?.()}`);
        expect(options).toContain(`group_id=${process.getgid?.()}`);
        expect(options).toContain("default_permissions");
        // Not ours: `fusermount3` mounts everything `MS_NOSUID | MS_NODEV`, and
        // an unprivileged mount that did not would be a privilege escalation.
        expect(options).toContain("nosuid");
        expect(options).toContain("nodev");
      },
      SLOW,
    );

    it(
      "is a usable filesystem the moment mount() resolves",
      async () => {
        // Not a conformance test — one round trip in each direction, to show
        // that a resolved `mount()` means the kernel has been through `INIT`
        // and not merely that `fusermount3` exited.
        const { path } = await openMount(createMemoryDriver());
        await writeFile(join(path, "hello.txt"), "written through the mount\n");
        expect(await readFile(join(path, "hello.txt"), "utf8")).toBe("written through the mount\n");
        await mkdir(join(path, "sub"));
        expect((await stat(join(path, "sub"))).isDirectory()).toBe(true);
      },
      SLOW,
    );

    it(
      "unmounts through fusermount3 and leaves nothing behind",
      async () => {
        const mounted = await openMount(createMemoryDriver());
        expect(entryAt(mounted.path)).toBeDefined();

        await mounted.mount.unmount();
        expect(entryAt(mounted.path)).toBeUndefined();
        expect(mounted.mount.active).toBe(false);
        expect(mounted.mount.session.destroyed).toBe(true);
        // Idempotent, exactly as at root.
        await mounted.mount.unmount();
      },
      SLOW,
    );

    it(
      "leaves a mountpoint that answers ENOTCONN, not one that hangs, when the server is killed",
      async () => {
        // The crash-safety guarantee in mount.ts, and the only end-to-end proof
        // that the received descriptor really is close-on-exec: if it had
        // leaked into any of the children this process spawns, the connection
        // would outlive the kill and `stat` below would block forever.
        const path = join(await sandbox(), "mnt");
        await mkdir(path);
        const child = await startDaemon(path);
        expect(entryAt(path)).toBeDefined();

        child.kill("SIGKILL");
        await new Promise((resolve) => child.once("close", resolve));

        await expect(stat(path)).rejects.toMatchObject({ code: "ENOTCONN" });
        // And a plain unmount clears it, with no force and no root.
        await exec("fusermount3", ["-u", "--", path]);
        expect(entryAt(path)).toBeUndefined();
      },
      SLOW,
    );

    it.skipIf(allowOtherPermitted())(
      "reports why allow_other is refused instead of failing obscurely",
      async () => {
        const driver = createMemoryDriver();
        const path = join(await sandbox(), "mnt");
        await mkdir(path);
        await expect(mount(driver, path, { allowOther: true })).rejects.toThrow(/user_allow_other/);
        expect(entryAt(path)).toBeUndefined();
      },
      SLOW,
    );

    it("refuses a mountpoint the user may not mount on", async () => {
      // `fusermount3` does its own permission checking, and this is the case it
      // exists for. The message is its own; what matters here is that it
      // arrives as a rejection rather than a half-built mount.
      await expect(mount(createMemoryDriver(), "/proc")).rejects.toThrow(/mounting \/proc failed/);
      expect(entryAt("/proc")?.type).toBe("proc");
    });

    it("rejects the root-only `device` option rather than ignoring it", async () => {
      const path = join(await sandbox(), "mnt");
      await mkdir(path);
      await expect(mount(createMemoryDriver(), path, { device: "/dev/fuse" })).rejects.toThrow(
        /root-mode option/,
      );
    });

    /**
     * A separate process that mounts and then does nothing.
     *
     * What a `SIGKILL` leaves behind can only be observed from outside the
     * process that owned the mount.
     */
    async function startDaemon(path: string): Promise<ChildProcess> {
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
      return child;
    }
  },
);
