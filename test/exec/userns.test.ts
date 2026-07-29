/**
 * Tier 2, without root — a real namespace, a real FUSE mount, a real command.
 *
 * ```sh
 * pnpm test:rootless
 * ```
 *
 * Everything here needs `/dev/fuse`, unprivileged user namespaces and
 * `unshare(1)`, and skips itself when it does not have them, so `pnpm test`
 * stays green on a host that has none of it. It deliberately does **not**
 * re-test the filesystem: what the command sees is FUSE, and
 * `test/fuse/conformance-mount.test.ts` already covers that whole column. What
 * is left to prove is everything that *is* different — that the mount is
 * private to the child, that `$MOUNTX_ROOT` is where the driver actually is,
 * that a relay failure reaches the caller as an error rather than as the
 * command's exit status, and that nothing survives the call.
 *
 * The threadpool gate is the same one `test/fuse/mount-rootless.test.ts` uses,
 * and for a *weaker* reason: the read loop on `/dev/fuse` lives in the relay,
 * a separate process, so this suite is not on both sides of its own mount the
 * way that one is. What it does share is a `FuseSession` answering from this
 * process while vitest runs other files' `fs` work alongside, so it keeps the
 * same discipline rather than inventing a second rule.
 */

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { exec } from "../../src/exec/index.ts";
import { usernsExecProbe } from "../../src/exec/probe.ts";
import { execUserns } from "../../src/exec/userns.ts";
import { createLoopback } from "../../src/harness.ts";
import type { FsDriver } from "../../src/types.ts";

const probe = usernsExecProbe();

/** Has someone raised the threadpool for us? Same gate as the FUSE Tier-2 files. */
const POOL = Number.parseInt(process.env.UV_THREADPOOL_SIZE ?? "", 10);
const roomToRun = Number.isFinite(POOL) && POOL >= 8;
const live = probe.usable && roomToRun;

/** Real mounts are slow enough that vitest's 5s default is a coin flip. */
const SLOW = 60_000;

/** A driver with one obvious file in it, plus a directory. */
async function demo(): Promise<FsDriver> {
  const driver = createMemoryDriver();
  const fs = createLoopback(driver);
  await fs.mkdir("/docs", { recursive: true });
  await fs.writeFile("/hello.txt", "hello from a driver that is not on any disk\n");
  await fs.writeFile("/docs/a.txt", "alpha\n");
  return driver;
}

describe.skipIf(!live)("execUserns", () => {
  const directories: string[] = [];

  afterEach(async () => {
    for (const directory of directories.splice(0)) {
      await rm(directory, { recursive: true, force: true }).catch(() => {});
    }
  });

  async function scratch(): Promise<string> {
    const path = await mkdtemp(join(tmpdir(), "mountx-exec-test-"));
    directories.push(path);
    return path;
  }

  it(
    "serves the driver to the command at $MOUNTX_ROOT",
    async () => {
      const out = join(await scratch(), "out");
      // Everything the command touches on the *host* is `out`; everything it
      // reads comes from the driver. `sh -c` so the `cd` happens after the
      // exec — a `cwd` into the mount is the one thing that deadlocks.
      const ran = await execUserns(await demo(), [
        "sh",
        "-c",
        `cd "$MOUNTX_ROOT" && cat hello.txt docs/a.txt > ${out} && ls >> ${out}`,
      ]);
      expect(ran.code).toBe(0);
      expect(ran.signal).toBeNull();
      const text = await readFile(out, "utf8");
      expect(text).toContain("hello from a driver that is not on any disk");
      expect(text).toContain("alpha");
      expect(text).toContain("docs");
    },
    SLOW,
  );

  it(
    "writes back through the driver, not to the host",
    async () => {
      const driver = await demo();
      const ran = await execUserns(driver, [
        "sh",
        "-c",
        'printf again > "$MOUNTX_ROOT/written.txt"',
      ]);
      expect(ran.code).toBe(0);
      // The driver kept it, and it never existed anywhere a host path could
      // reach — the mountpoint itself is gone by now.
      const written = await createLoopback(driver).readFile("/written.txt");
      expect(Buffer.from(written).toString("utf8")).toBe("again");
    },
    SLOW,
  );

  it(
    "mounts where it was told, and leaves nothing behind",
    async () => {
      const mountpoint = join(await scratch(), "deep", "mnt");
      const out = join(await scratch(), "root");
      // A mountpoint that does not exist yet: created here, recursively, rather
      // than failing three processes away inside `mount(8)`.
      const ran = await execUserns(await demo(), ["sh", "-c", `printf %s "$MOUNTX_ROOT" > ${out}`]);
      expect(ran.code).toBe(0);
      expect(ran.mountpoint).toMatch(/^\//);

      const named = await execUserns(
        await demo(),
        ["sh", "-c", `printf %s "$MOUNTX_ROOT" > ${out}`],
        {
          mountpoint,
        },
      );
      expect(named.mountpoint).toBe(mountpoint);
      expect(await readFile(out, "utf8")).toBe(mountpoint);
      // Back to an ordinary empty directory: the mount died with the namespace.
      await writeFile(join(mountpoint, "still-a-directory"), "");
    },
    SLOW,
  );

  it(
    "keeps the mount out of the host's mount table",
    async () => {
      // The property the whole mechanism exists for. Read from *this* process,
      // which is outside the namespace and is where a leak would show up.
      const before = await readFile("/proc/self/mounts", "utf8");
      const ran = await execUserns(await demo(), ["sh", "-c", 'test -f "$MOUNTX_ROOT/hello.txt"']);
      expect(ran.code).toBe(0);
      const after = await readFile("/proc/self/mounts", "utf8");
      expect(after).toBe(before);
      expect(after).not.toContain(ran.mountpoint);
    },
    SLOW,
  );

  it(
    "hands back the command's own status rather than swallowing it",
    async () => {
      // A command that fails is not an error here, exactly as it is not for
      // `child_process` — which is what makes the *thrown* errors mean
      // "the mechanism could not be set up" and nothing else.
      const ran = await execUserns(await demo(), ["sh", "-c", "exit 42"]);
      expect(ran.code).toBe(42);
      expect(ran.signal).toBeNull();
    },
    SLOW,
  );

  it(
    "turns a relay failure into an error instead of a plausible exit status",
    async () => {
      // The relay exits 70 when it gives up, and a command exiting 70 is a
      // thing that happens; the status file is what tells the two apart.
      await expect(
        execUserns(await demo(), ["definitely-not-a-binary-on-this-host"]),
      ).rejects.toThrow(/could not run definitely-not-a-binary-on-this-host/);
    },
    SLOW,
  );

  it(
    "refuses a cwd inside the mount rather than deadlocking on it",
    async () => {
      const mountpoint = join(await scratch(), "mnt");
      await expect(
        execUserns(await demo(), ["true"], { mountpoint, cwd: mountpoint }),
      ).rejects.toThrow(/deadlocks rather than failing/);
    },
    SLOW,
  );
});

describe.skipIf(!live)("exec", () => {
  it(
    "picks the user namespace on a host with a working /dev/fuse, and tags the result",
    async () => {
      const ran = await exec(await demo(), ["sh", "-c", 'cat "$MOUNTX_ROOT/hello.txt"']);
      expect(ran.mechanism).toBe("userns");
      expect(ran.code).toBe(0);
      // The tag is a discriminant over the mechanism's *own* result object, so
      // narrowing on it reaches `mountpoint` with no cast.
      if (ran.mechanism === "userns") {
        expect(ran.mountpoint).toMatch(/^\//);
      }
    },
    SLOW,
  );
});
