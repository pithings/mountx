/**
 * Tier 2: `mountx/auto` against whatever this host can actually mount.
 *
 * ```sh
 * pnpm test:rootless   # or under `test/root.sh`, which raises the pool too
 * ```
 *
 * The transport suites prove the transports; this proves the facade. What is
 * left to check once `mount()` has returned is that the thing it returned is
 * the transport's own mount object — tagged, disposable, and still carrying
 * the transport-specific members — and that the choice it made matches the
 * choice the probe published.
 *
 * It skips itself unless something can mount *and* the threadpool has been
 * raised, for the same reason `mount-rootless.test.ts` does: this process is
 * on both sides of every request. Everything below is asynchronous and
 * single-file for that reason — no `readFileSync`, no `rm -r`, no `spawn`
 * with a `cwd` inside the mountpoint.
 */

import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { type AutoMount, liveMounts, mount, probeTransports, unmountAll } from "../src/auto.ts";
import { createMemoryDriver } from "../src/drivers/memory.ts";

const here = await probeTransports();

/** See `mount-rootless.test.ts`: four threads is not enough to serve yourself. */
const POOL = Number.parseInt(process.env.UV_THREADPOOL_SIZE ?? "", 10);
const roomToRun = Number.isFinite(POOL) && POOL >= 8;

/** Real mounts are slow enough that vitest's 5s default is a coin flip. */
const SLOW = 60_000;

describe.skipIf(here.chosen === undefined || !roomToRun)("mount() with no transport named", () => {
  const mounts: AutoMount[] = [];
  const directories: string[] = [];

  afterEach(async () => {
    for (const mounted of mounts.splice(0)) {
      await mounted.unmount().catch(() => {});
    }
    for (const directory of directories.splice(0)) {
      await rm(directory, { recursive: true, force: true }).catch(() => {});
    }
  });

  async function mountpoint(): Promise<string> {
    const path = await mkdtemp(join(tmpdir(), "mountx-auto-mnt-"));
    directories.push(path);
    return path;
  }

  async function mounted(): Promise<{ at: string; mounted: AutoMount }> {
    const at = await mountpoint();
    const it = await mount(createMemoryDriver(), at);
    mounts.push(it);
    return { at, mounted: it };
  }

  it(
    "picks what the probe published, and serves through it",
    async () => {
      const { at, mounted: it } = await mounted();
      expect(it.transport).toBe(here.chosen);
      expect(it.mountpoint).toBe(at);
      expect(it.active).toBe(true);

      await writeFile(join(at, "hello.txt"), "hi from auto");
      expect(await readFile(join(at, "hello.txt"), "utf8")).toBe("hi from auto");
      expect((await stat(join(at, "hello.txt"))).size).toBe(12);
    },
    SLOW,
  );

  it(
    "hands back the transport's own object, not a wrapper",
    async () => {
      const { mounted: it } = await mounted();
      // The tag is a discriminant: narrowing on it reaches the members only
      // that transport has, on the same object the transport constructed.
      if (it.transport === "fuse") {
        expect(typeof it.fd).toBe("number");
        expect(it.session.destroyed).toBe(false);
        expect(typeof it.notifyInvalInode).toBe("function");
      } else {
        expect(it.port).toBeGreaterThan(0);
        expect(it.server.session.destroyed).toBe(false);
      }
      expect(it.source).toBeTruthy();
    },
    SLOW,
  );

  it(
    "lists the mount tagged, and unmounts it clean",
    async () => {
      const { at, mounted: it } = await mounted();
      const live = await liveMounts();
      expect(live.map((entry) => entry.mountpoint)).toContain(at);
      expect(live.every((entry) => entry.transport === here.chosen)).toBe(true);

      await it.unmount();
      expect(it.active).toBe(false);
      expect((await liveMounts()).map((entry) => entry.mountpoint)).not.toContain(at);
      // Idempotent, as both transports' own `unmount()` are.
      await it.unmount();
    },
    SLOW,
  );

  it(
    "unmounts everything it started",
    async () => {
      const { at } = await mounted();
      expect(await unmountAll()).toEqual([]);
      expect(await liveMounts()).toEqual([]);
      // The mountpoint is a plain empty directory again.
      expect((await stat(at)).isDirectory()).toBe(true);
    },
    SLOW,
  );

  it(
    "refuses to stack a second mount on the same point",
    async () => {
      const { at } = await mounted();
      await expect(mount(createMemoryDriver(), at)).rejects.toThrow(/already mounted|already has/);
    },
    SLOW,
  );
});
