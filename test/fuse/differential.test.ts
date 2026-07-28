/**
 * The differential suite: a real mount of the `node:fs` passthrough against a
 * plain directory, doing the same things.
 *
 * The mount side is Tier 2 (root, `/dev/fuse`, a kernel) and skips itself
 * otherwise. One test is *not* gated: running the script against two ordinary
 * directories proves the script itself is deterministic and root-independent,
 * which is what makes a divergence on the mount side mean something.
 *
 * ```sh
 * pnpm test:differential
 * ```
 *
 * Both roots are driven from this process, which is also the one serving the
 * mount, so every step is strictly sequential — see the threadpool note at the
 * top of `src/fuse/mount.ts`.
 */

import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createNodeFsDriver } from "../../src/drivers/node-fs.ts";
import { liveMounts, mount, type Mount } from "../../src/fuse/mount.ts";
import {
  diffSnapshots,
  formatDivergences,
  makeRemovable,
  randomOps,
  removeContents,
  runDifferential,
  scriptedOps,
  snapshot,
} from "./differential.ts";

const isRoot = (process.getuid?.() ?? -1) === 0;
/** The scripted pass writes a 3 MiB file and 300 directory entries, twice. */
const SLOW = 300_000;

/**
 * The seed, and how many operations it generates.
 *
 * Fixed in the file, because a differential failure has to be reproducible from
 * the repository rather than from the run that happened to find it. The two
 * environment variables are for *hunting*: `UNIMOUNT_DIFF_SEED=7
 * UNIMOUNT_DIFF_OPS=5000 pnpm test:differential` explores further, and anything
 * it finds gets pinned back here.
 */
const SEED = Number(process.env.UNIMOUNT_DIFF_SEED ?? 0xc0_ff_ee);
const RANDOM_OPS = Number(process.env.UNIMOUNT_DIFF_OPS ?? 400);

const sandboxes: string[] = [];

async function sandbox(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "unimount-diff-"));
  sandboxes.push(dir);
  return dir;
}

afterAll(async () => {
  const left: string[] = [];
  for (const dir of sandboxes.splice(0)) {
    // The random script leaves directories the cleanup cannot descend into —
    // see `makeRemovable`. Without this, every run leaked a sandbox.
    await makeRemovable(dir).catch(() => {});
    await rm(dir, { recursive: true, force: true }).catch(() => {});
    if (existsSync(dir)) {
      left.push(dir);
    }
  }
  // Asserted rather than hoped for: a test suite that cannot delete what it
  // created is a test suite that fills `/tmp` on every run, silently.
  expect(left).toEqual([]);
});

describe("the differential script", () => {
  it(
    "is deterministic and root-independent",
    async () => {
      // Two plain directories: no FUSE anywhere. If this ever diverges, the
      // script depends on something it should not (a clock, a path, an inode
      // number) and every mount-side result is worthless.
      const [left, right] = [await sandbox(), await sandbox()];
      const ops = [...scriptedOps(), ...randomOps(SEED, RANDOM_OPS)];
      expect(formatDivergences(await runDifferential(ops, left, right))).toEqual([]);
      expect(diffSnapshots(await snapshot(left), await snapshot(right))).toEqual([]);
    },
    SLOW,
  );
});

describe.skipIf(!isRoot)("a FUSE mount against node:fs", () => {
  const open_: Mount[] = [];

  afterAll(async () => {
    for (const mounted of open_.splice(0)) {
      await mounted.unmount().catch(() => {});
    }
    expect(liveMounts()).toEqual([]);
  });

  /**
   * A mounted passthrough, the directory behind it, and a plain directory that
   * gets the same treatment.
   *
   * `attrTimeout` and `entryTimeout` are zero here, deliberately. Ten seconds
   * of kernel caching is right for a production mount and wrong for an oracle:
   * it would let a stale attribute answer a `stat` the driver never saw, and
   * the suite would agree with a cache instead of with the filesystem.
   */
  async function setup(): Promise<{ mnt: string; backing: string; disk: string }> {
    const dir = await sandbox();
    const [mnt, backing, disk] = [join(dir, "mnt"), join(dir, "backing"), join(dir, "disk")];
    await mkdir(mnt);
    await mkdir(backing);
    await mkdir(disk);
    const mounted = await mount(createNodeFsDriver(backing), mnt, {
      fsname: "unimount-differential",
      attrTimeout: 0,
      entryTimeout: 0,
      readers: 4,
    });
    open_.push(mounted);
    return { mnt, backing, disk };
  }

  async function teardown(mnt: string): Promise<void> {
    const mounted = open_.find((candidate) => candidate.mountpoint === mnt);
    if (mounted !== undefined) {
      open_.splice(open_.indexOf(mounted), 1);
      expect(mounted.session.assertions).toEqual([]);
      const { requests, replies, noReply, dropped } = mounted.session.stats;
      expect(replies + noReply + dropped).toBe(requests);
      await mounted.unmount();
      expect(mounted.session.destroyed).toBe(true);
      expect(mounted.session.openHandles).toBe(0);
    }
  }

  it(
    "matches node:fs across the scripted sequence",
    async () => {
      const { mnt, backing, disk } = await setup();
      try {
        const divergences = await runDifferential(scriptedOps(), mnt, disk);
        expect(formatDivergences(divergences)).toEqual([]);

        // What the mount says it has...
        expect(diffSnapshots(await snapshot(mnt), await snapshot(disk))).toEqual([]);
        // ...and what actually landed on the disk behind it. The second check
        // is the one that catches a mount answering from its own bookkeeping.
        expect(diffSnapshots(await snapshot(backing), await snapshot(disk))).toEqual([]);

        await removeContents(mnt);
        expect(Object.keys((await snapshot(backing)).entries)).toEqual(["."]);
      } finally {
        await teardown(mnt);
      }
    },
    SLOW,
  );

  it(
    `matches node:fs across ${RANDOM_OPS} random operations (seed 0x${SEED.toString(16)})`,
    async () => {
      const { mnt, backing, disk } = await setup();
      try {
        const divergences = await runDifferential(randomOps(SEED, RANDOM_OPS), mnt, disk);
        expect(formatDivergences(divergences)).toEqual([]);
        expect(diffSnapshots(await snapshot(mnt), await snapshot(disk))).toEqual([]);
        expect(diffSnapshots(await snapshot(backing), await snapshot(disk))).toEqual([]);
      } finally {
        await teardown(mnt);
      }
    },
    SLOW,
  );
});
