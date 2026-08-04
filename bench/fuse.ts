/**
 * `pnpm bench:root` — the FUSE column, and the measured half of IDEA.md's
 * central performance claim.
 *
 * IDEA.md says the wins are in *negotiation*, not in micro-optimizing JS, and
 * that the benchmark suite is therefore a v1 deliverable rather than a
 * nice-to-have: it is the proof. So every scenario here runs against the
 * defaults the library ships with, and then again with one negotiated win taken
 * away — `max_write` back to 128 KiB, `attr_timeout`/`entry_timeout` to zero,
 * `READDIRPLUS` off, `FOPEN_KEEP_CACHE` off, the reader count moved. Nothing is
 * added to the library to make this possible; these are all existing options.
 *
 * The mounts are served from *this* process and driven from a child
 * (`bench/drive.ts` → `bench/mount-client.ts`), which is what makes it safe to
 * have operations in flight — see the note there.
 *
 * ```sh
 * pnpm bench:root                       # human summary
 * pnpm bench:root -- --json out.json    # and the machine-readable one
 * ```
 */

import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import { FUSE_READDIRPLUS_AUTO } from "../src/fuse/constants.ts";
import type { FuseSession } from "../src/fuse/session.ts";
import { mount, type MountOptions, unmountAll } from "../src/fuse/mount.ts";
import { createLoopback } from "../src/harness.ts";
import { drive } from "./drive.ts";
import { report, sampleRate, type Measurement, type RateSample } from "./harness.ts";
import { CORE, FULL_FUSE, populateCold } from "./scenarios.ts";

interface Variant {
  name: string;
  options: MountOptions;
  keys: string[];
  /** Why this variant exists, for the report. */
  why: string;
}

/**
 * One mount per row. Each degraded variant runs only the scenarios the knob it
 * moves can plausibly touch — the point is a comparison against `default`, not
 * a full matrix, and every mount costs a `mount(8)` and an `umount(8)`.
 *
 * The three that also set the timeouts to zero do it so the comparison is
 * against `attr/entry timeout=0` rather than against `default`: with the
 * shipped 10-second timeouts the kernel answers most of these scenarios out of
 * its own caches, which is a genuine win but hides everything else.
 */
const VARIANTS: Variant[] = [
  {
    name: "default",
    options: {},
    keys: FULL_FUSE,
    why: "what the library ships: max_write 1 MiB, readdirplus, keep_cache, 10 s timeouts, 2 readers",
  },
  {
    name: "attr/entry timeout=0",
    options: { attrTimeout: 0, entryTimeout: 0 },
    keys: [...CORE, "ls-l", "ls-l-cold", "stat-walk", "parallel-stat"],
    why: "every metadata op reaches the driver; the honest per-request cost",
  },
  {
    name: "maxWrite=128KiB",
    options: { init: { maxWrite: 128 * 1024 } },
    keys: ["write-4k", "seq-write", "seq-read"],
    why: "FUSE_MAX_PAGES given up — the pre-7.28 ceiling",
  },
  {
    name: "writebackCache=on",
    options: { init: { writebackCache: true } },
    keys: ["write-4k", "seq-write", "create-files"],
    why: "the one negotiated win v1 does *not* take: what it would be worth, and what it costs in semantics",
  },
  {
    name: "readdirplus, no AUTO",
    options: { init: { withoutFlags: FUSE_READDIRPLUS_AUTO } },
    keys: ["ls-l", "ls-l-cold", "readdir-100"],
    why: "READDIRPLUS on every page rather than only the first — see the report",
  },
  {
    name: "readdirplus=off",
    options: { init: { readdirplus: false } },
    keys: ["ls-l", "ls-l-cold", "readdir-100"],
    why: "LOOKUP no longer folded into READDIR, shipped timeouts",
  },
  {
    name: "readdirplus=off, timeout=0",
    options: { init: { readdirplus: false }, attrTimeout: 0, entryTimeout: 0 },
    keys: ["ls-l", "ls-l-cold", "readdir-100"],
    why: "the same, with no cache to hide behind",
  },
  {
    name: "keepCache=off",
    options: { keepCache: false },
    keys: ["seq-read", "open-read-4k"],
    why: "FOPEN_KEEP_CACHE given up: the page cache is dropped on every open",
  },
  {
    name: "readers=1, timeout=0",
    options: { readers: 1, attrTimeout: 0, entryTimeout: 0 },
    keys: ["parallel-stat", "stat"],
    why: "one read outstanding on /dev/fuse",
  },
  {
    name: "readers=4, timeout=0",
    options: { readers: 4, attrTimeout: 0, entryTimeout: 0 },
    keys: ["parallel-stat", "stat"],
    why: "four, against the default of two",
  },
];

/**
 * Watch the session's request counter while the client works.
 *
 * This is the number IDEA.md's "low tens of thousands of ops/sec" is actually
 * about, and it is not the same as any scenario's ops/sec: one `stat(2)` is two
 * FUSE requests when `entry_timeout` is zero and none at all when the kernel's
 * caches are warm. Sampling the counter is the only way to say what the
 * transport itself sustained.
 */
function trackRequests(session: FuseSession): { stop: () => RateSample } {
  return sampleRate(() => session.stats.requests);
}

async function main(): Promise<void> {
  if ((process.getuid?.() ?? -1) !== 0) {
    process.stderr.write("bench: the FUSE column needs root — run `pnpm bench:root`\n");
    process.exitCode = 1;
    return;
  }
  const sandbox = await mkdtemp(join(tmpdir(), "mountx-bench-"));
  const results: Measurement[] = [];
  try {
    for (const [index, variant] of VARIANTS.entries()) {
      const mountpoint = join(sandbox, `mnt-${index}`);
      await mkdir(mountpoint);
      process.stderr.write(`bench: ${variant.name} …\n`);
      const driver = createMemoryDriver();
      if (variant.keys.includes("ls-l-cold")) {
        // Straight into the driver, before the kernel has a chance to see any
        // of it — that is what makes the cold listing cold.
        await populateCold(createLoopback(driver));
      }
      const mounted = await mount(driver, mountpoint, {
        fsname: "mountx-bench",
        ...variant.options,
      });
      const negotiated = mounted.session.negotiated;
      const requests = trackRequests(mounted.session);
      try {
        const measured = await drive({
          mountpoint,
          keys: variant.keys,
          group: "FUSE mount (memory driver)",
          variant: variant.name,
        });
        const seen = requests.stop();
        for (const measurement of measured) {
          measurement.notes = {
            why: variant.why,
            readers: variant.options.readers ?? 2,
            attrTimeoutSec: variant.options.attrTimeout ?? 10,
            entryTimeoutSec: variant.options.entryTimeout ?? 10,
            keepCache: variant.options.keepCache !== false,
            maxWrite: negotiated?.maxWrite ?? 0,
            readdirplus: negotiated?.readdirplus ?? false,
            writebackCache: negotiated?.writebackCache ?? false,
            protocol: `7.${negotiated?.minor ?? 0}`,
            // Per *variant*, not per scenario: the counter is the session's.
            peakFuseRequestsPerSec: seen.peak,
            fuseRequests: seen.total,
          };
        }
        results.push(...measured);
      } finally {
        requests.stop();
        await mounted.unmount();
      }
    }
  } finally {
    // Belt and braces: a mountpoint left behind is the one failure mode of this
    // script that costs someone else an afternoon.
    for (const failure of await unmountAll()) {
      process.stderr.write(`bench: unmount failed: ${String(failure)}\n`);
    }
    await rm(sandbox, { recursive: true, force: true }).catch(() => {});
  }
  report("pnpm bench:root", results, process.argv);
}

await main();
