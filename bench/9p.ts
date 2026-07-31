/**
 * `pnpm bench:9p` — the 9P column, and the first measured numbers behind this
 * transport's two tuning knobs.
 *
 * Shaped exactly like `bench/fuse.ts`, for the same reason it is a separate
 * command from `pnpm bench`: a 9P mount needs `CAP_SYS_ADMIN` and v9fs has no
 * setuid helper of the `fusermount3` kind, so this cannot join the rootless
 * columns. It is its own script rather than a second file inside `pnpm
 * bench:root` because each column writes its own `--json`, and a script running
 * two of them could only hand the flag to one.
 *
 * **What the variants are for.** The FUSE column gives up one negotiated win
 * per row; 9P negotiates almost nothing — a dialect and an `msize` — so the
 * rows here move the two numbers that are actually tunable and have never been
 * measured: the `msize` a mount asks for (`P9_DEFAULT_MOUNT_MSIZE`, the
 * kernel's own default) and the server's dispatch window
 * (`DEFAULT_MAX_IN_FLIGHT`, `src/9p/server.ts`). Nothing is added to the
 * library to make this possible; both are existing options.
 *
 * **No cache row, deliberately.** Every mount here is the shipped
 * `cache=none`, so no scenario is answered out of a kernel cache and there is
 * no warm/cold distinction to draw — which is why `ls-l-cold` is absent where
 * the FUSE column runs it. Raising `cache=` would measure the bet described on
 * {@link MountP9Options.cache}, not the transport.
 *
 * The mount is served from *this* process and driven from a child
 * (`bench/drive.ts`) — see the note there; on 9P it is `spawn()` and
 * synchronous calls that deadlock, not asynchronous ones.
 *
 * ```sh
 * pnpm bench:9p                       # human summary
 * pnpm bench:9p -- --json out.json    # and the machine-readable one
 * ```
 */

import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  mount9p,
  type MountP9Options,
  P9_DEFAULT_MOUNT_MSIZE,
  p9ClientProbe,
  unmountAll9p,
} from "../src/9p/mount.ts";
import { DEFAULT_MAX_IN_FLIGHT } from "../src/9p/server.ts";
import type { P9Session } from "../src/9p/session.ts";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import { drive } from "./drive.ts";
import { report, type Measurement } from "./harness.ts";
import { FULL } from "./scenarios.ts";

const KIB = 1024;

interface Variant {
  name: string;
  options: MountP9Options;
  keys: string[];
  /** Why this variant exists, for the report. */
  why: string;
}

/**
 * One mount per row. Each knob's rows run only the scenarios that knob can
 * plausibly touch — `msize` bounds one message, so it is the I/O and the
 * directory pages; the dispatch window bounds how many requests are answered at
 * once, so it is only visible with requests actually in flight.
 */
const VARIANTS: Variant[] = [
  {
    name: "default",
    options: {},
    keys: FULL,
    why: `what the library ships: msize ${P9_DEFAULT_MOUNT_MSIZE}, maxInFlight ${DEFAULT_MAX_IN_FLIGHT}, cache=none, access=client`,
  },
  {
    name: "msize=16KiB",
    options: { mountMsize: 16 * KIB },
    keys: ["write-4k", "seq-read", "seq-write", "readdir-100"],
    why: "eight times fewer bytes per message: what the kernel shipped before it raised its own default to 128 KiB",
  },
  {
    name: "msize=1MiB",
    options: { mountMsize: 1024 * KIB },
    keys: ["write-4k", "seq-read", "seq-write", "readdir-100"],
    why: "the ceiling (P9_MAX_MOUNT_MSIZE, MAX_SOCK_BUF), which is also the session's own msize cap",
  },
  {
    name: "maxInFlight=1",
    options: { maxInFlight: 1 },
    keys: ["parallel-stat", "stat"],
    why: "the window closed: one request answered at a time, the rest waiting as frames",
  },
  {
    name: "maxInFlight=64",
    options: { maxInFlight: 64 },
    keys: ["parallel-stat", "stat"],
    why: "four times the default, and wider than the 64-op scenario is deep",
  },
];

/**
 * Watch the session's request counter while the client works.
 *
 * The same instrument `bench/fuse.ts` uses, and the same warning applies: this
 * is not any scenario's ops/sec. One `stat(2)` through v9fs is a `Twalk`, a
 * `Tgetattr` and a `Tclunk` — the census in `.agents/environment.md` shows how
 * lopsidedly walk-shaped this client is — so sampling the counter is the only
 * way to say what the transport itself sustained.
 */
function trackRequests(session: P9Session): { stop: () => { peak: number; total: number } } {
  const window = 250;
  const start = session.stats.requests;
  let last = start;
  // The *measured* interval, not the requested one: a timer that fires late
  // would otherwise have its extra requests divided by a window it did not
  // actually take.
  let since = process.hrtime.bigint();
  let peak = 0;
  const timer = setInterval(() => {
    const now = session.stats.requests;
    const at = process.hrtime.bigint();
    const elapsedMs = Number(at - since) / 1e6;
    if (elapsedMs > 0) {
      peak = Math.max(peak, ((now - last) * 1000) / elapsedMs);
    }
    last = now;
    since = at;
  }, window);
  timer.unref();
  return {
    stop: () => {
      clearInterval(timer);
      return { peak: Math.round(peak), total: session.stats.requests - start };
    },
  };
}

/** The busiest messages this variant saw, `"Twalk=9073 Tclunk=7562 …"`. */
function census(session: P9Session, limit = 6): string {
  return [...session.stats.messages]
    .sort((left, right) => right[1] - left[1])
    .slice(0, limit)
    .map(([name, count]) => `${name}=${count}`)
    .join(" ");
}

async function main(): Promise<void> {
  const probe = p9ClientProbe();
  if (!probe.usable) {
    // A skip, not a failure: the same discipline every Tier-2 suite keeps, and
    // for the same reason — a host without a v9fs client cannot acquire one.
    process.stderr.write(`bench: skipping the 9P column — ${probe.reason}\n`);
    return;
  }
  const sandbox = await mkdtemp(join(tmpdir(), "mountx-bench-"));
  const results: Measurement[] = [];
  try {
    for (const [index, variant] of VARIANTS.entries()) {
      const mountpoint = join(sandbox, `mnt-${index}`);
      await mkdir(mountpoint);
      process.stderr.write(`bench: ${variant.name} …\n`);
      const mounted = await mount9p(createMemoryDriver(), mountpoint, {
        ...variant.options,
      });
      const session = mounted.connection.session;
      const requests = trackRequests(session);
      try {
        const measured = await drive({
          mountpoint,
          keys: variant.keys,
          group: "9P mount (memory driver)",
          variant: variant.name,
        });
        const seen = requests.stop();
        for (const measurement of measured) {
          measurement.notes = {
            why: variant.why,
            // What the two ends agreed, read off the session rather than off
            // the option: the negotiated value is the smaller of the mount's
            // proposal and the server's own ceiling.
            msize: session.msize ?? 0,
            maxInFlight: variant.options.maxInFlight ?? DEFAULT_MAX_IN_FLIGHT,
            cache: "none",
            access: "client",
            trans: mounted.trans,
            protocol: session.version ?? "",
            // Per *variant*, not per scenario: the counter is the session's,
            // and it counts the scenarios' setup traffic too.
            peakP9RequestsPerSec: seen.peak,
            p9Requests: seen.total,
            messages: census(session),
          };
        }
        results.push(...measured);
      } finally {
        requests.stop();
        await mounted.unmount();
      }
    }
  } finally {
    // Belt and braces, exactly as the FUSE column does it: a mountpoint left
    // behind is the one failure mode of this script that costs someone else an
    // afternoon.
    for (const failure of await unmountAll9p()) {
      process.stderr.write(`bench: unmount failed: ${String(failure)}\n`);
    }
    await rm(sandbox, { recursive: true, force: true }).catch(() => {});
  }
  report("pnpm bench:9p", results, process.argv);
}

await main();
