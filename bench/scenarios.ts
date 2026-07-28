/**
 * The scenarios, written once and run in every column.
 *
 * The same trick the conformance matrix uses: everything here is expressed
 * against {@link Loopback}, so the *identical* client code drives the memory
 * driver directly (the ceiling), a real FUSE mount through `node:fs`, and the
 * NFSv3 server through the JS client. Any difference between the columns is
 * transport, not benchmark.
 *
 * Two of them look like they measure the same thing twice and do not, which is
 * the whole point of the exercise: `stat` and `open+read` are served out of the
 * *kernel's* caches when `attr_timeout`/`entry_timeout` are at their defaults,
 * and reach the driver on every call when they are zero. Running both is what
 * turns IDEA.md's "the wins are in negotiation, not in micro-optimizing JS"
 * into a number.
 */

import type { Loopback } from "../src/harness.ts";
import { measure, type Measurement } from "./harness.ts";

const KIB = 1024;
const MIB = 1024 * 1024;

/** Bytes in the sequential-throughput files. */
export const THROUGHPUT_SIZE = 100 * MIB;
/** Chunk one throughput iteration is issued in — the negotiated `max_write` at its default. */
export const THROUGHPUT_CHUNK = MIB;
/** Entries in the `ls -l` directory. */
export const LISTING_ENTRIES = 1000;
/** Directories `ls-l-cold` lists, one per iteration. See {@link populateCold}. */
export const COLD_LISTINGS = 8;
/** Files one `create` iteration makes. */
export const CREATE_FILES = 500;
/** Files the stat walk visits. */
export const WALK_FILES = 500;
/** Operations issued at once by the parallel scenario. */
export const PARALLEL_WIDTH = 64;

/**
 * What `bench/fuse.ts` asks `bench/fuse-client.ts` for: the same request
 * {@link runScenarios} takes, plus the mountpoint to open it at. It lives here
 * rather than in either half so that importing the constant does not import the
 * script that runs on load.
 */
export interface ClientRequest {
  mountpoint: string;
  keys: string[];
  group: string;
  variant: string;
  notes?: Record<string, string | number | boolean>;
}

/** Marker the parent looks for, so anything else the child prints stays harmless. */
export const RESULT_PREFIX = "__BENCH__";

export interface ScenarioRun {
  fs: Loopback;
  /** A directory this scenario owns, created for it and removed afterwards. */
  dir: string;
  group: string;
  variant: string;
  notes?: Record<string, string | number | boolean>;
}

export interface Scenario {
  key: string;
  measure: (run: ScenarioRun) => Promise<Measurement>;
}

/** The four ops every column runs. */
export const CORE = ["stat", "open-read-4k", "write-4k", "readdir-100"];

/** Everything that means something without a kernel cache to play against. */
export const FULL = [
  ...CORE,
  "seq-read",
  "seq-write",
  "create-files",
  "ls-l",
  "stat-walk",
  "parallel-stat",
];

/**
 * `FULL` plus the cold listing, which only means something *behind* a cache —
 * so only the FUSE column runs it, and only it can set the directories up
 * ({@link populateCold}).
 */
export const FULL_FUSE = [...FULL, "ls-l-cold"];

const payload = (size: number): Uint8Array => new Uint8Array(size).fill(0x61);

/** Where `ls-l-cold`'s directories live, at the root of the filesystem. */
export const COLD_PREFIX = "cold-";

/**
 * Fill {@link COLD_LISTINGS} directories the transport has never been told
 * about. Called by the *server* side against the driver itself, which is what
 * makes them cold: nothing the kernel caches has ever named them.
 */
export async function populateCold(fs: Loopback): Promise<void> {
  for (let index = 0; index < COLD_LISTINGS; index++) {
    const directory = `/${COLD_PREFIX}${index}`;
    await fs.mkdir(directory);
    await fill(fs, directory, LISTING_ENTRIES, 16);
  }
}

/** Remove a tree one entry at a time (see the threadpool note in `src/fuse/mount.ts`). */
export async function removeTree(fs: Loopback, path: string): Promise<void> {
  let entries: Awaited<ReturnType<Loopback["readdir"]>>;
  try {
    entries = await fs.readdir(path, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const child = `${path}/${entry.name}`;
    if (entry.isDirectory()) {
      await removeTree(fs, child);
    } else {
      await fs.unlink(child).catch(() => {});
    }
  }
  await fs.rmdir(path).catch(() => {});
}

/** `n` files of `size` bytes in `dir`, named `file-0000…`. */
async function fill(fs: Loopback, dir: string, count: number, size: number): Promise<string[]> {
  const bytes = payload(size);
  const paths: string[] = [];
  for (let i = 0; i < count; i++) {
    const path = `${dir}/file-${String(i).padStart(4, "0")}`;
    await fs.writeFile(path, bytes);
    paths.push(path);
  }
  return paths;
}

/** Read a whole file in `THROUGHPUT_CHUNK` slices, into one reused buffer. */
async function readAll(fs: Loopback, path: string, buffer: Uint8Array): Promise<number> {
  const handle = await fs.open(path, "r");
  let total = 0;
  try {
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.byteLength, total);
      if (bytesRead === 0) {
        return total;
      }
      total += bytesRead;
    }
  } finally {
    await handle.close();
  }
}

function scenario(key: string, body: (run: ScenarioRun) => Promise<Measurement>): Scenario {
  return { key, measure: body };
}

/** Everything the harness knows how to run, by key. */
export const SCENARIOS: Scenario[] = [
  scenario("stat", async (run) => {
    const path = `${run.dir}/target`;
    await run.fs.writeFile(path, "x");
    return measure({
      ...common(run),
      scenario: "stat",
      run: async () => void (await run.fs.stat(path)),
    });
  }),

  scenario("open-read-4k", async (run) => {
    const path = `${run.dir}/target`;
    await run.fs.writeFile(path, payload(4 * KIB));
    const buffer = new Uint8Array(4 * KIB);
    return measure({
      ...common(run),
      scenario: "open + read 4 KiB",
      run: async () => {
        const handle = await run.fs.open(path, "r");
        await handle.read(buffer, 0, buffer.byteLength, 0);
        await handle.close();
      },
    });
  }),

  scenario("write-4k", async (run) => {
    const path = `${run.dir}/target`;
    await run.fs.writeFile(path, payload(4 * KIB));
    const handle = await run.fs.open(path, "r+");
    const buffer = payload(4 * KIB);
    try {
      return await measure({
        ...common(run),
        scenario: "write 4 KiB",
        run: async () => void (await handle.write(buffer, 0, buffer.byteLength, 0)),
      });
    } finally {
      await handle.close();
    }
  }),

  scenario("readdir-100", async (run) => {
    await fill(run.fs, run.dir, 100, 16);
    return measure({
      ...common(run),
      scenario: "readdir (100 entries)",
      work: { units: 100, unit: "entries" },
      run: async () => void (await run.fs.readdir(run.dir, { withFileTypes: true })),
    });
  }),

  scenario("seq-read", async (run) => {
    const path = `${run.dir}/big`;
    await writeChunks(run.fs, path, THROUGHPUT_SIZE);
    const buffer = new Uint8Array(THROUGHPUT_CHUNK);
    return measure({
      ...common(run),
      scenario: "sequential read, 100 MiB",
      warmup: 1,
      targetMs: 0,
      minIterations: 3,
      maxIterations: 3,
      work: { units: THROUGHPUT_SIZE / MIB, unit: "MiB" },
      run: async () => void (await readAll(run.fs, path, buffer)),
    });
  }),

  scenario("seq-write", async (run) => {
    // One path, opened `w` every time: the truncate frees the previous
    // iteration's bytes, so the memory driver holds one copy rather than five.
    const path = `${run.dir}/big`;
    return measure({
      ...common(run),
      scenario: "sequential write, 100 MiB",
      warmup: 1,
      targetMs: 0,
      minIterations: 3,
      maxIterations: 3,
      work: { units: THROUGHPUT_SIZE / MIB, unit: "MiB" },
      run: async () => void (await writeChunks(run.fs, path, THROUGHPUT_SIZE)),
    });
  }),

  scenario("create-files", async (run) => {
    const bytes = payload(KIB);
    let round = 0;
    return measure({
      ...common(run),
      scenario: `create ${CREATE_FILES} small files`,
      warmup: 1,
      targetMs: 0,
      minIterations: 3,
      maxIterations: 3,
      work: { units: CREATE_FILES, unit: "files" },
      run: async () => {
        const directory = `${run.dir}/round-${round++}`;
        await run.fs.mkdir(directory);
        for (let i = 0; i < CREATE_FILES; i++) {
          const handle = await run.fs.open(`${directory}/f-${i}`, "wx", 0o644);
          await handle.write(bytes, 0, bytes.byteLength, 0);
          await handle.close();
        }
      },
    });
  }),

  scenario("ls-l", async (run) => {
    await fill(run.fs, run.dir, LISTING_ENTRIES, 16);
    return measure({
      ...common(run),
      scenario: `ls -l (${LISTING_ENTRIES} entries)`,
      warmup: 1,
      targetMs: 1000,
      minIterations: 3,
      maxIterations: 20,
      work: { units: LISTING_ENTRIES, unit: "entries" },
      run: async () => {
        // What `ls -l` is: one getdents pass, then one stat per name. With
        // READDIRPLUS the kernel already has the attributes and the stats never
        // leave it; without it, every name is a LOOKUP.
        const entries = await run.fs.readdir(run.dir, { withFileTypes: true });
        for (const entry of entries) {
          await run.fs.lstat(`${run.dir}/${entry.name}`);
        }
      },
    });
  }),

  scenario("ls-l-cold", async (run) => {
    // The only honest way to measure what READDIRPLUS buys. A warm `ls -l` is
    // answered by the kernel's dentry and attribute caches, and *creating* the
    // directory through the mount is what warms them — so these directories are
    // made straight in the driver by `populateCold`, behind the transport's
    // back, and each iteration lists one the kernel has never seen.
    return measure({
      ...common(run),
      scenario: `ls -l (${LISTING_ENTRIES} entries, cold)`,
      warmup: 0,
      targetMs: 0,
      minIterations: COLD_LISTINGS,
      maxIterations: COLD_LISTINGS,
      work: { units: LISTING_ENTRIES, unit: "entries" },
      run: async (iteration) => {
        const directory = `/${COLD_PREFIX}${iteration}`;
        const entries = await run.fs.readdir(directory, { withFileTypes: true });
        for (const entry of entries) {
          await run.fs.lstat(`${directory}/${entry.name}`);
        }
      },
    });
  }),

  scenario("stat-walk", async (run) => {
    // Deep-ish, so each stat resolves a path rather than hitting one directory.
    const paths: string[] = [];
    const perDirectory = 25;
    for (let d = 0; d * perDirectory < WALK_FILES; d++) {
      const directory = `${run.dir}/d-${d}/sub`;
      await run.fs.mkdir(directory, { recursive: true });
      for (let i = 0; i < perDirectory; i++) {
        const path = `${directory}/f-${i}`;
        await run.fs.writeFile(path, "x");
        paths.push(path);
      }
    }
    return measure({
      ...common(run),
      scenario: `stat walk (${paths.length} files)`,
      warmup: 1,
      targetMs: 1000,
      minIterations: 3,
      maxIterations: 50,
      work: { units: paths.length, unit: "stats" },
      run: async () => {
        for (const path of paths) {
          await run.fs.stat(path);
        }
      },
    });
  }),

  scenario("parallel-stat", async (run) => {
    const paths = await fill(run.fs, run.dir, PARALLEL_WIDTH, 16);
    return measure({
      ...common(run),
      scenario: `stat ×${PARALLEL_WIDTH} in flight`,
      work: { units: PARALLEL_WIDTH, unit: "ops" },
      minIterations: 20,
      maxIterations: 2000,
      run: async () => void (await Promise.all(paths.map((path) => run.fs.stat(path)))),
    });
  }),
];

function common(run: ScenarioRun): {
  group: string;
  variant: string;
  notes?: ScenarioRun["notes"];
} {
  return { group: run.group, variant: run.variant, notes: run.notes };
}

/** Write `size` bytes to `path` in `THROUGHPUT_CHUNK` slices, truncating first. */
async function writeChunks(fs: Loopback, path: string, size: number): Promise<void> {
  const chunk = payload(THROUGHPUT_CHUNK);
  const handle = await fs.open(path, "w", 0o644);
  try {
    for (let offset = 0; offset < size; offset += chunk.byteLength) {
      const count = Math.min(chunk.byteLength, size - offset);
      await handle.write(chunk, 0, count, offset);
    }
  } finally {
    await handle.close();
  }
}

const BY_KEY = new Map(SCENARIOS.map((entry) => [entry.key, entry]));

/**
 * Run the named scenarios against one filesystem, each in its own directory,
 * and clean up after every one of them.
 */
export async function runScenarios(
  fs: Loopback,
  keys: readonly string[],
  context: { group: string; variant?: string; notes?: ScenarioRun["notes"] },
): Promise<Measurement[]> {
  const results: Measurement[] = [];
  for (const key of keys) {
    const found = BY_KEY.get(key);
    if (found === undefined) {
      throw new Error(`bench: no scenario named ${key}`);
    }
    const dir = `/bench-${key}`;
    await removeTree(fs, dir);
    await fs.mkdir(dir);
    try {
      results.push(
        await found.measure({
          fs,
          dir,
          group: context.group,
          variant: context.variant ?? "default",
          notes: context.notes,
        }),
      );
    } finally {
      await removeTree(fs, dir);
    }
  }
  return results;
}
