/**
 * Tier 2 for `mountx/s3`, from the other end: a real **celld** fleet, with this
 * gateway as its bucket.
 *
 * ```sh
 * pnpm test     # runs when `celld` and `esbuild` are on PATH, skips when they are not
 * ```
 *
 * [celld](https://github.com/denoland/celld) runs Cloudflare Workers and
 * Durable Objects on your own machines. Every Durable Object is its own SQLite
 * database, replicated to object storage, and the nodes coordinate through that
 * storage alone — no control plane, no consensus. That makes it an unusually
 * sharp oracle for this transport, because it does not just *read and write*
 * the bucket, it **locks** on it: the ownership record for a cell is written
 * with `If-None-Match: *`, and the whole safety argument rests on the store
 * refusing the second one.
 *
 * A store that accepts a conditional header and ignores it passes every
 * ordinary test and then hands two nodes the same cell. That is exactly what
 * this gateway did until issue #19, and it is what the last case here pins.
 * `test/s3/session.test.ts` already checks the `412` in isolation; what a real
 * fleet adds is that a client's own compare-and-swap loop, written against
 * Amazon, comes out the other side with one owner.
 *
 * ## Shape
 *
 * One gateway for the whole file, one bucket, a [node-fs](../../src/drivers/node-fs.ts)
 * driver over a directory this file made — so "what the bucket holds" is a real
 * tree that `node:fs` can read back and assert on, which is the second half of
 * every case. Each case addresses its own cell, because a celld cell is keyed
 * by name and two cases sharing one would be sharing a counter.
 *
 * Every celld node gets an **ephemeral** port: `--listen 127.0.0.1:0` and
 * `--internal-listen 127.0.0.1:0`, with the resolved addresses read back from
 * the daemon's own startup lines. Nothing here picks a port number, so two
 * checkouts can run this suite at once, and `--advertise` is left off because
 * celld derives it from the resolved internal address.
 *
 * The temporary tree is `test/integrations/.tmp`, **not** `tmpdir()`, and it is
 * gitignored:
 *
 * ```
 * test/integrations/.tmp/bucket        the gateway's driver root — the fleet bucket, as files
 * test/integrations/.tmp/worker        the Worker project `celld deploy` bundles
 * test/integrations/.tmp/state-*       one local SQLite working directory per node
 * ```
 *
 * It **survives the run**, and is swept at the start of the next one rather
 * than at the end of this one. A failed race is diagnosed by reading the
 * ownership record the nodes fought over, and a tree deleted in `afterAll` is a
 * tree that is never there when it is wanted. Next to the test rather than
 * under a random name in the system temp directory, for the same reason.
 *
 * ## The known rough edge, and why this file is not flaky
 *
 * A `PUT` writes the object in place, with no temporary file and no rename, so
 * a reader can catch one half-written (issue #20). celld meets it because the
 * loser of a compare-and-swap immediately re-reads the record it lost, and gets
 * `EOF while parsing a value at line 1 column 0` when it lands mid-write. That
 * fails the *request* — `route failed: ResolveFailed` — and it does not produce
 * two owners.
 *
 * So the race case asserts what the fence actually guarantees and tolerates what
 * is known to be missing: no cell may ever answer `1` twice (that is two
 * owners), and most cells must come out clean. It does not demand that every
 * request succeed, because #20 says some will not.
 *
 * Every spawn is bounded, every wait has a deadline, and no literal control
 * character appears in this file.
 */

import { execFile, spawn, type ChildProcess } from "node:child_process";
import { accessSync, constants as fsConstants } from "node:fs";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createNodeFsDriver } from "../../src/drivers/node-fs.ts";
import { createS3Server, type S3Server } from "../../src/s3/server.ts";

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// the probe
// ---------------------------------------------------------------------------

/**
 * Find an executable on `PATH`, the way `command -v` does.
 *
 * Synchronous and cheap, because a `describe.skipIf` needs its answer at
 * collection time — the same reason `nfsClientProbe()` is synchronous, and the
 * same helper `test/s3/oracle.test.ts` uses for rclone.
 */
function findExecutable(name: string, path = process.env["PATH"]): string | undefined {
  const candidates = name.includes("/")
    ? [name]
    : (path ?? "").split(delimiter).map((directory) => join(directory, name));
  for (const candidate of candidates) {
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
 * Both binaries this file needs.
 *
 * `esbuild` is not optional and not this project's dependency: `celld deploy`
 * bundles a Worker by spawning it from `PATH`, so a host with celld and no
 * esbuild cannot deploy the Durable Object every case here needs. An oracle
 * nobody can run is not a reason for a red suite, so the file skips instead.
 */
const CELLD = findExecutable("celld");
const ESBUILD = findExecutable("esbuild");
const usable = CELLD !== undefined && ESBUILD !== undefined;

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const BUCKET = "cells";
const REGION = "us-east-1";
const CREDENTIALS = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};

/** The gitignored working tree, next to this file. See the module docs. */
const TMP = join(HERE, ".tmp");
/** The gateway's driver root: the fleet bucket, as ordinary files. */
const ROOT = join(TMP, "bucket");
/** The Worker project `celld deploy` bundles. */
const PROJECT = join(TMP, "worker");

/** Longest a celld node may take to print its listening line, in ms. */
const READY_TIMEOUT = 30_000;
/** Longest one spawned command may take, in ms. */
const SPAWN_TIMEOUT = 60_000;
/** Longest one HTTP request to a node may take, in ms. */
const REQUEST_TIMEOUT = 30_000;
/** Longest a node may take to exit after `SIGTERM`, in ms. */
const STOP_TIMEOUT = 10_000;

/** Cells raced by the fencing case. Each one is a fresh compare-and-swap. */
const RACED_CELLS = 6;

/**
 * The Worker: one Durable Object class, addressed by request path.
 *
 * Keyed by path so every case can have a cell of its own from one deployment.
 * The counter is the assertion: a cell with two owners hands out `1` twice,
 * because each owner restored its own empty SQLite database.
 */
const WORKER = `export class Counter {
  constructor(state) {
    this.state = state;
  }
  async fetch() {
    const n = ((await this.state.storage.get("n")) ?? 0) + 1;
    await this.state.storage.put("n", n);
    return new Response(JSON.stringify({ n }), { status: 200 });
  }
}
export default {
  async fetch(request, env) {
    const id = env.COUNTER.idFromName(new URL(request.url).pathname);
    return env.COUNTER.get(id).fetch(request);
  },
};
`;

const WRANGLER = JSON.stringify(
  {
    name: "counter",
    main: "index.js",
    compatibility_date: "2026-01-01",
    durable_objects: { bindings: [{ name: "COUNTER", class_name: "Counter" }] },
    migrations: [{ tag: "v1", new_sqlite_classes: ["Counter"] }],
  },
  undefined,
  2,
);

let server: S3Server;
/** Every `PreconditionFailed` the gateway answered, by request target. */
const refused: string[] = [];
/** Every node started by this file, stopped in `afterAll` whatever happened. */
const nodes: CelldNode[] = [];

// ---------------------------------------------------------------------------
// driving celld
// ---------------------------------------------------------------------------

/** The environment celld reads its bucket credentials and region from. */
function celldEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    AWS_ACCESS_KEY_ID: CREDENTIALS.accessKeyId,
    AWS_SECRET_ACCESS_KEY: CREDENTIALS.secretAccessKey,
    AWS_REGION: REGION,
    ...extra,
  };
}

/** The flags that point any celld invocation at this file's gateway. */
function bucketArgs(): string[] {
  return ["--bucket", `s3://${BUCKET}`, "--endpoint", server.url, "--region", REGION];
}

/** A running celld node: where to send a request, and how to stop it. */
interface CelldNode {
  /** `http://127.0.0.1:<port>`, the public Worker listener. */
  url: string;
  /** Everything the daemon has written to stdout and stderr. */
  output: () => string;
  process: ChildProcess;
  stop: () => Promise<void>;
}

/**
 * Start one node and resolve once it says it is listening.
 *
 * The readiness signal is the daemon's own `celld listening on <addr>` line
 * rather than a sleep or a poll: the port is ephemeral, so that line is the
 * only place the address exists, and waiting for it is the same act as reading
 * it. A node that dies first rejects with whatever it printed, which is the
 * difference between a diagnosable failure and a timeout.
 */
async function startNode(stateDir: string): Promise<CelldNode> {
  await mkdir(stateDir, { recursive: true });
  const child = spawn(
    CELLD as string,
    [...bucketArgs(), "--listen", "127.0.0.1:0", "--internal-listen", "127.0.0.1:0"],
    { env: celldEnv({ CELLD_WATCH: stateDir }), stdio: ["ignore", "pipe", "pipe"] },
  );
  let text = "";
  const collect = (chunk: string): void => void (text += chunk);
  child.stdout?.setEncoding("utf8");
  child.stdout?.on("data", collect);
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", collect);

  const node: CelldNode = {
    url: "",
    output: () => text,
    process: child,
    stop: async () => await stopNode(child),
  };
  nodes.push(node);

  node.url = await new Promise<string>((resolve, reject) => {
    const deadline = setTimeout(
      () => finish(new Error(`celld did not listen within ${READY_TIMEOUT} ms:\n${text}`)),
      READY_TIMEOUT,
    );
    function finish(error?: Error, address?: string): void {
      clearTimeout(deadline);
      child.stdout?.off("data", look);
      child.stderr?.off("data", look);
      child.off("exit", died);
      child.off("error", failed);
      if (error === undefined && address !== undefined) {
        resolve(`http://${address}`);
      } else {
        reject(error ?? new Error("celld start failed"));
      }
    }
    function look(): void {
      // The public listener, not the internal one: both lines say "listening".
      const match = /celld listening on (\S+)/.exec(text);
      if (match?.[1] !== undefined) {
        finish(undefined, match[1]);
      }
    }
    const died = (code: number | null): void =>
      finish(new Error(`celld exited with ${code} before listening:\n${text}`));
    const failed = (error: Error): void => finish(error);
    child.stdout?.on("data", look);
    child.stderr?.on("data", look);
    child.once("exit", died);
    child.once("error", failed);
    look();
  });
  return node;
}

/** Stop a node, and do not return until the process is gone. */
async function stopNode(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  child.kill("SIGTERM");
  await new Promise<void>((resolve) => {
    const deadline = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, STOP_TIMEOUT);
    child.once("exit", () => {
      clearTimeout(deadline);
      resolve();
    });
  });
}

/** One request to a node's Worker listener, with its body, never rejecting. */
async function call(node: CelldNode, path: string): Promise<{ status: number; body: string }> {
  try {
    const response = await fetch(new URL(path, node.url), {
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    });
    return { status: response.status, body: (await response.text()).trim() };
  } catch (error) {
    return { status: 0, body: `[request failed] ${(error as Error).message}` };
  }
}

/** The counter a successful Worker reply carries, or `undefined` for a failure. */
function counterOf(reply: { status: number; body: string }): number | undefined {
  if (reply.status !== 200) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(reply.body) as { n?: unknown };
    return typeof parsed.n === "number" ? parsed.n : undefined;
  } catch {
    return undefined;
  }
}

/** Every file the bucket holds, as keys relative to the driver root. */
async function bucketKeys(): Promise<string[]> {
  const entries = await readdir(ROOT, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) =>
      join(entry.parentPath, entry.name)
        .slice(ROOT.length + 1)
        .replaceAll("\\", "/"),
    )
    .sort();
}

// ---------------------------------------------------------------------------
// the suite
// ---------------------------------------------------------------------------

describe.skipIf(!usable)("a celld fleet with mountx/s3 as its bucket", () => {
  beforeAll(async () => {
    await rm(TMP, { recursive: true, force: true });
    await mkdir(ROOT, { recursive: true });
    await mkdir(PROJECT, { recursive: true });
    await writeFile(join(PROJECT, "index.js"), WORKER);
    await writeFile(join(PROJECT, "wrangler.json"), WRANGLER);

    server = await createS3Server(createNodeFsDriver(ROOT), {
      bucket: BUCKET,
      credentials: CREDENTIALS,
      region: REGION,
      onError: (error, head) => {
        const code = (error as { spec?: { code?: string } }).spec?.code;
        if (code === "PreconditionFailed" && head !== undefined) {
          refused.push(head.target);
        }
      },
    }).listen();

    // The deployment every case runs against. Its objects are asserted below.
    await run(CELLD as string, ["deploy", PROJECT, ...bucketArgs()], {
      env: celldEnv(),
      timeout: SPAWN_TIMEOUT,
    });
  }, 120_000);

  afterAll(async () => {
    for (const node of nodes.splice(0)) {
      await node.stop().catch(() => {
        // Cleanup, not an assertion. The cases own the diagnosis.
      });
    }
    await server?.close();
    /* The tree is deliberately **not** removed here. See the module docs: it is
       swept at the start of the next run instead, so whatever a failing run
       left behind is still on disk to be read. */
  }, 60_000);

  it("deploys a Worker into the driver's directory", async () => {
    const keys = await bucketKeys();

    // celld reads `deploy/current.json` at startup to find the live version.
    expect(keys).toContain("deploy/current.json");
    const current = JSON.parse(await readFile(join(ROOT, "deploy/current.json"), "utf8")) as Record<
      string,
      unknown
    >;
    expect(Object.keys(current).length).toBeGreaterThan(0);

    // The bundle itself is a real file, and it is the Worker we wrote.
    const bundles = keys.filter((key) => key.endsWith("/index.js"));
    expect(bundles.length).toBe(1);
    expect(await readFile(join(ROOT, bundles[0] as string), "utf8")).toContain("COUNTER");
  }, 30_000);

  it("activates a Durable Object, replicates it, and restores it from the bucket", async () => {
    const state = join(TMP, "state-solo");
    const cell = "/counter-solo";
    const first = await startNode(state);

    // A cold cell activates on the first request, and keeps counting.
    expect(counterOf(await call(first, cell)), first.output()).toBe(1);
    expect(counterOf(await call(first, cell))).toBe(2);

    // Its ownership record and its SQLite pages are in the bucket, as files.
    const keys = await bucketKeys();
    expect(keys.some((key) => key.startsWith("cells/") && key.endsWith("/own.json"))).toBe(true);
    expect(keys.some((key) => key.includes("/ltx/") && key.endsWith(".ltx"))).toBe(true);

    // The bucket is the source of truth: take the node's local state away and
    // the next node has to restore the cell from what this gateway holds.
    await first.stop();
    await rm(state, { recursive: true, force: true });

    const second = await startNode(state);
    expect(counterOf(await call(second, cell)), second.output()).toBe(3);
    await second.stop();
  }, 180_000);

  it("fences two nodes racing for the same new cell", async () => {
    const a = await startNode(join(TMP, "state-a"));
    const b = await startNode(join(TMP, "state-b"));
    const before = refused.length;

    /* Both nodes, one cell, at the same instant, repeated over fresh cells.
       Each pair is a compare-and-swap the two nodes run against the same
       ownership key: one create wins, the loser gets `412` and routes its
       request to the winner. */
    const races = await Promise.all(
      Array.from({ length: RACED_CELLS }, async (_, index) => {
        const cell = `/race-${index}`;
        const [fromA, fromB] = await Promise.all([call(a, cell), call(b, cell)]);
        return { cell, values: [counterOf(fromA), counterOf(fromB)], replies: [fromA, fromB] };
      }),
    );

    let clean = 0;
    for (const race of races) {
      const values = race.values.filter((value): value is number => value !== undefined);
      const report = `${race.cell}: ${JSON.stringify(race.replies)}`;

      // The whole point. Two owners each restore an empty database, so both
      // answer `1`; one owner answers `1` and then `2`, in either order.
      expect(values.filter((value) => value === 1).length, report).toBeLessThanOrEqual(1);
      expect([...values].sort(), report).toEqual([1, 2].slice(0, values.length));
      expect(values.length, report).toBeGreaterThan(0);
      if (values.length === 2) {
        clean++;
      }
    }

    /* Not every request has to succeed: a loser re-reads the record it lost and
       can catch the winner's `PUT` half-written (issue #20), which fails that
       one request without ever handing out a second owner. Four in a hundred,
       measured.

       This is also the line that catches issue #19, and it is worth knowing
       why it rather than the two-owners check above. When the fence is gone,
       both nodes take the cell and celld's *own* second defence stops it: the
       loser re-reads the ownership record before acknowledging, finds another
       node at its epoch, and answers `DurabilityUnproven` instead of a wrong
       count. So a store that ignores conditional writes does not show up as
       two `1`s — it shows up as every race failing. Verified against the
       commit before the fix: six of six, `clean` at zero. */
    expect(clean, JSON.stringify(races)).toBeGreaterThanOrEqual(Math.ceil(RACED_CELLS / 2));

    // The `412`s are the fence itself: every race had a loser, and the gateway
    // is what told it so. Ownership keys only — nothing else here is conditional.
    const ownership = refused.slice(before).filter((target) => target.endsWith("own.json"));
    expect(ownership.length).toBeGreaterThanOrEqual(RACED_CELLS);

    await a.stop();
    await b.stop();
  }, 300_000);
});
