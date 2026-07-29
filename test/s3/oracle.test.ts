/**
 * Tier 2 for the S3 gateway: a **foreign client**, driven for real.
 *
 * ```sh
 * pnpm test            # this file runs when rclone is on PATH, skips when it is not
 * ```
 *
 * Everything else under `test/s3/` is written from this repository's own
 * codecs — `test/s3/client.ts` signs with `src/s3/sigv4.ts` and parses with
 * `src/s3/xml.ts`, so a symmetric mistake in either is invisible to it. This
 * file is the answer to that: [rclone](https://rclone.org) shares none of our
 * code, is the client the gateway's mtime convention was designed against, and
 * has opinions about S3 that no fixture would have thought to have. `curl`
 * plays the same role for presigned URLs — a URL that is only a URL, with no
 * `Authorization` header behind it.
 *
 * It skips itself cleanly when neither binary is installed, the way
 * `test/nfs/mount.test.ts` skips on `nfsClientProbe()`: an oracle nobody can
 * run is not a reason for a red suite. `.agents/environment.md` records where
 * this host's rclone came from.
 *
 * ## The configuration is in the environment, and that is deliberate
 *
 * rclone is invoked with **no config file at all** (`RCLONE_CONFIG=""`) and the
 * remote defined entirely by `RCLONE_CONFIG_MX_*` variables, so a test run
 * writes nothing to `~/.config/rclone` and reads nothing from it — a developer
 * with their own remotes configured gets the same run as CI. The connection-
 * string form (`:s3,provider=Other,endpoint=…:bucket`) was tried first and is
 * the wrong tool: it splits on `,` and `:`, so an endpoint URL has to be quoted
 * inside it, and an unquoted one is silently parsed as the scheme alone
 * (`Custom endpoint 'http' was not a valid URI`).
 *
 * ## Two settings that are gateway limitations, named out loud
 *
 * Both are the difference between a green file and a red one, and hiding them
 * in a helper would be hiding the limitation:
 *
 * - **`list_version=2`.** rclone picks the list API from the provider: V2 for
 *   `AWS`, **V1 for everything else**, including `Other`. This gateway
 *   implements `ListObjectsV2` only, so an unconfigured rclone gets
 *   `501 NotImplemented: ListObjects (V1) is not implemented by this gateway`
 *   on its first listing.
 * - **`no_check_bucket=true`.** rclone's S3 backend sends `CreateBucket` before
 *   an upload unless the bucket has already been marked as existing, and the
 *   only thing that marks it is a **successful listing earlier in the same
 *   process** — there is no `HeadBucket` probe, verified with `--dump headers`.
 *   So `copy` and `sync`, which list the destination first, never send it,
 *   while `copyto`, `rcat` and anything that creates a directory marker do.
 *   Bucket creation is not something a gateway whose buckets are the drivers it
 *   was constructed with can honour, so it answers `501 NotImplemented` and
 *   rclone reports `failed to prepare upload`.
 *
 * Both refusals are asserted below rather than merely configured away, and the
 * `copyto` shape is what the second case uses precisely because it is the one
 * that cannot be explained by a listing that already happened.
 *
 * `provider=Other` is not a limitation, just the truth: this is not AWS, not
 * Ceph, not Minio, and claiming to be one of those turns on workarounds for
 * bugs it does not have.
 *
 * One more warning shows up only in `rclone purge`, which asks
 * `GET /bucket?versioning` first, is refused, logs `Failed to read versioning
 * status, assuming unversioned`, and then purges correctly. That warning is
 * captured and asserted below, the same posture `.agents/environment.md` takes
 * with the AppleDouble sidecars on macOS: say it out loud.
 *
 * ## Shape
 *
 * One server for the whole file, one bucket, and a key prefix per test — a
 * gateway is stateless between requests, and a listener per case would spend
 * more time on sockets than on rclone. The driver underneath is `node-fs` over
 * a `mkdtemp` directory, so "what the driver holds" is a real tree that can be
 * read back with `node:fs` and compared byte for byte, which is the second half
 * of every assertion here.
 *
 * Every spawn is bounded by {@link SPAWN_TIMEOUT} and by rclone's own
 * `--retries 1 --low-level-retries 1 --timeout`, so a gateway bug becomes a
 * failed assertion in a second rather than a suite that hangs. No literal
 * control character appears in this file.
 */

import { execFile } from "node:child_process";
import { accessSync, constants as fsConstants } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createNodeFsDriver } from "../../src/drivers/node-fs.ts";
import { MULTIPART_PREFIX } from "../../src/s3/constants.ts";
import { createS3Server, type S3Server } from "../../src/s3/server.ts";
import { formatAmzDate, presignRequest, uriEncode } from "../../src/s3/sigv4.ts";

const run = promisify(execFile);

// ---------------------------------------------------------------------------
// the probe
// ---------------------------------------------------------------------------

/** What one external binary this file needs looks like when it is present. */
interface BinaryProbe {
  /** Absolute path to the executable, or `undefined`. */
  path: string | undefined;
  /** Is it usable? */
  usable: boolean;
  /** Why not, in a sentence, or `undefined` when it is. */
  reason: string | undefined;
}

/**
 * Find an executable on `PATH`, the way `command -v` does.
 *
 * Synchronous and cheap, because a `describe.skipIf` needs its answer at
 * collection time — the same reason `nfsClientProbe()` is synchronous. An
 * absolute or relative name with a separator in it is taken as a path and not
 * searched for, which is what a shell does too.
 */
function findExecutable(
  name: string,
  path: string | undefined = process.env["PATH"],
): string | undefined {
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

/** Is `name` on `PATH`, and what should a skipped suite say if it is not? */
function binaryProbe(name: string, purpose: string): BinaryProbe {
  const path = findExecutable(name);
  return {
    path,
    usable: path !== undefined,
    reason: path === undefined ? `no \`${name}\` on PATH; ${purpose}` : undefined,
  };
}

const rclone = binaryProbe("rclone", "it is the S3 oracle for this file");
const curl = binaryProbe("curl", "it is what drives the presigned-URL cases");

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const BUCKET = "mountx";
const REGION = "us-east-1";
const CREDENTIALS = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};
/** Longest any one spawn may take, in milliseconds. */
const SPAWN_TIMEOUT = 30_000;
/**
 * Longest one case may take, in milliseconds.
 *
 * Generous against the ~100 ms these actually take, because the thing being
 * bounded is a *hang* — a spawn that never returns, a reply that never comes —
 * and vitest's 5 s default is short enough that a loaded machine could trip it
 * on a healthy run. The multipart case moves 11 MiB and gets more.
 */
const CASE_TIMEOUT = 20_000;
/** The same, for the one case that uploads and downloads 11 MiB. */
const MULTIPART_TIMEOUT = 60_000;
/** Enough to force a multipart upload at a 5 MiB cutoff, and no more. */
const BIG_SIZE = 11 * 1024 * 1024;
/** A timestamp on a whole millisecond — see {@link wholeMillisecond}. */
const STAMP_MS = 1_600_000_000_000;

/** The temp directories this file made, removed at the end whatever happened. */
const scratch: string[] = [];

let server: S3Server;
/** The `node-fs` driver's root: what the driver actually holds, on disk. */
let root: string;
/** The `RCLONE_CONFIG_MX_*` environment that defines the remote. */
let rcloneEnv: NodeJS.ProcessEnv;

async function scratchDir(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  scratch.push(path);
  return path;
}

/** Deterministic bytes that are not all the same, so a truncation cannot pass. */
function seeded(size: number): Buffer {
  const bytes = Buffer.alloc(size);
  for (let index = 0; index < size; index++) {
    bytes[index] = (index * 31 + (index >> 11)) & 0xff;
  }
  return bytes;
}

/**
 * The source tree every upload case starts from: nesting, a dotfile, a
 * non-ASCII name, and one empty directory.
 *
 * **Every mtime is stamped on a whole millisecond.** `x-amz-meta-mtime` is
 * carried as epoch seconds — a bare integer when whole, three decimals when
 * fractional (`formatMetaMtime`) — and applied
 * with `utimes`, so a gateway round trip quantises to the millisecond, while a
 * local file's mtime has nanosecond resolution and `writeFile` leaves whatever
 * the clock said. rclone's default tolerance between a local and an S3 remote
 * is **1 ns**, so an unstamped tree re-transfers every file on the second sync
 * with `Modification times differ by -478.92µs`. That is a real limitation of
 * the meta header, named here and asserted by {@link subMillisecondDrift};
 * `--modify-window 1ms` is the flag that papers over it in practice.
 */
async function makeTree(): Promise<string> {
  const source = await scratchDir("mountx-s3-src-");
  await mkdir(join(source, "nested", "deep"), { recursive: true });
  await mkdir(join(source, "emptydir"), { recursive: true });
  await writeFile(join(source, "hello.txt"), "hello\n");
  await writeFile(join(source, ".dotfile"), "dot\n");
  await writeFile(join(source, "nested", "unicode-日本.txt"), "unicode\n");
  await writeFile(join(source, "nested", "deep", "x.bin"), seeded(64));
  for (const name of TREE_FILES) {
    await wholeMillisecond(join(source, name));
  }
  return source;
}

/** The tree's files, in listing order, with their sizes. */
const TREE_FILES = [
  ".dotfile",
  "hello.txt",
  "nested/deep/x.bin",
  "nested/unicode-日本.txt",
] as const;
const TREE_SIZES: Record<string, number> = {
  ".dotfile": 4,
  "hello.txt": 6,
  "nested/deep/x.bin": 64,
  "nested/unicode-日本.txt": 8,
};

/** Stamp a file's mtime on an exact millisecond. See {@link makeTree}. */
async function wholeMillisecond(path: string, at = STAMP_MS): Promise<void> {
  await utimes(path, new Date(at), new Date(at));
}

// ---------------------------------------------------------------------------
// driving rclone
// ---------------------------------------------------------------------------

/** One rclone invocation, whether it succeeded or not. */
interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Spawn rclone with the remote in the environment and the retries turned off.
 *
 * Never rejects: an oracle's *failure* is as interesting as its success, and a
 * case that expects a refusal (`list_version=1`) needs the message. The exit
 * code is returned so a case that expects success can assert on it and print
 * both streams when it does not get one.
 */
async function rcloneRun(...args: string[]): Promise<Run> {
  return await rcloneIn(rcloneEnv, ...args);
}

/**
 * The same, with the environment replaced.
 *
 * Only the two refusal cases need it, and they need it for a reason worth
 * writing down: `RCLONE_CONFIG_MX_NO_CHECK_BUCKET` is part of the *remote's*
 * configuration, and a remote's configuration beats the `--s3-no-check-bucket`
 * flag. Turning a limitation back on means unsetting the variable, not passing
 * the flag with the other value.
 */
async function rcloneIn(env: NodeJS.ProcessEnv, ...args: string[]): Promise<Run> {
  const argv = [...args, "--retries", "1", "--low-level-retries", "1", "--timeout", "10s"];
  try {
    const done = await run("rclone", argv, {
      timeout: SPAWN_TIMEOUT,
      maxBuffer: 32 * 1024 * 1024,
      env,
    });
    return { code: 0, stdout: done.stdout, stderr: done.stderr };
  } catch (error) {
    const failed = error as { code?: unknown; killed?: boolean; stdout?: string; stderr?: string };
    return {
      code: typeof failed.code === "number" ? failed.code : 1,
      stdout: failed.stdout ?? "",
      // A timeout kill has code null; name the hang so it cannot masquerade
      // as an ordinary failure in a message assertion.
      stderr: (failed.killed ? "[spawn timed out and was killed]\n" : "") + (failed.stderr ?? ""),
    };
  }
}

/** Run rclone and fail the test — with both streams — if it did not succeed. */
async function ok(...args: string[]): Promise<Run> {
  const done = await rcloneRun(...args);
  expect(
    done.code,
    `rclone ${args.join(" ")} exited ${done.code}\n${done.stdout}\n${done.stderr}`,
  ).toBe(0);
  return done;
}

/** `mx:mountx/<prefix>`, the remote every case addresses. */
function remote(path = ""): string {
  return `mx:${BUCKET}${path === "" ? "" : `/${path}`}`;
}

/** One `rclone lsjson` entry, as far as this file reads them. */
interface JsonEntry {
  Path: string;
  Name: string;
  Size: number;
  ModTime: string;
  IsDir: boolean;
}

async function lsjson(target: string, ...extra: string[]): Promise<JsonEntry[]> {
  const done = await ok("lsjson", "-R", ...extra, target);
  return JSON.parse(done.stdout) as JsonEntry[];
}

/** The relative paths under `root/<prefix>` that the driver actually holds. */
async function driverTree(prefix: string): Promise<string[]> {
  const entries = await readdir(join(root, prefix), { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) => join(entry.parentPath, entry.name).slice(join(root, prefix).length + 1))
    .sort();
}

/** Every file under a directory, relative path to bytes. */
async function readTree(base: string): Promise<Map<string, Buffer>> {
  const files = new Map<string, Buffer>();
  const entries = await readdir(base, { recursive: true, withFileTypes: true });
  for (const entry of entries) {
    if (entry.isFile()) {
      const full = join(entry.parentPath, entry.name);
      files.set(full.slice(base.length + 1), await readFile(full));
    }
  }
  return files;
}

// ---------------------------------------------------------------------------
// the suite
// ---------------------------------------------------------------------------

describe.skipIf(!rclone.usable)(
  `rclone against the gateway (${rclone.reason ?? "present"})`,
  () => {
    beforeAll(async () => {
      root = await scratchDir("mountx-s3-root-");
      server = createS3Server(createNodeFsDriver(root), { credentials: CREDENTIALS });
      await server.listen();
      rcloneEnv = {
        ...process.env,
        /* No config file, in either direction: nothing is read from the
           developer's own remotes and nothing is written to them. */
        RCLONE_CONFIG: "",
        RCLONE_CONFIG_MX_TYPE: "s3",
        RCLONE_CONFIG_MX_PROVIDER: "Other",
        RCLONE_CONFIG_MX_ACCESS_KEY_ID: CREDENTIALS.accessKeyId,
        RCLONE_CONFIG_MX_SECRET_ACCESS_KEY: CREDENTIALS.secretAccessKey,
        RCLONE_CONFIG_MX_ENDPOINT: server.url,
        RCLONE_CONFIG_MX_REGION: REGION,
        RCLONE_CONFIG_MX_FORCE_PATH_STYLE: "true",
        // The two limitations; see the module docs, and the two cases below.
        RCLONE_CONFIG_MX_LIST_VERSION: "2",
        RCLONE_CONFIG_MX_NO_CHECK_BUCKET: "true",
      };
    });

    afterAll(async () => {
      await server?.close();
      for (const path of scratch.splice(0)) {
        await rm(path, { recursive: true, force: true });
      }
    });

    // -------------------------------------------------------------------------
    // 1-3: copy up, list, copy down
    // -------------------------------------------------------------------------

    it(
      "copies a tree up, and the driver holds exactly those bytes",
      { timeout: CASE_TIMEOUT },
      async () => {
        const source = await makeTree();
        await ok("copy", source, remote("up"));

        expect(await driverTree("up")).toEqual([...TREE_FILES].sort());
        const local = await readTree(source);
        const stored = await readTree(join(root, "up"));
        for (const name of TREE_FILES) {
          expect(stored.get(name), name).toEqual(local.get(name));
        }
        /* rclone dropped the empty directory: it is not in the driver either, and
           that is case 5's subject rather than an accident here. */
        expect(stored.has("emptydir")).toBe(false);
      },
    );

    it(
      "lists what was uploaded: ls, lsl and lsd agree with the tree",
      { timeout: CASE_TIMEOUT },
      async () => {
        const source = await makeTree();
        await ok("copy", source, remote("list"));

        const ls = await ok("ls", remote("list"));
        const listed = ls.stdout
          .split("\n")
          .filter((line) => line.trim() !== "")
          .map((line) => {
            const match = /^\s*(\d+) (.*)$/.exec(line);
            return { size: Number(match?.[1]), name: match?.[2] };
          });
        expect(listed.map((entry) => entry.name)).toEqual([...TREE_FILES]);
        for (const entry of listed) {
          expect(entry.size, entry.name).toBe(TREE_SIZES[entry.name as string]);
        }

        /* `lsl` is `ls` plus the modification time, which is the meta header coming
           back — the same value case 4 sets deliberately. */
        const lsl = await ok("lsl", remote("list"));
        for (const line of lsl.stdout.split("\n").filter((text) => text.trim() !== "")) {
          expect(line).toMatch(/^\s*\d+ \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \S/);
        }

        /* `lsd` is the common-prefix half of ListObjectsV2: directories only, one
           level, no marker object involved. */
        const lsd = await ok("lsd", remote("list"));
        const directories = lsd.stdout
          .split("\n")
          .filter((line) => line.trim() !== "")
          .map((line) => line.trim().split(/\s+/).at(-1));
        expect(directories).toEqual(["nested"]);
      },
    );

    it("copies back down byte-identically", { timeout: CASE_TIMEOUT }, async () => {
      const source = await makeTree();
      await ok("copy", source, remote("round"));
      const down = await scratchDir("mountx-s3-down-");
      await ok("copy", remote("round"), down);

      const before = await readTree(source);
      const after = await readTree(down);
      expect([...after.keys()].sort()).toEqual([...TREE_FILES].sort());
      for (const [name, bytes] of after) {
        expect(bytes, name).toEqual(before.get(name));
      }
    });

    // -------------------------------------------------------------------------
    // 4: mtime, the convention the gateway was built for
    // -------------------------------------------------------------------------

    it(
      "preserves mtime through x-amz-meta-mtime, up and back down",
      { timeout: CASE_TIMEOUT },
      async () => {
        const source = await makeTree();
        /* Distinct, and none of them "now" — a preserved timestamp and a fresh one
           are only distinguishable if the original could not have been now. */
        const stamps = new Map<string, number>(
          TREE_FILES.map((name, index) => [name, STAMP_MS + (index + 1) * 86_400_000]),
        );
        for (const [name, at] of stamps) {
          await wholeMillisecond(join(source, name), at);
        }
        await ok("copy", source, remote("times"));

        /* rclone's view: `lsl` prints the mtime it read from the meta header. */
        const listed = await lsjson(remote("times"));
        for (const entry of listed.filter((one) => !one.IsDir)) {
          expect(Date.parse(entry.ModTime), entry.Path).toBe(stamps.get(entry.Path));
        }

        /* The driver's view: `PUT` applied it with `utimes`, so the file on disk
           carries it too — this is the half a client-side cache could fake. */
        for (const [name, at] of stamps) {
          expect((await stat(join(root, "times", name))).mtimeMs, name).toBe(at);
        }

        /* And back down: the local copy is stamped from the same header. */
        const down = await scratchDir("mountx-s3-times-");
        await ok("copy", remote("times"), down);
        for (const [name, at] of stamps) {
          expect((await stat(join(down, name))).mtimeMs, name).toBe(at);
        }
      },
    );

    // -------------------------------------------------------------------------
    // 5: the empty directory, both ways
    // -------------------------------------------------------------------------

    it(
      "drops an empty directory unless asked twice, and round-trips it when asked",
      { timeout: CASE_TIMEOUT },
      async () => {
        const source = await makeTree();

        /* Plain `sync`: the empty directory is gone. Two independent reasons, and
           both have to be answered to get it back — rclone's *local* backend does
           not offer empty directories to a sync at all without
           `--create-empty-src-dirs`, and its *S3* backend has no way to represent
           one without `--s3-directory-markers`. */
        await ok("sync", source, remote("empty-plain"));
        expect(await driverTree("empty-plain")).toEqual([...TREE_FILES].sort());
        expect((await lsjson(remote("empty-plain"))).map((entry) => entry.Path)).not.toContain(
          "emptydir",
        );

        /* `--create-empty-src-dirs` alone is not enough: rclone logs
           `emptydir: Making directory` and the S3 backend makes that a no-op. */
        await ok("sync", "--create-empty-src-dirs", source, remote("empty-half"));
        expect(await driverTree("empty-half")).toEqual([...TREE_FILES].sort());

        /* Both flags: rclone sends `PUT empty-both/emptydir/` — a key ending in a
           slash, which is this gateway's directory marker — and the session's
           `#putDirectory` path turns it into a real `mkdir`. */
        await ok(
          "sync",
          "--create-empty-src-dirs",
          "--s3-directory-markers",
          source,
          remote("both"),
        );
        const entries = await readdir(join(root, "both"), { withFileTypes: true });
        const madeDirectory = entries.find((entry) => entry.name === "emptydir");
        expect(madeDirectory?.isDirectory()).toBe(true);
        expect(await readdir(join(root, "both", "emptydir"))).toEqual([]);

        /* And rclone reads its own marker back as a directory: `IsDir`, size 0. */
        const withMarkers = await lsjson(remote("both"), "--s3-directory-markers");
        const seen = withMarkers.find((entry) => entry.Path === "emptydir");
        expect(seen?.IsDir).toBe(true);
        expect(seen?.Size).toBe(0);

        /* The full round trip: down to a fresh local tree, empty directory and all. */
        const down = await scratchDir("mountx-s3-empty-");
        await ok("sync", "--create-empty-src-dirs", "--s3-directory-markers", remote("both"), down);
        expect((await readdir(join(down, "emptydir"))).length).toBe(0);
      },
    );

    // -------------------------------------------------------------------------
    // 6: incremental sync
    // -------------------------------------------------------------------------

    it(
      "syncs incrementally: only the changed object moves",
      { timeout: CASE_TIMEOUT },
      async () => {
        const source = await makeTree();
        await ok("sync", source, remote("incr"));
        const before = new Map<string, number>();
        for (const name of TREE_FILES) {
          before.set(name, (await stat(join(root, "incr", name))).mtimeMs);
        }

        await writeFile(join(source, "hello.txt"), "changed!\n");
        await wholeMillisecond(join(source, "hello.txt"), STAMP_MS + 7_000);
        const done = await ok("sync", "-vv", source, remote("incr"));

        /* rclone's own accounting: one transfer, three checks that matched. */
        expect(done.stderr).toContain("hello.txt: Copied (replaced existing)");
        expect(done.stderr).toMatch(/Transferred:\s+1 \/ 1, 100%/);
        for (const name of TREE_FILES) {
          if (name !== "hello.txt") {
            expect(done.stderr, name).toContain(`${name}: Unchanged skipping`);
          }
        }

        /* And the driver's: every other object's mtime is untouched, which is the
           thing an over-eager re-upload would have changed. */
        expect((await readFile(join(root, "incr", "hello.txt"))).toString("utf8")).toBe(
          "changed!\n",
        );
        for (const name of TREE_FILES) {
          if (name !== "hello.txt") {
            expect((await stat(join(root, "incr", name))).mtimeMs, name).toBe(before.get(name));
          }
        }
      },
    );

    /**
     * The limitation the case above is stamped to avoid, asserted rather than
     * alluded to: an mtime with sub-millisecond precision does **not** survive
     * `x-amz-meta-mtime`, and rclone's 1 ns tolerance notices.
     */
    it(
      "loses sub-millisecond mtime precision, which makes rclone re-transfer",
      { timeout: CASE_TIMEOUT },
      async () => {
        const source = await scratchDir("mountx-s3-drift-");
        await writeFile(join(source, "drift.txt"), "drift\n");
        await utimes(join(source, "drift.txt"), new Date(STAMP_MS), new Date(STAMP_MS));
        /* 250 microseconds past a whole millisecond: representable locally, not
           in a header whose resolution stops at the millisecond. */
        await utimes(
          join(source, "drift.txt"),
          STAMP_MS / 1000 + 0.00025,
          STAMP_MS / 1000 + 0.00025,
        );

        await ok("sync", source, remote("drift"));
        const again = await ok("sync", "-vv", source, remote("drift"));
        expect(again.stderr).toContain("Modification times differ");
        /* And the flag that makes it stop, which is what a user would reach for. */
        const tolerant = await ok("sync", "-vv", "--modify-window", "1ms", source, remote("drift"));
        expect(tolerant.stderr).toContain("drift.txt: Unchanged skipping");
      },
    );

    // -------------------------------------------------------------------------
    // 7: delete and purge
    // -------------------------------------------------------------------------

    it(
      "deletes a subtree and purges a prefix, with the versioning probe refused",
      { timeout: CASE_TIMEOUT },
      async () => {
        const source = await makeTree();
        await ok("copy", source, remote("gone"));

        /* `delete` removes the objects under a prefix and leaves the directories
           they lived in — S3 has no directories to remove, and the gateway is not
           going to invent a `rmdir` rclone did not ask for. */
        await ok("delete", remote("gone/nested"));
        expect(await driverTree("gone")).toEqual([".dotfile", "hello.txt"].sort());

        /* `purge` asks `GET /mountx?versioning` first. This gateway does not
           implement that sub-resource, rclone logs the refusal and carries on
           assuming an unversioned bucket, which is correct. Named, not hidden. */
        const purged = await ok("purge", remote("gone"));
        expect(purged.stderr).toContain("Failed to read versioning status, assuming unversioned");
        expect(purged.stderr).toContain(`"?versioning" is not implemented by this gateway`);
        expect(await driverTree("gone")).toEqual([]);
      },
    );

    // -------------------------------------------------------------------------
    // 8: multipart
    // -------------------------------------------------------------------------

    it(
      "uploads past the cutoff as a multipart upload and leaves no staging behind",
      { timeout: MULTIPART_TIMEOUT },
      async () => {
        const source = await scratchDir("mountx-s3-big-");
        const bytes = seeded(BIG_SIZE);
        const local = join(source, "big.bin");
        await writeFile(local, bytes);

        /* 11 MiB in 5 MiB chunks: `CreateMultipartUpload`, three `UploadPart`s and
           a `CompleteMultipartUpload`, all from a client that has never seen this
           session's fixtures. */
        const uploaded = await ok(
          "copyto",
          "--s3-upload-cutoff",
          "5M",
          "--s3-chunk-size",
          "5M",
          "-v",
          local,
          remote("multipart/big.bin"),
        );
        expect(uploaded.stderr).toContain("big.bin: Copied (new)");

        /* `Buffer.compare`, not `toEqual`: a deep-equality assertion over 11 Mi
           elements takes the better part of a minute and reports the same one bit
           of information. */
        expect(Buffer.compare(await readFile(join(root, "multipart", "big.bin")), bytes)).toBe(0);
        const down = await scratchDir("mountx-s3-bigdown-");
        await ok("copyto", remote("multipart/big.bin"), join(down, "big.bin"));
        expect(Buffer.compare(await readFile(join(down, "big.bin")), bytes)).toBe(0);

        /* The staging area exists — this is where the parts were assembled — and
           holds nothing: no abandoned upload directory, no orphan part. */
        expect(await readdir(join(root, MULTIPART_PREFIX))).toEqual([]);
        /* It is invisible to the client, which is the half a `readdir` cannot see. */
        const listed = await lsjson(remote());
        expect(listed.map((entry) => entry.Path)).not.toContain(MULTIPART_PREFIX);
      },
    );

    // -------------------------------------------------------------------------
    // 9: check, and what it could actually compare
    // -------------------------------------------------------------------------

    it(
      "checks clean, on size and modtime — the ETag is not an MD5 and rclone says so",
      { timeout: CASE_TIMEOUT },
      async () => {
        const source = await makeTree();
        await ok("copy", source, remote("check"));

        /* Plain `rclone check` announces `Using md5 for hash comparisons` and then
           reports that it could not do any: this gateway's ETag is the first 32 hex
           of sha256 over `dev:ino:size:mtimeMs` with a `-1` suffix, which rclone
           reads as "not a plain MD5" and declines to compare. The comparison that
           actually ran was **size plus modification time**, and it found nothing
           wrong — which is the honest result and worth pinning as such. */
        const checked = await ok("check", remote("check"), source);
        expect(checked.stderr).toContain("0 differences found");
        expect(checked.stderr).toContain(`${TREE_FILES.length} hashes could not be checked`);
        expect(checked.stderr).toContain(`${TREE_FILES.length} matching files`);

        /* `--size-only` is the comparison with no hash in it at all, so nothing is
           reported as unchecked. */
        const sized = await ok("check", "--size-only", remote("check"), source);
        expect(sized.stderr).toContain("0 differences found");
        expect(sized.stderr).not.toContain("hashes could not be checked");

        /* And it notices a real difference, so the clean runs above mean something. */
        await writeFile(join(source, "hello.txt"), "different length\n");
        const differing = await rcloneRun("check", "--size-only", remote("check"), source);
        expect(differing.code).not.toBe(0);
        expect(differing.stderr).toContain("1 differences found");
      },
    );

    // -------------------------------------------------------------------------
    // the two flags, as refusals
    // -------------------------------------------------------------------------

    it(
      "refuses ListObjects V1, which is why the remote sets list_version=2",
      { timeout: CASE_TIMEOUT },
      async () => {
        const done = await rcloneRun("ls", "--s3-list-version", "1", remote("up"));
        expect(done.code).not.toBe(0);
        expect(done.stderr).toContain("501");
        expect(done.stderr).toContain("NotImplemented: ListObjects (V1) is not implemented");
      },
    );

    it(
      "refuses CreateBucket, which is why the remote sets no_check_bucket=true",
      { timeout: CASE_TIMEOUT },
      async () => {
        const source = await scratchDir("mountx-s3-nobucket-");
        const local = join(source, "one.txt");
        await writeFile(local, "one\n");
        /* The remote with `no_check_bucket` removed, and `copyto` rather than
           `copy`: a single-object command lists nothing, so nothing has marked
           the bucket as existing and rclone sends `CreateBucket` first. That is
           the shape this refusal is really about — a `copy` of the same file
           would list the destination, mark the bucket, and never send it. */
        const { RCLONE_CONFIG_MX_NO_CHECK_BUCKET: _unset, ...strict } = rcloneEnv;
        const done = await rcloneIn(strict, "copyto", local, remote("nobucket/one.txt"));
        expect(done.code).not.toBe(0);
        expect(done.stderr).toContain("NotImplemented: CreateBucket is not implemented");
        expect(done.stderr).toContain("failed to prepare upload");
      },
    );

    // -------------------------------------------------------------------------
    // 10: presigned URLs, driven by curl
    // -------------------------------------------------------------------------

    describe.skipIf(!curl.usable)(`presigned URLs via curl (${curl.reason ?? "present"})`, () => {
      /**
       * A presigned URL for one request, built exactly as a caller would.
       *
       * The path handed to `presignRequest` is the **decoded** one (the module
       * docs in `sigv4.ts` are emphatic about this); the URL is the encoded one,
       * which is what `uriEncode` per segment gives.
       */
      function presigned(
        method: string,
        key: string,
        options: { expiresIn?: number; at?: number } = {},
      ): string {
        const path = `/${BUCKET}/${key}`;
        const host = `127.0.0.1:${server.port}`;
        const signed = presignRequest({
          method,
          path,
          headers: [{ name: "host", value: host }],
          credentials: CREDENTIALS,
          region: REGION,
          timestamp: formatAmzDate(options.at ?? Date.now()),
          expiresIn: options.expiresIn ?? 300,
        });
        const query = signed.query
          .map((entry) => `${uriEncode(entry.name)}=${uriEncode(entry.value)}`)
          .join("&");
        const encoded = path.split("/").map(uriEncode).join("/");
        return `${server.url}${encoded}?${query}`;
      }

      /** curl, with the status code appended to the body so both can be read. */
      async function curlRun(...args: string[]): Promise<{ status: number; body: string }> {
        const done = await run(
          "curl",
          [
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--write-out",
            "\\n%{http_code}",
            ...args,
          ],
          { timeout: SPAWN_TIMEOUT, maxBuffer: 8 * 1024 * 1024 },
        );
        const newline = done.stdout.lastIndexOf("\n");
        return {
          status: Number(done.stdout.slice(newline + 1)),
          body: done.stdout.slice(0, newline),
        };
      }

      it(
        "serves a presigned GET with no Authorization header at all",
        { timeout: CASE_TIMEOUT },
        async () => {
          await mkdir(join(root, "presign"), { recursive: true });
          await writeFile(join(root, "presign", "note.txt"), "presigned hello\n");

          const got = await curlRun(presigned("GET", "presign/note.txt"));
          expect(got.status).toBe(200);
          expect(got.body).toBe("presigned hello\n");
        },
      );

      it(
        "stores a presigned PUT, and the driver holds the bytes",
        { timeout: CASE_TIMEOUT },
        async () => {
          const source = await scratchDir("mountx-s3-presign-");
          const body = "uploaded through a URL\n";
          const local = join(source, "put.txt");
          await writeFile(local, body);

          const put = await curlRun(
            "--request",
            "PUT",
            "--upload-file",
            local,
            presigned("PUT", "presign/put.txt"),
          );
          expect(put.status).toBe(200);
          expect((await readFile(join(root, "presign", "put.txt"))).toString("utf8")).toBe(body);
        },
      );

      it(
        "refuses an expired presigned GET with an AccessDenied document",
        { timeout: CASE_TIMEOUT },
        async () => {
          await mkdir(join(root, "presign"), { recursive: true });
          await writeFile(join(root, "presign", "old.txt"), "too late\n");

          /* Signed an hour ago with a one-minute lifetime: valid signature, dead
             URL, which is the case a wrong expiry check would let through. */
          const url = presigned("GET", "presign/old.txt", {
            at: Date.now() - 3_600_000,
            expiresIn: 60,
          });
          const denied = await curlRun(url);
          expect(denied.status).toBe(403);
          expect(denied.body).toContain("<Code>AccessDenied</Code>");
          expect(denied.body).toContain("expired");
        },
      );
    });
  },
);
