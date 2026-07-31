/**
 * Tier 2 for the WebDAV server: a **foreign client**, driven for real.
 *
 * ```sh
 * pnpm test            # this file runs when rclone is on PATH, skips when it is not
 * ```
 *
 * Everything else under `test/webdav/` drives the server with `fetch` and reads
 * the replies with this repository's own expectations, so a symmetric
 * misreading of RFC 4918 is invisible to it. This file is the answer to that:
 * [rclone](https://rclone.org)'s WebDAV backend shares none of our code and has
 * opinions about the protocol that no fixture would have thought to have — it
 * insists on `Depth: 1` `PROPFIND`s to list, on `MKCOL` before a nested upload,
 * and on the `href`s in a multistatus matching the collection it asked about.
 * `curl` plays the smaller role of sending each method exactly as written, with
 * no backend in between.
 *
 * It skips itself cleanly when the binaries are absent, the way
 * `test/s3/oracle.test.ts` and `test/nfs/mount.test.ts` do: an oracle nobody can
 * run is not a reason for a red suite.
 *
 * ## The configuration is in the environment, and that is deliberate
 *
 * rclone is invoked with **no config file at all** (`RCLONE_CONFIG=""`) and the
 * remote defined entirely by `RCLONE_CONFIG_MX_*` variables, so a run writes
 * nothing to `~/.config/rclone` and reads nothing from it — a developer with
 * their own remotes configured gets the same run as CI.
 *
 * `vendor=other` is not a limitation, just the truth: this is not ownCloud and
 * not Nextcloud, and claiming to be one turns on checksum and chunked-upload
 * endpoints that do not exist here.
 *
 * ## Shape
 *
 * One server for the whole file and a collection per test — WebDAV is stateless
 * between requests, and a listener per case would spend more time on sockets
 * than on rclone. The driver underneath is `node-fs` over a `mkdtemp`
 * directory, so "what the driver holds" is a real tree that can be read back
 * with `node:fs` and compared byte for byte, which is the second half of every
 * assertion here.
 *
 * Every spawn is bounded by {@link SPAWN_TIMEOUT} and by rclone's own
 * `--retries 1 --low-level-retries 1 --timeout`, so a server bug becomes a
 * failed assertion in a second rather than a suite that hangs. No literal
 * control character appears in this file.
 */

import { execFile } from "node:child_process";
import { accessSync, constants as fsConstants } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createNodeFsDriver } from "../../src/drivers/node-fs.ts";
import { createWebdavServer, type WebdavServer } from "../../src/webdav/server.ts";

const run = promisify(execFile);

// ---------------------------------------------------------------------------
// the probe
// ---------------------------------------------------------------------------

/**
 * Find an executable on `PATH`, the way `command -v` does. Synchronous, because
 * a `describe.skipIf` needs its answer at collection time.
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

const rclone = findExecutable("rclone");
const curl = findExecutable("curl");

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/** Longest any one spawn may take, in milliseconds. */
const SPAWN_TIMEOUT = 30_000;
/** Longest one case may take. Generous, because what it bounds is a *hang*. */
const CASE_TIMEOUT = 20_000;
const USERNAME = "ada";
const PASSWORD = "a pass:word";

/** The temp directories this file made, removed at the end whatever happened. */
const scratch: string[] = [];

let server: WebdavServer;
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

async function rcloneRun(...args: string[]): Promise<{ stdout: string; stderr: string }> {
  return await run(
    rclone as string,
    ["--retries", "1", "--low-level-retries", "1", "--timeout", "10s", ...args],
    { env: rcloneEnv, timeout: SPAWN_TIMEOUT, maxBuffer: 32 * 1024 * 1024 },
  );
}

async function curlRun(...args: string[]): Promise<string> {
  const { stdout } = await run(
    curl as string,
    ["--silent", "--show-error", "--max-time", "10", "--user", `${USERNAME}:${PASSWORD}`, ...args],
    { timeout: SPAWN_TIMEOUT, maxBuffer: 8 * 1024 * 1024 },
  );
  return stdout;
}

beforeAll(async () => {
  root = await scratchDir("mountx-webdav-oracle-");
  server = createWebdavServer(createNodeFsDriver(root), {
    credentials: { username: USERNAME, password: PASSWORD },
  });
  await server.listen();
  rcloneEnv = {
    ...process.env,
    RCLONE_CONFIG: "",
    RCLONE_CONFIG_MX_TYPE: "webdav",
    RCLONE_CONFIG_MX_URL: server.url,
    RCLONE_CONFIG_MX_VENDOR: "other",
    RCLONE_CONFIG_MX_USER: USERNAME,
    RCLONE_CONFIG_MX_PASS: (
      await run(rclone as string, ["obscure", PASSWORD], { timeout: SPAWN_TIMEOUT })
    ).stdout.trim(),
  };
});

afterAll(async () => {
  await server?.close();
  for (const path of scratch.splice(0)) {
    await rm(path, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// rclone
// ---------------------------------------------------------------------------

describe.skipIf(rclone === undefined)("rclone against mountx/webdav", () => {
  it(
    "syncs a tree in, lists it, and syncs it back out byte for byte",
    async () => {
      const source = await scratchDir("mountx-webdav-source-");
      await mkdir(join(source, "nested"), { recursive: true });
      await writeFile(join(source, "hello.txt"), "hello world");
      await writeFile(join(source, "nested", "a name with spaces.bin"), seeded(64 * 1024));

      await rcloneRun("sync", source, "mx:tree", "--create-empty-src-dirs");

      // What the driver holds is a real tree, so it is checked on disk too.
      expect(await readFile(join(root, "tree", "hello.txt"), "utf8")).toBe("hello world");
      expect(await readFile(join(root, "tree", "nested", "a name with spaces.bin"))).toEqual(
        seeded(64 * 1024),
      );

      const listing = JSON.parse((await rcloneRun("lsjson", "-R", "mx:tree")).stdout) as {
        Path: string;
        IsDir: boolean;
        Size: number;
      }[];
      expect(listing.map((entry) => entry.Path).sort()).toEqual([
        "hello.txt",
        "nested",
        "nested/a name with spaces.bin",
      ]);
      expect(listing.find((entry) => entry.Path === "nested")?.IsDir).toBe(true);
      expect(listing.find((entry) => entry.Path === "hello.txt")?.Size).toBe(11);

      const back = await scratchDir("mountx-webdav-back-");
      await rcloneRun("sync", "mx:tree", back);
      expect(await readFile(join(back, "nested", "a name with spaces.bin"))).toEqual(
        seeded(64 * 1024),
      );
    },
    CASE_TIMEOUT,
  );

  it(
    "moves, copies and purges through the server's own methods",
    async () => {
      await writeFile(join(root, "movable.txt"), "before");
      await rcloneRun("moveto", "mx:movable.txt", "mx:moved.txt");
      expect(await readFile(join(root, "moved.txt"), "utf8")).toBe("before");
      await expect(stat(join(root, "movable.txt"))).rejects.toThrow();

      await rcloneRun("copyto", "mx:moved.txt", "mx:copies/again.txt");
      expect(await readFile(join(root, "copies", "again.txt"), "utf8")).toBe("before");

      await rcloneRun("purge", "mx:copies");
      await expect(stat(join(root, "copies"))).rejects.toThrow();
    },
    CASE_TIMEOUT,
  );

  it(
    "reads a byte range rather than the whole resource",
    async () => {
      await writeFile(join(root, "ranged.bin"), seeded(256 * 1024));
      const { stdout } = await rcloneRun(
        "cat",
        "--offset",
        "1024",
        "--count",
        "16",
        "mx:ranged.bin",
      );
      expect(Buffer.from(stdout, "binary").byteLength).toBe(16);
    },
    CASE_TIMEOUT,
  );

  it(
    "refuses the wrong password rather than serving it",
    async () => {
      await expect(
        run(rclone as string, ["--retries", "1", "lsf", "mx:"], {
          env: { ...rcloneEnv, RCLONE_CONFIG_MX_PASS: "" },
          timeout: SPAWN_TIMEOUT,
        }),
      ).rejects.toThrow();
    },
    CASE_TIMEOUT,
  );
});

// ---------------------------------------------------------------------------
// curl
// ---------------------------------------------------------------------------

describe.skipIf(curl === undefined)("curl against mountx/webdav", () => {
  it(
    "walks a resource through every method by hand",
    async () => {
      const base = `${server.url}/by-hand`;
      expect(await curlRun("-o", "/dev/null", "-w", "%{http_code}", "-X", "MKCOL", base)).toBe(
        "201",
      );

      const upload = join(await scratchDir("mountx-webdav-curl-"), "payload.txt");
      await writeFile(upload, "curl put this here");
      expect(
        await curlRun("-o", "/dev/null", "-w", "%{http_code}", "-T", upload, `${base}/note.txt`),
      ).toBe("201");
      expect(await readFile(join(root, "by-hand", "note.txt"), "utf8")).toBe("curl put this here");

      const listing = await curlRun("-X", "PROPFIND", "-H", "Depth: 1", base);
      expect(listing).toContain("<href>/by-hand/</href>");
      expect(listing).toContain("<href>/by-hand/note.txt</href>");
      expect(listing).toContain("<getcontentlength>18</getcontentlength>");

      expect(await curlRun(`${base}/note.txt`)).toBe("curl put this here");
      expect(await curlRun("-H", "Range: bytes=0-3", `${base}/note.txt`)).toBe("curl");

      expect(
        await curlRun(
          "-o",
          "/dev/null",
          "-w",
          "%{http_code}",
          "-X",
          "MOVE",
          "-H",
          `Destination: ${base}/renamed.txt`,
          `${base}/note.txt`,
        ),
      ).toBe("201");
      expect(await readFile(join(root, "by-hand", "renamed.txt"), "utf8")).toBe(
        "curl put this here",
      );

      expect(await curlRun("-o", "/dev/null", "-w", "%{http_code}", "-X", "DELETE", base)).toBe(
        "204",
      );
      await expect(stat(join(root, "by-hand"))).rejects.toThrow();
    },
    CASE_TIMEOUT,
  );

  it(
    "advertises classes 1, 2 and 3, and says so to an unauthenticated client too",
    async () => {
      /* Field names go out lowercase — RFC 9110 §5.1 makes them
         case-insensitive and HTTP/2 requires lowercase, which is also what the
         S3 gateway sends — so the assertion is on the name as sent, not on a
         canonical casing nothing promises. */
      const headers = await curlRun("-i", "-o", "-", "-X", "OPTIONS", `${server.url}/`);
      expect(headers.toLowerCase()).toContain("dav: 1, 2, 3");
      expect(headers.toLowerCase()).toContain("ms-author-via: dav");
      // Class 2 is advertised, and the method list says the same thing.
      expect(headers).toContain("LOCK");
      expect(headers).toContain("UNLOCK");

      const { stdout } = await run(
        curl as string,
        ["--silent", "-o", "/dev/null", "-w", "%{http_code}", "-X", "OPTIONS", `${server.url}/`],
        { timeout: SPAWN_TIMEOUT },
      );
      expect(stdout).toBe("401");
    },
    CASE_TIMEOUT,
  );
});
