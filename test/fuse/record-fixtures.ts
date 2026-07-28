/**
 * Records the committed `/dev/fuse` transcripts in `test/fixtures/`.
 *
 * Needs root and a real kernel, so it is a script rather than a test: the
 * fixtures it produces are what `replay.test.ts` runs on, and that runs
 * anywhere. Re-record only when the protocol layer changes what it *sends*;
 * the point of a fixture is that it does not move.
 *
 * ```sh
 * pnpm record:fixtures
 * ```
 *
 * Each scenario mounts a fresh memory driver, drives it from **another
 * process** (`ls`, `sh`, `tar` — a daemon that is also its own client wedges;
 * see the top of `src/fuse/mount.ts`), and writes the tap's frames out. The
 * tree each scenario starts from is built through the *driver*, not through the
 * mountpoint, so the transcript contains the workload and nothing else.
 */

import { execFile } from "node:child_process";
import { chown, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { mount } from "../../src/fuse/mount.ts";
import { TranscriptRecorder } from "../../src/fuse/record.ts";
import type { FsDriver } from "../../src/types.ts";

const exec = promisify(execFile);

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures");

/**
 * Payload bytes per transcript.
 *
 * These files are committed, and a `WRITE` carries its whole payload, so the
 * budget is the real constraint on what a scenario may do. This is a guard
 * rail rather than a target: the scenarios below are sized to finish well
 * inside it, and a transcript that reports `[truncated]` wants a smaller
 * workload, not a bigger limit.
 */
const LIMIT = 180_000;

interface Scenario {
  name: string;
  /** Built through the driver, so it costs no FUSE traffic. */
  seed?: (driver: FsDriver) => Promise<void>;
  /** Runs in another process, against the mountpoint. */
  drive: (mnt: string, scratch: string) => Promise<void>;
}

const SCENARIOS: Scenario[] = [
  {
    // The walk every shell prompt, editor and file manager does: LOOKUP,
    // OPENDIR, READDIRPLUS paging, GETATTR, RELEASEDIR, FORGET.
    name: "ls-walk",
    async seed(driver) {
      for (let index = 0; index < 4; index++) {
        const dir = `/dir-${String(index).padStart(2, "0")}`;
        await driver.mkdir!(dir, { mode: 0o755 });
        for (let file = 0; file < 6; file++) {
          const handle = await driver.open!(`${dir}/file-${file}`, "w", 0o644);
          await handle.write(new TextEncoder().encode(`${dir}/${file}\n`), 0, undefined, 0);
          await handle.close();
        }
        await driver.symlink!(`file-0`, `${dir}/link`);
      }
    },
    async drive(mnt) {
      await exec("ls", ["-laR", mnt]);
      await exec("find", [mnt, "-type", "f"]);
    },
  },
  {
    // The shape a build tool or `git` makes: write a file, rename it into
    // place, stat it, read it back. CREATE, WRITE, RENAME, LOOKUP, OPEN, READ,
    // FLUSH, RELEASE, and the subtree remap on every rename.
    name: "write-rename-stat",
    async drive(mnt) {
      await exec("sh", [
        "-c",
        `set -e
         i=0
         while [ $i -lt 8 ]; do
           printf 'contents of object %s\\n' "$i" > "$1/tmp.$i"
           mv "$1/tmp.$i" "$1/object.$i"
           stat "$1/object.$i" > /dev/null
           cat "$1/object.$i" > /dev/null
           i=$((i + 1))
         done
         mkdir "$1/objects"
         mv "$1"/object.* "$1/objects/"
         ls -l "$1/objects" > /dev/null`,
        "sh",
        mnt,
      ]);
    },
  },
  {
    // An archive extraction: MKDIR, CREATE, WRITE, SYMLINK, then the SETATTR
    // storm at the end when `tar` restores modes and timestamps.
    name: "tar-extract",
    async drive(mnt, scratch) {
      const source = join(scratch, "tree");
      await mkdir(join(source, "src", "nested"), { recursive: true });
      for (let index = 0; index < 12; index++) {
        await writeFile(join(source, "src", `unit-${index}.txt`), `unit ${index}\n`.repeat(40));
      }
      await writeFile(join(source, "src", "nested", "deep.txt"), "deep\n");
      await exec("ln", ["-s", "unit-0.txt", join(source, "src", "first")]);
      const archive = join(scratch, "tree.tar");
      await exec("tar", ["-cf", archive, "-C", source, "."]);
      await exec("tar", ["-xpf", archive, "-C", mnt]);
      await exec("ls", ["-lR", mnt]);
    },
  },
];

async function record(scenario: Scenario): Promise<void> {
  const scratch = await mkdtemp(join(tmpdir(), "unimount-record-"));
  const mnt = join(scratch, "mnt");
  await mkdir(mnt);
  const driver = createMemoryDriver();
  await scenario.seed?.(driver);

  const recorder = new TranscriptRecorder({ limit: LIMIT });
  // Zero timeouts: kernel caching is right for a production mount and wrong for
  // a fixture, where the whole value is in the requests the workload makes.
  const mounted = await mount(driver, mnt, {
    fsname: `unimount-record`,
    tap: recorder.tap,
    attrTimeout: 0,
    entryTimeout: 0,
  });
  try {
    await scenario.drive(mnt, scratch);
  } finally {
    // Both of these belong in the `finally`: this script runs as root, so an
    // aborted recording that skipped them would leave a mountpoint *and* a
    // root-owned directory in `/tmp` that the developer cannot delete.
    await mounted.unmount();
    await rm(scratch, { recursive: true, force: true });
  }

  const bytes = recorder.encode();
  const path = join(FIXTURES, `${scenario.name}.fuse`);
  await writeFile(path, bytes);
  // The script runs as root; the repository does not belong to root.
  const uid = Number(process.env.SUDO_UID ?? -1);
  const gid = Number(process.env.SUDO_GID ?? -1);
  if (uid >= 0) {
    await chown(path, uid, gid);
  }

  const requests = recorder.frames.filter((frame) => frame.direction === "in").length;
  process.stdout.write(
    `${scenario.name}: ${recorder.frames.length} frames (${requests} requests), ` +
      `${bytes.length} bytes${recorder.truncated ? " [truncated at the limit]" : ""}\n`,
  );
}

await mkdir(FIXTURES, { recursive: true });
for (const scenario of SCENARIOS) {
  await record(scenario);
}
