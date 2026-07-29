/**
 * Building the supervisor, and deciding whether this host can run it at all.
 *
 * The Tier-2 files here follow the same discipline as `test/nfs/mount.test.ts`
 * and `test/9p/mount.test.ts`: the precondition is checked up front and the
 * whole file skips itself when it is missing, so `pnpm test` stays green on a
 * machine with no Zig toolchain. Unlike those two the precondition is not root
 * — a seccomp user-notification filter needs no privileges at all, only
 * `no_new_privs` — which is the entire reason this mechanism is being pursued.
 *
 * Not a `*.test.ts` file: it is imported by them.
 */

import { execFile } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

/** Where the built supervisor lands. One copy, reused by every file here. */
const OUT = join(tmpdir(), "mountx-exec-test");

/**
 * Why this host cannot run the supervisor, or `undefined` if it can.
 *
 * x86-64 Linux only, because the BPF filter compares against one syscall table
 * and refuses to interpret any other — see `src/exec/seccomp/linux.zig`.
 */
export async function supervisorRefusal(): Promise<string | undefined> {
  if (process.platform !== "linux") {
    return `seccomp user notification is Linux-only, and this is ${process.platform}`;
  }
  if (process.arch !== "x64") {
    return `the filter is transcribed for x86-64, and this is ${process.arch}`;
  }
  try {
    await run("zig", ["version"]);
  } catch {
    return "no zig on PATH, so the supervisor cannot be built";
  }
  return undefined;
}

/** One build per process, however many tests ask for it. */
let building: Promise<string> | undefined;

/**
 * Build `mountx-trace` and answer with its path.
 *
 * The build is `zig build-exe` with the two modules the binary is made of, the
 * same command `test/exec/compare.sh` uses. Memoised because the conformance
 * column asks once per case: Zig's own cache makes a repeat build cheap, but
 * "cheap" is still a process spawn, and sixty-six of them is most of that
 * file's runtime.
 */
export function buildSupervisor(): Promise<string> {
  building ??= build();
  return building;
}

async function build(): Promise<string> {
  await mkdir(OUT, { recursive: true });
  const binary = join(OUT, "mountx-trace");
  await run(
    "zig",
    [
      "build-exe",
      "-lc",
      "-O",
      "ReleaseSmall",
      `-femit-bin=${binary}`,
      "--dep",
      "p9",
      "-Mroot=seccomp/trace.zig",
      "-Mp9=seccomp/p9.zig",
    ],
    { cwd: new URL("../../src/exec/", import.meta.url).pathname },
  );
  return binary;
}
