/**
 * Runs pjdfstest against a real mount of the in-memory driver.
 *
 * Mounts, walks `tests/**\/*.t`, runs each one with `sh` (cwd = the
 * mountpoint, which is the convention the suite's `misc.sh` expects), parses
 * the TAP it prints, and writes a per-category summary. Unmounts whatever
 * happens.
 *
 * ```sh
 * pnpm test:pjdfstest          # clone + build + run + summarize
 * pnpm test:pjdfstest chmod    # one category, or any path fragment
 * ```
 *
 * **Why not `prove`.** The suite's README says `prove -rv tests`, and `prove`
 * would be the right tool — but it is Perl's `TAP::Harness`, which is not
 * installed on every machine that has a `/dev/fuse` (it is not on this one).
 * The `.t` files are ordinary shell scripts printing ordinary TAP, so the
 * harness is forty lines and the run has no dependency beyond `sh` and `cc`.
 *
 * **Why the tests run as children.** The mount is served by *this* process, and
 * a process that is also a client of its own mountpoint parks a threadpool
 * thread per in-flight call — see the note at the top of `src/fuse/mount.ts`.
 * Every `.t` is a separate process, so none of that applies to them; this
 * process only ever waits.
 *
 * Expect failures, and expect them to be interesting. `.agents/pjdfstest-results.md`
 * is the analysis; this script is the instrument.
 */

import { spawn } from "node:child_process";
import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { mount } from "../../src/fuse/mount.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const SUITE = join(HERE, "pjdfstest");
const TESTS = join(SUITE, "tests");

/**
 * How long one `.t` may take before it is killed.
 *
 * Generous, because a few files are enormous — `chown/00.t` is 1280
 * assertions, and every one of them is several round trips through a mount
 * that is deliberately configured with no attribute caching at all.
 */
const TEST_TIMEOUT = 300_000;

interface FileResult {
  /** Path relative to `tests/`, e.g. `chmod/00.t`. */
  file: string;
  /** First `desc=` line in the script — what the file is about. */
  desc: string;
  planned: number;
  passed: number;
  failed: number;
  /** `# TODO` results: known-broken upstream, not our verdict. */
  todo: number;
  skipped: number;
  /**
   * Every failed assertion, verbatim.
   *
   * pjdfstest's `expect` prints what it tried and what it got, and that string
   * is the whole analysis: `expected 0, got ENOSYS` on an `mkfifo` is a
   * missing feature, `expected 0620, got 0600` is a mode bug, and the two want
   * completely different responses. Keeping them is what makes
   * `.agents/pjdfstest-results.md` a categorisation rather than a tally.
   */
  failures: string[];
  /** Set when the script died or never printed a plan. */
  note?: string;
}

async function collect(dir: string): Promise<string[]> {
  const found: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...(await collect(path)));
    } else if (entry.name.endsWith(".t")) {
      found.push(path);
    }
  }
  return found.sort();
}

/**
 * Run one `.t` with its working directory inside the mountpoint.
 *
 * **The `cd` happens in the shell, after `exec`, and that is load-bearing.**
 * `spawn(…, { cwd })` looks like the obvious way to do this and deadlocks the
 * process instantly: libuv's `uv_spawn` forks, has the *child* `chdir` before
 * it execs, and blocks the parent on a pipe until the exec happens — so a `cwd`
 * inside a mountpoint this process serves means the main thread is waiting for
 * a `LOOKUP` that only the main thread can answer. Handing the path to `sh`
 * instead moves the `chdir` past the exec, where the parent is free again. See
 * the module docs in `src/fuse/mount.ts`.
 */
function run(
  file: string,
  cwd: string,
): Promise<{ stdout: string; stderr: string; code: number | null; timedOut: boolean }> {
  return new Promise((resolve) => {
    const child = spawn("sh", ["-c", 'cd "$1" && exec sh "$2"', "sh", cwd, file], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, TEST_TIMEOUT);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.once("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code, timedOut });
    });
  });
}

/**
 * Parse one `.t` file's TAP.
 *
 * TAP 12, which is all pjdfstest emits: a `1..N` plan and then `ok N` /
 * `not ok N`, optionally with a `# TODO` or `# SKIP` directive. A `# TODO`
 * marks something the *suite* knows is broken on some filesystems, so it is
 * counted apart rather than held against the driver either way.
 */
function parse(file: string, desc: string, output: string): FileResult {
  const result: FileResult = {
    file,
    desc,
    planned: 0,
    passed: 0,
    failed: 0,
    todo: 0,
    skipped: 0,
    failures: [],
  };
  for (const line of output.split("\n")) {
    const plan = /^1\.\.(\d+)/.exec(line);
    if (plan !== null) {
      result.planned = Number(plan[1]);
      continue;
    }
    const test = /^(not )?ok(?:\s+(\d+))?(.*)$/.exec(line);
    if (test === null) {
      continue;
    }
    const directive = test[3] ?? "";
    if (/#\s*SKIP/i.test(directive)) {
      result.skipped++;
    } else if (/#\s*TODO/i.test(directive)) {
      result.todo++;
    } else if (test[1] === undefined) {
      result.passed++;
    } else {
      result.failed++;
      result.failures.push(line.trim());
    }
  }
  // A script that dies halfway through leaves its remaining assertions
  // unaccounted for. They are failures: something wedged or crashed.
  const missing = result.planned - (result.passed + result.failed + result.todo + result.skipped);
  if (missing > 0) {
    result.failed += missing;
    result.note = `${missing} of ${result.planned} planned results never printed`;
  }
  return result;
}

function categoryOf(file: string): string {
  const [head = "misc"] = file.split("/");
  return head;
}

async function main(): Promise<void> {
  const filter = process.argv[2];
  const files = (await collect(TESTS)).filter(
    (file) => filter === undefined || file.includes(filter),
  );
  if (files.length === 0) {
    throw new Error(
      `no .t files under ${TESTS}${filter === undefined ? "" : ` matching ${filter}`}`,
    );
  }

  const mountpoint = join(HERE, "mnt");
  await mkdir(mountpoint, { recursive: true });
  // `allowOther` matters: pjdfstest runs many assertions as an unprivileged
  // uid (`pjdfstest -u 65534 …`), and without it the kernel refuses everyone
  // but the mounting user before the request even reaches the driver.
  // `defaultPermissions` stays on for the same reason — it is what makes the
  // mode bits the tests set actually enforce anything.
  const mounted = await mount(createMemoryDriver(), mountpoint, {
    fsname: "mountx-pjdfstest",
    allowOther: true,
    attrTimeout: 0,
    entryTimeout: 0,
    readers: 4,
  });

  const results: FileResult[] = [];
  try {
    for (const file of files) {
      const name = relative(TESTS, file);
      const source = await import("node:fs/promises").then((fs) => fs.readFile(file, "utf8"));
      const desc = /^desc="?([^"\n]*)"?/m.exec(source)?.[1] ?? "";
      const { stdout, stderr, timedOut } = await run(file, mountpoint);
      const result = parse(name, desc, stdout);
      if (timedOut) {
        result.note = `timed out after ${TEST_TIMEOUT}ms${result.note === undefined ? "" : `; ${result.note}`}`;
      }
      if (stderr.trim() !== "" && result.failed > 0) {
        result.note = `${result.note ?? ""} stderr: ${stderr.trim().split("\n")[0]}`.trim();
      }
      results.push(result);
      process.stdout.write(
        `${result.failed === 0 ? "ok  " : "FAIL"} ${name.padEnd(24)} ` +
          `${result.passed}/${result.planned}` +
          `${result.todo > 0 ? ` (+${result.todo} todo)` : ""}` +
          `${result.note === undefined ? "" : ` — ${result.note}`}\n`,
      );
    }
  } finally {
    await mounted.unmount().catch((error: unknown) => {
      process.stderr.write(`unmount failed: ${String(error)}\n`);
    });
    await rm(mountpoint, { recursive: true, force: true }).catch(() => {});
  }

  await writeFile(join(HERE, "results.json"), `${JSON.stringify(results, undefined, 2)}\n`);
  await writeFile(join(HERE, "results.txt"), summarize(results));
  process.stdout.write(`\n${summarize(results)}`);
  // The point of this script is the breakdown, not a verdict: pjdfstest is not
  // a suite anything passes outright, and a non-zero exit would make it
  // impossible to run from anything that checks exit codes.
}

function summarize(results: readonly FileResult[]): string {
  const categories = new Map<
    string,
    {
      passed: number;
      failed: number;
      todo: number;
      skipped: number;
      files: number;
      failing: number;
    }
  >();
  for (const result of results) {
    const key = categoryOf(result.file);
    const totals = categories.get(key) ?? {
      passed: 0,
      failed: 0,
      todo: 0,
      skipped: 0,
      files: 0,
      failing: 0,
    };
    totals.passed += result.passed;
    totals.failed += result.failed;
    totals.todo += result.todo;
    totals.skipped += result.skipped;
    totals.files++;
    totals.failing += result.failed > 0 ? 1 : 0;
    categories.set(key, totals);
  }

  const lines: string[] = [];
  lines.push("| category | files | files failing | pass | fail | todo | skip | pass rate |");
  lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
  const total = { passed: 0, failed: 0, todo: 0, skipped: 0, files: 0, failing: 0 };
  for (const [name, totals] of [...categories].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const run_ = totals.passed + totals.failed;
    lines.push(
      `| ${name} | ${totals.files} | ${totals.failing} | ${totals.passed} | ${totals.failed} | ` +
        `${totals.todo} | ${totals.skipped} | ${run_ === 0 ? "—" : `${((100 * totals.passed) / run_).toFixed(1)}%`} |`,
    );
    total.passed += totals.passed;
    total.failed += totals.failed;
    total.todo += totals.todo;
    total.skipped += totals.skipped;
    total.files += totals.files;
    total.failing += totals.failing;
  }
  const run_ = total.passed + total.failed;
  lines.push(
    `| **total** | ${total.files} | ${total.failing} | ${total.passed} | ${total.failed} | ` +
      `${total.todo} | ${total.skipped} | ${run_ === 0 ? "—" : `${((100 * total.passed) / run_).toFixed(1)}%`} |`,
  );
  lines.push("");
  lines.push("Files with failures:");
  for (const result of results) {
    if (result.failed === 0) {
      continue;
    }
    lines.push(
      `  ${result.file.padEnd(24)} ${result.failed} failed (${result.passed}/${result.planned})` +
        ` — ${result.desc}${result.note === undefined ? "" : ` [${result.note}]`}`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

await main();
