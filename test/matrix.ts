/**
 * The conformance matrix reporter.
 *
 * ```sh
 * pnpm matrix
 * ```
 *
 * IDEA.md's organizing idea is that there is **one** conformance suite written
 * against the driver interface, run every way the library can carry it — and
 * that the matrix "reports honestly which capabilities each transport actually
 * loses, instead of a README table written from guesses". The six columns
 * already exist as ordinary vitest files; this script is only the thing that
 * runs them and lays the results side by side:
 *
 * - **loopback** — `test/drivers.test.ts`, no transport at all (and the raw
 *   `node:fs/promises` oracle, which runs in the same file).
 * - **FUSE** — `test/fuse/conformance-mount.test.ts`, a real kernel mount.
 *   Tier 2: needs root, so it goes through `test/root.sh` and skips itself with
 *   a reason when this host cannot run it.
 * - **9P** — `test/9p/conformance.test.ts`, the whole 9P2000.L stack through
 *   its codecs, no socket needed. Tier 1: no root, no mount.
 * - **NFSv3** — `test/nfs/v3/conformance.test.ts`, the whole NFSv3 stack over a
 *   real TCP socket. Tier 1: no root, no mount.
 * - **NFSv4.1** — `test/nfs/v4/conformance.test.ts`, the same, one protocol
 *   version up: sessions, compounds and a stateid per open. Also Tier 1 — and
 *   the two NFS columns side by side are what turn "which of these is the
 *   protocol and which is the server?" into a readable row.
 * - **S3** — `test/s3/conformance.test.ts`, the gateway with a JS client in
 *   front of it. Tier 1, and one step cheaper still: the session is a function
 *   from a request to a reply, so there is not even a socket.
 *
 * Deliberately dumb: it shells out to vitest's JSON reporter and parses the
 * result, because a custom reporter would have to be loaded into six separate
 * vitest processes (one of them under `sudo`) and then invent its own way of
 * getting the pieces back together. Nothing here knows anything about the
 * suite's contents.
 *
 * **Where a skip's reason comes from.** A skipped test leaves nothing behind
 * but its name, so `test/conformance.ts` puts the reason *in* the name: every
 * gated case is tagged `[needs <capability> + …]` whether or not it ran. A
 * requirement counts as unmet in a column when no case naming it passed there,
 * which is how "NFSv3 loses `handles`" ends up in the report as a derived fact
 * rather than a claim this script was told.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { REQUIREMENT_TAG } from "./conformance.ts";

/** One column of the matrix. */
interface Column {
  key: string;
  label: string;
  file: string;
  /** Tier 2: run it through `test/root.sh`. */
  root: boolean;
  description: string;
}

const COLUMNS: Column[] = [
  {
    key: "loopback",
    label: "loopback",
    file: "test/drivers.test.ts",
    root: false,
    description: "the driver behind `createLoopback`, no transport",
  },
  {
    key: "fuse",
    label: "FUSE",
    file: "test/fuse/conformance-mount.test.ts",
    root: true,
    description: "a real kernel mount, `node:fs` as the client",
  },
  {
    key: "9p",
    label: "9P",
    file: "test/9p/conformance.test.ts",
    root: false,
    description: "9P2000.L through the codecs, the JS client from `test/9p/client.ts`",
  },
  {
    key: "nfs",
    label: "NFSv3",
    file: "test/nfs/v3/conformance.test.ts",
    root: false,
    description: "NFSv3 over a TCP socket, the JS client from `test/nfs/v3/client.ts`",
  },
  {
    key: "nfs4",
    label: "NFSv4.1",
    file: "test/nfs/v4/conformance.test.ts",
    root: false,
    description:
      "NFSv4.1 over a TCP socket, the JS client from `test/nfs/v4/client.ts` and " +
      "the driver over it in `test/nfs/v4/driver.ts`",
  },
  {
    key: "s3",
    label: "S3",
    file: "test/s3/conformance.test.ts",
    root: false,
    description: "an S3 gateway in process, the JS client from `test/s3/client.ts`",
  },
];

type Status = "passed" | "failed" | "pending";

interface AssertionResult {
  ancestorTitles: string[];
  title: string;
  status: string;
}

interface VitestJson {
  testResults: { assertionResults: AssertionResult[] }[];
}

/** One conformance case, identified the same way in every column. */
interface Row {
  area: string;
  name: string;
  requires: string[];
  /** column key → target name → status. */
  cells: Map<string, Map<string, Status>>;
}

interface ColumnResult {
  /** Conformance targets seen in this column's run, in order. */
  targets: string[];
  /** Why the column could not run, if it could not. */
  unavailable?: string;
}

const rows = new Map<string, Row>();
const results = new Map<string, ColumnResult>();

/** Strip the `[needs …]` marker off a title and hand back what it named. */
function untag(title: string): { text: string; requires: string[] } {
  const match = REQUIREMENT_TAG.exec(title);
  if (match === null) {
    return { text: title, requires: [] };
  }
  return {
    text: title.slice(0, match.index),
    requires: match[1]!.split("+").map((part) => part.trim()),
  };
}

/**
 * Run one column and fold its results into {@link rows}.
 *
 * The output file goes in a directory this process owns, because the root
 * column writes it as root and `/tmp` is sticky.
 */
function run(column: Column, scratch: string): ColumnResult {
  const output = join(scratch, `${column.key}.json`);
  const [command, args] = column.root
    ? ["sh", ["test/root.sh", "--reporter=json", `--outputFile=${output}`, column.file]]
    : [
        process.execPath,
        [
          "node_modules/vitest/vitest.mjs",
          "run",
          "--reporter=json",
          `--outputFile=${output}`,
          column.file,
        ],
      ];
  const child = spawnSync(command!, args as string[], { encoding: "utf8" });
  if (!existsSync(output)) {
    const detail = `${child.stderr ?? ""}${child.stdout ?? ""}`.trim().split("\n").at(-1) ?? "";
    return {
      targets: [],
      unavailable: `vitest produced no report${detail === "" ? "" : `: ${detail}`}`,
    };
  }
  const report = JSON.parse(readFileSync(output, "utf8")) as VitestJson;
  const targets: string[] = [];
  for (const file of report.testResults) {
    for (const assertion of file.assertionResults) {
      // Every case lives under a `conformance: <target>` describe; everything
      // above it is the column's own scaffolding and everything below it is the
      // area. That segment is what makes a row identifiable across columns.
      const index = assertion.ancestorTitles.findIndex((title) =>
        title.startsWith("conformance: "),
      );
      if (index === -1) {
        continue;
      }
      const target = assertion.ancestorTitles[index]!.slice("conformance: ".length);
      if (!targets.includes(target)) {
        targets.push(target);
      }
      const area = untag(assertion.ancestorTitles.slice(index + 1).join(" › "));
      const name = untag(assertion.title);
      const key = `${area.text}\0${name.text}`;
      let row = rows.get(key);
      if (row === undefined) {
        row = {
          area: area.text,
          name: name.text,
          requires: [...area.requires, ...name.requires],
          cells: new Map(),
        };
        rows.set(key, row);
      }
      let cells = row.cells.get(column.key);
      if (cells === undefined) {
        cells = new Map();
        row.cells.set(column.key, cells);
      }
      cells.set(target, assertion.status as Status);
    }
  }
  return { targets };
}

/** Can the root column run here at all? A reason, or `undefined` for yes. */
function rootBlocker(): string | undefined {
  if (process.env.UNIMOUNT_MATRIX_SKIP_ROOT === "1") {
    return "UNIMOUNT_MATRIX_SKIP_ROOT=1";
  }
  if (process.platform !== "linux") {
    return `FUSE needs Linux, this is ${process.platform}`;
  }
  if (!existsSync("/dev/fuse")) {
    return "no /dev/fuse on this host";
  }
  if ((process.getuid?.() ?? -1) !== 0) {
    const sudo = spawnSync("sudo", ["-n", "true"], { stdio: "ignore" });
    if (sudo.status !== 0) {
      return "not root, and `sudo -n` is not available";
    }
  }
  return undefined;
}

/**
 * Which requirements a column does not meet.
 *
 * Derived, not declared: a requirement is met when at least one case naming it
 * passed. That is what turns "the NFS column skipped every `handles` case" into
 * the report's statement that NFSv3 loses `handles`.
 *
 * **At least one, across the targets in the column** — the drivers sharing a
 * column need not have the same capabilities. `unstorage` is a key-value store
 * with no symlinks, and it runs in the loopback column beside `memory`, which
 * has them; requiring every target to pass would report the *column* as having
 * lost symlinks on the strength of one driver that never claimed them. What
 * this column is being asked is what carrying the suite costs, and a capability
 * that survived for any driver in it did not cost anything. A target that
 * outright *fails* is a different thing and is reported as `**FAIL**` in its
 * own cell rather than being folded in here.
 */
function unmetIn(column: string): Set<string> {
  const named = new Set<string>();
  const met = new Set<string>();
  for (const row of rows.values()) {
    if (row.requires.length === 0) {
      continue;
    }
    const cells = row.cells.get(column);
    const passed = cells !== undefined && [...cells.values()].some((status) => status === "passed");
    for (const requirement of row.requires) {
      named.add(requirement);
      if (passed) {
        met.add(requirement);
      }
    }
  }
  return new Set([...named].filter((requirement) => !met.has(requirement)));
}

function cellText(row: Row, column: Column, unmet: Set<string>): string {
  const cells = row.cells.get(column.key);
  if (cells === undefined || cells.size === 0) {
    return "—";
  }
  const statuses = new Set(cells.values());
  const render = (status: Status): string => {
    if (status === "failed") {
      return "**FAIL**";
    }
    if (status === "passed") {
      return "pass";
    }
    const reasons = row.requires.filter((requirement) => unmet.has(requirement));
    return reasons.length === 0 ? "skip" : `skip: ${reasons.join(" + ")}`;
  };
  if (statuses.size === 1) {
    return render([...statuses][0]!);
  }
  // Drivers inside one column disagreeing is worth seeing, not averaging away.
  return [...cells].map(([target, status]) => `${render(status)} (${target})`).join(", ");
}

function counts(column: string): { passed: number; skipped: number; failed: number } {
  let passed = 0;
  let skipped = 0;
  let failed = 0;
  for (const row of rows.values()) {
    for (const status of row.cells.get(column)?.values() ?? []) {
      if (status === "passed") {
        passed++;
      } else if (status === "failed") {
        failed++;
      } else {
        skipped++;
      }
    }
  }
  return { passed, skipped, failed };
}

function main(): void {
  const scratch = mkdtempSync(join(tmpdir(), "unimount-matrix-"));
  try {
    for (const column of COLUMNS) {
      const blocker = column.root ? rootBlocker() : undefined;
      process.stdout.write(`matrix: ${column.label} … `);
      const result =
        blocker === undefined ? run(column, scratch) : { targets: [], unavailable: blocker };
      results.set(column.key, result);
      const { passed, skipped, failed } = counts(column.key);
      process.stdout.write(
        result.unavailable === undefined
          ? `${passed} passed, ${skipped} skipped, ${failed} failed\n`
          : `unavailable (${result.unavailable})\n`,
      );
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  const unmet = new Map(COLUMNS.map((column) => [column.key, unmetIn(column.key)]));
  const out: string[] = [];
  const push = (line = ""): void => void out.push(line);

  push("# Conformance matrix");
  push();
  push("<!-- Generated by `pnpm matrix` (test/matrix.ts). Do not edit by hand. -->");
  push();
  push(
    "One conformance suite (`test/conformance.ts`), written against the driver interface, run " +
      "every way the library can carry it. The driver never learns which column it is in, so a " +
      "row that passes in one column and fails in another is a *transport* bug by construction.",
  );
  push();
  push(`Generated ${new Date().toISOString().slice(0, 10)} with \`pnpm matrix\`.`);
  push();

  push("| Column | What it runs | Result |");
  push("| --- | --- | --- |");
  for (const column of COLUMNS) {
    const result = results.get(column.key)!;
    const { passed, skipped, failed } = counts(column.key);
    const verdict =
      result.unavailable === undefined
        ? `${passed} passed, ${skipped} skipped${failed > 0 ? `, **${failed} failed**` : ""} ` +
          `(${result.targets.length} target${result.targets.length === 1 ? "" : "s"}: ` +
          `${result.targets.join("; ")})`
        : `not run — ${result.unavailable}`;
    push(`| **${column.label}** | \`${column.file}\` — ${column.description} | ${verdict} |`);
  }
  push();

  push("## Capability loss");
  push();
  push(
    "Derived from the run, not declared here: a requirement counts as unmet in a column when no " +
      "case that names it passed there. `root` is an environment fact rather than a transport " +
      "one — it gates the one case that hands a file away, which only root may do — so it is " +
      "reported in its own column.",
  );
  push();
  push(
    "**What this direction of derivation cannot check.** A column declares its own capabilities " +
      "(`THROUGH_FUSE`, `THROUGH_9P`/`THROUGH_9P_REOPENED`, `THROUGH_NFS`, `THROUGH_NFS4`, " +
      "`THROUGH_S3`), and declaring one `false` skips every case that needs it " +
      "— which is exactly what a real loss looks like from here. So a capability the transport " +
      "*does* carry, wrongly declared lost, is reported as a loss with nothing to contradict it; " +
      "the evidence only ever runs the other way, from a passing case to a capability that must " +
      "be present. Every entry below is therefore a claim the transport's own test file makes " +
      "and the run did not refute, and the comment at each declaration is where the reasoning " +
      "for it lives.",
  );
  push();
  push("| Column | Capabilities lost | Environment |");
  push("| --- | --- | --- |");
  for (const column of COLUMNS) {
    const result = results.get(column.key)!;
    const missing = [...(unmet.get(column.key) ?? [])];
    const lost = missing.filter((name) => name !== "root");
    const environment = missing.includes("root") ? "not root: `root` cases skipped" : "complete";
    push(
      result.unavailable === undefined
        ? `| **${column.label}** | ${
            lost.length === 0 ? "none" : lost.map((name) => `\`${name}\``).join(", ")
          } | ${environment} |`
        : `| **${column.label}** | _not run_ | ${result.unavailable} |`,
    );
  }
  push();

  push("## Cases");
  push();
  const areas = [...new Set([...rows.values()].map((row) => row.area))];
  for (const area of areas) {
    push(`### ${area}`);
    push();
    push(`| Case | Needs | ${COLUMNS.map((column) => column.label).join(" | ")} |`);
    push(`| --- | --- | ${COLUMNS.map(() => "---").join(" | ")} |`);
    for (const row of [...rows.values()].filter((candidate) => candidate.area === area)) {
      const needs =
        row.requires.length === 0 ? "" : row.requires.map((r) => `\`${r}\``).join(" + ");
      const cells = COLUMNS.map((column) => cellText(row, column, unmet.get(column.key)!));
      push(`| ${row.name} | ${needs} | ${cells.join(" | ")} |`);
    }
    push();
  }

  writeFileSync(".agents/conformance-matrix.md", `${out.join("\n").trimEnd()}\n`);
  process.stdout.write("matrix: wrote .agents/conformance-matrix.md\n");
  if (COLUMNS.some((column) => counts(column.key).failed > 0)) {
    process.exitCode = 1;
  }
}

main();
