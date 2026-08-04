/**
 * The benchmark harness: warm up, run, count, report. Nothing else.
 *
 * IDEA.md makes a claim the README is not allowed to repeat until it has been
 * measured — "async main-thread mode should land in the low tens of thousands
 * of ops/sec", and, more importantly, that "the wins are in negotiation, not in
 * micro-optimizing JS". That makes the benchmark suite a v1 deliverable rather
 * than a nice-to-have, and it makes *this* file deliberately small: a warmup, a
 * loop, a monotonic clock, and percentiles from the samples it actually took.
 * No regression detection, no confidence intervals, no framework. The numbers
 * that get published are the ones in `.agents/benchmarks.md`, together with the
 * host they were taken on.
 *
 * Iteration counts are adaptive on purpose. The three columns differ by two
 * orders of magnitude, so a fixed count is either a rounding error in one
 * column or a coffee break in another; every scenario instead runs until it has
 * spent {@link BenchSpec.targetMs} or hit its iteration ceiling.
 */

import { writeFileSync } from "node:fs";
import { cpus, release, totalmem, type } from "node:os";

/** Work done per iteration, for the scenarios whose interesting number is a rate. */
export interface Work {
  /** How many units one iteration moves (bytes, files, entries). */
  units: number;
  /** What one unit is: `"MiB"`, `"files"`, `"entries"`. */
  unit: string;
}

export interface Measurement {
  group: string;
  scenario: string;
  /** Which configuration of the group this is — `"default"` unless something was degraded. */
  variant: string;
  iterations: number;
  /** From the wall window: `iterations / totalMs`. */
  opsPerSec: number;
  /** From inside the timed bracket, so `1 / meanMs` is *not* `opsPerSec`. */
  meanMs: number;
  p50Ms: number;
  p99Ms: number;
  minMs: number;
  /** Wall time the measured loop took, harness bookkeeping included. */
  totalMs: number;
  /** Time inside the timed brackets. `totalMs - insideMs` is the harness's cost. */
  insideMs: number;
  /** `units/sec` for scenarios that declared {@link Work}. */
  rate?: { value: number; unit: string };
  /** Anything worth carrying into the report: negotiated `max_write`, reader count, … */
  notes?: Record<string, string | number | boolean>;
}

export interface BenchSpec {
  group: string;
  scenario: string;
  variant?: string;
  /** Unrecorded iterations first, so JIT warmup is not in the samples. Default 5. */
  warmup?: number;
  /** Stop once this much time has been spent *and* `minIterations` are in. Default 1000. */
  targetMs?: number;
  /** Default 20. */
  minIterations?: number;
  /** Hard ceiling. Default 100_000. */
  maxIterations?: number;
  work?: Work;
  notes?: Record<string, string | number | boolean>;
  run: (iteration: number) => Promise<void>;
}

const NS_PER_MS = 1e6;

function percentile(sorted: Float64Array, fraction: number): number {
  if (sorted.length === 0) {
    return 0;
  }
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1));
  return sorted[index]!;
}

/** Run one scenario and report what it did. */
export async function measure(spec: BenchSpec): Promise<Measurement> {
  const warmup = spec.warmup ?? 5;
  const targetMs = spec.targetMs ?? 1000;
  const minIterations = spec.minIterations ?? 20;
  const maxIterations = spec.maxIterations ?? 100_000;

  for (let i = 0; i < warmup; i++) {
    await spec.run(i);
  }

  const samples: number[] = [];
  const started = process.hrtime.bigint();
  let wallMs = 0;
  for (let i = 0; samples.length < maxIterations; i++) {
    const before = process.hrtime.bigint();
    await spec.run(i);
    const after = process.hrtime.bigint();
    samples.push(Number(after - before) / NS_PER_MS);
    wallMs = Number(after - started) / NS_PER_MS;
    if (wallMs >= targetMs && samples.length >= minIterations) {
      break;
    }
  }

  const sorted = Float64Array.from(samples).sort();
  const insideMs = samples.reduce((sum, sample) => sum + sample, 0);
  const measurement: Measurement = {
    group: spec.group,
    scenario: spec.scenario,
    variant: spec.variant ?? "default",
    iterations: samples.length,
    // Throughput comes from the **wall** window, not from the sum of the
    // samples. The two differ by the harness's own bookkeeping — two
    // `hrtime.bigint()` calls and an array push, ~90 ns an iteration — which is
    // nothing against a FUSE round trip and 5–20% against a loopback `stat`.
    // Dividing by the sum would quietly credit the ceiling column with time it
    // spent in the harness, making every transport look relatively worse.
    opsPerSec: (samples.length / wallMs) * 1000,
    // Latency, in contrast, is the *bracket*: what one operation cost, with the
    // bookkeeping outside it. So `1 / meanMs` is deliberately not `opsPerSec`,
    // and the gap between them is the harness's overhead.
    meanMs: insideMs / samples.length,
    p50Ms: percentile(sorted, 0.5),
    p99Ms: percentile(sorted, 0.99),
    minMs: sorted[0] ?? 0,
    totalMs: wallMs,
    insideMs,
  };
  if (spec.work !== undefined) {
    measurement.rate = {
      value: (spec.work.units * samples.length) / (wallMs / 1000),
      unit: `${spec.work.unit}/s`,
    };
  }
  if (spec.notes !== undefined) {
    measurement.notes = spec.notes;
  }
  return measurement;
}

/**
 * Peak and total of a counter that only ever goes up, sampled on a timer.
 *
 * The counters worth watching during a benchmark — a session's request count,
 * most of all — say nothing about *rate* on their own, and a rate is what a
 * transport is judged on. Sampling one is the only way to say what it sustained
 * while something else was driving it.
 */
export interface RateSample {
  /** Highest per-second rate seen in any one window. */
  peak: number;
  /** How far the counter moved in total. */
  total: number;
}

/**
 * Watch `read()` on a timer until `stop()`.
 *
 * The window is the **measured** interval, not the requested one: a timer that
 * fires late — and one competing with a read/reply loop will — would otherwise
 * have its extra counts divided by a window it did not actually take.
 */
export function sampleRate(read: () => number, windowMs = 250): { stop: () => RateSample } {
  const start = read();
  let last = start;
  let since = process.hrtime.bigint();
  let peak = 0;
  const timer = setInterval(() => {
    const now = read();
    const at = process.hrtime.bigint();
    const elapsedMs = Number(at - since) / 1e6;
    if (elapsedMs > 0) {
      peak = Math.max(peak, ((now - last) * 1000) / elapsedMs);
    }
    last = now;
    since = at;
  }, windowMs);
  timer.unref();
  return {
    stop: () => {
      clearInterval(timer);
      return { peak: Math.round(peak), total: read() - start };
    },
  };
}

export interface HostInfo {
  os: string;
  kernel: string;
  cpus: number;
  cpuModel: string;
  memoryGiB: number;
  node: string;
  date: string;
}

/**
 * The line every published number has to be read against.
 *
 * A benchmark without its host is a number without a unit, and the README will
 * be quoting these — so the host goes into the JSON *and* the markdown.
 */
export function hostInfo(): HostInfo {
  const cores = cpus();
  return {
    os: type(),
    kernel: release(),
    cpus: cores.length,
    cpuModel: cores[0]?.model ?? "unknown",
    memoryGiB: Math.round((totalmem() / 1024 ** 3) * 10) / 10,
    node: process.version,
    date: new Date().toISOString().slice(0, 10),
  };
}

/** Thousands separated above 1000, `digits` decimals below it. */
export function fixed(value: number, digits = 2): string {
  if (!Number.isFinite(value)) {
    return "—";
  }
  return value >= 1000 ? Math.round(value).toLocaleString("en-US") : value.toFixed(digits);
}

/** Column-aligned plain text, one line per row, header underlined. */
export function table(header: readonly string[], rows: readonly string[][]): string {
  const widths = header.map((cell, column) =>
    Math.max(cell.length, ...rows.map((row) => (row[column] ?? "").length)),
  );
  const line = (cells: readonly string[]): string =>
    cells
      .map((cell, column) => cell.padEnd(widths[column]!))
      .join("  ")
      .trimEnd();
  return [line(header), line(widths.map((width) => "-".repeat(width))), ...rows.map(line)].join(
    "\n",
  );
}

/** A human-readable table, one row per measurement. */
function formatTable(results: readonly Measurement[]): string {
  return table(
    ["scenario", "variant", "ops/sec", "rate", "p50 ms", "p99 ms", "n"],
    results.map((result) => [
      result.scenario,
      result.variant,
      fixed(result.opsPerSec),
      result.rate === undefined ? "" : `${fixed(result.rate.value)} ${result.rate.unit}`,
      fixed(result.p50Ms, 3),
      fixed(result.p99Ms, 3),
      String(result.iterations),
    ]),
  );
}

interface BenchReport {
  host: HostInfo;
  /** `pnpm bench` or `pnpm bench:root`. */
  command: string;
  results: Measurement[];
}

/** Where `--json <path>` pointed, if anywhere. */
export function jsonTarget(argv: readonly string[]): string | undefined {
  const index = argv.indexOf("--json");
  return index === -1 ? undefined : argv[index + 1];
}

function writeReport(path: string, report: BenchReport): void {
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);
}

/** Print the human summary, and write the machine-readable one if asked for. */
export function report(command: string, results: Measurement[], argv: readonly string[]): void {
  const groups = [...new Set(results.map((result) => result.group))];
  const host = hostInfo();
  process.stdout.write(
    `\n${host.os} ${host.kernel}, ${host.cpus}× ${host.cpuModel}, node ${host.node}\n`,
  );
  for (const group of groups) {
    process.stdout.write(`\n## ${group}\n\n`);
    process.stdout.write(`${formatTable(results.filter((result) => result.group === group))}\n`);
  }
  const target = jsonTarget(argv);
  if (target !== undefined) {
    writeReport(target, { host, command, results });
    process.stdout.write(`\nwrote ${target}\n`);
  }
}
