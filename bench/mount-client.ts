/**
 * The client half of the real-mount benchmarks, in its own process.
 *
 * It has to be a separate process, and both mounting columns want that for
 * reasons that differ in mechanism and agree in conclusion — see the note at
 * the top of `bench/drive.ts`, which is what spawns this. What it buys the
 * numbers is the same either way: it measures the shape a real workload has,
 * someone else's process on the other side of the mountpoint.
 *
 * Spawned by `bench/drive.ts` with one JSON argument; answers with one
 * `__BENCH__`-prefixed JSON line on stdout.
 */

import { createLoopback } from "../src/harness.ts";
import { rootedNodeFs } from "../test/rooted-node-fs.ts";
import { type ClientRequest, RESULT_PREFIX, runScenarios } from "./scenarios.ts";

const request = JSON.parse(process.argv[2] ?? "{}") as ClientRequest;
const results = await runScenarios(createLoopback(rootedNodeFs(request.mountpoint)), request.keys, {
  group: request.group,
  variant: request.variant,
  notes: request.notes,
});
process.stdout.write(`${RESULT_PREFIX}${JSON.stringify(results)}\n`);
