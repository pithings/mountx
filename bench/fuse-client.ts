/**
 * The client half of the FUSE benchmark, in its own process.
 *
 * It has to be a separate process, and the reason is the sharp edge documented
 * at the top of `src/fuse/mount.ts`: a process that serves a mount and is also
 * its client parks a `UV_THREADPOOL_SIZE` thread for every operation it has in
 * flight, and the read loop needs one of those threads to pick the request up.
 * The benchmark deliberately puts operations in flight — that is what the
 * `readers` comparison is *for* — so keeping the client here removes the hazard
 * entirely instead of tiptoeing around it, and it measures the shape a real
 * workload has: someone else's process on the other side of the mountpoint.
 *
 * Spawned by `bench/fuse.ts` with one JSON argument; answers with one
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
