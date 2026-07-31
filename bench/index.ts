/**
 * `pnpm bench` — the columns that need no root.
 *
 * - **loopback**: the memory driver behind `createLoopback`, with no transport
 *   at all. The ceiling: whatever the FUSE and NFS columns cost, they cost it
 *   *on top of* this.
 * - **NFS**: the same scenarios over a real TCP socket to `createNfsServer`,
 *   driven by the JS client in `test/nfs/v3/client.ts`. Note what that is and is
 *   not: protocol encode/decode plus a loopback socket round trip, measured
 *   with a client in the same process. A kernel NFS client would add its own
 *   caching (which would make several of these numbers much better) and its own
 *   RPC scheduling; this host has no NFS client to measure with, so the honest
 *   description of the column is "the server's own cost, plus TCP".
 *
 * The two real-mount columns need root and are their own commands: FUSE is
 * `bench/fuse.ts` (`pnpm bench:root`) and 9P is `bench/9p.ts` (`pnpm bench:9p`).
 */

import { createMemoryDriver } from "../src/drivers/memory.ts";
import { createLoopback } from "../src/harness.ts";
import { createNfsServer } from "../src/nfs/server.ts";
import { check, NfsClient, nfsDriver } from "../test/nfs/v3/client.ts";
import { report, type Measurement } from "./harness.ts";
import { FULL, runScenarios } from "./scenarios.ts";

async function main(): Promise<void> {
  const results: Measurement[] = [];

  results.push(
    ...(await runScenarios(createLoopback(createMemoryDriver()), FULL, {
      group: "loopback (memory driver, no transport)",
    })),
  );

  const server = createNfsServer(createMemoryDriver());
  await server.listen();
  const client = await NfsClient.connect({ port: server.port });
  try {
    const root = check(await client.mnt("/"), "mount").fh!;
    results.push(
      ...(await runScenarios(createLoopback(nfsDriver(client, root)), FULL, {
        group: "NFSv3 over localhost TCP (memory driver)",
        notes: { client: "JS client, same process; protocol + TCP only, no kernel client" },
      })),
    );
  } finally {
    client.close();
    await server.close();
  }

  report("pnpm bench", results, process.argv);
}

await main();
