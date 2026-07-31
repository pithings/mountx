/**
 * Driving a real mount from a second process.
 *
 * Both mounting columns — `bench/fuse.ts` and `bench/9p.ts` — serve the
 * filesystem from the process running the benchmark and measure it from a
 * child. The mechanism differs and the conclusion does not.
 *
 * On FUSE it is the sharp edge documented at the top of `src/fuse/mount.ts`: a
 * process that serves a mount and is also its client parks a
 * `UV_THREADPOOL_SIZE` thread for every operation it has in flight, and the
 * read loop needs one of those threads to pick the request up — and these
 * benchmarks deliberately put operations in flight, which is what the `readers`
 * comparison is *for*. On 9P the server answers from the event loop over a
 * socket, so asynchronous `fs` calls against our own mountpoint are safe
 * (`src/9p/mount.ts` says so, and the Tier-2 suite relies on it); what is not
 * safe there is anything *synchronous* against the mountpoint and `spawn()`
 * itself, since `uv_spawn` holds the calling thread until the child has exec'd.
 * A child that is spawned once, before any measuring, and then never touches
 * the mount from the serving process avoids both.
 *
 * It also measures the right shape: someone else's process on the other side of
 * the mountpoint, which is what a mount is for.
 */

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Measurement } from "./harness.ts";
import { type ClientRequest, RESULT_PREFIX } from "./scenarios.ts";

const here = dirname(fileURLToPath(import.meta.url));

/** Run one variant's scenarios in a child process and hand back what it measured. */
export function drive(request: ClientRequest): Promise<Measurement[]> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [join(here, "mount-client.ts"), JSON.stringify(request)],
      {
        // Never a cwd inside the mountpoint: `uv_spawn` has the child `chdir`
        // before it execs while the parent blocks on the exec pipe, so the
        // lookup that produces would be waiting on the thread that has to
        // answer it. True of both transports, for the same reason.
        cwd: dirname(here),
        // The client is the side with operations in flight, and on FUSE every
        // one of them parks a pool thread of its own.
        env: { ...process.env, UV_THREADPOOL_SIZE: "128" },
        stdio: ["ignore", "pipe", "inherit"],
      },
    );
    let out = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      out += chunk;
    });
    child.once("error", reject);
    child.once("close", (status) => {
      const line = out.split("\n").find((candidate) => candidate.startsWith(RESULT_PREFIX));
      if (line === undefined) {
        reject(new Error(`bench: the client exited ${status} without a result`));
        return;
      }
      resolve(JSON.parse(line.slice(RESULT_PREFIX.length)) as Measurement[]);
    });
  });
}
