/**
 * The conformance matrix, seccomp-supervisor column.
 *
 * The organizing idea again: *one* suite written against the driver interface,
 * run every way the library can carry it. `drivers.test.ts` runs it through the
 * loopback harness, `test/9p/conformance.test.ts` through a whole 9P stack,
 * `test/fuse/conformance-mount.test.ts` through a real kernel mount — and this
 * file runs it through a **traced process**, with no mount anywhere.
 *
 * The path a single `fs.stat()` in this file takes: the suite calls the
 * loopback, which calls the driver in `seccomp-client.ts`, which writes a line
 * to a pipe; a `node` process on the far side of that pipe — running under a
 * seccomp filter it installed on itself — makes the `statx(2)` call; the kernel
 * suspends it and hands the supervisor a notification; the supervisor resolves
 * the path, walks it over 9P against a `P9Session`, reads `Rgetattr`, writes a
 * `struct statx` into the traced process's memory and answers the notification.
 * Nothing is short-circuited at any step.
 *
 * Tier 2, and unusually for a Tier-2 file in this repository it needs **no
 * root**: an unprivileged process may install a seccomp filter as long as it
 * sets `no_new_privs`. What it does need is a Zig toolchain to build the
 * supervisor, and x86-64 Linux, and it skips itself cleanly without either.
 */

import { afterEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { execSeccomp } from "../../src/exec/seccomp.ts";
import { createLoopback, type ResolvedCapabilities } from "../../src/harness.ts";
import { conformance } from "../conformance.ts";
import { buildSupervisor, supervisorRefusal } from "./seccomp-build.ts";
import { HelperLink, seccompDriver } from "./seccomp-client.ts";

const refusal = await supervisorRefusal();

/**
 * What survives the trip through the syscall boundary.
 *
 * Declared rather than derived, because this is the column's *claim*. It is the
 * 9P column's claim with nothing removed, which is the interesting part: the
 * supervisor speaks 9P to the same `P9Session` the kernel's v9fs client speaks
 * to, so everything that crosses one crosses the other.
 *
 * - **`handles: true`** — a `Tlopen` really opens the driver's file and the
 *   fid outlives an `unlink`, so a descriptor a traced process holds keeps
 *   working after the name is gone. The supervisor's own descriptor table
 *   holds the fid; the placeholder it injected has nothing in it.
 * - **`extensions: []`**, as in every transport column: the `mountx.*`
 *   namespace is a driver-to-session channel with no wire representation.
 *
 * Nothing here is faked to make a case pass. The gaps this transport really
 * has — `mmap` of a file on the tree, `execve` of a binary on it, extended
 * attributes, `sendfile`/`splice`/`copy_file_range` — are all things the driver
 * interface has no way to ask for, so the suite never asks.
 */
const THROUGH_SECCOMP: ResolvedCapabilities = {
  handles: true,
  atomicRename: true,
  hardlinks: true,
  symlinks: true,
  permissions: true,
  times: true,
  truncate: true,
  caseSensitive: true,
  statfs: true,
  readOnly: false,
  extensions: [],
};

const helper = new URL("./seccomp-helper.ts", import.meta.url).pathname;

/** Every traced process this file started, so a failure cannot leave one. */
const running: (() => Promise<void>)[] = [];

afterEach(async () => {
  for (const stop of running.splice(0)) await stop();
});

describe.skipIf(refusal !== undefined)("through a seccomp-traced process", () => {
  conformance({
    name: "memory driver, through the supervisor",
    capabilities: THROUGH_SECCOMP,
    setup: async () => {
      const trace = await buildSupervisor();
      const driver = createMemoryDriver();
      let ready: (link: HelperLink) => void = () => {};
      const linked = new Promise<HelperLink>((resolve) => {
        ready = resolve;
      });
      const exited = execSeccomp(driver, [process.execPath, helper], {
        trace,
        // stderr stays inherited: a helper that dies of something unexpected
        // should say so rather than hang the suite in silence.
        stdio: ["pipe", "pipe", "inherit"],
        onSpawn: (child) => ready(new HelperLink(child)),
      });
      const link = await linked;
      const stop = async (): Promise<void> => {
        link.finish();
        await exited;
      };
      running.push(stop);
      return { fs: createLoopback(seccompDriver(link)), cleanup: stop };
    },
  });

  it("really is running under a filter it cannot escape", async () => {
    const trace = await buildSupervisor();
    let status = "";
    const result = await execSeccomp(createMemoryDriver(), ["sh", "-c", "cat /proc/self/status"], {
      trace,
      stdio: ["ignore", "pipe", "inherit"],
      onSpawn: (child) => {
        child.stdout?.on("data", (chunk: Buffer) => {
          status += chunk.toString("utf8");
        });
      },
    });
    expect(result.code).toBe(0);
    // Mode 2 is `SECCOMP_MODE_FILTER`, and `NoNewPrivs` is what an
    // unprivileged process must set before it is allowed to install one.
    expect(status).toMatch(/^Seccomp:\s*2$/m);
    expect(status).toMatch(/^NoNewPrivs:\s*1$/m);
  });
});
