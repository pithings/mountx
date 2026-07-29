/**
 * Tier 0 for `execSeccomp()` — the part that has an opinion before anything is
 * built, spawned or trapped.
 *
 * Everything else about this transport needs a supervisor binary and a kernel
 * that will install a filter, and lives in `seccomp-run.test.ts` and
 * `seccomp-conformance.test.ts`, both of which skip themselves without a Zig
 * toolchain. This file runs everywhere, including on a machine that could never
 * run the mechanism at all.
 */

import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { execSeccomp } from "../../src/exec/seccomp.ts";

describe("execSeccomp", () => {
  it("refuses to run nothing", async () => {
    await expect(execSeccomp(createMemoryDriver(), [], { trace: "/nonexistent" })).rejects.toThrow(
      /needs a command/,
    );
  });

  it("says which supervisor it could not find", async () => {
    const saved = process.env.MOUNTX_TRACE;
    delete process.env.MOUNTX_TRACE;
    try {
      await expect(execSeccomp(createMemoryDriver(), ["true"])).rejects.toThrow(/MOUNTX_TRACE/);
    } finally {
      if (saved !== undefined) process.env.MOUNTX_TRACE = saved;
    }
  });

  it("cleans up the private socket when the supervisor cannot be spawned", async () => {
    await expect(
      execSeccomp(createMemoryDriver(), ["true"], { trace: "/nonexistent/mountx-trace" }),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });
});
