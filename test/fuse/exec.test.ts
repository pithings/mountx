/**
 * Tier 0 for the spawn helper every mount and every teardown goes through.
 *
 * This file exists because nothing imported `src/fuse/exec.ts` at all, and the
 * consequence was visible: the timeout that makes AGENTS.md's "every spawned
 * `umount` is bounded by that deadline and abandoned if it outlives it" true
 * was added for the NFS transport and the FUSE callers never started passing
 * one. A helper with no tests is a helper its callers can quietly stop using.
 *
 * Everything here spawns a real `node`, because the whole subject is child
 * processes; nothing here mounts anything, so it runs unprivileged on any host
 * as part of `pnpm test`.
 */

import { spawn } from "node:child_process";
import { describe as suite, expect, it } from "vitest";
import {
  deadlineIn,
  delay,
  describe,
  errorMessage,
  run,
  type SpawnResult,
  stdioWith,
} from "../../src/fuse/exec.ts";

/** Both streams captured, like every teardown spawn in `src/`. */
const CAPTURE: Array<"ignore" | "pipe" | number> = ["ignore", "pipe", "pipe"];

/** A child that will not finish on its own within any test's patience. */
const FOREVER = ["-e", "setTimeout(() => {}, 60_000)"];

/**
 * The same thing, deaf to `SIGTERM`.
 *
 * `run` kills with `SIGKILL`, which nothing can catch — the point of the case
 * is that the *promise* does not depend on the kill working, so a child that
 * declines the polite signal changes nothing about when the caller is answered.
 */
const STUBBORN = ["-e", "process.on('SIGTERM', () => {}); setTimeout(() => {}, 60_000)"];

suite("run", () => {
  it("reports a clean exit with what the child said on both streams", async () => {
    const result = await run(
      process.execPath,
      ["-e", "process.stdout.write('out'); process.stderr.write('err\\n')"],
      { stdio: CAPTURE },
    );
    expect(result).toEqual({
      status: 0,
      signal: null,
      stdout: "out",
      // Trimmed, because it goes straight into an error message.
      stderr: "err",
      timedOut: false,
    });
  });

  it("reports a non-zero exit rather than rejecting", async () => {
    const result = await run(process.execPath, ["-e", "process.exit(3)"], { stdio: CAPTURE });
    expect(result.status).toBe(3);
    expect(result.timedOut).toBe(false);
  });

  it("leaves stdout empty when it was not piped", async () => {
    const result = await run(process.execPath, ["-e", "process.stdout.write('unheard')"], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    expect(result.stdout).toBe("");
    expect(result.status).toBe(0);
  });

  it("adds to the environment rather than replacing it", async () => {
    const result = await run(
      process.execPath,
      [
        "-e",
        "process.stdout.write(`${process.env.MOUNTX_TEST}:${process.env.PATH === undefined}`)",
      ],
      { stdio: CAPTURE, env: { MOUNTX_TEST: "here" } },
    );
    expect(result.stdout).toBe("here:false");
  });

  it("rejects when the command does not exist", async () => {
    await expect(run("mountx-no-such-command", [], { stdio: CAPTURE })).rejects.toThrow(/ENOENT/);
  });

  it("settles at the deadline with a child that is still running", async () => {
    const started = Date.now();
    const result = await run(process.execPath, FOREVER, { stdio: CAPTURE, timeout: 250 });
    const elapsed = Date.now() - started;
    expect(result.timedOut).toBe(true);
    expect(result.status).toBeNull();
    expect(result.signal).toBeNull();
    // Generous, because the assertion is "not the child's 60 seconds".
    expect(elapsed).toBeLessThan(10_000);
  });

  it("settles at the deadline even when the child ignores SIGTERM", async () => {
    const started = Date.now();
    const result = await run(process.execPath, STUBBORN, { stdio: CAPTURE, timeout: 250 });
    expect(result.timedOut).toBe(true);
    expect(Date.now() - started).toBeLessThan(10_000);
  });

  it("keeps what the child managed to say before the deadline", async () => {
    const result = await run(
      process.execPath,
      ["-e", "process.stderr.write('half a message\\n'); setTimeout(() => {}, 60_000)"],
      { stdio: CAPTURE, timeout: 500 },
    );
    expect(result.timedOut).toBe(true);
    expect(result.stderr).toBe("half a message");
  });

  it("treats a spent budget as a deadline that has already passed", async () => {
    // `deadlineIn` answers `0` rather than `undefined` once its budget is gone,
    // and `0` has to mean "no time left", not "wait forever".
    const result = await run(process.execPath, FOREVER, { stdio: CAPTURE, timeout: 0 });
    expect(result.timedOut).toBe(true);
  });

  it("does not fire the deadline for a child that finished in time", async () => {
    const result = await run(process.execPath, ["-e", ""], { stdio: CAPTURE, timeout: 30_000 });
    expect(result).toMatchObject({ status: 0, timedOut: false });
  });

  /**
   * The case the invariant is actually about: a child that outlives its
   * deadline must not outlive the *caller*.
   *
   * `SIGKILL` deals with the ordinary child, so the interesting one is the child
   * whose stdio a survivor still holds — here a detached grandchild that
   * inherited the stderr pipe. The killed child's `close` never fires, because
   * Node waits for the stdio streams too, and the open pipe keeps the event
   * loop alive: without `stdout/stderr.destroy()` and `unref()` this process
   * would sit there until the grandchild let go. So the assertion is made from
   * outside, on a real `node` that runs `run()` and then simply returns.
   */
  it("lets go of a child completely, so a timed-out run does not hold the process open", async () => {
    const script = `
      const { run } = await import(${JSON.stringify(new URL("../../src/fuse/exec.ts", import.meta.url).href)});
      const survivor = ${JSON.stringify([
        "-e",
        "require('node:child_process').spawn(process.execPath, ['-e', 'setTimeout(() => {}, 20_000)'], { stdio: ['ignore', 'ignore', 'inherit'], detached: true }).unref(); setTimeout(() => {}, 20_000)",
      ])};
      const result = await run(process.execPath, survivor, {
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 300,
      });
      process.stdout.write(JSON.stringify({ timedOut: result.timedOut }));
    `;
    const started = Date.now();
    const exited = await new Promise<{ code: number | null; stdout: string }>((resolve) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
        stdio: ["ignore", "pipe", "inherit"],
      });
      let stdout = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        stdout += chunk;
      });
      child.once("close", (code) => resolve({ code, stdout }));
    });
    expect(exited.stdout).toContain('"timedOut":true');
    expect(exited.code).toBe(0);
    // The grandchild holds the pipe for 20 s. Anything under that is the
    // process having let go of it rather than waited for it.
    expect(Date.now() - started).toBeLessThan(10_000);
  }, 30_000);
});

suite("deadlineIn", () => {
  it("counts down and floors at zero rather than going negative", async () => {
    const budget = deadlineIn(100);
    const first = budget.remaining();
    expect(first).toBeGreaterThan(0);
    expect(first).toBeLessThanOrEqual(100);
    await delay(150);
    // Zero, not `undefined`: a spent budget is a deadline that has passed, and
    // `undefined` is what "no deadline at all" means to `run`.
    expect(budget.remaining()).toBe(0);
  });

  it("never hands a later step more than an earlier one left it", async () => {
    const budget = deadlineIn(1000);
    const first = budget.remaining()!;
    await delay(20);
    const second = budget.remaining()!;
    expect(second).toBeLessThan(first);
    // Three steps sharing one budget cost one budget, which is the whole point.
    expect(first + second).toBeLessThan(2000);
  });

  for (const [name, value] of [
    ["undefined", undefined],
    ["zero", 0],
    ["a negative number", -1],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["NaN", Number.NaN],
  ] as const) {
    it(`treats ${name} as no deadline at all`, () => {
      expect(deadlineIn(value).remaining()).toBeUndefined();
    });
  }
});

suite("delay", () => {
  it("resolves after the wait", async () => {
    const started = Date.now();
    await delay(30);
    expect(Date.now() - started).toBeGreaterThanOrEqual(20);
  });
});

suite("describe", () => {
  const base: SpawnResult = { status: 0, signal: null, stdout: "", stderr: "" };

  it("names an exit status", () => {
    expect(describe("umount", { ...base, status: 32 })).toBe("umount: exit 32");
  });

  it("names a signal ahead of the (null) status", () => {
    expect(describe("umount", { ...base, status: null, signal: "SIGKILL" })).toBe(
      "umount: signal SIGKILL",
    );
  });

  it("says a timed-out child is still running, not that it exited", () => {
    const result: SpawnResult = { ...base, status: null, timedOut: true };
    expect(describe("umount", result)).toBe("umount: no answer before the deadline, still running");
  });

  it("appends stderr when there is any", () => {
    expect(describe("umount", { ...base, status: 1, stderr: "target is busy" })).toBe(
      "umount: exit 1: target is busy",
    );
  });
});

suite("errorMessage", () => {
  it("unwraps an Error and stringifies anything else", () => {
    expect(errorMessage(new Error("boom"))).toBe("boom");
    expect(errorMessage("boom")).toBe("boom");
    expect(errorMessage(undefined)).toBe("undefined");
  });
});

suite("stdioWith", () => {
  it("puts the descriptor at its own index and captures stderr", () => {
    expect(stdioWith(7)).toEqual([
      "ignore",
      "ignore",
      "pipe",
      "ignore",
      "ignore",
      "ignore",
      "ignore",
      7,
    ]);
  });

  it("still leaves room for stderr when the descriptor is a low number", () => {
    expect(stdioWith(0)).toEqual([0, "ignore", "pipe"]);
  });
});
