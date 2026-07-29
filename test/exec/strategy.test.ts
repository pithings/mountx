/**
 * Tier 0: what `mountx/exec` decides, and what it refuses to decide.
 *
 * Nothing here runs a command — `test/exec/userns.test.ts` does that. This is
 * the choice itself: the preference order, the reasons a mechanism is ruled
 * out, and the named-mechanism paths that must *not* consult the probe at all.
 *
 * The `platform`/`arch`/`supervisor` overrides are what make it a Tier-0 suite
 * instead of a host-dependent one: darwin, win32 and arm64 are answered from
 * any host, and only the assertions about *this* host's real capabilities are
 * gated.
 */

import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { exec, probeExec } from "../../src/exec/index.ts";
import { seccompExecProbe, usernsExecProbe } from "../../src/exec/probe.ts";
import { cwdRefusal } from "../../src/exec/userns.ts";

const here = probeExec();

describe("probeExec", () => {
  it("prefers the user namespace, then seccomp — one order on every host", () => {
    // There is no second order to have: off Linux neither mechanism can work,
    // so nothing is decided by what follows what.
    expect(here.preference).toEqual(["userns", "seccomp"]);
    expect(probeExec("darwin").preference).toEqual(["userns", "seccomp"]);
  });

  it("rules both out on macOS, each in its own words", () => {
    const probe = probeExec("darwin");
    expect(probe.chosen).toBeUndefined();
    expect(probe.userns.usable).toBe(false);
    expect(probe.seccomp.usable).toBe(false);
    // Not one shared "needs Linux": a reader on macOS is entitled to know that
    // macFUSE does not help with the first and that nothing at all plays
    // seccomp's role for the second.
    expect(probe.userns.reason).toContain("macFUSE");
    expect(probe.seccomp.reason).toContain("Linux facility");
    // One sentence naming both, rather than whichever failed last.
    expect(probe.reason).toContain("user namespace:");
    expect(probe.reason).toContain("seccomp:");
    expect(probe.reason).toContain("darwin");
  });

  it("rules both out on Windows too", () => {
    const probe = probeExec("win32");
    expect(probe.chosen).toBeUndefined();
    expect(probe.reason).toContain("win32");
  });

  it("always pairs usability with a reason, and a choice with a usable mechanism", () => {
    for (const probe of [here.userns, here.seccomp]) {
      expect(probe.usable).toBe(probe.reason === undefined);
    }
    expect(here.platform).toBe(process.platform);
    if (here.chosen === undefined) {
      expect(here.reason).toBeTruthy();
    } else {
      expect(here.reason).toBeUndefined();
      expect(here[here.chosen].usable).toBe(true);
      // The choice is the first usable one in preference order, not any usable one.
      expect(here.preference.find((mechanism) => here[mechanism].usable)).toBe(here.chosen);
    }
  });

  it("delegates each question to the mechanism's own probe rather than re-deciding", () => {
    // Same probes `src/exec/probe.ts` publishes, not a second opinion — which
    // is what keeps "what does the user-namespace mechanism need" one fact in
    // one file.
    expect(here.userns).toEqual(usernsExecProbe());
    expect(here.seccomp).toEqual(seccompExecProbe());
  });

  it("honours a supervisor the caller names, and refuses one that is not there", () => {
    // The supervisor is not shipped in the package, so "where is it" is a real
    // input to the decision and not a host fact this file can read.
    expect(seccompExecProbe("linux", "x64", undefined).reason).toContain("$MOUNTX_TRACE");
    expect(seccompExecProbe("linux", "x64", "/definitely/not/here").reason).toContain(
      "not an executable file",
    );
    expect(seccompExecProbe("linux", "x64", "/definitely/not/here").supervisor).toBeUndefined();
  });

  it("rules seccomp out on an architecture its filter was not written for", () => {
    const probe = seccompExecProbe("linux", "arm64", "/bin/sh");
    expect(probe.usable).toBe(false);
    expect(probe.arch).toBe(false);
    // And says what it would take, because "a second syscall table" is a
    // different size of job from "a redesign".
    expect(probe.reason).toContain("x86-64");
    expect(probe.reason).toContain("arm64");
  });

  it("refuses to answer for Linux from a host that is not Linux", () => {
    // The `platform` override takes away every file the probe reads, so a
    // verdict of `usable` would rest on checks that never ran. Only asserted
    // off Linux, where it is the case that exists.
    if (process.platform === "linux") {
      expect(usernsExecProbe("linux").reason ?? "").not.toContain("not Linux");
      return;
    }
    expect(usernsExecProbe("linux").usable).toBe(false);
    expect(seccompExecProbe("linux", "x64", "/bin/sh").usable).toBe(false);
  });
});

describe("cwdRefusal", () => {
  it("refuses a cwd that is the mountpoint, or under it", () => {
    // The witnessed deadlock, refused up front: `uv_spawn` blocks the thread
    // that answers FUSE until the child execs, and the child's first act is the
    // `chdir` that needs an answer from it.
    expect(cwdRefusal("/mnt/x", "/mnt/x")).toContain("deadlocks");
    expect(cwdRefusal("/mnt/x/deep/er", "/mnt/x")).toContain("deadlocks");
    // And names the spelling that works, since the caller does want to be in there.
    expect(cwdRefusal("/mnt/x", "/mnt/x")).toContain("$MOUNTX_ROOT");
  });

  it("allows everything else, including a path that merely starts the same way", () => {
    expect(cwdRefusal("/tmp", "/mnt/x")).toBeUndefined();
    expect(cwdRefusal("/mnt", "/mnt/x")).toBeUndefined();
    // `/mnt/xy` is not inside `/mnt/x`; a prefix match with no separator would
    // say it was.
    expect(cwdRefusal("/mnt/xy", "/mnt/x")).toBeUndefined();
  });

  it("compares resolved paths, not the strings it was handed", () => {
    expect(cwdRefusal("/mnt/x/../x/sub", "/mnt/x")).toContain("deadlocks");
    expect(cwdRefusal("/mnt/x/..", "/mnt/x")).toBeUndefined();
  });
});

describe("exec", () => {
  it("needs a command", async () => {
    await expect(exec(createMemoryDriver(), [])).rejects.toThrow(/needs a command to run/);
  });

  it.skipIf(here.chosen !== undefined)(
    "refuses with both mechanisms' reasons when neither can run",
    async () => {
      await expect(exec(createMemoryDriver(), ["true"])).rejects.toThrow(
        /no mechanism can run a command with a driver on this host/,
      );
    },
  );

  it.skipIf(here.seccomp.usable)("lets a named mechanism fail in its own words", async () => {
    // The assertion is the *absence* of the picker's sentence: naming a
    // mechanism skips the probe, so whatever comes back is the mechanism's own
    // and is more specific than anything `probeExec` could have said. Which
    // sentence exactly is `src/exec/seccomp.ts`'s business, not this file's.
    const failure = await exec(createMemoryDriver(), ["true"], { mechanism: "seccomp" }).then(
      () => undefined,
      (error: unknown) => error as Error,
    );
    expect(failure).toBeInstanceOf(Error);
    expect(failure?.message).not.toContain("no mechanism can run a command");
  });

  it.skipIf(here.userns.usable)(
    "lets a named userns mechanism fail in its own words too",
    async () => {
      await expect(exec(createMemoryDriver(), ["true"], { mechanism: "userns" })).rejects.toThrow(
        /cannot run a command in a user namespace here/,
      );
    },
  );
});
