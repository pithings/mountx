/**
 * Tier 0 for the parts of the unprivileged mount path that are a decision
 * rather than a syscall: whether the helper can elevate, and what to say when a
 * mount failed because it did not.
 *
 * Everything here is pure, so it runs on any host — including one with no
 * `fusermount3` at all, which is exactly the host these messages are for.
 */

import { describe, expect, it } from "vitest";
import {
  deviceRefusalAdvice,
  elevationRefusal,
  type ExecPrivileges,
  execPrivileges,
} from "../../src/fuse/fusermount.ts";

const HELPER = "/usr/bin/fusermount3";

/** The ordinary desktop Linux case: no ambient capabilities, no sandbox. */
const PLAIN: ExecPrivileges = { ambient: false, noNewPrivs: false };
const SANDBOXED: ExecPrivileges = { ambient: false, noNewPrivs: true };

describe("elevationRefusal", () => {
  it("accepts a helper that is setuid root", () => {
    expect(elevationRefusal(HELPER, { mode: 0o104_755, uid: 0 }, PLAIN)).toBeUndefined();
  });

  it("refuses one whose setuid bit is gone, and says how to restore it", () => {
    const refusal = elevationRefusal(HELPER, { mode: 0o100_755, uid: 0 }, PLAIN);
    expect(refusal).toContain("not setuid");
    expect(refusal).toContain(`sudo chmod u+s ${HELPER}`);
  });

  it("refuses one that is setuid to somebody who is not root", () => {
    const refusal = elevationRefusal(HELPER, { mode: 0o104_755, uid: 1000 }, PLAIN);
    expect(refusal).toContain("uid 1000");
  });

  it("refuses a perfectly good helper when no_new_privs has made the bit inert", () => {
    const refusal = elevationRefusal(HELPER, { mode: 0o104_755, uid: 0 }, SANDBOXED);
    expect(refusal).toContain("no_new_privs");
    // The part that saves an afternoon: it says sudo is dead the same way, so
    // nobody goes looking for a chmod that could not have helped.
    expect(refusal).toContain("sudo is equally dead");
  });

  it("names no_new_privs ahead of the mode, which it explains away", () => {
    const refusal = elevationRefusal(HELPER, { mode: 0o100_755, uid: 0 }, SANDBOXED);
    expect(refusal).toContain("no_new_privs");
    expect(refusal).not.toContain("chmod u+s");
  });

  it("accepts a helper with no setuid bit when the caller passes CAP_SYS_ADMIN on", () => {
    expect(
      elevationRefusal(HELPER, { mode: 0o100_755, uid: 0 }, { ambient: true, noNewPrivs: true }),
    ).toBeUndefined();
  });

  it("says nothing when the helper could not be stat'd", () => {
    expect(elevationRefusal(HELPER, undefined, PLAIN)).toBeUndefined();
  });
});

describe("execPrivileges", () => {
  it("reads CAP_SYS_ADMIN out of an ambient mask", () => {
    expect(execPrivileges("Name:\tnode\nCapAmb:\t0000000000200000\n").ambient).toBe(true);
  });

  it("is false for an empty ambient set", () => {
    expect(execPrivileges("CapAmb:\t0000000000000000\n").ambient).toBe(false);
  });

  it("does not confuse the other three capability sets for the ambient one", () => {
    const status =
      "CapInh:\t0000000000200000\nCapEff:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
    expect(execPrivileges(status).ambient).toBe(false);
  });

  it("is false when the kernel does not report CapAmb at all", () => {
    expect(execPrivileges("Name:\tnode\n").ambient).toBe(false);
  });

  it("keeps every bit above 31, which a 32-bit parse would lose", () => {
    // CAP_CHECKPOINT_RESTORE (40) set, CAP_SYS_ADMIN (21) clear.
    expect(execPrivileges("CapAmb:\t0000010000000000\n").ambient).toBe(false);
  });

  it("reads NoNewPrivs both ways, and as off when the kernel does not report it", () => {
    expect(execPrivileges("NoNewPrivs:\t1\n").noNewPrivs).toBe(true);
    expect(execPrivileges("NoNewPrivs:\t0\n").noNewPrivs).toBe(false);
    expect(execPrivileges("Name:\tnode\n").noNewPrivs).toBe(false);
  });

  it("does not read the Seccomp line as a NoNewPrivs line", () => {
    expect(execPrivileges("Seccomp:\t1\nNoNewPrivs:\t0\n").noNewPrivs).toBe(false);
  });
});

describe("deviceRefusalAdvice", () => {
  it("names what is left once the probe has run, and how to tell the halves apart", () => {
    const advice = deviceRefusalAdvice(
      HELPER,
      `${HELPER}: failed to open /dev/fuse: Permission denied`,
    );
    expect(advice).toContain("nosuid");
    expect(advice).toContain("SELinux");
    expect(advice).toContain("device cgroup");
    expect(advice).toContain("sudo -n id");
  });

  it("does not blame the device's mode, which is not what libfuse checks", () => {
    const advice = deviceRefusalAdvice(
      HELPER,
      `${HELPER}: failed to open /dev/fuse: Permission denied`,
    );
    expect(advice).toContain("whatever the device's mode says");
    expect(advice).not.toContain("chmod 666");
  });

  it("also catches EPERM, which a device cgroup gives instead of EACCES", () => {
    const advice = deviceRefusalAdvice(
      HELPER,
      `${HELPER}: failed to open /dev/fuse: Operation not permitted`,
    );
    expect(advice).toBeDefined();
  });

  it("stays quiet for a failure that is about something else", () => {
    expect(
      deviceRefusalAdvice(HELPER, `${HELPER}: option allow_other only allowed if...`),
    ).toBeUndefined();
    expect(deviceRefusalAdvice(HELPER, `${HELPER}: mountpoint is not empty`)).toBeUndefined();
  });

  it("stays quiet for a permission error that is not about the device", () => {
    expect(
      deviceRefusalAdvice(HELPER, `${HELPER}: user has no write access to mountpoint`),
    ).toBeUndefined();
  });
});
