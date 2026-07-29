/**
 * Tier 0: what `mountx/exec` decides, and what it refuses to decide.
 *
 * Nothing here runs a command — `test/exec/userns.test.ts` does that. This is
 * the choice itself: the preference order, the reasons the mechanism is ruled
 * out, and the named-mechanism path that must *not* consult the picker's probe
 * at all.
 *
 * The `platform` override is what makes it a Tier-0 suite instead of a
 * host-dependent one: darwin and win32 are answered from any host, and only the
 * assertions about *this* host's real capabilities are gated.
 */

import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { exec, probeExec } from "../../src/exec/index.ts";
import { usernsExecProbe } from "../../src/exec/probe.ts";
import { cwdRefusal, usernsIdMap } from "../../src/exec/userns.ts";

const here = probeExec();

describe("probeExec", () => {
  it("has one preference order, on every host", () => {
    // One mechanism today, and the order is the seam a second arrives through
    // rather than a decision being made now: off Linux nothing here can work,
    // so there is no second order to have either way.
    expect(here.preference).toEqual(["userns"]);
    expect(probeExec("darwin").preference).toEqual(["userns"]);
  });

  it("rules the user namespace out on macOS, in its own words", () => {
    const probe = probeExec("darwin");
    expect(probe.chosen).toBeUndefined();
    expect(probe.userns.usable).toBe(false);
    // Not a bare "needs Linux": a reader on macOS is entitled to know that
    // macFUSE does not help either.
    expect(probe.userns.reason).toContain("macFUSE");
    // The picker's own sentence names the mechanism it asked, so it still reads
    // correctly once there is more than one to name.
    expect(probe.reason).toContain("user namespace:");
    expect(probe.reason).toContain("darwin");
  });

  it("rules it out on Windows too", () => {
    const probe = probeExec("win32");
    expect(probe.chosen).toBeUndefined();
    expect(probe.reason).toContain("win32");
  });

  it("always pairs usability with a reason, and a choice with a usable mechanism", () => {
    expect(here.userns.usable).toBe(here.userns.reason === undefined);
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

  it("delegates the question to the mechanism's own probe rather than re-deciding", () => {
    // The same probe `src/exec/probe.ts` publishes, not a second opinion — which
    // is what keeps "what does the user-namespace mechanism need" one fact in
    // one file.
    expect(here.userns).toEqual(usernsExecProbe());
  });

  it("names the missing piece rather than one errno", () => {
    // Whatever this host is, an unusable verdict has to be a sentence somebody
    // can act on: a sysctl to raise, a device to pass in, a package to install.
    if (here.userns.usable) {
      expect(here.userns.reason).toBeUndefined();
      return;
    }
    expect(here.userns.reason).toMatch(/dev\/fuse|namespace|unshare|CONFIG_FUSE_FS|Linux/);
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
    expect(usernsExecProbe("linux").reason).toContain("not Linux");
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

describe("usernsIdMap", () => {
  const map = usernsIdMap(1000, 2000);

  it("answers 0 for every driver-side id, because that is the whole id space", () => {
    // `unshare -r` maps one uid and one gid, both 0. Anything else on the wire
    // is `INVALID_UID` to the kernel, and an inode carrying one cannot be
    // unlinked, renamed, linked or opened for writing — the VFS refuses in
    // `may_delete()`/`may_linkat()` (`EOVERFLOW`) and `inode_permission()`
    // (`EACCES`) without ever asking the server. So the invoking user's own id
    // is not a special case: there is nowhere else for any id to go.
    expect(map.toMount(1000, false)).toBe(0);
    expect(map.toMount(2000, true)).toBe(0);
    expect(map.toMount(0, false)).toBe(0);
    // Including the one the kernel itself would have picked for an unmapped id:
    // `nobody` is unmapped in here too, so answering it reinstates the bug.
    expect(map.toMount(65_534, false)).toBe(0);
    expect(map.toMount(65_534, true)).toBe(0);
  });

  it("reads 0 back as the invoking user, uid and gid told apart", () => {
    // Which is what lets the session see the command as the process it already
    // is, and leave the files it creates owned by whoever ran mountx.
    expect(map.fromMount(0, false)).toBe(1000);
    expect(map.fromMount(0, true)).toBe(2000);
  });

  it("is total, and leaves an id it does not know alone", () => {
    // Nothing can produce one — `chown_common()` rejects an unmapped id with
    // `EINVAL` before FUSE is consulted — but the map still sits on the encode
    // path of every reply and may not throw.
    expect(map.fromMount(4242, false)).toBe(4242);
    expect(map.fromMount(65_534, true)).toBe(65_534);
  });
});

describe("exec", () => {
  it("needs a command", async () => {
    await expect(exec(createMemoryDriver(), [])).rejects.toThrow(/needs a command to run/);
  });

  it.skipIf(here.chosen !== undefined)(
    "refuses with the mechanism's reason when nothing can run",
    async () => {
      await expect(exec(createMemoryDriver(), ["true"])).rejects.toThrow(
        /no mechanism can run a command with a driver on this host/,
      );
    },
  );

  it.skipIf(here.userns.usable)("lets a named mechanism fail in its own words", async () => {
    // The assertion is the *absence* of the picker's sentence: naming a
    // mechanism skips the picker's probe, so whatever comes back is the
    // mechanism's own and is more specific than anything `probeExec` could say.
    await expect(exec(createMemoryDriver(), ["true"], { mechanism: "userns" })).rejects.toThrow(
      /cannot run a command in a user namespace here/,
    );
  });
});
