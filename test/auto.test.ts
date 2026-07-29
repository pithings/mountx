/**
 * Tier 0: what `mountx/auto` decides, and what it refuses to decide.
 *
 * Nothing here mounts anything — `test/auto-mount.test.ts` does that. This is
 * the choice itself: the preference order per host, the reasons a transport is
 * ruled out, and the named-transport paths that must *not* consult the probe
 * at all.
 *
 * The `platform` override is what makes it a Tier-0 suite instead of a
 * host-dependent one: darwin and win32 are answered from any host, and only
 * the assertions about *this* host's real capabilities are gated.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { type P9ClientProbe, p9ClientProbe } from "../src/9p/probe.ts";
import {
  type AutoMountOptions,
  liveMounts,
  mount,
  p9ModuleRefusal,
  probeTransports,
  unmountAll,
} from "../src/auto.ts";
import { createMemoryDriver } from "../src/drivers/memory.ts";

const here = await probeTransports();

describe("probeTransports", () => {
  it("prefers FUSE, then 9P, then NFS on Linux — and NFS everywhere else", async () => {
    // FUSE first because it is the only one that mounts without root; 9P ahead
    // of NFS because when both need root anyway, stateful beats stateless.
    expect((await probeTransports("linux")).preference).toEqual(["fuse", "9p", "nfs"]);
    // Off Linux only NFS can work, so it leads and the tail decides nothing.
    expect((await probeTransports("darwin")).preference).toEqual(["nfs", "fuse", "9p"]);
    expect((await probeTransports("win32")).preference).toEqual(["nfs", "fuse", "9p"]);
  });

  it("rules FUSE out on macOS for the right reason", async () => {
    const probe = await probeTransports("darwin");
    expect(probe.fuse.usable).toBe(false);
    // Not "needs Linux" and nothing else: someone reading this has macFUSE
    // installed and is entitled to know why it does not help.
    expect(probe.fuse.reason).toContain("macFUSE");
    expect(probe.chosen).not.toBe("fuse");
  });

  it("rules 9P out on macOS for the right reason", async () => {
    const probe = await probeTransports("darwin");
    expect(probe["9p"].usable).toBe(false);
    // The whole answer: no other kernel has a client, so there is nothing to
    // install and nothing to try.
    expect(probe["9p"].reason).toContain("darwin");
    expect(probe["9p"].reason).toContain("v9fs");
    expect(probe.chosen).not.toBe("9p");
  });

  it("delegates the 9P question to `p9ClientProbe`, and adds only the module refusal", () => {
    // Same probe `mountx/9p` publishes, not a second opinion — which is what
    // makes "9P needs Linux, root and a 9p filesystem" one fact in one file.
    // The one thing this layer adds on top is `p9ModuleRefusal`, below.
    const direct = p9ClientProbe();
    const refusal = p9ModuleRefusal(direct);
    expect(here["9p"].usable).toBe(direct.usable && refusal === undefined);
    expect(here["9p"].reason).toBe(direct.usable ? refusal : direct.reason);
  });

  it("rules all three out on a host that is none of them", async () => {
    const probe = await probeTransports("win32");
    expect(probe.chosen).toBeUndefined();
    expect(probe.fuse.usable).toBe(false);
    expect(probe["9p"].usable).toBe(false);
    expect(probe.nfs.usable).toBe(false);
    // One sentence naming all three, rather than whichever failed last.
    expect(probe.reason).toContain("FUSE:");
    expect(probe.reason).toContain("9P:");
    expect(probe.reason).toContain("NFS:");
    expect(probe.reason).toContain("win32");
  });

  it("always pairs usability with a reason, and a choice with a usable transport", () => {
    for (const probe of [here.fuse, here["9p"], here.nfs]) {
      expect(probe.usable).toBe(probe.reason === undefined);
    }
    expect(here.platform).toBe(process.platform);
    if (here.chosen === undefined) {
      expect(here.reason).toBeTruthy();
    } else {
      expect(here.reason).toBeUndefined();
      expect(here[here.chosen].usable).toBe(true);
      // The choice is the first usable one in preference order, not any usable one.
      expect(here.preference.find((transport) => here[transport].usable)).toBe(here.chosen);
    }
  });
});

describe("p9ModuleRefusal", () => {
  /** A host `p9ClientProbe` would call usable, minus whatever is overridden. */
  function probe(overrides: Partial<P9ClientProbe> = {}): P9ClientProbe {
    return {
      usable: true,
      platform: "linux",
      kernel: true,
      transport: true,
      modules: true,
      root: true,
      reason: undefined,
      ...overrides,
    };
  }

  it("says nothing when 9pnet_fd is already loaded", () => {
    expect(p9ModuleRefusal(probe())).toBeUndefined();
  });

  it("says nothing when the module is absent but a module tree could supply it", () => {
    // Two ways this host comes good and one refusal would rule both out:
    // `mount(8)` runs as root and modprobes a filesystem it does not find, and
    // /sys/module is empty for code built into the kernel in the first place.
    expect(p9ModuleRefusal(probe({ transport: false }))).toBeUndefined();
  });

  it("rules 9P out when the module is neither loaded nor loadable", () => {
    // The virtio-only guest: `9p` in /proc/filesystems, nothing to mount
    // `trans=unix` with, and nowhere to get it from. Choosing 9P here would be
    // a hard failure under the no-fallback rule, on a host where NFS works.
    const refusal = p9ModuleRefusal(probe({ transport: false, modules: false }));
    expect(refusal).toContain("9pnet_fd");
    expect(refusal).toContain("trans=unix");
    // And it says so without taking the choice away from someone who asks.
    expect(refusal).toContain("--transport 9p");
  });

  it("adds nothing to a verdict that was already a refusal", () => {
    // It only ever refines a usable one: a probe that failed for a better
    // reason keeps it, and `probeTransports` reports that one instead.
    const refused = probe({
      usable: false,
      reason: "mounting 9P needs root",
      root: false,
      transport: false,
      modules: false,
    });
    expect(p9ModuleRefusal(refused)).toBeUndefined();
  });
});

describe("mount", () => {
  const directories: string[] = [];

  afterEach(async () => {
    for (const directory of directories.splice(0)) {
      await rm(directory, { recursive: true, force: true }).catch(() => {});
    }
  });

  async function mountpoint(): Promise<string> {
    const path = await mkdtemp(join(tmpdir(), "mountx-auto-"));
    directories.push(path);
    return path;
  }

  it.skipIf(here.chosen !== undefined)(
    "refuses with every transport's reason when nothing can mount",
    async () => {
      await expect(mount(createMemoryDriver(), await mountpoint())).rejects.toThrow(
        /no transport can mount on this host/,
      );
    },
  );

  it.skipIf(here.nfs.usable)("lets a named transport fail in its own words", async () => {
    // Not `no transport can mount on this host` — naming a transport skips the
    // probe, so the error is the NFS transport's own and says what NFS needs.
    await expect(
      mount(createMemoryDriver(), await mountpoint(), { transport: "nfs" }),
    ).rejects.toThrow(/cannot mount NFS here/);
  });

  // Gated on the TRANSPORT probe, not `here["9p"].usable`: auto's verdict is
  // strictly narrower (the 9pnet_fd refusal), and on a host where the two
  // diverge this test would otherwise reach a real `mount -t 9p` as root.
  it.skipIf(p9ClientProbe().usable)(
    "lets a named 9P transport fail in its own words too",
    async () => {
      // Also the one assertion that the `"9p"` escape hatch exists and is typed
      // as the 9P transport's own options: `mountMsize` is on no other one, so
      // this stops compiling if the key ever loses its type.
      const options: AutoMountOptions = { transport: "9p", "9p": { mountMsize: 64 * 1024 } };
      await expect(mount(createMemoryDriver(), await mountpoint(), options)).rejects.toThrow(
        /cannot mount 9P here/,
      );
    },
  );

  it.skipIf(process.platform === "linux")(
    "lets a named FUSE transport fail in its own words too",
    async () => {
      await expect(
        mount(createMemoryDriver(), await mountpoint(), { transport: "fuse" }),
      ).rejects.toThrow(/FUSE mounts need Linux/);
    },
  );
});

describe("liveMounts and unmountAll", () => {
  it("answer without loading a transport that was never used", async () => {
    // Both are safe to call in a process that has mounted nothing — which is
    // also the only way to assert that they load nothing.
    expect(await liveMounts()).toEqual([]);
    expect(await unmountAll()).toEqual([]);
  });
});
