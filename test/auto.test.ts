/**
 * Tier 0: what `mountx/auto` decides, and what it refuses to decide.
 *
 * Nothing here mounts anything — `test/auto-mount.test.ts` does that. This is
 * the choice itself: the preference order per host, the reasons a transport is
 * ruled out, and the two paths that must *not* consult the probe at all.
 *
 * The `platform` override is what makes it a Tier-0 suite instead of a
 * host-dependent one: darwin and win32 are answered from any host, and only
 * the assertions about *this* host's real capabilities are gated.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { liveMounts, mount, probeTransports, unmountAll } from "../src/auto.ts";
import { createMemoryDriver } from "../src/drivers/memory.ts";

const here = await probeTransports();

describe("probeTransports", () => {
  it("prefers FUSE on Linux and NFS everywhere else", async () => {
    expect((await probeTransports("linux")).preference).toEqual(["fuse", "nfs"]);
    expect((await probeTransports("darwin")).preference).toEqual(["nfs", "fuse"]);
    expect((await probeTransports("win32")).preference).toEqual(["nfs", "fuse"]);
  });

  it("rules FUSE out on macOS for the right reason", async () => {
    const probe = await probeTransports("darwin");
    expect(probe.fuse.usable).toBe(false);
    // Not "needs Linux" and nothing else: someone reading this has macFUSE
    // installed and is entitled to know why it does not help.
    expect(probe.fuse.reason).toContain("macFUSE");
    expect(probe.chosen).not.toBe("fuse");
  });

  it("rules both out on a host that is neither", async () => {
    const probe = await probeTransports("win32");
    expect(probe.chosen).toBeUndefined();
    expect(probe.fuse.usable).toBe(false);
    expect(probe.nfs.usable).toBe(false);
    // One sentence naming both, rather than whichever failed last.
    expect(probe.reason).toContain("FUSE:");
    expect(probe.reason).toContain("NFS:");
    expect(probe.reason).toContain("win32");
  });

  it("always pairs usability with a reason, and a choice with a usable transport", () => {
    for (const probe of [here.fuse, here.nfs]) {
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
    "refuses with both reasons when nothing can mount",
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
