/**
 * Tier 0: the parts of `mount.ts` that are a platform difference, not a mount.
 *
 * `test/nfs/mount.test.ts` needs root, an NFS client and a host to mount on,
 * so it can only ever cover the host it runs on. Everything a *second* host
 * changes — the option string, the mount-table format, what the probe looks
 * for — is pure, and is checked here from either.
 *
 * The option assertions are transcriptions: each one is a line in Linux's
 * `nfs(5)` or Apple's `mount_nfs(8)`/`mount(8)`, and the two that are absences
 * (`hard` and `nolock` are Linux spellings; macOS has `nolocks` and no `hard`
 * at all) are the reason this file exists.
 */

import { describe, expect, it } from "vitest";
import { nfsClientProbe, nfsMountOptions, parseMountTable } from "../../src/nfs/mount.ts";

/** The option string as `key` → `value`, with valueless options mapped to `""`. */
function options(text: string): Map<string, string> {
  return new Map(
    text.split(",").map((part) => {
      const eq = part.indexOf("=");
      return eq === -1 ? [part, ""] : [part.slice(0, eq), part.slice(eq + 1)];
    }),
  );
}

describe("nfsMountOptions", () => {
  it("puts both programs on one port so no portmapper is needed", () => {
    for (const platform of ["linux", "darwin"] as const) {
      const parsed = options(nfsMountOptions(2049, {}, platform));
      expect(parsed.get("port")).toBe("2049");
      expect(parsed.get("mountport")).toBe("2049");
      expect(parsed.get("vers")).toBe("3");
      expect(parsed.get("proto")).toBe("tcp");
    }
  });

  it("defaults to a soft mount with the same timings on both hosts", () => {
    for (const platform of ["linux", "darwin"] as const) {
      const parsed = options(nfsMountOptions(1, {}, platform));
      expect(parsed.has("soft")).toBe(true);
      expect(parsed.has("hard")).toBe(false);
      // Both man pages document `timeo` in tenths of a second.
      expect(parsed.get("timeo")).toBe("50");
      expect(parsed.get("retrans")).toBe("2");
    }
  });

  it("spells the lock-free option the way each host does", () => {
    expect(options(nfsMountOptions(1, {}, "linux")).has("nolock")).toBe(true);
    expect(options(nfsMountOptions(1, {}, "darwin")).has("nolocks")).toBe(true);
    // Not the other one: an unknown option fails the mount outright.
    expect(options(nfsMountOptions(1, {}, "linux")).has("nolocks")).toBe(false);
    expect(options(nfsMountOptions(1, {}, "darwin")).has("nolock")).toBe(false);
  });

  it("asks for a hard mount by name on Linux and by silence on macOS", () => {
    const linux = options(nfsMountOptions(1, { hard: true }, "linux"));
    expect(linux.has("hard")).toBe(true);
    expect(linux.has("soft")).toBe(false);
    // macOS `mount_nfs(8)` documents `soft` and no counterpart, so the hard
    // mount is the default and `hard` would be an unknown option.
    const darwin = options(nfsMountOptions(1, { hard: true }, "darwin"));
    expect(darwin.has("hard")).toBe(false);
    expect(darwin.has("soft")).toBe(false);
  });

  it("hides the volume from the macOS GUI unless asked not to", () => {
    expect(options(nfsMountOptions(1, {}, "darwin")).has("nobrowse")).toBe(true);
    expect(options(nfsMountOptions(1, { nobrowse: false }, "darwin")).has("nobrowse")).toBe(false);
    // `nobrowse` is a macOS `mount(8)` option; Linux would reject it.
    expect(options(nfsMountOptions(1, {}, "linux")).has("nobrowse")).toBe(false);
    expect(options(nfsMountOptions(1, { nobrowse: true }, "linux")).has("nobrowse")).toBe(false);
  });

  it("appends caller options last, where the winning occurrence is", () => {
    for (const platform of ["linux", "darwin"] as const) {
      const text = nfsMountOptions(1, { mountOptions: ["rsize=131072", "hard"] }, platform);
      expect(text.endsWith(",rsize=131072,hard")).toBe(true);
      expect(text.indexOf("soft")).toBeLessThan(text.lastIndexOf("hard"));
    }
  });

  it("adds ro only when asked", () => {
    expect(options(nfsMountOptions(1, { readOnly: true }, "linux")).has("ro")).toBe(true);
    expect(options(nfsMountOptions(1, {}, "linux")).has("ro")).toBe(false);
  });

  it("never emits a non-numeric timeo or retrans", () => {
    const parsed = options(
      nfsMountOptions(1, { timeo: Number.NaN, retrans: Number.POSITIVE_INFINITY }, "darwin"),
    );
    expect(parsed.get("timeo")).toBe("50");
    expect(parsed.get("retrans")).toBe("2");
    // And a value below the floor is raised, not passed through.
    expect(options(nfsMountOptions(1, { timeo: 0 }, "linux")).get("timeo")).toBe("1");
    expect(options(nfsMountOptions(1, { timeo: 3.9 }, "linux")).get("timeo")).toBe("3");
  });
});

describe("parseMountTable", () => {
  it("reads /proc/self/mounts, escapes and all", () => {
    const table = [
      "proc /proc proc rw,relatime 0 0",
      "127.0.0.1:/ /tmp/a\\040b nfs rw,vers=3 0 0",
      "",
    ].join("\n");
    expect(parseMountTable("linux", table)).toEqual([
      { source: "proc", target: "/proc", type: "proc" },
      { source: "127.0.0.1:/", target: "/tmp/a b", type: "nfs" },
    ]);
  });

  it("unescapes tab, newline and backslash too", () => {
    const table = "127.0.0.1:/ /tmp/a\\011b\\012c\\134d nfs rw 0 0";
    expect(parseMountTable("linux", table)[0]?.target).toBe("/tmp/a\tb\nc\\d");
  });

  it("reads macOS mount(8) prose", () => {
    const table = [
      "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)",
      "devfs on /dev (devfs, local, nobrowse)",
      "127.0.0.1:/ on /private/var/folders/x/mountx (nfs, nodev, nosuid, mounted by dev)",
      "",
    ].join("\n");
    expect(parseMountTable("darwin", table)).toEqual([
      { source: "/dev/disk3s1s1", target: "/", type: "apfs" },
      { source: "devfs", target: "/dev", type: "devfs" },
      {
        source: "127.0.0.1:/",
        target: "/private/var/folders/x/mountx",
        type: "nfs",
      },
    ]);
  });

  it("takes the longest source when a path contains the separator", () => {
    const table = "127.0.0.1:/ on /tmp/on on /tmp/what (nfs, nodev)";
    expect(parseMountTable("darwin", table)[0]).toEqual({
      source: "127.0.0.1:/ on /tmp/on",
      target: "/tmp/what",
      type: "nfs",
    });
  });

  it("ignores lines that are not entries", () => {
    expect(parseMountTable("darwin", "\nmount: something went wrong\n")).toEqual([]);
    expect(parseMountTable("linux", "\n\n")).toEqual([]);
  });
});

describe("nfsClientProbe", () => {
  it("refuses a host that is neither Linux nor macOS", () => {
    const probe = nfsClientProbe("win32");
    expect(probe.usable).toBe(false);
    expect(probe.platform).toBeUndefined();
    expect(probe.helper).toBeUndefined();
    expect(probe.reason).toContain("win32");
  });

  it("looks for the helper each host actually ships", () => {
    // Whichever host this runs on, the *other* one's helper is not here, and
    // the message names the file rather than the flavour of NFS.
    const elsewhere = process.platform === "darwin" ? "linux" : "darwin";
    const probe = nfsClientProbe(elsewhere);
    expect(probe.usable).toBe(false);
    expect(probe.platform).toBe(elsewhere);
    expect(probe.reason).toContain(elsewhere === "darwin" ? "/sbin/mount_nfs" : "/sbin/mount.nfs");
  });

  it("says root is missing when it is", () => {
    const probe = nfsClientProbe();
    if ((process.getuid?.() ?? -1) === 0) {
      expect(probe.reason ?? "").not.toContain("needs root");
      return;
    }
    expect(probe.usable).toBe(false);
    expect(probe.reason).toContain("needs root");
  });
});
