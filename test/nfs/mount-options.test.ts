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
import {
  consentAdvice,
  isConsentDenial,
  nfsClientProbe,
  nfsMountOptions,
  ownershipRefusal,
  parseMountTable,
  versionRefusal,
} from "../../src/nfs/mount.ts";

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

describe("nfsMountOptions, version 4.1", () => {
  it("emits exactly the v4.1 option string, in order", () => {
    // Pinned whole rather than field by field: the option string is the entire
    // interface to `mount(8)`, and an option appearing where it should not is
    // as much of a bug as one missing.
    expect(nfsMountOptions(20_490, { version: "4.1" }, "linux")).toBe(
      "vers=4.1,proto=tcp,port=20490,soft,timeo=50,retrans=2",
    );
  });

  it("leaves out the two options nfs(5) marks version-2-and-3-only", () => {
    const parsed = options(nfsMountOptions(2049, { version: "4.1" }, "linux"));
    // No MOUNT program in v4, so nothing to point a `mountport` at.
    expect(parsed.has("mountport")).toBe(false);
    // NLM is folded into v4, so `nolock` is not an option there.
    expect(parsed.has("nolock")).toBe(false);
    expect(parsed.has("nolocks")).toBe(false);
    // `port` still matters: the server is on an ephemeral one, not 2049.
    expect(parsed.get("port")).toBe("2049");
    expect(parsed.get("vers")).toBe("4.1");
  });

  it("does not send clientaddr, which mount(8) discovers and nothing here uses", () => {
    // `nfs(5)`: with the option absent the mount command finds the callback
    // address itself. This server originates no callback at all — no
    // delegations, no pNFS, no backchannel asked for — and hard-coding the
    // loopback address would be wrong for any other `host`.
    expect(options(nfsMountOptions(1, { version: "4.1" }, "linux")).has("clientaddr")).toBe(false);
  });

  it("keeps the options every version shares, and the caller's, in the v4 branch", () => {
    const parsed = options(
      nfsMountOptions(
        1,
        { version: "4.1", hard: true, timeo: 7, retrans: 0, readOnly: true },
        "linux",
      ),
    );
    expect(parsed.has("hard")).toBe(true);
    expect(parsed.has("soft")).toBe(false);
    expect(parsed.get("timeo")).toBe("7");
    expect(parsed.get("retrans")).toBe("0");
    expect(parsed.has("ro")).toBe(true);
    const text = nfsMountOptions(1, { version: "4.1", mountOptions: ["nconnect=2"] }, "linux");
    expect(text.endsWith(",nconnect=2")).toBe(true);
  });

  it("refuses to build a macOS v4.1 mount at all", () => {
    expect(() => nfsMountOptions(1, { version: "4.1" }, "darwin")).toThrow(/Linux-only/);
  });

  it("leaves version 3 exactly as it was, however it is spelled", () => {
    // The default and the explicit `3` are the same string, and it is the one
    // the assertions above this block already pin.
    for (const platform of ["linux", "darwin"] as const) {
      expect(nfsMountOptions(2049, { version: 3 }, platform)).toBe(
        nfsMountOptions(2049, {}, platform),
      );
    }
    expect(nfsMountOptions(2049, {}, "linux")).toBe(
      "vers=3,proto=tcp,port=2049,mountport=2049,nolock,soft,timeo=50,retrans=2",
    );
    expect(nfsMountOptions(2049, {}, "darwin")).toBe(
      "vers=3,proto=tcp,port=2049,mountport=2049,nolocks,soft,timeo=50,retrans=2,nobrowse",
    );
  });
});

describe("versionRefusal", () => {
  it("refuses 4.1 on macOS, naming what is assumed rather than the error", () => {
    const refusal = versionRefusal("darwin", "4.1");
    // A1: macOS is treated as 4.0-only until somebody verifies otherwise, and
    // 4.1 is the only minor version this server speaks.
    expect(refusal).toContain("4.0-only");
    expect(refusal).toContain("version: 3");
  });

  it("allows everything else, including the default", () => {
    expect(versionRefusal("linux", "4.1")).toBeUndefined();
    expect(versionRefusal("darwin", 3)).toBeUndefined();
    expect(versionRefusal("darwin")).toBeUndefined();
    expect(versionRefusal("linux")).toBeUndefined();
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

  it("reads a vers=4.1 mount, which Linux lists under its own filesystem type", () => {
    // The one mount-table difference version 4 makes: `mount -t nfs -o
    // vers=4.1` produces an entry of type `nfs4`, because Linux registers the
    // version-4 client as a separate filesystem. Nothing in `mount.ts` matches
    // on the type — teardown asks about the mountpoint — and this is what a
    // consumer that starts to would have to cover.
    const table = "127.0.0.1:/ /tmp/mountx nfs4 rw,vers=4.1,soft,proto=tcp 0 0";
    expect(parseMountTable("linux", table)).toEqual([
      { source: "127.0.0.1:/", target: "/tmp/mountx", type: "nfs4" },
    ]);
    // And the prefix the CLI's stale-mount cleanup matches on still covers it.
    expect(parseMountTable("linux", table)[0]!.type.startsWith("nfs")).toBe(true);
  });

  it("ignores lines that are not entries", () => {
    expect(parseMountTable("darwin", "\nmount: something went wrong\n")).toEqual([]);
    expect(parseMountTable("linux", "\n\n")).toEqual([]);
  });
});

describe("isConsentDenial", () => {
  // The exact line `umount(8)` prints when macOS refuses at the consent gate,
  // observed on 26.6 with the mount still listed afterwards.
  const refusal = "umount: unmount(/private/tmp/mountx/mnt): Operation not permitted";

  it("recognizes macOS refusing a network volume", () => {
    expect(isConsentDenial("darwin", refusal)).toBe(true);
  });

  it("is macOS-only: the same words mean something else on Linux", () => {
    // Linux prints `EPERM` when a non-root caller tries to unmount at all,
    // which is a different problem with a different fix.
    expect(isConsentDenial("linux", refusal)).toBe(false);
  });

  it("does not claim a busy mountpoint is a consent problem", () => {
    expect(isConsentDenial("darwin", "umount: unmount(/mnt): Resource busy")).toBe(false);
    expect(isConsentDenial("darwin", "")).toBe(false);
  });
});

describe("consentAdvice", () => {
  it("names the grant, not a command that fails the same way", () => {
    const advice = consentAdvice("/private/tmp/mountx/mnt");
    expect(advice).toContain("Full Disk Access");
    // The whole point: `umount -f` is not the way out of this one, and the
    // advice has to say so rather than recommend it.
    expect(advice).toContain("fails the same way");
    expect(advice).toContain("/private/tmp/mountx/mnt");
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

  it("asks for root on Linux and not on macOS", () => {
    // `/sbin/mount_nfs` is not setuid and needs none: macOS is a BSD, and a BSD
    // lets an ordinary user mount onto a directory that user owns. Asking for
    // root there would refuse a mount the host would have allowed.
    expect(nfsClientProbe("darwin").reason ?? "").not.toContain("needs root");
    const linux = nfsClientProbe("linux").reason ?? "";
    if ((process.getuid?.() ?? -1) === 0) {
      expect(linux).not.toContain("needs root");
    } else {
      // Linux's unprivileged mount needs an `fstab` entry marked `user`, which
      // is not something a library can arrange, so the requirement is real.
      expect(linux).toContain("needs root");
    }
  });

  it("answers the v4 question separately, and only Linux can answer yes", () => {
    // A1 again: macOS is treated as 4.0-only, so the field is false there
    // whatever the host running this is, and the v3 path is untouched by it.
    expect(nfsClientProbe("darwin").v4).toBe(false);
    expect(nfsClientProbe("win32").v4).toBe(false);
    // On Linux it is a fact about the *host*, not about this process: a
    // non-root run reports `usable: false` and still says whether the client is
    // there. Off Linux the file it reads does not exist, so the answer is
    // `false` rather than a thrown `ENOENT`.
    const linux = nfsClientProbe("linux");
    expect(typeof linux.v4).toBe("boolean");
    // The one implication that holds on every host: the helper loads whichever
    // module a `vers=` asks for, so having it is enough — the same escape
    // hatch `kernel`'s weakness note describes.
    if (linux.helper !== undefined) {
      expect(linux.v4).toBe(true);
    }
  });
});

describe("ownershipRefusal", () => {
  it("refuses a mountpoint an unprivileged macOS caller does not own", () => {
    const refusal = ownershipRefusal("darwin", "/private/tmp/theirs", 0, 501);
    expect(refusal).toContain("/private/tmp/theirs");
    // Both uids, because "permission denied" without them is the message the
    // host already gave and the reason this function exists.
    expect(refusal).toContain("uid 0");
    expect(refusal).toContain("uid 501");
  });

  it("allows what the host allows", () => {
    // Owned by the caller, root (who may mount anywhere), and Linux — where an
    // unprivileged caller never gets this far, the probe having refused first.
    expect(ownershipRefusal("darwin", "/mine", 501, 501)).toBeUndefined();
    expect(ownershipRefusal("darwin", "/theirs", 501, 0)).toBeUndefined();
    expect(ownershipRefusal("linux", "/theirs", 0, 501)).toBeUndefined();
  });
});
