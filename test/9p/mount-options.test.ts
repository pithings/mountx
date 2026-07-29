/**
 * Tier 0: the parts of `src/9p/mount.ts` that are a string, not a mount.
 *
 * `test/9p/mount.test.ts` needs Linux, root and a kernel with v9fs in it, so it
 * can only ever cover the host it runs on. Everything that is pure — the option
 * string, the mount-table format, the refusals, the probe's reasoning — is
 * checked here, from any host and with no privileges.
 *
 * The option assertions are transcriptions. Every one of them is a line in the
 * v6.12 sources named beside it: `net/9p/client.c` (`trans`, `version`,
 * `msize`), `net/9p/trans_fd.c` (`port`, `MAX_SOCK_BUF`, `UNIX_PATH_MAX`) and
 * `fs/9p/v9fs.c` (`access`, `cache`, `uname`, `aname`).
 */

import { describe, expect, it } from "vitest";
import {
  P9_DEFAULT_MOUNT_MSIZE,
  P9_MAX_MOUNT_MSIZE,
  P9_UNIX_PATH_MAX,
  p9ClientProbe,
  p9MountOptions,
  parseMountTable,
  socketPathRefusal,
  tcpSourceRefusal,
} from "../../src/9p/mount.ts";
import { P9_IOHDRSZ, P9_MIN_MSIZE } from "../../src/9p/constants.ts";

/** The option string as `key` → `value`, with valueless options mapped to `""`. */
function options(text: string): Map<string, string> {
  return new Map(
    text.split(",").map((part) => {
      const eq = part.indexOf("=");
      return eq === -1 ? [part, ""] : [part.slice(0, eq), part.slice(eq + 1)];
    }),
  );
}

describe("p9MountOptions", () => {
  it("names the transport, and the port only when there is one", () => {
    const unix = options(p9MountOptions({ trans: "unix" }));
    expect(unix.get("trans")).toBe("unix");
    // `port=` is `trans_fd.c`'s option and means nothing to a unix socket; the
    // kernel would take it, but saying it would be a lie about how it connects.
    expect(unix.has("port")).toBe(false);
    const tcp = options(p9MountOptions({ trans: "tcp", port: 45_123 }));
    expect(tcp.get("trans")).toBe("tcp");
    // Without it the kernel would use P9_PORT (564), which is never where an
    // ephemeral listener landed.
    expect(tcp.get("port")).toBe("45123");
  });

  it("asks for 9p2000.L — the mount spelling, not the wire one", () => {
    // `p9_get_protocol_version()` compares against "9p2000.L"; the string that
    // goes out in `Tversion` is "9P2000.L". Both capitalizations are real.
    expect(options(p9MountOptions({ trans: "unix" })).get("version")).toBe("9p2000.L");
    expect(p9MountOptions({ trans: "unix" })).not.toContain("9P2000.L");
  });

  it("proposes the kernel's own default msize", () => {
    // `DEFAULT_MSIZE` in net/9p/client.c is `(128 * 1024) + P9_IOHDRSZ`, and
    // the header term is what makes the *payload* a round 128 KiB.
    expect(P9_DEFAULT_MOUNT_MSIZE).toBe(128 * 1024 + P9_IOHDRSZ);
    expect(options(p9MountOptions({ trans: "unix" })).get("msize")).toBe(
      String(P9_DEFAULT_MOUNT_MSIZE),
    );
  });

  it("refuses a port the kernel would silently replace with 564", () => {
    // `trans_fd.c`'s `parse_opts()` `continue`s past an option it cannot parse
    // and leaves `opts.port` at `P9_PORT`, so a bad port does not fail the
    // mount — it mounts against the wrong one. Hence a throw, not a clamp.
    for (const port of [undefined, Number.NaN, Number.POSITIVE_INFINITY, -1, 0, 65_536, 1024.5]) {
      expect(() => p9MountOptions({ trans: "tcp", port })).toThrow(/integer in \[1, 65535\]/);
    }
    // The ends of the range are fine, and so is anything between.
    expect(options(p9MountOptions({ trans: "tcp", port: 1 })).get("port")).toBe("1");
    expect(options(p9MountOptions({ trans: "tcp", port: 65_535 })).get("port")).toBe("65535");
    // And a unix mount never asks, so a missing port is not its problem.
    expect(() => p9MountOptions({ trans: "unix" })).not.toThrow();
  });

  it("clamps msize to what the kernel would accept anyway", () => {
    // Below 4096 `p9_client_create()` fails the mount outright; above
    // MAX_SOCK_BUF it clamps and prints "Limiting 'msize'".
    expect(options(p9MountOptions({ trans: "unix" }, { mountMsize: 512 })).get("msize")).toBe(
      String(P9_MIN_MSIZE),
    );
    expect(
      options(p9MountOptions({ trans: "unix" }, { mountMsize: 64 * 1024 * 1024 })).get("msize"),
    ).toBe(String(P9_MAX_MOUNT_MSIZE));
    expect(P9_MAX_MOUNT_MSIZE).toBe(1024 * 1024);
    // `NaN` is a mistake rather than an extreme, so it takes the default; the
    // point is that a literal `msize=NaN` never reaches the option string,
    // where `match_int()` fails and the kernel silently keeps its own default.
    expect(
      options(p9MountOptions({ trans: "unix" }, { mountMsize: Number.NaN })).get("msize"),
    ).toBe(String(P9_DEFAULT_MOUNT_MSIZE));
    // The infinities clamp like any other out-of-range number.
    expect(
      options(p9MountOptions({ trans: "unix" }, { mountMsize: Number.POSITIVE_INFINITY })).get(
        "msize",
      ),
    ).toBe(String(P9_MAX_MOUNT_MSIZE));
    expect(
      options(p9MountOptions({ trans: "unix" }, { mountMsize: Number.NEGATIVE_INFINITY })).get(
        "msize",
      ),
    ).toBe(String(P9_MIN_MSIZE));
    expect(options(p9MountOptions({ trans: "unix" }, { mountMsize: 8193.7 })).get("msize")).toBe(
      "8193",
    );
    // Whatever goes in, what comes out is always a number the kernel's `%u`
    // will match, inside the range it will accept.
    for (const mountMsize of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1e30, 0.5]) {
      const emitted = options(p9MountOptions({ trans: "unix" }, { mountMsize })).get("msize")!;
      expect(emitted).toMatch(/^\d+$/);
      expect(Number(emitted)).toBeGreaterThanOrEqual(P9_MIN_MSIZE);
      expect(Number(emitted)).toBeLessThanOrEqual(P9_MAX_MOUNT_MSIZE);
    }
  });

  it("defaults to client-side permission checks and no caching", () => {
    const parsed = options(p9MountOptions({ trans: "unix" }));
    // v9fs's own default for 9P2000.L (`v9fs_session_init` sets
    // V9FS_ACCESS_CLIENT), and the posture the FUSE transport takes with
    // `default_permissions`: the kernel enforces the mode bits it was told.
    expect(parsed.get("access")).toBe("client");
    // 9P has no invalidation channel, so anything above `none` is a bet that
    // nothing but the mount changes the driver.
    expect(parsed.get("cache")).toBe("none");
  });

  it("spells out the attach identity the kernel would have defaulted to", () => {
    const parsed = options(p9MountOptions({ trans: "unix" }));
    // V9FS_DEFUSER in fs/9p/v9fs.h.
    expect(parsed.get("uname")).toBe("nobody");
    // The session serves its driver's root and accepts "" or "/" for it.
    expect(parsed.get("aname")).toBe("/");
  });

  it("takes overrides for all four", () => {
    const parsed = options(
      p9MountOptions(
        { trans: "unix" },
        { access: "user", cache: "loose", uname: "dev", aname: "" },
      ),
    );
    expect(parsed.get("access")).toBe("user");
    expect(parsed.get("cache")).toBe("loose");
    expect(parsed.get("uname")).toBe("dev");
    expect(parsed.get("aname")).toBe("");
  });

  it("adds ro only when asked", () => {
    expect(options(p9MountOptions({ trans: "unix" }, { readOnly: true })).has("ro")).toBe(true);
    expect(options(p9MountOptions({ trans: "unix" })).has("ro")).toBe(false);
  });

  it("appends caller options last, where the winning occurrence is", () => {
    const text = p9MountOptions({ trans: "unix" }, { mountOptions: ["cache=loose", "posixacl"] });
    expect(text.endsWith(",cache=loose,posixacl")).toBe(true);
    // Both spellings are present and the caller's is the later one: the
    // kernel's parsers take the last occurrence.
    expect(text.indexOf("cache=none")).toBeLessThan(text.lastIndexOf("cache=loose"));
  });

  it("refuses a comma or whitespace in anything that goes into the -o list", () => {
    // Not a quoting bug: a comma would silently add mount options to a command
    // running as root.
    for (const bad of [
      { uname: "a,b" },
      { aname: "/a,b" },
      { access: "cli ent" },
      { cache: "none,ro" },
    ]) {
      expect(() => p9MountOptions({ trans: "unix" }, bad)).toThrow(
        /may not contain a comma or whitespace/,
      );
    }
  });

  it("is the whole of what the kernel is told, byte for byte", () => {
    // A golden, so that anything leaking into the option list — a path, a
    // mountpoint, a stray default — has to be noticed rather than merely
    // appended. Note what is *absent*: the socket path and the mountpoint are
    // separate argv elements to `mount(8)`, which is why a comma in either is
    // harmless and why neither is an input to this function at all.
    const msize = P9_DEFAULT_MOUNT_MSIZE;
    expect(p9MountOptions({ trans: "unix" })).toBe(
      `trans=unix,version=9p2000.L,msize=${msize},access=client,cache=none,uname=nobody,aname=/`,
    );
    expect(p9MountOptions({ trans: "tcp", port: 5640 })).toBe(
      `trans=tcp,port=5640,version=9p2000.L,msize=${msize},access=client,cache=none,` +
        `uname=nobody,aname=/`,
    );
  });
});

describe("socketPathRefusal", () => {
  it("allows what the kernel allows", () => {
    expect(socketPathRefusal("/tmp/mountx-9p-abc123/9p.sock")).toBeUndefined();
    // `strlen(addr) >= UNIX_PATH_MAX` is the kernel's test, so the longest
    // acceptable path is one byte under.
    expect(socketPathRefusal("/".repeat(P9_UNIX_PATH_MAX - 1))).toBeUndefined();
  });

  it("refuses a path the kernel would answer ENAMETOOLONG for", () => {
    const refusal = socketPathRefusal("/".repeat(P9_UNIX_PATH_MAX));
    expect(refusal).toContain("UNIX_PATH_MAX");
    expect(refusal).toContain("TMPDIR");
    expect(P9_UNIX_PATH_MAX).toBe(108);
  });

  it("counts bytes, not characters", () => {
    // `sun_path` is a byte array; a path of 60 three-byte characters is 180 of
    // them, and a length check in UTF-16 units would have let it through.
    expect(socketPathRefusal(`/tmp/${"€".repeat(60)}`)).toBeDefined();
  });
});

describe("tcpSourceRefusal", () => {
  it("allows the dotted quads valid_ipaddr4() allows", () => {
    for (const address of ["127.0.0.1", "0.0.0.0", "10.1.2.3", "255.255.255.255", "127.1.2.3"]) {
      expect(tcpSourceRefusal(address)).toBeUndefined();
    }
  });

  it("refuses the two shapes that look fine and are not", () => {
    // `p9_fd_create_tcp()` hard-codes `AF_INET` and calls `in_aton()`, so IPv6
    // is not a thing it can express — and `::1` is a loopback address a caller
    // may well pass as `host`, which the *server* accepts, so this is the one
    // that would otherwise become "wrong fs type".
    for (const address of ["::1", "::ffff:127.0.0.1", "fe80::1"]) {
      expect(tcpSourceRefusal(address)).toContain("IPv6");
    }
    // And there is no resolver inside `valid_ipaddr4()`: a name is `EINVAL`.
    for (const address of ["localhost", "example.test", ""]) {
      expect(tcpSourceRefusal(address)).toContain("dotted-quad");
    }
  });

  it("refuses a near-miss quad", () => {
    // `valid_ipaddr4()` bounds each octet at 255 and wants four of them.
    for (const address of ["127.0.0", "127.0.0.256", "127.0.0.1.5", "127.0.0.x", " 127.0.0.1"]) {
      expect(tcpSourceRefusal(address)).toBeDefined();
    }
  });

  it("names the way out", () => {
    const refusal = tcpSourceRefusal("::1")!;
    expect(refusal).toContain("127.0.0.1");
    expect(refusal).toContain("unix socket");
  });
});

describe("parseMountTable", () => {
  it("reads /proc/self/mounts, escapes and all", () => {
    const table = [
      "proc /proc proc rw,relatime 0 0",
      "/tmp/mountx-9p-a/9p.sock /tmp/a\\040b 9p rw,trans=unix,version=9p2000.L 0 0",
      "",
    ].join("\n");
    expect(parseMountTable(table)).toEqual([
      { source: "proc", target: "/proc", type: "proc" },
      { source: "/tmp/mountx-9p-a/9p.sock", target: "/tmp/a b", type: "9p" },
    ]);
  });

  it("unescapes tab, newline and backslash too", () => {
    const table = "/s/9p.sock /tmp/a\\011b\\012c\\134d 9p rw 0 0";
    expect(parseMountTable(table)[0]?.target).toBe("/tmp/a\tb\nc\\d");
  });

  it("ignores lines that are not entries", () => {
    expect(parseMountTable("\n\n")).toEqual([]);
  });
});

describe("p9ClientProbe", () => {
  it("refuses a host that is not Linux", () => {
    for (const platform of ["darwin", "win32"] as const) {
      const probe = p9ClientProbe(platform);
      expect(probe.usable).toBe(false);
      expect(probe.platform).toBeUndefined();
      expect(probe.reason).toContain(platform);
      // No other kernel has a v9fs client, so there is no second platform to
      // narrow to the way the NFS probe narrows to darwin.
      expect(probe.reason).toContain("Linux only");
    }
  });

  it("asks for root, and says why", () => {
    const probe = p9ClientProbe("linux");
    if ((process.getuid?.() ?? -1) === 0) {
      expect(probe.reason ?? "").not.toContain("needs root");
    } else {
      expect(probe.reason).toContain("CAP_SYS_ADMIN");
      expect(probe.usable).toBe(false);
    }
  });

  it("answers with booleans and never throws", () => {
    const probe = p9ClientProbe();
    expect(typeof probe.usable).toBe("boolean");
    expect(typeof probe.kernel).toBe("boolean");
    expect(typeof probe.transport).toBe("boolean");
    expect(typeof probe.modules).toBe("boolean");
    expect(typeof probe.root).toBe("boolean");
    // Usable and a reason are exclusive: one of them is always the answer.
    expect(probe.usable).toBe(probe.reason === undefined);
  });

  it("tells a missing module apart from a host that could never load one", () => {
    const probe = p9ClientProbe();
    if (process.platform !== "linux" || probe.kernel) {
      return;
    }
    // The distinction the reason has to make: `modprobe 9p` is advice on a
    // host with a module tree and a waste of an afternoon on one without.
    expect(probe.reason).toContain(probe.modules ? "modprobe 9p" : "no module tree");
  });

  it("does not refuse a host merely for having no 9pnet_fd in /sys/module", () => {
    // The transport module is reported, not required: it is invisible when
    // built into the kernel, and root may yet have it loaded by the time
    // `mount(8)` runs. `mount9p()` names it on the failure path instead.
    const probe = p9ClientProbe();
    expect(probe.reason ?? "").not.toContain("9pnet_fd");
  });
});
