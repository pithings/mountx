/**
 * Can this host mount 9P, and if not, which piece is missing?
 *
 * Split out of `mount.ts` for the reason `src/nfs/probe.ts` is: a probe should
 * cost nothing to ask. `mount.ts` pulls in the server, and the server pulls in
 * the session and the whole 9P2000.L codec behind it — a lot of module graph to
 * answer a question that reads two files and a uid. `mountx/auto` asks it before
 * deciding which transport to load, so this file imports `node:fs` and nothing
 * else. (`node:os` is not imported either: the kernel release comes from
 * `/proc/sys/kernel/osrelease`, which is the same string `uname -r` prints.)
 *
 * `mount.ts` re-exports everything here, so `mountx/9p` is one import either way.
 *
 * **Linux only, and root.** v9fs is a Linux filesystem; no other kernel has a
 * 9P client at all, so unlike NFS there is no second platform to narrow to.
 * Root is not a policy choice either: `mount(2)` needs `CAP_SYS_ADMIN` and 9P
 * has no setuid helper the way FUSE has `fusermount3`.
 */

import * as fs from "node:fs";

/** The one host that has a 9P client. */
export type P9Platform = "linux";

/** `process.platform`, narrowed to the host that can mount, or `undefined`. */
export function p9Platform(platform: NodeJS.Platform): P9Platform | undefined {
  return platform === "linux" ? "linux" : undefined;
}

/** What this host can and cannot do about mounting 9P. */
export interface P9ClientProbe {
  /** Can a 9P filesystem be mounted here at all? */
  usable: boolean;
  /** `"linux"`, or `undefined` on a host with no v9fs. */
  platform: P9Platform | undefined;
  /** Is `9p` listed in `/proc/filesystems`? */
  kernel: boolean;
  /**
   * Is `9pnet_fd` — the module providing `trans=unix`, `trans=tcp` and
   * `trans=fd` — visible in `/sys/module`?
   *
   * Deliberately **not** part of {@link P9ClientProbe.usable}: see the note on
   * {@link p9ClientProbe}.
   */
  transport: boolean;
  /** Is there a module tree for this kernel to load anything from? */
  modules: boolean;
  /** Are we root? Always required — `mount(2)` needs `CAP_SYS_ADMIN`. */
  root: boolean;
  /** Everything that is missing, in a sentence. */
  reason: string | undefined;
}

/** The kernel release, the way `uname -r` prints it, or `undefined`. */
function kernelRelease(): string | undefined {
  try {
    return fs.readFileSync("/proc/sys/kernel/osrelease", "utf8").trim() || undefined;
    /* v8 ignore next 3 -- no procfs on a Linux host is stranger than a missing module. */
  } catch {
    return undefined;
  }
}

/** Is `name` one of the filesystems the kernel knows, per `/proc/filesystems`? */
function hasFilesystem(name: string): boolean {
  let table: string;
  try {
    table = fs.readFileSync("/proc/filesystems", "utf8");
  } catch {
    return false;
  }
  // Each line is `nodev\t9p` or `\text4`: the filesystem name is the last
  // whitespace-separated field, and matching it exactly is what keeps `9p` from
  // being found inside `9pnet` or some future `9p2`.
  return table.split("\n").some((line) => line.trim().split(/\s+/).pop() === name);
}

/** Does `path` exist? */
function exists(path: string): boolean {
  try {
    fs.accessSync(path, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

/** Is there a module tree for `release`, with anything in it? */
function hasModuleTree(release: string | undefined): boolean {
  if (release === undefined) {
    return false;
  }
  try {
    return fs.readdirSync(`/lib/modules/${release}`).length > 0;
  } catch {
    return false;
  }
}

/**
 * Can this host mount 9P?
 *
 * Synchronous and cheap, so a test can gate itself on it and a mount can fail
 * with a message that names the missing piece instead of `mount: wrong fs type,
 * bad option, bad superblock`, which is what the kernel says for every one of
 * these causes at once.
 *
 * **What makes it usable:** Linux, root, and `9p` in `/proc/filesystems`. The
 * filesystem check is the honest one — `mount(8)` will `modprobe 9p` for a
 * filesystem it does not find, so a host with a module tree can come good, and
 * a host with neither the filesystem nor a module tree cannot. Those are
 * different sentences, and this tells them apart rather than blaming a
 * `modprobe` that was never going to work: a container whose `/lib/modules` is
 * empty (this project's own dev host, see `.agents/environment.md`) has no way
 * to acquire a 9p client at all, and saying "try modprobe" there wastes
 * somebody's afternoon.
 *
 * **What does not make it unusable, deliberately: the transport module.**
 * `/proc/filesystems` can list `9p` with only `9pnet_virtio` loaded, and every
 * transport `mount9p()` uses (`unix`, `tcp`, `fd`) lives in `9pnet_fd` instead —
 * the kernel does *not* autoload a transport (`v9fs_get_trans_by_name()` in
 * `net/9p/mod.c` walks a registered-module list and stops there), so a missing
 * `9pnet_fd` really does fail the mount. It is still not a refusal here, for two
 * reasons: `/sys/module/9pnet_fd` is absent when the code is built *into* the
 * kernel rather than loaded as a module, so its absence is not evidence; and
 * `mount(8)` runs as root, where a `modprobe` triggered by something else on the
 * system may yet have loaded it. So the fact is *reported* ({@link
 * P9ClientProbe.transport}) and `mount9p()` names it in the failure path,
 * where it is a diagnosis rather than a guess.
 *
 * `platform` exists to be overridden in tests; leave it alone otherwise.
 */
export function p9ClientProbe(platform: NodeJS.Platform = process.platform): P9ClientProbe {
  const host = p9Platform(platform);
  const root = (process.getuid?.() ?? -1) === 0;
  const linux = host !== undefined && process.platform === "linux";
  // Only ask this host about itself: with a `platform` override in play the
  // files below describe the machine the test is running on, not the one it is
  // asking about, and reporting those would be a lie in both directions.
  const kernel = linux && hasFilesystem("9p");
  const transport = linux && exists("/sys/module/9pnet_fd");
  const release = linux ? kernelRelease() : undefined;
  const modules = linux && hasModuleTree(release);

  const missing: string[] = [];
  if (host === undefined) {
    missing.push(
      `this is ${platform}; 9P mounts on Linux only — no other kernel has a v9fs client`,
    );
  }
  if (host !== undefined && !root) {
    missing.push(
      "mounting 9P needs root: mount(2) needs CAP_SYS_ADMIN and v9fs has no setuid helper the " +
        "way FUSE has fusermount3",
    );
  }
  if (host !== undefined && !kernel) {
    missing.push(
      modules
        ? `no \`9p\` in /proc/filesystems (the module is not loaded; \`modprobe 9p\` should ` +
            `find it under /lib/modules/${release})`
        : `the kernel has no 9p filesystem and no module tree at /lib/modules/${
            release ?? "<unknown release>"
          } to load one from`,
    );
  }
  return {
    usable: missing.length === 0,
    platform: host,
    kernel,
    transport,
    modules,
    root,
    reason: missing.length === 0 ? undefined : missing.join("; "),
  };
}
