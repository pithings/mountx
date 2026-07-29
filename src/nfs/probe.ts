/**
 * Can this host mount NFS, and which flavour of `mount(8)` does it have?
 *
 * Split out of `mount.ts` for one reason: a probe should cost nothing to ask.
 * `mount.ts` pulls in the server, and the server pulls in the session and the
 * whole RFC 1813 codec — around 90 kB to answer a question that reads two
 * paths and a uid. `mountx/auto` asks it before deciding which transport to
 * load, so this file imports `node:fs` and nothing else.
 *
 * `mount.ts` re-exports everything here, so `mountx/nfs` is unaffected.
 */

import * as fs from "node:fs";

/** A host this transport knows how to put a kernel NFS client in front of. */
export type NfsPlatform = "linux" | "darwin";

/** `process.platform`, narrowed to the two hosts that can mount, or `undefined`. */
export function nfsPlatform(platform: NodeJS.Platform): NfsPlatform | undefined {
  return platform === "linux" || platform === "darwin" ? platform : undefined;
}

/** What this host can and cannot do about mounting NFS. */
export interface NfsClientProbe {
  /** Can an NFS filesystem be mounted here at all? */
  usable: boolean;
  /** The host's mount flavour, or `undefined` if it is neither Linux nor macOS. */
  platform: NfsPlatform | undefined;
  /** Path of the `mount.nfs` (Linux) or `mount_nfs` (macOS) helper, if there is one. */
  helper: string | undefined;
  /** Does the kernel have an NFS client? See the weakness note below. */
  kernel: boolean;
  /**
   * Can this host mount **NFSv4.1** — the version `mountNfs({ version: "4.1" })`
   * asks for? Linux only; see the note below.
   *
   * Orthogonal to {@link NfsClientProbe.usable}, which is about mounting at all:
   * an unprivileged Linux process can read `usable: false` and `v4: true`,
   * because root is a fact about this process and this is one about the host.
   */
  v4: boolean;
  /** Are we root? Required on Linux, and deliberately not on macOS — see below. */
  root: boolean;
  /** Everything that is missing, in a sentence. */
  reason: string | undefined;
}

/**
 * Where each host keeps its mount helper.
 *
 * macOS has exactly one path and it is part of the OS, so there is nothing to
 * install and nothing to search for.
 */
const MOUNT_NFS_PATHS: Record<NfsPlatform, readonly string[]> = {
  linux: ["/sbin/mount.nfs", "/usr/sbin/mount.nfs", "/usr/local/sbin/mount.nfs"],
  darwin: ["/sbin/mount_nfs"],
};

/**
 * Can this host mount NFS?
 *
 * Synchronous and cheap, so a test can gate itself on it and a mount can fail
 * with a message that names the missing piece instead of `mount: wrong fs type`.
 *
 * Note that the kernel check is deliberately weak. On Linux, `nfs` appears in
 * `/proc/filesystems` only once the module is loaded, and `mount.nfs` loads it
 * on demand — so a host with the helper and a loadable module reports
 * `kernel: false` and is still usable. What is *not* usable is a host with
 * neither, which is what this actually distinguishes. On macOS there is no
 * equivalent list to read, and the client is not separable from the OS, so the
 * helper's presence is the whole answer.
 *
 * **Root is a Linux requirement, not an NFS one** (verified on macOS 26.6,
 * 2026-07-28). `/sbin/mount_nfs` is not setuid and holds no entitlement: macOS
 * is a BSD, and a BSD lets an ordinary user mount onto a directory that user
 * owns. So an unprivileged process there mounts with the same `mount(8)` spawn
 * root uses, and the kernel simply forces `MNT_NOSUID|MNT_NODEV` on the result.
 *
 * **`v4` is Linux-only, and it is an assumption on macOS** (A1). Linux's client
 * registers a second filesystem type for version 4 — `nfs4` in
 * `/proc/filesystems`, distinct from `nfs` — so the same weak-but-honest test
 * answers for the version too, with the same escape hatch: the helper loads
 * whichever module a `vers=` asks for, so a host that has `mount.nfs` can mount
 * v4 whether or not the module is loaded yet. macOS is reported `false` because
 * this project treats it as 4.0-only until somebody verifies otherwise on a mac
 * — its client is not known to speak 4.1, and 4.1 is the only minor version
 * `src/nfs/v4/` serves. Nothing about the macOS v3 path depends on this field.
 *
 * That leaves a precondition this function cannot answer: *ownership of the
 * mountpoint*, which is a fact about a path nobody has passed yet. It belongs
 * at mount time, and `mountNfs` checks it there (`ownershipRefusal`). Linux has
 * no equivalent — an unprivileged `mount(8)` needs an `fstab` entry marked
 * `user`, which is not something this library can arrange — so the root
 * requirement stays exactly where it is true.
 *
 * `platform` exists to be overridden in tests; leave it alone otherwise.
 */
export function nfsClientProbe(platform: NodeJS.Platform = process.platform): NfsClientProbe {
  const host = nfsPlatform(platform);
  const root = (process.getuid?.() ?? -1) === 0;
  const helper = (host === undefined ? [] : MOUNT_NFS_PATHS[host]).find((path) => {
    try {
      fs.accessSync(path, fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
  let kernel = helper !== undefined && host === "darwin";
  // A1: macOS is treated as 4.0-only, so the only host that can answer `true`
  // is Linux — see the note above.
  let v4 = false;
  if (host === "linux") {
    let filesystems = "";
    try {
      filesystems = fs.readFileSync("/proc/filesystems", "utf8");
    } catch {
      filesystems = "";
    }
    // The word boundaries matter in both: the file lists `nfs` and `nfs4` as
    // separate types, and a bare `/nfs/` would read the second as the first.
    kernel = /\bnfs\b/.test(filesystems);
    v4 = /\bnfs4\b/.test(filesystems) || helper !== undefined;
  }
  const missing: string[] = [];
  if (host === undefined) {
    missing.push(`this is ${platform}; the NFS transport mounts on Linux and macOS only`);
  }
  if (!root && host === "linux") {
    missing.push("mounting NFS needs root on Linux and this process is not root");
  }
  if (host !== undefined && helper === undefined && !kernel) {
    missing.push(
      host === "darwin"
        ? "no /sbin/mount_nfs, which every macOS is supposed to have"
        : "no /sbin/mount.nfs (install nfs-common / nfs-utils) and no `nfs` in /proc/filesystems",
    );
  }
  return {
    usable: missing.length === 0,
    platform: host,
    helper,
    kernel,
    v4,
    root,
    reason: missing.length === 0 ? undefined : missing.join("; "),
  };
}
