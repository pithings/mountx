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
  /** Are we root? */
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
  if (host === "linux") {
    try {
      kernel = /\bnfs\b/.test(fs.readFileSync("/proc/filesystems", "utf8"));
    } catch {
      kernel = false;
    }
  }
  const missing: string[] = [];
  if (host === undefined) {
    missing.push(`this is ${platform}; the NFS transport mounts on Linux and macOS only`);
  }
  if (!root) {
    missing.push("mounting NFS needs root and this process is not root");
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
    root,
    reason: missing.length === 0 ? undefined : missing.join("; "),
  };
}
