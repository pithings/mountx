/**
 * `mountx/auto` — mount a driver with whichever transport this host can use.
 *
 * ```ts
 * import { mount } from "mountx/auto";
 * await using mounted = await mount(createMemoryDriver(), "/mnt/point");
 * mounted.transport; // "fuse" | "9p" | "nfs"
 * ```
 *
 * This is the facade `src/index.ts` predicted: one `mount()` that picks a
 * transport, kept off the root export so that importing `mountx` for the
 * driver types does not drag three protocol stacks in with it.
 *
 * **What it decides.** FUSE where FUSE works, then 9P, then NFS:
 *
 * | host                              | transport | why                                        |
 * | --------------------------------- | --------- | ------------------------------------------ |
 * | Linux, `/dev/fuse`, non-root      | FUSE      | `fusermount3` + the addon do the mounting  |
 * | Linux, `/dev/fuse`, root          | FUSE      | in-kernel VFS protocol, and it can notify  |
 * | Linux, root, no FUSE, 9P loadable | 9P        | stateful opens, and it spawns no helper    |
 * | Linux, root, no FUSE, no 9P       | NFS       | the fallback: `mount.nfs` + the nfs module |
 * | Linux, non-root, no usable FUSE   | —         | 9P and NFS both need root here             |
 * | macOS, root or not                | NFS       | macFUSE is a different protocol, no v9fs   |
 *
 * FUSE is preferred wherever it works, for two reasons that do not overlap.
 * Unprivileged, it is the only one of the three that can mount at all — 9P and
 * NFS both need root on Linux. As root, it is the one the kernel talks to
 * directly: requests arrive on `/dev/fuse` itself, with no socket and no RPC
 * layer between the VFS and this process, and it has an invalidation channel
 * (`notify_inval_inode`/`notify_inval_entry`) that neither of the others has,
 * so a driver changing underneath a mount can say so instead of hoping nothing
 * cached it. It is also the transport this project has run pjdfstest against.
 *
 * 9P comes next and NFS last, which is a different argument: both need root, so
 * what separates them is semantics. 9P is stateful where NFSv3 is not, so a
 * file deleted while open stays readable instead of answering `ESTALE`,
 * `close()` and `fsync()` reach the driver for real (which is what a
 * handle-buffering driver needs), and no request pays for a handle-table
 * lookup. See the transport comparison in the docs.
 *
 * **Three things it deliberately does not do.**
 *
 * - **No fallback after a failure.** {@link probeTransports} decides, once,
 *   from host facts; if the chosen transport then fails to mount, that error
 *   is what you get. Silently mounting *another* transport would hand back a
 *   filesystem with different semantics than the error you never saw.
 * - **No probing when you asked for a transport by name.** `transport: "fuse"`
 *   calls the FUSE transport, whose own errors are more specific than
 *   anything this file could say about it.
 * - **No loading of what it does not use.** Every transport arrives through
 *   `await import()`, and the probe reaches only `src/nfs/probe.ts`,
 *   `src/9p/probe.ts` and `src/fuse/fusermount.ts` — none of which pulls in a
 *   protocol codec. The first two are cheap enough to import statically (they
 *   read `node:fs` and nothing else); the third is behind an `await import()`
 *   because it reaches the native addon.
 */

import { existsSync } from "node:fs";
import type { MountP9Options, P9Mount } from "./9p/mount.ts";
import { type P9ClientProbe, p9ClientProbe } from "./9p/probe.ts";
import type { Mount, MountOptions } from "./fuse/mount.ts";
import type { MountNfsOptions, NfsMount } from "./nfs/mount.ts";
import { nfsClientProbe } from "./nfs/probe.ts";
import type { FsDriver } from "./types.ts";

export type { MountP9Options, P9Mount } from "./9p/mount.ts";
export type { Mount, MountOptions } from "./fuse/mount.ts";
export type { MountNfsOptions, NfsMount } from "./nfs/mount.ts";

/** The transports {@link mount} can choose between. */
export type Transport = "fuse" | "9p" | "nfs";

/** Whether one transport can mount here, and what is missing if it cannot. */
export interface TransportProbe {
  usable: boolean;
  /** Everything missing, in a sentence. `undefined` when {@link usable}. */
  reason: string | undefined;
}

/** What this host can mount with, and what {@link mount} would pick. */
export interface AutoProbe {
  /** The platform the probe was answered for. */
  platform: NodeJS.Platform;
  /** What {@link mount} would use, or `undefined` if nothing can mount here. */
  chosen: Transport | undefined;
  /** Preference order for this host — the list `chosen` was picked from. */
  preference: readonly Transport[];
  fuse: TransportProbe;
  /** Quoted because `9p` is not an identifier; the transport name is the key. */
  "9p": TransportProbe;
  nfs: TransportProbe;
  /** Why nothing can mount, naming every transport. `undefined` when {@link chosen}. */
  reason: string | undefined;
}

/**
 * Options common to every transport, plus an escape hatch for each.
 *
 * Deliberately *not* the union of the three option types. They have same-named
 * options with genuinely different shapes (`onError` hands FUSE a request, NFS
 * an RPC call and 9P a message header), and a merged type would either lie
 * about that or collapse to something unusable. So the shared options are the
 * ones that mean the same thing in all three, and anything transport-specific
 * goes in {@link AutoMountOptions.fuse}, `"9p"` or {@link AutoMountOptions.nfs}
 * — which are applied *after* the shared ones and therefore win.
 */
export interface AutoMountOptions {
  /**
   * Which transport to use. Default `"auto"` — see {@link probeTransports}.
   *
   * Naming one skips the probe entirely, so the error you get when it cannot
   * mount is the transport's own.
   */
  transport?: Transport | "auto";
  /** Mount read-only. */
  readOnly?: boolean;
  /** Unmount on `SIGINT`/`SIGTERM`. Default `true`. */
  signals?: boolean;
  /** Milliseconds an unmount may spend before it is forced. Default `10_000`. */
  unmountTimeout?: number;
  /** Report the driver's own `ino` values instead of synthesising them. */
  useDriverIno?: boolean;
  /** Called for errors raised while answering a request. */
  onError?: (error: unknown) => void;
  /** Called for transport-level failures, and for a forced teardown. */
  onTransportError?: (error: unknown) => void;
  /** Options for the FUSE transport only. Applied after the shared ones. */
  fuse?: MountOptions;
  /**
   * Options for the 9P transport only. Applied after the shared ones.
   *
   * Quoted for the same reason {@link AutoProbe} quotes it: the key is the
   * transport name, and `9p` is not an identifier.
   */
  "9p"?: MountP9Options;
  /** Options for the NFS transport only. Applied after the shared ones. */
  nfs?: MountNfsOptions;
}

/**
 * A mount, tagged with the transport serving it.
 *
 * The tag is a discriminant, so narrowing on it gives you the full transport
 * type — `mounted.transport === "fuse"` reaches `session`, `fd` and the
 * `notifyInval*` pair; `"9p"` reaches `server`, `connection` and `trans`;
 * `"nfs"` reaches `server` and `port`. What all three share is `mountpoint`,
 * `source`, `active`, `unmount()` and `await using`.
 */
export type AutoMount =
  | (Mount & { readonly transport: "fuse" })
  | (P9Mount & { readonly transport: "9p" })
  | (NfsMount & { readonly transport: "nfs" });

/** Transports whose module has been loaded, so {@link unmountAll} knows who to ask. */
const loaded = new Set<Transport>();

const OK: TransportProbe = { usable: true, reason: undefined };

function unusable(reason: string): TransportProbe {
  return { usable: false, reason };
}

/**
 * Can the FUSE transport mount here?
 *
 * Three facts in order of cheapness: the platform, the device, and — only when
 * unprivileged — the helper and the addon, which is the one that needs a
 * module loaded to answer.
 */
async function probeFuse(platform: NodeJS.Platform): Promise<TransportProbe> {
  if (platform !== "linux") {
    return unusable(
      platform === "darwin"
        ? "FUSE needs Linux, and this is macOS — macFUSE is a third-party kernel " +
            "extension speaking its own protocol dialect, which mountx does not implement"
        : `FUSE needs Linux, this is ${platform}`,
    );
  }
  if (!existsSync("/dev/fuse")) {
    return unusable(
      "no /dev/fuse — the fuse module is not loaded, or this container was not given " +
        "the device (docker: --device /dev/fuse)",
    );
  }
  if ((process.getuid?.() ?? -1) === 0) {
    return OK;
  }
  const { rootlessProbe } = await import("./fuse/fusermount.ts");
  const probe = rootlessProbe();
  return probe.usable
    ? OK
    : unusable(
        `mounting without root needs the fusermount3 helper and mountx's ` +
          `native addon, and ${probe.reason}`,
      );
}

/**
 * Why a host `p9ClientProbe()` calls usable is still not one *this* file should
 * choose 9P for — or `undefined` when there is no such reason.
 *
 * There is exactly one, and it is `9pnet_fd`: the module registering the
 * `unix`, `tcp` and `fd` transports, without which `mount9p()`'s `trans=unix`
 * fails however healthy the rest of the client is. `p9ClientProbe()` reports it
 * ({@link P9ClientProbe.transport}) but deliberately does not refuse on it,
 * because the two sources of doubt run in opposite directions: an absent
 * `/sys/module/9pnet_fd` also describes a kernel with the code built in, and a
 * present module tree means `mount(8)` may yet `modprobe` it as root. That is
 * the right call for a *named* `-t 9p`, where the alternative is refusing a
 * mount that would have worked.
 *
 * It is the wrong call here, because of the no-fallback rule above: this
 * chooses once, and a wrong choice is a hard failure on a host where NFS would
 * have mounted. So the one case where the doubt is worth resolving against
 * 9P — no module loaded *and* no module tree to load one from, which is a
 * virtio-only guest or a container with an empty `/lib/modules` (a built-in
 * `9pnet_fd` would also look like this, but such a kernel is the rarity and
 * the refusal names `--transport 9p` as the way to overrule it) — rules 9P
 * out for `auto` while leaving `-t 9p` free to try and fail in its own more
 * specific words.
 *
 * Pure and exported for the Tier-0 test: the seam a test needs is a probe with
 * a `9pnet_fd` that is not there, and no host offers that on request.
 */
export function p9ModuleRefusal(probe: P9ClientProbe): string | undefined {
  if (!probe.usable || probe.transport || probe.modules) {
    return undefined;
  }
  return (
    "the kernel has a 9p filesystem but no 9pnet_fd in /sys/module — the module registering " +
    "the trans=unix this transport mounts with — and no module tree to load it from, which is " +
    "what a virtio-only guest looks like; `mountx --transport 9p` will try it anyway"
  );
}

/**
 * Can the 9P transport mount here? The probe is `src/9p/probe.ts`'s, plus
 * {@link p9ModuleRefusal}.
 *
 * The probe already answers per platform in its own words — "this is darwin; 9P
 * mounts on Linux only — no other kernel has a v9fs client" — so there is
 * nothing for this file to add the way there is for FUSE on macOS, where the
 * existence of macFUSE makes "needs Linux" an incomplete answer.
 */
function probe9p(platform: NodeJS.Platform): TransportProbe {
  const probe = p9ClientProbe(platform);
  if (!probe.usable) {
    return unusable(probe.reason!);
  }
  const refusal = p9ModuleRefusal(probe);
  return refusal === undefined ? OK : unusable(refusal);
}

/** Can the NFS transport mount here? The probe is `src/nfs/probe.ts`'s. */
function probeNfs(platform: NodeJS.Platform): TransportProbe {
  const probe = nfsClientProbe(platform);
  return probe.usable ? OK : unusable(probe.reason!);
}

/**
 * What can mount here, and what {@link mount} would choose.
 *
 * Cheap enough to call before deciding whether to offer a mount at all, and
 * specific enough to print: when nothing works, `reason` names what each
 * transport is missing rather than reporting the last failure.
 *
 * `platform` exists to be overridden in tests; leave it alone otherwise.
 */
export async function probeTransports(
  platform: NodeJS.Platform = process.platform,
): Promise<AutoProbe> {
  const fuse = await probeFuse(platform);
  const p9 = probe9p(platform);
  const nfs = probeNfs(platform);
  // Linux is the only host where more than one can work, so it is the only host
  // whose order decides anything: FUSE (the only one that mounts without root),
  // then 9P, then NFS. Off Linux only NFS can be usable — there is no v9fs
  // client on any other kernel, and macFUSE speaks a dialect this library does
  // not — so it leads, and what follows it decides nothing and keeps the order
  // the two have on Linux. Every transport appears in every list either way:
  // this is what `chosen` was picked from, and a name missing from it would
  // read as one that was never considered.
  const preference: readonly Transport[] =
    platform === "linux" ? ["fuse", "9p", "nfs"] : ["nfs", "fuse", "9p"];
  const probes = { fuse, "9p": p9, nfs };
  const chosen = preference.find((transport) => probes[transport].usable);
  return {
    platform,
    chosen,
    preference,
    fuse,
    "9p": p9,
    nfs,
    reason:
      chosen === undefined
        ? `no transport can mount on this host — FUSE: ${fuse.reason}; 9P: ${p9.reason}; ` +
          `NFS: ${nfs.reason}`
        : undefined,
  };
}

/** The shared options, in the shape each transport wants them. */
function shared(options: AutoMountOptions): MountOptions & MountP9Options & MountNfsOptions {
  return {
    readOnly: options.readOnly,
    signals: options.signals,
    unmountTimeout: options.unmountTimeout,
    useDriverIno: options.useDriverIno,
    onError: options.onError,
    onTransportError: options.onTransportError,
  };
}

/**
 * Stamp the transport onto the mount the transport just returned.
 *
 * The mount object itself is tagged rather than wrapped, so `await using`,
 * `unmount()` and the transport's own members keep working on the thing the
 * caller holds. Idempotent: {@link liveMounts} tags mounts {@link mount} has
 * already tagged.
 */
function tag<T extends Transport, M extends Mount | P9Mount | NfsMount>(
  mounted: M,
  transport: T,
): M & { readonly transport: T } {
  if (!("transport" in mounted)) {
    Object.defineProperty(mounted, "transport", { value: transport, enumerable: true });
  }
  return mounted as M & { readonly transport: T };
}

/**
 * Serve `driver` at `mountpoint` over whatever this host can mount.
 *
 * Resolves once the mountpoint is usable, and the result is the transport's
 * own mount object with a `transport` tag added — so `await using`, `unmount()`
 * and every transport-specific member work exactly as they do when you import
 * the transport directly.
 */
export async function mount(
  driver: FsDriver,
  mountpoint: string,
  options: AutoMountOptions = {},
): Promise<AutoMount> {
  const requested = options.transport ?? "auto";
  let transport: Transport;
  if (requested === "auto") {
    const probe = await probeTransports();
    if (probe.chosen === undefined) {
      throw new Error(`mountx: ${probe.reason}`);
    }
    transport = probe.chosen;
  } else {
    transport = requested;
  }
  loaded.add(transport);
  if (transport === "fuse") {
    const { mount: mountFuse } = await import("./fuse/mount.ts");
    return tag(
      await mountFuse(driver, mountpoint, { ...shared(options), ...options.fuse }),
      "fuse",
    );
  }
  if (transport === "9p") {
    const { mount9p } = await import("./9p/mount.ts");
    return tag(await mount9p(driver, mountpoint, { ...shared(options), ...options["9p"] }), "9p");
  }
  const { mountNfs } = await import("./nfs/mount.ts");
  return tag(await mountNfs(driver, mountpoint, { ...shared(options), ...options.nfs }), "nfs");
}

/**
 * Unmount every live mount in this process, on every transport. Never rejects.
 *
 * Only transports {@link mount} actually used are asked, so this loads nothing
 * that was not already loaded.
 */
export async function unmountAll(): Promise<unknown[]> {
  const failures: unknown[] = [];
  if (loaded.has("fuse")) {
    const { unmountAll: unmountAllFuse } = await import("./fuse/mount.ts");
    failures.push(...(await unmountAllFuse()));
  }
  if (loaded.has("9p")) {
    const { unmountAll9p } = await import("./9p/mount.ts");
    failures.push(...(await unmountAll9p()));
  }
  if (loaded.has("nfs")) {
    const { unmountAllNfs } = await import("./nfs/mount.ts");
    failures.push(...(await unmountAllNfs()));
  }
  return failures;
}

/** Every live mount in this process, on every transport, tagged. */
export async function liveMounts(): Promise<AutoMount[]> {
  const mounts: AutoMount[] = [];
  if (loaded.has("fuse")) {
    const { liveMounts: liveFuse } = await import("./fuse/mount.ts");
    mounts.push(...liveFuse().map((mounted) => tag(mounted, "fuse")));
  }
  if (loaded.has("9p")) {
    const { live9pMounts } = await import("./9p/mount.ts");
    mounts.push(...live9pMounts().map((mounted) => tag(mounted, "9p")));
  }
  if (loaded.has("nfs")) {
    const { liveNfsMounts } = await import("./nfs/mount.ts");
    mounts.push(...liveNfsMounts().map((mounted) => tag(mounted, "nfs")));
  }
  return mounts;
}
