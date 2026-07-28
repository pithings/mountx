/**
 * `mountx/auto` — mount a driver with whichever transport this host can use.
 *
 * ```ts
 * import { mount } from "mountx/auto";
 * await using mounted = await mount(createMemoryDriver(), "/mnt/point");
 * mounted.transport; // "fuse" | "nfs"
 * ```
 *
 * This is the facade `src/index.ts` predicted: one `mount()` that picks a
 * transport, kept off the root export so that importing `mountx` for the
 * driver types does not drag two protocol stacks in with it.
 *
 * **What it decides.** FUSE where FUSE works, NFS otherwise:
 *
 * | host                          | transport | why                                       |
 * | ----------------------------- | --------- | ----------------------------------------- |
 * | Linux, `/dev/fuse`, root      | FUSE      | real `open`/`release`, no `ESTALE`        |
 * | Linux, `/dev/fuse`, non-root  | FUSE      | `fusermount3` + the addon do the mounting |
 * | Linux, no usable FUSE, root   | NFS       | needs no `/dev/fuse` and no helper        |
 * | macOS, root                   | NFS       | macFUSE is a different protocol           |
 *
 * FUSE is preferred wherever both work, and the reason is behavioural rather
 * than performance: NFSv3 is stateless, so a file deleted while open answers
 * `ESTALE` instead of staying readable, and every request costs a handle
 * lookup. See the transport comparison in `README.md`.
 *
 * **Three things it deliberately does not do.**
 *
 * - **No fallback after a failure.** {@link probeTransports} decides, once,
 *   from host facts; if the chosen transport then fails to mount, that error
 *   is what you get. Silently mounting the *other* transport would hand back a
 *   filesystem with different semantics than the error you never saw.
 * - **No probing when you asked for a transport by name.** `transport: "fuse"`
 *   calls the FUSE transport, whose own errors are more specific than
 *   anything this file could say about it.
 * - **No loading of what it does not use.** Both transports arrive through
 *   `await import()`, and the probe reaches only `src/nfs/probe.ts` and
 *   `src/fuse/fusermount.ts` — neither of which pulls in a protocol codec.
 */

import { existsSync } from "node:fs";
import type { Mount, MountOptions } from "./fuse/mount.ts";
import type { MountNfsOptions, NfsMount } from "./nfs/mount.ts";
import { nfsClientProbe } from "./nfs/probe.ts";
import type { FsDriver } from "./types.ts";

export type { Mount, MountOptions } from "./fuse/mount.ts";
export type { MountNfsOptions, NfsMount } from "./nfs/mount.ts";

/** The transports {@link mount} can choose between. */
export type Transport = "fuse" | "nfs";

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
  nfs: TransportProbe;
  /** Why nothing can mount, naming both transports. `undefined` when {@link chosen}. */
  reason: string | undefined;
}

/**
 * Options common to both transports, plus an escape hatch for each.
 *
 * Deliberately *not* the union of both option types. The two transports have
 * same-named options with genuinely different shapes (`onError` hands FUSE a
 * request and NFS an RPC call), and a merged type would either lie about that
 * or collapse to something unusable. So the shared options are the ones that
 * mean the same thing in both, and anything transport-specific goes in
 * {@link AutoMountOptions.fuse} or {@link AutoMountOptions.nfs} — which are
 * applied *after* the shared ones and therefore win.
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
  /** Options for the NFS transport only. Applied after the shared ones. */
  nfs?: MountNfsOptions;
}

/**
 * A mount, tagged with the transport serving it.
 *
 * The tag is a discriminant, so narrowing on it gives you the full transport
 * type — `mounted.transport === "fuse"` reaches `session`, `fd` and the
 * `notifyInval*` pair; `"nfs"` reaches `server` and `port`. What both share is
 * `mountpoint`, `source`, `active`, `unmount()` and `await using`.
 */
export type AutoMount =
  | (Mount & { readonly transport: "fuse" })
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
  const nfs = probeNfs(platform);
  // Linux is the only host where both can work, so it is the only host whose
  // preference order decides anything.
  const preference: readonly Transport[] = platform === "linux" ? ["fuse", "nfs"] : ["nfs", "fuse"];
  const probes = { fuse, nfs };
  const chosen = preference.find((transport) => probes[transport].usable);
  return {
    platform,
    chosen,
    preference,
    fuse,
    nfs,
    reason:
      chosen === undefined
        ? `no transport can mount on this host — FUSE: ${fuse.reason}; NFS: ${nfs.reason}`
        : undefined,
  };
}

/** The shared options, in the shape each transport wants them. */
function shared(options: AutoMountOptions): MountOptions & MountNfsOptions {
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
function tag<T extends Transport, M extends Mount | NfsMount>(
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
  const { mountNfs } = await import("./nfs/mount.ts");
  return tag(await mountNfs(driver, mountpoint, { ...shared(options), ...options.nfs }), "nfs");
}

/**
 * Unmount every live mount in this process, on both transports. Never rejects.
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
  if (loaded.has("nfs")) {
    const { unmountAllNfs } = await import("./nfs/mount.ts");
    failures.push(...(await unmountAllNfs()));
  }
  return failures;
}

/** Every live mount in this process, on both transports, tagged. */
export async function liveMounts(): Promise<AutoMount[]> {
  const mounts: AutoMount[] = [];
  if (loaded.has("fuse")) {
    const { liveMounts: liveFuse } = await import("./fuse/mount.ts");
    mounts.push(...liveFuse().map((mounted) => tag(mounted, "fuse")));
  }
  if (loaded.has("nfs")) {
    const { liveNfsMounts } = await import("./nfs/mount.ts");
    mounts.push(...liveNfsMounts().map((mounted) => tag(mounted, "nfs")));
  }
  return mounts;
}
