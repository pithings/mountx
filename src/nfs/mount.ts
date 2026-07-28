/**
 * Mounting the NFS server with `mount(8)`.
 *
 * The transport is `server.ts`; this file is the convenience that puts a
 * kernel NFS client in front of it, and it is the second file in the library
 * that spawns a process.
 *
 * ```ts
 * import { mountNfs } from "mountx/nfs";
 * await using mounted = await mountNfs(createMemoryDriver(), "/mnt/point");
 * ```
 *
 * **Root, and a client.** `mount(2)` is not a syscall Node can issue, and there
 * is no setuid helper for NFS the way `fusermount3` is one for FUSE — so this
 * needs root, and it needs the host to have an NFS *client*: the `nfs` module
 * in the kernel and the `/sbin/mount.nfs` helper from `nfs-utils`. Neither is
 * something the server can provide, so {@link nfsClientProbe} exists to say
 * which is missing before anything is spawned.
 *
 * **Linux and macOS.** Everything above `server.ts` is portable; this file is
 * where the two hosts differ, and the differences are small enough to name in
 * full. macOS ships an NFSv2/v3/v4 client and `/sbin/mount_nfs`, so the same
 * loopback mount works there — which matters because macOS has no usable FUSE
 * (macFUSE is a third-party kext speaking its own protocol dialect, not the
 * Linux `fuse.h` 7.41 `src/fuse/` is written against). What differs:
 *
 * - **The mount table.** `/proc/self/mounts` does not exist on macOS, so the
 *   table comes from `mount(8)`'s output instead — which is why reading it is
 *   asynchronous, and why "is it mounted" is a *tri-state*: a table that could
 *   not be read is `undefined`, not `false`. Forcing a mount down on a maybe
 *   is safe; reporting a successful unmount on a maybe is not.
 * - **The option spelling.** `nolock` is `nolocks`, and there is no `hard`
 *   option at all — a hard mount is the absence of `soft` (verified against
 *   Apple's `mount_nfs(8)`, which documents `soft` and no counterpart). Adding
 *   `nobrowse` keeps Finder and Spotlight from crawling the driver.
 * - **The escalation ladder.** macOS has `umount -f` but no `umount -l`, so
 *   the lazy step — and the advice to run it — is Linux-only.
 *
 * Windows is neither: no NFS client worth the name, and no `mount(8)`.
 *
 * **No portmapper.** Both programs are on one port and the mount command is
 * told so with `port=` *and* `mountport=`, so `rpcbind` is never contacted.
 * `nolock`/`nolocks` keeps `lockd`/`rpc.statd` out of it too — NFSv3 file
 * locking is a separate protocol (NLM) that this server does not implement,
 * and a client that tried to use it would hang waiting for a service that is
 * not there. (macOS `locallocks`, which locks in the client's VFS layer
 * instead, is a reasonable thing to add via `mountOptions` if an application
 * on the mount needs `flock` to succeed.)
 *
 * **`soft` by default.** A hard mount retries forever, which is right when the
 * server is a machine that may reboot and wrong when the server is a JavaScript
 * object in the process doing the mounting: a bug in the driver would produce
 * unkillable `D`-state processes instead of an `EIO`. This is the same reasoning
 * the FUSE transport's unmount deadline comes from.
 *
 * Teardown follows the FUSE transport's discipline exactly, and for the same
 * reasons: `umount(8)` first, the mount table is the truth rather than an exit
 * status, `umount -f` (then `-l`, on Linux) when the deadline passes, and the
 * whole thing is idempotent and retryable.
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import { realpath, stat as statPath } from "node:fs/promises";
import { resolve as resolveNative } from "node:path";
import type { FsDriver } from "../types.ts";
import { createNfsServer, type NfsServer, type NfsServerOptions } from "./server.ts";

/** Signals a mount cleans up on. `SIGHUP` is deliberately not one. */
const TEARDOWN_SIGNALS = ["SIGINT", "SIGTERM"] as const;

/** A host this transport knows how to put a kernel NFS client in front of. */
export type NfsPlatform = "linux" | "darwin";

/** `process.platform`, narrowed to the two hosts that can mount, or `undefined`. */
function nfsPlatform(platform: NodeJS.Platform): NfsPlatform | undefined {
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

export interface MountNfsOptions extends NfsServerOptions {
  /** Serve an existing server instead of creating one. Its `listen()` is still called. */
  server?: NfsServer;
  /** Directory of the driver to export. Default `"/"`. */
  exportPath?: string;
  /** Mount read-only (`-o ro`). */
  readOnly?: boolean;
  /** Use a hard mount (retry forever) instead of `soft`. Default `false`. See the module docs. */
  hard?: boolean;
  /**
   * Tenths of a second before an NFS request is retried. Default `50` (5 s).
   *
   * Both hosts read this the same way — Linux's `nfs(5)` and Apple's
   * `mount_nfs(8)` both document `timeo` in tenths of a second.
   */
  timeo?: number;
  /** Retries before a `soft` mount gives up with `EIO`. Default `2`. */
  retrans?: number;
  /**
   * macOS only: hide the mount from the GUI (`-o nobrowse`). Default `true`.
   *
   * A visible volume is one Finder and Spotlight will crawl, which for a
   * JavaScript driver means a burst of traffic and a scattering of `.DS_Store`
   * writes nobody asked for. Set `false` if the point of the mount is for
   * someone to open it in Finder.
   */
  nobrowse?: boolean;
  /** Extra `-o` options, appended verbatim. */
  mountOptions?: readonly string[];
  /** Unmount on `SIGINT`/`SIGTERM`. Default `true`. */
  signals?: boolean;
  /**
   * Milliseconds {@link NfsMount.unmount} may spend before it forces the mount
   * down. Default `10_000`; `0` or `Infinity` waits forever.
   */
  unmountTimeout?: number;
  /** Called for transport-level failures, and for a forced teardown. */
  onTransportError?: (error: unknown, peer: string | undefined) => void;
}

/** A live NFS mountpoint. */
export interface NfsMount extends AsyncDisposable {
  /** Absolute path of the mountpoint. */
  readonly mountpoint: string;
  /** The server behind it. */
  readonly server: NfsServer;
  /** The port both programs are on. */
  readonly port: number;
  /** What the mount table shows as the device, e.g. `127.0.0.1:/`. */
  readonly source: string;
  /** `false` from the moment teardown starts. */
  readonly active: boolean;
  /**
   * Unmount and shut the server down. Idempotent, concurrency-safe, retryable
   * after a failure. Always settles, within `unmountTimeout`.
   */
  unmount(): Promise<void>;
}

const live = new Set<NfsMountImpl>();
let signalsInstalled = false;

async function onTeardownSignal(signal: NodeJS.Signals): Promise<void> {
  removeSignalHandlers();
  for (const failure of await unmountAllNfs()) {
    console.error(`mountx: NFS unmount on ${signal} failed: ${errorMessage(failure)}`);
  }
  if (process.listenerCount(signal) === 0) {
    process.kill(process.pid, signal);
  }
}

const signalHandlers = new Map<NodeJS.Signals, () => void>(
  TEARDOWN_SIGNALS.map((signal) => [signal, () => void onTeardownSignal(signal)]),
);

function installSignalHandlers(): void {
  if (signalsInstalled) {
    return;
  }
  signalsInstalled = true;
  for (const [signal, handler] of signalHandlers) {
    process.on(signal, handler);
  }
}

function removeSignalHandlers(): void {
  if (!signalsInstalled) {
    return;
  }
  signalsInstalled = false;
  for (const [signal, handler] of signalHandlers) {
    process.off(signal, handler);
  }
}

/** Unmount every live NFS mount in this process. Never rejects. */
export async function unmountAllNfs(): Promise<unknown[]> {
  const results = await Promise.allSettled([...live].map((mount) => mount.unmount()));
  return results
    .filter((result) => result.status === "rejected")
    .map((result) => (result as PromiseRejectedResult).reason);
}

/** The NFS mounts this process currently has up, in creation order. */
export function liveNfsMounts(): NfsMount[] {
  return [...live];
}

/**
 * Serve `driver` over NFSv3 and mount it at `mountpoint`.
 *
 * Resolves once `mount(8)` has returned successfully, which for NFS means the
 * client has already completed a MOUNT and an FSINFO — so a resolved
 * `mountNfs()` means the path is usable.
 */
export async function mountNfs(
  driver: FsDriver,
  mountpoint: string,
  options: MountNfsOptions = {},
): Promise<NfsMount> {
  const probe = nfsClientProbe();
  if (!probe.usable || probe.platform === undefined) {
    throw new Error(`mountx: cannot mount NFS here — ${probe.reason}`);
  }
  const platform = probe.platform;
  const resolved = resolveNative(mountpoint);
  const targetStat = await statPath(resolved).catch((error: unknown) => {
    throw new Error(`mountx: mountpoint ${resolved} is not usable: ${errorMessage(error)}`);
  });
  if (!targetStat.isDirectory()) {
    throw new Error(`mountx: mountpoint ${resolved} is not a directory`);
  }
  // The mount table records the path with every symlink resolved, and matching
  // against it is how teardown knows whether the mount is still there. macOS
  // makes this load-bearing rather than pedantic: its temporary directories
  // live under `/var/folders/…`, and `/var` is a symlink to `/private/var`, so
  // an unresolved mountpoint matches nothing in the table it is listed in.
  const target = await realpath(resolved).catch(() => resolved);
  // Same trap as the FUSE transport: both hosts stack mounts, and then
  // `umount` detaches the *top* one.
  for (const existing of live) {
    if (existing.mountpoint === target) {
      throw new Error(
        `mountx: ${target} is already mounted by this process. Unmount it before mounting again.`,
      );
    }
  }
  const occupant = await mountEntryAt(target, platform);
  if (occupant !== undefined && occupant !== null) {
    throw new Error(
      `mountx: ${target} already has a filesystem on it (${occupant.source}, type ` +
        `${occupant.type}). Clear it first: umount ${target}`,
    );
  }

  const server = options.server ?? createNfsServer(driver, options);
  await server.listen();
  const impl = new NfsMountImpl(server, target, options, platform);
  try {
    await impl.start();
  } catch (error) {
    await server.close().catch(() => {});
    throw error;
  }
  return impl;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** `/proc/self/mounts` escapes these four characters in paths. */
function unescapeMountPath(path: string): string {
  return path.replace(/\\(?:040|011|012|134)/g, (match) =>
    String.fromCharCode(Number.parseInt(match.slice(1), 8)),
  );
}

export interface MountEntry {
  source: string;
  target: string;
  type: string;
}

/** One line of `mount(8)`'s output on macOS: `<source> on <target> (<type>, …)`. */
const DARWIN_MOUNT_LINE = /^(.*) on (.*) \(([^,)]*)[,)]/;

/**
 * Parse the mount table as `platform` prints it.
 *
 * Linux gets `/proc/self/mounts`, which escapes the four characters that would
 * otherwise break its field split. macOS gets `mount(8)`'s prose, which escapes
 * nothing — so a mountpoint containing the literal string `" on "` is
 * ambiguous, and this resolves it the way every other parser of this format
 * does: greedily, giving the longest possible source. Neither the mountpoints
 * this transport creates nor any sane one hits that.
 */
export function parseMountTable(platform: NfsPlatform, table: string): MountEntry[] {
  const entries: MountEntry[] = [];
  for (const line of table.split("\n")) {
    if (platform === "darwin") {
      const match = DARWIN_MOUNT_LINE.exec(line);
      if (match !== null) {
        entries.push({ source: match[1]!, target: match[2]!, type: match[3]! });
      }
      continue;
    }
    const [source = "", path = "", type = ""] = line.split(" ");
    if (path !== "") {
      entries.push({
        source: unescapeMountPath(source),
        target: unescapeMountPath(path),
        type,
      });
    }
  }
  return entries;
}

/**
 * How long `mount(8)` gets to print the table on macOS before it is written
 * off as unreadable. It reads the kernel's list without contacting any server,
 * so this is a backstop, not a timeout anything is expected to reach.
 */
const MOUNT_TABLE_TIMEOUT = 5000;

/** The mount table, or `undefined` if it could not be read. */
async function mountTable(platform: NfsPlatform): Promise<MountEntry[] | undefined> {
  if (platform === "darwin") {
    const result = await run("mount", [], MOUNT_TABLE_TIMEOUT).catch(() => undefined);
    return result === undefined || result.status !== 0
      ? undefined
      : parseMountTable(platform, result.stdout);
  }
  try {
    return parseMountTable(platform, fs.readFileSync("/proc/self/mounts", "utf8"));
    /* v8 ignore next 3 -- no procfs is stranger than an unmounted filesystem. */
  } catch {
    return undefined;
  }
}

/**
 * What is mounted at `target`, `undefined` if nothing is, and `null` if the
 * table could not be read at all. The last matching entry wins — that is the
 * one on top, and the one `umount` would take down.
 */
async function mountEntryAt(
  target: string,
  platform: NfsPlatform,
): Promise<MountEntry | undefined | null> {
  const table = await mountTable(platform);
  if (table === undefined) {
    return null;
  }
  let found: MountEntry | undefined;
  for (const entry of table) {
    if (entry.target === target) {
      found = entry;
    }
  }
  return found;
}

/**
 * Is `target` mounted? `undefined` means the table could not be read.
 *
 * The tri-state is the point. Teardown has to distinguish "gone" from "no
 * idea": forcing down a mount that turns out to be gone is harmless, whereas
 * treating "no idea" as "gone" reports a successful unmount for a mount that
 * is still live — the one outcome that leaves the caller's processes hanging
 * on a mountpoint whose server has just been shut down underneath them.
 */
async function isMounted(target: string, platform: NfsPlatform): Promise<boolean | undefined> {
  const entry = await mountEntryAt(target, platform);
  return entry === null ? undefined : entry !== undefined;
}

interface SpawnResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

/**
 * Run a command and collect both its streams.
 *
 * `timeout` kills the child rather than rejecting, so the caller sees the
 * ordinary "died on a signal" result and decides what that means. Only the
 * mount-table read uses it; `mount`/`umount` are under the caller's deadline.
 */
function run(command: string, args: readonly string[], timeout?: number): Promise<SpawnResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, [...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => {
      stderr += chunk;
    });
    const timer =
      timeout === undefined ? undefined : setTimeout(() => child.kill("SIGKILL"), timeout);
    timer?.unref();
    child.once("error", (error) => {
      clearTimeout(timer);
      rejectPromise(error);
    });
    child.once("close", (status, signal) => {
      clearTimeout(timer);
      resolvePromise({ status, signal, stdout, stderr: stderr.trim() });
    });
  });
}

function describe(command: string, result: SpawnResult): string {
  const how = result.signal === null ? `exit ${result.status}` : `signal ${result.signal}`;
  return result.stderr === "" ? `${command}: ${how}` : `${command}: ${how}: ${result.stderr}`;
}

/** A mount option that must be a non-negative integer, whatever was passed. */
function count(value: number | undefined, fallback: number, floor: number): number {
  return Number.isFinite(value) ? Math.max(floor, Math.trunc(value!)) : fallback;
}

/**
 * The `-o` string this transport hands `mount(8)`, for `port`, on `platform`.
 *
 * Exported because it is the whole platform difference in one pure function:
 * a test can check both hosts from either, and anyone who would rather run the
 * mount themselves can print the command instead of reverse-engineering it.
 *
 * Every option here is documented in Linux's `nfs(5)` or Apple's
 * `mount_nfs(8)`/`mount(8)` — including the two absences, which are the parts
 * worth reading twice:
 *
 * - macOS's option is `nolocks`; `nolock` is the Linux spelling.
 * - macOS has **no `hard` option**. `soft` has no documented counterpart there,
 *   so a hard mount is what you get by not asking for a soft one, and emitting
 *   `hard` would fail the mount outright on an unknown option.
 */
export function nfsMountOptions(
  port: number,
  options: MountNfsOptions = {},
  platform: NfsPlatform = nfsPlatform(process.platform) ?? "linux",
): string {
  const darwin = platform === "darwin";
  const parts = [
    "vers=3",
    // This covers the MOUNT protocol as well as NFS, which matters because the
    // server is TCP-only: macOS documents `mntudp` as forcing MOUNT to UDP
    // "even for TCP NFS mounts", so by default MOUNT follows NFS onto TCP.
    "proto=tcp",
    // The two that make a portmapper unnecessary: both programs are here.
    `port=${port}`,
    `mountport=${port}`,
    // NLM is a separate protocol this server does not implement; a client
    // that tried to lock would wait for a service that does not exist.
    darwin ? "nolocks" : "nolock",
  ];
  if (options.hard === true) {
    // See the note above: on macOS this is the default and has no spelling.
    if (!darwin) {
      parts.push("hard");
    }
  } else {
    parts.push("soft");
  }
  parts.push(
    // `NaN` would floor to a literal `timeo=NaN` in the option string, which
    // `mount(8)` rejects with a message about nothing in particular. Same
    // guard the FUSE transport puts on `readers`.
    `timeo=${count(options.timeo, 50, 1)}`,
    `retrans=${count(options.retrans, 2, 0)}`,
  );
  if (darwin && options.nobrowse !== false) {
    parts.push("nobrowse");
  }
  if (options.readOnly === true) {
    parts.push("ro");
  }
  // Last, so a caller can override anything above it: both hosts' option
  // parsers take the last occurrence of an option as the winner.
  parts.push(...(options.mountOptions ?? []));
  return parts.join(",");
}

function delay(ms: number): Promise<void> {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, ms).unref();
  });
}

class NfsMountImpl implements NfsMount {
  readonly mountpoint: string;
  readonly server: NfsServer;
  readonly source: string;

  readonly #options: MountNfsOptions;
  readonly #platform: NfsPlatform;
  #stopping = false;
  #unmounting: Promise<void> | undefined;

  constructor(
    server: NfsServer,
    mountpoint: string,
    options: MountNfsOptions,
    platform: NfsPlatform,
  ) {
    this.server = server;
    this.mountpoint = mountpoint;
    this.#options = options;
    this.#platform = platform;
    const exported = options.exportPath ?? "/";
    if (/[\s,]/.test(exported)) {
      throw new Error(
        `mountx: \`exportPath\` may not contain whitespace or a comma — it is the source ` +
          `argument of mount(8) (got ${JSON.stringify(exported)})`,
      );
    }
    this.source = `${server.host}:${exported}`;
  }

  get port(): number {
    return this.server.port;
  }

  get active(): boolean {
    return !this.#stopping;
  }

  async start(): Promise<void> {
    const options = nfsMountOptions(this.server.port, this.#options, this.#platform);
    let result: SpawnResult;
    try {
      // Deliberately *not* `-i`: unlike FUSE, the NFS mount genuinely wants its
      // `mount.nfs`/`mount_nfs` helper, which is what resolves the host into
      // the `addr=` the kernel needs and negotiates the version.
      result = await run("mount", ["-t", "nfs", "-o", options, this.source, this.mountpoint]);
    } catch (error) {
      throw new Error(`mountx: could not run mount(8): ${errorMessage(error)}`);
    }
    if (result.status !== 0) {
      throw new Error(
        `mountx: mounting ${this.mountpoint} failed — ` +
          `${describe(`mount -t nfs -o ${options}`, result)}`,
      );
    }
    live.add(this);
    if (this.#options.signals !== false) {
      installSignalHandlers();
    }
  }

  /** Is the mountpoint still in the table? `undefined` if the table would not say. */
  #mounted(): Promise<boolean | undefined> {
    return isMounted(this.mountpoint, this.#platform);
  }

  async unmount(): Promise<void> {
    this.#unmounting ??= this.#unmount().catch((error: unknown) => {
      // A refused unmount is worth retrying once whatever held it lets go.
      this.#unmounting = undefined;
      throw error;
    });
    return this.#unmounting;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.unmount();
  }

  /**
   * The whole teardown, under a deadline.
   *
   * The deadline is not paranoia: `umount(8)` flushes the filesystem before it
   * detaches, so a driver that has stopped answering blocks it — and on a
   * `hard` mount, blocks it forever.
   */
  async #unmount(): Promise<void> {
    const timeout = this.#options.unmountTimeout ?? 10_000;
    let failure: unknown;
    const steps = this.#unmountSteps().then(
      () => "done" as const,
      (error: unknown) => {
        failure = error;
        return "failed" as const;
      },
    );
    if (!Number.isFinite(timeout) || timeout <= 0) {
      if ((await steps) === "failed") {
        // Deliberately *not* finished: the mount is still live, so the server
        // has to keep answering it or every process touching the mountpoint
        // hangs. `unmount()` is retryable for exactly this case.
        throw failure;
      }
      await this.#finish();
      return;
    }
    let timer: NodeJS.Timeout | undefined;
    const expiry = new Promise<"expired">((resolvePromise) => {
      timer = setTimeout(() => resolvePromise("expired"), timeout);
      timer.unref();
    });
    const outcome = await Promise.race([steps, expiry]);
    clearTimeout(timer);
    if (outcome === "expired") {
      await this.#force(timeout);
      return;
    }
    if (outcome === "failed") {
      // See above: a live mount whose server has gone away is worse than a
      // failed unmount, so the server stays up for the retry.
      throw failure;
    }
    await this.#finish();
  }

  async #unmountSteps(): Promise<void> {
    if ((await this.#mounted()) === false) {
      // Someone else already unmounted us.
      return;
    }
    let result: SpawnResult;
    try {
      result = await run("umount", [this.mountpoint]);
    } catch (error) {
      throw new Error(`mountx: could not run umount(8): ${errorMessage(error)}`);
    }
    // A failure that raced an external unmount is not a failure. A table that
    // will not say is not that race: the mount is presumed live.
    if (result.status === 0 || (await this.#mounted()) === false) {
      return;
    }
    throw new Error(
      `mountx: could not unmount ${this.mountpoint} (${describe("umount", result)}). ` +
        `The mount is still live. ${this.#stuckAdvice()}`,
    );
  }

  /** How to get rid of a mount this process could not, on this host. */
  #stuckAdvice(): string {
    return this.#platform === "darwin"
      ? `If a process is holding it, \`lsof ${this.mountpoint}\` will say which; ` +
          `\`sudo umount -f ${this.mountpoint}\` detaches it regardless.`
      : `If a process is holding it, \`fuser -m ${this.mountpoint}\` will say which; ` +
          `\`sudo umount -l ${this.mountpoint}\` detaches it regardless.`;
  }

  /**
   * Teardown when asking nicely did not work.
   *
   * `umount -f` is the one that matters for NFS — it is what the option was
   * invented for — and on Linux `umount -l` covers the table entry that
   * outlives it. macOS has no lazy unmount, so `-f` is the whole ladder there.
   * The exit statuses are not believed; the mount table is.
   */
  async #force(timeout: number): Promise<void> {
    const lazy = this.#platform === "darwin" ? "-f" : "-l";
    const error = new Error(
      `mountx: unmounting ${this.mountpoint} did not finish within ${timeout}ms — the ` +
        `driver has probably stopped answering. The mount has been forced down, so anything ` +
        `in flight was lost. If the mountpoint is somehow still listed: ` +
        `sudo umount ${lazy} ${this.mountpoint}`,
    );
    this.#options.onTransportError?.(error, undefined);
    const ladder =
      this.#platform === "darwin"
        ? [["-f", this.mountpoint]]
        : [
            ["-f", this.mountpoint],
            ["-l", this.mountpoint],
          ];
    for (const args of ladder) {
      // Only a table that says it is gone stops the ladder — see `isMounted`.
      if ((await this.#mounted()) === false) {
        break;
      }
      await run("umount", args).catch(() => {
        // Nothing to add: the mount table is the verdict.
      });
    }
    // Dropping the connections is itself a way out — a `soft` mount gives up
    // once the server stops answering — so the server goes down either way.
    await this.#finish();
    await delay(0);
    throw error;
  }

  /** Stop serving and forget the mount. Idempotent. */
  async #finish(): Promise<void> {
    this.#stopping = true;
    live.delete(this);
    if (live.size === 0) {
      removeSignalHandlers();
    }
    await this.server.close();
  }
}
