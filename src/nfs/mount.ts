/**
 * Mounting the NFS server with `mount(8)`.
 *
 * The transport is `server.ts`; this file is the convenience that puts a
 * kernel NFS client in front of it, and it is the second file in the library
 * that spawns a process.
 *
 * ```ts
 * import { mountNfs } from "unimount/nfs";
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
 * **No portmapper.** Both programs are on one port and the mount command is
 * told so with `port=` *and* `mountport=`, so `rpcbind` is never contacted.
 * `nolock` keeps `lockd`/`rpc.statd` out of it too — NFSv3 file locking is a
 * separate protocol (NLM) that this server does not implement, and a client
 * that tried to use it would hang waiting for a service that is not there.
 *
 * **`soft` by default.** A hard mount retries forever, which is right when the
 * server is a machine that may reboot and wrong when the server is a JavaScript
 * object in the process doing the mounting: a bug in the driver would produce
 * unkillable `D`-state processes instead of an `EIO`. This is the same reasoning
 * the FUSE transport's unmount deadline comes from.
 *
 * Teardown follows the FUSE transport's discipline exactly, and for the same
 * reasons: `umount(8)` first, `/proc/self/mounts` is the truth rather than an
 * exit status, `umount -f` then `-l` when the deadline passes, and the whole
 * thing is idempotent and retryable.
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import { stat as statPath } from "node:fs/promises";
import { resolve as resolveNative } from "node:path";
import type { FsDriver } from "../types.ts";
import { createNfsServer, type NfsServer, type NfsServerOptions } from "./server.ts";

/** Signals a mount cleans up on. `SIGHUP` is deliberately not one. */
const TEARDOWN_SIGNALS = ["SIGINT", "SIGTERM"] as const;

/** What this host can and cannot do about mounting NFS. */
export interface NfsClientProbe {
  /** Can an NFS filesystem be mounted here at all? */
  usable: boolean;
  /** Path of the `mount.nfs` helper, if there is one. */
  helper: string | undefined;
  /** Does the kernel list `nfs` in `/proc/filesystems`? */
  kernel: boolean;
  /** Are we root? */
  root: boolean;
  /** Everything that is missing, in a sentence. */
  reason: string | undefined;
}

const MOUNT_NFS_PATHS = ["/sbin/mount.nfs", "/usr/sbin/mount.nfs", "/usr/local/sbin/mount.nfs"];

/**
 * Can this host mount NFS?
 *
 * Synchronous and cheap, so a test can gate itself on it and a mount can fail
 * with a message that names the missing piece instead of `mount: wrong fs type`.
 *
 * Note that the kernel check is deliberately weak: `nfs` appears in
 * `/proc/filesystems` only once the module is loaded, and `mount.nfs` loads it
 * on demand — so a host with the helper and a loadable module reports
 * `kernel: false` and is still usable. What is *not* usable is a host with
 * neither, which is what this actually distinguishes.
 */
export function nfsClientProbe(): NfsClientProbe {
  const root = (process.getuid?.() ?? -1) === 0;
  const helper = MOUNT_NFS_PATHS.find((path) => {
    try {
      fs.accessSync(path, fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
  let kernel = false;
  try {
    kernel = /\bnfs\b/.test(fs.readFileSync("/proc/filesystems", "utf8"));
  } catch {
    kernel = false;
  }
  const missing: string[] = [];
  if (process.platform !== "linux") {
    missing.push(`this is ${process.platform}, not Linux`);
  }
  if (!root) {
    missing.push("mounting NFS needs root and this process is not root");
  }
  if (helper === undefined && !kernel) {
    missing.push(
      "no /sbin/mount.nfs (install nfs-common / nfs-utils) and no `nfs` in /proc/filesystems",
    );
  }
  return {
    usable: missing.length === 0,
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
  /** Tenths of a second before an NFS request is retried. Default `50` (5 s). */
  timeo?: number;
  /** Retries before a `soft` mount gives up with `EIO`. Default `2`. */
  retrans?: number;
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
  /** What `/proc/mounts` shows as the device, e.g. `127.0.0.1:/`. */
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
    console.error(`unimount: NFS unmount on ${signal} failed: ${errorMessage(failure)}`);
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
  if (!probe.usable) {
    throw new Error(`unimount: cannot mount NFS here — ${probe.reason}`);
  }
  const target = resolveNative(mountpoint);
  const targetStat = await statPath(target).catch((error: unknown) => {
    throw new Error(`unimount: mountpoint ${target} is not usable: ${errorMessage(error)}`);
  });
  if (!targetStat.isDirectory()) {
    throw new Error(`unimount: mountpoint ${target} is not a directory`);
  }
  // Same trap as the FUSE transport: Linux stacks mounts, and then `umount`
  // detaches the *top* one.
  for (const existing of live) {
    if (existing.mountpoint === target) {
      throw new Error(
        `unimount: ${target} is already mounted by this process. Unmount it before mounting again.`,
      );
    }
  }
  const occupant = mountEntryAt(target);
  if (occupant !== undefined) {
    throw new Error(
      `unimount: ${target} already has a filesystem on it (${occupant.source}, type ` +
        `${occupant.type}). Clear it first: umount ${target}`,
    );
  }

  const server = options.server ?? createNfsServer(driver, options);
  await server.listen();
  const impl = new NfsMountImpl(server, target, options);
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

interface MountEntry {
  source: string;
  target: string;
  type: string;
}

/** What is mounted at `target`, or `undefined`. The last matching line wins. */
function mountEntryAt(target: string): MountEntry | undefined {
  let table: string;
  try {
    table = fs.readFileSync("/proc/self/mounts", "utf8");
    /* v8 ignore next 3 -- no procfs is stranger than an unmounted filesystem. */
  } catch {
    return undefined;
  }
  let found: MountEntry | undefined;
  for (const line of table.split("\n")) {
    const [source = "", path = "", type = ""] = line.split(" ");
    if (unescapeMountPath(path) === target) {
      found = { source: unescapeMountPath(source), target, type };
    }
  }
  return found;
}

function isMounted(target: string): boolean {
  return mountEntryAt(target) !== undefined;
}

interface SpawnResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
}

function run(command: string, args: readonly string[]): Promise<SpawnResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, [...args], { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("error", rejectPromise);
    child.once("close", (status, signal) => {
      resolvePromise({ status, signal, stderr: stderr.trim() });
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
  #stopping = false;
  #unmounting: Promise<void> | undefined;

  constructor(server: NfsServer, mountpoint: string, options: MountNfsOptions) {
    this.server = server;
    this.mountpoint = mountpoint;
    this.#options = options;
    const exported = options.exportPath ?? "/";
    if (/[\s,]/.test(exported)) {
      throw new Error(
        `unimount: \`exportPath\` may not contain whitespace or a comma — it is the source ` +
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
    const options = this.#mountOptions();
    let result: SpawnResult;
    try {
      // Deliberately *not* `-i`: unlike FUSE, the NFS mount genuinely wants its
      // `/sbin/mount.nfs` helper, which is what resolves the host into the
      // `addr=` the kernel needs and negotiates the version.
      result = await run("mount", ["-t", "nfs", "-o", options, this.source, this.mountpoint]);
    } catch (error) {
      throw new Error(`unimount: could not run mount(8): ${errorMessage(error)}`);
    }
    if (result.status !== 0) {
      throw new Error(
        `unimount: mounting ${this.mountpoint} failed — ` +
          `${describe(`mount -t nfs -o ${options}`, result)}`,
      );
    }
    live.add(this);
    if (this.#options.signals !== false) {
      installSignalHandlers();
    }
  }

  #mountOptions(): string {
    const port = this.server.port;
    const parts = [
      "vers=3",
      "proto=tcp",
      // The two that make a portmapper unnecessary: both programs are here.
      `port=${port}`,
      `mountport=${port}`,
      // NLM is a separate protocol this server does not implement; a client
      // that tried to lock would wait for a service that does not exist.
      "nolock",
      this.#options.hard === true ? "hard" : "soft",
      // `NaN` would floor to a literal `timeo=NaN` in the option string, which
      // `mount(8)` rejects with a message about nothing in particular. Same
      // guard the FUSE transport puts on `readers`.
      `timeo=${count(this.#options.timeo, 50, 1)}`,
      `retrans=${count(this.#options.retrans, 2, 0)}`,
    ];
    if (this.#options.readOnly === true) {
      parts.push("ro");
    }
    parts.push(...(this.#options.mountOptions ?? []));
    return parts.join(",");
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
    if (!isMounted(this.mountpoint)) {
      // Someone else already unmounted us.
      return;
    }
    let result: SpawnResult;
    try {
      result = await run("umount", [this.mountpoint]);
    } catch (error) {
      throw new Error(`unimount: could not run umount(8): ${errorMessage(error)}`);
    }
    // A failure that raced an external unmount is not a failure.
    if (result.status === 0 || !isMounted(this.mountpoint)) {
      return;
    }
    throw new Error(
      `unimount: could not unmount ${this.mountpoint} (${describe("umount", result)}). ` +
        `The mount is still live. If a process is holding it, \`fuser -m ${this.mountpoint}\` ` +
        `will say which; \`sudo umount -l ${this.mountpoint}\` detaches it regardless.`,
    );
  }

  /**
   * Teardown when asking nicely did not work.
   *
   * `umount -f` is the one that matters for NFS — it is what the option was
   * invented for — and `umount -l` covers the table entry that outlives it.
   * The exit statuses are not believed; `/proc/self/mounts` is.
   */
  async #force(timeout: number): Promise<void> {
    const error = new Error(
      `unimount: unmounting ${this.mountpoint} did not finish within ${timeout}ms — the ` +
        `driver has probably stopped answering. The mount has been forced down, so anything ` +
        `in flight was lost. If the mountpoint is somehow still listed: ` +
        `sudo umount -l ${this.mountpoint}`,
    );
    this.#options.onTransportError?.(error, undefined);
    for (const args of [
      ["-f", this.mountpoint],
      ["-l", this.mountpoint],
    ]) {
      if (!isMounted(this.mountpoint)) {
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
