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
 * **A client, and — on Linux — root.** `mount(2)` is not a syscall Node can
 * issue, and there is no setuid helper for NFS the way `fusermount3` is one for
 * FUSE, so this spawns `mount(8)` and needs the host to have an NFS *client*:
 * the `nfs` module in the kernel and the `/sbin/mount.nfs` helper from
 * `nfs-utils`. Neither is something the server can provide, so
 * {@link nfsClientProbe} exists to say which is missing before anything is
 * spawned.
 *
 * Root is the Linux half of that and **not** the macOS half. `/sbin/mount_nfs`
 * is not setuid and needs no privilege: macOS is a BSD, and a BSD lets an
 * ordinary user mount onto a directory that user owns. The same spawn works
 * either way, so the unprivileged path here is not a second implementation —
 * it is the same one with a different precondition, checked by
 * {@link ownershipRefusal} because it is a fact about the mountpoint rather
 * than about the host.
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
 *   the lazy step — and the advice to run it — is Linux-only. It is also
 *   weaker than it looks: macOS puts network volumes behind a sandbox approval
 *   the user has to have granted in advance (Full Disk Access for whatever app
 *   the process is attributed to), and an ungranted process gets a `umount`
 *   that never returns or a `umount -f` that fails with `EPERM` — no prompt is
 *   ever shown. There is no escalation past that, so the transport bounds both
 *   steps, names the gate when it sees it ({@link isConsentDenial},
 *   {@link consentAdvice}), and says plainly that the mount survived.
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
 * **Two versions.** `version: "4.1"` mounts the same server's NFSv4.1 side
 * instead, on Linux only (see {@link versionRefusal}). Nothing above changes
 * except the two options that were about the protocols v4 folded in: it has no
 * MOUNT program to point a `mountport=` at and no NLM to keep out, and `nfs(5)`
 * lists both options as version-2-and-3-only, so both are absent from that
 * branch. The rest — `soft`, `timeo`, `retrans`, `ro` — is `nfs(5)`'s "options
 * supported by all versions" and is emitted the same way for both.
 *
 * One consequence worth knowing before reading a mount table: Linux registers
 * its version-4 client as a *separate filesystem type*, so a `vers=4.1` mount
 * made by `mount -t nfs` is listed in `/proc/self/mounts` with type `nfs4`.
 * Nothing here matches on the type — teardown asks about the mountpoint — but
 * anything that grows such a match has to cover both spellings.
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
import { nfsClientProbe, type NfsPlatform, nfsPlatform } from "./probe.ts";
import { createNfsServer, type NfsServer, type NfsServerOptions } from "./server.ts";

/** Signals a mount cleans up on. `SIGHUP` is deliberately not one. */
const TEARDOWN_SIGNALS = ["SIGINT", "SIGTERM"] as const;

// The probe and its platform types live in `probe.ts`, which imports nothing
// but `node:fs` — see the note there. Re-exported so `mountx/nfs` is one
// import either way.
export { nfsClientProbe, type NfsClientProbe, type NfsPlatform } from "./probe.ts";

/**
 * The NFS version to mount with, as `mount(8)`'s `vers=` would spell it.
 *
 * `3` is the default and is what both hosts get. `"4.1"` is the only v4 flavour
 * this server speaks — the minor version is fixed, because `src/nfs/v4/` answers
 * `NFS4ERR_MINOR_VERS_MISMATCH` to anything else — and it is Linux-only; see
 * {@link versionRefusal}.
 */
export type NfsVersion = 3 | "4.1";

export interface MountNfsOptions extends NfsServerOptions {
  /**
   * Which version the client should mount with. Default `3`.
   *
   * The server answers both on the one socket whatever this says; the option
   * decides only what the *client* is told to ask for.
   */
  version?: NfsVersion;
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
 * Serve `driver` over NFS and mount it at `mountpoint`.
 *
 * NFSv3 by default, NFSv4.1 with `version: "4.1"` — the server answers both on
 * the one socket either way, so this decides only what the client asks for.
 *
 * Resolves once `mount(8)` has returned successfully, which for NFS means the
 * client has already talked to the server — a MOUNT and an FSINFO on v3, an
 * EXCHANGE_ID/CREATE_SESSION and a first COMPOUND on v4.1 — so a resolved
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
  // Both version refusals, before a socket is opened: one is about the host
  // (A1, macOS), one about what its client has.
  const refusedVersion = versionRefusal(platform, options.version);
  if (refusedVersion !== undefined) {
    throw new Error(refusedVersion);
  }
  if (options.version === "4.1" && !probe.v4) {
    throw new Error(
      `mountx: this host has no NFSv4 client — no \`nfs4\` in /proc/filesystems and no ` +
        `mount.nfs to load it on demand (install nfs-common / nfs-utils). The same driver ` +
        `mounts over NFSv3 with the default \`version: 3\`.`,
    );
  }
  const resolved = resolveNative(mountpoint);
  const targetStat = await statPath(resolved).catch((error: unknown) => {
    throw new Error(`mountx: mountpoint ${resolved} is not usable: ${errorMessage(error)}`);
  });
  if (!targetStat.isDirectory()) {
    throw new Error(`mountx: mountpoint ${resolved} is not a directory`);
  }
  // The one precondition the probe cannot answer, because it is about this
  // path rather than about this host. Checked before anything is listening.
  const refusal = ownershipRefusal(
    platform,
    resolved,
    targetStat.uid,
    process.getuid?.() ?? targetStat.uid,
  );
  if (refusal !== undefined) {
    throw new Error(refusal);
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
 *
 * Exported for the CLI's stale-mount cleanup, which asks the same question
 * about a path nothing in this process mounted: macOS has no mount table to
 * read, only a `mount(8)` to spawn, and the tri-state that comes with it is
 * exactly the distinction that caller needs too. Kept off `mountx/nfs`'s
 * surface for the same reason {@link parseMountTable} is.
 */
export async function mountEntryAt(
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
  /** The deadline passed with the child still running. See {@link run}. */
  timedOut: boolean;
}

/**
 * Run a command and collect both its streams.
 *
 * `timeout` **settles** the promise rather than rejecting or waiting for the
 * child, and this is the part that matters: a `umount(8)` blocked inside the
 * kernel does not die on `SIGKILL`, so a run that waited for `close` would
 * never return and a caller that moved on without one would leave a child
 * behind, still holding the very mount the caller is about to escalate
 * against. The kill is sent because usually it works; the result is reported
 * either way, with `timedOut` saying which happened.
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
      timeout === undefined
        ? undefined
        : setTimeout(() => {
            child.kill("SIGKILL");
            // Let go of it completely: an unkillable child must not keep this
            // process's event loop alive after the caller has given up on it.
            child.stdout?.destroy();
            child.stderr?.destroy();
            child.unref();
            resolvePromise({
              status: null,
              signal: null,
              stdout,
              stderr: stderr.trim(),
              timedOut: true,
            });
          }, timeout);
    timer?.unref();
    child.once("error", (error) => {
      clearTimeout(timer);
      rejectPromise(error);
    });
    child.once("close", (status, signal) => {
      clearTimeout(timer);
      resolvePromise({ status, signal, stdout, stderr: stderr.trim(), timedOut: false });
    });
  });
}

function describe(command: string, result: SpawnResult): string {
  const how = result.timedOut
    ? "no answer before the deadline, still running"
    : result.signal === null
      ? `exit ${result.status}`
      : `signal ${result.signal}`;
  return result.stderr === "" ? `${command}: ${how}` : `${command}: ${how}: ${result.stderr}`;
}

/**
 * Does this `umount(8)` failure look like macOS refusing at its consent gate?
 *
 * macOS puts access to *network volumes* — which is what an NFS mount is,
 * loopback or not — behind a sandbox approval, and both `vnode_check_open` and
 * `mount_check_umount` go through it (witnessed on 26.6: the kernel stack of a
 * hung `umount` is `hook_mount_check_umount` → `approval_solicit` →
 * `__WAITING_ON_APPROVAL_FROM_SANDBOXD__`). A process the user has not granted
 * that access gets one of two answers, and this recognizes the second:
 *
 * - attributed to a GUI app, the call blocks waiting for an approval that is
 *   never solicited on screen — so `umount` simply never returns;
 * - attributed to nothing (launchd, a CI agent), it is refused outright with
 *   `EPERM`, which `umount(8)` prints as "Operation not permitted".
 *
 * Pure, and exported for the Tier-0 test: the host that can check this is not
 * the host that can reproduce it.
 */
export function isConsentDenial(platform: NfsPlatform, stderr: string): boolean {
  return platform === "darwin" && /operation not permitted/i.test(stderr);
}

/**
 * Why macOS will refuse this mountpoint to this user, if it will.
 *
 * The BSD rule an unprivileged mount lives under: the caller must own the
 * directory. Verified on macOS 26.6 — a mountpoint owned by root refuses with
 * `mount_nfs: … Operation not permitted` even though the very same command
 * succeeds one directory over. Root is exempt, and Linux never reaches here
 * (the probe already refused), so this is a darwin-and-not-root question.
 *
 * Pure and exported so a Tier-0 test can hold both answers from either host.
 */
export function ownershipRefusal(
  platform: NfsPlatform,
  mountpoint: string,
  ownerUid: number,
  callerUid: number,
): string | undefined {
  if (platform !== "darwin" || callerUid === 0 || ownerUid === callerUid) {
    return undefined;
  }
  return (
    `mountx: macOS lets an ordinary user mount only onto a directory that user owns, and ` +
    `${mountpoint} belongs to uid ${ownerUid} while this process is uid ${callerUid}. Mount ` +
    `somewhere you own — a directory you created yourself — or run as root.`
  );
}

/**
 * Why this host will not be asked for this NFS version, if it will not.
 *
 * One case, and it is an assumption rather than an observation: **macOS is
 * treated as NFSv4.0-only**. Its client is not known to speak 4.1, and 4.1 is
 * the only minor version this server serves, so asking `mount_nfs` for it would
 * produce either a 4.0 mount this server refuses op by op
 * (`NFS4ERR_MINOR_VERS_MISMATCH`) or an unhelpful failure from the helper. macOS
 * mounts v3, which works there and is the default anyway. If a mac turns out to
 * speak 4.1, deleting this refusal is the whole change.
 *
 * Pure and exported so a Tier-0 test can hold both answers from either host,
 * the way {@link ownershipRefusal} is.
 */
export function versionRefusal(platform: NfsPlatform, version: NfsVersion = 3): string | undefined {
  if (version === 3 || platform !== "darwin") {
    return undefined;
  }
  return (
    `mountx: NFSv4.1 mounts are Linux-only — macOS is treated as NFSv4.0-only, and 4.1 is the ` +
    `only minor version this server speaks. Mount with the default \`version: 3\` here; the ` +
    `same driver is served over both.`
  );
}

/** What to do about a mount macOS will not let this process take down. */
export function consentAdvice(mountpoint: string): string {
  return (
    `macOS gates network volumes behind a sandbox approval and shows no prompt for a ` +
    `command-line process, so this is a grant that has to be made in advance: give the app ` +
    `that runs this process — your terminal, or the CI agent — Full Disk Access under System ` +
    `Settings → Privacy & Security, then retry. Until then \`sudo umount -f ${mountpoint}\` ` +
    `fails the same way and a reboot is the only other way out.`
  );
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
 *
 * `options.version` picks the branch, and the v4.1 one is shorter by exactly
 * the two options `nfs(5)` documents under "options for NFS versions 2 and 3
 * only" — `mountport`, which points at a MOUNT program version 4 has no
 * equivalent of, and `nolock`, which keeps out an NLM version 4 folded into
 * itself. What it deliberately does *not* add is `clientaddr=`: `nfs(5)` says
 * the mount command discovers the callback address itself when the option is
 * absent, this server never originates a callback (no delegations, no pNFS, no
 * backchannel asked for at CREATE_SESSION), and a hard-coded `127.0.0.1` would
 * be wrong the moment `host` is not the loopback address. Since it throws for
 * the one refused combination, it is the same answer {@link mountNfs} would
 * reach — see {@link versionRefusal}.
 */
export function nfsMountOptions(
  port: number,
  options: MountNfsOptions = {},
  platform: NfsPlatform = nfsPlatform(process.platform) ?? "linux",
): string {
  const darwin = platform === "darwin";
  const refusal = versionRefusal(platform, options.version);
  if (refusal !== undefined) {
    throw new Error(refusal);
  }
  const parts =
    options.version === "4.1"
      ? [
          // One option, two numbers, and they travel in different places: the
          // RPC header says version 4 whichever minor version this is, and the
          // `.1` is what makes the client put `minorversion = 1` inside every
          // COMPOUND — the field `src/nfs/v4/session.ts` insists on.
          "vers=4.1",
          // Redundant (v4 requires a stream transport, and `nfs(5)` defaults to
          // TCP) and kept anyway, so the option string stays a complete
          // description of the mount rather than one that relies on defaults.
          "proto=tcp",
          `port=${port}`,
        ]
      : [
          "vers=3",
          // This covers the MOUNT protocol as well as NFS, which matters because
          // the server is TCP-only: macOS documents `mntudp` as forcing MOUNT to
          // UDP "even for TCP NFS mounts", so by default MOUNT follows NFS onto
          // TCP.
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
      //
      // `-t nfs` for both versions: `nfs(5)` documents `nfs4` as a deprecated
      // filesystem type and `-t nfs -o nfsvers=4` as how to ask for version 4.
      // The mount that comes back is still listed as type `nfs4` — see the
      // module docs.
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
    const bounded = Number.isFinite(timeout) && timeout > 0;
    let failure: unknown;
    // Bounded, `umount(8)` gets the whole deadline: the race below is what
    // covers the mount-table reads around it, not the unmount itself.
    const steps = this.#unmountSteps(bounded ? timeout : undefined).then(
      (outcome) => outcome,
      (error: unknown) => {
        failure = error;
        return "failed" as const;
      },
    );
    if (!bounded) {
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
    // "timeout" is the same situation as "expired", reached the better way:
    // `umount(8)` never answered and is no longer running on our behalf.
    if (outcome === "expired" || outcome === "timeout") {
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

  /**
   * `umount(8)`, under `deadline`. `"timeout"` means it never answered — the
   * caller escalates; anything genuinely wrong throws.
   */
  async #unmountSteps(deadline: number | undefined): Promise<"done" | "timeout"> {
    if ((await this.#mounted()) === false) {
      // Someone else already unmounted us.
      return "done";
    }
    let result: SpawnResult;
    try {
      result = await run("umount", [this.mountpoint], deadline);
    } catch (error) {
      throw new Error(`mountx: could not run umount(8): ${errorMessage(error)}`);
    }
    if (result.timedOut) {
      return "timeout";
    }
    // A failure that raced an external unmount is not a failure. A table that
    // will not say is not that race: the mount is presumed live.
    if (result.status === 0 || (await this.#mounted()) === false) {
      return "done";
    }
    throw new Error(
      `mountx: could not unmount ${this.mountpoint} (${describe("umount", result)}). ` +
        `The mount is still live. ${this.#stuckAdvice(result.stderr)}`,
    );
  }

  /**
   * How to get rid of a mount this process could not, on this host.
   *
   * `stderr` is the failed `umount(8)`'s, and on macOS it decides the answer:
   * "Operation not permitted" is the consent gate rather than a busy
   * mountpoint, and every piece of the usual advice is wrong for it — no
   * process is holding the mount, and `umount -f` fails identically.
   */
  #stuckAdvice(stderr = ""): string {
    if (isConsentDenial(this.#platform, stderr)) {
      return consentAdvice(this.mountpoint);
    }
    return this.#platform === "darwin"
      ? `If a process is holding it, \`lsof ${this.mountpoint}\` will say which; ` +
          `\`sudo umount -f ${this.mountpoint}\` detaches it unless macOS refuses that too ` +
          `(see \`consentAdvice\`).`
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
    const darwin = this.#platform === "darwin";
    const lazy = darwin ? "-f" : "-l";
    const error = new Error(
      `mountx: unmounting ${this.mountpoint} did not finish within ${timeout}ms — the ` +
        `driver has probably stopped answering.` +
        (darwin
          ? ` On macOS a \`umount\` that never answers is also what the network-volume ` +
            `consent gate looks like; the forcing below is what tells the two apart.`
          : "") +
        ` The mount has been forced down, so anything in flight was lost. If the mountpoint ` +
        `is somehow still listed: sudo umount ${lazy} ${this.mountpoint}`,
    );
    this.#options.onTransportError?.(error, undefined);
    const ladder = darwin
      ? [["-f", this.mountpoint]]
      : [
          ["-f", this.mountpoint],
          ["-l", this.mountpoint],
        ];
    let denied: SpawnResult | undefined;
    for (const args of ladder) {
      // Only a table that says it is gone stops the ladder — see `isMounted`.
      if ((await this.#mounted()) === false) {
        break;
      }
      // Bounded for the same reason the first `umount` is: a step that never
      // returns must not outlive the ladder it is a step of.
      const result = await run("umount", args, timeout).catch(() => undefined);
      if (result !== undefined && isConsentDenial(this.#platform, result.stderr)) {
        denied = result;
      }
    }
    // Dropping the connections is itself a way out — a `soft` mount gives up
    // once the server stops answering — so the server goes down either way.
    await this.#finish();
    await delay(0);
    if (denied !== undefined) {
      // Not a guess: `umount -f` said `EPERM` while the mount was plainly
      // still listed, which is the one outcome the ladder cannot recover from.
      throw new Error(
        `mountx: ${this.mountpoint} could not be unmounted ` +
          `(${describe("umount -f", denied)}), and the server behind it has been shut down — ` +
          `the mountpoint is now a live mount with nothing answering it. ` +
          consentAdvice(this.mountpoint),
      );
    }
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
