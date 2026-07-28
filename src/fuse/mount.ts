/**
 * The FUSE transport: `/dev/fuse`, a real mountpoint, and the read/reply loop.
 *
 * This file and `fusermount.ts` are the only ones that touch a device or spawn
 * a process. Everything below them — protocol, session, drivers — is bytes in,
 * bytes out, which is why all of it is testable with no root and no kernel.
 *
 * ```ts
 * import { mount } from "mountx/fuse";
 * import { createMemoryDriver } from "mountx/drivers/memory";
 *
 * await using mounted = await mount(createMemoryDriver(), "/mnt/point");
 * // ... /mnt/point is live until unmount() or the process exits ...
 * ```
 *
 * **Two ways in, chosen by uid.** `mount(2)` is not a syscall Node can issue,
 * and the way around it depends on who is asking.
 *
 * As root, getting the fd is pure JS (`/dev/fuse` is mode 0666 everywhere) and
 * stock `mount(8)` does the rest: the `fd=N` mount option resolves in the
 * *caller's* fd table, and fds are inheritable, so the child mounts and exits
 * while the parent keeps its copy of the descriptor for the loop.
 *
 * As anyone else, `fusermount3` does both — it opens the device and issues the
 * `mount(2)`, then sends the descriptor back over `SCM_RIGHTS`. Receiving it is
 * the one thing Node cannot do, and the only reason this library has native
 * code; see `fusermount.ts` and `native.ts`. Everything from here down is
 * identical either way, because what comes back is the same descriptor.
 *
 * **fd lifecycle, which is also the crash-safety story.** The kernel tears the
 * connection down when the last reference to the `/dev/fuse` file goes away, so
 * a killed process cannot leave a mountpoint that hangs on `ls` — it leaves one
 * that answers `ENOTCONN`, which `umount` clears without ceremony. That
 * guarantee only holds if nothing else keeps the descriptor alive, so the fd is
 * close-on-exec on both paths (libuv's default when this process opens it,
 * `MSG_CMSG_CLOEXEC` when `fusermount3` sends it) and is handed to exactly one
 * child, `mount(8)`, which exits immediately. Every other spawn runs without
 * it. `-o auto_unmount` is not used, so the stale *mount table entry* does
 * survive a crash; recovery is one command, and it is named in the error
 * messages here.
 *
 * **Serving a mount and using it from the same process is the sharp edge**, and
 * it has two forms. The first is obvious once seen: anything *synchronous* —
 * `readFileSync`, `execFileSync("ls", [mountpoint])`, `spawnSync` — blocks the
 * main thread inside a syscall that cannot complete until the main thread
 * answers the request it just generated. No amount of tuning fixes that one.
 *
 * The second is quieter. Every *asynchronous* `fs` call against your own
 * mountpoint also parks a `UV_THREADPOOL_SIZE` thread for the whole round trip,
 * and the read loop needs one of those threads to pick up the request. Reach
 * the pool limit and the process wedges: the main thread idles in `epoll_wait`
 * while every pool thread waits in `request_wait_answer` for a reply nobody can
 * read the request for. One call is enough to do it — `fs.rm(dir, { recursive:
 * true })` fans out over a directory, so a 200-entry tree is 200 concurrent
 * unlinks. Keep self-directed concurrency well under `UV_THREADPOOL_SIZE`, or
 * put the client in another process, where none of this applies. (Relay mode
 * makes the fd a socket and the whole problem disappears; it is a later
 * milestone. IDEA.md, "Concurrency".)
 *
 * The third form has nothing to do with the threadpool and is the meanest of
 * the three: **`child_process.spawn(…, { cwd })` with a `cwd` inside your own
 * mountpoint deadlocks immediately**, before any of the child's work begins.
 * `uv_spawn` forks, has the *child* `chdir` into `cwd` before it execs, and
 * blocks the **parent's main thread** on a pipe until that exec happens — so
 * the `LOOKUP` the `chdir` generates is waiting on the one thread that could
 * answer it. It is not a race; it hangs every time, and `spawn` is
 * asynchronous everywhere else, which is what makes it surprising. Move the
 * `chdir` past the `exec` — `spawn("sh", ["-c", 'cd "$1" && exec …', "sh",
 * mountpoint])` — or run the child from somewhere else entirely.
 *
 * **Exiting: `await unmount()`, and do not reach for `process.exit()`.** Node's
 * exit path joins the threadpool, and a live mount always has K reads parked in
 * it, so `process.exit()` does not return — it hangs until the connection is
 * torn down, and then needs a `SIGKILL` (measured: 25 s and still going). This
 * is why the signal handlers here unmount and then *re-raise* the signal rather
 * than calling `process.exit()`: by the time the default action runs there are
 * no parked reads left. Application code wanting a specific exit code should
 * `await mount.unmount()` first and set `process.exitCode`.
 */

import * as fs from "node:fs";
import { stat as statPath } from "node:fs/promises";
import { resolve as resolveNative } from "node:path";
import type { FsDriver } from "../types.ts";
import { S_IFDIR, S_IFMT } from "../types.ts";
import { FUSE_MAX_MAX_PAGES, FUSE_MIN_READ_BUFFER, FUSE_PAGE_SIZE } from "./constants.ts";
import { describe, errorMessage, run, type SpawnResult, stdioWith } from "./exec.ts";
import { mountViaFusermount, rootlessProbe, unmountViaFusermount } from "./fusermount.ts";
import { DEFAULT_MAX_WRITE } from "./init.ts";
import { FuseSession, type FuseSessionOptions } from "./session.ts";

/**
 * Slack above `max_write` in a receive buffer, libfuse's `FUSE_BUFFER_HEADER_SIZE`.
 *
 * The kernel writes one whole message per `read(2)` and answers a request that
 * does not fit with `-EIO` rather than a short read, so the buffer has to hold
 * the largest `WRITE` the handshake agreed on plus its headers. 4 KiB of slack
 * is what libfuse uses and is an order of magnitude more than the ~100 bytes
 * actually needed.
 */
const FUSE_BUFFER_HEADER_SIZE = 4096;

/** Signals a mount cleans up on. `SIGHUP` is deliberately not one: it is a reload convention. */
const TEARDOWN_SIGNALS = ["SIGINT", "SIGTERM"] as const;

export interface MountOptions extends FuseSessionOptions {
  /**
   * Reads kept outstanding on `/dev/fuse`. Default `2`.
   *
   * This is the concurrency knob, and it is a *threadpool* knob. `/dev/fuse` is
   * a character device, so libuv classifies it `UV_FILE` and every `fs.read`
   * parks one of the four (`UV_THREADPOOL_SIZE`) pool threads until a request
   * arrives — threads shared with all other `fs`, `dns` and `zlib` work in the
   * process, **including the driver's own I/O** if it does any. Two readers on
   * the default pool leaves two threads for a `node:fs` driver to work with;
   * four would deadlock it.
   *
   * Raise this only together with `UV_THREADPOOL_SIZE`, which must be set
   * *before the process starts* (it is read once, when the pool is first used):
   *
   * ```sh
   * UV_THREADPOOL_SIZE=32 node server.mjs   # then readers: 8 is reasonable
   * ```
   *
   * Replies do not use the pool at all — they are written synchronously, for
   * exactly this reason — so `readers` plus whatever the driver needs is the
   * whole budget.
   *
   * The relay and sync-worker modes in IDEA.md exist to make this knob go away.
   * Neither is v1.
   */
  readers?: number;
  /** What `/proc/mounts` shows as the device. Default `"mountx"`. */
  fsname?: string;
  /** Makes the mount type read `fuse.<subtype>`. Default: none. */
  subtype?: string;
  /**
   * Let the kernel enforce mode bits from `getattr`, so drivers never make
   * access decisions. Default `true`, and turning it off means the driver is
   * answering for every process on the machine.
   */
  defaultPermissions?: boolean;
  /**
   * Let users other than the mounting one in. Default `false`.
   *
   * `default_permissions` still applies, so this is not a way around mode bits.
   * Unprivileged mounts additionally need `user_allow_other` in
   * `/etc/fuse.conf`; without it `fusermount3` refuses the mount and says so.
   */
  allowOther?: boolean;
  /** Mount read-only (`-o ro`). The driver is not told; it just never sees writes. */
  readOnly?: boolean;
  /** Cap on a single `READ`, in bytes. Default: the kernel's own. */
  maxRead?: number;
  /** Extra `-o` options, appended verbatim. Escape hatch; nothing here needs it. */
  mountOptions?: readonly string[];
  /**
   * Unmount on `SIGINT`/`SIGTERM`. Default `true`.
   *
   * One handler pair per process, installed with the first mount and removed
   * with the last. If nothing else in the process listens for the signal, the
   * default action is re-raised once every mount is down, so the exit status
   * stays honest.
   */
  signals?: boolean;
  /**
   * Milliseconds to wait for the kernel's `FUSE_INIT` before giving up and
   * tearing the half-built mount down. Default `10_000`.
   */
  initTimeout?: number;
  /**
   * Milliseconds {@link Mount.unmount} may spend before it stops asking nicely
   * and forces the connection down. Default `10_000`; `0` or `Infinity` waits
   * forever.
   *
   * The thing being guarded against is a driver that stops answering. `umount(8)`
   * quiesces the filesystem before it detaches, so a request that never gets a
   * reply blocks it in `D` state — and with it `unmount()`, `await using`, and
   * the signal handlers. Ten seconds is generous for a healthy mount: writeback
   * caching is off by default, so there is nothing to flush, only in-flight
   * requests to finish. A driver that can legitimately take longer to quiesce
   * should raise it.
   */
  unmountTimeout?: number;
  /**
   * The device to open. Default `"/dev/fuse"`; a test double is the only reason
   * to change it. Root mode only — unprivileged mounts never open the device
   * themselves, so setting it is an error rather than a no-op.
   */
  device?: string;
  /**
   * Tee every byte that crosses `/dev/fuse`, in both directions. Off by default.
   *
   * `"in"` is one whole message as the kernel wrote it; `"out"` is one whole
   * reply or notification as the loop is about to write it. Nothing is copied
   * before the call, so the `Uint8Array` is a **view of a buffer that is reused
   * the moment this returns** — a recorder has to copy what it keeps.
   *
   * This is the hook `record`/`replay` is built on (IDEA.md, "Tier 0"): the
   * bytes here are exactly the ones a session has to be able to answer, which
   * makes a transcript of a real kernel a fixture that needs no kernel to
   * replay. Anything thrown is reported through {@link MountOptions.onTransportError}
   * and costs nothing else — a broken recorder must not break a mountpoint.
   */
  tap?: (direction: "in" | "out", bytes: Uint8Array) => void;
  /** Called for transport-level failures (a read or write that is not part of teardown). */
  onTransportError?: (error: unknown) => void;
}

/** A live mountpoint. */
export interface Mount extends AsyncDisposable {
  /** Absolute path of the mountpoint. */
  readonly mountpoint: string;
  /** What `/proc/mounts` shows as the device (`fsname`). */
  readonly source: string;
  /** The session answering for this mount — its `stats`, `inodes` and handles. */
  readonly session: FuseSession;
  /** The `/dev/fuse` descriptor. Open until teardown finishes. */
  readonly fd: number;
  /** `false` from the moment teardown starts, whoever started it. */
  readonly active: boolean;
  /**
   * Resolves when the loop has ended, the session is destroyed and the fd is
   * closed — whether that was {@link Mount.unmount} or someone else's
   * `umount(8)`. Never rejects; a fatal transport error surfaces through
   * `onTransportError` instead, so this can be held without a `catch`.
   */
  readonly closed: Promise<void>;
  /**
   * Unmount and tear down. Idempotent, concurrency-safe, and a no-op beyond
   * awaiting {@link Mount.closed} if the mount is already gone.
   *
   * Always settles, within `unmountTimeout`. It throws if `umount(8)` refused
   * — a busy mountpoint, essentially — or if the deadline passed and the
   * connection had to be aborted; both messages say how to recover, and a
   * failed unmount can be retried.
   */
  unmount(): Promise<void>;
  /** Drop the kernel's cached data (and optionally attributes) for one inode. */
  notifyInvalInode(ino: bigint, off?: bigint, len?: bigint): void;
  /** Drop the kernel's cached `parent`/`name` → inode mapping. */
  notifyInvalEntry(parent: bigint, name: string, flags?: number): void;
}

/** Every mount this process has up, for the signal handlers and {@link unmountAll}. */
const live = new Set<MountImpl>();
let signalsInstalled = false;

async function onTeardownSignal(signal: NodeJS.Signals): Promise<void> {
  // Removed first, so a second Ctrl-C kills the process instead of starting
  // another round of unmounts.
  removeSignalHandlers();
  // Nothing else is going to look at these, and the message on a failed
  // unmount is the one that says how to recover. Losing it to a signal
  // handler's silence is how a wedged mountpoint becomes a mystery.
  for (const failure of await unmountAll()) {
    console.error(`mountx: unmount on ${signal} failed: ${errorMessage(failure)}`);
  }
  // Nobody else is listening, so nothing will exit the process: re-raise, and
  // let the default action produce the conventional 128+n status. Note that
  // `process.exit()` would *not* work here — see the module docs.
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

/**
 * Unmount every live mount in this process.
 *
 * Never rejects: it resolves to whatever went wrong, so one stuck mountpoint
 * cannot stop the others from coming down.
 */
export async function unmountAll(): Promise<unknown[]> {
  const results = await Promise.allSettled([...live].map((mount) => mount.unmount()));
  return results
    .filter((result) => result.status === "rejected")
    .map((result) => (result as PromiseRejectedResult).reason);
}

/** The mounts this process currently has up, in creation order. */
export function liveMounts(): Mount[] {
  return [...live];
}

/**
 * Mount `driver` at `mountpoint`.
 *
 * Resolves once the kernel's `FUSE_INIT` has been answered, so a resolved
 * `mount()` means the path is usable, not merely that the mount helper exited.
 *
 * As root this needs nothing but a kernel. As anyone else it needs
 * `fusermount3` and this package's native addon, and throws before touching
 * anything if either is missing.
 */
export async function mount(
  driver: FsDriver,
  mountpoint: string,
  options: MountOptions = {},
): Promise<Mount> {
  if (process.platform !== "linux") {
    throw new Error(`mountx: FUSE mounts need Linux, this is ${process.platform}`);
  }
  const uid = process.getuid?.() ?? -1;
  if (uid !== 0) {
    const probe = rootlessProbe();
    if (!probe.usable) {
      throw new Error(
        `mountx: mounting without root needs the fusermount3 helper and mountx's native ` +
          `addon, and ${probe.reason}. The alternative is to run as root — note that ` +
          `root's PATH may lack node: sudo "$(command -v node)" script.mjs`,
      );
    }
    if (options.device !== undefined) {
      throw new Error(
        "mountx: `device` is a root-mode option — unprivileged mounting never opens the " +
          "device itself, fusermount3 does",
      );
    }
  }
  const target = resolveNative(mountpoint);
  const targetStat = await statPath(target).catch((error: unknown) => {
    throw new Error(`mountx: mountpoint ${target} is not usable: ${errorMessage(error)}`);
  });
  if (!targetStat.isDirectory()) {
    throw new Error(`mountx: mountpoint ${target} is not a directory`);
  }
  // Linux stacks mounts: mounting over a live mountpoint succeeds and hides the
  // one underneath, and then `umount` detaches whichever is on *top*. That is a
  // trap rather than a feature here — the second mount's `unmount()` would
  // destroy the first mount's connection and then wait forever for its own — so
  // it is refused, twice over: once for the mounts this process knows about,
  // and once for a FUSE mount someone else left there.
  for (const existing of live) {
    if (existing.mountpoint === target) {
      throw new Error(
        `mountx: ${target} is already mounted by this process. Unmount it before mounting again.`,
      );
    }
  }
  const occupant = mountEntryAt(target);
  if (occupant !== undefined && occupant.type.startsWith("fuse")) {
    throw new Error(
      `mountx: ${target} already has a FUSE filesystem on it (${occupant.source}, type ` +
        `${occupant.type}). Mounting over it would stack a second mount and make either ` +
        `unmount detach the wrong one. Clear it first: umount ${target}`,
    );
  }

  const session = new FuseSession(driver, options);
  // `rootmode` is how the kernel builds the root inode before it has ever
  // spoken to us, and it is parsed as octal. It must agree with what `GETATTR`
  // on nodeid 1 will say, or the VFS refuses to descend into the mount.
  const rootStat = await session.driver.stat("/").catch((error: unknown) => {
    throw new Error(`mountx: the driver cannot stat its own root: ${errorMessage(error)}`);
  });
  const rootMode = Number(rootStat.mode);
  if ((rootMode & S_IFMT) !== S_IFDIR) {
    throw new Error(
      `mountx: the driver's root must be a directory, its mode is 0o${rootMode.toString(8)}`,
    );
  }

  const impl = new MountImpl(session, target, options, uid !== 0);
  await impl.start(rootMode, uid);
  return impl;
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : undefined;
}

/** `/proc/self/mounts` escapes these four characters in paths. */
function unescapeMountPath(path: string): string {
  return path.replace(/\\(?:040|011|012|134)/g, (match) =>
    String.fromCharCode(Number.parseInt(match.slice(1), 8)),
  );
}

/** One line of `/proc/self/mounts`. */
interface MountEntry {
  source: string;
  target: string;
  type: string;
}

/**
 * What is mounted at `target`, or `undefined`.
 *
 * The *last* matching line wins: mounts stack, and the one the kernel resolves
 * — and the one `umount` would detach — is the topmost.
 */
function mountEntryAt(target: string): MountEntry | undefined {
  let table: string;
  try {
    table = fs.readFileSync("/proc/self/mounts", "utf8");
    /* v8 ignore next 4 -- no procfs, which on Linux means something stranger
       than an unmounted filesystem is going on. */
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

/** Is anything mounted at `target` right now? An unreadable `/proc` reads as no. */
function isMounted(target: string): boolean {
  return mountEntryAt(target) !== undefined;
}

/**
 * Reject anything that would not survive being joined into a `-o` list.
 *
 * `fsname` and `subtype` are the two *scalar* options that carry user strings,
 * and a comma in either of them is not a quoting bug but an *injection*: it
 * would silently add mount options to the string handed to `mount(8)`. A
 * leading dash is the same mistake one argument to the left — `fsname` is also
 * passed positionally, where a dash makes it an option instead.
 *
 * `mountOptions` is a third carrier and deliberately unchecked: adding options
 * is the whole point of it, it goes in as one argv element so it cannot reach
 * past the `-o` list, and what is *acceptable* there is `fusermount3`'s call to
 * make on the rootless path — it has the allowlist, and it forces
 * `MS_NOSUID|MS_NODEV` whatever it is given.
 */
function checkMountToken(name: string, value: string | undefined): string | undefined {
  if (value === undefined) {
    return value;
  }
  if (/[,=\s]/.test(value)) {
    throw new Error(
      `mountx: \`${name}\` may not contain a comma, an equals sign or whitespace — ` +
        `it is joined into the mount option list, where those separate options ` +
        `(got ${JSON.stringify(value)})`,
    );
  }
  if (value.startsWith("-")) {
    throw new Error(
      `mountx: \`${name}\` may not begin with a dash — it is also passed to mount(8) as ` +
        `an argument, where that would make it an option (got ${JSON.stringify(value)})`,
    );
  }
  return value;
}

class MountImpl implements Mount {
  readonly mountpoint: string;
  readonly source: string;
  readonly session: FuseSession;
  readonly closed: Promise<void>;

  readonly #options: MountOptions;
  /** Mounting through `fusermount3` rather than as root. Fixed at construction. */
  readonly #rootless: boolean;
  readonly #readers: number;
  readonly #buffers: Buffer[] = [];
  #fd = -1;
  /** Reads handed to the threadpool and not yet completed. */
  #pending = 0;
  /** Set once teardown has begun: no re-arming, no writes, no new work. */
  #stopping = false;
  #finished = false;
  #closedResolve!: () => void;
  #drained: (() => void) | undefined;
  #unmounting: Promise<void> | undefined;
  #ready: ((error?: Error) => void) | undefined;
  /** Teardown has been forced: stop waiting for anything that might not come. */
  #forced = false;

  constructor(session: FuseSession, mountpoint: string, options: MountOptions, rootless: boolean) {
    this.session = session;
    this.mountpoint = mountpoint;
    this.#options = options;
    this.#rootless = rootless;
    this.source = checkMountToken("fsname", options.fsname) ?? "mountx";
    checkMountToken("subtype", options.subtype);
    const readers = options.readers ?? 2;
    // `NaN` would floor to zero readers, which is a mount that answers nothing
    // and then times out in `INIT` with no clue why.
    this.#readers = Number.isFinite(readers) ? Math.max(1, Math.trunc(readers)) : 2;
    this.closed = new Promise<void>((resolvePromise) => {
      this.#closedResolve = resolvePromise;
    });
  }

  get fd(): number {
    return this.#fd;
  }

  get active(): boolean {
    return !this.#stopping;
  }

  // ---------------------------------------------------------------------------
  // setup
  // ---------------------------------------------------------------------------

  async start(rootMode: number, uid: number): Promise<void> {
    if (this.#rootless) {
      // `fusermount3` opens the device, mounts, and sends the descriptor back;
      // there is no window in which this process holds an fd for a mount that
      // does not exist, so there is nothing to unwind on failure.
      this.#fd = await mountViaFusermount(this.mountpoint, {
        options: this.#fusermountOptions(),
        timeout: this.#options.initTimeout,
      });
    } else {
      const gid = process.getgid?.() ?? 0;
      const device = this.#options.device ?? "/dev/fuse";
      this.#fd = fs.openSync(device, "r+");
      try {
        await this.#spawnMount(rootMode, uid, gid);
      } catch (error) {
        fs.closeSync(this.#fd);
        this.#fd = -1;
        throw error;
      }
    }

    // Only now is there something to tear down.
    live.add(this);
    if (this.#options.signals !== false) {
      installSignalHandlers();
    }

    const size = readBufferSize(this.#options.init?.maxWrite);
    for (let i = 0; i < this.#readers; i++) {
      this.#buffers.push(Buffer.allocUnsafe(size));
    }
    for (const buffer of this.#buffers) {
      this.#arm(buffer);
    }
    await this.#awaitInit();
  }

  async #spawnMount(rootMode: number, uid: number, gid: number): Promise<void> {
    const options = this.#mountOptions(rootMode, uid, gid);
    // Always `-t fuse`, never `-t fuse.subtype`: the second form only works
    // because libmount happens to split it back apart, whereas `subtype=` in
    // the options is parsed by the kernel itself and produces the same
    // `fuse.subtype` in the mount table.
    const type = "fuse";
    // `-i` matters: without it `mount(8)` hands off to `/sbin/mount.fuse`,
    // which reinterprets the source argument as a program to execute.
    // `--` for the same reason the `fusermount3` argv has one: `mount(8)`
    // permutes, so without it a source that begins with a dash is read as an
    // option to a program running as root rather than as the source.
    const args = ["-i", "-t", type, "-o", options, "--", this.source, this.mountpoint];
    let result: SpawnResult;
    try {
      // The fd has to land in the child at *its own number*, because that is
      // the number `-o fd=N` names — hardcode fd 3 and `mount` reports "wrong
      // fs type" from reading stdin instead.
      result = await run("mount", args, { stdio: stdioWith(this.#fd) });
    } catch (error) {
      throw new Error(`mountx: could not run mount(8): ${errorMessage(error)}`);
    }
    if (result.status !== 0) {
      throw new Error(
        `mountx: mounting ${this.mountpoint} failed — ${describe(
          `mount -t ${type} -o ${options}`,
          result,
        )}`,
      );
    }
  }

  /** The `-o` list for `mount(8)`: everything the kernel needs, spelled out. */
  #mountOptions(rootMode: number, uid: number, gid: number): string {
    return [
      `fd=${this.#fd}`,
      // Parsed as octal by the kernel (`fsparam_u32oct`).
      `rootmode=${rootMode.toString(8)}`,
      `user_id=${uid}`,
      `group_id=${gid}`,
      ...this.#sharedOptions(),
    ].join(",");
  }

  /**
   * The `-o` list for `fusermount3`.
   *
   * Four options are missing and none of them by accident. `fd`, `rootmode`,
   * `user_id` and `group_id` are supplied by the helper itself — it opened the
   * device, it took `rootmode` from the mountpoint's own file type, and the ids
   * are the calling user's by definition. (It would ignore them if they were
   * here; leaving them out says why.) The source, which is an *argument* to
   * `mount(8)`, is an option here: `fsname`.
   */
  #fusermountOptions(): string {
    return [`fsname=${this.source}`, ...this.#sharedOptions()].join(",");
  }

  /** The options that mean the same thing on both paths. */
  #sharedOptions(): string[] {
    const parts: string[] = [];
    if (this.#options.defaultPermissions !== false) {
      parts.push("default_permissions");
    }
    if (this.#options.allowOther === true) {
      parts.push("allow_other");
    }
    if (this.#options.readOnly === true) {
      parts.push("ro");
    }
    if (this.#options.maxRead !== undefined) {
      parts.push(`max_read=${Math.trunc(this.#options.maxRead)}`);
    }
    if (this.#options.subtype !== undefined) {
      parts.push(`subtype=${this.#options.subtype}`);
    }
    parts.push(...(this.#options.mountOptions ?? []));
    return parts;
  }

  /** Wait for the handshake, and tear the half-built mount down if it never comes. */
  async #awaitInit(): Promise<void> {
    if (this.session.negotiated !== undefined) {
      return;
    }
    const timeout = this.#options.initTimeout ?? 10_000;
    const error = await new Promise<Error | undefined>((resolvePromise) => {
      const timer = setTimeout(() => {
        this.#ready = undefined;
        resolvePromise(
          new Error(
            `mountx: the kernel sent no FUSE_INIT within ${timeout}ms — ` +
              `${this.mountpoint} was mounted but never came up`,
          ),
        );
      }, timeout);
      timer.unref();
      this.#ready = (failure) => {
        clearTimeout(timer);
        this.#ready = undefined;
        resolvePromise(failure);
      };
    });
    if (error !== undefined) {
      // Deliberately not awaited. A connection that never answered `INIT` is
      // also one whose `umount(8)` can block in `D` state (the VFS waits on a
      // filesystem that never came up), and hanging the caller inside a failure
      // path is worse than leaving one child running. The signal handlers and
      // the fd closing at exit are the backstop; `sudo umount -l` is the
      // manual one.
      void this.unmount().catch(() => {});
      throw error;
    }
  }

  // ---------------------------------------------------------------------------
  // the read/reply loop
  // ---------------------------------------------------------------------------

  /**
   * Post one read.
   *
   * The loop is deliberately the boring one: K reads outstanding, each
   * completion dispatched **without** being awaited, the buffer re-armed the
   * moment the session has finished decoding. Nothing here waits on a driver,
   * so a slow handler costs throughput and never blocks the queue.
   */
  #arm(buffer: Buffer): void {
    if (this.#stopping) {
      return;
    }
    this.#pending++;
    fs.read(this.#fd, buffer, 0, buffer.length, null, (error, bytesRead) => {
      this.#pending--;
      if (this.#stopping) {
        this.#checkDrained();
        return;
      }
      if (error !== null) {
        this.#onReadError(error, buffer);
        return;
      }
      // A zero-length read is the kernel saying the connection is gone; so is
      // `ENODEV` above. Both mean "someone unmounted us".
      if (bytesRead === 0) {
        void this.#finish();
        return;
      }
      this.#dispatch(buffer, bytesRead);
      this.#arm(buffer);
    });
  }

  #onReadError(error: NodeJS.ErrnoException, buffer: Buffer): void {
    switch (error.code) {
      // The connection is gone: `umount(8)` ran, ours or someone else's.
      case "ENODEV": {
        void this.#finish();
        return;
      }
      // libfuse's list of "not fatal, read again": a signal interrupted the
      // read (EINTR), the request was aborted before we picked it up (ENOENT),
      // or there was nothing to read (EAGAIN, impossible on a blocking fd).
      case "EINTR":
      case "EAGAIN":
      case "ENOENT": {
        this.#arm(buffer);
        return;
      }
      /* v8 ignore next 5 -- reachable only from a kernel bug or a mangled fd. */
      default: {
        this.#report(error);
        void this.#finish();
      }
    }
  }

  /**
   * Hand one message to the session and write whatever comes back.
   *
   * The buffer is passed as a view, with no copy, which is safe for exactly one
   * reason worth stating: `handleMessage` decodes the whole message — headers,
   * body, and any `WRITE` payload, all of which it copies — *before* its first
   * `await`. So by the time this function returns, the session owns everything
   * it needs and the buffer belongs to the transport again.
   */
  #dispatch(buffer: Buffer, length: number): void {
    const message = buffer.subarray(0, length);
    this.#tap("in", message);
    let reply: Promise<Uint8Array | null>;
    try {
      /* v8 ignore next 4 -- `handleMessage` is documented never to throw; the
         catch is here so that a broken invariant costs one request instead of
         crashing the process and wedging the mountpoint. */
      reply = this.session.handleMessage(message);
    } catch (error) {
      this.#report(error);
      return;
    }
    reply.then(
      (bytes) => {
        if (bytes !== null) {
          this.#write(bytes);
        }
      },
      (error: unknown) => this.#report(error),
    );
  }

  /**
   * Write one reply or notification.
   *
   * **Synchronously, deliberately.** A write to `/dev/fuse` copies the reply
   * into the waiting request and wakes it; it does not wait on anything and
   * cannot block, so the usual reason to hand a write to the threadpool does
   * not apply — and the reason *not* to is sharp. Every `fs.write` would take a
   * pool thread, competing with the K parked readers, with the driver's own
   * I/O, and with whatever the application is doing; on the default pool of
   * four that is how a mount deadlocks under concurrent writers. `writeSync`
   * costs one memcpy on the main thread and removes the whole class.
   *
   * Failures are dropped by design, because every one of them is normal.
   * `ENOENT` means the kernel gave up on that request (an interrupt, or the
   * calling process died) between sending it and our answer — the FUSE
   * convention is to say nothing. `ENODEV` means the mount is already gone,
   * which is teardown, not an error.
   */
  #write(bytes: Uint8Array): void {
    this.#tap("out", bytes);
    while (!this.#stopping && this.#fd >= 0) {
      try {
        fs.writeSync(this.#fd, bytes, 0, bytes.length, null);
        // The mount is only usable once INIT has actually been answered, which
        // is what `mount()` waits for.
        if (this.#ready !== undefined && this.session.negotiated !== undefined) {
          this.#ready();
        }
        return;
      } catch (error) {
        switch (errorCode(error)) {
          case "ENOENT": {
            return;
          }
          case "ENODEV":
          case "EBADF":
          case "EPIPE": {
            void this.#finish();
            return;
          }
          case "EINTR": {
            continue;
          }
          /* v8 ignore next 4 -- only a kernel bug gets here. */
          default: {
            this.#report(error);
            return;
          }
        }
      }
    }
  }

  #report(error: unknown): void {
    this.#options.onTransportError?.(error);
  }

  /** Feed the recorder, if there is one. It is never allowed to cost a reply. */
  #tap(direction: "in" | "out", bytes: Uint8Array): void {
    const tap = this.#options.tap;
    if (tap === undefined) {
      return;
    }
    try {
      tap(direction, bytes);
    } catch (error) {
      this.#report(error);
    }
  }

  // ---------------------------------------------------------------------------
  // notifications
  // ---------------------------------------------------------------------------

  notifyInvalInode(ino: bigint, off = -1n, len = 0n): void {
    this.#write(this.session.notifyInvalInode(ino, off, len));
  }

  notifyInvalEntry(parent: bigint, name: string, flags = 0): void {
    this.#write(this.session.notifyInvalEntry(parent, name, flags));
  }

  // ---------------------------------------------------------------------------
  // teardown
  // ---------------------------------------------------------------------------

  async unmount(): Promise<void> {
    this.#unmounting ??= this.#unmount().catch((error: unknown) => {
      // A refused unmount — a busy mountpoint, most likely — is worth trying
      // again once whatever held it lets go, so it must not be remembered as
      // this mount's final answer. (The assignment below has already run by
      // the time an async rejection lands here.)
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
   * Everything in the happy path waits on the kernel, and the kernel is waiting
   * on the driver: `umount(8)` quiesces the filesystem before it detaches, so a
   * request the driver never answers blocks it in `D` state, and the read loop
   * behind it never sees `ENODEV`. Without a deadline that is an `unmount()`
   * that never settles — and since `await using` and the signal handlers both
   * wait on it, one wedged driver takes the process with it.
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
      // Explicitly opted out of the deadline.
      if ((await steps) === "failed") {
        throw failure;
      }
      return;
    }
    let timer: NodeJS.Timeout | undefined;
    const expiry = new Promise<"expired">((resolvePromise) => {
      timer = setTimeout(() => resolvePromise("expired"), timeout);
      timer.unref();
    });
    const outcome = await Promise.race([steps, expiry]);
    clearTimeout(timer);
    if (outcome === "failed") {
      throw failure;
    }
    if (outcome === "expired") {
      await this.#force(timeout);
    }
  }

  async #unmountSteps(): Promise<void> {
    // Someone else already unmounted us and the loop noticed: there is nothing
    // to run, only teardown to wait for.
    if (!this.#stopping && !this.#finished) {
      await this.#runUnmount();
    }
    // The loop is what ends the mount, in both directions: `umount(8)` makes
    // the kernel abort the connection, every outstanding read returns `ENODEV`,
    // and `#finish` destroys the session and closes the fd.
    await this.closed;
  }

  /**
   * Ask the mount to go away, whichever way this process is allowed to ask.
   *
   * Root uses plain `umount(8)` even though `fusermount3` may be installed: as
   * root the helper is strictly worse, because it refuses mounts that are
   * missing from its own mtab. Unprivileged has only the helper.
   */
  async #runUnmount(): Promise<void> {
    let failure: unknown;
    if (this.#rootless) {
      await unmountViaFusermount(this.mountpoint).catch((error: unknown) => {
        failure = error;
      });
    } else {
      let result: SpawnResult;
      try {
        result = await run("umount", [this.mountpoint], { stdio: ["ignore", "ignore", "pipe"] });
      } catch (error) {
        throw new Error(`mountx: could not run umount(8): ${errorMessage(error)}`);
      }
      if (result.status !== 0) {
        failure = new Error(describe("umount", result));
      }
    }
    // A failure that raced an external unmount is not a failure.
    if (failure === undefined || !isMounted(this.mountpoint)) {
      return;
    }
    throw new Error(
      `mountx: could not unmount ${this.mountpoint} (${errorMessage(failure)}). ` +
        `The mount is still live. If a process is holding it, \`fuser -m ${this.mountpoint}\` ` +
        `will say which; \`${this.#detachCommand()}\` detaches it regardless.`,
    );
  }

  /** The command that always detaches a mountpoint, for whoever is asking. */
  #detachCommand(): string {
    return this.#rootless
      ? `fusermount3 -u -z ${this.mountpoint}`
      : `sudo umount -l ${this.mountpoint}`;
  }

  /**
   * Teardown when asking nicely did not work, in the order that actually works.
   *
   * `umount -f` is the important one, and it is not the obvious one. Closing
   * the `/dev/fuse` fd aborts a connection **only when no read is outstanding**:
   * a `read(2)` parked in the threadpool holds a reference to the open file, so
   * `fuse_dev_release` — and with it the abort — does not run until it returns,
   * which it never will (verified: still mounted two seconds after the close,
   * with `umount(8)` still blocked). `umount -f` goes the other way round,
   * through `fuse_umount_begin` → `fuse_abort_conn`, which fails every request
   * in flight *now*: the parked reads come back `ENODEV`, the ordinary teardown
   * path runs on its own, and the blocked `umount(8)` completes. Its own exit
   * status is unreliable while another `umount` is racing it ("target is busy",
   * status 32, mount gone anyway), so the mount table is what gets believed.
   *
   * `umount -l` then covers the case where the entry outlives the abort.
   *
   * **Unprivileged teardown is weaker, and honestly so.** Both routes to
   * `fuse_abort_conn` — `MNT_FORCE` and `/sys/fs/fuse/connections/<n>/abort` —
   * belong to root, so all a user can do is `fusermount3 -u -z`: detach the
   * mount and let the connection die when the last reference to the superblock
   * goes. That usually amounts to the same thing a moment later, but it is a
   * consequence rather than a request, so a driver that has genuinely stopped
   * answering can leave reads parked here where root would not.
   */
  async #force(timeout: number): Promise<void> {
    const error = new Error(
      `mountx: unmounting ${this.mountpoint} did not finish within ${timeout}ms — the ` +
        `driver has probably stopped answering. The connection has been aborted, so anything ` +
        `in flight was lost. If the mountpoint is somehow still listed: ` +
        this.#detachCommand(),
    );
    this.#report(error);
    if (this.#rootless) {
      if (isMounted(this.mountpoint)) {
        await unmountViaFusermount(this.mountpoint, { lazy: true }).catch(() => {
          // Nothing to add: the next check of the mount table is the verdict.
        });
      }
    } else {
      for (const args of [
        ["-f", this.mountpoint],
        ["-l", this.mountpoint],
      ]) {
        if (!isMounted(this.mountpoint)) {
          break;
        }
        await run("umount", args, { stdio: ["ignore", "ignore", "pipe"] }).catch(() => {
          // Nothing to add: the next check of the mount table is the verdict.
        });
      }
    }
    // The abort should have ended the loop by itself. Give it a moment to do
    // so, then stop waiting and tear down from this side regardless.
    await Promise.race([this.closed, delay(1000)]);
    await this.#finish(true);
    throw error;
  }

  /**
   * End the loop: drain the reads, destroy the session, close the fd.
   *
   * Idempotent. `force` skips the two waits that a wedged driver can hold open
   * — the read drain and `session.destroy()` — and also releases a drain that
   * an earlier, unforced call is already stuck in.
   */
  async #finish(force = false): Promise<void> {
    if (force) {
      this.#forced = true;
      this.#drained?.();
    }
    if (this.#stopping) {
      return;
    }
    this.#stopping = true;
    // A connection that dies before the handshake unblocks `start`, which then
    // unwinds the half-built mount.
    this.#ready?.(new Error(`mountx: ${this.mountpoint} lost its connection before FUSE_INIT`));
    live.delete(this);
    if (live.size === 0) {
      removeSignalHandlers();
    }
    // Reads parked in the threadpool still hold the descriptor. Closing it
    // under them would leave callbacks pointing at an fd number the process is
    // free to reuse, so wait — after the connection is aborted they return
    // `ENODEV` immediately, and nothing else can get here.
    await new Promise<void>((resolvePromise) => {
      this.#drained = resolvePromise;
      this.#checkDrained();
    });
    this.#drained = undefined;
    // A `-t fuse` mount never receives `FUSE_DESTROY` (that is `fuseblk`), so
    // this call is the only thing that closes leftover driver handles and
    // clears the inode table. `session.destroyed` is true from the moment it is
    // called, so a forced teardown does not have to wait for it to finish —
    // what it waits on is the driver, which is what we are running from.
    const destroyed = this.session.destroy().catch((error: unknown) => this.#report(error));
    if (!this.#forced) {
      await destroyed;
    }
    if (this.#fd >= 0) {
      const fd = this.#fd;
      this.#fd = -1;
      try {
        fs.closeSync(fd);
        /* v8 ignore next 3 -- only a double close reaches this. */
      } catch (error) {
        this.#report(error);
      }
    }
    this.#finished = true;
    this.#closedResolve();
  }

  #checkDrained(): void {
    if (this.#pending === 0 || this.#forced) {
      this.#drained?.();
    }
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, ms).unref();
  });
}

/**
 * Bytes per receive buffer: the biggest `WRITE` the session will agree to, plus
 * headers. One buffer per reader, allocated once — per-request allocation on
 * the read path is the one JS-side cost that shows up in profiles (IDEA.md).
 */
function readBufferSize(maxWrite: number | undefined): number {
  const ceiling = FUSE_MAX_MAX_PAGES * FUSE_PAGE_SIZE;
  const requested = maxWrite ?? DEFAULT_MAX_WRITE;
  // Negotiation can only ever agree to *less* than this, so the buffer is
  // never too small; clamping keeps a silly `maxWrite` from allocating a silly
  // buffer.
  const width = Math.min(Math.max(requested, FUSE_MIN_READ_BUFFER), ceiling);
  return width + FUSE_BUFFER_HEADER_SIZE;
}
