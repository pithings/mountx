/**
 * The FUSE transport: `/dev/fuse`, a real mountpoint, and the read/reply loop.
 *
 * This is the only file in the library that touches a device or spawns a
 * process. Everything below it — protocol, session, drivers — is bytes in,
 * bytes out, which is why all of it is testable with no root and no kernel.
 *
 * ```ts
 * import { mount } from "unimount/fuse";
 * import { createMemoryDriver } from "unimount/drivers/memory";
 *
 * await using mounted = await mount(createMemoryDriver(), "/mnt/point");
 * // ... /mnt/point is live until unmount() or the process exits ...
 * ```
 *
 * **Root mode only, in v1.** Getting the fd is pure JS (`/dev/fuse` is mode
 * 0666 everywhere), but `mount(2)` is not a syscall Node can issue. As root the
 * way around it is stock `mount(8)`: the `fd=N` mount option resolves in the
 * *caller's* fd table, and fds are inheritable, so the child mounts and exits
 * while the parent keeps its copy of the descriptor for the loop. Unprivileged
 * mounting needs `fusermount3` and `SCM_RIGHTS`, which Node cannot receive —
 * that is the native stub, and a later milestone.
 *
 * **fd lifecycle, which is also the crash-safety story.** The kernel tears the
 * connection down when the last reference to the `/dev/fuse` file goes away, so
 * a killed process cannot leave a mountpoint that hangs on `ls` — it leaves one
 * that answers `ENOTCONN`, which `umount` clears without ceremony. That
 * guarantee only holds if nothing else keeps the descriptor alive, so the fd is
 * opened `O_CLOEXEC` (libuv's default) and is handed to exactly one child,
 * `mount(8)`, which exits immediately. `umount(8)` and every other spawn run
 * without it. Without `fusermount3` there is no `-o auto_unmount`, so the stale
 * *mount table entry* does survive a crash; recovery is one command, and it is
 * named in the error messages here: `sudo umount -l <mountpoint>`.
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
 * **Exiting: `await unmount()`, and do not reach for `process.exit()`.** Node's
 * exit path joins the threadpool, and a live mount always has K reads parked in
 * it, so `process.exit()` does not return — it hangs until the connection is
 * torn down, and then needs a `SIGKILL` (measured: 25 s and still going). This
 * is why the signal handlers here unmount and then *re-raise* the signal rather
 * than calling `process.exit()`: by the time the default action runs there are
 * no parked reads left. Application code wanting a specific exit code should
 * `await mount.unmount()` first and set `process.exitCode`.
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import { stat as statPath } from "node:fs/promises";
import { resolve as resolveNative } from "node:path";
import type { FsDriver } from "../types.ts";
import { S_IFDIR, S_IFMT } from "../types.ts";
import { FUSE_MAX_MAX_PAGES, FUSE_MIN_READ_BUFFER, FUSE_PAGE_SIZE } from "./constants.ts";
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
  /** What `/proc/mounts` shows as the device. Default `"unimount"`. */
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
   * Harmless here (v1 mounts are root's anyway, and `default_permissions` still
   * applies), but note that the unprivileged path will need `user_allow_other`
   * in `/etc/fuse.conf` for the same option.
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
  /** The device to open. Default `"/dev/fuse"`; a test double is the only reason to change it. */
  device?: string;
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
    console.error(`unimount: unmount on ${signal} failed: ${errorMessage(failure)}`);
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
 * `mount()` means the path is usable, not merely that `mount(8)` exited.
 * Requires root (see the module docs); throws before touching anything if it
 * does not have it.
 */
export async function mount(
  driver: FsDriver,
  mountpoint: string,
  options: MountOptions = {},
): Promise<Mount> {
  if (process.platform !== "linux") {
    throw new Error(`unimount: FUSE mounts need Linux, this is ${process.platform}`);
  }
  const uid = process.getuid?.() ?? -1;
  if (uid !== 0) {
    throw new Error(
      "unimount: mounting FUSE needs root. Without `fusermount3` (this host has none) " +
        "there is no unprivileged path, so run the process as root — under `sudo`, note " +
        'that root\'s PATH may lack node: sudo "$(which node)" script.mjs',
    );
  }
  const target = resolveNative(mountpoint);
  const targetStat = await statPath(target).catch((error: unknown) => {
    throw new Error(`unimount: mountpoint ${target} is not usable: ${errorMessage(error)}`);
  });
  if (!targetStat.isDirectory()) {
    throw new Error(`unimount: mountpoint ${target} is not a directory`);
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
        `unimount: ${target} is already mounted by this process. Unmount it before mounting again.`,
      );
    }
  }
  const occupant = mountEntryAt(target);
  if (occupant !== undefined && occupant.type.startsWith("fuse")) {
    throw new Error(
      `unimount: ${target} already has a FUSE filesystem on it (${occupant.source}, type ` +
        `${occupant.type}). Mounting over it would stack a second mount and make either ` +
        `unmount detach the wrong one. Clear it first: umount ${target}`,
    );
  }

  const session = new FuseSession(driver, options);
  // `rootmode` is how the kernel builds the root inode before it has ever
  // spoken to us, and it is parsed as octal. It must agree with what `GETATTR`
  // on nodeid 1 will say, or the VFS refuses to descend into the mount.
  const rootStat = await session.driver.stat("/").catch((error: unknown) => {
    throw new Error(`unimount: the driver cannot stat its own root: ${errorMessage(error)}`);
  });
  const rootMode = Number(rootStat.mode);
  if ((rootMode & S_IFMT) !== S_IFDIR) {
    throw new Error(
      `unimount: the driver's root must be a directory, its mode is 0o${rootMode.toString(8)}`,
    );
  }

  const impl = new MountImpl(session, target, options);
  await impl.start(rootMode, uid);
  return impl;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
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
 * `fsname` and `subtype` are the two options that carry user strings, and a
 * comma in either of them is not a quoting bug but an *injection*: it would
 * silently add mount options to the string handed to `mount(8)`.
 */
function checkMountToken(name: string, value: string | undefined): string | undefined {
  if (value !== undefined && /[,=\s]/.test(value)) {
    throw new Error(
      `unimount: \`${name}\` may not contain a comma, an equals sign or whitespace — ` +
        `it is joined into the mount option list, where those separate options ` +
        `(got ${JSON.stringify(value)})`,
    );
  }
  return value;
}

interface SpawnResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
}

/**
 * Run a command to completion.
 *
 * `stdio` is passed through because the mount child is the one place where a
 * specific *fd number* has to survive into the child — see {@link MountImpl.start}.
 */
function run(
  command: string,
  args: readonly string[],
  stdio: Array<"ignore" | "pipe" | number>,
): Promise<SpawnResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, [...args], { stdio });
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

class MountImpl implements Mount {
  readonly mountpoint: string;
  readonly source: string;
  readonly session: FuseSession;
  readonly closed: Promise<void>;

  readonly #options: MountOptions;
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

  constructor(session: FuseSession, mountpoint: string, options: MountOptions) {
    this.session = session;
    this.mountpoint = mountpoint;
    this.#options = options;
    this.source = checkMountToken("fsname", options.fsname) ?? "unimount";
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
    // The fd has to land in the child at *its own number*, because that is the
    // number `-o fd=N` names. `openSync` returns whatever the process has free
    // (17 is typical, not 3), so the stdio array is padded out to it — hardcode
    // fd 3 and `mount` reports "wrong fs type" from reading stdin instead.
    const stdio: Array<"ignore" | "pipe" | number> = Array.from(
      { length: this.#fd + 1 },
      () => "ignore",
    );
    stdio[2] = "pipe";
    stdio[this.#fd] = this.#fd;
    // `-i` matters: without it `mount(8)` hands off to `/sbin/mount.fuse`,
    // which reinterprets the source argument as a program to execute.
    const args = ["-i", "-t", type, "-o", options, this.source, this.mountpoint];
    let result: SpawnResult;
    try {
      result = await run("mount", args, stdio);
    } catch (error) {
      throw new Error(`unimount: could not run mount(8): ${errorMessage(error)}`);
    }
    if (result.status !== 0) {
      throw new Error(
        `unimount: mounting ${this.mountpoint} failed — ${describe(
          `mount -t ${type} -o ${options}`,
          result,
        )}`,
      );
    }
  }

  #mountOptions(rootMode: number, uid: number, gid: number): string {
    const parts = [
      `fd=${this.#fd}`,
      // Parsed as octal by the kernel (`fsparam_u32oct`).
      `rootmode=${rootMode.toString(8)}`,
      `user_id=${uid}`,
      `group_id=${gid}`,
    ];
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
    return parts.join(",");
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
            `unimount: the kernel sent no FUSE_INIT within ${timeout}ms — ` +
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

  async #runUnmount(): Promise<void> {
    // Plain `umount(8)`: this is root-only for now, and root's `umount` is the
    // reliable path. (`fusermount3 -u` belongs to the unprivileged milestone,
    // which will have to introduce it along with the mount side — as root it is
    // strictly worse, because it refuses mounts missing from its own mtab.)
    let result: SpawnResult;
    try {
      result = await run("umount", [this.mountpoint], ["ignore", "ignore", "pipe"]);
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
   */
  async #force(timeout: number): Promise<void> {
    const error = new Error(
      `unimount: unmounting ${this.mountpoint} did not finish within ${timeout}ms — the ` +
        `driver has probably stopped answering. The connection has been aborted, so anything ` +
        `in flight was lost. If the mountpoint is somehow still listed: ` +
        `sudo umount -l ${this.mountpoint}`,
    );
    this.#report(error);
    for (const args of [
      ["-f", this.mountpoint],
      ["-l", this.mountpoint],
    ]) {
      if (!isMounted(this.mountpoint)) {
        break;
      }
      await run("umount", args, ["ignore", "ignore", "pipe"]).catch(() => {
        // Nothing to add: the next check of the mount table is the verdict.
      });
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
    this.#ready?.(new Error(`unimount: ${this.mountpoint} lost its connection before FUSE_INIT`));
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
