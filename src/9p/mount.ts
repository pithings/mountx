/**
 * Mounting the 9P server with `mount(8)`.
 *
 * The transport is `server.ts`; this file is the convenience that puts the
 * kernel's own v9fs client in front of it, and it is the third file in the
 * library that spawns a process.
 *
 * ```ts
 * import { mount9p } from "mountx/9p";
 * await using mounted = await mount9p(createMemoryDriver(), "/mnt/point");
 * ```
 *
 * **Linux, and root.** v9fs is a Linux filesystem — no other kernel has a 9P
 * client — and `mount(2)` needs `CAP_SYS_ADMIN`, with no setuid helper of the
 * `fusermount3` kind anywhere in sight. {@link p9ClientProbe} says which piece
 * is missing before anything is spawned, because the kernel's answer to all of
 * them is the same `wrong fs type, bad option, bad superblock`.
 *
 * **`trans=unix`, not `trans=fd`.** `net/9p/trans_fd.c` (v6.12) registers three
 * transports off the same code: `tcp`, `unix` and `fd`. `fd` is the one that
 * would take a socketpair — `-o trans=fd,rfdno=N,wfdno=N`, resolved in the
 * *mounting* process's fd table, which is the trick `src/fuse/mount.ts` plays
 * with `stdioWith()` — and Node cannot make a socketpair without native code:
 * `net.Socket` wraps an fd it is given but nothing in the API *creates* a
 * connected pair, and the addon this package ships is FUSE's, deliberately kept
 * off every other path. `unix` needs none of that. `p9_fd_create_unix()` takes
 * the mount's *source* argument as a filesystem path and connects a
 * `SOCK_STREAM` `AF_UNIX` socket to it itself, so the whole handoff is a listener
 * this process already knows how to make (`createP9Server({ path })`) and a path
 * in argv. The security property is the same one the socketpair was for: the
 * socket lives in a `mkdtemp` `0700` directory, mode `0600`, so no other local
 * user can reach it — which matters, because 9P authenticates nothing.
 * `trans=fd` stays on the table for a relay mode that has a descriptor to pass
 * anyway; it buys nothing here. It is also the shape the kernel's own
 * documentation reaches for: `Documentation/filesystems/9p.rst` mounts Plan 9
 * From User Space with ``mount -t 9p `namespace`/acme /mnt/9 -o
 * trans=unix,uname=$USER`` — a socket path as the source, exactly this.
 *
 * **`trans=tcp` is still reachable**, for the case the TCP listener exists for:
 * pass `port`/`host` (or a `server` of your own that is listening on a port) and
 * the mount is told `trans=tcp,port=N` with the address as its source. That is
 * the shape a VM guest mounting its host uses. On loopback it is strictly worse
 * than the unix socket — a port is reachable by every user on the machine —
 * so it is never the default.
 *
 * **One connection, and its EOF is the unmount.** 9P has no `Tdestroy` and no
 * analogue of `FUSE_DESTROY`: a mount ends when the transport does. The kernel
 * opens exactly one connection per mount and closes it in `v9fs_kill_super()`,
 * so {@link P9Connection.closed} — which resolves once the session is destroyed
 * *and* the socket has emitted `close` — is this transport's unmount detection,
 * for our own `umount` and for somebody else's alike.
 *
 * **Serving a mount and using it from the same process is mostly fine here**,
 * unlike FUSE. This server answers from the event loop over a socket rather
 * than from a threadpool-parked `read(2)`, so asynchronous `fs` calls against
 * our own mountpoint cannot starve the thing that has to answer them. Two
 * shapes still deadlock, and both are the same mistake: blocking the one thread
 * that replies while waiting on the mount. Anything *synchronous* —
 * `readFileSync`, `execFileSync` — is the obvious one. The other is
 * `child_process.spawn()`, because `uv_spawn` holds the calling thread until
 * the child has `chdir`ed and exec'd: a `cwd` inside the mountpoint hangs, and
 * so does spawning a *binary that lives on the mountpoint*, whose child parks
 * in `p9_client_rpc` under `do_open_execat` reading its own ELF header. That
 * second one does not even end when the server process is killed — `fork` gave
 * the child a copy of the server socket, so the connection outlives it — and
 * wants a `kill -9` on the child, which works because `p9_client_rpc` waits
 * killably. Spawn a shell and let it do the exec.
 *
 * Teardown follows the FUSE and NFS transports' discipline exactly, and for the
 * same reasons: `umount(8)` first, the mount table is the truth rather than an
 * exit status, `umount -f` and then `-l` when the deadline passes, every spawned
 * child bounded by that deadline and abandoned if it outlives it, and the whole
 * thing idempotent and retryable. `umount -f` is not a placebo here — v9fs
 * implements `.umount_begin` (`v9fs_umount_begin()` in `fs/9p/vfs_super.c`,
 * both `super_operations`), which cancels the requests in flight, exactly like
 * FUSE's `fuse_abort_conn`. And when even that does not land, dropping the
 * server is itself a way out: the client fails every outstanding request when
 * its socket dies, which is the same escape hatch a `soft` NFS mount has.
 */

import * as fs from "node:fs";
import { mkdtemp, realpath, rm, stat as statPath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve as resolveNative } from "node:path";
import {
  type Deadline,
  deadlineIn,
  delay,
  describe,
  errorMessage,
  run,
  type SpawnResult,
} from "../fuse/exec.ts";
import type { FsDriver } from "../types.ts";
import { P9_IOHDRSZ, P9_MIN_MSIZE } from "./constants.ts";
import { p9ClientProbe } from "./probe.ts";
import {
  createP9Server,
  type P9Connection,
  type P9Server,
  type P9ServerOptions,
} from "./server.ts";

/** Signals a mount cleans up on. `SIGHUP` is deliberately not one. */
const TEARDOWN_SIGNALS = ["SIGINT", "SIGTERM"] as const;

// The probe and its platform type live in `probe.ts`, which imports nothing but
// `node:fs` — see the note there. Re-exported so `mountx/9p` is one import
// either way.
export { p9ClientProbe, type P9ClientProbe, type P9Platform, p9Platform } from "./probe.ts";

/**
 * The `msize` a mount asks for: 128 KiB of payload plus the 9P I/O header.
 *
 * Character for character the kernel's own default (`DEFAULT_MSIZE` in
 * `net/9p/client.c`, `(128 * 1024) + P9_IOHDRSZ`), and the `+ 24` is the whole
 * point of it: `msize` bounds the entire message, so a round *payload* — what
 * `p9_client_read_once()` computes as `msize - P9_IOHDRSZ` — needs the header
 * added on top. A bigger `msize` means fewer round trips for the same bytes and
 * a bigger per-request allocation on both sides (the kernel allocates from a
 * `kmem_cache` of exactly this size); 128 KiB is where the kernel landed after
 * shipping 8 KiB for years, and there is no reason for this transport to
 * disagree with the client it is talking to.
 */
export const P9_DEFAULT_MOUNT_MSIZE = 128 * 1024 + P9_IOHDRSZ;

/**
 * The largest `msize` worth asking for: `MAX_SOCK_BUF` from `net/9p/trans_fd.c`.
 *
 * All three transports this file can use (`unix`, `tcp`, `fd`) declare it as
 * their `maxsize`, and `p9_client_create()` silently clamps anything larger,
 * printing `Limiting 'msize' to …`. Asking for more is not an error, just a lie
 * in the option string, so the builder clamps instead. It is also exactly the
 * ceiling `P9Session` defaults to, so the two agree by construction.
 */
export const P9_MAX_MOUNT_MSIZE = 1024 * 1024;

/**
 * `UNIX_PATH_MAX`, the bound on the socket path a `trans=unix` mount can name.
 *
 * `p9_fd_create_unix()` refuses `strlen(addr) >= UNIX_PATH_MAX` with
 * `ENAMETOOLONG` before it ever creates a socket, and `sockaddr_un.sun_path` is
 * 108 bytes on Linux. Checked here so a long `TMPDIR` produces a sentence
 * instead of a mount failure with no stderr to read.
 */
export const P9_UNIX_PATH_MAX = 108;

/** How v9fs is told to reach the server. */
export interface P9MountTarget {
  /** The `trans=` the mount is given. */
  trans: "unix" | "tcp";
  /** The TCP port, for `trans=tcp`. Ignored — and omitted — otherwise. */
  port?: number;
}

export interface MountP9Options extends P9ServerOptions {
  /**
   * Serve an existing server instead of creating one. Its `listen()` is still
   * called, and its transport is read off it: a server with a `path` is mounted
   * `trans=unix`, one without is mounted `trans=tcp`.
   *
   * **Four things a shared server changes, all of them worth knowing before
   * reaching for this.**
   *
   * - **It is closed on teardown.** {@link P9Mount.unmount} shuts the server
   *   down, whoever made it — a mount whose server outlived it would be a
   *   mountpoint with nothing answering. Do not share one server between a
   *   mount and something else you expect to keep working.
   * - **Its own options are the session's.** `readOnly` here still reaches the
   *   kernel as `-o ro`, so writes are refused at the VFS, but it does **not**
   *   reach a session this call did not construct: pass `readOnly` (and
   *   `msize`, and the rest of `P9SessionOptions`) to the server too, or the
   *   two will disagree about what the mount is.
   * - **It keeps its own `onTransportError`**, so the teardown silencing
   *   described on {@link MountP9Options.onTransportError} does not apply to it.
   * - **The kernel's connection is identified by being new.** Calls that share
   *   a server are serialized so two mounts cannot each adopt the other's, and
   *   on a loopback `trans=tcp` server a connection from anywhere but loopback
   *   is not a candidate. What is left is genuinely racy: a *third party*
   *   connecting to the shared server in the window between the snapshot and
   *   `mount(8)` returning could be adopted instead, and since
   *   {@link P9Connection.closed} is this transport's only unmount signal, that
   *   client's disconnect would tear the mount down. A server per mount — the
   *   default, with its own private socket — has no such window.
   */
  server?: P9Server;
  /** Mount read-only. Sets `-o ro` **and** the session's own `readOnly`. */
  readOnly?: boolean;
  /**
   * The `msize` to ask for, in bytes. Default {@link P9_DEFAULT_MOUNT_MSIZE},
   * clamped to `[P9_MIN_MSIZE, P9_MAX_MOUNT_MSIZE]`.
   *
   * This is the *client's* proposal; the negotiated value is the smaller of it
   * and the session's own `msize` ceiling, so lowering that ceiling below this
   * one is what actually caps a mount.
   */
  mountMsize?: number;
  /**
   * The `access=` mode. Default `"client"`.
   *
   * Which is also v9fs's own default for 9P2000.L (`v9fs_session_init()` sets
   * `V9FS_ACCESS_CLIENT` as soon as the negotiated protocol is `.L`), and the
   * right one for this server: `access=client` has the *kernel* check mode bits
   * against what `Rgetattr` reported, which is exactly the posture the FUSE
   * transport takes with `default_permissions`. The alternative, `access=user`,
   * expects the *server* to make access decisions per attaching uid — and this
   * server makes none, so it would mean no permission checking anywhere.
   *
   * `"any"`, `"user"` and a numeric uid (`access=1000`, v9fs's
   * `V9FS_ACCESS_SINGLE`) are the other spellings the kernel accepts.
   */
  access?: string;
  /**
   * The `cache=` mode. Default `"none"`.
   *
   * 9P has no invalidation channel — nothing in the protocol lets a server tell
   * a client that something it cached has changed, where FUSE has
   * `notify_inval_inode` — so every cache mode above `none` is a bet that
   * nothing but this mount modifies the driver. For a JavaScript filesystem,
   * whose whole point is often that the process serving it is also changing it,
   * that bet is usually wrong, and a stale read is a much worse bug than a slow
   * one. Raise it deliberately: `"readahead"`, `"mmap"`, `"loose"` and
   * `"fscache"` are the modes v6.12 accepts (`get_cache_mode()` in
   * `fs/9p/v9fs.c`).
   *
   * One consequence of the default worth knowing: `cache=none` supports only
   * read-only `mmap`, so executing a binary from the mount works and a
   * shared writable mapping does not.
   */
  cache?: string;
  /**
   * The `uname=` a client asserts in `Tattach`. Default `"nobody"`, which is
   * v9fs's own (`V9FS_DEFUSER`).
   *
   * Restated rather than left to the kernel so the option string says what it
   * is doing. It is decorative for this server: 9P's only authentication is a
   * name the client asserts, so the socket is the security boundary and the
   * session records `n_uname` (the numeric one) purely to give newly created
   * files an owner.
   */
  uname?: string;
  /**
   * The `aname=` — the tree to attach to. Default `"/"`.
   *
   * `""` (the kernel's `V9FS_DEFANAME`) and `"/"` both mean the driver's root.
   * Any other name attaches at **that subtree**, if it exists and is a
   * directory: `P9Session` resolves it against the root (`src/path.ts` clamps
   * `..`, so no `aname` reaches outside), answers `ENOENT` when it is not there
   * and `ENOTDIR` when it is not a directory.
   */
  aname?: string;
  /** Extra `-o` options, appended verbatim — last, so they win. */
  mountOptions?: readonly string[];
  /** Unmount on `SIGINT`/`SIGTERM`. Default `true`. */
  signals?: boolean;
  /**
   * Milliseconds {@link P9Mount.unmount} may spend before it forces the mount
   * down. Default `10_000`; `0` or `Infinity` waits forever.
   *
   * It bounds each of the two phases, not their sum: asking nicely gets this
   * long, and the forcing that follows gets its own budget of the same size, so
   * a teardown that has to escalate settles in at most twice it.
   */
  unmountTimeout?: number;
  /**
   * Called for transport-level failures, and for a forced teardown.
   *
   * Silent from the moment teardown begins: a mount going away takes its
   * connection with it, and a socket dying on schedule is not a fault worth
   * reporting.
   */
  onTransportError?: (error: unknown, peer: string | undefined) => void;
}

/** A live 9P mountpoint. */
export interface P9Mount extends AsyncDisposable {
  /** Absolute path of the mountpoint, with symlinks resolved. */
  readonly mountpoint: string;
  /** The server behind it. */
  readonly server: P9Server;
  /** What the mount table shows as the device: the socket path, or the address. */
  readonly source: string;
  /** How the kernel was told to reach the server. */
  readonly trans: "unix" | "tcp";
  /** The kernel's connection, and the only one this mount cares about. */
  readonly connection: P9Connection;
  /** `false` from the moment teardown starts, whoever started it. */
  readonly active: boolean;
  /**
   * Resolves once the connection is gone and the server is down — whether that
   * was {@link P9Mount.unmount} or somebody else's `umount(8)`. Never rejects.
   */
  readonly closed: Promise<void>;
  /**
   * Unmount and shut the server down. Idempotent, concurrency-safe, retryable
   * after a failure. Always settles: within `unmountTimeout` when asking nicely
   * works, and within twice it when the mount has to be forced down instead.
   */
  unmount(): Promise<void>;
}

const live = new Set<P9MountImpl>();
/**
 * Per-server mutex over "snapshot the clients, mount, adopt the new one".
 *
 * Keyed weakly on the server, so it costs nothing for the ordinary case of one
 * server per mount and serializes only the calls that actually share one.
 */
const adopting = new WeakMap<P9Server, Promise<void>>();
let signalsInstalled = false;

async function onTeardownSignal(signal: NodeJS.Signals): Promise<void> {
  removeSignalHandlers();
  for (const failure of await unmountAll9p()) {
    console.error(`mountx: 9P unmount on ${signal} failed: ${errorMessage(failure)}`);
  }
  // Nobody else is listening, so nothing will exit the process: re-raise, and
  // let the default action produce the conventional 128+n status.
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

/** Unmount every live 9P mount in this process. Never rejects. */
export async function unmountAll9p(): Promise<unknown[]> {
  const results = await Promise.allSettled([...live].map((mount) => mount.unmount()));
  return results
    .filter((result) => result.status === "rejected")
    .map((result) => (result as PromiseRejectedResult).reason);
}

/** The 9P mounts this process currently has up, in creation order. */
export function live9pMounts(): P9Mount[] {
  return [...live];
}

/**
 * Why this socket path will not do, if it will not.
 *
 * Pure and exported for the Tier-0 test: the host that can check this is not
 * necessarily the host with a `TMPDIR` long enough to hit it.
 */
export function socketPathRefusal(path: string): string | undefined {
  const length = Buffer.byteLength(path, "utf8");
  if (length < P9_UNIX_PATH_MAX) {
    return undefined;
  }
  return (
    `mountx: the 9P socket path is ${length} bytes and the kernel's limit is ` +
    `${P9_UNIX_PATH_MAX - 1} (UNIX_PATH_MAX, checked by p9_fd_create_unix before it connects): ` +
    `${path}. Set TMPDIR to something shorter, or pass a \`server\` listening on a shorter ` +
    `path of your own.`
  );
}

/** A dotted quad, and nothing else: four decimal octets, each `0`–`255`. */
const IPV4_LITERAL = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Why this `trans=tcp` source will not do, if it will not.
 *
 * `p9_fd_create_tcp()` answers `EINVAL` for anything `valid_ipaddr4()` does not
 * like, and `valid_ipaddr4()` is a `sscanf("%d.%d.%d.%d")` with an upper bound
 * on each octet — so the kernel takes a **dotted-quad IPv4 literal and nothing
 * else**. No hostname (there is no resolver in there to call), and no IPv6:
 * `sin_server.sin_family` is hard-coded `AF_INET` and the address goes through
 * `in_aton()`. `::1` is a perfectly good loopback address to
 * {@link P9ServerOptions.host} and a mount failure here, which is exactly the
 * kind of opaque `wrong fs type, bad option, bad superblock` this module exists
 * to turn into a sentence.
 *
 * Pure and exported for the Tier-0 test, like {@link socketPathRefusal}.
 */
export function tcpSourceRefusal(host: string): string | undefined {
  const match = IPV4_LITERAL.exec(host);
  if (match !== null && match.slice(1).every((octet) => Number(octet) <= 255)) {
    return undefined;
  }
  return (
    `mountx: a trans=tcp 9P mount needs a dotted-quad IPv4 address as its source and got ` +
    `${JSON.stringify(host)}. The kernel checks it with valid_ipaddr4() and connects with ` +
    `AF_INET/in_aton(), so it resolves no hostnames and speaks no IPv6 — use 127.0.0.1 rather ` +
    `than ::1 or localhost, or mount over a unix socket (the default), which has neither limit.`
  );
}

/**
 * Reject a value that would not survive being joined into a `-o` list.
 *
 * The mountpoint and the source are *not* checked, and that is not an
 * oversight: both are separate argv elements to `mount(8)`, so a comma or a
 * space in either is carried through untouched. These four are the ones that go
 * into the option string, where a comma does not need quoting so much as it
 * silently adds an option to a command running as root.
 */
function checkOptionValue(name: string, value: string): string {
  if (/[,\s]/.test(value)) {
    throw new Error(
      `mountx: \`${name}\` may not contain a comma or whitespace — it is joined into the ` +
        `mount option list, where a comma starts the next option ` +
        `(got ${JSON.stringify(value)})`,
    );
  }
  return value;
}

/**
 * An `msize` proposal, whatever was passed.
 *
 * `NaN` is the one value with no sensible clamp — it is a mistake rather than
 * an extreme — so it takes the default; the infinities clamp like any other
 * out-of-range number, which is what "as much as possible" should mean. What
 * must never happen is a literal `msize=NaN` reaching the option string, where
 * `match_int()` fails and the kernel quietly keeps its own default instead.
 */
function msizeOf(value: number | undefined): number {
  if (value === undefined || Number.isNaN(value)) {
    return P9_DEFAULT_MOUNT_MSIZE;
  }
  return Math.min(Math.max(Math.trunc(value), P9_MIN_MSIZE), P9_MAX_MOUNT_MSIZE);
}

/**
 * The `port=` for a `trans=tcp` mount, or a refusal.
 *
 * Thrown rather than clamped, because the failure it prevents is silent:
 * `trans_fd.c`'s `parse_opts()` `continue`s past an option whose `%u` does not
 * match *and* past one whose `match_int()` fails, leaving `opts.port` at its
 * initialized `P9_PORT` — so a `port=NaN`, a `port=-1` or a `port=70000` does
 * not fail the mount, it mounts against **port 564**, which is precisely the
 * outcome saying `port=` at all is meant to prevent.
 */
function portOf(port: number | undefined): number {
  if (!Number.isInteger(port) || port! < 1 || port! > 65_535) {
    throw new Error(
      `mountx: a trans=tcp 9P mount needs a port that is an integer in [1, 65535] and got ` +
        `${port === undefined ? "nothing" : JSON.stringify(port)}. The kernel ignores a \`port=\` ` +
        `it cannot parse and connects to 564 instead, so this has to be a refusal rather than a ` +
        `clamp.`,
    );
  }
  return port!;
}

/**
 * The `-o` string this transport hands `mount(8)`, for `target`.
 *
 * Exported because it is the whole of what the kernel is told, in one pure
 * function: a test can check it from any host, and anyone who would rather run
 * the mount themselves can print the command instead of reverse-engineering it.
 *
 * Every option is one the kernel parses, and they come from two different
 * parsers, which is worth knowing when one of them is rejected: `trans`,
 * `version` and `msize` are `net/9p/client.c`'s (plus `port`, which is
 * `net/9p/trans_fd.c`'s), while `access`, `cache`, `uname` and `aname` are
 * `fs/9p/v9fs.c`'s. `ro` is the VFS's own.
 *
 * The `version` spelling is the one that catches people: the mount option is
 * `9p2000.L` (`p9_get_protocol_version()`), while the string that goes on the
 * wire in `Tversion` is `9P2000.L`. Both capitalizations are load-bearing and
 * neither is a typo.
 */
export function p9MountOptions(target: P9MountTarget, options: MountP9Options = {}): string {
  const parts = [`trans=${target.trans}`];
  if (target.trans === "tcp") {
    // Without it — or with one the kernel cannot parse — v9fs uses P9_PORT
    // (564), which is never where an ephemeral listener landed.
    parts.push(`port=${portOf(target.port)}`);
  }
  parts.push(
    "version=9p2000.L",
    `msize=${msizeOf(options.mountMsize)}`,
    `access=${checkOptionValue("access", options.access ?? "client")}`,
    `cache=${checkOptionValue("cache", options.cache ?? "none")}`,
    `uname=${checkOptionValue("uname", options.uname ?? "nobody")}`,
    `aname=${checkOptionValue("aname", options.aname ?? "/")}`,
  );
  if (options.readOnly === true) {
    parts.push("ro");
  }
  // Last, so a caller can override anything above: the kernel's option parsers
  // take the last occurrence as the winner.
  parts.push(...(options.mountOptions ?? []));
  return parts.join(",");
}

/**
 * Serve `driver` over 9P2000.L and mount it at `mountpoint`.
 *
 * Resolves once `mount(8)` has returned successfully, which for 9P means the
 * kernel has already completed a `Tversion` and a `Tattach` — so a resolved
 * `mount9p()` means the path is usable, not merely that a child exited zero.
 */
export async function mount9p(
  driver: FsDriver,
  mountpoint: string,
  options: MountP9Options = {},
): Promise<P9Mount> {
  const probe = p9ClientProbe();
  if (!probe.usable) {
    throw new Error(`mountx: cannot mount 9P here — ${probe.reason}`);
  }
  const resolved = resolveNative(mountpoint);
  const targetStat = await statPath(resolved).catch((error: unknown) => {
    throw new Error(`mountx: mountpoint ${resolved} is not usable: ${errorMessage(error)}`);
  });
  if (!targetStat.isDirectory()) {
    throw new Error(`mountx: mountpoint ${resolved} is not a directory`);
  }
  // The mount table records the path with every symlink resolved, and matching
  // against it is how teardown knows whether the mount is still there.
  const target = await realpath(resolved).catch(() => resolved);
  // Linux stacks mounts: mounting over a live mountpoint succeeds and hides the
  // one underneath, and then `umount` detaches whichever is on *top*. Refused in
  // both directions — once for the mounts this process knows about, and once for
  // whatever anybody else left there.
  for (const existing of live) {
    if (existing.mountpoint === target) {
      throw new Error(
        `mountx: ${target} is already mounted by this process. Unmount it before mounting again.`,
      );
    }
  }
  // Deliberately stricter than the FUSE transport, which refuses only a `fuse*`
  // occupant: there is no such thing as a harmless filesystem to mount over —
  // whatever is under this one, `umount` still detaches the top — and unlike
  // FUSE there is no legitimate case of mounting 9P onto a path this library
  // itself is already serving. Same stance as `mountNfs`.
  const occupant = mountEntryAt(target);
  if (occupant !== undefined && occupant !== null) {
    throw new Error(
      `mountx: ${target} already has a filesystem on it (${occupant.source}, type ` +
        `${occupant.type}). Mounting over it would stack a second mount and make either ` +
        `unmount detach the wrong one. Clear it first: umount ${target}`,
    );
  }

  // A directory of our own making, `0700` from the moment it exists, holding
  // one socket — which is the access control for a protocol that has none. The
  // realpath first, because `mount(8)` canonicalizes the source it is given and
  // the kernel's 108-byte limit applies to whatever comes out of that.
  let socketDir: string | undefined;
  let server: P9Server;
  let trans: "unix" | "tcp";
  let source: string;
  let impl: P9MountImpl | undefined;
  const serverOptions: P9ServerOptions = {
    ...options,
    onTransportError: (error, peer) => {
      // Teardown is not a fault: the kernel dropping its connection is how a
      // 9P mount ends.
      if (impl?.active !== false) {
        options.onTransportError?.(error, peer);
      }
    },
  };
  if (options.server !== undefined) {
    server = options.server;
    trans = server.path === undefined ? "tcp" : "unix";
    source = server.path ?? server.host;
  } else if (
    options.port !== undefined ||
    options.host !== undefined ||
    options.path !== undefined
  ) {
    // A caller who named a port, an address or a path gets exactly that; the
    // server constructor is what refuses the combinations that make no sense.
    server = createP9Server(driver, serverOptions);
    trans = server.path === undefined ? "tcp" : "unix";
    source = server.path ?? server.host;
  } else {
    const base = await realpath(tmpdir()).catch(() => tmpdir());
    socketDir = await mkdtemp(join(base, "mountx-9p-"));
    source = join(socketDir, "9p.sock");
    trans = "unix";
    server = createP9Server(driver, { ...serverOptions, path: source });
  }
  /** Undo the directory this call made, and only that one. */
  const discard = async (): Promise<void> => {
    if (socketDir !== undefined) {
      await rm(socketDir, { recursive: true, force: true }).catch(() => {});
    }
  };
  // Whichever kernel-side bound applies to the source we are about to name,
  // checked before anything is bound: a long `TMPDIR` or an `::1` host should
  // produce a sentence, not a mount failure with nothing in its stderr.
  const refusal = trans === "unix" ? socketPathRefusal(source) : tcpSourceRefusal(source);
  if (refusal !== undefined) {
    await discard();
    throw new Error(refusal);
  }

  // Adoption is a set-difference over `server.clients` (see `start`), so two
  // mounts sharing one server must not overlap: interleaved, each could take
  // the other's connection, and a connection is this transport's unmount
  // signal. One at a time per server — different servers, which is the default,
  // never wait on each other.
  let release!: () => void;
  const held = new Promise<void>((resolvePromise) => {
    release = resolvePromise;
  });
  const gate = adopting.get(server) ?? Promise.resolve();
  adopting.set(
    server,
    gate.then(() => held),
  );
  await gate;
  try {
    const before = new Set(server.clients);
    await server.listen();
    impl = new P9MountImpl(
      server,
      target,
      { trans, port: server.port },
      source,
      options,
      socketDir,
    );
    await impl.start(before, probe.transport);
  } catch (error) {
    await server.close().catch(() => {});
    await discard();
    throw error;
  } finally {
    release();
  }
  return impl;
}

/** `/proc/self/mounts` escapes these four characters in paths. */
function unescapeMountPath(path: string): string {
  return path.replace(/\\(?:040|011|012|134)/g, (match) =>
    String.fromCharCode(Number.parseInt(match.slice(1), 8)),
  );
}

/** One line of `/proc/self/mounts`. */
export interface MountEntry {
  source: string;
  target: string;
  type: string;
}

/**
 * Parse `/proc/self/mounts`.
 *
 * A near-copy of the reader in `src/nfs/mount.ts`, deliberately: importing that
 * one would pull the whole NFS server and its RFC 1813 codec into every process
 * that mounts 9P, for fifteen lines of string handling. This one is Linux-only,
 * because 9P is.
 */
export function parseMountTable(table: string): MountEntry[] {
  const entries: MountEntry[] = [];
  for (const line of table.split("\n")) {
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
 * What is mounted at `target`, `undefined` if nothing is, and `null` if the
 * table could not be read at all. The last matching entry wins — that is the
 * one on top, and the one `umount` would take down.
 */
function mountEntryAt(target: string): MountEntry | undefined | null {
  let table: string;
  try {
    table = fs.readFileSync("/proc/self/mounts", "utf8");
    /* v8 ignore next 4 -- no procfs, which on Linux means something stranger
       than an unmounted filesystem is going on. */
  } catch {
    return null;
  }
  let found: MountEntry | undefined;
  for (const entry of parseMountTable(table)) {
    if (entry.target === target) {
      found = entry;
    }
  }
  return found;
}

/**
 * Is `target` mounted? `undefined` means the table could not be read.
 *
 * The tri-state is the point, and it is the same one `src/nfs/mount.ts`
 * documents: forcing down a mount that turns out to be gone is harmless,
 * whereas treating "no idea" as "gone" reports a successful unmount for a mount
 * that is still live — and then shuts the server down underneath it.
 */
function isMounted(target: string): boolean | undefined {
  const entry = mountEntryAt(target);
  return entry === null ? undefined : entry !== undefined;
}

/** Everything spawned here talks only through its exit status and stderr. */
const QUIET_STDIO: Array<"ignore" | "pipe" | number> = ["ignore", "ignore", "pipe"];

/** Is this an address a `trans=tcp` mount would reach over loopback? */
function isLoopbackAddress(address: string): boolean {
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(address);
}

/**
 * Is this `P9Connection.peer` — `address:port` — a loopback client?
 *
 * The `::ffff:` prefix is how a dual-stack listener reports an IPv4 peer, and
 * IPv4 is all a v9fs `trans=tcp` client can be (see {@link tcpSourceRefusal}),
 * so the whole space of answers is a `127.` address with or without that
 * prefix.
 */
function isLoopbackPeer(peer: string | undefined): boolean {
  if (peer === undefined) {
    return false;
  }
  const bare = peer.startsWith("::ffff:") ? peer.slice(7) : peer;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?$/.test(bare);
}

class P9MountImpl implements P9Mount {
  readonly mountpoint: string;
  readonly server: P9Server;
  readonly source: string;
  readonly trans: "unix" | "tcp";
  readonly closed: Promise<void>;

  readonly #target: P9MountTarget;
  readonly #options: MountP9Options;
  /** The temporary directory this mount made, and the only one it may delete. */
  readonly #socketDir: string | undefined;
  #connection: P9Connection | undefined;
  #closedResolve!: () => void;
  #stopping = false;
  #finishing: Promise<void> | undefined;
  #unmounting: Promise<void> | undefined;

  constructor(
    server: P9Server,
    mountpoint: string,
    target: P9MountTarget,
    source: string,
    options: MountP9Options,
    socketDir: string | undefined,
  ) {
    this.server = server;
    this.mountpoint = mountpoint;
    this.source = source;
    this.trans = target.trans;
    this.#target = target;
    this.#options = options;
    this.#socketDir = socketDir;
    this.closed = new Promise<void>((resolvePromise) => {
      this.#closedResolve = resolvePromise;
    });
  }

  get connection(): P9Connection {
    if (this.#connection === undefined) {
      /* v8 ignore next 2 -- `start()` either sets it or throws, and nothing
         hands out a `P9Mount` that did not finish starting. */
      throw new Error("mountx: this 9P mount has no connection yet");
    }
    return this.#connection;
  }

  get active(): boolean {
    return !this.#stopping;
  }

  /**
   * Spawn `mount(8)`, then adopt the connection it left behind.
   *
   * `before` is the set of connections the server already had, so the kernel's
   * is identified by being the new one rather than by being the first — a
   * caller-supplied server may already have clients on it.
   */
  async start(before: ReadonlySet<P9Connection>, transportModule: boolean): Promise<void> {
    const options = p9MountOptions(this.#target, this.#options);
    // `-i` matters for the same reason it does on the FUSE path: without it
    // `mount(8)` looks for a `/sbin/mount.9p` helper, and v9fs needs none.
    // `--` because `mount(8)` permutes its arguments, so a source beginning
    // with a dash would otherwise be read as an option to a program running as
    // root.
    const args = ["-i", "-t", "9p", "-o", options, "--", this.source, this.mountpoint];
    let result: SpawnResult;
    try {
      result = await run("mount", args, { stdio: QUIET_STDIO });
    } catch (error) {
      throw new Error(`mountx: could not run mount(8): ${errorMessage(error)}`);
    }
    if (result.status !== 0) {
      throw new Error(
        `mountx: mounting ${this.mountpoint} failed — ` +
          `${describe(`mount -t 9p -o ${options}`, result)}.` +
          (transportModule
            ? ""
            : ` Note that /sys/module/9pnet_fd is not there: trans=${this.trans} lives in that ` +
              `module, the kernel does not autoload a 9P transport, and without it every mount ` +
              `fails this way. \`modprobe 9pnet_fd\` if the host has it.`),
      );
    }
    const connection = this.server.clients.find(
      (client) => !before.has(client) && this.#plausible(client),
    );
    if (connection === undefined) {
      // Unreachable as far as the protocol goes — `mount(8)` returns zero only
      // after the kernel has completed a `Tversion` and a `Tattach` with us, so
      // the connection is there. Handled anyway, and handled by *undoing the
      // mount*: a mountpoint whose server is about to be closed underneath it is
      // worse than no mount at all.
      await run("umount", [this.mountpoint], { stdio: QUIET_STDIO, timeout: 10_000 }).catch(
        () => {},
      );
      throw new Error(
        `mountx: ${this.mountpoint} was mounted but no 9P connection arrived — refusing to ` +
          `serve a mount nothing is attached to`,
      );
    }
    this.#connection = connection;
    live.add(this);
    if (this.#options.signals !== false) {
      installSignalHandlers();
    }
    // There is no `Tdestroy`: the connection ending *is* the unmount, ours or
    // anybody else's. `closed` resolves after the session is destroyed and the
    // socket is closed, which is exactly when there is nothing left to serve.
    void connection.closed.then(() =>
      this.#finish().catch(() => {
        // Whoever calls `unmount()` gets this failure; an event handler has
        // nobody to hand it to, and an unhandled rejection here would take the
        // process down over a server that would not close.
      }),
    );
  }

  /**
   * Could this connection be the one the kernel just made?
   *
   * Only ever narrows, and only where narrowing is sound. A `trans=tcp` mount
   * against a *loopback* source has a kernel client whose peer is necessarily
   * loopback too, so anything else on that listener is somebody else and not a
   * candidate. A mount whose source is not loopback is one where the client
   * connects from the machine's own address, which this cannot predict — and a
   * unix socket has no peer address at all — so both take everything new and
   * lean on the serialization instead.
   */
  #plausible(connection: P9Connection): boolean {
    if (this.trans !== "tcp" || !isLoopbackAddress(this.source)) {
      return true;
    }
    return isLoopbackPeer(connection.peer);
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
   * The deadline is not paranoia: `umount(8)` quiesces the filesystem before it
   * detaches, so a driver that has stopped answering blocks it in `D` state —
   * and with it `unmount()`, `await using`, and the signal handlers.
   *
   * **One budget per phase, shared by its steps**, the same discipline
   * `src/nfs/mount.ts` keeps: the deadline is built once at the top and each
   * spawn gets what is left of it, so two `umount`s in a row cannot cost two
   * deadlines. The escalation then gets a budget of its own, because it runs
   * only once this one is spent.
   */
  async #unmount(): Promise<void> {
    const timeout = this.#options.unmountTimeout ?? 10_000;
    const bounded = Number.isFinite(timeout) && timeout > 0;
    const budget = deadlineIn(bounded ? timeout : undefined);
    let failure: unknown;
    const steps = this.#unmountSteps(budget).then(
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
        // gets `EIO`. `unmount()` is retryable for exactly this case.
        throw failure;
      }
      await this.#settle(budget);
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
      throw failure;
    }
    // Whatever the steps left of the budget is what shutting the server down
    // gets — the phase is one budget, and this is the last step in it.
    await this.#settle(budget);
  }

  /**
   * `umount(8)`, under `deadline`. `"timeout"` means it never answered — the
   * caller escalates; anything genuinely wrong throws.
   */
  async #unmountSteps(deadline: Deadline): Promise<"done" | "timeout"> {
    if (isMounted(this.mountpoint) === false) {
      // Someone else already unmounted us.
      return "done";
    }
    let result: SpawnResult;
    try {
      result = await run("umount", [this.mountpoint], {
        stdio: QUIET_STDIO,
        timeout: deadline.remaining(),
      });
    } catch (error) {
      throw new Error(`mountx: could not run umount(8): ${errorMessage(error)}`);
    }
    if (result.timedOut === true) {
      return "timeout";
    }
    // A failure that raced an external unmount is not a failure. A table that
    // will not say is not that race: the mount is presumed live.
    if (result.status === 0 || isMounted(this.mountpoint) === false) {
      return "done";
    }
    throw new Error(
      `mountx: could not unmount ${this.mountpoint} (${describe("umount", result)}). ` +
        `The mount is still live. If a process is holding it, \`fuser -m ${this.mountpoint}\` ` +
        `will say which; \`sudo umount -l ${this.mountpoint}\` detaches it regardless.`,
    );
  }

  /**
   * Teardown when asking nicely did not work.
   *
   * `umount -f` first, because v9fs really implements it: `MNT_FORCE` reaches
   * `v9fs_umount_begin()` → `v9fs_session_begin_cancel()`, which fails the
   * requests in flight and lets the blocked `umount` finish — the same shape as
   * FUSE's `fuse_abort_conn`. `umount -l` then covers a table entry that
   * outlives the abort. Neither exit status is believed; the mount table is.
   *
   * Dropping the server is the backstop below all of it: when the connection
   * dies the client fails everything outstanding, so `#finish()` runs whether
   * or not the ladder worked.
   */
  async #force(timeout: number): Promise<void> {
    // The escalation's own budget, shared by both rungs: given the full
    // `timeout` apiece they would cost twice the deadline that sent us here.
    const budget = deadlineIn(timeout);
    const error = new Error(
      `mountx: unmounting ${this.mountpoint} did not finish within ${timeout}ms — the driver ` +
        `has probably stopped answering. The mount has been forced down, so anything in flight ` +
        `was lost. If the mountpoint is somehow still listed: sudo umount -l ${this.mountpoint}`,
    );
    this.#options.onTransportError?.(error, undefined);
    for (const args of [
      ["-f", this.mountpoint],
      ["-l", this.mountpoint],
    ]) {
      // Only a table that says it is gone stops the ladder — see `isMounted`.
      if (isMounted(this.mountpoint) === false) {
        break;
      }
      // Bounded for the same reason the first `umount` is: a step that never
      // returns must not outlive the ladder it is a step of.
      await run("umount", args, { stdio: QUIET_STDIO, timeout: budget.remaining() }).catch(() => {
        // Nothing to add: the next read of the mount table is the verdict.
      });
    }
    // Under the ladder's own budget, not unbounded: see `#settle`, and note
    // that the driver this is closing fids through is by hypothesis the one
    // that stopped answering.
    await this.#settle(budget);
    throw error;
  }

  /**
   * {@link P9MountImpl.#finish}, and stop waiting when the phase's budget runs
   * out. This is what makes "settles within twice `unmountTimeout`" true.
   *
   * `#finish()` is not the quick bookkeeping it looks like. `server.close()`
   * ends by awaiting every connection's `close()`, each of which awaits
   * `P9Session.destroy()` — which closes the fids the session still holds
   * **through the driver**, and a driver that has stopped answering is the
   * stated premise of every path that gets here. Awaiting that unconditionally
   * would hand back the hang the deadline exists to prevent, one step down.
   *
   * Abandoning it is safe in the way that matters, because of the order
   * `P9ServerImpl.#close()` works in: the listener is closed and every owned
   * stream destroyed *before* the per-connection teardown is awaited. So what a
   * lapsed budget walks away from is only the driver's own `close()` calls —
   * precisely what the FUSE transport's `#finish(true)` skips for the same
   * reason. One consequence is worth naming: the `mkdtemp` socket directory is
   * removed at the *end* of `#doFinish`, so a close that never finishes leaves
   * that directory behind in `tmpdir` — an empty `0700` directory and a dead
   * socket, against a hang that would otherwise never return.
   */
  async #settle(budget: Deadline): Promise<void> {
    // Started before the budget is read, so an already-spent one still gets the
    // synchronous half — the listener closing and the streams going down.
    const finished = this.#finish().catch((error: unknown) => {
      this.#options.onTransportError?.(error, undefined);
    });
    const remaining = budget.remaining();
    if (remaining === undefined) {
      // No deadline at all, which is what `unmountTimeout: 0` asked for.
      await finished;
      return;
    }
    await Promise.race([finished, delay(remaining)]);
    // `closed` settles here rather than only at the end of `#doFinish`: by now
    // the mount is detached and nothing can reach the server, which is what
    // this promise means, and leaving it pending would let a caller that
    // awaits it inherit exactly the hang `unmount()` just refused to. Resolving
    // twice is a no-op, so `#doFinish` finishing later changes nothing.
    this.#closedResolve();
  }

  /** Stop serving, forget the mount, and take the socket directory with it. */
  #finish(): Promise<void> {
    this.#finishing ??= this.#doFinish();
    return this.#finishing;
  }

  async #doFinish(): Promise<void> {
    this.#stopping = true;
    live.delete(this);
    if (live.size === 0) {
      removeSignalHandlers();
    }
    await this.server.close();
    if (this.#socketDir !== undefined) {
      // Only ever the directory this mount made: a `path` or a `server` the
      // caller supplied is theirs, socket and all.
      await rm(this.#socketDir, { recursive: true, force: true }).catch(() => {});
    }
    this.#closedResolve();
  }
}
