/**
 * `execUserns()` — run a command with a driver mounted over FUSE inside an
 * unprivileged user namespace, visible to that command's process tree and to
 * nothing else on the machine.
 *
 * This is the mechanism {@link import("./index.ts").exec} picks wherever the
 * kernel's FUSE is usable, and it is not an approximation of a filesystem: what
 * the child sees *is* FUSE, with the kernel's own VFS in front of it, so every
 * POSIX guarantee `src/fuse/` already passes conformance on holds verbatim. It
 * also runs a static binary, a Go binary and a setuid binary the same as any
 * other, because nothing here depends on what the child is linked against.
 *
 * What it gives up is that it *is* a real kernel mount. It is simply a mount
 * nobody outside the namespace can see — `/proc/self/mounts` on the host stays
 * empty, and the mount dies with the namespace. That is the property that made
 * a user-namespace mode not worth shipping back when the goal was "mount a
 * directory for the machine" (see the roadmap's rootless-FUSE entry); for an
 * `exec()`-shaped API the tradeoff inverts, and invisible is the point.
 *
 * **Why there is a helper process at all.** `unshare(CLONE_NEWUSER)` demands a
 * single-threaded caller and Node is never single-threaded, so a mountx process
 * cannot enter the namespace it needs — not with `unshare(2)`, and not with
 * `setns(2)`, which has the same rule. The namespace is therefore entered by a
 * child, `/dev/fuse` is opened in there, and the traffic comes back out over a
 * unix socket to the session here. That split is not a workaround; it is the
 * shape any version of this has to take, and it is the "relay mode" the roadmap
 * defers, arrived at from the other direction.
 *
 * **Nothing here is privileged.** Inside the namespace the relay is uid 0 with
 * `CAP_SYS_ADMIN`, so it takes the ordinary root mount path: no `fusermount3`,
 * no setuid bit, and no native addon. On a host with no `fuse3` package
 * installed at all — this project's dev host, see `.agents/environment.md` —
 * this is the only FUSE route that works.
 *
 * ```ts
 * const ran = await execUserns(createMemoryDriver(), ["sh", "-c", "ls -la $MOUNTX_ROOT"]);
 * ran.code; // the command's exit status
 * ```
 */

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import * as net from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { FuseSession, type FuseSessionOptions } from "../fuse/session.ts";
import type { FsDriver } from "../types.ts";
import { usernsExecProbe } from "./probe.ts";

/** The `len` field every FUSE message begins with. */
const LEN_SIZE = 4;

/**
 * The `-o` options the mount gets when the caller names none: **none**, and
 * `default_permissions` in particular.
 *
 * It is the option a FUSE mount usually wants, and it is wrong here, for a
 * reason that only exists inside a user namespace. `default_permissions` asks
 * the *kernel* to check the driver's `uid`/`gid`/`mode` against the caller's
 * credentials — and in here those two are not the same identity space.
 * `unshare -r` maps exactly one uid, yours, onto 0; a driver reporting your
 * real uid (which every driver in this repository does, since that is what
 * `process.getuid()` says on the serving side) is therefore reporting an
 * identity the namespace does not map, which the kernel renders as `nobody`.
 * Witnessed: with `default_permissions` on, a `mode` 0755 root directory owned
 * by `nobody` refuses every write from the one process that is meant to have
 * it, and namespace-root's `CAP_DAC_OVERRIDE` does not rescue it because that
 * capability does not reach a file owned by an unmapped uid.
 *
 * So permission checking stays with the driver, where it can see who it is
 * serving. Nothing is lost by it: the mount carries no `allow_other`, so the
 * only process that can reach it is the one this call created it for.
 */
const DEFAULT_MOUNT_OPTIONS: readonly string[] = [];

/**
 * Where the relay is, relative to this module, in each layout it can be in.
 *
 * The relay is spawned rather than imported, so it has to be a file on disk
 * with a path — which makes it the one thing here that has to survive the
 * build as itself. It is a build entry for exactly that reason, landing at
 * `dist/exec/userns-relay.mjs`; what moves underneath it is *this* file:
 *
 * - `src/exec/userns.ts` — the source tree, where the relay is a sibling `.ts`
 *   and Node's own type stripping runs it directly.
 * - `dist/_chunks/userns.mjs` — the built package. `src/exec/index.ts` reaches
 *   this module through `await import()`, which is the whole point of the
 *   mechanism split, and obuild answers a dynamic import with a *chunk* rather
 *   than by inlining it. So the sibling relationship does not survive, and
 *   `dist/exec/` is one directory over.
 *
 * Both are checked, cheaply, once per call. A third layout would announce
 * itself as the thrown error below rather than as a mystery `ENOENT` from
 * `spawn`, which is what this is for.
 */
const RELAY_CANDIDATES = [
  "userns-relay.ts",
  "userns-relay.mjs",
  "../exec/userns-relay.mjs",
] as const;

/** The relay on disk, in whichever layout this module was loaded from. */
function relayPath(): string {
  for (const name of RELAY_CANDIDATES) {
    const candidate = new URL(name, import.meta.url).pathname;
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    "mountx: the userns relay is missing — `userns-relay` is spawned rather than imported, so " +
      "it has to exist as a file next to this module or under a sibling `exec/` directory, and " +
      "an install or bundle that dropped it cannot run a command in a namespace",
  );
}

export interface ExecUsernsOptions extends FuseSessionOptions {
  /**
   * Where the driver appears *inside the namespace*, and the value of
   * `$MOUNTX_ROOT`. Defaults to a private temporary directory.
   *
   * The path has to exist on the real filesystem — a mount namespace is a copy
   * of the parent's mount table, not an empty one — so a path that does not is
   * created here, recursively. The mount made on it is visible only to the
   * child tree either way.
   */
  mountpoint?: string;
  /**
   * Working directory for the command. Defaults to this process's.
   *
   * **Never inside {@link ExecUsernsOptions.mountpoint}** — see
   * {@link cwdRefusal}, which refuses that rather than letting it deadlock.
   */
  cwd?: string;
  /** Environment for the command. Defaults to this process's. */
  env?: NodeJS.ProcessEnv;
  /**
   * `-o` options passed through to `mount(8)` inside the namespace. Default
   * none — see {@link DEFAULT_MOUNT_OPTIONS} for why `default_permissions` is
   * not among them.
   */
  mountOptions?: string[];
}

export interface ExecUsernsResult {
  /** The command's exit status, or `null` if a signal ended it. */
  code: number | null;
  /** The signal that ended the command, if one did. */
  signal: NodeJS.Signals | null;
  /** Where the driver was mounted inside the namespace, and `$MOUNTX_ROOT`. */
  mountpoint: string;
}

/**
 * Why this `cwd` cannot be used with this mountpoint, or `undefined` if it can.
 *
 * The one refusal in this file that is about the *request* rather than the
 * host, and the reason it exists is witnessed rather than theoretical: setting
 * the child's `cwd` to the mountpoint wedges the relay in `D` state at
 * `fuse_get_req` permanently. It is the spawn hazard `src/fuse/mount.ts` and
 * `src/9p/mount.ts` both document, met from the inside — `uv_spawn` blocks the
 * calling thread until the child execs, the child's first act is a `chdir` into
 * the mount, and the reply that would unblock it can only come from the thread
 * that is blocked. Nothing on this side can recover from it, so it is refused
 * up front, with the spelling that works named in the message.
 *
 * Pure and exported for the Tier-0 test: the alternative way to check this
 * costs a hung process.
 */
export function cwdRefusal(cwd: string, mountpoint: string): string | undefined {
  const inside = resolve(cwd);
  const root = resolve(mountpoint);
  if (inside !== root && !inside.startsWith(`${root}/`)) {
    return undefined;
  }
  return (
    `cwd ${inside} is inside the mountpoint ${root}, which deadlocks rather than failing: ` +
    `uv_spawn blocks the thread serving FUSE until the child execs, and a child whose first ` +
    `act is a chdir into the mount waits for a reply only that thread can send. Run the ` +
    `command as \`sh -c 'cd "$MOUNTX_ROOT" && …'\` instead — a cd after the exec is safe`
  );
}

/**
 * Run `argv` with `driver` mounted at `options.mountpoint`, visible to that
 * command and everything it spawns and to nothing else on the machine.
 *
 * Resolves when the command exits, with that command's status; a command that
 * fails is not an error here. An error is thrown when the *mechanism* could not
 * be set up — a host that cannot do this (see `usernsExecProbe()`), a request
 * that cannot work ({@link cwdRefusal}), or a relay that failed before the
 * command ran, whose own message is what surfaces.
 *
 * Needs no root, no `fusermount3` and no native addon.
 */
export async function execUserns(
  driver: FsDriver,
  argv: readonly string[],
  options: ExecUsernsOptions = {},
): Promise<ExecUsernsResult> {
  if (argv.length === 0) {
    throw new Error("mountx: execUserns needs a command to run");
  }
  // The whole host verdict up front, in one sentence naming every missing
  // piece, rather than an ENOENT from an `open("/dev/fuse")` three processes
  // away that nothing here would be able to explain by the time it arrived.
  const probe = usernsExecProbe();
  if (!probe.usable) {
    throw new Error(`mountx: cannot run a command in a user namespace here — ${probe.reason}`);
  }
  const relay = relayPath();

  const scratch = await mkdtemp(resolve(tmpdir(), "mountx-exec-"));
  const socketPath = resolve(scratch, "relay.sock");
  const statusPath = resolve(scratch, "relay.status");
  const mountpoint =
    options.mountpoint === undefined ? resolve(scratch, "mnt") : resolve(options.mountpoint);

  let session: FuseSession | undefined;
  let server: net.Server | undefined;
  try {
    await prepareMountpoint(mountpoint);
    const cwd = resolve(options.cwd ?? process.cwd());
    const refusal = cwdRefusal(cwd, mountpoint);
    if (refusal !== undefined) {
      throw new Error(`mountx: ${refusal}`);
    }

    session = new FuseSession(driver, options);
    const attachedSession = session;
    server = net.createServer();
    /** Resolves once the relay has connected and the session is wired to it. */
    const attached = new Promise<void>((resolveAttached) => {
      server!.on("connection", (socket) => {
        attach(attachedSession, socket);
        resolveAttached();
      });
    });
    await new Promise<void>((resolveListen, rejectListen) => {
      server!.once("error", rejectListen);
      server!.listen(socketPath, resolveListen);
    });

    const relayArgs = [
      socketPath,
      mountpoint,
      (options.mountOptions ?? [...DEFAULT_MOUNT_OPTIONS]).join(","),
      "--",
      ...argv,
    ];
    const child = spawn(
      probe.unshare!,
      // Short flags on purpose. `-U -r -m` mean the same thing to util-linux's
      // `unshare(1)` and to busybox's applet, but the long spelling does not:
      // busybox 1.37 has `-r` and no `--map-root-user` at all, so the long form
      // fails outright on Alpine and anything else that is busybox-only.
      // `--propagation` is the one long option both do accept.
      ["-U", "-r", "-m", "--propagation", "private", process.execPath, relay, ...relayArgs],
      {
        stdio: "inherit",
        cwd,
        // `MOUNTX_RELAY_STATUS` is how a relay failure reaches this process as
        // an error instead of masquerading as the command's own exit status.
        // The relay strips it back out of what the command sees.
        env: { ...(options.env ?? process.env), MOUNTX_RELAY_STATUS: statusPath },
      },
    );
    const exited = new Promise<ExecUsernsResult>((resolveExit, rejectExit) => {
      child.on("error", (error) =>
        rejectExit(
          new Error(`mountx: could not run ${probe.unshare} — ${(error as Error).message}`, {
            cause: error,
          }),
        ),
      );
      child.on("exit", (code, signal) => resolveExit({ code, signal, mountpoint }));
    });
    // If the relay dies before connecting, `exited` settles first and nothing
    // waits forever on a handshake that is not coming.
    await Promise.race([attached, exited]);
    const result = await exited;
    const failure = statusMessage(statusPath);
    if (failure !== undefined) {
      throw new Error(`mountx: ${failure}`);
    }
    return result;
  } finally {
    await session?.destroy().catch(() => {});
    if (server !== undefined) {
      await new Promise<void>((resolveClose) => server!.close(() => resolveClose()));
    }
    await rm(scratch, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * Make sure `mountpoint` is a directory, creating it if it is not there.
 *
 * A missing one is the ordinary case (it is the default, in a directory this
 * call just made), and a non-directory is a mistake worth naming: `mount(8)`
 * inside the namespace would answer `not a directory` from three processes
 * away, where the caller cannot see which path it meant.
 */
async function prepareMountpoint(mountpoint: string): Promise<void> {
  try {
    const stats = await stat(mountpoint);
    if (!stats.isDirectory()) {
      throw new Error(`mountx: mountpoint ${mountpoint} exists and is not a directory`);
    }
    return;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
  await mkdir(mountpoint, { recursive: true });
}

/** What the relay said before giving up, or `undefined` if it never did. */
function statusMessage(path: string): string | undefined {
  try {
    return readFileSync(path, "utf8").trim() || undefined;
  } catch {
    return undefined;
  }
}

/**
 * Drive a {@link FuseSession} over a stream instead of over `/dev/fuse`.
 *
 * The zero-copy contract still applies and is still met the same way: each
 * whole message is handed to `handleMessage` without awaiting it, and the
 * session copies what it retains before its first `await`. The one difference
 * from the device is that `pending` here owns its bytes — a socket chunk is
 * already a fresh buffer — so slicing a message out of it is safe.
 */
function attach(session: FuseSession, socket: net.Socket): void {
  let pending = Buffer.alloc(0);
  socket.on("data", (chunk: Buffer<ArrayBuffer>) => {
    pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
    while (pending.length >= LEN_SIZE) {
      const length = pending.readUInt32LE(0);
      if (length < LEN_SIZE || pending.length < length) {
        break;
      }
      const message = pending.subarray(0, length);
      pending = pending.subarray(length);
      void session
        .handleMessage(message)
        .then((reply) => {
          if (reply !== null && !socket.destroyed) {
            socket.write(reply);
          }
        })
        .catch(() => {});
    }
  });
  socket.on("error", () => {});
}
