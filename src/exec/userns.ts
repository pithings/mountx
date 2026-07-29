/**
 * SPIKE A — "no root, no helper, no host mount": FUSE inside an unprivileged
 * user namespace. Not a shipping module yet.
 *
 * This is the cheap baseline the other two spikes are measured against, and it
 * is the only one of the three that is not an approximation of a filesystem:
 * what the child sees *is* FUSE, with the kernel's own VFS in front of it, so
 * every POSIX guarantee the FUSE transport already passes conformance on holds
 * verbatim. It also runs a static binary, a Go binary and a setuid binary the
 * same as any other, because nothing here depends on what the child is linked
 * against.
 *
 * What it gives up is the thing the framing asked for: it *is* a real kernel
 * mount. It is simply a mount nobody outside the namespace can see, which is
 * the property that matters for "give this subprocess a filesystem" and the
 * one that made a user-namespace mode not worth shipping back when the goal
 * was "mount a directory for the machine" (see the roadmap's rootless-FUSE
 * entry). For an `exec()`-shaped API the tradeoff inverts: invisible is the
 * point.
 *
 * **Why there is a helper process at all.** `unshare(CLONE_NEWUSER)` demands a
 * single-threaded caller and Node is never single-threaded, so a mountx process
 * cannot enter the namespace it needs — not with `unshare(2)`, and not with
 * `setns(2)`, which has the same rule. The namespace is therefore entered by a
 * child, `/dev/fuse` is opened in there, and the traffic comes back out over a
 * unix socket to the session here. That split is not a workaround for the
 * spike; it is the shape any version of this has to take, and it is the
 * "relay mode" the roadmap defers, arrived at from the other direction.
 *
 * ```ts
 * const status = await execUserns(createMemoryDriver(), ["ls", "-la", "/mnt/x"], {
 *   mountpoint: "/mnt/x",
 * });
 * ```
 */

import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import * as net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FuseSession, type FuseSessionOptions } from "../fuse/session.ts";
import type { FsDriver } from "../types.ts";

/** Where this file's sibling relay lives, resolved the way the CLI resolves the README. */
const RELAY = new URL("userns-relay.ts", import.meta.url).pathname;

/** The `len` field every FUSE message begins with. */
const LEN_SIZE = 4;

export interface ExecUsernsOptions extends FuseSessionOptions {
  /**
   * Where the driver appears *inside the namespace*. Defaults to a private
   * temporary directory, which is also where the child's `cwd` is set unless
   * `cwd` says otherwise.
   *
   * The path has to exist on the real filesystem — a mount namespace is a copy
   * of the parent's mount table, not an empty one — but the mount made on it is
   * visible only to the child tree.
   */
  mountpoint?: string;
  /** Working directory for the command. Defaults to the mountpoint. */
  cwd?: string;
  /** Environment for the command. Defaults to this process's. */
  env?: NodeJS.ProcessEnv;
  /** Extra `-o` options passed through to `mount(8)` inside the namespace. */
  mountOptions?: string[];
  /** Called with each line the relay writes to stderr. Defaults to forwarding. */
  onRelayError?: (message: string) => void;
}

export interface ExecUsernsResult {
  /** The command's exit status, or `null` if a signal ended it. */
  code: number | null;
  /** The signal that ended the command, if one did. */
  signal: NodeJS.Signals | null;
  /** Where the driver was mounted inside the namespace. */
  mountpoint: string;
}

/**
 * Run `argv` with `driver` mounted at `options.mountpoint`, visible to that
 * command and everything it spawns and to nothing else on the machine.
 *
 * Needs unprivileged user namespaces (`kernel.unprivileged_userns_clone`, or
 * simply a kernel that allows them, which is most) and `unshare(1)` from
 * util-linux. Needs no root, no `fusermount3` and no native addon.
 */
export async function execUserns(
  driver: FsDriver,
  argv: readonly string[],
  options: ExecUsernsOptions = {},
): Promise<ExecUsernsResult> {
  if (process.platform !== "linux") {
    throw new Error(`mountx: user namespaces need Linux, this is ${process.platform}`);
  }
  if (argv.length === 0) {
    throw new Error("mountx: execUserns needs a command to run");
  }
  const scratch = await mkdtemp(join(tmpdir(), "mountx-exec-"));
  const socketPath = join(scratch, "relay.sock");
  const mountpoint = options.mountpoint ?? join(scratch, "mnt");
  if (options.mountpoint === undefined) {
    await mkdir(mountpoint, { recursive: true });
  }

  const session = new FuseSession(driver, options);
  const server = net.createServer();
  /** Resolves once the relay has connected and the session is wired to it. */
  const attached = new Promise<void>((resolveAttached) => {
    server.on("connection", (socket) => {
      attach(session, socket);
      resolveAttached();
    });
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(socketPath, resolveListen);
  });

  try {
    const relayArgs = [
      socketPath,
      mountpoint,
      (options.mountOptions ?? ["default_permissions"]).join(","),
      "--",
      ...argv,
    ];
    const child = spawn(
      "unshare",
      // Short flags on purpose. `-U -r -m` mean the same thing to util-linux's
      // `unshare(1)` and to busybox's applet, but the long spelling does not:
      // busybox 1.37 has `-r` and no `--map-root-user` at all, so the long form
      // fails outright on Alpine and anything else that is busybox-only.
      // `--propagation` is the one long option both do accept.
      ["-U", "-r", "-m", "--propagation", "private", process.execPath, RELAY, ...relayArgs],
      {
        stdio: "inherit",
        cwd: options.cwd ?? process.cwd(),
        env: options.env ?? process.env,
      },
    );
    const exited = new Promise<ExecUsernsResult>((resolveExit, rejectExit) => {
      child.on("error", (error) => rejectExit(error));
      child.on("exit", (code, signal) => resolveExit({ code, signal, mountpoint }));
    });
    // If the relay dies before connecting, `exited` settles first and nothing
    // waits forever on a handshake that is not coming.
    await Promise.race([attached, exited]);
    return await exited;
  } finally {
    await session.destroy().catch(() => {});
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    await rm(scratch, { recursive: true, force: true }).catch(() => {});
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
