/**
 * The in-namespace half of `execUserns()`.
 *
 * This file is the only thing that runs *inside* the user+mount namespace. It
 * exists because of one kernel rule: `unshare(CLONE_NEWUSER)` requires a
 * single-threaded caller, and Node is never single-threaded (the libuv
 * threadpool and V8's platform threads are up before any user code runs), so
 * `EINVAL` is the only answer a mountx process could ever get from unsharing
 * itself. `setns(2)` into a user namespace has the same rule. The namespace
 * can therefore only ever be entered by a *child*, which means the process
 * holding `/dev/fuse` is never the process holding the driver.
 *
 * So this helper holds the device and nothing else. It opens `/dev/fuse`,
 * spawns `mount(8)` — inside the namespace `getuid()` is 0, so this is the
 * ordinary root mount path with no `fusermount3` and no addon anywhere near it
 * — and then pumps raw FUSE traffic over a unix socket to the parent, which
 * runs the real {@link FuseSession} against the real driver.
 *
 * **Framing costs nothing.** Every FUSE message begins with its own total
 * length in a little-endian `u32` (`fuse_in_header.len`, `fuse_out_header.len`),
 * so a stream socket carries them with no envelope of our own. The one rule
 * that does not survive the socket is that a reply must reach the device in a
 * single `write(2)`; this side reassembles whole messages before writing, which
 * is what the `#pending` buffer is for.
 *
 * **How a failure in here becomes an error out there.** Everything this process
 * can fail at happens after `execUserns()` has already handed control to
 * `unshare(1)`, so an exit status is the only channel back — and an exit status
 * is exactly what the *command* is going to use too. Reporting `mount(8) never
 * came up` as "the command exited 70" would be indistinguishable from a command
 * that exited 70. So {@link fail} also writes its message to the file named by
 * `$MOUNTX_RELAY_STATUS`, which the parent reads once the child is gone and
 * turns into a thrown error; a run that never wrote the file ended for the
 * command's own reasons.
 *
 * Usage: `node userns-relay.ts <socket> <mountpoint> <mount-options> -- <command> [args...]`
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as net from "node:net";

/** `readBufferSize()`'s answer for the default `maxWrite`, spelled out here so
 * the relay has no imports from `src/`. 1 MiB of payload plus a page of
 * headers — negotiation can only ever agree to less. */
const READ_BUFFER = 1024 * 1024 + 4096;

/** Length prefix width: the `len` field at the head of every FUSE message. */
const LEN_SIZE = 4;

/** Where the parent reads a failure from. Absent when nobody is listening. */
const statusPath = process.env.MOUNTX_RELAY_STATUS;

function fail(message: string): never {
  process.stderr.write(`mountx-relay: ${message}\n`);
  if (statusPath !== undefined) {
    // Best effort by design: the parent falls back to the exit status, and a
    // relay that cannot write a file in a directory the parent just made has
    // worse problems than the message it was trying to leave.
    try {
      fs.writeFileSync(statusPath, `${message}\n`);
    } catch {}
  }
  process.exit(70);
}

const argv = process.argv.slice(2);
const separator = argv.indexOf("--");
if (separator < 0 || separator < 2) {
  fail("usage: userns-relay <socket> <mountpoint> -- <command> [args...]");
}
const socketPath = argv[0]!;
const mountpoint = argv[1]!;
const mountOptions = argv[2] === "--" ? "" : argv[2]!;
const command = argv.slice(separator + 1);
if (command.length === 0) {
  fail("no command to run");
}

// Inside the namespace this process is uid 0 with a full capability set, so
// this is `mount(2)` by the ordinary route. Nothing here is setuid.
const uid = process.getuid?.() ?? -1;
if (uid !== 0) {
  fail(`expected to be uid 0 inside the namespace, am ${uid}`);
}

let device: number;
try {
  device = fs.openSync("/dev/fuse", fs.constants.O_RDWR);
} catch (error) {
  fail(`could not open /dev/fuse inside the namespace: ${(error as Error).message}`);
}

const socket = net.connect(socketPath);
socket.on("error", (error) => fail(`socket: ${error.message}`));
// The parent going away is not survivable: every request from here on would
// park forever in `fuse_get_req` with nobody to answer it, and this process
// would be left orphaned holding a wedged mount. Witnessed once during the
// spike, which is why it is handled rather than assumed away. Closing the
// device first is what aborts the connection so anything already blocked in
// the kernel gets an error instead of waiting.
socket.on("close", () => {
  try {
    fs.closeSync(device);
  } catch {}
  process.exit(75);
});

socket.on("connect", () => {
  const rootMode = fs.statSync(mountpoint).mode;
  const options = [
    // The fd has to land in the child at *its own* number, which is why the
    // device is handed over as stdio slot 3 below and named as `fd=3` here.
    "fd=3",
    `rootmode=${rootMode.toString(8)}`,
    `user_id=${uid}`,
    `group_id=${process.getgid?.() ?? 0}`,
    ...(mountOptions === "" ? [] : [mountOptions]),
  ].join(",");
  // `-i` so `mount(8)` does not hand off to `/sbin/mount.fuse`, `--` so a
  // source beginning with a dash stays a source. Same reasoning as
  // `src/fuse/mount.ts`; this is that call with the fd renumbered.
  const mounter = spawn("mount", ["-i", "-t", "fuse", "-o", options, "--", "mountx", mountpoint], {
    stdio: ["ignore", "inherit", "inherit", device],
  });
  mounter.on("error", (error) => fail(`could not run mount(8): ${error.message}`));
  mounter.on("exit", (code) => {
    if (code !== 0) {
      fail(`mount(8) exited ${code} — the namespace mount never came up`);
    }
    pump();
    run();
  });
});

/** Device → socket. One `read(2)` is exactly one message, forwarded verbatim. */
function pump(): void {
  const buffer = Buffer.allocUnsafe(READ_BUFFER);
  const arm = (): void => {
    fs.read(device, buffer, 0, buffer.length, null, (error, bytesRead) => {
      if (error !== null) {
        // ENODEV is the unmount signal: the connection is gone.
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "ENODEV" || code === "EBADF") {
          socket.end();
          return;
        }
        if (code === "EINTR" || code === "EAGAIN") {
          arm();
          return;
        }
        fail(`reading /dev/fuse: ${error.message}`);
      }
      if (bytesRead > 0) {
        socket.write(Buffer.from(buffer.subarray(0, bytesRead)));
      }
      arm();
    });
  };
  arm();
}

// Socket → device. Reassembled to whole messages, because the device rejects a
// reply delivered in pieces.
let pending = Buffer.alloc(0);
socket.on("data", (chunk: Buffer<ArrayBuffer>) => {
  pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
  while (pending.length >= LEN_SIZE) {
    const length = pending.readUInt32LE(0);
    if (length < LEN_SIZE || pending.length < length) {
      break;
    }
    const message = pending.subarray(0, length);
    try {
      fs.writeSync(device, message, 0, length);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      // ENOENT here means the kernel already gave up on that request — an
      // interrupted syscall, not our problem. Anything else is.
      if (code !== "ENOENT" && code !== "ENODEV") {
        process.stderr.write(`mountx-relay: writing /dev/fuse: ${(error as Error).message}\n`);
      }
    }
    pending = pending.subarray(length);
  }
});

/** Run the command the caller actually wanted, then take the mount down. */
function run(): void {
  // **`cwd` is deliberately not the mountpoint.** Witnessed: setting it wedges
  // this process in `D` state at `fuse_get_req` and never comes back. It is the
  // spawn hazard `src/fuse/mount.ts` and `src/9p/mount.ts` both document, met
  // here from the inside — `uv_spawn` blocks the calling thread until the child
  // execs, the child's first act is to `chdir` into the mount, and the reply
  // that would unblock it can only come from the thread that is blocked. The
  // mountpoint is handed over as an environment variable instead, so the `cd`
  // happens *after* the exec, in a process that is not the one pumping.
  //
  // This is the same rule for the command binary itself: a command that lives
  // on the mount deadlocks here and no amount of care on this side fixes it.
  // Only a relay whose pump is not on the spawning thread would.
  // `MOUNTX_RELAY_STATUS` is this process's private channel back to the parent
  // and means nothing to the command, so it does not travel any further.
  const env: NodeJS.ProcessEnv = { ...process.env, MOUNTX_ROOT: mountpoint };
  delete env.MOUNTX_RELAY_STATUS;
  const child = spawn(command[0]!, command.slice(1), { stdio: "inherit", env });
  child.on("error", (error) => fail(`could not run ${command[0]}: ${error.message}`));
  child.on("exit", (code, signal) => {
    // `umount` here is uid 0 in the namespace, so it needs no helper either.
    // Failure is not worth reporting: this namespace is about to cease to
    // exist, and with it the mount.
    spawn("umount", [mountpoint], { stdio: "ignore" }).on("exit", () => {
      try {
        fs.closeSync(device);
      } catch {}
      socket.end();
      process.exitCode = signal === null ? (code ?? 0) : 128 + 1;
      // The read loop holds a threadpool thread; nothing here can be exited
      // out of politely once it is parked, so this is the one place a hard
      // exit is right — the namespace and everything in it goes with us.
      process.exit(process.exitCode);
    });
  });
}
