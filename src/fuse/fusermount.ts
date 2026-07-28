/**
 * Mounting without root, by driving `fusermount3`.
 *
 * `fusermount3` is the setuid-root helper that ships with libfuse. It checks
 * that you are allowed to mount where you asked, opens `/dev/fuse`, issues the
 * `mount(2)` you cannot, and sends the descriptor back over a UNIX socket. The
 * only part of that Node cannot do is receive the descriptor — see
 * `src/fuse/native.ts`.
 *
 * ## The handshake
 *
 * Transcribed from libfuse 3.18.2, `lib/mount.c` (`fuse_mount_fusermount`,
 * `receive_fd`) and `util/fusermount.c` (`send_fd`, `do_mount`, `mount_fuse`).
 * Guessing any of this would be a way to hang on a socket forever.
 *
 * - `socketpair(AF_UNIX, SOCK_STREAM)`. One end goes to the child **at its own
 *   fd number**, named by the environment variable `_FUSE_COMMFD`; libfuse
 *   also sets `_FUSE_COMMFD2` to the other end, which only matters for
 *   `auto_unmount` and is deliberately not set here.
 * - `fusermount3 -o <opts> -- <mountpoint>`. The `--` is not decoration: a
 *   mountpoint starting with `-` is otherwise parsed as options.
 * - The reply is one byte of payload carrying one `SCM_RIGHTS` descriptor.
 *   Without `auto_unmount` the helper then exits, so the descriptor is already
 *   queued by the time the child is reaped and receiving it never blocks.
 *
 * ## What it accepts in `-o`
 *
 * `fusermount3` parses the option string itself and **exits 1 on anything it
 * does not recognise**. It takes `fsname=`, `subtype=`, `auto_unmount`,
 * `default_permissions`, `allow_other`, `max_read=`, `blksize=`, and the
 * generic mount flags (`ro`, `noatime`, …). It *silently ignores* `fd=`,
 * `rootmode=`, `user_id=` and `group_id=` because it supplies those itself —
 * `rootmode` from the mountpoint's own file type, the ids from the calling
 * user. Every mount it makes is `MS_NOSUID | MS_NODEV`.
 *
 * `allow_other` needs `user_allow_other` in `/etc/fuse.conf` and fails with a
 * message saying so; unprivileged mounting has no other way to grant it.
 */

import { existsSync } from "node:fs";
import { closeSync } from "node:fs";
import { delimiter, join } from "node:path";
import { describe, errorMessage, run, stdioWith } from "./exec.ts";
import { loadNative } from "./native.ts";

/**
 * The helper names to look for, newest first.
 *
 * `fusermount` is the FUSE 2 name. It speaks the same handshake and is worth
 * falling back to, but only after `fusermount3`: on a host with both, FUSE 3
 * is the one whose kernel protocol matches what this library negotiates.
 */
const HELPERS = ["fusermount3", "fusermount"] as const;

let probed: string | null | undefined;

/**
 * The `fusermount3` on this host, or `undefined`.
 *
 * Resolved from `PATH` once per process. Distributions put it in `/usr/bin`,
 * which is on every sane `PATH`; a host without it has no unprivileged mount
 * path at all, which is a fact about the host, not something to work around.
 */
export function fusermountPath(): string | undefined {
  if (probed !== undefined) {
    return probed ?? undefined;
  }
  probed = null;
  const directories = (process.env.PATH ?? "").split(delimiter).filter((part) => part !== "");
  search: for (const helper of HELPERS) {
    for (const directory of directories) {
      const candidate = join(directory, helper);
      if (existsSync(candidate)) {
        probed = candidate;
        break search;
      }
    }
  }
  return probed ?? undefined;
}

/** Can this process mount without root? */
export interface RootlessProbe {
  usable: boolean;
  /** Why not, phrased for an error message. Empty when {@link usable}. */
  reason: string;
}

/**
 * Everything unprivileged mounting needs, checked before anything is opened.
 *
 * Both halves are host facts that a process cannot fix at runtime, so this is
 * a probe rather than a repair: a suite can skip on it, and `mount()` can turn
 * it into one error that names both prerequisites instead of failing twice.
 */
export function rootlessProbe(): RootlessProbe {
  const helper = fusermountPath();
  if (helper === undefined) {
    return {
      usable: false,
      reason:
        `no ${HELPERS.join(" or ")} on PATH — it is the setuid helper that mounts on ` +
        `your behalf, and it comes from the fuse3 package (apt install fuse3, ` +
        `dnf install fuse3)`,
    };
  }
  try {
    loadNative();
  } catch (error) {
    return { usable: false, reason: errorMessage(error) };
  }
  return { usable: true, reason: "" };
}

export interface FusermountOptions {
  /** The `-o` string, already assembled and already validated. */
  options: string;
  /** Milliseconds to wait for the descriptor once the helper has exited. */
  timeout?: number;
}

/**
 * Mount `mountpoint` and return the `/dev/fuse` descriptor.
 *
 * The descriptor comes back close-on-exec, which is what makes a killed server
 * leave a mountpoint that answers `ENOTCONN` rather than one that hangs — the
 * whole fd-lifecycle argument at the top of `mount.ts` applies here unchanged.
 *
 * Both socket ends are closed before this returns, in every path — the sending
 * end as soon as the helper has exited, for the reason given below, and the
 * receiving end in the `finally`. Leaving either open would keep a socket alive
 * for the life of the mount for no reason.
 */
export async function mountViaFusermount(
  mountpoint: string,
  options: FusermountOptions,
): Promise<number> {
  const native = loadNative();
  const helper = fusermountPath();
  if (helper === undefined) {
    throw new Error(`mountx: ${rootlessProbe().reason}`);
  }

  const [ours, theirs] = native.socketpair();
  let sender = theirs;
  try {
    let result;
    try {
      result = await run(helper, ["-o", options.options, "--", mountpoint], {
        stdio: stdioWith(theirs),
        env: { _FUSE_COMMFD: String(theirs) },
      });
    } catch (error) {
      throw new Error(`mountx: could not run ${helper}: ${errorMessage(error)}`);
    }
    // Drop the sending end *before* receiving, not in the `finally`. While this
    // process holds a copy the socket can never reach EOF, so a helper that
    // exits 0 without sending anything is indistinguishable from one that is
    // about to send — and `recvFd` is synchronous, so the backstop below stops
    // being a backstop and becomes ten seconds of stalled event loop. Closing
    // it first turns that case into an immediate "the peer closed without
    // sending a descriptor". The helper has already exited by now (no
    // `auto_unmount`, so it does not linger) and has no use for it either way.
    closeQuietly(theirs);
    sender = -1;
    if (result.status !== 0) {
      throw new Error(
        `mountx: mounting ${mountpoint} failed — ` +
          describe(`${helper} -o ${options.options}`, result),
      );
    }
    // The helper has exited, so the descriptor is sitting in the socket buffer
    // and this returns immediately. The timeout is a backstop against a helper
    // that exits 0 without sending anything, not a wait anyone should observe.
    try {
      return native.recvFd(ours, options.timeout ?? 10_000);
    } catch (error) {
      // The helper mounted, sent, and exited 0 *before* this ran, so by now the
      // filesystem is live and this process has no descriptor for it. Nothing
      // is left to serve it or to close, so it sits there answering `ENOTCONN`
      // until somebody unmounts it by hand. Undo the mount before propagating.
      //
      // Unmounting by path rather than by connection is only sound because
      // `mount()` refuses to stack — the path cannot have come to name a
      // different mount in the microseconds since the helper made this one. Not
      // `-z` either: nothing can hold a reference yet, so a plain `-u` gives a
      // definite answer, where a lazy detach would report success and leave the
      // mount listed.
      throw await undoMount(mountpoint, error);
    }
  } finally {
    closeQuietly(ours);
    if (sender >= 0) {
      closeQuietly(sender);
    }
  }
}

/**
 * Unmount what a failed receive left behind, and say what to throw.
 *
 * `cause` is the failure that got us here and stays the diagnostic when the
 * unmount works. When it does not, the leftover mount is the thing the caller
 * cannot fix from the error alone, so that becomes the message and `cause`
 * keeps the detail.
 */
async function undoMount(mountpoint: string, cause: unknown): Promise<unknown> {
  try {
    await unmountViaFusermount(mountpoint);
  } catch (failure) {
    return new Error(
      `mountx: ${mountpoint} was mounted, no descriptor for it arrived, and unmounting ` +
        `it failed too (${errorMessage(failure)}) — unmount it by hand`,
      { cause },
    );
  }
  return cause;
}

/**
 * `fusermount3 -u`, the only unmount an unprivileged process has.
 *
 * `lazy` is `-z`, which detaches the mount and returns without waiting for the
 * filesystem to quiesce. That is the rootless replacement for `umount -f`:
 * forcing a connection down through `fuse_abort_conn` needs either `MNT_FORCE`
 * or `/sys/fs/fuse/connections/<n>/abort`, and both of those are root's.
 * Detaching does get there in the end — the superblock is destroyed once the
 * last reference goes, and *that* aborts the connection — but it is a
 * consequence rather than a request, so it is slower and less certain.
 */
export async function unmountViaFusermount(
  mountpoint: string,
  options: { lazy?: boolean } = {},
): Promise<void> {
  const helper = fusermountPath();
  if (helper === undefined) {
    throw new Error(`mountx: ${rootlessProbe().reason}`);
  }
  const args = options.lazy === true ? ["-u", "-z", "--", mountpoint] : ["-u", "--", mountpoint];
  let result;
  try {
    result = await run(helper, args, { stdio: ["ignore", "ignore", "pipe"] });
  } catch (error) {
    throw new Error(`mountx: could not run ${helper}: ${errorMessage(error)}`);
  }
  if (result.status !== 0) {
    throw new Error(describe(`${helper} ${args.slice(0, -2).join(" ")}`, result));
  }
}

function closeQuietly(fd: number): void {
  try {
    closeSync(fd);
  } catch {
    // The only way this fails is a double close, and there is nothing useful
    // to say about one on a socket that has already done its job.
  }
}
