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
 *
 * ## Where the privilege comes from
 *
 * The setuid bit on the helper, and nothing else. `/dev/fuse` is mode 0666 on a
 * host with udev, but opening it is the easy half — `mount(2)` needs
 * `CAP_SYS_ADMIN`, which an ordinary process does not have and cannot acquire.
 * So a helper that did not become root is not a helper at all, and it reports
 * that as `failed to open /dev/fuse: Permission denied` — a message about the
 * device, for a problem that is never the device's. `mount_fuse()` opens it
 * *first*, before its `drop_privs()`, and `drop_privs()` is `setfsuid`-based
 * with `main()` having already restored the fsuid, so a real setuid-root helper
 * opens even a 0600 root-owned device without trouble. A devtmpfs with no udev
 * rule gives exactly that device, and it is a red herring every time.
 *
 * Containers and sandboxes are where the elevation actually goes missing, four
 * ways: the image lost the setuid bit (`COPY` does not preserve it), `nosuid` on
 * the filesystem holding the helper disarms the bit that is there,
 * `no_new_privs` on the process tree makes the bit inert for this process and
 * every descendant, or an LSM/device cgroup denies the device to everyone, root
 * included. {@link rootlessProbe} checks the two that are visible in advance —
 * the bit and `no_new_privs` — and {@link deviceRefusalAdvice} names the rest
 * after the fact, because by then they are one errno.
 */

import { closeSync, existsSync, readFileSync, statSync } from "node:fs";
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

/** The setuid bit, `S_ISUID`. */
const SETUID = 0o4000;

/** `CAP_SYS_ADMIN`'s bit in a capability mask, from `include/uapi/linux/capability.h`. */
const CAP_SYS_ADMIN = 21n;

/** What an `execve` from this process would and would not carry across. */
export interface ExecPrivileges {
  /**
   * `CAP_SYS_ADMIN` in the *ambient* set.
   *
   * The ambient set is the only one that survives an `execve` of a file with no
   * capabilities of its own, so it is the only thing that could let a helper
   * that is *not* setuid mount anyway. Exotic — it takes a deliberate `capsh
   * --addamb` or a container runtime configured for it — but it is the one
   * arrangement in which {@link elevationRefusal} would otherwise be wrong.
   */
  ambient: boolean;
  /**
   * `PR_SET_NO_NEW_PRIVS`, which makes the setuid bit inert.
   *
   * Under it the kernel runs a setuid binary as the *calling* user and says
   * nothing: no error at `execve`, no clue in the file's mode. A seccomp
   * sandbox has to set it (installing a filter without `CAP_SYS_ADMIN`
   * requires it), it is inherited by every descendant, and it cannot be
   * cleared — so it is the one prerequisite here that no amount of fixing the
   * host will recover, and it deserves to be named rather than discovered.
   */
  noNewPrivs: boolean;
}

/**
 * Read the two facts about elevation out of `/proc/self/status`.
 *
 * Both are one line of the same file, so they are one read. A kernel too old to
 * report a field reads as the answer it had before the field existed.
 */
export function execPrivileges(status: string): ExecPrivileges {
  const ambient = /^CapAmb:\s*([\dA-Fa-f]+)$/m.exec(status);
  return {
    ambient:
      ambient?.[1] !== undefined && ((BigInt(`0x${ambient[1]}`) >> CAP_SYS_ADMIN) & 1n) === 1n,
    noNewPrivs: /^NoNewPrivs:\s*1$/m.test(status),
  };
}

/**
 * Why this helper cannot elevate, or `undefined` if it can.
 *
 * Split out of {@link rootlessProbe} because the interesting part is a decision
 * about three numbers and belongs in a test, not on a host that happens to have
 * a working `fuse3` install. `stats` is the helper's, `undefined` when it could
 * not be stat'd — which is not evidence of anything, so it reads as "fine" and
 * lets the mount produce the real error.
 */
export function elevationRefusal(
  helper: string,
  stats: { mode: number; uid: number } | undefined,
  privileges: ExecPrivileges,
): string | undefined {
  if (privileges.ambient) {
    return undefined;
  }
  // Before the mode checks, because it is the one that also explains why every
  // suggestion they produce (`chmod u+s`, `sudo`) would not work either.
  if (privileges.noNewPrivs) {
    return (
      `this process runs with no_new_privs set, which makes the setuid bit inert — ` +
      `${helper} would run as you rather than as root, and fail to open /dev/fuse. It ` +
      `is inherited from whatever started this process (a seccomp sandbox has to set ` +
      `it) and cannot be cleared, so sudo is equally dead and there is nothing to fix ` +
      `from in here: mounting needs a process tree that was not started under it`
    );
  }
  if (stats === undefined) {
    return undefined;
  }
  if ((stats.mode & SETUID) === 0) {
    return (
      `${helper} is not setuid (ls -l shows no \`s\` in its mode) — it is the bit that ` +
      `lets the helper open /dev/fuse and call mount(2) on your behalf, and without it ` +
      `an unprivileged mount cannot get off the ground. Container images and sandboxes ` +
      `lose it routinely. Restore it with \`sudo chmod u+s ${helper}\`, or mount as root`
    );
  }
  if (stats.uid !== 0) {
    return (
      `${helper} is setuid to uid ${stats.uid} rather than to root, so it gains no ` +
      `privilege that this process does not already have`
    );
  }
  return undefined;
}

/**
 * Everything unprivileged mounting needs, checked before anything is opened.
 *
 * All three parts are host facts that a process cannot fix at runtime, so this
 * is a probe rather than a repair: a suite can skip on it, and `mount()` can
 * turn it into one error that names the prerequisite it is missing instead of
 * failing later and less clearly.
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
  const refusal = elevationRefusal(helper, statQuietly(helper), execPrivileges(procStatus()));
  if (refusal !== undefined) {
    return { usable: false, reason: refusal };
  }
  try {
    loadNative();
  } catch (error) {
    return { usable: false, reason: errorMessage(error) };
  }
  return { usable: true, reason: "" };
}

function statQuietly(path: string): { mode: number; uid: number } | undefined {
  try {
    return statSync(path);
  } catch {
    return undefined;
  }
}

function procStatus(): string {
  try {
    return readFileSync("/proc/self/status", "utf8");
    /* v8 ignore next 3 -- no procfs, which on the only platform that mounts
       means something stranger than a missing capability is going on. */
  } catch {
    return "";
  }
}

/**
 * Name the cause when the helper could not open `/dev/fuse`.
 *
 * The helper's own message is `failed to open /dev/fuse: Permission denied`,
 * which reads as a problem with the device's mode and is not one. libfuse opens
 * the device as the *first* thing `mount_fuse()` does, before its `drop_privs()`
 * — and `drop_privs()` is `setfsuid`, so the fsuid at that open is still root
 * (`util/fusermount.c`, unchanged from 3.10 through 3.18). A 0600 root-owned
 * `/dev/fuse`, which is what a devtmpfs with no udev rule gives you, therefore
 * opens fine for a helper that really did become root. The message means it did
 * not, and by the time it is printed the reasons are indistinguishable — so this
 * names them all rather than guessing, in the same spirit as the NFS transport's
 * `consentAdvice`.
 *
 * {@link rootlessProbe} has already ruled out the two that are visible in
 * advance, so what is left here is the mount-time half.
 *
 * Returns `undefined` for every other failure, which keeps the ordinary
 * "`fusermount3` did not like your options" error as short as it is.
 */
export function deviceRefusalAdvice(helper: string, stderr: string): string | undefined {
  if (!stderr.includes("/dev/fuse")) {
    return undefined;
  }
  if (!/Permission denied|Operation not permitted/.test(stderr)) {
    return undefined;
  }
  return (
    `${helper} is setuid root precisely so it can open /dev/fuse, and it opens the device ` +
    `before dropping anything — so a permission error from it means it never became root, ` +
    `whatever the device's mode says. Three things left do that: the filesystem holding ` +
    `the helper is mounted nosuid (\`findmnt -no OPTIONS -T ${helper}\`), an LSM denies ` +
    `the device to this domain (SELinux gives the same EACCES — \`sudo dmesg | grep ` +
    `'avc.*fuse'\`), or a device cgroup denies it outright. Test which side you are on ` +
    `with \`sudo -n id\`: if that gives uid 0, setuid works and the device is being denied ` +
    `by policy; if it fails the same way, nothing here elevates. Mounting as root is the ` +
    `escape from the first — it opens /dev/fuse itself and runs no helper: ` +
    `sudo "$(command -v node)" your-script.mjs`
  );
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
      const advice = deviceRefusalAdvice(helper, result.stderr);
      throw new Error(
        `mountx: mounting ${mountpoint} failed — ` +
          describe(`${helper} -o ${options.options}`, result) +
          (advice === undefined ? "" : `. ${advice}`),
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
