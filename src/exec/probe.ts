/**
 * Can this host graft a driver onto a subprocess's filesystem view, and if not,
 * which piece is missing?
 *
 * Split out of the two mechanisms for the reason `src/nfs/probe.ts` and
 * `src/9p/probe.ts` are split out of their transports: asking should cost
 * nothing. `userns.ts` reaches the whole FUSE session and `seccomp.ts` reaches
 * the whole 9P2000.L codec — a lot of module graph to answer a question that
 * reads four files under `/proc` and one directory of `$PATH`. So this file
 * imports `node:fs` and nothing else, and `src/exec/index.ts` decides from it
 * before loading either mechanism.
 *
 * **Linux only, both of them.** A user namespace is a Linux object and seccomp
 * user notification is a Linux facility; macOS has neither, and `DYLD_INSERT_
 * LIBRARIES` — the one thing it does have — is blocked by SIP for exactly the
 * system binaries anyone would want to run. macOS stays NFS-mount territory.
 *
 * **Neither needs root.** That is the whole point of both: an unprivileged user
 * namespace is unprivileged by construction, and an unprivileged seccomp filter
 * needs only `no_new_privs`, which the supervisor sets on itself.
 */

import * as fs from "node:fs";

/**
 * The verdict for `probe("linux")` asked from somewhere that is not Linux.
 *
 * Every fact below `platform` is a file this process reads about *itself*, so a
 * `platform` override — which exists for the tests — takes them all away at
 * once. Answering `usable` on the strength of a check that never ran would be
 * the one lie a probe must not tell, so the missing evidence is the refusal.
 */
const NOT_THIS_HOST =
  "this probe was asked about Linux from a host that is not Linux, so nothing it reads — " +
  "/dev/fuse, /proc, $PATH — describes the machine in question";

/** The one host either mechanism runs on. */
export type ExecPlatform = "linux";

/** `process.platform`, narrowed to the host that can run a command, or `undefined`. */
export function execPlatform(platform: NodeJS.Platform): ExecPlatform | undefined {
  return platform === "linux" ? "linux" : undefined;
}

/** What this host can and cannot do about the user-namespace mechanism. */
export interface UsernsExecProbe {
  /** Can a command be run with a namespace-private FUSE mount here? */
  usable: boolean;
  /** `"linux"`, or `undefined` on a host with no user namespaces. */
  platform: ExecPlatform | undefined;
  /** Is `fuse` listed in `/proc/filesystems`? */
  kernel: boolean;
  /** Does `/dev/fuse` exist *and* open for reading and writing? */
  device: boolean;
  /** Can this process create a user namespace? */
  userns: boolean;
  /** The `unshare(1)` on `$PATH`, or `undefined`. */
  unshare: string | undefined;
  /** Everything that is missing, in a sentence. `undefined` when {@link usable}. */
  reason: string | undefined;
}

/** What this host can and cannot do about the seccomp mechanism. */
export interface SeccompExecProbe {
  /** Can a command be run under a seccomp user-notification supervisor here? */
  usable: boolean;
  /** `"linux"`, or `undefined` on a host with no seccomp. */
  platform: ExecPlatform | undefined;
  /** Is this an architecture the supervisor's syscall table covers? */
  arch: boolean;
  /** Does the kernel offer `SECCOMP_RET_USER_NOTIF`? */
  userNotif: boolean;
  /** The built supervisor binary, or `undefined` when there is not one. */
  supervisor: string | undefined;
  /** Everything that is missing, in a sentence. `undefined` when {@link usable}. */
  reason: string | undefined;
}

/** The contents of `path`, trimmed, or `undefined` if it could not be read. */
function readQuietly(path: string): string | undefined {
  try {
    return fs.readFileSync(path, "utf8").trim();
  } catch {
    return undefined;
  }
}

/** Is `name` one of the filesystems the kernel knows, per `/proc/filesystems`? */
function hasFilesystem(name: string): boolean {
  const table = readQuietly("/proc/filesystems");
  if (table === undefined) {
    return false;
  }
  // Each line is `nodev\tfuse` or `\text4`: the name is the last
  // whitespace-separated field, and matching it whole is what keeps `fuse` from
  // being found inside `fuseblk`.
  return table.split("\n").some((line) => line.trim().split(/\s+/).pop() === name);
}

/**
 * Why `/dev/fuse` cannot be used from here, or `undefined` if it can.
 *
 * Opened rather than stat'd, because the two failures a caller can act on are
 * different sentences and only an `open(2)` tells them apart. Both refusals say
 * the same last thing for the same reason: this is the case
 * `src/exec/seccomp.ts` exists for.
 */
function deviceRefusal(): string | undefined {
  let device: number;
  try {
    device = fs.openSync("/dev/fuse", fs.constants.O_RDWR);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENXIO" || code === "ENODEV") {
      return (
        "there is no usable /dev/fuse on this host — the fuse module is not loaded, or this " +
        "container was never given the device (docker/podman: --device /dev/fuse). A user " +
        "namespace cannot conjure one either: `mknod /dev/fuse c 10 229` as namespace-root " +
        "answers EPERM (verified on alpine:latest), so the node has to come from outside"
      );
    }
    if (code === "EACCES" || code === "EPERM") {
      return (
        "/dev/fuse exists but this process cannot open it — and entering a user namespace does " +
        "not help, because the namespace maps only your own uid: the permission check the relay " +
        "makes inside it is the one that just failed out here, and the namespace's " +
        "CAP_DAC_OVERRIDE does not reach a device node owned by a uid it does not map"
      );
    }
    return `/dev/fuse could not be opened (${code ?? "unknown error"})`;
  }
  fs.closeSync(device);
  return undefined;
}

/**
 * Why this process cannot create a user namespace, or `undefined` if it can.
 *
 * Three sysctls, each of which turns unprivileged namespace creation off in a
 * different distribution's idiom, plus the kernel-level "compiled without
 * namespaces at all". Root is exempt from the last two, which gate the
 * *unprivileged* path only.
 */
function usernsRefusal(root: boolean): string | undefined {
  if (!fs.existsSync("/proc/self/ns/user")) {
    return (
      "this kernel has no user namespaces at all (no /proc/self/ns/user), so there is no " +
      "namespace to mount FUSE inside"
    );
  }
  // Present on every namespace-capable kernel; zero is an administrator turning
  // the whole facility off, root included.
  const max = readQuietly("/proc/sys/user/max_user_namespaces");
  if (max === "0") {
    return (
      "user namespaces are disabled on this host (/proc/sys/user/max_user_namespaces is 0) — " +
      "raise it with `sysctl -w user.max_user_namespaces=<n>`, or use the seccomp mechanism, " +
      "which needs no namespace"
    );
  }
  if (root) {
    return undefined;
  }
  // Debian's long-standing knob, and Ubuntu's newer AppArmor one. Both gate the
  // unprivileged path only, which is why they are read after the root check.
  if (readQuietly("/proc/sys/kernel/unprivileged_userns_clone") === "0") {
    return (
      "unprivileged user namespaces are disabled " +
      "(/proc/sys/kernel/unprivileged_userns_clone is 0) — enable them with `sysctl -w " +
      "kernel.unprivileged_userns_clone=1`, run as root, or use the seccomp mechanism"
    );
  }
  if (readQuietly("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") === "1") {
    return (
      "AppArmor restricts unprivileged user namespaces on this host " +
      "(/proc/sys/kernel/apparmor_restrict_unprivileged_userns is 1, the Ubuntu 23.10+ " +
      "default) — an unconfined program gets EPERM from unshare(CLONE_NEWUSER) with no other " +
      "clue. Turn it off with `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, " +
      "install a profile for this program, or use the seccomp mechanism"
    );
  }
  return undefined;
}

/**
 * The named executable on `$PATH`, or `undefined`.
 *
 * `$PATH` is split on `:` and joined with `/` rather than through `node:path`,
 * which would be the only other import in this file: both mechanisms are Linux
 * only, and on Linux those two characters are the whole of the question.
 */
function onPath(name: string): string | undefined {
  for (const directory of (process.env.PATH ?? "").split(":")) {
    if (directory === "") {
      continue;
    }
    const candidate = `${directory}/${name}`;
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // Not here, or here and not executable — either way, keep looking.
    }
  }
  return undefined;
}

/**
 * Can this host run a command inside an unprivileged user namespace with the
 * driver mounted over FUSE?
 *
 * Synchronous and cheap, so a test can gate itself on it and `exec()` can refuse
 * with the missing piece named rather than with the raw `ENOENT` from
 * `open("/dev/fuse")` that a relay three processes away would otherwise report.
 *
 * **What makes it usable:** Linux, a `/dev/fuse` this process can open, `fuse`
 * in `/proc/filesystems`, user namespaces this process may create, and
 * `unshare(1)` on `$PATH` (busybox's applet counts — see `src/exec/userns.ts`
 * on why the flags are spelled short).
 *
 * The device is opened *before* `/proc/filesystems` is read, deliberately:
 * `/dev/fuse` is a misc device, so opening it is what triggers the module
 * autoload that puts `fuse` in that table in the first place. Reading the table
 * first would refuse a host that was one `open(2)` away from working.
 *
 * `platform` exists to be overridden in tests; leave it alone otherwise.
 */
export function usernsExecProbe(platform: NodeJS.Platform = process.platform): UsernsExecProbe {
  const host = execPlatform(platform);
  // Only ask this host about itself: with a `platform` override in play the
  // files below describe the machine the test runs on rather than the one it is
  // asking about, and reporting those would be a lie in both directions.
  const linux = host !== undefined && process.platform === "linux";
  const missing: string[] = [];
  if (host === undefined) {
    missing.push(
      `this is ${platform}; a namespace-private FUSE mount needs Linux — no other kernel ` +
        `has user namespaces, and macFUSE speaks a dialect mountx does not implement`,
    );
  }
  const device = linux ? deviceRefusal() : NOT_THIS_HOST;
  const kernel = linux && hasFilesystem("fuse");
  const namespaces = linux ? usernsRefusal((process.getuid?.() ?? -1) === 0) : NOT_THIS_HOST;
  const unshare = linux ? onPath("unshare") : undefined;
  if (host !== undefined && !linux) {
    missing.push(NOT_THIS_HOST);
  }
  if (linux) {
    if (device !== undefined) {
      missing.push(device);
    }
    if (device === undefined && !kernel) {
      missing.push(
        "the kernel has no `fuse` in /proc/filesystems even after /dev/fuse opened, which is " +
          "a kernel built without CONFIG_FUSE_FS",
      );
    }
    if (namespaces !== undefined) {
      missing.push(namespaces);
    }
    if (unshare === undefined) {
      missing.push(
        "there is no `unshare` on $PATH — util-linux and busybox both provide one, and the " +
          "namespace can only be entered by a child process (Node is never single-threaded, " +
          "and unshare(CLONE_NEWUSER) refuses a threaded caller)",
      );
    }
  }
  return {
    usable: missing.length === 0,
    platform: host,
    kernel,
    device: device === undefined,
    userns: namespaces === undefined,
    unshare,
    reason: missing.length === 0 ? undefined : missing.join("; "),
  };
}

/**
 * Can this host run a command under a seccomp user-notification supervisor?
 *
 * **What makes it usable:** Linux, an architecture the supervisor's syscall
 * table covers (x86-64 as built — a second table, not a redesign, is what arm64
 * would take), a kernel offering `SECCOMP_RET_USER_NOTIF`, and the built
 * supervisor binary itself. `CONFIG_SECCOMP_FILTER` is in every mainstream
 * kernel and cannot be a module, so the kernel half is nearly always yes; the
 * binary is the half that usually is not, because it is not shipped in the npm
 * package (see `src/exec/seccomp.ts`).
 *
 * `platform`, `arch` and `supervisor` exist to be overridden in tests; leave
 * them alone otherwise.
 */
export function seccompExecProbe(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
  supervisor: string | undefined = process.env.MOUNTX_TRACE,
): SeccompExecProbe {
  const host = execPlatform(platform);
  const linux = host !== undefined && process.platform === "linux";
  const okArch = arch === "x64";
  // `/proc/sys/kernel/seccomp/actions_avail` is a space-separated list of the
  // return actions this kernel implements. Absent on a kernel too old to have
  // the file, which is also too old to have user notification.
  const actions = linux ? (readQuietly("/proc/sys/kernel/seccomp/actions_avail") ?? "") : "";
  const userNotif = actions.split(/\s+/).includes("user_notif");
  const found = supervisor !== undefined && isExecutable(supervisor) ? supervisor : undefined;

  const missing: string[] = [];
  if (host === undefined) {
    missing.push(
      `this is ${platform}; seccomp user notification is a Linux facility and has no ` +
        `counterpart on any other kernel`,
    );
  }
  if (host !== undefined && !okArch) {
    missing.push(
      `the supervisor's syscall filter is written against x86-64 and this is ${arch} — a ` +
        `second syscall table, not a redesign, but it is not written yet`,
    );
  }
  if (host !== undefined && !linux) {
    missing.push(NOT_THIS_HOST);
  }
  if (linux && !userNotif) {
    missing.push(
      "this kernel does not offer SECCOMP_RET_USER_NOTIF (no `user_notif` in " +
        "/proc/sys/kernel/seccomp/actions_avail), which needs Linux 5.0 or newer built with " +
        "CONFIG_SECCOMP_FILTER",
    );
  }
  if (host !== undefined && found === undefined) {
    missing.push(
      supervisor === undefined
        ? "no supervisor binary — it is built from `src/exec/seccomp/` with a Zig toolchain " +
            "and pointed at with $MOUNTX_TRACE or the `trace` option; it is not shipped in the " +
            "npm package"
        : `the supervisor at ${supervisor} is not an executable file`,
    );
  }
  return {
    usable: missing.length === 0,
    platform: host,
    arch: okArch,
    userNotif,
    supervisor: found,
    reason: missing.length === 0 ? undefined : missing.join("; "),
  };
}

/** Is `path` a file this process may execute? */
function isExecutable(path: string): boolean {
  try {
    fs.accessSync(path, fs.constants.X_OK);
    return fs.statSync(path).isFile();
  } catch {
    return false;
  }
}
