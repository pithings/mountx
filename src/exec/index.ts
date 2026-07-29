/**
 * `mountx/exec` — run a command with a driver grafted onto its filesystem view.
 *
 * ```ts
 * import { exec } from "mountx/exec";
 * const ran = await exec(createMemoryDriver(), ["sh", "-c", "ls -la $MOUNTX_ROOT"]);
 * ran.mechanism; // "userns" | "seccomp"
 * ran.code; // the command's exit status
 * ```
 *
 * Where `mountx/auto` attaches a driver to a *directory on the machine*, this
 * attaches one to a *process tree*: the command and everything it spawns see
 * the driver at `$MOUNTX_ROOT`, and nothing else on the host does. That is the
 * `proot`-shaped question — "give this subprocess a filesystem" — and it has
 * two answers on Linux, neither of which is a mount anybody else can see.
 *
 * | mechanism  | what the child sees          | what it needs                           |
 * | ---------- | ---------------------------- | --------------------------------------- |
 * | `userns`   | FUSE, behind the kernel VFS  | `/dev/fuse`, user namespaces, `unshare` |
 * | `seccomp`  | trapped syscalls, no mount   | `SECCOMP_RET_USER_NOTIF`, a supervisor  |
 *
 * **The strategy is `userns` where the kernel's FUSE is usable, `seccomp`
 * otherwise.** `userns` is the cheapest correct thing by a wide margin: what
 * the child sees genuinely *is* FUSE, with the kernel's own VFS in front of it,
 * so it inherits the whole conformance column `src/fuse/` already passes, and
 * it is blind to what the child is linked against. It is simply a mount nobody
 * outside the namespace can see — `/proc/self/mounts` on the host stays empty
 * and the mount dies with the namespace.
 *
 * `seccomp` covers the case that motivated the question in the first place. The
 * environments where "no kernel mount" is *wanted* — a locked-down container, a
 * CI runner, an unprivileged sandbox — are exactly the ones that withhold
 * `/dev/fuse`, and there `userns` cannot be made to work from the inside by any
 * means: a user-namespace root cannot even create the device node
 * (`mknod /dev/fuse c 10 229` answers `EPERM`, verified on `alpine:latest`).
 * A seccomp filter needs no device node, no filesystem driver and no shared
 * library of any kind. It is also the newer and narrower of the two — read-only
 * as it stands, x86-64 only, and its supervisor is a separately built binary —
 * which is why it is second and not first.
 *
 * **Deliberately outside `mountx/auto`.** `auto`'s whole contract is "hand back
 * a mounted directory"; this hands back a child process's exit status and has
 * no mountpoint to give anyone. Same reasoning that keeps `mountx/s3` out of
 * it, arrived at from the other side: `probeTransports()` never mentions this,
 * `mount()` never picks it, and importing `mountx/auto` loads none of it.
 *
 * **Three things it deliberately does not do**, all three lifted from
 * `src/auto.ts` because the arguments are the same ones:
 *
 * - **No fallback after a failure.** {@link probeExec} decides once, from host
 *   facts; a mechanism that then fails reports its own error. Quietly re-running
 *   the command under the *other* mechanism would be worse here than it is for a
 *   mount — the two do not have the same semantics (one is a real filesystem,
 *   the other is eight trapped syscalls and read-only), and a command that has
 *   already run once may have had effects outside the driver.
 * - **No probing when you name a mechanism.** `mechanism: "seccomp"` calls the
 *   supervisor, whose own errors are more specific than anything this file
 *   could say about it.
 * - **No loading of what it does not use.** Each mechanism arrives through
 *   `await import()`, so choosing `userns` never loads the 9P codec behind the
 *   seccomp supervisor and choosing `seccomp` never loads the FUSE session.
 *   The probe reaches only `src/exec/probe.ts`, which imports `node:fs` and
 *   nothing else.
 *
 * The result is the mechanism's own result object with a `mechanism`
 * discriminant defined on it — tagged, not wrapped, the way `mountx/auto` tags
 * a mount — so narrowing on it reaches everything that mechanism reports.
 */

import type { FsDriver } from "../types.ts";
import {
  type SeccompExecProbe,
  seccompExecProbe,
  type UsernsExecProbe,
  usernsExecProbe,
} from "./probe.ts";
import type { ExecSeccompOptions, ExecSeccompResult } from "./seccomp.ts";
import type { ExecUsernsOptions, ExecUsernsResult } from "./userns.ts";

export type { ExecPlatform, SeccompExecProbe, UsernsExecProbe } from "./probe.ts";
export { execPlatform, seccompExecProbe, usernsExecProbe } from "./probe.ts";
export type { ExecSeccompOptions, ExecSeccompResult } from "./seccomp.ts";
export type { ExecUsernsOptions, ExecUsernsResult } from "./userns.ts";

/** The mechanisms {@link exec} can choose between. */
export type ExecMechanism = "userns" | "seccomp";

/** What this host can run a command with, and what {@link exec} would pick. */
export interface ExecProbe {
  /** The platform the probe was answered for. */
  platform: NodeJS.Platform;
  /** What {@link exec} would use, or `undefined` if neither works here. */
  chosen: ExecMechanism | undefined;
  /** Preference order — the list `chosen` was picked from. */
  preference: readonly ExecMechanism[];
  userns: UsernsExecProbe;
  seccomp: SeccompExecProbe;
  /** Why nothing can run, naming both mechanisms. `undefined` when {@link chosen}. */
  reason: string | undefined;
}

/**
 * Options common to both mechanisms, plus an escape hatch for each.
 *
 * Deliberately *not* the union of the two option types, for the reason
 * `AutoMountOptions` is not the union of three: they have same-named options
 * with genuinely different shapes (`onError` hands the FUSE side a request and
 * the 9P side a message header), and a merged type would either lie about that
 * or collapse to something unusable. So the shared options are the ones that
 * mean the same thing in both, and anything mechanism-specific goes in
 * {@link ExecOptions.userns} or {@link ExecOptions.seccomp} — which are applied
 * *after* the shared ones and therefore win.
 */
export interface ExecOptions {
  /** Which mechanism to use. Default `"auto"` — see {@link probeExec}. */
  mechanism?: ExecMechanism | "auto";
  /**
   * Where the driver appears to the command, and the value of `$MOUNTX_ROOT`.
   *
   * The two mechanisms mean subtly different things by it and both honour it:
   * for `userns` it is a **real directory** that gets a namespace-private FUSE
   * mount on it (created if missing, and defaulting to a private temporary
   * directory), for `seccomp` it is a **path prefix the supervisor claims** and
   * nothing is mounted there at all (default `/mountx`). Portable code should
   * read `$MOUNTX_ROOT` from inside the command rather than assume either.
   */
  root?: string;
  /** Working directory for the command. Never default to inside `root` — see below. */
  cwd?: string;
  /** Environment for the command. Defaults to this process's. */
  env?: NodeJS.ProcessEnv;
  /** Report the driver's own `ino` values instead of synthesising them. */
  useDriverIno?: boolean;
  /** Log protocol traffic to stderr. */
  debug?: boolean;
  /** Options for the user-namespace mechanism only. Applied after the shared ones. */
  userns?: ExecUsernsOptions;
  /** Options for the seccomp mechanism only. Applied after the shared ones. */
  seccomp?: ExecSeccompOptions;
}

/**
 * How a command ended, tagged with the mechanism that ran it.
 *
 * The tag is a discriminant, so narrowing on it gives the mechanism's full
 * result — `ran.mechanism === "userns"` reaches `mountpoint`, `"seccomp"`
 * reaches `root` and `requests`. What both share is `code` and `signal`.
 */
export type ExecResult =
  | (ExecUsernsResult & { readonly mechanism: "userns" })
  | (ExecSeccompResult & { readonly mechanism: "seccomp" });

/**
 * What this host can run a command with, and what {@link exec} would choose.
 *
 * Cheap enough to call before deciding whether to offer this at all, and
 * specific enough to print: when neither mechanism works, `reason` names what
 * each one is missing rather than reporting the last failure.
 *
 * Synchronous, unlike `probeTransports()` — every fact here is a `node:fs` read,
 * where FUSE's rootless probe has to load the native addon before it can answer.
 *
 * `platform`, `arch` and `supervisor` exist to be overridden in tests; leave
 * them alone otherwise.
 */
export function probeExec(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
  supervisor: string | undefined = process.env.MOUNTX_TRACE,
): ExecProbe {
  const userns = usernsExecProbe(platform);
  const seccomp = seccompExecProbe(platform, arch, supervisor);
  // One order on every host, because off Linux neither can work and there is
  // nothing for a second order to say. `userns` leads because it is a real
  // filesystem rather than eight trapped syscalls: full read/write, every
  // syscall, and the conformance column `src/fuse/` already passes. `seccomp`
  // follows because what it buys — no device node, no kernel module, no shared
  // library — only matters on a host where `userns` cannot run at all.
  const preference: readonly ExecMechanism[] = ["userns", "seccomp"];
  const probes = { userns, seccomp };
  const chosen = preference.find((mechanism) => probes[mechanism].usable);
  return {
    platform,
    chosen,
    preference,
    userns,
    seccomp,
    reason:
      chosen === undefined
        ? `no mechanism can run a command with a driver on this host — user namespace: ` +
          `${userns.reason}; seccomp: ${seccomp.reason}`
        : undefined,
  };
}

/** The shared options, in the shape each mechanism wants them. */
function shared(options: ExecOptions): Pick<ExecOptions, "cwd" | "env" | "useDriverIno" | "debug"> {
  return {
    cwd: options.cwd,
    env: options.env,
    useDriverIno: options.useDriverIno,
    debug: options.debug,
  };
}

/**
 * Stamp the mechanism onto the result the mechanism just returned.
 *
 * The result object itself is tagged rather than wrapped, so every
 * mechanism-specific member keeps working on the thing the caller holds. Same
 * shape as `src/auto.ts`'s `tag()`, and idempotent for the same reason.
 */
function tag<M extends ExecMechanism, R extends ExecUsernsResult | ExecSeccompResult>(
  result: R,
  mechanism: M,
): R & { readonly mechanism: M } {
  if (!("mechanism" in result)) {
    Object.defineProperty(result, "mechanism", { value: mechanism, enumerable: true });
  }
  return result as R & { readonly mechanism: M };
}

/**
 * Run `argv` with `driver` grafted onto its filesystem view.
 *
 * Resolves when the command exits, with that command's status — a command that
 * fails is not an error here, exactly as it is not for `child_process`. An
 * error is thrown only when the *mechanism* could not be set up, and it names
 * the missing piece.
 *
 * The command finds the driver at `$MOUNTX_ROOT`, which both mechanisms set in
 * its environment. Read it rather than hardcoding {@link ExecOptions.root}: it
 * is the one spelling that is right under either mechanism and with the default
 * (a private temporary directory) in play.
 *
 * **Do not point `cwd` inside the root.** Under `userns` that is a deadlock,
 * not a slow path: `uv_spawn` blocks the thread that answers FUSE requests
 * until the child execs, and a child whose first act is a `chdir` into the
 * mount waits for a reply only that thread can send. `sh -c 'cd "$MOUNTX_ROOT"
 * && …'` does the same thing safely, because the `cd` happens after the exec.
 * The same rule covers a command binary that *lives* on the driver.
 */
export async function exec(
  driver: FsDriver,
  argv: readonly string[],
  options: ExecOptions = {},
): Promise<ExecResult> {
  if (argv.length === 0) {
    throw new Error("mountx: exec needs a command to run");
  }
  const requested = options.mechanism ?? "auto";
  let mechanism: ExecMechanism;
  if (requested === "auto") {
    const probe = probeExec(process.platform, process.arch, options.seccomp?.trace);
    if (probe.chosen === undefined) {
      throw new Error(`mountx: ${probe.reason}`);
    }
    mechanism = probe.chosen;
  } else {
    mechanism = requested;
  }
  if (mechanism === "userns") {
    const { execUserns } = await import("./userns.ts");
    return tag(
      await execUserns(driver, argv, {
        ...shared(options),
        mountpoint: options.root,
        ...options.userns,
      }),
      "userns",
    );
  }
  const { execSeccomp } = await import("./seccomp.ts");
  return tag(
    await execSeccomp(driver, argv, { ...shared(options), root: options.root, ...options.seccomp }),
    "seccomp",
  );
}
