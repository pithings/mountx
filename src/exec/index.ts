/**
 * `mountx/exec` — run a command with a driver grafted onto its filesystem view.
 *
 * ```ts
 * import { exec } from "mountx/exec";
 * const ran = await exec(createMemoryDriver(), ["sh", "-c", "ls -la $MOUNTX_ROOT"]);
 * ran.mechanism; // "userns"
 * ran.code; // the command's exit status
 * ```
 *
 * Where `mountx/auto` attaches a driver to a *directory on the machine*, this
 * attaches one to a *process tree*: the command and everything it spawns see
 * the driver at `$MOUNTX_ROOT`, and nothing else on the host does. That is the
 * `proot`-shaped question — "give this subprocess a filesystem" — and the
 * answer here is a FUSE mount inside an unprivileged user namespace, which is
 * not a mount anybody outside the process tree can see.
 *
 * | mechanism | what the child sees         | what it needs                           |
 * | --------- | --------------------------- | --------------------------------------- |
 * | `userns`  | FUSE, behind the kernel VFS | `/dev/fuse`, user namespaces, `unshare` |
 *
 * **Why `userns` and not something cleverer.** It is the cheapest correct thing
 * by a wide margin: what the child sees genuinely *is* FUSE, with the kernel's
 * own VFS in front of it, so it inherits the whole conformance column
 * `src/fuse/` already passes, and it is blind to what the child is linked
 * against — a static binary, a Go binary and a setuid binary all behave. It is
 * simply a mount nobody outside the namespace can see: `/proc/self/mounts` on
 * the host stays empty and the mount dies with the namespace.
 *
 * What it costs is that it *is* a kernel mount, so it needs `/dev/fuse` — which
 * a locked-down container is exactly the sort of place to withhold, and which a
 * user-namespace root cannot conjure (`mknod /dev/fuse c 10 229` answers
 * `EPERM`, verified on `alpine:latest`). A second mechanism that needs no
 * device node at all — a seccomp user-notification supervisor — was built and
 * measured alongside this one and is not on this branch; it lives in the
 * history of PR #9 on `pithings/mountx`, and `.agents/proot-plan.md` records
 * what it showed.
 *
 * **This file is shaped for more than one mechanism, deliberately.** There is
 * one today, and {@link ExecMechanism}, {@link ExecProbe.preference} and the
 * discriminant on {@link ExecResult} are the seam a second arrives through
 * without an API change: a caller narrowing on `ran.mechanism` or reading
 * `probe.userns.reason` keeps working when the list grows. What is *not* here
 * is an invented second entry to make the shape look busier than it is.
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
 *   facts; a mechanism that then fails reports its own error. With one mechanism
 *   there is nothing to fall back *to*, and the rule is written down anyway
 *   because it is the rule a second one arrives under: two mechanisms would not
 *   have the same semantics, and a command that has already run once may have
 *   had effects outside the driver.
 * - **No probing when you name a mechanism.** `mechanism: "userns"` calls
 *   `execUserns()`, whose own errors are more specific than anything this file
 *   could say about it.
 * - **No loading of what it does not use.** The mechanism arrives through
 *   `await import()`, so a probe that refuses never loads the FUSE session, and
 *   the probe itself reaches only `src/exec/probe.ts`, which imports `node:fs`
 *   and nothing else.
 *
 * The result is the mechanism's own result object with a `mechanism`
 * discriminant defined on it — tagged, not wrapped, the way `mountx/auto` tags
 * a mount — so narrowing on it reaches everything that mechanism reports.
 */

import type { FsDriver } from "../types.ts";
import { type UsernsExecProbe, usernsExecProbe } from "./probe.ts";
import type { ExecUsernsOptions, ExecUsernsResult } from "./userns.ts";

export type { ExecPlatform, UsernsExecProbe } from "./probe.ts";
export { execPlatform, usernsExecProbe } from "./probe.ts";
export type { ExecUsernsOptions, ExecUsernsResult } from "./userns.ts";

/**
 * The mechanisms {@link exec} can choose between.
 *
 * One of them today. It is a union rather than a string literal because it is
 * the discriminant {@link ExecResult} narrows on, and widening a union is a
 * change a caller's `switch` survives where replacing a bare type is not.
 */
export type ExecMechanism = "userns";

/** What this host can run a command with, and what {@link exec} would pick. */
export interface ExecProbe {
  /** The platform the probe was answered for. */
  platform: NodeJS.Platform;
  /** What {@link exec} would use, or `undefined` if nothing works here. */
  chosen: ExecMechanism | undefined;
  /** Preference order — the list `chosen` was picked from. */
  preference: readonly ExecMechanism[];
  /** The user-namespace mechanism's own verdict, reasons and all. */
  userns: UsernsExecProbe;
  /** Why nothing can run, naming every mechanism. `undefined` when {@link chosen}. */
  reason: string | undefined;
}

/**
 * Options for the command, plus an escape hatch for the mechanism.
 *
 * Deliberately *not* the mechanism's option type re-exported under another
 * name, for the reason `AutoMountOptions` is not one of the three transports':
 * these are the options that mean the same thing however the driver reaches the
 * command, and anything mechanism-specific goes in {@link ExecOptions.userns} —
 * which is applied *after* the shared ones and therefore wins.
 */
export interface ExecOptions {
  /** Which mechanism to use. Default `"auto"` — see {@link probeExec}. */
  mechanism?: ExecMechanism | "auto";
  /**
   * Where the driver appears to the command, and the value of `$MOUNTX_ROOT`.
   *
   * For `userns` it is a **real directory** that gets a namespace-private FUSE
   * mount on it, created if missing, and defaulting to a private temporary
   * directory. Portable code should read `$MOUNTX_ROOT` from inside the command
   * rather than assume the default.
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
}

/**
 * How a command ended, tagged with the mechanism that ran it.
 *
 * The tag is a discriminant, so narrowing on it gives the mechanism's full
 * result — `ran.mechanism === "userns"` reaches `mountpoint`. A union of one
 * arm is a union: adding an arm is what a second mechanism does here, and a
 * caller that already narrows is a caller that already compiles.
 */
export type ExecResult = ExecUsernsResult & { readonly mechanism: "userns" };

/**
 * What this host can run a command with, and what {@link exec} would choose.
 *
 * Cheap enough to call before deciding whether to offer this at all, and
 * specific enough to print: when nothing works, `reason` names what each
 * mechanism is missing rather than reporting the last failure.
 *
 * Synchronous, unlike `probeTransports()` — every fact here is a `node:fs` read,
 * where FUSE's rootless probe has to load the native addon before it can answer.
 *
 * `platform` exists to be overridden in tests; leave it alone otherwise.
 */
export function probeExec(platform: NodeJS.Platform = process.platform): ExecProbe {
  const userns = usernsExecProbe(platform);
  // One order on every host, because off Linux nothing here can work and there
  // is nothing for a second order to say. The list is what a second mechanism
  // is appended to, and the rule it is appended under is that a real filesystem
  // outranks an approximation of one.
  const preference: readonly ExecMechanism[] = ["userns"];
  const probes = { userns };
  const chosen = preference.find((mechanism) => probes[mechanism].usable);
  return {
    platform,
    chosen,
    preference,
    userns,
    reason:
      chosen === undefined
        ? `no mechanism can run a command with a driver on this host — user namespace: ` +
          `${userns.reason}`
        : undefined,
  };
}

/** The shared options, in the shape the mechanism wants them. */
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
function tag<M extends ExecMechanism, R extends ExecUsernsResult>(
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
 * The command finds the driver at `$MOUNTX_ROOT`, which the mechanism sets in
 * its environment. Read it rather than hardcoding {@link ExecOptions.root}: it
 * is the one spelling that is right with the default (a private temporary
 * directory) in play.
 *
 * **Do not point `cwd` inside the root.** That is a deadlock, not a slow path:
 * `uv_spawn` blocks the thread that answers FUSE requests until the child
 * execs, and a child whose first act is a `chdir` into the mount waits for a
 * reply only that thread can send. `sh -c 'cd "$MOUNTX_ROOT" && …'` does the
 * same thing safely, because the `cd` happens after the exec. The same rule
 * covers a command binary that *lives* on the driver.
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
    const probe = probeExec();
    if (probe.chosen === undefined) {
      throw new Error(`mountx: ${probe.reason}`);
    }
    mechanism = probe.chosen;
  } else {
    mechanism = requested;
  }
  const { execUserns } = await import("./userns.ts");
  return tag(
    await execUserns(driver, argv, {
      ...shared(options),
      mountpoint: options.root,
      ...options.userns,
    }),
    mechanism,
  );
}
