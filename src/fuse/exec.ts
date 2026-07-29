/**
 * Running one command to completion, and the clock the teardown paths keep.
 *
 * Mounting is the one thing this library cannot do from JS alone, and every way
 * of doing it ends in a child process — `mount(8)` as root, `fusermount3` as
 * anyone, `mount -t 9p` for the 9P transport. This is the small piece they
 * share; `mount.ts`, `fusermount.ts` and `src/9p/mount.ts` are where the
 * interesting decisions live.
 *
 * {@link Deadline} and {@link delay} are here for the same reason {@link run}
 * is. Unmounting is a *sequence* of spawns — read the mount table, ask nicely,
 * escalate — and AGENTS.md's teardown invariant is about the sequence, not
 * about any one of them: "Every spawned `umount` is bounded by that deadline
 * and abandoned if it outlives it." A per-call timeout cannot say that, because
 * three calls each given the whole budget spend three times it. One `Deadline`
 * built at the top of a phase and asked for what is *left* at each step is what
 * makes the documented bound the real one, and having it here means the three
 * transports cannot drift apart on it the way the three `run()`s once did.
 *
 * It lives under `src/fuse/` because that is where it was first needed and
 * moving it would churn three files for a rename. `src/9p/mount.ts` imports it
 * across the transport boundary the way `src/9p/session.ts` imports
 * `src/fuse/flags.ts`: one implementation of a shared fact beats two.
 */

import { spawn } from "node:child_process";

export interface SpawnResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  /** Whatever the child wrote to stdout, or `""` when stdout was not piped. */
  stdout: string;
  stderr: string;
  /** The deadline passed with the child still running. See {@link RunOptions.timeout}. */
  timedOut?: boolean;
}

export interface RunOptions {
  /**
   * The child's file descriptors.
   *
   * Passed through because both mount paths need a specific *fd number* to
   * survive into the child — the `/dev/fuse` descriptor for `mount(8)`, the
   * socket for `fusermount3` — and the only way to say that is to pad this
   * array out to the number and put the descriptor at its own index.
   */
  stdio: Array<"ignore" | "pipe" | number>;
  /** Added to this process's environment, not replacing it. */
  env?: Record<string, string>;
  /**
   * Milliseconds before the child is written off. Default: wait forever.
   *
   * The deadline **settles** the promise rather than rejecting or waiting for
   * the child, and that is the part that matters: a `umount(8)` blocked inside
   * the kernel does not die on `SIGKILL`, so a run that waited for `close`
   * would never return, and a caller that moved on without one would leave a
   * child behind still holding the very mount it is about to escalate against.
   * The kill is sent because usually it works; the result is reported either
   * way, with {@link SpawnResult.timedOut} saying which happened.
   *
   * Every teardown spawn passes one, derived from a {@link Deadline} so the
   * steps of one phase share a budget rather than each getting the whole of it.
   * The mount paths do not: a `mount(8)` that hangs has produced no mount to
   * clean up, and there is no invariant about how long it may take.
   */
  timeout?: number;
}

/** Run a command, resolving when it has exited (or when its deadline passes). */
export function run(
  command: string,
  args: readonly string[],
  options: RunOptions,
): Promise<SpawnResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, [...args], {
      stdio: options.stdio,
      env: options.env === undefined ? process.env : { ...process.env, ...options.env },
    });
    let stdout = "";
    let stderr = "";
    // Both streams exist only when the corresponding `stdio` slot is `"pipe"`,
    // which is why every reader here is optional: a caller that ignores stdout
    // gets `""` rather than a listener on nothing.
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => {
      stderr += chunk;
    });
    const timer =
      options.timeout === undefined
        ? undefined
        : setTimeout(() => {
            child.kill("SIGKILL");
            // Let go of it completely: an unkillable child must not keep this
            // process's event loop alive after the caller has given up on it.
            child.stdout?.destroy();
            child.stderr?.destroy();
            child.unref();
            resolvePromise({
              status: null,
              signal: null,
              stdout,
              stderr: stderr.trim(),
              timedOut: true,
            });
          }, options.timeout);
    timer?.unref();
    child.once("error", (error) => {
      clearTimeout(timer);
      rejectPromise(error);
    });
    child.once("close", (status, signal) => {
      clearTimeout(timer);
      resolvePromise({ status, signal, stdout, stderr: stderr.trim(), timedOut: false });
    });
  });
}

/**
 * One wall-clock budget, shared by every step of one phase of a teardown.
 *
 * Handed to each step in turn, so what the second one gets is whatever the
 * first one left. An unbounded deadline answers `undefined`, which is exactly
 * what {@link RunOptions.timeout} means by "wait forever", so the two compose
 * with no branch at the call site.
 */
export interface Deadline {
  /**
   * Milliseconds left: `0` once the budget is spent, `undefined` when there
   * never was one.
   *
   * Zero is deliberately not `undefined`. A step that starts with nothing left
   * gets a `timeout` of `0` and is killed on the next turn of the timer queue,
   * which is the honest answer — the phase it belongs to has already used
   * everything it was given, and letting it run anyway is how the bound gets
   * exceeded.
   */
  remaining(): number | undefined;
}

/**
 * A budget of `timeout` milliseconds starting now.
 *
 * Anything that is not a positive finite number — `undefined`, `0`, `Infinity`,
 * `NaN` — is "no deadline at all", the same opt-out the `unmountTimeout` option
 * documents on all three transports.
 */
export function deadlineIn(timeout: number | undefined): Deadline {
  if (timeout === undefined || !Number.isFinite(timeout) || timeout <= 0) {
    return { remaining: () => undefined };
  }
  const end = Date.now() + timeout;
  return { remaining: () => Math.max(0, end - Date.now()) };
}

/**
 * Sleep, without holding the process open.
 *
 * `unref` because every caller is on a teardown path: a delay nobody is waiting
 * for must not be the reason Node stays alive, and a process that is exiting
 * anyway has already answered whatever this was waiting for.
 */
export function delay(ms: number): Promise<void> {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, ms).unref();
  });
}

/** How a command ended, for an error message. */
export function describe(command: string, result: SpawnResult): string {
  const how =
    result.timedOut === true
      ? "no answer before the deadline, still running"
      : result.signal === null
        ? `exit ${result.status}`
        : `signal ${result.signal}`;
  return result.stderr === "" ? `${command}: ${how}` : `${command}: ${how}: ${result.stderr}`;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * A child's stdio map with `fd` at its own index.
 *
 * `openSync` and `socketpair` return whatever number the process has free (17
 * is typical, not 3), and the fd has to land in the child at *that* number,
 * because that is the number `-o fd=N` and `_FUSE_COMMFD=N` name. Everything
 * else is `ignore`, except stderr, which is captured so a failure has
 * something to say.
 */
export function stdioWith(fd: number): Array<"ignore" | "pipe" | number> {
  const stdio: Array<"ignore" | "pipe" | number> = Array.from(
    { length: Math.max(fd, 2) + 1 },
    () => "ignore",
  );
  stdio[2] = "pipe";
  stdio[fd] = fd;
  return stdio;
}
