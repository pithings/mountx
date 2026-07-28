/**
 * Running one command to completion.
 *
 * Mounting is the one thing this library cannot do from JS alone, and both
 * ways of doing it end in a child process — `mount(8)` as root, `fusermount3`
 * as anyone. This is the small piece both of them share; `mount.ts` and
 * `fusermount.ts` are where the interesting decisions live.
 */

import { spawn } from "node:child_process";

export interface SpawnResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
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
}

/** Run a command, resolving when it has exited. */
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
    let stderr = "";
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("error", rejectPromise);
    child.once("close", (status, signal) => {
      resolvePromise({ status, signal, stderr: stderr.trim() });
    });
  });
}

/** How a command ended, for an error message. */
export function describe(command: string, result: SpawnResult): string {
  const how = result.signal === null ? `exit ${result.status}` : `signal ${result.signal}`;
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
