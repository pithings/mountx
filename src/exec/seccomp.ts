/**
 * `execSeccomp()` — run a command whose filesystem syscalls are answered by an
 * `FsDriver`, with no kernel mount and no libc involvement.
 *
 * The parent side is `createP9Server()` on a private unix socket, which is the
 * point worth noticing: the supervisor is a *client* of the same unchanged
 * server `mount9p()` points the kernel's v9fs client at. Everything that
 * decides what the filesystem does still lives in `src/9p/session.ts`, and this
 * side is a socket and a process.
 *
 * What makes the mechanism worth having is where the boundary sits. An
 * `LD_PRELOAD` interposer sees glibc's exported symbols and therefore serves
 * only what dynamically links glibc; a seccomp filter sees the syscall ABI, so
 * a static musl binary, a Go binary and `cat` are indistinguishable to it.
 * `src/exec/seccomp/trace.zig` is the supervisor, and its header is where the
 * mechanism, and every gap it still has, is written down.
 *
 * Needs no privileges — `no_new_privs` is all an unprivileged filter requires —
 * and no namespace, no device node and no filesystem driver. Linux only, and
 * x86-64 only, since the filter compares against one syscall table and refuses
 * to interpret any other.
 */

import { type ChildProcess, spawn, type StdioOptions } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createP9Server, type P9ServerOptions } from "../9p/server.ts";
import type { FsDriver } from "../types.ts";

export interface ExecSeccompOptions extends P9ServerOptions {
  /** The path prefix the supervisor claims. Nothing is mounted there. */
  root?: string;
  /** The built supervisor binary. Defaults to `$MOUNTX_TRACE`. */
  trace?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /**
   * How the command's standard streams are wired, as `child_process` spells it.
   * Defaults to `"inherit"`, which is what a command run for its output wants.
   */
  stdio?: StdioOptions;
  /**
   * The child, the moment it exists.
   *
   * `execSeccomp` resolves when the command has *exited*, which is the wrong
   * shape for a command that is being driven — a helper answering requests on
   * its standard input, say. This is the handle for that: whatever it is given
   * has already been spawned, and the promise is still outstanding.
   */
  onSpawn?: (child: ChildProcess) => void;
}

export interface ExecSeccompResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  root: string;
  requests: number;
}

export async function execSeccomp(
  driver: FsDriver,
  argv: readonly string[],
  options: ExecSeccompOptions = {},
): Promise<ExecSeccompResult> {
  if (argv.length === 0) {
    throw new Error("mountx: execSeccomp needs a command to run");
  }
  const trace = options.trace ?? process.env.MOUNTX_TRACE;
  if (trace === undefined) {
    throw new Error(
      "mountx: execSeccomp needs the built supervisor — pass `trace` or set $MOUNTX_TRACE",
    );
  }
  const root = options.root ?? "/mountx";
  const scratch = await mkdtemp(join(tmpdir(), "mountx-seccomp-"));
  const socketPath = join(scratch, "9p.sock");
  const server = createP9Server(driver, { ...options, path: socketPath });
  await server.listen();

  const seen = new Set<(typeof server.clients)[number]["session"]>();
  const sampler = setInterval(() => {
    for (const connection of server.clients) seen.add(connection.session);
  }, 20);
  sampler.unref();

  try {
    const child = spawn(trace, [socketPath, root, "--", ...argv], {
      stdio: options.stdio ?? "inherit",
      cwd: options.cwd ?? process.cwd(),
      env: { ...(options.env ?? process.env), MOUNTX_ROOT: root },
    });
    options.onSpawn?.(child);
    const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (resolveExit, rejectExit) => {
        child.on("error", rejectExit);
        child.on("exit", (code, signal) => resolveExit({ code, signal }));
      },
    );
    for (const connection of server.clients) seen.add(connection.session);
    let requests = 0;
    for (const session of seen) requests += session.stats.requests;
    return { ...result, root, requests };
  } finally {
    clearInterval(sampler);
    await server.close();
    await rm(scratch, { recursive: true, force: true }).catch(() => {});
  }
}
