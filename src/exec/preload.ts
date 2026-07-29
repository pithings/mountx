/**
 * SPIKE B — `execPreload()`: run a command with an `FsDriver` grafted onto its
 * filesystem view by an `LD_PRELOAD` interposer, with no kernel mount anywhere.
 *
 * The parent stays exactly what it already is: a 9P server over a private unix
 * socket, `createP9Server()` verbatim, the same one `mount9p()` points the
 * kernel's v9fs client at. The only new thing is *who* the client is — here it
 * is `src/exec/preload/shim.zig` living inside the target process, translating
 * libc calls into 9P messages, where normally it is the kernel.
 *
 * That is the whole design claim of this spike and it is worth stating plainly:
 * a filesystem interposer does not need a filesystem. It needs a **client**.
 * Path resolution, handle lifetimes, directory paging, error mapping and every
 * conformance question are already settled on the far side of the socket by
 * `src/9p/session.ts`; the shim is a wire adapter with an fd table.
 *
 * What it buys, against spike A's namespace mount: no namespace, no
 * `/dev/fuse`, no `unshare`, nothing that a locked-down container can withhold,
 * and a plausible route to macOS via `DYLD_INSERT_LIBRARIES`. What it costs is
 * in `preload/shim.zig`'s header: it serves what dynamically links glibc and
 * nothing else.
 *
 * ```ts
 * await execPreload(driver, ["cat", "/mountx/hello.txt"], { root: "/mountx" });
 * ```
 */

import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createP9Server, type P9ServerOptions } from "../9p/server.ts";
import type { FsDriver } from "../types.ts";

export interface ExecPreloadOptions extends P9ServerOptions {
  /**
   * The path prefix the shim claims, as the child sees it. Nothing is mounted
   * there and nothing needs to exist there — it is a string the interposer
   * compares against, which is exactly why this approach needs no privileges
   * and also exactly why it is not a real filesystem: a program that never
   * calls an interposed symbol will see nothing at that path at all.
   */
  root?: string;
  /** The built shim. Defaults to `$MOUNTX_SHIM`. */
  shim?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

export interface ExecPreloadResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  root: string;
  /** 9P messages the shim sent, as counted by the server. */
  requests: number;
}

export async function execPreload(
  driver: FsDriver,
  argv: readonly string[],
  options: ExecPreloadOptions = {},
): Promise<ExecPreloadResult> {
  if (argv.length === 0) {
    throw new Error("mountx: execPreload needs a command to run");
  }
  const shim = options.shim ?? process.env.MOUNTX_SHIM;
  if (shim === undefined) {
    throw new Error("mountx: execPreload needs the built shim — pass `shim` or set $MOUNTX_SHIM");
  }
  const root = options.root ?? "/mountx";
  if (!root.startsWith("/")) {
    throw new Error(`mountx: execPreload root must be absolute, got ${root}`);
  }
  const scratch = await mkdtemp(join(tmpdir(), "mountx-preload-"));
  const socketPath = join(scratch, "9p.sock");
  const server = createP9Server(driver, { ...options, path: socketPath });
  await server.listen();

  // `server.clients` drops a connection the moment it closes, and every
  // connection here closes when the child exits — so counting at the end
  // always reports zero. Sampling keeps a reference to each session instead.
  const seen = new Set<(typeof server.clients)[number]["session"]>();
  const sampler = setInterval(() => {
    for (const connection of server.clients) seen.add(connection.session);
  }, 20);
  sampler.unref();

  try {
    const child = spawn(argv[0]!, argv.slice(1), {
      stdio: "inherit",
      cwd: options.cwd ?? process.cwd(),
      env: {
        ...(options.env ?? process.env),
        // Prepending rather than replacing: a caller may already be running
        // under a preload of its own, and clobbering it would be a surprise.
        LD_PRELOAD:
          (options.env ?? process.env).LD_PRELOAD === undefined
            ? shim
            : `${shim}:${(options.env ?? process.env).LD_PRELOAD}`,
        MOUNTX_9P_SOCK: socketPath,
        MOUNTX_ROOT: root,
      },
    });
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
