/**
 * The two `open(2)` flag namespaces this transport straddles.
 *
 * `fuse_open_in.flags` and `fuse_create_in.flags` carry whatever the *Linux*
 * kernel put there, so they are read with `constants.ts`'s transcribed `O_*`.
 * A driver is the other namespace: `FsDriver` is a subset of
 * `node:fs/promises`, so the numbers it is handed are resolved against the
 * *host* by `node:fs`. On Linux — the only host this transport mounts on — the
 * two agree bit for bit, and the wire value is forwarded whole.
 *
 * They agree nowhere else. macOS's `O_TRUNC` is `0o2000`, which is Linux's
 * `O_APPEND`, and its `O_CREAT` is `0o1000`, which is Linux's `O_TRUNC` — so a
 * verbatim hand-off there reads `> file` as an append and `open(O_CREAT)` as a
 * truncate. No mount can reach that case (`src/fuse/` serves Linux only), but
 * the Tier-0 session tests do: they drive a real session against a real driver
 * on whatever host runs `pnpm test`, and without this translation they either
 * fail on a Mac or — worse — pass because the test and the driver were both
 * speaking the host's dialect while the session was speaking the wire's.
 */

import { constants } from "node:fs";
import { O_ACCMODE, O_APPEND, O_CREAT, O_EXCL, O_TRUNC } from "./constants.ts";

/**
 * The host `O_*` values a translation needs. `node:fs`'s `constants` satisfies
 * it; a test supplies another host's values to check the mapping from anywhere.
 */
export interface HostOpenFlags {
  readonly O_CREAT: number;
  readonly O_EXCL: number;
  readonly O_TRUNC: number;
  readonly O_APPEND: number;
}

/**
 * Translate wire flags into `host`'s, dropping every bit not named here.
 *
 * Dropping is the only honest answer for the rest: a bit Linux gave a meaning
 * has a different one — or none — on another host, so carrying the number
 * across would ask for something nobody requested. The access mode needs no
 * translation: `O_RDONLY`/`O_WRONLY`/`O_RDWR` are 0/1/2 on every POSIX host.
 */
export function translateOpenFlags(wire: number, host: HostOpenFlags): number {
  let flags = wire & O_ACCMODE;
  if ((wire & O_CREAT) !== 0) {
    flags |= host.O_CREAT;
  }
  if ((wire & O_EXCL) !== 0) {
    flags |= host.O_EXCL;
  }
  if ((wire & O_TRUNC) !== 0) {
    flags |= host.O_TRUNC;
  }
  if ((wire & O_APPEND) !== 0) {
    flags |= host.O_APPEND;
  }
  return flags;
}

/**
 * The flags to hand a driver for the wire flags of an `OPEN`/`CREATE`.
 *
 * Identity on Linux, deliberately: the wire *is* the host there, so the flags
 * pass through whole — including every bit `translateOpenFlags` does not
 * enumerate (`O_NOFOLLOW`, `O_DIRECT`, `O_NOATIME`, ...), which a driver is
 * entitled to inspect and which no partial translation could preserve.
 *
 * `platform` and `host` are parameters for the same reason
 * `nfsMountOptions()`'s are: the interesting case is the one this dev host
 * cannot be, and it should still be a Tier-0 test.
 */
export function driverOpenFlags(
  wire: number,
  platform: NodeJS.Platform = process.platform,
  host: HostOpenFlags = constants,
): number {
  return platform === "linux" ? wire : translateOpenFlags(wire, host);
}

/**
 * The flags to **re-open** with, for a driver that keeps no per-open state.
 *
 * `O_CREAT`, `O_EXCL` and `O_TRUNC` are one-shot: `open(2)` acts on them once,
 * when the description is created. A re-open is not another `open(2)` as far as
 * the application is concerned — it stands in for the description the kernel
 * already holds an `fh` for — so repeating them is wrong three ways, and all
 * three are reachable from a plain `handles: false` driver:
 *
 * - `O_EXCL` fails every operation on the file it just created (`EEXIST` on the
 *   first `WRITE` after a `CREATE`);
 * - `O_TRUNC` empties the file before *each* operation, so every write but the
 *   last is thrown away;
 * - `O_CREAT` would resurrect a file unlinked while open.
 *
 * Host-space in, host-space out: this runs on what `driverOpenFlags()`
 * returned. `O_APPEND` deliberately stays — the kernel has already resolved an
 * appending write's offset to EOF, and an appending re-open lands there too.
 */
export function reopenFlags(driverFlags: number): number {
  return driverFlags & ~(constants.O_CREAT | constants.O_EXCL | constants.O_TRUNC);
}
