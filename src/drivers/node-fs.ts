/**
 * A `node:fs/promises` passthrough driver rooted at a directory.
 *
 * Two jobs: give real drivers a mountable baseline, and act as the oracle the
 * conformance and differential suites are checked against. Which is why it
 * resolves paths itself instead of handing them to the kernel — every path is
 * walked component by component so that neither `..` nor a symlink (relative
 * or absolute, at any depth) can name anything outside the root.
 *
 * What that containment does and does not promise:
 *
 * - It assumes nothing else is moving components of the root concurrently.
 *   Resolution and the syscall are two steps, so a racing rename between them
 *   is not defended against; `openat`-style resolution would be, and needs
 *   syscalls Node does not expose.
 * - Errors raised *while resolving* are rewritten to the virtual path, as are
 *   `Dirent.parentPath` and the result of a recursive `mkdir`. Errors raised
 *   by the underlying syscall are forwarded untouched and still carry the
 *   host path.
 */

import { constants } from "node:fs";
import * as fs from "node:fs/promises";
import { dirname as nodeDirname, join as nodeJoin, resolve as nodeResolve } from "node:path";
import type { ErrnoCode } from "../errors.ts";
import { ERRNO_CODES, fsError, isFsError } from "../errors.ts";
import { normalizePath, resolvePath } from "../path.ts";
import type { DirentLike, FullFsDriver, MkdirOptions, ReaddirOptions } from "../types.ts";

const MAX_SYMLINK_DEPTH = 40;

/** Does this open ask for `O_CREAT | O_EXCL` ("wx", "ax+", `O_EXCL`, ...)? */
function isExclusive(flags: string | number): boolean {
  return typeof flags === "number" ? (flags & constants.O_EXCL) !== 0 : flags.includes("x");
}

export interface NodeFsDriverOptions {
  /** Report the driver as read-only (does not itself enforce it). */
  readOnly?: boolean;
}

/** Create a driver serving `root` (an existing directory on the host). */
export function createNodeFsDriver(
  rootPath: string,
  options: NodeFsDriverOptions = {},
): FullFsDriver {
  const root = nodeResolve(rootPath);

  /** What one component of the walk turned out to be. */
  type Component =
    | { kind: "missing" }
    | { kind: "symlink"; target: string }
    | { kind: "other" }
    /** The raw error, rethrown by the *walk* so it names that walk's path. */
    | { kind: "error"; error: unknown };

  async function lookAt(candidate: string): Promise<Component> {
    let stats;
    try {
      stats = await fs.lstat(candidate);
    } catch (error) {
      if (isFsError(error, "ENOENT")) {
        return { kind: "missing" };
      }
      return { kind: "error", error };
    }
    if (!stats.isSymbolicLink()) {
      return { kind: "other" };
    }
    return { kind: "symlink", target: await fs.readlink(candidate) };
  }

  /**
   * {@link lookAt}, answered once per candidate for the duration of **one**
   * driver call, and never carried between calls.
   *
   * The scope is the whole point. Resolution and the syscall it feeds are
   * already two steps within an operation (see the note at the top of this
   * file), so answering the same component twice inside one operation buys no
   * guarantee it does not already have — while a memo that outlived the call
   * would: every entry would be a promise that a component the driver has not
   * looked at since is still not a symlink, which nothing here can keep. That
   * is a containment claim, not a cost, so it is not traded for one.
   *
   * What it does buy: `rename`/`link` resolve two paths that almost always
   * share every component but the last, and a symlink target sends the walk
   * back over components it has already passed.
   */
  function memo(): (candidate: string) => Promise<Component> {
    const seen = new Map<string, Promise<Component>>();
    return (candidate) => {
      let component = seen.get(candidate);
      if (component === undefined) {
        component = lookAt(candidate);
        seen.set(candidate, component);
      }
      return component;
    };
  }

  /**
   * Resolve a virtual path to a real one that is guaranteed to be inside
   * `root`. Missing components are fine (the real syscall reports them); the
   * point is that nothing above `root` is ever reachable.
   */
  async function secure(
    path: string,
    follow: boolean,
    syscall: string,
    look = memo(),
  ): Promise<string> {
    // `segments` is a fresh array this call owns, so `shift()`/`unshift()` on
    // it are the walk's own business.
    const { path: virtualPath, segments: pending } = resolvePath(path);
    let current = root;
    let depth = 0;
    let links = 0;

    while (pending.length > 0) {
      const name = pending.shift()!;
      if (name === ".") {
        continue;
      }
      if (name === "..") {
        if (depth > 0) {
          current = nodeDirname(current);
          depth--;
        }
        continue;
      }
      const candidate = nodeJoin(current, name);
      const last = pending.length === 0;
      if (last && !follow) {
        return candidate;
      }
      const component = await look(candidate);
      if (component.kind === "error") {
        throw rethrow(component.error, syscall, virtualPath);
      }
      if (component.kind === "missing") {
        // Does not exist: it cannot be a symlink, so the rest of the walk is
        // safe to build lexically and the real syscall reports the error.
        current = candidate;
        depth++;
        continue;
      }
      if (component.kind === "symlink") {
        links++;
        if (links > MAX_SYMLINK_DEPTH) {
          throw fsError("ELOOP", { syscall, path: virtualPath });
        }
        const { target } = component;
        if (target.startsWith("/")) {
          // Absolute targets are interpreted relative to the root, chroot-style.
          current = root;
          depth = 0;
        }
        pending.unshift(...target.split("/").filter((segment) => segment !== ""));
        continue;
      }
      current = candidate;
      depth++;
    }
    return current;
  }

  /**
   * The two paths a `rename`/`link` needs, resolved together: one shared
   * {@link memo}, so a common prefix is walked once, and concurrently, so the
   * remaining `lstat`s are one round of threadpool jobs rather than two.
   *
   * Settled rather than raced, because an oracle may not report a different
   * error depending on which of two walks happened to fail first: the *first*
   * path's failure wins, exactly as it did when the two ran in sequence.
   */
  async function securePair(
    first: string,
    second: string,
    syscall: string,
  ): Promise<[string, string]> {
    const look = memo();
    const settled = await Promise.allSettled([
      secure(first, false, syscall, look),
      secure(second, false, syscall, look),
    ]);
    for (const result of settled) {
      if (result.status === "rejected") {
        throw result.reason;
      }
    }
    return [
      (settled[0] as PromiseFulfilledResult<string>).value,
      (settled[1] as PromiseFulfilledResult<string>).value,
    ];
  }

  /** Re-throw an error raised while resolving, in terms of the virtual path. */
  function rethrow(error: unknown, syscall: string, path: string): unknown {
    if (isFsError(error) && error.code in ERRNO_CODES) {
      return fsError(error.code as ErrnoCode, { syscall, path, cause: error });
    }
    return error;
  }

  /** Map a real path back to its virtual form. */
  function virtual(path: string | undefined): string | undefined {
    if (path === undefined) {
      return undefined;
    }
    return path.startsWith(root) ? normalizePath(path.slice(root.length)) : undefined;
  }

  return {
    // Only what `resolveCapabilities` cannot infer from the methods below.
    capabilities: {
      handles: true,
      atomicRename: true,
      caseSensitive: process.platform !== "darwin" && process.platform !== "win32",
      readOnly: options.readOnly ?? false,
    },

    async stat(path) {
      return fs.stat(await secure(path, true, "stat"));
    },

    async lstat(path) {
      return fs.lstat(await secure(path, false, "lstat"));
    },

    async statfs(path) {
      return fs.statfs(await secure(path, true, "statfs"));
    },

    async readdir(path: string, _options: ReaddirOptions): Promise<DirentLike[]> {
      const parentPath = normalizePath(path);
      const entries = await fs.readdir(await secure(path, true, "scandir"), {
        withFileTypes: true,
      });
      return entries.map((entry) => ({
        name: entry.name,
        parentPath,
        isFile: () => entry.isFile(),
        isDirectory: () => entry.isDirectory(),
        isSymbolicLink: () => entry.isSymbolicLink(),
        isBlockDevice: () => entry.isBlockDevice(),
        isCharacterDevice: () => entry.isCharacterDevice(),
        isFIFO: () => entry.isFIFO(),
        isSocket: () => entry.isSocket(),
      }));
    },

    async open(path, flags = "r", mode = 0o666) {
      // `O_EXCL` fails on anything that exists, including a symlink — dangling
      // or not — so the final component must not be followed: handing the
      // symlink itself to `open` is what makes the kernel answer EEXIST.
      const follow = !isExclusive(flags);
      return fs.open(await secure(path, follow, "open"), flags, mode);
    },

    async mkdir(path, mkdirOptions: MkdirOptions = {}) {
      return virtual(await fs.mkdir(await secure(path, false, "mkdir"), mkdirOptions));
    },

    async rmdir(path) {
      const real = await secure(path, false, "rmdir");
      if (real === root) {
        // `secure("/")` is the root itself — `splitPath` leaves no components
        // to walk — so an *empty* root would be handed straight to `rmdir(2)`
        // and deleted, permanently killing the driver. Every other operation
        // on the root is caught by the kernel (`unlink` is `EISDIR`, `rename`
        // is `EINVAL`, a non-empty `rmdir` is `ENOTEMPTY`); this one is not,
        // because from the host's side the root is an ordinary directory.
        // `rmdir("/")` on a real filesystem is `EBUSY`, which is what the
        // memory driver answers too.
        throw fsError("EBUSY", { syscall: "rmdir", path: normalizePath(path) });
      }
      return fs.rmdir(real);
    },

    async unlink(path) {
      return fs.unlink(await secure(path, false, "unlink"));
    },

    async rename(oldPath, newPath) {
      const [from, to] = await securePair(oldPath, newPath, "rename");
      return fs.rename(from, to);
    },

    async link(existingPath, newPath) {
      const [from, to] = await securePair(existingPath, newPath, "link");
      return fs.link(from, to);
    },

    async symlink(target, path) {
      // The target is stored verbatim and only resolved when walked, so it can
      // never reach outside the root.
      return fs.symlink(target, await secure(path, false, "symlink"));
    },

    async readlink(path) {
      return fs.readlink(await secure(path, false, "readlink"));
    },

    async chmod(path, mode) {
      return fs.chmod(await secure(path, true, "chmod"), mode);
    },

    async chown(path, uid, gid) {
      return fs.chown(await secure(path, true, "chown"), uid, gid);
    },

    async lchown(path, uid, gid) {
      return fs.lchown(await secure(path, false, "lchown"), uid, gid);
    },

    async truncate(path, length = 0) {
      return fs.truncate(await secure(path, true, "truncate"), length);
    },

    async utimes(path, atime, mtime) {
      return fs.utimes(await secure(path, true, "utime"), atime, mtime);
    },

    async lutimes(path, atime, mtime) {
      return fs.lutimes(await secure(path, false, "lutime"), atime, mtime);
    },
  };
}
