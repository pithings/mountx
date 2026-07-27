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
import { normalizePath, splitPath } from "../path.ts";
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

  /**
   * Resolve a virtual path to a real one that is guaranteed to be inside
   * `root`. Missing components are fine (the real syscall reports them); the
   * point is that nothing above `root` is ever reachable.
   */
  async function secure(path: string, follow: boolean, syscall: string): Promise<string> {
    const virtualPath = normalizePath(path);
    const pending = splitPath(virtualPath);
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
      let stats;
      try {
        stats = await fs.lstat(candidate);
      } catch (error) {
        if (isFsError(error, "ENOENT")) {
          // Does not exist: it cannot be a symlink, so the rest of the walk is
          // safe to build lexically and the real syscall reports the error.
          current = candidate;
          depth++;
          continue;
        }
        throw rethrow(error, syscall, virtualPath);
      }
      if (stats.isSymbolicLink()) {
        links++;
        if (links > MAX_SYMLINK_DEPTH) {
          throw fsError("ELOOP", { syscall, path: virtualPath });
        }
        const target = await fs.readlink(candidate);
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
      return fs.rmdir(await secure(path, false, "rmdir"));
    },

    async unlink(path) {
      return fs.unlink(await secure(path, false, "unlink"));
    },

    async rename(oldPath, newPath) {
      return fs.rename(
        await secure(oldPath, false, "rename"),
        await secure(newPath, false, "rename"),
      );
    },

    async link(existingPath, newPath) {
      return fs.link(
        await secure(existingPath, false, "link"),
        await secure(newPath, false, "link"),
      );
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
