/**
 * The loopback harness: driver calls fed straight to a driver, with the same
 * path normalization and capability resolution a transport would apply, and no
 * mount anywhere.
 *
 * This is what driver authors test against, and what the Tier-0 conformance
 * suite runs on.
 */

import { fsError } from "./errors.ts";
import { normalizePath } from "./path.ts";
import type { FsCapabilities, FsDriver, FsDriverMethod, MountxExtensions } from "./types.ts";

/** Capabilities with every member decided (declared, or inferred from the driver). */
export type ResolvedCapabilities = Required<Omit<FsCapabilities, "extensions">> & {
  extensions: readonly (keyof MountxExtensions)[];
};

/** Decide what a driver supports: declarations win, presence of a method is the fallback. */
export function resolveCapabilities(driver: FsDriver): ResolvedCapabilities {
  const declared = driver.capabilities ?? {};
  const has = (name: FsDriverMethod): boolean => typeof driver[name] === "function";
  return {
    // Neither of these can be inferred from the shape of a driver: `open()`
    // exists on every driver whether or not it returns real per-open state,
    // and `rename()` exists whether or not it is atomic. Unclaimed means no.
    handles: declared.handles ?? false,
    atomicRename: declared.atomicRename ?? false,
    hardlinks: declared.hardlinks ?? has("link"),
    symlinks: declared.symlinks ?? (has("symlink") && has("readlink") && has("lstat")),
    permissions: declared.permissions ?? has("chmod"),
    times: declared.times ?? has("utimes"),
    truncate: declared.truncate ?? has("truncate"),
    caseSensitive: declared.caseSensitive ?? true,
    statfs: declared.statfs ?? has("statfs"),
    readOnly: declared.readOnly ?? !(has("unlink") || has("mkdir") || has("rename")),
    extensions:
      declared.extensions ?? (Object.keys(driver.mountx ?? {}) as (keyof MountxExtensions)[]),
  };
}

/**
 * A driver with every optional method present: missing ones throw `ENOSYS`,
 * and every path is normalized before it reaches the driver.
 */
export interface Loopback extends Required<Omit<FsDriver, "capabilities" | "mountx">> {
  readonly driver: FsDriver;
  readonly capabilities: ResolvedCapabilities;
  readonly mountx: MountxExtensions | undefined;
  /** Whole-file read, for drivers and tests that do not want a handle dance. */
  readFile(path: string): Promise<Uint8Array>;
  /** Whole-file write (create + truncate). */
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
}

const encoder = new TextEncoder();

/** Wrap a driver in the loopback harness. */
export function createLoopback(driver: FsDriver): Loopback {
  function use<K extends FsDriverMethod>(name: K): NonNullable<FsDriver[K]> {
    const method = driver[name] as ((...args: never[]) => unknown) | undefined;
    if (typeof method !== "function") {
      throw fsError("ENOSYS", { syscall: name });
    }
    return method.bind(driver) as NonNullable<FsDriver[K]>;
  }

  const loopback: Loopback = {
    driver,
    capabilities: resolveCapabilities(driver),
    mountx: driver.mountx,

    // Every wrapper is `async` so that a missing method rejects rather than
    // throwing synchronously: callers only ever have to handle one of the two.
    stat: async (path) => use("stat")(normalizePath(path)),
    lstat: async (path) => use("lstat")(normalizePath(path)),
    statfs: async (path) => use("statfs")(normalizePath(path)),
    readdir: async (path, options) => use("readdir")(normalizePath(path), options),
    open: async (path, flags, mode) => use("open")(normalizePath(path), flags, mode),
    mkdir: async (path, options) => use("mkdir")(normalizePath(path), options),
    rmdir: async (path) => use("rmdir")(normalizePath(path)),
    unlink: async (path) => use("unlink")(normalizePath(path)),
    rename: async (oldPath, newPath) =>
      use("rename")(normalizePath(oldPath), normalizePath(newPath)),
    link: async (existingPath, newPath) =>
      use("link")(normalizePath(existingPath), normalizePath(newPath)),
    // The target of a symlink is opaque: it may be relative, and it is only
    // resolved when something walks through it.
    symlink: async (target, path, type) => use("symlink")(target, normalizePath(path), type),
    readlink: async (path) => use("readlink")(normalizePath(path)),
    chmod: async (path, mode) => use("chmod")(normalizePath(path), mode),
    chown: async (path, uid, gid) => use("chown")(normalizePath(path), uid, gid),
    lchown: async (path, uid, gid) => use("lchown")(normalizePath(path), uid, gid),
    truncate: async (path, length) => use("truncate")(normalizePath(path), length),
    utimes: async (path, atime, mtime) => use("utimes")(normalizePath(path), atime, mtime),
    lutimes: async (path, atime, mtime) => use("lutimes")(normalizePath(path), atime, mtime),

    async readFile(path) {
      const handle = await loopback.open(path, "r");
      try {
        const chunks: Uint8Array[] = [];
        let total = 0;
        for (;;) {
          const buffer = new Uint8Array(64 * 1024);
          const { bytesRead } = await handle.read(buffer, 0, buffer.byteLength, total);
          if (bytesRead === 0) {
            break;
          }
          chunks.push(buffer.subarray(0, bytesRead));
          total += bytesRead;
        }
        const data = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
          data.set(chunk, offset);
          offset += chunk.byteLength;
        }
        return data;
      } finally {
        await handle.close();
      }
    },

    async writeFile(path, data) {
      const bytes = typeof data === "string" ? encoder.encode(data) : data;
      const handle = await loopback.open(path, "w", 0o666);
      try {
        let written = 0;
        while (written < bytes.byteLength) {
          const remaining = bytes.byteLength - written;
          const { bytesWritten } = await handle.write(bytes, written, remaining, written);
          if (!Number.isInteger(bytesWritten) || bytesWritten <= 0 || bytesWritten > remaining) {
            throw fsError("EIO", { syscall: "write", path });
          }
          written += bytesWritten;
        }
      } finally {
        await handle.close();
      }
    },
  };

  return loopback;
}
