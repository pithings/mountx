/**
 * An in-memory `FsDriver`: memfs-shaped, no persistence, no dependencies.
 *
 * Correctness targets (the things transports actually exercise): symlinks,
 * hardlinks with real `nlink` counting, rename of a whole subtree, open
 * handles that survive `unlink`, and `node:fs`-identical errno.
 */

import { fsError } from "../errors.ts";
import { isPathInside, joinPath, normalizePath, splitPath } from "../path.ts";
import type { OpenFlags } from "./handle.ts";
import { parseOpenFlags, resizeBytes, validatePosition, validateRange } from "./handle.ts";
import type {
  DirentLike,
  FileHandleLike,
  FullFsDriver,
  MkdirOptions,
  ReaddirOptions,
  StatsFsLike,
  StatsLike,
  TimeLike,
} from "../types.ts";
import { S_IFDIR, S_IFLNK, S_IFMT, S_IFREG } from "../types.ts";

const BLOCK_SIZE = 4096;
const MAX_SYMLINK_DEPTH = 40;
const EMPTY = new Uint8Array(0);
const encoder = new TextEncoder();

interface MemNode {
  ino: number;
  mode: number;
  nlink: number;
  uid: number;
  gid: number;
  rdev: number;
  atimeMs: number;
  mtimeMs: number;
  ctimeMs: number;
  birthtimeMs: number;
  /** Regular files. */
  data?: Uint8Array;
  /** Directories. */
  children?: Map<string, MemNode>;
  /** Symlinks. */
  target?: string;
}

/** A resolved path: the containing directory, the final name, the node if it exists. */
interface Entry {
  parent: MemNode;
  name: string;
  node?: MemNode;
  path: string;
}

export interface MemoryDriverOptions {
  /** Owner of everything created. Defaults to the current process. */
  uid?: number;
  gid?: number;
  /**
   * Bits cleared from every `mkdir`/`open` mode. **Default `0`, i.e. none.**
   *
   * A umask belongs to a *process*, and a driver is not one. Under a mount it
   * is worse than redundant: the kernel has already applied the calling
   * process's umask before the mode reaches `FUSE_MKDIR`/`FUSE_CREATE` (there
   * is no `FUSE_DONT_MASK` in this build), so a second one here masks with the
   * wrong process's value and produces a file the caller did not ask for —
   * `create f 04777` arriving as `04755` (found by pjdfstest `chmod/12.t`).
   * Set it explicitly for a loopback filesystem that wants `node:fs`-like
   * behaviour.
   */
  umask?: number;
  /** Mode of the root directory. */
  rootMode?: number;
}

const isDirectory = (node: MemNode): boolean => (node.mode & S_IFMT) === S_IFDIR;
const isSymlink = (node: MemNode): boolean => (node.mode & S_IFMT) === S_IFLNK;

function toMs(time: TimeLike): number {
  return typeof time === "number" ? time * 1000 : time.getTime();
}

/** Create an in-memory filesystem driver, initially holding an empty root. */
export function createMemoryDriver(options: MemoryDriverOptions = {}): FullFsDriver {
  const uid = options.uid ?? process.getuid?.() ?? 0;
  const gid = options.gid ?? process.getgid?.() ?? 0;
  const umask = options.umask ?? 0;

  let nextIno = 1;
  let nextFd = 3;

  const now = (): number => Date.now();

  function createNode(mode: number, extra: Partial<MemNode> = {}): MemNode {
    const time = now();
    return {
      ino: nextIno++,
      mode,
      nlink: 1,
      uid,
      gid,
      rdev: 0,
      atimeMs: time,
      mtimeMs: time,
      ctimeMs: time,
      birthtimeMs: time,
      ...extra,
    };
  }

  const root = createNode(S_IFDIR | (options.rootMode ?? 0o755), { children: new Map() });

  // --- path resolution ---

  function walk(path: string, follow: boolean, syscall: string, depth = 0): Entry {
    const normalized = normalizePath(path);
    const segments = splitPath(normalized);
    let directory = root;
    for (let index = 0; index < segments.length; index++) {
      const name = segments[index]!;
      const last = index === segments.length - 1;
      if (!isDirectory(directory)) {
        throw fsError("ENOTDIR", { syscall, path: normalized });
      }
      const node = directory.children!.get(name);
      if (node === undefined) {
        if (last) {
          return { parent: directory, name, path: normalized };
        }
        throw fsError("ENOENT", { syscall, path: normalized });
      }
      if (isSymlink(node) && (follow || !last)) {
        if (depth >= MAX_SYMLINK_DEPTH) {
          throw fsError("ELOOP", { syscall, path: normalized });
        }
        const target = node.target!;
        const base = target.startsWith("/")
          ? target
          : `/${segments.slice(0, index).join("/")}/${target}`;
        return walk(joinPath(base, ...segments.slice(index + 1)), follow, syscall, depth + 1);
      }
      if (last) {
        return { parent: directory, name, node, path: normalized };
      }
      directory = node;
    }
    return { parent: root, name: "", node: root, path: "/" };
  }

  function resolve(path: string, follow: boolean, syscall: string): MemNode {
    const entry = walk(path, follow, syscall);
    if (entry.node === undefined) {
      throw fsError("ENOENT", { syscall, path: entry.path });
    }
    return entry.node;
  }

  function directoryOf(path: string, syscall: string): MemNode {
    const node = resolve(path, true, syscall);
    if (!isDirectory(node)) {
      throw fsError("ENOTDIR", { syscall, path: normalizePath(path) });
    }
    return node;
  }

  // --- node helpers ---

  function link(entry: Entry, node: MemNode): void {
    entry.parent.children!.set(entry.name, node);
    entry.parent.mtimeMs = entry.parent.ctimeMs = now();
  }

  function unlinkEntry(entry: Entry, node: MemNode): void {
    entry.parent.children!.delete(entry.name);
    entry.parent.mtimeMs = entry.parent.ctimeMs = now();
    node.nlink--;
    node.ctimeMs = now();
  }

  function nlinkOf(node: MemNode): number {
    if (!isDirectory(node)) {
      return node.nlink;
    }
    let count = 2;
    for (const child of node.children!.values()) {
      if (isDirectory(child)) {
        count++;
      }
    }
    return count;
  }

  function sizeOf(node: MemNode): number {
    if (isDirectory(node)) {
      return BLOCK_SIZE;
    }
    // A symlink's size is its target in bytes, not in UTF-16 code units.
    return isSymlink(node) ? encoder.encode(node.target!).byteLength : (node.data?.byteLength ?? 0);
  }

  function toStats(node: MemNode): StatsLike {
    const size = sizeOf(node);
    const type = node.mode & S_IFMT;
    return {
      dev: 0,
      ino: node.ino,
      mode: node.mode,
      nlink: nlinkOf(node),
      uid: node.uid,
      gid: node.gid,
      rdev: node.rdev,
      size,
      blksize: BLOCK_SIZE,
      blocks: Math.ceil(size / 512),
      atimeMs: node.atimeMs,
      mtimeMs: node.mtimeMs,
      ctimeMs: node.ctimeMs,
      birthtimeMs: node.birthtimeMs,
      isFile: () => type === S_IFREG,
      isDirectory: () => type === S_IFDIR,
      isSymbolicLink: () => type === S_IFLNK,
      isBlockDevice: () => false,
      isCharacterDevice: () => false,
      isFIFO: () => false,
      isSocket: () => false,
    };
  }

  // --- open handles ---

  function createFileHandle(node: MemNode, flags: OpenFlags, path: string): FileHandleLike {
    let position = 0;
    let closed = false;

    function begin(syscall: string, write: boolean): void {
      if (closed || (write ? !flags.write : !flags.read)) {
        throw fsError("EBADF", { syscall, path });
      }
      if (isDirectory(node)) {
        throw fsError("EISDIR", { syscall, path });
      }
    }

    return {
      fd: nextFd++,

      async read(buffer, offset, length, at) {
        begin("read", false);
        const { start, count } = validateRange(buffer, offset, length, false);
        const explicit = validatePosition(at);
        const from = explicit ?? position;
        const data = node.data ?? EMPTY;
        const bytesRead = Math.max(0, Math.min(count, data.byteLength - from));
        buffer.set(data.subarray(from, from + bytesRead), start);
        if (explicit === undefined) {
          position += bytesRead;
        }
        node.atimeMs = now();
        return { bytesRead, buffer };
      },

      async write(buffer, offset, length, at) {
        begin("write", true);
        const { start, count } = validateRange(buffer, offset, length, true);
        const explicit = validatePosition(at);
        const from = flags.append ? sizeOf(node) : (explicit ?? position);
        if (from + count > (node.data?.byteLength ?? 0)) {
          resizeBytes(node, from + count);
        }
        node.data!.set(buffer.subarray(start, start + count), from);
        if (flags.append || explicit === undefined) {
          position = from + count;
        }
        node.mtimeMs = node.ctimeMs = now();
        return { bytesWritten: count, buffer };
      },

      async stat() {
        if (closed) {
          throw fsError("EBADF", { syscall: "fstat", path });
        }
        return toStats(node);
      },

      async truncate(length = 0) {
        begin("ftruncate", true);
        resizeBytes(node, length);
        node.mtimeMs = node.ctimeMs = now();
      },

      async sync() {},

      async datasync() {},

      async close() {
        closed = true;
      },
    };
  }

  // --- driver ---

  const driver: FullFsDriver = {
    // Only what `resolveCapabilities` cannot infer from the methods below.
    capabilities: {
      handles: true,
      atomicRename: true,
      caseSensitive: true,
      readOnly: false,
    },

    async stat(path) {
      return toStats(resolve(path, true, "stat"));
    },

    async lstat(path) {
      return toStats(resolve(path, false, "lstat"));
    },

    async statfs(path): Promise<StatsFsLike> {
      resolve(path, true, "statfs");
      let used = 0;
      const seen = new Set<MemNode>();
      const visit = (node: MemNode): void => {
        if (seen.has(node)) {
          return;
        }
        seen.add(node);
        used += Math.ceil(sizeOf(node) / BLOCK_SIZE);
        if (isDirectory(node)) {
          for (const child of node.children!.values()) {
            visit(child);
          }
        }
      };
      visit(root);
      const blocks = 1024 * 1024;
      return {
        type: 0x01_02_19_94, // TMPFS_MAGIC
        bsize: BLOCK_SIZE,
        blocks,
        bfree: blocks - used,
        bavail: blocks - used,
        files: 1024 * 1024,
        ffree: 1024 * 1024 - seen.size,
      };
    },

    async readdir(path: string, _options: ReaddirOptions): Promise<DirentLike[]> {
      const node = directoryOf(path, "scandir");
      const parentPath = normalizePath(path);
      node.atimeMs = now();
      return [...node.children!].map(([name, child]) => {
        const stats = toStats(child);
        return {
          name,
          parentPath,
          isFile: stats.isFile,
          isDirectory: stats.isDirectory,
          isSymbolicLink: stats.isSymbolicLink,
          isBlockDevice: stats.isBlockDevice,
          isCharacterDevice: stats.isCharacterDevice,
          isFIFO: stats.isFIFO,
          isSocket: stats.isSocket,
        };
      });
    },

    async open(path, flags = "r", mode = 0o666) {
      const parsed = parseOpenFlags(flags, normalizePath(path));
      // `O_EXCL` fails on anything that exists, including a symlink — dangling
      // or not — so the final component must not be followed.
      const entry = walk(path, !(parsed.create && parsed.exclusive), "open");
      let node = entry.node;
      if (node === undefined) {
        if (!parsed.create) {
          throw fsError("ENOENT", { syscall: "open", path: entry.path });
        }
        node = createNode(S_IFREG | (mode & ~umask & 0o7777), { data: EMPTY });
        link(entry, node);
      } else {
        if (parsed.exclusive) {
          throw fsError("EEXIST", { syscall: "open", path: entry.path });
        }
        if (isDirectory(node) && parsed.write) {
          throw fsError("EISDIR", { syscall: "open", path: entry.path });
        }
        if (parsed.truncate && !isDirectory(node)) {
          resizeBytes(node, 0);
          node.mtimeMs = node.ctimeMs = now();
        }
      }
      return createFileHandle(node, parsed, entry.path);
    },

    async mkdir(path, options: MkdirOptions = {}) {
      const mode = S_IFDIR | ((options.mode ?? 0o777) & ~umask & 0o7777);
      if (options.recursive) {
        let firstCreated: string | undefined;
        let current = "/";
        const segments = splitPath(path);
        for (const [index, segment] of segments.entries()) {
          current = joinPath(current, segment);
          const entry = walk(current, true, "mkdir");
          if (entry.node === undefined) {
            link(entry, createNode(mode, { children: new Map() }));
            firstCreated ??= current;
          } else if (!isDirectory(entry.node)) {
            // In the way at the end is EEXIST; in the way mid-path is ENOTDIR.
            const last = index === segments.length - 1;
            throw fsError(last ? "EEXIST" : "ENOTDIR", { syscall: "mkdir", path: current });
          }
        }
        return firstCreated;
      }
      const entry = walk(path, false, "mkdir");
      if (entry.node !== undefined) {
        throw fsError("EEXIST", { syscall: "mkdir", path: entry.path });
      }
      link(entry, createNode(mode, { children: new Map() }));
      return undefined;
    },

    async rmdir(path) {
      const entry = walk(path, false, "rmdir");
      if (entry.node === undefined) {
        throw fsError("ENOENT", { syscall: "rmdir", path: entry.path });
      }
      if (entry.node === root) {
        throw fsError("EBUSY", { syscall: "rmdir", path: entry.path });
      }
      if (!isDirectory(entry.node)) {
        throw fsError("ENOTDIR", { syscall: "rmdir", path: entry.path });
      }
      if (entry.node.children!.size > 0) {
        throw fsError("ENOTEMPTY", { syscall: "rmdir", path: entry.path });
      }
      unlinkEntry(entry, entry.node);
    },

    async unlink(path) {
      const entry = walk(path, false, "unlink");
      if (entry.node === undefined) {
        throw fsError("ENOENT", { syscall: "unlink", path: entry.path });
      }
      if (isDirectory(entry.node)) {
        throw fsError("EISDIR", { syscall: "unlink", path: entry.path });
      }
      unlinkEntry(entry, entry.node);
    },

    async rename(oldPath, newPath) {
      const from = walk(oldPath, false, "rename");
      if (from.node === undefined) {
        throw fsError("ENOENT", {
          syscall: "rename",
          path: from.path,
          dest: normalizePath(newPath),
        });
      }
      const to = walk(newPath, false, "rename");
      if (from.node === to.node) {
        return;
      }
      const directory = isDirectory(from.node);
      if (directory && isPathInside(to.path, from.path)) {
        throw fsError("EINVAL", { syscall: "rename", path: from.path, dest: to.path });
      }
      if (to.node !== undefined) {
        if (directory) {
          if (!isDirectory(to.node)) {
            throw fsError("ENOTDIR", { syscall: "rename", path: from.path, dest: to.path });
          }
          if (to.node.children!.size > 0) {
            throw fsError("ENOTEMPTY", { syscall: "rename", path: from.path, dest: to.path });
          }
        } else if (isDirectory(to.node)) {
          throw fsError("EISDIR", { syscall: "rename", path: from.path, dest: to.path });
        }
        unlinkEntry(to, to.node);
      }
      from.parent.children!.delete(from.name);
      from.parent.mtimeMs = from.parent.ctimeMs = now();
      link(to, from.node);
      from.node.ctimeMs = now();
    },

    async link(existingPath, newPath) {
      const from = walk(existingPath, false, "link");
      if (from.node === undefined) {
        throw fsError("ENOENT", { syscall: "link", path: from.path, dest: normalizePath(newPath) });
      }
      if (isDirectory(from.node)) {
        throw fsError("EPERM", { syscall: "link", path: from.path, dest: normalizePath(newPath) });
      }
      const to = walk(newPath, false, "link");
      if (to.node !== undefined) {
        throw fsError("EEXIST", { syscall: "link", path: from.path, dest: to.path });
      }
      from.node.nlink++;
      from.node.ctimeMs = now();
      link(to, from.node);
    },

    async symlink(target, path) {
      const entry = walk(path, false, "symlink");
      if (entry.node !== undefined) {
        throw fsError("EEXIST", { syscall: "symlink", path: target, dest: entry.path });
      }
      link(entry, createNode(S_IFLNK | 0o777, { target }));
    },

    async readlink(path) {
      const node = resolve(path, false, "readlink");
      if (!isSymlink(node)) {
        throw fsError("EINVAL", { syscall: "readlink", path: normalizePath(path) });
      }
      return node.target!;
    },

    async chmod(path, mode) {
      const node = resolve(path, true, "chmod");
      node.mode = (node.mode & S_IFMT) | (mode & 0o7777);
      node.ctimeMs = now();
    },

    async chown(path, ownerUid, ownerGid) {
      chown(resolve(path, true, "chown"), ownerUid, ownerGid);
    },

    async lchown(path, ownerUid, ownerGid) {
      chown(resolve(path, false, "lchown"), ownerUid, ownerGid);
    },

    async truncate(path, length = 0) {
      const node = resolve(path, true, "truncate");
      if (isDirectory(node)) {
        throw fsError("EISDIR", { syscall: "open", path: normalizePath(path) });
      }
      resizeBytes(node, length);
      node.mtimeMs = node.ctimeMs = now();
    },

    async utimes(path, atime, mtime) {
      utimes(resolve(path, true, "utime"), atime, mtime);
    },

    async lutimes(path, atime, mtime) {
      utimes(resolve(path, false, "lutime"), atime, mtime);
    },
  };

  function chown(node: MemNode, ownerUid: number, ownerGid: number): void {
    if (ownerUid >= 0) {
      node.uid = ownerUid;
    }
    if (ownerGid >= 0) {
      node.gid = ownerGid;
    }
    node.ctimeMs = now();
  }

  function utimes(node: MemNode, atime: TimeLike, mtime: TimeLike): void {
    node.atimeMs = toMs(atime);
    node.mtimeMs = toMs(mtime);
    node.ctimeMs = now();
  }

  return driver;
}
