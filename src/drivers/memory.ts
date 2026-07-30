/**
 * An in-memory `FsDriver`: memfs-shaped, no persistence, no dependencies.
 *
 * Correctness targets (the things transports actually exercise): symlinks,
 * hardlinks with real `nlink` counting, rename of a whole subtree, open
 * handles that survive `unlink`, and `node:fs`-identical errno.
 */

import { fsError } from "../errors.ts";
import { isPathInside, joinPath, normalizePath, resolvePath, splitPath } from "../path.ts";
import type { OpenFlags } from "./handle.ts";
import { parseOpenFlags, resizeBytes, validatePosition, validateRange } from "./handle.ts";
import type {
  DirentLike,
  FileHandleLike,
  FullFsDriver,
  MkdirOptions,
  MountxExtensions,
  ReaddirOptions,
  StatsFsLike,
  StatsLike,
  TimeLike,
} from "../types.ts";
import {
  S_IFBLK,
  S_IFCHR,
  S_IFDIR,
  S_IFIFO,
  S_IFLNK,
  S_IFMT,
  S_IFREG,
  S_IFSOCK,
} from "../types.ts";

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

/** The four types only `mountx.mknod` can make, and which hold no bytes. */
const SPECIAL_TYPES: ReadonlySet<number> = new Set([S_IFIFO, S_IFCHR, S_IFBLK, S_IFSOCK]);
const isSpecial = (node: MemNode): boolean => SPECIAL_TYPES.has(node.mode & S_IFMT);

/** Type predicates for `StatsLike` and `DirentLike` alike: one field decides all seven. */
type TypePredicates = Pick<
  StatsLike,
  | "isFile"
  | "isDirectory"
  | "isSymbolicLink"
  | "isBlockDevice"
  | "isCharacterDevice"
  | "isFIFO"
  | "isSocket"
>;

function typePredicates(mode: number): TypePredicates {
  const type = mode & S_IFMT;
  return {
    isFile: () => type === S_IFREG,
    isDirectory: () => type === S_IFDIR,
    isSymbolicLink: () => type === S_IFLNK,
    isBlockDevice: () => type === S_IFBLK,
    isCharacterDevice: () => type === S_IFCHR,
    isFIFO: () => type === S_IFIFO,
    isSocket: () => type === S_IFSOCK,
  };
}

function toMs(time: TimeLike): number {
  return typeof time === "number" ? time * 1000 : time.getTime();
}

/**
 * What {@link createMemoryDriver} returns: every optional method, and a
 * `mountx.mknod` that is not optional either — so a caller can write
 * `driver.mountx.mknod(...)` without asking whether it is there.
 */
export type MemoryDriver = FullFsDriver & {
  readonly mountx: Required<Pick<MountxExtensions, "mknod">>;
};

/** Create an in-memory filesystem driver, initially holding an empty root. */
export function createMemoryDriver(options: MemoryDriverOptions = {}): MemoryDriver {
  const uid = options.uid ?? process.getuid?.() ?? 0;
  const gid = options.gid ?? process.getgid?.() ?? 0;
  const umask = options.umask ?? 0;

  let nextIno = 1;
  let nextFd = 3;

  /**
   * What `statfs` reports, kept as running totals.
   *
   * The obvious implementation walks the whole tree per call, and desktops poll
   * `statfs` on a timer (which is why `cli/watch.ts` lists it as noisy) — so a
   * mount of a large tree paid an O(nodes) walk, plus a `Set` of every node, at
   * whatever rate the desktop felt like asking. There are exactly three places
   * either total can change: a node joining the tree ({@link createNode}), the
   * last entry naming one going away ({@link unlinkEntry}), and a file's length
   * changing ({@link resize}).
   *
   * "In the tree" is `nlink > 0`, which holds for every node here: `createNode`
   * starts at 1, `link` bumps it, `unlinkEntry` drops it, and the root is never
   * unlinked. A node kept alive by an open handle after its last `unlink` is
   * *not* counted, which is what the tree walk answered too.
   */
  let nodeCount = 0;
  let usedBlocks = 0;

  const now = (): number => Date.now();

  function createNode(mode: number, extra: Partial<MemNode> = {}): MemNode {
    const time = now();
    const node: MemNode = {
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
    // Every node created here is linked into a directory by its caller on the
    // next line, bar the root — which is in the tree by definition.
    nodeCount++;
    usedBlocks += blocksOf(node);
    return node;
  }

  const root = createNode(S_IFDIR | (options.rootMode ?? 0o755), { children: new Map() });

  // --- path resolution ---

  function walk(path: string, follow: boolean, syscall: string, depth = 0): Entry {
    const { path: normalized, segments } = resolvePath(path);
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
        if (target === "") {
          // `symlink()` refuses to store one, but a driver built by hand (or an
          // older snapshot) can hold one, and it must not be walked: joining
          // an empty segment collapses onto the link's own parent, which would
          // make the link a live alias for the directory it sits in.
          throw fsError("ENOENT", { syscall, path: normalized });
        }
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
    if (node.nlink === 0) {
      nodeCount--;
      usedBlocks -= blocksOf(node);
    }
  }

  /** {@link resizeBytes}, keeping `statfs`'s block total in step. */
  function resize(node: MemNode, size: number): void {
    const before = blocksOf(node);
    resizeBytes(node, size);
    if (node.nlink > 0) {
      usedBlocks += blocksOf(node) - before;
    }
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

  function blocksOf(node: MemNode): number {
    return Math.ceil(sizeOf(node) / BLOCK_SIZE);
  }

  function toStats(node: MemNode): StatsLike {
    const size = sizeOf(node);
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
      ...typePredicates(node.mode),
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
        if (bytesRead > 0) {
          // `TypedArray.set` rejects an out-of-bounds offset even with nothing
          // to copy, and `read(buffer, offset, 0)` with an offset past the end
          // is a call `node:fs` answers `bytesRead: 0` to.
          buffer.set(data.subarray(from, from + bytesRead), start);
        }
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
          resize(node, from + count);
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
        resize(node, length);
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

  const driver: MemoryDriver = {
    // Only what `resolveCapabilities` cannot infer from the methods below.
    // `extensions` is inferred from the keys of `mountx`, so it is not here.
    capabilities: {
      handles: true,
      atomicRename: true,
      caseSensitive: true,
      readOnly: false,
    },

    mountx: {
      /**
       * FIFOs, sockets and device nodes — the one thing every transport can
       * carry and `node:fs/promises` cannot express, which is why it is an
       * extension rather than a method.
       *
       * There is no kernel obstacle to any of it: a node with the right `S_IF*`
       * in `mode` (and an `rdev` for the two device types) reported by `stat`
       * is all a FUSE, 9P or NFS client needs, and the VFS supplies the pipe,
       * socket and device semantics itself. What that leaves this driver is
       * storage and nothing else — the node holds no bytes, so `open` and
       * `truncate` refuse it (see both).
       *
       * Device *nodes* are not device *access*: `fusermount3` mounts `nodev`,
       * so a `mknod` of one over an unprivileged mount produces a node that
       * stats correctly and cannot be opened. That is the mount's rule, not
       * this driver's, and refusing to store one here would only hide it.
       */
      async mknod(path, mode, dev) {
        const type = mode & S_IFMT;
        const entry = walk(path, false, "mknod");
        if (entry.node !== undefined) {
          throw fsError("EEXIST", { syscall: "mknod", path: entry.path });
        }
        const permissions = mode & ~umask & 0o7777;
        if (type === S_IFREG || type === 0) {
          // `mknod(2)`'s regular-file case, which POSIX spells as a type of
          // zero and which the FUSE and 9P sessions fall back to `open` for
          // when no driver implements this. Reached here from `MKNOD` when the
          // kernel has no `CREATE`, and from tools that still create an empty
          // file this way.
          link(entry, createNode(S_IFREG | permissions, { data: EMPTY }));
          return;
        }
        if (!SPECIAL_TYPES.has(type)) {
          // A directory or a symlink is `EPERM` from `mknod(2)` too: those have
          // their own calls, and this one must not become a second way in.
          throw fsError("EPERM", { syscall: "mknod", path: entry.path });
        }
        link(
          entry,
          createNode(type | permissions, {
            // `rdev` means something for the two device types and nothing for
            // a FIFO or a socket, where POSIX leaves the argument unused.
            rdev: type === S_IFCHR || type === S_IFBLK ? dev : 0,
          }),
        );
      },
    },

    async stat(path) {
      return toStats(resolve(path, true, "stat"));
    },

    async lstat(path) {
      return toStats(resolve(path, false, "lstat"));
    },

    async statfs(path): Promise<StatsFsLike> {
      resolve(path, true, "statfs");
      const blocks = 1024 * 1024;
      const files = 1024 * 1024;
      return {
        type: 0x01_02_19_94, // TMPFS_MAGIC
        bsize: BLOCK_SIZE,
        blocks,
        bfree: blocks - usedBlocks,
        bavail: blocks - usedBlocks,
        files,
        ffree: files - nodeCount,
      };
    },

    async readdir(path: string, _options: ReaddirOptions): Promise<DirentLike[]> {
      const node = directoryOf(path, "scandir");
      const parentPath = normalizePath(path);
      node.atimeMs = now();
      // A `DirentLike` keeps only the type predicates, so a full `StatsLike`
      // per entry is all waste — and `nlinkOf` makes it worse than waste, by
      // rescanning every subdirectory's children to count links nobody reads.
      // The file type is one field of `mode`.
      return [...node.children!].map(([name, child]) => ({
        name,
        parentPath,
        ...typePredicates(child.mode),
      }));
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
        if (isSpecial(node)) {
          // A special file is a *name* here and nothing more: the node carries
          // the type and the `rdev`, and every client that reaches one over a
          // mount gets its pipe, socket or device semantics from its own kernel
          // rather than from this driver — the FUSE, 9P and NFS clients all
          // handle these types locally and never send the open across. So the
          // only caller that can arrive here is a loopback one, and answering
          // it with a byte buffer would invent a filesystem no mount has.
          // `ENXIO` is what `open(2)` says for a device with no driver behind
          // it, which is exactly the situation.
          throw fsError("ENXIO", { syscall: "open", path: entry.path });
        }
        if (parsed.truncate && !isDirectory(node)) {
          resize(node, 0);
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
      if (target === "") {
        // POSIX has no empty pathname, and `symlink(2)` rejects it in
        // `getname()` before the filesystem is reached. `node:fs` answers
        // `ENOENT` — and does so *before* the `EEXIST` check, so the order of
        // these two matters.
        throw fsError("ENOENT", { syscall: "symlink", path: target, dest: entry.path });
      }
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
      if (isSpecial(node)) {
        // `truncate(2)`'s own answer for anything that is not a regular file.
        throw fsError("EINVAL", { syscall: "open", path: normalizePath(path) });
      }
      resize(node, length);
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
