/**
 * An `FsDriver` over an [unstorage](https://unstorage.unjs.io) `Storage`.
 *
 * One adapter, and every unstorage driver becomes mountable: filesystem, S3,
 * Redis, Cloudflare KV, GitHub, an HTTP endpoint, or a `Storage` with several
 * of those mounted into one key space. `unstorage` is an **optional peer
 * dependency** and is imported for its types only — nothing in this file
 * survives to runtime but the adapter, so the zero-runtime-dependency rule
 * holds.
 *
 * ## The model
 *
 * A `Storage` is a flat key–value map. A filesystem is a tree with directories,
 * random access and metadata. The mapping, in full:
 *
 * - **Path to key.** `/a/b/c.txt` is the key `a:b:c.txt`. unstorage's own
 *   `normalizeKey` already treats `/` as `:`, so this is its convention rather
 *   than one invented here. The root is the empty base.
 * - **Directories are prefixes.** There is no such thing as an empty directory
 *   in a key–value store, so `mkdir` of one is remembered *in this process* and
 *   nowhere else; the moment it holds a file it is a real prefix and outlives
 *   the process like anything else. Nothing is written to the store to mark it
 *   — a marker key would show up as a file in every other consumer of that
 *   store, which is a worse trade than a directory that does not survive a
 *   restart while empty.
 * - **Files are values.** `getItemRaw`/`setItemRaw`, so a driver that can hold
 *   bytes holds bytes; one that cannot gets unstorage's own base64 fallback.
 *   Whatever comes back that is *not* bytes is rendered as text — a string as
 *   itself, anything else as JSON — so a store full of objects mounts as a tree
 *   of readable files rather than failing.
 * - **Random access is buffered.** A `Storage` has no partial read or write, so
 *   an open file is read into memory once and written back whole on `fsync` and
 *   on the last `close`. Handles on the same path share that one buffer, which
 *   is what keeps `stat` and a second reader consistent with a write that has
 *   not been flushed yet.
 * - **Permissions and timestamps are an overlay**, held in memory for the life
 *   of the driver, seeded from `getMeta` where the underlying driver has it
 *   (`fs`, `s3`, ...). `chmod`, `chown` and `utimes` therefore work — `cp -p`
 *   and `tar -x` need them — but a store that cannot hold that metadata does
 *   not gain the ability to; unmount and it is gone.
 *
 * ## What it does not do
 *
 * No symlinks, no hardlinks, no `statfs`, and `rename` is a copy followed by a
 * delete rather than an atomic operation. All four are declared, so the
 * transports answer `ENOSYS`/`ENOTSUP` rather than pretending.
 *
 * Costs worth knowing before mounting something remote: `readdir` lists every
 * key under the directory's prefix (there is no shallow listing in the
 * interface), and `stat` of a file falls back to fetching the value to measure
 * it when the underlying driver's `getMeta` reports no `size`.
 */

import { fsError } from "../errors.ts";
import { basename, dirname, isPathInside, normalizePath, splitPath } from "../path.ts";
import type {
  DirentLike,
  FileHandleLike,
  FsDriver,
  MkdirOptions,
  ReaddirOptions,
  StatsLike,
  TimeLike,
} from "../types.ts";
import { S_IFDIR, S_IFMT, S_IFREG } from "../types.ts";
import type { ByteHolder, OpenFlags } from "./handle.ts";
import { parseOpenFlags, resizeBytes, validatePosition, validateRange } from "./handle.ts";
import type { Storage } from "unstorage";

const BLOCK_SIZE = 4096;
const EMPTY = new Uint8Array(0);
const encoder = new TextEncoder();

/** unstorage's key separator; `normalizeKey` maps `/` onto it. */
const SEPARATOR = ":";

export interface UnstorageDriverOptions {
  /** Owner of everything in the tree. Defaults to the current process. */
  uid?: number;
  gid?: number;
  /** Permission bits reported for a file with no `chmod` applied. */
  fileMode?: number;
  /** Permission bits reported for a directory with no `chmod` applied. */
  dirMode?: number;
  /** Answer `EROFS` to everything that would write. */
  readOnly?: boolean;
}

/** What a path names, once the store has been asked. */
type Kind = "file" | "directory" | "missing";

/** Metadata the store cannot hold, kept for the life of the driver. */
interface Attributes {
  ino: number;
  mode?: number;
  uid?: number;
  gid?: number;
  atimeMs?: number;
  mtimeMs?: number;
  ctimeMs?: number;
}

/** A file's contents while something has it open. Shared by every handle on the path. */
interface OpenFile extends ByteHolder {
  path: string;
  data: Uint8Array;
  /** Open handles. The write-back happens when this reaches zero. */
  refs: number;
  dirty: boolean;
  /** Unlinked or renamed away: still readable, never written back. */
  orphan: boolean;
}

/** A copy that owns its bytes, so a later resize cannot alias what the store holds. */
const copyOf = (data: Uint8Array): Uint8Array => new Uint8Array(data);

/** `fs`-compatible timestamps are seconds or a `Date`; the store's are `Date`s. */
const toMs = (time: TimeLike): number => (typeof time === "number" ? time * 1000 : time.getTime());
const msOf = (value: unknown): number | undefined =>
  value instanceof Date ? value.getTime() : undefined;

/**
 * Whatever the store hands back, as bytes.
 *
 * `getItemRaw` returns bytes from a driver that stores bytes, a string from one
 * that stores text, and a parsed object from one that stores JSON. All three
 * have to become a file, and the last two become their text.
 */
function toBytes(value: unknown): Uint8Array {
  if (value === null || value === undefined) {
    return EMPTY;
  }
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return encoder.encode(typeof value === "string" ? value : JSON.stringify(value));
}

/**
 * Create a driver serving `storage`.
 *
 * Mount a subtree of a store by handing over `prefixStorage(storage, "base")`
 * rather than passing a base here: it is unstorage's own answer, and it keeps
 * key mapping in one place.
 */
export function createUnstorageDriver(
  storage: Storage,
  options: UnstorageDriverOptions = {},
): FsDriver {
  const uid = options.uid ?? process.getuid?.() ?? 0;
  const gid = options.gid ?? process.getgid?.() ?? 0;
  const fileMode = options.fileMode ?? 0o644;
  const dirMode = options.dirMode ?? 0o755;
  const readOnly = options.readOnly ?? false;

  /** Timestamp for anything the store cannot date. */
  const created = Date.now();
  const now = (): number => Date.now();

  let nextIno = 1;
  let nextFd = 3;

  const attributes = new Map<string, Attributes>();
  const openFiles = new Map<string, OpenFile>();
  /** Directories created but not yet holding anything — see the module docs. */
  const emptyDirectories = new Set<string>();

  // --- keys ---

  /**
   * The key a path maps to, or `EINVAL` for a name the mapping cannot survive.
   *
   * Three characters are special to unstorage and would otherwise corrupt
   * quietly: `:` *is* the separator, `?` is truncated away by `normalizeKey`
   * (`a?b` becomes `a`), and a key ending in `$` is unstorage's metadata
   * convention and is filtered out of `getKeys` — a file created with one would
   * exist and never be listed. Refusing is the only honest answer; this is the
   * single choke point where every path becomes a key, so nothing gets past it.
   */
  function keyOf(path: string, syscall: string): string {
    const segments = splitPath(path);
    for (const segment of segments) {
      if (segment.includes(SEPARATOR) || segment.includes("?") || segment.endsWith("$")) {
        throw fsError("EINVAL", {
          syscall,
          path: normalizePath(path),
          message: `Name is not representable as an unstorage key: '${segment}'`,
        });
      }
    }
    return segments.join(SEPARATOR);
  }

  /** The path a key maps back to. */
  const pathOf = (key: string): string => normalizePath(`/${key.split(SEPARATOR).join("/")}`);

  /** What `getKeys` under `base` prefixes its answers with. */
  const prefixOf = (base: string): string => (base === "" ? "" : base + SEPARATOR);

  // --- attributes ---

  function attributesOf(path: string): Attributes {
    let found = attributes.get(path);
    if (found === undefined) {
      found = { ino: nextIno++ };
      attributes.set(path, found);
    }
    return found;
  }

  /**
   * Move every per-path record for `from` and its subtree onto `to`.
   *
   * Each collection is scanned in full before any of it is rewritten: what
   * changes is the key a record is filed under, and rewriting those while
   * iterating would visit some of them twice.
   */
  function movePaths(from: string, to: string): void {
    const remap = (path: string): string => normalizePath(to + path.slice(from.length));

    function move<T>(records: Map<string, T>, moved?: (path: string, value: T) => void): void {
      const affected: [string, T][] = [];
      for (const record of records) {
        if (isPathInside(record[0], from)) {
          affected.push(record);
        }
      }
      for (const [path, value] of affected) {
        const destination = remap(path);
        records.delete(path);
        records.set(destination, value);
        moved?.(destination, value);
      }
    }

    move(openFiles, (path, entry) => {
      entry.path = path;
    });
    move(attributes);

    const directories: string[] = [];
    for (const path of emptyDirectories) {
      if (isPathInside(path, from)) {
        directories.push(path);
      }
    }
    for (const path of directories) {
      emptyDirectories.delete(path);
      emptyDirectories.add(remap(path));
    }
  }

  /** Record a modification the store cannot date by itself. */
  function touch(path: string): void {
    const found = attributesOf(path);
    found.mtimeMs = found.ctimeMs = now();
  }

  // --- resolution ---

  /**
   * What `path` names.
   *
   * A key wins over the prefix of the same name: a store holding both `a` and
   * `a:b` has no tree that represents it, and answering "file" keeps `stat`,
   * `readdir` and the `ENOTDIR` a walk through it produces all saying the same
   * thing. It is also the cheap order — `hasItem` is a point lookup and the
   * prefix test is a listing.
   */
  async function classify(path: string, syscall: string): Promise<Kind> {
    if (path === "/") {
      return "directory";
    }
    if (openFiles.has(path)) {
      return "file";
    }
    const key = keyOf(path, syscall);
    if (await storage.hasItem(key)) {
      return "file";
    }
    if (emptyDirectories.has(path)) {
      return "directory";
    }
    return (await storage.getKeys(key)).length > 0 ? "directory" : "missing";
  }

  /**
   * Classify `path`, but blame the right ancestor when the answer cannot stand
   * on its own. Returns `"missing"` rather than throwing for a path that is
   * simply not there — `open(O_CREAT)` and `rename` both need that case.
   *
   * Two things have to be checked, and both are arranged to stay off the happy
   * path:
   *
   * - **Missing** — walk down from the root to say whether this is `ENOENT` or
   *   `ENOTDIR`. Only needed here: a key exists only under prefixes, so
   *   anything that *was* found has directories above it by construction.
   * - **Found, and shadowed** — a store holding both `a` and `a:b` has no tree
   *   that represents it. `classify` calls `a` a file, so `a/b` has to be
   *   `ENOTDIR`, and testing the immediate parent is enough to make that hold
   *   at every depth: if `/a` is a key then `/a/b` answers `ENOTDIR`, which
   *   makes `/a/b` not a directory either, and so on down.
   */
  async function lookup(path: string, syscall: string): Promise<Kind> {
    const kind = await classify(path, syscall);
    if (kind === "missing") {
      await requireDirectory(dirname(path), syscall, path);
      return kind;
    }
    const parent = dirname(path);
    // Nothing can shadow the root, which is where most lookups stop.
    if (parent !== "/" && (await storage.hasItem(keyOf(parent, syscall)))) {
      throw fsError("ENOTDIR", { syscall, path });
    }
    return kind;
  }

  /** Every component of `path` must be a directory; say which one is not. */
  async function requireDirectory(path: string, syscall: string, reported: string): Promise<void> {
    let current = "";
    for (const segment of splitPath(path)) {
      current += `/${segment}`;
      const kind = await classify(current, syscall);
      if (kind !== "directory") {
        throw fsError(kind === "file" ? "ENOTDIR" : "ENOENT", {
          syscall,
          path: normalizePath(reported),
        });
      }
    }
  }

  /** Resolve to an existing file, or say why not. */
  async function resolveFile(path: string, syscall: string): Promise<void> {
    const kind = await lookup(path, syscall);
    if (kind === "missing") {
      throw fsError("ENOENT", { syscall, path });
    }
    if (kind === "directory") {
      throw fsError("EISDIR", { syscall, path });
    }
  }

  /** Does this directory hold anything at all? */
  async function hasEntries(path: string, syscall: string): Promise<boolean> {
    if ((await storage.getKeys(keyOf(path, syscall))).length > 0) {
      return true;
    }
    for (const directory of emptyDirectories) {
      if (directory !== path && isPathInside(directory, path)) {
        return true;
      }
    }
    return false;
  }

  function mutable(syscall: string, path: string): void {
    if (readOnly) {
      throw fsError("EROFS", { syscall, path: normalizePath(path) });
    }
  }

  // --- values ---

  /** The bytes at `path`. Borrowed: copy before handing them to anything that writes. */
  async function readValue(path: string, syscall: string): Promise<Uint8Array> {
    return toBytes(await storage.getItemRaw(keyOf(path, syscall)));
  }

  async function writeValue(path: string, data: Uint8Array, syscall: string): Promise<void> {
    await storage.setItemRaw(keyOf(path, syscall), copyOf(data));
    touch(path);
  }

  // --- stats ---

  function makeStats(path: string, mode: number, size: number, meta: StatsTimes): StatsLike {
    const found = attributesOf(path);
    const type = mode & S_IFMT;
    const mtimeMs = found.mtimeMs ?? msOf(meta.mtime) ?? created;
    return {
      dev: 0,
      ino: found.ino,
      mode,
      nlink: type === S_IFDIR ? 2 : 1,
      uid: found.uid ?? uid,
      gid: found.gid ?? gid,
      rdev: 0,
      size,
      blksize: BLOCK_SIZE,
      blocks: Math.ceil(size / 512),
      atimeMs: found.atimeMs ?? msOf(meta.atime) ?? mtimeMs,
      mtimeMs,
      ctimeMs: found.ctimeMs ?? msOf(meta.ctime) ?? mtimeMs,
      birthtimeMs: msOf(meta.birthtime) ?? mtimeMs,
      isFile: () => type === S_IFREG,
      isDirectory: () => type === S_IFDIR,
      isSymbolicLink: () => false,
      isBlockDevice: () => false,
      isCharacterDevice: () => false,
      isFIFO: () => false,
      isSocket: () => false,
    };
  }

  /** The timestamp fields an unstorage driver may report; all of them optional. */
  interface StatsTimes {
    atime?: unknown;
    mtime?: unknown;
    ctime?: unknown;
    birthtime?: unknown;
    size?: unknown;
  }

  /**
   * `stat` for a file. `entry` is the open buffer when there is one: while a
   * file is open that buffer *is* its contents, unflushed writes included, and
   * an orphan's are all that is left of it.
   */
  async function fileStats(
    path: string,
    syscall: string,
    entry = openFiles.get(path),
  ): Promise<StatsLike> {
    const mode = S_IFREG | (attributesOf(path).mode ?? fileMode);
    if (entry?.orphan === true) {
      return makeStats(path, mode, entry.data.byteLength, {});
    }
    // `nativeOnly` keeps this to the driver's own metadata: the other half of
    // `getMeta` is a second fetch of the `key$` item, which is unstorage's
    // user-set metadata and not something a filesystem should be paying for on
    // every `stat`.
    const meta = (await storage.getMeta(keyOf(path, syscall), { nativeOnly: true })) as StatsTimes;
    const size =
      entry?.data.byteLength ??
      (typeof meta.size === "number" ? meta.size : (await readValue(path, syscall)).byteLength);
    return makeStats(path, mode, size, meta);
  }

  function directoryStats(path: string): StatsLike {
    const mode = attributesOf(path).mode ?? dirMode;
    return makeStats(path, S_IFDIR | mode, BLOCK_SIZE, {});
  }

  async function statOf(path: string, syscall: string): Promise<StatsLike> {
    const kind = await lookup(path, syscall);
    if (kind === "missing") {
      throw fsError("ENOENT", { syscall, path });
    }
    return kind === "directory" ? directoryStats(path) : fileStats(path, syscall);
  }

  // --- open files ---

  /**
   * The shared buffer for `path`, loading it if nothing has it open.
   *
   * Two `open`s racing both miss the map and both read; whichever installs
   * first wins and the other joins it, so there is never more than one buffer
   * per path and a write through one handle is visible through the other.
   */
  async function acquire(path: string, known?: Uint8Array): Promise<OpenFile> {
    const existing = openFiles.get(path);
    if (existing !== undefined) {
      existing.refs++;
      return existing;
    }
    const data = copyOf(known ?? (await readValue(path, "open")));
    const raced = openFiles.get(path);
    if (raced !== undefined) {
      raced.refs++;
      return raced;
    }
    const entry: OpenFile = { path, data, refs: 1, dirty: false, orphan: false };
    openFiles.set(path, entry);
    return entry;
  }

  async function flush(entry: OpenFile): Promise<void> {
    if (!entry.dirty || entry.orphan) {
      return;
    }
    entry.dirty = false;
    try {
      await writeValue(entry.path, entry.data, "fsync");
    } catch (error) {
      entry.dirty = true;
      throw error;
    }
  }

  function removeClosed(entry: OpenFile): void {
    if (entry.refs === 0 && (!entry.dirty || entry.orphan) && openFiles.get(entry.path) === entry) {
      openFiles.delete(entry.path);
    }
  }

  async function release(entry: OpenFile): Promise<void> {
    entry.refs--;
    try {
      await flush(entry);
    } finally {
      // Only once nothing else holds it: the buffer *is* the file's contents
      // while it is open, and dropping it early would lose an unflushed write.
      removeClosed(entry);
    }
  }

  function createFileHandle(entry: OpenFile, flags: OpenFlags): FileHandleLike {
    let position = 0;
    let closed = false;

    function begin(syscall: string, write: boolean): void {
      if (closed || (write ? !flags.write : !flags.read)) {
        throw fsError("EBADF", { syscall, path: entry.path });
      }
    }

    return {
      fd: nextFd++,

      async read(buffer, offset, length, at) {
        begin("read", false);
        const { start, count } = validateRange(buffer, offset, length, false);
        const explicit = validatePosition(at);
        const from = explicit ?? position;
        const bytesRead = Math.max(0, Math.min(count, entry.data.byteLength - from));
        buffer.set(entry.data.subarray(from, from + bytesRead), start);
        if (explicit === undefined) {
          position += bytesRead;
        }
        return { bytesRead, buffer };
      },

      async write(buffer, offset, length, at) {
        begin("write", true);
        const { start, count } = validateRange(buffer, offset, length, true);
        const explicit = validatePosition(at);
        const from = flags.append ? entry.data.byteLength : (explicit ?? position);
        if (from + count > entry.data.byteLength) {
          resizeBytes(entry, from + count);
        }
        entry.data.set(buffer.subarray(start, start + count), from);
        if (flags.append || explicit === undefined) {
          position = from + count;
        }
        entry.dirty = true;
        touch(entry.path);
        return { bytesWritten: count, buffer };
      },

      async stat() {
        if (closed) {
          throw fsError("EBADF", { syscall: "fstat", path: entry.path });
        }
        return fileStats(entry.path, "fstat", entry);
      },

      async truncate(length = 0) {
        begin("ftruncate", true);
        resizeBytes(entry, length);
        entry.dirty = true;
        touch(entry.path);
      },

      async sync() {
        await flush(entry);
      },

      async datasync() {
        await flush(entry);
      },

      async close() {
        if (closed) {
          return;
        }
        closed = true;
        await release(entry);
      },
    };
  }

  /**
   * A directory handle. It exists because `open(2)` on a directory succeeds and
   * `read(2)` on the result is what fails; a driver that refused the `open`
   * would break `readdir` implementations that hold one open while paging.
   */
  function createDirectoryHandle(path: string): FileHandleLike {
    const reject = async (): Promise<never> => {
      throw fsError("EISDIR", { syscall: "read", path });
    };
    return {
      fd: nextFd++,
      read: reject,
      write: reject,
      truncate: reject,
      stat: async () => directoryStats(path),
      async sync() {},
      async datasync() {},
      async close() {},
    };
  }

  // --- rename ---

  /** Move one value, preserving whatever shape the store keeps it in. */
  async function moveValue(from: string, to: string): Promise<void> {
    const value = await storage.getItemRaw(keyOf(from, "rename"));
    await storage.setItemRaw(keyOf(to, "rename"), value ?? EMPTY);
    await storage.removeItem(keyOf(from, "rename"), { removeMeta: true });
  }

  // --- driver ---

  const driver: FsDriver = {
    // Only what `resolveCapabilities` cannot infer from the methods below.
    capabilities: {
      handles: true,
      // A copy and a delete, with no way to make the pair atomic through the
      // `Storage` interface.
      atomicRename: false,
      // Of the key space, which is what the paths are. A store backed by a
      // case-insensitive filesystem is the underlying driver's business.
      caseSensitive: true,
      readOnly,
    },

    async stat(path) {
      return statOf(normalizePath(path), "stat");
    },

    // No symlinks, so the two are the same call.
    async lstat(path) {
      return statOf(normalizePath(path), "lstat");
    },

    async readdir(path: string, _options: ReaddirOptions): Promise<DirentLike[]> {
      const parentPath = normalizePath(path);
      const kind = await lookup(parentPath, "scandir");
      if (kind === "missing") {
        throw fsError("ENOENT", { syscall: "scandir", path: parentPath });
      }
      if (kind === "file") {
        throw fsError("ENOTDIR", { syscall: "scandir", path: parentPath });
      }
      const base = keyOf(parentPath, "scandir");
      const prefix = prefixOf(base);

      // A key one segment past the prefix is a file; anything deeper only tells
      // us the first segment is a directory. A key that is *both* is a file,
      // for the reason in `classify`.
      const entries = new Map<string, boolean>();
      for (const key of await storage.getKeys(base)) {
        if (!key.startsWith(prefix)) {
          continue;
        }
        const relative = key.slice(prefix.length);
        if (relative === "") {
          continue;
        }
        const index = relative.indexOf(SEPARATOR);
        const name = index === -1 ? relative : relative.slice(0, index);
        if (index === -1 || !entries.has(name)) {
          entries.set(name, index !== -1);
        }
      }
      for (const directory of emptyDirectories) {
        if (dirname(directory) === parentPath && directory !== parentPath) {
          const name = basename(directory);
          if (!entries.has(name)) {
            entries.set(name, true);
          }
        }
      }

      return [...entries].map(([name, isDirectory]) => ({
        name,
        parentPath,
        isFile: () => !isDirectory,
        isDirectory: () => isDirectory,
        isSymbolicLink: () => false,
        isBlockDevice: () => false,
        isCharacterDevice: () => false,
        isFIFO: () => false,
        isSocket: () => false,
      }));
    },

    async open(path, flags = "r", mode = 0o666) {
      const resolved = normalizePath(path);
      const parsed = parseOpenFlags(flags, resolved);
      if (parsed.write || parsed.create) {
        mutable("open", resolved);
      }
      // `lookup` rather than `classify`: whether a missing file is `ENOENT` or
      // `ENOTDIR` is the parent's business either way, and it is only after
      // that that the `create` branch means anything.
      const kind = await lookup(resolved, "open");
      if (kind === "missing") {
        if (!parsed.create) {
          throw fsError("ENOENT", { syscall: "open", path: resolved });
        }
        attributesOf(resolved).mode = mode & 0o7777;
        // The file exists from here on, not from the first flush: `open(O_CREAT)`
        // is what creates it, and everything else asking has to see that.
        await writeValue(resolved, EMPTY, "open");
        return createFileHandle(await acquire(resolved, EMPTY), parsed);
      }
      if (parsed.exclusive) {
        throw fsError("EEXIST", { syscall: "open", path: resolved });
      }
      if (kind === "directory") {
        if (parsed.write) {
          throw fsError("EISDIR", { syscall: "open", path: resolved });
        }
        return createDirectoryHandle(resolved);
      }
      const entry = await acquire(resolved);
      if (parsed.truncate) {
        resizeBytes(entry, 0);
        entry.dirty = true;
        touch(resolved);
      }
      return createFileHandle(entry, parsed);
    },

    async mkdir(path, mkdirOptions: MkdirOptions = {}) {
      const resolved = normalizePath(path);
      mutable("mkdir", resolved);
      const mode = (mkdirOptions.mode ?? 0o777) & 0o7777;
      const segments = splitPath(resolved);
      if (mkdirOptions.recursive) {
        let firstCreated: string | undefined;
        let current = "";
        for (const [index, segment] of segments.entries()) {
          current += `/${segment}`;
          const kind = await classify(current, "mkdir");
          if (kind === "missing") {
            emptyDirectories.add(current);
            attributesOf(current).mode = mode;
            firstCreated ??= current;
          } else if (kind === "file") {
            // In the way at the end is EEXIST; in the way mid-path is ENOTDIR.
            const last = index === segments.length - 1;
            throw fsError(last ? "EEXIST" : "ENOTDIR", { syscall: "mkdir", path: current });
          }
        }
        return firstCreated;
      }
      if ((await lookup(resolved, "mkdir")) !== "missing") {
        throw fsError("EEXIST", { syscall: "mkdir", path: resolved });
      }
      emptyDirectories.add(resolved);
      attributesOf(resolved).mode = mode;
      return undefined;
    },

    async rmdir(path) {
      const resolved = normalizePath(path);
      mutable("rmdir", resolved);
      const kind = await lookup(resolved, "rmdir");
      if (kind === "missing") {
        throw fsError("ENOENT", { syscall: "rmdir", path: resolved });
      }
      if (kind === "file") {
        throw fsError("ENOTDIR", { syscall: "rmdir", path: resolved });
      }
      if (resolved === "/") {
        throw fsError("EBUSY", { syscall: "rmdir", path: resolved });
      }
      if (await hasEntries(resolved, "rmdir")) {
        throw fsError("ENOTEMPTY", { syscall: "rmdir", path: resolved });
      }
      emptyDirectories.delete(resolved);
      attributes.delete(resolved);
    },

    async unlink(path) {
      const resolved = normalizePath(path);
      mutable("unlink", resolved);
      const kind = await lookup(resolved, "unlink");
      if (kind === "missing") {
        throw fsError("ENOENT", { syscall: "unlink", path: resolved });
      }
      if (kind === "directory") {
        throw fsError("EISDIR", { syscall: "unlink", path: resolved });
      }
      await storage.removeItem(keyOf(resolved, "unlink"), { removeMeta: true });
      // Whoever still has it open keeps reading it, and never writes it back.
      const entry = openFiles.get(resolved);
      if (entry !== undefined) {
        entry.orphan = true;
        openFiles.delete(resolved);
      }
      attributes.delete(resolved);
    },

    async rename(oldPath, newPath) {
      const from = normalizePath(oldPath);
      const to = normalizePath(newPath);
      mutable("rename", from);
      const source = await lookup(from, "rename");
      if (source === "missing") {
        throw fsError("ENOENT", { syscall: "rename", path: from, dest: to });
      }
      if (from === to) {
        return;
      }
      const directory = source === "directory";
      if (directory && isPathInside(to, from)) {
        throw fsError("EINVAL", { syscall: "rename", path: from, dest: to });
      }
      const destination = await lookup(to, "rename");
      if (destination === "missing") {
        // Nothing to displace; `lookup` has already vouched for the parent.
      } else if (directory) {
        if (destination === "file") {
          throw fsError("ENOTDIR", { syscall: "rename", path: from, dest: to });
        }
        if (await hasEntries(to, "rename")) {
          throw fsError("ENOTEMPTY", { syscall: "rename", path: from, dest: to });
        }
      } else if (destination === "directory") {
        throw fsError("EISDIR", { syscall: "rename", path: from, dest: to });
      }

      // The replaced file's bytes stay readable to whoever had it open, and
      // must not be written back over what is arriving.
      const replaced = openFiles.get(to);
      if (replaced !== undefined) {
        replaced.orphan = true;
        openFiles.delete(to);
      }
      attributes.delete(to);
      emptyDirectories.delete(to);

      if (directory) {
        const base = keyOf(from, "rename");
        const prefix = prefixOf(base);
        for (const key of await storage.getKeys(base)) {
          if (!key.startsWith(prefix)) {
            continue;
          }
          const child = pathOf(key);
          await moveValue(child, normalizePath(to + child.slice(from.length)));
        }
        emptyDirectories.add(to);
      } else {
        await moveValue(from, to);
      }
      movePaths(from, to);
      touch(to);
    },

    async truncate(path, length = 0) {
      const resolved = normalizePath(path);
      mutable("truncate", resolved);
      await resolveFile(resolved, "truncate");
      const entry = openFiles.get(resolved);
      if (entry !== undefined) {
        // The buffer is the file's contents while it is open; the write-back
        // happens on flush like every other change made through a handle.
        resizeBytes(entry, length);
        entry.dirty = true;
        touch(entry.path);
        if (entry.refs === 0) {
          try {
            await flush(entry);
          } finally {
            removeClosed(entry);
          }
        }
        return;
      }
      const holder: ByteHolder = { data: copyOf(await readValue(resolved, "truncate")) };
      resizeBytes(holder, length);
      await writeValue(resolved, holder.data!, "truncate");
    },

    async chmod(path, mode) {
      const resolved = normalizePath(path);
      mutable("chmod", resolved);
      await statOf(resolved, "chmod");
      const found = attributesOf(resolved);
      found.mode = mode & 0o7777;
      found.ctimeMs = now();
    },

    async chown(path, ownerUid, ownerGid) {
      const resolved = normalizePath(path);
      mutable("chown", resolved);
      await statOf(resolved, "chown");
      const found = attributesOf(resolved);
      if (ownerUid >= 0) {
        found.uid = ownerUid;
      }
      if (ownerGid >= 0) {
        found.gid = ownerGid;
      }
      found.ctimeMs = now();
    },

    async utimes(path, atime, mtime) {
      const resolved = normalizePath(path);
      mutable("utime", resolved);
      await statOf(resolved, "utime");
      const found = attributesOf(resolved);
      found.atimeMs = toMs(atime);
      found.mtimeMs = toMs(mtime);
      found.ctimeMs = now();
    },
  };

  // No symlinks, so there is nothing for the `l` variants to differ about.
  driver.lchown = driver.chown;
  driver.lutimes = driver.utimes;

  return driver;
}
