/**
 * File handles and directory cookies — the two pieces of state a *stateless*
 * protocol still forces a server to keep.
 *
 * NFSv3 has no `open`, no `release` and no `FORGET`: every operation carries an
 * opaque handle of up to 64 bytes, and a client may present one it obtained an
 * hour ago, from a different process, after the server has been restarted. That
 * makes this table look like the FUSE `InodeTable` and behave quite differently:
 *
 * - **Nothing is refcounted, and nothing is ever dropped.** There is no message
 *   that says "I am done with this handle", so an entry lives as long as the
 *   server does. That is a real, bounded leak — one entry per path the client
 *   ever looked at — and it is the honest v1 tradeoff; a generation-stamped LRU
 *   is the fix if a workload ever needs one.
 * - **Handles are identity-keyed**, on the driver's `(dev, ino)`, exactly as
 *   nodeids are. That is what makes a handle survive `rename` (the file is the
 *   same file, whatever it is called now) and what makes two hardlinks one
 *   handle.
 * - **A handle whose last path is gone is `NFS3ERR_STALE`**, immediately. FUSE
 *   can keep an unlinked-but-open inode alive because the kernel told it the
 *   file is open; NFSv3 cannot, because it was never told a file was opened at
 *   all. Real clients paper over this with silly-rename (`.nfs00001234`), which
 *   is a *client*-side trick and stays out of the server.
 *
 * The handle itself is 20 bytes: a magic word, the server's boot verifier, and
 * a 64-bit entry id. The verifier is what makes a handle from a previous
 * process answer `NFS3ERR_STALE` rather than colliding with a live entry.
 */

import { randomFillSync } from "node:crypto";
import { fsError } from "../errors.ts";
import { isPathInside } from "../path.ts";
import type { StatsLike } from "../types.ts";
import { NFS3_COOKIEVERFSIZE, NFS3_FHSIZE } from "./v3/constants.ts";

/** `"UNFS"`, so a handle from something else is rejected rather than misread. */
const FH_MAGIC = 0x55_4e_46_53;
/** magic(4) + verifier(8) + id(8). Well under `NFS3_FHSIZE`. */
export const FH_SIZE = 20;
/** The root's entry id. Every table has it, bound to `/`. */
export const ROOT_HANDLE_ID = 1n;

/** One entry of the handle table: a file, and every name it answers to. */
export interface HandleEntry {
  readonly id: bigint;
  /** `${dev}:${ino}` when the driver offers a usable identity. */
  key: string | undefined;
  /** Insertion-ordered; the first is the primary path every driver call uses. */
  readonly paths: Set<string>;
}

function identityKey(stats: StatsLike): string | undefined {
  // `ino === 0` is a driver saying it has no identity to offer.
  return stats.ino > 0 ? `${stats.dev}:${stats.ino}` : undefined;
}

function stale(what: string): Error {
  return fsError("ESTALE", { message: `ESTALE: ${what}` });
}

export interface FileHandleTableOptions {
  /** Identify files by the driver's `(dev, ino)`, so hardlinks share a handle. Default `true`. */
  useDriverIno?: boolean;
  /** Boot verifier. Default: eight random bytes, so handles do not survive a restart. */
  verifier?: Uint8Array;
}

/** fh ↔ path ↔ `(dev, ino)`, for the lifetime of the server. */
export class FileHandleTable {
  readonly root: HandleEntry;
  /** The eight bytes that make this server's handles distinguishable from the last one's. */
  readonly verifier: Uint8Array;

  readonly #useDriverIno: boolean;
  readonly #byId = new Map<bigint, HandleEntry>();
  readonly #byPath = new Map<string, HandleEntry>();
  /** Only holds entries with at least one path — see {@link FileHandleTable.detachPath}. */
  readonly #byKey = new Map<string, HandleEntry>();
  #nextId = ROOT_HANDLE_ID + 1n;

  constructor(options: FileHandleTableOptions = {}) {
    this.#useDriverIno = options.useDriverIno ?? true;
    this.verifier = options.verifier ?? randomFillSync(new Uint8Array(8));
    this.root = { id: ROOT_HANDLE_ID, key: undefined, paths: new Set(["/"]) };
    this.#byId.set(ROOT_HANDLE_ID, this.root);
    this.#byPath.set("/", this.root);
  }

  /** Entries currently known. Only grows (see the module docs). */
  get size(): number {
    return this.#byId.size;
  }

  /** Paths currently mapped to an entry. */
  get pathCount(): number {
    return this.#byPath.size;
  }

  /** The wire handle for an entry. */
  encode(entry: HandleEntry): Uint8Array {
    const fh = new Uint8Array(FH_SIZE);
    const view = new DataView(fh.buffer);
    view.setUint32(0, FH_MAGIC, false);
    fh.set(this.verifier.subarray(0, 8), 4);
    view.setBigUint64(12, entry.id, false);
    return fh;
  }

  /**
   * The entry a wire handle names, or `ESTALE`.
   *
   * Every rejection is `ESTALE` rather than `EINVAL`: from a client's point of
   * view a handle it cannot use any more and a handle that was never ours are
   * the same event, and `ESTALE` is the one it knows how to recover from
   * (drop the dentry, look the name up again).
   */
  decode(fh: Uint8Array): HandleEntry {
    if (fh.byteLength !== FH_SIZE) {
      throw stale(
        fh.byteLength > NFS3_FHSIZE
          ? `file handle of ${fh.byteLength} bytes is over the protocol limit`
          : `file handle of ${fh.byteLength} bytes is not one of ours`,
      );
    }
    const view = new DataView(fh.buffer, fh.byteOffset, fh.byteLength);
    if (view.getUint32(0, false) !== FH_MAGIC) {
      throw stale("file handle has the wrong magic");
    }
    for (let index = 0; index < 8; index++) {
      if (fh[4 + index] !== this.verifier[index]) {
        throw stale("file handle is from a previous instance of this server");
      }
    }
    const entry = this.#byId.get(view.getBigUint64(12, false));
    if (entry === undefined) {
      throw stale("unknown file handle");
    }
    return entry;
  }

  get(id: bigint): HandleEntry | undefined {
    return this.#byId.get(id);
  }

  at(path: string): HandleEntry | undefined {
    return this.#byPath.get(path);
  }

  /**
   * The primary path of an entry, or `ESTALE`.
   *
   * Unlike the FUSE table this does *not* answer `ENOENT`: a path-less entry is
   * a file the client is still naming after its last link went away, which is
   * precisely what `NFS3ERR_STALE` means.
   */
  pathOf(entry: HandleEntry): string {
    for (const path of entry.paths) {
      // A path the table no longer maps to *this* entry is not this file's name
      // any more, whatever the entry still remembers. Dropping it here keeps a
      // single asymmetry between the two maps from turning into a handle that
      // silently operates on somebody else's file.
      if (this.#byPath.get(path) === entry) {
        return path;
      }
      entry.paths.delete(path);
    }
    throw stale(`file handle ${entry.id} names a file that has been removed`);
  }

  /** {@link FileHandleTable.decode} then {@link FileHandleTable.pathOf}. */
  resolve(fh: Uint8Array): string {
    return this.pathOf(this.decode(fh));
  }

  /**
   * Record that `path` currently holds the file described by `stats`, reusing
   * the entry the identity (or the path) already maps to.
   *
   * The same reasoning as `InodeTable.bind`: a different `ino` at a known path
   * means the file was replaced behind our back, and handing out the old handle
   * would alias two different files.
   */
  bind(path: string, stats: StatsLike): HandleEntry {
    const key = this.#useDriverIno ? identityKey(stats) : undefined;
    const byKey = key === undefined ? undefined : this.#byKey.get(key);
    const previous = this.#byPath.get(path);
    const sameFile = previous !== undefined && (previous.key === undefined || previous.key === key);
    let entry = byKey ?? (sameFile ? previous : undefined);

    if (entry === undefined) {
      entry = { id: this.#nextId++, key, paths: new Set() };
      this.#byId.set(entry.id, entry);
    }
    if (previous !== undefined && previous !== entry) {
      this.#detachPath(previous, path);
    }
    if (key !== undefined && entry.key === undefined) {
      entry.key = key;
    }
    this.#attachPath(entry, path);
    this.#pruneToNlink(entry, stats);
    return entry;
  }

  /**
   * Drop names an entry cannot still have.
   *
   * A file with `nlink` links has at most `nlink` names, so an entry holding
   * more than that is remembering one that went away without the server being
   * told. That is not hypothetical: with the `node:fs` passthrough, anything
   * *else* on the machine can `mv /a /c`, and a real filesystem hands the freed
   * inode number straight to the next file. Without this, binding `/c` finds
   * the old entry by identity, keeps `/a` as its primary path, and every
   * operation on the `/c` handle quietly lands on whatever `/a` is now.
   *
   * The oldest names go first — the one just bound is the one we have evidence
   * for. A driver that reports `nlink: 0` is not claiming anything, so nothing
   * is dropped.
   */
  #pruneToNlink(entry: HandleEntry, stats: StatsLike): void {
    const links = Math.trunc(stats.nlink);
    if (!Number.isFinite(links) || links < 1) {
      return;
    }
    for (const path of entry.paths) {
      if (entry.paths.size <= links) {
        return;
      }
      this.#detachPath(entry, path);
    }
  }

  /** {@link FileHandleTable.bind}, encoded. */
  handleFor(path: string, stats: StatsLike): Uint8Array {
    return this.encode(this.bind(path, stats));
  }

  /** A path stopped existing (`REMOVE`, `RMDIR`, the losing side of a `RENAME`). */
  unbind(path: string): HandleEntry | undefined {
    const entry = this.#byPath.get(path);
    if (entry !== undefined) {
      this.#detachPath(entry, path);
    }
    return entry;
  }

  /**
   * Move `from` to `to`, taking every tracked path below it along.
   *
   * This is what makes a handle survive a rename — including a handle to
   * something *inside* a renamed directory, which a client will go on using
   * with no idea anything moved.
   */
  remap(from: string, to: string): void {
    if (from !== to) {
      this.unbind(to);
      for (const path of this.#byPath.keys()) {
        if (path !== to && isPathInside(path, to)) {
          this.unbind(path);
        }
      }
    }
    const moved: { entry: HandleEntry; from: string; to: string }[] = [];
    for (const [path, entry] of this.#byPath) {
      if (isPathInside(path, from)) {
        moved.push({ entry, from: path, to: to + path.slice(from.length) });
      }
    }
    // Two passes, so a destination that is also a source is not clobbered.
    for (const move of moved) {
      this.#byPath.delete(move.from);
      move.entry.paths.delete(move.from);
    }
    for (const move of moved) {
      this.#attachPath(move.entry, move.to);
    }
  }

  /** Forget everything but the root. Teardown, and tests. */
  clear(): void {
    this.#byId.clear();
    this.#byPath.clear();
    this.#byKey.clear();
    this.root.paths.clear();
    this.root.paths.add("/");
    this.#byId.set(ROOT_HANDLE_ID, this.root);
    this.#byPath.set("/", this.root);
  }

  #attachPath(entry: HandleEntry, path: string): void {
    entry.paths.add(path);
    this.#byPath.set(path, entry);
    if (entry.key !== undefined) {
      this.#byKey.set(entry.key, entry);
    }
  }

  #detachPath(entry: HandleEntry, path: string): void {
    entry.paths.delete(path);
    this.#byPath.delete(path);
    // A path-less entry must not be found by identity again: a real filesystem
    // reuses the `ino` of a deleted file for the next one created.
    if (entry.paths.size === 0 && entry.key !== undefined && this.#byKey.get(entry.key) === entry) {
      this.#byKey.delete(entry.key);
    }
  }
}

// ---------------------------------------------------------------------------
// readdir cookies
// ---------------------------------------------------------------------------

/**
 * A directory listing, frozen so that cookies mean something.
 *
 * `fs.readdir` hands back the whole directory at once; NFS asks for a
 * byte-limited page starting at an opaque `cookie3` and expects the cookie to
 * still mean the same entry on the next call, possibly seconds later, possibly
 * from a different connection. So the listing is snapshotted, the cookie is
 * `index + 1` into that snapshot (`0` is reserved for "start"), and the
 * `cookieverf3` identifies *which* snapshot the cookie belongs to.
 *
 * The verifier is a content hash rather than a counter, which buys one useful
 * property: if the snapshot has been evicted from the cache but the directory
 * has not changed, re-listing reproduces the same verifier and the client's
 * cookies keep working. Only a client resuming into a snapshot that is both
 * evicted *and* stale gets `NFS3ERR_BAD_COOKIE`, which is exactly the case
 * where its cookies genuinely mean nothing.
 */
export interface DirSnapshot {
  /** Entry names, in driver order. Cookie `n` is `names[n - 1]`. */
  readonly names: readonly string[];
  readonly cookieverf: Uint8Array;
}

/** FNV-1a over the names, as the eight bytes of a `cookieverf3`. */
export function cookieVerifier(names: readonly string[]): Uint8Array {
  let hash = 0xcb_f2_9c_e4_84_22_23_25n;
  const prime = 0x00_00_01_00_00_00_01_b3n;
  const mask = 0xff_ff_ff_ff_ff_ff_ff_ffn;
  const bytes = new TextEncoder().encode(names.join("\0"));
  for (const byte of bytes) {
    hash = ((hash ^ BigInt(byte)) * prime) & mask;
  }
  const verf = new Uint8Array(NFS3_COOKIEVERFSIZE);
  new DataView(verf.buffer).setBigUint64(0, hash, false);
  return verf;
}

/** Are two verifiers the same eight bytes? */
export function sameVerifier(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  for (let index = 0; index < left.byteLength; index++) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

/**
 * The last N directory snapshots, keyed by handle id.
 *
 * Bounded on purpose: a server that cached every directory a client ever read
 * would be a memory leak with a `readdir` trigger. Eviction is not a
 * correctness problem — see {@link DirSnapshot}.
 */
export class DirectorySnapshots {
  readonly #entries = new Map<bigint, DirSnapshot>();
  readonly #limit: number;

  constructor(limit = 64) {
    this.#limit = Math.max(1, limit);
  }

  get size(): number {
    return this.#entries.size;
  }

  get(id: bigint): DirSnapshot | undefined {
    const snapshot = this.#entries.get(id);
    if (snapshot !== undefined) {
      // Re-insert so the Map's insertion order is an LRU order.
      this.#entries.delete(id);
      this.#entries.set(id, snapshot);
    }
    return snapshot;
  }

  set(id: bigint, names: readonly string[]): DirSnapshot {
    const snapshot: DirSnapshot = { names, cookieverf: cookieVerifier(names) };
    this.#entries.delete(id);
    this.#entries.set(id, snapshot);
    while (this.#entries.size > this.#limit) {
      const oldest = this.#entries.keys().next().value!;
      this.#entries.delete(oldest);
    }
    return snapshot;
  }

  delete(id: bigint): void {
    this.#entries.delete(id);
  }

  clear(): void {
    this.#entries.clear();
  }
}
