/**
 * The path↔inode map, and the lookup refcounting that goes with it.
 *
 * This is the real cost of a path-based driver interface (IDEA.md, "What the
 * library owns"): the kernel speaks 64-bit `nodeid`s that it expects to stay
 * valid until it says `FORGET`, and the driver speaks paths that move, vanish
 * and alias. Three facts drive the whole design:
 *
 * - **A directory rename remaps an entire subtree.** Every tracked path below
 *   the old name has to be rewritten, because the kernel keeps using the same
 *   nodeids afterwards.
 * - **An unlinked-but-open file keeps its inode with no path.** It stays
 *   reachable by nodeid (so a held file handle keeps working) until the kernel
 *   forgets it; only path-based operations answer `ENOENT`.
 * - **A hardlink is one inode with several paths.** They are identified by the
 *   driver's own `(dev, ino)`, which is also what makes `LINK` able to reply
 *   with the *existing* nodeid, as the kernel requires.
 *
 * **Everything here is synchronous.** No method awaits, so a whole mutation is
 * atomic with respect to the event loop and the session only needs a lock
 * around the read-then-await-then-mutate sequences (rename), not around the
 * table itself.
 */

import { fsError } from "../errors.ts";
import { remapSubtree, type SubtreeRemapOps } from "../subtree.ts";
import type { StatsLike } from "../types.ts";
import { FUSE_ROOT_ID } from "./constants.ts";

/**
 * One kernel-visible inode.
 *
 * `paths` is insertion-ordered and its first member is the **primary path** —
 * the one every path-based driver call uses. An empty `paths` means the inode
 * is orphaned: unlinked, but still alive because the kernel has not forgotten
 * it (and possibly still has it open).
 */
export interface Inode {
  readonly nodeid: bigint;
  /**
   * `${dev}:${ino}` from the driver's `stat`, when it reports a usable one.
   * This is what makes two hardlinked paths one inode.
   */
  key: string | undefined;
  /**
   * The kernel's lookup count. Incremented once per `LOOKUP`-shaped reply,
   * decremented by `FORGET`; the entry may only be dropped at zero — not on
   * `unlink`, not on `rmdir`.
   */
  nlookup: bigint;
  /** Every path this inode is currently reachable by. First one is primary. */
  readonly paths: Set<string>;
}

/** Nodeids are never reused, so the generation is always zero. */
export const INODE_GENERATION = 0n;

export interface InodeTableOptions {
  /**
   * Trust the driver's `(dev, ino)` to identify a file, so hardlinks collapse
   * onto one nodeid. Default `true`; a driver whose `ino` is always `0` (or
   * recycled aggressively) is handled by the `ino > 0` guard below, but can
   * also turn this off wholesale.
   */
  useDriverIno?: boolean;
}

function identityKey(stats: StatsLike): string | undefined {
  // `ino === 0` is how a driver says "I have no identity to offer" — and it is
  // also the value the kernel treats as "no inode", so it is never a real one.
  return stats.ino > 0 ? `${stats.dev}:${stats.ino}` : undefined;
}

/**
 * The inode table: nodeid → inode, path → inode, and `(dev, ino)` → inode.
 *
 * The root (`FUSE_ROOT_ID`) is created up front, bound to `/`, and never
 * dropped however many times the kernel forgets it.
 */
export class InodeTable {
  readonly root: Inode;
  private readonly useDriverIno: boolean;
  private readonly byNodeid = new Map<bigint, Inode>();
  private readonly byPath = new Map<string, Inode>();
  /** Only holds inodes with at least one path — see {@link detach}. */
  private readonly byKey = new Map<string, Inode>();
  private nextNodeid = FUSE_ROOT_ID + 1n;
  /**
   * The pair {@link InodeTable.remap} hands to `remapSubtree`. Built once
   * rather than per rename, and pointing at the same two private methods every
   * other mutation here goes through — the walk is shared, the meaning is not.
   */
  private readonly remapOps: SubtreeRemapOps<Inode> = {
    detach: (inode, path) => this.detachPath(inode, path),
    attach: (inode, path) => this.attachPath(inode, path),
  };

  constructor(options: InodeTableOptions = {}) {
    this.useDriverIno = options.useDriverIno ?? true;
    this.root = { nodeid: FUSE_ROOT_ID, key: undefined, nlookup: 1n, paths: new Set(["/"]) };
    this.byNodeid.set(FUSE_ROOT_ID, this.root);
    this.byPath.set("/", this.root);
  }

  /** Inodes the kernel could still name. */
  get size(): number {
    return this.byNodeid.size;
  }

  /** Paths currently mapped to an inode. */
  get pathCount(): number {
    return this.byPath.size;
  }

  get(nodeid: bigint): Inode | undefined {
    return this.byNodeid.get(nodeid);
  }

  /** The inode for a nodeid, or `ESTALE` — the kernel is naming a ghost. */
  require(nodeid: bigint): Inode {
    const inode = this.byNodeid.get(nodeid);
    if (inode === undefined) {
      throw fsError("ESTALE", { syscall: "lookup", message: `ESTALE: unknown nodeid ${nodeid}` });
    }
    return inode;
  }

  at(path: string): Inode | undefined {
    return this.byPath.get(path);
  }

  /** The primary path of an inode, or `ENOENT` if it has been unlinked. */
  pathOf(inode: Inode): string {
    const path = inode.paths.values().next().value;
    if (path === undefined) {
      throw fsError("ENOENT", { message: `ENOENT: nodeid ${inode.nodeid} has been unlinked` });
    }
    return path;
  }

  /** {@link require} then {@link pathOf}. */
  requirePath(nodeid: bigint): string {
    return this.pathOf(this.require(nodeid));
  }

  /**
   * Record that `path` currently holds the file described by `stats`, and
   * return the inode for it — reusing the existing one when the identity or
   * the path already maps to one.
   *
   * Does **not** touch `nlookup`: only a reply that hands the nodeid to the
   * kernel does that, via {@link acquire}.
   */
  bind(path: string, stats: StatsLike): Inode {
    const key = this.useDriverIno ? identityKey(stats) : undefined;
    const byKey = key === undefined ? undefined : this.byKey.get(key);
    const previous = this.byPath.get(path);
    // The path's old inode is only the same file if its identity does not say
    // otherwise. A different `ino` at the same path means the file was replaced
    // behind our back, and handing the kernel's existing nodeid to the
    // replacement would alias two different files — the exact bug identities
    // exist to prevent. An inode with no identity at all (a driver reporting
    // `ino: 0`) has nothing to contradict, so the path stands in for it.
    const sameFile = previous !== undefined && (previous.key === undefined || previous.key === key);
    let inode = byKey ?? (sameFile ? previous : undefined);

    if (inode === undefined) {
      inode = { nodeid: this.nextNodeid++, key, nlookup: 0n, paths: new Set() };
      this.byNodeid.set(inode.nodeid, inode);
    }
    if (previous !== undefined && previous !== inode) {
      // The old inode keeps its nodeid and its other paths; it just no longer
      // answers to this one, and is orphaned if that was its last.
      this.detachPath(previous, path);
    }

    // Adopting an identity, never swapping one: an inode found by key already
    // has it, an inode found by path only survived the `sameFile` test above
    // because it had none, and a fresh one was born with it.
    if (key !== undefined && inode.key === undefined) {
      inode.key = key;
    }
    this.attachPath(inode, path);
    return inode;
  }

  /** Hand this nodeid to the kernel: one more lookup to be forgotten later. */
  acquire(inode: Inode): Inode {
    inode.nlookup += 1n;
    return inode;
  }

  /**
   * `FORGET` / `BATCH_FORGET`: drop `count` lookups, and the whole entry when
   * the count reaches zero. The root is never dropped.
   *
   * Returns `true` if the inode went away.
   */
  forget(nodeid: bigint, count: bigint): boolean {
    const inode = this.byNodeid.get(nodeid);
    if (inode === undefined || inode === this.root) {
      return false;
    }
    inode.nlookup -= count > 0n ? count : 0n;
    if (inode.nlookup > 0n) {
      return false;
    }
    for (const path of inode.paths) {
      this.byPath.delete(path);
    }
    inode.paths.clear();
    this.releaseKey(inode);
    this.byNodeid.delete(nodeid);
    return true;
  }

  /**
   * A path stopped existing (`unlink`, `rmdir`, or the losing side of a
   * `rename`). The inode survives — with one fewer name, and orphaned if that
   * was its last — until the kernel forgets it.
   */
  unbind(path: string): Inode | undefined {
    const inode = this.byPath.get(path);
    if (inode !== undefined) {
      this.detachPath(inode, path);
    }
    return inode;
  }

  /**
   * Move `from` to `to`, taking every tracked path below it along.
   *
   * The subtree walk is what makes `rename` of a directory correct: the kernel
   * goes on using the nodeids it already has for everything underneath, and
   * every one of them must resolve to its new path afterwards.
   *
   * The walk itself is `src/subtree.ts`'s — the same one `FileHandleTable` and
   * `FidTable` do — driven by *this* table's {@link InodeTable.detachPath} and
   * {@link InodeTable.attachPath}, so what a replaced destination means here is
   * unchanged: the orphan keeps its nodeid and stays reachable until the kernel
   * forgets it. It costs two full scans of the path map per rename, i.e.
   * O(tracked paths) rather than O(subtree); see that module for why a prefix
   * tree is the fix and why it is a benchmark-milestone concern, not a v1 one.
   */
  remap(from: string, to: string): void {
    remapSubtree(this.byPath, from, to, this.remapOps);
  }

  /** Every nodeid currently known, for teardown and tests. */
  nodeids(): bigint[] {
    return [...this.byNodeid.keys()];
  }

  clear(): void {
    this.byNodeid.clear();
    this.byPath.clear();
    this.byKey.clear();
    this.byNodeid.set(FUSE_ROOT_ID, this.root);
    this.root.paths.clear();
    this.root.paths.add("/");
    this.byPath.set("/", this.root);
  }

  private attachPath(inode: Inode, path: string): void {
    inode.paths.add(path);
    this.byPath.set(path, inode);
    if (inode.key !== undefined) {
      this.byKey.set(inode.key, inode);
    }
  }

  private detachPath(inode: Inode, path: string): void {
    inode.paths.delete(path);
    this.byPath.delete(path);
    // An orphan must not be found by identity again: a driver over a real
    // filesystem will happily reuse the `ino` of a deleted file for the next
    // one created, and resurrecting the orphan would alias two different files.
    if (inode.paths.size === 0) {
      this.releaseKey(inode);
    }
  }

  /**
   * Give up an identity — but only if this inode still owns it.
   *
   * By the time an orphan is finally forgotten, a *different* live inode may
   * already hold its `(dev, ino)`: real filesystems reuse an inode number the
   * moment the old file is deleted. Deleting unconditionally would strip the
   * new inode of its identity, and the next `bind` would hand out a second
   * nodeid for a file that already has one — which is exactly the invariant
   * `LINK` depends on to reply with the existing nodeid.
   */
  private releaseKey(inode: Inode): void {
    if (inode.key !== undefined && this.byKey.get(inode.key) === inode) {
      this.byKey.delete(inode.key);
    }
  }
}
