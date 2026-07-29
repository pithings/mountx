/**
 * The path-keyed subtree rewrite a `rename` forces on every transport's table.
 *
 * All three transports keep a path → entry map that outlives the paths in it:
 * the FUSE `InodeTable` (`nodeid` → path), the NFS `FileHandleTable` (file
 * handle → path) and the 9P `FidTable` (`qid.path` → path). All three face the
 * same problem when a directory is renamed — the client goes on using the
 * nodeids, handles and fids it already holds, with no idea anything moved, so
 * every tracked path at or under the old name has to be rewritten — and all
 * three had grown their own character-identical copy of the answer. This is
 * that answer, once.
 *
 * ## What is shared, and what is deliberately not
 *
 * The *walk* is shared: which paths are affected, in what order, and the
 * two-pass rewrite that keeps a destination which is also a source from being
 * clobbered. What each table does to an entry is **not**, and must not be — the
 * three detach behaviours are three different meanings:
 *
 * - FUSE keeps the orphan reachable by nodeid, for a later `FORGET`.
 * - NFS drops the identity key *and* the entry id, so the handle answers
 *   `ESTALE` from `decode()` (the root is exempt).
 * - 9P releases the qid identity outright.
 *
 * So {@link remapSubtree} takes the table's own `detach`/`attach` pair rather
 * than reimplementing either. Each table already had exactly that pair as a
 * private method before this module existed; nothing about their semantics
 * changed by moving the walk out from between them.
 *
 * ## Cost
 *
 * **Two full scans of the map per rename**, plus two passes over the entries
 * that actually moved: one scan to detach everything under the destination
 * (skipped when `from === to`), one to collect everything under the source.
 * It is O(tracked paths), not O(subtree) — so a `tar -x` that leaves ~100k
 * paths cached makes every later `mv` walk 200k entries, and the FUSE session
 * runs this under `PathLock.write`, where it blocks every path-resolving
 * request for the duration.
 *
 * A prefix tree over the path map is the fix, and it is a
 * benchmark-milestone concern rather than a v1 one. It is also the reason this
 * module exists at all: written once, it can be *replaced* once, and all three
 * transports get it.
 *
 * **Everything here is synchronous**, like the tables it serves: a whole
 * rewrite is atomic against the event loop, and the sessions need `PathLock`
 * only around their read-then-await-then-mutate rename sequences, not around
 * the table.
 */

import { isPathInside } from "./path.ts";

/**
 * The one thing the three tables' entries have in common: every name the entry
 * currently answers to, insertion-ordered, first one primary.
 */
export interface PathBound {
  readonly paths: Set<string>;
}

/** The table's own per-path primitives, which {@link remapSubtree} drives. */
export interface SubtreeRemapOps<T extends PathBound> {
  /**
   * `path` stopped naming `value` — it was under the rename's destination, so
   * whatever lived there has just been replaced.
   *
   * This is the table's existing "a path went away" primitive, unchanged: it is
   * where the three transports' behaviours differ (see the module docs), and
   * flattening them into one would be a bug rather than a simplification.
   */
  detach(value: T, path: string): void;
  /**
   * `value` now also answers to `path`. The table's existing primitive again —
   * it is what re-files `paths`, the path map and any identity map.
   */
  attach(value: T, path: string): void;
}

/**
 * `from` was renamed to `to`: rewrite every tracked path at or under it, and
 * detach every tracked path at or under the destination it replaced.
 *
 * `byPath` is mutated in place, through `ops` for the two ends and directly for
 * the removal in between. See the module docs for the cost and for why `ops`
 * is a parameter rather than an implementation.
 */
export function remapSubtree<T extends PathBound>(
  byPath: Map<string, T>,
  from: string,
  to: string,
  ops: SubtreeRemapOps<T>,
): void {
  // Whatever used to live at the destination has just been replaced. Deleting
  // the current key mid-iteration is well defined for a Map, and detaching one
  // path never touches another one's entry in it.
  if (from !== to) {
    for (const [path, value] of byPath) {
      if (isPathInside(path, to)) {
        ops.detach(value, path);
      }
    }
  }
  const moved: { value: T; from: string; to: string }[] = [];
  for (const [path, value] of byPath) {
    if (isPathInside(path, from)) {
      moved.push({ value, from: path, to: to + path.slice(from.length) });
    }
  }
  // Two passes: a one-pass rewrite would clobber a destination that is also a
  // source (`mv a b` inside the same subtree). The removal here is deliberately
  // *not* `ops.detach` — these paths are moving, not going away, so an entry
  // must not lose an identity it is about to be re-attached under.
  for (const move of moved) {
    byPath.delete(move.from);
    move.value.paths.delete(move.from);
  }
  for (const move of moved) {
    ops.attach(move.value, move.to);
  }
}
