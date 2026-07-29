/**
 * The fid table: what a *stateful* protocol makes the server remember.
 *
 * A fid is a 32-bit name the **client** chooses for a path it has walked to,
 * and it is the one thing 9P has that NFSv3 does not: the client says
 * `Tlopen`, gets a fid it may read and write, and says `Tclunk` when it is
 * done. That buys the three properties the plan picked 9P over NFS for — no
 * `ESTALE`, a real close so a handle-buffering driver flushes, and a table
 * that shrinks again — and it costs exactly this file.
 *
 * The shape is `src/fuse/inodes.ts`'s, with three differences that all come
 * from who owns the numbering:
 *
 * - **The client picks the number, so it can pick a live one.** A nodeid is
 *   ours to allocate and can never collide; a fid arrives off the wire, and
 *   `Twalk`/`Tattach` naming a fid that is already in use is a protocol
 *   violation the server must refuse rather than quietly rebind (the 9P2000
 *   name for it is `EDUPFID`; .L has no error strings, so it goes out as an
 *   errno like everything else). {@link P9_NOFID} is a sentinel, never a key.
 * - **A fid is released explicitly**, by `Tclunk` or `Tremove`, and exactly
 *   once. So {@link FidTable.clunk} is deliberately *not* idempotent: a second
 *   clunk of the same fid means the client's own bookkeeping is broken, and
 *   answering it cheerfully would hide that while risking a double `close()`
 *   on the driver handle.
 * - **There is no `FORGET` and no refcount.** The lifetime is the client's,
 *   which is why nothing here is reference counted the way an inode is.
 *
 * What this module does *not* do: read directories, stat paths, open handles,
 * or resolve a walk. All of those need the driver, and the driver is the
 * session's. This file only holds what the session hands it, and it holds all
 * of it **synchronously** — no method awaits, so a whole mutation is atomic
 * against the event loop and only the read-then-await-then-mutate sequences
 * (rename) need `PathLock`, not the table.
 */

import { fsError } from "../errors.ts";
import { isPathInside, joinPath } from "../path.ts";
import { remapSubtree, type SubtreeRemapOps } from "../subtree.ts";
import {
  S_IFDIR,
  S_IFLNK,
  S_IFMT,
  type DirentLike,
  type FileHandleLike,
  type StatsLike,
} from "../types.ts";
import { P9_NOFID, P9_QTDIR, P9_QTFILE, P9_QTSYMLINK } from "./constants.ts";
import type { P9Qid } from "./wire.ts";

/** One past the largest fid a client may use; {@link P9_NOFID} itself. */
const FID_LIMIT = P9_NOFID;

/**
 * The first `qid.path` a table hands out. They are allocated upward from here
 * and never reused, exactly as `InodeTable` allocates nodeids.
 */
export const FIRST_QID_PATH = 1n;

/**
 * The driver's identity for a file, or `undefined` if it has none to offer.
 *
 * The **pair** is the identity, not the `ino` alone: `ino` is only unique
 * within a device, and a driver that spans two (the `node:fs` passthrough over
 * a tree with a mount in it, most obviously) will report the same `ino` for two
 * unrelated files. v9fs keys its inode cache on `qid.path`, so collapsing them
 * would serve one file's cached pages for the other. `src/fuse/inodes.ts` and
 * `src/nfs/handles.ts` build the same `${dev}:${ino}` key for the same reason.
 *
 * `ino === 0` is how a driver says it has no identity to offer — and it is also
 * the value the kernel treats as "no inode", so it is never a real one.
 */
function identityKey(stats: StatsLike): string | undefined {
  return Number.isFinite(stats.ino) && stats.ino > 0 ? `${stats.dev}:${stats.ino}` : undefined;
}

/**
 * One file, as the client's inode cache sees it.
 *
 * The `id` is **always ours**, never the driver's `ino`. Two reasons, both
 * fatal to the obvious shortcut of putting the `ino` straight on the wire:
 * an `ino` is only unique per device (see {@link identityKey}), and it arrives
 * as a JS `number`, where 2^53 is merely the last *exactly representable*
 * integer and nothing stops a driver reporting more — so no fixed base can
 * carve a collision-free range for synthesized values out of the same u64.
 * Allocating every id from one counter makes the question moot.
 *
 * `paths` is every name currently bound to this identity; a hardlink has more
 * than one. When the last goes, so does the identity — see
 * {@link FidTable.release}.
 */
interface QidIdentity {
  /** The u64 that goes out as `qid.path`. Allocated once, never reused. */
  readonly id: bigint;
  /** `${dev}:${ino}` when the driver offers one. */
  key: string | undefined;
  /** Every path bound to it. */
  readonly paths: Set<string>;
}

/**
 * What a fid's `Tlopen`/`Tlcreate` left behind.
 *
 * Mirrors `src/fuse/session.ts`'s `OpenFile`, including the distinction that
 * matters most: `handle === undefined` is **not** "unopened". An unopened fid
 * has no {@link FidOpenState} at all. A fid with a state and no handle is one
 * opened against a driver that does not declare `handles`, where every
 * operation re-opens from the path — so the flags it was opened with have to
 * survive here for that re-open to repeat them.
 */
export interface FidOpenState {
  /**
   * The `O_*` flags a **re-open** of this fid uses, in the *driver's*
   * namespace: `driverOpenFlags()` then `reopenFlags()`. The wire's flags are
   * the Linux kernel's and are a different namespace (see the invariant in
   * AGENTS.md); nothing downstream of this field may treat them as the same.
   */
  flags: number;
  /**
   * Real per-open driver state, or `undefined` when the driver declares no
   * `handles` and the session re-opens per operation.
   */
  handle: FileHandleLike | undefined;
  /**
   * `Tlopen` opened a directory, so `Treaddir` is legal on this fid and `Tread`
   * is not. The session enforces it; the table only remembers which it was.
   */
  directory: boolean;
  /**
   * The qid this fid was opened on, pinned for the life of the open.
   *
   * An open fid names a *file*, and it keeps naming it after its path stops
   * resolving — the whole point of a stateful open. So when the session has to
   * answer a `Tgetattr` the path can no longer answer (an unlinked file being
   * read through the fid that holds it open), the identity in the reply comes
   * from here rather than from {@link FidTable.qidFor}: re-deriving one would
   * mean *binding* an identity to a path that no longer exists, undoing the
   * {@link FidTable.release} that removal performed and letting the next file
   * created at that name inherit the dead one's `qid.path`.
   *
   * Only `type` and `path` are read from it. `version` is a change token rather
   * than an identity — it is the file's mtime — so it is recomputed from
   * whatever attributes the reply carries, and a client's cache check still
   * sees writes. `type` is safe to pin because nothing turns a file into a
   * directory.
   *
   * `undefined` only for a state built by hand: every one this session creates
   * carries the qid its `Tlopen`/`Tlcreate` already computed, and a state
   * without one simply falls back to the path, as before.
   */
  qid?: P9Qid;
}

/**
 * A directory listing frozen for the lifetime of one paging run.
 *
 * `fs.readdir` returns the whole directory at once and `Treaddir` asks for a
 * byte-limited page, so the listing is snapshotted and the offsets the server
 * hands out index into that snapshot. Unlike NFS's cookies these never outlive
 * the fid: an offset is only meaningful to the fid it was handed to, and a
 * clunk takes the whole cursor with it.
 */
export interface DirCursor<TDirent> {
  /** The listing being paged over, exactly as the session handed it in. */
  readonly entries: readonly TDirent[];
  /**
   * Every offset this fid has handed the client → the index a resume from it
   * starts at. Populated by {@link FidTable.noteOffset}, one entry per dirent
   * packed, because a client may resume from *any* entry it was shown, not
   * only from the last one of a page.
   */
  readonly offsets: Map<bigint, number>;
}

/** Where a `Treaddir` resumes: the snapshot, and the index into it. */
export interface DirResume<TDirent> {
  readonly entries: readonly TDirent[];
  readonly index: number;
}

/** One live fid. */
export interface Fid<TDirent = DirentLike> {
  /** The client's number. Immutable — a fid is never renumbered, only cloned. */
  readonly fid: number;
  /**
   * Absolute and normalized. Assigning it is how a walk moves the fid, and how
   * {@link FidTable.remap} follows a rename; both go through the setter, which
   * normalizes and **drops any readdir cursor** — see {@link Fid.cursor}.
   */
  path: string;
  /** `undefined` until `Tlopen`/`Tlcreate`; see {@link FidOpenState}. */
  open: FidOpenState | undefined;
  /**
   * The `iounit` reported by `Rlopen`/`Rlcreate` — the largest I/O the client
   * should send in one message. `0` is the protocol's "no opinion, use msize",
   * and is what an unopened fid carries.
   */
  iounit: number;
  /**
   * Paging state, taken on the first `Treaddir` and re-taken at offset 0.
   *
   * It belongs to the *directory the fid named when the snapshot was taken*,
   * which is why {@link Fid.path} throws it away when it changes: an in-place
   * walk (`Twalk` with `newfid == fid`) leaves the fid pointing somewhere else
   * entirely, and resuming an old offset would page the previous directory's
   * listing under the new directory's name. A rename of the directory being
   * read drops it too, which costs the client a restart of that one `readdir`
   * — the conservative side of a race no path-based server can resolve, and
   * cheap next to serving it entries that are no longer there.
   */
  cursor: DirCursor<TDirent> | undefined;
}

/**
 * The concrete entry.
 *
 * Only exists so {@link Fid.path} can be an accessor: cursor invalidation has
 * to be impossible to forget, and a plain mutable field on an object literal
 * would leave every future call site responsible for remembering it.
 */
class FidEntry<TDirent> implements Fid<TDirent> {
  readonly fid: number;
  open: FidOpenState | undefined = undefined;
  iounit = 0;
  cursor: DirCursor<TDirent> | undefined = undefined;
  #path: string;

  constructor(fid: number, path: string) {
    this.fid = fid;
    this.#path = joinPath(path);
  }

  get path(): string {
    return this.#path;
  }

  set path(next: string) {
    const normalized = joinPath(next);
    if (normalized !== this.#path) {
      this.#path = normalized;
      this.cursor = undefined;
    }
  }
}

export interface FidTableOptions {
  /**
   * Trust the driver's `(dev, ino)` to identify a file, so two hardlinks are
   * one file to the client. Default `true`; `src/fuse/inodes.ts` takes the same
   * option for the same reason, and a driver reporting `ino: 0` is handled by
   * the `> 0` guard in {@link identityKey} either way.
   *
   * It selects the *key*, never the number: `qid.path` is allocated here in
   * both settings (see {@link QidIdentity}). With the option off, identity is
   * per path — the same file under two names looks like two files, which is
   * the honest answer when the driver cannot say otherwise.
   */
  useDriverIno?: boolean;
}

function badFid(fid: number, why: string): Error {
  return fsError("EBADF", { message: `EBADF: fid ${fid} ${why}` });
}

/** The type bits of a qid: the top byte of the old 9P permission word. */
export function qidType(mode: number): number {
  switch (mode & S_IFMT) {
    case S_IFDIR: {
      return P9_QTDIR;
    }
    case S_IFLNK: {
      return P9_QTSYMLINK;
    }
    default: {
      // Devices, FIFOs and sockets are all `QTFILE` on the wire: 9P2000.L
      // reports their real type through `Rgetattr`'s mode, and the qid type
      // byte has no bit for any of them.
      return P9_QTFILE;
    }
  }
}

/**
 * The `qid.version` for a file: its modification time, truncated to 32 bits.
 *
 * The client caches page and dentry data against `(qid.path, qid.version)` and
 * throws that cache away the moment the version it is shown differs from the
 * one it cached — that, and nothing else, is what the field is for. So the only
 * requirement is that it *changes* when the file does, which mtime satisfies.
 *
 * Two caveats worth knowing rather than papering over. Millisecond granularity
 * means two writes inside the same millisecond share a version, so a client
 * may serve one from cache; a driver with a coarser clock widens that window,
 * and the fix if it ever bites is a per-path counter, not a finer clock we do
 * not have. And a version of `0` — which an epoch mtime produces — is the
 * protocol's "do not cache this", so a driver with no clock at all degrades to
 * a correct, uncached mount rather than a stale one.
 */
export function qidVersion(stats: StatsLike): number {
  const ms = stats.mtimeMs;
  if (!Number.isFinite(ms) || ms <= 0) {
    return 0;
  }
  return Math.trunc(ms) >>> 0;
}

/**
 * fid → path, open state, and paging state, for the life of one connection.
 *
 * `TDirent` is whatever the session snapshots a directory as — a `DirentLike[]`
 * by default, but the table never looks inside it, so a session that finds it
 * cheaper to snapshot pre-packed entries can say so.
 */
export class FidTable<TDirent = DirentLike> {
  readonly #useDriverIno: boolean;
  readonly #fids = new Map<number, FidEntry<TDirent>>();
  /** path → the identity currently bound to it. */
  readonly #qidByPath = new Map<string, QidIdentity>();
  /** `${dev}:${ino}` → identity. Only holds identities with at least one path. */
  readonly #qidByKey = new Map<string, QidIdentity>();
  #nextQidPath = FIRST_QID_PATH;
  /**
   * The pair {@link FidTable.remap} hands to `remapSubtree`. Built once rather
   * than per rename, and pointing at the same two private methods every other
   * qid mutation here goes through — the walk is shared, the meaning is not.
   */
  readonly #remapOps: SubtreeRemapOps<QidIdentity> = {
    detach: (identity, path) => this.#detachQid(identity, path),
    attach: (identity, path) => this.#attachQid(identity, path),
  };

  constructor(options: FidTableOptions = {}) {
    this.#useDriverIno = options.useDriverIno ?? true;
  }

  /** Live fids — a count that comes back down, unlike an NFS handle table's. */
  get size(): number {
    return this.#fids.size;
  }

  /** Paths currently holding a `qid.path`. Falls again on {@link FidTable.release}. */
  get qidPathCount(): number {
    return this.#qidByPath.size;
  }

  get(fid: number): Fid<TDirent> | undefined {
    return this.#fids.get(fid);
  }

  /**
   * The entry a fid names, or `EBADF`.
   *
   * `EBADF` rather than `ESTALE`: a fid is not a handle that can go out of
   * date, it is a number this connection either issued or did not, so a fid we
   * do not know is a client bug and the Linux errno for using a descriptor
   * that is not one is `EBADF`. {@link P9_NOFID} lands here too — it is a
   * sentinel meaning "no fid at all", so it can never be in the table.
   */
  require(fid: number): Fid<TDirent> {
    const entry = this.#fids.get(fid);
    if (entry === undefined) {
      throw badFid(fid, fid === P9_NOFID ? "is P9_NOFID, which names nothing" : "is not in use");
    }
    return entry;
  }

  /**
   * Take a fid the client has chosen, bound to `path`.
   *
   * Refuses a fid that is already in use. The kernel never does this — it
   * allocates fids from its own IDR and clunks before reusing — so a duplicate
   * is either a broken client or a desynced stream, and rebinding it would
   * strand whatever the old fid had open with no way left to clunk it.
   */
  create(fid: number, path: string): Fid<TDirent> {
    if (!Number.isInteger(fid) || fid < 0 || fid >= FID_LIMIT) {
      throw fsError("EINVAL", {
        message:
          fid === P9_NOFID
            ? "EINVAL: P9_NOFID cannot be used as a fid"
            : `EINVAL: ${fid} is not a valid fid`,
      });
    }
    if (this.#fids.has(fid)) {
      throw fsError("EINVAL", { message: `EINVAL: fid ${fid} is already in use` });
    }
    const entry = new FidEntry<TDirent>(fid, path);
    this.#fids.set(fid, entry);
    return entry;
  }

  /**
   * `Twalk`'s clone: `to` starts out naming whatever `from` names.
   *
   * **Open state is not cloned**, and that is the protocol's rule rather than
   * a simplification: a newfid "represents the same file" but is not open, so
   * the client must `Tlopen` it before reading. Cloning the handle would hand
   * two fids one `FileHandleLike` and make the first `Tclunk` close the file
   * out from under the second.
   *
   * `to === from` is the in-place walk (`newfid == fid`), which is legal and
   * changes nothing here — the session rewrites {@link Fid.path} itself once
   * every name has resolved, so a walk that fails part-way leaves the fid
   * exactly as it was, as `Rwalk`'s partial-walk semantics require.
   */
  clone(from: number, to: number): Fid<TDirent> {
    const source = this.require(from);
    if (to === from) {
      return source;
    }
    return this.create(to, source.path);
  }

  /**
   * `Tclunk` / `Tremove`: drop the fid and hand back what it had open, so the
   * session closes the driver handle exactly once.
   *
   * Not idempotent, and not forgiving: see the module docs. The entry is
   * removed *before* the caller can fail closing it, for the same reason
   * `RELEASE` frees first in the FUSE session — a fid the client has clunked
   * is gone whatever the driver thinks, and leaving it behind would let a
   * second clunk close the handle twice.
   */
  clunk(fid: number): Fid<TDirent> {
    const entry = this.require(fid);
    this.#fids.delete(fid);
    return entry;
  }

  // -------------------------------------------------------------------------
  // readdir paging
  // -------------------------------------------------------------------------

  /**
   * Resolve a `Treaddir` offset against this fid's cursor.
   *
   * - `0` **drops the cursor** and answers `undefined`: it is the client
   *   rewinding, and a rewind must re-list the directory rather than replay a
   *   snapshot that may be minutes old. The session reads the directory and
   *   calls {@link FidTable.snapshot}. It is also the only way a `Treaddir` run
   *   ever starts.
   *
   *   Dropping is unconditional, and that is the point: the session's re-list
   *   can *fail* (the driver's `readdir` rejects and the client gets an
   *   `Rlerror`), and if the old snapshot were still here the client could then
   *   present an offset from before the rewind and be served the listing it
   *   just rewound past. A rewind invalidates the old offsets whether or not
   *   anything replaces them.
   * - Any other offset must be one *this fid* handed out since its last
   *   snapshot. Unlike FUSE's readdir offsets, these are opaque cookies rather
   *   than indices, so one from a different fid, or from before a rewind,
   *   indexes a listing that no longer exists; guessing at it would silently
   *   skip or repeat files, where `EINVAL` makes the client start over.
   */
  resume(entry: Fid<TDirent>, offset: bigint): DirResume<TDirent> | undefined {
    if (offset === 0n) {
      entry.cursor = undefined;
      return undefined;
    }
    const cursor = entry.cursor;
    const index = cursor?.offsets.get(offset);
    if (cursor === undefined || index === undefined) {
      throw fsError("EINVAL", {
        message: `EINVAL: fid ${entry.fid} was never given readdir offset ${offset}`,
      });
    }
    return { entries: cursor.entries, index };
  }

  /**
   * Freeze a listing for this fid and start paging at its first entry.
   *
   * Whatever the session hands in is stored as-is; the table neither reads
   * directories nor inspects entries. Any offsets from a previous run go with
   * the old snapshot, because they index a listing that no longer exists.
   */
  snapshot(entry: Fid<TDirent>, entries: readonly TDirent[]): DirResume<TDirent> {
    entry.cursor = { entries, offsets: new Map() };
    return { entries, index: 0 };
  }

  /**
   * Record that `offset` — the cookie just written into a packed dirent —
   * resumes at `index` in the current snapshot.
   *
   * Called once per entry packed. `0` is never recorded: it is reserved for
   * "start over", and accepting it as a resume point would make a rewind
   * indistinguishable from a resume at the first entry.
   */
  noteOffset(entry: Fid<TDirent>, offset: bigint, index: number): void {
    if (offset !== 0n) {
      entry.cursor?.offsets.set(offset, index);
    }
  }

  // -------------------------------------------------------------------------
  // qids
  // -------------------------------------------------------------------------

  /**
   * The qid for a file: what the client uses as its inode identity.
   *
   * This is `InodeTable.bind` with the refcounting taken out. The `path` field
   * is an id of ours, allocated once per file and memoized under two keys: the
   * driver's `(dev, ino)` when there is one to trust, and the path always. The
   * identity key is what makes two hardlinks one file to the client, and what
   * makes an id survive a rename the server never hears about; the path
   * binding is what lets a driver with no `ino` at all still answer the same
   * qid for the same file every time. A client that saw two qid paths for one
   * file would cache it twice; one that saw a single qid path for two files
   * would serve one's pages for the other, which is the worse half and the
   * reason the key is the *pair* and never the `ino` alone.
   *
   * As in `InodeTable`, a path whose identity has *changed* gets a new id
   * rather than the old one: a different `(dev, ino)` at a known path means the
   * file was replaced behind our back, and handing out the id the client
   * already has would alias the replacement onto the original.
   *
   * **Across a rename** the id survives either way — the identity key does not
   * change, and the path binding is carried to the new name by
   * {@link FidTable.remap}. That matters because the client keeps using the
   * dentry it already has, and a qid path that changed under a rename would
   * look like a different file appearing at the new name.
   */
  qidFor(stats: StatsLike, path: string): P9Qid {
    return {
      type: qidType(stats.mode),
      version: qidVersion(stats),
      path: this.qidPathFor(stats, path),
    };
  }

  /** The u64 identity {@link FidTable.qidFor} puts in a qid. */
  qidPathFor(stats: StatsLike, path: string): bigint {
    const key = this.#useDriverIno ? identityKey(stats) : undefined;
    const byKey = key === undefined ? undefined : this.#qidByKey.get(key);
    const previous = this.#qidByPath.get(path);
    // An identity with no key of its own has nothing to contradict the path, so
    // the path stands in for it; one with a *different* key is a different file.
    const sameFile = previous !== undefined && (previous.key === undefined || previous.key === key);
    let identity = byKey ?? (sameFile ? previous : undefined);

    if (identity === undefined) {
      identity = { id: this.#nextQidPath++, key, paths: new Set() };
    }
    if (previous !== undefined && previous !== identity) {
      this.#detachQid(previous, path);
    }
    // Adopting a key, never swapping one — the same reasoning as `InodeTable`:
    // an identity found by key already has it, one found by path only survived
    // `sameFile` because it had none, and a fresh one was born with it.
    if (key !== undefined && identity.key === undefined) {
      identity.key = key;
    }
    this.#attachQid(identity, path);
    return identity.id;
  }

  /**
   * A path stopped existing (`Tremove`, `Tunlinkat`, the losing side of a
   * rename): forget the identity bound to it.
   *
   * Without this the memo would only ever grow — one entry per path the client
   * ever touched, for the life of the connection — and, worse, a path that is
   * removed and created again would inherit the dead file's `qid.path`, so the
   * client would serve the old file's cached pages for the new one. That is the
   * same aliasing {@link FidTable.remap} drops destination identities to
   * prevent, and `Tremove` needs it just as much.
   *
   * A hardlinked file keeps its identity until its *last* name goes, which is
   * what `paths` is counting. Once it does, the `(dev, ino)` key is released
   * too: a real filesystem hands the inode number of a deleted file straight to
   * the next one created, and resurrecting the identity for it would alias two
   * different files.
   */
  release(path: string): void {
    const identity = this.#qidByPath.get(path);
    if (identity !== undefined) {
      this.#detachQid(identity, path);
    }
  }

  #attachQid(identity: QidIdentity, path: string): void {
    identity.paths.add(path);
    this.#qidByPath.set(path, identity);
    if (identity.key !== undefined) {
      this.#qidByKey.set(identity.key, identity);
    }
  }

  #detachQid(identity: QidIdentity, path: string): void {
    identity.paths.delete(path);
    this.#qidByPath.delete(path);
    if (
      identity.paths.size === 0 &&
      identity.key !== undefined &&
      this.#qidByKey.get(identity.key) === identity
    ) {
      // Only if this identity still owns the key: by now a *different* live
      // identity may already hold that `(dev, ino)`, and deleting unconditionally
      // would strip it of the identity the client is caching against.
      this.#qidByKey.delete(identity.key);
    }
  }

  // -------------------------------------------------------------------------
  // rename
  // -------------------------------------------------------------------------

  /**
   * `from` was renamed to `to`: rewrite every fid at or under it, and carry any
   * synthesized qid identity along.
   *
   * This is the subtree walk `InodeTable.remap` does, for the same reason — the
   * client goes on using the fids it already holds afterwards, with no idea
   * anything moved, and every one of them has to name the new path. `Twalk`ing
   * a directory and then renaming it from another client is not exotic; it is
   * what `mv` on an open shell does.
   *
   * Fids at or under the *destination* keep their paths. Their file has just
   * been replaced, and a path-based server has nothing left to point them at:
   * 9P would have them keep working on the unlinked file (that is what a
   * stateful fid means), and we cannot, because the driver interface only names
   * files by path. Rewriting them to nothing would be a lie in the other
   * direction, so the honest thing is to leave them naming the path, note that
   * they now see the file that moved in, and let `Tclunk` end it. What they do
   * *not* keep is a readdir cursor: the directory under that name is a
   * different directory now, and resuming an offset into the old snapshot would
   * page a listing that has nothing to do with it.
   *
   * The qid identities under the destination are released outright, because the
   * files they identified are gone and reusing an id for the replacement would
   * alias two different files in the client's inode cache.
   *
   * The identity half of that is `src/subtree.ts`'s walk — the same one
   * `InodeTable` and `FileHandleTable` do — driven by *this* table's
   * {@link FidTable.detachQid} and {@link FidTable.attachQid}, so releasing the
   * replaced identities outright stays this transport's meaning and no other's.
   * The fid half below is 9P's alone: no other transport has a client-chosen
   * name for a path, or a readdir cursor pinned to one.
   *
   * Three full scans per rename, then — two of the qid map and one of the fid
   * map — i.e. O(tracked paths) rather than O(subtree). See `src/subtree.ts`
   * for why a prefix tree is the fix and why it is a benchmark-milestone
   * concern, not a v1 one.
   */
  remap(from: string, to: string): void {
    if (from === to) {
      return;
    }
    remapSubtree(this.#qidByPath, from, to, this.#remapOps);

    for (const entry of this.#fids.values()) {
      if (isPathInside(entry.path, from)) {
        // The setter drops the cursor; see `Fid.cursor`.
        entry.path = to + entry.path.slice(from.length);
      } else if (isPathInside(entry.path, to)) {
        entry.cursor = undefined;
      }
    }
  }

  // -------------------------------------------------------------------------
  // bookkeeping
  // -------------------------------------------------------------------------

  /** Every live fid number, for teardown and tests. */
  fids(): number[] {
    return [...this.#fids.keys()];
  }

  /** Every entry, in creation order. */
  entries(): Fid<TDirent>[] {
    return [...this.#fids.values()];
  }

  /**
   * Every fid holding a real driver handle, for `destroy()`.
   *
   * There is no `Tdestroy`: a 9P connection ends when the socket does, and
   * whatever the client had open at that moment is still open here. This is
   * the list the session closes — fids opened against a `handles: false`
   * driver are not in it, because they hold nothing to close.
   */
  openHandles(): { fid: Fid<TDirent>; handle: FileHandleLike }[] {
    const open: { fid: Fid<TDirent>; handle: FileHandleLike }[] = [];
    for (const entry of this.#fids.values()) {
      if (entry.open?.handle !== undefined) {
        open.push({ fid: entry, handle: entry.open.handle });
      }
    }
    return open;
  }

  /**
   * Drop every fid **and** every qid identity. Teardown, and tests.
   *
   * The identities go because the only thing that remembers a `qid.path` is the
   * client at the other end of this connection, and a table is cleared when
   * that connection is over. The counter is *not* rewound: it never hands out a
   * number twice for the life of the table, so nothing that outlives a clear
   * (a test reusing the table, a session that clears and carries on) can be
   * handed an id it has already seen mean something else.
   */
  clear(): void {
    this.#fids.clear();
    this.#qidByPath.clear();
    this.#qidByKey.clear();
  }
}

/**
 * Apply one `Twalk` name element to a path.
 *
 * The kernel sends bare name elements — never a slash, never an empty string —
 * and the two it does send that are not plain names are `..`, which
 * `src/path.ts` clamps at the root so no walk can ever leave the mount, and
 * `.`, which resolves to the same path.
 *
 * The three refusals are all the same refusal: an element that is not a name.
 * A `/` would let one element walk several levels and slip past a per-element
 * check the session is about to make. An empty element names nothing. And a
 * name with an embedded NUL is a name to 9P — its strings are counted, not
 * terminated — but not to the host: `node:fs` throws a `TypeError` for one,
 * which is not an `FsError`, so it would leave the session's catch-all to
 * report `EIO` for what is really a malformed request. Refusing it here keeps
 * the errno honest and the driver unbothered.
 */
export function walkStep(path: string, name: string): string {
  if (name === "") {
    throw fsError("EINVAL", { message: "EINVAL: walk element is empty" });
  }
  if (name.includes("/")) {
    throw fsError("EINVAL", { message: `EINVAL: walk element '${name}' contains a separator` });
  }
  // "\0" is the two-character escape, never a literal NUL: source stays
  // grep-able (AGENTS.md).
  if (name.includes("\0")) {
    throw fsError("EINVAL", { message: "EINVAL: walk element contains a NUL" });
  }
  return joinPath(path, name);
}
