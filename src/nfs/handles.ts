/**
 * File handles and directory cookies — the two pieces of state a *stateless*
 * protocol still forces a server to keep.
 *
 * NFSv3 has no `open`, no `release` and no `FORGET`: every operation carries an
 * opaque handle of up to 64 bytes, and a client may present one it obtained an
 * hour ago, from a different process, after the server has been restarted. That
 * makes this table look like the FUSE `InodeTable` and behave quite differently:
 *
 * - **Nothing is refcounted, and an entry lives as long as one of its names
 *   does.** There is no message that says "I am done with this handle", so an
 *   entry the client may still hold has to stay. What *can* go is an entry with
 *   no names left: it is reachable only through `decode()` → `pathOf()`, which
 *   always throws `ESTALE`, so dropping it changes nothing a client can see —
 *   the same handle now gets `ESTALE` from `decode()` instead, one sentence
 *   earlier. That matters because ids are minted from a monotonic counter and
 *   never reused, so create/delete churn under a mount (a build, a `tar -x`
 *   followed by a `rm -rf`) would otherwise grow `#byId` without any bound at
 *   all. What is left is one live entry per path the client currently has a
 *   name for, plus the root — held for the life of the server however long ago
 *   the client looked, unless the table is given a cap. See "The bound" below.
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
 *
 * ## The bound ({@link FileHandleTableOptions.maxHandles})
 *
 * Unset — the default — nothing is evicted, and the table grows to one entry
 * per path the client currently has a name for: a client that walks a
 * million-file tree leaves a million entries, and nothing on the wire will ever
 * say they can go. Set, the table keeps at most that many entries (the root
 * counted) and drops the least recently *used* one past the cap. Recency is
 * stamped by every path that reaches an entry — `decode`, `at`, `pathOf`, and
 * every `bind`/`remap` attach — not only by the call that created it, so the
 * entries a client is working with are the last ones considered, and the one it
 * looked up an hour ago and forgot is the first.
 *
 * Evicting is not free the way dropping a path-less entry was: the entry it
 * takes is one the client may still have a live name for, so this *is* visible
 * to it. It is however still **safe**, for the same reason — `#nextId` only
 * ever counts up, so the id in the handle the client kept can never be handed
 * to a different file, and that handle answers `ESTALE` ("unknown file handle")
 * rather than quietly naming somebody else's. What it costs an NFSv3 client is
 * one round trip: `ESTALE` means "drop the dentry and look the name up again",
 * which re-binds the path and mints a fresh handle. What it costs an NFSv4.1
 * client that had the file **open** is more — `v4/session.ts` keys open and
 * lock state by entry id, so the re-lookup is a different file as far as share
 * reservations are concerned and the client has to re-`OPEN`. That asymmetry is
 * why the cap is off unless asked for, rather than defaulted to some number.
 *
 * The root is never a victim: `PUTROOTFH`, `PUTPUBFH` and `MNT` hand out its
 * handle from the `root` field rather than from a lookup, so an id that stopped
 * decoding would be a handle this server minted and immediately refused.
 * Neither is the entry currently being bound — the call that overflowed the cap
 * is about to answer with it — so the smallest table a cap can produce is those
 * two, whatever number it is given.
 */

import { randomFillSync } from "node:crypto";
import { fsError } from "../errors.ts";
import { remapSubtree, type SubtreeRemapOps } from "../subtree.ts";
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
  /**
   * What both versions report as `fileid3`/`fattr4_fileid`: the driver's own
   * `ino` when it offered one, and the entry id when it did not.
   *
   * Kept on the entry, refreshed by every {@link FileHandleTable.bind}, because
   * a READDIR page needs one of these per name and an entry the table has
   * *already* bound can answer with no driver call at all — which is the whole
   * cost of a plain `ls` on a directory the client has walked before.
   */
  fileid: bigint;
  /** Insertion-ordered; the first is the primary path every driver call uses. */
  readonly paths: Set<string>;
}

function identityKey(stats: StatsLike): string | undefined {
  // `ino === 0` is a driver saying it has no identity to offer.
  return stats.ino > 0 ? `${stats.dev}:${stats.ino}` : undefined;
}

/** {@link HandleEntry.fileid} for a fresh `stat`, given the entry it landed on. */
function fileidOf(stats: StatsLike, id: bigint): bigint {
  // Userspace uses `fileid` to spot hardlinks, and the handle is keyed on the
  // same number anyway — so the driver's own is the answer whenever it has one.
  return stats.ino > 0 ? BigInt(Math.trunc(stats.ino)) : id;
}

function stale(what: string): Error {
  return fsError("ESTALE", { message: `ESTALE: ${what}` });
}

export interface FileHandleTableOptions {
  /** Identify files by the driver's `(dev, ino)`, so hardlinks share a handle. Default `true`. */
  useDriverIno?: boolean;
  /** Boot verifier. Default: eight random bytes, so handles do not survive a restart. */
  verifier?: Uint8Array;
  /**
   * Most entries to keep, the least recently used going first past it. Default:
   * no cap at all, which is what every version of this table did before the
   * option existed.
   *
   * The number counts everything {@link FileHandleTable.size} does, the root
   * included. The root and the entry being bound are never evicted, so a cap
   * below two is honoured as far as it can be rather than refused. See the
   * module docs for what an eviction costs a client still holding the handle —
   * it is a real cost, which is why there is no default.
   */
  maxHandles?: number;
}

/** fh ↔ path ↔ `(dev, ino)`, for the lifetime of the server. */
export class FileHandleTable {
  readonly root: HandleEntry;
  /** The eight bytes that make this server's handles distinguishable from the last one's. */
  readonly verifier: Uint8Array;

  readonly #useDriverIno: boolean;
  /** Entries to keep, or `0` for "no cap" — see {@link FileHandleTableOptions.maxHandles}. */
  readonly #maxHandles: number;
  /** Doubles as the LRU order: insertion order, youngest last. See {@link FileHandleTable.touch}. */
  readonly #byId = new Map<bigint, HandleEntry>();
  readonly #byPath = new Map<string, HandleEntry>();
  /** Only holds entries with at least one path — see {@link FileHandleTable.detachPath}. */
  readonly #byKey = new Map<string, HandleEntry>();
  #nextId = ROOT_HANDLE_ID + 1n;
  /**
   * The pair {@link FileHandleTable.remap} hands to `remapSubtree`. Built once
   * rather than per rename, and pointing at the same two private methods every
   * other mutation here goes through — the walk is shared, the meaning is not.
   */
  readonly #remapOps: SubtreeRemapOps<HandleEntry> = {
    detach: (entry, path) => this.#detachPath(entry, path),
    attach: (entry, path) => this.#attachPath(entry, path),
  };

  constructor(options: FileHandleTableOptions = {}) {
    this.#useDriverIno = options.useDriverIno ?? true;
    // Anything that is not a usable positive count — unset, zero, `Infinity`,
    // `NaN` — is the uncapped default rather than a refusal, because "grow
    // forever" is exactly what this table did before the option existed.
    const cap = Math.trunc(options.maxHandles ?? 0);
    this.#maxHandles = Number.isFinite(cap) && cap > 0 ? cap : 0;
    this.verifier = options.verifier ?? randomFillSync(new Uint8Array(8));
    this.root = {
      id: ROOT_HANDLE_ID,
      key: undefined,
      fileid: ROOT_HANDLE_ID,
      paths: new Set(["/"]),
    };
    this.#byId.set(ROOT_HANDLE_ID, this.root);
    this.#byPath.set("/", this.root);
  }

  /**
   * Entries currently known — one per file that still has at least one name,
   * plus the root, and never more than
   * {@link FileHandleTableOptions.maxHandles} when one was given. See the
   * module docs for what is and is not dropped.
   */
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
   * (drop the dentry, look the name up again). Under a cap, an entry that was
   * evicted arrives here as the second of those and leaves as the first.
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
    this.#touch(entry);
    return entry;
  }

  /**
   * The entry an id names, if it is still live. Nothing in `src/` needs this;
   * the tests do — which is also why it is the one lookup that does *not*
   * restamp recency: a test has to be able to look at the table without
   * changing what the next eviction picks.
   */
  get(id: bigint): HandleEntry | undefined {
    return this.#byId.get(id);
  }

  at(path: string): HandleEntry | undefined {
    const entry = this.#byPath.get(path);
    if (entry !== undefined) {
      this.#touch(entry);
    }
    return entry;
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
        this.#touch(entry);
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
      const id = this.#nextId++;
      entry = { id, key, fileid: fileidOf(stats, id), paths: new Set() };
      this.#byId.set(entry.id, entry);
    } else {
      entry.fileid = fileidOf(stats, entry.id);
    }
    if (previous !== undefined && previous !== entry) {
      this.#detachPath(previous, path);
    }
    if (key !== undefined && entry.key === undefined) {
      entry.key = key;
    }
    this.#attachPath(entry, path);
    this.#pruneToNlink(entry, stats);
    // Last, and only here: `bind` is the one thing that adds an entry, so it is
    // the one thing that can push the table over its cap. `entry` is exempt —
    // the caller is about to encode it into a reply.
    this.#enforceLimit(entry);
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
   *
   * The walk itself is `src/subtree.ts`'s — the same one `InodeTable` and
   * `FidTable` do — driven by *this* table's {@link FileHandleTable.detachPath}
   * and {@link FileHandleTable.attachPath}, so what a replaced destination
   * means here is unchanged: the entry loses its identity key and its id, and
   * the handle the client still holds answers `ESTALE`. It costs two full scans
   * of the path map per rename, i.e. O(tracked paths) rather than O(subtree);
   * see that module for why a prefix tree is the fix and why it is a
   * benchmark-milestone concern, not a v1 one.
   */
  remap(from: string, to: string): void {
    remapSubtree(this.#byPath, from, to, this.#remapOps);
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
    // Being given a name is a use, which is what makes `remap` — whose every
    // rewritten path lands here — restamp a whole moved subtree rather than
    // leaving it looking untouched since whenever it was first looked up.
    this.#touch(entry);
  }

  #detachPath(entry: HandleEntry, path: string): void {
    entry.paths.delete(path);
    // Only while the path map still agrees this is the entry's name. The two
    // can disagree — `pathOf` exists because of it — and an eviction detaches
    // every name an entry remembers in one go, so a name that has since been
    // re-bound to a different entry must not be taken out from under it.
    if (this.#byPath.get(path) === entry) {
      this.#byPath.delete(path);
    }
    if (entry.paths.size > 0) {
      return;
    }
    this.#dropEntry(entry);
  }

  /**
   * Forget an entry outright: the identity map, then the id map.
   *
   * Both callers mean the same thing by it — a last name went away, or the LRU
   * chose this one — and both need every map to agree afterwards, which is why
   * there is one copy of it rather than one per caller.
   */
  #dropEntry(entry: HandleEntry): void {
    // A dropped entry must not be found by identity again: a real filesystem
    // reuses the `ino` of a deleted file for the next one created.
    if (entry.key !== undefined && this.#byKey.get(entry.key) === entry) {
      this.#byKey.delete(entry.key);
    }
    // And it must not stay in `#byId` either. The only thing that could still
    // reach it is `decode()` of a handle the client kept, and the very next
    // thing that happens to it is `pathOf()` throwing `ESTALE`; dropping it
    // makes `decode()` say the same thing one sentence earlier ("unknown file
    // handle"), which is safe precisely because `#nextId` only ever counts up,
    // so no later file can be handed this id and alias the dead handle. That
    // last sentence is the whole licence for evicting a *live* entry too: the
    // client is told `ESTALE`, never handed somebody else's file.
    //
    // The root is the exception: `PUTROOTFH` and `MNT` hand out its handle from
    // the `root` field rather than from a lookup, so an id that no longer
    // decodes would be a handle this server minted and immediately refuses.
    if (entry.id !== ROOT_HANDLE_ID) {
      this.#byId.delete(entry.id);
    }
  }

  /**
   * Restamp an entry as the most recently used one.
   *
   * The LRU order *is* `#byId`'s insertion order — re-inserting moves an entry
   * to the young end, the same trick {@link DirectorySnapshots} plays — so
   * there is no second structure that could fall out of step with the three
   * maps, and no allocation per lookup. The `delete` result is the guard: an
   * entry that has already been dropped must not be resurrected by whatever is
   * still holding a reference to it.
   *
   * Uncapped, this is a no-op rather than bookkeeping nobody will read: with no
   * eviction there is no order to maintain, and a delete-and-set on every
   * `decode` is not free. The root is a no-op too, and for the opposite reason:
   * it can never be a victim, so its place in the order means nothing, and
   * leaving it where it was inserted — the old end, for the life of the table —
   * is what keeps {@link FileHandleTable.lruVictim}'s scan to a step or two.
   */
  #touch(entry: HandleEntry): void {
    if (this.#maxHandles <= 0 || entry.id === ROOT_HANDLE_ID) {
      return;
    }
    if (this.#byId.delete(entry.id)) {
      this.#byId.set(entry.id, entry);
    }
  }

  /** Drop least-recently-used entries until the table is inside its cap. */
  #enforceLimit(keep: HandleEntry): void {
    if (this.#maxHandles <= 0) {
      return;
    }
    while (this.#byId.size > this.#maxHandles) {
      const victim = this.#lruVictim(keep);
      // Root plus the entry just bound, and a cap of one or two asking for
      // less than that. Honour what can be honoured and stop.
      if (victim === undefined) {
        return;
      }
      this.#evict(victim);
    }
  }

  /**
   * The oldest entry that may go — anything but the root and the entry the
   * caller is in the middle of binding.
   *
   * The scan is not the linear cost it looks like: the root is inserted first
   * and never touched, so it sits at the old end for the life of the table and
   * this walks past it and one more entry at most.
   */
  #lruVictim(keep: HandleEntry): HandleEntry | undefined {
    for (const entry of this.#byId.values()) {
      if (entry.id !== ROOT_HANDLE_ID && entry !== keep) {
        return entry;
      }
    }
    return undefined;
  }

  /**
   * Drop an entry the client may still be naming.
   *
   * Name by name through {@link FileHandleTable.detachPath}, so this is the
   * same teardown as a file whose last link went away rather than a second one
   * beside it — the maps cannot end up disagreeing about an entry that is gone,
   * because only one piece of code decides what "gone" does. The trailing
   * {@link FileHandleTable.dropEntry} covers the case the loop cannot reach:
   * `pathOf` forgets a name the path map no longer agrees with without going
   * through `#detachPath` at all, so an entry can be down to no names and still
   * be here. It is idempotent, so paying for it unconditionally is cheaper than
   * asking.
   *
   * Deleting the name being visited is what {@link FileHandleTable.pruneToNlink}
   * already does to the same set, and is well defined for a `Set` iterator.
   */
  #evict(entry: HandleEntry): void {
    for (const path of entry.paths) {
      this.#detachPath(entry, path);
    }
    this.#dropEntry(entry);
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
 *
 * ## The invalidation rule
 *
 * Both sessions share this cache, and both obey one rule:
 *
 * > **A mutating operation drops the snapshot of every directory whose set of
 * > names it could have changed, and of no other directory.**
 *
 * Which is four cases and nothing else:
 *
 * - creating a name in `D` (CREATE, MKDIR, SYMLINK, MKNOD, LINK, and v4's
 *   creating OPEN) drops `D`'s;
 * - removing a name from `D` drops `D`'s;
 * - removing the directory `D` itself drops `D`'s own as well, since the
 *   listing it holds now describes something that is gone;
 * - a rename drops **both parents'** — the source's, which lost a name, and the
 *   target's, which gained one.
 *
 * Two things follow that are easy to get wrong in the other direction. A
 * directory that was itself *renamed* keeps its snapshot: its contents did not
 * change, and the handle table is identity-keyed, so it is still the same id.
 * And nothing invalidates on behalf of an unrelated directory — the old
 * `clear()`-on-rename threw away every cached listing in the server, so one
 * `mv` in the middle of a build cost every other client its paging position.
 *
 * "Could have changed" is deliberately conservative: an `UNCHECKED` CREATE over
 * a file that already exists changes no names, and still drops the snapshot.
 * Being wrong that way costs one re-`readdir` on the next resume, and the
 * verifier then matches and the client's cookies keep working. Being wrong the
 * other way serves a resuming client a listing it can prove is current, and is
 * silently the wrong one.
 *
 * A snapshot whose directory has ceased to exist altogether — the losing side
 * of a rename, a subtree that moved out from under one — needs no rule: its
 * handle no longer decodes (see {@link FileHandleTable}), so nothing can name
 * the id again, and it ages out of the LRU behind the live entries.
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
