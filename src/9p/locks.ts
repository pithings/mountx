/**
 * Byte-range locks: `Tlock` and `Tgetlock`, across every client of one server.
 *
 * **This is not `src/lock.ts`.** `PathLock` serializes a session's own
 * path-resolving work against its renames, and nothing in this file blocks
 * anything at all. What is here is POSIX record locking — the advisory ranges
 * `fcntl(F_SETLK)` takes — and its whole job is to answer "does this range
 * overlap one somebody else is already holding".
 *
 * ## Why the table is above the session
 *
 * Fids, `msize` and the qid map are per connection, which is why `P9Session`
 * owns them. A lock is the opposite: it exists to be seen by *another* client,
 * and 9P gives every client its own connection and therefore its own session.
 * So one table is shared by every session a `createP9Server` produces (through
 * {@link P9SessionOptions.locks}), the way `NfsSharedState` is shared by the two
 * NFS versions — and a session built by hand gets a private one, which is the
 * single-client `mount9p()` case: nobody else can ever be in that table, so
 * every request is granted exactly as it was before this file existed.
 *
 * ## Who owns a lock
 *
 * `(client_id, proc_id)`, the two fields the message carries for precisely this
 * purpose: `v9fs_file_do_lock()` (v6.12, `fs/9p/vfs_file.c`) sends
 * `utsname()->nodename` as `client_id` and the locking process's pid as
 * `proc_id`, so the pair names *a process on a machine*.
 *
 * It is deliberately **not** the connection. One kernel that mounts the same
 * export twice is still one kernel, and POSIX is explicit that a process's own
 * record locks never conflict with each other however many descriptors it holds
 * them through; keying on the connection would invent a conflict between two
 * mounts of one machine that neither the client nor POSIX believes in. The
 * price of trusting the pair is that two hosts sharing a nodename look like one
 * host — a property of the only identity this protocol puts on the wire, and
 * not something a server can improve on from its end.
 *
 * One consequence worth stating rather than discovering: an owner that re-locks
 * a range it already holds *through another connection* replaces its own record
 * rather than adding one, so the range then dies with the newer connection.
 * That is POSIX's replace semantics applied to an identity that spans
 * connections, and it errs toward releasing a range early rather than toward
 * stranding one — the direction this whole file errs in.
 *
 * The connection is still *recorded*, because it is what makes a lock die with
 * the client holding it: {@link P9LockClient.releaseAll} runs from the session's
 * teardown and from its `Tversion` reset, and {@link P9LockClient.releaseFid}
 * from every `Tclunk`/`Tremove`. A range that outlived its client would be
 * unreleasable by anybody and would deny that file to everybody, which is worse
 * than never having granted it. That is also why a range can only be taken
 * through a {@link P9LockClient} — there is no way to put one in this table
 * without something whose teardown takes it out again.
 *
 * ## Blocking: never
 *
 * A conflict is answered {@link P9_LOCK_BLOCKED} and this server never parks a
 * request waiting for one. That is what the protocol asks of it:
 * `v9fs_file_do_lock()` turns `P9_LOCK_BLOCKED` into `-EAGAIN` for `F_SETLK` —
 * exactly what a failed `fcntl` should report — and for `F_SETLKW` sleeps
 * `P9_LOCK_TIMEOUT` and asks again, so the waiting is the client's by design and
 * `P9_LOCK_FLAGS_BLOCK` describes what it will do next rather than requesting
 * that the server hold the tag. A waiter queue here would buy nothing that poll
 * does not already give and would cost the one thing 9P cannot do: cancel one.
 * `Tflush` is answered only once the request it names has settled, so a parked
 * `Tlock` would make a flush wait for a lock to be released rather than the
 * other way round.
 *
 * {@link P9_LOCK_GRACE} is never sent, for the reason NFSv4.1 has no grace
 * period: nothing here survives a restart, so there is nothing to reclaim and no
 * window in which to reclaim it. `P9_LOCK_FLAGS_RECLAIM` — which the v6.12
 * client never sets — is therefore served as an ordinary request.
 * {@link P9_LOCK_ERROR} is sent for one thing only, the per-file cap: the client
 * maps it to `-ENOLCK`, which is what "no locks available" means.
 *
 * ## What names a file
 *
 * Its path, because that is the only name two sessions can both say. `qid.path`
 * cannot be it — `FidTable` allocates those from a per-connection counter, so
 * one file held by two clients is two different numbers — and the driver
 * interface names files by path and nothing else. Two consequences, and the
 * session drives both: {@link P9LockTable.remap} follows a rename, so a range
 * stays with the file that moved rather than guarding the name it left, and
 * {@link P9LockTable.release} drops the ranges under a name that stopped
 * existing, because the next file created there is a *different* file and a
 * stale range under its name would deny it to everybody. A holder whose file
 * was removed under it keeps reading through its fid and finds its lock gone;
 * that is the honest limit of a path-keyed table, and it fails toward granting
 * rather than toward denying.
 *
 * The same limit has a second edge worth knowing. A rename rewrites the *other*
 * sessions' fid tables not at all — `FidTable.remap` is per connection, because
 * a fid is — so a client still holding a fid from before one goes on naming the
 * old path, while its ranges have moved to the new one. Nothing is stranded (the
 * records still die with that fid or that connection) and a client that walks
 * to the new name afterwards sees them, which is the case that matters; what it
 * costs is that a stale fid's next `Tlock` files itself under the old name and
 * its next `Tgetlock` looks there. Following renames across every session's fids
 * is the fix, and it is the same missing piece as the per-connection `PathLock`
 * — a rename by one client is not serialized against another's work either.
 *
 * ## Why this is not `src/nfs/v4/state.ts`'s lock table
 *
 * The range algebra below — overlap, split, coalesce — is POSIX's and is the
 * same shape there. The records are not: NFSv4.1 judges conflicts by
 * `(clientid, lock-owner)`, tracks the open stateid each range was taken
 * through, revokes under an expired lease and answers `NFS4ERR_DENIED` carrying
 * the holder's identity. 9P has no stateids, no lease and no revocation, its
 * owner is a `(nodename, pid)` pair off the wire, and its conflict reply is a
 * status byte. Sharing thirty lines of arithmetic would mean generifying it
 * over four differing key fields to save less than the indirection costs, so it
 * is written twice on purpose — the way `src/subtree.ts` was *not*, because
 * there the walk was character-identical and only the endpoints differed.
 *
 * **Everything here is synchronous**, like `fids.ts`: no method awaits, so a
 * whole grant or release is atomic against the event loop and the session needs
 * no lock of its own around one.
 */

import { fsError } from "../errors.ts";
import { remapSubtree, type PathBound, type SubtreeRemapOps } from "../subtree.ts";
import {
  P9_LOCK_BLOCKED,
  P9_LOCK_ERROR,
  P9_LOCK_SUCCESS,
  P9_LOCK_TYPE_RDLCK,
  P9_LOCK_TYPE_UNLCK,
  P9_LOCK_TYPE_WRLCK,
} from "./constants.ts";

/**
 * One past the last addressable byte: the exclusive end of a to-EOF range.
 *
 * `length == 0` means "to the end of the file, however long it becomes" —
 * `v9fs_file_do_lock()` sends it for an `l_end` of `OFFSET_MAX` — so the range
 * arithmetic gives it an end nothing can overlap past and no special case
 * anywhere but {@link lengthOf}, which puts the zero back on the wire.
 */
export const P9_LOCK_EOF_END = 1n << 64n;

/** Granted ranges one file may carry, across every client. */
export const DEFAULT_MAX_LOCKS_PER_FILE = 1024;

/** One granted range, `[start, end)`. */
export interface P9Lock {
  start: bigint;
  end: bigint;
  /** {@link P9_LOCK_TYPE_RDLCK} or {@link P9_LOCK_TYPE_WRLCK}; never `UNLCK`. */
  type: number;
  /** `(client_id, proc_id)` — the identity a conflict is judged against. */
  ownerKey: string;
  /** `proc_id`, kept whole because `Rgetlock` has to carry it back. */
  procId: number;
  /** `client_id`, kept for the same reason. */
  clientId: string;
  /**
   * The connection that took it — {@link P9LockClient.id}.
   *
   * Not part of the conflict identity (see the module docs); this is what a
   * session teardown releases by, so a client that goes away takes its ranges
   * with it.
   */
  holder: number;
  /**
   * The fid it was taken through, so a `Tclunk` releases it.
   *
   * Not part of the conflict identity either: an unlock names a range, not a
   * fid, and POSIX unlocks the *process's* ranges — so a client may lock through
   * one fid and unlock through another, and both work.
   */
  fid: number;
}

/** What a `Tlock`/`Tgetlock` asks about, decoded and with its fid resolved. */
export interface P9LockRequest {
  /** The file, named the only way two sessions can both name it. */
  path: string;
  /** The fid it came in on — recorded, never matched against. */
  fid: number;
  /** `P9_LOCK_TYPE_*`. */
  type: number;
  start: bigint;
  /** `0` is to-EOF; see {@link P9_LOCK_EOF_END}. */
  length: bigint;
  procId: number;
  clientId: string;
}

/** A conflicting lock, in the shape `Rgetlock` puts on the wire. */
export interface P9LockHolder {
  type: number;
  start: bigint;
  /** `0` for a range that runs to EOF, which is how it arrived. */
  length: bigint;
  procId: number;
  clientId: string;
}

export interface P9LockTableOptions {
  /** Granted ranges one file may carry. Default {@link DEFAULT_MAX_LOCKS_PER_FILE}. */
  maxLocksPerFile?: number;
}

/**
 * One connection's handle on the table.
 *
 * Obtained from {@link P9LockTable.client}, held for the life of a session, and
 * the only way to take a lock: everything that *grants* is reached through one
 * of these, so every granted range has a teardown that removes it.
 */
export interface P9LockClient {
  /** The table this handle belongs to; shared with every other client of it. */
  readonly table: P9LockTable;
  /** This connection's number, as recorded in {@link P9Lock.holder}. */
  readonly id: number;
  /** Ranges this connection is holding, across every file. */
  readonly held: number;
  /**
   * `Tlock` — take, upgrade, downgrade or release a range.
   *
   * Answers a `P9_LOCK_*` status: {@link P9_LOCK_SUCCESS} when the range is
   * held afterwards (or, for `UNLCK`, when it is not), {@link P9_LOCK_BLOCKED}
   * for a conflict with another owner, {@link P9_LOCK_ERROR} when this file is
   * at its cap. A lock type that is none of the three, or a range that cannot
   * exist, throws `EINVAL` — a malformed request rather than a refused one.
   */
  lock(request: P9LockRequest): number;
  /** `Tgetlock` — the first conflicting range, or `undefined` for none. */
  getlock(request: P9LockRequest): P9LockHolder | undefined;
  /** Release everything this connection took through one fid. `Tclunk`/`Tremove`. */
  releaseFid(fid: number): void;
  /** Release everything this connection holds. Teardown, and the `Tversion` reset. */
  releaseAll(): void;
  /**
   * A path was renamed: move **every** client's ranges with it.
   *
   * Table-wide on purpose — the rename is the file's, not this connection's.
   */
  renamed(from: string, to: string): void;
  /** A path stopped existing: drop every client's ranges under it. Table-wide too. */
  released(path: string): void;
}

/**
 * Every range granted on one path.
 *
 * A {@link PathBound} with exactly one path in it, which is what lets
 * `src/subtree.ts`'s rename walk drive this table the way it drives the three
 * handle tables.
 */
class LockedFile implements PathBound {
  readonly paths = new Set<string>();
  locks: P9Lock[] = [];
}

/**
 * The identity a conflict is judged against.
 *
 * `proc_id` first and in decimal, so the pair is recoverable from the string
 * and two different pairs can never build the same one: the digits before the
 * first `:` are the pid and everything after it is the nodename, whatever the
 * nodename happens to contain.
 */
function ownerKeyOf(request: P9LockRequest): string {
  return `${request.procId >>> 0}:${request.clientId}`;
}

/** The `[start, end)` a `(start, length)` names, or `EINVAL` if it names none. */
function rangeOf(start: bigint, length: bigint): { start: bigint; end: bigint } {
  const end = length === 0n ? P9_LOCK_EOF_END : start + length;
  if (start < 0n || length < 0n || end > P9_LOCK_EOF_END) {
    throw fsError("EINVAL", {
      message: `EINVAL: no byte range starts at ${start} and runs for ${length} bytes`,
    });
  }
  return { start, end };
}

/** The `length` a range goes back out as: `0` when it runs to EOF. */
function lengthOf(lock: P9Lock): bigint {
  return lock.end === P9_LOCK_EOF_END ? 0n : lock.end - lock.start;
}

function holderOf(lock: P9Lock): P9LockHolder {
  return {
    type: lock.type,
    start: lock.start,
    length: lengthOf(lock),
    procId: lock.procId,
    clientId: lock.clientId,
  };
}

function overlaps(lock: P9Lock, start: bigint, end: bigint): boolean {
  return lock.start < end && start < lock.end;
}

/** POSIX conflict: a range of another owner, where at least one side is a write lock. */
function conflicts(lock: P9Lock, ownerKey: string, type: number): boolean {
  return (
    lock.ownerKey !== ownerKey && (lock.type === P9_LOCK_TYPE_WRLCK || type === P9_LOCK_TYPE_WRLCK)
  );
}

/**
 * The group two ranges must share before they may be merged.
 *
 * The owner is not enough: a range is released by the fid it was taken through,
 * so merging one fid's range into another's would leave a `Tclunk` unable to
 * say which bytes it owned. Numbers first and in decimal keeps the key
 * unambiguous however arbitrary the nodename inside `ownerKey` is.
 */
function groupKeyOf(lock: P9Lock): string {
  return `${lock.holder}:${lock.fid}:${lock.ownerKey}`;
}

/**
 * Replace `[start, end)` for one owner, splitting and merging the way POSIX
 * requires of `fcntl`.
 *
 * Every same-owner range is trimmed out of the way first — which is what turns
 * an upgrade or a downgrade of a sub-range into a split — then the new range is
 * inserted and coalesced with the neighbours it now touches and agrees with.
 * Other owners' ranges are never touched.
 */
function replaceRange(locks: readonly P9Lock[], granted: P9Lock): P9Lock[] {
  const kept = subtractRange(locks, granted.ownerKey, granted.start, granted.end);
  kept.push({ ...granted });
  return coalesce(kept);
}

/** Remove `[start, end)` from every range `ownerKey` holds, splitting where it lands inside one. */
function subtractRange(
  locks: readonly P9Lock[],
  ownerKey: string,
  start: bigint,
  end: bigint,
): P9Lock[] {
  const kept: P9Lock[] = [];
  for (const lock of locks) {
    if (lock.ownerKey !== ownerKey || !overlaps(lock, start, end)) {
      kept.push(lock);
      continue;
    }
    if (lock.start < start) {
      kept.push({ ...lock, end: start });
    }
    if (lock.end > end) {
      kept.push({ ...lock, start: end });
    }
  }
  return kept;
}

/**
 * Sort by start and join each group's touching same-type ranges.
 *
 * Tracked per group rather than against the previous element, because two
 * owners' ranges interleave freely in start order and one owner's two adjacent
 * ranges would otherwise be left split by another owner's sorting between them.
 */
function coalesce(locks: P9Lock[]): P9Lock[] {
  const sorted = [...locks].sort((left, right) =>
    left.start < right.start ? -1 : left.start > right.start ? 1 : 0,
  );
  const merged: P9Lock[] = [];
  const lastOf = new Map<string, P9Lock>();
  for (const lock of sorted) {
    const groupKey = groupKeyOf(lock);
    const last = lastOf.get(groupKey);
    if (last !== undefined && last.type === lock.type && last.end >= lock.start) {
      last.end = last.end > lock.end ? last.end : lock.end;
      continue;
    }
    const kept = { ...lock };
    merged.push(kept);
    lastOf.set(groupKey, kept);
  }
  return merged;
}

/**
 * Every byte range granted over one driver, however many clients took them.
 *
 * ```ts
 * const locks = new P9LockTable();
 * const server = createP9Server(driver, { locks });
 * ```
 *
 * Shared by construction and empty by default: a table nobody hands to a second
 * session behaves exactly like the unconditional grant this replaced.
 */
export class P9LockTable {
  readonly #files = new Map<string, LockedFile>();
  readonly #maxPerFile: number;
  #nextClientId = 1;
  /**
   * The pair {@link P9LockTable.remap} hands `remapSubtree`. Built once, and
   * pointing at the same two methods every other path mutation here goes
   * through — the walk is shared, the meaning is this transport's.
   */
  readonly #remapOps: SubtreeRemapOps<LockedFile> = {
    detach: (file, path) => this.#forget(file, path),
    attach: (file, path) => this.#bind(file, path),
  };

  constructor(options: P9LockTableOptions = {}) {
    this.#maxPerFile = Math.max(
      1,
      Math.trunc(options.maxLocksPerFile ?? DEFAULT_MAX_LOCKS_PER_FILE),
    );
  }

  /** Paths holding at least one granted range. Falls again as they are released. */
  get files(): number {
    return this.#files.size;
  }

  /** Granted ranges in total, over every path and every client. */
  get size(): number {
    let total = 0;
    for (const file of this.#files.values()) {
      total += file.locks.length;
    }
    return total;
  }

  /** The ranges granted on one path. Empty for a path nobody has locked. */
  at(path: string): readonly P9Lock[] {
    return this.#files.get(path)?.locks ?? [];
  }

  /**
   * A handle for one connection. The session holds it for its whole life and
   * releases through it; see {@link P9LockClient}.
   */
  client(): P9LockClient {
    const id = this.#nextClientId++;
    // A literal of arrows rather than a class: `#lock` and `#drop` are this
    // table's own privates, and a closure is the only thing that can reach them
    // while still handing out something a session may not grant through twice.
    const count = (): number => this.#count(id);
    return {
      table: this,
      id,
      get held(): number {
        return count();
      },
      lock: (request) => this.#lock(id, request),
      getlock: (request) => this.getlock(request),
      releaseFid: (fid) => this.#drop((lock) => lock.holder === id && lock.fid === fid),
      releaseAll: () => this.#drop((lock) => lock.holder === id),
      renamed: (from, to) => this.remap(from, to),
      released: (path) => this.release(path),
    };
  }

  /**
   * `Tgetlock` — the first range that would deny this request, or `undefined`.
   *
   * The asking owner's own ranges are excluded, because a process is never
   * blocked by itself, and the type asked about decides what counts: a read
   * lock is only denied by a write lock, a write lock by either.
   *
   * Needs no client handle: asking is not holding.
   */
  getlock(request: P9LockRequest): P9LockHolder | undefined {
    const range = rangeOf(request.start, request.length);
    const type = requireHeldType(request.type);
    const ownerKey = ownerKeyOf(request);
    for (const held of this.at(request.path)) {
      if (overlaps(held, range.start, range.end) && conflicts(held, ownerKey, type)) {
        return holderOf(held);
      }
    }
    return undefined;
  }

  /**
   * `from` was renamed to `to`: the ranges move with the file.
   *
   * Whatever was at the destination has just been replaced, so its ranges go —
   * that is `remapSubtree`'s `detach`, and it is the same call
   * {@link P9LockTable.release} makes, because a name that no longer names the
   * file it did is a name whose locks mean nothing.
   */
  remap(from: string, to: string): void {
    if (from === to) {
      return;
    }
    remapSubtree(this.#files, from, to, this.#remapOps);
  }

  /** A path stopped existing (`Tremove`, `Tunlinkat`): drop the ranges under it. */
  release(path: string): void {
    const file = this.#files.get(path);
    if (file !== undefined) {
      this.#forget(file, path);
    }
  }

  #lock(holder: number, request: P9LockRequest): number {
    const range = rangeOf(request.start, request.length);
    const ownerKey = ownerKeyOf(request);
    if (request.type === P9_LOCK_TYPE_UNLCK) {
      // An unlock of bytes nobody holds is a success, not a refusal: POSIX's
      // `F_UNLCK` clears whatever of the caller's ranges is there, which may be
      // nothing at all.
      this.#unlock(request.path, ownerKey, range.start, range.end);
      return P9_LOCK_SUCCESS;
    }
    const type = requireHeldType(request.type);
    const existing = this.#files.get(request.path);
    const locks = existing?.locks ?? [];
    for (const held of locks) {
      if (overlaps(held, range.start, range.end) && conflicts(held, ownerKey, type)) {
        // Never a wait. See the module docs: the client polls, and it is the
        // only end of this that can be interrupted.
        return P9_LOCK_BLOCKED;
      }
    }
    // A soft cap, checked before the grant rather than after it: an upgrade at
    // the ceiling is refused even though it would not have grown the list, and
    // a split may take it one or two past. What it bounds is a client taking
    // unbounded server memory one alternating range at a time, and for that a
    // cap that is out by two is a cap.
    if (locks.length >= this.#maxPerFile) {
      return P9_LOCK_ERROR;
    }
    const file = existing ?? this.#bind(new LockedFile(), request.path);
    file.locks = replaceRange(file.locks, {
      start: range.start,
      end: range.end,
      type,
      ownerKey,
      // Masked the way {@link ownerKeyOf} masks it, so the identity a conflict
      // is judged by and the identity `Rgetlock` reports are the same number.
      procId: request.procId >>> 0,
      clientId: request.clientId,
      holder,
      fid: request.fid,
    });
    return P9_LOCK_SUCCESS;
  }

  #unlock(path: string, ownerKey: string, start: bigint, end: bigint): void {
    const file = this.#files.get(path);
    if (file === undefined) {
      return;
    }
    file.locks = subtractRange(file.locks, ownerKey, start, end);
    if (file.locks.length === 0) {
      this.#forget(file, path);
    }
  }

  #count(holder: number): number {
    let total = 0;
    for (const file of this.#files.values()) {
      for (const lock of file.locks) {
        if (lock.holder === holder) {
          total++;
        }
      }
    }
    return total;
  }

  /**
   * Drop every range a predicate matches, and forget the files left empty.
   *
   * A whole scan of the locked paths, which is what a clunk and a teardown each
   * cost. There is no per-client index because one would have to be kept true
   * across {@link P9LockTable.remap} as well, and an index that goes stale
   * across a rename is how a lock outlives the client that took it — the one
   * failure this table exists to make impossible. Locked paths are few; a scan
   * of them is not the cost worth optimizing first.
   */
  #drop(matches: (lock: P9Lock) => boolean): void {
    for (const [path, file] of this.#files) {
      const kept = file.locks.filter((lock) => !matches(lock));
      if (kept.length === file.locks.length) {
        continue;
      }
      file.locks = kept;
      if (kept.length === 0) {
        // Deleting the current key mid-iteration is well defined for a `Map`.
        this.#forget(file, path);
      }
    }
  }

  #bind(file: LockedFile, path: string): LockedFile {
    file.paths.add(path);
    this.#files.set(path, file);
    return file;
  }

  #forget(file: LockedFile, path: string): void {
    file.paths.delete(path);
    this.#files.delete(path);
  }
}

/**
 * The lock type a *held* range may have: `RDLCK` or `WRLCK`, never anything
 * else.
 *
 * `EINVAL` rather than {@link P9_LOCK_ERROR} for the rest, `UNLCK` included
 * where it is not meaningful: a type byte that is not a lock type is a
 * malformed request, and `P9_LOCK_ERROR` reaches userspace as `ENOLCK` — "no
 * locks available", which would send a reader looking for a full lock table
 * that does not exist.
 */
function requireHeldType(type: number): number {
  if (type !== P9_LOCK_TYPE_RDLCK && type !== P9_LOCK_TYPE_WRLCK) {
    throw fsError("EINVAL", { message: `EINVAL: ${type} is not a lock type that can be held` });
  }
  return type;
}
