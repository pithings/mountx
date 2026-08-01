/**
 * WebDAV write locks: the table behind class 2 (RFC 4918 §6, §7).
 *
 * **This is not `src/9p/locks.ts`**, and the difference is the whole design. A
 * 9P record lock is a POSIX byte range owned by a `(client_id, proc_id)` pair
 * the client puts on the wire; a WebDAV lock is a *whole resource* — or a whole
 * subtree — owned by a token **this server minted** and handed back, and the
 * only thing that proves ownership is a client repeating that token in an `If`
 * header (§7.5). Nothing here overlaps, splits or coalesces: a lock covers a
 * path, or a path and everything under it, and that is the entire geometry.
 *
 * **This is not `src/lock.ts` either.** `PathLock` serializes a session's own
 * work against its renames within one process; nothing in this file blocks
 * anything. What is here is state a *client* created and can come back for
 * minutes later, over a different connection.
 *
 * ## Pure, synchronous and clockless
 *
 * No `await`, no `Date.now()`, no timer. Every method that cares about time
 * takes `now` as a millisecond argument, exactly the way `src/http.ts` and
 * `src/s3/sigv4.ts` do, so the whole lease lifecycle is testable without
 * waiting for one — and so `WebdavSession` remains the single place a real
 * clock enters (`options.now`). The token generator is an option for the same
 * reason: {@link DavLockTable} with a counter for `newToken` produces the same
 * documents on every run.
 *
 * Expiry is therefore **lazy**: there is no timer sweeping the table, and a
 * lapsed lock stops existing the next time anything looks at the table with a
 * `now` past its deadline. §6.6 asks for exactly that shape ("if the timeout
 * expires, then the lock SHOULD be removed ... the server SHOULD act as if an
 * UNLOCK method was executed"), and it is also what a client is told to expect:
 * "clients MUST assume that locks can arbitrarily disappear at any time".
 *
 * ## Scope: what a lock covers
 *
 * §7.4 defines two, and both are here:
 *
 * - **Depth 0** — the lock root itself. On a collection that is the collection
 *   and its membership: creating, removing or renaming an internal member of it
 *   needs the token, while the members' own contents do not.
 * - **Depth infinity** — the root and every resource under it, which §6.1
 *   calls *indirectly* locked. Membership changes move resources in and out of
 *   that set as they happen; nothing is recorded per member, because the set is
 *   a prefix test ({@link DavLockTable.covering}) rather than a list.
 *
 * `Depth: 1` is not a lock scope RFC 4918 has — §9.10.3 says values other than
 * `0` or `infinity` "MUST NOT be used" — so {@link LockDepth} has two members
 * and the refusal happens in the session, at the header.
 *
 * ## Conflicts
 *
 * §9.10.5's compatibility table, in one sentence: two locks whose scopes
 * overlap conflict unless **both** are shared. That covers the indirect cases
 * §6.1 point 3 insists on ("whether either lock is direct or indirect"), and
 * the one §7.4 spells out — a depth-infinity `LOCK` over a subtree that already
 * holds a conflicting lock is `423`, which is why {@link DavLockTable.conflict}
 * looks *down* the tree as well as up it.
 *
 * ## A lock never follows its resource
 *
 * The sharpest contrast with `src/9p/locks.ts`, which remaps its ranges across
 * a rename. Here §7.6 is explicit: "a successful MOVE request on a write locked
 * resource MUST NOT move the write lock with the resource", and §6.1 point 8
 * settles what happens instead — "if a request causes the lock-root of any lock
 * to become an unmapped URL, then the lock MUST also be deleted by that
 * request". So a `MOVE` or `DELETE` of a lock root **destroys** that lock — the
 * session walks {@link DavLockTable.within} the path it unmapped, checks each
 * root and {@link DavLockTable.remove}s the ones that really went — and the
 * moved resource arrives at its destination unlocked, except for whatever
 * depth-infinity lock already covers the destination, which picks it up for free
 * because coverage is a prefix test.
 *
 * ## Why the lookups are linear
 *
 * Every query walks the map. A share holds tens of locks, not thousands, and
 * {@link MAX_LOCKS} makes that a bound rather than an assumption — while the
 * queries that matter (`covering`, `conflict`) are prefix tests over a path,
 * which no index this small would beat. The map is keyed by token because that
 * is the one lookup with an exact key: `UNLOCK` and every `If` header name a
 * lock by its token and nothing else.
 */

import { randomUUID } from "node:crypto";
import { isPathInside } from "../path.ts";
import type { XmlNode } from "../xml.ts";
import {
  DEFAULT_LOCK_TIMEOUT_SECONDS,
  LOCK_TOKEN_PREFIX,
  MAX_LOCK_TIMEOUT_SECONDS,
  MAX_LOCKS,
} from "./constants.ts";

// ---------------------------------------------------------------------------
// what a lock is
// ---------------------------------------------------------------------------

/**
 * The two lock scopes RFC 4918 §9.10.3 allows on the `Depth` header of a
 * `LOCK`. `1` is not one of them.
 */
export type LockDepth = 0 | "infinity";

/**
 * One active write lock.
 *
 * Every field is `readonly` and a refresh replaces the whole record rather than
 * mutating one ({@link DavLockTable.refresh}), so a lock handed to a caller is
 * a snapshot that cannot change under it while it renders a document from it.
 */
export interface DavLock {
  /** The token, `urn:uuid:…` — globally unique, and the only proof of
   * ownership there is (§6.5). */
  readonly token: string;
  /** The lock root as a driver path: the resource the `LOCK` named (§14.12). */
  readonly path: string;
  /**
   * Was the lock root a collection when the lock was taken?
   *
   * Carried only so `lockroot`'s `href` can end in `/` for one (§5.2), and
   * never re-read: a resource that changed kind under a live lock is a resource
   * that was deleted and recreated, which took the lock with it (§6.1 point 8).
   */
  readonly collection: boolean;
  /** `0` or `infinity` — see the module docs on what each covers (§7.4). */
  readonly depth: LockDepth;
  /** Exclusive (§14.6) rather than shared (§14.27). */
  readonly exclusive: boolean;
  /**
   * The client's `<owner>` element, preserved verbatim as §9.10.1 requires
   * ("the server MUST preserve the information provided by the client in the
   * 'owner' element"), or `undefined` when the request carried none — §14.11
   * makes it optional.
   *
   * Kept by reference and never read for meaning: the node comes from a body
   * that was buffered, parsed into fresh objects and then dropped, so there is
   * nothing here aliasing a transport buffer (`AGENTS.md`, invariant 12).
   */
  readonly owner: XmlNode | undefined;
  /** The lease granted, in seconds — what the reply's `timeout` element said
   * when the lock was taken or last refreshed. */
  readonly timeoutSeconds: number;
  /** When the lease lapses, in milliseconds since the epoch. */
  readonly expiresAt: number;
}

/** What a `LOCK` asks for, once the session has read the headers and body. */
export interface DavLockRequest {
  path: string;
  collection: boolean;
  depth: LockDepth;
  exclusive: boolean;
  owner?: XmlNode | undefined;
  /**
   * The `Timeout` header's request, in seconds, or `"infinite"` for
   * `Timeout: Infinite` — both only ever *suggestions* (§6.6). Absent means the
   * client asked for nothing.
   */
  timeoutSeconds?: number | "infinite" | undefined;
}

/**
 * The outcome of a {@link DavLockTable.create}: the lock, the one that stopped
 * it, or a full table.
 *
 * A union rather than a throw because this module is pure: the three outcomes
 * are `200`/`201`, `423 no-conflicting-lock` and `503`, and choosing between
 * them is the session's job, not this file's.
 */
export type DavLockGrant =
  | { kind: "granted"; lock: DavLock }
  | { kind: "conflict"; lock: DavLock }
  | { kind: "full" };

// ---------------------------------------------------------------------------
// the table
// ---------------------------------------------------------------------------

export interface DavLockTableOptions {
  /** Lease for a `LOCK` that asked for nothing, in seconds. Default
   * {@link DEFAULT_LOCK_TIMEOUT_SECONDS}. */
  defaultTimeoutSeconds?: number;
  /** Longest lease granted, in seconds, and what `Timeout: Infinite` becomes.
   * Default {@link MAX_LOCK_TIMEOUT_SECONDS}. */
  maxTimeoutSeconds?: number;
  /** Most live locks at once. Default {@link MAX_LOCKS}. */
  maxLocks?: number;
  /**
   * The token minter. Default `urn:uuid:` + `randomUUID()`.
   *
   * The one impure default in this file, and it is an option for the same
   * reason `S3SessionOptions.now` is: a deterministic minter makes a whole
   * `LOCK` reply — headers, `locktoken`, `lockdiscovery` — a fixture that can
   * be compared byte for byte.
   */
  newToken?: () => string;
}

/**
 * Every write lock one share holds.
 *
 * ```ts
 * const locks = new DavLockTable();
 * const grant = locks.create(
 *   { path: "/notes", collection: true, depth: "infinity", exclusive: true },
 *   Date.now(),
 * );
 * // grant.kind === "granted" → grant.lock.token goes in `Lock-Token`
 * ```
 */
export class DavLockTable {
  readonly #locks = new Map<string, DavLock>();
  readonly #defaultTimeout: number;
  readonly #maxTimeout: number;
  readonly #maxLocks: number;
  readonly #newToken: () => string;

  constructor(options: DavLockTableOptions = {}) {
    this.#defaultTimeout = options.defaultTimeoutSeconds ?? DEFAULT_LOCK_TIMEOUT_SECONDS;
    this.#maxTimeout = options.maxTimeoutSeconds ?? MAX_LOCK_TIMEOUT_SECONDS;
    this.#maxLocks = options.maxLocks ?? MAX_LOCKS;
    this.#newToken = options.newToken ?? (() => `${LOCK_TOKEN_PREFIX}${randomUUID()}`);
  }

  /** Live locks, expired ones swept first — so this is what a client could
   * still be holding, not what was ever taken. */
  size(now: number): number {
    this.#sweep(now);
    return this.#locks.size;
  }

  /**
   * Every lock still alive at `now`, in the order they were granted.
   *
   * For tests and for a caller that wants to see the whole table; nothing in
   * the protocol asks for it.
   */
  all(now: number): DavLock[] {
    this.#sweep(now);
    return [...this.#locks.values()];
  }

  /**
   * The locks whose **scope covers** this path: one rooted exactly here, and
   * every depth-infinity lock rooted above it (§6.1 point 4, §7.4).
   *
   * This is the answer to "is this resource locked" for a request that changes
   * the resource itself — its bytes, or its properties — and it is what
   * `lockdiscovery` reports (§15.8), which is why an indirectly locked member
   * shows the ancestor's lock rather than nothing.
   */
  covering(path: string, now: number): DavLock[] {
    this.#sweep(now);
    const covering: DavLock[] = [];
    for (const lock of this.#locks.values()) {
      if (lock.path === path || (lock.depth === "infinity" && isPathInside(path, lock.path))) {
        covering.push(lock);
      }
    }
    return covering;
  }

  /**
   * The locks **rooted at or under** this path.
   *
   * The other direction, and it answers a different question: not "is this
   * resource locked" but "does removing this subtree remove somebody's lock
   * root". `DELETE` and `MOVE` need it for §6.1 point 8, and a depth-infinity
   * `LOCK` needs it for §7.4's "collection containing member URLs identifying
   * resources that are currently locked".
   */
  within(path: string, now: number): DavLock[] {
    this.#sweep(now);
    const within: DavLock[] = [];
    for (const lock of this.#locks.values()) {
      if (isPathInside(lock.path, path)) {
        within.push(lock);
      }
    }
    return within;
  }

  /** The lock this token names, if it is still alive. */
  find(token: string, now: number): DavLock | undefined {
    this.#sweep(now);
    return this.#locks.get(token);
  }

  /**
   * Is `path` inside the scope of this lock (§9.11: "the Request-URI MUST
   * identify a resource within the scope of the lock")?
   *
   * The lock root itself always is; a member is only inside a depth-infinity
   * one. Static because it is a fact about the record rather than about the
   * table.
   */
  static inScope(lock: DavLock, path: string): boolean {
    return lock.path === path || (lock.depth === "infinity" && isPathInside(path, lock.path));
  }

  /**
   * The lock that would stop this request, or `undefined` if the scope is
   * clear (§9.10.5's compatibility table).
   *
   * Two locks conflict when their scopes overlap and at least one is exclusive;
   * two shared locks never do, which is the entire point of a shared lock
   * (§6.2). Overlap is checked **both ways**: up the tree through
   * {@link DavLockTable.covering}, and — for a depth-infinity request only —
   * down it through {@link DavLockTable.within}, because a depth-infinity lock
   * over a subtree holding a conflicting lock is the case §7.4 makes a `423`.
   */
  conflict(path: string, depth: LockDepth, exclusive: boolean, now: number): DavLock | undefined {
    const candidates =
      depth === "infinity"
        ? [...this.covering(path, now), ...this.within(path, now)]
        : this.covering(path, now);
    return candidates.find((lock) => exclusive || lock.exclusive);
  }

  /**
   * Take a new lock, or say why not.
   *
   * The caller has already decided the request is legal — that the depth is one
   * of two, that the lock type is `write`, that the resource exists or has just
   * been created for it (§7.3). What is decided *here* is the compatibility
   * table, the table's own cap, and the lease.
   */
  create(request: DavLockRequest, now: number): DavLockGrant {
    const conflict = this.conflict(request.path, request.depth, request.exclusive, now);
    if (conflict !== undefined) {
      return { kind: "conflict", lock: conflict };
    }
    /* `size` swept, so the cap is measured against live locks only: a table
       full of lapsed ones is not full. */
    if (this.size(now) >= this.#maxLocks) {
      return { kind: "full" };
    }
    const timeoutSeconds = this.#grantedTimeout(request.timeoutSeconds);
    const lock: DavLock = {
      token: this.#newToken(),
      path: request.path,
      collection: request.collection,
      depth: request.depth,
      exclusive: request.exclusive,
      owner: request.owner,
      timeoutSeconds,
      expiresAt: now + timeoutSeconds * 1000,
    };
    this.#locks.set(lock.token, lock);
    return { kind: "granted", lock };
  }

  /**
   * Restart a lock's lease (§9.10.2), and answer the record that replaced it —
   * or `undefined` for a token that names no live lock.
   *
   * §6.6: "the timeout counter MUST be restarted if a refresh lock request is
   * successful", and the new lease is the server's to choose again, which is
   * why a refresh with no `Timeout` header goes back to the default rather than
   * keeping whatever the last one was. Everything else about the lock — scope,
   * owner, token — is untouched: a refresh is a new deadline, not a new lock.
   */
  refresh(
    token: string,
    requested: number | "infinite" | undefined,
    now: number,
  ): DavLock | undefined {
    const existing = this.find(token, now);
    if (existing === undefined) {
      return undefined;
    }
    const timeoutSeconds = this.#grantedTimeout(requested);
    const refreshed: DavLock = {
      ...existing,
      timeoutSeconds,
      expiresAt: now + timeoutSeconds * 1000,
    };
    this.#locks.set(token, refreshed);
    return refreshed;
  }

  /** Delete one lock by token, and say whether there was one (`UNLOCK`, §9.11). */
  remove(token: string): boolean {
    return this.#locks.delete(token);
  }

  /**
   * Seconds left on a lease, for the `timeout` element (§14.29: "the number of
   * seconds remaining before a lock expires").
   *
   * Rounded **down**, and never below zero: a client told `Second-1` has at
   * most a second, which errs toward refreshing early.
   */
  static remaining(lock: DavLock, now: number): number {
    return Math.max(0, Math.floor((lock.expiresAt - now) / 1000));
  }

  /**
   * The lease this server grants for what the client asked (§6.6, §10.7).
   *
   * Absent is the default; `Infinite` is the maximum, because an unbounded lock
   * on a server with no way to break one is a resource nobody can recover; a
   * number is honoured up to that maximum and floored at one second, since a
   * zero-second lock would be granted and gone in the same reply.
   */
  #grantedTimeout(requested: number | "infinite" | undefined): number {
    if (requested === undefined) {
      return this.#defaultTimeout;
    }
    if (requested === "infinite") {
      return this.#maxTimeout;
    }
    return Math.max(1, Math.min(Math.trunc(requested), this.#maxTimeout));
  }

  /** Drop everything whose lease has lapsed at `now` (§6.6). */
  #sweep(now: number): void {
    for (const [token, lock] of this.#locks) {
      if (lock.expiresAt <= now) {
        this.#locks.delete(token);
      }
    }
  }
}
