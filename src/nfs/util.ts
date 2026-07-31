/**
 * The pieces both NFS versions need, and neither owns.
 *
 * `v3/` and `v4/` never import from each other, so anything the second version
 * turns out to need from the first moves down here — and only then. This file
 * is that pressure valve, and it stays deliberately small: everything in it is
 * either **version-neutral logic** (a POSIX permission decision, a POSIX file
 * type) or the **session contract the router owns** (the options bag, the
 * counters, the objects one server shares across its versions).
 *
 * What is *not* here is as deliberate: no wire constant. `ACCESS3_*` and
 * `ACCESS4_*` happen to be the same six numbers, and `ftype3` and `nfs_ftype4`
 * the same seven, but they are transcribed from RFC 1813 and RFC 8881
 * respectively and each version keeps its own copy. {@link allowedAccess}
 * therefore answers with a *structure* rather than a bitmask, and each session
 * maps that onto its own constants — which is what keeps this file honest
 * against the "wire constants are transcribed, never borrowed" invariant.
 */

import type { PathLock } from "../lock.ts";
import type { StatsLike } from "../types.ts";
import { S_IFDIR, S_IFMT } from "../types.ts";
import { sameVerifier, type FileHandleTable } from "./handles.ts";
import { copyBytes, type RpcCall, type RpcCredentials } from "./rpc.ts";

/**
 * The largest offset either version can name.
 *
 * `offset4`/`offset3` are 64 bits, but the driver interface takes `number`
 * offsets, so anything past `Number.MAX_SAFE_INTEGER` cannot be passed on and
 * is refused rather than silently rounded. It is also what both versions report
 * as the largest file they will name (`FSINFO.maxfilesize`, `fattr4_maxfilesize`),
 * so a client is told before it tries.
 */
export const MAX_OFFSET = BigInt(Number.MAX_SAFE_INTEGER);

/** Bytes in one path component, and the `name_max`/`maxname` both versions report. */
export const NAME_MAX = 255;

// ---------------------------------------------------------------------------
// the session contract
// ---------------------------------------------------------------------------

/**
 * How a uid or gid becomes an `owner`/`owner_group` string, and back
 * (RFC 8881 §5.9).
 *
 * NFSv4 carries ownership as a `utf8str_mixed` of the form `user@dns_domain`
 * rather than as a number, and §5.9 leaves the translation entirely to the
 * implementation: "The translation used to interpret owner and group strings is
 * not specified as part of the protocol." Configure nothing and the v4 session
 * speaks only the numeric form §5.9 also allows ("owner and group strings that
 * consist of decimal numeric values with no leading zeros can be given a
 * special interpretation"), which is what a Linux client falls back to when its
 * own idmapper has nothing to say.
 *
 * Both hooks are synchronous, because a COMPOUND consults them between two
 * driver calls; a map that needs a network service should keep its own cache
 * behind these.
 */
export interface Nfs4IdMap {
  /**
   * The one DNS domain this server maps names in.
   *
   * Used in both directions: a {@link Nfs4IdMap.nameOf} result with no `@` in
   * it is qualified with this domain on the way out, and an incoming
   * `user@other.example` — a domain this server does not serve — is
   * `NFS4ERR_BADOWNER` without {@link Nfs4IdMap.idOf} being asked at all, which
   * §5.9 permits: "A server may treat other domains as having no valid
   * translations."
   */
  domain?: string | undefined;
  /**
   * A uid (or gid, when `group`) as the string to put on the wire.
   *
   * `undefined` falls back to the numeric form, which is §5.9's "in the case
   * where there is no translation available ... the attribute value will be
   * constructed without the '@'".
   */
  nameOf?: ((id: number, group: boolean) => string | undefined) | undefined;
  /**
   * The uid (or gid, when `group`) a wire string names, with the domain
   * suffix already stripped when it matched {@link Nfs4IdMap.domain}.
   *
   * `undefined` is `NFS4ERR_BADOWNER`, which §5.9 makes the answer for a string
   * with no translation.
   */
  idOf?: ((name: string, group: boolean) => number | undefined) | undefined;
}

/**
 * NFSv4.1-only knobs.
 *
 * Spelled out here rather than imported so the shared layer names nothing from
 * `v4/`; everything but {@link Nfs4StateKnobs.idmap} is structurally a subset
 * of `Nfs4StateOptions` and is forwarded verbatim to `v4/state.ts`'s
 * `Nfs4State`. The ID map is the session's own — the state table deals in
 * client IDs and stateids and has no idea what a uid is — so it is destructured
 * out before the rest is handed on.
 */
export interface Nfs4StateKnobs {
  /** How uids and gids become `owner`/`owner_group` strings. Default: numeric only. */
  idmap?: Nfs4IdMap | undefined;
  /** Milliseconds since an arbitrary epoch. Default `Date.now`. */
  now?: (() => number) | undefined;
  /** Lease length in seconds. Default 90. */
  leaseSeconds?: number | undefined;
  /** Folded into every id the state table mints, so two instances differ. */
  seed?: number | undefined;
  /** Sessions one client may hold at once. */
  maxSessions?: number | undefined;
  /** Fore-channel slots, the `ca_maxrequests` counter-offer ceiling. */
  maxForeSlots?: number | undefined;
  /** `ca_maxoperations` counter-offer ceiling, and the pre-session COMPOUND cap. */
  maxOperations?: number | undefined;
  /** `ca_maxrequestsize`/`ca_maxresponsesize` ceiling. */
  maxRequestSize?: number | undefined;
  /** `ca_maxresponsesize_cached` ceiling. */
  maxCachedResponseSize?: number | undefined;
  /** Opens one file may carry across all clients. */
  maxOpensPerFile?: number | undefined;
  /** Granted byte ranges one file may carry. */
  maxLocksPerFile?: number | undefined;
  /** Enforce RFC 8881 §18.51.3's "RECLAIM_COMPLETE before the first lock". */
  requireReclaimComplete?: boolean | undefined;
}

/**
 * One options bag for the whole server, whichever version answers.
 *
 * It lives here rather than in either version because the router builds one of
 * these and hands the same object to both sessions.
 */
export interface NfsSessionOptions {
  /** Identify files by the driver's `(dev, ino)`, so hardlinks share a handle. Default `true`. */
  useDriverIno?: boolean;
  /** Boot verifier for file handles. Default: random, so restarts invalidate handles. */
  verifier?: Uint8Array;
  /**
   * Most file handle table entries to keep, the least recently used going
   * first past it. Default: no cap, which is what this server has always done.
   *
   * An eviction costs the client holding that handle an `ESTALE` and a
   * re-lookup — and an NFSv4.1 client that had the file **open** its share
   * reservation, since the re-lookup is a different entry id and so a different
   * `FileState`. A cap below the largest READDIRPLUS page a client asks for is
   * also self-defeating. Read `./handles.ts` before setting it.
   */
  maxHandles?: number;
  /** Largest `READ` answered. */
  rtmax?: number;
  /** Largest `WRITE` accepted. */
  wtmax?: number;
  /** Directory snapshots kept for readdir cookies. Default `64`. */
  snapshotCache?: number;
  /**
   * `chown` a newly created entry to the `AUTH_SYS` uid the request carried,
   * and to the group POSIX gives it. Default `true`.
   *
   * The same problem the FUSE session solves the same way: the driver creates
   * everything as the server process, while the requests arriving on it come
   * from whoever mounted the share. Quiet when the driver has no `lchown`, or
   * when the server is not privileged enough to hand ownership away — a driver
   * with no concept of ownership is not thereby broken.
   *
   * The group is not always the caller's: a set-gid parent directory hands its
   * own down and a new directory takes the bit with it, which is `chmod`'s job
   * and so is gated by this option too (`src/ownership.ts`). Turning it off
   * leaves every new entry exactly as the driver made it.
   */
  claimOwnership?: boolean;
  /** Called for every request that ends in an error status. */
  onError?: (error: unknown, call: RpcCall | undefined) => void;
  /** NFSv4.1 state-machine knobs. Ignored by the v3 session. */
  nfs4?: Nfs4StateKnobs | undefined;
}

/** Counters, all cheap, all useful in a test. Shared across the versions. */
export interface NfsSessionStats {
  /** RPC records handed to a session's `handleCall`. */
  requests: number;
  /** Replies produced (successful or not). */
  replies: number;
  /** Of which replies carrying a non-success status. */
  errors: number;
  /** Records too malformed to answer at all. */
  dropped: number;
  /** Per-procedure counts, keyed `"NFS:LOOKUP"` / `"MOUNT:MNT"` / `"NFS4:COMPOUND"`. */
  procedures: Map<string, number>;
}

/** A zeroed {@link NfsSessionStats}. */
export function newSessionStats(): NfsSessionStats {
  return { requests: 0, replies: 0, errors: 0, dropped: 0, procedures: new Map() };
}

/**
 * How long one exclusive-create verifier is remembered: two minutes.
 *
 * The thing being survived is a **retransmission**, not an outage: the client
 * resends because it never saw the reply, and it resends on an RPC timeout —
 * seconds, doubling, a handful of times. Two minutes is generous against that
 * and short enough that the table empties itself on any idle server.
 */
export const EXCLUSIVE_CREATE_WINDOW_MS = 120_000;

/** How many exclusive-create verifiers are remembered at once. */
export const DEFAULT_EXCLUSIVE_CREATES = 256;

/** One remembered exclusive create. */
export interface ExclusiveCreate {
  /** The verifier the client sent, copied out of its request. */
  readonly verifier: Uint8Array;
  /**
   * The attribute bits the original request actually applied, so a replay
   * answers with the same `attrset` the lost reply carried. Always empty for
   * v3, whose `EXCLUSIVE` carries no `sattr3` at all.
   */
  readonly attrset: readonly number[];
  /** When it was recorded, for the window. */
  readonly at: number;
}

/** Knobs for {@link ExclusiveCreates}; the defaults are the two constants above. */
export interface ExclusiveCreatesOptions {
  /** Entries kept at once. Default {@link DEFAULT_EXCLUSIVE_CREATES}. */
  limit?: number | undefined;
  /** How long one is remembered. Default {@link EXCLUSIVE_CREATE_WINDOW_MS}. */
  windowMs?: number | undefined;
  /** Milliseconds since an arbitrary epoch. Default `Date.now`. */
  now?: (() => number) | undefined;
}

/**
 * The verifiers of exclusive creates, for exactly as long as a retry can take.
 *
 * `CREATE` with `EXCLUSIVE` (RFC 1813 §3.3.8) and OPEN with `EXCLUSIVE4` /
 * `EXCLUSIVE4_1` (RFC 8881 §18.16.3) ask a server for the same one thing: keep
 * the client's verifier beside the file it created, so that the *duplicate* of
 * a request whose reply was lost recognises its own creation and is answered
 * with it instead of `EXIST`. That is the whole feature — an exclusive create
 * is the one operation a client cannot make idempotent by itself.
 *
 * **This is a table in memory, and it says so.** Both RFCs would rather it were
 * not: §3.3.8 wants the verifier in stable storage, and §18.16.4 names "the
 * requirement to commit the verifier to stable storage" as the reason a server
 * may refuse the mode outright. There is nowhere in `FsDriver` to commit one to
 * — it would want an xattr — so what is kept here survives a lost reply and a
 * retransmission, **and nothing else**. A restarted server has forgotten every
 * verifier, exactly as it has forgotten every file handle (`../handles.ts`) and
 * for the same reason; a client retrying across a restart is told `EXIST` by
 * the create that follows, which is what it would have had from `GUARDED`.
 *
 * **Bounded twice**, in the spirit `../handles.ts` states its own growth:
 *
 * - **By age.** An entry older than the window is not matched, and is dropped
 *   when it is next looked at. A lookup does *not* refresh it — the window is
 *   about how long the original request can still be in flight, and re-reading
 *   the entry does not make that longer.
 * - **By count.** `limit` entries, oldest insertion evicted first, so a client
 *   creating exclusively in a loop cannot grow this without bound.
 *
 * Both edges fail the same safe way: the retry stops being recognised and gets
 * `EXIST`, which is a worse answer than the RFC's but never a wrong file.
 *
 * An entry is dropped as soon as it cannot mean anything: the file was removed
 * or renamed away (a later file at that path is a different file, and must not
 * inherit the promise), or the client sent the SETATTR that §3.3.8 makes the
 * commit — the follow-up that carries the attributes an exclusive create had
 * nowhere to put, after which there is nothing left for the verifier to
 * protect.
 */
export class ExclusiveCreates {
  readonly #entries = new Map<string, ExclusiveCreate>();
  readonly #limit: number;
  readonly #windowMs: number;
  readonly #now: () => number;

  constructor(options: ExclusiveCreatesOptions = {}) {
    this.#limit = Math.max(1, options.limit ?? DEFAULT_EXCLUSIVE_CREATES);
    this.#windowMs = Math.max(0, options.windowMs ?? EXCLUSIVE_CREATE_WINDOW_MS);
    this.#now = options.now ?? Date.now;
  }

  /** Entries held, expired ones included until something looks at them. */
  get size(): number {
    return this.#entries.size;
  }

  /** Remember `verifier` as the one that created `path`. */
  set(path: string, verifier: Uint8Array, attrset: readonly number[] = []): void {
    // Copied, both of them: this outlives the request they were decoded from,
    // and `attrset` is the caller's own array, still being pushed to. The copy
    // is `copyBytes` and not `verifier.slice()` because `handleCall` is public
    // and takes any `Uint8Array`: hand it a `Buffer` and `.slice()` is
    // `subarray`, which would leave this table holding a view of somebody
    // else's receive buffer for the next two minutes.
    const entry: ExclusiveCreate = {
      verifier: copyBytes(verifier),
      attrset: [...attrset],
      at: this.#now(),
    };
    // Delete first, so the Map's insertion order stays the eviction order.
    this.#entries.delete(path);
    this.#entries.set(path, entry);
    while (this.#entries.size > this.#limit) {
      const oldest = this.#entries.keys().next().value!;
      this.#entries.delete(oldest);
    }
  }

  /**
   * The record at `path` when `verifier` is the one that created it.
   *
   * `undefined` for every other case — nothing remembered, the window passed,
   * or a *different* verifier, which is a second client racing for the same
   * name and is the one case that genuinely is `EXIST`.
   */
  match(path: string, verifier: Uint8Array): ExclusiveCreate | undefined {
    const entry = this.#entries.get(path);
    if (entry === undefined) {
      return undefined;
    }
    if (this.#now() - entry.at >= this.#windowMs) {
      this.#entries.delete(path);
      return undefined;
    }
    return sameVerifier(entry.verifier, verifier) ? entry : undefined;
  }

  /**
   * Forget `path`, and everything under it.
   *
   * The subtree sweep is for the one caller that needs it — a renamed or
   * removed *directory* takes every remembered name below it with it — and is
   * a walk of a table capped at `limit`, which is why it does not need the
   * index `../subtree.ts` builds for the handle table.
   *
   * The root is the one path this cannot sweep, its prefix being `//`, and
   * that is the wanted answer rather than an edge case: `/` is never removed
   * or renamed, and a SETATTR on it is about the directory, not about the
   * files inside it.
   */
  forget(path: string): void {
    if (this.#entries.size === 0) {
      return;
    }
    this.#entries.delete(path);
    const prefix = `${path}/`;
    for (const key of this.#entries.keys()) {
      if (key.startsWith(prefix)) {
        this.#entries.delete(key);
      }
    }
  }

  clear(): void {
    this.#entries.clear();
  }
}

/** What the caller of a request is, as far as `AUTH_SYS` can say. */
export interface NfsRequestContext {
  /** Remote address, for `DUMP` and for logging. */
  peer?: string;
}

/**
 * The objects one server shares across every version it speaks.
 *
 * The router constructs these once and passes them into each versioned
 * session, so one path maps to one file handle whichever version a client used
 * to obtain it, one `RENAME` excludes readers on both, and the counters add up
 * across the pair. Every field is optional: a versioned session constructed on
 * its own (which is what its unit tests do) makes its own.
 */
export interface NfsSharedState {
  /** fh ↔ path ↔ `(dev, ino)`, for the lifetime of the server. */
  handles?: FileHandleTable | undefined;
  /** The single writer / many readers lock over the path map. */
  lock?: PathLock | undefined;
  /** The counters both versions increment. */
  stats?: NfsSessionStats | undefined;
  /**
   * The verifiers of exclusive creates still worth remembering.
   *
   * Shared for the same reason the handle table is: a client that created a
   * file exclusively over v3 and retransmits over v4 (or the reverse — the two
   * are one server on one port) must be answered from one table, or the same
   * request gets two different answers depending on which version carried it.
   */
  exclusiveCreates?: ExclusiveCreates | undefined;
}

// ---------------------------------------------------------------------------
// version-neutral POSIX decisions
// ---------------------------------------------------------------------------

/**
 * What a caller may do with an object, as booleans rather than wire bits.
 *
 * Each field is the *question* both versions' ACCESS operations ask, and each
 * session maps the answer onto its own `ACCESS3_*` / `ACCESS4_*` constants.
 */
export interface AccessRights {
  /** Read data from a file, or read a directory. */
  read: boolean;
  /** Look up a name in a directory. Never set for a non-directory. */
  lookup: boolean;
  /** Rewrite existing file data, or modify existing directory entries. */
  modify: boolean;
  /** Write new data, or add directory entries. */
  extend: boolean;
  /** Delete an existing directory entry. Only ever set for a directory. */
  delete: boolean;
  /** Execute a regular file. Never set for a directory. */
  execute: boolean;
}

/**
 * What a caller with these credentials may do with this object, by mode bits.
 *
 * The client asks because it is about to make a permission decision and NFS
 * gives it nothing else to decide with. The answer is computed from the
 * driver's mode/uid/gid against the `AUTH_SYS` credentials, which is exactly as
 * trustworthy as `AUTH_SYS` — the real enforcement is the socket, and the
 * kernel's own checks once the share is mounted. A driver with no permission
 * model reports mode `0` for everything, and then this correctly says "no",
 * which is why a session only ever masks these bits *down* from what was asked.
 *
 * Plain POSIX: owner, then group, then other; uid 0 gets everything except
 * `execute` on something with no execute bit at all, which is the one place
 * root is not omnipotent.
 */
export function allowedAccess(stats: StatsLike, creds: RpcCredentials): AccessRights {
  const isDir = (stats.mode & S_IFMT) === S_IFDIR;
  const mode = stats.mode & 0o777;
  const uid = creds.uid ?? 0;
  const gid = creds.gid ?? 0;
  const root = uid === 0;
  const bits = root
    ? 0b111
    : uid === stats.uid
      ? (mode >> 6) & 0b111
      : gid === stats.gid || creds.gids.includes(stats.gid)
        ? (mode >> 3) & 0b111
        : mode & 0b111;
  const readable = (bits & 0b100) !== 0;
  const writable = (bits & 0b010) !== 0;
  const executable = root ? (mode & 0o111) !== 0 || isDir : (bits & 0b001) !== 0;

  return {
    read: readable,
    lookup: executable && isDir,
    modify: writable,
    extend: writable,
    delete: writable && isDir,
    execute: executable && !isDir,
  };
}

/**
 * The `S_IF*` bits a file type number is asking for.
 *
 * The four device-ish types only, which are the ones neither `node:fs` nor the
 * driver interface can name and that only `mountx.mknod` can create. The
 * numbering is the same in both protocols — RFC 1813's `ftype3` and RFC 8881
 * §5.8.1.2's `nfs_ftype4` agree on 3/4/6/7 for BLK/CHR/SOCK/FIFO — and each
 * version passes its own constant in, so nothing here is a borrowed value.
 */
export function modeBitsOfFtype(type: number): number {
  switch (type) {
    case 3: {
      return 0o060_000; // S_IFBLK
    }
    case 4: {
      return 0o020_000; // S_IFCHR
    }
    case 6: {
      return 0o140_000; // S_IFSOCK
    }
    case 7: {
      return 0o010_000; // S_IFIFO
    }
    /* v8 ignore next 3 -- creating a directory or a symlink this way is not a
       thing a client asks for; the driver would refuse it anyway. */
    default: {
      return 0;
    }
  }
}
