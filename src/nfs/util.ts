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
import type { FileHandleTable } from "./handles.ts";
import type { RpcCall, RpcCredentials } from "./rpc.ts";

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
 * NFSv4.1-only knobs, forwarded verbatim to `v4/state.ts`'s `Nfs4State`.
 *
 * Spelled out here rather than imported so the shared layer names nothing from
 * `v4/`; it is structurally a subset of `Nfs4StateOptions`, which is what makes
 * the forward a spread rather than a translation.
 */
export interface Nfs4StateKnobs {
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
  /** Largest `READ` answered. */
  rtmax?: number;
  /** Largest `WRITE` accepted. */
  wtmax?: number;
  /** Directory snapshots kept for readdir cookies. Default `64`. */
  snapshotCache?: number;
  /**
   * `chown` a newly created entry to the `AUTH_SYS` uid/gid the request
   * carried. Default `true`.
   *
   * The same problem the FUSE session solves the same way: the driver creates
   * everything as the server process, while the requests arriving on it come
   * from whoever mounted the share. Quiet when the driver has no `lchown`, or
   * when the server is not privileged enough to hand ownership away — a driver
   * with no concept of ownership is not thereby broken.
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
