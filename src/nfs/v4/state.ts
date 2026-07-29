/**
 * NFSv4.1 server state: client IDs, sessions and their reply caches, stateids,
 * share reservations, byte-range locks and the lease clock.
 *
 * NFSv3 was stateless and its server kept two things it could rebuild at will
 * (`../handles.ts`). NFSv4.1 is the opposite: a client *registers* (EXCHANGE_ID),
 * *confirms* (CREATE_SESSION), and from then on every request occupies a numbered
 * slot whose reply the server has to be able to hand back verbatim. Opens, locks
 * and leases hang off that registration. All of it is in this file, and none of
 * it touches a socket, a driver or a filehandle — the session (step 7) resolves
 * paths and calls the driver, then asks this table what the protocol permits.
 *
 * ## Conventions
 *
 * - **A protocol outcome is a returned status, never an exception.** Every
 *   method answers with an object carrying `status: nfsstat4`, and the session
 *   maps it 1:1 into the operation's result. Exceptions are for programmer
 *   error only — a ticket that did not come from {@link Nfs4State.sequence},
 *   an option that cannot be honoured — and the session is not expected to
 *   catch them.
 * - **Nothing here is async.** Every method is synchronous, so a COMPOUND can
 *   consult the table between two awaited driver calls without a window opening
 *   in the middle of a check.
 * - **A file is a caller-chosen opaque key** (`fileKey`), because this table has
 *   no idea what a file is. The session passes the identity its own handle table
 *   uses, and two names for one file must produce one key or the share
 *   reservations of §9.9 will not coalesce.
 * - **Time and identity are injected.** `now()` is the only clock, and every id
 *   this table mints (client IDs, session IDs, stateid `other` values) is a
 *   counter folded with the `seed` option, so a test run is reproducible.
 *   A real server passes a boot-unique `seed`; that is what makes a client ID
 *   from a previous instance recognisable as stale.
 *
 * ## The replay cache, and who owns the bytes
 *
 * `sequence()` reserves a slot and hands back a {@link SlotTicket}; the session
 * finishes the COMPOUND and calls {@link Nfs4State.cacheReply} with the encoded
 * reply. The contract, in both directions:
 *
 * - **On insert the table copies.** `cacheReply` stores a copy of the bytes it
 *   is given, so the session may re-use, re-frame or overwrite its own buffer
 *   the moment the call returns. This is the same rule the decoders keep
 *   (`Buffer.prototype.slice` is `subarray`, not a copy).
 * - **On replay the table hands back its own array, and the session MUST NOT
 *   write to it.** A replay is a read of a stored reply; copying it again per
 *   retransmission would double the cost of the one path that exists to be
 *   cheap. The session writes reply buffers once, before caching them, and
 *   never mutates one afterwards.
 * - **A slot's cached reply is dropped the moment its sequence advances**
 *   (§2.10.6.1: a new request on a slot is proof the previous reply arrived).
 *
 * ## Lease policy: a courteous server
 *
 * §8.4.3 lets a server either free a client's locks the instant its lease
 * expires or keep them "for a considerable period", subject to one MUST: state
 * held under an expired lease may not block a conflicting request. This table
 * takes the courteous option, and revokes in three places:
 *
 * - **On conflict.** {@link Nfs4State.open}, {@link Nfs4State.lock} and
 *   {@link Nfs4State.lockt} revoke the state of any *other* client whose lease
 *   has expired before deciding, so an expired holder never denies anybody.
 * - **On SEQUENCE.** A SEQUENCE arriving after its own lease expired revokes
 *   that client's locking state, sets the sticky
 *   `SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED` bit (§18.46.3) and *renews* the
 *   lease so the session stays usable for the FREE_STATEID acknowledgement the
 *   flag is waiting on. §8.3 allows the renewal ("the server MAY renew the
 *   lease"), and §18.46.3's "MUST be renewed ... except if
 *   SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED" relieves the obligation without
 *   forbidding it.
 * - **On demand.** {@link Nfs4State.sweep} is the hard version, for a server
 *   timer: an expired client is removed outright, sessions and all, so its
 *   sessions answer `NFS4ERR_BADSESSION` and its client ID
 *   `NFS4ERR_STALE_CLIENTID` (§8.4.3's "invalidate the session and the
 *   associated client ID").
 *
 * Revoked stateids survive as tombstones answering `NFS4ERR_EXPIRED`
 * (§8.2.4, §15.1.5.4) until FREE_STATEID acknowledges them (§18.38.3).
 *
 * ## No grace period
 *
 * This server keeps no state across restarts, so there is nothing to reclaim
 * and no grace period to wait out: every reclaim — OPEN with CLAIM_PREVIOUS,
 * LOCK with `reclaim` — answers `NFS4ERR_NO_GRACE`, which is strategy 1 of the
 * two §8.4.3 requires a server to pick between ("Reject all reclaims with
 * NFS4ERR_NO_GRACE. This is extremely unforgiving, but necessary if the server
 * does not record lock state in stable storage") and matches §15.1.9.3's first
 * bullet, "there is no active grace period applying to the file system object
 * for which the request was made".
 *
 * The ordering rule around RECLAIM_COMPLETE is *not* waived by that, and this
 * was checked rather than assumed: §18.51.3 says a client "MUST send a
 * RECLAIM_COMPLETE with rca_one_fs set to FALSE" before its first non-reclaim
 * lock-obtaining operation "even if there are no locks to reclaim", and that
 * "if non-reclaim locking operations are done before the RECLAIM_COMPLETE, an
 * NFS4ERR_GRACE error will be returned". So OPEN and LOCK before the global
 * RECLAIM_COMPLETE answer `NFS4ERR_GRACE` (both list it as a legal error in
 * §15.2's table), and {@link Nfs4StateOptions.requireReclaimComplete} exists to
 * turn that off for tests, not because the rule is optional.
 *
 * ## Bounds
 *
 * Every table here is bounded, because every one of them is fed by a remote
 * peer. The status each cap answers with is the one the RFC sanctions for it:
 * `NFS4ERR_NOSPC` for a session whose reply cache cannot be allocated
 * (§18.36.4, phase 4), and `NFS4ERR_DELAY` — "the replier could not process
 * this operation" (§15.1.1.3) — for the per-file open and lock caps. Not
 * `NFS4ERR_RESOURCE`: it is absent from §15.1's error table and is not a legal
 * NFSv4.1 status.
 */

import {
  EXCHGID4_FLAG_BIND_PRINC_STATEID,
  EXCHGID4_FLAG_CONFIRMED_R,
  EXCHGID4_FLAG_SUPP_MOVED_MIGR,
  EXCHGID4_FLAG_SUPP_MOVED_REFER,
  EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
  EXCHGID4_FLAG_USE_NON_PNFS,
  EXCHGID4_FLAG_USE_PNFS_DS,
  EXCHGID4_FLAG_USE_PNFS_MDS,
  NFS4_MAXFILELEN,
  NFS4_OK,
  NFS4_OTHER_SIZE,
  NFS4_SESSIONID_SIZE,
  NFS4ERR_BAD_HIGH_SLOT,
  NFS4ERR_BAD_STATEID,
  NFS4ERR_BADSESSION,
  NFS4ERR_BADSLOT,
  NFS4ERR_CLIENTID_BUSY,
  NFS4ERR_COMPLETE_ALREADY,
  NFS4ERR_DELAY,
  NFS4ERR_DENIED,
  NFS4ERR_EXPIRED,
  NFS4ERR_GRACE,
  NFS4ERR_INVAL,
  NFS4ERR_LOCKED,
  NFS4ERR_LOCKS_HELD,
  NFS4ERR_NO_GRACE,
  NFS4ERR_NOENT,
  NFS4ERR_NOSPC,
  NFS4ERR_NOT_SAME,
  NFS4ERR_OLD_STATEID,
  NFS4ERR_RETRY_UNCACHED_REP,
  NFS4ERR_SEQ_MISORDERED,
  NFS4ERR_SERVERFAULT,
  NFS4ERR_SHARE_DENIED,
  NFS4ERR_STALE_CLIENTID,
  NFS4ERR_TOOSMALL,
  OPEN4_SHARE_ACCESS_BOTH,
  OPEN4_SHARE_ACCESS_READ,
  OPEN4_SHARE_ACCESS_WANT_DELEG_MASK,
  OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED,
  OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL,
  OPEN4_SHARE_ACCESS_WRITE,
  OPEN4_SHARE_DENY_BOTH,
  READ_LT,
  READW_LT,
  SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED,
  WRITE_LT,
  WRITEW_LT,
} from "./constants.ts";
import type {
  ChannelAttrs4,
  Lock4denied,
  Sequence4args,
  Sequence4res,
  Stateid4,
} from "./protocol.ts";

// ---------------------------------------------------------------------------
// numbers, keys and stateid arithmetic
// ---------------------------------------------------------------------------

/** `NFS4_UINT32_MAX`, the value a `seqid4` wraps at. */
const UINT32_MAX = 0xff_ff_ff_ff;
/** One past the last addressable byte of a file: the exclusive end of a to-EOF lock. */
const EOF_END = 1n << 64n;

/**
 * The next sequence ID for a *slot* (RFC 8881 §2.10.6.1).
 *
 * Wraps to zero, and does not skip it: "If the previous sequence ID was
 * 0xFFFFFFFF, then the next request for the slot MUST have the sequence ID set
 * to zero". A stateid's seqid is the *other* convention — see
 * {@link bumpSeqid} — and the pair is why both are exported: neither wrap is
 * reachable through the public API, since a slot cannot be walked to
 * `0xFFFFFFFF` one request at a time, so the tests pin them here.
 */
export function nextSlotSeqid(seqid: number): number {
  return (seqid + 1) >>> 0;
}

/**
 * The next seqid for a *stateid* (RFC 8881 §8.2.2).
 *
 * "This pattern continues until the seqid is incremented past NFS4_UINT32_MAX,
 * and one (not zero) is the next seqid value" — zero is skipped here because
 * zero means "the most recent" on the wire.
 */
export function bumpSeqid(seqid: number): number {
  return seqid === UINT32_MAX ? 1 : seqid + 1;
}

/** Lowercase hex of an opaque, for use as a `Map` key. Same idea as `handles.ts`. */
function keyOf(bytes: Uint8Array): string {
  let key = "";
  for (const byte of bytes) {
    key += byte.toString(16).padStart(2, "0");
  }
  return key;
}

function copyOf(bytes: Uint8Array): Uint8Array {
  return bytes.slice();
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
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
 * The special stateids of RFC 8881 §8.2.3, by name.
 *
 * `"invalid"` is the reserved combination the RFC defines *as* an error (other
 * zero, seqid `NFS4_UINT32_MAX`), which is also what CLOSE returns to make a
 * client's misuse of its result obvious (§18.2.4).
 */
export type SpecialStateid = "anonymous" | "bypass" | "current" | "invalid";

/** All-zero `other`, all-ones `other`, or neither. */
function otherShape(other: Uint8Array): "zero" | "ones" | "normal" {
  let zeros = 0;
  let ones = 0;
  for (const byte of other) {
    if (byte === 0) {
      zeros++;
    } else if (byte === 0xff) {
      ones++;
    }
  }
  if (zeros === other.byteLength) {
    return "zero";
  }
  return ones === other.byteLength ? "ones" : "normal";
}

/**
 * Classify a stateid whose `other` is reserved (RFC 8881 §8.2.3).
 *
 * Returns the special meaning, `"normal"` when `other` is an ordinary value, or
 * `undefined` for a reserved `other` with a seqid the RFC does not define — "if
 * a stateid value is used that has all zeros or all ones in the 'other' field
 * but does not match one of the cases above, the server MUST return
 * NFS4ERR_BAD_STATEID".
 */
export function specialStateid(stateid: Stateid4): SpecialStateid | "normal" | undefined {
  const shape = otherShape(stateid.other);
  if (shape === "normal") {
    return "normal";
  }
  if (shape === "ones") {
    return stateid.seqid === UINT32_MAX ? "bypass" : undefined;
  }
  if (stateid.seqid === 0) {
    return "anonymous";
  }
  if (stateid.seqid === 1) {
    return "current";
  }
  return stateid.seqid === UINT32_MAX ? "invalid" : undefined;
}

/** `{ seqid: NFS4_UINT32_MAX, other: 0 }` — the invalid stateid CLOSE returns (§18.2.4). */
export function invalidStateid(): Stateid4 {
  return { seqid: UINT32_MAX, other: new Uint8Array(NFS4_OTHER_SIZE) };
}

/**
 * Every `OPEN4_SHARE_ACCESS_WANT_*` bit `share_access` may carry.
 *
 * `OPEN4_SHARE_ACCESS_WANT_DELEG_MASK` covers only the five mutually exclusive
 * delegation wishes; the two standalone flags §18.16.3 lists beside them —
 * `..._SIGNAL_DELEG_WHEN_RESRC_AVAIL` and `..._PUSH_DELEG_WHEN_UNCONTENDED` —
 * are legal in the same field and sit outside it, so masking with the named
 * mask alone would make a legal OPEN look malformed.
 */
const SHARE_ACCESS_WANT_MASK =
  OPEN4_SHARE_ACCESS_WANT_DELEG_MASK |
  OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL |
  OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED;

/**
 * The access mode inside a `share_access`, or `undefined` when there is none.
 *
 * §18.16.4 and §18.18.3 say the same thing for OPEN and OPEN_DOWNGRADE: with
 * the delegation wishes removed, the value "MUST be one of
 * OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_ACCESS_WRITE, or
 * OPEN4_SHARE_ACCESS_BOTH. If not, the server MUST return NFS4ERR_INVAL." So
 * this is an exact test, not a mask — a bit the protocol does not define is a
 * malformed request rather than something to quietly drop.
 */
function shareAccessOf(shareAccess: number): number | undefined {
  const access = (shareAccess & ~SHARE_ACCESS_WANT_MASK) >>> 0;
  return access === OPEN4_SHARE_ACCESS_READ ||
    access === OPEN4_SHARE_ACCESS_WRITE ||
    access === OPEN4_SHARE_ACCESS_BOTH
    ? access
    : undefined;
}

/** The plain access bits of a mode this server already validated or produced itself. */
function accessBits(shareAccess: number): number {
  return shareAccess & OPEN4_SHARE_ACCESS_BOTH;
}

/** `READW_LT`/`WRITEW_LT` are the polling forms of the same two locks (§9.6, §18.11.3). */
function baseLockType(locktype: number): number {
  if (locktype === READW_LT) {
    return READ_LT;
  }
  return locktype === WRITEW_LT ? WRITE_LT : locktype;
}

// ---------------------------------------------------------------------------
// byte-range locks (RFC 8881 §9.1-§9.6, §18.10-§18.12)
// ---------------------------------------------------------------------------

/**
 * One granted byte range, `[start, end)`.
 *
 * A to-EOF lock (`length == NFS4_UINT64_MAX`) has `end === 2^64`, one past the
 * last addressable byte, so a lock running "through the end-of-file (no matter
 * how long the file actually is)" needs no special case in the overlap
 * arithmetic — only in the encoding back out, which {@link lengthOf} does.
 */
export interface ByteRangeLock {
  start: bigint;
  end: bigint;
  /** `READ_LT` or `WRITE_LT`; the `W` forms are folded onto these two. */
  type: number;
  /** `${clientid}:${lock-owner}` — the identity a conflict is judged against (§9.5). */
  ownerKey: string;
  /**
   * The open stateid this range was last locked through.
   *
   * Not part of the conflict identity — §9.5 is explicit that the locking
   * status of a byte follows the lock-owner "independent of the stateid through
   * which the request was sent" — but recorded because the same section makes
   * the *assignment* follow the last LOCK, and CLOSE has to know which of its
   * own open's locks would survive it (§9.8).
   */
  openKey: string;
  /** The lock-owner's real client ID, which a `LOCK4denied` MUST carry (§18.10.3). */
  clientid: bigint;
  /** `lock_owner4.owner`, for the same reason. */
  owner: Uint8Array;
}

/** The `length4` that describes a range: `NFS4_UINT64_MAX` when it runs to EOF. */
function lengthOf(lock: ByteRangeLock): bigint {
  return lock.end === EOF_END ? NFS4_MAXFILELEN : lock.end - lock.start;
}

function overlaps(lock: ByteRangeLock, start: bigint, end: bigint): boolean {
  return lock.start < end && start < lock.end;
}

/** POSIX conflict: overlapping ranges of different owners, at least one a write lock. */
function conflicts(lock: ByteRangeLock, ownerKey: string, type: number): boolean {
  return lock.ownerKey !== ownerKey && (lock.type === WRITE_LT || type === WRITE_LT);
}

/**
 * Replace `[start, end)` in `locks` for one owner, splitting and merging as
 * POSIX requires (§9.2, §9.3).
 *
 * Every same-owner range is trimmed out of the way first — which is what turns
 * an upgrade or downgrade of a sub-range into a split — then the new range is
 * inserted and coalesced with the same-owner neighbours it now touches and
 * agrees with in type. Other owners' ranges are never touched.
 */
function replaceRange(locks: ByteRangeLock[], granted: ByteRangeLock): ByteRangeLock[] {
  const kept = subtractRange(locks, granted.ownerKey, granted.start, granted.end);
  kept.push({ ...granted });
  return coalesce(kept);
}

/** Remove `[start, end)` from every range `ownerKey` holds, splitting where it lands inside one. */
function subtractRange(
  locks: readonly ByteRangeLock[],
  ownerKey: string,
  start: bigint,
  end: bigint,
): ByteRangeLock[] {
  const kept: ByteRangeLock[] = [];
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
 * Sort by start and join each owner's touching same-type ranges.
 *
 * The merge is tracked *per owner* rather than against the previous element,
 * because two owners' ranges interleave freely in start order and one owner's
 * two adjacent locks would otherwise be left split by another owner's lock
 * sorting between them. Ranges of one owner that were taken through different
 * opens are left separate for the same reason `ByteRangeLock.openKey` exists:
 * merging them would throw away which open each is assigned to (§9.5).
 */
function coalesce(locks: ByteRangeLock[]): ByteRangeLock[] {
  const sorted = [...locks].sort((left, right) =>
    left.start < right.start ? -1 : left.start > right.start ? 1 : 0,
  );
  const merged: ByteRangeLock[] = [];
  const lastOf = new Map<string, ByteRangeLock>();
  for (const lock of sorted) {
    // `|` is safe as a delimiter and stays grep-able: both halves are hex with
    // one `:` in them, so neither can contain it.
    const groupKey = `${lock.ownerKey}|${lock.openKey}`;
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

// ---------------------------------------------------------------------------
// records
// ---------------------------------------------------------------------------

/** One entry of a session's fore-channel slot table (RFC 8881 §2.10.6.1). */
class Slot {
  /** The last sequence ID seen on this slot. Zero until the first request (§18.36.4). */
  sequenceid = 0;
  /** The cached whole-COMPOUND reply, or `undefined` when this slot's reply was not cached. */
  bytes: Uint8Array | undefined;
  /**
   * Nothing has executed on this slot yet.
   *
   * §18.36.4 has the server record, at session creation, "an entry containing a
   * COMPOUND reply with zero operations and the error NFS4ERR_SEQ_MISORDERED",
   * so that the illegal first request with `sa_sequenceid == 0` replays that
   * rather than being executed. This flag *is* that contrived entry: the reply
   * it stands for is one the session can produce from a status alone.
   */
  fresh = true;

  readonly slotid: number;

  /** The session's negotiated `ca_maxresponsesize_cached` (§18.36.3). */
  readonly maxCachedBytes: number;

  constructor(slotid: number, maxCachedBytes: number) {
    this.slotid = slotid;
    this.maxCachedBytes = maxCachedBytes;
  }
}

/**
 * The public face of a reserved slot: hand it back to
 * {@link Nfs4State.cacheReply} once the reply exists.
 *
 * It carries the sequence ID the slot was at when the ticket was issued, so a
 * reply that arrives after the client has moved the slot on — which can only
 * happen if the session cached out of order — is dropped instead of being
 * filed under the wrong request.
 */
export interface SlotTicket {
  readonly slotid: number;
  readonly sequenceid: number;
  /**
   * The session's negotiated `ca_maxresponsesize_cached` (§18.36.3).
   *
   * Published because the caller has to know it *before* it finishes the
   * reply: §2.10.6.4 makes an over-sized reply the client asked to have cached
   * an error rather than a silent omission — "If the reply exceeds
   * ca_maxresponsesize_cached (and sa_cachethis ... is TRUE), then the server
   * MUST return NFS4ERR_REP_TOO_BIG_TO_CACHE" — and the reply that carries that
   * status is a *different*, shorter reply, which only the encoder can build.
   */
  readonly maxCachedBytes: number;
}

class Ticket implements SlotTicket {
  readonly slot: Slot;
  readonly slotid: number;
  readonly sequenceid: number;
  readonly maxCachedBytes: number;

  constructor(slot: Slot, slotid: number, sequenceid: number) {
    this.slot = slot;
    this.slotid = slotid;
    this.sequenceid = sequenceid;
    this.maxCachedBytes = slot.maxCachedBytes;
  }
}

interface SessionRecord {
  sessionid: Uint8Array;
  key: string;
  clientid: bigint;
  slots: Slot[];
  flags: number;
  foreChanAttrs: ChannelAttrs4;
  backChanAttrs: ChannelAttrs4;
}

/**
 * The reply CREATE_SESSION produced, kept for the one-slot per-client replay
 * cache (§18.36.4).
 *
 * It holds the `status` too, because phase 4 can fail after phase 2 has already
 * advanced the slot — and a reply cache that answered a retransmission of a
 * failed CREATE_SESSION with anything but that failure would not be one.
 */
interface CachedCreateSession {
  status: number;
  sessionid: Uint8Array;
  flags: number;
  foreChanAttrs: ChannelAttrs4 | undefined;
  backChanAttrs: ChannelAttrs4 | undefined;
}

/**
 * A server's client record: the 5-tuple of §18.35.4 minus the principal.
 *
 * The principal is absent because this server speaks `AUTH_NONE`/`AUTH_SYS` and
 * has no RPCSEC_GSS identity to record; the two EXCHANGE_ID scenarios that turn
 * on it — case 3's client collision and case 9's wrong principal — are noted
 * where they would be decided rather than half-implemented against a uid.
 */
interface ClientRecord {
  clientid: bigint;
  ownerKey: string;
  ownerid: Uint8Array;
  verifier: Uint8Array;
  confirmed: boolean;
  /** `eir_sequenceid`, the value CREATE_SESSION's `csa_sequence` must match. */
  sequenceid: number;
  /** The one-slot CREATE_SESSION reply cache (§18.36.4). */
  createSlot: { sequenceid: number; reply: CachedCreateSession | undefined };
  /** Last renewal, on the injected clock. */
  renewed: number;
  sessions: Map<string, SessionRecord>;
  opens: Map<string, OpenState>;
  locks: Map<string, LockState>;
  /** Stateid `other`s revoked but not yet acknowledged by FREE_STATEID (§8.2.4). */
  revoked: Set<string>;
  /** Sticky `SEQ4_STATUS_*` bits reported by every SEQUENCE until acknowledged (§18.46.3). */
  statusFlags: number;
  /** Global RECLAIM_COMPLETE seen (§18.51.3). */
  reclaimComplete: boolean;
}

/** An open stateid: one per (client, open-owner, file) triple (§8.2.1). */
interface OpenState {
  kind: "open";
  key: string;
  other: Uint8Array;
  seqid: number;
  clientid: bigint;
  ownerKey: string;
  owner: Uint8Array;
  fileKey: string;
  access: number;
  deny: number;
  /** Keys of the lock stateids taken under this open (§9.1.1). */
  lockStates: Set<string>;
}

/** A lock stateid: one per (client, lock-owner, open) triple (§8.2.1, §9.5). */
interface LockState {
  kind: "lock";
  key: string;
  other: Uint8Array;
  seqid: number;
  clientid: bigint;
  ownerKey: string;
  owner: Uint8Array;
  fileKey: string;
  /** The open stateid this lock state was derived from (§9.1.1). */
  openKey: string;
}

interface FileState {
  opens: Set<OpenState>;
  locks: ByteRangeLock[];
}

// ---------------------------------------------------------------------------
// results
// ---------------------------------------------------------------------------

/** EXCHANGE_ID (RFC 8881 §18.35.2), minus the fields the session fills in itself. */
export interface ExchangeIdResult {
  status: number;
  clientid: bigint;
  /** `eir_sequenceid`. */
  sequenceid: number;
  /** `eir_flags`. */
  flags: number;
}

export interface ExchangeIdRequest {
  /** `eia_clientowner.co_ownerid`. */
  ownerid: Uint8Array;
  /** `eia_clientowner.co_verifier`. */
  verifier: Uint8Array;
  /** `eia_flags`. */
  flags: number;
}

export interface CreateSessionRequest {
  clientid: bigint;
  /** `csa_sequence`. */
  sequence: number;
  flags: number;
  foreChanAttrs: ChannelAttrs4;
  backChanAttrs: ChannelAttrs4;
}

/** CREATE_SESSION (RFC 8881 §18.36.2). `replay` is a note for the caller, not a wire field. */
export interface CreateSessionResult {
  status: number;
  sessionid: Uint8Array;
  sequence: number;
  flags: number;
  foreChanAttrs: ChannelAttrs4 | undefined;
  backChanAttrs: ChannelAttrs4 | undefined;
  /** This answer came from the per-client CREATE_SESSION reply cache. */
  replay: boolean;
}

/**
 * What SEQUENCE decided (RFC 8881 §2.10.6.1, §18.46.3).
 *
 * The four arms are the four things a slot can say, and the session maps each
 * onto a reply shape: `error` is a COMPOUND carrying just that status,
 * `replay` is the cached bytes handed back untouched, `replay-uncached` is a
 * successful SEQUENCE followed by `opStatus` on the next operation — which is
 * why it is not simply an error, since §2.10.6.1.3 forbids returning
 * `NFS4ERR_RETRY_UNCACHED_REP` *as* the answer to a leading SEQUENCE — and
 * `new` is a request to execute.
 */
export type SequenceOutcome =
  | { kind: "error"; status: number }
  | { kind: "replay"; status: number; bytes: Uint8Array }
  | { kind: "replay-uncached"; status: number; sequence: Sequence4res; opStatus: number }
  | {
      kind: "new";
      status: number;
      sequence: Sequence4res;
      clientid: bigint;
      /** `sa_cachethis`: the client asked for the whole reply to be cached. */
      cachethis: boolean;
      ticket: SlotTicket;
    };

export interface OpenRequest {
  clientid: bigint;
  /** `open_owner4.owner`; the `clientid` field inside it is ignored (§18.16.3). */
  owner: Uint8Array;
  fileKey: string;
  shareAccess: number;
  shareDeny: number;
  /**
   * The claim is a reclaim — `CLAIM_PREVIOUS` or one of the `*_PREV` delegation
   * forms. Always `NFS4ERR_NO_GRACE` here; see the module docs.
   */
  reclaim?: boolean | undefined;
}

export interface OpenResult {
  status: number;
  stateid?: Stateid4 | undefined;
  /** The OPEN found an existing open by the same owner and widened it (§9.9). */
  upgraded?: boolean | undefined;
}

export interface StateidRequest {
  clientid: bigint;
  stateid: Stateid4;
  /** When given, the stateid must name state on this file (§8.2.4). */
  fileKey?: string | undefined;
  /** Restrict what the stateid may name; a mismatch is `NFS4ERR_BAD_STATEID` (§8.2.4). */
  want?: "open" | "lock" | "any" | undefined;
}

/**
 * What a stateid names (RFC 8881 §8.2.3, §8.2.4).
 *
 * `kind` is meaningful only when `status` is `NFS4_OK`. `"current"` is the
 * special stateid the *session* has to resolve — it means "whatever the last
 * operation in this COMPOUND returned" — so it comes back named rather than
 * resolved, and the session calls again with the substitute.
 */
export interface StateidResult {
  status: number;
  kind?: "open" | "lock" | SpecialStateid | undefined;
  /** The share access bits in force, for the OPENMODE check of §9.1.2. */
  access?: number | undefined;
  deny?: number | undefined;
  fileKey?: string | undefined;
  /** The stateid with its current seqid, for an operation that echoes one back. */
  stateid?: Stateid4 | undefined;
  /**
   * The open state the access above belongs to: this stateid itself when it is
   * an open, and the open a lock stateid was derived from when it is a lock
   * (§9.1.1, §9.1.2's "for stateids returned by byte-range LOCK operations, the
   * appropriate mode is the access mode for the OPEN stateid associated with
   * the lock set represented by the stateid").
   *
   * Named rather than merely accounted for because a caller that keeps
   * per-open resources — a session holding one file handle per open — has to be
   * able to get from a lock stateid to the open without a second lookup it has
   * no key for.
   */
  openStateid?: Stateid4 | undefined;
}

export interface LockRequest {
  clientid: bigint;
  fileKey: string;
  locktype: number;
  offset: bigint;
  length: bigint;
  reclaim?: boolean | undefined;
  /** `locker4` `new_lock_owner == TRUE`: an open stateid plus the new lock-owner. */
  openStateid?: Stateid4 | undefined;
  /** `open_to_lock_owner4.lock_owner.owner`. */
  lockOwner?: Uint8Array | undefined;
  /** `locker4` `new_lock_owner == FALSE`: the lock stateid of an established lock-owner. */
  lockStateid?: Stateid4 | undefined;
}

export interface LockResult {
  status: number;
  stateid?: Stateid4 | undefined;
  /** Set with `NFS4ERR_DENIED`, and carrying the conflicting owner's real client ID (§18.10.3). */
  denied?: Lock4denied | undefined;
}

export interface LocktRequest {
  clientid: bigint;
  fileKey: string;
  locktype: number;
  offset: bigint;
  length: bigint;
  /** `LOCKT4args.owner.owner`; the `clientid` beside it is ignored (§18.11.3). */
  owner: Uint8Array;
}

export interface LockuRequest {
  clientid: bigint;
  fileKey: string;
  lockStateid: Stateid4;
  offset: bigint;
  length: bigint;
}

export interface Nfs4StateOptions {
  /** Milliseconds since an arbitrary epoch. Default `Date.now`. */
  now?: (() => number) | undefined;
  /** Lease length. Default 90 s, the value Linux's server uses. */
  leaseSeconds?: number | undefined;
  /**
   * Folded into every id this table mints, so ids from two instances differ.
   * Default `0`, which keeps a test run reproducible; a server passes something
   * boot-unique so a client ID from its previous life reads as stale.
   */
  seed?: number | undefined;
  /** Sessions one client may hold at once. Default 4. */
  maxSessions?: number | undefined;
  /** Fore-channel slots, the `ca_maxrequests` counter-offer ceiling. Default 64. */
  maxForeSlots?: number | undefined;
  /** `ca_maxoperations` counter-offer ceiling. Default 64. */
  maxOperations?: number | undefined;
  /** `ca_maxrequestsize`/`ca_maxresponsesize` ceiling. Default 1 MiB, well under the transport's 8 MiB record cap. */
  maxRequestSize?: number | undefined;
  /** `ca_maxresponsesize_cached` ceiling, and the largest reply that is stored. Default 64 KiB. */
  maxCachedResponseSize?: number | undefined;
  /** Opens one file may carry across all clients. Default 256. */
  maxOpensPerFile?: number | undefined;
  /** Granted byte ranges one file may carry. Default 1024. */
  maxLocksPerFile?: number | undefined;
  /** Enforce §18.51.3's "RECLAIM_COMPLETE before the first lock". Default `true`. */
  requireReclaimComplete?: boolean | undefined;
  /**
   * An open stateid has stopped existing, whatever ended it.
   *
   * Called with the state's own `other` bytes — the caller must copy them if it
   * keeps them — from every path that drops an open: CLOSE, the lease-expiry
   * revocation of §8.4.3, {@link Nfs4State.sweep}, DESTROY_CLIENTID, and the
   * EXCHANGE_ID that replaces an unconfirmed record. It exists because a
   * session holds one driver file handle per open state and there is otherwise
   * no event for "this open went away without a CLOSE"; this table stays
   * driver-free and hands the fact out instead of acting on it.
   *
   * Synchronous, like everything here, and must not throw: it is called in the
   * middle of a table walk. A caller with asynchronous work to do queues it.
   */
  onOpenReleased?: ((other: Uint8Array) => void) | undefined;
}

const DEFAULT_LEASE_SECONDS = 90;

/** The channel attributes this server insists on, whatever it was offered. */
interface ChannelCaps {
  maxForeSlots: number;
  maxOperations: number;
  maxRequestSize: number;
  maxCachedResponseSize: number;
}

/**
 * The smallest fore-channel `ca_maxresponsesize` this server can answer inside.
 *
 * Derived rather than guessed, from the shortest reply it can ever send — a
 * COMPOUND carrying nothing but a SEQUENCE result:
 *
 * - RPC accepted reply header, 24 bytes: xid, msg_type, reply_stat, an
 *   AUTH_NONE verifier (flavor + zero length) and accept_stat.
 * - `COMPOUND4res`, 12 bytes: status, a zero-length tag, and the result count.
 * - One `SEQUENCE4resok`, 44 bytes: opnum, status, `sessionid4` (16) and the
 *   five `uint32_t`s.
 *
 * That is 80 bytes, plus the four of a TCP record mark that
 * `ca_maxrequestsize`/`ca_maxresponsesize` explicitly exclude. Rounded up to
 * 128 so the number is a bound rather than a fit — a client offering less than
 * this "could never send a response" in §18.36.3's sense and is answered with
 * `NFS4ERR_TOOSMALL` rather than being handed a session that cannot reply.
 */
const MIN_RESPONSE_SIZE = 128;

/**
 * Cap each of the client's offers, per §18.36.3's "the server MAY decrease this
 * value but MUST NOT increase it".
 *
 * Nothing here raises an offer except the two *counts*, and only off zero: a
 * session with no slots or no operations per COMPOUND cannot carry a single
 * request, and §18.36.3 does not define either value. That floor is the one
 * deliberate deviation, and it is a count rather than a size — the sizes are
 * never raised, because a too-small `ca_maxresponsesize` has an answer of its
 * own ({@link MIN_RESPONSE_SIZE}) and a too-small `ca_maxrequestsize` simply
 * means the client's own requests will not fit, which is its business and
 * self-consistent (`NFS4ERR_REQ_TOO_BIG`).
 */
function counterOffer(offered: ChannelAttrs4, caps: ChannelCaps, fore: boolean): ChannelAttrs4 {
  const bounded = (value: number, cap: number, floor: number): number =>
    Math.max(floor, Math.min(value, cap));
  return {
    // "MAY decrease this value but MUST NOT increase it" — zero is "no padding".
    headerpadsize: 0,
    maxrequestsize: Math.min(offered.maxrequestsize, caps.maxRequestSize),
    maxresponsesize: Math.min(offered.maxresponsesize, caps.maxRequestSize),
    maxresponsesizeCached: Math.min(offered.maxresponsesizeCached, caps.maxCachedResponseSize),
    // For the backchannel "the server MUST NOT change the value the client
    // offers" for these two; only the fore channel may be trimmed (§18.36.3).
    maxoperations: fore
      ? bounded(offered.maxoperations, caps.maxOperations, 1)
      : offered.maxoperations,
    maxrequests: fore ? bounded(offered.maxrequests, caps.maxForeSlots, 1) : offered.maxrequests,
    rdmaIrd: [],
  };
}

/** The `eia_flags` bits a client is allowed to set (§18.35.3). */
const EXCHGID4_FLAG_ARG_MASK =
  EXCHGID4_FLAG_SUPP_MOVED_REFER |
  EXCHGID4_FLAG_SUPP_MOVED_MIGR |
  EXCHGID4_FLAG_BIND_PRINC_STATEID |
  EXCHGID4_FLAG_USE_NON_PNFS |
  EXCHGID4_FLAG_USE_PNFS_MDS |
  EXCHGID4_FLAG_USE_PNFS_DS |
  EXCHGID4_FLAG_UPD_CONFIRMED_REC_A;

// ---------------------------------------------------------------------------
// the table
// ---------------------------------------------------------------------------

/**
 * Every piece of NFSv4.1 state one server holds.
 *
 * One instance per {@link https://www.rfc-editor.org/rfc/rfc8881 RFC 8881}
 * server: client records keyed by `co_ownerid`, their sessions and slot tables,
 * the stateids they own, and the share and byte-range locks those stateids
 * stand for. See the module docs for the result convention, the replay-cache
 * ownership contract and the lease policy.
 */
export class Nfs4State {
  readonly #now: () => number;
  readonly #leaseMs: number;
  readonly #seed: number;
  readonly #caps: ChannelCaps;
  readonly #maxSessions: number;
  readonly #maxOpensPerFile: number;
  readonly #maxLocksPerFile: number;
  readonly #requireReclaimComplete: boolean;
  readonly #onOpenReleased: ((other: Uint8Array) => void) | undefined;

  /** `co_ownerid` → the confirmed and unconfirmed records that ownerid has (§18.35.4 case 5). */
  readonly #byOwner = new Map<string, { confirmed?: ClientRecord; unconfirmed?: ClientRecord }>();
  readonly #byClientid = new Map<bigint, ClientRecord>();
  readonly #sessions = new Map<string, SessionRecord>();
  /** stateid `other` → the state it names, across every client (checked against the client at use). */
  readonly #states = new Map<string, OpenState | LockState>();
  readonly #files = new Map<string, FileState>();

  #nextClientid = 1n;
  #nextSessionid = 1n;
  #nextOther = 1n;

  constructor(options: Nfs4StateOptions = {}) {
    this.#now = options.now ?? (() => Date.now());
    this.#leaseMs = Math.max(1, options.leaseSeconds ?? DEFAULT_LEASE_SECONDS) * 1000;
    this.#seed = (options.seed ?? 0) >>> 0;
    this.#caps = {
      maxForeSlots: Math.max(1, options.maxForeSlots ?? 64),
      maxOperations: Math.max(1, options.maxOperations ?? 64),
      maxRequestSize: Math.max(1, options.maxRequestSize ?? 1024 * 1024),
      maxCachedResponseSize: Math.max(0, options.maxCachedResponseSize ?? 64 * 1024),
    };
    this.#maxSessions = Math.max(1, options.maxSessions ?? 4);
    this.#maxOpensPerFile = Math.max(1, options.maxOpensPerFile ?? 256);
    this.#maxLocksPerFile = Math.max(1, options.maxLocksPerFile ?? 1024);
    this.#requireReclaimComplete = options.requireReclaimComplete ?? true;
    this.#onOpenReleased = options.onOpenReleased;
  }

  /** The lease length, in seconds — the `lease_time` attribute the session reports. */
  get leaseSeconds(): number {
    return Math.round(this.#leaseMs / 1000);
  }

  /** Client records currently held, confirmed or not. */
  get clientCount(): number {
    return this.#byClientid.size;
  }

  /** Live sessions across every client. */
  get sessionCount(): number {
    return this.#sessions.size;
  }

  /** Stateids currently issued across every client. */
  get stateCount(): number {
    return this.#states.size;
  }

  /** The granted byte ranges on one file, in range order. A read-only view for callers and tests. */
  locksOf(fileKey: string): readonly ByteRangeLock[] {
    return this.#files.get(fileKey)?.locks ?? [];
  }

  /** The client ID a session belongs to, or `undefined` if the session is unknown (§18.46.4). */
  clientOfSession(sessionid: Uint8Array): bigint | undefined {
    return this.#sessions.get(keyOf(sessionid))?.clientid;
  }

  // -------------------------------------------------------------------------
  // EXCHANGE_ID (RFC 8881 §18.35)
  // -------------------------------------------------------------------------

  /**
   * Register a client, or recognise one already registered (§18.35.4).
   *
   * The five scenarios that do not need a principal are implemented by their
   * numbers in §18.35.4's second list: 1 (new owner ID), 2 (non-update on an
   * existing client ID), 4 (replacement of an unconfirmed record), 5 (client
   * restart) and, under `EXCHGID4_FLAG_UPD_CONFIRMED_REC_A`, 6 (update), 7 (no
   * confirmed record → `NFS4ERR_NOENT`) and 8 (wrong verifier →
   * `NFS4ERR_NOT_SAME`). Case 3 (a chance `co_ownerid` collision between two
   * clients) and case 9 (update by the wrong principal) are the two that turn on
   * the RPC principal, and with `AUTH_SYS` there is nothing trustworthy to
   * compare: a colliding ownerid is treated as case 5, the client restart it is
   * indistinguishable from without a principal.
   */
  exchangeId(request: ExchangeIdRequest): ExchangeIdResult {
    const refused = (status: number): ExchangeIdResult => ({
      status,
      clientid: 0n,
      sequenceid: 0,
      flags: 0,
    });
    // "Bits not defined above cannot be set in the eia_flags field. If they
    // are, the server MUST reject the operation with NFS4ERR_INVAL."
    if ((request.flags & ~EXCHGID4_FLAG_ARG_MASK) !== 0) {
      return refused(NFS4ERR_INVAL);
    }
    const update = (request.flags & EXCHGID4_FLAG_UPD_CONFIRMED_REC_A) !== 0;
    const ownerKey = keyOf(request.ownerid);
    const entry = this.#byOwner.get(ownerKey);

    if (update) {
      const confirmed = entry?.confirmed;
      if (confirmed === undefined) {
        return refused(NFS4ERR_NOENT); // case 7
      }
      if (!sameBytes(confirmed.verifier, request.verifier)) {
        return refused(NFS4ERR_NOT_SAME); // case 8
      }
      return this.#exchangeIdOk(confirmed); // case 6: the record is left intact
    }

    if (entry?.unconfirmed !== undefined) {
      // Case 4: an unconfirmed record is replaced outright, whatever the
      // verifier, "to eliminate ambiguity".
      this.#forget(entry.unconfirmed);
    }
    const confirmed = this.#byOwner.get(ownerKey)?.confirmed;
    if (confirmed !== undefined && sameBytes(confirmed.verifier, request.verifier)) {
      return this.#exchangeIdOk(confirmed); // case 2
    }
    // Case 1 (no record) and case 5 (client restart) build the same unconfirmed
    // record; in case 5 the confirmed one stays until CREATE_SESSION confirms
    // its replacement, which is the state §18.35.4 describes as one ownerid
    // existing in both states at once.
    return this.#exchangeIdOk(this.#addClient(request));
  }

  #exchangeIdOk(client: ClientRecord): ExchangeIdResult {
    // Trunking-free: this table hands out one client ID per registration and
    // says nothing that would invite a client to trunk (§2.10.5). The
    // server_owner and scope the session writes beside this are constant, so a
    // second connection to the same server is recognised as the same server and
    // no more than that.
    return {
      status: NFS4_OK,
      clientid: client.clientid,
      sequenceid: client.sequenceid,
      // `>>> 0` because EXCHGID4_FLAG_CONFIRMED_R is bit 31 and JavaScript's
      // bitwise operators are signed: without it `eir_flags` would be negative.
      flags:
        (EXCHGID4_FLAG_USE_NON_PNFS | (client.confirmed ? EXCHGID4_FLAG_CONFIRMED_R : 0)) >>> 0,
    };
  }

  #addClient(request: ExchangeIdRequest): ClientRecord {
    const ownerKey = keyOf(request.ownerid);
    const clientid = (BigInt(this.#seed) << 32n) | this.#nextClientid++;
    const client: ClientRecord = {
      clientid,
      ownerKey,
      ownerid: copyOf(request.ownerid),
      verifier: copyOf(request.verifier),
      confirmed: false,
      sequenceid: 1,
      // "Before the server replies to that EXCHANGE_ID operation, it
      // initializes the client ID slot to be equal to eir_sequenceid - 1
      // (accounting for underflow), and records a contrived CREATE_SESSION
      // result with a 'cached' result of NFS4ERR_SEQ_MISORDERED" (§18.36.4).
      // `reply: undefined` is that contrived result.
      createSlot: { sequenceid: 0, reply: undefined },
      renewed: this.#now(),
      sessions: new Map(),
      opens: new Map(),
      locks: new Map(),
      revoked: new Set(),
      statusFlags: 0,
      reclaimComplete: false,
    };
    this.#byClientid.set(clientid, client);
    const entry = this.#byOwner.get(ownerKey) ?? {};
    entry.unconfirmed = client;
    this.#byOwner.set(ownerKey, entry);
    return client;
  }

  // -------------------------------------------------------------------------
  // CREATE_SESSION (RFC 8881 §18.36)
  // -------------------------------------------------------------------------

  /**
   * Create a session, confirming the client ID if this is its first (§18.36.3).
   *
   * The four phases of §18.36.4 in order: look the client ID up
   * (`NFS4ERR_STALE_CLIENTID`), run `csa_sequence` against the client's
   * one-slot reply cache (equal → replay the cached reply, +1 → proceed,
   * anything else → `NFS4ERR_SEQ_MISORDERED`), confirm, then build the session.
   *
   * The counter-offer is the server's, and every returned attribute may be
   * smaller than what was asked for; no `CREATE_SESSION4_FLAG_CONN_BACK_CHAN`
   * is ever set, because this server has no back channel and "if
   * CREATE_SESSION4_FLAG_CONN_BACK_CHAN is not set in csa_flags, then [it] MUST
   * NOT be set in csr_flags" cuts only one way — a server that never sets it
   * needs no callbacks at all.
   */
  createSession(request: CreateSessionRequest): CreateSessionResult {
    const refused = (status: number): CreateSessionResult => ({
      status,
      sessionid: new Uint8Array(NFS4_SESSIONID_SIZE),
      sequence: request.sequence,
      flags: 0,
      foreChanAttrs: undefined,
      backChanAttrs: undefined,
      replay: false,
    });
    const client = this.#byClientid.get(request.clientid);
    if (client === undefined) {
      return refused(NFS4ERR_STALE_CLIENTID); // phase 1
    }

    // Phase 2. Equal to the slot's sequence ID is a replay; the contrived entry
    // an unconfirmed client starts with replays as NFS4ERR_SEQ_MISORDERED.
    const slot = client.createSlot;
    if (request.sequence === slot.sequenceid) {
      const cached = slot.reply;
      if (cached === undefined) {
        return refused(NFS4ERR_SEQ_MISORDERED);
      }
      return { ...cached, sequence: request.sequence, replay: true };
    }
    if (request.sequence !== nextSlotSeqid(slot.sequenceid)) {
      return refused(NFS4ERR_SEQ_MISORDERED);
    }
    // The phases run in the RFC's order, so the slot advances here — before
    // anything phase 4 can refuse. A phase-4 failure is therefore cached like
    // any other reply, and a retransmission of that request replays it; the
    // client's way forward is a *new* CREATE_SESSION at the next sequence ID,
    // which is exactly what it would send after seeing the failure.
    slot.sequenceid = request.sequence;
    const cache = (result: CreateSessionResult): CreateSessionResult => {
      slot.reply = {
        status: result.status,
        sessionid: result.sessionid,
        flags: result.flags,
        foreChanAttrs: result.foreChanAttrs,
        backChanAttrs: result.backChanAttrs,
      };
      return result;
    };

    // Phase 4's checks come before phase 3 is committed, because §18.36.4 has
    // the confirmation *scheduled* and then committed only "once the session is
    // successfully created. If the session is not successfully created, then no
    // changes are made to any client records on the server."
    if (request.foreChanAttrs.maxresponsesize < MIN_RESPONSE_SIZE) {
      // "If the client selects a value for ca_maxresponsesize such that a
      // replier on a channel could never send a response, the server SHOULD
      // return NFS4ERR_TOOSMALL in the CREATE_SESSION reply" (§18.36.3).
      return cache(refused(NFS4ERR_TOOSMALL));
    }
    if (client.sessions.size >= this.#maxSessions) {
      // Phase 4's "if there is not enough space, the server returns
      // NFS4ERR_NOSPC" — a session this table will not allocate is exactly that.
      return cache(refused(NFS4ERR_NOSPC));
    }

    // Phase 3, committed. Confirming an unconfirmed record replaces the
    // confirmed record the same ownerid may still have, and destroys the
    // previous incarnation's state (§18.35.4 case 5, §18.36.4 "Successful
    // Confirmation").
    if (!client.confirmed) {
      const entry = this.#byOwner.get(client.ownerKey) ?? {};
      if (entry.confirmed !== undefined && entry.confirmed !== client) {
        this.#forget(entry.confirmed);
      }
      client.confirmed = true;
      this.#byOwner.set(client.ownerKey, { confirmed: client });
    }

    // Phase 4.
    const foreChanAttrs = counterOffer(request.foreChanAttrs, this.#caps, true);
    const backChanAttrs = counterOffer(request.backChanAttrs, this.#caps, false);
    // None of the three `csa_flags` bits is granted, and `csr_flags` is
    // therefore always zero: CREATE_SESSION4_FLAG_PERSIST would promise a reply
    // cache in stable storage, CREATE_SESSION4_FLAG_CONN_BACK_CHAN a back
    // channel this server does not have, and CREATE_SESSION4_FLAG_CONN_RDMA an
    // RDMA step-up on a TCP socket. Each is refused by being left unset, which
    // is exactly what §18.36.3 says a refusal looks like.
    const flags = 0;
    const sessionid = this.#mintSessionid(client.clientid);
    const session: SessionRecord = {
      sessionid,
      key: keyOf(sessionid),
      clientid: client.clientid,
      slots: Array.from(
        { length: foreChanAttrs.maxrequests },
        (_unused, slotid) => new Slot(slotid, foreChanAttrs.maxresponsesizeCached),
      ),
      flags,
      foreChanAttrs,
      backChanAttrs,
    };
    this.#sessions.set(session.key, session);
    client.sessions.set(session.key, session);
    client.renewed = this.#now();
    return cache({
      status: NFS4_OK,
      sessionid,
      sequence: request.sequence,
      flags,
      foreChanAttrs,
      backChanAttrs,
      replay: false,
    });
  }

  #mintSessionid(clientid: bigint): Uint8Array {
    const sessionid = new Uint8Array(NFS4_SESSIONID_SIZE);
    const view = new DataView(sessionid.buffer);
    view.setBigUint64(0, clientid, false);
    view.setBigUint64(8, this.#nextSessionid++, false);
    return sessionid;
  }

  /**
   * DESTROY_SESSION (§18.37.3): close the session and discard its reply cache.
   *
   * "Locks, delegations, layouts, wants, and the lease, which are all tied to
   * the client ID, are not affected", so the client record stays exactly as it
   * was. An unknown session ID is `NFS4ERR_BADSESSION` (§15.1.11.1), which is
   * also what a second DESTROY_SESSION for the same session gets.
   */
  destroySession(sessionid: Uint8Array): { status: number } {
    const key = keyOf(sessionid);
    const session = this.#sessions.get(key);
    if (session === undefined) {
      return { status: NFS4ERR_BADSESSION };
    }
    this.#sessions.delete(key);
    this.#byClientid.get(session.clientid)?.sessions.delete(key);
    return { status: NFS4_OK };
  }

  /**
   * DESTROY_CLIENTID (§18.50.3): forget a client ID with nothing left on it.
   *
   * "If there are sessions (both idle and non-idle), opens, locks, delegations,
   * layouts, and/or wants ... associated with the unexpired lease of the client
   * ID, the server MUST return NFS4ERR_CLIENTID_BUSY", and so must a
   * DESTROY_CLIENTID naming the very client the enclosing SEQUENCE belongs to —
   * which is what `sessionClientid` is for.
   */
  destroyClientid(
    clientid: bigint,
    options: { sessionClientid?: bigint | undefined } = {},
  ): { status: number } {
    const client = this.#byClientid.get(clientid);
    if (client === undefined) {
      return { status: NFS4ERR_STALE_CLIENTID };
    }
    if (options.sessionClientid === clientid) {
      return { status: NFS4ERR_CLIENTID_BUSY };
    }
    const expired = this.#expired(client);
    if (!expired && (client.sessions.size > 0 || client.opens.size > 0 || client.locks.size > 0)) {
      return { status: NFS4ERR_CLIENTID_BUSY };
    }
    this.#forget(client);
    return { status: NFS4_OK };
  }

  // -------------------------------------------------------------------------
  // SEQUENCE and the slot table (RFC 8881 §2.10.6.1, §18.46)
  // -------------------------------------------------------------------------

  /**
   * Run a SEQUENCE against its slot (§18.46.3).
   *
   * The sequence ID is compared with the slot's, and the three cases are the
   * RFC's: equal is a retry answered from the reply cache, one greater
   * (wrapping) is a new request, and anything else — lower, or two or more
   * ahead — is `NFS4ERR_SEQ_MISORDERED`, since wraparound makes a misordered
   * retry and a misordered new request indistinguishable.
   *
   * A `new` outcome has already advanced the slot and dropped its previous
   * cached reply; the caller must finish by calling {@link Nfs4State.cacheReply}
   * with the ticket, whether or not it has bytes to cache. On any error the
   * slot is untouched and the lease is not renewed (§2.10.6.1.2, §18.46.3).
   */
  sequence(args: Sequence4args): SequenceOutcome {
    const session = this.#sessions.get(keyOf(args.sessionid));
    if (session === undefined) {
      return { kind: "error", status: NFS4ERR_BADSESSION };
    }
    if (args.slotid >= session.slots.length) {
      return { kind: "error", status: NFS4ERR_BADSLOT };
    }
    if (args.highestSlotid >= session.slots.length) {
      // "The highest_slot argument in a Sequence operation exceeds the
      // replier's enforced highest_slotid" (§15.1.11.3).
      return { kind: "error", status: NFS4ERR_BAD_HIGH_SLOT };
    }
    const client = this.#byClientid.get(session.clientid);
    if (client === undefined) {
      // A session outliving its client record is this table's own bug; answer
      // rather than throw, since a reply is owed either way.
      return { kind: "error", status: NFS4ERR_BADSESSION };
    }

    const slot = session.slots[args.slotid]!;
    const highestSlotid = session.slots.length - 1;
    const reply = (): Sequence4res => ({
      status: NFS4_OK,
      // A copy: `sr_sessionid` is the caller's to hold, and this table's own
      // key must not become reachable from a reply buffer.
      sessionid: copyOf(session.sessionid),
      sequenceid: args.sequenceid,
      slotid: args.slotid,
      highestSlotid,
      targetHighestSlotid: highestSlotid,
      statusFlags: client.statusFlags,
    });

    if (args.sequenceid === slot.sequenceid) {
      // A retry. §8.3: "successful retrieval of the result of SEQUENCE from the
      // reply cache ... will result in the lease being implicitly renewed".
      if (slot.fresh) {
        // The contrived entry §18.36.4 puts in every fresh slot.
        return { kind: "error", status: NFS4ERR_SEQ_MISORDERED };
      }
      this.#renew(client);
      if (slot.bytes !== undefined) {
        return { kind: "replay", status: NFS4_OK, bytes: slot.bytes };
      }
      return {
        kind: "replay-uncached",
        status: NFS4_OK,
        sequence: reply(),
        // §2.10.6.1.3: the *following* operation carries this, never the
        // leading SEQUENCE itself.
        opStatus: NFS4ERR_RETRY_UNCACHED_REP,
      };
    }
    if (args.sequenceid !== nextSlotSeqid(slot.sequenceid)) {
      return { kind: "error", status: NFS4ERR_SEQ_MISORDERED };
    }

    slot.sequenceid = args.sequenceid;
    slot.fresh = false;
    slot.bytes = undefined;
    this.#renew(client);
    return {
      kind: "new",
      status: NFS4_OK,
      sequence: reply(),
      clientid: session.clientid,
      cachethis: args.cachethis,
      ticket: new Ticket(slot, args.slotid, args.sequenceid),
    };
  }

  /**
   * Record the reply for the slot a {@link Nfs4State.sequence} ticket reserved.
   *
   * `bytes` is **copied**; the caller keeps ownership of its own buffer. Pass
   * `undefined` — or nothing — when the reply was not cached, which is what a
   * `sa_cachethis` of false means and what an over-sized reply gets:
   * `ca_maxresponsesize_cached` is a promise about what will be *stored*, and a
   * reply past it is left uncached so the retry answers
   * `NFS4ERR_RETRY_UNCACHED_REP` rather than silently growing the cache.
   *
   * Throws a `TypeError` for a ticket this table did not issue: that is a
   * programmer error, not a protocol outcome.
   *
   * Answers whether the bytes were stored, so a caller that owes the client
   * `NFS4ERR_REP_TOO_BIG_TO_CACHE` (§2.10.6.4) can tell "too big" from "not
   * asked for" without measuring the reply against
   * {@link SlotTicket.maxCachedBytes} a second time.
   */
  cacheReply(ticket: SlotTicket, bytes?: Uint8Array | undefined): boolean {
    if (!(ticket instanceof Ticket)) {
      throw new TypeError("cacheReply: ticket did not come from Nfs4State.sequence()");
    }
    const slot = ticket.slot;
    if (slot.sequenceid !== ticket.sequenceid) {
      // The slot has moved on, so this reply belongs to a request the client
      // has already had an answer for. Caching it would answer the *next*
      // retransmission with the previous request's bytes.
      return false;
    }
    const stored = bytes !== undefined && bytes.byteLength <= slot.maxCachedBytes;
    slot.bytes = stored ? copyOf(bytes) : undefined;
    return stored;
  }

  // -------------------------------------------------------------------------
  // leases (RFC 8881 §8.3, §8.4.3)
  // -------------------------------------------------------------------------

  #renew(client: ClientRecord): void {
    const now = this.#now();
    if (now - client.renewed > this.#leaseMs) {
      // The lease had already lapsed. Revoke what it was holding, say so in
      // every SEQUENCE from now on, and renew anyway so the client has a live
      // session to acknowledge the revocation over (§8.3, §18.46.3).
      this.#revoke(client);
    }
    client.renewed = now;
  }

  #expired(client: ClientRecord): boolean {
    return this.#now() - client.renewed > this.#leaseMs;
  }

  /**
   * Free everything a client holds, leaving revoked-stateid tombstones behind
   * (§8.4.3).
   *
   * The drops delete from the very maps being walked, which is defined for a
   * `Map`: an entry removed while it is the current one has already been
   * visited, and nothing here removes an entry that has not been.
   */
  #revoke(client: ClientRecord): void {
    if (client.opens.size === 0 && client.locks.size === 0) {
      return;
    }
    for (const lock of client.locks.values()) {
      this.#dropLockState(client, lock);
    }
    for (const open of client.opens.values()) {
      this.#dropOpenState(client, open);
    }
    client.statusFlags |= SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED;
  }

  /**
   * Revoke the state of every *other* client on `fileKey` whose lease has
   * expired, so it cannot deny the request about to be decided.
   *
   * §8.4.3 makes this a MUST: "locks associated with an expired lease do not
   * prevent such a conflicting lock from being granted but MUST be revoked as
   * necessary so as to avoid interfering with such conflicting requests."
   */
  #revokeExpiredHolders(fileKey: string, clientid: bigint): void {
    const file = this.#files.get(fileKey);
    if (file === undefined) {
      return;
    }
    const holders = new Set<bigint>();
    for (const open of file.opens) {
      holders.add(open.clientid);
    }
    for (const lock of file.locks) {
      holders.add(lock.clientid);
    }
    for (const holder of holders) {
      if (holder === clientid) {
        continue;
      }
      const client = this.#byClientid.get(holder);
      if (client !== undefined && this.#expired(client)) {
        this.#revoke(client);
      }
    }
  }

  /**
   * Remove every client whose lease has expired, sessions and all.
   *
   * The hard half of the policy in the module docs, for a server timer to call:
   * where a conflict revokes only the state that is in the way, this forgets
   * the client outright, so its sessions answer `NFS4ERR_BADSESSION` and its
   * client ID `NFS4ERR_STALE_CLIENTID` — §8.4.3's "the server may choose to
   * invalidate the session and the associated client ID". Returns how many
   * clients went.
   */
  sweep(): number {
    let removed = 0;
    for (const client of this.#byClientid.values()) {
      if (this.#expired(client)) {
        this.#forget(client);
        removed++;
      }
    }
    return removed;
  }

  /** Drop a client record and everything hanging off it. */
  #forget(client: ClientRecord): void {
    for (const key of client.sessions.keys()) {
      this.#sessions.delete(key);
    }
    client.sessions.clear();
    for (const lock of client.locks.values()) {
      this.#dropLockState(client, lock);
    }
    for (const open of client.opens.values()) {
      this.#dropOpenState(client, open);
    }
    client.revoked.clear();
    this.#byClientid.delete(client.clientid);
    const entry = this.#byOwner.get(client.ownerKey);
    if (entry !== undefined) {
      if (entry.confirmed === client) {
        delete entry.confirmed;
      }
      if (entry.unconfirmed === client) {
        delete entry.unconfirmed;
      }
      if (entry.confirmed === undefined && entry.unconfirmed === undefined) {
        this.#byOwner.delete(client.ownerKey);
      }
    }
  }

  // -------------------------------------------------------------------------
  // RECLAIM_COMPLETE (RFC 8881 §18.51)
  // -------------------------------------------------------------------------

  /**
   * Record that the client has finished reclaiming (§18.51.3).
   *
   * A second global one is `NFS4ERR_COMPLETE_ALREADY` (§18.51.4). The per-file
   * system form (`oneFs`) is accepted and ignored: "when the current filehandle
   * designates a filehandle in a file system not in the process of migration,
   * the operation returns NFS4_OK and is otherwise ignored", and nothing here
   * ever migrates.
   */
  reclaimComplete(clientid: bigint, oneFs = false): { status: number } {
    const client = this.#byClientid.get(clientid);
    if (client === undefined) {
      // Unreachable through a live session; RECLAIM_COMPLETE's valid errors
      // (§15.2) do not include NFS4ERR_EXPIRED, and NFS4ERR_SERVERFAULT is
      // both listed and what an inconsistency on this side actually is.
      return { status: NFS4ERR_SERVERFAULT };
    }
    if (oneFs) {
      return { status: NFS4_OK };
    }
    if (client.reclaimComplete) {
      return { status: NFS4ERR_COMPLETE_ALREADY };
    }
    client.reclaimComplete = true;
    return { status: NFS4_OK };
  }

  // -------------------------------------------------------------------------
  // stateids (RFC 8881 §8.2)
  // -------------------------------------------------------------------------

  /**
   * Validate a stateid and say what it names (§8.2.3, §8.2.4).
   *
   * Special stateids come back named rather than resolved — `"anonymous"`,
   * `"bypass"`, `"current"` — because what they mean is the *operation's*
   * business: an anonymous stateid on a READ is a request to be checked against
   * the share reservations ({@link Nfs4State.shareDenies}), the same value on a
   * LOCK is `NFS4ERR_BAD_STATEID`, and `"current"` is a substitution only the
   * COMPOUND knows how to make. Everything else is resolved: an unknown `other`
   * is `NFS4ERR_BAD_STATEID`, a revoked one `NFS4ERR_EXPIRED`, a seqid below the
   * current one `NFS4ERR_OLD_STATEID` and above it `NFS4ERR_BAD_STATEID`, and
   * zero is the "use the most recent" wildcard.
   */
  checkStateid(request: StateidRequest): StateidResult {
    const special = specialStateid(request.stateid);
    if (special === undefined || special === "invalid") {
      return { status: NFS4ERR_BAD_STATEID };
    }
    if (special !== "normal") {
      return { status: NFS4_OK, kind: special };
    }
    const client = this.#byClientid.get(request.clientid);
    if (client === undefined) {
      return { status: NFS4ERR_EXPIRED };
    }
    const other = keyOf(request.stateid.other);
    if (client.revoked.has(other)) {
      return { status: NFS4ERR_EXPIRED };
    }
    const state = this.#states.get(other);
    if (state === undefined || state.clientid !== request.clientid) {
      // "If the client ID in the table entry does not match the client ID
      // associated with the current session, return NFS4ERR_BAD_STATEID."
      return { status: NFS4ERR_BAD_STATEID };
    }
    if (request.fileKey !== undefined && state.fileKey !== request.fileKey) {
      return { status: NFS4ERR_BAD_STATEID };
    }
    const want = request.want ?? "any";
    if (want !== "any" && want !== state.kind) {
      return { status: NFS4ERR_BAD_STATEID };
    }
    const seqid = request.stateid.seqid;
    if (seqid !== 0) {
      if (seqid > state.seqid) {
        return { status: NFS4ERR_BAD_STATEID };
      }
      if (seqid < state.seqid) {
        return { status: NFS4ERR_OLD_STATEID };
      }
    }
    const open = state.kind === "open" ? state : this.#openOf(state);
    return {
      status: NFS4_OK,
      kind: state.kind,
      access: open?.access ?? 0,
      deny: open?.deny ?? 0,
      fileKey: state.fileKey,
      stateid: { seqid: state.seqid, other: copyOf(state.other) },
      openStateid:
        open === undefined ? undefined : { seqid: open.seqid, other: copyOf(open.other) },
    };
  }

  /**
   * TEST_STATEID (§18.48.3): one status per stateid, and the operation itself
   * succeeds whatever they are.
   */
  testStateid(clientid: bigint, stateids: readonly Stateid4[]): number[] {
    return stateids.map((stateid) => this.checkStateid({ clientid, stateid }).status);
  }

  /**
   * FREE_STATEID (§18.38.3): drop a stateid that holds no locks.
   *
   * This is how a client acknowledges revoked state, which is why a revoked
   * `other` is accepted here and refused everywhere else; the last such
   * acknowledgement clears the sticky
   * `SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED` bit (§18.46.3). A live stateid with
   * locks under it is `NFS4ERR_LOCKS_HELD`.
   */
  freeStateid(clientid: bigint, stateid: Stateid4): { status: number } {
    const client = this.#byClientid.get(clientid);
    if (client === undefined) {
      // As for RECLAIM_COMPLETE: FREE_STATEID's §15.2 list has no
      // NFS4ERR_EXPIRED, and NFS4ERR_SERVERFAULT is listed.
      return { status: NFS4ERR_SERVERFAULT };
    }
    const other = keyOf(stateid.other);
    if (client.revoked.delete(other)) {
      if (client.revoked.size === 0) {
        client.statusFlags &= ~SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED;
      }
      return { status: NFS4_OK };
    }
    const state = this.#states.get(other);
    if (state === undefined || state.clientid !== clientid) {
      return { status: NFS4ERR_BAD_STATEID };
    }
    if (state.kind === "open") {
      return { status: NFS4ERR_LOCKS_HELD };
    }
    if (this.#hasRanges(state)) {
      return { status: NFS4ERR_LOCKS_HELD };
    }
    this.#dropLockState(client, state, { tombstone: false });
    return { status: NFS4_OK };
  }

  /**
   * {@link Nfs4State.checkStateid} for an operation that needs a *real* stateid
   * of a given kind, resolved to the record itself.
   *
   * The guard on `kind` is the whole point, and §8.2.4 spells the case out: "if
   * the combination is valid in general but is not appropriate to the context
   * in which the stateid is used (e.g., an all-zero stateid is used when an
   * OPEN stateid is required in a LOCK operation), the error
   * NFS4ERR_BAD_STATEID is also returned". A special stateid passes
   * `checkStateid` with `NFS4_OK` by design — READ and WRITE want to be told
   * "anonymous" rather than refused — so every caller that then needs an entry
   * out of the table has to come through here or it would dereference nothing.
   */
  #stateOf<K extends "open" | "lock">(
    clientid: bigint,
    stateid: Stateid4,
    fileKey: string | undefined,
    want: K,
  ): { status: number; state?: (K extends "open" ? OpenState : LockState) | undefined } {
    const checked = this.checkStateid({ clientid, stateid, fileKey, want });
    if (checked.status !== NFS4_OK) {
      return { status: checked.status };
    }
    const state = this.#states.get(keyOf(stateid.other));
    if (checked.kind !== want || state === undefined || state.kind !== want) {
      return { status: NFS4ERR_BAD_STATEID };
    }
    return { status: NFS4_OK, state: state as K extends "open" ? OpenState : LockState };
  }

  #openStateOf(
    clientid: bigint,
    stateid: Stateid4,
    fileKey?: string | undefined,
  ): { status: number; state?: OpenState | undefined } {
    return this.#stateOf(clientid, stateid, fileKey, "open");
  }

  #lockStateOf(
    clientid: bigint,
    stateid: Stateid4,
    fileKey?: string | undefined,
  ): { status: number; state?: LockState | undefined } {
    return this.#stateOf(clientid, stateid, fileKey, "lock");
  }

  #mintOther(): Uint8Array {
    const other = new Uint8Array(NFS4_OTHER_SIZE);
    const view = new DataView(other.buffer);
    view.setUint32(0, this.#seed, false);
    view.setBigUint64(4, this.#nextOther++, false);
    // An "other" of all zeros or all ones is reserved (§8.2.3); the counter
    // starts at one and the seed sits above it, so neither pattern is reachable.
    return other;
  }

  #openOf(lock: LockState): OpenState | undefined {
    const open = this.#states.get(lock.openKey);
    return open?.kind === "open" ? open : undefined;
  }

  #fileOf(fileKey: string): FileState {
    let file = this.#files.get(fileKey);
    if (file === undefined) {
      file = { opens: new Set(), locks: [] };
      this.#files.set(fileKey, file);
    }
    return file;
  }

  #forgetFileIfEmpty(fileKey: string): void {
    const file = this.#files.get(fileKey);
    if (file !== undefined && file.opens.size === 0 && file.locks.length === 0) {
      this.#files.delete(fileKey);
    }
  }

  // -------------------------------------------------------------------------
  // share reservations (RFC 8881 §9.7, §9.9, §18.16, §18.18, §18.2)
  // -------------------------------------------------------------------------

  /**
   * OPEN's share reservation half (§9.7).
   *
   * The check is §9.7's pseudo-code verbatim, including its awkward corner: the
   * `file_state` it is run against "includes bits that reflect all current
   * opens, **including those for the open-owner making the new OPEN request**",
   * so an owner that opened denying reads and then asks for read access is
   * denied by its own reservation. A repeat OPEN by the same owner on the same
   * file is an upgrade rather than a second open — one stateid, the union of
   * the access and deny bits, and a seqid bump "even in cases in which the
   * 'upgrade' results in no change to the open mode" (§9.9).
   */
  open(request: OpenRequest): OpenResult {
    const client = this.#byClientid.get(request.clientid);
    if (client === undefined) {
      return { status: NFS4ERR_EXPIRED };
    }
    if (request.reclaim === true) {
      // No stable storage, so no grace period and nothing to reclaim (§8.4.3
      // strategy 1, §15.1.9.3).
      return { status: NFS4ERR_NO_GRACE };
    }
    const access = shareAccessOf(request.shareAccess);
    if (
      access === undefined ||
      request.shareDeny > OPEN4_SHARE_DENY_BOTH ||
      request.shareDeny < 0
    ) {
      // §18.16.4 makes both tests a MUST, and names NFS4ERR_INVAL for each.
      return { status: NFS4ERR_INVAL };
    }
    if (this.#requireReclaimComplete && !client.reclaimComplete) {
      // §18.51.3: "If non-reclaim locking operations are done before the
      // RECLAIM_COMPLETE, an NFS4ERR_GRACE error will be returned."
      return { status: NFS4ERR_GRACE };
    }
    this.#revokeExpiredHolders(request.fileKey, request.clientid);

    const ownerKey = `${request.clientid}:${keyOf(request.owner)}`;
    let existing: OpenState | undefined;
    let state = 0;
    let denied = 0;
    for (const open of this.#files.get(request.fileKey)?.opens ?? []) {
      if (open.ownerKey === ownerKey) {
        existing = open;
      }
      state |= open.access;
      denied |= open.deny;
    }
    if ((access & denied) !== 0 || (request.shareDeny & state) !== 0) {
      return { status: NFS4ERR_SHARE_DENIED };
    }
    if (existing !== undefined) {
      existing.access |= access;
      existing.deny |= request.shareDeny;
      existing.seqid = bumpSeqid(existing.seqid);
      return {
        status: NFS4_OK,
        stateid: { seqid: existing.seqid, other: copyOf(existing.other) },
        upgraded: true,
      };
    }
    if ((this.#files.get(request.fileKey)?.opens.size ?? 0) >= this.#maxOpensPerFile) {
      return { status: NFS4ERR_DELAY };
    }
    const other = this.#mintOther();
    const open: OpenState = {
      kind: "open",
      key: keyOf(other),
      other,
      seqid: 1, // "When such a set of locks is first created, the server returns a stateid with seqid value of one" (§8.2.2).
      clientid: request.clientid,
      ownerKey,
      owner: copyOf(request.owner),
      fileKey: request.fileKey,
      access,
      deny: request.shareDeny,
      lockStates: new Set(),
    };
    this.#states.set(open.key, open);
    client.opens.set(open.key, open);
    this.#fileOf(request.fileKey).opens.add(open);
    return {
      status: NFS4_OK,
      stateid: { seqid: open.seqid, other: copyOf(other) },
      upgraded: false,
    };
  }

  /**
   * OPEN_DOWNGRADE (§18.18.3): narrow an open to a subset of what it holds.
   *
   * Invalid access or deny values are `NFS4ERR_INVAL` (MUST), and so is a set
   * of bits that is not a subset of the ones already granted — the RFC's SHOULD
   * for the second case, taken because the alternative is granting an *upgrade*
   * through the one operation whose name says it cannot. The seqid is bumped
   * "even in situations in which there is no change to the access and deny
   * bits".
   */
  openDowngrade(request: {
    clientid: bigint;
    stateid: Stateid4;
    shareAccess: number;
    shareDeny: number;
  }): { status: number; stateid?: Stateid4 | undefined } {
    const resolved = this.#openStateOf(request.clientid, request.stateid);
    if (resolved.status !== NFS4_OK) {
      return { status: resolved.status };
    }
    const open = resolved.state!;
    const access = shareAccessOf(request.shareAccess);
    if (access === undefined) {
      return { status: NFS4ERR_INVAL };
    }
    if (request.shareDeny < 0 || request.shareDeny > OPEN4_SHARE_DENY_BOTH) {
      return { status: NFS4ERR_INVAL };
    }
    if ((access & ~open.access) !== 0 || (request.shareDeny & ~open.deny) !== 0) {
      return { status: NFS4ERR_INVAL };
    }
    open.access = access;
    open.deny = request.shareDeny;
    open.seqid = bumpSeqid(open.seqid);
    return { status: NFS4_OK, stateid: { seqid: open.seqid, other: copyOf(open.other) } };
  }

  /**
   * CLOSE (§18.2.3): release the share reservations one open stateid stands for.
   *
   * "The server MUST return failure if any locks would exist after the CLOSE",
   * named `NFS4ERR_LOCKS_HELD` in §9.8 — this server does not free byte-range
   * locks implicitly, so a client LOCKUs first. Lock *stateids* with no ranges
   * left are not locks and go with the open. The stateid returned is the
   * invalid special one §18.2.4 recommends, since CLOSE's result is deprecated
   * and a client using it should find out.
   */
  close(request: { clientid: bigint; stateid: Stateid4 }): {
    status: number;
    stateid?: Stateid4 | undefined;
  } {
    const resolved = this.#openStateOf(request.clientid, request.stateid);
    if (resolved.status !== NFS4_OK) {
      return { status: resolved.status };
    }
    const client = this.#byClientid.get(request.clientid)!;
    const open = resolved.state!;
    for (const lockKey of open.lockStates) {
      const lock = this.#states.get(lockKey);
      if (lock?.kind === "lock" && this.#hasRanges(lock)) {
        return { status: NFS4ERR_LOCKS_HELD };
      }
    }
    for (const lockKey of open.lockStates) {
      const lock = this.#states.get(lockKey);
      if (lock?.kind === "lock") {
        this.#dropLockState(client, lock, { tombstone: false });
      }
    }
    this.#dropOpenState(client, open, { tombstone: false });
    return { status: NFS4_OK, stateid: invalidStateid() };
  }

  /**
   * Do the share reservations on a file deny `access` (§9.1.2)?
   *
   * Answers `NFS4ERR_LOCKED` — "when the OPEN denies READ or WRITE operations,
   * that denial results in such operations being rejected with error
   * NFS4ERR_LOCKED" — for I/O carrying an anonymous or READ-bypass stateid,
   * which by definition names no open of its own. Byte-range locks are advisory
   * here (§9.1.2), so they are not consulted: they "only prevent the granting of
   * conflicting lock requests and have no effect on READs or WRITEs".
   *
   * Expired holders are revoked first, exactly as {@link Nfs4State.open} and
   * {@link Nfs4State.lock} do. §8.4.3's MUST is written about conflicting *lock*
   * requests, so leaving I/O out would be defensible on the letter — but a
   * share reservation held under a dead lease blocking a live client's READ is
   * the same interference by a different route, and the asymmetry would be one
   * more rule to remember at every call site. `clientid` names the requester so
   * its own reservations are left alone; omit it and every expired holder is
   * revoked, which is right for a request that belongs to no client. No client
   * ID is ever `0n` — the counter starts at one.
   */
  shareDenies(fileKey: string, access: number, clientid = 0n): number {
    this.#revokeExpiredHolders(fileKey, clientid);
    const file = this.#files.get(fileKey);
    if (file === undefined) {
      return NFS4_OK;
    }
    let denied = 0;
    for (const open of file.opens) {
      denied |= open.deny;
    }
    return (accessBits(access) & denied) === 0 ? NFS4_OK : NFS4ERR_LOCKED;
  }

  #dropOpenState(
    client: ClientRecord,
    open: OpenState,
    options: { tombstone?: boolean } = {},
  ): void {
    this.#states.delete(open.key);
    client.opens.delete(open.key);
    const file = this.#files.get(open.fileKey);
    file?.opens.delete(open);
    if (options.tombstone !== false) {
      client.revoked.add(open.key);
    }
    this.#forgetFileIfEmpty(open.fileKey);
    this.#onOpenReleased?.(open.other);
  }

  // -------------------------------------------------------------------------
  // byte-range locks (RFC 8881 §9.1-§9.6, §18.10-§18.12)
  // -------------------------------------------------------------------------

  /**
   * LOCK (§18.10.3): take a byte range, or say who is holding it.
   *
   * The range rules are the RFC's: a length of zero is `NFS4ERR_INVAL`, a
   * length of `NFS4_UINT64_MAX` runs to EOF however long the file becomes, and
   * any other length whose sum with the offset exceeds `NFS4_UINT64_MAX` is
   * `NFS4ERR_INVAL`. Everything in the `locker4` that 4.1 made vestigial is
   * ignored: the open-owner's `clientid` and all three v4.0-era seqids, because
   * the client ID comes from the session.
   *
   * A conflict is `NFS4ERR_DENIED` carrying the conflicting range, its type and
   * its owner — with **that owner's real client ID**, "whether this is the
   * client ID associated with the current session or a different one", which is
   * the one place a client learns another client's identity. Ranges of the same
   * lock-owner are replaced rather than refused: overlapping, adjacent and
   * sub-ranges merge and split POSIX-style, so neither `NFS4ERR_LOCK_RANGE` nor
   * `NFS4ERR_LOCK_NOTSUPP` is ever returned. There is no blocking: `READW_LT`
   * and `WRITEW_LT` are answered exactly as their base types, and a client that
   * wants to wait polls (§9.6).
   */
  lock(request: LockRequest): LockResult {
    const client = this.#byClientid.get(request.clientid);
    if (client === undefined) {
      return { status: NFS4ERR_EXPIRED };
    }
    if (request.reclaim === true) {
      return { status: NFS4ERR_NO_GRACE };
    }
    const range = rangeOf(request.offset, request.length);
    if (range === undefined) {
      return { status: NFS4ERR_INVAL };
    }
    const type = baseLockType(request.locktype);
    if (type !== READ_LT && type !== WRITE_LT) {
      return { status: NFS4ERR_INVAL };
    }
    if (this.#requireReclaimComplete && !client.reclaimComplete) {
      return { status: NFS4ERR_GRACE };
    }

    // Which lock state the grant will be recorded against. Resolving it is
    // deliberately split from *creating* it: a lock-owner's first stateid must
    // come back with a seqid of one (§8.2.2), so nothing is minted until the
    // range has actually been granted.
    let lockState: LockState | undefined;
    let open: OpenState | undefined;
    if (request.lockStateid !== undefined) {
      const resolved = this.#lockStateOf(request.clientid, request.lockStateid, request.fileKey);
      if (resolved.status !== NFS4_OK) {
        return { status: resolved.status };
      }
      lockState = resolved.state;
      open = this.#openOf(lockState!);
    } else {
      if (request.openStateid === undefined || request.lockOwner === undefined) {
        // Neither arm of `locker4` was supplied: the caller decoded something
        // this table cannot act on.
        throw new TypeError("lock: locker4 needs either lockStateid or openStateid + lockOwner");
      }
      const resolved = this.#openStateOf(request.clientid, request.openStateid, request.fileKey);
      if (resolved.status !== NFS4_OK) {
        return { status: resolved.status };
      }
      open = resolved.state!;
      lockState = this.#lockStateIn(open, request.lockOwner);
    }
    if (open === undefined) {
      // A lock stateid whose open has gone is state this table should not hold.
      return { status: NFS4ERR_BAD_STATEID };
    }
    const ownerKey = lockState?.ownerKey ?? `${request.clientid}:${keyOf(request.lockOwner!)}`;

    this.#revokeExpiredHolders(request.fileKey, request.clientid);
    const file = this.#fileOf(request.fileKey);
    for (const held of file.locks) {
      if (overlaps(held, range.start, range.end) && conflicts(held, ownerKey, type)) {
        return { status: NFS4ERR_DENIED, denied: deniedOf(held) };
      }
    }
    if (file.locks.length >= this.#maxLocksPerFile) {
      return { status: NFS4ERR_DELAY };
    }
    if (lockState === undefined) {
      lockState = this.#createLockState(client, open, request.lockOwner!);
    } else {
      lockState.seqid = bumpSeqid(lockState.seqid);
    }
    file.locks = replaceRange(file.locks, {
      ownerKey,
      openKey: lockState.openKey,
      clientid: request.clientid,
      owner: lockState.owner,
      type,
      start: range.start,
      end: range.end,
    });
    return { status: NFS4_OK, stateid: { seqid: lockState.seqid, other: copyOf(lockState.other) } };
  }

  /**
   * LOCKT (§18.11.3): would a lock be granted, without taking one.
   *
   * "If no lock is held, nothing other than NFS4_OK is returned", and a
   * conflict comes back as `NFS4ERR_DENIED` with the holder's owner and real
   * client ID. The test excludes the asking lock-owner's own ranges, which
   * §18.11.4 says it SHOULD.
   */
  lockt(request: LocktRequest): { status: number; denied?: Lock4denied | undefined } {
    const client = this.#byClientid.get(request.clientid);
    if (client === undefined) {
      // A client ID this table never issued cannot reach here through a live
      // session, and LOCKT's valid errors (§15.2) include neither
      // NFS4ERR_EXPIRED nor NFS4ERR_STALE_CLIENTID nor NFS4ERR_SERVERFAULT, so
      // the answer is the one status §15.2 does list for "the replier could not
      // process this operation" (§15.1.1.3).
      return { status: NFS4ERR_DELAY };
    }
    const range = rangeOf(request.offset, request.length);
    if (range === undefined) {
      return { status: NFS4ERR_INVAL };
    }
    const type = baseLockType(request.locktype);
    if (type !== READ_LT && type !== WRITE_LT) {
      return { status: NFS4ERR_INVAL };
    }
    this.#revokeExpiredHolders(request.fileKey, request.clientid);
    const ownerKey = `${request.clientid}:${keyOf(request.owner)}`;
    for (const held of this.#files.get(request.fileKey)?.locks ?? []) {
      if (overlaps(held, range.start, range.end) && conflicts(held, ownerKey, type)) {
        return { status: NFS4ERR_DENIED, denied: deniedOf(held) };
      }
    }
    return { status: NFS4_OK };
  }

  /**
   * LOCKU (§18.12.3): release exactly the given range.
   *
   * The range is subtracted from whatever the lock-owner holds, splitting a
   * larger lock in two where it lands inside one — the POSIX behaviour
   * §18.12.4 describes a server as being allowed to refuse with
   * `NFS4ERR_LOCK_RANGE`, and this one implements instead. Two `LOCKU4args`
   * fields are decoration and neither reaches {@link LockuRequest}: `locktype`,
   * which "has no effect on the success or failure of the LOCKU operation", and
   * `seqid`, which "MAY be any value and the server MUST ignore it" (§18.12.3).
   * The stateid is the one argument that counts.
   */
  locku(request: LockuRequest): { status: number; stateid?: Stateid4 | undefined } {
    const range = rangeOf(request.offset, request.length);
    if (range === undefined) {
      return { status: NFS4ERR_INVAL };
    }
    const resolved = this.#lockStateOf(request.clientid, request.lockStateid, request.fileKey);
    if (resolved.status !== NFS4_OK) {
      return { status: resolved.status };
    }
    const lockState = resolved.state!;
    const file = this.#fileOf(request.fileKey);
    file.locks = subtractRange(file.locks, lockState.ownerKey, range.start, range.end);
    lockState.seqid = bumpSeqid(lockState.seqid);
    this.#forgetFileIfEmpty(request.fileKey);
    return { status: NFS4_OK, stateid: { seqid: lockState.seqid, other: copyOf(lockState.other) } };
  }

  /** The lock stateid this (lock-owner, open) pair already has, if any (§9.1.1). */
  #lockStateIn(open: OpenState, owner: Uint8Array): LockState | undefined {
    const ownerKey = `${open.clientid}:${keyOf(owner)}`;
    for (const key of open.lockStates) {
      const state = this.#states.get(key);
      if (state?.kind === "lock" && state.ownerKey === ownerKey) {
        return state;
      }
    }
    return undefined;
  }

  /**
   * Mint the lock stateid for a (lock-owner, open) pair.
   *
   * Called only once the LOCK that needed it has been granted, and with a seqid
   * of one rather than zero-then-bumped, because §8.2.2's "when such a set of
   * locks is first created, the server returns a stateid with seqid value of
   * one" is about the value the *client* first sees.
   */
  #createLockState(client: ClientRecord, open: OpenState, owner: Uint8Array): LockState {
    const other = this.#mintOther();
    const lockState: LockState = {
      kind: "lock",
      key: keyOf(other),
      other,
      seqid: 1,
      clientid: open.clientid,
      ownerKey: `${open.clientid}:${keyOf(owner)}`,
      owner: copyOf(owner),
      fileKey: open.fileKey,
      openKey: open.key,
    };
    this.#states.set(lockState.key, lockState);
    client.locks.set(lockState.key, lockState);
    open.lockStates.add(lockState.key);
    return lockState;
  }

  /**
   * Does this lock stateid still stand for granted bytes?
   *
   * Matched on the lock-owner **and** the open the range was last taken
   * through, which is the pair §9.5 makes meaningful: the *locking status* of a
   * byte belongs to the lock-owner "independent of the stateid through which
   * the request was sent" (so conflicts and merges key on the owner alone), but
   * "the open-owner to which that byte-range lock is assigned SHOULD be that of
   * the open-owner associated with the stateid through which the last LOCK of
   * that byte was done". Keying this question on the owner alone would let one
   * open-owner's ranges answer for another's when a client happens to use the
   * same lock-owner name under two opens — and CLOSE would then refuse forever
   * on locks its own open does not hold, against §9.8's "if any locks would
   * exist after the CLOSE".
   */
  #hasRanges(lock: LockState): boolean {
    const file = this.#files.get(lock.fileKey);
    return (
      file !== undefined &&
      file.locks.some((held) => held.ownerKey === lock.ownerKey && held.openKey === lock.openKey)
    );
  }

  #dropLockState(
    client: ClientRecord,
    lock: LockState,
    options: { tombstone?: boolean } = {},
  ): void {
    const file = this.#files.get(lock.fileKey);
    if (file !== undefined) {
      file.locks = file.locks.filter(
        (held) => held.ownerKey !== lock.ownerKey || held.openKey !== lock.openKey,
      );
    }
    this.#states.delete(lock.key);
    client.locks.delete(lock.key);
    const open = this.#states.get(lock.openKey);
    if (open?.kind === "open") {
      open.lockStates.delete(lock.key);
    }
    if (options.tombstone !== false) {
      client.revoked.add(lock.key);
    }
    this.#forgetFileIfEmpty(lock.fileKey);
  }
}

/** `LOCK4denied` for a held range, carrying its owner's real client ID (§18.10.3). */
function deniedOf(lock: ByteRangeLock): Lock4denied {
  return {
    offset: lock.start,
    length: lengthOf(lock),
    locktype: lock.type,
    owner: { clientid: lock.clientid, owner: copyOf(lock.owner) },
  };
}

/**
 * `(offset, length)` as `[start, end)`, or `undefined` for the two combinations
 * §18.10.3 makes `NFS4ERR_INVAL`: a zero length, and a length other than
 * `NFS4_UINT64_MAX` whose sum with the offset exceeds `NFS4_UINT64_MAX`.
 */
function rangeOf(offset: bigint, length: bigint): { start: bigint; end: bigint } | undefined {
  if (length === 0n || offset < 0n || length < 0n || offset > NFS4_MAXFILELEN) {
    return undefined;
  }
  if (length === NFS4_MAXFILELEN) {
    return { start: offset, end: EOF_END };
  }
  if (offset + length > NFS4_MAXFILELEN) {
    return undefined;
  }
  return { start: offset, end: offset + length };
}
