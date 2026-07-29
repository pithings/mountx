/**
 * Tier 0 for `src/nfs/v4/state.ts`: the NFSv4.1 state machine on its own.
 *
 * The module is pure and synchronous, so everything here is a direct call —
 * no socket, no driver, no encoded bytes. The clock is injected, which is what
 * makes the lease tests instant and deterministic rather than a `setTimeout`
 * with a prayer.
 *
 * Two things are worth naming, because they are the cases a state machine gets
 * wrong quietly:
 *
 * - **The replay cache is proved by a counter, not by a status.** The tests
 *   that matter run a fake COMPOUND through a `execute()` that increments
 *   `executions`, and a retransmission is only correct if the counter *does not
 *   move* and the bytes come back identical. A server that re-executed and
 *   happened to produce the same reply would pass a byte comparison alone.
 * - **The two seqid wraps are different conventions**, and both are RFC text: a
 *   slot's wraps to zero (§2.10.6.1) and a stateid's skips zero (§8.2.2).
 */

import { describe, expect, it } from "vitest";
import {
  EXCHGID4_FLAG_CONFIRMED_R,
  EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
  EXCHGID4_FLAG_USE_NON_PNFS,
  NFS4_MAXFILELEN,
  NFS4_OK,
  NFS4_OTHER_SIZE,
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
  OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
  OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL,
  OPEN4_SHARE_ACCESS_WRITE,
  OPEN4_SHARE_DENY_NONE,
  OPEN4_SHARE_DENY_READ,
  OPEN4_SHARE_DENY_WRITE,
  READ_LT,
  READW_LT,
  SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED,
  WRITE_LT,
} from "../../../src/nfs/v4/constants.ts";
import type { ChannelAttrs4, Stateid4 } from "../../../src/nfs/v4/protocol.ts";
import {
  bumpSeqid,
  nextSlotSeqid,
  Nfs4State,
  specialStateid,
  type Nfs4StateOptions,
  type SequenceOutcome,
} from "../../../src/nfs/v4/state.ts";

const UINT32_MAX = 0xff_ff_ff_ff;

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** A `channel_attrs4` offering more than any cap here allows, so trimming shows. */
function offeredAttrs(overrides: Partial<ChannelAttrs4> = {}): ChannelAttrs4 {
  return {
    headerpadsize: 16,
    maxrequestsize: 4 * 1024 * 1024,
    maxresponsesize: 4 * 1024 * 1024,
    maxresponsesizeCached: 1024 * 1024,
    maxoperations: 512,
    maxrequests: 1024,
    rdmaIrd: [],
    ...overrides,
  };
}

/** A clock the tests drive by hand, in milliseconds. */
function clock(): { now: () => number; advance: (seconds: number) => void } {
  let at = 1_000_000;
  return {
    now: () => at,
    advance: (seconds) => {
      at += seconds * 1000;
    },
  };
}

/**
 * One registered, confirmed, reclaim-complete client with a session, plus the
 * slot bookkeeping a COMPOUND would do.
 *
 * `send()` is a whole request: it runs SEQUENCE and, only for a `new` outcome,
 * "executes" — which is where the re-execution counter lives.
 */
class Peer {
  clientid = 0n;
  sessionid: Uint8Array = new Uint8Array(16);
  executions = 0;
  readonly seqids = new Map<number, number>();

  constructor(
    readonly state: Nfs4State,
    readonly ownerid: string,
    readonly verifier = "verifier-1",
  ) {}

  register(options: { reclaimComplete?: boolean; attrs?: ChannelAttrs4 } = {}): this {
    const exchanged = this.state.exchangeId({
      ownerid: bytes(this.ownerid),
      verifier: bytes(this.verifier),
      flags: 0,
    });
    expect(exchanged.status).toBe(NFS4_OK);
    this.clientid = exchanged.clientid;
    const created = this.state.createSession({
      clientid: this.clientid,
      sequence: exchanged.sequenceid,
      flags: 0,
      foreChanAttrs: options.attrs ?? offeredAttrs(),
      backChanAttrs: offeredAttrs(),
    });
    expect(created.status).toBe(NFS4_OK);
    this.sessionid = created.sessionid;
    if (options.reclaimComplete !== false) {
      expect(this.state.reclaimComplete(this.clientid).status).toBe(NFS4_OK);
    }
    return this;
  }

  /** The next sequence ID for a slot, tracked the way a client tracks it. */
  next(slotid: number): number {
    const seqid = nextSlotSeqid(this.seqids.get(slotid) ?? 0);
    this.seqids.set(slotid, seqid);
    return seqid;
  }

  sequence(
    options: {
      slotid?: number;
      sequenceid?: number;
      cachethis?: boolean;
      highestSlotid?: number;
    } = {},
  ) {
    const slotid = options.slotid ?? 0;
    return this.state.sequence({
      sessionid: this.sessionid,
      sequenceid: options.sequenceid ?? this.next(slotid),
      slotid,
      highestSlotid: options.highestSlotid ?? slotid,
      cachethis: options.cachethis ?? true,
    });
  }

  /**
   * A whole request: SEQUENCE, then the body, then the reply cache.
   *
   * `body()` stands for the rest of the COMPOUND and is called exactly once per
   * *new* request — never on a replay, which is the property under test.
   */
  send(
    body: () => Uint8Array,
    options: { slotid?: number; sequenceid?: number; cachethis?: boolean } = {},
  ): { outcome: SequenceOutcome; bytes?: Uint8Array | undefined } {
    const outcome = this.sequence(options);
    if (outcome.kind !== "new") {
      return { outcome, bytes: outcome.kind === "replay" ? outcome.bytes : undefined };
    }
    this.executions++;
    const reply = body();
    this.state.cacheReply(outcome.ticket, outcome.cachethis ? reply : undefined);
    return { outcome, bytes: reply };
  }
}

function newState(options: Nfs4StateOptions = {}): {
  state: Nfs4State;
  advance: (seconds: number) => void;
} {
  const time = clock();
  return { state: new Nfs4State({ now: time.now, ...options }), advance: time.advance };
}

// ---------------------------------------------------------------------------

describe("EXCHANGE_ID (RFC 8881 §18.35.4)", () => {
  it("case 1: a new owner ID gets a new, unconfirmed client ID", () => {
    const { state } = newState();
    const result = state.exchangeId({ ownerid: bytes("owner-a"), verifier: bytes("v1"), flags: 0 });

    expect(result.status).toBe(NFS4_OK);
    expect(result.clientid).not.toBe(0n);
    expect(result.sequenceid).toBe(1);
    expect(result.flags & EXCHGID4_FLAG_CONFIRMED_R).toBe(0);
    expect(result.flags & EXCHGID4_FLAG_USE_NON_PNFS).toBe(EXCHGID4_FLAG_USE_NON_PNFS);
  });

  it("case 4: repeating EXCHANGE_ID on an unconfirmed record replaces it", () => {
    const { state } = newState();
    const first = state.exchangeId({ ownerid: bytes("owner-a"), verifier: bytes("v1"), flags: 0 });
    const second = state.exchangeId({ ownerid: bytes("owner-a"), verifier: bytes("v1"), flags: 0 });

    expect(second.clientid).not.toBe(first.clientid);
    expect(state.clientCount).toBe(1);
  });

  it("case 2: the same owner and verifier on a confirmed record returns it unchanged", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    const again = state.exchangeId({
      ownerid: bytes("owner-a"),
      verifier: bytes("verifier-1"),
      flags: 0,
    });

    expect(again.clientid).toBe(peer.clientid);
    expect((again.flags & EXCHGID4_FLAG_CONFIRMED_R) >>> 0).toBe(EXCHGID4_FLAG_CONFIRMED_R);
  });

  it("case 5: a new verifier is a restarted client — new ID, old state kept until confirmation", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    expect(
      state.open({
        clientid: peer.clientid,
        owner: bytes("p1"),
        fileKey: "f",
        shareAccess: OPEN4_SHARE_ACCESS_READ,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).status,
    ).toBe(NFS4_OK);

    // A verifier of a different length is a different incarnation too.
    const restarted = state.exchangeId({
      ownerid: bytes("owner-a"),
      verifier: bytes("verifier-two"),
      flags: 0,
    });
    expect(restarted.clientid).not.toBe(peer.clientid);
    expect(restarted.flags & EXCHGID4_FLAG_CONFIRMED_R).toBe(0);
    // Both records exist at once, exactly as §18.35.4 case 5 describes.
    expect(state.clientCount).toBe(2);
    expect(state.stateCount).toBe(1);

    const created = state.createSession({
      clientid: restarted.clientid,
      sequence: restarted.sequenceid,
      flags: 0,
      foreChanAttrs: offeredAttrs(),
      backChanAttrs: offeredAttrs(),
    });
    expect(created.status).toBe(NFS4_OK);
    // Confirmation destroys the previous incarnation, its session and its opens.
    expect(state.clientCount).toBe(1);
    expect(state.sessionCount).toBe(1);
    expect(state.stateCount).toBe(0);
  });

  it("a different owner ID is a different client", () => {
    const { state } = newState();
    const a = new Peer(state, "owner-a").register();
    const b = new Peer(state, "owner-b").register();

    expect(a.clientid).not.toBe(b.clientid);
    expect(state.clientCount).toBe(2);
  });

  it("rejects undefined eia_flags bits with NFS4ERR_INVAL", () => {
    const { state } = newState();
    const result = state.exchangeId({
      ownerid: bytes("owner-a"),
      verifier: bytes("v1"),
      flags: 0x00_00_10_00,
    });

    expect(result.status).toBe(NFS4ERR_INVAL);
    expect(state.clientCount).toBe(0);
  });

  it("cases 6-8: an update needs a confirmed record and a matching verifier", () => {
    const { state } = newState();
    const update = {
      ownerid: bytes("owner-a"),
      verifier: bytes("verifier-1"),
      flags: EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
    };

    // Case 7: no confirmed record at all.
    expect(state.exchangeId(update).status).toBe(NFS4ERR_NOENT);

    const peer = new Peer(state, "owner-a").register();
    // Case 8: confirmed, wrong verifier.
    expect(state.exchangeId({ ...update, verifier: bytes("verifier-9") }).status).toBe(
      NFS4ERR_NOT_SAME,
    );
    // Case 6: the update itself.
    const updated = state.exchangeId(update);
    expect(updated.status).toBe(NFS4_OK);
    expect(updated.clientid).toBe(peer.clientid);
    expect((updated.flags & EXCHGID4_FLAG_CONFIRMED_R) >>> 0).toBe(EXCHGID4_FLAG_CONFIRMED_R);
  });
});

describe("CREATE_SESSION (RFC 8881 §18.36)", () => {
  it("phase 1: an unknown client ID is NFS4ERR_STALE_CLIENTID", () => {
    const { state } = newState();
    const created = state.createSession({
      clientid: 999n,
      sequence: 1,
      flags: 0,
      foreChanAttrs: offeredAttrs(),
      backChanAttrs: offeredAttrs(),
    });

    expect(created.status).toBe(NFS4ERR_STALE_CLIENTID);
  });

  it("phase 2: the contrived cache entry answers csa_sequence == eir_sequenceid - 1", () => {
    const { state } = newState();
    const exchanged = state.exchangeId({
      ownerid: bytes("owner-a"),
      verifier: bytes("v1"),
      flags: 0,
    });

    const early = state.createSession({
      clientid: exchanged.clientid,
      sequence: 0,
      flags: 0,
      foreChanAttrs: offeredAttrs(),
      backChanAttrs: offeredAttrs(),
    });
    expect(early.status).toBe(NFS4ERR_SEQ_MISORDERED);
    // The slot did not move: the real sequence still works.
    expect(
      state.createSession({
        clientid: exchanged.clientid,
        sequence: exchanged.sequenceid,
        flags: 0,
        foreChanAttrs: offeredAttrs(),
        backChanAttrs: offeredAttrs(),
      }).status,
    ).toBe(NFS4_OK);
  });

  it("phase 2: a repeated csa_sequence replays the identical reply and creates no session", () => {
    const { state } = newState();
    const exchanged = state.exchangeId({
      ownerid: bytes("owner-a"),
      verifier: bytes("v1"),
      flags: 0,
    });
    const args = {
      clientid: exchanged.clientid,
      sequence: exchanged.sequenceid,
      flags: 0,
      foreChanAttrs: offeredAttrs(),
      backChanAttrs: offeredAttrs(),
    };

    const first = state.createSession(args);
    const replay = state.createSession(args);

    expect(replay.replay).toBe(true);
    expect(replay.status).toBe(NFS4_OK);
    expect([...replay.sessionid]).toEqual([...first.sessionid]);
    expect(replay.foreChanAttrs).toEqual(first.foreChanAttrs);
    expect(replay.backChanAttrs).toEqual(first.backChanAttrs);
    expect(replay.flags).toBe(first.flags);
    expect(state.sessionCount).toBe(1);
  });

  it("phase 2: a csa_sequence two ahead is NFS4ERR_SEQ_MISORDERED", () => {
    const { state } = newState();
    const exchanged = state.exchangeId({
      ownerid: bytes("owner-a"),
      verifier: bytes("v1"),
      flags: 0,
    });

    const created = state.createSession({
      clientid: exchanged.clientid,
      sequence: exchanged.sequenceid + 1,
      flags: 0,
      foreChanAttrs: offeredAttrs(),
      backChanAttrs: offeredAttrs(),
    });

    expect(created.status).toBe(NFS4ERR_SEQ_MISORDERED);
    expect(state.sessionCount).toBe(0);
  });

  it("counter-offers every channel attribute, and never grants a back channel", () => {
    const { state } = newState({
      maxForeSlots: 8,
      maxOperations: 16,
      maxRequestSize: 65_536,
      maxCachedResponseSize: 4096,
    });
    const exchanged = state.exchangeId({
      ownerid: bytes("owner-a"),
      verifier: bytes("v1"),
      flags: 0,
    });

    const created = state.createSession({
      clientid: exchanged.clientid,
      sequence: exchanged.sequenceid,
      // CREATE_SESSION4_FLAG_CONN_BACK_CHAN, asked for and refused.
      flags: 0x00_00_00_02,
      foreChanAttrs: offeredAttrs(),
      backChanAttrs: offeredAttrs({ maxrequests: 7, maxoperations: 9 }),
    });

    expect(created.status).toBe(NFS4_OK);
    expect(created.flags).toBe(0);
    expect(created.foreChanAttrs).toEqual({
      headerpadsize: 0,
      maxrequestsize: 65_536,
      maxresponsesize: 65_536,
      maxresponsesizeCached: 4096,
      maxoperations: 16,
      maxrequests: 8,
      rdmaIrd: [],
    });
    // For the back channel the server "MUST NOT change the value the client
    // offers" for maxrequests and maxoperations.
    expect(created.backChanAttrs?.maxrequests).toBe(7);
    expect(created.backChanAttrs?.maxoperations).toBe(9);
  });

  it("refuses more sessions than the cap with NFS4ERR_NOSPC", () => {
    const { state } = newState({ maxSessions: 1 });
    const peer = new Peer(state, "owner-a").register();

    const second = state.createSession({
      clientid: peer.clientid,
      sequence: 2,
      flags: 0,
      foreChanAttrs: offeredAttrs(),
      backChanAttrs: offeredAttrs(),
    });

    expect(second.status).toBe(NFS4ERR_NOSPC);
  });
});

describe("SEQUENCE and the slot table (RFC 8881 §2.10.6.1, §18.46.3)", () => {
  it("rejects an unknown session, an out-of-range slot and an out-of-range highest slot", () => {
    const { state } = newState({ maxForeSlots: 4 });
    const peer = new Peer(state, "owner-a").register({ attrs: offeredAttrs({ maxrequests: 4 }) });

    expect(
      state.sequence({
        sessionid: new Uint8Array(16),
        sequenceid: 1,
        slotid: 0,
        highestSlotid: 0,
        cachethis: false,
      }),
    ).toEqual({ kind: "error", status: NFS4ERR_BADSESSION });
    expect(peer.sequence({ slotid: 4, sequenceid: 1 })).toEqual({
      kind: "error",
      status: NFS4ERR_BADSLOT,
    });
    expect(peer.sequence({ slotid: 0, sequenceid: 1, highestSlotid: 9 })).toEqual({
      kind: "error",
      status: NFS4ERR_BAD_HIGH_SLOT,
    });
  });

  it("answers the illegal first sequence ID of zero from the contrived cache entry", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();

    expect(peer.sequence({ sequenceid: 0 })).toEqual({
      kind: "error",
      status: NFS4ERR_SEQ_MISORDERED,
    });
    // The slot is untouched, so the mandated first sequence ID of one works.
    expect(peer.sequence({ sequenceid: 1 }).kind).toBe("new");
  });

  it("replays the exact cached bytes without re-executing", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    const body = (): Uint8Array => new Uint8Array([1, 2, 3, 4, 5]);

    const first = peer.send(body, { sequenceid: 1 });
    const retry = peer.send(body, { sequenceid: 1 });

    expect(first.outcome.kind).toBe("new");
    expect(retry.outcome.kind).toBe("replay");
    expect(peer.executions).toBe(1);
    expect([...retry.bytes!]).toEqual([1, 2, 3, 4, 5]);
    // Same bytes, and a *third* retry still does not run the body.
    peer.send(body, { sequenceid: 1 });
    expect(peer.executions).toBe(1);
  });

  it("copies the reply in, so the caller may re-use its buffer", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    const buffer = new Uint8Array([9, 9, 9]);

    const outcome = peer.sequence({ sequenceid: 1 });
    expect(outcome.kind).toBe("new");
    if (outcome.kind !== "new") {
      return;
    }
    state.cacheReply(outcome.ticket, buffer);
    buffer.fill(0);

    const replay = peer.sequence({ sequenceid: 1 });
    expect(replay.kind).toBe("replay");
    expect([...(replay as { bytes: Uint8Array }).bytes]).toEqual([9, 9, 9]);
  });

  it("answers a retry of an uncached reply with NFS4ERR_RETRY_UNCACHED_REP on the next operation", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    const body = (): Uint8Array => new Uint8Array([7]);

    peer.send(body, { sequenceid: 1, cachethis: false });
    const retry = peer.sequence({ sequenceid: 1 });

    expect(retry.kind).toBe("replay-uncached");
    if (retry.kind !== "replay-uncached") {
      return;
    }
    // The SEQUENCE itself succeeds: §2.10.6.1.3 forbids answering a *leading*
    // SEQUENCE with NFS4ERR_RETRY_UNCACHED_REP.
    expect(retry.status).toBe(NFS4_OK);
    expect(retry.sequence.status).toBe(NFS4_OK);
    expect(retry.opStatus).toBe(NFS4ERR_RETRY_UNCACHED_REP);
    expect(peer.executions).toBe(1);
  });

  it("leaves a reply too large for ca_maxresponsesize_cached uncached", () => {
    const { state } = newState({ maxCachedResponseSize: 8 });
    const peer = new Peer(state, "owner-a").register();

    peer.send(() => new Uint8Array(64), { sequenceid: 1 });

    expect(peer.sequence({ sequenceid: 1 }).kind).toBe("replay-uncached");
  });

  it("refuses a sequence ID two ahead, and does not move the slot", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    peer.send(() => new Uint8Array([1]), { sequenceid: 1 });

    expect(peer.sequence({ sequenceid: 3 })).toEqual({
      kind: "error",
      status: NFS4ERR_SEQ_MISORDERED,
    });
    expect(peer.sequence({ sequenceid: 2 }).kind).toBe("new");
    expect(peer.executions).toBe(1);
  });

  it("refuses a sequence ID behind the slot", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    peer.send(() => new Uint8Array([1]), { sequenceid: 1 });
    peer.send(() => new Uint8Array([2]), { sequenceid: 2 });

    expect(peer.sequence({ sequenceid: 1 })).toEqual({
      kind: "error",
      status: NFS4ERR_SEQ_MISORDERED,
    });
  });

  it("tracks slots independently", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();

    expect(peer.send(() => new Uint8Array([1]), { slotid: 0, sequenceid: 1 }).outcome.kind).toBe(
      "new",
    );
    expect(peer.send(() => new Uint8Array([2]), { slotid: 3, sequenceid: 1 }).outcome.kind).toBe(
      "new",
    );
    expect(peer.sequence({ slotid: 3, sequenceid: 1 }).kind).toBe("replay");
    expect(peer.sequence({ slotid: 0, sequenceid: 2 }).kind).toBe("new");
  });

  it("wraps a slot's sequence ID to zero, and a stateid's to one", () => {
    // §2.10.6.1: "If the previous sequence ID was 0xFFFFFFFF, then the next
    // request for the slot MUST have the sequence ID set to zero."
    expect(nextSlotSeqid(1)).toBe(2);
    expect(nextSlotSeqid(UINT32_MAX)).toBe(0);
    // §8.2.2: "until the seqid is incremented past NFS4_UINT32_MAX, and one
    // (not zero) is the next seqid value."
    expect(bumpSeqid(1)).toBe(2);
    expect(bumpSeqid(UINT32_MAX)).toBe(1);
  });

  it("reports the client's sticky status flags and the enforced highest slot", () => {
    const { state } = newState({ maxForeSlots: 4 });
    const peer = new Peer(state, "owner-a").register({ attrs: offeredAttrs({ maxrequests: 4 }) });

    const outcome = peer.sequence({ sequenceid: 1 });
    expect(outcome.kind).toBe("new");
    if (outcome.kind !== "new") {
      return;
    }
    expect(outcome.sequence.slotid).toBe(0);
    expect(outcome.sequence.sequenceid).toBe(1);
    expect(outcome.sequence.highestSlotid).toBe(3);
    expect(outcome.sequence.targetHighestSlotid).toBe(3);
    expect(outcome.sequence.statusFlags).toBe(0);
    expect([...outcome.sequence.sessionid]).toEqual([...peer.sessionid]);
    expect(state.clientOfSession(peer.sessionid)).toBe(peer.clientid);
  });
});

describe("stateids (RFC 8881 §8.2)", () => {
  const file = "file-1";

  function opened(): { state: Nfs4State; peer: Peer; stateid: Stateid4 } {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    const result = state.open({
      clientid: peer.clientid,
      owner: bytes("open-owner-1"),
      fileKey: file,
      shareAccess: OPEN4_SHARE_ACCESS_BOTH,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    });
    expect(result.status).toBe(NFS4_OK);
    return { state, peer, stateid: result.stateid! };
  }

  it("issues seqid 1 and bumps it on every state-changing operation", () => {
    const { state, peer, stateid } = opened();
    expect(stateid.seqid).toBe(1);

    const upgrade = state.open({
      clientid: peer.clientid,
      owner: bytes("open-owner-1"),
      fileKey: file,
      shareAccess: OPEN4_SHARE_ACCESS_READ,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    });

    expect(upgrade.status).toBe(NFS4_OK);
    expect(upgrade.upgraded).toBe(true);
    expect([...upgrade.stateid!.other]).toEqual([...stateid.other]);
    expect(upgrade.stateid!.seqid).toBe(2);
  });

  it("accepts seqid zero as the wildcard and refuses stale and future seqids", () => {
    const { state, peer, stateid } = opened();
    state.open({
      clientid: peer.clientid,
      owner: bytes("open-owner-1"),
      fileKey: file,
      shareAccess: OPEN4_SHARE_ACCESS_READ,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    });

    const wildcard = state.checkStateid({
      clientid: peer.clientid,
      stateid: { seqid: 0, other: stateid.other },
    });
    expect(wildcard.status).toBe(NFS4_OK);
    expect(wildcard.kind).toBe("open");
    expect(wildcard.stateid?.seqid).toBe(2);
    expect(wildcard.access).toBe(OPEN4_SHARE_ACCESS_BOTH);

    expect(
      state.checkStateid({ clientid: peer.clientid, stateid: { seqid: 1, other: stateid.other } })
        .status,
    ).toBe(NFS4ERR_OLD_STATEID);
    expect(
      state.checkStateid({ clientid: peer.clientid, stateid: { seqid: 3, other: stateid.other } })
        .status,
    ).toBe(NFS4ERR_BAD_STATEID);
  });

  it("refuses an unknown other, another client's stateid and the wrong file", () => {
    const { state, peer, stateid } = opened();
    const other = new Peer(state, "owner-b").register();

    const unknown = { seqid: 1, other: new Uint8Array(NFS4_OTHER_SIZE).fill(7) };
    expect(state.checkStateid({ clientid: peer.clientid, stateid: unknown }).status).toBe(
      NFS4ERR_BAD_STATEID,
    );
    expect(state.checkStateid({ clientid: other.clientid, stateid }).status).toBe(
      NFS4ERR_BAD_STATEID,
    );
    expect(
      state.checkStateid({ clientid: peer.clientid, stateid, fileKey: "other-file" }).status,
    ).toBe(NFS4ERR_BAD_STATEID);
    expect(state.checkStateid({ clientid: peer.clientid, stateid, want: "lock" }).status).toBe(
      NFS4ERR_BAD_STATEID,
    );
  });

  it("names the special stateids and refuses every other reserved combination (§8.2.3)", () => {
    const { state, peer } = opened();
    const zero = new Uint8Array(NFS4_OTHER_SIZE);
    const ones = new Uint8Array(NFS4_OTHER_SIZE).fill(0xff);
    const check = (stateid: Stateid4) => state.checkStateid({ clientid: peer.clientid, stateid });

    expect(check({ seqid: 0, other: zero })).toMatchObject({ status: NFS4_OK, kind: "anonymous" });
    expect(check({ seqid: UINT32_MAX, other: ones })).toMatchObject({
      status: NFS4_OK,
      kind: "bypass",
    });
    expect(check({ seqid: 1, other: zero })).toMatchObject({ status: NFS4_OK, kind: "current" });
    // Reserved and defined to be invalid, plus two undefined combinations.
    expect(check({ seqid: UINT32_MAX, other: zero }).status).toBe(NFS4ERR_BAD_STATEID);
    expect(check({ seqid: 5, other: zero }).status).toBe(NFS4ERR_BAD_STATEID);
    expect(check({ seqid: 0, other: ones }).status).toBe(NFS4ERR_BAD_STATEID);

    expect(specialStateid({ seqid: 0, other: new Uint8Array(NFS4_OTHER_SIZE).fill(3) })).toBe(
      "normal",
    );
  });

  it("TEST_STATEID answers per stateid, and FREE_STATEID drops an empty lock stateid", () => {
    const { state, peer, stateid } = opened();
    const lock = state.lock({
      clientid: peer.clientid,
      fileKey: "file-1",
      locktype: WRITE_LT,
      offset: 0n,
      length: 16n,
      openStateid: stateid,
      lockOwner: bytes("lock-owner-1"),
    });
    expect(lock.status).toBe(NFS4_OK);

    expect(
      state.testStateid(peer.clientid, [
        stateid,
        lock.stateid!,
        { seqid: 1, other: new Uint8Array(12).fill(4) },
      ]),
    ).toEqual([NFS4_OK, NFS4_OK, NFS4ERR_BAD_STATEID]);

    // Locks are held, so the lock stateid cannot be freed yet.
    expect(state.freeStateid(peer.clientid, lock.stateid!).status).toBe(NFS4ERR_LOCKS_HELD);
    // An open stateid is never freeable this way.
    expect(state.freeStateid(peer.clientid, stateid).status).toBe(NFS4ERR_LOCKS_HELD);

    expect(
      state.locku({
        clientid: peer.clientid,
        fileKey: "file-1",
        lockStateid: lock.stateid!,
        offset: 0n,
        length: 16n,
      }).status,
    ).toBe(NFS4_OK);
    expect(state.freeStateid(peer.clientid, lock.stateid!).status).toBe(NFS4_OK);
    expect(state.checkStateid({ clientid: peer.clientid, stateid: lock.stateid! }).status).toBe(
      NFS4ERR_BAD_STATEID,
    );
  });
});

describe("share reservations (RFC 8881 §9.7, §9.9, §18.2)", () => {
  const file = "file-1";

  function twoClients(): { state: Nfs4State; a: Peer; b: Peer } {
    const { state } = newState();
    return {
      state,
      a: new Peer(state, "owner-a").register(),
      b: new Peer(state, "owner-b").register(),
    };
  }

  function open(state: Nfs4State, peer: Peer, owner: string, access: number, deny: number) {
    return state.open({
      clientid: peer.clientid,
      owner: bytes(owner),
      fileKey: file,
      shareAccess: access,
      shareDeny: deny,
    });
  }

  it("denies an access the file's opens deny, and a deny the file's opens use", () => {
    const { state, a, b } = twoClients();
    expect(open(state, a, "p1", OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_READ).status).toBe(
      NFS4_OK,
    );

    // request.access & file_state.deny
    expect(open(state, b, "p2", OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE).status).toBe(
      NFS4ERR_SHARE_DENIED,
    );
    // request.deny & file_state.access
    expect(open(state, b, "p2", OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_WRITE).status).toBe(
      NFS4ERR_SHARE_DENIED,
    );
    // Neither: a write-only open with no deny of its own is fine.
    expect(open(state, b, "p2", OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE).status).toBe(
      NFS4_OK,
    );
  });

  it("checks the requesting open-owner's own reservation too, as §9.7 spells out", () => {
    const { state, a } = twoClients();
    expect(open(state, a, "p1", OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_READ).status).toBe(
      NFS4_OK,
    );

    // "the current file_state used in the algorithm includes bits that reflect
    // all current opens, including those for the open-owner making the new OPEN
    // request" — so this owner is denied by its own DENY_READ.
    expect(open(state, a, "p1", OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE).status).toBe(
      NFS4ERR_SHARE_DENIED,
    );
  });

  it("refuses a zero access mode and an out-of-range deny", () => {
    const { state, a } = twoClients();
    expect(open(state, a, "p1", 0, OPEN4_SHARE_DENY_NONE).status).toBe(NFS4ERR_INVAL);
    expect(open(state, a, "p1", OPEN4_SHARE_ACCESS_READ, 4).status).toBe(NFS4ERR_INVAL);
  });

  it("OPEN_DOWNGRADE narrows to a subset and refuses anything else", () => {
    const { state, a } = twoClients();
    const opened = open(state, a, "p1", OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_WRITE);
    const stateid = opened.stateid!;

    // Not a subset of the deny bits already granted (§18.18.3's SHOULD).
    const bad = state.openDowngrade({
      clientid: a.clientid,
      stateid,
      shareAccess: OPEN4_SHARE_ACCESS_BOTH,
      shareDeny: 3,
    });
    expect(bad.status).toBe(NFS4ERR_INVAL);
    // Not a legal share_deny value at all (§18.18.3's MUST).
    expect(
      state.openDowngrade({
        clientid: a.clientid,
        stateid,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: 4,
      }).status,
    ).toBe(NFS4ERR_INVAL);
    expect(
      state.openDowngrade({
        clientid: a.clientid,
        stateid,
        shareAccess: 0,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).status,
    ).toBe(NFS4ERR_INVAL);

    const downgraded = state.openDowngrade({
      clientid: a.clientid,
      stateid,
      shareAccess: OPEN4_SHARE_ACCESS_READ,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    });
    expect(downgraded.status).toBe(NFS4_OK);
    expect(downgraded.stateid!.seqid).toBe(2);
    expect(state.checkStateid({ clientid: a.clientid, stateid: downgraded.stateid! }).access).toBe(
      OPEN4_SHARE_ACCESS_READ,
    );
  });

  it("CLOSE releases the reservation, and refuses while byte-range locks are held", () => {
    const { state, a, b } = twoClients();
    const opened = open(state, a, "p1", OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_WRITE);
    const stateid = opened.stateid!;
    expect(open(state, b, "p2", OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE).status).toBe(
      NFS4ERR_SHARE_DENIED,
    );

    const lock = state.lock({
      clientid: a.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 0n,
      length: 4n,
      openStateid: stateid,
      lockOwner: bytes("lock-owner-1"),
    });
    expect(lock.status).toBe(NFS4_OK);
    // §18.2.3/§9.8: the server MUST fail rather than free the locks.
    expect(state.close({ clientid: a.clientid, stateid }).status).toBe(NFS4ERR_LOCKS_HELD);

    expect(
      state.locku({
        clientid: a.clientid,
        fileKey: file,
        lockStateid: lock.stateid!,
        offset: 0n,
        length: 4n,
      }).status,
    ).toBe(NFS4_OK);
    const closed = state.close({ clientid: a.clientid, stateid });
    expect(closed.status).toBe(NFS4_OK);
    // §18.2.4: the deprecated result is the invalid special stateid.
    expect(closed.stateid).toEqual({ seqid: UINT32_MAX, other: new Uint8Array(NFS4_OTHER_SIZE) });
    expect(state.stateCount).toBe(0);
    expect(open(state, b, "p2", OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE).status).toBe(
      NFS4_OK,
    );
  });

  it("answers NFS4ERR_LOCKED for I/O that a share reservation denies", () => {
    const { state, a } = twoClients();
    expect(open(state, a, "p1", OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_READ).status).toBe(
      NFS4_OK,
    );

    expect(state.shareDenies(file, OPEN4_SHARE_ACCESS_READ)).toBe(NFS4ERR_LOCKED);
    expect(state.shareDenies(file, OPEN4_SHARE_ACCESS_WRITE)).toBe(NFS4_OK);
    expect(state.shareDenies("untouched-file", OPEN4_SHARE_ACCESS_BOTH)).toBe(NFS4_OK);
  });

  it("refuses a reclaim with NFS4ERR_NO_GRACE and a first open before RECLAIM_COMPLETE with NFS4ERR_GRACE", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register({ reclaimComplete: false });
    const request = {
      clientid: peer.clientid,
      owner: bytes("p1"),
      fileKey: file,
      shareAccess: OPEN4_SHARE_ACCESS_READ,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    };

    expect(state.open({ ...request, reclaim: true }).status).toBe(NFS4ERR_NO_GRACE);
    expect(state.open(request).status).toBe(NFS4ERR_GRACE);

    expect(state.reclaimComplete(peer.clientid).status).toBe(NFS4_OK);
    expect(state.open(request).status).toBe(NFS4_OK);
  });

  it("refuses more opens on one file than the cap", () => {
    const { state } = newState({ maxOpensPerFile: 1 });
    const a = new Peer(state, "owner-a").register();
    const b = new Peer(state, "owner-b").register();

    expect(open(state, a, "p1", OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE).status).toBe(
      NFS4_OK,
    );
    // NFS4ERR_DELAY, not NFS4ERR_RESOURCE: the latter is not a legal 4.1 status.
    expect(open(state, b, "p2", OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE).status).toBe(
      NFS4ERR_DELAY,
    );
  });
});

describe("byte-range locks (RFC 8881 §9.1-§9.6, §18.10-§18.12)", () => {
  const file = "file-1";

  function locker(): { state: Nfs4State; peer: Peer; open: Stateid4 } {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    const opened = state.open({
      clientid: peer.clientid,
      owner: bytes("p1"),
      fileKey: file,
      shareAccess: OPEN4_SHARE_ACCESS_BOTH,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    });
    return { state, peer, open: opened.stateid! };
  }

  function ranges(state: Nfs4State): { start: bigint; end: bigint; type: number }[] {
    return state
      .locksOf(file)
      .map((lock) => ({ start: lock.start, end: lock.end, type: lock.type }));
  }

  it("refuses a zero length and an offset+length past NFS4_UINT64_MAX", () => {
    const { state, peer, open } = locker();
    const lock = (offset: bigint, length: bigint) =>
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset,
        length,
        openStateid: open,
        lockOwner: bytes("l1"),
      });

    expect(lock(0n, 0n).status).toBe(NFS4ERR_INVAL);
    expect(lock(2n, NFS4_MAXFILELEN - 1n).status).toBe(NFS4ERR_INVAL);
    // Exactly NFS4_UINT64_MAX is the sum's limit, not past it.
    expect(lock(1n, NFS4_MAXFILELEN - 1n).status).toBe(NFS4_OK);
  });

  it("takes a to-EOF lock when the length is NFS4_UINT64_MAX", () => {
    const { state, peer, open } = locker();
    const taken = state.lock({
      clientid: peer.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 100n,
      length: NFS4_MAXFILELEN,
      openStateid: open,
      lockOwner: bytes("l1"),
    });

    expect(taken.status).toBe(NFS4_OK);
    expect(state.locksOf(file)).toHaveLength(1);
    // A conflict on it reports the length back as NFS4_UINT64_MAX, not as an
    // arithmetic difference.
    const conflict = state.lockt({
      clientid: peer.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 1_000_000n,
      length: 1n,
      owner: bytes("l2"),
    });
    expect(conflict.status).toBe(NFS4ERR_DENIED);
    expect(conflict.denied?.offset).toBe(100n);
    expect(conflict.denied?.length).toBe(NFS4_MAXFILELEN);
  });

  it("merges the same owner's adjacent and overlapping ranges", () => {
    const { state, peer, open } = locker();
    const lock = (offset: bigint, length: bigint, type = WRITE_LT) =>
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: type,
        offset,
        length,
        openStateid: open,
        lockOwner: bytes("l1"),
      });

    expect(lock(0n, 10n).status).toBe(NFS4_OK);
    expect(lock(10n, 10n).status).toBe(NFS4_OK);
    expect(ranges(state)).toEqual([{ start: 0n, end: 20n, type: WRITE_LT }]);

    expect(lock(15n, 20n).status).toBe(NFS4_OK);
    expect(ranges(state)).toEqual([{ start: 0n, end: 35n, type: WRITE_LT }]);
  });

  it("splits a range when the same owner takes a different type inside it", () => {
    const { state, peer, open } = locker();
    const lock = (offset: bigint, length: bigint, type: number) =>
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: type,
        offset,
        length,
        openStateid: open,
        lockOwner: bytes("l1"),
      });

    expect(lock(0n, 100n, READ_LT).status).toBe(NFS4_OK);
    expect(lock(40n, 10n, WRITE_LT).status).toBe(NFS4_OK);

    expect(ranges(state)).toEqual([
      { start: 0n, end: 40n, type: READ_LT },
      { start: 40n, end: 50n, type: WRITE_LT },
      { start: 50n, end: 100n, type: READ_LT },
    ]);
  });

  it("LOCKU frees exactly the range it names, splitting a larger lock", () => {
    const { state, peer, open } = locker();
    const taken = state.lock({
      clientid: peer.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 0n,
      length: 100n,
      openStateid: open,
      lockOwner: bytes("l1"),
    });
    // §8.2.2: the first stateid of a set carries seqid one, not one bump later.
    expect(taken.stateid!.seqid).toBe(1);

    const released = state.locku({
      clientid: peer.clientid,
      fileKey: file,
      lockStateid: taken.stateid!,
      offset: 40n,
      length: 10n,
    });

    expect(released.status).toBe(NFS4_OK);
    expect(released.stateid!.seqid).toBe(2);
    expect(ranges(state)).toEqual([
      { start: 0n, end: 40n, type: WRITE_LT },
      { start: 50n, end: 100n, type: WRITE_LT },
    ]);

    // The stateid moved with the LOCKU, so re-presenting the one that went in
    // is NFS4ERR_OLD_STATEID (§8.2.2) — the exact-range unlocks below carry the
    // stateid each previous answer returned.
    expect(
      state.locku({
        clientid: peer.clientid,
        fileKey: file,
        lockStateid: taken.stateid!,
        offset: 0n,
        length: 40n,
      }).status,
    ).toBe(NFS4ERR_OLD_STATEID);

    const left = state.locku({
      clientid: peer.clientid,
      fileKey: file,
      lockStateid: released.stateid!,
      offset: 0n,
      length: 40n,
    });
    expect(left.status).toBe(NFS4_OK);
    expect(
      state.locku({
        clientid: peer.clientid,
        fileKey: file,
        lockStateid: left.stateid!,
        offset: 50n,
        length: 50n,
      }).status,
    ).toBe(NFS4_OK);
    expect(state.locksOf(file)).toHaveLength(0);
  });

  it("denies a conflicting range and names the holder's owner and real client ID", () => {
    const { state } = newState();
    const a = new Peer(state, "owner-a").register();
    const b = new Peer(state, "owner-b").register();
    const openOf = (peer: Peer, owner: string): Stateid4 =>
      state.open({
        clientid: peer.clientid,
        owner: bytes(owner),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).stateid!;

    const held = state.lock({
      clientid: a.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 10n,
      length: 10n,
      openStateid: openOf(a, "p1"),
      lockOwner: bytes("lock-owner-a"),
    });
    expect(held.status).toBe(NFS4_OK);

    const denied = state.lock({
      clientid: b.clientid,
      fileKey: file,
      locktype: READ_LT,
      offset: 15n,
      length: 10n,
      openStateid: openOf(b, "p2"),
      lockOwner: bytes("lock-owner-b"),
    });

    expect(denied.status).toBe(NFS4ERR_DENIED);
    expect(denied.denied).toEqual({
      offset: 10n,
      length: 10n,
      locktype: WRITE_LT,
      // §18.10.3: "the actual client associated with the conflicting lock,
      // whether this is the client ID associated with the current session or a
      // different one."
      owner: { clientid: a.clientid, owner: bytes("lock-owner-a") },
    });
    expect(denied.denied!.owner.clientid).not.toBe(b.clientid);
  });

  it("lets two read locks of different owners overlap, and refuses a write over them", () => {
    const { state } = newState();
    const a = new Peer(state, "owner-a").register();
    const b = new Peer(state, "owner-b").register();
    const openOf = (peer: Peer): Stateid4 =>
      state.open({
        clientid: peer.clientid,
        owner: bytes("p"),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).stateid!;

    expect(
      state.lock({
        clientid: a.clientid,
        fileKey: file,
        locktype: READ_LT,
        offset: 0n,
        length: 20n,
        openStateid: openOf(a),
        lockOwner: bytes("la"),
      }).status,
    ).toBe(NFS4_OK);
    const second = state.lock({
      clientid: b.clientid,
      fileKey: file,
      // READW_LT is the polling form of READ_LT and is answered identically.
      locktype: READW_LT,
      offset: 10n,
      length: 20n,
      openStateid: openOf(b),
      lockOwner: bytes("lb"),
    });
    expect(second.status).toBe(NFS4_OK);
    expect(state.locksOf(file)).toHaveLength(2);

    expect(
      state.lockt({
        clientid: a.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset: 25n,
        length: 1n,
        owner: bytes("la"),
      }).status,
    ).toBe(NFS4ERR_DENIED);
  });

  it("LOCKT tests without taking anything, and ignores the asking owner's own locks", () => {
    const { state, peer, open } = locker();
    expect(
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset: 0n,
        length: 10n,
        openStateid: open,
        lockOwner: bytes("l1"),
      }).status,
    ).toBe(NFS4_OK);

    const own = state.lockt({
      clientid: peer.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 0n,
      length: 10n,
      owner: bytes("l1"),
    });
    expect(own).toEqual({ status: NFS4_OK });

    const free = state.lockt({
      clientid: peer.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 500n,
      length: 10n,
      owner: bytes("l2"),
    });
    expect(free).toEqual({ status: NFS4_OK });
    // Nothing was taken by either test.
    expect(state.locksOf(file)).toHaveLength(1);
  });

  it("takes the second lock of a lock-owner through its lock stateid", () => {
    const { state, peer, open } = locker();
    const first = state.lock({
      clientid: peer.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 0n,
      length: 10n,
      openStateid: open,
      lockOwner: bytes("l1"),
    });

    const second = state.lock({
      clientid: peer.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 100n,
      length: 10n,
      lockStateid: first.stateid!,
    });

    expect(second.status).toBe(NFS4_OK);
    expect([...second.stateid!.other]).toEqual([...first.stateid!.other]);
    expect(first.stateid!.seqid).toBe(1);
    expect(second.stateid!.seqid).toBe(2);
    expect(state.locksOf(file)).toHaveLength(2);
  });

  it("refuses a lock reclaim with NFS4ERR_NO_GRACE and a first lock before RECLAIM_COMPLETE with NFS4ERR_GRACE", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register({ reclaimComplete: false });
    expect(state.reclaimComplete(peer.clientid).status).toBe(NFS4_OK);
    const open = state.open({
      clientid: peer.clientid,
      owner: bytes("p1"),
      fileKey: file,
      shareAccess: OPEN4_SHARE_ACCESS_BOTH,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    }).stateid!;

    const request = {
      clientid: peer.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 0n,
      length: 1n,
      openStateid: open,
      lockOwner: bytes("l1"),
    };
    expect(state.lock({ ...request, reclaim: true }).status).toBe(NFS4ERR_NO_GRACE);

    const strict = new Nfs4State();
    const other = new Peer(strict, "owner-z").register({ reclaimComplete: false });
    expect(
      strict.open({
        clientid: other.clientid,
        owner: bytes("p1"),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).status,
    ).toBe(NFS4ERR_GRACE);
  });
});

describe("leases (RFC 8881 §8.3, §8.4.3)", () => {
  const file = "file-1";

  function openOn(state: Nfs4State, peer: Peer, owner = "p1"): Stateid4 {
    return state.open({
      clientid: peer.clientid,
      owner: bytes(owner),
      fileKey: file,
      shareAccess: OPEN4_SHARE_ACCESS_WRITE,
      shareDeny: OPEN4_SHARE_DENY_READ,
    }).stateid!;
  }

  it("SEQUENCE renews the lease", () => {
    const { state, advance } = newState({ leaseSeconds: 60 });
    const peer = new Peer(state, "owner-a").register();
    const stateid = openOn(state, peer);

    advance(50);
    expect(peer.sequence({ sequenceid: 1 }).kind).toBe("new");
    advance(50);

    // 100 s after the open but only 50 s after the renewal.
    const checked = state.checkStateid({ clientid: peer.clientid, stateid });
    expect(checked.status).toBe(NFS4_OK);
    expect(state.sweep()).toBe(0);
  });

  it("revokes an expired client's state when it stands in a live client's way", () => {
    const { state, advance } = newState({ leaseSeconds: 60 });
    const a = new Peer(state, "owner-a").register();
    const b = new Peer(state, "owner-b").register();
    const stale = openOn(state, a);
    expect(
      state.open({
        clientid: b.clientid,
        owner: bytes("p2"),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_READ,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).status,
    ).toBe(NFS4ERR_SHARE_DENIED);

    advance(61);
    // B renews its own lease, then opens: A's reservation is expired and MUST
    // NOT stand in the way (§8.4.3).
    expect(b.sequence({ sequenceid: 1 }).kind).toBe("new");
    expect(
      state.open({
        clientid: b.clientid,
        owner: bytes("p2"),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_READ,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).status,
    ).toBe(NFS4_OK);
    // A's stateid is now a revoked tombstone.
    expect(state.checkStateid({ clientid: a.clientid, stateid: stale }).status).toBe(
      NFS4ERR_EXPIRED,
    );
  });

  it("a SEQUENCE on an expired lease revokes, reports and renews", () => {
    const { state, advance } = newState({ leaseSeconds: 60 });
    const peer = new Peer(state, "owner-a").register();
    const stateid = openOn(state, peer);

    advance(61);
    const outcome = peer.sequence({ sequenceid: 1 });
    expect(outcome.kind).toBe("new");
    if (outcome.kind !== "new") {
      return;
    }
    expect(outcome.sequence.statusFlags & SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED).toBe(
      SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED,
    );
    expect(state.checkStateid({ clientid: peer.clientid, stateid }).status).toBe(NFS4ERR_EXPIRED);

    // FREE_STATEID is the acknowledgement that clears the sticky bit (§18.46.3).
    expect(state.freeStateid(peer.clientid, stateid).status).toBe(NFS4_OK);
    const after = peer.sequence({ sequenceid: 2 });
    expect(after.kind).toBe("new");
    if (after.kind === "new") {
      expect(after.sequence.statusFlags).toBe(0);
    }
  });

  it("sweep() removes an expired client outright: BADSESSION, then STALE_CLIENTID", () => {
    const { state, advance } = newState({ leaseSeconds: 60 });
    const peer = new Peer(state, "owner-a").register();
    openOn(state, peer);

    advance(61);
    expect(state.sweep()).toBe(1);
    expect(state.clientCount).toBe(0);
    expect(state.sessionCount).toBe(0);
    expect(state.stateCount).toBe(0);

    expect(peer.sequence({ sequenceid: 1 })).toEqual({ kind: "error", status: NFS4ERR_BADSESSION });
    expect(
      state.createSession({
        clientid: peer.clientid,
        sequence: 2,
        flags: 0,
        foreChanAttrs: offeredAttrs(),
        backChanAttrs: offeredAttrs(),
      }).status,
    ).toBe(NFS4ERR_STALE_CLIENTID);
  });
});

describe("RECLAIM_COMPLETE, DESTROY_SESSION and DESTROY_CLIENTID", () => {
  it("records the global RECLAIM_COMPLETE once (§18.51.4)", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register({ reclaimComplete: false });

    expect(state.reclaimComplete(peer.clientid).status).toBe(NFS4_OK);
    expect(state.reclaimComplete(peer.clientid).status).toBe(NFS4ERR_COMPLETE_ALREADY);
    // The per-file system form is accepted and ignored, however often it comes.
    expect(state.reclaimComplete(peer.clientid, true).status).toBe(NFS4_OK);
    expect(state.reclaimComplete(peer.clientid, true).status).toBe(NFS4_OK);
  });

  it("DESTROY_SESSION is once, and leaves the client's state alone (§18.37.3)", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    const stateid = state.open({
      clientid: peer.clientid,
      owner: bytes("p1"),
      fileKey: "file-1",
      shareAccess: OPEN4_SHARE_ACCESS_READ,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    }).stateid!;

    expect(state.destroySession(peer.sessionid).status).toBe(NFS4_OK);
    expect(state.destroySession(peer.sessionid).status).toBe(NFS4ERR_BADSESSION);
    expect(state.destroySession(new Uint8Array(16)).status).toBe(NFS4ERR_BADSESSION);
    expect(state.sessionCount).toBe(0);
    expect(state.checkStateid({ clientid: peer.clientid, stateid }).status).toBe(NFS4_OK);
  });

  it("DESTROY_CLIENTID refuses a busy client and an unknown one (§18.50.3)", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();

    expect(state.destroyClientid(12_345n).status).toBe(NFS4ERR_STALE_CLIENTID);
    // Sessions exist.
    expect(state.destroyClientid(peer.clientid).status).toBe(NFS4ERR_CLIENTID_BUSY);
    // Sent inside a SEQUENCE for the very client being destroyed.
    expect(state.destroyClientid(peer.clientid, { sessionClientid: peer.clientid }).status).toBe(
      NFS4ERR_CLIENTID_BUSY,
    );

    const stateid = state.open({
      clientid: peer.clientid,
      owner: bytes("p1"),
      fileKey: "file-1",
      shareAccess: OPEN4_SHARE_ACCESS_READ,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    }).stateid!;
    expect(state.destroySession(peer.sessionid).status).toBe(NFS4_OK);
    // Still busy: an open is state too.
    expect(state.destroyClientid(peer.clientid).status).toBe(NFS4ERR_CLIENTID_BUSY);

    expect(state.close({ clientid: peer.clientid, stateid }).status).toBe(NFS4_OK);
    expect(state.destroyClientid(peer.clientid).status).toBe(NFS4_OK);
    expect(state.clientCount).toBe(0);
  });
});

describe("argument errors, caps and the paths a session leans on", () => {
  const file = "file-1";

  function openedPeer(options: Nfs4StateOptions = {}): {
    state: Nfs4State;
    peer: Peer;
    open: Stateid4;
    advance: (seconds: number) => void;
  } {
    const { state, advance } = newState(options);
    const peer = new Peer(state, "owner-a").register();
    const open = state.open({
      clientid: peer.clientid,
      owner: bytes("p1"),
      fileKey: file,
      shareAccess: OPEN4_SHARE_ACCESS_BOTH,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    }).stateid!;
    return { state, peer, open, advance };
  }

  it("reports the lease it was configured with", () => {
    const { state } = newState({ leaseSeconds: 45 });
    expect(state.leaseSeconds).toBe(45);
    expect(new Nfs4State().leaseSeconds).toBe(90);
  });

  it("throws for a ticket it did not issue, and ignores one whose slot has moved on", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();

    expect(() => state.cacheReply({ slotid: 0, sequenceid: 1 })).toThrow(TypeError);

    const first = peer.sequence({ sequenceid: 1 });
    expect(first.kind).toBe("new");
    if (first.kind !== "new") {
      return;
    }
    // The client moves the slot on without the first reply ever being cached.
    expect(peer.sequence({ sequenceid: 2 }).kind).toBe("new");
    state.cacheReply(first.ticket, new Uint8Array([1, 2, 3]));

    // The stale reply was dropped rather than filed under sequence 2.
    expect(peer.sequence({ sequenceid: 2 }).kind).toBe("replay-uncached");
  });

  it("refuses every operation from a client it has never heard of", () => {
    const { state } = newState();
    const unknown = 4242n;
    const stateid: Stateid4 = { seqid: 1, other: new Uint8Array(NFS4_OTHER_SIZE).fill(2) };

    expect(
      state.open({
        clientid: unknown,
        owner: bytes("p"),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_READ,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).status,
    ).toBe(NFS4ERR_EXPIRED);
    expect(
      state.lock({
        clientid: unknown,
        fileKey: file,
        locktype: WRITE_LT,
        offset: 0n,
        length: 1n,
        openStateid: stateid,
        lockOwner: bytes("l"),
      }).status,
    ).toBe(NFS4ERR_EXPIRED);
    // Each of the three below answers with a status §15.2 lists for *that*
    // operation: LOCKT's valid errors have no NFS4ERR_EXPIRED and no
    // NFS4ERR_SERVERFAULT, RECLAIM_COMPLETE's and FREE_STATEID's have the
    // latter but not the former.
    expect(
      state.lockt({
        clientid: unknown,
        fileKey: file,
        locktype: WRITE_LT,
        offset: 0n,
        length: 1n,
        owner: bytes("l"),
      }).status,
    ).toBe(NFS4ERR_DELAY);
    expect(state.freeStateid(unknown, stateid).status).toBe(NFS4ERR_SERVERFAULT);
    // A stateid this table never issued, presented by a client it does know.
    const known = new Peer(state, "owner-known").register();
    expect(state.freeStateid(known.clientid, stateid).status).toBe(NFS4ERR_BAD_STATEID);
    expect(state.reclaimComplete(unknown).status).toBe(NFS4ERR_SERVERFAULT);
    expect(state.checkStateid({ clientid: unknown, stateid }).status).toBe(NFS4ERR_EXPIRED);
  });

  it("refuses a lock type outside nfs_lock_type4, and an unusable locker4", () => {
    const { state, peer, open } = openedPeer();
    const request = {
      clientid: peer.clientid,
      fileKey: file,
      offset: 0n,
      length: 1n,
      openStateid: open,
      lockOwner: bytes("l1"),
    };

    expect(state.lock({ ...request, locktype: 9 }).status).toBe(NFS4ERR_INVAL);
    expect(
      state.lockt({
        clientid: peer.clientid,
        fileKey: file,
        locktype: 9,
        offset: 0n,
        length: 1n,
        owner: bytes("l1"),
      }).status,
    ).toBe(NFS4ERR_INVAL);
    expect(
      state.lockt({
        clientid: peer.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset: 0n,
        length: 0n,
        owner: bytes("l1"),
      }).status,
    ).toBe(NFS4ERR_INVAL);
    expect(() =>
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset: 0n,
        length: 1n,
      }),
    ).toThrow(TypeError);
  });

  it("passes a bad stateid straight through from LOCK, LOCKU, CLOSE and OPEN_DOWNGRADE", () => {
    const { state, peer, open } = openedPeer();
    const unknown: Stateid4 = { seqid: 1, other: new Uint8Array(NFS4_OTHER_SIZE).fill(5) };
    const lock = state.lock({
      clientid: peer.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 0n,
      length: 4n,
      openStateid: open,
      lockOwner: bytes("l1"),
    });

    expect(
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset: 0n,
        length: 1n,
        openStateid: unknown,
        lockOwner: bytes("l1"),
      }).status,
    ).toBe(NFS4ERR_BAD_STATEID);
    expect(
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset: 0n,
        length: 1n,
        lockStateid: unknown,
      }).status,
    ).toBe(NFS4ERR_BAD_STATEID);
    expect(
      state.locku({
        clientid: peer.clientid,
        fileKey: file,
        lockStateid: unknown,
        offset: 0n,
        length: 1n,
      }).status,
    ).toBe(NFS4ERR_BAD_STATEID);
    expect(
      state.locku({
        clientid: peer.clientid,
        fileKey: file,
        lockStateid: lock.stateid!,
        offset: 0n,
        length: 0n,
      }).status,
    ).toBe(NFS4ERR_INVAL);
    // A lock stateid is not an open stateid, for either operation that needs one.
    expect(state.close({ clientid: peer.clientid, stateid: lock.stateid! }).status).toBe(
      NFS4ERR_BAD_STATEID,
    );
    expect(
      state.openDowngrade({
        clientid: peer.clientid,
        stateid: lock.stateid!,
        shareAccess: OPEN4_SHARE_ACCESS_READ,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).status,
    ).toBe(NFS4ERR_BAD_STATEID);
  });

  it("refuses a LOCK before the global RECLAIM_COMPLETE, before it even looks at the stateid", () => {
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register({ reclaimComplete: false });

    expect(
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset: 0n,
        length: 1n,
        openStateid: { seqid: 1, other: new Uint8Array(NFS4_OTHER_SIZE).fill(6) },
        lockOwner: bytes("l1"),
      }).status,
    ).toBe(NFS4ERR_GRACE);
  });

  it("refuses more granted ranges on one file than the cap", () => {
    const { state, peer, open } = openedPeer({ maxLocksPerFile: 1 });
    const lock = (offset: bigint) =>
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset,
        length: 10n,
        openStateid: open,
        lockOwner: bytes("l1"),
      });

    expect(lock(0n).status).toBe(NFS4_OK);
    expect(lock(100n).status).toBe(NFS4ERR_DELAY);
  });

  it("revokes an expired client's byte-range locks when they block a live client", () => {
    const { state, advance } = newState({ leaseSeconds: 60 });
    const a = new Peer(state, "owner-a").register();
    const b = new Peer(state, "owner-b").register();
    const openOf = (peer: Peer): Stateid4 =>
      state.open({
        clientid: peer.clientid,
        owner: bytes("p"),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).stateid!;
    const stale = state.lock({
      clientid: a.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 0n,
      length: 100n,
      openStateid: openOf(a),
      lockOwner: bytes("la"),
    });
    expect(stale.status).toBe(NFS4_OK);
    const openB = openOf(b);

    // B renews inside its lease and A never does, so 80 s on only A is expired.
    advance(40);
    expect(b.sequence({ sequenceid: 1 }).kind).toBe("new");
    advance(40);
    const taken = state.lock({
      clientid: b.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 0n,
      length: 100n,
      openStateid: openB,
      lockOwner: bytes("lb"),
    });

    expect(taken.status).toBe(NFS4_OK);
    expect(state.locksOf(file)).toHaveLength(1);
    expect(state.checkStateid({ clientid: a.clientid, stateid: stale.stateid! }).status).toBe(
      NFS4ERR_EXPIRED,
    );
  });

  it("sweeps a client that is holding locks", () => {
    const { state, peer, open, advance } = openedPeer({ leaseSeconds: 60 });
    expect(
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset: 0n,
        length: 8n,
        openStateid: open,
        lockOwner: bytes("l1"),
      }).status,
    ).toBe(NFS4_OK);

    advance(61);
    expect(state.sweep()).toBe(1);
    expect(state.locksOf(file)).toHaveLength(0);
    expect(state.stateCount).toBe(0);
    expect(state.clientOfSession(peer.sessionid)).toBeUndefined();
  });
});

describe("verification follow-ups (the six findings, pinned)", () => {
  const file = "file-1";

  function openedPeer(options: Nfs4StateOptions = {}): {
    state: Nfs4State;
    peer: Peer;
    open: Stateid4;
  } {
    const { state } = newState(options);
    const peer = new Peer(state, "owner-a").register();
    const open = state.open({
      clientid: peer.clientid,
      owner: bytes("p1"),
      fileKey: file,
      shareAccess: OPEN4_SHARE_ACCESS_BOTH,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    }).stateid!;
    return { state, peer, open };
  }

  it("evicts the cached reply when the slot advances", () => {
    // The eviction on advance is invisible to a well-behaved client, so this
    // drives the one sequence that exposes it: advance the slot without ever
    // caching a reply for the new request, then retry the *old* sequence ID.
    // Without the eviction the slot still holds request 1's bytes and the retry
    // of request 2 replays them — the wrong reply for the wrong request.
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();

    peer.send(() => new Uint8Array([1, 1, 1]), { sequenceid: 1 });
    const second = peer.sequence({ sequenceid: 2 });
    expect(second.kind).toBe("new");

    const retry = peer.sequence({ sequenceid: 2 });
    expect(retry.kind).toBe("replay-uncached");
    expect((retry as { bytes?: Uint8Array }).bytes).toBeUndefined();
  });

  it("returns seqid 1 on a lock-owner's first stateid, and mints nothing when the lock is denied", () => {
    const { state } = newState();
    const a = new Peer(state, "owner-a").register();
    const b = new Peer(state, "owner-b").register();
    const openOf = (peer: Peer): Stateid4 =>
      state.open({
        clientid: peer.clientid,
        owner: bytes("p"),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).stateid!;
    const openA = openOf(a);
    const openB = openOf(b);

    const first = state.lock({
      clientid: a.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 0n,
      length: 10n,
      openStateid: openA,
      lockOwner: bytes("la"),
    });
    expect(first.status).toBe(NFS4_OK);
    expect(first.stateid!.seqid).toBe(1);

    const states = state.stateCount;
    const denied = state.lock({
      clientid: b.clientid,
      fileKey: file,
      locktype: WRITE_LT,
      offset: 0n,
      length: 10n,
      openStateid: openB,
      lockOwner: bytes("lb"),
    });
    expect(denied.status).toBe(NFS4ERR_DENIED);
    // A denied LOCK leaves no stateid behind for a lock-owner that got nothing.
    expect(state.stateCount).toBe(states);
  });

  it("refuses every special stateid where LOCK and LOCKU need a real one", () => {
    const { state, peer, open } = openedPeer();
    const zero = new Uint8Array(NFS4_OTHER_SIZE);
    const ones = new Uint8Array(NFS4_OTHER_SIZE).fill(0xff);
    const specials: Stateid4[] = [
      { seqid: 0, other: zero }, // anonymous
      { seqid: 1, other: zero }, // current
      { seqid: UINT32_MAX, other: ones }, // READ bypass
    ];
    // Sanity: all three are stateids checkStateid itself accepts.
    for (const stateid of specials) {
      expect(state.checkStateid({ clientid: peer.clientid, stateid }).status).toBe(NFS4_OK);
    }

    for (const stateid of specials) {
      // §8.2.4: valid in general, not valid in this context.
      expect(
        state.lock({
          clientid: peer.clientid,
          fileKey: file,
          locktype: WRITE_LT,
          offset: 0n,
          length: 1n,
          openStateid: stateid,
          lockOwner: bytes("l1"),
        }).status,
      ).toBe(NFS4ERR_BAD_STATEID);
      expect(
        state.lock({
          clientid: peer.clientid,
          fileKey: file,
          locktype: WRITE_LT,
          offset: 0n,
          length: 1n,
          lockStateid: stateid,
        }).status,
      ).toBe(NFS4ERR_BAD_STATEID);
      expect(
        state.locku({
          clientid: peer.clientid,
          fileKey: file,
          lockStateid: stateid,
          offset: 0n,
          length: 1n,
        }).status,
      ).toBe(NFS4ERR_BAD_STATEID);
      expect(state.close({ clientid: peer.clientid, stateid }).status).toBe(NFS4ERR_BAD_STATEID);
      expect(
        state.openDowngrade({
          clientid: peer.clientid,
          stateid,
          shareAccess: OPEN4_SHARE_ACCESS_READ,
          shareDeny: OPEN4_SHARE_DENY_NONE,
        }).status,
      ).toBe(NFS4ERR_BAD_STATEID);
    }
    // None of that disturbed the open it was aimed past.
    expect(state.checkStateid({ clientid: peer.clientid, stateid: open }).status).toBe(NFS4_OK);
  });

  it("refuses a share_access carrying a bit the protocol does not define", () => {
    const { state, peer, open } = openedPeer();
    // Bit 2 sits between the access bits and OPEN4_SHARE_ACCESS_WANT_DELEG_MASK
    // and is defined nowhere: the mask-and-accept this replaced dropped it.
    const undefinedBit = OPEN4_SHARE_ACCESS_BOTH | 0x00_00_00_04;

    expect(
      state.open({
        clientid: peer.clientid,
        owner: bytes("p2"),
        fileKey: file,
        shareAccess: undefinedBit,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).status,
    ).toBe(NFS4ERR_INVAL);
    expect(
      state.openDowngrade({
        clientid: peer.clientid,
        stateid: open,
        shareAccess: undefinedBit,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).status,
    ).toBe(NFS4ERR_INVAL);

    // The delegation wishes are not undefined bits: §18.16.3 defines all seven
    // for this field, and only five of them are inside WANT_DELEG_MASK.
    const wanted =
      OPEN4_SHARE_ACCESS_READ |
      OPEN4_SHARE_ACCESS_WANT_NO_DELEG |
      OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL;
    const withWants = state.open({
      clientid: peer.clientid,
      owner: bytes("p3"),
      fileKey: file,
      shareAccess: wanted,
      shareDeny: OPEN4_SHARE_DENY_NONE,
    });
    expect(withWants.status).toBe(NFS4_OK);
    expect(
      state.checkStateid({ clientid: peer.clientid, stateid: withWants.stateid! }).access,
    ).toBe(OPEN4_SHARE_ACCESS_READ);
    // A bit above every WANT flag is undefined too.
    expect(
      state.open({
        clientid: peer.clientid,
        owner: bytes("p4"),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_READ | 0x00_04_00_00,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).status,
    ).toBe(NFS4ERR_INVAL);
  });

  it("answers NFS4ERR_TOOSMALL for a ca_maxresponsesize nothing fits in, and never raises a size", () => {
    const { state } = newState({ maxRequestSize: 1024 * 1024 });
    const exchanged = state.exchangeId({
      ownerid: bytes("owner-a"),
      verifier: bytes("v1"),
      flags: 0,
    });
    const create = (attrs: ChannelAttrs4, sequence: number) =>
      state.createSession({
        clientid: exchanged.clientid,
        sequence,
        flags: 0,
        foreChanAttrs: attrs,
        backChanAttrs: offeredAttrs(),
      });

    // §18.36.3: a response size a reply could never fit in.
    expect(create(offeredAttrs({ maxresponsesize: 0 }), 1).status).toBe(NFS4ERR_TOOSMALL);
    expect(state.sessionCount).toBe(0);
    // The slot advanced with phase 2, so the failure is what a retry replays.
    const replayed = create(offeredAttrs({ maxresponsesize: 0 }), 1);
    expect(replayed.status).toBe(NFS4ERR_TOOSMALL);
    expect(replayed.replay).toBe(true);
    expect(create(offeredAttrs({ maxresponsesize: 64 }), 2).status).toBe(NFS4ERR_TOOSMALL);

    // A workable but tiny offer is accepted verbatim: sizes are only ever
    // lowered, and the two counts are the only values a zero offer raises.
    const created = create(
      offeredAttrs({
        maxresponsesize: 200,
        maxrequestsize: 300,
        maxresponsesizeCached: 0,
        maxrequests: 0,
        maxoperations: 0,
      }),
      3,
    );
    expect(created.status).toBe(NFS4_OK);
    expect(created.foreChanAttrs?.maxresponsesize).toBe(200);
    expect(created.foreChanAttrs?.maxrequestsize).toBe(300);
    expect(created.foreChanAttrs?.maxresponsesizeCached).toBe(0);
    expect(created.foreChanAttrs?.maxrequests).toBe(1);
    expect(created.foreChanAttrs?.maxoperations).toBe(1);
  });

  it("hands the back channel's offer back untouched, sizes and counts alike", () => {
    // The back channel gets no floor and no `NFS4ERR_TOOSMALL`: the replier on
    // it is the *client*, so "could never send a response" is not this server's
    // judgement to make, and §18.36.3's "MAY decrease this value but MUST NOT
    // increase it" is all that applies. Sizes below the fore channel's own
    // minimum are therefore legal here and must come back verbatim.
    const { state } = newState({
      maxRequestSize: 1024 * 1024,
      maxCachedResponseSize: 64 * 1024,
      maxForeSlots: 8,
      maxOperations: 16,
    });
    const exchanged = state.exchangeId({
      ownerid: bytes("owner-a"),
      verifier: bytes("v1"),
      flags: 0,
    });

    const created = state.createSession({
      clientid: exchanged.clientid,
      sequence: exchanged.sequenceid,
      flags: 0,
      foreChanAttrs: offeredAttrs(),
      backChanAttrs: offeredAttrs({
        maxresponsesize: 100,
        maxrequestsize: 100,
        maxresponsesizeCached: 0,
        maxrequests: 2,
        maxoperations: 3,
      }),
    });

    expect(created.status).toBe(NFS4_OK);
    expect(created.backChanAttrs?.maxresponsesize).toBe(100);
    expect(created.backChanAttrs?.maxrequestsize).toBe(100);
    expect(created.backChanAttrs?.maxresponsesizeCached).toBe(0);
    // "For the backchannel, the server MUST NOT change the value the client
    // offers" — the counts pass through even where the fore channel's caps are
    // lower than what was offered.
    expect(created.backChanAttrs?.maxrequests).toBe(2);
    expect(created.backChanAttrs?.maxoperations).toBe(3);
    // The fore channel was capped in the same call, so this is the difference
    // between the two channels and not a server that trims nothing.
    expect(created.foreChanAttrs?.maxrequests).toBe(8);
    expect(created.foreChanAttrs?.maxoperations).toBe(16);
  });

  it("caches a CREATE_SESSION cap failure on the advanced slot, and lets the next sequence succeed", () => {
    const { state } = newState({ maxSessions: 1 });
    const peer = new Peer(state, "owner-a").register();
    const create = (sequence: number) =>
      state.createSession({
        clientid: peer.clientid,
        sequence,
        flags: 0,
        foreChanAttrs: offeredAttrs(),
        backChanAttrs: offeredAttrs(),
      });

    expect(create(2).status).toBe(NFS4ERR_NOSPC);
    // Phase 2 advances the slot before phase 4 can refuse, so the retry is a
    // replay of that refusal rather than a second attempt.
    const retry = create(2);
    expect(retry.status).toBe(NFS4ERR_NOSPC);
    expect(retry.replay).toBe(true);

    expect(state.destroySession(peer.sessionid).status).toBe(NFS4_OK);
    // A new sequence ID is a new request, and now there is room.
    expect(create(3).status).toBe(NFS4_OK);
  });

  it("keeps two open-owners sharing one lock-owner name apart at CLOSE", () => {
    // One client, one file, two open-owners, and the same lock-owner name under
    // both — the aliasing §9.5 allows and CLOSE has to see through.
    const { state } = newState();
    const peer = new Peer(state, "owner-a").register();
    const openOf = (owner: string): Stateid4 =>
      state.open({
        clientid: peer.clientid,
        owner: bytes(owner),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_BOTH,
        shareDeny: OPEN4_SHARE_DENY_NONE,
      }).stateid!;
    const openOne = openOf("p1");
    const openTwo = openOf("p2");
    const lockOn = (open: Stateid4, offset: bigint) =>
      state.lock({
        clientid: peer.clientid,
        fileKey: file,
        locktype: WRITE_LT,
        offset,
        length: 10n,
        openStateid: open,
        lockOwner: bytes("shared-lock-owner"),
      });

    const one = lockOn(openOne, 0n);
    const two = lockOn(openTwo, 100n);
    expect(one.status).toBe(NFS4_OK);
    expect(two.status).toBe(NFS4_OK);
    // Two lock stateids, one per open (§9.1.1), and two granted ranges.
    expect([...one.stateid!.other]).not.toEqual([...two.stateid!.other]);
    expect(state.locksOf(file)).toHaveLength(2);

    expect(state.close({ clientid: peer.clientid, stateid: openOne }).status).toBe(
      NFS4ERR_LOCKS_HELD,
    );
    expect(
      state.locku({
        clientid: peer.clientid,
        fileKey: file,
        lockStateid: one.stateid!,
        offset: 0n,
        length: 10n,
      }).status,
    ).toBe(NFS4_OK);

    // The first open now holds nothing, even though the same lock-owner name
    // still holds a range through the second open.
    expect(state.close({ clientid: peer.clientid, stateid: openOne }).status).toBe(NFS4_OK);
    expect(state.locksOf(file)).toHaveLength(1);
    expect(state.close({ clientid: peer.clientid, stateid: openTwo }).status).toBe(
      NFS4ERR_LOCKS_HELD,
    );
  });

  it("revokes an expired holder before answering shareDenies, as open and lock do", () => {
    const { state, advance } = newState({ leaseSeconds: 60 });
    const stale = new Peer(state, "owner-a").register();
    const live = new Peer(state, "owner-b").register();
    expect(
      state.open({
        clientid: stale.clientid,
        owner: bytes("p1"),
        fileKey: file,
        shareAccess: OPEN4_SHARE_ACCESS_WRITE,
        shareDeny: OPEN4_SHARE_DENY_READ,
      }).status,
    ).toBe(NFS4_OK);
    expect(state.shareDenies(file, OPEN4_SHARE_ACCESS_READ, live.clientid)).toBe(NFS4ERR_LOCKED);

    advance(61);
    expect(state.shareDenies(file, OPEN4_SHARE_ACCESS_READ, live.clientid)).toBe(NFS4_OK);
    // The holder's own reservation is not revoked on its own behalf.
    expect(state.shareDenies(file, OPEN4_SHARE_ACCESS_READ, stale.clientid)).toBe(NFS4_OK);
  });
});
