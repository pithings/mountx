/**
 * Tier 0 for the version router in `src/nfs/session.ts`.
 *
 * The router is four lines of decision and one refusal, and all of it is about
 * *which* session gets the bytes — so every assertion here is about where a
 * record went, never about what the session did with it once it arrived. That
 * is what `v3/session.test.ts` and `v4/session.test.ts` are for.
 *
 * Two habits make the routing observable without reaching into the object:
 *
 * - **Procedure 1 means different things in the two versions.** It is v3's
 *   GETATTR and v4's COMPOUND, so one record body — a COMPOUND with no
 *   operations — answers `NFS4_OK` at `vers = 4` and `GARBAGE_ARGS` at
 *   `vers = 3`. Nothing but the routing differs between those two calls.
 * - **No socket.** The router is bytes in, bytes out, so the session is driven
 *   directly; `server.ts` adds nothing this file is about.
 *
 * What the router *owns* rather than routes — the one handle table, the one
 * counters object shared by both versions — is asserted in
 * `test/nfs/v4/session.test.ts`, where there is a v4 client to obtain a handle
 * with. This file is the switch itself.
 */

import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import {
  decodeReply,
  encodeCall,
  MSG_ACCEPTED,
  RPC_GARBAGE_ARGS,
  RPC_PROG_MISMATCH,
  RPC_PROG_UNAVAIL,
  RPC_SUCCESS,
} from "../../src/nfs/rpc.ts";
import { NfsSession } from "../../src/nfs/session.ts";
import { MOUNT_PROGRAM, MOUNT_V3, NFS_PROGRAM, NFS_V3 } from "../../src/nfs/v3/constants.ts";
import {
  NFS4_OK,
  NFS4ERR_MINOR_VERS_MISMATCH,
  NFS_V4,
  NFSPROC4_COMPOUND,
} from "../../src/nfs/v4/constants.ts";
import { XdrWriter } from "../../src/nfs/xdr.ts";

/** The one procedure number both versions define, and the two disagree on. */
const PROCEDURE_ONE = NFSPROC4_COMPOUND;

/** `COMPOUND4args` with the given minor version and no operations at all. */
function emptyCompound(minorversion = 1): Uint8Array {
  return new XdrWriter(32).string("route").u32(minorversion).u32(0).bytes();
}

/** Put a hand-built call through the router and decode the reply. */
async function answer(
  session: NfsSession,
  call: Parameters<typeof encodeCall>[0],
): Promise<ReturnType<typeof decodeReply>> {
  const reply = await session.handleCall(encodeCall(call));
  expect(reply).not.toBeNull();
  return decodeReply(reply!);
}

function session(): NfsSession {
  return new NfsSession(createMemoryDriver());
}

describe("the version router: which session gets the record", () => {
  it("hands version 3 to the v3 session", async () => {
    const routed = session();
    const { reply } = await answer(routed, {
      xid: 1,
      program: NFS_PROGRAM,
      version: NFS_V3,
      procedure: PROCEDURE_ONE,
      args: emptyCompound(),
    });
    expect(reply.replyStat).toBe(MSG_ACCEPTED);
    // v3's procedure 1 is GETATTR, and a COMPOUND is not an `nfs_fh3`. The
    // counter is what names where the record went — the v3 dispatcher counts
    // by procedure before it decodes the arguments it then rejects — and the
    // very same bytes are answered as a COMPOUND below.
    expect(routed.stats.procedures.get("NFS:GETATTR")).toBe(1);
    expect(reply.acceptStat).toBe(RPC_GARBAGE_ARGS);
  });

  it("hands version 4 to the v4 session", async () => {
    const { reply, results } = await answer(session(), {
      xid: 2,
      program: NFS_PROGRAM,
      version: NFS_V4,
      procedure: PROCEDURE_ONE,
      args: emptyCompound(),
    });
    expect(reply.acceptStat).toBe(RPC_SUCCESS);
    // A `COMPOUND4res`: status, the tag echoed back, an empty result array.
    expect(results.u32("status")).toBe(NFS4_OK);
    expect(results.string(64, "tag")).toBe("route");
    expect(results.u32("resarray count")).toBe(0);
  });

  it("leaves the minor version to the v4 session, which is where it lives", async () => {
    // `vers=4.0` and `vers=4.1` are the same 4 on the wire, so a 4.0 client is
    // routed here and refused *inside* the COMPOUND (RFC 8881 §16.2.3) rather
    // than being told version 4 is unavailable.
    const { reply, results } = await answer(session(), {
      xid: 3,
      program: NFS_PROGRAM,
      version: NFS_V4,
      procedure: PROCEDURE_ONE,
      args: emptyCompound(0),
    });
    expect(reply.acceptStat).toBe(RPC_SUCCESS);
    expect(results.u32("status")).toBe(NFS4ERR_MINOR_VERS_MISMATCH);
  });

  it("refuses every other NFS version with the range it now speaks", async () => {
    for (const version of [2, 5, 0, 0xffff_ffff]) {
      const { reply } = await answer(session(), {
        xid: 10 + version,
        program: NFS_PROGRAM,
        version,
        procedure: 0,
      });
      expect(reply.replyStat).toBe(MSG_ACCEPTED);
      expect(reply.acceptStat).toBe(RPC_PROG_MISMATCH);
      // The whole point of the version switch: both versions are advertised,
      // so a client that negotiates downwards is told v4 is available.
      expect([reply.low, reply.high]).toEqual([NFS_V3, NFS_V4]);
    }
  });

  it("keeps MOUNT v3-only, with its own unchanged range", async () => {
    const mounted = session();
    // MOUNT is a v3 protocol and has no version 4, so the router hands every
    // MOUNT record to v3 — including one naming a version that does not exist,
    // which v3's own dispatcher refuses with MOUNT's range rather than NFS's.
    const wrong = await answer(mounted, {
      xid: 20,
      program: MOUNT_PROGRAM,
      version: 1,
      procedure: 0,
    });
    expect(wrong.reply.acceptStat).toBe(RPC_PROG_MISMATCH);
    expect([wrong.reply.low, wrong.reply.high]).toEqual([MOUNT_V3, MOUNT_V3]);
    // And MOUNT's own NULL still answers, which is what says the record was
    // routed rather than refused.
    const ok = await answer(mounted, {
      xid: 21,
      program: MOUNT_PROGRAM,
      version: MOUNT_V3,
      procedure: 0,
    });
    expect(ok.reply.acceptStat).toBe(RPC_SUCCESS);
  });

  it("refuses a program no version serves", async () => {
    const { reply } = await answer(session(), {
      xid: 30,
      program: 999_999,
      version: 4,
      procedure: 0,
    });
    expect(reply.acceptStat).toBe(RPC_PROG_UNAVAIL);
  });

  it("counts a refusal as the one request and one reply it is", async () => {
    const routed = session();
    await answer(routed, { xid: 40, program: NFS_PROGRAM, version: 2, procedure: 0 });
    expect(routed.stats.requests).toBe(1);
    expect(routed.stats.replies).toBe(1);
    expect(routed.stats.dropped).toBe(0);
  });

  it("does not judge a record too short to peek at", async () => {
    const routed = session();
    // Shorter than `vers` at offset 16, so there is nothing to route on. It
    // goes to v3, which drops it for want of an xid to answer.
    expect(await routed.handleCall(new Uint8Array(12))).toBeNull();
    expect(routed.stats.dropped).toBe(1);
  });

  it("reads the version at its fixed offset, whatever follows it", async () => {
    // The peek is only sound because `prog` and `vers` sit at fixed offsets in
    // a `call_body` — nothing variable-length precedes them, credentials
    // included. A long credential shifts everything *after* the peek only.
    const bytes = encodeCall({
      xid: 50,
      program: NFS_PROGRAM,
      version: NFS_V4,
      procedure: PROCEDURE_ONE,
      cred: { flavor: 1, body: new Uint8Array(200) },
      args: emptyCompound(),
    });
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    expect(view.getUint32(12, false)).toBe(NFS_PROGRAM);
    expect(view.getUint32(16, false)).toBe(NFS_V4);
    const reply = await session().handleCall(bytes);
    const { results } = decodeReply(reply!);
    expect(results.u32("status")).toBe(NFS4_OK);
  });
});
