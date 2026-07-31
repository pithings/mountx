/**
 * The version router: one RPC record in, one RPC record out.
 *
 * `NfsSession` is the public entry point of this transport and, since the
 * server grew a second NFS version, the only thing in front of the versioned
 * sessions in `v3/` (and, later, `v4/`). It is deliberately thin: it decides
 * *which* version a record belongs to and hands the **same raw bytes** on. The
 * versioned session then does its own full RPC decode, so the header is decoded
 * twice on purpose — the alternative is a shared pre-decoded call object
 * threaded through both, which is a far larger change to a codec that works.
 *
 * **The peek.** Records reaching {@link NfsSession.handleCall} are already
 * de-framed (`RecordAssembler` in `rpc.ts`), so the fixed head of an RPC call
 * (RFC 5531 §9) sits at known offsets with no variable-length field before it:
 * `xid` at 0, `mtype` at 4, `rpcvers` at 8, **`prog` at 12, `vers` at 16**.
 * Reading those two words is all the routing needs, and a record too short to
 * hold them is not judged here at all — it goes to the v3 session, which
 * already answers a damaged record the way it always has.
 *
 * **The refusals.** Two answers belong to the router rather than to any
 * version: a program nobody serves (`PROG_UNAVAIL`) and an NFS version nobody
 * serves (`PROG_MISMATCH`, carrying the range this server speaks). Both are
 * RPC-level, and both come *after* the checks that outrank them — a record that
 * is not a decodable call is dropped, a caller speaking a different RPC version
 * is told so, and a credential flavor we will not take is refused — which is
 * why this path decodes the call it is about to refuse instead of answering
 * from the peek alone. That ordering is RFC 5531 §9's and is what the v3
 * dispatcher already did for these same records.
 *
 * **What the router owns.** One {@link FileHandleTable}, one `PathLock` and one
 * counters object, constructed here and handed to both versioned sessions
 * (`../util.ts`'s `NfsSharedState`). That is what makes a handle mean the same
 * file whichever version a client obtained it through, a `RENAME` exclude
 * readers on both, and `stats` add up across the pair. Each versioned session
 * still builds its own when constructed alone, which is what its unit tests do.
 *
 * **Two versions, advertised.** A record naming NFS version 4 reaches
 * {@link Nfs4Session}, and the `PROG_MISMATCH` range this file answers with is
 * `{low: 3, high: 4}` — so a client that negotiates downwards from a version it
 * cannot get is told this server speaks both. The range, the mount options
 * (`src/nfs/mount.ts`) and the client probe (`src/nfs/probe.ts`) moved together
 * on purpose: advertising a version the mount command cannot be told to ask for
 * would be an offer nothing can take up.
 *
 * The *minor* version is not this file's business. `vers=4.1` and `vers=4.0`
 * are the same `vers` field on the wire — 4 — and the minor version travels
 * inside COMPOUND, where {@link Nfs4Session} refuses everything but 1 with
 * `NFS4ERR_MINOR_VERS_MISMATCH` (RFC 8881 §16.2.3). A 4.0 client is therefore
 * routed here and refused there, which is the clean answer rather than a
 * `PROG_MISMATCH` that would claim v4 is unavailable altogether.
 */

import type { Loopback } from "../harness.ts";
import { PathLock } from "../lock.ts";
import type { FsDriver } from "../types.ts";
import { FileHandleTable } from "./handles.ts";
import {
  AUTH_NONE,
  AUTH_SYS,
  AUTH_TOOWEAK,
  decodeCall,
  encodeAcceptError,
  encodeAuthError,
  encodeRpcMismatch,
  RPC_PROG_MISMATCH,
  RPC_PROG_UNAVAIL,
  RPC_VERSION,
  type RpcCall,
} from "./rpc.ts";
import {
  newSessionStats,
  type NfsRequestContext,
  type NfsSessionOptions,
  type NfsSessionStats,
  type NfsSharedState,
} from "./util.ts";
import { MOUNT_PROGRAM, NFS_PROGRAM, NFS_V3 } from "./v3/constants.ts";
import { Nfs3Session } from "./v3/session.ts";
import { NFS_V4 } from "./v4/constants.ts";
import { Nfs4Session } from "./v4/session.ts";

export { DEFAULT_DTPREF, DEFAULT_RTMAX, DEFAULT_WTMAX } from "./v3/session.ts";
export { MAX_OFFSET } from "./util.ts";
export type {
  Nfs4IdMap,
  Nfs4StateKnobs,
  NfsRequestContext,
  NfsSessionOptions,
  NfsSessionStats,
  NfsSharedState,
} from "./util.ts";

/** Offset of `prog` in a `call_body` (RFC 5531 §9), counting the `xid`. */
const PROGRAM_OFFSET = 12;
/** Offset of `vers`, the word after it. */
const VERSION_OFFSET = 16;
/** Shortest record the peek can read: everything through `vers`. */
const PEEK_BYTES = VERSION_OFFSET + 4;

/** The lowest and highest NFS version this server answers, for `PROG_MISMATCH`. */
const NFS_VERSION_LOW = NFS_V3;
const NFS_VERSION_HIGH = NFS_V4;

/** `(prog, vers)` read at their fixed offsets, or `undefined` for a short record. */
function peekProgram(message: Uint8Array): { program: number; version: number } | undefined {
  if (message.byteLength < PEEK_BYTES) {
    return undefined;
  }
  const view = new DataView(message.buffer, message.byteOffset, message.byteLength);
  return {
    program: view.getUint32(PROGRAM_OFFSET, false),
    version: view.getUint32(VERSION_OFFSET, false),
  };
}

/**
 * Whether the v3 session owns this record.
 *
 * MOUNT is a v3-only protocol, so every MOUNT record is v3's — including one
 * naming a MOUNT version that does not exist, which v3's own dispatcher already
 * refuses with the range it speaks.
 */
function servedByV3(program: number, version: number): boolean {
  return program === MOUNT_PROGRAM || (program === NFS_PROGRAM && version === NFS_V3);
}

/** Whether the v4 session owns this record. NFS only; there is no MOUNT in v4. */
function servedByV4(program: number, version: number): boolean {
  return program === NFS_PROGRAM && version === NFS_V4;
}

/**
 * An NFS server over a driver, with no socket.
 *
 * ```ts
 * const session = new NfsSession(createMemoryDriver());
 * const reply = await session.handleCall(rpcRecordBytes); // Uint8Array | null
 * ```
 *
 * The state a versioned session needs — the file handle table, the path lock,
 * the counters — is reached through here, so the accessors below are the one
 * public view of it whichever version answered.
 */
export class NfsSession {
  readonly options: NfsSessionOptions;
  /** Counters, shared with the versioned sessions that increment them. */
  readonly stats: NfsSessionStats;

  readonly #v3: Nfs3Session;
  readonly #v4: Nfs4Session;
  readonly #shared: Required<NfsSharedState>;

  constructor(driver: FsDriver, options: NfsSessionOptions = {}) {
    // Built here, once, and shared with both — see the module docs.
    this.#shared = {
      handles: new FileHandleTable({
        useDriverIno: options.useDriverIno,
        verifier: options.verifier,
        maxHandles: options.maxHandles,
      }),
      lock: new PathLock(),
      stats: newSessionStats(),
    };
    this.#v3 = new Nfs3Session(driver, options, this.#shared);
    this.#v4 = new Nfs4Session(driver, options, this.#shared);
    this.options = options;
    this.stats = this.#shared.stats;
  }

  /** The NFSv4.1 session, for the tests that drive it directly. */
  get v4(): Nfs4Session {
    return this.#v4;
  }

  /** The driver, wrapped so paths are normalized and gaps answer `ENOSYS`. */
  get driver(): Loopback {
    return this.#v3.driver;
  }

  /** The file handle table, shared by every version this server speaks. */
  get handles(): FileHandleTable {
    return this.#shared.handles;
  }

  /** The `writeverf3` every v3 `WRITE` and `COMMIT` reply carries. */
  get writeVerifier(): Uint8Array {
    return this.#v3.writeVerifier;
  }

  /** MOUNT registrations currently outstanding, in order. */
  get mounts(): Nfs3Session["mounts"] {
    return this.#v3.mounts;
  }

  get destroyed(): boolean {
    return this.#v3.destroyed;
  }

  /** The v3 session, for the tests and the CLI that reach past the router. */
  get v3(): Nfs3Session {
    return this.#v3;
  }

  /**
   * Answer one RPC record.
   *
   * Resolves to the encoded reply, or `null` for a record too damaged to carry
   * an xid — there is nothing to address a reply to. **Never rejects.**
   *
   * A direct caller must not overwrite `message` while the promise is
   * outstanding; everything a session *keeps* — names, `WRITE` payloads, file
   * handles — is copied out of it by the decoders. The transport never has to
   * think about it: `./rpc.ts`'s `RecordAssembler` hands over a record copied
   * out of the socket's buffers rather than a view of them.
   *
   * The **reply** travels the other way: this forwards whichever versioned
   * session answered, and both hand back a view of the one `XdrWriter` they
   * built for that call. Write it to the wire before yielding — the writer is
   * dropped at `return` so nothing will overwrite it, but nothing copies it for
   * you either. See `XdrWriter.view()` for the rule.
   */
  async handleCall(
    message: Uint8Array,
    context: NfsRequestContext = {},
  ): Promise<Uint8Array | null> {
    const peeked = peekProgram(message);
    if (peeked === undefined || servedByV3(peeked.program, peeked.version)) {
      return this.#v3.handleCall(message, context);
    }
    if (servedByV4(peeked.program, peeked.version)) {
      return this.#v4.handleCall(message, context);
    }
    return this.#refuse(message);
  }

  /** Drop every handle and cached listing, in both versions. Idempotent. */
  async destroy(): Promise<void> {
    await Promise.all([this.#v3.destroy(), this.#v4.destroy()]);
  }

  /**
   * The RPC-level refusal for a record no version serves.
   *
   * Counted exactly like a record a version answered, because from the outside
   * it is one: one request, one reply, or a drop when it could not be decoded
   * far enough to address a reply.
   */
  #refuse(message: Uint8Array): Uint8Array | null {
    this.stats.requests++;
    let call: RpcCall;
    try {
      ({ call } = decodeCall(message));
    } catch {
      this.stats.dropped++;
      return null;
    }
    this.stats.replies++;
    if (call.rpcVersion !== RPC_VERSION) {
      return encodeRpcMismatch(call.xid);
    }
    // Parsed, never verified — see the note at the top of `rpc.ts`.
    if (call.cred.flavor !== AUTH_NONE && call.cred.flavor !== AUTH_SYS) {
      return encodeAuthError(call.xid, AUTH_TOOWEAK);
    }
    if (call.program !== NFS_PROGRAM) {
      return encodeAcceptError(call.xid, RPC_PROG_UNAVAIL);
    }
    return encodeAcceptError(call.xid, RPC_PROG_MISMATCH, {
      low: NFS_VERSION_LOW,
      high: NFS_VERSION_HIGH,
    });
  }
}

/** Create a session over a driver. */
export function createNfsSession(driver: FsDriver, options?: NfsSessionOptions): NfsSession {
  return new NfsSession(driver, options);
}
