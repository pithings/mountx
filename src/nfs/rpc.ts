/**
 * ONC RPC v2 (RFC 5531) message framing, both directions.
 *
 * Everything here is encoded *and* decoded, for the same reason the FUSE codecs
 * are: the Tier-1 test client is built from these exact functions, so a full
 * conformance run needs no kernel, no mount and no root (IDEA.md, "Tier 1").
 *
 * **Authentication, stated plainly.** This server *parses* `AUTH_NONE` and
 * `AUTH_SYS` credentials and refuses anything else, and that is all it does
 * with them. It does not verify them, and it cannot: `AUTH_SYS` is a uid and a
 * gid asserted by the client with nothing to back the assertion, which is why
 * it has never been a security mechanism. The security boundary for this
 * transport is **the socket** — the server binds `127.0.0.1` and rejects
 * non-loopback peers by default (see `server.ts`) — plus whatever the mount
 * itself enforces once the kernel has the filesystem. Exporting this to a
 * network means adopting NFSv3's threat model, which is "trust the network".
 */

import { XdrError, XdrReader, XdrWriter } from "./xdr.ts";

// ---------------------------------------------------------------------------
// ONC RPC v2 constants (RFC 5531 §9)
// ---------------------------------------------------------------------------
//
// These live here rather than beside a version's own constants because they
// belong to *no* NFS version: the same `msg_type`, `accept_stat` and auth
// flavors frame an NFSv3 call, an NFSv4.1 COMPOUND and a MOUNT call alike.
// `v3/constants.ts` re-exports every name below, so the public `mountx/nfs`
// surface is unchanged by their having moved.

/** The only RPC version that exists. */
export const RPC_VERSION = 2;

/** `enum msg_type`. */
export const RPC_CALL = 0;
export const RPC_REPLY = 1;

/** `enum reply_stat`. */
export const MSG_ACCEPTED = 0;
export const MSG_DENIED = 1;

/** `enum accept_stat`. */
export const RPC_SUCCESS = 0;
export const RPC_PROG_UNAVAIL = 1;
export const RPC_PROG_MISMATCH = 2;
export const RPC_PROC_UNAVAIL = 3;
export const RPC_GARBAGE_ARGS = 4;
export const RPC_SYSTEM_ERR = 5;

/** `enum reject_stat`. */
export const RPC_MISMATCH = 0;
export const RPC_AUTH_ERROR = 1;

/** `enum auth_stat`. */
export const AUTH_OK = 0;
export const AUTH_BADCRED = 1;
export const AUTH_REJECTEDCRED = 2;
export const AUTH_BADVERF = 3;
export const AUTH_REJECTEDVERF = 4;
export const AUTH_TOOWEAK = 5;
export const AUTH_INVALIDRESP = 6;
export const AUTH_FAILED = 7;

/** `enum auth_flavor`. `AUTH_SYS` is `AUTH_UNIX`'s modern name. */
export const AUTH_NONE = 0;
export const AUTH_SYS = 1;
export const AUTH_SHORT = 2;

/** Longest `opaque_auth` body (RFC 5531: `opaque body<400>`). */
export const RPC_MAX_AUTH_BYTES = 400;

/** Record-marking fragment header: high bit is "last fragment". */
export const RM_LAST_FRAGMENT = 0x80_00_00_00;
/** Low 31 bits of a record-marking header are the fragment length. */
export const RM_LENGTH_MASK = 0x7f_ff_ff_ff;

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

/** `struct opaque_auth { auth_flavor flavor; opaque body<400>; }`. */
export interface OpaqueAuth {
  flavor: number;
  body: Uint8Array;
}

/** The `AUTH_NONE` credential, and the verifier on every reply we send. */
export const AUTH_NULL: OpaqueAuth = { flavor: AUTH_NONE, body: new Uint8Array(0) };

/** `struct authsys_parms` (RFC 5531 Appendix A), the body of an `AUTH_SYS` credential. */
export interface AuthSysParams {
  stamp: number;
  machineName: string;
  uid: number;
  gid: number;
  /** Supplementary groups, `gids<16>`. */
  gids: number[];
}

export function encodeAuthSys(params: AuthSysParams): Uint8Array {
  const writer = new XdrWriter(64);
  writer.u32(params.stamp);
  writer.string(params.machineName);
  writer.u32(params.uid);
  writer.u32(params.gid);
  writer.array(params.gids.slice(0, 16), (w, gid) => w.u32(gid));
  return writer.bytes();
}

export function decodeAuthSys(body: Uint8Array): AuthSysParams {
  const reader = new XdrReader(body);
  return {
    stamp: reader.u32("authsys stamp"),
    machineName: reader.string(255, "authsys machinename"),
    uid: reader.u32("authsys uid"),
    gid: reader.u32("authsys gid"),
    gids: reader.array((r) => r.u32("gid"), 16, "authsys gids"),
  };
}

/** An `AUTH_SYS` credential for this process. */
export function authSys(
  uid = process.getuid?.() ?? 0,
  gid = process.getgid?.() ?? 0,
  machineName = "mountx",
): OpaqueAuth {
  return {
    flavor: AUTH_SYS,
    body: encodeAuthSys({ stamp: 0, machineName, uid, gid, gids: [] }),
  };
}

/**
 * The credentials a request arrived with, as far as they can be believed.
 *
 * `undefined` uid/gid means `AUTH_NONE`: the client did not claim to be anyone.
 */
export interface RpcCredentials {
  flavor: number;
  uid: number | undefined;
  gid: number | undefined;
  gids: readonly number[];
}

/** Read `cred` for whatever it is worth. Unknown flavors never get this far. */
export function credentialsOf(cred: OpaqueAuth): RpcCredentials {
  if (cred.flavor !== AUTH_SYS) {
    return { flavor: cred.flavor, uid: undefined, gid: undefined, gids: [] };
  }
  try {
    const parsed = decodeAuthSys(cred.body);
    return { flavor: cred.flavor, uid: parsed.uid, gid: parsed.gid, gids: parsed.gids };
    /* v8 ignore next 4 -- a malformed AUTH_SYS body is not worth an RPC
       rejection: the credential is advisory here (see the module docs). */
  } catch {
    return { flavor: cred.flavor, uid: undefined, gid: undefined, gids: [] };
  }
}

function readAuth(reader: XdrReader, what: string): OpaqueAuth {
  return {
    flavor: reader.u32(`${what} flavor`),
    body: reader.varOpaque(RPC_MAX_AUTH_BYTES, `${what} body`),
  };
}

function writeAuth(writer: XdrWriter, auth: OpaqueAuth): void {
  writer.u32(auth.flavor);
  writer.varOpaque(auth.body);
}

// ---------------------------------------------------------------------------
// calls
// ---------------------------------------------------------------------------

/** A decoded `call_body` plus its `xid`. The arguments stay in the reader. */
export interface RpcCall {
  xid: number;
  rpcVersion: number;
  program: number;
  version: number;
  procedure: number;
  cred: OpaqueAuth;
  verf: OpaqueAuth;
}

/**
 * Decode one RPC call, leaving the reader positioned at its arguments.
 *
 * Throws {@link XdrError} for anything malformed — including a message that is
 * a reply rather than a call, since a server that answered one would be
 * answering itself.
 */
export function decodeCall(bytes: Uint8Array): { call: RpcCall; args: XdrReader } {
  const reader = new XdrReader(bytes);
  const xid = reader.u32("xid");
  const type = reader.u32("mtype");
  if (type !== RPC_CALL) {
    throw new XdrError(`expected an RPC call, got mtype ${type}`, { offset: 4 });
  }
  const call: RpcCall = {
    xid,
    rpcVersion: reader.u32("rpcvers"),
    program: reader.u32("prog"),
    version: reader.u32("vers"),
    procedure: reader.u32("proc"),
    cred: readAuth(reader, "cred"),
    verf: readAuth(reader, "verf"),
  };
  return { call, args: reader };
}

export interface RpcCallOptions {
  xid: number;
  program: number;
  version: number;
  procedure: number;
  cred?: OpaqueAuth;
  verf?: OpaqueAuth;
  /** Encoded arguments, appended verbatim. */
  args?: Uint8Array;
}

/** Encode one RPC call. */
export function encodeCall(options: RpcCallOptions): Uint8Array {
  const writer = new XdrWriter(128 + (options.args?.byteLength ?? 0));
  writer.u32(options.xid);
  writer.u32(RPC_CALL);
  writer.u32(RPC_VERSION);
  writer.u32(options.program);
  writer.u32(options.version);
  writer.u32(options.procedure);
  writeAuth(writer, options.cred ?? AUTH_NULL);
  writeAuth(writer, options.verf ?? AUTH_NULL);
  if (options.args !== undefined) {
    writer.raw(options.args);
  }
  return writer.bytes();
}

// ---------------------------------------------------------------------------
// replies
// ---------------------------------------------------------------------------

/** A decoded reply. Exactly one of the three shapes is populated. */
export interface RpcReply {
  xid: number;
  /** `MSG_ACCEPTED` or `MSG_DENIED`. */
  replyStat: number;
  /** `accept_stat`, when accepted. */
  acceptStat: number | undefined;
  /** `reject_stat`, when denied. */
  rejectStat: number | undefined;
  /** `auth_stat`, when denied with `AUTH_ERROR`. */
  authStat: number | undefined;
  /** Version range, from `PROG_MISMATCH` or `RPC_MISMATCH`. */
  low: number | undefined;
  high: number | undefined;
  verf: OpaqueAuth | undefined;
}

/** Decode a reply, leaving the reader on its results (if it has any). */
export function decodeReply(bytes: Uint8Array): { reply: RpcReply; results: XdrReader } {
  const reader = new XdrReader(bytes);
  const xid = reader.u32("xid");
  const type = reader.u32("mtype");
  if (type !== RPC_REPLY) {
    throw new XdrError(`expected an RPC reply, got mtype ${type}`, { offset: 4 });
  }
  const reply: RpcReply = {
    xid,
    replyStat: reader.u32("reply_stat"),
    acceptStat: undefined,
    rejectStat: undefined,
    authStat: undefined,
    low: undefined,
    high: undefined,
    verf: undefined,
  };
  if (reply.replyStat === MSG_ACCEPTED) {
    reply.verf = readAuth(reader, "reply verf");
    reply.acceptStat = reader.u32("accept_stat");
    // `PROG_MISMATCH` is the one accepted status that carries a body of its own.
    if (reply.acceptStat === 2) {
      reply.low = reader.u32("mismatch low");
      reply.high = reader.u32("mismatch high");
    }
  } else if (reply.replyStat === MSG_DENIED) {
    reply.rejectStat = reader.u32("reject_stat");
    if (reply.rejectStat === RPC_MISMATCH) {
      reply.low = reader.u32("mismatch low");
      reply.high = reader.u32("mismatch high");
    } else if (reply.rejectStat === RPC_AUTH_ERROR) {
      reply.authStat = reader.u32("auth_stat");
    } else {
      throw new XdrError(`unknown reject_stat ${reply.rejectStat}`);
    }
  } else {
    throw new XdrError(`unknown reply_stat ${reply.replyStat}`);
  }
  return { reply, results: reader };
}

/**
 * Bytes an accepted reply's header occupies: `xid`, `mtype`, `reply_stat`, the
 * `AUTH_NULL` verifier (a flavor and a zero length, no body) and `accept_stat`.
 *
 * Fixed, which is what lets a session write it into the front of the same
 * writer its results go into instead of concatenating two buffers afterwards.
 */
export const ACCEPTED_REPLY_HEADER_SIZE = 24;

/**
 * Write `MSG_ACCEPTED` / `SUCCESS` into `writer`, results to follow.
 *
 * The header for the reply a *handler* is about to append. Callers that have
 * the results already should use {@link encodeAcceptedReply}; callers that are
 * about to produce them start here, so the whole reply is built once in one
 * buffer. {@link ACCEPTED_REPLY_HEADER_SIZE} is how many bytes this adds.
 */
export function writeAcceptedReplyHeader(writer: XdrWriter, xid: number): XdrWriter {
  writer.u32(xid);
  writer.u32(RPC_REPLY);
  writer.u32(MSG_ACCEPTED);
  writeAuth(writer, AUTH_NULL);
  writer.u32(RPC_SUCCESS);
  return writer;
}

/**
 * `MSG_ACCEPTED` with `SUCCESS`, then the encoded results.
 *
 * For a caller holding results it did not write into a reply writer itself —
 * NFSv4.1's replay cache, whose bytes come back from `./v4/state.ts` and must
 * not be written into. One allocation and one copy of `results`; building it
 * through an `XdrWriter` cost two.
 */
export function encodeAcceptedReply(xid: number, results?: Uint8Array): Uint8Array {
  const out = new Uint8Array(ACCEPTED_REPLY_HEADER_SIZE + (results?.byteLength ?? 0));
  const view = new DataView(out.buffer);
  view.setUint32(0, xid >>> 0, false);
  view.setUint32(4, RPC_REPLY, false);
  view.setUint32(8, MSG_ACCEPTED, false);
  view.setUint32(12, AUTH_NONE, false);
  // The `AUTH_NULL` verifier's body is empty, so its length word is the zero
  // `out` already holds; `accept_stat` follows it.
  view.setUint32(20, RPC_SUCCESS, false);
  if (results !== undefined) {
    out.set(results, ACCEPTED_REPLY_HEADER_SIZE);
  }
  return out;
}

/** `MSG_ACCEPTED` with an error status (`PROG_UNAVAIL`, `GARBAGE_ARGS`, …). */
export function encodeAcceptError(
  xid: number,
  acceptStat: number,
  mismatch?: { low: number; high: number },
): Uint8Array {
  const writer = new XdrWriter(48);
  writer.u32(xid);
  writer.u32(RPC_REPLY);
  writer.u32(MSG_ACCEPTED);
  writeAuth(writer, AUTH_NULL);
  writer.u32(acceptStat);
  if (mismatch !== undefined) {
    writer.u32(mismatch.low);
    writer.u32(mismatch.high);
  }
  return writer.bytes();
}

/** `MSG_DENIED` / `AUTH_ERROR`, the answer to a credential we will not take. */
export function encodeAuthError(xid: number, authStat: number): Uint8Array {
  const writer = new XdrWriter(32);
  writer.u32(xid);
  writer.u32(RPC_REPLY);
  writer.u32(MSG_DENIED);
  writer.u32(RPC_AUTH_ERROR);
  writer.u32(authStat);
  return writer.bytes();
}

/** `MSG_DENIED` / `RPC_MISMATCH`: we do not speak the caller's RPC version. */
export function encodeRpcMismatch(xid: number, low = RPC_VERSION, high = RPC_VERSION): Uint8Array {
  const writer = new XdrWriter(32);
  writer.u32(xid);
  writer.u32(RPC_REPLY);
  writer.u32(MSG_DENIED);
  writer.u32(RPC_MISMATCH);
  writer.u32(low);
  writer.u32(high);
  return writer.bytes();
}

// ---------------------------------------------------------------------------
// record marking (RFC 5531 §11)
// ---------------------------------------------------------------------------

/**
 * Wrap one message as a single-fragment record.
 *
 * RPC over TCP has no message boundaries of its own, so every record is a chain
 * of fragments, each prefixed by a 4-byte header: the high bit says "last
 * fragment", the low 31 bits are the fragment's length. One fragment per
 * message is what every implementation sends and is what we send; the
 * *receiver* still has to handle chains, because clients that split writes
 * across fragments exist and a receiver that assumed otherwise would corrupt
 * them silently.
 */
/**
 * Just the 4-byte header for a `length`-byte last fragment.
 *
 * For a sender that would rather put the mark and the message on the socket as
 * two chunks than copy the message to put them on as one — which is what
 * `server.ts` does, since a corked pair leaves as one `writev` and a
 * {@link frameRecord} of a 1 MiB `READ` is a 1 MiB `memcpy`.
 */
export function recordMark(length: number): Uint8Array {
  const mark = new Uint8Array(4);
  new DataView(mark.buffer).setUint32(0, RM_LAST_FRAGMENT | length, false);
  return mark;
}

export function frameRecord(message: Uint8Array): Uint8Array {
  const framed = new Uint8Array(4 + message.byteLength);
  new DataView(framed.buffer).setUint32(0, RM_LAST_FRAGMENT | message.byteLength, false);
  framed.set(message, 4);
  return framed;
}

/** Split a message into fragments of at most `size` bytes. For tests. */
export function frameFragments(message: Uint8Array, size: number): Uint8Array {
  if (size < 1) {
    throw new XdrError(`fragment size must be positive, got ${size}`);
  }
  const parts: Uint8Array[] = [];
  let total = 0;
  for (let at = 0; at < message.byteLength || at === 0; at += size) {
    const chunk = message.subarray(at, Math.min(at + size, message.byteLength));
    const last = at + size >= message.byteLength;
    const fragment = new Uint8Array(4 + chunk.byteLength);
    new DataView(fragment.buffer).setUint32(
      0,
      (last ? RM_LAST_FRAGMENT : 0) | chunk.byteLength,
      false,
    );
    fragment.set(chunk, 4);
    parts.push(fragment);
    total += fragment.byteLength;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/**
 * A genuine copy, whatever the input is.
 *
 * Not `bytes.slice(start, end)`: the input here is very often a socket
 * `Buffer`, and `Buffer.prototype.slice` **is `subarray`** — it returns a view,
 * the trap `xdr.ts` documents at length.
 *
 * `xdr.ts` spells its copy `Uint8Array.prototype.slice.call`, which is equally
 * correct and costs the same — the two are within noise of each other at every
 * size and from either kind of input. What differs is the *type* that comes
 * back: `slice.call` goes through `TypedArraySpeciesCreate`, so a `Buffer` in
 * gives a `Buffer` out, and a record handed to a session would then be a value
 * whose own `.slice()` is `subarray` again. A record exists to be owned
 * outright by whoever holds it; handing back a plain `Uint8Array` keeps that
 * from depending on what the socket happened to allocate.
 *
 * Which is why this is the copy anything **retaining** wire bytes past the call
 * they arrived on uses — `RecordAssembler` below, and the verifiers
 * `ExclusiveCreates` (`./util.ts`) keeps for two minutes. `handleCall` is
 * public and takes any `Uint8Array`, so "the assembler happens to allocate
 * plain ones" is not something a table outliving the request may rely on.
 */
export function copyBytes(
  bytes: Uint8Array,
  start = 0,
  end: number = bytes.byteLength,
): Uint8Array {
  const out = new Uint8Array(end - start);
  out.set(bytes.subarray(start, end));
  return out;
}

/**
 * How many fragments one record may arrive in, derived from its byte limit.
 *
 * A fragment costs a `Uint8Array` and an array slot whatever its length, so the
 * byte limit alone does not bound what a record can make this class hold: a
 * legal fragment may carry **zero** bytes, and a stream of bare 4-byte headers
 * would grow `#fragments` without ever advancing `#assembled` (measured: 2 MB
 * in, 59 MB retained). One fragment per kibibyte of the limit is far above what
 * any real client does — the kernel's client and every `mount.nfs` send one
 * fragment per record, and libtirpc's `xdrrec` flushes at its 8800-byte send
 * buffer — and far below the count that makes the overhead matter.
 */
function fragmentLimit(byteLimit: number): number {
  return Math.max(64, Math.ceil(byteLimit / 1024));
}

/**
 * The receiving half of record marking: bytes in, whole messages out.
 *
 * A stream reassembler, so it has to be paranoid about exactly three things — a
 * fragment header that claims more than the byte limit, a record whose
 * fragments add up past it, and a record split into more fragments than
 * {@link fragmentLimit} allows. All three are answered by throwing, which the
 * server turns into a closed connection: there is no way to resynchronize a
 * record-marked stream once a length is not to be believed.
 *
 * ## Every record handed out is a copy
 *
 * Records used to be views of the socket chunk they arrived in whenever they
 * fit in one, and copies whenever they did not — a per-caller contract that
 * depended on how the bytes happened to be delivered. They are copies now,
 * always, and the contract is simply that the caller owns what it is handed.
 * The cost is one `memcpy` per record, which is what buys:
 *
 * - **Linear reassembly.** The old `concat(buffer, chunk)` per delivery was
 *   O(n²) in record size against libuv's 64 KiB `data` cap — a legal 8 MiB
 *   record cost ~79 ms of `memcpy` and blocked the event loop for all of it.
 *   Deliveries are queued instead and the copy happens once, when a fragment is
 *   complete: the same 8 MiB now reassembles in ~1.2 ms, and 1 MiB in 74 µs
 *   against 823 µs.
 * - **No pinned socket memory.** A 120-byte record that was a view kept its
 *   whole 64 KiB pool slab alive for as long as anything held it. The old
 *   defense against that (`#buffer.slice()`) never fired: `concat` returned the
 *   socket `Buffer` unchanged when nothing was pending, so `.slice()` was
 *   `subarray`.
 *
 * Downstream is unaffected either way — `xdr.ts` copies everything it retains,
 * which is the standing rule and stays the standing rule.
 */
export class RecordAssembler {
  /** Fragment bodies accepted for the record being assembled. Empty ones are not kept. */
  #fragments: Uint8Array[] = [];
  /** Payload bytes accepted for it. */
  #assembled = 0;
  /** Fragments accepted for it, empty ones included — what {@link fragmentLimit} bounds. */
  #count = 0;
  /**
   * Deliveries not yet consumed, oldest first, with `#head` bytes of the first
   * already taken. Appending is O(1), which is the whole point.
   */
  #chunks: Uint8Array[] = [];
  #head = 0;
  /** Bytes across `#chunks` past `#head`. */
  #buffered = 0;
  readonly #limit: number;
  readonly #maxFragments: number;

  constructor(limit = 8 * 1024 * 1024, maxFragments = fragmentLimit(limit)) {
    this.#limit = limit;
    this.#maxFragments = Math.max(1, Math.trunc(maxFragments));
  }

  /**
   * Bytes held for a partially received record.
   *
   * Fragment headers count: they are four bytes this class consumed and cannot
   * give back, and leaving them out is what let a flood of empty fragments
   * report `0` while it grew.
   */
  get pending(): number {
    return this.#assembled + this.#count * 4 + this.#buffered;
  }

  /**
   * Feed the socket's bytes in; get whatever complete records came out.
   *
   * `chunk` is **kept** — queued as-is until its bytes have been consumed into a
   * fragment — so a caller must not overwrite a buffer it has handed over.
   * Node's own socket chunks satisfy that: libuv allocates each one out of a
   * pool it only ever advances. The records coming back have no such condition
   * on them; see the class docs.
   */
  push(chunk: Uint8Array<ArrayBufferLike>): Uint8Array[] {
    if (chunk.byteLength > 0) {
      this.#chunks.push(chunk);
      this.#buffered += chunk.byteLength;
    }
    const records: Uint8Array[] = [];
    while (this.#buffered >= 4) {
      const header = this.#header();
      const length = header & RM_LENGTH_MASK;
      const last = (header & RM_LAST_FRAGMENT) !== 0;
      // Both bounds are checked before the fragment is complete, so a record
      // that cannot be legal is refused without being buffered first.
      if (this.#assembled + length > this.#limit) {
        throw new XdrError(
          `RPC record of at least ${this.#assembled + length} bytes exceeds the ` +
            `${this.#limit}-byte limit`,
        );
      }
      if (this.#count >= this.#maxFragments) {
        throw new XdrError(
          `RPC record arrived in more than ${this.#maxFragments} fragments ` +
            `(${this.#assembled} bytes so far)`,
        );
      }
      if (this.#buffered < 4 + length) {
        break;
      }
      this.#drop(4);
      this.#assembled += length;
      this.#count++;
      if (length > 0) {
        this.#fragments.push(this.#take(length));
      }
      if (last) {
        records.push(join(this.#fragments, this.#assembled));
        this.#fragments = [];
        this.#assembled = 0;
        this.#count = 0;
      }
    }
    // What is left over is a partial fragment. While it spans deliveries it
    // stays queued — copying it out on every delivery is the O(n²) this class
    // exists to avoid — but a tail sitting inside one otherwise-consumed chunk
    // is copied loose, so a 4-byte remainder does not pin a 64 KiB pool slab.
    if (this.#chunks.length === 1 && this.#head > 0) {
      this.#chunks[0] = copyBytes(this.#chunks[0]!, this.#head, this.#head + this.#buffered);
      this.#head = 0;
    }
    return records;
  }

  /** The next four buffered bytes as a big-endian u32, without consuming them. */
  #header(): number {
    let value = 0;
    let need = 4;
    let at = this.#head;
    for (let index = 0; need > 0; index++) {
      const chunk = this.#chunks[index]!;
      for (let byte = at; byte < chunk.byteLength && need > 0; byte++) {
        value = value * 0x1_00 + chunk[byte]!;
        need--;
      }
      at = 0;
    }
    return value;
  }

  /**
   * Consume `length` buffered bytes, copied out. Only ever called with enough
   * present, and with `length > 0`.
   *
   * One allocation and one pass over the fragment however many deliveries it
   * spans — which is the whole difference from the `concat`-per-delivery this
   * replaced.
   */
  #take(length: number): Uint8Array {
    const out = new Uint8Array(length);
    let filled = 0;
    while (filled < length) {
      const chunk = this.#chunks[0]!;
      const width = Math.min(chunk.byteLength - this.#head, length - filled);
      out.set(chunk.subarray(this.#head, this.#head + width), filled);
      filled += width;
      this.#advance(width);
    }
    return out;
  }

  /** Consume `count` buffered bytes without copying them: a fragment header. */
  #drop(count: number): void {
    let dropped = 0;
    while (dropped < count) {
      const chunk = this.#chunks[0]!;
      const width = Math.min(chunk.byteLength - this.#head, count - dropped);
      dropped += width;
      this.#advance(width);
    }
  }

  #advance(width: number): void {
    this.#head += width;
    this.#buffered -= width;
    if (this.#head === this.#chunks[0]!.byteLength) {
      this.#chunks.shift();
      this.#head = 0;
    }
  }
}

function join(parts: Uint8Array[], total: number): Uint8Array {
  // One fragment is the common record and `#take` already copied it; zero
  // fragments is the empty record, legal and produced by real clients.
  if (parts.length === 1) {
    return parts[0]!;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}
