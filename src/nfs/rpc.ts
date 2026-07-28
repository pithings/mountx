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

import {
  AUTH_NONE,
  AUTH_SYS,
  MSG_ACCEPTED,
  MSG_DENIED,
  RM_LAST_FRAGMENT,
  RM_LENGTH_MASK,
  RPC_AUTH_ERROR,
  RPC_CALL,
  RPC_MAX_AUTH_BYTES,
  RPC_MISMATCH,
  RPC_REPLY,
  RPC_SUCCESS,
  RPC_VERSION,
} from "./constants.ts";
import { XdrError, XdrReader, XdrWriter } from "./xdr.ts";

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

/** `struct authsys_parms` (RFC 5531 §8.2), the body of an `AUTH_SYS` credential. */
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

/** `MSG_ACCEPTED` with `SUCCESS`, then the encoded results. */
export function encodeAcceptedReply(xid: number, results?: Uint8Array): Uint8Array {
  const writer = new XdrWriter(32 + (results?.byteLength ?? 0));
  writer.u32(xid);
  writer.u32(RPC_REPLY);
  writer.u32(MSG_ACCEPTED);
  writeAuth(writer, AUTH_NULL);
  writer.u32(RPC_SUCCESS);
  if (results !== undefined) {
    writer.raw(results);
  }
  return writer.bytes();
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
 * The receiving half of record marking: bytes in, whole messages out.
 *
 * A stream reassembler, so it has to be paranoid about exactly two things — a
 * fragment header that claims more than the limit, and a record whose fragments
 * add up past it. Both are answered by throwing, which the server turns into a
 * closed connection: there is no way to resynchronize a record-marked stream
 * once a length is not to be believed.
 */
export class RecordAssembler {
  /** Bytes accepted for the record currently being assembled. */
  #fragments: Uint8Array[] = [];
  #assembled = 0;
  /** Buffered stream bytes not yet consumed as a fragment. */
  #buffer: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  readonly #limit: number;

  constructor(limit = 8 * 1024 * 1024) {
    this.#limit = limit;
  }

  /** Bytes held for a partially received record. */
  get pending(): number {
    return this.#assembled + this.#buffer.byteLength;
  }

  /**
   * Feed the socket's bytes in; get whatever complete records came out.
   *
   * **The records may be views of `chunk`**, and `chunk` itself is kept when a
   * record spans deliveries — so a caller must not overwrite a buffer it has
   * handed over. That is deliberate rather than an oversight: a record is
   * consumed by decoders that copy everything they retain (`xdr.ts`), so
   * nothing downstream ever holds socket memory, and the framing layer stays
   * free of a per-message `memcpy` on the `WRITE` path. Node's own socket
   * chunks satisfy the contract — libuv allocates each one out of a pool it
   * only ever advances.
   */
  push(chunk: Uint8Array<ArrayBufferLike>): Uint8Array[] {
    this.#buffer = concat(this.#buffer, chunk);
    const records: Uint8Array[] = [];
    for (;;) {
      if (this.#buffer.byteLength < 4) {
        break;
      }
      const header = new DataView(
        this.#buffer.buffer,
        this.#buffer.byteOffset,
        this.#buffer.byteLength,
      ).getUint32(0, false);
      const length = header & RM_LENGTH_MASK;
      const last = (header & RM_LAST_FRAGMENT) !== 0;
      if (this.#assembled + length > this.#limit) {
        throw new XdrError(
          `RPC record of at least ${this.#assembled + length} bytes exceeds the ` +
            `${this.#limit}-byte limit`,
        );
      }
      if (this.#buffer.byteLength < 4 + length) {
        break;
      }
      this.#fragments.push(this.#buffer.slice(4, 4 + length));
      this.#assembled += length;
      this.#buffer = this.#buffer.subarray(4 + length);
      if (last) {
        records.push(join(this.#fragments, this.#assembled));
        this.#fragments = [];
        this.#assembled = 0;
      }
    }
    // The remaining view keeps the whole chunk alive; copy it loose once it is
    // the only thing left, so a big write does not pin its buffer forever.
    if (this.#buffer.byteLength > 0 && this.#buffer.byteOffset > 0) {
      this.#buffer = this.#buffer.slice();
    }
    return records;
  }
}

function concat(
  left: Uint8Array<ArrayBufferLike>,
  right: Uint8Array<ArrayBufferLike>,
): Uint8Array<ArrayBufferLike> {
  if (left.byteLength === 0) {
    return right;
  }
  const out = new Uint8Array(left.byteLength + right.byteLength);
  out.set(left, 0);
  out.set(right, left.byteLength);
  return out;
}

function join(parts: Uint8Array[], total: number): Uint8Array {
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
