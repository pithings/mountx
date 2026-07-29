/**
 * A minimal 9P2000.L client, built from the server's own codecs.
 *
 * The same Tier-1 trick `test/nfs/client.ts` plays: the codecs in
 * `src/9p/protocol.ts` are symmetric, so the client that drives the server can
 * be written in JavaScript — and the whole protocol runs in one process, with
 * no kernel, no mount and no root.
 *
 * It speaks to a {@link P9Transport}, which is any function from a framed
 * request to a framed reply. {@link P9Client.overSession} makes one out of a
 * `P9Session` directly, which is what the session tests use; step 7's server
 * tests will hand it a socket instead, and nothing here changes.
 *
 * Two things it deliberately does *not* do. It does not track a pending map
 * keyed by tag — a transport answers the frame it was handed, so the reply is
 * simply the result of the call — and it does not resolve paths: it speaks fids
 * and names, exactly like the wire. What it does do is check the reply's type
 * and tag, and turn an `Rlerror` into an error shaped like a `node:fs` one, so
 * a test can say `rejects.toThrow(...)` and mean it.
 */

import { ERRNO_CODES, fsError, type ErrnoCode, type FsError } from "../../src/errors.ts";
import {
  P9_NOFID,
  P9_NOTAG,
  P9_RATTACH,
  P9_RCLUNK,
  P9_RFLUSH,
  P9_RGETATTR,
  P9_RLERROR,
  P9_READDIRHDRSZ,
  P9_RREADDIR,
  P9_RSTATFS,
  P9_RVERSION,
  P9_RWALK,
  P9_TATTACH,
  P9_TCLUNK,
  P9_TFLUSH,
  P9_TGETATTR,
  P9_TREADDIR,
  P9_TSTATFS,
  P9_TVERSION,
  P9_TWALK,
  P9_GETATTR_ALL,
  P9_VERSION_DOTL,
  messageName,
} from "../../src/9p/constants.ts";
import {
  encodeMessage,
  readDirents,
  readRattach,
  readRgetattr,
  readRlerror,
  readRreaddir,
  readRstatfs,
  readRversion,
  readRwalk,
  readEmptyBody,
  writeFidRequest,
  writeTattach,
  writeTflush,
  writeTgetattr,
  writeTreaddir,
  writeTversion,
  writeTwalk,
  type P9Dirent,
  type Rgetattr,
  type Rstatfs,
  type Rversion,
} from "../../src/9p/protocol.ts";
import type { P9Session } from "../../src/9p/session.ts";
import { P9Reader, type P9Qid, type P9Writer } from "../../src/9p/wire.ts";

/** Framed request in, framed reply out. A session, a socket, a fixture. */
export type P9Transport = (request: Uint8Array) => Promise<Uint8Array | null>;

/** The `msize` the client proposes unless a test says otherwise. */
export const CLIENT_MSIZE = 8192;

/** errno → code, the inverse of the table `Rlerror` puts on the wire. */
const CODE_BY_ERRNO = new Map<number, ErrnoCode>(
  Object.entries(ERRNO_CODES).map(([code, errno]) => [errno, code as ErrnoCode]),
);

/**
 * The error an `Rlerror` becomes.
 *
 * Shaped like a `node:fs` error whenever the errno is one `src/errors.ts`
 * names, because that is the whole point of 9P2000.L carrying errnos: what the
 * driver threw is what comes back. An errno outside the table keeps the number
 * and gets a synthetic code, rather than being flattened into `EIO` — a client
 * that hid the difference could not tell a server bug from a driver one.
 */
export function remoteError(ecode: number, what: string): FsError {
  const code = CODE_BY_ERRNO.get(ecode);
  if (code !== undefined) {
    return fsError(code, { message: `${code}: ${what} answered Rlerror ${ecode}` });
  }
  const error = new Error(`${what} answered Rlerror ${ecode}`) as FsError;
  error.code = `ERRNO_${ecode}`;
  error.errno = -ecode;
  return error;
}

/** A reply that is not the one asked for: wrong type, wrong tag, or absent. */
export class P9ProtocolError extends Error {
  readonly code = "ERR_9P_PROTOCOL";

  constructor(message: string) {
    super(message);
    this.name = "P9ProtocolError";
  }
}

/** One reply, decoded down to its header and a reader over the body. */
export interface P9Reply {
  type: number;
  tag: number;
  body: P9Reader;
}

/** The wire, plus one typed method per message this server answers. */
export class P9Client {
  readonly transport: P9Transport;
  /** What {@link P9Client.version} proposes by default. */
  msize = CLIENT_MSIZE;
  /** The `msize` the last successful {@link P9Client.version} agreed on. */
  negotiated: number | undefined;
  #tag = 0;

  constructor(transport: P9Transport) {
    this.transport = transport;
  }

  /** Drive a session directly — no socket, no framing, one call per message. */
  static overSession(session: P9Session): P9Client {
    return new P9Client((request) => session.handleCall(request));
  }

  /**
   * The next tag, wrapping at 16 bits and never {@link P9_NOTAG}.
   *
   * Tags are only recycled after their reply, exactly as the kernel's IDR
   * recycles them, so the duplicate-tag path is something a test has to ask for
   * on purpose.
   */
  nextTag(): number {
    this.#tag = (this.#tag + 1) & 0xff_ff;
    if (this.#tag === P9_NOTAG) {
      this.#tag = 0;
    }
    return this.#tag;
  }

  /** Send one message and get its reply, checking only the tag. */
  async send(
    type: number,
    tag: number,
    write?: (writer: P9Writer) => void,
    capacity?: number,
  ): Promise<P9Reply> {
    return this.sendFrame(encodeMessage(type, tag, write, capacity), tag, messageName(type));
  }

  /** Send bytes as they are — for the malformed frames the tests need. */
  async sendFrame(frame: Uint8Array, tag: number, what: string): Promise<P9Reply> {
    const reply = await this.transport(frame);
    if (reply === null) {
      throw new P9ProtocolError(`${what} was dropped without a reply`);
    }
    const reader = new P9Reader(reply);
    const size = reader.u32("size");
    if (size !== reply.byteLength) {
      throw new P9ProtocolError(`${what} reply says ${size} bytes but is ${reply.byteLength}`);
    }
    const replyType = reader.u8("type");
    const replyTag = reader.u16("tag");
    if (replyTag !== tag) {
      throw new P9ProtocolError(`${what} was tagged ${tag} but the reply is tagged ${replyTag}`);
    }
    return { type: replyType, tag: replyTag, body: reader };
  }

  /**
   * Send one message and insist on the matching reply type.
   *
   * An `Rlerror` throws {@link remoteError}; any other mismatch throws
   * {@link P9ProtocolError}, because a server answering `Rwalk` to a `Tgetattr`
   * is a bug no test should be able to read past.
   */
  async call(
    type: number,
    expected: number,
    write?: (writer: P9Writer) => void,
    options: { tag?: number; capacity?: number } = {},
  ): Promise<P9Reply> {
    const tag = options.tag ?? this.nextTag();
    const what = messageName(type);
    const reply = await this.send(type, tag, write, options.capacity);
    if (reply.type === P9_RLERROR && expected !== P9_RLERROR) {
      const { ecode } = readRlerror(reply.body);
      reply.body.end("Rlerror");
      throw remoteError(ecode, what);
    }
    if (reply.type !== expected) {
      throw new P9ProtocolError(
        `${what} was answered ${messageName(reply.type)}, not ${messageName(expected)}`,
      );
    }
    return reply;
  }

  // --- messages ---

  /**
   * `Tversion`. Records the agreed `msize` unless the server said `unknown`,
   * which is the one reply that is a refusal without being an error.
   */
  async version(msize = this.msize, version = P9_VERSION_DOTL): Promise<Rversion> {
    const reply = await this.call(
      P9_TVERSION,
      P9_RVERSION,
      (writer) => writeTversion(writer, { msize, version }),
      { tag: P9_NOTAG },
    );
    const agreed = readRversion(reply.body);
    reply.body.end("Rversion");
    this.negotiated = agreed.version === P9_VERSION_DOTL ? agreed.msize : undefined;
    return agreed;
  }

  async attach(
    fid: number,
    options: { afid?: number; uname?: string; aname?: string; nUname?: number } = {},
  ): Promise<P9Qid> {
    const reply = await this.call(P9_TATTACH, P9_RATTACH, (writer) =>
      writeTattach(writer, {
        fid,
        afid: options.afid ?? P9_NOFID,
        uname: options.uname ?? "",
        aname: options.aname ?? "",
        nUname: options.nUname ?? 0,
      }),
    );
    const { qid } = readRattach(reply.body);
    reply.body.end("Rattach");
    return qid;
  }

  async walk(fid: number, newfid: number, wnames: string[]): Promise<P9Qid[]> {
    const reply = await this.call(
      P9_TWALK,
      P9_RWALK,
      (writer) => writeTwalk(writer, { fid, newfid, wnames }),
      { capacity: 256 },
    );
    const { wqids } = readRwalk(reply.body);
    reply.body.end("Rwalk");
    return wqids;
  }

  async clunk(fid: number): Promise<void> {
    const reply = await this.call(P9_TCLUNK, P9_RCLUNK, (writer) =>
      writeFidRequest(writer, { fid }),
    );
    readEmptyBody(reply.body, "Rclunk");
  }

  async getattr(fid: number, requestMask = P9_GETATTR_ALL): Promise<Rgetattr> {
    const reply = await this.call(P9_TGETATTR, P9_RGETATTR, (writer) =>
      writeTgetattr(writer, { fid, requestMask }),
    );
    const attr = readRgetattr(reply.body);
    reply.body.end("Rgetattr");
    return attr;
  }

  async statfs(fid: number): Promise<Rstatfs> {
    const reply = await this.call(P9_TSTATFS, P9_RSTATFS, (writer) =>
      writeFidRequest(writer, { fid }),
    );
    const stats = readRstatfs(reply.body);
    reply.body.end("Rstatfs");
    return stats;
  }

  /**
   * `Treaddir`, unpacked. `count` defaults to what the negotiated `msize`
   * leaves for entries, which is what `p9_client_readdir()` clamps to.
   */
  async readdir(fid: number, offset: bigint, count?: number): Promise<P9Dirent[]> {
    const budget = count ?? (this.negotiated ?? this.msize) - P9_READDIRHDRSZ;
    const reply = await this.call(
      P9_TREADDIR,
      P9_RREADDIR,
      (writer) => writeTreaddir(writer, { fid, offset, count: budget }),
      { capacity: 32 },
    );
    const { data } = readRreaddir(reply.body);
    reply.body.end("Rreaddir");
    return readDirents(data);
  }

  /** Every entry of a directory, paged to exhaustion. */
  async readdirAll(fid: number, count?: number): Promise<P9Dirent[]> {
    const all: P9Dirent[] = [];
    let offset = 0n;
    for (;;) {
      const page = await this.readdir(fid, offset, count);
      if (page.length === 0) {
        return all;
      }
      all.push(...page);
      offset = page.at(-1)!.offset;
    }
  }

  async flush(oldtag: number, options: { tag?: number } = {}): Promise<void> {
    const reply = await this.call(
      P9_TFLUSH,
      P9_RFLUSH,
      (writer) => writeTflush(writer, { oldtag }),
      options,
    );
    readEmptyBody(reply.body, "Rflush");
  }

  /** Send a message and return the `Rlerror` errno it must answer with. */
  async expectError(
    type: number,
    write?: (writer: P9Writer) => void,
    options: { tag?: number; capacity?: number } = {},
  ): Promise<number> {
    const reply = await this.call(type, P9_RLERROR, write, options);
    const { ecode } = readRlerror(reply.body);
    reply.body.end("Rlerror");
    return ecode;
  }
}
