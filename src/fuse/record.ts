/**
 * Record and replay: `/dev/fuse` traffic as a file, and a file as a test.
 *
 * A running mount sees things nobody would think to write by hand — the exact
 * `LOOKUP`/`OPEN`/`READ`/`FORGET` sequence `git status` produces, the order a
 * `tar -x` interleaves `CREATE` with `SETATTR`, the `READDIRPLUS` paging a
 * 300-entry directory needs. `mount`'s `tap` option makes that
 * stream capturable; this module gives it a file format and a way to feed it back
 * through a {@link FuseSession} with no kernel, no mount and no root.
 *
 * ```ts
 * const recorder = new TranscriptRecorder();
 * await using mounted = await mount(driver, "/mnt/point", { tap: recorder.tap });
 * // ...run a workload against /mnt/point from another process...
 * await writeFile("transcript.fuse", recorder.encode());
 * ```
 *
 * ```ts
 * const report = await replayTranscript(new FuseSession(freshDriver()), transcript);
 * // report.failures is empty for a session that answered everything.
 * ```
 *
 * **What a replay proves, and what it cannot.** The recorded *replies* depend
 * on the state of the driver that produced them — its inode numbers, its file
 * contents, the file handles it happened to hand out. Replaying the requests
 * against a *fresh* driver therefore cannot produce byte-identical replies, and
 * comparing them would only assert that the fixture was recorded twice. What
 * replay does assert is everything that is a property of the *protocol* rather
 * than of the data: every request decodes, every request that requires a reply
 * gets exactly one, addressed to the right `unique`; nothing throws; the
 * session's own exactly-once assertions stay silent and its counters balance.
 * Those are the invariants whose violation hangs a mountpoint, and they hold
 * for any driver. The recorded reply direction is kept in the file anyway —
 * it is what makes a transcript readable, and it is checked for
 * well-formedness — but it is documentation, not an expectation.
 */

import { decodeInHeader, decodeOutHeader, decodeRequest, type FuseRequest } from "./protocol.ts";
import type { FuseSession } from "./session.ts";

/** `"UMFT"`, first four bytes of every transcript. */
export const TRANSCRIPT_MAGIC = 0x55_4d_46_54;
/** Format version. Bumped only for a change a v1 reader would misread. */
export const TRANSCRIPT_VERSION = 1;

/** Bytes before the first frame: magic, version, three reserved zeroes. */
const HEADER_SIZE = 8;
/** Bytes before each frame's payload: direction, flags, reserved, length, timestamp. */
const FRAME_SIZE = 16;

const DIRECTION_IN = 0;
const DIRECTION_OUT = 1;

/** Which way one frame went. `"in"` is kernel → daemon, `"out"` is daemon → kernel. */
export type TranscriptDirection = "in" | "out";

/** One message, exactly as it crossed the device. */
export interface TranscriptFrame {
  direction: TranscriptDirection;
  /** Nanoseconds since the first frame of the transcript. */
  timestamp: bigint;
  bytes: Uint8Array;
}

/**
 * Serialize frames.
 *
 * Deliberately the dullest format that works: a fixed header, then
 * `[dir u8, flags u8, reserved u16, len u32le, ts u64le, len bytes]` with no
 * padding, no compression and no index. A transcript is a test fixture — it has
 * to be readable from a hex dump ten years from now by someone who has only
 * this comment.
 */
export function encodeTranscript(frames: readonly TranscriptFrame[]): Uint8Array {
  let total = HEADER_SIZE;
  for (const frame of frames) {
    total += FRAME_SIZE + frame.bytes.length;
  }
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint32(0, TRANSCRIPT_MAGIC, false);
  view.setUint8(4, TRANSCRIPT_VERSION);
  let offset = HEADER_SIZE;
  for (const frame of frames) {
    view.setUint8(offset, frame.direction === "in" ? DIRECTION_IN : DIRECTION_OUT);
    view.setUint8(offset + 1, 0);
    view.setUint16(offset + 2, 0, true);
    view.setUint32(offset + 4, frame.bytes.length, true);
    view.setBigUint64(offset + 8, frame.timestamp, true);
    out.set(frame.bytes, offset + FRAME_SIZE);
    offset += FRAME_SIZE + frame.bytes.length;
  }
  return out;
}

/**
 * A real copy of some bytes.
 *
 * Not `bytes.slice()`, which is the trap this exists to avoid: on a Node
 * `Buffer` — which is what both a transport's receive buffer and `readFileSync`
 * hand you — `slice` is an alias for `subarray` and copies **nothing**. A
 * recorder built on it stores views of a buffer the transport is about to
 * overwrite, and produces a transcript whose frames say one length and contain
 * a later message's bytes.
 */
function copyOf(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}

/** Thrown for a file that is not a transcript, or is a truncated one. */
export class TranscriptError extends Error {
  override readonly name = "TranscriptError";
}

/** Parse a transcript. Throws {@link TranscriptError} on anything malformed. */
export function decodeTranscript(bytes: Uint8Array): TranscriptFrame[] {
  if (bytes.length < HEADER_SIZE) {
    throw new TranscriptError(`transcript is ${bytes.length} bytes, shorter than its header`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, false) !== TRANSCRIPT_MAGIC) {
    throw new TranscriptError("not a transcript: bad magic");
  }
  const version = view.getUint8(4);
  if (version !== TRANSCRIPT_VERSION) {
    throw new TranscriptError(`transcript version ${version}, expected ${TRANSCRIPT_VERSION}`);
  }
  const frames: TranscriptFrame[] = [];
  let offset = HEADER_SIZE;
  while (offset < bytes.length) {
    if (offset + FRAME_SIZE > bytes.length) {
      throw new TranscriptError(`truncated frame header at byte ${offset}`);
    }
    const direction = view.getUint8(offset);
    const length = view.getUint32(offset + 4, true);
    const timestamp = view.getBigUint64(offset + 8, true);
    const start = offset + FRAME_SIZE;
    if (start + length > bytes.length) {
      throw new TranscriptError(`truncated frame payload at byte ${start}: wanted ${length}`);
    }
    if (direction !== DIRECTION_IN && direction !== DIRECTION_OUT) {
      throw new TranscriptError(`frame at byte ${offset} has direction ${direction}`);
    }
    frames.push({
      direction: direction === DIRECTION_IN ? "in" : "out",
      timestamp,
      bytes: copyOf(bytes.subarray(start, start + length)),
    });
    offset = start + length;
  }
  return frames;
}

export interface TranscriptRecorderOptions {
  /**
   * Stop recording once this many payload bytes have been captured. Default:
   * no limit.
   *
   * A transcript is only useful if it can be committed, and a `WRITE` carries
   * its whole payload, so a workload that copies a gigabyte produces a
   * gigabyte. Recording stops cleanly at the limit rather than truncating a
   * frame: {@link TranscriptRecorder.truncated} says whether it did.
   */
  limit?: number;
  /** Clock, in nanoseconds. Default `process.hrtime.bigint`. */
  now?: () => bigint;
}

/**
 * Collects frames from `mount`'s `tap` option.
 *
 * The tap hands out a view of a buffer the transport is about to reuse, so
 * every frame is copied on the way in. That copy is the cost of recording, and
 * it is why the tap is off by default.
 */
export class TranscriptRecorder {
  readonly frames: TranscriptFrame[] = [];
  /** `true` once {@link TranscriptRecorderOptions.limit} stopped the recording. */
  truncated = false;
  /** Payload bytes captured so far, excluding framing. */
  bytes = 0;

  readonly #limit: number;
  readonly #now: () => bigint;
  #origin: bigint | undefined;

  constructor(options: TranscriptRecorderOptions = {}) {
    this.#limit = options.limit ?? Number.POSITIVE_INFINITY;
    this.#now = options.now ?? process.hrtime.bigint.bind(process.hrtime);
  }

  /** Pass this straight to `mount`'s `tap` option. Bound, so it can be detached. */
  readonly tap = (direction: TranscriptDirection, bytes: Uint8Array): void => {
    // Once the limit is reached, recording stops for good. Skipping only the
    // frames that do not fit would leave a transcript with *holes* in it —
    // a reply to a request that was never recorded — where stopping leaves a
    // prefix, which is a valid transcript of a shorter workload.
    if (this.truncated || this.bytes + bytes.length > this.#limit) {
      this.truncated = true;
      return;
    }
    const now = this.#now();
    this.#origin ??= now;
    this.bytes += bytes.length;
    this.frames.push({ direction, timestamp: now - this.#origin, bytes: copyOf(bytes) });
  };

  /** Serialize everything recorded so far. */
  encode(): Uint8Array {
    return encodeTranscript(this.frames);
  }
}

/** One request in a replay that did not behave. */
export interface ReplayFailure {
  /** Index of the frame in the transcript. */
  index: number;
  reason: string;
}

/** What a replay saw. */
export interface ReplayReport {
  /** Kernel → daemon frames fed to the session. */
  requests: number;
  /** Replies the session produced. */
  replies: number;
  /** Requests the kernel wants no answer to (`FORGET`, `BATCH_FORGET`). */
  noReply: number;
  /** Opcode name → how many times it appeared. */
  opcodes: Record<string, number>;
  /** Empty for a healthy session. */
  failures: ReplayFailure[];
}

/**
 * Feed a transcript's requests through a session, in order.
 *
 * Sequentially, one await per message: a transcript is a *log*, and its later
 * requests routinely depend on the file handles and nodeids earlier ones
 * produced. Replies are checked for shape, never for content — see the module
 * docs for why byte-comparison is not a meaningful assertion here.
 *
 * `out` frames are checked too, but only for being well-formed
 * `fuse_out_header`s: they are the recording's own reply direction, kept for
 * readability.
 */
export async function replayTranscript(
  session: FuseSession,
  frames: readonly TranscriptFrame[],
): Promise<ReplayReport> {
  const report: ReplayReport = {
    requests: 0,
    replies: 0,
    noReply: 0,
    opcodes: {},
    failures: [],
  };
  const fail = (index: number, reason: string): void => {
    report.failures.push({ index, reason });
  };

  for (const [index, frame] of frames.entries()) {
    if (frame.direction === "out") {
      try {
        const header = decodeOutHeader(frame.bytes);
        if (header.len !== frame.bytes.length) {
          fail(index, `recorded reply says len ${header.len}, frame is ${frame.bytes.length}`);
        }
      } catch (error) {
        fail(index, `recorded reply does not decode: ${String(error)}`);
      }
      continue;
    }

    report.requests++;
    let request: FuseRequest;
    try {
      request = decodeRequest(frame.bytes, session.protocol);
    } catch (error) {
      fail(index, `request does not decode: ${String(error)}`);
      continue;
    }
    report.opcodes[request.name] = (report.opcodes[request.name] ?? 0) + 1;

    // `handleMessage` is documented never to reject; a `try` here is what
    // turns a broken promise into a named failure instead of a failed run.
    let reply: Uint8Array | null;
    try {
      reply = await session.handleMessage(frame.bytes);
    } catch (error) {
      fail(index, `${request.name} rejected: ${String(error)}`);
      continue;
    }

    if (reply === null) {
      report.noReply++;
      if (!NO_REPLY_OPCODES.has(request.name)) {
        fail(index, `${request.name} was not answered`);
      }
      continue;
    }
    report.replies++;
    if (NO_REPLY_OPCODES.has(request.name)) {
      fail(index, `${request.name} must not be answered, but was`);
      continue;
    }
    try {
      const header = decodeOutHeader(reply);
      if (header.unique !== decodeInHeader(frame.bytes).unique) {
        fail(index, `${request.name} answered unique ${header.unique}, not its own`);
      }
      if (header.len !== reply.length) {
        fail(index, `${request.name} reply says len ${header.len}, is ${reply.length}`);
      }
    } catch (error) {
      fail(index, `${request.name} reply does not decode: ${String(error)}`);
    }
  }
  return report;
}

/** The opcodes the kernel wants no answer to. Anything else must be answered. */
const NO_REPLY_OPCODES = new Set(["FORGET", "BATCH_FORGET", "NOTIFY_REPLY"]);
