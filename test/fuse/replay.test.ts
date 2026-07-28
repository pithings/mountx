/**
 * Replay: the committed `/dev/fuse` transcripts, fed back through a session.
 *
 * No root, no kernel, no mount — this is Tier 0, and it runs in plain
 * `pnpm test`. The fixtures come from `record-fixtures.ts` against a real
 * kernel, which is the point: they contain request sequences nobody would think
 * to write by hand, in the order a real `ls`, `sh` and `tar` produced them.
 *
 * **These tests assert protocol invariants, not bytes.** The recorded replies
 * describe the driver that was mounted at record time — its inode numbers, its
 * file handles, its contents — so replaying against a fresh driver cannot
 * reproduce them, and comparing them would only prove the fixture was recorded.
 * What must hold for *any* driver is that every request decodes, every request
 * that needs a reply gets exactly one addressed to its own `unique`, nothing
 * throws, and the session's own exactly-once bookkeeping stays clean. Those are
 * the invariants whose violation leaves a process in `D` state. See the module
 * docs in `src/fuse/record.ts`.
 */

import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { FUSE_FORGET, FUSE_GETATTR, FUSE_ROOT_ID } from "../../src/fuse/constants.ts";
import { encodeReply, encodeRequest } from "../../src/fuse/protocol.ts";
import {
  decodeTranscript,
  encodeTranscript,
  replayTranscript,
  TranscriptError,
  TranscriptRecorder,
  type TranscriptFrame,
} from "../../src/fuse/record.ts";
import { FuseSession } from "../../src/fuse/session.ts";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures");

/**
 * The committed transcripts, and the opcodes each one exists to carry.
 *
 * The opcode lists are the regression guard on the *fixtures*: re-recording
 * with a smaller workload, or with kernel caching left on, would quietly
 * produce a file that still replays green while covering half as much.
 */
const TRANSCRIPTS = [
  {
    name: "ls-walk",
    what: "ls -laR and find over a seeded tree",
    opcodes: [
      "INIT",
      "GETATTR",
      "LOOKUP",
      "OPENDIR",
      "READDIR",
      "READDIRPLUS",
      "RELEASEDIR",
      "READLINK",
      "LISTXATTR",
      "GETXATTR",
      "STATFS",
    ],
  },
  {
    name: "write-rename-stat",
    what: "the write / rename / stat / read loop a build tool makes",
    opcodes: [
      "INIT",
      "CREATE",
      "WRITE",
      "FLUSH",
      "RELEASE",
      "RENAME",
      // `mv` reaches for `renameat2` first, which is a different opcode with a
      // different struct — and one no hand-written test would have thought to
      // send.
      "RENAME2",
      "LOOKUP",
      "GETATTR",
      // `stat(1)` uses `statx(2)`, which the session answers `-ENOSYS`.
      "STATX",
      "OPEN",
      "READ",
      "MKDIR",
      "READDIRPLUS",
    ],
  },
  {
    name: "tar-extract",
    what: "tar -xp of an archive with directories, files and a symlink",
    opcodes: [
      "INIT",
      "MKDIR",
      "CREATE",
      "WRITE",
      "SYMLINK",
      "SETATTR",
      "READLINK",
      "LOOKUP",
      "RELEASE",
    ],
  },
] as const;

/** Fixtures are committed; a transcript that outgrows this wants a smaller workload. */
const MAX_FIXTURE_BYTES = 200_000;

function load(name: string): TranscriptFrame[] {
  return decodeTranscript(readFileSync(join(FIXTURES, `${name}.fuse`)));
}

describe("the transcript format", () => {
  it("round-trips frames", () => {
    const frames: TranscriptFrame[] = [
      { direction: "in", timestamp: 0n, bytes: new Uint8Array([1, 2, 3]) },
      { direction: "out", timestamp: 1_234_567_890n, bytes: new Uint8Array(0) },
      { direction: "in", timestamp: 2n ** 40n, bytes: new Uint8Array([255]) },
    ];
    expect(decodeTranscript(encodeTranscript(frames))).toEqual(frames);
  });

  it("round-trips an empty transcript", () => {
    expect(decodeTranscript(encodeTranscript([]))).toEqual([]);
  });

  it("refuses anything that is not one", () => {
    expect(() => decodeTranscript(new Uint8Array(4))).toThrow(TranscriptError);
    expect(() => decodeTranscript(new Uint8Array(16))).toThrow(/bad magic/);
    const good = encodeTranscript([
      { direction: "in", timestamp: 0n, bytes: new Uint8Array([7, 7]) },
    ]);
    // A wrong version reads as a different format, not as a corrupt one.
    const wrongVersion = good.slice();
    wrongVersion[4] = 99;
    expect(() => decodeTranscript(wrongVersion)).toThrow(/version 99/);
    // Truncation is the failure a half-written recording produces.
    expect(() => decodeTranscript(good.slice(0, good.length - 1))).toThrow(/truncated frame/);
    expect(() => decodeTranscript(good.slice(0, 12))).toThrow(/truncated frame header/);
  });

  it("copies what the tap hands it, because the transport reuses that buffer", () => {
    let clock = 0n;
    const recorder = new TranscriptRecorder({
      now: () => (clock += 1000n),
    });
    // A `Buffer`, on purpose: that is what the transport's receive buffer is,
    // and `Buffer.prototype.slice` does not copy. A recorder that used it would
    // store views of a buffer about to be overwritten.
    const buffer = Buffer.from([1, 2, 3, 4]);
    recorder.tap("in", buffer);
    buffer.fill(0xaa);
    recorder.tap("out", buffer);

    expect([...recorder.frames[0]!.bytes]).toEqual([1, 2, 3, 4]);
    expect([...recorder.frames[1]!.bytes]).toEqual([0xaa, 0xaa, 0xaa, 0xaa]);
    // Timestamps are relative to the first frame.
    expect(recorder.frames[0]!.timestamp).toBe(0n);
    expect(recorder.frames[1]!.timestamp).toBe(1000n);
    expect(recorder.bytes).toBe(8);
    expect(recorder.truncated).toBe(false);
  });

  it("stops at the limit rather than recording a transcript with holes in it", () => {
    const recorder = new TranscriptRecorder({ limit: 6 });
    recorder.tap("in", new Uint8Array(4));
    // Does not fit: recording stops here...
    recorder.tap("in", new Uint8Array(4));
    // ...and stays stopped, even though this one would have fit.
    recorder.tap("in", new Uint8Array(1));
    expect(recorder.truncated).toBe(true);
    expect(recorder.frames).toHaveLength(1);
  });
});

describe.each(TRANSCRIPTS)("replaying $name", ({ name, what, opcodes }) => {
  it(`is a transcript of ${what}`, () => {
    const bytes = statSync(join(FIXTURES, `${name}.fuse`)).size;
    expect(bytes).toBeLessThan(MAX_FIXTURE_BYTES);
    const frames = load(name);
    expect(frames.length).toBeGreaterThan(100);
    // Both directions were captured, and time moves forward.
    expect(frames.some((frame) => frame.direction === "in")).toBe(true);
    expect(frames.some((frame) => frame.direction === "out")).toBe(true);
    expect([...frames].sort((a, b) => Number(a.timestamp - b.timestamp))[0]!.timestamp).toBe(0n);
  });

  it("answers every request exactly once, with nothing thrown", async () => {
    const session = new FuseSession(createMemoryDriver());
    const report = await replayTranscript(session, load(name));

    expect(report.failures).toEqual([]);
    expect(report.requests).toBeGreaterThan(50);
    expect(report.replies + report.noReply).toBe(report.requests);
    // The session's own exactly-once assertions, which are what the transport
    // relies on: a missed reply is an unkillable process.
    expect(session.assertions).toEqual([]);
    expect(session.stats.assertions).toBe(0);
    expect(session.stats.dropped).toBe(0);
    expect(session.stats.replies + session.stats.noReply).toBe(session.stats.requests);
    // The handshake is in the transcript, so a replayed session is negotiated.
    expect(session.negotiated).toBeDefined();
  });

  it("carries the opcodes it was recorded for", async () => {
    const report = await replayTranscript(new FuseSession(createMemoryDriver()), load(name));
    for (const opcode of opcodes) {
      expect(report.opcodes[opcode] ?? 0).toBeGreaterThan(0);
    }
  });

  it("contains no opcode this build has no name for", async () => {
    const report = await replayTranscript(new FuseSession(createMemoryDriver()), load(name));
    expect(Object.keys(report.opcodes).filter((opcode) => opcode.startsWith("UNKNOWN"))).toEqual(
      [],
    );
  });

  it("replays identically twice, so a fixture is a deterministic test", async () => {
    const first = await replayTranscript(new FuseSession(createMemoryDriver()), load(name));
    const second = await replayTranscript(new FuseSession(createMemoryDriver()), load(name));
    expect(second).toEqual(first);
  });
});

describe("replay reporting", () => {
  it("names a request the session did not answer", async () => {
    const session = new FuseSession(createMemoryDriver());
    // `unique == 0` marks a notification, which cannot be answered — the
    // session drops it, and replay says so rather than passing quietly.
    const requests = load("ls-walk").filter((frame) => frame.direction === "in");
    const broken = requests[1]!.bytes;
    new DataView(broken.buffer, broken.byteOffset, broken.byteLength).setBigUint64(8, 0n, true);
    const report = await replayTranscript(session, [
      requests[0]!,
      { direction: "in", timestamp: 1n, bytes: broken },
    ]);
    expect(report.failures.map((failure) => failure.reason)).toEqual([
      expect.stringContaining("was not answered"),
    ]);
  });

  /**
   * A session that answers however the test says.
   *
   * The remaining detectors exist for a *broken* server, and `FuseSession` is
   * not one — so the only way to reach them is to substitute something that
   * is. Everything `replayTranscript` touches on a session is here: the codec
   * context and `handleMessage`.
   */
  function brokenSession(answer: (message: Uint8Array) => Promise<Uint8Array | null>): FuseSession {
    return { protocol: undefined, handleMessage: answer } as unknown as FuseSession;
  }

  function request(opcode: number, unique: bigint, body: unknown): TranscriptFrame {
    return {
      direction: "in",
      timestamp: 0n,
      bytes: encodeRequest({ opcode, unique, nodeid: FUSE_ROOT_ID, body }),
    };
  }

  const getattr = (unique: bigint): TranscriptFrame =>
    request(FUSE_GETATTR, unique, { getattrFlags: 0, fh: 0n });

  it("names a reply addressed to somebody else's request", async () => {
    // The invariant that keeps a mountpoint alive: a reply carries the
    // `unique` it is answering. Get this wrong and one caller hangs while
    // another gets an answer meant for it.
    const session = brokenSession(async () => encodeReply(999n));
    const report = await replayTranscript(session, [getattr(7n)]);
    expect(report.failures.map((failure) => failure.reason)).toEqual([
      "GETATTR answered unique 999, not its own",
    ]);
  });

  it("names a reply whose header length disagrees with the bytes", async () => {
    const session = brokenSession(async () => {
      const reply = encodeReply(7n);
      const padded = new Uint8Array(reply.length + 1);
      padded.set(reply);
      return padded;
    });
    const report = await replayTranscript(session, [getattr(7n)]);
    expect(report.failures.map((failure) => failure.reason)).toEqual([
      "GETATTR reply says len 16, is 17",
    ]);
  });

  it("names a reply that is not a reply at all", async () => {
    const session = brokenSession(async () => new Uint8Array(3));
    const report = await replayTranscript(session, [getattr(7n)]);
    expect(report.failures).toHaveLength(1);
    expect(report.failures[0]!.reason).toMatch(/^GETATTR reply does not decode: /);
  });

  it("names an answer to a request the kernel wants no answer to", async () => {
    const session = brokenSession(async () => encodeReply(11n));
    const report = await replayTranscript(session, [request(FUSE_FORGET, 11n, { nlookup: 1n })]);
    expect(report.failures.map((failure) => failure.reason)).toEqual([
      "FORGET must not be answered, but was",
    ]);
    expect(report.replies).toBe(1);
  });

  it("names a session that rejected instead of replying", async () => {
    // `handleMessage` is documented never to reject. If it ever does, replay
    // has to say which request did it rather than take the whole run down.
    const session = brokenSession(() => Promise.reject(new Error("boom")));
    const report = await replayTranscript(session, [getattr(7n)]);
    expect(report.failures.map((failure) => failure.reason)).toEqual([
      "GETATTR rejected: Error: boom",
    ]);
    expect(report.replies + report.noReply).toBe(0);
  });

  it("names a frame that does not decode", async () => {
    const report = await replayTranscript(new FuseSession(createMemoryDriver()), [
      { direction: "in", timestamp: 0n, bytes: new Uint8Array(8) },
      { direction: "out", timestamp: 1n, bytes: new Uint8Array(3) },
    ]);
    expect(report.failures).toHaveLength(2);
    expect(report.failures[0]!.reason).toMatch(/does not decode/);
    expect(report.failures[1]!.reason).toMatch(/does not decode/);
  });
});
