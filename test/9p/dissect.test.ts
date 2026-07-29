/**
 * The independent wire oracle: `tshark`'s 9P dissector reading our bytes.
 *
 * Every other test in `test/9p/` is us marking our own homework — the Tier-1
 * client speaks the codecs in `src/9p/protocol.ts`, so a field written and read
 * back through the same encoder round-trips whether or not the layout is the
 * one the kernel expects. What this file adds is a second implementation with
 * no shared ancestry: Wireshark's `packet-9P.c`, written from the protocol
 * documents by people who have never seen this repository. A real exchange
 * between `P9Client` and `createP9Server` is handed to it, and what it says
 * each message means is compared, field by field, with what we say.
 *
 * This is the role `libnfs` plays for the NFS transport (`.agents/
 * environment.md`), and the reason 9P gets a dissector instead of a client is
 * that Wireshark ships one and the alternative — a 9P client on this host —
 * needs a kernel mount, which is Tier 2.
 *
 * **No capture is taken.** Live capture needs `CAP_NET_RAW`, and Tier-0/1 runs
 * unprivileged. The exchange is driven over an in-process duplex, its bytes are
 * recorded, and `test/9p/pcap.ts` synthesizes a capture file from them; nothing
 * here opens a socket or asks for a privilege. Segmentation is therefore ours
 * to choose, which is a feature: two messages are deliberately cut in half so
 * the dissector has to reassemble a 9P message from two TCP segments — one of
 * them cut inside its four-byte `size` field, the case that catches a framing
 * layer that peeks instead of buffering.
 *
 * **What was found.** Wireshark's `Tgetlock`/`Rgetlock` dissection reads a
 * four-byte `flags` field that 9P2000.L does not have there — `Tlock` has one,
 * `Tgetlock` does not (`struct p9_flock` vs `struct p9_getlock` in the kernel's
 * `include/net/9p/9p.h` v6.12, and the `"dbdqqds"` vs `"dbqqds"` format strings
 * in `net/9p/client.c`) — so it runs four bytes past the end of the message and
 * reports it malformed. Our encoders are right; the last test in this file
 * pins the defect precisely enough to prove that, and passes either way once
 * Wireshark fixes it. Observed with TShark 4.6.7.
 *
 * Skips itself when `tshark` is not on `PATH` (`wireshark-cli`), which is most
 * CI images. It runs on the dev host.
 */

import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { duplexPair } from "node:stream";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  P9_GETATTR_ALL,
  P9_GETATTR_BASIC,
  P9_LOCK_FLAGS_BLOCK,
  P9_LOCK_SUCCESS,
  P9_LOCK_TYPE_UNLCK,
  P9_LOCK_TYPE_WRLCK,
  P9_NOFID,
  P9_NOTAG,
  P9_QTDIR,
  P9_QTFILE,
  P9_QTSYMLINK,
  P9_SETATTR_ATIME,
  P9_SETATTR_ATIME_SET,
  P9_SETATTR_GID,
  P9_SETATTR_MODE,
  P9_SETATTR_MTIME,
  P9_SETATTR_MTIME_SET,
  P9_SETATTR_SIZE,
  P9_SETATTR_UID,
  P9_TWALK,
  P9_VERSION_DOTL,
  messageName,
} from "../../src/9p/constants.ts";
import { P9FrameAssembler, type Rstatfs } from "../../src/9p/protocol.ts";
import { createP9Server } from "../../src/9p/server.ts";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { ERRNO_CODES } from "../../src/errors.ts";
import { DT_DIR, DT_REG, O_CREAT, O_EXCL, O_RDONLY, O_RDWR } from "../../src/fuse/constants.ts";
import type { FsDriver, StatsFsLike } from "../../src/types.ts";
import { CLIENT_MSIZE, P9Client, type P9Transport } from "./client.ts";
import { buildPcap, P9_TCP_PORT, type P9Delivery } from "./pcap.ts";

// ---------------------------------------------------------------------------
// the exchange
// ---------------------------------------------------------------------------

/**
 * `O_DIRECTORY`, from the kernel's `include/uapi/asm-generic/fcntl.h`.
 *
 * On the wire this is the *kernel's* `O_*` namespace whatever host the test
 * runs on (`src/fuse/flags.ts` documents the crossing), so it is transcribed
 * here rather than read out of the host's `node:fs` constants. It is in the
 * exchange because a `Tlopen` whose flags are all zero would prove nothing
 * about how the flag word is placed.
 */
const O_DIRECTORY = 0o200_000;

/** Fids the script uses, one per role, all distinct and none reused. */
const ROOT_FID = 1;
const FILE_FID = 2;
const DIR_FID = 3;
const MADE_FID = 4;
const LINK_FID = 5;
const SUB_FID = 6;
/** The fid a failing `Twalk` asks for, and never gets. */
const DOOMED_FID = 9;

/** What `/dir/hello.txt` holds. Nine bytes, and visible in a hex dump. */
const HELLO = "hello, 9P";

/** The name of the file under `/dir`. */
const HELLO_NAME = "hello.txt";

/** The `Twrite` payload: long enough to need two segments, and not a run. */
const PAYLOAD = Uint8Array.from({ length: 2100 }, (_, at) => (at * 7 + 13) & 0xff);

/** Distinct values for the `Tlock` fields, so a transposition cannot hide. */
const LOCK = {
  type: P9_LOCK_TYPE_WRLCK,
  flags: P9_LOCK_FLAGS_BLOCK,
  start: 0x11_22_33_44_55_66_77_88n,
  length: 0x99n,
  procId: 0x24_68,
  clientId: "mountx-dissect",
} as const;

/** Distinct values for `Tsetattr`, including two times with nonzero nanoseconds. */
const SETATTR = {
  mode: 0o604,
  uid: 4321,
  gid: 8765,
  size: 5n,
  atime: { sec: 1_234_567_890n, nsec: 123_456_789n },
  mtime: { sec: 1_400_000_000n, nsec: 987_654_321n },
} as const;

/**
 * What the driver behind this exchange answers `statfs` with.
 *
 * The memory driver's own numbers are honest and useless here: it reports
 * `bfree === bavail === ffree` and `blocks === files`, and an oracle cannot see
 * a transposition between two fields that hold the same number. So the seven
 * fields a driver supplies are overridden with seven distinct ones. The other
 * two of `Rstatfs`'s nine are the *server's* and cannot come from here —
 * `fsid` is always `0` and `namelen` always `NAME_MAX`, both decided in
 * `src/9p/session.ts` and asserted as the constants they are.
 */
const STATFS = {
  type: 0x12_34_ab_cd,
  bsize: 7168,
  blocks: 900_001,
  bfree: 800_002,
  bavail: 700_003,
  files: 600_004,
  ffree: 500_005,
} as const;

/** `fsid`, which the session pins to zero rather than inventing one. */
const STATFS_FSID = 0n;

/** `namelen`: `NAME_MAX`, the bytes this server allows in one path component. */
const STATFS_NAMELEN = 255;

/** The tag `Tflush` asks about: one no request ever carried. */
const UNKNOWN_TAG = 0x44_44;

/** The client's ephemeral port. Fabricated, like everything below IP here. */
const CLIENT_PORT = 40_404;

/** One 9P message as it crossed the wire, with the header we parsed ourselves. */
interface Recorded {
  from: "client" | "server";
  /** `Tversion`, `Rlerror`, … */
  name: string;
  type: number;
  tag: number;
  bytes: Uint8Array;
}

/** The exchange, plus the values the assertions compare `tshark` against. */
interface Exchange {
  messages: Recorded[];
  /** Everything the client learned, kept for the field-by-field comparison. */
  seen: {
    msize: number;
    rootQid: P9QidLike;
    walkQids: P9QidLike[];
    fileQid: P9QidLike;
    dirQid: P9QidLike;
    madeQid: P9QidLike;
    subQid: P9QidLike;
    linkQid: P9QidLike;
    valid: bigint;
    mode: number;
    size: bigint;
    nlink: bigint;
    uid: number;
    gid: number;
    blksize: bigint;
    blocks: bigint;
    afterSetattr: { atime: TimeLike; mtime: TimeLike; uid: number; gid: number };
    modeAfter: number;
    direntBlock: Uint8Array;
    direntCount: number;
    lockStatus: number;
    statfs: Rstatfs;
    enoent: number;
  };
}

interface P9QidLike {
  type: number;
  version: number;
  path: bigint;
}

interface TimeLike {
  sec: bigint;
  nsec: bigint;
}

/**
 * Where a message is cut into two TCP segments, by message name.
 *
 * `Tattach` is cut at three bytes — inside its own `size` field — and the
 * client really does write it in two pieces, so our assembler and the
 * dissector face the same stream. The `Rgetattr` cuts — every one of them, the
 * rule being by name rather than by occurrence — are made in the capture only:
 * the server wrote each reply in one call, and a network would have been free
 * to split it anywhere, which is the whole point of asking a dissector to
 * reassemble rather than trusting delivery boundaries.
 */
const CUTS = new Map<string, number>([
  ["Tattach", 3],
  ["Rgetattr", 40],
]);

/** Run the scripted exchange, recording every message in order. */
async function exchange(): Promise<Exchange> {
  const memory = createMemoryDriver();
  await memory.mkdir("/dir");
  const seed = await memory.open("/dir/hello.txt", "w", 0o644);
  const hello = new TextEncoder().encode(HELLO);
  await seed.write(hello, 0, hello.byteLength, 0);
  await seed.close();

  // Everything the memory driver does, except `statfs`, which answers with
  // {@link STATFS} so no two fields of the reply hold the same number.
  const driver: FsDriver = {
    ...memory,
    statfs: async (): Promise<StatsFsLike> => STATFS,
  };

  const [ours, theirs] = duplexPair();
  const server = createP9Server(driver);
  const connection = server.attach(theirs, { own: false });

  const messages: Recorded[] = [];
  const record = (from: "client" | "server", bytes: Uint8Array): void => {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const type = view.getUint8(4);
    messages.push({ from, name: messageName(type), type, tag: view.getUint16(5, true), bytes });
  };

  const ready: Uint8Array[] = [];
  let waiting: ((frame: Uint8Array) => void) | undefined;
  const assembler = new P9FrameAssembler();
  ours.on("data", (chunk: Buffer) => {
    for (const frame of assembler.push(chunk)) {
      record("server", frame);
      const pending = waiting;
      if (pending === undefined) {
        ready.push(frame);
      } else {
        waiting = undefined;
        pending(frame);
      }
    }
  });

  const transport: P9Transport = async (request) => {
    record("client", request);
    // The same rule `deliveriesOf()` applies when it builds the capture, so
    // what the server's assembler saw and what `tshark` is asked to reassemble
    // are the same stream, however many messages of a name the script sends.
    for (const piece of piecesOf(messages.at(-1)!)) {
      ours.write(piece);
    }
    return await new Promise<Uint8Array>((resolve) => {
      const frame = ready.shift();
      if (frame === undefined) {
        waiting = resolve;
      } else {
        resolve(frame);
      }
    });
  };

  const client = new P9Client(transport);
  const version = await client.version();
  const rootQid = await client.attach(ROOT_FID, {
    uname: "dissect",
    aname: "",
    nUname: 4242,
  });

  // A two-element walk, then everything a reader does with what it found.
  const walkQids = await client.walk(ROOT_FID, FILE_FID, ["dir", HELLO_NAME]);
  const attr = await client.getattr(FILE_FID, P9_GETATTR_ALL);
  await client.lopen(FILE_FID, O_RDONLY);
  const read = await client.read(FILE_FID, 0n, 64);
  await client.clunk(FILE_FID);

  // The directory: open it as one, and page it once.
  const dirQids = await client.walk(ROOT_FID, DIR_FID, ["dir"]);
  await client.lopen(DIR_FID, O_RDONLY | O_DIRECTORY);
  const dirents = await client.readdir(DIR_FID, 0n, 512);

  // Create, write across a segment boundary, sync, and change every attribute.
  await client.walk(ROOT_FID, MADE_FID, ["dir"]);
  const made = await client.lcreate(MADE_FID, "made.txt", {
    flags: O_RDWR | O_CREAT | O_EXCL,
    mode: 0o644,
    gid: 7,
  });
  const written = await client.write(MADE_FID, 0n, PAYLOAD);
  await client.fsync(MADE_FID, 1);
  await client.setattr(MADE_FID, {
    valid:
      P9_SETATTR_MODE |
      P9_SETATTR_UID |
      P9_SETATTR_GID |
      P9_SETATTR_SIZE |
      P9_SETATTR_ATIME |
      P9_SETATTR_ATIME_SET |
      P9_SETATTR_MTIME |
      P9_SETATTR_MTIME_SET,
    ...SETATTR,
  });
  const after = await client.getattr(MADE_FID, P9_GETATTR_BASIC);

  // Locks, and a flush of a tag nobody used.
  const lockStatus = await client.lock(MADE_FID, LOCK);
  await client.getlock(MADE_FID, {
    type: LOCK.type,
    start: LOCK.start,
    length: LOCK.length,
    procId: LOCK.procId,
    clientId: LOCK.clientId,
  });
  await client.flush(UNKNOWN_TAG);

  // The rest of the namespace.
  const subQid = await client.mkdir(ROOT_FID, "sub", 0o750, 11);
  const linkQid = await client.symlink(ROOT_FID, "link", "dir/hello.txt", 13);
  await client.walk(ROOT_FID, LINK_FID, ["link"]);
  await client.readlink(LINK_FID);
  await client.link(ROOT_FID, MADE_FID, "hard.txt");
  await client.renameat(DIR_FID, "made.txt", ROOT_FID, "moved.txt");
  await client.unlinkat(ROOT_FID, "moved.txt", 0);
  await client.unlinkat(ROOT_FID, "hard.txt", 0);
  await client.walk(ROOT_FID, SUB_FID, ["sub"]);
  await client.remove(SUB_FID);
  const statfs = await client.statfs(ROOT_FID);

  // One error, and one that has to be the driver's: `nope.txt` is not there.
  const enoent = await client.expectError(P9_TWALK, (writer) => {
    writer.u32(ROOT_FID);
    writer.u32(DOOMED_FID);
    writer.u16(1);
    writer.string("nope.txt");
  });

  await client.clunk(DIR_FID);
  await client.clunk(MADE_FID);
  await client.clunk(LINK_FID);
  await client.clunk(ROOT_FID);

  await server.close();
  await connection.closed;
  ours.destroy();

  expect(new TextDecoder().decode(read)).toBe(HELLO);
  expect(written).toBe(PAYLOAD.byteLength);
  expect(version.version).toBe(P9_VERSION_DOTL);

  return {
    messages,
    seen: {
      msize: version.msize,
      rootQid,
      walkQids,
      fileQid: walkQids[1]!,
      dirQid: dirQids[0]!,
      madeQid: made.qid,
      subQid,
      linkQid,
      valid: attr.valid,
      mode: attr.mode,
      size: attr.size,
      nlink: attr.nlink,
      uid: attr.uid,
      gid: attr.gid,
      blksize: attr.blksize,
      blocks: attr.blocks,
      afterSetattr: { atime: after.atime, mtime: after.mtime, uid: after.uid, gid: after.gid },
      modeAfter: after.mode,
      direntBlock: direntBlockOf(messages),
      direntCount: dirents.length,
      lockStatus,
      statfs,
      enoent,
    },
  };
}

/** The packed dirent block the one `Rreaddir` carried, straight off the wire. */
function direntBlockOf(messages: readonly Recorded[]): Uint8Array {
  const reply = messages.find((message) => message.name === "Rreaddir");
  if (reply === undefined) {
    throw new Error("the exchange did not produce an Rreaddir");
  }
  // size[4] type[1] tag[2] count[4], then the entries.
  return reply.bytes.slice(11);
}

/**
 * One message as the pieces it is sent in: whole, or cut per {@link CUTS}.
 *
 * The one rule, used both by the transport (which really writes these pieces)
 * and by {@link deliveriesOf} (which turns them into segments) — the capture
 * cannot describe a stream the server never saw if there is only one rule.
 */
function piecesOf(message: Recorded): Uint8Array[] {
  const at = CUTS.get(message.name);
  if (at === undefined || at >= message.bytes.byteLength) {
    return [message.bytes];
  }
  return [message.bytes.subarray(0, at), message.bytes.subarray(at)];
}

/** The bytes of each TCP segment, in order, with {@link CUTS} applied. */
function deliveriesOf(messages: readonly Recorded[]): P9Delivery[] {
  return messages.flatMap((message) =>
    piecesOf(message).map((bytes) => ({ from: message.from, bytes })),
  );
}

// ---------------------------------------------------------------------------
// tshark
// ---------------------------------------------------------------------------

/** The version string, or `undefined` when there is no `tshark` to ask. */
function tsharkVersion(): string | undefined {
  try {
    const probe = spawnSync("tshark", ["-v"], { encoding: "utf8", timeout: 30_000 });
    if (probe.error !== undefined || probe.status !== 0) {
      return undefined;
    }
    return probe.stdout.split("\n", 1)[0]?.trim();
  } catch {
    return undefined;
  }
}

const version = tsharkVersion();
const missing =
  version === undefined ? " [skipped: tshark is not on PATH — install wireshark-cli]" : "";

/** Run `tshark` over the capture, or throw with whatever it complained about. */
function tshark(pcap: string, ...args: string[]): string {
  const run = spawnSync(
    "tshark",
    [
      "-r",
      pcap,
      // No name resolution: nothing here should reach a resolver, and a capture
      // full of documentation addresses is exactly what would make it try.
      "-n",
      // Belt and braces. Port 564 already carries this dissector by default
      // (`tshark -G decodes` lists it), so this only pins what a preference
      // could otherwise move.
      "-d",
      `tcp.port==${P9_TCP_PORT},9p`,
      ...args,
    ],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 120_000 },
  );
  if (run.error !== undefined) {
    throw run.error;
  }
  if (run.status !== 0) {
    throw new Error(`tshark exited ${run.status}: ${run.stderr}`);
  }
  return run.stdout;
}

/** A dissected field tree: strings at the leaves, subtrees in between. */
type Tree = { [key: string]: string | string[] | Tree | Tree[] };

/** One dissected 9P message, and the frame it came out of. */
interface Dissected {
  frame: number;
  name: string;
  type: number;
  tag: number;
  fields: Tree;
  /** The `data` layer of the same frame — a payload the dissector left alone. */
  payload: string | undefined;
}

/** A single string field, insisted upon. */
function text(fields: Tree, key: string): string {
  const value = fields[key];
  if (typeof value !== "string") {
    throw new Error(`${key} is ${JSON.stringify(value)}, not a string`);
  }
  return value;
}

/** A field that may appear once or many times, always as an array. */
function texts(fields: Tree, key: string): string[] {
  const value = fields[key];
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value) && value.every((one) => typeof one === "string")) {
    return value as string[];
  }
  throw new Error(`${key} is ${JSON.stringify(value)}, not a string or list of them`);
}

/**
 * The qids in a message, in order.
 *
 * The dissector puts each one in a subtree whose *key* is its own summary
 * (`Qid type=0x80 vers=… path=1`), so they are found by shape rather than by
 * name. Object key order is insertion order, which is wire order.
 */
function qids(fields: Tree): P9QidLike[] {
  const found: P9QidLike[] = [];
  for (const [key, value] of Object.entries(fields)) {
    if (!key.startsWith("Qid ")) {
      continue;
    }
    for (const tree of Array.isArray(value) ? value : [value]) {
      const qid = tree as Tree;
      found.push({
        type: Number(text(qid, "9p.qidtype")),
        version: Number(text(qid, "9p.qidvers")),
        path: BigInt(text(qid, "9p.qidpath")),
      });
    }
  }
  return found;
}

/** Our bytes in the dissector's `aa:bb` spelling, for a readable diff. */
function hexOf(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join(":");
}

/**
 * An absolute time as the dissector renders it, back to `sec`/`nsec`.
 *
 * The format is `2026-07-29T04:01:09.205000000Z` — ISO 8601 with nine
 * fractional digits, which is more than `Date.parse` is required to accept, so
 * the seconds and the nanoseconds are split apart first.
 */
function timeOf(rendered: string): TimeLike {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{9})Z$/.exec(rendered);
  const when = match?.[1];
  const nsec = match?.[2];
  if (when === undefined || nsec === undefined) {
    throw new Error(`${rendered} is not a time this test knows how to read`);
  }
  const seconds = Date.parse(`${when}Z`);
  if (Number.isNaN(seconds)) {
    throw new Error(`${rendered} has an unparseable date part`);
  }
  return { sec: BigInt(seconds) / 1000n, nsec: BigInt(nsec) };
}

// ---------------------------------------------------------------------------
// the suite
// ---------------------------------------------------------------------------

describe.skipIf(version === undefined)(`tshark's 9P dissector on our wire${missing}`, () => {
  let directory: string;
  let capture: string;
  let recorded: Exchange;
  let dissected: Dissected[];

  beforeAll(async () => {
    recorded = await exchange();
    directory = await mkdtemp(join(tmpdir(), "mountx-9p-dissect-"));
    capture = join(directory, "exchange.pcap");
    // The ports are named rather than defaulted: 564 is what puts the 9P
    // dissector on this conversation in the first place.
    await writeFile(
      capture,
      buildPcap(deliveriesOf(recorded.messages), {
        clientPort: CLIENT_PORT,
        serverPort: P9_TCP_PORT,
      }),
    );

    const packets = JSON.parse(tshark(capture, "-T", "json", "--no-duplicate-keys")) as {
      _source: { layers: Record<string, unknown> };
    }[];
    dissected = [];
    for (const packet of packets) {
      const layers = packet._source.layers;
      const nine = layers["9p"];
      if (nine === undefined) {
        continue;
      }
      const frame = Number(text(layers["frame"] as Tree, "frame.number"));
      const data = layers["data"] as Tree | undefined;
      for (const one of Array.isArray(nine) ? nine : [nine]) {
        const fields = one as Tree;
        const type = Number(text(fields, "9p.msgtype"));
        dissected.push({
          frame,
          name: messageName(type),
          type,
          tag: Number(text(fields, "9p.tag")),
          fields,
          payload: data === undefined ? undefined : text(data, "data.data"),
        });
      }
    }
  }, 120_000);

  afterAll(async () => {
    if (directory !== undefined) {
      await rm(directory, { recursive: true, force: true });
    }
  });

  /** The one dissected message of a kind, or the `nth` of several. */
  const only = (name: string, nth = 0): Dissected => {
    const found = dissected.filter((message) => message.name === name);
    const one = found[nth];
    if (one === undefined) {
      throw new Error(`no ${name} #${nth} among ${found.length} of them`);
    }
    return one;
  };

  /** The same message as we recorded it, for the tag comparison. */
  const ours = (name: string, nth = 0): Recorded => {
    const found = recorded.messages.filter((message) => message.name === name);
    const one = found[nth];
    if (one === undefined) {
      throw new Error(`we never sent a ${name} #${nth}`);
    }
    return one;
  };

  describe("the conversation", () => {
    it("dissects as the exact sequence of messages the script sent", () => {
      // The literal is the point: it says what this oracle covers, and a
      // message quietly dropped from the script would change it.
      expect(dissected.map((message) => message.name)).toEqual([
        "Tversion",
        "Rversion",
        "Tattach",
        "Rattach",
        "Twalk",
        "Rwalk",
        "Tgetattr",
        "Rgetattr",
        "Tlopen",
        "Rlopen",
        "Tread",
        "Rread",
        "Tclunk",
        "Rclunk",
        "Twalk",
        "Rwalk",
        "Tlopen",
        "Rlopen",
        "Treaddir",
        "Rreaddir",
        "Twalk",
        "Rwalk",
        "Tlcreate",
        "Rlcreate",
        "Twrite",
        "Rwrite",
        "Tfsync",
        "Rfsync",
        "Tsetattr",
        "Rsetattr",
        "Tgetattr",
        "Rgetattr",
        "Tlock",
        "Rlock",
        "Tgetlock",
        "Rgetlock",
        "Tflush",
        "Rflush",
        "Tmkdir",
        "Rmkdir",
        "Tsymlink",
        "Rsymlink",
        "Twalk",
        "Rwalk",
        "Treadlink",
        "Rreadlink",
        "Tlink",
        "Rlink",
        "Trenameat",
        "Rrenameat",
        "Tunlinkat",
        "Runlinkat",
        "Tunlinkat",
        "Runlinkat",
        "Twalk",
        "Rwalk",
        "Tremove",
        "Rremove",
        "Tstatfs",
        "Rstatfs",
        "Twalk",
        "Rlerror",
        "Tclunk",
        "Rclunk",
        "Tclunk",
        "Rclunk",
        "Tclunk",
        "Rclunk",
        "Tclunk",
        "Rclunk",
      ]);
    });

    it("agrees with our own reading of every header, message for message", () => {
      expect(dissected.map((message) => [message.type, message.tag])).toEqual(
        recorded.messages.map((message) => [message.type, message.tag]),
      );
    });

    it("dissects 9P because the conversation is the one 9P is registered on", () => {
      // Why any of this works with no `-d` needed: `tshark -G decodes` lists
      // `tcp.port 564 -> 9p`, so the ports the capture was built with are what
      // put this dissector on it. Every 9P message is between those two ports
      // and no others.
      const ports = new Set(
        tshark(capture, "-T", "fields", "-e", "tcp.srcport", "-e", "tcp.dstport", "-Y", "9p")
          .trim()
          .split(/[\t\n]/)
          .map(Number),
      );
      expect([...ports].sort((a, b) => a - b)).toEqual([P9_TCP_PORT, CLIENT_PORT]);
    });

    it("pairs every request with a reply of the next type up, on the same tag", () => {
      // The exchange is strictly request-then-reply, so the pairs are adjacent.
      // T-messages are even and their replies are the odd number above them
      // (`Tversion` 100 / `Rversion` 101), with `Rlerror` standing in for any
      // of them — which is the whole of 9P2000.L's error convention.
      const wrong: string[] = [];
      for (let at = 0; at < dissected.length; at += 2) {
        const request = dissected[at]!;
        const reply = dissected[at + 1]!;
        const answered = reply.type === request.type + 1 || reply.name === "Rlerror";
        if (request.type % 2 !== 0 || !answered || reply.tag !== request.tag) {
          wrong.push(`${request.name}#${request.tag} answered ${reply.name}#${reply.tag}`);
        }
      }
      expect(wrong).toEqual([]);
      expect(dissected.length % 2).toBe(0);
    });
  });

  describe("field agreement", () => {
    it("Tversion and Rversion: the msize and the version string", () => {
      const request = only("Tversion");
      expect(request.tag).toBe(P9_NOTAG);
      expect(Number(text(request.fields, "9p.maxsize"))).toBe(CLIENT_MSIZE);
      expect(text(request.fields, "9p.version")).toBe(P9_VERSION_DOTL);

      const reply = only("Rversion");
      expect(reply.tag).toBe(P9_NOTAG);
      expect(Number(text(reply.fields, "9p.maxsize"))).toBe(recorded.seen.msize);
      expect(text(reply.fields, "9p.version")).toBe(P9_VERSION_DOTL);
    });

    it("Tattach and Rattach: fid, afid, uname, n_uname, and the root qid", () => {
      const request = only("Tattach");
      expect(Number(text(request.fields, "9p.fid"))).toBe(ROOT_FID);
      expect(Number(text(request.fields, "9p.afid"))).toBe(P9_NOFID);
      expect(text(request.fields, "9p.uname")).toBe("dissect");
      expect(text(request.fields, "9p.aname")).toBe("");
      // The dissector calls `n_uname` `9p.uid`, which is what it is.
      expect(Number(text(request.fields, "9p.uid"))).toBe(4242);

      const root = qids(only("Rattach").fields);
      expect(root).toEqual([recorded.seen.rootQid]);
      expect(root[0]!.type).toBe(P9_QTDIR);
    });

    it("Twalk and Rwalk: the names going out and the qids coming back", () => {
      const request = only("Twalk");
      expect(Number(text(request.fields, "9p.fid"))).toBe(ROOT_FID);
      expect(Number(text(request.fields, "9p.newfid"))).toBe(FILE_FID);
      expect(Number(text(request.fields, "9p.nwalk"))).toBe(2);
      expect(texts(request.fields, "9p.wname")).toEqual(["dir", HELLO_NAME]);

      const reply = only("Rwalk");
      expect(Number(text(reply.fields, "9p.nqid"))).toBe(2);
      expect(qids(reply.fields)).toEqual(recorded.seen.walkQids);
      expect(qids(reply.fields).map((qid) => qid.type)).toEqual([P9_QTDIR, P9_QTFILE]);
    });

    it("qid paths are the identities we minted, not the change tokens", () => {
      // Worth stating on its own, because a dissector cannot catch a qid whose
      // `version` and `path` have swapped places: both are read positionally,
      // so a server that put the change token in `path` would still "agree"
      // with `tshark` field for field. What gives it away is the *values* —
      // `src/9p/fids.ts` mints `path` from its own counter in first-seen
      // order, and `version` is a change token derived from the file's times.
      const pathsOf = (name: string, nth = 0): bigint[] =>
        qids(only(name, nth).fields).map((qid) => qid.path);
      expect(pathsOf("Rattach")).toEqual([1n]);
      expect(pathsOf("Rwalk")).toEqual([2n, 3n]);
      expect(pathsOf("Rlcreate")).toEqual([4n]);
      expect(pathsOf("Rmkdir")).toEqual([5n]);
      expect(pathsOf("Rsymlink")).toEqual([6n]);

      // One file, three messages, one qid — identity is what `path` carries,
      // and v9fs turns it straight into `st_ino` (`QID2INO`).
      const file = qids(only("Rwalk").fields)[1]!;
      expect(file.path).toBe(3n);
      expect(qids(only("Rgetattr").fields)).toEqual([file]);
      expect(qids(only("Rlopen").fields)).toEqual([file]);
    });

    it("Tgetattr and Rgetattr: the 64-bit masks and every attribute", () => {
      const request = only("Tgetattr");
      expect(Number(text(request.fields, "9p.fid"))).toBe(FILE_FID);
      expect(BigInt(text(request.fields, "9p.getattr.flags"))).toBe(P9_GETATTR_ALL);

      const reply = only("Rgetattr");
      expect(BigInt(text(reply.fields, "9p.getattr.flags"))).toBe(recorded.seen.valid);
      expect(qids(reply.fields)).toEqual([recorded.seen.fileQid]);
      // `9p.statmode` is decimal here whatever its octal display base says.
      expect(Number(text(reply.fields, "9p.statmode"))).toBe(recorded.seen.mode);
      expect(BigInt(text(reply.fields, "9p.size"))).toBe(recorded.seen.size);
      expect(BigInt(text(reply.fields, "9p.nlink"))).toBe(recorded.seen.nlink);
      // This file's owner is whoever runs the test, so `uid` and `gid` are
      // very often the same number here and prove nothing about their order.
      // The pair that does is on the second `Rgetattr`, below, after a
      // `Tsetattr` gave them two values that cannot be confused.
      expect(Number(text(reply.fields, "9p.uid"))).toBe(recorded.seen.uid);
      expect(Number(text(reply.fields, "9p.gid"))).toBe(recorded.seen.gid);
      expect(BigInt(text(reply.fields, "9p.blksize"))).toBe(recorded.seen.blksize);
      expect(BigInt(text(reply.fields, "9p.blocks"))).toBe(recorded.seen.blocks);
      expect(BigInt(text(reply.fields, "9p.rdev"))).toBe(0n);
      expect(BigInt(text(reply.fields, "9p.gen"))).toBe(0n);
      expect(BigInt(text(reply.fields, "9p.dataversion"))).toBe(0n);
      // The size field is what the file holds, and the file holds `HELLO`.
      expect(Number(text(reply.fields, "9p.size"))).toBe(HELLO.length);
    });

    it("Tlopen and Rlopen: the flag word, and the qid of what opened", () => {
      const request = only("Tlopen", 1);
      expect(Number(text(request.fields, "9p.fid"))).toBe(DIR_FID);
      // The dissector spells the `Tlopen` flag word `9p.statmode`, and breaks
      // out the same `O_*` bits underneath it that we put there.
      expect(Number(text(request.fields, "9p.statmode"))).toBe(O_RDONLY | O_DIRECTORY);
      const bits = request.fields["9p.statmode_tree"] as Tree;
      expect(text(bits, "9p.lflags.directory")).toBe("1");
      expect(text(bits, "9p.lflags.create")).toBe("0");

      const reply = only("Rlopen", 1);
      expect(qids(reply.fields)).toEqual([recorded.seen.dirQid]);
      expect(Number(text(reply.fields, "9p.iounit"))).toBe(0);
    });

    it("Tread and Rread: offset, count, and the bytes themselves", () => {
      const request = only("Tread");
      expect(Number(text(request.fields, "9p.fid"))).toBe(FILE_FID);
      expect(BigInt(text(request.fields, "9p.offset"))).toBe(0n);
      expect(Number(text(request.fields, "9p.count"))).toBe(64);

      const reply = only("Rread");
      expect(Number(text(reply.fields, "9p.count"))).toBe(HELLO.length);
      // The payload is left to the `data` dissector, which is as independent a
      // reading of it as anything here.
      expect(reply.payload).toBe(hexOf(new TextEncoder().encode(HELLO)));
    });

    it("Tlcreate and Rlcreate: name, flags, mode and gid", () => {
      const request = only("Tlcreate");
      expect(Number(text(request.fields, "9p.fid"))).toBe(MADE_FID);
      expect(text(request.fields, "9p.filename")).toBe("made.txt");
      expect(Number(text(request.fields, "9p.lcreate.flags"))).toBe(O_RDWR | O_CREAT | O_EXCL);
      const bits = request.fields["9p.lcreate.flags_tree"] as Tree;
      expect(text(bits, "9p.lflags.create")).toBe("1");
      expect(text(bits, "9p.lflags.excl")).toBe("1");
      expect(Number(text(request.fields, "9p.statmode"))).toBe(0o644);
      expect(Number(text(request.fields, "9p.gid"))).toBe(7);

      expect(qids(only("Rlcreate").fields)).toEqual([recorded.seen.madeQid]);
    });

    it("Twrite and Rwrite: the count, and 2100 bytes across two segments", () => {
      const request = only("Twrite");
      expect(Number(text(request.fields, "9p.fid"))).toBe(MADE_FID);
      expect(BigInt(text(request.fields, "9p.offset"))).toBe(0n);
      expect(Number(text(request.fields, "9p.count"))).toBe(PAYLOAD.byteLength);
      expect(request.payload).toBe(hexOf(PAYLOAD));

      expect(Number(text(only("Rwrite").fields, "9p.count"))).toBe(PAYLOAD.byteLength);
    });

    it("Treaddir and Rreaddir: the request, and the packed block byte for byte", () => {
      const request = only("Treaddir");
      expect(Number(text(request.fields, "9p.fid"))).toBe(DIR_FID);
      expect(BigInt(text(request.fields, "9p.offset"))).toBe(0n);
      expect(Number(text(request.fields, "9p.count"))).toBe(512);

      // The dissector counts the block but does not unpack the entries, so
      // this is the field-level check available: the byte count it read, and
      // the bytes it left over, are the block we packed. `.`, `..` and the one
      // file are what a v9fs client would see (`v9fs_dir_readdir_dotl` never
      // calls `dir_emit_dots`, so the server synthesizes both).
      const reply = only("Rreaddir");
      expect(recorded.seen.direntCount).toBe(3);
      expect(Number(text(reply.fields, "9p.count"))).toBe(recorded.seen.direntBlock.byteLength);
      expect(reply.payload).toBe(hexOf(recorded.seen.direntBlock));

      // And since the dissector stops there, the block is unpacked here by
      // hand — `qid[13] offset[8] type[1] name[s]`, straight from the protocol
      // document, with a `DataView` rather than `src/9p/protocol.ts`, so a
      // packer that agreed only with its own unpacker would show up.
      const block = recorded.seen.direntBlock;
      const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
      const entries: unknown[] = [];
      let at = 0;
      while (at < block.byteLength) {
        const length = view.getUint16(at + 22, true);
        entries.push({
          qidType: view.getUint8(at),
          qidPath: view.getBigUint64(at + 5, true),
          offset: view.getBigUint64(at + 13, true),
          type: view.getUint8(at + 21),
          name: new TextDecoder().decode(block.subarray(at + 24, at + 24 + length)),
        });
        at += 24 + length;
      }
      expect(at).toBe(block.byteLength);
      expect(entries).toEqual([
        { qidType: P9_QTDIR, qidPath: 2n, offset: 1n, type: DT_DIR, name: "." },
        { qidType: P9_QTDIR, qidPath: 1n, offset: 2n, type: DT_DIR, name: ".." },
        { qidType: P9_QTFILE, qidPath: 3n, offset: 3n, type: DT_REG, name: HELLO_NAME },
      ]);
    });

    it("Tfsync: the fid, and the datasync flag the dissector leaves as bytes", () => {
      const request = only("Tfsync");
      expect(Number(text(request.fields, "9p.fid"))).toBe(MADE_FID);
      // No `9p.fsync.datasync` field exists; the four bytes fall through to
      // `9p.message_data`, which still pins where we put them.
      expect(text(request.fields, "9p.message_data")).toBe("01:00:00:00");
    });

    it("Tsetattr: the mask, and every field it turned on", () => {
      const request = only("Tsetattr");
      expect(Number(text(request.fields, "9p.fid"))).toBe(MADE_FID);
      expect(Number(text(request.fields, "9p.setattr.flags"))).toBe(
        P9_SETATTR_MODE |
          P9_SETATTR_UID |
          P9_SETATTR_GID |
          P9_SETATTR_SIZE |
          P9_SETATTR_ATIME |
          P9_SETATTR_ATIME_SET |
          P9_SETATTR_MTIME |
          P9_SETATTR_MTIME_SET,
      );
      expect(Number(text(request.fields, "9p.statmode"))).toBe(SETATTR.mode);
      expect(Number(text(request.fields, "9p.uid"))).toBe(SETATTR.uid);
      expect(Number(text(request.fields, "9p.gid"))).toBe(SETATTR.gid);
      expect(BigInt(text(request.fields, "9p.size"))).toBe(SETATTR.size);
      // Both halves of both `sec[8] nsec[8]` pairs, read back out of a rendered
      // timestamp — the one field pair where a swapped 64-bit write would
      // otherwise look plausible.
      expect(timeOf(text(request.fields, "9p.atime"))).toEqual(SETATTR.atime);
      expect(timeOf(text(request.fields, "9p.mtime"))).toEqual(SETATTR.mtime);
    });

    it("Rgetattr after Tsetattr: the owner and the times the server kept", () => {
      const reply = only("Rgetattr", 1);
      // The one place the oracle sees a distinct owner pair, and so the one
      // place a `uid`/`gid` transposition anywhere in the `Rgetattr` encoder
      // has to show itself. They are literals, not what our client decoded.
      expect(Number(text(reply.fields, "9p.uid"))).toBe(SETATTR.uid);
      expect(Number(text(reply.fields, "9p.gid"))).toBe(SETATTR.gid);
      expect(recorded.seen.afterSetattr.uid).toBe(SETATTR.uid);
      expect(recorded.seen.afterSetattr.gid).toBe(SETATTR.gid);
      expect(timeOf(text(reply.fields, "9p.atime"))).toEqual(recorded.seen.afterSetattr.atime);
      expect(timeOf(text(reply.fields, "9p.mtime"))).toEqual(recorded.seen.afterSetattr.mtime);
      // The permission bits are the ones `Tsetattr` asked for; the file type
      // above them is the server's, and `Tsetattr` has no business changing it.
      expect(Number(text(reply.fields, "9p.statmode")) & 0o7777).toBe(SETATTR.mode);
      expect(Number(text(reply.fields, "9p.statmode"))).toBe(recorded.seen.modeAfter);
      expect(BigInt(text(reply.fields, "9p.size"))).toBe(SETATTR.size);
    });

    it("Tlock and Rlock: six distinct fields and a status", () => {
      const request = only("Tlock");
      expect(Number(text(request.fields, "9p.fid"))).toBe(MADE_FID);
      expect(Number(text(request.fields, "9p.lock.type"))).toBe(LOCK.type);
      expect(Number(text(request.fields, "9p.lock.flag"))).toBe(LOCK.flags);
      expect(BigInt(text(request.fields, "9p.lock.start"))).toBe(LOCK.start);
      expect(BigInt(text(request.fields, "9p.lock.length"))).toBe(LOCK.length);
      expect(Number(text(request.fields, "9p.lock.procid"))).toBe(LOCK.procId);
      // The dissector reuses `9p.wname` for the client id string.
      expect(texts(request.fields, "9p.wname")).toEqual([LOCK.clientId]);

      expect(Number(text(only("Rlock").fields, "9p.lock.status"))).toBe(P9_LOCK_SUCCESS);
      expect(recorded.seen.lockStatus).toBe(P9_LOCK_SUCCESS);
    });

    it("Tflush and Rflush: the old tag, and an empty reply", () => {
      const request = only("Tflush");
      expect(Number(text(request.fields, "9p.oldtag"))).toBe(UNKNOWN_TAG);
      expect(Number(text(only("Rflush").fields, "9p.msglen"))).toBe(7);
    });

    it("Tmkdir and Tsymlink: name, mode, target and gid", () => {
      const mkdir = only("Tmkdir");
      expect(Number(text(mkdir.fields, "9p.fid"))).toBe(ROOT_FID);
      expect(texts(mkdir.fields, "9p.wname")).toEqual(["sub"]);
      expect(Number(text(mkdir.fields, "9p.statmode"))).toBe(0o750);
      expect(Number(text(mkdir.fields, "9p.gid"))).toBe(11);
      expect(qids(only("Rmkdir").fields)).toEqual([recorded.seen.subQid]);

      const symlink = only("Tsymlink");
      expect(Number(text(symlink.fields, "9p.fid"))).toBe(ROOT_FID);
      expect(texts(symlink.fields, "9p.wname")).toEqual(["link", "dir/hello.txt"]);
      expect(Number(text(symlink.fields, "9p.gid"))).toBe(13);
      const made = qids(only("Rsymlink").fields);
      expect(made).toEqual([recorded.seen.linkQid]);
      expect(made[0]!.type).toBe(P9_QTSYMLINK);
    });

    it("Treadlink and Rreadlink: the fid, and the target that comes back", () => {
      expect(Number(text(only("Treadlink").fields, "9p.fid"))).toBe(LINK_FID);
      expect(texts(only("Rreadlink").fields, "9p.wname")).toEqual(["dir/hello.txt"]);
    });

    it("Tlink, Trenameat and Tunlinkat: two fids and the names between them", () => {
      const link = only("Tlink");
      expect(Number(text(link.fields, "9p.dfid"))).toBe(ROOT_FID);
      expect(Number(text(link.fields, "9p.fid"))).toBe(MADE_FID);
      expect(texts(link.fields, "9p.wname")).toEqual(["hard.txt"]);

      const rename = only("Trenameat");
      expect(Number(text(rename.fields, "9p.dfid"))).toBe(DIR_FID);
      expect(Number(text(rename.fields, "9p.newfid"))).toBe(ROOT_FID);
      expect(texts(rename.fields, "9p.wname")).toEqual(["made.txt", "moved.txt"]);

      const unlink = only("Tunlinkat");
      expect(Number(text(unlink.fields, "9p.dfid"))).toBe(ROOT_FID);
      expect(texts(unlink.fields, "9p.wname")).toEqual(["moved.txt"]);
      // Nothing here removes a directory, so `AT_REMOVEDIR` stays off — the
      // `sub` directory goes through `Tremove` instead.
      expect(Number(text(unlink.fields, "9p.unlinkat.flags"))).toBe(0);
    });

    it("Tremove and Tstatfs: the fid, and all nine fields of the filesystem", () => {
      expect(Number(text(only("Tremove").fields, "9p.fid"))).toBe(SUB_FID);

      expect(Number(text(only("Tstatfs").fields, "9p.fid"))).toBe(ROOT_FID);
      const reply = only("Rstatfs").fields;
      // Nine distinct numbers, nine literal assertions — `Rstatfs` is five
      // consecutive 64-bit counters, and nothing but distinct values can tell
      // a correct encoder from one that swapped a pair of them.
      expect({
        type: Number(text(reply, "9p.fstype")),
        bsize: Number(text(reply, "9p.blksize")),
        blocks: BigInt(text(reply, "9p.blocks")),
        bfree: BigInt(text(reply, "9p.bfree")),
        bavail: BigInt(text(reply, "9p.bavail")),
        files: BigInt(text(reply, "9p.files")),
        ffree: BigInt(text(reply, "9p.ffree")),
        fsid: BigInt(text(reply, "9p.fsid")),
        namelen: Number(text(reply, "9p.namelen")),
      }).toEqual({
        type: STATFS.type,
        bsize: STATFS.bsize,
        blocks: BigInt(STATFS.blocks),
        bfree: BigInt(STATFS.bfree),
        bavail: BigInt(STATFS.bavail),
        files: BigInt(STATFS.files),
        ffree: BigInt(STATFS.ffree),
        fsid: STATFS_FSID,
        namelen: STATFS_NAMELEN,
      });
      // And our own client read the same reply the same way.
      expect(recorded.seen.statfs).toEqual({
        type: STATFS.type,
        bsize: STATFS.bsize,
        blocks: BigInt(STATFS.blocks),
        bfree: BigInt(STATFS.bfree),
        bavail: BigInt(STATFS.bavail),
        files: BigInt(STATFS.files),
        ffree: BigInt(STATFS.ffree),
        fsid: STATFS_FSID,
        namelen: STATFS_NAMELEN,
      });
    });

    it("Rlerror: the errno our driver threw, where the wire says it goes", () => {
      // The sixth `Twalk`: the five before it all found what they asked for.
      const failed = only("Twalk", 5);
      expect(texts(failed.fields, "9p.wname")).toEqual(["nope.txt"]);
      expect(Number(text(failed.fields, "9p.newfid"))).toBe(DOOMED_FID);

      // 9P2000.L's `Rlerror` body is one `ecode[4]`, and this dissector has no
      // field for it — the four bytes fall through to `9p.message_data`. That
      // still pins the number and its byte order, which is the whole message.
      const reply = only("Rlerror");
      expect(recorded.seen.enoent).toBe(ERRNO_CODES.ENOENT);
      expect(text(reply.fields, "9p.message_data")).toBe(
        hexOf(Uint8Array.of(ERRNO_CODES.ENOENT, 0, 0, 0)),
      );
      expect(Number(text(reply.fields, "9p.msglen"))).toBe(11);
    });
  });

  describe("reassembly", () => {
    /** The frames a message was rebuilt from, per `tcp.segments`. */
    const segmentsOf = (name: string): string[] => {
      const fields = tshark(
        capture,
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "9p.msgtype",
        "-e",
        "tcp.segment",
        "-e",
        "tcp.reassembled.length",
        "-E",
        "occurrence=a",
        "-Y",
        "9p",
      );
      const wanted = only(name);
      for (const line of fields.trim().split("\n")) {
        const [frame, , segments, length] = line.split("\t");
        if (Number(frame) === wanted.frame) {
          return [segments ?? "", length ?? ""];
        }
      }
      throw new Error(`frame ${wanted.frame} is not in the field output`);
    };

    it("rebuilds a Twrite that spans two TCP segments", () => {
      const [segments, length] = segmentsOf("Twrite");
      expect(segments?.split(",").length).toBe(2);
      // header[7] + fid[4] + offset[8] + count[4] + the payload.
      expect(Number(length)).toBe(7 + 4 + 8 + 4 + PAYLOAD.byteLength);
    });

    it("rebuilds a Tattach cut inside its own size field", () => {
      const [segments, length] = segmentsOf("Tattach");
      expect(segments?.split(",").length).toBe(2);
      expect(Number(length)).toBe(ours("Tattach").bytes.byteLength);
    });

    it("rebuilds an Rgetattr cut mid-body", () => {
      const [segments, length] = segmentsOf("Rgetattr");
      expect(segments?.split(",").length).toBe(2);
      expect(Number(length)).toBe(ours("Rgetattr").bytes.byteLength);
    });
  });

  describe("the dissector's own complaints", () => {
    /** Frame numbers `tshark` flagged at warning severity or worse. */
    const complaints = (): { frame: number; message: string }[] => {
      // PI_WARN is 0x00600000 and PI_ERROR 0x00800000; below that are the
      // chat/note items a healthy TCP conversation produces (SYN, FIN).
      const out = tshark(
        capture,
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "_ws.expert.message",
        "-E",
        "occurrence=a",
        "-Y",
        "_ws.expert.severity >= 0x00600000",
      );
      return out
        .trim()
        .split("\n")
        .filter((line) => line.length > 0)
        .map((line) => {
          const [frame, message] = line.split("\t");
          return { frame: Number(frame), message: message ?? "" };
        });
    };

    it("finds nothing wrong with anything but the two getlock messages", () => {
      const flagged = complaints();
      const getlock = new Set(
        dissected
          .filter((message) => message.name === "Tgetlock" || message.name === "Rgetlock")
          .map((message) => message.frame),
      );
      expect(getlock.size).toBe(2);
      // A subset check, not an equality: this passes unchanged the day
      // Wireshark fixes the defect the next test describes.
      expect(flagged.filter((one) => !getlock.has(one.frame))).toEqual([]);

      // And while that defect is present, those two frames really are flagged
      // — which is what keeps the check above from passing merely because the
      // filter stopped matching anything.
      if (only("Tgetlock").fields["9p.lock.flag"] !== undefined) {
        expect(flagged.map((one) => one.frame).sort((a, b) => a - b)).toEqual(
          [...getlock].sort((a, b) => a - b),
        );
        expect(flagged.map((one) => one.message.includes("Malformed"))).toEqual([true, true]);
      }
    });

    it("leaves no message undissected: every frame with 9P bytes has a message", () => {
      // 70 messages, and the dissector found all of them — which also says no
      // frame was silently swallowed by the reassembler.
      expect(dissected.length).toBe(recorded.messages.length);
      expect(new Set(dissected.map((message) => message.frame)).size).toBe(dissected.length);
    });
  });

  describe("the one disagreement: Wireshark's Tgetlock/Rgetlock", () => {
    /**
     * Wireshark reads a `flags[4]` field in `Tgetlock`/`Rgetlock` that the
     * protocol does not have. The authority is the kernel: `struct p9_flock`
     * has `type`, `flags`, `start`, `length`, `proc_id`, `client_id` and
     * `struct p9_getlock` has the same list *without* `flags`
     * (`include/net/9p/9p.h`, v6.12), which is exactly what the format strings
     * `"dbdqqds"` (`p9_client_lock_dotl`) and `"dbqqds"`
     * (`p9_client_getlock_dotl`) in `net/9p/client.c` encode. `src/9p/
     * protocol.ts` follows the kernel, and says so where the two codecs sit
     * next to each other.
     *
     * The consequence is arithmetic: everything after `type` is read four
     * bytes early, and the dissector runs off the end of the message and marks
     * it malformed. This test proves that reading rather than asserting "it is
     * broken" — it recomputes what a four-byte-late cursor would report and
     * insists that is what came out. If Wireshark ever fixes it, the `else`
     * branch takes over and demands agreement with our values instead.
     *
     * Observed with TShark 4.6.7 (Git commit b439fb7b47a9).
     */
    it("is a phantom four-byte flags field, and nothing more", () => {
      const request = only("Tgetlock");
      const body = ours("Tgetlock").bytes.subarray(7);
      const view = new DataView(body.buffer, body.byteOffset, body.byteLength);

      expect(Number(text(request.fields, "9p.fid"))).toBe(MADE_FID);
      expect(Number(text(request.fields, "9p.lock.type"))).toBe(LOCK.type);

      if (request.fields["9p.lock.flag"] === undefined) {
        // Fixed upstream: then it must agree with us field for field.
        expect(BigInt(text(request.fields, "9p.lock.start"))).toBe(LOCK.start);
        expect(BigInt(text(request.fields, "9p.lock.length"))).toBe(LOCK.length);
        expect(Number(text(request.fields, "9p.lock.procid"))).toBe(LOCK.procId);
        return;
      }

      // Still broken: fid[4] type[1], then a four-byte field that is really
      // the first half of `start`, and every field after it four bytes early.
      expect(Number(text(request.fields, "9p.lock.flag"))).toBe(view.getUint32(5, true));
      expect(BigInt(text(request.fields, "9p.lock.start"))).toBe(view.getBigUint64(9, true));
      expect(BigInt(text(request.fields, "9p.lock.length"))).toBe(view.getBigUint64(17, true));
      expect(Number(text(request.fields, "9p.lock.procid"))).toBe(view.getUint32(25, true));
      // The last of those four-byte reads lands inside the client id string,
      // which is how far past the truth it has drifted by the end.
      expect(view.getUint32(25, true)).not.toBe(LOCK.procId);
    });

    it("costs the Rgetlock nothing we cannot check ourselves", () => {
      // What the dissector cannot be asked about is pinned a layer down:
      // `test/9p/golden.test.ts` holds both messages' bytes to the byte,
      // including the four-byte difference between them that Wireshark
      // misses. What is left here is the reply's meaning — unlocked, because
      // this server grants every lock and reports no conflict.
      const reply = only("Rgetlock");
      expect(Number(text(reply.fields, "9p.lock.type"))).toBe(P9_LOCK_TYPE_UNLCK);
      expect(reply.tag).toBe(ours("Rgetlock").tag);
    });
  });
});
