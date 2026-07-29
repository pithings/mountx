/**
 * The S3 session, against the memory driver, in process, with no sockets.
 *
 * Four kinds of assertion live here, and they are not the same kind of fact:
 *
 * - **Semantics.** What each operation answers, taken from the Amazon S3 API
 *   Reference and from the plan's decisions (`.agents/s3-plan.md`): the derived
 *   ETag, the directory conventions, `DELETE` of a missing key answering `204`,
 *   the empty-directory marker in both listing modes.
 * - **Ordering and paging**, which is where an S3 gateway is usually wrong. The
 *   `a.txt` / `a/b` / `a0` case is pinned in both modes, a full walk is compared
 *   against the same walk taken one key at a time, and the resume points are
 *   chosen to land mid-directory and across the boundary between a
 *   `CommonPrefixes` row and a `Contents` row.
 * - **HTTP.** `Range`, `If-Range` and the four conditional headers are RFC 9110
 *   behaviour, so they are checked against the RFC's rules rather than against
 *   what S3 happens to do.
 * - **The one-reply discipline.** A driver that throws, a body that dies
 *   mid-stream and an errno nothing has a name for each produce exactly one
 *   well-formed reply, and the session answers the next request normally.
 *
 * The fixtures give every field a distinct value (`AGENTS.md`), and no literal
 * control character appears in this file.
 */

import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { fsError } from "../../src/errors.ts";
import { createLoopback } from "../../src/harness.ts";
import type { FsDriver, StatsLike } from "../../src/types.ts";
import { signChunk, type ChunkedSignature } from "../../src/s3/chunked.ts";
import {
  MIN_PART_SIZE,
  MULTIPART_PREFIX,
  STREAMING_PAYLOAD,
  STREAMING_UNSIGNED_PAYLOAD_TRAILER,
} from "../../src/s3/constants.ts";
import { formatHttpDate, parseRequestTarget } from "../../src/s3/protocol.ts";
import {
  EMPTY_PAYLOAD_SHA256,
  formatAmzDate,
  presignRequest,
  sha256Hex,
  signRequest,
  uriEncode,
  type CredentialScope,
  type HeaderEntry,
} from "../../src/s3/sigv4.ts";
import {
  compareKeys,
  decodeContinuationToken,
  objectETag,
  S3Session,
  STORAGE_CLASS,
  SYNTHETIC_OWNER,
  type S3RequestHead,
} from "../../src/s3/session.ts";

// ---------------------------------------------------------------------------
// fixtures and helpers
// ---------------------------------------------------------------------------

const BUCKET = "mountx";
const REGION = "eu-west-3";
const CREDENTIALS = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};
/** A fixed clock: every signed fixture below is signed at this instant. */
const NOW = Date.UTC(2026, 6, 28, 12, 34, 56);

const CRLF = "\r\n";
const encoder = new TextEncoder();

function ascii(text: string): Uint8Array {
  return encoder.encode(text);
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function headerEntries(headers: Record<string, string>): HeaderEntry[] {
  return Object.entries(headers).map(([name, value]) => ({ name, value }));
}

/** Seed a driver: `"a/b.txt": "text"` is a file, `"e/": ""` is a directory. */
async function seed(driver: FsDriver, tree: Record<string, string>): Promise<void> {
  const loop = createLoopback(driver);
  for (const [key, value] of Object.entries(tree)) {
    if (key.endsWith("/")) {
      await loop.mkdir(`/${key.slice(0, -1)}`, { recursive: true });
      continue;
    }
    const slash = key.lastIndexOf("/");
    if (slash !== -1) {
      await loop.mkdir(`/${key.slice(0, slash)}`, { recursive: true });
    }
    await loop.writeFile(`/${key}`, value);
  }
}

interface Reply {
  status: number;
  headers: Record<string, string>;
  bytes: Uint8Array;
  text: string;
  /** How many pieces the body arrived in; `1` for a buffered one. */
  pieces: number;
}

async function collect(body: Uint8Array | AsyncIterable<Uint8Array> | undefined): Promise<{
  bytes: Uint8Array;
  pieces: number;
}> {
  if (body === undefined) {
    return { bytes: new Uint8Array(0), pieces: 0 };
  }
  if (body instanceof Uint8Array) {
    return { bytes: body, pieces: 1 };
  }
  const parts: Uint8Array[] = [];
  for await (const part of body) {
    parts.push(part);
  }
  return { bytes: concat(parts), pieces: parts.length };
}

interface Request {
  method?: string;
  target: string;
  headers?: Record<string, string>;
  headerEntries?: HeaderEntry[];
  body?: Uint8Array | string | AsyncIterable<Uint8Array>;
  /** Send no `Content-Length`, whatever the body is. */
  omitContentLength?: boolean;
}

/** One request through the session, with the body collected. */
async function call(session: S3Session, request: Request): Promise<Reply> {
  const method = request.method ?? "GET";
  const bytes =
    typeof request.body === "string"
      ? ascii(request.body)
      : (request.body as Uint8Array | undefined);
  const buffered = bytes instanceof Uint8Array ? bytes : undefined;
  const headers: Record<string, string> = { ...request.headers };
  if (buffered !== undefined && request.omitContentLength !== true) {
    headers["content-length"] ??= String(buffered.byteLength);
  }
  const head: S3RequestHead = {
    method,
    target: request.target,
    headers: [...headerEntries(headers), ...(request.headerEntries ?? [])],
  };
  const body =
    buffered === undefined
      ? (request.body as AsyncIterable<Uint8Array> | undefined)
      : oneChunk(buffered);
  const response = await session.handleRequest(head, body);
  const { bytes: out, pieces } = await collect(response.body);
  return {
    status: response.status,
    headers: response.headers,
    bytes: out,
    text: Buffer.from(out).toString("utf8"),
    pieces,
  };
}

async function* oneChunk(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
  yield bytes;
}

/** A body delivered in `count` roughly equal pieces. */
async function* inPieces(bytes: Uint8Array, count: number): AsyncGenerator<Uint8Array> {
  const size = Math.ceil(bytes.byteLength / count);
  for (let offset = 0; offset < bytes.byteLength; offset += size) {
    yield bytes.subarray(offset, Math.min(offset + size, bytes.byteLength));
  }
}

/** A body that dies before it yields anything, the way a reset connection does. */
async function* deadBody(): AsyncGenerator<Uint8Array> {
  throw new Error("the peer never spoke");
}

/** A body that dies part way through, the way a dropped connection does. */
async function* dyingBody(prefix: Uint8Array): AsyncGenerator<Uint8Array> {
  yield prefix;
  throw new Error("the peer went away");
}

// --- XML readers (the encoder emits no whitespace, so these are exact) ---

function unescapeXml(value: string): string {
  return value
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", `"`)
    .replaceAll("&apos;", `'`)
    .replaceAll(/&#x([\da-fA-F]+);/g, (_, hex: string) =>
      String.fromCodePoint(Number.parseInt(hex, 16)),
    )
    .replaceAll("&amp;", "&");
}

function field(block: string, name: string): string {
  const match = new RegExp(`<${name}>([^<]*)</${name}>`).exec(block);
  return match === null ? "" : unescapeXml(match[1] as string);
}

interface ListedObject {
  key: string;
  size: number;
  etag: string;
  owner: string | undefined;
}

function contentsOf(xml: string): ListedObject[] {
  return [...xml.matchAll(/<Contents>(.*?)<\/Contents>/g)].map((match) => {
    const block = match[1] as string;
    return {
      key: field(block, "Key"),
      size: Number(field(block, "Size")),
      etag: field(block, "ETag"),
      owner: block.includes("<Owner>") ? field(block, "ID") : undefined,
    };
  });
}

function keysOf(xml: string): string[] {
  return contentsOf(xml).map((entry) => entry.key);
}

function prefixesOf(xml: string): string[] {
  return [...xml.matchAll(/<CommonPrefixes><Prefix>([^<]*)<\/Prefix><\/CommonPrefixes>/g)].map(
    (match) => unescapeXml(match[1] as string),
  );
}

function errorCodeOf(reply: Reply): string {
  return field(reply.text, "Code");
}

// --- signing ---

interface Signed {
  headers: HeaderEntry[];
  signature: string;
  scope: CredentialScope;
  amzDate: string;
}

function signHeaders(input: {
  method: string;
  target: string;
  headers?: Record<string, string>;
  payloadHash: string;
  timestamp?: number;
  region?: string;
}): Signed {
  const parsed = parseRequestTarget(input.target);
  if (!parsed.ok) {
    throw new Error(`unsignable target ${input.target}`);
  }
  const timestamp = input.timestamp ?? NOW;
  const base: HeaderEntry[] = [
    { name: "host", value: "s3.example" },
    { name: "x-amz-date", value: formatAmzDate(timestamp) },
    { name: "x-amz-content-sha256", value: input.payloadHash },
    ...headerEntries(input.headers ?? {}),
  ];
  const signed = signRequest({
    method: input.method,
    path: parsed.target.path,
    query: parsed.target.query,
    headers: base,
    credentials: CREDENTIALS,
    region: input.region ?? REGION,
    timestamp,
    payloadHash: input.payloadHash,
  });
  return {
    headers: [...base, { name: "authorization", value: signed.authorization }],
    signature: signed.signature,
    scope: signed.scope,
    amzDate: signed.amzDate,
  };
}

/** An `aws-chunked` body, signed with the module's own primitives. */
function chunkedBody(
  payloads: readonly Uint8Array[],
  options: { signature?: ChunkedSignature; trailers?: readonly HeaderEntry[] } = {},
): Uint8Array {
  const frames: Uint8Array[] = [];
  let previous = options.signature?.seed ?? "";
  for (const payload of [...payloads, new Uint8Array(0)]) {
    let header = payload.byteLength.toString(16);
    if (options.signature !== undefined) {
      const signature = signChunk(options.signature, previous, sha256Hex(payload));
      previous = signature;
      header += `;chunk-signature=${signature}`;
    }
    frames.push(
      payload.byteLength === 0
        ? ascii(header + CRLF)
        : concat([ascii(header + CRLF), payload, ascii(CRLF)]),
    );
  }
  for (const trailer of options.trailers ?? []) {
    frames.push(ascii(`${trailer.name}:${trailer.value}${CRLF}`));
  }
  frames.push(ascii(CRLF));
  return concat(frames);
}

// --- sessions ---

let driver = createMemoryDriver();
let session = new S3Session({ [BUCKET]: driver });

beforeEach(() => {
  driver = createMemoryDriver();
  session = new S3Session({ [BUCKET]: driver });
});

/** Every reply this session produced was exactly one reply. */
function healthy(target: S3Session = session): void {
  expect(target.assertions).toEqual([]);
  expect(target.stats.replies).toBe(target.stats.requests);
}

const OBJECT = `/${BUCKET}/hello.txt`;

// ---------------------------------------------------------------------------

describe("S3Session: the object round trip", () => {
  it("puts, gets, heads and deletes an object", async () => {
    const put = await call(session, { method: "PUT", target: OBJECT, body: "hello world" });
    expect(put.status).toBe(200);
    expect(put.headers.etag).toMatch(/^"[\da-f]{32}-1"$/);
    expect(put.headers["content-length"]).toBe("0");

    const get = await call(session, { target: OBJECT });
    expect(get.status).toBe(200);
    expect(get.text).toBe("hello world");
    expect(get.headers["content-length"]).toBe("11");
    expect(get.headers["content-type"]).toBe("application/octet-stream");
    expect(get.headers["accept-ranges"]).toBe("bytes");
    expect(get.headers.etag).toBe(put.headers.etag);

    const head = await call(session, { method: "HEAD", target: OBJECT });
    expect(head.status).toBe(200);
    expect(head.bytes.byteLength).toBe(0);
    expect(head.headers["content-length"]).toBe("11");
    expect(head.headers.etag).toBe(put.headers.etag);

    expect((await call(session, { method: "DELETE", target: OBJECT })).status).toBe(204);
    const gone = await call(session, { target: OBJECT });
    expect(gone.status).toBe(404);
    expect(errorCodeOf(gone)).toBe("NoSuchKey");
    healthy();
  });

  it("carries a multi-MiB body in either direction, split across many pieces", async () => {
    const bytes = new Uint8Array(3 * 1024 * 1024);
    for (let index = 0; index < bytes.byteLength; index++) {
      bytes[index] = (index * 31 + (index >> 11)) & 0xff;
    }
    const put = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/big.bin`,
      headers: { "content-length": String(bytes.byteLength) },
      body: inPieces(bytes, 197),
    });
    expect(put.status).toBe(200);

    const get = await call(session, { target: `/${BUCKET}/big.bin` });
    expect(get.status).toBe(200);
    expect(get.headers["content-length"]).toBe(String(bytes.byteLength));
    expect(Buffer.from(get.bytes).equals(Buffer.from(bytes))).toBe(true);
    // Streamed, not buffered: 3 MiB at 128 KiB a read.
    expect(get.pieces).toBe(24);
    healthy();
  });

  it("changes the ETag when an object is overwritten", async () => {
    const first = await call(session, { method: "PUT", target: OBJECT, body: "one" });
    const second = await call(session, { method: "PUT", target: OBJECT, body: "another one" });
    expect(second.headers.etag).not.toBe(first.headers.etag);
    expect((await call(session, { target: OBJECT })).text).toBe("another one");
    healthy();
  });

  it("refuses a PUT whose length it cannot know", async () => {
    const reply = await call(session, {
      method: "PUT",
      target: OBJECT,
      body: "hello",
      omitContentLength: true,
    });
    expect(reply.status).toBe(411);
    expect(errorCodeOf(reply)).toBe("MissingContentLength");
    healthy();
  });

  it("refuses a body that is not the declared length", async () => {
    const reply = await call(session, {
      method: "PUT",
      target: OBJECT,
      headers: { "content-length": "99" },
      body: oneChunk(ascii("short")),
    });
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("IncompleteBody");
    healthy();
  });

  it("stores a zero-byte object", async () => {
    expect((await call(session, { method: "PUT", target: OBJECT, body: "" })).status).toBe(200);
    const get = await call(session, { target: OBJECT });
    expect(get.status).toBe(200);
    expect(get.headers["content-length"]).toBe("0");
    expect(get.bytes.byteLength).toBe(0);
    healthy();
  });

  it("answers 204 for deleting a key that was never there", async () => {
    expect((await call(session, { method: "DELETE", target: `/${BUCKET}/ghost` })).status).toBe(
      204,
    );
    healthy();
  });

  it("answers NoSuchBucket for every operation on an unknown bucket", async () => {
    for (const request of [
      { method: "GET", target: "/other/key" },
      { method: "HEAD", target: "/other" },
      { method: "PUT", target: "/other/key", body: "x" },
      { method: "DELETE", target: "/other/key" },
      { method: "GET", target: "/other?list-type=2" },
    ] satisfies Request[]) {
      const reply = await call(session, request);
      expect(reply.status, request.target).toBe(404);
      if (request.method !== "HEAD") {
        expect(errorCodeOf(reply)).toBe("NoSuchBucket");
      }
    }
    healthy();
  });
});

describe("S3Session: the ETag recipe", () => {
  it("is the first 32 hex of sha256 over dev:ino:size:mtimeMs, suffixed -1", () => {
    const stats = {
      dev: 2049,
      ino: 8675309,
      mode: 0o100644,
      nlink: 1,
      uid: 1000,
      gid: 1001,
      rdev: 0,
      size: 4131,
      blksize: 4096,
      blocks: 9,
      atimeMs: 1_700_000_000_111,
      mtimeMs: 1_700_000_000_222,
      ctimeMs: 1_700_000_000_333,
      birthtimeMs: 1_700_000_000_444,
      isFile: () => true,
      isDirectory: () => false,
      isSymbolicLink: () => false,
      isBlockDevice: () => false,
      isCharacterDevice: () => false,
      isFIFO: () => false,
      isSocket: () => false,
    } satisfies StatsLike;
    const expected = createHash("sha256")
      .update("2049:8675309:4131:1700000000222", "utf8")
      .digest("hex")
      .slice(0, 32);
    expect(objectETag(stats)).toBe(`${expected}-1`);
  });

  it("is what a GET answers, computed from the driver's own stat", async () => {
    await call(session, { method: "PUT", target: OBJECT, body: "hello" });
    const stats = await createLoopback(driver).stat("/hello.txt");
    const get = await call(session, { target: OBJECT });
    expect(get.headers.etag).toBe(`"${objectETag(stats)}"`);
    healthy();
  });
});

describe("S3Session: ListObjectsV2 ordering", () => {
  beforeEach(async () => {
    await seed(driver, { "a.txt": "one", "a/b": "two", a0: "three" });
  });

  it("orders by effective key, not by name (a.txt < a/b < a0)", async () => {
    const reply = await call(session, { target: `/${BUCKET}?list-type=2` });
    expect(keysOf(reply.text)).toEqual(["a.txt", "a/b", "a0"]);
    healthy();
  });

  it("keeps that order across the CommonPrefixes boundary with a delimiter", async () => {
    const reply = await call(session, { target: `/${BUCKET}?list-type=2&delimiter=/` });
    expect(keysOf(reply.text)).toEqual(["a.txt", "a0"]);
    expect(prefixesOf(reply.text)).toEqual(["a/"]);
    // ... and the merged cursor order is a.txt, a/, a0:
    const paged: string[] = [];
    let token: string | undefined;
    for (let page = 0; page < 5; page++) {
      const query = `list-type=2&delimiter=/&max-keys=1${
        token === undefined ? "" : `&continuation-token=${uriEncode(token)}`
      }`;
      const next = await call(session, { target: `/${BUCKET}?${query}` });
      paged.push(...keysOf(next.text), ...prefixesOf(next.text));
      if (field(next.text, "IsTruncated") !== "true") {
        break;
      }
      token = field(next.text, "NextContinuationToken");
    }
    expect(paged).toEqual(["a.txt", "a/", "a0"]);
    healthy();
  });

  it("orders unicode keys by their UTF-8 bytes, not their UTF-16 units", async () => {
    /* U+FFFD is three UTF-8 bytes starting 0xEF; U+1F600 is four starting 0xF0,
       so UTF-8 puts the emoji last. UTF-16 puts it first, because a surrogate
       (0xD83D) sorts below 0xFFFD — which is the bug this pins. */
    const replacement = String.fromCodePoint(0xff_fd);
    const emoji = String.fromCodePoint(0x1_f6_00);
    await seed(driver, { [`u/${replacement}`]: "a", [`u/${emoji}`]: "b", "u/z": "c" });
    expect(compareKeys(replacement, emoji)).toBeLessThan(0);
    expect(replacement < emoji).toBe(false);
    const reply = await call(session, { target: `/${BUCKET}?list-type=2&prefix=u/` });
    expect(keysOf(reply.text)).toEqual([`u/z`, `u/${replacement}`, `u/${emoji}`]);
    healthy();
  });

  it("walks a deep tree depth first, in full-key order", async () => {
    await seed(driver, {
      "deep/a/b/c/leaf": "1",
      "deep/a/b/zz": "2",
      "deep/a/c": "3",
      "deep/b": "4",
    });
    const reply = await call(session, { target: `/${BUCKET}?list-type=2&prefix=deep/` });
    expect(keysOf(reply.text)).toEqual(["deep/a/b/c/leaf", "deep/a/b/zz", "deep/a/c", "deep/b"]);
    healthy();
  });
});

describe("S3Session: ListObjectsV2 prefixes", () => {
  beforeEach(async () => {
    await seed(driver, {
      "photos/2023/x.jpg": "x",
      "photos/2024/july.jpg": "july",
      "photos/2024/june.jpg": "june",
      "poems.txt": "poem",
    });
  });

  it("matches a prefix that stops in the middle of a name", async () => {
    const reply = await call(session, { target: `/${BUCKET}?list-type=2&prefix=pho` });
    expect(keysOf(reply.text)).toEqual([
      "photos/2023/x.jpg",
      "photos/2024/july.jpg",
      "photos/2024/june.jpg",
    ]);
    const grouped = await call(session, {
      target: `/${BUCKET}?list-type=2&prefix=pho&delimiter=/`,
    });
    expect(keysOf(grouped.text)).toEqual([]);
    expect(prefixesOf(grouped.text)).toEqual(["photos/"]);
    healthy();
  });

  it("matches a prefix that stops in the middle of a name, several levels down", async () => {
    const reply = await call(session, {
      target: `/${BUCKET}?list-type=2&prefix=${uriEncode("photos/2024/ju")}`,
    });
    expect(keysOf(reply.text)).toEqual(["photos/2024/july.jpg", "photos/2024/june.jpg"]);
    healthy();
  });

  it("answers an empty listing for a prefix deeper than any directory", async () => {
    const reply = await call(session, {
      target: `/${BUCKET}?list-type=2&prefix=${uriEncode("photos/2024/june.jpg/more")}`,
    });
    expect(reply.status).toBe(200);
    expect(keysOf(reply.text)).toEqual([]);
    expect(field(reply.text, "KeyCount")).toBe("0");
    healthy();
  });

  it("answers the one key for a prefix that names a file exactly", async () => {
    const reply = await call(session, { target: `/${BUCKET}?list-type=2&prefix=poems.txt` });
    expect(keysOf(reply.text)).toEqual(["poems.txt"]);
    healthy();
  });

  it("lists a directory for a prefix with a trailing slash", async () => {
    const reply = await call(session, {
      target: `/${BUCKET}?list-type=2&prefix=${uriEncode("photos/2024/")}&delimiter=/`,
    });
    expect(keysOf(reply.text)).toEqual(["photos/2024/july.jpg", "photos/2024/june.jpg"]);
    expect(prefixesOf(reply.text)).toEqual([]);
    healthy();
  });

  it("lists the whole bucket for an empty prefix", async () => {
    const reply = await call(session, { target: `/${BUCKET}?list-type=2` });
    expect(keysOf(reply.text)).toEqual([
      "photos/2023/x.jpg",
      "photos/2024/july.jpg",
      "photos/2024/june.jpg",
      "poems.txt",
    ]);
    expect(field(reply.text, "Name")).toBe(BUCKET);
    expect(field(reply.text, "Prefix")).toBe("");
    expect(field(reply.text, "MaxKeys")).toBe("1000");
    expect(field(reply.text, "IsTruncated")).toBe("false");
    healthy();
  });

  it("names the owner only when asked, and always the synthetic one", async () => {
    const plain = await call(session, { target: `/${BUCKET}?list-type=2&prefix=poems` });
    expect(contentsOf(plain.text)[0]?.owner).toBeUndefined();
    const owned = await call(session, {
      target: `/${BUCKET}?list-type=2&prefix=poems&fetch-owner=true`,
    });
    expect(contentsOf(owned.text)[0]?.owner).toBe(SYNTHETIC_OWNER.id);
    expect(plain.text).toContain(`<StorageClass>${STORAGE_CLASS}</StorageClass>`);
    healthy();
  });

  it("url-encodes keys, prefixes and the delimiter when asked to", async () => {
    await seed(driver, { "sp ace/a+b.txt": "x" });
    const reply = await call(session, {
      target: `/${BUCKET}?list-type=2&encoding-type=url&prefix=sp%20ace/`,
    });
    expect(field(reply.text, "EncodingType")).toBe("url");
    expect(field(reply.text, "Key")).toBe("sp%20ace%2Fa%2Bb.txt");
    expect(field(reply.text, "Prefix")).toBe("sp%20ace%2F");
    const grouped = await call(session, {
      target: `/${BUCKET}?list-type=2&encoding-type=url&delimiter=/`,
    });
    expect(field(grouped.text, "Delimiter")).toBe("%2F");
    expect(prefixesOf(grouped.text)).toEqual(["photos%2F", "sp%20ace%2F"]);
    healthy();
  });
});

describe("S3Session: ListObjectsV2 pagination", () => {
  const tree = {
    "b.txt": "b",
    "d/1": "1",
    "d/2": "2",
    "d/3": "3",
    "d/e/deep": "deep",
    "empty/": "",
    "z.txt": "z",
  };

  beforeEach(async () => {
    await seed(driver, tree);
  });

  async function page(query: string): Promise<Reply> {
    return await call(session, { target: `/${BUCKET}?list-type=2&${query}` });
  }

  /** Walk a listing one key at a time and return everything it emitted. */
  async function walkPaged(extra: string, maxKeys: number): Promise<string[]> {
    const seen: string[] = [];
    let token: string | undefined;
    for (let guard = 0; guard < 50; guard++) {
      const reply = await page(
        `max-keys=${maxKeys}&${extra}${
          token === undefined ? "" : `&continuation-token=${uriEncode(token)}`
        }`,
      );
      expect(reply.status).toBe(200);
      /* One page is a contiguous window of the merged sequence, but the
         document shape splits it into `Contents` then `CommonPrefixes` — S3's
         schema, not an ordering — so the window is re-merged here. */
      const emitted = [...keysOf(reply.text), ...prefixesOf(reply.text)].sort(compareKeys);
      expect(field(reply.text, "KeyCount")).toBe(String(emitted.length));
      seen.push(...emitted);
      if (field(reply.text, "IsTruncated") !== "true") {
        expect(reply.text).not.toContain("<NextContinuationToken>");
        return seen;
      }
      token = field(reply.text, "NextContinuationToken");
      expect(token).not.toBe("");
    }
    throw new Error("the listing never ended");
  }

  it("pages one key at a time to exactly the unpaginated listing", async () => {
    const whole = keysOf((await page("")).text);
    expect(whole).toEqual(["b.txt", "d/1", "d/2", "d/3", "d/e/deep", "empty/", "z.txt"]);
    expect(await walkPaged("", 1)).toEqual(whole);
    expect(await walkPaged("", 3)).toEqual(whole);
    healthy();
  });

  it("pages a delimited listing across the Contents / CommonPrefixes boundary", async () => {
    const reply = await page("delimiter=/");
    expect(keysOf(reply.text)).toEqual(["b.txt", "z.txt"]);
    expect(prefixesOf(reply.text)).toEqual(["d/", "empty/"]);
    expect(await walkPaged("delimiter=/", 1)).toEqual(["b.txt", "d/", "empty/", "z.txt"]);
    expect(await walkPaged("delimiter=/", 2)).toEqual(["b.txt", "d/", "empty/", "z.txt"]);
    healthy();
  });

  it("resumes in the middle of a directory", async () => {
    const first = await page("max-keys=2");
    expect(keysOf(first.text)).toEqual(["b.txt", "d/1"]);
    expect(field(first.text, "IsTruncated")).toBe("true");
    const token = field(first.text, "NextContinuationToken");
    expect(decodeContinuationToken(token)).toBe("d/1");
    const second = await page(`max-keys=2&continuation-token=${uriEncode(token)}`);
    expect(keysOf(second.text)).toEqual(["d/2", "d/3"]);
    expect(field(second.text, "ContinuationToken")).toBe(token);
    healthy();
  });

  it("mints tokens that are opaque base64 of the last key of the page", async () => {
    const reply = await page("max-keys=4");
    const token = field(reply.text, "NextContinuationToken");
    expect(token).toBe(Buffer.from("d/3", "utf8").toString("base64"));
    expect(/^[\d+/A-Za-z]+={0,2}$/.test(token)).toBe(true);
    healthy();
  });

  it("refuses a continuation token it did not mint", async () => {
    const reply = await page("continuation-token=not-base64%3D%3D%3D");
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("InvalidArgument");
    healthy();
  });

  it("honours start-after on the first page", async () => {
    const reply = await page(`start-after=${uriEncode("d/2")}`);
    expect(keysOf(reply.text)).toEqual(["d/3", "d/e/deep", "empty/", "z.txt"]);
    expect(field(reply.text, "StartAfter")).toBe("d/2");
    healthy();
  });

  it("clamps max-keys to the protocol ceiling and answers nothing for zero", async () => {
    expect(field((await page("max-keys=99999")).text, "MaxKeys")).toBe("1000");
    const none = await page("max-keys=0");
    expect(field(none.text, "KeyCount")).toBe("0");
    expect(field(none.text, "IsTruncated")).toBe("false");
    expect(none.text).not.toContain("<NextContinuationToken>");
    healthy();
  });
});

describe("S3Session: directories and empty-directory markers", () => {
  beforeEach(async () => {
    await seed(driver, { "a/b.txt": "b", "e/": "" });
  });

  it("lists an empty directory as a zero-byte marker object", async () => {
    const flat = await call(session, { target: `/${BUCKET}?list-type=2` });
    expect(keysOf(flat.text)).toEqual(["a/b.txt", "e/"]);
    expect(contentsOf(flat.text)[1]?.size).toBe(0);
  });

  it("groups that marker like any other key when a delimiter is given", async () => {
    const grouped = await call(session, { target: `/${BUCKET}?list-type=2&delimiter=/` });
    expect(keysOf(grouped.text)).toEqual([]);
    expect(prefixesOf(grouped.text)).toEqual(["a/", "e/"]);
  });

  it("lists the marker as Contents when the prefix is the directory itself", async () => {
    const inside = await call(session, {
      target: `/${BUCKET}?list-type=2&delimiter=/&prefix=e/`,
    });
    expect(keysOf(inside.text)).toEqual(["e/"]);
    expect(prefixesOf(inside.text)).toEqual([]);
    const nonEmpty = await call(session, {
      target: `/${BUCKET}?list-type=2&delimiter=/&prefix=a/`,
    });
    expect(keysOf(nonEmpty.text)).toEqual(["a/b.txt"]);
  });

  it("serves and refuses the two readings of a directory key", async () => {
    const marker = await call(session, { target: `/${BUCKET}/e/` });
    expect(marker.status).toBe(200);
    expect(marker.headers["content-length"]).toBe("0");
    expect(marker.bytes.byteLength).toBe(0);
    // A directory is not an object at the un-suffixed key ...
    expect((await call(session, { target: `/${BUCKET}/e` })).status).toBe(404);
    // ... and a file is not one at the suffixed key.
    expect((await call(session, { target: `/${BUCKET}/a/b.txt/` })).status).toBe(404);
    healthy();
  });

  it("creates a directory with PUT and removes it with DELETE", async () => {
    const put = await call(session, { method: "PUT", target: `/${BUCKET}/made/deep/`, body: "" });
    expect(put.status).toBe(200);
    expect(put.headers.etag).toMatch(/^"[\da-f]{32}-1"$/);
    // mkdir -p, and idempotent.
    expect(
      (await call(session, { method: "PUT", target: `/${BUCKET}/made/`, body: "" })).status,
    ).toBe(200);
    const listing = await call(session, { target: `/${BUCKET}?list-type=2&prefix=made` });
    expect(keysOf(listing.text)).toEqual(["made/deep/"]);
    expect(
      (await call(session, { method: "DELETE", target: `/${BUCKET}/made/deep/` })).status,
    ).toBe(204);
    expect(
      (await call(session, { method: "DELETE", target: `/${BUCKET}/made/deep/` })).status,
    ).toBe(204);
    healthy();
  });

  it("refuses a directory PUT that carries bytes", async () => {
    const reply = await call(session, { method: "PUT", target: `/${BUCKET}/nope/`, body: "bytes" });
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("InvalidRequest");
    const listing = await call(session, { target: `/${BUCKET}?list-type=2&prefix=nope` });
    expect(keysOf(listing.text)).toEqual([]);
    expect(prefixesOf(listing.text)).toEqual([]);
    healthy();
  });

  it("answers 409 for deleting a directory that still has something in it", async () => {
    const reply = await call(session, { method: "DELETE", target: `/${BUCKET}/a/` });
    expect(reply.status).toBe(409);
    expect(errorCodeOf(reply)).toBe("BucketNotEmpty");
    healthy();
  });
});

describe("S3Session: the multipart staging prefix", () => {
  beforeEach(async () => {
    await seed(driver, {
      [`${MULTIPART_PREFIX}/upload-7/part-1`]: "staged",
      "visible.txt": "seen",
    });
  });

  it("never appears in a listing, at any depth or under any prefix", async () => {
    for (const query of [
      "list-type=2",
      "list-type=2&delimiter=/",
      `list-type=2&prefix=${uriEncode(".mountx")}`,
      `list-type=2&prefix=${uriEncode(`${MULTIPART_PREFIX}/`)}`,
      `list-type=2&prefix=${uriEncode(`${MULTIPART_PREFIX}/upload-7/`)}&delimiter=/`,
    ]) {
      const reply = await call(session, { target: `/${BUCKET}?${query}` });
      /* The echoed `<Prefix>` repeats whatever the client asked for; what must
         never appear is a row naming the staging area. */
      expect(keysOf(reply.text), query).not.toContain(`${MULTIPART_PREFIX}/upload-7/part-1`);
      expect(prefixesOf(reply.text).join(" "), query).not.toContain(MULTIPART_PREFIX);
      expect(
        contentsOf(reply.text)
          .map((entry) => entry.key)
          .join(" "),
        query,
      ).not.toContain(MULTIPART_PREFIX);
    }
    const whole = await call(session, { target: `/${BUCKET}?list-type=2` });
    expect(keysOf(whole.text)).toEqual(["visible.txt"]);
    healthy();
  });

  it("answers a staged key the way an absent one is answered, by method", async () => {
    const staged = `/${BUCKET}/${MULTIPART_PREFIX}/upload-7/part-1`;
    expect((await call(session, { target: staged })).status).toBe(404);
    expect((await call(session, { method: "HEAD", target: staged })).status).toBe(404);
    expect((await call(session, { method: "PUT", target: staged, body: "x" })).status).toBe(404);
    expect((await call(session, { method: "DELETE", target: staged })).status).toBe(204);
    // ... and nothing was written or removed.
    expect(await createLoopback(driver).readFile(`/${MULTIPART_PREFIX}/upload-7/part-1`)).toEqual(
      ascii("staged"),
    );
    healthy();
  });
});

describe("S3Session: conditionals and ranges", () => {
  let etag = "";
  let lastModified = "";

  beforeEach(async () => {
    await call(session, { method: "PUT", target: OBJECT, body: "hello world" });
    const head = await call(session, { method: "HEAD", target: OBJECT });
    etag = head.headers.etag as string;
    lastModified = head.headers["last-modified"] as string;
  });

  it("answers 412 for an If-Match that does not hold", async () => {
    const reply = await call(session, { target: OBJECT, headers: { "if-match": `"nope"` } });
    expect(reply.status).toBe(412);
    expect(errorCodeOf(reply)).toBe("PreconditionFailed");
    expect((await call(session, { target: OBJECT, headers: { "if-match": etag } })).status).toBe(
      200,
    );
  });

  it("answers 304 for an If-None-Match that matches", async () => {
    const reply = await call(session, { target: OBJECT, headers: { "if-none-match": etag } });
    expect(reply.status).toBe(304);
    expect(reply.headers.etag).toBe(etag);
    expect(reply.bytes.byteLength).toBe(0);
    expect(
      (await call(session, { target: OBJECT, headers: { "if-none-match": `"other"` } })).status,
    ).toBe(200);
  });

  it("answers 304 for If-Modified-Since when nothing changed", async () => {
    const reply = await call(session, {
      target: OBJECT,
      headers: { "if-modified-since": lastModified },
    });
    expect(reply.status).toBe(304);
  });

  it("serves a single range as 206 with a Content-Range", async () => {
    const reply = await call(session, { target: OBJECT, headers: { range: "bytes=0-4" } });
    expect(reply.status).toBe(206);
    expect(reply.text).toBe("hello");
    expect(reply.headers["content-range"]).toBe("bytes 0-4/11");
    expect(reply.headers["content-length"]).toBe("5");
  });

  it("serves a suffix range", async () => {
    const reply = await call(session, { target: OBJECT, headers: { range: "bytes=-5" } });
    expect(reply.status).toBe(206);
    expect(reply.text).toBe("world");
    expect(reply.headers["content-range"]).toBe("bytes 6-10/11");
  });

  it("answers 416 for a range past the end", async () => {
    const reply = await call(session, { target: OBJECT, headers: { range: "bytes=100-" } });
    expect(reply.status).toBe(416);
    expect(errorCodeOf(reply)).toBe("InvalidRange");
    expect(reply.headers["content-range"]).toBe("bytes */11");
  });

  it("keeps the range when If-Range still holds and drops it when it does not", async () => {
    const kept = await call(session, {
      target: OBJECT,
      headers: { range: "bytes=0-4", "if-range": etag },
    });
    expect(kept.status).toBe(206);
    expect(kept.text).toBe("hello");

    const byDate = await call(session, {
      target: OBJECT,
      headers: { range: "bytes=0-4", "if-range": lastModified },
    });
    expect(byDate.status).toBe(206);

    for (const ifRange of [`"stale"`, `W/${etag}`, formatHttpDate(0)]) {
      const dropped = await call(session, {
        target: OBJECT,
        headers: { range: "bytes=0-4", "if-range": ifRange },
      });
      expect(dropped.status, ifRange).toBe(200);
      expect(dropped.text).toBe("hello world");
    }
    healthy();
  });
});

describe("S3Session: the mtime metadata header", () => {
  it("stores x-amz-meta-mtime on PUT and echoes it on GET and HEAD", async () => {
    const put = await call(session, {
      method: "PUT",
      target: OBJECT,
      headers: { "x-amz-meta-mtime": "1234567890" },
      body: "timed",
    });
    expect(put.status).toBe(200);
    for (const method of ["GET", "HEAD"]) {
      const reply = await call(session, { method, target: OBJECT });
      expect(reply.headers["x-amz-meta-mtime"], method).toBe("1234567890");
      expect(reply.headers["last-modified"], method).toBe(formatHttpDate(1_234_567_890_000));
    }
    healthy();
  });

  it("ignores a meta-mtime that is not a number, rather than failing the upload", async () => {
    const before = Date.now();
    const put = await call(session, {
      method: "PUT",
      target: OBJECT,
      headers: { "x-amz-meta-mtime": "yesterday" },
      body: "timed",
    });
    expect(put.status).toBe(200);
    // The bytes are stored and the object keeps the time it was written at.
    const get = await call(session, { target: OBJECT });
    expect(get.text).toBe("timed");
    const echoed = Number(get.headers["x-amz-meta-mtime"]) * 1000;
    expect(echoed).toBeGreaterThanOrEqual(before - 1000);
    expect(echoed).toBeLessThanOrEqual(Date.now() + 1000);
    healthy();
  });
});

describe("S3Session: CopyObject", () => {
  beforeEach(async () => {
    await seed(driver, { "source.txt": "the source bytes" });
  });

  function copyHeaders(source: string, extra: Record<string, string> = {}): Record<string, string> {
    return { "x-amz-copy-source": source, ...extra };
  }

  it("copies an object and answers the new ETag", async () => {
    const reply = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/copy.txt`,
      headers: copyHeaders(`/${BUCKET}/source.txt`),
    });
    expect(reply.status).toBe(200);
    expect(reply.text).toContain("<CopyObjectResult");
    expect(field(reply.text, "ETag")).toMatch(/^"[\da-f]{32}-1"$/);
    expect((await call(session, { target: `/${BUCKET}/copy.txt` })).text).toBe("the source bytes");
    healthy();
  });

  it("copies across buckets", async () => {
    const other = createMemoryDriver();
    const twoBuckets = new S3Session({ [BUCKET]: driver, other });
    const reply = await call(twoBuckets, {
      method: "PUT",
      target: `/other/from-mountx.txt`,
      headers: copyHeaders(`/${BUCKET}/source.txt`),
    });
    expect(reply.status).toBe(200);
    expect((await call(twoBuckets, { target: "/other/from-mountx.txt" })).text).toBe(
      "the source bytes",
    );
    healthy(twoBuckets);
  });

  it("answers NoSuchKey for a missing source and NoSuchBucket for a missing bucket", async () => {
    const missingKey = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/copy.txt`,
      headers: copyHeaders(`/${BUCKET}/ghost.txt`),
    });
    expect(missingKey.status).toBe(404);
    expect(errorCodeOf(missingKey)).toBe("NoSuchKey");

    const missingBucket = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/copy.txt`,
      headers: copyHeaders(`/nowhere/source.txt`),
    });
    expect(missingBucket.status).toBe(404);
    expect(errorCodeOf(missingBucket)).toBe("NoSuchBucket");
    healthy();
  });

  it("refuses a copy onto itself that changes nothing", async () => {
    const reply = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/source.txt`,
      headers: copyHeaders(`/${BUCKET}/source.txt`),
    });
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("InvalidRequest");
    expect(reply.text).toContain("copy an object to itself");
    healthy();
  });

  it("rewrites only the metadata for a REPLACE copy onto itself", async () => {
    const reply = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/source.txt`,
      headers: copyHeaders(`/${BUCKET}/source.txt`, {
        "x-amz-metadata-directive": "REPLACE",
        "x-amz-meta-mtime": "1000000000",
      }),
    });
    expect(reply.status).toBe(200);
    const get = await call(session, { target: `/${BUCKET}/source.txt` });
    expect(get.text).toBe("the source bytes");
    expect(get.headers["x-amz-meta-mtime"]).toBe("1000000000");
    healthy();
  });

  it("preserves the source mtime for COPY and takes the request's for REPLACE", async () => {
    await call(session, {
      method: "PUT",
      target: `/${BUCKET}/stamped.txt`,
      headers: { "x-amz-meta-mtime": "1111111111" },
      body: "stamped",
    });
    const copied = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/copy-directive.txt`,
      headers: copyHeaders(`/${BUCKET}/stamped.txt`, { "x-amz-metadata-directive": "COPY" }),
    });
    expect(copied.status).toBe(200);
    expect(
      (await call(session, { target: `/${BUCKET}/copy-directive.txt` })).headers[
        "x-amz-meta-mtime"
      ],
    ).toBe("1111111111");

    const replaced = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/replace-directive.txt`,
      headers: copyHeaders(`/${BUCKET}/stamped.txt`, {
        "x-amz-metadata-directive": "REPLACE",
        "x-amz-meta-mtime": "2222222222",
      }),
    });
    expect(replaced.status).toBe(200);
    expect(
      (await call(session, { target: `/${BUCKET}/replace-directive.txt` })).headers[
        "x-amz-meta-mtime"
      ],
    ).toBe("2222222222");
    healthy();
  });

  it("honours all four x-amz-copy-source-if-* conditionals", async () => {
    const head = await call(session, { method: "HEAD", target: `/${BUCKET}/source.txt` });
    const etag = head.headers.etag as string;
    const modified = head.headers["last-modified"] as string;
    const cases: Record<string, string>[] = [
      { "x-amz-copy-source-if-match": `"not-the-etag"` },
      { "x-amz-copy-source-if-none-match": etag },
      { "x-amz-copy-source-if-unmodified-since": formatHttpDate(0) },
      { "x-amz-copy-source-if-modified-since": modified },
    ];
    for (const conditional of cases) {
      const reply = await call(session, {
        method: "PUT",
        target: `/${BUCKET}/conditional.txt`,
        headers: copyHeaders(`/${BUCKET}/source.txt`, conditional),
      });
      expect(reply.status, JSON.stringify(conditional)).toBe(412);
      expect(errorCodeOf(reply)).toBe("PreconditionFailed");
    }
    // ... and the ones that hold let the copy through.
    const allowed = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/conditional.txt`,
      headers: copyHeaders(`/${BUCKET}/source.txt`, {
        "x-amz-copy-source-if-match": etag,
      }),
    });
    expect(allowed.status).toBe(200);
    healthy();
  });
});

describe("S3Session: DeleteObjects", () => {
  function document(keys: readonly string[], quiet = false): string {
    const objects = keys.map((key) => `<Object><Key>${key}</Key></Object>`).join("");
    return `<Delete>${objects}${quiet ? "<Quiet>true</Quiet>" : ""}</Delete>`;
  }

  beforeEach(async () => {
    await seed(driver, { "one.txt": "1", "two.txt": "2", "full/inside.txt": "3" });
  });

  it("deletes what it can and reports the rest, per key", async () => {
    const reply = await call(session, {
      method: "POST",
      target: `/${BUCKET}?delete`,
      body: document(["one.txt", "ghost.txt", "full/", "bad//key"]),
    });
    expect(reply.status).toBe(200);
    const deleted = [...reply.text.matchAll(/<Deleted><Key>([^<]*)<\/Key><\/Deleted>/g)].map(
      (match) => match[1],
    );
    expect(deleted).toEqual(["one.txt", "ghost.txt"]);
    const errors = [...reply.text.matchAll(/<Error>(.*?)<\/Error>/g)].map((match) => ({
      key: field(match[1] as string, "Key"),
      code: field(match[1] as string, "Code"),
    }));
    expect(errors).toEqual([
      { key: "full/", code: "BucketNotEmpty" },
      { key: "bad//key", code: "InvalidArgument" },
    ]);
    expect((await call(session, { target: `/${BUCKET}/one.txt` })).status).toBe(404);
    expect((await call(session, { target: `/${BUCKET}/two.txt` })).status).toBe(200);
    healthy();
  });

  it("reports only the failures in quiet mode", async () => {
    const reply = await call(session, {
      method: "POST",
      target: `/${BUCKET}?delete`,
      body: document(["one.txt", "full/"], true),
    });
    expect(reply.status).toBe(200);
    expect(reply.text).not.toContain("<Deleted>");
    expect(reply.text).toContain("<Key>full/</Key>");
    healthy();
  });

  it("treats a staged key as the empty space it pretends to be", async () => {
    const reply = await call(session, {
      method: "POST",
      target: `/${BUCKET}?delete`,
      body: document([`${MULTIPART_PREFIX}/u/part-1`]),
    });
    expect(reply.text).toContain(`<Deleted><Key>${MULTIPART_PREFIX}/u/part-1</Key></Deleted>`);
    healthy();
  });

  it("verifies Content-MD5 when the client sends one", async () => {
    const body = document(["one.txt"]);
    const digest = createHash("md5").update(body, "utf8").digest("base64");
    expect(
      (
        await call(session, {
          method: "POST",
          target: `/${BUCKET}?delete`,
          headers: { "content-md5": digest },
          body,
        })
      ).status,
    ).toBe(200);
    const wrong = await call(session, {
      method: "POST",
      target: `/${BUCKET}?delete`,
      headers: { "content-md5": createHash("md5").update("other", "utf8").digest("base64") },
      body: document(["two.txt"]),
    });
    expect(wrong.status).toBe(400);
    expect(errorCodeOf(wrong)).toBe("BadDigest");
    expect((await call(session, { target: `/${BUCKET}/two.txt` })).status).toBe(200);
    healthy();
  });

  it("refuses more than a thousand keys", async () => {
    const keys = Array.from({ length: 1001 }, (_, index) => `k${index}`);
    const reply = await call(session, {
      method: "POST",
      target: `/${BUCKET}?delete`,
      body: document(keys),
    });
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("MalformedXML");
    healthy();
  });

  it("refuses a document over the byte budget, by header and by count", async () => {
    const small = new S3Session({ [BUCKET]: driver }, { maxXmlBytes: 64 });
    const declared = await call(small, {
      method: "POST",
      target: `/${BUCKET}?delete`,
      headers: { "content-length": "4096" },
      body: oneChunk(ascii(document(["one.txt"]))),
    });
    expect(declared.status).toBe(400);
    expect(errorCodeOf(declared)).toBe("MaxMessageLengthExceeded");

    const streamed = await call(small, {
      method: "POST",
      target: `/${BUCKET}?delete`,
      body: oneChunk(ascii(document(["one.txt", "two.txt", "full/inside.txt"]))),
    });
    expect(errorCodeOf(streamed)).toBe("MaxMessageLengthExceeded");
    healthy(small);
  });

  it("refuses a document that is not the DeleteObjects grammar", async () => {
    const reply = await call(session, {
      method: "POST",
      target: `/${BUCKET}?delete`,
      body: "<NotDelete/>",
    });
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("MalformedXML");
    healthy();
  });
});

describe("S3Session: ListBuckets and HeadBucket", () => {
  it("lists every configured bucket, in key order, with the synthetic owner", async () => {
    const many = new S3Session({ zulu: createMemoryDriver(), alpha: createMemoryDriver() });
    const reply = await call(many, { target: "/" });
    expect(reply.status).toBe(200);
    const names = [...reply.text.matchAll(/<Name>([^<]*)<\/Name>/g)].map((match) => match[1]);
    expect(names).toEqual(["alpha", "zulu"]);
    expect(reply.text).toContain(`<ID>${SYNTHETIC_OWNER.id}</ID>`);
    expect(reply.text).toContain(`<DisplayName>${SYNTHETIC_OWNER.displayName}</DisplayName>`);
    expect(reply.text).toMatch(/<CreationDate>\d{4}-\d\d-\d\dT/);
    healthy(many);
  });

  it("answers HeadBucket for a bucket it has and 404 for one it does not", async () => {
    expect((await call(session, { method: "HEAD", target: `/${BUCKET}` })).status).toBe(200);
    expect((await call(session, { method: "HEAD", target: "/absent" })).status).toBe(404);
    healthy();
  });
});

describe("S3Session: aws-chunked bodies", () => {
  const payload = ascii("chunked object bytes");

  function put(bytes: Uint8Array, headers: HeaderEntry[]): Promise<Reply> {
    return call(session, {
      method: "PUT",
      target: `/${BUCKET}/chunked.bin`,
      headerEntries: headers,
      body: oneChunk(bytes),
    });
  }

  beforeEach(() => {
    session = new S3Session({ [BUCKET]: driver }, { credentials: CREDENTIALS, now: () => NOW });
  });

  function signedChunkedHeaders(bodyLength: () => number, decoded: number): Signed {
    return signHeaders({
      method: "PUT",
      target: `/${BUCKET}/chunked.bin`,
      payloadHash: STREAMING_PAYLOAD,
      headers: {
        "content-encoding": "aws-chunked",
        "x-amz-decoded-content-length": String(decoded),
        "content-length": String(bodyLength()),
      },
    });
  }

  it("stores a signed streaming body", async () => {
    /* The frame length depends on nothing the signature covers, so it is safe
       to sign first and measure afterwards — but the header has to carry the
       real number, so the body is built twice: once to measure, once for real. */
    const signature = (signed: Signed): ChunkedSignature => ({
      seed: signed.signature,
      amzDate: signed.amzDate,
      scope: signed.scope,
      secretAccessKey: CREDENTIALS.secretAccessKey,
    });
    const draft = signedChunkedHeaders(() => 0, payload.byteLength);
    const length = chunkedBody([payload], { signature: signature(draft) }).byteLength;
    const signed = signedChunkedHeaders(() => length, payload.byteLength);
    const body = chunkedBody([payload.subarray(0, 8), payload.subarray(8)], {
      signature: signature(signed),
    });

    const reply = await put(body, signed.headers);
    expect(reply.status).toBe(200);
    expect(await createLoopback(driver).readFile("/chunked.bin")).toEqual(payload);
    healthy();
  });

  it("stores nothing when the first chunk's signature does not verify", async () => {
    const signed = signedChunkedHeaders(() => 0, payload.byteLength);
    const body = chunkedBody([payload], {
      signature: {
        // A seed that is not the request's signature: every chunk mismatches.
        seed: "0".repeat(64),
        amzDate: signed.amzDate,
        scope: signed.scope,
        secretAccessKey: CREDENTIALS.secretAccessKey,
      },
    });
    const reply = await put(body, signed.headers);
    expect(reply.status).toBe(403);
    expect(errorCodeOf(reply)).toBe("SignatureDoesNotMatch");
    // Nothing was created: the destination is not opened until a chunk verifies.
    await expect(createLoopback(driver).stat("/chunked.bin")).rejects.toMatchObject({
      code: "ENOENT",
    });
    healthy();
  });

  it("stores an unsigned streaming body with a trailer", async () => {
    const decoded = payload.byteLength;
    const body = chunkedBody([payload], {
      trailers: [{ name: "x-amz-checksum-crc32", value: "1B2M2Y8=" }],
    });
    const signed = signHeaders({
      method: "PUT",
      target: `/${BUCKET}/chunked.bin`,
      payloadHash: STREAMING_UNSIGNED_PAYLOAD_TRAILER,
      headers: {
        "content-encoding": "aws-chunked",
        "x-amz-trailer": "x-amz-checksum-crc32",
        "x-amz-decoded-content-length": String(decoded),
        "content-length": String(body.byteLength),
      },
    });
    const reply = await put(body, signed.headers);
    expect(reply.status).toBe(200);
    expect(await createLoopback(driver).readFile("/chunked.bin")).toEqual(payload);
    healthy();
  });

  it("reports malformed framing as the client's error, not the server's", async () => {
    const signed = signHeaders({
      method: "PUT",
      target: `/${BUCKET}/chunked.bin`,
      payloadHash: STREAMING_UNSIGNED_PAYLOAD_TRAILER,
      headers: {
        "content-encoding": "aws-chunked",
        "x-amz-decoded-content-length": "5",
        "content-length": "13",
      },
    });
    const reply = await put(ascii(`notahexsize${CRLF}`), signed.headers);
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("InvalidRequest");
    healthy();
  });
});

describe("S3Session: authentication", () => {
  beforeEach(async () => {
    await seed(driver, { "signed.txt": "signed bytes" });
    session = new S3Session(
      { [BUCKET]: driver },
      { credentials: CREDENTIALS, region: REGION, now: () => NOW },
    );
  });

  it("accepts a correctly signed request", async () => {
    const signed = signHeaders({
      method: "GET",
      target: `/${BUCKET}/signed.txt`,
      payloadHash: EMPTY_PAYLOAD_SHA256,
    });
    const reply = await call(session, {
      target: `/${BUCKET}/signed.txt`,
      headerEntries: signed.headers,
    });
    expect(reply.status).toBe(200);
    expect(reply.text).toBe("signed bytes");
    healthy();
  });

  it("refuses an unsigned request, a bad signature, a skewed clock and a wrong region", async () => {
    const unsigned = await call(session, { target: `/${BUCKET}/signed.txt` });
    expect(unsigned.status).toBe(403);
    expect(errorCodeOf(unsigned)).toBe("AccessDenied");

    const signed = signHeaders({
      method: "GET",
      target: `/${BUCKET}/signed.txt`,
      payloadHash: EMPTY_PAYLOAD_SHA256,
    });
    const tampered = signed.headers.map((header) =>
      header.name === "authorization"
        ? { name: header.name, value: header.value.replace(/Signature=\w/, "Signature=0") }
        : header,
    );
    const wrong = await call(session, {
      target: `/${BUCKET}/signed.txt`,
      headerEntries: tampered,
    });
    expect(wrong.status).toBe(403);
    expect(errorCodeOf(wrong)).toBe("SignatureDoesNotMatch");

    const stale = signHeaders({
      method: "GET",
      target: `/${BUCKET}/signed.txt`,
      payloadHash: EMPTY_PAYLOAD_SHA256,
      timestamp: NOW - 60 * 60 * 1000,
    });
    const skewed = await call(session, {
      target: `/${BUCKET}/signed.txt`,
      headerEntries: stale.headers,
    });
    expect(skewed.status).toBe(403);
    expect(errorCodeOf(skewed)).toBe("RequestTimeTooSkewed");

    const elsewhere = signHeaders({
      method: "GET",
      target: `/${BUCKET}/signed.txt`,
      payloadHash: EMPTY_PAYLOAD_SHA256,
      region: "us-west-1",
    });
    const misScoped = await call(session, {
      target: `/${BUCKET}/signed.txt`,
      headerEntries: elsewhere.headers,
    });
    expect(misScoped.status).toBe(400);
    expect(errorCodeOf(misScoped)).toBe("AuthorizationHeaderMalformed");
    healthy();
  });

  it("serves a presigned GET and refuses an expired one", async () => {
    function presigned(expiresIn: number, at: number): string {
      const request = presignRequest({
        method: "GET",
        path: `/${BUCKET}/signed.txt`,
        headers: [{ name: "host", value: "s3.example" }],
        credentials: CREDENTIALS,
        region: REGION,
        timestamp: at,
        expiresIn,
      });
      const query = request.query
        .map((entry) => `${uriEncode(entry.name)}=${uriEncode(entry.value)}`)
        .join("&");
      return `/${BUCKET}/signed.txt?${query}`;
    }
    const fresh = await call(session, {
      target: presigned(3600, NOW),
      headers: { host: "s3.example" },
    });
    expect(fresh.status).toBe(200);
    expect(fresh.text).toBe("signed bytes");

    const expired = await call(session, {
      target: presigned(60, NOW - 3600 * 1000),
      headers: { host: "s3.example" },
    });
    expect(expired.status).toBe(403);
    expect(errorCodeOf(expired)).toBe("AccessDenied");
    expect(expired.text).toContain("Request has expired");
    healthy();
  });

  it("accepts anything parseable when no credentials are configured", async () => {
    const anonymous = new S3Session({ [BUCKET]: driver });
    const reply = await call(anonymous, {
      target: `/${BUCKET}/signed.txt`,
      headers: { authorization: "AWS4-HMAC-SHA256 nonsense" },
    });
    expect(reply.status).toBe(200);
    healthy(anonymous);
  });
});

describe("S3Session: one reply, whatever happens", () => {
  /** A driver that fails one named method with one named errno. */
  function failing(method: "open" | "stat" | "unlink" | "rmdir", code: string): FsDriver {
    const base = createMemoryDriver();
    return {
      ...base,
      [method]: async () => {
        throw code === "EWEIRD"
          ? Object.assign(new Error("something nobody named"), { code: "EWEIRD" })
          : fsError(code as "EACCES");
      },
    } as FsDriver;
  }

  it("maps a driver's errno to the S3 error the table names", async () => {
    for (const [code, status, error] of [
      ["EACCES", 403, "AccessDenied"],
      ["EROFS", 403, "AccessDenied"],
      ["ENOSPC", 503, "ServiceUnavailable"],
      ["EWEIRD", 500, "InternalError"],
    ] as const) {
      const broken = new S3Session({ [BUCKET]: failing("open", code) });
      const reply = await call(broken, { method: "PUT", target: OBJECT, body: "x" });
      expect(reply.status, code).toBe(status);
      expect(errorCodeOf(reply), code).toBe(error);
      healthy(broken);
    }
  });

  it("survives a driver that throws after the request was accepted", async () => {
    const broken = new S3Session({ [BUCKET]: failing("stat", "EACCES") });
    const first = await call(broken, { target: OBJECT });
    expect(first.status).toBe(403);
    const second = await call(broken, { method: "HEAD", target: `/${BUCKET}` });
    expect(second.status).toBe(200);
    expect(broken.stats.requests).toBe(2);
    healthy(broken);
  });

  it("names a body that dies mid-stream as an incomplete body, not a framing error", async () => {
    const reply = await call(session, {
      method: "PUT",
      target: OBJECT,
      headers: { "content-length": "1024" },
      body: dyingBody(ascii("the start of it")),
    });
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("IncompleteBody");
    // ... and the session answers the next request normally.
    expect((await call(session, { method: "PUT", target: OBJECT, body: "fine" })).status).toBe(200);
    expect((await call(session, { target: OBJECT })).text).toBe("fine");
    healthy();
  });

  it("reports errors to onError and never lets a logger cost a reply", async () => {
    const seen: unknown[] = [];
    const noisy = new S3Session(
      { [BUCKET]: failing("open", "EACCES") },
      {
        onError: (error) => {
          seen.push(error);
          throw new Error("the logger is broken too");
        },
      },
    );
    const reply = await call(noisy, { method: "PUT", target: OBJECT, body: "x" });
    expect(reply.status).toBe(403);
    expect(seen).toHaveLength(1);
    healthy(noisy);
  });

  it("counts every request, every reply and every operation", async () => {
    await call(session, { method: "PUT", target: OBJECT, body: "x" });
    await call(session, { target: OBJECT });
    await call(session, { target: `/${BUCKET}?list-type=2` });
    expect(session.stats.requests).toBe(3);
    expect(session.stats.replies).toBe(3);
    expect(session.stats.errors).toBe(0);
    expect(session.stats.operations.get("PutObject")).toBe(1);
    expect(session.stats.operations.get("GetObject")).toBe(1);
    expect(session.stats.operations.get("ListObjectsV2")).toBe(1);
    healthy();
  });

  it("refuses the multipart operations this gateway does not implement", async () => {
    for (const request of [
      /* Bucket-scoped `?uploads` is `ListMultipartUploads`, and `?uploadId`
         with `x-amz-copy-source` is `UploadPartCopy`: neither is in the plan's
         supported set, and both are refused rather than half-answered. */
      { method: "GET", target: `/${BUCKET}?uploads` },
      {
        method: "PUT",
        target: `/${BUCKET}/big.bin?uploadId=${"0".repeat(32)}&partNumber=1`,
        headers: { "x-amz-copy-source": `/${BUCKET}/source.txt` },
      },
    ] satisfies Request[]) {
      const reply = await call(session, request);
      expect(reply.status, request.target).toBe(501);
      expect(errorCodeOf(reply)).toBe("NotImplemented");
    }
    healthy();
  });

  it("carries the request id on every reply", async () => {
    const fixed = new S3Session({ [BUCKET]: driver }, { requestId: () => "0123456789abcdef" });
    const ok = await call(fixed, { method: "HEAD", target: `/${BUCKET}` });
    expect(ok.headers["x-amz-request-id"]).toBe("0123456789abcdef");
    const bad = await call(fixed, { target: `/${BUCKET}/missing` });
    expect(bad.headers["x-amz-request-id"]).toBe("0123456789abcdef");
    expect(bad.text).toContain("<RequestId>0123456789abcdef</RequestId>");
    expect(fixed.assertions).toEqual([]);
  });

  it("refuses a body over the configured cap", async () => {
    const capped = new S3Session({ [BUCKET]: driver }, { maxBodyBytes: 8 });
    const reply = await call(capped, {
      method: "PUT",
      target: OBJECT,
      body: "far more than eight bytes",
    });
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("EntityTooLarge");
    healthy(capped);
  });

  it("refuses a key that does not map to a path", async () => {
    for (const key of ["a//b", "a/./b", "a/../b"]) {
      const reply = await call(session, { target: `/${BUCKET}/${key}` });
      expect(reply.status, key).toBe(400);
      expect(errorCodeOf(reply)).toBe("InvalidArgument");
    }
    healthy();
  });
});

describe("S3Session: the edges", () => {
  it("accepts a request with no body at all", async () => {
    const response = await session.handleRequest({
      method: "PUT",
      target: OBJECT,
      headers: [{ name: "content-length", value: "0" }],
    });
    expect(response.status).toBe(200);
    expect((await call(session, { target: OBJECT })).headers["content-length"]).toBe("0");
    healthy();
  });

  it("refuses a target that is not a URI and a length that is not a number", async () => {
    const target = await call(session, { target: `/${BUCKET}/%zz` });
    expect(target.status).toBe(400);
    expect(errorCodeOf(target)).toBe("InvalidURI");

    const length = await call(session, {
      method: "PUT",
      target: OBJECT,
      headers: { "content-length": "twelve" },
      body: oneChunk(ascii("x")),
    });
    expect(length.status).toBe(400);
    expect(errorCodeOf(length)).toBe("InvalidArgument");
    healthy();
  });

  it("refuses a copy onto a directory key", async () => {
    await seed(driver, { "source.txt": "s" });
    const reply = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/into/`,
      headers: { "x-amz-copy-source": `/${BUCKET}/source.txt` },
    });
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("InvalidRequest");
    healthy();
  });

  it("decodes a signed streaming body as an unsigned one when it has no credentials", async () => {
    const payload = ascii("no credentials here");
    const body = chunkedBody([payload], {
      signature: {
        seed: "f".repeat(64),
        amzDate: formatAmzDate(NOW),
        scope: { date: "20260728", region: REGION, service: "s3" },
        secretAccessKey: "not the gateway's",
      },
    });
    const reply = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/anon.bin`,
      headers: {
        "content-encoding": "aws-chunked",
        "x-amz-content-sha256": STREAMING_PAYLOAD,
        "x-amz-decoded-content-length": String(payload.byteLength),
      },
      body: oneChunk(body),
    });
    expect(reply.status).toBe(200);
    expect(await createLoopback(driver).readFile("/anon.bin")).toEqual(payload);
    healthy();
  });

  it("dates a bucket at the epoch when its driver cannot stat its own root", async () => {
    const base = createMemoryDriver();
    const rootless = new S3Session({
      [BUCKET]: {
        ...base,
        stat: async () => {
          throw fsError("EACCES", { syscall: "stat", path: "/" });
        },
      } as FsDriver,
    });
    const reply = await call(rootless, { target: "/" });
    expect(field(reply.text, "CreationDate")).toBe("1970-01-01T00:00:00.000Z");
    healthy(rootless);
  });

  it("skips an object that vanished between the readdir and its stat", async () => {
    const base = createMemoryDriver();
    await seed(base, { "a.txt": "a", "b.txt": "b" });
    const flaky = new S3Session({
      [BUCKET]: {
        ...base,
        stat: async (path: string) => {
          if (path === "/a.txt") {
            throw fsError("ENOENT", { syscall: "stat", path });
          }
          return await base.stat(path);
        },
      } as FsDriver,
    });
    const reply = await call(flaky, { target: `/${BUCKET}?list-type=2` });
    expect(keysOf(reply.text)).toEqual(["b.txt"]);
    expect(field(reply.text, "KeyCount")).toBe("1");
    healthy(flaky);
  });

  it("lists neither a symlink nor anything else that is not a file or a directory", async () => {
    await seed(driver, { "real.txt": "r" });
    await createLoopback(driver).symlink("/real.txt", "/link.txt");
    const reply = await call(session, { target: `/${BUCKET}?list-type=2` });
    expect(keysOf(reply.text)).toEqual(["real.txt"]);
    healthy();
  });

  it("answers an empty listing for a delimited prefix that names nothing", async () => {
    const reply = await call(session, {
      target: `/${BUCKET}?list-type=2&delimiter=/&prefix=${uriEncode("nowhere/")}`,
    });
    expect(reply.status).toBe(200);
    expect(field(reply.text, "KeyCount")).toBe("0");
    healthy();
  });

  it("passes a readdir failure through as the error its errno names", async () => {
    const unreadable = new S3Session({
      [BUCKET]: {
        ...createMemoryDriver(),
        readdir: async () => {
          throw fsError("EACCES", { syscall: "scandir", path: "/" });
        },
      } as FsDriver,
    });
    const reply = await call(unreadable, { target: `/${BUCKET}?list-type=2` });
    expect(reply.status).toBe(403);
    expect(errorCodeOf(reply)).toBe("AccessDenied");
    healthy(unreadable);
  });

  it("answers InternalError for a thrown value nothing can name", async () => {
    for (const thrown of ["a string, thrown", Object.assign(new Error("odd"), { code: 12 })]) {
      const odd = new S3Session({
        [BUCKET]: {
          ...createMemoryDriver(),
          stat: async () => {
            throw thrown;
          },
        } as FsDriver,
      });
      const reply = await call(odd, { target: OBJECT });
      expect(reply.status).toBe(500);
      expect(errorCodeOf(reply)).toBe("InternalError");
      healthy(odd);
    }
  });

  it("ends the body when the object shrinks under an open stream", async () => {
    const base = createMemoryDriver();
    await seed(base, { "shrinking.bin": "x".repeat(300 * 1024) });
    let closed = 0;
    const shrinking = new S3Session({
      [BUCKET]: {
        ...base,
        open: async (path: string, flags?: string | number, mode?: number) => {
          const handle = await base.open(path, flags, mode);
          let reads = 0;
          return {
            ...handle,
            read: async (
              buffer: Uint8Array,
              offset?: number | null,
              length?: number | null,
              at?: number | null,
            ) => {
              reads += 1;
              return reads > 1
                ? { bytesRead: 0, buffer }
                : await handle.read(buffer, offset, length, at);
            },
            close: async () => {
              closed += 1;
              await handle.close();
            },
          };
        },
      } as FsDriver,
    });
    const reply = await call(shrinking, { target: `/${BUCKET}/shrinking.bin` });
    expect(reply.status).toBe(200);
    // The header promised the whole object; the body stopped where the reads did.
    expect(reply.headers["content-length"]).toBe(String(300 * 1024));
    expect(reply.bytes.byteLength).toBe(128 * 1024);
    expect(closed).toBe(1);
    healthy(shrinking);
  });

  it("emits no marker for an empty bucket or for a name filter inside an empty directory", async () => {
    const empty = await call(session, { target: `/${BUCKET}?list-type=2&delimiter=/` });
    expect(field(empty.text, "KeyCount")).toBe("0");
    await seed(driver, { "hollow/": "" });
    const filtered = await call(session, {
      target: `/${BUCKET}?list-type=2&delimiter=/&prefix=${uriEncode("hollow/z")}`,
    });
    expect(field(filtered.text, "KeyCount")).toBe("0");
    const named = await call(session, {
      target: `/${BUCKET}?list-type=2&delimiter=/&prefix=${uriEncode("hollow/")}`,
    });
    expect(keysOf(named.text)).toEqual(["hollow/"]);
    healthy();
  });

  it("does not mistake a pinned request id for a request answered twice", async () => {
    /* The client-visible id is `options.requestId`'s to choose, and a caller
       may pin it — a server that stamps one id per connection, a test that
       wants a stable fixture. The single-reply tracking is on this session's
       own monotonic ticket, so concurrency under a constant id is ordinary
       traffic and not an assertion failure. */
    const pinned = new S3Session({ [BUCKET]: driver }, { requestId: () => "the-same-id" });
    const replies = await Promise.all([
      call(pinned, { method: "HEAD", target: `/${BUCKET}` }),
      call(pinned, { method: "HEAD", target: `/${BUCKET}` }),
      call(pinned, { method: "PUT", target: OBJECT, body: "concurrent" }),
      call(pinned, { target: `/${BUCKET}?list-type=2` }),
    ]);
    expect(replies.map((reply) => reply.headers["x-amz-request-id"])).toEqual(
      Array.from({ length: 4 }, () => "the-same-id"),
    );
    expect(pinned.assertions).toEqual([]);
    expect(pinned.stats.assertions).toBe(0);
    expect(pinned.stats.replies).toBe(4);
    healthy(pinned);
  });
});

describe("S3Session: HEAD", () => {
  it("answers the GET's headers, opens nothing, and honours a Range", async () => {
    const base = createMemoryDriver();
    await seed(base, { "headed.txt": "hello world" });
    let opens = 0;
    const counted = new S3Session({
      [BUCKET]: {
        ...base,
        open: async (path: string, flags?: string | number, mode?: number) => {
          opens += 1;
          return await base.open(path, flags, mode);
        },
      } as FsDriver,
    });
    const whole = await call(counted, { method: "HEAD", target: `/${BUCKET}/headed.txt` });
    expect(whole.status).toBe(200);
    expect(whole.headers["content-length"]).toBe("11");
    expect(whole.bytes.byteLength).toBe(0);

    const ranged = await call(counted, {
      method: "HEAD",
      target: `/${BUCKET}/headed.txt`,
      headers: { range: "bytes=2-5" },
    });
    expect(ranged.status).toBe(206);
    expect(ranged.headers["content-range"]).toBe("bytes 2-5/11");
    expect(ranged.headers["content-length"]).toBe("4");
    expect(ranged.bytes.byteLength).toBe(0);
    expect(opens).toBe(0);
    healthy(counted);
  });
});

describe("S3Session: prefixes no key can begin with", () => {
  /* The verifier's finding: a prefix that is not a key prefix used to reach the
     walk, where it derived a driver path of its own — listing the staging
     subtree (which the bucket-root skip no longer covered) and fabricating keys
     that a GET of the same key refuses. Every one of these matches nothing, so
     every one of them is an empty listing rather than an error: S3 matches a
     prefix as a literal string. */
  const impossible = [
    "/",
    "/a",
    "./",
    "../",
    "a/../",
    "a/./b",
    "a//",
    "//",
    "empty//",
    `${MULTIPART_PREFIX}/`,
    `${MULTIPART_PREFIX}/upload-7/`,
  ];

  beforeEach(async () => {
    /* The dotfiles make the `impossible` list non-vacuous: `./` and `../`
       must answer empty *despite* keys that begin with a dot existing, which
       is what separates "matches nothing" from "wrongly refused". */
    await seed(driver, {
      [`${MULTIPART_PREFIX}/upload-7/part-1`]: "staged",
      "a/b.txt": "b",
      "a/.hidden": "h",
      ".dotfile": "d",
      "..x": "x",
      "empty/": "",
    });
  });

  it("treats a trailing partial `.` or `..` as a name prefix, not a segment", async () => {
    /* The re-verification's regression: the segment rule applies to complete
       segments only. `.` is a prefix of every dotfile; only `./` closes the
       segment and matches nothing. */
    for (const [prefix, expected] of [
      [".", ["..x", ".dotfile"]],
      ["..", ["..x"]],
      ["a/.", ["a/.hidden"]],
      ["a/..", []],
    ] as const) {
      const reply = await call(session, {
        target: `/${BUCKET}?list-type=2&prefix=${uriEncode(prefix)}`,
      });
      expect(reply.status, prefix).toBe(200);
      expect(keysOf(reply.text), prefix).toEqual([...expected]);
    }
    healthy();
  });

  it("answers an empty listing, in both modes, and leaks no staging debris", async () => {
    for (const prefix of impossible) {
      for (const delimiter of ["", "&delimiter=/"]) {
        const reply = await call(session, {
          target: `/${BUCKET}?list-type=2${delimiter}&prefix=${uriEncode(prefix)}`,
        });
        const where = `${JSON.stringify(prefix)}${delimiter}`;
        expect(reply.status, where).toBe(200);
        expect(field(reply.text, "KeyCount"), where).toBe("0");
        expect(field(reply.text, "IsTruncated"), where).toBe("false");
        expect(keysOf(reply.text), where).toEqual([]);
        expect(prefixesOf(reply.text), where).toEqual([]);
      }
    }
    healthy();
  });

  it("never names a key a GET would refuse", async () => {
    /* `empty//` used to list as a marker object; `parseObjectKey` refuses that
       key, so a client could read it out of a listing and get a 400 fetching
       it. Both halves are pinned here. */
    const listing = await call(session, {
      target: `/${BUCKET}?list-type=2&prefix=${uriEncode("empty//")}`,
    });
    expect(listing.text).not.toContain("<Key>");
    const fetched = await call(session, { target: `/${BUCKET}/empty//` });
    expect(fetched.status).toBe(400);
    expect(errorCodeOf(fetched)).toBe("InvalidArgument");
    healthy();
  });

  it("still lists everything for the canonical prefixes beside them", async () => {
    const all = await call(session, { target: `/${BUCKET}?list-type=2` });
    expect(keysOf(all.text)).toEqual(["..x", ".dotfile", "a/.hidden", "a/b.txt", "empty/"]);
    const inside = await call(session, {
      target: `/${BUCKET}?list-type=2&prefix=${uriEncode("a/")}`,
    });
    expect(keysOf(inside.text)).toEqual(["a/.hidden", "a/b.txt"]);
    healthy();
  });
});

describe("S3Session: the staging prefix has neighbours", () => {
  beforeEach(async () => {
    await seed(driver, {
      [`${MULTIPART_PREFIX}/upload-7/part-1`]: "staged",
      [`${MULTIPART_PREFIX}2/kept.txt`]: "a neighbour",
      [`${MULTIPART_PREFIX}X`]: "another neighbour",
      "zz.txt": "z",
    });
  });

  it("hides the staging directory and nothing else that starts like it", async () => {
    const flat = await call(session, { target: `/${BUCKET}?list-type=2` });
    expect(keysOf(flat.text)).toEqual([
      `${MULTIPART_PREFIX}2/kept.txt`,
      `${MULTIPART_PREFIX}X`,
      "zz.txt",
    ]);

    const grouped = await call(session, { target: `/${BUCKET}?list-type=2&delimiter=/` });
    expect(keysOf(grouped.text)).toEqual([`${MULTIPART_PREFIX}X`, "zz.txt"]);
    expect(prefixesOf(grouped.text)).toEqual([`${MULTIPART_PREFIX}2/`]);
  });

  it("lists the neighbours under the bare staging name as a prefix, in both modes", async () => {
    const flat = await call(session, {
      target: `/${BUCKET}?list-type=2&prefix=${uriEncode(MULTIPART_PREFIX)}`,
    });
    expect(keysOf(flat.text)).toEqual([`${MULTIPART_PREFIX}2/kept.txt`, `${MULTIPART_PREFIX}X`]);

    const grouped = await call(session, {
      target: `/${BUCKET}?list-type=2&delimiter=/&prefix=${uriEncode(MULTIPART_PREFIX)}`,
    });
    expect(keysOf(grouped.text)).toEqual([`${MULTIPART_PREFIX}X`]);
    expect(prefixesOf(grouped.text)).toEqual([`${MULTIPART_PREFIX}2/`]);
    healthy();
  });
});

describe("S3Session: a prefix is not a directory", () => {
  it("creates the prefix chain a nested PUT names, two levels and four", async () => {
    const two = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/photos/june.jpg`,
      body: "two levels",
    });
    expect(two.status).toBe(200);
    expect((await call(session, { target: `/${BUCKET}/photos/june.jpg` })).text).toBe("two levels");

    const four = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/a/b/c/d.txt`,
      body: "four levels",
    });
    expect(four.status).toBe(200);
    expect((await call(session, { target: `/${BUCKET}/a/b/c/d.txt` })).text).toBe("four levels");

    const listing = await call(session, { target: `/${BUCKET}?list-type=2` });
    expect(keysOf(listing.text)).toEqual(["a/b/c/d.txt", "photos/june.jpg"]);
    healthy();
  });

  it("creates the prefix chain a copy destination names", async () => {
    await call(session, { method: "PUT", target: `/${BUCKET}/source.txt`, body: "copied bytes" });
    const reply = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/deep/deeper/copy.txt`,
      headers: { "x-amz-copy-source": `/${BUCKET}/source.txt` },
    });
    expect(reply.status).toBe(200);
    expect((await call(session, { target: `/${BUCKET}/deep/deeper/copy.txt` })).text).toBe(
      "copied bytes",
    );
    healthy();
  });

  it("creates nothing at all for an upload refused before its first byte", async () => {
    const refused = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/never/made/it.txt`,
      headers: { "content-length": "64" },
      body: deadBody(),
    });
    expect(refused.status).toBe(400);
    expect(errorCodeOf(refused)).toBe("IncompleteBody");
    // No object, and no prefix chain either: the destination was never opened.
    await expect(createLoopback(driver).stat("/never")).rejects.toMatchObject({ code: "ENOENT" });
    healthy();
  });

  it("leaves the prefix and what had been written when an upload dies mid-body", async () => {
    /* The documented limit of writing in place: past the first byte there is a
       partial object, and the prefix that holds it. Pinned so that a future
       temp-and-rename is a deliberate change rather than a surprise. */
    const refused = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/half/there.txt`,
      headers: { "content-length": "64" },
      body: dyingBody(ascii("some of it")),
    });
    expect(refused.status).toBe(400);
    expect((await call(session, { target: `/${BUCKET}/half/there.txt` })).text).toBe("some of it");
    healthy();
  });

  it("answers honestly when a file sits on a component of the prefix", async () => {
    await call(session, { method: "PUT", target: `/${BUCKET}/blocker`, body: "a file, not a dir" });
    const reply = await call(session, {
      method: "PUT",
      target: `/${BUCKET}/blocker/under.txt`,
      body: "nowhere to go",
    });
    // ENOTDIR: the key cannot exist in this tree.
    expect(reply.status).toBe(404);
    expect(errorCodeOf(reply)).toBe("NoSuchKey");
    expect((await call(session, { target: `/${BUCKET}/blocker` })).text).toBe("a file, not a dir");
    healthy();
  });

  it("keeps serving a driver that cannot make directories, where the prefix exists", async () => {
    const base = createMemoryDriver();
    await seed(base, { "existing/file.txt": "here" });
    const { mkdir: _mkdir, ...withoutMkdir } = base;
    const limited = new S3Session({ [BUCKET]: withoutMkdir as FsDriver });
    expect(
      (
        await call(limited, {
          method: "PUT",
          target: `/${BUCKET}/existing/another.txt`,
          body: "beside it",
        })
      ).status,
    ).toBe(200);
    const refused = await call(limited, {
      method: "PUT",
      target: `/${BUCKET}/brand/new.txt`,
      body: "no mkdir here",
    });
    expect(refused.status).toBe(501);
    expect(errorCodeOf(refused)).toBe("NotImplemented");
    healthy(limited);
  });
});

// ---------------------------------------------------------------------------
// multipart
// ---------------------------------------------------------------------------

/**
 * The five multipart operations, against the staging area they share.
 *
 * Three kinds of fact are pinned here and they are not the same kind:
 *
 * - **S3's semantics**, from the API Reference: parts arrive out of order and
 *   are listed in order, a re-uploaded part replaces the first, the part list
 *   (not the staging area) is the object, `Complete` validates order, presence,
 *   the ETag echo and the minimum size, and an upload that is not there is
 *   `NoSuchUpload` whichever operation asked.
 * - **The plan's invisibility decision**, which is what step 6's verify line is
 *   about: with an upload in flight, nothing about it is visible through any
 *   other operation, and after `close()` nothing about it is left at all.
 * - **The races, stated as outcomes rather than as timing**: two operations on
 *   one upload always answer honestly, and never leave a half-assembled object
 *   behind.
 *
 * The parts are real 5 MiB parts wherever a `Complete` has to succeed with more
 * than one of them, because {@link MIN_PART_SIZE} is a rule this gateway
 * enforces and a test that dodged it would be testing something else.
 */
describe("S3Session: multipart uploads", () => {
  const KEY = "big.bin";
  const TARGET = `/${BUCKET}/${KEY}`;

  /** A deterministic byte pattern; two seeds never produce the same bytes. */
  function pattern(size: number, seed: number): Uint8Array {
    const bytes = new Uint8Array(size);
    for (let index = 0; index < size; index++) {
      bytes[index] = (index * 31 + seed * 101 + (index >> 13)) & 0xff;
    }
    return bytes;
  }

  /* Built once: every test that needs a part big enough to sit before the last
     one shares these. */
  const FIRST = pattern(MIN_PART_SIZE, 1);
  const SECOND = pattern(MIN_PART_SIZE, 2);
  const LAST = ascii("the last part, which may be any size at all");

  interface ListedPart {
    partNumber: number;
    etag: string;
    size: number;
  }

  function partsOf(xml: string): ListedPart[] {
    return [...xml.matchAll(/<Part>(.*?)<\/Part>/g)].map((match) => {
      const block = match[1] as string;
      return {
        partNumber: Number(field(block, "PartNumber")),
        etag: field(block, "ETag"),
        size: Number(field(block, "Size")),
      };
    });
  }

  async function createUpload(
    options: { target?: string; headers?: Record<string, string>; on?: S3Session } = {},
  ): Promise<string> {
    const reply = await call(options.on ?? session, {
      method: "POST",
      target: `${options.target ?? TARGET}?uploads`,
      headers: options.headers,
    });
    expect(reply.status).toBe(200);
    return field(reply.text, "UploadId");
  }

  async function uploadPart(
    uploadId: string,
    partNumber: number,
    body: Uint8Array | string,
    options: { target?: string; on?: S3Session } = {},
  ): Promise<Reply> {
    return await call(options.on ?? session, {
      method: "PUT",
      target: `${options.target ?? TARGET}?uploadId=${uploadId}&partNumber=${partNumber}`,
      body,
    });
  }

  function completeDocument(parts: readonly { partNumber: number; etag: string }[]): string {
    const rows = parts
      .map(
        (part) =>
          `<Part><PartNumber>${part.partNumber}</PartNumber><ETag>${part.etag}</ETag></Part>`,
      )
      .join("");
    return `<CompleteMultipartUpload>${rows}</CompleteMultipartUpload>`;
  }

  async function complete(
    uploadId: string,
    parts: readonly { partNumber: number; etag: string }[],
    options: { target?: string; on?: S3Session } = {},
  ): Promise<Reply> {
    return await call(options.on ?? session, {
      method: "POST",
      target: `${options.target ?? TARGET}?uploadId=${uploadId}`,
      headers: { host: "s3.example" },
      body: completeDocument(parts),
    });
  }

  function stagingPath(uploadId: string, name?: string): string {
    return `/${MULTIPART_PREFIX}/${uploadId}${name === undefined ? "" : `/${name}`}`;
  }

  /** Is anything at all left of this upload in the store? */
  async function staged(uploadId: string, on: FsDriver = driver): Promise<string[] | undefined> {
    const entries = await createLoopback(on)
      .readdir(stagingPath(uploadId), { withFileTypes: true })
      .catch(() => undefined);
    return entries?.map((entry) => entry.name).sort();
  }

  it("round-trips an upload whose parts arrive out of order", async () => {
    const created = await call(session, { method: "POST", target: `${TARGET}?uploads` });
    expect(created.status).toBe(200);
    expect(field(created.text, "Bucket")).toBe(BUCKET);
    expect(field(created.text, "Key")).toBe(KEY);
    const uploadId = field(created.text, "UploadId");
    expect(uploadId).toMatch(/^[\da-f]{32}$/);

    const etags = new Map<number, string>();
    for (const [partNumber, bytes] of [
      [3, LAST],
      [1, FIRST],
      [2, SECOND],
    ] as const) {
      const reply = await uploadPart(uploadId, partNumber, bytes);
      expect(reply.status, `part ${partNumber}`).toBe(200);
      expect(reply.headers.etag).toMatch(/^"[\da-f]{32}-1"$/);
      expect(reply.headers["content-length"]).toBe("0");
      etags.set(partNumber, reply.headers.etag as string);
    }

    // Listed in part-number order, whatever order they arrived in.
    const listed = await call(session, { target: `${TARGET}?uploadId=${uploadId}` });
    expect(listed.status).toBe(200);
    expect(field(listed.text, "Key")).toBe(KEY);
    expect(field(listed.text, "UploadId")).toBe(uploadId);
    expect(field(listed.text, "StorageClass")).toBe(STORAGE_CLASS);
    expect(listed.text).toContain(`<ID>${SYNTHETIC_OWNER.id}</ID>`);
    expect(field(listed.text, "IsTruncated")).toBe("false");
    expect(partsOf(listed.text)).toEqual([
      { partNumber: 1, etag: etags.get(1), size: FIRST.byteLength },
      { partNumber: 2, etag: etags.get(2), size: SECOND.byteLength },
      { partNumber: 3, etag: etags.get(3), size: LAST.byteLength },
    ]);

    // One part a page, resumed by part-number-marker.
    const seen: number[] = [];
    let marker = 0;
    for (;;) {
      const page = await call(session, {
        target: `${TARGET}?uploadId=${uploadId}&max-parts=1&part-number-marker=${marker}`,
      });
      expect(field(page.text, "MaxParts")).toBe("1");
      expect(field(page.text, "PartNumberMarker")).toBe(String(marker));
      const parts = partsOf(page.text);
      expect(parts).toHaveLength(1);
      seen.push((parts[0] as ListedPart).partNumber);
      if (field(page.text, "IsTruncated") === "false") {
        expect(page.text).not.toContain("<NextPartNumberMarker>");
        break;
      }
      marker = Number(field(page.text, "NextPartNumberMarker"));
      expect(marker).toBe((parts[0] as ListedPart).partNumber);
    }
    expect(seen).toEqual([1, 2, 3]);

    const completed = await complete(uploadId, [
      { partNumber: 1, etag: etags.get(1) as string },
      { partNumber: 2, etag: etags.get(2) as string },
      { partNumber: 3, etag: etags.get(3) as string },
    ]);
    expect(completed.status).toBe(200);
    expect(field(completed.text, "Bucket")).toBe(BUCKET);
    expect(field(completed.text, "Key")).toBe(KEY);
    expect(field(completed.text, "Location")).toBe(`http://s3.example/${BUCKET}/${KEY}`);

    const object = await call(session, { target: TARGET });
    expect(object.status).toBe(200);
    expect(Buffer.from(object.bytes).equals(Buffer.concat([FIRST, SECOND, LAST]))).toBe(true);
    // The reply's ETag is the assembled object's own, so a GET agrees with it.
    expect(object.headers.etag).toBe(field(completed.text, "ETag"));

    // The staging area is gone, and the upload id names nothing.
    expect(await staged(uploadId)).toBeUndefined();
    expect(
      await createLoopback(driver).readdir(`/${MULTIPART_PREFIX}`, { withFileTypes: true }),
    ).toEqual([]);
    const after = await call(session, { target: `${TARGET}?uploadId=${uploadId}` });
    expect(after.status).toBe(404);
    expect(errorCodeOf(after)).toBe("NoSuchUpload");
    healthy();
  });

  it("answers max-parts=0 as a truncated empty page that a client can resume from", async () => {
    const uploadId = await createUpload();
    await uploadPart(uploadId, 4, "a part");
    const page = await call(session, { target: `${TARGET}?uploadId=${uploadId}&max-parts=0` });
    expect(page.status).toBe(200);
    expect(partsOf(page.text)).toEqual([]);
    expect(field(page.text, "IsTruncated")).toBe("true");
    expect(field(page.text, "NextPartNumberMarker")).toBe("0");
    healthy();
  });

  it("replaces a part that is uploaded twice", async () => {
    const uploadId = await createUpload();
    const first = await uploadPart(uploadId, 1, FIRST);
    const draft = await uploadPart(uploadId, 2, "the first version of the last part");
    const final = await uploadPart(uploadId, 2, "the second version");
    expect(final.headers.etag).not.toBe(draft.headers.etag);

    const listed = await call(session, { target: `${TARGET}?uploadId=${uploadId}` });
    expect(partsOf(listed.text).map((part) => part.partNumber)).toEqual([1, 2]);

    const completed = await complete(uploadId, [
      { partNumber: 1, etag: first.headers.etag as string },
      { partNumber: 2, etag: final.headers.etag as string },
    ]);
    expect(completed.status).toBe(200);
    const object = await call(session, { target: TARGET });
    expect(
      Buffer.from(object.bytes).equals(Buffer.concat([FIRST, ascii("the second version")])),
    ).toBe(true);
    healthy();
  });

  it("assembles the parts the client listed, and discards the rest", async () => {
    const uploadId = await createUpload();
    const first = await uploadPart(uploadId, 1, FIRST);
    await uploadPart(uploadId, 2, "staged and never named");
    const last = await uploadPart(uploadId, 3, LAST);

    const completed = await complete(uploadId, [
      { partNumber: 1, etag: first.headers.etag as string },
      { partNumber: 3, etag: last.headers.etag as string },
    ]);
    expect(completed.status).toBe(200);
    const object = await call(session, { target: TARGET });
    expect(Buffer.from(object.bytes).equals(Buffer.concat([FIRST, LAST]))).toBe(true);
    // The part nobody named went with the staging area.
    expect(await staged(uploadId)).toBeUndefined();
    healthy();
  });

  it("accepts a last part below the minimum, and a single small part alone", async () => {
    const uploadId = await createUpload();
    const only = await uploadPart(uploadId, 1, "three bytes is a whole object");
    const completed = await complete(uploadId, [
      { partNumber: 1, etag: only.headers.etag as string },
    ]);
    expect(completed.status).toBe(200);
    expect((await call(session, { target: TARGET })).text).toBe("three bytes is a whole object");
    healthy();
  });

  it("validates the part list the way S3 does", async () => {
    const uploadId = await createUpload();
    const one = await uploadPart(uploadId, 1, "part one");
    const two = await uploadPart(uploadId, 2, "part two");
    const etag = (reply: Reply): string => reply.headers.etag as string;

    // A part that was never staged.
    const missing = await complete(uploadId, [{ partNumber: 7, etag: `"${"0".repeat(32)}-1"` }]);
    expect(missing.status).toBe(400);
    expect(errorCodeOf(missing)).toBe("InvalidPart");

    // An ETag that is not the staged part's.
    const wrong = await complete(uploadId, [{ partNumber: 2, etag: etag(one) }]);
    expect(wrong.status).toBe(400);
    expect(errorCodeOf(wrong)).toBe("InvalidPart");

    // Descending, and repeated: both are "not in ascending order".
    for (const parts of [
      [
        { partNumber: 2, etag: etag(two) },
        { partNumber: 1, etag: etag(one) },
      ],
      [
        { partNumber: 1, etag: etag(one) },
        { partNumber: 1, etag: etag(one) },
      ],
    ]) {
      const reply = await complete(uploadId, parts);
      expect(reply.status).toBe(400);
      expect(errorCodeOf(reply)).toBe("InvalidPartOrder");
    }

    // A part below the minimum that is not the last one.
    const small = await complete(uploadId, [
      { partNumber: 1, etag: etag(one) },
      { partNumber: 2, etag: etag(two) },
    ]);
    expect(small.status).toBe(400);
    expect(errorCodeOf(small)).toBe("EntityTooSmall");

    // Nothing above touched the staging area, and no object was created.
    expect(await staged(uploadId)).toEqual(["part-1", "part-2", "upload.json"]);
    expect((await call(session, { target: TARGET })).status).toBe(404);
    healthy();
  });

  it("keeps the upload alive when the assembly fails, so the retry works", async () => {
    /* A driver whose reads of one named file fail. `Complete` opens the parts
       in the order it was given, so this fails *after* the first part has been
       written into the destination. */
    let broken: string | undefined;
    const base = createMemoryDriver();
    const brittle: FsDriver = {
      ...base,
      open: async (path, flags, mode) => {
        if (broken !== undefined && path.endsWith(broken) && flags === "r") {
          throw fsError("EIO");
        }
        return await base.open(path, flags, mode);
      },
    };
    const brittleSession = new S3Session({ [BUCKET]: brittle });
    const uploadId = await createUpload({ on: brittleSession });
    const first = await uploadPart(uploadId, 1, FIRST, { on: brittleSession });
    const last = await uploadPart(uploadId, 2, LAST, { on: brittleSession });
    const parts = [
      { partNumber: 1, etag: first.headers.etag as string },
      { partNumber: 2, etag: last.headers.etag as string },
    ];

    broken = "part-2";
    const failed = await complete(uploadId, parts, { on: brittleSession });
    expect(failed.status).toBe(500);
    expect(errorCodeOf(failed)).toBe("InternalError");
    // The staging area survives a failed Complete: S3 keeps the upload alive.
    expect(await staged(uploadId, brittle)).toEqual(["part-1", "part-2", "upload.json"]);

    broken = undefined;
    const retried = await complete(uploadId, parts, { on: brittleSession });
    expect(retried.status).toBe(200);
    const object = await call(brittleSession, { target: TARGET });
    expect(Buffer.from(object.bytes).equals(Buffer.concat([FIRST, LAST]))).toBe(true);
    expect(await staged(uploadId, brittle)).toBeUndefined();
    healthy(brittleSession);
  });

  it("aborts an upload, and answers NoSuchUpload for everything afterwards", async () => {
    const uploadId = await createUpload();
    const part = await uploadPart(uploadId, 1, "staged bytes");
    expect(await staged(uploadId)).toEqual(["part-1", "upload.json"]);

    const aborted = await call(session, {
      method: "DELETE",
      target: `${TARGET}?uploadId=${uploadId}`,
    });
    expect(aborted.status).toBe(204);
    expect(aborted.bytes.byteLength).toBe(0);
    expect(await staged(uploadId)).toBeUndefined();

    for (const request of [
      { method: "PUT", target: `${TARGET}?uploadId=${uploadId}&partNumber=1`, body: "late" },
      { method: "GET", target: `${TARGET}?uploadId=${uploadId}` },
      { method: "DELETE", target: `${TARGET}?uploadId=${uploadId}` },
    ] satisfies Request[]) {
      const reply = await call(session, request);
      expect(reply.status, request.method).toBe(404);
      expect(errorCodeOf(reply), request.method).toBe("NoSuchUpload");
    }
    const completed = await complete(uploadId, [
      { partNumber: 1, etag: part.headers.etag as string },
    ]);
    expect(completed.status).toBe(404);
    expect(errorCodeOf(completed)).toBe("NoSuchUpload");
    // A part that arrived after the abort created nothing.
    expect(await staged(uploadId)).toBeUndefined();
    healthy();
  });

  it("answers honestly when a Complete and an Abort race", async () => {
    const uploadId = await createUpload();
    const only = await uploadPart(uploadId, 1, "the whole object in one part");
    const [completed, aborted] = await Promise.all([
      complete(uploadId, [{ partNumber: 1, etag: only.headers.etag as string }]),
      call(session, { method: "DELETE", target: `${TARGET}?uploadId=${uploadId}` }),
    ]);
    /* Whichever won, the loser is told the upload is gone rather than given a
       half-assembled object, and the staging area is gone either way. */
    const outcome = `${completed.status}/${aborted.status}`;
    expect(["200/404", "404/204"]).toContain(outcome);
    const object = await call(session, { target: TARGET });
    if (outcome === "200/404") {
      expect(errorCodeOf(aborted)).toBe("NoSuchUpload");
      expect(object.text).toBe("the whole object in one part");
    } else {
      expect(errorCodeOf(completed)).toBe("NoSuchUpload");
      expect(object.status).toBe(404);
    }
    expect(await staged(uploadId)).toBeUndefined();
    healthy();
  });

  it("sweeps every bucket's staging area on close, and keeps answering", async () => {
    const second = createMemoryDriver();
    const twoBuckets = new S3Session({ [BUCKET]: driver, other: second });
    const first = await createUpload({ on: twoBuckets });
    await uploadPart(first, 1, "in the first bucket", { on: twoBuckets });
    const other = await createUpload({ on: twoBuckets, target: `/other/${KEY}` });
    await uploadPart(other, 2, "in the other bucket", {
      on: twoBuckets,
      target: `/other/${KEY}`,
    });

    await twoBuckets.close();
    for (const store of [driver, second]) {
      await expect(createLoopback(store).stat(`/${MULTIPART_PREFIX}`)).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
    // Idempotent, and the session still answers.
    await twoBuckets.close();
    const gone = await call(twoBuckets, { target: `${TARGET}?uploadId=${first}` });
    expect(gone.status).toBe(404);
    expect(errorCodeOf(gone)).toBe("NoSuchUpload");
    expect(
      (await call(twoBuckets, { method: "PUT", target: TARGET, body: "after close" })).status,
    ).toBe(200);
    healthy(twoBuckets);
  });

  it("refuses a hostile upload id without touching a driver", async () => {
    const base = createMemoryDriver();
    const calls: string[] = [];
    const counted = new Proxy(base, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver) as unknown;
        if (typeof value !== "function") {
          return value;
        }
        return (...args: unknown[]) => {
          calls.push(String(property));
          return (value as (...rest: unknown[]) => unknown).apply(target, args);
        };
      },
    }) as FsDriver;
    const watched = new S3Session({ [BUCKET]: counted });
    calls.length = 0;

    for (const uploadId of [
      "..%2Fx",
      "a%2Fb",
      "%2E%2E",
      "0".repeat(31),
      "0".repeat(33),
      "Z".repeat(32),
      `${"0".repeat(30)}-1`,
      // Hex, the right width, and upper case: not an id this gateway mints.
      "abcdef0123456789abcdef0123456789".toUpperCase(),
    ]) {
      for (const request of [
        { method: "GET", target: `${TARGET}?uploadId=${uploadId}` },
        { method: "DELETE", target: `${TARGET}?uploadId=${uploadId}` },
        { method: "PUT", target: `${TARGET}?uploadId=${uploadId}&partNumber=1`, body: "x" },
        { method: "POST", target: `${TARGET}?uploadId=${uploadId}`, body: "<x/>" },
      ] satisfies Request[]) {
        const reply = await call(watched, request);
        expect(reply.status, `${request.method} ${uploadId}`).toBe(404);
        expect(errorCodeOf(reply), `${request.method} ${uploadId}`).toBe("NoSuchUpload");
      }
    }
    expect(calls).toEqual([]);
    /* An **empty** `?uploadId=` never reaches the session at all: the router
       refuses it as `InvalidArgument`, which is where that decision was made
       (step 4) and where it is tested. */
    const empty = await call(watched, { target: `${TARGET}?uploadId=` });
    expect(empty.status).toBe(400);
    expect(errorCodeOf(empty)).toBe("InvalidArgument");
    healthy(watched);
  });

  it("refuses an upload id that belongs to another key", async () => {
    const uploadId = await createUpload();
    const elsewhere = `/${BUCKET}/other.bin`;
    for (const request of [
      { method: "GET", target: `${elsewhere}?uploadId=${uploadId}` },
      { method: "PUT", target: `${elsewhere}?uploadId=${uploadId}&partNumber=1`, body: "x" },
      { method: "DELETE", target: `${elsewhere}?uploadId=${uploadId}` },
    ] satisfies Request[]) {
      const reply = await call(session, request);
      expect(reply.status, request.method).toBe(404);
      expect(errorCodeOf(reply), request.method).toBe("NoSuchUpload");
    }
    // ... and the upload it does belong to is untouched.
    expect(await staged(uploadId)).toEqual(["upload.json"]);
    healthy();
  });

  it("refuses to upload a directory key in parts", async () => {
    const reply = await call(session, { method: "POST", target: `/${BUCKET}/photos/?uploads` });
    expect(reply.status).toBe(400);
    expect(errorCodeOf(reply)).toBe("InvalidRequest");
    healthy();
  });

  it("applies the caps and the length rules a PUT is held to", async () => {
    const uploadId = await createUpload();
    const capped = new S3Session({ [BUCKET]: driver }, { maxBodyBytes: 8 });
    const big = await uploadPart(uploadId, 1, "far more than eight bytes", { on: capped });
    expect(big.status).toBe(400);
    expect(errorCodeOf(big)).toBe("EntityTooLarge");

    const unmeasured = await call(session, {
      method: "PUT",
      target: `${TARGET}?uploadId=${uploadId}&partNumber=1`,
      body: "no length at all",
      omitContentLength: true,
    });
    expect(unmeasured.status).toBe(411);
    expect(errorCodeOf(unmeasured)).toBe("MissingContentLength");
    healthy();
    healthy(capped);
  });

  it("carries x-amz-meta-mtime from Create through to the assembled object", async () => {
    const uploadId = await createUpload({ headers: { "x-amz-meta-mtime": "1700000000" } });
    const only = await uploadPart(uploadId, 1, "timestamped bytes");
    expect(
      (await complete(uploadId, [{ partNumber: 1, etag: only.headers.etag as string }])).status,
    ).toBe(200);
    const head = await call(session, { method: "HEAD", target: TARGET });
    expect(head.headers["x-amz-meta-mtime"]).toBe("1700000000");
    expect(head.headers["last-modified"]).toBe(formatHttpDate(1_700_000_000_000));
    healthy();
  });

  it("picks up an upload another session started, because the manifest is a file", async () => {
    const uploadId = await createUpload();
    const first = await uploadPart(uploadId, 1, FIRST);
    const last = await uploadPart(uploadId, 2, LAST);

    // A new process, over the same store: nothing in memory survived.
    const restarted = new S3Session({ [BUCKET]: driver });
    const listed = await call(restarted, { target: `${TARGET}?uploadId=${uploadId}` });
    expect(listed.status).toBe(200);
    expect(partsOf(listed.text).map((part) => part.etag)).toEqual([
      first.headers.etag,
      last.headers.etag,
    ]);
    const completed = await complete(
      uploadId,
      [
        { partNumber: 1, etag: first.headers.etag as string },
        { partNumber: 2, etag: last.headers.etag as string },
      ],
      { on: restarted },
    );
    expect(completed.status).toBe(200);
    const object = await call(restarted, { target: TARGET });
    expect(Buffer.from(object.bytes).equals(Buffer.concat([FIRST, LAST]))).toBe(true);
    healthy(restarted);
  });

  it("stays invisible while an upload is in flight", async () => {
    await seed(driver, { "visible.txt": "seen" });
    const uploadId = await createUpload();
    await uploadPart(uploadId, 1, "staged bytes");

    for (const query of ["list-type=2", "list-type=2&delimiter=/"]) {
      const listing = await call(session, { target: `/${BUCKET}?${query}` });
      expect(keysOf(listing.text), query).toEqual(["visible.txt"]);
      expect(prefixesOf(listing.text).join(" "), query).not.toContain(MULTIPART_PREFIX);
      expect(listing.text, query).not.toContain(uploadId);
    }

    // The staged part answers as an absent key does, by method — and survives.
    const stagedKey = `/${BUCKET}${stagingPath(uploadId, "part-1")}`;
    expect((await call(session, { target: stagedKey })).status).toBe(404);
    expect((await call(session, { method: "PUT", target: stagedKey, body: "x" })).status).toBe(404);
    expect((await call(session, { method: "DELETE", target: stagedKey })).status).toBe(204);
    expect(await staged(uploadId)).toEqual(["part-1", "upload.json"]);
    const listed = await call(session, { target: `${TARGET}?uploadId=${uploadId}` });
    expect(partsOf(listed.text)).toHaveLength(1);
    healthy();
  });

  it("treats a manifest it cannot read as an upload that is not there", async () => {
    const uploadId = await createUpload();
    const loop = createLoopback(driver);
    for (const manifest of [
      "not json at all",
      "7",
      "[]",
      `{"key":"another.bin"}`,
      `{"mtime":17}`,
    ]) {
      await loop.writeFile(stagingPath(uploadId, "upload.json"), manifest);
      const reply = await call(session, { target: `${TARGET}?uploadId=${uploadId}` });
      expect(reply.status, manifest).toBe(404);
      expect(errorCodeOf(reply), manifest).toBe("NoSuchUpload");
    }
    healthy();
  });

  it("lists only well-formed part files, and sweeps everything else away", async () => {
    const uploadId = await createUpload();
    const part = await uploadPart(uploadId, 1, "a real part");
    const loop = createLoopback(driver);
    /* Nothing here is written by this gateway. It is what a store shared with
       something else, or interrupted half way, can look like. */
    await loop.writeFile(stagingPath(uploadId, "part-01"), "a padded number is not a part");
    await loop.writeFile(stagingPath(uploadId, "part-20000"), "outside 1..10000");
    await loop.writeFile(stagingPath(uploadId, "notes.txt"), "not a part either");
    await loop.mkdir(stagingPath(uploadId, "part-2"), { recursive: true });

    const listed = await call(session, { target: `${TARGET}?uploadId=${uploadId}` });
    expect(partsOf(listed.text)).toEqual([
      { partNumber: 1, etag: part.headers.etag, size: "a real part".length },
    ]);

    const aborted = await call(session, {
      method: "DELETE",
      target: `${TARGET}?uploadId=${uploadId}`,
    });
    expect(aborted.status).toBe(204);
    // The subtree goes whole, directories and strangers included.
    expect(await staged(uploadId)).toBeUndefined();
    healthy();
  });

  it("answers NoSuchUpload for a part whose staging directory vanished under it", async () => {
    /* The race the module docs name: the manifest read wins, and the write
       finds the directory an `Abort` already removed. A part is never allowed
       to recreate it, so the answer is about the upload, not about a key. */
    const base = createMemoryDriver();
    let vanished = false;
    const racing: FsDriver = {
      ...base,
      open: async (path, flags, mode) => {
        if (vanished && path.startsWith(`/${MULTIPART_PREFIX}/`) && flags === "w") {
          throw fsError("ENOENT");
        }
        return await base.open(path, flags, mode);
      },
    };
    const racy = new S3Session({ [BUCKET]: racing });
    const uploadId = await createUpload({ on: racy });
    vanished = true;
    const late = await uploadPart(uploadId, 1, "too late", { on: racy });
    expect(late.status).toBe(404);
    expect(errorCodeOf(late)).toBe("NoSuchUpload");
    expect(await staged(uploadId, racing)).toEqual(["upload.json"]);
    healthy(racy);
  });

  it("reports a sweep it could not finish instead of throwing on the way out", async () => {
    const seen: unknown[] = [];
    const base = createMemoryDriver();
    const hostile: FsDriver = {
      ...base,
      readdir: async (path, options) => {
        if (path === `/${MULTIPART_PREFIX}`) {
          throw fsError("EACCES");
        }
        return await base.readdir(path, options);
      },
    };
    const guarded = new S3Session({ [BUCKET]: hostile }, { onError: (error) => seen.push(error) });
    const uploadId = await createUpload({ on: guarded });
    await expect(guarded.close()).resolves.toBeUndefined();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ code: "EACCES" });
    // Nothing was swept, and the upload is still there to be aborted by hand.
    expect(await staged(uploadId, hostile)).toEqual(["upload.json"]);
    healthy(guarded);
  });

  it("takes a signed aws-chunked part, and stores nothing when a chunk is tampered with", async () => {
    const secure = new S3Session(
      { [BUCKET]: driver },
      { credentials: CREDENTIALS, now: () => NOW },
    );
    const created = signHeaders({
      method: "POST",
      target: `${TARGET}?uploads`,
      payloadHash: EMPTY_PAYLOAD_SHA256,
    });
    const create = await call(secure, {
      method: "POST",
      target: `${TARGET}?uploads`,
      headerEntries: created.headers,
    });
    expect(create.status).toBe(200);
    const uploadId = field(create.text, "UploadId");

    const payload = ascii("a part sent as signed chunks");
    const target = `${TARGET}?uploadId=${uploadId}&partNumber=1`;
    const signedFor = (length: number): Signed =>
      signHeaders({
        method: "PUT",
        target,
        payloadHash: STREAMING_PAYLOAD,
        headers: {
          "content-encoding": "aws-chunked",
          "x-amz-decoded-content-length": String(payload.byteLength),
          "content-length": String(length),
        },
      });
    const material = (signed: Signed): ChunkedSignature => ({
      seed: signed.signature,
      amzDate: signed.amzDate,
      scope: signed.scope,
      secretAccessKey: CREDENTIALS.secretAccessKey,
    });
    const draft = signedFor(0);
    const length = chunkedBody([payload], { signature: material(draft) }).byteLength;
    const signed = signedFor(length);
    const body = chunkedBody([payload], { signature: material(signed) });

    const part = await call(secure, {
      method: "PUT",
      target,
      headerEntries: signed.headers,
      body: oneChunk(body),
    });
    expect(part.status).toBe(200);
    expect(await createLoopback(driver).readFile(stagingPath(uploadId, "part-1"))).toEqual(payload);

    /* A tampered chunk on part 2: the seed is not the request's signature, so
       the first chunk fails and the destination is never opened — the same
       buffer-then-verify guarantee `PutObject` gives, and the same limit, that
       a *later* chunk failing leaves the bytes already written. */
    const secondTarget = `${TARGET}?uploadId=${uploadId}&partNumber=2`;
    const secondDraft = signHeaders({
      method: "PUT",
      target: secondTarget,
      payloadHash: STREAMING_PAYLOAD,
      headers: {
        "content-encoding": "aws-chunked",
        "x-amz-decoded-content-length": String(payload.byteLength),
        "content-length": "0",
      },
    });
    const tampered = await call(secure, {
      method: "PUT",
      target: secondTarget,
      headerEntries: secondDraft.headers,
      body: oneChunk(
        chunkedBody([payload], {
          signature: {
            seed: "0".repeat(64),
            amzDate: secondDraft.amzDate,
            scope: secondDraft.scope,
            secretAccessKey: CREDENTIALS.secretAccessKey,
          },
        }),
      ),
    });
    expect(tampered.status).toBe(403);
    expect(errorCodeOf(tampered)).toBe("SignatureDoesNotMatch");
    // Part 2 was never created, and part 1 is intact.
    expect(await staged(uploadId)).toEqual(["part-1", "upload.json"]);
    expect(await createLoopback(driver).readFile(stagingPath(uploadId, "part-1"))).toEqual(payload);
    healthy(secure);
  });
});
