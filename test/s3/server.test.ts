/**
 * The S3 gateway over a real socket: `createS3Server()`, `fetch`, and
 * `node:http` on the client side where `fetch` cannot say what has to be said.
 *
 * Everything below `server.ts` is already pinned in-process by
 * `session.test.ts`, so what is checked here is only what a socket adds:
 *
 * - **The bind gate.** Without credentials the gateway is loopback-only, and
 *   the refusal happens in `createS3Server()` — synchronously, before a server
 *   object exists, which is what "nothing listened" means here.
 * - **Framing over the wire.** `HEAD` carrying headers and no bytes,
 *   `Expect: 100-continue`, `aws-chunked` arriving as an actual HTTP body,
 *   keep-alive, pipelining, and the `411` a `Transfer-Encoding: chunked`
 *   request earns — plus the one message HTTP cannot recover from, a body that
 *   ends short of its `Content-Length`, which must take the connection with it
 *   rather than leave a client waiting for bytes that are not coming.
 * - **Streaming in both directions.** Backpressure from a reader that stops
 *   reading, and an abandoned download releasing the file handle it opened.
 * - **`close()`.** In-flight responses finish, a response past the deadline is
 *   cut, staging is swept, and the second call is free.
 *
 * Every port is ephemeral (`port: 0`), every wait is bounded, and no literal
 * control character appears in this file.
 */

import { Agent, request as httpRequest, type IncomingMessage } from "node:http";
import { connect } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { createLoopback } from "../../src/harness.ts";
import type { FileHandleLike, FsDriver } from "../../src/types.ts";
import { signChunk, type ChunkedSignature } from "../../src/s3/chunked.ts";
import { MIN_PART_SIZE, MULTIPART_PREFIX, STREAMING_PAYLOAD } from "../../src/s3/constants.ts";
import { parseRequestTarget } from "../../src/s3/protocol.ts";
import {
  createS3Server,
  isLoopbackHost,
  isS3BindError,
  loopbackRefusal,
  S3BindError,
  type S3Server,
  type S3ServerOptions,
  type S3Source,
} from "../../src/s3/server.ts";
import {
  EMPTY_PAYLOAD_SHA256,
  formatAmzDate,
  sha256Hex,
  signRequest,
  type CredentialScope,
  type HeaderEntry,
} from "../../src/s3/sigv4.ts";

// ---------------------------------------------------------------------------
// fixtures and helpers
// ---------------------------------------------------------------------------

const BUCKET = "mountx";
const REGION = "eu-west-3";
const CREDENTIALS = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};
const CRLF = "\r\n";
const encoder = new TextEncoder();
/** A body big enough to still be streaming when a 50 ms deadline expires. */
const SLOW_SIZE = 512 * 1024;

/** Every server this file started, closed after each test whatever happened. */
const running: S3Server[] = [];

afterEach(async () => {
  for (const server of running.splice(0)) {
    await server.close();
  }
});

async function serve(source: S3Source, options: S3ServerOptions = {}): Promise<S3Server> {
  const server = createS3Server(source, options);
  running.push(server);
  await server.listen();
  return server;
}

function ascii(text: string): Uint8Array {
  return encoder.encode(text);
}

function text(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("utf8");
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

/** The XML element's text, the way the session tests read one. */
function field(block: string, name: string): string {
  const match = new RegExp(`<${name}>([^<]*)</${name}>`).exec(block);
  return match === null ? "" : (match[1] as string);
}

/** Bytes that are not all the same, so a truncation cannot pass as a match. */
function pattern(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let index = 0; index < size; index++) {
    bytes[index] = (index * 31 + (index >> 8)) & 0xff;
  }
  return bytes;
}

/**
 * A `fetch` body from bytes.
 *
 * `BodyInit` does not accept a plain `Uint8Array` under this TypeScript's DOM
 * types, and a `Blob` is the spelling that keeps `Content-Length` — which every
 * `PUT` here needs, since an identity body without one is a `411`.
 */
function bodyOf(bytes: Uint8Array): BodyInit {
  return new Blob([new Uint8Array(bytes)]);
}

/**
 * Two byte strings are the same.
 *
 * Through a hash rather than `toEqual`, which walks a multi-megabyte typed
 * array element by element and turns a passing assertion into a test timeout.
 */
function same(actual: Uint8Array, expected: Uint8Array): void {
  expect({ bytes: actual.byteLength, sha256: sha256Hex(actual) }).toEqual({
    bytes: expected.byteLength,
    sha256: sha256Hex(expected),
  });
}

async function until(predicate: () => boolean, label: string, timeout = 2000): Promise<void> {
  const deadline = Date.now() + timeout;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${label}`);
    }
    await delay(5);
  }
}

// --- raw HTTP, for what `fetch` will not send ---

interface RawOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: Uint8Array | string;
  /** Hold the body back until the server answers `100 Continue`. */
  expectContinue?: boolean;
  agent?: Agent;
}

function rawRequest(url: string, options: RawOptions = {}): Promise<IncomingMessage> {
  return new Promise<IncomingMessage>((resolve, reject) => {
    const request = httpRequest(
      url,
      { method: options.method ?? "GET", headers: options.headers, agent: options.agent },
      resolve,
    );
    request.on("error", reject);
    const send = (): void => {
      if (options.body === undefined) {
        request.end();
      } else {
        request.end(options.body);
      }
    };
    if (options.expectContinue === true) {
      request.on("continue", send);
      request.flushHeaders();
    } else {
      send();
    }
  });
}

async function readAll(response: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of response) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

// --- signing ---

interface Signed {
  headers: Record<string, string>;
  signature: string;
  scope: CredentialScope;
  amzDate: string;
}

/**
 * Sign a request for a server that is actually listening.
 *
 * The `host` header has to be the one the client will really send — `signRequest`
 * signs the value, and `127.0.0.1:52341` is not `s3.example` — so it comes from
 * the server's own URL and is passed back to the client explicitly.
 */
function sign(
  server: S3Server,
  input: {
    method: string;
    target: string;
    payloadHash: string;
    headers?: Record<string, string>;
    timestamp?: number;
  },
): Signed {
  const parsed = parseRequestTarget(input.target);
  if (!parsed.ok) {
    throw new Error(`unsignable target ${input.target}`);
  }
  const timestamp = input.timestamp ?? Date.now();
  const base: HeaderEntry[] = [
    { name: "host", value: new URL(server.url).host },
    { name: "x-amz-date", value: formatAmzDate(timestamp) },
    { name: "x-amz-content-sha256", value: input.payloadHash },
    ...Object.entries(input.headers ?? {}).map(([name, value]) => ({ name, value })),
  ];
  const signed = signRequest({
    method: input.method,
    path: parsed.target.path,
    query: parsed.target.query,
    headers: base,
    credentials: CREDENTIALS,
    region: REGION,
    timestamp,
    payloadHash: input.payloadHash,
  });
  return {
    headers: {
      ...Object.fromEntries(base.map((header) => [header.name, header.value])),
      authorization: signed.authorization,
    },
    signature: signed.signature,
    scope: signed.scope,
    amzDate: signed.amzDate,
  };
}

/** An `aws-chunked` body, framed and signed with the module's own primitives. */
function chunkedBody(payloads: readonly Uint8Array[], signature: ChunkedSignature): Uint8Array {
  const frames: Uint8Array[] = [];
  let previous = signature.seed;
  for (const payload of [...payloads, new Uint8Array(0)]) {
    const chunkSignature = signChunk(signature, previous, sha256Hex(payload));
    previous = chunkSignature;
    const header = `${payload.byteLength.toString(16)};chunk-signature=${chunkSignature}`;
    frames.push(
      payload.byteLength === 0
        ? ascii(header + CRLF)
        : concat([ascii(header + CRLF), payload, ascii(CRLF)]),
    );
  }
  frames.push(ascii(CRLF));
  return concat(frames);
}

// --- drivers ---

interface Counted {
  driver: FsDriver;
  /** Handles opened, and handles closed. Equal once nothing is in flight. */
  counts: { opened: number; closed: number };
}

/**
 * A driver that counts open handles, and can be told to make every read slow.
 *
 * The counts are what proves an abandoned download released its descriptor:
 * the `GET` generator closes the handle in a `finally`, and only the transport
 * can make that `finally` run.
 */
function counting(inner: FsDriver, readDelayMs = 0): Counted {
  const counts = { opened: 0, closed: 0 };
  const driver: FsDriver = {
    ...inner,
    open: async (path, flags, mode): Promise<FileHandleLike> => {
      const handle = await inner.open(path, flags, mode);
      counts.opened++;
      return {
        ...handle,
        read: async (buffer, offset, length, position) => {
          if (readDelayMs > 0) {
            await delay(readDelayMs);
          }
          return await handle.read(buffer, offset, length, position);
        },
        close: async () => {
          counts.closed++;
          await handle.close();
        },
      };
    },
  };
  return { driver, counts };
}

/**
 * A driver whose reads stop delivering after `deliver` bytes of `path`, while
 * `stat` keeps reporting the whole size.
 *
 * Exactly the shape of the TOCTOU the passthrough driver lives with: another
 * process truncates the file between the `stat` that fixed the
 * `Content-Length` and the reads that were supposed to fill it. `streamHandle`
 * ends the body on a short read, and the reply is then one HTTP cannot
 * terminate — which is what the transport has to notice.
 */
function truncating(inner: FsDriver, name: string, deliver: number): FsDriver {
  return {
    ...inner,
    open: async (path, flags, mode): Promise<FileHandleLike> => {
      const handle = await inner.open(path, flags, mode);
      if (!path.endsWith(name)) {
        return handle;
      }
      return {
        ...handle,
        read: async (buffer, offset, length, position) => {
          const at = Number(position ?? 0);
          const room = deliver - at;
          if (room <= 0) {
            // A short read is how `streamHandle` learns the file ended early.
            return { bytesRead: 0, buffer };
          }
          const wanted = length === undefined || length === null ? room : Math.min(length, room);
          return await handle.read(buffer, offset, wanted, position);
        },
      };
    },
  };
}

// ---------------------------------------------------------------------------

describe("createS3Server: the bind gate", () => {
  it("accepts every literal loopback spelling and nothing else", () => {
    for (const host of [
      "127.0.0.1",
      "127.0.0.53",
      "127.255.255.255",
      "localhost",
      "LOCALHOST",
      "::1",
      "[::1]",
      "::ffff:127.0.0.1",
    ]) {
      expect({ host, loopback: isLoopbackHost(host) }).toEqual({ host, loopback: true });
    }
    for (const host of [
      "",
      "0.0.0.0",
      "::",
      "[::]",
      "192.168.1.10",
      "127.0.0.256",
      "128.0.0.1",
      "1270.0.0.1",
      "example.com",
      // A name that resolves to loopback is still a name: nothing here resolves.
      "localhost.localdomain",
    ]) {
      expect({ host, loopback: isLoopbackHost(host) }).toEqual({ host, loopback: false });
    }
  });

  it("names the unspecified addresses as the danger they are", () => {
    expect(loopbackRefusal("0.0.0.0", false)).toContain("binds every interface");
    expect(loopbackRefusal("::", false)).toContain("binds every interface");
    expect(loopbackRefusal("", false)).toContain("every interface");
    expect(loopbackRefusal("203.0.113.7", false)).toContain("reachable from outside");
    expect(loopbackRefusal("203.0.113.7", false)).toContain("credentials");
    // With credentials, or on loopback, there is nothing to say.
    expect(loopbackRefusal("203.0.113.7", true)).toBeUndefined();
    expect(loopbackRefusal("127.0.0.1", false)).toBeUndefined();
  });

  it("refuses a non-loopback bind with no credentials, before anything listens", () => {
    for (const host of ["0.0.0.0", "::", "192.0.2.10", "s3.example.com"]) {
      /* Synchronous, out of `createS3Server()` itself: there is no server
         object, so there is nothing that could have bound a socket. */
      let thrown: unknown;
      try {
        createS3Server(createMemoryDriver(), { host });
      } catch (error) {
        thrown = error;
      }
      expect({ host, refused: isS3BindError(thrown) }).toEqual({ host, refused: true });
      expect(thrown).toBeInstanceOf(S3BindError);
      expect((thrown as S3BindError).code).toBe("ERR_S3_BIND");
      expect((thrown as S3BindError).host).toBe(host);
      expect((thrown as S3BindError).name).toBe("S3BindError");
    }
  });

  it("allows any bind once credentials are configured", () => {
    /* Constructed, not listened: binding every interface from a unit test is
       exactly the thing the gate exists to think twice about. */
    const server = createS3Server(createMemoryDriver(), {
      host: "0.0.0.0",
      credentials: CREDENTIALS,
    });
    expect(server.host).toBe("0.0.0.0");
    expect(server.url).toBe("http://0.0.0.0:0");
  });

  it("refuses a value that is neither a driver nor a bucket map", () => {
    expect(() => createS3Server({} as unknown as S3Source)).toThrow(TypeError);
    expect(() => createS3Server({ buckets: {} } as S3Source)).not.toThrow();
    // A half-driver is not a driver: `stat` alone is not the required three.
    expect(() => createS3Server({ stat: async () => ({}) } as unknown as S3Source)).toThrow(
      TypeError,
    );
  });

  it("refuses a bucket name that cannot be a path segment", () => {
    for (const bucket of ["", ".", "..", "a/b"]) {
      expect(() => createS3Server(createMemoryDriver(), { bucket })).toThrow(TypeError);
    }
  });
});

describe("createS3Server: the object round trip over HTTP", () => {
  it("puts, gets, heads, lists and deletes through fetch", async () => {
    const driver = createMemoryDriver();
    const server = await serve(driver);
    expect(server.buckets).toEqual([BUCKET]);
    expect(server.url).toBe(`http://127.0.0.1:${server.port}`);
    expect(server.port).toBeGreaterThan(0);

    const put = await fetch(`${server.url}/${BUCKET}/hello.txt`, {
      method: "PUT",
      body: "hello world",
    });
    expect(put.status).toBe(200);
    const etag = put.headers.get("etag");
    expect(etag).toMatch(/^"[\da-f]{32}-1"$/);
    await put.arrayBuffer();

    const got = await fetch(`${server.url}/${BUCKET}/hello.txt`);
    expect(got.status).toBe(200);
    expect(got.headers.get("etag")).toBe(etag);
    expect(got.headers.get("content-length")).toBe("11");
    expect(await got.text()).toBe("hello world");

    const head = await fetch(`${server.url}/${BUCKET}/hello.txt`, { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(head.headers.get("content-length")).toBe("11");
    expect(await head.arrayBuffer()).toEqual(new ArrayBuffer(0));

    const listed = await fetch(`${server.url}/${BUCKET}?list-type=2`);
    expect(listed.status).toBe(200);
    expect(listed.headers.get("content-type")).toBe("application/xml");
    const listing = await listed.text();
    expect(listing).toContain("<Key>hello.txt</Key>");

    const missing = await fetch(`${server.url}/${BUCKET}/ghost.txt`);
    expect(missing.status).toBe(404);
    expect(field(await missing.text(), "Code")).toBe("NoSuchKey");

    const removed = await fetch(`${server.url}/${BUCKET}/hello.txt`, { method: "DELETE" });
    expect(removed.status).toBe(204);
    await removed.arrayBuffer();
    await expect(createLoopback(driver).stat("/hello.txt")).rejects.toThrow();

    expect(server.session.assertions).toEqual([]);
    expect(server.session.stats.replies).toBe(server.session.stats.requests);
  });

  it("answers DeleteObjects over the wire", async () => {
    const driver = createMemoryDriver();
    const server = await serve(driver);
    await fetch(`${server.url}/${BUCKET}/one.txt`, { method: "PUT", body: "1" });
    await fetch(`${server.url}/${BUCKET}/two.txt`, { method: "PUT", body: "2" });

    const reply = await fetch(`${server.url}/${BUCKET}?delete`, {
      method: "POST",
      body: "<Delete><Object><Key>one.txt</Key></Object><Object><Key>ghost</Key></Object></Delete>",
    });
    expect(reply.status).toBe(200);
    const document = await reply.text();
    expect(document).toContain("<Deleted><Key>one.txt</Key></Deleted>");
    expect(document).toContain("<Deleted><Key>ghost</Key></Deleted>");
    expect(text(await createLoopback(driver).readFile("/two.txt"))).toBe("2");
  });

  it("runs a multipart upload end to end", async () => {
    const driver = createMemoryDriver();
    const server = await serve(driver);
    const key = `${server.url}/${BUCKET}/big.bin`;

    const created = await fetch(`${key}?uploads`, { method: "POST" });
    expect(created.status).toBe(200);
    const uploadId = field(await created.text(), "UploadId");
    expect(uploadId).toMatch(/^[\da-f]{32}$/);

    /* The first part is `MIN_PART_SIZE`, because S3's own rule is that every
       part but the last must be — and this is the case that proves the
       assembly, and the 5 MiB body, survive a socket. */
    const pieces = [pattern(MIN_PART_SIZE), ascii("and the tail end of it")];
    const parts: { partNumber: number; etag: string }[] = [];
    for (const [index, piece] of pieces.entries()) {
      const uploaded = await fetch(`${key}?uploadId=${uploadId}&partNumber=${index + 1}`, {
        method: "PUT",
        body: bodyOf(piece),
      });
      expect(uploaded.status).toBe(200);
      parts.push({ partNumber: index + 1, etag: uploaded.headers.get("etag") as string });
      await uploaded.arrayBuffer();
    }

    const rows = parts
      .map(
        (part) =>
          `<Part><PartNumber>${part.partNumber}</PartNumber><ETag>${part.etag}</ETag></Part>`,
      )
      .join("");
    const completed = await fetch(`${key}?uploadId=${uploadId}`, {
      method: "POST",
      body: `<CompleteMultipartUpload>${rows}</CompleteMultipartUpload>`,
    });
    expect(completed.status).toBe(200);
    expect(field(await completed.text(), "Key")).toBe("big.bin");

    same(await createLoopback(driver).readFile("/big.bin"), concat(pieces));
    // Nothing staged survives a completion.
    await expect(createLoopback(driver).stat(`/${MULTIPART_PREFIX}/${uploadId}`)).rejects.toThrow();
  });

  it("serves a bucket map, and disposes with `await using`", async () => {
    const photos = createMemoryDriver();
    const notes = createMemoryDriver();
    {
      await using server = await createS3Server({ buckets: { photos, notes } }).listen();
      expect(server.buckets).toEqual(["notes", "photos"]);

      const listed = await fetch(`${server.url}/`);
      const document = await listed.text();
      expect(document).toContain("<Name>photos</Name>");
      expect(document).toContain("<Name>notes</Name>");

      await fetch(`${server.url}/photos/one.jpg`, { method: "PUT", body: "an image" });
      const wrongBucket = await fetch(`${server.url}/notes/one.jpg`);
      expect(wrongBucket.status).toBe(404);
      expect(field(await wrongBucket.text(), "Code")).toBe("NoSuchKey");

      const unknown = await fetch(`${server.url}/archive/one.jpg`);
      expect(unknown.status).toBe(404);
      expect(field(await unknown.text(), "Code")).toBe("NoSuchBucket");

      expect(text(await createLoopback(photos).readFile("/one.jpg"))).toBe("an image");
    }
    /* Out of scope: the dispose closed it. A request now has nowhere to go. */
  });

  it("uses the bucket option for the single-driver shape", async () => {
    const server = await serve(createMemoryDriver(), { bucket: "photos" });
    expect(server.buckets).toEqual(["photos"]);
    const wrong = await fetch(`${server.url}/${BUCKET}/x`);
    expect(field(await wrong.text(), "Code")).toBe("NoSuchBucket");
  });
});

describe("createS3Server: what the wire adds", () => {
  it("carries a HEAD reply's content-length with no body", async () => {
    const server = await serve(createMemoryDriver());
    await fetch(`${server.url}/${BUCKET}/sized.bin`, {
      method: "PUT",
      body: bodyOf(pattern(4096)),
    });

    const response = await rawRequest(`${server.url}/${BUCKET}/sized.bin`, { method: "HEAD" });
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-length"]).toBe("4096");
    expect((await readAll(response)).byteLength).toBe(0);
  });

  it("answers a PUT that sent Expect: 100-continue", async () => {
    const server = await serve(createMemoryDriver());
    const body = "a body the client held back until it was invited";
    const response = await rawRequest(`${server.url}/${BUCKET}/continue.txt`, {
      method: "PUT",
      headers: { "content-length": String(body.length), expect: "100-continue" },
      body,
      expectContinue: true,
    });
    expect(response.statusCode).toBe(200);
    await readAll(response);

    const stored = await fetch(`${server.url}/${BUCKET}/continue.txt`);
    expect(await stored.text()).toBe(body);
  });

  it("reuses one keep-alive connection for two requests", async () => {
    const server = await serve(createMemoryDriver());
    const agent = new Agent({ keepAlive: true, maxSockets: 1 });
    try {
      const first = await rawRequest(`${server.url}/${BUCKET}/keep.txt`, {
        method: "PUT",
        headers: { "content-length": "5" },
        body: "first",
        agent,
      });
      expect(first.statusCode).toBe(200);
      await readAll(first);
      expect(server.connections).toBe(1);

      const second = await rawRequest(`${server.url}/${BUCKET}/keep.txt`, { agent });
      expect(second.statusCode).toBe(200);
      expect((await readAll(second)).toString("utf8")).toBe("first");
      // Still one: the second request went down the socket the first left open.
      expect(server.connections).toBe(1);
    } finally {
      agent.destroy();
    }
  });

  it("answers 411 for a request that framed its body with transfer-encoding", async () => {
    /* Node decodes `Transfer-Encoding: chunked` before the session sees it, so
       the body arrives fine and the *length* does not — which is S3's own
       `411`, and the reason every client here sets `content-length`. */
    const server = await serve(createMemoryDriver());
    const response = await rawRequest(`${server.url}/${BUCKET}/te.txt`, {
      method: "PUT",
      headers: { "transfer-encoding": "chunked" },
      body: "framed by the transport",
    });
    expect(response.statusCode).toBe(411);
    expect(field((await readAll(response)).toString("utf8"), "Code")).toBe("MissingContentLength");
  });
});

describe("createS3Server: signed requests", () => {
  it("serves a signed round trip and refuses a bad signature", async () => {
    const driver = createMemoryDriver();
    const server = await serve(driver, { credentials: CREDENTIALS, region: REGION });
    const target = `/${BUCKET}/signed.txt`;
    const body = "signed bytes";

    const put = sign(server, {
      method: "PUT",
      target,
      payloadHash: sha256Hex(body),
      headers: { "content-length": String(body.length) },
    });
    const stored = await rawRequest(`${server.url}${target}`, {
      method: "PUT",
      headers: put.headers,
      body,
    });
    expect(stored.statusCode).toBe(200);
    await readAll(stored);
    expect(text(await createLoopback(driver).readFile("/signed.txt"))).toBe(body);

    const get = sign(server, { method: "GET", target, payloadHash: EMPTY_PAYLOAD_SHA256 });
    const read = await rawRequest(`${server.url}${target}`, { headers: get.headers });
    expect(read.statusCode).toBe(200);
    expect((await readAll(read)).toString("utf8")).toBe(body);

    // The same request with one character of the signature changed.
    const tampered = (get.headers.authorization as string).replace(/.$/, (last) =>
      last === "0" ? "1" : "0",
    );
    const refused = await rawRequest(`${server.url}${target}`, {
      headers: { ...get.headers, authorization: tampered },
    });
    expect(refused.statusCode).toBe(403);
    const document = (await readAll(refused)).toString("utf8");
    expect(field(document, "Code")).toBe("SignatureDoesNotMatch");

    // And with no signature at all.
    const unsigned = await fetch(`${server.url}${target}`);
    expect(unsigned.status).toBe(403);
    expect(field(await unsigned.text(), "Code")).toBe("AccessDenied");
  });

  it("stores a signed aws-chunked body sent over HTTP", async () => {
    const driver = createMemoryDriver();
    const server = await serve(driver, { credentials: CREDENTIALS, region: REGION });
    const target = `/${BUCKET}/chunked.bin`;
    const payload = pattern(70_000);
    const timestamp = Date.now();

    /* The frame length depends on nothing the signature covers, so the body is
       built twice: once to measure it, once with the real content-length in the
       headers that were signed. */
    const headersFor = (contentLength: number): Signed =>
      sign(server, {
        method: "PUT",
        target,
        payloadHash: STREAMING_PAYLOAD,
        timestamp,
        headers: {
          "content-encoding": "aws-chunked",
          "x-amz-decoded-content-length": String(payload.byteLength),
          "content-length": String(contentLength),
        },
      });
    const seedOf = (signed: Signed): ChunkedSignature => ({
      seed: signed.signature,
      amzDate: signed.amzDate,
      scope: signed.scope,
      secretAccessKey: CREDENTIALS.secretAccessKey,
    });
    const pieces = [payload.subarray(0, 65_536), payload.subarray(65_536)];
    const draft = headersFor(0);
    const length = chunkedBody(pieces, seedOf(draft)).byteLength;
    const signed = headersFor(length);
    const body = chunkedBody(pieces, seedOf(signed));
    expect(body.byteLength).toBe(length);

    const response = await rawRequest(`${server.url}${target}`, {
      method: "PUT",
      headers: signed.headers,
      body,
    });
    expect(response.statusCode).toBe(200);
    await readAll(response);
    same(await createLoopback(driver).readFile("/chunked.bin"), payload);
  });
});

describe("createS3Server: streaming", () => {
  const SIZE = 3 * 1024 * 1024;

  it("streams a multi-MiB GET in pieces, and gets every byte there", async () => {
    const server = await serve(createMemoryDriver());
    const payload = pattern(SIZE);
    await fetch(`${server.url}/${BUCKET}/big.bin`, { method: "PUT", body: bodyOf(payload) });

    const response = await rawRequest(`${server.url}/${BUCKET}/big.bin`);
    expect(response.headers["content-length"]).toBe(String(SIZE));
    let pieces = 0;
    const chunks: Buffer[] = [];
    for await (const chunk of response) {
      pieces++;
      chunks.push(chunk as Buffer);
    }
    expect(pieces).toBeGreaterThan(1);
    same(Buffer.concat(chunks), payload);
  });

  it("waits for a reader that stopped reading, and finishes when it resumes", async () => {
    const server = await serve(createMemoryDriver());
    const payload = pattern(SIZE);
    await fetch(`${server.url}/${BUCKET}/slow.bin`, { method: "PUT", body: bodyOf(payload) });

    const response = await rawRequest(`${server.url}/${BUCKET}/slow.bin`);
    /* Nobody is reading: the socket buffer fills, `write()` answers false, and
       the server parks until this resumes. */
    response.pause();
    await delay(100);
    response.resume();
    same(await readAll(response), payload);
  });

  it("releases the handle when a download is abandoned, and serves the next request", async () => {
    const { driver, counts } = counting(createMemoryDriver(), 2);
    const server = await serve(driver, { readChunkBytes: 16 * 1024 });
    await fetch(`${server.url}/${BUCKET}/abandoned.bin`, {
      method: "PUT",
      body: bodyOf(pattern(SIZE)),
    });
    const afterPut = counts.opened;

    const controller = new AbortController();
    const response = await fetch(`${server.url}/${BUCKET}/abandoned.bin`, {
      signal: controller.signal,
    });
    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    await reader.read();
    expect(counts.opened).toBe(afterPut + 1);
    controller.abort();
    await reader.cancel().catch(() => undefined);

    // The generator's `finally` runs on the transport's `return()`, not before.
    await until(() => counts.closed === counts.opened, "the abandoned handle to close");

    const next = await fetch(`${server.url}/${BUCKET}/abandoned.bin`, {
      headers: { range: "bytes=0-9" },
    });
    expect(next.status).toBe(206);
    same(new Uint8Array(await next.arrayBuffer()), pattern(SIZE).subarray(0, 10));
    expect(server.session.assertions).toEqual([]);
  });

  it("releases the handle when the socket dies mid-body", async () => {
    /* The abort lands while the server is parked waiting to drain, which is the
       other half of the abandoned-download case: `write()` said false and there
       is now nobody left to say `drain`. */
    const { driver, counts } = counting(createMemoryDriver());
    const server = await serve(driver, { readChunkBytes: 16 * 1024 });
    await fetch(`${server.url}/${BUCKET}/cut.bin`, { method: "PUT", body: bodyOf(pattern(SIZE)) });
    const afterPut = counts.opened;

    const response = await rawRequest(`${server.url}/${BUCKET}/cut.bin`);
    response.pause();
    await until(() => counts.opened === afterPut + 1, "the download to open its handle");
    await delay(50);
    response.destroy();

    await until(() => counts.closed === counts.opened, "the cut download to close its handle");
    const next = await fetch(`${server.url}/${BUCKET}/cut.bin`, {
      headers: { range: "bytes=0-3" },
    });
    expect(next.status).toBe(206);
    await next.arrayBuffer();
  });

  it("closes the body of a reply the client is no longer there for", async () => {
    /* Aborted before the reply was even written: `#write` finds the response
       destroyed, and the `GET` generator it was handed still has to be closed
       or the handle leaks. The delay is in `open`, so the abort lands between
       the session opening the object and the transport writing a byte. */
    const inner = createMemoryDriver();
    const counts = { opened: 0, closed: 0 };
    const driver: FsDriver = {
      ...inner,
      open: async (path, flags, mode): Promise<FileHandleLike> => {
        const handle = await inner.open(path, flags, mode);
        counts.opened++;
        if (path.endsWith("/late.bin")) {
          await delay(150);
        }
        return {
          ...handle,
          close: async () => {
            counts.closed++;
            await handle.close();
          },
        };
      },
    };
    const server = await serve(driver);
    await fetch(`${server.url}/${BUCKET}/late.bin`, { method: "PUT", body: "read too late" });

    const controller = new AbortController();
    const pending = fetch(`${server.url}/${BUCKET}/late.bin`, { signal: controller.signal });
    await delay(30);
    controller.abort();
    await expect(pending).rejects.toThrow();

    await until(() => counts.closed === counts.opened, "the unsent reply to close its handle");
    expect(server.session.assertions).toEqual([]);
  });
});

describe("createS3Server: framing", () => {
  const WHOLE = 256 * 1024;
  const DELIVERED = 64 * 1024;

  /** A gateway whose `short.bin` reads stop a quarter of the way in. */
  async function shortening(): Promise<{ server: S3Server; errors: unknown[] }> {
    const errors: unknown[] = [];
    const server = await serve(truncating(createMemoryDriver(), "/short.bin", DELIVERED), {
      readChunkBytes: 16 * 1024,
      onTransportError: (error) => errors.push(error),
    });
    for (const key of ["short.bin", "whole.bin"]) {
      const stored = await fetch(`${server.url}/${BUCKET}/${key}`, {
        method: "PUT",
        body: bodyOf(pattern(WHOLE)),
      });
      expect(stored.status).toBe(200);
      await stored.arrayBuffer();
    }
    return { server, errors };
  }

  it("kills the connection when a body ends short of its content-length", async () => {
    const { server, errors } = await shortening();

    const response = await rawRequest(`${server.url}/${BUCKET}/short.bin`);
    expect(response.headers["content-length"]).toBe(String(WHOLE));
    const started = Date.now();
    let failure: unknown;
    let received = -1;
    try {
      received = (await readAll(response)).byteLength;
    } catch (error) {
      failure = error;
    }
    /* The point of the whole case: the client finds out. A reply left out of
       frame would sit here until the test timed out. */
    expect(Date.now() - started).toBeLessThan(2000);
    expect(failure !== undefined || response.complete === false).toBe(true);
    expect(received).toBeLessThan(WHOLE);

    /* One report about the framing, and whatever the dying connection said
       after it (node calls a request cut off mid-message `aborted`). */
    const framing = errors.filter((error) => String(error).includes("out of frame"));
    expect(framing).toHaveLength(1);
    expect(String(framing[0])).toContain(`declared ${WHOLE} bytes and produced ${DELIVERED}`);

    // A fresh connection is unaffected: only the framed-wrong one was dropped.
    const next = await fetch(`${server.url}/${BUCKET}/whole.bin`);
    expect(next.status).toBe(200);
    same(new Uint8Array(await next.arrayBuffer()), pattern(WHOLE));
    expect(server.session.assertions).toEqual([]);
  });

  it("does not let a truncated reply swallow the next one on a keep-alive socket", async () => {
    const { server } = await shortening();
    const agent = new Agent({ keepAlive: true, maxSockets: 1 });
    try {
      const truncated = await rawRequest(`${server.url}/${BUCKET}/short.bin`, { agent });
      await readAll(truncated).catch(() => undefined);

      /* The agent would reuse the socket if it were still alive, and the reply
         below would be read as the tail of the one above. It cannot be: the
         connection died with the message that broke. */
      const second = await rawRequest(`${server.url}/${BUCKET}/whole.bin`, { agent });
      expect(second.statusCode).toBe(200);
      expect(second.headers["content-length"]).toBe(String(WHOLE));
      const bytes = await readAll(second);
      expect(second.complete).toBe(true);
      same(bytes, pattern(WHOLE));
    } finally {
      agent.destroy();
    }
  });

  it("answers two pipelined requests in order on one socket", async () => {
    const server = await serve(createMemoryDriver());
    await fetch(`${server.url}/${BUCKET}/pipe-one.txt`, { method: "PUT", body: "the first reply" });
    await fetch(`${server.url}/${BUCKET}/pipe-two.txt`, {
      method: "PUT",
      body: "the second reply",
    });

    const host = new URL(server.url).host;
    const line = (key: string, last: boolean): string =>
      `GET /${BUCKET}/${key} HTTP/1.1${CRLF}host: ${host}${CRLF}` +
      `${last ? `connection: close${CRLF}` : ""}${CRLF}`;
    const socket = connect({ port: server.port, host: "127.0.0.1" });
    try {
      // Both requests go out before either reply comes back.
      socket.write(line("pipe-one.txt", false) + line("pipe-two.txt", true));
      const chunks: Buffer[] = [];
      for await (const chunk of socket) {
        chunks.push(chunk as Buffer);
      }
      const raw = Buffer.concat(chunks).toString("utf8");
      expect(raw.match(/HTTP\/1\.1 200/g)).toHaveLength(2);
      expect(raw.indexOf("the first reply")).toBeGreaterThan(-1);
      expect(raw.indexOf("the first reply")).toBeLessThan(raw.indexOf("the second reply"));
    } finally {
      socket.destroy();
    }
  });
});

describe("createS3Server: close", () => {
  it("lets an in-flight response finish", async () => {
    const server = await serve(createMemoryDriver());
    const payload = pattern(1024 * 1024);
    await fetch(`${server.url}/${BUCKET}/inflight.bin`, { method: "PUT", body: bodyOf(payload) });

    const response = await rawRequest(`${server.url}/${BUCKET}/inflight.bin`);
    response.pause();
    // Closing with the response parked mid-body: the socket is not idle, so it
    // survives the sweep and only the deadline could cut it.
    const closing = server.close();
    await delay(50);
    response.resume();
    same(await readAll(response), payload);
    await closing;
  });

  it("cuts a response that outlives the drain deadline", async () => {
    const { driver } = counting(createMemoryDriver(), 30);
    const server = await serve(driver, { readChunkBytes: 16 * 1024, drainTimeout: 50 });
    await fetch(`${server.url}/${BUCKET}/slow.bin`, {
      method: "PUT",
      body: bodyOf(pattern(SLOW_SIZE)),
    });

    const response = await rawRequest(`${server.url}/${BUCKET}/slow.bin`);
    const started = Date.now();
    const received = readAll(response).catch(() => undefined);
    await server.close();
    expect(Date.now() - started).toBeLessThan(3000);
    const bytes = await received;
    expect(bytes === undefined || bytes.byteLength < SLOW_SIZE).toBe(true);
  });

  it("sweeps multipart staging, is idempotent, and stops answering", async () => {
    const driver = createMemoryDriver();
    const server = await serve(driver);
    const created = await fetch(`${server.url}/${BUCKET}/never-finished.bin?uploads`, {
      method: "POST",
    });
    const uploadId = field(await created.text(), "UploadId");
    const uploaded = await fetch(
      `${server.url}/${BUCKET}/never-finished.bin?uploadId=${uploadId}&partNumber=1`,
      { method: "PUT", body: "a part nobody ever completed" },
    );
    expect(uploaded.status).toBe(200);
    await uploaded.arrayBuffer();
    const staged = createLoopback(driver);
    expect((await staged.stat(`/${MULTIPART_PREFIX}/${uploadId}`)).isDirectory()).toBe(true);

    const url = server.url;
    await server.close();
    await server.close();
    await expect(staged.stat(`/${MULTIPART_PREFIX}`)).rejects.toThrow();

    await expect(fetch(`${url}/${BUCKET}/never-finished.bin`)).rejects.toThrow();
  });

  it("closes a server that never listened", async () => {
    const server = createS3Server(createMemoryDriver());
    expect(server.port).toBe(0);
    await server.close();
  });

  it("rejects a listen that cannot have the port", async () => {
    const first = await serve(createMemoryDriver());
    const second = createS3Server(createMemoryDriver(), { port: first.port });
    running.push(second);
    await expect(second.listen()).rejects.toMatchObject({ code: "EADDRINUSE" });
  });

  it("brackets an IPv6 host in the URL", () => {
    const server = createS3Server(createMemoryDriver(), { host: "::1", port: 9000 });
    expect(server.url).toBe("http://[::1]:9000");
  });
});
