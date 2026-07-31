/**
 * The WebDAV server over a real socket: `createWebdavServer()` and `fetch`.
 *
 * Everything below `server.ts` is already pinned in-process by
 * `session.test.ts` and `protocol.test.ts`, so what is checked here is only
 * what a socket adds:
 *
 * - **The bind gate.** Without credentials the share is loopback-only, and the
 *   refusal happens in `createWebdavServer()` — synchronously, before a server
 *   object exists, which is what "nothing listened" means here.
 * - **A round trip a real client would make**: `OPTIONS`, `MKCOL`, `PUT`,
 *   `PROPFIND`, `GET`, `MOVE`, `DELETE`, over one keep-alive connection.
 * - **Framing.** `HEAD` carrying headers and no bytes, and the one message HTTP
 *   cannot recover from — a body that ends short of its `Content-Length`, which
 *   must take the connection with it rather than leave a client waiting.
 * - **Streaming.** A multi-MiB `GET` arriving whole, and an abandoned download
 *   releasing the file handle it opened.
 * - **`close()`.** In-flight responses finish, and the second call is free.
 *
 * Every port is ephemeral (`port: 0`), every wait is bounded, and no literal
 * control character appears in this file.
 */

import { connect } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import type { FileHandleLike, FsDriver } from "../../src/types.ts";
import {
  bindRefusal,
  createWebdavServer,
  isLoopbackHost,
  isWebdavBindError,
  WebdavBindError,
  type WebdavServer,
  type WebdavServerOptions,
} from "../../src/webdav/server.ts";

// ---------------------------------------------------------------------------
// fixtures and helpers
// ---------------------------------------------------------------------------

const CRLF = "\r\n";
/** A body big enough that the reply is streamed in several pieces. */
const BIG = 512 * 1024;

/** Every server this file started, closed after each test whatever happened. */
const running: WebdavServer[] = [];

afterEach(async () => {
  for (const server of running.splice(0)) {
    await server.close();
  }
});

async function serve(
  driver: FsDriver = createMemoryDriver(),
  options: WebdavServerOptions = {},
): Promise<WebdavServer> {
  const server = createWebdavServer(driver, options);
  running.push(server);
  await server.listen();
  return server;
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

/** Bytes that are not all the same, so a truncation cannot pass as a match. */
function pattern(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let index = 0; index < size; index++) {
    bytes[index] = (index * 31 + (index >> 8)) & 0xff;
  }
  return bytes;
}

/**
 * A `fetch` body from bytes. `BodyInit` does not accept a plain `Uint8Array`
 * under this TypeScript's DOM types, and a `Blob` keeps the `Content-Length`.
 */
function bodyOf(bytes: Uint8Array): BodyInit {
  return new Blob([new Uint8Array(bytes)]);
}

/** A driver that counts the handles it opens and closes. */
function counting(inner: FsDriver): {
  driver: FsDriver;
  counts: { opened: number; closed: number };
} {
  const counts = { opened: 0, closed: 0 };
  const driver: FsDriver = {
    ...inner,
    open: async (path, flags, mode): Promise<FileHandleLike> => {
      const handle = await inner.open(path, flags, mode);
      counts.opened++;
      return {
        ...handle,
        read: async (buffer, offset, length, position) =>
          await handle.read(buffer, offset, length, position),
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
 * A driver whose reads stop delivering after `deliver` bytes, while `stat`
 * keeps reporting the whole size — the TOCTOU a passthrough driver lives with,
 * and the one reply the transport has to notice is out of frame.
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
          const at = position ?? 0;
          if (at >= deliver) {
            return { bytesRead: 0, buffer };
          }
          const capped = Math.min(length ?? buffer.byteLength, deliver - at);
          return await handle.read(buffer, offset, capped, position);
        },
        close: async () => await handle.close(),
      };
    },
  };
}

/** One raw request on its own socket, answered as text. */
function raw(server: WebdavServer, lines: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const socket = connect(server.port, server.host, () => socket.write(lines));
    let received = "";
    socket.setTimeout(2000, () => socket.destroy(new Error("raw request timed out")));
    socket.on("data", (chunk: Buffer) => {
      received += chunk.toString("utf8");
    });
    socket.on("close", () => resolve(received));
    socket.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// the bind gate
// ---------------------------------------------------------------------------

describe("createWebdavServer: the bind gate", () => {
  it("accepts every literal loopback spelling and nothing else", () => {
    for (const host of [
      "localhost",
      "LOCALHOST",
      "127.0.0.1",
      "127.9.9.9",
      "::1",
      "[::1]",
      "::ffff:127.0.0.1",
    ]) {
      expect(isLoopbackHost(host), host).toBe(true);
    }
    for (const host of ["", "0.0.0.0", "::", "[::]", "10.0.0.1", "127.0.0.256", "::1]"]) {
      expect(isLoopbackHost(host), host).toBe(false);
    }
  });

  it("names the unspecified addresses as the danger they are", () => {
    expect(bindRefusal("0.0.0.0", false)).toContain("binds every interface");
    expect(bindRefusal("", false)).toContain("every interface");
    expect(bindRefusal("192.168.1.10", false)).toContain("reachable from outside");
    expect(bindRefusal("127.0.0.1", false)).toBeUndefined();
  });

  it("refuses a non-loopback bind with no credentials, before anything listens", () => {
    let thrown: unknown;
    try {
      createWebdavServer(createMemoryDriver(), { host: "0.0.0.0" });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(WebdavBindError);
    expect(isWebdavBindError(thrown)).toBe(true);
    expect((thrown as WebdavBindError).host).toBe("0.0.0.0");
    expect((thrown as WebdavBindError).code).toBe("ERR_WEBDAV_BIND");
  });

  it("allows any bind once credentials are configured", () => {
    const server = createWebdavServer(createMemoryDriver(), {
      host: "0.0.0.0",
      credentials: { username: "ada", password: "secret" },
    });
    expect(server.host).toBe("0.0.0.0");
    expect(server.port).toBe(0);
  });

  it("refuses a value that is not a driver", () => {
    expect(() => createWebdavServer({} as FsDriver)).toThrow(TypeError);
  });

  it("brackets an IPv6 host in the URL", () => {
    expect(createWebdavServer(createMemoryDriver(), { host: "::1" }).url).toBe("http://[::1]:0");
  });
});

// ---------------------------------------------------------------------------
// the round trip
// ---------------------------------------------------------------------------

describe("createWebdavServer: a client's session", () => {
  it("walks a whole tree through fetch", async () => {
    const server = await serve();

    const options = await fetch(`${server.url}/`, { method: "OPTIONS" });
    expect(options.status).toBe(200);
    expect(options.headers.get("dav")).toBe("1, 2, 3");

    expect((await fetch(`${server.url}/notes`, { method: "MKCOL" })).status).toBe(201);

    const put = await fetch(`${server.url}/notes/a%20b.txt`, {
      method: "PUT",
      body: "the body",
    });
    expect(put.status).toBe(201);
    expect(put.headers.get("etag")).toMatch(/^"[\da-f]{32}"$/);

    const propfind = await fetch(`${server.url}/notes`, {
      method: "PROPFIND",
      headers: { depth: "1" },
    });
    expect(propfind.status).toBe(207);
    expect(propfind.headers.get("content-type")).toBe('application/xml; charset="utf-8"');
    const listing = await propfind.text();
    expect(listing).toContain("<href>/notes/</href>");
    expect(listing).toContain("<href>/notes/a%20b.txt</href>");

    const get = await fetch(`${server.url}/notes/a%20b.txt`);
    expect(await get.text()).toBe("the body");

    const move = await fetch(`${server.url}/notes/a%20b.txt`, {
      method: "MOVE",
      headers: { destination: `${server.url}/notes/renamed.txt` },
    });
    expect(move.status).toBe(201);
    expect((await fetch(`${server.url}/notes/renamed.txt`)).status).toBe(200);

    expect((await fetch(`${server.url}/notes`, { method: "DELETE" })).status).toBe(204);
    expect((await fetch(`${server.url}/notes/renamed.txt`)).status).toBe(404);
    expect(server.session.assertions).toEqual([]);
  });

  it("challenges an unauthenticated request and serves an authenticated one", async () => {
    const server = await serve(createMemoryDriver(), {
      credentials: { username: "ada", password: "secret" },
    });
    const anonymous = await fetch(`${server.url}/`, { method: "OPTIONS" });
    expect(anonymous.status).toBe(401);
    expect(anonymous.headers.get("www-authenticate")).toContain("Basic realm=");

    const authorization = `Basic ${Buffer.from("ada:secret", "utf8").toString("base64")}`;
    const allowed = await fetch(`${server.url}/`, {
      method: "OPTIONS",
      headers: { authorization },
    });
    expect(allowed.status).toBe(200);
  });

  it("disposes with `await using`", async () => {
    let url: string;
    {
      await using server = await createWebdavServer(createMemoryDriver()).listen();
      url = server.url;
      expect((await fetch(`${url}/`, { method: "OPTIONS" })).status).toBe(200);
    }
    await expect(fetch(`${url}/`, { method: "OPTIONS" })).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// what the wire adds
// ---------------------------------------------------------------------------

describe("createWebdavServer: framing", () => {
  it("carries a HEAD reply's content-length with no body", async () => {
    const server = await serve();
    await fetch(`${server.url}/f.txt`, { method: "PUT", body: "0123456789" });
    const head = await fetch(`${server.url}/f.txt`, { method: "HEAD" });
    expect(head.headers.get("content-length")).toBe("10");
    expect(await head.text()).toBe("");
  });

  it("reuses one keep-alive connection for two requests", async () => {
    const server = await serve();
    const answer = await raw(
      server,
      `OPTIONS / HTTP/1.1${CRLF}host: dav.test${CRLF}${CRLF}` +
        `PROPFIND / HTTP/1.1${CRLF}host: dav.test${CRLF}depth: 0${CRLF}connection: close${CRLF}${CRLF}`,
    );
    /* Two replies, in order, on one socket. Counted by status *line* rather
       than by substring: a `207`'s body carries `HTTP/1.1 200 OK` inside every
       propstat, which is the same text in a different place. */
    const statusLines = answer.split(CRLF).filter((line) => line.startsWith("HTTP/1.1 "));
    expect(statusLines).toEqual(["HTTP/1.1 200 OK", "HTTP/1.1 207 Multi-Status"]);
  });

  it("drains a body the session never read", async () => {
    /* A `DELETE` that carried one: the bytes have to leave the socket or the
       next request on it cannot be framed. */
    const server = await serve();
    await fetch(`${server.url}/f.txt`, { method: "PUT", body: "x" });
    const answer = await raw(
      server,
      `DELETE /f.txt HTTP/1.1${CRLF}host: dav.test${CRLF}content-length: 5${CRLF}${CRLF}hello` +
        `OPTIONS / HTTP/1.1${CRLF}host: dav.test${CRLF}connection: close${CRLF}${CRLF}`,
    );
    expect(answer).toContain("HTTP/1.1 204 No Content");
    expect(answer).toContain("HTTP/1.1 200 OK");
  });

  it("kills the connection when a body ends short of its content-length", async () => {
    const server = await serve(truncating(createMemoryDriver(), "short.bin", 1024), {
      readChunkBytes: 512,
      onTransportError: () => undefined,
    });
    await fetch(`${server.url}/short.bin`, { method: "PUT", body: bodyOf(pattern(4096)) });
    /* The reply promises 4096 bytes and can produce 1024. A client must not be
       left waiting for the rest, so the connection goes. */
    await expect(
      fetch(`${server.url}/short.bin`).then(async (response) => await response.arrayBuffer()),
    ).rejects.toThrow();
    expect(server.session.assertions).toEqual([]);
  });
});

describe("createWebdavServer: streaming", () => {
  it("streams a multi-MiB GET, and every byte arrives", async () => {
    const server = await serve(createMemoryDriver(), { readChunkBytes: 16 * 1024 });
    const bytes = pattern(BIG);
    await fetch(`${server.url}/big.bin`, { method: "PUT", body: bodyOf(bytes) });
    const response = await fetch(`${server.url}/big.bin`);
    expect(response.headers.get("content-length")).toBe(String(BIG));
    expect(Buffer.from(await response.arrayBuffer()).equals(Buffer.from(bytes))).toBe(true);
  });

  it("releases the handle when a download is abandoned", async () => {
    const { driver, counts } = counting(createMemoryDriver());
    const server = await serve(driver, { readChunkBytes: 16 * 1024 });
    await fetch(`${server.url}/abandoned.bin`, { method: "PUT", body: bodyOf(pattern(BIG)) });
    const afterPut = counts.opened;

    const controller = new AbortController();
    const response = await fetch(`${server.url}/abandoned.bin`, { signal: controller.signal });
    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    await reader.read();
    expect(counts.opened).toBe(afterPut + 1);
    controller.abort();
    await reader.cancel().catch(() => undefined);

    // The generator's `finally` runs on the transport's `return()`, not before.
    await until(() => counts.closed === counts.opened, "the abandoned handle to close");
    expect((await fetch(`${server.url}/abandoned.bin`, { method: "HEAD" })).status).toBe(200);
    expect(server.session.assertions).toEqual([]);
  });

  it("closes the body of a reply the client is no longer there for", async () => {
    /* Aborted before the reply was even written: `#write` finds the response
       destroyed, and the `GET` generator it was handed still has to be closed
       or the handle leaks. The delay is in `open`, so the abort lands between
       the session opening the resource and the transport writing a byte. */
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
    await fetch(`${server.url}/late.bin`, { method: "PUT", body: "read too late" });

    const controller = new AbortController();
    const pending = fetch(`${server.url}/late.bin`, { signal: controller.signal });
    await delay(30);
    controller.abort();
    await expect(pending).rejects.toThrow();

    await until(() => counts.closed === counts.opened, "the unsent reply to close its handle");
    expect(server.session.assertions).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// close
// ---------------------------------------------------------------------------

describe("createWebdavServer: close", () => {
  it("lets an in-flight response finish", async () => {
    const server = await serve(createMemoryDriver(), { readChunkBytes: 8 * 1024 });
    const bytes = pattern(BIG);
    await fetch(`${server.url}/big.bin`, { method: "PUT", body: bodyOf(bytes) });
    /* Awaited to the headers, so the connection exists and the body is still
       streaming — the socket is not idle, so it survives the sweep and only the
       deadline could cut it. */
    const response = await fetch(`${server.url}/big.bin`);
    const closing = server.close();
    const body = await response.arrayBuffer();
    await closing;
    expect(body.byteLength).toBe(BIG);
  });

  it("stops answering, and the second close is free", async () => {
    const server = await serve();
    const url = server.url;
    await server.close();
    await server.close();
    await expect(fetch(`${url}/`, { method: "OPTIONS" })).rejects.toThrow();
    expect(server.connections).toBe(0);
  });

  it("closes a server that never listened", async () => {
    const server = createWebdavServer(createMemoryDriver());
    await expect(server.close()).resolves.toBeUndefined();
  });

  it("rejects a listen that cannot have the port", async () => {
    const first = await serve();
    const second = createWebdavServer(createMemoryDriver(), { port: first.port });
    running.push(second);
    await expect(second.listen()).rejects.toThrow();
  });
});
