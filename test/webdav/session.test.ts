/**
 * The WebDAV session, against the memory driver, in process, with no sockets.
 *
 * Three kinds of assertion, and they answer to different authorities:
 *
 * - **RFC 4918's semantics.** What each method answers, and — where the RFC
 *   makes the choice and a plain HTTP server would choose differently — *why*:
 *   `PUT` under a missing parent is `409` and never `404`, an overwriting
 *   `COPY` deletes the destination first, a partial `DELETE` answers `207`,
 *   `PROPFIND` with no `Depth` is `infinity` and therefore refused.
 * - **HTTP.** `Range`, `HEAD`, and the status/`Allow` pairs, which are
 *   RFC 9110's rather than WebDAV's.
 * - **The one-reply discipline.** A driver that throws an errno nothing has a
 *   name for, a body source that dies, and a method that does not exist each
 *   produce exactly one well-formed reply, and the session answers the next
 *   request normally.
 *
 * The fixtures give every field a distinct value (`AGENTS.md`), and no literal
 * control character appears in this file.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { fsError } from "../../src/errors.ts";
import { S_IFIFO } from "../../src/types.ts";
import type { FsDriver, StatsFsLike } from "../../src/types.ts";
import { WebdavSession } from "../../src/webdav/session.ts";
import type { WebdavResponse } from "../../src/webdav/protocol.ts";

// ---------------------------------------------------------------------------
// the harness
// ---------------------------------------------------------------------------

interface Reply {
  status: number;
  headers: Record<string, string>;
  text: string;
}

/** Drain a reply's body, whichever of the three shapes it is. */
async function bodyText(reply: WebdavResponse): Promise<string> {
  if (reply.body === undefined) {
    return "";
  }
  if (reply.body instanceof Uint8Array) {
    return Buffer.from(reply.body).toString("utf8");
  }
  let text = "";
  for await (const chunk of reply.body) {
    text += Buffer.from(chunk).toString("utf8");
  }
  return text;
}

async function* stream(body: string | Uint8Array): AsyncGenerator<Uint8Array> {
  yield typeof body === "string" ? Buffer.from(body, "utf8") : body;
}

function request(
  session: WebdavSession,
  method: string,
  target: string,
  options: { headers?: Record<string, string>; body?: string | Uint8Array } = {},
): Promise<Reply> {
  const head = { method, target, headers: options.headers ?? {} };
  const body = options.body === undefined ? undefined : stream(options.body);
  return session.handleRequest(head, body).then(async (reply) => ({
    status: reply.status,
    headers: reply.headers,
    text: await bodyText(reply),
  }));
}

/** The `<href>`s of a multistatus, in document order. */
function hrefs(document: string): string[] {
  return [...document.matchAll(/<href>([^<]*)<\/href>/g)].map((match) => match[1] as string);
}

/** The propstat status codes of a multistatus, in document order. */
function statuses(document: string): number[] {
  return [...document.matchAll(/<status>HTTP\/1\.1 (\d{3})/g)].map((match) => Number(match[1]));
}

/** The text of one property element, or `undefined` if it is not there. */
function property(document: string, name: string): string | undefined {
  return new RegExp(`<${name}>([^<]*)</${name}>`).exec(document)?.[1];
}

let driver: ReturnType<typeof createMemoryDriver>;
let session: WebdavSession;

beforeEach(async () => {
  driver = createMemoryDriver();
  session = new WebdavSession(driver);
  await driver.mkdir("/dir");
  const handle = await driver.open("/dir/file.txt", "w");
  await handle.write(Buffer.from("hello world", "utf8"), 0, 11, 0);
  await handle.close();
});

// ---------------------------------------------------------------------------
// OPTIONS
// ---------------------------------------------------------------------------

describe("OPTIONS", () => {
  it("advertises class 1 and 3, and never class 2", async () => {
    const reply = await request(session, "OPTIONS", "/");
    expect(reply.status).toBe(200);
    expect(reply.headers["dav"]).toBe("1, 3");
    expect(reply.headers["allow"]).toContain("PROPFIND");
    expect(reply.headers["allow"]).not.toContain("LOCK");
    expect(reply.headers["ms-author-via"]).toBe("DAV");
  });

  it("answers for a resource that does not exist yet", async () => {
    /* The request a client makes before its first `PUT`. A `404` here would end
       the conversation before it started. */
    expect((await request(session, "OPTIONS", "/nothing/here")).status).toBe(200);
  });
});

describe("an unimplemented method", () => {
  it("is 405 with an Allow that tells the truth", async () => {
    for (const method of ["LOCK", "UNLOCK", "PATCH", "REPORT"]) {
      const reply = await request(session, method, "/dir/file.txt");
      expect(reply.status, method).toBe(405);
      expect(reply.headers["allow"], method).toContain("PROPFIND");
    }
  });
});

// ---------------------------------------------------------------------------
// GET / HEAD
// ---------------------------------------------------------------------------

describe("GET", () => {
  it("serves a resource with its validators", async () => {
    const reply = await request(session, "GET", "/dir/file.txt");
    expect(reply.status).toBe(200);
    expect(reply.text).toBe("hello world");
    expect(reply.headers["content-length"]).toBe("11");
    expect(reply.headers["content-type"]).toBe("application/octet-stream");
    expect(reply.headers["accept-ranges"]).toBe("bytes");
    expect(reply.headers["etag"]).toMatch(/^"[\da-f]{32}"$/);
    expect(reply.headers["last-modified"]).toMatch(/GMT$/);
  });

  it("answers a byte range with 206 and a Content-Range", async () => {
    const reply = await request(session, "GET", "/dir/file.txt", {
      headers: { range: "bytes=6-10" },
    });
    expect(reply.status).toBe(206);
    expect(reply.text).toBe("world");
    expect(reply.headers["content-range"]).toBe("bytes 6-10/11");
    expect(reply.headers["content-length"]).toBe("5");
  });

  it("answers 416 with an unsatisfied-range for a range past the end", async () => {
    const reply = await request(session, "GET", "/dir/file.txt", {
      headers: { range: "bytes=99-" },
    });
    expect(reply.status).toBe(416);
    expect(reply.headers["content-range"]).toBe("bytes */11");
  });

  it("ignores a range it cannot use, which RFC 9110 §14.2 requires", async () => {
    const reply = await request(session, "GET", "/dir/file.txt", {
      headers: { range: "furlongs=1-2" },
    });
    expect(reply.status).toBe(200);
    expect(reply.text).toBe("hello world");
  });

  it("is 405 on a collection, with PROPFIND named in Allow", async () => {
    const reply = await request(session, "GET", "/dir");
    expect(reply.status).toBe(405);
    expect(reply.headers["allow"]).toContain("PROPFIND");
  });

  it("is 403 on a resource HTTP cannot transfer", async () => {
    await driver.mountx.mknod("/fifo", S_IFIFO | 0o644, 0);
    expect((await request(session, "GET", "/fifo")).status).toBe(403);
  });

  it("is 404 for a resource that is not there", async () => {
    expect((await request(session, "GET", "/dir/missing")).status).toBe(404);
    expect((await request(session, "GET", "/dir/file.txt/under")).status).toBe(404);
  });

  it("serves an empty resource as an empty body", async () => {
    await (await driver.open("/empty", "w")).close();
    const reply = await request(session, "GET", "/empty");
    expect(reply.status).toBe(200);
    expect(reply.headers["content-length"]).toBe("0");
    expect(reply.text).toBe("");
  });
});

describe("HEAD", () => {
  it("carries the GET's headers and none of its bytes", async () => {
    const get = await request(session, "GET", "/dir/file.txt");
    const head = await request(session, "HEAD", "/dir/file.txt");
    expect(head.status).toBe(200);
    expect(head.text).toBe("");
    expect(head.headers).toEqual(get.headers);
  });
});

// ---------------------------------------------------------------------------
// PUT
// ---------------------------------------------------------------------------

describe("PUT", () => {
  it("creates with 201 and replaces with 204", async () => {
    const created = await request(session, "PUT", "/dir/new.txt", { body: "first" });
    expect(created.status).toBe(201);
    expect(created.headers["etag"]).toMatch(/^"[\da-f]{32}"$/);
    const replaced = await request(session, "PUT", "/dir/new.txt", { body: "second" });
    expect(replaced.status).toBe(204);
    expect((await request(session, "GET", "/dir/new.txt")).text).toBe("second");
  });

  it("truncates what it replaces", async () => {
    await request(session, "PUT", "/dir/file.txt", { body: "hi" });
    expect((await request(session, "GET", "/dir/file.txt")).text).toBe("hi");
  });

  it("stores an empty body as an empty resource", async () => {
    expect((await request(session, "PUT", "/dir/empty", { body: "" })).status).toBe(201);
    expect((await request(session, "GET", "/dir/empty")).headers["content-length"]).toBe("0");
  });

  it("is 409 under a parent that is missing or is not a collection", async () => {
    /* §9.7.1's rule, and the one place this differs most visibly from a plain
       HTTP server: it is a Conflict, not a Not Found, and the collection is the
       client's to create with MKCOL. */
    expect((await request(session, "PUT", "/nope/x.txt", { body: "x" })).status).toBe(409);
    expect((await request(session, "PUT", "/dir/file.txt/x", { body: "x" })).status).toBe(409);
    await expect(driver.stat("/nope")).rejects.toThrow();
  });

  it("is 405 onto an existing collection or the root", async () => {
    expect((await request(session, "PUT", "/dir", { body: "x" })).status).toBe(405);
    expect((await request(session, "PUT", "/", { body: "x" })).status).toBe(405);
  });

  it("refuses a Content-Range rather than writing the whole resource", async () => {
    const reply = await request(session, "PUT", "/dir/file.txt", {
      headers: { "content-range": "bytes 0-1/11" },
      body: "XX",
    });
    expect(reply.status).toBe(400);
    expect((await request(session, "GET", "/dir/file.txt")).text).toBe("hello world");
  });

  it("refuses a body past maxBodyBytes", async () => {
    const bounded = new WebdavSession(driver, { maxBodyBytes: 4 });
    expect((await request(bounded, "PUT", "/dir/big", { body: "0123456789" })).status).toBe(413);
  });
});

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------

describe("DELETE", () => {
  it("removes a resource with 204 and no body", async () => {
    const reply = await request(session, "DELETE", "/dir/file.txt");
    expect(reply.status).toBe(204);
    expect(reply.text).toBe("");
    expect((await request(session, "GET", "/dir/file.txt")).status).toBe(404);
  });

  it("removes a collection and everything under it", async () => {
    await driver.mkdir("/dir/deep");
    await (await driver.open("/dir/deep/leaf", "w")).close();
    expect((await request(session, "DELETE", "/dir")).status).toBe(204);
    await expect(driver.stat("/dir")).rejects.toThrow();
  });

  it("is 400 for Depth: 0 on a collection, which §9.6.1 has no meaning for", async () => {
    expect((await request(session, "DELETE", "/dir", { headers: { depth: "0" } })).status).toBe(
      400,
    );
    expect((await request(session, "DELETE", "/dir", { headers: { depth: "2" } })).status).toBe(
      400,
    );
  });

  it("removes a link to a collection, not what it points at", async () => {
    /* The destructive difference between `stat` and `lstat`: following the link
       here would empty out `/dir` and leave the client's own entry behind. */
    await driver.symlink("/dir", "/shortcut");
    expect((await request(session, "DELETE", "/shortcut")).status).toBe(204);
    await expect(driver.stat("/shortcut")).rejects.toThrow();
    expect((await driver.stat("/dir/file.txt")).isFile()).toBe(true);
  });

  it("unlinks a link inside a tree rather than walking into it", async () => {
    await driver.mkdir("/outside");
    await (await driver.open("/outside/survivor.txt", "w")).close();
    await driver.symlink("/outside", "/dir/shortcut");
    expect((await request(session, "DELETE", "/dir")).status).toBe(204);
    expect((await driver.stat("/outside/survivor.txt")).isFile()).toBe(true);
  });

  it("falls back to stat for a driver with no lstat", async () => {
    /* `lstat` is optional on `FsDriver`, and a driver without one has no links
       for the distinction to matter to — so the delete still works. */
    const { lstat: _lstat, ...withoutLstat } = driver as unknown as Record<string, unknown>;
    const plain = new WebdavSession(withoutLstat as unknown as FsDriver);
    expect((await request(plain, "DELETE", "/dir")).status).toBe(204);
    await expect(driver.stat("/dir")).rejects.toThrow();
  });

  it("is 404 for what is not there and 403 for the share itself", async () => {
    expect((await request(session, "DELETE", "/missing")).status).toBe(404);
    expect((await request(session, "DELETE", "/")).status).toBe(403);
  });

  it("answers 207 naming what would not go, and leaves the rest gone", async () => {
    await driver.mkdir("/dir/keep");
    await (await driver.open("/dir/keep/stuck", "w")).close();
    await (await driver.open("/dir/gone", "w")).close();
    const stubborn = withFailure(driver, "unlink", (path) =>
      path === "/dir/keep/stuck" ? fsError("EACCES", { syscall: "unlink", path }) : undefined,
    );
    const reply = await request(new WebdavSession(stubborn), "DELETE", "/dir");
    expect(reply.status).toBe(207);
    expect(hrefs(reply.text)).toEqual(["/dir/keep/stuck"]);
    expect(statuses(reply.text)).toEqual([403]);
    // What could go, went; the collections above the survivor stayed.
    await expect(driver.stat("/dir/gone")).rejects.toThrow();
    await expect(driver.stat("/dir/keep/stuck")).resolves.toBeDefined();
  });

  it("reports a collection that would not go, and one it could not read", async () => {
    await driver.mkdir("/dir/inner");
    const stubbornRmdir = withFailure(driver, "rmdir", (path) =>
      path === "/dir/inner" ? fsError("EBUSY", { syscall: "rmdir", path }) : undefined,
    );
    const busy = await request(new WebdavSession(stubbornRmdir), "DELETE", "/dir");
    expect(busy.status).toBe(207);
    expect(hrefs(busy.text)).toEqual(["/dir/inner/"]);
    expect(statuses(busy.text)).toEqual([409]);

    const unreadable = withFailure(driver, "readdir", (path) =>
      path === "/dir" ? fsError("EACCES", { syscall: "scandir", path }) : undefined,
    );
    const blind = await request(new WebdavSession(unreadable), "DELETE", "/dir");
    expect(blind.status).toBe(207);
    expect(hrefs(blind.text)).toEqual(["/dir/"]);
    expect(statuses(blind.text)).toEqual([403]);
  });
});

// ---------------------------------------------------------------------------
// MKCOL
// ---------------------------------------------------------------------------

describe("MKCOL", () => {
  it("creates a collection with 201", async () => {
    expect((await request(session, "MKCOL", "/fresh")).status).toBe(201);
    expect((await driver.stat("/fresh")).isDirectory()).toBe(true);
  });

  it("is 405 on anything that already exists, the root included", async () => {
    expect((await request(session, "MKCOL", "/dir")).status).toBe(405);
    expect((await request(session, "MKCOL", "/dir/file.txt")).status).toBe(405);
    expect((await request(session, "MKCOL", "/")).status).toBe(405);
  });

  it("is 409 under a parent that is not a collection", async () => {
    expect((await request(session, "MKCOL", "/nope/deep")).status).toBe(409);
    expect((await request(session, "MKCOL", "/dir/file.txt/deep")).status).toBe(409);
  });

  it("is 415 for a request body, which this server defines none of", async () => {
    const reply = await request(session, "MKCOL", "/fresh", { body: "<mkcol/>" });
    expect(reply.status).toBe(415);
    await expect(driver.stat("/fresh")).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// COPY and MOVE
// ---------------------------------------------------------------------------

describe("COPY", () => {
  const to = (destination: string, extra: Record<string, string> = {}) => ({
    headers: { destination, host: "dav.test", ...extra },
  });

  it("copies a resource's bytes with 201", async () => {
    expect((await request(session, "COPY", "/dir/file.txt", to("/copy.txt"))).status).toBe(201);
    expect((await request(session, "GET", "/copy.txt")).text).toBe("hello world");
    // The source is untouched.
    expect((await request(session, "GET", "/dir/file.txt")).text).toBe("hello world");
  });

  it("copies a whole tree by default", async () => {
    await driver.mkdir("/dir/deep");
    await (await driver.open("/dir/deep/leaf", "w")).close();
    expect((await request(session, "COPY", "/dir", to("/clone"))).status).toBe(201);
    expect((await driver.stat("/clone/deep/leaf")).isFile()).toBe(true);
  });

  it("copies a collection without its members at Depth: 0, per §9.8.3", async () => {
    expect((await request(session, "COPY", "/dir", to("/shallow", { depth: "0" }))).status).toBe(
      201,
    );
    expect(await driver.readdir("/shallow", { withFileTypes: true })).toEqual([]);
  });

  it("is 400 for Depth: 1, which COPY does not define", async () => {
    expect((await request(session, "COPY", "/dir", to("/x", { depth: "1" }))).status).toBe(400);
  });

  it("replaces an existing destination with 204, having deleted it first", async () => {
    await driver.mkdir("/target");
    await (await driver.open("/target/stale", "w")).close();
    expect((await request(session, "COPY", "/dir", to("/target"))).status).toBe(204);
    /* §9.8.4: the destination is DELETEd with Depth infinity first, so nothing
       of what used to be there survives the copy. */
    await expect(driver.stat("/target/stale")).rejects.toThrow();
    expect((await driver.stat("/target/file.txt")).isFile()).toBe(true);
  });

  it("is 412 when the destination exists and Overwrite is F", async () => {
    await (await driver.open("/taken", "w")).close();
    const reply = await request(session, "COPY", "/dir/file.txt", to("/taken", { overwrite: "F" }));
    expect(reply.status).toBe(412);
    expect((await driver.stat("/taken")).size).toBe(0);
  });

  it("is 403 for a destination that is the source or inside it", async () => {
    expect((await request(session, "COPY", "/dir", to("/dir"))).status).toBe(403);
    expect((await request(session, "COPY", "/dir", to("/dir/inner"))).status).toBe(403);
    // The share's own root is neither copied nor moved away.
    expect((await request(session, "COPY", "/", to("/backup"))).status).toBe(403);
  });

  it("is 400 for an Overwrite that is neither T nor F", async () => {
    expect(
      (await request(session, "COPY", "/dir/file.txt", to("/x", { overwrite: "maybe" }))).status,
    ).toBe(400);
  });

  it("names a resource it cannot transfer rather than copying nothing quietly", async () => {
    await driver.mountx.mknod("/dir/fifo", S_IFIFO | 0o644, 0);
    const reply = await request(session, "COPY", "/dir", to("/clone"));
    expect(reply.status).toBe(207);
    expect(hrefs(reply.text)).toEqual(["/dir/fifo"]);
    expect(statuses(reply.text)).toEqual([403]);
    // Everything that could be copied still was.
    expect((await driver.stat("/clone/file.txt")).isFile()).toBe(true);
  });

  it("reports a link to a collection instead of walking into it", async () => {
    /* The walk that would not terminate: `/dir/back` points at its own parent,
       so following it would copy `/dir` into `/clone/back`, then into
       `/clone/back/back`, for as long as names can get longer. */
    await driver.symlink("/dir", "/dir/back");
    const reply = await request(session, "COPY", "/dir", to("/clone"));
    expect(reply.status).toBe(207);
    expect(hrefs(reply.text)).toEqual(["/dir/back/"]);
    expect(statuses(reply.text)).toEqual([403]);
    // Everything that is not the link was copied, once.
    expect((await driver.stat("/clone/file.txt")).isFile()).toBe(true);
    await expect(driver.stat("/clone/back")).rejects.toThrow();
  });

  it("copies the bytes a link to a resource points at", async () => {
    await driver.symlink("/dir/file.txt", "/dir/alias.txt");
    expect((await request(session, "COPY", "/dir", to("/clone"))).status).toBe(201);
    expect((await request(session, "GET", "/clone/alias.txt")).text).toBe("hello world");
    // A copy, not a link: WebDAV has no way to name one.
    expect((await driver.lstat("/clone/alias.txt")).isSymbolicLink()).toBe(false);
  });

  it("answers 207 when the destination it must delete first will not go", async () => {
    await (await driver.open("/taken", "w")).close();
    const stubborn = withFailure(driver, "unlink", (path) =>
      path === "/taken" ? fsError("EPERM", { syscall: "unlink", path }) : undefined,
    );
    const reply = await request(new WebdavSession(stubborn), "COPY", "/dir/file.txt", to("/taken"));
    expect(reply.status).toBe(207);
    expect(hrefs(reply.text)).toEqual(["/taken"]);
    expect(statuses(reply.text)).toEqual([403]);
    expect((await driver.stat("/taken")).size).toBe(0);
  });

  it("is 409 under a destination parent that is not a collection", async () => {
    expect((await request(session, "COPY", "/dir/file.txt", to("/nope/x"))).status).toBe(409);
  });

  it("answers 207 for a tree that only partly copied", async () => {
    await driver.mkdir("/dir/deep");
    await (await driver.open("/dir/deep/leaf", "w")).close();
    const stubborn = withFailure(driver, "mkdir", (path) =>
      path === "/clone/deep" ? fsError("ENOSPC", { syscall: "mkdir", path }) : undefined,
    );
    const reply = await request(new WebdavSession(stubborn), "COPY", "/dir", to("/clone"));
    expect(reply.status).toBe(207);
    expect(hrefs(reply.text)).toEqual(["/dir/deep/"]);
    expect(statuses(reply.text)).toEqual([507]);
    // What could be copied, was.
    expect((await driver.stat("/clone/file.txt")).isFile()).toBe(true);
  });
});

describe("MOVE", () => {
  const to = (destination: string, extra: Record<string, string> = {}) => ({
    headers: { destination, host: "dav.test", ...extra },
  });

  it("renames with 201 and leaves nothing behind", async () => {
    expect((await request(session, "MOVE", "/dir/file.txt", to("/moved.txt"))).status).toBe(201);
    expect((await request(session, "GET", "/moved.txt")).text).toBe("hello world");
    expect((await request(session, "GET", "/dir/file.txt")).status).toBe(404);
  });

  it("takes an absolute-URI destination on the same origin", async () => {
    const reply = await request(session, "MOVE", "/dir/file.txt", {
      headers: { destination: "http://dav.test/moved.txt", host: "dav.test" },
    });
    expect(reply.status).toBe(201);
  });

  it("is 502 for a destination on another server", async () => {
    const reply = await request(session, "MOVE", "/dir/file.txt", {
      headers: { destination: "http://elsewhere/moved.txt", host: "dav.test" },
    });
    expect(reply.status).toBe(502);
  });

  it("replaces an existing destination with 204", async () => {
    await (await driver.open("/taken", "w")).close();
    expect((await request(session, "MOVE", "/dir/file.txt", to("/taken"))).status).toBe(204);
    expect((await request(session, "GET", "/taken")).text).toBe("hello world");
  });

  it("is 400 at any depth but infinity, per §9.9.2", async () => {
    expect((await request(session, "MOVE", "/dir", to("/x", { depth: "0" }))).status).toBe(400);
    expect((await request(session, "MOVE", "/dir", to("/x", { depth: "1" }))).status).toBe(400);
  });

  it("is 403 for the share itself", async () => {
    expect((await request(session, "MOVE", "/", to("/elsewhere"))).status).toBe(403);
  });

  it("is 501 when the driver cannot rename", async () => {
    /* `ENOSYS` is what the loopback answers for a method a driver does not
       have, and 501 is the answer that says so without blaming the client. */
    const { rename: _rename, ...withoutRename } = driver as unknown as Record<string, unknown>;
    const reply = await request(
      new WebdavSession(withoutRename as unknown as FsDriver),
      "MOVE",
      "/dir/file.txt",
      to("/moved.txt"),
    );
    expect(reply.status).toBe(501);
  });
});

// ---------------------------------------------------------------------------
// PROPFIND
// ---------------------------------------------------------------------------

describe("PROPFIND", () => {
  it("describes the resource itself at Depth: 0", async () => {
    const reply = await request(session, "PROPFIND", "/dir/file.txt", {
      headers: { depth: "0" },
    });
    expect(reply.status).toBe(207);
    expect(reply.headers["content-type"]).toBe('application/xml; charset="utf-8"');
    expect(hrefs(reply.text)).toEqual(["/dir/file.txt"]);
    expect(property(reply.text, "getcontentlength")).toBe("11");
    expect(property(reply.text, "displayname")).toBe("file.txt");
    expect(property(reply.text, "getcontenttype")).toBe("application/octet-stream");
    expect(reply.text).toContain("<resourcetype></resourcetype>");
    expect(statuses(reply.text)).toEqual([200]);
  });

  it("lists a collection and its children at Depth: 1", async () => {
    await driver.mkdir("/dir/sub");
    const reply = await request(session, "PROPFIND", "/dir", { headers: { depth: "1" } });
    expect(reply.status).toBe(207);
    /* The collection itself first, then its members; a collection's href ends
       in a slash and a resource's does not. */
    expect(hrefs(reply.text)).toEqual(["/dir/", "/dir/file.txt", "/dir/sub/"]);
    expect(reply.text).toContain("<resourcetype><collection></collection></resourcetype>");
  });

  it("percent-encodes a name that would otherwise re-parse as syntax", async () => {
    await (await driver.open("/dir/a b?c", "w")).close();
    const reply = await request(session, "PROPFIND", "/dir", { headers: { depth: "1" } });
    expect(hrefs(reply.text)).toContain("/dir/a%20b%3Fc");
  });

  it("refuses infinity — the default — with propfind-finite-depth", async () => {
    for (const headers of [{}, { depth: "infinity" }] as Record<string, string>[]) {
      const reply = await request(session, "PROPFIND", "/dir", { headers });
      expect(reply.status).toBe(403);
      expect(reply.text).toContain("<propfind-finite-depth>");
    }
  });

  it("is 400 for a Depth the protocol has no meaning for", async () => {
    expect((await request(session, "PROPFIND", "/dir", { headers: { depth: "2" } })).status).toBe(
      400,
    );
  });

  it("leaves a property the resource does not have out of allprop", async () => {
    /* A collection has no `getcontentlength` — §15.4 defines it as the
       `Content-Length` of a `GET`, which is a 405 here — so allprop does not
       mention it, and there is no 404 propstat at all. */
    const reply = await request(session, "PROPFIND", "/dir", { headers: { depth: "0" } });
    expect(reply.text).not.toContain("getcontentlength");
    expect(reply.text).not.toContain("getetag");
    expect(statuses(reply.text)).toEqual([200]);
  });

  it("splits found and missing properties into two propstats", async () => {
    const reply = await request(session, "PROPFIND", "/dir/file.txt", {
      headers: { depth: "0" },
      body:
        `<D:propfind xmlns:D="DAV:"><D:prop>` +
        `<D:getcontentlength/><D:getetag/><D:nosuchprop/>` +
        `</D:prop></D:propfind>`,
    });
    expect(statuses(reply.text)).toEqual([200, 404]);
    expect(property(reply.text, "getcontentlength")).toBe("11");
    expect(reply.text).toContain("<nosuchprop></nosuchprop>");
  });

  it("answers propname with names and no values", async () => {
    const reply = await request(session, "PROPFIND", "/dir/file.txt", {
      headers: { depth: "0" },
      body: `<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>`,
    });
    expect(reply.text).toContain("<getcontentlength></getcontentlength>");
    expect(reply.text).toContain("<getetag></getetag>");
    expect(statuses(reply.text)).toEqual([200]);
  });

  it("answers the quota pair from statfs, and only when asked", async () => {
    const body =
      `<D:propfind xmlns:D="DAV:"><D:prop>` +
      `<D:quota-available-bytes/><D:quota-used-bytes/>` +
      `</D:prop></D:propfind>`;
    const reply = await request(session, "PROPFIND", "/", { headers: { depth: "0" }, body });
    expect(statuses(reply.text)).toEqual([200]);
    expect(Number(property(reply.text, "quota-available-bytes"))).toBeGreaterThan(0);
    expect(Number(property(reply.text, "quota-used-bytes"))).toBeGreaterThanOrEqual(0);
    // Not in `allprop`, which RFC 4331 §3 requires.
    const all = await request(session, "PROPFIND", "/", { headers: { depth: "0" } });
    expect(all.text).not.toContain("quota-");
  });

  it("is a 404 propstat, never a zero, for a driver with no statfs", async () => {
    const { statfs: _statfs, ...withoutStatfs } = driver as unknown as Record<string, unknown>;
    const reply = await request(
      new WebdavSession(withoutStatfs as unknown as FsDriver),
      "PROPFIND",
      "/",
      {
        headers: { depth: "0" },
        body: `<D:propfind xmlns:D="DAV:"><D:prop><D:quota-used-bytes/></D:prop></D:propfind>`,
      },
    );
    expect(statuses(reply.text)).toEqual([404]);
  });

  it("skips a child that vanishes between the listing and its stat", async () => {
    await (await driver.open("/dir/ghost", "w")).close();
    const haunted = withFailure(driver, "stat", (path) =>
      path === "/dir/ghost" ? fsError("ENOENT", { syscall: "stat", path }) : undefined,
    );
    const reply = await request(new WebdavSession(haunted), "PROPFIND", "/dir", {
      headers: { depth: "1" },
    });
    expect(reply.status).toBe(207);
    expect(hrefs(reply.text)).toEqual(["/dir/", "/dir/file.txt"]);
  });

  it("is 404 for a resource that is not there", async () => {
    expect((await request(session, "PROPFIND", "/nope", { headers: { depth: "0" } })).status).toBe(
      404,
    );
  });

  it("is 400 for a body that is not a propfind", async () => {
    const reply = await request(session, "PROPFIND", "/dir", {
      headers: { depth: "0" },
      body: `<D:whatever xmlns:D="DAV:"/>`,
    });
    expect(reply.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// PROPPATCH
// ---------------------------------------------------------------------------

describe("PROPPATCH", () => {
  it("names every property with 403 and the condition that explains it", async () => {
    const reply = await request(session, "PROPPATCH", "/dir/file.txt", {
      body:
        `<D:propertyupdate xmlns:D="DAV:">` +
        `<D:set><D:prop><D:getlastmodified>x</D:getlastmodified></D:prop></D:set>` +
        `<D:remove><D:prop><Z:mine xmlns:Z="urn:z"/></D:prop></D:remove>` +
        `</D:propertyupdate>`,
    });
    expect(reply.status).toBe(207);
    expect(statuses(reply.text)).toEqual([403]);
    expect(reply.text).toContain("<getlastmodified></getlastmodified>");
    expect(reply.text).toContain("<mine></mine>");
    expect(reply.text).toContain("<cannot-modify-protected-property>");
  });

  it("is 404 for a resource that is not there", async () => {
    const reply = await request(session, "PROPPATCH", "/nope", {
      body: `<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:a/></D:prop></D:set></D:propertyupdate>`,
    });
    expect(reply.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// authentication
// ---------------------------------------------------------------------------

describe("Basic authentication", () => {
  const credentials = { username: "ada", password: "pass:word" };
  const encode = (text: string): string => Buffer.from(text, "utf8").toString("base64");

  it("serves everything when no credentials are configured", async () => {
    expect((await request(session, "OPTIONS", "/")).status).toBe(200);
  });

  it("challenges a request with no credentials", async () => {
    const guarded = new WebdavSession(driver, { credentials });
    const reply = await request(guarded, "GET", "/dir/file.txt");
    expect(reply.status).toBe(401);
    expect(reply.headers["www-authenticate"]).toBe(`Basic realm="mountx", charset="UTF-8"`);
    expect(reply.text).toBe("");
  });

  it("accepts the pair it was given, colons in the password included", async () => {
    const guarded = new WebdavSession(driver, { credentials });
    const reply = await request(guarded, "GET", "/dir/file.txt", {
      headers: { authorization: `Basic ${encode("ada:pass:word")}` },
    });
    expect(reply.status).toBe(200);
  });

  it("refuses base64 that decodes to something else than it says", async () => {
    /* Node's decoder is sloppy — it will accept `YWQ` and answer one byte — so
       a header that does not survive a re-encode is not the credential it
       appears to be. */
    const guarded = new WebdavSession(driver, { credentials });
    const reply = await request(guarded, "OPTIONS", "/", {
      headers: { authorization: "Basic YWQ" },
    });
    expect(reply.status).toBe(401);
  });

  it("refuses everything else", async () => {
    const guarded = new WebdavSession(driver, { credentials, realm: 'the "share"' });
    for (const header of [
      `Basic ${encode("ada:wrong")}`,
      `Basic ${encode("eve:pass:word")}`,
      `Basic ${encode("ada")}`,
      `Bearer ${encode("ada:pass:word")}`,
      `Basic not-base64!`,
      `Basic`,
      ``,
    ]) {
      const reply = await request(guarded, "GET", "/dir/file.txt", {
        headers: { authorization: header },
      });
      expect(reply.status, JSON.stringify(header)).toBe(401);
      // The realm is quoted, so a quote in it cannot end the parameter early.
      expect(reply.headers["www-authenticate"]).toBe(`Basic realm="the share", charset="UTF-8"`);
    }
  });
});

// ---------------------------------------------------------------------------
// the one-reply discipline
// ---------------------------------------------------------------------------

describe("one reply, always", () => {
  it("carries a driver failure that is not absence through as its own status", async () => {
    /* The difference `#statOrAbsent` turns on: `ENOENT` is "there is nothing
       there" and everything else is a failure the client is owed. */
    const guarded = withFailure(driver, "stat", (path) =>
      path === "/dir/locked.txt" ? fsError("EACCES", { syscall: "stat", path }) : undefined,
    );
    const reply = await request(new WebdavSession(guarded), "PUT", "/dir/locked.txt", {
      body: "x",
    });
    expect(reply.status).toBe(403);
  });

  it("turns an errno nothing has a name for into one 500", async () => {
    const broken = withFailure(driver, "stat", (path) =>
      path === "/dir/file.txt" ? Object.assign(new Error("weird"), { code: "EWHAT" }) : undefined,
    );
    const failing = new WebdavSession(broken);
    expect((await request(failing, "GET", "/dir/file.txt")).status).toBe(500);
    // And the next request is answered normally.
    expect((await request(failing, "OPTIONS", "/")).status).toBe(200);
    expect(failing.assertions).toEqual([]);
    expect(failing.stats.replies).toBe(failing.stats.requests);
  });

  it("answers a body source that dies without leaving the request unanswered", async () => {
    const reply = await session.handleRequest(
      { method: "PUT", target: "/dir/torn", headers: {} },
      (async function* () {
        yield Buffer.from("half", "utf8");
        throw new Error("the client hung up");
      })(),
    );
    expect(reply.status).toBe(500);
    expect(session.assertions).toEqual([]);
  });

  it("counts every request and every reply", async () => {
    await request(session, "OPTIONS", "/");
    await request(session, "GET", "/nope");
    expect(session.stats.requests).toBe(2);
    expect(session.stats.replies).toBe(2);
    expect(session.stats.errors).toBe(1);
    expect(session.stats.methods.get("GET")).toBe(1);
    expect(session.stats.assertions).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// a driver that fails on demand
// ---------------------------------------------------------------------------

/**
 * The base driver with one method made to fail for chosen paths.
 *
 * The failure is keyed on the path so the rest of a recursive walk runs
 * normally, which is what the `207` cases need: a tree where exactly one entry
 * will not go.
 */
function withFailure(
  base: FsDriver & { statfs?: (path: string) => Promise<StatsFsLike> },
  method: "stat" | "unlink" | "mkdir" | "rmdir" | "readdir",
  failure: (path: string) => Error | undefined,
): FsDriver {
  const original = base[method] as (...args: unknown[]) => Promise<unknown>;
  return {
    ...base,
    [method]: async (path: string, ...rest: unknown[]) => {
      const error = failure(path);
      if (error !== undefined) {
        throw error;
      }
      return await original.call(base, path, ...rest);
    },
  } as FsDriver;
}
