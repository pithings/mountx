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
  it("advertises classes 1, 2 and 3, each of which is answered", async () => {
    const reply = await request(session, "OPTIONS", "/");
    expect(reply.status).toBe(200);
    expect(reply.headers["dav"]).toBe("1, 2, 3");
    expect(reply.headers["allow"]).toContain("PROPFIND");
    expect(reply.headers["allow"]).toContain("LOCK");
    expect(reply.headers["allow"]).toContain("UNLOCK");
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
    for (const method of ["PATCH", "REPORT", "SEARCH", "BREW"]) {
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

describe("COPY of a symbolic link at the top of the tree", () => {
  it("is 403 for a link to a collection, which is what makes the walk terminate", async () => {
    /* The destination-inside-source test compares paths as text, so a link to
       an ancestor slips past it — and the walk then copies a tree it is writing
       into, creating the next level every pass. `#copyTree` already refuses a
       link to a collection it meets *inside* the tree; this is the same rule at
       the top of it. */
    await driver.symlink("/", "/link");
    const reply = await request(session, "COPY", "/link", {
      headers: { destination: "/dst" },
    });
    expect(reply.status).toBe(403);
    await expect(driver.stat("/dst")).rejects.toThrow();
  });

  it("still copies the bytes behind a link to a file, and still moves the link", async () => {
    await driver.symlink("/dir/file.txt", "/pointer");
    expect(
      (await request(session, "COPY", "/pointer", { headers: { destination: "/copied.txt" } }))
        .status,
    ).toBe(201);
    expect((await request(session, "GET", "/copied.txt")).text).toBe("hello world");
    // A MOVE walks nothing — it renames the link itself — so it is untouched.
    await driver.symlink("/dir", "/dirlink");
    expect(
      (await request(session, "MOVE", "/dirlink", { headers: { destination: "/moved-link" } }))
        .status,
    ).toBe(201);
    expect((await driver.lstat("/moved-link")).isSymbolicLink()).toBe(true);
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

  it("does not answer a foreign property that shares a local name with one of its own", async () => {
    /* §4 names a property with a namespace *and* a local name. Finder and
       Explorer ask for `urn:schemas-microsoft-com:` properties; answering one
       of those with the `DAV:` value would be answering a question nobody
       asked. Both are in the one request so the two propstats are the same
       resource's. */
    const reply = await request(session, "PROPFIND", "/dir/file.txt", {
      headers: { depth: "0" },
      body:
        `<propfind xmlns="DAV:" xmlns:Z="urn:schemas-microsoft-com:">` +
        `<prop><getlastmodified/><Z:getlastmodified/><Z:Win32CreationTime/></prop></propfind>`,
    });
    expect(reply.status).toBe(207);
    expect(statuses(reply.text)).toEqual([200, 404]);
    // The 404 block names both foreign properties, each in the namespace it was asked in.
    expect(reply.text).toContain(
      `<getlastmodified xmlns="urn:schemas-microsoft-com:"></getlastmodified>`,
    );
    expect(reply.text).toContain(
      `<Win32CreationTime xmlns="urn:schemas-microsoft-com:"></Win32CreationTime>`,
    );
    // ...and the 200 block holds exactly one `getlastmodified`, the server's own.
    expect(reply.text.split("<getlastmodified>")).toHaveLength(2);
  });

  it("names a property asked for under an undeclared prefix, without the prefix", async () => {
    const reply = await request(session, "PROPFIND", "/dir/file.txt", {
      headers: { depth: "0" },
      body: `<propfind xmlns="DAV:"><prop><Z:Win32FileAttributes/></prop></propfind>`,
    });
    expect(statuses(reply.text)).toEqual([404]);
    /* In no namespace, said with an empty declaration — writing it bare would
       put it in `DAV:` and claim the client named a property of this server's. */
    expect(reply.text).toContain(`<Win32FileAttributes xmlns=""></Win32FileAttributes>`);
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
  it("names every property with its own status and the condition that explains it", async () => {
    const reply = await request(session, "PROPPATCH", "/dir/file.txt", {
      body:
        `<D:propertyupdate xmlns:D="DAV:">` +
        `<D:set><D:prop><D:displayname>x</D:displayname></D:prop></D:set>` +
        `<D:remove><D:prop><Z:mine xmlns:Z="urn:z"/></D:prop></D:remove>` +
        `</D:propertyupdate>`,
    });
    expect(reply.status).toBe(207);
    expect(statuses(reply.text)).toEqual([403]);
    expect(reply.text).toContain("<displayname></displayname>");
    /* Named back in the namespace it was asked about, not re-rooted in `DAV:`
       where it would be a different property. */
    expect(reply.text).toContain(`<mine xmlns="urn:z"></mine>`);
    expect(reply.text).toContain("<cannot-modify-protected-property>");
  });

  it("is 404 for a resource that is not there", async () => {
    const reply = await request(session, "PROPPATCH", "/nope", {
      body: `<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:a/></D:prop></D:set></D:propertyupdate>`,
    });
    expect(reply.status).toBe(404);
  });

  it("stores getlastmodified through utimes, which is the one property it can", async () => {
    const when = "Sun, 06 Nov 1994 08:49:37 GMT";
    const reply = await request(session, "PROPPATCH", "/dir/file.txt", {
      body:
        `<D:propertyupdate xmlns:D="DAV:">` +
        `<D:set><D:prop><D:getlastmodified>${when}</D:getlastmodified></D:prop></D:set>` +
        `</D:propertyupdate>`,
    });
    expect(reply.status).toBe(207);
    expect(statuses(reply.text)).toEqual([200]);
    expect(reply.text).not.toContain("cannot-modify-protected-property");
    // The driver really has it, and a GET reports it back.
    expect((await driver.stat("/dir/file.txt")).mtimeMs).toBe(Date.parse(when));
    expect((await request(session, "HEAD", "/dir/file.txt")).headers["last-modified"]).toBe(when);
  });

  it("will not write a foreign getlastmodified onto the driver", async () => {
    /* The one place reading half a name would have been a *mutation* decided
       by a misread: same local name, somebody else's namespace, and `utimes`
       on the other side of it. */
    const before = (await driver.stat("/dir/file.txt")).mtimeMs;
    const reply = await request(session, "PROPPATCH", "/dir/file.txt", {
      body:
        `<propertyupdate xmlns="DAV:" xmlns:Z="urn:schemas-microsoft-com:">` +
        `<set><prop><Z:getlastmodified>Sun, 06 Nov 1994 08:49:37 GMT</Z:getlastmodified></prop></set>` +
        `</propertyupdate>`,
    });
    expect(reply.status).toBe(207);
    expect(statuses(reply.text)).toEqual([403]);
    expect(reply.text).toContain("cannot-modify-protected-property");
    expect(reply.text).toContain(
      `<getlastmodified xmlns="urn:schemas-microsoft-com:"></getlastmodified>`,
    );
    expect((await driver.stat("/dir/file.txt")).mtimeMs).toBe(before);
  });

  it("is 409 for a value that is not an HTTP-date (§9.2.1)", async () => {
    const reply = await request(session, "PROPPATCH", "/dir/file.txt", {
      body:
        `<D:propertyupdate xmlns:D="DAV:">` +
        `<D:set><D:prop><D:getlastmodified>last Tuesday</D:getlastmodified></D:prop></D:set>` +
        `</D:propertyupdate>`,
    });
    expect(statuses(reply.text)).toEqual([409]);
    expect((await driver.stat("/dir/file.txt")).mtimeMs).not.toBe(Number.NaN);
  });

  it("is atomic: one failure makes the settable property 424 and writes nothing", async () => {
    /* §9.2: "instructions MUST either all be executed or none executed", and
       §9.2.1 spells out the reply — a property that would have succeeded
       becomes 424 Failed Dependency. */
    const before = (await driver.stat("/dir/file.txt")).mtimeMs;
    const reply = await request(session, "PROPPATCH", "/dir/file.txt", {
      body:
        `<D:propertyupdate xmlns:D="DAV:">` +
        `<D:set><D:prop>` +
        `<D:getlastmodified>Sun, 06 Nov 1994 08:49:37 GMT</D:getlastmodified>` +
        `<D:getetag>"whatever"</D:getetag>` +
        `</D:prop></D:set>` +
        `</D:propertyupdate>`,
    });
    expect(statuses(reply.text)).toEqual([424, 403]);
    expect((await driver.stat("/dir/file.txt")).mtimeMs).toBe(before);
  });

  it("refuses getlastmodified on a driver that cannot keep it", async () => {
    /* Declared-or-inferred, never faked: without `times` the property really is
       protected here, and answering 200 would be storing nothing. */
    const { utimes: _utimes, ...timeless } = driver as FsDriver & { utimes?: unknown };
    const reply = await request(
      new WebdavSession(timeless as FsDriver),
      "PROPPATCH",
      "/dir/file.txt",
      {
        body:
          `<D:propertyupdate xmlns:D="DAV:">` +
          `<D:set><D:prop><D:getlastmodified>Sun, 06 Nov 1994 08:49:37 GMT</D:getlastmodified></D:prop></D:set>` +
          `</D:propertyupdate>`,
      },
    );
    expect(statuses(reply.text)).toEqual([403]);
    expect(reply.text).toContain("<cannot-modify-protected-property>");
  });

  it("removes nothing: a live property cannot be removed either", async () => {
    const reply = await request(session, "PROPPATCH", "/dir/file.txt", {
      body:
        `<D:propertyupdate xmlns:D="DAV:">` +
        `<D:remove><D:prop><D:getlastmodified/></D:prop></D:remove>` +
        `</D:propertyupdate>`,
    });
    expect(statuses(reply.text)).toEqual([403]);
  });
});

// ---------------------------------------------------------------------------
// LOCK / UNLOCK
// ---------------------------------------------------------------------------

/* One base moment and a clock the test moves by hand: a lease is the one thing
   in this protocol that passes on its own, and waiting for it is not a test. */
const LOCK_START = 1_700_000_000_000;

/** A session with a clock a test drives and tokens a test can write down. */
function lockingSession(base: FsDriver = driver): {
  session: WebdavSession;
  advance: (seconds: number) => void;
} {
  let clock = LOCK_START;
  let minted = 0;
  const built = new WebdavSession(base, {
    now: () => clock,
    locks: { newToken: () => `urn:uuid:token-${++minted}` },
  });
  return { session: built, advance: (seconds) => (clock += seconds * 1000) };
}

const LOCKINFO =
  `<D:lockinfo xmlns:D="DAV:">` +
  `<D:lockscope><D:exclusive/></D:lockscope>` +
  `<D:locktype><D:write/></D:locktype>` +
  `<D:owner><D:href>mailto:ada@example.com</D:href></D:owner>` +
  `</D:lockinfo>`;

const SHARED_LOCKINFO =
  `<D:lockinfo xmlns:D="DAV:">` +
  `<D:lockscope><D:shared/></D:lockscope>` +
  `<D:locktype><D:write/></D:locktype>` +
  `</D:lockinfo>`;

/** `LOCK` a path and answer the token the reply minted. */
async function lockOf(
  target: WebdavSession,
  path: string,
  options: { headers?: Record<string, string>; body?: string } = {},
): Promise<string> {
  const reply = await request(target, "LOCK", path, {
    headers: options.headers,
    body: options.body ?? LOCKINFO,
  });
  const token = /<locktoken><href>([^<]+)<\/href>/.exec(reply.text)?.[1];
  if (token === undefined) {
    throw new Error(`LOCK ${path} answered ${reply.status} and no token`);
  }
  return token;
}

describe("LOCK", () => {
  it("answers 200, a Lock-Token header and §9.10.1's body for a resource that is there", async () => {
    const { session: locking } = lockingSession();
    const reply = await request(locking, "LOCK", "/dir/file.txt", { body: LOCKINFO });
    expect(reply.status).toBe(200);
    expect(reply.headers["lock-token"]).toBe("<urn:uuid:token-1>");
    expect(reply.headers["content-type"]).toBe(`application/xml; charset="utf-8"`);
    expect(reply.text).toContain(`<prop xmlns="DAV:"><lockdiscovery><activelock>`);
    expect(reply.text).toContain(`<lockscope><exclusive></exclusive></lockscope>`);
    expect(reply.text).toContain(`<depth>infinity</depth>`);
    expect(reply.text).toContain(`<owner><href>mailto:ada@example.com</href></owner>`);
    expect(reply.text).toContain(`<timeout>Second-600</timeout>`);
    expect(reply.text).toContain(`<locktoken><href>urn:uuid:token-1</href></locktoken>`);
    expect(reply.text).toContain(`<lockroot><href>/dir/file.txt</href></lockroot>`);
    expect(locking.locks.all(LOCK_START)).toHaveLength(1);
  });

  it("creates the locked empty resource §7.3 requires, and answers 201", async () => {
    const { session: locking } = lockingSession();
    const reply = await request(locking, "LOCK", "/dir/reserved.txt", { body: LOCKINFO });
    expect(reply.status).toBe(201);
    expect(reply.headers["lock-token"]).toBe("<urn:uuid:token-1>");
    // A real, empty, readable resource — not a lock-null one.
    expect((await driver.stat("/dir/reserved.txt")).size).toBe(0);
    expect((await request(locking, "GET", "/dir/reserved.txt")).status).toBe(200);
  });

  it("is 409 when the collection above the new resource does not exist", async () => {
    /* §9.10.6: "a resource cannot be created at the destination until one or
       more intermediate collections have been created. The server MUST NOT
       create those intermediate collections automatically." */
    const { session: locking } = lockingSession();
    expect((await request(locking, "LOCK", "/nope/deep.txt", { body: LOCKINFO })).status).toBe(409);
    await expect(driver.stat("/nope")).rejects.toThrow();
  });

  it("takes Depth 0 or infinity and refuses 1 (§9.10.3)", async () => {
    const { session: locking } = lockingSession();
    const zero = await request(locking, "LOCK", "/dir", {
      headers: { depth: "0" },
      body: LOCKINFO,
    });
    expect(zero.status).toBe(200);
    expect(zero.text).toContain("<depth>0</depth>");
    expect(zero.text).toContain(`<lockroot><href>/dir/</href></lockroot>`);
    const one = await request(locking, "LOCK", "/dir/file.txt", {
      headers: { depth: "1" },
      body: LOCKINFO,
    });
    expect(one.status).toBe(400);
  });

  it("honours the Timeout header, and answers Infinite with the cap it will grant", async () => {
    const { session: locking } = lockingSession();
    const asked = await request(locking, "LOCK", "/dir/file.txt", {
      headers: { timeout: "Second-90" },
      body: LOCKINFO,
    });
    expect(asked.text).toContain("<timeout>Second-90</timeout>");
    const forever = await request(locking, "LOCK", "/dir", {
      headers: { timeout: "Infinite, Second-4100000000", depth: "0" },
      body: SHARED_LOCKINFO,
    });
    expect(forever.text).toContain("<timeout>Second-3600</timeout>");
  });

  it("is 423 no-conflicting-lock, naming the lock in the way (§9.10.5, §16)", async () => {
    const { session: locking } = lockingSession();
    await lockOf(locking, "/dir", { headers: { depth: "infinity" } });
    const reply = await request(locking, "LOCK", "/dir/file.txt", { body: LOCKINFO });
    expect(reply.status).toBe(423);
    expect(reply.text).toContain(`<no-conflicting-lock><href>/dir/</href></no-conflicting-lock>`);
  });

  it("refuses a depth-infinity lock over a subtree that already holds one (§7.4)", async () => {
    const { session: locking } = lockingSession();
    await lockOf(locking, "/dir/file.txt");
    const reply = await request(locking, "LOCK", "/dir", { body: LOCKINFO });
    expect(reply.status).toBe(423);
    expect(reply.text).toContain(`<href>/dir/file.txt</href>`);
  });

  it("grants two shared locks on one resource", async () => {
    const { session: locking } = lockingSession();
    const first = await lockOf(locking, "/dir/file.txt", { body: SHARED_LOCKINFO });
    const second = await lockOf(locking, "/dir/file.txt", { body: SHARED_LOCKINFO });
    expect(second).not.toBe(first);
    expect(locking.locks.covering("/dir/file.txt", LOCK_START)).toHaveLength(2);
  });

  it("is 503 rather than a new lock when the table is full", async () => {
    const full = new WebdavSession(driver, { now: () => LOCK_START, locks: { maxLocks: 1 } });
    expect((await request(full, "LOCK", "/dir/file.txt", { body: SHARED_LOCKINFO })).status).toBe(
      200,
    );
    const reply = await request(full, "LOCK", "/dir", {
      headers: { depth: "0" },
      body: SHARED_LOCKINFO,
    });
    expect(reply.status).toBe(503);
  });

  it("refuses a body that is not a lockinfo this server can serve", async () => {
    const { session: locking } = lockingSession();
    for (const body of [
      `<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope></D:lockinfo>`,
      `<D:lockinfo xmlns:D="DAV:"><D:locktype><D:write/></D:locktype></D:lockinfo>`,
      `<D:propfind xmlns:D="DAV:"/>`,
    ]) {
      expect((await request(locking, "LOCK", "/dir/file.txt", { body })).status).toBe(400);
    }
  });

  it("lapses on its own once the lease runs out, with no timer anywhere", async () => {
    const { session: locking, advance } = lockingSession();
    await lockOf(locking, "/dir/file.txt", { headers: { timeout: "Second-60" } });
    advance(59);
    expect(locking.locks.all(LOCK_START + 59_000)).toHaveLength(1);
    advance(1);
    // And the resource takes an exclusive lock again, which is what expiry is for.
    expect((await request(locking, "LOCK", "/dir/file.txt", { body: LOCKINFO })).status).toBe(200);
  });
});

describe("LOCK refresh", () => {
  it("restarts the lease and answers no Lock-Token (§9.10.2)", async () => {
    const { session: locking, advance } = lockingSession();
    const token = await lockOf(locking, "/dir/file.txt", { headers: { timeout: "Second-600" } });
    advance(300);
    const reply = await request(locking, "LOCK", "/dir/file.txt", {
      headers: { if: `(<${token}>)`, timeout: "Second-120", depth: "1" },
    });
    expect(reply.status).toBe(200);
    expect(reply.headers["lock-token"]).toBeUndefined();
    expect(reply.text).toContain(`<timeout>Second-120</timeout>`);
    expect(reply.text).toContain(`<locktoken><href>${token}</href></locktoken>`);
    // `Depth: 1` above is ignored on a refresh, which §9.10.2 requires.
    expect(reply.text).toContain(`<depth>infinity</depth>`);
    expect(locking.locks.all(LOCK_START + 300_000)).toHaveLength(1);
  });

  it("refreshes through any URL inside the lock's scope", async () => {
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir");
    const reply = await request(locking, "LOCK", "/dir/file.txt", {
      headers: { if: `(<${token}>)` },
    });
    expect(reply.status).toBe(200);
    expect(reply.text).toContain(`<lockroot><href>/dir/</href></lockroot>`);
  });

  it("needs an If header, since that is the only thing naming the lock", async () => {
    const { session: locking } = lockingSession();
    await lockOf(locking, "/dir/file.txt");
    expect((await request(locking, "LOCK", "/dir/file.txt")).status).toBe(400);
  });

  it("is 412 lock-token-matches-request-uri for a token that names no lock here", async () => {
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir/file.txt");
    // A token that never existed.
    const unknown = await request(locking, "LOCK", "/dir/file.txt", {
      headers: { if: `(<urn:uuid:nobody>)` },
    });
    expect(unknown.status).toBe(412);
    expect(unknown.text).toContain("<lock-token-matches-request-uri>");
    // A real token, on a resource outside its depth-0 scope.
    const outside = await request(locking, "LOCK", "/dir", { headers: { if: `(<${token}>)` } });
    expect(outside.status).toBe(412);
  });

  it("is 400 for an If header that is not §10.4.2's grammar", async () => {
    const { session: locking } = lockingSession();
    expect(
      (await request(locking, "LOCK", "/dir/file.txt", { headers: { if: "(<unterminated" } }))
        .status,
    ).toBe(400);
  });
});

describe("UNLOCK", () => {
  it("deletes the lock and answers 204 with no body (§9.11.1)", async () => {
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir/file.txt");
    const reply = await request(locking, "UNLOCK", "/dir/file.txt", {
      headers: { "lock-token": `<${token}>` },
    });
    expect(reply.status).toBe(204);
    expect(reply.text).toBe("");
    expect(locking.locks.all(LOCK_START)).toEqual([]);
  });

  it("unlocks through any URL inside the scope, and refuses one outside it", async () => {
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir");
    const outside = await request(locking, "UNLOCK", "/", {
      headers: { "lock-token": `<${token}>` },
    });
    expect(outside.status).toBe(409);
    expect(outside.text).toContain("<lock-token-matches-request-uri>");
    expect(
      (
        await request(locking, "UNLOCK", "/dir/file.txt", {
          headers: { "lock-token": `<${token}>` },
        })
      ).status,
    ).toBe(204);
  });

  it("is 400 with no token and 409 with one that names no lock", async () => {
    const { session: locking } = lockingSession();
    expect((await request(locking, "UNLOCK", "/dir/file.txt")).status).toBe(400);
    expect(
      (await request(locking, "UNLOCK", "/dir/file.txt", { headers: { "lock-token": "nope" } }))
        .status,
    ).toBe(400);
    expect(
      (
        await request(locking, "UNLOCK", "/dir/file.txt", {
          headers: { "lock-token": "<urn:uuid:nobody>" },
        })
      ).status,
    ).toBe(409);
  });
});

describe("locks and the resources under them", () => {
  it("reports supportedlock and lockdiscovery as what is really there (§15.8, §15.10)", async () => {
    const { session: locking } = lockingSession();
    const empty = await request(locking, "PROPFIND", "/dir/file.txt", {
      headers: { depth: "0" },
      body: `<D:propfind xmlns:D="DAV:"><D:prop><D:supportedlock/><D:lockdiscovery/></D:prop></D:propfind>`,
    });
    expect(empty.text).toContain("<lockdiscovery></lockdiscovery>");
    expect(empty.text).toContain("<lockentry><lockscope><exclusive></exclusive></lockscope>");
    const token = await lockOf(locking, "/dir");
    const held = await request(locking, "PROPFIND", "/dir/file.txt", {
      headers: { depth: "0" },
      body: `<D:propfind xmlns:D="DAV:"><D:prop><D:lockdiscovery/></D:prop></D:propfind>`,
    });
    /* An indirectly locked member reports the ancestor's lock: §15.8 describes
       "the active locks on a resource", and this resource is locked. */
    expect(held.text).toContain(`<locktoken><href>${token}</href></locktoken>`);
    expect(held.text).toContain(`<lockroot><href>/dir/</href></lockroot>`);
    expect(statuses(held.text)).toEqual([200]);
  });

  it("destroys the locks a DELETE unmaps, and leaves the ones above it (§6.1)", async () => {
    const { session: locking } = lockingSession();
    await lockOf(locking, "/", { headers: { depth: "0" }, body: SHARED_LOCKINFO });
    const token = await lockOf(locking, "/dir/file.txt", { body: SHARED_LOCKINFO });
    expect(locking.locks.all(LOCK_START)).toHaveLength(2);
    const reply = await request(locking, "DELETE", "/dir/file.txt", {
      headers: { if: `(<${token}>)` },
    });
    expect(reply.status).toBe(204);
    expect(locking.locks.all(LOCK_START).map((lock) => lock.path)).toEqual(["/"]);
  });

  it("does not move a lock with the resource it locks (§7.6)", async () => {
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir/file.txt");
    const reply = await request(locking, "MOVE", "/dir/file.txt", {
      headers: { destination: "/moved.txt", if: `(<${token}>)` },
    });
    expect(reply.status).toBe(201);
    expect(locking.locks.all(LOCK_START)).toEqual([]);
  });

  it("keeps a destination's own lock across an overwriting MOVE (§7.6)", async () => {
    /* "If there is an existing lock at the destination, the server MUST add the
       moved resource to the destination lock scope" — the lock stays put and
       the arriving resource joins it. */
    const { session: locking } = lockingSession();
    await (await driver.open("/dir/other.txt", "w")).close();
    const token = await lockOf(locking, "/dir/other.txt", { body: SHARED_LOCKINFO });
    const reply = await request(locking, "MOVE", "/dir/file.txt", {
      /* §7.5.1's own form: the token belongs to the destination, so the list
         is tagged with the destination rather than left to fall on the request
         URI — which is not locked by it, and would be a 412. */
      headers: { destination: "/dir/other.txt", if: `</dir/other.txt> (<${token}>)` },
    });
    expect(reply.status).toBe(204);
    expect(locking.locks.all(LOCK_START).map((lock) => lock.token)).toEqual([token]);
  });
});

describe("the If header", () => {
  it("is a precondition on any method, and a false one is 412", async () => {
    const { session: locking } = lockingSession();
    const wrong = { if: `(["${"0".repeat(32)}"])` };
    expect((await request(locking, "GET", "/dir/file.txt", { headers: wrong })).status).toBe(412);
    expect(
      (await request(locking, "PUT", "/dir/file.txt", { headers: wrong, body: "x" })).status,
    ).toBe(412);
    expect((await request(locking, "DELETE", "/dir/file.txt", { headers: wrong })).status).toBe(
      412,
    );
  });

  it("matches an entity tag, weakly, as §10.4.4 lets a server choose", async () => {
    const { session: locking } = lockingSession();
    const etag = (await request(locking, "HEAD", "/dir/file.txt")).headers["etag"] as string;
    expect(
      (await request(locking, "GET", "/dir/file.txt", { headers: { if: `([${etag}])` } })).status,
    ).toBe(200);
    /* §10.4.9's example carries `[W/"A weak ETag"]` and expects it to match, so
       the weak comparison function is the one in use. */
    expect(
      (await request(locking, "GET", "/dir/file.txt", { headers: { if: `([W/${etag}])` } })).status,
    ).toBe(200);
  });

  it("is a conjunction inside a list and a disjunction between them (§10.4.3)", async () => {
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir/file.txt");
    const etag = (await request(locking, "HEAD", "/dir/file.txt")).headers["etag"] as string;
    // Both conditions hold.
    expect(
      (
        await request(locking, "GET", "/dir/file.txt", {
          headers: { if: `(<${token}> [${etag}])` },
        })
      ).status,
    ).toBe(200);
    // One of the two fails, so the list does — and there is no other list.
    expect(
      (await request(locking, "GET", "/dir/file.txt", { headers: { if: `(<${token}> ["nope"])` } }))
        .status,
    ).toBe(412);
    // A second list saves it.
    expect(
      (
        await request(locking, "GET", "/dir/file.txt", {
          headers: { if: `(<${token}> ["nope"]) ([${etag}])` },
        })
      ).status,
    ).toBe(200);
  });

  it("evaluates a tagged list against the resource it names (§10.4.10)", async () => {
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir");
    /* The lock is on the collection, and the list says so — this is the exact
       shape §10.4.10 walks through for a DELETE of a member. */
    const tagged = await request(locking, "DELETE", "/dir/file.txt", {
      headers: { if: `</dir/> (<${token}>)` },
    });
    expect(tagged.status).toBe(204);
  });

  it("treats an unmapped URL as a resource with none of the state asked about (§10.4.11)", async () => {
    const { session: locking } = lockingSession();
    expect(
      (await request(locking, "GET", "/dir/file.txt", { headers: { if: `</nothing> (["4217"])` } }))
        .status,
    ).toBe(412);
    expect(
      (
        await request(locking, "GET", "/dir/file.txt", {
          headers: { if: `</nothing> (Not ["4217"])` },
        })
      ).status,
    ).toBe(200);
  });

  it("submits a token even when the list it is in was never true (§10.4.8)", async () => {
    /* `(Not <DAV:no-lock>)` is the idiom: it makes the whole header true, so
       the first list's truth stops mattering, while the token in it still
       counts as submitted. */
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir/file.txt");
    const reply = await request(locking, "PUT", "/dir/file.txt", {
      headers: { if: `(<${token}> ["stale"]) (Not <DAV:no-lock>)` },
      body: "rewritten",
    });
    expect(reply.status).toBe(204);
  });

  it("is 400 for a header that is not the grammar", async () => {
    const { session: locking } = lockingSession();
    expect(
      (await request(locking, "GET", "/dir/file.txt", { headers: { if: "nonsense" } })).status,
    ).toBe(400);
  });
});

describe("what a write lock protects", () => {
  it("refuses a PUT to a locked resource, and names the lock root (§7.5.2)", async () => {
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir/file.txt");
    const refused = await request(locking, "PUT", "/dir/file.txt", { body: "mine" });
    expect(refused.status).toBe(423);
    expect(refused.text).toContain(
      `<lock-token-submitted><href>/dir/file.txt</href></lock-token-submitted>`,
    );
    // The bytes are untouched, and the token is what lets them through.
    expect((await request(locking, "GET", "/dir/file.txt")).text).toBe("hello world");
    const allowed = await request(locking, "PUT", "/dir/file.txt", {
      headers: { if: `(<${token}>)` },
      body: "mine",
    });
    expect(allowed.status).toBe(204);
  });

  it("is §7.5.2's answer for a member of a depth-infinity locked collection", async () => {
    const { session: locking } = lockingSession();
    await lockOf(locking, "/dir");
    const reply = await request(locking, "DELETE", "/dir/file.txt");
    expect(reply.status).toBe(423);
    expect(reply.text).toContain(`<lock-token-submitted><href>/dir/</href></lock-token-submitted>`);
  });

  it("protects a locked collection's membership at depth 0 as well (§7.4)", async () => {
    /* A depth-0 lock on a collection protects nothing inside it *except* its
       membership — so an existing member is writable and a new one is not. */
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir", { headers: { depth: "0" } });
    expect((await request(locking, "PUT", "/dir/file.txt", { body: "still fine" })).status).toBe(
      204,
    );
    expect((await request(locking, "PUT", "/dir/new.txt", { body: "no" })).status).toBe(423);
    expect((await request(locking, "MKCOL", "/dir/sub")).status).toBe(423);
    expect((await request(locking, "DELETE", "/dir/file.txt")).status).toBe(423);
    expect(
      (await request(locking, "MKCOL", "/dir/sub", { headers: { if: `</dir/> (<${token}>)` } }))
        .status,
    ).toBe(201);
  });

  it("answers 207 with 423 for a locked member of a tree, and deletes nothing", async () => {
    /* §9.6.1: "the Multi-Status body could include a response with status 423
       (Locked) if an internal resource was locked" — the failing resource is
       not the request URI, so it cannot be a bare status. */
    const { session: locking } = lockingSession();
    await lockOf(locking, "/dir/file.txt", { body: SHARED_LOCKINFO });
    const reply = await request(locking, "DELETE", "/dir");
    expect(reply.status).toBe(207);
    expect(hrefs(reply.text)).toEqual(["/dir/file.txt"]);
    expect(statuses(reply.text)).toEqual([423]);
    expect((await driver.stat("/dir/file.txt")).size).toBe(11);
  });

  it("needs both ends of a MOVE and only the destination of a COPY (§7.5.1)", async () => {
    const { session: locking } = lockingSession();
    await driver.mkdir("/target");
    const source = await lockOf(locking, "/dir/file.txt", { body: SHARED_LOCKINFO });
    const target = await lockOf(locking, "/target", { body: SHARED_LOCKINFO });
    // A COPY leaves the source alone, so only the destination's token is owed.
    expect(
      (
        await request(locking, "COPY", "/dir/file.txt", {
          headers: { destination: "/target/copy.txt", if: `</target/> (<${target}>)` },
        })
      ).status,
    ).toBe(201);
    // A MOVE changes both ends.
    expect(
      (
        await request(locking, "MOVE", "/dir/file.txt", {
          headers: { destination: "/target/moved.txt", if: `</target/> (<${target}>)` },
        })
      ).status,
    ).toBe(423);
    expect(
      (
        await request(locking, "MOVE", "/dir/file.txt", {
          headers: {
            destination: "/target/moved.txt",
            if: `(<${source}>) </target/> (<${target}>)`,
          },
        })
      ).status,
    ).toBe(201);
  });

  it("protects PROPPATCH and leaves GET, HEAD and PROPFIND alone (§7)", async () => {
    const { session: locking } = lockingSession();
    await lockOf(locking, "/dir/file.txt");
    const proppatch = await request(locking, "PROPPATCH", "/dir/file.txt", {
      body: `<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:a/></D:prop></D:set></D:propertyupdate>`,
    });
    expect(proppatch.status).toBe(423);
    /* "All other HTTP/WebDAV methods defined so far -- GET in particular --
       function independently of a write lock." */
    expect((await request(locking, "GET", "/dir/file.txt")).status).toBe(200);
    expect((await request(locking, "HEAD", "/dir/file.txt")).status).toBe(200);
    expect(
      (await request(locking, "PROPFIND", "/dir/file.txt", { headers: { depth: "0" } })).status,
    ).toBe(207);
  });

  it("refuses a LOCK that would create a member of a locked collection (§7.4)", async () => {
    const { session: locking } = lockingSession();
    const token = await lockOf(locking, "/dir", { headers: { depth: "0" } });
    const refused = await request(locking, "LOCK", "/dir/reserved.txt", { body: LOCKINFO });
    expect(refused.status).toBe(423);
    await expect(driver.stat("/dir/reserved.txt")).rejects.toThrow();
    const allowed = await request(locking, "LOCK", "/dir/reserved.txt", {
      headers: { if: `</dir/> (<${token}>)` },
      body: LOCKINFO,
    });
    expect(allowed.status).toBe(201);
  });
});

// ---------------------------------------------------------------------------
// RFC 9110's conditional requests
// ---------------------------------------------------------------------------

describe("conditional requests", () => {
  /** The resource's validators, as a client would have read them. */
  async function validators(): Promise<{ etag: string; lastModified: string }> {
    const reply = await request(session, "HEAD", "/dir/file.txt");
    return {
      etag: reply.headers["etag"] as string,
      lastModified: reply.headers["last-modified"] as string,
    };
  }

  it("answers 304 to a GET whose client already has this representation", async () => {
    const { etag, lastModified } = await validators();
    const conditions: Record<string, string>[] = [
      { "if-none-match": etag },
      { "if-none-match": `"other", ${etag}` },
      { "if-none-match": "*" },
      { "if-modified-since": lastModified },
    ];
    for (const headers of conditions) {
      const reply = await request(session, "GET", "/dir/file.txt", { headers });
      expect(reply.status, JSON.stringify(headers)).toBe(304);
      // §15.4.5: the validators, and no content — not even a length.
      expect(reply.headers["etag"]).toBe(etag);
      expect(reply.headers["content-length"]).toBeUndefined();
      expect(reply.text).toBe("");
    }
    expect(
      (await request(session, "HEAD", "/dir/file.txt", { headers: { "if-none-match": etag } }))
        .status,
    ).toBe(304);
  });

  it("answers 412 to a GET whose precondition failed", async () => {
    const { lastModified } = await validators();
    const past = new Date(Date.parse(lastModified) - 60_000).toUTCString();
    const conditions: Record<string, string>[] = [
      { "if-match": `"${"9".repeat(32)}"` },
      { "if-match": `W/"weak"` },
      { "if-unmodified-since": past },
    ];
    for (const headers of conditions) {
      expect(
        (await request(session, "GET", "/dir/file.txt", { headers })).status,
        JSON.stringify(headers),
      ).toBe(412);
    }
  });

  it("evaluates the conditionals before the Range (RFC 9110 §13.2.2)", async () => {
    const { etag } = await validators();
    const reply = await request(session, "GET", "/dir/file.txt", {
      headers: { "if-none-match": etag, range: "bytes=0-3" },
    });
    expect(reply.status).toBe(304);
  });

  it("ignores a date it cannot parse, which §13.1.3 requires", async () => {
    const reply = await request(session, "GET", "/dir/file.txt", {
      headers: { "if-modified-since": "the day before yesterday" },
    });
    expect(reply.status).toBe(200);
    expect(reply.text).toBe("hello world");
  });

  it("refuses a PUT whose precondition failed, and leaves the bytes alone", async () => {
    const { etag } = await validators();
    const stale = await request(session, "PUT", "/dir/file.txt", {
      headers: { "if-match": `"${"9".repeat(32)}"` },
      body: "overwritten",
    });
    expect(stale.status).toBe(412);
    expect((await request(session, "GET", "/dir/file.txt")).text).toBe("hello world");
    /* A match is 412 on a PUT and never 304: §13.2.2 gives `304` to `GET` and
       `HEAD` only. */
    const present = await request(session, "PUT", "/dir/file.txt", {
      headers: { "if-none-match": etag },
      body: "overwritten",
    });
    expect(present.status).toBe(412);
    const fresh = await request(session, "PUT", "/dir/file.txt", {
      headers: { "if-match": etag },
      body: "overwritten",
    });
    expect(fresh.status).toBe(204);
  });

  it("is where `If-None-Match: *` means create-only", async () => {
    /* The one case `mountx/s3` never has to answer: a `PUT` to a URL with no
       representation at all. §13.1.1 fails `If-Match` on it and §13.1.2 lets
       `If-None-Match` through. */
    expect(
      (
        await request(session, "PUT", "/dir/new.txt", {
          headers: { "if-none-match": "*" },
          body: "created",
        })
      ).status,
    ).toBe(201);
    expect(
      (
        await request(session, "PUT", "/dir/new.txt", {
          headers: { "if-none-match": "*" },
          body: "again",
        })
      ).status,
    ).toBe(412);
    expect(
      (
        await request(session, "PUT", "/dir/other.txt", {
          headers: { "if-match": "*" },
          body: "no",
        })
      ).status,
    ).toBe(412);
    await expect(driver.stat("/dir/other.txt")).rejects.toThrow();
    // A date form on nothing is ignored rather than refused (§13.1.4).
    expect(
      (
        await request(session, "PUT", "/dir/dated.txt", {
          headers: { "if-unmodified-since": "Sun, 06 Nov 1994 08:49:37 GMT" },
          body: "created anyway",
        })
      ).status,
    ).toBe(201);
  });

  it("answers 423 before 412 on a locked resource", async () => {
    /* Both preconditions failed; the lock is the one that says something
       durable about the resource, and the one the client must resolve first. */
    const { session: locking } = lockingSession();
    await lockOf(locking, "/dir/file.txt");
    const reply = await request(locking, "PUT", "/dir/file.txt", {
      headers: { "if-match": `"${"9".repeat(32)}"` },
      body: "no",
    });
    expect(reply.status).toBe(423);
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
