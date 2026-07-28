/**
 * The NFS session: everything the conformance suite cannot see.
 *
 * The conformance column proves the *filesystem* semantics survive the trip.
 * This file is about the parts of NFSv3 that have no `node:fs` equivalent and
 * so would otherwise be untested: post-operation attributes and weak cache
 * consistency, readdir cookies, stale handles, handle stability across renames
 * and hardlinks, and the RPC-level error statuses.
 *
 * Driven through a real socket with the JS client, because that is what proves
 * the encoders and decoders meet in the middle.
 */

import { afterEach, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../../src/drivers/memory.ts";
import {
  ACCESS3_LOOKUP,
  ACCESS3_MODIFY,
  ACCESS3_READ,
  AUTH_TOOWEAK,
  CREATE_EXCLUSIVE,
  CREATE_GUARDED,
  CREATE_UNCHECKED,
  FILE_SYNC,
  FSF3_CANSETTIME,
  FSF3_HOMOGENEOUS,
  FSF3_LINK,
  FSF3_SYMLINK,
  MNT3_OK,
  MNT3ERR_NOENT,
  MNT3ERR_NOTDIR,
  MOUNT_PROGRAM,
  MOUNT_V3,
  MSG_ACCEPTED,
  MSG_DENIED,
  NF3CHR,
  NF3DIR,
  NF3REG,
  NFS3_OK,
  NFS3ERR_BAD_COOKIE,
  NFS3ERR_EXIST,
  NFS3ERR_NAMETOOLONG,
  NFS3ERR_NOENT,
  NFS3ERR_NOTSUPP,
  NFS3ERR_STALE,
  NFS3ERR_TOOSMALL,
  NFS_PROGRAM,
  NFS_V3,
  NFSPROC3_LOOKUP,
  NFSPROC3_NULL,
  RPC_GARBAGE_ARGS,
  RPC_PROC_UNAVAIL,
  RPC_PROG_MISMATCH,
  RPC_PROG_UNAVAIL,
} from "../../../src/nfs/v3/constants.ts";
import { decodeReply, encodeCall, frameFragments } from "../../../src/nfs/rpc.ts";
import { createNfsServer, type NfsServer } from "../../../src/nfs/server.ts";
import type { FsDriver } from "../../../src/types.ts";
import { check, NfsClient, nfsDriver } from "./client.ts";
import { createLoopback, type Loopback } from "../../../src/harness.ts";

const encoder = new TextEncoder();

interface Harness {
  server: NfsServer;
  client: NfsClient;
  root: Uint8Array;
  fs: Loopback;
}

const open: Harness[] = [];

afterEach(async () => {
  for (const harness of open.splice(0)) {
    harness.client.close();
    await harness.server.close();
  }
});

async function serve(driver: FsDriver = createMemoryDriver()): Promise<Harness> {
  const server = createNfsServer(driver);
  await server.listen();
  const client = await NfsClient.connect({ port: server.port });
  const mounted = await client.mnt("/");
  expect(mounted.status).toBe(MNT3_OK);
  const harness: Harness = {
    server,
    client,
    root: mounted.fh!,
    fs: createLoopback(nfsDriver(client, mounted.fh!)),
  };
  open.push(harness);
  return harness;
}

describe("the MOUNT program", () => {
  it("hands out the root handle and the auth flavors it accepts", async () => {
    const { client } = await serve();
    const mounted = await client.mnt("/");
    expect(mounted.status).toBe(MNT3_OK);
    expect(mounted.fh!.byteLength).toBeGreaterThan(0);
    expect(mounted.fh!.byteLength).toBeLessThanOrEqual(64);
    // AUTH_NONE and AUTH_SYS, which are the two a v3 client sends.
    expect(mounted.authFlavors).toEqual([0, 1]);
  });

  it("exports any directory, so 127.0.0.1:/sub works", async () => {
    const { client, fs, root } = await serve();
    await fs.mkdir("/sub");
    const mounted = await client.mnt("/sub");
    expect(mounted.status).toBe(MNT3_OK);
    // The handle is the same one LOOKUP gives, because handles are keyed on the
    // driver's identity for the file, not on how they were obtained.
    const looked = check(await client.lookup(root, "sub"), "lookup");
    expect([...mounted.fh!]).toEqual([...looked.object!]);
  });

  it("answers MNT for something missing, or not a directory, with its own statuses", async () => {
    const { client, fs } = await serve();
    await fs.writeFile("/file", "x");
    expect((await client.mnt("/nope")).status).toBe(MNT3ERR_NOENT);
    expect((await client.mnt("/file")).status).toBe(MNT3ERR_NOTDIR);
  });

  it("tracks mounts for DUMP and forgets them on UMNT", async () => {
    const { client } = await serve();
    expect(await client.dump()).toEqual([{ hostname: "127.0.0.1", directory: "/" }]);
    await client.umnt("/");
    expect(await client.dump()).toEqual([]);
    await client.mnt("/");
    await client.mnt("/");
    expect(await client.dump()).toHaveLength(2);
    await client.umntall();
    expect(await client.dump()).toEqual([]);
  });

  it("lists one export, the driver's root", async () => {
    const { client } = await serve();
    expect(await client.exports()).toEqual([{ directory: "/", groups: [] }]);
    await client.mountNull();
    await client.null();
  });
});

describe("RPC-level errors", () => {
  it("refuses an unknown program with PROG_UNAVAIL", async () => {
    const { server } = await serve();
    const reply = await answer(server, { xid: 1, program: 999_999, version: 1, procedure: 0 });
    expect(reply.replyStat).toBe(MSG_ACCEPTED);
    expect(reply.acceptStat).toBe(RPC_PROG_UNAVAIL);
  });

  it("refuses the wrong program version with PROG_MISMATCH and the range it speaks", async () => {
    const { server } = await serve();
    const nfs = await answer(server, {
      xid: 2,
      program: NFS_PROGRAM,
      version: 2,
      procedure: NFSPROC3_NULL,
    });
    expect(nfs.acceptStat).toBe(RPC_PROG_MISMATCH);
    expect([nfs.low, nfs.high]).toEqual([NFS_V3, NFS_V3]);
    const mount = await answer(server, {
      xid: 3,
      program: MOUNT_PROGRAM,
      version: 1,
      procedure: 0,
    });
    expect(mount.acceptStat).toBe(RPC_PROG_MISMATCH);
    expect([mount.low, mount.high]).toEqual([MOUNT_V3, MOUNT_V3]);
  });

  it("refuses an unknown procedure with PROC_UNAVAIL", async () => {
    const { server } = await serve();
    for (const program of [NFS_PROGRAM, MOUNT_PROGRAM]) {
      const reply = await answer(server, { xid: 4, program, version: 3, procedure: 99 });
      expect(reply.acceptStat).toBe(RPC_PROC_UNAVAIL);
    }
  });

  it("refuses undecodable arguments with GARBAGE_ARGS", async () => {
    const { server } = await serve();
    const reply = await answer(server, {
      xid: 5,
      program: NFS_PROGRAM,
      version: NFS_V3,
      procedure: NFSPROC3_LOOKUP,
      args: new Uint8Array([0, 0, 0, 0xff]),
    });
    expect(reply.acceptStat).toBe(RPC_GARBAGE_ARGS);
  });

  it("refuses an auth flavor it cannot parse with AUTH_TOOWEAK", async () => {
    const { server } = await serve();
    const reply = await answer(server, {
      xid: 6,
      program: NFS_PROGRAM,
      version: NFS_V3,
      procedure: NFSPROC3_NULL,
      cred: { flavor: 6, body: new Uint8Array(4) },
    });
    expect(reply.replyStat).toBe(MSG_DENIED);
    expect(reply.authStat).toBe(AUTH_TOOWEAK);
  });

  it("refuses an RPC version other than 2", async () => {
    const { server } = await serve();
    const message = encodeCall({
      xid: 7,
      program: NFS_PROGRAM,
      version: NFS_V3,
      procedure: NFSPROC3_NULL,
    });
    // Word 2 is `rpcvers`. Nothing else in the message changes.
    new DataView(message.buffer).setUint32(8, 3, false);
    const reply = decodeReply((await server.session.handleCall(message))!).reply;
    expect(reply.replyStat).toBe(MSG_DENIED);
    expect([reply.low, reply.high]).toEqual([2, 2]);
  });

  it("drops a record that carries no usable xid rather than answering it", async () => {
    const { server } = await serve();
    expect(await server.session.handleCall(new Uint8Array(3))).toBeNull();
    expect(server.session.stats.dropped).toBeGreaterThan(0);
  });
});

/** Put a hand-built call through the session and decode the reply. */
async function answer(
  server: NfsServer,
  call: Parameters<typeof encodeCall>[0],
): Promise<ReturnType<typeof decodeReply>["reply"]> {
  const reply = await server.session.handleCall(encodeCall(call));
  expect(reply).not.toBeNull();
  return decodeReply(reply!).reply;
}

describe("post-operation attributes and wcc_data", () => {
  it("carries post-op attributes on every read-shaped reply, success or not", async () => {
    const { client, fs, root } = await serve();
    await fs.writeFile("/f", "hello");
    const file = check(await client.lookup(root, "f"), "lookup").object!;

    // Success: the object's attributes and its directory's.
    const looked = check(await client.lookup(root, "f"), "lookup");
    expect(looked.objAttributes?.type).toBe(NF3REG);
    expect(looked.dirAttributes?.type).toBe(NF3DIR);

    // Failure: the directory's attributes are still there, which is what lets a
    // client cache a negative lookup without another round trip.
    const missing = await client.lookup(root, "nope");
    expect(missing.status).toBe(NFS3ERR_NOENT);
    expect(missing.object).toBeUndefined();
    expect(missing.dirAttributes?.type).toBe(NF3DIR);

    expect((await client.access(file)).attributes).toBeDefined();
    expect((await client.read(file, 0n, 5)).attributes).toBeDefined();
    expect((await client.readlink(file)).attributes).toBeDefined();
    expect((await client.fsstat(root)).attributes).toBeDefined();
    expect((await client.fsinfo(root)).attributes).toBeDefined();
    expect((await client.pathconf(root)).attributes).toBeDefined();
    expect((await client.readdir(root)).dirAttributes).toBeDefined();
    expect((await client.readdirplus(root)).dirAttributes).toBeDefined();
  });

  it("describes the directory before and after every mutation", async () => {
    const { client, root } = await serve();
    const before = check(await client.getattr(root), "stat").attributes!;

    const created = check(await client.create(root, "f", CREATE_UNCHECKED), "create");
    // `before` is the directory as it was: same size and mtime as the GETATTR
    // taken a moment ago, which is exactly what lets a client keep its cache.
    expect(created.dirWcc.before?.mtime).toEqual(before.mtime);
    expect(created.dirWcc.after).toBeDefined();

    // The driver stamps from `Date.now()`, so two operations in the same
    // millisecond genuinely have the same mtime — wait past the tick, or this
    // asserts on the clock's resolution rather than on the server.
    await new Promise((resolve) => setTimeout(resolve, 5));
    const removed = check(await client.remove(root, "f"), "remove");
    expect(removed.wcc.before).toBeDefined();
    expect(removed.wcc.after).toBeDefined();
    // The directory's mtime moved, and the reply says so without a second call.
    expect(removed.wcc.after!.mtime).not.toEqual(removed.wcc.before!.mtime);
    // And `before` is the state the *previous* reply already described.
    expect(removed.wcc.before!.mtime).toEqual(created.dirWcc.after!.mtime);
  });

  it("carries wcc_data on a failed mutation too", async () => {
    const { client, root } = await serve();
    const failed = await client.remove(root, "never-existed");
    expect(failed.status).toBe(NFS3ERR_NOENT);
    expect(failed.wcc.after).toBeDefined();
  });

  it("reports the file's own wcc on a WRITE", async () => {
    const { client, fs, root } = await serve();
    await fs.writeFile("/f", "12345");
    const file = check(await client.lookup(root, "f"), "lookup").object!;
    const written = check(await client.write(file, 5n, encoder.encode("67890")), "write");
    expect(written.count).toBe(5);
    expect(written.wcc.before?.size).toBe(5n);
    expect(written.wcc.after?.size).toBe(10n);
  });

  it("names both directories in a RENAME reply", async () => {
    const { client, fs, root } = await serve();
    await fs.mkdir("/a");
    await fs.mkdir("/b");
    await fs.writeFile("/a/f", "x");
    const from = check(await client.lookup(root, "a"), "lookup").object!;
    const to = check(await client.lookup(root, "b"), "lookup").object!;
    const renamed = check(await client.rename(from, "f", to, "g"), "rename");
    expect(renamed.fromWcc.before).toBeDefined();
    expect(renamed.fromWcc.after).toBeDefined();
    expect(renamed.toWcc.before).toBeDefined();
    expect(renamed.toWcc.after).toBeDefined();
  });
});

describe("writes are always FILE_SYNC", () => {
  it("reports FILE_SYNC whatever the client asked for, and COMMIT succeeds", async () => {
    const { client, root, server } = await serve();
    const file = check(await client.create(root, "f", CREATE_UNCHECKED), "create").obj!;
    for (const stable of [0, 1, 2]) {
      const written = check(await client.write(file, 0n, encoder.encode("data"), stable), "write");
      // The driver has whole-file semantics and no writeback of its own, so
      // there is never anything outstanding to commit — saying `UNSTABLE`
      // would be describing a buffer that does not exist.
      expect(written.committed).toBe(FILE_SYNC);
      expect([...written.verf]).toEqual([...server.session.writeVerifier]);
    }
    const committed = check(await client.commit(file), "commit");
    expect(committed.status).toBe(NFS3_OK);
    expect(committed.wcc.after).toBeDefined();
  });

  it("keeps one write verifier for the life of the server", async () => {
    const { client, root, server } = await serve();
    const file = check(await client.create(root, "f", CREATE_UNCHECKED), "create").obj!;
    const first = check(await client.write(file, 0n, encoder.encode("a")), "write").verf;
    const second = check(await client.write(file, 1n, encoder.encode("b")), "write").verf;
    const commit = check(await client.commit(file), "commit").verf;
    expect([...second]).toEqual([...first]);
    expect([...commit]).toEqual([...first]);
    expect([...first]).toEqual([...server.session.writeVerifier]);
  });
});

describe("file handles", () => {
  it("survives a rename, of the file and of a directory above it", async () => {
    const { client, fs, root } = await serve();
    await fs.mkdir("/dir");
    await fs.writeFile("/dir/f", "payload");
    const file = check(await client.lookup(root, "dir"), "lookup").object!;
    const inner = check(
      await client.lookup(check(await client.lookup(root, "dir"), "lookup").object!, "f"),
      "lookup",
    ).object!;

    await fs.rename("/dir/f", "/dir/g");
    // The handle names the *file*, and the file did not change.
    expect(check(await client.getattr(inner), "stat").attributes!.size).toBe(7n);

    await fs.rename("/dir", "/moved");
    // And the directory handle, and the handle to what is inside it, both
    // still resolve — a client goes on using them with no idea anything moved.
    expect(check(await client.getattr(file), "stat").attributes!.type).toBe(NF3DIR);
    expect(check(await client.read(inner, 0n, 16), "read").data.byteLength).toBe(7);
    expect(await fs.readdir("/moved", { withFileTypes: true })).toHaveLength(1);
  });

  it("gives two hardlinks the same handle", async () => {
    const { client, fs, root } = await serve();
    await fs.writeFile("/one", "shared");
    await fs.link("/one", "/two");
    const one = check(await client.lookup(root, "one"), "lookup").object!;
    const two = check(await client.lookup(root, "two"), "lookup").object!;
    expect([...two]).toEqual([...one]);
    expect(check(await client.getattr(one), "stat").attributes!.nlink).toBe(2);
    // Removing one name leaves the handle usable through the other.
    check(await client.remove(root, "one"), "remove");
    expect(check(await client.getattr(two), "stat").attributes!.nlink).toBe(1);
  });

  it("goes STALE once the last name is gone", async () => {
    const { client, fs, root } = await serve();
    await fs.writeFile("/doomed", "bye");
    const file = check(await client.lookup(root, "doomed"), "lookup").object!;
    expect((await client.getattr(file)).status).toBe(NFS3_OK);

    check(await client.remove(root, "doomed"), "remove");
    // NFSv3 has no `open`, so the server was never told the file was in use and
    // cannot keep it alive. Real clients hide this with silly-rename.
    expect((await client.getattr(file)).status).toBe(NFS3ERR_STALE);
    expect((await client.read(file, 0n, 8)).status).toBe(NFS3ERR_STALE);
    expect((await client.setattr(file, { size: 0n })).status).toBe(NFS3ERR_STALE);
  });

  it("rejects a handle that is not ours, or is from a previous server", async () => {
    const { client, root } = await serve();
    expect((await client.getattr(new Uint8Array(20))).status).toBe(NFS3ERR_STALE);
    expect((await client.getattr(new Uint8Array(0))).status).toBe(NFS3ERR_STALE);
    expect((await client.getattr(new Uint8Array(64))).status).toBe(NFS3ERR_STALE);

    // Right magic, right shape, wrong boot verifier: the handle belongs to a
    // server that is not this one.
    const forged = root.slice();
    forged[5] = forged[5]! ^ 0xff;
    expect((await client.getattr(forged)).status).toBe(NFS3ERR_STALE);

    // Right verifier, unknown id.
    const unknown = root.slice();
    new DataView(unknown.buffer).setBigUint64(12, 9999n, false);
    expect((await client.getattr(unknown)).status).toBe(NFS3ERR_STALE);
  });

  it("keeps the root handle stable across connections", async () => {
    const { server, root } = await serve();
    const second = await NfsClient.connect({ port: server.port });
    try {
      const mounted = await second.mnt("/");
      expect([...mounted.fh!]).toEqual([...root]);
      // And a handle obtained on one connection works on the other, because
      // there is no per-connection state at all.
      expect((await second.getattr(root)).status).toBe(NFS3_OK);
    } finally {
      second.close();
    }
  });
});

describe("readdir cookies", () => {
  /** A directory with `count` files named `f000`, `f001`, … */
  async function populate(fs: Loopback, count: number): Promise<void> {
    await fs.mkdir("/dir");
    for (let index = 0; index < count; index++) {
      await fs.writeFile(`/dir/f${String(index).padStart(3, "0")}`, "x");
    }
  }

  it("pages through a directory with stable cookies and one cookieverf", async () => {
    const { client, fs, root } = await serve();
    await populate(fs, 40);
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;

    // A count small enough to force several pages.
    const first = check(await client.readdir(dir, 0n, undefined, 256), "readdir");
    expect(first.eof).toBe(false);
    expect(first.entries.length).toBeGreaterThan(0);
    expect(first.entries.length).toBeLessThan(40);

    const names = first.entries.map((entry) => entry.name);
    let cookie = first.entries.at(-1)!.cookie;
    let pages = 1;
    for (;;) {
      const page = check(await client.readdir(dir, cookie, first.cookieverf, 256), "readdir");
      pages++;
      // The verifier never changes while the directory does not.
      expect([...page.cookieverf]).toEqual([...first.cookieverf]);
      names.push(...page.entries.map((entry) => entry.name));
      if (page.eof) {
        break;
      }
      cookie = page.entries.at(-1)!.cookie;
    }
    expect(pages).toBeGreaterThan(2);
    expect(names).toHaveLength(40);
    expect(new Set(names).size).toBe(40);
    // Cookies are dense and ordered, which is what makes them resumable.
    expect(first.entries.map((entry) => Number(entry.cookie))).toEqual(
      first.entries.map((_, index) => index + 1),
    );
  });

  it("gives the same entry the same cookie on a re-read", async () => {
    const { client, fs, root } = await serve();
    await populate(fs, 10);
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;
    const one = check(await client.readdir(dir), "readdir");
    const two = check(await client.readdir(dir), "readdir");
    expect(two.entries).toEqual(one.entries);
    expect([...two.cookieverf]).toEqual([...one.cookieverf]);
  });

  it("keeps a client's page stable even when the directory changes underneath", async () => {
    const { client, fs, root } = await serve();
    await populate(fs, 20);
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;
    const first = check(await client.readdir(dir, 0n, undefined, 200), "readdir");
    expect(first.eof).toBe(false);

    // Something else adds a file mid-scan. The snapshot the cookies belong to
    // is cached, so the client's paging is unaffected.
    await fs.writeFile("/dir/zzz-new", "x");
    const rest = check(
      await client.readdir(dir, first.entries.at(-1)!.cookie, first.cookieverf, 4096),
      "readdir",
    );
    expect(rest.eof).toBe(true);
    expect(first.entries.length + rest.entries.length).toBe(20);
  });

  it("answers BAD_COOKIE for a cookie past the end, or a verifier from nowhere", async () => {
    const { client, fs, root } = await serve();
    await populate(fs, 3);
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;
    const listing = check(await client.readdir(dir), "readdir");
    expect(listing.eof).toBe(true);
    expect((await client.readdir(dir, 99n, listing.cookieverf)).status).toBe(NFS3ERR_BAD_COOKIE);
    expect((await client.readdir(dir, 1n, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))).status).toBe(
      NFS3ERR_BAD_COOKIE,
    );
  });

  it("resumes from a cookie whose snapshot was evicted, if the directory is unchanged", async () => {
    // A cache of one, so reading a second directory evicts the first.
    const server = createNfsServer(createMemoryDriver(), { snapshotCache: 1 });
    await server.listen();
    const client = await NfsClient.connect({ port: server.port });
    open.push({ server, client, root: new Uint8Array(), fs: null as never });
    const root = check(await client.mnt("/"), "mount").fh!;
    const fs = createLoopback(nfsDriver(client, root));
    await populate(fs, 6);
    await fs.mkdir("/other");

    const dir = check(await client.lookup(root, "dir"), "lookup").object!;
    const other = check(await client.lookup(root, "other"), "lookup").object!;
    const first = check(await client.readdir(dir, 0n, undefined, 200), "readdir");
    expect(first.eof).toBe(false);
    // Evict.
    check(await client.readdir(other), "readdir");
    // The verifier is a content hash, so re-listing reproduces it and the
    // client's cookies keep working.
    const rest = check(
      await client.readdir(dir, first.entries.at(-1)!.cookie, first.cookieverf, 4096),
      "readdir",
    );
    expect(first.entries.length + rest.entries.length).toBe(6);
    expect(rest.eof).toBe(true);
  });

  it("answers TOOSMALL rather than an empty page that would loop forever", async () => {
    const { client, fs, root } = await serve();
    await populate(fs, 3);
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;
    expect((await client.readdir(dir, 0n, undefined, 4)).status).toBe(NFS3ERR_TOOSMALL);
    expect((await client.readdirplus(dir, 0n, undefined, 4, 4)).status).toBe(NFS3ERR_TOOSMALL);
    // An empty directory fits in any budget: there is nothing to not fit.
    await fs.mkdir("/empty");
    const empty = check(await client.lookup(root, "empty"), "lookup").object!;
    const listing = check(await client.readdir(empty, 0n, undefined, 4), "readdir");
    expect(listing.entries).toEqual([]);
    expect(listing.eof).toBe(true);
  });

  it("carries attributes and a handle on every READDIRPLUS entry", async () => {
    const { client, fs, root } = await serve();
    await fs.mkdir("/dir");
    await fs.writeFile("/dir/file", "x");
    await fs.mkdir("/dir/sub");
    await fs.symlink("file", "/dir/link");
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;
    const entries = await client.readdirplusAll(dir);
    expect(entries.map((entry) => entry.name).sort()).toEqual(["file", "link", "sub"]);
    for (const entry of entries) {
      expect(entry.attributes).toBeDefined();
      expect(entry.handle).toBeDefined();
      expect(entry.fileid).toBe(entry.attributes!.fileid);
      // The handle in the listing is the one LOOKUP would have given.
      const looked = check(await client.lookup(dir, entry.name), "lookup");
      expect([...entry.handle!]).toEqual([...looked.object!]);
    }
  });

  it("does not invent `.` and `..` entries", async () => {
    // RFC 1813 does not require them, and the Linux client emits its own — so
    // a server that adds them makes a `readdir` that lists them twice.
    const { client, fs, root } = await serve();
    await fs.writeFile("/only", "x");
    const entries = await client.readdirAll(root);
    expect(entries.map((entry) => entry.name)).toEqual(["only"]);
  });
});

describe("individual procedures", () => {
  it("looks up `.` and `..`, and clamps `..` at the root", async () => {
    const { client, fs, root } = await serve();
    await fs.mkdir("/dir");
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;
    expect([...check(await client.lookup(dir, "."), "lookup").object!]).toEqual([...dir]);
    expect([...check(await client.lookup(dir, ".."), "lookup").object!]).toEqual([...root]);
    // `..` at the root is the root: nothing above an export is reachable.
    expect([...check(await client.lookup(root, ".."), "lookup").object!]).toEqual([...root]);
  });

  it("refuses a name longer than name_max", async () => {
    const { client, root } = await serve();
    const long = "x".repeat(256);
    expect((await client.lookup(root, long)).status).toBe(NFS3ERR_NAMETOOLONG);
    expect((await client.create(root, long, CREATE_UNCHECKED)).status).toBe(NFS3ERR_NAMETOOLONG);
    expect(check(await client.pathconf(root), "pathconf").nameMax).toBe(255);
    // 255 bytes is fine, and the limit is bytes rather than characters.
    expect((await client.create(root, "x".repeat(255), CREATE_UNCHECKED)).status).toBe(NFS3_OK);
    expect((await client.create(root, "é".repeat(128), CREATE_UNCHECKED)).status).toBe(
      NFS3ERR_NAMETOOLONG,
    );
  });

  it("implements all three CREATE modes, EXCLUSIVE as NOTSUPP", async () => {
    const { client, root } = await serve();
    expect(check(await client.create(root, "f", CREATE_UNCHECKED), "create").obj).toBeDefined();
    // UNCHECKED over an existing file succeeds and applies the attributes.
    const again = check(await client.create(root, "f", CREATE_UNCHECKED, { size: 0n }), "create");
    expect(again.objAttributes!.size).toBe(0n);
    expect((await client.create(root, "f", CREATE_GUARDED)).status).toBe(NFS3ERR_EXIST);
    // EXCLUSIVE wants the verifier stored somewhere that survives a retry, and
    // there is nowhere in the driver interface to put it. Linux falls back.
    const exclusive = await client.create(
      root,
      "excl",
      CREATE_EXCLUSIVE,
      {},
      new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    );
    expect(exclusive.status).toBe(NFS3ERR_NOTSUPP);
    expect((await client.lookup(root, "excl")).status).toBe(NFS3ERR_NOENT);
  });

  it("answers MKNOD with NOTSUPP, because the driver interface cannot express it", async () => {
    const { client, root } = await serve();
    const made = await client.mknod(root, "dev", NF3CHR, { mode: 0o666 }, { major: 1, minor: 3 });
    expect(made.status).toBe(NFS3ERR_NOTSUPP);
    expect(made.dirWcc.after).toBeDefined();
  });

  it("reports EOF on a READ that reaches the end, and not before", async () => {
    const { client, fs, root } = await serve();
    await fs.writeFile("/f", "0123456789");
    const file = check(await client.lookup(root, "f"), "lookup").object!;
    const partial = check(await client.read(file, 0n, 4), "read");
    expect(partial.eof).toBe(false);
    expect(partial.count).toBe(4);
    const rest = check(await client.read(file, 4n, 100), "read");
    expect(rest.eof).toBe(true);
    expect(rest.count).toBe(6);
    // Past the end is zero bytes and EOF, not an error.
    const past = check(await client.read(file, 100n, 8), "read");
    expect(past).toMatchObject({ count: 0, eof: true });
  });

  it("computes ACCESS from the mode bits", async () => {
    const { client, fs, root } = await serve();
    await fs.writeFile("/f", "x");
    await fs.chmod("/f", 0o400);
    const file = check(await client.lookup(root, "f"), "lookup").object!;
    const readOnly = check(await client.access(file), "access");
    const uid = process.getuid?.() ?? 0;
    if (uid !== 0) {
      // Owner, read-only: readable, not modifiable.
      expect(readOnly.access & ACCESS3_READ).toBe(ACCESS3_READ);
      expect(readOnly.access & ACCESS3_MODIFY).toBe(0);
    }
    const directory = check(await client.access(root), "access");
    expect(directory.access & ACCESS3_LOOKUP).toBe(ACCESS3_LOOKUP);
    // Only the bits that were asked for come back.
    expect(check(await client.access(root, ACCESS3_READ), "access").access).toBe(ACCESS3_READ);
  });

  it("honours a SETATTR ctime guard", async () => {
    const { client, fs, root } = await serve();
    await fs.writeFile("/f", "x");
    const file = check(await client.lookup(root, "f"), "lookup").object!;
    const attributes = check(await client.getattr(file), "stat").attributes!;
    // The guard matches, so the change applies.
    expect(
      (
        await client.setattr(
          file,
          { mode: 0o600 },
          { seconds: attributes.ctime.seconds, nseconds: 0 },
        )
      ).status,
    ).toBe(NFS3_OK);
    // A guard naming a different ctime is refused with NOT_SYNC (10002).
    const stale = await client.setattr(file, { mode: 0o644 }, { seconds: 1, nseconds: 0 });
    expect(stale.status).toBe(10_002);
    expect(check(await client.getattr(file), "stat").attributes!.mode).toBe(0o600);
  });

  it("reports the filesystem the driver describes", async () => {
    const { client, root } = await serve();
    const info = check(await client.fsinfo(root), "fsinfo");
    expect(info.rtmax).toBeGreaterThan(0);
    expect(info.wtmax).toBeGreaterThan(0);
    expect(info.rtmult).toBe(4096);
    expect(info.properties & FSF3_HOMOGENEOUS).toBe(FSF3_HOMOGENEOUS);
    // The memory driver has all three, so all three bits are set.
    expect(info.properties & FSF3_LINK).toBe(FSF3_LINK);
    expect(info.properties & FSF3_SYMLINK).toBe(FSF3_SYMLINK);
    expect(info.properties & FSF3_CANSETTIME).toBe(FSF3_CANSETTIME);
    // Timestamps come from `Date`, so a millisecond is the finest observable
    // change; claiming nanoseconds would be a lie a client acts on.
    expect(info.timeDelta).toEqual({ seconds: 0, nseconds: 1_000_000 });

    const stat = check(await client.fsstat(root), "fsstat");
    expect(stat.tbytes).toBeGreaterThan(0n);
    expect(stat.fbytes).toBeLessThanOrEqual(stat.tbytes);

    const pathconf = check(await client.pathconf(root), "pathconf");
    expect(pathconf).toMatchObject({
      nameMax: 255,
      noTrunc: true,
      caseInsensitive: false,
      casePreserving: true,
    });
    expect(pathconf.linkmax).toBeGreaterThan(1);
  });

  it("counts every procedure it answered", async () => {
    const { client, root, server } = await serve();
    await client.null();
    await client.getattr(root);
    expect(server.session.stats.procedures.get("NFS:NULL")).toBe(1);
    expect(server.session.stats.procedures.get("NFS:GETATTR")).toBe(1);
    expect(server.session.stats.procedures.get("MOUNT:MNT")).toBe(1);
    expect(server.session.stats.replies).toBeGreaterThan(0);
  });
});

describe("the socket", () => {
  it("reassembles a call split across RPC fragments", async () => {
    const { client, server } = await serve();
    const xid = 0x51_51_51_51;
    const message = encodeCall({
      xid,
      program: NFS_PROGRAM,
      version: NFS_V3,
      procedure: NFSPROC3_NULL,
    });
    // Eight bytes per fragment: five fragments for a 40-byte NULL call.
    const results = await client.sendFramed(frameFragments(message, 8), xid);
    results.end("NULL reply");
    expect(server.session.stats.procedures.get("NFS:NULL")).toBe(1);
  });

  it("answers many requests in flight at once", async () => {
    const { client, fs, root } = await serve();
    for (let index = 0; index < 20; index++) {
      await fs.writeFile(`/f${index}`, `body ${index}`);
    }
    const looked = await Promise.all(
      Array.from({ length: 20 }, (_, index) => client.lookup(root, `f${index}`)),
    );
    const read = await Promise.all(
      looked.map((entry) => client.read(check(entry, "lookup").object!, 0n, 64)),
    );
    expect(read.map((result) => new TextDecoder().decode(result.data))).toEqual(
      Array.from({ length: 20 }, (_, index) => `body ${index}`),
    );
  });

  it("closes a connection whose record header cannot be believed", async () => {
    const errors: unknown[] = [];
    const server = createNfsServer(createMemoryDriver(), {
      maxRecord: 1024,
      onTransportError: (error) => errors.push(error),
    });
    await server.listen();
    const client = await NfsClient.connect({ port: server.port });
    open.push({ server, client, root: new Uint8Array(), fs: null as never });

    // A fragment header claiming 64 MiB. There is no resynchronizing a
    // record-marked stream, so the connection goes.
    const header = new Uint8Array(4);
    new DataView(header.buffer).setUint32(0, 0x80_00_00_00 | (64 * 1024 * 1024), false);
    const rejected = client.sendFramed(header, 1);
    await expect(rejected).rejects.toThrow();
    expect(errors.length).toBeGreaterThan(0);
  });

  it("refuses a connection from an address that is not loopback", async () => {
    const errors: unknown[] = [];
    const server = createNfsServer(createMemoryDriver(), {
      host: "0.0.0.0",
      onTransportError: (error) => errors.push(error),
    });
    await server.listen();
    try {
      // Connecting to a non-loopback address of this host is what a remote
      // client looks like; there may not be one, so the assertion is on the
      // *policy* rather than on finding an address.
      const client = await NfsClient.connect({ port: server.port, host: "127.0.0.1" });
      await client.null();
      client.close();
      expect(errors).toEqual([]);
    } finally {
      await server.close();
    }
  });

  it("stops serving and drops connections on close", async () => {
    const server = createNfsServer(createMemoryDriver());
    await server.listen();
    const client = await NfsClient.connect({ port: server.port });
    expect(server.port).toBeGreaterThan(0);
    await client.null();
    expect(server.connections).toBe(1);
    await server.close();
    // Idempotent, and the session went with it.
    await server.close();
    expect(server.session.destroyed).toBe(true);
    expect(server.connections).toBe(0);
    await expect(client.null()).rejects.toThrow();
  });
});
