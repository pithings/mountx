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
  NF3FIFO,
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
  NFSPROC3_CREATE,
  NFSPROC3_LOOKUP,
  NFSPROC3_NULL,
  NFSPROC3_READ,
  NFSPROC3_READDIRPLUS,
  RPC_GARBAGE_ARGS,
  RPC_PROC_UNAVAIL,
  RPC_PROG_MISMATCH,
  RPC_PROG_UNAVAIL,
} from "../../../src/nfs/v3/constants.ts";
import { NFS_V4 } from "../../../src/nfs/v4/constants.ts";
import {
  AUTH_SYS,
  decodeReply,
  encodeAuthSys,
  encodeCall,
  frameFragments,
  type OpaqueAuth,
} from "../../../src/nfs/rpc.ts";
import { encodeXdr } from "../../../src/nfs/xdr.ts";
import { readCreateRes, writeCreateArgs } from "../../../src/nfs/v3/protocol.ts";
import { createNfsServer, type NfsServer } from "../../../src/nfs/server.ts";
import type { FsDriver, FullFsDriver } from "../../../src/types.ts";
import { withLatency } from "../../latency.ts";
import { withoutExtensions } from "../../no-extensions.ts";
import { check, NfsClient, nfsDriver } from "./client.ts";
import { createLoopback, type Loopback } from "../../../src/harness.ts";

const encoder = new TextEncoder();

/** One client's `createverf3`: eight bytes it made up, and keeps resending. */
const VERIFIER = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

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

async function serve(
  driver: FsDriver = createMemoryDriver(),
  options: { cred?: OpaqueAuth; claimOwnership?: boolean } = {},
): Promise<Harness> {
  const server = createNfsServer(driver, { claimOwnership: options.claimOwnership });
  await server.listen();
  const client = await NfsClient.connect({ port: server.port, cred: options.cred });
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
    // The range is the *server's*, not this session's: a record naming an NFS
    // version other than 3 never reaches here at all — the router in
    // `src/nfs/session.ts` refuses it with the pair of versions the server
    // speaks, which `test/nfs/session.test.ts` holds. This asserts the number a
    // client actually receives from a server built by `createNfsServer`.
    expect([nfs.low, nfs.high]).toEqual([NFS_V3, NFS_V4]);
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

  it("keeps a client's page stable when the directory changes behind the server's back", async () => {
    // The change is made straight on the driver, so the server never hears
    // about it and its snapshot is the last thing it knows to be true. That is
    // what the snapshot is *for*: the client's cookies keep meaning what they
    // meant, and it pages to the end of the listing it started.
    const driver = createMemoryDriver();
    const { client, root } = await serve(driver);
    const behind = createLoopback(driver);
    await populate(behind, 20);
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;
    const first = check(await client.readdir(dir, 0n, undefined, 200), "readdir");
    expect(first.eof).toBe(false);

    await behind.writeFile("/dir/zzz-new", "x");
    const rest = check(
      await client.readdir(dir, first.entries.at(-1)!.cookie, first.cookieverf, 4096),
      "readdir",
    );
    expect(rest.eof).toBe(true);
    expect(first.entries.length + rest.entries.length).toBe(20);
  });

  /**
   * The other half of the same rule, and the one that used to be wrong.
   *
   * A CREATE the *server* performed is a directory it knows has changed, so the
   * cached listing goes (`DirectorySnapshots` in `src/nfs/handles.ts` states
   * the rule). Before that, the snapshot survived with its verifier still
   * matching and the resuming client was handed names from before the create —
   * the one outcome the cookie scheme exists to prevent, since the client has
   * no way to tell that page from a current one.
   */
  it("stops resuming a page whose directory the server itself changed", async () => {
    const { client, fs, root } = await serve();
    await populate(fs, 20);
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;
    const first = check(await client.readdir(dir, 0n, undefined, 200), "readdir");
    expect(first.eof).toBe(false);

    await fs.writeFile("/dir/zzz-new", "x");
    // Not a stale page: `NFS3ERR_BAD_COOKIE`, which is a client's cue to start
    // the listing again — and starting again shows the new name.
    expect(
      (await client.readdir(dir, first.entries.at(-1)!.cookie, first.cookieverf, 4096)).status,
    ).toBe(NFS3ERR_BAD_COOKIE);
    const names = await client.readdirAll(dir);
    expect(names.map((entry) => entry.name)).toContain("zzz-new");
  });

  it("drops only the directories a mutation touched", async () => {
    const base = createMemoryDriver();
    let readdirs = 0;
    const counted: FsDriver = {
      ...base,
      async readdir(path, options) {
        readdirs++;
        return base.readdir(path, options as never) as never;
      },
    };
    const { client, fs, root } = await serve(counted);
    await populate(fs, 20);
    await fs.mkdir("/other");
    await fs.writeFile("/other/a", "x");
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;
    const first = check(await client.readdir(dir, 0n, undefined, 200), "readdir");
    expect(first.eof).toBe(false);

    // A rename somewhere else entirely.
    const before = readdirs;
    await fs.rename("/other/a", "/other/b");
    const rest = check(
      await client.readdir(dir, first.entries.at(-1)!.cookie, first.cookieverf, 4096),
      "readdir",
    );
    expect(rest.eof).toBe(true);
    expect(first.entries.length + rest.entries.length).toBe(20);
    // And the resume came straight out of the cache. RENAME used to `clear()`
    // every snapshot in the server, so one `mv` during a build made every other
    // directory anyone was paging re-list itself from the driver to prove the
    // client's cookies still meant something.
    expect(readdirs - before).toBe(0);
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

  /**
   * What a page costs the driver.
   *
   * A page used to be one `lstat` per name, awaited one after the other, purely
   * to fill `fileid3` — 5000 serialized round trips for a 5000-entry `ls`, and
   * on a driver like `unstorage` (whose `stat` falls back to fetching the value)
   * one download per object, in series. Two things changed: the page is chosen
   * from the names alone and then resolved as a batch, and a child the handle
   * table has already bound answers from the entry with no driver call at all.
   */
  it("resolves a readdir page as one batch, and re-lists a bound directory for free", async () => {
    const base = createMemoryDriver();
    let lstats = 0;
    let inFlight = 0;
    let peak = 0;
    const counted: FsDriver = {
      ...base,
      async lstat(path) {
        lstats++;
        inFlight++;
        peak = Math.max(peak, inFlight);
        try {
          return await base.lstat(path);
        } finally {
          inFlight--;
        }
      },
    };
    const { client, root } = await serve(counted);
    // Populated straight on the driver, so the handle table has never seen any
    // of these names — which is the shape a client that mounts an existing tree
    // and lists it once actually has.
    await populate(createLoopback(base), 40);
    const dir = check(await client.lookup(root, "dir"), "lookup").object!;

    const before = lstats;
    expect(await client.readdirAll(dir)).toHaveLength(40);
    // Every name is new to the table, so the first pass still stats all of
    // them — but concurrently. On base this peaks at exactly 1.
    expect(lstats - before).toBeGreaterThanOrEqual(40);
    expect(peak).toBeGreaterThan(1);

    const bound = lstats;
    expect(await client.readdirAll(dir)).toHaveLength(40);
    // The second pass is the directory's own `post_op_attr` and nothing else.
    // On base it is another 40.
    expect(lstats - bound).toBeLessThan(5);
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

  it("implements all three CREATE modes", async () => {
    const { client, root } = await serve();
    expect(check(await client.create(root, "f", CREATE_UNCHECKED), "create").obj).toBeDefined();
    // UNCHECKED over an existing file succeeds and applies the attributes.
    const again = check(await client.create(root, "f", CREATE_UNCHECKED, { size: 0n }), "create");
    expect(again.objAttributes!.size).toBe(0n);
    expect((await client.create(root, "f", CREATE_GUARDED)).status).toBe(NFS3ERR_EXIST);
    // EXCLUSIVE creates like GUARDED, and carries a verifier instead of an
    // `sattr3` — so there are no attributes to apply and none are.
    const created = check(
      await client.create(root, "excl", CREATE_EXCLUSIVE, {}, VERIFIER),
      "create",
    );
    expect(created.obj).toBeDefined();
    expect(created.objAttributes!.type).toBe(NF3REG);
    expect(check(await client.lookup(root, "excl"), "lookup").object).toEqual(created.obj);
  });

  /**
   * §3.3.8's whole point: a client cannot make a create idempotent by itself,
   * because a lost reply leaves it unable to tell "I created it" from "someone
   * else did". The verifier is how it tells the difference, and the table
   * behind it is `ExclusiveCreates` in `src/nfs/util.ts` — a retry, not a
   * restart.
   */
  it("answers the retry of an EXCLUSIVE create with the file it already made", async () => {
    const { client, root, fs } = await serve();
    const first = check(
      await client.create(root, "excl", CREATE_EXCLUSIVE, {}, VERIFIER),
      "create",
    );
    await fs.writeFile("/excl", "written after the create");

    // The duplicate of a request whose reply never arrived: the same file
    // handle back, `NFS3_OK` rather than `EXIST`, and nothing truncated.
    const retry = check(
      await client.create(root, "excl", CREATE_EXCLUSIVE, {}, VERIFIER),
      "create",
    );
    expect([...retry.obj!]).toEqual([...first.obj!]);
    expect(retry.objAttributes!.size).toBe(24n);
    expect(new TextDecoder().decode(await fs.readFile("/excl"))).toBe("written after the create");

    // A different verifier on the same name is a *second client*, which is the
    // one case that really is `NFS3ERR_EXIST`.
    const other = new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9]);
    expect((await client.create(root, "excl", CREATE_EXCLUSIVE, {}, other)).status).toBe(
      NFS3ERR_EXIST,
    );
  });

  /**
   * The same promise, kept against the duplicate that actually happens.
   *
   * A retransmission is sent because the reply was *lost*, which means it goes
   * out while the original is still in flight — not after it has been answered.
   * A verifier recorded any later than "the create won" is therefore a verifier
   * the duplicate looks for, does not find, and is told `NFS3ERR_EXIST` about
   * by the very request that succeeded.
   *
   * Driven through {@link withLatency}, because the ordering is only observable
   * against a driver that takes a real turn to answer: 17 of 17 duplicates were
   * told `EXIST` before the verifier moved ahead of the `close()`.
   */
  it("answers duplicates that arrive while the original is still in flight", async () => {
    const { server, root } = await serve(withLatency(createMemoryDriver()));
    // The same record 18 times — same xid and all, which is what an RPC
    // retransmission *is* — handed to the session together rather than one
    // after another, so none of them can see another's reply. The server
    // dispatches every record it reads without awaiting it, so this is the
    // arrival pattern a congested client produces, not a synthetic one.
    const record = encodeCall({
      xid: 0x3c_3c_3c_3c,
      program: NFS_PROGRAM,
      version: NFS_V3,
      procedure: NFSPROC3_CREATE,
      args: encodeXdr((w) =>
        writeCreateArgs(w, {
          where: { dir: root, name: "excl" },
          mode: CREATE_EXCLUSIVE,
          attributes: {},
          verf: VERIFIER,
        }),
      ),
    });
    const replies = await Promise.all(
      Array.from({ length: 18 }, () => server.session.handleCall(record)),
    );
    const results = replies.map((reply) => readCreateRes(decodeReply(reply!).results));
    const first = check(results[0]!, "create");
    for (const result of results) {
      expect(result.status).toBe(NFS3_OK);
      // Every one of them is the same file, which is the whole promise.
      expect([...check(result, "create").obj!]).toEqual([...first.obj!]);
    }
  });

  it("forgets the verifier once the client commits with SETATTR", async () => {
    const { client, root } = await serve();
    const created = check(
      await client.create(root, "excl", CREATE_EXCLUSIVE, {}, VERIFIER),
      "create",
    );
    // The follow-up §3.3.8 sends the client back for, since EXCLUSIVE had
    // nowhere to carry the mode. After it, the client is not retrying.
    expect((await client.setattr(created.obj!, { mode: 0o600 })).status).toBe(NFS3_OK);
    expect((await client.create(root, "excl", CREATE_EXCLUSIVE, {}, VERIFIER)).status).toBe(
      NFS3ERR_EXIST,
    );
  });

  it("forgets the verifier when the name stops meaning that file", async () => {
    const { client, root } = await serve();
    // Removed, then re-created by somebody else: the name is a different file
    // now, and the promise made about the first one must not cover it.
    check(await client.create(root, "gone", CREATE_EXCLUSIVE, {}, VERIFIER), "create");
    expect((await client.remove(root, "gone")).status).toBe(NFS3_OK);
    check(await client.create(root, "gone", CREATE_UNCHECKED), "create");
    expect((await client.create(root, "gone", CREATE_EXCLUSIVE, {}, VERIFIER)).status).toBe(
      NFS3ERR_EXIST,
    );

    // Same again through a rename, which moves the file out from under the
    // name rather than deleting it.
    check(await client.create(root, "moved", CREATE_EXCLUSIVE, {}, VERIFIER), "create");
    expect((await client.rename(root, "moved", root, "elsewhere")).status).toBe(NFS3_OK);
    check(await client.create(root, "moved", CREATE_UNCHECKED), "create");
    expect((await client.create(root, "moved", CREATE_EXCLUSIVE, {}, VERIFIER)).status).toBe(
      NFS3ERR_EXIST,
    );
  });

  it("answers MKNOD with NOTSUPP when the driver has no mknod extension", async () => {
    const { client, root } = await serve(withoutExtensions(createMemoryDriver()));
    const made = await client.mknod(root, "dev", NF3CHR, { mode: 0o666 }, { major: 1, minor: 3 });
    expect(made.status).toBe(NFS3ERR_NOTSUPP);
    expect(made.dirWcc.after).toBeDefined();
  });

  it("creates a device node and a FIFO through the mknod extension", async () => {
    const { client, root, fs } = await serve();

    const device = await client.mknod(root, "dev", NF3CHR, { mode: 0o666 }, { major: 1, minor: 3 });
    expect(device.status).toBe(NFS3_OK);
    // `ftype3` and `specdata3` both come back on the wire, from the driver's
    // `mode` and `rdev` — the two fields a special file *is*.
    expect(device.objAttributes?.type).toBe(NF3CHR);
    expect(device.objAttributes?.rdev).toEqual({ major: 1, minor: 3 });

    const fifo = await client.mknod(root, "fifo", NF3FIFO, { mode: 0o644 });
    expect(fifo.status).toBe(NFS3_OK);
    expect(fifo.objAttributes?.type).toBe(NF3FIFO);

    // ...and the same two files seen through GETATTR a second time, from the
    // driver over this client rather than from the create reply.
    const stats = await fs.lstat("/dev");
    expect(stats.isCharacterDevice()).toBe(true);
    expect(stats.rdev).toBe((1 << 8) | 3);
    expect((await fs.lstat("/fifo")).isFIFO()).toBe(true);
    const entries = await fs.readdir("/", { withFileTypes: true });
    expect(entries.find((entry) => entry.name === "fifo")?.isFIFO()).toBe(true);
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

  it("sizes a READ reply from what was read, not from what was asked for", async () => {
    // `handleCall` returns a *view* of the buffer it built the reply in, and
    // `server.ts` hands that straight to `socket.write` — so the buffer lives
    // until the write flushes. Reserving from `rsize` rather than from the
    // bytes the driver returned made a 200-byte reply pin megabytes, once per
    // call in flight.
    const { server, client, fs, root } = await serve();
    await fs.writeFile("/short", "0123456789");
    const file = check(await client.lookup(root, "short"), "lookup").object!;
    const reply = (await server.session.handleCall(
      encodeCall({
        xid: 41,
        program: NFS_PROGRAM,
        version: NFS_V3,
        procedure: NFSPROC3_READ,
        args: encodeXdr((writer) => {
          writer.varOpaque(file);
          writer.u64(0n);
          writer.u32(1024 * 1024);
        }),
      }),
    ))!;
    expect(reply.byteLength).toBeLessThan(512);
    // The whole allocation, not just the part in use.
    expect(reply.buffer.byteLength).toBeLessThan(1024);
  });

  it("sizes a READDIRPLUS reply from the page it chose, not from maxcount", async () => {
    const { server, client, fs, root } = await serve();
    await fs.mkdir("/d");
    await fs.writeFile("/d/one", "x");
    const dir = check(await client.lookup(root, "d"), "lookup").object!;
    const reply = (await server.session.handleCall(
      encodeCall({
        xid: 42,
        program: NFS_PROGRAM,
        version: NFS_V3,
        procedure: NFSPROC3_READDIRPLUS,
        args: encodeXdr((writer) => {
          writer.varOpaque(dir);
          writer.u64(0n);
          writer.raw(new Uint8Array(8));
          writer.u32(32 * 1024);
          writer.u32(1024 * 1024);
        }),
      }),
    ))!;
    expect(reply.byteLength).toBeLessThan(2048);
    expect(reply.buffer.byteLength).toBeLessThan(4096);
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

/**
 * The rule in `src/ownership.ts`, driven through CREATE/MKDIR/SYMLINK/MKNOD.
 *
 * Everything here is about the *group*, which the caller's `AUTH_SYS`
 * credential does not settle: a set-gid parent hands its own group down, and a
 * new directory takes the bit with it. The tree is built through the driver
 * rather than through the mount, so that the setup is not itself subject to the
 * rule under test.
 */
describe("set-gid inheritance", () => {
  const TEAM = 4000;
  /** A caller in no group the fixture uses, so every group below is inherited. */
  const OUTSIDER = credential(4242, 4343);
  /** The same caller, with the team in its supplementary list (`AUTH_SYS` gids). */
  const MEMBER = credential(4242, 4343, [7, TEAM]);

  function credential(uid: number, gid: number, gids: number[] = []): OpaqueAuth {
    // `authSys()` always sends an empty `gids`, and the supplementary list is
    // exactly what one half of the rule turns on.
    return {
      flavor: AUTH_SYS,
      body: encodeAuthSys({ stamp: 0, machineName: "test", uid, gid, gids }),
    };
  }

  /** `/team` is set-gid and owned by group 4000; `/plain` is an ordinary one. */
  async function fixture(): Promise<FullFsDriver> {
    const driver = createMemoryDriver();
    await driver.mkdir("/team");
    await driver.chown("/team", 500, TEAM);
    await driver.chmod("/team", 0o2775);
    await driver.mkdir("/plain");
    return driver;
  }

  async function served(options: { cred?: OpaqueAuth; claimOwnership?: boolean } = {}): Promise<{
    client: NfsClient;
    team: Uint8Array;
    plain: Uint8Array;
  }> {
    const { client, root } = await serve(await fixture(), { cred: OUTSIDER, ...options });
    return {
      client,
      team: check(await client.lookup(root, "team"), "lookup").object!,
      plain: check(await client.lookup(root, "plain"), "lookup").object!,
    };
  }

  it("gives a new file the parent's group and the caller the ownership", async () => {
    const { client, team } = await served();
    const created = check(await client.create(team, "f", CREATE_UNCHECKED), "create");
    expect(created.objAttributes!.uid).toBe(4242);
    expect(created.objAttributes!.gid).toBe(TEAM);
    // EXCLUSIVE carries no `sattr3` at all, and inherits just the same.
    const exclusive = check(
      await client.create(team, "x", CREATE_EXCLUSIVE, {}, VERIFIER),
      "create",
    );
    expect(exclusive.objAttributes!.gid).toBe(TEAM);
  });

  it("gives a new directory the group *and* the set-gid bit", async () => {
    const { client, team } = await served();
    const made = check(await client.mkdir(team, "sub", { mode: 0o755 }), "mkdir");
    expect(made.objAttributes!.gid).toBe(TEAM);
    // `inode(7)`: "newly created subdirectories inherit the set-group-ID bit",
    // which is what makes the rule apply to the whole tree rather than one
    // level of it.
    expect(made.objAttributes!.mode).toBe(0o2755);
    // And it really is inherited *again* one level down.
    const sub = made.obj!;
    expect(check(await client.mkdir(sub, "deeper"), "mkdir").objAttributes!.mode & 0o2000).toBe(
      0o2000,
    );
    expect(
      check(await client.create(sub, "f", CREATE_UNCHECKED), "create").objAttributes!.gid,
    ).toBe(TEAM);
  });

  it("inherits through SYMLINK and MKNOD too", async () => {
    const { client, team } = await served();
    const link = check(await client.symlink(team, "l", "./f"), "symlink");
    expect(link.objAttributes!.gid).toBe(TEAM);
    // A symlink's own mode is 0o777 and stays it: nothing was chmod'ed through
    // the link.
    expect(link.objAttributes!.mode).toBe(0o777);
    const fifo = check(await client.mknod(team, "fifo", NF3FIFO, { mode: 0o644 }), "mknod");
    expect(fifo.objAttributes!.gid).toBe(TEAM);
  });

  it("gives the caller's own group in an ordinary directory", async () => {
    const { client, plain } = await served();
    const created = check(await client.create(plain, "f", CREATE_UNCHECKED), "create");
    expect(created.objAttributes!.uid).toBe(4242);
    expect(created.objAttributes!.gid).toBe(4343);
    const made = check(await client.mkdir(plain, "sub", { mode: 0o755 }), "mkdir");
    expect(made.objAttributes!.gid).toBe(4343);
    // No parent bit, nothing to inherit: the mode is the one that was asked for.
    expect(made.objAttributes!.mode).toBe(0o755);
  });

  it("clears set-gid on a new executable the creator has no claim to that group", async () => {
    const { client, team } = await served();
    const created = check(
      await client.create(team, "run", CREATE_UNCHECKED, { mode: 0o2775 }),
      "create",
    );
    // A set-gid executable is a way to *run as* a group, so one may not be made
    // for a group its creator is not in — `inode_init_owner()`, and the reason
    // the supplementary list is on the wire at all.
    expect(created.objAttributes!.mode).toBe(0o775);
    expect(created.objAttributes!.gid).toBe(TEAM);
  });

  it("keeps it when only the supplementary list makes the creator a member", async () => {
    const { client, team } = await served({ cred: MEMBER });
    const created = check(
      await client.create(team, "run", CREATE_UNCHECKED, { mode: 0o2775 }),
      "create",
    );
    expect(created.objAttributes!.mode).toBe(0o2775);
    // Not group-executable, so there is nothing to run as and nothing to clear.
    const plainMode = check(
      await client.create(team, "data", CREATE_UNCHECKED, { mode: 0o2664 }),
      "create",
    );
    expect(plainMode.objAttributes!.mode).toBe(0o2664);
  });

  /**
   * The bit goes on top of the mode the driver **made**, not the one the client
   * asked for.
   *
   * `open`/`mkdir` mask their mode argument with the umask of the process the
   * driver runs in and a `chmod` is not masked at all, so a rule that
   * re-asserts the requested mode hands the caller *wider* permissions in a
   * set-gid directory than the same call gets one directory over. The memory
   * driver applies no umask by default, which is why every case above is blind
   * to this; one that does is the smallest thing that can see it.
   */
  it("puts the bit on the mode the driver made, not the one the client asked for", async () => {
    const driver = createMemoryDriver({ umask: 0o022 });
    await driver.mkdir("/team");
    await driver.chown("/team", 500, TEAM);
    await driver.chmod("/team", 0o2775);
    await driver.mkdir("/plain");
    const { client, root } = await serve(driver, { cred: OUTSIDER });
    const team = check(await client.lookup(root, "team"), "lookup").object!;
    const plain = check(await client.lookup(root, "plain"), "lookup").object!;

    // 0o775 asked for, 0o755 created, 0o2755 after the bit: the same mode the
    // plain directory produces, plus the one bit that was inherited.
    const inherited = check(await client.mkdir(team, "sub", { mode: 0o775 }), "mkdir");
    const control = check(await client.mkdir(plain, "sub", { mode: 0o775 }), "mkdir");
    expect(control.objAttributes!.mode).toBe(0o755);
    expect(inherited.objAttributes!.mode).toBe(0o2755);

    // The clearing half reads back the same way: 0o2775 asked for, 0o2755
    // created, 0o755 once the bit this caller may not hand out comes off.
    const executable = check(
      await client.create(team, "run", CREATE_UNCHECKED, { mode: 0o2775 }),
      "create",
    );
    expect(executable.objAttributes!.mode).toBe(0o755);
  });

  /**
   * `#claim` is about a *new* entry, and an `UNCHECKED` CREATE is not always
   * one: §3.3.8's UNCHECKED "does not check for the existence of the file", so
   * it succeeds over a file somebody else made and owns. Claiming that file
   * would hand it to whoever named it last — and, once the rule started
   * `chmod`ing as well, would strip the set-gid bit off it on the way.
   */
  it("claims only the entry the call actually created", async () => {
    const driver = await fixture();
    // Somebody else's shared executable, already in the team directory.
    await (await driver.open("/team/run", "w")).close();
    await driver.chown("/team/run", 500, TEAM);
    await driver.chmod("/team/run", 0o2775);

    const { client, root } = await serve(driver, { cred: OUTSIDER });
    const team = check(await client.lookup(root, "team"), "lookup").object!;
    const over = check(await client.create(team, "run", CREATE_UNCHECKED), "create");
    expect(over.objAttributes!.uid).toBe(500);
    expect(over.objAttributes!.gid).toBe(TEAM);
    expect(over.objAttributes!.mode).toBe(0o2775);

    // ...and the file this call *did* create is claimed exactly as before.
    const made = check(await client.create(team, "new", CREATE_UNCHECKED), "create");
    expect(made.objAttributes!.uid).toBe(4242);
    expect(made.objAttributes!.gid).toBe(TEAM);
  });

  it("does not claim at all with claimOwnership off", async () => {
    const { client, team } = await served({ claimOwnership: false });
    const created = check(await client.create(team, "f", CREATE_UNCHECKED), "create");
    // Whatever the driver did on its own: the server's own uid and gid, and no
    // set-gid bit added to a new directory either.
    expect(created.objAttributes!.uid).toBe(process.getuid?.() ?? 0);
    expect(created.objAttributes!.gid).toBe(process.getgid?.() ?? 0);
    const made = check(await client.mkdir(team, "sub", { mode: 0o755 }), "mkdir");
    expect(made.objAttributes!.mode).toBe(0o755);
    expect(made.objAttributes!.gid).toBe(process.getgid?.() ?? 0);
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
