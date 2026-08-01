/**
 * The WebDAV lock table on its own: no driver, no session, no clock.
 *
 * Every assertion here answers to RFC 4918's lock model (§6, §7) rather than to
 * a method's wire shape — the compatibility table of §9.10.5, the two scopes of
 * §7.4, the lease of §6.6, and §6.1 point 8's rule that a lock dies with its
 * root. `now` is a plain number that moves when the test says so, which is the
 * whole reason `DavLockTable` takes it as an argument, and `newToken` is a
 * counter so a token is a value a test can write down.
 */

import { describe, expect, it } from "vitest";
import { DavLockTable, type DavLock } from "../../src/webdav/locks.ts";

/** A table whose tokens count up, so every one of them is distinct and known. */
function tableOf(options: ConstructorParameters<typeof DavLockTable>[0] = {}): DavLockTable {
  let minted = 0;
  return new DavLockTable({ newToken: () => `urn:uuid:token-${++minted}`, ...options });
}

/** Take a lock and hand back the record, failing loudly if it was refused. */
function granted(
  table: DavLockTable,
  request: Parameters<DavLockTable["create"]>[0],
  now: number,
): DavLock {
  const grant = table.create(request, now);
  if (grant.kind !== "granted") {
    throw new Error(`expected a grant, got ${grant.kind}`);
  }
  return grant.lock;
}

/* One base time, and every other moment in the file is an offset from it — so a
   lease and an expiry are never the same number by accident. */
const START = 1_700_000_000_000;

const EXCLUSIVE_TREE = {
  path: "/notes",
  collection: true,
  depth: "infinity",
  exclusive: true,
  timeoutSeconds: 120,
} as const;

/* The same tree, shared — so a lock on a member can coexist with it and the
   two-lock cases below are about scope rather than about compatibility. */
const SHARED_TREE = { ...EXCLUSIVE_TREE, exclusive: false } as const;

const SHARED_FILE = {
  path: "/notes/draft.txt",
  collection: false,
  depth: 0,
  exclusive: false,
  timeoutSeconds: 45,
} as const;

// ---------------------------------------------------------------------------
// scope
// ---------------------------------------------------------------------------

describe("scope", () => {
  it("covers the lock root, and a depth-infinity lock covers everything under it", () => {
    const table = tableOf();
    const tree = granted(table, EXCLUSIVE_TREE, START);
    expect(table.covering("/notes", START).map((lock) => lock.token)).toEqual([tree.token]);
    expect(table.covering("/notes/a/b.txt", START).map((lock) => lock.token)).toEqual([tree.token]);
    // Not a sibling whose name merely starts the same way.
    expect(table.covering("/notesXX", START)).toEqual([]);
    expect(table.covering("/", START)).toEqual([]);
  });

  it("keeps a depth-0 lock to its own resource", () => {
    const table = tableOf();
    const file = granted(table, { ...SHARED_FILE, path: "/dir" }, START);
    expect(table.covering("/dir", START).map((lock) => lock.token)).toEqual([file.token]);
    expect(table.covering("/dir/inside.txt", START)).toEqual([]);
  });

  it("looks down the tree for lock roots, which is what an unmapping request needs", () => {
    const table = tableOf();
    const tree = granted(table, SHARED_TREE, START);
    const file = granted(table, SHARED_FILE, START);
    expect(table.within("/notes", START).map((lock) => lock.token)).toEqual([
      tree.token,
      file.token,
    ]);
    expect(table.within("/notes/draft.txt", START).map((lock) => lock.token)).toEqual([file.token]);
    expect(table.within("/other", START)).toEqual([]);
  });

  it("puts a member inside a depth-infinity scope and outside a depth-0 one", () => {
    const table = tableOf();
    const tree = granted(table, SHARED_TREE, START);
    const file = granted(table, SHARED_FILE, START);
    expect(DavLockTable.inScope(tree, "/notes")).toBe(true);
    expect(DavLockTable.inScope(tree, "/notes/deep/er.txt")).toBe(true);
    expect(DavLockTable.inScope(file, "/notes/draft.txt")).toBe(true);
    expect(DavLockTable.inScope(file, "/notes")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// §9.10.5's compatibility table
// ---------------------------------------------------------------------------

describe("conflicts", () => {
  it("is §9.10.5's table: only shared over shared is granted", () => {
    for (const held of [true, false]) {
      for (const wanted of [true, false]) {
        const table = tableOf();
        granted(table, { path: "/f.txt", collection: false, depth: 0, exclusive: held }, START);
        const grant = table.create(
          { path: "/f.txt", collection: false, depth: 0, exclusive: wanted },
          START,
        );
        expect(grant.kind, `held exclusive=${held}, wanted exclusive=${wanted}`).toBe(
          held || wanted ? "conflict" : "granted",
        );
      }
    }
  });

  it("conflicts through an ancestor's depth-infinity lock, direct or indirect", () => {
    const table = tableOf();
    const tree = granted(table, EXCLUSIVE_TREE, START);
    const grant = table.create(
      { path: "/notes/deep/file.txt", collection: false, depth: 0, exclusive: false },
      START,
    );
    expect(grant.kind === "conflict" && grant.lock.token).toBe(tree.token);
  });

  it("refuses a depth-infinity lock over a subtree that already holds one (§7.4)", () => {
    const table = tableOf();
    const inner = granted(
      table,
      { path: "/notes/deep/file.txt", collection: false, depth: 0, exclusive: true },
      START,
    );
    const grant = table.create(
      { path: "/notes", collection: true, depth: "infinity", exclusive: false },
      START,
    );
    expect(grant.kind === "conflict" && grant.lock.token).toBe(inner.token);
    // A depth-0 lock on the same collection does not reach down to it.
    expect(
      table.create({ path: "/notes", collection: true, depth: 0, exclusive: false }, START).kind,
    ).toBe("granted");
  });

  it("lets two shared locks live on one resource, each with its own token", () => {
    const table = tableOf();
    const first = granted(table, SHARED_FILE, START);
    const second = granted(table, SHARED_FILE, START);
    expect(second.token).not.toBe(first.token);
    expect(table.covering(SHARED_FILE.path, START)).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// the lease
// ---------------------------------------------------------------------------

describe("the lease", () => {
  it("grants what was asked for, the default when nothing was, and the cap for Infinite", () => {
    const table = tableOf({ defaultTimeoutSeconds: 300, maxTimeoutSeconds: 900 });
    const base = { path: "/a", collection: false, depth: 0, exclusive: false } as const;
    expect(granted(table, { ...base, timeoutSeconds: 60 }, START).timeoutSeconds).toBe(60);
    expect(granted(table, base, START).timeoutSeconds).toBe(300);
    expect(granted(table, { ...base, timeoutSeconds: "infinite" }, START).timeoutSeconds).toBe(900);
    expect(granted(table, { ...base, timeoutSeconds: 4_100_000_000 }, START).timeoutSeconds).toBe(
      900,
    );
    // A zero-second lock would be granted and gone in the same reply.
    expect(granted(table, { ...base, timeoutSeconds: 0 }, START).timeoutSeconds).toBe(1);
  });

  it("reports the seconds remaining, rounded down and never negative", () => {
    const table = tableOf();
    const lock = granted(table, { ...SHARED_FILE, timeoutSeconds: 45 }, START);
    expect(DavLockTable.remaining(lock, START)).toBe(45);
    expect(DavLockTable.remaining(lock, START + 1500)).toBe(43);
    expect(DavLockTable.remaining(lock, START + 999_000)).toBe(0);
  });

  it("stops existing once its lease has lapsed, with no timer anywhere", () => {
    const table = tableOf();
    const lock = granted(table, { ...SHARED_FILE, timeoutSeconds: 45 }, START);
    expect(table.find(lock.token, START + 44_000)?.token).toBe(lock.token);
    expect(table.find(lock.token, START + 45_000)).toBeUndefined();
    expect(table.covering(SHARED_FILE.path, START + 45_000)).toEqual([]);
    expect(table.size(START + 45_000)).toBe(0);
    // And the resource is lockable again, which is what expiry is for.
    expect(table.create({ ...SHARED_FILE, exclusive: true }, START + 45_000).kind).toBe("granted");
  });

  it("restarts the counter on a refresh and keeps everything else (§6.6, §9.10.2)", () => {
    const table = tableOf({ defaultTimeoutSeconds: 300 });
    const lock = granted(table, { ...EXCLUSIVE_TREE, timeoutSeconds: 120 }, START);
    const refreshed = table.refresh(lock.token, 200, START + 100_000);
    expect(refreshed).toMatchObject({
      token: lock.token,
      path: lock.path,
      depth: "infinity",
      exclusive: true,
      timeoutSeconds: 200,
    });
    expect(refreshed?.expiresAt).toBe(START + 100_000 + 200_000);
    // The record is replaced rather than mutated, so an earlier snapshot is intact.
    expect(lock.timeoutSeconds).toBe(120);
    // A refresh that names no live lock answers nothing at all.
    expect(table.refresh("urn:uuid:nobody", 200, START)).toBeUndefined();
    expect(table.refresh(lock.token, undefined, START + 999_000_000)).toBeUndefined();
  });

  it("takes the server's default on a refresh that asked for nothing", () => {
    const table = tableOf({ defaultTimeoutSeconds: 300 });
    const lock = granted(table, { ...SHARED_FILE, timeoutSeconds: 45 }, START);
    expect(table.refresh(lock.token, undefined, START)?.timeoutSeconds).toBe(300);
  });
});

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

describe("lifecycle", () => {
  it("deletes one lock by token, and says whether there was one", () => {
    const table = tableOf();
    const lock = granted(table, SHARED_FILE, START);
    expect(table.remove(lock.token)).toBe(true);
    expect(table.remove(lock.token)).toBe(false);
    expect(table.all(START)).toEqual([]);
  });

  it("finds the roots an unmapping request has to delete, and not the one above them", () => {
    /* §6.1 point 8 is the session's to apply — it deletes the roots that really
       went — and this is the query it applies it to. */
    const table = tableOf();
    const tree = granted(table, SHARED_TREE, START);
    const file = granted(table, SHARED_FILE, START);
    expect(table.within("/notes/draft.txt", START).map((lock) => lock.token)).toEqual([file.token]);
    table.remove(file.token);
    expect(table.all(START).map((lock) => lock.token)).toEqual([tree.token]);
    expect(table.within("/notes", START).map((lock) => lock.token)).toEqual([tree.token]);
  });

  it("refuses a lock past the cap, counting only the live ones", () => {
    const table = tableOf({ maxLocks: 2 });
    const base = { collection: false, depth: 0, exclusive: false, timeoutSeconds: 30 } as const;
    expect(table.create({ ...base, path: "/one" }, START).kind).toBe("granted");
    expect(table.create({ ...base, path: "/two" }, START).kind).toBe("granted");
    expect(table.create({ ...base, path: "/three" }, START).kind).toBe("full");
    // Past their lease the two are gone, so the table is not full any more.
    expect(table.create({ ...base, path: "/three" }, START + 30_000).kind).toBe("granted");
  });

  it("mints a distinct token for every lock, in the urn:uuid form §6.5 encourages", () => {
    const table = new DavLockTable();
    const base = { collection: false, depth: 0, exclusive: false } as const;
    const first = granted(table, { ...base, path: "/one" }, START);
    const second = granted(table, { ...base, path: "/two" }, START);
    expect(first.token).toMatch(
      /^urn:uuid:[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/,
    );
    expect(second.token).not.toBe(first.token);
  });
});
