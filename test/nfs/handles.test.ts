/**
 * The file handle table and the readdir cookie scheme.
 *
 * Tier 0, synchronous, no driver. This is the state a *stateless* protocol
 * still forces a server to keep, so its edge cases are the ones that produce
 * "my handle reads the wrong file" bugs rather than crashes.
 */

import { describe, expect, it } from "vitest";
import { NFS3_COOKIEVERFSIZE } from "../../src/nfs/v3/constants.ts";
import {
  cookieVerifier,
  DirectorySnapshots,
  FH_SIZE,
  FileHandleTable,
  ROOT_HANDLE_ID,
  sameVerifier,
} from "../../src/nfs/handles.ts";
import { S_IFDIR, S_IFREG } from "../../src/types.ts";
import type { StatsLike } from "../../src/types.ts";

/** The parts of a `StatsLike` this table looks at, and nothing else. */
function stats(ino: number, nlink = 1, mode = S_IFREG | 0o644): StatsLike {
  return { dev: 1, ino, nlink, mode } as StatsLike;
}

describe("handle encoding", () => {
  it("round-trips an entry through a 20-byte handle", () => {
    const table = new FileHandleTable();
    const entry = table.bind("/f", stats(2));
    const fh = table.encode(entry);
    expect(fh.byteLength).toBe(FH_SIZE);
    expect(table.decode(fh)).toBe(entry);
    expect(table.resolve(fh)).toBe("/f");
    expect(table.encode(table.root)).toEqual(table.encode(table.get(ROOT_HANDLE_ID)!));
  });

  it("rejects anything that is not one of ours with ESTALE", () => {
    const table = new FileHandleTable();
    const good = table.encode(table.root);
    const cases: [string, Uint8Array][] = [
      ["empty", new Uint8Array(0)],
      ["too short", good.subarray(0, 8)],
      ["over the protocol limit", new Uint8Array(80)],
      ["right length, wrong magic", new Uint8Array(FH_SIZE)],
    ];
    for (const [what, fh] of cases) {
      expect(() => table.decode(fh), what).toThrow(
        expect.objectContaining({ code: "ESTALE", errno: -116 }),
      );
    }

    // Right magic and shape, wrong boot verifier: a handle from the server that
    // ran before this one.
    const other = good.slice();
    other[6] = other[6]! ^ 0xff;
    expect(() => table.decode(other)).toThrow(/previous instance/);

    // Right verifier, an id that was never handed out.
    const unknown = good.slice();
    new DataView(unknown.buffer).setBigUint64(12, 4242n, false);
    expect(() => table.decode(unknown)).toThrow(/unknown file handle/);
  });

  it("uses a fresh verifier per table unless one is supplied", () => {
    expect(new FileHandleTable().verifier).not.toEqual(new FileHandleTable().verifier);
    const verifier = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const one = new FileHandleTable({ verifier });
    const two = new FileHandleTable({ verifier });
    // Same verifier, so the root handle is interchangeable — which is what
    // makes a handle survive a restart when a server wants that.
    expect(two.decode(one.encode(one.root))).toBe(two.root);
  });
});

describe("identity", () => {
  it("gives two hardlinks one entry, and keeps it after one name goes", () => {
    const table = new FileHandleTable();
    const first = table.bind("/a", stats(5, 2));
    const second = table.bind("/b", stats(5, 2));
    expect(second).toBe(first);
    expect([...first.paths]).toEqual(["/a", "/b"]);
    expect(table.pathOf(first)).toBe("/a");

    table.unbind("/a");
    expect(table.pathOf(first)).toBe("/b");
    table.unbind("/b");
    expect(() => table.pathOf(first)).toThrow(/has been removed/);
  });

  it("allocates a new entry when the same path holds a different file", () => {
    const table = new FileHandleTable();
    const before = table.bind("/f", stats(5));
    const after = table.bind("/f", stats(9));
    expect(after).not.toBe(before);
    // The replaced entry keeps its id and loses its only name, so a client
    // still holding its handle is told the file is gone rather than being
    // handed the impostor.
    expect(() => table.pathOf(before)).toThrow(/has been removed/);
    expect(table.pathOf(after)).toBe("/f");
  });

  it("does not identify files when the driver reports no inode number", () => {
    const table = new FileHandleTable();
    expect(table.bind("/a", stats(0))).not.toBe(table.bind("/b", stats(0)));
    const off = new FileHandleTable({ useDriverIno: false });
    expect(off.bind("/a", stats(5, 2))).not.toBe(off.bind("/b", stats(5, 2)));
  });

  /**
   * The out-of-band case, which is not hypothetical with the `node:fs`
   * passthrough: something else on the machine renames `/a` to `/c`, and the
   * filesystem hands the freed inode number straight back.
   */
  it("drops a name an inode cannot still have when its number is reused", () => {
    const table = new FileHandleTable();
    const first = table.bind("/a", stats(5));
    // No REMOVE and no RENAME was ever seen by the server; the next thing it
    // hears about inode 5 is that it is at `/c`, with one link.
    const reused = table.bind("/c", stats(5));
    expect(reused).toBe(first);
    // Without the nlink check this would still be `/a` — and every operation on
    // the `/c` handle would land on whatever `/a` is now.
    expect(table.pathOf(reused)).toBe("/c");
    expect([...reused.paths]).toEqual(["/c"]);
    expect(table.at("/a")).toBeUndefined();
  });

  it("keeps every name a file's link count allows", () => {
    const table = new FileHandleTable();
    table.bind("/a", stats(5, 3));
    table.bind("/b", stats(5, 3));
    const entry = table.bind("/c", stats(5, 3));
    expect([...entry.paths]).toEqual(["/a", "/b", "/c"]);
    // The link count falling to one is the server being told the other two are
    // gone, even if it never saw the removals.
    const after = table.bind("/c", stats(5, 1));
    expect([...after.paths]).toEqual(["/c"]);
  });

  it("believes a driver that reports no link count at all", () => {
    const table = new FileHandleTable();
    table.bind("/a", stats(5, 0));
    const entry = table.bind("/b", stats(5, 0));
    expect([...entry.paths]).toEqual(["/a", "/b"]);
  });

  it("carries the fileid every version reports, and refreshes it on rebind", () => {
    const table = new FileHandleTable();
    expect(table.bind("/a", stats(7)).fileid).toBe(7n);
    // No `ino` on offer is a driver with no identity, and the entry id is what
    // both sessions substitute.
    const anonymous = table.bind("/b", stats(0));
    expect(anonymous.fileid).toBe(anonymous.id);
  });
});

/**
 * The half of the lifetime rule that is not "nothing is ever dropped".
 *
 * An entry whose last name is gone can only be reached through `decode()` →
 * `pathOf()`, and `pathOf()` always throws `ESTALE` for it — so keeping it
 * bought nothing and cost one entry per name the client had ever seen, with no
 * bound at all under create/delete churn.
 */
describe("path-less entries", () => {
  it("frees an entry whose last name is gone, so churn does not grow the table", () => {
    const table = new FileHandleTable();
    const handles: Uint8Array[] = [];
    for (let index = 0; index < 100; index++) {
      const path = `/build/tmp${index}`;
      const entry = table.bind(path, stats(1000 + index));
      handles.push(table.encode(entry));
      table.unbind(path);
      expect(table.get(entry.id)).toBeUndefined();
    }
    // The root and nothing else. Before this, 101 — one per file the churn ever
    // touched, none of them reachable.
    expect(table.size).toBe(1);
    expect(table.pathCount).toBe(1);

    // And every handle the client kept still answers `ESTALE`, which is the
    // whole reason dropping them is safe: the message moves from `pathOf` to
    // `decode`, the status does not.
    for (const fh of handles) {
      expect(() => table.decode(fh)).toThrow(
        expect.objectContaining({ code: "ESTALE", errno: -116 }),
      );
    }
  });

  it("keeps an entry while any of its names is left", () => {
    const table = new FileHandleTable();
    const entry = table.bind("/a", stats(5, 2));
    table.bind("/b", stats(5, 2));
    table.unbind("/a");
    expect(table.get(entry.id)).toBe(entry);
    expect(table.resolve(table.encode(entry))).toBe("/b");
  });

  it("never hands a freed id to a later file", () => {
    const table = new FileHandleTable();
    const gone = table.bind("/a", stats(5));
    const fh = table.encode(gone);
    table.unbind("/a");
    // The same `ino`, straight back from the driver — which is what a real
    // filesystem does. Ids come off a counter that only goes up, so the dead
    // handle cannot alias the new file however the identities line up.
    const fresh = table.bind("/b", stats(5));
    expect(fresh.id).not.toBe(gone.id);
    expect(() => table.decode(fh)).toThrow(/unknown file handle/);
  });

  it("never frees the root, whose handle is handed out without a lookup", () => {
    const table = new FileHandleTable();
    table.bind("/", stats(2, 1, S_IFDIR | 0o755));
    // The driver's root turns out to be a different object than it was, so `/`
    // is detached from the entry holding it — which happens to be the one entry
    // `PUTROOTFH` and `MNT` encode from a field rather than from a lookup. It
    // has to stay decodable, or this server mints a handle it then refuses.
    table.bind("/", stats(9, 1, S_IFDIR | 0o755));
    expect(table.decode(table.encode(table.root))).toBe(table.root);
  });
});

/**
 * The other half of the growth story: an entry whose names are all still live.
 *
 * Nothing on the wire ever says a client is done with one, so a cap is the only
 * bound there can be — and evicting one is visible to the client, unlike
 * dropping a path-less entry. What these check is that it is visible as
 * `ESTALE` and never as somebody else's file.
 */
describe("the handle-table bound", () => {
  it("grows without limit unless a cap is asked for", () => {
    const table = new FileHandleTable();
    for (let index = 0; index < 200; index++) {
      table.bind(`/f${index}`, stats(100 + index));
    }
    expect(table.size).toBe(201);
    expect(table.pathCount).toBe(201);
  });

  it("evicts the least recently used, and only past the cap", () => {
    // Root plus three.
    const table = new FileHandleTable({ maxHandles: 4 });
    const a = table.bind("/a", stats(2));
    const b = table.bind("/b", stats(3));
    const c = table.bind("/c", stats(4));
    const gone = table.encode(b);
    expect(table.size).toBe(4);

    // Using `/a` makes `/b` the oldest, which is the whole point of stamping
    // recency on `decode` rather than only on `bind`.
    expect(table.decode(table.encode(a))).toBe(a);
    table.bind("/d", stats(5));

    expect(table.size).toBe(4);
    expect(table.get(b.id)).toBeUndefined();
    expect(table.at("/b")).toBeUndefined();
    expect(table.get(a.id)).toBe(a);
    expect(table.get(c.id)).toBe(c);
    // What the client that still holds `/b`'s handle is told.
    expect(() => table.decode(gone)).toThrow(
      expect.objectContaining({ code: "ESTALE", errno: -116 }),
    );
    expect(() => table.decode(gone)).toThrow(/unknown file handle/);
  });

  it("leaves an evicted handle stale however the identities line up afterwards", () => {
    const table = new FileHandleTable({ maxHandles: 2 });
    const evicted = table.bind("/a", stats(5));
    const gone = table.encode(evicted);
    table.bind("/b", stats(6));
    expect(table.get(evicted.id)).toBeUndefined();

    // The same `(dev, ino)`, straight back from the driver, at the same path:
    // the evicted entry must not be found by identity, and the id it had must
    // not come round again.
    const fresh = table.bind("/a", stats(5));
    expect(fresh).not.toBe(evicted);
    expect(fresh.id).not.toBe(evicted.id);
    expect(() => table.decode(gone)).toThrow(/unknown file handle/);
    expect(table.pathOf(fresh)).toBe("/a");
  });

  it("never evicts an entry the client is working with", () => {
    const table = new FileHandleTable({ maxHandles: 3 });
    const keep = table.bind("/keep", stats(2));
    const kept = table.encode(keep);
    // Churn far past the cap, touching `/keep` the way a client holding its
    // handle would.
    for (let index = 0; index < 50; index++) {
      table.bind(`/tmp${index}`, stats(100 + index));
      expect(table.resolve(kept)).toBe("/keep");
    }
    expect(table.size).toBe(3);
    expect(table.get(keep.id)).toBe(keep);
  });

  it("counts reaching an entry by path as a use", () => {
    const table = new FileHandleTable({ maxHandles: 3 });
    const dir = table.bind("/dir", stats(2, 2, S_IFDIR | 0o755));
    for (let index = 0; index < 20; index++) {
      table.bind(`/dir/f${index}`, stats(100 + index));
      // What a READDIR paging through a directory does with it: reach the entry
      // by path rather than by the handle the client sent.
      expect(table.at("/dir")).toBe(dir);
    }
    expect(table.get(dir.id)).toBe(dir);
  });

  it("never evicts the root, whose handle is handed out without a lookup", () => {
    const table = new FileHandleTable({ maxHandles: 2 });
    for (let index = 0; index < 20; index++) {
      table.bind(`/f${index}`, stats(100 + index));
    }
    expect(table.size).toBe(2);
    expect(table.decode(table.encode(table.root))).toBe(table.root);
    expect(table.pathOf(table.root)).toBe("/");
  });

  it("keeps the root and the entry being bound however small the cap is", () => {
    const table = new FileHandleTable({ maxHandles: 1 });
    const entry = table.bind("/a", stats(2));
    // Two is the floor: the caller is about to encode `entry` into a reply, and
    // the root is never evictable at all.
    expect(table.size).toBe(2);
    expect(table.resolve(table.encode(entry))).toBe("/a");
  });

  it("takes a cap that is not a usable count as no cap", () => {
    for (const maxHandles of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      const table = new FileHandleTable({ maxHandles });
      for (let index = 0; index < 10; index++) {
        table.bind(`/f${index}`, stats(100 + index));
      }
      expect(table.size, `maxHandles: ${maxHandles}`).toBe(11);
    }
  });

  it("leaves the path map agreeing with the id map after an eviction", () => {
    const table = new FileHandleTable({ maxHandles: 4 });
    // A hardlinked pair, so the evicted entry has two names to lose at once.
    const linked = table.bind("/a", stats(5, 2));
    table.bind("/b", stats(5, 2));
    expect(table.size).toBe(2);
    table.bind("/c", stats(6));
    table.bind("/d", stats(7));
    table.bind("/e", stats(8));

    expect(table.get(linked.id)).toBeUndefined();
    expect(table.at("/a")).toBeUndefined();
    expect(table.at("/b")).toBeUndefined();
    // One path per surviving entry, plus the root's `/`.
    expect(table.size).toBe(4);
    expect(table.pathCount).toBe(4);
  });

  it("never takes a pinned entry, however long it has been idle", () => {
    const table = new FileHandleTable({ maxHandles: 3 });
    const pinned = table.bind("/open", stats(2));
    const held = table.encode(pinned);
    table.pin(pinned.id);
    // Never touched again: under the LRU alone this is the first thing to go,
    // every single time.
    for (let index = 0; index < 50; index++) {
      table.bind(`/tmp${index}`, stats(100 + index));
    }
    expect(table.get(pinned.id)).toBe(pinned);
    expect(table.resolve(held)).toBe("/open");
    expect(table.size).toBe(3);
  });

  it("makes an unpinned entry the first victim again", () => {
    const table = new FileHandleTable({ maxHandles: 3 });
    const entry = table.bind("/open", stats(2));
    table.pin(entry.id);
    table.bind("/a", stats(3));
    table.bind("/b", stats(4));
    expect(table.get(entry.id)).toBe(entry);

    table.unpin(entry.id);
    // Nothing re-evicts on unpin — the cap is only enforced by a `bind` — so
    // the next one is what takes it, and it takes the oldest, which is this.
    table.bind("/c", stats(5));
    expect(table.get(entry.id)).toBeUndefined();
    expect(table.size).toBe(3);
  });

  it("counts pins, so one holder cannot release another's", () => {
    const table = new FileHandleTable({ maxHandles: 2 });
    const entry = table.bind("/open", stats(2));
    table.pin(entry.id);
    table.pin(entry.id);
    table.unpin(entry.id);
    expect(entry.pins).toBe(1);
    table.bind("/a", stats(3));
    expect(table.get(entry.id)).toBe(entry);

    table.unpin(entry.id);
    expect(entry.pins).toBe(0);
    table.bind("/b", stats(4));
    expect(table.get(entry.id)).toBeUndefined();
  });

  it("never counts a pin below zero, so a lapsed holder cannot go negative", () => {
    const table = new FileHandleTable({ maxHandles: 2 });
    const entry = table.bind("/open", stats(2));
    table.unpin(entry.id);
    expect(entry.pins).toBe(0);
    // And an id the table no longer has is neither pinnable nor a throw: a
    // holder whose file was removed unpins into thin air.
    table.unbind("/open");
    expect(table.get(entry.id)).toBeUndefined();
    table.pin(entry.id);
    table.unpin(entry.id);
    expect(table.size).toBe(1);
  });

  it("exceeds the cap rather than evicting a pinned entry", () => {
    const table = new FileHandleTable({ maxHandles: 3 });
    const pinned: bigint[] = [];
    for (let index = 0; index < 10; index++) {
      const entry = table.bind(`/open${index}`, stats(100 + index));
      table.pin(entry.id);
      pinned.push(entry.id);
    }
    // Root plus ten, at a cap of three: the soft cap, which is the accepted
    // trade — a broken share reservation is worse than a table over its bound.
    expect(table.size).toBe(11);
    for (const id of pinned) {
      expect(table.get(id)).toBeDefined();
    }
    // And it does not evict its way back down when the pins go: it comes down
    // as the next binds find victims again.
    for (const id of pinned) {
      table.unpin(id);
    }
    expect(table.size).toBe(11);
    table.bind("/next", stats(200));
    expect(table.size).toBe(3);
  });

  it("still drops a pinned entry whose last path is gone", () => {
    const table = new FileHandleTable({ maxHandles: 4 });
    const entry = table.bind("/doomed", stats(2));
    table.pin(entry.id);
    // A pin is about the LRU and nothing else: a removed file's handles are
    // ESTALE whether or not somebody has it open, and keeping the entry alive
    // for the pin would be a leak with a `rm` trigger.
    table.unbind("/doomed");
    expect(table.get(entry.id)).toBeUndefined();
    expect(table.size).toBe(1);
  });

  it("drops the pins with the entries on clear()", () => {
    const table = new FileHandleTable({ maxHandles: 3 });
    const entry = table.bind("/open", stats(2));
    table.pin(entry.id);
    table.pin(table.root.id);
    table.clear();
    expect(table.root.pins).toBe(0);
    expect(table.get(entry.id)).toBeUndefined();
    for (let index = 0; index < 10; index++) {
      table.bind(`/f${index}`, stats(100 + index));
    }
    expect(table.size).toBe(3);
  });

  it("restamps a renamed subtree, and moves it whole", () => {
    const table = new FileHandleTable({ maxHandles: 5 });
    const stale = table.bind("/old", stats(2));
    const dir = table.bind("/dir", stats(3, 2, S_IFDIR | 0o755));
    const file = table.bind("/dir/f", stats(4));
    const deep = table.bind("/dir/sub/g", stats(5));

    table.remap("/dir", "/moved");
    expect(table.pathOf(dir)).toBe("/moved");
    expect(table.pathOf(file)).toBe("/moved/f");
    expect(table.pathOf(deep)).toBe("/moved/sub/g");

    // The rename touched all three, so the entry nobody has named since it was
    // created is the one that goes.
    table.bind("/new", stats(6));
    expect(table.get(stale.id)).toBeUndefined();
    expect(table.size).toBe(5);
    expect(table.resolve(table.encode(deep))).toBe("/moved/sub/g");
  });
});

describe("rename", () => {
  it("moves a path and everything under it", () => {
    const table = new FileHandleTable();
    const dir = table.bind("/dir", stats(2, 2, S_IFDIR | 0o755));
    const file = table.bind("/dir/f", stats(3));
    const deep = table.bind("/dir/sub/g", stats(4));

    table.remap("/dir", "/moved");
    expect(table.pathOf(dir)).toBe("/moved");
    expect(table.pathOf(file)).toBe("/moved/f");
    expect(table.pathOf(deep)).toBe("/moved/sub/g");
    expect(table.at("/dir")).toBeUndefined();
  });

  it("replaces whatever was at the destination", () => {
    const table = new FileHandleTable();
    const victim = table.bind("/to", stats(9));
    const inside = table.bind("/to/child", stats(10));
    const moved = table.bind("/from", stats(5));

    table.remap("/from", "/to");
    expect(table.pathOf(moved)).toBe("/to");
    expect(() => table.pathOf(victim)).toThrow(/has been removed/);
    expect(() => table.pathOf(inside)).toThrow(/has been removed/);
  });

  it("survives a rename inside the moved subtree", () => {
    const table = new FileHandleTable();
    const file = table.bind("/a/b", stats(3));
    table.remap("/a/b", "/a/c");
    expect(table.pathOf(file)).toBe("/a/c");
    expect(table.pathCount).toBeGreaterThan(0);
  });

  it("clears back to the root", () => {
    const table = new FileHandleTable();
    table.bind("/a", stats(2));
    table.bind("/b", stats(3));
    expect(table.size).toBe(3);
    table.clear();
    expect(table.size).toBe(1);
    expect(table.pathOf(table.root)).toBe("/");
  });
});

describe("cookie verifiers", () => {
  it("is eight bytes and depends on the whole listing", () => {
    expect(cookieVerifier([]).byteLength).toBe(NFS3_COOKIEVERFSIZE);
    expect(sameVerifier(cookieVerifier(["a", "b"]), cookieVerifier(["a", "b"]))).toBe(true);
    expect(sameVerifier(cookieVerifier(["a", "b"]), cookieVerifier(["b", "a"]))).toBe(false);
    expect(sameVerifier(cookieVerifier(["a"]), cookieVerifier(["a", "b"]))).toBe(false);
  });

  it("separates names with a byte no name can contain", () => {
    // The delimiter is a NUL, because it is the one byte a POSIX filename
    // cannot hold. A separator that *could* appear in a name would make
    // `["a b"]` and `["a", "b"]` the same directory as far as the verifier is
    // concerned — and this assertion is what keeps a formatter, or a future
    // "tidy up the join" edit, from quietly reintroducing that.
    expect(sameVerifier(cookieVerifier(["a b"]), cookieVerifier(["a", "b"]))).toBe(false);
    expect(sameVerifier(cookieVerifier(["a,b"]), cookieVerifier(["a", "b"]))).toBe(false);
    expect(sameVerifier(cookieVerifier(["a/b"]), cookieVerifier(["a", "b"]))).toBe(false);
  });

  it("compares defensively", () => {
    expect(sameVerifier(new Uint8Array(8), new Uint8Array(4))).toBe(false);
    expect(sameVerifier(new Uint8Array(8), new Uint8Array(8))).toBe(true);
  });
});

describe("directory snapshots", () => {
  it("evicts the least recently used", () => {
    const cache = new DirectorySnapshots(2);
    cache.set(1n, ["a"]);
    cache.set(2n, ["b"]);
    // Touching 1 makes 2 the oldest.
    expect(cache.get(1n)).toBeDefined();
    cache.set(3n, ["c"]);
    expect(cache.size).toBe(2);
    expect(cache.get(2n)).toBeUndefined();
    expect(cache.get(1n)).toBeDefined();
    expect(cache.get(3n)).toBeDefined();
  });

  it("stores the verifier alongside the names", () => {
    const cache = new DirectorySnapshots();
    const snapshot = cache.set(1n, ["x", "y"]);
    expect(snapshot.names).toEqual(["x", "y"]);
    expect(sameVerifier(snapshot.cookieverf, cookieVerifier(["x", "y"]))).toBe(true);
    cache.delete(1n);
    expect(cache.get(1n)).toBeUndefined();
    cache.set(2n, []);
    cache.clear();
    expect(cache.size).toBe(0);
  });

  it("keeps at least one entry however small it is asked to be", () => {
    const cache = new DirectorySnapshots(0);
    cache.set(1n, ["a"]);
    expect(cache.size).toBe(1);
  });
});
