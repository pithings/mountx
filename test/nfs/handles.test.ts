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
