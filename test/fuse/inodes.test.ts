/**
 * The inode table on its own.
 *
 * The session tests drive it through the wire, which is the honest end-to-end
 * check; this file goes at the cases that are hard to *reach* from a kernel but
 * trivial to get wrong — a path whose identity changed underneath, a rename
 * over a populated destination, an over-large `FORGET`.
 */

import { describe, expect, it } from "vitest";
import { FUSE_ROOT_ID } from "../../src/fuse/constants.ts";
import { InodeTable } from "../../src/fuse/inodes.ts";
import { S_IFDIR, S_IFREG, type StatsLike } from "../../src/types.ts";

/** The smallest `StatsLike` the table looks at: `dev`, `ino`. */
function stats(ino: number, options: { dev?: number; directory?: boolean } = {}): StatsLike {
  const directory = options.directory ?? false;
  return {
    dev: options.dev ?? 0,
    ino,
    mode: (directory ? S_IFDIR : S_IFREG) | 0o644,
    nlink: 1,
    uid: 0,
    gid: 0,
    rdev: 0,
    size: 0,
    blksize: 4096,
    blocks: 0,
    atimeMs: 0,
    mtimeMs: 0,
    ctimeMs: 0,
    birthtimeMs: 0,
    isFile: () => !directory,
    isDirectory: () => directory,
    isSymbolicLink: () => false,
    isBlockDevice: () => false,
    isCharacterDevice: () => false,
    isFIFO: () => false,
    isSocket: () => false,
  };
}

describe("InodeTable", () => {
  it("starts with the root bound to /", () => {
    const table = new InodeTable();
    expect(table.root.nodeid).toBe(FUSE_ROOT_ID);
    expect(table.requirePath(FUSE_ROOT_ID)).toBe("/");
    expect(table.at("/")).toBe(table.root);
    expect(table.size).toBe(1);
    expect(table.pathCount).toBe(1);
  });

  it("allocates nodeids above the root and never reuses them", () => {
    const table = new InodeTable();
    const a = table.bind("/a", stats(10));
    const b = table.bind("/b", stats(11));
    expect(a.nodeid).toBe(FUSE_ROOT_ID + 1n);
    expect(b.nodeid).toBe(FUSE_ROOT_ID + 2n);

    table.acquire(a);
    table.forget(a.nodeid, 1n);
    const c = table.bind("/c", stats(12));
    expect(c.nodeid).toBe(FUSE_ROOT_ID + 3n);
  });

  it("reuses one inode for every hardlinked path", () => {
    const table = new InodeTable();
    const one = table.bind("/one", stats(42));
    const two = table.bind("/two", stats(42));
    expect(two).toBe(one);
    expect([...one.paths]).toEqual(["/one", "/two"]);
    // The primary path is the first one bound, and drives every driver call.
    expect(table.pathOf(one)).toBe("/one");
    table.unbind("/one");
    expect(table.pathOf(one)).toBe("/two");
  });

  it("keeps identities apart when useDriverIno is off", () => {
    const table = new InodeTable({ useDriverIno: false });
    expect(table.bind("/one", stats(42))).not.toBe(table.bind("/two", stats(42)));
  });

  it("treats ino 0 as no identity at all", () => {
    const table = new InodeTable();
    expect(table.bind("/one", stats(0))).not.toBe(table.bind("/two", stats(0)));
    expect(table.bind("/one", stats(0)).key).toBeUndefined();
  });

  it("separates identities by device", () => {
    const table = new InodeTable();
    const here = table.bind("/here", stats(7, { dev: 1 }));
    const there = table.bind("/there", stats(7, { dev: 2 }));
    expect(there).not.toBe(here);
  });

  it("detaches a path whose file was replaced behind our back", () => {
    const table = new InodeTable();
    const old = table.acquire(table.bind("/f", stats(1)));
    const replacement = table.bind("/f", stats(2));

    expect(replacement).not.toBe(old);
    expect(old.paths.size).toBe(0);
    expect(table.at("/f")).toBe(replacement);
    // The old inode is orphaned, not dropped: the kernel still holds a lookup.
    expect(table.get(old.nodeid)).toBe(old);
    expect(() => table.pathOf(old)).toThrow(/ENOENT/);
  });

  it("adopts an identity for an inode that never had one", () => {
    const table = new InodeTable();
    const inode = table.bind("/f", stats(0));
    expect(inode.key).toBeUndefined();
    // A driver that starts reporting a usable `ino` is not describing a
    // different file, so the nodeid stays — and hardlinks start working.
    const again = table.bind("/f", stats(9));
    expect(again).toBe(inode);
    expect(inode.key).toBe("0:9");
    expect(table.bind("/other", stats(9))).toBe(inode);
  });

  it("only drops an inode when its lookups reach zero", () => {
    const table = new InodeTable();
    const inode = table.bind("/f", stats(3));
    table.acquire(inode);
    table.acquire(inode);
    expect(inode.nlookup).toBe(2n);

    expect(table.forget(inode.nodeid, 1n)).toBe(false);
    expect(table.get(inode.nodeid)).toBe(inode);
    expect(table.forget(inode.nodeid, 1n)).toBe(true);
    expect(table.get(inode.nodeid)).toBeUndefined();
    expect(table.at("/f")).toBeUndefined();
  });

  it("survives an over-large or negative FORGET", () => {
    const table = new InodeTable();
    const inode = table.acquire(table.bind("/f", stats(3)));
    expect(table.forget(inode.nodeid, -5n)).toBe(false);
    expect(inode.nlookup).toBe(1n);
    expect(table.forget(inode.nodeid, 1_000_000n)).toBe(true);
    expect(table.forget(inode.nodeid, 1n)).toBe(false);
    expect(table.forget(FUSE_ROOT_ID, 99n)).toBe(false);
    expect(table.get(FUSE_ROOT_ID)).toBe(table.root);
  });

  it("does not strip a live inode of an identity it inherited", () => {
    const table = new InodeTable();
    // A real filesystem reuses an inode number the moment the old file is
    // deleted, so the new file legitimately owns `(dev, ino)` while the old
    // inode is still hanging around waiting to be forgotten.
    const gone = table.acquire(table.bind("/a", stats(10, { dev: 1 })));
    table.unbind("/a");
    const reborn = table.bind("/b", stats(10, { dev: 1 }));
    expect(reborn).not.toBe(gone);

    table.forget(gone.nodeid, 1n);

    // The survivor must still be reachable by identity — otherwise the next
    // bind mints a second nodeid for it and `LINK` can no longer reply with
    // the existing one.
    expect(table.get(gone.nodeid)).toBeUndefined();
    expect(table.bind("/c", stats(10, { dev: 1 }))).toBe(reborn);
    expect([...reborn.paths]).toEqual(["/b", "/c"]);
  });

  it("throws ESTALE for a nodeid it does not know", () => {
    const table = new InodeTable();
    expect(() => table.require(404n)).toThrow(/ESTALE/);
    expect(table.get(404n)).toBeUndefined();
    expect(table.unbind("/nothing")).toBeUndefined();
  });

  it("remaps a whole subtree on rename", () => {
    const table = new InodeTable();
    const a = table.bind("/a", stats(1, { directory: true }));
    const b = table.bind("/a/b", stats(2, { directory: true }));
    const c = table.bind("/a/b/c.txt", stats(3));

    table.remap("/a", "/x");

    expect(table.pathOf(a)).toBe("/x");
    expect(table.pathOf(b)).toBe("/x/b");
    expect(table.pathOf(c)).toBe("/x/b/c.txt");
    expect(table.at("/a")).toBeUndefined();
    expect(table.at("/a/b/c.txt")).toBeUndefined();
    expect(table.at("/x/b")).toBe(b);
  });

  it("orphans whatever the destination used to hold, subtree and all", () => {
    const table = new InodeTable();
    const source = table.bind("/src", stats(1, { directory: true }));
    const doomed = table.acquire(table.bind("/dst", stats(2, { directory: true })));
    const child = table.acquire(table.bind("/dst/inside", stats(3)));

    table.remap("/src", "/dst");

    expect(table.pathOf(source)).toBe("/dst");
    expect(doomed.paths.size).toBe(0);
    expect(child.paths.size).toBe(0);
    // Both survive as ghosts until the kernel forgets them.
    expect(table.get(doomed.nodeid)).toBe(doomed);
    expect(table.get(child.nodeid)).toBe(child);
  });

  it("moves a subtree onto a path inside itself without losing entries", () => {
    const table = new InodeTable();
    const dir = table.bind("/a", stats(1, { directory: true }));
    const file = table.bind("/a/f", stats(2));
    // A one-pass rewrite would clobber `/a/f` with `/a` on the way past.
    table.remap("/a", "/a2");
    expect(table.pathOf(dir)).toBe("/a2");
    expect(table.pathOf(file)).toBe("/a2/f");

    table.remap("/a2", "/a2");
    expect(table.pathOf(dir)).toBe("/a2");
    expect(table.pathOf(file)).toBe("/a2/f");
  });

  it("only moves the renamed name of a hardlinked inode", () => {
    const table = new InodeTable();
    const inode = table.bind("/one", stats(5));
    table.bind("/two", stats(5));
    table.remap("/one", "/three");
    expect([...inode.paths].sort()).toEqual(["/three", "/two"]);
  });

  it("clears back to a bare root", () => {
    const table = new InodeTable();
    table.acquire(table.bind("/a", stats(1)));
    table.clear();
    expect(table.size).toBe(1);
    expect(table.pathCount).toBe(1);
    expect(table.nodeids()).toEqual([FUSE_ROOT_ID]);
    expect(table.requirePath(FUSE_ROOT_ID)).toBe("/");
  });
});
