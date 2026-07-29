/**
 * The fid table on its own.
 *
 * The session tests (step 4 onward) drive it over the wire, which is the
 * honest end-to-end check; this file goes at what is hard to *reach* from a
 * kernel and trivial to get wrong — a client reusing a live fid, a rename that
 * catches a sibling whose name merely starts the same way, a readdir offset
 * from before a rewind, and the qid identity a client caches everything
 * against.
 */

import { describe, expect, it } from "vitest";
import { P9_NOFID, P9_QTDIR, P9_QTFILE, P9_QTSYMLINK } from "../../src/9p/constants.ts";
import { FIRST_QID_PATH, FidTable, qidType, qidVersion, walkStep } from "../../src/9p/fids.ts";
import {
  S_IFDIR,
  S_IFIFO,
  S_IFLNK,
  S_IFMT,
  S_IFREG,
  type FileHandleLike,
  type StatsLike,
} from "../../src/types.ts";

/** The only fields this table looks at: `dev`, `ino`, `mode`, `mtimeMs`. */
function stats(
  options: { dev?: number; ino?: number; mode?: number; mtimeMs?: number } = {},
): StatsLike {
  const mode = options.mode ?? S_IFREG | 0o644;
  const type = mode & S_IFMT;
  return {
    dev: options.dev ?? 7,
    ino: options.ino ?? 0,
    mode,
    nlink: 1,
    uid: 1000,
    gid: 1000,
    rdev: 0,
    size: 0,
    blksize: 4096,
    blocks: 0,
    atimeMs: 0,
    mtimeMs: options.mtimeMs ?? 0,
    ctimeMs: 0,
    birthtimeMs: 0,
    isFile: () => type === S_IFREG,
    isDirectory: () => type === S_IFDIR,
    isSymbolicLink: () => type === S_IFLNK,
    isBlockDevice: () => false,
    isCharacterDevice: () => false,
    isFIFO: () => type === S_IFIFO,
    isSocket: () => false,
  };
}

/** A handle that only has to be distinguishable by identity; nothing calls it. */
function fakeHandle(): FileHandleLike {
  return { close: () => Promise.resolve() } as FileHandleLike;
}

describe("FidTable lifecycle", () => {
  it("starts empty and takes the fid the client chose", () => {
    const table = new FidTable();
    expect(table.size).toBe(0);

    const root = table.create(1, "/");
    expect(root.fid).toBe(1);
    expect(root.path).toBe("/");
    expect(root.open).toBeUndefined();
    expect(root.iounit).toBe(0);
    expect(root.cursor).toBeUndefined();
    expect(table.size).toBe(1);
    expect(table.get(1)).toBe(root);
    expect(table.fids()).toEqual([1]);
  });

  it("normalizes the path a fid is created with", () => {
    const table = new FidTable();
    expect(table.create(1, "/a/./b/../c/").path).toBe("/a/c");
  });

  it("refuses a fid that is already in use", () => {
    const table = new FidTable();
    table.create(4, "/a");
    expect(() => table.create(4, "/b")).toThrow(/already in use/);
    // The live fid is untouched — that is the whole point of refusing.
    expect(table.require(4).path).toBe("/a");
    expect(table.size).toBe(1);
  });

  it("never lets P9_NOFID into the table", () => {
    const table = new FidTable();
    expect(() => table.create(P9_NOFID, "/")).toThrow(/P9_NOFID/);
    expect(() => table.require(P9_NOFID)).toThrow(/P9_NOFID/);
    expect(table.size).toBe(0);
  });

  it("refuses a fid that is not a u32", () => {
    const table = new FidTable();
    for (const bad of [-1, 1.5, Number.NaN, 2 ** 32]) {
      expect(() => table.create(bad, "/"), `${bad}`).toThrow(/not a valid fid/);
    }
  });

  it("answers EBADF for a fid nobody issued", () => {
    const table = new FidTable();
    expect(table.get(9)).toBeUndefined();
    expect(() => table.require(9)).toThrow(/EBADF/);
    expect(() => table.clunk(9)).toThrow(/EBADF/);
  });

  it("clones a fid without cloning what it has open", () => {
    const table = new FidTable();
    const source = table.create(1, "/a/b");
    source.open = { flags: 0, handle: fakeHandle(), directory: false };
    source.iounit = 8192;
    source.cursor = { entries: [], offsets: new Map() };

    const clone = table.clone(1, 2);
    expect(clone.fid).toBe(2);
    expect(clone.path).toBe("/a/b");
    expect(clone.open).toBeUndefined();
    expect(clone.iounit).toBe(0);
    expect(clone.cursor).toBeUndefined();
    // The source keeps everything.
    expect(source.open?.handle).toBeDefined();
    expect(table.size).toBe(2);
  });

  it("treats a clone onto the same fid as the in-place walk it is", () => {
    const table = new FidTable();
    const entry = table.create(1, "/a");
    entry.open = { flags: 0, handle: fakeHandle(), directory: false };
    expect(table.clone(1, 1)).toBe(entry);
    expect(entry.open).toBeDefined();
    expect(table.size).toBe(1);
  });

  it("refuses a clone onto a live fid, and onto an unknown source", () => {
    const table = new FidTable();
    table.create(1, "/a");
    table.create(2, "/b");
    expect(() => table.clone(1, 2)).toThrow(/already in use/);
    expect(() => table.clone(3, 4)).toThrow(/EBADF/);
    expect(table.size).toBe(2);
    expect(table.require(2).path).toBe("/b");
  });

  it("clunks once, hands back the open state, and refuses the second clunk", () => {
    const table = new FidTable();
    const entry = table.create(1, "/a");
    const handle = fakeHandle();
    entry.open = { flags: 0, handle, directory: false };

    const clunked = table.clunk(1);
    expect(clunked).toBe(entry);
    expect(clunked.open?.handle).toBe(handle);
    expect(table.size).toBe(0);
    expect(() => table.clunk(1)).toThrow(/EBADF/);
  });

  it("lists only the fids holding a real driver handle", () => {
    const table = new FidTable();
    const withHandle = table.create(1, "/a");
    const handle = fakeHandle();
    withHandle.open = { flags: 0, handle, directory: false };
    // A `handles: false` driver: opened, but nothing to close.
    table.create(2, "/b").open = { flags: 0, handle: undefined, directory: false };
    table.create(3, "/c");

    expect(table.openHandles()).toEqual([{ fid: withHandle, handle }]);
    expect(table.entries().map((entry) => entry.fid)).toEqual([1, 2, 3]);

    table.clear();
    expect(table.size).toBe(0);
    expect(table.openHandles()).toEqual([]);
  });
});

describe("walkStep", () => {
  it("appends one element", () => {
    expect(walkStep("/", "a")).toBe("/a");
    expect(walkStep("/a", "b")).toBe("/a/b");
  });

  it("clamps `..` at the root", () => {
    expect(walkStep("/a/b", "..")).toBe("/a");
    expect(walkStep("/a", "..")).toBe("/");
    expect(walkStep("/", "..")).toBe("/");
    expect(walkStep(walkStep(walkStep("/", ".."), ".."), "etc")).toBe("/etc");
  });

  it("resolves `.` to the same path", () => {
    expect(walkStep("/a/b", ".")).toBe("/a/b");
    expect(walkStep("/", ".")).toBe("/");
  });

  it("refuses an empty element", () => {
    expect(() => walkStep("/a", "")).toThrow(/EINVAL/);
  });

  it("refuses an element containing a separator", () => {
    for (const bad of ["a/b", "/", "/a", "a/", "../../etc"]) {
      expect(() => walkStep("/x", bad), bad).toThrow(/separator/);
    }
  });

  it("refuses an element containing a NUL", () => {
    // 9P strings are counted, so a NUL survives the wire; `node:fs` answers one
    // with a TypeError, which is not an FsError and would surface as EIO.
    for (const bad of ["a\0b", "\0", "trailing\0"]) {
      expect(() => walkStep("/x", bad), JSON.stringify(bad)).toThrow(/NUL/);
    }
  });
});

describe("FidTable.remap", () => {
  it("moves the renamed path, everything under it, and nothing else", () => {
    const table = new FidTable();
    const above = table.create(1, "/");
    const at = table.create(2, "/a");
    const below = table.create(3, "/a/b/c");
    const elsewhere = table.create(4, "/other");
    // The classic prefix bug: `/ab` is not inside `/a`.
    const sibling = table.create(5, "/ab");
    const siblingBelow = table.create(6, "/abc/d");

    table.remap("/a", "/z");

    expect(above.path).toBe("/");
    expect(at.path).toBe("/z");
    expect(below.path).toBe("/z/b/c");
    expect(elsewhere.path).toBe("/other");
    expect(sibling.path).toBe("/ab");
    expect(siblingBelow.path).toBe("/abc/d");
  });

  it("moves a subtree into itself without clobbering", () => {
    const table = new FidTable();
    const outer = table.create(1, "/a");
    const inner = table.create(2, "/a/b");
    table.remap("/a", "/a/b");
    expect(outer.path).toBe("/a/b");
    expect(inner.path).toBe("/a/b/b");
  });

  it("does nothing when the two paths are the same", () => {
    const table = new FidTable();
    const entry = table.create(1, "/a/b");
    table.remap("/a", "/a");
    expect(entry.path).toBe("/a/b");
  });

  it("leaves a fid at the clobbered destination naming that path", () => {
    // Documented in `remap`: a path-based server has nowhere else to point it.
    const table = new FidTable();
    const victim = table.create(1, "/dest");
    table.create(2, "/src");
    table.remap("/src", "/dest");
    expect(victim.path).toBe("/dest");
    expect(table.require(2).path).toBe("/dest");
  });
});

describe("FidTable readdir cursor", () => {
  const listing = ["a", "b", "c"];

  it("re-snapshots at offset 0, every time", () => {
    const table = new FidTable<string>();
    const entry = table.create(1, "/d");
    expect(table.resume(entry, 0n)).toBeUndefined();

    const first = table.snapshot(entry, listing);
    expect(first).toEqual({ entries: listing, index: 0 });
    table.noteOffset(entry, 1n, 1);
    // A client rewinding is told to re-list, not handed the stale snapshot.
    expect(table.resume(entry, 0n)).toBeUndefined();
  });

  it("has no cursor before the first snapshot", () => {
    const table = new FidTable<string>();
    const entry = table.create(1, "/d");
    expect(entry.cursor).toBeUndefined();
    // A non-zero offset with no snapshot at all is still a refusal.
    expect(() => table.resume(entry, 4n)).toThrow(/never given readdir offset 4/);
  });

  it("resumes at an offset it handed out", () => {
    const table = new FidTable<string>();
    const entry = table.create(1, "/d");
    table.snapshot(entry, listing);
    for (let index = 0; index < listing.length; index++) {
      table.noteOffset(entry, BigInt(index + 1), index + 1);
    }
    expect(table.resume(entry, 2n)).toEqual({ entries: listing, index: 2 });
    expect(table.resume(entry, 3n)).toEqual({ entries: listing, index: 3 });
  });

  it("refuses an offset it never handed out", () => {
    const table = new FidTable<string>();
    const entry = table.create(1, "/d");
    table.snapshot(entry, listing);
    table.noteOffset(entry, 1n, 1);
    expect(() => table.resume(entry, 99n)).toThrow(/never given readdir offset 99/);
  });

  it("refuses an offset from before a rewind", () => {
    const table = new FidTable<string>();
    const entry = table.create(1, "/d");
    table.snapshot(entry, listing);
    table.noteOffset(entry, 7n, 1);
    table.snapshot(entry, ["a"]);
    expect(() => table.resume(entry, 7n)).toThrow(/never given readdir offset 7/);
  });

  it("refuses an offset another fid handed out", () => {
    const table = new FidTable<string>();
    const one = table.create(1, "/d");
    const two = table.create(2, "/d");
    table.snapshot(one, listing);
    table.noteOffset(one, 5n, 2);
    table.snapshot(two, listing);
    expect(() => table.resume(two, 5n)).toThrow(/never given readdir offset 5/);
  });

  it("never records offset 0 as a resume point", () => {
    const table = new FidTable<string>();
    const entry = table.create(1, "/d");
    table.snapshot(entry, listing);
    table.noteOffset(entry, 0n, 2);
    expect(entry.cursor?.offsets.size).toBe(0);
    expect(table.resume(entry, 0n)).toBeUndefined();
  });

  it("drops the cursor with the fid", () => {
    const table = new FidTable<string>();
    const entry = table.create(1, "/d");
    table.snapshot(entry, listing);
    table.clunk(1);
    expect(table.get(1)).toBeUndefined();
  });

  it("drops the snapshot at offset 0, even when nothing replaces it", () => {
    // The session's re-list can fail (driver `readdir` rejects → Rlerror). If
    // the old snapshot survived that, the client could then present an offset
    // from before the rewind and be paged the listing it just rewound past.
    const table = new FidTable<string>();
    const entry = table.create(1, "/d");
    table.snapshot(entry, listing);
    table.noteOffset(entry, 2n, 2);

    expect(table.resume(entry, 0n)).toBeUndefined();
    expect(entry.cursor).toBeUndefined();
    expect(() => table.resume(entry, 2n)).toThrow(/never given readdir offset 2/);
  });
});

describe("FidTable cursor invalidation", () => {
  const listing = ["a", "b", "c"];

  it("drops the cursor when a walk moves the fid", () => {
    const table = new FidTable<string>();
    const entry = table.create(1, "/one");
    table.snapshot(entry, listing);
    table.noteOffset(entry, 1n, 1);

    // `Twalk` with newfid == fid: the session rewrites the path in place.
    entry.path = "/two";

    expect(entry.cursor).toBeUndefined();
    expect(() => table.resume(entry, 1n)).toThrow(/never given readdir offset 1/);
  });

  it("keeps the cursor when the path is assigned the value it already had", () => {
    const table = new FidTable<string>();
    const entry = table.create(1, "/one");
    table.snapshot(entry, listing);
    table.noteOffset(entry, 1n, 1);
    entry.path = "/one/././";
    expect(entry.path).toBe("/one");
    expect(table.resume(entry, 1n)).toEqual({ entries: listing, index: 1 });
  });

  it("drops the cursor of a fid whose directory a rename replaced", () => {
    const table = new FidTable<string>();
    const victim = table.create(1, "/dest");
    table.snapshot(victim, listing);
    table.noteOffset(victim, 1n, 1);

    table.remap("/src", "/dest");

    // The path is unchanged, but it is a different directory now.
    expect(victim.path).toBe("/dest");
    expect(victim.cursor).toBeUndefined();
    expect(() => table.resume(victim, 1n)).toThrow(/never given readdir offset 1/);
  });

  it("drops the cursor of a fid the rename moved", () => {
    // Conservative on purpose: the listing is probably still valid, but the one
    // race we cannot resolve is worth an EINVAL and a client-side restart.
    const table = new FidTable<string>();
    const moved = table.create(1, "/a");
    const below = table.create(2, "/a/sub");
    table.snapshot(moved, listing);
    table.snapshot(below, listing);

    table.remap("/a", "/z");

    expect(moved.path).toBe("/z");
    expect(below.path).toBe("/z/sub");
    expect(moved.cursor).toBeUndefined();
    expect(below.cursor).toBeUndefined();
  });

  it("leaves an untouched fid's cursor alone across a rename", () => {
    const table = new FidTable<string>();
    const bystander = table.create(1, "/elsewhere");
    table.snapshot(bystander, listing);
    table.noteOffset(bystander, 1n, 1);
    table.remap("/a", "/z");
    expect(table.resume(bystander, 1n)).toEqual({ entries: listing, index: 1 });
  });
});

describe("qid synthesis", () => {
  it("reports the type bits the mode names", () => {
    expect(qidType(S_IFDIR | 0o755)).toBe(P9_QTDIR);
    expect(qidType(S_IFLNK | 0o777)).toBe(P9_QTSYMLINK);
    expect(qidType(S_IFREG | 0o644)).toBe(P9_QTFILE);
    // Nothing else has a qid bit of its own in 9P2000.L.
    expect(qidType(S_IFIFO | 0o600)).toBe(P9_QTFILE);
  });

  it("takes the version from mtime, and says `do not cache` when there is none", () => {
    expect(qidVersion(stats({ mtimeMs: 1_700_000_000_123 }))).toBe(
      Math.trunc(1_700_000_000_123) >>> 0,
    );
    expect(qidVersion(stats({ mtimeMs: 0 }))).toBe(0);
    expect(qidVersion(stats({ mtimeMs: Number.NaN }))).toBe(0);
    // A modification changes it, which is the only thing the field must do.
    expect(qidVersion(stats({ mtimeMs: 1000 }))).not.toBe(qidVersion(stats({ mtimeMs: 1001 })));
  });

  it("allocates the qid path itself, never handing out the driver's ino", () => {
    const table = new FidTable();
    const qid = table.qidFor(stats({ ino: 4242, mode: S_IFDIR | 0o755, mtimeMs: 5 }), "/a");
    expect(qid).toEqual({ type: P9_QTDIR, version: 5, path: FIRST_QID_PATH });
    expect(table.qidPathCount).toBe(1);
    expect(table.qidPathFor(stats({ ino: 77 }), "/b")).toBe(FIRST_QID_PATH + 1n);
  });

  it("keys identity on (dev, ino), not on ino alone", () => {
    const table = new FidTable();
    // Two devices, one inode number: a real possibility for any driver spanning
    // a mount, and v9fs would serve one file's cached pages for the other.
    const one = table.qidPathFor(stats({ dev: 1, ino: 5 }), "/one");
    const two = table.qidPathFor(stats({ dev: 2, ino: 5 }), "/two");
    expect(one).not.toBe(two);
    // The same pair under two names is one file — that is what a hardlink is.
    expect(table.qidPathFor(stats({ dev: 1, ino: 5 }), "/link")).toBe(one);
  });

  it("cannot be aliased by an out-of-range ino", () => {
    // 2^53 is the last exactly representable integer, not the value ceiling: a
    // driver may report far more, and no fixed base can fence it off.
    const table = new FidTable();
    const huge = table.qidPathFor(stats({ ino: 2 ** 63 }), "/huge");
    const plain = table.qidPathFor(stats(), "/plain");
    const later = table.qidPathFor(stats({ ino: 3 }), "/later");
    expect(new Set([huge, plain, later]).size).toBe(3);
    for (const id of [huge, plain, later]) {
      expect(id).toBeLessThan(1n << 64n);
    }
  });

  it("answers the same qid path for the same path, every time", () => {
    const table = new FidTable();
    const first = table.qidPathFor(stats(), "/a/b");
    expect(table.qidPathFor(stats({ mtimeMs: 99 }), "/a/b")).toBe(first);
    expect(table.qidPathFor(stats(), "/a/b")).toBe(first);
  });

  it("gives a path a new identity when the file under it was replaced", () => {
    const table = new FidTable();
    const before = table.qidPathFor(stats({ ino: 5 }), "/a");
    expect(table.qidPathFor(stats({ ino: 6 }), "/a")).not.toBe(before);
  });

  it("identifies per path when `useDriverIno` is off", () => {
    const table = new FidTable({ useDriverIno: false });
    expect(table.qidPathFor(stats({ ino: 4242 }), "/a")).toBe(FIRST_QID_PATH);
    // The ino is ignored entirely, in both directions: a changed one does not
    // re-identify the path, and a shared one does not merge two paths.
    expect(table.qidPathFor(stats({ ino: 4243 }), "/a")).toBe(FIRST_QID_PATH);
    expect(table.qidPathFor(stats({ ino: 4242 }), "/b")).toBe(FIRST_QID_PATH + 1n);
  });

  it("carries an identity across a rename", () => {
    const table = new FidTable();
    const dir = table.qidPathFor(stats({ mode: S_IFDIR | 0o755 }), "/a");
    const child = table.qidPathFor(stats(), "/a/b");
    const sibling = table.qidPathFor(stats(), "/ab");

    table.remap("/a", "/z");

    // The client keeps its dentries, so the file at the new name must still be
    // the same file to it.
    expect(table.qidPathFor(stats({ mode: S_IFDIR | 0o755 }), "/z")).toBe(dir);
    expect(table.qidPathFor(stats(), "/z/b")).toBe(child);
    expect(table.qidPathFor(stats(), "/ab")).toBe(sibling);
    // And the old names are gone, so a file created there gets a fresh one.
    expect(table.qidPathFor(stats(), "/a")).not.toBe(dir);
  });

  it("drops the identity of whatever the rename replaced", () => {
    const table = new FidTable();
    const doomed = table.qidPathFor(stats(), "/dest");
    const mover = table.qidPathFor(stats(), "/src");
    table.remap("/src", "/dest");
    expect(table.qidPathFor(stats(), "/dest")).toBe(mover);
    expect(table.qidPathFor(stats(), "/dest")).not.toBe(doomed);
  });
});

describe("FidTable.release", () => {
  it("gives a recreated path a new identity", () => {
    const table = new FidTable();
    const before = table.qidPathFor(stats({ ino: 5 }), "/a");
    table.release("/a");
    // A real filesystem hands the deleted file's ino to the next one created,
    // so even the identical `(dev, ino)` must not resurrect the old qid.
    expect(table.qidPathFor(stats({ ino: 5 }), "/a")).not.toBe(before);
  });

  it("does not grow the memo across remove cycles", () => {
    const table = new FidTable();
    for (let cycle = 0; cycle < 1000; cycle++) {
      table.qidPathFor(stats({ ino: cycle + 1 }), "/tmp/scratch");
      table.release("/tmp/scratch");
    }
    expect(table.qidPathCount).toBe(0);
  });

  it("keeps a hardlinked file's identity until its last name goes", () => {
    const table = new FidTable();
    const id = table.qidPathFor(stats({ ino: 5 }), "/a");
    expect(table.qidPathFor(stats({ ino: 5 }), "/b")).toBe(id);

    table.release("/a");
    expect(table.qidPathFor(stats({ ino: 5 }), "/b")).toBe(id);
    // ...and the surviving name can still lend it to a new link.
    expect(table.qidPathFor(stats({ ino: 5 }), "/c")).toBe(id);

    table.release("/b");
    table.release("/c");
    expect(table.qidPathFor(stats({ ino: 5 }), "/b")).not.toBe(id);
  });

  it("ignores a path it never identified", () => {
    const table = new FidTable();
    expect(() => table.release("/nothing")).not.toThrow();
    expect(table.qidPathCount).toBe(0);
  });
});

describe("FidTable.clear", () => {
  it("drops the fids and the qid identities, and never rewinds the counter", () => {
    const table = new FidTable();
    table.create(1, "/a");
    const first = table.qidPathFor(stats(), "/a");
    expect(table.qidPathCount).toBe(1);

    table.clear();

    expect(table.size).toBe(0);
    expect(table.qidPathCount).toBe(0);
    // The same path, re-identified — but never with a number already handed out.
    expect(table.qidPathFor(stats(), "/a")).toBe(first + 1n);
  });
});
