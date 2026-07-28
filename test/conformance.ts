/**
 * The Tier-0 conformance suite.
 *
 * One suite, written against the driver interface, run against every driver
 * (and against raw `node:fs/promises`, to keep the oracle honest). A driver
 * that passes this behaves like a POSIX filesystem for everything the
 * transports rely on.
 *
 * Not a `*.test.ts` file: it is imported by one.
 */

import { constants } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ErrnoCode } from "../src/errors.ts";
import { ERRNO_CODES } from "../src/errors.ts";
import type { Loopback, ResolvedCapabilities } from "../src/harness.ts";
import { S_IFMT } from "../src/types.ts";

export interface ConformanceTarget {
  /** Name of the driver under test. */
  name: string;
  /**
   * What the driver claims to support, resolved once up front so that a
   * missing capability shows up as a *skipped* test rather than a green one.
   */
  capabilities: ResolvedCapabilities;
  /** Fresh, empty filesystem per test. */
  setup: () => Promise<{ fs: Loopback; cleanup?: () => Promise<void> }>;
}

const decoder = new TextDecoder();

/** Only root may give a file away, so the tests that do are gated on it. */
const isRoot = (process.getuid?.() ?? -1) === 0;
/** `nobody`, by convention. Any uid that is not the one running the suite would do. */
const NOBODY_UID = 65_534;
const NOBODY_GID = 65_534;

/** Assert a call rejects with exactly the `node:fs` error shape for `code`. */
async function rejects(promise: Promise<unknown>, code: ErrnoCode): Promise<void> {
  await expect(promise).rejects.toMatchObject({ code, errno: -ERRNO_CODES[code] });
}

/** Assert a call rejects the way `node:fs` rejects a bad offset/length/position. */
async function rejectsRange(promise: Promise<unknown>): Promise<void> {
  await expect(promise).rejects.toMatchObject({ code: "ERR_OUT_OF_RANGE" });
}

export function conformance(target: ConformanceTarget): void {
  const { capabilities } = target;

  describe(`conformance: ${target.name}`, () => {
    let fs: Loopback;
    let cleanup: (() => Promise<void>) | undefined;

    beforeEach(async () => {
      ({ fs, cleanup } = await target.setup());
    });

    afterEach(async () => {
      await cleanup?.();
    });

    const read = async (path: string): Promise<string> => decoder.decode(await fs.readFile(path));

    describe("files", () => {
      it("creates, writes, reads back and closes", async () => {
        const handle = await fs.open("/hello.txt", "w");
        const { bytesWritten } = await handle.write(new TextEncoder().encode("hello"), 0, 5, 0);
        expect(bytesWritten).toBe(5);
        await handle.close();

        const reader = await fs.open("/hello.txt", "r");
        const buffer = new Uint8Array(16);
        const { bytesRead } = await reader.read(buffer, 0, 16, 0);
        await reader.close();
        expect(bytesRead).toBe(5);
        expect(decoder.decode(buffer.subarray(0, 5))).toBe("hello");
      });

      it("reads and writes at explicit positions", async () => {
        await fs.writeFile("/data", "0123456789");
        const handle = await fs.open("/data", "r+");
        const buffer = new Uint8Array(4);
        expect((await handle.read(buffer, 0, 4, 3)).bytesRead).toBe(4);
        expect(decoder.decode(buffer)).toBe("3456");
        await handle.write(new TextEncoder().encode("ab"), 0, 2, 1);
        await handle.close();
        expect(await read("/data")).toBe("0ab3456789");
      });

      it("advances the implicit position across reads", async () => {
        await fs.writeFile("/data", "abcdef");
        const handle = await fs.open("/data", "r");
        const buffer = new Uint8Array(2);
        await handle.read(buffer, 0, 2);
        expect(decoder.decode(buffer)).toBe("ab");
        await handle.read(buffer, 0, 2);
        expect(decoder.decode(buffer)).toBe("cd");
        await handle.close();
      });

      it("appends at the end in append mode", async () => {
        await fs.writeFile("/log", "one");
        const handle = await fs.open("/log", "a");
        await handle.write(new TextEncoder().encode("-two"), 0, 4, null);
        await handle.close();
        expect(await read("/log")).toBe("one-two");
      });

      it("reads past the end as zero bytes", async () => {
        await fs.writeFile("/short", "abc");
        const handle = await fs.open("/short", "r");
        const { bytesRead } = await handle.read(new Uint8Array(8), 0, 8, 100);
        await handle.close();
        expect(bytesRead).toBe(0);
      });

      it("truncates on open with 'w'", async () => {
        await fs.writeFile("/f", "long content");
        await fs.writeFile("/f", "short");
        expect(await read("/f")).toBe("short");
      });

      it("accepts numeric open flags", async () => {
        const handle = await fs.open("/numeric", constants.O_RDWR | constants.O_CREAT, 0o644);
        await handle.write(new TextEncoder().encode("x"), 0, 1, 0);
        await handle.close();
        expect(await read("/numeric")).toBe("x");
      });

      it("flushes without complaint", async () => {
        const handle = await fs.open("/sync", "w");
        await handle.sync?.();
        await handle.datasync?.();
        await handle.close();
      });

      it("rejects a write to a read-only handle with EBADF", async () => {
        await fs.writeFile("/ro", "x");
        const handle = await fs.open("/ro", "r");
        await rejects(handle.write(new TextEncoder().encode("y"), 0, 1, 0), "EBADF");
        await handle.close();
      });

      it("rejects opening a missing file with ENOENT", async () => {
        await rejects(fs.open("/missing", "r"), "ENOENT");
      });

      it("rejects an exclusive open of an existing file with EEXIST", async () => {
        await fs.writeFile("/exists", "x");
        await rejects(fs.open("/exists", "wx"), "EEXIST");
      });

      it.skipIf(!capabilities.symlinks)(
        "rejects an exclusive open of a symlink, dangling or not, with EEXIST",
        async () => {
          await fs.symlink("nowhere", "/dangling");
          await rejects(fs.open("/dangling", "wx"), "EEXIST");
          // The exclusive open must not have created the target either.
          await rejects(fs.lstat("/nowhere"), "ENOENT");

          await fs.writeFile("/target", "x");
          await fs.symlink("target", "/link");
          await rejects(fs.open("/link", "wx"), "EEXIST");

          // Without O_EXCL the symlink is followed, as usual.
          const handle = await fs.open("/dangling", "w");
          await handle.close();
          expect((await fs.stat("/nowhere")).isFile()).toBe(true);
        },
      );

      it("reports only the bytes it actually copied", async () => {
        await fs.writeFile("/f", "");
        const handle = await fs.open("/f", "r+");
        const written = await handle.write(new Uint8Array([1, 2]), 0, 2, 0);
        expect(written.bytesWritten).toBe(2);
        expect((await handle.stat()).size).toBe(2);

        const buffer = new Uint8Array(8);
        const { bytesRead } = await handle.read(buffer, 0, 8, 0);
        expect(bytesRead).toBe(2);
        expect([...buffer.subarray(0, 4)]).toEqual([1, 2, 0, 0]);
        await handle.close();
      });

      it("rejects out-of-range read and write arguments", async () => {
        await fs.writeFile("/f", "0123456789");
        const handle = await fs.open("/f", "r+");
        const buffer = new Uint8Array(4);

        await rejectsRange(handle.read(buffer, 0, 10, 0));
        await rejectsRange(handle.read(buffer, -1, 2, 0));
        await rejectsRange(handle.read(buffer, 0, -2, 0));
        await rejectsRange(handle.read(buffer, 0, 4, -5));
        await rejectsRange(handle.write(new Uint8Array(2), 0, 10, 0));
        await rejectsRange(handle.write(new Uint8Array(2), 5, 1, 0));
        await rejectsRange(handle.write(new Uint8Array(2), -1, 1, 0));

        // A position of -1 means "wherever the handle is", as in node:fs.
        const { bytesRead } = await handle.read(buffer, 0, 4, -1);
        expect(bytesRead).toBe(4);
        expect(decoder.decode(buffer)).toBe("0123");
        await handle.close();

        // None of the rejected calls touched the file.
        expect(await read("/f")).toBe("0123456789");
      });

      it("rejects a path that traverses a file with ENOTDIR", async () => {
        await fs.writeFile("/file", "x");
        await rejects(fs.open("/file/child", "r"), "ENOTDIR");
        await rejects(fs.stat("/file/child"), "ENOTDIR");
      });

      it("rejects opening a directory for writing with EISDIR", async () => {
        await fs.mkdir("/dir");
        await rejects(fs.open("/dir", "w"), "EISDIR");
      });

      it("rejects reading a directory handle with EISDIR", async () => {
        await fs.mkdir("/dir");
        const handle = await fs.open("/dir", "r");
        await rejects(handle.read(new Uint8Array(4), 0, 4, 0), "EISDIR");
        await handle.close();
      });
    });

    describe("stat", () => {
      it("agrees across stat, lstat and the handle", async () => {
        await fs.writeFile("/f", "12345");
        const stats = await fs.stat("/f");
        const lstats = await fs.lstat("/f");
        const handle = await fs.open("/f", "r");
        const fstats = await handle.stat();
        await handle.close();

        expect(stats.isFile()).toBe(true);
        expect(stats.isDirectory()).toBe(false);
        expect(stats.size).toBe(5);
        expect(stats.ino).toBeGreaterThan(0);
        for (const other of [lstats, fstats]) {
          expect(other.ino).toBe(stats.ino);
          expect(other.size).toBe(stats.size);
          expect(other.mode).toBe(stats.mode);
          expect(other.nlink).toBe(stats.nlink);
        }
      });

      it("reports directories", async () => {
        await fs.mkdir("/dir");
        const stats = await fs.stat("/dir");
        expect(stats.isDirectory()).toBe(true);
        expect(stats.isFile()).toBe(false);
        expect(stats.mode & S_IFMT).toBe(0o040_000);
      });

      it("rejects a missing path with ENOENT", async () => {
        await rejects(fs.stat("/nope"), "ENOENT");
        await rejects(fs.lstat("/nope"), "ENOENT");
      });

      it.skipIf(!capabilities.statfs)("reports filesystem statistics", async () => {
        const stats = await fs.statfs("/");
        expect(stats.bsize).toBeGreaterThan(0);
        expect(stats.blocks).toBeGreaterThan(0);
        expect(stats.bfree).toBeGreaterThanOrEqual(0);
      });
    });

    describe("readdir", () => {
      it("lists an empty root", async () => {
        expect(await fs.readdir("/", { withFileTypes: true })).toEqual([]);
      });

      it("returns entries with file types", async () => {
        await fs.writeFile("/a", "a");
        await fs.mkdir("/b");
        if (capabilities.symlinks) {
          await fs.symlink("a", "/c");
        }
        const entries = await fs.readdir("/", { withFileTypes: true });
        entries.sort((left, right) => left.name.localeCompare(right.name));
        expect(entries.map((entry) => entry.name)).toEqual(
          capabilities.symlinks ? ["a", "b", "c"] : ["a", "b"],
        );
        expect(entries[0]!.isFile()).toBe(true);
        expect(entries[1]!.isDirectory()).toBe(true);
        if (capabilities.symlinks) {
          expect(entries[2]!.isSymbolicLink()).toBe(true);
          expect(entries[2]!.isFile()).toBe(false);
        }
      });

      it("lists a nested directory", async () => {
        await fs.mkdir("/dir");
        await fs.writeFile("/dir/inner", "x");
        const entries = await fs.readdir("/dir", { withFileTypes: true });
        expect(entries.map((entry) => entry.name)).toEqual(["inner"]);
      });

      it("rejects a file with ENOTDIR and a missing path with ENOENT", async () => {
        await fs.writeFile("/f", "x");
        await rejects(fs.readdir("/f", { withFileTypes: true }), "ENOTDIR");
        await rejects(fs.readdir("/nope", { withFileTypes: true }), "ENOENT");
      });
    });

    describe("mkdir / rmdir", () => {
      it("creates and removes a directory", async () => {
        await fs.mkdir("/dir");
        expect((await fs.stat("/dir")).isDirectory()).toBe(true);
        await fs.rmdir("/dir");
        await rejects(fs.stat("/dir"), "ENOENT");
      });

      it("creates parents recursively and is idempotent", async () => {
        await fs.mkdir("/a/b/c", { recursive: true });
        expect((await fs.stat("/a/b/c")).isDirectory()).toBe(true);
        await fs.mkdir("/a/b/c", { recursive: true });
      });

      it("rejects an existing directory with EEXIST", async () => {
        await fs.mkdir("/dir");
        await rejects(fs.mkdir("/dir"), "EEXIST");
        await fs.mkdir("/dir", { recursive: true });
      });

      it("rejects an existing file with EEXIST, recursive or not", async () => {
        await fs.writeFile("/f", "x");
        await rejects(fs.mkdir("/f"), "EEXIST");
        await rejects(fs.mkdir("/f", { recursive: true }), "EEXIST");
      });

      it("rejects a missing parent with ENOENT", async () => {
        await rejects(fs.mkdir("/missing/child"), "ENOENT");
      });

      it("rejects a parent that is a file with ENOTDIR", async () => {
        await fs.writeFile("/f", "x");
        await rejects(fs.mkdir("/f/child"), "ENOTDIR");
        await rejects(fs.mkdir("/f/child", { recursive: true }), "ENOTDIR");
      });

      it("rejects rmdir of a non-empty directory with ENOTEMPTY", async () => {
        await fs.mkdir("/dir");
        await fs.writeFile("/dir/child", "x");
        await rejects(fs.rmdir("/dir"), "ENOTEMPTY");
      });

      it("rejects rmdir of a file with ENOTDIR and of nothing with ENOENT", async () => {
        await fs.writeFile("/f", "x");
        await rejects(fs.rmdir("/f"), "ENOTDIR");
        await rejects(fs.rmdir("/nope"), "ENOENT");
      });
    });

    describe("unlink", () => {
      it("removes a file", async () => {
        await fs.writeFile("/f", "x");
        await fs.unlink("/f");
        await rejects(fs.stat("/f"), "ENOENT");
      });

      it("rejects a directory with EISDIR and a missing file with ENOENT", async () => {
        await fs.mkdir("/dir");
        await rejects(fs.unlink("/dir"), "EISDIR");
        await rejects(fs.unlink("/nope"), "ENOENT");
      });

      it.skipIf(!capabilities.handles)("keeps an open handle readable after unlink", async () => {
        await fs.writeFile("/doomed", "still here");
        const handle = await fs.open("/doomed", "r");
        await fs.unlink("/doomed");
        await rejects(fs.stat("/doomed"), "ENOENT");

        const buffer = new Uint8Array(32);
        const { bytesRead } = await handle.read(buffer, 0, 32, 0);
        expect(decoder.decode(buffer.subarray(0, bytesRead))).toBe("still here");
        expect((await handle.stat()).size).toBe(10);
        await handle.close();
      });
    });

    describe("rename", () => {
      it("renames a file", async () => {
        await fs.writeFile("/from", "content");
        await fs.rename("/from", "/to");
        await rejects(fs.stat("/from"), "ENOENT");
        expect(await read("/to")).toBe("content");
      });

      it("replaces an existing destination file", async () => {
        await fs.writeFile("/from", "new");
        await fs.writeFile("/to", "old");
        await fs.rename("/from", "/to");
        expect(await read("/to")).toBe("new");
        expect((await fs.readdir("/", { withFileTypes: true })).length).toBe(1);
      });

      it("moves a whole subtree", async () => {
        await fs.mkdir("/src/deep", { recursive: true });
        await fs.writeFile("/src/deep/file", "payload");
        await fs.mkdir("/dst");
        await fs.rename("/src", "/dst/moved");
        await rejects(fs.stat("/src"), "ENOENT");
        expect(await read("/dst/moved/deep/file")).toBe("payload");
      });

      it("renames a directory onto an empty directory", async () => {
        await fs.mkdir("/a");
        await fs.writeFile("/a/f", "x");
        await fs.mkdir("/b");
        await fs.rename("/a", "/b");
        expect(await read("/b/f")).toBe("x");
      });

      it("rejects a non-empty destination directory with ENOTEMPTY", async () => {
        await fs.mkdir("/a");
        await fs.mkdir("/b");
        await fs.writeFile("/b/f", "x");
        await rejects(fs.rename("/a", "/b"), "ENOTEMPTY");
      });

      it("rejects mismatched types with EISDIR and ENOTDIR", async () => {
        await fs.mkdir("/dir");
        await fs.writeFile("/file", "x");
        await rejects(fs.rename("/file", "/dir"), "EISDIR");
        await rejects(fs.rename("/dir", "/file"), "ENOTDIR");
      });

      it("rejects a missing source with ENOENT", async () => {
        await rejects(fs.rename("/nope", "/other"), "ENOENT");
      });

      it("renames a path onto itself as a no-op", async () => {
        await fs.writeFile("/f", "content");
        await fs.rename("/f", "/f");
        expect(await read("/f")).toBe("content");
      });

      it("rejects moving a directory into itself with EINVAL", async () => {
        await fs.mkdir("/dir/inner", { recursive: true });
        await rejects(fs.rename("/dir", "/dir/inner/self"), "EINVAL");
      });
    });

    describe.skipIf(!capabilities.hardlinks)("hard links", () => {
      it("shares an inode and counts nlink", async () => {
        await fs.writeFile("/original", "shared");
        await fs.link("/original", "/alias");

        const original = await fs.stat("/original");
        const alias = await fs.stat("/alias");
        expect(alias.ino).toBe(original.ino);
        expect(alias.nlink).toBe(2);
        expect(await read("/alias")).toBe("shared");

        await fs.writeFile("/original", "updated");
        expect(await read("/alias")).toBe("updated");

        await fs.unlink("/original");
        expect((await fs.stat("/alias")).nlink).toBe(1);
        expect(await read("/alias")).toBe("updated");
      });

      it("rejects an existing destination with EEXIST", async () => {
        await fs.writeFile("/a", "a");
        await fs.writeFile("/b", "b");
        await rejects(fs.link("/a", "/b"), "EEXIST");
      });

      it("rejects linking a directory with EPERM and a missing source with ENOENT", async () => {
        await fs.mkdir("/dir");
        await rejects(fs.link("/dir", "/dirlink"), "EPERM");
        await rejects(fs.link("/nope", "/other"), "ENOENT");
      });
    });

    describe.skipIf(!capabilities.symlinks)("symlinks", () => {
      it("round-trips through readlink and distinguishes lstat from stat", async () => {
        await fs.writeFile("/target", "payload");
        await fs.symlink("target", "/link");

        expect(await fs.readlink("/link")).toBe("target");
        const lstats = await fs.lstat("/link");
        const stats = await fs.stat("/link");
        expect(lstats.isSymbolicLink()).toBe(true);
        expect(lstats.isFile()).toBe(false);
        expect(stats.isSymbolicLink()).toBe(false);
        expect(stats.isFile()).toBe(true);
        expect(stats.ino).toBe((await fs.stat("/target")).ino);
        expect(await read("/link")).toBe("payload");
      });

      it("resolves symlinked directories as path components", async () => {
        await fs.mkdir("/real");
        await fs.writeFile("/real/file", "inside");
        await fs.symlink("real", "/alias");
        expect(await read("/alias/file")).toBe("inside");
        expect((await fs.readdir("/alias", { withFileTypes: true })).map((e) => e.name)).toEqual([
          "file",
        ]);
      });

      it("keeps dangling symlinks visible to lstat only", async () => {
        await fs.symlink("nowhere", "/dangling");
        expect((await fs.lstat("/dangling")).isSymbolicLink()).toBe(true);
        expect(await fs.readlink("/dangling")).toBe("nowhere");
        await rejects(fs.stat("/dangling"), "ENOENT");
        await fs.unlink("/dangling");
        await rejects(fs.lstat("/dangling"), "ENOENT");
      });

      it("rejects symlink loops with ELOOP", async () => {
        await fs.symlink("loop-b", "/loop-a");
        await fs.symlink("loop-a", "/loop-b");
        await rejects(fs.stat("/loop-a"), "ELOOP");
      });

      it("rejects readlink of a regular file with EINVAL", async () => {
        await fs.writeFile("/f", "x");
        await rejects(fs.readlink("/f"), "EINVAL");
        await rejects(fs.readlink("/nope"), "ENOENT");
      });

      it("sizes a symlink by its target in bytes", async () => {
        await fs.symlink("héllo→ø", "/unicode");
        expect((await fs.lstat("/unicode")).size).toBe(11);
        expect(await fs.readlink("/unicode")).toBe("héllo→ø");
      });

      it("rejects creating a symlink over an existing name with EEXIST", async () => {
        await fs.writeFile("/taken", "x");
        await rejects(fs.symlink("whatever", "/taken"), "EEXIST");
      });
    });

    describe("metadata", () => {
      it.skipIf(!capabilities.permissions)("changes permission bits", async () => {
        await fs.writeFile("/f", "x");
        await fs.chmod("/f", 0o600);
        expect((await fs.stat("/f")).mode & 0o777).toBe(0o600);
        await fs.chmod("/f", 0o644);
        expect((await fs.stat("/f")).mode & 0o777).toBe(0o644);
        await rejects(fs.chmod("/nope", 0o644), "ENOENT");
      });

      it.skipIf(!capabilities.permissions)(
        "keeps ownership when set to the current owner",
        async () => {
          await fs.writeFile("/f", "x");
          const before = await fs.stat("/f");
          await fs.chown("/f", before.uid, before.gid);
          const after = await fs.stat("/f");
          expect(after.uid).toBe(before.uid);
          expect(after.gid).toBe(before.gid);
        },
      );

      it.skipIf(!capabilities.times)("sets access and modification times", async () => {
        await fs.writeFile("/f", "x");
        await fs.utimes("/f", new Date(1000), new Date(2000));
        const stats = await fs.stat("/f");
        expect(stats.atimeMs).toBe(1000);
        expect(stats.mtimeMs).toBe(2000);

        // Numbers are seconds since the epoch, as in `node:fs`.
        await fs.utimes("/f", 5, 6);
        const seconds = await fs.stat("/f");
        expect(seconds.atimeMs).toBe(5000);
        expect(seconds.mtimeMs).toBe(6000);
        await rejects(fs.utimes("/nope", 1, 1), "ENOENT");
      });

      it.skipIf(!capabilities.times || !capabilities.symlinks)(
        "sets times on the symlink itself with lutimes",
        async () => {
          await fs.writeFile("/target", "x");
          await fs.symlink("target", "/link");
          await fs.utimes("/target", new Date(1000), new Date(1000));
          await fs.lutimes("/link", new Date(9000), new Date(9000));
          expect((await fs.lstat("/link")).mtimeMs).toBe(9000);
          expect((await fs.stat("/target")).mtimeMs).toBe(1000);
        },
      );

      /**
       * Handing ownership *away* is a privileged operation on a real
       * filesystem, so the interesting half of `lchown` can only be checked as
       * root. Everything below the `skipIf` would otherwise degenerate into
       * `chown` to the uid the file already has — an assertion nothing can
       * fail, which is exactly how the symlink-following bug in `SETATTR`
       * survived a green suite.
       */
      it.skipIf(!capabilities.permissions || !capabilities.symlinks || !isRoot)(
        "changes ownership of the symlink itself with lchown, not of its target",
        async () => {
          await fs.writeFile("/target", "x");
          await fs.symlink("target", "/link");
          const before = await fs.stat("/target");

          await fs.lchown("/link", NOBODY_UID, NOBODY_GID);
          const link = await fs.lstat("/link");
          expect(link.uid).toBe(NOBODY_UID);
          expect(link.gid).toBe(NOBODY_GID);

          // The whole point of the `l`: the target is untouched.
          const target = await fs.stat("/target");
          expect(target.uid).toBe(before.uid);
          expect(target.gid).toBe(before.gid);

          // And the following variant does reach the target, so the two are
          // demonstrably different calls rather than one aliased twice.
          await fs.chown("/link", NOBODY_UID, NOBODY_GID);
          expect((await fs.stat("/target")).uid).toBe(NOBODY_UID);
        },
      );
    });

    describe.skipIf(!capabilities.truncate)("truncate", () => {
      it("shrinks and grows a file", async () => {
        await fs.writeFile("/f", "0123456789");
        await fs.truncate("/f", 4);
        expect(await read("/f")).toBe("0123");
        expect((await fs.stat("/f")).size).toBe(4);

        await fs.truncate("/f", 6);
        const grown = await fs.readFile("/f");
        expect(grown.length).toBe(6);
        expect([...grown.subarray(4)]).toEqual([0, 0]);

        await fs.truncate("/f");
        expect((await fs.stat("/f")).size).toBe(0);
      });

      it("truncates through a handle", async () => {
        await fs.writeFile("/f", "abcdef");
        const handle = await fs.open("/f", "r+");
        await handle.truncate(3);
        expect((await handle.stat()).size).toBe(3);
        await handle.close();
        expect(await read("/f")).toBe("abc");
      });

      it("rejects a directory with EISDIR and a missing file with ENOENT", async () => {
        await fs.mkdir("/dir");
        await rejects(fs.truncate("/dir", 0), "EISDIR");
        await rejects(fs.truncate("/nope", 0), "ENOENT");
      });
    });
  });
}
