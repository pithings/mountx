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
import { constants as osConstants } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ErrnoCode } from "../src/errors.ts";
import { ERRNO_CODES } from "../src/errors.ts";
import type { Loopback, ResolvedCapabilities } from "../src/harness.ts";
import type { MountxExtensions } from "../src/types.ts";
import { S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFMT, S_IFREG, S_IFSOCK } from "../src/types.ts";

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
  /**
   * Where this target's errors come from, which decides how exactly the numbers
   * and codes below can be pinned down.
   *
   * - `"linux"` (the default) — the target carries `src/errors.ts`'s
   *   transcribed table and answers identically on every host, so both the code
   *   and the number are exact.
   * - `"host"` — the target forwards errors the host kernel raised. On Linux
   *   that is the same thing; on darwin it is not (`ENOTEMPTY` is 66 rather
   *   than 39, `ELOOP` 62 rather than 40) and the number is accepted as either.
   *   Not a weakening of the interesting assertion: a driver like `node-fs`
   *   resolves some path components itself — those errors come from the
   *   transcribed table — and forwards the rest, so on a non-Linux host it is
   *   genuinely a mixture, and the *code* is what the transports and the tests
   *   downstream of them rely on.
   */
  errors?: "linux" | "host";
  /**
   * What this target carries of an extension it *has* — narrower than the
   * presence of the call, and unset when the two are the same thing.
   *
   * `capabilities.extensions` answers "can this target be asked at all", which
   * is the only question a driver has. A transport column has a second one: a
   * wire can have the operation and still not carry every argument to it. The
   * `mknod` case is the whole reason this field exists — NFSv3 and NFSv4.1 put
   * the file type in `ftype3`/`nfs_ftype4`, a four-member enum, so the `mode`'s
   * `S_IFMT` never reaches the driver and a type outside those four cannot be
   * asked for, let alone refused by whoever should refuse it.
   *
   * Declared-or-inferred, as capabilities are: unset means the extension is
   * carried whole, so every target that had one before this field existed still
   * claims what it always did, and a column that carries less says so in the one
   * place its other losses are already declared.
   */
  carries?: readonly Carried[];
}

const decoder = new TextDecoder();

/** Only root may give a file away, so the tests that do are gated on it. */
const isRoot = (process.getuid?.() ?? -1) === 0;
/** `nobody`, by convention. Any uid that is not the one running the suite would do. */
const NOBODY_UID = 65_534;
const NOBODY_GID = 65_534;

/** The host kernel's own numbers, for a target that forwards its errors. */
const HOST_ERRNO = osConstants.errno as Record<string, number | undefined>;

/** Assert a call rejects the way `node:fs` rejects a bad offset/length/position. */
async function rejectsRange(promise: Promise<unknown>): Promise<void> {
  await expect(promise).rejects.toMatchObject({ code: "ERR_OUT_OF_RANGE" });
}

/**
 * A part of an extension a target may carry or not, having the call either
 * way — see {@link ConformanceTarget.carries}.
 *
 * One member, and it is deliberately about an *argument* rather than about an
 * operation: `mknod`'s `mode` naming a type outside the four a device-ish enum
 * can spell. A case gated on this is one whose answer has to come from the
 * driver, and a wire that cannot ask the question cannot carry the answer back
 * either — which is why the alternative to skipping is a client inventing an
 * errno, and that is the thing invariant 5 forbids.
 */
export type Carried = "mknod.anyType";

/** Every {@link Carried} member, for the matrix's benefit. */
export const CARRIED: readonly Carried[] = ["mknod.anyType"];

/**
 * Something a case needs before it can mean anything: a capability, root, one
 * named member of the `mountx.*` extension namespace, or one {@link Carried}
 * part of such a member.
 *
 * The extensions are spelled `mountx.<name>` rather than folded into
 * `capabilities`, because `extensions` is a *list* — `capabilities.extensions`
 * is never `true`, so a case gated on it alone would skip everywhere and say
 * nothing about which extension it wanted.
 */
export type Requirement =
  | Exclude<keyof ResolvedCapabilities, "extensions">
  | "root"
  | `mountx.${keyof MountxExtensions}`
  | Carried;

const EXTENSION_PREFIX = "mountx.";

/** The `[needs …]` marker appended to every gated case name. */
export const REQUIREMENT_TAG = /\s\[needs ([^\]]+)]$/;

export function conformance(target: ConformanceTarget): void {
  const { capabilities } = target;
  const hostErrors = target.errors === "host";

  /**
   * The {@link Carried} parts this target has, inferred when it does not say.
   *
   * An extension declared and nothing else said is an extension carried whole:
   * that is what every target meant before `carries` existed, and it keeps the
   * narrowing where the transport that needs it can explain itself.
   */
  const carried: readonly Carried[] =
    target.carries ?? (capabilities.extensions.includes("mknod") ? ["mknod.anyType"] : []);

  /** Every `errno` this target is allowed to report for `code`. */
  const errnosFor = (code: ErrnoCode): number[] => {
    const linux = -ERRNO_CODES[code];
    const host = HOST_ERRNO[code];
    return !hostErrors || host === undefined || -host === linux ? [linux] : [linux, -host];
  };

  /** Assert a call rejects with the `node:fs` error shape for `code`. */
  const rejects = async (promise: Promise<unknown>, code: ErrnoCode): Promise<void> => {
    const error = (await promise.then(
      () => undefined,
      (reason: unknown) => reason,
    )) as { errno?: number } | undefined;
    if (error === undefined) {
      expect.fail(`expected a rejection with code ${code}, but the call resolved`);
    }
    expect(error).toMatchObject({ code });
    expect(errnosFor(code)).toContain(error.errno);
  };

  /**
   * `unlink` of a directory. POSIX permits either answer and the two families
   * differ: Linux says `EISDIR`, the BSDs (darwin included) say `EPERM`. Only a
   * host-backed target can disagree with Linux here — one carrying the
   * transcribed table answers `EISDIR` everywhere and is held to it.
   */
  const unlinkDirCode: ErrnoCode = hostErrors && process.platform !== "linux" ? "EPERM" : "EISDIR";

  /**
   * `it` / `describe` for a case that only means something when the target has
   * what it names: skipped without it, and **tagged with it either way**.
   *
   * The tag is not decoration. A skipped test leaves nothing behind but its
   * name — vitest reports it as `pending`, with no reason attached — so the
   * name is the only place the reason can live if the conformance matrix is to
   * say *why* a cell is a skip rather than merely that it is (`pnpm matrix`,
   * `.agents/conformance-matrix.md`). Declaring the requirement and the skip in
   * one call is what keeps the two from drifting apart.
   */
  const met = (requirement: Requirement): boolean => {
    if (requirement === "root") {
      return isRoot;
    }
    if (CARRIED.includes(requirement as Carried)) {
      return carried.includes(requirement as Carried);
    }
    if (requirement.startsWith(EXTENSION_PREFIX)) {
      const name = requirement.slice(EXTENSION_PREFIX.length) as keyof MountxExtensions;
      return capabilities.extensions.includes(name);
    }
    return capabilities[requirement as Exclude<keyof ResolvedCapabilities, "extensions">] === true;
  };
  const tag = (requirements: readonly Requirement[]): string =>
    ` [needs ${requirements.join(" + ")}]`;
  const itNeeds =
    (...requirements: Requirement[]) =>
    (name: string, fn: () => Promise<void>): void => {
      it.skipIf(!requirements.every(met))(name + tag(requirements), fn);
    };
  const describeNeeds =
    (...requirements: Requirement[]) =>
    (name: string, fn: () => void): void => {
      describe.skipIf(!requirements.every(met))(name + tag(requirements), fn);
    };

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

      itNeeds("symlinks")(
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

      itNeeds("statfs")("reports filesystem statistics", async () => {
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
        await rejects(fs.unlink("/dir"), unlinkDirCode);
        await rejects(fs.unlink("/nope"), "ENOENT");
      });

      itNeeds("handles")("keeps an open handle readable after unlink", async () => {
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

      itNeeds("handles")("keeps an open file attached across rename", async () => {
        await fs.writeFile("/from", "aaaa");
        const handle = await fs.open("/from", "r+");
        await handle.write(new TextEncoder().encode("bb"), 0, 2, 0);
        await fs.rename("/from", "/to");
        await handle.write(new TextEncoder().encode("cc"), 0, 2, 2);
        await handle.close();

        await rejects(fs.stat("/from"), "ENOENT");
        expect(await read("/to")).toBe("bbcc");
      });

      itNeeds("handles")("keeps an open file attached across ancestor rename", async () => {
        await fs.mkdir("/from");
        await fs.writeFile("/from/file", "aaaa");
        const handle = await fs.open("/from/file", "r+");
        await handle.write(new TextEncoder().encode("bb"), 0, 2, 0);
        await fs.rename("/from", "/to");
        await handle.write(new TextEncoder().encode("cc"), 0, 2, 2);
        await handle.close();

        await rejects(fs.stat("/from"), "ENOENT");
        expect(await read("/to/file")).toBe("bbcc");
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

    describeNeeds("hardlinks")("hard links", () => {
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

    describeNeeds("symlinks")("symlinks", () => {
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

    describeNeeds("mountx.mknod")("special files", () => {
      /**
       * The extension, which the gate above has established this target has.
       *
       * It is reached through `fs.mountx` rather than through a method of its
       * own: `FsDriver` is a subset of `node:fs/promises`, which cannot create
       * a FIFO, a socket or a device node, so this is the one thing a driver
       * says in the extension namespace instead.
       */
      const mknod = (path: string, mode: number, dev = 0): Promise<void> =>
        fs.mountx!.mknod!(path, mode, dev);

      it("creates a FIFO and a socket that stat and readdir both name", async () => {
        await mknod("/fifo", S_IFIFO | 0o644);
        await mknod("/sock", S_IFSOCK | 0o600);

        const fifo = await fs.stat("/fifo");
        expect(fifo.isFIFO()).toBe(true);
        expect(fifo.isFile()).toBe(false);
        expect(fifo.mode & S_IFMT).toBe(S_IFIFO);
        expect(fifo.mode & 0o7777).toBe(0o644);
        expect(fifo.size).toBe(0);

        const sock = await fs.stat("/sock");
        expect(sock.isSocket()).toBe(true);
        expect(sock.mode & S_IFMT).toBe(S_IFSOCK);

        // A dirent decides the same seven predicates off the same one field,
        // and a client that only ever reads the directory must see it too.
        const entries = new Map(
          (await fs.readdir("/", { withFileTypes: true })).map((entry) => [entry.name, entry]),
        );
        expect(entries.get("fifo")?.isFIFO()).toBe(true);
        expect(entries.get("sock")?.isSocket()).toBe(true);
        expect(entries.get("sock")?.isFile()).toBe(false);
      });

      it("carries the device number of a character and a block device", async () => {
        // `/dev/null` and `/dev/loop0`, as good a pair of numbers as any: the
        // point is that `dev` survives, not that these two mean anything here.
        const nullDev = (1 << 8) | 3;
        const loopDev = (7 << 8) | 0;
        await mknod("/char", S_IFCHR | 0o666, nullDev);
        await mknod("/block", S_IFBLK | 0o660, loopDev);

        const character = await fs.stat("/char");
        expect(character.isCharacterDevice()).toBe(true);
        expect(character.rdev).toBe(nullDev);

        const block = await fs.stat("/block");
        expect(block.isBlockDevice()).toBe(true);
        expect(block.rdev).toBe(loopDev);
      });

      itNeeds("mknod.anyType")(
        "creates a regular file from a mode naming one, or naming no type",
        async () => {
          // The fallback every session already has when no driver implements the
          // extension, and which a driver that does implement it must not lose:
          // `mknod(path, S_IFREG)` — and `mknod(path, 0)`, which POSIX reads the
          // same way — is how a few tools still create an empty file.
          await mknod("/plain", 0o644);
          await mknod("/regular", S_IFREG | 0o600);
          expect((await fs.stat("/plain")).isFile()).toBe(true);
          expect((await fs.stat("/regular")).isFile()).toBe(true);
          expect((await fs.stat("/regular")).size).toBe(0);
          expect(await read("/regular")).toBe("");
        },
      );

      it("is an ordinary name once it exists: rename, unlink, stat again", async () => {
        await mknod("/fifo", S_IFIFO | 0o644);
        await fs.rename("/fifo", "/moved");
        await rejects(fs.stat("/fifo"), "ENOENT");
        expect((await fs.stat("/moved")).isFIFO()).toBe(true);
        await fs.unlink("/moved");
        await rejects(fs.stat("/moved"), "ENOENT");
      });

      it("refuses an existing name and a missing directory", async () => {
        await fs.writeFile("/taken", "x");
        await rejects(mknod("/taken", S_IFIFO | 0o644), "EEXIST");
        await rejects(mknod("/nowhere/fifo", S_IFIFO | 0o644), "ENOENT");
      });

      // Split from the two refusals above rather than asserted beside them:
      // those name a FIFO, which every carrier of the extension can ask for,
      // and this one names a type that only a `mode` can express.
      itNeeds("mknod.anyType")("refuses a type with its own call", async () => {
        // `mknod(2)` answers `EPERM` for a directory: `mkdir` is that call, and
        // this one must not become a second way in.
        await rejects(mknod("/dir", S_IFDIR | 0o755), "EPERM");
      });
    });

    describe("metadata", () => {
      itNeeds("permissions")("changes permission bits", async () => {
        await fs.writeFile("/f", "x");
        await fs.chmod("/f", 0o600);
        expect((await fs.stat("/f")).mode & 0o777).toBe(0o600);
        await fs.chmod("/f", 0o644);
        expect((await fs.stat("/f")).mode & 0o777).toBe(0o644);
        await rejects(fs.chmod("/nope", 0o644), "ENOENT");
      });

      itNeeds("permissions")("keeps ownership when set to the current owner", async () => {
        await fs.writeFile("/f", "x");
        const before = await fs.stat("/f");
        await fs.chown("/f", before.uid, before.gid);
        const after = await fs.stat("/f");
        expect(after.uid).toBe(before.uid);
        expect(after.gid).toBe(before.gid);
      });

      itNeeds("times")("sets access and modification times", async () => {
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

      itNeeds("times", "symlinks")("sets times on the symlink itself with lutimes", async () => {
        await fs.writeFile("/target", "x");
        await fs.symlink("target", "/link");
        await fs.utimes("/target", new Date(1000), new Date(1000));
        await fs.lutimes("/link", new Date(9000), new Date(9000));
        expect((await fs.lstat("/link")).mtimeMs).toBe(9000);
        expect((await fs.stat("/target")).mtimeMs).toBe(1000);
      });

      /**
       * Handing ownership *away* is a privileged operation on a real
       * filesystem, so the interesting half of `lchown` can only be checked as
       * root. Everything below the `skipIf` would otherwise degenerate into
       * `chown` to the uid the file already has — an assertion nothing can
       * fail, which is exactly how the symlink-following bug in `SETATTR`
       * survived a green suite.
       */
      itNeeds(
        "permissions",
        "symlinks",
        "root",
      )("changes ownership of the symlink itself with lchown, not of its target", async () => {
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
      });
    });

    describeNeeds("truncate")("truncate", () => {
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
