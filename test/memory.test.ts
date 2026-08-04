import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import { createLoopback } from "../src/harness.ts";
import { S_IFCHR, S_IFIFO, S_IFSOCK } from "../src/types.ts";
import { Rng } from "./fuse/random.ts";

describe("memory driver", () => {
  it("applies umask and ownership options", async () => {
    const fs = createLoopback(createMemoryDriver({ uid: 501, gid: 20, umask: 0o077 }));
    await fs.mkdir("/dir");
    await fs.writeFile("/file", "x");
    const dir = await fs.stat("/dir");
    const file = await fs.stat("/file");
    expect(dir.mode & 0o777).toBe(0o700);
    expect(file.mode & 0o777).toBe(0o600);
    expect(file.uid).toBe(501);
    expect(file.gid).toBe(20);
  });

  it("applies no umask unless one is asked for", async () => {
    // The default is `0`, and that is a decision rather than an oversight: a
    // umask belongs to a process, and under a mount the kernel has already
    // applied the *caller's* before the mode reaches `FUSE_MKDIR`/`FUSE_CREATE`.
    // Masking again used the daemon's value and produced modes nobody asked
    // for — `create f 04777` arriving as `04755` (pjdfstest `chmod/12.t`).
    const fs = createLoopback(createMemoryDriver());
    await fs.mkdir("/dir", { mode: 0o755 });
    await fs.mkdir("/wide", { mode: 0o777 });
    const handle = await fs.open("/file", "w", 0o666);
    await handle.close();
    expect((await fs.stat("/dir")).mode & 0o777).toBe(0o755);
    expect((await fs.stat("/wide")).mode & 0o777).toBe(0o777);
    expect((await fs.stat("/file")).mode & 0o777).toBe(0o666);
  });

  it("rejects a file larger than memory with EFBIG, not EIO", async () => {
    // `new Uint8Array(1e15)` throws a `RangeError`, which a transport can only
    // turn into `EIO` — an errno that tells the caller nothing. Every
    // filesystem has a maximum file size and says `EFBIG` past it.
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/f", "x");
    await expect(fs.truncate("/f", 1e15)).rejects.toMatchObject({ code: "EFBIG" });
    const handle = await fs.open("/f", "r+");
    await expect(handle.truncate(1e15)).rejects.toMatchObject({ code: "EFBIG" });
    await handle.close();
    // ...and the file it refused to grow is untouched.
    expect((await fs.stat("/f")).size).toBe(1);
  });

  it("counts directory links", async () => {
    const fs = createLoopback(createMemoryDriver());
    expect((await fs.stat("/")).nlink).toBe(2);
    await fs.mkdir("/a");
    await fs.mkdir("/b");
    expect((await fs.stat("/")).nlink).toBe(4);
    await fs.rmdir("/b");
    expect((await fs.stat("/")).nlink).toBe(3);
  });

  it("keeps the directory link count in step with the tree it counts", async () => {
    // `nlinkOf` stopped scanning a directory's children per `stat` and started
    // keeping a running total, which is only right if every path that moves a
    // directory in or out of a parent maintains it — `rename` most of all,
    // since it is the one that deletes from a child map without going through
    // `unlinkEntry`. So: random operations, and after each one the counter is
    // checked against the scan it replaced, for every directory in the tree.
    const fs = createLoopback(createMemoryDriver());
    const rng = new Rng(0x6e_6c_69_6e);
    const names = ["a", "b", "c", "d"];
    const paths = ["/", "/a", "/b", "/a/c", "/a/d", "/b/c", "/b/c/d"];
    const pick = <T>(from: readonly T[]): T => from[rng.int(from.length)]!;

    const scan = async (dir: string): Promise<void> => {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      const subdirs = entries.filter((entry) => entry.isDirectory());
      expect((await fs.stat(dir)).nlink).toBe(2 + subdirs.length);
      for (const entry of subdirs) {
        await scan(dir === "/" ? `/${entry.name}` : `${dir}/${entry.name}`);
      }
    };

    for (let step = 0; step < 400; step++) {
      const path = pick(paths);
      const other = `${pick(paths)}/${pick(names)}`;
      // Most of these fail — ENOENT, EEXIST, ENOTEMPTY, EINVAL for a rename
      // into its own subtree — and a failed operation must not move the count
      // either, so they are as much of the test as the ones that land.
      try {
        switch (rng.int(6)) {
          case 0: {
            await fs.mkdir(path);
            break;
          }
          case 1: {
            await fs.rmdir(path);
            break;
          }
          case 2: {
            await fs.writeFile(path, "x");
            break;
          }
          case 3: {
            await fs.unlink(path);
            break;
          }
          case 4: {
            await fs.symlink("/a", path);
            break;
          }
          default: {
            await fs.rename(path, other);
          }
        }
      } catch {
        // Expected for most steps; the invariant below is what is under test.
      }
      await scan("/");
    }
  });

  // --- path resolution ---
  //
  // All of these ask one question: can a path resolve to something the tree no
  // longer says it names? They exist because `walk` is where every optimization
  // of this driver has wanted to go — it scans the path string rather than
  // splitting it, and a *cache* keyed on the parent directory was written and
  // measured on top of that (see `walk`'s comment for why it did not stay).
  //
  // What made them necessary is worth recording: with that cache in place and
  // both of its invalidation points deleted outright, the entire repository
  // stayed green — this file, `test/conformance.ts` and every transport suite,
  // 3,270 tests. Nothing here reached a path whose prefix had moved. So these
  // are not redundant with the suites above them, and a future attempt at the
  // same optimization should be run against them first.

  it("does not resolve a renamed directory under its old name, however deep", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.mkdir("/a/b/c/d", { recursive: true });
    await fs.writeFile("/a/b/c/d/f", "one");
    // Resolve it once first: anything that remembers a prefix remembers it here.
    expect(new TextDecoder().decode(await fs.readFile("/a/b/c/d/f"))).toBe("one");

    await fs.rename("/a/b", "/a/z");
    // The old name resolves to nothing at all — not to the subtree it used to
    // reach — and the new one reaches every level of it.
    await expect(fs.stat("/a/b/c/d/f")).rejects.toMatchObject({ code: "ENOENT" });
    await expect(fs.stat("/a/b/c/d")).rejects.toMatchObject({ code: "ENOENT" });
    expect(new TextDecoder().decode(await fs.readFile("/a/z/c/d/f"))).toBe("one");

    // ...and a write through the old name must not land in the detached node.
    await expect(fs.writeFile("/a/b/c/d/g", "x")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("does not resolve a directory that was removed and made again", async () => {
    // The nastiest shape this can take: the replacement is a *different* node
    // at the same path, so resolving the old one does not fail — it writes into
    // a directory nothing can reach any more.
    const fs = createLoopback(createMemoryDriver());
    await fs.mkdir("/d/sub", { recursive: true });
    await fs.writeFile("/d/sub/f", "one");
    await fs.unlink("/d/sub/f");
    await fs.rmdir("/d/sub");
    await fs.mkdir("/d/sub");

    await fs.writeFile("/d/sub/f", "two");
    expect((await fs.readdir("/d/sub", { withFileTypes: true })).map((e) => e.name)).toEqual(["f"]);
    expect(new TextDecoder().decode(await fs.readFile("/d/sub/f"))).toBe("two");
  });

  it("says ENOTDIR through a directory that a file has replaced", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.mkdir("/d/sub", { recursive: true });
    await fs.writeFile("/d/sub/f", "one");
    await fs.unlink("/d/sub/f");
    await fs.rmdir("/d/sub");
    await fs.writeFile("/d/sub", "now a file");
    // `ENOTDIR`, not the `ENOENT` a remembered directory node would answer.
    await expect(fs.stat("/d/sub/f")).rejects.toMatchObject({ code: "ENOTDIR" });
  });

  it("does not resolve a path through a symlink that has been repointed", async () => {
    // `walk` restarts on a rewritten path the moment a prefix component is a
    // symlink, so the second half of a path is re-resolved from the target
    // every time. This is the arithmetic that splices the two halves together.
    const fs = createLoopback(createMemoryDriver());
    await fs.mkdir("/one/deep", { recursive: true });
    await fs.mkdir("/two/deep", { recursive: true });
    await fs.writeFile("/one/deep/f", "one");
    await fs.writeFile("/two/deep/f", "two");
    await fs.symlink("/one", "/link");
    expect(new TextDecoder().decode(await fs.readFile("/link/deep/f"))).toBe("one");

    await fs.unlink("/link");
    await fs.symlink("/two", "/link");
    expect(new TextDecoder().decode(await fs.readFile("/link/deep/f"))).toBe("two");

    // ...and the same when the *target* directory moves out from under it.
    await fs.rename("/two/deep", "/two/moved");
    await expect(fs.stat("/link/deep/f")).rejects.toMatchObject({ code: "ENOENT" });
    expect(new TextDecoder().decode(await fs.readFile("/link/moved/f"))).toBe("two");
  });

  it("keeps hard links to one node reachable under every name after a rename", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.mkdir("/a/b", { recursive: true });
    await fs.writeFile("/a/b/f", "one");
    await fs.link("/a/b/f", "/a/b/g");
    await fs.link("/a/b/f", "/elsewhere");
    const ino = (await fs.stat("/a/b/f")).ino;

    await fs.rename("/a/b", "/a/c");
    expect((await fs.stat("/a/c/f")).ino).toBe(ino);
    expect((await fs.stat("/a/c/g")).ino).toBe(ino);
    expect((await fs.stat("/elsewhere")).ino).toBe(ino);
    expect((await fs.stat("/elsewhere")).nlink).toBe(3);
    await expect(fs.stat("/a/b/g")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("tells two directories apart by case, and clamps `..` at the root", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.mkdir("/Dir");
    await fs.mkdir("/dir");
    await fs.writeFile("/Dir/f", "upper");
    await fs.writeFile("/dir/f", "lower");
    expect(new TextDecoder().decode(await fs.readFile("/Dir/f"))).toBe("upper");
    expect(new TextDecoder().decode(await fs.readFile("/dir/f"))).toBe("lower");

    // A `..` path is not in normalized form, so it takes the walk — and both
    // routes have to agree, including where `..` runs out of tree.
    expect(new TextDecoder().decode(await fs.readFile("/dir/../Dir/f"))).toBe("upper");
    expect((await fs.stat("/Dir/../../../dir")).ino).toBe((await fs.stat("/dir")).ino);
    expect((await fs.stat("/dir/..")).ino).toBe((await fs.stat("/")).ino);
  });

  it("resolves the earliest of thousands of directories after all the rest", async () => {
    // A wide root rather than a deep one: whatever `walk` remembers between
    // calls, this asks for the earliest paths again after thousands of others
    // have been resolved in between.
    const fs = createLoopback(createMemoryDriver());
    const count = 5000;
    for (let index = 0; index < count; index += 1) {
      await fs.mkdir(`/d-${index}`);
      await fs.writeFile(`/d-${index}/f`, String(index));
    }
    for (const index of [0, 1, 2, count - 2, count - 1]) {
      expect(new TextDecoder().decode(await fs.readFile(`/d-${index}/f`))).toBe(String(index));
    }
  });

  it("resolves a path the same way whichever form it arrives in", async () => {
    // Random mutations with a check after each, in the shape of the `nlink`
    // test above. Every path is asked for twice: once already normalized, which
    // is the form `walk` scans straight through, and once written so that it is
    // not (`//./a/./b`) and has to be normalized first. The two must agree on
    // the node *and* on the errno, after every step.
    //
    // Two details are what give it teeth, and both were found by breaking the
    // driver on purpose and watching an earlier version of this pass anyway:
    //
    // - It drives the **driver**, not `createLoopback`. The harness normalizes
    //   every path before the driver sees one, so through it the long way round
    //   arrives as the short way round and both routes are the same route.
    // - The two passes are separate loops, not one interleaved loop. Anything
    //   `walk` might remember, the second pass would refresh — so all the
    //   short-form answers are taken before any long-form one is.
    //
    // Against the parent cache `walk` was measured with and did not keep, this
    // found a stale entry within ~140 steps on every seed tried.
    const driver = createMemoryDriver();
    const rng = new Rng(0x70_61_72_65);
    const names = ["a", "b", "c", "z"];
    const paths = ["/a", "/z", "/a/b", "/a/b/c", "/z/c", "/a/c/b", "/z/a/c/b"];
    const pick = <T>(from: readonly T[]): T => from[rng.int(from.length)]!;
    const outcome = async (path: string): Promise<string> => {
      try {
        const stats = await driver.lstat(path);
        return `ino ${stats.ino} mode ${stats.mode.toString(8)}`;
      } catch (error) {
        return `error ${(error as { code?: string }).code}`;
      }
    };
    // `//./a/./b` normalizes to `/a/b`, and `isNormalizedPath` refuses it — so
    // it is the same path, obliged to take the walk.
    const theLongWay = (path: string): string => `/${path.replaceAll("/", "/./")}`;

    for (let step = 0; step < 500; step += 1) {
      const path = pick(paths);
      // Sometimes a top-level destination, so that a *non-empty* directory gets
      // renamed out from under a remembered path — the one shape that leaves a
      // stale entry holding children rather than merely holding nothing.
      const other = rng.int(2) === 0 ? `/${pick(names)}` : `${pick(paths)}/${pick(names)}`;
      try {
        switch (rng.int(7)) {
          case 0: {
            await driver.mkdir(path, { recursive: true });
            break;
          }
          case 1: {
            await driver.rmdir(path);
            break;
          }
          case 2: {
            await (await driver.open(path, "w", 0o666)).close();
            break;
          }
          case 3: {
            await driver.unlink(path);
            break;
          }
          case 4: {
            await driver.symlink(pick(paths), path);
            break;
          }
          case 5: {
            await driver.link(path, other);
            break;
          }
          default: {
            await driver.rename(path, other);
          }
        }
      } catch {
        // Most steps fail, and a failed one must not move the map either.
      }
      const cached: string[] = [];
      for (const candidate of paths) {
        cached.push(await outcome(candidate));
      }
      const walked: string[] = [];
      for (const candidate of paths) {
        walked.push(await outcome(theLongWay(candidate)));
      }
      expect([step, ...cached]).toEqual([step, ...walked]);
    }
  });

  it("accounts for used blocks in statfs", async () => {
    const fs = createLoopback(createMemoryDriver());
    const before = await fs.statfs("/");
    await fs.writeFile("/file", "x".repeat(64 * 1024));
    const after = await fs.statfs("/");
    expect(before.bfree - after.bfree).toBe(16);
    expect(after.ffree).toBe(before.ffree - 1);
  });

  it("keeps the statfs totals in step with every mutation", async () => {
    // `statfs` answers from running counters rather than a whole-tree walk, so
    // the risk moved from cost to drift: every path that adds a node, drops the
    // last entry naming one, or changes a file's length has to be accounted
    // for. Each step below is checked against what the walk would have said.
    const fs = createLoopback(createMemoryDriver());
    const used = async (): Promise<{ blocks: number; nodes: number }> => {
      const stats = await fs.statfs("/");
      return { blocks: stats.blocks - stats.bfree, nodes: stats.files - stats.ffree };
    };
    // The root: one node, one block.
    expect(await used()).toEqual({ blocks: 1, nodes: 1 });

    await fs.mkdir("/d");
    await fs.writeFile("/d/f", "x".repeat(8192));
    expect(await used()).toEqual({ blocks: 4, nodes: 3 });

    // Shrinking gives the blocks back; growing through a handle takes them.
    await fs.truncate("/d/f", 0);
    expect(await used()).toEqual({ blocks: 2, nodes: 3 });
    const handle = await fs.open("/d/f", "r+");
    await handle.write(new Uint8Array(4096), 0, 4096, 0);
    expect(await used()).toEqual({ blocks: 3, nodes: 3 });

    // A second link is not a second node, and dropping one of two frees nothing.
    await fs.link("/d/f", "/hard");
    expect(await used()).toEqual({ blocks: 3, nodes: 3 });
    await fs.unlink("/hard");
    expect(await used()).toEqual({ blocks: 3, nodes: 3 });

    // Unlinked but still open: gone from the tree, so gone from `statfs` —
    // which is exactly what walking the tree from the root answered too.
    await fs.unlink("/d/f");
    expect(await used()).toEqual({ blocks: 2, nodes: 2 });
    await handle.truncate(1_000_000);
    expect(await used()).toEqual({ blocks: 2, nodes: 2 });
    await handle.close();

    // Renaming moves a node without creating one; renaming *over* one frees it.
    await fs.writeFile("/a", "aa");
    await fs.writeFile("/b", "bb");
    expect(await used()).toEqual({ blocks: 4, nodes: 4 });
    await fs.rename("/a", "/b");
    expect(await used()).toEqual({ blocks: 3, nodes: 3 });

    await fs.unlink("/b");
    await fs.rmdir("/d");
    expect(await used()).toEqual({ blocks: 1, nodes: 1 });
  });

  it("rejects invalid open flags and removing the root", async () => {
    const fs = createLoopback(createMemoryDriver());
    await expect(fs.open("/f", "nonsense")).rejects.toMatchObject({ code: "EINVAL" });
    await expect(fs.rmdir("/")).rejects.toMatchObject({ code: "EBUSY" });
  });

  it("rejects an inherited property as open flags", async () => {
    // The flag table was an object literal, so `"toString"` resolved to a
    // *function* off `Object.prototype` and `"__proto__"` to the prototype
    // itself — neither `undefined`, so neither was rejected. The handle that
    // came back had `read`/`write`/`create` all `undefined` and answered
    // `EBADF` to everything instead of the open failing.
    const fs = createLoopback(createMemoryDriver());
    for (const flags of ["toString", "__proto__", "constructor", "hasOwnProperty", "valueOf"]) {
      await expect(fs.open("/f", flags)).rejects.toMatchObject({ code: "EINVAL" });
    }
  });

  it("rejects an empty symlink target instead of aliasing the parent", async () => {
    // POSIX has no empty pathname; `symlink(2)` rejects it in `getname()` and
    // `node:fs` answers `ENOENT`. Stored, it collapsed on the walk and made the
    // link a live alias for its own parent directory — `/d/l` listed itself,
    // and a walker descended `/d/l/l/l/...` for 40 levels before `ELOOP`.
    const fs = createLoopback(createMemoryDriver());
    await fs.mkdir("/d");
    await expect(fs.symlink("", "/d/l")).rejects.toMatchObject({ code: "ENOENT" });
    // ...and `ENOENT` beats `EEXIST`, the way `node:fs` orders the two.
    await fs.writeFile("/d/taken", "x");
    await expect(fs.symlink("", "/d/taken")).rejects.toMatchObject({ code: "ENOENT" });
    expect((await fs.readdir("/d", { withFileTypes: true })).map((entry) => entry.name)).toEqual([
      "taken",
    ]);
  });

  it("sizes a symlink target the way TextEncoder would, pair by pair", async () => {
    // `sizeOf` counts UTF-8 bytes without encoding any, so the four widths and
    // the two surrogate cases are checked against the encoder it replaced —
    // the conformance suite's `héllo→ø` reaches 2 and 3 bytes but never a pair.
    const fs = createLoopback(createMemoryDriver());
    const encoder = new TextEncoder();
    const targets = [
      "/plain/ascii",
      "café", // 2 bytes
      "日本語", // 3 bytes
      "🎉🚀", // surrogate pairs, 4 bytes each
      "a🎉b→c", // mixed widths, so a miscounted pair shifts the total
      "\uD83C", // an unpaired high surrogate: `TextEncoder` substitutes U+FFFD
      "\uDC00x", // an unpaired low surrogate
      "\uD83Cx", // a high surrogate followed by something that is not a low one
    ];
    for (const [index, target] of targets.entries()) {
      await fs.symlink(target, `/l-${index}`);
      expect((await fs.lstat(`/l-${index}`)).size).toBe(encoder.encode(target).byteLength);
    }
  });

  it("validates read/write arguments the way node:fs does", async () => {
    // Every case here was run against `node:fs/promises` first; the two agree
    // except where noted.
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/f", "abcdefgh");
    const handle = await fs.open("/f", "r+");
    const buffer = new Uint8Array(4);

    // A zero-length read past the end of the buffer copies nothing and says so.
    // The out-of-range guard was `write`-only, so this fell through to the
    // remaining-bytes bound and compared `0` against a *negative* remainder.
    expect(await handle.read(buffer, 10, 0)).toMatchObject({ bytesRead: 0 });
    expect(await handle.read(buffer, 4, 0)).toMatchObject({ bytesRead: 0 });
    // A non-zero length past the end is still an error, reported against
    // `length` — which is `node:fs`'s own choice of parameter, not a mistake.
    await expect(handle.read(buffer, 10, 1)).rejects.toMatchObject({ code: "ERR_OUT_OF_RANGE" });
    await expect(handle.read(buffer, 10)).rejects.toMatchObject({ code: "ERR_OUT_OF_RANGE" });
    // `write` rejects the offset itself, before any length is considered.
    await expect(handle.write(buffer, 10, 0)).rejects.toMatchObject({
      code: "ERR_OUT_OF_RANGE",
      message: /"offset"/,
    });

    // A fractional position used to be carried straight through, and came back
    // out as a fractional `bytesRead` — `3.5` — which then flows into whatever
    // added it to an offset.
    for (const position of [1.5, -0.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      await expect(handle.read(buffer, 0, 4, position)).rejects.toMatchObject({
        code: "ERR_OUT_OF_RANGE",
        message: /"position"/,
      });
      // `node:fs` does not validate a *write* position at all; this driver
      // does, because a fractional one reaches the resize path.
      await expect(handle.write(buffer, 0, 4, position)).rejects.toMatchObject({
        code: "ERR_OUT_OF_RANGE",
      });
    }
    // ...and the ordinary sentinels still mean "wherever the handle is".
    expect(await handle.read(buffer, 0, 4, -1)).toMatchObject({ bytesRead: 4 });
    expect(await handle.read(buffer, 0, 4, null)).toMatchObject({ bytesRead: 4 });

    // A fractional offset or length is rejected too. `node:fs` agrees on the
    // offset; on the length its JavaScript layer lets one through to a C++
    // `CHECK(args[3]->IsInt32())` that aborts the process, so there is no
    // behaviour to match, only one to refuse to copy.
    await expect(handle.read(buffer, 1.5, 1)).rejects.toMatchObject({
      code: "ERR_OUT_OF_RANGE",
      message: /"offset"/,
    });
    await expect(handle.read(buffer, 0, 1.5)).rejects.toMatchObject({
      code: "ERR_OUT_OF_RANGE",
      message: /"length"/,
    });
    await handle.close();
    expect((await fs.stat("/f")).size).toBe(8);
  });

  it("keeps hard-linked content and metadata in sync", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/a", "one");
    await fs.link("/a", "/b");
    await fs.chmod("/b", 0o600);
    expect((await fs.stat("/a")).mode & 0o777).toBe(0o600);
    await fs.truncate("/b", 1);
    expect((await fs.stat("/a")).size).toBe(1);
  });

  it("survives a rename over a hard link", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/a", "one");
    await fs.link("/a", "/b");
    await fs.writeFile("/c", "two");
    await fs.rename("/c", "/b");
    expect((await fs.stat("/a")).nlink).toBe(1);
    expect((await fs.stat("/b")).nlink).toBe(1);
  });

  it("refuses to open or truncate a special file, which holds no bytes", async () => {
    // The shared conformance suite does not ask this: over a mount no client
    // ever gets here — the FUSE, 9P and NFS clients all supply pipe, socket and
    // device semantics locally and never send the open across — so the only
    // caller who can is a loopback one, and handing it a byte buffer would be a
    // filesystem no mount has. `ENXIO` is `open(2)`'s answer for a device with
    // nothing behind it, which is the situation exactly.
    const fs = createLoopback(createMemoryDriver());
    await fs.mountx!.mknod!("/fifo", S_IFIFO | 0o644, 0);
    await fs.mountx!.mknod!("/null", S_IFCHR | 0o666, (1 << 8) | 3);
    await expect(fs.open("/fifo", "r")).rejects.toMatchObject({ code: "ENXIO" });
    await expect(fs.open("/null", "w")).rejects.toMatchObject({ code: "ENXIO" });
    // `truncate(2)`'s own answer for anything that is not a regular file.
    await expect(fs.truncate("/fifo", 0)).rejects.toMatchObject({ code: "EINVAL" });
    // ...and neither refusal costs the node its identity.
    expect((await fs.stat("/fifo")).isFIFO()).toBe(true);
    expect((await fs.stat("/null")).rdev).toBe((1 << 8) | 3);
  });

  it("gives a FIFO and a socket no device number to carry", async () => {
    // POSIX leaves `dev` unused for these two, so a caller passing one anyway
    // must not end up with a FIFO that stats like a device.
    const fs = createLoopback(createMemoryDriver());
    await fs.mountx!.mknod!("/fifo", S_IFIFO | 0o644, (1 << 8) | 3);
    await fs.mountx!.mknod!("/sock", S_IFSOCK | 0o600, 42);
    expect((await fs.stat("/fifo")).rdev).toBe(0);
    expect((await fs.stat("/sock")).rdev).toBe(0);
  });

  it("counts a special file in statfs and lets go of it on unlink", async () => {
    const fs = createLoopback(createMemoryDriver());
    const before = await fs.statfs("/");
    await fs.mountx!.mknod!("/fifo", S_IFIFO | 0o644, 0);
    const after = await fs.statfs("/");
    // One more inode, and no blocks: the node holds nothing.
    expect(before.ffree - after.ffree).toBe(1);
    expect(after.bfree).toBe(before.bfree);
    await fs.unlink("/fifo");
    expect((await fs.statfs("/")).ffree).toBe(before.ffree);
  });
});
