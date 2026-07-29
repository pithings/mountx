import { readFile, stat as nodeStat } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import {
  basename,
  createLoopback,
  dirname,
  ERRNO_CODES,
  errnoOf,
  fsError,
  isNormalizedPath,
  isPathInside,
  isFsError,
  joinPath,
  normalizePath,
  resolveCapabilities,
  resolvePath,
  splitPath,
} from "../src/index.ts";
import type { FsDriver } from "../src/index.ts";

describe("the root export's module graph", () => {
  /**
   * Every specifier `path` imports, statically or dynamically, ignoring the
   * ones inside comments and doc examples.
   *
   * Statements only — an `import`/`export` at the start of a line, or an
   * `import(` anywhere — which is what keeps the many prose mentions of
   * `node:fs` in these files' doc comments out of the answer: a JSDoc line
   * starts with `*`, never with `import`.
   */
  function specifiersOf(source: string): { specifier: string; typeOnly: boolean }[] {
    const found: { specifier: string; typeOnly: boolean }[] = [];
    const statement =
      /^[ \t]*(?:import|export)[ \t]+(type[ \t]+)?[^;]*?from[ \t]*["']([^"']+)["']/gm;
    const bare = /^[ \t]*import[ \t]*["']([^"']+)["']/gm;
    const dynamic = /\bimport\([ \t]*["']([^"']+)["']/g;
    for (const match of source.matchAll(statement)) {
      found.push({ specifier: match[2]!, typeOnly: match[1] !== undefined });
    }
    for (const match of source.matchAll(bare)) {
      found.push({ specifier: match[1]!, typeOnly: false });
    }
    for (const match of source.matchAll(dynamic)) {
      found.push({ specifier: match[1]!, typeOnly: false });
    }
    return found;
  }

  it("reaches no node: builtin and no package, from any file", async () => {
    /*
     * The root `mountx` export is the driver interface, the errors, the paths,
     * the lock and the loopback harness — what a driver author composes with —
     * and it is the one entry point that has to stay free of `node:`. Anything
     * that opens a device, a socket, a process or an HTTP listener lives behind
     * a transport subpath, where reaching for `node:net` or `node:child_process`
     * is what the subpath is *for*. The comment in `src/index.ts` says exactly
     * this; without a check it holds only until the first convenience
     * re-export, which is the kind of thing that regresses silently.
     *
     * Checked on the source rather than on `dist/`, because `pnpm test` runs
     * with no build in front of it and a stale `dist/` would answer for a tree
     * nobody is editing. `obuild` bundles `src/index.ts` into a single
     * `dist/index.mjs`, so the graph walked here is exactly what ends up in the
     * artifact — verified by hand against a real build.
     */
    const walked = new Set<string>();
    const offenders: string[] = [];

    const walk = async (url: URL): Promise<void> => {
      const key = url.pathname;
      if (walked.has(key)) return;
      walked.add(key);
      const source = await readFile(url, "utf8");
      for (const { specifier, typeOnly } of specifiersOf(source)) {
        if (specifier.startsWith(".")) {
          await walk(new URL(specifier, url));
          continue;
        }
        // Type-only imports are erased, so they cost nothing at runtime; a
        // value import of anything that is not a sibling file is either a
        // `node:` builtin or a dependency, and the root export may have
        // neither.
        if (!typeOnly) offenders.push(`${key.split("/src/")[1]}: ${specifier}`);
      }
    };

    await walk(new URL("../src/index.ts", import.meta.url));

    expect(offenders).toEqual([]);
    // And the walk actually walked: a regex that stopped matching would pass
    // the assertion above without reading a thing.
    expect(walked.size).toBeGreaterThanOrEqual(6);
  });
});

describe("paths", () => {
  it("normalizes to absolute POSIX paths", () => {
    expect(normalizePath("a/b")).toBe("/a/b");
    expect(normalizePath("/a//b/")).toBe("/a/b");
    expect(normalizePath("/a/./b")).toBe("/a/b");
    expect(normalizePath("")).toBe("/");
    expect(normalizePath("/")).toBe("/");
  });

  it("clamps `..` at the root", () => {
    expect(normalizePath("/a/../b")).toBe("/b");
    expect(normalizePath("/../../etc/passwd")).toBe("/etc/passwd");
    expect(normalizePath("../..")).toBe("/");
    expect(splitPath("/a/b/../c")).toEqual(["a", "c"]);
  });

  it("joins, splits and inspects", () => {
    expect(joinPath("/a", "b", "c")).toBe("/a/b/c");
    expect(dirname("/a/b/c")).toBe("/a/b");
    expect(dirname("/a")).toBe("/");
    expect(dirname("/")).toBe("/");
    expect(basename("/a/b")).toBe("b");
    expect(basename("/")).toBe("/");
    expect(isPathInside("/a/b", "/a")).toBe(true);
    expect(isPathInside("/a", "/a")).toBe(true);
    expect(isPathInside("/ab", "/a")).toBe(false);
    expect(isPathInside("/a", "/")).toBe(true);
  });

  it("recognizes an already-normalized path", () => {
    for (const path of ["/", "/a", "/a/b/c", "/..a", "/a../b", "/...", "/a.b", "/.a"]) {
      expect(isNormalizedPath(path)).toBe(true);
    }
    for (const path of ["", "a", "a/b", "/a/", "//a", "/a//b", "/.", "/..", "/a/./b", "/a/b/.."]) {
      expect(isNormalizedPath(path)).toBe(false);
    }
  });

  it("still rewrites everything the fast path must not accept", () => {
    for (const [input, expected] of [
      ["", "/"],
      ["a", "/a"],
      ["/a/", "/a"],
      ["//a", "/a"],
      ["/a//b", "/a/b"],
      ["/a/./b", "/a/b"],
      ["/a/..", "/"],
      ["/.", "/"],
      ["/..", "/"],
      ["/a/b/..", "/a"],
      ["/a/b/.", "/a/b"],
    ] as const) {
      expect(normalizePath(input)).toBe(expected);
    }
  });

  it("normalizes and splits in one call", () => {
    expect(resolvePath("/a/b")).toEqual({ path: "/a/b", segments: ["a", "b"] });
    expect(resolvePath("/")).toEqual({ path: "/", segments: [] });
    expect(resolvePath("")).toEqual({ path: "/", segments: [] });
    expect(resolvePath("a/../b/./c/")).toEqual({ path: "/b/c", segments: ["b", "c"] });
    expect(resolvePath("/../escape")).toEqual({ path: "/escape", segments: ["escape"] });
  });

  it("agrees with normalizePath and splitPath on every input", () => {
    for (const input of [
      "",
      "/",
      "a",
      "/a",
      "/a/b/c",
      "//a//b//",
      "/a/./b/../c",
      "/../../etc/passwd",
      "/a/..",
      "/...",
      "/..a/b..",
    ]) {
      const resolved = resolvePath(input);
      expect(resolved.path).toBe(normalizePath(input));
      expect(resolved.segments).toEqual(splitPath(input));
      // The array is the caller's: drivers `shift()` and index into it.
      resolved.segments.push("mutable");
      expect(resolvePath(input).segments).toEqual(splitPath(input));
    }
  });

  it("matches the unoptimized algorithm on a generated corpus", () => {
    /*
     * The split-and-rejoin `normalizePath` was before the fast path landed.
     * Nothing can observe the difference between it and the current one by
     * running them — the fast path is value-preserving on purpose, and a
     * primitive string has no observable reference identity — so what is
     * pinned here is the two properties that *can* go wrong: the predicate
     * deciding a path is normal when it is not (which would return an
     * unnormalized path from `normalizePath`), and the helpers' shortcuts
     * disagreeing with the long way round.
     */
    const reference = (path: string): string => {
      const kept: string[] = [];
      for (const segment of path.split("/")) {
        if (segment === "" || segment === ".") continue;
        if (segment === "..") {
          kept.pop();
          continue;
        }
        kept.push(segment);
      }
      return kept.length === 0 ? "/" : `/${kept.join("/")}`;
    };

    const tokens = ["a", "b", "", ".", "..", "...", "..a", "a.."];
    const bodies = [""];
    for (let depth = 0; depth < 3; depth++) {
      for (const body of bodies.slice()) {
        for (const token of tokens) bodies.push(body === "" ? token : `${body}/${token}`);
      }
    }

    let normalized = 0;
    for (const body of bodies) {
      for (const input of [body, `/${body}`, `${body}/`, `/${body}/`]) {
        const expected = reference(input);
        expect(normalizePath(input), input).toBe(expected);
        // The predicate is the fast path's only decision, and it must agree
        // exactly with "the long way round changed nothing".
        expect(isNormalizedPath(input), input).toBe(expected === input);
        if (isNormalizedPath(input)) normalized++;

        const resolved = resolvePath(input);
        expect(resolved.path, input).toBe(expected);
        expect(resolved.segments, input).toEqual(splitPath(input));

        const parent = reference(`${expected}/..`);
        expect(dirname(input), input).toBe(parent);
        expect(basename(input), input).toBe(
          expected === "/" ? "/" : expected.slice(parent === "/" ? 1 : parent.length + 1),
        );
      }
    }
    // Guard against the corpus degenerating into only one side of the branch.
    expect(normalized).toBeGreaterThan(100);
    expect(bodies.length * 4 - normalized).toBeGreaterThan(100);
  });

  it("takes the same fast path in dirname and basename", () => {
    for (const [input, dir, base] of [
      ["/", "/", "/"],
      ["/a", "/", "a"],
      ["/a/b", "/a", "b"],
      ["/a/b/c", "/a/b", "c"],
      ["/a//b/", "/a", "b"],
      ["/a/b/..", "/", "a"],
      ["", "/", "/"],
    ] as const) {
      expect(dirname(input)).toBe(dir);
      expect(basename(input)).toBe(base);
    }
  });
});

describe("errors", () => {
  it("matches the node:fs error shape", async () => {
    const real = await nodeStat("/definitely/not/here").catch((error: unknown) => error);
    const ours = fsError("ENOENT", { syscall: "stat", path: "/definitely/not/here" });
    expect(isFsError(real, "ENOENT")).toBe(true);
    expect(ours.code).toBe((real as NodeJS.ErrnoException).code);
    expect(ours.errno).toBe((real as NodeJS.ErrnoException).errno);
    expect(ours.message).toBe((real as Error).message);
  });

  it("builds messages the way node does", () => {
    expect(fsError("EEXIST", { syscall: "rename", path: "/a", dest: "/b" }).message).toBe(
      "EEXIST: file already exists, rename '/a' -> '/b'",
    );
    expect(fsError("EIO", { message: "custom" }).message).toBe("custom");
  });

  it("uses Linux errno values", () => {
    expect(ERRNO_CODES.ENOENT).toBe(2);
    expect(ERRNO_CODES.ENOTEMPTY).toBe(39);
    expect(fsError("ENOTEMPTY").errno).toBe(-39);
  });

  it("maps any error back to a positive errno", () => {
    expect(errnoOf(fsError("ENOTDIR"))).toBe(20);
    expect(errnoOf(new Error("boom"))).toBe(ERRNO_CODES.EIO);
    expect(errnoOf({ code: "SOMETHING_ELSE", errno: -17 })).toBe(17);
    expect(errnoOf(undefined)).toBe(ERRNO_CODES.EIO);
  });

  it("recognizes fs errors", () => {
    expect(isFsError(fsError("EPERM"), "EPERM")).toBe(true);
    expect(isFsError(fsError("EPERM"), "EACCES")).toBe(false);
    expect(isFsError(new Error("plain"))).toBe(false);
    expect(isFsError(null)).toBe(false);
  });
});

describe("harness", () => {
  const minimal: FsDriver = {
    stat: () => Promise.reject(new Error("unused")),
    readdir: () => Promise.resolve([]),
    open: () => Promise.reject(new Error("unused")),
  };

  it("infers capabilities from the methods a driver has", () => {
    // `handles`, `atomicRename` and `readOnly` cannot be inferred from a
    // driver's shape, so an undeclared driver gets the conservative answer —
    // and for `readOnly` the conservative answer is `false`: nothing about a
    // missing `unlink` promises that every mutating call answers `EROFS`.
    expect(resolveCapabilities(minimal)).toMatchObject({
      handles: false,
      atomicRename: false,
      hardlinks: false,
      symlinks: false,
      permissions: false,
      times: false,
      truncate: false,
      statfs: false,
      readOnly: false,
      extensions: [],
    });
    expect(resolveCapabilities(createMemoryDriver())).toMatchObject({
      handles: true,
      atomicRename: true,
      hardlinks: true,
      symlinks: true,
      permissions: true,
      times: true,
      truncate: true,
      statfs: true,
      readOnly: false,
    });
  });

  it("takes readOnly only from a declaration", () => {
    // A driver with none of the three name-level mutators still has `open`,
    // and can have `truncate` and `chmod` — so it is not read-only unless it
    // says it is, and one that says it is stays so however many methods it has.
    expect(resolveCapabilities({ ...minimal, truncate: async () => {} }).readOnly).toBe(false);
    expect(resolveCapabilities({ ...minimal, capabilities: { readOnly: true } }).readOnly).toBe(
      true,
    );
    expect(
      resolveCapabilities({
        ...minimal,
        capabilities: { readOnly: true },
        unlink: async () => {},
        mkdir: async () => undefined,
        rename: async () => {},
      }).readOnly,
    ).toBe(true);
  });

  it("resolves the extension namespace from the driver's own keys", () => {
    expect(resolveCapabilities(minimal).extensions).toEqual([]);
    expect(
      resolveCapabilities({ ...minimal, mountx: { mknod: async () => {} } }).extensions,
    ).toEqual(["mknod"]);
    expect(
      resolveCapabilities({
        ...minimal,
        mountx: { mknod: async () => {} },
        capabilities: { extensions: ["utimens"] },
      }).extensions,
    ).toEqual(["utimens"]);
  });

  it("lets a driver declare capabilities its methods contradict", () => {
    const lying: FsDriver = {
      ...minimal,
      capabilities: { symlinks: false },
      symlink: async () => {},
    };
    expect(resolveCapabilities(lying).symlinks).toBe(false);
  });

  it("reports missing methods as ENOSYS", async () => {
    const fs = createLoopback(minimal);
    await expect(fs.symlink("a", "/b")).rejects.toMatchObject({ code: "ENOSYS", errno: -38 });
    await expect(fs.mkdir("/dir")).rejects.toMatchObject({ code: "ENOSYS" });
  });

  it("reads the driver's shape once, at construction", async () => {
    // The one semantic the once-only binding changes, pinned so it is a
    // decision rather than a surprise: the loopback resolves which methods the
    // driver has when it is built, not per call.
    const growing: FsDriver = { ...minimal };
    const fs = createLoopback(growing);
    (growing as { mkdir?: FsDriver["mkdir"] }).mkdir = async () => "/late";
    await expect(fs.mkdir("/late")).rejects.toMatchObject({ code: "ENOSYS" });
    // Still ENOSYS on the second call: the answer is cached, not re-derived
    // and not memoized off a first failure.
    await expect(fs.mkdir("/late")).rejects.toMatchObject({ code: "ENOSYS" });
    // A fresh loopback over the same object does see it.
    await expect(createLoopback(growing).mkdir("/late")).resolves.toBe("/late");

    // And the mirror: a method removed afterwards keeps working, because the
    // bound function is held rather than looked up again.
    const shrinking = createMemoryDriver() as FsDriver;
    const held = createLoopback(shrinking);
    delete (shrinking as { mkdir?: unknown }).mkdir;
    await held.mkdir("/still-there");
    expect((await held.stat("/still-there")).isDirectory()).toBe(true);
  });

  it("normalizes paths before they reach the driver", async () => {
    const seen: string[] = [];
    const driver: FsDriver = {
      ...minimal,
      readdir: async (path) => {
        seen.push(path);
        return [];
      },
    };
    const fs = createLoopback(driver);
    await fs.readdir("a/../b/./c/", { withFileTypes: true });
    await fs.readdir("/../escape", { withFileTypes: true });
    expect(seen).toEqual(["/b/c", "/escape"]);
  });

  it("reads and writes whole files", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/empty", "");
    expect((await fs.readFile("/empty")).length).toBe(0);
    await fs.writeFile("/big", "x".repeat(200_000));
    expect((await fs.readFile("/big")).length).toBe(200_000);
    await fs.writeFile("/bytes", new Uint8Array([1, 2, 3]));
    expect([...(await fs.readFile("/bytes"))]).toEqual([1, 2, 3]);
  });

  it("completes short writes", async () => {
    const backing = createMemoryDriver();
    const calls: [number, number, number | null][] = [];
    const fs = createLoopback({
      ...backing,
      async open(path, flags, mode) {
        const handle = await backing.open(path, flags, mode);
        return {
          ...handle,
          async write(buffer, offset, length, position) {
            const start = offset ?? 0;
            const count = Math.min(length ?? buffer.byteLength - start, 2);
            calls.push([start, count, position ?? null]);
            return handle.write(buffer, start, count, position);
          },
        };
      },
    });

    await fs.writeFile("/short", "abcde");

    expect(new TextDecoder().decode(await fs.readFile("/short"))).toBe("abcde");
    expect(calls).toEqual([
      [0, 2, 0],
      [2, 2, 2],
      [4, 1, 4],
    ]);
  });

  it.each([0, -1, 0.5, 5])("rejects invalid write progress: %s", async (bytesWritten) => {
    const backing = createMemoryDriver();
    const fs = createLoopback({
      ...backing,
      async open(path, flags, mode) {
        const handle = await backing.open(path, flags, mode);
        return {
          ...handle,
          async write(buffer) {
            return { bytesWritten, buffer };
          },
        };
      },
    });

    await expect(fs.writeFile("/stalled", "data")).rejects.toMatchObject({ code: "EIO" });
  });
});
