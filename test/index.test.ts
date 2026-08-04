import { spawn } from "node:child_process";
import { mkdtemp, readFile, rename as nodeRename, rm, stat as nodeStat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import { createNodeFsDriver } from "../src/drivers/node-fs.ts";
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
import type { ErrnoCode, FsDriver, FsError, StatsLike } from "../src/index.ts";
import { claimNewEntry, newEntryOwnership } from "../src/ownership.ts";

describe("every entry point runs under node's type stripping", () => {
  /**
   * `package.json` runs TypeScript sources directly — `node bench/index.ts`,
   * `node src/cli/index.ts`, `node test/matrix.ts` — so `src/` may only use the
   * TypeScript that node can *erase*. Anything needing emit (a parameter
   * property, an `enum`, a `namespace`) throws
   * `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX` at import.
   *
   * Vitest cannot catch this: it transforms TypeScript in full, so a file that
   * node refuses passes every suite. It reached `main` exactly that way — a
   * `constructor(readonly slotid: number)` in `src/nfs/v4/state.ts` broke
   * `pnpm bench` and `pnpm mountx -t nfs` from the day NFSv4.1 landed, with the
   * whole suite green over it.
   *
   * Hence a real subprocess: one node, importing every published entry point,
   * which is also why this asserts nothing about *which* syntax is at fault.
   * The failure mode is "node cannot load it", and the check is node.
   */
  it("loads each published entry point in a plain node process", async () => {
    const entries = [
      "src/index.ts",
      "src/auto.ts",
      "src/fuse/index.ts",
      "src/nfs/index.ts",
      "src/9p/index.ts",
      "src/s3/index.ts",
      "src/webdav/index.ts",
      "src/drivers/memory.ts",
      "src/drivers/node-fs.ts",
      "src/drivers/unstorage.ts",
    ];
    const root = new URL("..", import.meta.url);
    const program = entries
      .map((entry) => `await import(${JSON.stringify(new URL(entry, root).href)});`)
      .join("\n");

    const node = await new Promise<{ code: number | null; stderr: string }>((resolve) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", program], {
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (chunk: string) => (stderr += chunk));
      child.on("close", (code) => resolve({ code, stderr }));
    });

    expect(node.stderr).not.toContain("ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX");
    expect({ code: node.code, stderr: node.stderr }).toEqual({ code: 0, stderr: "" });
  }, 30_000);
});

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

  /**
   * The sibling rule to invariant 4: an `FsError` has to be
   * indistinguishable from what `node:fs` throws, field by field — not just
   * on the three fields the test above compares. This is the one that pins
   * the shape `fsError()` builds a stackless error into, since dropping the
   * frames is the only place it deliberately differs from `node:fs`.
   */
  it("is indistinguishable from a node:fs error, property by property", async () => {
    const path = "/definitely/not/here";
    const dest = "/nope/x";
    const real = (await nodeRename(path, dest).catch((error: unknown) => error)) as FsError;
    const ours = fsError("ENOENT", { syscall: "rename", path, dest });

    // Same prototype, same class, same name — through every predicate that
    // asks: `instanceof`, `Object.prototype.toString`, and the `name` that is
    // inherited rather than owned.
    expect(ours).toBeInstanceOf(Error);
    expect(Object.getPrototypeOf(ours)).toBe(Object.getPrototypeOf(real));
    expect(Object.prototype.toString.call(ours)).toBe(Object.prototype.toString.call(real));
    expect(ours.name).toBe(real.name);
    expect(Object.hasOwn(ours, "name")).toBe(Object.hasOwn(real, "name"));

    // Same own properties, in the same order, with the same descriptors —
    // which is what a spread, `Object.keys()` and `JSON.stringify()` read.
    expect(Object.getOwnPropertyNames(ours)).toEqual(Object.getOwnPropertyNames(real));
    expect(Object.keys(ours)).toEqual(Object.keys(real));
    expect({ ...ours }).toEqual({ ...real });
    for (const key of Object.getOwnPropertyNames(real)) {
      const mine = Object.getOwnPropertyDescriptor(ours, key)!;
      const theirs = Object.getOwnPropertyDescriptor(real, key)!;
      expect(typeof mine.get, key).toBe(typeof theirs.get);
      expect(typeof mine.set, key).toBe(typeof theirs.set);
      expect(mine.enumerable, key).toBe(theirs.enumerable);
      expect(mine.configurable, key).toBe(theirs.configurable);
      expect(mine.writable, key).toBe(theirs.writable);
    }
    for (const key of ["message", "code", "errno", "syscall", "path", "dest"] as const) {
      expect(ours[key], key).toBe(real[key]);
    }
  });

  /**
   * `fsError()` skips the frame capture for the codes a mount answers as a
   * matter of course, so `.stack` on one of those is the `Error:` line alone.
   * It is still a string, still starts with the same line `node:fs` would
   * print, and every other code still names the throw site.
   */
  it("keeps a readable stack, with frames wherever a fault is possible", () => {
    const expected = fsError("ENOENT", { syscall: "stat", path: "/missing" });
    expect(typeof expected.stack).toBe("string");
    expect(expected.stack).toBe("Error: ENOENT: no such file or directory, stat '/missing'");

    const fault = fsError("EIO", { syscall: "read", path: "/disk" });
    expect(fault.stack?.startsWith("Error: EIO: i/o error, read '/disk'\n    at ")).toBe(true);
    // The frames name this file, not `src/errors.ts`'s internals only.
    expect(fault.stack).toContain("index.test.ts");

    // A writable `stack`, as node's is — some loggers replace it.
    expected.stack = "replaced";
    expect(expected.stack).toBe("replaced");
  });

  it("leaves Error.stackTraceLimit alone", () => {
    const limit = Error.stackTraceLimit;
    Error.stackTraceLimit = 3;
    try {
      fsError("ENOENT");
      expect(Error.stackTraceLimit).toBe(3);
      expect(new Error("after").stack?.split("\n").length).toBe(4);
    } finally {
      Error.stackTraceLimit = limit;
    }
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

/**
 * `src/ownership.ts` on its own: the decision, with no session around it.
 *
 * The NFS session suites drive the same rule end to end; this is the table of
 * cases `inode_init_owner()` distinguishes, including the two a wire is
 * unlikely to produce (an unreadable parent, a caller who did not say who it
 * is) and the one that needs a privileged caller.
 */
describe("set-gid inheritance", () => {
  /** Only the two fields the rule reads. */
  const dir = (mode: number, gid: number): StatsLike => ({ mode, gid }) as StatsLike;
  const caller = { uid: 1000, gid: 1000, gids: [] as number[] };

  it("takes the caller's group when the parent has no set-gid bit", () => {
    expect(
      newEntryOwnership(caller, { parent: dir(0o40755, 4000), directory: false, mode: 0o644 }),
    ).toEqual({ uid: 1000, gid: 1000, setgid: undefined });
  });

  it("inherits nothing from a parent that could not be read", () => {
    expect(newEntryOwnership(caller, { parent: undefined, directory: true, mode: 0o755 })).toEqual({
      uid: 1000,
      gid: 1000,
      setgid: undefined,
    });
  });

  it("leaves both alone for a caller that did not say who it is", () => {
    // AUTH_NONE: `-1` is `chown`'s "leave this one alone", and there is still a
    // group to inherit if the parent has the bit.
    expect(newEntryOwnership({}, { parent: undefined, directory: false, mode: 0o644 })).toEqual({
      uid: -1,
      gid: -1,
      setgid: undefined,
    });
    expect(
      newEntryOwnership({}, { parent: dir(0o42775, 4000), directory: false, mode: 0o644 }),
    ).toEqual({ uid: -1, gid: 4000, setgid: undefined });
  });

  it("asks for the bit on a new directory, whatever mode the create named", () => {
    expect(
      newEntryOwnership(caller, { parent: dir(0o42775, 4000), directory: true, mode: 0o755 }),
    ).toEqual({ uid: 1000, gid: 4000, setgid: true });
    // Asked for even when the create named it: `mkdir(2)` is not allowed to set
    // `S_ISGID` itself, so whether it is there is a question for the driver.
    // `claimNewEntry` reads back and skips the `chmod` when it already is.
    expect(
      newEntryOwnership(caller, { parent: dir(0o42775, 4000), directory: true, mode: 0o2755 }),
    ).toEqual({ uid: 1000, gid: 4000, setgid: true });
  });

  it("clears set-gid on an executable for a group the caller is not in", () => {
    const entry = { parent: dir(0o42775, 4000), directory: false, mode: 0o2775 };
    expect(newEntryOwnership(caller, entry).setgid).toBe(false);
    // Membership counts whether it is the effective group or a supplementary
    // one, and a privileged caller keeps the bit either way
    // (`capable_wrt_inode_uidgid(dir, CAP_FSETID)`).
    expect(newEntryOwnership({ uid: 1000, gid: 4000 }, entry).setgid).toBeUndefined();
    expect(newEntryOwnership({ ...caller, gids: [4000] }, entry).setgid).toBeUndefined();
    expect(newEntryOwnership({ ...caller, uid: 0 }, entry).setgid).toBeUndefined();
    // Not group-executable: nothing to run as, so nothing to clear.
    expect(newEntryOwnership(caller, { ...entry, mode: 0o2664 }).setgid).toBeUndefined();
  });

  describe("applying it", () => {
    /**
     * A driver that records its calls, and can be told to refuse them.
     *
     * `lstat` answers with `mode`, which is what the entry is supposed to have
     * come back from the create as — the whole point of the read-back being
     * that it is not the mode the create *asked* for.
     */
    function recorder(mode = 0o755, refusal?: string) {
      const calls: string[] = [];
      const answer = async (what: string): Promise<void> => {
        calls.push(what);
        if (refusal !== undefined) throw fsError(refusal as ErrnoCode);
      };
      return {
        calls,
        lchown: (path: string, uid: number, gid: number) => answer(`lchown ${path} ${uid}:${gid}`),
        chmod: (path: string, mode: number) => answer(`chmod ${path} ${mode.toString(8)}`),
        lstat: async (path: string) => {
          calls.push(`lstat ${path}`);
          if (refusal !== undefined) throw fsError(refusal as ErrnoCode);
          return { mode } as StatsLike;
        },
      };
    }

    it("chowns, then chmods — never the other way round", async () => {
      const driver = recorder(0o755);
      await claimNewEntry(driver, "/f", { uid: 1000, gid: 4000, setgid: true });
      // `chown(2)` clears set-group-ID on an executable when an unprivileged
      // caller changes ownership, so the bit has to go on afterwards.
      expect(driver.calls).toEqual(["lchown /f 1000:4000", "lstat /f", "chmod /f 2755"]);
    });

    it("chmods the mode the driver made, not the one the create asked for", async () => {
      // The create asked for 0o775 and a umask of 022 made it 0o755. Asserting
      // the requested mode here would hand the caller group-write it was denied
      // one directory over, purely because this parent is set-gid.
      const driver = recorder(0o755);
      await claimNewEntry(driver, "/d", { uid: -1, gid: 4000, setgid: true });
      expect(driver.calls).toEqual(["lchown /d -1:4000", "lstat /d", "chmod /d 2755"]);

      // And the clearing direction reads back the same way.
      const executable = recorder(0o2755);
      await claimNewEntry(executable, "/x", { uid: -1, gid: 4000, setgid: false });
      expect(executable.calls).toEqual(["lchown /x -1:4000", "lstat /x", "chmod /x 755"]);
    });

    it("does nothing when the driver already produced the answer", async () => {
      const driver = recorder();
      await claimNewEntry(driver, "/f", {
        uid: process.getuid?.() ?? -1,
        gid: process.getgid?.() ?? -1,
        setgid: undefined,
      });
      await claimNewEntry(driver, "/f", { uid: -1, gid: -1, setgid: undefined });
      expect(driver.calls).toEqual([]);

      // ...including a driver that applied the rule itself: the bit is already
      // there, so the read-back is the end of it.
      const inherited = recorder(0o2755);
      await claimNewEntry(inherited, "/d", { uid: -1, gid: -1, setgid: true });
      expect(inherited.calls).toEqual(["lstat /d"]);
    });

    /**
     * The same thing against a driver with a real umask behind it.
     *
     * The recorder above proves what is chmod'ed; this proves the number it is
     * computed from is the truth. `createNodeFsDriver` goes to `node:fs`, so
     * `mkdir`'s mode is masked by the umask of *this* process and the `chmod`
     * that follows is not — which is the whole bug: asserting the requested
     * mode here widens a directory that a plain parent would have narrowed.
     * The memory driver applies no umask unless asked, which is why none of the
     * session suites could see it.
     */
    it("reads back a real driver rather than widening what the umask narrowed", async () => {
      const sandbox = await mkdtemp(join(tmpdir(), "mountx-setgid-"));
      try {
        const driver = createNodeFsDriver(sandbox);
        await driver.mkdir!("/d", { mode: 0o775 });
        const created = (await driver.lstat!("/d")).mode & 0o7777;
        await claimNewEntry(driver as never, "/d", { uid: -1, gid: -1, setgid: true });
        const claimed = (await driver.lstat!("/d")).mode & 0o7777;
        // Exactly one bit different, whatever this host's umask turned 0o775
        // into — 0o755 at the usual 022, which the old rule published as
        // 0o2775.
        expect(claimed).toBe(created | 0o2000);
      } finally {
        await rm(sandbox, { recursive: true, force: true });
      }
    });

    it("is quiet for a driver with no concept of ownership, and only for that", async () => {
      for (const code of ["ENOSYS", "EPERM", "ENOTSUP"]) {
        const driver = recorder(0o755, code);
        await claimNewEntry(driver, "/f", { uid: 1000, gid: 4000, setgid: true });
        // Quiet, and the refused `lchown` does not stop the mode half from
        // being tried: they are two different things the driver may or may not
        // have. The `lstat` refusing is the end of that half, since there is
        // nothing to put the bit on top of.
        expect(driver.calls).toEqual(["lchown /f 1000:4000", "lstat /f"]);
      }
      // Anything else is a real failure of the create that just happened.
      const broken = recorder(0o755, "EIO");
      await expect(
        claimNewEntry(broken, "/f", { uid: 1000, gid: 4000, setgid: undefined }),
      ).rejects.toMatchObject({ code: "EIO" });
    });
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
