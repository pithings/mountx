/**
 * The differential oracle: the same operations, run twice.
 *
 * One side is a real kernel mount of the `node:fs` passthrough driver; the
 * other is an ordinary directory driven straight through `node:fs`. Every
 * operation's *result* is compared — its return value, or the errno it failed
 * with — and then the two trees are compared in full. Anything that differs is,
 * by construction, something the FUSE stack did to a filesystem that a
 * filesystem does not do to itself.
 *
 * Nothing in this file mounts anything or needs root: it is the script and the
 * comparison, so it can be read (and unit-tested) on its own.
 * `differential.test.ts` supplies the two roots.
 *
 * **What is deliberately not compared**, and why:
 *
 * - `st_dev` and `st_ino` *values*. A different filesystem has different
 *   numbers; what has to match is the *partition* they induce, so hardlink
 *   groups are compared as sets of paths ({@link Snapshot.hardlinks}).
 * - Timestamps in the tree walk. `atime` depends on mount options nobody here
 *   controls, and `mtime` on directories depends on the backing filesystem's
 *   granularity. Times are checked where they are the point instead: `utimes`
 *   sets one and the next `lstat` reads it back, as an *operation result*.
 * - The `size` of a **directory**. It is a backing-filesystem detail (ext4 says
 *   4096, tmpfs counts entries in its own units) and carries no information
 *   about whether the mount behaved.
 *
 * Everything else — type, permission bits, `nlink`, file and symlink sizes,
 * file contents, symlink targets — must match exactly.
 *
 * ## Symlink targets stay inside the tree
 *
 * Every symlink an op here creates has a relative target with no `..` in it.
 * That is a correctness *and* a safety rule: the kernel resolves symlinks on
 * the client side, so `mnt/link -> ../../etc/passwd` would escape the
 * mountpoint into the real filesystem, land somewhere different from what the
 * plain-directory side resolves, and report a divergence that is really a test
 * bug — after possibly writing outside the sandbox.
 */

import { createHash } from "node:crypto";
import {
  appendFile,
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  readlink,
  rename,
  rmdir,
  stat,
  symlink,
  truncate,
  unlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { Rng } from "./random.ts";

/** One step of a differential script. */
export interface DiffOp {
  /** Stable label; it is what a divergence report names. */
  readonly name: string;
  /** Runs against one root. Must return something JSON-shaped and root-independent. */
  run(root: string): Promise<unknown>;
}

function op(name: string, run: (root: string) => Promise<unknown>): DiffOp {
  return { name, run };
}

/** What an op did: a value, or the errno it failed with. Compared as a string. */
export type OpResult = string;

function codeOf(error: unknown): string {
  if (typeof error === "object" && error !== null) {
    const { code, name } = error as { code?: unknown; name?: unknown };
    if (typeof code === "string") {
      return code;
    }
    if (typeof name === "string") {
      return name;
    }
  }
  return String(error);
}

/**
 * Run one op and reduce it to a comparable string.
 *
 * Failures are results too — an op that raises `ENOTEMPTY` on both sides agrees
 * — so nothing here throws. Only the *code* is kept: messages carry the path,
 * which differs between the two roots by definition.
 */
export async function runOp(operation: DiffOp, root: string): Promise<OpResult> {
  try {
    return `ok ${JSON.stringify(await operation.run(root)) ?? "undefined"}`;
  } catch (error) {
    return `error ${codeOf(error)}`;
  }
}

// ---------------------------------------------------------------------------
// snapshots
// ---------------------------------------------------------------------------

/** One path's observable state. */
export interface EntryState {
  type: "file" | "dir" | "symlink" | "other";
  /** Permission bits, octal. */
  mode: string;
  nlink: number;
  /** Files and symlinks only — see the note on directory sizes. */
  size?: number;
  /** Files: a digest of the contents. */
  content?: string;
  /** Symlinks: the target, verbatim. */
  target?: string;
  /**
   * Set when the contents could not be read at all — a `chmod 0400` on a
   * directory, say. The errno is part of the comparison rather than a reason to
   * stop walking, so an unreadable subtree is a *difference* and not a crash.
   */
  unreadable?: string;
}

/** A whole tree, in a form two different filesystems can be expected to agree on. */
export interface Snapshot {
  /** Relative path → state, `"."` being the root itself. */
  entries: Record<string, EntryState>;
  /**
   * Hardlink groups: every set of paths sharing one inode, sorted. Inode
   * *numbers* cannot match across filesystems; the partition must.
   */
  hardlinks: string[][];
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex").slice(0, 16);
}

/**
 * Walk a tree into a {@link Snapshot}.
 *
 * Strictly one entry at a time. A concurrent walk of a mountpoint this process
 * is *serving* parks a threadpool thread per outstanding call and deadlocks as
 * soon as it runs out — the hazard documented at the top of `src/fuse/mount.ts`.
 */
export async function snapshot(root: string): Promise<Snapshot> {
  const entries: Record<string, EntryState> = {};
  const inodes = new Map<string, string[]>();

  async function visit(relative: string): Promise<void> {
    const absolute = relative === "." ? root : join(root, relative);
    let stats;
    try {
      stats = await lstat(absolute);
    } catch (error) {
      // A directory with its execute bit cleared can still be *listed*, so a
      // name can be here with nothing behind it that we are allowed to see.
      entries[relative] = { type: "other", mode: "????", nlink: 0, unreadable: codeOf(error) };
      return;
    }
    const state: EntryState = {
      type: stats.isDirectory()
        ? "dir"
        : stats.isFile()
          ? "file"
          : stats.isSymbolicLink()
            ? "symlink"
            : "other",
      mode: (stats.mode & 0o7777).toString(8).padStart(4, "0"),
      nlink: stats.nlink,
    };
    if (state.type !== "dir") {
      state.size = stats.size;
    }
    if (state.type === "file") {
      try {
        state.content = digest(await readFile(absolute));
      } catch (error) {
        state.unreadable = codeOf(error);
      }
      if (stats.nlink > 1) {
        const key = `${stats.dev}:${stats.ino}`;
        const group = inodes.get(key) ?? [];
        group.push(relative);
        inodes.set(key, group);
      }
    }
    if (state.type === "symlink") {
      state.target = await readlink(absolute);
    }
    entries[relative] = state;
    if (state.type !== "dir") {
      return;
    }
    let names: string[];
    try {
      names = (await readdir(absolute)).sort();
    } catch (error) {
      state.unreadable = codeOf(error);
      return;
    }
    for (const name of names) {
      await visit(relative === "." ? name : `${relative}/${name}`);
    }
  }

  await visit(".");
  const hardlinks = [...inodes.values()]
    .map((group) => group.sort())
    .sort((left, right) => (left[0]! < right[0]! ? -1 : 1));
  return { entries, hardlinks };
}

/** Human-readable differences between two snapshots. Empty means identical. */
export function diffSnapshots(left: Snapshot, right: Snapshot): string[] {
  const differences: string[] = [];
  const paths = [...new Set([...Object.keys(left.entries), ...Object.keys(right.entries)])].sort();
  for (const path of paths) {
    const a = left.entries[path];
    const b = right.entries[path];
    if (a === undefined || b === undefined) {
      differences.push(`${path}: ${a === undefined ? "missing on the mount" : "missing on disk"}`);
      continue;
    }
    for (const field of [
      "type",
      "mode",
      "nlink",
      "size",
      "content",
      "target",
      "unreadable",
    ] as const) {
      if (a[field] !== b[field]) {
        differences.push(`${path}.${field}: mount ${String(a[field])} ≠ disk ${String(b[field])}`);
      }
    }
  }
  const groups = (value: Snapshot): string => JSON.stringify(value.hardlinks);
  if (groups(left) !== groups(right)) {
    differences.push(`hardlink groups: mount ${groups(left)} ≠ disk ${groups(right)}`);
  }
  return differences;
}

// ---------------------------------------------------------------------------
// the scripted sequence
// ---------------------------------------------------------------------------

/** 255 bytes: exactly `NAME_MAX`, which both sides must accept. */
const LONGEST_NAME = "n".repeat(255);
/** 256 bytes: one over, which both sides must refuse with `ENAMETOOLONG`. */
const TOO_LONG_NAME = "n".repeat(256);
/** Multi-byte, because `namelen` on the wire is a byte count. */
const UTF8_NAME = "héllo-λ-字-🙂.txt";
const SPACED_NAME = "a file  with spaces.txt";
/** Deeper than any FUSE message: the kernel walks it one `LOOKUP` at a time. */
const DEEP = Array.from({ length: 32 }, (_, index) => `deep${index}`).join("/");
/** Bigger than the negotiated `max_write` (1 MiB), so the kernel splits it. */
const BIG_SIZE = 3 * 1024 * 1024 + 12_345;

function bigBuffer(): Buffer {
  const buffer = Buffer.allocUnsafe(BIG_SIZE);
  for (let index = 0; index < BIG_SIZE; index++) {
    buffer[index] = (index * 7 + (index >> 11)) & 0xff;
  }
  return buffer;
}

/**
 * `mkdir(…, { recursive: true })` answers with the *absolute* path of the
 * topmost directory it created, which is different for the two roots by
 * definition. Only the tail carries information.
 */
async function mkdirp(root: string, path: string): Promise<string | undefined> {
  const created = await mkdir(join(root, path), { recursive: true });
  return created === undefined ? undefined : created.slice(root.length);
}

async function describePath(path: string): Promise<unknown> {
  const stats = await lstat(path);
  return {
    type: stats.isDirectory() ? "dir" : stats.isSymbolicLink() ? "symlink" : "file",
    mode: (stats.mode & 0o7777).toString(8),
    size: stats.isDirectory() ? undefined : stats.size,
    nlink: stats.nlink,
  };
}

/**
 * The hand-written sequence: one pass over everything the task list names.
 *
 * Written as data rather than as a test body so that both roots run *exactly*
 * the same steps, and so a divergence report can name the step.
 */
export function scriptedOps(): DiffOp[] {
  return [
    // --- nested mkdir / rmdir ---
    op("mkdir /a", (root) => mkdir(join(root, "a"))),
    op("mkdir /a/b", (root) => mkdir(join(root, "a/b"))),
    op("mkdir /a/b/c", (root) => mkdir(join(root, "a/b/c"))),
    op("mkdir /a/b (again)", (root) => mkdir(join(root, "a/b"))),
    op("mkdir /a/b/c recursive", (root) => mkdirp(root, "a/b/c")),
    op("rmdir /a/b (non-empty)", (root) => rmdir(join(root, "a/b"))),
    op("rmdir /a/b/c", (root) => rmdir(join(root, "a/b/c"))),
    op("readdir /a/b", async (root) => (await readdir(join(root, "a/b"))).sort()),
    op("write /a/b/inner.txt", (root) => writeFile(join(root, "a/b/inner.txt"), "inner")),

    // --- deep paths ---
    op("mkdir deep tree", (root) => mkdirp(root, DEEP)),
    op("write at the bottom", (root) => writeFile(join(root, DEEP, "bottom.txt"), "down here")),
    op("read at the bottom", (root) => readFile(join(root, DEEP, "bottom.txt"), "utf8")),
    op("stat at the bottom", (root) => describePath(join(root, DEEP, "bottom.txt"))),

    // --- create / write / append / truncate ---
    op("create /f", (root) => writeFile(join(root, "f"), "hello")),
    op("read /f", (root) => readFile(join(root, "f"), "utf8")),
    op("append /f", (root) => appendFile(join(root, "f"), " world")),
    op("read /f after append", (root) => readFile(join(root, "f"), "utf8")),
    op("truncate /f to 5", (root) => truncate(join(root, "f"), 5)),
    op("read /f after truncate", (root) => readFile(join(root, "f"), "utf8")),
    op("grow /f to 12", (root) => truncate(join(root, "f"), 12)),
    op("read /f after grow", async (root) => [...(await readFile(join(root, "f")))]),
    op("stat /f", (root) => describePath(join(root, "f"))),
    op("write at an offset", async (root) => {
      const handle = await open(join(root, "f"), "r+");
      try {
        const { bytesWritten } = await handle.write(Buffer.from("XY"), 0, 2, 8);
        return bytesWritten;
      } finally {
        await handle.close();
      }
    }),
    op("read back the offset write", async (root) => [...(await readFile(join(root, "f")))]),
    op("read past the end", async (root) => {
      const handle = await open(join(root, "f"), "r");
      try {
        const { bytesRead } = await handle.read(Buffer.alloc(16), 0, 16, 1000);
        return bytesRead;
      } finally {
        await handle.close();
      }
    }),

    // --- a file larger than one max_write ---
    op("write a 3 MiB file", (root) => writeFile(join(root, "big.bin"), bigBuffer())),
    op("digest the big file", async (root) => digest(await readFile(join(root, "big.bin")))),
    op("size of the big file", (root) => describePath(join(root, "big.bin"))),
    op("truncate the big file", (root) => truncate(join(root, "big.bin"), 1_000_000)),
    op("digest it again", async (root) => digest(await readFile(join(root, "big.bin")))),
    op("read the big file at an offset", async (root) => {
      const handle = await open(join(root, "big.bin"), "r");
      try {
        const into = Buffer.alloc(4096);
        const { bytesRead } = await handle.read(into, 0, 4096, 999_000);
        return [bytesRead, digest(into.subarray(0, bytesRead))];
      } finally {
        await handle.close();
      }
    }),
    op("unlink the big file", (root) => unlink(join(root, "big.bin"))),

    // --- hardlinks ---
    op("link /f -> /hard", (root) => link(join(root, "f"), join(root, "hard"))),
    op("stat /f after link", (root) => describePath(join(root, "f"))),
    op("stat /hard", (root) => describePath(join(root, "hard"))),
    op("same inode?", async (root) => {
      const [left, right] = [await stat(join(root, "f")), await stat(join(root, "hard"))];
      return left.ino === right.ino && left.dev === right.dev;
    }),
    op("write through the link", (root) => writeFile(join(root, "hard"), "through the link")),
    op("read through the other name", (root) => readFile(join(root, "f"), "utf8")),
    op("link onto an existing name", (root) => link(join(root, "f"), join(root, "hard"))),
    op("link a directory", (root) => link(join(root, "a"), join(root, "dirlink"))),
    op("link a missing file", (root) => link(join(root, "nope"), join(root, "other"))),
    op("unlink /hard", (root) => unlink(join(root, "hard"))),
    op("nlink back to one", (root) => describePath(join(root, "f"))),

    // --- symlinks, including dangling ones ---
    op("symlink f -> /link", (root) => symlink("f", join(root, "link"))),
    op("readlink /link", (root) => readlink(join(root, "link"))),
    op("lstat /link", (root) => describePath(join(root, "link"))),
    op("read through /link", (root) => readFile(join(root, "link"), "utf8")),
    op("stat through /link", async (root) => (await stat(join(root, "link"))).size),
    op("dangling symlink", (root) => symlink("nowhere", join(root, "dangling"))),
    op("lstat the dangling one", (root) => describePath(join(root, "dangling"))),
    op("stat the dangling one", (root) => stat(join(root, "dangling"))),
    op("readlink the dangling one", (root) => readlink(join(root, "dangling"))),
    op("symlink to a directory", (root) => symlink("a", join(root, "adir"))),
    op("readdir through the symlink", async (root) => (await readdir(join(root, "adir"))).sort()),
    op("symlink with a utf-8 target", (root) => symlink(UTF8_NAME, join(root, "utf8link"))),
    op("size of the utf-8 symlink", (root) => describePath(join(root, "utf8link"))),
    op("symlink loop a", (root) => symlink("loop-b", join(root, "loop-a"))),
    op("symlink loop b", (root) => symlink("loop-a", join(root, "loop-b"))),
    op("stat into the loop", (root) => stat(join(root, "loop-a"))),
    op("readlink a regular file", (root) => readlink(join(root, "f"))),
    op("symlink onto a taken name", (root) => symlink("whatever", join(root, "f"))),

    // --- unlink while open: the mkstemp pattern ---
    op("open, write, unlink, keep using", async (root) => {
      const handle = await open(join(root, "doomed"), "w+");
      try {
        await handle.write(Buffer.from("still here"), 0, 10, 0);
        await unlink(join(root, "doomed"));
        const gone = await stat(join(root, "doomed")).then(
          () => "visible",
          (error: unknown) => codeOf(error),
        );
        const beforeTruncate = (await handle.stat()).size;
        await handle.truncate(4);
        const afterTruncate = (await handle.stat()).size;
        const into = Buffer.alloc(16);
        const { bytesRead } = await handle.read(into, 0, 16, 0);
        return {
          gone,
          beforeTruncate,
          afterTruncate,
          content: into.subarray(0, bytesRead).toString("utf8"),
          nlink: (await handle.stat()).nlink,
        };
      } finally {
        await handle.close();
      }
    }),

    // --- rename: file, onto an existing file, directory, onto a directory ---
    op("rename a file", (root) => rename(join(root, "f"), join(root, "renamed"))),
    op("the old name is gone", (root) => stat(join(root, "f"))),
    op("read the new name", (root) => readFile(join(root, "renamed"), "utf8")),
    op("rename onto an existing file", async (root) => {
      await writeFile(join(root, "victim"), "overwrite me");
      await rename(join(root, "renamed"), join(root, "victim"));
      return readFile(join(root, "victim"), "utf8");
    }),
    op("rename a populated directory", (root) => rename(join(root, "a"), join(root, "moved"))),
    op("its contents came along", async (root) => (await readdir(join(root, "moved"))).sort()),
    op("read through the moved subtree", (root) =>
      readFile(join(root, "moved/b/inner.txt"), "utf8"),
    ),
    op("write into the moved subtree", (root) =>
      writeFile(join(root, "moved/b/inner.txt"), "after the move"),
    ),
    op("read it back", (root) => readFile(join(root, "moved/b/inner.txt"), "utf8")),
    op("rename a dir onto an empty dir", async (root) => {
      await mkdir(join(root, "empty-target"));
      await rename(join(root, "moved/b"), join(root, "empty-target"));
      return (await readdir(join(root, "empty-target"))).sort();
    }),
    op("rename a dir onto a non-empty dir", async (root) => {
      await mkdir(join(root, "occupied"));
      await writeFile(join(root, "occupied/tenant"), "x");
      return rename(join(root, "moved"), join(root, "occupied"));
    }),
    op("rename a file onto a directory", (root) =>
      rename(join(root, "victim"), join(root, "occupied")),
    ),
    op("rename a directory onto a file", (root) =>
      rename(join(root, "occupied"), join(root, "victim")),
    ),
    op("rename something missing", (root) => rename(join(root, "nope"), join(root, "elsewhere"))),
    op("rename a path onto itself", (root) => rename(join(root, "victim"), join(root, "victim"))),
    op("it survived", (root) => readFile(join(root, "victim"), "utf8")),
    op("rename a directory into itself", (root) =>
      rename(join(root, "occupied"), join(root, "occupied/self")),
    ),

    // --- weird names ---
    op("a name with spaces", (root) => writeFile(join(root, SPACED_NAME), "spaces")),
    op("read the spaced name", (root) => readFile(join(root, SPACED_NAME), "utf8")),
    op("a utf-8 name", (root) => writeFile(join(root, UTF8_NAME), "utf-8")),
    op("read the utf-8 name", (root) => readFile(join(root, UTF8_NAME), "utf8")),
    op("a 255-byte name", (root) => writeFile(join(root, LONGEST_NAME), "at the limit")),
    op("read the 255-byte name", (root) => readFile(join(root, LONGEST_NAME), "utf8")),
    op("a 256-byte name", (root) => writeFile(join(root, TOO_LONG_NAME), "over the limit")),
    op("mkdir a 256-byte name", (root) => mkdir(join(root, TOO_LONG_NAME))),
    op("a name that is just a dot-file", (root) => writeFile(join(root, ".hidden"), "dot")),
    op("readdir the root", async (root) => (await readdir(root)).sort()),
    op("readdir with types", async (root) =>
      (await readdir(root, { withFileTypes: true }))
        .map((entry) => `${entry.name}:${entry.isDirectory() ? "d" : entry.isFile() ? "f" : "l"}`)
        .sort(),
    ),

    // --- chmod and utimes ---
    op("chmod 0600", (root) => chmod(join(root, "victim"), 0o600)),
    op("mode after chmod", (root) => describePath(join(root, "victim"))),
    op("chmod 0755", (root) => chmod(join(root, "victim"), 0o755)),
    op("mode after chmod again", (root) => describePath(join(root, "victim"))),
    op("chmod with sticky and setgid", (root) => chmod(join(root, "occupied"), 0o3755)),
    op("mode of the directory", (root) => describePath(join(root, "occupied"))),
    op("chmod something missing", (root) => chmod(join(root, "nope"), 0o644)),
    op("utimes", (root) =>
      utimes(join(root, "victim"), new Date(Date.UTC(2001, 0, 1)), new Date(Date.UTC(2002, 1, 2))),
    ),
    op("times after utimes", async (root) => {
      const stats = await stat(join(root, "victim"));
      return [stats.atimeMs, stats.mtimeMs];
    }),
    op("utimes with sub-second precision", (root) =>
      utimes(join(root, "victim"), 1_234_567.25, 7_654_321.75),
    ),
    op("sub-second times read back", async (root) => {
      const stats = await stat(join(root, "victim"));
      return [stats.atimeMs, stats.mtimeMs];
    }),
    op("utimes something missing", (root) => utimes(join(root, "nope"), 1, 1)),

    // --- the errno cases, in one place ---
    op("stat a missing path", (root) => stat(join(root, "nope"))),
    op("open a missing path", (root) => readFile(join(root, "nope"))),
    op("exclusive open of an existing file", async (root) => {
      const handle = await open(join(root, "victim"), "wx");
      await handle.close();
    }),
    op("read a directory as a file", (root) => readFile(join(root, "occupied"))),
    op("readdir a file", (root) => readdir(join(root, "victim"))),
    op("descend through a file", (root) => stat(join(root, "victim/child"))),
    op("mkdir under a file", (root) => mkdir(join(root, "victim/child"))),
    op("mkdir with a missing parent", (root) => mkdir(join(root, "no/such/parent"))),
    op("unlink a directory", (root) => unlink(join(root, "occupied"))),
    op("rmdir a file", (root) => rmdir(join(root, "victim"))),
    op("rmdir something missing", (root) => rmdir(join(root, "nope"))),
    op("truncate a directory", (root) => truncate(join(root, "occupied"), 0)),
    op("truncate something missing", (root) => truncate(join(root, "nope"), 0)),
    op("open a directory for writing", async (root) => {
      const handle = await open(join(root, "occupied"), "w");
      await handle.close();
    }),
    op("write to a read-only handle", async (root) => {
      const handle = await open(join(root, "victim"), "r");
      try {
        await handle.write(Buffer.from("no"), 0, 2, 0);
      } finally {
        await handle.close();
      }
    }),

    // --- and a final listing, which is also the readdir paging path ---
    op("a directory with 300 entries", async (root) => {
      await mkdir(join(root, "many"));
      for (let index = 0; index < 300; index++) {
        await writeFile(join(root, "many", `entry-${String(index).padStart(3, "0")}`), "x");
      }
      return (await readdir(join(root, "many"))).length;
    }),
    op("list the big directory", async (root) =>
      digest(Buffer.from((await readdir(join(root, "many"))).sort().join("\n"))),
    ),
    op(
      "list it with types",
      async (root) =>
        (await readdir(join(root, "many"), { withFileTypes: true })).filter((entry) =>
          entry.isFile(),
        ).length,
    ),
  ];
}

// ---------------------------------------------------------------------------
// the seeded-random sequence
// ---------------------------------------------------------------------------

/** Names the random script may touch. Nothing outside this set is ever created. */
const POOL = {
  dirs: ["d0", "d1", "d0/n0", "d1/n1", "d0/n0/n00"],
  files: ["f0", "f1", "f2", "d0/g0", "d1/g1", "d0/n0/h0"],
  links: ["l0", "l1", "d0/l2"],
} as const;

const EVERY_PATH: readonly string[] = [...POOL.dirs, ...POOL.files, ...POOL.links, "missing"];

/** Symlink targets: relative, no `..`, so nothing can resolve out of the tree. */
const TARGETS: readonly string[] = ["f0", "f1", "d0", "d0/g0", "nowhere", "l0"];

const MODES = [0o644, 0o600, 0o755, 0o400, 0o777] as const;

/**
 * A few hundred operations from a fixed seed.
 *
 * Random *what*, never random *when*: the sequence depends only on the seed, so
 * a divergence is reproducible from the number in the test. Both roots get the
 * identical list — it is generated once, up front, not sampled per root.
 */
export function randomOps(seed: number, count: number): DiffOp[] {
  const rng = new Rng(seed);
  const ops: DiffOp[] = [];
  const path = (): string => rng.pick(EVERY_PATH);

  for (let index = 0; index < count; index++) {
    const label = (what: string): string => `#${String(index).padStart(3, "0")} ${what}`;
    switch (rng.int(16)) {
      case 0: {
        const target = rng.pick(POOL.dirs);
        ops.push(op(label(`mkdir ${target}`), (root) => mkdir(join(root, target))));
        break;
      }
      case 1: {
        const target = rng.pick(POOL.dirs);
        ops.push(op(label(`rmdir ${target}`), (root) => rmdir(join(root, target))));
        break;
      }
      case 2: {
        const target = rng.pick(POOL.files);
        const body = "x".repeat(rng.range(0, 4096));
        ops.push(
          op(label(`write ${target} (${body.length}B)`), (root) =>
            writeFile(join(root, target), body),
          ),
        );
        break;
      }
      case 3: {
        const target = rng.pick(POOL.files);
        const body = "a".repeat(rng.range(1, 128));
        ops.push(
          op(label(`append ${target} (${body.length}B)`), (root) =>
            appendFile(join(root, target), body),
          ),
        );
        break;
      }
      case 4: {
        const target = rng.pick(POOL.files);
        const length = rng.range(0, 2048);
        ops.push(
          op(label(`truncate ${target} ${length}`), (root) => truncate(join(root, target), length)),
        );
        break;
      }
      case 5: {
        const target = path();
        ops.push(op(label(`unlink ${target}`), (root) => unlink(join(root, target))));
        break;
      }
      case 6: {
        const [from, to] = [path(), path()];
        ops.push(
          op(label(`rename ${from} ${to}`), (root) => rename(join(root, from), join(root, to))),
        );
        break;
      }
      case 7: {
        const [from, to] = [rng.pick(POOL.files), rng.pick(POOL.files)];
        ops.push(op(label(`link ${from} ${to}`), (root) => link(join(root, from), join(root, to))));
        break;
      }
      case 8: {
        const [target, at] = [rng.pick(TARGETS), rng.pick(POOL.links)];
        ops.push(op(label(`symlink ${target} ${at}`), (root) => symlink(target, join(root, at))));
        break;
      }
      case 9: {
        const target = path();
        ops.push(op(label(`readlink ${target}`), (root) => readlink(join(root, target))));
        break;
      }
      case 10: {
        const [target, mode] = [path(), rng.pick(MODES)];
        ops.push(
          op(label(`chmod ${target} ${mode.toString(8)}`), (root) =>
            chmod(join(root, target), mode),
          ),
        );
        break;
      }
      case 11: {
        const target = path();
        // Fixed epochs: a clock in a differential test is a divergence waiting
        // to happen.
        const [atime, mtime] = [rng.range(1, 1_000_000), rng.range(1, 1_000_000)];
        ops.push(
          op(label(`utimes ${target} ${atime} ${mtime}`), async (root) => {
            await utimes(join(root, target), atime, mtime);
            const stats = await stat(join(root, target));
            return [stats.atimeMs, stats.mtimeMs];
          }),
        );
        break;
      }
      case 12: {
        const target = rng.pick([...POOL.dirs, "."]);
        ops.push(
          op(label(`readdir ${target}`), async (root) =>
            (await readdir(join(root, target))).sort(),
          ),
        );
        break;
      }
      case 13: {
        const target = path();
        ops.push(op(label(`lstat ${target}`), (root) => describePath(join(root, target))));
        break;
      }
      case 14: {
        const target = rng.pick(POOL.files);
        ops.push(
          op(label(`read ${target}`), async (root) => digest(await readFile(join(root, target)))),
        );
        break;
      }
      default: {
        const target = rng.pick(POOL.files);
        const offset = rng.range(0, 3000);
        const body = "z".repeat(rng.range(1, 64));
        ops.push(
          op(label(`pwrite ${target} @${offset} (${body.length}B)`), async (root) => {
            const handle = await open(join(root, target), "r+");
            try {
              const { bytesWritten } = await handle.write(
                Buffer.from(body),
                0,
                body.length,
                offset,
              );
              return bytesWritten;
            } finally {
              await handle.close();
            }
          }),
        );
        break;
      }
    }
  }
  return ops;
}

// ---------------------------------------------------------------------------
// running a script against two roots
// ---------------------------------------------------------------------------

/** One step where the two roots disagreed. */
export interface Divergence {
  index: number;
  op: string;
  mount: OpResult;
  disk: OpResult;
}

/**
 * Run `ops` against both roots, one step at a time, alternating.
 *
 * Interleaved rather than run-A-then-run-B on purpose: both trees are in the
 * same state before every step, so the *first* reported divergence is the one
 * that caused all the others.
 */
export async function runDifferential(
  ops: readonly DiffOp[],
  mountRoot: string,
  diskRoot: string,
): Promise<Divergence[]> {
  const divergences: Divergence[] = [];
  for (const [index, operation] of ops.entries()) {
    const mount = await runOp(operation, mountRoot);
    const disk = await runOp(operation, diskRoot);
    if (mount !== disk) {
      divergences.push({ index, op: operation.name, mount, disk });
    }
  }
  return divergences;
}

/** Format divergences for an assertion message. */
export function formatDivergences(divergences: readonly Divergence[]): string[] {
  return divergences.map(
    (divergence) =>
      `[${divergence.index}] ${divergence.op}: mount ${divergence.mount} ≠ disk ${divergence.disk}`,
  );
}

/**
 * `rm -rf`, one entry at a time.
 *
 * Node's recursive `rm` fans out, and a fan-out against a mountpoint this
 * process is serving is the threadpool deadlock. Not fast; correct.
 */
export async function removeAll(path: string): Promise<void> {
  const stats = await lstat(path);
  if (!stats.isDirectory()) {
    await unlink(path);
    return;
  }
  for (const name of await readdir(path)) {
    await removeAll(join(path, name));
  }
  await rmdir(path);
}

/**
 * Restore enough permission on a tree that it can be deleted.
 *
 * The random script chmods directories, and one of the modes it picks is
 * `0400`: readable, not searchable. Nothing can descend into such a directory
 * afterwards — including the cleanup — so `rm -rf` fails with `EACCES` and the
 * sandbox survives the test run. (It survived every non-root `pnpm test` until
 * someone looked in `/tmp`.) Top-down, because the walk needs the execute bit
 * on a directory before it can list what is inside it.
 */
export async function makeRemovable(path: string): Promise<void> {
  const stats = await lstat(path);
  if (!stats.isDirectory()) {
    return;
  }
  await chmod(path, 0o700);
  for (const name of await readdir(path)) {
    await makeRemovable(join(path, name));
  }
}

/** Empty a directory without removing it — a mountpoint cannot be `rmdir`ed. */
export async function removeContents(path: string): Promise<void> {
  for (const name of await readdir(path)) {
    await removeAll(join(path, name));
  }
}
