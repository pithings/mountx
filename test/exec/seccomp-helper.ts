/**
 * The tracee half of the conformance column: a filesystem REPL that runs
 * **under the supervisor** and does what it is told with `node:fs/promises`.
 *
 * This is the piece that makes a conformance column possible at all. Every
 * other column in this repository reaches its transport through a client
 * library — `test/9p/client.ts` speaks 9P, `test/nfs/v4/client.ts` speaks
 * COMPOUND — but the seccomp supervisor has no client: its interface *is* the
 * syscall ABI, and the only way to drive it is to be a process making syscalls.
 * So the driver under test lives on the other side of a pipe, in a process
 * whose `openat`, `read`, `write` and `getdents64` are answered by the
 * supervisor out of an `FsDriver`.
 *
 * `node:fs/promises` rather than the sync API on purpose: it is exactly what
 * the loopback column of the matrix runs against, so anything this column
 * disagrees about is a difference the supervisor introduced and not one the API
 * has. It also means every request travels the libuv threadpool, which is a
 * second tracee thread by construction — the multi-threaded case the supervisor
 * has to key its tables on a thread *group* to survive.
 *
 * Requests and replies are NDJSON, one per line, and payloads are base64. Not a
 * `*.test.ts` file: it is spawned by one.
 */

import { Buffer } from "node:buffer";
import type { Stats } from "node:fs";
import * as fs from "node:fs/promises";
import { createInterface } from "node:readline";

/** Where the driver appears in this process's namespace. */
const root = process.env.MOUNTX_ROOT ?? "/mountx";

/** Absolute paths only, and never one that escapes the tree. */
function at(path: string): string {
  return path === "/" ? root : root + path;
}

const handles = new Map<number, fs.FileHandle>();
let nextHandle = 1;

function need(id: number): fs.FileHandle {
  const handle = handles.get(id);
  if (handle === undefined) {
    throw Object.assign(new Error("EBADF: no such handle"), { code: "EBADF", errno: -9 });
  }
  return handle;
}

/** A `Stats` flattened to what `StatsLike` needs, plus the mode to rebuild it. */
function stats(value: Stats): Record<string, number> {
  return {
    dev: Number(value.dev),
    ino: Number(value.ino),
    mode: Number(value.mode),
    nlink: Number(value.nlink),
    uid: Number(value.uid),
    gid: Number(value.gid),
    rdev: Number(value.rdev),
    size: Number(value.size),
    blksize: Number(value.blksize),
    blocks: Number(value.blocks),
    atimeMs: value.atimeMs,
    mtimeMs: value.mtimeMs,
    ctimeMs: value.ctimeMs,
    birthtimeMs: value.birthtimeMs,
  };
}

// eslint-disable-next-line complexity
async function perform(op: string, args: unknown[]): Promise<unknown> {
  // A fixed-length tuple rather than an array, so that indexing it is not
  // `T | undefined` under `noUncheckedIndexedAccess`: the shape of each
  // request's arguments is decided by its `op`, and the switch below is where
  // that is checked.
  const a = args as [never, never, never, never, never];
  switch (op) {
    case "stat":
      return stats(await fs.stat(at(a[0])));
    case "lstat":
      return stats(await fs.lstat(at(a[0])));
    case "statfs": {
      const value = await fs.statfs(at(a[0]));
      return {
        type: Number(value.type),
        bsize: Number(value.bsize),
        blocks: Number(value.blocks),
        bfree: Number(value.bfree),
        bavail: Number(value.bavail),
        files: Number(value.files),
        ffree: Number(value.ffree),
      };
    }
    case "readdir": {
      const entries = await fs.readdir(at(a[0]), { withFileTypes: true });
      return entries.map((entry) => ({
        name: entry.name,
        // The type bits, rebuilt on the far side. A `Dirent` cannot cross a
        // pipe, and its seven predicates all come from one value.
        type: entry.isDirectory()
          ? "d"
          : entry.isSymbolicLink()
            ? "l"
            : entry.isFile()
              ? "f"
              : entry.isBlockDevice()
                ? "b"
                : entry.isCharacterDevice()
                  ? "c"
                  : entry.isFIFO()
                    ? "p"
                    : entry.isSocket()
                      ? "s"
                      : "?",
      }));
    }
    case "open": {
      const handle = await fs.open(at(a[0]), a[1], a[2]);
      const id = nextHandle++;
      handles.set(id, handle);
      return id;
    }
    case "close": {
      const handle = need(a[0]);
      handles.delete(a[0]);
      await handle.close();
      return null;
    }
    case "read": {
      const buffer = Buffer.alloc(a[1]);
      const { bytesRead } = await need(a[0]).read(buffer, a[2], a[3], a[4]);
      return { bytesRead, data: buffer.toString("base64") };
    }
    case "write": {
      const buffer = Buffer.from(a[1] as string, "base64");
      const { bytesWritten } = await need(a[0]).write(buffer, a[2], a[3], a[4]);
      return bytesWritten;
    }
    case "fstat":
      return stats(await need(a[0]).stat());
    case "ftruncate":
      await need(a[0]).truncate(a[1]);
      return null;
    case "fsync":
      await need(a[0]).sync();
      return null;
    case "fdatasync":
      await need(a[0]).datasync();
      return null;
    case "mkdir":
      return (await fs.mkdir(at(a[0]), a[1])) ?? null;
    case "rmdir":
      await fs.rmdir(at(a[0]));
      return null;
    case "unlink":
      await fs.unlink(at(a[0]));
      return null;
    case "rename":
      await fs.rename(at(a[0]), at(a[1]));
      return null;
    case "link":
      await fs.link(at(a[0]), at(a[1]));
      return null;
    case "symlink":
      // The target is opaque: it is stored as given, never rooted.
      await fs.symlink(a[0], at(a[1]));
      return null;
    case "readlink":
      return await fs.readlink(at(a[0]));
    case "chmod":
      await fs.chmod(at(a[0]), a[1]);
      return null;
    case "chown":
      await fs.chown(at(a[0]), a[1], a[2]);
      return null;
    case "lchown":
      await fs.lchown(at(a[0]), a[1], a[2]);
      return null;
    case "truncate":
      await fs.truncate(at(a[0]), a[1]);
      return null;
    case "utimes":
      await fs.utimes(at(a[0]), a[1], a[2]);
      return null;
    case "lutimes":
      await fs.lutimes(at(a[0]), a[1], a[2]);
      return null;
    default:
      throw new Error(`unknown op ${op}`);
  }
}

/** An error, flattened to the fields `node:fs`'s shape is made of. */
function flatten(error: unknown): Record<string, unknown> {
  const value = error as { code?: string; errno?: number; syscall?: string; message?: string };
  return {
    code: value.code ?? "EIO",
    errno: value.errno,
    syscall: value.syscall,
    message: value.message ?? String(error),
  };
}

const lines = createInterface({ input: process.stdin });
for await (const line of lines) {
  if (line.trim() === "") continue;
  const request = JSON.parse(line) as { i: number; op: string; a: unknown[] };
  if (request.op === "exit") break;
  let reply: string;
  try {
    reply = JSON.stringify({ i: request.i, v: await perform(request.op, request.a) });
  } catch (error) {
    reply = JSON.stringify({ i: request.i, e: flatten(error) });
  }
  process.stdout.write(`${reply}\n`);
}
