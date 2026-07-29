/**
 * An `FsDriver` whose every call is a syscall made by a *traced process*.
 *
 * This is the other end of `seccomp-helper.ts`, and together they are what lets
 * `test/conformance.ts` run unmodified as the supervisor's column of the
 * matrix. A call arrives here, crosses a pipe as one line of NDJSON, becomes a
 * `node:fs/promises` call in a process running under the seccomp filter, is
 * trapped by the kernel, answered by the supervisor out of a 9P client against
 * a `P9Session` over the driver under test, and comes back the same way.
 *
 * Nothing is short-circuited anywhere along that path — which is the point, and
 * also why this column is slower than every other one.
 *
 * Not a `*.test.ts` file: it is imported by one.
 */

import { Buffer } from "node:buffer";
import type { ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import {
  S_IFBLK,
  S_IFCHR,
  S_IFDIR,
  S_IFIFO,
  S_IFLNK,
  S_IFMT,
  S_IFREG,
  S_IFSOCK,
} from "../../src/types.ts";
import type {
  DirentLike,
  FileHandleLike,
  FsDriver,
  MkdirOptions,
  StatsFsLike,
  StatsLike,
  TimeLike,
} from "../../src/types.ts";

interface Reply {
  i: number;
  v?: unknown;
  e?: { code: string; errno?: number; syscall?: string; message: string };
}

/**
 * The pipe, with one request outstanding at a time.
 *
 * Serialized deliberately: the suite is written as a sequence of awaited calls,
 * and pipelining them would test the helper's request ordering rather than the
 * supervisor's behaviour. The supervisor's own concurrency is exercised
 * elsewhere — `node:fs/promises` puts every one of these on a threadpool
 * thread, so the notifications already arrive from a thread that is not the
 * one that started the process.
 */
export class HelperLink {
  #child: ChildProcess;
  #pending = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (error: unknown) => void }
  >();
  #next = 1;
  #closed: Error | undefined;

  constructor(child: ChildProcess) {
    this.#child = child;
    const stdout = child.stdout;
    if (stdout === null || child.stdin === null) {
      throw new Error("mountx: the helper needs piped stdio");
    }
    const lines = createInterface({ input: stdout });
    lines.on("line", (line) => {
      if (line.trim() === "") return;
      const reply = JSON.parse(line) as Reply;
      const waiter = this.#pending.get(reply.i);
      if (waiter === undefined) return;
      this.#pending.delete(reply.i);
      if (reply.e === undefined) {
        waiter.resolve(reply.v);
      } else {
        waiter.reject(
          Object.assign(new Error(reply.e.message), {
            code: reply.e.code,
            errno: reply.e.errno,
            syscall: reply.e.syscall,
          }),
        );
      }
    });
    child.on("exit", () => {
      this.#closed = new Error("mountx: the traced helper exited");
      for (const waiter of this.#pending.values()) waiter.reject(this.#closed);
      this.#pending.clear();
    });
  }

  call(op: string, ...a: unknown[]): Promise<unknown> {
    if (this.#closed !== undefined) return Promise.reject(this.#closed);
    const i = this.#next++;
    return new Promise((resolve, reject) => {
      this.#pending.set(i, { resolve, reject });
      this.#child.stdin?.write(`${JSON.stringify({ i, op, a })}\n`);
    });
  }

  /** Ask the helper to leave, which is what ends the traced command. */
  finish(): void {
    this.#child.stdin?.write(`${JSON.stringify({ i: 0, op: "exit", a: [] })}\n`);
    this.#child.stdin?.end();
  }
}

/** The seven predicates, rebuilt from the one number they all come from. */
function typedBy(mode: number): Omit<StatsLike, keyof Record<string, number>> {
  const is = (bits: number): boolean => (mode & S_IFMT) === bits;
  return {
    isFile: () => is(S_IFREG),
    isDirectory: () => is(S_IFDIR),
    isSymbolicLink: () => is(S_IFLNK),
    isBlockDevice: () => is(S_IFBLK),
    isCharacterDevice: () => is(S_IFCHR),
    isFIFO: () => is(S_IFIFO),
    isSocket: () => is(S_IFSOCK),
  } as Omit<StatsLike, keyof Record<string, number>>;
}

function toStats(value: Record<string, number>): StatsLike {
  return { ...value, ...typedBy(value.mode ?? 0) } as unknown as StatsLike;
}

function toDirent(entry: { name: string; type: string }): DirentLike {
  const is = (letter: string): boolean => entry.type === letter;
  return {
    name: entry.name,
    isFile: () => is("f"),
    isDirectory: () => is("d"),
    isSymbolicLink: () => is("l"),
    isBlockDevice: () => is("b"),
    isCharacterDevice: () => is("c"),
    isFIFO: () => is("p"),
    isSocket: () => is("s"),
  };
}

/** A `TimeLike` the far side can parse: `Date`s do not survive JSON as dates. */
function toTime(value: TimeLike): number {
  return value instanceof Date ? value.getTime() / 1000 : value;
}

export function seccompDriver(link: HelperLink): FsDriver {
  const handle = (id: number): FileHandleLike => ({
    async read(buffer, offset, length, position) {
      const result = (await link.call(
        "read",
        id,
        buffer.length,
        offset ?? 0,
        length ?? buffer.length,
        position ?? null,
      )) as { bytesRead: number; data: string };
      const bytes = Buffer.from(result.data, "base64");
      buffer.set(bytes.subarray(0, buffer.length));
      return { bytesRead: result.bytesRead, buffer };
    },
    async write(buffer, offset, length, position) {
      const bytesWritten = (await link.call(
        "write",
        id,
        Buffer.from(buffer).toString("base64"),
        offset ?? 0,
        length ?? buffer.length,
        position ?? null,
      )) as number;
      return { bytesWritten, buffer };
    },
    async stat() {
      return toStats((await link.call("fstat", id)) as Record<string, number>);
    },
    async truncate(length) {
      await link.call("ftruncate", id, length ?? 0);
    },
    async close() {
      await link.call("close", id);
    },
    async sync() {
      await link.call("fsync", id);
    },
    async datasync() {
      await link.call("fdatasync", id);
    },
  });

  return {
    async stat(path) {
      return toStats((await link.call("stat", path)) as Record<string, number>);
    },
    async lstat(path) {
      return toStats((await link.call("lstat", path)) as Record<string, number>);
    },
    async statfs(path) {
      return (await link.call("statfs", path)) as StatsFsLike;
    },
    async readdir(path) {
      const entries = (await link.call("readdir", path)) as { name: string; type: string }[];
      return entries.map(toDirent);
    },
    async open(path, flags, mode) {
      const id = (await link.call("open", path, flags ?? "r", mode ?? 0o666)) as number;
      return handle(id);
    },
    async mkdir(path, options?: MkdirOptions) {
      return ((await link.call("mkdir", path, options ?? {})) as string | null) ?? undefined;
    },
    async rmdir(path) {
      await link.call("rmdir", path);
    },
    async unlink(path) {
      await link.call("unlink", path);
    },
    async rename(oldPath, newPath) {
      await link.call("rename", oldPath, newPath);
    },
    async link(existingPath, newPath) {
      await link.call("link", existingPath, newPath);
    },
    async symlink(target, path) {
      await link.call("symlink", target, path);
    },
    async readlink(path) {
      return (await link.call("readlink", path)) as string;
    },
    async chmod(path, mode) {
      await link.call("chmod", path, mode);
    },
    async chown(path, uid, gid) {
      await link.call("chown", path, uid, gid);
    },
    async lchown(path, uid, gid) {
      await link.call("lchown", path, uid, gid);
    },
    async truncate(path, length) {
      await link.call("truncate", path, length ?? 0);
    },
    async utimes(path, atime, mtime) {
      await link.call("utimes", path, toTime(atime), toTime(mtime));
    },
    async lutimes(path, atime, mtime) {
      await link.call("lutimes", path, toTime(atime), toTime(mtime));
    },
  };
}
