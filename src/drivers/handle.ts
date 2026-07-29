/**
 * The parts of a `FileHandleLike` that are the same in every driver holding its
 * own bytes — `memory` and `unstorage` are both such drivers.
 *
 * Three things, all pure: turning `node:fs`'s two flag namespaces into one set
 * of booleans, rejecting the out-of-range `read`/`write` arguments `node:fs`
 * rejects, and resizing the buffer a file's contents live in. The flag table in
 * particular is one that gets transcribed subtly wrong (`"a+"` is read *and*
 * write; `"w"` truncates and `"a"` does not), so it lives here once.
 *
 * Nothing here touches a filesystem.
 */

import { constants } from "node:fs";
import { fsError, rangeError } from "../errors.ts";

/** What an `open()` flags argument asks for, in one shape. */
export interface OpenFlags {
  read: boolean;
  write: boolean;
  create: boolean;
  truncate: boolean;
  append: boolean;
  exclusive: boolean;
}

/**
 * A `Map` rather than an object literal, deliberately: a plain object inherits
 * from `Object.prototype`, so `STRING_FLAGS["toString"]` is a *function* and
 * `STRING_FLAGS["__proto__"]` is `Object.prototype` — neither `undefined`, so
 * both would sail past the check in {@link parseOpenFlags} and produce a
 * "flags" object whose `read`/`write`/`create` are all `undefined`. The handle
 * that came back would then answer `EBADF` to everything instead of the open
 * being rejected outright.
 */
const STRING_FLAGS: ReadonlyMap<string, OpenFlags> = new Map(
  (
    [
      ["r", "r--"],
      ["r+", "rw-"],
      ["w", "-wct"],
      ["wx", "-wctx"],
      ["w+", "rwct"],
      ["wx+", "rwctx"],
      ["a", "-wca"],
      ["ax", "-wcax"],
      ["a+", "rwca"],
      ["ax+", "rwcax"],
    ] as const
  ).map(([name, spec]): [string, OpenFlags] => [
    name,
    {
      read: spec.includes("r"),
      write: spec.includes("w"),
      create: spec.includes("c"),
      truncate: spec.includes("t"),
      append: spec.includes("a"),
      exclusive: spec.includes("x"),
    },
  ]),
);

/**
 * Parse either flags namespace: the `"r"`/`"w+"`/`"ax"` strings, or the
 * numeric `O_*` bits.
 *
 * The `s` (synchronous) modifier is dropped rather than rejected — it asks for
 * a write-through the driver already gives, so `"rs+"` is `"r+"`.
 */
export function parseOpenFlags(flags: string | number, path: string): OpenFlags {
  if (typeof flags === "number") {
    const access = flags & (constants.O_RDONLY | constants.O_WRONLY | constants.O_RDWR);
    return {
      read: access === constants.O_RDONLY || access === constants.O_RDWR,
      write: access === constants.O_WRONLY || access === constants.O_RDWR,
      create: (flags & constants.O_CREAT) !== 0,
      truncate: (flags & constants.O_TRUNC) !== 0,
      append: (flags & constants.O_APPEND) !== 0,
      exclusive: (flags & constants.O_EXCL) !== 0,
    };
  }
  const parsed = STRING_FLAGS.get(flags.replace(/s/g, ""));
  if (parsed === undefined) {
    throw fsError("EINVAL", { syscall: "open", path, message: `Invalid open flags: '${flags}'` });
  }
  return parsed;
}

/**
 * `node:fs` argument validation for `read` / `write`: a driver that quietly
 * clamped these would report byte counts it never copied.
 *
 * The order of the checks is `node:fs`'s own, verified against it rather than
 * reasoned about — `offset` is checked for integrality *before* its range
 * (`-0.5` is "must be an integer", `-1` is "must be >= 0"), and `length` the
 * other way round (`-0.5` is "must be >= 0"). The one place this is stricter
 * than `node:fs` is a fractional `length`, which Node's JavaScript layer lets
 * through to a C++ `CHECK(args[3]->IsInt32())` that aborts the process; a
 * `RangeError` is the only sane reading of "what would `node:fs` do".
 */
export function validateRange(
  buffer: Uint8Array,
  offset: number | null | undefined,
  length: number | null | undefined,
  write: boolean,
): { start: number; count: number } {
  const byteLength = buffer.byteLength;
  const start = offset ?? 0;
  if (!Number.isInteger(start)) {
    throw rangeError("offset", "an integer", start);
  }
  if (start < 0 || start > Number.MAX_SAFE_INTEGER) {
    throw rangeError("offset", `>= 0 && <= ${Number.MAX_SAFE_INTEGER}`, start);
  }
  if (write && start > byteLength) {
    throw rangeError("offset", `<= ${byteLength}`, start);
  }
  const count = length ?? byteLength - start;
  if (count < 0) {
    throw rangeError("length", ">= 0", count);
  }
  // A zero-length read is the one shape that survives an out-of-range read
  // offset: `node:fs` copies nothing, looks at nothing, and reports
  // `bytesRead: 0`. Without this the remaining bound would compare `0` against
  // a *negative* remainder and reject a call the oracle accepts.
  if (count > 0 && count > byteLength - start) {
    throw rangeError("length", `<= ${byteLength - start}`, count);
  }
  if (!Number.isInteger(count)) {
    throw rangeError("length", "an integer", count);
  }
  return { start, count };
}

/**
 * An explicit position, or `undefined` for "wherever the handle is" (`null` and
 * `-1`).
 *
 * A fractional position is rejected rather than carried: it reaches
 * `resizeBytes(node, 1.5 + count)` on the write side, and on the read side it
 * comes back out as a *fractional* `bytesRead` — measured at `3.5` before this
 * check existed — which then flows into every caller that adds it to an offset.
 * `node:fs` rejects one with `ERR_OUT_OF_RANGE` "It must be an integer", which
 * also covers `NaN` and `Infinity`.
 */
export function validatePosition(position: number | null | undefined): number | undefined {
  if (position === undefined || position === null || position === -1) {
    return undefined;
  }
  if (!Number.isInteger(position)) {
    throw rangeError("position", "an integer", position);
  }
  if (position < -1 || position > Number.MAX_SAFE_INTEGER) {
    throw rangeError("position", `>= -1 && <= ${Number.MAX_SAFE_INTEGER}`, position);
  }
  return position;
}

/** Anything holding a file's contents: a memory node, an open-file entry. */
export interface ByteHolder {
  data?: Uint8Array;
}

const EMPTY = new Uint8Array(0);

/**
 * Allocate `bytes`, or say `EFBIG`.
 *
 * Every filesystem has a maximum file size and answers `EFBIG` past it. A
 * driver holding its bytes in the heap has whatever the engine will hand out,
 * which is a moving target — V8's cap has changed between releases and
 * `buffer.constants` reports a limit far above what actually allocates — so it
 * is *asked* rather than assumed. Without this, `truncate(f, 1e15)` escapes as
 * a `RangeError`, which a transport can only report as `EIO`: an errno that
 * tells the caller nothing (found by pjdfstest `truncate/12.t`).
 */
function allocate(bytes: number): ArrayBuffer | undefined {
  try {
    return new ArrayBuffer(bytes);
  } catch (error) {
    if (error instanceof RangeError) {
      return undefined;
    }
    /* v8 ignore next 2 -- nothing else comes out of an ArrayBuffer allocation. */
    throw error;
  }
}

/**
 * Set a file's length, keeping spare capacity behind it.
 *
 * `holder.data` is always a view of exactly the file's size, so everything
 * reading it still sees `byteLength` as the length — but the buffer under it is
 * grown geometrically and is usually bigger. That matters more than it looks: a
 * file arrives in `max_write`-sized chunks, and reallocating on every one of
 * them makes writing an *n*-byte file cost O(n²) bytes of copying. Measured,
 * before this: 100 MiB through the memory driver in 1 MiB chunks moved ~5 GiB
 * and ran at 60 MiB/s, with the same 60 MiB/s showing up at the far end of the
 * NFS transport and looking like a protocol cost.
 *
 * Shrinking keeps the capacity unless the file has lost most of its size, so
 * that `truncate(f, 0)` on something large does give the memory back.
 */
export function resizeBytes(holder: ByteHolder, size: number): void {
  const data = holder.data ?? EMPTY;
  const length = data.byteLength;
  if (size === length) {
    return;
  }
  const capacity = data.buffer.byteLength - data.byteOffset;
  if (size <= capacity && size * 4 >= capacity) {
    // Bytes past a shrink are not cleared, so a file truncated down and back
    // up would otherwise resurrect them instead of reading as zeros.
    const next = new Uint8Array(data.buffer, data.byteOffset, size);
    if (size > length) {
      next.fill(0, length);
    }
    holder.data = next;
    return;
  }
  // Doubling first, the exact size as the fallback: the file may be within
  // what the engine can allocate while twice its capacity is not.
  let buffer = size > length ? allocate(Math.max(size, capacity * 2)) : undefined;
  buffer ??= allocate(size);
  if (buffer === undefined) {
    throw fsError("EFBIG", { syscall: "truncate" });
  }
  const next = new Uint8Array(buffer, 0, size);
  next.set(data.subarray(0, Math.min(size, length)));
  holder.data = next;
}
