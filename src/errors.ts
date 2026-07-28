/**
 * Errno discipline.
 *
 * Drivers throw errors shaped exactly like `node:fs` errors — a POSIX `code`
 * and a libuv-style negative `errno` — so a driver that forwards a real
 * `node:fs` error needs zero translation, and the transports can map any
 * driver error onto the wire with `errnoOf()`.
 */

/**
 * Common POSIX error codes with their **Linux** errno values (positive, as in
 * `<asm-generic/errno.h>`).
 *
 * Note that `node:fs` (and libuv) report these *negated* on `error.errno`:
 * `ENOENT` is `2` here and `-2` on a Node error object. `fsError()` follows
 * the Node convention; `errnoOf()` converts back.
 */
export const ERRNO_CODES = {
  EPERM: 1,
  ENOENT: 2,
  EINTR: 4,
  EIO: 5,
  ENXIO: 6,
  EBADF: 9,
  EAGAIN: 11,
  ENOMEM: 12,
  EACCES: 13,
  EBUSY: 16,
  EEXIST: 17,
  EXDEV: 18,
  ENODEV: 19,
  ENOTDIR: 20,
  EISDIR: 21,
  EINVAL: 22,
  ENFILE: 23,
  EMFILE: 24,
  EFBIG: 27,
  ENOSPC: 28,
  ESPIPE: 29,
  EROFS: 30,
  EMLINK: 31,
  ERANGE: 34,
  ENAMETOOLONG: 36,
  ENOSYS: 38,
  ENOTEMPTY: 39,
  ELOOP: 40,
  ENODATA: 61,
  EPROTO: 71,
  EOVERFLOW: 75,
  ENOTSUP: 95,
  /**
   * Not a code `node:fs` can produce — libuv has no name for it — but the one
   * POSIX answer for "that handle names something that no longer exists",
   * which is exactly what a transport owes the kernel for a forgotten nodeid.
   */
  ESTALE: 116,
  EDQUOT: 122,
} as const;

export type ErrnoCode = keyof typeof ERRNO_CODES;

/** Message fragments, matching libuv's `uv_strerror` (and so Node's). */
const ERRNO_MESSAGES: Record<ErrnoCode, string> = {
  EPERM: "operation not permitted",
  ENOENT: "no such file or directory",
  EINTR: "interrupted system call",
  EIO: "i/o error",
  ENXIO: "no such device or address",
  EBADF: "bad file descriptor",
  EAGAIN: "resource temporarily unavailable",
  ENOMEM: "not enough memory",
  EACCES: "permission denied",
  EBUSY: "resource busy or locked",
  EEXIST: "file already exists",
  EXDEV: "cross-device link not permitted",
  ENODEV: "no such device",
  ENOTDIR: "not a directory",
  EISDIR: "illegal operation on a directory",
  EINVAL: "invalid argument",
  ENFILE: "file table overflow",
  EMFILE: "too many open files",
  EFBIG: "file too large",
  ENOSPC: "no space left on device",
  ESPIPE: "invalid seek",
  EROFS: "read-only file system",
  EMLINK: "too many links",
  ERANGE: "result too large",
  ENAMETOOLONG: "name too long",
  ENOSYS: "function not implemented",
  ENOTEMPTY: "directory not empty",
  ELOOP: "too many symbolic links encountered",
  ENODATA: "no data available",
  EPROTO: "protocol error",
  EOVERFLOW: "value too large for defined data type",
  ENOTSUP: "operation not supported on socket",
  ESTALE: "stale file handle",
  EDQUOT: "disk quota exceeded",
};

/** An error shaped like a `node:fs` error. */
export interface FsError extends Error {
  code: string;
  /** Negative libuv-style errno, e.g. `-2` for `ENOENT`. */
  errno: number;
  syscall?: string;
  path?: string;
  dest?: string;
}

export interface FsErrorOptions {
  /** Overrides the generated `CODE: description, syscall 'path'` message. */
  message?: string;
  syscall?: string;
  path?: string;
  dest?: string;
  cause?: unknown;
}

/**
 * Create an error indistinguishable from the one `node:fs` throws.
 *
 * ```ts
 * throw fsError("ENOENT", { syscall: "stat", path: "/missing" });
 * // ENOENT: no such file or directory, stat '/missing'
 * ```
 */
export function fsError(code: ErrnoCode, options: FsErrorOptions = {}): FsError {
  let message = options.message;
  if (message === undefined) {
    message = `${code}: ${ERRNO_MESSAGES[code]}`;
    if (options.syscall) {
      message += `, ${options.syscall}`;
    }
    if (options.path !== undefined) {
      message += ` '${options.path}'`;
    }
    if (options.dest !== undefined) {
      message += ` -> '${options.dest}'`;
    }
  }
  const error = new Error(
    message,
    options.cause === undefined ? undefined : { cause: options.cause },
  ) as FsError;
  error.code = code;
  error.errno = -ERRNO_CODES[code];
  if (options.syscall !== undefined) {
    error.syscall = options.syscall;
  }
  if (options.path !== undefined) {
    error.path = options.path;
  }
  if (options.dest !== undefined) {
    error.dest = options.dest;
  }
  return error;
}

/**
 * The `RangeError` `node:fs` throws for bad `offset` / `length` / `position`
 * arguments. Not an errno error: argument validation fails before any
 * filesystem is involved, and callers distinguish it by `code`.
 */
export function rangeError(name: string, expected: string, value: number): RangeError {
  const error = new RangeError(
    `The value of "${name}" is out of range. It must be ${expected}. Received ${value}`,
  ) as RangeError & { code: string };
  error.code = "ERR_OUT_OF_RANGE";
  return error;
}

/** Is this a `node:fs`-shaped error (optionally of a specific code)? */
export function isFsError(error: unknown, code?: ErrnoCode): error is FsError {
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const candidate = error as Partial<FsError>;
  if (typeof candidate.code !== "string" || typeof candidate.errno !== "number") {
    return false;
  }
  return code === undefined || candidate.code === code;
}

/**
 * The positive Linux errno for any error, for transports that must reply with
 * one. Unknown errors become `EIO`, which is the only safe default: a request
 * that never gets a reply hangs the mountpoint.
 */
export function errnoOf(error: unknown): number {
  if (typeof error === "object" && error !== null) {
    const candidate = error as Partial<FsError>;
    if (typeof candidate.code === "string" && candidate.code in ERRNO_CODES) {
      return ERRNO_CODES[candidate.code as ErrnoCode];
    }
    if (typeof candidate.errno === "number" && candidate.errno !== 0) {
      return Math.abs(candidate.errno);
    }
  }
  return ERRNO_CODES.EIO;
}
