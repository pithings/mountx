/**
 * The one native thing this library has, in the shape the rest of it expects.
 *
 * Rootless mounting goes through `fusermount3`, which returns `/dev/fuse` over
 * `SCM_RIGHTS`, and Node cannot `recvmsg` a descriptor. `native/src/main.zig`
 * closes exactly that gap and nothing else.
 *
 * Finding and `dlopen`ing the binary is `#unfs/native` (`native/index.mjs`),
 * which is a separate, unbundled file because locating a sibling of the addon
 * relative to `import.meta.url` only works from a file that is still where it
 * was written. This module is the part that has opinions: it turns the addon's
 * raw positive `errno` into a `node:fs`-shaped error, so the errno table stays
 * transcribed exactly once, in `src/errors.ts`.
 *
 * **Nothing here is on the root-mode path.** `mount()` as root opens
 * `/dev/fuse` itself and spawns `mount(8)`, and never imports this module — so
 * a host with no prebuilt for its platform loses unprivileged mounting and
 * nothing else, and the pure-JS story stays true for everyone who is not using
 * it.
 */

import { loadNative as dlopenNative, type NativeBinding, nativePath } from "#unfs/native";
import { ERRNO_CODES, type ErrnoCode } from "../errors.ts";

export type { NativeBinding };
export { nativePath };

/** `errno` → `code`, the inverse of {@link ERRNO_CODES}. */
const CODE_BY_ERRNO = new Map<number, ErrnoCode>(
  Object.entries(ERRNO_CODES).map(([code, errno]) => [errno, code as ErrnoCode]),
);

let wrapped: NativeBinding | undefined;

/** Load the addon and give its errors the shape everything else here uses. */
export function loadNative(): NativeBinding {
  wrapped ??= wrap(dlopenNative());
  return wrapped;
}

/** Is unprivileged mounting even possible in this process? */
export function nativeAvailable(): boolean {
  try {
    loadNative();
    return true;
  } catch {
    return false;
  }
}

/**
 * Give the addon's errors the shape `node:fs` uses.
 *
 * The Zig side reports a raw positive `errno` and the syscall's name, because
 * the errno table is transcribed once and having a second copy of it in
 * another language is how the two drift. Here it becomes a negative `errno`
 * and — when `ERRNO_CODES` names it — a POSIX `code`, so these errors are
 * indistinguishable from any other error in the library and `errnoOf()`
 * understands them either way, since it falls back to the `errno`.
 */
function wrap(binding: NativeBinding): NativeBinding {
  return {
    socketpair: () => call(() => binding.socketpair()),
    sendFd: (socket, fd) => call(() => binding.sendFd(socket, fd)),
    recvFd: (socket, timeoutMs) => call(() => binding.recvFd(socket, timeoutMs)),
  };
}

function call<T>(fn: () => T): T {
  try {
    return fn();
  } catch (error) {
    throw annotate(error);
  }
}

function annotate(error: unknown): unknown {
  if (!(error instanceof Error)) {
    return error;
  }
  const errno = (error as NodeJS.ErrnoException).errno;
  if (typeof errno !== "number" || errno <= 0) {
    return error;
  }
  const annotated = error as NodeJS.ErrnoException;
  // Only when the table names it. `ERRNO_CODES` is the filesystem set, and
  // these three syscalls can raise socket errnos that are not in it (`EPIPE`,
  // `ENOTSOCK`, `EMSGSIZE`, `ECONNRESET`, ...). Assigning the lookup
  // unconditionally would leave `code` present-but-`undefined`, which reads as
  // "this error has no code" to `in` and as a failed match to every comparison
  // — a shape no `node:fs` error ever has. Leaving the property off is the
  // truthful version of the same fact, and `errno` still carries the detail.
  const code = CODE_BY_ERRNO.get(errno);
  if (code !== undefined) {
    annotated.code = code;
  }
  annotated.errno = -errno;
  return annotated;
}
