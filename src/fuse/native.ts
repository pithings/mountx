/**
 * Loading the one native thing this library has.
 *
 * Rootless mounting goes through `fusermount3`, which returns `/dev/fuse` over
 * `SCM_RIGHTS`, and Node cannot `recvmsg` a descriptor. `native/src/main.zig`
 * closes exactly that gap and nothing else; this file finds the prebuilt,
 * loads it once, and reshapes its errors into the ones the rest of the library
 * already speaks.
 *
 * **Nothing here is on the root-mode path.** `mount()` as root opens
 * `/dev/fuse` itself and spawns `mount(8)`, and never imports this module — so
 * a host with no prebuilt for its platform loses unprivileged mounting and
 * nothing else, and the pure-JS story stays true for everyone who is not using
 * it.
 */

import { arch, platform } from "node:process";
import { ERRNO_CODES, type ErrnoCode } from "../errors.ts";

/** What `native/src/main.zig` exports. */
export interface NativeBinding {
  /**
   * `socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)`.
   *
   * Both ends come back close-on-exec. The end a child needs is handed to it
   * through the stdio map, which clears the flag on the copy it makes; every
   * other spawn in the process is unaffected, which is the point.
   */
  socketpair(): [number, number];
  /**
   * Send one descriptor, with the one byte of payload `unix(7)` requires.
   *
   * The library never calls this — `fusermount3` is the sender. It exists so
   * the round trip can be tested in one process with no helper, no mountpoint
   * and no privileges.
   */
  sendFd(socket: number, fd: number): void;
  /**
   * Receive one descriptor, `O_CLOEXEC`, waiting at most `timeoutMs` for it
   * (negative waits forever).
   *
   * The close-on-exec part is load-bearing: the kernel tears a FUSE connection
   * down when the last reference to the `/dev/fuse` file goes away, which is
   * what makes a killed server leave a mountpoint that answers `ENOTCONN`
   * instead of one that hangs. A descriptor leaked into an unrelated child
   * would be exactly such a reference.
   */
  recvFd(socket: number, timeoutMs: number): number;
}

/** `errno` → `code`, the inverse of {@link ERRNO_CODES}. */
const CODE_BY_ERRNO = new Map<number, ErrnoCode>(
  Object.entries(ERRNO_CODES).map(([code, errno]) => [errno, code as ErrnoCode]),
);

/** The prebuilt for the running platform, whether or not it exists. */
export function nativePath(): URL {
  return new URL(`../../native/prebuilt/mountx-${platform}-${arch}.node`, import.meta.url);
}

let cached: NativeBinding | undefined;
let failure: Error | undefined;

/**
 * Load the addon, once per process.
 *
 * A failure is remembered as well as a success: the answer cannot change while
 * the process runs, and retrying a `dlopen` on every mount attempt would turn
 * one clear error into a stutter.
 */
export function loadNative(): NativeBinding {
  if (cached !== undefined) {
    return cached;
  }
  if (failure !== undefined) {
    throw failure;
  }
  const path = nativePath();
  const loaded = { exports: {} as NativeBinding };
  try {
    process.dlopen(loaded, path.pathname);
  } catch (error) {
    failure = new Error(
      `mountx: could not load the native helper for ${platform}-${arch} ` +
        `(${path.pathname}): ${error instanceof Error ? error.message : String(error)}. ` +
        `It is only needed for unprivileged mounting; mounting as root does not use it. ` +
        `To build it from source: pnpm build:native`,
      { cause: error },
    );
    throw failure;
  }
  cached = wrap(loaded.exports);
  return cached;
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
 * the errno table is transcribed once, in `src/errors.ts`, and having a second
 * copy of it in another language is how the two drift. Here it becomes a
 * negative `errno` and a POSIX `code`, so these errors are indistinguishable
 * from any other error in the library and `errnoOf()` understands them.
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
  annotated.code = CODE_BY_ERRNO.get(errno);
  annotated.errno = -errno;
  return annotated;
}
