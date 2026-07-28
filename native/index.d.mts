/**
 * Types for `#unfs/native`. The implementation is `native/index.mjs`, which is
 * plain JavaScript on purpose — see the note at the top of it.
 */

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

/** The prebuilt for the running platform, whether or not it exists. */
export function nativePath(): string;

/** Load the addon, once per process. Throws with a message naming the file. */
export function loadNative(): NativeBinding;
