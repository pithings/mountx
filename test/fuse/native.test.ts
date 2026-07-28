/**
 * The native helper, on its own.
 *
 * Passing a descriptor over a socket needs no `fusermount3`, no mountpoint and
 * no privileges — it is two processes' worth of kernel machinery that happens
 * to be reachable from one — so the whole of `native/src/main.zig` is Tier 0.
 * That matters more than it looks: it means the cmsg arithmetic, the
 * close-on-exec flags and the error shapes stay covered on every host, and the
 * Tier-2 rootless suite is left proving only that `fusermount3` was driven
 * correctly.
 *
 * `sendFd` exists for this file. Nothing in the library calls it.
 */

import { closeSync, openSync, readFileSync, readlinkSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { loadNative, nativeAvailable, nativePath } from "../../src/fuse/native.ts";

/** `O_CLOEXEC`, as `/proc/self/fdinfo/<n>` reports it. */
const O_CLOEXEC = 0o2000000;

/** The file status flags the kernel has on `fd`, close-on-exec included. */
function fdFlags(fd: number): number {
  const info = readFileSync(`/proc/self/fdinfo/${fd}`, "utf8");
  const match = /^flags:\s*(\d+)$/m.exec(info);
  if (match === null) {
    throw new Error(`no flags line in fdinfo for fd ${fd}`);
  }
  return Number.parseInt(match[1]!, 8);
}

/** The inode `/proc/self/fdinfo/<n>` reports, identifying the open file. */
function inodeOf(fd: number): string {
  const info = readFileSync(`/proc/self/fdinfo/${fd}`, "utf8");
  const match = /^ino:\s*(\d+)$/m.exec(info);
  if (match === null) {
    throw new Error(`no ino line in fdinfo for fd ${fd}`);
  }
  return match[1]!;
}

describe.skipIf(!nativeAvailable())(`the native helper (${nativePath()})`, () => {
  const native = nativeAvailable() ? loadNative() : undefined!;
  const open: number[] = [];

  /** Remember an fd so a failing assertion cannot leak it. */
  function track(fd: number): number {
    open.push(fd);
    return fd;
  }

  function pair(): [number, number] {
    const [a, b] = native.socketpair();
    return [track(a), track(b)];
  }

  afterEach(() => {
    for (const fd of open.splice(0)) {
      try {
        closeSync(fd);
      } catch {
        // Already closed by the test, which several of them do on purpose.
      }
    }
  });

  describe("socketpair", () => {
    it("returns two distinct descriptors", () => {
      const [a, b] = pair();
      expect(a).toBeGreaterThanOrEqual(0);
      expect(b).toBeGreaterThanOrEqual(0);
      expect(a).not.toBe(b);
    });

    it("makes both ends close-on-exec", () => {
      const [a, b] = pair();
      expect(fdFlags(a) & O_CLOEXEC).toBe(O_CLOEXEC);
      expect(fdFlags(b) & O_CLOEXEC).toBe(O_CLOEXEC);
    });
  });

  describe("the round trip", () => {
    it("delivers a descriptor for the same open file", () => {
      const [a, b] = pair();
      const original = track(openSync("/dev/null", "r"));
      native.sendFd(b, original);
      const received = track(native.recvFd(a, 1000));

      expect(received).not.toBe(original);
      expect(readlinkSync(`/proc/self/fd/${received}`)).toBe("/dev/null");
      // The same *open file description*, not a reopen — which is the whole
      // reason `fusermount3` has to pass a descriptor rather than a path.
      // Reopening `/dev/fuse` would get a second, unconnected FUSE channel.
      expect(inodeOf(received)).toBe(inodeOf(original));
    });

    it("receives it close-on-exec", () => {
      const [a, b] = pair();
      const original = track(openSync("/dev/null", "r"));
      // `FD_CLOEXEC` is a property of the descriptor, not of the open file
      // description, so it cannot cross a socket. The flag on the copy below
      // can only have come from `MSG_CMSG_CLOEXEC`.
      native.sendFd(b, original);
      const received = track(native.recvFd(a, 1000));
      expect(fdFlags(received) & O_CLOEXEC).toBe(O_CLOEXEC);
    });

    it("carries descriptors in order, one per message", () => {
      const [a, b] = pair();
      const first = track(openSync("/dev/null", "r"));
      const second = track(openSync("/dev/zero", "r"));
      native.sendFd(b, first);
      native.sendFd(b, second);

      const one = track(native.recvFd(a, 1000));
      const two = track(native.recvFd(a, 1000));
      expect(readlinkSync(`/proc/self/fd/${one}`)).toBe("/dev/null");
      expect(readlinkSync(`/proc/self/fd/${two}`)).toBe("/dev/zero");
    });
  });

  describe("failure", () => {
    it("times out when nothing is sent", () => {
      const [a] = pair();
      expect(() => native.recvFd(a, 20)).toThrow(/timed out/);
    });

    it("reports a closed peer as such, not as a timeout", () => {
      const [a, b] = pair();
      closeSync(b);
      expect(() => native.recvFd(a, 1000)).toThrow(/closed without sending/);
    });

    it("gives a bad descriptor the shape of a node:fs error", () => {
      // 2^30 is far past any fd this process could have open, and small enough
      // to stay an int32.
      const error = (() => {
        try {
          native.recvFd(2 ** 30, 20);
          return undefined;
        } catch (thrown) {
          return thrown as NodeJS.ErrnoException;
        }
      })();
      expect(error).toBeDefined();
      expect(error!.code).toBe("EBADF");
      expect(error!.errno).toBe(-9);
      expect(error!.syscall).toBe("recvmsg");
    });

    it("refuses a non-numeric descriptor", () => {
      expect(() => (native.recvFd as unknown as (a: unknown, b: unknown) => number)({}, 0)).toThrow(
        /must be numbers/,
      );
    });
  });
});
