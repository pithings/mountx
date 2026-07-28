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

import { closeSync, existsSync, openSync, readdirSync, readFileSync, readlinkSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { NativeBinding } from "#unfs/native";
import { afterEach, describe, expect, it } from "vitest";
// Straight to the generated embed, not through `#unfs/native`: `prebuilt.mjs`
// is committed, so it is there in every clone, and nothing in `src/` needs
// these — a re-export in `native/index.mjs` would exist for this file alone.
import { embeddedNative, loadEmbedded, PAYLOADS } from "../../native/prebuilt.mjs";
import { loadNative } from "../../src/fuse/native.ts";

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

/**
 * The addon, or `undefined` on a host with no copy of it that will load.
 *
 * There is one copy — the embed — so there is nothing to name in the title
 * below: `loadNative()` cannot have loaded anything else.
 */
const NATIVE: NativeBinding | undefined = (() => {
  try {
    return loadNative();
  } catch {
    return undefined;
  }
})();

describe.skipIf(NATIVE === undefined)("the native helper", () => {
  const native = NATIVE!;
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

/**
 * The embedded copy — `native/prebuilt.mjs`, generated by `native/build.ts`.
 *
 * This is the only form of the addon that is committed or published, so these
 * tests are the ones that hold for everyone: a clone has no `.node` file to
 * compare against, and no Zig either.
 */
describe("the embedded addon", () => {
  it("has a payload for the platforms we build for", () => {
    expect(Object.keys(PAYLOADS)).toContain("linux-x64");
    expect(Object.keys(PAYLOADS)).toContain("linux-arm64");
  });

  it("answers undefined for a platform with no prebuilt", () => {
    expect(embeddedNative("aix-mips")).toBeUndefined();
  });

  it.skipIf(NATIVE === undefined)("extracts and loads, leaving nothing behind", () => {
    const binding = loadEmbedded() as NativeBinding;
    const [a, b] = binding.socketpair();
    try {
      expect(a).not.toBe(b);
    } finally {
      closeSync(a);
      closeSync(b);
    }
    // The extraction directory is deleted before `loadEmbedded()` returns —
    // the mapping holds the inode, not the name — so `/proc/self/maps` has the
    // library under a path that is already gone.
    expect(readFileSync("/proc/self/maps", "utf8")).toMatch(/mountx-.*\.node.*\(deleted\)/);
  });
});

/** `native/prebuilt/*.node`, sorted; empty in a clone that has not run `zig build`. */
function localBuilds(): { key: string; file: string }[] {
  const dir = fileURLToPath(new URL("../../native/prebuilt/", import.meta.url));
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir)
    .sort()
    .flatMap((name) => {
      const match = /^mountx-(.+)\.node$/.exec(name);
      return match === null ? [] : [{ key: match[1]!, file: join(dir, name) }];
    });
}

const LOCAL = localBuilds();

/**
 * The embed against a local `zig build`, when there is one.
 *
 * `native/prebuilt/` is a build output — gitignored, unpublished — so this only
 * runs for whoever just rebuilt the addon, which is exactly who can make the
 * two disagree: `zig build` on its own rewrites the binaries and leaves the
 * embed behind. `pnpm build:native` does both halves and is the fix.
 *
 * Nothing loads those binaries — the embed is the only copy `loadNative()`
 * knows about — so this comparison is the whole of what says a `zig build` and
 * the addon everything actually runs are the same thing.
 */
describe.skipIf(LOCAL.length === 0)("the embed against the local zig build", () => {
  it("covers every prebuilt in native/prebuilt/", () => {
    expect(Object.keys(PAYLOADS).sort()).toEqual(LOCAL.map((prebuilt) => prebuilt.key));
  });

  // `$key`, not `mountx-$key.node`: vitest reads what follows a `$` as a
  // property path, so the `.node` made it look up `key.node` and print
  // "mountx-undefined" for every platform.
  it.each(LOCAL)("is byte-identical to the prebuilt for $key", ({ key, file }) => {
    // `toEqual` on two ~7 KB buffers, not a hash: when this fails the sizes in
    // the report say which one is stale, and a digest mismatch says nothing.
    expect(embeddedNative(key)).toEqual(readFileSync(file));
  });
});
