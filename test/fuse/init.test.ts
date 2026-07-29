import { describe, expect, it } from "vitest";
import { ERRNO_CODES } from "../../src/errors.ts";
import {
  FUSE_ASYNC_READ,
  FUSE_ATOMIC_O_TRUNC,
  FUSE_CACHE_SYMLINKS,
  FUSE_DO_READDIRPLUS,
  FUSE_EXPORT_SUPPORT,
  FUSE_FLOCK_LOCKS,
  FUSE_INIT_EXT,
  FUSE_KERNEL_MINOR_VERSION,
  FUSE_MAX_PAGES,
  FUSE_PASSTHROUGH,
  FUSE_POSIX_LOCKS,
  FUSE_READDIRPLUS_AUTO,
  FUSE_SETXATTR_EXT,
  FUSE_WRITEBACK_CACHE,
} from "../../src/fuse/constants.ts";
import {
  DEFAULT_MAX_WRITE,
  DEFAULT_WANTED_FLAGS,
  joinInitFlags,
  negotiateInit,
  splitInitFlags,
} from "../../src/fuse/init.ts";
import type { InitPreferences } from "../../src/fuse/init.ts";
import { decodeInitOut, encodeInitOut } from "../../src/fuse/protocol.ts";
import type { FuseInitIn } from "../../src/fuse/protocol.ts";

/** What a 6.12 kernel actually offers, minus the flags we never ask for. */
function kernelInit(overrides: Partial<FuseInitIn> = {}): FuseInitIn {
  const offered = splitInitFlags(
    DEFAULT_WANTED_FLAGS | FUSE_INIT_EXT | FUSE_WRITEBACK_CACHE | FUSE_PASSTHROUGH,
  );
  return {
    major: 7,
    minor: FUSE_KERNEL_MINOR_VERSION,
    maxReadahead: 131_072,
    flags: offered.flags,
    flags2: offered.flags2,
    ...overrides,
  };
}

function ok(kernel: FuseInitIn, preferences?: InitPreferences) {
  const result = negotiateInit(kernel, preferences);
  if (result.status !== "ok") {
    throw new Error(`expected ok, got ${result.status}`);
  }
  return result;
}

describe("flag packing", () => {
  it("joins and splits the two wire words", () => {
    expect(joinInitFlags(0x8000_0000, 0x0000_0003)).toBe(0x0000_0003_8000_0000n);
    expect(splitInitFlags(0x0000_0003_8000_0000n)).toEqual({
      flags: 0x8000_0000,
      flags2: 0x0000_0003,
    });
    expect(splitInitFlags(joinInitFlags(0xff_ff_ff_ff, 0xff_ff_ff_ff))).toEqual({
      flags: 0xff_ff_ff_ff,
      flags2: 0xff_ff_ff_ff,
    });
  });
});

describe("defaults", () => {
  it("agrees 7.41, 1 MiB writes via 256 max_pages, readdirplus on, writeback off", () => {
    const { reply, session } = ok(kernelInit());
    expect(reply.major).toBe(7);
    expect(reply.minor).toBe(FUSE_KERNEL_MINOR_VERSION);
    expect(session.maxWrite).toBe(DEFAULT_MAX_WRITE);
    expect(session.maxWrite).toBe(1024 * 1024);
    expect(session.maxPages).toBe(256);
    expect(reply.maxPages).toBe(256);
    expect(session.readdirplus).toBe(true);
    expect(session.writebackCache).toBe(false);
    expect(session.flags & FUSE_MAX_PAGES).toBe(FUSE_MAX_PAGES);
    expect(session.flags & FUSE_WRITEBACK_CACHE).toBe(0n);
    expect(session.flags & FUSE_DO_READDIRPLUS).toBe(FUSE_DO_READDIRPLUS);
    expect(session.flags & FUSE_READDIRPLUS_AUTO).toBe(FUSE_READDIRPLUS_AUTO);
    expect(session.protocol).toEqual({ minor: 41, setxattrExt: true });
  });

  it("picks a sensible background queue", () => {
    const { reply, session } = ok(kernelInit());
    expect(reply.maxBackground).toBe(64);
    expect(reply.congestionThreshold).toBe(48); // 3/4 of max_background
    expect(session.maxBackground).toBe(64);
    expect(reply.timeGran).toBe(1); // nanoseconds
  });

  it("never claims a flag the kernel did not offer", () => {
    const { session } = ok(kernelInit({ flags: 0, flags2: 0 }));
    expect(session.flags).toBe(0n);
    expect(session.readdirplus).toBe(false);
    expect(session.setxattrExt).toBe(false);
    expect(session.maxPages).toBe(0);
  });

  it("takes the kernel's max_readahead unless asked for less", () => {
    expect(ok(kernelInit({ maxReadahead: 4096 })).session.maxReadahead).toBe(4096);
    expect(ok(kernelInit(), { maxReadahead: 8192 }).session.maxReadahead).toBe(8192);
    // A larger preference cannot raise the kernel's ceiling.
    expect(
      ok(kernelInit({ maxReadahead: 4096 }), { maxReadahead: 1 << 20 }).session.maxReadahead,
    ).toBe(4096);
  });

  it("round-trips its reply through the codec", () => {
    const { reply } = ok(kernelInit());
    expect(decodeInitOut(encodeInitOut(reply))).toEqual(reply);
  });
});

describe("version handling", () => {
  it("clamps to the kernel's minor when the kernel is older", () => {
    const { reply, session } = ok(kernelInit({ minor: 31 }));
    expect(reply.minor).toBe(31);
    expect(session.minor).toBe(31);
    expect(session.protocol.minor).toBe(31);
    expect(reply.maxStackDepth).toBe(0); // 7.40+ field
    expect(reply.flags2).toBe(0); // 7.36+ field
  });

  it("clamps to our minor when the kernel is newer", () => {
    expect(ok(kernelInit({ minor: 99 })).reply.minor).toBe(FUSE_KERNEL_MINOR_VERSION);
    expect(ok(kernelInit({ minor: 99 }), { minor: 31 }).reply.minor).toBe(31);
  });

  it("drops max_background and time_gran on pre-7.13 / pre-7.23 kernels", () => {
    const old = ok(kernelInit({ minor: 12 }));
    expect(old.reply.maxBackground).toBe(0);
    expect(old.reply.congestionThreshold).toBe(0);
    expect(old.reply.timeGran).toBe(0);
    expect(ok(kernelInit({ minor: 22 })).reply.timeGran).toBe(0);
    expect(ok(kernelInit({ minor: 23 })).reply.timeGran).toBe(1);
  });

  it("pins max_write to one page below 7.5, where the field does not exist", () => {
    const { session } = ok(kernelInit({ minor: 4 }));
    expect(session.maxWrite).toBe(4096);
    expect(encodeInitOut(ok(kernelInit({ minor: 4 })).reply).length).toBe(8);
  });

  it("asks the kernel to retry when it speaks a newer major", () => {
    const result = negotiateInit(kernelInit({ major: 8 }));
    expect(result.status).toBe("retry");
    if (result.status !== "retry") {
      throw new Error("unreachable");
    }
    expect(result.reply.major).toBe(7);
    expect(result.reply.minor).toBe(FUSE_KERNEL_MINOR_VERSION);
    // fuse.h: reply with our version and wait for a second INIT.
    expect(encodeInitOut(result.reply).length).toBe(64);
  });

  it("errors with EPROTO on a pre-7.0 major", () => {
    const result = negotiateInit(kernelInit({ major: 6 }));
    expect(result).toEqual({ status: "error", errno: ERRNO_CODES.EPROTO });
  });

  it("ignores flags2 unless the kernel set FUSE_INIT_EXT", () => {
    const split = splitInitFlags(DEFAULT_WANTED_FLAGS | FUSE_PASSTHROUGH);
    const withoutExt = ok(
      kernelInit({ flags: split.flags & ~Number(FUSE_INIT_EXT), flags2: split.flags2 }),
      { extraFlags: FUSE_PASSTHROUGH },
    );
    expect(withoutExt.session.flags & FUSE_PASSTHROUGH).toBe(0n);
    expect(withoutExt.reply.flags2).toBe(0);

    const withExt = ok(kernelInit(), { extraFlags: FUSE_PASSTHROUGH });
    expect(withExt.session.flags & FUSE_PASSTHROUGH).toBe(FUSE_PASSTHROUGH);
    // Claiming a flags2 bit requires echoing FUSE_INIT_EXT.
    expect(withExt.session.flags & FUSE_INIT_EXT).toBe(FUSE_INIT_EXT);
    expect(withExt.reply.flags2).toBe(splitInitFlags(FUSE_PASSTHROUGH).flags2);
  });

  it("does not set FUSE_INIT_EXT when no high bit is used", () => {
    expect(ok(kernelInit()).session.flags & FUSE_INIT_EXT).toBe(0n);
  });
});

describe("max_write and max_pages", () => {
  it("clamps a huge request to FUSE_MAX_MAX_PAGES", () => {
    const { reply, session } = ok(kernelInit(), { maxWrite: 64 * 1024 * 1024 });
    expect(session.maxPages).toBe(256);
    expect(session.maxWrite).toBe(1024 * 1024);
    expect(reply.maxPages).toBe(256);
    expect(reply.maxWrite).toBe(1024 * 1024);
  });

  it("falls back to 128 KiB without FUSE_MAX_PAGES", () => {
    const offered = splitInitFlags(DEFAULT_WANTED_FLAGS & ~FUSE_MAX_PAGES);
    const { reply, session } = ok(kernelInit({ flags: offered.flags, flags2: offered.flags2 }));
    expect(session.maxPages).toBe(0);
    expect(session.maxWrite).toBe(128 * 1024); // FUSE_DEFAULT_MAX_PAGES_PER_REQ * 4096
    expect(reply.maxPages).toBe(0);
    expect(session.flags & FUSE_MAX_PAGES).toBe(0n);
  });

  it("falls back to 128 KiB on a pre-7.28 kernel even if the flag is set", () => {
    const { session } = ok(kernelInit({ minor: 27 }));
    expect(session.maxPages).toBe(0);
    expect(session.maxWrite).toBe(128 * 1024);
  });

  it("rounds a small max_write up to a whole page", () => {
    expect(ok(kernelInit(), { maxWrite: 100 }).session.maxWrite).toBe(4096);
    expect(ok(kernelInit(), { maxWrite: 0 }).session.maxWrite).toBe(4096);
    expect(ok(kernelInit(), { maxWrite: 8193 }).session.maxPages).toBe(3);
    expect(ok(kernelInit(), { maxWrite: 8193 }).session.maxWrite).toBe(8193);
  });

  it("keeps max_background inside its uint16", () => {
    const { reply } = ok(kernelInit(), { maxBackground: 1e9, congestionThreshold: 1e9 });
    expect(reply.maxBackground).toBe(0xff_ff);
    expect(reply.congestionThreshold).toBe(0xff_ff);
  });
});

describe("preferences", () => {
  it("turns readdirplus off", () => {
    const { session } = ok(kernelInit(), { readdirplus: false });
    expect(session.readdirplus).toBe(false);
    expect(session.flags & (FUSE_DO_READDIRPLUS | FUSE_READDIRPLUS_AUTO)).toBe(0n);
  });

  it("turns writeback cache on when explicitly asked", () => {
    const { session } = ok(kernelInit(), { writebackCache: true });
    expect(session.writebackCache).toBe(true);
    expect(session.flags & FUSE_WRITEBACK_CACHE).toBe(FUSE_WRITEBACK_CACHE);
  });

  it("clears a flag that a replacement set but a boolean turned off", () => {
    const { session } = ok(kernelInit(), {
      flags: DEFAULT_WANTED_FLAGS | FUSE_WRITEBACK_CACHE,
      writebackCache: false,
    });
    expect(session.writebackCache).toBe(false);
    expect(session.flags & FUSE_WRITEBACK_CACHE).toBe(0n);
  });

  it("never asks for the three flags the session cannot serve", () => {
    // `posixLocks`/`flockLocks`/`exportSupport` used to be booleans on
    // `InitPreferences`. They were deleted: the session answers the lock
    // opcodes `ENOSYS` and `checkName` rejects `.` and `..`, so their only
    // reachable effect was to break a mount. The defaults must not ask for
    // them, whatever this kernel happens to offer.
    expect(DEFAULT_WANTED_FLAGS & FUSE_POSIX_LOCKS).toBe(0n);
    expect(DEFAULT_WANTED_FLAGS & FUSE_FLOCK_LOCKS).toBe(0n);
    expect(DEFAULT_WANTED_FLAGS & FUSE_EXPORT_SUPPORT).toBe(0n);

    const kernel = kernelInit({
      flags: splitInitFlags(
        joinInitFlags(kernelInit().flags, kernelInit().flags2) |
          FUSE_POSIX_LOCKS |
          FUSE_FLOCK_LOCKS |
          FUSE_EXPORT_SUPPORT,
      ).flags,
    });
    const { session } = ok(kernel);
    expect(session.posixLocks).toBe(false);
    expect(session.flockLocks).toBe(false);
    expect(session.exportSupport).toBe(false);
    expect(session.flags & (FUSE_POSIX_LOCKS | FUSE_FLOCK_LOCKS | FUSE_EXPORT_SUPPORT)).toBe(0n);
  });

  it("still reports the three as a readback when extraFlags asks for them", () => {
    // The readback fields stayed: they say what the kernel *agreed to*, which
    // is what the deliberate `extraFlags` escape hatch needs in order to be
    // usable at all. A readback cannot fake a capability.
    const kernel = kernelInit({
      flags: splitInitFlags(
        joinInitFlags(kernelInit().flags, kernelInit().flags2) | FUSE_POSIX_LOCKS,
      ).flags,
    });
    const { session } = ok(kernel, { extraFlags: FUSE_POSIX_LOCKS | FUSE_FLOCK_LOCKS });
    expect(session.posixLocks).toBe(true);
    // Asked for, but this kernel did not offer it — so it is not claimed.
    expect(session.flockLocks).toBe(false);
  });

  it("exposes cacheSymlinks, the one opt-in the session can serve", () => {
    const kernel = kernelInit({
      flags: splitInitFlags(
        joinInitFlags(kernelInit().flags, kernelInit().flags2) | FUSE_CACHE_SYMLINKS,
      ).flags,
    });
    expect(ok(kernel, { cacheSymlinks: true }).session.cacheSymlinks).toBe(true);
    expect(ok(kernel).session.cacheSymlinks).toBe(false);
  });

  it("accepts a wholesale flag replacement", () => {
    const wanted = FUSE_ASYNC_READ | FUSE_ATOMIC_O_TRUNC;
    const kernel = kernelInit({
      flags: splitInitFlags(
        FUSE_ASYNC_READ | FUSE_ATOMIC_O_TRUNC | FUSE_CACHE_SYMLINKS | FUSE_EXPORT_SUPPORT,
      ).flags,
      flags2: 0,
    });
    expect(ok(kernel, { flags: wanted }).session.flags).toBe(wanted);
  });

  it("subtracts withoutFlags last", () => {
    const { session } = ok(kernelInit(), {
      extraFlags: FUSE_WRITEBACK_CACHE,
      withoutFlags: FUSE_WRITEBACK_CACHE | FUSE_SETXATTR_EXT,
    });
    expect(session.flags & FUSE_WRITEBACK_CACHE).toBe(0n);
    expect(session.setxattrExt).toBe(false);
    expect(session.protocol.setxattrExt).toBe(false);
  });

  it("is pure: same input, same output", () => {
    const kernel = kernelInit();
    expect(negotiateInit(kernel, { maxWrite: 65_536 })).toEqual(
      negotiateInit(kernel, { maxWrite: 65_536 }),
    );
    expect(kernel).toEqual(kernelInit());
  });
});
