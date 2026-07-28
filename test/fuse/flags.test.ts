/**
 * Wire `O_*` → driver `O_*`, Tier 0.
 *
 * The interesting host is the one that disagrees with Linux, so darwin's values
 * are written out here and checked from any host — the same trick
 * `test/nfs/mount-options.test.ts` uses for the platform difference it covers.
 */

import { constants } from "node:fs";
import { describe, expect, it } from "vitest";
import * as wire from "../../src/fuse/constants.ts";
import { driverOpenFlags, translateOpenFlags } from "../../src/fuse/flags.ts";

/** `sys/fcntl.h`, macOS 15. The whole reason this module exists. */
const DARWIN = {
  O_CREAT: 0o1000,
  O_EXCL: 0o4000,
  O_TRUNC: 0o2000,
  O_APPEND: 0o10,
} as const;

/** `asm-generic/fcntl.h`, the values `constants.ts` transcribes. */
const LINUX = {
  O_CREAT: wire.O_CREAT,
  O_EXCL: wire.O_EXCL,
  O_TRUNC: wire.O_TRUNC,
  O_APPEND: wire.O_APPEND,
} as const;

describe("translateOpenFlags", () => {
  it("carries the access mode through untouched", () => {
    for (const mode of [wire.O_RDONLY, wire.O_WRONLY, wire.O_RDWR]) {
      expect(translateOpenFlags(mode, DARWIN)).toBe(mode);
    }
  });

  it("maps each named bit to the host's value for it", () => {
    expect(translateOpenFlags(wire.O_CREAT, DARWIN)).toBe(DARWIN.O_CREAT);
    expect(translateOpenFlags(wire.O_EXCL, DARWIN)).toBe(DARWIN.O_EXCL);
    expect(translateOpenFlags(wire.O_TRUNC, DARWIN)).toBe(DARWIN.O_TRUNC);
    expect(translateOpenFlags(wire.O_APPEND, DARWIN)).toBe(DARWIN.O_APPEND);
  });

  it("translates the combinations a kernel actually sends", () => {
    // `open(path, "w")`: O_WRONLY|O_CREAT|O_TRUNC.
    expect(translateOpenFlags(wire.O_WRONLY | wire.O_CREAT | wire.O_TRUNC, DARWIN)).toBe(
      constants.O_WRONLY | DARWIN.O_CREAT | DARWIN.O_TRUNC,
    );
    // `open(path, "ax")`: O_WRONLY|O_CREAT|O_EXCL|O_APPEND.
    expect(
      translateOpenFlags(wire.O_WRONLY | wire.O_CREAT | wire.O_EXCL | wire.O_APPEND, DARWIN),
    ).toBe(constants.O_WRONLY | DARWIN.O_CREAT | DARWIN.O_EXCL | DARWIN.O_APPEND);
  });

  it("is the identity when the host's values are Linux's", () => {
    const all = wire.O_RDWR | wire.O_CREAT | wire.O_EXCL | wire.O_TRUNC | wire.O_APPEND;
    expect(translateOpenFlags(all, LINUX)).toBe(all);
  });

  it("drops a bit it does not name rather than reinterpreting the number", () => {
    // Linux's `O_NOFOLLOW` is `0o400000`; darwin's is `0o400`. Nothing here
    // claims to map it, so it does not travel — carrying the Linux number over
    // would set some unrelated darwin bit.
    const O_NOFOLLOW_LINUX = 0o400_000;
    expect(translateOpenFlags(wire.O_RDONLY | O_NOFOLLOW_LINUX, DARWIN)).toBe(wire.O_RDONLY);
  });

  it("never confuses macOS's O_TRUNC with Linux's O_APPEND", () => {
    // The bug this exists to prevent: the two numbers are the same, so a
    // verbatim hand-off turns `> file` into `>> file`.
    expect(DARWIN.O_TRUNC).toBe(wire.O_APPEND);
    expect(translateOpenFlags(wire.O_TRUNC, DARWIN) & DARWIN.O_APPEND).toBe(0);
    expect(translateOpenFlags(wire.O_APPEND, DARWIN) & DARWIN.O_TRUNC).toBe(0);
  });
});

describe("driverOpenFlags", () => {
  it("forwards everything verbatim on Linux, unnamed bits included", () => {
    const O_NOATIME_LINUX = 0o1_000_000;
    const flags = wire.O_RDWR | wire.O_TRUNC | O_NOATIME_LINUX;
    expect(driverOpenFlags(flags, "linux", DARWIN)).toBe(flags);
  });

  it("translates on every other host", () => {
    expect(driverOpenFlags(wire.O_WRONLY | wire.O_TRUNC, "darwin", DARWIN)).toBe(
      constants.O_WRONLY | DARWIN.O_TRUNC,
    );
  });

  it("defaults to this host, and agrees with node:fs about it", () => {
    // Whatever host this is, the result has to be what `node:fs` would resolve:
    // on Linux by passing through, elsewhere by translating.
    expect(driverOpenFlags(wire.O_WRONLY | wire.O_CREAT | wire.O_TRUNC)).toBe(
      constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC,
    );
  });
});
