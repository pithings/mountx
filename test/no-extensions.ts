/**
 * A driver with the `mountx.*` namespace taken off.
 *
 * Every session has two paths through `MKNOD`/`Tmknod`/`CREATE`: the extension
 * when the driver has it, and a refusal (or the regular-file fallback) when it
 * does not. The bundled memory driver implements `mountx.mknod`, so it can no
 * longer stand for the second one — this is what the cases about *that* path
 * are written against, so they keep testing the session rather than the driver
 * that happens to be handy.
 *
 * Not a `*.test.ts` file: it is imported by several.
 */

import type { FsDriver } from "../src/types.ts";

/** The same driver, minus `mountx` — the key itself, not just its members. */
export function withoutExtensions<T extends FsDriver>(driver: T): Omit<T, "mountx"> {
  // Dropped rather than set to `undefined`: `resolveCapabilities` infers
  // `extensions` from the *keys* of `mountx`, so a present-but-empty namespace
  // would still be a claim.
  const { mountx: _extensions, ...rest } = driver;
  return rest;
}
