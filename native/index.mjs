/**
 * Finding and loading the prebuilt addon.
 *
 * **This file is deliberately not part of the bundle.** It is plain `.mjs`,
 * shipped verbatim, and imported through the `#unfs/native` subpath so that
 * nothing rewrites it on the way out. That is the whole reason it exists: the
 * binary is located relative to `import.meta.url`, and `import.meta.url` is
 * only trustworthy in a file whose position relative to `prebuilt/` is fixed.
 * Resolving it from `src/` worked by coincidence — `dist/fuse/` happens to sit
 * the same distance from the package root — and would have broken silently the
 * first time the build layout changed.
 *
 * What is *not* here is anything that needs to know what the addon means:
 * `src/fuse/native.ts` does the error reshaping, because the errno table lives
 * in `src/errors.ts` and there is only ever one copy of it.
 *
 * @module
 */

import { fileURLToPath } from "node:url";

/** The prebuilt for the running platform, whether or not it exists. */
export function nativePath() {
  // `fileURLToPath`, not `url.pathname`: a package installed under a path with
  // a space in it is percent-encoded in the URL and would not open.
  return fileURLToPath(
    new URL(`./prebuilt/mountx-${process.platform}-${process.arch}.node`, import.meta.url),
  );
}

let cached;
let failure;

/**
 * Load the addon, once per process.
 *
 * A failure is remembered as well as a success: the answer cannot change while
 * the process runs, and retrying a `dlopen` on every mount attempt would turn
 * one clear error into a stutter.
 */
export function loadNative() {
  if (cached !== undefined) {
    return cached;
  }
  if (failure !== undefined) {
    throw failure;
  }
  const path = nativePath();
  const loaded = { exports: {} };
  try {
    process.dlopen(loaded, path);
  } catch (error) {
    failure = new Error(
      `mountx: could not load the native helper for ${process.platform}-${process.arch} ` +
        `(${path}): ${error instanceof Error ? error.message : String(error)}. ` +
        `It is only needed for unprivileged mounting; mounting as root does not use it. ` +
        `To build it from source: pnpm build:native`,
      { cause: error },
    );
    throw failure;
  }
  cached = loaded.exports;
  return cached;
}
