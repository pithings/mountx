/**
 * Build the addon, then embed it in a JavaScript file. `pnpm build:native`.
 *
 * One command with two halves, and no way to run half of it: the binaries and
 * the embed are the same artifact in two forms, and a flag that rebuilt one
 * without the other would exist only to leave them disagreeing.
 *
 * The `zig build` half is the same one `build.zig` has always done: both
 * prebuilts, cross-compiled from any host, into `native/prebuilt/`. The second
 * half is why this script exists. A `.node` file is loaded by *path*, and a
 * path is the one thing an application bundle does not have: bundlers rewrite
 * module graphs, not sibling binaries, so `new URL("./prebuilt/...")` resolves
 * relative to wherever the bundle landed and finds nothing. Embedding the
 * bytes in a module turns the addon into something a bundler already knows how
 * to carry — text in the graph — and `prebuilt.mjs` unpacks itself at load
 * time. See the header this writes for what "unpacks itself" costs.
 *
 * The bytes are brotli'd before they are base64'd, which is most of the file:
 * ~15 KB of addon is ~20 KB of base64 and ~8 KB of compressed base64, in a
 * module every install downloads and every bundle carries. It costs one
 * `brotliDecompressSync` — ~0.1 ms, once per process, and only in a process
 * that mounts unprivileged at all.
 *
 * What comes out is generated code and is written as such: no prose, no JSDoc,
 * no imports. The reasoning for every line of it lives here instead — see
 * {@link generate} — because a generated file carrying explanations is a file
 * someone eventually edits in place, and the explanation and the generator then
 * disagree with nobody to notice.
 *
 * `prebuilt.mjs` is the *only* committed and published form of the addon —
 * `native/prebuilt/` is a gitignored build output — so it has to be
 * reproducible: no timestamps, no host details, every brotli parameter named
 * rather than defaulted (see {@link pack}), and the targets emitted in sorted
 * order. Rebuilding without touching `native/src/` leaves the file
 * byte-unchanged, which is what makes "did the addon actually change?" a
 * readable diff. Compression puts one thing outside that guarantee — a Node
 * upgrade carrying a different libbrotli re-encodes bytes it did not change —
 * so the sha256 written above each payload is of the *decompressed* file, and
 * answers the question even on the diff where the base64 churned.
 *
 * @module
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompressSync, brotliDecompressSync, constants } from "node:zlib";

/** `native/`, wherever the repository is checked out. */
const HERE = fileURLToPath(new URL(".", import.meta.url));
const PREBUILT_DIR = join(HERE, "prebuilt");
const GENERATED = join(HERE, "prebuilt.mjs");

/** `mountx-linux-x64.node` → `linux-x64`; anything else is not ours. */
const PREBUILT_NAME = /^mountx-(.+)\.node$/;

function main(): void {
  zigBuild();
  const targets = collect();
  if (targets.length === 0) {
    throw new Error(`zig build wrote no mountx-*.node into ${PREBUILT_DIR}`);
  }
  writeFileSync(GENERATED, generate(targets));
  for (const target of targets) {
    console.log(
      `  ${target.key.padEnd(14)} ${String(target.bytes.length).padStart(6)} bytes` +
        ` → ${String(target.packed.length).padStart(6)} brotli`,
    );
  }
  console.log(`embedded ${targets.length} prebuilt(s) in ${GENERATED}`);
}

/** `zig build --prefix prebuilt`, from `native/`, output passed through. */
function zigBuild(): void {
  try {
    execFileSync("zig", ["build", "--prefix", "prebuilt"], { cwd: HERE, stdio: "inherit" });
  } catch (error) {
    const cause = error instanceof Error ? error.message : String(error);
    throw new Error(
      `zig build failed (${cause}). Zig is only needed to change the addon — ` +
        `the built copy in native/prebuilt.mjs is committed and is what ships, ` +
        `so nobody who is not editing native/src/ has to install anything.`,
      { cause: error },
    );
  }
}

interface Target {
  /** `${process.platform}-${process.arch}`, the key the loader computes. */
  key: string;
  /** The `.node` file as `zig build` wrote it. */
  bytes: Buffer;
  /** The same bytes, brotli'd; what actually gets embedded. */
  packed: Buffer;
}

/** Every `prebuilt/mountx-*.node`, sorted, so the output is a function of them. */
function collect(): Target[] {
  // `existsSync` because this runs after `zig build`, not instead of it: an
  // absent directory here means the build silently produced nothing, and
  // `main()` says so more usefully than an `ENOENT` stack would.
  return (existsSync(PREBUILT_DIR) ? readdirSync(PREBUILT_DIR) : []).sort().flatMap((name) => {
    const match = PREBUILT_NAME.exec(name);
    if (match === null) {
      return [];
    }
    const key = match[1]!;
    const bytes = readFileSync(join(PREBUILT_DIR, name));
    const packed = pack(bytes);
    // Decoding what was just encoded costs a fraction of a millisecond and
    // covers the one failure this script can commit and publish without
    // noticing: a payload that no longer unpacks to the addon. Every other
    // check of the embed needs a `prebuilt/` to compare against, and outside
    // this machine there is never one.
    if (!brotliDecompressSync(packed).equals(bytes)) {
      throw new Error(`brotli round trip changed ${name}`);
    }
    return [{ key, bytes, packed }];
  });
}

/**
 * Brotli, with every parameter named.
 *
 * Nothing here is defaulted, because the payload has to be a function of the
 * input bytes and the library version and nothing else — a default that moves
 * between Node releases is a default that rewrites the committed file. The
 * size hint is what tells brotli it is compressing ~7 KB and not a stream.
 *
 * Maximum quality: this runs only when `native/src/` changes and costs ~20 ms
 * per binary, against a file that is downloaded on every install and parsed on
 * every bundle. Decompression does not care what quality produced the stream —
 * ~0.1 ms either way — so the slow setting is free where it is spent.
 */
function pack(bytes: Buffer): Buffer {
  return brotliCompressSync(bytes, {
    params: {
      [constants.BROTLI_PARAM_MODE]: constants.BROTLI_MODE_GENERIC,
      [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY,
      [constants.BROTLI_PARAM_LGWIN]: constants.BROTLI_MAX_WINDOW_BITS,
      [constants.BROTLI_PARAM_SIZE_HINT]: bytes.length,
    },
  });
}

/**
 * The generated module.
 *
 * Written already formatted the way `oxfmt` would leave it, since `pnpm lint`
 * checks this file like any other and a generated file that fails the linter
 * is a generated file someone edits by hand.
 *
 * It has no `import` statements. `prebuilt.mjs` sits on the *static* import
 * path of `mountx/fuse` (`mount.ts` → `fusermount.ts` → `native.ts` →
 * `#unfs/native`), so every consumer pays its module loads — including the
 * ones that mount as root, mount over NFS, or never mount at all, none of
 * which run a line of it. Statically importing `node:os` and `node:zlib` for
 * that cost ~0.5 ms of the ~1.5 ms this module took to import, against ~0.05 ms
 * for the 13 KB of base64 itself. `process.getBuiltinModule` moves that to the
 * call sites without making anything async — `loadNative()` is sync by design —
 * and, unlike `createRequire`, it is a property access no bundler has to
 * understand.
 *
 * What the emitted functions are for, since they no longer say so themselves:
 *
 * - `embeddedNative(key)` reverses {@link pack} — base64, then brotli — and
 *   returns bytes identical to `prebuilt/mountx-<key>.node`, or `undefined`
 *   where no addon for `key` was embedded.
 * - `loadEmbedded(key)` is self-extracting in the literal sense: it writes
 *   those bytes into a directory of its own (`mkdtemp`, mode 0700), `dlopen`s
 *   them, and removes the file and the directory before returning. Deleting a
 *   mapped library is safe — the mapping holds the inode, not the name — so
 *   nothing is left to clean up later, to collide with another process, or to
 *   be swapped underneath us between the write and the `dlopen`. It is *not*
 *   memoized; `loadNative()` in `index.mjs` is the caching entry point.
 * - `extractionDirs()` is a list because `/tmp` is `noexec` on some hardened
 *   hosts, and a mapping that may not be executed is not a loadable library:
 *   a `dlopen` failure from one directory is a reason to try the next rather
 *   than to give up. `MOUNTX_NATIVE_DIR` is the escape hatch for a host where
 *   neither default works.
 *
 * The comment above each payload stays, and is the one piece of the output
 * that is not code: the sha256 is of the *decompressed* bytes, so an entry can
 * be checked against the binary it came from even on a diff where a different
 * libbrotli re-encoded the base64 without changing what it encodes.
 */
function generate(targets: Target[]): string {
  const payloads = targets
    .map((target) => {
      const digest = createHash("sha256").update(target.bytes).digest("hex");
      // The value on its own indented line is not decoration: it is where
      // `oxfmt` puts a string this long, and `pnpm fmt` runs over the output.
      return (
        `  // ${target.key} — ${target.bytes.length} bytes (${target.packed.length} brotli), sha256 ${digest}\n` +
        `  ${JSON.stringify(target.key)}:\n` +
        `    ${JSON.stringify(target.packed.toString("base64"))},`
      );
    })
    .join("\n");
  return `${HEADER}
export const PAYLOADS = {
${payloads}
};

export function nativeKey() {
  return \`\${process.platform}-\${process.arch}\`;
}

export function embeddedNative(key = nativeKey()) {
  const payload = PAYLOADS[key];
  if (payload === undefined) {
    return undefined;
  }
  const { brotliDecompressSync } = process.getBuiltinModule("node:zlib");
  return brotliDecompressSync(Buffer.from(payload, "base64"));
}

export function loadEmbedded(key = nativeKey()) {
  const bytes = embeddedNative(key);
  if (bytes === undefined) {
    throw new Error(
      \`mountx: no native helper is embedded for \${key} (embedded: \${Object.keys(PAYLOADS).join(", ")})\`,
    );
  }
  const { mkdtempSync, rmSync, writeFileSync } = process.getBuiltinModule("node:fs");
  const { join } = process.getBuiltinModule("node:path");
  const failures = [];
  for (const base of extractionDirs()) {
    let dir;
    try {
      dir = mkdtempSync(join(base, "mountx-"));
    } catch (error) {
      failures.push(\`\${base}: \${error.message}\`);
      continue;
    }
    try {
      const file = join(dir, \`mountx-\${key}.node\`);
      writeFileSync(file, bytes, { mode: 0o500 });
      const loaded = { exports: {} };
      process.dlopen(loaded, file);
      return loaded.exports;
    } catch (error) {
      failures.push(\`\${dir}: \${error.message}\`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  throw new Error(\`mountx: could not extract the native helper for \${key}: \${failures.join("; ")}\`);
}

function extractionDirs() {
  const { homedir, tmpdir } = process.getBuiltinModule("node:os");
  const configured = process.env.MOUNTX_NATIVE_DIR;
  return configured ? [configured, tmpdir(), homedir()] : [tmpdir(), homedir()];
}
`;
}

/**
 * The banner, and the whole of the output that is not code or a payload.
 *
 * Two lines: what wrote this and how to write it again. Everything the file
 * used to explain about itself is in this script now — {@link generate} says
 * why — and the pointer above is what gets a reader there.
 */
const HEADER = `// Generated by native/build.ts
`;

main();
