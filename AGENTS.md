Keep important information about project in AGENTS.md. For more detailed info, progressively document them in .agents/*.md and reference from this file.

# unimount

Mount a JavaScript filesystem: one driver interface (a subset of
`node:fs/promises`), multiple transports (FUSE first, then NFSv3).
Design source of truth: `IDEA.md`.

- Plan & finalized decisions: `.agents/roadmap.md`
- Verified environment facts (FUSE, sudo, toolchain caveats): `.agents/environment.md`

Conventions: pure JS/TS, zero runtime deps, pure-JS-first (no native code in
v1). Single package with subpath exports. Small conventional commits to
`main`, tests green (`pnpm test`) before each commit.

## Layout (milestone 1)

- `src/types.ts` — `FsDriver` (a subset of `node:fs/promises`; `node:fs/promises`
  itself is assignable to it), `FsCapabilities`, the typed-only `unimount.*`
  extension namespace, and the structural `StatsLike`/`DirentLike`/
  `FileHandleLike` shapes Node's own types satisfy.
- `src/errors.ts` — `ERRNO_CODES` (Linux values), `fsError()` producing errors
  byte-identical to `node:fs`'s (negative `errno`, same message), `errnoOf()`
  for transports.
- `src/path.ts` — absolute POSIX path helpers; `..` is clamped at the root.
- `src/harness.ts` — `createLoopback(driver)`: normalizes paths, fills in
  missing methods with `ENOSYS`, resolves capabilities. What driver authors
  test against.
- `src/drivers/memory.ts`, `src/drivers/node-fs.ts` — the two v1 drivers. The
  passthrough resolves every path component itself so nothing escapes its root.
- `test/conformance.ts` — the one Tier-0 suite, run against both drivers and
  raw `node:fs/promises` from `test/drivers.test.ts`.
