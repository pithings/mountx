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

## Layout (milestone 2 — FUSE protocol layer, `unimount/fuse`)

Pure data transformation: no I/O, no `/dev/fuse`, no mount, runs on any OS.

- `src/fuse/constants.ts` — opcodes, `FUSE_*` / `FOPEN_*` / `FATTR_*` / `DT_*`
  and the compat struct sizes. **Transcribed from the Linux kernel's
  `include/uapi/linux/fuse.h` at tag v6.12 (protocol 7.41)**, which is what
  this host's kernel speaks. Nothing is guessed; each codec repeats the C
  declaration with byte offsets.
- `src/fuse/protocol.ts` — every struct encoded **and** decoded (the symmetry
  is what makes a synthetic kernel and record/replay possible), the opcode
  dispatch table (`OPCODES`), whole-message framing, errno-on-the-wire helpers,
  and dirent packing (`DirentPacker`).
- `src/fuse/init.ts` — `negotiateInit(kernelInit, preferences)`, pure.

Conventions inside the protocol layer:

- **Every 64-bit wire field is a `bigint`**, every smaller one a `number`;
  `padding` / `dummy` fields are not modelled, so `decode(encode(x))` is `x`.
- **Only `ProtocolError` escapes a decoder** — that invariant is fuzzed, and it
  is what keeps a malformed message from hanging a mountpoint.
- Version-dependent layouts go through `ProtocolContext { minor, setxattrExt }`;
  `FUSE_INIT` alone is decoded from its own length (nothing is negotiated yet).
- Negotiation defaults: `max_write` 1 MiB via 256 `max_pages`, readdirplus on,
  writeback cache **off**, `max_background` 64.

Tests live in `test/fuse/`: `random.ts` (seeded PRNG + per-opcode generators),
`protocol.test.ts` (round-trips, framing, compat layouts), `golden.test.ts`
(hand-verified hex fixtures), `dirent.test.ts`, `init.test.ts`, `fuzz.test.ts`.
