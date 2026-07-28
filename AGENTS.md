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

## Layout (milestone 3 — FUSE session layer, also `unimount/fuse`)

Still no I/O: `handleMessage(bytes)` → `Promise<Uint8Array | null>`. The
transport that carries those bytes is milestone 4.

- `src/fuse/session.ts` — `FuseSession(driver, options)`. `INIT` handshake,
  opcode `switch`, file-handle table, readdir paging, `SETATTR` bitmask →
  driver calls, `StatsLike` → `fuse_attr`, notify encoders.
- `src/fuse/inodes.ts` — `InodeTable`: nodeid ↔ path ↔ `(dev, ino)`, lookup
  refcounting, subtree remap on rename, orphans. **Entirely synchronous**, so
  every mutation is atomic between awaits.
- `src/fuse/notify.ts` — `notify_inval_inode` / `notify_inval_entry` codecs
  (`fuse_out_header` with `unique == 0`, `error` = the notify code).

Invariants worth not breaking:

- **Exactly one reply per request.** `FORGET`, `BATCH_FORGET` and
  `NOTIFY_REPLY` get none; everything else is answered, and any thrown value
  becomes a negative errno (`errnoOf`, unknown → `EIO`). `handleMessage` never
  rejects. A dev-mode assertion tracks it per `unique` (`session.assertions`,
  `session.stats`).
- **Inodes are identified by the driver's `(dev, ino)`**, which is what makes
  hardlinks one nodeid and lets `LINK` reply with the existing one. A changed
  `ino` at a known path allocates a _new_ nodeid rather than aliasing.
- **Nothing is serialized except `RENAME`**, which takes a writer lock (subtree
  remap) that path resolution waits on. Revisit at the benchmark milestone.
- Unimplemented opcodes, `INTERRUPT` and `ACCESS` answer `-ENOSYS`; a forgotten
  nodeid answers `ESTALE`.
- **An unlinked-but-open inode is still stattable.** `fuse_getattr` /
  `fuse_setattr` are `inode_operations` hooks, so a plain `fstat(2)` or
  `ftruncate(2)` on an open fd arrives with **no** `FUSE_GETATTR_FH` /
  `FATTR_FH` — the session falls back to any live handle on the inode before it
  will answer `ENOENT`. Getting this wrong breaks every `mkstemp`+`unlink`
  program. Only ops with no handle-based equivalent (`chmod`, `chown`,
  `utimes`) still answer `ENOENT` once the last name is gone.
- **Teardown belongs to the transport.** A `-t fuse` mount **never receives
  `FUSE_DESTROY`** — `fuse_init_fs_context` sets `ctx->destroy` only for
  `fuseblk`, and a live `umount(8)` ends with `STATFS` as the last opcode. The
  session handles `DESTROY` anyway (for the mounts that do send it), but
  milestone 4 must call `session.destroy()` itself when `/dev/fuse` hits EOF or
  `ENODEV`. It is idempotent and safe with requests in flight.

Tests: `test/fuse/synthetic-kernel.ts` (the other side of the session, built
from the same codecs — encodes requests, decodes replies, tracks `unique` and
per-nodeid lookup counts), `session.test.ts`, `inodes.test.ts`,
`session-fuzz.test.ts` (bytes in → never a rejection, never a missing reply).
