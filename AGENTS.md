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

## Layout (milestone 4 — FUSE transport, root mode)

- `src/fuse/mount.ts` — the only file that opens a device or spawns a process.
  `mount(driver, mountpoint, options)` → `Mount` (`unmount()`, `closed`,
  `session`, `notifyInval*`, `Symbol.asyncDispose`), plus `unmountAll()` and
  `liveMounts()`. Exported from `unimount/fuse` only: putting `mount` on the
  root would pull the session and `node:child_process` into every
  `import … from "unimount"`, and the root `mount` should be the
  transport-picking facade once there is more than one transport to pick.
- `pnpm test:mount` runs the Tier-2 suite (root, `TMPDIR` redirected so root's
  vitest caches do not accumulate in `/tmp`):
  `sudo env TMPDIR=… UV_THREADPOOL_SIZE=32 "$(which node)" node_modules/vitest/vitest.mjs run test/fuse/mount.test.ts`.
  `test/fuse/mount.test.ts` skips itself when not root, so `pnpm test` stays
  green for everyone.

How it works, and the parts that are load-bearing:

- **Mounting is `mount(8)`.** `openSync('/dev/fuse')`, then
  `mount -i -t fuse -o fd=N,rootmode=…,user_id=…,group_id=…,default_permissions <fsname> <mountpoint>`
  with the fd placed **at its own number** in the child's stdio array (it is
  ~17, never 3). `rootmode` is octal and comes from the driver's root `stat`.
  The source argument is the `fsname` (default `unimount`); `subtype=x` in the
  options — not `-t fuse.x`, which only works because libmount splits it back
  apart — is what makes `/proc/mounts` say `fuse.x`. Both are rejected if they
  contain a comma or an equals sign, which would inject mount options.
- **The loop:** K reads (`readers`, default 2) outstanding on the fd, each
  completion dispatched into `session.handleMessage` **without** awaiting, the
  buffer re-armed as soon as that call returns. That is safe because the
  session decodes (and copies) everything before its first `await` — a contract
  with its own non-root test. One preallocated buffer per reader, sized
  `max_write + 4 KiB`. Replies are written with **`writeSync`**: a write to
  `/dev/fuse` never blocks, and every `fs.write` would take a threadpool thread
  away from the readers and the driver.
- **The threadpool is the whole concurrency story** until relay mode exists.
  Each outstanding read parks one of `UV_THREADPOOL_SIZE` (4) threads, and so
  does every `fs` call the driver makes. Worse, a process that is _also a
  client_ of its own mount parks a thread per in-flight operation: reach the
  pool limit and it wedges (main thread idle in `epoll_wait`, every pool thread
  in `request_wait_answer`). `fs.rm(dir, { recursive: true })` alone does it on
  a 200-entry tree. Documented at the top of `mount.ts`; the mount tests obey
  it by deleting sequentially.
- **Teardown, both directions.** `unmount()` spawns `umount(8)` (root only, so
  `fusermount3 -u` is the unprivileged milestone's problem, not a fallback here)
  and then waits for the loop: the kernel aborts the connection, every read
  returns `ENODEV`, and only then does the transport call `session.destroy()`,
  drain the outstanding reads and close the fd — closing it under a parked read
  would leave callbacks pointing at a reusable fd number. Someone else's
  `umount` arrives at the same place from the other end. `unmount()` is
  idempotent, concurrency-safe and retryable after a failure;
  `SIGINT`/`SIGTERM` handlers (one pair per process, removed with the last
  mount, so a second Ctrl-C kills) unmount everything, `console.error` whatever
  failed, and re-raise.
- **Teardown has a deadline** (`unmountTimeout`, default 10 s), because every
  step of it waits on a driver that may have stopped answering: `umount(8)`
  quiesces the filesystem first, so an unanswered request blocks it in `D`
  state and `unmount()` with it. On expiry the connection is forced down with
  **`umount -f`** — and that is the one that works. Closing the fd aborts a
  connection _only when no read is outstanding_: a parked `read(2)` holds a
  reference to the open file, so `fuse_dev_release` never runs (verified: still
  mounted two seconds after the close, `umount` still blocked). `umount -f`
  goes in the other end, `fuse_umount_begin` → `fuse_abort_conn`, failing every
  request in flight, after which the parked reads return `ENODEV` and the
  normal path finishes. Its exit status lies while another `umount` races it
  ("target is busy", status 32, mount gone anyway) — believe `/proc/self/mounts`.
  `umount -l` is the last resort for a table entry that outlives the abort.
- **Mounting over a live mountpoint is refused**, in both directions (this
  process's own mounts, and a FUSE mount in `/proc/self/mounts`). Linux stacks
  mounts happily, and then `umount` detaches the _top_ one — so the second
  mount's teardown kills the first mount's connection and then waits forever
  for its own.
- **Crash safety:** the connection dies with the last reference to the fd, so a
  killed process leaves a mountpoint that answers `ENOTCONN`, not one that
  hangs. Nothing else may hold that fd — it is `O_CLOEXEC` and goes to exactly
  one child, `mount(8)`. Without `fusermount3` there is no `-o auto_unmount`,
  so the stale mount table entry does survive: `sudo umount -l <mountpoint>`.
- **`process.exit()` does not work with a mount up.** Node's exit path joins the
  threadpool and the K reads are parked in it (measured: 25 s and still going,
  needed a `SIGKILL`). `await unmount()` and set `process.exitCode`; the signal
  handlers re-raise the signal for exactly this reason.
- **Errno conventions on the wire:** `ENOENT` from a reply write means the
  request was interrupted — drop it. `ENODEV` (either direction) means
  unmounted → tear down. `EINTR`/`EAGAIN`/`ENOENT` on a read → re-arm.
- **`/sys/fs/fuse/connections` is empty in this container**, so the fusectl
  `abort` file is not an option here even though it is the documented one.
