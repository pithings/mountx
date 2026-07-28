Keep important information about project in AGENTS.md. For more detailed info, progressively document them in .agents/*.md and reference from this file.

# unimount

Mount a JavaScript filesystem: one driver interface (a subset of
`node:fs/promises`), multiple transports (FUSE first, then NFSv3).
Design source of truth: `IDEA.md`.

- Plan & finalized decisions: `.agents/roadmap.md`
- Verified environment facts (FUSE, sudo, toolchain caveats): `.agents/environment.md`
- pjdfstest results and failure analysis: `.agents/pjdfstest-results.md`

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
- `test/root.sh` runs any Tier-2 file under sudo (absolute node path, raised
  `UV_THREADPOOL_SIZE`, `TMPDIR` redirected so root's vitest caches do not
  accumulate in `/tmp`, `UNIMOUNT_*` variables forwarded through `sudo`'s
  environment reset). `pnpm test:mount` is `sh test/root.sh
test/fuse/mount.test.ts`; see the milestone-5 section for the rest.
  Every Tier-2 file skips itself when not root, so `pnpm test` stays green for
  everyone.

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

## Layout (milestone 5 — validation)

Four oracles, none of which anyone had to author test cases for. All of them
found real bugs; each fix is named in the comment that guards it.

- `test/fuse/differential.ts` + `differential.test.ts` — **the differential
  suite**. One operation script run step-by-step against a real mount of the
  `node:fs` passthrough _and_ against a plain directory, comparing each
  operation's result (or errno) and then the two trees in full, plus the
  mount's own backing directory as a third view. A scripted sequence covers
  everything in the task list; a seeded generator (`UNIMOUNT_DIFF_SEED`,
  `UNIMOUNT_DIFF_OPS`) adds a few hundred more. `pnpm test:differential`.
  A non-root test runs the same script against two plain directories, which is
  what proves the script itself is deterministic and root-independent.
  Not compared, on purpose: `st_dev`/`st_ino` _values_ (the hardlink
  _partition_ is), timestamps in the tree walk (`utimes` is checked as an
  operation result instead), and directory `size`.
- `src/fuse/record.ts` + `test/fuse/record-fixtures.ts` + `replay.test.ts` —
  **record/replay**. `mount({ tap })` tees every byte crossing `/dev/fuse` in
  both directions; `TranscriptRecorder` frames them into a dead-simple file
  (`"UMFT"`, version, then `[dir u8, flags u8, pad u16, len u32le, ts u64le,
bytes]`), and `replayTranscript(session, frames)` feeds the kernel→daemon
  direction back through a fresh session with no root and no kernel.
  `test/fixtures/*.fuse` (~320 KB total) are committed transcripts of `ls -laR`
  - `find`, a write/rename/stat loop, and `tar -xp`; `pnpm record:fixtures`
    re-records them. **Replay asserts protocol invariants, not bytes** — replies
    depend on the driver state that produced them, so a fresh driver cannot
    reproduce them, and comparing would only prove the fixture was recorded
    twice. What is asserted: every request decodes, every request that needs a
    reply gets exactly one addressed to its own `unique`, nothing throws, the
    exactly-once assertions stay silent, counters balance, and the opcode
    histogram still contains what the fixture was recorded for.
- `test/fuse/conformance-mount.test.ts` — **the conformance matrix's FUSE
  column**. The same `test/conformance.ts` suite, run over a real mount of each
  driver with `node:fs` as the client (`test/rooted-node-fs.ts` is the adapter,
  shared with the loopback column). **126/126, no capability skips**: the FUSE
  transport loses nothing either v1 driver has. `pnpm test:conformance:mount`.
- `test/pjdfstest/run.sh` + `run.ts` — **pjdfstest** against a memory-driver
  mount, pinned to commit `ededbeb`. The clone and its build are gitignored;
  the analysis is committed in `.agents/pjdfstest-results.md`. No `prove`
  needed (this host has no `TAP::Harness`): the `.t` files are shell scripts
  printing TAP, and `run.ts` parses it and writes the per-category breakdown.

`pnpm test:root` runs all three Tier-2 vitest files, and is what the CI
`mount` job runs on a stock Linux runner. pjdfstest stays out of CI (~15
minutes, and its output is an analysis rather than a verdict): it runs locally
and its results are committed.

Bugs the oracles found, all fixed:

- **`nlink` was clamped to `≥ 1`** in `fuse_attr`, so `fstat` on an
  unlinked-but-open file said 1 where every real filesystem says 0. (Differential.)
- **`SETATTR` followed symlinks.** A nodeid names an inode, and that inode can
  be a symlink, so the driver call must be the `AT_SYMLINK_NOFOLLOW` one
  (`lchown`/`lutimes`, falling back on `ENOSYS`). `tar -xp` of any archive with
  a forward-pointing symlink in it failed outright. (Found while recording the
  `tar-extract` fixture.)
- **New inodes were owned by the daemon, not the caller.** `fuse_in_header`
  carries the caller's `uid`/`gid` and nothing in `FsDriver` can express them,
  so the session now `lchown`s a freshly created entry to the requester
  (skipped when that is the daemon; quiet on `ENOSYS`/`EPERM`). Without it,
  `default_permissions` denied a file's own creator every subsequent
  operation — hundreds of pjdfstest `EACCES`/`EPERM` failures. Still not done,
  and wanting credentials in the driver interface rather than more patching:
  supplementary groups, and set-gid directory inheritance.
- **`NAME_MAX` was advertised but not enforced.** The kernel only rejects names
  over `FUSE_NAME_MAX` (1024) and expects the server to know its own limit, so
  a driver without one created names its own `statfs` called impossible.
  `checkName` now answers `ENAMETOOLONG` past 255 bytes, the same number the
  `STATFS` reply carries. (pjdfstest, every `02.t`.)
- **Memory driver: a umask out of nowhere.** Its default was `0o022`, so it
  masked a mode the kernel had _already_ masked with the caller's umask —
  using the wrong process's value, and turning `create f 04777` into `04755`.
  Now `0`; a umask belongs to a process, and a driver is not one.
- **Memory driver: `EFBIG`.** `truncate` past what a `Uint8Array` can hold was
  a `RangeError`, which the session could only report as `EIO`.
- Two test-side traps worth remembering: `Buffer.prototype.slice` **does not
  copy** (it is `subarray`), which silently corrupted the first transcripts;
  and `spawn(…, { cwd })` with a `cwd` inside your own mountpoint deadlocks in
  `uv_spawn` — the child `chdir`s before `exec` while the parent blocks on the
  exec pipe, so the `LOOKUP` waits on the only thread that could answer it.
  Both are documented where they bite (`src/fuse/record.ts`, `src/fuse/mount.ts`).

## Layout (milestone 6 — NFSv3 loopback transport, `unimount/nfs`)

The second transport over the same `FsDriver`, and the one that needs no
`/dev/fuse` and no native code — just a TCP socket. Layered exactly like the
FUSE side, and for the same reason: everything above the socket is bytes in,
bytes out, so a JavaScript client built from the same codecs can drive the whole
protocol with **no mount and no root** (IDEA.md, "Tier 1").

- `src/nfs/xdr.ts` — XDR (RFC 4506): `XdrReader`/`XdrWriter`, bounds-checked,
  big-endian, 64-bit fields as `bigint`. **Only `XdrError` escapes a decoder**,
  the same invariant `ProtocolError` has on the FUSE side, and it is fuzzed.
  Every counted read is bounded before it allocates.
- `src/nfs/rpc.ts` — ONC RPC v2 (RFC 5531): call/reply, `AUTH_NONE`/`AUTH_SYS`,
  and TCP record marking (`frameRecord`, `frameFragments`, `RecordAssembler`).
- `src/nfs/constants.ts` + `src/nfs/protocol.ts` — RFC 1813 transcribed. Every
  struct encoded **and** decoded; each codec repeats the XDR declaration it
  implements.
- `src/nfs/handles.ts` — `FileHandleTable` and the readdir cookie scheme.
- `src/nfs/session.ts` — `NfsSession(driver, options)`: `handleCall(bytes)` →
  `Promise<Uint8Array | null>`, answering both programs. Never rejects.
- `src/nfs/server.ts` — `createNfsServer(driver, options)`; the only file here
  that opens a socket. `src/nfs/mount.ts` — `mountNfs()` and `nfsClientProbe()`.
- `src/nfs/index.ts` re-exports `protocol.ts` **by name**, minus the fourteen
  sub-struct helpers (`readFattr`/`writeFattr`, `readSattr`/`writeSattr`, and the
  `post_op_*` / `wcc_data` / `nfstime3` / `specdata3` pairs). Those are what the
  procedure codecs are built from, not something a consumer composes with.
- `src/lock.ts` — `PathLock`, shared with the FUSE session (see below).

Decisions worth not re-litigating:

- **One TCP port, no portmapper.** MOUNT (100005 v3) and NFS (100003 v3) are
  answered on the same socket and the mount command is told so with `port=`
  _and_ `mountport=`, so `rpcbind` is never contacted (IDEA.md).
- **The socket is the security boundary.** `AUTH_SYS` is a uid the client
  asserts, so it is parsed and never believed; the server binds `127.0.0.1` and
  drops non-loopback peers unless `allowRemote` says otherwise. New objects are
  still `lchown`ed to the caller's credentials, the same fix the FUSE session
  needed for the same reason.
- **File handles are 20 bytes**: magic, an 8-byte boot verifier, a 64-bit entry
  id. They are identity-keyed on the driver's `(dev, ino)`, so a handle survives
  `rename` (including a rename of a directory _above_ it) and two hardlinks
  share one. The verifier makes a handle from a previous process `ESTALE`
  instead of aliasing a live entry.
- **Nothing is ever forgotten.** NFSv3 has no `FORGET`, so a handle entry lives
  as long as the server: a real, bounded leak (one per path the client ever
  named) and the honest v1 tradeoff. A generation-stamped LRU is the fix if a
  workload needs one.
- **A handle with no path left is `NFS3ERR_STALE`**, immediately. FUSE keeps an
  unlinked-but-open inode alive because the kernel says the file is open; NFSv3
  never says so. Real clients paper over this with silly-rename, which is a
  _client_-side trick. This is the one capability the transport loses.
- **Readdir cookies** are `index + 1` into a snapshot of the listing, and the
  `cookieverf3` is an FNV-1a hash of the entry names. Two useful consequences: a
  client paging through is unaffected by concurrent changes (the snapshot it is
  reading is cached), and a client whose snapshot was _evicted_ still resumes as
  long as the directory has not changed, because re-listing reproduces the same
  verifier. Only evicted-and-changed gets `NFS3ERR_BAD_COOKIE`.
- **Writes are always `FILE_SYNC`.** The driver has whole-file semantics and no
  writeback, so a resolved `WRITE` is already as durable as it can be; claiming
  `UNSTABLE` would describe a buffer that does not exist. `COMMIT` exists and
  succeeds anyway, because clients send it regardless. One `writeverf3` per
  server instance.
- **`.` and `..` are not in `READDIR`.** RFC 1813 does not require them and the
  Linux client emits its own (`dir_emit_dots`), so a server that adds them makes
  a listing that shows them twice. `LOOKUP` of both still works, and `..` is
  clamped at the export root.
- **`RENAME` takes a writer lock** over the path map, exactly as in the FUSE
  session; `READ` and `WRITE` deliberately run outside it. The lock is now
  **`src/lock.ts`, shared by both sessions** — it was character-identical in the
  two and depends on nothing, so there was never a bundle-size reason to keep
  two copies (an earlier draft of this file claimed there was; there wasn't).
- Not supported, on purpose: `MKNOD` (`NFS3ERR_NOTSUPP` — the driver interface
  cannot express a device node) and `CREATE` with `EXCLUSIVE` (`NFS3ERR_NOTSUPP`
  — the verifier would have to be _stored_ somewhere that survives a retry, and
  Linux falls back to `GUARDED`). NLM locking is out of scope, hence `nolock`.

Tests in `test/nfs/`:

- `client.ts` — the Tier-1 client: RPC over TCP plus one method per procedure,
  and `nfsDriver()`, an `FsDriver` over it that walks paths and follows symlinks
  itself (which is what an NFS client does). The counterpart of
  `test/fuse/synthetic-kernel.ts`.
- `xdr.test.ts`, `protocol.test.ts`, `handles.test.ts`, `golden.test.ts`,
  `fuzz.test.ts` — Tier 0. **The golden fixtures give every field a distinct
  value on purpose**: a fixture built from `uid: 0, gid: 0, size == used,
fsid == fileid` is satisfied by an encoder _and_ decoder that transpose the
  same pair, so the bytes and the round-trips both stay green while the wire
  format is wrong. Mutation testing confirmed it — five symmetric transpositions
  passed the entire suite against the old fixture, and all five fail against the
  new one. Symmetric codecs cannot catch a symmetric mistake; only an asymmetric
  fixture can, and `golden.test.ts` asserts its own 21 words are distinct so the
  property cannot quietly erode.
- `conformance.test.ts` — the conformance matrix's **NFS column**: the same
  `test/conformance.ts` suite over a real socket, both drivers, no root.
  **122/126**, with `handles` off (see above) — that is the whole capability
  loss, and it is declared rather than derived.
- `mount.test.ts` — Tier 2, `pnpm test:nfs:mount`, gated on `nfsClientProbe()`.
  **This host cannot run it**: no `mount.nfs`, no `nfs` in `/proc/filesystems`,
  no loadable modules at all (see `.agents/environment.md`). That is precisely
  why the Tier-1 column carries the weight.

Verified independently: `libnfs`'s `nfs-ls`/`nfs-cp`/`nfs-io` (a real NFSv3
client sharing none of this code) drove a 30-assertion workload, a 3000-entry
readdir and 4 MiB round-trips against the server, and `tshark` dissected the
exchange with no warnings. That is the oracle the Tier-1 column cannot be, since
the Tier-1 client is built from the server's own codecs. Reach for it again when
the wire format changes — see `.agents/environment.md`.

Bugs found while building it, and in review:

- **`XdrWriter` wrote into a discarded buffer whenever it grew.**
  `this.#view.setUint32(this.#room(4), …)` evaluates `this.#view` _before_ the
  call that may replace it. Any message past the initial capacity — a large
  `READ` reply — was silently corrupted or threw a `RangeError`. Fixed by
  taking the offset into a local first, in every scalar writer and in `raw()`.
- **`code in ERRNO_TO_NFS` matched `Object.prototype`.** An error with
  `code: "toString"` looked up a _function_, which the writer coerced to `0` — an
  `NFS3_OK` status word in front of a failure body, so a client's decoder
  desyncs rather than merely getting the wrong answer. `Object.hasOwn` now, and
  the "unmapped becomes `NFS3ERR_IO`" guarantee the module documents is true again.
- **"Decoders copy" was false.** `Buffer.prototype.slice` is `subarray`, so a
  `WRITE` payload reached the driver as a _view of the socket's receive pool_ —
  the identical trap that corrupted the first FUSE transcripts. The three
  `XdrReader` byte-readers go through `Uint8Array.prototype.slice.call` now. The
  framing layer above them still hands out views on purpose, and
  `RecordAssembler.push` says so: records are consumed by decoders that copy what
  they keep, which is the narrowest place the copy has to happen.
- **A reused inode number aliased a handle to a stale path.** Bind `/a`, then
  have something outside the server move it to `/c` and bind that: the entry was
  found by identity, kept `/a` as its primary name, and every operation on the
  `/c` handle landed on whatever `/a` had become. `bind` now drops names a file's
  `nlink` says it cannot still have (oldest first, the just-bound one kept), and
  `pathOf` skips any name the table no longer maps to that entry.
- **The cookie verifier's delimiter was a raw NUL byte in the source**, which
  made `handles.ts` binary to `file(1)` and `grep`. It is `"\0"` now — the
  behaviour was always right, and a test pins `["a b"]` against `["a", "b"]` so a
  tidy-up cannot turn it into a character a filename could contain.

## Layout (milestone 7 — conformance matrix + benchmarks)

Two generated reports, both committed, both regenerable with one command. The
README is written from them and may claim nothing they do not say.

- `test/matrix.ts` (`pnpm matrix`) → **`.agents/conformance-matrix.md`**. Runs
  the three conformance columns that already exist as ordinary vitest files
  (`test/drivers.test.ts`, `test/fuse/conformance-mount.test.ts` through
  `test/root.sh`, `test/nfs/conformance.test.ts`), parses vitest's JSON reporter
  and lays them side by side. The root column skips itself with a reason
  (`UNIMOUNT_MATRIX_SKIP_ROOT=1`, no `/dev/fuse`, no passwordless `sudo`) rather
  than failing. The npm script pipes the output through `oxfmt`, because
  `pnpm lint` formats markdown too and a generated table is not oxfmt-shaped.
  - **A skip's reason lives in the test's name.** A skipped test leaves nothing
    else behind — vitest reports `pending` with no reason — so `conformance()`
    appends `[needs <capability> + …]` to every gated case, whether or not it
    ran, via the `itNeeds`/`describeNeeds` helpers that also compute the skip.
    One call site, so the two cannot drift.
  - **Capability loss is derived, not declared:** a requirement counts as unmet
    in a column when _no_ case naming it passed there. Current answer: FUSE loses
    nothing, NFSv3 loses `handles`, and `root` is an environment fact reported
    separately.
- `bench/` (`pnpm bench`, `pnpm bench:root`) → **`.agents/benchmarks.md`**.
  Scenarios written once against `Loopback` and run in all three columns, the
  same trick the matrix uses. `harness.ts` is a warmup, an adaptive loop and
  percentiles; `--json <path>` writes the machine-readable form. Nothing here
  runs inside `pnpm test`.
  - **`ops/sec` is wall-clock, `p50`/`p99` are the timed bracket**, so `1 / p50`
    is deliberately not `ops/sec`. Dividing throughput by the sum of the samples
    would hand the harness's own ~90 ns of per-iteration bookkeeping to the
    ceiling column for free — nothing against a FUSE round trip, 5–20% on a
    loopback `stat`, and a systematic flattering of the denominator every
    transport is compared against.
  - **The FUSE client is a child process** (`bench/fuse-client.ts`), which is
    what makes it safe to have operations in flight at all — see the threadpool
    note in `src/fuse/mount.ts`.
  - **`bench/fuse.ts` mounts once per negotiation variant** and gives up exactly
    one win each time, which is the measurement IDEA.md calls the proof of its
    central claim. It also samples `session.stats.requests` while the client
    works, because scenario ops/sec undercount the transport (one `stat(2)` is
    two FUSE requests at `entry_timeout = 0`).

What the numbers said, in one line each — the file has the tables and the
caveats:

- **IDEA.md's "low tens of thousands of ops/sec" holds**, at the upper end:
  **41.5–50.3 k FUSE requests/sec** with requests in flight, 13.6 k/s strictly
  sequential. A single-threaded client sees 2–4 k _syscalls_/sec on uncached
  metadata, because each is two to five requests.
- **Negotiation dominates, as claimed.** `attr_timeout`/`entry_timeout` are
  worth 8–15×; `FOPEN_KEEP_CACHE` 4.9× on re-read; `max_write` at 1 MiB only
  ~15–40% against this driver (expect more against one that does real I/O per
  request). Nothing JS-side in this codebase has been worth anything comparable.
- **`FUSE_READDIRPLUS_AUTO` is costing us the readdirplus win.** The kernel only
  uses plus for the _first page_ of a listing under `AUTO`, so a cold 1000-entry
  `ls -l` is 10.3 k entries/s with our defaults and 25.0 k without `AUTO` —
  IDEA.md's predicted 2.4×, currently unclaimed. Dropping `AUTO` costs ~20% on a
  names-only `readdir`. **Not changed** (benchmark milestone, not a defaults
  one); it is the best-supported open question in the repo.
- **`readers` is not a useful knob** with a CPU-bound driver: 1/2/4 readers span
  ~20% (8.1 / 9.5 / 10.0 k ops/s on 64 concurrent stats) across a 4× change, and
  reorder between runs, because every completion lands on the same main thread. The
  modes that would change that (sync-worker, relay) do not exist yet, and
  IDEA.md's "sync-worker should be meaningfully better" stays **unmeasured**.
- **Writeback caching would be worth 2.6× on small writes** and is off on
  purpose; that is what the semantics cost.
- **A real bug, found by the benchmarks:** the memory driver's `resize()`
  reallocated on every growth, so a file arriving in `max_write` chunks cost
  O(n²) — 100 MiB written moved ~5 GiB. The loopback column, which is supposed to
  be the _ceiling_, was slower than the transports it was the denominator for.
  Now geometric with shrink-to-fit; sequential write went 60 → 1,382 MiB/s
  loopback and 53 → 308 MiB/s over NFS, and the `EFBIG` behaviour pjdfstest
  pinned is preserved (doubling first, exact size as the fallback).
