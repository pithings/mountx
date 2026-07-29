# mountx v1 roadmap

Design source of truth: `IDEA.md`. Environment facts: `.agents/environment.md`.

## v1 shipped

All 7 planned milestones are done (commits `8609d65..97e7ba9`, 2026-07-27/28):
the driver interface and its two drivers, the FUSE protocol/session/root-mode
transport, the validation suites (differential, record/replay, pjdfstest),
NFSv3 loopback, and the conformance matrix + benchmark suite the README is
drawn from. See `AGENTS.md` for the current code map and invariants, and
`.agents/conformance-matrix.md` / `.agents/benchmarks.md` for the generated
results.

## Shipped since v1

- **Unprivileged FUSE mounting** (2026-07-28). `mount()` picks its path by
  uid; non-root goes through `fusermount3`, whose `SCM_RIGHTS` reply is
  received by a ~7 KB Zig Node-API addon in `native/` — three functions,
  the only native code in the repository, lazily loaded and never on the
  root path. `pnpm test:rootless` is the Tier-2 column that needs no sudo.
  What was _not_ done, deliberately: no user-namespace mode (a mount made
  in one is invisible outside its mount namespace, so it serves "mount for
  my own process tree" and not much else), and no setuid binary of our own
  (it would mean reimplementing `fusermount3`'s security model — ownership
  checks, `allow_other` gating, `fuse.conf`, mtab — in a binary running as
  root, to save one package dependency).

- **`mountx/auto`** (2026-07-28). The transport chooser `src/index.ts`
  predicted, as its own subpath rather than the root export: `probeTransports()`
  publishes what each transport can do here and why not, `mount()` takes the
  first usable one in preference order (FUSE on Linux — root _or_ rootless —
  NFS otherwise), and both transports arrive through `await import()` so
  choosing one never loads the other's codec. The returned object is the
  transport's own mount with a `transport` discriminant defined on it, so
  narrowing reaches every transport-specific member and `await using` is
  unaffected. Two refusals are part of the design: no fallback after a mount
  failure (the probe decides from host facts, once — a silent second attempt
  would hand back different semantics than the error nobody saw), and no probe
  at all when a transport is named. Options are a shared subset plus
  `fuse: {…}`/`nfs: {…}` escape hatches, because the two transports'
  same-named options are genuinely different shapes.

- **Unprivileged NFS mounting on macOS** (2026-07-28). It turned out to need no
  new code at all: `/sbin/mount_nfs` is not setuid and holds no entitlement,
  because macOS is a BSD and a BSD lets an ordinary user mount onto a directory
  that user owns. The `mount(8)` spawn `mountNfs()` already makes works verbatim
  as uid 501 — the kernel just forces `MNT_NOSUID|MNT_NODEV` and records
  `mounted by <user>`. The only thing standing in the way was our own
  `nfsClientProbe()`, which asked for root unconditionally.
  So: the root requirement is now Linux's (where an unprivileged `mount(8)`
  needs an `fstab` entry marked `user`, which a library cannot arrange), and the
  macOS precondition — _the caller owns the mountpoint_ — is checked at mount
  time by `ownershipRefusal()`, because it is a fact about a path rather than
  about the host. `mountx/auto` therefore picks NFS on macOS for a non-root
  process instead of refusing, and `pnpm test:rootless` runs the NFS mount
  column plus `mountx/auto` there with no sudo.
  The NetFS route was investigated and rejected: `open nfs://…` has no handler
  at all on 26.6 (`kLSApplicationNotFoundErr`), and `NetFSMountURLSync` parses a
  URL port into `kNetFSAlternatePortKey` and then never reads it — it goes to
  port 111 and fails `ECONNREFUSED`, which for a server with no portmapper is
  fatal. Options can only reach `mount_nfs` through a `?options=` query string.
  It buys exactly one thing, `/Volumes` mountpoints, and costs FFI; see
  "Future / deferred".

- **S3 gateway transport, `mountx/s3`** (commits `3d582b7..4cd9d64`, 2026-07-28/29,
  plan in `.agents/s3-plan.md`). A transport over the same `FsDriver`,
  and the first that is not a mount: `createS3Server(driver, opts?)` — or
  `createS3Server({ buckets: { name: driver, ... } })` for several — serves it
  to any S3 client (`rclone`, the AWS CLI, an SDK, a presigned URL) over
  path-style HTTP. Layered the way FUSE and NFS are (`sigv4.ts`, `xml.ts`,
  `chunked.ts`, `protocol.ts`, `session.ts`, `server.ts`), every constant and
  error code transcribed from Amazon's own docs since there is no RFC for S3.
  SigV4 is signed _and_ verified, both the header and presigned-query forms,
  against the official `aws-sig-v4-test-suite` goldens. Ships with a Tier-1
  conformance column (`test/s3/conformance.test.ts`: a signing JS client plus an
  `FsDriver` adapter over it, no sockets, folded into `pnpm matrix`) and a
  no-root oracle (`test/s3/oracle.test.ts`) that drives real `rclone` and `curl`
  binaries — gated on both being on `PATH`, needing no root — through
  copy/sync/check/multipart/presigned-URL round trips against a real `node-fs`
  driver.

  Design decisions worth restating, each a place a client could see a
  difference from Amazon's own service:
  - **Gateway, not mount** — kept out of `mountx/auto` on purpose: auto's
    whole contract is a mountpoint, and this transport never produces one.
  - **Derived ETags** — first 32 hex characters of sha256 over
    `dev:ino:size:mtimeMs`, suffixed `-1` so the shape itself says "not an
    MD5"; `rclone check` reads it exactly that way and falls back to
    size/modtime instead of reporting a mismatch.
  - **Multipart staging is invisible** — parts live under
    `.mountx-multipart/<uploadId>/`, a 404 to every other operation and absent
    from every listing, swept on abort and on `close()`.
  - **Write-in-place, first-byte atomic only** — the driver interface has no
    primitive to stage a whole object elsewhere first; a rejection at or
    before the first byte leaves the bucket untouched, one after leaves a
    partial object where a whole one used to be.

  What was _not_ done, deliberately: `mountx/drivers/s3` (mounting a real
  bucket as a driver, reusing `test/s3/client.ts`'s signing client rather than
  writing a second one) is a named follow-up, not part of this effort; no
  bench column (perf claims come only from `.agents/benchmarks.md`, so the
  docs for this transport make none); `ListObjects` (V1), bucket ACLs/policies
  and versioning all answer a well-formed `NotImplemented` rather than being
  faked.

- **The 9P2000.L transport, `mountx/9p`** (2026-07-29). A third transport
  beside FUSE and NFS, over the same `FsDriver`: wire primitives and the whole
  `.L` message set both directions (`src/9p/wire.ts`/`constants.ts`/
  `protocol.ts`, transcribed from `include/net/9p/9p.h` v6.12), a fid table
  (keyed by fid; qid identity is what is keyed `(dev, ino)`, `fids.ts`), a
  session with no I/O
  (`session.ts`), and `createP9Server` — TCP, unix-socket and an
  `attach(duplex)` mode for embedders, one session per connection. `mount9p()`
  mounts locally over `trans=unix` — a private `mkdtemp` socket the kernel
  connects to itself, needing no native code — and `trans=tcp` reaches
  external clients, the VM-guest case, gated to dotted-quad IPv4 by the
  kernel's own `valid_ipaddr4()`. `mountx/auto`'s Linux preference is now
  `["fuse", "9p", "nfs"]`: 9P beats NFS whenever both need root, because it is
  **stateful** — a fid survives an unlink (no `ESTALE`), `close()`/`fsync()`
  reach the driver for real, and the fid table cannot leak the way NFSv3's
  handle table does. `-t 9p` works from the CLI, and `p9ClientProbe()` +
  `p9ModuleRefusal()` keep `auto` from choosing 9P on a virtio-only guest
  where the mount would fail. **Witnessed real, locally, under sudo on this
  dev host** the same day the code landed (`.agents/environment.md`'s "9P
  mounting" section): a 3 MiB byte-exact round trip, unlink-while-open, locks,
  a 1500-entry directory, rename-with-open-fd, executing a binary off the
  mount, clean teardown across three mount/unmount cycles, no leaks. An
  independent tshark oracle (`test/9p/dissect.test.ts`) found one defect —
  Wireshark's own 9P dissector, not this transport's (`Tgetlock`/`Rgetlock`
  misaligned by a phantom field `Tlock` has and they don't).
  What was deliberately **not** done: `trans=fd` (a real socketpair, which
  Node cannot make without native code — deferred to a relay mode that
  already holds a descriptor; `trans=unix` is the identical kernel transport
  module and was judged to buy the same no-exposure property with no native
  code at all); a real multi-client lock table (`Tlock`/`Tgetlock` grant
  unconditionally, honest for the one local client this transport is built
  for and not for two attached to one `createP9Server`); and a benchmark
  column (no host could mount 9P when the benchmark suite was last run — see
  "Future / deferred", now that one can).

- **`mountx/exec`** (2026-07-29). A `proot`-shaped `exec()`: run a command
  with a driver grafted onto its filesystem view at `$MOUNTX_ROOT`, visible
  to that process tree and to nothing else on the machine, resolving with
  that command's exit status. Three mechanisms were built and measured
  (`.agents/proot-plan.md`); two ship behind one picker. `probeExec()`
  publishes what each can do here and why not, `exec()` takes the first
  usable one in preference order — the **user namespace** (FUSE inside
  `unshare -U -r -m`, driver in the parent, traffic relayed over a unix
  socket because `unshare(CLONE_NEWUSER)` refuses a threaded caller) where
  the kernel's FUSE is usable, the **seccomp** user-notification supervisor
  otherwise, which is the case that motivated the question: a container that
  withholds `/dev/fuse` withholds it from a namespace root too (`mknod`
  answers `EPERM`, verified on `alpine:latest`). Both arrive through
  `await import()`; the result is the mechanism's own object with a
  `mechanism` discriminant defined on it. `src/exec/probe.ts` is import-light
  in `src/nfs/probe.ts`'s sense and names causes a caller can act on rather
  than one errno.
  Deliberately **outside `mountx/auto`**, whose contract is a mountpoint this
  produces none of — the line `mountx/s3` already sits on.
  What was deliberately **not** done: **`LD_PRELOAD` was rejected** rather
  than finished (it cannot see a Go or static binary by construction, its
  symbol surface tracks other projects' releases, a descriptor it creates
  does not survive `exec`, and its characteristic failure is a confident
  wrong answer — the code stays as the written-up evidence, reachable from
  its own runner and the comparison harness and from nothing that ships); no
  conformance-matrix column for either mechanism (the `userns` one would
  duplicate FUSE's exactly, the `seccomp` one is not ready for it); no
  supervisor binary in the npm package, so the seccomp mechanism needs a Zig
  toolchain and `$MOUNTX_TRACE`; and no `default_permissions` on the
  namespace mount, because the kernel checking a driver's uid against a
  namespace that maps exactly one turns every write into `EACCES`.

## Finalized decisions (still binding)

- **Scope:** FUSE (Linux) + NFSv3 loopback transports. WebDAV deferred.
- **Layout:** single `mountx` package with subpath exports (`mountx`,
  `mountx/auto`, `mountx/fuse`, `mountx/nfs`, `mountx/drivers/memory`,
  `mountx/drivers/node-fs`). pnpm workspace kept for future splitting.
- **Drivers in v1:** in-memory driver + `node:fs` passthrough (the
  differential-test oracle). unstorage adapter deferred.
- **Git flow:** small conventional commits directly to `main`.
- **Native stub:** pure-JS-first per `IDEA.md` — root-mode FUSE via
  `mount(8)` spawn is the primary v1 mount path. A small zig-based
  binary/N-API stub for native parts (unprivileged mounting) IS allowed when
  needed (per Pooya, 2026-07-27), but only after the pure-JS path works and
  is tested. **Done** — see "Shipped since v1". The rule that survives it:
  native code is allowed only where JS genuinely cannot reach, it stays off
  the path that already works, and it is never required to install.
- **Subagent models:** implementation work SHOULD use `opus`; docs work
  SHOULD use `sonnet`.

## Future / deferred

Nothing here blocks v1; each is a real gap worth picking up deliberately
rather than by accident.

- **Relay mode and sync-driver-in-worker-threads concurrency modes.** v1
  ships async main-thread mode only. Relay would take `/dev/fuse` off the
  libuv threadpool entirely (removing the self-client hazard); sync-worker
  is the mode `IDEA.md` expects to scale with worker count. Both are
  unmeasured — see the "known gaps" in `.agents/benchmarks.md`. A relay mode
  is also where `src/9p/`'s deferred `trans=fd` would finally earn its keep:
  it wants a descriptor the relay already holds, where `mount9p()`'s own
  `trans=unix` has nothing to relay to.
- **`mountx/exec`'s seccomp mechanism, past the spike.** It ships as the
  second choice and covers the case `userns` cannot, but four things are
  open and each is named in `src/exec/seccomp.ts` and
  `.agents/proot-plan.md`: **streaming instead of slurping** (a file open
  copies the whole file into a `memfd`, which is what buys native
  `read`/`lseek`/`mmap` afterwards and is wrong for a large file and for
  anything that writes — trapping `read`/`write`/`lseek` per descriptor is
  the fix, the way `getdents64` already is); **write-back at all**, since it
  is read-only as spiked; **arm64**, which is a second syscall table rather
  than a redesign; and **trapping `close`**, which means not sharing a filter
  with the tracee, i.e. the `SCM_RIGHTS` shape after all — for which
  `native/` already has `recvFd`. Also: the supervisor is not in the npm
  package, so the mechanism needs a Zig toolchain and `$MOUNTX_TRACE` today.
- **A conformance-matrix column for `mountx/exec`.** Neither mechanism has
  one. The `userns` one would duplicate the FUSE column exactly (what the
  child sees _is_ FUSE, through the kernel's VFS), which is an argument for
  never writing it rather than for writing it later; the `seccomp` one is
  the interesting one and wants the streaming work above first, since a
  read-only column would be mostly skips.
- **`mountx/exec` on macOS.** Nothing from any of this transfers: no user
  namespaces, no seccomp, and SIP blocks `DYLD_INSERT_LIBRARIES` for exactly
  the system binaries anyone would want to run. macOS stays NFS-mount
  territory, and the honest answer is that this feature is Linux's.
- **A 9P bench column.** `bench/` has loopback and NFS columns and a
  sudo-gated FUSE one; 9P has none yet, and unlike when the transport was
  designed, a host that can mount it now exists (`.agents/environment.md`).
  Worth its own pass rather than folding into step 12's docs work: `msize`
  and `maxInFlight` (`DEFAULT_MAX_IN_FLIGHT = 16`, `src/9p/server.ts`) are
  both real tuning knobs with no measured numbers behind them yet, and the
  invariant that perf claims come only from `.agents/benchmarks.md` means
  none of this can be said in prose until the column exists.
- **A real multi-client lock table for 9P.** `Tlock`/`Tgetlock` grant
  unconditionally today (`src/9p/session.ts`), which is honest for the one
  local client `mount9p()` serves and not for a second one attached to a
  `createP9Server` over TCP. Worth doing only if TCP serving — multiple VM
  guests, or several processes against one `attach()`ed server — grows real
  users; until then it is a documented gap, not a silent one.
- **9P has no FUSE-style invalidation channel.** `notify_inval_inode`/
  `notify_inval_entry` have no 9P analogue — nothing in the protocol lets a
  server tell a client that something it cached has changed — which is why
  `cache=none` is `mount9p()`'s default rather than a tuning suggestion:
  every mode above it (`readahead`, `mmap`, `loose`, `fscache`) is a bet that
  nothing but the mount itself changes the driver, with no way to walk that
  bet back after the fact the way FUSE's `notifyInvalInode()` can. Worth
  revisiting only alongside a concrete driver that wants the tradeoff.
- **macOS NFS mounting is witnessed** (2026-07-28, macOS 26.6 arm64 — see
  `.agents/environment.md`). `pnpm test:nfs:mount` passes there: mounts, appears
  in `mount(8)`'s table, carries the full workload, refuses to stack, reports
  `statfs`, unmounts clean, three runs with no leaks. Every option
  `nfsMountOptions()` sends comes back intact in `nfsstat -m`, so the transcribed
  darwin half — helper path, `nolocks`, no `hard`, `nobrowse`, `mount(8)` as the
  table, realpath'd mountpoints — was right as written.
  **Tier 0/1 is green on darwin too**, which it was not before: `pnpm test`
  failed 14 cases there, all of them the suite assuming Linux — host `O_*` handed
  to a session that reads the wire's (now `src/fuse/flags.ts`) and host `errno`
  numbers checked against the transcribed table (now a target's `errors: "host"`).
  `.github/workflows/checks.yml` runs both: Tier 0/1 on a `macos-latest` matrix
  leg alongside ubuntu, and the unprivileged Tier-2 column as `mount-macos`,
  both blocking. The doubt about that second job was the consent gate — a
  runner is launchd-attributed, the context it refuses instantly with `EPERM`
  rather than prompting — and the first run answered it: 9 passed, including
  the workload case that opens, reads, writes and lists through a real mount,
  with nothing left mounted. **The gate does not fire for a mountpoint the
  caller owns**, which is what `mkdtemp` gives the suite, so no PPPC profile is
  needed. Whole run, four jobs, ~50 s.
  What the run _changed_:
  - **The `-f`-only escalation ladder is weaker than it claimed.** macOS gates
    network volumes behind a sandbox approval that is never prompted for a
    command-line process, and `umount` blocks (GUI-attributed) or fails `EPERM`
    (launchd-attributed) behind it. There is no escalation past that, so the
    transport now bounds both `umount` steps, refuses to leak a child that
    outlives its own deadline, and names the gate instead of blaming the driver
    (`isConsentDenial`/`consentAdvice`).
  - **AppleDouble sidecars.** `com.apple.provenance` on every new file + no xattr
    procedure in NFSv3 means the client writes a `._name` companion per file, so
    a driver mounted on macOS accumulates them. Nothing server-side can prevent
    it; the Tier-2 suite filters and asserts them. Worth saying out loud in the
    README's macOS section before anyone is surprised by it.
  - `unlink` of a directory answers `EPERM` there, the same host split
    `test/conformance.ts` already carries.
- **Mounting into `/Volumes` on macOS** — the only part of the NetFS
  investigation that is still open, and the only thing the unprivileged path
  cannot do. See "Shipped since v1" for what that investigation settled.
  `NetFSMountURLSync` can mount anywhere Finder can, but reaching it means FFI
  (against the zero-runtime-deps invariant) or `osascript` (which gives up
  mountpoint control and has no timeout). Worth it only if someone actually
  needs the volume to appear where Finder puts one.
- **WebDAV and Windows support.** Not designed against; WebDAV is the
  unprivileged, zero-native-code path for macOS/Windows per `IDEA.md`.
  Windows also has no `mount(8)`, so it stays out of the NFS transport's
  platform switch.
- **`mknod` / FIFOs / device nodes / UNIX sockets.** `FsDriver` has no way
  to create a special file (neither does `node:fs/promises`). This is the
  entire remaining pjdfstest gap (45 failing files, all one missing
  feature) — see `.agents/pjdfstest-results.md`. Needs an `FsDriver.mknod`
  or `mountx.mknod` extension plus matching storage in the memory driver.
- **xattr and the rest of the `mountx.*` extension namespace** (byte-range
  locks, `fallocate`/`lseek`, cache-invalidation `notify`) — `ENOTSUP` until
  a real user needs one.
- **NFS `CREATE` with `EXCLUSIVE`** — currently `NFS3ERR_NOTSUPP`; the
  verifier would have to be stored somewhere that survives a retry.
- **NLM byte-range locking** — out of scope, hence NFS mounts use `nolock`.
- **FUSE over io_uring** (Linux 6.14+) — would replace the read/reply loop
  with a shared ring and obsolete the threadpool discussion entirely; the
  transport layer should stay swappable so this is one file, not a rewrite.
- **`FUSE_PASSTHROUGH`** (Linux 6.9+) — lets the kernel bypass the daemon
  for read/write on a backing fd; relevant for overlay-shaped drivers.
- **`FUSE_READDIRPLUS_AUTO` default.** Benchmarked as actively costing the
  readdirplus win: a cold 1000-entry `ls -l` gets 9.6k entries/s with it
  on vs. 25.0k (the predicted 2.4×, measured 2.6×) with it off, at a 1.56×
  cost to a names-only `readdir`. Measured on two trees in one sitting
  (2.6× and 2.47×), so the finding replicates; the cost side grew from
  1.32× because `7185f33` made the plain-`READDIR` path 1.20× faster and
  left the plus path alone. Not changed in v1 — see `.agents/benchmarks.md`
  for the numbers — but it is the best-supported open question in the repo.
- **unstorage driver adapter** — deferred per the drivers-in-v1 decision
  above; would make 30+ storage backends mountable with no new code.
- **`mountx/drivers/s3`** — an `FsDriver` over a real S3-compatible bucket,
  mounting one rather than serving one. Named as the natural follow-up to the
  S3 gateway transport (see "Shipped since v1"); it would reuse
  `test/s3/client.ts`'s signing client instead of writing a second one. Not
  started.
- **Negative-entry caching.** Nothing currently populates FUSE's negative
  dentry cache for lookups that miss, so a repeated failed `LOOKUP` always
  reaches the driver.
- **Handle-table growth bound.** Neither NFS version has a `FORGET`, so
  nothing tells the server a client is done with a handle. Half of this is
  now closed: `FileHandleTable.#detachPath` drops an entry once its last path
  is detached, since such an entry could only ever be reached by `decode()` →
  `pathOf()` and that always threw `ESTALE` — ids come off a monotonic
  counter and are never reused, so the same handle still answers `ESTALE`,
  from `decode()` ("unknown file handle") one step earlier. Create/delete
  churn under a mount therefore no longer grows the table without bound.
  What is left is genuinely bounded: **one entry per path a client currently
  has a name for**, held for the life of the server however long ago the
  client looked, plus the root entry, which is exempt from eviction because
  `PUTROOTFH`/`PUTPUBFH`/`MNT` encode it from a field rather than from a
  lookup. A generation-stamped LRU is still the fix if a workload needs a
  bound on _that_ — it is the only remaining growth, and it is the one an
  LRU can serve without breaking a live client.
- **Set-gid inheritance and caller credentials in the driver interface.** A
  new entry in a set-gid directory should take its parent's group; more
  generally, supplementary groups and per-call caller credentials want to
  be first-class in `FsDriver` rather than patched on after the fact (the
  way new-inode ownership is today, via a post-hoc `lchown` in each
  session's `#claim`).
