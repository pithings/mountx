# mountx roadmap

**Open work only.** What shipped is the code: `.agents/architecture.md` is the
map, `.agents/invariants.md` the rules, `.agents/conformance-matrix.md` /
`.agents/benchmarks.md` / `.agents/pjdfstest-results.md` the generated results,
`.agents/environment.md` the verified host facts, and `git log` the history.
Nothing is removed from this file until it is done _and_ recorded in one of
those.

## Decisions still binding

- **Layout:** single `mountx` package with subpath exports; the pnpm workspace
  is kept for future splitting.
- **Git flow:** small conventional commits directly to `main`.
- **Native code is allowed only where JS genuinely cannot reach**, it stays off
  the path that already works, and it is never required to install. (The one
  case is `native/`: `fusermount3`'s `SCM_RIGHTS` reply, which Node cannot
  `recvmsg`.)
- **No user-namespace FUSE mode and no setuid binary of our own.** A mount made
  in a user namespace is invisible outside its mount namespace, so it serves
  "mount for my own process tree" and not much else; a setuid binary would mean
  reimplementing `fusermount3`'s security model — ownership checks,
  `allow_other` gating, `fuse.conf`, mtab — in a binary running as root, to save
  one package dependency.
- **`mountx/auto` never falls back after a mount failure**, and never probes
  when a transport is named. The probe decides from host facts, once — a silent
  second attempt would hand back different semantics than the error nobody saw.
- **The S3 gateway stays out of `mountx/auto`.** Auto's whole contract is a
  mountpoint and that transport never produces one.
- **NLM byte-range locking is out of scope**, hence NFS mounts use `nolock`.
- **Subagent models:** implementation work SHOULD use `opus`; docs work SHOULD
  use `sonnet`.

## Future / deferred

Nothing here blocks a release; each is a real gap worth picking up deliberately
rather than by accident.

- **Relay mode and sync-driver-in-worker-threads concurrency modes.** Async
  main-thread mode is all that ships. Relay would take `/dev/fuse` off the libuv
  threadpool entirely (removing the self-client hazard); sync-worker is the mode
  expected to scale with worker count. Both are unmeasured — see the "known
  gaps" in `.agents/benchmarks.md`. A relay mode is also where `src/9p/`'s
  deferred `trans=fd` would finally earn its keep: it wants a descriptor the
  relay already holds, where `mount9p()`'s own `trans=unix` has nothing to relay
  to.
- **A 9P bench column.** `bench/` has loopback and NFS columns and a sudo-gated
  FUSE one; 9P has none, and unlike when the transport was designed, a host that
  can mount it now exists (`.agents/environment.md`). `msize` and `maxInFlight`
  (`DEFAULT_MAX_IN_FLIGHT = 16`, `src/9p/server.ts`) are both real tuning knobs
  with no measured numbers behind them, and the invariant that perf claims come
  only from `.agents/benchmarks.md` means none of it can be said in prose until
  the column exists.
- **An NFSv4.1 bench column**, for the same reason: both it and 9P are in the
  conformance matrix and neither is in the benchmarks.
- **A real multi-client lock table for 9P.** `Tlock`/`Tgetlock` grant
  unconditionally today (`src/9p/session.ts`), which is honest for the one local
  client `mount9p()` serves and not for a second one attached to a
  `createP9Server` over TCP. Worth doing only if TCP serving — multiple VM
  guests, or several processes against one `attach()`ed server — grows real
  users; until then it is a documented gap, not a silent one.
- **9P has no FUSE-style invalidation channel.** `notify_inval_inode`/
  `notify_inval_entry` have no 9P analogue — nothing in the protocol lets a
  server tell a client that something it cached has changed — which is why
  `cache=none` is `mount9p()`'s default rather than a tuning suggestion: every
  mode above it (`readahead`, `mmap`, `loose`, `fscache`) is a bet that nothing
  but the mount itself changes the driver, with no way to walk that bet back
  after the fact the way FUSE's `notifyInvalInode()` can. Worth revisiting only
  alongside a concrete driver that wants the tradeoff.
- **AppleDouble sidecars are undocumented in `docs/`.** macOS tags every new
  file with `com.apple.provenance` and NFSv3 has no xattr procedure, so the
  client writes a `._name` companion per file and a driver mounted there
  accumulates them. Nothing server-side can prevent it; the Tier-2 suite filters
  and asserts them, and `.agents/environment.md` records it — but the docs'
  macOS prose still does not, and someone will be surprised by it.
- **Mounting into `/Volumes` on macOS** — the one thing the unprivileged path
  cannot do. `NetFSMountURLSync` can mount anywhere Finder can, but reaching it
  means FFI (against the zero-runtime-deps invariant) or `osascript` (which
  gives up mountpoint control and has no timeout). The rest of that
  investigation is settled and negative: `open nfs://…` has no handler at all on
  26.6 (`kLSApplicationNotFoundErr`), and `NetFSMountURLSync` parses a URL port
  into `kNetFSAlternatePortKey` and then never reads it — it goes to port 111
  and fails `ECONNREFUSED`, fatal for a server with no portmapper. Worth it only
  if someone actually needs the volume to appear where Finder puts one.
- **WebDAV and Windows support.** Not designed against; WebDAV is the
  unprivileged, zero-native-code path for macOS/Windows. Windows also has no
  `mount(8)`, so it stays out of the NFS transport's platform switch.
- **A `mknod` polyfill for drivers that cannot store a special file
  themselves.** The extension itself shipped (`mountx.mknod` + the memory
  driver, which closed the whole pjdfstest gap). What is deferred is the
  fallback: an overlay holding the node in memory only, writing nothing through
  to the backing store — a small union filesystem, because it has to win on
  every creating call (`mkdir`/`symlink`/`link`/`open(O_CREAT)`/a `rename`
  destination must answer `EEXIST` against an overlaid name) and not merely on
  the three that read types. Opt-in if it is built, not default: making
  `resolveCapabilities(node:fs/promises)` report `extensions: ["mknod"]` would
  claim an extension whose nodes live in one process's heap, and on a shared
  backing store the FIFO would be real to the mounting process and absent to
  every other one.
- **xattr and the rest of the `mountx.*` extension namespace** (byte-range
  locks, `fallocate`/`lseek`, cache-invalidation `notify`) — `ENOTSUP` until a
  real user needs one.
- **NFS `CREATE` with `EXCLUSIVE`** — currently `NFS3ERR_NOTSUPP`; the verifier
  would have to be stored somewhere that survives a retry.
- **FUSE over io_uring** (Linux 6.14+) — would replace the read/reply loop with
  a shared ring and obsolete the threadpool discussion entirely; the transport
  layer should stay swappable so this is one file, not a rewrite.
- **`FUSE_PASSTHROUGH`** (Linux 6.9+) — lets the kernel bypass the daemon for
  read/write on a backing fd; relevant for overlay-shaped drivers.
- **`FUSE_READDIRPLUS_AUTO` default.** Benchmarked as actively costing the
  readdirplus win: a cold 1000-entry `ls -l` gets 9.6k entries/s with it on vs.
  25.0k (the predicted 2.4×, measured 2.6×) with it off, at a 1.56× cost to a
  names-only `readdir`. Measured on two trees in one sitting (2.6× and 2.47×),
  so the finding replicates; the cost side grew from 1.32× because `7185f33`
  made the plain-`READDIR` path 1.20× faster and left the plus path alone. Not
  changed yet — see `.agents/benchmarks.md` for the numbers — but it is the
  best-supported open question in the repo.
- **`mountx/drivers/s3`** — an `FsDriver` over a real S3-compatible bucket,
  mounting one rather than serving one; the natural follow-up to the S3 gateway
  transport. It would reuse `test/s3/client.ts`'s signing client instead of
  writing a second one. Not started.
- **Handle-table growth bound.** Neither NFS version has a `FORGET`, so nothing
  tells the server a client is done with a handle. Half of this is closed:
  `FileHandleTable.#detachPath` drops an entry once its last path is detached,
  so create/delete churn under a mount no longer grows the table without bound.
  What is left is genuinely bounded: **one entry per path a client currently has
  a name for**, held for the life of the server however long ago the client
  looked, plus the root entry, which is exempt from eviction because
  `PUTROOTFH`/`PUTPUBFH`/`MNT` encode it from a field rather than from a lookup.
  A generation-stamped LRU is the fix if a workload needs a bound on _that_ — it
  is the only remaining growth, and the one an LRU can serve without breaking a
  live client.
- **Set-gid inheritance on the FUSE session.** The rule itself now exists —
  `src/ownership.ts`, a transcription of `inode_init_owner()` — and both NFS
  sessions apply it: a new entry in a set-gid directory takes the parent's
  group, a new directory takes the bit, and a new group-executable loses
  `S_ISGID` when its creator is in neither the effective nor the supplementary
  group `AUTH_SYS` carried. 9P needs nothing: its client computes both halves
  (`v9fs_get_fsgid_for_create()`) and they arrive on the wire. **FUSE is the
  gap**, and `#claim` in `src/fuse/session.ts` says why it was not simply
  mirrored: the NFS sessions read the parent anyway (for `wcc_data` and
  `change_info4`) while nothing on the FUSE path does, so the rule would add an
  `lstat` to every create for every caller — including the daemon-is-the-caller
  case that currently costs no driver call at all — and the membership half
  needs `FUSE_CREATE_SUPP_GROUP` (7.38), which `src/fuse/init.ts` does not ask
  for. Both are decisions to take deliberately, not omissions.
- **Per-call caller credentials in `FsDriver`: considered, and not the
  answer.** The shape was a `mountx.*` extension carrying the caller's
  uid/gid/groups into each creating call, so ownership would be the driver's
  from the start instead of a post-hoc `lchown` in `#claim`. Three things
  against it, and they compound: `node:fs/promises` has no credential parameter
  and the POSIX way to get one — `setfsuid(2)`/`setfsgid(2)` — is per-thread
  state Node does not expose and the threadpool would scramble, so `node-fs`
  could never implement it and `unstorage`/S3 have no ownership to implement it
  with; the memory driver, the only one that could, enforces no permissions at
  all, so the sole observable effect of a credential inside it is the initial
  owner and group, which `src/ownership.ts` now gets right; and invariant 5
  means every session must keep the `lchown` path anyway for drivers without
  the extension, so the whole surface buys one driver's atomicity at the price
  of two permanent code paths. What would reopen it is a driver that enforces
  permissions itself — at that point the credential decides whether a call
  _succeeds_, not just who owns the result, and `#claim` cannot express that at
  all. Note that the credential is already first-class where the **server**
  decides: `allowedAccess()` in `src/nfs/util.ts` answers ACCESS from the
  effective and supplementary groups both.
