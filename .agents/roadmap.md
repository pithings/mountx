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

- **FUSE reader concurrency: one mode worth building, two not.** Async
  main-thread mode is all that ships. This bullet used to ask for a relay mode
  and a sync-driver-in-workers mode; a design pass against
  `.agents/benchmarks.md` cut it down, and what follows is the residue.

  **Relay buys no throughput.** The reader-count experiment already says pulling
  requests off `/dev/fuse` is not the bottleneck, so a mode whose whole content
  is pulling them differently cannot move the ceiling. What it buys is one of
  the four self-client hazards — the async-`fs`-fan-out form. The synchronous
  form, the `uv_spawn` form and the driver-needs-the-pool form all survive, as
  9P demonstrates: it already answers from the event loop over a socket, the
  shape relay would give FUSE, and `src/9p/mount.ts`'s header still documents
  the `spawn` deadlock.

  **What is left is smaller and opt-in:** a worker thread doing blocking
  `readSync` into a `SharedArrayBuffer` ring, replies still written from the
  main thread — so the reply path crosses no boundary and invariants 9 and 12
  keep their present shape (invariant 12's transport half becomes "release the
  slot when `handleMessage` returns", which is `#arm(buffer)` with a different
  verb). A worker reading _asynchronously_ would fix nothing: the libuv
  threadpool is process-global and shared with worker threads. It cannot be the
  default, and it does not improve invariant 21 — a worker parked in a blocking
  read is shed by neither `unref()` nor `terminate()` nor `process.exit()`, only
  by `SIGKILL`. Three things gate it, all unmeasured: a predicted single-digit
  sequential regression, the ring's memory ordering (argued from the memory
  model, never measured), and whether `fs.readSync` on `/dev/fuse` can
  short-read.

  **Sync-driver-in-workers is declined.** An `FsDriver` is closures and closures
  do not `postMessage`, so it needs a second driver contract that invariant 4
  will not have; and the loopback column against the FUSE one — 1,093,940 stat/s
  against 33,434 (`.agents/benchmarks.md`) — says the driver is a rounding error
  in every measured column. A driver that wants a worker pool can own one today
  with no library support.

  **And the fix that covers all four hazards is free:** serve from one process
  and use the mount from another. `bench/drive.ts` does exactly that in reverse,
  which is why no benchmark column has ever wedged.

- **9P `trans=fd`, no longer waiting on a relay.** It was deferred twice, and
  both premises are gone. `.agents/9p-plan.md` deferred it because Node
  supposedly cannot create a socketpair without native code; that is **false**,
  and verified on this host — libuv's `stdio: "pipe"` on POSIX _is_
  `socketpair(AF_UNIX, SOCK_STREAM)`, the child's inherited fd reads
  `socket:[…]`, and the parent end is a full-duplex `net.Socket` that
  round-trips bytes. This file deferred it again because it wanted a descriptor
  only a relay would hold; with relay cut down to a worker that holds nothing of
  the sort, that no longer follows either. So `trans=fd` is reachable today with
  no relay and no native code, and it is now an ordinary option to be judged on
  its own merits. Two facts need one root mount each first: whether `mount(8)`
  keeps an inherited socket fd open across `mount(2)`, and whether v9fs's
  `trans=fd` drives an `AF_UNIX` stream.
- **An NFSv4.1 bench column.** 9P has one now (`pnpm bench:9p`), which leaves
  v4.1 as the last transport that is in the conformance matrix and not in the
  benchmarks.
- **Whether `DEFAULT_MAX_IN_FLIGHT` should be higher.** The 9P column put numbers
  behind both of that transport's knobs, and they point opposite ways. The
  dispatch window pays: 64 against the shipped 16 is 1.34–1.35× on stats 64 deep,
  and closing it to 1 costs 0.87–0.94×, so the default sits below where it stops
  earning. `msize` is settled the other way — 1 MiB buys 1.29× over the shipped
  default for eight times the per-request memory, and the default is already
  3.0–3.2× the 16 KiB the kernel used to ship. Changing a shipped default wants a
  second sitting on another host before the one measurement becomes a decision.
- **Cross-session fid remap, and a `PathLock` that spans connections.** A rename
  moves the byte ranges with the file (`P9LockTable.remap`) but rewrites only the
  renaming connection's fid table, because `FidTable.remap` is per connection —
  so another client holding a pre-rename fid goes on naming the old path, and its
  next `Tlock`/`Tgetlock` files itself there. Nothing is stranded (records still
  die with the fid or the connection) and a client that walks to the new name
  afterwards sees them. It is the same missing piece as the per-connection
  `PathLock`: a rename by one client is not serialized against another's work
  either. `src/9p/locks.ts` documents both edges.
- **No Tier-2 multi-client 9P case.** The lock table's cross-client behaviour is
  covered at Tier 0/1 — two connections on one `createP9Server`, including the
  release when one drops — but two _real_ mounts of one server, a guest and its
  host or two guests, is not, and needs a host that can produce them.
- **A driver → transport "path X changed underneath you" channel.** Half of this
  already ships, and it is the transport-facing half: `notifyInvalInode()` /
  `notifyInvalEntry()` on the FUSE session (`src/fuse/session.ts`) and on the
  mount (`src/fuse/mount.ts`), pure encoders in `src/fuse/notify.ts`. What is
  missing is the driver end — nothing in `FsDriver` can say a path changed, so
  the only caller today is code that already knows because it made the change
  itself. It is **not** a `mountx.*` member: every extension there is a
  path-shaped call the session makes, and this is an event the driver raises
  unprompted, so it wants a `watch`-shaped surface on `FsDriver` rather than a
  method in the namespace. The FUSE half of the translation is already in place
  — `InodeTable.byPath` turns the path into the `ino` a notification needs, and
  a path the kernel never looked up has nothing cached, which is the natural
  no-op.
  **FUSE is the only transport that could consume it today, and the only one
  that can without new protocol work.** 9P has no invalidation message at all
  (below). NFSv3 is request/response only: client caching is bounded by
  attribute timeouts and nothing server-initiated exists. NFSv4.1 does have a
  back channel — delegation recall and `CB_NOTIFY` — but this server grants no
  delegations, never sets `CREATE_SESSION4_FLAG_CONN_BACK_CHAN`, refuses a
  `CDFC4_BACK` `BIND_CONN_TO_SESSION` with `NFS4ERR_INVAL` and answers
  `BACKCHANNEL_CTL` the same way, so reaching it means building the callback
  program, delegations, and `GET_DIR_DELEGATION` for the directory case — far
  more work than the notification it would carry. The S3 gateway has neither a
  channel nor a client cache to invalidate.
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
  locks, `fallocate`/`lseek`) — `ENOTSUP` until a real user needs one.
  Cache-invalidation `notify` used to be listed here and is not an extension at
  all; it has its own entry above.
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
- **Set-gid inheritance and caller credentials in the driver interface.** A new
  entry in a set-gid directory should take its parent's group; more generally,
  supplementary groups and per-call caller credentials want to be first-class in
  `FsDriver` rather than patched on after the fact (the way new-inode ownership
  is today, via a post-hoc `lchown` in each session's `#claim`).
