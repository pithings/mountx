# mountx roadmap

**Open work only.** What shipped is the code: `.agents/architecture.md` is the
map, `.agents/invariants.md` the rules, `.agents/conformance-matrix.md` /
`.agents/benchmarks.md` / `.agents/pjdfstest-results.md` the generated results,
`.agents/environment.md` the verified host facts, and `git log` the history.
Nothing is removed from this file until it is done _and_ recorded in one of
those.

**Then it is removed entirely.** Finished work is not mentioned here at all —
not as a checked box, not as "X shipped", not as "half of this is closed". An
entry that needs a fact about what exists states it in the present tense, as the
constraint the remaining work runs into; the entry is deleted the moment nothing
is left to run into it. A reader here is looking for what to pick up, and every
sentence about something already done is a sentence they have to rule out first.

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
- **Per-call caller credentials are not going into `FsDriver`.** The shape would
  be a `mountx.*` extension carrying the caller's uid/gid/groups into each
  creating call, so ownership is the driver's from the start instead of a
  post-hoc `lchown` in each session's `#claim`. Three things against it, and
  they compound: `node:fs/promises` has no credential parameter and the POSIX
  way to get one — `setfsuid(2)`/`setfsgid(2)` — is per-thread state Node does
  not expose and the threadpool would scramble, so `node-fs` could never
  implement it and `unstorage`/S3 have no ownership to implement it with; the
  memory driver, the only one that could, enforces no permissions at all, so the
  only observable effect of a credential inside it is the initial owner and
  group, which `src/ownership.ts` decides; and invariant 5 means every session
  keeps the `lchown` path anyway for drivers without the extension, so the whole
  surface buys one driver's atomicity at the price of two permanent code paths.
  What would reopen it is a driver that enforces permissions itself — there the
  credential decides whether a call _succeeds_, not just who owns the result,
  and `#claim` cannot express that at all. Where the **server** decides, the
  credential is already first-class: `allowedAccess()` in `src/nfs/util.ts`
  answers ACCESS from the effective and supplementary groups both.
- **Subagent models:** implementation work SHOULD use `opus`; docs work SHOULD
  use `sonnet`.

## Future / deferred

Nothing here blocks a release; each is a real gap worth picking up deliberately
rather than by accident.

- **FUSE reader concurrency: one mode worth building, two not.** Async
  main-thread mode is all there is.

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

- **9P `trans=fd`.** Reachable today with no relay and no native code, and an
  ordinary option to be judged on its own merits: Node _can_ create a socketpair
  without native code — verified on this host, libuv's `stdio: "pipe"` on POSIX
  **is** `socketpair(AF_UNIX, SOCK_STREAM)`, the child's inherited fd reads
  `socket:[…]`, and the parent end is a full-duplex `net.Socket` that
  round-trips bytes. (`.agents/9p-plan.md` says otherwise; it is wrong.) Two
  facts need one root mount each first: whether `mount(8)` keeps an inherited
  socket fd open across `mount(2)`, and whether v9fs's `trans=fd` drives an
  `AF_UNIX` stream.
- **An NFSv4.1 bench column.** The last transport that is in the conformance
  matrix and not in the benchmarks.
- **Whether `DEFAULT_MAX_IN_FLIGHT` should be higher.** The 9P column has numbers
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
- **A driver → transport "path X changed underneath you" channel.** The driver
  end is what is missing: nothing in `FsDriver` can say a path changed, so the
  only caller of `notifyInvalInode()` / `notifyInvalEntry()`
  (`src/fuse/session.ts`, `src/fuse/mount.ts`, encoders in `src/fuse/notify.ts`)
  is code that already knows because it made the change itself. It is **not** a
  `mountx.*` member: every extension there is a path-shaped call the session
  makes, and this is an event the driver raises unprompted, so it wants a
  `watch`-shaped surface on `FsDriver` rather than a method in the namespace.
  The translation costs nothing — `InodeTable.byPath` turns the path into the
  `ino` a notification needs, and a path the kernel never looked up has nothing
  cached, which is the natural no-op.
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
  themselves.** A driver without `mountx.mknod` answers `ENOTSUP`; the fallback
  would be an overlay holding the node in memory only, writing nothing through
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
  Cache-invalidation `notify` is not an extension at all; it has its own entry
  above.
- **`suppattr_exclcreat` (75) is unadvertised** in `src/nfs/v4/attr.ts`'s
  `SUPPORTED_ATTRS`. The exclusive-create verifier lives beside the file rather
  than in an attribute, so the honest value is the full settable set — the
  attribute's "deliberately absent, it is the OPEN step's call" note predates
  the OPEN step making that call.
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
  writing a second one.
- **A default for `maxHandles`.** The cap is opt-in, and what makes picking a
  default a judgement call rather than a number is that **the cap is soft**: an
  entry with live NFSv4.1 state is pinned and never a victim, so when every
  candidate is pinned the table exceeds `maxHandles` rather than breaking a
  share reservation, and it does not evict its way back down until the opens
  close. A default is therefore a hint about the working set, not a memory
  ceiling, and the honest one depends on a workload nobody has measured here
  yet. Two smaller things belong with it: nothing enforces a floor relative to a
  READDIRPLUS page (at `maxHandles: 8` one 40-entry page returns 40 handles of
  which 33 are stale before the reply leaves — it converges, and it is
  documented rather than clamped), and `MNT` binds the export root through an
  ordinary lookup, so a _subdirectory_ export's mount root is evictable and a v3
  client has no name above it to recover with. A directly constructed
  `Nfs3Session` / `Nfs4Session` also builds its own table and ignores the
  option; every public path goes through the router, so this is the tests and
  the CLI only.
- **Set-gid inheritance on the FUSE session.** `src/ownership.ts` holds the rule
  (`inode_init_owner()`) and the two NFS sessions apply it from the parent
  `stat` they take anyway for `wcc_data` / `change_info4`. 9P needs nothing —
  its client computes both halves (`v9fs_get_fsgid_for_create()`) and they
  arrive on the wire. FUSE is the gap, and `#claim` in `src/fuse/session.ts`
  says why it is not simply mirrored: nothing on that path reads the parent, so
  the rule would add an `lstat` to every create for every caller — including the
  daemon-is-the-caller case that costs no driver call at all — and the
  membership half needs `FUSE_CREATE_SUPP_GROUP` (7.38), which
  `src/fuse/init.ts` does not ask for. Both are decisions to take deliberately,
  not omissions.
