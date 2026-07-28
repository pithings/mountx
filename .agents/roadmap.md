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
  unmeasured — see the "known gaps" in `.agents/benchmarks.md`.
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
  A `macos-latest` CI job is now worth doing for both layers, with one open
  question first: a CI runner is launchd-attributed, which is the context that
  gets an instant `EPERM` from the consent gate rather than a prompt, so the
  Tier-2 column may need a PPPC profile to run there at all.
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
- **Rootless NFS mounting on macOS** — the same shape as the rootless FUSE work
  above, and the reason not to hard-code "NFS needs root" anywhere outside
  `nfsClientProbe()`. `mount_nfs(8)` needs root, but Finder mounts `nfs://`
  URLs as an ordinary user, which means something unprivileged can already ask
  for the mount: `NetFS.framework`'s `NetFSMountURLSync`, and possibly the
  `open nfs://127.0.0.1:<port>/` URL handler that sits on top of it. Neither is
  verified — in particular whether a non-standard port survives the URL, and
  where the volume lands (`/Volumes/…`, not a path we chose). Investigate
  before promising anything.
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
  readdirplus win: a cold 1000-entry `ls -l` gets 10.3k entries/s with it
  on vs. 25.0k (the predicted 2.4×) with it off, at a ~20% cost to a
  names-only `readdir`. Not changed in v1 — see `.agents/benchmarks.md` for
  the numbers — but it is the best-supported open question in the repo.
- **unstorage driver adapter** — deferred per the drivers-in-v1 decision
  above; would make 30+ storage backends mountable with no new code.
- **Negative-entry caching.** Nothing currently populates FUSE's negative
  dentry cache for lookups that miss, so a repeated failed `LOOKUP` always
  reaches the driver.
- **Handle-table / file-handle growth bound.** NFSv3 has no `FORGET`, so a
  handle entry lives as long as the server — a real, bounded leak (one per
  path the client ever named), accepted as the honest v1 tradeoff. A
  generation-stamped LRU is the fix if a workload needs bounded memory.
- **Set-gid inheritance and caller credentials in the driver interface.** A
  new entry in a set-gid directory should take its parent's group; more
  generally, supplementary groups and per-call caller credentials want to
  be first-class in `FsDriver` rather than patched on after the fact (the
  way new-inode ownership is today, via a post-hoc `lchown` in each
  session's `#claim`).
