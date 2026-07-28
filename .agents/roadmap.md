# unimount v1 roadmap

Design source of truth: `IDEA.md`. Environment facts: `.agents/environment.md`.

## v1 shipped

All 7 planned milestones are done (commits `8609d65..97e7ba9`, 2026-07-27/28):
the driver interface and its two drivers, the FUSE protocol/session/root-mode
transport, the validation suites (differential, record/replay, pjdfstest),
NFSv3 loopback, and the conformance matrix + benchmark suite the README is
drawn from. See `AGENTS.md` for the current code map and invariants, and
`.agents/conformance-matrix.md` / `.agents/benchmarks.md` for the generated
results.

## Finalized decisions (still binding)

- **Scope:** FUSE (Linux) + NFSv3 loopback transports. WebDAV deferred.
- **Layout:** single `unimount` package with subpath exports (`unimount`,
  `unimount/fuse`, `unimount/nfs`, `unimount/drivers/memory`,
  `unimount/drivers/node-fs`). pnpm workspace kept for future splitting.
- **Drivers in v1:** in-memory driver + `node:fs` passthrough (the
  differential-test oracle). unstorage adapter deferred.
- **Git flow:** small conventional commits directly to `main`.
- **Native stub:** pure-JS-first per `IDEA.md` — root-mode FUSE via
  `mount(8)` spawn is the primary v1 mount path. A small zig-based
  binary/N-API stub for native parts (unprivileged mounting) IS allowed when
  needed (per Pooya, 2026-07-27), but only after the pure-JS path works and
  is tested.
- **Subagent models:** implementation work SHOULD use `opus`; docs work
  SHOULD use `sonnet`.

## Future / deferred

Nothing here blocks v1; each is a real gap worth picking up deliberately
rather than by accident.

- **Unprivileged mounting stub** (`zig cc`, exec or relay mode — see
  `IDEA.md`). This host has no `fusermount3`/`fusermount`, so all v1 Tier-2
  tests run under sudo; the stub is what removes that requirement.
- **Relay mode and sync-driver-in-worker-threads concurrency modes.** v1
  ships async main-thread mode only. Relay would take `/dev/fuse` off the
  libuv threadpool entirely (removing the self-client hazard); sync-worker
  is the mode `IDEA.md` expects to scale with worker count. Both are
  unmeasured — see the "known gaps" in `.agents/benchmarks.md`.
- **WebDAV and Windows support.** Not designed against; WebDAV is the
  unprivileged, zero-native-code path for macOS/Windows per `IDEA.md`.
- **`mknod` / FIFOs / device nodes / UNIX sockets.** `FsDriver` has no way
  to create a special file (neither does `node:fs/promises`). This is the
  entire remaining pjdfstest gap (45 failing files, all one missing
  feature) — see `.agents/pjdfstest-results.md`. Needs an `FsDriver.mknod`
  or `unimount.mknod` extension plus matching storage in the memory driver.
- **xattr and the rest of the `unimount.*` extension namespace** (byte-range
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
