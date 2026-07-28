# unimount v1 roadmap

Finalized decisions (2026-07-27, confirmed by Pooya):

- **Scope:** FUSE (Linux) + NFSv3 loopback transports. WebDAV deferred.
- **Layout:** single `unimount` package with subpath exports
  (`unimount`, `unimount/fuse`, `unimount/nfs`, `unimount/drivers/memory`,
  `unimount/drivers/node-fs`). pnpm workspace kept for future splitting.
- **Drivers in v1:** in-memory driver + `node:fs` passthrough (the
  differential-test oracle). unstorage adapter deferred.
- **Git flow:** small conventional commits directly to `main`, one per
  completed milestone/substep.
- **Native stub:** pure-JS-first per IDEA.md — root-mode FUSE via
  `mount(8)` spawn is the primary v1 mount path. A small zig-based
  binary/N-API stub for native parts (unprivileged mounting) IS allowed
  when needed (per Pooya, 2026-07-27), but only after the pure-JS path
  works and is tested.
- **Subagent models:** implementation work SHOULD use `opus`; docs work
  SHOULD use `sonnet`.

Design source of truth: `IDEA.md`. Environment facts: `.agents/environment.md`.

## Milestones (in order; each ends with tests green + a commit)

1. ✅ **DONE** (commit 8609d65, 2026-07-27) **Driver interface & drivers.** `FsDriver` = subset of `node:fs/promises`
   (stat/lstat/statfs, readdir withFileTypes, open→FileHandle, mkdir/rmdir/
   unlink/rename/link/symlink/readlink, chmod/chown/truncate/utimes/…),
   capability declaration (`{ handles, hardlinks, symlinks, xattr, … }`),
   optional `unimount.*` extension namespace typed but mostly unimplemented.
   In-memory driver + node:fs passthrough driver. Loopback harness feeding
   calls straight to a driver (no mount) + one conformance suite run against
   both drivers (Tier 0).
2. ✅ **DONE** (commit 3aa8e2f, 2026-07-28) **FUSE protocol layer.** Pure JS, zero deps: all struct codecs with
   `DataView`, opcode table, `FUSE_INIT` negotiation logic as pure functions.
   Property-tested round-trips, golden byte fixtures, decoder fuzz (no
   exception escapes; exactly-once reply invariant harness).
3. ✅ **DONE** (commit 2d138ab, 2026-07-28) **Session layer.** Inode table + `FORGET`/`BATCH_FORGET` refcounting,
   path↔inode map (rename subtree remap, unlink-while-open, hardlinks),
   file-handle table, readdir paging/snapshots, errno discipline (catch-all
   → `-EIO`, reply-exactly-once assertion in dev), `INTERRUPT` → `-ENOSYS`,
   teardown. Tested against a synthetic kernel built from the same codecs.
4. ✅ **DONE** (commit af1db7f, 2026-07-28) **FUSE transport (root mode).** Open `/dev/fuse`, spawn
   `mount -i -t fuse` with fd mapped into child stdio, read/reply loop,
   negotiation defaults (`max_write` 1 MiB, `readdirplus`, attr/entry
   timeouts, `default_permissions`; writeback cache OFF), signal handlers +
   unmount + recovery docs. Real-mount smoke test under sudo (Tier 2).
5. ✅ **DONE** (commit 06d8210, 2026-07-28)
   **Validation.** Differential suite: same op sequence against passthrough
   mount vs real `node:fs`, diff results. `unimount record`/replay fixtures.
   pjdfstest run against a real mount, **locally under sudo only** — the run
   takes ~15 minutes and what it produces is an analysis rather than a
   pass/fail, so the results are committed instead
   (`.agents/pjdfstest-results.md`). CI gets a `mount` job running
   `pnpm test:root` — the three Tier-2 vitest files — on a stock Linux runner.
6. ✅ **DONE** (commit 5fed4d9, 2026-07-28)
   **NFSv3 loopback.** XDR codecs, MOUNT + NFSv3 servers over TCP (explicit
   `port=`/`mountport=`, no portmap), handle synthesis in the session layer
   for stateless ops. Tier-1 tests with a JS NFS client built from the same
   XDR codecs (no mount, no root), then sudo mount test — the last of which
   **cannot run on this host** (no kernel NFS client at all, see
   `.agents/environment.md`) and is gated on a probe.
7. **Conformance matrix + benchmarks + docs.** One driver-interface
   conformance suite run three ways (loopback, FUSE, NFS); report per-
   transport capability loss honestly. Benchmark suite (ops/sec per mode).
   README + docs (sonnet), no unmeasured perf claims.

## Deferred / open (do not block v1)

- xattr and the rest of the extension namespace → `ENOTSUP` until a real
  user needs it.
- Unprivileged mounting stub (zig cc), relay/exec modes, sync-worker mode.
- WebDAV, Windows, io_uring, FUSE_PASSTHROUGH.
