# 9P2000.L transport — implementation plan

Executed step-by-step by an autonomous loop on branch `feat/9p`. One step per
loop iteration. This file is the single source of truth for progress: a step
is done when its checkbox is checked **and** its commit exists.

## Decisions (settled with Pooya, 2026-07-28)

- **Naming:** directory `src/9p/`, subpath export `mountx/9p`, test dir
  `test/9p/`. Identifiers use a `P9` prefix (`P9Session`, `createP9Server`,
  `mount9p`, `p9ClientProbe`) — mirrors the kernel's own `p9_*` naming.
  The `mountx/auto` options escape hatch is the quoted key `"9p"`.
- **Version:** 9P2000.L only, and the wire string is **`"9P2000.L"`** —
  capital P, what `p9_client_version()` sends; `9p2000.L` is only the mount
  option spelling (`fs/9p/v9fs.c`). Any other `Tversion` string answers
  `Rversion` with `"unknown"` per spec. Legacy 9P2000 opcodes
  (`Topen`/`Tcreate`/`Tstat`/`Twstat`) answer `Rlerror ENOTSUP`.
- **Locks:** `Tlock` always grants (`P9_LOCK_SUCCESS`), `Tgetlock` always
  reports unlocked. Honest for a single-client loopback server — the client
  kernel does local POSIX-lock bookkeeping; documented as such where the
  NFS `nolock` decision is documented.
- **Server scope:** full `createP9Server` — TCP listener, unix-socket
  listener, and an attach-a-duplex mode for embedders holding a stream.
- **Local mount path (AMENDED in step 9, was `trans=fd`):** `trans=unix` —
  the server listens on a 0600 socket in a 0700 `mkdtemp` dir and
  `mount -t 9p <socketpath> <mnt> -o trans=unix,version=9p2000.L,...`.
  Why the change: `trans=fd` needs a true socketpair, which Node cannot
  create without native code (invariant-bound to the FUSE path only), and
  `trans=unix` is the SAME kernel transport module (`net/9p/trans_fd.c`
  registers tcp/unix/fd side by side, same maxsize, same machinery) with
  the kernel's own docs blessing the shape. The no-exposure property the
  socketpair was chosen for is preserved by the private directory.
  Verifier round independently validated this against v6.12 sources.
  `trans=fd` stays deferred (relay/embedder holding a descriptor). TCP is
  for serving external clients (VM guests: `trans=tcp` against the host);
  its source must be a dotted-quad IPv4 (`valid_ipaddr4()` — no
  hostnames, no IPv6).
- **Root:** mounting needs root on Linux (plain `mount(2)`), and Linux is
  the only platform with a client — Darwin has no v9fs. So 9P never appears
  on macOS, and `mountx/auto`'s Linux preference becomes
  `["fuse", "9p", "nfs"]` — FUSE stays first (rootless-capable), 9P beats
  NFS when both need root anyway (stateful opens: no `ESTALE`, real
  close/fsync so handle-buffering drivers work, no handle-table leak).
- **Errors:** `Rlerror` carries a positive Linux errno — `src/errors.ts`'s
  table goes on the wire directly, unknown → `EIO`. No mapping layer.
- **Open flags:** `Tlopen`/`Tlcreate` flags are the Linux kernel's `O_*` —
  the same namespace as FUSE's wire. Reuse `src/fuse/flags.ts`'s
  `driverOpenFlags()` (import it; hoist only if an import from `src/9p/`
  into `src/fuse/` proves unacceptable — decide in step 5, don't duplicate).
- **Tier-2 witnessing (updated 2026-07-28, mid-run):** the host has loaded
  the 9p kernel modules — `/proc/filesystems` lists `9p`, `/sys/module` has
  `9p`, `9pnet`, `9pnet_virtio`. Step 10 is therefore a REAL local mount
  witnessing under sudo, not QEMU. Caveat: `9pnet_fd` (the module providing
  `trans=fd`, `trans=tcp` and `trans=unix`) was not loaded at check time —
  only the virtio transport was. `mount(2)` may autoload it through the
  host's modprobe; if it does not, the host needs `modprobe 9pnet_fd`.
  `test/9p/mount.test.ts` stays probe-gated regardless (other hosts still
  lack the module), exactly like NFS Tier-2.
- **Wire authority:** message types, bit masks and struct layouts are
  transcribed from the Linux kernel's `include/net/9p/9p.h` (tag v6.12,
  matching the FUSE constants' tag), with diod's `protocol.md` as the prose
  reference. Never guessed, never borrowed from host headers.
- **Bench column:** deferred until a host can mount (roadmap entry in
  step 12); benchmarks only come from `.agents/benchmarks.md` per invariant.

## Loop protocol (every step)

1. Pick the first unchecked step below. Re-read `AGENTS.md` invariants.
2. Spawn an **implementation subagent, `model: "opus"`** (synchronous,
   `run_in_background: false`) with: the step's goal, files and acceptance
   criteria pasted in full, the relevant AGENTS.md invariants, and the
   instruction to run `pnpm test` before returning. Docs-only steps use
   **`model: "sonnet"`** instead.
3. Spawn an **independent verification subagent, `model: "opus"`**
   (synchronous). It gets the step's acceptance criteria and the diff
   (`git diff` + new files) but NOT the implementer's notes. It must
   adversarially check: invariants (golden fixtures all-distinct, decoders
   copy retained bytes, exactly-one-reply, zero-copy contract, no `Buffer
.slice` retention), wire correctness against `include/net/9p/9p.h`, and
   run `pnpm test` itself. It returns a verdict + concrete defects.
4. Defects → one fix round trip back to an opus subagent, then re-verify.
   If still failing after two fix rounds, STOP the loop and report to the
   user — do not commit a red or doubted step.
5. Green + verified → commit (small conventional commit, e.g.
   `feat(9p): wire codec and constants`, ending with the Claude Code
   trailer), check the box below **in the same commit**, and note anything
   learned in "Log" at the bottom.
6. All boxes checked → run the loop's final step 13, then stop the loop
   (`ScheduleWakeup {stop: true}`) and summarize.

Subagent prompts must be self-contained: a subagent sees none of this
conversation. Always include: repo root path, the step text, the decisions
above that the step touches, and the commands to run.

## Steps

- [x] **1. Wire primitives + constants** — `src/9p/wire.ts`: `P9Reader`/
      `P9Writer`, little-endian, unaligned, bounds-checked; u8/u16/u32,
      u64 as `bigint`, `string` as u16-length-prefixed UTF-8 (no padding),
      qid (type u8, version u32, path u64), byte blobs. Reader **copies**
      retained bytes. `src/9p/constants.ts`: all `P9_T*`/`P9_R*` message types,
      `P9_GETATTR_*`/`P9_SETATTR_*` masks, `P9_LOCK_*`, `P9_QTDIR`/`P9_QTFILE`/
      `P9_QTSYMLINK`, `P9_NOTAG`/`P9_NOFID`, `P9_MAXWELEM = 16`, header size 7,
      `IOHDRSZ`, transcribed from `include/net/9p/9p.h` v6.12 with the source
      named in the file header like `src/fuse/constants.ts` does.
      Tests `test/9p/wire.test.ts`: round-trips, bounds, golden byte fixtures
      with all-distinct values, truncation → throws. Commit.
- [x] **2. Message codecs** — `src/9p/protocol.ts`: every 9P2000.L message
      encoded **and** decoded (both directions — the JS test client needs the
      T-encoders/R-decoders, the session the inverse): version, auth, attach,
      flush, walk, read, write, clunk, remove, statfs, lopen, lcreate, symlink,
      mknod, rename, readlink, getattr, setattr, xattrwalk, xattrcreate,
      readdir (entry packing with qid/offset/type/name), fsync, lock, getlock,
      link, mkdir, renameat, unlinkat, lerror. Frame helpers: `size[4] type[1]
tag[2]` header read/write, `framesFrom()` reassembly over a byte stream
      (partial frames buffered, size bounds-checked against negotiated msize).
      Tests `test/9p/protocol.test.ts` (golden, all-distinct) +
      `test/9p/fuzz.test.ts` (random struct round-trips + hostile truncated/
      oversized frames never throw uncaught). Commit.
- [x] **3. Fid table** — `src/9p/fids.ts`: fid → path + open state (driver
      `FileHandleLike` or path-mode) + iounit + per-fid readdir cursor keyed by
      offset (offset 0 resnapshots; an unknown non-zero offset is `EINVAL` —
      offsets are opaque cookies we mint, guessing would skip or repeat files).
      Walk clones fids; clunk/remove release; qid identity keyed on the
      `(dev, ino)` pair with `qid.path` always allocated from our own counter
      (`useDriverIno` selects the identity key only; the driver's `ino` goes
      out in `Rgetattr`, not `qid.path` — the FUSE nodeid/`st_ino` split).
      `..` clamps at the root (`src/path.ts` semantics). Tests
      `test/9p/fids.test.ts`. Commit.
- [x] **4. Session core + JS client** — `src/9p/session.ts`: `P9Session
(driver, options)` with `handleCall(bytes): Promise<Uint8Array | null>`
      shape mirroring `NfsSession`; this step implements version negotiation
      (msize = min(client, cap 1 MiB); reject non-`9p2000.L`), attach (aname
      ""/"/" → root fid; record n_uname for the `#claim`-style ownership
      pattern the other sessions use), walk (MAXWELEM, partial-walk Rwalk
      semantics: error only when the first element fails), clunk, getattr
      (mask-driven from driver stat), statfs, readdir, flush (tag tracking:
      in-flight map; Rflush sent only after oldtag settles; unknown oldtag →
      immediate Rflush; exactly one reply per tag — extend the dev-mode
      assertion pattern). Errno discipline: never rejects, thrown → Rlerror,
      unknown → EIO. Zero-copy: decode+copy before first await.
      `test/9p/client.ts`: Tier-1 JS client speaking to the session (built on
      the same codecs, like `test/nfs/client.ts`). `test/9p/session.test.ts`
      for this step's ops. Commit.
- [x] **5. Session I/O + namespace ops** — lopen/lcreate (flags through
      `driverOpenFlags()`; `handles: false` drivers get the reopen-per-op path
      with `reopenFlags()` semantics), read/write (clamped to msize−IOHDRSZ,
      payload copied before await), fsync, setattr (bitmask → driver calls,
      mirroring the FUSE SETATTR switch), mkdir, symlink, readlink, link,
      mknod (wire to `mountx.mknod` if declared, else ENOSYS — matches FUSE),
      rename/renameat/unlinkat/remove (**`PathLock` from `src/lock.ts` around
      rename**, subtree fid-path remap on rename like `InodeTable` does),
      xattrwalk/xattrcreate → ENOTSUP (Linux clients probe `security.*` on
      write — the refusal path is hot, keep it cheap), lock/getlock per the
      grant-all decision, legacy opcodes → ENOTSUP. Notes settled by step 4's
      verification: `Rgetattr` has NO `st_ino` field — v9fs derives `st_ino`
      from `qid.path` (`QID2INO`), so the driver's `ino` never reaches the
      wire and `useDriverIno` only picks the identity key (documented in
      session.ts; the step-3 carry-forward about an st_ino fill was based on
      a wrong premise). Walk-from-open-fid refusal is already implemented.
      Remaining carry-forward: call `FidTable.release(path)` on
      Tremove/Tunlinkat and on create-over so a recreated path never
      inherits the dead file's identity. Extend session tests. Commit.
- [x] **6. Conformance column + session fuzz** — `test/9p/conformance.test.ts`
      runs `test/conformance.ts` through the JS client against `P9Session` over
      memory + node-fs (rooted oracle), like the NFS column. A session fuzz
      file (hostile frames, bad fids, bad tags, flush races) in the spirit of
      `test/fuse/session-fuzz.test.ts`. Fix what they find. Commit.
- [x] **7. Server** — `src/9p/server.ts`: `createP9Server(driver, options)` —
      TCP listener, unix-socket listener (0700-checked path), and
      `attach(duplex)` for a socketpair/fd; per-connection framing via
      `framesFrom()`, one `P9Session` per connection, dispatch-without-await +
      buffer re-arm per the zero-copy contract, EOF/error → `session.destroy()`
      (idempotent, safe with requests in flight — there is no DESTROY message;
      same rule as the FUSE `-t fuse` invariant). Tests: JS client over a real
      TCP socket and a unix socket. Commit.
- [x] **8. Independent wire oracle** — a gated test (skips without `tshark`)
      that captures one JS-client-over-TCP exchange covering version/attach/
      walk/lopen/read/readdir/clunk and asserts tshark's 9P dissector agrees
      with our field values (`tshark -d tcp.port==<p>,9p -T fields …`). This is
      the libnfs role: an implementation sharing none of our codecs. Record
      findings in the Log. Commit.
- [x] **9. Probe + mount + packaging** — `src/9p/probe.ts`:
      `p9ClientProbe()` — Linux only, root required, `9p` in
      `/proc/filesystems` OR module loadable (as root, `mount(8)` autoloads;
      treat "no module files at all" as unusable with a precise reason — this
      host's state). Import-light like `src/nfs/probe.ts` (auto must reach it
      without pulling the codec). `src/9p/mount.ts`: `mount9p(driver,
mountpoint, options)` — socketpair, spawn `mount -t 9p -o trans=fd,
rfdno=N,wfdno=N,version=9p2000.L,msize=…` with stdio-padded fd; no mount
      stacking (both directions); teardown deadline + `umount -f` escalation +
      abandoned-child rule; mount-table tri-state (`/proc/self/mounts`);
      unmount detection = EOF on the socketpair. `src/9p/index.ts` re-exports.
      `package.json` exports + obuild config for `mountx/9p`. Tier-2
      `test/9p/mount.test.ts`, probe-gated (expected to RUN on this host now —
      see step 10), added to `pnpm test:root`'s file list with the skip
      self-contained. Commit.
- [ ] **10. Real-mount witnessing (local, under sudo)** — the host loaded the
      9p modules mid-run (see the Tier-2 decision above). Run the Tier-2 suite
      for real: `sh test/root.sh test/9p/mount.test.ts`. If the mount fails
      because `9pnet_fd` did not autoload (EPROTONOSUPPORT-shaped failure on
      `trans=fd`), STOP the loop and ask the user to `modprobe 9pnet_fd` on
      the host — do not fight it and do not fall back to QEMU. Success →
      record the witnessed facts (protocol accepted, msize honored, full
      workload, clean teardown, no leaks in `/proc/self/mounts`) in
      `.agents/environment.md` + the Log, and fix whatever the real kernel
      disagrees with (likely suspects: Tflush ordering, iounit, readdir
      offsets). Note in the Log that QEMU-TCG became unnecessary. Either
      outcome commits.
- [ ] **11. `mountx/auto` + CLI** — `src/auto.ts`: `Transport` gains
      `"9p"`, Linux preference `["fuse", "9p", "nfs"]`, `probe9p()` via
      `p9ClientProbe()` (import-light), `"9p"` options key, tagging;
      `test/auto.test.ts` updated for the new order and reasons (platform
      override answers darwin/win32 from any host). CLI: `-t 9p` accepted,
      stale-mount cleanup recognizes a `9p` entry at the mountpoint (root-only
      route → prints the sudo line, like Linux+NFS). Commit.
- [ ] **12. Docs + agent docs** — **sonnet subagent(s).** `docs/`
      (standalone project, edit files only — no install needed to write):
      new `docs/2.transports/` 9P page (guide prose + full export surface, the
      NFS page as the template), overview page gains the third transport +
      the auto page's table row, reference index maps `mountx/9p`,
      troubleshooting gains the no-9p-module case. README link list touch only.
      `AGENTS.md`: code map section for `src/9p/` + `test/9p/`, invariants
      additions (no-DESTROY-analog EOF rule already generalizes; add the
      9p-specific notes where FUSE/NFS ones live). `.agents/roadmap.md`:
      "Shipped since v1" entry + deferred items (bench column pending a
      mounting host; witnessing status from step 10; multi-client lock table
      if TCP serving grows real users). Commit.
- [ ] **13. Final sweep** — `pnpm matrix` (9p conformance column present, or
      Log why not), `pnpm fmt`, full `pnpm test`, then one independent opus
      review subagent over `git diff main...feat/9p` for invariant violations
      and drift between docs and code. Fix, commit. Then open a PR from
      `feat/9p` to `main` with `gh pr create` (conventional title, body
      summarizing the transport + witnessing status, ending with the
      Claude Code PR trailer per repo conventions), stop the loop, and
      summarize for the user with the PR URL.

## Log

(append one dated line per step: what was learned, what surprised, what was
deferred)

- 2026-07-28 step 1: `wire.ts` + `constants.ts` + 33 tests. Verifier PASS,
  zero defects — scripted diff matched all 118 constants against the kernel
  sources. Learned: the setattr bits live in `fs/9p/vfs_inode_dotl.c`, not
  `9p.h` (both cited in the file header). Fixed pre-commit: a backwards doc
  comment about 9P2000.L's numbering gaps. Deferred nits: the fuzz-suite doc
  reference becomes true in step 2; NaN-count/writer-growth edge cases mirror
  `xdr.ts` convention deliberately.
- 2026-07-28: host loaded the 9p modules mid-run (`9p`/`9pnet`/`9pnet_virtio`,
  no `9pnet_fd` yet) — Tier-2 decision and step 10 rewritten from QEMU-TCG to
  local real-mount witnessing; step 13 now also opens the PR (user request).
- 2026-07-28: host confirmed `9pnet_fd` loaded (lsmod) and persisted in
  `/etc/modules-load.d/9p.conf` — `trans=fd`/`tcp`/`unix` all available with
  no autoload doubt. Step 10's stop-and-ask branch should now be unreachable.
- 2026-07-28 step 2: `protocol.ts` (29 message families both directions,
  framing, dirent packer, latching frame assembler) + 166 tests in 4 files.
  Verifier round 1 FAILED with three real defects — packer wrote 22 bytes
  before throwing on an over-long name (block corrupted), assembler threw
  without latching (desynced stream parsed as garbage), 17 messages lacked
  goldens incl. one a comment claimed existed. Fixed (throw-before-write →
  `ENAMETOOLONG`-able; poison latch + `reset()`-for-next-connection; all
  families byte-pinned) → round 2 PASS with 400k packer / 470k assembler
  fuzz calls and six goldens independently re-derived. Learned: kernel v6.12
  has no `p9_client_auth` — Tauth layout rests on diod alone; decoded anyway
  so the session can refuse it politely. Nits carried: wire.ts scalar writers
  mask silently; assembler O(n²) vs byte-dribblers (same shape as rpc.ts).
- 2026-07-29 step 3: `fids.ts` (fid lifecycle, subtree remap, readdir
  cursors, qid identity) + 50 tests. Verifier round 1 FAILED: qid.path
  dropped `dev` (cross-device ino collapse — v9fs keys its inode cache on
  qid.path), a driver `ino ≥ 2^63` aliased the synthesized range, no release
  API (unbounded memo + recreated paths inheriting dead identities), and
  rewind-to-0 left stale cursors resumable. Fix round removed the dual space
  entirely — qid.path is always allocated, identity keyed `(dev, ino)`
  InodeTable-style, `release()` added, cursors invalidated on any path
  identity change. Round 2 confirmed all fixes but found the fix round had
  introduced the repo's only TS parameter property, which plain `node`
  cannot load in strip-only mode (green under vitest/tsc — caught only by
  running `node -e 'import(...)'`); fixed inline by the orchestrator with
  the verifier's exact repro re-run, plus the lost `Number.isFinite` guard
  in `identityKey`. Step-5 carry-forwards written into the plan: Rgetattr
  st_ino fill, `release()` on remove/create-over, refuse walk-from-open-fid.
  Lesson for later steps: verify with plain `node`, not only the test
  runner.
- 2026-07-29 step 4: `session.ts` (version/attach/walk/clunk/getattr/statfs/
  readdir/flush), `test/9p/client.ts` (Tier-1 client), 60 session tests.
  Corrections to the plan discovered against kernel sources: the wire
  version string is `"9P2000.L"` (capital P); `Rgetattr` has no `st_ino` —
  v9fs derives it from `qid.path`, so the step-3 carry-forward died. The
  server must synthesize `.`/`..` (`v9fs_dir_readdir_dotl` never calls
  `dir_emit_dots`). Verifier round 1 FAILED: readdir byte budget read after
  an await went NaN when a reset landed mid-request (NaN disables the
  packer's budget check → over-msize reply → `p9_conn_cancel()` kills the
  connection), and in-flight requests crossed destroy()/re-version
  unnoticed. Fixed: budget captured in the synchronous prologue, `#msize`
  never undefined, generation counter discards overtaken replies (ENODEV
  after destroy, EIO after re-version). Round 2 PASS, all reproductions
  re-run. Nit carried: destroyed-session getters can report an msize if
  destroy() interleaves inside a parked Tversion reset (cosmetic, gate
  still refuses requests).
- 2026-07-29 step 5: every remaining opcode in `session.ts` (+1147 lines),
  139 session tests, both open models. Verifier round 1 FAILED on two:
  overlapping Tlopen/Tlcreate on one fid leaked a driver handle forever
  (the open-guard ran in the prologue but `entry.open` was assigned after
  awaits — matters because step 7's TCP server faces arbitrary clients),
  and a comment cited a false kernel fact (v9fs DOES map O_CREAT; O_TRUNC
  is the never-mapped one, and `do_dentry_open` strips
  O_CREAT|O_EXCL|O_NOCTTY|O_TRUNC before Tlopen). Fixed via
  `#ensureOpenable` post-await re-check (loser closes its handle, answers
  EBUSY, distinct from sequential-double-open EINVAL); Rlopen re-stats
  after O_TRUNC opens. Round 2 PASS: opens==closes across a 150-round
  6-op-per-round same-fid race stress. Decisions recorded in-code: iounit
  0, directory opens ask the driver nothing, fsync-via-reopen for
  handles:false, CTIME bit accepted as no-op, Tremove clunks even on
  failure/EROFS. Step-12 doc note: a Tlcreate loser's created file
  survives with no fid pointing at it (deliberate; one line in the docs
  page). Twrite is unclamped at session level (frame assembler bounds it
  in real transports; harness-only reachability, documented).
- 2026-07-29 step 6: conformance column (three targets: memory with
  handles, memory handles:false, rooted node:fs oracle with errors:"host";
  adapter `p9Driver` in client.ts walks a fresh fid per call, resolves
  symlinks client-side with the VFS's 40-link bound, chunks I/O at msize)
  - session-fuzz suite (ledger invariant `requests === replies + dropped`).
    The column found a real bug: Tgetattr ignored the open handle, so an
    unlinked-but-open file failed to stat. The first fix REGRESSED — statting
    through the handle fed handle-derived stats to `qidFor`, rebinding a
    symlink's path to its target's identity and undoing release-on-unlink
    (qid churn under a held-open fd). Final shape: the qid is pinned on
    `FidOpenState` at Tlopen/Tlcreate (post-O_TRUNC stats), `qidFor` is only
    ever fed path-derived stats, symlink fids answer from the path, version
    stays a recomputed change token. Verifier round 2 PASS with mutation
    testing — each of the four behaviors fails exactly its own test when
    broken. Pre-existing quirk logged, not fixed: with useDriverIno, an
    identity is forgotten when its last _bound_ name is released even if a
    hardlink made behind the server's back still exists (`#link` binds, but
    a driver-side link does not). Step-13 follow-up recorded: `test/matrix.ts`
    COLUMNS needs the 9p conformance entry.
- 2026-07-29 step 7: `server.ts` (TCP / unix-socket / attach(duplex), one
  session + one assembler per connection, un-awaited dispatch, 22 tests
  over real sockets). Verifier round 1 FAILED on three: close() hung
  forever on a half-closed non-reading peer (the connection forgot itself
  before its socket died, so close() had nothing to hard-drop); reply
  amplification — backpressure paused future reads but not replies of
  already-parsed frames, one 64 KB delivery of 2,800 Treads queued 2.93 GB
  (45,557x, RSS 6 GB); missing .catch on the dispatch chain (attach()ed
  duplex whose write() throws killed the process). Fixed: `#owned` stream
  set emptied by each stream's own 'close' event; serialized reply writes
  awaiting 'drain' + a dispatch window (`DEFAULT_MAX_IN_FLIGHT = 16`,
  excess waits as parsed frames — bytes, not msize-sized replies); the NFS
  server's .catch mirrored. Also fixed for real: the assembler's O(n²)
  re-concat (now a compacting buffer; 256 KiB byte-dribble 7.5 s → 10 ms)
  since TCP exposes it to arbitrary peers. Round 2 PASS: 3,000-seed
  differential fuzz of the new assembler, 240-connection chaos soak, all
  reproductions re-run (amplification now one frame; close() 1 ms).
  Step-12 notes: teardown is a reset not a flush (peer can see ECONNRESET
  with replies queued — say so in docs); bench should record
  `maxInFlight` rather than discover it.
- 2026-07-29 step 8: `test/9p/dissect.test.ts` + `test/9p/pcap.ts` — a
  70-message client↔server exchange recorded off the real duplex, wrapped
  in a JS-built pcap (fabricated Ethernet/IPv4/TCP, computed checksums,
  seq/ack continuity, port 564 so dissection auto-engages) and fed to
  tshark 4.6.7's 9P dissector; 31 tests, three TCP-reassembly cases (one
  frame cut inside its own size field). Verifier PASS after independently
  confirming the headline finding: **a Wireshark defect, not ours** —
  Tgetlock/Rgetlock are dissected with Tlock's phantom `flags[4]`
  (kernel: `"dbdqqds"` vs `"dbqqds"`), misaligning everything after
  `type` and flagging exactly those two frames malformed; the test pins
  the shifted reading and passes either way once upstream fixes it.
  Learned: a positional dissector cannot see symmetric field swaps —
  closed with literal qid-path/uid-gid/statfs-all-nine assertions
  (mutation-checked). tshark has no field for Rlerror's ecode, Tfsync's
  datasync, or Rreaddir entries; covered via message_data bytes and a
  hand-written unpacker.
- 2026-07-29 step 9: `probe.ts`, `mount.ts`, `index.ts`, the `mountx/9p`
  subpath export and obuild entry, 24 Tier-0 tests plus a probe-gated Tier-2
  suite (skips as non-root; `pnpm test:9p:mount`, and added to `pnpm
test:root`). **The plan's `trans=fd` decision became `trans=unix`.**
  `net/9p/trans_fd.c` (v6.12) registers `tcp`, `unix` and `fd` off one file;
  `p9_fd_create_unix()` takes the mount's _source_ argument as a socket path
  and connects to it itself, and the kernel's own
  `Documentation/filesystems/9p.rst` mounts exactly that way — so the
  socketpair Node cannot make without native code buys nothing here: a
  `mkdtemp` 0700 directory holding a 0600 socket has the same "no other local
  user can reach it" property, and the code is symmetric with `mountNfs`'s
  spawn. `trans=fd` deferred to a relay mode that already holds a descriptor
  (docs note in step 12). `trans=tcp` is reachable by passing `port`/`host`.
  Option defaults settled against the sources rather than guessed: `msize` is
  the kernel's own `DEFAULT_MSIZE` (128 KiB + `P9_IOHDRSZ`, so the _payload_ is
  a round 128 KiB), clamped to `MAX_SOCK_BUF` = 1 MiB — which is also
  `P9Session`'s ceiling, so the two agree by construction; `access=client`,
  which is v9fs's own default for 9P2000.L (`v9fs_session_init()`) and the same
  posture as FUSE's `default_permissions` — `access=user` would mean _no_
  permission checking anywhere, since this server makes no access decisions;
  `cache=none`, because 9P has no invalidation channel at all (no
  `notify_inval_inode` analogue), so any client caching is a bet that nothing
  else changes the driver; `uname=nobody`/`aname=/` restated rather than left
  to the kernel. `UNIX_PATH_MAX` (108) is checked before anything binds.
  Comma hazard resolved the other way from NFS's `exportPath`: the socket path
  and the mountpoint are separate argv elements, so only the four option
  _values_ are refused. `umount -f` is real for 9P — v9fs implements
  `.umount_begin` → `v9fs_session_begin_cancel()`. `src/fuse/exec.ts` gained an
  optional `timeout` (kill, abandon, report `timedOut`) rather than the repo
  growing a third copy of `run()`; `/proc/self/mounts` parsing _is_ duplicated,
  deliberately, because importing `src/nfs/mount.ts` would drag the RFC 1813
  codec into every 9P mount. Verifier PASS with three defects, closed in the
  same step: no precondition on a `trans=tcp` source (`valid_ipaddr4()` takes a
  dotted quad and nothing else — no hostname, no IPv6 — so a `host: "::1"` the
  _server_ accepts mounted as `wrong fs type`; now `tcpSourceRefusal()`, pure
  and tested); `p9MountOptions` emitted `target.port` verbatim, and
  `trans_fd.c`'s `parse_opts()` silently _ignores_ a `port=` it cannot parse and
  connects to 564, so a bad port is now a refusal (integer in [1, 65535]) rather
  than a clamp; and connection adoption was an unserialized set-difference over
  `server.clients`, now a per-server mutex over snapshot→mount→adopt plus a
  loopback-peer filter when the `trans=tcp` source is loopback, with the
  residual third-party race — and the fact that teardown closes a
  caller-supplied server, and that such a server's session does not see
  `readOnly` — documented on `MountP9Options.server`. In the same pass
  `src/nfs/mount.ts`'s private `run()`/`describe()`/`errorMessage()` were
  deleted: `exec.ts`'s `run()` grew stdout capture and is now the only copy, and
  the NFS suite passes unchanged.
