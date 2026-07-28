# 9P2000.L transport — implementation plan

Executed step-by-step by an autonomous loop on branch `feat/9p`. One step per
loop iteration. This file is the single source of truth for progress: a step
is done when its checkbox is checked **and** its commit exists.

## Decisions (settled with Pooya, 2026-07-28)

- **Naming:** directory `src/9p/`, subpath export `mountx/9p`, test dir
  `test/9p/`. Identifiers use a `P9` prefix (`P9Session`, `createP9Server`,
  `mount9p`, `p9ClientProbe`) — mirrors the kernel's own `p9_*` naming.
  The `mountx/auto` options escape hatch is the quoted key `"9p"`.
- **Version:** `9p2000.L` only. Any other `Tversion` string answers
  `Rversion` with `"unknown"` per spec. Legacy 9P2000 opcodes
  (`Topen`/`Tcreate`/`Tstat`/`Twstat`) answer `Rlerror ENOTSUP`.
- **Locks:** `Tlock` always grants (`P9_LOCK_SUCCESS`), `Tgetlock` always
  reports unlocked. Honest for a single-client loopback server — the client
  kernel does local POSIX-lock bookkeeping; documented as such where the
  NFS `nolock` decision is documented.
- **Server scope:** full `createP9Server` — TCP listener, unix-socket
  listener, and an attach-a-duplex/fd mode used by `mount9p()`'s socketpair.
- **Local mount path:** `mount -t 9p -o trans=fd,rfdno=N,wfdno=N` with a
  socketpair, the child's stdio padded so the fd number matches its position
  (the exact trick `src/fuse/mount.ts`'s root path uses — see
  `.agents/environment.md` "fd mapping" caveat). No port, no socket path,
  no exposure to other local users. TCP is for serving external clients
  (VM guests: `trans=tcp` against the host).
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
- [ ] **2. Message codecs** — `src/9p/protocol.ts`: every 9P2000.L message
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
- [ ] **3. Fid table** — `src/9p/fids.ts`: fid → path + open state (driver
      `FileHandleLike` or path-mode) + iounit + per-fid readdir cursor keyed by
      offset (re-`readdir` on offset 0 or unknown offset, like FUSE paging).
      Walk clones fids; clunk/remove release; qid synthesis from `StatsLike`
      (type from mode; path from ino — respect `useDriverIno` option parity
      later). `..` clamps at the root (`src/path.ts` semantics). Tests
      `test/9p/fids.test.ts`. Commit.
- [ ] **4. Session core + JS client** — `src/9p/session.ts`: `P9Session
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
- [ ] **5. Session I/O + namespace ops** — lopen/lcreate (flags through
      `driverOpenFlags()`; `handles: false` drivers get the reopen-per-op path
      with `reopenFlags()` semantics), read/write (clamped to msize−IOHDRSZ,
      payload copied before await), fsync, setattr (bitmask → driver calls,
      mirroring the FUSE SETATTR switch), mkdir, symlink, readlink, link,
      mknod (wire to `mountx.mknod` if declared, else ENOSYS — matches FUSE),
      rename/renameat/unlinkat/remove (**`PathLock` from `src/lock.ts` around
      rename**, subtree fid-path remap on rename like `InodeTable` does),
      xattrwalk/xattrcreate → ENOTSUP (Linux clients probe `security.*` on
      write — the refusal path is hot, keep it cheap), lock/getlock per the
      grant-all decision, legacy opcodes → ENOTSUP. Extend session tests.
      Commit.
- [ ] **6. Conformance column + session fuzz** — `test/9p/conformance.test.ts`
      runs `test/conformance.ts` through the JS client against `P9Session` over
      memory + node-fs (rooted oracle), like the NFS column. A session fuzz
      file (hostile frames, bad fids, bad tags, flush races) in the spirit of
      `test/fuse/session-fuzz.test.ts`. Fix what they find. Commit.
- [ ] **7. Server** — `src/9p/server.ts`: `createP9Server(driver, options)` —
      TCP listener, unix-socket listener (0700-checked path), and
      `attach(duplex)` for a socketpair/fd; per-connection framing via
      `framesFrom()`, one `P9Session` per connection, dispatch-without-await +
      buffer re-arm per the zero-copy contract, EOF/error → `session.destroy()`
      (idempotent, safe with requests in flight — there is no DESTROY message;
      same rule as the FUSE `-t fuse` invariant). Tests: JS client over a real
      TCP socket and a unix socket. Commit.
- [ ] **8. Independent wire oracle** — a gated test (skips without `tshark`)
      that captures one JS-client-over-TCP exchange covering version/attach/
      walk/lopen/read/readdir/clunk and asserts tshark's 9P dissector agrees
      with our field values (`tshark -d tcp.port==<p>,9p -T fields …`). This is
      the libnfs role: an implementation sharing none of our codecs. Record
      findings in the Log. Commit.
- [ ] **9. Probe + mount + packaging** — `src/9p/probe.ts`:
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
