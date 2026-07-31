# Testing

## Tiers

- **Tier 0** — pure, no sockets, no mounts, no privileges. Codecs, tables, state
  machines, pure refusal/advice helpers. Runs everywhere under `pnpm test`.
- **Tier 1** — real sockets and in-process sessions driven by a JS client written
  against the session's own codecs. Still no root, still under `pnpm test`.
- **Tier 2** — a real kernel mount. Every file here skips itself when the host cannot
  do it (`nfsClientProbe()`, `p9ClientProbe()`, `rootlessProbe()`) and when the
  threadpool has not been raised. Reached through `test/root.sh` / `test/rootless.sh`,
  never through a plain `pnpm test`.

## The conformance matrix

`test/conformance.ts` is the one Tier-0 suite, written against the driver interface.
`drivers.test.ts` runs it against memory, node-fs, unstorage and raw
`node:fs/promises` (the loopback column); each transport contributes its own column
through its Tier-1 JS client, and FUSE contributes a real-mount column.

- A case may name an extension as its requirement (`mountx.mknod`, alongside the
  capabilities and `root`) — `capabilities.extensions` is a _list_, so a gate on it
  as a whole would skip everywhere and say nothing about which member it wanted.
- `test/no-extensions.ts` is the other side of the same seam: `withoutExtensions(driver)`
  drops the `mountx` key so the four sessions' no-extension paths keep being tested
  now that the memory driver has one.
- `test/latency.ts` is the other driver wrapper: `withLatency(driver)` pushes every
  call to the next macrotask, because the memory driver answers inside a microtask
  and two requests that arrive together therefore run through it in lockstep. That
  hides every "the duplicate reached the table before the original wrote to it"
  bug — the NFS exclusive-create verifier was recorded a `close()` too late and
  every suite was green over it — so a case about _ordering under concurrency_
  belongs against this rather than against a bare memory driver.
- A target declares `errors: "host"` when it forwards the host kernel's errors rather
  than carrying `src/errors.ts`'s table: on Linux that changes nothing, and on darwin
  it is what lets the suite hold the _code_ exact while allowing either number
  (`ENOTEMPTY` is 66 there, not 39) and expect BSD's `EPERM` for `unlink` of a
  directory.
- `test/rooted-node-fs.ts` — `node:fs/promises` rooted at a directory; the oracle
  shared by `drivers.test.ts` and the FUSE conformance column.
- `test/matrix.ts` generates `.agents/conformance-matrix.md` (`pnpm matrix`). Its
  `unmetIn()` counts a capability as met when **at least one** target in the column
  passed a case naming it, not every one — the drivers sharing a column need not have
  the same capabilities now that `unstorage` runs beside `memory`. A `mountx.*`
  requirement is dropped from the "capabilities lost" table (not from the per-case
  rows): the suite reaches an extension by name through `fs.mountx`, which only the
  loopback column has, so a skip in a transport column is about how the case is
  written and not about what the wire carries — all four sessions carry `mknod`.

## Per area

- `test/9p/` — Tier 0 (`wire`, `protocol` + `golden`, `fuzz`, `fids`, `session`,
  `session-fuzz`, `server` — a real TCP and unix-socket server, `mount-options` —
  `p9MountOptions()`/`socketPathRefusal()`/`tcpSourceRefusal()`, checked with no
  mount), the Tier-1 JS client (`client.ts`, built on the session's own codecs, like
  `test/nfs/v3/client.ts` — it walks a fresh fid per call and resolves symlinks
  client-side, chunking I/O at `msize`) and its conformance column
  (`conformance.test.ts` — memory with handles, memory `handles: false`, and the
  rooted `node:fs` oracle with `errors: "host"`), `dissect.test.ts` + `pcap.ts` — the
  independent wire oracle: a real client↔server exchange wrapped in a JS-built pcap
  and fed to `tshark`'s 9P dissector, the same role libnfs plays for NFS. Its one
  finding is upstream's, not this transport's: `Tgetlock`/`Rgetlock` are dissected
  with `Tlock`'s phantom `flags[4]` field (kernel struct string `"dbdqqds"` vs.
  `"dbqqds"`), misaligning everything after `type` in exactly those two frames — the
  test pins the shifted reading rather than "fixing" a defect that is not ours.
  Tier-2 `mount.test.ts` is gated on `p9ClientProbe().usable`; sudo only (`pnpm
test:9p:mount` / `pnpm test:root`) — 9P has no unprivileged route on any host, so
  there is no `9p` file under `pnpm test:rootless`.
- `test/fuse/` — protocol/session Tier 0 (`random.ts`, `protocol`, `golden`,
  `dirent`, `init`, `flags`, `session`, `inodes`, `session-fuzz`,
  `synthetic-kernel.ts`, `fuzz`), `exec.test.ts` (the shared spawn/deadline helpers,
  including the child that must not keep the caller's event loop alive),
  `fusermount.test.ts` (the elevation checks and the device-refusal advice — pure, so
  it runs on a host with no `fuse3` at all), `native.test.ts` (the whole addon —
  passing a descriptor to yourself needs no helper and no privileges), Tier 2
  `mount.test.ts` and `mount-rootless.test.ts` (no sudo), the differential oracle
  (`differential.ts` + `differential.test.ts`), record/replay (`record-fixtures.ts` +
  `replay.test.ts`), the FUSE conformance column (`conformance-mount.test.ts`).
- `test/nfs/` — Tier 0 for the shared layer (`xdr`, `handles`, `mount-options` — the
  platform difference, checked from either host) plus `session.test.ts` for the
  version router alone: which session a `(prog, vers)` pair reaches, and nothing
  about what it does once it arrives. In `v3/` beside the code it covers: Tier 0 for
  the protocol (`protocol`, `golden`, `fuzz`) plus the Tier-1 JS client (`client.ts`)
  and its conformance column. In `v4/`: `constants.test.ts` (the transcription check
  — RFC spot-checks at distinct points plus whole-table shape assertions, no gap, no
  repeat, every value named), `attr`, `protocol`, `golden`, `fuzz` for the codec,
  `state.test.ts` for the state machine alone (synchronous, no socket — the replay
  cache and the lease clock proved with an injected clock rather than a real
  `setTimeout`), `session.test.ts` for COMPOUND dispatch driven with encoded bytes,
  and the Tier-1 JS client (`client.ts`, which does its own path-walking and
  POSIX-vs-NFSv4 op-collapsing — `unlink` vs `rmdir`, OPEN not being for directories)
  plus `driver.ts` (the `FsDriver` over it) and `conformance.test.ts`.
- `test/s3/` — Tier 0 (`sigv4.test.ts` against the official `aws-sig-v4-test-suite`
  goldens, `xml`, `chunked`, `protocol`, `constants` — the errno↔S3-error table's
  totality), `server.test.ts` (real sockets, driven with `fetch`), the Tier-1 signing
  JS client (`client.ts`) and its conformance column (`conformance.test.ts`,
  `session.test.ts`, in-process against the memory driver, no sockets), and
  `oracle.test.ts` — a real `rclone`/`curl` against the gateway, gated on `command -v
rclone`/`curl` and needing no root, so it runs as part of `pnpm test` and skips
  clean when either binary is absent.
- `test/webdav/` — Tier 0/1, all of it socket-optional: `protocol.test.ts` (the
  three request grammars, the `If` header's disjunction-of-conjunctions, the
  `multistatus`/`error`/lock documents, and the target↔`href` mapping round-tripped
  — the security-relevant half, since a name is the only thing that decides which
  resource a request reaches), `locks.test.ts` (the lock table alone, with `now` a
  number the test moves and `newToken` a counter: §9.10.5's compatibility table,
  both scopes, the lease, and §6.1's rule that a lock dies with its root),
  `session.test.ts` (in-process against the memory driver, no sockets: RFC 4918's
  per-method semantics, `LOCK`/`UNLOCK` and what a write lock refuses — `412`,
  `423` and the `207` that names a locked member — RFC 9110's conditionals, the
  `207` partial-failure shapes for `DELETE` and `COPY`, Basic auth, and the
  one-reply discipline), and `server.test.ts` (real sockets driven with `fetch`
  plus one raw one: the bind gate, keep-alive, an unread body drained, a short body
  taking the connection with it, and an abandoned download releasing its handle),
  plus `oracle.test.ts` — a real `rclone` and `curl` against the server, gated on
  `command -v` and needing no root, so it runs as part of `pnpm test` and skips
  clean when either binary is absent. That is the file that catches a symmetric
  misreading of RFC 4918 — including the whole class-2 round trip, where curl takes
  a lock on an unmapped URL, is refused `423` for an untokened `PUT`, and gets
  through with an `If` header. **No conformance column yet** — see Known gaps.
- `test/webdav/mount.test.ts` — Tier 2, and the only test in the package that puts a
  **kernel** in front of this server: `mount.davfs` (davfs2, over FUSE) mounts the
  share and the workload is ordinary syscalls, not WebDAV. Gated on the in-file
  `davfsClientProbe()` — Linux, `mount.davfs`, `/dev/fuse`, and root, since davfs2
  refuses an unprivileged caller without an `/etc/fstab` entry — so it is sudo only
  (`pnpm test:webdav:mount` / `pnpm test:root`) and skips clean everywhere else. Two
  facts shape it, both in `.agents/environment.md`: davfs2 caches, so a driver-side
  check is a bounded poll and the read path is proved by seeding the driver _before_
  mounting; and teardown is `umount -i`, because the `umount.davfs` helper waits on a
  daemon that a container with no reaping init never reaps.
- `test/auto.test.ts` — Tier 0 for `mountx/auto`: the preference order and the
  ruled-out reasons, answered for darwin and win32 from any host via the `platform`
  override. `test/auto-mount.test.ts` — Tier 2, whichever transport this host chose.
- `test/unstorage.test.ts` — Tier 0 for what conformance cannot see about
  `drivers/unstorage.ts`: the key mapping itself, an existing store mounted as a
  tree, the shared open buffer, and read-only.
- `test/pjdfstest/` — `run.sh` + `run.ts` drive the pinned pjdfstest clone
  (gitignored) against a real mount and write `.agents/pjdfstest-results.md`.

## Known gaps

- **No WebDAV conformance column.** `test/webdav/` pins the protocol thoroughly but
  does not run the shared suite, because that needs an `FsDriver` built over the
  WebDAV session the way `test/s3/client.ts` is over the S3 one — and a WebDAV client
  can offer no `handles`, no `symlinks`, no `permissions` and no `truncate`, so most
  of what the column would report is already known from the protocol. It is worth
  writing anyway, for the same reason the S3 column was: the rows nobody predicted
  are the point. Until then `pnpm matrix` has five columns, not six.

- **No real-mount NFSv4.1 column.** Tier-2 `test/nfs/mount.test.ts` is v3-only; the
  dev host has no `mount.nfs` to write a v4.1 one against. The protocol is not
  unwitnessed, though: a VM guest supplies the missing client, and two of them have
  mounted this server with `vers=4.1` and passed a read/write/mkdir/dd/rename/unlink
  workload — an Alpine guest under QEMU, and a real Firecracker microVM (whose root
  image has no `mount.nfs` at all, which works because an explicit
  `addr=`/`clientaddr=` leaves the helper nothing to resolve). See
  `.agents/environment.md` § VM guests. Turning that into a Tier-2 column would mean
  carrying a VM in the suite.
- **No NFSv4.1 or S3 benchmark column**, and the 9P one is from a later sitting than
  the rest — see `.agents/benchmarks.md`.

## Runner scripts

- `test/root.sh` — runs any Tier-2 vitest file under sudo with the environment fixed
  up (raised `UV_THREADPOOL_SIZE`, redirected `TMPDIR`, forwarded `MOUNTX_*`); every
  Tier-2 file skips itself when not root. Root's `PATH` lacks `node` (fnm), which is
  why it invokes `sudo "$(command -v node)" ...` rather than plain `sudo node ...`.
- `test/rootless.sh` — the same idea minus the `sudo` and minus everything `sudo`
  made necessary: `UV_THREADPOOL_SIZE` is all that is left, and
  `mount-rootless.test.ts` skips itself unless it has been raised. That gate is what
  keeps a plain `pnpm test` from mounting anything now that macOS needs no root.
