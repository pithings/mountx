# Architecture

The per-file map, with the reasoning that is not visible from the code. `AGENTS.md`
carries the short version and the invariants; this file is what you read before
changing something in an area you have not touched yet.

Every transport directory follows the same shape — `constants.ts` (transcribed from
the kernel header or RFC named in the file), `protocol.ts` (every message encoded
**and** decoded, both directions), `session.ts` (protocol ↔ `FsDriver`), a
`server.ts` and/or `mount.ts`, a `probe.ts` where the host can refuse, and an
`index.ts` that re-exports by name. What follows is what each one does beyond that
pattern.

## Core (`src/`)

- `types.ts` — `FsDriver` (a subset of `node:fs/promises`; `node:fs/promises` itself
  is assignable to it), `FsCapabilities`, the `mountx.*` extension namespace,
  `StatsLike`/`DirentLike`/`FileHandleLike`. The namespace is **two live members**,
  not a typed-only shelf: `mknod` is consumed by the FUSE, 9P and both NFS sessions
  and implemented by `drivers/memory.ts`, `utimens` by FUSE and 9P. There are no
  xattr methods — no session ever had an opcode case for them, and re-adding them
  would be type-only.
- `errors.ts` — `ERRNO_CODES` (Linux values), `fsError()` producing errors
  byte-identical to `node:fs`'s, `errnoOf()` for transports.
- `path.ts` — absolute POSIX path helpers; `..` clamps at the root.
  `normalizePath`/`dirname`/`basename` early-return on an already-canonical path
  after one allocation-free scan, which is the case every session hands a driver
  (they have all been through `joinPath`); a non-canonical path pays ~12 ns for the
  failed scan. `resolvePath()` returns `{ path, segments }` for the callers that
  would otherwise normalize and then split the same string again.
- `harness.ts` — `createLoopback(driver)`: normalizes paths, fills missing methods
  with `ENOSYS`, resolves capabilities. What driver authors test against. The method
  table is resolved **once at construction**, so a driver that grows a method
  afterwards keeps answering `ENOSYS` — no caller in the repo mutates a driver after
  wrapping it, and `cli/watch.ts`'s `Proxy` is stateless per access. `readOnly` is
  declared-only, like `handles`: inferring it from the absence of
  `unlink`/`mkdir`/`rename` labelled a driver read-only that could still `open` for
  writing, `truncate` and `chmod`.
- `lock.ts` — `PathLock`, the writer lock over the path map, shared by the FUSE, 9P
  and NFS sessions (`RENAME` takes it; `READ`/`WRITE` run outside it). 9P holds one
  `PathLock` per connection, not per driver — a rename is serialized against other
  work on the same connection and not against a second client's, the way two local
  processes racing a rename on the same filesystem are not serialized against each
  other either.
- `subtree.ts` — `remapSubtree()`, the path-keyed subtree rewrite a rename forces on
  all three transports' tables (`fuse/inodes.ts`, `nfs/handles.ts`, `9p/fids.ts`),
  driven by each table's own detach/attach pair rather than reimplementing either.
  What is shared is the walk — which paths are affected, in what order, and the
  two-pass rewrite that stops a destination which is also a source being clobbered;
  what "this path went away" _means_ stays in each table, because the three
  genuinely differ (FUSE keeps the orphan reachable by nodeid for a later `FORGET`,
  NFS drops the key and the id with the root exempt, 9P releases the qid identity
  outright). Internal — not re-exported, and deliberately not in `path.ts`, which is
  public. Cost: O(tracked paths), two scans per rename, and FUSE runs it under
  `PathLock.write`; a trie is the real fix and is out of scope until there is a
  benchmark that wants it.
- `auto.ts` — exported as `mountx/auto`: `probeTransports()` and a `mount()` that
  picks FUSE where FUSE works (root _or_ `fusermount3`), then 9P, then NFS — which
  is what macOS gets regardless, since neither FUSE nor v9fs exists there. Every
  transport arrives via `await import()`, and the probe reaches only `nfs/probe.ts`,
  `9p/probe.ts` and `fuse/fusermount.ts`, so choosing one never loads either other
  codec. The result is the transport's own mount object with a `transport`
  discriminant defined on it — tagged, not wrapped. No fallback after a failure, and
  no probe when a transport is named: both are deliberate, see the module docs.
  `unmountAll()`/`liveMounts()` are scoped by which transports `mount()` has loaded
  and by nothing else — each transport keeps one process-wide `live` set, so a mount
  made by importing `mountx/fuse` directly is reported _and_ torn down here once
  `auto` has loaded FUSE; the only gap is a transport `auto` never loaded, and
  closing it would need import-time self-registration that `"sideEffects": false`
  entitles a bundler to drop. `p9ModuleRefusal` is the one extra refusal this file
  adds on top of `p9ClientProbe()`'s own verdict: a virtio-only guest (no `9pnet_fd`,
  no module tree to load one from) reports `usable` from the probe but would fail to
  actually mount, and the no-fallback rule makes a wrong choice here costly in a way
  it is not for a _named_ `-t 9p`, where trying and failing in 9P's own words is
  fine.

### Drivers (`src/drivers/`)

- `memory.ts`, `node-fs.ts` — the two built-in drivers; the passthrough resolves
  every path component itself so nothing escapes its root. Memory is the **only
  implementation of `mountx.mknod`** in the repo, which is what makes FIFOs, sockets
  and device nodes reachable through all four sessions rather than a typed path with
  nothing behind it: the node carries the type in `mode` and the number in `rdev`,
  and the client's own VFS supplies the pipe/socket/device semantics — so the driver
  stores and nothing more. It holds no bytes, hence `open` → `ENXIO` and `truncate` →
  `EINVAL` on one (unreachable over a mount, where every client handles these types
  locally, so the only caller is a loopback one and a byte buffer would be a
  filesystem no mount has). `createMemoryDriver` returns `MemoryDriver`, whose
  `mountx.mknod` is non-optional, so callers need no `!`.
- `handle.ts` — the parts of a `FileHandleLike` that are identical in every driver
  holding its own bytes, shared by `memory` and `unstorage`: `parseOpenFlags()` (both
  `node:fs` flag namespaces), `validateRange()`/`validatePosition()` (the
  `ERR_OUT_OF_RANGE` rejections `node:fs` makes), and `resizeBytes()` (geometric
  growth, `EFBIG` by asking the engine rather than assuming a cap). Pure; touches no
  filesystem.
- `unstorage.ts` — exported as `mountx/drivers/unstorage`: an `FsDriver` over an
  [unstorage](https://unstorage.unjs.io) `Storage`, which makes every unstorage
  driver mountable. `unstorage` is an **optional peer dependency imported for types
  only** — the built `dist/drivers/unstorage.mjs` has no import of it, so
  zero-runtime-deps holds. Path `/a/b` is the key `a:b` (unstorage's own
  `normalizeKey` already maps `/` onto `:`); directories are key prefixes, and an
  empty one exists only in this process because a marker key would be a file to
  every other consumer of the store. Random access is buffered per path — one shared
  `OpenFile` per open path, written back on `fsync` and last `close` — because
  `Storage` has no partial read or write. Permissions and timestamps are an
  in-memory overlay seeded from `getMeta`. `:`/`?`/trailing-`$` in a name answer
  `EINVAL` rather than corrupting quietly (`normalizeKey` eats all three). No
  symlinks, hardlinks or `statfs`, and `rename` is copy-then-delete, all declared.

## FUSE (`src/fuse/`, exported as `mountx/fuse`)

- `constants.ts` — opcodes and `FUSE_*`/`FOPEN_*`/`FATTR_*`/`DT_*`, transcribed from
  the kernel's `include/uapi/linux/fuse.h` (tag v6.12, protocol 7.41).
- `protocol.ts` — every struct encoded and decoded, opcode dispatch table
  (`OPCODES`), message framing, errno-on-the-wire helpers, dirent packing
  (`DirentPacker`).
- `init.ts` — `negotiateInit(kernelInit, preferences)`, pure.
- `flags.ts` — the two `open(2)` flag namespaces, pure: `driverOpenFlags()` turns the
  kernel's `O_*` into the host's for the hand-off to a driver (the identity on Linux,
  where the wire _is_ the host, so unnamed bits survive), and `reopenFlags()` drops
  the one-shot creation flags a `handles: false` re-open must not repeat. The
  translation exists because Tier-0 tests drive a real session on whatever host runs
  `pnpm test`, and macOS's `O_TRUNC` is Linux's `O_APPEND`.
- `session.ts` — `FuseSession(driver, options)`: `INIT` handshake, opcode switch,
  file-handle table, readdir paging, `SETATTR` bitmask → driver calls, notify
  encoders.
- `inodes.ts` — `InodeTable`: nodeid ↔ path ↔ `(dev, ino)`, lookup refcounting,
  subtree remap on rename, orphans. Entirely synchronous.
- `notify.ts` — `notify_inval_inode`/`notify_inval_entry` codecs.
- `mount.ts` — `mount(driver, mountpoint, options)` → `Mount`, plus
  `unmountAll()`/`liveMounts()`. Picks its path by uid: root opens `/dev/fuse` here
  and spawns `mount(8)` with the descriptor at its own fd number; everyone else goes
  through `fusermount.ts`. Past the descriptor the two paths are the same code.
- `fusermount.ts` — the unprivileged mount path: `rootlessProbe()`,
  `mountViaFusermount()` → fd, `unmountViaFusermount()`. The `_FUSE_COMMFD`
  handshake is transcribed from libfuse 3.18.2 (`lib/mount.c`,
  `util/fusermount.c`), including which `-o` options the helper accepts and which
  four it supplies itself. The privilege comes from the helper's setuid bit and
  nowhere else, and `failed to open /dev/fuse: Permission denied` means it never
  arrived — **never** that the device's mode is wrong, since `mount_fuse()` opens the
  device before its `setfsuid`-based `drop_privs()`, so a real setuid-root helper
  opens a 0600 root-owned device fine (a devtmpfs with no udev rule gives exactly
  that, and it is a red herring every time). `rootlessProbe()` checks the two causes
  visible in advance — the setuid bit, and `no_new_privs`, which makes the bit inert
  for the whole process tree and cannot be cleared — via `elevationRefusal()` and
  `execPrivileges()` (one `/proc/self/status` read for `NoNewPrivs` and for `CapAmb`,
  whose `CAP_SYS_ADMIN` is the one arrangement where a helper with no bit still
  works). `deviceRefusalAdvice()` names what is left (`nosuid`, an LSM, a device
  cgroup) after a failure, the way `consentAdvice()` does for macOS. All pure, tested
  in `test/fuse/fusermount.test.ts`.
- `native.ts` — reshapes the addon's raw positive `errno` into a `node:fs`-shaped
  `code`/negative `errno`. Never imported on the root path. Locating and `dlopen`ing
  the binary is _not_ here: that is `#unfs/native` (`native/index.mjs`).
- `exec.ts` — `run()`/`describe()`/`errorMessage()`/`stdioWith()` plus
  `deadlineIn()`/`Deadline` and `delay()`, shared by all five files that spawn
  (`fuse/mount.ts`, `fuse/fusermount.ts`, `9p/mount.ts`, `nfs/mount.ts`,
  `cli/index.ts`). It lives under `fuse/` for historical reasons rather than
  transport ones. `run()` carries an optional `timeout` (kill, abandon, report
  `timedOut`) and stdout capture. `Deadline` exists because the teardown invariant is
  about a _sequence_ of spawns: one budget is built at the top of a phase and each
  step is given `remaining()`. Steps each handed the whole `unmountTimeout` are how a
  documented ten seconds had become a possible **thirty** on Linux NFS and 9P (a 10 s
  `umount`, then a two-rung ladder of 10 s each) and **twenty-five** on macOS NFS
  (the graceful race capped the first phase at 10 s, then a one-rung ladder of a 5 s
  table read plus a 10 s `umount -f`); the same arithmetic is written out at
  `src/nfs/mount.ts`'s `#unmount`. `test/fuse/exec.test.ts` is Tier 0 over all of it,
  including the case the invariant exists for: a child that outlives its deadline and
  whose stdio a survivor still holds must not keep the caller's event loop alive.
- `record.ts` — tees `/dev/fuse` traffic (`mount({ tap })`) into a transcript;
  `replayTranscript()` feeds one back through a fresh session.

## 9P (`src/9p/`, exported as `mountx/9p`)

- `wire.ts` — the 9P primitives: `P9Reader`/`P9Writer`, little-endian, unaligned,
  bounds-checked; u64 as `bigint`, strings length-prefixed UTF-8 with no padding, qid
  encode/decode. The reader copies retained bytes, same rule as everywhere else.
- `constants.ts` — message types (`P9_T*`/`P9_R*`), `P9_GETATTR_*`/`P9_SETATTR_*`
  masks, `P9_LOCK_*`, qid type bits, `P9_MAXWELEM`, transcribed from the kernel's
  `include/net/9p/9p.h` (tag v6.12, matching the FUSE constants' tag) with diod's
  `protocol.md` as the prose reference.
- `protocol.ts` — every 9P2000.L message encoded and decoded, both directions (the JS
  test client needs the T-encoders/R-decoders, the session the inverse); frame
  helpers (`size[4] type[1] tag[2]` header, `P9FrameAssembler` reassembly, latched so
  a desynced stream parses as a poisoned connection rather than garbage);
  `P9DirentPacker`.
- `fids.ts` — `FidTable`: fid → path + open state + iounit + a per-fid readdir cursor
  keyed by offset (offset 0 resnapshots; an unknown non-zero offset is `EINVAL` —
  offsets are cookies this table mints, not real positions). Qid identity is keyed
  `(dev, ino)` InodeTable-style; `qid.path` is always allocated from the table's own
  counter, because `Rgetattr` has no `st_ino` field — v9fs derives `st_ino` from
  `qid.path` (`v9fs_qid2ino()`), so a driver's own `ino` never reaches the 9P wire
  and `useDriverIno` only selects which files share that identity, not what goes on
  the wire. `release()` clears an identity on remove/create-over so a recreated path
  never inherits the dead file's number. Entirely synchronous.
- `session.ts` — `P9Session(driver, options)`: version negotiation (`msize =
min(client, cap)`; rejects anything but `"9P2000.L"`, capital P), attach (aname
  `""`/`"/"` → root fid), walk (`P9_MAXWELEM`, partial-walk `Rwalk` semantics — error
  only when the first element fails), the whole `.L` opcode set
  (lopen/lcreate/read/write/fsync/setattr/mkdir/symlink/readlink/link/mknod/rename
  family/lock family), `Tflush` (the protocol's only ordering rule — answered only
  once the tag it names has settled), legacy 9P2000 opcodes and anything
  unrecognized → `Rlerror ENOTSUP`. `Rlerror` carries a positive Linux errno straight
  from `src/errors.ts` — the one transport with no status-mapping layer at all.
  `Tlopen`/`Tlcreate` flags are the Linux kernel's `O_*`, the same wire FUSE has,
  crossed to the driver with `src/fuse/flags.ts`'s `driverOpenFlags()` — imported
  rather than duplicated, a deliberate dependency from `src/9p/` onto `src/fuse/`
  because the translation is a fact about Linux and the host, not about either
  transport. `Tlock`/`Tgetlock` grant unconditionally — honest for one client's local
  POSIX-lock bookkeeping, not for two (see `server.ts`). A `Tlcreate` race loser's
  file survives on the driver with no fid pointing at it — deliberate, not a leak the
  table tracks.
- `server.ts` — `createP9Server(driver, options)`: a TCP listener, a unix-socket
  listener (its directory checked `0700`, the socket itself chmoded `0600`), and
  `attach(duplex)` for an embedder holding a stream — the same code past the stream
  either way. One `P9Session` and one `P9FrameAssembler` **per connection**: fids are
  per-connection state in 9P, so two clients get two fid tables and two negotiated
  `msize`s over the one driver they share, and `Tlock` granting unconditionally is
  only honest for the first of them. Dispatch is un-awaited and bounded by a
  per-connection window, `DEFAULT_MAX_IN_FLIGHT = 16`, against a client that
  pipelines thousands of requests in one delivery (2,800 `Tread`s fit in 64 KiB and,
  all dispatched at once, would answer with gigabytes nobody asked for); replies are
  serialized one `write()` at a time and go out in completion order, matching the
  protocol's own tag-based reply matching rather than request order. `close()` is a
  **reset, not a flush** — every accepted socket is destroyed outright rather than
  waited for politely, so a peer can see `ECONNRESET` with replies still queued; a
  mounted client otherwise keeps its connection open forever, so a close that waited
  for it would never return.
- `mount.ts` — `mount9p(driver, mountpoint, options)` → `P9Mount`: mounts
  `trans=unix` — a unix-domain server on a `mkdtemp` `0700` directory holding a
  `0600` socket, which `mount -t 9p` is pointed at as its _source_ argument
  (`p9_fd_create_unix()` connects to it itself; `Documentation/filesystems/9p.rst`
  mounts this exact shape). `trans=tcp` is reachable too, for the VM-guest case (a
  guest mounting its host), checked against `valid_ipaddr4()` — a dotted-quad IPv4
  literal only, no hostnames and no IPv6. `trans=fd` stays **deferred**: it would need
  a true socketpair, which Node cannot create without native code, and `trans=unix`
  is the _same_ kernel transport module (`net/9p/trans_fd.c` registers
  `tcp`/`unix`/`fd` off one file, same maxsize, same machinery) with the same
  no-exposure property from the private directory rather than an unshared descriptor
  — it stays on the table for a relay mode that already holds one. `msize` defaults
  to the kernel's own `DEFAULT_MSIZE` (128 KiB of payload + `P9_IOHDRSZ`), clamped to
  `MAX_SOCK_BUF` (1 MiB) — the same ceiling `P9Session` defaults to, so the two agree
  by construction. `cache=none` is the default because 9P has no invalidation channel
  at all (no `notify_inval_inode` analogue), so any cache mode above it is a bet that
  nothing else changes the driver. One connection per mount, and its EOF is the
  unmount signal. Teardown follows the FUSE/NFS discipline: deadline, `umount -f`
  escalation (real here — v9fs implements `.umount_begin`/`v9fs_umount_begin()`),
  every spawned child bounded and abandoned past the deadline, idempotent and
  retryable throughout. Spawning a binary that lives on the mount from the process
  serving it deadlocks (`uv_spawn` blocks the replying thread until the child execs,
  and the child parks in `p9_client_rpc` reading its own ELF header) and does not end
  when the server is killed, because `fork` gave the child a copy of the server
  socket — witnessed, documented at the top of the file.
- `probe.ts` — `p9ClientProbe()`: Linux only, root always required (`mount(2)` needs
  `CAP_SYS_ADMIN`, and v9fs has no setuid helper the way FUSE has `fusermount3`),
  usable only when `9p` is actually listed in `/proc/filesystems` — a module tree
  changes nothing about `usable`, only which reason sentence is printed when `9p` is
  missing. Reports `9pnet_fd` presence (the module registering
  `trans=unix`/`tcp`/`fd`) without refusing on it — an absent `/sys/module/9pnet_fd`
  is ambiguous (a built-in client looks the same as a never-loadable one), and
  `mount(8)`'s own `modprobe` may resolve it as root; `p9ModuleRefusal` in
  `src/auto.ts` is where that doubt gets resolved _against_ 9P for the no-fallback
  `auto` picker specifically. Import-light like `src/nfs/probe.ts` — reads `node:fs`
  and nothing else.
- `index.ts` — re-exports every file above by name, except `mount.ts`'s
  `parseMountTable`/`MountEntry` (Linux's mount-table format, not something a
  consumer composes with — same treatment as the NFS transport's).

## NFS (`src/nfs/`, exported as `mountx/nfs`)

- `xdr.ts` — XDR (RFC 4506): `XdrReader`/`XdrWriter`, bounds-checked, big-endian,
  64-bit fields as `bigint`.
- `rpc.ts` — ONC RPC v2 (RFC 5531): the constants (`RPC_*`, `AUTH_*`, `MSG_*`,
  `RM_*`) plus call/reply, `AUTH_NONE`/`AUTH_SYS` and TCP record marking. The
  constants live here rather than beside a version's because they frame an NFSv3
  call, an NFSv4.1 COMPOUND and a MOUNT call alike; `v3/constants.ts` re-exports
  every one of them, so `mountx/nfs`'s surface is what it always was.
- `handles.ts` — `FileHandleTable` and the readdir cookie scheme, shared by every
  version. An entry is dropped once its last path is detached: it was reachable only
  through `decode()` → `pathOf()`, which always threw `ESTALE`, and ids come off a
  monotonic counter, so the same handle still answers `ESTALE` — from `decode()` one
  step earlier. The root is exempt, because `PUTROOTFH`/`MNT` encode it from a field
  rather than a lookup. `DirectorySnapshots` carries the invalidation rule both
  sessions obey: a mutating op drops the snapshot of every directory whose name set
  it could have changed, and of no other.
- `util.ts` — the pressure valve between `v3/` and `v4/`, which never import from
  each other: version-neutral POSIX logic (`allowedAccess()`, `modeBitsOfFtype()`)
  that answers with a structure rather than a bitmask so each version maps it onto
  its own transcribed constants, plus the session contract the router owns —
  `NfsSessionOptions` (including `nfs4`, the v4-only knobs forwarded to `Nfs4State`
  verbatim except `idmap`, which is the session's own), `Nfs4IdMap`
  (`owner`/`owner_group` ↔ uid/gid, RFC 8881 §5.9; numeric strings are the default
  with nothing configured), and `NfsSharedState` — the one
  `FileHandleTable`/`PathLock`/counters object the router builds once and hands to
  both versioned sessions.
- `v3/constants.ts` + `v3/protocol.ts` — RFC 1813 transcribed; every struct encoded
  and decoded. The MOUNT program is here too: it is v3-only.
- `v3/session.ts` — `Nfs3Session(driver, options)`: `handleCall(bytes)` →
  `Promise<Uint8Array | null>`, answering both MOUNT and NFS programs.
- `v4/constants.ts` — RFC 8881 (NFSv4.1) transcribed, with RFC 5662 (its normative
  XDR companion) for the values RFC 8881 states only in prose: `nfsstat4` whole,
  `nfs_opnum4` 3..58 plus `OP_ILLEGAL`, every `FATTR4_*` bit number 0..76, the
  OPEN/EXCHANGE_ID/CREATE_SESSION/SEQUENCE flag words, and the sizes. Complete tables
  even where this 4.1-only server answers `NFS4ERR_NOTSUPP`, because the codec has to
  _name_ what arrives; no v4.2 values. Carries the status↔errno mapping
  (`nfs4StatusOf`/`errnoCodeOfStatus4`/`errnoOfStatus4`/`status4Name`) the way
  `v3/protocol.ts` carries v3's, over `src/errors.ts`'s table. Not on `mountx/nfs`
  yet.
- `v4/attr.ts` — the `bitmap4`/`fattr4` codec (RFC 8881 §3.3.7, §18.7.3; XDR
  sub-types from RFC 5662): a counted bitmap plus one opaque byte string, values back
  to back in ascending attribute-number order, no per-attribute length. `decodeFattr`
  walks every set bit and pushes the ones with no codec here into `unsupported`,
  ascending, rather than guessing a skip length for them; once the first such bit has
  been seen, a _later_ bit that does have a codec is silently left out of `values`
  too — its byte offset in the opaque string can no longer be trusted — without being
  added to `unsupported` itself, so `v4/session.ts` diffs the full `attrmask` against
  its own supported-attribute set separately to catch that case. `encodeFattr` writes
  `requested ∩ supported ∩ available` and drops the rest silently, which is GETATTR's
  own rule (§18.7.3), not a shortcut. No ACL bits — `nfsace4` has no counterpart in
  the driver interface.
- `v4/protocol.ts` — the COMPOUND framing and every stateless operation, both
  directions, transcribed from RFC 5662 with each codec naming its RFC 8881 section.
  One procedure carries an array of operations against a _current filehandle_ the
  earlier ones in the same array set; most results are a union on `nfsstat4` carrying
  a body only on `NFS4_OK`, three name a second case arm (`SETATTR4res` on every
  status, `LOCK4res`/`LOCKT4res` on `NFS4ERR_DENIED` too), and an opcode with no
  codec row ends the message rather than guessing how many bytes to skip.
  `OP_CODECS` holds the stateless operations and the state ones (EXCHANGE_ID,
  CREATE_SESSION, SEQUENCE, OPEN, READ, WRITE, LOCK, ...) alike; the optional
  operations this server will never implement (DELEGRETURN, OPENATTR, GETDEVICEINFO,
  the LAYOUT family, ...) are absent by design, not by gap.
- `v4/state.ts` — the state machine: client IDs, sessions and their per-slot reply
  caches, stateids, share reservations, byte-range locks, the lease clock. Pure and
  synchronous — every method returns a status rather than throwing, so a COMPOUND can
  consult it between two awaited driver calls with no window for a race — and a
  `fileKey` is a caller-chosen opaque identity, so two names for one file must fold
  to one key for share reservations to coalesce. **The replay cache**: `sequence()`
  reserves a slot, the session runs the COMPOUND and calls `cacheReply()` with the
  encoded bytes, which the table copies on insert (the session may reuse its buffer
  immediately) and hands back **uncopied** on replay (the session must not mutate
  what it gets back) — a slot's cached reply is dropped the moment its sequence
  advances (§2.10.6.1). **Lease policy**: a courteous server, revoking a client's
  state in exactly three places — on conflict (another client's `OPEN`/`LOCK`/`LOCKT`
  finds an expired holder in the way), lazily on that client's own next `SEQUENCE` if
  its lease had already lapsed (which _is_ revocation on expiry, just detected rather
  than swept for), and on demand from `sweep()` for a server timer — rather than
  freeing it the instant the lease lapses with nothing yet asking (§8.4.3's "MAY …
  for a considerable period"). `DESTROY_CLIENTID` is not a fourth: it answers
  `NFS4ERR_CLIENTID_BUSY` against a client with live state rather than revoking it.
  **No grace period**: no stable storage survives a restart, so every reclaim (`OPEN`
  with `CLAIM_PREVIOUS`, a reclaiming `LOCK`) answers `NFS4ERR_NO_GRACE`, and
  `RECLAIM_COMPLETE` still gates ordinary locking exactly as §18.51.3 requires.
- `v4/session.ts` — `Nfs4Session(driver, options, shared)`: COMPOUND dispatch, the
  same `handleCall(bytes)` → `Promise<Uint8Array | null>` shape as `v3/session.ts`,
  over `./state.ts`'s decisions. Owns the mapping from an open state to the one
  `FileHandleLike` behind it (open exactly while the state that named it exists;
  CLOSE is the ordinary end, lease expiry/`DESTROY_CLIENTID`/a swept client the
  others, via `onOpenReleased`) and the COMPOUND cursor's current stateid (an
  operation that returns one sets it, one that only sets the current filehandle
  clears it, SAVEFH/RESTOREFH move both halves, the special "whatever that is now"
  stateid gets substituted here because only the COMPOUND knows the answer). No
  delegations, no pNFS, no backchannel use, no RPCSEC_GSS, minorversion anything but
  1 → `NFS4ERR_MINOR_VERS_MISMATCH`.
- `session.ts` — `NfsSession(driver, options)`, the public entry point and the
  version router. A de-framed record has `prog` at byte 12 and `vers` at 16, so it
  peeks those two words and hands the **same raw bytes** to the versioned session,
  which does its own full RPC decode (the duplicated header decode is what keeps
  `v3/session.ts` free of the router). It answers only what belongs to no version —
  `PROG_UNAVAIL`, and `PROG_MISMATCH` with the range `{low: 3, high: 4}` this server
  speaks — decoding the call first so an undecodable record, a wrong `rpcvers` and a
  refused credential still outrank both. Everything public (`driver`, `handles`,
  `stats`, `mounts`, `writeVerifier`, `destroy()`, plus `.v3`/`.v4` for the tests and
  the CLI) is the versioned session's, reached through here. `v3/` and `v4/` never
  import from each other; `session.ts` and `util.ts` are what either may reach for
  instead.
- `probe.ts` — `nfsClientProbe()` and the `NfsPlatform` narrowing, split out of
  `mount.ts` because `mountx/auto` asks before deciding what to load: it imports
  `node:fs` and nothing else, where `mount.ts` pulls the server and the whole codec
  behind it. Root is required for **Linux only**. `v4` (can this host mount
  NFSv4.1?) is Linux-only too and orthogonal to `usable` — an unprivileged Linux
  process can read `usable: false, v4: true` in one call. `mount.ts` re-exports it.
- `server.ts` — `createNfsServer(driver, options)`, the only file here that opens a
  socket. One `NfsConnection` per accepted socket, the same shape `src/9p/server.ts`
  uses and ported from it: dispatch is un-awaited, the write chain is appended to
  **when a reply is produced** rather than in request order (RPC matches by `xid`,
  and awaiting inside the chain made every reply wait on the slowest call ahead of
  it), and a per-connection window — `DEFAULT_NFS_MAX_IN_FLIGHT = 64` (named apart
  from 9P's `DEFAULT_MAX_IN_FLIGHT = 16` the way `DEFAULT_NFS_PORT` already is, since
  one identifier meaning two numbers on two subpaths is a difference an import cannot
  show), not 16 because this server counter-offers `ca_maxrequests` up to 64 and a
  smaller window would throttle traffic it said it would take — `socket.pause()`s at
  the limit and resumes on `drain`.
- `mount.ts` — `mountNfs()`/`nfsMountOptions()`, and the only platform-aware
  transport in the project: it mounts on **Linux and macOS** — on macOS **without
  root**, since `mount_nfs` is not setuid and a BSD lets an ordinary user mount onto
  a directory they own (`ownershipRefusal()` checks that at mount time, because it is
  a fact about the path rather than the host) — and keeps the difference in pure,
  tested pieces (`nfsMountOptions()`, `parseMountTable()`, `ownershipRefusal()`,
  `isConsentDenial()`/`consentAdvice()`, the probe's helper paths) plus a `-f`-only
  escalation ladder on macOS that the consent gate can refuse outright. macOS is
  NFS-only by necessity — macFUSE is a third-party kext with its own protocol
  dialect, so `src/fuse/` cannot serve it. **Two versions**: `mountNfs({ version:
"4.1" })` mounts the same server's NFSv4.1 side, an assumption away from working on
  macOS too (A1: macOS is treated as NFSv4.0-only until verified otherwise —
  `versionRefusal()`), and drops the two options that were about the protocols v4
  folded in (`mountport=`, `nolock`/`nolocks`) since v4 has no MOUNT program and no
  separate NLM. A `vers=4.1` mount is listed in `/proc/self/mounts` with type `nfs4`,
  which nothing here matches on.
- `index.ts` — re-exports `v3/protocol.ts` by name, minus the sub-struct helpers
  (`readFattr`/`writeFattr`, `readSattr`/`writeSattr`, ...). `v4/protocol.ts` and
  `v4/constants.ts` are not re-exported yet — reachable only through `NfsSession.v4`
  for now.

## S3 (`src/s3/`, exported as `mountx/s3`)

The transport that is not a mount — it serves an `FsDriver` to an S3 client
(`rclone`, the AWS CLI, an SDK, a presigned URL) over HTTP, path-style, one bucket
per driver. Deliberately outside `mountx/auto`, whose contract is a mountpoint this
transport never produces.

- `constants.ts` — the errno → S3 error table (`ERRNO_S3_ERRORS`/`s3ErrorOf`), typed
  as total over every `ErrnoCode` so an unmapped one fails the typecheck rather than
  silently answering `InternalError`; the protocol's numeric limits (`MAX_KEYS`,
  part-size/part-count, the 1024-byte key limit) and the SigV4 payload-hash
  sentinels. There is no RFC for S3 — everything here is transcribed from Amazon's
  own docs and named where it is used.
- `sigv4.ts` — AWS Signature Version 4, signed **and** verified (header and
  presigned-query forms, ±15 min clock skew), pure and clockless — every function
  takes the time as an argument. The one S3-specific rule (single URI-encoding, no
  dot/empty-segment normalization, unlike every other AWS service) lives in
  `canonicalUri()` alone. Goldens are the official `aws-sig-v4-test-suite`.
- `xml.ts` — bounded XML encoder for list/error/multipart responses and parser for
  the two request bodies (`DeleteObjects`, `CompleteMultipartUpload`); no entity
  expansion, depth- and byte-capped.
- `chunked.ts` — the `aws-chunked`/`STREAMING-AWS4-HMAC-SHA256-PAYLOAD` streaming
  decoder, per-chunk signature verification, unsigned-chunked passthrough.
- `protocol.ts` — pure request parsing and routing: path-style URL → `(bucket, key)`,
  the `S3_OPS` op-discrimination table, `Range`/conditional/`x-amz-meta-mtime` header
  parsing, the S3 XML error responses. An operation or sub-resource this gateway does
  not implement is `NotImplemented`, never a fall-through to a neighbour.
- `session.ts` — `S3Session`: one HTTP request in, one reply out, streaming **both
  ways** (unlike `NfsSession.handleCall(bytes)`, because buffering a multi-gigabyte
  body either direction is not a thing a gateway may do). ETags are derived (sha256
  over `dev:ino:size:mtimeMs`, `-1` suffix, never a fake MD5); multipart stages under
  the reserved prefix `.mountx-multipart/<uploadId>/`, invisible to every other op; a
  `PUT` writes in place, so only the _first_ byte is guaranteed atomic.
- `server.ts` — `createS3Server(source, options)`, the only file here that imports
  `node:http`. With no `credentials`, binds loopback-only and refuses any other
  `host` with a named `S3BindError`; with credentials, verifies every request and
  allows any bind. `close()` drains in order: stop accepting, let in-flight replies
  finish, drop the rest, sweep multipart staging last.
- `index.ts` — re-exports the above by name, minus `xml.ts`'s generic XML primitives
  it is built on (the same treatment `mountx/nfs` gives its sub-struct helpers).

## CLI (`src/cli/`, the `mountx` bin, `pnpm mountx` from source)

- `index.ts` — `node:util`'s `parseArgs`, then a memory driver holding one file —
  this package's own `README.md`, read through `new URL("../../README.md",
import.meta.url)`, which is the package root from `src/cli/` and from `dist/cli/`
  alike, and npm publishes a README whatever the `files` list says — wrapped in
  `watch.ts` and mounted through `mountx/auto` at `~/mountx` (`[mountpoint]`/`-m`/
  `$MOUNTX_MOUNTPOINT`; `-t`, `-q`, `-r`, `--empty`, `--allow-other`). It is a demo
  and a test bench, not a mount tool — what it serves is always a tree that dies with
  the process. `process.exit` appears only in paths that run _before_ the mount (with
  one up it wedges), and the stale-mount cleanup detaches only a `fuse*`/`nfs*`/`9p`
  mount at that exact path (matched whole for `9p`, so a future `9p2` stays
  untouched), printing the `sudo` line rather than spawning one when the route needs
  root. It runs on **both hosts**: Linux reads `/proc/self/mounts` inline, macOS asks
  `mountEntryAt()` from `src/nfs/mount.ts` (dynamically imported, so a Linux run
  never loads the NFS codec) and clears with an unprivileged `umount -f`, which works
  because a BSD lets the mounting user unmount. Linux+NFS and Linux+9P both have no
  unprivileged route and get the `sudo` line — no worse than it sounds, since both
  needed root to be mounted in the first place. Bounded by `STALE_TIMEOUT`, because
  the macOS consent gate turns `umount` into a call that never returns — on expiry it
  prints `consentAdvice()` and lets `mount()` refuse.
- `watch.ts` — the `FsDriver` `Proxy` that narrates every request, open file handles
  included. `color.ts` — ANSI, off under `NO_COLOR`.

## Native (`native/`)

The only non-JS in the repository. It exists for one reason: unprivileged FUSE
mounting needs `fusermount3` to hand `/dev/fuse` back over `SCM_RIGHTS`, and Node
cannot `recvmsg` a descriptor.

- `src/main.zig` — a Node-API addon with three functions and nothing else:
  `socketpair`, `recvFd` (`poll(2)` + `recvmsg(2)` with `MSG_CMSG_CLOEXEC`) and
  `sendFd`, which the library never calls and the tests do. No fork, no exec, no
  strings, no allocation, no libc.
- `src/napi.zig` — the ~10 Node-API entry points used, `extern`-declared, transcribed
  from Node v24's `js_native_api.h`.
- `build.zig` — cross-compiles `prebuilt/mountx-linux-{x64,arm64}.node` from any
  host, `ReleaseSmall`, ~7 KB each. `prebuilt/` is a build output: gitignored,
  unpublished, and needed only by whoever is changing the addon.
- `build.ts` — `pnpm build:native`, the whole of it: `zig build`, then regenerate
  `prebuilt.mjs` from what it wrote. No flags and no half-runs — the binaries and the
  embed are one artifact in two forms, and anything that rebuilt one alone would
  exist only to leave them disagreeing. Output is deterministic — sorted targets, no
  timestamps, every brotli parameter named rather than defaulted — because it is the
  committed artifact and "did the addon change?" has to be a readable diff.
  Compression is the one thing outside that: a Node release with a different
  libbrotli re-encodes bytes it did not change, which is why the sha256 written above
  each payload is of the _decompressed_ file and still answers the question.
- `prebuilt.mjs` — **generated, do not edit.** The addon brotli'd and base64'd (~13 KB
  for both platforms, against ~20 KB uncompressed), plus `loadEmbedded()`, which
  writes the bytes to a `mkdtemp` directory, `dlopen`s them, and deletes both before
  returning. This is the only committed and published form of the addon: a bundler
  carries text in the module graph, not a sibling binary, and an npm install carries
  it just as well. No user needs a toolchain. It is written as generated code: no
  prose, no JSDoc, and no `import` statements — builtins are reached with
  `process.getBuiltinModule` at the call sites, because this module sits on the
  _static_ import path of `mountx/fuse` and nothing in it runs unless a process
  mounts unprivileged (statically importing `node:os`+`node:zlib` cost ~1 ms of
  import time for consumers that never touch the addon; the 13 KB of base64 costs
  ~0.05 ms and is not worth deferring). Every explanation that used to live in the
  file is in `build.ts` — a generated file carrying its own rationale is one somebody
  edits in place.
- `index.mjs` + `index.d.mts` — `dlopen`s the embedded addon once per process,
  memoizing the failure as well as the success, and exports that one function:
  `loadNative()` is all `src/` asks for, and the tests read the embed from
  `prebuilt.mjs` directly. Hand-written JS, shipped verbatim, imported as
  `#unfs/native`. Verified end to end by `npm pack` → install → mount from
  `node_modules`, and by bundling `#unfs/native` and running the bundle from a
  directory with no package near it.

## Benchmarks (`bench/`)

`harness.ts` (warmup, adaptive loop, percentiles), `scenarios.ts` (written once
against the driver interface), `index.ts` (loopback + NFS columns),
`fuse.ts`+`fuse-client.ts` (the FUSE column, client in a child process); generates
`.agents/benchmarks.md`. There is no 9P or S3 column yet.

## Docs site (`docs/`)

The [undocs](https://undocs.dev) site at <https://mountx.vercel.app>. **This is where
user-facing prose goes** — anything longer than a paragraph belongs on a page here,
not in `README.md`, which is the intro, its snippet, install and a link list (the CLI
mounts the README, so it stays short on purpose).

A **standalone pnpm project**, deliberately outside the root workspace (its own
`package.json`, lockfile and `pnpm-workspace.yaml`), so the site's dependency tree
never reaches the package's: `pnpm install && pnpm dev` **from inside `docs/`**.

Three sections, numbered-prefix routing (`1.guide/` → `/guide`):

- `1.guide/` — introduction, quick start, the CLI, `3.drivers/` (the interface, then
  the built-in three and writing your own), mounting, VMs, tuning, troubleshooting.
- `2.transports/` — the overview of what `auto` is choosing between, then
  `mountx/auto`, FUSE, 9P, NFS (one page carrying both v3 and v4.1, since they are
  one server behind one `mountNfs()`) and the S3 gateway; guide-level prose first and
  the full export surface below it, because a transport's API and the protocol it
  speaks are one subject and two pages of it drift.
- `3.reference/` — what is left once each entry point is documented beside what it
  does: the root `mountx` export split by subject (the driver interface,
  capabilities, errors, the loopback harness, paths and locking) plus the index that
  maps every subpath to its page.

`.config/docs.yaml` is the landing page and the site config; `.docs/public/` holds
the icons.
