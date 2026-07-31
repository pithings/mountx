# Architecture

A map, not a manual. **The source carries its own reasoning** — a module header plus
per-symbol JSDoc, a sixth to a third of every file, and up to 100 header lines on the
transports' hard files. Why the qid counter exists, why `close()` resets rather than
flushes, which RFC section a rule comes from: it is all in the file. Read it. What is
here is the shape of the tree, one line per file so you know which one to open, and
the cross-cutting facts that live in no single file.

`AGENTS.md` has the invariants; `.agents/invariants.md` has them in full.

## The transport shape

Every transport directory is the same six roles:

| File           | Role                                                              |
| -------------- | ----------------------------------------------------------------- |
| `constants.ts` | transcribed from the kernel header or RFC named in the file       |
| `protocol.ts`  | every message encoded **and** decoded — both directions, always   |
| `session.ts`   | protocol ↔ `FsDriver`; `handleCall`/`handleMessage` never rejects |
| `server.ts`    | the only file that opens a socket (FUSE has none — it owns an fd) |
| `mount.ts`     | spawns `mount(8)`, owns teardown and the `live` set               |
| `probe.ts`     | can this host use this transport, and if not, why (import-light)  |
| `index.ts`     | re-exports by name                                                |

Deviations are noted per area below.

## Core (`src/`)

| File           | What                                                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `types.ts`     | `FsDriver`, `FsCapabilities`, `StatsLike`/`DirentLike`/`FileHandleLike`, and the `mountx.*` namespace — **two live members**, `mknod` and `utimens`, no xattr |
| `errors.ts`    | `ERRNO_CODES` (Linux), `fsError()` (byte-identical to `node:fs`'s), `errnoOf()` — the one errno table in the repo                                             |
| `path.ts`      | absolute POSIX helpers, `..` clamps at root; canonical paths early-return, `resolvePath()` returns `{ path, segments }`                                       |
| `harness.ts`   | `createLoopback(driver)` — normalize, fill gaps with `ENOSYS`, resolve capabilities. The method table is fixed **at construction**                            |
| `lock.ts`      | `PathLock` — `RENAME` takes it, `READ`/`WRITE` run outside it                                                                                                 |
| `subtree.ts`   | `remapSubtree()` — the rename rewrite; internal, deliberately not in the public `path.ts`                                                                     |
| `ownership.ts` | who a new entry belongs to: `inode_init_owner()`'s set-gid rule, plus the `lchown`/`chmod` that applies it. Internal; used by the two NFS sessions' `#claim`  |
| `auto.ts`      | `mountx/auto` — probe, then FUSE → 9P → NFS, each behind `await import()`                                                                                     |

### Drivers (`src/drivers/`)

| File           | What                                                                                                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `memory.ts`    | the reference driver, and the **only `mountx.mknod` implementation** in the repo — which is what makes FIFOs/sockets/devices reachable through all four sessions. Holds no bytes for one, so `open` → `ENXIO` |
| `node-fs.ts`   | `node:fs` passthrough; resolves every path component itself so nothing escapes its root. The differential-test oracle                                                                                         |
| `unstorage.ts` | `mountx/drivers/unstorage` — `/a/b` is the key `a:b`, directories are prefixes, random access buffered per path. `unstorage` is a **types-only optional peer**                                                |
| `handle.ts`    | the `FileHandleLike` parts identical in every driver holding its own bytes (flag parsing, range validation, geometric resize). Pure                                                                           |

## FUSE (`src/fuse/`, exported as `mountx/fuse`)

Constants from the kernel's `include/uapi/linux/fuse.h` (tag v6.12, protocol 7.41).
Linux only. No `server.ts` — it owns `/dev/fuse` directly.

| File            | What                                                                                                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `session.ts`    | `INIT` handshake, opcode switch, handle table, readdir paging, `SETATTR` bitmask → driver calls                                                                                 |
| `inodes.ts`     | `InodeTable` — nodeid ↔ path ↔ `(dev, ino)`, lookup refcounting, orphans. Synchronous                                                                                           |
| `init.ts`       | `negotiateInit()`, pure                                                                                                                                                         |
| `flags.ts`      | **the one crossing between the kernel's `O_*` and the host's** — `driverOpenFlags()`, `reopenFlags()`. Pure                                                                     |
| `notify.ts`     | `notify_inval_inode`/`notify_inval_entry` codecs                                                                                                                                |
| `mount.ts`      | root opens `/dev/fuse` and spawns `mount(8)`; everyone else goes through `fusermount.ts`. Past the descriptor, one code path                                                    |
| `fusermount.ts` | the unprivileged route — the `_FUSE_COMMFD` handshake (from libfuse 3.18.2), `rootlessProbe()`, and the refusal advice. **Read its header before debugging a permission error** |
| `native.ts`     | reshapes the addon's raw errno into a `node:fs` shape. Never imported on the root path                                                                                          |
| `exec.ts`       | shared spawn helpers and `Deadline` — see Cross-cutting                                                                                                                         |
| `record.ts`     | tees `/dev/fuse` traffic into a transcript; `replayTranscript()` feeds one back                                                                                                 |

## 9P (`src/9p/`, exported as `mountx/9p`)

9P2000.L only. Constants from the kernel's `include/net/9p/9p.h` (tag v6.12), diod's
`protocol.md` as the prose reference. Linux, root only — v9fs has no setuid helper.

| File         | What                                                                                                                                                                                             |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `wire.ts`    | `P9Reader`/`P9Writer` — little-endian, unaligned, bounds-checked, u64 as `bigint`                                                                                                                |
| `fids.ts`    | `FidTable` — fid → path + open state + iounit + readdir cursor. `qid.path` comes off this table's own counter, because v9fs derives `st_ino` from it. Synchronous                                |
| `locks.ts`   | `P9LockTable` — POSIX byte ranges for `Tlock`/`Tgetlock`, owned by `(client_id, proc_id)` and keyed by path. **Per server, not per session**; a conflict is `BLOCKED`, never a wait. Synchronous |
| `session.ts` | version negotiation, attach, walk, the whole `.L` opcode set, `Tflush`. Anything else → `Rlerror ENOTSUP`; errnos go on the wire raw, with no mapping layer                                      |
| `server.ts`  | TCP, unix socket, or `attach(duplex)` — one session and one assembler **per connection**, since fids are per-connection state; one lock table shared across all of them                          |
| `mount.ts`   | `trans=unix` by default (a `0700` dir holding a `0600` socket), `trans=tcp` for VM guests, `trans=fd` deferred. **Read its header before spawning anything near a mount**                        |
| `probe.ts`   | needs `9p` in `/proc/filesystems`; reports `9pnet_fd` without refusing on it                                                                                                                     |

## NFS (`src/nfs/`, exported as `mountx/nfs`)

Two versions behind one router and one server. Linux and macOS — and on macOS
**without root**, since `mount_nfs` is not setuid.

| File                                | What                                                                                                                                                                                                                           |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `xdr.ts`                            | XDR (RFC 4506) — bounds-checked, big-endian, 64-bit as `bigint`                                                                                                                                                                |
| `rpc.ts`                            | ONC RPC v2 (RFC 5531) + TCP record marking + `AUTH_NONE`/`AUTH_SYS`. Version-neutral, so it lives here rather than in `v3/`                                                                                                    |
| `handles.ts`                        | `FileHandleTable` (ids off a monotonic counter, so a dropped entry still answers `ESTALE`; `maxHandles` evicts LRU past a cap, root and `pin`ned entries exempt — so the cap is soft) and `DirectorySnapshots`                 |
| `util.ts`                           | the seam between `v3/` and `v4/` — version-neutral POSIX logic, `NfsSessionOptions`, `Nfs4IdMap`, `ExclusiveCreates` (the create verifiers a retransmission is recognised by), and the `NfsSharedState` the router builds once |
| `session.ts`                        | `NfsSession` — peeks `prog`/`vers` and hands the **same raw bytes** on. Everything public is the versioned session's, reached through here                                                                                     |
| `server.ts`                         | one connection per socket, window of 64 (it counter-offers `ca_maxrequests` up to 64)                                                                                                                                          |
| `mount.ts`                          | the only platform-aware transport: Linux and macOS, `version: "3"` or `"4.1"`, plus the macOS consent gate                                                                                                                     |
| `probe.ts`                          | root for Linux only; `v4` is reported orthogonally to `usable`                                                                                                                                                                 |
| `v3/constants.ts`, `v3/protocol.ts` | RFC 1813, plus the MOUNT program — v3-only                                                                                                                                                                                     |
| `v3/session.ts`                     | answers both MOUNT and NFS programs                                                                                                                                                                                            |
| `v4/constants.ts`                   | RFC 8881 with RFC 5662 for the XDR it states only in prose. Complete tables even where the server answers `NFS4ERR_NOTSUPP`; no v4.2                                                                                           |
| `v4/attr.ts`                        | the `bitmap4`/`fattr4` codec — an unsupported bit poisons every later offset, which is why `v4/session.ts` diffs the mask separately                                                                                           |
| `v4/protocol.ts`                    | COMPOUND framing and every operation. Optional ops this server will never implement are absent by design                                                                                                                       |
| `v4/state.ts`                       | client ids, sessions, slot replay caches, stateids, share reservations, locks, the lease clock. Pure and synchronous — **no grace period**, courteous revocation                                                               |
| `v4/session.ts`                     | COMPOUND dispatch over `state.ts`'s decisions; owns open-state → `FileHandleLike` and the current-stateid cursor                                                                                                               |

Not on `mountx/nfs` yet: `v4/protocol.ts` and `v4/constants.ts`, reachable only
through `NfsSession.v4`.

## S3 (`src/s3/`, exported as `mountx/s3`)

The transport that is not a mount — it serves a driver to an S3 client (`rclone`, the
AWS CLI, an SDK, a presigned URL) over HTTP, path-style, one bucket per driver. There
is no RFC; everything is transcribed from Amazon's docs and named where it is used.

| File           | What                                                                                                                                                             |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sigv4.ts`     | SigV4 signed **and** verified, header and presigned forms. Pure and clockless — the time is always an argument. Goldens are the official `aws-sig-v4-test-suite` |
| `chunked.ts`   | `aws-chunked` streaming decode with per-chunk signature verification                                                                                             |
| `xml.ts`       | bounded encoder + the two request-body parsers; no entity expansion                                                                                              |
| `constants.ts` | the errno → S3 error table, typed **total** over `ErrnoCode`, plus the protocol's numeric limits                                                                 |
| `protocol.ts`  | URL → `(bucket, key)`, op discrimination, header parsing. An unimplemented op is `NotImplemented`, never a fall-through                                          |
| `session.ts`   | one request in, one reply out, streaming **both ways**. Derived ETags, multipart staged under a reserved prefix                                                  |
| `server.ts`    | loopback-only without credentials; ordered drain on `close()`                                                                                                    |

## CLI (`src/cli/`, the `mountx` bin, `pnpm mountx` from source)

A demo and a test bench, not a mount tool: it mounts this package's own `README.md`
from a memory driver through `mountx/auto`, and what it serves always dies with the
process. `index.ts` is arg parsing, stale-mount cleanup and signal handling;
`watch.ts` is the `FsDriver` `Proxy` that narrates every request; `color.ts` is ANSI,
off under `NO_COLOR`.

## Native (`native/`)

The only non-JS in the repository, and it exists for one reason: unprivileged FUSE
mounting needs `fusermount3` to hand `/dev/fuse` back over `SCM_RIGHTS`, and Node
cannot `recvmsg` a descriptor.

| File           | What                                                                                                                       |
| -------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `src/main.zig` | three functions — `socketpair`, `recvFd`, `sendFd`. No fork, no exec, no allocation, no libc                               |
| `src/napi.zig` | the ~10 Node-API entry points used, `extern`-declared from Node v24's `js_native_api.h`                                    |
| `build.zig`    | cross-compiles `prebuilt/mountx-linux-{x64,arm64}.node`, `ReleaseSmall`, ~7 KB each. `prebuilt/` is gitignored             |
| `build.ts`     | `pnpm build:native` — `zig build` **and** the re-embed, deterministically. One artifact in two forms; never run half of it |
| `prebuilt.mjs` | **generated, do not edit** — the addon brotli'd and base64'd, ~13 KB, plus `loadEmbedded()`. The only published copy       |
| `index.mjs`    | `loadNative()`, memoized per process. All `src/` asks for. Imported as `#unfs/native`                                      |

## Tests, benchmarks, docs

`test/` — see `.agents/testing.md`. `bench/` — `harness.ts`, `scenarios.ts` (written
once against the driver interface), `index.ts` (loopback + NFS), `fuse.ts` and `9p.ts`
(the two sudo-gated real-mount columns, each its own command), and the client half
they share, `drive.ts` + `mount-client.ts`; generates `.agents/benchmarks.md`, and has
no NFSv4.1 or S3 column yet.

`docs/` — the [undocs](https://undocs.dev) site at <https://mountx.vercel.app>, and
**where user-facing prose goes**: anything longer than a paragraph belongs on a page
there, not in `README.md` (which the CLI mounts, so it stays short). It is a
**standalone pnpm project** outside the root workspace — `pnpm install && pnpm dev`
from inside it. Numbered-prefix routing, three sections: `1.guide/`, `2.transports/`
(one page per transport, prose above the export surface, NFS carrying both versions
since they are one server), `3.reference/`.

## Cross-cutting

The facts no single file's header can own.

- **`src/9p/session.ts` imports `src/fuse/flags.ts`.** A deliberate dependency from
  one transport onto another: the kernel↔host `O_*` translation is a fact about
  Linux, not about either protocol, and `Tlopen.flags` is the same namespace as
  `fuse_open_in.flags`. One copy, in `flags.ts`.
- **`src/fuse/exec.ts` is not FUSE-specific.** All five files that spawn share it
  (`fuse/mount.ts`, `fuse/fusermount.ts`, `9p/mount.ts`, `nfs/mount.ts`,
  `cli/index.ts`). `Deadline` is the shape the teardown invariant needs: one budget
  per _phase_, each step given `remaining()`, so a phase costs one `unmountTimeout`
  however many spawns it takes. The arithmetic is written out at `src/nfs/mount.ts`'s
  `#unmount`.
- **`src/subtree.ts` is shared by four tables** (`fuse/inodes.ts`, `nfs/handles.ts`,
  `9p/fids.ts`, `9p/locks.ts`) and drives each one's own detach/attach pair. What is
  shared is the walk and the two-pass rewrite; what "this path went away" _means_
  differs per transport (FUSE keeps the orphan for a later `FORGET`, NFS drops the
  key, 9P releases the qid identity — and, in the lock table, the ranges granted under
  a name that has been replaced). Cost is O(tracked paths) per rename; a trie is the
  real fix and waits on a benchmark that wants it.
- **`src/ownership.ts` is one rule for four sessions, and two of them use it.** The
  NFS sessions apply it from the parent `stat` they already took for `wcc_data` /
  `change_info4`; 9P's client computes the same rule and puts the answer on the wire
  (`v9fs_get_fsgid_for_create()`), so the session would be disagreeing with the
  kernel if it applied it again; FUSE's would need an `lstat` per create that nothing
  there does today, and `FUSE_CREATE_SUPP_GROUP` for the membership half. Each of the
  three states its own reason at its `#claim`.
- **`v3/` and `v4/` never import from each other.** `nfs/session.ts` and
  `nfs/util.ts` are the only seam, and the router hands both versions one shared
  `FileHandleTable`/`PathLock`.
- **`auto.ts` is the only file that ranks transports.** FUSE → 9P → NFS, every one
  behind `await import()` so choosing one never loads another's codec; no fallback
  after a failure, and no probe when a transport is named. `p9ModuleRefusal` lives
  there rather than in `9p/probe.ts` because it is a judgement call the no-fallback
  rule forces, not a fact about the host.
- **`mountx/s3` is outside `auto` on purpose** — `auto`'s contract is a mountpoint,
  and the gateway never produces one.
- **Platforms.** FUSE is Linux; 9P is Linux and root-only; NFS is Linux (root) and
  macOS (no root, behind a consent gate); S3 is anywhere. macOS gets NFS by necessity
  — macFUSE is a third-party kext with its own dialect, so `src/fuse/` cannot serve
  it.
- **`memory.ts` is the only driver with `mountx.mknod`**, which is what keeps the
  special-file paths in all four sessions exercised rather than dead.
