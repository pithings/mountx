Keep important information about project in AGENTS.md. For more detailed info, progressively document them in .agents/*.md and reference from this file.

# mountx

Mount a JavaScript filesystem: one driver interface (a subset of `node:fs/promises`), multiple transports (FUSE first, then NFSv3). user-facing docs: `README.md`.

Conventions: pure JS/TS, zero runtime deps, pure-JS-first (no native code in v1). Single package with subpath exports. Small conventional commits to `main`, tests green (`pnpm test`) before each commit.

## Code map

Core (`src/`):

- `types.ts` — `FsDriver` (a subset of `node:fs/promises`; `node:fs/promises` itself is assignable to it), `FsCapabilities`, the typed-only `mountx.*` extension namespace, `StatsLike`/`DirentLike`/`FileHandleLike`.
- `errors.ts` — `ERRNO_CODES` (Linux values), `fsError()` producing errors byte-identical to `node:fs`'s, `errnoOf()` for transports.
- `path.ts` — absolute POSIX path helpers; `..` clamps at the root.
- `harness.ts` — `createLoopback(driver)`: normalizes paths, fills missing methods with `ENOSYS`, resolves capabilities. What driver authors test against.
- `lock.ts` — `PathLock`, the writer lock over the path map, shared by the FUSE and NFS sessions (`RENAME` takes it; `READ`/`WRITE` run outside it).
- `drivers/memory.ts`, `drivers/node-fs.ts` — the two v1 drivers; the passthrough resolves every path component itself so nothing escapes its root.

FUSE (`src/fuse/`, exported as `mountx/fuse`):

- `constants.ts` — opcodes and `FUSE_*`/`FOPEN_*`/`FATTR_*`/`DT_*`, transcribed from the kernel's `include/uapi/linux/fuse.h` (tag v6.12, protocol 7.41).
- `protocol.ts` — every struct encoded **and** decoded, opcode dispatch table (`OPCODES`), message framing, errno-on-the-wire helpers, dirent packing (`DirentPacker`).
- `init.ts` — `negotiateInit(kernelInit, preferences)`, pure.
- `session.ts` — `FuseSession(driver, options)`: `INIT` handshake, opcode switch, file-handle table, readdir paging, `SETATTR` bitmask → driver calls, notify encoders.
- `inodes.ts` — `InodeTable`: nodeid ↔ path ↔ `(dev, ino)`, lookup refcounting, subtree remap on rename, orphans. Entirely synchronous.
- `notify.ts` — `notify_inval_inode`/`notify_inval_entry` codecs.
- `mount.ts` — the only file that opens a device or spawns a process: `mount(driver, mountpoint, options)` → `Mount`, plus `unmountAll()`/`liveMounts()`.
- `record.ts` — tees `/dev/fuse` traffic (`mount({ tap })`) into a transcript; `replayTranscript()` feeds one back through a fresh session.

NFS (`src/nfs/`, exported as `mountx/nfs`):

- `xdr.ts` — XDR (RFC 4506): `XdrReader`/`XdrWriter`, bounds-checked, big-endian, 64-bit fields as `bigint`.
- `rpc.ts` — ONC RPC v2 (RFC 5531): call/reply, `AUTH_NONE`/`AUTH_SYS`, TCP record marking.
- `constants.ts` + `protocol.ts` — RFC 1813 transcribed; every struct encoded **and** decoded.
- `handles.ts` — `FileHandleTable` and the readdir cookie scheme.
- `session.ts` — `NfsSession(driver, options)`: `handleCall(bytes)` → `Promise<Uint8Array | null>`, answering both MOUNT and NFS programs.
- `server.ts` — `createNfsServer(driver, options)`, the only file here that opens a socket. `mount.ts` — `mountNfs()`/`nfsClientProbe()`, and the only platform-aware file in the project: it mounts on **Linux and macOS**, and keeps the difference in three pure, tested pieces (`nfsMountOptions()`, `parseMountTable()`, the probe's helper paths) plus a `-f`-only escalation ladder on macOS. macOS is NFS-only by necessity — macFUSE is a third-party kext with its own protocol dialect, so `src/fuse/` cannot serve it.
- `index.ts` — re-exports `protocol.ts` by name, minus the sub-struct helpers (`readFattr`/`writeFattr`, `readSattr`/`writeSattr`, ...).

Tests (`test/`):

- `conformance.ts` — the one Tier-0 suite, written against the driver interface; `drivers.test.ts` runs it against memory, node-fs and raw `node:fs/promises` (loopback column).
- `rooted-node-fs.ts` — `node:fs/promises` rooted at a directory; the oracle shared by `drivers.test.ts` and the FUSE conformance column.
- `fuse/` — protocol/session Tier 0 (`random.ts`, `protocol.test.ts`, `golden.test.ts`, `dirent.test.ts`, `init.test.ts`, `session.test.ts`, `inodes.test.ts`, `session-fuzz.test.ts`, `synthetic-kernel.ts`, `fuzz.test.ts`), Tier 2 `mount.test.ts`, the differential oracle (`differential.ts`+`differential.test.ts`), record/replay (`record-fixtures.ts`+`replay.test.ts`), the FUSE conformance column (`conformance-mount.test.ts`).
- `nfs/` — Tier 0 (`xdr.test.ts`, `protocol.test.ts`, `handles.test.ts`, `golden.test.ts`, `fuzz.test.ts`, `mount-options.test.ts` — the platform difference, checked from either host), the Tier-1 JS client (`client.ts`) and its conformance column (`conformance.test.ts`, `session.test.ts`), Tier 2 `mount.test.ts` (gated on `nfsClientProbe()`, runs on Linux and macOS).
- `pjdfstest/` — `run.sh`+`run.ts` drive the pinned pjdfstest clone (gitignored) against a real mount and write the committed analysis.
- `matrix.ts` — generates `.agents/conformance-matrix.md`. `root.sh` — runs any Tier-2 vitest file under sudo with the environment fixed up (raised `UV_THREADPOOL_SIZE`, redirected `TMPDIR`, forwarded `MOUNTX_*`); every Tier-2 file skips itself when not root.

`bench/` — `harness.ts` (warmup, adaptive loop, percentiles), `scenarios.ts` (written once against the driver interface), `index.ts` (loopback + NFS columns), `fuse.ts`+`fuse-client.ts` (the FUSE column, client in a child process); generates `.agents/benchmarks.md`.

## Invariants (do not break)

- **Zero runtime deps.**
- **`FsDriver` is a subset of `node:fs/promises`**, proven by the assignability acid test: `const driver: FsDriver = await import("node:fs/promises")` must compile with no cast.
- **Capabilities are declared-or-inferred, never faked.** An unmet capability answers `ENOSYS`/`ENOTSUP`; it is never silently pretended.
- **Errno discipline: exactly one reply per request.** `handleMessage`/`handleCall` never reject; every request needing a reply gets exactly one, a thrown value becomes a negative errno (unknown → `EIO`), and a dev-mode assertion tracks it per request id.
- **The zero-copy contract.** A session decodes and copies everything it keeps before its first `await`; the transport dispatches each read without awaiting it and re-arms the buffer as soon as that call returns. Breaking either half corrupts data under concurrent I/O.
- **Decoders always copy the bytes they retain.** `Buffer.prototype.slice` is `subarray`, not a copy — this exact mistake corrupted the first FUSE transcripts and an NFS `WRITE` payload before both were fixed.
- **Wire constants are transcribed, never guessed or borrowed from host `node:fs`.** FUSE constants come from the kernel's `include/uapi/linux/fuse.h`; NFS constants come from RFC 1813/5531/4506.
- **A `-t fuse` mount never receives `FUSE_DESTROY`.** The transport must detect unmount itself (read EOF/`ENODEV` on `/dev/fuse`) and call `session.destroy()`; it is idempotent and safe with requests in flight.
- **No mount stacking.** Mounting over a live mountpoint — this process's own, or any FUSE mount already in `/proc/self/mounts` — is refused, in both directions.
- **An unreadable mount table means "still mounted", never "gone".** NFS teardown treats "is it mounted" as a tri-state (`src/nfs/mount.ts`'s `isMounted`): forcing down a mount that turns out to be gone is harmless, whereas reporting a successful unmount on a guess shuts the server down under a live mount. This is why the table read is async — macOS has no `/proc/self/mounts` and the table comes from spawning `mount(8)`.
- **Teardown has a deadline** (`unmountTimeout`, default 10 s) and escalates to `umount -f` on expiry. Closing the `/dev/fuse` fd only aborts the connection when no read is parked on it.
- **Self-client threadpool hazard.** Serving a mount and using it (any sync `fs` call, or enough concurrent async ones) from the same process parks threadpool threads the read loop also needs, and wedges. Documented at the top of `src/fuse/mount.ts`.
- **`process.exit()` does not work with a mount up.** Node's exit path joins the threadpool the reads are parked in. `await unmount()` and set `process.exitCode`; this is also why the signal handlers re-raise the signal instead of exiting directly.
- **Source stays NUL-free and grep-able.** E.g. the NFS cookie verifier delimiter is the two-character string `"\0"`, never a literal NUL byte.
- **Golden fixtures must give every field a distinct value.** A fixture built from repeated/mirrored values (`uid: 0, gid: 0, size == used`) passes even with transposed encoder/decoder fields; only an all-distinct fixture catches a symmetric encode/decode bug.
- **README perf claims may come only from `.agents/benchmarks.md`**, and must carry that file's host line with them.

## Commands

- `pnpm test` — lint + typecheck + the Tier-0/Tier-1 vitest suites; no root needed, runs everywhere.
- `pnpm test:root` — the four Tier-2 real-mount suites under sudo (`sh test/root.sh test/fuse/mount.test.ts test/fuse/differential.test.ts test/fuse/conformance-mount.test.ts test/nfs/mount.test.ts`).
- `pnpm test:mount` — just the FUSE mount smoke test under sudo.
- `pnpm test:nfs:mount` — the NFS mount test under sudo; skips itself via `nfsClientProbe()` when the host has no NFS client.
- `pnpm matrix` — regenerates `.agents/conformance-matrix.md`.
- `pnpm bench` — the loopback + NFS benchmark columns, no root.
- `pnpm bench:root` — the FUSE benchmark column, under sudo.
- `pnpm fmt` — `automd && oxlint . --fix && oxfmt .`.
- `pnpm lint` — `oxlint . && oxfmt --check .`.
- `pnpm build` — `obuild`.

Tier-2 (`*:root`/`*:mount`) commands need sudo; root's `PATH` lacks `node` (fnm), so they invoke `sudo "$(command -v node)" ...` rather than plain `sudo node ...` — see `test/root.sh`.

## More detail: `.agents/*.md`

- `.agents/roadmap.md` — the finalized v1 decisions that still bind, and every deferred/open item for future work.
- `.agents/environment.md` — verified FUSE/sudo/toolchain facts and wedge recovery procedures for the dev host.
- `.agents/pjdfstest-results.md` — pjdfstest pass/fail breakdown and the bugs it found.
- `.agents/conformance-matrix.md` — generated per-transport conformance table (`pnpm matrix`).
- `.agents/benchmarks.md` — generated performance numbers and their interpretation (`pnpm bench`).
