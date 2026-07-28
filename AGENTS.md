Keep important information about project in AGENTS.md. For more detailed info, progressively document them in .agents/*.md and reference from this file.

# mountx

Mount a JavaScript filesystem: one driver interface (a subset of `node:fs/promises`), multiple transports (FUSE first, then NFSv3). User-facing docs live in `docs/` (<https://mountx.vercel.app>); `README.md` is the landing page for npm and GitHub and links there.

Conventions: pure JS/TS, zero runtime deps, pure-JS-first. Single package with subpath exports. Small conventional commits to `main`, tests green (`pnpm test`) before each commit.

There is exactly one piece of native code, and it exists for one reason: unprivileged FUSE mounting needs `fusermount3` to hand `/dev/fuse` back over `SCM_RIGHTS`, and Node cannot `recvmsg` a descriptor. See `native/` and the invariants below.

## Code map

Core (`src/`):

- `types.ts` — `FsDriver` (a subset of `node:fs/promises`; `node:fs/promises` itself is assignable to it), `FsCapabilities`, the typed-only `mountx.*` extension namespace, `StatsLike`/`DirentLike`/`FileHandleLike`.
- `errors.ts` — `ERRNO_CODES` (Linux values), `fsError()` producing errors byte-identical to `node:fs`'s, `errnoOf()` for transports.
- `path.ts` — absolute POSIX path helpers; `..` clamps at the root.
- `harness.ts` — `createLoopback(driver)`: normalizes paths, fills missing methods with `ENOSYS`, resolves capabilities. What driver authors test against.
- `lock.ts` — `PathLock`, the writer lock over the path map, shared by the FUSE and NFS sessions (`RENAME` takes it; `READ`/`WRITE` run outside it).
- `auto.ts` — exported as `mountx/auto`: `probeTransports()` and a `mount()` that picks FUSE where FUSE works (root _or_ `fusermount3`) and NFS otherwise, which is what macOS gets — root or not, since NFS needs none there. Both transports arrive via `await import()`, and the probe reaches only `nfs/probe.ts` and `fuse/fusermount.ts`, so choosing one never loads the other's codec. The result is the transport's own mount object with a `transport` discriminant defined on it — tagged, not wrapped. No fallback after a failure, and no probe when a transport is named: both are deliberate, see the module docs.
- `drivers/memory.ts`, `drivers/node-fs.ts` — the two v1 drivers; the passthrough resolves every path component itself so nothing escapes its root.

FUSE (`src/fuse/`, exported as `mountx/fuse`):

- `constants.ts` — opcodes and `FUSE_*`/`FOPEN_*`/`FATTR_*`/`DT_*`, transcribed from the kernel's `include/uapi/linux/fuse.h` (tag v6.12, protocol 7.41).
- `protocol.ts` — every struct encoded **and** decoded, opcode dispatch table (`OPCODES`), message framing, errno-on-the-wire helpers, dirent packing (`DirentPacker`).
- `init.ts` — `negotiateInit(kernelInit, preferences)`, pure.
- `flags.ts` — the two `open(2)` flag namespaces, pure: `driverOpenFlags()` turns the kernel's `O_*` into the host's for the hand-off to a driver (the identity on Linux, where the wire _is_ the host, so unnamed bits survive), and `reopenFlags()` drops the one-shot creation flags a `handles: false` re-open must not repeat. The translation exists because Tier-0 tests drive a real session on whatever host runs `pnpm test`, and macOS's `O_TRUNC` is Linux's `O_APPEND`.
- `session.ts` — `FuseSession(driver, options)`: `INIT` handshake, opcode switch, file-handle table, readdir paging, `SETATTR` bitmask → driver calls, notify encoders.
- `inodes.ts` — `InodeTable`: nodeid ↔ path ↔ `(dev, ino)`, lookup refcounting, subtree remap on rename, orphans. Entirely synchronous.
- `notify.ts` — `notify_inval_inode`/`notify_inval_entry` codecs.
- `mount.ts` — `mount(driver, mountpoint, options)` → `Mount`, plus `unmountAll()`/`liveMounts()`. Picks its path by uid: root opens `/dev/fuse` here and spawns `mount(8)` with the descriptor at its own fd number; everyone else goes through `fusermount.ts`. Past the descriptor the two paths are the same code.
- `fusermount.ts` — the unprivileged mount path: `rootlessProbe()`, `mountViaFusermount()` → fd, `unmountViaFusermount()`. The `_FUSE_COMMFD` handshake is transcribed from libfuse 3.18.2 (`lib/mount.c`, `util/fusermount.c`), including which `-o` options the helper accepts and which four it supplies itself.
- `native.ts` — reshapes the addon's raw positive `errno` into a `node:fs`-shaped `code`/negative `errno`. Never imported on the root path. Locating and `dlopen`ing the binary is _not_ here: that is `#unfs/native` (`native/index.mjs`), for the reason in the invariants.
- `exec.ts` — `run()`/`describe()`/`stdioWith()`, shared by the two files that spawn.
- `record.ts` — tees `/dev/fuse` traffic (`mount({ tap })`) into a transcript; `replayTranscript()` feeds one back through a fresh session.

NFS (`src/nfs/`, exported as `mountx/nfs`):

- `xdr.ts` — XDR (RFC 4506): `XdrReader`/`XdrWriter`, bounds-checked, big-endian, 64-bit fields as `bigint`.
- `rpc.ts` — ONC RPC v2 (RFC 5531): call/reply, `AUTH_NONE`/`AUTH_SYS`, TCP record marking.
- `constants.ts` + `protocol.ts` — RFC 1813 transcribed; every struct encoded **and** decoded.
- `handles.ts` — `FileHandleTable` and the readdir cookie scheme.
- `session.ts` — `NfsSession(driver, options)`: `handleCall(bytes)` → `Promise<Uint8Array | null>`, answering both MOUNT and NFS programs.
- `probe.ts` — `nfsClientProbe()` and the `NfsPlatform` narrowing, split out of `mount.ts` because `mountx/auto` asks before deciding what to load: it imports `node:fs` and nothing else, where `mount.ts` pulls the server and the whole codec behind it. Root is required for **Linux only**. `mount.ts` re-exports it.
- `server.ts` — `createNfsServer(driver, options)`, the only file here that opens a socket. `mount.ts` — `mountNfs()`/`nfsMountOptions()`, and the only platform-aware transport in the project: it mounts on **Linux and macOS** — on macOS **without root**, since `mount_nfs` is not setuid and a BSD lets an ordinary user mount onto a directory they own (`ownershipRefusal()` checks that at mount time, because it is a fact about the path rather than the host) — and keeps the difference in pure, tested pieces (`nfsMountOptions()`, `parseMountTable()`, `ownershipRefusal()`, `isConsentDenial()`/`consentAdvice()`, the probe's helper paths) plus a `-f`-only escalation ladder on macOS that the consent gate can refuse outright. macOS is NFS-only by necessity — macFUSE is a third-party kext with its own protocol dialect, so `src/fuse/` cannot serve it.
- `index.ts` — re-exports `protocol.ts` by name, minus the sub-struct helpers (`readFattr`/`writeFattr`, `readSattr`/`writeSattr`, ...).

CLI (`src/cli/`, the `mountx` bin, `pnpm play` from source):

- `index.ts` — `node:util`'s `parseArgs`, then a memory driver holding one file — this package's own `README.md`, read through `new URL("../../README.md", import.meta.url)`, which is the package root from `src/cli/` and from `dist/cli/` alike, and npm publishes a README whatever the `files` list says — wrapped in `watch.ts` and mounted through `mountx/auto` at `~/mountx` (`[mountpoint]`/`-m`/`$MOUNTX_MOUNTPOINT`; `-t`, `-q`, `-r`, `--empty`, `--allow-other`). It is a demo and a test bench, not a mount tool — what it serves is always a tree that dies with the process. `process.exit` appears only in paths that run _before_ the mount (with one up it wedges), and the stale-mount cleanup detaches only a `fuse*`/`nfs*` mount at that exact path, printing the `sudo` line rather than spawning one when the route needs root. It runs on **both hosts**: Linux reads `/proc/self/mounts` inline, macOS asks `mountEntryAt()` from `src/nfs/mount.ts` (dynamically imported, so a Linux run never loads the NFS codec) and clears with an unprivileged `umount -f`, which works because a BSD lets the mounting user unmount. Only Linux+NFS has no unprivileged route and gets the `sudo` line. Bounded by `STALE_TIMEOUT`, because the macOS consent gate turns `umount` into a call that never returns — on expiry it prints `consentAdvice()` and lets `mount()` refuse.
- `watch.ts` — the `FsDriver` `Proxy` that narrates every request, open file handles included. `color.ts` — ANSI, off under `NO_COLOR`.

Tests (`test/`):

- `conformance.ts` — the one Tier-0 suite, written against the driver interface; `drivers.test.ts` runs it against memory, node-fs and raw `node:fs/promises` (loopback column). A target declares `errors: "host"` when it forwards the host kernel's errors rather than carrying `src/errors.ts`'s table: on Linux that changes nothing, and on darwin it is what lets the suite hold the _code_ exact while allowing either number (`ENOTEMPTY` is 66 there, not 39) and expect BSD's `EPERM` for `unlink` of a directory.
- `rooted-node-fs.ts` — `node:fs/promises` rooted at a directory; the oracle shared by `drivers.test.ts` and the FUSE conformance column.
- `auto.test.ts` — Tier 0 for `mountx/auto`: the preference order and the ruled-out reasons, answered for darwin and win32 from any host via the `platform` override. `auto-mount.test.ts` — Tier 2, whichever transport this host chose; runs under `test:rootless` and skips unless something can mount _and_ the threadpool has been raised.
- `fuse/` — protocol/session Tier 0 (`random.ts`, `protocol.test.ts`, `golden.test.ts`, `dirent.test.ts`, `init.test.ts`, `flags.test.ts`, `session.test.ts`, `inodes.test.ts`, `session-fuzz.test.ts`, `synthetic-kernel.ts`, `fuzz.test.ts`), `native.test.ts` (the whole addon, Tier 0 — passing a descriptor to yourself needs no helper and no privileges), Tier 2 `mount.test.ts` and `mount-rootless.test.ts` (no sudo), the differential oracle (`differential.ts`+`differential.test.ts`), record/replay (`record-fixtures.ts`+`replay.test.ts`), the FUSE conformance column (`conformance-mount.test.ts`).
- `nfs/` — Tier 0 (`xdr.test.ts`, `protocol.test.ts`, `handles.test.ts`, `golden.test.ts`, `fuzz.test.ts`, `mount-options.test.ts` — the platform difference, checked from either host), the Tier-1 JS client (`client.ts`) and its conformance column (`conformance.test.ts`, `session.test.ts`), Tier 2 `mount.test.ts` (gated on `nfsClientProbe()`; sudo on Linux, `pnpm test:rootless` on macOS, where it needs none).
- `pjdfstest/` — `run.sh`+`run.ts` drive the pinned pjdfstest clone (gitignored) against a real mount and write the committed analysis.
- `matrix.ts` — generates `.agents/conformance-matrix.md`. `root.sh` — runs any Tier-2 vitest file under sudo with the environment fixed up (raised `UV_THREADPOOL_SIZE`, redirected `TMPDIR`, forwarded `MOUNTX_*`); every Tier-2 file skips itself when not root. `rootless.sh` is the same idea minus the `sudo` and minus everything `sudo` made necessary — `UV_THREADPOOL_SIZE` is all that is left, and `mount-rootless.test.ts` skips itself unless it has been raised.

Native (`native/`), the only non-JS in the repository:

- `src/main.zig` — a Node-API addon with three functions and nothing else: `socketpair`, `recvFd` (`poll(2)` + `recvmsg(2)` with `MSG_CMSG_CLOEXEC`) and `sendFd`, which the library never calls and the tests do. No fork, no exec, no strings, no allocation, no libc.
- `src/napi.zig` — the ~10 Node-API entry points used, `extern`-declared, transcribed from Node v24's `js_native_api.h`.
- `build.zig` — cross-compiles `prebuilt/mountx-linux-{x64,arm64}.node` from any host, `ReleaseSmall`, ~7 KB each. `prebuilt/` is a build output: gitignored, unpublished, and needed only by whoever is changing the addon.
- `build.ts` — `pnpm build:native`, the whole of it: `zig build`, then regenerate `prebuilt.mjs` from what it wrote. No flags and no half-runs — the binaries and the embed are one artifact in two forms, and anything that rebuilt one alone would exist only to leave them disagreeing. Output is deterministic — sorted targets, no timestamps, every brotli parameter named rather than defaulted — because it is the committed artifact and "did the addon change?" has to be a readable diff. Compression is the one thing outside that: a Node release with a different libbrotli re-encodes bytes it did not change, which is why the sha256 written above each payload is of the _decompressed_ file and still answers the question.
- `prebuilt.mjs` — **generated, do not edit.** The addon brotli'd and base64'd (~13 KB for both platforms, against ~20 KB uncompressed), plus `loadEmbedded()`, which writes the bytes to a `mkdtemp` directory, `dlopen`s them, and deletes both before returning. This is the only committed and published form of the addon: a bundler carries text in the module graph, not a sibling binary, and an npm install carries it just as well. No user needs a toolchain. It is written as generated code: no prose, no JSDoc, and no `import` statements — builtins are reached with `process.getBuiltinModule` at the call sites, because this module sits on the _static_ import path of `mountx/fuse` and nothing in it runs unless a process mounts unprivileged (statically importing `node:os`+`node:zlib` cost ~1 ms of import time for consumers that never touch the addon; the 13 KB of base64 costs ~0.05 ms and is not worth deferring). Every explanation that used to live in the file is in `build.ts` — a generated file carrying its own rationale is one somebody edits in place.
- `index.mjs` + `index.d.mts` — `dlopen`s the embedded addon once per process, memoizing the failure as well as the success, and exports that one function: `loadNative()` is all `src/` asks for, and the tests read the embed from `prebuilt.mjs` directly. Hand-written JS, shipped verbatim, imported as `#unfs/native`. Verified end to end by `npm pack` → install → mount from `node_modules`, and by bundling `#unfs/native` and running the bundle from a directory with no package near it.

`bench/` — `harness.ts` (warmup, adaptive loop, percentiles), `scenarios.ts` (written once against the driver interface), `index.ts` (loopback + NFS columns), `fuse.ts`+`fuse-client.ts` (the FUSE column, client in a child process); generates `.agents/benchmarks.md`.

Docs (`docs/`) — the [undocs](https://undocs.dev) site at <https://mountx.vercel.app>. A **standalone pnpm project**, deliberately outside the root workspace (its own `package.json`, lockfile and `pnpm-workspace.yaml`), so the site's dependency tree never reaches the package's: `pnpm install && pnpm dev` inside `docs/`. Three sections, numbered-prefix routing (`1.guide/` → `/guide`): `1.guide/` (introduction, quick start, writing a driver, mounting, tuning, troubleshooting), `2.transports/` (how `auto` chooses, then FUSE and NFSv3 in detail), `3.reference/` (one page per entry point, plus the CLI). `.config/docs.yaml` is the landing page and the site config; `.docs/public/` holds the icons. **This is where user-facing prose goes now.** `README.md` was cut back to the intro, its snippet, install and a link list when the site landed — a second full copy is one that goes stale, and the CLI mounts the README, so it stays short on purpose. Anything longer than a paragraph belongs on a page here.

## Invariants (do not break)

- **Zero runtime deps.**
- **The native addon is optional, lazy, and never on the root path.** Mounting as root opens `/dev/fuse` itself and touches no native code, so a host with no prebuilt for its platform loses unprivileged mounting and nothing else. Anything added to `native/` has to keep that true: if it becomes required, the pure-JS story is gone.
- **What ships is the embed, not a binary.** `native/prebuilt.mjs` is the only committed and published copy of the addon; `native/prebuilt/*.node` is a gitignored `zig build` output. This is what makes bundling work — nothing has to be marked external, nothing resolves a sibling path — and `native/index.mjs` never looks for one, so `prebuilt/` being absent (as it is in CI and in every install) is not a case it has to handle.
- **The embed is the only copy anything loads.** `loadNative()` calls `loadEmbedded()` and nothing else: no path, no `existsSync`, no `import.meta.url`. `native/prebuilt/*.node` is consumed by `test/fuse/native.test.ts` and by nothing at runtime, so "which copy am I running?" has one answer on every host, bundled or not. This is why `pnpm build:native` is the command and `zig build` alone is not — a rebuilt binary is not live until it has been re-embedded.
- **`native/prebuilt.mjs` is generated, so it can go stale against `native/src/`.** `zig build` alone rewrites `prebuilt/` and leaves the embed behind; `pnpm build:native` runs both halves. `test/fuse/native.test.ts` compares every payload against its `.node` file whenever `prebuilt/` exists — which is exactly on the machine that just rebuilt it. Nothing in a fresh clone can check the embed against the Zig source, so **regenerating it is part of any `native/src/` change**, not a follow-up.
- **The errno table is transcribed once**, in `src/errors.ts`. The addon reports a raw positive `errno` and lets `src/fuse/native.ts` name it, rather than carrying a second copy of the table in another language where the two would drift.
- **`FsDriver` is a subset of `node:fs/promises`**, proven by the assignability acid test: `const driver: FsDriver = await import("node:fs/promises")` must compile with no cast.
- **Capabilities are declared-or-inferred, never faked.** An unmet capability answers `ENOSYS`/`ENOTSUP`; it is never silently pretended.
- **Errno discipline: exactly one reply per request.** `handleMessage`/`handleCall` never reject; every request needing a reply gets exactly one, a thrown value becomes a negative errno (unknown → `EIO`), and a dev-mode assertion tracks it per request id.
- **The zero-copy contract.** A session decodes and copies everything it keeps before its first `await`; the transport dispatches each read without awaiting it and re-arms the buffer as soon as that call returns. Breaking either half corrupts data under concurrent I/O.
- **Decoders always copy the bytes they retain.** `Buffer.prototype.slice` is `subarray`, not a copy — this exact mistake corrupted the first FUSE transcripts and an NFS `WRITE` payload before both were fixed.
- **The wire's `O_*` and a driver's `O_*` are different namespaces.** `fuse_open_in.flags` is the Linux kernel's; `FsDriver` is a subset of `node:fs/promises`, so a driver resolves what it is handed against the host. `src/fuse/flags.ts` is the one crossing, and it is the identity on Linux — the only host that mounts. Flags this server _originates_ for a driver (`mountx.mknod`'s fallback) are already the host's and must not be translated.
- **Wire constants are transcribed, never guessed or borrowed from host `node:fs`.** FUSE constants come from the kernel's `include/uapi/linux/fuse.h`; NFS constants come from RFC 1813/5531/4506; the `fusermount3` handshake and the Node-API declarations come from libfuse's and Node's own sources, both named where they are used.
- **A `-t fuse` mount never receives `FUSE_DESTROY`.** The transport must detect unmount itself (read EOF/`ENODEV` on `/dev/fuse`) and call `session.destroy()`; it is idempotent and safe with requests in flight.
- **No mount stacking.** Mounting over a live mountpoint — this process's own, or any FUSE mount already in `/proc/self/mounts` — is refused, in both directions.
- **An unreadable mount table means "still mounted", never "gone".** NFS teardown treats "is it mounted" as a tri-state (`src/nfs/mount.ts`'s `isMounted`): forcing down a mount that turns out to be gone is harmless, whereas reporting a successful unmount on a guess shuts the server down under a live mount. This is why the table read is async — macOS has no `/proc/self/mounts` and the table comes from spawning `mount(8)`.
- **Teardown has a deadline** (`unmountTimeout`, default 10 s) and escalates to `umount -f` on expiry. Every spawned `umount` is bounded by that deadline and abandoned if it outlives it — a `umount(8)` parked in the kernel does not die on `SIGKILL`, and a child still running is a child racing the escalation. Closing the `/dev/fuse` fd only aborts the connection when no read is parked on it.
- **On macOS the escalation can be refused outright.** Network volumes sit behind a sandbox approval that is never prompted for a command-line process, so `umount` blocks and `umount -f` answers `EPERM`; `src/nfs/mount.ts` names that case (`isConsentDenial`/`consentAdvice`) instead of blaming the driver, and says the mount survived. Do not paper over it — the fix is a grant the user makes in advance, and verified facts live in `.agents/environment.md`.
- **Unprivileged teardown is weaker, and says so.** Both routes to `fuse_abort_conn` — `MNT_FORCE` and `/sys/fs/fuse/connections/<n>/abort` — are root's, so a user can only `fusermount3 -u -z` and let the connection die with the superblock. Do not paper over the difference.
- **Self-client threadpool hazard.** Serving a mount and using it (any sync `fs` call, or enough concurrent async ones) from the same process parks threadpool threads the read loop also needs, and wedges. Documented at the top of `src/fuse/mount.ts`.
- **`process.exit()` does not work with a mount up.** Node's exit path joins the threadpool the reads are parked in. `await unmount()` and set `process.exitCode`; this is also why the signal handlers re-raise the signal instead of exiting directly.
- **Source stays NUL-free and grep-able.** E.g. the NFS cookie verifier delimiter is the two-character string `"\0"`, never a literal NUL byte.
- **Golden fixtures must give every field a distinct value.** A fixture built from repeated/mirrored values (`uid: 0, gid: 0, size == used`) passes even with transposed encoder/decoder fields; only an all-distinct fixture catches a symmetric encode/decode bug.
- **Published perf claims may come only from `.agents/benchmarks.md`**, and must carry that file's host line with them. That covers `README.md` and `docs/` alike; the README now links to the docs rather than repeating the numbers, so `docs/1.guide/4.tuning.md` is where they live.

## Commands

- `pnpm test` — lint + typecheck + the Tier-0/Tier-1 vitest suites; no root needed, runs everywhere.
- `pnpm test:rootless` — the Tier-2 unprivileged mount suite: FUSE on Linux, NFS on macOS, plus `mountx/auto` against whichever it is. **No sudo**; the FUSE column needs `fusermount3` (`dnf install fuse3` / `apt install fuse3`) and a prebuilt for the platform, and skips itself without them. Every file here also skips unless the threadpool has been raised, which is what keeps a plain `pnpm test` from mounting anything now that macOS needs no root.
- `pnpm build:native` — rebuilds both prebuilts with `zig build` and regenerates `native/prebuilt.mjs` from them. Only needed when `native/src/` changes, and the regenerated `prebuilt.mjs` is the part that gets committed (the `.node` files are gitignored). Needs a Zig toolchain; nobody who is not editing `native/src/` needs one.
- `pnpm test:root` — the four Tier-2 real-mount suites under sudo (`sh test/root.sh test/fuse/mount.test.ts test/fuse/differential.test.ts test/fuse/conformance-mount.test.ts test/nfs/mount.test.ts`).
- `pnpm test:mount` — just the FUSE mount smoke test under sudo.
- `pnpm test:nfs:mount` — the NFS mount test under sudo; skips itself via `nfsClientProbe()` when the host has no NFS client.
- `pnpm mountx` — the CLI from source (`node src/cli/index.ts`), no root; `--help` for the flags.
- `pnpm matrix` — regenerates `.agents/conformance-matrix.md`.
- `pnpm bench` — the loopback + NFS benchmark columns, no root.
- `pnpm bench:root` — the FUSE benchmark column, under sudo.
- `pnpm fmt` — `automd && oxlint . --fix && oxfmt .`.
- `pnpm lint` — `oxlint . && oxfmt --check .`.
- `pnpm build` — `obuild`.
- `docs/`: `pnpm install` then `pnpm dev` / `pnpm build`, **from inside `docs/`** — it is its own project, not a workspace member.

Tier-2 (`*:root`/`*:mount`) commands need sudo; root's `PATH` lacks `node` (fnm), so they invoke `sudo "$(command -v node)" ...` rather than plain `sudo node ...` — see `test/root.sh`.

## More detail: `.agents/*.md`

- `.agents/roadmap.md` — the finalized v1 decisions that still bind, and every deferred/open item for future work.
- `.agents/environment.md` — verified FUSE/sudo/toolchain facts and wedge recovery procedures for the dev host.
- `.agents/pjdfstest-results.md` — pjdfstest pass/fail breakdown and the bugs it found.
- `.agents/conformance-matrix.md` — generated per-transport conformance table (`pnpm matrix`).
- `.agents/benchmarks.md` — generated performance numbers and their interpretation (`pnpm bench`).
