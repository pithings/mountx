# mountx

Mount a JavaScript filesystem: one driver interface (a subset of `node:fs/promises`),
multiple transports — FUSE, 9P, NFS (v3 and v4.1) — plus an S3 gateway (`mountx/s3`)
that serves the same driver to an S3 client instead of mounting it, deliberately
outside `mountx/auto`.

**Conventions:** pure JS/TS, zero runtime deps, pure-JS-first. Single package with
subpath exports. Small conventional commits to `main`, `pnpm test` green before each
commit. User-facing prose goes in `docs/` (<https://mountx.vercel.app>), not in
`README.md`, which is the npm/GitHub landing page and links there.

There is exactly one piece of native code (`native/`), and it exists for one reason:
unprivileged FUSE mounting needs `fusermount3` to hand `/dev/fuse` back over
`SCM_RIGHTS`, and Node cannot `recvmsg` a descriptor.

**Detail lives in `.agents/`** — start with `.agents/architecture.md` before changing
an area you have not touched, and `.agents/invariants.md` for the reasoning behind
any rule below that looks removable.

## Layout

| Path             | What                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------------------------ |
| `src/types.ts`   | `FsDriver`, `FsCapabilities`, the `mountx.*` extension namespace (`mknod`, `utimens`)                  |
| `src/errors.ts`  | `ERRNO_CODES`, `fsError()`, `errnoOf()` — the one errno table                                          |
| `src/path.ts`    | absolute POSIX path helpers; `..` clamps at the root                                                   |
| `src/harness.ts` | `createLoopback(driver)` — what driver authors test against                                            |
| `src/lock.ts`    | `PathLock`, taken by `RENAME` on every transport                                                       |
| `src/subtree.ts` | `remapSubtree()` — the rename rewrite all three handle tables share (internal)                         |
| `src/auto.ts`    | `mountx/auto`: probe, then FUSE → 9P → NFS, each via `await import()`                                  |
| `src/drivers/`   | `memory` (the only `mountx.mknod` implementation), `node-fs`, `unstorage`, `handle.ts`                 |
| `src/fuse/`      | `mountx/fuse` — protocol 7.41, root and `fusermount3` mount paths, `exec.ts` (shared spawn/`Deadline`) |
| `src/9p/`        | `mountx/9p` — 9P2000.L, `trans=unix` by default, one session per connection                            |
| `src/nfs/`       | `mountx/nfs` — a version router over `v3/` (RFC 1813 + MOUNT) and `v4/` (NFSv4.1); Linux and macOS     |
| `src/s3/`        | `mountx/s3` — SigV4 gateway over HTTP, path-style, one bucket per driver                               |
| `src/cli/`       | the `mountx` bin — a demo and test bench that mounts this package's README                             |
| `native/`        | the Zig Node-API addon and its generated embed (`prebuilt.mjs`)                                        |
| `test/`          | Tier 0/1/2 suites and the shared conformance suite — see `.agents/testing.md`                          |
| `bench/`         | generates `.agents/benchmarks.md`                                                                      |
| `docs/`          | the undocs site — **a standalone pnpm project**, not a workspace member                                |

Every transport directory follows one shape: `constants.ts` (transcribed from the
kernel header or RFC named in the file), `protocol.ts` (every message encoded **and**
decoded), `session.ts` (protocol ↔ `FsDriver`), `server.ts`/`mount.ts`, `probe.ts`,
`index.ts`.

## Invariants (do not break)

Each line is the rule; `.agents/invariants.md` has the reasoning and the traps.

1. **Zero runtime deps.** `unstorage` is a type-only optional peer — check
   `dist/drivers/unstorage.mjs` has no import of it if that driver is touched.
2. **The native addon is optional, lazy, and never on the root path.** Root mounting
   opens `/dev/fuse` itself and touches no native code.
3. **The embed is the only copy anything loads**, and it is generated — regenerating
   `native/prebuilt.mjs` with `pnpm build:native` is part of any `native/src/`
   change, not a follow-up.
4. **`FsDriver` is a subset of `node:fs/promises`** — `const driver: FsDriver = await
import("node:fs/promises")` must compile with no cast.
5. **Capabilities are declared-or-inferred, never faked** — unmet answers
   `ENOSYS`/`ENOTSUP`.
6. **The errno table is transcribed once**, in `src/errors.ts`.
7. **Wire constants are transcribed** from the kernel headers and RFCs named in each
   file — never guessed, never read off host `node:fs`.
8. **The wire's `O_*` and a driver's `O_*` are different namespaces.**
   `src/fuse/flags.ts` is the one crossing; 9P imports it rather than copying it.
9. **Exactly one reply per request** (per COMPOUND on v4.1);
   `handleMessage`/`handleCall` never reject, and a thrown value becomes that
   transport's error reply.
10. **A minor version other than 1 is refused** with `NFS4ERR_MINOR_VERS_MISMATCH`,
    not guessed at.
11. **No grace period on NFSv4.1** — every reclaim answers `NFS4ERR_NO_GRACE`, and
    `RECLAIM_COMPLETE` still gates ordinary locking.
12. **The zero-copy contract.** Sessions copy everything they keep before the first
    `await`; the reply path returns a view of a per-reply writer that is never
    written to again.
13. **Decoders always copy the bytes they retain** — `slice` is `subarray`. One
    documented exception: `FuseRequest.payload`.
14. **No mount stacking**, in either direction.
15. **An unreadable mount table means "still mounted", never "gone".**
16. **Teardown has a deadline** (`unmountTimeout`, default 10 s) and it is **per
    phase over a shared `Deadline`, never per spawn**; every spawned child is bounded
    and abandoned past it. Server shutdown is a step _inside_ the phase.
17. **Unmount is the transport's job to detect** — no `FUSE_DESTROY`, no `Tdestroy`;
    EOF on `/dev/fuse` or on the 9P connection is the signal.
18. **On macOS the umount escalation can be refused outright** by the sandbox consent
    gate — name it (`isConsentDenial`/`consentAdvice`), never paper over it.
19. **Unprivileged FUSE teardown is weaker, and says so** — `fusermount3 -u -z` only.
20. **Self-client hazard.** Serving a mount and using it from the same process wedges
    (threadpool on FUSE, `uv_spawn` on both FUSE and 9P).
21. **`process.exit()` does not work with a mount up** — `await unmount()` and set
    `process.exitCode`.
22. **Source stays NUL-free and grep-able** (e.g. the cookie delimiter is `"\0"`, the
    two-character string).
23. **Golden fixtures give every field a distinct value** — mirrored values pass with
    transposed encode/decode.
24. **Published perf claims come only from `.agents/benchmarks.md`**, carrying its
    host line.

## Commands

| Command                                        | What                                                                     | Root      |
| ---------------------------------------------- | ------------------------------------------------------------------------ | --------- |
| `pnpm test`                                    | lint + typecheck + the Tier-0/Tier-1 suites; runs everywhere             | no        |
| `pnpm test:rootless`                           | Tier-2 unprivileged mounts: FUSE on Linux, NFS on macOS, plus `auto`     | no        |
| `pnpm test:root`                               | the five Tier-2 real-mount suites (FUSE ×3, NFS, 9P)                     | sudo      |
| `pnpm test:mount` / `:nfs:mount` / `:9p:mount` | one Tier-2 suite each                                                    | sudo      |
| `pnpm test:pjdfstest`                          | pjdfstest against a real mount                                           | sudo      |
| `pnpm build:native`                            | `zig build` **and** regenerate the embed; only for `native/src/` changes | no        |
| `pnpm mountx`                                  | the CLI from source; `--help` for flags                                  | no        |
| `pnpm matrix`                                  | regenerate `.agents/conformance-matrix.md`                               | no        |
| `pnpm bench` / `pnpm bench:root`               | loopback + NFS columns / the FUSE column                                 | no / sudo |
| `pnpm fmt` / `pnpm lint` / `pnpm build`        | `automd`+`oxlint`+`oxfmt` / check / `obuild`                             | no        |

Every Tier-2 file skips itself when the host cannot mount (`nfsClientProbe()`,
`p9ClientProbe()`, `rootlessProbe()`) or when `UV_THREADPOOL_SIZE` has not been
raised, so `pnpm test` never mounts anything. `docs/` is its own project: `pnpm
install && pnpm dev` **from inside it**.

## More detail: `.agents/*.md`

| File                       | What                                                                        |
| -------------------------- | --------------------------------------------------------------------------- |
| `architecture.md`          | the per-file map and the design reasoning behind it                         |
| `invariants.md`            | the list above, in full, with the "why"                                     |
| `testing.md`               | tiers, the conformance matrix, per-area test layout, known gaps             |
| `roadmap.md`               | what shipped, the decisions still binding, deferred work                    |
| `environment.md`           | verified host facts (FUSE, 9P, VM guests, rclone, macOS) and wedge recovery |
| `conformance-matrix.md`    | generated per-transport conformance table (`pnpm matrix`)                   |
| `benchmarks.md`            | generated performance numbers and their interpretation (`pnpm bench`)       |
| `pjdfstest-results.md`     | pjdfstest pass/fail breakdown and the bugs it found                         |
| `9p-plan.md`, `s3-plan.md` | the implementation plans those two transports shipped from                  |
