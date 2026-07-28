# mountx

<!-- automd:badges color=yellow -->

[![npm version](https://img.shields.io/npm/v/mountx?color=yellow)](https://npmjs.com/package/mountx)
[![npm downloads](https://img.shields.io/npm/dm/mountx?color=yellow)](https://npm.chart.dev/mountx)

<!-- /automd -->

**Write a filesystem in JavaScript, mount it as a real kernel filesystem.**

A driver is an object with the `node:fs/promises` methods (`stat`, `readdir`, `open`, `mkdir`, `rename`).

Mountx takes that object and mounts it, either as a [FUSE mount](https://en.wikipedia.org/wiki/Filesystem_in_Userspace) on Linux or as an NFSv3 share. The driver never learns which. There is nothing to adapt: `node:fs/promises` already _is_ the interface, and its errors already _are_ the error contract.

So anything you can describe as a filesystem gets a real mountpoint — an in-memory store, a zip file, an S3 bucket, a content-addressed blob store, a `node:fs` directory served back out.

## Installation

```sh
npx nypm install mountx
```

Subpath exports: `mountx` (driver interface, loopback harness), `mountx/fuse`,
`mountx/nfs`, `mountx/drivers/memory`, `mountx/drivers/node-fs`.

## Quickstart

### FUSE (Linux, needs root)

```ts
import { mount } from "mountx/fuse";
import { createMemoryDriver } from "mountx/drivers/memory";

await using mounted = await mount(createMemoryDriver(), "/mnt/point");
// /mnt/point is a real mountpoint until unmount() or the process exits.
```

Mounting needs root — `mount(2)` is not a syscall Node can issue, and v1 has
no unprivileged path yet (see Roadmap). Run it with `sudo`:

```sh
sudo node --experimental-strip-types your-script.ts
```

If a process dies without unmounting, the mountpoint is left stale rather than
hung (`ls` answers `ENOTCONN`, it does not block). Clear it with:

```sh
sudo umount -l /mnt/point
```

### NFSv3 (no root to serve, root to mount)

```ts
import { mountNfs } from "mountx/nfs";
import { createMemoryDriver } from "mountx/drivers/memory";

await using mounted = await mountNfs(createMemoryDriver(), "/mnt/point");
```

`mountNfs` still needs root and a host with an NFS client (`nfsClientProbe()`
tells you before it tries). To drive the server from anywhere with an NFSv3
client and no root at all, mount it yourself:

```sh
sudo mount -t nfs -o vers=3,tcp,port=<p>,mountport=<p>,nolock 127.0.0.1:/ /mnt
```

`<p>` is `mounted.port` if you used `mountNfs()` (shown above), or
`server.port` if you called `createNfsServer` directly — either picks an
ephemeral port unless you set one.

## The driver interface

`FsDriver` is a subset of `node:fs/promises`, not a bespoke shape — the acid
test is that the real thing satisfies it with no wrapper:

```ts
import type { FsDriver } from "mountx";

const driver: FsDriver = await import("node:fs/promises"); // compiles as-is
```

Only `stat`, `readdir` and `open` are required; everything else (`mkdir`,
`rename`, `link`, `symlink`, `chmod`, `chown`, `truncate`, `utimes`, ...) is
optional, and a missing method means the capability is genuinely absent — the
transport answers `ENOSYS`/`ENOTSUP` rather than pretending. A driver declares
what it supports:

```ts
const capabilities = {
  handles: true, // open() returns real per-open state that survives unlink
  hardlinks: false,
  symlinks: true,
  // ...
};
```

Unclaimed capabilities are inferred from which methods exist (see
`resolveCapabilities` in `src/harness.ts`), but two — `handles` and
`atomicRename` — can't be inferred from shape alone and default to `false`
until declared.

Errors follow `node:fs` convention exactly: throw (or forward) an error with a
POSIX `code` and a libuv-style negative `errno`, and it maps onto the wire with
no translation. `src/errors.ts`'s `fsError()` produces one identical to
Node's own.

Test a driver with **no mount at all** using the loopback harness:

```ts
import { createLoopback } from "mountx";
import { createMemoryDriver } from "mountx/drivers/memory";

const fs = createLoopback(createMemoryDriver());
await fs.writeFile("/hello.txt", "hi");
await fs.readFile("/hello.txt"); // Uint8Array
```

It normalizes paths, fills in missing methods with `ENOSYS`, and resolves
capabilities — the same treatment a transport gives a driver, without
`/dev/fuse` or a socket anywhere. `test/conformance.ts` is the suite this
project runs against it; write your own scripts against the same harness.

## Transports

| transport | platforms                     | native code                                 | privilege to mount | semantics                   |
| --------- | ----------------------------- | ------------------------------------------- | ------------------ | --------------------------- |
| **FUSE**  | Linux                         | none (root mode); unprivileged stub planned | root               | full — no capability loss   |
| **NFSv3** | anywhere with an NFSv3 client | none                                        | root               | stateless — loses `handles` |

**FUSE** gets real `open`/`release` state, kernel-side caching under your
control, and full POSIX errno propagation. v1 is root-mode only: `mount(8)` is
spawned with an already-open `/dev/fuse` fd handed down through the child's
stdio (`src/fuse/mount.ts`). Unprivileged mounting needs a small setuid-helper
stub that hasn't been built yet — see Roadmap.

**NFSv3** needs no native code and no `/dev/fuse`, just a TCP socket
(`src/nfs/server.ts`), which is what makes it reachable from any OS with an
NFSv3 client. The cost is statelessness: NFSv3 has no `open`/`release`, so
every operation carries a file handle synthesized from the driver's `(dev,
ino)` identity rather than real per-open state. The one capability this loses
in practice — keeping an unlinked-but-open file readable — is the one the
conformance matrix names below.

Use FUSE when you have root on Linux and want the driver interface with
nothing lost. Use NFSv3 when you need a mount from something that isn't
Linux-with-`/dev/fuse`, or when root is available but a FUSE mount isn't
(there's no native-code dependency either way).

## Conformance

One suite (`test/conformance.ts`), written once against the driver interface,
run three ways — loopback, over a real FUSE mount, over a real NFSv3 socket —
so any test that passes in one column and fails in another is, by
construction, a transport bug rather than a driver bug. Full tables:
[`.agents/conformance-matrix.md`](https://github.com/pithings/mountx/blob/main/.agents/conformance-matrix.md).

The honest summary: **FUSE loses nothing** either bundled driver has (126/126
passing, no skips). **NFSv3 loses exactly one capability**, `handles` — an
unlinked-but-open file is `ESTALE` over NFS instead of staying readable,
because NFSv3 is stateless and has no `FORGET`. That's the whole capability
loss; it's declared once and derived from the test run, not guessed at.

Beyond the driver-interface suite, the FUSE transport was measured against
[**pjdfstest**](https://github.com/pjd/pjdfstest), the POSIX filesystem test
suite, over a real mount: **59.1% passing** (5179/8770 assertions), and **every
one of the 45 remaining failing files** exercises `mkfifo`/`mknod`/UNIX-socket
creation — a driver-interface gap (`node:fs/promises` has no way to create a
special file either), not a session bug. Full breakdown and bug list:
[`.agents/pjdfstest-results.md`](https://github.com/pithings/mountx/blob/main/.agents/pjdfstest-results.md).

The validation arsenal behind both reports:

- **Differential testing** — the same operation sequence run against a real
  FUSE mount and against plain `node:fs`, diffing every result and the two
  trees.
- **Record/replay** — real `/dev/fuse` traffic from `ls -laR`, `find`,
  `tar -xp` and more, captured once and replayed with no kernel and no root.
- **`libnfs` cross-validation** — a real NFSv3 client sharing none of this
  code, driving a 30-assertion workload and a 3000-entry `readdir` against the
  server, with `tshark` confirming the wire format.
- **Real-kernel tests** (Tier 2) — `pjdfstest` and the mount smoke tests run
  against an actual mountpoint, gated on root/`sudo`.

## Performance

All numbers below are from
[`.agents/benchmarks.md`](https://github.com/pithings/mountx/blob/main/.agents/benchmarks.md),
taken on one host, one day (Linux 6.12, Node v24.18.0, in-memory driver) —
they are not portable, and the file has the full tables and caveats.

- **FUSE sustains 41,500–50,300 requests/sec at zero timeouts with requests
  in flight** (readers 1/2/4: 41,539 / 48,549 / 50,349), and 13,600/sec for a
  strictly sequential client — confirming IDEA.md's "low tens of thousands of
  ops/sec" prediction, at the upper end. The shipped-default configuration
  (10 s timeouts, a cache-heavy scenario mix) peaks much lower on its own, around
  20,468 requests/sec, because most of that traffic never reaches the daemon —
  the request-level ceiling is a property of the zero-timeout, in-flight
  workload, not of the defaults. A single-threaded client sees 2,000–4,000
  syscalls/sec on uncached metadata, because each syscall is several FUSE
  requests.
- **Negotiation defaults dominate, not JS-side tuning.** `attr_timeout`/
  `entry_timeout` are worth **8–15×**; `FOPEN_KEEP_CACHE` is worth **~4.9×** on
  re-read. Nothing hand-optimized in this codebase has been worth anything
  comparable.
- **Open question: `FUSE_READDIRPLUS_AUTO`.** On by default, it limits
  readdirplus to a listing's first page, so a cold 1000-entry `ls -l` gets
  10,345 entries/s instead of the ~2.4× win IDEA.md predicts; disabling `AUTO`
  reaches 25,047 entries/s (the predicted win) but costs ~20% on a names-only
  `readdir`. Not changed in v1 — benchmarks.md calls it the best-supported
  open question in the repo.
- **Throughput:** sequential read at 7,537 MiB/s (page-cache-backed) /
  1,526 MiB/s (transport floor with the cache off); sequential write at
  796 MiB/s over FUSE, 308 MiB/s over NFS. `max_write` at 1 MiB over 128 KiB is
  worth ~20% here (1.21×) against this driver — read it as 15–40%, not a
  sharper number, and expect more against a driver that does real per-request
  I/O. Throughput is the one place the NFS numbers are not held back by the
  test client (see below) — read these as real, not as a floor.
- **NFS's metadata numbers are a floor, not a ceiling.** A 500-file `stat`
  walk runs at 3,571 stats/s over NFS against FUSE's 33,813, and `ls -l` at
  4,980 entries/s against 27,246 — not the protocol being slow, but the JS
  test client having no dentry cache and re-walking every path component on
  every call. A real kernel NFS client would do markedly better.

This is fine for a content-addressed store, an S3 mount, a git filesystem, a
config filesystem. **It is not a hot build directory.** The faster paths IDEA.md
describes — a sync driver running in worker threads, and a relay mode that
takes `/dev/fuse` off the libuv threadpool entirely — don't exist yet. v1 ships
async main-thread mode only, and no claim is made about the other two beyond
"expected to be faster."

## Hazards

The must-knows; each is documented in full where the code lives.

- **Root, in v1.** Both `mount()` (`mountx/fuse`) and `mountNfs()`
  (`mountx/nfs`) need to run as root. Neither has an unprivileged path yet.
- **Don't be your own client.** Serving a mount and using it from the same
  process is the sharp edge: any synchronous `fs` call against your own
  mountpoint deadlocks outright, and enough concurrent _async_ calls against it
  (e.g. `fs.rm(dir, { recursive: true })` on a couple hundred entries) exhausts
  `UV_THREADPOOL_SIZE` and wedges the process — the read loop needs one of
  those same threads to keep the mount alive. Put the client in another
  process, or keep self-directed concurrency well under the pool size. Full
  explanation at the top of `src/fuse/mount.ts`.
- **Don't `process.exit()` with a mount up.** Node's exit path joins the
  threadpool, which a live mount always has reads parked in — it will hang,
  not exit. `await mount.unmount()` first and set `process.exitCode`; that's
  also why the built-in `SIGINT`/`SIGTERM` handlers unmount and then re-raise
  the signal instead of calling `process.exit()` themselves.
- **A crashed process leaves a stale mount table entry**, not a hung one — the
  kernel drops the connection with the last reference to the fd, so `ls`
  answers `ENOTCONN` rather than blocking. Recover with
  `sudo umount -l <mountpoint>`.

## Status / roadmap

**Shipped in v1:** the driver interface (`mountx`), the FUSE protocol,
session and root-mode transport (`mountx/fuse`), NFSv3 loopback
(`mountx/nfs`), the in-memory and `node:fs` passthrough drivers, the
loopback test harness, and the conformance + benchmark suites this README is
drawn from.

**Deferred, not designed against:**

- Unprivileged FUSE mounting (a small native stub — see IDEA.md).
- Sync-driver-in-worker-threads and relay concurrency modes (would remove the
  threadpool hazard above and, per IDEA.md, should scale with worker count —
  unmeasured, not built).
- `mknod` / FIFOs / device nodes / UNIX sockets — the entire remaining
  pjdfstest gap traces back to this one interface gap.
- xattr, byte-range locks, WebDAV, Windows support.

**Reasoned, not observed:** the NFSv3 transport has never been exercised
against a real kernel NFS client — the development host has no `nfs` kernel
module and no `mount.nfs` at all (`nfsClientProbe()` will tell you if yours
does). Its correctness case rests on the Tier-1 JS client (built from the same
XDR codecs as the server, so not an independent check) and on `libnfs`
cross-validation (independent, but narrower than a full conformance run). If
you mount it against a real client, a bug report is worth more than the
benchmarks in this file.

## Development

<details>

<summary>local development</summary>

- Clone this repository
- Install latest LTS version of [Node.js](https://nodejs.org/en/)
- Enable [Corepack](https://github.com/nodejs/corepack) using `corepack enable`
- Install dependencies using `pnpm install`
- Run interactive tests using `pnpm dev`
- `pnpm test` runs lint, typecheck and the Tier-0/Tier-1 suites (no root
  needed); `pnpm test:root` additionally runs the Tier-2 real-mount suites
  under `sudo`.
- `pnpm matrix` and `pnpm bench` / `pnpm bench:root` regenerate the two
  committed reports this README draws from
  (`.agents/conformance-matrix.md`, `.agents/benchmarks.md`).

</details>

## License

Published under the [MIT](https://github.com/pithings/mountx/blob/main/LICENSE) license 💛.
