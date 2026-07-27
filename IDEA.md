# unimount

**Mount a JavaScript filesystem. One driver interface, several transports.**

Write a filesystem once, in TypeScript, and mount it — as a real kernel
filesystem on Linux via FUSE, as a loopback NFS share on macOS, or over WebDAV
anywhere. The driver never learns which.

The valuable abstraction here is *not* "FUSE bindings for JS". It's the driver
interface plus a small set of transports that carry it into a kernel. FUSE is
the best of those transports; it should not be the only one, and the interface
must not assume it.

---

## The driver interface is `node:fs/promises`

Not a bespoke `FsDriver`. Not libfuse's high-level API with the names changed.
A **subset of `node:fs/promises`**, exactly as Node defines it:

```ts
interface FsDriver {
  stat / lstat / statfs
  readdir(path, { withFileTypes: true })
  open(path, flags, mode): Promise<FileHandle>   // .read .write .sync .close .stat
  mkdir / rmdir / unlink / rename / link / symlink / readlink
  chmod / chown / lchown / truncate / utimes / lutimes
}
```

Why this and not a purpose-built interface: every existing JS filesystem already
implements it. `unfs`, `memfs`, `@zenfs/core`, `node:fs` itself (a passthrough
mount, which is how you test against a real kernel FS), and anything wrapping a
remote store. The adapter isn't thin — there is no adapter. That is the whole
adoption argument, and a custom interface throws it away for nothing.

It also makes error mapping free: `node:fs` errors already carry a POSIX `code`
and `errno`, so a driver that throws `ENOENT` the way Node does — or simply
forwards errors from a real `node:fs` call — maps back onto the wire with no
translation table. A bespoke interface would have to invent an error contract;
this one inherits it.

What `node:fs` genuinely doesn't cover becomes a small, **optional** extension
namespace the transport probes for and degrades without:

| gap                      | extension                         | who needs it            |
| ------------------------ | --------------------------------- | ----------------------- |
| nanosecond `utimens`     | `unimount.utimens(path, ns)`      | rsync, make, git        |
| `mknod` (FIFOs, devices) | `unimount.mknod(path, mode, dev)` | pjdfstest, `mkfifo`     |
| byte-range locks         | `unimount.getlk` / `setlk`        | sqlite, `flock` users   |
| xattr                    | `unimount.getxattr` / `setxattr`  | SELinux, macOS metadata |
| `fallocate`, `SEEK_HOLE` | `unimount.fallocate` / `lseek`    | sparse files            |
| cache invalidation       | `unimount.notify` (see below)     | live-updating mounts    |

`fs.utimes` takes float seconds and loses nanoseconds; `fs.statfs` exists (Node
≥18.15) and covers `df`; exact `O_*` open flags need no extension at all,
because `fs.open` has always accepted raw numeric flags. Everything else above
is genuinely absent from `node:fs` and genuinely optional.

**Flagship driver: `unfs`.** Content-addressed, immutable, every write a
snapshot, `cp -r` of a subtree is O(1), any subtree exports to a single CAR
file. Mounting it gives a demo nothing else has: a real POSIX mountpoint where
`cp -r` on a 4 GB tree is instant, every state is addressable by hash, and you
can `tar` the entire history into one portable file. It also has the sync twin
that unlocks the concurrency design below.

Other drivers that fall out for free: a zip/tar archive, an S3 or R2 bucket, an
`unstorage` mount (30+ backends, instantly), a git tree, sqlite, an HTTP
range-request mount, a process-info FS.

**Capabilities, not lies.** A driver declares what it supports
(`{ handles: true, hardlinks: false, xattr: false }`); transports adapt or
return `ENOTSUP`. Silently faking a capability is how you get a filesystem that
passes `ls` and corrupts data under `git`.

---

## Transports

Three, in shipping order. Each judged on whether it can ship, not on elegance.

| transport  | platforms             | native code                | privilege to mount              | semantics | perf |
| ---------- | --------------------- | -------------------------- | ------------------------------- | --------- | ---- |
| **FUSE**   | Linux                 | none as root; stub if not  | root, or setuid helper          | excellent | good |
| **NFSv3**  | Linux, macOS          | none                       | root                            | good      | fair |
| **WebDAV** | macOS, Windows, Linux | none                       | unprivileged on macOS / Windows | weak      | poor |

FUSE first — not because Linux matters most, but because it's the only transport
with semantics strong enough to *validate the driver interface*. If the
interface survives `pjdfstest` over FUSE, the weaker transports are subsets. Do
the reverse and you bake NFS's statelessness into the contract forever.

### 1. FUSE (Linux) — the primary target

Real `open`/`release` state, real POSIX errno propagation, unprivileged
mounting, kernel-side caching we control.

Three layers:

1. **Transport** — obtain a `/dev/fuse` fd, run a read/reply loop. The only
   layer that ever touches native code, and then only for unprivileged mounting.
2. **Protocol** — pure JS, zero deps. `FUSE_INIT` negotiation, opcode dispatch,
   ~45 structs encoded/decoded with `DataView`. The bulk of the code, and
   entirely deterministic data transformation — so **the whole protocol layer is
   unit-testable against recorded byte fixtures in CI: no root, no `/dev/fuse`,
   no mount.** No existing binding can say that; their protocol layer is in C.
3. **Session** — inode table, refcounts, handle table, notifies. See "What the
   library owns".

#### The native boundary is smaller than it looks

Getting the fd is not the problem. `fs.openSync('/dev/fuse', 'r+')` works in
pure JS — the device is mode 0666 on every mainstream distro. The problem is
`mount(2)`, which associates that fd with a mountpoint, and which Node cannot
issue because Node cannot issue arbitrary syscalls.

**As root, pure JS is enough.** The `fd=N` in the mount options resolves in the
*caller's* fd table, and fds are inheritable. So open `/dev/fuse` in JS and hand
it to stock `mount(8)`:

```js
spawn("mount", ["-i", "-t", "fuse", "-o", `fd=3,rootmode=40000,user_id=${uid},group_id=${gid}`,
                "/dev/fuse", mountpoint],
      { stdio: ["ignore", "ignore", "inherit", fuseFd] })  // fd 3 == /dev/fuse
```

The child mounts and exits, the kernel keeps its reference, and the parent keeps
its copy of the fd for the read/reply loop. No compiled artifact anywhere. (The
`-i` matters: without it, `mount(8)` hands off to the `/sbin/mount.fuse` helper,
which reinterprets the source argument as a program to execute.)

*Caveat to verify before building on it:* `sudo` closes fds ≥ 3 by default
(`closefrom`), so this works when the process is **already** root, not when
shelling out through `sudo`. Overriding needs `closefrom_override` in sudoers,
which can't be assumed. Worth a 20-line spike on a real host.

**Unprivileged mounting is the only thing that needs native code.** The setuid
`fusermount3` helper does the mount and returns the descriptor over
`SCM_RIGHTS`; Node has no `recvmsg` with control-message support. libuv can
receive such fds internally, but Node surfaces that only through
`child_process`'s own IPC protocol — between Node processes, for handle types
libuv recognizes. A raw fd from a setuid C binary is not reachable.

So: **one ~150-line prebuilt stub, two modes**, needed only for the
unprivileged path.

```sh
# exec mode — stub performs the handshake, dup2s the fd to 3, execs the daemon
unimount-helper /mnt/point -- node daemon.js        # fd 3 == /dev/fuse

# relay mode — stub holds /dev/fuse, proxies both directions over a unix socket
unimount-helper --relay /run/unimount.sock /mnt/point # any process connects
```

Exec mode is zero-copy and the default. Relay mode costs one `memcpy` per
message and buys two things worth more than that copy:

- **`mount()` from inside an already-running process** — the ergonomic API
  everyone actually wants — with no N-API addon. This is the *only* addon-free
  way to get there, precisely because SCM_RIGHTS can't reach a live Node process.
- **The fd becomes a socket**, which is event-loop native, which makes the
  threadpool problem below disappear entirely.

FUSE messages are self-framing (`fuse_in_header.len` is the first u32), so a
`SOCK_STREAM` unix socket needs no framing layer — which matters, because Node
doesn't do `SOCK_SEQPACKET`. Most FUSE requests are under 200 bytes; the copy is
only meaningful on 1 MiB data ops, where it is still far below the JS dispatch
cost.

The stub is an **executable, not a binding** — `exec`'d, never loaded into the
process, so it has zero Node coupling of any kind. Be precise about why that
beats the prior art, because the usual version of this argument is wrong: N-API
*is* ABI-stable across Node releases, and has been since Node 10, so addons do
not need per-Node-version rebuilds. What actually rots them is the platform
matrix (arm64, musl vs glibc, new OS versions), linking `libfuse` at build time,
and maintainer attrition. The stub wins on being 150 auditable lines with no
`libfuse` dependency that can be statically linked — not on N-API being fragile.
Build it with `zig cc` (no libc coupling either, ~20 KB per arch), ship
`linux-x64` / `linux-arm64` in the package, fall back to `cc` from source.

**Bun and Deno need no stub at all** — both have FFI, so they can `dlopen`
libc, do the `recvmsg` dance, and even call `mount(2)` directly. The stub is the
Node-shaped answer to a Node-shaped hole, not an architectural requirement.
Ship it as an optional peer, not a hard dependency.

### 2. NFSv3 loopback (macOS, and Linux without native code)

Serve NFSv3 over TCP and `mount -t nfs 127.0.0.1:/ /mnt`. Pure JS — just
sockets. This is the macOS story, because the FUSE option there is macFUSE: a
signed system extension requiring System Settings approval and a reboot. Not
shippable. (FUSE-T, the closed-source macOS alternative, is exactly this trick
under the hood — a userspace NFS server. Worth knowing the approach is proven.)

Costs, honestly:

- Mounting needs **root** on both platforms; there is no setuid helper
  equivalent. `sudo` in the docs, forever.
- NFSv3 is **stateless** — no `open`/`release`; every op carries a file handle
  derived from the driver's identity for that file. Drivers with real open state
  need the session layer to synthesize it, keyed on the handle.
- Protocol surface is larger than FUSE's (MOUNT + NFSv3 over XDR), but frozen
  and thoroughly specified. **portmap/rpcbind is avoidable** — pass explicit
  `port=` and `mountport=` to the mount command and you never touch port 111,
  which removes one privileged listener and a whole class of conflicts.

### 3. WebDAV (everywhere, including Windows)

The escape hatch, and the only transport that is both zero-native-code **and**
unprivileged on macOS and Windows: Finder's "Connect to Server" and Explorer's
`net use` both mount WebDAV as a normal user. On Linux, `davfs2`.

Semantics are the weakest of the three — HTTP verbs, no partial writes without
range extensions, no real file handles. Windows' client wants the WebClient
service running, defaults to refusing Basic auth over plain HTTP
(`BasicAuthLevel`), and caps file size around 50 MB by default
(`FileSizeLimitInBytes`). Perf is poor. But it's a few hundred lines over an
HTTP server, works on every desktop OS with no install, and for read-mostly
drivers (an archive, a bucket, a git tree) it is entirely adequate.

### Explicitly out of scope

- **SMB** — the obvious "why not" for Windows and macOS, and the answer is that
  a correct SMB2 server is a larger project than all three transports combined,
  with authentication surface that turns a toy mount into a security liability.
- **9P** — needs virtio or a root-only Linux mount, with semantics that don't
  pay for the implementation.
- **WinFsp** — a native Windows filesystem driver, its own large protocol,
  Windows ACLs and case-insensitivity. Real work, only if Windows demand
  materializes beyond what WebDAV covers.
- **macFUSE** — see above.

Design the interface to not assume FUSE, ship FUSE first, add transports on
demand. Do not design all of them up front.

**And build pure-JS-first.** Protocol + session + NFS + WebDAV + root-mode FUSE
is already a complete library — zero native artifacts, zero build step — that
passes `pjdfstest` against a real mountpoint in stock CI. That reaches a
validated driver interface and a full conformance matrix before a line of C
exists. The stub is a v1.x affordance for unprivileged mounting, not a
prerequisite; if unprivileged mounting turns out not to matter to real users, it
may never need to be written at all.

---

## What the library owns

The parts every driver author reimplements, badly:

- **Lookup refcounting.** The kernel sends `FORGET`/`BATCH_FORGET` with an
  `nlookup` count; an inode entry may only be dropped when that count reaches
  zero — not on `unlink`, not on `rmdir`. Getting this wrong produces
  stale-inode bugs that reproduce once an hour under load.
- **The path↔inode map.** This is the real cost of a path-based driver
  interface, and it is where the bugs live: a directory rename must remap an
  entire subtree, an unlinked-but-open file keeps its inode with no path, and a
  hardlink means one inode with several. The interface is worth the bookkeeping,
  but the bookkeeping is not free and belongs here, once.
- **The file-handle table**, plus a writeback buffer: the kernel issues small
  offset writes and most JS-side stores want whole-file semantics.
- **Readdir paging.** The kernel fills a size-limited buffer from an offset, and
  NFS resumes from opaque cookies; `fs.readdir` returns everything at once. The
  session layer snapshots the listing per open directory and synthesizes stable
  offsets over it — preferring `fs.opendir`'s streaming `Dir` when the driver
  has one, so a million-entry directory never materializes in memory.
- **Permission checks.** Mount with `default_permissions` so the kernel enforces
  mode bits from `getattr` and drivers never make access decisions. Document
  `allow_other` and its `/etc/fuse.conf` gate once, here, instead of in every
  driver's issue tracker.
- **`INTERRUPT` and `DESTROY`.** Ignore `FUSE_INTERRUPT` and Ctrl-C on a slow
  read hangs the shell. The cheap correct answer is to reply `-ENOSYS` to the
  first one, which tells the kernel to stop sending them; the expensive correct
  answer is real cancellation via `AbortSignal` into the driver. Ship cheap,
  offer expensive.
- **Errno discipline.** Every request must be replied to exactly once. A thrown
  JS error escaping a handler means a hung mountpoint and a process in `D`
  state, unkillable. Every dispatch is wrapped in a catch-all replying `-EIO`,
  and a reply-tracking assertion runs in dev.
- **Notifies.** `notify_inval_inode` / `notify_inval_entry` / `notify_store`.
  This is why the low-level layer must be exported: `unfs` has `watch`, and
  `watch` + notify is a mount that updates live when another process syncs the
  store. Nothing path-based can express that.
- **Negotiation defaults** (below), which matter more than any JS optimization.
- **Teardown.** Unmount on `SIGINT`/`SIGTERM`, `-o auto_unmount` so a crashed
  daemon doesn't leave a mountpoint that `ls` hangs on, and a documented
  `fusermount3 -u` / `umount -f` recovery path. Every FUSE binding user gets
  burned by this exactly once and never forgets it.

---

## Concurrency

The kernel keeps many requests in flight and accepts out-of-order replies (each
carries a `unique` tag). The constraint is that the read loop must never block
behind a handler: keep N reads outstanding, dispatch each completion without
awaiting it, re-arm.

The classic Node trap: `fs.read()` on `/dev/fuse` parks a **libuv threadpool
thread** (default pool size 4, shared with all other fs/dns/zlib work). Ten
outstanding reads on a pool of four is a deadlock. And `/dev/fuse` cannot be
added to the event loop — `uv_guess_handle` classifies a char device as
`UV_FILE`, so `net.Socket({ fd })` routes it back to the threadpool.

The tempting conclusion is that this is unfixable in JS, and that the library's
job is to document `UV_THREADPOOL_SIZE` and move on. It isn't. There are three
real answers, and the library should ship all three:

1. **Relay mode** (above). The fd is a unix socket. Fully event-loop native, no
   threadpool involvement, no environment variable. This is the default for
   async drivers, and the ergonomic story.
2. **Sync driver in worker threads.** If the driver exposes a synchronous
   surface — and `unfs` does, deliberately — then each worker runs a blocking
   `readSync` / decode / dispatch / `writeSync` loop on its own thread. That
   touches the threadpool zero times, scales across cores, and has the shortest
   possible path from syscall to reply. `unfs`'s core has no `node:` imports and
   is content-addressed, so it moves into a worker cleanly. **No existing JS
   FUSE binding can do this**, because they inherit libfuse's threading model.
3. **Exec mode + async driver.** The old path. Document
   `UV_THREADPOOL_SIZE=32` and reserve K threads. Keep it for zero-copy
   throughput on drivers that can't be synchronous.

The cost of mode 2 is that the driver must tolerate concurrent calls across
workers. Default to one worker (safe, still fast), let the driver opt in to N
via a capability flag, and serialize per-inode when it doesn't.

(NFS and WebDAV are exempt from all of this — sockets, natively.)

---

## Performance

Order of magnitude: syscall + JS dispatch per request. Async main-thread mode
should land in the low tens of thousands of ops/sec; sync-worker mode should be
meaningfully better and scale with worker count — but claim nothing in the
README until it's measured, because "we benchmarked it" is the only sentence
here anyone should trust.

Fine for a content-addressed store, an S3 mount, a git FS, a config FS. Not fine
as a hot build directory. Say so.

The wins are in negotiation, not in micro-optimizing JS:

- `max_write` at 1 MiB (needs `FUSE_MAX_PAGES`, protocol 7.28+)
- `FUSE_CAP_WRITEBACK_CACHE` — makes the kernel your write buffer and collapses
  small writes. **With a caveat the docs must state:** the kernel becomes
  authoritative for size and mtime, and writes can arrive after `release`. For
  `unfs` this collides directly with snapshot granularity (below).
- generous `attr_timeout` / `entry_timeout`
- `FOPEN_KEEP_CACHE`
- `readdirplus` — folds `lookup` into `readdir`, often 2–3× on `ls -l`
- a preallocated buffer ring; per-request `Buffer` allocation is the one JS-side
  cost that actually shows up in profiles

A library with these defaults right beats a hand-rolled driver without them, by
a lot — which means **the benchmark suite is a v1 deliverable, not a nice-to-have.**
It's the proof of the central claim.

### The macOS turd problem

Finder writes `.DS_Store` and AppleDouble `._*` files into every directory it
touches, over both NFS and WebDAV, and probes for `.hidden`, `.metadata_never_index`,
and Spotlight paths. A synthetic driver gets spammed with writes it never asked
for, and a read-only driver gets a stream of `EROFS`. Mount `-o nobrowse`, ship
a default filter for the known-junk patterns, and make it a documented opt-out
rather than something each driver author discovers on their own.

macOS has a second, quieter trap: Finder sends filenames in decomposed Unicode
(NFD), so a driver whose keys are NFC strings stores names it can never look up
again. Normalize at the session boundary, or document that keys are bytes.

---

## Testing

The native surface is ~150 lines doing one handshake. Everything above it is
bytes in, bytes out — and bytes are testable anywhere. Three tiers, by what they
need from the machine.

### Tier 0 — no kernel. Plain `node --test`, any runner, including macOS/Windows

- **Codec round-trips.** All ~45 structs, `decode(encode(x)) ≍ x`, property
  tested over generated messages, plus golden byte fixtures for wire-format
  regressions.
- **A synthetic kernel.** This falls out of the protocol being symmetric: you
  already have encoders for everything the kernel sends and decoders for
  everything it receives, so the *other side* is a few hundred lines. That drives
  the full session layer — `LOOKUP`/`OPEN`/`READ`/`WRITE`/`FORGET` sequences —
  with no `/dev/fuse` anywhere. It is where the real bugs are reachable: FORGET
  refcounting, rename subtree remap, unlink-while-open, handle reuse.
- **Record → replay.** A `unimount record` mode dumps live `/dev/fuse` traffic
  during a real mount (`ls -l`, `git status`, `tar -x`, `pjdfstest`). Commit the
  transcripts, replay them in CI. Real kernel behaviour — including the
  sequences nobody would think to write by hand — as a deterministic fixture.
  Generated, not authored, which is the difference between full opcode coverage
  and the twelve opcodes someone felt like typing.
- **Differential against `node:fs`.** A passthrough driver over a temp dir; run
  an operation sequence against it and against real `node:fs`, diff the results.
  A free oracle, and it catches the path↔inode bugs nothing else does.
- **Fuzz the decoder.** Random bytes in; assert no exception escapes and every
  request gets exactly one reply. The exactly-once invariant deserves a
  dedicated assertion harness — a missed reply is an unkillable `D`-state
  process, the worst failure mode in the system, and the cheapest to test for.
- **A loopback harness** feeding synthetic requests straight to a driver, so
  driver authors test their own logic with no mount at all. This is the feature
  that makes the library adoptable.

### Tier 1 — NFS and WebDAV, fully conformance-tested unprivileged

Both transports have userspace clients, so nothing is ever mounted:

- **WebDAV** — `litmus` is the standard conformance suite and runs against a URL
  as a normal user. Or drive it with `fetch` directly.
- **NFSv3** — `libnfs` ships `nfs-ls` / `nfs-cp` / `nfs-io`, which speak NFS over
  TCP with no mount and no root. And since the XDR codecs already exist from
  writing the server, the client can be written in JS too — the same symmetry
  trick as the synthetic kernel.

Worth noting because it inverts the usual assumption: these two are the
*easiest* transports to get under test, not the hardest.

### Tier 2 — real mounts, which are ordinary CI jobs

Because root-mode FUSE is pure JS (above) and GitHub Actions Linux runners give
passwordless sudo, `pjdfstest` and the `xfstests` generic group against a real
mountpoint need no native artifact and no self-hosted runner. rclone and
gocryptfs already run FUSE integration tests on stock GHA runners, so
`/dev/fuse` availability there is well-trodden. Locally, a container with
`--cap-add SYS_ADMIN --device /dev/fuse`.

The stub itself gets exactly one integration test: build it with `zig cc` in CI,
assert fd 3 is a working `/dev/fuse`. Everything downstream of that fd is
already covered by tiers 0–2, so the native surface under test is a single
smoke test, not a matrix.

### The organizing idea

Write **one conformance suite against the driver interface** and run it four
ways: direct loopback, WebDAV, NFS, FUSE. The driver never learns which
transport it is under, so any divergence between the four columns is by
definition a transport bug. That matrix is the strongest available evidence that
the central abstraction claim is true — and it reports honestly which
capabilities each transport actually loses, instead of a README table written
from guesses.

---

## Prior art

`fuse-native` (Holepunch), `@cocalc/fuse-native`, `node-fuse-bindings` — all
bind libfuse's *high-level* C API. They inherit libfuse's threading model,
cannot expose low-level notifies, keep the protocol untestable in JS, and are
effectively unmaintained because of the prebuild treadmill.

A pure-JS protocol implementation behind a minimal, ABI-stable stub — with
alternate transports for the platforms FUSE can't reach — is a real gap.

---

## Forward-looking

Not v1, but worth not designing against:

- **FUSE over io_uring** (Linux 6.14) replaces the read/reply loop with a shared
  ring. It would obsolete the entire threadpool discussion above. The transport
  layer should be swappable so this is one file, not a rewrite.
- **`FUSE_PASSTHROUGH`** (Linux 6.9) lets the kernel bypass the daemon entirely
  for read/write on a backing fd — relevant for overlay-shaped drivers, where it
  turns a JS filesystem into a zero-overhead one for the hot path.

---

## Open questions

- **Snapshot granularity for `unfs`.** Every write is a new snapshot, and the
  kernel issues many small offset writes. Snapshot per write is absurd; snapshot
  per `release`/`fsync` loses data on crash; batching by time is arbitrary. And
  `FUSE_CAP_WRITEBACK_CACHE` — the single biggest perf win — makes the arrival
  of writes nondeterministic, which makes any policy harder. This is the most
  interesting unresolved problem in the whole design and it's specific to the
  flagship driver. The least-bad direction so far: treat `fsync` and `release`
  as the durable snapshot boundaries, absorb the kernel's small writes between
  them in an `unfs` write batch, cap crash loss with a time/size bound — and
  leave writeback cache off until that policy survives the differential suite.
  A direction, not an answer.
- **Multi-worker driver contract.** Is "thread-safe" a capability flag, or does
  the library serialize per-inode and expose parallelism only as a tuning knob?
  Getting this wrong once means a data race in someone else's driver.
- **xattr.** `node:fs` has no API for it, macOS depends on it heavily, SELinux
  depends on it on Linux. Extension namespace, or `ENOTSUP` and accept the
  fallout?
- **Windows.** Is WebDAV genuinely adequate, or is WinFsp table stakes for
  anyone who'd use this on Windows at all? Answer with users, not guesses.

---

## Naming

`unimount` — "universal mount", following `unimport` and `unifont`. The `uni-`
prefix is load-bearing: bare `un-` inverts verbs, and every filesystem verb is
its own antonym (`unmount`, `unlink`, `unshare`, `unexport`, `unfuse` are all
real inverse operations). `uni-` parses first, so the name reads as *universal
mounting* rather than *unmounting*. It also survives adding WinFsp or SMB later,
which `unfuse` would not. Free on npm as of this writing.
