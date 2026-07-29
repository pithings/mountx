# proot-style exec: three spikes, measured

Question asked (2026-07-29): can mountx give a subprocess access to an
`FsDriver` **without a real kernel mount** — a `proot`-shaped `exec()` that
injects `LD_PRELOAD`, or any other universal syscall-inspection route?

Answer: yes, two different ways, and they are not close in quality. This file
records what was built, what was measured, and what should happen next.

**Status (2026-07-29): the recommendation at the bottom was carried out.**
Both surviving mechanisms ship behind one picker at `mountx/exec` — see the
roadmap's "Shipped since v1" entry, `docs/2.transports/6.exec.md` for the
user-facing page, and `AGENTS.md`'s code map for the file-by-file account.
`LD_PRELOAD` was dropped as recommended and is reachable from nothing that
ships. Neither mechanism has a conformance-matrix column, and nothing is
wired into `mountx/auto` — deliberately, since `auto`'s contract is a
mountpoint and this produces none. The measurements below are unchanged and
are what the decision rests on.

## The structural finding

**An interceptor does not need a filesystem. It needs a client.**

Both no-mount spikes translate one intercepted operation into one or two 9P
messages against an unmodified `createP9Server()` — the same server
`mount9p()` points the kernel's v9fs client at. Path resolution, handle
lifetimes, directory paging, error mapping and every conformance question stay
in `src/9p/session.ts`. The native side is a wire adapter with an fd table and
no filesystem logic at all, which is why `src/exec/preload/p9.zig` is shared
verbatim between spike B and spike C.

This is what makes the approach tractable. A `proot` that had to _be_ a
filesystem would be a second implementation of everything this repository
already tests.

## What was built

|     | file                                       | what it is                                                             | today                          |
| --- | ------------------------------------------ | ---------------------------------------------------------------------- | ------------------------------ |
| A   | `src/exec/userns.ts`, `userns-relay.ts`    | FUSE inside an unprivileged user namespace, driver stays in the parent | ships, first choice            |
| B   | `src/exec/preload.ts`, `preload/shim.zig`  | `LD_PRELOAD` libc interposer → 9P                                      | **rejected**, kept as evidence |
| C   | `src/exec/seccomp.ts`, `seccomp/trace.zig` | seccomp user-notification supervisor → 9P                              | ships, second choice           |
| —   | `src/exec/preload/p9.zig`                  | the 9P2000.L client both B and C are built on                          | shared verbatim                |
| —   | `test/exec/probe.c`, `probe-raw.c`         | one workload, three linkages                                           | the spike harness              |
| —   | `test/exec/compare.sh`                     | builds everything and runs the matrix                                  | the spike harness              |

## Measured results

Host: Linux 6.12.96 (Debian 13) x86-64, glibc 2.43, zig 0.16, unprivileged user
namespaces available, **no `fusermount3` installed**, no root used anywhere.

One workload (`test/exec/probe.c`) built three ways, each reading a 44-byte
file, stat-ing and reading a 3 MiB file whole, and listing a directory. "pass"
means the FNV checksum over the 3 MiB matched byte for byte.

|                      | dynamic glibc | static musl | raw syscalls (the Go case) |
| -------------------- | ------------- | ----------- | -------------------------- |
| **A** userns + FUSE  | pass          | pass        | pass                       |
| **B** `LD_PRELOAD`   | pass          | **fail**    | **fail**                   |
| **C** seccomp notify | pass          | pass        | pass                       |

Coreutils workload (`ls`, `cat`, `sha256sum`, `wc`, `tail`, `find`, `du`,
`cp -r`) on the dynamic-glibc case all three claim:

|     | sha256  | `wc -l < file` | `find -type f` | `du -s` |
| --- | ------- | -------------- | -------------- | ------- |
| A   | correct | 100            | 5              | 3082    |
| B   | correct | **0**          | 5              | 3082    |
| C   | correct | 100            | 5              | 3082    |

That `0` is spike B's structural defect and is discussed below.

Artifact sizes, `ReleaseSmall`: shim 153 KB, supervisor 154 KB. Both are
dominated by Zig's formatting machinery pulled in through `std.fmt` and would
shrink a lot under the same discipline `native/src/main.zig` already follows
(no allocation, no strings, no std).

## Spike A — FUSE in a user namespace

Not a "no kernel mount" answer, and included anyway because it is the honest
baseline: what the child sees _is_ FUSE, with the kernel's VFS in front of it,
so it inherits the entire conformance column the FUSE transport already
passes. It also ran the static and raw-syscall binaries without a line of
special handling, because nothing about it depends on what the child is linked
against.

It is a mount, but a mount **nobody outside the process tree can see** —
`/proc/self/mounts` on the host stays empty, and the mount dies with the
namespace. The roadmap ruled a user-namespace mode out when the goal was
"mount a directory for the machine"; for an `exec()`-shaped API the tradeoff
inverts, and invisible is the point.

Four things it cost, all witnessed — the first three during the spike, the
last one while productionising it:

- **Node can never enter the namespace.** `unshare(CLONE_NEWUSER)` requires a
  single-threaded caller and Node is never single-threaded; `setns(2)` has the
  same rule. So the namespace is entered by a child, `/dev/fuse` is opened
  there, and the traffic comes back out over a unix socket to a `FuseSession`
  in the parent. That relay is not a workaround for the spike — it is the shape
  any version of this must take, and it is the "relay mode" the roadmap defers,
  arrived at from the other direction.
- **The relay deadlocks if it spawns into its own mount.** Setting the child's
  `cwd` to the mountpoint wedged the relay in `D` state at `fuse_get_req`
  permanently: `uv_spawn` blocks the calling thread until the child execs, and
  the child's first act was a `chdir` that only that thread could answer. Same
  hazard `src/fuse/mount.ts` and `src/9p/mount.ts` both document, met from the
  inside. Fixed by passing the mountpoint as `$MOUNTX_ROOT` so the `cd` happens
  after the exec.
- **A killed parent orphans a wedged mount.** Handled by having the relay exit
  when the socket closes.
- **`default_permissions` makes the mount read-only by accident.** Found while
  productionising A (2026-07-29), not during the spike, because the spike's
  workload never wrote. The option asks the _kernel_ to check the driver's
  `uid`/`gid`/`mode` against the caller's credentials, and inside the namespace
  those are not the same identity space: `unshare -r` maps exactly one uid, so
  a driver reporting the serving process's real uid reports an identity the
  namespace renders as `nobody`, and a `nobody`-owned `0755` root directory
  refuses every write from the one process meant to have it. Namespace-root's
  `CAP_DAC_OVERRIDE` does not rescue it either — that capability does not reach
  a file owned by an unmapped uid. It is no longer the default; permission
  checking stays with the driver, and the mount carries no `allow_other`, so
  the only process that can reach it is the one it was created for.

Also worth recording, because it changes what `mountx/auto` could do on this
class of host: **this host has no `fusermount3` at all**, so today's rootless
FUSE path cannot run here — yet inside `unshare -Urm` the process is uid 0 with
`CAP_SYS_ADMIN`, `/dev/fuse` is 0666, and the ordinary root mount path works
verbatim with no helper and no native addon.

## Spike B — `LD_PRELOAD`

Works, and should not be shipped. **The code has since been removed from the
branch** (`src/exec/preload.ts`, `preload/shim.zig`, `demo-preload.ts`); what
follows is why, and it is kept because the reasoning is what justifies the
shape of the two mechanisms that remain. The 9P client it shared with the
seccomp supervisor stayed and now lives at `src/exec/seccomp/p9.zig`.

It reached a genuinely useful level of function — `ls -la`, `cat`, `grep`,
`tail`, `sha256sum`, `find`, `du` and a full `cp -r` of the tree all behave —
across 49 exported symbols. Getting there took seven distinct discoveries, and
the pattern they form is the finding:

1. **`statx` is load-bearing.** glibc 2.33+ routes the public `stat()` to
   `statx` _internally_, without a PLT hop, so interposing `stat` and `fstatat`
   catches nothing. A shim without `statx` serves `cat` and is invisible to
   `ls`.
2. **stdio bypasses `read` entirely.** `sha256sum` imports `fopen`, not `open`.
   Bridging it the obvious way — this shim's `open`, then the real `fdopen` —
   _appears_ to work and is silently wrong: glibc's `FILE` machinery reads the
   descriptor through an internal read the shim never sees, so `sha256sum` on a
   3 MiB file returned **the hash of the empty string, exit status 0**. The fix
   is to slurp the file into a `memfd` at `fopen` time, which costs the whole
   file in memory and cannot write back.
3. **Fortified variants are separate symbols.** `tail -2` printed nothing and
   exited 0 because it imports `__read_chk`. `-D_FORTIFY_SOURCE=2` is the
   default on Debian, Fedora and Ubuntu.
4. **`fdopendir` is where `find` dies** — "Not a directory" on a path the shim
   had just listed.
5. **`*at()` resolution is needed in three places.** `openat`, `fstatat` _and_
   `statx` each need the relative-against-our-dirfd branch, and missing any one
   fails differently. Modern coreutils reach `statx`, so with that one missing,
   `find` and `du` reported ENOTDIR for every entry of a directory they had
   just enumerated correctly.
6. **`dup` breaks descriptor identity.** `fts` duplicates the directory fd
   before walking it, and the duplicate was a real `dup` of the shim's
   `/dev/null` placeholder. Handling it means giving the duplicate its own fid,
   which **diverges from POSIX**: a real `dup` shares the file offset, this one
   does not.
7. **`getxattr` must be answered** or `ls -l` prints every mode string with a
   trailing `?`.

So the surface is not "the POSIX names". It is those names crossed with the
`64` suffix, the `__*_chk` suffix, and the legacy `__xstat` versioned symbols —
with the landing site decided by the glibc a program was _compiled_ against.
That is a maintenance surface that grows with other people's releases.

**And one hole cannot be closed at all.** A descriptor the shim created does not
survive `exec`: the fd number is inherited but the shim's table lives in
process memory that `exec` discards. So a shell redirection into the virtual
tree silently yields an empty file — `wc -l < /mountx/numbers.txt` returns `0`
where the other two return `100`. There is no symbol to interpose that fixes
this; the state would have to live outside the process, which is what spike C
does by construction.

Every one of spike B's worst failures is a **silent wrong answer**, not an
error. For a filesystem library that is the wrong failure mode to design in.

## Spike C — seccomp user notification

The mechanism that actually answers the question.

A BPF filter traps eight syscalls and everything else runs natively without
leaving the kernel. Because the boundary is the syscall ABI, the traced program's
linkage is invisible: the static musl binary and the no-libc raw-syscall
binary — neither of which spike B can see at all — pass byte-exact.

One structural nicety: **no descriptor is passed anywhere.** The usual shape of
this forks, has the child install the filter, and hands the listener fd back
over `SCM_RIGHTS` — the exact `recvmsg` dance that needed a native addon for
`fusermount3`. A seccomp filter is inherited across fork and exec, so the
supervisor installs the filter on _itself_, keeps the listener, and forks. The
price is a rule the file must keep: after installing, the supervisor may never
make a trapped syscall itself, or it suspends waiting for a reply only it can
send. Violating that (an `open("/dev/null")` inside the openat handler) hung
everything the first time anything opened a directory.

What the spike also measured:

- **`fstat` is its own syscall number**, and glibc's `opendir` uses it to check
  what it just opened. Untrapped, `opendir` saw the placeholder's real type and
  answered ENOTDIR.
- **musl uses the legacy `open`(2)/`stat`(4)/`lstat`(6)**, not the `*at`
  forms — so even a syscall boundary has more than one door per operation. The
  difference from spike B is that this set is finite and fixed by the kernel
  ABI rather than growing with each libc release.
- **`dup` is solvable here, unlike in spike B.** Every injected descriptor is a
  `memfd` with a unique name, so `/proc/<pid>/fd/<n>` identifies it as
  `/memfd:mx-<serial>` for the original and every duplicate alike. No trapping
  of `dup` required, and it survives `exec` and `fork` for free.
- **Not trapping `close` costs correctness, not just memory.** Descriptor
  numbers get reused immediately, and a stale mapping shadowed a live one:
  `fstat` on a freshly opened file returned the _directory_ that previously
  held that number, and `cp -r` correctly concluded the file had been replaced
  underneath it. Fixed by evicting on reuse; the underlying fid leak stays until
  a supervisor exists that does not share a filter with its tracee.
- **`stat` and `statx` must agree on `st_dev`.** `statx` reports a major/minor
  pair that glibc recomposes with `makedev()`; a minor over 255 does not
  round-trip, so the two forms disagreed and `cp` again reported a replaced
  file. Both spikes now use a minor under 256. (Spike B had the same latent
  bug and was fixed alongside.)

Costs as first spiked, and what became of each:

- ~~A file open copies the whole file into a `memfd`.~~ **Closed.** I/O is
  streamed per open-file-description now — `read`/`pread64`/`readv` and the
  `write` family and `lseek` are all trapped, with an offset that `dup` shares
  — and no copy is made. The one thing the `memfd` bought and streaming cannot
  is `mmap` of a file on the tree, which now answers `ENODEV` rather than
  silently mapping a stale copy.
- ~~Read-only as spiked.~~ **Closed, and this was the important one.** The
  read-only version did not fail cleanly: `memfd`s are always writable and
  `write` was untrapped, so a program's writes landed in the in-memory copy and
  vanished. Measured at the time: `dd conv=notrunc` reported success and left
  the file unchanged; `rm -f` reported success and left the file in place. That
  is the same silent-wrong-answer failure class this document rejects spike B
  for, and it is why `test/exec/compare.sh` grew a write-back row that asserts
  against the driver rather than against an exit status.
- **x86-64 only**, since the filter compares against one syscall table. arm64 is
  a second table, not a redesign.
- **Still one notification at a time**, tag always zero, one 9P request in
  flight. Multi-threaded and multi-process tracees are correct — the tables are
  keyed on the thread group behind `seccomp_notif.pid`, which is a _thread_ id,
  and they grow — but they serialize.
- **`execve` of a binary living on the tree is not supported** and was never in
  scope; it fails at 127 rather than hanging.

## Portability: what each one actually needs on a bare system

Asked directly (2026-07-29): does spike A work on a bare Alpine system with no
kernel modules and no extra shared libraries? Tested in `podman` against
`alpine:latest` and `node:24-alpine`, busybox-only, no `util-linux`, no
`fuse3`, no `fusermount3`.

**Userland: nothing extra needed, after one fix.** busybox provides both
`unshare` and `mount` applets, and spike A needs no native addon at all. The
one incompatibility found: busybox 1.37's `unshare` has `-r` but **no
`--map-root-user`**, so the long spelling fails outright. `src/exec/userns.ts`
now spawns `-U -r -m --propagation private`, which util-linux and busybox both
accept.

**Privileges: none.** Verified with `--cap-drop=ALL --user 1000:1000`, no
`--privileged`: the tree mounts and reads back byte-exact.

**Kernel: yes, and it is not avoidable.** Spike A _is_ FUSE, so it needs the
host kernel's `CONFIG_FUSE_FS` and a working `/dev/fuse` node.

- `alpine:latest` has **no `/dev/fuse`**, and spike A fails there with an
  accurate message rather than anything mysterious.
- A user-namespace root **cannot create it**: `mknod /d/fuse c 10 229` inside
  `unshare -Urm` answers `EPERM`. Verified. So the node has to come from
  outside — `--device /dev/fuse`, or a host that has it.
- With `--device /dev/fuse` supplied it works completely: full listing, 3 MiB
  read, sha256 `bfe74807…` matching every other column.

**Spike C needs none of that.** The same question, same image, **without**
`--device`, `--cap-drop=ALL`, uid 1000, using a statically linked musl build of
the supervisor: full pass, byte-exact, on the no-libc `probe-raw` binary. It
needs `CONFIG_SECCOMP_FILTER`, which is built into every mainstream kernel and
cannot be a module, plus `no_new_privs` — and no device node, no filesystem
driver, and no shared library of any kind.

Two portability fixes came out of building the static musl supervisor, both
real bugs rather than build-system friction:

- **`ioctl` differs between libcs.** glibc's takes `unsigned long`, musl's takes
  `int`, and the `SECCOMP_IOCTL_*` request numbers have the high bit set — so
  the constants do not survive musl's prototype. The supervisor now issues
  `ioctl` as a raw syscall, which takes an unsigned long on every ABI.
- **Reading a path out of another process must respect page boundaries.**
  `process_vm_readv` fails the _entire_ request if any part of the range is
  unmapped, so reading a fixed 64-byte chunk fails whenever the path sits near
  the end of a mapping. This was an intermittent, ASLR-dependent failure:
  `probe-raw` would read two files and then fail to open a directory, because
  that one path was the environment string at the top of the stack. Reads are
  now clamped to the end of the current page. 3/3 on repeat runs after the fix.

### What this changes about the recommendation

It sharpens it rather than reversing it. Spike A remains the cheapest correct
thing on a normal Linux host or any container given `--device /dev/fuse`. But
the environments where "no kernel mount" is _wanted_ — a locked-down container,
a CI runner, an unprivileged sandbox — are exactly the ones that withhold
`/dev/fuse`, and there A cannot be made to work from inside by any means.
Spike C is the only one of the two that runs there.

So: land A for the common case, and treat C as the one that covers the case
that motivated the question in the first place.

## Recommendation

1. **Drop spike B.** It is the most familiar approach and the worst one here.
   Its coverage excludes Go and static binaries by construction, its symbol
   surface tracks other projects' releases, it has a hole (`exec`) that cannot
   be closed from inside the process, and its characteristic failure is a
   confident wrong answer rather than an error. Keep the file as the written-up
   evidence for why, not as a thing to finish.

2. **Land spike A as the near-term `mountx/exec`.** It is nearly free, it is
   _actually FUSE_ so it inherits the existing conformance guarantees whole, it
   covers every binary, and on a host like this one it is the only FUSE route
   that works at all. Scope it honestly: Linux with unprivileged user
   namespaces, and say plainly that it is a namespace-private kernel mount
   rather than no mount.

3. **Pursue spike C as the real no-mount transport.** ~~Next milestone:
   streaming rather than slurping, plus a supervisor that can trap `close`.~~
   **Both done.** I/O streams per descriptor, and `close` is trapped, which
   required exactly the predicted change — the supervisor no longer shares its
   filter with the tracee; the child installs it and passes the listener back
   over `SCM_RIGHTS`, reusing `native/src/main.zig`'s cmsg transcription. It
   carries the full conformance column (`test/exec/seccomp-conformance.test.ts`,
   65 of 66 cases, the one skip being the root-only `lchown` case every column
   skips). What is left is concurrent dispatch, `mmap`, `execve` off the tree,
   and arm64.

4. **Keep `p9.zig` as the shared asset** whichever way this goes. It is the part
   that made both spikes small, and it is the reason neither one contains a
   filesystem.

5. **macOS gets nothing from any of this.** No user namespaces, no seccomp, and
   SIP blocks `DYLD_INSERT_LIBRARIES` for system binaries. macOS stays NFS-mount
   territory.

## Reproducing

```sh
sh test/exec/compare.sh              # builds all three, runs the matrix, no root
node src/exec/demo-userns.ts  <cmd>  # userns + FUSE
MOUNTX_SHIM=…  node src/exec/demo-preload.ts <cmd>
MOUNTX_TRACE=… node src/exec/demo-seccomp.ts <cmd>
MOUNTX_TRACE_DEBUG=1                 # per-syscall tracing for the supervisor
```

The runners were `spike-a.ts`/`spike-b.ts`/`spike-c.ts` when the measurements
below were taken; all three are now named after their mechanisms.

The command sees the driver at `$MOUNTX_ROOT`, which all three set.
