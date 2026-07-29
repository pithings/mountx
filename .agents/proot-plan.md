# proot-style exec: what was measured, and what shipped

Question asked (2026-07-29): can mountx give a subprocess access to an
`FsDriver` **without a real kernel mount** — a `proot`-shaped `exec()` that
injects `LD_PRELOAD`, or any other universal syscall-inspection route?

Three mechanisms were built and measured. This file is the trimmed record: what
ships on this branch, why it is shaped the way it is, and where the rest went.

**What ships here: mechanism A**, FUSE inside an unprivileged user namespace,
as `mountx/exec` — see `AGENTS.md`'s code map for the file-by-file account and
`docs/2.transports/6.exec.md` for the user-facing page. It has no
conformance-matrix column and is not wired into `mountx/auto`, both
deliberately: the column would duplicate FUSE's exactly, and `auto`'s contract
is a mountpoint this produces none of.

**What does not ship here.** Mechanism C — a seccomp user-notification
supervisor over an unchanged `createP9Server()` — was built, measured and
found to work in the one environment A cannot serve: a host or container that
withholds `/dev/fuse`. It is **not on this branch**. It lives in the history of
**PR #9 on `pithings/mountx`**, which was closed rather than merged, together
with its own tests, its Zig sources, the three-way comparison harness and the
full autopsy of mechanism B (`LD_PRELOAD`), which was rejected. Read that PR
for any of it.

## The measured comparison

Host: Linux 6.12.96 (Debian 13) x86-64, glibc 2.43, zig 0.16, unprivileged user
namespaces available, **no `fusermount3` installed**, no root used anywhere.

One workload built three ways, each reading a 44-byte file, stat-ing and reading
a 3 MiB file whole, and listing a directory. "pass" means the FNV checksum over
the 3 MiB matched byte for byte.

|                      | dynamic glibc | static musl | raw syscalls (the Go case) |
| -------------------- | ------------- | ----------- | -------------------------- |
| **A** userns + FUSE  | pass          | pass        | pass                       |
| **B** `LD_PRELOAD`   | pass          | **fail**    | **fail**                   |
| **C** seccomp notify | pass          | pass        | pass                       |

The conclusion that decided this branch: **A is the cheapest correct thing on
any host that has `/dev/fuse`, and it is correct for reasons that do not have
to be maintained.** It covers every binary because nothing about it depends on
what the child is linked against; B cannot see a static or Go binary at all,
and its symbol surface tracks other projects' releases. C matches A on
coverage — the boundary is the syscall ABI — and buys the no-device-node case,
at the price of a separately built supervisor binary, x86-64 only, and a
narrower feature set. So A first, and C as the thing that covers what A cannot.

## Why mechanism A is shaped the way it is

Not a "no kernel mount" answer, and included anyway because it is the honest
baseline: what the child sees _is_ FUSE, with the kernel's VFS in front of it,
so it inherits the entire conformance column the FUSE transport already passes.

It is a mount, but a mount **nobody outside the process tree can see** —
`/proc/self/mounts` on the host stays empty, and the mount dies with the
namespace. The roadmap ruled a user-namespace mode out when the goal was "mount
a directory for the machine"; for an `exec()`-shaped API the tradeoff inverts,
and invisible is the point.

Four things it cost, all witnessed — the first three during the spike, the last
one while productionising it. Each is a comment in the code today:

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
  after the exec, and refused up front (`cwdRefusal()`) when asked for anyway.
- **A killed parent orphans a wedged mount.** Handled by having the relay exit
  when the socket closes.
- **`default_permissions` makes the mount read-only by accident.** Found while
  productionising A, not during the spike, because the spike's workload never
  wrote. The option asks the _kernel_ to check the driver's `uid`/`gid`/`mode`
  against the caller's credentials, and inside the namespace those are not the
  same identity space: `unshare -r` maps exactly one uid, so a driver reporting
  the serving process's real uid reports an identity the namespace renders as
  `nobody`, and a `nobody`-owned `0755` root directory refuses every write from
  the one process meant to have it. Namespace-root's `CAP_DAC_OVERRIDE` does
  not rescue it either — that capability does not reach a file owned by an
  unmapped uid. It is no longer the default; permission checking stays with the
  driver, and the mount carries no `allow_other`, so the only process that can
  reach it is the one it was created for.

Also worth recording, because it changes what `mountx/auto` could do on this
class of host: **this host has no `fusermount3` at all**, so today's rootless
FUSE path cannot run here — yet inside `unshare -Urm` the process is uid 0 with
`CAP_SYS_ADMIN`, `/dev/fuse` is 0666, and the ordinary root mount path works
verbatim with no helper and no native addon.

## Portability: what A needs on a bare system

Asked directly (2026-07-29): does it work on a bare Alpine system with no kernel
modules and no extra shared libraries? Tested in `podman` against
`alpine:latest` and `node:24-alpine`, busybox-only, no `util-linux`, no `fuse3`,
no `fusermount3`.

**Userland: nothing extra needed, after one fix.** busybox provides both
`unshare` and `mount` applets, and A needs no native addon at all. The one
incompatibility found: busybox 1.37's `unshare` has `-r` but **no
`--map-root-user`**, so the long spelling fails outright. `src/exec/userns.ts`
spawns `-U -r -m --propagation private`, which util-linux and busybox both
accept.

**Privileges: none.** Verified with `--cap-drop=ALL --user 1000:1000`, no
`--privileged`: the tree mounts and reads back byte-exact.

**Kernel: yes, and it is not avoidable.** A _is_ FUSE, so it needs the host
kernel's `CONFIG_FUSE_FS` and a working `/dev/fuse` node.

- `alpine:latest` has **no `/dev/fuse`**, and A fails there with an accurate
  message rather than anything mysterious.
- A user-namespace root **cannot create it**: `mknod /d/fuse c 10 229` inside
  `unshare -Urm` answers `EPERM`. Verified. So the node has to come from
  outside — `--device /dev/fuse`, or a host that has it.
- With `--device /dev/fuse` supplied it works completely: full listing, 3 MiB
  read, sha256 `bfe74807…` matching every other column.

This is exactly the gap mechanism C was pursued for, and exactly why it is
worth reviving from PR #9 rather than rediscovering: the environments where "no
kernel mount" is _wanted_ — a locked-down container, a CI runner, an
unprivileged sandbox — are the ones that withhold `/dev/fuse`, and there A
cannot be made to work from inside by any means.

## macOS

Nothing from any of this transfers: no user namespaces, no seccomp, and SIP
blocks `DYLD_INSERT_LIBRARIES` for system binaries. macOS stays NFS-mount
territory.

## Reproducing

```sh
node src/exec/demo-userns.ts <cmd>   # the mechanism, against the demo tree
sh test/rootless.sh test/exec/userns.test.ts
```

The command sees the driver at `$MOUNTX_ROOT`.
