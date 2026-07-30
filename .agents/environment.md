# Environment facts (verified 2026-07-27 on this dev host)

- Kernel 6.12, FUSE protocol **7.41** (kernel replied to FUSE_INIT).
  `/dev/fuse` is mode 0666; `fuse` present in `/proc/filesystems`.
- **Pure-JS root-mode mount verified working**: `openSync('/dev/fuse','r+')`
  then `spawnSync('mount', ['-i','-t','fuse','-o', 'fd=N,rootmode=40000,...'])`
  succeeded and the kernel sent FUSE_INIT.
- **Caveat — fd mapping:** the fd from `openSync` is NOT fd 3 (it was 17).
  When spawning `mount`, the child's stdio array must be padded so the fd
  number in `-o fd=N` matches its position: `stdio[N] = fd`. Hardcoding
  fd 3 fails with "wrong fs type".
- **Caveat — teardown:** if FUSE_INIT is never replied to, `umount` hangs
  (D-state). Closing the `/dev/fuse` fd aborts the connection and unblocks.
  Always reply to INIT before anything else; always install teardown.
- **Caveat — teardown after INIT:** for `-t fuse` mounts the kernel NEVER
  sends `FUSE_DESTROY` (that's `fuseblk` only — see `fuse_init_fs_context`
  in fs/fuse/inode.c; verified twice on a live mount: last opcode before a
  clean umount was STATFS). Therefore the transport MUST detect unmount via
  read() returning EOF/ENODEV on /dev/fuse and call `session.destroy()`
  itself — that call is the only thing that closes leftover handles and
  clears the inode table. Keep the read loop alive through umount; if INIT
  was never answered, close the fd to abort the connection.
- `sudo` is passwordless BUT root's PATH lacks node (fnm). Use
  `sudo "$(which node)" script.mjs`. Since node itself runs as root, the
  sudo `closefrom` fd-stripping caveat from IDEA.md does not apply.
- **Leak detection:** `/sys/fs/fuse/connections` is EMPTY on this host until
  fusectl is mounted: `sudo mount -t fusectl none /sys/fs/fuse/connections`.
  Without it, only `/proc/self/mounts` shows leaks.
- **Wedge recovery (verified):**
  - `umount -l` alone does NOT unwedge a mount with in-flight requests.
  - Closing the /dev/fuse fd aborts the connection ONLY when no reads are
    parked on it — a threadpool-parked read(2) holds the file reference,
    so fuse_dev_release never runs and the mount stays wedged.
  - What always works: `umount -f` → fuse_umount_begin → fuse_abort_conn
    (fails all in-flight requests, parked reads return ENODEV). Its exit
    status lies when racing another umount — trust /proc/self/mounts.
  - With fusectl mounted, `echo 1 > /sys/fs/fuse/connections/<N>/abort`
    also unwedges (process resumes with ENOTCONN).
  - After `kill -9` (no parked-read holder left), a PLAIN `umount` clears
    the stale entry.
- **`fusermount3` is installed** (`dnf install fuse3`, fuse3-3.18.2, verified
  2026-07-28). It is `-rwsr-xr-x root root`, `/` is not `nosuid`, and the
  container's `CapBnd` includes `cap_sys_admin` + `cap_setuid` — all three are
  needed for a setuid helper to actually be able to mount, and a container
  missing any of them would fail in a confusing way. **Unprivileged mounting
  works here**: `pnpm test:rootless` mounts, uses and unmounts as `dev`.
  Tier-2 FUSE suites other than `mount-rootless.test.ts` still need sudo.
- `/etc/fuse.conf` exists with `user_allow_other` **commented out** (the
  distribution default), so `{ allowOther: true }` is refused for unprivileged
  mounts. That refusal is asserted by the rootless suite, which skips the
  assertion if a host has enabled the line.
- **Rootless leak recovery:** `fusermount3 -u <mnt>`, or `-u -z` for the
  detach-now form. `umount -f` and `/sys/fs/fuse/connections/<n>/abort` are
  root-only, so a wedged unprivileged mount has no equivalent of the abort —
  after a `kill -9` (no parked-read holder left) a plain `fusermount3 -u`
  clears it.
- Toolchain: Node v24.18.0, pnpm 11.17.0, zig 0.16.0 (via zvm) + gcc/clang.
  Zig 0.16 notes for `native/build.zig`: the errno helper is
  `std.os.linux.errno(rc)`, not `E.init(rc)`; and passing
  `preferred_optimize_mode` to `standardOptimizeOption` swaps `-Doptimize` for
  a `-Drelease` bool, which is why the build hardcodes `ReleaseSmall` instead.
  Node ships no headers in an fnm install, hence the transcribed
  `native/src/napi.zig`.
- Tests: vitest. Lint/format: oxlint + oxfmt. Build: obuild.
  Typecheck: `tsgo --noEmit --skipLibCheck`. Run `pnpm test` before commits.
- **No NFS client on this host:** no `mount.nfs`/`mount.nfs4` anywhere on
  `PATH` or in `/sbin`, no `nfs` line in `/proc/filesystems`, `/lib/modules`
  is an empty symlink to /usr/lib/modules and there is no `modprobe` — so
  the kernel NFS client cannot be loaded even as root. NOTE: this is Fedora
  44 — package manager is `dnf` (with network access), NOT apt.
  libnfs/libnfs-utils/wireshark-cli/gdb are installed; libnfs's
  nfs-ls/nfs-cp are userspace NFSv3 clients usable as independent oracles
  (caveat: getlogin() segfaults in this container — LD_PRELOAD a shim
  returning a name). `rpcbind` and
  `nfsstat` are absent too. The NFS _server_ (`mountx/nfs`) is unaffected: it
  is pure JS over a TCP socket and its Tier-0/Tier-1 suites need nothing. Only
  `pnpm test:nfs:mount` (Tier 2) is affected, and it skips itself on
  `nfsClientProbe()`. On a host with `nfs-common`/`nfs-utils` installed it
  should run as-is.
  **Use libnfs whenever the wire format changes**: it shares none of our
  codecs, which is exactly what the Tier-1 JS client — built from the server's
  own codecs — cannot give. `tshark` dissects the exchange to confirm.

## 9P mounting (verified 2026-07-29, this Linux host)

Kernel `6.12.96+deb13-amd64` (Debian 13). `9p` is in `/proc/filesystems`, and
`/sys/module` has `9p`, `9pnet`, `9pnet_fd` and `9pnet_virtio` — `9pnet_fd` is
the one `trans=unix`/`tcp`/`fd` live in, and it is pinned by
`/etc/modules-load.d/9p.conf`, so nothing depends on `mount(8)` autoloading it.
`pnpm test:9p:mount` **passes** as root: 9 passed, 2 skipped, ~0.8 s.

- **The mount that works**, verbatim (`mount9p()` builds it):

  ```sh
  mount -i -t 9p -o trans=unix,version=9p2000.L,msize=131096,access=client,\
  cache=none,uname=nobody,aname=/ -- /tmp/mountx-9p-XXXXXX/9p.sock /mnt/point
  ```

  and the line it leaves in `/proc/self/mounts`:

  ```
  /tmp/mountx-9p-XXXXXX/9p.sock /tmp/mountx-9p-mnt-XXXXXX 9p rw,relatime,aname=/,access=client,trans=unix 0 0
  ```

- **`msize` is invisible in the mount table at the default, and that absence is
  the proof it landed.** `p9_show_client_options()` prints `msize=` only when it
  differs from `DEFAULT_MSIZE` — which is `(128 * 1024) + P9_IOHDRSZ` = **131096**,
  character for character what this transport asks for. Mounting with
  `{ mountMsize: 16384 }` makes `msize=16384` appear in the same line, and
  `connection.session.msize` agreed to both (131096 and 16384). Same rule
  elsewhere in that line: `uname=nobody` is omitted because it _is_ `V9FS_DEFUSER`,
  while `aname=/` is printed because `V9FS_DEFANAME` is the empty string.
- **There is no `dmesg` on this host.** `kernel.dmesg_restrict=1`, the container's
  `CapBnd` has no `CAP_SYSLOG`, and there is no `/dev/kmsg`; `sudo dmesg` answers
  `Operation not permitted`. So the usual "read what v9fs logged" route does not
  exist here. What replaces it, and is better: `connection.session.version` /
  `.msize` (the server's own view of the negotiation — witnessed `9P2000.L` and
  131096), the mount-table line above, and an **opcode census** taken by shadowing
  `connection.session.handleCall` on the live mount.
- **What v9fs actually sends.** One full workload (3 MiB file, metadata, links,
  a 1500-entry directory, locks, removal):

  ```
  Twalk=9073 Tclunk=7562 Tgetattr=6062 Twrite=1530 Txattrwalk=1513 Tlcreate=1505
  Tunlinkat=1504 Tread=30 Tlopen=13 Treaddir=13 Tlock=8 Tsetattr=3 Tfsync=3
  Treadlink=2 Tstatfs=2 Tlink=1 Tsymlink=1 Trenameat=1 Tmkdir=1 Tgetlock=1
  ```

  Three things to keep from that. No legacy 9P2000 opcode ever arrives, so the
  `Topen`/`Tcreate`/`Tstat`/`Twstat` → `ENOTSUP` path is unreachable from a real
  client. There is **one `Txattrwalk` per created file** (1513 against 1505
  `Tlcreate`) — the `security.*` probe, exactly as hot as the plan assumed, which
  is why its refusal is kept cheap. And walk/clunk dominate everything: v9fs
  clones a fid per operation, so `FidTable` is the hot data structure, not the
  codec.

- **`access=client` is enforced by the client, and costs one `Tattach` per uid.**
  A file `0600 root:root` is `Permission denied` to uid 1000 through the mount and
  readable at `0644`; the first access by a new uid produced a fresh `Tattach`
  (`v9fs_fid_lookup` attaches per `fsuid` under `V9FS_ACCESS_CLIENT`).
- **Locks work and always grant**, per the transport's decision. `flock -x -w 5`
  exits 0; Python `fcntl.lockf` `LOCK_EX`/`LOCK_UN`/`LOCK_SH` all succeed;
  `F_GETLK` reports `F_UNLCK` (2). The kernel really puts them on the wire — 8
  `Tlock` and 1 `Tgetlock` for that shape — so this is the server answering, not
  the client keeping it local.
- **`statfs` passes the driver's `f_type` through verbatim.** `v9fs_statfs()`
  assigns `buf->f_type = rs.type`, so `stat -f` prints whatever the driver
  declares: the memory driver's `TMPFS_MAGIC` (`0x01021994`) makes it say
  `Type: tmpfs`. Not a bug, but do not read it as "9P is not mounted".
- **Witnessed by hand, all passing**: a 3 MiB write/read byte-exact through a
  131096 `msize` (and 1 MiB through a 16384 one, so it really pages), the same
  bytes on the driver side; `chmod`/`chown`/`utimes`; `st_ino` stable across
  stats, distinct per file, matching through `fstat` and shared by a hardlink
  (v9fs derives it from `qid.path` via `QID2INO`); `nlink` 2 then 1;
  symlink/`readlink`/`lstat`/read-through; rename with an open fd, and read+write
  through that fd afterwards; **unlink-while-open** then read, write, `fstat` and
  `fsync` through the fd — the stateful-9P claim, and the reason 9P beats NFS
  when both need root; `fsync`/`fdatasync` and `sync -f`; a 1500-entry directory
  with 200-byte names (~360 KB of dirents, ~3 `Treaddir` pages) listed complete
  and duplicate-free by both `readdir` and `ls -1`; `.` and `..` (the server
  synthesizes them — `v9fs_dir_readdir_dotl` never calls `dir_emit_dots`) and
  `cd ..` out of the mount; `ENOENT`/`ENOTDIR`/`ENOTEMPTY`/`EISDIR`/`EEXIST`/
  `ENAMETOOLONG`; `O_APPEND`, `O_TRUNC`, rename-over and cross-directory rename;
  255-byte and UTF-8 names; executing a binary copied onto the mount (`cache=none`
  gives read-only `mmap`, which is enough); 24 concurrent 512 KiB write+read
  round-trips and 16 concurrent `pread()`s, all byte-exact.
- **Teardown is uneventful.** Plain `umount` every time, table clear afterwards,
  the private socket directory removed with it; three mount/unmount rounds leave
  nothing in `/proc/self/mounts`. Somebody else's `umount` resolves
  `connection.closed`, flips `mount.active` to `false`, drops
  `server.connections` to 0, and a following `unmount()` is a no-op.
- **A killed server does not wedge anything** — the opposite of FUSE. `SIGKILL`
  the serving process and the mount stays in the table, but the first access
  fails `ECONNRESET` and every one after it `EIO`, _immediately_, with no
  timeout to wait out; a **plain `umount` then clears it**. Nothing needs
  forcing. The one leak is the `mkdtemp` socket directory: there is no process
  left to remove it, so `/tmp/mountx-9p-*` wants a `sudo rm -rf` after a kill.
- **The one real wedge is self-inflicted: spawning a binary that lives on the
  mount, from the process serving it.** `uv_spawn` holds the parent's main thread
  until the child execs, and the child parks in
  `p9_client_rpc ← p9_client_walk ← v9fs_vfs_atomic_open_dotl ← do_open_execat`
  waiting for the thread it is blocking. `umount -f` answers `target is busy`,
  and killing the _server_ does not help — `fork` gave the child a copy of the
  server socket, so the connection outlives the server process. What works:
  `kill -9` on the parked child (`p9_client_rpc` is a `wait_event_killable`, so
  `D` state does die), then a plain `umount`. Same class as the `spawn(…, { cwd })`
  hazard already documented, and both are avoided by letting `sh -c` do the exec.

## VM guests (verified 2026-07-29, this Linux host)

QEMU `10.2.2` (`qemu-system-x86-core`, installed via dnf). The guest was the
stock **Alpine 3.21.3 `virt` ISO**, kernel `6.12.13-0-virt`, booted with
`-nographic` — it reaches a serial login on `/dev/ttyS0` in under 90 s and needs
no extraction or custom initramfs, so the whole thing is scriptable by driving
the console. `test/…` has no VM tier; the harnesses used here live only in the
session scratchpad, and this section is the record.

- **`/dev/kvm` is not reachable as `dev`** (mode `0660`, group `993`, which this
  uid is not in), so QEMU was run under `sudo`. Nothing about the demo needs
  root on a normal desktop, where the user is in the `kvm` group — this is a
  container artefact, not a property of the recipe.
- **QEMU needs no tap at all**, which is why it was the first column: its
  user-mode networking is pure userspace. `/dev/net/tun` was absent when that
  work was done and has since been added to the container; `CAP_NET_ADMIN` still
  is **not**, so tap creation needs the user-namespace route described under
  Firecracker below.
- **QEMU's slirp routes `10.0.2.2` to the host's loopback**, so a server left on
  its default `127.0.0.1` bind is reachable from the guest with **no
  `allowRemote`, no tap, no bridge and no host-side `ip` command**. Verified for
  both transports below. The guest's own address is `10.0.2.15/24`; the host is
  on-link, so **no default route is needed for the mount** — `ip addr add
10.0.2.15/24 dev eth0 && ip link set eth0 up` is the whole client-side network
  setup, and was verified as the minimal sequence.
- **9P over `trans=tcp` works with three options and no `modprobe`.**
  `mount -t 9p -o trans=tcp,port=5640,version=9p2000.L 10.0.2.2 /mnt/x` succeeds
  — `mount(8)` autoloads `v9fs`/`9pnet_fd` — and leaves

  ```
  10.0.2.2 /mnt/x 9p rw,relatime,access=client,trans=tcp,port=5640 0 0
  ```

  in `/proc/self/mounts`. Note the absent `msize=`, the same proof-by-omission as
  the local mount above; asking for `msize=1048576` makes it appear. Witnessed
  through the mount: `ls`, read, write, `mkdir -p`, 16 MiB `dd` both directions,
  `mv` across directories, `rm`, `df -T` (reports type `9p`) and `umount`.

- **NFSv4.1 is verified against a real Linux kernel client for the first time**,
  which the NFS section of `AGENTS.md` had listed as untested for want of a
  `mount.nfs` on this host — a VM guest supplies one.
  `mount -t nfs4 -o vers=4.1,addr=10.0.2.2,clientaddr=10.0.2.15,port=2049,proto=tcp,sec=sys,hard 10.0.2.2:/ /mnt/x`
  succeeds against `createNfsServer()` on its default loopback bind, and leaves

  ```
  10.0.2.2:/ /mnt/x nfs4 rw,relatime,vers=4.1,rsize=1047672,wsize=1047532,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.0.2.15,local_lock=none,addr=10.0.2.2 0 0
  ```

  Same workload as above passed: `ls`, read, write, `mkdir -p`, 16 MiB `dd`,
  rename, unlink, `umount`. No `rpcbind` and no MOUNT program are involved. This
  is still **not** a test-suite column — no `mount.nfs` exists on the host
  itself, so a Tier-2 v4.1 file would have to carry a VM, which is a bigger
  decision than this note.

- **`node src/…` drives any transport directly, including NFS.** It did not when
  this work was done — Node 24's type stripping refused `src/nfs/v4/state.ts`
  with `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX` over a TS parameter property, so the
  harnesses here imported `dist/nfs/index.mjs` after a `pnpm build`. `fix: keep
every entry point loadable by node's type stripping` has since removed that
  constraint; re-verified after rebasing onto it. A scratch script can import
  `src/` for either transport now.

### Firecracker (verified 2026-07-29, `v1.16.1`)

**A real microVM booted and mounted this server over NFSv4.1.** Guest kernel
`6.1.102` and rootfs `ubuntu-22.04.ext4`, both from
`firecracker-ci/v1.10/x86_64`. The same workload as the QEMU columns passed:
`ls`, read, write, `mkdir -p`, 16 MiB `dd` both directions, rename, unlink and
`umount`, leaving

```
172.20.0.1:/ /mnt/x nfs4 rw,relatime,vers=4.1,rsize=1047672,wsize=1047532,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=172.20.0.2,local_lock=none,addr=172.20.0.1 0 0
```

- **The user namespace is what made it possible without a container restart.**
  `/dev/net/tun` was added to this container, but `CAP_NET_ADMIN` was **not** —
  `capsh --decode` of `CapBnd`/`CapEff` (`00000000a82425fb`) lists `cap_sys_admin`
  and `cap_net_raw` but no `cap_net_admin`, so `ip tuntap add` answers
  `ioctl(TUNSETIFF): Operation not permitted` even under `sudo`. A **new user
  namespace grants a full capability set** (`CapEff: 000001ffffffffff`) over the
  network namespace it owns, so the whole thing runs under

  ```sh
  sudo unshare -Urn --map-root-user node harness.mjs
  ```

  with the tap, the mountx server and Firecracker all inside that one namespace —
  the guest never needs to reach the container's real network at all.
  `--map-root-user` matters: plain `sudo unshare -Urn` maps root to `nobody`,
  which then cannot read anything. Assets must also live outside the session
  scratchpad, whose `/tmp/claude-*` chain is `drwx------ dev` and therefore
  unreadable to the namespace's root; `/var/tmp/mxfc`, root-owned, works.
  `/workspace` and the fnm `node` are already world-readable, so `dist/` is
  reachable as-is.

- **The guest needs no network commands.** An `ip=` kernel boot argument
  (`ip=172.20.0.2::172.20.0.1:255.255.255.0::eth0:off`) configures `eth0` before
  userspace starts.
- **No `mount.nfs`/`mount.nfs4` exists in Firecracker's own root image, and the
  mount works anyway.** `which mount.nfs mount.nfs4` finds nothing, but
  `mount -t nfs4` with `addr=` and `clientaddr=` given explicitly leaves the
  helper nothing to resolve, so `mount(8)` falls through to the `mount(2)`
  syscall. Spelling those two options out is what makes a guest with no NFS
  userland work — worth keeping in the docs, since it is the difference between
  "add nfs-common to your image" and "nothing to install".

The read-only facts below were established before the run and still hold.

- **There is no 9P route into a Firecracker guest, by two independent facts.**
  It emulates only virtio-net/block/vsock (plus balloon and rng) — there is no
  `virtio-9p` device — and both the in-repo `resources/guest_configs/*.config`
  and the config shipped beside the CI kernel binary
  (`firecracker-ci/v1.10/x86_64/vmlinux-6.1.102.config`) carry
  `# CONFIG_NET_9P is not set`.
- **Its kernel does have NFS, and only the v4 half**: `CONFIG_NFS_FS=y`,
  `CONFIG_NFS_V4=y`, `CONFIG_NFS_V4_1=y`, `CONFIG_ROOT_NFS=y`, and
  `# CONFIG_NFS_V3 is not set`. So `mountx/nfs` at `version: "4.1"` is the only
  transport that can reach a stock Firecracker guest, which is what
  `docs/1.guide/5.vms.md` documents.
- **QEMU's own `virtio-9p` cannot be pointed at an external server.** Every
  `-fsdev` backend is directory-based (`-fsdev sock,…` → `fsdriver sock not
found`), so there is no way to hand a mountx socket to `virtio-9p` and TCP is
  genuinely the route, not a fallback.

## pjdfstest's build prerequisite (verified 2026-07-30, this Linux host)

`pnpm test:pjdfstest` clones a project that ships **`configure.ac`, not
`configure`**, so the first run needs autotools — and this image has none of it
until something asks:

- `autoreconf` and `aclocal` are absent from a fresh container; `/usr/local/sbin`
  holds **shims** for `autoconf` and `automake` that install the real package on
  first invocation (Fedora `dnf`: autoconf 2.72, automake 1.18.1). `autoreconf`
  and `autoheader` arrive with autoconf, `aclocal` with automake, both in
  `/usr/sbin`.
- So the whole prerequisite is **invoking the two shims once**, in this order,
  before the harness:

  ```sh
  autoconf --version >/dev/null; automake --version >/dev/null
  ```

  Without them `run.sh` stops at `autoreconf: command not found`, having already
  cloned into `test/pjdfstest/pjdfstest` — which is fine to leave: the clone is
  pinned and gitignored, and a second run picks it up and only builds.

- Everything after the build is already root's (`run.sh` runs `run.ts` under
  `sudo`, because pjdfstest changes uid and mounting needs it), and that is also
  why the suite's numbers are for a **privileged** mount: no `nodev`, so device
  nodes are openable there and would not be under `fusermount3`.

## rclone, the S3 oracle (installed 2026-07-29)

- **`~/.local/bin/rclone`, rclone v1.74.4** (linux/amd64, go1.26.5, statically
  linked). Installed **user-level, no root and no package manager**: the
  official static zip, one binary extracted out of it. `~/.local/bin` is already
  on this host's `PATH`, so `command -v rclone` answers without any further
  setup. Reinstall in one line:

  ```sh
  curl -fsSL -o /tmp/rclone.zip https://downloads.rclone.org/rclone-current-linux-amd64.zip \
    && unzip -qo /tmp/rclone.zip -d /tmp && install -m 755 /tmp/rclone-v*-linux-amd64/rclone ~/.local/bin/rclone
  ```

- **It exists for exactly one thing:** `test/s3/oracle.test.ts`, the S3
  gateway's foreign-client column. Everything else under `test/s3/` is written
  from this repository's own codecs (`test/s3/client.ts` signs with
  `src/s3/sigv4.ts` and parses with `src/s3/xml.ts`), so a symmetric
  encoder/decoder mistake is invisible to it; rclone shares none of that code
  and is the client whose `x-amz-meta-mtime` convention the gateway was built
  against. `curl` (already present) plays the same role for presigned URLs.
  The file skips itself cleanly when either binary is absent, the way
  `test/nfs/mount.test.ts` skips on `nfsClientProbe()` — **verified both ways**:
  15 passed with it on `PATH`, 15 skipped with `PATH` stripped of
  `~/.local/bin`.

- **Nothing is written to `~/.config/rclone`.** The test runs rclone with
  `RCLONE_CONFIG=""` (no config file at all) and defines the remote entirely in
  `RCLONE_CONFIG_MX_*` environment variables, so a developer's own remotes are
  neither read nor touched. The connection-string form
  (`:s3,provider=Other,endpoint=…:bucket`) is the wrong tool here: it splits on
  `,` and `:`, so an unquoted endpoint URL is parsed as the scheme alone
  (`Custom endpoint 'http' was not a valid URI`).

- **Two settings rclone needs against this gateway, both real limitations:**
  - `list_version=2` — rclone uses ListObjects **V1** for every provider except
    `AWS`, including `Other`, and the gateway implements V2 only. Without it the
    first listing is `501 NotImplemented: ListObjects (V1) …`.
  - `no_check_bucket=true` — rclone sends `CreateBucket` before an upload unless
    a _successful listing earlier in the same process_ has marked the bucket as
    existing. There is no `HeadBucket` probe (verified with `--dump headers`),
    so `copy`/`sync` never send it and `copyto`, `rcat` and directory-marker
    `Mkdir` always do. The gateway's buckets are the drivers it was constructed
    with, so it answers `501 NotImplemented`.

  A third is informational: `rclone purge` asks `GET /bucket?versioning`, is
  refused, logs `Failed to read versioning status, assuming unversioned`, and
  then purges correctly.

- **Empty directories need two flags, not one.** `--create-empty-src-dirs`
  alone is not enough (rclone's S3 backend has no way to represent one) and
  `--s3-directory-markers` alone is not enough (rclone's _local_ backend does
  not offer empty directories to a sync). With both, rclone sends
  `PUT prefix/emptydir/` — the gateway's own directory-marker convention — and
  the directory round-trips.

- **mtime survives to the millisecond and no further.** `x-amz-meta-mtime`
  carries epoch seconds — a bare integer when whole, three decimal places when
  fractional (`formatMetaMtime`) — so a local file's sub-millisecond mtime
  quantises on the way through. rclone's default tolerance between a
  local and an S3 remote is 1 ns, so a tree whose mtimes are not on whole
  milliseconds re-transfers in full on the second `sync`
  (`Modification times differ by -478.92µs`). `--modify-window 1ms` is the fix
  in practice; the test stamps its fixtures on whole milliseconds and asserts
  the drift case separately.

- **`rclone check` cannot compare hashes here.** The gateway's ETag is the
  first 32 hex of sha256 over `dev:ino:size:mtimeMs` with a `-1` suffix, which
  rclone reads as "not a plain MD5": it reports `N hashes could not be checked`
  and falls back to **size plus modification time**. `--size-only` is the
  comparison with no hash in it at all.

## macOS host (verified 2026-07-28)

macOS 26.6 (build 25G72), arm64 (`VirtualMac2,1`), Node v24.18.0, passwordless
sudo, SIP enabled. FUSE does not apply here (see `src/nfs/mount.ts`); this is
the host the NFS transport's Tier-2 column was witnessed on.

- **`pnpm test:nfs:mount` passes**: 4 passed, 2 skipped, ~0.5 s. `/sbin/mount_nfs`
  is present, so `nfsClientProbe()` reports usable. `nfsstat -m` shows every
  option `nfsMountOptions()` sends landing intact:
  `vers=3,proto=tcp,port=…,mountport=…,soft,nolocks,timeo=50,retrans=2,nobrowse`.
- **The consent gate is the one thing that will waste a day.** macOS puts access
  to _network volumes_ behind a sandbox approval, and an NFS mount is one even on
  loopback. An ungranted process gets one of two answers, and neither says why:
  - attributed to a GUI app (a terminal), the syscall **blocks forever** — no
    dialog is ever shown. Kernel stack of the hung process:
    `mac_vnode_check_open` → `hook_vnode_check_open (Sandbox)` →
    `approval_solicit` → `__WAITING_ON_APPROVAL_FROM_SANDBOXD__`. `spindump <pid>`
    is how to see it;
  - attributed to nothing (launchd, a CI agent), it is refused instantly with
    `EPERM` — `ls: /path: Operation not permitted`.

  `umount(8)` goes through the same hook (`hook_mount_check_umount`), so teardown
  hangs or returns `EPERM` too, and `diskutil unmount force` is no better. The
  fix is a grant made **in advance**: Full Disk Access for the app the process is
  attributed to (System Settings → Privacy & Security), or a PPPC profile for
  automation. Killing the waiting process releases the approval and lets the
  queued unmount through; short of that, a reboot. This is what
  `isConsentDenial()`/`consentAdvice()` in `src/nfs/mount.ts` exist to name.

- **AppleDouble sidecars are real files in your driver.** macOS tags every new
  file with a `com.apple.provenance` extended attribute, NFSv3 has no procedure
  for extended attributes, so the client writes each one to a `._name` companion:
  120 `writeFile`s through a mount produce **240** entries, and `ls -1` lists the
  sidecars here (unlike on a local volume, where it hides them). Nothing on the
  server side can prevent it — `test/nfs/mount.test.ts` filters them and asserts
  each one belongs to a file it wrote.
- **`unlink` of a directory is `EPERM`**, not Linux's `EISDIR` — the BSD answer,
  and the client kernel's to give. Same split `test/conformance.ts` already
  handles with `errors: "host"`.
- **Mounting needs no root here.** `/sbin/mount_nfs` is `-rwxr-xr-x`, not setuid,
  and has no entitlements; a BSD lets an ordinary user mount onto a directory
  that user owns. Verified as uid 501, no sudo anywhere: `mount -t nfs -o
vers=3,proto=tcp,port=…,mountport=…,nolocks,soft,nobrowse 127.0.0.1:/ ./mnt`
  → exit 0, read and write through it, `umount ./mnt` → exit 0. The kernel
  forces `MNT_NOSUID|MNT_NODEV` and records `mounted by <user>`; a mountpoint
  owned by root refuses with `Operation not permitted`. There is no
  `vfs.usermount` sysctl on Darwin — the behaviour is unconditional.
- **The NetFS route is a dead end, and the port is the trap.** `open nfs://…`
  has no handler on 26.6 at all (`kLSApplicationNotFoundErr`; `smb://`, `afp://`
  and `ftp://` all resolve to Finder). `NetFSMountURLSync` parses `:20490` into
  `kNetFSAlternatePortKey` and then never reads that key — tcpdump shows it
  going to **port 111**, twice, failing `61 Connection refused`, which is fatal
  for a server with no portmapper. Its `mount_options` dictionary can express
  only `kNetFSMountFlagsKey`/`SoftMount`/`AllowSubMounts`/`MountAtMountDir`;
  `mountport`, `nolocks`, `vers`, `proto`, `timeo`, `retrans` have to go through
  a `?options=` query string, which the plugin passes verbatim to `mount_nfs -o`.
  `osascript -e 'mount volume "nfs://…?options=…"'` does work unprivileged, but
  lands in `/Volumes/<name>` with no say in the path and hangs forever when the
  server is absent.
- **Wedge recovery:** a mount whose server has gone is unresponsive to `stat`
  (`ETIMEDOUT` after `timeo`), and every route down is behind the gate above. In
  order: kill whatever is parked on the mountpoint (that frees the pending
  approval), then `sudo umount -f`, then reboot. A hung `umount` does **not** die
  on `SIGKILL` — it is parked in the kernel — which is why `run()` in
  `src/nfs/mount.ts` settles on its own deadline instead of waiting for `close`.
