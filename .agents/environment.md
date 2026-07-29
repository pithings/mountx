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
