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
- **Caveat — teardown after INIT (corrected during milestone 3):** for
  `-t fuse` mounts the kernel NEVER sends `FUSE_DESTROY` (that's `fuseblk`
  only — see `fuse_init_fs_context` in fs/fuse/inode.c; verified twice on
  a live mount: last opcode before a clean umount was STATFS). Therefore
  the transport MUST detect unmount via read() returning EOF/ENODEV on
  /dev/fuse and call `session.destroy()` itself — that call is the only
  thing that closes leftover handles and clears the inode table. Keep the
  read loop alive through umount; if INIT was never answered, close the
  fd to abort the connection.
- `sudo` is passwordless BUT root's PATH lacks node (fnm). Use
  `sudo "$(which node)" script.mjs`. Since node itself runs as root, the
  sudo `closefrom` fd-stripping caveat from IDEA.md does not apply.
- **Leak detection:** `/sys/fs/fuse/connections` is EMPTY on this host until
  fusectl is mounted: `sudo mount -t fusectl none /sys/fs/fuse/connections`.
  Without it, only `/proc/self/mounts` shows leaks.
- **Wedge recovery (verified, both agents' measurements reconciled):**
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
- **No `fusermount3` or `fusermount` installed** — unprivileged mounting is
  impossible on this host until the stub exists. All Tier-2 tests must run
  via sudo; gate/skip them when not root.
- Toolchain: Node v24.18.0, pnpm 11.17.0, zig + gcc/clang available.
- Tests: vitest. Lint/format: oxlint + oxfmt. Build: obuild.
  Typecheck: `tsgo --noEmit --skipLibCheck`. Run `pnpm test` before commits.
- **No NFS client on this host** (verified 2026-07-28, milestone 6): no
  `mount.nfs`/`mount.nfs4` anywhere on `PATH` or in `/sbin`, no `nfs` line in
  `/proc/filesystems`, `/lib/modules` is an empty symlink to /usr/lib/modules
  and there is no `modprobe` — so the kernel NFS client cannot be loaded even
  as root. NOTE: this is Fedora 44 — package manager is `dnf` (with network
  access), NOT apt. libnfs/libnfs-utils/wireshark-cli/gdb are now installed
  (milestone-6 verification); libnfs's nfs-ls/nfs-cp are userspace NFSv3
  clients usable as independent oracles (caveat: getlogin() segfaults in
  this container — LD_PRELOAD a shim returning a name). `rpcbind` and
  `nfsstat` are absent too. The NFS _server_ (`unimount/nfs`) is unaffected: it
  is pure JS over a TCP socket and its Tier-0/Tier-1 suites need nothing. Only
  `pnpm test:nfs:mount` (Tier 2) is affected, and it skips itself on
  `nfsClientProbe()`. On a host with `nfs-common`/`nfs-utils` installed it
  should run as-is.
  **Use libnfs whenever the wire format changes**: it shares none of our
  codecs, which is exactly what the Tier-1 JS client — built from the server's
  own codecs — cannot give. `tshark` dissects the exchange to confirm.
