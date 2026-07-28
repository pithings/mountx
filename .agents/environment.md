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
- **Wedge recovery:** a mount whose server has gone is unresponsive to `stat`
  (`ETIMEDOUT` after `timeo`), and every route down is behind the gate above. In
  order: kill whatever is parked on the mountpoint (that frees the pending
  approval), then `sudo umount -f`, then reboot. A hung `umount` does **not** die
  on `SIGKILL` — it is parked in the kernel — which is why `run()` in
  `src/nfs/mount.ts` settles on its own deadline instead of waiting for `close`.
