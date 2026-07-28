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
- **No `fusermount3` or `fusermount` installed** — unprivileged mounting is
  impossible on this host until the stub exists. All Tier-2 tests must run
  via sudo; gate/skip them when not root.
- Toolchain: Node v24.18.0, pnpm 11.17.0, zig + gcc/clang available.
- Tests: vitest. Lint/format: oxlint + oxfmt. Build: obuild.
  Typecheck: `tsgo --noEmit --skipLibCheck`. Run `pnpm test` before commits.
