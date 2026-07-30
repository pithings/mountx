# Changelog


## v0.0.2

[compare changes](https://github.com/pithings/mountx/compare/v0.0.1...v0.0.2)

### 🚀 Enhancements

- S3 gateway transport (mountx/s3) ([#5](https://github.com/pithings/mountx/pull/5))
- 9P2000.L transport ([#6](https://github.com/pithings/mountx/pull/6))
- **nfs:** NFSv4.1 alongside NFSv3 ([#7](https://github.com/pithings/mountx/pull/7))

### 🔥 Performance

- **fuse:** Copy the request payload lazily and frame replies in one buffer ([c7ee989](https://github.com/pithings/mountx/commit/c7ee989))
- **core:** Resolve the loopback once and short-circuit canonical paths ([0ee70d6](https://github.com/pithings/mountx/commit/0ee70d6))
- **unstorage:** Stop downloading objects to discard them, and walk in one round trip ([310e278](https://github.com/pithings/mountx/commit/310e278))
- **nfs:** One buffer per reply, from the RPC header to the last payload byte ([16e99b8](https://github.com/pithings/mountx/commit/16e99b8))

### 🩹 Fixes

- **fuse:** Name why fusermount3 could not elevate ([ffc0f66](https://github.com/pithings/mountx/commit/ffc0f66))
- **fuse:** Copy retained decoder bytes ([#2](https://github.com/pithings/mountx/pull/2))
- **unstorage:** Preserve open files across rename ([#3](https://github.com/pithings/mountx/pull/3))
- **harness:** Complete short writes ([#4](https://github.com/pithings/mountx/pull/4))
- **fuse:** Stop minting unforgettable inodes on a plain READDIR ([7185f33](https://github.com/pithings/mountx/commit/7185f33))
- **nfs:** Answer in completion order and bound in-flight work per connection ([2b52975](https://github.com/pithings/mountx/commit/2b52975))
- **nfs:** Bound record reassembly and stop handing out socket views ([5488085](https://github.com/pithings/mountx/commit/5488085))
- **mount:** Make the teardown deadline a deadline on all three transports ([0eb0c3f](https://github.com/pithings/mountx/commit/0eb0c3f))
- **nfs:** Free dead handles, resolve readdir pages concurrently, one snapshot rule ([0747df0](https://github.com/pithings/mountx/commit/0747df0))
- **drivers:** Stop `rmdir("/")` deleting the driver's own root ([e80c8ff](https://github.com/pithings/mountx/commit/e80c8ff))
- **auto:** Say what unmountAll actually covers, and stop remembering failed imports ([805c245](https://github.com/pithings/mountx/commit/805c245))
- Keep every entry point loadable by node's type stripping ([95c2c44](https://github.com/pithings/mountx/commit/95c2c44))

### 💅 Refactors

- One subtree rewrite for all three transports' path tables ([edfdde6](https://github.com/pithings/mountx/commit/edfdde6))

### 📖 Documentation

- Reconcile the guide, reference and invariants with the sweep ([e5c015a](https://github.com/pithings/mountx/commit/e5c015a))
- **bench:** Re-measure every column, against a baseline instead of the old file ([27ea613](https://github.com/pithings/mountx/commit/27ea613))
- Mounting into a VM guest ([#8](https://github.com/pithings/mountx/pull/8))

### ❤️ Contributors

- Pi0x <x@pi0.io>
- Pooya Parsa ([@pi0](https://github.com/pi0))
- Max ([@onmax](https://github.com/onmax))

## v0.0.1


### 🚀 Enhancements

- Driver interface, memory + node:fs drivers, loopback harness (milestone 1) ([8609d65](https://github.com/pithings/mountx/commit/8609d65))
- Pure-JS FUSE wire protocol layer (milestone 2) ([3aa8e2f](https://github.com/pithings/mountx/commit/3aa8e2f))
- FUSE session layer (milestone 3) ([2d138ab](https://github.com/pithings/mountx/commit/2d138ab))
- Root-mode FUSE mount transport (milestone 4) ([af1db7f](https://github.com/pithings/mountx/commit/af1db7f))
- Validation suite — differential, record/replay, pjdfstest (milestone 5) ([06d8210](https://github.com/pithings/mountx/commit/06d8210))
- NFSv3 loopback transport (milestone 6) ([5fed4d9](https://github.com/pithings/mountx/commit/5fed4d9))
- Conformance matrix, benchmark suite, README (milestone 7) ([97e7ba9](https://github.com/pithings/mountx/commit/97e7ba9))
- **fuse:** Native SCM_RIGHTS helper for rootless mounting ([b29fd48](https://github.com/pithings/mountx/commit/b29fd48))
- **fuse:** Mount without root via fusermount3 ([cad9150](https://github.com/pithings/mountx/commit/cad9150))
- **nfs:** Make mount(8) integration platform-aware ([0a84f5d](https://github.com/pithings/mountx/commit/0a84f5d))
- **auto:** Add mountx/auto transport chooser ([9421fc7](https://github.com/pithings/mountx/commit/9421fc7))
- **nfs:** Mount without root on macOS ([ad71615](https://github.com/pithings/mountx/commit/ad71615))
- `mountx` cli ([2941e4b](https://github.com/pithings/mountx/commit/2941e4b))
- Unstorage driver ([5c6bdab](https://github.com/pithings/mountx/commit/5c6bdab))

### 🩹 Fixes

- **test:** Parse the mount table into fields, not tuples ([25e7fc6](https://github.com/pithings/mountx/commit/25e7fc6))
- **test:** Drop the empty argv slot from the daemon spawn ([7e1c88d](https://github.com/pithings/mountx/commit/7e1c88d))
- **fuse:** Locate the addon from a file the bundler never touches ([78667c5](https://github.com/pithings/mountx/commit/78667c5))
- **fuse:** Close the sending socket before waiting for the descriptor ([59d9b5f](https://github.com/pithings/mountx/commit/59d9b5f))
- **native:** Close the descriptors a truncated message did deliver ([c7ff61e](https://github.com/pithings/mountx/commit/c7ff61e))
- **fuse:** Do not give a native error a code of `undefined` ([60537ce](https://github.com/pithings/mountx/commit/60537ce))
- **fuse:** Unmount when the descriptor never arrives ([302f9a4](https://github.com/pithings/mountx/commit/302f9a4))
- **fuse:** Pass the source to mount(8) after `--` ([f87eb8b](https://github.com/pithings/mountx/commit/f87eb8b))
- **fuse:** Do not repeat one-shot open flags on a re-open ([347dcb1](https://github.com/pithings/mountx/commit/347dcb1))
- **nfs:** Bound umount, and name macOS's consent gate ([fbfa8de](https://github.com/pithings/mountx/commit/fbfa8de))
- **cli:** Clear a stale mount on macOS, not just Linux ([644da68](https://github.com/pithings/mountx/commit/644da68))

### 💅 Refactors

- Rename to mountx ([5350594](https://github.com/pithings/mountx/commit/5350594))
- **cli:** Verbose mode ([4095db6](https://github.com/pithings/mountx/commit/4095db6))

### 📖 Documentation

- Distill AGENTS.md and .agents into a working guide ([f1947d0](https://github.com/pithings/mountx/commit/f1947d0))
- Rootless mounting ([e840e8a](https://github.com/pithings/mountx/commit/e840e8a))
- Record the witnessed macOS NFS run ([f996d23](https://github.com/pithings/mountx/commit/f996d23))
- Record the unprivileged macOS mount finding ([130d4b5](https://github.com/pithings/mountx/commit/130d4b5))
- Lead the drivers guide with the built-in drivers ([60ace9f](https://github.com/pithings/mountx/commit/60ace9f))
- Restructure ([a9acd17](https://github.com/pithings/mountx/commit/a9acd17))

### 📦 Build

- Embed prebuilt native ([8fafad7](https://github.com/pithings/mountx/commit/8fafad7))

### 🏡 Chore

- Point repository references at pithings/unimount ([f2dd2ed](https://github.com/pithings/mountx/commit/f2dd2ed))
- Update docs ([e39bb53](https://github.com/pithings/mountx/commit/e39bb53))
- Update readme ([744a38d](https://github.com/pithings/mountx/commit/744a38d))
- Add playground ([c82affd](https://github.com/pithings/mountx/commit/c82affd))
- Update readme ([6960368](https://github.com/pithings/mountx/commit/6960368))
- Update typecheck ([7bc6920](https://github.com/pithings/mountx/commit/7bc6920))

### ✅ Tests

- **fuse:** Tier-2 rootless mount suite, no sudo ([ea7f7dc](https://github.com/pithings/mountx/commit/ea7f7dc))
- Run the Tier-0 suite honestly on a non-Linux host ([ffe2a2c](https://github.com/pithings/mountx/commit/ffe2a2c))
- **nfs:** Run the Tier-2 mount column honestly on macOS ([bece0a6](https://github.com/pithings/mountx/commit/bece0a6))
- Run the mount columns unprivileged on macOS ([59da618](https://github.com/pithings/mountx/commit/59da618))

### 🤖 CI

- Run the suites on a macOS runner ([efb203f](https://github.com/pithings/mountx/commit/efb203f))
- Let the macOS mount job block ([b44b55d](https://github.com/pithings/mountx/commit/b44b55d))

### ❤️ Contributors

- Pooya Parsa ([@pi0](https://github.com/pi0))
- Pooya <pooya@pooyas-Virtual-Machine.local>

