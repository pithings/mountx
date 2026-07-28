# pjdfstest against a unimount FUSE mount

Measured 2026-07-28 on the dev host (Linux 6.12, FUSE protocol 7.41, Node
v24.18.0). Reproduce with `pnpm test:pjdfstest`; the harness is
`test/pjdfstest/run.sh` + `run.ts` and writes `results.txt` / `results.json`
next to itself (both gitignored — this file is the committed part).

- **Suite:** <https://github.com/pjd/pjdfstest>, pinned at
  `ededbeb2b44929972898afb87474b0937f78a877`, built with `autoreconf -ifs &&
./configure && make pjdfstest`.
- **Under test:** the in-memory driver, mounted with `default_permissions` and
  `allow_other` (pjdfstest changes uid to check permission enforcement, so both
  are load-bearing) and with `attrTimeout`/`entryTimeout` set to `0`, so that
  every answer comes from the driver rather than from the kernel's cache.
- **Harness:** no `prove`. Perl's `TAP::Harness` is not installed on this host,
  and the `.t` files are plain shell scripts printing plain TAP — `run.ts`
  executes each one with its working directory inside the mountpoint and parses
  the result. 238 files.

## Headline

|             | files | files failing | pass | fail | pass rate |
| ----------- | ----: | ------------: | ---: | ---: | --------: |
| first run   |   238 |            72 | 4952 | 3819 |     56.5% |
| after fixes |   238 |        **45** | 5179 | 3591 | **59.1%** |

The pass _rate_ is the least interesting number here and is dominated by one
missing feature — see "Everything that still fails". The number that moved is
**72 → 45 failing files**, and four categories going to 100%.

## Per category (final run)

| category        | files | files failing | pass | fail | todo | pass rate | first run |
| --------------- | ----: | ------------: | ---: | ---: | ---: | --------: | --------: |
| chflags         |    14 |             0 |   14 |    0 |    0 |    100.0% |    100.0% |
| chmod           |    13 |             3 |  199 |  128 |    0 |     60.9% |     55.0% |
| chown           |    11 |             3 |  650 |  820 |   27 |     44.2% |     39.4% |
| ftruncate       |    15 |             0 |   89 |    0 |    0 |    100.0% |     92.1% |
| granular        |     7 |             0 |    7 |    0 |    0 |    100.0% |    100.0% |
| link            |    18 |             3 |  199 |  160 |    0 |     55.4% |     53.2% |
| mkdir           |    13 |             2 |   95 |   23 |    0 |     80.5% |     77.1% |
| mkfifo          |    13 |             7 |   51 |   69 |    0 |     42.5% |     41.7% |
| mknod           |    12 |             8 |   65 |  121 |    0 |     34.9% |     33.3% |
| open            |    27 |             5 |  258 |   79 |    0 |     76.6% |     54.6% |
| posix_fallocate |     1 |             0 |    1 |    0 |    0 |    100.0% |    100.0% |
| rename          |    25 |             8 | 2905 | 1952 |    0 |     59.8% |     59.2% |
| rmdir           |    16 |             2 |  126 |   19 |    0 |     86.9% |     85.5% |
| symlink         |    13 |             1 |   87 |    8 |    0 |     91.6% |     90.5% |
| truncate        |    15 |             0 |   84 |    0 |    0 |    100.0% |     91.7% |
| unlink          |    15 |             2 |  247 |  192 |    1 |     56.3% |     56.0% |
| utimensat       |    10 |             1 |  102 |   20 |    0 |     83.6% |     83.6% |
| **total**       |   238 |            45 | 5179 | 3591 |   28 |     59.1% |     56.5% |

`chflags` is 14/14 because every one of its tests is "this system does not have
`chflags`, skip" — Linux, not us. The 28 `# TODO` results are assertions the
suite itself marks as known-broken and are counted apart from both columns.

## Bugs this found, and the fixes

Five, all in already-committed layers, all found by an assertion nobody wrote by
hand. Each is documented at the code that fixes it.

1. **New inodes were owned by the daemon, not by the caller.**
   `src/fuse/session.ts`, `#claim`. `fuse_in_header` carries the requesting
   process's `uid`/`gid`, and nothing in `FsDriver` can express them, so a
   driver's `mkdir` or `open(O_CREAT)` necessarily creates something owned by
   whoever is running the server — root. With `default_permissions` on, the
   kernel then denied a file's _own creator_ every subsequent operation on it.
   The session now `lchown`s a freshly created entry to the requester (skipped
   when that is the daemon itself, quiet on `ENOSYS`/`EPERM`).
   This one fix moved `open` from 54.6% to 76.6% and emptied `chmod/05.t`,
   `chmod/07.t`, `chown/05.t`, `ftruncate/05.t`, `truncate/05.t`, `link/06.t`,
   `link/07.t` and most of `open/06.t`.
2. **The in-memory driver applied a umask.** `src/drivers/memory.ts`, default
   changed from `0o022` to `0`. A umask belongs to a process; a driver is not
   one, and under a mount the kernel has _already_ applied the caller's umask
   before the mode reaches `FUSE_CREATE`/`FUSE_MKDIR` (no `FUSE_DONT_MASK` in
   this build). Masking again used the wrong process's value: `create f 04777`
   arrived as `04755`. Fixed `chmod/12.t`, `open/02.t`, `open/03.t`,
   `rename/21.t`, `chown/02.t`.
3. **`NAME_MAX` was advertised but not enforced.** `src/fuse/session.ts`,
   `checkName`. The kernel only rejects names longer than `FUSE_NAME_MAX`
   (1024) and assumes the server knows its own limit, so a driver without one
   created names that the same mount's `statfs` reported as impossible, and
   `chmod` on a too-long name answered `ENOENT` where POSIX says
   `ENAMETOOLONG`. Now 255 bytes, the same number the `STATFS` reply carries.
   Fixed the `02.t` of every category that has one.
4. **`truncate` past what memory can hold was `EIO`.**
   `src/drivers/memory.ts`, `resize`. `new Uint8Array(1e15)` throws a
   `RangeError`, which the session can only report as `EIO`; a filesystem says
   `EFBIG`. The allocation is now _attempted_ and a `RangeError` mapped, rather
   than compared against a guessed constant — the first attempt at this used a
   fixed cap and broke `open/25.t` (a legitimate 2 GiB file), which is exactly
   the kind of regression a second run is for. Fixed `truncate/12.t`,
   `ftruncate/12.t`.
5. **`SETATTR` followed symlinks** (`lchown`/`lutimes`, `src/fuse/session.ts`)
   and **`nlink` was clamped to ≥ 1** (`#attrOf`). Both were found by the other
   milestone-5 oracles — record/replay and the differential suite — rather than
   here, but both show up in these numbers.

## Everything that still fails

**All 3591 remaining failures are one missing feature.** Every one of the 45
failing files exercises FIFOs, UNIX-domain sockets or device nodes, and the
failures decompose as:

| what                                                                                       | count |
| ------------------------------------------------------------------------------------------ | ----: |
| `mkfifo` / `mknod` / `bind` answered `-ENOSYS`                                             |   691 |
| the same, where pjdfstest prints a bare `not ok` (its socket helper)                       |   104 |
| downstream of those: `ENOENT`/`EISDIR`/unexpected success on a name that was never created |  2796 |

The cascade is what makes the raw percentages misleading. `mkdir/10.t` is
typical: it loops over seven file types, and for `fifo` the `mkfifo` fails, the
following `mkdir` therefore _succeeds_ where `EEXIST` was expected, and the
`unlink` after it hits the directory that mkdir just made — one missing feature,
three failed assertions, in every iteration of every loop. `rename/09.t` and
`rename/10.t` alone are 1772 of the 3591, and they are a nested loop over the
same seven types.

### Classification

- **Driver limitation (expected, and the accepted answer for v1).** `FsDriver`
  has no `mknod`: the interface is a subset of `node:fs/promises`, which has no
  way to create a FIFO, a socket or a device node either. `FUSE_MKNOD` for a
  regular file is handled (the kernel uses it when `CREATE` is unavailable);
  everything else answers `-ENOSYS`, which is how a FUSE server says "not
  implemented" and is what the milestone brief names as acceptable.
  Worth noting for whenever it _is_ implemented: there is no kernel obstacle.
  A FUSE server creates a special file by inventing an inode with the right
  `S_IF*` in `mode` (and `rdev` for devices) and reporting it in `getattr` —
  the VFS supplies the pipe, socket and device semantics itself. It needs an
  `FsDriver.mknod` (or an `unimount.mknod` extension) and matching storage in
  the in-memory driver, and it would take the suite from 45 failing files to
  a handful. It is a milestone-1 interface change, so it is not one this
  milestone made.
- **Session bugs.** None left. The five above were fixed and re-measured.
- **Kernel/FUSE semantics deliberately not supported.** None are load-bearing
  in the remaining numbers, but two are worth stating because they would be the
  next things to trip over:
  - **`killpriv`.** Clearing SUID/SGID when a non-owner writes is negotiated
    with `FUSE_HANDLE_KILLPRIV`/`_V2`, which this build does not request; the
    kernel handles it through `SETATTR` instead, which is why `chmod/12.t`
    passes. If a driver ever wants to do it itself, that is the flag.
  - **`FUSE_EXT_GROUPS`.** Only a single `gid` is on the wire, so a
    supplementary-group permission decision is the kernel's (via
    `default_permissions`) and can never be the driver's. Fine for v1, and the
    reason `#claim` sets only `uid`/`gid`.
- **Known gaps that are ours but not pjdfstest's.** Set-gid directory
  inheritance (a new entry in a set-gid directory should take its parent's
  group) is not implemented; pjdfstest does not cover it, and the honest fix is
  caller credentials in the driver interface rather than more work in `#claim`.

## Running it

```sh
pnpm test:pjdfstest             # clone (pinned), build, mount, run, summarize
pnpm test:pjdfstest chmod       # one category, or any path fragment
```

The whole run takes about 15 minutes, most of it in `chown/00.t` (1280
assertions) and `rename/09.t`/`rename/10.t` (4452 between them) — with
attribute caching switched off, every assertion is several round trips through
a JavaScript filesystem.
