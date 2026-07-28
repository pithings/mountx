# Benchmarks

Numbers, and what they do and do not say.

1. **"Async main-thread mode should land in the low tens of thousands of
   ops/sec."**
2. **"The wins are in negotiation, not in micro-optimizing JS"** — which is why
   the benchmark suite is a v1 deliverable rather than a nice-to-have.

Both are answered below, with the numbers they were answered from. **Anything
the README says about performance must come from this file**, and must carry the
host line with it.

## Host

Every number here was taken on one machine, on one day. They are not portable.

|                          |                                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------- |
| Date                     | 2026-07-28                                                                                                    |
| OS                       | Linux 6.12.96+deb13-amd64 (container, Fedora 44 userland)                                                     |
| CPU                      | 16 × Intel(R) Core(TM) i7-10700K @ 3.80 GHz                                                                   |
| Memory                   | 31.3 GiB                                                                                                      |
| Node                     | v24.18.0                                                                                                      |
| FUSE protocol negotiated | 7.41, `max_write` 1 MiB (256 `max_pages`), `readdirplus` on, writeback cache off                              |
| Driver under test        | the in-memory driver (`src/drivers/memory.ts`), so what is measured is the _transport_, not someone's storage |

Reproduce with:

```sh
pnpm bench                       # loopback + NFS columns, no root
pnpm bench:root                  # the FUSE column, sudo
pnpm bench -- --json out.json    # either one, machine-readable
```

`bench/` is scripts only — nothing here runs inside `pnpm test`.

## What is being measured

The same scenarios, written once (`bench/scenarios.ts`) against the driver
interface and run in every column, exactly as the conformance matrix does it. So
the client code is identical; the difference between columns is transport.

- **loopback** — the driver behind `createLoopback`, no transport at all. The
  ceiling: whatever FUSE and NFS cost, they cost it on top of this.
- **FUSE mount** — a real kernel mount, served by the benchmark process and
  driven from a **child process** (`bench/fuse-client.ts`). It has to be a child:
  a process that serves a mount and is also its client parks a threadpool thread
  per in-flight operation, and the read loop needs one of those threads (see the
  note at the top of `src/fuse/mount.ts`). Putting the client in another process
  removes the hazard instead of tiptoeing around it, and it is the shape a real
  workload has.
- **NFSv3** — the server over a real TCP socket, driven by the JS client in
  `test/nfs/client.ts`. **This is protocol + TCP overhead, not kernel-client
  overhead.** This host has no NFS client at all (`.agents/environment.md`), so
  there is no way to measure the thing a user would actually mount; a kernel
  client would add its own attribute and page caching — which would make several
  of these numbers much better — and its own RPC scheduling.

A warmup, then iterations until a second has been spent, then ops/sec and
p50/p99 (`bench/harness.ts`). No regression detection, no confidence intervals.

Two things to know about how the numbers are computed. **`ops/sec` comes from the
wall window and `p50`/`p99` come from inside the timed bracket**, so `1 / p50` is
deliberately not `ops/sec`: the gap between them is the harness's own bookkeeping
(~90 ns an iteration), invisible against a FUSE round trip and worth 5–20% on a
loopback `stat`. Throughput divides by the wall clock because that is the number
that cannot flatter the ceiling column at the transports' expense. And **the
low-`n` rows are the 100 MiB throughput scenarios and `create 500 small files`**,
all of which run exactly three iterations by construction: read those as ±10%,
not as precision.

---

## Loopback baseline (memory driver, no transport)

| scenario                  |   ops/sec |                rate | p50 ms | p99 ms |      n |
| ------------------------- | --------: | ------------------: | -----: | -----: | -----: |
| stat                      |   615,333 |                   — |  0.001 |  0.003 | 100000 |
| open + read 4 KiB         |   439,582 |                   — |  0.002 |  0.004 | 100000 |
| write 4 KiB               | 2,012,584 |                   — |  0.000 |  0.001 | 100000 |
| readdir (100 entries)     |    82,470 | 8,246,976 entries/s |  0.011 |  0.023 |  82470 |
| sequential read, 100 MiB  |    147.82 |        14,782 MiB/s |  6.677 |  6.940 |      3 |
| sequential write, 100 MiB |     13.82 |         1,382 MiB/s | 72.476 | 72.552 |      3 |
| create 500 small files    |    526.13 |     263,063 files/s |  1.922 |  2.018 |      3 |
| ls -l (1000 entries)      |    470.89 |   470,895 entries/s |  2.192 |  3.324 |     20 |
| stat walk (500 files)     |     1,174 |     587,188 stats/s |  0.826 |  1.162 |     50 |
| stat ×64 in flight        |    12,436 |       795,900 ops/s |  0.078 |  0.102 |   2000 |

**Interpretation.** This is a JavaScript `Map` walk behind a promise, and it
prices the _harness_, not a filesystem: hundreds of thousands of metadata ops per
second, a memcpy-bound 14.8 GiB/s read. Its only job is to be the denominator —
every transport number below is a fraction of a row in this table, and the
fraction is the transport's cost. Two rows are worth keeping in mind when reading
the rest: `write 4 KiB` at 2.0 M/s says the driver contributes essentially
nothing to the FUSE and NFS write numbers, and `sequential write` at 1,382 MiB/s
(against 14,782 MiB/s for read) is the driver's remaining asymmetry — growing a
file still reallocates geometrically and zero-fills, which is ~4× the memory
traffic of the bytes written. That is a driver property, not a transport one, and
it is one bug fix old (below).

---

## FUSE mount, shipped defaults

`max_write` 1 MiB, `readdirplus` on, `FOPEN_KEEP_CACHE` on, `attr_timeout` and
`entry_timeout` 10 s, 2 readers, writeback cache off.

| scenario                   | ops/sec |              rate |  p50 ms |  p99 ms |     n |
| -------------------------- | ------: | ----------------: | ------: | ------: | ----: |
| stat                       |  31,097 |                 — |   0.031 |   0.047 | 31097 |
| open + read 4 KiB          |   4,989 |                 — |   0.195 |   0.307 |  4990 |
| write 4 KiB                |  12,882 |                 — |   0.075 |   0.114 | 12883 |
| readdir (100 entries)      |   1,191 | 119,076 entries/s |   0.718 |   2.742 |  1191 |
| sequential read, 100 MiB   |   75.37 |       7,537 MiB/s |  13.366 |  13.418 |     3 |
| sequential write, 100 MiB  |    7.96 |      796.46 MiB/s | 125.701 | 126.626 |     3 |
| create 500 small files     |    5.06 |     2,528 files/s | 197.971 | 199.378 |     3 |
| ls -l (1000 entries)       |   27.25 |  27,246 entries/s |  36.706 |  38.945 |    20 |
| ls -l (1000 entries, cold) |   10.35 |  10,345 entries/s |  94.200 | 102.783 |     8 |
| stat walk (500 files)      |   67.63 |    33,813 stats/s |  14.738 |  15.451 |    50 |
| stat ×64 in flight         |   1,966 |     125,796 ops/s |   0.491 |   0.752 |  1966 |

**Interpretation.** Read this table knowing that **most of it never reaches the
daemon**. With 10-second attribute and entry timeouts a repeated `stat` is a
kernel cache hit (31 k/s, 31 µs — an order of magnitude off the uncached number
below), and with `FOPEN_KEEP_CACHE` a re-read of a file the page cache still
holds is a memcpy (7,537 MiB/s). That is not cheating; it is what the negotiated
defaults are _for_, and it is what a real workload gets. But it means the honest
per-request cost of the transport is in the next section, and that the rows here
which do reach the driver on every call — `write 4 KiB` at 12,882/s, `create 500
small files` at 2,528 files/s, `sequential write` at 796 MiB/s — are the ones
describing the daemon rather than the kernel.

---

## Negotiation, measured

One mount per row, each giving up exactly one negotiated win. This is the
evidence for IDEA.md's central performance claim, and it holds: **every one of
these deltas is larger than anything a JS-side micro-optimization has been worth
in this codebase.** Where a variant also sets the timeouts to zero it is because
the comparison would otherwise be against the kernel's cache rather than against
the knob being moved.

`default ÷ changed`, so a number **above 1 is what the default buys** and a
number below 1 is a configuration that beat the default.

| what was changed                          | scenario                   |           default |           changed |                        default ÷ changed |
| ----------------------------------------- | -------------------------- | ----------------: | ----------------: | ---------------------------------------: |
| `attr_timeout`/`entry_timeout` 10 s → 0   | stat                       |      31,097 ops/s |       3,332 ops/s |                                 **9.3×** |
|                                           | stat walk (500 files)      |    33,813 stats/s |     2,236 stats/s |                                **15.1×** |
|                                           | ls -l (1000 entries)       |  27,246 entries/s |   3,410 entries/s |                                 **8.0×** |
|                                           | open + read 4 KiB          |       4,989 ops/s |       2,069 ops/s |                                 **2.4×** |
|                                           | readdir (100 entries)      | 119,076 entries/s | 112,004 entries/s |                                    1.06× |
| `FOPEN_KEEP_CACHE` on → off               | sequential read, 100 MiB   |       7,537 MiB/s |       1,526 MiB/s |                                 **4.9×** |
|                                           | open + read 4 KiB          |       4,989 ops/s |       3,713 ops/s |                                    1.34× |
| `max_write` 1 MiB → 128 KiB               | sequential write, 100 MiB  |      796.46 MiB/s |      660.50 MiB/s |                                    1.21× |
|                                           | write 4 KiB                |      12,882 ops/s |      13,181 ops/s |                                    0.98× |
| `READDIRPLUS` on → off, cold dir          | ls -l (1000 entries, cold) |  10,345 entries/s |  10,427 entries/s |                 0.99× — _no win to lose_ |
| `READDIRPLUS_AUTO` on → **off**, cold dir | ls -l (1000 entries, cold) |  10,345 entries/s |  25,047 entries/s |   **0.41× — the default is losing this** |
|                                           | readdir (100 entries)      | 119,076 entries/s | 100,347 entries/s |      1.19× — _and this is what it costs_ |
| writeback cache off → **on**              | write 4 KiB                |      12,882 ops/s |      33,363 ops/s | **0.39× — left on the table on purpose** |
|                                           | create 500 small files     |     2,528 files/s |     2,237 files/s |                                    1.13× |
|                                           | sequential write, 100 MiB  |      796.46 MiB/s |      665.65 MiB/s |                                    1.20× |
| 2 readers → 1                             | stat ×64 in flight         |     9,499 ops/s\* |       8,148 ops/s |                                    1.17× |
| 2 readers → 4                             | stat ×64 in flight         |     9,499 ops/s\* |      10,007 ops/s |                                    0.95× |

\* the reader rows all run at `timeout=0`, so the default they are compared
against is `attr/entry timeout=0`'s 9,499 ops/s, not the cached 125,796.

**Interpretation, one paragraph per finding.**

_Attribute and entry timeouts are the whole ballgame._ An 8–15× swing from two
numbers in a struct, against a driver that is already as fast as a `Map` lookup.
Nothing in the JS below them could move a metadata workload by that much, and a
hand-rolled binding that forgets to set them starts 8× behind. This is the claim,
and it is not close.

_`FOPEN_KEEP_CACHE` is worth 4.9× on re-read, and the 1,526 MiB/s is the real
number._ The 7,537 MiB/s in the default table is the page cache answering without
the daemon; with the flag off, the same 100 MiB genuinely crosses `/dev/fuse` in
1 MiB replies at 1,526 MiB/s. Both numbers are true and they answer different
questions — "how fast is a re-read" and "how fast is the transport".

_`max_write` at 1 MiB is worth ~20% here, far less than IDEA.md's framing
suggests, and the reason is the driver._ At 128 KiB the same 100 MiB is 800
`WRITE` requests instead of 100, and 8× the request count buys only ~20% because
each request is cheap and the memory driver's own copy dominates. Expect this gap
to widen with a driver that does real I/O per request (an S3 or content-addressed
backend, where per-request overhead is a network round trip) and to stay small
for anything memcpy-bound. `n = 3`, and earlier runs of the same pair read 1.15×
and 1.4×; call it 15–40% and do not quote a sharper number than that.

_`READDIRPLUS` is worth nothing as we currently ask for it, and 2.4× if we stop
asking for the `AUTO` variant._ This is the one place the benchmark found a
defaults problem rather than confirming one. `FUSE_READDIRPLUS_AUTO` is in
`DEFAULT_WANTED_FLAGS`, and the kernel's `fuse_use_readdirplus` only uses plus for
the **first page** of a listing unless a lookup in that directory has recently
missed. A 1000-entry directory is ~10 pages, so 90% of it arrives as plain
`READDIR` and the following `stat`s are 900 `LOOKUP`s: 10,345 entries/s with plus,
10,427 without it — identical, and the "often 2–3×" in IDEA.md is simply absent.
Drop `AUTO` (`init: { withoutFlags: FUSE_READDIRPLUS_AUTO }`) and the same cold
listing runs at 25,047 entries/s, **2.4×**, which is the figure IDEA.md predicted.
The cost of dropping it is visible too and it is real: a names-only `readdir` of
100 entries goes 119,076 → 100,347 entries/s, because plus sends attributes
nobody asked for. **Not changed here** — this is a benchmark milestone, not a
defaults milestone — but it is the best-supported open question in the file, and
the honest reading is that the current default optimizes `readdir` at the cost of
`ls -l`, which is backwards for the workloads this library is for. Note also that
the _warm_ `ls -l` rows are all 24–27 k entries/s regardless of readdirplus: once
the entry cache holds the names, nothing else matters.

_Writeback caching is worth 2.6× on small writes and we are deliberately not
taking it._ `FUSE_WRITEBACK_CACHE` turns `write 4 KiB` from 12,882 to 33,363
ops/s by making the kernel the write buffer and collapsing the writes — and it
makes the kernel authoritative for size and mtime and lets writes arrive after
`release`, which is the reason `src/fuse/init.ts` leaves it off. It buys nothing
on the 1 MiB-chunked sequential write (666 vs 796 MiB/s — if anything worse, and
`n = 3`), because there is nothing to collapse. The trade is a semantics one, not
a performance one, and this is what the semantics cost.

_The reader count is not a knob worth turning._ 1, 2 and 4 readers produce
8,148 / 9,499 / 10,007 ops/s on 64 concurrent stats, with peak request rates of
41,539 / 48,549 / 50,349 per second — a ~20% spread across a 4× change, and one
that has reordered itself between runs. That is the expected result and it is
worth stating plainly: `readers` bounds how many requests can be _pulled off_
`/dev/fuse` at once, and pulling is not the bottleneck. Every completion lands on
the same main thread, and that thread is the ceiling. Raising `readers` matters
when the driver blocks (it does not here), and the modes that would actually
change the picture — sync-worker and relay — do not exist yet.

### The transport's own ceiling

Scenario ops/sec undercount the transport, because one syscall is often several
FUSE requests: a `stat(2)` at `entry_timeout = 0` is a `LOOKUP` **and** a
`GETATTR`, and an `open`+`read`+`close` is five. So the session's request counter
is sampled directly while the client works, over the interval the sampler
actually took rather than the one it asked for:

| variant                      | peak FUSE requests/sec | requests in the run |
| ---------------------------- | ---------------------: | ------------------: |
| `default`                    |                 20,468 |              79,775 |
| `attr/entry timeout=0`       |                 48,549 |             234,262 |
| `maxWrite=128KiB`            |                 13,512 |              18,068 |
| `writebackCache=on`          |                 18,003 |              22,525 |
| `readdirplus, no AUTO`       |                 14,094 |              20,393 |
| `readdirplus=off`            |                 14,061 |              26,708 |
| `readdirplus=off, timeout=0` |                 20,620 |              94,037 |
| `keepCache=off`              |                 16,885 |              18,228 |
| `readers=1, timeout=0`       |                 41,539 |              62,459 |
| `readers=4, timeout=0`       |                 50,349 |              70,634 |

The rate is per _variant_, not per scenario — it is one counter on one session —
so the three rows that reach 41–50 k are exactly the ones whose variant included
the 64-in-flight scenario at zero timeouts, and the rest are bounded by whatever
their own scenario mix asked for rather than by the transport.

**Does IDEA.md's "low tens of thousands of ops/sec" hold? Yes, at the request
level, at the upper end of that range.** The transport sustained **41,500–50,300
FUSE requests per second** with requests in flight, and **13,600 per second** for
a strictly sequential client (`write 4 KiB` at zero timeouts: one request per
syscall, no concurrency and no cache). A single-threaded client therefore sees
2,000–4,000 _syscalls_ per second on uncached metadata, because each of those
syscalls is two to five requests — a number worth quoting alongside the request
rate, since it is the one a user experiences.

---

## NFSv3 over localhost TCP

**Protocol and TCP overhead only.** The client is JavaScript, in the same process
as the server, over a loopback socket; there is no kernel NFS client on this host
to measure (`.agents/environment.md`). A real client would cache attributes and
pages and would pipeline differently.

| scenario                  | ops/sec |              rate |  p50 ms |  p99 ms |     n |
| ------------------------- | ------: | ----------------: | ------: | ------: | ----: |
| stat                      |   5,217 |                 — |   0.165 |   0.573 |  5217 |
| open + read 4 KiB         |   4,113 |                 — |   0.222 |   0.487 |  4113 |
| write 4 KiB               |  15,304 |                 — |   0.060 |   0.124 | 15305 |
| readdir (100 entries)     |   1,117 | 111,740 entries/s |   0.809 |   1.734 |  1118 |
| sequential read, 100 MiB  |    3.65 |      364.61 MiB/s | 273.908 | 275.133 |     3 |
| sequential write, 100 MiB |    3.08 |      308.03 MiB/s | 323.886 | 330.117 |     3 |
| create 500 small files    |    5.11 |     2,557 files/s | 194.198 | 201.073 |     3 |
| ls -l (1000 entries)      |    4.98 |   4,980 entries/s | 201.094 | 204.465 |     5 |
| stat walk (500 files)     |    7.14 |     3,571 stats/s | 139.614 | 141.033 |     8 |
| stat ×64 in flight        |  188.83 |      12,085 ops/s |   4.689 |  13.408 |   189 |

**Interpretation.** Per _request_ the NFS server is in the same class as the FUSE
session — 15,304 4 KiB writes per second against FUSE's 12,882, and 12,085 ops/s
with 64 in flight against FUSE's 9,499 at zero timeouts — which is the useful
result, because the two share nothing but the driver interface. Where it looks
much worse is anything path-shaped: `stat walk` is 3,571 stats/s against FUSE's
33,813, and `ls -l` is 4,980 entries/s against 27,246. That is not the protocol
being slow, it is the **absence of a kernel client**: NFS has no path resolution
on the wire, so `test/nfs/client.ts` walks every component with its own `LOOKUP`s
and repeats the walk for every operation, where a real client would have a dentry
cache. Read the four core rows as the server's cost and the path-shaped rows as
an artifact of the test client. Throughput (365 MiB/s read, 308 MiB/s write in
1 MiB RPCs) is the one place the JS client is not in the way, and it is a fifth
of what the FUSE transport does — XDR framing and a socket against a `writeSync`
to a character device.

---

## A real bug the benchmarks found

**The memory driver grew files in O(n²).** `resize()` allocated a new
`Uint8Array` of exactly the new size and copied the old one into it on _every_
growth, and a file arrives in `max_write`-sized chunks — so writing 100 MiB in
1 MiB `WRITE`s moved ~5 GiB. It showed up as the loopback column, which is
supposed to be the ceiling, being _slower_ than the transports it was the
denominator for:

|                                    |      before |                   after |
| ---------------------------------- | ----------: | ----------------------: |
| loopback, sequential write 100 MiB | 60.43 MiB/s |   1,382 MiB/s (**23×**) |
| NFS, sequential write 100 MiB      | 53.18 MiB/s | 308.03 MiB/s (**5.8×**) |

Fixed in `src/drivers/memory.ts`: `node.data` is still a view of exactly the
file's length, but the buffer under it is grown geometrically, so the copying is
amortised. Shrinking keeps the capacity unless the file lost three quarters of
its size, so `truncate(f, 0)` still returns the memory. The `EFBIG` behaviour
pjdfstest pinned is preserved — doubling is attempted first and the exact size is
the fallback, and only a failure of _both_ is `EFBIG`.

Worth noticing what this says about the benchmark suite: it caught a bug that
made a _transport_ look 5× slower than it was. Without the loopback column as a
denominator, 53 MiB/s over NFS would have looked like an NFS number.

## Known gaps

- **Only one concurrency mode exists.** IDEA.md describes three — relay,
  sync-driver-in-workers, and exec mode with an async driver — and v1 has the
  third only. Everything above is main-thread async, which is why the reader
  count does not move the numbers and why the ceiling is ~50 k requests/s: they
  all land on one thread. The sync-worker mode is the one IDEA.md expects to be
  "meaningfully better and scale with worker count"; **that claim is unmeasured
  and must not appear in the README.**
- **One driver.** Every number is against the in-memory driver, on purpose: it
  isolates the transport. A driver that does real I/O will be bounded by its own
  latency long before any of these ceilings, which is the honest thing to tell a
  user asking "how fast is it".
- **No kernel NFS client.** The NFS column is the server's cost plus TCP, and
  cannot be anything else on this host.
- **No `git status` / `tar -x` / build-tree macro-benchmark.** The scenarios are
  synthetic; the record/replay fixtures (`test/fixtures/*.fuse`) contain real
  traffic from `ls -laR`, `find` and `tar -xp`, but they are correctness
  fixtures, not timed workloads.
- **The low-`n` rows are `n = 3`.** ±10%, and the `max_write` and writeback
  sequential-write comparisons are where that matters.
