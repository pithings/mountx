# Benchmarks

Numbers, and what they do and do not say.

1. **"Async main-thread mode should land in the low tens of thousands of
   ops/sec."**
2. **"The wins are in negotiation, not in micro-optimizing JS"** — which is why
   the benchmark suite is a v1 deliverable rather than a nice-to-have.

Both are answered below, with the numbers they were answered from. **Anything
the README or `docs/` says about performance must come from this file**, and must
carry the host line with it.

## Host

**Every number in this file was taken on one host, and — apart from the 9P
column — in one sitting, on one day.** That has not always been true of this
file — the loopback/NFS columns and the FUSE column are two separate commands
(`pnpm bench` and `pnpm bench:root`) and have previously been regenerated apart
— so it is stated here rather than assumed. Four runs went into the 2026-07-29
sitting: both commands on the shipping tree, and both again on a pre-sweep
baseline (below).

**The 9P column is a second sitting, two days later**, because it did not exist
until then; it carries its own date, its own tree and its own denominators, and
[says so in full](#9p-over-transunix-a-real-kernel-mount). Nothing above it was
re-measured for it and nothing above it was changed by it.

|                          |                                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------- |
| Date                     | 2026-07-29 (loopback, NFSv3, FUSE) · 2026-07-31 (9P)                                                          |
| Tree                     | `95c2c44`, i.e. after the `c7ee989..95c2c44` performance sweep · `81b40a4` for the 9P column                  |
| Baseline tree            | `0f359e7` + the type-stripping fix only (see below)                                                           |
| Columns                  | loopback, NFSv3 and FUSE — all three measured together, on both trees, in the first sitting; 9P in the second |
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
pnpm bench:9p                    # the 9P column, sudo (mount(2) needs CAP_SYS_ADMIN)
pnpm bench -- --json out.json    # any one of them, machine-readable
```

`bench/` is scripts only — nothing here runs inside `pnpm test`.

### The baseline, and why there is one

Every "the sweep made this faster" claim below is against a **paired run on the
tree immediately before the sweep, in the same sitting on the same idle host,
minutes apart.** The method, because it matters:

- A git worktree at **`0f359e7`**, the commit before `c7ee989..95c2c44`.
- Onto it, and _only_ it, `git checkout 95c2c44 -- src/nfs/v4/state.ts src/s3/session.ts`.
  `95c2c44` is the fix that made every entry point loadable by node's type
  stripping, and without it `node bench/index.ts` does not start at all on the old
  tree. Those two files are the whole of that commit's change to `src/`, and the
  change is three constructors' parameter properties rewritten as explicit field
  assignments — same emit, so it cannot move a number. Nothing else was taken from
  the swept tree.
- Both benchmark commands run on it, in the same sitting as the swept pair.

This exists because the first draft of this file compared the new runs against
**the numbers already written in this file**, which had been measured on another
day and another tree. That comparison produced six apparent regressions, and the
paired baseline shows that five of them were not regressions at all — one of them
(`NFS write 4 KiB`) was a **1.74× improvement** reading as an 11% loss. The
methodological rule that falls out of it is worth stating plainly, because the
mistake is cheap to repeat:

> **This file's own previous numbers are not a baseline for a code change.** They
> are a record of what a tree measured on a day. To attribute a delta to a diff,
> measure both trees in one sitting.

### Reading these numbers

A warmup, then iterations until a second has been spent, then ops/sec and
p50/p99 (`bench/harness.ts`). No regression detection, no confidence intervals.

**`ops/sec` comes from the wall window and `p50`/`p99` come from inside the timed
bracket**, so `1 / p50` is deliberately not `ops/sec`: the gap between them is the
harness's own bookkeeping (~90 ns an iteration), invisible against a FUSE round
trip and worth 5–20% on a loopback `stat`. Throughput divides by the wall clock
because that is the number that cannot flatter the ceiling column at the
transports' expense.

**Run-to-run spread on this host is about ±8%, even on the high-`n` rows.** This
sitting measures that directly rather than guessing at it, twice over:

- `write 4 KiB` over FUSE appears in three variants that cannot differ for it — a
  4 KiB write is far under either `max_write`, and attribute timeouts do not touch
  the write path — and on the shipping tree reads 10,961 / 11,895 / 11,900 ops/s
  at `n ≈ 12,000`, an 8% spread.
- The same three on the baseline tree read 11,987 / 11,894 / 12,548, an equally
  wide spread with the members in a different order.

So **treat anything under ~1.15× as no difference**, and read the `n = 3` rows —
the 100 MiB throughput scenarios and `create 500 small files`, all of which run
exactly three iterations by construction — as ±10% on top of that. Two `n = 3`
rows in this sitting make the point on their own: the FUSE `sequential read`
scenario measured 5,936 MiB/s in the baseline `default` variant and 7,124 MiB/s in
the baseline `maxWrite=128KiB` variant, a knob that cannot touch reads at all.

This calibration is what makes the rest of the file readable. The deltas the sweep
produced are 1.2× to 3.0×; the three unexplained residues are 9–15%. Those are
different kinds of number and must not be read the same way.

---

## Loopback baseline (memory driver, no transport)

| scenario                  |   ops/sec |                 rate | p50 ms | p99 ms |      n |
| ------------------------- | --------: | -------------------: | -----: | -----: | -----: |
| stat                      | 1,093,940 |                    — |  0.001 |  0.002 | 100000 |
| open + read 4 KiB         |   731,105 |                    — |  0.001 |  0.003 | 100000 |
| write 4 KiB               | 1,983,062 |                    — |  0.000 |  0.001 | 100000 |
| readdir (100 entries)     |   108,480 | 10,847,957 entries/s |  0.008 |  0.022 | 100000 |
| sequential read, 100 MiB  |    121.71 |         12,171 MiB/s |  8.283 |  8.332 |      3 |
| sequential write, 100 MiB |     12.57 |          1,257 MiB/s | 76.954 | 84.854 |      3 |
| create 500 small files    |    623.20 |      311,601 files/s |  1.602 |  1.636 |      3 |
| ls -l (1000 entries)      |    992.24 |    992,239 entries/s |  0.908 |  1.700 |     20 |
| stat walk (500 files)     |     2,305 |    1,152,689 stats/s |  0.425 |  0.714 |     50 |
| stat ×64 in flight        |    24,862 |      1,591,151 ops/s |  0.038 |  0.071 |   2000 |

**Interpretation.** This is a JavaScript `Map` walk behind a promise, and it
prices the _harness_, not a filesystem: a million metadata ops per second, a
memcpy-bound 12.2 GiB/s read. Its only job is to be the denominator — every
transport number below is a fraction of a row in this table, and the fraction is
the transport's cost.

The sweep moved this column hard, and it moved it exactly where the commit
messages said it would. Against the paired baseline: `stat` **1.79×**, `stat walk`
**2.72×**, `ls -l` **1.75×**, `stat ×64` **2.03×**, `open + read` **1.73×** — the
loopback's per-call rebind going away and `normalizePath` growing a canonical fast
path (`0ee70d6` measured 837 ns → 355 ns for a `stat` through the loopback in
isolation, and the whole-scenario numbers agree with it). `readdir` **1.47×** is
`memory.readdir` deriving its type predicates from `mode & S_IFMT` instead of
building and discarding a `StatsLike` per entry (`e80c8ff`). The full pairing is in
[What the sweep moved](#what-the-sweep-moved).

Two rows are worth keeping in mind when reading the rest. `write 4 KiB` at 2.0 M/s
says the driver contributes essentially nothing to the FUSE and NFS write numbers
— it is unchanged by the sweep (1.04×), and it was never the thing in the way.
`sequential write` at 1,257 MiB/s against 12,171 MiB/s for read is the driver's
remaining asymmetry: growing a file still reallocates geometrically and zero-fills,
which is ~4× the memory traffic of the bytes written. That is a driver property,
not a transport one, and it is one bug fix old (below). Neither throughput row was
a target of the sweep and neither moved meaningfully (write 1.04×, read 0.90× at
`n = 3` — see [what is left open](#what-is-left-open-and-small)).

---

## FUSE mount, shipped defaults

`max_write` 1 MiB, `readdirplus` on, `FOPEN_KEEP_CACHE` on, `attr_timeout` and
`entry_timeout` 10 s, 2 readers, writeback cache off.

| scenario                   | ops/sec |              rate |  p50 ms |  p99 ms |     n |
| -------------------------- | ------: | ----------------: | ------: | ------: | ----: |
| stat                       |  33,434 |                 — |   0.027 |   0.071 | 33434 |
| open + read 4 KiB          |   4,190 |                 — |   0.209 |   0.889 |  4191 |
| write 4 KiB                |  10,961 |                 — |   0.086 |   0.155 | 10961 |
| readdir (100 entries)      |   1,483 | 148,273 entries/s |   0.617 |   1.297 |  1483 |
| sequential read, 100 MiB   |   62.21 |       6,221 MiB/s |  16.262 |  16.448 |     3 |
| sequential write, 100 MiB  |    6.37 |      636.75 MiB/s | 155.900 | 160.963 |     3 |
| create 500 small files     |    4.61 |     2,303 files/s | 217.077 | 225.309 |     3 |
| ls -l (1000 entries)       |   28.96 |  28,958 entries/s |  34.234 |  38.603 |    20 |
| ls -l (1000 entries, cold) |    9.60 |   9,602 entries/s | 102.551 | 112.218 |     8 |
| stat walk (500 files)      |   60.79 |    30,397 stats/s |  16.352 |  20.716 |    50 |
| stat ×64 in flight         |   2,009 |     128,600 ops/s |   0.476 |   0.790 |  2000 |

**Interpretation.** Read this table knowing that **most of it never reaches the
daemon**. With 10-second attribute and entry timeouts a repeated `stat` is a
kernel cache hit (33 k/s, 27 µs — an order of magnitude off the uncached 3,429/s
below), and with `FOPEN_KEEP_CACHE` a re-read of a file the page cache still holds
is a memcpy (6,221 MiB/s). That is not cheating; it is what the negotiated
defaults are _for_, and it is what a real workload gets. But it means the honest
per-request cost of the transport is in the next section, and that the rows here
which do reach the driver on every call — `write 4 KiB` at 10,961/s, `create 500
small files` at 2,303 files/s, `sequential write` at 636.75 MiB/s — are the ones
describing the daemon rather than the kernel.

This is the column the sweep moved least, and the first paragraph is the reason:
at the shipped defaults, the scenarios that would exercise the changed paths are
answered by the kernel instead. Where the sweep does show through it shows through
cleanly — `sequential write` **1.25×**, `readdir` **1.20×**, `ls -l` **1.09×** —
and the sharper evidence is in the degraded variants, where the cache is out of the
way: the uncached sequential read (`keepCache=off`) is **1.19×** and the
plain-`READDIR` path (`readdirplus=off`) is **1.20×**, both attributable to a named
commit. Everything else here is inside the spread, except `open + read 4 KiB`,
which is [open](#what-is-left-open-and-small).

---

## Negotiation, measured

One mount per row, each giving up exactly one negotiated win. This is the
evidence for IDEA.md's central performance claim. Where a variant also sets the
timeouts to zero it is because the comparison would otherwise be against the
kernel's cache rather than against the knob being moved.

`default ÷ changed`, so a number **above 1 is what the default buys** and a
number below 1 is a configuration that beat the default. Every row here is from
the shipping tree; the last column is the same ratio computed from the pre-sweep
run, and it is there because a negotiation finding that replicates on two trees in
one sitting is worth much more than one that does not.

| what was changed                          | scenario                   |            default |           changed |                        default ÷ changed | on baseline |
| ----------------------------------------- | -------------------------- | -----------------: | ----------------: | ---------------------------------------: | ----------: |
| `attr_timeout`/`entry_timeout` 10 s → 0   | stat                       |       33,434 ops/s |       3,429 ops/s |                                 **9.8×** |       10.9× |
|                                           | stat walk (500 files)      |     30,397 stats/s |     2,052 stats/s |                                **14.8×** |       15.5× |
|                                           | ls -l (1000 entries)       |   28,958 entries/s |   2,970 entries/s |                                 **9.8×** |        8.3× |
|                                           | open + read 4 KiB          |        4,190 ops/s |       1,924 ops/s |                                 **2.2×** |        2.5× |
|                                           | readdir (100 entries)      |  148,273 entries/s | 121,865 entries/s |                                    1.22× |       1.17× |
| `FOPEN_KEEP_CACHE` on → off               | sequential read, 100 MiB   |        6,221 MiB/s |       1,568 MiB/s |                                 **4.0×** |        4.5× |
|                                           | open + read 4 KiB          |        4,190 ops/s |       3,765 ops/s |                                    1.11× |       1.27× |
| `max_write` 1 MiB → 128 KiB               | sequential write, 100 MiB  |       636.75 MiB/s |      517.51 MiB/s |                                    1.23× |   **0.95×** |
|                                           | write 4 KiB                |       10,961 ops/s |      11,900 ops/s |                      0.92× — _no change_ |       0.96× |
|                                           | sequential read, 100 MiB   |        6,221 MiB/s |       6,460 MiB/s |                      0.96× — _no change_ |       0.83× |
| `READDIRPLUS` on → off, cold dir          | ls -l (1000 entries, cold) |    9,602 entries/s |  10,208 entries/s |                 0.94× — _no win to lose_ |       1.02× |
|                                           | ls -l (1000 entries)       |   28,958 entries/s |  28,439 entries/s |                                    1.02× |       1.05× |
|                                           | readdir (100 entries)      |  148,273 entries/s | 171,638 entries/s |    0.86× — _and this is what plus costs_ |       0.87× |
| `READDIRPLUS_AUTO` on → **off**, cold dir | ls -l (1000 entries, cold) |    9,602 entries/s |  24,976 entries/s |   **0.38× — the default is losing this** |   **0.41×** |
|                                           | ls -l (1000 entries)       |   28,958 entries/s |  24,794 entries/s |                                    1.17× |       1.11× |
|                                           | readdir (100 entries)      |  148,273 entries/s |  95,297 entries/s |  **1.56× — _and this is what it costs_** |       1.32× |
| `READDIRPLUS` on → off, timeouts 0        | ls -l (1000 entries, cold) |   3,074 entries/s† |   2,952 entries/s |                                    1.04× |       1.01× |
|                                           | ls -l (1000 entries)       |   2,970 entries/s† |   2,842 entries/s |                                    1.05× |       0.99× |
|                                           | readdir (100 entries)      | 121,865 entries/s† | 138,655 entries/s |                                    0.88× |       1.02× |
| writeback cache off → **on**              | write 4 KiB                |       10,961 ops/s |      34,481 ops/s | **0.32× — left on the table on purpose** |   **0.37×** |
|                                           | create 500 small files     |      2,303 files/s |     2,229 files/s |                                    1.03× |       1.08× |
|                                           | sequential write, 100 MiB  |       636.75 MiB/s |      639.66 MiB/s |                                    1.00× |       0.87× |
| 2 readers → 1                             | stat ×64 in flight         |      9,132 ops/s\* |       7,479 ops/s |                                    1.22× |       1.17× |
|                                           | stat                       |      3,429 ops/s\* |       3,589 ops/s |                                    0.96× |       0.97× |
| 2 readers → 4                             | stat ×64 in flight         |      9,132 ops/s\* |       8,736 ops/s |                                    1.05× |       1.18× |
|                                           | stat                       |      3,429 ops/s\* |       3,449 ops/s |                                    0.99× |       0.86× |

\* the reader rows all run at `timeout=0`, so the default they are compared
against is `attr/entry timeout=0`'s 9,132 ops/s, not the cached 128,600.

† likewise: the `timeouts 0` readdirplus rows are compared against
`attr/entry timeout=0`, which still has `READDIRPLUS` (with `AUTO`) on.

**Interpretation, one paragraph per finding.**

_Attribute and entry timeouts are the whole ballgame._ A 9.8–14.8× swing from two
numbers in a struct on the shipping tree, and 8.3–15.5× on the pre-sweep one — the
same finding twice, against a driver that is already as fast as a `Map` lookup.
This is the claim, and it is not close.

_But "the wins are in negotiation, not in micro-optimizing JS" needs qualifying,
and there is now real evidence for the qualification rather than a stale-file
inference._ The claim as written said every negotiated delta beats anything
JS-side. The paired baseline shows a two-tier picture instead. The **top**
negotiated wins still dwarf everything: timeouts at 9.8–14.8×, `FOPEN_KEEP_CACHE`
at 4.0×. Below them, one sweep of ordinary JS work is worth **3.01× on NFS
sequential read, 2.72× on loopback `stat walk`, 2.03× on 64-in-flight loopback
stats, 1.86× on NFS `readdir`, 1.74× on NFS `write 4 KiB`** — which beats
`READDIRPLUS_AUTO` (2.6×, and a win we are not taking), and beats `max_write`, the
reader count and warm `READDIRPLUS` several times over. The honest form of the
claim is: _get the handshake right first, because no amount of JS recovers a 10×
cache miss — and then the JS is worth more than every remaining knob put together._

_`FOPEN_KEEP_CACHE` is worth 4.0× on re-read, the 1,568 MiB/s is the real number,
and the ratio fell for a good reason._ The 6,221 MiB/s in the default table is the
page cache answering without the daemon; with the flag off, the same 100 MiB
genuinely crosses `/dev/fuse` in 1 MiB replies at 1,568 MiB/s. Both numbers are
true and they answer different questions — "how fast is a re-read" and "how fast is
the transport". The ratio went 4.5× → 4.0× across the sweep, and that is the
_transport_ improving rather than the cache degrading: the uncached read went
**1,314 → 1,568 MiB/s, 1.19×**, which is `c7ee989`'s READ reply built in one buffer
instead of two (measured there at 180 → 73 µs per 1 MiB reply). Making the slow
path faster is exactly what shrinks the value of the cache in front of it.

_`max_write` at 1 MiB is real in principle and not reliably measurable on this
driver._ At 128 KiB the same 100 MiB is 800 `WRITE` requests instead of 100, and 8×
the request count ought to cost something. It measures 1.23× on the shipping tree
— and **0.95× on the baseline tree in the same sitting**, i.e. the default losing.
Across every paired run this file has recorded, the comparison reads 0.95×, 1.15×,
1.21×, 1.23× and 1.4×. All are `n = 3`, and the neighbouring control rows — a 4 KiB
write and a page-cached read, both of which any `max_write` covers — come back at
0.83×–0.96×, which is the size of the noise on the same scenarios. **Do not quote a
number for this knob on an in-memory driver.** What can be said: the mechanism is
request count, so expect it to matter with a driver that does real I/O per request
(an S3 or content-addressed backend, where per-request overhead is a network round
trip) and to stay lost in the noise for anything memcpy-bound.

_`READDIRPLUS` is worth nothing as we currently ask for it, and ~2.5× if we stop
asking for the `AUTO` variant._ This is the one place the benchmark found a
defaults problem rather than confirming one, and it now replicates on both trees:
0.38× on the shipping tree, 0.41× on the baseline. `FUSE_READDIRPLUS_AUTO` is in
`DEFAULT_WANTED_FLAGS`, and the kernel's `fuse_use_readdirplus` only uses plus for
the **first page** of a listing unless a lookup in that directory has recently
missed. A 1000-entry directory is ~10 pages, so 90% of it arrives as plain
`READDIR` and the following `stat`s are 900 `LOOKUP`s: 9,602 entries/s with plus,
10,208 with it off — the same number, and the "often 2–3×" in IDEA.md is simply
absent. Drop `AUTO` (`init: { withoutFlags: FUSE_READDIRPLUS_AUTO }`) and the same
cold listing runs at 24,976 entries/s, **2.6×**, which is the figure IDEA.md
predicted. The cost is visible too: a names-only `readdir` of 100 entries goes
148,273 → 95,297 entries/s, **1.56×**, because plus sends attributes nobody asked
for. That cost grew across the sweep — it was 1.32× before — and the pairing says
exactly why, which is a direct confirmation of `7185f33`: the plain-`READDIR` path
stopped binding an inode per entry and went **142,526 → 171,638 entries/s (1.20×)**,
while the always-plus path, which legitimately still acquires one, went 93,874 →
95,297 (1.02×). Making plain `readdir` cheaper makes plus look dearer. Turning plus
off entirely moves the row to 171,638, so the shipped default sits about a third of
the way along that line, which is what `AUTO` means in practice. **Not changed
here** — this is a benchmark milestone, not a defaults milestone — but it is the
best-supported open question in the file, and the honest reading is that the
current default optimizes `readdir` at the cost of `ls -l`, which is backwards for
the workloads this library is for. Note also that the _warm_ `ls -l` rows are all
24.8–29.0 k entries/s regardless of readdirplus: once the entry cache holds the
names, nothing else matters. And the `timeouts 0` pair is the control that rules
out the cache as the explanation — with no cache to hide behind at all, turning
plus off still costs only 4–5%, because with `AUTO` in the way there was never much
plus happening to lose.

_Writeback caching is worth ~3× on small writes and we are deliberately not taking
it._ `FUSE_WRITEBACK_CACHE` turns `write 4 KiB` from 10,961 to 34,481 ops/s (3.1×;
2.7× on the baseline tree) by making the kernel the write buffer and collapsing the
writes — and it makes the kernel authoritative for size and mtime and lets writes
arrive after `release`, which is the reason `src/fuse/init.ts` leaves it off. It
buys **nothing** on the 1 MiB-chunked sequential write (1.00× on the shipping tree,
0.87× on the baseline) or on file creation (1.03× / 1.08×), because in neither is
there anything to collapse. The trade is a semantics one, not a performance one,
and this is what the semantics cost: ~3× on the one workload shaped to benefit, and
nothing anywhere else.

_The reader count is not a knob worth turning, and the paired runs settle it._ 1, 2
and 4 readers produce 7,479 / **9,132** / 8,736 ops/s on 64 concurrent stats on the
shipping tree, and 7,555 / **8,866** / 7,509 on the baseline — two readers best both
times, a 15–22% spread across a 4× change, and **not monotonic in either**. Between
the two runs the ordering of 1 against 4 inverted, and an older sweep had it
monotonically rising; three orderings from three runs is the strongest possible
statement that the ordering is not real. On the strictly sequential `stat` row all
three are within 5% of each other on the shipping tree, as they must be — one
outstanding operation cannot use a second reader. That is the expected result and
it is worth stating plainly: `readers` bounds how many requests can be _pulled off_
`/dev/fuse` at once, and pulling is not the bottleneck. Every completion lands on
the same main thread, and that thread is the ceiling. Raising `readers` matters when
the driver blocks (it does not here), and the modes that would actually change the
picture — sync-worker and relay — do not exist yet.

### The transport's own ceiling

Scenario ops/sec undercount the transport, because one syscall is often several
FUSE requests: a `stat(2)` at `entry_timeout = 0` is a `LOOKUP` **and** a
`GETATTR`, and an `open`+`read`+`close` is five.

**The direct request-counter measurement was not repeated in this sitting.**
`bench/fuse.ts` samples `session.stats.requests` while the client works, but it
reports the result only through `notes` in the `--json` output, and neither run was
taken with `--json`. The table below is therefore **the 2026-07-28 sweep's, on an
older tree**, kept because nothing has replaced it and marked because it is the one
block in this file that does not share the others' vintage. Do not quote it beside
a number from the tables above without saying so.

| variant (2026-07-28, tree `c7ee989~1`) | peak FUSE requests/sec | requests in the run |
| -------------------------------------- | ---------------------: | ------------------: |
| `default`                              |                 20,468 |              79,775 |
| `attr/entry timeout=0`                 |                 48,549 |             234,262 |
| `maxWrite=128KiB`                      |                 13,512 |              18,068 |
| `writebackCache=on`                    |                 18,003 |              22,525 |
| `readdirplus, no AUTO`                 |                 14,094 |              20,393 |
| `readdirplus=off`                      |                 14,061 |              26,708 |
| `readdirplus=off, timeout=0`           |                 20,620 |              94,037 |
| `keepCache=off`                        |                 16,885 |              18,228 |
| `readers=1, timeout=0`                 |                 41,539 |              62,459 |
| `readers=4, timeout=0`                 |                 50,349 |              70,634 |

The rate is per _variant_, not per scenario — it is one counter on one session,
sampled across the whole child-driven period including each scenario's setup and
teardown — so a row's peak is whatever the busiest 250 ms of that variant's mix
happened to be, and the rows that reach 41–50 k are the ones whose variant included
the 64-in-flight scenario at zero timeouts.

**What _this_ sitting does support, without that counter**, is a lower bound read
straight off the scenario tables, using the request counts above:

| what the client was doing                              | FUSE requests/sec |
| ------------------------------------------------------ | ----------------: |
| `write 4 KiB`, timeouts 0 — one `WRITE`, one at a time |        **11,895** |
| `open + read 4 KiB`, timeouts 0 — five requests each   |        **~9,600** |
| `stat ×64 in flight`, timeouts 0 — ≥2 requests each    |       **≥18,300** |

**Does IDEA.md's "low tens of thousands of ops/sec" hold? Yes, at the request
level.** A strictly sequential client — one request outstanding, no concurrency and
no cache — gets **11,900 requests per second**, and a client with 64 operations in
flight sustains **at least 18,300**, with the older sweep's direct sampling putting
the peak nearer 50,000. A single-threaded client therefore sees roughly
**2,000–3,500 _syscalls_ per second** on uncached metadata (`stat` at 3,429/s,
`open+read+close` at 1,924/s, `stat walk` at 2,052/s), because each of those
syscalls is two to five requests — and that is the number a user experiences, so
quote it alongside the request rate rather than instead of it.

---

## NFSv3 over localhost TCP

**Protocol and TCP overhead only.** The client is JavaScript, in the same process
as the server, over a loopback socket; there is no kernel NFS client on this host
to measure (`.agents/environment.md`). A real client would cache attributes and
pages and would pipeline differently.

| scenario                  | ops/sec |              rate |  p50 ms |  p99 ms |     n |
| ------------------------- | ------: | ----------------: | ------: | ------: | ----: |
| stat                      |   5,177 |                 — |   0.169 |   0.442 |  5177 |
| open + read 4 KiB         |   4,115 |                 — |   0.217 |   0.612 |  4115 |
| write 4 KiB               |  13,653 |                 — |   0.060 |   0.191 | 13653 |
| readdir (100 entries)     |   1,309 | 130,860 entries/s |   0.674 |   1.650 |  1309 |
| sequential read, 100 MiB  |    9.77 |      977.16 MiB/s | 102.501 | 102.517 |     3 |
| sequential write, 100 MiB |    4.12 |      411.79 MiB/s | 240.057 | 255.704 |     3 |
| create 500 small files    |    4.80 |     2,399 files/s | 185.709 | 255.225 |     3 |
| ls -l (1000 entries)      |    4.97 |   4,972 entries/s | 199.735 | 214.353 |     5 |
| stat walk (500 files)     |    7.63 |     3,816 stats/s | 130.303 | 133.396 |     8 |
| stat ×64 in flight        |  200.38 |      12,824 ops/s |   4.394 |   9.803 |   201 |

**This is the column the sweep changed most, and it is not close.** Against the
paired baseline: sequential read **3.01×** (325 → 977 MiB/s), `readdir` **1.86×**,
`write 4 KiB` **1.74×**, sequential write **1.56×**, `open + read 4 KiB` **1.41×**.
Those are `16e99b8` collapsing six full-size passes over a 1 MiB READ payload to
two, `5488085` making record reassembly linear (8 MiB: 81 ms → 1.13 ms) and dropping
`fixedOpaque`'s pointless memset, `2b52975` unchaining replies so a call no longer
waits on the one before it, and `0747df0` resolving `READDIR` pages concurrently
instead of one serialized `lstat` per entry. Every one of those commits predicted a
direction and the paired run produced it. The tail moved with the mean, which is
`2b52975`'s signature specifically: `write 4 KiB` p99 went 0.626 → 0.191 ms and
`open + read 4 KiB` p99 1.407 → 0.612 ms.

**Interpretation.** Per _request_ the NFS server is now comfortably ahead of the
FUSE session — 13,653 4 KiB writes per second against FUSE's 10,961, and 12,824
ops/s with 64 in flight against FUSE's 9,132 at zero timeouts — which is the useful
result, because the two share nothing but the driver interface.

Where it looks much worse is anything path-shaped: `stat walk` is 3,816 stats/s
against FUSE's 30,397, and `ls -l` is 4,972 entries/s against 28,958. That is not
the protocol being slow, it is the **absence of a kernel client**: NFS has no path
resolution on the wire, so `test/nfs/v3/client.ts` walks every component with its
own `LOOKUP`s and repeats the walk for every operation, where a real client would
have a dentry cache. The pairing confirms this from a new direction and settles it.
The loopback column underneath went 1.7–2.7× on exactly these shapes, and **these
rows did not move**: `stat` 1.01×, `ls -l` 1.03×, `stat walk` 1.06×. Whatever bounds
them is not the driver, the loopback, or the path helpers that got faster. It is the
round trips. Read the four core rows as the server's cost and the path-shaped rows
as an artifact of the test client.

**Throughput is where this sweep landed, and it changes the conclusion this section
used to draw.** The old reading — "a fifth of what the FUSE transport does, XDR
framing and a socket against a `writeSync` to a character device" — no longer holds
and must not be repeated. Compared like for like against the number that also
crosses a real transport rather than a page cache, NFS sequential read is now **62%
of FUSE's** (977 vs 1,568 MiB/s with `keepCache` off) where before the sweep it was
**25%** (325 vs 1,314), and NFS sequential write **65%** (412 vs 637) where it was
52%. A socket and XDR framing now cost roughly half again what a `writeSync` to
`/dev/fuse` costs, not four times it. Against the loopback ceiling the two
transports are 8% and 13% of 12,171 MiB/s respectively, which is the number to keep
if you want one that does not depend on which transport you started from.

---

## 9P over `trans=unix`, a real kernel mount

**A second sitting, and it says so.** Everything above was measured on
2026-07-29 at `95c2c44`; this column was measured on **2026-07-31 at `81b40a4`**
(branch `fix/9p`), on the same host, with `pnpm bench:9p`. It is a separate
command because a 9P mount needs `CAP_SYS_ADMIN` — `mount(2)`, and v9fs has no
setuid helper of the `fusermount3` kind — and a separate sitting because the
column did not exist until now. Two consequences, both handled below rather than
waved at: the numbers here come with **their own denominators**, re-measured in
this sitting (the trees differ by one commit that touches the driver every
column runs through — see [the denominator
moved](#the-denominator-moved-and-why-this-column-carries-its-own)), and every
comparison with the FUSE tables above is **cross-sitting** and marked as such.

**Two runs, minutes apart, are reported side by side.** A column whose entire
point is two untuned knobs has to show which differences survive a repeat, and
this pair measures its own spread instead of borrowing the FUSE column's: run 2
came out **12–27% faster than run 1 on nine of ten rows**, wider than the ±8%
this file calibrates elsewhere, so **treat anything under ~1.3× in this section
as no difference** unless it holds in both runs. The tenth row is `stat walk`,
which went the other way by 1.94× at `n = 3` — the single most spread-out
measurement in this file, and a reminder of what `n = 3` is worth.

The mount is the one `mount9p()` builds and `.agents/environment.md` records
verbatim: `trans=unix` over a `0700` socket, `version=9p2000.L`, `msize=131096`,
`access=client`, **`cache=none`**, one connection, the memory driver, and the
client in a child process (`bench/drive.ts`). Read `cache=none` as the headline
of the whole section: **nothing here is answered out of a kernel cache.** A
repeated `stat(2)` costs three to four messages every single time — the session
counters below show 4.3 requests per `stat(2)` over a whole variant — where the
FUSE `default` column is mostly the kernel answering itself. So compare these
rows against FUSE's `attr/entry timeout=0` variant, never against its defaults.

### Shipped defaults

| scenario                  | ops/sec | rate             |  p50 ms |  p99 ms |    n | run 2             |
| ------------------------- | ------: | ---------------- | ------: | ------: | ---: | ----------------- |
| stat                      |   2,123 | —                |   0.448 |   0.826 | 2123 | 2,381 ops/s       |
| open + read 4 KiB         |   1,392 | —                |   0.696 |   1.072 | 1392 | 1,660 ops/s       |
| write 4 KiB               |   5,486 | —                |   0.174 |   0.290 | 5486 | 6,459 ops/s       |
| readdir (100 entries)     |  865.36 | 86,536 entries/s |   1.102 |   1.755 |  866 | 109,979 entries/s |
| sequential read, 100 MiB  |    7.88 | 787.89 MiB/s     | 126.154 | 129.239 |    3 | 895.06 MiB/s      |
| sequential write, 100 MiB |    4.09 | 408.62 MiB/s     | 247.284 | 247.434 |    3 | 466.20 MiB/s      |
| create 500 small files    |    1.72 | 859.15 files/s   | 553.958 | 658.369 |    3 | 1,091 files/s     |
| ls -l (1000 entries)      |    2.24 | 2,238 entries/s  | 449.690 | 450.698 |    3 | 2,631 entries/s   |
| stat walk (500 files)     |    2.80 | 1,401 stats/s    | 357.913 | 358.982 |    3 | 721.38 stats/s    |
| stat ×64 in flight        |  200.00 | 12,800 ops/s     |   4.838 |   8.171 |  200 | 14,885 ops/s      |

**Interpretation.** This is the first column in this file where every row is a
real kernel client with no cache in front of it, and it reads that way: the
metadata rows are two to five _thousand_ operations per second where the cached
FUSE column is tens of thousands, and the throughput rows are within a factor of
two of the transports that do cache. The two comparisons worth making:

- **Against FUSE at zero timeouts** (2026-07-29 sitting, so indicative, not
  paired): `stat` 2,123–2,381/s against 3,429/s, `open + read 4 KiB`
  1,392–1,660/s against 1,924/s, `ls -l` 2,238–2,631 entries/s against 2,970,
  `stat walk` against 2,052 stats/s. 9P lands at **0.7–0.9× of an uncached FUSE
  mount on metadata** while doing strictly more work per syscall — v9fs clones a
  fid per operation, so a `stat(2)` is `Twalk`/`Tgetattr`/`Tclunk` where FUSE's is
  `LOOKUP`/`GETATTR`. On concurrency it is **ahead**: 12,800–14,885 ops/s with 64
  stats in flight against FUSE's 9,132 at zero timeouts, which is the socket and
  the event loop against `/dev/fuse` and the threadpool.
- **Against NFSv3 re-measured in this sitting** (`stat` 5,281/s, `write 4 KiB`
  14,726/s, `readdir` 128,732 entries/s, sequential read 861 MiB/s, write 475
  MiB/s, 64 in flight 12,229 ops/s): NFS wins every per-message row, and it is
  **not a like-for-like win** — that column's client is JavaScript in the same
  process with no kernel between the two, so it pays one round trip where 9P pays
  three to four plus a context switch. The rows where the two are close in spite
  of that (throughput, and 64-in-flight, where 9P is ahead) are the ones where the
  kernel client's cost is amortised.

Sequential read at 788–895 MiB/s and write at 409–466 MiB/s are **6–7% of the
loopback ceiling** measured the same day (13.1 GiB/s and 1.25 GiB/s), against
FUSE's 12% for an uncached read on the older tree. Nothing about that is
mysterious: at the shipped `msize` a 100 MiB read is 800 round trips, and the
next section prices exactly that.

**What the session sustained**, sampled off `session.stats.requests` while the
client worked — the same instrument `bench/fuse.ts` uses, and the same warning:
this is **not** any scenario's ops/sec, because one syscall is several messages.

| variant          | peak 9P requests/sec (run 1 / run 2) | requests in the run |
| ---------------- | -----------------------------------: | ------------------: |
| `default`        |                      55,440 / 62,061 |   253,604 / 270,723 |
| `msize=16KiB`    |                      17,246 / 18,981 |     82,017 / 83,641 |
| `msize=1MiB`     |                      11,394 / 13,341 |     22,711 / 26,909 |
| `maxInFlight=1`  |                      51,282 / 61,041 |     55,594 / 75,748 |
| `maxInFlight=64` |                      72,143 / 84,677 |    90,599 / 103,947 |

**This is the highest request rate any transport in this file has been measured
at: 72–85 k messages per second peak, 55–62 k at the shipped defaults**, against
the FUSE session's 20–50 k from the 2026-07-28 direct sampling. It is a peak over
a 250 ms window on a variant's whole mix, so read it as a ceiling rather than as
a sustained rate — but it settles the direction of IDEA.md's "low tens of
thousands of ops/sec" for this transport: at the _message_ level 9P is comfortably
above it, and the reason a user sees 2,000 `stat`s a second anyway is that v9fs
spends three to four messages on each one.

The message census confirms what `.agents/environment.md` found by hand, on a
much larger sample — the `default` variant's run 1, in order:

```
Tgetattr=80495 Twalk=68437 Tclunk=64684 Twrite=13158 Txattrwalk=9661 Tread=4601
```

Walk and clunk dominate, `Tgetattr` outnumbers `Twalk`, and there is roughly one
`Txattrwalk` — the `security.*` probe, refused cheaply — per file created. **The
fid table is the hot data structure in this transport, not the codec**, and any
future optimization work should start there.

### `msize`, measured

The knob the roadmap called untuned. `mountMsize` is the client's proposal; the
negotiated value is the smaller of it and the session's own ceiling, and the
figure below is what the session reported after `Tversion`. The default is
131096 = 128 KiB + `P9_IOHDRSZ`, character for character the kernel's own. Every
cell is `run 1 / run 2`, as in the table above.

| scenario                  |                msize=16 KiB |           **131096 (default)** |               msize=1 MiB |
| ------------------------- | --------------------------: | -----------------------------: | ------------------------: |
| sequential read, 100 MiB  |       258.89 / 278.27 MiB/s |      **787.89 / 895.06 MiB/s** |       1,015 / 1,176 MiB/s |
| sequential write, 100 MiB |       190.49 / 188.10 MiB/s |      **408.62 / 466.20 MiB/s** |     475.05 / 598.30 MiB/s |
| write 4 KiB               |         5,400 / 6,032 ops/s |        **5,486 / 6,459 ops/s** |       4,897 / 6,286 ops/s |
| readdir (100 entries)     | 100,233 / 103,950 entries/s | **86,536 / 109,979 entries/s** | 84,365 / 98,592 entries/s |

**The default is worth 3.0–3.2× on sequential read and 2.1–2.5× on sequential
write against the 16 KiB the kernel shipped for years**, and both ratios hold in
both runs, well clear of this column's spread. That is the clearest measured win
in the section and it is entirely mechanical: 100 MiB at 16 KiB a message is
6,400 round trips, at 131096 it is 800.

**Raising it further to the 1 MiB ceiling is worth another 1.29× / 1.31× on read
and 1.16× / 1.28× on write** — a real effect, repeated, and much smaller than the
step below it, exactly as an 8× reduction in an already-small round-trip count
should be. It is **not free**: `msize` is the per-request allocation on both ends
(the kernel allocates from a `kmem_cache` of exactly this size, and this server's
frame assembler adopts the negotiated value), so 1 MiB is 8× the memory per
in-flight request for ~1.3× the bulk throughput. With `maxInFlight` at 16 that is
16 MiB of reply headroom per connection instead of 2.

**Nothing else moves with it, in either direction.** `write 4 KiB` is 0.89×–1.07×
across a 64× change in `msize` — a 4 KiB write fits in every one of them — and
`readdir` of a 100-entry directory is 0.86×–1.06×, because one page carries the
whole listing at any of these sizes. Both are controls, and both come back flat,
which is what makes the throughput rows readable.

**The recommendation the numbers support:** leave `mountMsize` alone. Raise it
toward `P9_MAX_MOUNT_MSIZE` only for a bulk-transfer workload on a connection
count you can afford the memory for, and expect ~1.3×, not a step change.

### The dispatch window (`maxInFlight`), measured

`DEFAULT_MAX_IN_FLIGHT = 16` (`src/9p/server.ts`) is how many requests one
connection answers at once before the rest wait as frames. It can only matter
when requests are actually in flight, so these two rows are the whole
experiment — 64 concurrent `stat`s, and a strictly sequential `stat` as the
control.

| scenario           | maxInFlight=1         | **16 (default)**          | maxInFlight=64        |
| ------------------ | --------------------- | ------------------------- | --------------------- |
| stat ×64 in flight | 11,981 / 12,984 ops/s | **12,800 / 14,885 ops/s** | 17,184 / 20,025 ops/s |
| stat (sequential)  | 507\* / 2,809 ops/s   | **2,123 / 2,381 ops/s**   | 2,522 / 2,746 ops/s   |

\* an outlier, and named as one: `mean` 1.971 ms against a `p50` of 0.517 ms and
a `p99` of 16.666 ms, i.e. a handful of multi-millisecond stalls in an otherwise
normal run, **not reproduced** — the second run of the same variant measured
2,809 ops/s with a 0.482 ms p99. It is left in the table rather than dropped,
because a window of 1 is the configuration where a stall of that shape is at
least plausible, and one unreplicated observation is exactly the kind of thing
this file should record without believing.

**Widening the window to 64 is worth 1.34× / 1.35× on the 64-in-flight
scenario**, in both runs, which is the only claim here that clears the spread.
The mechanism is visible in the counters above: that variant's peak message rate
is 72–85 k/s against the default's 55–62 k. **Closing it to 1 costs only
0.87×–0.94×** on the same scenario — much less than the 16× change in the knob
suggests, and the reason is that the window bounds _dispatch_, not the kernel:
v9fs keeps its own handful of requests outstanding per mount, so the queue behind
a window of 1 is short and the frames waiting in it cost their wire size.

**The recommendation the numbers support:** leave `maxInFlight` at 16 for a
mount. It is a memory bound first and a throughput knob second — the replies
alive at once are `maxInFlight × msize` — and the ~1.34× at 64 is only reachable
by a client that keeps dozens of requests outstanding, which the kernel's own
client does not do for ordinary work. Raise it, with the memory arithmetic in
hand, for a `createP9Server` serving several attached clients.

### What this column does not say

- **Nothing about `cache=`.** Every mount here is the shipped `cache=none`, so
  there is no warm/cold distinction to draw and no `ls -l (cold)` row of the kind
  the FUSE column runs. Raising `cache=` would measure the bet documented on
  `MountP9Options.cache` — that nothing but the mount modifies the driver — and
  that is a semantics decision, not a benchmark one.
- **Nothing about `trans=tcp`.** Every row is the default unix socket. A TCP
  mount is the VM-guest shape and would be measuring the loopback stack.
- **Nothing about multiple clients.** One connection, one session, one fid table.

### The denominator moved, and why this column carries its own

The 9P column's sitting is two days and one `src/` commit after the rest of the
file, so the loopback column was re-measured in it — and **a paired run, in this
sitting, of `95c2c44` against `81b40a4` shows the shared denominator moving**:

| loopback scenario     | `95c2c44`            | `81b40a4` (two runs)            |                  ratio |
| --------------------- | -------------------- | ------------------------------- | ---------------------: |
| readdir (100 entries) | 10,323,455 entries/s | 5,421,611 / 5,230,716 entries/s |      **0.53× / 0.51×** |
| stat                  | 1,086,332 ops/s      | 900,930 / 849,935 ops/s         |          0.83× / 0.78× |
| stat ×64 in flight    | 1,437,160 ops/s      | 1,226,443 / 1,194,581 ops/s     |          0.85× / 0.83× |
| ls -l (1000 entries)  | 867,224 entries/s    | 755,421 / 764,958 entries/s     |          0.87× / 0.88× |
| stat walk (500 files) | 982,499 stats/s      | 895,877 / 924,847 stats/s       |          0.91× / 0.94× |
| everything else       | —                    | —                               | 0.96×–1.15×, i.e. flat |

Method: a `git worktree` at `95c2c44`, `node bench/index.ts` in it, and the same
command on `81b40a4`, minutes apart on this host — the discipline
[stated above](#the-baseline-and-why-there-is-one), applied in the direction it
was written for. The only commit touching `src/` between the two trees is
`5defab0` (`mountx.mknod` and the memory driver's special files), so **the
`readdir` half is a real, paired, 1.9× regression in the memory driver**, not a
day-to-day difference; the 0.83×/0.85× rows are smaller and less certain.

Three things follow. It is a **driver** finding, not a 9P one — no transport row
shows it, because at 100 entries a round trip costs more than an entry does (NFS
`readdir` is 128,732 entries/s this sitting against 130,860 on 2026-07-29, i.e.
unmoved). It is **not chased here**, because this milestone is a benchmark
column. And it is precisely why the 9P section quotes denominators from its own
sitting: reading a 9P number against the loopback table above would have credited
this transport with a change in the driver underneath it.

---

## What the sweep moved

`0f359e7` (+ the type-stripping fix) against `95c2c44`, both measured in this
sitting on this host. Ratios are swept ÷ baseline, so **above 1 is faster after**.
Read anything from 0.93× to 1.15× as no change (see
[the calibration](#reading-these-numbers)); the `n = 3` rows are marked.

**Loopback** — `0ee70d6` (loopback rebind, `normalizePath` fast path) and
`e80c8ff` (`memory.readdir`, `memory.statfs`).

| scenario                  |            baseline |                swept |       ratio |
| ------------------------- | ------------------: | -------------------: | ----------: |
| stat walk (500 files)     |     423,052 stats/s |    1,152,689 stats/s |   **2.72×** |
| stat ×64 in flight        |       782,082 ops/s |      1,591,151 ops/s |   **2.03×** |
| stat                      |       611,564 ops/s |      1,093,940 ops/s |   **1.79×** |
| ls -l (1000 entries)      |   567,300 entries/s |    992,239 entries/s |   **1.75×** |
| open + read 4 KiB         |       423,127 ops/s |        731,105 ops/s |   **1.73×** |
| readdir (100 entries)     | 7,362,071 entries/s | 10,847,957 entries/s |   **1.47×** |
| create 500 small files    |     266,961 files/s |      311,601 files/s | 1.17× (n=3) |
| write 4 KiB               |     1,912,490 ops/s |      1,983,062 ops/s |       1.04× |
| sequential write, 100 MiB |         1,210 MiB/s |          1,257 MiB/s | 1.04× (n=3) |
| sequential read, 100 MiB  |        13,537 MiB/s |         12,171 MiB/s | 0.90× (n=3) |

**NFSv3** — `16e99b8`, `5488085`, `2b52975`, `0747df0`.

| scenario                  |         baseline |             swept |           ratio |
| ------------------------- | ---------------: | ----------------: | --------------: |
| sequential read, 100 MiB  |     324.74 MiB/s |      977.16 MiB/s | **3.01×** (n=3) |
| readdir (100 entries)     | 70,180 entries/s | 130,860 entries/s |       **1.86×** |
| write 4 KiB               |      7,844 ops/s |      13,653 ops/s |       **1.74×** |
| sequential write, 100 MiB |     264.61 MiB/s |      411.79 MiB/s | **1.56×** (n=3) |
| open + read 4 KiB         |      2,924 ops/s |       4,115 ops/s |       **1.41×** |
| stat ×64 in flight        |     11,483 ops/s |      12,824 ops/s |           1.12× |
| create 500 small files    |    2,243 files/s |     2,399 files/s |     1.07× (n=3) |
| stat walk (500 files)     |    3,588 stats/s |     3,816 stats/s |           1.06× |
| ls -l (1000 entries)      |  4,812 entries/s |   4,972 entries/s |           1.03× |
| stat                      |      5,102 ops/s |       5,177 ops/s |           1.01× |

**FUSE** — `c7ee989`, `7185f33`. The `default` variant is mostly kernel cache, so
the four indented variant rows below it are where the transport's own change is
legible.

| scenario                           |          baseline |             swept |           ratio |
| ---------------------------------- | ----------------: | ----------------: | --------------: |
| sequential write, 100 MiB          |      507.53 MiB/s |      636.75 MiB/s | **1.25×** (n=3) |
| readdir (100 entries)              | 123,769 entries/s | 148,273 entries/s |       **1.20×** |
| ls -l (1000 entries)               |  26,660 entries/s |  28,958 entries/s |           1.09× |
| stat ×64 in flight                 |     121,608 ops/s |     128,600 ops/s |           1.06× |
| sequential read, 100 MiB           |       5,936 MiB/s |       6,221 MiB/s |     1.05× (n=3) |
| stat                               |      32,702 ops/s |      33,434 ops/s |           1.02× |
| ls -l (1000 entries, cold)         |   9,680 entries/s |   9,602 entries/s |           0.99× |
| create 500 small files             |     2,359 files/s |     2,303 files/s |     0.98× (n=3) |
| stat walk (500 files)              |    31,755 stats/s |    30,397 stats/s |           0.96× |
| write 4 KiB                        |      11,987 ops/s |      10,961 ops/s |           0.91× |
| open + read 4 KiB                  |       4,918 ops/s |       4,190 ops/s |           0.85× |
| — `keepCache=off`, seq read        |       1,314 MiB/s |       1,568 MiB/s | **1.19×** (n=3) |
| — `readdirplus=off`, readdir       | 142,526 entries/s | 171,638 entries/s |       **1.20×** |
| — `no AUTO` (always plus), readdir |  93,874 entries/s |  95,297 entries/s |           1.02× |
| — `timeout=0`, write 4 KiB         |      11,894 ops/s |      11,895 ops/s |           1.00× |

The last four FUSE rows are the sharpest single result in this table, because they
split a claim into the half that should move and the half that should not.
`7185f33` stopped a plain `READDIR` binding an inode per entry and left
`READDIRPLUS`, which legitimately acquires one, alone — and the plain path is 1.20×
where the always-plus path is 1.02×. That is the commit message, measured.

### What is left open, and small

Three rows are slower after the sweep by more than the calibration comfortably
absorbs. They are recorded as open rather than explained, because neither available
story is proved.

- **FUSE `open + read 4 KiB`, 4,918 → 4,190 ops/s (0.85×).** The largest residue,
  and the interesting thing about it is where the loss sits: **p50 moved only
  0.196 → 0.209 ms (−6.6%) while p99 went 0.318 → 0.889 ms (2.8×)**. A slower code
  path shows up in p50; this is in the tail. The same scenario is 0.99× in the
  `timeout=0` variant and 0.97× in `keepCache=off`, i.e. flat in both variants where
  the kernel cache is out of the way — so whatever it is, it is not in a path the
  sweep touched.
- **FUSE `write 4 KiB`, 11,987 → 10,961 ops/s (0.91×).** Right at the edge of the
  ±8% spread, and the two other measurements of the same thing in the same pair are
  1.00× (`timeout=0`) and 0.95× (`maxWrite=128KiB`). Reads as noise; it is listed
  because the mean of the three is −5% rather than zero.
- **Loopback `sequential read`, 13,537 → 12,171 MiB/s (0.90×), `n = 3`.** Nothing
  in `c7ee989..95c2c44` touches `memory`'s read path — `e80c8ff` changed `readdir`
  and `statfs`, both of which improved as advertised in the same run. The FUSE
  page-cached read, which is the same memcpy behind a mount, went the other way
  (1.05×, also `n = 3`).

**What would settle them:** repeat the paired A/B several times and take medians
per row, and raise the iteration count on the throughput scenarios so the `n = 3`
rows stop being `n = 3`. One paired run cannot separate a 10% effect from this
host's spread, and this host is a container on a shared machine. In the meantime do
**not** claim the sweep caused these, and do not claim the host did — the first is
contradicted by the variants that stayed flat, and the second is unproved.

---

## A real bug the benchmarks found

**The memory driver grew files in O(n²).** `resize()` allocated a new
`Uint8Array` of exactly the new size and copied the old one into it on _every_
growth, and a file arrives in `max_write`-sized chunks — so writing 100 MiB in
1 MiB `WRITE`s moved ~5 GiB. It showed up as the loopback column, which is
supposed to be the ceiling, being _slower_ than the transports it was the
denominator for:

|                                    |      before |      after (2026-07-28) | now (this sitting) |
| ---------------------------------- | ----------: | ----------------------: | -----------------: |
| loopback, sequential write 100 MiB | 60.43 MiB/s |   1,382 MiB/s (**23×**) |        1,257 MiB/s |
| NFS, sequential write 100 MiB      | 53.18 MiB/s | 308.03 MiB/s (**5.8×**) |       411.79 MiB/s |

The before/after pair is a single controlled comparison from the sweep that found
it, and is left as it was measured. The third column is where those two rows sit
today: the loopback within this host's spread of where the fix left it, and the NFS
row a further **1.56×** up on its own paired baseline (264.61 MiB/s) for a reason
that has nothing to do with the driver — `16e99b8` and `5488085`, above.

Fixed in `src/drivers/memory.ts`: `node.data` is still a view of exactly the file's
length, but the buffer under it is grown geometrically, so the copying is
amortised. Shrinking keeps the capacity unless the file lost three quarters of its
size, so `truncate(f, 0)` still returns the memory. The `EFBIG` behaviour pjdfstest
pinned is preserved — doubling is attempted first and the exact size is the
fallback, and only a failure of _both_ is `EFBIG`.

Worth noticing what this says about the benchmark suite: it caught a bug that made
a _transport_ look 5× slower than it was. Without the loopback column as a
denominator, 53 MiB/s over NFS would have looked like an NFS number.

## Known gaps

- **Only one concurrency mode exists.** IDEA.md describes three — relay,
  sync-driver-in-workers, and exec mode with an async driver — and v1 has the
  third only. Everything above is main-thread async, which is why the reader count
  does not move the numbers and why the request ceiling sits in the tens of
  thousands: they all land on one thread. The sync-worker mode is the one IDEA.md
  expects to be "meaningfully better and scale with worker count"; **that claim is
  unmeasured and must not appear in the README or the docs.**
- **The FUSE request counter was not re-measured.** `bench/fuse.ts` collects it but
  only emits it under `--json`, and this sitting was run without. The ceiling
  section's table is therefore older than everything around it, and the numbers this
  sitting _can_ support are lower bounds. Anyone regenerating this file should pass
  `--json` to every command.
- **One paired run, not several.** The baseline makes attribution possible; it does
  not make a 10% delta readable. Medians over repeated pairs would, and would also
  retire [the three open rows](#what-is-left-open-and-small).
- **No NFSv4.1 or S3 column.** Both ship, NFSv4.1 is in the conformance matrix,
  and neither has a `bench/` column — so no number may be quoted for either,
  including in `docs/2.transports/`.
- **The 9P column is a second sitting, and only two runs of it.** Its own
  numbers are paired against denominators taken with them, so they stand on their
  own; what does not stand is a FUSE-versus-9P table, because no sitting has yet
  measured both. `pnpm bench && pnpm bench:root && pnpm bench:9p` in one sitting
  would produce one, and would be the right way to regenerate this whole file
  next time. Until then, every cross-transport sentence in the 9P section is
  marked indicative and must stay that way.
- **One driver.** Every number is against the in-memory driver, on purpose: it
  isolates the transport. A driver that does real I/O will be bounded by its own
  latency long before any of these ceilings, which is the honest thing to tell a
  user asking "how fast is it".
- **No kernel NFS client.** The NFS column is the server's cost plus TCP, and
  cannot be anything else on this host.
- **No `git status` / `tar -x` / build-tree macro-benchmark.** The scenarios are
  synthetic; the record/replay fixtures (`test/fixtures/*.fuse`) contain real
  traffic from `ls -laR`, `find` and `tar -xp`, but they are correctness fixtures,
  not timed workloads.
