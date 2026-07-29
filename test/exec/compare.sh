#!/bin/sh
# SPIKE harness: build the three interception mechanisms and run one identical
# workload through each, so the comparison in `.agents/proot-plan.md` is
# measured rather than argued.
#
#   sh test/exec/compare.sh
#
# Needs a Zig toolchain (spikes B and C are native), unprivileged user
# namespaces (spike A) and nothing else. No root anywhere.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${MOUNTX_SPIKE_OUT:-${TMPDIR:-/tmp}/mountx-spike}
mkdir -p "$OUT"
cd "$ROOT"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
row() { printf '  %-22s %s\n' "$1" "$2"; }

say "building fixtures and mechanisms into $OUT"
# One workload, three linkages — the axis the whole comparison turns on.
zig cc test/exec/probe.c -O2 -o "$OUT/probe-glibc"
zig cc -target x86_64-linux-musl -static test/exec/probe.c -O2 -o "$OUT/probe-musl"
# -ffreestanding -fno-builtin or the compiler turns the hand-written loops back
# into calls to the libc this binary deliberately does not have.
zig cc -target x86_64-linux-none -nostdlib -static -ffreestanding -fno-builtin \
  test/exec/probe-raw.c -O2 -o "$OUT/probe-raw"
( cd src/exec && zig build-lib -dynamic -lc -fPIC -O ReleaseSmall \
    -femit-bin="$OUT/libmountx-shim.so" preload/shim.zig )
( cd src/exec && zig build-exe -lc -O ReleaseSmall -femit-bin="$OUT/mountx-trace" \
    --dep p9 -Mroot=seccomp/trace.zig -Mp9=preload/p9.zig )
row "shim" "$(wc -c < "$OUT/libmountx-shim.so") bytes"
row "supervisor" "$(wc -c < "$OUT/mountx-trace") bytes"

export MOUNTX_SHIM="$OUT/libmountx-shim.so"
export MOUNTX_TRACE="$OUT/mountx-trace"

# The checksum every passing run must produce over the 3 MiB file. Any
# divergence here is a correctness failure, not a coverage gap — which is the
# distinction that matters most, since one of the mechanisms was briefly
# capable of returning a clean, confident, wrong answer.
EXPECT=ae82061e44e22325

probe() { # <spike-runner> <probe>
  out=$(timeout 60 node "$1" "$OUT/$2" 2>&1 || true)
  if printf '%s' "$out" | grep -q "fnv=$EXPECT"; then
    printf 'pass'
  elif printf '%s' "$out" | grep -q 'fnv='; then
    printf 'WRONG DATA'
  else
    printf 'fail'
  fi
}

# Each column is one *named* mechanism, run through its own demo runner, so the
# comparison never depends on what the picker in `mountx/exec` would have chosen.
for spike in userns preload seccomp; do
  case $spike in
    userns)  name="A  userns + FUSE" ;;
    preload) name="B  LD_PRELOAD" ;;
    seccomp) name="C  seccomp notify" ;;
  esac
  say "spike $name"
  for p in probe-glibc probe-musl probe-raw; do
    row "$p" "$(probe "src/exec/demo-$spike.ts" "$p")"
  done
done

say "coreutils workload (glibc, the case all three claim)"
WORK='
  set -e
  ls "$MOUNTX_ROOT" >/dev/null
  cat "$MOUNTX_ROOT/hello.txt" >/dev/null
  sha256sum "$MOUNTX_ROOT/big.bin" | cut -c1-16
  wc -l < "$MOUNTX_ROOT/numbers.txt"
  tail -1 "$MOUNTX_ROOT/numbers.txt"
  find "$MOUNTX_ROOT" -type f | wc -l
  du -s "$MOUNTX_ROOT" | cut -f1
'
for spike in userns preload seccomp; do
  printf '  %-8s: ' "$spike"
  timeout 90 node "src/exec/demo-$spike.ts" sh -c "$WORK" 2>&1 |
    grep -vE '^\[(userns|preload|seccomp)' | tr '\n' ' '
  printf '\n'
done

say "write-back (does what the command wrote actually reach the driver?)"
# The axis that separates the three, and the one worth measuring rather than
# claiming: the seccomp supervisor answered `openat` from an injected `memfd`
# until this was closed, so every one of these reported success and changed
# nothing. A mechanism that prints anything but the four expected words here is
# losing data quietly, which is worse than failing.
WRITES='
  echo created > "$MOUNTX_ROOT/w.txt"
  cat "$MOUNTX_ROOT/w.txt"
  echo appended >> "$MOUNTX_ROOT/w.txt"
  tail -1 "$MOUNTX_ROOT/w.txt"
  printf ab | dd of="$MOUNTX_ROOT/w.txt" bs=1 seek=0 conv=notrunc 2>/dev/null
  head -c 2 "$MOUNTX_ROOT/w.txt"; echo
  rm -f "$MOUNTX_ROOT/w.txt"
  test -e "$MOUNTX_ROOT/w.txt" && echo "STILL THERE" || echo removed
'
for spike in userns preload seccomp; do
  printf '  %-8s: ' "$spike"
  timeout 90 node "src/exec/demo-$spike.ts" sh -c "$WRITES" 2>&1 |
    grep -vE '^\[(userns|preload|seccomp)' | tr '\n' ' '
  printf '\n'
done

say "done — expected sha prefix bfe74807c87a6443, 5 files, 3082 blocks"
say "     — expected writes: created appended ab removed"
