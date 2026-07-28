#!/bin/sh
# Clone, build and run pjdfstest against a real mountx FUSE mount.
#
#   sh test/pjdfstest/run.sh            # everything
#   sh test/pjdfstest/run.sh chmod      # one category (any path fragment)
#
# The clone is gitignored and pinned to PJDFSTEST_COMMIT below: the suite is
# the *measurement instrument*, so it has to be the same instrument every time.
# The analysis of what it measured is committed, in `.agents/pjdfstest-results.md`.
#
# pjdfstest requires root for almost everything it does (it changes uid to test
# permission enforcement), and so does mounting here, so the whole run is under
# sudo. `run.ts` mounts, runs each `.t` as a child process, and unmounts.
set -eu

PJDFSTEST_REPO=https://github.com/pjd/pjdfstest
PJDFSTEST_COMMIT=ededbeb2b44929972898afb87474b0937f78a877

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
suite="$here/pjdfstest"

if [ ! -d "$suite/.git" ]; then
  echo "cloning pjdfstest into $suite"
  git clone --quiet "$PJDFSTEST_REPO" "$suite"
fi
git -C "$suite" fetch --quiet origin "$PJDFSTEST_COMMIT" 2>/dev/null || true
git -C "$suite" checkout --quiet "$PJDFSTEST_COMMIT"

if [ ! -x "$suite/pjdfstest" ]; then
  echo "building pjdfstest (autoreconf, configure, make)"
  (cd "$suite" && autoreconf -ifs >/dev/null && ./configure >/dev/null && make pjdfstest >/dev/null)
fi

echo "pjdfstest $(git -C "$suite" rev-parse --short HEAD) against a mountx memory-driver mount"
status=0
sudo env UV_THREADPOOL_SIZE=32 "$(command -v node)" "$here/run.ts" "$@" || status=$?

# The run is root's; the files it leaves behind are not.
sudo chown "$(id -u):$(id -g)" "$here/results.txt" "$here/results.json" 2>/dev/null || true
exit $status
