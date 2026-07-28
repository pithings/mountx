#!/bin/sh
# Run Tier-2 (root, /dev/fuse, real mount) vitest files under sudo.
#
#   sh test/root.sh test/fuse/mount.test.ts [...]
#
# Three things this wrapper exists for:
#
# - `sudo` needs an absolute path to node: root's PATH has no version-manager
#   shims on it.
# - `UV_THREADPOOL_SIZE` must be raised *before the process starts*, because a
#   test process is on both sides of every request — see the note at the top of
#   `src/fuse/mount.ts`.
# - `TMPDIR` is redirected so root's vitest caches and sandboxes do not
#   accumulate in a `/tmp` the developer cannot delete afterwards. It is removed
#   again unless something is still mounted underneath it.
#
# File parallelism is off: two suites serving mounts at once is a thread-budget
# question nobody should have to think about.
#
# `sudo` resets the environment, so anything a suite reads from it has to be
# carried across explicitly. Every `MOUNTX_*` variable is forwarded — that is
# the namespace the suites use for knobs like `MOUNTX_DIFF_SEED`. (Values
# containing whitespace are not supported, and none of the knobs have any.)
set -u

TMP=/tmp/mountx-vitest
mkdir -p "$TMP"

forward=""
for name in $(env | sed -n 's/^\(MOUNTX_[A-Za-z0-9_]*\)=.*/\1/p'); do
  eval "value=\$$name"
  forward="$forward $name=$value"
done

# shellcheck disable=SC2086 -- `$forward` must word-split into NAME=VALUE pairs.
sudo env TMPDIR="$TMP" UV_THREADPOOL_SIZE=32 $forward "$(command -v node)" \
  node_modules/vitest/vitest.mjs run --no-file-parallelism "$@"
status=$?

# Do not delete the scratch directory while something is still mounted under
# it. macOS has no `/proc`, so the table comes from `mount(8)` there — and a
# table that cannot be read at all means "leave it alone", not "clean it up".
if [ -r /proc/self/mounts ]; then
  table=$(cat /proc/self/mounts)
else
  table=$(mount) || table=" $TMP"
fi
printf '%s\n' "$table" | grep -q " $TMP" || sudo rm -rf "$TMP"
exit $status
