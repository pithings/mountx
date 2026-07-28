#!/bin/sh
# Run the Tier-2 *unprivileged* mount suite.
#
#   sh test/rootless.sh test/fuse/mount-rootless.test.ts [...]
#
# The absence of `sudo` here is the feature. Everything `root.sh` does to
# survive being root — an absolute path to node, a redirected `TMPDIR`,
# forwarded `MOUNTX_*` — is unnecessary when the suite runs as the developer.
#
# What is still necessary is `UV_THREADPOOL_SIZE`, and for the same reason: the
# test process is on both sides of every request, so the read loop and the
# suite's own `fs` calls are competing for the same four threads by default.
# See the note at the top of `src/fuse/mount.ts`.
#
# File parallelism is off: two suites serving mounts at once is a thread-budget
# question nobody should have to think about.
set -u

UV_THREADPOOL_SIZE=32 node node_modules/vitest/vitest.mjs run --no-file-parallelism "$@"
