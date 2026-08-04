/**
 * The conformance matrix, 9P column.
 *
 * IDEA.md's organizing idea again: *one* suite written against the driver
 * interface, run every way the library can carry it. `drivers.test.ts` runs it
 * through the loopback harness, `test/fuse/conformance-mount.test.ts` through a
 * real kernel mount, `test/nfs/v3/conformance.test.ts` through an NFS server — and
 * this file runs it through the **whole 9P2000.L stack**, with a JavaScript
 * client on the far end.
 *
 * Tier 1: no root, no mount, no kernel — which is the only way this column can
 * exist at all before step 9, and worth keeping afterwards for the same reason
 * the NFS one is. Every call travels the real codecs in both directions:
 * `p9Driver` encodes a `T`-message, `P9Session.handleCall` decodes it, answers
 * from the driver, encodes the `R`-message, and the client decodes that. There
 * is no shortcut into the session anywhere.
 *
 * A fresh session, a fresh attach and a fresh driver per test, so the isolation
 * is exactly the loopback column's: an empty filesystem, not an empty
 * directory.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect } from "vitest";
import { P9Session } from "../../src/9p/session.ts";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { createLoopback, type Loopback, type ResolvedCapabilities } from "../../src/harness.ts";
import type { FsDriver } from "../../src/types.ts";
import { conformance } from "../conformance.ts";
import { rootedNodeFs } from "../rooted-node-fs.ts";
import { P9Client, p9Driver } from "./client.ts";

/**
 * What survives the trip through 9P2000.L.
 *
 * Declared rather than derived, because this is the column's *claim*. Unlike
 * NFS's it is very nearly "everything", and the difference is the protocol's:
 *
 * - **`handles: true`**, where NFSv3 has to say `false`. A fid is server-side
 *   open state — `Tlopen` really opens the driver's file, `Tclunk` really
 *   closes it — so a file unlinked while open stays readable through the fid
 *   that holds it, with no silly-rename anywhere. This is the capability the
 *   plan's `["fuse", "9p", "nfs"]` preference order is *about*.
 * - **`extensions: ["mknod"]`**, which the other transport columns do not
 *   claim. 9P2000.L has an operation for it and carries the whole `mode`, type
 *   bits included: `p9Driver`'s `mountx.mknod` is a `Tmknod`,
 *   `P9Session.#mknod` passes the mode to the driver's extension unchanged, and
 *   every refusal the cases assert — `EEXIST`, `ENOENT`, `EPERM` for a
 *   directory — is the far side's answer arriving as `Rlerror`. That is the
 *   capability *carried*, not declared over: a client offering a by-name handle
 *   onto a wire operation is what a driver adapter is. `utimens` stays off the
 *   list: `Tsetattr` carries the nanoseconds, but this client spends them
 *   through `utimes`/`lutimes` and never asks for the extension by name.
 *
 *   What the extension cases buy over `session.test.ts`'s dispatch tests is the
 *   rest of the surface: `stat` and `readdir` agreeing on the seven type
 *   predicates off the wire's own encoding, `rdev` surviving the `major`/`minor`
 *   split and `Rgetattr`'s single `rdev[8]` rejoining it, and a FIFO behaving
 *   as an ordinary name under `rename` and `unlink` afterwards.
 *
 * Everything else — hardlinks, symlinks, permissions, times, truncate, atomic
 * rename, `statfs` — crosses intact, and each of those is a message of its own
 * (`Tlink`, `Tsymlink`/`Treadlink`, `Tsetattr`, `Trenameat`, `Tstatfs`).
 *
 * Nothing here is faked to make a case pass: the one gap 9P really has is
 * extended attributes (`Txattrwalk`/`Txattrcreate` answer `ENOTSUP`), and the
 * driver interface has no notion of them, so the suite never asks. Byte-range
 * locks are answered from `src/9p/locks.ts` rather than granted blind, and are
 * not a driver capability either — they are arbitrated between clients here and
 * never reach the driver.
 */
const THROUGH_9P: ResolvedCapabilities = {
  handles: true,
  atomicRename: true,
  hardlinks: true,
  symlinks: true,
  permissions: true,
  times: true,
  truncate: true,
  caseSensitive: true,
  statfs: true,
  readOnly: false,
  // Not a wire property at all: it is a claim about the driver behind the
  // mount, and every driver these suites use leaves it unclaimed.
  durableWrites: false,
  extensions: ["mknod"],
};

/**
 * The same, for a driver with no per-open state.
 *
 * One capability differs and it is the one that cannot survive: a `handles:
 * false` driver has nothing for `Tlopen` to keep, so every `Tread`, `Twrite`
 * and `Tfsync` re-opens the fid's *path* (`#withHandle`), and a path that has
 * been unlinked cannot be re-opened. That is the honest degradation FUSE
 * documents for the same model, and the suite's "keeps an open handle readable
 * after unlink" case is skipped rather than passed by some other route.
 *
 * Everything else is identical, which is the point of running the column at
 * all: the re-open path is where `reopenFlags()` matters (an `O_TRUNC` repeated
 * on every write empties the file each time, an `O_EXCL` fails every one), and
 * this is the only place that path is exercised across a whole filesystem's
 * worth of operations rather than a handful of session tests.
 */
const THROUGH_9P_REOPENED: ResolvedCapabilities = { ...THROUGH_9P, handles: false };

/** Every session this file made, checked for assertion failures on the way out. */
const sessions: P9Session[] = [];

afterEach(() => {
  for (const session of sessions.splice(0)) {
    // The exactly-one-reply bookkeeping, asserted for every request the suite
    // sent: a conformance run is several thousand of them per file.
    expect(session.assertions).toEqual([]);
    expect(session.stats.requests).toBe(session.stats.replies + session.stats.dropped);
  }
});

/** Stand a session up over `driver`, negotiate, and attach its root to fid 0. */
async function serve(driver: FsDriver): Promise<{ fs: Loopback; cleanup: () => Promise<void> }> {
  const session = new P9Session(driver);
  sessions.push(session);
  const client = P9Client.overSession(session);
  await client.version();
  await client.attach(0);
  return {
    fs: createLoopback(p9Driver(client, 0)),
    cleanup: () => session.destroy(),
  };
}

describe("over a 9P2000.L session", () => {
  conformance({
    name: "memory driver, over 9P",
    capabilities: THROUGH_9P,
    setup: () => serve(createMemoryDriver()),
  });

  conformance({
    name: "memory driver with no handles, over 9P",
    capabilities: THROUGH_9P_REOPENED,
    setup: () => {
      const base = createMemoryDriver();
      // The same store, declaring no per-open state: what a driver whose bytes
      // live somewhere other than in a handle looks like to this session.
      return serve({ ...base, capabilities: { ...base.capabilities, handles: false } });
    },
  });

  conformance({
    name: "node-fs oracle, over 9P",
    /*
     * `THROUGH_9P`, minus the one entry that is the *driver's* to answer rather
     * than the transport's: the oracle implements no `mountx.mknod`, so
     * `#mknod` answers `ENOSYS` for every type but a regular file, exactly as
     * it should. The column carries the extension; this target has none to
     * carry, and declaring one here is the difference between a capability and
     * a claim.
     */
    capabilities: { ...THROUGH_9P, extensions: [] },
    /*
     * The oracle forwards the host kernel's errors, so the *code* is pinned and
     * the *number* is allowed to be either family's.
     *
     * Which is a narrower allowance here than it looks, and narrower than the
     * NFS column's: `Rlerror` carries the number `errnoOf()` produced, and that
     * is looked up from the error's `code` in `src/errors.ts`'s transcribed
     * Linux table — so what goes on the wire is a Linux errno on every host,
     * and what the client rebuilds from it is a Linux errno too. The mode is
     * declared for the one thing it still buys: `unlink` of a directory, where
     * the BSDs say `EPERM` and Linux says `EISDIR`, and the disagreement is
     * about the code rather than the number.
     */
    errors: "host",
    setup: async () => {
      const backing = await mkdtemp(join(tmpdir(), "mountx-9p-"));
      const served = await serve(rootedNodeFs(backing));
      return {
        fs: served.fs,
        cleanup: async () => {
          await served.cleanup();
          await rm(backing, { recursive: true, force: true });
        },
      };
    },
  });
});
