/**
 * The conformance matrix, NFS column.
 *
 * IDEA.md's organizing idea, third column: *one* suite written against the
 * driver interface, run every way the library can carry it. `drivers.test.ts`
 * runs it through the loopback harness, `test/fuse/conformance-mount.test.ts`
 * through a real kernel mount — and this file runs it through the **whole NFS
 * stack over a real TCP socket**, with a JavaScript client on the far end.
 *
 * Tier 1: no root, no mount, no kernel. That is the property IDEA.md points out
 * as inverting the usual assumption — NFS is one of the *easiest* transports to
 * get under test, because its client can be written from the server's own
 * codecs.
 *
 * A fresh server, a fresh connection and a fresh driver per test, so the
 * isolation is exactly the loopback column's: an empty filesystem, not an empty
 * directory.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../../src/drivers/memory.ts";
import { createNodeFsDriver } from "../../../src/drivers/node-fs.ts";
import { createLoopback, type ResolvedCapabilities } from "../../../src/harness.ts";
import { createNfsServer } from "../../../src/nfs/server.ts";
import type { FsDriver } from "../../../src/types.ts";
import { S_IFDIR } from "../../../src/types.ts";
import { conformance } from "../../conformance.ts";
import { check, NfsClient, nfsDriver } from "./client.ts";

/**
 * What survives the trip through NFSv3.
 *
 * Declared rather than derived, because this is the column's *claim* — and
 * unlike the FUSE column it is not "everything". Two honest losses, both
 * inherent to the protocol rather than to this implementation:
 *
 * - **`handles: false`.** NFSv3 is stateless: there is no `open` on the wire,
 *   so the server is never told a file is in use and cannot keep an unlinked
 *   one alive. A real client hides this with silly-rename (it renames the file
 *   to `.nfs0000…` instead of removing it, and removes that on close), which is
 *   a client-side trick — the Linux kernel's client does it, our test client
 *   does not, and the server is right either way. The conformance suite's
 *   "keeps an open handle readable after unlink" case is therefore skipped.
 * - **`extensions: ["mknod"]`, carried in part.** MKNOD is a procedure of its
 *   own (§3.3.11), `nfsDriver`'s `mountx.mknod` is that procedure, and the
 *   session hands what arrives to the driver's extension — so a FIFO, a socket
 *   and both kinds of device node cross intact, `rdev` included, and every
 *   refusal the cases assert (`EEXIST`, `ENOENT`) is the far side's answer
 *   arriving as an `nfsstat3`. What does *not* cross is the type in the
 *   **mode**: `mknoddata3` switches on `ftype3`, a four-member enum for this
 *   purpose, and `sattr3.mode` is masked to `0o7777` at both ends. A mode
 *   naming a regular file, a directory or no type at all is therefore a
 *   question this wire cannot ask — so the two cases that ask it stay skipped,
 *   declared as `carries: []` on the target below rather than papered over by a
 *   client inventing an errno. `utimens` stays off the list: SETATTR carries
 *   nanoseconds, but this client spends them through `utimes`/`lutimes` and
 *   never asks for the extension by name.
 *
 * Everything else — hardlinks, symlinks, permissions, times, truncate, atomic
 * rename, `statfs` — crosses intact.
 */
const THROUGH_NFS: ResolvedCapabilities = {
  handles: false,
  atomicRename: true,
  hardlinks: true,
  symlinks: true,
  permissions: true,
  times: true,
  truncate: true,
  caseSensitive: true,
  statfs: true,
  readOnly: false,
  extensions: ["mknod"],
};

/** Stand a server up over `driver`, connect to it, and MOUNT its root. */
async function serve(driver: FsDriver): Promise<{
  fs: ReturnType<typeof createLoopback>;
  cleanup: () => Promise<void>;
}> {
  const server = createNfsServer(driver);
  await server.listen();
  const client = await NfsClient.connect({ port: server.port });
  const root = check(await client.mnt("/"), "mount").fh!;
  return {
    fs: createLoopback(nfsDriver(client, root)),
    cleanup: async () => {
      await client.umnt("/");
      client.close();
      await server.close();
    },
  };
}

describe("over an NFSv3 server", () => {
  conformance({
    name: "memory driver, over NFS",
    capabilities: THROUGH_NFS,
    // The extension is here, but not the half of it that needs `mknod`'s mode
    // to carry the type — see `THROUGH_NFS` above.
    carries: [],
    setup: () => serve(createMemoryDriver()),
  });

  conformance({
    name: "node-fs driver, over NFS",
    /*
     * `THROUGH_NFS`, minus the one entry that is the *driver's* to answer
     * rather than the transport's: `node-fs` implements no `mountx.mknod`, so
     * `NfsSession.#mknod` answers `NFS3ERR_NOTSUPP` for every MKNOD, exactly as
     * it should. The column carries the extension; this target has none to
     * carry, and declaring one here is the difference between a capability and
     * a claim.
     */
    capabilities: { ...THROUGH_NFS, extensions: [] },
    // The driver forwards the host kernel's errors, and `NFS3ERR_*` carries the
    // ones this suite asks about straight through.
    errors: "host",
    setup: async () => {
      const backing = await mkdtemp(join(tmpdir(), "mountx-nfs-"));
      const served = await serve(createNodeFsDriver(backing));
      return {
        fs: served.fs,
        cleanup: async () => {
          await served.cleanup();
          await rm(backing, { recursive: true, force: true });
        },
      };
    },
  });

  /**
   * The other half of `carries: []`: what happens when something asks anyway.
   *
   * The two skipped cases prove the column does not *claim* the mode-typed half
   * of `mknod`. This proves the client does not quietly supply it either — the
   * refusal is a bare `Error` with no `code` and no `errno`, so `rejects()`
   * could never match it and anyone who un-gates a case gets a failure naming
   * the wire's limit rather than a fabricated `EPERM` (invariant 5).
   */
  it("refuses a type NFSv3 has no ftype3 for, and not with an errno", async () => {
    const served = await serve(createMemoryDriver());
    try {
      const error = await served.fs.mountx!.mknod!("/dir", S_IFDIR | 0o755, 0).then(
        () => undefined,
        (reason: unknown) => reason,
      );
      expect(error).toBeInstanceOf(Error);
      expect(error).not.toHaveProperty("code");
      expect(error).not.toHaveProperty("errno");
      expect((error as Error).message).toContain("MKNOD");
      // Nothing reached the wire: the name is still free.
      await expect(served.fs.stat("/dir")).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await served.cleanup();
    }
  });
});
