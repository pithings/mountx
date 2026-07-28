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
import { describe } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { createNodeFsDriver } from "../../src/drivers/node-fs.ts";
import { createLoopback, type ResolvedCapabilities } from "../../src/harness.ts";
import { createNfsServer } from "../../src/nfs/server.ts";
import type { FsDriver } from "../../src/types.ts";
import { conformance } from "../conformance.ts";
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
 * - **`extensions: []`**, for the same reason as the FUSE column: the
 *   `unimount.*` namespace is a driver-to-session channel with no wire
 *   representation.
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
  extensions: [],
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
    setup: () => serve(createMemoryDriver()),
  });

  conformance({
    name: "node-fs driver, over NFS",
    capabilities: THROUGH_NFS,
    setup: async () => {
      const backing = await mkdtemp(join(tmpdir(), "unimount-nfs-"));
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
});
