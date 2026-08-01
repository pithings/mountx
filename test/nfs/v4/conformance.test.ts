/**
 * The conformance matrix, NFSv4.1 column.
 *
 * The same suite `../v3/conformance.test.ts` runs, one protocol version up:
 * `test/conformance.ts` written against the driver interface, carried this time
 * through EXCHANGE_ID, CREATE_SESSION, a slot table, COMPOUNDs full of
 * operations and a stateid per open — over a real TCP socket, with a JavaScript
 * client on the far end.
 *
 * Tier 1: no root, no mount, no kernel. A fresh server, a fresh session and a
 * fresh driver per test, so the isolation is the loopback column's — an empty
 * filesystem, not an empty directory.
 *
 * Running it beside the v3 column is the point: the two share a driver
 * interface, a `FileHandleTable` and a socket, and the matrix puts their
 * answers in adjacent cells. A row that passes in one and not the other is a
 * difference between the *protocols* by construction.
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
import { Nfs4Client } from "./client.ts";
import { nfs4Driver } from "./driver.ts";

/**
 * What survives the trip through NFSv4.1.
 *
 * Declared rather than derived, because this is the column's *claim*. It is
 * `THROUGH_NFS`'s list, and the one entry worth arguing about is the first:
 *
 * - **`handles: false`, and not for v3's reason.** NFSv3 loses it because it is
 *   stateless — there is no `open` on the wire at all. NFSv4.1 has one, and
 *   `src/nfs/v4/session.ts` holds a real driver handle per open state, so the
 *   half of the capability that is about *reading an unlinked file* has a
 *   descriptor behind it. What it does not have is a name: this server's
 *   filehandles are path-keyed (`src/nfs/handles.ts`), a REMOVE unbinds the
 *   path, and every operation resolves the current filehandle to one before it
 *   runs — so the READ that would have used the surviving descriptor answers
 *   `NFS4ERR_STALE` before reaching it. The session says as much where it
 *   declines to advertise `OPEN4_RESULT_PRESERVE_UNLINKED`: "a REMOVE here
 *   unbinds the handle and the open file goes with it". That is a property of
 *   the shared handle table rather than of NFSv4.1, and lifting it would mean
 *   giving the table an identity that outlives the last link — which is a
 *   change to `src/`, not to this column. Real clients paper over the same gap
 *   with silly-rename, at both versions.
 * - **`extensions: ["mknod"]`, carried in part**, as in the v3 column and for
 *   the same reason one version down. v4 has no MKNOD: a special file is a
 *   CREATE (§18.4), `nfs4Driver`'s `mountx.mknod` is that CREATE, and
 *   `Nfs4Session.#create` hands what arrives to the driver's extension — so a
 *   FIFO, a socket and both kinds of device node cross intact, `rawdev`
 *   included, and every refusal the cases assert (`EEXIST`, `ENOENT`) is the
 *   far side's answer arriving as an `nfsstat4`. What does *not* cross is the
 *   type in the **mode**: `createtype4` switches on `nfs_ftype4` and `fattr4`'s
 *   `mode` is permission bits. A mode naming a regular file is OPEN's business
 *   and `NFS4ERR_BADTYPE` here (§15.1.4.1); a mode naming a directory would be
 *   `mkdir` rather than the `EPERM` `mknod(2)` owes it. So the two cases that
 *   ask the mode to carry a type stay skipped, declared as `carries: []` on the
 *   target below rather than papered over by a client inventing an errno.
 *
 * Everything else — hardlinks, symlinks, permissions, times, truncate, atomic
 * rename, `statfs` — crosses intact.
 */
const THROUGH_NFS4: ResolvedCapabilities = {
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

/** Stand a server up over `driver`, connect to it, and establish a session. */
async function serve(driver: FsDriver): Promise<{
  fs: ReturnType<typeof createLoopback>;
  cleanup: () => Promise<void>;
}> {
  const server = createNfsServer(driver);
  await server.listen();
  const client = await Nfs4Client.open({ port: server.port });
  const root = await client.rootFh();
  return {
    fs: createLoopback(nfs4Driver(client, root)),
    cleanup: async () => {
      await client.destroySession();
      client.close();
      await server.close();
    },
  };
}

describe("over an NFSv4.1 server", () => {
  /**
   * Both targets declare `errors: "host"`, and the second one for a reason the
   * first does not share.
   *
   * `node-fs` forwards the host kernel's errors, exactly as it does in the v3
   * column. The memory driver does not — it carries `src/errors.ts`'s table —
   * but this column has one error of its own that no driver produces: `unlink`
   * of a directory. NFSv4 has a single REMOVE for files and directories alike,
   * so the refusal is the client's to make (see `./driver.ts`), and a client
   * makes it with its own kernel's rule — `EISDIR` on Linux, `EPERM` on the
   * BSDs. That is precisely what `errors: "host"` describes, and declaring it
   * is what keeps this column honest on a Mac.
   */
  const errors = "host";

  conformance({
    name: "memory driver, over NFSv4.1",
    capabilities: THROUGH_NFS4,
    // The extension is here, but not the half of it that needs `mknod`'s mode
    // to carry the type — see `THROUGH_NFS4` above.
    carries: [],
    errors,
    setup: () => serve(createMemoryDriver()),
  });

  conformance({
    name: "node-fs driver, over NFSv4.1",
    /*
     * `THROUGH_NFS4`, minus the one entry that is the *driver's* to answer
     * rather than the transport's: `node-fs` implements no `mountx.mknod`, so
     * `Nfs4Session.#create` answers `NFS4ERR_BADTYPE` for every device-ish
     * type — §15.1.4.1's "the type is not supported by the server" — exactly as
     * it should. The column carries the extension; this target has none to
     * carry, and declaring one here is the difference between a capability and
     * a claim.
     */
    capabilities: { ...THROUGH_NFS4, extensions: [] },
    errors,
    setup: async () => {
      const backing = await mkdtemp(join(tmpdir(), "mountx-nfs4-"));
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
   * the wire's limit rather than a fabricated `EPERM` (invariant 5). A
   * directory is the sharper of the two here: `NF4DIR` *is* `mkdir` on this
   * wire, so passing the mode through would have made one.
   */
  it("refuses a type NFSv4.1 has no createtype4 for, and not with an errno", async () => {
    const served = await serve(createMemoryDriver());
    try {
      const error = await served.fs.mountx!.mknod!("/dir", S_IFDIR | 0o755, 0).then(
        () => undefined,
        (reason: unknown) => reason,
      );
      expect(error).toBeInstanceOf(Error);
      expect(error).not.toHaveProperty("code");
      expect(error).not.toHaveProperty("errno");
      expect((error as Error).message).toContain("CREATE");
      // Nothing reached the wire: the name is still free.
      await expect(served.fs.stat("/dir")).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await served.cleanup();
    }
  });
});
