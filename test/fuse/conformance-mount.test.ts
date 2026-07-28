/**
 * The conformance matrix, FUSE column.
 *
 * IDEA.md's organizing idea: *one* conformance suite written against the driver
 * interface, run every way the library can carry it. `drivers.test.ts` runs it
 * through the loopback harness (no transport at all); this file runs the same
 * suite through a real kernel mount, with `node:fs` as the client. The driver
 * never learns which column it is in, so anything that passes in one and fails
 * in the other is a *transport* bug by construction.
 *
 * ```sh
 * pnpm test:conformance:mount
 * ```
 *
 * Tier 2: root, `/dev/fuse`, a kernel. Skips itself otherwise.
 *
 * **Two mounts, up for the whole file.** Mounting per test would be honest and
 * unusably slow (each mount is a `mount(8)`, a handshake and an `umount(8)`), so
 * each mount goes up once and every test gets a fresh directory *inside* it.
 * That is a slightly weaker isolation than the loopback column — a test starts
 * from an empty directory rather than an empty filesystem — and the one place
 * it shows is `statfs`, which reports the whole mount.
 *
 * Every operation is sequential. This process serves both mounts and is also
 * their only client; see the threadpool note at the top of `src/fuse/mount.ts`.
 */

import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { createNodeFsDriver } from "../../src/drivers/node-fs.ts";
import { mount, type Mount } from "../../src/fuse/mount.ts";
import { createLoopback, type ResolvedCapabilities } from "../../src/harness.ts";
import { conformance } from "../conformance.ts";
import { rootedNodeFs } from "../rooted-node-fs.ts";
import { removeAll } from "./differential.ts";

const isRoot = (process.getuid?.() ?? -1) === 0;

/**
 * What survives the trip through FUSE.
 *
 * Declared rather than derived, because this is the column's *claim*: the FUSE
 * transport loses none of the capabilities either v1 driver has. Both drivers
 * declare the same set, so one list covers both mounts — and if the transport
 * ever did lose one, turning it off here would show up as a row of skips in the
 * report, which is the honest way to say so (IDEA.md: "reports honestly which
 * capabilities each transport actually loses").
 *
 * `extensions` is empty on purpose: the `unimount.*` namespace is a
 * driver-to-session channel and has no wire representation, so nothing that
 * uses it can cross a mount. Nothing in the suite needs it.
 */
const THROUGH_FUSE: ResolvedCapabilities = {
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
  extensions: [],
};

describe.skipIf(!isRoot)("over a real FUSE mount", () => {
  const mounts: Mount[] = [];
  let sandbox = "";
  /** Mountpoint per column, filled in by `beforeAll`. */
  const at: Record<string, string> = {};
  let cases = 0;

  beforeAll(async () => {
    sandbox = await mkdtemp(join(tmpdir(), "unimount-conformance-"));
    for (const [name, driver] of [
      ["memory", createMemoryDriver()],
      ["node-fs", createNodeFsDriver(await freshDirectory("backing"))],
    ] as const) {
      const mountpoint = await freshDirectory(`mnt-${name}`);
      // Zero timeouts, as in the differential suite: a cached attribute would
      // let the kernel answer a question the driver never saw, and a
      // conformance column that agrees with a cache proves nothing.
      mounts.push(
        await mount(driver, mountpoint, {
          fsname: `unimount-${name}`,
          attrTimeout: 0,
          entryTimeout: 0,
          readers: 4,
        }),
      );
      at[name] = mountpoint;
    }
  }, 60_000);

  afterAll(async () => {
    for (const mounted of mounts.splice(0)) {
      await mounted.unmount().catch(() => {
        // The mount tests assert on leaks; here the cleanup is what matters.
      });
    }
    if (sandbox !== "") {
      await rm(sandbox, { recursive: true, force: true }).catch(() => {});
    }
  }, 60_000);

  async function freshDirectory(name: string): Promise<string> {
    const path = join(sandbox, name);
    await mkdir(path);
    return path;
  }

  /**
   * A fresh, empty directory inside a mountpoint, and the sequential delete
   * that cleans it up. `fs.rm(…, { recursive: true })` fans out, and a fan-out
   * against a mountpoint this process serves is the threadpool deadlock.
   */
  function column(
    name: string,
  ): () => Promise<{ fs: ReturnType<typeof createLoopback>; cleanup: () => Promise<void> }> {
    return async () => {
      const root = join(at[name]!, `case-${cases++}`);
      await mkdir(root);
      return {
        fs: createLoopback(rootedNodeFs(root)),
        cleanup: () => removeAll(root),
      };
    };
  }

  conformance({
    name: "memory driver, through a FUSE mount",
    capabilities: THROUGH_FUSE,
    setup: column("memory"),
  });

  conformance({
    name: "node-fs driver, through a FUSE mount",
    capabilities: THROUGH_FUSE,
    setup: column("node-fs"),
  });
});
