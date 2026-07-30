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

import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { createNodeFsDriver } from "../../src/drivers/node-fs.ts";
import { mount, type Mount } from "../../src/fuse/mount.ts";
import { createLoopback, type ResolvedCapabilities } from "../../src/harness.ts";
import { conformance } from "../conformance.ts";
import { rootedNodeFs } from "../rooted-node-fs.ts";
import { removeAll } from "./differential.ts";

// FUSE needs Linux as well as root: on macOS `mount()` refuses outright
// (macFUSE is a different protocol), so the suite skips rather than errors.
const isRoot = (process.getuid?.() ?? -1) === 0 && process.platform === "linux";

const exec = promisify(execFile);

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
 * `extensions` is empty on purpose: the `mountx.*` namespace is a
 * driver-to-session channel, and the suite's extension cases call it *by name*
 * through `fs.mountx` — which a client on the far side of a mount does not
 * have, whatever the session does with `MKNOD` when one arrives. What crosses
 * the wire is checked by the case at the bottom of this file instead, in the
 * only terms a mounted client has: `mkfifo`, `mknod` and `bind`.
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
    sandbox = await mkdtemp(join(tmpdir(), "mountx-conformance-"));
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
          fsname: `mountx-${name}`,
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

  /**
   * The one thing the shared suite cannot ask a mounted client for.
   *
   * `mountx.mknod` is reached by name through `fs.mountx` in the loopback
   * column, and a client on the far side of a mount has no such handle — it has
   * `mkfifo(3)`, `mknod(2)` and `bind(2)`, all of which arrive as `FUSE_MKNOD`.
   * What is being checked is not that the driver stored something: it is that
   * the *kernel* gives a node the driver invented the semantics of the type it
   * claims. Data really flows through the FIFO, and the character device really
   * reads as `/dev/null` does, neither of which the driver implements.
   *
   * Every command runs in a child process: this one serves the mount, so a
   * synchronous call against it is an instant deadlock (see the file header).
   * The node driver's column is not run here — `node:fs/promises` cannot create
   * a special file, so `createNodeFsDriver` has no `mountx.mknod` to test.
   */
  it("carries FIFOs, sockets and device nodes across the wire", async () => {
    const root = join(at["memory"]!, `case-${cases++}`);
    await mkdir(root);
    const fs = createLoopback(rootedNodeFs(root));
    const path = (name: string): string => join(root, name);
    try {
      await exec("mkfifo", [path("pipe")]);
      expect((await fs.lstat("/pipe")).isFIFO()).toBe(true);
      // The kernel's pipe, over an inode this server invented: one process
      // writes, another reads, and neither touches the driver to do it.
      const piped = await exec("sh", [
        "-c",
        `(echo hello > ${path("pipe")} &) ; cat ${path("pipe")}`,
      ]);
      expect(piped.stdout).toBe("hello\n");

      // `bind(2)`, which is the only way to make a socket and is `FUSE_MKNOD`
      // on the wire like the rest.
      await exec(process.execPath, [
        "-e",
        `require("net").createServer().listen(${JSON.stringify(path("sock"))}, () => process.exit(0))`,
      ]);
      expect((await fs.lstat("/sock")).isSocket()).toBe(true);

      // A device node — root only, and root is what this file already needs.
      // `mount(8)` adds no `nodev` here, unlike `fusermount3`, so the node is
      // openable and reads as the device it names rather than as a file.
      await exec("mknod", [path("null"), "c", "1", "3"]);
      const device = await fs.lstat("/null");
      expect(device.isCharacterDevice()).toBe(true);
      expect(device.rdev).toBe((1 << 8) | 3);
      const read = await exec("sh", ["-c", `head -c 8 ${path("null")} | wc -c`]);
      expect(read.stdout.trim()).toBe("0");
    } finally {
      await removeAll(root);
    }
  }, 60_000);
});
