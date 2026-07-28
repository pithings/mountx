import { mkdtemp, rm } from "node:fs/promises";
import * as fsPromises from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import { createNodeFsDriver } from "../src/drivers/node-fs.ts";
import { createLoopback, resolveCapabilities } from "../src/harness.ts";
import type { FsDriver, FullFsDriver } from "../src/types.ts";
import { conformance } from "./conformance.ts";
import { rootedNodeFs } from "./rooted-node-fs.ts";

/**
 * The acid test for the whole design: `node:fs/promises` *is* an `FsDriver`,
 * with no adapter and no cast.
 */
const nodeFsPromises: FsDriver = fsPromises;

/** And it implements every optional method, so it is a `FullFsDriver` too. */
const nodeFsPromisesIsComplete: FullFsDriver = fsPromises;

async function temporaryRoot(): Promise<{ root: string; cleanup: () => Promise<void> }> {
  const root = await mkdtemp(join(tmpdir(), "mountx-"));
  return { root, cleanup: () => rm(root, { recursive: true, force: true }) };
}

describe("driver interface", () => {
  it("accepts node:fs/promises as a driver", () => {
    expect(typeof nodeFsPromises.open).toBe("function");
    expect(typeof nodeFsPromises.readdir).toBe("function");
    expect(nodeFsPromises.capabilities).toBeUndefined();
    expect(typeof nodeFsPromisesIsComplete.statfs).toBe("function");
    expect(typeof nodeFsPromisesIsComplete.lutimes).toBe("function");
  });
});

conformance({
  name: "memory",
  capabilities: resolveCapabilities(createMemoryDriver()),
  setup: async () => ({ fs: createLoopback(createMemoryDriver()) }),
});

conformance({
  name: "node-fs",
  capabilities: resolveCapabilities(createNodeFsDriver(tmpdir())),
  // Every error not raised by its own path resolution is the host kernel's.
  errors: "host",
  setup: async () => {
    const { root, cleanup } = await temporaryRoot();
    return { fs: createLoopback(createNodeFsDriver(root)), cleanup };
  },
});

conformance({
  name: "node:fs/promises (raw)",
  capabilities: resolveCapabilities(rootedNodeFs(tmpdir())),
  // The oracle *is* the host kernel, so its errors are the host's throughout.
  errors: "host",
  setup: async () => {
    const { root, cleanup } = await temporaryRoot();
    return { fs: createLoopback(rootedNodeFs(root)), cleanup };
  },
});
