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

/**
 * The acid test for the whole design: `node:fs/promises` *is* an `FsDriver`,
 * with no adapter and no cast.
 */
const nodeFsPromises: FsDriver = fsPromises;

/** And it implements every optional method, so it is a `FullFsDriver` too. */
const nodeFsPromisesIsComplete: FullFsDriver = fsPromises;

/** `node:fs/promises` itself, with paths joined onto a root. No resolution. */
function rootedNodeFs(root: string): FsDriver {
  const real = (path: string): string => join(root, path);
  return {
    // The two things no driver's shape can reveal.
    capabilities: { handles: true, atomicRename: true },
    stat: (path) => fsPromises.stat(real(path)),
    lstat: (path) => fsPromises.lstat(real(path)),
    statfs: (path) => fsPromises.statfs(real(path)),
    readdir: (path, options) => fsPromises.readdir(real(path), options),
    open: (path, flags, mode) => fsPromises.open(real(path), flags, mode),
    mkdir: (path, options) => fsPromises.mkdir(real(path), options),
    rmdir: (path) => fsPromises.rmdir(real(path)),
    unlink: (path) => fsPromises.unlink(real(path)),
    rename: (from, to) => fsPromises.rename(real(from), real(to)),
    link: (from, to) => fsPromises.link(real(from), real(to)),
    symlink: (target, path) => fsPromises.symlink(target, real(path)),
    readlink: (path) => fsPromises.readlink(real(path)),
    chmod: (path, mode) => fsPromises.chmod(real(path), mode),
    chown: (path, uid, gid) => fsPromises.chown(real(path), uid, gid),
    lchown: (path, uid, gid) => fsPromises.lchown(real(path), uid, gid),
    truncate: (path, length) => fsPromises.truncate(real(path), length),
    utimes: (path, atime, mtime) => fsPromises.utimes(real(path), atime, mtime),
    lutimes: (path, atime, mtime) => fsPromises.lutimes(real(path), atime, mtime),
  };
}

async function temporaryRoot(): Promise<{ root: string; cleanup: () => Promise<void> }> {
  const root = await mkdtemp(join(tmpdir(), "unimount-"));
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
  setup: async () => {
    const { root, cleanup } = await temporaryRoot();
    return { fs: createLoopback(createNodeFsDriver(root)), cleanup };
  },
});

conformance({
  name: "node:fs/promises (raw)",
  capabilities: resolveCapabilities(rootedNodeFs(tmpdir())),
  setup: async () => {
    const { root, cleanup } = await temporaryRoot();
    return { fs: createLoopback(rootedNodeFs(root)), cleanup };
  },
});
