import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createNodeFsDriver } from "../src/drivers/node-fs.ts";
import { createLoopback, type Loopback } from "../src/harness.ts";
import type { FsDriver } from "../src/types.ts";
import { rootedNodeFs } from "./rooted-node-fs.ts";

describe("node-fs driver", () => {
  let sandbox: string;
  let root: string;
  let outside: string;
  let driver: FsDriver;
  let fs: Loopback;

  beforeEach(async () => {
    sandbox = await mkdtemp(join(tmpdir(), "mountx-sandbox-"));
    root = join(sandbox, "root");
    outside = join(sandbox, "outside");
    await mkdir(root);
    await mkdir(outside);
    await writeFile(join(outside, "secret"), "classified");
    driver = createNodeFsDriver(root);
    fs = createLoopback(driver);
  });

  afterEach(async () => {
    await rm(sandbox, { recursive: true, force: true });
  });

  it("clamps `..` at the root, even unnormalized", async () => {
    // The harness normalizes, but the driver must not depend on it.
    await expect(driver.stat!("/../outside/secret")).rejects.toMatchObject({ code: "ENOENT" });
    await expect(driver.stat!("/a/../../../outside/secret")).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect((await driver.stat!("/../..")).isDirectory()).toBe(true);
  });

  it("resolves absolute symlink targets relative to the root", async () => {
    await fs.symlink("/outside", "/escape");
    await expect(fs.stat("/escape/secret")).rejects.toMatchObject({ code: "ENOENT" });

    // ...and the same name inside the root is what it actually reaches.
    await fs.mkdir("/outside");
    await fs.writeFile("/escape/inside", "safe");
    expect(await readFile(join(root, "outside", "inside"), "utf8")).toBe("safe");
    expect(await readFile(join(outside, "secret"), "utf8")).toBe("classified");
  });

  it("clamps relative symlink targets that walk out of the root", async () => {
    await fs.mkdir("/deep/deeper", { recursive: true });
    await fs.symlink("../../../../outside", "/deep/deeper/escape");
    await expect(fs.stat("/deep/deeper/escape/secret")).rejects.toMatchObject({ code: "ENOENT" });

    // Walking off the top lands on the root, not on the host's filesystem.
    await fs.symlink("../../../../..", "/deep/deeper/up");
    await fs.writeFile("/marker", "x");
    expect(
      (await fs.readdir("/deep/deeper/up", { withFileTypes: true })).map((entry) => entry.name),
    ).toContain("marker");
  });

  it("refuses to traverse a symlink chain that escapes mid-path", async () => {
    await fs.symlink("/", "/top");
    await fs.symlink("../../..", "/up");
    await fs.writeFile("/marker", "x");
    expect((await fs.readdir("/top/up/top", { withFileTypes: true })).map((e) => e.name)).toContain(
      "marker",
    );
    expect(await readFile(join(outside, "secret"), "utf8")).toBe("classified");
  });

  it("rejects a symlink loop with ELOOP instead of hanging", async () => {
    await fs.symlink("b", "/a");
    await fs.symlink("a", "/b");
    await expect(fs.stat("/a")).rejects.toMatchObject({ code: "ELOOP" });
    await expect(fs.open("/a", "r")).rejects.toMatchObject({ code: "ELOOP" });
  });

  it("maps results back into the virtual namespace", async () => {
    // Known gap: errors raised by the underlying syscall still carry the host
    // path. Only errors raised while resolving are rewritten.
    let error: NodeJS.ErrnoException | undefined;
    try {
      await fs.stat("/nope");
    } catch (cause) {
      error = cause as NodeJS.ErrnoException;
    }
    expect(error?.path).toBe(join(root, "nope"));

    const entries = await fs.readdir("/", { withFileTypes: true });
    expect(entries.every((entry) => entry.parentPath === "/")).toBe(true);

    await fs.mkdir("/deep/dir", { recursive: true });
    const created = await fs.mkdir("/other/dir", { recursive: true });
    expect(created).toBe("/other");
  });

  it("refuses to remove its own root", async () => {
    // `secure("/")` has no components to walk and so returns the root itself,
    // which `rmdir(2)` was happy to delete once it was empty — permanently
    // killing the driver, in the file the conformance and differential suites
    // treat as the oracle. Every other operation on the root is caught by the
    // host kernel; this one is not, because from its side the root is an
    // ordinary directory.
    for (const path of ["/", "/.", "/a/..", "//"]) {
      await expect(fs.rmdir(path)).rejects.toMatchObject({ code: "EBUSY" });
    }
    // ...and the root is still there, still usable.
    await fs.writeFile("/still-here", "x");
    expect((await fs.stat("/")).isDirectory()).toBe(true);
    expect(await readFile(join(root, "still-here"), "utf8")).toBe("x");
  });

  it("resolves both paths of a rename or link once, together", async () => {
    // Two sequential walks over `/a/b/c` cost six `lstat`s where four will do,
    // and each is a libuv threadpool job — the pool `fuse/mount.ts` documents
    // as the wedge hazard. The memo lives for the one call and no longer.
    await fs.mkdir("/a/b/c", { recursive: true });
    await fs.writeFile("/a/b/c/f", "content");
    await fs.rename("/a/b/c/f", "/a/b/c/g");
    await fs.link("/a/b/c/g", "/a/b/c/h");
    expect(await readFile(join(root, "a/b/c/h"), "utf8")).toBe("content");
    expect((await fs.stat("/a/b/c/g")).nlink).toBe(2);
    // A failure still names the *first* path, as it did when the two ran in
    // sequence: a symlink loop on the source is the source's error.
    await fs.symlink("loop", "/loop");
    await expect(fs.rename("/loop/x", "/a/b/c/z")).rejects.toMatchObject({ code: "ELOOP" });
    await expect(fs.link("/a/b/c/z", "/loop/x")).rejects.toMatchObject({ code: "ELOOP" });
  });

  it("declares its capabilities", () => {
    expect(fs.capabilities).toMatchObject({ hardlinks: true, symlinks: true, readOnly: false });
    expect(createLoopback(createNodeFsDriver(root, { readOnly: true })).capabilities.readOnly).toBe(
      true,
    );
  });
});

describe("rooted node:fs oracle", () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "mountx-oracle-"));
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("refuses to remove the directory it is rooted at", async () => {
    // `join(root, "/")` is `root`, so this oracle deleted its own root as
    // readily as the driver it is the oracle for — the temp directory in
    // `drivers.test.ts`, and the *mountpoint* in the FUSE conformance column.
    const fs = createLoopback(rootedNodeFs(root));
    for (const path of ["/", "/.", "/a/..", "//"]) {
      await expect(fs.rmdir(path)).rejects.toMatchObject({ code: "EBUSY" });
    }
    await fs.writeFile("/still-here", "x");
    expect(await readFile(join(root, "still-here"), "utf8")).toBe("x");
  });
});
