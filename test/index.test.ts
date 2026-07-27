import { stat as nodeStat } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import {
  basename,
  createLoopback,
  dirname,
  ERRNO_CODES,
  errnoOf,
  fsError,
  isPathInside,
  isFsError,
  joinPath,
  normalizePath,
  resolveCapabilities,
  splitPath,
} from "../src/index.ts";
import type { FsDriver } from "../src/index.ts";

describe("paths", () => {
  it("normalizes to absolute POSIX paths", () => {
    expect(normalizePath("a/b")).toBe("/a/b");
    expect(normalizePath("/a//b/")).toBe("/a/b");
    expect(normalizePath("/a/./b")).toBe("/a/b");
    expect(normalizePath("")).toBe("/");
    expect(normalizePath("/")).toBe("/");
  });

  it("clamps `..` at the root", () => {
    expect(normalizePath("/a/../b")).toBe("/b");
    expect(normalizePath("/../../etc/passwd")).toBe("/etc/passwd");
    expect(normalizePath("../..")).toBe("/");
    expect(splitPath("/a/b/../c")).toEqual(["a", "c"]);
  });

  it("joins, splits and inspects", () => {
    expect(joinPath("/a", "b", "c")).toBe("/a/b/c");
    expect(dirname("/a/b/c")).toBe("/a/b");
    expect(dirname("/a")).toBe("/");
    expect(dirname("/")).toBe("/");
    expect(basename("/a/b")).toBe("b");
    expect(basename("/")).toBe("/");
    expect(isPathInside("/a/b", "/a")).toBe(true);
    expect(isPathInside("/a", "/a")).toBe(true);
    expect(isPathInside("/ab", "/a")).toBe(false);
    expect(isPathInside("/a", "/")).toBe(true);
  });
});

describe("errors", () => {
  it("matches the node:fs error shape", async () => {
    const real = await nodeStat("/definitely/not/here").catch((error: unknown) => error);
    const ours = fsError("ENOENT", { syscall: "stat", path: "/definitely/not/here" });
    expect(isFsError(real, "ENOENT")).toBe(true);
    expect(ours.code).toBe((real as NodeJS.ErrnoException).code);
    expect(ours.errno).toBe((real as NodeJS.ErrnoException).errno);
    expect(ours.message).toBe((real as Error).message);
  });

  it("builds messages the way node does", () => {
    expect(fsError("EEXIST", { syscall: "rename", path: "/a", dest: "/b" }).message).toBe(
      "EEXIST: file already exists, rename '/a' -> '/b'",
    );
    expect(fsError("EIO", { message: "custom" }).message).toBe("custom");
  });

  it("uses Linux errno values", () => {
    expect(ERRNO_CODES.ENOENT).toBe(2);
    expect(ERRNO_CODES.ENOTEMPTY).toBe(39);
    expect(fsError("ENOTEMPTY").errno).toBe(-39);
  });

  it("maps any error back to a positive errno", () => {
    expect(errnoOf(fsError("ENOTDIR"))).toBe(20);
    expect(errnoOf(new Error("boom"))).toBe(ERRNO_CODES.EIO);
    expect(errnoOf({ code: "SOMETHING_ELSE", errno: -17 })).toBe(17);
    expect(errnoOf(undefined)).toBe(ERRNO_CODES.EIO);
  });

  it("recognizes fs errors", () => {
    expect(isFsError(fsError("EPERM"), "EPERM")).toBe(true);
    expect(isFsError(fsError("EPERM"), "EACCES")).toBe(false);
    expect(isFsError(new Error("plain"))).toBe(false);
    expect(isFsError(null)).toBe(false);
  });
});

describe("harness", () => {
  const minimal: FsDriver = {
    stat: () => Promise.reject(new Error("unused")),
    readdir: () => Promise.resolve([]),
    open: () => Promise.reject(new Error("unused")),
  };

  it("infers capabilities from the methods a driver has", () => {
    // `handles` and `atomicRename` cannot be inferred from a driver's shape,
    // so an undeclared driver gets the conservative answer.
    expect(resolveCapabilities(minimal)).toMatchObject({
      handles: false,
      atomicRename: false,
      hardlinks: false,
      symlinks: false,
      permissions: false,
      times: false,
      truncate: false,
      statfs: false,
      readOnly: true,
      extensions: [],
    });
    expect(resolveCapabilities(createMemoryDriver())).toMatchObject({
      handles: true,
      atomicRename: true,
      hardlinks: true,
      symlinks: true,
      permissions: true,
      times: true,
      truncate: true,
      statfs: true,
      readOnly: false,
    });
  });

  it("lets a driver declare capabilities its methods contradict", () => {
    const lying: FsDriver = {
      ...minimal,
      capabilities: { symlinks: false },
      symlink: async () => {},
    };
    expect(resolveCapabilities(lying).symlinks).toBe(false);
  });

  it("reports missing methods as ENOSYS", async () => {
    const fs = createLoopback(minimal);
    await expect(fs.symlink("a", "/b")).rejects.toMatchObject({ code: "ENOSYS", errno: -38 });
    await expect(fs.mkdir("/dir")).rejects.toMatchObject({ code: "ENOSYS" });
  });

  it("normalizes paths before they reach the driver", async () => {
    const seen: string[] = [];
    const driver: FsDriver = {
      ...minimal,
      readdir: async (path) => {
        seen.push(path);
        return [];
      },
    };
    const fs = createLoopback(driver);
    await fs.readdir("a/../b/./c/", { withFileTypes: true });
    await fs.readdir("/../escape", { withFileTypes: true });
    expect(seen).toEqual(["/b/c", "/escape"]);
  });

  it("reads and writes whole files", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/empty", "");
    expect((await fs.readFile("/empty")).length).toBe(0);
    await fs.writeFile("/big", "x".repeat(200_000));
    expect((await fs.readFile("/big")).length).toBe(200_000);
    await fs.writeFile("/bytes", new Uint8Array([1, 2, 3]));
    expect([...(await fs.readFile("/bytes"))]).toEqual([1, 2, 3]);
  });
});
