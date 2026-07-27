import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import { createLoopback } from "../src/harness.ts";

describe("memory driver", () => {
  it("applies umask and ownership options", async () => {
    const fs = createLoopback(createMemoryDriver({ uid: 501, gid: 20, umask: 0o077 }));
    await fs.mkdir("/dir");
    await fs.writeFile("/file", "x");
    const dir = await fs.stat("/dir");
    const file = await fs.stat("/file");
    expect(dir.mode & 0o777).toBe(0o700);
    expect(file.mode & 0o777).toBe(0o600);
    expect(file.uid).toBe(501);
    expect(file.gid).toBe(20);
  });

  it("counts directory links", async () => {
    const fs = createLoopback(createMemoryDriver());
    expect((await fs.stat("/")).nlink).toBe(2);
    await fs.mkdir("/a");
    await fs.mkdir("/b");
    expect((await fs.stat("/")).nlink).toBe(4);
    await fs.rmdir("/b");
    expect((await fs.stat("/")).nlink).toBe(3);
  });

  it("accounts for used blocks in statfs", async () => {
    const fs = createLoopback(createMemoryDriver());
    const before = await fs.statfs("/");
    await fs.writeFile("/file", "x".repeat(64 * 1024));
    const after = await fs.statfs("/");
    expect(before.bfree - after.bfree).toBe(16);
    expect(after.ffree).toBe(before.ffree - 1);
  });

  it("rejects invalid open flags and removing the root", async () => {
    const fs = createLoopback(createMemoryDriver());
    await expect(fs.open("/f", "nonsense")).rejects.toMatchObject({ code: "EINVAL" });
    await expect(fs.rmdir("/")).rejects.toMatchObject({ code: "EBUSY" });
  });

  it("keeps hard-linked content and metadata in sync", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/a", "one");
    await fs.link("/a", "/b");
    await fs.chmod("/b", 0o600);
    expect((await fs.stat("/a")).mode & 0o777).toBe(0o600);
    await fs.truncate("/b", 1);
    expect((await fs.stat("/a")).size).toBe(1);
  });

  it("survives a rename over a hard link", async () => {
    const fs = createLoopback(createMemoryDriver());
    await fs.writeFile("/a", "one");
    await fs.link("/a", "/b");
    await fs.writeFile("/c", "two");
    await fs.rename("/c", "/b");
    expect((await fs.stat("/a")).nlink).toBe(1);
    expect((await fs.stat("/b")).nlink).toBe(1);
  });
});
