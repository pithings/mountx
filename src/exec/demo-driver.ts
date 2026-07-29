/** The tree both mechanisms are pointed at, so their results compare. */

import { createMemoryDriver } from "../drivers/memory.ts";
import { createLoopback } from "../harness.ts";
import type { FsDriver } from "../types.ts";

/** A memory driver holding a handful of files a shell can obviously exercise. */
export async function createDemoDriver(): Promise<FsDriver> {
  const driver = createMemoryDriver();
  const fs = createLoopback(driver);
  await fs.mkdir("/docs", { recursive: true });
  await fs.writeFile("/hello.txt", "hello from a driver that is not on any disk\n");
  await fs.writeFile("/docs/a.txt", "alpha\n");
  await fs.writeFile("/docs/b.txt", "bravo\n");
  await fs.writeFile(
    "/numbers.txt",
    `${Array.from({ length: 100 }, (_, i) => i + 1).join("\n")}\n`,
  );
  // 3 MiB of deterministic bytes, for a byte-exactness check that is bigger
  // than any single message on any of the three transports.
  const big = Buffer.allocUnsafe(3 * 1024 * 1024);
  for (let i = 0; i < big.length; i++) {
    big[i] = (i * 31 + 7) & 0xff;
  }
  await fs.writeFile("/big.bin", big);
  return driver;
}
