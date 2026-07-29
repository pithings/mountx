/** SPIKE B runner: `MOUNTX_SHIM=/path/to/libmountx-shim.so node src/exec/spike-b.ts [command...]` */

import { createDemoDriver } from "./demo-driver.ts";
import { execPreload } from "./preload.ts";

const root = process.env.MOUNTX_TEST_ROOT ?? "/mountx";
const command =
  process.argv.length > 2
    ? process.argv.slice(2)
    : ["sh", "-c", `ls -la ${root} && cat ${root}/hello.txt && wc -c ${root}/big.bin`];

const driver = await createDemoDriver();
const result = await execPreload(driver, command, { root });
process.stderr.write(
  `\n[spike-b] root=${result.root} code=${result.code} signal=${result.signal} 9p-requests=${result.requests}\n`,
);
process.exitCode = result.code ?? 1;
