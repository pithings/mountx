/** SPIKE C runner: `MOUNTX_TRACE=/path/to/mountx-trace node src/exec/spike-c.ts [command...]` */

import { createDemoDriver } from "./demo-driver.ts";
import { execSeccomp } from "./seccomp.ts";

const root = process.env.MOUNTX_TEST_ROOT ?? "/mountx";
const command =
  process.argv.length > 2
    ? process.argv.slice(2)
    : ["sh", "-c", `ls -la ${root} && cat ${root}/hello.txt`];

const driver = await createDemoDriver();
const result = await execSeccomp(driver, command, { root });
process.stderr.write(
  `\n[spike-c] root=${result.root} code=${result.code} signal=${result.signal} 9p-requests=${result.requests}\n`,
);
process.exitCode = result.code ?? 1;
