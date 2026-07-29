/**
 * The seccomp mechanism, run against the shared demo tree.
 *
 * ```sh
 * MOUNTX_TRACE=/path/to/mountx-trace node src/exec/demo-seccomp.ts [command...]
 * ```
 *
 * A test bench rather than an entry point — `mountx/exec` is the entry point,
 * and this is what `test/exec/compare.sh` drives to fill one column of the
 * comparison in `.agents/proot-plan.md`. It calls `execSeccomp()` by name on
 * purpose: the value of that comparison is that each column is one *named*
 * mechanism rather than whatever the picker would have chosen.
 */

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
  `\n[seccomp] root=${result.root} code=${result.code} signal=${result.signal} 9p-requests=${result.requests}\n`,
);
process.exitCode = result.code ?? 1;
