/**
 * The `LD_PRELOAD` mechanism, run against the shared demo tree.
 *
 * ```sh
 * MOUNTX_SHIM=/path/to/libmountx-shim.so node src/exec/demo-preload.ts [command...]
 * ```
 *
 * **This mechanism was rejected** — see `src/exec/preload.ts` and
 * `.agents/proot-plan.md`. Nothing reaches it but this runner and
 * `test/exec/compare.sh`, and it is deliberately not one of the mechanisms
 * `mountx/exec` can choose. It stays in the tree as the evidence for the
 * decision, which is the kind of thing that gets re-argued from scratch every
 * couple of years once the measurements are deleted.
 */

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
  `\n[preload] root=${result.root} code=${result.code} signal=${result.signal} 9p-requests=${result.requests}\n`,
);
process.exitCode = result.code ?? 1;
