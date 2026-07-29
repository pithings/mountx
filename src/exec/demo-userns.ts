/**
 * The user-namespace mechanism, run against the shared demo tree.
 *
 * ```sh
 * node src/exec/demo-userns.ts [command...]
 * ```
 *
 * A test bench rather than an entry point — `mountx/exec` is the entry point,
 * and this is what `test/exec/compare.sh` drives to fill one column of the
 * comparison in `.agents/proot-plan.md`. It calls `execUserns()` by name on
 * purpose: the value of that comparison is that each column is one *named*
 * mechanism rather than whatever the picker would have chosen.
 */

import { createDemoDriver } from "./demo-driver.ts";
import { execUserns } from "./userns.ts";

// `$MOUNTX_ROOT` rather than a hardcoded path: the relay sets it, and a `cd`
// that happens after the exec is the only kind that does not deadlock.
const command =
  process.argv.length > 2
    ? process.argv.slice(2)
    : [
        "sh",
        "-c",
        'cd "$MOUNTX_ROOT" && ls -la && cat hello.txt && wc -c big.bin && sha256sum big.bin',
      ];

const driver = await createDemoDriver();
const result = await execUserns(driver, command, { debug: process.env.MOUNTX_DEBUG === "1" });
process.stderr.write(
  `\n[userns] mountpoint=${result.mountpoint} code=${result.code} signal=${result.signal}\n`,
);
process.exitCode = result.code ?? 1;
