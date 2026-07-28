/**
 * Playground: an in-memory filesystem, seeded with a few files, mounted for real.
 *
 * ```sh
 * sudo "$(command -v node)" playground/index.ts [mountpoint]
 * ```
 *
 * Mounting needs root (see `src/fuse/mount.ts`), and `sudo node` alone will not
 * find node under fnm — hence the `command -v`. Ctrl-C unmounts and exits.
 *
 * Everything is imported from `src/` directly, so edits take effect on the next
 * run with no build step.
 *
 * **Poke at the mount from another terminal, never from here.** Serving a mount
 * and using it from the same process parks the very threadpool threads the read
 * loop needs, and wedges — the whole story is at the top of `src/fuse/mount.ts`.
 * The seeding below goes through the driver, which is just a Map in memory and
 * never touches the mountpoint.
 */

import { execFile } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import { mount } from "../src/fuse/mount.ts";
import { createLoopback } from "../src/harness.ts";
import { bold, cyan, dim, green, red, yellow } from "./color.ts";
import { watchDriver } from "./watch.ts";

const run = promisify(execFile);

const mountpoint = resolve(
  process.argv[2] ?? process.env.MOUNTX_MOUNTPOINT ?? "/tmp/mountx-playground",
);

// The mount is root's, but the fun is in the other terminal — so everything in
// it belongs to the user who ran `sudo`, not to root.
const uid = Number(process.env.SUDO_UID ?? process.getuid?.() ?? 0);
const gid = Number(process.env.SUDO_GID ?? process.getgid?.() ?? 0);

// The driver is what gets mounted; the loopback is the friendlier `fs`-shaped
// view of the same thing, used here to seed it before anyone can look.
const driver = createMemoryDriver({ uid, gid });
const fs = createLoopback(driver);

await fs.writeFile("/hello.txt", "hello from mountx\n");
await fs.mkdir("/docs");
await fs.writeFile("/docs/readme.md", "# playground\n\nThis whole tree lives in RAM.\n");
await fs.writeFile("/docs/numbers.txt", Array.from({ length: 10 }, (_, i) => i).join("\n"));
// Relative on purpose: an absolute target is resolved by the *client's* root,
// so "/hello.txt" would point at the host's, outside the mount.
await fs.symlink("hello.txt", "/hello.link");
await fs.mkdir("/scratch");

// What gets mounted is the driver wrapped in the watcher, so every request the
// kernel makes is narrated — all of them, reads and stats included. The seeding
// above went to the bare driver, so the log starts empty.
const watched = watchDriver(driver);

// A previous run that was killed rather than unmounted leaves the mountpoint in
// the mount table — answering ENOTCONN, and enough for `mount()` to refuse to
// stack on it. Clear it out so the playground is always one command.
await unmountStale(mountpoint);

// `allowOther`, because a root-mounted FUSE filesystem is invisible to every
// other user by default — including the one who is about to `cat` it.
await mkdir(mountpoint, { recursive: true });
await using mounted = await mount(watched, mountpoint, { allowOther: true });

console.log(`
${green("●")} ${bold("mounted")} ${cyan(mounted.mountpoint)} ${dim(`(source: ${mounted.source})`)}

${dim("From another terminal:")}

${bold(`ls -l ${mountpoint}`)}
${bold(`cat ${mountpoint}/hello.txt`)}
${bold(`echo 'written from outside' > ${mountpoint}/scratch/note.txt`)}
${bold(`cat ${mountpoint}/scratch/note.txt`)}

${dim("Every request shows up below. Ctrl-C to unmount; if this process ever")}
${dim(`dies without unmounting, clear it with ${bold(`sudo umount -l ${mountpoint}`)}`)}
`);

// Nothing else to do: the read loop keeps the process alive, and the signal
// handlers `mount()` installed unmount on Ctrl-C. `closed` also resolves if
// someone unmounts from outside, which is the tidy way out of the playground.
await mounted.closed;
console.log(`\n${yellow("○")} ${bold("unmounted")} ${dim(JSON.stringify(mounted.session.stats))}`);

/**
 * Detach whatever an earlier run left at `target`, with `sudo umount -l`.
 *
 * Lazy, because the thing being cleaned up is usually a dead connection: the
 * kernel tears a FUSE session down when the last `/dev/fuse` reference goes, so
 * a killed server leaves a mountpoint that answers `ENOTCONN` rather than one
 * that hangs, and `-l` is what clears it (`src/fuse/mount.ts`).
 *
 * **Only FUSE mounts.** Anything else at that path belongs to someone else, and
 * a playground has no business unmounting it — `mount()` will say so.
 */
async function unmountStale(target: string): Promise<void> {
  const table = await readFile("/proc/self/mounts", "utf8").catch(() => "");
  let type: string | undefined;
  for (const line of table.split("\n")) {
    // Mounts stack: the last line for a path is the one `umount` detaches.
    const [, path = "", kind = ""] = line.split(" ");
    // `/proc/self/mounts` escapes space, tab, newline and backslash.
    const unescaped = path.replace(/\\(?:040|011|012|134)/g, (match) =>
      String.fromCodePoint(Number.parseInt(match.slice(1), 8)),
    );
    if (unescaped === target) type = kind;
  }
  if (type === undefined || !type.startsWith("fuse")) return;

  console.log(`${yellow("!")} ${bold("unmounting stale")} ${cyan(target)} ${dim(`(${type})`)}`);
  try {
    await run("sudo", ["umount", "-l", target]);
  } catch (error) {
    // Not fatal here: `mount()` refuses to stack and its message says the rest.
    console.error(red(`could not unmount ${target}: ${(error as Error).message}`));
  }
}
