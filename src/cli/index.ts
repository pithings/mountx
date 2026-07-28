#!/usr/bin/env node
/**
 * `mountx` — the one-command way to see this library actually mount something.
 *
 * ```sh
 * npx mountx                  # an in-memory tree at ~/mountx
 * npx mountx /tmp/scratch -t nfs
 * npx mountx --help
 * ```
 *
 * An in-memory filesystem holding one file — this package's own `README.md`,
 * copied in — wrapped in the request logger (`watch.ts`) and mounted for real
 * through `mountx/auto`, which picks FUSE on Linux and NFS on macOS and needs
 * no root on either (unprivileged FUSE wants `fusermount3`; macOS NFS wants a
 * mountpoint you own).
 *
 * It is a demonstration and a test bench, not a mount tool: what it serves is
 * always {@link createMemoryDriver}'s tree, which exists for as long as the
 * process does and no longer. The library is what mounts a real driver.
 *
 * **Poke at the mount from another terminal, never from here.** Serving a mount
 * and using it from the same process parks the very threadpool threads the read
 * loop needs, and wedges — the whole story is at the top of `src/fuse/mount.ts`.
 * The seeding below goes through the driver, which is just a Map in memory and
 * never touches the mountpoint.
 */

import { execFile } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { parseArgs, promisify } from "node:util";
import { mount, probeTransports, type Transport } from "../auto.ts";
import { createMemoryDriver } from "../drivers/memory.ts";
import { createLoopback } from "../harness.ts";
import type { FsDriver } from "../types.ts";
import { bold, cyan, dim, green, red, yellow } from "./color.ts";
import { watchDriver } from "./watch.ts";

const run = promisify(execFile);

const TRANSPORTS = new Set<string>(["auto", "fuse", "nfs"]);

const CLI = {
  allowPositionals: true,
  options: {
    mountpoint: { type: "string", short: "m" },
    transport: { type: "string", short: "t", default: "auto" },
    quiet: { type: "boolean", short: "q", default: false },
    "read-only": { type: "boolean", short: "r", default: false },
    empty: { type: "boolean", default: false },
    "allow-other": { type: "boolean", default: false },
    help: { type: "boolean", short: "h", default: false },
  },
} as const;

const HELP = `
${bold("mountx")} ${dim("— mount an in-memory filesystem and watch what the kernel asks it")}

${bold("Usage:")}  mountx [mountpoint] [options]

${bold("Options:")}
  -m, --mountpoint ${dim("<path>")}  where to mount        ${dim("(default: ~/mountx, $MOUNTX_MOUNTPOINT)")}
  -t, --transport ${dim("<name>")}   auto | fuse | nfs     ${dim("(default: auto)")}
  -q, --quiet              do not log filesystem requests
  -r, --read-only          mount read-only
      --empty              start empty, without the README copied in
      --allow-other        let other users see the mount ${dim("(FUSE; implied under root)")}
  -h, --help               this

${dim("Ctrl-C unmounts and exits.")}
`;

// The entry point is the whole of the module's side effects, and it is the
// binary's: nothing here is importable API. `process.exit` is safe in the paths
// that use it because every one of them runs before anything is mounted — with
// a mount up it wedges, which is why the end of `main` sets `exitCode` instead
// (`src/fuse/mount.ts`).
await main();

/** Mount, print, and stay up until the mount goes away. */
async function main(): Promise<void> {
  const { values, positionals } = parseCli();

  if (values.help) {
    console.log(HELP);
    return;
  }

  if (positionals.length > 1) {
    fail(`one mountpoint at a time, got ${positionals.length}`);
  }

  const requested = values.transport ?? "auto";
  if (!TRANSPORTS.has(requested)) {
    fail(`unknown transport ${bold(requested)} ${dim(`(expected ${[...TRANSPORTS].join(", ")})`)}`);
  }
  const transport = requested as Transport | "auto";

  const mountpoint = expand(
    positionals[0] ?? values.mountpoint ?? process.env.MOUNTX_MOUNTPOINT ?? "~/mountx",
  );

  // Asked once, up front: when nothing can mount here, the probe's reason names
  // what each transport is missing, where a failed mount reports only the last
  // thing that went wrong.
  if (transport === "auto") {
    const probe = await probeTransports();
    if (probe.chosen === undefined) {
      console.error(`${red("!")} ${probe.reason}`);
      process.exit(1);
    }
  }

  // The mount may be root's, but the fun is in the other terminal — so
  // everything in it belongs to the user who ran `sudo`, not to root.
  const uid = Number(process.env.SUDO_UID ?? process.getuid?.() ?? 0);
  const gid = Number(process.env.SUDO_GID ?? process.getgid?.() ?? 0);

  // The driver is what gets mounted; the loopback is the friendlier `fs`-shaped
  // view of the same thing, used here to seed it before anyone can look.
  const driver = createMemoryDriver({ uid, gid });
  if (!values.empty) {
    await seed(createLoopback(driver));
  }

  // What gets mounted is the driver wrapped in the watcher, so every request the
  // kernel makes is narrated — all of them, reads and stats included. The
  // seeding above went to the bare driver, so the log starts empty.
  const served: FsDriver = values.quiet ? driver : watchDriver(driver);

  // A previous run that was killed rather than unmounted leaves the mountpoint
  // in the mount table — answering ENOTCONN, and enough for `mount()` to refuse
  // to stack on it. Clear it out so this stays a one-command tool.
  await unmountStale(mountpoint);

  await mkdir(mountpoint, { recursive: true });
  await using mounted = await mount(served, mountpoint, {
    transport,
    readOnly: values["read-only"],
    // A root-mounted FUSE filesystem is invisible to every other user by
    // default — including the one who is about to `cat` it. An unprivileged
    // mount is the mounting user's already, and `allow_other` needs
    // `user_allow_other` in /etc/fuse.conf there, so it stays opt-in off root.
    fuse: { allowOther: values["allow-other"] || (process.getuid?.() ?? -1) === 0 },
  });

  // What is worth typing depends on what was mounted: nothing to read in an
  // empty tree, nothing to write in a read-only one.
  const hints = [
    `ls -l ${mountpoint}`,
    ...(values.empty ? [] : [`head ${mountpoint}/README.md`]),
    ...(values["read-only"]
      ? []
      : [`echo 'written from outside' > ${mountpoint}/note.txt`, `cat ${mountpoint}/note.txt`]),
  ];

  console.log(`
${green("●")} ${bold("mounted")} ${cyan(mounted.mountpoint)} ${dim(
    `(${mounted.transport}, source: ${mounted.source})`,
  )}

${dim("From another terminal:")}

${hints.map((hint) => bold(hint)).join("\n")}

${values.quiet ? dim("Requests are not logged (--quiet).") : dim("Every request shows up below.")}
${dim("Ctrl-C to unmount; if this process ever dies without unmounting, clear it")}
${dim(`with ${bold(staleCommand(mountpoint, mounted.transport).join(" "))}`)}
`);

  // Nothing else to do: the transport keeps the process alive, and the signal
  // handlers `mount()` installed unmount on Ctrl-C.
  if (mounted.transport === "fuse") {
    // `closed` also resolves if someone unmounts from outside, which is the
    // tidy way out.
    await mounted.closed;
    console.log(
      `\n${yellow("○")} ${bold("unmounted")} ${dim(JSON.stringify(mounted.session.stats))}`,
    );
    return;
  }
  // NFS has no equivalent: the mount is a client the server never hears from
  // again, so the listening socket is what holds the loop open and the signal
  // handler — which unmounts, then re-raises — is what ends the process.
  await new Promise<never>(() => {});
}

// --- helpers --------------------------------------------------------------

/** The command line, or a usage error and exit 2. */
function parseCli(): ReturnType<typeof parseArgs<typeof CLI>> {
  try {
    return parseArgs(CLI);
  } catch (error) {
    return fail(`${(error as Error).message}\n${dim("try --help")}`);
  }
}

/** Complain and exit. Only ever called before anything is mounted. */
function fail(message: string): never {
  console.error(`${red("!")} ${message}`);
  process.exit(2);
}

/** Resolve `path`, expanding a leading `~` the way a shell would have. */
function expand(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return resolve(homedir(), path.slice(2));
  return isAbsolute(path) ? path : resolve(path);
}

/**
 * One file, so there is something real to read: this package's own README,
 * copied into memory.
 *
 * Resolved relative to this module rather than to the working directory, and
 * two levels up in both forms — `src/cli/index.ts` and `dist/cli/index.mjs`
 * are the same distance from the package root, and npm publishes `README.md`
 * regardless of the `files` list. Unreadable is not fatal: the point of the
 * mount is the mount.
 */
async function seed(fs: ReturnType<typeof createLoopback>): Promise<void> {
  const readme = await readFile(new URL("../../README.md", import.meta.url), "utf8").catch(
    (error: Error) => `# mountx\n\nThe package README could not be read: ${error.message}\n`,
  );
  await fs.writeFile("/README.md", readme);
}

/**
 * What detaches a mount left behind by a killed run, for this user on this host.
 *
 * `kind` is a mount-table type (`fuse.mountx`, `nfs`, ...) or the transport name
 * that produced it, because only one of the two has an unprivileged route:
 * `fusermount3 -u` is setuid and `umount(8)` is not, so a stale NFS mount on
 * Linux is root's to clear either way.
 */
function staleCommand(target: string, kind: string): string[] {
  if (kind.startsWith("fuse") && (process.getuid?.() ?? -1) !== 0) {
    return ["fusermount3", "-u", "-z", target];
  }
  if (process.platform === "darwin") return ["umount", "-f", target];
  // Lazy, because the thing being cleaned up is usually a dead connection: the
  // kernel tears a FUSE session down when the last `/dev/fuse` reference goes,
  // so a killed server leaves a mountpoint that answers `ENOTCONN` rather than
  // one that hangs, and `-l` is what clears it (`src/fuse/mount.ts`).
  return ["umount", "-l", target];
}

/**
 * Detach whatever an earlier run left at `target`.
 *
 * **Only mounts this CLI could have made.** Anything else at that path belongs
 * to someone else, and a demo has no business unmounting it — `mount()` will
 * say so. Linux only: the check reads `/proc/self/mounts`, which macOS does not
 * have, and there the NFS transport's own teardown is the story.
 */
async function unmountStale(target: string): Promise<void> {
  if (process.platform !== "linux") return;
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
  if (type === undefined || !(type.startsWith("fuse") || type.startsWith("nfs"))) return;

  const [command, ...args] = staleCommand(target, type);
  if (command !== "fusermount3" && (process.getuid?.() ?? -1) !== 0) {
    // Escalating from here would mean a `sudo` reading a password off a pipe.
    console.error(
      `${yellow("!")} ${cyan(target)} is still mounted ${dim(`(${type})`)}\n` +
        `  clear it with ${bold(`sudo ${command} ${args.join(" ")}`)}`,
    );
    return;
  }

  console.log(`${yellow("!")} ${bold("unmounting stale")} ${cyan(target)} ${dim(`(${type})`)}`);
  try {
    await run(command!, args);
  } catch (error) {
    // Not fatal here: `mount()` refuses to stack and its message says the rest.
    console.error(red(`could not unmount ${target}: ${(error as Error).message}`));
  }
}
