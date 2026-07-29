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

import { spawn } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { parseArgs } from "node:util";
import { mount, probeTransports, type Transport } from "../auto.ts";
import { createMemoryDriver } from "../drivers/memory.ts";
import { createLoopback } from "../harness.ts";
import type { FsDriver } from "../types.ts";
import { bold, cyan, dim, green, red, yellow } from "./color.ts";
import { watchDriver } from "./watch.ts";

const TRANSPORTS = new Set<string>(["auto", "fuse", "nfs"]);

/**
 * How long the stale-mount cleanup gets before it gives up on `umount(8)`.
 *
 * Not a formality on macOS: the network-volume consent gate turns an unapproved
 * `umount` into a call that never returns and does not die on `SIGKILL`
 * (`src/nfs/mount.ts`), and this runs *before* anything is mounted — a wait
 * with no ceiling here is a CLI that hangs with nothing on screen.
 */
const STALE_TIMEOUT = 5000;

const CLI = {
  allowPositionals: true,
  options: {
    mountpoint: { type: "string", short: "m" },
    transport: { type: "string", short: "t", default: "auto" },
    quiet: { type: "boolean", short: "q", default: false },
    verbose: { type: "boolean", short: "v", default: false },
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
  -v, --verbose            log the metadata polls too ${dim("(lstat, stat, statfs)")}
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
  // kernel makes is narrated — reads included, and the metadata polls too under
  // `--verbose`. The seeding above went to the bare driver, so the log starts
  // empty.
  const served: FsDriver = values.quiet ? driver : watchDriver(driver, { verbose: values.verbose });

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

${
  values.quiet
    ? dim("Requests are not logged (--quiet).")
    : values.verbose
      ? dim("Every request shows up below.")
      : dim("Requests show up below; --verbose adds the metadata polls.")
}
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
 * that produced it, because that is what decides whether there is an
 * unprivileged route at all — see {@link staleNeedsRoot}.
 */
function staleCommand(target: string, kind: string): string[] {
  if (kind.startsWith("fuse") && (process.getuid?.() ?? -1) !== 0) {
    return ["fusermount3", "-u", "-z", target];
  }
  // macOS has no lazy unmount, and `-f` is what an NFS mount whose server is
  // gone needs anyway: the client would otherwise wait for a flush nobody is
  // going to answer.
  if (process.platform === "darwin") return ["umount", "-f", target];
  // Lazy, because the thing being cleaned up is usually a dead connection: the
  // kernel tears a FUSE session down when the last `/dev/fuse` reference goes,
  // so a killed server leaves a mountpoint that answers `ENOTCONN` rather than
  // one that hangs, and `-l` is what clears it (`src/fuse/mount.ts`).
  return ["umount", "-l", target];
}

/**
 * Would {@link staleCommand}'s answer need privileges this process lacks?
 *
 * Two unprivileged routes, one per host, and they are unprivileged for
 * unrelated reasons: `fusermount3 -u` is setuid, and macOS is a BSD, where the
 * user who mounted a filesystem may unmount it — the same rule that lets the
 * NFS transport mount there without root in the first place
 * (`src/nfs/mount.ts`). Linux's `umount(8)` is neither, so a stale NFS mount
 * there is root's to clear.
 *
 * A macOS mount made by somebody *else* still refuses, and that shows up as the
 * spawn failing rather than as a guess made here.
 */
function staleNeedsRoot(command: string): boolean {
  if ((process.getuid?.() ?? -1) === 0) return false;
  return command !== "fusermount3" && process.platform !== "darwin";
}

/**
 * The mount-table type at `target`, or `undefined` if nothing is mounted there
 * and if the table would not say.
 *
 * Linux reads `/proc/self/mounts` directly; macOS has no such file, so the
 * table means spawning `mount(8)` — which `src/nfs/mount.ts` already does,
 * tri-state and all. It is imported dynamically so a Linux run, where FUSE is
 * the answer, never loads the NFS codec sitting behind it.
 *
 * "Could not read the table" collapses to `undefined` here, which is right for
 * this caller and not for that one: the worst this does on a bad guess is skip
 * a cleanup, and then `mount()` refuses to stack and says so.
 */
async function staleType(target: string): Promise<string | undefined> {
  if (process.platform === "darwin") {
    const { mountEntryAt } = await import("../nfs/mount.ts");
    return (await mountEntryAt(target, "darwin"))?.type;
  }
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
  return type;
}

/**
 * Detach whatever an earlier run left at `target`.
 *
 * **Only mounts this CLI could have made.** Anything else at that path belongs
 * to someone else, and a demo has no business unmounting it — `mount()` will
 * say so.
 *
 * Both matches are prefixes because both families spell themselves more than
 * one way: FUSE is `fuse`, `fuse.mountx` or `fuseblk`, and NFS is `nfs` for a
 * v3 mount and `nfs4` for a `vers=4.1` one (`src/nfs/mount.ts`).
 */
async function unmountStale(target: string): Promise<void> {
  const type = await staleType(target);
  if (type === undefined || !(type.startsWith("fuse") || type.startsWith("nfs"))) return;

  const [command, ...args] = staleCommand(target, type);
  if (staleNeedsRoot(command!)) {
    // Escalating from here would mean a `sudo` reading a password off a pipe.
    console.error(
      `${yellow("!")} ${cyan(target)} is still mounted ${dim(`(${type})`)}\n` +
        `  clear it with ${bold(`sudo ${command} ${args.join(" ")}`)}`,
    );
    return;
  }

  console.log(`${yellow("!")} ${bold("unmounting stale")} ${cyan(target)} ${dim(`(${type})`)}`);
  // Not fatal, whatever happens: `mount()` refuses to stack and its message
  // says the rest, so this reports and gets out of the way.
  const result = await run(command!, args, STALE_TIMEOUT).catch((error: unknown) => {
    console.error(red(`could not run ${command}: ${(error as Error).message}`));
    return undefined;
  });
  if (result === undefined || result.status === 0) {
    return;
  }
  const how = result.timedOut
    ? `no answer within ${STALE_TIMEOUT}ms`
    : result.stderr === ""
      ? `${command} exited ${result.status}`
      : result.stderr;
  console.error(red(`could not unmount ${target}: ${how}`));
  if (result.timedOut && process.platform === "darwin") {
    // The one failure whose cause is not the mountpoint. Named rather than
    // guessed at, by the transport that had to work it out.
    const { consentAdvice } = await import("../nfs/mount.ts");
    console.error(dim(consentAdvice(target)));
  }
}

interface RunResult {
  status: number | null;
  stderr: string;
  /** The deadline passed with the child still running. */
  timedOut: boolean;
}

/**
 * Run a command, bounded by `timeout`.
 *
 * The timeout **settles** rather than rejecting or waiting, and the child is
 * let go of completely — same reasoning as `src/nfs/mount.ts`'s `run`, which is
 * where it is written out in full: a `umount(8)` blocked inside the kernel
 * survives `SIGKILL`, so waiting for `close` would never return and holding on
 * to the child would keep this process's event loop alive after it has been
 * given up on.
 */
function run(command: string, args: readonly string[], timeout: number): Promise<RunResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, [...args], { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => {
      stderr += chunk;
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      child.stderr?.destroy();
      child.unref();
      resolvePromise({ status: null, stderr: stderr.trim(), timedOut: true });
    }, timeout);
    timer.unref();
    child.once("error", (error) => {
      clearTimeout(timer);
      rejectPromise(error);
    });
    child.once("close", (status) => {
      clearTimeout(timer);
      resolvePromise({ status, stderr: stderr.trim(), timedOut: false });
    });
  });
}
