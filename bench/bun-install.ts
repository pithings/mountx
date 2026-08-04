/**
 * `pnpm bench:bun` — one real workload, on every transport that mounts, and an
 * answer to "who paid for it".
 *
 * `bench/index.ts` and `bench/fuse.ts` measure operations one at a time, which
 * is what you want when the question is "how much does a LOOKUP cost". This
 * script asks the other question: a package manager unpacking a dependency tree
 * onto the mount — thousands of files, a directory tree deeper than anything in
 * `bench/scenarios.ts`, and a client that keeps dozens of operations in flight
 * — and then says where the serving process's CPU actually went.
 *
 * Three instruments, because no one of them can answer it alone:
 *
 * - **A V8 CPU profile** of the serving process, sampled while the install
 *   runs, summarised here by source file and by function and written out as a
 *   `.cpuprofile` for Chrome DevTools / VS Code. This is the "what is taking
 *   most of the time" table, and its most important row is often `(idle)`: if
 *   the server is idle most of the wall clock, no amount of micro-optimising
 *   the codecs will move the workload, and the answer is in the kernel's caches
 *   or in the round trip instead.
 * - **Per-message accounting**, by wrapping the session's one entry point —
 *   `handleMessage` on FUSE, `handleCall` on 9P and NFS. The profile says which
 *   *functions* ran; this says which *requests* asked them to, which is the
 *   half you can act on by negotiating differently.
 * - **A host-filesystem baseline**: the same install, same warm package cache,
 *   in a plain directory. Without it "12 seconds" means nothing.
 *
 * Every mounting transport runs the same workload, one after another, each on
 * its own memory driver and its own mountpoint, and the comparison table at the
 * end is the point of running more than one: the driver and the client are
 * identical, so what is left is the transport and what its client caches.
 *
 * Two things this deliberately does not do. It does not wrap the driver — a
 * `Proxy` per call would land in the profile it is trying to take, and the
 * profile already attributes `src/drivers/memory.ts` by file. And it does not
 * iterate: one install is one sample, the numbers move a few percent between
 * runs, and the ranking is what is being read, not the third digit.
 *
 * ```sh
 * pnpm bench:bun                                     # fuse, 9p and nfs
 * pnpm bench:bun -- --transport 9p --package vite
 * pnpm bench:bun -- --transport fuse,nfs4 --json out.json
 * pnpm bench:bun -- --no-baseline --readers 4
 * ```
 *
 * Root, because mounting is — all three of these mount with `mount(8)`, and
 * `fusermount3` cannot help the other two. The install itself is dropped back
 * to the invoking user (`SUDO_UID`) for two reasons: it is the shape a mount is
 * for — someone else's process on the other side of the mountpoint — and it
 * keeps the workload pointed at that user's warm `~/.bun/install/cache`,
 * without which this measures the npm registry rather than the filesystem.
 */

import { spawn } from "node:child_process";
import {
  access,
  chmod,
  chown,
  constants,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import type { Profiler } from "node:inspector";
import { Session } from "node:inspector/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { messageName, P9_RLERROR } from "../src/9p/constants.ts";
import { mount9p, unmountAll9p } from "../src/9p/mount.ts";
import { readHeader } from "../src/9p/protocol.ts";
import { P9Reader } from "../src/9p/wire.ts";
import { createMemoryDriver } from "../src/drivers/memory.ts";
import { opcodeName } from "../src/fuse/constants.ts";
import { mount as mountFuse, type MountOptions, unmountAll } from "../src/fuse/mount.ts";
import { decodeInHeader, decodeOutHeader } from "../src/fuse/protocol.ts";
import { mountNfs, type NfsVersion, unmountAllNfs } from "../src/nfs/mount.ts";
import { decodeCall, decodeReply } from "../src/nfs/rpc.ts";
import type { NfsRequestContext } from "../src/nfs/session.ts";
import { NFS_PROGRAM, procedureName } from "../src/nfs/v3/constants.ts";
import { createLoopback, type Loopback } from "../src/harness.ts";
import type { FsDriver } from "../src/types.ts";
import { fixed, hostInfo, jsonTarget, sampleRate, table, type RateSample } from "./harness.ts";

/** The repository root, so profile URLs can be shortened against it. */
const REPO = dirname(dirname(fileURLToPath(import.meta.url)));

/** Where the install happens, inside the filesystem being served. */
const WORK = "/work";

/** Enough of a manifest for `bun install <pkg>` to have somewhere to write. */
const MANIFEST = `{\n  "name": "mountx-bench",\n  "version": "0.0.0",\n  "private": true\n}\n`;

const MIB = 1024 * 1024;

/** One frame of a sampled stack. `Runtime.CallFrame`, named where it is used. */
type CallFrame = Profiler.ProfileNode["callFrame"];

// --- options ---------------------------------------------------------------

/** `nfs` is NFSv3, `nfs4` is NFSv4.1 — the two the server answers on one socket. */
type TransportKey = "fuse" | "9p" | "nfs" | "nfs4";

const TRANSPORT_KEYS: readonly TransportKey[] = ["fuse", "9p", "nfs", "nfs4"];

/**
 * What `--transport` defaults to: the three that are a fair comparison.
 *
 * NFSv4.1 is left out because its per-message table would be a single
 * `NFS4:COMPOUND` row — see {@link nfsTransport} — not because it does not
 * mount. Ask for it by name.
 */
const DEFAULT_TRANSPORTS: readonly TransportKey[] = ["fuse", "9p", "nfs"];

interface Options {
  /** Which transports to run, in order. */
  transports: TransportKey[];
  /** What to install. Anything `bun install` accepts. */
  package: string;
  /** Where the `.cpuprofile`s go — one per transport, with the key appended. */
  profile: string;
  /** `--json <path>`, or `undefined`. */
  json: string | undefined;
  /** V8 sampling interval, microseconds. */
  intervalUs: number;
  /** Rows in the hotspot tables. */
  top: number;
  /** Run the same install on the host filesystem first, for scale. */
  baseline: boolean;
  /** Where that baseline install runs. Its filesystem is reported. */
  baselineDir: string;
  /** FUSE mount knobs worth turning from the command line. */
  mount: MountOptions;
  /**
   * Make the driver declare `capabilities.durableWrites`, so the FUSE session
   * stops answering `FLUSH` (`--durable-writes`).
   *
   * True of the memory driver this benchmark runs on — a write is in the node
   * the moment `write()` resolves — and *not* declared by it, because the
   * capability is a promise about `close(2)` error reporting rather than a
   * performance switch. Which mechanism does the declining is
   * `--flush enosys|noflush`; it does nothing on its own.
   */
  durableWrites: boolean;
  /**
   * 9P's `cache=` mode. Default `"none"`, which is the transport's own default
   * and the single biggest lever on this workload — see {@link p9Transport}.
   */
  p9Cache: string;
}

function value(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  return index === -1 ? undefined : argv[index + 1];
}

function numeric(argv: readonly string[], name: string): number | undefined {
  const raw = value(argv, name);
  if (raw === undefined) {
    return undefined;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) {
    throw new Error(`bench: ${name} wants a number, got ${raw}`);
  }
  return parsed;
}

function parseTransports(argv: readonly string[]): TransportKey[] {
  const raw = value(argv, "--transport");
  if (raw === undefined) {
    return [...DEFAULT_TRANSPORTS];
  }
  const asked = raw.split(",").map((name) => name.trim().toLowerCase());
  for (const name of asked) {
    if (!TRANSPORT_KEYS.includes(name as TransportKey)) {
      throw new Error(`bench: unknown transport ${name} — one of ${TRANSPORT_KEYS.join(", ")}`);
    }
  }
  return asked as TransportKey[];
}

function parseOptions(argv: readonly string[]): Options {
  const mountOptions: MountOptions = { fsname: "mountx-bench" };
  const readers = numeric(argv, "--readers");
  const attrTimeout = numeric(argv, "--attr-timeout");
  const entryTimeout = numeric(argv, "--entry-timeout");
  const negativeTimeout = numeric(argv, "--negative-timeout");
  if (readers !== undefined) {
    mountOptions.readers = readers;
  }
  if (attrTimeout !== undefined) {
    mountOptions.attrTimeout = attrTimeout;
  }
  if (entryTimeout !== undefined) {
    mountOptions.entryTimeout = entryTimeout;
  }
  if (negativeTimeout !== undefined) {
    mountOptions.negativeTimeout = negativeTimeout;
  }
  if (argv.includes("--writeback")) {
    mountOptions.init = { writebackCache: true };
  }
  const flush = value(argv, "--flush");
  if (flush !== undefined) {
    if (flush !== "enosys" && flush !== "noflush") {
      throw new Error(`bench: --flush wants enosys or noflush, got ${flush}`);
    }
    mountOptions.flushMechanism = flush;
  }
  return {
    transports: parseTransports(argv),
    package: value(argv, "--package") ?? "nuxt",
    profile: value(argv, "--profile") ?? join(REPO, "bun-install"),
    json: jsonTarget(argv),
    intervalUs: numeric(argv, "--interval") ?? 200,
    top: numeric(argv, "--top") ?? 15,
    baseline: !argv.includes("--no-baseline"),
    baselineDir: value(argv, "--baseline-dir") ?? tmpdir(),
    mount: mountOptions,
    durableWrites: argv.includes("--durable-writes"),
    p9Cache: value(argv, "--9p-cache") ?? "none",
  };
}

/**
 * The driver, with `durableWrites` declared on top when `--durable-writes` asks.
 *
 * Wrapped rather than made an option of `createMemoryDriver`: the claim is the
 * benchmark's, not the driver's, and keeping it out here means the column with
 * the flag and the column without it run *exactly* the same driver code.
 */
function withDurableWrites(driver: FsDriver, options: Options): FsDriver {
  if (!options.durableWrites) {
    return driver;
  }
  return { ...driver, capabilities: { ...driver.capabilities, durableWrites: true } };
}

/** What the FUSE column did about `FLUSH`, for its own summary line. */
function describeFlush(driver: FsDriver, options: Options): string {
  if (driver.capabilities?.durableWrites !== true) {
    return "answered";
  }
  return `declined via ${options.mount.flushMechanism ?? "enosys"}`;
}

// --- who runs the workload -------------------------------------------------

interface Identity {
  uid: number;
  gid: number;
  name: string;
  /** The install's `$HOME`, and so the package cache it will hit. */
  home: string;
}

/**
 * The user behind the `sudo`, and their home directory.
 *
 * `sudo` leaves `SUDO_UID`/`SUDO_GID` behind but points `HOME` at root's, and
 * root's package cache is empty on a machine where all the work has been done
 * as somebody else — which turns this benchmark into a download. So the home
 * directory is read from `/etc/passwd` by uid rather than taken from the
 * environment. `MOUNTX_BENCH_HOME` overrides it; running without `sudo -u`
 * (as plain root) is allowed and says what it costs.
 */
async function invoker(): Promise<Identity> {
  const uid = Number(process.env.SUDO_UID ?? Number.NaN);
  const gid = Number(process.env.SUDO_GID ?? Number.NaN);
  if (!Number.isInteger(uid) || !Number.isInteger(gid)) {
    return {
      uid: 0,
      gid: 0,
      name: "root",
      home: process.env.MOUNTX_BENCH_HOME ?? process.env.HOME ?? "/root",
    };
  }
  const name = process.env.SUDO_USER ?? String(uid);
  let home = process.env.MOUNTX_BENCH_HOME;
  if (home === undefined) {
    const passwd = await readFile("/etc/passwd", "utf8").catch(() => "");
    for (const line of passwd.split("\n")) {
      const fields = line.split(":");
      if (fields.length >= 6 && Number(fields[2]) === uid) {
        home = fields[5];
        break;
      }
    }
  }
  return { uid, gid, name, home: home ?? `/home/${name}` };
}

const executable = (path: string): Promise<boolean> =>
  access(path, constants.X_OK).then(
    () => true,
    () => false,
  );

/**
 * Find `bun`.
 *
 * `sudo` replaces `PATH` with its `secure_path`, which on most distributions
 * does not include wherever bun installed itself — so looking only at `PATH`
 * fails in a way that reads like bun is not installed at all. The package
 * script passes `MOUNTX_BENCH_BUN`; this is the fallback for a hand-run.
 */
async function findBun(home: string): Promise<string> {
  const explicit = process.env.MOUNTX_BENCH_BUN;
  const searched = explicit === undefined ? [] : [explicit];
  if (explicit === undefined) {
    const dirs = [
      ...(process.env.PATH ?? "").split(":").filter(Boolean),
      join(home, ".bun/bin"),
      "/opt/bun/bin",
      "/usr/local/bin",
    ];
    searched.push(...dirs.map((dir) => join(dir, "bun")));
  }
  for (const candidate of searched) {
    if (await executable(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    `bench: no executable bun among ${searched.length} candidate(s) — ` +
      "set MOUNTX_BENCH_BUN=/path/to/bun",
  );
}

// --- per-message accounting ------------------------------------------------

interface OpStat {
  /** `LOOKUP`, `Twalk`, `NFS:LOOKUP` — whatever the transport calls it. */
  name: string;
  count: number;
  /** Replies carrying an error status. `ENOENT` from a lookup is normal. */
  errors: number;
  /** Summed request *latency*, so concurrency makes it exceed the wall clock. */
  latencyMs: number;
  maxMs: number;
  bytesIn: number;
  bytesOut: number;
}

/**
 * The one entry point of a session, described so it can be counted.
 *
 * All four sessions have the same shape — bytes in, bytes out, never rejects —
 * which is what makes one wrapper enough. Each transport supplies the getter
 * and setter (rather than a session object and a method name) so that no part
 * of this has to reach through a type it does not own.
 */
interface CallEntry {
  /** The original, already bound. */
  call: (message: Uint8Array, ...rest: unknown[]) => Promise<Uint8Array | null>;
  /** Put the wrapper in place. */
  install: (
    wrapper: (message: Uint8Array, ...rest: unknown[]) => Promise<Uint8Array | null>,
  ) => void;
  /** Put the original back. */
  restore: () => void;
  /** What to call this request in the table. */
  describe: (message: Uint8Array) => string;
  /** Did the reply carry an error? `name` is what `describe` said. */
  failed: (reply: Uint8Array | null, name: string) => boolean;
}

interface OpTracker {
  stop: () => OpStat[];
}

/**
 * Count and time every request, by message name, until `stop()`.
 *
 * This wraps the session's entry point rather than asking the library for a
 * hook: the numbers are a benchmark's business and nothing in `src/` should
 * carry a counter for them. Two things make the wrapper safe. It is installed
 * after the mount call has returned, so whatever handshake the transport needs
 * — `FUSE_INIT`, `Tversion`/`Tattach`, `MNT` — is already done and cannot be
 * perturbed. And it honours the zero-copy contract at the top of
 * `src/fuse/mount.ts` (the other three transports repeat it): everything it
 * reads from `message`, and the call that hands `message` on, happen in the
 * synchronous prologue before the first `await`, so the session still owns the
 * bytes before the transport reuses the buffer.
 *
 * What it costs is one header decode and two `hrtime` reads per request — real,
 * and visible in the profile as `bench/bun-install.ts`, which is the honest
 * place for it to show up.
 */
function trackOps(entry: CallEntry): OpTracker {
  const stats = new Map<string, OpStat>();

  entry.install(async (message: Uint8Array, ...rest: unknown[]) => {
    const bytesIn = message.byteLength;
    const name = entry.describe(message);
    const started = process.hrtime.bigint();
    const reply = await entry.call(message, ...rest);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    let stat = stats.get(name);
    if (stat === undefined) {
      stat = { name, count: 0, errors: 0, latencyMs: 0, maxMs: 0, bytesIn: 0, bytesOut: 0 };
      stats.set(name, stat);
    }
    stat.count++;
    stat.latencyMs += elapsedMs;
    stat.maxMs = Math.max(stat.maxMs, elapsedMs);
    stat.bytesIn += bytesIn;
    stat.bytesOut += reply?.length ?? 0;
    if (entry.failed(reply, name)) {
      stat.errors++;
    }
    return reply;
  });

  return {
    stop: () => {
      entry.restore();
      return [...stats.values()].sort((a, b) => b.latencyMs - a.latencyMs);
    },
  };
}

/** Anything a header decode throws is "cannot say", never a benchmark failure. */
function quietly<T>(read: () => T, fallback: T): T {
  try {
    return read();
  } catch {
    return fallback;
  }
}

// --- the transports --------------------------------------------------------

/** One mounted filesystem, described in the only three ways the report needs. */
interface Mounted {
  /** The mount's own summary line: what it negotiated. */
  detail: string;
  /** The session's monotonic request counter, for the rate sampler. */
  requests: () => number;
  /** Install the per-message accounting. */
  track: () => OpTracker;
  unmount: () => Promise<void>;
}

interface Transport {
  key: TransportKey;
  /** Column heading. */
  label: string;
  mount: (driver: FsDriver, mountpoint: string, options: Options) => Promise<Mounted>;
}

const fuseTransport: Transport = {
  key: "fuse",
  label: "FUSE",
  async mount(driver, mountpoint, options) {
    const mounted = await mountFuse(driver, mountpoint, {
      // The install runs as somebody else, so it has to be let in. `sudo`
      // mounts do not need `user_allow_other` in `/etc/fuse.conf`;
      // unprivileged ones do, which is one more reason this script asks for
      // root. The other two transports have no equivalent — 9P's `access=client`
      // and NFS's `AUTH_SYS` let any local user in by construction.
      allowOther: true,
      ...options.mount,
    });
    const negotiated = mounted.session.negotiated;
    const session = mounted.session;
    return {
      detail:
        `protocol 7.${negotiated?.minor ?? 0}, max_write ` +
        `${fixed((negotiated?.maxWrite ?? 0) / 1024, 0)} KiB, readdirplus ` +
        `${negotiated?.readdirplus ?? false}, writeback ${negotiated?.writebackCache ?? false}, ` +
        `${options.mount.readers ?? 2} readers, attr/entry/negative timeout ` +
        `${options.mount.attrTimeout ?? 10}/${options.mount.entryTimeout ?? 10}/` +
        `${options.mount.negativeTimeout ?? 0} s, flush ` +
        `${describeFlush(driver, options)}`,
      requests: () => session.stats.requests,
      track: () => {
        const original = session.handleMessage.bind(session);
        return trackOps({
          call: original,
          install: (wrapper) => {
            session.handleMessage = wrapper;
          },
          restore: () => {
            session.handleMessage = original;
          },
          describe: (message) =>
            quietly(() => opcodeName(decodeInHeader(message).opcode), "UNDECODABLE"),
          failed: (reply) => reply !== null && quietly(() => decodeOutHeader(reply).error, 0) !== 0,
        });
      },
      unmount: () => mounted.unmount(),
    };
  },
};

/**
 * 9P, at whatever `cache=` mode was asked for.
 *
 * The cache mode is the one option this benchmark surfaces, because on this
 * workload it is not a detail: `cache=none` — the transport's default, and the
 * only mode 9P2000.L can offer *safely*, since the protocol has no way for a
 * server to tell a client that something it cached has changed — means no page
 * cache and no dentry cache, so every path component is walked again on every
 * syscall that names it. That is most of the message count in the table below,
 * and comparing it against FUSE's 10-second attribute and entry timeouts is
 * comparing two different bets rather than two codecs. `--9p-cache loose` makes
 * the other bet.
 *
 * The mount takes no other options: the point of the comparison is what each
 * transport ships with. `mount9p` makes its own 0700 socket directory, which is
 * the one thing it will not take from a caller's 0755 sandbox.
 */
const p9Transport: Transport = {
  key: "9p",
  label: "9P",
  async mount(driver, mountpoint, options) {
    const mounted = await mount9p(driver, mountpoint, { cache: options.p9Cache });
    // 9P is a session per connection, and the kernel's is the only one there
    // is — `mount9p` adopts exactly that connection and nothing else.
    const session = mounted.connection.session;
    return {
      // `cache=` is stated rather than read back: the kernel prints 9P's mount
      // options only where they differ from its own defaults, so the mode that
      // explains the message count is exactly the one the table omits.
      detail: `trans=${mounted.trans}, cache=${options.p9Cache}, ${await mountOptionsAt(mountpoint)}`,
      requests: () => session.stats.requests,
      track: () => {
        const original = session.handleCall.bind(session);
        return trackOps({
          call: original,
          install: (wrapper) => {
            session.handleCall = wrapper;
          },
          restore: () => {
            session.handleCall = original;
          },
          // `readHeader` off a bare reader, *not* `decodeP9`: that helper ends
          // with `reader.end()`, which insists the whole frame was consumed —
          // true of a codec, never true of a seven-byte peek. Getting this
          // wrong throws a `P9Error` per message, and since an `Error` captures
          // a stack, the first version of this benchmark spent 29% of the 9P
          // column building exceptions for itself to swallow.
          describe: (message) =>
            quietly(() => messageName(readHeader(new P9Reader(message)).type), "UNDECODABLE"),
          failed: (reply) =>
            reply !== null && quietly(() => readHeader(new P9Reader(reply)).type, 0) === P9_RLERROR,
        });
      },
      unmount: () => mounted.unmount(),
    };
  },
};

/**
 * `addr=` for a host with no `mount.nfs`.
 *
 * `mount(8)` hands NFS to the `mount.nfs` helper when there is one, and the
 * helper is what resolves `host:/path` into the `addr=` option the kernel
 * wants. Without it — this container has the client modules loaded and no
 * userland helper at all — util-linux goes straight to `fsconfig()` with the
 * options as written, the kernel finds no server address to match `proto=tcp`
 * against, and refuses with the memorable "Server address does not match
 * proto= option". Passing `addr=` ourselves is the whole fix, and it is only
 * passed when the helper is missing: where there is one, it builds its own.
 *
 * `127.0.0.1` rather than something read back from the mount: it is what
 * `mountNfs` puts in the `host:/path` source by default, and this benchmark
 * does not move the server off loopback.
 */
async function nfsMountOptionsFor(): Promise<string[]> {
  const helpers = [
    "/sbin/mount.nfs",
    "/usr/sbin/mount.nfs",
    "/bin/mount.nfs",
    "/usr/bin/mount.nfs",
  ];
  for (const helper of helpers) {
    if (await executable(helper)) {
      return [];
    }
  }
  return ["addr=127.0.0.1"];
}

/**
 * NFS, at either version the server speaks.
 *
 * The per-message table is per **RPC procedure**, which is the honest
 * granularity for v3 and a blunt one for v4.1: NFSv4 is one procedure,
 * COMPOUND, carrying an array of operations, and naming the operations inside
 * would mean decoding the COMPOUND a second time here — the kind of thing that
 * belongs in the session, not in a benchmark wrapper. So `nfs4` reports one row
 * and its wall clock, and `nfs` is the column to read a per-operation ranking
 * off.
 */
function nfsTransport(key: "nfs" | "nfs4", version: NfsVersion): Transport {
  return {
    key,
    label: version === 3 ? "NFSv3" : "NFSv4.1",
    async mount(driver, mountpoint) {
      const mounted = await mountNfs(driver, mountpoint, {
        version,
        mountOptions: await nfsMountOptionsFor(),
      });
      const session = mounted.server.session;
      return {
        detail: await mountOptionsAt(mountpoint),
        requests: () => session.stats.requests,
        track: () => {
          const original = session.handleCall.bind(session);
          return trackOps({
            // The context is `NfsRequestContext`, and the wrapper is typed in
            // `unknown`s so one wrapper can serve four sessions; this is the
            // one place the two meet.
            call: (message, ...rest) => original(message, rest[0] as NfsRequestContext),
            install: (wrapper) => {
              session.handleCall = wrapper;
            },
            restore: () => {
              session.handleCall = original;
            },
            describe: (message) =>
              quietly(() => {
                const { call } = decodeCall(message);
                if (call.program === NFS_PROGRAM && call.version >= 4) {
                  return "NFS4:COMPOUND";
                }
                const program = call.program === NFS_PROGRAM ? "NFS" : "MOUNT";
                return `${program}:${procedureName(call.program, call.procedure)}`;
              }, "UNDECODABLE"),
            // Every NFS procedure that can fail answers with its status in the
            // first word of the results — `nfsstat3` on v3, COMPOUND's `status`
            // on v4.1. MOUNT is left alone: `DUMP` and `EXPORT` answer with a
            // list rather than a status, and reading one as the other would
            // invent errors.
            failed: (reply, name) =>
              reply !== null &&
              name.startsWith("NFS") &&
              quietly(() => decodeReply(reply).results.u32("status"), 0) !== 0,
          });
        },
        unmount: () => mounted.unmount(),
      };
    },
  };
}

const TRANSPORTS: Record<TransportKey, Transport> = {
  fuse: fuseTransport,
  "9p": p9Transport,
  nfs: nfsTransport("nfs", 3),
  nfs4: nfsTransport("nfs4", "4.1"),
};

/** Every mount table this script can leave an entry in, asked in turn. */
async function unmountEverything(): Promise<unknown[]> {
  return [...(await unmountAll()), ...(await unmountAll9p()), ...(await unmountAllNfs())];
}

// --- the CPU profile -------------------------------------------------------

interface Hotspot {
  label: string;
  selfMs: number;
  /** Of the profiled window, idle included. */
  wallShare: number;
  /** Of the time the process was not idle. */
  busyShare: number;
}

interface ProfileSummary {
  wallMs: number;
  busyMs: number;
  idleMs: number;
  samples: number;
  areas: Hotspot[];
  functions: Hotspot[];
}

/** Run `body` with the V8 sampling profiler on, and hand back what it recorded. */
async function profiled<T>(
  intervalUs: number,
  body: () => Promise<T>,
): Promise<{ result: T; profile: Profiler.Profile }> {
  const session = new Session();
  session.connect();
  try {
    await session.post("Profiler.enable");
    await session.post("Profiler.setSamplingInterval", { interval: intervalUs });
    await session.post("Profiler.start");
    const result = await body();
    const { profile } = await session.post("Profiler.stop");
    return { result, profile };
  } finally {
    session.disconnect();
  }
}

/**
 * Which file a frame belongs to, shortened to something worth putting in a
 * table.
 *
 * Two kinds of frame have no url and so no file. V8's own — `(idle)`,
 * `(program)`, `(garbage collector)` — already name themselves, and `(idle)` is
 * usually the row that decides how to read every other one. The rest are native
 * bindings, and on this workload they are not noise: `writeBuffer` and `read`
 * *are* the round trip, so they are labelled rather than lumped.
 */
function areaOf(frame: CallFrame): string {
  if (frame.url === "") {
    if (frame.functionName === "") {
      return "(native)";
    }
    return frame.functionName.startsWith("(")
      ? frame.functionName
      : `(native) ${frame.functionName}`;
  }
  if (frame.url.startsWith("node:")) {
    return "node:internal";
  }
  const path = frame.url.startsWith("file://") ? fileURLToPath(frame.url) : frame.url;
  const rel = relative(REPO, path);
  return rel === "" || rel.startsWith("..") ? path : rel;
}

function labelOf(frame: CallFrame): string {
  const area = areaOf(frame);
  if (frame.url === "") {
    return area;
  }
  return `${frame.functionName === "" ? "(anonymous)" : frame.functionName}  ${area}:${frame.lineNumber + 1}`;
}

/**
 * Self time per frame, from the samples.
 *
 * Self time comes from `timeDeltas` rather than from `hitCount × interval`: the
 * sampler misses its deadline under load — which is exactly when this runs —
 * and the deltas are what actually elapsed. A delta is the gap *before* its
 * sample, and V8 occasionally emits a negative one; those are dropped rather
 * than subtracted from somebody else's total.
 */
function analyze(profile: Profiler.Profile, top: number): ProfileSummary {
  const frames = new Map<number, CallFrame>();
  for (const node of profile.nodes) {
    frames.set(node.id, node.callFrame);
  }
  const samples = profile.samples ?? [];
  const deltas = profile.timeDeltas ?? [];
  const byArea = new Map<string, number>();
  const byFunction = new Map<string, number>();
  let totalUs = 0;
  let idleUs = 0;
  for (const [index, id] of samples.entries()) {
    const delta = deltas[index] ?? 0;
    if (delta <= 0) {
      continue;
    }
    const frame = frames.get(id);
    if (frame === undefined) {
      continue;
    }
    const area = areaOf(frame);
    totalUs += delta;
    if (frame.functionName === "(idle)") {
      idleUs += delta;
    }
    byArea.set(area, (byArea.get(area) ?? 0) + delta);
    const label = labelOf(frame);
    byFunction.set(label, (byFunction.get(label) ?? 0) + delta);
  }
  const busyUs = totalUs - idleUs;
  const rank = (entries: Map<string, number>, limit: number): Hotspot[] =>
    [...entries]
      .sort(([, a], [, b]) => b - a)
      .slice(0, limit)
      .map(([label, us]) => ({
        label,
        selfMs: us / 1000,
        wallShare: totalUs === 0 ? 0 : us / totalUs,
        // `(idle)` has no share of busy — it is what busy is measured against,
        // and printing idle÷busy in that column invites reading it as one.
        busyShare: busyUs === 0 || label === "(idle)" ? 0 : us / busyUs,
      }));
  return {
    wallMs: totalUs / 1000,
    busyMs: busyUs / 1000,
    idleMs: idleUs / 1000,
    samples: samples.length,
    areas: rank(byArea, top),
    functions: rank(byFunction, top),
  };
}

// --- the workload ----------------------------------------------------------

interface InstallResult {
  wallMs: number;
  status: number | null;
  signal: NodeJS.Signals | null;
  output: string;
}

/**
 * `bun install <package>` in `dir`, as `who`.
 *
 * Spawned through `sh -c 'cd … && exec …'` rather than with `cwd` pointed at
 * the mount, and that is not a style choice: `uv_spawn` has the child `chdir`
 * while the calling thread blocks on the exec pipe, so a `cwd` inside our own
 * mountpoint would park the process that has to answer the lookup it causes
 * (the same trap `bench/drive.ts` documents, and it is a trap on every
 * transport — `uv_spawn` does not care which filesystem the path is on). The
 * shell's `cd` happens after the fork has been reported, in a process that is
 * not serving anything.
 */
function install(options: {
  bun: string;
  dir: string;
  package: string;
  who: Identity;
  /** Somewhere outside the mount for the spawn itself to stand in. */
  spawnCwd: string;
}): Promise<InstallResult> {
  return new Promise((resolve, reject) => {
    const started = process.hrtime.bigint();
    const child = spawn(
      "/bin/sh",
      ["-c", 'cd "$1" && exec "$2" install "$3"', "sh", options.dir, options.bun, options.package],
      {
        cwd: options.spawnCwd,
        uid: options.who.uid,
        gid: options.who.gid,
        env: {
          ...process.env,
          HOME: options.who.home,
          USER: options.who.name,
          LOGNAME: options.who.name,
          PATH: `${dirname(options.bun)}:${process.env.PATH ?? ""}`,
          // Nothing here should be reading these, but a child that believes it
          // is still under sudo is a debugging afternoon nobody needs.
          SUDO_UID: undefined,
          SUDO_GID: undefined,
          SUDO_USER: undefined,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let output = "";
    const collect = (chunk: string): void => {
      output += chunk;
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    child.once("error", reject);
    child.once("close", (status, signal) => {
      resolve({
        wallMs: Number(process.hrtime.bigint() - started) / 1e6,
        status,
        signal,
        output: output.trim(),
      });
    });
  });
}

interface TreeStats {
  files: number;
  dirs: number;
  symlinks: number;
  bytes: number;
}

/**
 * What the install left behind, counted through the driver rather than through
 * the mountpoint — the serving process must not be its own client, and this is
 * also two orders of magnitude cheaper than 14 000 round trips.
 */
async function walk(fs: Loopback, path: string, into: TreeStats): Promise<void> {
  const entries = await fs.readdir(path, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    const child = path === "/" ? `/${entry.name}` : `${path}/${entry.name}`;
    if (entry.isDirectory()) {
      into.dirs++;
      await walk(fs, child, into);
    } else if (entry.isSymbolicLink()) {
      into.symlinks++;
    } else {
      into.files++;
      const stats = await fs.lstat(child).catch(() => undefined);
      into.bytes += stats === undefined ? 0 : Number(stats.size);
    }
  }
}

/** One line of `/proc/self/mounts`, split. */
async function mountEntries(): Promise<{ point: string; type: string; options: string }[]> {
  const mounts = await readFile("/proc/self/mounts", "utf8").catch(() => "");
  const entries: { point: string; type: string; options: string }[] = [];
  for (const line of mounts.split("\n")) {
    const [, point, type, options] = line.split(" ");
    if (point !== undefined && type !== undefined && options !== undefined) {
      entries.push({ point, type, options });
    }
  }
  return entries;
}

/** What the kernel says it mounted, which is the only account of it that counts. */
async function mountOptionsAt(path: string): Promise<string> {
  for (const entry of await mountEntries()) {
    if (entry.point === path) {
      return `${entry.type} ${entry.options}`;
    }
  }
  return "not in the mount table";
}

/** The filesystem type behind a path, for the baseline's line in the report. */
async function filesystemOf(path: string): Promise<string> {
  let best = "unknown";
  let bestLength = -1;
  for (const entry of await mountEntries()) {
    const inside =
      path === entry.point || path.startsWith(entry.point === "/" ? "/" : `${entry.point}/`);
    if (inside && entry.point.length > bestLength) {
      best = entry.type;
      bestLength = entry.point.length;
    }
  }
  return best;
}

/** Everything one mounted, profiled install produces. */
interface Outcome {
  transport: TransportKey;
  label: string;
  detail: string;
  profilePath: string;
  run: InstallResult;
  summary: ProfileSummary;
  cpu: NodeJS.CpuUsage;
  tree: TreeStats;
  traffic: RateSample;
  stats: OpStat[];
  requests: number;
}

// --- report ----------------------------------------------------------------

const percent = (share: number): string => `${(share * 100).toFixed(1)}%`;

function opTable(stats: readonly OpStat[], requests: number): string {
  return table(
    [
      "message",
      "count",
      "% reqs",
      "latency ms",
      "mean µs",
      "max ms",
      "errors",
      "in MiB",
      "out MiB",
    ],
    stats.map((stat) => [
      stat.name,
      fixed(stat.count, 0),
      percent(requests === 0 ? 0 : stat.count / requests),
      fixed(stat.latencyMs, 1),
      fixed((stat.latencyMs * 1000) / stat.count, 1),
      fixed(stat.maxMs, 2),
      fixed(stat.errors, 0),
      fixed(stat.bytesIn / MIB, 1),
      fixed(stat.bytesOut / MIB, 1),
    ]),
  );
}

function hotspotTable(rows: readonly Hotspot[], heading: string): string {
  return table(
    [heading, "self ms", "% wall", "% busy"],
    rows.map((row) => [
      row.label,
      fixed(row.selfMs, 1),
      percent(row.wallShare),
      row.busyShare === 0 ? "—" : percent(row.busyShare),
    ]),
  );
}

const out = (text: string): void => {
  process.stdout.write(text);
};

/** One transport's section: what it did, what it was asked, and where it went. */
function reportOutcome(outcome: Outcome, options: Options): void {
  const { run, summary, cpu, tree, stats } = outcome;
  out(`\n## ${outcome.label}: bun install ${options.package}\n\n`);
  out(`${outcome.detail}\n\n`);
  out(
    `${fixed(run.wallMs / 1000, 2)} s wall, ${fixed(tree.files, 0)} files, ` +
      `${fixed(tree.dirs, 0)} dirs, ${fixed(tree.symlinks, 0)} symlinks, ` +
      `${fixed(tree.bytes / MIB, 1)} MiB, exit ${run.signal ?? run.status}\n`,
  );
  if (run.status !== 0) {
    out(`\nthe install did not succeed — every number below describes a failed run\n`);
  }
  if (run.output !== "") {
    out(`\n${run.output.replace(/^/gm, "  ")}\n`);
  }

  out(
    `\n${outcome.requests.toLocaleString("en-US")} requests, ` +
      `${fixed((outcome.requests / run.wallMs) * 1000)}/s mean, ` +
      `${outcome.traffic.peak.toLocaleString("en-US")}/s peak\n\n`,
  );
  out(`${opTable(stats, outcome.requests)}\n`);

  const cpuMs = (cpu.user + cpu.system) / 1000;
  out(
    `\n${fixed(cpuMs / 1000, 2)} s of process CPU over ${fixed(run.wallMs / 1000, 2)} s of wall ` +
      `(${percent(cpuMs / run.wallMs)} of one core): ${fixed(cpu.user / 1e6, 2)} s user, ` +
      `${fixed(cpu.system / 1e6, 2)} s system. Main thread: ` +
      `${fixed(summary.busyMs / 1000, 2)} s busy, ${fixed(summary.idleMs / 1000, 2)} s idle ` +
      `(${summary.samples.toLocaleString("en-US")} samples at ${options.intervalUs} µs)\n`,
  );

  out(`\n${hotspotTable(summary.areas, `${outcome.label}: self time by file`)}\n`);
  out(`\n${hotspotTable(summary.functions, `${outcome.label}: self time by function`)}\n`);
  out(`\nwrote ${outcome.profilePath}\n`);
}

// --- main ------------------------------------------------------------------

/** Mount, install, profile, unmount. Everything transport-specific is behind `transport`. */
async function measure(
  transport: Transport,
  options: Options,
  context: { sandbox: string; bun: string; who: Identity; index: number },
): Promise<Outcome> {
  const mountpoint = join(context.sandbox, `mnt-${transport.key}`);
  await mkdir(mountpoint, { recursive: true });
  const driver = withDurableWrites(createMemoryDriver(), options);
  const fs = createLoopback(driver);
  // Straight into the driver, before the kernel has ever heard of the mount:
  // the install needs a directory it owns and a manifest to add to.
  await fs.mkdir(WORK);
  await fs.writeFile(`${WORK}/package.json`, MANIFEST);
  await fs.chown(WORK, context.who.uid, context.who.gid);
  await fs.chown(`${WORK}/package.json`, context.who.uid, context.who.gid);

  process.stderr.write(`bench: mounting ${transport.label} at ${mountpoint} …\n`);
  const mounted = await transport.mount(driver, mountpoint, options);
  const tracker = mounted.track();
  const rate = sampleRate(mounted.requests);
  const startedCpu = process.cpuUsage();
  const profilePath = `${options.profile}.${transport.key}.cpuprofile`;
  try {
    process.stderr.write(`bench: bun install ${options.package} on ${transport.label} …\n`);
    const profiling = await profiled(options.intervalUs, () =>
      install({
        bun: context.bun,
        dir: join(mountpoint, WORK.slice(1)),
        package: options.package,
        who: context.who,
        // Outside the mount. See the note on `install`.
        spawnCwd: context.sandbox,
      }),
    );
    const cpu = process.cpuUsage(startedCpu);
    const traffic = rate.stop();
    const stats = tracker.stop();
    const tree: TreeStats = { files: 0, dirs: 0, symlinks: 0, bytes: 0 };
    await walk(fs, WORK, tree);
    await writeFile(profilePath, `${JSON.stringify(profiling.profile)}\n`);
    await chown(profilePath, context.who.uid, context.who.gid).catch(() => {});
    return {
      transport: transport.key,
      label: transport.label,
      detail: mounted.detail,
      profilePath,
      run: profiling.result,
      summary: analyze(profiling.profile, options.top),
      cpu,
      tree,
      traffic,
      stats,
      requests: stats.reduce((sum, stat) => sum + stat.count, 0),
    };
  } finally {
    // No-ops if the try block already stopped them; the point is the path where
    // it threw. A mountpoint left behind is the one failure mode of this script
    // that costs someone else an afternoon.
    rate.stop();
    tracker.stop();
    await mounted.unmount();
  }
}

async function main(): Promise<void> {
  const options = parseOptions(process.argv.slice(2));
  if ((process.getuid?.() ?? -1) !== 0) {
    process.stderr.write("bench: this one mounts, so it needs root — run `pnpm bench:bun`\n");
    process.exitCode = 1;
    return;
  }
  const who = await invoker();
  const bun = await findBun(who.home);
  if (who.uid === 0) {
    process.stderr.write(
      "bench: no SUDO_UID, so the install runs as root against root's package cache — " +
        "expect a download, not a filesystem benchmark\n",
    );
  }

  const sandbox = await mkdtemp(join(tmpdir(), "mountx-bun-"));
  // `mkdtemp` makes it 0700, and root's 0700 is a wall the install cannot walk
  // through to reach the mountpoints below it. The mounts' own permissions are
  // unaffected: they come from the driver.
  await chmod(sandbox, 0o755);

  const outcomes: Outcome[] = [];
  const skipped: { label: string; reason: string }[] = [];
  let baseline: { wallMs: number; filesystem: string; status: number | null } | undefined;
  try {
    // The host-filesystem numbers, taken before anything is mounted so nothing
    // this process serves can colour them. The warmup is thrown away on
    // purpose: it is what puts the registry metadata and every tarball in the
    // cache, and without it the first measured run pays for the network and
    // every later one does not.
    if (options.baseline) {
      for (const [name, keep] of [
        ["warmup", false],
        ["baseline", true],
      ] as const) {
        const parent = await mkdtemp(join(options.baselineDir, "mountx-bun-host-"));
        const dir = join(parent, name);
        await mkdir(dir);
        await writeFile(join(dir, "package.json"), MANIFEST);
        await chown(parent, who.uid, who.gid);
        await chown(dir, who.uid, who.gid);
        await chown(join(dir, "package.json"), who.uid, who.gid);
        process.stderr.write(`bench: ${name} install on the host filesystem …\n`);
        const run = await install({ bun, dir, package: options.package, who, spawnCwd: sandbox });
        if (keep) {
          baseline = {
            wallMs: run.wallMs,
            filesystem: await filesystemOf(dir),
            status: run.status,
          };
        }
        await rm(parent, { recursive: true, force: true });
      }
    }

    for (const [index, key] of options.transports.entries()) {
      const transport = TRANSPORTS[key];
      try {
        outcomes.push(await measure(transport, options, { sandbox, bun, who, index }));
      } catch (error) {
        // One transport that cannot mount here is a row in the table, not the
        // end of the run — `mount9p`/`mountNfs` refuse with a probe's reason,
        // and that reason is worth printing next to the ones that did run.
        const reason = error instanceof Error ? error.message : String(error);
        skipped.push({ label: transport.label, reason });
        process.stderr.write(`bench: ${transport.label} skipped — ${reason}\n`);
      }
    }
  } finally {
    for (const failure of await unmountEverything()) {
      process.stderr.write(`bench: unmount failed: ${String(failure)}\n`);
    }
    await rm(sandbox, { recursive: true, force: true }).catch(() => {});
  }

  // --- print it ------------------------------------------------------------

  const host = hostInfo();
  out(`\n${host.os} ${host.kernel}, ${host.cpus}× ${host.cpuModel}, node ${host.node}\n`);
  out(`bun ${bun}, as ${who.name} (uid ${who.uid}), HOME=${who.home}\n`);

  out(`\n## bun install ${options.package}: every transport\n\n`);
  out(
    `${table(
      ["transport", "wall s", "vs host", "requests", "req/s", "CPU s", "main thread busy"],
      [
        ...(baseline === undefined
          ? []
          : [
              [
                `host (${baseline.filesystem})`,
                fixed(baseline.wallMs / 1000, 2),
                "1.00×",
                "",
                "",
                "",
                "",
              ],
            ]),
        ...outcomes.map((outcome) => [
          outcome.label,
          fixed(outcome.run.wallMs / 1000, 2),
          baseline === undefined ? "" : `${fixed(outcome.run.wallMs / baseline.wallMs)}×`,
          fixed(outcome.requests, 0),
          fixed((outcome.requests / outcome.run.wallMs) * 1000, 0),
          fixed((outcome.cpu.user + outcome.cpu.system) / 1e6, 2),
          percent(outcome.summary.busyMs / Math.max(outcome.summary.wallMs, 1)),
        ]),
        ...skipped.map((skip) => [skip.label, "—", "—", "—", "—", "—", "—"]),
      ],
    )}\n`,
  );
  for (const skip of skipped) {
    out(`\n${skip.label} did not run: ${skip.reason}\n`);
  }
  out(
    `\nsame driver, same client, same warm package cache — what differs is the transport\n` +
      `and what its client caches. Request counts are not comparable between transports:\n` +
      `one open(2) is a different number of messages on each.\n`,
  );

  for (const outcome of outcomes) {
    reportOutcome(outcome, options);
  }

  out(
    `\nlatency is summed per request, so it exceeds the wall clock by however many\n` +
      `requests were in flight at once — read the ranking, not the total. The profile\n` +
      `is the main thread, where all the JS runs, while the CPU figure is the whole\n` +
      `process: main-thread idle next to more than one core of CPU means reader threads\n` +
      `in read(2), not a resting machine.\n`,
  );

  if (options.json !== undefined) {
    await writeFile(
      options.json,
      `${JSON.stringify(
        {
          host,
          command: "pnpm bench:bun",
          package: options.package,
          baseline,
          skipped,
          runs: outcomes.map((outcome) => ({
            ...outcome,
            run: { ...outcome.run, output: undefined },
          })),
        },
        null,
        2,
      )}\n`,
    );
    await chown(options.json, who.uid, who.gid).catch(() => {});
    out(`\nwrote ${options.json}\n`);
  }
  if (outcomes.some((outcome) => outcome.run.status !== 0)) {
    process.exitCode = 1;
  }
}

await main();
