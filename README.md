# ⛰️mountx

**Write a filesystem in JavaScript, mount it as a real kernel filesystem.**

You can write a driver with the same methods as `node:fs/promises` (`stat`,
`readdir`, `open`, `mkdir`, `rename`). Mountx takes your driver and turns it into a real folder on the machine, so `ls`, `cat`, AI Agents, VSCode and any other program can use it.

There is no special API to learn: `node:fs/promises` already _is_ the
interface, and the errors it throws already _are_ the error format.

So anything that behaves a bit like a filesystem can get a real path: an
in-memory store, a zip file, an S3 bucket, a database, or a plain folder served back out with your own rules on top.

```ts
import { mount } from "mountx/auto";
import { createLoopback } from "mountx";
import { createMemoryDriver } from "mountx/drivers/memory";

// A driver is any object with stat(), readdir(), open(), [mkdir()] and [rename()] methods.
// Mountx has built-in memory and fs drivers
const driver = createMemoryDriver();

// Work with FS in-process without mounting
const fs = createLoopback(driver);
await fs.mkdir("/notes");
await fs.writeFile("/notes/hello.txt", "hi!");
new TextDecoder().decode(await fs.readFile("/notes/hello.txt")); // "hi"

// Mount the driver to the kernel with whatever this host can use
// FUSE on Linux (no root needed), NFSv3 on macOS
await using mounted = await mount(driver, "/mnt/point", {
  fuse: { attrTimeout: 10 }, // seconds the kernel may cache attributes
});

/**
# /mnt/point is a real folder now, so every program on the machine can use it:
$ cat /mnt/point/notes/hello.txt   =>   hi!
$ echo hey > /mnt/point/notes/other.txt
**/

if (mounted.transport === "fuse") {
  mounted.notifyInvalInode(2n); // storage changed behind mountx's back? drop the cache
}

await mounted.unmount(); // or let `await using` do it at the end of the block
```

## Install

```sh
npx nypm i mountx
```

The package has six entry points:

| import from              | what you get                                                  |
| ------------------------ | ------------------------------------------------------------- |
| `mountx/auto`            | **start here** — `mount()`, picks the transport for this host |
| `mountx`                 | the driver types, errors, loopback harness                    |
| `mountx/drivers/memory`  | a ready-made in-memory filesystem                             |
| `mountx/drivers/node-fs` | a ready-made passthrough to a real folder                     |
| `mountx/fuse`            | the FUSE transport on its own, if you want to pin it          |
| `mountx/nfs`             | the NFSv3 transport, and `createNfsServer()`                  |

`mountx/auto` is the one to import unless you have a reason not to: it works
out what this host can mount with and hands back that transport's own mount
object. Each subpath loads only what it needs — `auto` reaches a transport
through `await import()`, so choosing FUSE never loads the NFS stack.

## Step 1 — try it with no mounting at all

The easiest way to start is without touching the operating system. Wrap a
driver in `createLoopback()` and use it like `fs/promises` right inside your
program:

```ts
import { createLoopback } from "mountx";
import { createMemoryDriver } from "mountx/drivers/memory";

const fs = createLoopback(createMemoryDriver());

await fs.mkdir("/notes");
await fs.writeFile("/notes/hello.txt", "hi");

const entries = await fs.readdir("/notes", { withFileTypes: true });
console.log(entries.map((entry) => entry.name)); // [ "hello.txt" ]

const bytes = await fs.readFile("/notes/hello.txt"); // Uint8Array
console.log(new TextDecoder().decode(bytes)); // "hi"
```

`createLoopback` does the same tidying-up a real mount does: it cleans up
paths, answers `ENOSYS` for methods your driver does not have, and works out
what your driver supports. Nothing is mounted, no root needed, works on every
platform. This is the best place to develop and test a driver.

## Step 2 — mount it for real

Now the same driver, but as a folder anyone on the machine can open. `mount()`
from `mountx/auto` picks the transport this host can use — FUSE on Linux,
NFSv3 on macOS — so this is the same code everywhere:

```ts
// serve.ts
import { mount } from "mountx/auto";
import { createMemoryDriver } from "mountx/drivers/memory";

await using mounted = await mount(createMemoryDriver(), "/mnt/point");

mounted.transport; // "fuse" | "nfs" — which one you got

// /mnt/point is a real folder now. Keep the process alive.
await new Promise(() => {});
```

Run it:

```sh
node serve.ts
```

Then, **from another terminal**:

```sh
echo hi > /mnt/point/hello.txt
cat /mnt/point/hello.txt
ls -l /mnt/point
```

Press Ctrl-C in the first terminal and the folder disappears. `await using`
unmounts when the block ends; you can also call `await mounted.unmount()`
yourself.

**Do I need root?** On Linux, where you get FUSE: no, as long as `fusermount3`
is installed — it is the setuid helper that ships with FUSE, and it is already
there on most desktop Linux (`apt install fuse3` / `dnf install fuse3`
otherwise). Mounting is a syscall Node cannot make on its own, so mountx asks
`fusermount3` to make it and hand the connection back. If you are root, it
skips the helper and uses `mount(8)` directly. On macOS, where you get NFSv3,
mounting does need root — serving never does, on either transport.

Two things an unprivileged FUSE mount cannot do: `allowOther` needs
`user_allow_other` in `/etc/fuse.conf`, and forcing down a mount whose driver
has stopped answering is weaker (there is no `umount -f` without root).

**If a FUSE process dies without unmounting**, the folder is left stale rather
than frozen — `ls` says `ENOTCONN` instead of hanging. Clean it up with:

```sh
fusermount3 -u /mnt/point   # or, as root: umount -l /mnt/point
```

**Want to poke at one without writing it?** The repository ships a playground —
a seeded in-memory filesystem, mounted, with every request the kernel makes
printed as it happens:

```sh
sudo "$(command -v node)" playground/index.ts   # mounts /tmp/mountx-playground
```

Source: [`playground/index.ts`](https://github.com/pithings/mountx/blob/main/playground/index.ts).

## Step 3 — serve a real folder

The second bundled driver hands requests to a real directory, and makes sure
nothing outside it can be reached:

```ts
import { mount } from "mountx/auto";
import { createNodeFsDriver } from "mountx/drivers/node-fs";

await using mounted = await mount(createNodeFsDriver("/home/me/data"), "/mnt/point");
```

This is useful on its own, and it is also the easiest thing to build on: wrap
it, and you can add caching, logging, filtering or transformation to a normal
directory.

## Step 4 — write your own driver

A driver only has to answer three things: `stat`, `readdir` and `open`.
Everything else is optional, and a missing method simply means "not supported" —
the mount answers `ENOSYS`/`ENOTSUP` rather than pretending.

Here is a complete read-only filesystem with one file in it:

```ts
import { createLoopback, fsError } from "mountx";
import type { DirentLike, FsDriver, StatsLike } from "mountx";

const S_IFMT = 0o170000;
const S_IFREG = 0o100000;
const S_IFDIR = 0o040000;

const content = new TextEncoder().encode("hello from JavaScript\n");

// `stat` returns the same fields as `fs.Stats`, so a helper keeps it short.
function stats(mode: number, size: number, ino: number): StatsLike {
  const now = Date.now();
  const is = (type: number) => () => (mode & S_IFMT) === type;
  return {
    dev: 1,
    ino,
    mode,
    nlink: 1,
    uid: 0,
    gid: 0,
    rdev: 0,
    size,
    blksize: 4096,
    blocks: Math.ceil(size / 512),
    atimeMs: now,
    mtimeMs: now,
    ctimeMs: now,
    birthtimeMs: now,
    isFile: is(S_IFREG),
    isDirectory: is(S_IFDIR),
    isSymbolicLink: () => false,
    isBlockDevice: () => false,
    isCharacterDevice: () => false,
    isFIFO: () => false,
    isSocket: () => false,
  };
}

// A directory entry needs a name plus the same set of type questions.
const dirent = (name: string, mode: number): DirentLike => ({ name, ...stats(mode, 0, 0) });

const driver: FsDriver = {
  capabilities: { readOnly: true },

  async stat(path) {
    if (path === "/") return stats(S_IFDIR | 0o555, 0, 1);
    if (path === "/hello.txt") return stats(S_IFREG | 0o444, content.length, 2);
    throw fsError("ENOENT", { syscall: "stat", path });
  },

  async readdir(path) {
    if (path !== "/") throw fsError("ENOTDIR", { syscall: "scandir", path });
    return [dirent("hello.txt", S_IFREG | 0o444)];
  },

  async open(path) {
    if (path !== "/hello.txt") throw fsError("ENOENT", { syscall: "open", path });
    return {
      async read(buffer, offset, length, position) {
        const start = position ?? 0;
        const slice = content.subarray(start, start + (length ?? buffer.length));
        buffer.set(slice, offset ?? 0);
        return { bytesRead: slice.length, buffer };
      },
      async stat() {
        return stats(S_IFREG | 0o444, content.length, 2);
      },
      // Read-only, so the two writing methods just say so.
      async write(): Promise<never> {
        throw fsError("EROFS", { syscall: "write", path });
      },
      async truncate(): Promise<never> {
        throw fsError("EROFS", { syscall: "ftruncate", path });
      },
      async close() {},
    };
  },
};

const fs = createLoopback(driver);
console.log(new TextDecoder().decode(await fs.readFile("/hello.txt")));
// "hello from JavaScript"
```

Swap `createLoopback(driver)` for `mount(driver, "/mnt/point")` and the same
code becomes a folder you can `cat`.

### Errors

Throw errors the way `node:fs` does: an error with a POSIX `code` (like
`"ENOENT"`) and a negative `errno`. `fsError()` builds one that is byte-for-byte
identical to Node's, and it travels to the kernel untranslated:

```ts
throw fsError("EACCES", { syscall: "open", path });
```

If you are forwarding an error from a real `fs` call, just let it through — it
is already the right shape.

### Capabilities

Mountx works out what your driver supports from which methods exist. Two things
cannot be guessed from shape, so declare them if they are true:

```ts
const driver = {
  capabilities: {
    handles: true, // open() returns real state that survives unlink
    atomicRename: true, // rename() replaces the target in one step
  },
  // ...
};
```

Other flags you may want to set: `symlinks`, `hardlinks`, `caseSensitive`,
`statfs`, `readOnly`. The full list and the inference rules are in
`resolveCapabilities` (`src/harness.ts`). Nothing is ever faked: an unsupported
capability reports itself as unsupported.

### Testing your driver

`test/conformance.ts` in this repo is one suite written against the driver
interface, and it runs against the loopback harness with no mount needed. Point
it at your driver, or write your own checks the same way — anything that works
through `createLoopback()` works through a mount.

## Step 5 — transports

There are two, and `mountx/auto` is how you should normally reach either:

```ts
import { mount, probeTransports } from "mountx/auto";
import { createMemoryDriver } from "mountx/drivers/memory";

await using mounted = await mount(createMemoryDriver(), "/mnt/point");
mounted.transport; // "fuse" on Linux, "nfs" on macOS
```

It prefers FUSE wherever FUSE works — including unprivileged, via
`fusermount3` — and uses NFSv3 otherwise, which is what macOS gets. The result
is the transport's own mount object with a `transport` tag added, so narrowing
on it reaches everything that transport has (`session`, `fd`,
`notifyInvalInode` for FUSE; `server`, `port` for NFS) and `await using` works
the same.

Ask before you commit to it:

```ts
const probe = await probeTransports();
probe.chosen; // "fuse" | "nfs" | undefined
probe.reason; // when nothing can mount, what each transport is missing
```

Options common to both (`readOnly`, `signals`, `unmountTimeout`,
`useDriverIno`, `onError`, `onTransportError`) sit at the top level;
transport-specific ones go in `fuse: {…}` or `nfs: {…}` and win over the
shared ones.

Two deliberate limits. Naming a transport (`{ transport: "nfs" }`) skips the
probe, so the error you get is that transport's own. And there is no fallback
_after_ a failure: the probe decides once, and if the chosen transport then
fails, that error is what you get rather than a silent mount with different
semantics.

### What it is choosing between

| transport | `mount…()` runs on | serves to                     | root to mount          | what you lose         |
| --------- | ------------------ | ----------------------------- | ---------------------- | --------------------- |
| **FUSE**  | Linux              | the local kernel              | no, with `fusermount3` | nothing               |
| **NFSv3** | Linux, macOS       | anything with an NFSv3 client | yes                    | `handles` (see below) |

**FUSE** is preferred on Linux: you get real `open`/`release` state, control
over kernel caching, and every errno passes through untouched.

**NFSv3** covers everything that is not Linux-with-`/dev/fuse` — macOS, most
obviously, which has no usable FUSE (macFUSE is a third-party kernel extension
speaking its own protocol) but does ship an NFSv3 client. The trade-off is that
NFSv3 is stateless: there is no `open`/`release`, so every request carries a
handle built from the driver's `(dev, ino)` identity. In practice this costs one
behaviour — a file that is deleted while still open stays readable over FUSE,
but gives `ESTALE` over NFS.

Serving needs no native code at all — the protocols are pure JS, which is a
design rule of this project. The one exception is a ~7 KB helper used only to
receive the mount connection from `fusermount3`; it ships prebuilt, is loaded
only when you mount without root, and nothing else in the library touches it.
It survives bundling: the same bytes ship a second time as base64 inside
`native/prebuilt.mjs`, so when a bundler has moved the code away from the `.node`
file the loader extracts the embedded copy to a private temporary directory,
`dlopen`s it, and deletes it again. Nothing to configure, and nothing to mark as
external.
`createNfsServer()` runs anywhere Node does, including Windows: only putting a
_client_ in front of it is platform-specific.

### Pinning one yourself

`mountx/fuse` and `mountx/nfs` are the same transports without the probe, for
when you know what you want and would rather have that transport's own error
than a choice made for you:

```ts
import { mount } from "mountx/fuse"; // Linux only
import { mountNfs } from "mountx/nfs"; // Linux and macOS, needs root

await using mounted = await mount(createMemoryDriver(), "/mnt/point");
```

Their options sit at the top level rather than under `fuse: {…}`/`nfs: {…}`;
everything else is identical, because this is what `mountx/auto` calls.
`nfsClientProbe()` tells you whether the host has an NFS client before
`mountNfs()` tries, and names the missing piece; the option-string differences
between Linux and macOS are handled for you, and `nfsMountOptions()` returns the
exact `-o` string if you want to see it.

### Serving NFSv3 without mounting

Serving does **not** need root, on either transport. You can start just the NFS
server, then mount it yourself with whatever NFSv3 client you have:

```ts
import { createNfsServer } from "mountx/nfs";

await using server = createNfsServer(createMemoryDriver());
await server.listen();
console.log(server.port); // an ephemeral port unless you set one
```

```sh
# Linux
sudo mount -t nfs -o vers=3,tcp,port=<p>,mountport=<p>,nolock 127.0.0.1:/ /mnt

# macOS — `nolocks`, and no `hard` option (hard is the default there)
sudo mount -t nfs -o vers=3,tcp,port=<p>,mountport=<p>,nolocks,nobrowse 127.0.0.1:/ /mnt
```

`<p>` is `server.port` above, or `mounted.port` if you used `mountNfs()`.

By default the server binds to `127.0.0.1` and refuses non-loopback
connections. To reach it from another machine you must set both `host` and
`allowRemote: true` — and be aware that NFSv3 has no authentication worth the
name, so that exports your driver to anything that can reach the port.

## Tuning

Sensible defaults are already set; these are the knobs worth knowing. The two
that matter most for speed are FUSE options, so through `mountx/auto` they go
in `fuse: {…}` and are simply ignored on a host that mounts over NFS —
importing `mountx/fuse` directly takes the same options at the top level.

### Caching (this is where the speed is)

```ts
await mount(driver, "/mnt/point", {
  fuse: {
    attrTimeout: 10, // seconds the kernel may cache file attributes (default: 10)
    entryTimeout: 10, // seconds it may cache name → file lookups (default: 10)
    keepCache: true, // keep page cache between opens (default: true)
    negativeTimeout: 0, // also cache "this file does not exist" (default: 0, off)
  },
});
```

These two timeouts are worth far more than anything you can optimise in
JavaScript — see [Performance](#performance). Lower them if something other
than your driver changes the storage; raise them if nothing does. Turning on
`negativeTimeout` has the same caveat, but sharper: a file created behind
mountx's back stays invisible for the whole timeout.

### Concurrency

```ts
await mount(driver, "/mnt/point", { fuse: { readers: 2 } });
```

`readers` is how many reads are kept waiting on `/dev/fuse` at once. Each one
occupies a libuv threadpool thread, and so does any file I/O your driver does.
The default pool has four threads, so the default of `2` leaves two for the
driver. To go higher, raise both — and `UV_THREADPOOL_SIZE` must be set before
the process starts:

```sh
UV_THREADPOOL_SIZE=32 node serve.ts   # then readers: 8 is reasonable
```

### Other mount options

```ts
await mount(driver, "/mnt/point", {
  // shared — these mean the same thing on both transports
  readOnly: true, // the driver never sees writes
  unmountTimeout: 10_000, // ms before unmount stops asking nicely
  signals: true, // unmount on SIGINT/SIGTERM (default: true)

  fuse: {
    fsname: "mydata", // what /proc/mounts shows as the device
    subtype: "myfs", // makes the type read `fuse.myfs`
    allowOther: false, // let other users in (default: false)
  },
  nfs: {
    exportPath: "/", // hard, timeo, retrans and mountOptions live here too
    nobrowse: true, // macOS only, on by default: keeps Finder and Spotlight out
  },
});
```

`useDriverIno`, `onError` and `onTransportError` are shared as well. Whichever
transport is chosen gets its own block applied after the shared options, so a
value in `fuse: {…}`/`nfs: {…}` wins.

### Telling the kernel something changed

If your storage changes behind mountx's back, drop the kernel's cached copy:

```ts
if (mounted.transport === "fuse") {
  mounted.notifyInvalInode(42n); // forget this file's cached data and attributes
  mounted.notifyInvalEntry(1n, "hello.txt"); // forget this name → file mapping
}
```

Both take inode numbers as `bigint`. They are FUSE-only, which is what the
`transport` check narrows to — with `mountx/fuse` imported directly they are
just there.

## Things that will bite you

Each of these is documented in full where the code lives.

- **Mounting over NFS still requires root**, and so does FUSE on a host with no
  `fusermount3` — so `mount()` from `mountx/auto` needs root on macOS and on a
  Linux host without the helper. Serving never does; only attaching the mount to
  the filesystem.
- **Do not use your own mount from the process serving it.** A synchronous `fs`
  call against your own mountpoint deadlocks. Enough concurrent _async_ calls
  (for example `fs.rm(dir, { recursive: true })` over a few hundred entries) use
  up the threadpool that the mount's read loop also needs, and the process
  wedges. Put the client in another process, or keep the concurrency well below
  the pool size. Full explanation at the top of `src/fuse/mount.ts`.
- **Do not call `process.exit()` while mounted.** Node's exit path waits for the
  threadpool, and a live mount always has reads parked there — it will hang.
  Instead `await mounted.unmount()` and set `process.exitCode`. (This is also
  why the built-in signal handlers unmount and then re-raise the signal.)
- **A crashed process leaves a stale mount entry**, not a frozen one. `ls`
  answers `ENOTCONN`. Recover with `fusermount3 -u <mountpoint>`, or
  `sudo umount -l <mountpoint>` if you mounted as root.

## How well does it work?

One test suite (`test/conformance.ts`), written once against the driver
interface, is run three ways: through the loopback harness, through a real FUSE
mount, and through a real NFSv3 socket. So a test that passes in one column and
fails in another is a transport bug by construction, not a driver bug. Full
tables:
[`.agents/conformance-matrix.md`](https://github.com/pithings/mountx/blob/main/.agents/conformance-matrix.md).

The FUSE transport was also run against
[**pjdfstest**](https://github.com/pjd/pjdfstest), the POSIX filesystem test
suite, over a real mount: **59.1% passing** (5179/8770 assertions). Every one of
the 45 remaining failing files tests `mkfifo`/`mknod`/UNIX-socket creation —
which the driver interface simply has no way to express, since
`node:fs/promises` cannot create special files either. Breakdown:
[`.agents/pjdfstest-results.md`](https://github.com/pithings/mountx/blob/main/.agents/pjdfstest-results.md).

## Performance

All numbers below come from
[`.agents/benchmarks.md`](https://github.com/pithings/mountx/blob/main/.agents/benchmarks.md)
and were taken on **one host, on one day**: Linux 6.12.96+deb13-amd64, 16 ×
Intel i7-10700K @ 3.80 GHz, Node v24.18.0, in-memory driver. They are not
portable, and that file has the full tables and caveats.

- **Throughput:** sequential read **7,537 MiB/s** (served from page cache) or
  **1,526 MiB/s** with the cache off; sequential write 796 MiB/s over FUSE and
  308 MiB/s over NFS. Raising `max_write` from 128 KiB to 1 MiB is worth ~20%
  here — read that as "15–40%", and expect more from a driver doing real I/O.
- **FUSE handles 41,500–50,300 requests/sec** with requests in flight and
  timeouts off (1/2/4 readers: 41,539 / 48,549 / 50,349), and 13,600/sec for a
  strictly one-at-a-time client. With the shipped defaults (10 s timeouts, a
  cache-friendly mix) the measured peak is lower, around 20,468 requests/sec —
  because most of that traffic never reaches your driver at all. A
  single-threaded client sees 2,000–4,000 syscalls/sec on uncached metadata,
  since one syscall is several FUSE requests.
- **Cache settings matter far more than JavaScript tuning.**
  `attrTimeout`/`entryTimeout` are worth **8–15×**. `keepCache` is worth
  **~4.9×** on re-read. Nothing hand-optimised in this codebase comes close.

## Development

<details>

<summary>local development</summary>

- Clone this repository
- Install the latest LTS version of [Node.js](https://nodejs.org/en/)
- Enable [Corepack](https://github.com/nodejs/corepack) with `corepack enable`
- Install dependencies with `pnpm install`
- Run tests in watch mode with `pnpm dev`
- `sudo "$(command -v node)" playground/index.ts` mounts the playground
  (`playground/index.ts`) and logs every driver call it serves
- `pnpm test` runs lint, typecheck and the suites that need no root;
  `pnpm test:rootless` adds the unprivileged real-mount suite (still no
  `sudo`); `pnpm test:root` adds the ones that do need it.
- `pnpm build:native` rebuilds the prebuilt FUSE mount helper with `zig build`
  and re-embeds it into `native/prebuilt.mjs`. Both outputs are committed, so
  this is only needed when `native/` changes; `pnpm build:native:embed`
  re-embeds the committed binaries without a Zig toolchain.
- `pnpm matrix` and `pnpm bench` / `pnpm bench:root` regenerate the two
  committed reports this README draws from
  (`.agents/conformance-matrix.md`, `.agents/benchmarks.md`).

</details>

## License

Published under the [MIT](https://github.com/pithings/mountx/blob/main/LICENSE) license 💛.
