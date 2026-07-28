# ⛰️mountx

> [!WARNING]
> **Alpha.** Mountx is early development: the API can still change, and it has not
> been through a security or correctness audit. A driver is reachable by every
> program on the machine once it is mounted.

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

Or mount a demo filesystem right now, and watch every request the kernel makes:

```sh
npx mountx
```

## Documentation

**[mountx.vercel.app](https://mountx.vercel.app)**

- [Quick Start](https://mountx.vercel.app/guide/quick-start) — install it and have a folder in about a minute.
- [Writing a driver](https://mountx.vercel.app/guide/drivers) — the interface, errors, capabilities, testing.
- [Mounting](https://mountx.vercel.app/guide/mounting) — `mount()`, the mount object, lifecycle and unmount.
- [Tuning](https://mountx.vercel.app/guide/tuning) — caching, concurrency, and the measured numbers.
- [Troubleshooting](https://mountx.vercel.app/guide/troubleshooting) — the things that will bite you, and how to recover.
- [Transports](https://mountx.vercel.app/transports) — FUSE and NFSv3, what each costs, and how to pin one.
- [Reference](https://mountx.vercel.app/reference) — every entry point, option and type.

## Development

<details>

<summary>local development</summary>

- Clone this repository
- Install the latest LTS version of [Node.js](https://nodejs.org/en/)
- Enable [Corepack](https://github.com/nodejs/corepack) with `corepack enable`
- Install dependencies with `pnpm install`
- Run tests in watch mode with `pnpm dev`
- `pnpm mountx` runs the CLI (`src/cli/index.ts`) from source: it mounts an
  in-memory copy of this README at `~/mountx` and logs every driver call it
  serves
- `pnpm test` runs lint, typecheck and the suites that need no root;
  `pnpm test:rootless` adds the unprivileged real-mount suite (still no
  `sudo`); `pnpm test:root` adds the ones that do need it.
- `pnpm build:native` rebuilds the FUSE mount helper with `zig build` and
  re-embeds it into `native/prebuilt.mjs`, which is the committed artifact —
  the `.node` files it is built from are gitignored. Only needed when
  `native/src/` changes.
- `pnpm matrix` and `pnpm bench` / `pnpm bench:root` regenerate the two
  committed reports the docs draw from
  (`.agents/conformance-matrix.md`, `.agents/benchmarks.md`).
- The docs site is `docs/`, its own pnpm project: `cd docs && pnpm install && pnpm dev`.

</details>

## License

Published under the [MIT](https://github.com/pithings/mountx/blob/main/LICENSE) license 💛.
