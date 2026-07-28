/**
 * A driver wrapper that narrates what the filesystem is being asked to do.
 *
 * ```ts
 * await mount(watchDriver(driver), mountpoint);
 * ```
 *
 * It is a `Proxy` around an `FsDriver`, so it works with any driver and adds
 * nothing to the library — playground scaffolding, not a public API. Open files
 * are followed too: `open` returns a wrapped {@link FileHandleLike} so writes
 * land under the path they belong to instead of a bare fd.
 *
 * **Everything is logged**, reads and stats included — a single `ls -l` is a
 * lookup and a getattr per entry, and seeing that volume is half the point of
 * watching. Colour carries the triage instead: mutations are bright, the
 * observers are dim, failures are red.
 *
 * The zero-copy contract still applies (`src/fuse/mount.ts`): the wrapper reads
 * `buffer.length` *before* awaiting and never keeps the buffer itself.
 */

// The kernel's values, not the host's: these flags come off the FUSE wire, and
// `src/fuse/constants.ts` says why substituting `node:fs`'s would be wrong.
import {
  O_ACCMODE,
  O_APPEND,
  O_CREAT,
  O_EXCL,
  O_RDONLY,
  O_TRUNC,
  O_WRONLY,
} from "../src/fuse/constants.ts";
import type { FileHandleLike, FsDriver } from "../src/types.ts";
import { CYAN, DIM, GREEN, paint, RED, YELLOW } from "./color.ts";

export interface WatchOptions {
  /** Where lines go. Default `console.log`. */
  log?: (line: string) => void;
}

/** Two paths, `from → to`, rather than one path and an argument. */
const TWO_PATHS = new Set(["rename", "link", "symlink"]);

export function watchDriver(driver: FsDriver, options: WatchOptions = {}): FsDriver {
  const log = options.log ?? ((line: string) => console.log(line));

  function emit(op: string, subject: string, note: string): void {
    const styled = paint(OP_STYLE[op] ?? DIM, op.padEnd(9));
    log(`${paint(DIM, stamp())}  ${styled} ${subject}${note && `  ${note}`}`);
  }

  /** Run `call`, log it, and log the errno instead if it fails. */
  async function watched<T>(
    op: string,
    subject: string,
    note: string,
    call: () => Promise<T>,
  ): Promise<T> {
    try {
      const result = await call();
      emit(op, subject, note && paint(DIM, note));
      return result;
    } catch (error) {
      emit(op, subject, paint(RED, `→ ${errnoOf(error)}`));
      throw error;
    }
  }

  function watchHandle(handle: FileHandleLike, path: string): FileHandleLike {
    return new Proxy(handle, {
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver) as unknown;
        if (typeof value !== "function" || typeof prop !== "string") return value;
        const method = value.bind(target) as (...args: unknown[]) => Promise<unknown>;
        return (...args: unknown[]) => {
          // Measured before the await: the caller may reuse this buffer the
          // moment the call returns.
          const size = args[0] instanceof Uint8Array ? `${args[0].length} B` : "";
          const note = prop === "truncate" ? `${args[0] ?? 0} B` : size;
          return watched(prop, path, note, () => method(...args));
        };
      },
    });
  }

  return new Proxy(driver, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value !== "function" || typeof prop !== "string") return value;
      const method = value.bind(target) as (...args: unknown[]) => Promise<unknown>;

      return async (...args: unknown[]) => {
        const [first, second] = args;
        const subject = TWO_PATHS.has(prop)
          ? `${first} ${paint(DIM, "→")} ${second}`
          : String(first);

        const result = await watched(prop, subject, describe(prop, args), () => method(...args));
        return prop === "open" ? watchHandle(result as FileHandleLike, String(first)) : result;
      };
    },
  }) as FsDriver;
}

// --- colour ---------------------------------------------------------------

/** Bright for the ops that change something; everything else stays dim. */
const OP_STYLE: Record<string, string> = {
  // creating
  mkdir: GREEN,
  symlink: GREEN,
  link: GREEN,
  write: GREEN,
  open: CYAN,
  // removing
  unlink: RED,
  rmdir: RED,
  truncate: RED,
  // moving and metadata
  rename: YELLOW,
  chmod: YELLOW,
  chown: YELLOW,
  lchown: YELLOW,
  utimes: YELLOW,
  lutimes: YELLOW,
};

// --- formatting -----------------------------------------------------------

/** The argument worth showing, per method. Everything else is just the path. */
function describe(op: string, args: readonly unknown[]): string {
  switch (op) {
    case "open": {
      return flagText(args[1]);
    }
    case "chmod": {
      return `0${(args[1] as number).toString(8)}`;
    }
    case "chown":
    case "lchown": {
      return `${args[1]}:${args[2]}`;
    }
    case "truncate": {
      return `${args[1] ?? 0} B`;
    }
    default: {
      return "";
    }
  }
}

function flagText(flags: unknown): string {
  if (typeof flags === "string") return flags;
  if (typeof flags !== "number") return "r";
  const mode = flags & O_ACCMODE;
  const parts = [mode === O_RDONLY ? "r" : mode === O_WRONLY ? "w" : "rw"];
  if (flags & O_CREAT) parts.push("create");
  if (flags & O_EXCL) parts.push("excl");
  if (flags & O_TRUNC) parts.push("trunc");
  if (flags & O_APPEND) parts.push("append");
  return parts.join(",");
}

function errnoOf(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : "EIO";
}

function stamp(): string {
  const now = new Date();
  return `${now.toTimeString().slice(0, 8)}.${String(now.getMilliseconds()).padStart(3, "0")}`;
}
