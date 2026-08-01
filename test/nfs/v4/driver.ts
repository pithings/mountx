/**
 * An `FsDriver` over the Tier-1 NFSv4.1 client.
 *
 * `./client.ts` speaks the wire — filehandles, stateids, compounds. This is the
 * layer above it: the thing `test/conformance.ts` can run unmodified, which is
 * what makes the whole NFSv4.1 stack a column of the conformance matrix
 * (`./conformance.test.ts`). It is the counterpart of the `nfsDriver` at the
 * bottom of `../v3/client.ts`, and it lives in its own file only because
 * `./client.ts` is already the larger half of the pair.
 *
 * **What a v4 client has to do for itself**, and therefore what most of this
 * file is:
 *
 * - **Path resolution.** NFS has never had a multi-component path on the wire.
 *   `stat("/a/b/c")` is a PUTROOTFH and three LOOKUPs, and the symlinks between
 *   them are the client's to chase — the server refuses to cross one
 *   (`NFS4ERR_SYMLINK`) rather than resolving it. {@link nfs4Driver}'s `walk` is
 *   that, `ELOOP` at forty links and all.
 * - **The POSIX distinctions v4 collapsed.** NFSv3 had MKDIR, RMDIR, REMOVE,
 *   SYMLINK and MKNOD; NFSv4 has CREATE for everything that is not an ordinary
 *   file, OPEN for the ones that are, and one REMOVE for files and directories
 *   alike. So "`unlink` of a directory is an error" and "`rmdir` of a file is an
 *   error" are rules this file enforces before anything reaches the wire —
 *   which is exactly where a real client enforces them too, in the VFS above
 *   its own transport.
 * - **`open` of a directory.** OPEN is for ordinary files (§18.16.3), so a
 *   directory opened for reading — which `node:fs` allows, and which the
 *   conformance suite checks — cannot be an OPEN at all. It is a handle with no
 *   stateid behind it, and the `EISDIR` its first `read` earns comes from the
 *   server, over the wire, like every other error here.
 *
 * Everything else is thin: a `Fattr4Values` becomes a `StatsLike`, an `Entry4`
 * becomes a `DirentLike`, and an `Nfs4File` becomes a `FileHandleLike`.
 */

import { constants } from "node:fs";
import { fsError, rangeError, type ErrnoCode } from "../../../src/errors.ts";
import {
  type Fattr4Values,
  fromTime4,
  modeType4Of,
  numericOwner,
  parseNumericOwner,
  toTime4,
} from "../../../src/nfs/v4/attr.ts";
import {
  NF4BLK,
  NF4CHR,
  NF4DIR,
  NF4FIFO,
  NF4LNK,
  NF4SOCK,
  NFS4_OK,
  NFS4ERR_NOENT,
  OP_GETATTR,
  OP_GETFH,
  OP_LOOKUP,
  SET_TO_CLIENT_TIME4,
} from "../../../src/nfs/v4/constants.ts";
import type { Getattr4res, Getfh4res, Stateid4 } from "../../../src/nfs/v4/protocol.ts";
import { basename, dirname, joinPath, normalizePath } from "../../../src/path.ts";
import type {
  DirentLike,
  FileHandleLike,
  FsDriver,
  MkdirOptions,
  ReadResult,
  StatsFsLike,
  StatsLike,
  TimeLike,
  WriteResult,
} from "../../../src/types.ts";
import {
  S_IFBLK,
  S_IFCHR,
  S_IFDIR,
  S_IFIFO,
  S_IFLNK,
  S_IFMT,
  S_IFREG,
  S_IFSOCK,
} from "../../../src/types.ts";
import {
  ANONYMOUS_STATEID,
  type Nfs4Client,
  type Nfs4File,
  nfs4Error,
  OBJECT_ATTRS,
  op,
  openFlagsOf,
  putfh,
  resFor,
  shareAccessOf,
} from "./client.ts";

/** How many symlinks a resolution may traverse before it is a loop. */
const MAX_SYMLINKS = 40;

/**
 * The block size this client reports for `statfs`.
 *
 * NFSv4 has no FSINFO and no `rtmult`: the space attributes are counts of
 * *bytes* (§5.8.2.11 and its neighbours), and `maxread`/`maxwrite` are transfer
 * ceilings rather than an allocation unit. So the block size is the client's to
 * pick, and `statfs(2)` on a real NFS mount reports the transfer size for the
 * same reason — there is nothing else to report.
 */
const BLOCK_SIZE = 4096;

/**
 * `unlink` of a directory, refused before anything is sent.
 *
 * v4 has one REMOVE for files and directories alike (§18.25), so the POSIX
 * distinction is the client's to make — and a real NFSv4 client makes it in the
 * same place, its own VFS, with its own kernel's answer. The two families
 * disagree and always have: Linux says `EISDIR`, the BSDs say `EPERM`. This is
 * the one error in this column that comes from the host rather than from the
 * wire, and it is why both targets in `./conformance.test.ts` declare
 * `errors: "host"`.
 */
const UNLINK_DIR_CODE: ErrnoCode = process.platform === "linux" ? "EISDIR" : "EPERM";

/**
 * The `nfs_ftype4` a `mknod` mode is asking for — and a plain `Error` when it
 * is asking for something CREATE has no way to say.
 *
 * v4 has no MKNOD: a special file is a CREATE, and `createtype4` switches on
 * `nfs_ftype4` (§18.4). The mode's `S_IFMT` reaches the wire *only* here —
 * `fattr4`'s `mode` is permission bits, and `Nfs4Session.#create` takes the
 * type from `objtype` and nothing else — so the four device-ish types route
 * faithfully and the rest do not route at all:
 *
 * - `NF4REG` is `NFS4ERR_BADTYPE` by §15.1.4.1, because a regular file is
 *   created with OPEN. Diverting there would test this adapter's routing rather
 *   than the session's own regular-file fallback.
 * - `NF4DIR` *is* `mkdir` on this wire, so a mode naming a directory would
 *   quietly make one instead of earning the `EPERM` `mknod(2)` owes it.
 *
 * What is thrown is deliberately **not** errno-shaped: no `code`, no `errno`,
 * nothing `rejects()` in the conformance suite could match. Invariant 5 is the
 * whole point — deciding `EPERM` here would be this client inventing a refusal
 * that belongs to the driver on the far side, and the column would pass a case
 * it never carried. The cases that need it are gated on `mknod.anyType`, which
 * this column does not claim; anyone who un-gates one gets this, loudly,
 * instead of a fabricated errno.
 */
function ftype4Of(mode: number): number {
  switch (mode & S_IFMT) {
    case S_IFBLK: {
      return NF4BLK;
    }
    case S_IFCHR: {
      return NF4CHR;
    }
    case S_IFSOCK: {
      return NF4SOCK;
    }
    case S_IFIFO: {
      return NF4FIFO;
    }
    default: {
      throw new Error(
        `NFSv4.1 CREATE cannot ask for the type in mode 0o${mode.toString(8)}: ` +
          "`createtype4` names a block device, a character device, a socket, a FIFO " +
          "and a symlink, a regular file is OPEN's and a directory is mkdir's",
      );
    }
  }
}

/** A `fattr4`'s worth of values as the `StatsLike` a driver has to return. */
export function stats4Of(values: Fattr4Values): StatsLike {
  const mode = modeType4Of(values.type ?? 0) | ((values.mode ?? 0) & 0o7777);
  const is = (bits: number): boolean => (mode & S_IFMT) === bits;
  const rdev = values.rawdev ?? { major: 0, minor: 0 };
  return {
    dev: Number(values.fsid?.major ?? 0n),
    ino: Number(values.fileid ?? 0n),
    mode,
    nlink: values.numlinks ?? 1,
    uid: idOf(values.owner),
    gid: idOf(values.ownerGroup),
    rdev: (rdev.major << 8) | rdev.minor,
    size: Number(values.size ?? 0n),
    blksize: BLOCK_SIZE,
    blocks: Number((values.spaceUsed ?? 0n) / 512n),
    atimeMs: msOf(values.timeAccess),
    mtimeMs: msOf(values.timeModify),
    ctimeMs: msOf(values.timeMetadata),
    birthtimeMs: msOf(values.timeMetadata),
    isFile: () => is(S_IFREG),
    isDirectory: () => is(S_IFDIR),
    isSymbolicLink: () => is(S_IFLNK),
    isBlockDevice: () => is(0o060_000),
    isCharacterDevice: () => is(0o020_000),
    isFIFO: () => is(0o010_000),
    isSocket: () => is(0o140_000),
  };
}

/**
 * The uid or gid an `owner`/`owner_group` string names.
 *
 * §5.9's numeric form is the fast path and, for a session with no `idmap`
 * configured — which is what this column runs — the only form the server emits.
 * A name (`"root"`, `"user@example.org"`) is a mapping this client has no name
 * service to do, so it reports zero rather than inventing a number; every case
 * the conformance suite asks about goes through the numeric path.
 */
function idOf(owner: string | undefined): number {
  return owner === undefined ? 0 : (parseNumericOwner(owner) ?? 0);
}

/** An `nfstime4` as milliseconds, with "the server did not send one" as zero. */
function msOf(time: Fattr4Values["timeAccess"]): number {
  return time === undefined ? 0 : fromTime4(time);
}

/** An entry of a READDIR reply as the `DirentLike` `readdir` has to return. */
export function dirent4Of(name: string, values: Fattr4Values | undefined): DirentLike {
  const stats = values === undefined ? undefined : stats4Of(values);
  return {
    name,
    isFile: () => stats?.isFile() ?? false,
    isDirectory: () => stats?.isDirectory() ?? false,
    isSymbolicLink: () => stats?.isSymbolicLink() ?? false,
    isBlockDevice: () => stats?.isBlockDevice() ?? false,
    isCharacterDevice: () => stats?.isCharacterDevice() ?? false,
    isFIFO: () => stats?.isFIFO() ?? false,
    isSocket: () => stats?.isSocket() ?? false,
  };
}

/** A `TimeLike` as the `settime4` a SETATTR carries. */
function setTimeOf(value: TimeLike): { how: number; time: { seconds: bigint; nseconds: number } } {
  const ms = value instanceof Date ? value.getTime() : value * 1000;
  return { how: SET_TO_CLIENT_TIME4, time: toTime4(ms) };
}

/** A path resolved to a filehandle, with the attributes the LOOKUP asked for. */
interface Resolved {
  fh: Uint8Array;
  values: Fattr4Values;
}

/** Where a name lives, and what is already there under it. */
interface Target {
  /** The (resolved, symlink-free) directory holding the name. */
  dir: Uint8Array;
  /** The absolute path of that directory, for joining a relative link target. */
  dirPath: string;
  name: string;
  /** What the name currently is, or `undefined` for a name that is free. */
  found: Resolved | undefined;
}

/**
 * `FsDriver` over an {@link Nfs4Client}, rooted at `root`.
 *
 * `root` is what PUTROOTFH answers with — {@link Nfs4Client.rootFh} — passed in
 * rather than fetched here so that the driver holds no promise and every method
 * starts from a filehandle it already has, exactly as `../v3/client.ts`'s takes
 * the handle MOUNT gave it.
 */
export function nfs4Driver(client: Nfs4Client, root: Uint8Array): FsDriver {
  /** LOOKUP `name` under `dir`, with attributes, or `undefined` for ENOENT. */
  async function lookup(
    dir: Uint8Array,
    name: string,
    path: string,
  ): Promise<Resolved | undefined> {
    const reply = await client.compound(
      [
        putfh(dir),
        op(OP_LOOKUP, { objname: name }),
        op(OP_GETFH),
        op(OP_GETATTR, { attrRequest: OBJECT_ATTRS }),
      ],
      { tag: "lookup" },
    );
    if (reply.status === NFS4ERR_NOENT) {
      return undefined;
    }
    if (reply.status !== NFS4_OK) {
      throw nfs4Error(reply.status, "lookup", path);
    }
    return {
      fh: resFor<Getfh4res>(reply, OP_GETFH).object!,
      values: resFor<Getattr4res>(reply, OP_GETATTR).objAttributes!.values,
    };
  }

  /** The root, with attributes — the starting point of every walk. */
  async function rootOf(): Promise<Resolved> {
    return { fh: root, values: await client.getattr(root) };
  }

  /**
   * Resolve every component of `path`, following symlinks as `follow` says.
   *
   * The shape is `../v3/client.ts`'s, because the job is the same one: a
   * component that turns out to be a symlink is spliced out, the rest of the
   * path is appended to what it pointed at, and the whole thing is walked
   * again from the top with one more link on the counter.
   */
  async function walk(path: string, follow: boolean, depth = 0): Promise<Resolved> {
    if (depth > MAX_SYMLINKS) {
      throw fsError("ELOOP", { syscall: "open", path });
    }
    const parts = normalizePath(path).split("/").filter(Boolean);
    let current = await rootOf();
    for (const [index, name] of parts.entries()) {
      const last = index === parts.length - 1;
      const next = await lookup(current.fh, name, path);
      if (next === undefined) {
        throw fsError("ENOENT", { syscall: "lookup", path });
      }
      if (next.values.type === NF4LNK && (follow || !last)) {
        const target = await client.readlink(next.fh);
        const rest = parts.slice(index + 1).join("/");
        const base = target.startsWith("/")
          ? normalizePath(target)
          : joinPath(dirOf(parts, index), target);
        return walk(rest === "" ? base : joinPath(base, rest), follow, depth + 1);
      }
      current = next;
    }
    return current;
  }

  /** The directory `parts[index]` lives in, as an absolute path. */
  function dirOf(parts: string[], index: number): string {
    return index === 0 ? "/" : `/${parts.slice(0, index).join("/")}`;
  }

  /** Resolve the *parent* of a path, plus the final name. */
  async function parentOf(
    path: string,
    syscall: string,
  ): Promise<{ dir: Uint8Array; name: string }> {
    const normalized = normalizePath(path);
    if (normalized === "/") {
      throw fsError("EINVAL", { syscall, path });
    }
    const parent = await walk(dirname(normalized), true);
    if (parent.values.type !== NF4DIR) {
      throw fsError("ENOTDIR", { syscall, path });
    }
    return { dir: parent.fh, name: basename(normalized) };
  }

  /**
   * Where a name lives and what is under it, following a final symlink only
   * when `follow` says so.
   *
   * This is what `open` needs and `walk` cannot give it: the *parent* handle
   * and the name, for a name that may not exist yet — and, when the final
   * component is a symlink that is being followed, the parent of what it points
   * at, even if that is a dangling name. `open(path, "w")` on a dangling link
   * creates the link's target, which is only reachable this way.
   */
  async function targetOf(
    path: string,
    follow: boolean,
    syscall: string,
    depth = 0,
  ): Promise<Target> {
    if (depth > MAX_SYMLINKS) {
      throw fsError("ELOOP", { syscall, path });
    }
    const normalized = normalizePath(path);
    if (normalized === "/") {
      throw fsError("EISDIR", { syscall, path });
    }
    const dirPath = dirname(normalized);
    const parent = await walk(dirPath, true);
    if (parent.values.type !== NF4DIR) {
      throw fsError("ENOTDIR", { syscall, path });
    }
    const name = basename(normalized);
    const found = await lookup(parent.fh, name, path);
    if (found !== undefined && found.values.type === NF4LNK && follow) {
      const link = await client.readlink(found.fh);
      const next = link.startsWith("/") ? normalizePath(link) : joinPath(dirPath, link);
      return targetOf(next, follow, syscall, depth + 1);
    }
    return { dir: parent.fh, dirPath, name, found };
  }

  async function attrsOf(fh: Uint8Array): Promise<StatsLike> {
    return stats4Of(await client.getattr(fh));
  }

  /** The `node:fs` rejections for a bad `offset`, `length` or `position`. */
  function checkRange(buffer: Uint8Array, offset: number, length: number, position: number): void {
    if (offset < 0 || offset > buffer.byteLength) {
      throw rangeError("offset", `>= 0 && <= ${buffer.byteLength}`, offset);
    }
    if (length < 0 || offset + length > buffer.byteLength) {
      throw rangeError("length", `>= 0 && <= ${buffer.byteLength - offset}`, length);
    }
    if (position < -1) {
      throw rangeError("position", ">= -1", position);
    }
  }

  /**
   * An open file, or a directory a caller opened for reading.
   *
   * `file` is the OPEN's state — the stateid every READ and WRITE rides, and
   * the thing CLOSE releases. It is `undefined` for a directory, which has no
   * OPEN behind it (§18.16.3: OPEN is for ordinary files) and whose reads go
   * out under the anonymous stateid so that the `EISDIR` comes back from the
   * server rather than being invented here.
   */
  function makeHandle(fh: Uint8Array, flags: number, file: Nfs4File | undefined): FileHandleLike {
    let position = 0;
    const writable = (flags & constants.O_WRONLY) !== 0 || (flags & constants.O_RDWR) !== 0;
    const readable = (flags & constants.O_WRONLY) === 0;
    const append = (flags & constants.O_APPEND) !== 0;
    const stateid = (): Stateid4 => file?.stateid ?? ANONYMOUS_STATEID;
    return {
      async read(buffer, offset = 0, length, at): Promise<ReadResult> {
        const start = offset ?? 0;
        const count = length ?? buffer.byteLength - start;
        const from = at ?? -1;
        checkRange(buffer, start, count, from);
        if (!readable) {
          throw fsError("EBADF", { syscall: "read" });
        }
        const where = from === -1 ? position : from;
        const result = await client.read(fh, BigInt(where), count, stateid());
        buffer.set(result.data, start);
        if (from === -1) {
          position = where + result.data.byteLength;
        }
        return { bytesRead: result.data.byteLength, buffer };
      },
      async write(buffer, offset = 0, length, at): Promise<WriteResult> {
        const start = offset ?? 0;
        const count = length ?? buffer.byteLength - start;
        const from = at ?? -1;
        checkRange(buffer, start, count, from);
        if (!writable) {
          throw fsError("EBADF", { syscall: "write" });
        }
        let where = from === -1 ? position : from;
        if (append) {
          where = Number((await client.getattr(fh)).size ?? 0n);
        }
        const result = await client.write(
          fh,
          BigInt(where),
          buffer.subarray(start, start + count),
          stateid(),
        );
        if (from === -1 || append) {
          position = where + result.count;
        }
        return { bytesWritten: result.count, buffer };
      },
      stat: () => attrsOf(fh),
      async truncate(length = 0): Promise<void> {
        await client.setattr(fh, { size: BigInt(length) }, { stateid: stateid() });
      },
      async close(): Promise<void> {
        await file?.close();
      },
      async sync(): Promise<void> {
        await client.commit(fh);
      },
      async datasync(): Promise<void> {
        await client.commit(fh);
      },
    };
  }

  return {
    // NFSv4.1 is stateful, and the session does hold a driver handle per open —
    // but this server's filehandles are path-keyed (`src/nfs/handles.ts`), so a
    // REMOVE unbinds the path and every later operation on that handle answers
    // `NFS4ERR_STALE` before it reaches the descriptor. The session says the
    // same thing where it declines to advertise `OPEN4_RESULT_PRESERVE_UNLINKED`.
    // So an open file does not survive `unlink` here either; the capability is
    // declared lost in `./conformance.test.ts`, with the reasoning.
    // `extensions` is inferred from the keys of `mountx` below, so it is not
    // here.
    capabilities: { handles: false, atomicRename: true },

    mountx: {
      /**
       * CREATE of a device, a socket or a FIFO — the one place this adapter
       * offers a `mountx.*` member by name.
       *
       * It is not the extension crossing the wire — it is the wire operation
       * that already exists wearing the name the driver interface has for it.
       * The type travels in `createtype4` (see {@link ftype4Of}), the
       * permission bits in `fattr4`'s `mode`, and `Nfs4Session.#create` puts
       * the two back together for the driver. So the four device-ish types
       * route faithfully and nothing else does, which is what `carries` in
       * `./conformance.test.ts` says.
       *
       * `dev` comes apart the way `Nfs4Session.#create` puts it back together —
       * one 8-bit split across the project — which is what makes the round trip
       * through `specdata4`'s `major`/`minor` and back out of `rawdev` worth
       * testing at all. Every refusal the cases assert is the far side's,
       * arriving as an `nfsstat4`: nothing is decided here.
       */
      async mknod(path, mode, dev) {
        const type = ftype4Of(mode);
        const { dir, name } = await parentOf(path, "mknod");
        await client
          .mknod(dir, name, type, {
            mode: mode & 0o7777,
            major: dev >>> 8,
            minor: dev & 0xff,
          })
          .catch((error: unknown) => {
            throw retarget(error, path);
          });
      },
    },

    async stat(path) {
      return stats4Of((await walk(path, true)).values);
    },
    async lstat(path) {
      return stats4Of((await walk(path, false)).values);
    },
    async statfs(path): Promise<StatsFsLike> {
      const { fh } = await walk(path, true);
      const values = await client.statfs(fh);
      const bsize = BigInt(BLOCK_SIZE);
      return {
        type: 0x6969, // NFS_SUPER_MAGIC, as `statfs(2)` reports for an NFS mount.
        bsize: BLOCK_SIZE,
        blocks: Number((values.spaceTotal ?? 0n) / bsize),
        bfree: Number((values.spaceFree ?? 0n) / bsize),
        bavail: Number((values.spaceAvail ?? 0n) / bsize),
        files: Number(values.filesTotal ?? 0n),
        ffree: Number(values.filesFree ?? 0n),
      };
    },

    async readdir(path) {
      const { fh, values } = await walk(path, true);
      if (values.type !== NF4DIR) {
        throw fsError("ENOTDIR", { syscall: "scandir", path });
      }
      const entries = await client.readdirAll(fh, { attrRequest: OBJECT_ATTRS });
      return entries.map((entry) => dirent4Of(entry.name, entry.attrs.values));
    },

    async open(path, flags = "r", mode = 0o666) {
      const numeric = typeof flags === "number" ? flags : openFlagsOf(flags);
      const create = (numeric & constants.O_CREAT) !== 0;
      const exclusive = (numeric & constants.O_EXCL) !== 0;
      const writing = (numeric & constants.O_WRONLY) !== 0 || (numeric & constants.O_RDWR) !== 0;
      const normalized = normalizePath(path);

      // The root, and every other directory, reaches OPEN only to be refused:
      // §18.16.3 is for ordinary files. Reading one is still legal at the
      // `node:fs` level, so it gets a handle with no open state behind it.
      if (normalized === "/") {
        if (writing) {
          throw fsError("EISDIR", { syscall: "open", path });
        }
        return makeHandle(root, numeric, undefined);
      }

      // O_EXCL is the one case that must *not* follow a final symlink: the
      // link's own existence is what makes the create fail (`EEXIST`), and
      // resolving it would create the file it points at instead.
      const target = await targetOf(path, !exclusive, "open", 0);
      if (target.found !== undefined && target.found.values.type === NF4DIR) {
        if (writing) {
          throw fsError("EISDIR", { syscall: "open", path });
        }
        return makeHandle(target.found.fh, numeric, undefined);
      }
      if (!create && target.found === undefined) {
        throw fsError("ENOENT", { syscall: "open", path });
      }
      const file = await client.openAt(target.dir, target.name, {
        access: shareAccessOf(numeric),
        create,
        exclusive,
        truncate: (numeric & constants.O_TRUNC) !== 0,
        mode,
        path: normalized,
      });
      return makeHandle(file.fh, numeric, file);
    },

    async mkdir(path, options: MkdirOptions = {}) {
      const mode = (options.mode ?? 0o777) & 0o7777;
      if (options.recursive !== true) {
        const { dir, name } = await parentOf(path, "mkdir");
        try {
          await client.mkdir(dir, name, mode);
        } catch (error) {
          throw retarget(error, path);
        }
        return undefined;
      }
      // `recursive` is a client-side loop: NFS has no such operation, at either
      // version, which is also true of the kernel's client.
      const parts = normalizePath(path).split("/").filter(Boolean);
      let dir = root;
      let first: string | undefined;
      let walked = "";
      for (const [index, name] of parts.entries()) {
        walked = joinPath(walked, name);
        const found = await lookup(dir, name, walked);
        if (found !== undefined) {
          if (found.values.type !== NF4DIR) {
            // The last component already existing as a non-directory is
            // `EEXIST`; anything *inside* a non-directory is `ENOTDIR`, which
            // is what `node:fs` reports and what the driver would have said.
            throw fsError(index === parts.length - 1 ? "EEXIST" : "ENOTDIR", {
              syscall: "mkdir",
              path: walked,
            });
          }
          dir = found.fh;
          continue;
        }
        const made = await client.mkdir(dir, name, mode).catch((error: unknown) => {
          throw retarget(error, walked);
        });
        first ??= walked;
        dir = made.fh;
      }
      return first;
    },

    async rmdir(path) {
      // v4 has one REMOVE for both kinds of object, so "this is not a
      // directory" is the client's to say — and it must be said before the
      // REMOVE, which would otherwise unlink the file quite happily.
      const target = await walk(path, false);
      if (target.values.type !== NF4DIR) {
        throw fsError("ENOTDIR", { syscall: "rmdir", path });
      }
      const { dir, name } = await parentOf(path, "rmdir");
      await client.remove(dir, name).catch((error: unknown) => {
        throw retarget(error, path);
      });
    },
    async unlink(path) {
      const target = await walk(path, false);
      if (target.values.type === NF4DIR) {
        throw fsError(UNLINK_DIR_CODE, { syscall: "unlink", path });
      }
      const { dir, name } = await parentOf(path, "unlink");
      await client.remove(dir, name).catch((error: unknown) => {
        throw retarget(error, path);
      });
    },
    async rename(from, to) {
      const source = await parentOf(from, "rename");
      const destination = await parentOf(to, "rename");
      await client
        .rename(source.dir, source.name, destination.dir, destination.name)
        .catch((error: unknown) => {
          throw retarget(error, from);
        });
    },
    async link(existing, path) {
      const target = await walk(existing, false);
      const { dir, name } = await parentOf(path, "link");
      await client.link(target.fh, dir, name).catch((error: unknown) => {
        throw retarget(error, path);
      });
    },
    async symlink(target, path) {
      const { dir, name } = await parentOf(path, "symlink");
      await client.symlink(dir, name, target).catch((error: unknown) => {
        throw retarget(error, path);
      });
    },
    async readlink(path) {
      const { fh } = await walk(path, false);
      return client.readlink(fh).catch((error: unknown) => {
        throw retarget(error, path);
      });
    },

    async chmod(path, mode) {
      const { fh } = await walk(path, true);
      await client.setattr(fh, { mode: mode & 0o7777 }, { path });
    },
    async chown(path, uid, gid) {
      const { fh } = await walk(path, true);
      await client.setattr(fh, ownership(uid, gid), { path });
    },
    async lchown(path, uid, gid) {
      const { fh } = await walk(path, false);
      await client.setattr(fh, ownership(uid, gid), { path });
    },
    async truncate(path, length = 0) {
      const { fh } = await walk(path, true);
      await client.setattr(fh, { size: BigInt(length) }, { path });
    },
    async utimes(path, atime, mtime) {
      const { fh } = await walk(path, true);
      await client.setattr(fh, times(atime, mtime), { path });
    },
    async lutimes(path, atime, mtime) {
      const { fh } = await walk(path, false);
      await client.setattr(fh, times(atime, mtime), { path });
    },
  };
}

/**
 * Put the path back on an error the client raised for a filehandle.
 *
 * `./client.ts`'s helpers name what they can — a component, usually — and the
 * driver interface promises the whole path, which only the caller knows.
 */
function retarget(error: unknown, path: string): unknown {
  if (error instanceof Error && "code" in error) {
    Object.assign(error, { path });
  }
  return error;
}

function ownership(uid: number, gid: number): Fattr4Values {
  return {
    // `-1` is `node:fs`'s "leave this one alone", and an attribute left out of
    // the mask is v4's — the two say the same thing, so nothing is sent.
    owner: uid >= 0 ? numericOwner(uid) : undefined,
    ownerGroup: gid >= 0 ? numericOwner(gid) : undefined,
  };
}

function times(atime: TimeLike, mtime: TimeLike): Fattr4Values {
  return { timeAccessSet: setTimeOf(atime), timeModifySet: setTimeOf(mtime) };
}
