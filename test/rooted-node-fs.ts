/**
 * `node:fs/promises` as an `FsDriver`, with every path joined onto a root.
 *
 * No resolution, no containment, no cleverness — that is the point. It is the
 * *oracle*: whatever the conformance suite asks of it, the kernel answers, so
 * a disagreement between this and a driver is the driver's. Used two ways:
 *
 * - rooted at a temp directory, it is the third column of `drivers.test.ts`
 *   (does the suite itself describe a real filesystem?);
 * - rooted at a **mountpoint**, it turns the same suite into the FUSE column of
 *   IDEA.md's conformance matrix — the driver under test never learns that a
 *   kernel and a transport are in the middle.
 */

import * as fsPromises from "node:fs/promises";
import { join } from "node:path";
import type { FsDriver } from "../src/types.ts";

export function rootedNodeFs(root: string): FsDriver {
  const real = (path: string): string => join(root, path);
  return {
    // The two things no driver's shape can reveal.
    capabilities: { handles: true, atomicRename: true },
    stat: (path) => fsPromises.stat(real(path)),
    lstat: (path) => fsPromises.lstat(real(path)),
    statfs: (path) => fsPromises.statfs(real(path)),
    readdir: (path, options) => fsPromises.readdir(real(path), options),
    open: (path, flags, mode) => fsPromises.open(real(path), flags, mode),
    mkdir: (path, options) => fsPromises.mkdir(real(path), options),
    rmdir: (path) => fsPromises.rmdir(real(path)),
    unlink: (path) => fsPromises.unlink(real(path)),
    rename: (from, to) => fsPromises.rename(real(from), real(to)),
    link: (from, to) => fsPromises.link(real(from), real(to)),
    symlink: (target, path) => fsPromises.symlink(target, real(path)),
    readlink: (path) => fsPromises.readlink(real(path)),
    chmod: (path, mode) => fsPromises.chmod(real(path), mode),
    chown: (path, uid, gid) => fsPromises.chown(real(path), uid, gid),
    lchown: (path, uid, gid) => fsPromises.lchown(real(path), uid, gid),
    truncate: (path, length) => fsPromises.truncate(real(path), length),
    utimes: (path, atime, mtime) => fsPromises.utimes(real(path), atime, mtime),
    lutimes: (path, atime, mtime) => fsPromises.lutimes(real(path), atime, mtime),
  };
}
