/**
 * Who a newly created entry belongs to, and the set-group-ID rule that decides
 * it.
 *
 * A driver creates everything as the server process, so every session hands a
 * fresh entry to its caller afterwards (`#claim`). "Its caller" is the easy
 * half. The group is not: POSIX declines to pick one, `mkdir(2)` saying the new
 * directory's group "shall be set to the group ID of the parent directory or to
 * the effective group ID of the process" and `open(2)` saying the same of a new
 * file. Linux picks between those two arms with the parent's set-group-ID bit,
 * and `inode(7)` states the choice as the meaning of the bit on a directory:
 * "newly created files in the directory inherit the group of the directory, and
 * newly created subdirectories inherit the set-group-ID bit". This is a
 * transcription of `inode_init_owner()` (`fs/inode.c`), which is where the
 * kernel makes that decision on behalf of every local filesystem — and which
 * nothing makes on behalf of a userspace one.
 *
 * The rule lives here rather than in a session because it is one rule and there
 * are four sessions. Two use it, and the other two say at their own `#claim`
 * why their wire settles this before or without them: 9P's client computes the
 * group and the bit itself (`v9fs_get_fsgid_for_create()`), and FUSE's does
 * not, but also does not carry the supplementary groups the file half of the
 * rule needs.
 *
 * **Not a rename.** Moving an entry into a set-group-ID directory does not
 * change its group on Linux, and `rename(2)` gives no licence to: the rule is
 * about creation, and `inode_init_owner()` is only called where an inode is
 * made.
 */

import { S_ISGID, S_IXGRP, type StatsLike } from "./types.ts";

/**
 * Who a request says it is, as far as its transport can say.
 *
 * `undefined` is "did not say" — `AUTH_NONE` over RPC — and stays `-1`, the
 * `node:fs` `chown` convention for "leave this one alone". `gids` is the
 * supplementary set; only `AUTH_SYS` carries one (`RpcCredentials`).
 */
export interface CallerCredentials {
  uid?: number | undefined;
  gid?: number | undefined;
  gids?: readonly number[] | undefined;
}

/** A new entry, described as the create that just made it described it. */
export interface NewEntry {
  /**
   * The parent directory's attributes as they were when it was created, or
   * `undefined` when they could not be read — in which case nothing is
   * inherited, which is the same answer a parent with the bit clear gives.
   */
  parent: StatsLike | undefined;
  /** Directories inherit the set-group-ID bit itself. Nothing else does. */
  directory: boolean;
  /** The permission bits the create used (`& 0o7777`). */
  mode: number;
}

/** What the new entry's owner, group and set-group-ID bit should be. */
export interface NewEntryOwnership {
  /** For `lchown`; `-1` means "leave it alone". */
  uid: number;
  /** For `lchown`; `-1` means "leave it alone". */
  gid: number;
  /**
   * The set-group-ID bit the entry has to end up with, or `undefined` when the
   * create already settled it — which is the overwhelmingly common answer, and
   * the one that costs no extra driver call.
   *
   * A **bit**, not a mode, and deliberately: the mode a create asks for is not
   * the mode it gets. `open(2)` and `mkdir(2)` mask their mode argument with
   * the umask of the process the driver runs in (and `vfs_mkdir` strips
   * `S_ISGID` from it outright), so re-asserting the requested mode through
   * `chmod` would hand the caller *wider* permissions than the same call gets
   * one directory over — at umask 022, `mkdir 0775` coming out `2775` under a
   * set-group-ID parent and `0755` under a plain one. {@link claimNewEntry}
   * therefore reads back what the driver actually created and changes this one
   * bit of it.
   */
  setgid: boolean | undefined;
}

/**
 * `inode_init_owner()`'s decision, for one new entry.
 *
 * Two departures from the kernel, both because the information is not on every
 * wire: a caller with no supplementary groups behaves as a caller in no
 * supplementary group (which errs towards *clearing* set-group-ID, the safe
 * direction), and `capable_wrt_inode_uidgid(dir, CAP_FSETID)` is read as uid 0,
 * since a userspace server has no other view of a remote caller's capabilities.
 */
export function newEntryOwnership(caller: CallerCredentials, entry: NewEntry): NewEntryOwnership {
  const uid = caller.uid ?? -1;
  const parent = entry.parent;
  if (parent === undefined || (parent.mode & S_ISGID) === 0) {
    // "} else inode->i_gid = current_fsgid();"
    return { uid, gid: caller.gid ?? -1, setgid: undefined };
  }
  // "if (dir && dir->i_mode & S_ISGID) { inode->i_gid = dir->i_gid;"
  const gid = parent.gid;
  if (entry.directory) {
    // "Directories are special, and always inherit S_ISGID." Asked for even
    // when the create named the bit itself: `mkdir(2)` is not allowed to set
    // it ("mode &= (S_IRWXUGO | S_ISVTX);" in `vfs_mkdir()`), so whether it is
    // there is a question for the driver rather than for the request, and
    // `claimNewEntry` skips the `chmod` when the answer is already yes.
    return { uid, gid, setgid: true };
  }
  // "else if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP) &&
  //  !in_group_p(inode->i_gid) && !capable_wrt_inode_uidgid(dir, CAP_FSETID))
  //  mode &= ~S_ISGID;" — a set-group-ID *executable* is a way to run as a
  // group, so one may not be created for a group the creator is not in.
  const setgidExecutable = (entry.mode & (S_ISGID | S_IXGRP)) === (S_ISGID | S_IXGRP);
  const member = caller.gid === gid || caller.gids?.includes(gid) === true;
  if (setgidExecutable && !member && uid !== 0) {
    return { uid, gid, setgid: false };
  }
  return { uid, gid, setgid: undefined };
}

/** The three driver calls giving an entry away can take. */
interface OwnershipDriver {
  lchown(path: string, uid: number, gid: number): Promise<void>;
  chmod(path: string, mode: number): Promise<void>;
  lstat(path: string): Promise<StatsLike>;
}

/**
 * Give `path` to `owner`, quietly.
 *
 * Deliberately skipped when the answer is the state the driver already
 * produced — the caller *is* the server process and nothing was inherited —
 * because that is the common case and worth a round trip. Deliberately quiet
 * when the driver has no `lchown`/`lstat`/`chmod` (`ENOSYS`) or is not
 * privileged enough to hand ownership away (`EPERM`/`ENOTSUP`): a driver with
 * no concept of ownership is not thereby broken, and failing the create it just
 * completed would be the wrong answer to that.
 *
 * The `chmod` runs **after** the `lchown`, not before: `chown(2)` clears
 * set-group-ID on an executable when an unprivileged caller changes ownership,
 * so a driver modelled on it would undo the bit in the other order.
 */
export async function claimNewEntry(
  driver: OwnershipDriver,
  path: string,
  owner: NewEntryOwnership,
): Promise<void> {
  const mine = owner.uid === (process.getuid?.() ?? -1) && owner.gid === (process.getgid?.() ?? -1);
  if (!mine && (owner.uid !== -1 || owner.gid !== -1)) {
    await quietly(driver.lchown(path, owner.uid, owner.gid));
  }
  if (owner.setgid !== undefined) {
    await quietly(setgid(driver, path, owner.setgid));
  }
}

/**
 * Turn `S_ISGID` on (or off) on an entry that has just been created.
 *
 * The mode chmod'ed is the one the driver **made**, read back, not the one the
 * create asked for: `open(2)`/`mkdir(2)` mask their mode argument with the
 * umask of the process the driver runs in and a `chmod` is not masked at all,
 * so re-asserting the requested mode here would silently widen the entry (see
 * {@link NewEntryOwnership.setgid}). That `lstat` is paid **only under a
 * set-group-ID parent** — every other create leaves `setgid` `undefined` and
 * never reaches here — and it is the same call that lets a driver which already
 * applied the rule itself be left alone.
 */
async function setgid(driver: OwnershipDriver, path: string, on: boolean): Promise<void> {
  const current = (await driver.lstat(path)).mode & 0o7777;
  const wanted = on ? current | S_ISGID : current & ~S_ISGID;
  if (wanted !== current) {
    await driver.chmod(path, wanted);
  }
}

async function quietly(call: Promise<void>): Promise<void> {
  try {
    await call;
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code !== "ENOSYS" && code !== "EPERM" && code !== "ENOTSUP") {
      throw error;
    }
  }
}
