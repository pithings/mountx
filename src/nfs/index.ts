/**
 * The NFS loopback transport: `mountx/nfs`.
 *
 * The second transport over the same `FsDriver`, and the one that needs no
 * `/dev/fuse` and no native code — just a TCP socket (IDEA.md, "NFSv3
 * loopback"). It now speaks two versions on that one socket, NFSv3 (RFC 1813)
 * and NFSv4.1 (RFC 8881), behind a router that never loads a version's codec
 * a caller does not reach:
 *
 * - `xdr.ts` — XDR primitives (RFC 4506): a bounds-checked reader and writer
 *   that only ever throw `XdrError`.
 * - `rpc.ts` — ONC RPC v2 (RFC 5531): calls, replies, auth, and TCP record
 *   marking, encoded *and* decoded, plus the constants that frame a call in
 *   either version alike.
 * - `handles.ts` — the file handle table and the readdir cookie scheme,
 *   shared by both versions — the state a stateless protocol still needs.
 * - `util.ts` — the pressure valve between `v3/` and `v4/`, which never import
 *   from each other: version-neutral POSIX logic, the session options bag, and
 *   the one handle table / path lock / counters object the router builds once
 *   and hands to both.
 * - `v3/constants.ts` / `v3/protocol.ts` — RFC 1813 transcribed: every NFSv3
 *   and MOUNTv3 struct, both directions. `v3/session.ts` — bytes in, bytes
 *   out: both programs over a driver, with no socket anywhere.
 * - `v4/constants.ts` / `v4/attr.ts` / `v4/protocol.ts` — RFC 8881 (with RFC
 *   5662 for the XDR it states only in prose) transcribed: every NFSv4.1
 *   struct and the sparse `bitmap4`/`fattr4` attribute codec, both directions.
 *   `v4/state.ts` — client IDs, sessions, stateids, locks and the lease clock,
 *   pure and synchronous. `v4/session.ts` — COMPOUND dispatch over it, the
 *   same bytes-in-bytes-out shape as `v3/session.ts`.
 * - `session.ts` — the router in front of both: it peeks the `(prog, vers)` a
 *   record names and hands the bytes on unchanged to whichever versioned
 *   session owns it.
 * - `server.ts` — the socket, and `mount.ts` — `mount(8)` for either version.
 *
 * Everything except the last two runs on any OS with no privileges, which is
 * what makes the whole protocol testable by a JS client built from these same
 * codecs.
 */

export * from "./v3/constants.ts";
export * from "./handles.ts";
// Everything from `mount.ts` **except** `parseMountTable`/`mountEntryAt`/
// `MountEntry`, which are the platform's mount-table format rather than
// anything a consumer of this package composes with, and the pure refusal
// predicates (`ownershipRefusal`, `versionRefusal`, `isConsentDenial`,
// `consentAdvice`), which are what `mountNfs` says when it refuses rather than
// something a caller asks. Same treatment, and same reason, as the sub-struct
// helpers below: still exported from `mount.ts` for the tests and for the CLI.
export {
  liveNfsMounts,
  mountNfs,
  type MountNfsOptions,
  nfsClientProbe,
  type NfsClientProbe,
  type NfsMount,
  nfsMountOptions,
  type NfsPlatform,
  type NfsVersion,
  unmountAllNfs,
} from "./mount.ts";
// Everything from `protocol.ts` **except** the sub-struct helpers
// (`readFattr`/`writeFattr`, `readSattr`/`writeSattr`, the `post_op_*` and
// `wcc_data` pairs, `nfstime3`, `specdata3`). Those are the pieces the
// procedure codecs are built from, not something a consumer composes with —
// they are still exported from `mountx/nfs`'s own `protocol.ts` for the
// tests, they just do not belong on the package's public surface.
export {
  FATTR3_SIZE,
  entryPlusSize,
  entrySize,
  errnoCodeOfStatus,
  errnoOfStatus,
  fattrOf,
  fromTime,
  ftypeOf,
  modeTypeOf,
  nfsStatusOf,
  readAccessArgs,
  readAccessRes,
  readCommitArgs,
  readCommitRes,
  readCreateArgs,
  readCreateRes,
  readDirOp,
  readExportList,
  readFsinfoRes,
  readFsstatRes,
  readGetattrRes,
  readLinkArgs,
  readLinkRes,
  readLookupRes,
  readMkdirArgs,
  readMknodArgs,
  readMountList,
  readMountRes,
  readPathconfRes,
  readReadArgs,
  readReadRes,
  readReaddirArgs,
  readReaddirRes,
  readReaddirplusArgs,
  readReaddirplusRes,
  readReadlinkRes,
  readRenameArgs,
  readRenameRes,
  readSetattrArgs,
  readSymlinkArgs,
  readWccRes,
  readWriteArgs,
  readWriteRes,
  statusName,
  toTime,
  wccAttrOf,
  writeAccessArgs,
  writeAccessRes,
  writeCommitArgs,
  writeCommitRes,
  writeCreateArgs,
  writeCreateRes,
  writeDirOp,
  writeExportList,
  writeFsinfoRes,
  writeFsstatRes,
  writeGetattrRes,
  writeLinkArgs,
  writeLinkRes,
  writeLookupRes,
  writeMkdirArgs,
  writeMknodArgs,
  writeMountList,
  writeMountRes,
  writePathconfRes,
  writeReadArgs,
  writeReadRes,
  writeReaddirArgs,
  writeReaddirRes,
  writeReaddirplusArgs,
  writeReaddirplusRes,
  writeReadlinkRes,
  writeRenameArgs,
  writeRenameRes,
  writeSetattrArgs,
  writeSymlinkArgs,
  writeWccRes,
  writeWriteArgs,
  writeWriteRes,
} from "./v3/protocol.ts";
export type {
  Access3args,
  Access3res,
  Commit3args,
  Commit3res,
  Create3args,
  CreateRes,
  DirOpArgs,
  Entry3,
  EntryPlus3,
  ExportEntry3,
  Fattr3,
  Fsinfo3res,
  Fsstat3res,
  Getattr3res,
  Link3args,
  Link3res,
  Lookup3res,
  Mkdir3args,
  Mknod3args,
  MountEntry3,
  Mountres3,
  NfsTime3,
  Pathconf3res,
  Read3args,
  Read3res,
  Readdir3args,
  Readdir3res,
  Readdirplus3args,
  Readdirplus3res,
  Readlink3res,
  Rename3args,
  Rename3res,
  Sattr3,
  SetTime3,
  Setattr3args,
  SpecData3,
  Symlink3args,
  WccAttr,
  WccData,
  WccRes,
  Write3args,
  Write3res,
} from "./v3/protocol.ts";
export * from "./rpc.ts";
export * from "./server.ts";
export * from "./session.ts";
export * from "./xdr.ts";
