/**
 * The WebDAV server: `mountx/webdav`.
 *
 * The second transport that is not a mount — it serves an `FsDriver` to a
 * WebDAV client (`rclone`, `curl`, `cadaver`, a file manager, `davfs2`) over
 * HTTP, one driver per share. Nothing here produces a mountpoint, which is why
 * it is outside `mountx/auto` for the same reason `mountx/s3` is: `auto`'s
 * contract is a mountpoint, and this never makes one.
 *
 * **Class 1 of RFC 4918** — every method except `LOCK` and `UNLOCK`, and the
 * `DAV` header says so rather than claiming a class 2 that is not there.
 * `src/webdav/session.ts`'s header sets out what that costs and which clients
 * it costs it with.
 *
 * Layered the way the other transports are:
 *
 * - `constants.ts` — the errno → status table (total over `ErrnoCode`), the
 *   protocol's literals, and the reason phrases a `propstat` needs.
 * - `protocol.ts` — pure request parsing and document building: the target as a
 *   driver path and back as an `href`, `Depth`/`Overwrite`/`Destination`, the
 *   two request grammars, `multistatus` and `error`.
 * - `session.ts` — a request in, a reply out, over one driver, with no socket.
 * - `server.ts` — the socket, and the only file that imports `node:http`.
 *
 * Everything except the last runs with no listener and no privileges, which is
 * what makes the protocol testable without a client.
 */

export * from "./constants.ts";
export * from "./protocol.ts";
export * from "./server.ts";
export * from "./session.ts";
