# Invariants, in full

`AGENTS.md` lists these as one-liners. This file is the same list with the reasoning
that stops each one being "fixed" by somebody who does not know why it is there.
Order matches `AGENTS.md`.

## Dependencies and packaging

**Zero runtime deps.** `unstorage` is an optional peer dependency (`"*"`), and
`src/drivers/unstorage.ts` imports it with `import type` only — check
`dist/drivers/unstorage.mjs` for an `unstorage` import if that file is touched.

**The native addon is optional, lazy, and never on the root path.** Mounting as root
opens `/dev/fuse` itself and touches no native code, so a host with no prebuilt for
its platform loses unprivileged mounting and nothing else. Anything added to
`native/` has to keep that true: if it becomes required, the pure-JS story is gone.

**What ships is the embed, not a binary.** `native/prebuilt.mjs` is the only
committed and published copy of the addon; `native/prebuilt/*.node` is a gitignored
`zig build` output. This is what makes bundling work — nothing has to be marked
external, nothing resolves a sibling path — and `native/index.mjs` never looks for
one, so `prebuilt/` being absent (as it is in CI and in every install) is not a case
it has to handle.

**The embed is the only copy anything loads.** `loadNative()` calls `loadEmbedded()`
and nothing else: no path, no `existsSync`, no `import.meta.url`.
`native/prebuilt/*.node` is consumed by `test/fuse/native.test.ts` and by nothing at
runtime, so "which copy am I running?" has one answer on every host, bundled or not.
This is why `pnpm build:native` is the command and `zig build` alone is not — a
rebuilt binary is not live until it has been re-embedded.

**`native/prebuilt.mjs` is generated, so it can go stale against `native/src/`.**
`zig build` alone rewrites `prebuilt/` and leaves the embed behind; `pnpm
build:native` runs both halves. `test/fuse/native.test.ts` compares every payload
against its `.node` file whenever `prebuilt/` exists — which is exactly on the
machine that just rebuilt it. Nothing in a fresh clone can check the embed against
the Zig source, so **regenerating it is part of any `native/src/` change**, not a
follow-up.

## The driver interface

**`FsDriver` is a subset of `node:fs/promises`**, proven by the assignability acid
test: `const driver: FsDriver = await import("node:fs/promises")` must compile with
no cast.

**Capabilities are declared-or-inferred, never faked.** An unmet capability answers
`ENOSYS`/`ENOTSUP`; it is never silently pretended.

**The errno table is transcribed once**, in `src/errors.ts`. The addon reports a raw
positive `errno` and lets `src/fuse/native.ts` name it, rather than carrying a second
copy of the table in another language where the two would drift. The same argument
covers a wire format two transports share: RFC 9110's `HTTP-date`, `Range` and `ETag`
spellings live in `src/http.ts` — with the two entity-tag comparison functions and the
§13.2.2 conditional-request rules built on them — and `src/s3/protocol.ts` re-exports
them under its own names while `src/webdav/` imports them directly. One transcription,
two HTTP transports; `evaluateConditionals` is wrapped rather than re-exported only
because SigV4 makes the S3 gateway keep its headers as a signed list. `src/xml.ts`
is the same arrangement for XML 1.0 and Namespaces in XML — the character rules, the
serializer and the bounded parser, re-exported by `src/s3/xml.ts`, imported directly
by `src/webdav/`.

## Wire protocols

**Wire constants are transcribed, never guessed or borrowed from host `node:fs`.**
FUSE constants come from the kernel's `include/uapi/linux/fuse.h`; NFS constants come
from RFC 1813/5531/4506 and, for v4.1, RFC 8881 with RFC 5662 for the XDR it does not
spell out; 9P constants come from the kernel's `include/net/9p/9p.h` (both header
sources pinned at tag v6.12) with diod's `protocol.md` as the prose reference; WebDAV's methods,
statuses, properties and precondition names come from RFC 4918, with RFC 4331 for the
quota pair and RFC 9110 for the HTTP underneath; the `fusermount3` handshake and the
Node-API declarations come from libfuse's and Node's own sources, both named where
they are used.

**The wire's `O_*` and a driver's `O_*` are different namespaces.**
`fuse_open_in.flags` is the Linux kernel's; `FsDriver` is a subset of
`node:fs/promises`, so a driver resolves what it is handed against the host.
`src/fuse/flags.ts` is the one crossing, and it is the identity on Linux — the only
host that mounts. Flags this server _originates_ for a driver (`mountx.mknod`'s
fallback) are already the host's and must not be translated. `Tlopen.flags`/
`Tlcreate.flags` are the same Linux `O_*` namespace as `fuse_open_in.flags` — 9P's
wire is the same kernel's — so `src/9p/session.ts` imports `src/fuse/flags.ts`'s
`driverOpenFlags()`/`reopenFlags()` rather than carrying a second copy of a fact
about Linux and the host.

**Errno discipline: exactly one reply per request** — one reply per _compound_, for
NFSv4.1, since COMPOUND is the one procedure everything else travels inside.
`handleMessage`/`handleCall` never reject; every request needing a reply gets exactly
one, a thrown value becomes a negative errno on FUSE (unknown → `EIO`), a positive
Linux errno in an `Rlerror` on 9P, an `nfsstat3` on NFSv3, a legal `nfsstat4` on
NFSv4.1 (an escaped `XdrError` → `NFS4ERR_BADXDR`, anything else →
`NFS4ERR_SERVERFAULT`), one S3 XML error body on the gateway, and one HTTP status —
mapped from the errno by `src/webdav/constants.ts`'s table, with a `DAV:` `<error>`
document when there is a §16 condition to carry — on WebDAV, and a dev-mode
assertion tracks it per request id. A retried `(session, slot, sequence)` on v4.1
answers from the slot's reply cache and re-runs nothing.

**A minor version other than 1 is refused, not guessed at.** `vers=4.1` and
`vers=4.0` are the same RPC `vers` field — 4 — so the router in `src/nfs/session.ts`
cannot tell them apart; the minor version travels inside COMPOUND instead, and
`src/nfs/v4/session.ts` answers anything but 1 with `NFS4ERR_MINOR_VERS_MISMATCH`
rather than serving it or claiming v4 is unavailable altogether.

**No grace period on NFSv4.1.** This server keeps no stable storage across a restart,
so there is nothing to reclaim and no window in which to reclaim it: every reclaiming
`OPEN` (`CLAIM_PREVIOUS`) or `LOCK` answers `NFS4ERR_NO_GRACE` unconditionally.
`RECLAIM_COMPLETE` still gates ordinary locking exactly as RFC 8881 §18.51.3
requires, independent of that — do not let "there is no grace period" read as
"RECLAIM_COMPLETE is a no-op".

## Buffers

**The zero-copy contract.** A session decodes and copies everything it keeps before
its first `await`; the transport dispatches each read without awaiting it and re-arms
the buffer as soon as that call returns. Breaking either half corrupts data under
concurrent I/O.

NFSv4.1's slot replay cache amends this in one place: `cacheReply()` copies the
encoded `COMPOUND4res` **on insert**, so the session may reuse its buffer the moment
the call returns, but hands its own array back **uncopied** on replay — the session
may read it but must never write to it, since copying again on every retransmission
would double the cost of the one path that exists to be cheap.

The NFS record layer does not participate in the view half at all: `RecordAssembler`
hands every record out as a copy, always, because view-or-copy-depending-on-how-the-
bytes-arrived is not a contract a caller can hold. The NFS **reply** path runs the
opposite rule, deliberately: `handleCall` returns `XdrWriter.view()` — a view of the
one writer that call built — and it is safe only because of two properties the code
must keep, one writer per reply (never pooled, never reused; the server dispatches up
to `maxInFlight` calls at once, so a shared writer would corrupt across clients) and
no write after `view()` (a later grow would leave the caller holding the old buffer).
Inbound copies because the buffer belongs to the socket; outbound does not because
the buffer belongs to the reply. `bytes()` remains for any caller that cannot promise
both.

**Decoders always copy the bytes they retain.** `Buffer.prototype.slice` is
`subarray`, not a copy — this exact mistake corrupted the first FUSE transcripts and
an NFS `WRITE` payload before both were fixed. **One deliberate exception, and it is
narrow:** `FuseRequest.payload` is a lazy memoized getter, so it copies whatever the
receive buffer holds _at the moment it is first read_ — which is the request's own
bytes only during the decode tick, before the transport re-arms. Nothing in `src/`
reads it (the decoded `body` is what the session uses, and `decodeWriteIn` makes the
contract copy eagerly); it stays exported for consumers, with the narrowing
documented on the field. Do not read `request.payload` after an `await`, and do not
add a second exception without the same treatment.

## Mounting and teardown

**No mount stacking.** Mounting over a live mountpoint — this process's own, or any
FUSE mount already in `/proc/self/mounts` — is refused, in both directions.

**An unreadable mount table means "still mounted", never "gone".** NFS teardown
treats "is it mounted" as a tri-state (`src/nfs/mount.ts`'s `isMounted`): forcing
down a mount that turns out to be gone is harmless, whereas reporting a successful
unmount on a guess shuts the server down under a live mount. This is why the table
read is async — macOS has no `/proc/self/mounts` and the table comes from spawning
`mount(8)`.

**Teardown has a deadline** (`unmountTimeout`, default 10 s) and escalates to `umount
-f` on expiry. Every spawned `umount` — and `fusermount3 -u`, and the `mount(8)` that
reads the table on macOS — is bounded by that deadline and abandoned if it outlives
it: a `umount(8)` parked in the kernel does not die on `SIGKILL`, and a child still
running is a child racing the escalation. The bound is **per phase, over a shared
`Deadline`, not per spawn**: asking nicely gets one `unmountTimeout` split across its
steps, the escalation ladder gets a second one split across its own, and a forced
teardown therefore settles within twice it — twice, with nothing added on top, which
is why FUSE's post-abort settle window is `min(1000, budget.remaining())` rather than
a flat second. A spawn given the whole timeout each is how the sum silently exceeded
the guarantee — do not reintroduce a bare `timeout: this.#options.unmountTimeout` at
a call site.

**Shutting the server down is a step of the phase, not something after it.**
`NfsServer.close()` and `P9Server.close()` end in `session.destroy()`, which closes
every handle the session still holds one at a time _through the driver_ — the same
driver that stopped answering, on every path that reaches a forced teardown — so both
mounts await it through a `#settle(budget)` that stops waiting when the budget does.
That is only safe because both servers close the listener and destroy every socket
_before_ the session teardown: what a lapsed budget abandons is the driver's own
`close()` calls and nothing else, exactly what FUSE's `#finish(true)` already
skipped. Closing the `/dev/fuse` fd only aborts the connection when no read is parked
on it.

**A `-t fuse` mount never receives `FUSE_DESTROY`.** The transport must detect
unmount itself (read EOF/`ENODEV` on `/dev/fuse`) and call `session.destroy()`; it is
idempotent and safe with requests in flight. 9P has the same shape and no protocol
message to detect it with either — there is no `Tdestroy` — so EOF on the connection
(`P9Connection.closed`: session destroyed _and_ the stream closed) is the unmount
signal there, exactly the way `/dev/fuse` EOF is for FUSE.

**On macOS the escalation can be refused outright.** Network volumes sit behind a
sandbox approval that is never prompted for a command-line process, so `umount`
blocks and `umount -f` answers `EPERM`; `src/nfs/mount.ts` names that case
(`isConsentDenial`/`consentAdvice`) instead of blaming the driver, and says the mount
survived. Do not paper over it — the fix is a grant the user makes in advance, and
verified facts live in `.agents/environment.md`.

**Unprivileged teardown is weaker, and says so.** Both routes to `fuse_abort_conn` —
`MNT_FORCE` and `/sys/fs/fuse/connections/<n>/abort` — are root's, so a user can only
`fusermount3 -u -z` and let the connection die with the superblock. Do not paper over
the difference.

## Process hazards

**Self-client threadpool hazard.** Serving a mount and using it (any sync `fs` call,
or enough concurrent async ones) from the same process parks threadpool threads the
read loop also needs, and wedges. Documented at the top of `src/fuse/mount.ts`. 9P
does not share the threadpool half of this — `P9Session` answers from the event loop
over a socket, not a threadpool-parked `read(2)`, so ordinary async `fs` calls
against a self-served 9P mount are safe — but it shares the `child_process.spawn()`
half: `uv_spawn` blocks the one thread that replies until the child execs, so a `cwd`
inside the mountpoint or a binary that _lives_ on it hangs the same way, and killing
the server does not free it (`fork` gave the child its own copy of the server
socket). Witnessed and documented at the top of `src/9p/mount.ts`.

**`process.exit()` does not work with a mount up.** Node's exit path joins the
threadpool the reads are parked in. `await unmount()` and set `process.exitCode`;
this is also why the signal handlers re-raise the signal instead of exiting directly.

## Repository hygiene

**Source stays NUL-free and grep-able.** E.g. the NFS cookie verifier delimiter is
the two-character string `"\0"`, never a literal NUL byte.

**Golden fixtures must give every field a distinct value.** A fixture built from
repeated/mirrored values (`uid: 0, gid: 0, size == used`) passes even with transposed
encoder/decoder fields; only an all-distinct fixture catches a symmetric
encode/decode bug.

**Published perf claims may come only from `.agents/benchmarks.md`**, and must carry
that file's host line with them. That covers `README.md` and `docs/` alike; the
README links to the docs rather than repeating the numbers, so
`docs/1.guide/6.tuning.md` is where they live.
