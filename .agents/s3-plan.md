# S3 transport plan (`mountx/s3`)

Working plan for the S3 gateway transport, executed step by step on `feat/s3`.
Each step: **implement → independently verify → fix until green → commit → tick
the checkbox here (same commit)**. Design rationale below is binding unless a
step's verifier proves it wrong, in which case update this file in the same
commit and say why.

## Process rules (every step)

- Implementation subagents run **`model: opus`**; docs/prose subagents run
  **`model: sonnet`** (roadmap "Subagent models" decision). Verification of
  implementation uses **opus**; verification of docs uses **sonnet**.
- The verifier is a **fresh, independent subagent** that did not write the
  code. It gets the step's acceptance criteria from this file, reads the diff,
  runs `pnpm test` (lint + typecheck + Tier 0/1), and adversarially checks the
  invariants in `AGENTS.md` (zero runtime deps, decoders copy what they keep,
  golden fixtures all-distinct, one reply per request, NUL-free source). It
  reports findings; it does not fix.
- Findings go back to an implementation agent; re-verify after fixes. Commit
  only when the verifier passes and `pnpm test` is green.
- Small conventional commits on `feat/s3` (e.g. `feat(s3): sigv4 codec`).
- Never edit `native/`; nothing here touches it.

## Decisions (settled with Pooya, 2026-07-28)

- **Shape:** a gateway server, not a mount. `createS3Server()` in `src/s3/`,
  exported as `mountx/s3`, sibling of `createNfsServer()`. **Not** part of
  `mountx/auto` (auto's contract is a mountpoint; S3 never produces one).
- **Bucket model:** `createS3Server(driver, opts?)` serves one bucket
  (`bucket` option, default `"mountx"`); `createS3Server({ buckets: { name:
driver, ... } }, opts?)` serves several. Path-style URLs only.
  `CreateBucket`/`DeleteBucket` → `NotImplemented` (501, S3 XML error).
- **Auth:** credentials optional. Without them: bind loopback only (refuse a
  non-loopback `host` option outright, named error), signatures parsed but not
  verified. With `{ accessKeyId, secretAccessKey }`: strict SigV4 (header and
  presigned-query forms, ±15 min clock skew), any bind allowed.
- **Supported ops:** ListBuckets, HeadBucket, ListObjectsV2, GetObject,
  HeadObject, PutObject, DeleteObject, DeleteObjects, CopyObject, and the five
  multipart calls. Everything else answers a well-formed S3 `NotImplemented`
  XML error — capabilities philosophy applied to the protocol: refused, never
  faked.
- **ETag:** derived, never a fake MD5: first 32 hex chars of sha256 over
  `dev:ino:size:mtimeMs`, suffixed `-1` (the multipart shape signals
  "not an MD5"; clients fall back to size/modtime). Stable across GETs.
- **mtime:** `x-amz-meta-mtime` (epoch seconds, rclone convention) on PUT maps
  to `driver.utimes()` when the driver has `times`; emitted from `stat.mtime`
  on HEAD/GET. All other `x-amz-meta-*` is dropped, documented. Content-Type
  is not stored; answered as `application/octet-stream`.
- **Directories:** prefixes. `PUT key/` (empty body) → `mkdir` recursive;
  `DELETE key/` → `rmdir` (`ENOTEMPTY` → 409). Listings emit a `dir/` marker
  object only for an **empty** directory (keeps `sync` able to recreate them
  without inflating listings).
- **ListObjectsV2:** `delimiter=/` → one `readdir` level (CommonPrefixes).
  No delimiter → sorted DFS walk. Full-key lexicographic order requires
  comparing by _effective key_ (`name` for files, `name + "/"` for dirs) at
  each level — plain name sort interleaves wrong (`a.txt` < `a/b` < `a0`).
  Continuation token = opaque base64 of the last emitted key (stateless
  start-after cursor), bounded by `max-keys` (default/cap 1000).
- **Conditionals & Range:** If-Match/If-None-Match/If-Modified-Since/
  If-Unmodified-Since on GET/HEAD (304/412); single-range `Range` with 416,
  mapped to positional reads through the open handle.
- **Multipart:** staged through the driver under a reserved bucket-root prefix
  `.mountx-multipart/<uploadId>/<part-N>` (upload ids from
  `crypto.randomBytes`). The prefix is invisible to every S3 op (404 on
  direct access, skipped in listings). Complete = streamed concat in part
  order (offsets are unknowable until all prior part sizes exist — parts
  arrive out of order and vary in size); Abort and server close clean it up.
- **Key ↔ path:** key `a/b` → path `/a/b` via `src/path.ts`. Keys that do not
  survive the round-trip (empty segments `a//b`, `.`/`..` segments, NUL) →
  400 `InvalidArgument` rather than quiet corruption — same posture as the
  unstorage driver's `EINVAL`; over-length keys → S3's own `KeyTooLongError`.
  Staging-prefix keys are answered the way an **absent** key is answered, by
  method — invisibility, per the multipart decision; a 400 would advertise the
  reserved name and disagree with listings (this bullet originally said 400,
  contradicting the multipart bullet; resolved toward invisibility during step
  4). `DELETE` → 204 (S3's answer for deleting a missing key), `GET`/`HEAD` →
  `NoSuchKey` 404, `PUT`/`POST` → `NoSuchKey` 404, which is the one remaining
  tell and is accepted knowingly: the alternatives are a 200 that drops the
  bytes or an `AccessDenied` that says the name is guarded.
- **Session boundary is streaming** (unlike `NfsSession.handleCall(bytes)`):
  `S3Session.handleRequest(head, body: AsyncIterable<Uint8Array>)` →
  `{ status, headers, body?: Uint8Array | AsyncIterable<Uint8Array> }`.
  `node:http` appears **only** in `server.ts`. Copy-what-you-keep applies to
  header/body bytes retained past an await.
- **Error discipline:** exactly one well-formed reply per request; a thrown
  value maps errno → S3 code via one table in `constants.ts` (`ENOENT` →
  `NoSuchKey`, `EACCES`/`EPERM` → `AccessDenied`, `ENOTEMPTY` → 409, unknown
  → `InternalError` 500), with the dev-mode single-reply assertion the other
  sessions carry.
- **Transcription sources** (no RFC exists; name them where used): AWS S3 API
  reference + error-responses page; AWS SigV4 spec and its official test
  vectors; `aws-chunked` / `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` framing from
  the SigV4 streaming spec. Real clients (rclone, curl) are oracles, not
  sources.
- **Scope cut:** transport only. The Tier-1 JS client stays test-only;
  `mountx/drivers/s3` (mount real buckets) is a named follow-up that reuses
  it. No bench column in this effort (perf claims only from
  `.agents/benchmarks.md`, so docs make none).

## Steps

Each step lists deliverables and what its verifier must confirm beyond
`pnpm test` green.

- [x] **1. `src/s3/constants.ts` + `src/s3/sigv4.ts`** — errno→S3-error table,
      limits (op names moved to step 4: the discrimination table belongs with the
      router, decided during step-1 verification); SigV4 canonical request,
      signing key derivation, header
      and presigned-query verification, clock-skew window. Tests:
      `test/s3/sigv4.test.ts` against AWS's published SigV4 test vectors as
      goldens. Verify: vectors are transcribed (named source), not invented;
      `node:crypto` only.
- [x] **2. `src/s3/xml.ts`** — bounded XML encoder for list/error/multipart
      responses and parser for the two request bodies (DeleteObjects,
      CompleteMultipartUpload); escaping both ways. Tests: round-trips + golden
      fixtures. Verify: fixtures give every field a distinct value; parser is
      bounds-checked against hostile input (no entity expansion, depth-capped).
- [x] **3. `src/s3/chunked.ts`** — `aws-chunked` /
      `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` streaming decoder with per-chunk
      signature verification (and unsigned-chunked passthrough), trailer
      handling. Tests: golden frames, split-across-read-boundary cases. Verify:
      decoder copies retained bytes; malformed framing → clean error, not hang.
- [x] **4. `src/s3/protocol.ts`** — pure request parsing/routing: path-style
      URL → (bucket, key), the op-name table and op discrimination from
      method + query
      (`list-type=2`, `uploads`, `uploadId`, `delete`, ...), Range/conditional/
      `x-amz-meta-mtime` header parsing, response header building, S3 XML error
      responses. Tests: `test/s3/protocol.test.ts` routing table + goldens.
      Verify: unknown ops route to `NotImplemented`, never fall through.
- [x] **5. `src/s3/session.ts` (core ops)** — `S3Session` with the streaming
      interface; GET/HEAD (ETag, conditionals, Range), PUT (incl. mtime meta,
      chunked bodies), DELETE, DeleteObjects, CopyObject, HeadBucket,
      ListBuckets, ListObjectsV2 (both delimiter modes, effective-key ordering,
      continuation tokens, empty-dir markers), key validation, errno mapping,
      single-reply assertion. Tests: `test/s3/session.test.ts` against the
      memory driver (in-process, no sockets). Verify: ordering cases
      (`a.txt`/`a/b`/`a0`), pagination resume mid-directory, zero-copy contract
      at every await.
- [x] **6. Multipart in `session.ts`** — the five ops, staging prefix
      invisibility, out-of-order parts, streamed assembly, abort + close
      cleanup, part-list validation (ETag echo, part numbering). Tests extend
      `session.test.ts`. Verify: staging never leaks into any listing or
      GET/PUT/DELETE; interrupted upload leaves no debris after close.
- [ ] **7. `src/s3/server.ts` + `src/s3/index.ts` + wiring** — `node:http`
      binding, loopback/credential gate, both `createS3Server` call shapes,
      `close()` (drains, cleans staging), subpath export `mountx/s3` in
      `package.json` + obuild config; `index.ts` re-exports by name (NFS
      pattern). Tests: `test/s3/server.test.ts` over real sockets with `fetch`.
      Verify: non-loopback bind without credentials refuses with the named
      error; built `dist/s3/*` imports no runtime dep; export map resolves.
- [ ] **8. Tier-1 conformance column** — `test/s3/client.ts`: a signing JS
      client speaking to the session directly (no sockets, `test/nfs/client.ts`
      pattern) plus an `FsDriver`-shaped adapter over it;
      `test/s3/conformance.test.ts` runs `test/conformance.ts` as a column with
      honestly declared capabilities (no symlinks/hardlinks/permissions,
      rename absent → copy+delete semantics, `times` via mtime meta). Update
      `test/matrix.ts` so `pnpm matrix` grows the column; regenerate
      `.agents/conformance-matrix.md`. Verify: declared capabilities match what
      the session actually answers, none faked.
- [ ] **9. rclone oracle** — install the static rclone binary user-level
      (document where in `.agents/environment.md`); `test/s3/oracle.test.ts`
      gated on a `command -v rclone` probe (skips clean when absent, the
      `nfsClientProbe` pattern): copy/ls/sync round-trips, mtime preservation
      via the meta header, `sync` against a tree with an empty directory; plus
      a curl presigned-URL GET/PUT case. Verify: runs green here, skips clean
      when the binary is hidden from PATH.
- [ ] **10. Docs + bookkeeping (sonnet)** — `docs/2.transports/` page for S3
      (guide prose first, full export surface below, same as FUSE/NFS pages;
      explicitly: gateway not mount, why it's outside `mountx/auto`, auth
      posture, ETag/mtime/empty-dir semantics, the `NotImplemented` boundary);
      transports overview + reference index updated; README link list mention;
      `AGENTS.md` code map + `.agents/roadmap.md` "shipped" entry. Verify
      (sonnet): docs claim nothing unimplemented, no perf numbers, code map
      matches the tree.

## Loop protocol

Each iteration: read this file, take the **first unchecked step**, run
impl → verify → fix → commit (code + ticked checkbox together). One step per
iteration is the floor, not the ceiling — continue while context is fresh.
When all boxes are ticked: run `pnpm test` once more, make sure the tree is
clean, and stop the loop.
