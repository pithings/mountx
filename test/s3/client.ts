/**
 * A minimal S3 client, built from the gateway's own codecs — and an `FsDriver`
 * over it.
 *
 * The S3 counterpart of `test/nfs/v3/client.ts`, and the same Tier-1 trick: the
 * signing, XML and routing codecs in `src/s3/` are symmetric, so the client
 * that exercises the server can be written in JavaScript. Here it is one step
 * cheaper still — `S3Session.handleRequest()` is a function from a request to a
 * reply, so this client speaks to it **directly**, with no socket at all
 * (`test/s3/server.test.ts` is where the socket is under test).
 *
 * Two layers:
 *
 * - {@link S3Client} — one typed method per operation, over
 *   {@link S3Session.handleRequest}. It knows about buckets, keys and HTTP; it
 *   knows nothing about paths. SigV4 signing is optional and composes with
 *   every call ({@link S3ClientOptions.credentials}).
 * - {@link s3Driver} — an `FsDriver` over a client and a bucket, which is what
 *   lets `test/conformance.ts` run unmodified as the S3 column of the
 *   conformance matrix.
 *
 * ## What the adapter is, and is not
 *
 * The plan's scope cut is that the Tier-1 client stays test-only
 * (`.agents/s3-plan.md`), so this is **not** exported from the package and
 * `mountx/drivers/s3` does not exist. It is about 80% of what one would be, and
 * the missing 20% is written down here rather than discovered later:
 *
 * - **Every check is check-then-act.** S3 has no `open`, no `mkdir` that fails
 *   on an existing name, and no `DELETE` that fails on a missing one — a
 *   `DELETE` of nothing is `204`, which is the operation's whole point. POSIX
 *   wants `EEXIST`, `ENOENT`, `EISDIR` and `ENOTDIR` for exactly those cases,
 *   so the adapter asks first and acts second. Two clients racing can therefore
 *   see an answer neither would get from a kernel. A real driver would want
 *   conditional requests (`If-None-Match: *`) for the create cases, which this
 *   gateway does not implement on `PUT`.
 * - **`ENOTDIR` cannot come back over the wire.** `constants.ts` maps it to
 *   `NoSuchKey`, the same code `ENOENT` gets, because from S3's side "a
 *   component of the key is a file" and "there is no such key" are the same
 *   fact. So the adapter walks the ancestors itself when a key turns out to be
 *   missing ({@link classifyAbsence}) — the same shape as the NFS client
 *   resolving a path component by component, and for the same reason.
 * - **An open file is a whole buffer.** `open` fetches the object and `close`
 *   puts it back, one shared buffer per open path, exactly as
 *   `src/drivers/unstorage.ts` does for a store with no partial I/O. That is
 *   what makes `truncate` and `handles` work at all here, and it means a 5 GiB
 *   object needs 5 GiB of heap. A real driver would use `Range` for reads (the
 *   gateway implements it) and multipart for writes.
 * - **`rename` is a copy and a delete**, per file, recursing through a
 *   directory tree — so it is not atomic, it is O(entries) requests, and an
 *   interrupted one leaves both trees partly populated. Declared
 *   `atomicRename: false`.
 * - **Times are half there.** `utimes` writes `x-amz-meta-mtime` through a
 *   metadata-only self-copy and the mtime survives; `atime` has nowhere to go,
 *   so the capability is declared **false** and the partial support is pinned
 *   by its own test rather than claimed here. See {@link S3_CAPABILITIES}.
 *
 * Nothing in this file modifies `src/`, and nothing in it is on the package's
 * import graph.
 */

import { fsError, type ErrnoCode } from "../../src/errors.ts";
import {
  parseOpenFlags,
  resizeBytes,
  validatePosition,
  validateRange,
  type ByteHolder,
  type OpenFlags,
} from "../../src/drivers/handle.ts";
import { isPathInside, joinPath, normalizePath } from "../../src/path.ts";
import { MAX_KEYS } from "../../src/s3/constants.ts";
import { META_MTIME_HEADER, parseHttpDate, pathToKey } from "../../src/s3/protocol.ts";
import type { S3RequestHead, S3Session } from "../../src/s3/session.ts";
import {
  canonicalUri,
  EMPTY_PAYLOAD_SHA256,
  formatAmzDate,
  sha256Hex,
  signRequest,
  uriEncode,
  type HeaderEntry,
  type QueryEntry,
  type SigV4Credentials,
} from "../../src/s3/sigv4.ts";
import { escapeXmlText, parseXml, XML_DECLARATION, type ParsedElement } from "../../src/s3/xml.ts";
import {
  S_IFDIR,
  S_IFMT,
  S_IFREG,
  type DirentLike,
  type FileHandleLike,
  type FsDriver,
  type MkdirOptions,
  type ReadResult,
  type StatsLike,
  type TimeLike,
  type WriteResult,
} from "../../src/types.ts";

const encoder = new TextEncoder();
const EMPTY = new Uint8Array(0);

/** The `Host` every request carries. Signed, so it has to be stable. */
export const CLIENT_HOST = "s3.mountx.test";

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/**
 * S3 `<Code>` back to an errno — the reverse of `constants.ts`'s table, and
 * **lossy on purpose**, because the forward table is not injective.
 *
 * `ENOENT`, `ENOTDIR` and `ESTALE` all leave as `NoSuchKey`; `EEXIST` and
 * `EBUSY` both leave as `OperationAborted`; `EISDIR` leaves as
 * `InvalidRequest`, which several non-`EISDIR` refusals also use. So each code
 * comes back as the errno a client would act on — the common one — and every
 * case where the conformance suite requires one of the *others* is decided by
 * the adapter before a request is sent (see the module docs). Nothing here
 * guesses: a code with no row answers by status.
 */
export const ERRNO_OF_S3_CODE: Record<string, ErrnoCode> = {
  AccessDenied: "EACCES",
  BadDigest: "EIO",
  BucketNotEmpty: "ENOTEMPTY",
  EntityTooLarge: "EFBIG",
  IncompleteBody: "EIO",
  InternalError: "EIO",
  InvalidArgument: "EINVAL",
  InvalidBucketName: "EINVAL",
  InvalidPart: "EINVAL",
  InvalidPartOrder: "EINVAL",
  InvalidRange: "ERANGE",
  InvalidRequest: "EINVAL",
  InvalidURI: "EINVAL",
  KeyTooLongError: "ENAMETOOLONG",
  MethodNotAllowed: "EPERM",
  MissingContentLength: "EINVAL",
  NoSuchBucket: "ENOENT",
  NoSuchKey: "ENOENT",
  NoSuchUpload: "ENOENT",
  NotImplemented: "ENOSYS",
  OperationAborted: "EEXIST",
  PreconditionFailed: "EINVAL",
  ServiceUnavailable: "EAGAIN",
  SignatureDoesNotMatch: "EACCES",
  SlowDown: "EAGAIN",
};

/**
 * The fallback: an HTTP status to an errno.
 *
 * Needed for real, not only as a default — a `HEAD` reply carries no body
 * (RFC 9110 §9.3.2), so a failing `HEAD` has a status and nothing else, and
 * `HEAD` is how this adapter asks whether anything exists.
 */
export const ERRNO_OF_STATUS: Record<number, ErrnoCode> = {
  400: "EINVAL",
  403: "EACCES",
  404: "ENOENT",
  405: "EPERM",
  409: "EEXIST",
  411: "EINVAL",
  412: "EINVAL",
  416: "ERANGE",
  501: "ENOSYS",
  503: "EAGAIN",
};

/** The errno a failed reply stands for. */
export function errnoOfReply(reply: S3Reply): ErrnoCode {
  const named = reply.errorCode === undefined ? undefined : ERRNO_OF_S3_CODE[reply.errorCode];
  return named ?? ERRNO_OF_STATUS[reply.status] ?? "EIO";
}

/** Throw a `node:fs`-shaped error for a reply that failed. */
export function s3Fail(reply: S3Reply, syscall: string, path?: string): never {
  throw fsError(errnoOfReply(reply), {
    syscall,
    path,
    cause: new Error(
      `${reply.status} ${reply.errorCode ?? "(no error document)"}: ${reply.errorMessage ?? ""}`,
    ),
  });
}

/** Hand back a successful reply, or throw the errno the failure stands for. */
export function check(reply: S3Reply, syscall: string, path?: string): S3Reply {
  if (reply.status >= 400) {
    s3Fail(reply, syscall, path);
  }
  return reply;
}

// ---------------------------------------------------------------------------
// the client
// ---------------------------------------------------------------------------

/** One reply, with its body collected. */
export interface S3Reply {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
  /** The body as text — empty when there was none. */
  text: string;
  /** `<Code>` of the error document, when the reply carried one. */
  errorCode?: string;
  /** `<Message>` of the error document, when the reply carried one. */
  errorMessage?: string;
}

export interface S3ClientOptions {
  /**
   * Sign every request (header form). Absent means anonymous, which is what a
   * session with no credentials expects and what the conformance column runs.
   */
  credentials?: SigV4Credentials;
  /** The region the signature is scoped to. Default `us-east-1`. */
  region?: string;
  /** The clock the signature is dated with. Default `Date.now`. */
  now?: () => number;
}

/** One call, before it becomes a request target. */
export interface S3Call {
  method: string;
  /** The **decoded** path: `/bucket/a b/c`. Encoded once on the way out. */
  path: string;
  /** Decoded query parameters. */
  query?: QueryEntry[];
  headers?: Record<string, string>;
  body?: Uint8Array;
}

/** What `listObjectsV2` asks for, in the query's own vocabulary. */
export interface ListObjectsV2Params {
  prefix?: string;
  delimiter?: string;
  maxKeys?: number;
  continuationToken?: string;
  startAfter?: string;
  fetchOwner?: boolean;
  encodingType?: "url";
}

/** One `<Contents>` row. */
export interface ListedObject {
  key: string;
  size: number;
  etag: string;
  lastModified: string;
  storageClass?: string;
  ownerId?: string;
}

/** A `ListObjectsV2` reply, parsed. */
export interface ListObjectsV2Page {
  name: string;
  prefix: string;
  keyCount: number;
  maxKeys: number;
  isTruncated: boolean;
  continuationToken?: string;
  nextContinuationToken?: string;
  contents: ListedObject[];
  commonPrefixes: string[];
}

/** One `<Part>` of a `ListParts` reply. */
export interface ListedPart {
  partNumber: number;
  size: number;
  etag: string;
}

/** What a completed multipart upload answers. */
export interface CompletedUpload {
  bucket: string;
  key: string;
  etag: string;
}

/**
 * An S3 client over a session.
 *
 * ```ts
 * const client = new S3Client(new S3Session({ mountx: createMemoryDriver() }));
 * await client.putObject("mountx", "hello.txt", "hello");
 * ```
 */
export class S3Client {
  readonly session: S3Session;
  readonly options: S3ClientOptions;
  /** Requests sent, which is what makes "how many round trips did that cost" a test. */
  requests = 0;

  readonly #region: string;
  readonly #now: () => number;

  constructor(session: S3Session, options: S3ClientOptions = {}) {
    this.session = session;
    this.options = options;
    this.#region = options.region ?? "us-east-1";
    this.#now = options.now ?? Date.now;
  }

  /** Is this client signing what it sends? */
  get signing(): boolean {
    return this.options.credentials !== undefined;
  }

  /**
   * Send one call and collect the reply.
   *
   * The request target is built the way a real client builds one — each path
   * segment percent-encoded once ({@link canonicalUri}, which is also what
   * SigV4 canonicalizes), and the query encoded with the same rules — so
   * `parseRequestTarget()` on the far side decodes back to exactly the path
   * and query handed in here.
   */
  async send(call: S3Call): Promise<S3Reply> {
    this.requests++;
    const query = call.query ?? [];
    const body = call.body;
    const headers: Record<string, string> = { host: CLIENT_HOST, ...call.headers };
    if (body !== undefined) {
      headers["content-length"] = String(body.byteLength);
    }
    const credentials = this.options.credentials;
    if (credentials !== undefined) {
      const timestamp = this.#now();
      headers["x-amz-date"] = formatAmzDate(timestamp);
      const payloadHash = body === undefined ? EMPTY_PAYLOAD_SHA256 : sha256Hex(body);
      headers["x-amz-content-sha256"] = payloadHash;
      headers.authorization = signRequest({
        method: call.method,
        path: call.path,
        query,
        headers: headerEntries(headers),
        credentials,
        region: this.#region,
        timestamp,
        payloadHash,
      }).authorization;
    }
    const head: S3RequestHead = {
      method: call.method,
      target: buildTarget(call.path, query),
      headers: headerEntries(headers),
    };
    const response = await this.session.handleRequest(
      head,
      body === undefined ? undefined : oneChunk(body),
    );
    const collected = await collect(response.body);
    const reply: S3Reply = {
      status: response.status,
      headers: response.headers,
      body: collected,
      text: collected.byteLength === 0 ? "" : Buffer.from(collected).toString("utf8"),
    };
    if (reply.status >= 400 && reply.text !== "") {
      const document = parseDocument(reply.text);
      if (document?.name === "Error") {
        reply.errorCode = childText(document, "Code");
        reply.errorMessage = childText(document, "Message");
      }
    }
    return reply;
  }

  // --- service and bucket ---

  async listBuckets(): Promise<S3Reply> {
    return await this.send({ method: "GET", path: "/" });
  }

  /** The bucket names a `ListBuckets` reply carries. */
  async bucketNames(): Promise<string[]> {
    const reply = check(await this.listBuckets(), "listBuckets");
    const document = parseDocument(reply.text);
    const buckets = document === undefined ? undefined : child(document, "Buckets");
    return buckets === undefined
      ? []
      : buckets.children
          .filter((entry) => entry.name === "Bucket")
          .map((entry) => childText(entry, "Name") ?? "");
  }

  async headBucket(bucket: string): Promise<S3Reply> {
    return await this.send({ method: "HEAD", path: `/${bucket}` });
  }

  async listObjectsV2(bucket: string, params: ListObjectsV2Params = {}): Promise<S3Reply> {
    const query: QueryEntry[] = [{ name: "list-type", value: "2" }];
    const add = (name: string, value: string | undefined): void => {
      if (value !== undefined) {
        query.push({ name, value });
      }
    };
    add("prefix", params.prefix);
    add("delimiter", params.delimiter);
    add("max-keys", params.maxKeys === undefined ? undefined : String(params.maxKeys));
    add("continuation-token", params.continuationToken);
    add("start-after", params.startAfter);
    add("fetch-owner", params.fetchOwner === undefined ? undefined : String(params.fetchOwner));
    add("encoding-type", params.encodingType);
    return await this.send({ method: "GET", path: `/${bucket}`, query });
  }

  /** {@link listObjectsV2}, parsed, or the errno the refusal stands for. */
  async list(bucket: string, params: ListObjectsV2Params = {}): Promise<ListObjectsV2Page> {
    const reply = check(await this.listObjectsV2(bucket, params), "readdir");
    return parseListBucketResult(reply.text);
  }

  /** Every key under a prefix, following the continuation tokens. */
  async listAll(bucket: string, params: ListObjectsV2Params = {}): Promise<ListObjectsV2Page> {
    const all: ListObjectsV2Page = {
      name: bucket,
      prefix: params.prefix ?? "",
      keyCount: 0,
      maxKeys: params.maxKeys ?? MAX_KEYS,
      isTruncated: false,
      contents: [],
      commonPrefixes: [],
    };
    let token: string | undefined;
    do {
      const page = await this.list(bucket, { ...params, continuationToken: token });
      all.contents.push(...page.contents);
      all.commonPrefixes.push(...page.commonPrefixes);
      all.keyCount += page.keyCount;
      token = page.isTruncated ? page.nextContinuationToken : undefined;
    } while (token !== undefined);
    return all;
  }

  // --- objects ---

  async putObject(
    bucket: string,
    key: string,
    body: Uint8Array | string = EMPTY,
    options: { mtimeSeconds?: number; headers?: Record<string, string> } = {},
  ): Promise<S3Reply> {
    const headers: Record<string, string> = { ...options.headers };
    if (options.mtimeSeconds !== undefined) {
      headers[META_MTIME_HEADER] = String(options.mtimeSeconds);
    }
    return await this.send({
      method: "PUT",
      path: keyPath(bucket, key),
      headers,
      body: typeof body === "string" ? encoder.encode(body) : body,
    });
  }

  async getObject(
    bucket: string,
    key: string,
    options: { range?: string; headers?: Record<string, string> } = {},
  ): Promise<S3Reply> {
    const headers: Record<string, string> = { ...options.headers };
    if (options.range !== undefined) {
      headers.range = options.range;
    }
    return await this.send({ method: "GET", path: keyPath(bucket, key), headers });
  }

  async headObject(
    bucket: string,
    key: string,
    options: { headers?: Record<string, string> } = {},
  ): Promise<S3Reply> {
    return await this.send({
      method: "HEAD",
      path: keyPath(bucket, key),
      headers: options.headers,
    });
  }

  async deleteObject(bucket: string, key: string): Promise<S3Reply> {
    return await this.send({ method: "DELETE", path: keyPath(bucket, key) });
  }

  /** `POST /bucket?delete` — the bulk form, up to 1000 keys per call. */
  async deleteObjects(
    bucket: string,
    keys: readonly string[],
    options: { quiet?: boolean } = {},
  ): Promise<S3Reply> {
    const parts = [XML_DECLARATION, "<Delete>"];
    if (options.quiet === true) {
      parts.push("<Quiet>true</Quiet>");
    }
    for (const key of keys) {
      parts.push(`<Object><Key>${escapeXmlText(key)}</Key></Object>`);
    }
    parts.push("</Delete>");
    return await this.send({
      method: "POST",
      path: `/${bucket}`,
      query: [{ name: "delete", value: "" }],
      body: encoder.encode(parts.join("")),
    });
  }

  async copyObject(
    bucket: string,
    key: string,
    source: { bucket: string; key: string },
    options: {
      metadataDirective?: "COPY" | "REPLACE";
      mtimeSeconds?: number;
      headers?: Record<string, string>;
    } = {},
  ): Promise<S3Reply> {
    const headers: Record<string, string> = {
      "x-amz-copy-source": canonicalUri(keyPath(source.bucket, source.key)),
      ...options.headers,
    };
    if (options.metadataDirective !== undefined) {
      headers["x-amz-metadata-directive"] = options.metadataDirective;
    }
    if (options.mtimeSeconds !== undefined) {
      headers[META_MTIME_HEADER] = String(options.mtimeSeconds);
    }
    return await this.send({ method: "PUT", path: keyPath(bucket, key), headers });
  }

  // --- multipart ---

  async createMultipartUpload(
    bucket: string,
    key: string,
    options: { mtimeSeconds?: number } = {},
  ): Promise<S3Reply> {
    const headers: Record<string, string> = {};
    if (options.mtimeSeconds !== undefined) {
      headers[META_MTIME_HEADER] = String(options.mtimeSeconds);
    }
    return await this.send({
      method: "POST",
      path: keyPath(bucket, key),
      query: [{ name: "uploads", value: "" }],
      headers,
    });
  }

  /** {@link createMultipartUpload}, with the upload id pulled out. */
  async startUpload(bucket: string, key: string): Promise<string> {
    const reply = check(
      await this.createMultipartUpload(bucket, key),
      "createMultipartUpload",
      key,
    );
    const document = parseDocument(reply.text);
    const uploadId = document === undefined ? undefined : childText(document, "UploadId");
    if (uploadId === undefined) {
      throw new Error("mountx test client: CreateMultipartUpload answered no UploadId");
    }
    return uploadId;
  }

  async uploadPart(
    bucket: string,
    key: string,
    uploadId: string,
    partNumber: number,
    body: Uint8Array | string,
  ): Promise<S3Reply> {
    return await this.send({
      method: "PUT",
      path: keyPath(bucket, key),
      query: [
        { name: "uploadId", value: uploadId },
        { name: "partNumber", value: String(partNumber) },
      ],
      body: typeof body === "string" ? encoder.encode(body) : body,
    });
  }

  async completeMultipartUpload(
    bucket: string,
    key: string,
    uploadId: string,
    parts: readonly { partNumber: number; etag: string }[],
  ): Promise<S3Reply> {
    const document = [XML_DECLARATION, "<CompleteMultipartUpload>"];
    for (const part of parts) {
      document.push(
        `<Part><PartNumber>${part.partNumber}</PartNumber>` +
          `<ETag>${escapeXmlText(part.etag)}</ETag></Part>`,
      );
    }
    document.push("</CompleteMultipartUpload>");
    return await this.send({
      method: "POST",
      path: keyPath(bucket, key),
      query: [{ name: "uploadId", value: uploadId }],
      body: encoder.encode(document.join("")),
    });
  }

  /** {@link completeMultipartUpload}, parsed. */
  async finishUpload(
    bucket: string,
    key: string,
    uploadId: string,
    parts: readonly { partNumber: number; etag: string }[],
  ): Promise<CompletedUpload> {
    const reply = check(
      await this.completeMultipartUpload(bucket, key, uploadId, parts),
      "completeMultipartUpload",
      key,
    );
    const document = parseDocument(reply.text);
    return {
      bucket: (document === undefined ? undefined : childText(document, "Bucket")) ?? bucket,
      key: (document === undefined ? undefined : childText(document, "Key")) ?? key,
      etag: (document === undefined ? undefined : childText(document, "ETag")) ?? "",
    };
  }

  async abortMultipartUpload(bucket: string, key: string, uploadId: string): Promise<S3Reply> {
    return await this.send({
      method: "DELETE",
      path: keyPath(bucket, key),
      query: [{ name: "uploadId", value: uploadId }],
    });
  }

  async listParts(
    bucket: string,
    key: string,
    uploadId: string,
    options: { maxParts?: number; partNumberMarker?: number } = {},
  ): Promise<S3Reply> {
    const query: QueryEntry[] = [{ name: "uploadId", value: uploadId }];
    if (options.maxParts !== undefined) {
      query.push({ name: "max-parts", value: String(options.maxParts) });
    }
    if (options.partNumberMarker !== undefined) {
      query.push({ name: "part-number-marker", value: String(options.partNumberMarker) });
    }
    return await this.send({ method: "GET", path: keyPath(bucket, key), query });
  }

  /** {@link listParts}, parsed. */
  async parts(bucket: string, key: string, uploadId: string): Promise<ListedPart[]> {
    const reply = check(await this.listParts(bucket, key, uploadId), "listParts", key);
    const document = parseDocument(reply.text);
    if (document === undefined) {
      return [];
    }
    return document.children
      .filter((entry) => entry.name === "Part")
      .map((entry) => ({
        partNumber: Number(childText(entry, "PartNumber") ?? "0"),
        size: Number(childText(entry, "Size") ?? "0"),
        etag: unquote(childText(entry, "ETag") ?? ""),
      }));
  }
}

// ---------------------------------------------------------------------------
// wire helpers
// ---------------------------------------------------------------------------

function headerEntries(headers: Record<string, string>): HeaderEntry[] {
  return Object.entries(headers).map(([name, value]) => ({ name, value }));
}

/** The decoded path a `(bucket, key)` pair addresses. The empty key is the bucket. */
export function keyPath(bucket: string, key: string): string {
  return key === "" ? `/${bucket}` : `/${bucket}/${key}`;
}

/** A raw request target: the path encoded once per segment, then the query. */
function buildTarget(path: string, query: readonly QueryEntry[]): string {
  const encoded = query
    .map((entry) => `${uriEncode(entry.name)}=${uriEncode(entry.value)}`)
    .join("&");
  return encoded === "" ? canonicalUri(path) : `${canonicalUri(path)}?${encoded}`;
}

async function* oneChunk(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
  yield bytes;
}

async function collect(
  body: Uint8Array | AsyncIterable<Uint8Array> | undefined,
): Promise<Uint8Array> {
  if (body === undefined) {
    return EMPTY;
  }
  if (body instanceof Uint8Array) {
    return body;
  }
  const parts: Uint8Array[] = [];
  let total = 0;
  for await (const part of body) {
    // The session may reuse a read buffer between yields, so a consumer that
    // keeps one copies it (`AGENTS.md`: decoders copy what they retain).
    parts.push(new Uint8Array(part));
    total += part.byteLength;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/** Parse a reply body, or `undefined` when it is not XML this understands. */
function parseDocument(text: string): ParsedElement | undefined {
  if (text === "") {
    return undefined;
  }
  try {
    return parseXml(text);
  } catch {
    return undefined;
  }
}

function child(element: ParsedElement, name: string): ParsedElement | undefined {
  return element.children.find((candidate) => candidate.name === name);
}

function childText(element: ParsedElement, name: string): string | undefined {
  return child(element, name)?.text;
}

/** An ETag as stored: the quotes an S3 reply wraps it in are not part of it. */
function unquote(value: string): string {
  return value.startsWith(`"`) && value.endsWith(`"`) && value.length >= 2
    ? value.slice(1, -1)
    : value;
}

/** A `ListBucketResult` document, as the fields a caller acts on. */
export function parseListBucketResult(text: string): ListObjectsV2Page {
  const document = parseDocument(text);
  if (document === undefined || document.name !== "ListBucketResult") {
    throw new Error("mountx test client: expected a ListBucketResult document");
  }
  const contents: ListedObject[] = [];
  const commonPrefixes: string[] = [];
  for (const entry of document.children) {
    if (entry.name === "Contents") {
      contents.push({
        key: childText(entry, "Key") ?? "",
        size: Number(childText(entry, "Size") ?? "0"),
        etag: unquote(childText(entry, "ETag") ?? ""),
        lastModified: childText(entry, "LastModified") ?? "",
        storageClass: childText(entry, "StorageClass"),
        ownerId: (() => {
          const owner = child(entry, "Owner");
          return owner === undefined ? undefined : childText(owner, "ID");
        })(),
      });
      continue;
    }
    if (entry.name === "CommonPrefixes") {
      const prefix = childText(entry, "Prefix");
      if (prefix !== undefined) {
        commonPrefixes.push(prefix);
      }
    }
  }
  return {
    name: childText(document, "Name") ?? "",
    prefix: childText(document, "Prefix") ?? "",
    keyCount: Number(childText(document, "KeyCount") ?? "0"),
    maxKeys: Number(childText(document, "MaxKeys") ?? "0"),
    isTruncated: childText(document, "IsTruncated") === "true",
    continuationToken: childText(document, "ContinuationToken"),
    nextContinuationToken: childText(document, "NextContinuationToken"),
    contents,
    commonPrefixes,
  };
}

// ---------------------------------------------------------------------------
// the driver over a client
// ---------------------------------------------------------------------------

/**
 * What the S3 column claims, and why each `false` is a fact about the gateway
 * rather than about this adapter being lazy.
 *
 * - **`handles: true`** — an open file is a client-side buffer, so it does
 *   survive `unlink`, which is what the capability means. It is the adapter's
 *   property and not the gateway's: S3 is as stateless as NFSv3, and a
 *   streaming adapter would declare `false` here the way `test/nfs/v3/client.ts`
 *   does.
 * - **`atomicRename: false`** — `rename` is `CopyObject` plus `DeleteObject`,
 *   recursively for a tree. Nothing in S3 can make the pair one operation.
 * - **`hardlinks: false` / `symlinks: false`** — there is no object that names
 *   another object, and no operation that would create one.
 * - **`permissions: false`** — an object has no mode, uid or gid. The
 *   `S_IFREG | 0o644` a `stat` reports here is synthesized (bucket policies and
 *   ACLs are a different model, and `?acl` is `NotImplemented` by design).
 * - **`times: false`** — and this one is the interesting refusal. `utimes` is
 *   implemented and the **mtime survives** (`x-amz-meta-mtime` through a
 *   metadata-only self-copy, which is exactly what the gateway supports and
 *   what rclone uses), but S3 has nowhere to put an access time and a `HEAD`
 *   has none to report. The conformance case asks for both, so claiming
 *   `times` would be claiming half of it; the half that does work is pinned by
 *   its own test in `test/s3/conformance.test.ts`.
 * - **`truncate: true`** — delivered through the open buffer: shrink or grow it
 *   and put it back, zero-filled, which is what the case checks.
 * - **`statfs: false`** — S3 has no notion of the size of a bucket, and no
 *   operation that would report one.
 * - **`caseSensitive: true`** — keys are byte strings.
 */
export const S3_CAPABILITIES = {
  handles: true,
  atomicRename: false,
  hardlinks: false,
  symlinks: false,
  permissions: false,
  times: false,
  truncate: true,
  caseSensitive: true,
  statfs: false,
  readOnly: false,
  // The one driver in this repository for which the answer is interesting:
  // writes land in an open buffer and reach the bucket in the `PutObject` that
  // `close()` sends, so a failure is discovered exactly at `close(2)` time.
  // This is the shape of driver the FUSE session keeps answering `FLUSH` for.
  durableWrites: false,
} as const;

export interface S3DriverOptions {
  /** Reported by every `stat`. Default: the process's own. */
  uid?: number;
  gid?: number;
  /** Permission bits every object reports. Default `0o644`. */
  fileMode?: number;
  /** Permission bits every prefix reports. Default `0o755`. */
  dirMode?: number;
}

/** What a path turned out to be. */
type Kind = "file" | "directory" | "missing";

interface Found {
  kind: Kind;
  /** Present for a file or a directory. */
  stats?: StatsLike;
}

/** A file's bytes while something has it open. Shared by every handle on the path. */
interface OpenFile {
  /**
   * Where the buffer is filed *now*, which a rename moves — so every handle
   * reads it off the entry rather than closing over the name it was opened
   * under. Same reason `drivers/unstorage.ts`'s `OpenFile` carries one.
   */
  path: string;
  data: Uint8Array;
  refs: number;
  dirty: boolean;
  /** Deleted or renamed *over*: still readable, never written back. */
  orphan: boolean;
  /** The mtime the object had when it was opened, in milliseconds. */
  mtimeMs: number;
}

/** A stable, positive inode number for a path: FNV-1a over its bytes. */
export function inodeOf(path: string): number {
  let hash = 0x81_1c_9d_c5;
  for (const byte of Buffer.from(path, "utf8")) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01_00_01_93);
  }
  return (hash >>> 0) + 1;
}

/**
 * `FsDriver` over an {@link S3Client}, serving one bucket.
 *
 * The interesting part is what it has to do *itself*, because S3 will not: it
 * classifies every path before acting on it (there is no `open`, and a `DELETE`
 * of nothing succeeds), it walks the ancestors of a key that turned out to be
 * missing to tell `ENOTDIR` from `ENOENT` (the wire says `NoSuchKey` for both),
 * and it buffers an object whole while it is open (there is no partial write).
 * All three are the same shape of imperfection, and the module docs list them.
 */
export function s3Driver(
  client: S3Client,
  bucket: string,
  options: S3DriverOptions = {},
): FsDriver {
  const uid = options.uid ?? process.getuid?.() ?? 0;
  const gid = options.gid ?? process.getgid?.() ?? 0;
  const fileMode = options.fileMode ?? 0o644;
  const dirMode = options.dirMode ?? 0o755;
  const openFiles = new Map<string, OpenFile>();
  let nextFd = 3;

  // --- keys ---

  /** The key a path maps to. `/` is the empty key, the bucket root. */
  const keyOf = (path: string): string => pathToKey(normalizePath(path));

  /** The key a *directory* path maps to: `a/b/`, with the marker slash. */
  const dirKeyOf = (path: string): string => pathToKey(normalizePath(path), true);

  // --- stats ---

  function makeStats(path: string, mode: number, size: number, mtimeMs: number): StatsLike {
    const directory = (mode & S_IFMT) === S_IFDIR;
    return {
      dev: 0,
      ino: inodeOf(path),
      mode,
      nlink: 1,
      uid,
      gid,
      rdev: 0,
      size,
      blksize: 4096,
      blocks: Math.ceil(size / 512),
      // S3 dates objects once. Reporting the same instant three times is the
      // honest shape of that: there is no access time and no change time.
      atimeMs: mtimeMs,
      mtimeMs,
      ctimeMs: mtimeMs,
      birthtimeMs: mtimeMs,
      isFile: () => !directory,
      isDirectory: () => directory,
      isSymbolicLink: () => false,
      isBlockDevice: () => false,
      isCharacterDevice: () => false,
      isFIFO: () => false,
      isSocket: () => false,
    };
  }

  const fileStats = (path: string, size: number, mtimeMs: number): StatsLike =>
    makeStats(path, S_IFREG | fileMode, size, mtimeMs);
  const dirStats = (path: string, mtimeMs: number): StatsLike =>
    makeStats(path, S_IFDIR | dirMode, 0, mtimeMs);

  /**
   * The modification time a reply reports.
   *
   * `x-amz-meta-mtime` first: it is the same instant `Last-Modified` carries and
   * it is already a number, where the `IMF-fixdate` has to be parsed. Both are
   * second-resolution, which is all an S3 reply ever carries.
   */
  function mtimeOf(headers: Record<string, string>): number {
    const meta = headers[META_MTIME_HEADER];
    if (meta !== undefined) {
      const seconds = Number(meta);
      if (Number.isFinite(seconds)) {
        return seconds * 1000;
      }
    }
    return parseHttpDate(headers["last-modified"] ?? "") ?? 0;
  }

  // --- classification ---

  /**
   * What is at `path`: a file, a directory, or nothing.
   *
   * Two `HEAD`s at most, and they are the two halves of the directory
   * convention: `HEAD a/b` answers only for a file and `HEAD a/b/` only for a
   * directory (`#statObject` in `src/s3/session.ts` refuses the crossed cases
   * with `NoSuchKey`). The root is a directory without asking — the bucket is
   * one by definition, and `HEAD /bucket/` is `HeadBucket`, a different
   * operation.
   */
  async function classify(path: string, syscall: string): Promise<Found> {
    const normalized = normalizePath(path);
    if (normalized === "/") {
      return { kind: "directory", stats: dirStats("/", 0) };
    }
    const file = await client.headObject(bucket, keyOf(normalized));
    if (file.status === 200) {
      return {
        kind: "file",
        stats: fileStats(
          normalized,
          Number(file.headers["content-length"] ?? "0"),
          mtimeOf(file.headers),
        ),
      };
    }
    if (file.status !== 404) {
      s3Fail(file, syscall, normalized);
    }
    const directory = await client.headObject(bucket, dirKeyOf(normalized));
    if (directory.status === 200) {
      return { kind: "directory", stats: dirStats(normalized, mtimeOf(directory.headers)) };
    }
    if (directory.status !== 404) {
      s3Fail(directory, syscall, normalized);
    }
    return { kind: "missing" };
  }

  /**
   * Why a path is not there: `ENOTDIR` when a component of it is a file,
   * `ENOENT` otherwise — plus whether the parent directory exists, which is
   * what separates "create it" from `ENOENT` for a creating `open` and a
   * non-recursive `mkdir`.
   *
   * The wire cannot answer any of this — `constants.ts` maps both `ENOTDIR` and
   * `ENOENT` to `NoSuchKey`, because to S3 they are the same fact — so the
   * ancestors are walked here, root downwards, exactly the way the NFS client
   * resolves a path one `LOOKUP` at a time. Only reached when something was
   * already found to be missing, so it costs nothing on the common path.
   */
  async function classifyAbsence(
    path: string,
    syscall: string,
  ): Promise<{ code: ErrnoCode; parentExists: boolean }> {
    const parts = normalizePath(path).split("/").filter(Boolean);
    let walked = "";
    for (const name of parts.slice(0, -1)) {
      walked = joinPath(walked === "" ? "/" : walked, name);
      const found = await classify(walked, syscall);
      if (found.kind === "file") {
        return { code: "ENOTDIR", parentExists: false };
      }
      if (found.kind === "missing") {
        return { code: "ENOENT", parentExists: false };
      }
    }
    return { code: "ENOENT", parentExists: true };
  }

  /** {@link classify}, with "nothing there" turned into the errno it deserves. */
  async function resolve(path: string, syscall: string): Promise<Found & { stats: StatsLike }> {
    const found = await classify(path, syscall);
    if (found.kind === "missing" || found.stats === undefined) {
      const absence = await classifyAbsence(path, syscall);
      throw fsError(absence.code, { syscall, path: normalizePath(path) });
    }
    return found as Found & { stats: StatsLike };
  }

  // --- objects ---

  /** The whole object at `path`. */
  async function readObject(path: string, syscall: string): Promise<Uint8Array> {
    const reply = await client.getObject(bucket, keyOf(path));
    check(reply, syscall, normalizePath(path));
    return reply.body;
  }

  async function writeObject(path: string, data: Uint8Array, syscall: string): Promise<void> {
    check(await client.putObject(bucket, keyOf(path), data), syscall, normalizePath(path));
  }

  // --- open files ---

  /**
   * The shared buffer for `path`, fetching the object if nothing has it open.
   *
   * One buffer per open path, so a write through one handle is visible through
   * another — the same rule, and the same reason, as `drivers/unstorage.ts`:
   * while a file is open, that buffer *is* its contents.
   */
  async function acquire(path: string, load: boolean, mtimeMs: number): Promise<OpenFile> {
    const existing = openFiles.get(path);
    if (existing !== undefined) {
      existing.refs++;
      return existing;
    }
    const data = load ? await readObject(path, "open") : EMPTY;
    const raced = openFiles.get(path);
    if (raced !== undefined) {
      raced.refs++;
      return raced;
    }
    const entry: OpenFile = {
      path,
      data: new Uint8Array(data),
      refs: 1,
      dirty: false,
      orphan: false,
      mtimeMs,
    };
    openFiles.set(path, entry);
    return entry;
  }

  async function flush(entry: OpenFile): Promise<void> {
    if (!entry.dirty || entry.orphan) {
      return;
    }
    entry.dirty = false;
    try {
      await writeObject(entry.path, entry.data, "fsync");
    } catch (error) {
      // The write did not land, so the buffer is still the only copy of it.
      entry.dirty = true;
      throw error;
    }
  }

  /**
   * Drop a closed entry, but only once there is nothing left in it: a failed
   * flush leaves `dirty` set, and the buffer is then the only copy of those
   * bytes. `drivers/unstorage.ts` keeps the same one.
   */
  function removeClosed(entry: OpenFile): void {
    if (entry.refs === 0 && (!entry.dirty || entry.orphan) && openFiles.get(entry.path) === entry) {
      openFiles.delete(entry.path);
    }
  }

  async function release(entry: OpenFile): Promise<void> {
    entry.refs--;
    try {
      await flush(entry);
    } finally {
      removeClosed(entry);
    }
  }

  /** An open path is gone: keep the buffer readable, never write it back. */
  function orphan(path: string): void {
    const entry = openFiles.get(path);
    if (entry !== undefined) {
      entry.orphan = true;
      entry.dirty = false;
      openFiles.delete(path);
    }
  }

  /**
   * File every open buffer for `from` and its subtree under `to` instead.
   *
   * A rename does not disturb what a handle is holding — the object moved, and
   * the buffer *is* that object while it is open — so the entry follows the
   * path rather than being orphaned at the old one. `drivers/unstorage.ts`'s
   * `movePaths` is the same function for the same reason, down to scanning the
   * map in full before rewriting any of it: what changes is the key a record is
   * filed under, and rewriting those while iterating would visit some twice.
   */
  function movePaths(from: string, to: string): void {
    const affected: OpenFile[] = [];
    for (const [path, entry] of openFiles) {
      if (isPathInside(path, from)) {
        affected.push(entry);
      }
    }
    for (const entry of affected) {
      openFiles.delete(entry.path);
      entry.path = normalizePath(to + entry.path.slice(from.length));
      openFiles.set(entry.path, entry);
    }
  }

  function createFileHandle(entry: OpenFile, flags: OpenFlags): FileHandleLike {
    let position = 0;
    let closed = false;

    function begin(syscall: string, write: boolean): void {
      if (closed || (write ? !flags.write : !flags.read)) {
        throw fsError("EBADF", { syscall, path: entry.path });
      }
    }

    return {
      fd: nextFd++,

      async read(buffer, offset, length, at): Promise<ReadResult> {
        begin("read", false);
        const { start, count } = validateRange(buffer, offset, length, false);
        const explicit = validatePosition(at);
        const from = explicit ?? position;
        const bytesRead = Math.max(0, Math.min(count, entry.data.byteLength - from));
        buffer.set(entry.data.subarray(from, from + bytesRead), start);
        if (explicit === undefined) {
          position += bytesRead;
        }
        return { bytesRead, buffer };
      },

      async write(buffer, offset, length, at): Promise<WriteResult> {
        begin("write", true);
        const { start, count } = validateRange(buffer, offset, length, true);
        const explicit = validatePosition(at);
        const from = flags.append ? entry.data.byteLength : (explicit ?? position);
        if (from + count > entry.data.byteLength) {
          resizeBytes(entry, from + count);
        }
        entry.data.set(buffer.subarray(start, start + count), from);
        if (flags.append || explicit === undefined) {
          position = from + count;
        }
        entry.dirty = true;
        return { bytesWritten: count, buffer };
      },

      async stat(): Promise<StatsLike> {
        if (closed) {
          throw fsError("EBADF", { syscall: "fstat", path: entry.path });
        }
        // The buffer is the file while it is open, unflushed writes included —
        // and for an orphan it is all that is left of it.
        return fileStats(entry.path, entry.data.byteLength, entry.mtimeMs);
      },

      async truncate(length = 0): Promise<void> {
        begin("ftruncate", true);
        resizeBytes(entry, length);
        entry.dirty = true;
      },

      async sync(): Promise<void> {
        await flush(entry);
      },

      async datasync(): Promise<void> {
        await flush(entry);
      },

      async close(): Promise<void> {
        if (closed) {
          return;
        }
        closed = true;
        await release(entry);
      },
    };
  }

  /**
   * A directory handle: `open(2)` on a directory succeeds and it is `read(2)`
   * on the result that fails, which is what the conformance suite checks.
   */
  function createDirectoryHandle(path: string, stats: StatsLike): FileHandleLike {
    const reject = async (): Promise<never> => {
      throw fsError("EISDIR", { syscall: "read", path });
    };
    return {
      fd: nextFd++,
      read: reject,
      write: reject,
      truncate: reject,
      stat: async () => stats,
      async sync() {},
      async datasync() {},
      async close() {},
    };
  }

  // --- listings ---

  /** One directory level, as the keys and prefixes S3 groups it into. */
  async function listLevel(path: string): Promise<{ files: string[]; directories: string[] }> {
    const normalized = normalizePath(path);
    const prefix = normalized === "/" ? "" : dirKeyOf(normalized);
    const page = await client.listAll(bucket, { prefix, delimiter: "/" });
    const files: string[] = [];
    for (const entry of page.contents) {
      // The marker object for an empty directory *is* this directory, and is
      // not an entry in it.
      if (entry.key !== prefix) {
        files.push(entry.key.slice(prefix.length));
      }
    }
    return {
      files,
      directories: page.commonPrefixes.map((value) => value.slice(prefix.length, -1)),
    };
  }

  // --- rename ---

  /** Copy every entry of `from` into `to`, which already exists as a directory. */
  async function copyTree(from: string, to: string): Promise<void> {
    const level = await listLevel(from);
    for (const name of level.files) {
      check(
        await client.copyObject(
          bucket,
          keyOf(joinPath(to, name)),
          { bucket, key: keyOf(joinPath(from, name)) },
          { metadataDirective: "COPY" },
        ),
        "rename",
        joinPath(from, name),
      );
    }
    for (const name of level.directories) {
      check(
        await client.putObject(bucket, dirKeyOf(joinPath(to, name))),
        "rename",
        joinPath(to, name),
      );
      await copyTree(joinPath(from, name), joinPath(to, name));
    }
  }

  /**
   * Remove a directory and everything under it, depth first.
   *
   * It touches no open buffer, and its one caller is why: `rename` copies the
   * tree before removing it, so a file open under `path` has *moved* rather
   * than gone, and {@link movePaths} refiles it under the destination once the
   * removal is done. Orphaning here would throw away the very entry that is
   * about to be renamed.
   */
  async function removeTree(path: string): Promise<void> {
    const level = await listLevel(path);
    if (level.files.length > 0) {
      check(
        await client.deleteObjects(
          bucket,
          level.files.map((name) => keyOf(joinPath(path, name))),
          { quiet: true },
        ),
        "rename",
        path,
      );
    }
    for (const name of level.directories) {
      await removeTree(joinPath(path, name));
    }
    check(await client.deleteObject(bucket, dirKeyOf(path)), "rename", path);
  }

  // --- the driver ---

  const driver: FsDriver = {
    capabilities: { ...S3_CAPABILITIES },

    async stat(path) {
      return (await resolve(path, "stat")).stats;
    },

    // No object names another object, so there is nothing for `lstat` to see
    // that `stat` does not. Declared `symlinks: false` either way.
    async lstat(path) {
      return (await resolve(path, "lstat")).stats;
    },

    async readdir(path) {
      const found = await resolve(path, "scandir");
      if (found.kind !== "directory") {
        throw fsError("ENOTDIR", { syscall: "scandir", path: normalizePath(path) });
      }
      const level = await listLevel(path);
      const entries: DirentLike[] = [];
      for (const name of level.files) {
        entries.push(direntOf(name, false));
      }
      for (const name of level.directories) {
        entries.push(direntOf(name, true));
      }
      return entries;
    },

    async open(path, flags = "r") {
      const normalized = normalizePath(path);
      const parsed = parseOpenFlags(flags, normalized);
      const found = await classify(normalized, "open");

      if (found.kind === "directory") {
        if (parsed.write) {
          throw fsError("EISDIR", { syscall: "open", path: normalized });
        }
        return createDirectoryHandle(normalized, found.stats as StatsLike);
      }

      if (found.kind === "missing") {
        const absence = await classifyAbsence(normalized, "open");
        if (!parsed.create || !absence.parentExists) {
          throw fsError(absence.code, { syscall: "open", path: normalized });
        }
      } else if (parsed.create && parsed.exclusive) {
        throw fsError("EEXIST", { syscall: "open", path: normalized });
      }

      /* The object is created — or emptied — *here* rather than at `close`,
         because `open(2)` does both: a `w` on an existing file truncates it
         whether or not a byte is ever written, and a created file exists to
         everything else the moment `open` returns. */
      const fresh = found.kind === "missing" || parsed.truncate;
      if (fresh) {
        await writeObject(normalized, EMPTY, "open");
      }
      // A `PUT` reply carries no `Last-Modified`, so a freshly written object
      // is dated from here rather than from a second `HEAD` to ask.
      const entry = await acquire(normalized, !fresh, found.stats?.mtimeMs ?? Date.now());
      if (parsed.truncate && entry.data.byteLength > 0) {
        // A handle already open on this path shares the buffer, so the
        // truncation has to reach it too.
        resizeBytes(entry, 0);
        entry.dirty = false;
      }
      return createFileHandle(entry, parsed);
    },

    /**
     * `PUT key/` is `mkdir -p` on the far side (plan decision), so every
     * refusal `mkdir(2)` owes the caller — `EEXIST`, `ENOENT`, `ENOTDIR` — is
     * decided here, before the request. Check-then-act, as the module docs say.
     */
    async mkdir(path, mkdirOptions: MkdirOptions = {}) {
      const normalized = normalizePath(path);
      if (mkdirOptions.recursive !== true) {
        const found = await classify(normalized, "mkdir");
        if (found.kind !== "missing") {
          throw fsError("EEXIST", { syscall: "mkdir", path: normalized });
        }
        const absence = await classifyAbsence(normalized, "mkdir");
        if (!absence.parentExists) {
          throw fsError(absence.code, { syscall: "mkdir", path: normalized });
        }
        check(await client.putObject(bucket, dirKeyOf(normalized)), "mkdir", normalized);
        return undefined;
      }

      const parts = normalized.split("/").filter(Boolean);
      let walked = "";
      let first: string | undefined;
      for (const [index, name] of parts.entries()) {
        walked = joinPath(walked === "" ? "/" : walked, name);
        const found = await classify(walked, "mkdir");
        if (found.kind === "file") {
          // The last component already being a file is `EEXIST`; anything
          // *inside* a file is `ENOTDIR`, which is what `node:fs` reports.
          throw fsError(index === parts.length - 1 ? "EEXIST" : "ENOTDIR", {
            syscall: "mkdir",
            path: walked,
          });
        }
        if (found.kind === "directory") {
          continue;
        }
        first ??= walked;
      }
      if (first !== undefined) {
        check(await client.putObject(bucket, dirKeyOf(normalized)), "mkdir", normalized);
      }
      return first;
    },

    async rmdir(path) {
      const normalized = normalizePath(path);
      const found = await resolve(normalized, "rmdir");
      if (found.kind !== "directory") {
        throw fsError("ENOTDIR", { syscall: "rmdir", path: normalized });
      }
      check(await client.deleteObject(bucket, dirKeyOf(normalized)), "rmdir", normalized);
    },

    async unlink(path) {
      const normalized = normalizePath(path);
      const found = await resolve(normalized, "unlink");
      if (found.kind !== "file") {
        throw fsError("EISDIR", { syscall: "unlink", path: normalized });
      }
      check(await client.deleteObject(bucket, keyOf(normalized)), "unlink", normalized);
      orphan(normalized);
    },

    /**
     * `rename` is a copy and a delete — the only shape S3 offers — so it is not
     * atomic and a directory costs one request per entry, twice. Every refusal
     * a `rename(2)` owes the caller is decided here for the same reason `mkdir`
     * decides its own.
     */
    async rename(from, to) {
      const source = normalizePath(from);
      const destination = normalizePath(to);
      const found = await resolve(source, "rename");
      if (source === destination) {
        return;
      }
      if (destination.startsWith(`${source}/`)) {
        throw fsError("EINVAL", { syscall: "rename", path: source });
      }
      const existing = await classify(destination, "rename");
      if (existing.kind === "missing") {
        const absence = await classifyAbsence(destination, "rename");
        if (!absence.parentExists) {
          throw fsError(absence.code, { syscall: "rename", path: destination });
        }
      }

      if (found.kind === "file") {
        if (existing.kind === "directory") {
          throw fsError("EISDIR", { syscall: "rename", path: destination });
        }
        // The displaced file's bytes stay readable to whoever had it open, and
        // must not be written back over what is arriving. The *source*'s open
        // buffer is not orphaned: that object moved, so its entry moves too.
        orphan(destination);
        check(
          await client.copyObject(
            bucket,
            keyOf(destination),
            { bucket, key: keyOf(source) },
            { metadataDirective: "COPY" },
          ),
          "rename",
          source,
        );
        check(await client.deleteObject(bucket, keyOf(source)), "rename", source);
        movePaths(source, destination);
        return;
      }

      if (existing.kind === "file") {
        throw fsError("ENOTDIR", { syscall: "rename", path: destination });
      }
      if (existing.kind === "directory") {
        const level = await listLevel(destination);
        if (level.files.length > 0 || level.directories.length > 0) {
          throw fsError("ENOTEMPTY", { syscall: "rename", path: destination });
        }
      } else {
        check(await client.putObject(bucket, dirKeyOf(destination)), "rename", destination);
      }
      await copyTree(source, destination);
      await removeTree(source);
      // Same rule one level up: every buffer open anywhere under the old tree
      // is refiled under the new one, so an ancestor rename is as invisible to
      // an open handle as a rename of the file itself.
      movePaths(source, destination);
    },

    /**
     * Read, resize, write — through the open buffer when there is one, so that
     * a handle open on the path sees the new length rather than a stale copy.
     */
    async truncate(path, length = 0) {
      const normalized = normalizePath(path);
      const found = await resolve(normalized, "truncate");
      if (found.kind !== "file") {
        throw fsError("EISDIR", { syscall: "truncate", path: normalized });
      }
      const entry = openFiles.get(normalized);
      if (entry !== undefined) {
        resizeBytes(entry, length);
        entry.dirty = true;
        await flush(entry);
        // A closed-but-dirty entry is one a failed flush left behind; now that
        // its bytes have landed there is nothing left in it to keep.
        if (entry.refs === 0) {
          removeClosed(entry);
        }
        return;
      }
      const holder: ByteHolder = { data: await readObject(normalized, "truncate") };
      resizeBytes(holder, length);
      await writeObject(normalized, holder.data ?? EMPTY, "truncate");
    },

    /**
     * The mtime, and **only** the mtime: a metadata-only self-copy carrying
     * `x-amz-meta-mtime`, which is what the gateway stores and what rclone
     * writes. `atime` is dropped on the floor — S3 has nowhere to keep one —
     * which is why {@link S3_CAPABILITIES} declares `times: false` rather than
     * letting a caller believe both arguments landed.
     */
    async utimes(path, _atime: TimeLike, mtime: TimeLike) {
      const normalized = normalizePath(path);
      const found = await resolve(normalized, "utimes");
      if (found.kind !== "file") {
        throw fsError("EISDIR", { syscall: "utimes", path: normalized });
      }
      const ms = typeof mtime === "number" ? mtime * 1000 : mtime.getTime();
      check(
        await client.copyObject(
          bucket,
          keyOf(normalized),
          { bucket, key: keyOf(normalized) },
          { metadataDirective: "REPLACE", mtimeSeconds: Math.floor(ms / 1000) },
        ),
        "utimes",
        normalized,
      );
    },
  };

  return driver;
}

function direntOf(name: string, directory: boolean): DirentLike {
  return {
    name,
    isFile: () => !directory,
    isDirectory: () => directory,
    isSymbolicLink: () => false,
    isBlockDevice: () => false,
    isCharacterDevice: () => false,
    isFIFO: () => false,
    isSocket: () => false,
  };
}
