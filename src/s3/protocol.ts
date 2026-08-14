/**
 * S3 request parsing and routing: the layer between a raw HTTP head and the
 * session's operation handlers.
 *
 * Pure — no I/O, no driver calls, no sockets, and **no clock**. Every function
 * that needs a timestamp takes one, the same discipline `sigv4.ts` keeps, so a
 * router decision is reproducible from its inputs alone.
 *
 * There is no RFC for S3. Everything about the operation set is transcribed
 * from Amazon's own documentation and named where it is used:
 *
 * - **Amazon S3 API Reference** — one page per operation; the `Request Syntax`
 *   block of each is what {@link S3_OPS} and {@link routeRequest} discriminate
 *   on (method, path shape, and the query parameter that selects a
 *   sub-resource).
 * - **Amazon S3 API Reference, "Error responses"** — the `<Code>` strings, the
 *   descriptions used as default messages, and the HTTP status each rides on.
 *   {@link S3_ERRORS} is that page; nothing here invents a code.
 * - **RFC 9110** — `Range` (§14), the conditional-request precedence (§13.2.2)
 *   and the three `HTTP-date` formats (§5.6.7). HTTP is the one part of this
 *   transport that *does* have a standard, and it is followed rather than
 *   guessed at from S3's behavior.
 *
 * Real clients (rclone, curl, the AWS SDKs) are oracles, never sources.
 *
 * **The URL contract.** The caller hands over the raw request target; this
 * module splits path from query and percent-decodes the path **once**
 * ({@link parseRequestTarget}), and nothing downstream decodes again — which is
 * exactly the contract `sigv4.ts` documents for the path it signs. `+` in the
 * path is a literal plus (S3 does not form-decode a path); `+` in the query is
 * a space. The raw, still-encoded query pairs are kept beside the decoded ones
 * because a presigned URL is signed over what was sent.
 *
 * **The refusal posture.** An operation this gateway does not implement gets a
 * well-formed `NotImplemented`, never a fall-through to a neighbouring
 * operation: `GET /bucket/key?acl` answers an error, and must never answer the
 * object's bytes because the sub-resource was unrecognized. `UNSUPPORTED_SUBRESOURCES`
 * is the list that makes that true, and the router checks it before it looks at
 * anything else.
 */

import type { ChunkedRefusal } from "./chunked.ts";
import { streamingPayloadKind } from "./chunked.ts";
import {
  AWS_CHUNKED_ENCODING,
  MAX_KEY_BYTES,
  MAX_KEYS,
  MAX_PARTS,
  MULTIPART_PREFIX,
} from "./constants.ts";
import {
  evaluateConditionals as evaluateHttpConditionals,
  formatContentRange,
  formatETag,
  formatHttpDate,
  MAX_TIMESTAMP_MS,
  parseETagList,
  type ConditionalResult,
  type ConditionalTarget,
} from "../http.ts";
import { normalizePath } from "../path.ts";
import type { HeaderEntry, QueryEntry, SigV4RefusalReason } from "./sigv4.ts";
import type { XmlRefusal } from "./xml.ts";
import { encodeS3ErrorDocument } from "./xml.ts";

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/**
 * One error this gateway can answer with: the S3 `<Code>`, the HTTP status it
 * rides on, and the message that goes in the document.
 *
 * A superset of `constants.ts`'s `S3Error` — that table maps an errno to a code
 * and a status, and a message only exists once there is a request to describe.
 */
export interface S3ErrorSpec {
  /** The `<Code>` element, e.g. `NoSuchKey`. */
  code: string;
  /** The HTTP status S3 returns that code with. */
  status: number;
  /** The `<Message>` element. Safe to show a client: never holds a secret. */
  message: string;
}

/**
 * Every error code this transport answers with, with Amazon's own description
 * as the default message. Two AWS pages carry these tables and have disagreed
 * on wording since a ~2023 rewrite: the S3 API Reference's "Error responses"
 * (now a redirect; its text survives in the API PDF and in `API_Error.html`)
 * and the user guide's newer list. Rows here follow `API_Error.html`, the
 * page that still resolves.
 *
 * The descriptions are transcribed word for word, so that a client matching on
 * message text — some do — sees what it would see from S3. The **one** liberty
 * taken is that where a description ends with a pointer to further AWS
 * documentation ("For more information, see REST Authentication..."), the
 * pointer is dropped and the sentences before it kept verbatim: a link into
 * Amazon's documentation from this gateway's error document would be a lie
 * about who answered. A caller passes a more specific message to
 * {@link s3Error} when it has one.
 *
 * Every code `ERRNO_S3_ERRORS` can produce has a row here, so the errno bridge
 * the session runs on its error path is total — asserted in
 * `test/s3/protocol.test.ts`, because the two tables live in different files
 * and nothing else would notice them drifting apart.
 */
export const S3_ERRORS = {
  AccessDenied: { code: "AccessDenied", status: 403, message: "Access Denied" },
  /**
   * The `Content-MD5` a client attached to a request document does not match
   * the document. Only ever produced for a *request body* this gateway parses
   * (`DeleteObjects`); object bytes are the transport's to protect.
   */
  BadDigest: {
    code: "BadDigest",
    status: 400,
    message: "The Content-MD5 you specified did not match what we received.",
  },
  AuthorizationHeaderMalformed: {
    code: "AuthorizationHeaderMalformed",
    status: 400,
    message: "The authorization header you provided is invalid.",
  },
  /**
   * The presigned form's counterpart of `AuthorizationHeaderMalformed`. The
   * message is the one S3 sends when a required `X-Amz-*` parameter is missing.
   */
  AuthorizationQueryParametersError: {
    code: "AuthorizationQueryParametersError",
    status: 400,
    message:
      "Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.",
  },
  BucketNotEmpty: {
    code: "BucketNotEmpty",
    status: 409,
    message: "The bucket you tried to delete is not empty.",
  },
  EntityTooLarge: {
    code: "EntityTooLarge",
    status: 400,
    message: "Your proposed upload exceeds the maximum allowed object size.",
  },
  EntityTooSmall: {
    code: "EntityTooSmall",
    status: 400,
    message: "Your proposed upload is smaller than the minimum allowed object size.",
  },
  IncompleteBody: {
    code: "IncompleteBody",
    status: 400,
    message: "You did not provide the number of bytes specified by the Content-Length HTTP header.",
  },
  InternalError: {
    code: "InternalError",
    status: 500,
    message: "We encountered an internal error. Please try again.",
  },
  InvalidAccessKeyId: {
    code: "InvalidAccessKeyId",
    status: 403,
    message: "The AWS access key ID you provided does not exist in our records.",
  },
  InvalidArgument: { code: "InvalidArgument", status: 400, message: "Invalid Argument" },
  InvalidBucketName: {
    code: "InvalidBucketName",
    status: 400,
    message: "The specified bucket is not valid.",
  },
  InvalidPart: {
    code: "InvalidPart",
    status: 400,
    message:
      "One or more of the specified parts could not be found. The part might not have been uploaded, or the specified entity tag might not have matched the part's entity tag.",
  },
  InvalidPartOrder: {
    code: "InvalidPartOrder",
    status: 400,
    message:
      "The list of parts was not in ascending order. Parts list must be specified in order by part number.",
  },
  InvalidRange: {
    code: "InvalidRange",
    status: 416,
    message: "The requested range cannot be satisfied.",
  },
  InvalidRequest: { code: "InvalidRequest", status: 400, message: "Invalid Request" },
  InvalidURI: { code: "InvalidURI", status: 400, message: "Couldn't parse the specified URI." },
  KeyTooLongError: { code: "KeyTooLongError", status: 400, message: "Your key is too long." },
  MalformedXML: {
    code: "MalformedXML",
    status: 400,
    message:
      "The XML you provided was not well-formed or did not validate against our published schema.",
  },
  /**
   * "Your request was too big." A *request document* over the cap, which is not
   * the same event as an object over the cap — see {@link XML_REFUSAL_ERRORS}.
   */
  MaxMessageLengthExceeded: {
    code: "MaxMessageLengthExceeded",
    status: 400,
    message: "Your request was too big.",
  },
  MethodNotAllowed: {
    code: "MethodNotAllowed",
    status: 405,
    message: "The specified method is not allowed against this resource.",
  },
  MissingContentLength: {
    code: "MissingContentLength",
    status: 411,
    message: "You must provide the Content-Length HTTP header.",
  },
  /** S3's generic conflict, and `ERRNO_S3_ERRORS`'s answer for `EEXIST`/`EBUSY`. */
  OperationAborted: {
    code: "OperationAborted",
    status: 409,
    message:
      "A conflicting conditional operation is currently in progress against this resource. Try again.",
  },
  NoSuchBucket: {
    code: "NoSuchBucket",
    status: 404,
    message: "The specified bucket does not exist.",
  },
  NoSuchKey: { code: "NoSuchKey", status: 404, message: "The specified key does not exist." },
  NoSuchUpload: {
    code: "NoSuchUpload",
    status: 404,
    message:
      "The specified multipart upload does not exist. The upload ID might be invalid, or the multipart upload might have been aborted or completed.",
  },
  NotImplemented: {
    code: "NotImplemented",
    status: 501,
    message: "A header you provided implies functionality that is not implemented.",
  },
  PreconditionFailed: {
    code: "PreconditionFailed",
    status: 412,
    message: "At least one of the preconditions you specified did not hold.",
  },
  RequestTimeTooSkewed: {
    code: "RequestTimeTooSkewed",
    status: 403,
    message: "The difference between the request time and the server's time is too large.",
  },
  SignatureDoesNotMatch: {
    code: "SignatureDoesNotMatch",
    status: 403,
    message:
      "The request signature we calculated does not match the signature you provided. Check your AWS secret access key and signing method.",
  },
  /**
   * 503, and reachable only through `ERRNO_S3_ERRORS` (`ENOSPC`, `EDQUOT`,
   * `ENOMEM`) — the router never produces it, but the errno bridge does, so the
   * row has to exist for that bridge to be total. `SlowDown` carries the same
   * description on Amazon's page; the codes differ, not the sentence.
   */
  ServiceUnavailable: {
    code: "ServiceUnavailable",
    status: 503,
    message: "Service is unable to handle request.",
  },
  SlowDown: { code: "SlowDown", status: 503, message: "Reduce your request rate." },
} as const satisfies Record<string, S3ErrorSpec>;

/** The name of a row in {@link S3_ERRORS}. */
export type S3ErrorName = keyof typeof S3_ERRORS;

/**
 * One error, with Amazon's description or a more specific message.
 *
 * ```ts
 * s3Error("NoSuchKey");
 * s3Error("InvalidArgument", "Invalid List Type: 3");
 * ```
 */
export function s3Error(name: S3ErrorName, message?: string): S3ErrorSpec {
  const spec = S3_ERRORS[name];
  return { code: spec.code, status: spec.status, message: message ?? spec.message };
}

// ---------------------------------------------------------------------------
// refusal mapping tables
// ---------------------------------------------------------------------------

/**
 * `xml.ts`'s refusals, as S3 errors. Total over the closed union: adding a
 * refusal reason there fails the typecheck here until somebody decides what S3
 * calls it, the same way `ERRNO_S3_ERRORS` is total over `ErrnoCode`.
 *
 * **`too-large` is `MaxMessageLengthExceeded`, not `EntityTooLarge`.** The two
 * codes are about different things on Amazon's own error page:
 * `EntityTooLarge` is "your proposed *upload* exceeds the maximum allowed
 * object size", which is a fact about an object's bytes, while
 * `MaxMessageLengthExceeded` is "your *request* was too big". Every body this
 * parser sees is a request document (`DeleteObjects`,
 * `CompleteMultipartUpload`), never object content, so the second is the honest
 * one. `xml.ts`'s doc comment guesses `EntityTooLarge`; this table is the
 * decision, and `chunked.ts`'s `too-large` — which *is* a frame of object bytes
 * — keeps `EntityTooLarge` below, which is the distinction working.
 *
 * Everything else is `MalformedXML`: the client sent a document that is not
 * well-formed or does not validate, which is precisely what that code says.
 * `encoding` and `invalid-character` are included deliberately — a body that is
 * not decodable UTF-8 is not well-formed XML.
 */
export const XML_REFUSAL_ERRORS: Record<XmlRefusal, S3ErrorSpec> = {
  "too-large": s3Error("MaxMessageLengthExceeded"),
  encoding: s3Error("MalformedXML"),
  "invalid-character": s3Error("MalformedXML"),
  malformed: s3Error("MalformedXML"),
  doctype: s3Error("MalformedXML"),
  entity: s3Error("MalformedXML"),
  depth: s3Error("MalformedXML"),
  "too-many-elements": s3Error("MalformedXML"),
  "unexpected-root": s3Error("MalformedXML"),
  "missing-field": s3Error("MalformedXML"),
  "duplicate-field": s3Error("MalformedXML"),
  "invalid-field": s3Error("MalformedXML"),
};

/** The S3 error for an XML refusal, with the parser's message carried over. */
export function xmlRefusalError(reason: XmlRefusal, message?: string): S3ErrorSpec {
  const spec = XML_REFUSAL_ERRORS[reason];
  return { code: spec.code, status: spec.status, message: message ?? spec.message };
}

/**
 * `chunked.ts`'s refusals, as S3 errors — the table its `ChunkedRefusal` doc
 * comment describes, written out. Total over the union.
 *
 * The groups, and why they differ: a framing error is the client's request
 * being wrong (`InvalidRequest`), a short body is the client not sending what
 * it promised (`IncompleteBody`), and a chunk signature that does not verify is
 * `SignatureDoesNotMatch` — the same code the header signature gets, because it
 * is the same failure one layer down. `internal` is the decoder's own bug and
 * must not be reported as the client's fault.
 */
export const CHUNKED_REFUSAL_ERRORS: Record<ChunkedRefusal, S3ErrorSpec> = {
  "bad-size": s3Error("InvalidRequest"),
  "too-large": s3Error("EntityTooLarge"),
  malformed: s3Error("InvalidRequest"),
  "missing-signature": s3Error("SignatureDoesNotMatch"),
  "signature-mismatch": s3Error("SignatureDoesNotMatch"),
  truncated: s3Error("IncompleteBody"),
  "trailing-bytes": s3Error("IncompleteBody"),
  "length-mismatch": s3Error("IncompleteBody"),
  trailer: s3Error("InvalidRequest"),
  internal: s3Error("InternalError"),
};

/** The S3 error for a chunked-body refusal, with the decoder's message. */
export function chunkedRefusalError(reason: ChunkedRefusal, message?: string): S3ErrorSpec {
  const spec = CHUNKED_REFUSAL_ERRORS[reason];
  return { code: spec.code, status: spec.status, message: message ?? spec.message };
}

/**
 * `sigv4.ts`'s refusals, as S3 errors — the **header** form. Total over the
 * union; {@link SIGV4_PRESIGNED_ERRORS} overrides the two rows whose code S3
 * spells differently when the signature arrived in the query string.
 *
 * The decisions worth naming:
 *
 * - **`expired` is `AccessDenied` with "Request has expired"**, 403. That is
 *   what S3 answers for a presigned URL used past its `X-Amz-Expires`, verbatim
 *   — *not* `ExpiredToken`, which is about an STS session token that has aged
 *   out and is a 400.
 * - **`malformed` is `AuthorizationHeaderMalformed`** (400) for a header the
 *   parser could not take apart, and `AuthorizationQueryParametersError` (400)
 *   for the query form, which is the code S3 answers when the six `X-Amz-*`
 *   parameters do not add up.
 * - **`scope-mismatch` is the same pair.** A credential scope naming the wrong
 *   region or service *is* a malformed authorization: S3's own message for it
 *   ("the region 'x' is wrong; expecting 'y'") is an
 *   `AuthorizationHeaderMalformed`, not a signature mismatch.
 * - **`unsupported-algorithm` is `InvalidRequest`**, whose documented
 *   description is literally "Please use AWS4-HMAC-SHA256".
 * - **`missing` is `AccessDenied`**, which is what an unsigned request to a
 *   bucket that requires credentials gets. It is only reached when this gateway
 *   was configured with credentials; without them nothing is verified at all.
 */
export const SIGV4_REFUSAL_ERRORS: Record<SigV4RefusalReason, S3ErrorSpec> = {
  missing: s3Error("AccessDenied"),
  malformed: s3Error("AuthorizationHeaderMalformed"),
  "unsupported-algorithm": s3Error("InvalidRequest", "Please use AWS4-HMAC-SHA256."),
  "unknown-access-key": s3Error("InvalidAccessKeyId"),
  "scope-mismatch": s3Error("AuthorizationHeaderMalformed"),
  "clock-skew": s3Error("RequestTimeTooSkewed"),
  expired: s3Error("AccessDenied", "Request has expired"),
  "signature-mismatch": s3Error("SignatureDoesNotMatch"),
};

/** The rows the presigned form spells differently. */
export const SIGV4_PRESIGNED_ERRORS: Partial<Record<SigV4RefusalReason, S3ErrorSpec>> = {
  malformed: s3Error("AuthorizationQueryParametersError"),
  "scope-mismatch": s3Error("AuthorizationQueryParametersError"),
};

/**
 * The S3 error for a SigV4 refusal. `form` is which shape carried the
 * signature — `SigV4Verified["form"]`, and `"header"` for a request that
 * carried neither.
 */
export function sigv4RefusalError(
  reason: SigV4RefusalReason,
  form: "header" | "presigned" = "header",
  message?: string,
): S3ErrorSpec {
  const spec =
    (form === "presigned" ? SIGV4_PRESIGNED_ERRORS[reason] : undefined) ??
    SIGV4_REFUSAL_ERRORS[reason];
  return { code: spec.code, status: spec.status, message: message ?? spec.message };
}

// ---------------------------------------------------------------------------
// responses
// ---------------------------------------------------------------------------

/** The content type of every XML document this gateway sends. */
export const XML_CONTENT_TYPE = "application/xml";

/**
 * The content type of every object this gateway serves.
 *
 * Content-Type is not stored (plan decision: only `x-amz-meta-mtime` survives a
 * round trip), so it is answered rather than remembered.
 */
export const OBJECT_CONTENT_TYPE = "application/octet-stream";

/** A reply, before it reaches a socket. */
export interface S3Response {
  status: number;
  /** Lowercase header names, single values. */
  headers: Record<string, string>;
  body: Uint8Array;
}

/**
 * A reply whose body may not be in memory yet.
 *
 * The session's boundary streams (plan decision): a `GET` of a 5 GiB object
 * answers an `AsyncIterable` of bounded pieces, and a `204` or a `HEAD` answers
 * no body at all. Every {@link S3Response} is one of these — an error document
 * is bytes and stays bytes — so `s3ErrorResponse()` composes with the session
 * without a conversion anywhere.
 */
export interface S3StreamResponse {
  status: number;
  /** Lowercase header names, single values. */
  headers: Record<string, string>;
  /** Bytes, a stream of bytes, or nothing. */
  body?: Uint8Array | AsyncIterable<Uint8Array>;
}

/** What the caller knows about the request that the error document names. */
export interface S3ErrorExtra {
  /** The `<Resource>`: the bucket/key path the request named, e.g. `/b/k`. */
  resource?: string;
  /** The `<RequestId>`. Supplied by the caller — this module has no clock and
   * no randomness. */
  requestId?: string;
  hostId?: string;
}

/**
 * Render an S3 XML error document into a full reply.
 *
 * Takes the {@link S3ErrorSpec} whole rather than `(code, status, message)`
 * separately: a refusal route already carries one, and three positional strings
 * next to each other is an argument-order bug waiting to happen.
 */
export function s3ErrorResponse(error: S3ErrorSpec, extra: S3ErrorExtra = {}): S3Response {
  const body = Buffer.from(
    encodeS3ErrorDocument({
      code: error.code,
      message: error.message,
      resource: extra.resource,
      requestId: extra.requestId,
      hostId: extra.hostId,
    }),
    "utf8",
  );
  const headers: Record<string, string> = {
    "content-type": XML_CONTENT_TYPE,
    "content-length": String(body.byteLength),
  };
  if (extra.requestId !== undefined) {
    headers["x-amz-request-id"] = extra.requestId;
  }
  if (extra.hostId !== undefined) {
    headers["x-amz-id-2"] = extra.hostId;
  }
  return { status: error.status, headers, body };
}

// ---------------------------------------------------------------------------
// dates, Range and ETag: RFC 9110, and shared
// ---------------------------------------------------------------------------

/*
 * `HTTP-date`, the `Range` grammar, the `ETag` quoting, the entity-tag
 * comparison functions and the conditional-request rules are RFC 9110 rather
 * than S3, and `mountx/webdav` answers the same ones — its `If` header
 * (RFC 4918 §10.4) matches entity tags with the very same list parser. They
 * live in `src/http.ts` and are re-exported here under the names they have
 * always had, so this module's surface — and `mountx/s3`'s — is unchanged.
 * `evaluateConditionals` is the one that is wrapped rather than re-exported: it
 * takes this transport's header list and hands the shared rule a lookup.
 */
export {
  formatContentRange,
  formatETag,
  formatHttpDate,
  formatIsoDate,
  formatUnsatisfiedRange,
  MAX_TIMESTAMP_MS,
  parseETagList,
  parseHttpDate,
  parseRange,
  type ConditionalResult,
  type ConditionalTarget,
  type ETag,
  type ETagList,
  type RangeSpec,
} from "../http.ts";

// ---------------------------------------------------------------------------
// the request target
// ---------------------------------------------------------------------------

/**
 * One query parameter **exactly as it arrived**, still percent-encoded, with
 * `value: undefined` for a bare flag (`?acl`, which is not the same as
 * `?acl=`).
 *
 * Kept beside the decoded pairs because a presigned URL's signature covers what
 * was sent: a client that encoded `~` as `%7E` signed `%7E`, and re-encoding a
 * decoded value cannot always put it back.
 */
export interface RawQueryEntry {
  name: string;
  value: string | undefined;
}

/** A request target, taken apart. */
export interface ParsedTarget {
  /** The path, percent-decoded **once**, always starting with `/`. */
  path: string;
  /** The path as it arrived, still encoded. */
  rawPath: string;
  /** Decoded parameters in wire order — what `sigv4.ts` canonicalizes. */
  query: QueryEntry[];
  /** The same parameters, untouched. */
  rawQuery: RawQueryEntry[];
  /** Everything after the first `?`, verbatim; `""` when there was none. */
  rawQueryString: string;
}

/** {@link parseRequestTarget}'s answer. */
export type TargetResult = { ok: true; target: ParsedTarget } | { ok: false; error: S3ErrorSpec };

/**
 * Percent-decode one component. `decodeURIComponent` semantics exactly: a
 * malformed escape (`%`, `%zz`, `%e0%80`) throws `URIError`, which is turned
 * into a refusal by the caller rather than escaping.
 */
function decodeOnce(value: string): string | undefined {
  if (!value.includes("%")) {
    return value;
  }
  try {
    return decodeURIComponent(value);
  } catch {
    return undefined;
  }
}

/**
 * Split a raw request target into a decoded path and both views of the query.
 *
 * The path is decoded **once and only once** — the invariant `sigv4.ts` depends
 * on, and the reason a key containing `%2541` comes out as `%41` rather than
 * `A`. `+` is left alone in the path (S3 does not form-decode a path) and read
 * as a space in the query, which is where form encoding actually applies.
 *
 * A `%2F` inside a key decodes to a separator and is indistinguishable from one
 * afterwards. That is S3's own ambiguity, not this parser's: a key with a slash
 * in it *is* a prefix.
 */
export function parseRequestTarget(target: string): TargetResult {
  const questionMark = target.indexOf("?");
  const rawPath = questionMark === -1 ? target : target.slice(0, questionMark);
  const rawQueryString = questionMark === -1 ? "" : target.slice(questionMark + 1);
  if (!rawPath.startsWith("/")) {
    return {
      ok: false,
      error: s3Error("InvalidURI", `Couldn't parse the specified URI: ${JSON.stringify(rawPath)}`),
    };
  }
  const path = decodeOnce(rawPath);
  if (path === undefined) {
    return {
      ok: false,
      error: s3Error("InvalidURI", "Couldn't parse the specified URI: malformed percent-encoding."),
    };
  }
  const query: QueryEntry[] = [];
  const rawQuery: RawQueryEntry[] = [];
  for (const pair of rawQueryString.split("&")) {
    if (pair === "") {
      continue;
    }
    const equals = pair.indexOf("=");
    const rawName = equals === -1 ? pair : pair.slice(0, equals);
    const rawValue = equals === -1 ? undefined : pair.slice(equals + 1);
    const name = decodeOnce(rawName.replaceAll("+", " "));
    const value = rawValue === undefined ? "" : decodeOnce(rawValue.replaceAll("+", " "));
    if (name === undefined || value === undefined) {
      return {
        ok: false,
        error: s3Error(
          "InvalidURI",
          "Couldn't parse the specified URI: malformed percent-encoding in the query string.",
        ),
      };
    }
    query.push({ name, value });
    rawQuery.push({ name: rawName, value: rawValue });
  }
  return { ok: true, target: { path, rawPath, query, rawQuery, rawQueryString } };
}

/** First value for a query parameter, or `undefined`. Names are case-sensitive,
 * as S3's are: `?ACL` is an unknown parameter, not the `acl` sub-resource. */
export function queryValue(query: readonly QueryEntry[], name: string): string | undefined {
  for (const entry of query) {
    if (entry.name === name) {
      return entry.value;
    }
  }
  return undefined;
}

/** Was this parameter present at all, with or without a value? */
export function hasQuery(query: readonly QueryEntry[], name: string): boolean {
  return queryValue(query, name) !== undefined;
}

/**
 * The **first** value for a header, matched case-insensitively (HTTP field
 * names are).
 *
 * First, not combined: a repeated singleton field (`Content-Length`,
 * `Range`, `x-amz-copy-source`) is a malformed request, and joining two of them
 * into `"5, 7"` would turn a header this module refuses into one it merely
 * misreads. For the fields where a repeat *is* legal — the comma-separated list
 * ones — use {@link headerList}, which combines them the way RFC 9110 §5.3
 * says a recipient may.
 */
export function headerValue(headers: readonly HeaderEntry[], name: string): string | undefined {
  const wanted = name.toLowerCase();
  for (const header of headers) {
    if (header.name.toLowerCase() === wanted) {
      return header.value;
    }
  }
  return undefined;
}

/**
 * Every value for a header, combined into one comma-separated value — RFC 9110
 * §5.3's rule that a recipient may join repeated list-based fields "without
 * changing the semantics of the message".
 *
 * Used for the three list-based fields this module reads: `If-Match`,
 * `If-None-Match` and `Content-Encoding`. A client that sends two `If-None-
 * Match` lines means both of them, and reading only the first would answer
 * `200` where `304` was required.
 */
export function headerList(headers: readonly HeaderEntry[], name: string): string | undefined {
  const wanted = name.toLowerCase();
  const values: string[] = [];
  for (const header of headers) {
    if (header.name.toLowerCase() === wanted) {
      values.push(header.value);
    }
  }
  return values.length === 0 ? undefined : values.join(", ");
}

// ---------------------------------------------------------------------------
// numbers
// ---------------------------------------------------------------------------

/**
 * A non-negative decimal integer, or `undefined` for anything else: no sign, no
 * whitespace, no exponent, no `0x`, and nothing above `Number.MAX_SAFE_INTEGER`
 * (past which a byte count silently stops being exact).
 */
export function parseUnsignedInteger(value: string): number | undefined {
  if (!/^\d+$/.test(value)) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------

/** A validated object key and the driver path it maps to. */
export interface S3Key {
  /** The key as the client sent it, decoded, trailing `/` kept. */
  key: string;
  /** The driver path: `/a/b`, absolute, never with a trailing slash. */
  path: string;
  /**
   * Did the key end in `/`? The directory-marker convention: `PUT a/b/` is a
   * `mkdir` and `DELETE a/b/` is an `rmdir` (plan decision).
   */
  directory: boolean;
}

/** {@link parseObjectKey}'s answer. */
export type KeyResult = { ok: true; key: S3Key } | { ok: false; error: S3ErrorSpec };

/** Is this key inside the multipart staging area? */
export function isStagingKey(key: string): boolean {
  return key === MULTIPART_PREFIX || key.startsWith(`${MULTIPART_PREFIX}/`);
}

/**
 * Validate an object key and map it to a driver path.
 *
 * Key `a/b` is path `/a/b` (plan decision), and the mapping has to be exactly
 * reversible or a listing would name a key that a GET could not fetch. So every
 * key that would not survive the round trip is refused rather than quietly
 * normalized:
 *
 * - **empty** — there is no such object. Unreachable through the router, which
 *   answers a bucket operation when the path carries no key and
 *   `InvalidBucketName` for `//key` (the empty first segment is the bucket, and
 *   it is refused before the key is looked at); it exists for the callers that
 *   hand a key over directly, such as {@link parseCopySource}.
 * - **an empty segment** (`a//b`) — `/a//b` normalizes to `/a/b`, another key.
 * - **`.` or `..` segments** — `..` clamps at the root in `src/path.ts`, so
 *   `a/../b` would resolve to a key the client never named.
 * - **NUL** — `AGENTS.md` keeps source NUL-free and a path with one is not a
 *   path any driver can carry.
 * - **over `MAX_KEY_BYTES` UTF-8 bytes** — S3's own 1024-byte limit, answered
 *   with S3's own code `KeyTooLongError` rather than the generic
 *   `InvalidArgument` the other classes get. `constants.ts` maps
 *   `ENAMETOOLONG` to the same code, so a key refused here and a path refused
 *   by a driver read alike.
 *
 * **The staging prefix answers `NoSuchKey` (404), not `InvalidArgument`.** The
 * plan says both things in two places — the key↔path decision groups the
 * staging prefix with the round-trip failures, and the multipart decision says
 * the prefix is "invisible to every S3 op (404 on direct access, skipped in
 * listings)". Invisibility wins, and it is the stronger property: a 400 would
 * tell a client that this one name is special, and it would disagree with the
 * listings, which never mention it.
 *
 * 404 is the *read* answer, which is what this function is for — it is reached
 * for a copy source, where the prefix has to look empty. The router does not
 * reach it: it checks {@link isStagingKey} first and answers by method, because
 * "this key does not exist" is a different status for a `DELETE` than for a
 * `GET` and one answer for all of them would be the tell it is trying not to
 * be. See `stagingAnswer()` in this file.
 *
 * A trailing slash is **kept**, not rejected: it is the directory marker, and
 * `key`/`path`/`directory` carry both readings.
 */
export function parseObjectKey(key: string): KeyResult {
  if (key === "") {
    return { ok: false, error: s3Error("InvalidArgument", "The object key must not be empty.") };
  }
  if (Buffer.byteLength(key, "utf8") > MAX_KEY_BYTES) {
    return { ok: false, error: s3Error("KeyTooLongError") };
  }
  if (key.includes("\0")) {
    return {
      ok: false,
      error: s3Error("InvalidArgument", "The object key must not contain a NUL character."),
    };
  }
  const segments = key.split("/");
  const directory = segments.at(-1) === "";
  const parts = directory ? segments.slice(0, -1) : segments;
  /* `parts` is never empty: `split` yields at least one element and only the
     empty key could lose it to the trailing-slash strip, which is refused
     above. A key of only slashes lands in the empty-segment check below. */
  for (const segment of parts) {
    if (segment === "" || segment === "." || segment === "..") {
      return {
        ok: false,
        error: s3Error(
          "InvalidArgument",
          `The object key ${JSON.stringify(key)} does not map to a path: ` +
            `empty, "." and ".." segments are not allowed.`,
        ),
      };
    }
  }
  if (isStagingKey(key)) {
    return { ok: false, error: s3Error("NoSuchKey") };
  }
  const path = `/${parts.join("/")}`;
  /* Belt and braces: everything that would change here is already refused
     above, so a mismatch means this function and `src/path.ts` disagree. */
  if (normalizePath(path) !== path) {
    return {
      ok: false,
      error: s3Error(
        "InvalidArgument",
        `The object key ${JSON.stringify(key)} does not map to a path.`,
      ),
    };
  }
  return { ok: true, key: { key, path, directory } };
}

/**
 * The key an absolute driver path corresponds to — the inverse of
 * {@link parseObjectKey}. The bucket root (`/`) is the empty key.
 */
export function pathToKey(path: string, directory = false): string {
  const key = path === "/" ? "" : path.replace(/^\//, "");
  return directory && key !== "" ? `${key}/` : key;
}

/**
 * Is this a bucket name this gateway will look up?
 *
 * Deliberately *not* Amazon's bucket-naming rules (3–63 characters, lowercase,
 * no underscores): the bucket set here is the operator's, configured in
 * `createS3Server()`, so refusing `MyBucket` would refuse a bucket that exists.
 * What is checked is only what a path segment cannot carry — an unknown name
 * gets `NoSuchBucket` from the session, which is where the bucket table lives.
 */
export function isValidBucketName(bucket: string): boolean {
  if (bucket === "" || bucket === "." || bucket === ".." || bucket.length > 255) {
    return false;
  }
  for (const character of bucket) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f || character === "/" || character === "\\") {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// the operation table
// ---------------------------------------------------------------------------

/** Every S3 operation this gateway implements (plan decision, "Supported ops"). */
export type S3OpName =
  | "ListBuckets"
  | "HeadBucket"
  | "ListObjectsV2"
  | "GetObject"
  | "HeadObject"
  | "PutObject"
  | "DeleteObject"
  | "DeleteObjects"
  | "CopyObject"
  | "CreateMultipartUpload"
  | "UploadPart"
  | "CompleteMultipartUpload"
  | "AbortMultipartUpload"
  | "ListParts";

/** What each operation is selected by. */
export interface S3OpEntry {
  /** The HTTP method, exactly (S3 API Reference, per-operation `Request Syntax`). */
  method: "GET" | "HEAD" | "PUT" | "POST" | "DELETE";
  /** What the request addresses: the service root, a bucket, or an object. */
  scope: "service" | "bucket" | "object";
  /** The rest of the discrimination, in words — the query parameter or header
   * that picks this operation out of the others sharing its method and scope. */
  selector: string;
}

/**
 * The operation table: the "op names" deliverable, moved here from step 1
 * during that step's verification, because a name is only meaningful next to
 * what selects it.
 *
 * Every row is transcribed from that operation's page in the S3 API Reference.
 * `routeRequest()` produces exactly these names and no others, which
 * `test/s3/protocol.test.ts` checks in both directions.
 */
export const S3_OPS: Record<S3OpName, S3OpEntry> = {
  ListBuckets: { method: "GET", scope: "service", selector: "GET on /" },
  HeadBucket: { method: "HEAD", scope: "bucket", selector: "HEAD on /bucket" },
  ListObjectsV2: { method: "GET", scope: "bucket", selector: "list-type=2" },
  GetObject: { method: "GET", scope: "object", selector: "no sub-resource" },
  HeadObject: { method: "HEAD", scope: "object", selector: "no sub-resource" },
  PutObject: { method: "PUT", scope: "object", selector: "no sub-resource, no x-amz-copy-source" },
  DeleteObject: { method: "DELETE", scope: "object", selector: "no sub-resource" },
  DeleteObjects: { method: "POST", scope: "bucket", selector: "?delete" },
  CopyObject: { method: "PUT", scope: "object", selector: "x-amz-copy-source header" },
  CreateMultipartUpload: { method: "POST", scope: "object", selector: "?uploads" },
  UploadPart: { method: "PUT", scope: "object", selector: "?uploadId & partNumber" },
  CompleteMultipartUpload: { method: "POST", scope: "object", selector: "?uploadId" },
  AbortMultipartUpload: { method: "DELETE", scope: "object", selector: "?uploadId" },
  ListParts: { method: "GET", scope: "object", selector: "?uploadId" },
};

/**
 * Query parameters that **select an operation** this gateway does not
 * implement.
 *
 * Checked before anything else, and this is the step-4 invariant: a request
 * carrying one of these answers `NotImplemented`, never the plain-object
 * operation that shares its method. `GET /bucket/key?acl` asking for an ACL and
 * receiving the object's bytes would be a data leak dressed as a fall-through.
 *
 * Transcribed from the S3 API Reference's operation list: every bucket and
 * object sub-resource with an operation of its own, including the ones added
 * after the classic set (`renameObject`, the S3 Tables and metadata-table
 * calls, the Vectors calls, the express-session token). The four this gateway
 * *does* dispatch on — `uploads`, `uploadId`, `delete`, `list-type` — are
 * deliberately absent, and so is `versionId`, which selects nothing on its own
 * and is handled by {@link routeRequest} instead.
 *
 * **Selecting, not merely unknown.** A parameter that changes *which* operation
 * S3 runs belongs here; a parameter that only decorates one does not. The AWS
 * SDKs append `?x-id=GetObject` to every request they send, and presigned URLs
 * carry `response-content-disposition` and the six `X-Amz-*` parameters, so
 * refusing unknown parameters wholesale would refuse most real traffic. That is
 * why this is a list and not a rule.
 */
export const UNSUPPORTED_SUBRESOURCES: readonly string[] = [
  "abac",
  "accelerate",
  "acl",
  "analytics",
  "annotation",
  "annotationName",
  "attributes",
  "cors",
  "encryption",
  "id",
  "intelligent-tiering",
  "inventory",
  "legal-hold",
  "lifecycle",
  "location",
  "logging",
  "metadataAnnotationTable",
  "metadataConfiguration",
  "metadataInventoryTable",
  "metadataJournalTable",
  "metadataTable",
  "metrics",
  "notification",
  "object-lock",
  "ownershipControls",
  "policy",
  "policyStatus",
  "publicAccessBlock",
  "renameObject",
  "replication",
  "requestPayment",
  "restore",
  "retention",
  "select",
  "select-type",
  "session",
  "tagging",
  "torrent",
  "versioning",
  "versions",
  "website",
];

/**
 * The parameter that names an object version.
 *
 * Not in the list above, because it does not select an operation: `GET
 * /bucket/key?versionId=<id>` is still a `GetObject`, of a *particular version*.
 * This gateway has one version of every object, so the only value it can honour
 * is the null version — and answering the live object for a request that named
 * a specific version would serve, overwrite or delete the wrong bytes without
 * ever saying so. `null` and an empty value proceed; anything else is
 * `NotImplemented`. Exactly the rule {@link parseCopySource} applies to
 * `x-amz-copy-source`, applied to the request target too.
 */
export const VERSION_ID_PARAMETER = "versionId";

/**
 * The null version: the only version identifier a gateway with no versioning
 * can answer for (S3 API Reference — an object in a bucket that never had
 * versioning enabled has version ID `null`).
 */
export const NULL_VERSION_ID = "null";

/** `ListParts`'s `MaxParts`: both the default and the ceiling (S3 API
 * Reference, `ListParts`). The same number as `MAX_KEYS` and a different fact —
 * one bounds a listing of keys, the other a listing of parts. */
export const MAX_PARTS_PER_PAGE = 1000;

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

/** Fields every object-scoped route carries. */
export interface S3ObjectTarget {
  bucket: string;
  /** The key as sent, decoded, trailing `/` kept. */
  key: string;
  /** The driver path for that key. */
  path: string;
  /** Did the key end in `/`? */
  directory: boolean;
}

/** `x-amz-copy-source`, taken apart — the same fields, in another bucket. */
export type S3CopySource = S3ObjectTarget;

/** The parsed `ListObjectsV2` query (S3 API Reference, `ListObjectsV2`). */
export interface ListObjectsV2Query {
  prefix: string;
  /** `undefined` means "no delimiter": a full depth-first walk. */
  delimiter: string | undefined;
  /** Already clamped to `MAX_KEYS`, as S3 clamps it. */
  maxKeys: number;
  continuationToken: string | undefined;
  startAfter: string | undefined;
  fetchOwner: boolean;
  /** `"url"` or `undefined`; anything else is refused. */
  encodingType: "url" | undefined;
}

/** Every route `routeRequest()` can produce, discriminated by `op`. */
export type S3Request =
  | { op: "ListBuckets" }
  | { op: "HeadBucket"; bucket: string }
  | ({ op: "ListObjectsV2"; bucket: string } & ListObjectsV2Query)
  | ({ op: "GetObject" } & S3ObjectTarget)
  | ({ op: "HeadObject" } & S3ObjectTarget)
  | ({ op: "PutObject" } & S3ObjectTarget)
  | ({ op: "DeleteObject" } & S3ObjectTarget)
  | { op: "DeleteObjects"; bucket: string }
  | ({
      op: "CopyObject";
      source: S3CopySource;
      metadataDirective: "COPY" | "REPLACE";
    } & S3ObjectTarget)
  | ({ op: "CreateMultipartUpload" } & S3ObjectTarget)
  | ({ op: "UploadPart"; uploadId: string; partNumber: number } & S3ObjectTarget)
  | ({ op: "CompleteMultipartUpload"; uploadId: string } & S3ObjectTarget)
  | ({ op: "AbortMultipartUpload"; uploadId: string } & S3ObjectTarget)
  | ({
      op: "ListParts";
      uploadId: string;
      maxParts: number;
      partNumberMarker: number;
    } & S3ObjectTarget);

/** A request that never reaches an operation handler. */
export interface S3Refusal {
  op: "Refused";
  error: S3ErrorSpec;
  /** The `<Resource>` for the error document, when the path named one. */
  resource?: string;
}

/**
 * A request the router answers **itself**, with a status and no body: no error
 * document, and no driver call.
 *
 * There is exactly one of these, and it exists so that the multipart staging
 * area can be invisible rather than merely refused — see {@link parseObjectKey}.
 * A `DELETE` of a key that does not exist is `204` in S3, so a `DELETE` under
 * the staging prefix has to be `204` as well; a refusal there would be an
 * oracle for the one prefix this gateway reserves.
 */
export interface S3Answered {
  op: "Answered";
  /** Always a status with no body of its own (`204`). */
  status: number;
  resource?: string;
}

/**
 * {@link routeRequest}'s answer: an operation, a refusal carrying an error, or
 * a reply the router made itself.
 */
export type S3Route = S3Request | S3Refusal | S3Answered;

/** Is this route a refusal? */
export function isRefusal(route: S3Route): route is S3Refusal {
  return route.op === "Refused";
}

/** Did the router answer this request itself, with no error and no driver call? */
export function isAnswered(route: S3Route): route is S3Answered {
  return route.op === "Answered";
}

function refuse(error: S3ErrorSpec, resource: string): S3Refusal {
  return { op: "Refused", error, resource };
}

function notImplemented(what: string, resource: string): S3Refusal {
  return refuse(s3Error("NotImplemented", `${what} is not implemented by this gateway.`), resource);
}

/**
 * What a key under the multipart staging prefix answers, by method.
 *
 * The prefix has to look like empty space, and "empty space" is a different
 * reply for each method, so a single answer for all of them *is* the tell:
 *
 * - **`DELETE` → `204`.** S3 answers `204` for deleting a key that is not
 *   there, so anything else here would mark the prefix as special. This is the
 *   one that costs nothing to hide.
 * - **`GET`/`HEAD` → `NoSuchKey` 404**, byte for byte what a missing key
 *   answers. (A `HEAD` carries the status and no body, which is HTTP's rule for
 *   `HEAD` rather than anything about this prefix.)
 * - **`PUT`/`POST` → `NoSuchKey` 404**, and this one **is** a tell: a `PUT` to a
 *   key that does not exist normally succeeds, so a client that tries can see
 *   that this prefix behaves differently. It is accepted knowingly. Perfect
 *   invisibility would mean answering `200` and dropping the bytes, which
 *   trades a visible refusal for silent data loss, and `AccessDenied` would be
 *   *more* revealing — it says the name exists and is guarded. A 404 at least
 *   tells the truth about the outcome: nothing was written. The reserved prefix
 *   is documented in `docs/`, so this is a name a user can avoid on purpose,
 *   not a trap.
 *
 * Everything else falls through to the method check that follows, which
 * answers `MethodNotAllowed` — the same answer that method gets on any key.
 */
function stagingAnswer(method: string, resource: string): S3Route {
  switch (method) {
    case "DELETE": {
      return { op: "Answered", status: 204, resource };
    }
    case "GET":
    case "HEAD":
    case "PUT":
    case "POST": {
      return refuse(s3Error("NoSuchKey"), resource);
    }
    default: {
      return methodNotAllowed(method, resource);
    }
  }
}

function methodNotAllowed(method: string, resource: string): S3Refusal {
  return refuse(
    s3Error("MethodNotAllowed", `The method ${method} is not allowed against this resource.`),
    resource,
  );
}

/**
 * Parse an `x-amz-copy-source` header.
 *
 * The documented forms are `/source-bucket/source-key` and
 * `source-bucket/source-key`, percent-encoded, with an optional
 * `?versionId=<id>` (S3 API Reference, `CopyObject`). The `?` is found in the
 * **encoded** value, before decoding, so an encoded `%3F` inside a key is not
 * mistaken for the separator; the path is then decoded once, exactly like a
 * request target.
 *
 * `versionId=null` is the null version — this gateway's only one — and is
 * accepted. Any other value is `NotImplemented`.
 */
export function parseCopySource(
  value: string,
): { ok: true; source: S3CopySource } | { ok: false; error: S3ErrorSpec } {
  const invalid = s3Error(
    "InvalidArgument",
    "Copy Source must mention the source bucket and key: sourcebucket/sourcekey",
  );
  const questionMark = value.indexOf("?");
  const rawSource = questionMark === -1 ? value : value.slice(0, questionMark);
  const rawQuery = questionMark === -1 ? "" : value.slice(questionMark + 1);
  for (const pair of rawQuery.split("&")) {
    if (pair === "") {
      continue;
    }
    const equals = pair.indexOf("=");
    const name = equals === -1 ? pair : pair.slice(0, equals);
    const raw = equals === -1 ? "" : pair.slice(equals + 1);
    if (name === "versionId") {
      const versionId = decodeOnce(raw);
      if (versionId === undefined) {
        return { ok: false, error: invalid };
      }
      if (versionId !== "null" && versionId !== "") {
        return {
          ok: false,
          error: s3Error("NotImplemented", "Versioning is not implemented by this gateway."),
        };
      }
    }
  }
  const decoded = decodeOnce(rawSource);
  if (decoded === undefined) {
    return { ok: false, error: invalid };
  }
  const withoutLeading = decoded.startsWith("/") ? decoded.slice(1) : decoded;
  const slash = withoutLeading.indexOf("/");
  if (slash === -1) {
    return { ok: false, error: invalid };
  }
  const bucket = withoutLeading.slice(0, slash);
  const key = withoutLeading.slice(slash + 1);
  if (!isValidBucketName(bucket)) {
    return { ok: false, error: invalid };
  }
  if (key === "") {
    return { ok: false, error: invalid };
  }
  const parsed = parseObjectKey(key);
  if (!parsed.ok) {
    return { ok: false, error: parsed.error };
  }
  return {
    ok: true,
    source: { bucket, key: parsed.key.key, path: parsed.key.path, directory: parsed.key.directory },
  };
}

function parseListObjectsV2Query(
  query: readonly QueryEntry[],
): { ok: true; list: ListObjectsV2Query } | { ok: false; error: S3ErrorSpec } {
  const rawMaxKeys = queryValue(query, "max-keys");
  let maxKeys = MAX_KEYS;
  if (rawMaxKeys !== undefined && rawMaxKeys !== "") {
    const parsed = parseUnsignedInteger(rawMaxKeys);
    if (parsed === undefined || parsed > 2_147_483_647) {
      return {
        ok: false,
        error: s3Error(
          "InvalidArgument",
          "Argument max-keys must be an integer between 0 and 2147483647",
        ),
      };
    }
    /* S3 clamps rather than refusing: "returns up to 1,000 keys ... if there
       are more". */
    maxKeys = Math.min(parsed, MAX_KEYS);
  }
  const encodingTypeRaw = queryValue(query, "encoding-type");
  if (encodingTypeRaw !== undefined && encodingTypeRaw !== "" && encodingTypeRaw !== "url") {
    return {
      ok: false,
      error: s3Error("InvalidArgument", "Invalid Encoding Method specified in Request"),
    };
  }
  const delimiter = queryValue(query, "delimiter");
  if (delimiter !== undefined && delimiter !== "" && delimiter !== "/") {
    /* A delimiter other than "/" would need a grouping pass over a full walk,
       which is not implemented; refused rather than silently ignored, which
       would hand back a flat listing the client would read as grouped. */
    return {
      ok: false,
      error: s3Error(
        "NotImplemented",
        `A delimiter other than "/" is not implemented by this gateway.`,
      ),
    };
  }
  const continuationToken = queryValue(query, "continuation-token");
  const startAfter = queryValue(query, "start-after");
  return {
    ok: true,
    list: {
      prefix: queryValue(query, "prefix") ?? "",
      delimiter: delimiter === undefined || delimiter === "" ? undefined : delimiter,
      maxKeys,
      continuationToken:
        continuationToken === undefined || continuationToken === "" ? undefined : continuationToken,
      startAfter: startAfter === undefined || startAfter === "" ? undefined : startAfter,
      fetchOwner: (queryValue(query, "fetch-owner") ?? "").toLowerCase() === "true",
      encodingType: encodingTypeRaw === "url" ? "url" : undefined,
    },
  };
}

/**
 * Route one request to an operation, or to a refusal carrying the S3 error it
 * should answer with.
 *
 * `path` is the **decoded** path from {@link parseRequestTarget} and `query`
 * its decoded parameters; `headers` is needed because two operations are
 * selected by a header rather than the URL (`x-amz-copy-source` picks
 * `CopyObject` out of `PutObject`, and picks `UploadPartCopy` — which is not
 * implemented — out of `UploadPart`).
 *
 * Path-style only, by plan decision: the first path segment is the bucket and
 * the rest is the key. A virtual-hosted-style request (`bucket.host/key`)
 * arrives here as a key at the service root and is routed on its path like any
 * other, which is the honest behaviour for a gateway that never advertised a
 * wildcard DNS name.
 */
export function routeRequest(
  method: string,
  path: string,
  query: readonly QueryEntry[],
  headers: readonly HeaderEntry[] = [],
): S3Route {
  const resource = path;
  for (const name of UNSUPPORTED_SUBRESOURCES) {
    if (hasQuery(query, name)) {
      return notImplemented(`The sub-resource "?${name}"`, resource);
    }
  }
  const versionId = queryValue(query, VERSION_ID_PARAMETER);
  if (versionId !== undefined && versionId !== "" && versionId !== NULL_VERSION_ID) {
    /* Not a sub-resource — it narrows an operation this gateway *does* run, to
       a version it does not have. Serving the live object here would answer a
       GET, satisfy a PUT or complete a DELETE against the wrong bytes and say
       nothing about it, which is why this refuses rather than ignores. */
    return notImplemented(`The parameter "?${VERSION_ID_PARAMETER}"`, resource);
  }
  if (!path.startsWith("/")) {
    return refuse(s3Error("InvalidURI", "Couldn't parse the specified URI."), resource);
  }
  const withoutLeading = path.slice(1);
  const slash = withoutLeading.indexOf("/");
  const bucket = slash === -1 ? withoutLeading : withoutLeading.slice(0, slash);
  const rawKey = slash === -1 ? "" : withoutLeading.slice(slash + 1);

  if (bucket === "") {
    /* The service root. `GET /` is the only operation S3 has here. */
    if (rawKey !== "") {
      return refuse(s3Error("InvalidBucketName"), resource);
    }
    return method === "GET" ? { op: "ListBuckets" } : methodNotAllowed(method, resource);
  }
  if (!isValidBucketName(bucket)) {
    return refuse(s3Error("InvalidBucketName"), resource);
  }

  const uploads = hasQuery(query, "uploads");
  const uploadId = queryValue(query, "uploadId");
  const deleteMultiple = hasQuery(query, "delete");
  const copySource = headerValue(headers, "x-amz-copy-source");

  if (rawKey === "") {
    /* Bucket scope. */
    if (uploads) {
      return method === "GET"
        ? notImplemented("ListMultipartUploads", resource)
        : methodNotAllowed(method, resource);
    }
    if (uploadId !== undefined) {
      return methodNotAllowed(method, resource);
    }
    switch (method) {
      case "GET": {
        const listType = queryValue(query, "list-type");
        if (listType === undefined) {
          /* A bare `GET /bucket` is ListObjects **V1**. Deliberately refused:
             V2 is what every current client speaks, and answering V1's document
             shape from V2's walk would be a second listing implementation with
             its own marker semantics. */
          return notImplemented("ListObjects (V1)", resource);
        }
        if (listType !== "2") {
          return refuse(s3Error("InvalidArgument", `Invalid List Type: ${listType}`), resource);
        }
        const parsed = parseListObjectsV2Query(query);
        return parsed.ok
          ? { op: "ListObjectsV2", bucket, ...parsed.list }
          : refuse(parsed.error, resource);
      }
      case "HEAD": {
        return { op: "HeadBucket", bucket };
      }
      case "POST": {
        return deleteMultiple
          ? { op: "DeleteObjects", bucket }
          : notImplemented("POST Object (browser form upload)", resource);
      }
      case "PUT": {
        return notImplemented("CreateBucket", resource);
      }
      case "DELETE": {
        return notImplemented("DeleteBucket", resource);
      }
      default: {
        return methodNotAllowed(method, resource);
      }
    }
  }

  /* Object scope. */
  if (isStagingKey(rawKey)) {
    return stagingAnswer(method, resource);
  }
  const parsedKey = parseObjectKey(rawKey);
  if (!parsedKey.ok) {
    return refuse(parsedKey.error, resource);
  }
  const target: S3ObjectTarget = {
    bucket,
    key: parsedKey.key.key,
    path: parsedKey.key.path,
    directory: parsedKey.key.directory,
  };

  if (deleteMultiple && method === "POST") {
    /* `?delete` is bucket-scoped; with a key there is no such operation. */
    return methodNotAllowed(method, resource);
  }
  if (uploads) {
    if (method === "POST") {
      return { op: "CreateMultipartUpload", ...target };
    }
    return method === "GET"
      ? notImplemented("ListMultipartUploads", resource)
      : methodNotAllowed(method, resource);
  }
  if (uploadId !== undefined) {
    if (uploadId === "") {
      return refuse(s3Error("InvalidArgument", "The uploadId must not be empty."), resource);
    }
    switch (method) {
      case "PUT": {
        if (copySource !== undefined) {
          return notImplemented("UploadPartCopy", resource);
        }
        const rawPartNumber = queryValue(query, "partNumber");
        const partNumber =
          rawPartNumber === undefined ? undefined : parseUnsignedInteger(rawPartNumber);
        if (partNumber === undefined || partNumber < 1 || partNumber > MAX_PARTS) {
          return refuse(
            s3Error(
              "InvalidArgument",
              `Part number must be an integer between 1 and ${MAX_PARTS}, inclusive`,
            ),
            resource,
          );
        }
        return { op: "UploadPart", uploadId, partNumber, ...target };
      }
      case "POST": {
        return { op: "CompleteMultipartUpload", uploadId, ...target };
      }
      case "DELETE": {
        return { op: "AbortMultipartUpload", uploadId, ...target };
      }
      case "GET": {
        const rawMaxParts = queryValue(query, "max-parts");
        const maxParts =
          rawMaxParts === undefined || rawMaxParts === ""
            ? MAX_PARTS_PER_PAGE
            : parseUnsignedInteger(rawMaxParts);
        const rawMarker = queryValue(query, "part-number-marker");
        const partNumberMarker =
          rawMarker === undefined || rawMarker === "" ? 0 : parseUnsignedInteger(rawMarker);
        if (maxParts === undefined || partNumberMarker === undefined) {
          return refuse(
            s3Error("InvalidArgument", "max-parts and part-number-marker must be integers"),
            resource,
          );
        }
        return {
          op: "ListParts",
          uploadId,
          maxParts: Math.min(maxParts, MAX_PARTS_PER_PAGE),
          partNumberMarker,
          ...target,
        };
      }
      default: {
        return methodNotAllowed(method, resource);
      }
    }
  }

  switch (method) {
    case "GET": {
      if (hasQuery(query, "partNumber")) {
        return notImplemented("GetObject for a single part", resource);
      }
      return { op: "GetObject", ...target };
    }
    case "HEAD": {
      if (hasQuery(query, "partNumber")) {
        return notImplemented("HeadObject for a single part", resource);
      }
      return { op: "HeadObject", ...target };
    }
    case "PUT": {
      if (copySource === undefined) {
        return { op: "PutObject", ...target };
      }
      const source = parseCopySource(copySource);
      if (!source.ok) {
        return refuse(source.error, resource);
      }
      const directive = headerValue(headers, "x-amz-metadata-directive");
      if (directive !== undefined && directive !== "COPY" && directive !== "REPLACE") {
        return refuse(s3Error("InvalidArgument", "Unknown metadata directive."), resource);
      }
      return {
        op: "CopyObject",
        source: source.source,
        metadataDirective: directive === "REPLACE" ? "REPLACE" : "COPY",
        ...target,
      };
    }
    case "DELETE": {
      return { op: "DeleteObject", ...target };
    }
    case "POST": {
      return methodNotAllowed(method, resource);
    }
    default: {
      return methodNotAllowed(method, resource);
    }
  }
}

// ---------------------------------------------------------------------------
// conditional requests
// ---------------------------------------------------------------------------

/**
 * Evaluate the four conditional headers in RFC 9110 §13.2.2's order.
 *
 * The rules are HTTP's rather than S3's and live in `src/http.ts` beside the
 * entity-tag comparison functions they use; this is the S3 spelling of the same
 * call, taking the header list this transport carries (SigV4 signs headers as
 * they were sent, so they stay a list of entries here) and joining the two
 * list-based fields the way RFC 9110 §5.3 permits.
 */
export function evaluateConditionals(
  target: ConditionalTarget,
  headers: readonly HeaderEntry[],
  method: string,
): ConditionalResult {
  return evaluateHttpConditionals(
    target,
    {
      "if-match": headerList(headers, "if-match"),
      "if-none-match": headerList(headers, "if-none-match"),
      "if-modified-since": headerValue(headers, "if-modified-since"),
      "if-unmodified-since": headerValue(headers, "if-unmodified-since"),
    },
    method,
  );
}

/**
 * What a `PUT`'s conditional headers ask for, before anything is stat'ed.
 *
 * `evaluateConditionals` needs a representation to compare against, and the
 * whole point of a conditional `PUT` is that there may not be one — so the
 * session has to decide whether to go looking *first*. That decision is here,
 * as three facts about the headers alone:
 *
 * - `conditional` — is there anything to evaluate at all? `If-Modified-Since`
 *   does not count: §13.2.2 evaluates it only for `GET`/`HEAD`, so on a `PUT`
 *   it changes no answer and must not cost a `stat`.
 * - `createOnly` — `If-None-Match: *`, and nothing else that needs the object
 *   to be there. This is the "create only if absent" idiom, and the one case a
 *   driver can make atomic on its own (`O_CREAT|O_EXCL`).
 * - `requiresPresence` — there is an `If-Match`, whose subject must exist:
 *   S3 answers a missing key `404`, not `412`.
 */
export interface PutCondition {
  /** Is there a conditional header that applies to a `PUT`? */
  conditional: boolean;
  /** Is it exactly `If-None-Match: *`, with no condition needing the object? */
  createOnly: boolean;
  /** Is there an `If-Match`? */
  requiresPresence: boolean;
}

/** {@link PutCondition}, read off the request headers. */
export function putCondition(headers: readonly HeaderEntry[]): PutCondition {
  const ifMatch = headerList(headers, "if-match");
  const ifNoneMatch = headerList(headers, "if-none-match");
  const ifUnmodifiedSince = headerValue(headers, "if-unmodified-since");
  return {
    conditional:
      ifMatch !== undefined || ifNoneMatch !== undefined || ifUnmodifiedSince !== undefined,
    createOnly:
      ifMatch === undefined &&
      ifUnmodifiedSince === undefined &&
      ifNoneMatch !== undefined &&
      parseETagList(ifNoneMatch).any,
    requiresPresence: ifMatch !== undefined,
  };
}

// ---------------------------------------------------------------------------
// object metadata headers
// ---------------------------------------------------------------------------

/**
 * The one metadata header that survives a round trip: rclone's `mtime`
 * convention, epoch **seconds** with an optional fractional part (plan
 * decision; everything else `x-amz-meta-*` is dropped).
 */
export const META_MTIME_HEADER = "x-amz-meta-mtime";

/**
 * Read `x-amz-meta-mtime` as a millisecond timestamp, or `undefined`.
 *
 * A value that is not a number is **ignored rather than refused**: rclone and
 * its lookalikes write this header from whatever their backend had, a bad one
 * costs a timestamp and nothing else, and a 400 would fail an upload that S3
 * itself would have accepted (S3 stores user metadata without reading it).
 * Negative values are accepted — they are pre-1970 files.
 */
export function parseMetaMtime(value: string | undefined): number | undefined {
  if (value === undefined || !/^-?\d+(?:\.\d+)?$/.test(value)) {
    return undefined;
  }
  const seconds = Number(value);
  if (!Number.isFinite(seconds)) {
    return undefined;
  }
  const milliseconds = Math.round(seconds * 1000);
  return Math.abs(milliseconds) > MAX_TIMESTAMP_MS ? undefined : milliseconds;
}

/**
 * Format a millisecond timestamp as `x-amz-meta-mtime`: epoch seconds, with a
 * fractional part only when the timestamp is not a whole second, so a file with
 * a whole-second mtime round-trips through rclone byte-identically.
 */
export function formatMetaMtime(timestamp: number): string {
  const seconds = timestamp / 1000;
  return Number.isInteger(seconds) ? String(seconds) : seconds.toFixed(3);
}
/** What an object reply's headers are built from. */
export interface ObjectHeadersInput {
  /** The derived ETag; quoted for you. */
  etag: string;
  /** The number of bytes in **this reply's** body — the range length for a 206. */
  size: number;
  /** The object's modification time, in milliseconds. */
  mtimeMs: number;
  /** Present on a 206: which bytes these are, and how many there are in all. */
  contentRange?: { start: number; end: number; total: number };
}

/**
 * The headers every `GET`/`HEAD`/`PUT` object reply carries.
 *
 * `Content-Type` is always `application/octet-stream` (it is not stored),
 * `Accept-Ranges: bytes` is unconditional because every object here is
 * positionally readable, and `x-amz-meta-mtime` is echoed from the stat so a
 * client that wrote it back gets it back.
 */
export function objectResponseHeaders(input: ObjectHeadersInput): Record<string, string> {
  const headers: Record<string, string> = {
    "content-type": OBJECT_CONTENT_TYPE,
    "content-length": String(input.size),
    etag: formatETag(input.etag),
    "last-modified": formatHttpDate(input.mtimeMs),
    "accept-ranges": "bytes",
    [META_MTIME_HEADER]: formatMetaMtime(input.mtimeMs),
  };
  if (input.contentRange !== undefined) {
    headers["content-range"] = formatContentRange(
      input.contentRange.start,
      input.contentRange.end,
      input.contentRange.total,
    );
  }
  return headers;
}

// ---------------------------------------------------------------------------
// request bodies
// ---------------------------------------------------------------------------

/**
 * The tokens of a `Content-Encoding` header, lowercased.
 *
 * A list, never a single value: `aws-chunked,gzip` is legal and a client that
 * sends it means both (`constants.ts`, {@link AWS_CHUNKED_ENCODING}).
 */
export function contentCodings(value: string | undefined): string[] {
  if (value === undefined) {
    return [];
  }
  const codings: string[] = [];
  for (const token of value.split(",")) {
    const trimmed = token.trim().toLowerCase();
    if (trimmed !== "") {
      codings.push(trimmed);
    }
  }
  return codings;
}

/** How a request body is framed on the wire. */
export interface S3BodyMode {
  /** `aws-chunked` means the body needs `chunked.ts` before it is object bytes. */
  framing: "identity" | "aws-chunked";
  /** Do the chunks carry `chunk-signature=` extensions that must verify? */
  signedChunks: boolean;
  /** May a trailing-header block follow the terminal chunk? */
  trailers: boolean;
  /** `x-amz-content-sha256` verbatim, for the canonical request. */
  payloadHash: string | undefined;
}

/**
 * Decide how the body is framed, from the two headers that say so.
 *
 * `x-amz-content-sha256` carries the three streaming sentinels
 * (`streamingPayloadKind()` reads them). The fourth shape — `aws-chunked`
 * framing with no sentinel at all, which is unsigned and has no trailers — is
 * only visible in `Content-Encoding`, which is exactly the case `chunked.ts`
 * documents as the caller's to pair up.
 */
export function bodyMode(headers: readonly HeaderEntry[]): S3BodyMode {
  const payloadHash = headerValue(headers, "x-amz-content-sha256");
  const kind = payloadHash === undefined ? undefined : streamingPayloadKind(payloadHash);
  if (kind !== undefined) {
    return {
      framing: "aws-chunked",
      signedChunks: kind.signed,
      trailers: kind.trailers,
      payloadHash,
    };
  }
  if (contentCodings(headerList(headers, "content-encoding")).includes(AWS_CHUNKED_ENCODING)) {
    return { framing: "aws-chunked", signedChunks: false, trailers: false, payloadHash };
  }
  return { framing: "identity", signedChunks: false, trailers: false, payloadHash };
}

/** The two lengths a request can declare. */
export interface S3ContentLengths {
  /** `Content-Length`: the bytes on the wire, framing included. */
  contentLength: number | undefined;
  /** `x-amz-decoded-content-length`: the object bytes inside an `aws-chunked`
   * body. */
  decodedContentLength: number | undefined;
}

/**
 * Read `Content-Length` and `x-amz-decoded-content-length`.
 *
 * Both must be a plain non-negative decimal integer within
 * `Number.MAX_SAFE_INTEGER` — no sign, no whitespace, no `0x`, nothing that
 * `Number()` would accept and a byte count would not survive. Anything else is
 * `InvalidArgument`, which is a refusal rather than a silent `NaN` reaching a
 * read loop.
 */
export function parseContentLengths(
  headers: readonly HeaderEntry[],
): { ok: true; lengths: S3ContentLengths } | { ok: false; error: S3ErrorSpec } {
  const lengths: S3ContentLengths = { contentLength: undefined, decodedContentLength: undefined };
  const raw = headerValue(headers, "content-length");
  if (raw !== undefined) {
    const parsed = parseUnsignedInteger(raw.trim());
    if (parsed === undefined) {
      return {
        ok: false,
        error: s3Error("InvalidArgument", `Invalid Content-Length: ${JSON.stringify(raw)}`),
      };
    }
    lengths.contentLength = parsed;
  }
  const rawDecoded = headerValue(headers, "x-amz-decoded-content-length");
  if (rawDecoded !== undefined) {
    const parsed = parseUnsignedInteger(rawDecoded.trim());
    if (parsed === undefined) {
      return {
        ok: false,
        error: s3Error(
          "InvalidArgument",
          `Invalid x-amz-decoded-content-length: ${JSON.stringify(rawDecoded)}`,
        ),
      };
    }
    lengths.decodedContentLength = parsed;
  }
  return { ok: true, lengths };
}
