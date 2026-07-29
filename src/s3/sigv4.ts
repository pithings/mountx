/**
 * AWS Signature Version 4, for the `s3` service. Pure: no I/O, no sockets, and
 * **no clock** — every function that needs the time takes it as an argument, so
 * the server owns `Date.now()` and the tests own everything else.
 *
 * Transcribed from:
 *
 * - **The AWS Signature Version 4 specification** (AWS General Reference,
 *   "Signing AWS API requests"): the canonical request, the string to sign, the
 *   signing-key derivation chain, and the two forms a signature arrives in —
 *   an `Authorization` header or a presigned query string.
 * - **The official `aws-sig-v4-test-suite`** (awslabs; the copy under
 *   `tests/aws-signing-test-suite/v4` in `awslabs/aws-c-auth`), which supplies
 *   the goldens in `test/s3/sigv4.test.ts` for all three stages — canonical
 *   request, string to sign, signature — rather than just the last one.
 *
 * **The S3 rule that is not the general rule.** For every AWS service *except*
 * S3, the canonical URI is the path URI-encoded **twice**. S3 encodes it
 * **once**, and does not normalize dot or empty path segments either — the two
 * switches AWS SDKs spell `use_double_uri_encode = false` and
 * `should_normalize_uri_path = false` for this service. `canonicalUri()`
 * implements the S3 side and nothing else; a `/a b` key canonicalizes to
 * `/a%20b`, never `/a%2520b`, and `//x//` stays `//x//`.
 *
 * The path handed in here is the **percent-decoded** one. A server has the
 * encoded form on the wire and could sign it verbatim, but clients differ on
 * which non-unreserved bytes they encode, and decoding once then re-encoding
 * with the AWS rules is what makes those agree. The one thing it cannot
 * recover is a `%2F` inside a key name: decoding turns it into a separator, and
 * S3 has the same ambiguity, since a key with a slash in it *is* a prefix.
 *
 * **Direction.** This is a server, so verification is the point, but both
 * directions are here: `signRequest()`/`presignRequest()` exist because the
 * Tier-1 test client signs with them, and verifying against our own signer
 * proves the two halves agree while the official vectors prove they agree with
 * Amazon.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { UNSIGNED_PAYLOAD } from "./constants.ts";

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

/** The only algorithm this transport speaks. */
export const SIGV4_ALGORITHM = "AWS4-HMAC-SHA256";

/** The service name in every S3 credential scope. */
export const S3_SERVICE = "s3";

/** The fixed last component of a credential scope. */
export const SIGV4_TERMINATOR = "aws4_request";

/**
 * How far a header-form request's `x-amz-date` may sit from the server's clock
 * before it is refused, in milliseconds. AWS's window, and the plan's.
 */
export const MAX_CLOCK_SKEW_MS = 15 * 60 * 1000;

/** Longest presigned lifetime AWS accepts, in seconds: one week. */
export const MAX_PRESIGNED_EXPIRES = 7 * 24 * 60 * 60;

/** `sha256("")`, the payload hash of every body-less request. */
export const EMPTY_PAYLOAD_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/** The presigned-URL query parameters, spelled exactly as AWS spells them. */
export const QUERY_ALGORITHM = "X-Amz-Algorithm";
export const QUERY_CREDENTIAL = "X-Amz-Credential";
export const QUERY_DATE = "X-Amz-Date";
export const QUERY_EXPIRES = "X-Amz-Expires";
export const QUERY_SIGNED_HEADERS = "X-Amz-SignedHeaders";
export const QUERY_SIGNATURE = "X-Amz-Signature";

/** The two headers the header form reads outside the signature itself. */
export const HEADER_AUTHORIZATION = "authorization";
export const HEADER_DATE = "x-amz-date";
export const HEADER_CONTENT_SHA256 = "x-amz-content-sha256";

// ---------------------------------------------------------------------------
// request pieces
// ---------------------------------------------------------------------------

/**
 * One header as it arrived, in wire order and wire case. Repeats are kept:
 * duplicates are joined, not deduplicated, when they are canonicalized.
 */
export interface HeaderEntry {
  name: string;
  value: string;
}

/** One query parameter, **percent-decoded**, in wire order. */
export interface QueryEntry {
  name: string;
  value: string;
}

/** The credentials a gateway was configured with. */
export interface SigV4Credentials {
  accessKeyId: string;
  secretAccessKey: string;
}

/** `<date>/<region>/<service>/aws4_request`, taken apart. */
export interface CredentialScope {
  /** `YYYYMMDD`, UTC, and the same day as the request's `x-amz-date`. */
  date: string;
  region: string;
  service: string;
}

// ---------------------------------------------------------------------------
// encoding
// ---------------------------------------------------------------------------

/** RFC 3986's unreserved set: the only bytes SigV4 leaves alone. */
const UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

const UNRESERVED_BYTES = new Uint8Array(256);
for (let at = 0; at < UNRESERVED.length; at++) {
  UNRESERVED_BYTES[UNRESERVED.charCodeAt(at)] = 1;
}

/**
 * Percent-encode one UTF-8 string the way SigV4 requires: every byte outside
 * `A-Za-z0-9-_.~` becomes `%XX` with **uppercase** hex, and `/` is encoded too
 * (`canonicalUri()` splits on separators before calling this, so a `/` reaching
 * here is part of a name).
 *
 * Written over UTF-8 bytes rather than over `encodeURIComponent`, which leaves
 * `!'()*` unescaped and throws on a lone surrogate. Nothing here throws.
 */
export function uriEncode(value: string): string {
  const bytes = Buffer.from(value, "utf8");
  let encoded = "";
  for (const byte of bytes) {
    encoded +=
      UNRESERVED_BYTES[byte] === 1
        ? String.fromCharCode(byte)
        : `%${byte.toString(16).padStart(2, "0").toUpperCase()}`;
  }
  return encoded;
}

/**
 * The canonical URI: each path segment encoded **once**, separators kept, and
 * nothing normalized. See the S3 rule in the module docs — this is the one
 * place the s3 service differs from every other AWS service.
 *
 * SigV4 canonicalizes the *absolute* path, and an origin-form request target
 * always begins with a separator, so nothing off the wire arrives here without
 * one. A caller that hands over a relative path gets it read as the absolute
 * path it must have been, rather than a canonical request silently missing its
 * leading slash — which would produce a signature mismatch with no clue in it.
 */
export function canonicalUri(path: string): string {
  if (path === "") {
    return "/";
  }
  const absolute = path.startsWith("/") ? path : `/${path}`;
  return absolute
    .split("/")
    .map((segment) => uriEncode(segment))
    .join("/");
}

/**
 * The canonical query string: every name and value encoded, then sorted by
 * encoded name and, for repeats of one name, by encoded value. A parameter with
 * no value canonicalizes as `name=`.
 */
export function canonicalQuery(query: readonly QueryEntry[]): string {
  const encoded = query.map((entry) => ({
    name: uriEncode(entry.name),
    value: uriEncode(entry.value),
  }));
  encoded.sort((left, right) => {
    if (left.name !== right.name) {
      return left.name < right.name ? -1 : 1;
    }
    if (left.value === right.value) {
      return 0;
    }
    return left.value < right.value ? -1 : 1;
  });
  return encoded.map((entry) => `${entry.name}=${entry.value}`).join("&");
}

/** Lowercase, deduplicate and sort a signed-header list. */
export function canonicalSignedHeaders(signedHeaders: readonly string[]): string[] {
  return [...new Set(signedHeaders.map((name) => name.toLowerCase()))].sort();
}

/**
 * A header value as it goes into the canonical request: surrounding **ASCII
 * space and tab** removed, and internal runs of them collapsed to one space.
 * The collapse applies inside quotes as well — the suite's
 * `get-header-value-trim` vector signs `"a   b   c"` as `"a b c"`.
 *
 * ASCII deliberately: neither `String.prototype.trim()` nor `\s` would do,
 * because both are Unicode-aware. A header value carrying U+00A0 arrives as the
 * single byte `0xA0` (Node decodes header bytes as latin-1), a real signer
 * leaves that byte alone, and collapsing it here would mismatch every signature
 * over a value containing one.
 */
function normalizeHeaderValue(value: string): string {
  return value.replaceAll(/^[ \t]+|[ \t]+$/g, "").replaceAll(/[ \t]+/g, " ");
}

/**
 * The canonical headers block, one `name:value` line per signed header and a
 * trailing newline on each.
 *
 * Repeats of one name are joined with `,` **in the order they arrived**, which
 * is what `aws-c-auth` and the AWS SDKs do (`get-header-key-duplicate` signs
 * `value2,value2,value1`). The oldest copies of the test suite sorted those
 * values instead; that behavior was never what a signer produced, and a server
 * that sorted would reject every duplicated header a real client sends.
 *
 * A signed header that is not present at all contributes an empty value rather
 * than an error: the signature check that follows is the thing that fails, and
 * it fails for the right reason.
 */
export function canonicalHeaders(
  headers: readonly HeaderEntry[],
  signedHeaders: readonly string[],
): string {
  const byName = new Map<string, string[]>();
  for (const header of headers) {
    const name = header.name.toLowerCase();
    const values = byName.get(name);
    if (values === undefined) {
      byName.set(name, [normalizeHeaderValue(header.value)]);
    } else {
      values.push(normalizeHeaderValue(header.value));
    }
  }
  let block = "";
  for (const name of canonicalSignedHeaders(signedHeaders)) {
    block += `${name}:${(byName.get(name) ?? []).join(",")}\n`;
  }
  return block;
}

// ---------------------------------------------------------------------------
// canonical request, string to sign, signature
// ---------------------------------------------------------------------------

/** Everything the canonical request is built from. */
export interface CanonicalRequestInput {
  method: string;
  /** The **percent-decoded** request path (see the module docs). */
  path: string;
  query: readonly QueryEntry[];
  headers: readonly HeaderEntry[];
  /** Names to sign; case and order do not matter, they are canonicalized. */
  signedHeaders: readonly string[];
  /**
   * The payload hash **verbatim**: a sha256 hex digest, `UNSIGNED-PAYLOAD`, or
   * `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`. Whatever the client signed is what
   * goes here — it is a string in the canonical request, never a computation.
   */
  payloadHash: string;
}

/** The canonical request, exactly as it is hashed into the string to sign. */
export function canonicalRequest(input: CanonicalRequestInput): string {
  const signed = canonicalSignedHeaders(input.signedHeaders);
  return [
    input.method.toUpperCase(),
    canonicalUri(input.path),
    canonicalQuery(input.query),
    canonicalHeaders(input.headers, signed),
    signed.join(";"),
    input.payloadHash,
  ].join("\n");
}

/** Lowercase hex sha256, over UTF-8 for a string. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** `<date>/<region>/<service>/aws4_request`. */
export function credentialScope(scope: CredentialScope): string {
  return `${scope.date}/${scope.region}/${scope.service}/${SIGV4_TERMINATOR}`;
}

/** The string to sign: algorithm, timestamp, scope, hashed canonical request. */
export function stringToSign(amzDate: string, scope: CredentialScope, canonical: string): string {
  return [SIGV4_ALGORITHM, amzDate, credentialScope(scope), sha256Hex(canonical)].join("\n");
}

function hmac(key: string | Uint8Array, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

/**
 * The derivation chain: `AWS4` + secret, then date, region, service and the
 * terminator, each HMAC keyed by the previous result.
 */
export function signingKey(secretAccessKey: string, scope: CredentialScope): Buffer {
  const dateKey = hmac(`AWS4${secretAccessKey}`, scope.date);
  const regionKey = hmac(dateKey, scope.region);
  const serviceKey = hmac(regionKey, scope.service);
  return hmac(serviceKey, SIGV4_TERMINATOR);
}

/** The final signature, lowercase hex. */
export function signatureOf(
  secretAccessKey: string,
  scope: CredentialScope,
  toSign: string,
): string {
  return createHmac("sha256", signingKey(secretAccessKey, scope))
    .update(toSign, "utf8")
    .digest("hex");
}

/**
 * Constant-time signature comparison. Length is compared first because
 * `timingSafeEqual` throws on a length mismatch, and a mismatched length is
 * public information anyway — it means the value was not a signature.
 *
 * The comparison is **case-insensitive**, which is deliberate leniency rather
 * than an oversight: SigV4 signatures are lowercase hex, both sides here are
 * hex, and refusing an uppercase one would reject a correct signature over a
 * spelling difference that carries no information.
 */
export function signaturesMatch(expected: string, actual: string): boolean {
  const left = Buffer.from(expected.toLowerCase(), "utf8");
  const right = Buffer.from(actual.toLowerCase(), "utf8");
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

// ---------------------------------------------------------------------------
// timestamps
// ---------------------------------------------------------------------------

/** `YYYYMMDDTHHMMSSZ` — ISO 8601 basic format, which is what SigV4 uses. */
export function formatAmzDate(timestamp: number): string {
  /* `2015-08-30T12:36:00.000Z` becomes `20150830T123600Z`: the separators go,
     and so do the milliseconds, which SigV4 has no room for. */
  const iso = new Date(timestamp).toISOString();
  return `${iso.slice(0, 10).replaceAll("-", "")}T${iso.slice(11, 19).replaceAll(":", "")}Z`;
}

const AMZ_DATE = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/;

/**
 * Parse `YYYYMMDDTHHMMSSZ` to a millisecond epoch, or `undefined` if it is not
 * one. Round-tripped through `formatAmzDate()` so that a well-shaped but
 * impossible date (`20150230T...`, which `Date.UTC` would roll into March) is
 * refused rather than silently accepted.
 */
export function parseAmzDate(value: string): number | undefined {
  const match = AMZ_DATE.exec(value);
  if (match === null) {
    return undefined;
  }
  const timestamp = Date.UTC(
    Number(match[1]),
    Number(match[2]) - 1,
    Number(match[3]),
    Number(match[4]),
    Number(match[5]),
    Number(match[6]),
  );
  return formatAmzDate(timestamp) === value ? timestamp : undefined;
}

// ---------------------------------------------------------------------------
// parsing what the client sent
// ---------------------------------------------------------------------------

/** A parsed `Authorization: AWS4-HMAC-SHA256 ...` header. */
export interface AuthorizationHeader {
  algorithm: string;
  accessKeyId: string;
  scope: CredentialScope;
  signedHeaders: readonly string[];
  signature: string;
}

/** Split `<key>/<date>/<region>/<service>/aws4_request`. */
function parseCredential(
  value: string,
): { accessKeyId: string; scope: CredentialScope } | undefined {
  const parts = value.split("/");
  if (parts.length < 5) {
    return undefined;
  }
  const terminator = parts.at(-1);
  const service = parts.at(-2);
  const region = parts.at(-3);
  const date = parts.at(-4);
  const accessKeyId = parts.slice(0, -4).join("/");
  if (
    terminator !== SIGV4_TERMINATOR ||
    service === undefined ||
    region === undefined ||
    date === undefined ||
    accessKeyId === ""
  ) {
    return undefined;
  }
  return { accessKeyId, scope: { date, region, service } };
}

/**
 * Parse an `Authorization` header value, or answer `undefined` for anything
 * that is not one. Never throws — a malformed header is a refusal with a name,
 * not an exception (`AGENTS.md`: exactly one well-formed reply per request).
 */
export function parseAuthorizationHeader(value: string): AuthorizationHeader | undefined {
  const space = value.indexOf(" ");
  if (space === -1) {
    return undefined;
  }
  const algorithm = value.slice(0, space);
  const fields = new Map<string, string>();
  for (const field of value.slice(space + 1).split(",")) {
    const trimmed = field.trim();
    const equals = trimmed.indexOf("=");
    if (equals === -1) {
      return undefined;
    }
    fields.set(trimmed.slice(0, equals), trimmed.slice(equals + 1));
  }
  const credential = fields.get("Credential");
  const signedHeaders = fields.get("SignedHeaders");
  const signature = fields.get("Signature");
  if (credential === undefined || signedHeaders === undefined || signature === undefined) {
    return undefined;
  }
  const parsed = parseCredential(credential);
  if (parsed === undefined || signedHeaders === "" || signature === "") {
    return undefined;
  }
  return {
    algorithm,
    accessKeyId: parsed.accessKeyId,
    scope: parsed.scope,
    signedHeaders: signedHeaders.split(";"),
    signature,
  };
}

/** A parsed presigned query string. */
export interface PresignedQuery {
  algorithm: string;
  accessKeyId: string;
  scope: CredentialScope;
  signedHeaders: readonly string[];
  signature: string;
  /** The `X-Amz-Date` value, verbatim, as it goes into the string to sign. */
  amzDate: string;
  /** `X-Amz-Expires`, in seconds. */
  expiresIn: number;
}

/** First value for a query parameter, matched case-insensitively. */
function queryValue(query: readonly QueryEntry[], name: string): string | undefined {
  const wanted = name.toLowerCase();
  for (const entry of query) {
    if (entry.name.toLowerCase() === wanted) {
      return entry.value;
    }
  }
  return undefined;
}

/** First value for a header, matched case-insensitively. */
function headerValue(headers: readonly HeaderEntry[], name: string): string | undefined {
  for (const header of headers) {
    if (header.name.toLowerCase() === name) {
      return header.value;
    }
  }
  return undefined;
}

/** Is this request signed in the query string at all? */
export function isPresigned(query: readonly QueryEntry[]): boolean {
  return queryValue(query, QUERY_SIGNATURE) !== undefined;
}

/** Parse the six `X-Amz-*` parameters, or `undefined` if they do not add up. */
export function parsePresignedQuery(query: readonly QueryEntry[]): PresignedQuery | undefined {
  const algorithm = queryValue(query, QUERY_ALGORITHM);
  const credential = queryValue(query, QUERY_CREDENTIAL);
  const amzDate = queryValue(query, QUERY_DATE);
  const expires = queryValue(query, QUERY_EXPIRES);
  const signedHeaders = queryValue(query, QUERY_SIGNED_HEADERS);
  const signature = queryValue(query, QUERY_SIGNATURE);
  if (
    algorithm === undefined ||
    credential === undefined ||
    amzDate === undefined ||
    expires === undefined ||
    signedHeaders === undefined ||
    signature === undefined ||
    signedHeaders === "" ||
    signature === ""
  ) {
    return undefined;
  }
  const parsed = parseCredential(credential);
  if (parsed === undefined) {
    return undefined;
  }
  if (!/^\d{1,7}$/.test(expires)) {
    return undefined;
  }
  const expiresIn = Number(expires);
  if (expiresIn < 1 || expiresIn > MAX_PRESIGNED_EXPIRES) {
    return undefined;
  }
  return {
    algorithm,
    accessKeyId: parsed.accessKeyId,
    scope: parsed.scope,
    signedHeaders: signedHeaders.split(";"),
    signature,
    amzDate,
    expiresIn,
  };
}

// ---------------------------------------------------------------------------
// verification
// ---------------------------------------------------------------------------

/**
 * Why a request was refused. Every one of these is a name the caller can turn
 * into an S3 error code without inspecting a message.
 */
export type SigV4RefusalReason =
  | "missing"
  | "malformed"
  | "unsupported-algorithm"
  | "unknown-access-key"
  | "scope-mismatch"
  | "clock-skew"
  | "expired"
  | "signature-mismatch";

/** A request whose signature checked out. */
export interface SigV4Verified {
  ok: true;
  /** Which form carried the signature. */
  form: "header" | "presigned";
  accessKeyId: string;
  scope: CredentialScope;
  /** Canonicalized: lowercase, sorted, deduplicated. */
  signedHeaders: readonly string[];
  /** The payload hash that was signed, verbatim. */
  payloadHash: string;
  /** The signing time, as a millisecond epoch. */
  timestamp: number;
}

/** A request that was not accepted, and the named reason. */
export interface SigV4Refused {
  ok: false;
  reason: SigV4RefusalReason;
  /** Safe to log and safe to return: never contains a secret or a signature. */
  detail: string;
}

export type SigV4Result = SigV4Verified | SigV4Refused;

/** What `verifyRequest()` needs to know about the request and the server. */
export interface VerifyRequestInput {
  method: string;
  /** The **percent-decoded** request path (see the module docs). */
  path: string;
  /** Percent-decoded query parameters, in wire order. */
  query: readonly QueryEntry[];
  /** Headers in wire order, repeats included. */
  headers: readonly HeaderEntry[];
  /** The one credential pair this gateway was configured with. */
  credentials: SigV4Credentials;
  /**
   * The current time in milliseconds. Required, and never read from the clock
   * here: the server passes `Date.now()`, the tests pass whatever they mean.
   */
  now: number;
  /**
   * Region the credential scope must name. Omitted means any region is
   * accepted, which is what an S3-compatible gateway wants — clients pick a
   * region out of the air and there is nothing here for it to select.
   */
  region?: string;
  /** Service the scope must name. Defaults to `s3`. */
  service?: string;
  /** Clock-skew window for the header form. Defaults to `MAX_CLOCK_SKEW_MS`. */
  skewMs?: number;
}

function refuse(reason: SigV4RefusalReason, detail: string): SigV4Refused {
  return { ok: false, reason, detail };
}

/** Longest run of client-supplied text a refusal `detail` will repeat. */
const MAX_DETAIL_CHARS = 64;

/**
 * Client-supplied text, made fit to appear in a `detail`: control characters
 * replaced — a newline in a log line is somebody else's forged log entry — and
 * the whole thing bounded, since every string quoted below arrives from the
 * request and none of them has a length the client cannot choose.
 *
 * `SigV4Refused.detail` promises to be safe to log and safe to return. A
 * promise about a string every later step will pass along has to be kept where
 * the string is built.
 */
function quote(value: string): string {
  let printable = "";
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    printable += code < 0x20 || code === 0x7f ? "?" : character;
  }
  return printable.length <= MAX_DETAIL_CHARS
    ? printable
    : `${printable.slice(0, MAX_DETAIL_CHARS)}...`;
}

/** The scope checks both forms share. */
function checkScope(
  input: VerifyRequestInput,
  accessKeyId: string,
  scope: CredentialScope,
  amzDate: string,
): SigV4Refused | undefined {
  if (accessKeyId !== input.credentials.accessKeyId) {
    return refuse("unknown-access-key", `no such access key id: ${quote(accessKeyId)}`);
  }
  const service = input.service ?? S3_SERVICE;
  if (scope.service !== service) {
    return refuse("scope-mismatch", `credential scope names service ${quote(scope.service)}`);
  }
  if (input.region !== undefined && scope.region !== input.region) {
    return refuse("scope-mismatch", `credential scope names region ${quote(scope.region)}`);
  }
  if (scope.date !== amzDate.slice(0, 8)) {
    return refuse(
      "scope-mismatch",
      `credential scope date ${quote(scope.date)} is not the request date`,
    );
  }
  return undefined;
}

/**
 * Verify a signed request, in whichever form it arrived. Never throws, and
 * never reads the clock — `input.now` is the only time it knows.
 *
 * **The compatibility boundary: `x-amz-date` is required in header form.**
 * SigV4 also allows the timestamp to come from a plain `Date` header, and this
 * does not implement that: the string to sign would then need the ISO 8601
 * basic rendering of an RFC 1123 date, there is no vector in the official suite
 * for it, and a signing rule reconstructed from prose rather than transcribed
 * is the kind of thing that fails in production and nowhere else. Every AWS
 * SDK, rclone and curl's own signer send `x-amz-date`, so what this refuses is
 * a signer nobody ships — and it refuses it as a named `malformed`, not as a
 * signature mismatch that would send the reader hunting for the wrong bug.
 */
export function verifyRequest(input: VerifyRequestInput): SigV4Result {
  if (isPresigned(input.query)) {
    return verifyPresigned(input);
  }
  const authorization = headerValue(input.headers, HEADER_AUTHORIZATION);
  if (authorization === undefined) {
    return refuse("missing", "no Authorization header and no X-Amz-Signature parameter");
  }
  return verifyHeaderForm(input, authorization);
}

function verifyHeaderForm(input: VerifyRequestInput, authorization: string): SigV4Result {
  const parsed = parseAuthorizationHeader(authorization);
  if (parsed === undefined) {
    return refuse("malformed", "Authorization header is not a SigV4 credential");
  }
  if (parsed.algorithm !== SIGV4_ALGORITHM) {
    return refuse("unsupported-algorithm", `unsupported algorithm ${quote(parsed.algorithm)}`);
  }
  const amzDate = headerValue(input.headers, HEADER_DATE);
  if (amzDate === undefined) {
    return refuse("malformed", "missing x-amz-date");
  }
  const timestamp = parseAmzDate(amzDate);
  if (timestamp === undefined) {
    return refuse("malformed", "x-amz-date is not an ISO 8601 basic timestamp");
  }
  const scopeRefusal = checkScope(input, parsed.accessKeyId, parsed.scope, amzDate);
  if (scopeRefusal !== undefined) {
    return scopeRefusal;
  }
  const skewMs = input.skewMs ?? MAX_CLOCK_SKEW_MS;
  if (Math.abs(input.now - timestamp) > skewMs) {
    return refuse("clock-skew", `x-amz-date ${quote(amzDate)} is outside the ${skewMs} ms window`);
  }
  /* S3 requires the payload hash as a header on every SigV4 header-form
     request, and there is nothing to substitute: the value is part of the
     canonical request, so guessing it would only produce a mismatch with a
     misleading name. */
  const payloadHash = headerValue(input.headers, HEADER_CONTENT_SHA256);
  if (payloadHash === undefined) {
    return refuse("malformed", "missing x-amz-content-sha256");
  }
  return check(input, {
    form: "header",
    accessKeyId: parsed.accessKeyId,
    scope: parsed.scope,
    signedHeaders: parsed.signedHeaders,
    signature: parsed.signature,
    amzDate,
    timestamp,
    payloadHash,
    query: input.query,
  });
}

function verifyPresigned(input: VerifyRequestInput): SigV4Result {
  const parsed = parsePresignedQuery(input.query);
  if (parsed === undefined) {
    return refuse("malformed", "presigned query is missing or malformed X-Amz-* parameters");
  }
  if (parsed.algorithm !== SIGV4_ALGORITHM) {
    return refuse("unsupported-algorithm", `unsupported algorithm ${quote(parsed.algorithm)}`);
  }
  const timestamp = parseAmzDate(parsed.amzDate);
  if (timestamp === undefined) {
    return refuse("malformed", "X-Amz-Date is not an ISO 8601 basic timestamp");
  }
  const scopeRefusal = checkScope(input, parsed.accessKeyId, parsed.scope, parsed.amzDate);
  if (scopeRefusal !== undefined) {
    return scopeRefusal;
  }
  const skewMs = input.skewMs ?? MAX_CLOCK_SKEW_MS;
  if (timestamp - input.now > skewMs) {
    return refuse("clock-skew", `X-Amz-Date ${quote(parsed.amzDate)} is in the future`);
  }
  if (input.now > timestamp + parsed.expiresIn * 1000) {
    return refuse(
      "expired",
      `presigned URL expired ${parsed.expiresIn} s after ${quote(parsed.amzDate)}`,
    );
  }
  /* A presigned URL signs `UNSIGNED-PAYLOAD` unless the request also carries
     `x-amz-content-sha256`, in which case that is the value it signed. Either
     way the hash is covered by the signature, so taking it verbatim is safe —
     and it is what makes `presignRequest({ payloadHash })` round-trip. */
  const payloadHash = headerValue(input.headers, HEADER_CONTENT_SHA256) ?? UNSIGNED_PAYLOAD;
  return check(input, {
    form: "presigned",
    accessKeyId: parsed.accessKeyId,
    scope: parsed.scope,
    signedHeaders: parsed.signedHeaders,
    signature: parsed.signature,
    amzDate: parsed.amzDate,
    timestamp,
    payloadHash,
    /* The signature parameter cannot cover itself. */
    query: input.query.filter(
      (entry) => entry.name.toLowerCase() !== QUERY_SIGNATURE.toLowerCase(),
    ),
  });
}

interface CheckInput {
  form: "header" | "presigned";
  accessKeyId: string;
  scope: CredentialScope;
  signedHeaders: readonly string[];
  signature: string;
  amzDate: string;
  timestamp: number;
  payloadHash: string;
  query: readonly QueryEntry[];
}

/** The last step both forms share: rebuild the signature and compare. */
function check(input: VerifyRequestInput, parsed: CheckInput): SigV4Result {
  const signedHeaders = canonicalSignedHeaders(parsed.signedHeaders);
  const canonical = canonicalRequest({
    method: input.method,
    path: input.path,
    query: parsed.query,
    headers: input.headers,
    signedHeaders,
    payloadHash: parsed.payloadHash,
  });
  const expected = signatureOf(
    input.credentials.secretAccessKey,
    parsed.scope,
    stringToSign(parsed.amzDate, parsed.scope, canonical),
  );
  if (!signaturesMatch(expected, parsed.signature)) {
    return refuse("signature-mismatch", "the request signature does not match");
  }
  return {
    ok: true,
    form: parsed.form,
    accessKeyId: parsed.accessKeyId,
    scope: parsed.scope,
    signedHeaders,
    payloadHash: parsed.payloadHash,
    timestamp: parsed.timestamp,
  };
}

// ---------------------------------------------------------------------------
// signing
// ---------------------------------------------------------------------------

/** What both signing entry points need. */
export interface SignRequestInput {
  method: string;
  /** The **percent-decoded** request path (see the module docs). */
  path: string;
  /** Percent-decoded query parameters. Order does not matter. */
  query?: readonly QueryEntry[];
  headers: readonly HeaderEntry[];
  credentials: SigV4Credentials;
  region: string;
  /** Defaults to `s3`. */
  service?: string;
  /** A millisecond epoch, or an `x-amz-date` string already in wire form. */
  timestamp: number | string;
  /** Defaults to every header name in `headers`. */
  signedHeaders?: readonly string[];
}

/** A signed request, with the intermediate stages kept for the goldens. */
export interface SignedRequest {
  amzDate: string;
  scope: CredentialScope;
  signedHeaders: readonly string[];
  canonicalRequest: string;
  stringToSign: string;
  signature: string;
}

/** Everything `signRequest()` returns, plus the header to send it in. */
export interface SignedHeaderRequest extends SignedRequest {
  /** The `Authorization` header value. */
  authorization: string;
}

/** Everything `presignRequest()` returns, plus the query to send it in. */
export interface PresignedRequest extends SignedRequest {
  expiresIn: number;
  /** The full query — the caller's parameters, the six `X-Amz-*`, and the
   * signature — ready to hand straight back to `verifyRequest()`. */
  query: QueryEntry[];
}

function amzDateOf(timestamp: number | string): string {
  return typeof timestamp === "string" ? timestamp : formatAmzDate(timestamp);
}

function scopeOf(input: SignRequestInput, amzDate: string): CredentialScope {
  return {
    date: amzDate.slice(0, 8),
    region: input.region,
    service: input.service ?? S3_SERVICE,
  };
}

function defaultSignedHeaders(input: SignRequestInput): string[] {
  return canonicalSignedHeaders(input.signedHeaders ?? input.headers.map((header) => header.name));
}

/** The `Credential=` value: an access key id joined to the scope it signs in. */
export function credentialOf(accessKeyId: string, scope: CredentialScope): string {
  return `${accessKeyId}/${credentialScope(scope)}`;
}

/**
 * Sign a request in header form. The counterpart of `verifyRequest()`, and the
 * signer the Tier-1 client uses.
 */
export function signRequest(
  input: SignRequestInput & { payloadHash: string },
): SignedHeaderRequest {
  const amzDate = amzDateOf(input.timestamp);
  const scope = scopeOf(input, amzDate);
  const credential = credentialOf(input.credentials.accessKeyId, scope);
  const signedHeaders = defaultSignedHeaders(input);
  const canonical = canonicalRequest({
    method: input.method,
    path: input.path,
    query: input.query ?? [],
    headers: input.headers,
    signedHeaders,
    payloadHash: input.payloadHash,
  });
  const toSign = stringToSign(amzDate, scope, canonical);
  const signature = signatureOf(input.credentials.secretAccessKey, scope, toSign);
  return {
    amzDate,
    scope,
    signedHeaders,
    canonicalRequest: canonical,
    stringToSign: toSign,
    signature,
    authorization:
      `${SIGV4_ALGORITHM} Credential=${credential}, ` +
      `SignedHeaders=${signedHeaders.join(";")}, Signature=${signature}`,
  };
}

/**
 * Sign a request in presigned-query form. The payload hash defaults to
 * `UNSIGNED-PAYLOAD`, which is what a presigned URL carries in practice: the
 * body, if there is one, is not known when the URL is minted.
 *
 * **Where a non-default `payloadHash` has to come back from.** Nothing in the
 * query records it — there is no `X-Amz-Content-Sha256` parameter, only a
 * header of that name — so a verifier can only recover it from the request the
 * URL is finally used on. `verifyRequest()` does exactly that: it reads
 * `x-amz-content-sha256` and falls back to `UNSIGNED-PAYLOAD`. So a URL signed
 * with a body hash round-trips **only if the request carries that same header**,
 * and otherwise answers `signature-mismatch`. That is AWS's behavior rather
 * than a limitation here, and both halves of it are pinned in
 * `test/s3/sigv4.test.ts`. Leave the option alone unless you are signing a
 * request that will send the header too.
 */
export function presignRequest(
  input: SignRequestInput & { expiresIn: number; payloadHash?: string },
): PresignedRequest {
  const amzDate = amzDateOf(input.timestamp);
  const scope = scopeOf(input, amzDate);
  const signedHeaders = defaultSignedHeaders(input);
  const query: QueryEntry[] = [
    ...(input.query ?? []),
    { name: QUERY_ALGORITHM, value: SIGV4_ALGORITHM },
    { name: QUERY_CREDENTIAL, value: credentialOf(input.credentials.accessKeyId, scope) },
    { name: QUERY_DATE, value: amzDate },
    { name: QUERY_EXPIRES, value: String(input.expiresIn) },
    { name: QUERY_SIGNED_HEADERS, value: signedHeaders.join(";") },
  ];
  const canonical = canonicalRequest({
    method: input.method,
    path: input.path,
    query,
    headers: input.headers,
    signedHeaders,
    payloadHash: input.payloadHash ?? UNSIGNED_PAYLOAD,
  });
  const toSign = stringToSign(amzDate, scope, canonical);
  const signature = signatureOf(input.credentials.secretAccessKey, scope, toSign);
  return {
    amzDate,
    scope,
    signedHeaders,
    expiresIn: input.expiresIn,
    canonicalRequest: canonical,
    stringToSign: toSign,
    signature,
    query: [...query, { name: QUERY_SIGNATURE, value: signature }],
  };
}
