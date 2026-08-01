/**
 * WebDAV's wire, with no driver and no socket: request lines and headers in,
 * XML documents and refusals out.
 *
 * Everything here is pure and total. `session.ts` decides what an operation
 * *means*; this file decides what the bytes said and what the bytes will say —
 * the `Depth`, `Overwrite`, `Destination`, `Timeout`, `Lock-Token` and `If`
 * headers, the URL ↔ driver-path mapping in both directions, the three request
 * grammars, and the `multistatus`, `error` and lock documents. Sources are
 * **RFC 4918** for the DAV parts and **RFC 9110** for the HTTP ones, named at
 * the rule they justify.
 *
 * The one header with a grammar of its own rather than a value is `If`
 * (§10.4.2): a disjunction of conjunctions over lock tokens and entity tags,
 * each optionally about some *other* resource. {@link parseIf} takes it apart
 * and nothing more — whether a condition is true needs a driver and a lock
 * table, so `session.ts` evaluates what this file parsed.
 *
 * ## Namespaces, and the one place they are read
 *
 * Documents go out with `DAV:` as the **default** namespace —
 * `<multistatus xmlns="DAV:">` with unprefixed children — rather than with the
 * `D:` prefix RFC 4918's examples use. The two are the same document to a
 * namespace-aware parser (§14 binds names to the namespace, never to a prefix),
 * and the default form is what the shared encoder produces without a second
 * spelling of every element name. An element in another namespace — a property
 * this server does not have, an `<owner>` written under someone else's prefix —
 * re-declares as it is written, so the pair goes back out as it came in.
 *
 * Coming in, the split is deliberate and it is not symmetric:
 *
 * - **A property name is read as the pair** it is, {@link DavPropertyName}, and
 *   both halves decide which property was named. This is the whole of §4:
 *   `getlastmodified` in `DAV:` is this server's, and the same local name in
 *   `urn:schemas-microsoft-com:` — which is what Finder and Explorer send — is
 *   a property it does not have. Answering the second with the first's value
 *   would be answering a question nobody asked, and on `PROPPATCH` it would be
 *   a *write* decided by a misread name.
 * - **Every structural element is read by local name alone**, and its namespace
 *   is not checked: `<propfind>`, `<prop>`, `<set>`, `<lockinfo>`, `<exclusive>`
 *   and the rest. They carry no identity to confuse — a `<propfind>` body
 *   arriving on a `PROPFIND` is the document it says it is — so checking would
 *   buy nothing and would newly refuse the clients that send these grammars
 *   with no declaration at all, which is a thing clients do.
 */

import { normalizePath, splitPath } from "../path.ts";
import { parseXml, XmlError, xmlDocument, type XmlNode } from "../xml.ts";
import { DAV_NS, MAX_XML_BYTES, statusLine, statusOf, XML_CONTENT_TYPE } from "./constants.ts";
import { DavLockTable, type DavLock } from "./locks.ts";

// ---------------------------------------------------------------------------
// the request and the reply
// ---------------------------------------------------------------------------

/**
 * One request, as the transport hands it over.
 *
 * Headers are **lowercased, single-valued and already combined** — the shape
 * `node:http` hands out — which the S3 gateway deliberately cannot use (SigV4
 * signs headers as they were sent) and WebDAV has no reason not to: nothing
 * here is signed, and every header this protocol defines is a single value.
 */
export interface WebdavRequestHead {
  /** The HTTP method, uppercase. */
  method: string;
  /** The raw request target: `/a/b%20c`, still percent-encoded. */
  target: string;
  /** Lowercase header names to their single combined value. */
  headers: Readonly<Record<string, string | undefined>>;
}

/**
 * A reply, before it reaches a socket.
 *
 * The body may be bytes, an async stream of them (a `GET`), or absent (a `204`,
 * or any `HEAD`). Same shape and same reasoning as `S3StreamResponse`: a `GET`
 * of a 5 GiB file is not a document to be built in memory.
 */
export interface WebdavResponse {
  status: number;
  /** Lowercase header names, single values. */
  headers: Record<string, string>;
  body?: Uint8Array | AsyncIterable<Uint8Array>;
}

/**
 * An empty request body, for a method that has none.
 *
 * Written as an iterator rather than an empty `async function*` for the same
 * reason `src/s3/session.ts` writes its own that way: a generator that never
 * yields has a lint rule to answer to, and this has nothing to say.
 */
export const NO_BODY: AsyncIterable<Uint8Array> = {
  [Symbol.asyncIterator]: () => ({
    next: async () => ({ done: true as const, value: undefined }),
  }),
};

// ---------------------------------------------------------------------------
// refusals
// ---------------------------------------------------------------------------

/**
 * A refusal thrown from inside an operation, for the one reply to render.
 *
 * The WebDAV twin of `src/s3/session.ts`'s `S3ErrorThrown`, and it exists for
 * the same reason: a refusal is often several calls deep, and the
 * exactly-one-reply discipline (`AGENTS.md`, invariant 9) is kept by the single
 * catch in `WebdavSession.handleRequest` rather than by threading a result type
 * through every helper.
 *
 * `condition` is a RFC 4918 §16 precondition/postcondition element name, which
 * is the machine-readable half of a refusal: `403` alone says "no", and
 * `403` with `propfind-finite-depth` says which rule was broken.
 */
export class DavFault extends Error {
  readonly code = "ERR_WEBDAV_FAULT";
  readonly status: number;
  /** A §16 condition element name, rendered inside `<error>`. */
  readonly condition: string | undefined;
  /**
   * `href` children of the condition element.
   *
   * Two of §16's conditions carry them, and one *requires* one:
   * `lock-token-submitted` "MUST contain at least one URL of a locked resource
   * that prevented the request", and `no-conflicting-lock` may name the root of
   * the lock that stopped a `LOCK`. Both spare the client a `PROPFIND` for
   * `lockdiscovery` to find out which resource it was.
   */
  readonly hrefs: readonly string[];
  /** Extra headers the refusal carries (`Allow`, `Content-Range`). */
  readonly headers: Record<string, string>;

  constructor(
    status: number,
    options: {
      condition?: string;
      hrefs?: readonly string[];
      message?: string;
      headers?: Record<string, string>;
    } = {},
  ) {
    super(options.message ?? statusLine(status));
    this.name = "DavFault";
    this.status = status;
    this.condition = options.condition;
    this.hrefs = options.hrefs ?? [];
    this.headers = options.headers ?? {};
  }
}

/** Is this a {@link DavFault}? */
export function isDavFault(error: unknown): error is DavFault {
  return error instanceof DavFault;
}

/** Shorthand for `throw refuse(409)` at the call sites that read better that way. */
export function refuse(
  status: number,
  options?: {
    condition?: string;
    hrefs?: readonly string[];
    message?: string;
    headers?: Record<string, string>;
  },
): DavFault {
  return new DavFault(status, options);
}

/**
 * The status a thrown value becomes.
 *
 * A {@link DavFault} carries its own; a driver error is looked up by errno
 * (`constants.ts`); anything else is `500`, because an error this server cannot
 * name is this server's fault.
 */
export function statusOfError(error: unknown): number {
  if (isDavFault(error)) {
    return error.status;
  }
  if (typeof error === "object" && error !== null) {
    const code = (error as { code?: unknown }).code;
    return statusOf(typeof code === "string" ? code : undefined);
  }
  return statusOf(undefined);
}

/**
 * Render a refusal as a reply.
 *
 * A refusal with a §16 condition gets an `<error>` document, because that is
 * the only way the condition reaches the client; one without gets **no body at
 * all**. Deliberately not a prose page: a body a client will not read is a body
 * that has to be framed, and `Content-Length: 0` is unambiguous for every
 * method including `HEAD`.
 */
export function faultResponse(error: unknown): WebdavResponse {
  const status = statusOfError(error);
  const condition = isDavFault(error) ? error.condition : undefined;
  const extra = isDavFault(error) ? error.headers : {};
  if (condition === undefined) {
    return { status, headers: { ...extra, "content-length": "0" } };
  }
  const hrefs = isDavFault(error) ? error.hrefs : [];
  return xmlBody(status, encodeErrorDocument(condition, hrefs), extra);
}

/** An XML document as a reply, with the length and content type it needs. */
export function xmlBody(
  status: number,
  document: string,
  extra: Record<string, string> = {},
): WebdavResponse {
  const body = Buffer.from(document, "utf8");
  return {
    status,
    headers: {
      ...extra,
      "content-type": XML_CONTENT_TYPE,
      "content-length": String(body.byteLength),
    },
    body,
  };
}

// ---------------------------------------------------------------------------
// paths and hrefs
// ---------------------------------------------------------------------------

/**
 * A request target as a driver path.
 *
 * The path is percent-decoded **per segment** and then normalized, which is the
 * difference from the S3 gateway's decode-the-whole-path-once rule and it is
 * the right one here: S3 keys really can contain a `/` (a key *is* a prefix),
 * a POSIX name cannot, so a `%2F` inside a segment is not a separator and not a
 * name — it is a request this server has no resource for, and it is refused
 * rather than quietly read as a directory boundary.
 *
 * Refused with `400`: a malformed escape, a decoded segment holding a `/` or a
 * NUL, and a target that is not a path at all. `.` and `..` are resolved by
 * `normalizePath`, which clamps at the root — there is no traversal out of the
 * driver, by construction rather than by check.
 *
 * The query string is dropped: no method here defines one, and a client that
 * appends `?` is asking for the same resource.
 *
 * @throws {DavFault} `400` for anything that is not a resolvable path.
 */
export function parseTargetPath(target: string): string {
  const withoutQuery = target.split("?", 1)[0] as string;
  const withoutFragment = withoutQuery.split("#", 1)[0] as string;
  if (!withoutFragment.startsWith("/")) {
    throw refuse(400, { message: `the request target ${target} is not an absolute path` });
  }
  const decoded: string[] = [];
  for (const raw of withoutFragment.split("/")) {
    if (raw === "") {
      continue;
    }
    const segment = decodeSegment(raw);
    if (segment === undefined || segment.includes("/") || segment.includes("\0")) {
      throw refuse(400, { message: `the request target ${target} does not name a resource` });
    }
    decoded.push(segment);
  }
  return normalizePath(`/${decoded.join("/")}`);
}

/** Percent-decode one segment, or `undefined` for a malformed escape. */
function decodeSegment(value: string): string | undefined {
  if (!value.includes("%")) {
    return value;
  }
  try {
    return decodeURIComponent(value);
  } catch {
    /* `decodeURIComponent` throws `URIError` for `%`, `%zz` and for an escape
       sequence that is not valid UTF-8. All three are a malformed target. */
    return undefined;
  }
}

/**
 * A driver path as the `href` that names it (RFC 4918 §8.3).
 *
 * Each segment is percent-encoded on its own, so a name containing a `/` — which
 * this server never produces, but a driver could hand back — cannot become two
 * segments. A collection's href ends in `/`, which §5.2 recommends and several
 * clients rely on to tell a collection from a resource before reading
 * `resourcetype`.
 */
export function hrefOf(path: string, collection: boolean): string {
  const segments = splitPath(path).map((segment) => encodeURIComponent(segment));
  const href = `/${segments.join("/")}`;
  return collection && !href.endsWith("/") ? `${href}/` : href;
}

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

/** What a `Depth` header can say (RFC 4918 §10.2). */
export type Depth = 0 | 1 | "infinity";

/**
 * Parse `Depth`, with the default this method applies when the header is
 * absent.
 *
 * `undefined` — the invalid case — is a `400`, and it is separate from "absent"
 * on purpose: §10.2 gives every method a default, and a client that *sent*
 * `Depth: 2` sent something the protocol has no meaning for.
 */
export function parseDepth(value: string | undefined, fallback: Depth): Depth | undefined {
  if (value === undefined) {
    return fallback;
  }
  const depth = value.trim().toLowerCase();
  if (depth === "0") {
    return 0;
  }
  if (depth === "1") {
    return 1;
  }
  return depth === "infinity" ? "infinity" : undefined;
}

/**
 * Parse `Overwrite` (RFC 4918 §10.6): `T` or `F`, defaulting to `T`.
 *
 * `undefined` for anything else, which the caller answers `400`.
 */
export function parseOverwrite(value: string | undefined): boolean | undefined {
  if (value === undefined) {
    return true;
  }
  const flag = value.trim().toUpperCase();
  if (flag === "T") {
    return true;
  }
  return flag === "F" ? false : undefined;
}

/**
 * The `Destination` header as a driver path (RFC 4918 §10.3).
 *
 * §10.3 requires an absolute URI, and clients send one — but an absolute *path*
 * is what several of them send instead, and it names the same resource on the
 * same origin, so both are accepted. What is **not** accepted is a destination
 * on another host: §9.9.4 gives that `502`, and answering anything else would
 * mean this server copying a resource somewhere it does not serve.
 *
 * `host` is the request's `Host` header. A request that arrived without one
 * (HTTP/1.0) cannot have its destination's authority checked, so a destination
 * carrying one is refused rather than assumed to be local.
 *
 * @throws {DavFault} `400` for a missing or unparseable header, `502` for
 * another origin.
 */
export function parseDestination(value: string | undefined, host: string | undefined): string {
  if (value === undefined || value.trim() === "") {
    throw refuse(400, { message: "the Destination header is required" });
  }
  const destination = value.trim();
  if (destination.startsWith("/")) {
    return parseTargetPath(destination);
  }
  let url: URL;
  try {
    url = new URL(destination);
  } catch {
    throw refuse(400, { message: `the Destination header ${destination} is not a URI` });
  }
  if (url.host === "" || host === undefined || url.host.toLowerCase() !== host.toLowerCase()) {
    throw refuse(502, {
      message: `the Destination ${destination} is not on this server`,
    });
  }
  return parseTargetPath(url.pathname);
}

/**
 * Parse `Timeout` (RFC 4918 §10.7): `Second-<n>` or `Infinite`, as a
 * comma-separated list in the client's order of preference.
 *
 * ```
 * TimeOut = "Timeout" ":" 1#TimeType
 * TimeType = ("Second-" DAVTimeOutVal | "Infinite")
 * DAVTimeOutVal = 1*DIGIT
 * ```
 *
 * **Only the first entry is read**, and that is a policy rather than a
 * shortcut: this server clamps whatever it is asked for into its own range
 * (`DavLockTable`) instead of refusing values it will not grant, so there is
 * never a second entry to fall back to. `Timeout: Infinite, Second-4100000000`
 * — the header §9.10.7's own example sends — therefore lands on `Infinite` and
 * gets the server's maximum, which is what that example's server does with it
 * too.
 *
 * `undefined` for an absent header **and** for one that does not parse: §6.6
 * makes the value a suggestion the server may ignore entirely, so a malformed
 * suggestion is one more thing to ignore, not a request to refuse. A value past
 * `2^32-1` — which §10.7 forbids — is read as the number it is and clamped by
 * the table like any other.
 */
export function parseTimeout(value: string | undefined): number | "infinite" | undefined {
  if (value === undefined) {
    return undefined;
  }
  const first = (value.split(",", 1)[0] as string).trim();
  if (first.toLowerCase() === "infinite") {
    return "infinite";
  }
  const seconds = /^[Ss]econd-(\d+)$/.exec(first);
  return seconds === null ? undefined : Number(seconds[1]);
}

/**
 * The token inside a `Lock-Token` header (RFC 4918 §10.5): a Coded-URL,
 * `<urn:uuid:…>`, angle brackets and all.
 *
 * `undefined` for an absent header and for anything that is not a Coded-URL —
 * `UNLOCK` answers `400` for both, which §9.11.1 spells out ("400 (Bad
 * Request) - No lock token was provided"), because a token this server cannot
 * read is a token it cannot delete.
 */
export function parseLockToken(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const coded = /^<([^<>]+)>$/.exec(value.trim());
  return coded === null ? undefined : (coded[1] as string);
}

/** A token as the `Lock-Token` **response** header wants it: `<urn:uuid:…>`. */
export function formatLockToken(token: string): string {
  return `<${token}>`;
}

// ---------------------------------------------------------------------------
// the If header
// ---------------------------------------------------------------------------

/**
 * One `Condition` of an `If` header (RFC 4918 §10.4.2): a state token or an
 * entity tag, optionally negated.
 *
 * Exactly one of {@link IfCondition.token} and {@link IfCondition.etag} is
 * present — the grammar has no third form, and a `Condition` is one or the
 * other.
 */
export interface IfCondition {
  /** `Not` was in front of it, so the condition is the negation (§10.4.3). */
  negated: boolean;
  /** A `State-token`: the URI inside `<…>`, without the brackets. */
  token?: string;
  /** An entity tag as sent, quotes and any `W/` kept: `"abc"`, `W/"abc"`. */
  etag?: string;
}

/**
 * One `List` of an `If` header, with the resource it is about.
 *
 * A list is a conjunction of its conditions, and the header is a disjunction of
 * its lists (§10.4.3) — so this array is `OR` over `AND`.
 */
export interface IfList {
  /**
   * The driver path this list is about: the `Resource-Tag`'s, or `undefined`
   * for an untagged list, which is about the request URI (§10.4.2).
   */
  resource: string | undefined;
  /**
   * The tag named a resource this server does not serve — another origin, or a
   * target that is not a path.
   *
   * Not a refusal: §10.4.4's "handling unmapped URLs" rule says to treat a URL
   * with no resource as one that exists and has none of the state asked about,
   * and a URL on somebody else's server is that case as far as this one can
   * tell. So every plain condition against it is false and every negated one is
   * true — which is exactly what a client using `<DAV:no-lock>` is relying on.
   */
  foreign: boolean;
  conditions: IfCondition[];
}

/**
 * Parse an `If` header into its lists (RFC 4918 §10.4.2).
 *
 * ```
 * If = "If" ":" ( 1*No-tag-list | 1*Tagged-list )
 * No-tag-list = List
 * Tagged-list = Resource-Tag 1*List
 * List = "(" 1*Condition ")"
 * Condition = ["Not"] (State-token | "[" entity-tag "]")
 * State-token = Coded-URL
 * Resource-Tag = "<" Simple-ref ">"
 * ```
 *
 * A `Resource-Tag` applies to every list after it until the next one, so the
 * tag is carried forward rather than attached once. **Tagged and untagged lists
 * are accepted in the same header** even though §10.4.2 says they cannot be
 * mixed: the same section explains why that costs nothing — "the No-tag-list
 * syntax is just a shorthand notation for a Tagged-list production with a
 * Resource-Tag referring to the Request-URI" — so a mixed header has one
 * unambiguous reading, and refusing it would buy strictness with interop.
 *
 * `host` is the request's `Host` header, used exactly as
 * {@link parseDestination} uses it: a tag naming another authority is
 * {@link IfList.foreign} rather than an error.
 *
 * `undefined` for a header that is not this grammar at all — an unbalanced
 * `(`, a `<` with no `>`, a condition outside any list. The session answers
 * `400`: §10.4 gives the header one syntax, and a header this server cannot
 * read is one it cannot honour, which is the opposite of the `412` it would
 * mean by guessing.
 */
export function parseIf(value: string, host: string | undefined): IfList[] | undefined {
  const lists: IfList[] = [];
  let tag: { resource: string | undefined; foreign: boolean } | undefined;
  let at = 0;
  while (at < value.length) {
    const character = value[at] as string;
    if (/\s/.test(character)) {
      at++;
      continue;
    }
    if (character === "<") {
      /* At this depth a Coded-URL is a Resource-Tag; a state token only ever
         appears inside a list, which the `(` branch consumes whole. */
      const close = value.indexOf(">", at + 1);
      if (close === -1) {
        return undefined;
      }
      tag = resourceTag(value.slice(at + 1, close), host);
      at = close + 1;
      continue;
    }
    if (character !== "(") {
      return undefined;
    }
    const list = parseIfList(value, at);
    if (list === undefined) {
      return undefined;
    }
    lists.push({
      resource: tag?.resource,
      foreign: tag?.foreign ?? false,
      conditions: list.conditions,
    });
    at = list.at;
  }
  return lists.length === 0 ? undefined : lists;
}

/**
 * A `Resource-Tag`'s URI as a driver path.
 *
 * `Simple-ref` (§8.3) is an absolute URI or an absolute path, which is the same
 * pair {@link parseDestination} accepts — and the same reasoning applies to
 * both, with one difference in the answer: a `Destination` on another host is a
 * `502` because this server would have to write there, while an `If` tag on
 * another host is merely a resource whose state this server cannot know
 * (§10.4.4).
 */
function resourceTag(
  reference: string,
  host: string | undefined,
): { resource: string | undefined; foreign: boolean } {
  const trimmed = reference.trim();
  try {
    if (trimmed.startsWith("/")) {
      return { resource: parseTargetPath(trimmed), foreign: false };
    }
    const url = new URL(trimmed);
    if (url.host === "" || host === undefined || url.host.toLowerCase() !== host.toLowerCase()) {
      return { resource: undefined, foreign: true };
    }
    return { resource: parseTargetPath(url.pathname), foreign: false };
  } catch {
    /* An unparseable URI, or a path this server has no resource for
       (`parseTargetPath`'s `400`). Either way it names nothing here. */
    return { resource: undefined, foreign: true };
  }
}

/** One `"(" 1*Condition ")"`, from the `(` at `start`. */
function parseIfList(
  value: string,
  start: number,
): { conditions: IfCondition[]; at: number } | undefined {
  const conditions: IfCondition[] = [];
  let at = start + 1;
  let negated = false;
  while (at < value.length) {
    const character = value[at] as string;
    if (/\s/.test(character)) {
      at++;
      continue;
    }
    if (character === ")") {
      // A list must hold at least one condition: `1*Condition`.
      return conditions.length === 0 ? undefined : { conditions, at: at + 1 };
    }
    if (value.slice(at, at + 3).toLowerCase() === "not") {
      negated = true;
      at += 3;
      continue;
    }
    if (character === "<") {
      const close = value.indexOf(">", at + 1);
      if (close === -1) {
        return undefined;
      }
      conditions.push({ negated, token: value.slice(at + 1, close).trim() });
      negated = false;
      at = close + 1;
      continue;
    }
    if (character !== "[") {
      return undefined;
    }
    const close = entityTagEnd(value, at + 1);
    if (close === -1) {
      return undefined;
    }
    conditions.push({ negated, etag: value.slice(at + 1, close).trim() });
    negated = false;
    at = close + 1;
  }
  // Ran off the end with the list still open.
  return undefined;
}

/**
 * The `]` closing an entity tag, skipping any inside the quoted part.
 *
 * An `entity-tag`'s opaque value is a quoted string and RFC 9110 §8.8.3 lets it
 * hold a `]`; §10.4.2 forbids whitespace between the brackets but says nothing
 * about that. Scanning through the quotes costs one flag and means an ETag this
 * server never produces — but a client may have been handed by something else —
 * does not truncate the header.
 */
function entityTagEnd(value: string, from: number): number {
  let quoted = false;
  for (let at = from; at < value.length; at++) {
    const character = value[at];
    if (character === `"`) {
      quoted = !quoted;
      continue;
    }
    if (character === "]" && !quoted) {
      return at;
    }
  }
  return -1;
}

/**
 * Every state token the header submitted, in order and without duplicates.
 *
 * §10.4.1's second purpose, and it is deliberately **independent of
 * evaluation**: "a state token counts as being submitted independently of
 * whether the server actually has evaluated the state list it appears in, and
 * also independently of whether or not the condition it expressed was found to
 * be true". A token under `Not` is the one exclusion, and it is not an
 * exception to that rule but a reading of what the client said: `Not <token>`
 * asserts the resource is *not* held by it, which is the opposite of claiming
 * to hold it — and it is how §10.4.8's `(Not <DAV:no-lock>)` idiom stays a
 * tautology rather than a claim on a lock.
 */
export function submittedTokens(lists: readonly IfList[]): string[] {
  const tokens: string[] = [];
  for (const list of lists) {
    for (const condition of list.conditions) {
      if (
        condition.token !== undefined &&
        !condition.negated &&
        !tokens.includes(condition.token)
      ) {
        tokens.push(condition.token);
      }
    }
  }
  return tokens;
}

// ---------------------------------------------------------------------------
// request bodies
// ---------------------------------------------------------------------------

/**
 * Read a request body into memory, refusing one over `limit`.
 *
 * Only the two XML grammars come through here; `PUT` streams (`session.ts`).
 * Each chunk is **copied** on the way in, because a transport is free to reuse
 * the buffer it handed over the moment the `await` returns (`AGENTS.md`,
 * invariant 12).
 *
 * @throws {DavFault} `413` past the limit.
 */
export async function collectBody(
  body: AsyncIterable<Uint8Array>,
  limit: number = MAX_XML_BYTES,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of body) {
    total += chunk.byteLength;
    if (total > limit) {
      throw refuse(413, { message: `the request body is over the ${limit}-byte budget` });
    }
    chunks.push(Uint8Array.prototype.slice.call(chunk));
  }
  const buffer = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, at);
    at += chunk.byteLength;
  }
  return buffer;
}

/**
 * One property name: the pair RFC 4918 §4 defines a property to be named by,
 * a namespace and a local name.
 *
 * Both halves are compared. `<D:getlastmodified xmlns:D="DAV:">` is this
 * server's `getlastmodified`; `<Z:getlastmodified xmlns:Z="urn:example">` is a
 * property it has never heard of that happens to share the local name, and
 * answering it with the `DAV:` value would be answering a question nobody
 * asked. §4: "properties are named with a URI ... the namespace partitions the
 * set of property names".
 */
export interface DavPropertyName {
  /** The namespace URI, `""` for a name in none. */
  ns: string;
  /** The local name, with any prefix already resolved away. */
  name: string;
}

/** Are these the same property? */
export function samePropertyName(a: DavPropertyName, b: DavPropertyName): boolean {
  return a.ns === b.ns && a.name === b.name;
}

/** One property of this server's own, which is every one it can answer. */
export function davProperty(name: string): DavPropertyName {
  return { ns: DAV_NS, name };
}

/** What a `PROPFIND` body asked for (RFC 4918 §9.1, §14.2, §14.20, §14.21). */
export type PropfindRequest =
  | { kind: "allprop" }
  | { kind: "propname" }
  | { kind: "prop"; names: DavPropertyName[] };

/**
 * Parse a `PROPFIND` body.
 *
 * **An empty body is `allprop`**, which §9.1 requires ("A client may choose not
 * to submit a request body ... treat as if it were an `allprop` request") and
 * which is what `curl -X PROPFIND` sends.
 *
 * `<include>` is parsed and folded into `allprop`: it names properties a server
 * may leave out of `allprop`, and this server leaves none out that it has, so
 * the answer is the same document either way.
 *
 * @throws {DavFault} `400` for a body that is not a well-formed `propfind`.
 */
export function parsePropfind(body: Uint8Array): PropfindRequest {
  if (body.byteLength === 0) {
    return { kind: "allprop" };
  }
  const root = parseDocument(body, "propfind");
  const names: DavPropertyName[] = [];
  let sawProp = false;
  for (const child of root.children) {
    if (child.name === "propname") {
      return { kind: "propname" };
    }
    if (child.name === "allprop") {
      return { kind: "allprop" };
    }
    if (child.name === "prop") {
      sawProp = true;
      for (const property of child.children) {
        const asked = { ns: property.ns, name: property.name };
        if (!names.some((seen) => samePropertyName(seen, asked))) {
          names.push(asked);
        }
      }
    }
  }
  if (!sawProp) {
    throw refuse(400, { message: "a propfind body must hold propname, allprop or prop" });
  }
  return { kind: "prop", names };
}

/** One `<set>` instruction: a property name and the value it was given. */
export interface ProppatchSet {
  name: DavPropertyName;
  /**
   * The element's text content, which is the whole value for every property
   * this server can store — `getlastmodified` is an `HTTP-date` (§15.7) and
   * nothing else is settable. A property whose value is *markup* keeps only its
   * text here, which is enough to refuse it and not enough to store it; that is
   * the same limit as "no dead properties" seen from the parser.
   */
  text: string;
}

/**
 * The properties a `PROPPATCH` body wants written or removed (RFC 4918 §9.2).
 *
 * Both lists are kept whether or not this server can act on them: the reply has
 * to name **every** property the request did, each with its own status, and a
 * `remove` that vanished from the reply would be a `207` that silently agreed
 * to it.
 *
 * The order is the document's, which §9.2 makes normative ("servers MUST
 * process PROPPATCH instructions in document order (an exception to the normal
 * rule that ordering is irrelevant)").
 */
export interface ProppatchRequest {
  /** Property names and values under `<set>`, in request order. */
  set: ProppatchSet[];
  /** Property names under `<remove>`, in request order. */
  remove: DavPropertyName[];
}

/**
 * Parse a `PROPPATCH` body.
 *
 * @throws {DavFault} `400` for a body that is not a well-formed `propertyupdate`.
 */
export function parseProppatch(body: Uint8Array): ProppatchRequest {
  const root = parseDocument(body, "propertyupdate");
  const set: ProppatchSet[] = [];
  const remove: DavPropertyName[] = [];
  for (const child of root.children) {
    const setting = child.name === "set";
    if (!setting && child.name !== "remove") {
      continue;
    }
    for (const prop of child.children) {
      if (prop.name !== "prop") {
        continue;
      }
      for (const property of prop.children) {
        const named = { ns: property.ns, name: property.name };
        if (setting) {
          set.push({ name: named, text: property.text });
        } else {
          remove.push(named);
        }
      }
    }
  }
  if (set.length === 0 && remove.length === 0) {
    throw refuse(400, { message: "a propertyupdate body must name at least one property" });
  }
  return { set, remove };
}

/** What a `LOCK` body asked for (RFC 4918 §9.10, §14.11). */
export interface LockInfoRequest {
  /** `<exclusive/>` rather than `<shared/>` (§14.13). */
  exclusive: boolean;
  /**
   * The `<owner>` element, preserved whole, or `undefined` when the body had
   * none — §14.11 makes it optional and §9.10.1 requires a server that gets one
   * to keep it.
   */
  owner: XmlNode | undefined;
}

/**
 * Parse a `LOCK` body, or answer `undefined` for the empty one that means
 * "refresh" (RFC 4918 §7.7, §9.10.2).
 *
 * The two forms are the whole method: a body creates a lock, and **no body
 * refreshes one** — "a server receiving a LOCK request with no body MUST NOT
 * create a new lock". The distinction is the body's presence, so an empty body
 * is not an error here and the session reads it as the refresh it is.
 *
 * `<locktype>` must be `<write/>`: it is the only type RFC 4918 defines
 * (§14.15, §7), and one this server does not have is refused rather than
 * granted as a write lock the client did not ask for. `<lockscope>` must be
 * one of the two §14.13 names.
 *
 * @throws {DavFault} `400` for a body that is not a well-formed `lockinfo`, and
 * for a lock type or scope this server has no meaning for.
 */
export function parseLockInfo(body: Uint8Array): LockInfoRequest | undefined {
  if (body.byteLength === 0) {
    return undefined;
  }
  const root = parseDocument(body, "lockinfo");
  let exclusive: boolean | undefined;
  let write = false;
  let owner: XmlNode | undefined;
  for (const child of root.children) {
    if (child.name === "lockscope") {
      exclusive = child.children.some((scope) => scope.name === "exclusive")
        ? true
        : child.children.some((scope) => scope.name === "shared")
          ? false
          : undefined;
    } else if (child.name === "locktype") {
      write = child.children.some((type) => type.name === "write");
    } else if (child.name === "owner") {
      owner = toXmlNode(child);
    }
  }
  if (exclusive === undefined) {
    throw refuse(400, { message: "a lockinfo body needs a lockscope of exclusive or shared" });
  }
  if (!write) {
    throw refuse(400, { message: "write is the only lock type this server has (RFC 4918 §7)" });
  }
  return { exclusive, owner };
}

/**
 * A parsed element as an encodable one, so an `<owner>` can go back out the way
 * it came in (§9.10.1: "the server ... MUST return the value of the owner
 * element as submitted by the client").
 *
 * Namespaces come back with it — an owner written under a prefix bound
 * somewhere other than `DAV:` is re-declared on the way out rather than
 * silently re-rooted, which is what makes "as submitted" true of the pair and
 * not only of the local name. The prefix itself is not preserved and does not
 * need to be: §14 binds a name to its namespace, never to the spelling of the
 * prefix that reached it.
 *
 * Still lossy for mixed content, which is flattened the same way the parser
 * flattens it — every text run of an element concatenated ahead of its children
 * — and that is enough for the `<owner><href>…</href></owner>` and
 * `<owner>a name</owner>` forms clients actually send.
 */
function toXmlNode(element: ReturnType<typeof parseXml>): XmlNode {
  return {
    name: element.name,
    ns: element.ns,
    text: element.text === "" ? undefined : element.text,
    children: element.children.map((child) => toXmlNode(child)),
  };
}

/**
 * Parse a body and check its root element.
 *
 * Every refusal the XML layer can produce — too large, not UTF-8, malformed, a
 * DOCTYPE, an entity, too deep — becomes one `400`. WebDAV has no equivalent of
 * S3's per-refusal error codes, so the distinction has nowhere to go on the
 * wire; the reason survives in the message.
 *
 * @throws {DavFault} `400`.
 */
function parseDocument(body: Uint8Array, root: string): ReturnType<typeof parseXml> {
  let parsed: ReturnType<typeof parseXml>;
  try {
    parsed = parseXml(body, { maxBytes: MAX_XML_BYTES });
  } catch (error) {
    if (error instanceof XmlError) {
      throw refuse(400, { message: `the request body is not usable XML: ${error.message}` });
    }
    /* v8 ignore next 2 -- `parseXml` documents `XmlError` as the only thing it
       throws; this keeps that a fact rather than an assumption. */
    throw error;
  }
  if (parsed.name !== root) {
    throw refuse(400, { message: `expected a ${root} document, got ${parsed.name}` });
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// response documents
// ---------------------------------------------------------------------------

/** One `<propstat>`: a set of properties that share a status. */
export interface Propstat {
  status: number;
  /** The property elements, already built. */
  props: XmlNode[];
  /** A §16 condition element for the `<error>` inside this propstat. */
  condition?: string;
}

/**
 * One `<response>` in a `multistatus`.
 *
 * Either form of §14.24: `propstat` (what `PROPFIND` and `PROPPATCH` answer)
 * **or** a bare `status` (what a partly failed `DELETE` or `COPY` answers).
 * Both at once is not a document RFC 4918 defines, and the encoder writes
 * `propstat` when it is there.
 */
export interface MultistatusEntry {
  href: string;
  propstat?: Propstat[];
  status?: number;
}

/** Encode a `<multistatus>` document (RFC 4918 §14.16). */
export function encodeMultistatus(entries: readonly MultistatusEntry[]): string {
  return xmlDocument(
    {
      name: "multistatus",
      children: entries.map((entry) => ({
        name: "response",
        children: [
          { name: "href", text: entry.href },
          ...(entry.propstat ?? []).map((propstat) => ({
            name: "propstat",
            children: [
              { name: "prop", children: propstat.props },
              { name: "status", text: statusLine(propstat.status) },
              propstat.condition === undefined
                ? undefined
                : { name: "error", children: [{ name: propstat.condition }] },
            ],
          })),
          entry.status === undefined
            ? undefined
            : { name: "status", text: statusLine(entry.status) },
        ],
      })),
    },
    { xmlns: DAV_NS },
  );
}

/**
 * Encode an `<error>` document carrying one §16 condition (RFC 4918 §14.5),
 * with the `href`s that condition names.
 *
 * `lock-token-submitted` "MUST contain at least one URL of a locked resource
 * that prevented the request" (§16), so the hrefs are children of the condition
 * element rather than siblings — the shape §7.5.2's example shows.
 */
export function encodeErrorDocument(condition: string, hrefs: readonly string[] = []): string {
  return xmlDocument(
    {
      name: "error",
      children: [
        { name: condition, children: hrefs.map((href) => ({ name: "href", text: href })) },
      ],
    },
    { xmlns: DAV_NS },
  );
}

// ---------------------------------------------------------------------------
// lock documents
// ---------------------------------------------------------------------------

/**
 * The `supportedlock` property (RFC 4918 §15.10): one `lockentry` per
 * combination of scope and type this server will grant.
 *
 * Both of §14.13's scopes over §14.15's one type, which is every lock RFC 4918
 * defines — and it is a *listing of what a `LOCK` here would accept* rather
 * than a constant: the two entries are exactly what `parseLockInfo` lets
 * through, so this cannot advertise a lock the next request would be refused
 * (`AGENTS.md`, invariant 5).
 */
export function supportedLockNode(): XmlNode {
  return {
    name: "supportedlock",
    children: [
      {
        name: "lockentry",
        children: [
          { name: "lockscope", children: [{ name: "exclusive" }] },
          { name: "locktype", children: [{ name: "write" }] },
        ],
      },
      {
        name: "lockentry",
        children: [
          { name: "lockscope", children: [{ name: "shared" }] },
          { name: "locktype", children: [{ name: "write" }] },
        ],
      },
    ],
  };
}

/**
 * One `<activelock>` (RFC 4918 §14.1).
 *
 * Child order is the DTD's — `(lockscope, locktype, depth, owner?, timeout?,
 * locktoken?, lockroot)` — which is **not** the order §9.10.7's example writes
 * them in; the examples put `locktype` first, and the declaration is the
 * normative half. Every optional child is sent: the token because §6.5 allows
 * it and a client that lost its `Lock-Token` header can only recover it here,
 * the owner because §9.10.1 requires this server to have preserved it, and the
 * timeout because it is the only place the *granted* lease is stated.
 */
export function activeLockNode(lock: DavLock, now: number): XmlNode {
  return {
    name: "activelock",
    children: [
      { name: "lockscope", children: [{ name: lock.exclusive ? "exclusive" : "shared" }] },
      { name: "locktype", children: [{ name: "write" }] },
      { name: "depth", text: String(lock.depth) },
      lock.owner,
      { name: "timeout", text: `Second-${DavLockTable.remaining(lock, now)}` },
      {
        name: "locktoken",
        children: [{ name: "href", text: lock.token }],
      },
      {
        name: "lockroot",
        children: [{ name: "href", text: hrefOf(lock.path, lock.collection) }],
      },
    ],
  };
}

/**
 * The `lockdiscovery` property (RFC 4918 §15.8): every lock covering a
 * resource, or the empty element when none do.
 *
 * "If there are no locks, but the server supports locks, the property will be
 * present but contain zero 'activelock' elements" — which is why this is
 * answered for every resource rather than left out, and why it looks the same
 * as the truthfully-empty element this server sent before it had locks at all.
 */
export function lockDiscoveryNode(locks: readonly DavLock[], now: number): XmlNode {
  return {
    name: "lockdiscovery",
    children: locks.map((lock) => activeLockNode(lock, now)),
  };
}

/**
 * The body of a successful `LOCK`: `<prop><lockdiscovery><activelock/>…`
 * (RFC 4918 §9.10.1).
 *
 * "MUST contain a body with the value of the DAV:lockdiscovery property in a
 * prop XML element ... the full information about the lock just granted, while
 * information about other (shared) locks is OPTIONAL" — so what goes back is
 * the one lock this request took or refreshed, and not whatever else is on the
 * resource.
 */
export function encodeLockResponse(lock: DavLock, now: number): string {
  return xmlDocument(
    { name: "prop", children: [lockDiscoveryNode([lock], now)] },
    { xmlns: DAV_NS },
  );
}
