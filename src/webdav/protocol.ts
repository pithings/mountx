/**
 * WebDAV's wire, with no driver and no socket: request lines and headers in,
 * XML documents and refusals out.
 *
 * Everything here is pure and total. `session.ts` decides what an operation
 * *means*; this file decides what the bytes said and what the bytes will say —
 * the `Depth`, `Overwrite` and `Destination` headers, the URL ↔ driver-path
 * mapping in both directions, the two request grammars, and the `multistatus`
 * and `error` documents. Sources are **RFC 4918** for the DAV parts and
 * **RFC 9110** for the HTTP ones, named at the rule they justify.
 *
 * ## Namespaces, and the one thing this layer loses
 *
 * Documents go out with `DAV:` as the **default** namespace —
 * `<multistatus xmlns="DAV:">` with unprefixed children — rather than with the
 * `D:` prefix RFC 4918's examples use. The two are the same document to a
 * namespace-aware parser (§14 binds names to the namespace, never to a prefix),
 * and the default form is what the shared encoder produces without a second
 * spelling of every element name.
 *
 * Coming in, the XML parser this module borrows (`src/s3/xml.ts`) reports an
 * element's **local name** and drops its prefix, which is exactly right for the
 * grammar — `<D:propfind>` and `<a:propfind>` are one element — and lossy for
 * one thing: a requested property in some *other* namespace, which Finder and
 * Office both send. `Z:Win32CreationTime` comes back as `Win32CreationTime`
 * in the `DAV:` namespace, inside the `404` propstat where the client is
 * looking only at the status. It is a real deviation, it is bounded to
 * properties this server does not have, and undoing it means a
 * namespace-tracking parser — see `.agents/roadmap.md`.
 */

import { normalizePath, splitPath } from "../path.ts";
import { parseXml, XmlError, xmlDocument, type XmlNode } from "../s3/xml.ts";
import { DAV_NS, MAX_XML_BYTES, statusLine, statusOf, XML_CONTENT_TYPE } from "./constants.ts";

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
  /** Extra headers the refusal carries (`Allow`, `Content-Range`). */
  readonly headers: Record<string, string>;

  constructor(
    status: number,
    options: { condition?: string; message?: string; headers?: Record<string, string> } = {},
  ) {
    super(options.message ?? statusLine(status));
    this.name = "DavFault";
    this.status = status;
    this.condition = options.condition;
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
  options?: { condition?: string; message?: string; headers?: Record<string, string> },
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
  return xmlBody(status, encodeErrorDocument(condition), extra);
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

/** What a `PROPFIND` body asked for (RFC 4918 §9.1, §14.2, §14.20, §14.21). */
export type PropfindRequest =
  | { kind: "allprop" }
  | { kind: "propname" }
  | { kind: "prop"; names: string[] };

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
  const names: string[] = [];
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
        if (!names.includes(property.name)) {
          names.push(property.name);
        }
      }
    }
  }
  if (!sawProp) {
    throw refuse(400, { message: "a propfind body must hold propname, allprop or prop" });
  }
  return { kind: "prop", names };
}

/**
 * The properties a `PROPPATCH` body wants written or removed (RFC 4918 §9.2).
 *
 * Both lists are kept even though this server writes neither: the reply has to
 * name **every** property the request did, each with its own status, and a
 * `remove` that vanished from the reply would be a `207` that silently agreed
 * to it.
 */
export interface ProppatchRequest {
  /** Property names under `<set>`, in request order. */
  set: string[];
  /** Property names under `<remove>`, in request order. */
  remove: string[];
}

/**
 * Parse a `PROPPATCH` body.
 *
 * @throws {DavFault} `400` for a body that is not a well-formed `propertyupdate`.
 */
export function parseProppatch(body: Uint8Array): ProppatchRequest {
  const root = parseDocument(body, "propertyupdate");
  const set: string[] = [];
  const remove: string[] = [];
  for (const child of root.children) {
    const into = child.name === "set" ? set : child.name === "remove" ? remove : undefined;
    if (into === undefined) {
      continue;
    }
    for (const prop of child.children) {
      if (prop.name === "prop") {
        for (const property of prop.children) {
          into.push(property.name);
        }
      }
    }
  }
  if (set.length === 0 && remove.length === 0) {
    throw refuse(400, { message: "a propertyupdate body must name at least one property" });
  }
  return { set, remove };
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

/** Encode an `<error>` document carrying one §16 condition (RFC 4918 §14.5). */
export function encodeErrorDocument(condition: string): string {
  return xmlDocument({ name: "error", children: [{ name: condition }] }, { xmlns: DAV_NS });
}
