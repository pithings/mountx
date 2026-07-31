/**
 * The HTTP the two HTTP transports share: `HTTP-date`, `Range`, `ETag` and the
 * two entity-tag comparison functions.
 *
 * All of it is **RFC 9110**, none of it is S3's or WebDAV's, and it lives here
 * for the same reason `src/errors.ts` holds one errno table: a wire format
 * transcribed twice is a wire format that will be transcribed differently twice
 * (`AGENTS.md`, invariants 6 and 7). `src/s3/protocol.ts` re-exports every
 * symbol below under its own name, so `mountx/s3`'s surface is unchanged and
 * the S3 gateway still reads as though it owned them.
 *
 * Pure and clockless: a timestamp is always an argument, never `Date.now()`.
 */

// ---------------------------------------------------------------------------
// dates
// ---------------------------------------------------------------------------

const DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

const MONTH_NAMES = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

/** The widest millisecond timestamp `Date` represents (ECMA-262, `Date` range). */
export const MAX_TIMESTAMP_MS = 8.64e15;

function two(value: number): string {
  return String(value).padStart(2, "0");
}

/**
 * An `IMF-fixdate`, the one format a sender may use (RFC 9110 §5.6.7):
 * `Sun, 06 Nov 1994 08:49:37 GMT`.
 *
 * Built from the UTC fields rather than `toUTCString()` so the output is this
 * module's own, and so a non-finite timestamp is a caller error here rather
 * than the string `"Invalid Date"` on the wire.
 */
export function formatHttpDate(timestamp: number): string {
  const date = new Date(timestamp);
  return (
    `${DAY_NAMES[date.getUTCDay()]}, ${two(date.getUTCDate())} ` +
    `${MONTH_NAMES[date.getUTCMonth()]} ${date.getUTCFullYear()} ` +
    `${two(date.getUTCHours())}:${two(date.getUTCMinutes())}:${two(date.getUTCSeconds())} GMT`
  );
}

/**
 * The ISO 8601 form S3 puts in XML documents (`LastModified`, `CreationDate`):
 * `1994-11-06T08:49:37.000Z`, always with milliseconds and always UTC.
 */
export function formatIsoDate(timestamp: number): string {
  return new Date(timestamp).toISOString();
}

const IMF_FIXDATE =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) ([A-Za-z]{3}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$/;

const RFC850_DATE =
  /^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-([A-Za-z]{3})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) GMT$/;

const ASCTIME_DATE =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([A-Za-z]{3}) ([ \d]\d) (\d{2}):(\d{2}):(\d{2}) (\d{4})$/;

function utcOf(
  year: number,
  monthName: string,
  day: number,
  hour: number,
  minute: number,
  second: number,
): number | undefined {
  const month = MONTH_NAMES.indexOf(monthName);
  /* `year < 100` is refused rather than passed to `Date.UTC`, which maps 0..99
     onto 1900..1999 — so `0099` would silently become 1999. A four-digit year
     under 100 is not a date any client meant. */
  if (
    month === -1 ||
    year < 100 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 60
  ) {
    return undefined;
  }
  const timestamp = Date.UTC(year, month, day, hour, minute, Math.min(second, 59));
  /* Date.UTC rolls a day past the month's end forward; a date that does not
     survive the round trip was never a real one. */
  if (!Number.isFinite(timestamp) || new Date(timestamp).getUTCDate() !== day) {
    return undefined;
  }
  return timestamp;
}

/**
 * Parse an `HTTP-date` into a millisecond epoch, or `undefined` for anything
 * that is not one.
 *
 * All three formats RFC 9110 §5.6.7 requires a recipient to accept: the
 * preferred `IMF-fixdate`, the obsolete RFC 850 form, and `asctime()`. A
 * two-digit RFC 850 year uses the fixed `69`/`70` split rather than the
 * "50 years in the future" rule, because that rule needs a clock and this
 * module does not have one — the difference only shows up for dates after 2069,
 * in a format no client has sent this century.
 *
 * A leap second (`:60`) is accepted and read as `:59`, which is what RFC 9110
 * recommends. Never throws: an unparseable date is `undefined`, and every
 * conditional header treats that as absent (RFC 9110 §13.1.3/§13.1.4).
 */
export function parseHttpDate(value: string): number | undefined {
  const fixdate = IMF_FIXDATE.exec(value);
  if (fixdate !== null) {
    return utcOf(
      Number(fixdate[3]),
      fixdate[2] as string,
      Number(fixdate[1]),
      Number(fixdate[4]),
      Number(fixdate[5]),
      Number(fixdate[6]),
    );
  }
  const rfc850 = RFC850_DATE.exec(value);
  if (rfc850 !== null) {
    const short = Number(rfc850[3]);
    return utcOf(
      short >= 70 ? 1900 + short : 2000 + short,
      rfc850[2] as string,
      Number(rfc850[1]),
      Number(rfc850[4]),
      Number(rfc850[5]),
      Number(rfc850[6]),
    );
  }
  const asctime = ASCTIME_DATE.exec(value);
  if (asctime !== null) {
    return utcOf(
      Number(asctime[6]),
      asctime[1] as string,
      Number(asctime[2]),
      Number(asctime[3]),
      Number(asctime[4]),
      Number(asctime[5]),
    );
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Range
// ---------------------------------------------------------------------------

/**
 * What a `Range` header asked for, against a known resource size.
 *
 * - `full` — no range, or one this server must ignore. RFC 9110 §14.2 is
 *   explicit that an unsatisfiable *syntax* is ignored rather than refused, and
 *   a multi-range request is ignored here too: neither transport over this
 *   answers a `multipart/byteranges` document, and S3 itself does not either
 *   ("Amazon S3 doesn't support retrieving multiple ranges of data per GET
 *   request") — what goes back is `200` with the whole resource.
 * - `range` — a satisfiable single range, already clamped to the resource.
 * - `unsatisfiable` — the 416 case (`Content-Range: bytes * /n`).
 */
export type RangeSpec =
  | { kind: "full" }
  | { kind: "range"; start: number; end: number; length: number }
  | { kind: "unsatisfiable" };

/* Fresh objects rather than shared constants: a route object handed to a
   caller should never be a value another request can see mutated. */
function full(): RangeSpec {
  return { kind: "full" };
}

function unsatisfiable(): RangeSpec {
  return { kind: "unsatisfiable" };
}

/**
 * A `first-byte-pos`/`last-byte-pos`/`suffix-length`: digits only, and read as
 * a plain number even past `Number.MAX_SAFE_INTEGER` — a position that large is
 * only ever compared against a size, and `1e20 >= size` is true whether or not
 * the digits were exact.
 */
function rangeNumber(value: string): number | undefined {
  return /^\d+$/.test(value) ? Number(value) : undefined;
}

/**
 * Parse a `Range` header against a resource of `size` bytes (RFC 9110 §14.1).
 *
 * The three forms: `bytes=a-b`, `bytes=a-` and `bytes=-n`. A range unit other
 * than `bytes`, more than one range, or anything that does not parse is
 * **ignored** — the whole resource, status 200 — which is what RFC 9110
 * requires of an unparseable header (see {@link RangeSpec} on the multi-range
 * case).
 *
 * Unsatisfiable, per §14.1.1 and §14.4: `first-byte-pos` at or past the end of
 * the resource, or a `suffix-length` of zero. An empty resource therefore refuses
 * every byte range, including `bytes=0-`, since there is no byte 0 to serve.
 */
export function parseRange(value: string | undefined, size: number): RangeSpec {
  if (value === undefined || value === "") {
    return full();
  }
  const equals = value.indexOf("=");
  if (equals === -1 || value.slice(0, equals).trim().toLowerCase() !== "bytes") {
    return full();
  }
  const spec = value.slice(equals + 1).trim();
  if (spec.includes(",")) {
    return full();
  }
  const dash = spec.indexOf("-");
  if (dash === -1) {
    return full();
  }
  const firstText = spec.slice(0, dash).trim();
  const lastText = spec.slice(dash + 1).trim();
  if (firstText === "") {
    /* `bytes=-n`: the last n bytes. */
    const suffix = rangeNumber(lastText);
    if (suffix === undefined) {
      return full();
    }
    if (suffix === 0 || size === 0) {
      return unsatisfiable();
    }
    const start = Math.max(0, size - suffix);
    return { kind: "range", start, end: size - 1, length: size - start };
  }
  const first = rangeNumber(firstText);
  if (first === undefined) {
    return full();
  }
  if (lastText === "") {
    /* `bytes=a-`: to the end. */
    if (first >= size) {
      return unsatisfiable();
    }
    return { kind: "range", start: first, end: size - 1, length: size - first };
  }
  const last = rangeNumber(lastText);
  if (last === undefined || last < first) {
    /* An invalid range spec makes the whole header invalid (§14.1.1). */
    return full();
  }
  if (first >= size) {
    return unsatisfiable();
  }
  const end = Math.min(last, size - 1);
  return { kind: "range", start: first, end, length: end - first + 1 };
}

// ---------------------------------------------------------------------------
// entity tags
// ---------------------------------------------------------------------------

/** One entity tag, with the weakness marker kept: `W/` is part of the tag. */
export interface ETag {
  /** The opaque value, without quotes and without the `W/` prefix. */
  value: string;
  /** Was it sent as `W/"..."`? */
  weak: boolean;
}

/** An entity tag list: `*`, or the tags as sent. */
export type ETagList = { any: true } | { any: false; tags: ETag[] };

/** Take a tag apart: `W/"abc"` is `{ value: "abc", weak: true }`. */
export function parseETag(value: string): ETag {
  const weak = value.startsWith("W/");
  const withoutWeak = weak ? value.slice(2) : value;
  const unquoted =
    withoutWeak.startsWith(`"`) && withoutWeak.endsWith(`"`) && withoutWeak.length >= 2
      ? withoutWeak.slice(1, -1)
      : withoutWeak;
  return { value: unquoted, weak };
}

/**
 * Parse an `If-Match`/`If-None-Match` value (RFC 9110 §13.1.1/§13.1.2).
 *
 * The weakness marker is **kept**, because the two headers do not compare tags
 * the same way: `If-Match` uses the strong comparison function and `If-None-
 * Match` the weak one (§8.8.3.2). The client controls its side of that
 * comparison, so `If-Match: W/"x"` never matches anything — including a
 * representation whose strong ETag is `x` — while `If-None-Match: W/"x"` does.
 */
export function parseETagList(value: string): ETagList {
  if (value.trim() === "*") {
    return { any: true };
  }
  const tags: ETag[] = [];
  for (const part of value.split(",")) {
    const trimmed = part.trim();
    if (trimmed !== "") {
      tags.push(parseETag(trimmed));
    }
  }
  return { any: false, tags };
}

/**
 * The **strong** comparison function (RFC 9110 §8.8.3.2): the values match and
 * *neither* tag is weak. `*` matches any existing representation.
 */
export function etagMatchesStrongly(list: ETagList, etag: string): boolean {
  if (list.any) {
    return true;
  }
  const target = parseETag(etag);
  return !target.weak && list.tags.some((tag) => !tag.weak && tag.value === target.value);
}

/**
 * The **weak** comparison function: the values match, whatever either side's
 * weakness marker says.
 */
export function etagMatchesWeakly(list: ETagList, etag: string): boolean {
  if (list.any) {
    return true;
  }
  const target = parseETag(etag);
  return list.tags.some((tag) => tag.value === target.value);
}

/** Wrap an ETag in quotes if it is not already quoted. */
export function formatETag(etag: string): string {
  return etag.startsWith(`"`) && etag.endsWith(`"`) && etag.length >= 2 ? etag : `"${etag}"`;
}

/** `Content-Range: bytes 0-99/1234` (RFC 9110 §14.4). */
export function formatContentRange(start: number, end: number, total: number): string {
  return `bytes ${start}-${end}/${total}`;
}

/** The `Content-Range` of a 416 reply: `bytes * /n`, the "unsatisfied-range" form. */
export function formatUnsatisfiedRange(total: number): string {
  return `bytes */${total}`;
}
