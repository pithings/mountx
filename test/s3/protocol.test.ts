/**
 * The S3 router and its header parsers.
 *
 * Three kinds of assertion live here, and they are not the same kind of fact:
 *
 * - **Routing goldens.** Every operation the gateway implements, recognized
 *   from a request built the way the Amazon S3 API Reference's `Request Syntax`
 *   block for that operation writes it. The expected route objects give every
 *   field a distinct value (`AGENTS.md`: a fixture built from repeated values
 *   passes with two fields transposed), so `bucket`, `key`, `path`, `uploadId`
 *   and `partNumber` can never be swapped without a failure.
 * - **Refusals.** The step-4 invariant, checked exhaustively: every
 *   sub-resource this gateway does not implement answers `NotImplemented`, and
 *   *never* the neighbouring object operation. `GET /bucket/key?acl` returning
 *   the object's bytes would be a data leak wearing a fall-through's clothes,
 *   so the deny list is walked in full, for every method.
 * - **RFC behaviour.** `Range` (RFC 9110 §14), the conditional-request
 *   precedence (§13.2.2) and the three `HTTP-date` formats (§5.6.7) are
 *   standards, so they are tested against the standard's own cases rather than
 *   against what S3 happens to do.
 *
 * No literal control characters appear in this file: the cases that need one
 * build it with `String.fromCodePoint`, which keeps the source NUL-free and
 * grep-able.
 */

import { describe, expect, it } from "vitest";
import type { ChunkedRefusal } from "../../src/s3/chunked.ts";
import {
  ERRNO_S3_ERRORS,
  MAX_KEY_BYTES,
  MAX_KEYS,
  MAX_PARTS,
  MULTIPART_PREFIX,
  STREAMING_PAYLOAD,
  STREAMING_PAYLOAD_TRAILER,
  STREAMING_UNSIGNED_PAYLOAD_TRAILER,
  UNSIGNED_PAYLOAD,
} from "../../src/s3/constants.ts";
import {
  bodyMode,
  CHUNKED_REFUSAL_ERRORS,
  chunkedRefusalError,
  contentCodings,
  evaluateConditionals,
  formatContentRange,
  formatETag,
  formatHttpDate,
  formatIsoDate,
  formatMetaMtime,
  formatUnsatisfiedRange,
  hasQuery,
  headerList,
  headerValue,
  isAnswered,
  isRefusal,
  isStagingKey,
  isValidBucketName,
  MAX_PARTS_PER_PAGE,
  NULL_VERSION_ID,
  objectResponseHeaders,
  parseContentLengths,
  parseCopySource,
  parseETagList,
  parseHttpDate,
  parseMetaMtime,
  parseObjectKey,
  parseRange,
  parseRequestTarget,
  parseUnsignedInteger,
  pathToKey,
  queryValue,
  routeRequest,
  S3_ERRORS,
  S3_OPS,
  type S3ErrorSpec,
  s3Error,
  s3ErrorResponse,
  type S3OpName,
  type S3Route,
  SIGV4_REFUSAL_ERRORS,
  sigv4RefusalError,
  UNSUPPORTED_SUBRESOURCES,
  VERSION_ID_PARAMETER,
  XML_REFUSAL_ERRORS,
  xmlRefusalError,
} from "../../src/s3/protocol.ts";
import type { HeaderEntry } from "../../src/s3/sigv4.ts";
import type { XmlRefusal } from "../../src/s3/xml.ts";

const NUL = String.fromCodePoint(0);

/** Headers in wire order, from a plain object. */
function headersOf(entries: Record<string, string> = {}): HeaderEntry[] {
  return Object.entries(entries).map(([name, value]) => ({ name, value }));
}

/**
 * Parse a raw request target and route it — the two halves a server runs back
 * to back, so every routing case exercises the URL contract as well.
 */
function route(method: string, target: string, headers: Record<string, string> = {}): S3Route {
  const parsed = parseRequestTarget(target);
  if (!parsed.ok) {
    return { op: "Refused", error: parsed.error };
  }
  return routeRequest(method, parsed.target.path, parsed.target.query, headersOf(headers));
}

/** The error a refused route carries, or a failure if it was not refused. */
function refusalOf(routed: S3Route): S3ErrorSpec {
  expect(isRefusal(routed), `expected a refusal, got ${routed.op}`).toBe(true);
  return (routed as { error: S3ErrorSpec }).error;
}

// ---------------------------------------------------------------------------

describe("the request target", () => {
  it("splits the path from the query and decodes the path once", () => {
    const parsed = parseRequestTarget("/photos/2026/rome%20trip.txt?versionId=null&x=1");
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) {
      return;
    }
    expect(parsed.target).toEqual({
      path: "/photos/2026/rome trip.txt",
      rawPath: "/photos/2026/rome%20trip.txt",
      query: [
        { name: "versionId", value: "null" },
        { name: "x", value: "1" },
      ],
      rawQuery: [
        { name: "versionId", value: "null" },
        { name: "x", value: "1" },
      ],
      rawQueryString: "versionId=null&x=1",
    });
  });

  it("decodes the path exactly once, so %2541 is %41 and not A", () => {
    /* The contract `sigv4.ts` documents: whatever signs the request decodes the
       path once and nothing decodes it again. A second pass here would turn a
       key literally named `%41` into one named `A`. */
    const routed = route("GET", "/bucket/pct%2541");
    expect(routed).toMatchObject({ op: "GetObject", key: "pct%41", path: "/pct%41" });
  });

  it("reads + in the path as a literal plus and in the query as a space", () => {
    const routed = route("GET", "/bucket/a+b.txt");
    expect(routed).toMatchObject({ op: "GetObject", key: "a+b.txt" });
    const parsed = parseRequestTarget("/bucket?list-type=2&prefix=holiday+photos%2F");
    expect(parsed.ok && parsed.target.query).toEqual([
      { name: "list-type", value: "2" },
      { name: "prefix", value: "holiday photos/" },
    ]);
  });

  it("keeps the raw query pairs beside the decoded ones", () => {
    /* A presigned signature covers what was *sent*: a client that wrote `%7E`
       signed `%7E`, and re-encoding the decoded `~` cannot always put it back. */
    const parsed = parseRequestTarget(
      "/b?X-Amz-Credential=AKID%2F20260728%2Fus-east-1&flag&tilde=%7E",
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) {
      return;
    }
    expect(parsed.target.rawQuery).toEqual([
      { name: "X-Amz-Credential", value: "AKID%2F20260728%2Fus-east-1" },
      { name: "flag", value: undefined },
      { name: "tilde", value: "%7E" },
    ]);
    expect(parsed.target.query).toEqual([
      { name: "X-Amz-Credential", value: "AKID/20260728/us-east-1" },
      { name: "flag", value: "" },
      { name: "tilde", value: "~" },
    ]);
    expect(parsed.target.rawQueryString).toBe(
      "X-Amz-Credential=AKID%2F20260728%2Fus-east-1&flag&tilde=%7E",
    );
  });

  it("refuses a malformed escape with InvalidURI", () => {
    for (const target of ["/bucket/%zz", "/bucket/%", "/bucket/%E0%80", "/bucket/%2"]) {
      const parsed = parseRequestTarget(target);
      expect(parsed.ok, target).toBe(false);
      expect(parsed.ok ? undefined : parsed.error).toMatchObject({
        code: "InvalidURI",
        status: 400,
      });
    }
  });

  it("refuses a malformed escape in the query string too", () => {
    const parsed = parseRequestTarget("/bucket?prefix=%zz");
    expect(parsed.ok).toBe(false);
    expect(parsed.ok ? undefined : parsed.error.code).toBe("InvalidURI");
  });

  it("refuses a target that is not origin-form", () => {
    const parsed = parseRequestTarget("http://example.com/bucket/key");
    expect(parsed.ok).toBe(false);
    expect(parsed.ok ? undefined : parsed.error.code).toBe("InvalidURI");
  });

  it("finds parameters and headers the way the wire spells them", () => {
    const query = [
      { name: "list-type", value: "2" },
      { name: "prefix", value: "a" },
    ];
    expect(queryValue(query, "prefix")).toBe("a");
    expect(queryValue(query, "Prefix")).toBeUndefined();
    expect(hasQuery(query, "list-type")).toBe(true);
    expect(hasQuery(query, "delimiter")).toBe(false);
    /* HTTP field names are case-insensitive; S3's query parameters are not. */
    const headers = headersOf({ "X-Amz-Copy-Source": "/b/k", Range: "bytes=0-1" });
    expect(headerValue(headers, "x-amz-copy-source")).toBe("/b/k");
    expect(headerValue(headers, "RANGE")).toBe("bytes=0-1");
    expect(headerValue(headers, "if-match")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------

describe("the operation table", () => {
  /** One request per supported operation, shaped as its API Reference page is. */
  const EXAMPLES: readonly {
    op: S3OpName;
    method: string;
    target: string;
    headers?: Record<string, string>;
  }[] = [
    { op: "ListBuckets", method: "GET", target: "/" },
    { op: "HeadBucket", method: "HEAD", target: "/bucket" },
    { op: "ListObjectsV2", method: "GET", target: "/bucket?list-type=2" },
    { op: "GetObject", method: "GET", target: "/bucket/key" },
    { op: "HeadObject", method: "HEAD", target: "/bucket/key" },
    { op: "PutObject", method: "PUT", target: "/bucket/key" },
    { op: "DeleteObject", method: "DELETE", target: "/bucket/key" },
    { op: "DeleteObjects", method: "POST", target: "/bucket?delete" },
    {
      op: "CopyObject",
      method: "PUT",
      target: "/bucket/key",
      headers: { "x-amz-copy-source": "/other/source" },
    },
    { op: "CreateMultipartUpload", method: "POST", target: "/bucket/key?uploads" },
    { op: "UploadPart", method: "PUT", target: "/bucket/key?uploadId=u&partNumber=1" },
    { op: "CompleteMultipartUpload", method: "POST", target: "/bucket/key?uploadId=u" },
    { op: "AbortMultipartUpload", method: "DELETE", target: "/bucket/key?uploadId=u" },
    { op: "ListParts", method: "GET", target: "/bucket/key?uploadId=u" },
  ];

  it("names every operation the plan supports, and no others", () => {
    expect(Object.keys(S3_OPS).sort()).toEqual(
      [
        "AbortMultipartUpload",
        "CompleteMultipartUpload",
        "CopyObject",
        "CreateMultipartUpload",
        "DeleteObject",
        "DeleteObjects",
        "GetObject",
        "HeadBucket",
        "HeadObject",
        "ListBuckets",
        "ListObjectsV2",
        "ListParts",
        "PutObject",
        "UploadPart",
      ].sort(),
    );
  });

  it("routes to every operation in the table, and the table to every route", () => {
    const reached = new Set<string>();
    for (const example of EXAMPLES) {
      const routed = route(example.method, example.target, example.headers);
      expect(routed.op, `${example.method} ${example.target}`).toBe(example.op);
      reached.add(routed.op);
    }
    expect([...reached].sort()).toEqual(Object.keys(S3_OPS).sort());
  });

  it("agrees with each row's method and scope", () => {
    for (const example of EXAMPLES) {
      const entry = S3_OPS[example.op];
      expect(entry.method, example.op).toBe(example.method);
      const scope =
        example.target === "/"
          ? "service"
          : example.target.split("?")[0]?.split("/").length === 2
            ? "bucket"
            : "object";
      expect(entry.scope, example.op).toBe(scope);
      expect(entry.selector.length, example.op).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------

describe("routing", () => {
  it("routes GET / to ListBuckets", () => {
    expect(route("GET", "/")).toEqual({ op: "ListBuckets" });
    expect(route("GET", "/?anything=1")).toEqual({ op: "ListBuckets" });
  });

  it("routes HEAD /bucket to HeadBucket, with or without the trailing slash", () => {
    expect(route("HEAD", "/holiday-photos")).toEqual({
      op: "HeadBucket",
      bucket: "holiday-photos",
    });
    expect(route("HEAD", "/holiday-photos/")).toEqual({
      op: "HeadBucket",
      bucket: "holiday-photos",
    });
  });

  it("routes list-type=2 to ListObjectsV2, with every parameter parsed", () => {
    expect(
      route(
        "GET",
        "/images-bucket?list-type=2&prefix=trips%2F&delimiter=%2F&max-keys=57" +
          "&continuation-token=Q29udGludWU%3D&start-after=trips%2Falps.txt" +
          "&fetch-owner=true&encoding-type=url",
      ),
    ).toEqual({
      op: "ListObjectsV2",
      bucket: "images-bucket",
      prefix: "trips/",
      delimiter: "/",
      maxKeys: 57,
      continuationToken: "Q29udGludWU=",
      startAfter: "trips/alps.txt",
      fetchOwner: true,
      encodingType: "url",
    });
  });

  it("defaults the ListObjectsV2 parameters nobody sent", () => {
    expect(route("GET", "/b?list-type=2")).toEqual({
      op: "ListObjectsV2",
      bucket: "b",
      prefix: "",
      delimiter: undefined,
      maxKeys: MAX_KEYS,
      continuationToken: undefined,
      startAfter: undefined,
      fetchOwner: false,
      encodingType: undefined,
    });
  });

  it("reads fetch-owner case-insensitively, and everything else as false", () => {
    for (const value of ["true", "TRUE", "True"]) {
      expect(route("GET", `/b?list-type=2&fetch-owner=${value}`), value).toMatchObject({
        fetchOwner: true,
      });
    }
    for (const value of ["false", "1", "yes", ""]) {
      expect(route("GET", `/b?list-type=2&fetch-owner=${value}`), value).toMatchObject({
        fetchOwner: false,
      });
    }
  });

  it("clamps max-keys the way S3 does, and refuses one that is not a number", () => {
    expect(route("GET", "/b?list-type=2&max-keys=5000")).toMatchObject({ maxKeys: MAX_KEYS });
    expect(route("GET", "/b?list-type=2&max-keys=0")).toMatchObject({ maxKeys: 0 });
    for (const bad of ["-1", "1e3", "12.5", "abc", "0x10"]) {
      expect(refusalOf(route("GET", `/b?list-type=2&max-keys=${bad}`)), bad).toMatchObject({
        code: "InvalidArgument",
        status: 400,
      });
    }
  });

  it("refuses an encoding-type it does not speak", () => {
    expect(refusalOf(route("GET", "/b?list-type=2&encoding-type=base64"))).toMatchObject({
      code: "InvalidArgument",
    });
  });

  it("refuses a delimiter other than / rather than pretending to group", () => {
    expect(refusalOf(route("GET", "/b?list-type=2&delimiter=%3A"))).toMatchObject({
      code: "NotImplemented",
      status: 501,
    });
  });

  it("routes the plain object operations", () => {
    expect(route("GET", "/photo-bucket/trips/rome.txt")).toEqual({
      op: "GetObject",
      bucket: "photo-bucket",
      key: "trips/rome.txt",
      path: "/trips/rome.txt",
      directory: false,
    });
    expect(route("HEAD", "/audio-bucket/podcasts/ep-14.mp3")).toEqual({
      op: "HeadObject",
      bucket: "audio-bucket",
      key: "podcasts/ep-14.mp3",
      path: "/podcasts/ep-14.mp3",
      directory: false,
    });
    expect(route("PUT", "/notes-bucket/journal/day-3.md")).toEqual({
      op: "PutObject",
      bucket: "notes-bucket",
      key: "journal/day-3.md",
      path: "/journal/day-3.md",
      directory: false,
    });
    expect(route("DELETE", "/tmp-bucket/scratch/old.bin")).toEqual({
      op: "DeleteObject",
      bucket: "tmp-bucket",
      key: "scratch/old.bin",
      path: "/scratch/old.bin",
      directory: false,
    });
  });

  it("keeps a trailing slash as the directory marker", () => {
    expect(route("PUT", "/bucket/empty-dir/")).toEqual({
      op: "PutObject",
      bucket: "bucket",
      key: "empty-dir/",
      path: "/empty-dir",
      directory: true,
    });
    expect(route("DELETE", "/bucket/a/b/")).toEqual({
      op: "DeleteObject",
      bucket: "bucket",
      key: "a/b/",
      path: "/a/b",
      directory: true,
    });
  });

  it("routes POST ?delete to DeleteObjects", () => {
    expect(route("POST", "/archive-bucket?delete")).toEqual({
      op: "DeleteObjects",
      bucket: "archive-bucket",
    });
  });

  it("routes a PUT carrying x-amz-copy-source to CopyObject", () => {
    expect(
      route("PUT", "/dest-bucket/copies/new.txt", {
        "x-amz-copy-source": "/src-bucket/originals/old%20name.txt?versionId=null",
        "x-amz-metadata-directive": "REPLACE",
      }),
    ).toEqual({
      op: "CopyObject",
      bucket: "dest-bucket",
      key: "copies/new.txt",
      path: "/copies/new.txt",
      directory: false,
      metadataDirective: "REPLACE",
      source: {
        bucket: "src-bucket",
        key: "originals/old name.txt",
        path: "/originals/old name.txt",
        directory: false,
      },
    });
  });

  it("defaults the metadata directive to COPY and refuses an unknown one", () => {
    expect(route("PUT", "/b/k", { "x-amz-copy-source": "src/other" })).toMatchObject({
      op: "CopyObject",
      metadataDirective: "COPY",
    });
    expect(
      refusalOf(
        route("PUT", "/b/k", {
          "x-amz-copy-source": "src/other",
          "x-amz-metadata-directive": "MERGE",
        }),
      ),
    ).toMatchObject({ code: "InvalidArgument" });
  });

  it("routes the five multipart operations", () => {
    expect(route("POST", "/uploads-bucket/big/file.iso?uploads")).toEqual({
      op: "CreateMultipartUpload",
      bucket: "uploads-bucket",
      key: "big/file.iso",
      path: "/big/file.iso",
      directory: false,
    });
    expect(route("PUT", "/parts-bucket/big/file.iso?partNumber=7&uploadId=upload-42")).toEqual({
      op: "UploadPart",
      bucket: "parts-bucket",
      key: "big/file.iso",
      path: "/big/file.iso",
      directory: false,
      uploadId: "upload-42",
      partNumber: 7,
    });
    expect(route("POST", "/done-bucket/big/file.iso?uploadId=upload-43")).toEqual({
      op: "CompleteMultipartUpload",
      bucket: "done-bucket",
      key: "big/file.iso",
      path: "/big/file.iso",
      directory: false,
      uploadId: "upload-43",
    });
    expect(route("DELETE", "/abort-bucket/big/file.iso?uploadId=upload-44")).toEqual({
      op: "AbortMultipartUpload",
      bucket: "abort-bucket",
      key: "big/file.iso",
      path: "/big/file.iso",
      directory: false,
      uploadId: "upload-44",
    });
    expect(
      route(
        "GET",
        "/list-bucket/big/file.iso?uploadId=upload-45&max-parts=13&part-number-marker=4",
      ),
    ).toEqual({
      op: "ListParts",
      bucket: "list-bucket",
      key: "big/file.iso",
      path: "/big/file.iso",
      directory: false,
      uploadId: "upload-45",
      maxParts: 13,
      partNumberMarker: 4,
    });
  });

  it("refuses a part number outside 1..MAX_PARTS, and a missing one", () => {
    for (const bad of ["0", String(MAX_PARTS + 1), "-1", "", "two"]) {
      expect(refusalOf(route("PUT", `/b/k?uploadId=u&partNumber=${bad}`)), bad).toMatchObject({
        code: "InvalidArgument",
      });
    }
    expect(refusalOf(route("PUT", "/b/k?uploadId=u"))).toMatchObject({ code: "InvalidArgument" });
    expect(route("PUT", `/b/k?uploadId=u&partNumber=${MAX_PARTS}`)).toMatchObject({
      op: "UploadPart",
      partNumber: MAX_PARTS,
    });
  });

  it("refuses an empty uploadId", () => {
    expect(refusalOf(route("POST", "/b/k?uploadId="))).toMatchObject({ code: "InvalidArgument" });
  });

  it("refuses a method the multipart sub-resources have no operation for", () => {
    expect(refusalOf(route("HEAD", "/b/k?uploadId=u"))).toMatchObject({
      code: "MethodNotAllowed",
    });
    expect(refusalOf(route("PUT", "/b/k?uploads"))).toMatchObject({ code: "MethodNotAllowed" });
    expect(refusalOf(route("DELETE", "/b/k?uploads"))).toMatchObject({
      code: "MethodNotAllowed",
    });
  });

  it("refuses a ListParts pagination parameter that is not a number", () => {
    for (const target of [
      "/b/k?uploadId=u&max-parts=many",
      "/b/k?uploadId=u&part-number-marker=-1",
    ]) {
      expect(refusalOf(route("GET", target)), target).toMatchObject({ code: "InvalidArgument" });
    }
    expect(route("GET", "/b/k?uploadId=u&max-parts=99999")).toMatchObject({
      maxParts: MAX_PARTS_PER_PAGE,
    });
  });

  it("refuses a copy source the header parser rejected", () => {
    expect(refusalOf(route("PUT", "/b/k", { "x-amz-copy-source": "no-key-here" }))).toMatchObject({
      code: "InvalidArgument",
    });
  });

  it("reads a path that never went through parseRequestTarget defensively", () => {
    /* `routeRequest()` is exported on its own, so it does not assume the target
       parser ran first. */
    expect(refusalOf(routeRequest("GET", "bucket/key", []))).toMatchObject({ code: "InvalidURI" });
  });
});

// ---------------------------------------------------------------------------

describe("refusals", () => {
  it("answers NotImplemented for every sub-resource it does not implement", () => {
    /* The step-4 invariant. Walked for all four object methods, because the
       failure this guards against is method-specific: a `?acl` that fell
       through on GET would serve the object's bytes. */
    for (const name of UNSUPPORTED_SUBRESOURCES) {
      for (const method of ["GET", "HEAD", "PUT", "DELETE", "POST"]) {
        const routed = route(method, `/bucket/key?${name}`);
        expect(refusalOf(routed), `${method} ?${name}`).toMatchObject({
          code: "NotImplemented",
          status: 501,
        });
        const onBucket = route(method, `/bucket?${name}=value`);
        expect(refusalOf(onBucket), `${method} /bucket?${name}`).toMatchObject({
          code: "NotImplemented",
        });
      }
    }
  });

  it("names the sub-resource in the message, so a client can see which one", () => {
    expect(refusalOf(route("GET", "/bucket/key?tagging")).message).toContain("?tagging");
  });

  it("carries the sub-resources added after the classic set", () => {
    /* Named one by one rather than counted: this list is the whole of the
       never-fall-through guarantee, and a name silently dropped from it turns
       an operation S3 has into one of ours. */
    for (const name of [
      "abac",
      "annotation",
      "annotationName",
      "attributes",
      "id",
      "metadataAnnotationTable",
      "metadataConfiguration",
      "metadataInventoryTable",
      "metadataJournalTable",
      "metadataTable",
      "renameObject",
      "session",
    ]) {
      expect(UNSUPPORTED_SUBRESOURCES, name).toContain(name);
    }
    expect([...UNSUPPORTED_SUBRESOURCES].sort()).toEqual([...UNSUPPORTED_SUBRESOURCES]);
    /* The four the router dispatches on must never appear here. */
    for (const name of ["uploads", "uploadId", "delete", "list-type", VERSION_ID_PARAMETER]) {
      expect(UNSUPPORTED_SUBRESOURCES, name).not.toContain(name);
    }
  });

  it("refuses a request that names a specific object version", () => {
    /* `?versionId` selects no operation of its own — it narrows one this
       gateway runs, to a version it does not have. Serving the live object
       would read, overwrite or delete the wrong bytes silently. */
    for (const method of ["GET", "HEAD", "PUT", "DELETE", "POST"]) {
      const routed = route(method, "/bucket/key?versionId=3sL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY");
      expect(refusalOf(routed), method).toMatchObject({ code: "NotImplemented", status: 501 });
      expect(refusalOf(routed).message, method).toContain(`?${VERSION_ID_PARAMETER}`);
    }
    expect(refusalOf(route("GET", "/bucket?versionId=x"))).toMatchObject({
      code: "NotImplemented",
    });
  });

  it("proceeds for the null version, which is the only one it has", () => {
    /* The rule `parseCopySource()` applies to `x-amz-copy-source`, applied to
       the request target: `null` and an empty value are this gateway's only
       version, so they route normally. */
    expect(NULL_VERSION_ID).toBe("null");
    expect(route("GET", `/bucket/key?versionId=${NULL_VERSION_ID}`)).toMatchObject({
      op: "GetObject",
      key: "key",
    });
    expect(route("DELETE", "/bucket/key?versionId=")).toMatchObject({ op: "DeleteObject" });
  });

  it("routes normally for parameters that decorate an operation instead of selecting one", () => {
    /* The AWS SDKs append `?x-id=<Operation>` to everything they send, and a
       presigned URL carries the six `X-Amz-*` parameters plus any response
       overrides. Refusing unknown parameters wholesale would refuse most real
       traffic, which is why the deny list is a list. */
    expect(route("GET", "/bucket/key?x-id=GetObject")).toMatchObject({ op: "GetObject" });
    expect(route("PUT", "/bucket/key?x-id=PutObject")).toMatchObject({ op: "PutObject" });
    expect(
      route(
        "GET",
        "/bucket/key?response-content-disposition=attachment&response-content-type=text%2Fplain" +
          "&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900&X-Amz-Signature=deadbeef",
      ),
    ).toMatchObject({ op: "GetObject", key: "key" });
    expect(route("POST", "/bucket/key?uploads&x-id=CreateMultipartUpload")).toMatchObject({
      op: "CreateMultipartUpload",
    });
  });

  it("refuses ListObjects V1 rather than answering V2's walk in V1's shape", () => {
    expect(refusalOf(route("GET", "/bucket"))).toMatchObject({
      code: "NotImplemented",
      status: 501,
    });
    expect(refusalOf(route("GET", "/bucket/"))).toMatchObject({ code: "NotImplemented" });
  });

  it("refuses a list-type it does not know", () => {
    expect(refusalOf(route("GET", "/bucket?list-type=1"))).toMatchObject({
      code: "InvalidArgument",
    });
    expect(refusalOf(route("GET", "/bucket?list-type=3")).message).toContain("3");
  });

  it("refuses CreateBucket and DeleteBucket", () => {
    expect(refusalOf(route("PUT", "/new-bucket"))).toMatchObject({
      code: "NotImplemented",
      status: 501,
    });
    expect(refusalOf(route("PUT", "/new-bucket")).message).toContain("CreateBucket");
    expect(refusalOf(route("DELETE", "/old-bucket"))).toMatchObject({ code: "NotImplemented" });
    expect(refusalOf(route("DELETE", "/old-bucket")).message).toContain("DeleteBucket");
  });

  it("refuses the multipart and object operations it does not implement", () => {
    /* ListMultipartUploads, UploadPartCopy, GetObject/HeadObject for one part,
       and the browser form POST — each shares a shape with something supported,
       which is exactly why each needs its own case. */
    expect(refusalOf(route("GET", "/bucket?uploads")).message).toContain("ListMultipartUploads");
    expect(refusalOf(route("GET", "/bucket/key?uploads")).message).toContain(
      "ListMultipartUploads",
    );
    expect(
      refusalOf(
        route("PUT", "/bucket/key?uploadId=u&partNumber=1", {
          "x-amz-copy-source": "/other/source",
        }),
      ).message,
    ).toContain("UploadPartCopy");
    expect(refusalOf(route("GET", "/bucket/key?partNumber=2"))).toMatchObject({
      code: "NotImplemented",
    });
    expect(refusalOf(route("HEAD", "/bucket/key?partNumber=2"))).toMatchObject({
      code: "NotImplemented",
    });
    expect(refusalOf(route("POST", "/bucket"))).toMatchObject({ code: "NotImplemented" });
  });

  it("answers MethodNotAllowed for a method S3 has no operation for", () => {
    for (const method of ["PATCH", "OPTIONS", "TRACE", "CONNECT", "get", "BREW"]) {
      expect(refusalOf(route(method, "/bucket/key")), method).toMatchObject({
        code: "MethodNotAllowed",
        status: 405,
      });
      expect(refusalOf(route(method, "/bucket")), method).toMatchObject({
        code: "MethodNotAllowed",
      });
      expect(refusalOf(route(method, "/")), method).toMatchObject({ code: "MethodNotAllowed" });
    }
    /* And for a supported method against the wrong resource. */
    expect(refusalOf(route("POST", "/bucket/key"))).toMatchObject({ code: "MethodNotAllowed" });
    expect(refusalOf(route("POST", "/bucket/key?delete"))).toMatchObject({
      code: "MethodNotAllowed",
    });
    expect(refusalOf(route("PUT", "/bucket?uploads"))).toMatchObject({ code: "MethodNotAllowed" });
    expect(refusalOf(route("GET", "/bucket?uploadId=u"))).toMatchObject({
      code: "MethodNotAllowed",
    });
    expect(refusalOf(route("PUT", "/"))).toMatchObject({ code: "MethodNotAllowed" });
  });

  it("carries the request path as the error document's Resource", () => {
    const routed = route("GET", "/bucket/deep/key?acl");
    expect(isRefusal(routed) && routed.resource).toBe("/bucket/deep/key");
  });

  it("refuses a bucket name a path segment cannot carry", () => {
    expect(refusalOf(route("GET", `/bad${NUL}bucket/key`))).toMatchObject({
      code: "InvalidBucketName",
      status: 400,
    });
    expect(refusalOf(route("GET", "/%2E%2E/key"))).toMatchObject({ code: "InvalidBucketName" });
    expect(refusalOf(route("GET", "//key"))).toMatchObject({ code: "InvalidBucketName" });
  });

  it("accepts the bucket names an operator can actually configure", () => {
    /* Not Amazon's naming rules: the bucket set is the operator's, so a name
       S3 would refuse is still a name `createS3Server()` can be handed. */
    for (const name of ["mountx", "MyBucket", "a_b", "bucket.with.dots", "x"]) {
      expect(isValidBucketName(name), name).toBe(true);
    }
    for (const name of ["", ".", "..", "a/b", `a${NUL}b`, "x".repeat(256)]) {
      expect(isValidBucketName(name), JSON.stringify(name)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------

describe("key validation", () => {
  it("maps a key onto a driver path and back", () => {
    const parsed = parseObjectKey("a/b/c.txt");
    expect(parsed.ok && parsed.key).toEqual({
      key: "a/b/c.txt",
      path: "/a/b/c.txt",
      directory: false,
    });
    expect(pathToKey("/a/b/c.txt")).toBe("a/b/c.txt");
    expect(pathToKey("/a/b", true)).toBe("a/b/");
    expect(pathToKey("/")).toBe("");
  });

  it("round-trips every key it accepts", () => {
    for (const key of ["a", "a/b", "a b/c+d", "dir/", "a.b/c.d", "unicode/ünïcødé.txt", "%41"]) {
      const parsed = parseObjectKey(key);
      expect(parsed.ok, key).toBe(true);
      if (parsed.ok) {
        expect(pathToKey(parsed.key.path, parsed.key.directory), key).toBe(key);
      }
    }
  });

  it("refuses the keys that would not survive the round trip", () => {
    for (const key of ["", "a//b", "/a", "a/./b", "a/../b", ".", "..", "a/..", "a/b//"]) {
      const parsed = parseObjectKey(key);
      expect(parsed.ok, JSON.stringify(key)).toBe(false);
      expect(parsed.ok ? undefined : parsed.error, JSON.stringify(key)).toMatchObject({
        code: "InvalidArgument",
        status: 400,
      });
    }
  });

  it("refuses a key containing NUL", () => {
    const parsed = parseObjectKey(`a${NUL}b`);
    expect(parsed.ok).toBe(false);
    expect(parsed.ok ? undefined : parsed.error.code).toBe("InvalidArgument");
  });

  it("measures the key limit in UTF-8 bytes, not characters", () => {
    const ascii = "k".repeat(MAX_KEY_BYTES);
    expect(parseObjectKey(ascii).ok).toBe(true);
    expect(parseObjectKey(`${ascii}k`).ok).toBe(false);
    /* A two-byte character straddling the limit: 1022 + 2 fits, 1023 + 2 does
       not, and a character count would call both of them 1024 or under. */
    const straddleFits = `${"k".repeat(MAX_KEY_BYTES - 2)}é`;
    const straddleOver = `${"k".repeat(MAX_KEY_BYTES - 1)}é`;
    expect(Buffer.byteLength(straddleFits, "utf8")).toBe(MAX_KEY_BYTES);
    expect(Buffer.byteLength(straddleOver, "utf8")).toBe(MAX_KEY_BYTES + 1);
    expect(straddleOver.length).toBeLessThanOrEqual(MAX_KEY_BYTES);
    expect(parseObjectKey(straddleFits).ok).toBe(true);
    const refused = parseObjectKey(straddleOver);
    expect(refused.ok).toBe(false);
    expect(refused.ok ? undefined : refused.error).toMatchObject({
      code: "KeyTooLongError",
      status: 400,
    });
  });

  it("refuses a key the router cannot map, naming the request path", () => {
    const routed = route("GET", "/bucket/a//b");
    expect(refusalOf(routed)).toMatchObject({ code: "InvalidArgument", status: 400 });
    expect(isRefusal(routed) && routed.resource).toBe("/bucket/a//b");
    expect(refusalOf(route("PUT", `/bucket/${"k".repeat(MAX_KEY_BYTES + 1)}`))).toMatchObject({
      code: "KeyTooLongError",
    });
  });

  it("recognizes the staging prefix only at a segment boundary", () => {
    expect(isStagingKey(MULTIPART_PREFIX)).toBe(true);
    expect(isStagingKey(`${MULTIPART_PREFIX}/upload-1/part-2`)).toBe(true);
    expect(isStagingKey(`${MULTIPART_PREFIX}/`)).toBe(true);
    expect(isStagingKey(`${MULTIPART_PREFIX}isan/x`)).toBe(false);
    expect(isStagingKey(`a/${MULTIPART_PREFIX}/x`)).toBe(false);
    /* A key that only starts with the same letters is an ordinary key. */
    expect(route("GET", `/bucket/${MULTIPART_PREFIX}isan/x`)).toMatchObject({ op: "GetObject" });
  });

  it("answers a staging key the way an absent key is answered, per method", () => {
    /* Invisibility is method-shaped: one answer for every method would itself
       be the tell, because S3 answers a missing key differently depending on
       what you asked to do with it. */
    for (const key of [MULTIPART_PREFIX, `${MULTIPART_PREFIX}/upload-1/part-2`]) {
      /* DELETE of a key that is not there is 204, with no body. */
      expect(route("DELETE", `/bucket/${key}`), key).toEqual({
        op: "Answered",
        status: 204,
        resource: `/bucket/${key}`,
      });
      expect(isAnswered(route("DELETE", `/bucket/${key}`)), key).toBe(true);
      /* GET and HEAD of a key that is not there is NoSuchKey. */
      for (const method of ["GET", "HEAD"]) {
        expect(refusalOf(route(method, `/bucket/${key}`)), `${method} ${key}`).toEqual({
          code: "NoSuchKey",
          status: 404,
          message: S3_ERRORS.NoSuchKey.message,
        });
      }
      /* PUT and POST answer NoSuchKey too, and this is the one tell that
         remains: a PUT to an absent key normally succeeds. Accepted knowingly —
         see `stagingAnswer()` — because the alternatives are worse (a 200 that
         drops the bytes, or an AccessDenied that says the name is guarded). */
      for (const method of ["PUT", "POST"]) {
        expect(refusalOf(route(method, `/bucket/${key}`)), `${method} ${key}`).toMatchObject({
          code: "NoSuchKey",
          status: 404,
        });
      }
      /* And a method with no operation at all is refused as it would be on any
         other key, which is the answer that gives nothing away. */
      expect(refusalOf(route("PATCH", `/bucket/${key}`)), key).toMatchObject({
        code: "MethodNotAllowed",
      });
    }
  });

  it("keeps the staging prefix out of a copy source, which is a read", () => {
    expect(parseCopySource(`/b/${MULTIPART_PREFIX}/x`)).toMatchObject({
      ok: false,
      error: { code: "NoSuchKey", status: 404 },
    });
    /* And `parseObjectKey()` on its own keeps the read-shaped answer. */
    const parsed = parseObjectKey(`${MULTIPART_PREFIX}/x`);
    expect(parsed.ok).toBe(false);
    expect(parsed.ok ? undefined : parsed.error.code).toBe("NoSuchKey");
  });
});

// ---------------------------------------------------------------------------

describe("parseRange", () => {
  const SIZE = 1000;

  it("parses the three forms RFC 9110 defines", () => {
    expect(parseRange("bytes=0-499", SIZE)).toEqual({
      kind: "range",
      start: 0,
      end: 499,
      length: 500,
    });
    expect(parseRange("bytes=500-999", SIZE)).toEqual({
      kind: "range",
      start: 500,
      end: 999,
      length: 500,
    });
    expect(parseRange("bytes=500-", SIZE)).toEqual({
      kind: "range",
      start: 500,
      end: 999,
      length: 500,
    });
    expect(parseRange("bytes=-500", SIZE)).toEqual({
      kind: "range",
      start: 500,
      end: 999,
      length: 500,
    });
    expect(parseRange("bytes=0-0", SIZE)).toEqual({ kind: "range", start: 0, end: 0, length: 1 });
  });

  it("clamps a last-byte-pos and a suffix past the end of the object", () => {
    expect(parseRange("bytes=0-9999", SIZE)).toEqual({
      kind: "range",
      start: 0,
      end: 999,
      length: 1000,
    });
    expect(parseRange("bytes=-9999", SIZE)).toEqual({
      kind: "range",
      start: 0,
      end: 999,
      length: 1000,
    });
  });

  it("answers unsatisfiable for a first-byte-pos at or past the end, and for -0", () => {
    expect(parseRange("bytes=1000-", SIZE)).toEqual({ kind: "unsatisfiable" });
    expect(parseRange("bytes=1000-1200", SIZE)).toEqual({ kind: "unsatisfiable" });
    expect(parseRange("bytes=-0", SIZE)).toEqual({ kind: "unsatisfiable" });
    expect(parseRange("bytes=99999999999999999999-", SIZE)).toEqual({ kind: "unsatisfiable" });
  });

  it("has no satisfiable byte range over an empty object", () => {
    expect(parseRange("bytes=0-", 0)).toEqual({ kind: "unsatisfiable" });
    expect(parseRange("bytes=0-0", 0)).toEqual({ kind: "unsatisfiable" });
    expect(parseRange("bytes=-1", 0)).toEqual({ kind: "unsatisfiable" });
    expect(parseRange(undefined, 0)).toEqual({ kind: "full" });
  });

  it("ignores a header it must not act on", () => {
    /* RFC 9110 §14.1.1: an invalid range spec makes the whole header invalid,
       and an invalid header is ignored. S3 additionally ignores multi-range —
       it answers 200 with the whole object rather than multipart/byteranges. */
    for (const value of [
      undefined,
      "",
      "bytes=0-499,600-700",
      "bytes=-",
      "bytes=abc-def",
      "bytes=500-499",
      "items=0-10",
      "0-10",
      "bytes 0-10",
      "bytes=",
    ]) {
      expect(parseRange(value, SIZE), String(value)).toEqual({ kind: "full" });
    }
  });

  it("accepts the unit case-insensitively and tolerates spacing", () => {
    expect(parseRange("Bytes=0-1", SIZE)).toEqual({ kind: "range", start: 0, end: 1, length: 2 });
    expect(parseRange("bytes = 0 - 1 ", SIZE)).toEqual({
      kind: "range",
      start: 0,
      end: 1,
      length: 2,
    });
  });

  it("hands back a fresh object every time", () => {
    const first = parseRange("nonsense", SIZE);
    const second = parseRange("nonsense", SIZE);
    expect(first).not.toBe(second);
  });
});

// ---------------------------------------------------------------------------

describe("HTTP dates", () => {
  const MOMENT = Date.UTC(1994, 10, 6, 8, 49, 37);

  it("reads all three formats RFC 9110 §5.6.7 requires a recipient to accept", () => {
    expect(parseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT")).toBe(MOMENT);
    expect(parseHttpDate("Sunday, 06-Nov-94 08:49:37 GMT")).toBe(MOMENT);
    expect(parseHttpDate("Sun Nov  6 08:49:37 1994")).toBe(MOMENT);
  });

  it("writes the preferred format", () => {
    expect(formatHttpDate(MOMENT)).toBe("Sun, 06 Nov 1994 08:49:37 GMT");
    expect(formatHttpDate(0)).toBe("Thu, 01 Jan 1970 00:00:00 GMT");
    expect(parseHttpDate(formatHttpDate(MOMENT))).toBe(MOMENT);
  });

  it("writes the ISO form S3's XML documents carry", () => {
    expect(formatIsoDate(MOMENT)).toBe("1994-11-06T08:49:37.000Z");
    expect(formatIsoDate(MOMENT + 250)).toBe("1994-11-06T08:49:37.250Z");
  });

  it("answers undefined for anything that is not an HTTP-date", () => {
    for (const value of [
      "",
      "not a date",
      "Sun, 06 Nov 1994 08:49:37",
      "Sun, 06 Nov 1994 08:49:37 UTC",
      "Sun, 31 Nov 1994 08:49:37 GMT",
      "Sun, 06 Foo 1994 08:49:37 GMT",
      "Sun, 06 Nov 1994 25:49:37 GMT",
      "1994-11-06T08:49:37Z",
    ]) {
      expect(parseHttpDate(value), JSON.stringify(value)).toBeUndefined();
    }
  });

  it("refuses a four-digit year under 100 rather than mapping it onto the 1900s", () => {
    /* `Date.UTC(99, ...)` is 1999, so a bare pass-through would read `0099` as
       a date twenty centuries away from the one it names. */
    expect(parseHttpDate("Sun, 06 Nov 0099 08:49:37 GMT")).toBeUndefined();
    expect(parseHttpDate("Sun Nov  6 08:49:37 0001")).toBeUndefined();
    expect(parseHttpDate("Sun, 06 Nov 0100 08:49:37 GMT")).toBe(Date.UTC(100, 10, 6, 8, 49, 37));
  });

  it("splits a two-digit year at 69/70", () => {
    expect(parseHttpDate("Thursday, 01-Jan-70 00:00:00 GMT")).toBe(Date.UTC(1970, 0, 1));
    expect(parseHttpDate("Friday, 01-Jan-69 00:00:00 GMT")).toBe(Date.UTC(2069, 0, 1));
  });

  it("reads a leap second as :59 rather than refusing it", () => {
    expect(parseHttpDate("Sun, 31 Dec 1995 23:59:60 GMT")).toBe(Date.UTC(1995, 11, 31, 23, 59, 59));
  });
});

// ---------------------------------------------------------------------------

describe("conditional requests", () => {
  const ETAG = "9f86d081884c7d65-1";
  const MTIME = Date.UTC(2026, 6, 28, 12, 0, 0);
  const BEFORE = formatHttpDate(MTIME - 60_000);
  const AFTER = formatHttpDate(MTIME + 60_000);
  const SAME = formatHttpDate(MTIME);
  const target = { etag: ETAG, mtimeMs: MTIME };

  /** RFC 9110 §13.2.2's precedence, one row per rule. */
  const MATRIX: readonly {
    what: string;
    headers: Record<string, string>;
    method?: string;
    status: 200 | 304 | 412;
  }[] = [
    { what: "nothing at all", headers: {}, status: 200 },
    { what: "If-Match on the tag", headers: { "if-match": `"${ETAG}"` }, status: 200 },
    { what: "If-Match on *", headers: { "if-match": "*" }, status: 200 },
    { what: "If-Match on another tag", headers: { "if-match": `"other"` }, status: 412 },
    {
      what: "If-Match in a list containing the tag",
      headers: { "if-match": `"other", "${ETAG}"` },
      status: 200,
    },
    { what: "If-None-Match on the tag", headers: { "if-none-match": `"${ETAG}"` }, status: 304 },
    { what: "If-None-Match on *", headers: { "if-none-match": "*" }, status: 304 },
    { what: "If-None-Match on another tag", headers: { "if-none-match": `"other"` }, status: 200 },
    {
      what: "If-None-Match on the tag, unsafe method",
      headers: { "if-none-match": `"${ETAG}"` },
      method: "PUT",
      status: 412,
    },
    {
      what: "If-None-Match on * , unsafe method",
      headers: { "if-none-match": "*" },
      method: "DELETE",
      status: 412,
    },
    {
      what: "If-Modified-Since before the mtime",
      headers: { "if-modified-since": BEFORE },
      status: 200,
    },
    {
      what: "If-Modified-Since after the mtime",
      headers: { "if-modified-since": AFTER },
      status: 304,
    },
    { what: "If-Modified-Since at the mtime", headers: { "if-modified-since": SAME }, status: 304 },
    {
      what: "If-Modified-Since on an unsafe method (not evaluated)",
      headers: { "if-modified-since": AFTER },
      method: "PUT",
      status: 200,
    },
    {
      what: "If-Unmodified-Since after the mtime",
      headers: { "if-unmodified-since": AFTER },
      status: 200,
    },
    {
      what: "If-Unmodified-Since before the mtime",
      headers: { "if-unmodified-since": BEFORE },
      status: 412,
    },
    {
      what: "If-Match wins over If-Unmodified-Since (step 2 is skipped)",
      headers: { "if-match": `"${ETAG}"`, "if-unmodified-since": BEFORE },
      status: 200,
    },
    {
      what: "a failing If-Match wins over a passing If-None-Match",
      headers: { "if-match": `"other"`, "if-none-match": `"other"` },
      status: 412,
    },
    {
      what: "If-None-Match wins over If-Modified-Since (step 4 is skipped)",
      headers: { "if-none-match": `"other"`, "if-modified-since": AFTER },
      status: 200,
    },
    {
      what: "a matching If-None-Match after a passing If-Match",
      headers: { "if-match": "*", "if-none-match": `"${ETAG}"` },
      status: 304,
    },
    {
      what: "an unparseable If-Modified-Since (ignored)",
      headers: { "if-modified-since": "yesterday" },
      status: 200,
    },
    {
      what: "an unparseable If-Unmodified-Since (ignored)",
      headers: { "if-unmodified-since": "tomorrow" },
      status: 200,
    },
    {
      what: "a weak If-None-Match tag against our strong one",
      headers: { "if-none-match": `W/"${ETAG}"` },
      status: 304,
    },
    {
      what: "a weak If-None-Match tag on an unsafe method",
      headers: { "if-none-match": `W/"${ETAG}"` },
      method: "PUT",
      status: 412,
    },
    {
      /* RFC 9110 §13.1.1: If-Match uses the *strong* comparison function, and
         §8.8.3.2's strong comparison fails whenever either tag is weak — the
         client's side included. */
      what: "a weak If-Match tag against our strong one",
      headers: { "if-match": `W/"${ETAG}"` },
      status: 412,
    },
    {
      what: "a weak If-Match tag on an unsafe method",
      headers: { "if-match": `W/"${ETAG}"` },
      method: "PUT",
      status: 412,
    },
    {
      what: "a list where only the weak tag matches If-Match",
      headers: { "if-match": `"other", W/"${ETAG}"` },
      status: 412,
    },
    {
      what: "a list where a strong tag matches If-Match beside a weak one",
      headers: { "if-match": `W/"other", "${ETAG}"` },
      status: 200,
    },
    {
      what: "If-Match * against a weak client tag elsewhere",
      headers: { "if-match": "*", "if-none-match": `W/"${ETAG}"` },
      status: 304,
    },
    { what: "an unquoted tag", headers: { "if-match": ETAG }, status: 200 },
  ];

  for (const row of MATRIX) {
    it(`answers ${row.status} for ${row.what}`, () => {
      expect(evaluateConditionals(target, headersOf(row.headers), row.method ?? "GET")).toEqual({
        status: row.status,
      });
    });
  }

  it("compares dates at one-second resolution, which is all an HTTP-date has", () => {
    const withMillis = { etag: ETAG, mtimeMs: MTIME + 300 };
    expect(
      evaluateConditionals(withMillis, headersOf({ "if-modified-since": SAME }), "GET"),
    ).toEqual({ status: 304 });
    expect(
      evaluateConditionals(withMillis, headersOf({ "if-unmodified-since": SAME }), "PUT"),
    ).toEqual({ status: 200 });
  });

  it("parses entity-tag lists, keeping the weakness marker", () => {
    expect(parseETagList("*")).toEqual({ any: true });
    expect(parseETagList(` * `)).toEqual({ any: true });
    expect(parseETagList(`"a", W/"b" ,"c"`)).toEqual({
      any: false,
      tags: [
        { value: "a", weak: false },
        { value: "b", weak: true },
        { value: "c", weak: false },
      ],
    });
    expect(parseETagList("")).toEqual({ any: false, tags: [] });
  });

  it("fails If-Match when our own ETag is weak, which is the other half of §8.8.3.2", () => {
    /* Every ETag this gateway produces is strong, so this can only happen to a
       caller that passes one in — but the comparison function is the standard's,
       not ours, and it is symmetric. */
    const weakTarget = { etag: `W/"${ETAG}"`, mtimeMs: MTIME };
    expect(evaluateConditionals(weakTarget, headersOf({ "if-match": `"${ETAG}"` }), "GET")).toEqual(
      { status: 412 },
    );
    /* The weak comparison still matches it. */
    expect(
      evaluateConditionals(weakTarget, headersOf({ "if-none-match": `"${ETAG}"` }), "GET"),
    ).toEqual({ status: 304 });
  });

  it("combines repeated list-based headers per RFC 9110 §5.3", () => {
    const headers: HeaderEntry[] = [
      { name: "If-None-Match", value: `"other"` },
      { name: "if-none-match", value: `"${ETAG}"` },
    ];
    expect(headerList(headers, "if-none-match")).toBe(`"other", "${ETAG}"`);
    /* Reading only the first line here would answer 200 where 304 is required. */
    expect(evaluateConditionals(target, headers, "GET")).toEqual({ status: 304 });
    expect(headerValue(headers, "if-none-match")).toBe(`"other"`);
    expect(headerList(headers, "if-match")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------

describe("x-amz-meta-mtime", () => {
  it("reads epoch seconds, whole or fractional", () => {
    expect(parseMetaMtime("1720000000")).toBe(1_720_000_000_000);
    expect(parseMetaMtime("1720000000.5")).toBe(1_720_000_000_500);
    expect(parseMetaMtime("1720000000.123456789")).toBe(1_720_000_000_123);
    expect(parseMetaMtime("0")).toBe(0);
    expect(parseMetaMtime("-86400")).toBe(-86_400_000);
  });

  it("ignores a value it cannot read, rather than failing the upload", () => {
    /* rclone compatibility: a bad meta header costs a timestamp, and S3 itself
       stores user metadata without ever reading it. */
    for (const value of [undefined, "", "now", "1e9", "0x10", "12.", ".5", " 12", "12 ", "NaN"]) {
      expect(parseMetaMtime(value), JSON.stringify(value)).toBeUndefined();
    }
    expect(parseMetaMtime("99999999999999999")).toBeUndefined();
    /* All digits, and still not a number `Number()` can hold. */
    expect(parseMetaMtime("9".repeat(400))).toBeUndefined();
  });

  it("writes a whole second without a fractional part", () => {
    expect(formatMetaMtime(1_720_000_000_000)).toBe("1720000000");
    expect(formatMetaMtime(1_720_000_000_500)).toBe("1720000000.500");
    expect(parseMetaMtime(formatMetaMtime(1_720_000_000_500))).toBe(1_720_000_000_500);
  });
});

// ---------------------------------------------------------------------------

describe("x-amz-copy-source", () => {
  it("accepts both documented forms and decodes the key once", () => {
    expect(parseCopySource("/src-bucket/a%20b/c.txt")).toEqual({
      ok: true,
      source: { bucket: "src-bucket", key: "a b/c.txt", path: "/a b/c.txt", directory: false },
    });
    expect(parseCopySource("src-bucket/a%20b/c.txt")).toEqual({
      ok: true,
      source: { bucket: "src-bucket", key: "a b/c.txt", path: "/a b/c.txt", directory: false },
    });
  });

  it("finds the versionId separator before decoding, not after", () => {
    /* An encoded `%3F` inside a key is part of the key; only a literal `?`
       starts the query. */
    expect(parseCopySource("/b/key%3Fnot-a-query")).toEqual({
      ok: true,
      source: { bucket: "b", key: "key?not-a-query", path: "/key?not-a-query", directory: false },
    });
  });

  it("accepts the null version and refuses a real one", () => {
    expect(parseCopySource("/b/k?versionId=null")).toMatchObject({ ok: true });
    const refused = parseCopySource("/b/k?versionId=3sL4kqtJlcpXroDTDmJ%2BrmSpXd3dIbrHY");
    expect(refused.ok).toBe(false);
    expect(refused.ok ? undefined : refused.error).toMatchObject({
      code: "NotImplemented",
      status: 501,
    });
  });

  it("accepts a bare ?versionId and refuses a malformed escape anywhere in the value", () => {
    expect(parseCopySource("/b/k?versionId")).toMatchObject({ ok: true });
    expect(parseCopySource("/b/k?other=1&versionId=null")).toMatchObject({ ok: true });
    expect(parseCopySource("/b/k?versionId=%zz")).toMatchObject({
      ok: false,
      error: { code: "InvalidArgument" },
    });
    expect(parseCopySource("/b/%zz")).toMatchObject({
      ok: false,
      error: { code: "InvalidArgument" },
    });
  });

  it("refuses a source that names no key", () => {
    for (const value of ["/just-a-bucket", "just-a-bucket", "/b/", "", "/", "//key"]) {
      const parsed = parseCopySource(value);
      expect(parsed.ok, JSON.stringify(value)).toBe(false);
      expect(parsed.ok ? undefined : parsed.error.code, JSON.stringify(value)).toBe(
        "InvalidArgument",
      );
    }
  });

  it("refuses a source key that is not a key", () => {
    expect(parseCopySource("/b/a//c").ok).toBe(false);
    expect(parseCopySource(`/b/${MULTIPART_PREFIX}/x`)).toMatchObject({
      ok: false,
      error: { code: "NoSuchKey" },
    });
  });
});

// ---------------------------------------------------------------------------

describe("request bodies", () => {
  it("reads Content-Encoding as a list of tokens", () => {
    expect(contentCodings(undefined)).toEqual([]);
    expect(contentCodings("aws-chunked")).toEqual(["aws-chunked"]);
    expect(contentCodings(" AWS-Chunked , gzip ")).toEqual(["aws-chunked", "gzip"]);
    expect(contentCodings(",,")).toEqual([]);
  });

  it("reads the framing from the two headers that carry it", () => {
    expect(bodyMode(headersOf({}))).toEqual({
      framing: "identity",
      signedChunks: false,
      trailers: false,
      payloadHash: undefined,
    });
    expect(bodyMode(headersOf({ "x-amz-content-sha256": UNSIGNED_PAYLOAD }))).toEqual({
      framing: "identity",
      signedChunks: false,
      trailers: false,
      payloadHash: UNSIGNED_PAYLOAD,
    });
    expect(bodyMode(headersOf({ "x-amz-content-sha256": STREAMING_PAYLOAD }))).toEqual({
      framing: "aws-chunked",
      signedChunks: true,
      trailers: false,
      payloadHash: STREAMING_PAYLOAD,
    });
    expect(bodyMode(headersOf({ "x-amz-content-sha256": STREAMING_PAYLOAD_TRAILER }))).toEqual({
      framing: "aws-chunked",
      signedChunks: true,
      trailers: true,
      payloadHash: STREAMING_PAYLOAD_TRAILER,
    });
    expect(
      bodyMode(headersOf({ "x-amz-content-sha256": STREAMING_UNSIGNED_PAYLOAD_TRAILER })),
    ).toEqual({
      framing: "aws-chunked",
      signedChunks: false,
      trailers: true,
      payloadHash: STREAMING_UNSIGNED_PAYLOAD_TRAILER,
    });
  });

  it("sees the framing that lives only in Content-Encoding", () => {
    /* The one shape `streamingPayloadKind()` cannot answer for: framed, but
       unsigned and without trailers. */
    const hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(
      bodyMode(headersOf({ "content-encoding": "aws-chunked,gzip", "x-amz-content-sha256": hash })),
    ).toEqual({ framing: "aws-chunked", signedChunks: false, trailers: false, payloadHash: hash });
  });

  it("parses the two declared lengths", () => {
    const parsed = parseContentLengths(
      headersOf({ "content-length": "1234", "x-amz-decoded-content-length": "1000" }),
    );
    expect(parsed).toEqual({
      ok: true,
      lengths: { contentLength: 1234, decodedContentLength: 1000 },
    });
    expect(parseContentLengths(headersOf({}))).toEqual({
      ok: true,
      lengths: { contentLength: undefined, decodedContentLength: undefined },
    });
  });

  it("refuses a length that is not a plain non-negative integer", () => {
    for (const value of ["-1", "1.5", "0x10", "1e3", "", "12abc", "+12"]) {
      expect(parseContentLengths(headersOf({ "content-length": value })), value).toMatchObject({
        ok: false,
        error: { code: "InvalidArgument", status: 400 },
      });
      expect(
        parseContentLengths(headersOf({ "x-amz-decoded-content-length": value })),
        value,
      ).toMatchObject({ ok: false, error: { code: "InvalidArgument" } });
    }
    expect(parseUnsignedInteger(String(Number.MAX_SAFE_INTEGER))).toBe(Number.MAX_SAFE_INTEGER);
    expect(parseUnsignedInteger("9007199254740993")).toBeUndefined();
    expect(parseUnsignedInteger("007")).toBe(7);
  });
});

// ---------------------------------------------------------------------------

describe("response headers", () => {
  const MTIME = Date.UTC(2026, 6, 28, 12, 34, 56);

  it("builds the headers of a whole-object reply", () => {
    expect(objectResponseHeaders({ etag: "abc123-1", size: 4096, mtimeMs: MTIME })).toEqual({
      "content-type": "application/octet-stream",
      "content-length": "4096",
      etag: `"abc123-1"`,
      "last-modified": "Tue, 28 Jul 2026 12:34:56 GMT",
      "accept-ranges": "bytes",
      "x-amz-meta-mtime": "1785242096",
    });
  });

  it("builds the headers of a ranged reply", () => {
    expect(
      objectResponseHeaders({
        etag: `"def456-1"`,
        size: 100,
        mtimeMs: MTIME + 500,
        contentRange: { start: 10, end: 109, total: 8192 },
      }),
    ).toEqual({
      "content-type": "application/octet-stream",
      "content-length": "100",
      etag: `"def456-1"`,
      "last-modified": "Tue, 28 Jul 2026 12:34:56 GMT",
      "accept-ranges": "bytes",
      "x-amz-meta-mtime": "1785242096.500",
      "content-range": "bytes 10-109/8192",
    });
  });

  it("quotes an ETag exactly once", () => {
    expect(formatETag("abc")).toBe(`"abc"`);
    expect(formatETag(`"abc"`)).toBe(`"abc"`);
  });

  it("writes both Content-Range forms", () => {
    expect(formatContentRange(0, 499, 1234)).toBe("bytes 0-499/1234");
    expect(formatUnsatisfiedRange(1234)).toBe("bytes */1234");
  });
});

// ---------------------------------------------------------------------------

describe("error rendering", () => {
  it("renders the document S3's error-responses page describes", () => {
    /* Every field distinct, so a transposed Resource/RequestId would fail. */
    const response = s3ErrorResponse(s3Error("NoSuchKey"), {
      resource: "/photo-bucket/trips/rome.txt",
      requestId: "4442587FB7D0A2F9",
      hostId: "cURqCLnGhLu0Y3xUoQ",
    });
    expect(response.status).toBe(404);
    expect(response.headers).toEqual({
      "content-type": "application/xml",
      "content-length": String(response.body.byteLength),
      "x-amz-request-id": "4442587FB7D0A2F9",
      "x-amz-id-2": "cURqCLnGhLu0Y3xUoQ",
    });
    expect(Buffer.from(response.body).toString("utf8")).toBe(
      `<?xml version="1.0" encoding="UTF-8"?><Error>` +
        `<Code>NoSuchKey</Code>` +
        `<Message>The specified key does not exist.</Message>` +
        `<Resource>/photo-bucket/trips/rome.txt</Resource>` +
        `<RequestId>4442587FB7D0A2F9</RequestId>` +
        `<HostId>cURqCLnGhLu0Y3xUoQ</HostId>` +
        `</Error>`,
    );
  });

  it("omits what the caller did not supply", () => {
    const response = s3ErrorResponse(
      s3Error("MethodNotAllowed", "The method BREW is not allowed."),
    );
    expect(response.status).toBe(405);
    expect(response.headers["x-amz-request-id"]).toBeUndefined();
    expect(Buffer.from(response.body).toString("utf8")).toBe(
      `<?xml version="1.0" encoding="UTF-8"?><Error>` +
        `<Code>MethodNotAllowed</Code>` +
        `<Message>The method BREW is not allowed.</Message>` +
        `</Error>`,
    );
  });

  it("escapes what a client put in the path", () => {
    const response = s3ErrorResponse(s3Error("NoSuchKey"), { resource: `/b/<a&b>"c"` });
    expect(Buffer.from(response.body).toString("utf8")).toContain(
      `<Resource>/b/&lt;a&amp;b&gt;&quot;c&quot;</Resource>`,
    );
  });

  it("gives every catalogued error a usable code, status and message", () => {
    for (const [name, spec] of Object.entries(S3_ERRORS)) {
      expect(spec.code, name).toBe(name);
      expect(spec.status, name).toBeGreaterThanOrEqual(400);
      expect(spec.status, name).toBeLessThan(600);
      expect(spec.message.length, name).toBeGreaterThan(0);
    }
  });

  it("has a row for every code the errno table can produce", () => {
    /* `ERRNO_S3_ERRORS` maps a driver's errno to a code and a status but has no
       message; this catalogue is where the message comes from. The two live in
       different files, so nothing but this test would notice them drifting. */
    const byCode = new Map<string, S3ErrorSpec>(
      Object.values(S3_ERRORS).map((spec) => [spec.code, spec]),
    );
    for (const [errno, error] of Object.entries(ERRNO_S3_ERRORS)) {
      const row = byCode.get(error.code);
      expect(row, `${errno} -> ${error.code}`).toBeDefined();
      expect(row?.status, `${errno} -> ${error.code}`).toBe(error.status);
    }
  });

  it("lets a caller replace the message without touching the code or status", () => {
    expect(s3Error("InvalidArgument", "Invalid List Type: 3")).toEqual({
      code: "InvalidArgument",
      status: 400,
      message: "Invalid List Type: 3",
    });
    expect(s3Error("InvalidArgument")).toEqual({
      code: "InvalidArgument",
      status: 400,
      message: "Invalid Argument",
    });
  });
});

// ---------------------------------------------------------------------------

describe("the refusal mapping tables", () => {
  const XML_REFUSALS: readonly XmlRefusal[] = [
    "too-large",
    "encoding",
    "invalid-character",
    "malformed",
    "doctype",
    "entity",
    "depth",
    "too-many-elements",
    "unexpected-root",
    "missing-field",
    "duplicate-field",
    "invalid-field",
  ];

  const CHUNKED_REFUSALS: readonly ChunkedRefusal[] = [
    "bad-size",
    "too-large",
    "malformed",
    "missing-signature",
    "signature-mismatch",
    "truncated",
    "trailing-bytes",
    "length-mismatch",
    "trailer",
    "internal",
  ];

  const SIGV4_REFUSALS = [
    "missing",
    "malformed",
    "unsupported-algorithm",
    "unknown-access-key",
    "scope-mismatch",
    "clock-skew",
    "expired",
    "signature-mismatch",
  ] as const;

  it("answers for every XML refusal, and only those", () => {
    expect(Object.keys(XML_REFUSAL_ERRORS).sort()).toEqual([...XML_REFUSALS].sort());
    for (const reason of XML_REFUSALS) {
      expect(xmlRefusalError(reason).code, reason).toMatch(/^[A-Za-z]+$/);
      expect(xmlRefusalError(reason).status, reason).toBe(400);
    }
  });

  it("calls an oversized request document MaxMessageLengthExceeded, not EntityTooLarge", () => {
    /* The two codes are about different things: EntityTooLarge is "your
       proposed upload exceeds the maximum allowed object size", and every body
       the XML parser sees is a request document, never object content. The
       chunked decoder's `too-large` *is* object content, and keeps the other
       code — which is the distinction doing its job. */
    expect(xmlRefusalError("too-large")).toEqual({
      code: "MaxMessageLengthExceeded",
      status: 400,
      message: "Your request was too big.",
    });
    expect(chunkedRefusalError("too-large").code).toBe("EntityTooLarge");
  });

  it("maps every other XML refusal to MalformedXML", () => {
    for (const reason of XML_REFUSALS) {
      if (reason !== "too-large") {
        expect(xmlRefusalError(reason).code, reason).toBe("MalformedXML");
      }
    }
  });

  it("carries the parser's own message when it has one", () => {
    expect(xmlRefusalError("depth", "too deep at offset 12").message).toBe("too deep at offset 12");
    expect(chunkedRefusalError("truncated", "ran out at 7").message).toBe("ran out at 7");
  });

  it("answers for every chunked refusal, in the three groups its docs name", () => {
    expect(Object.keys(CHUNKED_REFUSAL_ERRORS).sort()).toEqual([...CHUNKED_REFUSALS].sort());
    expect(chunkedRefusalError("signature-mismatch")).toMatchObject({
      code: "SignatureDoesNotMatch",
      status: 403,
    });
    expect(chunkedRefusalError("missing-signature")).toMatchObject({
      code: "SignatureDoesNotMatch",
      status: 403,
    });
    for (const reason of ["truncated", "trailing-bytes", "length-mismatch"] as const) {
      expect(chunkedRefusalError(reason), reason).toMatchObject({
        code: "IncompleteBody",
        status: 400,
      });
    }
    for (const reason of ["bad-size", "malformed", "trailer"] as const) {
      expect(chunkedRefusalError(reason), reason).toMatchObject({
        code: "InvalidRequest",
        status: 400,
      });
    }
    expect(chunkedRefusalError("internal")).toMatchObject({ code: "InternalError", status: 500 });
  });

  it("answers for every SigV4 refusal", () => {
    expect(Object.keys(SIGV4_REFUSAL_ERRORS).sort()).toEqual([...SIGV4_REFUSALS].sort());
    expect(sigv4RefusalError("signature-mismatch")).toMatchObject({
      code: "SignatureDoesNotMatch",
      status: 403,
    });
    expect(sigv4RefusalError("clock-skew")).toMatchObject({
      code: "RequestTimeTooSkewed",
      status: 403,
    });
    expect(sigv4RefusalError("unknown-access-key")).toMatchObject({
      code: "InvalidAccessKeyId",
      status: 403,
    });
    expect(sigv4RefusalError("missing")).toMatchObject({ code: "AccessDenied", status: 403 });
    expect(sigv4RefusalError("unsupported-algorithm")).toEqual({
      code: "InvalidRequest",
      status: 400,
      message: "Please use AWS4-HMAC-SHA256.",
    });
  });

  it("answers an expired presigned URL the way S3 does, verbatim", () => {
    /* AccessDenied with "Request has expired", 403 — not ExpiredToken, which is
       about an STS session token and is a 400. */
    expect(sigv4RefusalError("expired", "presigned")).toEqual({
      code: "AccessDenied",
      status: 403,
      message: "Request has expired",
    });
    expect(sigv4RefusalError("expired")).toMatchObject({ code: "AccessDenied" });
  });

  it("spells a malformed signature differently in each form", () => {
    expect(sigv4RefusalError("malformed", "header").code).toBe("AuthorizationHeaderMalformed");
    expect(sigv4RefusalError("malformed", "presigned").code).toBe(
      "AuthorizationQueryParametersError",
    );
    expect(sigv4RefusalError("scope-mismatch", "header").code).toBe("AuthorizationHeaderMalformed");
    expect(sigv4RefusalError("scope-mismatch", "presigned").code).toBe(
      "AuthorizationQueryParametersError",
    );
    /* Everything else is the same in both forms. */
    for (const reason of SIGV4_REFUSALS) {
      if (reason !== "malformed" && reason !== "scope-mismatch") {
        expect(sigv4RefusalError(reason, "presigned"), reason).toEqual(
          sigv4RefusalError(reason, "header"),
        );
      }
    }
  });

  it("hands back a fresh spec every time, so a caller can add a message", () => {
    const first = sigv4RefusalError("missing");
    first.message = "changed";
    expect(sigv4RefusalError("missing").message).toBe("Access Denied");
    expect(xmlRefusalError("malformed")).not.toBe(XML_REFUSAL_ERRORS.malformed);
  });
});
