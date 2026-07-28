/**
 * The errno → S3 error table and the protocol limits.
 *
 * Two things are worth a test here and the rest is transcription. The first is
 * **totality**: `s3ErrorOf()` is on the error path of every request, so it has
 * to answer for every errno `src/errors.ts` can produce and for anything it has
 * never heard of, without the caller checking. The second is the *shape* of the
 * answers — a status outside the HTTP range or an empty code would produce a
 * reply no client can read, which is the one failure mode a gateway must not
 * have.
 *
 * The individual mappings that are load-bearing decisions (rather than
 * one-to-one names) are asserted by hand, with the reasoning in
 * `src/s3/constants.ts` beside each row.
 */

import { describe, expect, it } from "vitest";
import { ERRNO_CODES, type ErrnoCode } from "../../src/errors.ts";
import {
  ERRNO_S3_ERRORS,
  MAX_KEY_BYTES,
  MAX_KEYS,
  MAX_PART_SIZE,
  MAX_PARTS,
  MIN_PART_SIZE,
  MULTIPART_PREFIX,
  S3_INTERNAL_ERROR,
  s3ErrorOf,
  STREAMING_PAYLOAD,
  UNSIGNED_PAYLOAD,
} from "../../src/s3/constants.ts";

const ERRNO_NAMES = Object.keys(ERRNO_CODES) as ErrnoCode[];

describe("the errno table", () => {
  it("answers for every errno a driver can throw", () => {
    for (const name of ERRNO_NAMES) {
      const error = s3ErrorOf(name);
      expect(error, name).toBe(ERRNO_S3_ERRORS[name]);
    }
    expect(Object.keys(ERRNO_S3_ERRORS).sort()).toEqual([...ERRNO_NAMES].sort());
  });

  it("gives every row a usable code and a real HTTP status", () => {
    for (const name of ERRNO_NAMES) {
      const error = ERRNO_S3_ERRORS[name];
      expect(error.code, name).toMatch(/^[A-Za-z]+$/);
      expect(error.status, name).toBeGreaterThanOrEqual(400);
      expect(error.status, name).toBeLessThan(600);
    }
  });

  it("maps the errnos the S3 error-responses page names outright", () => {
    expect(s3ErrorOf("ENOENT")).toEqual({ code: "NoSuchKey", status: 404 });
    expect(s3ErrorOf("EACCES")).toEqual({ code: "AccessDenied", status: 403 });
    expect(s3ErrorOf("EPERM")).toEqual({ code: "AccessDenied", status: 403 });
    expect(s3ErrorOf("EFBIG")).toEqual({ code: "EntityTooLarge", status: 400 });
    expect(s3ErrorOf("EINVAL")).toEqual({ code: "InvalidArgument", status: 400 });
    expect(s3ErrorOf("ENAMETOOLONG")).toEqual({ code: "KeyTooLongError", status: 400 });
  });

  it("answers a capability this driver does not have with NotImplemented", () => {
    expect(s3ErrorOf("ENOSYS")).toEqual({ code: "NotImplemented", status: 501 });
    expect(s3ErrorOf("ENOTSUP")).toEqual({ code: "NotImplemented", status: 501 });
  });

  it("answers a non-empty directory with a 409, as the plan requires", () => {
    expect(s3ErrorOf("ENOTEMPTY")).toEqual({ code: "BucketNotEmpty", status: 409 });
  });

  it("falls back to InternalError for anything it has never heard of", () => {
    expect(s3ErrorOf(undefined)).toBe(S3_INTERNAL_ERROR);
    expect(s3ErrorOf("")).toBe(S3_INTERNAL_ERROR);
    expect(s3ErrorOf("EWHATEVER")).toBe(S3_INTERNAL_ERROR);
    expect(S3_INTERNAL_ERROR).toEqual({ code: "InternalError", status: 500 });
  });

  it("does not mistake an inherited property for a row", () => {
    /* The lookup is `Object.hasOwn`, not `in`: `s3ErrorOf("toString")` must not
       come back holding a function. */
    for (const name of ["toString", "constructor", "__proto__", "hasOwnProperty"]) {
      expect(s3ErrorOf(name), name).toBe(S3_INTERNAL_ERROR);
    }
  });
});

describe("the protocol limits", () => {
  it("carries the ListObjectsV2 page size", () => {
    expect(MAX_KEYS).toBe(1000);
  });

  it("carries the multipart limits, in bytes and in parts", () => {
    expect(MIN_PART_SIZE).toBe(5 * 1024 * 1024);
    expect(MAX_PART_SIZE).toBe(5 * 1024 * 1024 * 1024);
    expect(MAX_PARTS).toBe(10_000);
    expect(MAX_PART_SIZE).toBeGreaterThan(MIN_PART_SIZE);
  });

  it("carries the key limit as a byte count", () => {
    expect(MAX_KEY_BYTES).toBe(1024);
  });

  it("stages multipart uploads under a prefix no key of ours can collide with", () => {
    expect(MULTIPART_PREFIX).toBe(".mountx-multipart");
    expect(MULTIPART_PREFIX).not.toContain("/");
  });

  it("spells the two payload sentinels exactly as SigV4 does", () => {
    expect(UNSIGNED_PAYLOAD).toBe("UNSIGNED-PAYLOAD");
    expect(STREAMING_PAYLOAD).toBe("STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
  });
});
