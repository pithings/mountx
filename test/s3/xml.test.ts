/**
 * The S3 XML codec.
 *
 * **The goldens are transcribed from the Amazon S3 API Reference**, one named
 * page per fixture: the "Examples" block of `ListBuckets`, `ListObjectsV2`,
 * `DeleteObjects`, `CopyObject`, `CreateMultipartUpload`,
 * `CompleteMultipartUpload` and `ListParts`, and the "Error responses" page for
 * `<Error>`. Values are transcribed **except where the comment above a fixture
 * says otherwise**, which happens for three reasons and only these:
 *
 * - AWS pretty-prints its examples and `src/s3/xml.ts` emits no whitespace at
 *   all, so every golden is the reference's *element tree and values*
 *   serialized by this codec's rules. The layout is ours and is asserted byte
 *   for byte.
 * - Where a reference example repeats a value across two fields (`ListParts`
 *   gives both its parts the same `<Size>`), the fixture **varies** it. A
 *   fixture built from repeated values passes with two fields transposed, which
 *   `AGENTS.md` names as the way a symmetric encode bug hides; every field of
 *   every fixture below holds a distinct value, and where two are equal it is
 *   because the protocol makes them equal and the comment says so.
 * - Where no single example exercises a document's optional members, the
 *   fixture is a **composite** of several, and its comment names the example
 *   each value came from and marks the ones invented to fill a gap.
 *
 * **No literal control characters appear in this file.** The escaping cases
 * build theirs with `String.fromCodePoint`, which keeps the source NUL-free and
 * grep-able (`AGENTS.md`) — and keeps an editor from silently turning a `\u`
 * escape into the byte it names.
 */

import { describe, expect, it } from "vitest";
import { MAX_PARTS } from "../../src/s3/constants.ts";
import {
  type CompleteMultipartUploadRequest,
  type DeleteObjectsRequest,
  encodeCompleteMultipartUploadResult,
  encodeCopyObjectResult,
  encodeDeleteResult,
  encodeInitiateMultipartUploadResult,
  encodeListAllMyBucketsResult,
  encodeListBucketResult,
  encodeListPartsResult,
  encodeS3ErrorDocument,
  escapeXmlText,
  isXmlChar,
  isXmlError,
  parseCompleteMultipartUpload,
  parseDeleteObjects,
  parseXml,
  S3_XMLNS,
  XML_DECLARATION,
  XML_MAX_DEPTH_CEILING,
  XML_REPLACEMENT,
  type XmlRefusal,
  xmlDocument,
} from "../../src/s3/xml.ts";
import { Rng } from "../fuse/random.ts";

const XMLNS = ` xmlns="${S3_XMLNS}"`;

/** The reason a call refused, or `"(no throw)"` — as one assertable value. */
function refusalOf(call: () => unknown): XmlRefusal | "(no throw)" {
  try {
    call();
  } catch (error) {
    if (!isXmlError(error)) {
      throw error;
    }
    return error.reason;
  }
  return "(no throw)";
}

// ---------------------------------------------------------------------------
// the response goldens
// ---------------------------------------------------------------------------

describe("the response documents", () => {
  // S3 API Reference, "Error responses". The one document with no xmlns: AWS
  // sends `<Error>` bare.
  it("encodes an Error", () => {
    expect(
      encodeS3ErrorDocument({
        code: "NoSuchKey",
        message: "The resource you requested does not exist",
        resource: "/mybucket/myfoto.jpg",
        requestId: "4442587FB7D0A2F9",
      }),
    ).toBe(
      `${XML_DECLARATION}<Error>` +
        `<Code>NoSuchKey</Code>` +
        `<Message>The resource you requested does not exist</Message>` +
        `<Resource>/mybucket/myfoto.jpg</Resource>` +
        `<RequestId>4442587FB7D0A2F9</RequestId>` +
        `</Error>`,
    );
  });

  it("drops the optional parts of an Error it was not given", () => {
    expect(encodeS3ErrorDocument({ code: "NotImplemented", message: "not supported here" })).toBe(
      `${XML_DECLARATION}<Error>` +
        `<Code>NotImplemented</Code><Message>not supported here</Message>` +
        `</Error>`,
    );
  });

  // S3 API Reference, `ListBuckets`. This is the classic example — the owner
  // and the `quotes`/`samples` buckets — from an earlier revision of the page;
  // the current one shows different samples and, like several pages, prints
  // them without the declaration or the xmlns. The framing here is what real S3
  // sends, which is what a client has to parse.
  it("encodes a ListAllMyBucketsResult", () => {
    expect(
      encodeListAllMyBucketsResult({
        owner: { id: "bcaf1ffd86f41161ca5fb16fd081034f", displayName: "webfile" },
        buckets: [
          { name: "quotes", creationDate: "2006-02-03T16:45:09.000Z" },
          { name: "samples", creationDate: "2006-02-03T16:41:58.000Z" },
        ],
      }),
    ).toBe(
      `${XML_DECLARATION}<ListAllMyBucketsResult${XMLNS}>` +
        `<Owner><ID>bcaf1ffd86f41161ca5fb16fd081034f</ID><DisplayName>webfile</DisplayName></Owner>` +
        `<Buckets>` +
        `<Bucket><Name>quotes</Name><CreationDate>2006-02-03T16:45:09.000Z</CreationDate></Bucket>` +
        `<Bucket><Name>samples</Name><CreationDate>2006-02-03T16:41:58.000Z</CreationDate></Bucket>` +
        `</Buckets>` +
        `</ListAllMyBucketsResult>`,
    );
  });

  // A **composite** of the `ListObjectsV2` examples, because no single one
  // carries every optional member: the bucket name `example-bucket`,
  // `photos/2006/` with the `/` delimiter and the two `<CommonPrefixes>` are
  // the delimiter example's, the `<Contents>` ETag and Size are the first
  // example's, and `NextContinuationToken` is the truncated example's (its
  // value shortened here, since the real token is a page of base64 and its
  // length pins nothing). Invented to fill gaps: the key
  // `photos/2006/index.html`, `KeyCount 3` and `IsTruncated true` appear in
  // no example. The element *order* is the one the examples agree on and is
  // the point of the assertion.
  it("encodes a ListBucketResult", () => {
    expect(
      encodeListBucketResult({
        name: "example-bucket",
        prefix: "photos/2006/",
        delimiter: "/",
        keyCount: 3,
        maxKeys: 1000,
        isTruncated: true,
        nextContinuationToken: "1ueGcxLPRx1Tr",
        contents: [
          {
            key: "photos/2006/index.html",
            lastModified: "2009-10-12T17:50:30.000Z",
            etag: '"fba9dede5f27731c9771645a39863328"',
            size: 434_234,
            storageClass: "STANDARD",
          },
        ],
        commonPrefixes: ["photos/2006/February/", "photos/2006/January/"],
      }),
    ).toBe(
      `${XML_DECLARATION}<ListBucketResult${XMLNS}>` +
        `<Name>example-bucket</Name>` +
        `<Prefix>photos/2006/</Prefix>` +
        `<NextContinuationToken>1ueGcxLPRx1Tr</NextContinuationToken>` +
        `<KeyCount>3</KeyCount>` +
        `<MaxKeys>1000</MaxKeys>` +
        `<Delimiter>/</Delimiter>` +
        `<IsTruncated>true</IsTruncated>` +
        `<Contents>` +
        `<Key>photos/2006/index.html</Key>` +
        `<LastModified>2009-10-12T17:50:30.000Z</LastModified>` +
        `<ETag>&quot;fba9dede5f27731c9771645a39863328&quot;</ETag>` +
        `<Size>434234</Size>` +
        `<StorageClass>STANDARD</StorageClass>` +
        `</Contents>` +
        `<CommonPrefixes><Prefix>photos/2006/February/</Prefix></CommonPrefixes>` +
        `<CommonPrefixes><Prefix>photos/2006/January/</Prefix></CommonPrefixes>` +
        `</ListBucketResult>`,
    );
  });

  it("emits an empty Prefix when the request had none, as S3 does", () => {
    expect(
      encodeListBucketResult({
        name: "bucket",
        keyCount: 0,
        maxKeys: 1000,
        isTruncated: false,
        contents: [],
      }),
    ).toBe(
      `${XML_DECLARATION}<ListBucketResult${XMLNS}>` +
        `<Name>bucket</Name><Prefix></Prefix>` +
        `<KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>` +
        `</ListBucketResult>`,
    );
  });

  // S3 API Reference, `DeleteObjects` → Examples.
  it("encodes a DeleteResult", () => {
    expect(
      encodeDeleteResult({
        deleted: [{ key: "sample1.txt" }],
        errors: [{ key: "sample2.txt", code: "AccessDenied", message: "Access Denied" }],
      }),
    ).toBe(
      `${XML_DECLARATION}<DeleteResult${XMLNS}>` +
        `<Deleted><Key>sample1.txt</Key></Deleted>` +
        `<Error><Key>sample2.txt</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error>` +
        `</DeleteResult>`,
    );
  });

  // S3 API Reference, `CopyObject` → Examples.
  it("encodes a CopyObjectResult", () => {
    expect(
      encodeCopyObjectResult({
        lastModified: "2009-10-28T22:32:00.000Z",
        etag: '"9b2cf535f27731c974343645a3985328"',
      }),
    ).toBe(
      `${XML_DECLARATION}<CopyObjectResult${XMLNS}>` +
        `<LastModified>2009-10-28T22:32:00.000Z</LastModified>` +
        `<ETag>&quot;9b2cf535f27731c974343645a3985328&quot;</ETag>` +
        `</CopyObjectResult>`,
    );
  });

  // S3 API Reference, `CreateMultipartUpload` → Examples.
  it("encodes an InitiateMultipartUploadResult", () => {
    expect(
      encodeInitiateMultipartUploadResult({
        bucket: "example-bucket",
        key: "example-object",
        uploadId: "VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA",
      }),
    ).toBe(
      `${XML_DECLARATION}<InitiateMultipartUploadResult${XMLNS}>` +
        `<Bucket>example-bucket</Bucket>` +
        `<Key>example-object</Key>` +
        `<UploadId>VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA</UploadId>` +
        `</InitiateMultipartUploadResult>`,
    );
  });

  // S3 API Reference, `CompleteMultipartUpload` → Examples. `Bucket` and `Key`
  // also appear inside `Location` because S3 builds that URL out of them.
  it("encodes a CompleteMultipartUploadResult", () => {
    expect(
      encodeCompleteMultipartUploadResult({
        location: "http://example-bucket.s3.eu-west-1.amazonaws.com/example-object",
        bucket: "example-bucket",
        key: "example-object",
        etag: '"3858f62230ac3c915f300c664312c11f-9"',
      }),
    ).toBe(
      `${XML_DECLARATION}<CompleteMultipartUploadResult${XMLNS}>` +
        `<Location>http://example-bucket.s3.eu-west-1.amazonaws.com/example-object</Location>` +
        `<Bucket>example-bucket</Bucket>` +
        `<Key>example-object</Key>` +
        `<ETag>&quot;3858f62230ac3c915f300c664312c11f-9&quot;</ETag>` +
        `</CompleteMultipartUploadResult>`,
    );
  });

  // S3 API Reference, `ListParts` → Examples. Two values are **varied** from
  // the page for the all-distinct rule: the second part's `<Size>`, which the
  // example gives the same 10485760 as the first, and `<MaxParts>`, which the
  // example sets to 2 — the same number as the first part's `<PartNumber>`, so
  // a transposition of those two would have gone unnoticed. Everything else is
  // the example's, and `NextPartNumberMarker` equals the last part's number
  // because the protocol says it does.
  it("encodes a ListPartsResult", () => {
    expect(
      encodeListPartsResult({
        bucket: "example-bucket",
        key: "example-object",
        uploadId: "XXBsb2FkIElEIGZvciBlbHZpbmcncyVcdS1tb3ZpZS5tMnRzEEEwbG9hZA",
        initiator: {
          id: "arn:aws:iam::111122223333:user/some-user",
          displayName: "umat-user-11116a31",
        },
        owner: {
          id: "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a",
          displayName: "someName",
        },
        storageClass: "STANDARD",
        partNumberMarker: 1,
        nextPartNumberMarker: 3,
        maxParts: 9,
        isTruncated: true,
        parts: [
          {
            partNumber: 2,
            lastModified: "2010-11-10T20:48:34.000Z",
            etag: '"7778aef83f66abc1fa1e8477f296d394"',
            size: 10_485_760,
          },
          {
            partNumber: 3,
            lastModified: "2010-11-10T20:48:33.000Z",
            etag: '"aaaa18db4cc2f85cedef654fccc4a4x8"',
            size: 10_485_761,
          },
        ],
      }),
    ).toBe(
      `${XML_DECLARATION}<ListPartsResult${XMLNS}>` +
        `<Bucket>example-bucket</Bucket>` +
        `<Key>example-object</Key>` +
        `<UploadId>XXBsb2FkIElEIGZvciBlbHZpbmcncyVcdS1tb3ZpZS5tMnRzEEEwbG9hZA</UploadId>` +
        `<Initiator>` +
        `<ID>arn:aws:iam::111122223333:user/some-user</ID>` +
        `<DisplayName>umat-user-11116a31</DisplayName>` +
        `</Initiator>` +
        `<Owner>` +
        `<ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>` +
        `<DisplayName>someName</DisplayName>` +
        `</Owner>` +
        `<StorageClass>STANDARD</StorageClass>` +
        `<PartNumberMarker>1</PartNumberMarker>` +
        `<NextPartNumberMarker>3</NextPartNumberMarker>` +
        `<MaxParts>9</MaxParts>` +
        `<IsTruncated>true</IsTruncated>` +
        `<Part>` +
        `<PartNumber>2</PartNumber>` +
        `<LastModified>2010-11-10T20:48:34.000Z</LastModified>` +
        `<ETag>&quot;7778aef83f66abc1fa1e8477f296d394&quot;</ETag>` +
        `<Size>10485760</Size>` +
        `</Part>` +
        `<Part>` +
        `<PartNumber>3</PartNumber>` +
        `<LastModified>2010-11-10T20:48:33.000Z</LastModified>` +
        `<ETag>&quot;aaaa18db4cc2f85cedef654fccc4a4x8&quot;</ETag>` +
        `<Size>10485761</Size>` +
        `</Part>` +
        `</ListPartsResult>`,
    );
  });

  it("is deterministic: the same tree is the same bytes", () => {
    const result = {
      name: "bucket",
      keyCount: 1,
      maxKeys: 2,
      isTruncated: false,
      contents: [
        {
          key: "a",
          lastModified: "2020-01-02T03:04:05.000Z",
          etag: '"e-6"',
          size: 7n,
          storageClass: "STANDARD",
        },
      ],
    } as const;
    expect(encodeListBucketResult(result)).toBe(encodeListBucketResult(result));
  });

  it("renders a bigint size without exponent or separator", () => {
    expect(
      encodeListBucketResult({
        name: "b",
        keyCount: 1,
        maxKeys: 2,
        isTruncated: false,
        contents: [
          {
            key: "big",
            lastModified: "2021-03-04T05:06:07.000Z",
            etag: '"e-8"',
            size: 9_007_199_254_740_993n,
          },
        ],
      }),
    ).toContain("<Size>9007199254740993</Size>");
  });
});

// ---------------------------------------------------------------------------
// escaping
// ---------------------------------------------------------------------------

describe("escaping", () => {
  it("escapes the five predefined entities", () => {
    expect(escapeXmlText(`&<>"'`)).toBe("&amp;&lt;&gt;&quot;&apos;");
  });

  it("leaves tab and LF alone and escapes CR", () => {
    const text = `a${String.fromCodePoint(0x09)}b${String.fromCodePoint(0x0a)}c${String.fromCodePoint(0x0d)}d`;
    expect(escapeXmlText(text)).toBe(
      `a${String.fromCodePoint(0x09)}b${String.fromCodePoint(0x0a)}c&#13;d`,
    );
  });

  it("replaces a C0 control", () => {
    expect(escapeXmlText(`a${String.fromCodePoint(0x01)}b`)).toBe(`a${XML_REPLACEMENT}b`);
    expect(escapeXmlText(String.fromCodePoint(0x00))).toBe(XML_REPLACEMENT);
  });

  it("replaces DEL and a C1 control, the shape a latin-1 header byte arrives in", () => {
    expect(escapeXmlText(String.fromCodePoint(0x7f))).toBe(XML_REPLACEMENT);
    expect(escapeXmlText(String.fromCodePoint(0x85))).toBe(XML_REPLACEMENT);
    expect(escapeXmlText(String.fromCodePoint(0x9f))).toBe(XML_REPLACEMENT);
    /* U+00A0, one past the C1 range, is an ordinary character. */
    expect(escapeXmlText(String.fromCodePoint(0xa0))).toBe(String.fromCodePoint(0xa0));
  });

  it("replaces a lone surrogate — the half sigv4's quote() can leave behind", () => {
    expect(escapeXmlText(String.fromCodePoint(0xd8_3d))).toBe(XML_REPLACEMENT);
    expect(escapeXmlText(String.fromCodePoint(0xde_00))).toBe(XML_REPLACEMENT);
  });

  it("carries an astral pair through intact", () => {
    const astral = String.fromCodePoint(0x1_f6_00);
    expect(escapeXmlText(`x${astral}y`)).toBe(`x${astral}y`);
    expect([...escapeXmlText(astral)]).toHaveLength(1);
  });

  it("replaces U+FFFE and U+FFFF, in plane 0 and above it", () => {
    expect(escapeXmlText(String.fromCodePoint(0xff_fe))).toBe(XML_REPLACEMENT);
    expect(escapeXmlText(String.fromCodePoint(0xff_ff))).toBe(XML_REPLACEMENT);
    expect(escapeXmlText(String.fromCodePoint(0x1_ff_fe))).toBe(XML_REPLACEMENT);
    /* U+FFFD itself is a character, and the replacement is idempotent. */
    expect(escapeXmlText(XML_REPLACEMENT)).toBe(XML_REPLACEMENT);
  });

  it("agrees with isXmlChar over the whole BMP and the plane boundaries", () => {
    for (let code = 0; code <= 0xff_ff; code++) {
      const character = String.fromCodePoint(code);
      const escaped = escapeXmlText(character);
      if (`&<>"'`.includes(character) || code === 0x0d) {
        expect(escaped.startsWith("&"), `U+${code.toString(16)}`).toBe(true);
        continue;
      }
      expect(escaped === character, `U+${code.toString(16)}`).toBe(isXmlChar(code));
    }
    expect(isXmlChar(0x1_00_00)).toBe(true);
    expect(isXmlChar(0x10_ff_ff)).toBe(false);
  });

  it("escapes an error message rather than failing to encode it", () => {
    /* Exactly what `sigv4.ts`'s quote() can hand over: a detail cut mid-pair,
       with markup in it. An error response must always encode. */
    const detail = `no such access key id: <a&b${String.fromCodePoint(0xd8_3d)}`;
    expect(encodeS3ErrorDocument({ code: "InvalidAccessKeyId", message: detail })).toBe(
      `${XML_DECLARATION}<Error><Code>InvalidAccessKeyId</Code>` +
        `<Message>no such access key id: &lt;a&amp;b${XML_REPLACEMENT}</Message>` +
        `</Error>`,
    );
  });

  it("escapes an object key, wherever it appears", () => {
    const document = encodeDeleteResult({
      deleted: [{ key: `a&b<c>d"e'f` }],
      errors: [],
    });
    expect(document).toContain("<Key>a&amp;b&lt;c&gt;d&quot;e&apos;f</Key>");
  });
});

// ---------------------------------------------------------------------------
// the two request bodies
// ---------------------------------------------------------------------------

const DELETE_BODY =
  `${XML_DECLARATION}\n<Delete${XMLNS}>` +
  `<Object><Key>sample1.txt</Key></Object>` +
  `<Object><Key>sample2.txt</Key><VersionId>OYcLXagmS.WaD..oyH4KRguB95_YhLs7</VersionId></Object>` +
  `<Quiet>true</Quiet>` +
  `</Delete>`;

const COMPLETE_BODY =
  `${XML_DECLARATION}\n<CompleteMultipartUpload${XMLNS}>` +
  `<Part><PartNumber>1</PartNumber><ETag>&quot;a54357aff0632cce46d942af68356b38&quot;</ETag></Part>` +
  `<Part><PartNumber>2</PartNumber><ETag>"0c78aef83f66abc1fa1e8477f296d394"</ETag></Part>` +
  `</CompleteMultipartUpload>`;

describe("parsing DeleteObjects", () => {
  it("parses the body aws-cli sends", () => {
    expect(parseDeleteObjects(DELETE_BODY)).toEqual({
      objects: [
        { key: "sample1.txt" },
        { key: "sample2.txt", versionId: "OYcLXagmS.WaD..oyH4KRguB95_YhLs7" },
      ],
      quiet: true,
    } satisfies DeleteObjectsRequest);
  });

  it("takes bytes as well as a string", () => {
    expect(parseDeleteObjects(new TextEncoder().encode(DELETE_BODY)).objects).toHaveLength(2);
  });

  it("defaults Quiet to false and accepts 1/0 spellings", () => {
    expect(parseDeleteObjects(`<Delete><Object><Key>k</Key></Object></Delete>`).quiet).toBe(false);
    expect(
      parseDeleteObjects(`<Delete><Object><Key>k</Key></Object><Quiet>1</Quiet></Delete>`).quiet,
    ).toBe(true);
    expect(
      parseDeleteObjects(`<Delete><Object><Key>k</Key></Object><Quiet> FALSE </Quiet></Delete>`)
        .quiet,
    ).toBe(false);
  });

  it("accepts a namespace-prefixed root and children", () => {
    expect(
      parseDeleteObjects(
        `<s3:Delete xmlns:s3="${S3_XMLNS}"><s3:Object><s3:Key>k</s3:Key></s3:Object></s3:Delete>`,
      ).objects,
    ).toEqual([{ key: "k" }]);
  });

  it("accepts whitespace, comments and processing instructions between elements", () => {
    const body =
      `<?xml version="1.0"?>\n<!-- a comment -->\n<Delete>\n` +
      `  <!-- another -->\n  <?sdk generated="yes"?>\n  <Object>\n    <Key>k</Key>\n  </Object>\n` +
      `</Delete>\n<!-- and after -->\n`;
    expect(parseDeleteObjects(body).objects).toEqual([{ key: "k" }]);
  });

  it("takes a key out of a CDATA section verbatim", () => {
    expect(
      parseDeleteObjects(`<Delete><Object><Key><![CDATA[a&b<c>]]></Key></Object></Delete>`).objects,
    ).toEqual([{ key: "a&b<c>" }]);
  });

  it("keeps a key's own whitespace, which is part of the key", () => {
    expect(
      parseDeleteObjects(`<Delete><Object><Key> spaced key </Key></Object></Delete>`).objects,
    ).toEqual([{ key: " spaced key " }]);
  });

  it("skips elements it has never heard of", () => {
    expect(
      parseDeleteObjects(
        `<Delete><Object><Key>k</Key><ChecksumAlgorithm>CRC32</ChecksumAlgorithm>` +
          `</Object><Future><Nested>x</Nested></Future></Delete>`,
      ).objects,
    ).toEqual([{ key: "k" }]);
  });

  it("refuses a body with no Object, a missing Key or a duplicated one", () => {
    expect(refusalOf(() => parseDeleteObjects(`<Delete></Delete>`))).toBe("missing-field");
    expect(refusalOf(() => parseDeleteObjects(`<Delete><Object></Object></Delete>`))).toBe(
      "missing-field",
    );
    expect(
      refusalOf(() =>
        parseDeleteObjects(`<Delete><Object><Key>a</Key><Key>b</Key></Object></Delete>`),
      ),
    ).toBe("duplicate-field");
    expect(
      refusalOf(() =>
        parseDeleteObjects(
          `<Delete><Object><Key>k</Key></Object><Quiet>a</Quiet><Quiet>b</Quiet></Delete>`,
        ),
      ),
    ).toBe("duplicate-field");
  });

  it("refuses a Quiet that is not a boolean, and the wrong root", () => {
    expect(
      refusalOf(() =>
        parseDeleteObjects(`<Delete><Object><Key>k</Key></Object><Quiet>yes</Quiet></Delete>`),
      ),
    ).toBe("invalid-field");
    expect(refusalOf(() => parseDeleteObjects(COMPLETE_BODY))).toBe("unexpected-root");
  });
});

describe("parsing CompleteMultipartUpload", () => {
  it("parses the body aws-cli sends, quoted ETags and all", () => {
    expect(parseCompleteMultipartUpload(COMPLETE_BODY)).toEqual({
      parts: [
        { partNumber: 1, etag: '"a54357aff0632cce46d942af68356b38"' },
        { partNumber: 2, etag: '"0c78aef83f66abc1fa1e8477f296d394"' },
      ],
    } satisfies CompleteMultipartUploadRequest);
  });

  it("keeps the quotes and trims only the whitespace around them", () => {
    expect(
      parseCompleteMultipartUpload(
        `<CompleteMultipartUpload><Part>\n  <PartNumber> 7 </PartNumber>\n` +
          `  <ETag>\n    "e-1"\n  </ETag>\n</Part></CompleteMultipartUpload>`,
      ).parts,
    ).toEqual([{ partNumber: 7, etag: '"e-1"' }]);
  });

  it("does not reorder or renumber what it was sent", () => {
    expect(
      parseCompleteMultipartUpload(
        `<CompleteMultipartUpload>` +
          `<Part><PartNumber>3</PartNumber><ETag>"c"</ETag></Part>` +
          `<Part><PartNumber>1</PartNumber><ETag>"a"</ETag></Part>` +
          `</CompleteMultipartUpload>`,
      ).parts,
    ).toEqual([
      { partNumber: 3, etag: '"c"' },
      { partNumber: 1, etag: '"a"' },
    ]);
  });

  it("refuses a part list that is empty, incomplete or duplicated", () => {
    const refusal = (body: string) => refusalOf(() => parseCompleteMultipartUpload(body));
    expect(refusal(`<CompleteMultipartUpload></CompleteMultipartUpload>`)).toBe("missing-field");
    expect(
      refusal(`<CompleteMultipartUpload><Part><ETag>"a"</ETag></Part></CompleteMultipartUpload>`),
    ).toBe("missing-field");
    expect(
      refusal(
        `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>`,
      ),
    ).toBe("missing-field");
    expect(
      refusal(
        `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>` +
          `<ETag>"a"</ETag><ETag>"b"</ETag></Part></CompleteMultipartUpload>`,
      ),
    ).toBe("duplicate-field");
  });

  it("refuses a PartNumber that is not a number or not in range", () => {
    const part = (number: string) =>
      refusalOf(() =>
        parseCompleteMultipartUpload(
          `<CompleteMultipartUpload><Part><PartNumber>${number}</PartNumber>` +
            `<ETag>"a"</ETag></Part></CompleteMultipartUpload>`,
        ),
      );
    expect(part("one")).toBe("invalid-field");
    expect(part("1.5")).toBe("invalid-field");
    expect(part("-1")).toBe("invalid-field");
    expect(part("0")).toBe("invalid-field");
    expect(part(String(MAX_PARTS + 1))).toBe("invalid-field");
    expect(part("1e3")).toBe("invalid-field");
    expect(part(String(MAX_PARTS))).toBe("(no throw)");
    /* Leading zeros are a spelling, not an error — ten digits of them, the
       same width `#entity()` allows a character reference. */
    expect(part("0000000001")).toBe("(no throw)");
    expect(part("00000000001")).toBe("invalid-field");
  });

  it("refuses more parts than a multipart upload can have", () => {
    const part = `<Part><PartNumber>1</PartNumber><ETag>"a"</ETag></Part>`;
    const body = (count: number) =>
      `<CompleteMultipartUpload>${part.repeat(count)}</CompleteMultipartUpload>`;
    expect(refusalOf(() => parseCompleteMultipartUpload(body(MAX_PARTS + 1)))).toBe(
      "invalid-field",
    );
    expect(refusalOf(() => parseCompleteMultipartUpload(body(MAX_PARTS)))).toBe("(no throw)");
  });

  it("refuses an empty ETag", () => {
    expect(
      refusalOf(() =>
        parseCompleteMultipartUpload(
          `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>` +
            `<ETag>  </ETag></Part></CompleteMultipartUpload>`,
        ),
      ),
    ).toBe("invalid-field");
  });
});

describe("round trips", () => {
  it("parses back what the builder wrote, key for key", () => {
    const keys = [
      `a&b<c>d"e'f`,
      `photos/2006/${String.fromCodePoint(0x1_f6_00)}.jpg`,
      ` leading and trailing `,
      "]]>",
      String.fromCodePoint(0xa0),
    ];
    const body = xmlDocument(
      {
        name: "Delete",
        children: [
          ...keys.map((key) => ({ name: "Object", children: [{ name: "Key", text: key }] })),
          { name: "Quiet", text: false },
        ],
      },
      { xmlns: S3_XMLNS },
    );
    expect(parseDeleteObjects(body)).toEqual({
      objects: keys.map((key) => ({ key })),
      quiet: false,
    });
  });

  it("parses back a part list the builder wrote", () => {
    const body = xmlDocument({
      name: "CompleteMultipartUpload",
      children: [1, 2, MAX_PARTS].map((partNumber) => ({
        name: "Part",
        children: [
          { name: "PartNumber", text: partNumber },
          { name: "ETag", text: `"etag-${partNumber}"` },
        ],
      })),
    });
    expect(parseCompleteMultipartUpload(body).parts).toEqual([
      { partNumber: 1, etag: '"etag-1"' },
      { partNumber: 2, etag: '"etag-2"' },
      { partNumber: MAX_PARTS, etag: `"etag-${MAX_PARTS}"` },
    ]);
  });
});

// ---------------------------------------------------------------------------
// hostile input
// ---------------------------------------------------------------------------

describe("hostile input", () => {
  it("refuses a DOCTYPE wherever it appears, and never expands an entity", () => {
    const laughs =
      `<!DOCTYPE lolz [<!ENTITY lol "lol">` +
      `<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>` +
      `<Delete><Object><Key>&lol2;</Key></Object></Delete>`;
    expect(refusalOf(() => parseDeleteObjects(laughs))).toBe("doctype");
    expect(refusalOf(() => parseXml(`<Delete><!DOCTYPE x><Object/></Delete>`))).toBe("doctype");
    expect(refusalOf(() => parseXml(`<a/><!DOCTYPE x>`))).toBe("doctype");
    /* An external entity has nowhere to be declared, so the reference itself
       is the refusal — no fetch, no file read, nothing to resolve. */
    expect(refusalOf(() => parseXml(`<Delete><Object><Key>&xxe;</Key></Object></Delete>`))).toBe(
      "entity",
    );
  });

  it("refuses any other markup declaration", () => {
    expect(refusalOf(() => parseXml(`<!ENTITY x "y"><a/>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<a><![INCLUDE[x]]></a>`))).toBe("malformed");
  });

  it("caps nesting depth", () => {
    const deep = `${"<a>".repeat(200)}x${"</a>".repeat(200)}`;
    expect(refusalOf(() => parseXml(deep, { maxDepth: 8 }))).toBe("depth");
    expect(refusalOf(() => parseXml(deep))).toBe("depth");
    /* A body exactly at the cap still parses. */
    expect(
      refusalOf(() => parseXml(`${"<a>".repeat(8)}${"</a>".repeat(8)}`, { maxDepth: 8 })),
    ).toBe("(no throw)");
  });

  it("clamps a caller's maxDepth: the stack is not a caller's to spend", () => {
    /* `#element` recurses, so an unbounded maxDepth would turn the "throws
       XmlError and nothing else" contract into a RangeError from the engine.
       Deep enough to blow a default Node stack many times over. */
    const deep = `${"<a>".repeat(20_000)}x${"</a>".repeat(20_000)}`;
    for (const maxDepth of [1e9, Number.MAX_SAFE_INTEGER, Number.POSITIVE_INFINITY]) {
      expect(
        refusalOf(() => parseXml(deep, { maxDepth })),
        String(maxDepth),
      ).toBe("depth");
    }
    /* And the clamp is the only thing that changed: it is still a refusal at
       the ceiling, not at whatever was asked for. */
    expect(
      refusalOf(() => parseXml(`${"<a>".repeat(300)}${"</a>".repeat(300)}`, { maxDepth: 1e9 })),
    ).toBe("depth");
    expect(
      refusalOf(() =>
        parseXml(`${"<a>".repeat(XML_MAX_DEPTH_CEILING)}${"</a>".repeat(XML_MAX_DEPTH_CEILING)}`, {
          maxDepth: 1e9,
        }),
      ),
    ).toBe("(no throw)");
  });

  it("survives a cap that is not a number", () => {
    /* Every comparison against NaN is false, so a NaN cap that reached the
       parser would be no cap at all. */
    const deep = `${"<a>".repeat(20_000)}x${"</a>".repeat(20_000)}`;
    expect(refusalOf(() => parseXml(deep, { maxDepth: Number.NaN }))).toBe("depth");
    expect(refusalOf(() => parseXml(`<a><b/></a>`, { maxDepth: 0 }))).toBe("depth");
    expect(refusalOf(() => parseXml(`<a><b/></a>`, { maxElements: Number.NaN }))).toBe(
      "(no throw)",
    );
    expect(refusalOf(() => parseXml(`<a><b/></a>`, { maxBytes: Number.NaN }))).toBe("(no throw)");
  });

  it("refuses a body that is not UTF-8 rather than guessing a key", () => {
    /* A lone 0x85 continuation byte: latin-1 text, or a truncated multi-byte
       sequence. A lossy decoder would turn it into U+FFFD and this gateway
       would delete a *different* key than the client named. */
    const body = new TextEncoder().encode(`<Delete><Object><Key>ab</Key></Object></Delete>`);
    const corrupt = Uint8Array.prototype.slice.call(body);
    corrupt[body.indexOf(0x62)] = 0x85;
    expect(refusalOf(() => parseDeleteObjects(corrupt))).toBe("encoding");
    expect(refusalOf(() => parseXml(new Uint8Array([0x3c, 0x61, 0x3e, 0xc3, 0x28])))).toBe(
      "encoding",
    );
    /* Well-formed multi-byte UTF-8 still arrives intact. */
    expect(
      parseXml(new TextEncoder().encode(`<a>${String.fromCodePoint(0x1_f6_00)}</a>`)).text,
    ).toBe(String.fromCodePoint(0x1_f6_00));
  });

  it("caps the element count", () => {
    const bomb = `<Delete>${"<Object><Key>k</Key></Object>".repeat(400)}</Delete>`;
    expect(refusalOf(() => parseDeleteObjects(bomb, { maxElements: 100 }))).toBe(
      "too-many-elements",
    );
    expect(refusalOf(() => parseDeleteObjects(bomb))).toBe("(no throw)");
  });

  it("caps the input size", () => {
    expect(refusalOf(() => parseXml(`<a>${"x".repeat(64)}</a>`, { maxBytes: 16 }))).toBe(
      "too-large",
    );
    expect(refusalOf(() => parseXml(new Uint8Array(4096), { maxBytes: 1024 }))).toBe("too-large");
  });

  it("refuses truncated and mismatched markup", () => {
    expect(refusalOf(() => parseXml(`<Delete`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<Delete>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<Delete></Deletx>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<Delete><Object></Delete></Object>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<Delete></Delete`))).toBe("malformed");
    expect(refusalOf(() => parseXml(``))).toBe("malformed");
    expect(refusalOf(() => parseXml(`   `))).toBe("malformed");
    expect(refusalOf(() => parseXml(`not xml at all`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<a/><b/>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<a><!-- unterminated </a>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<a><![CDATA[x</a>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<?xml version="1.0"`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<1a/>`))).toBe("malformed");
  });

  it("refuses malformed attributes but keeps well-formed ones", () => {
    expect(refusalOf(() => parseXml(`<a b/>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<a b=c/>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<a b="c/>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<a b="<"/>`))).toBe("malformed");
    expect(refusalOf(() => parseXml(`<a b="c"d="e"/>`))).toBe("malformed");
    expect(parseXml(`<a b='c' d="&amp;" ><e/></a>`).children).toHaveLength(1);
  });

  it("resolves only the five entities and well-formed numeric references", () => {
    expect(parseXml(`<a>&amp;&lt;&gt;&quot;&apos;</a>`).text).toBe(`&<>"'`);
    expect(parseXml(`<a>&#65;&#x42;&#X43;</a>`).text).toBe("ABC");
    expect(parseXml(`<a>&#128512;</a>`).text).toBe(String.fromCodePoint(0x1_f6_00));
    expect(refusalOf(() => parseXml(`<a>&AMP;</a>`))).toBe("entity");
    /* Leading zeros are tolerated to the same depth in both radices: ten
       digits either way, so the same character written two ways is accepted
       two ways. Eleven is past the scan window in both. */
    expect(parseXml(`<a>&#0000000065;&#x0000000042;&#X0000000043;</a>`).text).toBe("ABC");
    expect(refusalOf(() => parseXml(`<a>&#00000000065;</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&#x00000000042;</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&#;</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&#xZZ;</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&amp</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&${"x".repeat(64)};</a>`))).toBe("entity");
  });

  it("refuses a character reference naming something XML cannot carry", () => {
    /* Pinned deliberately: `&#0;` is a refusal, never a NUL in an object key,
       and the rule is the encoder's predicate applied backwards. */
    expect(refusalOf(() => parseXml(`<a>&#0;</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&#x1;</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&#133;</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&#xD83D;</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&#xFFFE;</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&#x110000;</a>`))).toBe("entity");
    expect(refusalOf(() => parseXml(`<a>&#9;&#xD;&#x41;</a>`))).toBe("(no throw)");
  });

  it("refuses a raw character the encoder could not emit back", () => {
    const raw = (code: number) =>
      refusalOf(() => parseXml(`<a>x${String.fromCodePoint(code)}y</a>`));
    expect(raw(0x00)).toBe("invalid-character");
    expect(raw(0x1f)).toBe("invalid-character");
    expect(raw(0x7f)).toBe("invalid-character");
    expect(raw(0x9f)).toBe("invalid-character");
    expect(raw(0xd8_3d)).toBe("invalid-character");
    expect(raw(0xff_fe)).toBe("invalid-character");
    expect(raw(0xa0)).toBe("(no throw)");
    expect(raw(0x1_f6_00)).toBe("(no throw)");
    /* Even inside a CDATA section, where a parser does no other checking. */
    expect(refusalOf(() => parseXml(`<a><![CDATA[${String.fromCodePoint(0x00)}]]></a>`))).toBe(
      "invalid-character",
    );
  });

  it("copies what it keeps: the input buffer may be reused", () => {
    const bytes = new TextEncoder().encode(`<Delete><Object><Key>keep</Key></Object></Delete>`);
    const parsed = parseDeleteObjects(bytes);
    bytes.fill(0x20);
    expect(parsed.objects).toEqual([{ key: "keep" }]);
  });

  it("drops a byte-order mark", () => {
    expect(parseXml(`${String.fromCodePoint(0xfe_ff)}<a>x</a>`).text).toBe("x");
  });
});

// ---------------------------------------------------------------------------
// fuzzing
// ---------------------------------------------------------------------------

/**
 * The invariant is the one every decoder in this repository carries: **only
 * `XmlError` escapes.** A `TypeError` out of a field that was not there, a
 * `RangeError` out of `String.fromCodePoint`, an unbounded scan or a loop that
 * stops advancing all reach the request handler as something it cannot answer,
 * and a gateway that dies on a malformed body is one an anonymous client can
 * take down.
 *
 * Deterministic: every case comes from a seeded PRNG (`test/fuse/random.ts`),
 * so a failure reproduces from the seed in the name.
 */
function mutate(rng: Rng, source: Uint8Array): Uint8Array {
  const copy = (): Uint8Array => Uint8Array.prototype.slice.call(source);
  switch (rng.int(5)) {
    case 0: {
      return source.subarray(0, rng.int(source.length + 1));
    }
    case 1: {
      const at = rng.int(source.length + 1);
      const injected = rng.bytes(rng.range(1, 8));
      const out = new Uint8Array(source.length + injected.length);
      out.set(source.subarray(0, at));
      out.set(injected, at);
      out.set(source.subarray(at), at + injected.length);
      return out;
    }
    case 2: {
      const out = copy();
      out[rng.int(out.length)] = rng.u32() & 0xff;
      return out;
    }
    case 3: {
      const start = rng.int(source.length);
      const piece = source.subarray(start, start + rng.int(source.length - start + 1));
      const out = new Uint8Array(source.length + piece.length);
      out.set(source);
      out.set(piece, source.length);
      return out;
    }
    default: {
      const start = rng.int(source.length);
      const end = start + rng.int(source.length - start + 1);
      const out = new Uint8Array(source.length - (end - start));
      out.set(source.subarray(0, start));
      out.set(source.subarray(end), start);
      return out;
    }
  }
}

describe("fuzzing", () => {
  const limits = { maxBytes: 64 * 1024, maxDepth: 8, maxElements: 500 };
  const parsers = [
    ["parseXml", (bytes: Uint8Array) => parseXml(bytes, limits)],
    ["parseDeleteObjects", (bytes: Uint8Array) => parseDeleteObjects(bytes, limits)],
    [
      "parseCompleteMultipartUpload",
      (bytes: Uint8Array) => parseCompleteMultipartUpload(bytes, limits),
    ],
  ] as const;

  for (const seed of [1, 2, 3, 4]) {
    it(`only ever throws XmlError, seed ${seed}`, () => {
      const rng = new Rng(seed);
      const encoder = new TextEncoder();
      const bodies = [encoder.encode(DELETE_BODY), encoder.encode(COMPLETE_BODY)];
      for (let iteration = 0; iteration < 200; iteration++) {
        const bytes = mutate(rng, rng.pick(bodies));
        for (const [name, parse] of parsers) {
          try {
            parse(bytes);
          } catch (error) {
            if (!isXmlError(error)) {
              throw new Error(
                `${name} threw ${String(error)} for seed ${seed} iteration ${iteration}`,
                { cause: error },
              );
            }
            expect(error.code).toBe("ERR_S3_XML");
          }
        }
      }
    });
  }

  it("re-encodes whatever it accepted, for any mutation that parsed", () => {
    const rng = new Rng(9);
    const body = new TextEncoder().encode(DELETE_BODY);
    let parsed = 0;
    for (let iteration = 0; iteration < 200; iteration++) {
      let request: DeleteObjectsRequest;
      try {
        request = parseDeleteObjects(mutate(rng, body), limits);
      } catch (error) {
        expect(isXmlError(error)).toBe(true);
        continue;
      }
      parsed++;
      /* Whatever survived is emittable, which is the round-trip property the
         module docs claim: the parser accepts exactly what the encoder writes. */
      const round = parseDeleteObjects(
        xmlDocument({
          name: "Delete",
          children: request.objects.map((object) => ({
            name: "Object",
            children: [{ name: "Key", text: object.key }],
          })),
        }),
        limits,
      );
      expect(round.objects.map((object) => object.key)).toEqual(
        request.objects.map((object) => object.key),
      );
    }
    /* The corpus is only useful if some of it survives the mutations. */
    expect(parsed).toBeGreaterThan(0);
  });
});
