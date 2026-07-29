/**
 * SigV4, checked against Amazon's own vectors.
 *
 * The goldens below are **transcribed from the official
 * `aws-sig-v4-test-suite`** — the awslabs copy that ships as
 * `tests/aws-signing-test-suite/v4` in `awslabs/aws-c-auth`, one directory per
 * case holding `request.txt`, `header-canonical-request.txt`,
 * `header-string-to-sign.txt`, `header-signature.txt` and the `query-*`
 * equivalents for the presigned form. Every vector asserts **all three
 * stages**, not just the signature: a canonical request and a string to sign
 * that both drift together still produce a matching signature, and the middle
 * stages are where a transcription bug shows up as something a human can read.
 *
 * The suite's fixed inputs, from every case's `context.json`: access key
 * `AKIDEXAMPLE`, secret `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, region
 * `us-east-1`, **service `service`** and timestamp `20150830T123600Z`. The
 * service is deliberately not `s3` — these vectors pin the parts of SigV4 that
 * are the same everywhere, and `src/s3/sigv4.ts` reaches them by being handed
 * `service: "service"`.
 *
 * **Single encoding, and where the vectors already prove it.** A generic AWS
 * service double-encodes the canonical URI; S3 encodes it once. The suite's own
 * canonical requests single-encode, so three of the vectors below are
 * distinguishing cases on their own: `get-space-unnormalized` signs
 * `/example%20space/` and `get-utf8` signs `/%E1%88%B4`, where a double-encoding
 * signer would produce `/example%2520space/` and `/%25E1%2588%25B4`;
 * `get-vanilla-utf8-query` does the same for a query name. The dedicated S3
 * tests in "the S3 canonicalization rules" below add what the suite has no case
 * for — a path with a space *and* a multi-byte segment together, and an
 * assertion that no `%25` appears anywhere in the result.
 *
 * The **no-normalization** half of the S3 configuration is covered the same
 * way: the suite's `*-unnormalized` variants are the ones matching S3, so
 * `get-slashes-unnormalized` is included in that form (signing `//example//`
 * intact) and the `normalize: true` path cases, which would collapse it, are
 * left out.
 *
 * Everything after the two vector blocks is ours, and every fixture in it gives
 * each field a distinct value (`AGENTS.md`): a fixture built from repeated
 * values passes with two fields transposed.
 */

import { describe, expect, it } from "vitest";
import { STREAMING_PAYLOAD, UNSIGNED_PAYLOAD } from "../../src/s3/constants.ts";
import {
  canonicalHeaders,
  canonicalQuery,
  canonicalRequest,
  canonicalUri,
  EMPTY_PAYLOAD_SHA256,
  formatAmzDate,
  MAX_CLOCK_SKEW_MS,
  parseAmzDate,
  parseAuthorizationHeader,
  parsePresignedQuery,
  presignRequest,
  sha256Hex,
  signaturesMatch,
  signatureOf,
  signRequest,
  stringToSign,
  uriEncode,
  verifyRequest,
  type CredentialScope,
  type HeaderEntry,
  type QueryEntry,
  type SigV4Credentials,
} from "../../src/s3/sigv4.ts";

// ---------------------------------------------------------------------------
// the official suite
// ---------------------------------------------------------------------------

/** `context.json`, identical in every case below. */
const SUITE_CREDENTIALS: SigV4Credentials = {
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
};
const SUITE_REGION = "us-east-1";
const SUITE_SERVICE = "service";
const SUITE_DATE = "20150830T123600Z";
const SUITE_SCOPE: CredentialScope = {
  date: "20150830",
  region: SUITE_REGION,
  service: SUITE_SERVICE,
};
/** `expiration_in_seconds`, for the presigned half. */
const SUITE_EXPIRES = 3600;

interface SuiteVector {
  /** The suite directory this came from. */
  name: string;
  method: string;
  path: string;
  query: QueryEntry[];
  headers: HeaderEntry[];
  /** Only the presigned cases sign a subset of the headers they send. */
  signedHeaders?: string[];
  payloadHash: string;
  canonicalRequest: string;
  stringToSign: string;
  signature: string;
}

/**
 * The header-form cases. `request.txt` supplies the method, path, query and
 * headers; the signer adds `x-amz-date` (and `x-amz-content-sha256` where the
 * case signs a body), which is why those two appear here and not in the suite's
 * request file.
 */
const HEADER_VECTORS: SuiteVector[] = [
  {
    name: "get-vanilla",
    method: "GET",
    path: "/",
    query: [],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/",
      "",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
    ].join("\n"),
    signature: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
  },
  {
    name: "get-vanilla-query-order-key-case",
    method: "GET",
    path: "/",
    query: [
      { name: "Param2", value: "value2" },
      { name: "Param1", value: "value1" },
    ],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/",
      "Param1=value1&Param2=value2",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0",
    ].join("\n"),
    signature: "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
  },
  {
    name: "get-vanilla-query-unreserved",
    method: "GET",
    path: "/",
    query: [
      {
        name: "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        value: "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
      },
    ],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/",
      "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "c30d4703d9f799439be92736156d47ccfb2d879ddf56f5befa6d1d6aab979177",
    ].join("\n"),
    signature: "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197",
  },
  {
    name: "get-vanilla-utf8-query",
    method: "GET",
    path: "/",
    query: [{ name: "ሴ", value: "bar" }],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/",
      "%E1%88%B4=bar",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "eb30c5bed55734080471a834cc727ae56beb50e5f39d1bff6d0d38cb192a7073",
    ].join("\n"),
    signature: "2cdec8eed098649ff3a119c94853b13c643bcf08f8b0a1d91e12c9027818dd04",
  },
  {
    name: "get-header-key-duplicate",
    method: "GET",
    path: "/",
    query: [],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "My-Header1", value: "value2" },
      { name: "My-Header1", value: "value2" },
      { name: "My-Header1", value: "value1" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/",
      "",
      "host:example.amazonaws.com",
      "my-header1:value2,value2,value1",
      "x-amz-date:20150830T123600Z",
      "",
      "host;my-header1;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "dc7f04a3abfde8d472b0ab1a418b741b7c67174dad1551b4117b15527fbe966c",
    ].join("\n"),
    signature: "c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea",
  },
  {
    name: "get-header-value-order",
    method: "GET",
    path: "/",
    query: [],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "My-Header1", value: "value4" },
      { name: "My-Header1", value: "value1" },
      { name: "My-Header1", value: "value3" },
      { name: "My-Header1", value: "value2" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/",
      "",
      "host:example.amazonaws.com",
      "my-header1:value4,value1,value3,value2",
      "x-amz-date:20150830T123600Z",
      "",
      "host;my-header1;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "31ce73cd3f3d9f66977ad3dd957dc47af14df92fcd8509f59b349e9137c58b86",
    ].join("\n"),
    signature: "08c7e5a9acfcfeb3ab6b2185e75ce8b1deb5e634ec47601a50643f830c755c01",
  },
  {
    name: "get-header-value-trim",
    method: "GET",
    path: "/",
    query: [],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "My-Header1", value: " value1" },
      { name: "My-Header2", value: ' "a   b   c"' },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/",
      "",
      "host:example.amazonaws.com",
      "my-header1:value1",
      'my-header2:"a b c"',
      "x-amz-date:20150830T123600Z",
      "",
      "host;my-header1;my-header2;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "a726db9b0df21c14f559d0a978e563112acb1b9e05476f0a6a1c7d68f28605c7",
    ].join("\n"),
    signature: "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
  },
  {
    name: "get-unreserved",
    method: "GET",
    path: "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    query: [],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
      "",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "6a968768eefaa713e2a6b16b589a8ea192661f098f37349f4e2c0082757446f9",
    ].join("\n"),
    signature: "07ef7494c76fa4850883e2b006601f940f8a34d404d0cfa977f52a65bbf5f24f",
  },
  {
    name: "get-utf8",
    method: "GET",
    path: "/ሴ",
    query: [],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/%E1%88%B4",
      "",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "2a0a97d02205e45ce2e994789806b19270cfbbb0921b278ccf58f5249ac42102",
    ].join("\n"),
    signature: "8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85",
  },
  {
    name: "get-space-unnormalized",
    method: "GET",
    path: "/example space/",
    query: [],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/example%20space/",
      "",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "63ee75631ed7234ae61b5f736dfc7754cdccfedbff4b5128a915706ee9390d86",
    ].join("\n"),
    signature: "652487583200325589f1fba4c7e578f72c47cb61beeca81406b39ddec1366741",
  },
  {
    name: "get-slashes-unnormalized",
    method: "GET",
    path: "//example//",
    query: [],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "//example//",
      "",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "528ec3105ee1f34ab014bb0a1a45da0ed2742a4fea3555149e5b4d5d201eb240",
    ].join("\n"),
    signature: "87cca117541a147f6df867677d98a7d80dff226d2bfca9e4ffa899665623c7e5",
  },
  {
    name: "post-vanilla",
    method: "POST",
    path: "/",
    query: [],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "POST",
      "/",
      "",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "553f88c9e4d10fc9e109e2aeb65f030801b70c2f6468faca261d401ae622fc87",
    ].join("\n"),
    signature: "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
  },
  {
    name: "post-vanilla-query",
    method: "POST",
    path: "/",
    query: [{ name: "Param1", value: "value1" }],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "POST",
      "/",
      "Param1=value1",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "9d659678c1756bb3113e2ce898845a0a79dbbc57b740555917687f1b3340fbbd",
    ].join("\n"),
    signature: "28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11",
  },
  {
    name: "post-header-key-sort",
    method: "POST",
    path: "/",
    query: [],
    headers: [
      { name: "Host", value: "example.amazonaws.com" },
      { name: "My-Header1", value: "value1" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
    ],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "POST",
      "/",
      "",
      "host:example.amazonaws.com",
      "my-header1:value1",
      "x-amz-date:20150830T123600Z",
      "",
      "host;my-header1;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "9368318c2967cf6de74404b30c65a91e8f6253e0a8659d6d5319f1a812f87d65",
    ].join("\n"),
    signature: "c5410059b04c1ee005303aed430f6e6645f61f4dc9e1461ec8f8916fdf18852c",
  },
  {
    name: "post-x-www-form-urlencoded",
    method: "POST",
    path: "/",
    query: [],
    headers: [
      { name: "Content-Type", value: "application/x-www-form-urlencoded" },
      { name: "Host", value: "example.amazonaws.com" },
      { name: "Content-Length", value: "13" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
      {
        name: "X-Amz-Content-Sha256",
        value: "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
      },
    ],
    payloadHash: "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
    canonicalRequest: [
      "POST",
      "/",
      "",
      "content-length:13",
      "content-type:application/x-www-form-urlencoded",
      "host:example.amazonaws.com",
      "x-amz-content-sha256:9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
      "x-amz-date:20150830T123600Z",
      "",
      "content-length;content-type;host;x-amz-content-sha256;x-amz-date",
      "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "b1edd1d03544c25390e32085d55b57acc9a3961bb59415ff86c45c3d89d16cfb",
    ].join("\n"),
    signature: "d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b",
  },
  {
    name: "post-x-www-form-urlencoded-parameters",
    method: "POST",
    path: "/",
    query: [],
    headers: [
      { name: "Content-Type", value: "application/x-www-form-urlencoded; charset=utf-8" },
      { name: "Host", value: "example.amazonaws.com" },
      { name: "Content-Length", value: "13" },
      { name: "X-Amz-Date", value: "20150830T123600Z" },
      {
        name: "X-Amz-Content-Sha256",
        value: "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
      },
    ],
    payloadHash: "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
    canonicalRequest: [
      "POST",
      "/",
      "",
      "content-length:13",
      "content-type:application/x-www-form-urlencoded; charset=utf-8",
      "host:example.amazonaws.com",
      "x-amz-content-sha256:9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
      "x-amz-date:20150830T123600Z",
      "",
      "content-length;content-type;host;x-amz-content-sha256;x-amz-date",
      "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "a89f1a5b53e37702ee6363ce1da3ce8f54386f3c8f352ae652153c2982a0bc4d",
    ].join("\n"),
    signature: "328d1b9eaadca9f5818ef05e8392801e091653bafec24fcab71e7344e7f51422",
  },
];

/**
 * The presigned-query cases: same requests, signature moved into the query,
 * `x-amz-date` gone from the headers because `X-Amz-Date` carries it.
 */
const QUERY_VECTORS: SuiteVector[] = [
  {
    name: "get-vanilla",
    method: "GET",
    path: "/",
    query: [],
    headers: [{ name: "Host", value: "example.amazonaws.com" }],
    signedHeaders: ["host"],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/",
      "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host",
      "host:example.amazonaws.com",
      "",
      "host",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "bb7705b4aa3cb8e8f5e1e0b3d4c0b64030797a313c8ceee43e33117cc43eadc5",
    ].join("\n"),
    signature: "e93c787ed7f371d5c6b165c1b38ede9550f4dce4144713e844b25b7192d3865d",
  },
  {
    name: "get-vanilla-query-order-key-case",
    method: "GET",
    path: "/",
    query: [
      { name: "Param2", value: "value2" },
      { name: "Param1", value: "value1" },
    ],
    headers: [{ name: "Host", value: "example.amazonaws.com" }],
    signedHeaders: ["host"],
    payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    canonicalRequest: [
      "GET",
      "/",
      "Param1=value1&Param2=value2&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host",
      "host:example.amazonaws.com",
      "",
      "host",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "b82878ecb2ab7ad194b9fe79b2946c2a36ee1627a219408089b2d774c1a0cedb",
    ].join("\n"),
    signature: "86012e2c9ad4d77369f5d81c11f75158aae4f895a085212cc6d3f923d300bed5",
  },
  {
    name: "post-x-www-form-urlencoded",
    method: "POST",
    path: "/",
    query: [],
    headers: [
      { name: "Content-Type", value: "application/x-www-form-urlencoded" },
      { name: "Host", value: "example.amazonaws.com" },
      { name: "Content-Length", value: "13" },
    ],
    signedHeaders: ["content-length", "content-type", "host"],
    payloadHash: "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
    canonicalRequest: [
      "POST",
      "/",
      "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=content-length%3Bcontent-type%3Bhost",
      "content-length:13",
      "content-type:application/x-www-form-urlencoded",
      "host:example.amazonaws.com",
      "",
      "content-length;content-type;host",
      "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
    ].join("\n"),
    stringToSign: [
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "ee5059a7c437165a28d0e775e6498be428761255d657d8c04cb1baa41de6514c",
    ].join("\n"),
    signature: "89a40deed0f26f9461242825a082d2222717248abc7ab41f552ad84a94ad46e9",
  },
];

describe("aws-sig-v4-test-suite, header form", () => {
  for (const vector of HEADER_VECTORS) {
    it(`${vector.name}: canonical request, string to sign and signature`, () => {
      const canonical = canonicalRequest({
        method: vector.method,
        path: vector.path,
        query: vector.query,
        headers: vector.headers,
        signedHeaders: vector.signedHeaders ?? vector.headers.map((header) => header.name),
        payloadHash: vector.payloadHash,
      });
      expect(canonical).toBe(vector.canonicalRequest);

      const toSign = stringToSign(SUITE_DATE, SUITE_SCOPE, canonical);
      expect(toSign).toBe(vector.stringToSign);

      expect(signatureOf(SUITE_CREDENTIALS.secretAccessKey, SUITE_SCOPE, toSign)).toBe(
        vector.signature,
      );
    });

    it(`${vector.name}: signRequest() reaches the same three stages`, () => {
      const signed = signRequest({
        method: vector.method,
        path: vector.path,
        query: vector.query,
        headers: vector.headers,
        credentials: SUITE_CREDENTIALS,
        region: SUITE_REGION,
        service: SUITE_SERVICE,
        timestamp: SUITE_DATE,
        payloadHash: vector.payloadHash,
      });
      expect(signed.canonicalRequest).toBe(vector.canonicalRequest);
      expect(signed.stringToSign).toBe(vector.stringToSign);
      expect(signed.signature).toBe(vector.signature);
      expect(signed.authorization).toBe(
        `AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ` +
          `SignedHeaders=${signed.signedHeaders.join(";")}, Signature=${vector.signature}`,
      );
    });
  }
});

describe("aws-sig-v4-test-suite, presigned query form", () => {
  for (const vector of QUERY_VECTORS) {
    it(`${vector.name}: canonical request, string to sign and signature`, () => {
      const presigned = presignRequest({
        method: vector.method,
        path: vector.path,
        query: vector.query,
        headers: vector.headers,
        signedHeaders: vector.signedHeaders,
        credentials: SUITE_CREDENTIALS,
        region: SUITE_REGION,
        service: SUITE_SERVICE,
        timestamp: SUITE_DATE,
        expiresIn: SUITE_EXPIRES,
        payloadHash: vector.payloadHash,
      });
      expect(presigned.canonicalRequest).toBe(vector.canonicalRequest);
      expect(presigned.stringToSign).toBe(vector.stringToSign);
      expect(presigned.signature).toBe(vector.signature);
    });

    it(`${vector.name}: the signature parameter is not part of what it signs`, () => {
      const presigned = presignRequest({
        method: vector.method,
        path: vector.path,
        query: vector.query,
        headers: vector.headers,
        signedHeaders: vector.signedHeaders,
        credentials: SUITE_CREDENTIALS,
        region: SUITE_REGION,
        service: SUITE_SERVICE,
        timestamp: SUITE_DATE,
        expiresIn: SUITE_EXPIRES,
        payloadHash: vector.payloadHash,
      });
      expect(presigned.canonicalRequest).not.toContain("X-Amz-Signature");
      expect(presigned.query.at(-1)).toEqual({
        name: "X-Amz-Signature",
        value: vector.signature,
      });
    });
  }
});

// ---------------------------------------------------------------------------
// the S3 rules the suite does not reach
// ---------------------------------------------------------------------------

describe("the S3 canonicalization rules", () => {
  it("single-encodes the path, where every other AWS service encodes it twice", () => {
    /* A double-encoding service signs `%2520` for the space and `%25C3%25BC`
       for the umlaut; S3 signs each byte once. */
    expect(canonicalUri("/holiday photos/über brücke.jpg")).toBe(
      "/holiday%20photos/%C3%BCber%20br%C3%BCcke.jpg",
    );
    expect(canonicalUri("/holiday photos/über brücke.jpg")).not.toContain("%25");
  });

  it("normalizes nothing: dot, dot-dot and empty segments survive", () => {
    expect(canonicalUri("//archive/./2024/../2025//")).toBe("//archive/./2024/../2025//");
  });

  it("treats an empty path as the root", () => {
    expect(canonicalUri("")).toBe("/");
  });

  it("reads a path with no leading separator as the absolute path it must be", () => {
    /* Nothing off the wire arrives this way — an origin-form request target
       always starts with a separator — but signing `holiday%20photos/x.jpg`
       would be a mismatch with nothing in it to explain the mismatch. */
    expect(canonicalUri("holiday photos/x.jpg")).toBe("/holiday%20photos/x.jpg");
  });

  it("encodes a slash that is part of a name", () => {
    expect(uriEncode("quarterly/report")).toBe("quarterly%2Freport");
  });

  it("leaves the RFC 3986 unreserved set alone and encodes the sub-delimiters", () => {
    expect(uriEncode("-_.~")).toBe("-_.~");
    /* The characters `encodeURIComponent` would have left literal. */
    expect(uriEncode("a!b'c(d)e*f+g")).toBe("a%21b%27c%28d%29e%2Af%2Bg");
  });

  it("sorts the canonical query by encoded name, then by encoded value", () => {
    expect(
      canonicalQuery([
        { name: "prefix", value: "photos/" },
        { name: "list-type", value: "2" },
        { name: "prefix", value: "archive/" },
        { name: "max-keys", value: "37" },
      ]),
    ).toBe("list-type=2&max-keys=37&prefix=archive%2F&prefix=photos%2F");
  });

  it("keeps a parameter repeated with the same value twice over", () => {
    expect(
      canonicalQuery([
        { name: "prefix", value: "photos/" },
        { name: "prefix", value: "photos/" },
      ]),
    ).toBe("prefix=photos%2F&prefix=photos%2F");
  });

  it("gives a valueless parameter a trailing equals sign", () => {
    expect(canonicalQuery([{ name: "uploads", value: "" }])).toBe("uploads=");
  });

  it("names the body-less payload hash every empty request signs", () => {
    expect(EMPTY_PAYLOAD_SHA256).toBe(sha256Hex(""));
    /* And it is what the suite signs in all but the two body-carrying cases. */
    expect(HEADER_VECTORS[0]?.payloadHash).toBe(EMPTY_PAYLOAD_SHA256);
  });

  it("puts an unsigned or streaming payload hash in verbatim", () => {
    const canonical = canonicalRequest({
      method: "put",
      path: "/bucket/object",
      query: [],
      headers: [{ name: "Host", value: "s3.mountx.test:9001" }],
      signedHeaders: ["host"],
      payloadHash: STREAMING_PAYLOAD,
    });
    expect(canonical.endsWith(`\n${STREAMING_PAYLOAD}`)).toBe(true);
    /* And the method is uppercased on the way in. */
    expect(canonical.startsWith("PUT\n")).toBe(true);
  });
});

describe("the canonical headers block", () => {
  it("trims and collapses ASCII space and tab", () => {
    expect(
      canonicalHeaders(
        [{ name: "X-Amz-Meta-Note", value: " \tone  two\t\tthree \t" }],
        ["x-amz-meta-note"],
      ),
    ).toBe("x-amz-meta-note:one two three\n");
  });

  it("leaves the latin-1 no-break space alone, inside the value and around it", () => {
    /* U+00A0 arrives as the single byte 0xA0, and a real signer treats it as
       any other byte. Both `trim()` and the `\s` class are Unicode-aware and
       would eat it, mismatching every signature over a value that has one.
       Written as escapes on purpose: an invisible byte in a fixture is one
       nobody can grep for. */
    const value = " \u00A0alpha\u00A0 \u00A0beta\u00A0 ";
    expect(canonicalHeaders([{ name: "X-Amz-Meta-Note", value }], ["x-amz-meta-note"])).toBe(
      "x-amz-meta-note:\u00A0alpha\u00A0 \u00A0beta\u00A0\n",
    );
  });

  it("gives a signed header the request does not carry an empty value", () => {
    expect(
      canonicalHeaders(
        [{ name: "Host", value: "s3.mountx.test:9001" }],
        ["host", "x-amz-storage-class"],
      ),
    ).toBe("host:s3.mountx.test:9001\nx-amz-storage-class:\n");
  });
});

// ---------------------------------------------------------------------------
// verification, against our own signer
// ---------------------------------------------------------------------------

/** This gateway's credentials — every character distinct from the suite's. */
const GATEWAY: SigV4Credentials = {
  accessKeyId: "AKIAMOUNTX7GATEWAY9",
  secretAccessKey: "Kp3+mountX/gateway-secret-0123456789abcdX",
};
const GATEWAY_REGION = "eu-central-1";
const GATEWAY_HOST = "s3.mountx.test:9001";
/** 2026-07-28T09:41:17Z, a time with no repeated field. */
const NOW = Date.UTC(2026, 6, 28, 9, 41, 17);

const OBJECT_PATH = "/holiday photos/über brücke.jpg";
const OBJECT_QUERY: QueryEntry[] = [{ name: "response-content-type", value: "image/jpeg" }];
const BODY_SHA256 = "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e";

interface Request {
  method: string;
  path: string;
  query: QueryEntry[];
  headers: HeaderEntry[];
}

/** A request signed in header form by our own signer, at `signedAt`. */
function headerSigned(
  signedAt = NOW,
  payloadHash = BODY_SHA256,
  service?: string,
  region = GATEWAY_REGION,
): Request {
  const headers: HeaderEntry[] = [
    { name: "Host", value: GATEWAY_HOST },
    { name: "X-Amz-Date", value: formatAmzDate(signedAt) },
    { name: "X-Amz-Content-Sha256", value: payloadHash },
  ];
  const signed = signRequest({
    method: "GET",
    path: OBJECT_PATH,
    query: OBJECT_QUERY,
    headers,
    credentials: GATEWAY,
    region,
    service,
    timestamp: signedAt,
    payloadHash,
  });
  return {
    method: "GET",
    path: OBJECT_PATH,
    query: OBJECT_QUERY,
    headers: [...headers, { name: "Authorization", value: signed.authorization }],
  };
}

/** A presigned request from our own signer. */
function presigned(signedAt = NOW, expiresIn = 900): Request {
  const headers: HeaderEntry[] = [{ name: "Host", value: GATEWAY_HOST }];
  const result = presignRequest({
    method: "PUT",
    path: OBJECT_PATH,
    query: [{ name: "x-id", value: "PutObject" }],
    headers,
    credentials: GATEWAY,
    region: GATEWAY_REGION,
    timestamp: signedAt,
    expiresIn,
  });
  return { method: "PUT", path: OBJECT_PATH, query: result.query, headers };
}

function verify(request: Request, now = NOW, region?: string) {
  return verifyRequest({ ...request, credentials: GATEWAY, now, region });
}

describe("verifyRequest, header form", () => {
  it("accepts what our own signer produced, and reports the scope it read", () => {
    const result = verify(headerSigned());
    expect(result).toEqual({
      ok: true,
      form: "header",
      accessKeyId: GATEWAY.accessKeyId,
      scope: { date: "20260728", region: GATEWAY_REGION, service: "s3" },
      signedHeaders: ["host", "x-amz-content-sha256", "x-amz-date"],
      payloadHash: BODY_SHA256,
      timestamp: NOW,
    });
  });

  it("refuses a path the signature does not cover", () => {
    const request = headerSigned();
    const result = verify({ ...request, path: "/holiday photos/über bruecke.jpg" });
    expect(result).toMatchObject({ ok: false, reason: "signature-mismatch" });
  });

  it("refuses a query parameter the signature does not cover", () => {
    const request = headerSigned();
    const result = verify({
      ...request,
      query: [...request.query, { name: "versionId", value: "17" }],
    });
    expect(result).toMatchObject({ ok: false, reason: "signature-mismatch" });
  });

  it("refuses a header value the signature does not cover", () => {
    const request = headerSigned();
    const headers = request.headers.map((header) =>
      header.name === "Host" ? { name: "Host", value: "evil.mountx.test:9001" } : header,
    );
    expect(verify({ ...request, headers })).toMatchObject({
      ok: false,
      reason: "signature-mismatch",
    });
  });

  it("refuses a request that lost a header its signature covers", () => {
    /* The signer signed `x-amz-storage-class`; something between the client and
       here dropped it. The canonical request then names the header with an
       empty value, so this comes out as a mismatch rather than a throw. */
    const headers: HeaderEntry[] = [
      { name: "Host", value: GATEWAY_HOST },
      { name: "X-Amz-Date", value: formatAmzDate(NOW) },
      { name: "X-Amz-Content-Sha256", value: BODY_SHA256 },
      { name: "X-Amz-Storage-Class", value: "GLACIER" },
    ];
    const signed = signRequest({
      method: "GET",
      path: OBJECT_PATH,
      query: OBJECT_QUERY,
      headers,
      credentials: GATEWAY,
      region: GATEWAY_REGION,
      timestamp: NOW,
      payloadHash: BODY_SHA256,
    });
    expect(signed.signedHeaders).toContain("x-amz-storage-class");

    const sent = [
      ...headers.filter((header) => header.name !== "X-Amz-Storage-Class"),
      { name: "Authorization", value: signed.authorization },
    ];
    expect(
      verify({ method: "GET", path: OBJECT_PATH, query: OBJECT_QUERY, headers: sent }),
    ).toMatchObject({ ok: false, reason: "signature-mismatch" });
  });

  it("takes UNSIGNED-PAYLOAD as the literal it was signed as", () => {
    const result = verify(headerSigned(NOW, UNSIGNED_PAYLOAD));
    expect(result).toMatchObject({ ok: true, payloadHash: UNSIGNED_PAYLOAD });
  });

  it("takes the streaming sentinel as the literal it was signed as", () => {
    const result = verify(headerSigned(NOW, STREAMING_PAYLOAD));
    expect(result).toMatchObject({ ok: true, payloadHash: STREAMING_PAYLOAD });
  });

  it("accepts a signature exactly 15 minutes old, and refuses one a millisecond older", () => {
    const request = headerSigned(NOW - MAX_CLOCK_SKEW_MS);
    expect(verify(request)).toMatchObject({ ok: true });
    expect(verify(request, NOW + 1)).toMatchObject({ ok: false, reason: "clock-skew" });
  });

  it("accepts a signature exactly 15 minutes ahead, and refuses one further out", () => {
    const request = headerSigned(NOW + MAX_CLOCK_SKEW_MS);
    expect(verify(request)).toMatchObject({ ok: true });
    expect(verify(request, NOW - 1)).toMatchObject({ ok: false, reason: "clock-skew" });
  });

  it("refuses an unknown access key id before it checks anything else", () => {
    const request = headerSigned();
    const headers = request.headers.map((header) =>
      header.name === "Authorization"
        ? {
            name: "Authorization",
            value: header.value.replace(GATEWAY.accessKeyId, "AKIAINTRUDER0"),
          }
        : header,
    );
    expect(verify({ ...request, headers })).toMatchObject({
      ok: false,
      reason: "unknown-access-key",
    });
  });

  it("refuses a scope naming another service", () => {
    expect(verify(headerSigned(NOW, BODY_SHA256, "execute-api"))).toMatchObject({
      ok: false,
      reason: "scope-mismatch",
    });
  });

  it("refuses a scope naming another region, but only when a region was configured", () => {
    const request = headerSigned(NOW, BODY_SHA256, undefined, "us-west-2");
    expect(verify(request)).toMatchObject({ ok: true });
    expect(verify(request, NOW, GATEWAY_REGION)).toMatchObject({
      ok: false,
      reason: "scope-mismatch",
    });
  });

  it("refuses a scope whose date is not the request's date", () => {
    const request = headerSigned();
    const headers = request.headers.map((header) =>
      header.name === "Authorization"
        ? { name: "Authorization", value: header.value.replace("/20260728/", "/20260727/") }
        : header,
    );
    expect(verify({ ...request, headers })).toMatchObject({ ok: false, reason: "scope-mismatch" });
  });

  it("refuses a request with no x-amz-date", () => {
    const request = headerSigned();
    const headers = request.headers.filter((header) => header.name !== "X-Amz-Date");
    expect(verify({ ...request, headers })).toEqual({
      ok: false,
      reason: "malformed",
      detail: "missing x-amz-date",
    });
  });

  it("refuses a request with no x-amz-content-sha256", () => {
    const request = headerSigned();
    const headers = request.headers.filter((header) => header.name !== "X-Amz-Content-Sha256");
    expect(verify({ ...request, headers })).toEqual({
      ok: false,
      reason: "malformed",
      detail: "missing x-amz-content-sha256",
    });
  });

  it("refuses an x-amz-date that is not a real instant", () => {
    const request = headerSigned();
    const headers = request.headers.map((header) =>
      header.name === "X-Amz-Date" ? { name: "X-Amz-Date", value: "20260230T094117Z" } : header,
    );
    expect(verify({ ...request, headers })).toMatchObject({ ok: false, reason: "malformed" });
  });

  it("refuses an unsigned request by name", () => {
    const request = headerSigned();
    const headers = request.headers.filter((header) => header.name !== "Authorization");
    expect(verify({ ...request, headers })).toMatchObject({ ok: false, reason: "missing" });
  });

  it("bounds the client text it repeats in a refusal detail", () => {
    const request = headerSigned();
    const headers = request.headers.map((header) =>
      header.name === "Authorization"
        ? {
            name: "Authorization",
            value: header.value.replace(GATEWAY.accessKeyId, "A".repeat(4096)),
          }
        : header,
    );
    const result = verify({ ...request, headers });
    expect(result).toMatchObject({ ok: false, reason: "unknown-access-key" });
    expect((result as { detail: string }).detail.length).toBeLessThan(128);
  });

  it("never repeats a control character into a refusal detail", () => {
    const request = headerSigned();
    const headers = request.headers.map((header) =>
      header.name === "Authorization"
        ? {
            name: "Authorization",
            value: header.value.replace(GATEWAY_REGION, "eu\ncentral\r1\u0000"),
          }
        : header,
    );
    const result = verify({ ...request, headers }, NOW, GATEWAY_REGION);
    expect(result).toMatchObject({ ok: false, reason: "scope-mismatch" });
    /* A forged log line is somebody else's problem to explain. */
    const codes = [...(result as { detail: string }).detail].map(
      (character) => character.codePointAt(0) ?? 0,
    );
    expect(Math.min(...codes)).toBeGreaterThanOrEqual(0x20);
    expect(codes).not.toContain(0x7f);
  });

  it("names every malformed Authorization header instead of throwing", () => {
    const malformed = [
      "",
      "Basic dXNlcjpwYXNz",
      "AWS4-HMAC-SHA256",
      "AWS4-HMAC-SHA256 Credential",
      "AWS4-HMAC-SHA256 Credential=AKIAMOUNTX7GATEWAY9/20260728/eu-central-1/s3/aws4_request",
      "AWS4-HMAC-SHA256 Credential=AKIAMOUNTX7GATEWAY9/eu-central-1/s3/aws4_request, SignedHeaders=host, Signature=00",
      "AWS4-HMAC-SHA256 Credential=AKIAMOUNTX7GATEWAY9/20260728/eu-central-1/s3/not_aws4, SignedHeaders=host, Signature=00",
      "AWS4-HMAC-SHA256 Credential=AKIAMOUNTX7GATEWAY9/20260728/eu-central-1/s3/aws4_request, SignedHeaders=, Signature=00",
      "AWS4-HMAC-SHA256 Credential=AKIAMOUNTX7GATEWAY9/20260728/eu-central-1/s3/aws4_request, SignedHeaders=host, Signature=",
      "AWS3-HTTPS Credential=AKIAMOUNTX7GATEWAY9/20260728/eu-central-1/s3/aws4_request, SignedHeaders=host, Signature=00",
    ];
    const request = headerSigned();
    for (const value of malformed) {
      const headers = [
        ...request.headers.filter((header) => header.name !== "Authorization"),
        { name: "Authorization", value },
      ];
      const result = verify({ ...request, headers });
      expect(result.ok, value).toBe(false);
      expect(["malformed", "unsupported-algorithm"], value).toContain(
        (result as { reason: string }).reason,
      );
    }
  });
});

describe("verifyRequest, presigned form", () => {
  it("accepts a URL our own signer minted, with an unsigned payload", () => {
    const result = verify(presigned());
    expect(result).toMatchObject({
      ok: true,
      form: "presigned",
      accessKeyId: GATEWAY.accessKeyId,
      payloadHash: UNSIGNED_PAYLOAD,
      signedHeaders: ["host"],
      timestamp: NOW,
    });
  });

  it("round-trips a URL signed over a body hash, when the request carries that header", () => {
    /* Nothing in the query records a non-default `payloadHash`, so the only
       place a verifier can recover it from is `x-amz-content-sha256` on the
       request the URL is used for. Signer and verifier agree on that. */
    const headers: HeaderEntry[] = [
      { name: "Host", value: GATEWAY_HOST },
      { name: "X-Amz-Content-Sha256", value: BODY_SHA256 },
    ];
    const result = presignRequest({
      method: "PUT",
      path: OBJECT_PATH,
      headers,
      signedHeaders: ["host"],
      credentials: GATEWAY,
      region: GATEWAY_REGION,
      timestamp: NOW,
      expiresIn: 900,
      payloadHash: BODY_SHA256,
    });
    expect(
      verify({ method: "PUT", path: OBJECT_PATH, query: result.query, headers }),
    ).toMatchObject({ ok: true, form: "presigned", payloadHash: BODY_SHA256 });

    /* Without the header the verifier falls back to UNSIGNED-PAYLOAD, which is
       not what was signed — a mismatch, and the documented consequence. */
    expect(
      verify({
        method: "PUT",
        path: OBJECT_PATH,
        query: result.query,
        headers: [{ name: "Host", value: GATEWAY_HOST }],
      }),
    ).toMatchObject({ ok: false, reason: "signature-mismatch" });
  });

  it("accepts it at the last instant of its life and refuses it a millisecond later", () => {
    const request = presigned(NOW, 900);
    expect(verify(request, NOW + 900_000)).toMatchObject({ ok: true });
    expect(verify(request, NOW + 900_001)).toMatchObject({ ok: false, reason: "expired" });
  });

  it("accepts a URL signed at the edge of the skew window and refuses one beyond it", () => {
    /* A second, not a millisecond: `X-Amz-Date` has one-second resolution, so
       anything finer than that is the same signature. */
    expect(verify(presigned(NOW + MAX_CLOCK_SKEW_MS))).toMatchObject({ ok: true });
    expect(verify(presigned(NOW + MAX_CLOCK_SKEW_MS + 1000))).toMatchObject({
      ok: false,
      reason: "clock-skew",
    });
  });

  it("refuses a tampered signature", () => {
    const request = presigned();
    const query = request.query.map((entry) =>
      entry.name === "X-Amz-Signature"
        ? {
            name: entry.name,
            value: entry.value.replace(/^./, (first) => (first === "0" ? "1" : "0")),
          }
        : entry,
    );
    expect(verify({ ...request, query })).toMatchObject({
      ok: false,
      reason: "signature-mismatch",
    });
  });

  it("refuses a tampered path", () => {
    const request = presigned();
    expect(verify({ ...request, path: "/holiday photos/über brucke.jpg" })).toMatchObject({
      ok: false,
      reason: "signature-mismatch",
    });
  });

  it("refuses an extra query parameter smuggled in after signing", () => {
    const request = presigned();
    const query = [...request.query, { name: "x-amz-acl", value: "public-read" }];
    expect(verify({ ...request, query })).toMatchObject({
      ok: false,
      reason: "signature-mismatch",
    });
  });

  it("refuses a signature parameter with nothing else beside it", () => {
    const result = verifyRequest({
      method: "GET",
      path: OBJECT_PATH,
      query: [{ name: "X-Amz-Signature", value: "deadbeef" }],
      headers: [{ name: "Host", value: GATEWAY_HOST }],
      credentials: GATEWAY,
      now: NOW,
    });
    expect(result).toMatchObject({ ok: false, reason: "malformed" });
  });

  it("refuses an expiry outside the one-week range", () => {
    for (const expires of ["0", "604801", "-60", "9e9", ""]) {
      const request = presigned();
      const query = request.query.map((entry) =>
        entry.name === "X-Amz-Expires" ? { name: entry.name, value: expires } : entry,
      );
      expect(verify({ ...request, query }), expires).toMatchObject({
        ok: false,
        reason: "malformed",
      });
    }
  });

  it("names every malformed or mismatched parameter instead of throwing", () => {
    const cases: [name: string, value: string, reason: string][] = [
      ["X-Amz-Algorithm", "AWS3-HTTPS", "unsupported-algorithm"],
      ["X-Amz-Date", "20260230T094117Z", "malformed"],
      ["X-Amz-Date", "yesterday", "malformed"],
      ["X-Amz-Credential", "AKIAMOUNTX7GATEWAY9/20260728/eu-central-1/s3", "malformed"],
      ["X-Amz-Credential", "/20260728/eu-central-1/s3/aws4_request", "malformed"],
      [
        "X-Amz-Credential",
        "AKIAINTRUDER0/20260728/eu-central-1/s3/aws4_request",
        "unknown-access-key",
      ],
      [
        "X-Amz-Credential",
        "AKIAMOUNTX7GATEWAY9/20260728/eu-central-1/execute-api/aws4_request",
        "scope-mismatch",
      ],
      [
        "X-Amz-Credential",
        "AKIAMOUNTX7GATEWAY9/20260727/eu-central-1/s3/aws4_request",
        "scope-mismatch",
      ],
      ["X-Amz-SignedHeaders", "", "malformed"],
    ];
    for (const [name, value, reason] of cases) {
      const request = presigned();
      const query = request.query.map((entry) => (entry.name === name ? { name, value } : entry));
      expect(verify({ ...request, query }), `${name}=${value}`).toMatchObject({
        ok: false,
        reason,
      });
    }
  });

  it("prefers the presigned form when both forms are present", () => {
    const request = presigned();
    const headers = [
      ...request.headers,
      { name: "Authorization", value: "AWS4-HMAC-SHA256 nonsense" },
    ];
    expect(verify({ ...request, headers })).toMatchObject({ ok: true, form: "presigned" });
  });
});

// ---------------------------------------------------------------------------
// the small pieces
// ---------------------------------------------------------------------------

describe("timestamps", () => {
  it("formats a millisecond epoch as ISO 8601 basic", () => {
    expect(formatAmzDate(NOW)).toBe("20260728T094117Z");
  });

  it("round-trips through the parser", () => {
    expect(parseAmzDate(formatAmzDate(NOW))).toBe(NOW);
  });

  it("refuses anything that is not one, including a date that does not exist", () => {
    for (const value of [
      "",
      "20260230T094117Z",
      "2026-07-28T09:41:17Z",
      "20260728T094117",
      "20260728T2461172",
    ]) {
      expect(parseAmzDate(value), value).toBeUndefined();
    }
  });
});

describe("parsing", () => {
  it("takes an Authorization header apart into distinct fields", () => {
    const parsed = parseAuthorizationHeader(
      "AWS4-HMAC-SHA256 Credential=AKIAMOUNTX7GATEWAY9/20260728/eu-central-1/s3/aws4_request, " +
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abc123",
    );
    expect(parsed).toEqual({
      algorithm: "AWS4-HMAC-SHA256",
      accessKeyId: "AKIAMOUNTX7GATEWAY9",
      scope: { date: "20260728", region: "eu-central-1", service: "s3" },
      signedHeaders: ["host", "x-amz-content-sha256", "x-amz-date"],
      signature: "abc123",
    });
  });

  it("reads the six presigned parameters, whatever case they arrive in", () => {
    const parsed = parsePresignedQuery([
      { name: "x-amz-algorithm", value: "AWS4-HMAC-SHA256" },
      {
        name: "x-amz-credential",
        value: "AKIAMOUNTX7GATEWAY9/20260728/eu-central-1/s3/aws4_request",
      },
      { name: "x-amz-date", value: "20260728T094117Z" },
      { name: "x-amz-expires", value: "900" },
      { name: "x-amz-signedheaders", value: "host" },
      { name: "x-amz-signature", value: "fedcba" },
    ]);
    expect(parsed).toEqual({
      algorithm: "AWS4-HMAC-SHA256",
      accessKeyId: "AKIAMOUNTX7GATEWAY9",
      scope: { date: "20260728", region: "eu-central-1", service: "s3" },
      signedHeaders: ["host"],
      signature: "fedcba",
      amzDate: "20260728T094117Z",
      expiresIn: 900,
    });
  });

  it("answers undefined rather than throwing on junk", () => {
    expect(parseAuthorizationHeader("nonsense")).toBeUndefined();
    expect(parsePresignedQuery([])).toBeUndefined();
  });
});

describe("signaturesMatch", () => {
  it("compares equal signatures, whatever case they are written in", () => {
    expect(signaturesMatch("5fa00fa31553b73e", "5FA00FA31553B73E")).toBe(true);
  });

  it("answers false for a different length instead of throwing", () => {
    expect(signaturesMatch("5fa00fa31553b73e", "5fa0")).toBe(false);
    expect(signaturesMatch("", "0")).toBe(false);
  });

  it("answers false for the same length and different bytes", () => {
    expect(signaturesMatch("5fa00fa31553b73e", "5fa00fa31553b73f")).toBe(false);
  });
});
