/**
 * Tier 0 for `src/nfs/v4/attr.ts`: the `bitmap4`/`fattr4` codec.
 *
 * Two kinds of check, for the reason `test/nfs/v3/golden.test.ts` gives at
 * length: round trips prove the codec agrees with *itself*, which a
 * consistently wrong codec also does, so the fixtures here are written out by
 * hand from RFC 8881 (§3.3.7, §5.6 table 4, §5.7 table 5) and RFC 5662 §2 —
 * word by word, with **every field a distinct value**, since a fixture built
 * from repeated values is satisfied by an encoder and decoder that transpose
 * the same pair.
 *
 * The sparse container has two failure modes NFSv3's fixed struct does not, and
 * both are pinned below: attributes are packed in bit order with nothing but
 * their own types to say where each ends, and a bitmap can name attributes past
 * anything this server has heard of.
 */

import { describe, expect, it } from "vitest";
import {
  bitmapBits,
  bitmapDifference,
  bitmapHas,
  bitmapIntersection,
  bitmapIsEmpty,
  bitmapOf,
  changeOf,
  decodeFattr,
  encodeFattr,
  fattr4FsOf,
  fattr4Of,
  fromTime4,
  ftype4Of,
  GETABLE_ATTRS,
  KNOWN_ATTRS,
  modeType4Of,
  numericOwner,
  parseNumericOwner,
  readBitmap,
  readTime4,
  SET_ONLY_ATTRS,
  SETTABLE_ATTRS,
  SUPPORTED_ATTRS,
  toTime4,
  writeBitmap,
  writeTime4,
  type Fattr4Values,
} from "../../../src/nfs/v4/attr.ts";
import {
  FATTR4_CHANGE,
  FATTR4_FILEHANDLE,
  FATTR4_MODE,
  FATTR4_OWNER,
  FATTR4_OWNER_GROUP,
  FATTR4_SIZE,
  FATTR4_SUPPATTR_EXCLCREAT,
  FATTR4_TIME_ACCESS,
  FATTR4_TIME_ACCESS_SET,
  FATTR4_TIME_MODIFY_SET,
  FATTR4_TYPE,
  NF4BLK,
  NF4CHR,
  NF4DIR,
  NF4FIFO,
  NF4LNK,
  NF4REG,
  NF4SOCK,
  SET_TO_CLIENT_TIME4,
  SET_TO_SERVER_TIME4,
} from "../../../src/nfs/v4/constants.ts";
import { decodeXdr, encodeXdr, isXdrError, XdrReader, XdrWriter } from "../../../src/nfs/xdr.ts";
import {
  S_IFBLK,
  S_IFCHR,
  S_IFDIR,
  S_IFIFO,
  S_IFLNK,
  S_IFREG,
  S_IFSOCK,
  type StatsLike,
} from "../../../src/types.ts";

/** Bytes as lowercase hex, in 4-byte words, for a readable diff. */
function hex(bytes: Uint8Array): string {
  const words: string[] = [];
  for (let at = 0; at < bytes.byteLength; at += 4) {
    words.push(
      [...bytes.subarray(at, at + 4)].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
    );
  }
  return words.join(" ");
}

/** Hex words → bytes, so a fixture can be written the way the RFC prints it. */
function bytesOf(words: readonly string[]): Uint8Array {
  const joined = words.join("");
  const bytes = new Uint8Array(joined.length / 2);
  for (let at = 0; at < bytes.byteLength; at++) {
    bytes[at] = Number.parseInt(joined.slice(at * 2, at * 2 + 2), 16);
  }
  return bytes;
}

describe("bitmap4", () => {
  it("encodes the count and the words, low word first (RFC 8881 §3.3.7)", () => {
    // Attribute 0 is bit 0 of word 0; attribute 33 is bit 1 of word 1.
    const bytes = encodeXdr((writer) => writeBitmap(writer, bitmapOf([0, 33])));
    expect(hex(bytes)).toBe(
      [
        "00000002", // bitmap4 count = 2 words
        "00000001", // word 0: bit 0 (supported_attrs)
        "00000002", // word 1: bit 1 = attribute 33 (mode)
      ].join(" "),
    );
  });

  it("round-trips an empty bitmap as a bare count of zero", () => {
    const bytes = encodeXdr((writer) => writeBitmap(writer, bitmapOf([])));
    expect(hex(bytes)).toBe("00000000");
    expect(decodeXdr(bytes, (reader) => readBitmap(reader))).toEqual([]);
    expect(bitmapIsEmpty([])).toBe(true);
    // All-zero words count as empty too — a client may pad, and "no attributes"
    // is what it means either way.
    expect(bitmapIsEmpty([0, 0])).toBe(true);
    expect(bitmapIsEmpty([0, 1])).toBe(false);
  });

  it("keeps a bitmap wider than this server understands, word for word", () => {
    // suppattr_exclcreat is attribute 75: bit 11 of word 2. A request naming it
    // has three words, one more than `SUPPORTED_ATTRS` ever needs, and the
    // decoder must carry it through rather than truncate to what it knows.
    const words = [
      "00000003", // count = 3 words
      "00000018", // word 0: bits 3 and 4 (change, size)
      "00000002", // word 1: bit 1 = attribute 33 (mode)
      "00000800", // word 2: bit 11 = attribute 75 (suppattr_exclcreat)
    ];
    const bitmap = decodeXdr(bytesOf(words), (reader) => readBitmap(reader));
    expect(bitmap).toEqual([0x18, 0x2, 0x800]);
    expect(bitmapBits(bitmap)).toEqual([
      FATTR4_CHANGE,
      FATTR4_SIZE,
      FATTR4_MODE,
      FATTR4_SUPPATTR_EXCLCREAT,
    ]);
    expect(bitmapHas(bitmap, FATTR4_SUPPATTR_EXCLCREAT)).toBe(true);
    // And back out byte-identically: the third word is not ours to normalize.
    expect(hex(encodeXdr((writer) => writeBitmap(writer, bitmap)))).toBe(words.join(" "));
  });

  it("sets the top bit of a word without going negative", () => {
    // Attribute 31 is `1 << 31`, which is negative as a JS number; a word that
    // escaped as -2147483648 would encode fine and compare wrong everywhere else.
    const bitmap = bitmapOf([31]);
    expect(bitmap).toEqual([0x80_00_00_00]);
    expect(bitmap[0]).toBeGreaterThan(0);
    expect(bitmapHas(bitmap, 31)).toBe(true);
    expect(bitmapHas(bitmap, 30)).toBe(false);
  });

  it("drops trailing zero words when building, so a reply is minimal", () => {
    expect(bitmapOf([0])).toEqual([1]);
    expect(bitmapOf([])).toEqual([]);
    // A bit in word 2 forces the empty word 1 to stay: it is not trailing.
    expect(bitmapOf([0, 75])).toEqual([1, 0, 0x800]);
  });

  it("reads a bit beyond the words present as unset", () => {
    expect(bitmapHas([1], 999)).toBe(false);
  });

  it("refuses a bit no bitmap4 could carry", () => {
    expect(() => bitmapOf([-1])).toThrow(/cannot carry attribute/);
    expect(() => bitmapOf([512])).toThrow(/cannot carry attribute/);
    expect(() => bitmapOf([1.5])).toThrow(/cannot carry attribute/);
  });

  it("intersects and subtracts", () => {
    expect(bitmapIntersection(bitmapOf([1, 33, 75]), bitmapOf([33, 47]))).toEqual(bitmapOf([33]));
    expect(bitmapDifference(bitmapOf([1, 33, 75]), bitmapOf([33]))).toEqual(bitmapOf([1, 75]));
  });

  it("fails with an XdrError on a bitmap wider than its own message", () => {
    // A count is an allocation an attacker chooses the size of, so it is
    // checked against the bytes actually present before anything is read —
    // whether it is off by one word or absurd.
    for (const words of [["00000002", "00000001"], ["ffffffff", "00000001"], ["000000"]]) {
      let thrown: unknown;
      try {
        decodeXdr(bytesOf(words), (reader) => readBitmap(reader));
      } catch (error) {
        thrown = error;
      }
      expect(isXdrError(thrown)).toBe(true);
    }
  });
});

describe("nfstime4", () => {
  it("encodes int64 seconds and uint32 nanoseconds (RFC 5662 §2)", () => {
    // Not nfstime3: seconds is 64 bits *and* signed here.
    const bytes = encodeXdr((writer) =>
      writeTime4(writer, { seconds: 1_700_000_000n, nseconds: 123_456_789 }),
    );
    expect(hex(bytes)).toBe(
      [
        "00000000",
        "6553f100", // seconds = 1700000000 (int64, high word first)
        "075bcd15", // nseconds = 123456789
      ].join(" "),
    );
    expect(decodeXdr(bytes, (reader) => readTime4(reader))).toEqual({
      seconds: 1_700_000_000n,
      nseconds: 123_456_789,
    });
  });

  it("carries a time before the epoch, which nfstime3 cannot", () => {
    const time = toTime4(-1500);
    expect(time).toEqual({ seconds: -2n, nseconds: 500_000_000 });
    expect(fromTime4(time)).toBe(-1500);
    expect(hex(encodeXdr((writer) => writeTime4(writer, time)))).toBe(
      ["ffffffff", "fffffffe", "1dcd6500"].join(" "),
    );
  });

  it("splits milliseconds into whole seconds and nanoseconds", () => {
    expect(toTime4(1_700_000_000_123)).toEqual({
      seconds: 1_700_000_000n,
      nseconds: 123_000_000,
    });
    // Sub-millisecond precision survives as far as a double carries it.
    expect(toTime4(1_700_000_000_000.5)).toEqual({ seconds: 1_700_000_000n, nseconds: 500_000 });
    expect(toTime4(Number.NaN)).toEqual({ seconds: 0n, nseconds: 0 });
  });
});

describe("the advertised attribute set", () => {
  /**
   * `SUPPORTED_ATTRS` written out by hand, bit by bit, rather than derived from
   * the constant it checks.
   *
   * Word 0: attributes 0..11 (0x00000fff), 19..23 (0x00f80000), 27..31
   * (0xf8000000). Word 1: 33 (bit 1), 35..37 (bits 3..5), 41..45 (bits 9..13),
   * 47..48 (bits 15..16), 51..54 (bits 19..22) — 0x0079be3a.
   */
  it("is the two words RFC 8881's numbering makes it", () => {
    expect(SUPPORTED_ATTRS).toEqual([0xf8_f8_0f_ff, 0x00_79_be_3a]);
    expect(bitmapBits(SUPPORTED_ATTRS)).toEqual([
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 19, 20, 21, 22, 23, 27, 28, 29, 30, 31, 33, 35, 36, 37,
      41, 42, 43, 44, 45, 47, 48, 51, 52, 53, 54,
    ]);
  });

  it("advertises only attributes the codec can actually encode", () => {
    expect(bitmapDifference(SUPPORTED_ATTRS, KNOWN_ATTRS)).toEqual([]);
  });

  it("keeps the write-only pair out of what a GETATTR may return (§5.5)", () => {
    expect(bitmapBits(SET_ONLY_ATTRS)).toEqual([FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET]);
    expect(bitmapHas(GETABLE_ATTRS, FATTR4_TIME_ACCESS_SET)).toBe(false);
    expect(bitmapHas(GETABLE_ATTRS, FATTR4_TIME_MODIFY_SET)).toBe(false);
    expect(bitmapHas(GETABLE_ATTRS, FATTR4_TIME_ACCESS)).toBe(true);
    // Everything else is shared, so the two differ by exactly that pair.
    expect(bitmapDifference(SUPPORTED_ATTRS, GETABLE_ATTRS)).toEqual([...SET_ONLY_ATTRS]);
  });

  it("keeps every settable attribute inside the supported set", () => {
    expect(bitmapDifference(SETTABLE_ATTRS, SUPPORTED_ATTRS)).toEqual([]);
    expect(bitmapBits(SETTABLE_ATTRS)).toEqual([
      FATTR4_SIZE,
      FATTR4_MODE,
      FATTR4_OWNER,
      FATTR4_OWNER_GROUP,
      FATTR4_TIME_ACCESS_SET,
      FATTR4_TIME_MODIFY_SET,
    ]);
  });

  it("does not claim the attributes no driver can answer", () => {
    for (const bit of [12 /* acl */, 50 /* time_create */, 55 /* mounted_on_fileid */, 75, 76]) {
      expect(bitmapHas(SUPPORTED_ATTRS, bit)).toBe(false);
    }
  });
});

describe("fattr4 golden fixtures", () => {
  /**
   * **Every field gets a distinct value, on purpose** — the same rule
   * `test/nfs/v3/golden.test.ts` documents. Adjacent same-typed attributes are
   * where a transposition hides, and this container has whole runs of them
   * (`fsid`'s two halves, `owner`/`owner_group`, the three timestamps).
   */
  const GOLDEN_VALUES: Fattr4Values = {
    type: NF4DIR, // 2
    change: 0x01_23_45_67_89_ab_cd_efn,
    size: 0x00_00_00_01_00_00_10_00n, // 4 GiB + 4096: both halves non-zero
    fsid: { major: 0x11_22_33_44_55_66_77_88n, minor: 0x99_aa_bb_cc_dd_ee_ff_00n },
    fileid: 0x0a_0b_0c_0d_0e_0f_10_11n,
    mode: 0o751,
    numlinks: 3,
    owner: "1000",
    ownerGroup: "100",
    rawdev: { major: 13, minor: 9 },
    spaceUsed: 0x00_00_00_04_00_00_20_00n,
    timeAccess: { seconds: 1_700_000_001n, nseconds: 111_111_111 },
    timeMetadata: { seconds: 1_700_000_002n, nseconds: 222_222_222 },
    timeModify: { seconds: 1_700_000_003n, nseconds: 333_333_333 },
  };

  /**
   * The attributes above in ascending bit order — 1, 3, 4, 8, 20, 33, 35, 36,
   * 37, 41, 45, 47, 52, 53 — written out as the words they occupy.
   *
   * Bitmap word 0 has bits 1, 3, 4, 8, 20 = 0x2 + 0x8 + 0x10 + 0x100 +
   * 0x100000 = 0x0010011a. Word 1 has bits 1 (33), 3 (35), 4 (36), 5 (37), 9
   * (41), 13 (45), 15 (47), 20 (52), 21 (53) = 0x2 + 0x8 + 0x10 + 0x20 + 0x200
   * + 0x2000 + 0x8000 + 0x100000 + 0x200000 = 0x0030a23a.
   *
   * `attr_vals` is an `opaque<>`, so the values are preceded by their own byte
   * count: 4 (type) + 8 (change) + 8 (size) + 16 (fsid) + 8 (fileid) + 4 (mode)
   * + 4 (numlinks) + 8 (owner) + 8 (owner_group, padded) + 8 (rawdev) + 8
   * (space_used) + 3 × 12 (times) = 120.
   */
  const GOLDEN_WORDS = [
    "00000002", // attrmask: bitmap4 count = 2 words
    "0010011a", // word 0: type, change, size, fsid, fileid
    "0030a23a", // word 1: mode, numlinks, owner, owner_group, rawdev, space_used, times
    "00000078", // attrlist4 length = 120 bytes
    "00000002", // 1  type = NF4DIR
    "01234567",
    "89abcdef", // 3  change (uint64)
    "00000001",
    "00001000", // 4  size = 0x100001000
    "11223344",
    "55667788", // 8  fsid.major
    "99aabbcc",
    "ddeeff00", // 8  fsid.minor
    "0a0b0c0d",
    "0e0f1011", // 20 fileid
    "000001e9", // 33 mode = 0751 — permission bits only, no S_IFMT
    "00000003", // 35 numlinks = 3
    "00000004",
    "31303030", // 36 owner = "1000" (length 4, no padding needed)
    "00000003",
    "31303000", // 37 owner_group = "100" plus one byte of XDR padding
    "0000000d", // 41 rawdev.specdata1 = 13 (major)
    "00000009", // 41 rawdev.specdata2 = 9 (minor)
    "00000004",
    "00002000", // 45 space_used = 0x400002000
    "00000000",
    "6553f101",
    "069f6bc7", // 47 time_access = 1700000001 s (int64), 111111111 ns
    "00000000",
    "6553f102",
    "0d3ed78e", // 52 time_metadata = 1700000002 s, 222222222 ns
    "00000000",
    "6553f103",
    "13de4355", // 53 time_modify = 1700000003 s, 333333333 ns
  ];

  it("gives every field of the fixture a distinct value", () => {
    // Not the *words* — lengths and the zero high word of a timestamp repeat
    // however the fixture is written — but every value a transposition could
    // swap, which is the property the rule is really about.
    const fields = [
      GOLDEN_VALUES.type,
      GOLDEN_VALUES.change,
      GOLDEN_VALUES.size,
      GOLDEN_VALUES.fsid?.major,
      GOLDEN_VALUES.fsid?.minor,
      GOLDEN_VALUES.fileid,
      GOLDEN_VALUES.mode,
      GOLDEN_VALUES.numlinks,
      GOLDEN_VALUES.owner,
      GOLDEN_VALUES.ownerGroup,
      GOLDEN_VALUES.rawdev?.major,
      GOLDEN_VALUES.rawdev?.minor,
      GOLDEN_VALUES.spaceUsed,
      GOLDEN_VALUES.timeAccess?.seconds,
      GOLDEN_VALUES.timeAccess?.nseconds,
      GOLDEN_VALUES.timeMetadata?.seconds,
      GOLDEN_VALUES.timeMetadata?.nseconds,
      GOLDEN_VALUES.timeModify?.seconds,
      GOLDEN_VALUES.timeModify?.nseconds,
    ].map(String);
    expect(new Set(fields).size).toBe(fields.length);
  });

  it("packs a fattr4 in ascending attribute order", () => {
    const bytes = encodeXdr((writer) =>
      encodeFattr(writer, SUPPORTED_ATTRS, GOLDEN_VALUES, SUPPORTED_ATTRS),
    );
    expect(hex(bytes)).toBe(GOLDEN_WORDS.join(" "));
  });

  it("decodes the same bytes back to the same values", () => {
    const decoded = decodeXdr(bytesOf(GOLDEN_WORDS), (reader) => decodeFattr(reader));
    expect(decoded.attrmask).toEqual([0x00_10_01_1a, 0x00_30_a2_3a]);
    expect(decoded.unsupported).toEqual([]);
    expect(decoded.values).toEqual(GOLDEN_VALUES);
  });

  it("copies the filehandle it decodes rather than viewing the record", () => {
    const handle = new Uint8Array([0x55, 0x4e, 0x46, 0x53, 0xa1, 0xb2, 0xc3, 0xd4]);
    // A `Buffer`, deliberately: `Buffer.prototype.slice` is `subarray`, so a
    // decoder that reached for it would hand back a view of this record.
    const record = Buffer.from(
      encodeXdr((writer) =>
        encodeFattr(writer, bitmapOf([FATTR4_FILEHANDLE]), { filehandle: handle }),
      ),
    );
    const decoded = decodeFattr(new XdrReader(record));
    // Compared as plain arrays: `Uint8Array.prototype.slice` copies through the
    // species constructor, so a copy taken out of a `Buffer` is itself a
    // `Buffer` — which is a copy all the same, and that is what is under test.
    expect([...(decoded.values.filehandle ?? [])]).toEqual([...handle]);
    record.fill(0);
    expect([...(decoded.values.filehandle ?? [])]).toEqual([...handle]);
  });

  it("answers a full GETATTR of everything this server supports", () => {
    const values: Fattr4Values = {
      ...GOLDEN_VALUES,
      supportedAttrs: SUPPORTED_ATTRS,
      fhExpireType: 0, // FH4_PERSISTENT
      // Alternating, so a transposition between two adjacent booleans shows up
      // as a changed value rather than the same word twice.
      linkSupport: true,
      symlinkSupport: false,
      namedAttr: true,
      uniqueHandles: false,
      leaseTime: 90,
      rdattrError: 10_004, // NFS4ERR_NOTSUPP, so it differs from fh_expire_type
      filehandle: new Uint8Array([1, 2, 3, 4]),
      filesAvail: 21n,
      filesFree: 22n,
      filesTotal: 23n,
      maxfilesize: 0x00_1f_ff_ff_ff_ff_ff_ffn,
      maxlink: 32_000,
      maxname: 255,
      maxread: 0x10_00_00n,
      maxwrite: 0x08_00_00n,
      spaceAvail: 42n,
      spaceFree: 43n,
      spaceTotal: 44n,
      timeDelta: { seconds: 0n, nseconds: 1_000_000 },
    };
    const bytes = encodeXdr((writer) => encodeFattr(writer, SUPPORTED_ATTRS, values));
    const decoded = decodeXdr(bytes, (reader) => decodeFattr(reader));
    // The reply bitmap is the supported set minus the two write-only bits,
    // which no GETATTR may carry — and it is what the decoder read back.
    expect(decoded.attrmask).toEqual([...GETABLE_ATTRS]);
    expect(decoded.unsupported).toEqual([]);
    expect(decoded.values).toEqual(values);
  });

  it("writes a SETATTR fattr4 with both settime4 arms", () => {
    // `union settime4 switch (time_how4 set_it)` (RFC 5662 §2): only
    // SET_TO_CLIENT_TIME4 carries an nfstime4; SET_TO_SERVER_TIME4 selects the
    // void arm, so that attribute is one word and nothing more.
    const values: Fattr4Values = {
      size: 0x00_00_00_00_00_00_04_00n,
      mode: 0o644,
      owner: "1000",
      ownerGroup: "100",
      timeAccessSet: { how: SET_TO_SERVER_TIME4 },
      timeModifySet: {
        how: SET_TO_CLIENT_TIME4,
        time: { seconds: 1_700_000_009n, nseconds: 987_654_321 },
      },
    };
    const bytes = encodeXdr((writer) =>
      encodeFattr(writer, SETTABLE_ATTRS, values, SETTABLE_ATTRS),
    );
    expect(hex(bytes)).toBe(
      [
        "00000002", // attrmask count = 2 words
        "00000010", // word 0: bit 4 = size
        "00410032", // word 1: bits 1, 4, 5 (mode, owner, owner_group), 16 (48), 22 (54)
        "00000030", // attrlist4 length = 8 + 4 + 8 + 8 + 4 + 16 = 48
        "00000000",
        "00000400", // 4  size = 1024
        "000001a4", // 33 mode = 0644
        "00000004",
        "31303030", // 36 owner = "1000"
        "00000003",
        "31303000", // 37 owner_group = "100" plus padding
        "00000000", // 48 time_access_set: set_it = SET_TO_SERVER_TIME4, void arm
        "00000001", // 54 time_modify_set: set_it = SET_TO_CLIENT_TIME4
        "00000000",
        "6553f109",
        "3ade68b1", // 54 ... nfstime4 = 1700000009 s, 987654321 ns
      ].join(" "),
    );
    expect(decodeXdr(bytes, (reader) => decodeFattr(reader)).values).toEqual(values);
  });
});

describe("decodeFattr", () => {
  it("stops at the first attribute it cannot name and says which", () => {
    // A client asking to set `archive` (14) alongside `mode` (33): the value of
    // 14 has no length prefix, so nothing after it can be parsed. `mode` is
    // numbered after 14, so it is exactly what is lost.
    const bytes = bytesOf([
      "00000002", // attrmask count
      "00004000", // word 0: bit 14 = archive
      "00000002", // word 1: bit 1 = attribute 33 (mode)
      "00000008", // attrlist4 length = 8
      "00000001", // archive = TRUE
      "000001a4", // mode = 0644
    ]);
    const decoded = decodeXdr(bytes, (reader) => decodeFattr(reader));
    expect(decoded.unsupported).toEqual([14]);
    expect(decoded.values).toEqual({});
    expect(decoded.attrmask).toEqual([0x4000, 0x2]);
  });

  it("keeps the attributes numbered below the unsupported one", () => {
    const bytes = bytesOf([
      "00000001", // attrmask count = 1 word
      "00004010", // word 0: bit 4 (size) and bit 14 (archive)
      "0000000c", // attrlist4 length = 12
      "00000000",
      "00000400", // size = 1024
      "00000001", // archive = TRUE
    ]);
    const decoded = decodeXdr(bytes, (reader) => decodeFattr(reader));
    expect(decoded.values).toEqual({ size: 1024n });
    expect(decoded.unsupported).toEqual([14]);
  });

  it("reports every unknown bit, not just the one it stopped on", () => {
    const bytes = bytesOf([
      "00000003",
      "00004000", // bit 14 = archive
      "00000000",
      "00000800", // bit 75 = suppattr_exclcreat
      "00000004",
      "00000001",
    ]);
    expect(decodeXdr(bytes, (reader) => decodeFattr(reader)).unsupported).toEqual([14, 75]);
  });

  it("refuses an attrlist4 with bytes left over", () => {
    const bytes = bytesOf([
      "00000001",
      "00000010", // bit 4 = size
      "0000000c", // attrlist4 length = 12, four more than a size needs
      "00000000",
      "00000400",
      "deadbeef",
    ]);
    expect(() => decodeXdr(bytes, (reader) => decodeFattr(reader))).toThrow(/trailing bytes/);
  });

  it("refuses an attrlist4 too short for the attributes it names", () => {
    const bytes = bytesOf([
      "00000001",
      "00000010", // bit 4 = size, which needs eight bytes
      "00000004", // attrlist4 length = 4
      "00000000",
    ]);
    expect(() => decodeXdr(bytes, (reader) => decodeFattr(reader))).toThrow(/truncated/);
  });

  it("fails with an XdrError at every truncation, never a RangeError", () => {
    const whole = bytesOf(["00000001", "00000010", "00000008", "00000000", "00000400"]);
    for (let length = 0; length < whole.byteLength; length++) {
      let thrown: unknown;
      try {
        decodeXdr(whole.subarray(0, length), (reader) => decodeFattr(reader));
      } catch (error) {
        thrown = error;
      }
      expect(isXdrError(thrown)).toBe(true);
    }
    expect(decodeXdr(whole, (reader) => decodeFattr(reader)).values).toEqual({ size: 1024n });
  });
});

describe("encodeFattr", () => {
  it("omits a requested attribute the server does not support", () => {
    // `archive` (14) is not ours; GETATTR must drop it silently (§18.7.3).
    const attrmask = encodeFattr(new XdrWriter(64), bitmapOf([14, FATTR4_SIZE]), { size: 7n });
    expect(attrmask).toEqual(bitmapOf([FATTR4_SIZE]));
  });

  it("omits a supported attribute it has no value for", () => {
    const attrmask = encodeFattr(new XdrWriter(64), bitmapOf([FATTR4_SIZE, FATTR4_MODE]), {
      size: 7n,
    });
    expect(attrmask).toEqual(bitmapOf([FATTR4_SIZE]));
  });

  it("never returns a write-only attribute", () => {
    const attrmask = encodeFattr(new XdrWriter(64), bitmapOf([FATTR4_TIME_MODIFY_SET]), {
      timeModifySet: { how: SET_TO_SERVER_TIME4 },
    });
    expect(attrmask).toEqual([]);
  });

  it("answers an empty request with an empty bitmap and an empty list", () => {
    const bytes = encodeXdr((writer) => encodeFattr(writer, [], { size: 1n }));
    expect(hex(bytes)).toBe(["00000000", "00000000"].join(" "));
    const decoded = decodeXdr(bytes, (reader) => decodeFattr(reader));
    expect(decoded.attrmask).toEqual([]);
    expect(decoded.values).toEqual({});
  });
});

describe("the driver bridge", () => {
  const stats = (over: Partial<StatsLike> = {}): StatsLike => ({
    dev: 0x1a_2b_3c,
    ino: 0x4d_5e_6f,
    mode: S_IFREG | 0o644,
    nlink: 2,
    uid: 1000,
    gid: 100,
    rdev: 0,
    size: 4096,
    blksize: 4096,
    blocks: 16,
    atimeMs: 1_700_000_001_000,
    mtimeMs: 1_700_000_002_000,
    ctimeMs: 1_700_000_003_000,
    birthtimeMs: 1_700_000_000_000,
    isFile: () => true,
    isDirectory: () => false,
    isSymbolicLink: () => false,
    isBlockDevice: () => false,
    isCharacterDevice: () => false,
    isFIFO: () => false,
    isSocket: () => false,
    ...over,
  });

  it("maps a StatsLike onto the per-object attributes", () => {
    const values = fattr4Of(stats());
    expect(values.type).toBe(NF4REG);
    // Permission bits only: the type lives in `type`, never in both.
    expect(values.mode).toBe(0o644);
    expect(values.size).toBe(4096n);
    expect(values.fsid).toEqual({ major: 0x1a_2b_3cn, minor: 0n });
    expect(values.fileid).toBe(0x4d_5e_6fn);
    expect(values.numlinks).toBe(2);
    expect(values.owner).toBe("1000");
    expect(values.ownerGroup).toBe("100");
    // 16 blocks of 512 bytes.
    expect(values.spaceUsed).toBe(8192n);
    expect(values.timeAccess).toEqual({ seconds: 1_700_000_001n, nseconds: 0 });
    expect(values.timeMetadata).toEqual({ seconds: 1_700_000_003n, nseconds: 0 });
    expect(values.timeModify).toEqual({ seconds: 1_700_000_002n, nseconds: 0 });
    // Never invented: no handle was supplied, so the attribute is absent.
    expect(values.filehandle).toBeUndefined();
  });

  it("takes the fileid and filehandle the session assigns", () => {
    const handle = new Uint8Array([9, 8, 7]);
    const values = fattr4Of(stats(), { fileid: 42n, filehandle: handle });
    expect(values.fileid).toBe(42n);
    expect(values.filehandle).toBe(handle);
  });

  it("falls back to the size when a driver counts no blocks", () => {
    expect(fattr4Of(stats({ blocks: 0, size: 1234 })).spaceUsed).toBe(1234n);
  });

  it("splits rdev the way the NFSv3 transport does", () => {
    expect(fattr4Of(stats({ rdev: (13 << 8) | 9 })).rawdev).toEqual({ major: 13, minor: 9 });
  });

  it("derives change from the later of mtime and ctime, in nanoseconds", () => {
    expect(changeOf(stats())).toBe(1_700_000_003_000_000_000n);
    // A driver that moves mtime and not ctime still gets a moving change.
    expect(changeOf(stats({ mtimeMs: 1_700_000_009_500, ctimeMs: 0 }))).toBe(
      1_700_000_009_500_000_000n,
    );
  });

  it("keeps a pre-epoch change equal to what a client decodes", () => {
    // `changeid4` is a `uint64_t`, so a timestamp before 1970 is wrapped — and
    // it has to be wrapped *here*, or the value this returns and the value that
    // comes back off the wire are two different bigints for the same file.
    const before1970 = stats({ mtimeMs: -2_000_000_000_000, ctimeMs: -2_000_000_000_000 });
    const change = changeOf(before1970);
    expect(change).toBeGreaterThan(0n);
    const bytes = encodeXdr((writer) =>
      encodeFattr(writer, bitmapOf([FATTR4_CHANGE]), fattr4Of(before1970)),
    );
    expect(decodeXdr(bytes, (reader) => decodeFattr(reader)).values.change).toBe(change);
  });

  it("turns a StatsFsLike into the files_* and space_* attributes", () => {
    const values = fattr4FsOf({
      type: 0x01_02_03,
      bsize: 4096,
      blocks: 1000,
      bfree: 800,
      bavail: 700,
      files: 500,
      ffree: 400,
    });
    expect(values.spaceTotal).toBe(4_096_000n);
    expect(values.spaceFree).toBe(3_276_800n);
    expect(values.spaceAvail).toBe(2_867_200n);
    expect(values.filesTotal).toBe(500n);
    expect(values.filesFree).toBe(400n);
    // `StatsFsLike` has no reservation for the privileged, so "available" is
    // "free" — the same answer NFSv3's FSSTAT gives.
    expect(values.filesAvail).toBe(400n);
  });

  it("maps every file type both ways", () => {
    const pairs: [number, number][] = [
      [S_IFREG, NF4REG],
      [S_IFDIR, NF4DIR],
      [S_IFLNK, NF4LNK],
      [S_IFBLK, NF4BLK],
      [S_IFCHR, NF4CHR],
      [S_IFSOCK, NF4SOCK],
      [S_IFIFO, NF4FIFO],
    ];
    for (const [mode, type] of pairs) {
      expect(ftype4Of(mode | 0o644)).toBe(type);
      expect(modeType4Of(type)).toBe(mode);
    }
    // No type bits at all is a regular file; `nfs_ftype4` has no "unknown".
    expect(ftype4Of(0o644)).toBe(NF4REG);
    expect(modeType4Of(0)).toBe(S_IFREG);
  });
});

describe("numeric owner strings (RFC 8881 §5.9)", () => {
  it("formats a uid as decimal with no leading zeros", () => {
    expect(numericOwner(0)).toBe("0");
    expect(numericOwner(1000)).toBe("1000");
    expect(numericOwner(0xff_ff_ff_ff)).toBe("4294967295");
  });

  it("parses only the form the RFC defines", () => {
    expect(parseNumericOwner("0")).toBe(0);
    expect(parseNumericOwner("1000")).toBe(1000);
    expect(parseNumericOwner("4294967295")).toBe(0xff_ff_ff_ff);
    // A name, a name@domain, a leading zero and an out-of-range number are all
    // for the session to map or refuse — not this codec's business.
    expect(parseNumericOwner("root")).toBeUndefined();
    expect(parseNumericOwner("1000@example.org")).toBeUndefined();
    expect(parseNumericOwner("007")).toBeUndefined();
    expect(parseNumericOwner("4294967296")).toBeUndefined();
    expect(parseNumericOwner("")).toBeUndefined();
    expect(parseNumericOwner("-1")).toBeUndefined();
  });

  it("round-trips through the attribute itself", () => {
    const bytes = encodeXdr((writer) =>
      encodeFattr(writer, bitmapOf([FATTR4_OWNER, FATTR4_OWNER_GROUP]), {
        owner: numericOwner(4242),
        ownerGroup: numericOwner(24),
      }),
    );
    const values = decodeXdr(bytes, (reader) => decodeFattr(reader)).values;
    expect(parseNumericOwner(values.owner ?? "")).toBe(4242);
    expect(parseNumericOwner(values.ownerGroup ?? "")).toBe(24);
  });
});

describe("round trips", () => {
  it("survives every supported attribute at once, twice", () => {
    // Distinct values throughout, for the reason the golden fixture gives.
    const values: Fattr4Values = {
      supportedAttrs: SUPPORTED_ATTRS,
      type: NF4LNK,
      fhExpireType: 0,
      change: 7n,
      size: 8n,
      linkSupport: false,
      symlinkSupport: true,
      namedAttr: false,
      fsid: { major: 9n, minor: 10n },
      uniqueHandles: true,
      leaseTime: 11,
      rdattrError: 12,
      filehandle: new Uint8Array([13, 14, 15]),
      fileid: 16n,
      filesAvail: 17n,
      filesFree: 18n,
      filesTotal: 19n,
      maxfilesize: 20n,
      maxlink: 21,
      maxname: 22,
      maxread: 23n,
      maxwrite: 24n,
      mode: 0o251,
      numlinks: 26,
      owner: "27",
      ownerGroup: "28",
      rawdev: { major: 29, minor: 30 },
      spaceAvail: 31n,
      spaceFree: 32n,
      spaceTotal: 33n,
      spaceUsed: 34n,
      timeAccess: { seconds: 35n, nseconds: 36 },
      timeAccessSet: { how: SET_TO_CLIENT_TIME4, time: { seconds: 37n, nseconds: 38 } },
      timeDelta: { seconds: 39n, nseconds: 40 },
      timeMetadata: { seconds: 41n, nseconds: 42 },
      timeModify: { seconds: 43n, nseconds: 44 },
      timeModifySet: { how: SET_TO_CLIENT_TIME4, time: { seconds: 45n, nseconds: 46 } },
    };
    const first = encodeXdr((writer) =>
      encodeFattr(writer, SUPPORTED_ATTRS, values, SUPPORTED_ATTRS),
    );
    const decoded = decodeXdr(first, (reader) => decodeFattr(reader));
    expect(decoded.values).toEqual(values);
    const second = encodeXdr((writer) =>
      encodeFattr(writer, SUPPORTED_ATTRS, decoded.values, SUPPORTED_ATTRS),
    );
    expect(hex(second)).toBe(hex(first));
  });

  it("survives a fattr4 nested where an operation would put it", () => {
    // The container has to be self-delimiting: `attr_vals` is an `opaque<>`, so
    // whatever follows a fattr4 in a COMPOUND still decodes.
    const bytes = encodeXdr((writer) => {
      encodeFattr(writer, bitmapOf([FATTR4_TYPE, FATTR4_SIZE]), { type: NF4REG, size: 99n });
      writer.u32(0xab_cd_ef_01);
    });
    const reader = new XdrReader(bytes);
    expect(decodeFattr(reader).values).toEqual({ type: NF4REG, size: 99n });
    expect(reader.u32()).toBe(0xab_cd_ef_01);
    reader.end();
  });
});
