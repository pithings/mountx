/**
 * XDR primitives, RPC framing, and TCP record marking.
 *
 * Tier 0: pure data transformation, no socket, no driver. The invariant under
 * test throughout is the one the fuzz suite then attacks — a decoder either
 * returns a value or throws `XdrError`, and nothing else.
 */

import { describe, expect, it } from "vitest";
import {
  AUTH_NONE,
  AUTH_SYS,
  MSG_ACCEPTED,
  MSG_DENIED,
  NFS_PROGRAM,
  NFS_V3,
  RM_LAST_FRAGMENT,
  RPC_AUTH_ERROR,
  RPC_GARBAGE_ARGS,
  RPC_SUCCESS,
  RPC_VERSION,
} from "../../src/nfs/v3/constants.ts";
import {
  authSys,
  credentialsOf,
  decodeAuthSys,
  decodeCall,
  decodeReply,
  encodeAcceptError,
  encodeAcceptedReply,
  encodeAuthError,
  encodeAuthSys,
  encodeCall,
  encodeRpcMismatch,
  frameFragments,
  frameRecord,
  RecordAssembler,
} from "../../src/nfs/rpc.ts";
import {
  decodeXdr,
  encodeXdr,
  isXdrError,
  XdrError,
  XdrReader,
  XdrWriter,
  xdrAlign,
  xdrPad,
  XDR_MAX_ITEM,
} from "../../src/nfs/xdr.ts";

const encoder = new TextEncoder();

describe("alignment", () => {
  it("pads every item out to four bytes", () => {
    expect([0, 1, 2, 3, 4, 5].map(xdrPad)).toEqual([0, 3, 2, 1, 0, 3]);
    expect([0, 1, 2, 3, 4, 5].map(xdrAlign)).toEqual([0, 4, 4, 4, 4, 8]);
  });
});

describe("scalars", () => {
  it("round-trips every width, big-endian", () => {
    const bytes = encodeXdr((writer) => {
      writer.u32(0xde_ad_be_ef);
      writer.i32(-2);
      writer.u64(0xff_ff_ff_ff_ff_ff_ff_ffn);
      writer.i64(-1n);
      writer.bool(true);
      writer.bool(false);
    });
    // Hand-checked: the first word is `de ad be ef` in network order.
    expect([...bytes.subarray(0, 4)]).toEqual([0xde, 0xad, 0xbe, 0xef]);
    const reader = new XdrReader(bytes);
    expect(reader.u32()).toBe(0xde_ad_be_ef);
    expect(reader.i32()).toBe(-2);
    expect(reader.u64()).toBe(0xff_ff_ff_ff_ff_ff_ff_ffn);
    expect(reader.i64()).toBe(-1n);
    expect(reader.bool()).toBe(true);
    expect(reader.bool()).toBe(false);
    reader.end();
  });

  it("refuses a bool that is not 0 or 1", () => {
    const bytes = encodeXdr((writer) => writer.u32(2));
    expect(() => new XdrReader(bytes).bool()).toThrow(XdrError);
  });

  it("refuses to read past the end", () => {
    const reader = new XdrReader(new Uint8Array(4));
    expect(reader.u32()).toBe(0);
    expect(reader.remaining).toBe(0);
    expect(reader.atEnd).toBe(true);
    expect(() => reader.u32()).toThrow(XdrError);
    expect(() => new XdrReader(new Uint8Array(4)).u64()).toThrow(XdrError);
  });

  it("reports the offset it failed at", () => {
    const reader = new XdrReader(new Uint8Array(8));
    reader.u32();
    try {
      reader.u64();
      expect.unreachable();
    } catch (error) {
      expect(isXdrError(error)).toBe(true);
      expect((error as XdrError).offset).toBe(4);
    }
  });
});

describe("counted items", () => {
  it("round-trips opaques of every alignment", () => {
    for (let length = 0; length < 9; length++) {
      const value = new Uint8Array(length).map((_, index) => index + 1);
      const bytes = encodeXdr((writer) => writer.varOpaque(value));
      expect(bytes.byteLength).toBe(4 + xdrAlign(length));
      // The padding is zero, always: a decoder skips it, but a peer comparing
      // messages byte for byte would see whatever we left there.
      expect([...bytes.subarray(4 + length)]).toEqual(
        Array.from({ length: xdrPad(length) }, () => 0),
      );
      expect([...decodeXdr(bytes, (reader) => reader.varOpaque())]).toEqual([...value]);
    }
  });

  it("round-trips fixed opaques, padding and truncating as needed", () => {
    const bytes = encodeXdr((writer) => writer.fixedOpaque(new Uint8Array([1, 2, 3]), 8));
    expect(bytes.byteLength).toBe(8);
    expect([...bytes]).toEqual([1, 2, 3, 0, 0, 0, 0, 0]);
    expect([...decodeXdr(bytes, (reader) => reader.fixedOpaque(8))]).toEqual([
      1, 2, 3, 0, 0, 0, 0, 0,
    ]);
  });

  it("round-trips strings, including non-ASCII", () => {
    for (const value of ["", "a", "héllo→ø", "x".repeat(255)]) {
      const bytes = encodeXdr((writer) => writer.string(value));
      expect(decodeXdr(bytes, (reader) => reader.string())).toBe(value);
    }
  });

  it("decodes invalid UTF-8 lossily rather than throwing", () => {
    // A name that is bytes, not text — which real filesystems allow.
    const bytes = encodeXdr((writer) => writer.varOpaque(new Uint8Array([0xff, 0xfe])));
    expect(decodeXdr(bytes, (reader) => reader.string())).toBe("��");
  });

  it("refuses an item longer than its limit", () => {
    const bytes = encodeXdr((writer) => writer.varOpaque(encoder.encode("abcdefgh")));
    expect(() => decodeXdr(bytes, (reader) => reader.varOpaque(4))).toThrow(XdrError);
  });

  it("copies, even out of a Buffer whose `slice` does not", () => {
    // `Buffer.prototype.slice` **is `subarray`** — it returns a view. A decoder
    // that used it would hand a driver a window onto the socket's receive pool
    // to keep, which is the exact trap that corrupted the first FUSE
    // transcripts (`src/fuse/record.ts`). The reader must copy regardless of
    // what kind of `Uint8Array` it was handed.
    const source = Buffer.from(
      encodeXdr((writer) => {
        writer.varOpaque(new Uint8Array([1, 2, 3, 4, 5]));
        writer.fixedOpaque(new Uint8Array([9, 9, 9, 9]), 4);
        writer.raw(new Uint8Array([7, 7, 7, 7]));
      }),
    );
    // Sanity: this really is the aliasing kind of `slice`.
    expect(source.slice(0, 4).buffer).toBe(source.buffer);

    const reader = new XdrReader(source);
    const counted = reader.varOpaque();
    const fixed = reader.fixedOpaque(4);
    const rest = reader.rest();
    source.fill(0xee);

    expect([...counted]).toEqual([1, 2, 3, 4, 5]);
    expect([...fixed]).toEqual([9, 9, 9, 9]);
    expect([...rest]).toEqual([7, 7, 7, 7]);
    for (const decoded of [counted, fixed, rest]) {
      expect(decoded.buffer).not.toBe(source.buffer);
    }
  });

  it("copies a string's bytes too", () => {
    const source = Buffer.from(encodeXdr((writer) => writer.string("keep me")));
    const decoded = new XdrReader(source).string();
    source.fill(0);
    expect(decoded).toBe("keep me");
  });

  it("refuses a length that cannot fit in what is left", () => {
    // A four-byte length claiming 4 GiB, with nothing behind it.
    const bytes = encodeXdr((writer) => writer.u32(0xff_ff_ff_ff));
    expect(() => decodeXdr(bytes, (reader) => reader.varOpaque(XDR_MAX_ITEM))).toThrow(XdrError);
  });
});

describe("optionals, arrays and lists", () => {
  it("round-trips an optional in both states", () => {
    const present = encodeXdr((writer) => writer.optional(7, (w, value) => w.u32(value)));
    const absent = encodeXdr((writer) =>
      writer.optional(undefined, (w, value: number) => w.u32(value)),
    );
    expect(present.byteLength).toBe(8);
    expect(absent.byteLength).toBe(4);
    expect(decodeXdr(present, (reader) => reader.optional((r) => r.u32()))).toBe(7);
    expect(decodeXdr(absent, (reader) => reader.optional((r) => r.u32()))).toBeUndefined();
  });

  it("round-trips a counted array", () => {
    const bytes = encodeXdr((writer) => writer.array([1, 2, 3], (w, value) => w.u32(value)));
    expect(decodeXdr(bytes, (reader) => reader.array((r) => r.u32()))).toEqual([1, 2, 3]);
  });

  it("round-trips a linked list, which is how RFC 1813 spells every list", () => {
    const bytes = encodeXdr((writer) => writer.list(["a", "bb"], (w, value) => w.string(value)));
    expect(decodeXdr(bytes, (reader) => reader.list((r) => r.string()))).toEqual(["a", "bb"]);
    // Empty is one `false`.
    expect(encodeXdr((writer) => writer.list([], (w, v: string) => w.string(v))).byteLength).toBe(
      4,
    );
  });

  it("refuses an array count larger than the bytes could hold", () => {
    const bytes = encodeXdr((writer) => {
      writer.u32(1_000_000);
      writer.u32(1);
    });
    expect(() => decodeXdr(bytes, (reader) => reader.array((r) => r.u32()))).toThrow(XdrError);
  });

  it("refuses a list longer than its bound", () => {
    const bytes = encodeXdr((writer) => writer.list([1, 2, 3, 4], (w, value) => w.u32(value)));
    expect(() => decodeXdr(bytes, (reader) => reader.list((r) => r.u32(), 2))).toThrow(XdrError);
  });
});

describe("the writer", () => {
  it("grows past its initial capacity", () => {
    const writer = new XdrWriter(16);
    for (let index = 0; index < 1000; index++) {
      writer.u32(index);
    }
    expect(writer.length).toBe(4000);
    const reader = new XdrReader(writer.bytes());
    for (let index = 0; index < 1000; index++) {
      expect(reader.u32()).toBe(index);
    }
    reader.end();
  });

  it("insists a message is fully consumed", () => {
    const bytes = encodeXdr((writer) => {
      writer.u32(1);
      writer.u32(2);
    });
    expect(() => decodeXdr(bytes, (reader) => reader.u32())).toThrow(XdrError);
  });
});

describe("auth", () => {
  it("round-trips AUTH_SYS parameters", () => {
    const params = { stamp: 42, machineName: "mountx", uid: 1000, gid: 100, gids: [1, 2, 3] };
    expect(decodeAuthSys(encodeAuthSys(params))).toEqual(params);
  });

  it("caps the supplementary group list at sixteen", () => {
    const gids = Array.from({ length: 32 }, (_, index) => index);
    expect(
      decodeAuthSys(encodeAuthSys({ stamp: 0, machineName: "h", uid: 0, gid: 0, gids })).gids,
    ).toHaveLength(16);
  });

  it("reads credentials out of AUTH_SYS and reports AUTH_NONE as anonymous", () => {
    expect(credentialsOf(authSys(1234, 56))).toMatchObject({
      flavor: AUTH_SYS,
      uid: 1234,
      gid: 56,
    });
    expect(credentialsOf({ flavor: AUTH_NONE, body: new Uint8Array(0) })).toMatchObject({
      uid: undefined,
      gid: undefined,
    });
  });
});

describe("RPC messages", () => {
  it("round-trips a call and leaves the reader on its arguments", () => {
    const message = encodeCall({
      xid: 0x11_22_33_44,
      program: NFS_PROGRAM,
      version: NFS_V3,
      procedure: 3,
      cred: authSys(1000, 1000),
      args: encodeXdr((writer) => writer.u32(0xab_cd_ef_01)),
    });
    const { call, args } = decodeCall(message);
    expect(call).toMatchObject({
      xid: 0x11_22_33_44,
      rpcVersion: RPC_VERSION,
      program: NFS_PROGRAM,
      version: NFS_V3,
      procedure: 3,
    });
    expect(call.cred.flavor).toBe(AUTH_SYS);
    expect(args.u32()).toBe(0xab_cd_ef_01);
    args.end();
  });

  it("refuses to decode a reply as a call, and a call as a reply", () => {
    const call = encodeCall({ xid: 1, program: NFS_PROGRAM, version: NFS_V3, procedure: 0 });
    const reply = encodeAcceptedReply(1);
    expect(() => decodeReply(call)).toThrow(XdrError);
    expect(() => decodeCall(reply)).toThrow(XdrError);
  });

  it("round-trips every reply shape", () => {
    const success = decodeReply(
      encodeAcceptedReply(
        7,
        encodeXdr((w) => w.u32(9)),
      ),
    );
    expect(success.reply).toMatchObject({
      xid: 7,
      replyStat: MSG_ACCEPTED,
      acceptStat: RPC_SUCCESS,
    });
    expect(success.results.u32()).toBe(9);

    const garbage = decodeReply(encodeAcceptError(8, RPC_GARBAGE_ARGS));
    expect(garbage.reply).toMatchObject({ replyStat: MSG_ACCEPTED, acceptStat: RPC_GARBAGE_ARGS });

    const mismatch = decodeReply(encodeAcceptError(9, 2, { low: 3, high: 3 }));
    expect(mismatch.reply).toMatchObject({ acceptStat: 2, low: 3, high: 3 });

    const denied = decodeReply(encodeAuthError(10, 5));
    expect(denied.reply).toMatchObject({
      replyStat: MSG_DENIED,
      rejectStat: RPC_AUTH_ERROR,
      authStat: 5,
    });

    const version = decodeReply(encodeRpcMismatch(11));
    expect(version.reply).toMatchObject({ replyStat: MSG_DENIED, rejectStat: 0, low: 2, high: 2 });
  });
});

describe("record marking", () => {
  it("frames one message as a single last fragment", () => {
    const framed = frameRecord(encoder.encode("hello!!!"));
    expect(framed.byteLength).toBe(12);
    const header = new DataView(framed.buffer).getUint32(0, false);
    expect((header & RM_LAST_FRAGMENT) >>> 0).toBe(RM_LAST_FRAGMENT);
    expect(header & ~RM_LAST_FRAGMENT).toBe(8);
  });

  it("reassembles a record delivered whole", () => {
    const assembler = new RecordAssembler();
    const records = assembler.push(frameRecord(encoder.encode("one")));
    expect(records).toHaveLength(1);
    expect(new TextDecoder().decode(records[0])).toBe("one");
    expect(assembler.pending).toBe(0);
  });

  it("reassembles a record split across many fragments", () => {
    const message = encoder.encode("abcdefghijklmnopqrstuvwxyz");
    const assembler = new RecordAssembler();
    const records = assembler.push(frameFragments(message, 4));
    expect(records).toHaveLength(1);
    expect(new TextDecoder().decode(records[0])).toEqual("abcdefghijklmnopqrstuvwxyz");
  });

  it("reassembles a record delivered one byte at a time", () => {
    const framed = frameFragments(encoder.encode("split me up"), 3);
    const assembler = new RecordAssembler();
    const out: Uint8Array[] = [];
    for (const byte of framed) {
      out.push(...assembler.push(new Uint8Array([byte])));
    }
    expect(out).toHaveLength(1);
    expect(new TextDecoder().decode(out[0])).toBe("split me up");
  });

  it("splits several records arriving in one chunk", () => {
    const chunk = new Uint8Array(
      [frameRecord(encoder.encode("aa")), frameRecord(encoder.encode("bbbb"))].flatMap((part) => [
        ...part,
      ]),
    );
    const records = new RecordAssembler().push(chunk);
    expect(records.map((record) => new TextDecoder().decode(record))).toEqual(["aa", "bbbb"]);
  });

  it("handles an empty record and an empty non-final fragment", () => {
    expect(new RecordAssembler().push(frameRecord(new Uint8Array(0)))[0]).toHaveLength(0);
    // A zero-length fragment followed by a real one is legal and pointless,
    // which is exactly the sort of thing a fuzzer or a lazy client produces.
    const empty = new Uint8Array(4);
    new DataView(empty.buffer).setUint32(0, 0, false);
    const assembler = new RecordAssembler();
    expect(assembler.push(empty)).toHaveLength(0);
    const records = assembler.push(frameRecord(encoder.encode("tail")));
    expect(new TextDecoder().decode(records[0])).toBe("tail");
  });

  it("refuses a record over the limit, whether in one fragment or many", () => {
    const one = new RecordAssembler(16);
    expect(() => one.push(frameRecord(new Uint8Array(32)))).toThrow(XdrError);
    const many = new RecordAssembler(16);
    expect(() => many.push(frameFragments(new Uint8Array(64), 8))).toThrow(XdrError);
  });

  it("keeps a partial record pending rather than guessing", () => {
    const assembler = new RecordAssembler();
    const framed = frameRecord(encoder.encode("incomplete"));
    expect(assembler.push(framed.subarray(0, 7))).toEqual([]);
    expect(assembler.pending).toBeGreaterThan(0);
    expect(assembler.push(framed.subarray(7))).toHaveLength(1);
  });
});
