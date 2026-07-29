import { describe, expect, it } from "vitest";
import { ERRNO_CODES, fsError } from "../../src/errors.ts";
import {
  FUSE_CREATE,
  FUSE_GETXATTR,
  FUSE_IN_HEADER_SIZE,
  FUSE_LOOKUP,
  FUSE_NOTIFY_INVAL_INODE,
  FUSE_OPEN,
  FUSE_OUT_HEADER_SIZE,
  FUSE_READ,
  FUSE_SETXATTR,
  FUSE_STATFS,
  FUSE_WRITE,
  OPCODE_NAMES,
  opcodeName,
} from "../../src/fuse/constants.ts";
import { decodeNotify, encodeNotify } from "../../src/fuse/notify.ts";
import {
  allocReply,
  attrOutSize,
  attrSize,
  DEFAULT_PROTOCOL,
  decodeAttrOut,
  decodeEntryOut,
  decodeGetxattrOut,
  decodeInHeader,
  decodeInitIn,
  decodeInitOut,
  decodeOutHeader,
  decodeReply,
  decodeReplyBody,
  decodeRequest,
  decodeRequestBody,
  decodeStatfsOut,
  decodeXattrNames,
  encodeAttrOut,
  encodeEntryOut,
  encodeErrorReply,
  encodeErrorReplyFor,
  encodeGetxattrOut,
  encodeInHeader,
  encodeInitIn,
  encodeInitOut,
  encodeOutHeader,
  encodeReply,
  encodeReplyBody,
  encodeReplyFor,
  encodeRequest,
  encodeRequestBody,
  encodeStatfsOut,
  encodeXattrNames,
  entryOutSize,
  finishReply,
  fuseErrno,
  initOutSize,
  isProtocolError,
  kstatfsSize,
  nameByteLength,
  OPCODES,
  ProtocolError,
  readWriteInSize,
  SUPPORTED_OPCODES,
  UNIMPLEMENTED_OPCODES,
  writeOutHeaderInto,
} from "../../src/fuse/protocol.ts";
import type { FuseRawData, FuseWriteIn, ProtocolContext } from "../../src/fuse/protocol.ts";
import {
  randomAttr,
  randomAttrOut,
  randomEntryOut,
  randomInHeader,
  randomKstatfs,
  REPLY_GENERATORS,
  REQUEST_GENERATORS,
  Rng,
} from "./random.ts";

/**
 * The round-trip matrix. The old minors are not decoration: every struct that
 * changed shape has a version below where a decoder can read a field the
 * encoder never wrote (`fuse_attr.flags` is `padding` before 7.32, the
 * `fuse_read_in` tail before 7.9, `umask` before 7.12, `frsize` before 7.4,
 * the `fuse_init_out` tail before 7.23). Round-tripping at those versions is
 * what catches that class of bug.
 */
const CONTEXTS: Array<[string, ProtocolContext]> = [
  ["7.41", DEFAULT_PROTOCOL],
  ["7.41 + SETXATTR_EXT", { minor: 41, setxattrExt: true }],
  ["7.22 (no init_out tail, fuse_attr.flags is padding)", { minor: 22, setxattrExt: false }],
  ["7.8 (compat fuse_attr, fuse_read_in and fuse_write_in)", { minor: 8, setxattrExt: false }],
  ["7.3 (compat fuse_kstatfs, 8-byte init_out)", { minor: 3, setxattrExt: false }],
];

const ROUNDTRIPS = 120;

describe("opcode table", () => {
  it("covers every opcode a v1 server needs", () => {
    // The list Milestone 2 is specified against. A missing codec here is a
    // request the session layer could not even parse.
    const required = [
      "INIT",
      "DESTROY",
      "LOOKUP",
      "FORGET",
      "BATCH_FORGET",
      "GETATTR",
      "SETATTR",
      "READLINK",
      "SYMLINK",
      "MKNOD",
      "MKDIR",
      "UNLINK",
      "RMDIR",
      "RENAME",
      "RENAME2",
      "LINK",
      "OPEN",
      "READ",
      "WRITE",
      "RELEASE",
      "FSYNC",
      "FLUSH",
      "OPENDIR",
      "READDIR",
      "READDIRPLUS",
      "RELEASEDIR",
      "FSYNCDIR",
      "STATFS",
      "ACCESS",
      "CREATE",
      "INTERRUPT",
      "GETXATTR",
      "SETXATTR",
      "LISTXATTR",
      "REMOVEXATTR",
      "FALLOCATE",
      "LSEEK",
      "GETLK",
      "SETLK",
      "SETLKW",
      "POLL",
    ];
    const covered = new Set(SUPPORTED_OPCODES.map((opcode) => opcodeName(opcode)));
    expect([...required].filter((name) => !covered.has(name))).toEqual([]);
  });

  it("names every spec and marks the reply-less ones", () => {
    for (const opcode of SUPPORTED_OPCODES) {
      const spec = OPCODES.get(opcode);
      expect(spec?.name).toBe(OPCODE_NAMES[opcode]);
    }
    expect(OPCODES.get(2)?.hasReply).toBe(false); // FORGET
    expect(OPCODES.get(42)?.hasReply).toBe(false); // BATCH_FORGET
    expect(OPCODES.get(FUSE_LOOKUP)?.hasReply).toBe(true);
  });

  it("has a generator for every supported opcode, in both directions", () => {
    const missing = SUPPORTED_OPCODES.filter(
      (opcode) => !REQUEST_GENERATORS.has(opcode) || !REPLY_GENERATORS.has(opcode),
    );
    expect(missing.map((opcode) => opcodeName(opcode))).toEqual([]);
  });

  it("rejects opcodes it has no codec for", () => {
    for (const opcode of UNIMPLEMENTED_OPCODES) {
      expect(OPCODES.has(opcode)).toBe(false);
      expect(() => decodeRequestBody(opcode, new Uint8Array(0))).toThrow(ProtocolError);
      expect(() => encodeRequestBody(opcode, {})).toThrow(ProtocolError);
      expect(() => decodeReplyBody(opcode, new Uint8Array(0))).toThrow(ProtocolError);
      expect(() => encodeReplyBody(opcode, {})).toThrow(ProtocolError);
    }
  });
});

describe("round-trips", () => {
  for (const [label, ctx] of CONTEXTS) {
    it(`decode(encode(request)) === request at ${label}`, () => {
      const rng = new Rng(0x5e_ed_01);
      for (const opcode of SUPPORTED_OPCODES) {
        const generate = REQUEST_GENERATORS.get(opcode);
        expect(generate, opcodeName(opcode)).toBeTypeOf("function");
        for (let round = 0; round < ROUNDTRIPS; round++) {
          const value = generate?.(rng, ctx);
          const bytes = encodeRequestBody(opcode, value, ctx);
          expect(decodeRequestBody(opcode, bytes, ctx), opcodeName(opcode)).toEqual(value);
        }
      }
    });

    it(`decode(encode(reply)) === reply at ${label}`, () => {
      const rng = new Rng(0x5e_ed_02);
      for (const opcode of SUPPORTED_OPCODES) {
        const generate = REPLY_GENERATORS.get(opcode);
        expect(generate, opcodeName(opcode)).toBeTypeOf("function");
        for (let round = 0; round < ROUNDTRIPS; round++) {
          const value = generate?.(rng, ctx);
          const bytes = encodeReplyBody(opcode, value, ctx);
          expect(decodeReplyBody(opcode, bytes, ctx), opcodeName(opcode)).toEqual(value);
        }
      }
    });
  }

  it("round-trips fuse_in_header", () => {
    const rng = new Rng(0x5e_ed_03);
    for (let round = 0; round < 500; round++) {
      const header = randomInHeader(rng);
      expect(decodeInHeader(encodeInHeader(header))).toEqual(header);
    }
  });

  it("round-trips fuse_out_header, including negative errors", () => {
    const rng = new Rng(0x5e_ed_04);
    for (let round = 0; round < 500; round++) {
      const header = {
        len: rng.range(16, 4096),
        error: rng.bool() ? 0 : -rng.range(1, 133),
        unique: rng.u64(),
      };
      expect(decodeOutHeader(encodeOutHeader(header))).toEqual(header);
    }
  });

  it("round-trips whole request messages through the header", () => {
    const rng = new Rng(0x5e_ed_05);
    for (let round = 0; round < 200; round++) {
      const body = { name: rng.name() };
      const message = encodeRequest({
        opcode: FUSE_LOOKUP,
        unique: rng.u64(),
        nodeid: rng.u64(),
        uid: rng.u32(),
        gid: rng.u32(),
        pid: rng.u32(),
        body,
      });
      const decoded = decodeRequest(message);
      expect(decoded.header.len).toBe(message.length);
      expect(decoded.header.opcode).toBe(FUSE_LOOKUP);
      expect(decoded.name).toBe("LOOKUP");
      expect(decoded.body).toEqual(body);
      expect(decoded.extensions).toEqual(new Uint8Array(0));
    }
  });

  it("round-trips whole reply messages", () => {
    const rng = new Rng(0x5e_ed_06);
    for (let round = 0; round < 200; round++) {
      const unique = rng.u64();
      const entry = randomEntryOut(rng);
      const message = encodeReplyFor(unique, FUSE_LOOKUP, entry);
      const decoded = decodeReply(message, FUSE_LOOKUP);
      expect(decoded.header).toEqual({ len: message.length, error: 0, unique });
      expect(decoded.body).toEqual(entry);
    }
  });
});

describe("retained bytes", () => {
  it("copies Buffer-backed request bytes before the transport reuses them", () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    const extensions = new Uint8Array([5, 6, 7, 8, 9, 10, 11, 12]);
    const encoded = encodeRequest({
      opcode: FUSE_WRITE,
      unique: 1n,
      nodeid: 2n,
      body: {
        fh: 3n,
        offset: 4n,
        size: data.length,
        writeFlags: 0,
        lockOwner: 5n,
        flags: 0,
        data,
      } satisfies FuseWriteIn,
      extensions,
    });
    const message = Buffer.allocUnsafe(encoded.length);
    message.set(encoded);
    const decoded = decodeRequest(message);

    // Nothing reads `.payload` first: the fields a session keeps must survive
    // the transport re-arming its receive buffer on their own. For a `WRITE`
    // the body *is* the data, so `body.data` is the load-bearing copy.
    message.fill(0xaa);

    expect([...decoded.extensions]).toEqual([...extensions]);
    expect([...(decoded.body as FuseWriteIn).data]).toEqual([...data]);
  });

  it("copies the payload lazily, memoized on the first read", () => {
    const payloadBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const encoded = encodeRequest({ opcode: 39 /* IOCTL */, unique: 1n, payload: payloadBytes });
    const message = Buffer.allocUnsafe(encoded.length);
    message.set(encoded);
    const decoded = decodeRequest(message);

    // Read inside the decode tick, the way `FuseRequest.payload` documents.
    const first = decoded.payload;
    expect([...first]).toEqual([...payloadBytes]);

    message.fill(0xaa);

    // The first read really copied, and the second returns that same array
    // rather than re-reading the reused buffer.
    expect([...decoded.payload]).toEqual([...payloadBytes]);
    expect(decoded.payload).toBe(first);
  });

  it("pins the documented narrowing: a payload read after reuse sees the reuse", () => {
    // Not a bug being enshrined — it is the trade `FuseRequest.payload` states
    // in its own doc comment, and the reason no reader in `src/` may touch it
    // past the first `await`. If this ever needs to become an eager copy again,
    // this case is the one that says so out loud.
    const payloadBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const encoded = encodeRequest({ opcode: 39 /* IOCTL */, unique: 1n, payload: payloadBytes });
    const message = Buffer.allocUnsafe(encoded.length);
    message.set(encoded);
    const decoded = decodeRequest(message);

    message.fill(0xaa);

    expect([...decoded.payload]).toEqual([0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]);
  });

  it("copies Buffer-backed reply bytes before the caller reuses them", () => {
    const data = new Uint8Array([13, 14, 15, 16]);
    const message = Buffer.from(encodeReplyFor(6n, FUSE_READ, { data } satisfies FuseRawData));
    const decoded = decodeReply(message, FUSE_READ);

    message.fill(0xbb);

    expect([...decoded.payload]).toEqual([...data]);
    expect([...(decoded.body as FuseRawData).data]).toEqual([...data]);
  });

  it("copies a directly decoded Buffer-backed raw body", () => {
    const message = Buffer.from([17, 18, 19, 20]);
    const decoded = decodeReplyBody(FUSE_READ, message) as FuseRawData;

    message.fill(0xcc);

    expect([...decoded.data]).toEqual([17, 18, 19, 20]);
  });

  it("copies a Buffer-backed notification body", () => {
    const body = new Uint8Array([21, 22, 23, 24]);
    const message = Buffer.from(encodeNotify(FUSE_NOTIFY_INVAL_INODE, body));
    const decoded = decodeNotify(message);

    message.fill(0xdd);

    expect([...decoded.body]).toEqual([...body]);
  });
});

describe("framed replies", () => {
  it("allocates header and body as one buffer", () => {
    const reply = allocReply(64);
    expect(reply.message.length).toBe(FUSE_OUT_HEADER_SIZE + 64);
    expect(reply.body.length).toBe(64);
    expect(reply.body.buffer).toBe(reply.message.buffer);
    expect(reply.body.byteOffset).toBe(reply.message.byteOffset + FUSE_OUT_HEADER_SIZE);
    // Filling the body is filling the message: one allocation, two views.
    reply.body.fill(0x5a);
    expect(reply.message[FUSE_OUT_HEADER_SIZE]).toBe(0x5a);
  });

  it("is byte-identical to encodeReply for a full body", () => {
    const rng = new Rng(0x5e_ed_0a);
    for (let round = 0; round < 200; round++) {
      const unique = rng.u64();
      const body = rng.bytes(rng.int(300));
      const reply = allocReply(body.length);
      reply.body.set(body);
      expect(finishReply(reply, unique)).toEqual(encodeReply(unique, body));
    }
  });

  it("is byte-identical to encodeReply for an empty body", () => {
    expect(finishReply(allocReply(0), 7n)).toEqual(encodeReply(7n));
    expect(finishReply(allocReply(0), 7n)).toEqual(encodeReply(7n, new Uint8Array(0)));
  });

  it("trims a short fill — the READ case", () => {
    // A driver asked for 4096 bytes and returned 5: `len` and the returned
    // bytes must describe what was filled, never what was allocated.
    const reply = allocReply(4096);
    reply.body.set(new Uint8Array([1, 2, 3, 4, 5]));
    const message = finishReply(reply, 9n, 5);

    expect(message.length).toBe(FUSE_OUT_HEADER_SIZE + 5);
    expect(decodeOutHeader(message)).toEqual({
      len: FUSE_OUT_HEADER_SIZE + 5,
      error: 0,
      unique: 9n,
    });
    expect(decodeReply(message, FUSE_READ).payload).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    expect(message).toEqual(encodeReply(9n, new Uint8Array([1, 2, 3, 4, 5])));
  });

  it("trims a zero-length fill", () => {
    const message = finishReply(allocReply(4096), 11n, 0);
    expect(message.length).toBe(FUSE_OUT_HEADER_SIZE);
    expect(message).toEqual(encodeReply(11n));
  });

  it("rejects an impossible body size", () => {
    expect(() => allocReply(-1)).toThrow(ProtocolError);
    expect(() => allocReply(1.5)).toThrow(ProtocolError);
    expect(() => allocReply(Number.NaN)).toThrow(ProtocolError);
  });

  it("rejects a bytesUsed the body cannot back", () => {
    const reply = allocReply(8);
    expect(() => finishReply(reply, 1n, 9)).toThrow(ProtocolError);
    expect(() => finishReply(reply, 1n, -1)).toThrow(ProtocolError);
    expect(() => finishReply(reply, 1n, 1.5)).toThrow(ProtocolError);
    expect(finishReply(reply, 1n, 8).length).toBe(FUSE_OUT_HEADER_SIZE + 8);
  });

  it("writes a fuse_out_header in place without touching the body", () => {
    const message = new Uint8Array(FUSE_OUT_HEADER_SIZE + 4).fill(0x77);
    writeOutHeaderInto(message, { len: message.length, error: -2, unique: 5n });
    expect(message.subarray(0, FUSE_OUT_HEADER_SIZE)).toEqual(
      encodeOutHeader({ len: message.length, error: -2, unique: 5n }),
    );
    expect([...message.subarray(FUSE_OUT_HEADER_SIZE)]).toEqual([0x77, 0x77, 0x77, 0x77]);
  });

  it("writes into a subarray at its own offset, not the underlying buffer's", () => {
    const backing = new Uint8Array(FUSE_OUT_HEADER_SIZE + 8).fill(0x33);
    const target = backing.subarray(8);
    writeOutHeaderInto(target, { len: FUSE_OUT_HEADER_SIZE, error: 0, unique: 1n });
    expect([...backing.subarray(0, 8)]).toEqual([0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33]);
    expect(decodeOutHeader(target)).toEqual({ len: FUSE_OUT_HEADER_SIZE, error: 0, unique: 1n });
  });

  it("rejects a target too small for the header", () => {
    expect(() =>
      writeOutHeaderInto(new Uint8Array(FUSE_OUT_HEADER_SIZE - 1), {
        len: FUSE_OUT_HEADER_SIZE,
        error: 0,
        unique: 1n,
      }),
    ).toThrow(ProtocolError);
  });
});

describe("message framing", () => {
  it("strips the 7.38+ extension block from the payload", () => {
    const extensions = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    const message = encodeRequest({
      opcode: FUSE_LOOKUP,
      unique: 7n,
      nodeid: 1n,
      body: { name: "x" },
      extensions,
    });
    expect(message.length).toBe(FUSE_IN_HEADER_SIZE + 2 + 16);
    const decoded = decodeRequest(message);
    expect(decoded.header.totalExtlen).toBe(2);
    expect(decoded.payload).toEqual(new Uint8Array([0x78, 0]));
    expect(decoded.extensions).toEqual(extensions);
    expect(decoded.body).toEqual({ name: "x" });
  });

  it("rejects unaligned extension blocks", () => {
    expect(() =>
      encodeRequest({ opcode: FUSE_LOOKUP, unique: 1n, extensions: new Uint8Array(3) }),
    ).toThrow(ProtocolError);
  });

  it("rejects an extension block larger than the message", () => {
    const message = encodeRequest({ opcode: FUSE_LOOKUP, unique: 1n, body: { name: "a" } });
    // Claim eight 8-byte extensions in a message with a 2-byte body.
    message[36] = 8;
    expect(() => decodeRequest(message)).toThrow(ProtocolError);
  });

  it("rejects a header claiming more bytes than were read", () => {
    const message = encodeRequest({ opcode: FUSE_LOOKUP, unique: 1n, body: { name: "a" } });
    const view = new DataView(message.buffer);
    view.setUint32(0, message.length + 8, true);
    expect(() => decodeRequest(message)).toThrow(ProtocolError);
    view.setUint32(0, 8, true);
    expect(() => decodeRequest(message)).toThrow(ProtocolError);
  });

  it("rejects a reply header claiming more bytes than were read", () => {
    const message = encodeReply(1n, new Uint8Array(4));
    const view = new DataView(message.buffer);
    view.setUint32(0, 999, true);
    expect(() => decodeReply(message, FUSE_READ)).toThrow(ProtocolError);
    view.setUint32(0, 4, true);
    expect(() => decodeReply(message, FUSE_READ)).toThrow(ProtocolError);
  });

  it("leaves the body undecoded for an unknown opcode", () => {
    const payload = new Uint8Array([9, 9, 9, 9]);
    const message = encodeRequest({ opcode: 39 /* IOCTL */, unique: 3n, payload });
    const decoded = decodeRequest(message);
    expect(decoded.name).toBe("IOCTL");
    expect(decoded.body).toBeUndefined();
    expect(decoded.payload).toEqual(payload);
    expect(opcodeName(9999)).toBe("UNKNOWN(9999)");
  });

  it("leaves the reply body undecoded on an error reply", () => {
    const message = encodeErrorReply(5n, "ENOENT");
    const decoded = decodeReply(message, FUSE_LOOKUP);
    expect(decoded.header.error).toBe(-2);
    expect(decoded.body).toBeUndefined();
    expect(decoded.payload).toEqual(new Uint8Array(0));
  });

  it("ignores trailing bytes past fuse_in_header.len", () => {
    const message = encodeRequest({ opcode: FUSE_LOOKUP, unique: 1n, body: { name: "ab" } });
    const padded = new Uint8Array(message.length + 32);
    padded.set(message);
    expect(decodeRequest(padded).body).toEqual({ name: "ab" });
  });
});

describe("errno on the wire", () => {
  it("negates positive errnos and leaves negative ones alone", () => {
    expect(fuseErrno("ENOENT")).toBe(-ERRNO_CODES.ENOENT);
    expect(fuseErrno("ENOSYS")).toBe(-38);
    expect(fuseErrno(2)).toBe(-2);
    expect(fuseErrno(-2)).toBe(-2);
    expect(fuseErrno(0)).toBe(0);
  });

  it("maps thrown node:fs errors through errnoOf", () => {
    const reply = encodeErrorReplyFor(9n, fsError("ENOTEMPTY", { syscall: "rmdir" }));
    expect(decodeOutHeader(reply)).toEqual({
      len: FUSE_OUT_HEADER_SIZE,
      error: -ERRNO_CODES.ENOTEMPTY,
      unique: 9n,
    });
  });

  it("falls back to -EIO for anything unrecognizable", () => {
    const reply = encodeErrorReplyFor(1n, new TypeError("boom"));
    expect(decodeOutHeader(reply).error).toBe(-ERRNO_CODES.EIO);
  });

  it("rejects an unknown errno name", () => {
    expect(() => fuseErrno("ENOSUCHTHING" as "ENOENT")).toThrow(ProtocolError);
  });

  it("writes a header-only error reply", () => {
    expect(encodeErrorReply(3n, "EACCES").length).toBe(FUSE_OUT_HEADER_SIZE);
    expect(encodeReply(3n).length).toBe(FUSE_OUT_HEADER_SIZE);
  });
});

describe("version-dependent layouts", () => {
  it("sizes fuse_attr, fuse_entry_out and fuse_attr_out per minor version", () => {
    expect(attrSize(41)).toBe(88);
    expect(attrSize(8)).toBe(80);
    expect(entryOutSize(41)).toBe(128);
    expect(entryOutSize(8)).toBe(120); // FUSE_COMPAT_ENTRY_OUT_SIZE
    expect(attrOutSize(41)).toBe(104);
    expect(attrOutSize(8)).toBe(96); // FUSE_COMPAT_ATTR_OUT_SIZE
    expect(kstatfsSize(41)).toBe(80);
    expect(kstatfsSize(3)).toBe(48); // FUSE_COMPAT_STATFS_SIZE
    expect(readWriteInSize(41)).toBe(40);
    expect(readWriteInSize(8)).toBe(24); // FUSE_COMPAT_WRITE_IN_SIZE
    expect(initOutSize(41)).toBe(64);
    expect(initOutSize(22)).toBe(24); // FUSE_COMPAT_22_INIT_OUT_SIZE
    expect(initOutSize(4)).toBe(8); // FUSE_COMPAT_INIT_OUT_SIZE
  });

  it("drops blksize/flags from fuse_attr before 7.9", () => {
    const rng = new Rng(1);
    const attr = randomAttr(rng);
    const old: ProtocolContext = { minor: 8, setxattrExt: false };
    const entry = { ...randomEntryOut(rng), attr };
    const bytes = encodeEntryOut(entry, old);
    expect(bytes.length).toBe(120);
    expect(decodeEntryOut(bytes, old)).toEqual({
      ...entry,
      attr: { ...attr, blksize: 0, flags: 0 },
    });
  });

  it("zeroes fuse_attr.flags before 7.32 but keeps blksize", () => {
    const rng = new Rng(2);
    const value = { ...randomAttrOut(rng), attr: { ...randomAttr(rng), blksize: 512, flags: 3 } };
    const ctx: ProtocolContext = { minor: 31, setxattrExt: false };
    const decoded = decodeAttrOut(encodeAttrOut(value, ctx), ctx);
    expect(decoded.attr.blksize).toBe(512);
    expect(decoded.attr.flags).toBe(0);
  });

  it("does not surface fuse_attr's reserved word as flags before 7.32", () => {
    // The word at attr+84 is `padding` until 7.32 and `flags` after. A
    // round-trip cannot catch a decoder that reads it too early, because our
    // own encoder writes zero there — so put a *non-zero* value on the wire
    // (as only a peer ever would) and decode it as an older protocol.
    const rng = new Rng(2);
    const attr = { ...randomAttr(rng), blksize: 512, flags: 0xde_ad_be_ef };
    const wire = encodeAttrOut({ attrValid: 1n, attrValidNsec: 0, attr }, DEFAULT_PROTOCOL);
    expect(wire.length).toBe(104);
    // Sanity: the reserved word really is non-zero on the wire.
    expect(new DataView(wire.buffer).getUint32(100, true)).toBe(0xde_ad_be_ef);

    for (const minor of [9, 22, 31]) {
      const decoded = decodeAttrOut(wire, { minor, setxattrExt: false });
      expect(decoded.attr.blksize, `7.${minor}`).toBe(512);
      expect(decoded.attr.flags, `7.${minor}`).toBe(0);
    }
    expect(decodeAttrOut(wire, { minor: 32, setxattrExt: false }).attr.flags).toBe(0xde_ad_be_ef);
  });

  it("drops frsize from fuse_kstatfs before 7.4", () => {
    const value = { ...randomKstatfs(new Rng(3)), frsize: 4096 };
    const old: ProtocolContext = { minor: 3, setxattrExt: false };
    const bytes = encodeStatfsOut(value, old);
    expect(bytes.length).toBe(48);
    expect(decodeStatfsOut(bytes, old)).toEqual({ ...value, frsize: 0 });
    expect(encodeStatfsOut(value).length).toBe(80);
  });

  it("drops lock_owner and flags from fuse_read_in before 7.9", () => {
    const old: ProtocolContext = { minor: 8, setxattrExt: false };
    const value = {
      fh: 7n,
      offset: 4096n,
      size: 128,
      readFlags: 2,
      lockOwner: 0x1122334455667788n,
      flags: 0o2,
    };
    const bytes = encodeRequestBody(FUSE_READ, value, old);
    expect(bytes.length).toBe(24);
    expect(decodeRequestBody(FUSE_READ, bytes, old)).toEqual({
      ...value,
      lockOwner: 0n,
      flags: 0,
    });
  });

  it("drops the tail of fuse_write_in before 7.9 but keeps the payload", () => {
    const old: ProtocolContext = { minor: 8, setxattrExt: false };
    const data = new Uint8Array([1, 2, 3]);
    const bytes = encodeRequestBody(
      FUSE_WRITE,
      { fh: 1n, offset: 0n, size: 3, writeFlags: 0, lockOwner: 5n, flags: 1, data },
      old,
    );
    expect(bytes.length).toBe(24 + 3);
    expect(decodeRequestBody(FUSE_WRITE, bytes, old)).toEqual({
      fh: 1n,
      offset: 0n,
      size: 3,
      writeFlags: 0,
      lockOwner: 0n,
      flags: 0,
      data,
    });
  });

  it("drops umask/open_flags from fuse_create_in before 7.12", () => {
    const old: ProtocolContext = { minor: 11, setxattrExt: false };
    const bytes = encodeRequestBody(
      FUSE_CREATE,
      { flags: 0o102, mode: 0o644, umask: 0o22, openFlags: 1, name: "f" },
      old,
    );
    expect(bytes.length).toBe(8 + 2);
    expect(decodeRequestBody(FUSE_CREATE, bytes, old)).toEqual({
      flags: 0o102,
      mode: 0o644,
      umask: 0,
      openFlags: 0,
      name: "f",
    });
  });

  it("uses the 8-byte fuse_setxattr_in without FUSE_SETXATTR_EXT", () => {
    const value = {
      flags: 1,
      setxattrFlags: 0,
      name: "user.a",
      value: new Uint8Array([9, 9]),
    };
    const plain = encodeRequestBody(FUSE_SETXATTR, value, DEFAULT_PROTOCOL);
    const extended = encodeRequestBody(FUSE_SETXATTR, value, { minor: 41, setxattrExt: true });
    expect(extended.length - plain.length).toBe(8);
    expect(decodeRequestBody(FUSE_SETXATTR, plain, DEFAULT_PROTOCOL)).toEqual(value);
  });

  it("truncates fuse_init_out for old kernels", () => {
    const value = {
      major: 7,
      minor: 4,
      maxReadahead: 1,
      flags: 2,
      maxBackground: 3,
      congestionThreshold: 4,
      maxWrite: 5,
      timeGran: 6,
      maxPages: 7,
      mapAlignment: 8,
      flags2: 9,
      maxStackDepth: 10,
    };
    expect(encodeInitOut(value).length).toBe(8);
    expect(encodeInitOut({ ...value, minor: 22 }).length).toBe(24);
    expect(encodeInitOut({ ...value, minor: 23 }).length).toBe(64);
    // A 24-byte reply decodes with the missing tail zeroed.
    const short = encodeInitOut({ ...value, minor: 22 });
    expect(decodeInitOut(short)).toEqual({
      ...value,
      minor: 22,
      timeGran: 0,
      maxPages: 0,
      mapAlignment: 0,
      flags2: 0,
      maxStackDepth: 0,
    });
  });

  it("refuses to encode a fuse_init_out that disagrees with the session", () => {
    // Size and the announced minor come from one source: a reply laid out as
    // 7.22 must not claim 7.41 (or the reverse).
    const value = {
      major: 7,
      minor: 41,
      maxReadahead: 1,
      flags: 2,
      maxBackground: 3,
      congestionThreshold: 4,
      maxWrite: 5,
      timeGran: 6,
      maxPages: 7,
      mapAlignment: 8,
      flags2: 9,
      maxStackDepth: 10,
    };
    expect(() => encodeInitOut(value, { minor: 22, setxattrExt: false })).toThrow(ProtocolError);
    expect(encodeInitOut(value, { minor: 41, setxattrExt: false }).length).toBe(64);
    expect(encodeInitOut({ ...value, minor: 22 }).length).toBe(24);
  });

  it("decodes fuse_init_in from its own length", () => {
    const full = encodeInitIn({ major: 7, minor: 41, maxReadahead: 8, flags: 16, flags2: 32 });
    expect(full.length).toBe(64);
    expect(decodeInitIn(full)).toEqual({
      major: 7,
      minor: 41,
      maxReadahead: 8,
      flags: 16,
      flags2: 32,
    });
    // A pre-7.36 kernel sends only 16 bytes.
    expect(decodeInitIn(full.subarray(0, 16))).toEqual({
      major: 7,
      minor: 41,
      maxReadahead: 8,
      flags: 16,
      flags2: 0,
    });
    // A pre-7.6 kernel sends only 8.
    expect(decodeInitIn(full.subarray(0, 8))).toEqual({
      major: 7,
      minor: 41,
      maxReadahead: 0,
      flags: 0,
      flags2: 0,
    });
  });

  it("zeroes backing_id before 7.40", () => {
    const old: ProtocolContext = { minor: 39, setxattrExt: false };
    const bytes = encodeReplyBody(FUSE_OPEN, { fh: 1n, openFlags: 2, backingId: 7 }, old);
    expect(decodeReplyBody(FUSE_OPEN, bytes, old)).toEqual({ fh: 1n, openFlags: 2, backingId: 0 });
  });
});

describe("xattr helpers", () => {
  it("round-trips a LISTXATTR name list", () => {
    const names = ["user.one", "security.selinux", "trusted.λ"];
    const bytes = encodeXattrNames(names);
    expect(bytes.at(-1)).toBe(0);
    expect(decodeXattrNames(bytes)).toEqual(names);
    expect(decodeXattrNames(new Uint8Array(0))).toEqual([]);
  });

  it("round-trips the size-probe reply", () => {
    expect(decodeGetxattrOut(encodeGetxattrOut({ size: 4096 }))).toEqual({ size: 4096 });
    // The 8-byte struct is indistinguishable from an 8-byte value on the wire,
    // so the generic decoder always returns raw data.
    const raw = decodeReplyBody(FUSE_GETXATTR, encodeGetxattrOut({ size: 1 })) as {
      data: Uint8Array;
    };
    expect(raw.data.length).toBe(8);
  });

  it("rejects a name containing NUL", () => {
    expect(() => encodeXattrNames(["a\0b"])).toThrow(ProtocolError);
    expect(() => encodeRequestBody(FUSE_LOOKUP, { name: "a\0b" })).toThrow(ProtocolError);
  });
});

describe("decoder totality", () => {
  it("throws ProtocolError on truncation, never RangeError", () => {
    const full = encodeReplyBody(FUSE_STATFS, randomKstatfs(new Rng(11)));
    for (let length = 0; length < full.length; length++) {
      const error = (() => {
        try {
          decodeReplyBody(FUSE_STATFS, full.subarray(0, length));
          return undefined;
        } catch (cause) {
          return cause;
        }
      })();
      expect(isProtocolError(error), `length ${length}`).toBe(true);
    }
  });

  it("throws on trailing bytes", () => {
    const bytes = new Uint8Array(9); // fuse_forget_in is 8
    expect(() => decodeRequestBody(2, bytes)).toThrow(ProtocolError);
  });

  it("throws on an unterminated name", () => {
    expect(() => decodeRequestBody(FUSE_LOOKUP, new Uint8Array([0x61, 0x62]))).toThrow(
      ProtocolError,
    );
  });

  it("refuses to allocate from an unvalidated BATCH_FORGET count", () => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setUint32(0, 0xff_ff_ff_ff, true);
    const error = (() => {
      try {
        decodeRequestBody(42, bytes);
        return undefined;
      } catch (cause) {
        return cause;
      }
    })();
    expect(isProtocolError(error)).toBe(true);
    expect((error as ProtocolError).message).toContain("4294967295");
  });

  it("rejects a WRITE whose size exceeds its payload", () => {
    const bytes = new Uint8Array(40 + 2);
    new DataView(bytes.buffer).setUint32(16, 1000, true);
    expect(() => decodeRequestBody(FUSE_WRITE, bytes)).toThrow(ProtocolError);
  });

  it("rejects a SETXATTR whose size exceeds its value", () => {
    const bytes = new Uint8Array([
      // size = 100, flags = 0
      100, 0, 0, 0, 0, 0, 0, 0,
      // "a\0" then one value byte
      0x61, 0, 1,
    ]);
    expect(() => decodeRequestBody(FUSE_SETXATTR, bytes)).toThrow(ProtocolError);
  });

  it("carries a code and an offset", () => {
    try {
      decodeInHeader(new Uint8Array(4));
      expect.unreachable();
    } catch (error) {
      expect(isProtocolError(error)).toBe(true);
      expect((error as ProtocolError).code).toBe("ERR_FUSE_PROTOCOL");
      expect((error as ProtocolError).name).toBe("ProtocolError");
      expect((error as ProtocolError).offset).toBe(4);
    }
  });

  it("rejects headers shorter than their own struct", () => {
    const header = encodeInHeader({
      len: 0,
      opcode: 1,
      unique: 1n,
      nodeid: 1n,
      uid: 0,
      gid: 0,
      pid: 0,
      totalExtlen: 0,
    });
    expect(() => decodeInHeader(header)).toThrow(ProtocolError);
    expect(() => decodeOutHeader(encodeOutHeader({ len: 4, error: 0, unique: 1n }))).toThrow(
      ProtocolError,
    );
  });
});

describe("name lengths", () => {
  it("counts UTF-8 bytes, not code units", () => {
    expect(nameByteLength("abc")).toBe(3);
    expect(nameByteLength("é")).toBe(2);
    expect(nameByteLength("🙂")).toBe(4);
  });
});
