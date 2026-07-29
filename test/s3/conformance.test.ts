/**
 * The conformance matrix, S3 column.
 *
 * The same suite as every other column (`test/conformance.ts`), carried this
 * time by an **S3 gateway**: a driver behind `S3Session`, an S3 client in front
 * of it, and an `FsDriver` rebuilt out of `PUT`, `GET`, `HEAD`, `DELETE`,
 * `CopyObject` and `ListObjectsV2` (`test/s3/client.ts`). Tier 1 — no socket,
 * no mount, no root: the session is a function from a request to a reply, so
 * the whole protocol runs in one process.
 *
 * It is the column that loses the most, and every loss is a fact about S3
 * rather than about this implementation — an object has no mode, no link
 * count, no access time and no second name. What the column proves is the
 * other half: that the file semantics a client actually depends on — creating,
 * reading at an offset, appending, truncating, listing, renaming, and the
 * errnos for all the ways those go wrong — survive a round trip through an
 * object store with none of them.
 *
 * A fresh session and a fresh driver per test, so the isolation is the loopback
 * column's: an empty filesystem, not an empty bucket that used to have things
 * in it.
 */

import { describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { createLoopback, type Loopback, type ResolvedCapabilities } from "../../src/harness.ts";
import { S3Session } from "../../src/s3/session.ts";
import { conformance } from "../conformance.ts";
import { S3_CAPABILITIES, S3Client, s3Driver } from "./client.ts";

const BUCKET = "mountx";
const REGION = "eu-west-3";
const CREDENTIALS = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};

const decoder = new TextDecoder();

/**
 * What survives the trip through an S3 gateway.
 *
 * Not restated here: it is {@link S3_CAPABILITIES}, declared beside the adapter
 * that has to deliver it, with the reasoning for each entry. `extensions` is
 * empty for the reason the FUSE and NFS columns give — the `mountx.*` namespace
 * is a driver-to-session channel with no wire representation, and S3's wire has
 * even less room for one than theirs.
 */
const THROUGH_S3: ResolvedCapabilities = { ...S3_CAPABILITIES, extensions: [] };

interface Gateway {
  session: S3Session;
  client: S3Client;
  fs: Loopback;
}

/** A gateway over a fresh memory driver, with the client in front of it. */
function gateway(options: { credentials?: boolean } = {}): Gateway {
  const session = new S3Session(
    { [BUCKET]: createMemoryDriver() },
    options.credentials === true ? { credentials: CREDENTIALS, region: REGION } : {},
  );
  const client = new S3Client(session, {
    credentials: options.credentials === true ? CREDENTIALS : undefined,
    region: REGION,
  });
  return { session, client, fs: createLoopback(s3Driver(client, BUCKET)) };
}

/** One conformance target: the gateway, plus the teardown that checks it. */
async function serve(): Promise<{ fs: Loopback; cleanup: () => Promise<void> }> {
  const { session, fs } = gateway();
  return {
    fs,
    cleanup: async () => {
      await session.close();
      // The session's own discipline, checked once per conformance case rather
      // than only in `session.test.ts`: one reply per request, and no request
      // answered twice.
      expect(session.assertions).toEqual([]);
    },
  };
}

describe("over an S3 gateway", () => {
  conformance({
    name: "memory driver, over S3",
    // Only the memory driver: every errno this column reports is synthesized by
    // the adapter from `src/errors.ts`'s table (the wire cannot carry one — see
    // `ERRNO_OF_S3_CODE`), so a second backing driver would exercise the
    // session, not the column, and `test/s3/session.test.ts` already does that.
    capabilities: THROUGH_S3,
    setup: serve,
  });
});

describe("the S3 column's own claims", () => {
  it("declares exactly what the adapter resolves to", () => {
    const { fs } = gateway();
    expect(fs.capabilities).toEqual(THROUGH_S3);
  });

  it("refuses what it does not claim, with ENOSYS rather than a pretence", async () => {
    const { fs } = gateway();
    await fs.writeFile("/f", "x");
    for (const call of [
      fs.chmod("/f", 0o600),
      fs.chown("/f", 0, 0),
      fs.link("/f", "/alias"),
      fs.symlink("f", "/link"),
      fs.readlink("/f"),
      fs.statfs("/"),
      fs.lutimes("/f", 1, 1),
      fs.lchown("/f", 0, 0),
    ]) {
      await expect(call).rejects.toMatchObject({ code: "ENOSYS" });
    }
  });

  /**
   * The `times: false` declaration, and the half of it that does work.
   *
   * `utimes` writes `x-amz-meta-mtime` through a metadata-only self-copy, which
   * is the gateway's own convention (and rclone's), so the modification time
   * round-trips to the second. The access time does not exist in S3 at all, and
   * the conformance case asks for both — which is why the capability is
   * declared `false` and this test is where the surviving half is pinned.
   */
  it("round-trips an mtime and drops the atime, which is why `times` is false", async () => {
    const { fs } = gateway();
    await fs.writeFile("/dated", "x");
    await fs.utimes("/dated", new Date(1000), new Date(1_234_567_000));
    const stats = await fs.stat("/dated");
    expect(stats.mtimeMs).toBe(1_234_567_000);
    // Not 1000: there is no access time on the wire, so `stat` answers the one
    // timestamp an object has.
    expect(stats.atimeMs).toBe(stats.mtimeMs);
    expect(decoder.decode(await fs.readFile("/dated"))).toBe("x");
  });

  it("keeps the empty-directory marker out of its own listing", async () => {
    const { client, fs } = gateway();
    await fs.mkdir("/empty");
    expect(await fs.readdir("/empty", { withFileTypes: true })).toEqual([]);
    // The marker is there on the wire — it is what makes the directory visible
    // to a client at all — and it is the adapter that knows it is not an entry.
    const page = await client.list(BUCKET, { prefix: "empty/", delimiter: "/" });
    expect(page.contents.map((entry) => entry.key)).toEqual(["empty/"]);
  });
});

describe("the adapter's buffering, which is where its capabilities come from", () => {
  it("shares one buffer between every handle on a path", async () => {
    const { fs } = gateway();
    await fs.writeFile("/shared", "original");
    const first = await fs.open("/shared", "r+");
    const second = await fs.open("/shared", "r+");
    await first.write(new TextEncoder().encode("OR"), 0, 2, 0);

    // Through the *other* handle, before anything has been put back.
    const buffer = new Uint8Array(8);
    await second.read(buffer, 0, 8, 0);
    expect(decoder.decode(buffer)).toBe("ORiginal");
    expect((await second.stat()).size).toBe(8);

    await first.close();
    await second.close();
    expect(decoder.decode(await fs.readFile("/shared"))).toBe("ORiginal");
  });

  it("truncates the shared buffer, from a path and from a re-open", async () => {
    const { fs } = gateway();
    await fs.writeFile("/live", "0123456789");
    const handle = await fs.open("/live", "r+");

    // The path-level call has to reach the open buffer, not a stale copy.
    await fs.truncate("/live", 4);
    expect((await handle.stat()).size).toBe(4);

    // And so does an `open` that truncates while the first handle is still up.
    const truncating = await fs.open("/live", "w");
    expect((await handle.stat()).size).toBe(0);
    await truncating.close();
    await handle.close();
    expect((await fs.stat("/live")).size).toBe(0);
  });

  it("rejects a closed handle with EBADF", async () => {
    const { fs } = gateway();
    await fs.writeFile("/closed", "x");
    const handle = await fs.open("/closed", "r");
    await handle.close();
    // Closing twice is a no-op, as it is everywhere else.
    await handle.close();
    await expect(handle.stat()).rejects.toMatchObject({ code: "EBADF" });
    await expect(handle.read(new Uint8Array(1), 0, 1, 0)).rejects.toMatchObject({ code: "EBADF" });
  });

  it("refuses utimes on a directory, which CopyObject cannot name", async () => {
    const { fs } = gateway();
    await fs.mkdir("/dir");
    await expect(fs.utimes("/dir", 1, 1)).rejects.toMatchObject({ code: "EISDIR" });
    await expect(fs.utimes("/nope", 1, 1)).rejects.toMatchObject({ code: "ENOENT" });
  });

  /**
   * The one refusal the suite does not ask for and a real client would meet:
   * a destination whose parent is a file. `ENOTDIR` cannot come back over the
   * wire — the gateway answers `NoSuchKey` for it, as it does for a key that
   * is simply absent — so the adapter walks the destination's ancestors before
   * copying anything.
   */
  it("refuses a rename into a path that traverses a file", async () => {
    const { fs } = gateway();
    await fs.writeFile("/from", "payload");
    await fs.writeFile("/blocker", "x");
    await expect(fs.rename("/from", "/blocker/child")).rejects.toMatchObject({ code: "ENOTDIR" });
    await expect(fs.rename("/from", "/missing/child")).rejects.toMatchObject({ code: "ENOENT" });
    expect(decoder.decode(await fs.readFile("/from"))).toBe("payload");
  });

  it("holds a directory open without letting anything be written to it", async () => {
    const { fs } = gateway();
    await fs.mkdir("/held");
    const handle = await fs.open("/held", "r");
    expect((await handle.stat()).isDirectory()).toBe(true);
    await expect(handle.write(new Uint8Array(1), 0, 1, 0)).rejects.toMatchObject({
      code: "EISDIR",
    });
    await expect(handle.truncate(0)).rejects.toMatchObject({ code: "EISDIR" });
    await handle.sync?.();
    await handle.datasync?.();
    await handle.close();
  });

  it("reports directory entries as directories", async () => {
    const { fs } = gateway();
    await fs.mkdir("/d");
    const [entry] = await fs.readdir("/", { withFileTypes: true });
    expect(entry?.isDirectory()).toBe(true);
    expect(entry?.isSymbolicLink()).toBe(false);
    expect(entry?.isBlockDevice()).toBe(false);
    expect(entry?.isCharacterDevice()).toBe(false);
    expect(entry?.isFIFO()).toBe(false);
    expect(entry?.isSocket()).toBe(false);
  });
});

describe("the client's remaining surface", () => {
  it("answers the service and bucket operations", async () => {
    const { client } = gateway();
    expect(await client.bucketNames()).toEqual([BUCKET]);
    expect((await client.headBucket(BUCKET)).status).toBe(200);
    expect((await client.headBucket("absent")).status).toBe(404);
  });

  it("reads a range, and the mtime it was told to store", async () => {
    const { client, fs } = gateway();
    await client.putObject(BUCKET, "ranged.txt", "0123456789", { mtimeSeconds: 1_700_000_000 });
    const ranged = await client.getObject(BUCKET, "ranged.txt", { range: "bytes=2-5" });
    expect(ranged.status).toBe(206);
    expect(ranged.text).toBe("2345");
    expect((await fs.stat("/ranged.txt")).mtimeMs).toBe(1_700_000_000_000);
  });

  it("follows the continuation tokens", async () => {
    const { client, fs } = gateway();
    await fs.writeFile("/a.txt", "1");
    await fs.mkdir("/b");
    await fs.writeFile("/b/inner", "2");
    await fs.writeFile("/c.txt", "3");

    // One key per page, so the loop in `listAll` has to run four times: three
    // pages and the one that answers `IsTruncated: false`.
    const page = await client.list(BUCKET, { delimiter: "/", maxKeys: 1 });
    expect(page.isTruncated).toBe(true);
    expect(page.nextContinuationToken).toBeDefined();

    const all = await client.listAll(BUCKET, { delimiter: "/", maxKeys: 1 });
    expect(all.contents.map((entry) => entry.key)).toEqual(["a.txt", "c.txt"]);
    expect(all.commonPrefixes).toEqual(["b/"]);
    expect(all.keyCount).toBe(3);
  });

  it("aborts an upload and forgets its parts", async () => {
    const { session, client } = gateway();
    const uploadId = await client.startUpload(BUCKET, "abandoned.bin");
    await client.uploadPart(BUCKET, "abandoned.bin", uploadId, 1, "some bytes");
    expect(await client.parts(BUCKET, "abandoned.bin", uploadId)).toHaveLength(1);

    expect((await client.abortMultipartUpload(BUCKET, "abandoned.bin", uploadId)).status).toBe(204);
    const gone = await client.listParts(BUCKET, "abandoned.bin", uploadId, {
      maxParts: 10,
      partNumberMarker: 0,
    });
    expect(gone.status).toBe(404);
    expect(gone.errorCode).toBe("NoSuchUpload");
    await session.close();
  });
});

describe("the same workload, signed", () => {
  /**
   * Everything above runs anonymously, which is the gateway's loopback posture.
   * This is the proof that the client's SigV4 composes with every call it
   * makes: the same operations against a session that verifies each one, where
   * a signature this client got wrong is `AccessDenied` rather than a wrong
   * answer.
   */
  it("carries a file, a directory, a listing and a rename through a verifying session", async () => {
    const { session, client, fs } = gateway({ credentials: true });
    expect(client.signing).toBe(true);

    await fs.mkdir("/photos/2024", { recursive: true });
    await fs.writeFile("/photos/2024/june.txt", "summer");
    await fs.writeFile("/photos/note", "unfiled");

    expect(decoder.decode(await fs.readFile("/photos/2024/june.txt"))).toBe("summer");
    const entries = await fs.readdir("/photos", { withFileTypes: true });
    expect(entries.map((entry) => entry.name).sort()).toEqual(["2024", "note"]);

    await fs.rename("/photos/note", "/photos/2024/note");
    await expect(fs.stat("/photos/note")).rejects.toMatchObject({ code: "ENOENT" });
    expect(decoder.decode(await fs.readFile("/photos/2024/note"))).toBe("unfiled");

    await fs.unlink("/photos/2024/june.txt");
    await fs.unlink("/photos/2024/note");
    await fs.rmdir("/photos/2024");
    await fs.rmdir("/photos");
    expect(await fs.readdir("/", { withFileTypes: true })).toEqual([]);

    expect(session.assertions).toEqual([]);
    // Every one of those calls was verified, which is only worth saying because
    // the same session refuses a client that is not signing at all: the
    // workload above passing is evidence about the signatures, not about the
    // gateway having let anything through.
    const anonymous = new S3Client(session);
    const refused = await anonymous.putObject(BUCKET, "unsigned", "bytes");
    expect(refused.status).toBe(403);
    expect(refused.errorCode).toBe("AccessDenied");
    await session.close();
  });

  it("refuses the same client once its credentials are wrong", async () => {
    const { session } = gateway({ credentials: true });
    const impostor = new S3Client(session, {
      credentials: { ...CREDENTIALS, secretAccessKey: "not the key" },
      region: REGION,
    });
    const reply = await impostor.putObject(BUCKET, "denied", "bytes");
    expect(reply.status).toBe(403);
    expect(reply.errorCode).toBe("SignatureDoesNotMatch");
    await session.close();
  });

  it("signs the multipart calls too", async () => {
    const { session, client } = gateway({ credentials: true });
    const uploadId = await client.startUpload(BUCKET, "assembled.bin");
    const part = await client.uploadPart(BUCKET, "assembled.bin", uploadId, 1, "one part only");
    expect(part.status).toBe(200);
    const etag = part.headers.etag ?? "";
    expect(etag).not.toBe("");
    expect(await client.parts(BUCKET, "assembled.bin", uploadId)).toEqual([
      { partNumber: 1, size: 13, etag: etag.replaceAll(`"`, "") },
    ]);
    const completed = await client.finishUpload(BUCKET, "assembled.bin", uploadId, [
      { partNumber: 1, etag },
    ]);
    expect(completed.key).toBe("assembled.bin");

    const fetched = await client.getObject(BUCKET, "assembled.bin");
    expect(fetched.text).toBe("one part only");

    // And the bulk delete, which the adapter uses for a directory rename.
    const deleted = await client.deleteObjects(BUCKET, ["assembled.bin"]);
    expect(deleted.status).toBe(200);
    expect(deleted.text).toContain("<Deleted>");
    expect((await client.headObject(BUCKET, "assembled.bin")).status).toBe(404);
    await session.close();
  });
});
