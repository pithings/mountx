/**
 * Tier 2 for the seccomp supervisor: real commands, really traced, against a
 * driver that is not on any disk.
 *
 * The suite next door (`seccomp-conformance.test.ts`) drives the whole
 * conformance matrix through one traced process and is the broader check. This
 * file is the narrower and more literal one: it runs the shell, `cat`, `mv`,
 * `chmod` and a statically linked binary with no libc calls at all, and then
 * asserts on the **driver** rather than on what the command printed.
 *
 * That distinction is the whole point. The spike this replaces answered
 * `openat` by slurping the file into a `memfd`, so a program's writes landed in
 * a private copy that was thrown away: `dd conv=notrunc` reported success and
 * changed nothing, `rm -f` reported success and the file was still there. Every
 * command below that changes something is checked against the driver
 * afterwards, because "the command exited 0" is exactly what that failure
 * looked like.
 *
 * Skips itself with no Zig toolchain, off x86-64 Linux, or where a filter
 * cannot be installed. It needs **no root**: an unprivileged process may
 * install a seccomp filter as long as it sets `no_new_privs`, which is the
 * property this whole mechanism exists for.
 */

import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMemoryDriver } from "../../src/drivers/memory.ts";
import { execSeccomp } from "../../src/exec/seccomp.ts";
import { createLoopback, type Loopback } from "../../src/harness.ts";
import type { FsDriver } from "../../src/types.ts";
import { buildSupervisor, supervisorRefusal } from "./seccomp-build.ts";

const run = promisify(execFile);
const refusal = await supervisorRefusal();
const decoder = new TextDecoder();

describe.skipIf(refusal !== undefined)("a command traced by the seccomp supervisor", () => {
  let trace = "";
  let scratch = "";

  beforeAll(async () => {
    trace = await buildSupervisor();
    scratch = await mkdtemp(join(tmpdir(), "mountx-exec-run-"));
  }, 120_000);

  afterAll(async () => {
    await rm(scratch, { recursive: true, force: true });
  });

  /** A fresh driver with one file in it, and a loopback to inspect it with. */
  async function fixture(): Promise<{ driver: FsDriver; fs: Loopback }> {
    const driver = createMemoryDriver();
    const fs = createLoopback(driver);
    await fs.writeFile("/hello.txt", "hello from a driver\n");
    await fs.mkdir("/docs");
    await fs.writeFile("/docs/a.txt", "alpha\n");
    return { driver, fs };
  }

  /** Run `argv` under the supervisor and collect what it printed. */
  async function traced(
    driver: FsDriver,
    argv: readonly string[],
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    let stdout = "";
    let stderr = "";
    const result = await execSeccomp(driver, argv, {
      trace,
      stdio: ["ignore", "pipe", "pipe"],
      onSpawn: (child) => {
        child.stdout?.on("data", (chunk: Buffer) => {
          stdout += chunk.toString("utf8");
        });
        child.stderr?.on("data", (chunk: Buffer) => {
          stderr += chunk.toString("utf8");
        });
      },
    });
    return { code: result.code, stdout, stderr };
  }

  const shell = (driver: FsDriver, script: string) => traced(driver, ["sh", "-c", script]);

  it("reads a file the driver holds", async () => {
    const { driver } = await fixture();
    const result = await shell(driver, 'cat "$MOUNTX_ROOT/hello.txt"');
    expect(result.stderr).toBe("");
    expect(result.code).toBe(0);
    expect(result.stdout).toBe("hello from a driver\n");
  });

  it("lists a directory, with types", async () => {
    const { driver } = await fixture();
    const result = await shell(driver, 'ls -1 "$MOUNTX_ROOT"; ls -d "$MOUNTX_ROOT/docs"');
    expect(result.stdout.split("\n").filter(Boolean).sort()).toEqual([
      "/mountx/docs",
      "docs",
      "hello.txt",
    ]);
  });

  // --- the whole reason this file exists ---------------------------------

  it("a shell redirection reaches the driver", async () => {
    const { driver, fs } = await fixture();
    const result = await shell(driver, 'echo written > "$MOUNTX_ROOT/new.txt"');
    expect(result.code).toBe(0);
    expect(decoder.decode(await fs.readFile("/new.txt"))).toBe("written\n");
  });

  it("appends rather than replacing", async () => {
    const { driver, fs } = await fixture();
    await shell(driver, 'echo more >> "$MOUNTX_ROOT/hello.txt"');
    expect(decoder.decode(await fs.readFile("/hello.txt"))).toBe("hello from a driver\nmore\n");
  });

  it("truncates on a plain redirection", async () => {
    const { driver, fs } = await fixture();
    await shell(driver, 'echo short > "$MOUNTX_ROOT/hello.txt"');
    expect(decoder.decode(await fs.readFile("/hello.txt"))).toBe("short\n");
  });

  it("writes in the middle of a file without disturbing the rest", async () => {
    const { driver, fs } = await fixture();
    await fs.writeFile("/data", "0123456789");
    const result = await shell(
      driver,
      'printf ab | dd of="$MOUNTX_ROOT/data" bs=1 seek=3 conv=notrunc 2>/dev/null',
    );
    expect(result.code).toBe(0);
    // The spike answered this one with a clean exit and an unchanged file.
    expect(decoder.decode(await fs.readFile("/data"))).toBe("012ab56789");
  });

  it("removes a file, and the driver agrees it is gone", async () => {
    const { driver, fs } = await fixture();
    const result = await shell(driver, 'rm -f "$MOUNTX_ROOT/hello.txt"');
    expect(result.code).toBe(0);
    await expect(fs.stat("/hello.txt")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("creates and removes directories", async () => {
    const { driver, fs } = await fixture();
    await shell(driver, 'mkdir -p "$MOUNTX_ROOT/a/b/c" && rmdir "$MOUNTX_ROOT/a/b/c"');
    expect((await fs.stat("/a/b")).isDirectory()).toBe(true);
    await expect(fs.stat("/a/b/c")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("renames", async () => {
    const { driver, fs } = await fixture();
    await shell(driver, 'mv "$MOUNTX_ROOT/hello.txt" "$MOUNTX_ROOT/docs/moved.txt"');
    await expect(fs.stat("/hello.txt")).rejects.toMatchObject({ code: "ENOENT" });
    expect(decoder.decode(await fs.readFile("/docs/moved.txt"))).toBe("hello from a driver\n");
  });

  it("changes permissions", async () => {
    const { driver, fs } = await fixture();
    await shell(driver, 'chmod 600 "$MOUNTX_ROOT/hello.txt"');
    expect((await fs.stat("/hello.txt")).mode & 0o777).toBe(0o600);
  });

  it("creates and reads symlinks", async () => {
    const { driver, fs } = await fixture();
    const result = await shell(
      driver,
      'ln -s hello.txt "$MOUNTX_ROOT/link" && readlink "$MOUNTX_ROOT/link" && cat "$MOUNTX_ROOT/link"',
    );
    expect(result.stdout).toBe("hello.txt\nhello from a driver\n");
    expect((await fs.lstat("/link")).isSymbolicLink()).toBe(true);
  });

  it("copies a whole subtree out of the tree", async () => {
    const { driver } = await fixture();
    const target = join(scratch, "copied");
    const result = await shell(
      driver,
      `cp -r "$MOUNTX_ROOT/docs" ${target} && cat ${target}/a.txt`,
    );
    expect(result.stderr).toBe("");
    expect(result.stdout).toBe("alpha\n");
  });

  // --- the working directory ---------------------------------------------

  it("honours a working directory inside the tree", async () => {
    const { driver, fs } = await fixture();
    const result = await shell(
      driver,
      'cd "$MOUNTX_ROOT" && pwd && cat hello.txt && echo relative > made.txt && ls -1 .',
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toBe("/mountx\nhello from a driver\ndocs\nhello.txt\nmade.txt\n");
    expect(decoder.decode(await fs.readFile("/made.txt"))).toBe("relative\n");
  });

  it("stays inside the tree when a working directory outside it cannot be reached", async () => {
    const { driver } = await fixture();
    // A `cd` that fails leaves a shell exactly where it was. A supervisor that
    // forgot the virtual working directory on the *attempt* would resolve every
    // relative path afterwards against somewhere else entirely.
    const result = await shell(
      driver,
      'cd "$MOUNTX_ROOT" && { cd /nonexistent-mountx-xyz 2>/dev/null || true; }; pwd; cat hello.txt; cd /tmp && pwd',
    );
    expect(result.stdout).toBe("/mountx\nhello from a driver\n/tmp\n");
  });

  it("resolves `..` inside the tree and clamps it at the root", async () => {
    const { driver } = await fixture();
    const result = await shell(
      driver,
      'cd "$MOUNTX_ROOT/docs" && cat ../hello.txt && cat ../../hello.txt',
    );
    expect(result.stdout).toBe("hello from a driver\nhello from a driver\n");
  });

  // --- more than one of everything ---------------------------------------

  it("serves several traced processes at once", async () => {
    const { driver, fs } = await fixture();
    // Eight subshells, each its own process with its own descriptors, all
    // writing at the same time. The supervisor answers notifications one at a
    // time, so what this checks is that a *second* process's descriptors and
    // working directory are not the first one's — which is what keying every
    // table on the thread group behind `seccomp_notif.pid` is for.
    const result = await shell(
      driver,
      'cd "$MOUNTX_ROOT" && for i in 1 2 3 4 5 6 7 8; do (echo "worker $i" > "w$i.txt") & done; wait',
    );
    expect(result.stderr).toBe("");
    for (let index = 1; index <= 8; index++) {
      expect(decoder.decode(await fs.readFile(`/w${index}.txt`))).toBe(`worker ${index}\n`);
    }
  });

  it("keeps a descriptor a child inherited working after the parent closes it", async () => {
    const { driver } = await fixture();
    // The shape that breaks a supervisor which frees an open file the moment
    // the last descriptor it *knows about* goes: the shell opens the file,
    // forks, the child moves it onto its standard input and the parent lets go.
    const result = await shell(driver, 'wc -c < "$MOUNTX_ROOT/hello.txt"');
    expect(result.stdout.trim()).toBe("20");
  });

  it("walks a path deeper than one Twalk can carry", async () => {
    const { driver, fs } = await fixture();
    const deep = Array.from({ length: 20 }, (_, index) => `d${index}`).join("/");
    const result = await shell(
      driver,
      `mkdir -p "$MOUNTX_ROOT/${deep}" && echo bottom > "$MOUNTX_ROOT/${deep}/f" && cat "$MOUNTX_ROOT/${deep}/f"`,
    );
    // `P9_MAXWELEM` is 16, so this path takes two walks and the second one has
    // to continue from where the first stopped.
    expect(result.stdout).toBe("bottom\n");
    expect(decoder.decode(await fs.readFile(`/${deep}/f`))).toBe("bottom\n");
  });

  it("survives more opens than any fid table could hold at once", async () => {
    const { driver } = await fixture();
    const result = await shell(
      driver,
      'cd "$MOUNTX_ROOT" && i=0; while [ $i -lt 400 ]; do echo $i > "f$i"; i=$((i+1)); done; cat f399; ls -1 | wc -l',
    );
    expect(result.stdout).toBe("399\n402\n");
  }, 120_000);

  // --- the properties that make this mechanism worth having ---------------

  it("serves a statically linked binary that never calls libc", async () => {
    const { driver, fs } = await fixture();
    await fs.writeFile("/payload.bin", "abcdefghij");
    const source = join(scratch, "raw.c");
    const binary = join(scratch, "raw");
    // No libc, no dynamic loader, nothing for an `LD_PRELOAD` interposer to
    // interpose on: every one of these is a bare `syscall` instruction. This is
    // the case the whole seccomp approach exists for.
    await writeFile(
      source,
      `
static long sys(long n, long a, long b, long c) {
  long r;
  __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
  return r;
}
/* The kernel enters at _start with the stack 16-byte aligned and argc on top,
   which is not what a C function signature says; re-aligning here is what a
   libc start file would otherwise do. */
__asm__(".globl _start\\n_start:\\n  xor %rbp, %rbp\\n  and $-16, %rsp\\n  call start_c\\n");
void start_c(void) {
  char buf[64];
  long fd = sys(2, (long) "/mountx/payload.bin", 0, 0);
  long got = fd < 0 ? -1 : sys(0, fd, (long) buf, sizeof buf);
  if (got > 0) sys(1, 1, (long) buf, got);
  sys(231, got == 10 ? 0 : 9, 0, 0);
  __builtin_unreachable();
}
`,
    );
    await run("zig", [
      "cc",
      "-target",
      "x86_64-linux-none",
      "-nostdlib",
      "-static",
      "-ffreestanding",
      "-fno-builtin",
      "-O2",
      source,
      "-o",
      binary,
    ]);
    const result = await traced(driver, [binary]);
    expect(result.code).toBe(0);
    expect(result.stdout).toBe("abcdefghij");
  }, 120_000);

  it("carries a payload bigger than one 9P message byte for byte", async () => {
    const { driver, fs } = await fixture();
    const big = Buffer.allocUnsafe(3 * 1024 * 1024);
    for (let index = 0; index < big.length; index++) big[index] = (index * 31 + 7) & 0xff;
    await fs.writeFile("/big.bin", big);
    const result = await shell(
      driver,
      'cat "$MOUNTX_ROOT/big.bin" > "$MOUNTX_ROOT/copy.bin"; cmp "$MOUNTX_ROOT/big.bin" "$MOUNTX_ROOT/copy.bin" && echo identical',
    );
    expect(result.stdout).toBe("identical\n");
    expect(Buffer.from(await fs.readFile("/copy.bin")).equals(big)).toBe(true);
  }, 120_000);

  // --- the answers that must be errors rather than lies -------------------

  it("refuses to map a file on the tree instead of mapping an empty one", async () => {
    const { driver } = await fixture();
    // Without the refusal this reads as an all-zero file of the right length,
    // which is the silent wrong answer the injected `memfd` used to give.
    const result = await shell(
      driver,
      'dd if="$MOUNTX_ROOT/hello.txt" of=/dev/null 2>/dev/null; echo done',
    );
    expect(result.stdout).toBe("done\n");
  });

  it("reports a missing file as ENOENT and leaves the exit status alone", async () => {
    const { driver } = await fixture();
    const result = await shell(driver, 'cat "$MOUNTX_ROOT/nope" 2>&1; echo "status=$?"');
    expect(result.stdout).toMatch(/No such file or directory/);
    expect(result.stdout).toMatch(/status=1/);
  });

  it("leaves everything outside the tree to the real filesystem", async () => {
    const { driver } = await fixture();
    const outside = join(scratch, "outside.txt");
    await writeFile(outside, "on the real disk\n");
    const result = await shell(driver, `cat ${outside}`);
    expect(result.stdout).toBe("on the real disk\n");
  });

  it("passes the command's exit status through", async () => {
    const { driver } = await fixture();
    expect((await shell(driver, "exit 42")).code).toBe(42);
  });
});
