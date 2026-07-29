/*
 * SPIKE fixture: the same workload with no libc anywhere — raw `syscall`
 * instructions, its own `_start`, `-nostdlib -static`.
 *
 *   zig cc -target x86_64-linux-none -nostdlib -static probe-raw.c -o probe-raw
 *
 * This is the Go case. A Go binary issues its syscalls from its own runtime
 * rather than through libc, which is why it is the standard counter-example to
 * every `LD_PRELOAD` sandbox — there is no symbol to interpose, and on a static
 * binary there is not even a dynamic loader to read `LD_PRELOAD` in the first
 * place. Writing it in C with inline asm rather than installing a Go toolchain
 * keeps the fixture to one file and makes the syscalls it issues explicit,
 * which is the whole point of the fixture.
 *
 * A mechanism that serves this binary serves anything.
 */

typedef long ssize_t_;
typedef unsigned long size_t_;

#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_openat 257
#define SYS_getdents64 217
#define SYS_statx 332
#define SYS_exit_group 231
#define AT_FDCWD (-100)
#define O_RDONLY 0

static long sys(long n, long a, long b, long c, long d, long e, long f) {
  long ret;
  register long r10 __asm__("r10") = d;
  register long r8 __asm__("r8") = e;
  register long r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}

static size_t_ slen(const char *s) {
  size_t_ n = 0;
  while (s[n]) n++;
  return n;
}
static void out(const char *s) { sys(SYS_write, 1, (long)s, (long)slen(s), 0, 0, 0); }
static void outn(unsigned long long v) {
  char b[24];
  int i = 23;
  b[i--] = 0;
  if (!v) b[i--] = '0';
  while (v) { b[i--] = (char)('0' + (v % 10)); v /= 10; }
  out(&b[i + 1]);
}
static void outx(unsigned long long v) {
  char b[24];
  int i = 23;
  b[i--] = 0;
  if (!v) b[i--] = '0';
  while (v) { b[i--] = "0123456789abcdef"[v & 15]; v >>= 4; }
  out(&b[i + 1]);
}
static char *cat(char *dst, const char *a, const char *b) {
  char *p = dst;
  while (*a) *p++ = *a++;
  while (*b) *p++ = *b++;
  *p = 0;
  return dst;
}

/* Only the fields this fixture reads; the kernel fills the rest. */
struct statx_ {
  unsigned int mask, blksize;
  unsigned long long attributes;
  unsigned int nlink, uid, gid;
  unsigned short mode, spare0[1];
  unsigned long long ino, size, blocks, attributes_mask;
  unsigned long long rest[24];
};

struct dirent64_ {
  unsigned long long d_ino, d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
};

static const char *env_root(char **envp) {
  for (char **e = envp; *e; e++) {
    const char *k = "MOUNTX_ROOT=";
    const char *p = *e;
    size_t_ i = 0;
    while (k[i] && p[i] == k[i]) i++;
    if (!k[i]) return p + i;
  }
  return 0;
}

static unsigned char buf[4 << 20];

int probe_main(int argc, char **argv, char **envp) {
  const char *root = env_root(envp);
  if (!root && argc > 1) root = argv[1];
  if (!root) root = "/";
  out("probe-raw: root=");
  out(root);
  out("\n");
  char path[4096];

  /* 1. small file */
  cat(path, root, "/hello.txt");
  long fd = sys(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
  if (fd < 0) { out("probe-raw: FAIL open hello.txt errno="); outn((unsigned long long)-fd); out("\n"); return 1; }
  long n = sys(SYS_read, fd, (long)buf, 256, 0, 0, 0);
  sys(SYS_close, fd, 0, 0, 0, 0, 0);
  out("probe-raw: hello.txt ");
  outn((unsigned long long)(n < 0 ? 0 : n));
  out(" bytes: ");
  if (n > 0) { buf[n] = 0; out((char *)buf); }

  /* 2. statx + whole-file read */
  cat(path, root, "/big.bin");
  struct statx_ stx;
  long rc = sys(SYS_statx, AT_FDCWD, (long)path, 0, 0xfff, (long)&stx, 0);
  if (rc < 0) { out("probe-raw: FAIL statx errno="); outn((unsigned long long)-rc); out("\n"); return 1; }
  fd = sys(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
  if (fd < 0) { out("probe-raw: FAIL open big.bin\n"); return 1; }
  unsigned long long got = 0, h = 0xcbf29ce484222325ULL;
  for (;;) {
    long r = sys(SYS_read, fd, (long)buf, sizeof buf, 0, 0, 0);
    if (r <= 0) break;
    for (long i = 0; i < r; i++) { h ^= buf[i]; h *= 0x100000001b3ULL; }
    got += (unsigned long long)r;
  }
  sys(SYS_close, fd, 0, 0, 0, 0, 0);
  out("probe-raw: big.bin stat=");
  outn(stx.size);
  out(" read=");
  outn(got);
  out(" fnv=");
  outx(h);
  out("\n");

  /* 3. getdents64 */
  fd = sys(SYS_openat, AT_FDCWD, (long)root, O_RDONLY | 0200000 /* O_DIRECTORY */, 0, 0, 0);
  if (fd < 0) { out("probe-raw: FAIL opendir\n"); return 1; }
  unsigned long long count = 0;
  for (;;) {
    long r = sys(SYS_getdents64, fd, (long)buf, 32768, 0, 0, 0);
    if (r <= 0) break;
    for (long off = 0; off < r;) {
      struct dirent64_ *e = (struct dirent64_ *)(buf + off);
      if (e->d_name[0] != '.' || (e->d_name[1] && !(e->d_name[1] == '.' && !e->d_name[2]))) {
        count++;
        out("probe-raw: dirent ");
        out(e->d_name);
        out("\n");
      }
      off += e->d_reclen;
    }
  }
  sys(SYS_close, fd, 0, 0, 0, 0, 0);
  out("probe-raw: ");
  outn(count);
  out(" entries\nprobe-raw: OK\n");
  return 0;
}

/* No libc, so the kernel's entry contract is honoured by hand: rsp points at
 * argc, then argv, then a NULL, then envp. */
__asm__(".globl _start\n_start:\n  xor %rbp, %rbp\n  mov %rsp, %rdi\n  and $-16, %rsp\n  call start_c\n");

void start_c(long *sp) {
  int argc = (int)sp[0];
  char **argv = (char **)&sp[1];
  char **envp = argv + argc + 1;
  int rc = probe_main(argc, argv, envp);
  sys(SYS_exit_group, rc, 0, 0, 0, 0, 0);
  __builtin_unreachable();
}
