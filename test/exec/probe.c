/*
 * SPIKE fixture: the same filesystem workload, built two ways off one source.
 *
 * The three interception mechanisms differ almost entirely in *which binaries
 * they can serve*, so the comparison is only honest if the workload is
 * identical and the linkage is the only variable:
 *
 *   zig cc probe.c -o probe-glibc                        dynamic glibc
 *   zig cc -target x86_64-linux-musl -static probe.c     static, no loader
 *
 * The first is what an LD_PRELOAD shim can serve; the second is what it cannot,
 * because a static binary never consults a dynamic loader and therefore never
 * consults LD_PRELOAD. `probe-raw.c` is the third case — no libc at all.
 *
 * Written in C rather than Zig on purpose: this fixture exists to pin down
 * *which libc symbols* get called, and C is the language where that is written
 * down rather than inferred from a standard library's internals.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Cheap enough to run on every invocation, specific enough that a short read
 * or a torn offset changes it. */
static unsigned long long fnv(const unsigned char *b, size_t n) {
  unsigned long long h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) {
    h ^= b[i];
    h *= 0x100000001b3ULL;
  }
  return h;
}

int main(int argc, char **argv) {
  const char *root = getenv("MOUNTX_ROOT");
  if (!root && argc > 1) root = argv[1];
  if (!root) root = "/";
  printf("probe: root=%s\n", root);
  char p[4096];

  /* 1. open + read a small file. */
  snprintf(p, sizeof p, "%s/hello.txt", root);
  int fd = open(p, O_RDONLY);
  if (fd < 0) { perror("probe: open hello.txt"); return 1; }
  char small[256];
  ssize_t n = read(fd, small, sizeof small);
  close(fd);
  printf("probe: hello.txt %zd bytes: %.*s", n, (int)(n < 0 ? 0 : n), small);

  /* 2. stat, then read a large file whole and checksum it. Catches short
   *    reads and offset bugs a small file never would. */
  snprintf(p, sizeof p, "%s/big.bin", root);
  struct stat st;
  if (stat(p, &st)) { perror("probe: stat big.bin"); return 1; }
  fd = open(p, O_RDONLY);
  if (fd < 0) { perror("probe: open big.bin"); return 1; }
  unsigned char *buf = malloc((size_t)st.st_size);
  size_t got = 0;
  ssize_t r;
  while (got < (size_t)st.st_size && (r = read(fd, buf + got, (size_t)st.st_size - got)) > 0) {
    got += (size_t)r;
  }
  close(fd);
  printf("probe: big.bin stat=%lld read=%zu fnv=%llx\n", (long long)st.st_size, got, fnv(buf, got));

  /* 3. read the directory. */
  DIR *d = opendir(root);
  if (!d) { perror("probe: opendir"); return 1; }
  struct dirent *e;
  int count = 0;
  while ((e = readdir(d))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
    count++;
    printf("probe: dirent %s type=%d\n", e->d_name, e->d_type);
  }
  closedir(d);
  printf("probe: %d entries\nprobe: OK\n", count);
  return 0;
}
