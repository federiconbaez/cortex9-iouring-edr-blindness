/* Benign io_uring vs classic file-op victim. No network, no rootkit.
 * Usage: victim <workdir> uring|classic
 * Prints one JSON line with submitted opcodes when mode=uring (for Tracer C).
 * Exit 0 if all scored ops succeed.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NOPS 8

static void die(const char *msg) {
  perror(msg);
  exit(2);
}

static int do_classic(const char *wd) {
  char a[512], b[512], c[512], d[512];
  snprintf(a, sizeof a, "%s/a.txt", wd);
  snprintf(b, sizeof b, "%s/b.txt", wd);
  snprintf(c, sizeof c, "%s/c.txt", wd);
  snprintf(d, sizeof d, "%s/d-dir", wd);

  int fd = open(a, O_CREAT | O_RDWR | O_TRUNC, 0644);
  if (fd < 0) die("open");
  const char *payload = "payload-classic\n";
  if (write(fd, payload, strlen(payload)) < 0) die("write");
  if (close(fd) < 0) die("close");

  fd = open(a, O_RDONLY);
  if (fd < 0) die("open2");
  char buf[64];
  if (read(fd, buf, sizeof buf) <= 0) die("read");
  close(fd);

  struct stat st;
  if (stat(a, &st) < 0) die("stat");

  if (mkdir(d, 0755) < 0) die("mkdir");

  int fdb = open(b, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fdb < 0) die("open b");
  write(fdb, "x\n", 2);
  close(fdb);
  if (rename(b, c) < 0) die("rename");
  if (unlink(c) < 0) die("unlink");
  return 0;
}

static int wait1(struct io_uring *ring, int *out_res) {
  struct io_uring_cqe *cqe;
  int ret = io_uring_submit_and_wait(ring, 1);
  if (ret < 0) return ret;
  ret = io_uring_wait_cqe(ring, &cqe);
  if (ret < 0) return ret;
  if (out_res) *out_res = cqe->res;
  int res = cqe->res;
  io_uring_cqe_seen(ring, cqe);
  return res < 0 ? res : 0;
}

static void peek_push(unsigned *ops, int *n, struct io_uring_sqe *sqe) {
  if (*n < 64) ops[(*n)++] = sqe->opcode;
}

static int do_uring(const char *wd) {
  char a[512], b[512], cpath[512], d[512];
  snprintf(a, sizeof a, "%s/a.txt", wd);
  snprintf(b, sizeof b, "%s/b.txt", wd);
  snprintf(cpath, sizeof cpath, "%s/c.txt", wd);
  snprintf(d, sizeof d, "%s/d-dir", wd);

  struct io_uring ring;
  if (io_uring_queue_init(32, &ring, 0) < 0) die("io_uring_queue_init");

  unsigned peeked[64];
  int npeek = 0;
  struct io_uring_sqe *sqe;
  int res = 0;
  const char *payload = "payload-uring\n";
  char rbuf[64];
  struct statx stx;

  /* openat a.txt */
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_openat(sqe, AT_FDCWD, a, O_CREAT | O_RDWR | O_TRUNC, 0644);
  peek_push(peeked, &npeek, sqe);
  if (wait1(&ring, &res) < 0) return 1;
  int fd = res;

  /* write */
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_write(sqe, fd, payload, strlen(payload), 0);
  peek_push(peeked, &npeek, sqe);
  if (wait1(&ring, &res) < 0) return 1;

  /* close */
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_close(sqe, fd);
  peek_push(peeked, &npeek, sqe);
  if (wait1(&ring, &res) < 0) return 1;

  /* openat + read + close */
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_openat(sqe, AT_FDCWD, a, O_RDONLY, 0);
  peek_push(peeked, &npeek, sqe); /* scaffolding open; still an openat */
  if (wait1(&ring, &res) < 0) return 1;
  int rfd = res;

  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_read(sqe, rfd, rbuf, sizeof rbuf, 0);
  peek_push(peeked, &npeek, sqe);
  if (wait1(&ring, &res) < 0) return 1;

  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_close(sqe, rfd);
  peek_push(peeked, &npeek, sqe); /* scaffolding close */
  wait1(&ring, &res);

  /* statx */
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_statx(sqe, AT_FDCWD, a, 0, STATX_BASIC_STATS, &stx);
  peek_push(peeked, &npeek, sqe);
  if (wait1(&ring, &res) < 0) return 1;

  /* mkdirat */
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_mkdirat(sqe, AT_FDCWD, d, 0755);
  peek_push(peeked, &npeek, sqe);
  if (wait1(&ring, &res) < 0) return 1;

  /* seed b.txt entirely via io_uring (no classic open/write) */
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_openat(sqe, AT_FDCWD, b, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  peek_push(peeked, &npeek, sqe); /* scaffolding */
  if (wait1(&ring, &res) < 0) return 1;
  int fdb = res;
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_write(sqe, fdb, "x\n", 2, 0);
  peek_push(peeked, &npeek, sqe); /* scaffolding */
  if (wait1(&ring, &res) < 0) return 1;
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_close(sqe, fdb);
  peek_push(peeked, &npeek, sqe); /* scaffolding */
  wait1(&ring, &res);

  /* renameat */
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_renameat(sqe, AT_FDCWD, b, AT_FDCWD, cpath, 0);
  peek_push(peeked, &npeek, sqe);
  if (wait1(&ring, &res) < 0) return 1;

  /* unlinkat */
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_unlinkat(sqe, AT_FDCWD, cpath, 0);
  peek_push(peeked, &npeek, sqe);
  if (wait1(&ring, &res) < 0) return 1;

  io_uring_queue_exit(&ring);

  /* Emit peeked opcodes for Tracer C (ring-peek at submit site). */
  fputs("{\"peeked_opcodes\":[", stdout);
  for (int i = 0; i < npeek; i++) {
    if (i) fputc(',', stdout);
    fprintf(stdout, "%u", peeked[i]);
  }
  fputs("]}\n", stdout);
  fflush(stdout);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <workdir> uring|classic\n", argv[0]);
    return 2;
  }
  if (strcmp(argv[2], "classic") == 0) return do_classic(argv[1]);
  if (strcmp(argv[2], "uring") == 0) return do_uring(argv[1]);
  fprintf(stderr, "mode must be uring|classic\n");
  return 2;
}
