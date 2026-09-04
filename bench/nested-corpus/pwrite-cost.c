// pwrite-cost.c - what one positioned write costs, by chunk size.
//
// The control for round 23's finding 2 (see
// research/RAR-PERF-AUDIT-2026-09-02.md): the one-pass download path
// issues one pwrite per article, so an article-size sweep changes the
// CALL count at fixed bytes. This makes the same sweep with nothing but
// the syscall in it, in the same shape the decoders use - eight threads,
// ascending round-robin offsets into one file - so the fixed per-call
// term can be separated from the per-byte one by fitting
// sys = a * calls + b * bytes over two chunk sizes.
//
//   cc -O2 -o pw pwrite-cost.c && ./pw <chunk bytes> <path> [prealloc]
//
// It reports SYSTEM time, which on a loaded box is inflated by
// descheduling and is an upper bound - run it on an idle box before
// quoting a number. `prealloc` ftruncates the file to its full size
// first; it did not change the answer on APFS.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>

static int fd;
static size_t CH;
static uint64_t TOTAL;
static int NT = 8;
static char *buf;

static void *worker(void *a) {
    long id = (long)a;
    uint64_t n = (TOTAL + CH - 1) / CH;
    for (uint64_t i = id; i < n; i += NT) {
        off_t off = (off_t)(i * CH);
        size_t len = (off + (off_t)CH > (off_t)TOTAL) ? (size_t)(TOTAL - off) : CH;
        ssize_t w = pwrite(fd, buf, len, off);
        if (w < 0) { perror("pwrite"); exit(1); }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: pw <chunk bytes> <path> [prealloc]\n"); return 2; }
    CH = (size_t)atoll(argv[1]);
    const char *path = argv[2];
    int prealloc = argc > 3 ? atoi(argv[3]) : 0;
    TOTAL = 1ull << 30;
    buf = malloc(CH);
    memset(buf, 0xa5, CH);
    unlink(path);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return 1; }
    if (prealloc) { ftruncate(fd, (off_t)TOTAL); }
    struct timeval t0, t1;
    gettimeofday(&t0, 0);
    pthread_t th[16];
    for (long i = 0; i < NT; i++) pthread_create(&th[i], 0, worker, (void *)i);
    for (int i = 0; i < NT; i++) pthread_join(th[i], 0);
    gettimeofday(&t1, 0);
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    double wall = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;
    double sys = ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
    double usr = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6;
    uint64_t n = (TOTAL + CH - 1) / CH;
    printf("chunk=%zu prealloc=%d calls=%llu wall=%.3f sys=%.3f user=%.3f  us/call=%.2f\n",
           CH, prealloc, (unsigned long long)n, wall, sys, usr, sys * 1e6 / n);
    close(fd);
    unlink(path);
    return 0;
}
