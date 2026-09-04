/*
 * readscan - one sequential pass over a file, with the read-side cache
 * hints under a switch. The MECHANISM isolated from the engine.
 *
 * Written 3 Sep 2026 alongside crates/nzbkit-base/src/disk/readpolicy.rs.
 * The policy there is measured end to end by par2-cache-round.sh on a
 * box that can run the engine. This exists for the boxes that cannot:
 * a device class whose only representative on the fleet has no compiler,
 * no root and a libc far older than any host we build on. Statically
 * linked it runs there anyway, and it does exactly what the engine's
 * scan loop does - open, read front to back in a fixed buffer, and
 * optionally tell the kernel about it - so the kernel behaviour the
 * policy is betting on can be measured where the engine cannot go.
 *
 *   cc -O2 -static -o readscan readscan.c
 *   readscan [-s] [-d MiB] [-g] [-b MiB] FILE
 *     -s        POSIX_FADV_SEQUENTIAL at open
 *     -d MiB    POSIX_FADV_DONTNEED behind the reader every MiB (0 = off)
 *     -g        GATE the drop on what we brought in (see below)
 *     -b MiB    read buffer, default 8
 *
 * `-g` is the answer to the one result that stopped this policy shipping
 * armed: drop-behind wins 9.8% COLD and loses 7.1% WARM, and the warm
 * loss is the kernel freeing pages the reader never brought in, inline,
 * at ~0.64 us each. So gate it: give back only what you brought in.
 *
 * THE SAMPLE HAS TO BE TAKEN AT OPEN, and that is the whole subtlety.
 * A per-stride "was this resident before I read it?" is contaminated by
 * our OWN readahead, which by construction runs ahead of the reader and
 * has already pulled the next stride in - so the honest sample would
 * report "already cached, leave it" for every stride and the cold win
 * would quietly vanish. One mincore(2) over the whole file before the
 * first read is not contaminated by anything, costs one syscall, and is
 * exact per page. A stride is dropped only if it was ENTIRELY absent at
 * open, which errs toward leaving other people's pages alone.
 *
 * Prints: bytes, wall seconds, MB/s. Reads only; never writes, never
 * creates, never unlinks - it is pointed at other people's files.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Per-stride "was this entirely absent from the page cache at open?".
 * Returns a malloc'd byte per stride (1 = ours to drop), or NULL if the
 * sample could not be taken - in which case the caller must fall back to
 * dropping nothing, never to dropping everything. */
static unsigned char *sample_absent(int fd, unsigned long long len, size_t stride,
                                    size_t *n_out, double *cost_s) {
    /* Only the DROP needs posix_fadvise; the SAMPLE needs mincore, which
     * macOS has too. Keeping them apart means the sampler - the half
     * with the readahead-contamination subtlety in it - can be checked
     * on a laptop, where `-g` then reports what it found and drops
     * nothing. */
    long ps = sysconf(_SC_PAGESIZE);
    size_t pages = (size_t)((len + (unsigned long long)ps - 1) / (unsigned long long)ps);
    size_t nstride = (size_t)((len + stride - 1) / stride);
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    void *map = mmap(NULL, (size_t)len, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { return NULL; }
    unsigned char *vec = malloc(pages);
    unsigned char *out = calloc(nstride, 1);
    if (!vec || !out || mincore(map, (size_t)len, (void *)vec) != 0) {
        munmap(map, (size_t)len); free(vec); free(out);
        return NULL;
    }
    size_t per = stride / (size_t)ps;
    for (size_t k = 0; k < nstride; k++) {
        size_t lo = k * per, hi = lo + per;
        if (hi > pages) { hi = pages; }
        int any = 0;
        for (size_t i = lo; i < hi; i++) { if (vec[i] & 1) { any = 1; break; } }
        out[k] = any ? 0 : 1;   /* ours to drop only if NOTHING was there */
    }
    munmap(map, (size_t)len);
    free(vec);
    clock_gettime(CLOCK_MONOTONIC, &b);
    *cost_s = (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_nsec - a.tv_nsec) / 1e9;
    *n_out = nstride;
    return out;
}

int main(int argc, char **argv) {
    int seq = 0, gate = 0;
    long drop_mb = 0, buf_mb = 8;
    int c;
    while ((c = getopt(argc, argv, "sgd:b:")) != -1) {
        switch (c) {
        case 's': seq = 1; break;
        case 'g': gate = 1; break;
        case 'd': drop_mb = atol(optarg); break;
        case 'b': buf_mb = atol(optarg); break;
        default: return 2;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "usage: %s [-s] [-g] [-d MiB] [-b MiB] FILE\n", argv[0]);
        return 2;
    }
    const char *path = argv[optind];
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 1; }
#ifdef POSIX_FADV_SEQUENTIAL
    if (seq) { posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL); }
#endif
    size_t bs = (size_t)(buf_mb > 0 ? buf_mb : 8) << 20;
    char *buf = malloc(bs);
    if (!buf) { fprintf(stderr, "out of memory\n"); return 1; }
    size_t stride = (size_t)drop_mb << 20;
    unsigned long long total = 0, dropped = 0;
    /* Sampled BEFORE the first read, so our own readahead cannot have
     * touched it. NULL means the sample failed: then gate everything
     * off rather than dropping blind. */
    unsigned char *ours = NULL;
    size_t n_ours = 0;
    double sample_s = 0.0;
    struct stat st0;
    if (gate && stride && fstat(fd, &st0) == 0 && st0.st_size > 0) {
        ours = sample_absent(fd, (unsigned long long)st0.st_size, stride,
                             &n_ours, &sample_s);
        if (!ours) { stride = 0; }
    } else if (gate) {
        stride = 0;
    }
    /* macOS has no posix_fadvise, so the drop-behind block below is
     * preprocessed away there and these two go unused. The file still
     * has to COMPILE on the machine a lane is sitting at, and a -Wall
     * warning is how a real mistake in it would announce itself. */
    (void)stride;
    (void)dropped;
    (void)gate;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        ssize_t n = read(fd, buf, bs);
        if (n < 0) { perror("read"); return 1; }
        if (n == 0) { break; }
        total += (unsigned long long)n;
#ifdef POSIX_FADV_DONTNEED
        if (stride && total - dropped >= stride) {
            unsigned long long upto = total - (total % stride);
            while (dropped < upto) {
                size_t k = (size_t)(dropped / stride);
                /* Ungated, or this stride was entirely absent at open
                 * and is therefore ours to give back. */
                if (!ours || (k < n_ours && ours[k])) {
                    posix_fadvise(fd, (off_t)dropped, (off_t)stride,
                                  POSIX_FADV_DONTNEED);
                }
                dropped += stride;
            }
        }
#endif
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double wall = (double)(t1.tv_sec - t0.tv_sec) +
                  (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    size_t mine = 0;
    for (size_t k = 0; k < n_ours; k++) { mine += ours[k] ? 1 : 0; }
    printf("%llu %.3f %.1f seq=%d drop_mb=%ld buf_mb=%ld gate=%d "
           "ours=%zu/%zu sample_s=%.3f\n",
           total, wall, wall > 0 ? (double)total / wall / 1e6 : 0.0, seq,
           drop_mb, buf_mb, gate, mine, n_ours, sample_s);
    close(fd);
    free(buf);
    free(ours);
    return 0;
}
