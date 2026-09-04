/*
 * uncache - drop a file's clean pages from the page cache, without root.
 *
 * Written 3 Sep 2026 for the rotational leg of the read-side cache
 * policy (claim par2-readpolicy-rotational-leg). Every cold arm in
 * research/PAR2-TWO-LANES-COMPARED-2026-09-03.md was established with
 * `echo 3 > /proc/sys/vm/drop_caches`, which needs root - and the class
 * of box that most wants a cache round is a storage appliance, where
 * the login is an ordinary user with no passwordless sudo. The obvious
 * alternative, establishing a cold start by reading other data until
 * the payload falls out, costs a read of the whole of RAM per rep:
 * minutes of array time per arm, and a live NAS under sustained load
 * for no measurement.
 *
 * POSIX_FADV_DONTNEED over a whole file needs no privilege at all: any
 * reader can ask the kernel to give back the CLEAN pages of a file it
 * can open. That is a per-file drop rather than a global one, which is
 * exactly what a round wants anyway - it makes ONE payload cold and
 * leaves the unrelated working set the round is measuring alone, where
 * drop_caches would flatten both and the eviction metric with them.
 *
 *   cc -O2 -static -o uncache uncache.c
 *   uncache FILE...   -> per file: <resident_before> <resident_after> <total_pages> <path>
 *
 * The counts come from mincore(2), the same instrument as resident.c, so
 * the drop is VERIFIED rather than assumed: a filesystem that ignores
 * the advice, or a file somebody else holds dirty or mapped, reports a
 * nonzero `after` and the caller can see it and refuse the leg. Do not
 * assume this worked - read the second number.
 *
 * Reads nothing, writes nothing, creates nothing, unlinks nothing: it
 * opens O_RDONLY and issues advice. It is pointed at other people's
 * files.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Resident page count for an open fd, or (size_t)-1 if it cannot be
 * taken. Kept identical in shape to resident.c's loop on purpose: two
 * tools disagreeing about what "resident" means would be worse than
 * either being wrong. */
static size_t resident_pages(int fd, size_t len, size_t *pages_out) {
    long ps = sysconf(_SC_PAGESIZE);
    size_t pages = (len + (size_t)ps - 1) / (size_t)ps;
    *pages_out = pages;
    if (len == 0) { return 0; }
    void *p = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { return (size_t)-1; }
    unsigned char *vec = malloc(pages);
    if (!vec || mincore(p, len, (void *)vec) != 0) {
        munmap(p, len);
        free(vec);
        return (size_t)-1;
    }
    size_t res = 0;
    for (size_t k = 0; k < pages; k++) {
        if (vec[k] & 1) { res++; }
    }
    free(vec);
    munmap(p, len);
    return res;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE...\n", argv[0]);
        return 2;
    }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        const char *path = argv[i];
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "%s: open: %s\n", path, strerror(errno));
            rc = 1;
            continue;
        }
        struct stat st;
        if (fstat(fd, &st) != 0) {
            fprintf(stderr, "%s: fstat: %s\n", path, strerror(errno));
            close(fd);
            rc = 1;
            continue;
        }
        size_t len = (size_t)st.st_size, pages = 0;
        size_t before = resident_pages(fd, len, &pages);
#ifdef POSIX_FADV_DONTNEED
        /* Length 0 means "to the end of the file" for posix_fadvise. */
        posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#else
        fprintf(stderr, "%s: no POSIX_FADV_DONTNEED on this platform\n", path);
        rc = 1;
#endif
        size_t after = resident_pages(fd, len, &pages);
        printf("%zu %zu %zu %s\n", before, after, pages, path);
        close(fd);
    }
    return rc;
}
