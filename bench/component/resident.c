/*
 * resident - how much of a file the page cache is holding, exactly.
 *
 * Written 3 Sep 2026 for the PAR2 read-side cache policy round
 * (claim par2-pagecache-policy). The metric that round needed is not
 * inside the process being measured: it is how much of an UNRELATED
 * working set survived while that process read a 23 GB payload. Every
 * PAR2 leg in research/PAR2-PERF-AUDIT-2026-09-02.md timed the PAR2
 * process and none of them timed the box around it.
 *
 * A timed re-read answers the same question with a wall clock, which
 * the method rules at the top of research/PAR2-RIGS-2026-09-02.md say
 * to prefer counts over. mincore(2) gives the count directly: one bit
 * per page, no I/O, no cache disturbance of its own.
 *
 *   cc -O2 -o resident resident.c
 *   resident FILE...      ->  one line per file:
 *                             <resident_pages> <total_pages> <bytes_resident> <path>
 *
 * Linux and macOS both have mincore; the vector element is unsigned
 * char on both, and bit 0 means resident on both. macOS mmap of a
 * zero-length file fails, so empty files report 0 0 0 rather than an
 * error - a working set that is not there is a measurement fault the
 * caller must see as zero, not as a crash.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE...\n", argv[0]);
        return 2;
    }
    long ps = sysconf(_SC_PAGESIZE);
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
        if (fstat(fd, &st) != 0 || st.st_size == 0) {
            printf("0 0 0 %s\n", path);
            close(fd);
            continue;
        }
        size_t len = (size_t)st.st_size;
        void *p = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) {
            fprintf(stderr, "%s: mmap failed\n", path);
            close(fd);
            rc = 1;
            continue;
        }
        size_t pages = (len + (size_t)ps - 1) / (size_t)ps;
        unsigned char *vec = malloc(pages);
        if (!vec || mincore(p, len, (void *)vec) != 0) {
            fprintf(stderr, "%s: mincore failed\n", path);
            munmap(p, len);
            close(fd);
            free(vec);
            rc = 1;
            continue;
        }
        size_t res = 0;
        for (size_t k = 0; k < pages; k++) {
            if (vec[k] & 1) {
                res++;
            }
        }
        printf("%zu %zu %zu %s\n", res, pages, res * (size_t)ps, path);
        free(vec);
        munmap(p, len);
        close(fd);
    }
    return rc;
}
