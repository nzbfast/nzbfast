// member-cost.c - the per-MEMBER floor: what N output files cost, at
// fixed bytes, with nothing in it but the filesystem.
//
// The structural control for the many-small-member residue
// (research/MANYSMALL-PER-MEMBER-RESIDUE-2026-09-16.md). A 1 GiB stored
// set cut into 2,048 members costs 3.45x the instructions per byte of
// the same 1 GiB as one member, and the first question about that
// number is how much of it is OURS at all: 2,048 members means 2,048
// files, and creating, sizing, filling and closing a file is work the
// engine does not get to skip. This is that work and only that work -
// no NNTP, no yEnc, no RAR, no routing - in the shape the extractor
// writes it: one create + one ftruncate + one pwrite per article-sized
// chunk + one close per member, over `NT` threads.
//
//   cc -O2 -o mc member-cost.c
//   /usr/bin/time -l ./mc <members> <total bytes> <chunk> <dir> [threads] [fsync] [article] [stats]
//
// `article` NON-ZERO IS THE ARTICLE MODE, AND IT EXISTS BECAUSE THE
// CHUNK MODE ABOVE UNDERCOUNTS THE FLOOR. Read this before quoting any
// number from either arm.
//
// The 16 Sep round ran the chunk mode at two member counts with the
// chunk chosen so that BOTH arms issued 2,048 pwrites (512 members x
// 2 MiB / 512 KiB, against 2,048 members x 512 KiB / 512 KiB). Holding
// the call count fixed is what made the member axis clean - the
// difference is then one create + one ftruncate + one close per member
// and nothing else - and it measured 1.69 M instructions per member.
// But the engine does NOT hold that count fixed: cutting a
// fixed byte count into more members ADDS writes. At 1 GiB and 700 KB
// articles that is 1,534 pwrites as one member and ~3,581 as 2,048
// members - **+1.0 pwrite per member**, which the fixed-call-count
// floor charges to nobody. The round's own residue section says so as
// a stated limit; this mode is what closes it.
//
// THIS MODE IS A STATED SYSCALL MIX, NOT A CLAIM ABOUT TODAY'S ENGINE,
// and it must not be read as one. Since `0fe3e4138` (3 Sep 2026) the
// writer COALESCES per file - `NZBFAST_WRITE_COALESCE_KB` defaults to
// 4 MiB, measured -82.8% to -95.1% of positioned writes - so the engine
// issues far fewer calls than one per intersection. A 512 KiB member is
// far below that window and coalesces to about ONE write; a 1 GiB
// member to about 256. The per-member DELTA is therefore ~+0.875 rather
// than the +1.0 modelled here, which is close enough that the term
// still prices as free, and the error is in the safe direction (the
// engine writes less than this models). Count the real thing with
// `NZBFAST_WRITE_COALESCE_KB=0` against the default if you ever need it
// exactly.
//
// `stats` IS THE THIRD GAP, AND IT IS NOT A WRITE COST AT ALL. After
// every member is written the engine's post-download tail asks what
// each output file IS - `Rar!`, the 7-Zip signature, a zip local
// header, `ustar` - from a great many predicates, and since round 26 of
// research/RAR-PERF-AUDIT-2026-09-02.md those asks share one memo
// (`nzbkit_base::headpeek`) whose key is the file's IDENTITY. So the
// reads are gone and ONE `stat` per ask remains, about eighteen per
// output file. `stats` is that count: a second pass over the members
// issuing that many `stat`s each, after all the writing is done, which
// is the phase the engine runs it in. Zero (the default) leaves the
// tool measuring writes only, as it always did.
//
// So: `article` is the article size in bytes. Each member is written in
// the pieces its byte range is cut into by the GLOBAL article grid,
// which is the extractor's own write pattern, and the tool then models
// a whole shape rather than one axis of it. Run it once per shape at
// that shape's real member count and article size and difference the
// two; the chunk mode stays for the single-axis question it answers.
//
// `fsync` SELECTS THE DURABILITY ARM, and the three are not
// interchangeable: 0 none, 1 one plain `fsync(2)` per member, 2 one
// `fcntl(F_FULLFSYNC)` per member.
//
// Arm 1 is what the extractor's closing walk does (`sync_plain` over
// every inner writer, then ONE device barrier - see the comment at
// `Extractor`'s finish walk in crates/nzbkit/src/extract/mod.rs), and
// the 16 Sep round measured it free: 512 members 1.095 -> 1.103 G,
// 2,048 members 3.686 -> 3.750 G, inside the no-fsync arm's own 6-9%
// spread and the wrong sign in one pair.
//
// ARM 2 EXISTS BECAUSE ARM 1 IS NOT THE ONLY DURABILITY CALL THE
// ENGINE MAKES, AND READING ARM 1's "FREE" AS "DURABILITY IS FREE" IS
// THE MISTAKE THIS ARM PREVENTS. Rust's `File::sync_data` is
// `fcntl(F_FULLFSYNC)` on Apple platforms - a WHOLE-DEVICE barrier, not
// a file flush - and round 26 of research/RAR-PERF-AUDIT-2026-09-02.md
// records `Extractor::finish()` issuing one per writer, serially, under
// the `inner` lock. A plain `fsync` and a full barrier are different
// syscalls with different kernel work behind them, so arm 1 says
// nothing whatever about arm 2's cost. Price the call the engine
// actually makes, not the one with the similar name.
//
// READ `instructions retired` FROM `/usr/bin/time -l`, NOT THE WALL OR
// SYS THIS PRINTS. Same rule as pwrite-cost.c beside it and as every
// number in the residue round: on this fleet at 5 to 12x
// oversubscription wall and system time are the box's load, and only
// instructions are stable enough to difference. Run it at two member
// counts over the SAME total bytes and divide the instruction
// difference by the member difference; that quotient is the floor a
// fix cannot go below.
//
// Members are spread over the threads round-robin, so the create storm
// is as concurrent as the decoders' is. Each member is written
// front-to-back, which is the ordinary stored-set case; the engine's
// own writes can arrive out of order, and that costs APFS more, not
// less - so this stays a FLOOR either way.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/stat.h>

static long NMEM;
static uint64_t TOTAL, MSIZE;
static size_t CH;
static const char *DIR;
static int NT = 8;
static char *buf;
static int DOSYNC = 0;
static uint64_t ART = 0;
// The artefact pin for this tool: the call count it ACTUALLY issued.
// An article mode that silently degenerated to one write per member
// reports a perfectly good instruction number (memory topic
// nzbfast-absent-fault-passes-every-outcome-check), and the only way to
// see it is to count the calls and print them beside the result.
static uint64_t NWRITES = 0;
static int NSTAT = 0;

static void *worker(void *a) {
    long id = (long)a;
    char path[4096];
    for (long m = id; m < NMEM; m += NT) {
        snprintf(path, sizeof path, "%s/f%06ld.bin", DIR, m);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { perror("open"); exit(1); }
        if (ftruncate(fd, (off_t)MSIZE) != 0) { perror("ftruncate"); exit(1); }
        if (ART) {
            // Article mode: cut this member's byte range at the GLOBAL
            // article grid, so the call count is the (article x member)
            // intersection count the extractor actually issues. `base`
            // is the member's global offset; the first piece runs to
            // the next article boundary above it, which is why this
            // cannot be written as a fixed stride from zero.
            uint64_t base = (uint64_t)m * MSIZE;
            uint64_t off = 0;
            while (off < MSIZE) {
                uint64_t g = base + off;
                uint64_t nxt = (g / ART + 1) * ART;      // next article boundary
                uint64_t end = nxt - base;
                if (end > MSIZE) end = MSIZE;
                size_t len = (size_t)(end - off);
                if (len > CH) len = CH;                  // buffer bound
                if (pwrite(fd, buf, len, (off_t)off) != (ssize_t)len) { perror("pwrite"); exit(1); }
                __atomic_fetch_add(&NWRITES, 1, __ATOMIC_RELAXED);
                off += len;
            }
        } else {
            for (uint64_t off = 0; off < MSIZE; off += CH) {
                size_t len = (off + CH > MSIZE) ? (size_t)(MSIZE - off) : CH;
                if (pwrite(fd, buf, len, (off_t)off) != (ssize_t)len) { perror("pwrite"); exit(1); }
                __atomic_fetch_add(&NWRITES, 1, __ATOMIC_RELAXED);
            }
        }
        if (NSTAT) {
            // The tail's identity-key checks, in the phase they run in:
            // after the file exists and is written.
            struct stat st;
            for (int k = 0; k < NSTAT; k++) {
                if (stat(path, &st) != 0) { perror("stat"); exit(1); }
            }
        }
        if (DOSYNC == 1) {
            fsync(fd);
        } else if (DOSYNC == 2) {
            // What Rust's File::sync_data() lowers to on Apple platforms.
            if (fcntl(fd, F_FULLFSYNC, 0) < 0) { perror("F_FULLFSYNC"); exit(1); }
        }
        close(fd);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <members> <total bytes> <chunk> <dir> [threads] [fsync] [article]\n", argv[0]);
        return 2;
    }
    NMEM = atol(argv[1]);
    TOTAL = strtoull(argv[2], NULL, 10);
    CH = (size_t)strtoull(argv[3], NULL, 10);
    DIR = argv[4];
    if (argc > 5) NT = atoi(argv[5]);
    if (argc > 6) DOSYNC = atoi(argv[6]);
    if (argc > 7) ART = strtoull(argv[7], NULL, 10);
    if (argc > 8) NSTAT = atoi(argv[8]);
    MSIZE = TOTAL / (uint64_t)NMEM;
    buf = malloc(CH);
    if (!buf) return 1;
    memset(buf, 0xA5, CH);
    pthread_t t[64];
    if (NT > 64) NT = 64;
    for (long i = 0; i < NT; i++) pthread_create(&t[i], NULL, worker, (void *)i);
    for (long i = 0; i < NT; i++) pthread_join(t[i], NULL);
    printf("MC members=%ld total=%llu msize=%llu chunk=%zu threads=%d fsync=%d article=%llu writes=%llu stats/member=%d\n",
           NMEM, (unsigned long long)TOTAL, (unsigned long long)MSIZE, CH, NT, DOSYNC,
           (unsigned long long)ART, (unsigned long long)NWRITES, NSTAT);
    return 0;
}
