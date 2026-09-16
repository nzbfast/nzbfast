// memmove-cost.c - what a byte of copy COSTS in instructions retired on
// this box, so a counted byte total can be turned into a priced term.
//
// The sibling of member-cost.c, and the same idea: member-cost.c is the
// control that turns "the per-member cost is 4.75 M" into "and 1.64 M
// of it is not ours", and this is the control that turns "the engine
// copies N bytes on this shape and M on the control" into instructions.
// Written 16 Sep 2026 for the routing-lock round
// (research/ROUTING-LOCK-HOLD-2026-09-16.md), whose parent had located
// `_platform_memmove` at 12.8% of the live sample column on `manysmall`
// against 3.2% on the one-member control and left it UNPRICED, with the
// honest reason that no A/B arm separates a copy from the work around
// it without changing what the engine does.
//
// THE POINT OF THIS TOOL IS THAT A SAMPLER CANNOT PRICE A COPY AT ALL,
// and reading one as if it could is the trap the parent round's whole
// method exists to avoid. A wide `memcpy` retires very few instructions
// per byte and stalls on memory for a great many cycles, so its WALL
// share is large and its WORK share is small - the same split that made
// `stat` 13.2% of the live column and 3.8% of the work. Two SIMD loads
// and two stores move 64 bytes, so the per-byte instruction cost is of
// the order of 1/16, and a term that looks like an eighth of the
// profile can price out at well under a percent of the instructions.
// That is a finding about the site, not a disappointment about the
// tool.
//
//   cc -O2 -o mmc memmove-cost.c
//   /usr/bin/time -l ./mmc <iters> <len> <mode> [dstwin] [threads]
//
// Modes, both of which the engine really does and which price
// DIFFERENTLY - the second carries an allocator round trip per copy and
// the first does not:
//
//   win   memcpy into a long-lived destination window at a rolling
//         offset. This is `VolumeMapper::stash`, which copies the part
//         of every article that overlaps the 4 MiB parse window
//         (`MAX_WIN`) into it - `self.win[..].copy_from_slice(&data[..])`.
//   vec   malloc + memcpy + free per copy, which is `to_vec()` on a
//         span slice: the held-span sites in `extract_span_hits`, and
//         the header stash in `retain_header_bytes`.
//
// IT READS 2.4x HIGH AGAINST THE SAME COPIES IN SITU, SO TREAT EVERY
// NUMBER IT PRINTS AS AN UPPER BOUND. Measured 16 Sep 2026 on the dev
// Mac: this tool says 0.1879 instructions per byte at 700 KB and 0.1882
// at 64 KB, with a 0.1% spread either way; the engine's own copies,
// priced by moving `VolumeMapper`'s parse window from 4 MiB to 256 KiB
// over eight alternating rounds with a null control, come out at
// 0.068-0.085. The in-situ figure is also the one close to what a
// 64-bytes-per-four-instructions SIMD copy implies (0.0625) and this
// tool's is not, so the likeliest reading is that the rolling
// destination offset and the anti-dead-store checksum below are a third
// of what this measures at these sizes - i.e. the tool's own loop, not
// the copy. Nobody has run that down. WHERE THE TWO DISAGREE, THE
// IN-SITU ARM WINS: it measures the real copies in the real program and
// it has a control. Use this tool to bound a term and to decide whether
// one is worth an arm at all, never to quote a price.
//   research/ROUTING-LOCK-HOLD-2026-09-16.md, sections 2 and "Follow-ups".
//
// READ IT AS A TWO-POINT DIFFERENCE, NEVER AS ONE ABSOLUTE. Run the
// same mode at `iters` and `2*iters` and divide the difference by the
// extra bytes: process start-up, the page faults that first touch the
// buffers, and this tool's own loop overhead are all in the absolute
// and all cancel in the difference. `member-cost.c` is read the same
// way and for the same reason.
//
// TWO TRAPS, BOTH MET ON 16 SEP 2026 AND BOTH IN THE TOOL NOW:
//
//  1. A destination the compiler can prove is dead is a copy that does
//     not happen. `-O2` will delete the whole loop. Every arm therefore
//     folds one byte of the destination into a checksum that is
//     PRINTED, which is a data dependency the optimiser cannot remove,
//     and the source buffer is filled from the checksum so no arm can
//     be hoisted out of the loop either.
//  2. First touch of a fresh mapping is a page fault, not a copy, and
//     zero-fill faults read at the top of a profile as `memmove` (the
//     memory topic is nzbfast-memmove-at-the-top-is-often-page-faults).
//     Both buffers are touched once before the timed loop, and `vec`
//     mode's malloc/free pair is deliberately inside it because the
//     allocator round trip is part of what `to_vec()` costs.
//
// `dstwin` is the destination window size in bytes (default 4 MiB, the
// mapper's `MAX_WIN`); the rolling offset wraps inside it, which is
// what makes the destination cache-resident exactly as the parse
// window is. `threads` defaults to 1: this is a per-byte RATE, and the
// engine's copies run on eight decode threads, so a multi-thread arm
// measures memory bandwidth rather than the rate this tool is for.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static size_t ITERS, LEN, DSTWIN;
static int MODE_VEC;
static unsigned char *SRC;

static void *run(void *arg) {
    (void)arg;
    unsigned char *dst = MODE_VEC ? NULL : malloc(DSTWIN);
    if (!MODE_VEC) memset(dst, 1, DSTWIN);
    unsigned long sum = 0;
    size_t off = 0;
    for (size_t i = 0; i < ITERS; i++) {
        // The data dependency that keeps the copy alive under -O2.
        SRC[i % 64] = (unsigned char)sum;
        if (MODE_VEC) {
            unsigned char *p = malloc(LEN);
            memcpy(p, SRC, LEN);
            sum += p[LEN - 1] + p[0];
            free(p);
        } else {
            if (off + LEN > DSTWIN) off = 0;
            memcpy(dst + off, SRC, LEN);
            sum += dst[off] + dst[off + LEN - 1];
            off += LEN;
        }
    }
    if (dst) free(dst);
    return (void *)sum;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <iters> <len> <win|vec> [dstwin] [threads]\n", argv[0]);
        return 2;
    }
    ITERS = strtoull(argv[1], 0, 10);
    LEN = strtoull(argv[2], 0, 10);
    MODE_VEC = strcmp(argv[3], "vec") == 0;
    DSTWIN = argc > 4 ? strtoull(argv[4], 0, 10) : (4ull << 20);
    int nt = argc > 5 ? atoi(argv[5]) : 1;
    if (!MODE_VEC && LEN > DSTWIN) { fprintf(stderr, "len > dstwin\n"); return 2; }
    SRC = malloc(LEN);
    memset(SRC, 7, LEN);
    pthread_t t[64];
    unsigned long total = 0;
    for (int i = 0; i < nt; i++) pthread_create(&t[i], 0, run, 0);
    for (int i = 0; i < nt; i++) { void *r; pthread_join(t[i], &r); total += (unsigned long)r; }
    // The artefact pin: bytes actually copied, and the checksum that
    // proves the loop ran. A leg that quietly did nothing prints zero
    // here rather than a well-formed instruction count with no work
    // behind it.
    printf("MMC mode=%s iters=%zu len=%zu threads=%d bytes=%llu sum=%lu\n",
           MODE_VEC ? "vec" : "win", ITERS, LEN, nt,
           (unsigned long long)ITERS * LEN * nt, total);
    return 0;
}
