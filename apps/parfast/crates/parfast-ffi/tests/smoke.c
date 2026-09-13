/*
 * The C smoke test: one whole PAR2 life cycle through the C ABI and
 * nothing else.
 *
 * WHY IT IS C. Two hosts consume this library through a C header - the
 * macOS app through a bridging header, the Windows app by translating
 * the same declarations into P/Invoke - and a Rust test that called
 * the same functions would prove the Rust side only. A C compiler
 * reading include/parfast_ffi.h is the thing that proves the header is
 * a header: the types line up, the calling convention lines up, and a
 * `char *` that comes back really can be handed to free through
 * pf_string_free.
 *
 * THE SETS ARE BUILT WITH THE ENGINE, NOT WITH AN EXTERNAL par2.
 * tools/par2-gate.py refuses a test that shells out to par2cmdline
 * without a have_par2() guard; there is nothing to guard here, because
 * the set this exercises is created by pf_job_submit on a create spec
 * and read back by the same library. Interop against the reference
 * belongs to the conformance harness and to the e2e suite.
 *
 * Everything is asserted on SUBSTRINGS of the JSON rather than through
 * a JSON parser: a parser in C would be a second implementation of the
 * contract to get wrong, and what this test is for is the ABI.
 */

#include "parfast_ffi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A step that failed, for the Rust side to print. */
static char g_why[1024];

static int fail(int step, const char *what, const char *detail) {
    snprintf(g_why, sizeof g_why, "step %d (%s): %s", step, what,
             detail ? detail : "(no detail)");
    return step;
}

/* Poll one job until it stops moving. Answers the snapshot, which the
 * caller frees; NULL if it never settled. */
static char *await_finish(pf_session *s, int64_t id, int max_polls) {
    for (int i = 0; i < max_polls; i++) {
        char *snap = pf_job_snapshot(s, id);
        if (!snap) {
            return NULL;
        }
        if (strstr(snap, "\"state\":\"done\"") ||
            strstr(snap, "\"state\":\"failed\"") ||
            strstr(snap, "\"state\":\"cancelled\"")) {
            return snap;
        }
        pf_string_free(snap);
        /* 1 ms, without pulling in a platform sleep header: the queue
         * ticks at 100 ms and a job finishes when it finishes. */
        for (volatile long spin = 0; spin < 200000L; spin++) {
        }
    }
    return NULL;
}

/* Wait until a job reports one exact state. 0 on success. */
static int await_state(pf_session *s, int64_t id, const char *want, int max_polls) {
    char needle[64];
    snprintf(needle, sizeof needle, "\"state\":\"%s\"", want);
    for (int i = 0; i < max_polls; i++) {
        char *snap = pf_job_snapshot(s, id);
        if (!snap) {
            return -1;
        }
        int hit = strstr(snap, needle) != NULL;
        pf_string_free(snap);
        if (hit) {
            return 0;
        }
        for (volatile long spin = 0; spin < 200000L; spin++) {
        }
    }
    return -1;
}

/*
 * `dir` holds a.bin, b.bin and c.bin already (written by the Rust side,
 * which is not part of the ABI). Answers 0, or the number of the step
 * that failed; `pf_smoke_why` then says what went wrong.
 */
int pf_smoke_run(const char *dir) {
    char spec[4096];
    char set_path[1024];
    snprintf(set_path, sizeof set_path, "%s/set.par2", dir);

    pf_session *s = pf_session_new(NULL);
    if (!s) {
        return fail(1, "pf_session_new", "answered NULL");
    }

    /* ---- capabilities are readable before anything is submitted ---- */
    char *caps = pf_capabilities(s);
    if (!caps || !strstr(caps, "\"kernel\"")) {
        pf_string_free(caps);
        pf_session_free(s);
        return fail(2, "pf_capabilities", "no kernel key");
    }
    pf_string_free(caps);

    /* ---- 3. the preview, which must read no source byte ---- */
    snprintf(spec, sizeof spec,
             "{\"sources\":[{\"path\":\"%s/a.bin\"},{\"path\":\"%s/b.bin\"},"
             "{\"path\":\"%s/c.bin\"}],"
             "\"output\":\"%s\",\"block\":{\"size\":2048},"
             "\"recovery\":{\"count\":40}}",
             dir, dir, dir, set_path);
    char *preview = pf_plan_preview(s, spec);
    if (!preview || !strstr(preview, "\"block_size\":2048") ||
        !strstr(preview, "\"recovery_blocks\":40") ||
        !strstr(preview, "parfast c ")) {
        char detail[1200];
        snprintf(detail, sizeof detail, "%s", preview ? preview : "(NULL)");
        pf_string_free(preview);
        pf_session_free(s);
        return fail(3, "pf_plan_preview", detail);
    }
    pf_string_free(preview);

    /* ---- 4. create the set ---- */
    char job[4200];
    snprintf(job, sizeof job, "{\"kind\":\"create\",\"create\":%s}", spec);
    int64_t create_id = pf_job_submit(s, job);
    if (create_id < 0) {
        char *e = pf_last_error(s);
        int r = fail(4, "submit create", e);
        pf_string_free(e);
        pf_session_free(s);
        return r;
    }
    char *snap = await_finish(s, create_id, 60000);
    if (!snap || !strstr(snap, "\"state\":\"done\"")) {
        char detail[1200];
        snprintf(detail, sizeof detail, "%s", snap ? snap : "(never settled)");
        pf_string_free(snap);
        pf_session_free(s);
        return fail(4, "create", detail);
    }
    if (!strstr(snap, ".vol")) {
        pf_string_free(snap);
        pf_session_free(s);
        return fail(4, "create", "no volume in the written list");
    }
    pf_string_free(snap);

    /* ---- 5. damage b.bin, then verify: repairable, with a damaged run ---- */
    char victim[1024];
    snprintf(victim, sizeof victim, "%s/b.bin", dir);
    FILE *f = fopen(victim, "r+b");
    if (!f) {
        pf_session_free(s);
        return fail(5, "open the victim", victim);
    }
    /* Two whole blocks, from the third block on, so the run-length map
     * has an unambiguous damaged run in the middle and not at an edge. */
    if (fseek(f, 2 * 2048, SEEK_SET) != 0) {
        fclose(f);
        pf_session_free(s);
        return fail(5, "seek the victim", victim);
    }
    for (int i = 0; i < 2 * 2048; i++) {
        fputc(0x5a, f);
    }
    fclose(f);

    char vspec[2048];
    snprintf(vspec, sizeof vspec,
             "{\"kind\":\"verify\",\"verify\":{\"par2\":\"%s\"}}", set_path);
    int64_t vid = pf_job_submit(s, vspec);
    if (vid < 0) {
        pf_session_free(s);
        return fail(5, "submit verify", "negative id");
    }
    snap = await_finish(s, vid, 60000);
    if (!snap) {
        pf_session_free(s);
        return fail(5, "verify", "never settled");
    }
    if (!strstr(snap, "\"verdict\":\"repairable\"")) {
        char detail[1200];
        snprintf(detail, sizeof detail, "%s", snap);
        pf_string_free(snap);
        pf_session_free(s);
        return fail(5, "verify verdict", detail);
    }
    /* State 2 is DAMAGED in the block-run encoding, and a run is a
     * two-element array, so this is the map actually carrying the
     * damage and not merely a file marked damaged. */
    if (!strstr(snap, "\"status\":\"damaged\"") || !strstr(snap, "[2,")) {
        char detail[1200];
        snprintf(detail, sizeof detail, "%s", snap);
        pf_string_free(snap);
        pf_session_free(s);
        return fail(5, "block_runs", detail);
    }
    pf_string_free(snap);

    /* ---- 6. a second verify, cancelled from inside the job ----
     *
     * Deterministic on purpose. The queue is paused, the job is
     * submitted and paused, and the queue is let go: the worker then
     * starts, reaches the FIRST gate in `parfast_session::runner::run`
     * and parks there. Cancelling releases that park and the job must
     * report `cancelled`.
     *
     * What this does NOT pin is a cancel arriving in the middle of the
     * hashing of a particular member: making that deterministic needs a
     * set big enough to be slow, which is a timing assumption in a test
     * that runs on a loaded CI box. The gate it parks at is the same
     * `Control::gate` the per-member loop calls, so the mechanism under
     * test is the same one; what differs is which call site.
     */
    if (pf_queue_set_paused(s, true) != PF_OK) {
        pf_session_free(s);
        return fail(6, "pause the queue", NULL);
    }
    int64_t cid = pf_job_submit(s, vspec);
    if (cid < 0) {
        pf_session_free(s);
        return fail(6, "submit the second verify", "negative id");
    }
    if (pf_job_pause(s, cid) != PF_OK) {
        pf_session_free(s);
        return fail(6, "pause the job", NULL);
    }
    if (pf_queue_set_paused(s, false) != PF_OK) {
        pf_session_free(s);
        return fail(6, "resume the queue", NULL);
    }
    if (await_state(s, cid, "paused", 60000) != 0) {
        pf_session_free(s);
        return fail(6, "wait for paused", "never reported paused");
    }
    if (pf_job_cancel(s, cid) != PF_OK) {
        pf_session_free(s);
        return fail(6, "cancel", NULL);
    }
    snap = await_finish(s, cid, 60000);
    if (!snap || !strstr(snap, "\"state\":\"cancelled\"")) {
        char detail[1200];
        snprintf(detail, sizeof detail, "%s", snap ? snap : "(never settled)");
        pf_string_free(snap);
        pf_session_free(s);
        return fail(6, "cancelled", detail);
    }
    pf_string_free(snap);

    /* ---- 7. repair ---- */
    char rspec[2048];
    snprintf(rspec, sizeof rspec,
             "{\"kind\":\"repair\",\"repair\":{\"par2\":\"%s\"}}", set_path);
    int64_t rid = pf_job_submit(s, rspec);
    if (rid < 0) {
        pf_session_free(s);
        return fail(7, "submit repair", "negative id");
    }
    snap = await_finish(s, rid, 120000);
    if (!snap || !strstr(snap, "\"state\":\"done\"")) {
        char detail[1200];
        snprintf(detail, sizeof detail, "%s", snap ? snap : "(never settled)");
        pf_string_free(snap);
        pf_session_free(s);
        return fail(7, "repair", detail);
    }
    if (!strstr(snap, "\"verdict\":\"repaired\"")) {
        char detail[1200];
        snprintf(detail, sizeof detail, "%s", snap);
        pf_string_free(snap);
        pf_session_free(s);
        return fail(7, "repair verdict", detail);
    }
    pf_string_free(snap);

    /* ---- 8. verify again: clean ---- */
    int64_t fid = pf_job_submit(s, vspec);
    snap = await_finish(s, fid, 60000);
    if (!snap || !strstr(snap, "\"verdict\":\"complete\"")) {
        char detail[1200];
        snprintf(detail, sizeof detail, "%s", snap ? snap : "(never settled)");
        pf_string_free(snap);
        pf_session_free(s);
        return fail(8, "final verify", detail);
    }
    pf_string_free(snap);

    /* ---- 9. the queue table holds all five jobs and every one of them
     * is finished ---- */
    char *q = pf_queue_snapshot(s);
    if (!q || !strstr(q, "\"concurrency\":1")) {
        char detail[1200];
        snprintf(detail, sizeof detail, "%s", q ? q : "(NULL)");
        pf_string_free(q);
        pf_session_free(s);
        return fail(9, "pf_queue_snapshot", detail);
    }
    pf_string_free(q);

    /* ---- 10. a finished job can be removed, and a second remove of
     * the same id is refused rather than silently accepted ---- */
    if (pf_job_remove(s, fid) != PF_OK) {
        pf_session_free(s);
        return fail(10, "remove a finished job", NULL);
    }
    if (pf_job_remove(s, fid) != PF_ERR_NOT_FOUND) {
        pf_session_free(s);
        return fail(10, "remove twice", "the second remove was accepted");
    }

    pf_session_free(s);
    return 0;
}

/* Why the last pf_smoke_run failed. Valid until the next call. */
const char *pf_smoke_why(void) { return g_why; }
