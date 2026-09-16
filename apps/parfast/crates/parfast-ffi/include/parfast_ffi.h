#ifndef PARFAST_FFI_H
#define PARFAST_FFI_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * 0. Every function that answers an `int` answers this on success.
 */
#define PF_OK 0

/**
 * A null or non-UTF-8 argument where a string was required.
 */
#define PF_ERR_ARG -1

/**
 * JSON that did not parse, or did not carry the shape asked for.
 */
#define PF_ERR_JSON -2

/**
 * A job id nothing answers, or a state change the job's state
 * forbids (removing one that is still running).
 */
#define PF_ERR_NOT_FOUND -3

/**
 * The operation is understood and was refused - a plan over sources
 * that are not there, a post-queue action that is not one of the four.
 */
#define PF_ERR_REFUSED -4

/**
 * The opaque session handle. One per app, normally.
 *
 * `pf_`-prefixed snake_case is the C convention this whole header is
 * written in, and the name is part of the published ABI - two UI
 * lanes are compiling against `pf_session` right now - so Rust's
 * camel-case style is waived here and nowhere else in the crate.
 */
typedef struct pf_session pf_session;

/**
 * The host's wake function: no arguments but its own context, no
 * return, any thread. See the module docs.
 *
 * NULLABLE, and spelled as an `Option` for that reason: passing NULL
 * is how a host REMOVES its wake, which it must be able to do before
 * the context it registered goes away. The `Option<extern "C" fn>`
 * spelling is the one that is ABI-identical to a plain C function
 * pointer, so the header declares exactly `void (*)(void *)`.
 *
 * The snake_case name is the published ABI's - see [`pf_session`].
 */
typedef void (*pf_wake_fn)(void *ctx);

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Create a session. `settings_json` may be NULL for the defaults.
 *
 * # Safety
 * `settings_json` is null or a NUL-terminated UTF-8 C string.
 */
struct pf_session *pf_session_new(const char *settings_json);

/**
 * Free a session. Cancels every job it holds and waits for none of
 * them: a worker sees the cancel at its next honouring point.
 *
 * # Safety
 * `s` is null, or a pointer from [`pf_session_new`] that has not
 * already been freed, and no other thread is inside any `pf_*` call
 * on it.
 */
void pf_session_free(struct pf_session *s);

/**
 * Install the wake callback. Pass a NULL `f` to remove it.
 *
 * # Safety
 * `s` is a live session. `f`, if non-null, is a valid function
 * pointer, and `ctx` stays valid until the wake is replaced or the
 * session is freed. `f` may be called from any thread.
 */
void pf_session_set_wake(struct pf_session *s, pf_wake_fn f, void *ctx);

/**
 * Submit a job. Answers its id, or a negative code.
 *
 * # Safety
 * `s` is a live session and `spec_json` a NUL-terminated UTF-8 string.
 */
int64_t pf_job_submit(struct pf_session *s, const char *spec_json);

/**
 * One job's snapshot as JSON, or NULL for an id nothing answers.
 *
 * # Safety
 * `s` is a live session. The result is the caller's and is released
 * with [`pf_string_free`].
 */
char *pf_job_snapshot(struct pf_session *s, int64_t id);

/**
 * The whole queue as JSON.
 *
 * # Safety
 * `s` is a live session; the result is released with
 * [`pf_string_free`].
 */
char *pf_queue_snapshot(struct pf_session *s);

/**
 * Cancel a job. A queued job stops at once; a running one at its next
 * honouring point - see `parfast_session::runner` for what each kind
 * can actually reach.
 *
 * # Safety
 * `s` is a live session.
 */
int32_t pf_job_cancel(struct pf_session *s, int64_t id);

/**
 * Pause a job. A verify, a repair and the two checksum kinds park; a
 * create runs on. `pf_capabilities.pause_in_fold` is what a host reads
 * before offering the button on a repair, and it has been true since
 * 12 Sep 2026 - with one stated exception, the solve, which is seconds
 * on a structured repair. See that key's comment.
 *
 * # Safety
 * `s` is a live session.
 */
int32_t pf_job_pause(struct pf_session *s, int64_t id);

/**
 * Resume a paused job.
 *
 * # Safety
 * `s` is a live session.
 */
int32_t pf_job_resume(struct pf_session *s, int64_t id);

/**
 * Remove a FINISHED job from the table. A running or queued one is
 * refused: a host that wants it gone cancels it first, and a remove
 * that silently cancelled would lose work on a misclick.
 *
 * # Safety
 * `s` is a live session.
 */
int32_t pf_job_remove(struct pf_session *s, int64_t id);

/**
 * Section 5.5's "Run now": take this QUEUED job before anything else
 * waiting, whatever its id.
 *
 * It does not interrupt what is running and it does not raise the
 * concurrency - on a serial queue the effect is that this job is the
 * next one started. Refused (`PF_ERR_NOT_FOUND`) for a job that is
 * already running or finished: there is nothing to bring forward.
 *
 * An ADDITION beyond plan 4.5, asked for by the Windows lane on
 * 12 Sep 2026. Raising the concurrency to start one job starts every
 * job queued ahead of it too, and resuming the selected job only lets
 * the scheduler reach it in its own turn; neither is "run this now".
 *
 * # Safety
 * `s` is a live session.
 */
int32_t pf_job_run_next(struct pf_session *s, int64_t id);

/**
 * Mark a job low priority. Advisory: it is reported in the snapshot
 * for the host to act on, and nothing in the engine reads it.
 *
 * # Safety
 * `s` is a live session.
 */
int32_t pf_job_set_low_priority(struct pf_session *s, int64_t id, bool on);

/**
 * Pause or resume the QUEUE: a paused queue starts nothing new and
 * leaves what is running alone.
 *
 * # Safety
 * `s` is a live session.
 */
int32_t pf_queue_set_paused(struct pf_session *s, bool paused);

/**
 * How many jobs may run at once. Clamped to at least 1.
 *
 * # Safety
 * `s` is a live session.
 */
int32_t pf_queue_set_concurrency(struct pf_session *s, uint32_t n);

/**
 * What to do when the queue drains: `none`, `notify`, `sleep` or
 * `shutdown`. The session REPORTS it (`post_action_due` in the queue
 * snapshot); the host performs it.
 *
 * # Safety
 * `s` is a live session and `action` a NUL-terminated UTF-8 string.
 */
int32_t pf_queue_set_post_action(struct pf_session *s, const char *action);

/**
 * Tell the session the post-queue action has been dealt with, so it
 * does not fall due again for this drain.
 *
 * # Safety
 * `s` is a live session.
 */
int32_t pf_queue_clear_post_action(struct pf_session *s);

/**
 * Persist the queue to `path` and load whatever is already there.
 * Answers the number of jobs loaded, or a negative code.
 *
 * # Safety
 * `s` is a live session and `path` a NUL-terminated UTF-8 string.
 */
int32_t pf_queue_open_store(struct pf_session *s, const char *path);

/**
 * The create preview for a spec: block size and count, padding,
 * efficiency, the files that would be written, and the equivalent
 * command line. Reads no source byte beyond `stat`.
 *
 * # Safety
 * `s` is a live session and `create_spec_json` a NUL-terminated UTF-8
 * string; the result is released with [`pf_string_free`].
 */
char *pf_plan_preview(struct pf_session *s, const char *create_spec_json);

/**
 * What this build can actually do. A host HIDES any control whose
 * capability is false; that is how the two app lanes stay correct
 * whatever the engine turns out to support on the day they ship.
 *
 * # Safety
 * `s` may be null. The result is released with [`pf_string_free`].
 */
char *pf_capabilities(struct pf_session *_s);

/**
 * The settings object, with every default filled in.
 *
 * # Safety
 * `s` is a live session; the result is released with
 * [`pf_string_free`].
 */
char *pf_settings_get(struct pf_session *s);

/**
 * Replace the settings. Keys left out take their defaults, and
 * unknown keys are ignored - see `parfast_session::settings`.
 *
 * # Safety
 * `s` is a live session and `settings_json` a NUL-terminated UTF-8
 * string.
 */
int32_t pf_settings_set(struct pf_session *s, const char *settings_json);

/**
 * "Clear remembered checksums": delete every record in the per-user
 * digest store that `performance.digest_cache` fills. Answers how many
 * files went (0 where there is no store), or `PF_ERR_REFUSED` with the
 * folder and the reason in [`pf_last_error`]. Safe while a job runs.
 *
 * # Safety
 * `s` is a live session.
 */
int32_t pf_digest_cache_clear(struct pf_session *s);

/**
 * `{"code":"...","message":"..."}` for the last failure on this
 * session, or `{}`. Reading it does not clear it; the next failure
 * replaces it.
 *
 * # Safety
 * `s` is a live session; the result is released with
 * [`pf_string_free`].
 */
char *pf_last_error(struct pf_session *s);

/**
 * Release a string this library returned. NULL is accepted and does
 * nothing.
 *
 * # Safety
 * `p` is null, or a pointer THIS library returned that has not
 * already been freed. A pointer from any other allocator is undefined
 * behaviour - it is reclaimed as a `CString`.
 */
void pf_string_free(char *p);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* PARFAST_FFI_H */
