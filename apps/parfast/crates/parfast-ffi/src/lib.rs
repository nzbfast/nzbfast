//! C ABI over [`parfast_session`], for the two parfast desktop apps.
//!
//! The contract is `research/PLAN-PARFAST-GUI-2026-09-12.md` section
//! 4.5 and `API.md` beside this file; the header
//! `include/parfast_ffi.h` is generated from THIS file by cbindgen and
//! committed, and `tests/header.rs` fails if regenerating it would
//! produce different bytes. So a signature change is a diff a reviewer
//! reads, which is the property the hand-written `nzbfast-ffi` header
//! was kept for.
//!
//! # The five rules, all of them enforced below
//!
//! 1. **JSON in, JSON out.** Every rich value crosses as a UTF-8 JSON
//!    object. A C struct per shape would mean a header edit, a Swift
//!    edit and a C# edit per field, three times a week, forever.
//! 2. **Every returned `char *` is the CALLER's** and is released with
//!    [`pf_string_free`]. Nothing else frees one, and a pointer from
//!    any other allocator must never be passed to it.
//! 3. **Every `int` is 0 on success and negative otherwise**, with
//!    [`pf_last_error`] holding `{code,message}` for the last failure
//!    on THIS session.
//! 4. **The session is thread-safe** and every function may be called
//!    from any thread.
//! 5. **The wake callback carries no data and may fire on any
//!    thread.** The host marshals to its UI thread and then polls. That
//!    one rule is what keeps both UIs free of cross-thread hazards, and
//!    it is why no callback here takes a payload.
//!
//! # Why the handle is opaque
//!
//! A `pf_session *` is a `Box<Session>` and nothing else. The host
//! cannot see a field, so no field can be read at the wrong moment or
//! written from the wrong thread, and the Rust side can change every
//! one of them without moving a byte in either app.

use std::ffi::{CStr, CString, c_char};
use std::sync::{Arc, Mutex};

use parfast_session::job::JobSpec;
use parfast_session::planner;
use parfast_session::queue::Session;
use parfast_session::settings::{PostQueueAction, Settings};

/// The opaque session handle. One per app, normally.
///
/// `pf_`-prefixed snake_case is the C convention this whole header is
/// written in, and the name is part of the published ABI - two UI
/// lanes are compiling against `pf_session` right now - so Rust's
/// camel-case style is waived here and nowhere else in the crate.
#[allow(non_camel_case_types)]
pub struct pf_session {
    session: Session,
    last_error: Mutex<Option<(String, String)>>,
}

/// The host's wake function: no arguments but its own context, no
/// return, any thread. See the module docs.
///
/// NULLABLE, and spelled as an `Option` for that reason: passing NULL
/// is how a host REMOVES its wake, which it must be able to do before
/// the context it registered goes away. The `Option<extern "C" fn>`
/// spelling is the one that is ABI-identical to a plain C function
/// pointer, so the header declares exactly `void (*)(void *)`.
///
/// The snake_case name is the published ABI's - see [`pf_session`].
#[allow(non_camel_case_types)]
pub type pf_wake_fn = Option<extern "C" fn(ctx: *mut std::ffi::c_void)>;

/// 0. Every function that answers an `int` answers this on success.
pub const PF_OK: i32 = 0;
/// A null or non-UTF-8 argument where a string was required.
pub const PF_ERR_ARG: i32 = -1;
/// JSON that did not parse, or did not carry the shape asked for.
pub const PF_ERR_JSON: i32 = -2;
/// A job id nothing answers, or a state change the job's state
/// forbids (removing one that is still running).
pub const PF_ERR_NOT_FOUND: i32 = -3;
/// The operation is understood and was refused - a plan over sources
/// that are not there, a post-queue action that is not one of the four.
pub const PF_ERR_REFUSED: i32 = -4;

/// The context pointer a host hands [`pf_session_set_wake`].
///
/// The host promises it stays valid until the wake is replaced or the
/// session is freed; that promise is in the header and is the ONLY
/// thing that makes sending it between threads sound.
struct WakeCtx(*mut std::ffi::c_void);

// SAFETY: the pointer is opaque to this crate - it is never read,
// written or dereferenced here, only handed back to the host's own
// callback. The host's contract (stated in the header) is that it
// remains valid and is safe to use from any thread until the wake is
// replaced or the session freed, which is exactly the obligation
// `Send`/`Sync` name.
unsafe impl Send for WakeCtx {}
// SAFETY: as above - shared access is handing an opaque value back to
// its owner, which reads no memory this crate owns.
unsafe impl Sync for WakeCtx {}

impl WakeCtx {
    /// The pointer, through a METHOD rather than a field read.
    ///
    /// Edition 2024 closures capture disjoint FIELDS, so a closure
    /// spelling `ctx.0` captures the raw pointer itself - which is
    /// neither `Send` nor `Sync` however the wrapper is marked, and the
    /// `unsafe impl`s above would then be decorating a type nothing
    /// captures. Going through a method captures the whole `WakeCtx`,
    /// which is the thing those impls are about.
    fn ptr(&self) -> *mut std::ffi::c_void {
        self.0
    }
}

impl pf_session {
    fn fail(&self, code: &str, message: impl Into<String>) {
        *self.last_error.lock().unwrap_or_else(|p| p.into_inner()) =
            Some((code.to_string(), message.into()));
    }
}

/// Borrow a session handle, or answer `None` for a null one.
///
/// # Safety
/// `s` is either null or a pointer [`pf_session_new`] returned and
/// [`pf_session_free`] has not been called on.
unsafe fn borrow<'a>(s: *mut pf_session) -> Option<&'a pf_session> {
    // SAFETY: the caller's obligation above is exactly that `s` is null
    // or a live `Box<pf_session>` pointer; a live one is valid,
    // aligned, and outlives this borrow because only `pf_session_free`
    // can end it and the caller promises it has not run.
    unsafe { s.as_ref() }
}

/// A borrowed C string, or `None` for null or non-UTF-8.
///
/// # Safety
/// `p` is either null or a pointer to a NUL-terminated C string that
/// stays valid for this call.
unsafe fn str_of<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller's obligation is that `p` is a live
    // NUL-terminated string for the duration of the call, which is
    // `CStr::from_ptr`'s whole precondition.
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

/// A Rust string as a `char *` the caller owns.
fn out(s: String) -> *mut c_char {
    // A NUL inside would truncate the JSON silently, so it is replaced
    // rather than refused: every producer here is serde, which cannot
    // emit one, and a refusal would turn an impossible case into a
    // crash-on-null in two hosts.
    CString::new(s.replace('\0', "\u{fffd}"))
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Create a session. `settings_json` may be NULL for the defaults.
///
/// # Safety
/// `settings_json` is null or a NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_session_new(settings_json: *const c_char) -> *mut pf_session {
    // SAFETY: the caller's obligation on `settings_json` is `str_of`'s.
    let settings = match unsafe { str_of(settings_json) } {
        None => None,
        // A settings object that does not parse is NOT a refusal to
        // start: the app would have no way to show the error, and a
        // corrupt preferences file must not be an app that will not
        // launch. The defaults are used instead.
        Some(text) => Settings::from_json(text).ok(),
    };
    let handle = Box::new(pf_session {
        session: Session::new(settings),
        last_error: Mutex::new(None),
    });
    // SAFETY note for readers: this is a plain leak of a Box, undone by
    // `pf_session_free`. No `unsafe` is needed for it.
    Box::into_raw(handle)
}

/// Free a session. Cancels every job it holds and waits for none of
/// them: a worker sees the cancel at its next honouring point.
///
/// # Safety
/// `s` is null, or a pointer from [`pf_session_new`] that has not
/// already been freed, and no other thread is inside any `pf_*` call
/// on it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_session_free(s: *mut pf_session) {
    if s.is_null() {
        return;
    }
    // SAFETY: the caller promises `s` came from `Box::into_raw` in
    // `pf_session_new`, has not been freed, and that no other thread is
    // using it - which is what makes reclaiming the Box sound.
    drop(unsafe { Box::from_raw(s) });
}

/// Install the wake callback. Pass a NULL `f` to remove it.
///
/// # Safety
/// `s` is a live session. `f`, if non-null, is a valid function
/// pointer, and `ctx` stays valid until the wake is replaced or the
/// session is freed. `f` may be called from any thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_session_set_wake(
    s: *mut pf_session,
    f: pf_wake_fn,
    ctx: *mut std::ffi::c_void,
) {
    // SAFETY: `borrow`'s obligation is the caller's above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return;
    };
    match f {
        None => h.session.set_wake(None),
        Some(f) => {
            let ctx = WakeCtx(ctx);
            h.session.set_wake(Some(Arc::new(move || {
                f(ctx.ptr());
            })));
        }
    }
}

/// Submit a job. Answers its id, or a negative code.
///
/// # Safety
/// `s` is a live session and `spec_json` a NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_job_submit(s: *mut pf_session, spec_json: *const c_char) -> i64 {
    // SAFETY: both obligations are the caller's above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return i64::from(PF_ERR_ARG);
    };
    // SAFETY: as above.
    let Some(text) = (unsafe { str_of(spec_json) }) else {
        h.fail("arg", "spec_json was null or not UTF-8");
        return i64::from(PF_ERR_ARG);
    };
    match serde_json::from_str::<JobSpec>(text) {
        Ok(spec) => h.session.submit(spec),
        Err(e) => {
            h.fail("json", e.to_string());
            i64::from(PF_ERR_JSON)
        }
    }
}

/// One job's snapshot as JSON, or NULL for an id nothing answers.
///
/// # Safety
/// `s` is a live session. The result is the caller's and is released
/// with [`pf_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_job_snapshot(s: *mut pf_session, id: i64) -> *mut c_char {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return std::ptr::null_mut();
    };
    match h.session.job(id) {
        Some(j) => out(serde_json::to_string(&j).unwrap_or_else(|_| "{}".to_string())),
        None => {
            h.fail("not_found", format!("no job {id}"));
            std::ptr::null_mut()
        }
    }
}

/// The whole queue as JSON.
///
/// # Safety
/// `s` is a live session; the result is released with
/// [`pf_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_queue_snapshot(s: *mut pf_session) -> *mut c_char {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return std::ptr::null_mut();
    };
    out(serde_json::to_string(&h.session.snapshot()).unwrap_or_else(|_| "{}".to_string()))
}

// The four id-taking calls are written out LONGHAND and not behind a
// macro, deliberately: cbindgen does not expand macros (it parses
// source, it does not run `cargo expand`), so a macro here produces a
// header that silently omits these four - which is a library two apps
// link against and cannot call half of. `tests/header.rs` asserts
// every name in the contract is present for exactly that reason.

/// Cancel a job. A queued job stops at once; a running one at its next
/// honouring point - see `parfast_session::runner` for what each kind
/// can actually reach.
///
/// # Safety
/// `s` is a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_job_cancel(s: *mut pf_session, id: i64) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    answer(h, id, h.session.cancel(id))
}

/// Pause a job. A verify, a repair and the two checksum kinds park; a
/// create runs on. `pf_capabilities.pause_in_fold` is what a host reads
/// before offering the button on a repair, and it has been true since
/// 12 Sep 2026 - with one stated exception, the solve, which is seconds
/// on a structured repair. See that key's comment.
///
/// # Safety
/// `s` is a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_job_pause(s: *mut pf_session, id: i64) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    answer(h, id, h.session.set_job_paused(id, true))
}

/// Resume a paused job.
///
/// # Safety
/// `s` is a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_job_resume(s: *mut pf_session, id: i64) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    answer(h, id, h.session.set_job_paused(id, false))
}

/// Remove a FINISHED job from the table. A running or queued one is
/// refused: a host that wants it gone cancels it first, and a remove
/// that silently cancelled would lose work on a misclick.
///
/// # Safety
/// `s` is a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_job_remove(s: *mut pf_session, id: i64) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    answer(h, id, h.session.remove(id))
}

/// The one place the four above turn a `bool` into the ABI's answer, so
/// "no such job" and "its state forbids it" cannot be reported two
/// ways.
fn answer(h: &pf_session, id: i64, ok: bool) -> i32 {
    if ok {
        return PF_OK;
    }
    h.fail("not_found", format!("no job {id}, or its state forbids it"));
    PF_ERR_NOT_FOUND
}

/// Section 5.5's "Run now": take this QUEUED job before anything else
/// waiting, whatever its id.
///
/// It does not interrupt what is running and it does not raise the
/// concurrency - on a serial queue the effect is that this job is the
/// next one started. Refused (`PF_ERR_NOT_FOUND`) for a job that is
/// already running or finished: there is nothing to bring forward.
///
/// An ADDITION beyond plan 4.5, asked for by the Windows lane on
/// 12 Sep 2026. Raising the concurrency to start one job starts every
/// job queued ahead of it too, and resuming the selected job only lets
/// the scheduler reach it in its own turn; neither is "run this now".
///
/// # Safety
/// `s` is a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_job_run_next(s: *mut pf_session, id: i64) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    answer(h, id, h.session.run_next(id))
}

/// Mark a job low priority. Advisory: it is reported in the snapshot
/// for the host to act on, and nothing in the engine reads it.
///
/// # Safety
/// `s` is a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_job_set_low_priority(s: *mut pf_session, id: i64, on: bool) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    if h.session.set_low_priority(id, on) {
        PF_OK
    } else {
        h.fail("not_found", format!("no job {id}"));
        PF_ERR_NOT_FOUND
    }
}

/// Pause or resume the QUEUE: a paused queue starts nothing new and
/// leaves what is running alone.
///
/// # Safety
/// `s` is a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_queue_set_paused(s: *mut pf_session, paused: bool) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    h.session.set_queue_paused(paused);
    PF_OK
}

/// How many jobs may run at once. Clamped to at least 1.
///
/// # Safety
/// `s` is a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_queue_set_concurrency(s: *mut pf_session, n: u32) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    h.session.set_concurrency(n);
    PF_OK
}

/// What to do when the queue drains: `none`, `notify`, `sleep` or
/// `shutdown`. The session REPORTS it (`post_action_due` in the queue
/// snapshot); the host performs it.
///
/// # Safety
/// `s` is a live session and `action` a NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_queue_set_post_action(
    s: *mut pf_session,
    action: *const c_char,
) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    // SAFETY: as above.
    let Some(text) = (unsafe { str_of(action) }) else {
        h.fail("arg", "action was null or not UTF-8");
        return PF_ERR_ARG;
    };
    match PostQueueAction::parse(text) {
        Some(a) => {
            h.session.set_post_action(a);
            PF_OK
        }
        None => {
            h.fail(
                "refused",
                format!("{text} is not one of none, notify, sleep, shutdown"),
            );
            PF_ERR_REFUSED
        }
    }
}

/// Tell the session the post-queue action has been dealt with, so it
/// does not fall due again for this drain.
///
/// # Safety
/// `s` is a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_queue_clear_post_action(s: *mut pf_session) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    h.session.clear_post_action_due();
    PF_OK
}

/// Persist the queue to `path` and load whatever is already there.
/// Answers the number of jobs loaded, or a negative code.
///
/// # Safety
/// `s` is a live session and `path` a NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_queue_open_store(s: *mut pf_session, path: *const c_char) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    // SAFETY: as above.
    let Some(text) = (unsafe { str_of(path) }) else {
        h.fail("arg", "path was null or not UTF-8");
        return PF_ERR_ARG;
    };
    match h.session.open_store(std::path::Path::new(text)) {
        Ok(n) => i32::try_from(n).unwrap_or(i32::MAX),
        Err(e) => {
            h.fail("refused", e);
            PF_ERR_REFUSED
        }
    }
}

/// The create preview for a spec: block size and count, padding,
/// efficiency, the files that would be written, and the equivalent
/// command line. Reads no source byte beyond `stat`.
///
/// # Safety
/// `s` is a live session and `create_spec_json` a NUL-terminated UTF-8
/// string; the result is released with [`pf_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_plan_preview(
    s: *mut pf_session,
    create_spec_json: *const c_char,
) -> *mut c_char {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return std::ptr::null_mut();
    };
    // SAFETY: as above.
    let Some(text) = (unsafe { str_of(create_spec_json) }) else {
        h.fail("arg", "create_spec_json was null or not UTF-8");
        return std::ptr::null_mut();
    };
    // BOTH SPELLINGS ARE ACCEPTED: a whole job spec
    // (`{"kind":"create","create":{...}}`) and the bare create object.
    // A pane building a spec has the first; a pane previewing while the
    // kind is implicit has the second, and refusing it would make every
    // host wrap the object for one call.
    let spec = match serde_json::from_str::<JobSpec>(text) {
        Ok(JobSpec::Create { create }) => Some(create),
        Ok(_) => {
            h.fail("refused", "pf_plan_preview takes a create spec");
            return std::ptr::null_mut();
        }
        Err(_) => serde_json::from_str(text).ok(),
    };
    let Some(spec) = spec else {
        h.fail("json", "not a create spec");
        return std::ptr::null_mut();
    };
    match planner::preview(&spec) {
        Ok(p) => out(serde_json::to_string(&p).unwrap_or_else(|_| "{}".to_string())),
        Err(e) => {
            h.fail(e.code, e.message);
            std::ptr::null_mut()
        }
    }
}

/// What this build can actually do. A host HIDES any control whose
/// capability is false; that is how the two app lanes stay correct
/// whatever the engine turns out to support on the day they ship.
///
/// # Safety
/// `s` may be null. The result is released with [`pf_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_capabilities(_s: *mut pf_session) -> *mut c_char {
    out(capabilities_json())
}

/// The capability object, in Rust, so the crate's own tests can read
/// it without going through the ABI.
pub fn capabilities_json() -> String {
    let caps = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "engine": format!("nzbkit {}", nzbkit_version()),
        "cpu": cpu_name(),
        // The row kernel the fold would run here, from the engine's
        // own dispatcher rather than from a second reading of the
        // CPU features - `gf16::scale_kernel` IS the answer
        // `scale_dispatch` acts on.
        "kernel": nzbkit::gf16::scale_kernel().name(),
        // The spec's own `vol<first>-<last>` volume spelling, as a
        // rename after the writer has finished - the same shape the
        // reference's own field widths already are.
        // `parfast::create::final_volume_names` is the one rule, read
        // by the rename AND by the preview, so the Create pane cannot
        // name a file the create will not write.
        "std_naming": true,
        // An explicit per-volume ceiling in blocks or bytes. The
        // reference's dialect has ONE volume ceiling, `-l`, so parfast
        // carries an arbitrary one in a long option of its own
        // (`--volume-blocks=N`, spec R.3) that reaches
        // `par2gen::CreatePlan::max_blocks_per_volume`. The preview and
        // the run resolve it through the same
        // `parfast::create::volume_ceiling`.
        "volume_limit_explicit": true,
        // FALSE, and it says why in API.md and in the handoff: `never` /
        // `always` are not implemented, and `par2gen`'s comment writer
        // picks its packet by CONTENT - ASCII text takes the ASCII
        // packet, anything above U+007F takes the Unicode one - which
        // IS `auto`, the only honest value while it is the only policy.
        "unicode_policy": false,
        // TRUE since 12 Sep 2026. Off the session crate's own predicate
        // and never a second answer, so the create preview's warning and
        // this key cannot disagree about whether the field is live.
        "comment": parfast_session::planner::capabilities_comment(),
        // The engine's `-N` / `-S` reach the CLI options and are
        // carried through; nothing here gates them.
        "data_skipping": true,
        "fast_solver": true,
        // A verify and the two checksum kinds park between units of
        // work; a repair and a CREATE park inside the engine, each with
        // one stated exception - see `parfast_session::runner`'s header
        // for exactly what each control reaches.
        "pause": true,
        // TRUE SINCE 12 Sep 2026 (plan 4.2 item 1), for the repair AND
        // - since later the same day, claim `par2gen-create-control` -
        // for the CREATE, whose member hashing, fold or transform and
        // volume writes report and are controlled the same way. The
        // keys are not per-kind; API.md's per-job-kind table is, and it
        // is what a host should read. What each answer means:
        //
        // - progress: four phases, each a rising fraction that lands.
        // - cancel: polled per member, per fed block, per fold unit and
        //   per written block. The repair ends there; API.md and
        //   `RepairError::Cancelled` state what is left on disk.
        // - pause: parks in the hashing loop, the feed and the patch -
        //   every site where a thread holds nothing another could take.
        //   The SOLVE is the stated exception: its unit grid is a shared
        //   work-stealing queue, so a Pause pressed during it takes
        //   effect at the end of it. Seconds on a structured repair,
        //   which is nearly all of them. A create's exception is the
        //   same shape and the same reason: a TRANSFORM claims its
        //   stripes off a shared counter, so a Pause pressed during one
        //   lands at the end of it.
        //
        // AND FOR A CREATE, the one thing no other kind has: a
        // cancelled create leaves NOTHING on disk. The engine unlinks
        // the index and every volume the run wrote, because a volume is
        // written to its final name with the critical packets patched
        // in last - so a half-written set names no member and verifies
        // against nothing. A host does not have to clean up after a
        // Cancel, and must not offer to.
        "pause_in_fold": true,
        "cancel_in_fold": true,
        "progress_in_fold": true,
        "low_priority": false,
    });
    caps.to_string()
}

/// The engine's version, which is `nzbkit`'s package version and not
/// this crate's - a host that reports "engine" must report the engine.
fn nzbkit_version() -> &'static str {
    nzbkit::VERSION
}

/// A human-readable CPU name for the About box. Best effort by design:
/// an empty string is a perfectly good answer and no host branches on
/// the contents.
fn cpu_name() -> String {
    std::env::var("NZBFAST_CPU_NAME").unwrap_or_else(|_| std::env::consts::ARCH.to_string())
}

/// The settings object, with every default filled in.
///
/// # Safety
/// `s` is a live session; the result is released with
/// [`pf_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_settings_get(s: *mut pf_session) -> *mut c_char {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return std::ptr::null_mut();
    };
    out(h.session.settings().to_json())
}

/// Replace the settings. Keys left out take their defaults, and
/// unknown keys are ignored - see `parfast_session::settings`.
///
/// # Safety
/// `s` is a live session and `settings_json` a NUL-terminated UTF-8
/// string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_settings_set(s: *mut pf_session, settings_json: *const c_char) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    // SAFETY: as above.
    let Some(text) = (unsafe { str_of(settings_json) }) else {
        h.fail("arg", "settings_json was null or not UTF-8");
        return PF_ERR_ARG;
    };
    match Settings::from_json_reporting(text) {
        Ok((s2, ignored)) => {
            h.session.set_settings(s2);
            // A SUCCESSFUL WRITE THAT DROPPED SOMETHING STILL SAYS SO.
            // Unknown top-level keys are accepted on purpose (a host
            // built against a different core is never stopped by a
            // field only one side knows), but accepting in silence is
            // what let the Windows lane lose `notifications` for a day
            // - so the names land in `pf_last_error` under a code of
            // their own. The return is still PF_OK: this is a note,
            // not a failure, and API.md says so where it warns that
            // `pf_last_error` can hold one after a success.
            if !ignored.is_empty() {
                h.fail(
                    "settings_ignored_keys",
                    format!(
                        "the write succeeded, but this build does not know these top-level \
                         keys and ignored them: {}",
                        ignored.join(", ")
                    ),
                );
            }
            PF_OK
        }
        Err(e) => {
            h.fail(e.code, e.message);
            PF_ERR_JSON
        }
    }
}

/// "Clear remembered checksums": delete every record in the per-user
/// digest store that `performance.digest_cache` fills. Answers how many
/// files went (0 where there is no store), or `PF_ERR_REFUSED` with the
/// folder and the reason in [`pf_last_error`]. Safe while a job runs.
///
/// # Safety
/// `s` is a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_digest_cache_clear(s: *mut pf_session) -> i32 {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return PF_ERR_ARG;
    };
    match h.session.clear_digest_cache() {
        Ok(n) => i32::try_from(n).unwrap_or(i32::MAX),
        Err(e) => {
            h.fail("refused", e);
            PF_ERR_REFUSED
        }
    }
}

/// `{"code":"...","message":"..."}` for the last failure on this
/// session, or `{}`. Reading it does not clear it; the next failure
/// replaces it.
///
/// # Safety
/// `s` is a live session; the result is released with
/// [`pf_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_last_error(s: *mut pf_session) -> *mut c_char {
    // SAFETY: the caller's obligation above.
    let Some(h) = (unsafe { borrow(s) }) else {
        return std::ptr::null_mut();
    };
    let held = h.last_error.lock().unwrap_or_else(|p| p.into_inner());
    match held.as_ref() {
        Some((code, message)) => {
            out(serde_json::json!({"code": code, "message": message}).to_string())
        }
        None => out("{}".to_string()),
    }
}

/// Release a string this library returned. NULL is accepted and does
/// nothing.
///
/// # Safety
/// `p` is null, or a pointer THIS library returned that has not
/// already been freed. A pointer from any other allocator is undefined
/// behaviour - it is reclaimed as a `CString`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pf_string_free(p: *mut c_char) {
    if p.is_null() {
        return;
    }
    // SAFETY: the caller promises `p` came from `CString::into_raw` in
    // `out` above and has not been freed, which is exactly
    // `CString::from_raw`'s precondition.
    drop(unsafe { CString::from_raw(p) });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> CString {
        CString::new(s).expect("no interior NUL in a test literal")
    }

    /// Take a returned string and free it through the ABI, which is
    /// also the assertion that `pf_string_free` accepts what these
    /// functions hand out.
    fn take(p: *mut c_char) -> String {
        assert!(!p.is_null(), "the call answered NULL");
        // SAFETY: `p` is non-null and came from one of this crate's own
        // `out` calls, so it is a live `CString` pointer.
        let s = unsafe { CStr::from_ptr(p) }
            .to_str()
            .expect("this library only emits UTF-8")
            .to_string();
        // SAFETY: same pointer, not yet freed, from this library.
        unsafe { pf_string_free(p) };
        s
    }

    #[test]
    fn a_null_settings_pointer_is_the_defaults_and_not_a_refusal() {
        // SAFETY: a null settings pointer is explicitly allowed.
        let s = unsafe { pf_session_new(std::ptr::null()) };
        assert!(!s.is_null());
        // SAFETY: `s` is live and nothing else touches it.
        let got = take(unsafe { pf_settings_get(s) });
        let want = Settings::default().to_json();
        assert_eq!(got, want);
        // SAFETY: `s` is live, unfreed, and this thread is the only user.
        unsafe { pf_session_free(s) };
    }

    /// Settings that do not parse must NOT stop the session starting: a
    /// corrupt preferences file has to be an app that launches and
    /// complains, never an app that will not launch.
    #[test]
    fn unparseable_settings_still_start_a_session() {
        // SAFETY: a valid NUL-terminated string.
        let s = unsafe { pf_session_new(c("{ not json").as_ptr()) };
        assert!(!s.is_null());
        // SAFETY: `s` is live.
        let got = take(unsafe { pf_settings_get(s) });
        assert_eq!(got, Settings::default().to_json());
        // SAFETY: as above.
        unsafe { pf_session_free(s) };
    }

    #[test]
    fn every_null_handle_answers_a_code_and_never_faults() {
        let n = std::ptr::null_mut();
        // SAFETY: every one of these is documented to accept null.
        unsafe {
            assert_eq!(pf_job_submit(n, c("{}").as_ptr()), i64::from(PF_ERR_ARG));
            assert!(pf_job_snapshot(n, 1).is_null());
            assert!(pf_queue_snapshot(n).is_null());
            assert_eq!(pf_job_cancel(n, 1), PF_ERR_ARG);
            assert_eq!(pf_job_pause(n, 1), PF_ERR_ARG);
            assert_eq!(pf_job_resume(n, 1), PF_ERR_ARG);
            assert_eq!(pf_job_remove(n, 1), PF_ERR_ARG);
            assert_eq!(pf_job_set_low_priority(n, 1, true), PF_ERR_ARG);
            assert_eq!(pf_queue_set_paused(n, true), PF_ERR_ARG);
            assert_eq!(pf_queue_set_concurrency(n, 2), PF_ERR_ARG);
            assert_eq!(pf_queue_set_post_action(n, c("sleep").as_ptr()), PF_ERR_ARG);
            assert_eq!(pf_settings_set(n, c("{}").as_ptr()), PF_ERR_ARG);
            assert!(pf_settings_get(n).is_null());
            assert!(pf_last_error(n).is_null());
            assert!(pf_plan_preview(n, c("{}").as_ptr()).is_null());
            pf_session_set_wake(n, None, std::ptr::null_mut());
            pf_session_free(n);
            pf_string_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn a_bad_spec_is_a_negative_code_with_a_readable_last_error() {
        // SAFETY: null settings are allowed.
        let s = unsafe { pf_session_new(std::ptr::null()) };
        // SAFETY: `s` is live and the string is valid.
        let id = unsafe { pf_job_submit(s, c(r#"{"kind":"fly"}"#).as_ptr()) };
        assert_eq!(id, i64::from(PF_ERR_JSON));
        // SAFETY: `s` is live.
        let err = take(unsafe { pf_last_error(s) });
        assert!(err.contains(r#""code":"json""#), "{err}");
        // SAFETY: as above.
        unsafe { pf_session_free(s) };
    }

    #[test]
    fn an_unknown_post_action_is_refused_by_name() {
        // SAFETY: null settings are allowed.
        let s = unsafe { pf_session_new(std::ptr::null()) };
        // SAFETY: `s` is live and the string is valid.
        let code = unsafe { pf_queue_set_post_action(s, c("hibernate").as_ptr()) };
        assert_eq!(code, PF_ERR_REFUSED);
        // SAFETY: `s` is live.
        let err = take(unsafe { pf_last_error(s) });
        assert!(err.contains("hibernate"), "{err}");
        // SAFETY: as above.
        unsafe { pf_session_free(s) };
    }

    /// Every capability the two UI lanes branch on is present and is a
    /// boolean, so a host that reads one never gets `undefined`.
    #[test]
    fn the_capability_object_carries_every_key_a_ui_branches_on() {
        // SAFETY: `pf_capabilities` documents a null session.
        let json = take(unsafe { pf_capabilities(std::ptr::null_mut()) });
        let v: serde_json::Value = serde_json::from_str(&json).expect("capabilities parse");
        for key in [
            "std_naming",
            "volume_limit_explicit",
            "unicode_policy",
            "comment",
            "data_skipping",
            "fast_solver",
            "pause",
            "pause_in_fold",
            "cancel_in_fold",
            "progress_in_fold",
            "low_priority",
        ] {
            assert!(v[key].is_boolean(), "{key} is {:?}", v[key]);
        }
        // And the one the engine work of 12 Sep 2026 turned on, pinned
        // by VALUE: the two UI lanes hide the Comment field while it is
        // false, so a flip back is a feature disappearing from both
        // apps and must be a deliberate edit here.
        assert_eq!(v["comment"], serde_json::json!(true));
        for key in ["version", "engine", "cpu", "kernel"] {
            assert!(v[key].is_string(), "{key} is {:?}", v[key]);
        }
    }

    /// A preview takes the whole job spec AND the bare create object,
    /// because a pane has one or the other depending on where it is in
    /// being filled in.
    #[test]
    fn a_preview_takes_both_spellings_of_a_create_spec() {
        let d = std::env::temp_dir().join(format!("parfast-ffi-prev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        std::fs::write(d.join("a.bin"), vec![3u8; 40_000]).expect("fixture");
        let bare = format!(
            r#"{{"sources":[{{"path":"{}"}}],"output":"{}","block":{{"size":2048}}}}"#,
            d.join("a.bin").display(),
            d.join("set.par2").display()
        );
        let wrapped = format!(r#"{{"kind":"create","create":{bare}}}"#);
        // SAFETY: null settings are allowed.
        let s = unsafe { pf_session_new(std::ptr::null()) };
        // SAFETY: `s` is live and both strings are valid.
        let a = take(unsafe { pf_plan_preview(s, c(&bare).as_ptr()) });
        // SAFETY: as above.
        let b = take(unsafe { pf_plan_preview(s, c(&wrapped).as_ptr()) });
        assert_eq!(a, b);
        let v: serde_json::Value = serde_json::from_str(&a).expect("preview parses");
        assert_eq!(v["block_size"], 2048);
        assert!(
            v["command"]
                .as_str()
                .unwrap_or_default()
                .starts_with("parfast c ")
        );
        // SAFETY: `s` is live.
        unsafe { pf_session_free(s) };
        let _ = std::fs::remove_dir_all(&d);
    }
}
