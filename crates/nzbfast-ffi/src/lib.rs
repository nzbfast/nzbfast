//! C ABI over the embedded nzbfast engine. iOS forbids exec, so unlike
//! Android (which runs the nzbfast binary as a child process) the engine
//! must live INSIDE the app process: this crate builds as a staticlib
//! the app links, and the daemon serves its API + dashboard on
//! 127.0.0.1 from a background thread.
//!
//! Contract (mirrored in include/nzbfast.h):
//! - `nzbfast_start(config_dir, port, apikey)` - spawn the engine.
//!   Returns 0 on accepted start, negative on refusal. Asynchronous:
//!   poll the port (or `nzbfast_is_up`) for readiness.
//! - `nzbfast_stop()` - stop it and release the port. Blocks until the
//!   listener is closed and the runtime is torn down, or until
//!   [`STOP_WAIT`] elapses. Returns 0 = stopped, -1 = not running,
//!   -2 = still stopping (the wait ran out; see `nzbfast_stop`).
//! - `nzbfast_is_up()` - 1 while the engine thread is alive.
//!
//! Threading: all three are safe from any thread; a global mutex
//! serializes state transitions. Start-after-stop is supported (the
//! serve loop's `request_stop` seam exists for exactly this cycle).
//!
//! THE STOP BOUND IS REAL SINCE 26 Aug 2026 (TODO 307 item 3) and was
//! not before. The contract above and the mirrored one in
//! include/nzbfast.h have always said "bounded"; the implementation
//! held the ENGINE lock across an UNBOUNDED `JoinHandle::join`, and
//! `STOP_BUDGET` bounds only the runtime teardown that happens AFTER
//! `serve()` has already returned. So a `serve()` that wedged hung the
//! host app inside `nzbfast_stop` forever - and, because the lock is
//! held across the wait, hung `nzbfast_is_up` with it, which is the one
//! call a host would reach for to find out what was going on. On iOS
//! this is the only stop path there is.

use std::ffi::{CStr, c_char};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

/// How long the ENGINE THREAD gives `rt.shutdown_timeout` to wind the
/// tokio runtime up before abandoning still-blocked pool threads. The
/// HTTP workers exit within one accept tick (500 ms), so the port itself
/// is released well inside this.
///
/// Read this as what it is and not as the stop contract - reading it as
/// the contract is what left `nzbfast_stop` unbounded for so long. It
/// starts counting only once `serve()` has ALREADY returned, so it can
/// say nothing at all about a `serve()` that never does. The bound a
/// caller sees is [`STOP_WAIT`].
const STOP_BUDGET: Duration = Duration::from_secs(8);

/// The bound `nzbfast_stop` actually enforces: how long it waits for the
/// engine thread to reach its last statement before giving up on it and
/// answering -2.
///
/// DERIVED from `STOP_BUDGET` rather than written as a second literal,
/// because it has to be LONGER: a healthy stop pays the serve loop's own
/// wind-up (the HTTP workers leave within one 500 ms accept tick) and
/// then up to the whole of `STOP_BUDGET` inside `rt.shutdown_timeout`,
/// so a wait at or below that figure would time out on an engine that is
/// shutting down exactly as designed - and a -2 that fires on a healthy
/// stop is worse than no bound at all, because a host learns to ignore
/// it. The four seconds of headroom is for the wind-up plus scheduling
/// on a loaded phone.
const STOP_WAIT: Duration = Duration::from_secs(STOP_BUDGET.as_secs() + 4);

struct Engine {
    thread: std::thread::JoinHandle<()>,
    /// Signalled by the engine thread as its LAST act, after
    /// `rt.shutdown_timeout` has returned. This is what gives
    /// `nzbfast_stop` something it can put a deadline on: a
    /// `JoinHandle` offers no timed join.
    ///
    /// A panic anywhere in the engine thread drops the sender instead,
    /// which the waiter reads as `Disconnected` - also "the thread is
    /// over", and the right answer for the same reason.
    done: std::sync::mpsc::Receiver<()>,
}

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

/// The config file `nzbfast_start` loads out of its `config_dir`.
///
/// `pub` so the tests can SEED it rather than spelling the name a second
/// time. That is not tidiness: `nzbkit::config::Config::load` answers a
/// MISSING file by finding a SABnzbd install's `sabnzbd.ini` through
/// `$HOME`, so a test whose config is not there runs against whatever
/// server list the BOX happens to have - the developer's on this fleet,
/// none at all on a CI runner. A test seeding a name that had drifted
/// from this one would be back in that state with nothing to show it.
pub const CONFIG_FILE: &str = "config.local.json";

/// Start the engine. `config_dir` must be a writable directory (the
/// app's Application Support dir on iOS); config, settings, spool and
/// downloads all live under it. `apikey` may be NULL for an open
/// loopback API (the host app is the only possible client on iOS - the
/// bind is hard-wired to 127.0.0.1).
///
/// Returns 0 = started, -1 = already running, -2 = bad arguments.
///
/// # Safety
/// `config_dir` (and `apikey` when non-NULL) must point to valid
/// NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbfast_start(
    config_dir: *const c_char,
    port: u16,
    apikey: *const c_char,
) -> i32 {
    // SAFETY: this function's own `# Safety` clause puts the burden on
    // the caller: `config_dir` is NULL or a valid NUL-terminated string,
    // which is exactly what `cstr_utf8` requires.
    let dir = match unsafe { cstr_utf8(config_dir) } {
        Some(s) if !s.is_empty() => PathBuf::from(s),
        _ => return -2,
    };
    // SAFETY: as above - the caller guarantees `apikey` is NULL or a
    // valid NUL-terminated string.
    let apikey = unsafe { cstr_utf8(apikey) }.filter(|s| !s.is_empty());

    let mut engine = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(e) = engine.take() {
        if e.thread.is_finished() {
            let _ = e.thread.join();
        } else {
            *engine = Some(e);
            return -1;
        }
    }

    nzbfast::embedded_init();
    // Arm the stop seam BEFORE spawning, under the ENGINE lock: a
    // request_stop() issued any time after this start() returns then
    // lands above this run's baseline and can never be erased. The old
    // design reset a global flag at serve() entry, so a stop that raced
    // the engine thread's bootstrap was wiped and nzbfast_stop() hung
    // forever in join().
    nzbfast::serve::arm_embedded_stop();
    let config = dir.join(CONFIG_FILE);
    let out_root = dir.join("downloads");
    let (done_tx, done) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::Builder::new()
        .name("nzbfast-engine".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("nzbfast-ffi: runtime build failed: {e}");
                    return;
                }
            };
            let opts = nzbfast::embedded_serve_opts(port, apikey, out_root);
            if let Err(e) = rt.block_on(nzbfast::serve::serve(config, opts)) {
                eprintln!("nzbfast-ffi: serve failed: {e:#}");
            }
            // serve() returned (a stop request, or a startup failure):
            // tear the runtime down without waiting on pool threads that
            // may be parked in long blocking work. The HTTP workers exit
            // on their own within one accept tick, which is what
            // actually frees the port.
            rt.shutdown_timeout(STOP_BUDGET);
            // The last act of this thread, and the whole of what makes
            // `nzbfast_stop`'s deadline meaningful. It must stay LAST:
            // anything moved below it is work a stop would report as
            // finished while it was still running.
            let _ = done_tx.send(());
        });
    match thread {
        Ok(t) => {
            *engine = Some(Engine { thread: t, done });
            0
        }
        Err(e) => {
            eprintln!("nzbfast-ffi: engine thread spawn failed: {e}");
            -2
        }
    }
}

/// Stop the engine and wait, up to [`STOP_WAIT`], for the port to be
/// released and the engine thread to finish.
///
/// Returns 0 = stopped, -1 = not running, -2 = still stopping.
///
/// WHAT -2 LEAVES BEHIND, which a host has to know because it is a
/// state, not an error: the stop request has been made and is permanent
/// (the serve loop's stop epoch only ever moves forward), and the engine
/// thread is still running - not detached and forgotten, but still
/// registered here. So until it does finish:
///
/// - `nzbfast_is_up()` keeps answering 1, truthfully, and is the poll a
///   host should use to find out when the old engine has gone;
/// - `nzbfast_start()` REFUSES with -1, which is the important half. A
///   timed-out stop must not let a fresh engine arm the process-global
///   stop baseline underneath a still-live one, or race it for the
///   port. The `is_finished()` check at the top of `nzbfast_start`
///   already gives exactly that, and now has something to check;
/// - calling `nzbfast_stop()` again is safe and is how a host waits
///   longer: it re-requests the stop (a no-op) and waits another
///   `STOP_WAIT`, answering 0 as soon as the thread is really gone.
///
/// A -2 means the engine did not wind up inside a budget generous
/// enough that a healthy one never comes close - so it is a bug report,
/// not a retry hint. The host is nonetheless free to carry on: nothing
/// it can call will now deadlock on the wedged thread.
#[unsafe(no_mangle)]
pub extern "C" fn nzbfast_stop() -> i32 {
    stop_within(STOP_WAIT)
}

/// The body of [`nzbfast_stop`], with the deadline as a parameter.
///
/// `pub` only so `tests/stop_bound.rs` can drive the timeout arm with a
/// deadline short enough to hit deterministically: a wedged `serve()` is
/// not something a test can arrange cheaply, but a zero-length wait
/// against a healthy engine reaches the identical code path. Not
/// `#[unsafe(no_mangle)]` and not in the C header - the ABI is the three
/// functions above and nothing else.
#[doc(hidden)]
pub fn stop_within(wait: Duration) -> i32 {
    // The ENGINE lock is held through request_stop AND the wait: the
    // stop epoch and its Notify are process-global - a start()
    // interleaved here could re-arm the baseline under engine A (which
    // then parks forever while we wait on it) or race A for the port.
    // Holding the lock makes a concurrent start/stop/is_up park until
    // the old engine is provably gone, or until this wait runs out.
    //
    // That "or" is the 26 Aug 2026 change. The lock discipline is
    // unchanged and deliberately so; what changed is that the thing it
    // is held across is now bounded, so the worst a concurrent
    // `nzbfast_is_up` can wait is `wait` rather than forever.
    let mut engine = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
    let e = match engine.take() {
        Some(e) => e,
        None => return -1,
    };
    nzbfast::serve::request_stop();
    match e.done.recv_timeout(wait) {
        // Signalled, or the sender went down with a panicking thread:
        // either way the engine thread has run its last statement, so
        // the join below is only its stack unwind and can no longer
        // block on the engine's own work.
        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            let _ = e.thread.join();
            0
        }
        // Still going. Put it BACK rather than dropping the handle:
        // a detached engine is one `nzbfast_start` cannot see, and
        // start refusing while the old thread lives is the whole
        // protection - see this function's caller for what -2 means.
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            *engine = Some(e);
            -2
        }
    }
}

/// 1 while the engine thread is alive (which includes startup, before
/// the listener answers - poll the HTTP port for real readiness, and
/// the window after a [`nzbfast_stop`] that answered -2, where this is
/// the poll that tells a host when the old engine has finally gone).
///
/// Takes the ENGINE lock, so a stop in flight blocks this call - for at
/// most [`STOP_WAIT`] since 26 Aug 2026, and previously forever.
#[unsafe(no_mangle)]
pub extern "C" fn nzbfast_is_up() -> i32 {
    let engine = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
    match engine.as_ref() {
        Some(e) if !e.thread.is_finished() => 1,
        _ => 0,
    }
}

/// # Safety
/// `p` is NULL or a valid NUL-terminated string.
unsafe fn cstr_utf8(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` is non-NULL (checked above) and this function's
    // `# Safety` clause makes the caller responsible for it pointing at
    // a NUL-terminated string. The borrow is consumed into an owned
    // `String` before returning, so the `CStr` never outlives `p`.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .ok()
        .map(str::to_owned)
}
