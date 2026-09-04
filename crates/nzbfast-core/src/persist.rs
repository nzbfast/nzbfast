//! Crash-safe file persistence for the daemon's JSON state (queue.json,
//! settings.json, quota.json, …). Two halves:
//!
//! * `write_atomic` - tmp-write + rename (the tools.rs binary-extraction
//!   pattern, extracted). ENOSPC or a crash mid-write can only tear the
//!   temp file; the previous good file survives intact.
//! * `load_json_with_backup` - refreshes a `.bak` of the last good parse
//!   on every successful load, and on a parse failure REFUSES to report
//!   the file as "empty" (the next save would make the loss permanent):
//!   the corrupt bytes are set aside as `.corrupt` and the `.bak` is
//!   restored instead, loudly.
//! * `blocking_db` - runs a synchronous database closure without
//!   starving the async runtime (see its doc).

use serde_json::Value;
use std::path::{Path, PathBuf};
use tracing::{error, warn};

/// `queue.json` → `queue.json.bak` (same directory, so the pair travels
/// together with the spool).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(suffix);
    PathBuf::from(os)
}

/// Write `bytes` at `path` atomically: write a same-directory temp file,
/// then rename over the target (rename replaces on Windows too). The
/// counter keeps concurrent writers in this process off each other's
/// temp file; the pid does the same across processes.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // TEST SEAM (below): the two fsyncs are ~71 ms a call on this box's
    // APFS, so a test that drives hundreds of state writes through here
    // spends its whole budget in the durability it is not asserting -
    // dupe_tests::the_same_post_arm_stays_cheap_against_a_wide_queue was
    // 30 s of which ~29 s was 210 enqueues x 2 saves x 2 fsyncs. The
    // seam is a THREAD-LOCAL so it cannot leak into another test in the
    // same process (the durability cases keep the real path), and it is
    // cfg(test) so production has no such door.
    // The two fsyncs below (file, then directory) can take arbitrarily long
    // on a busy or remote filesystem, and several callers run on tokio
    // worker threads - save_queue via the watch poller, QuotaLedger::save
    // on the download runner. Same starvation class as blocking_db's doc:
    // demote the worker for the duration; off the runtime it runs inline.
    blocking_db(|| write_atomic_sync(path, bytes))
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    /// Test seam for `write_atomic`: `true` skips the file and directory
    /// fsyncs on THIS thread only. Set it at the top of a test whose
    /// subject is not durability and whose cost is hundreds of state
    /// saves; `blocking_db` runs the write inline off a runtime, so the
    /// calling thread is the writing thread. Never read by production
    /// code - the whole item is `cfg(test)`.
    pub static SKIP_FSYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn write_atomic_sync(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = sibling(path, &format!(".{}.{n}.tmp", std::process::id()));
    #[cfg(any(test, feature = "test-support"))]
    let skip_fsync = SKIP_FSYNC.with(std::cell::Cell::get);
    #[cfg(not(any(test, feature = "test-support")))]
    let skip_fsync = false;
    // fsync the temp file BEFORE the rename commits: a rename is metadata,
    // journaled independently of the data blocks, so on power loss the target
    // (and its .bak, written through here too) could otherwise come back
    // 0-byte/torn. State files are daemon-private and can hold credentials, so
    // create them mode 0600 on unix.
    let done = (|| -> std::io::Result<()> {
        use std::io::Write;
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        if !skip_fsync {
            f.sync_all()?;
        }
        drop(f);
        std::fs::rename(&tmp, path)?;
        // ...and fsync the DIRECTORY, because the rename that just published
        // those bytes is itself only a directory entry. Syncing the file
        // persists its contents; the name pointing at them is separate
        // metadata with its own flush. Without this the function could return
        // success and the file still be absent after power loss - which for
        // queue/settings/quota/usage state means the next start rebuilds from
        // defaults and saves them over whatever survived.
        //
        // `nzbkit::disk::sync_dir` and not `smart::sync_dir`: the two do
        // the same fsync, and the one in `smart` only adds an error
        // context this call discards anyway. Reaching for it had the
        // crash-safe writer - which `smart` itself calls - depending on
        // `smart`, which is the cycle the crate-split prep (step 1 of
        // research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md) removes.
        if !skip_fsync && let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            nzbkit::disk::sync_dir(dir);
        }
        Ok(())
    })();
    if done.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    done
}

/// Read `path` as JSON. `None` means "no data on disk" - a missing file
/// (fresh start, or a deliberate delete-to-reset, which must stay
/// effective). A file that EXISTS but won't parse is never reported as
/// that: its bytes are preserved at `<path>.corrupt`, and the `.bak` of
/// the last good parse is loaded - and written back to `path` so the
/// daemon self-heals rather than logging forever.
/// True when `path` (or its `.bak`) is on disk but NEITHER yields usable
/// JSON. Distinct from "absent" and from "parsed fine but empty": this is
/// the state where a store that MAY have held data silently loaded as
/// nothing. `load_json_with_backup` deliberately degrades to an empty map
/// there so one torn file cannot erase every other setting - correct for
/// settings, dangerous for a credential, so the caller can ask.
pub fn json_store_unreadable(path: &Path) -> bool {
    let bak = sibling(path, ".bak");
    let readable = |p: &Path| {
        std::fs::read(p)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .is_some()
    };
    // `.corrupt` counts as evidence the primary once existed: an
    // unparseable primary is RENAMED there, so by the next start the
    // primary looks merely absent.
    let existed = path.exists() || bak.exists() || sibling(path, ".corrupt").exists();
    existed && !readable(path) && !readable(&bak)
}

pub fn load_json_with_backup(path: &Path) -> Option<Value> {
    let bak = sibling(path, ".bak");
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        // A genuinely-absent file with NO backup means "no data" (fresh
        // start, or a deliberate reset).
        //
        // An absent primary WITH a good backup is a different story: that is
        // what a crash between the temp write and the rename leaves behind,
        // and returning None there makes the caller rebuild from defaults and
        // then save those defaults over the last good state - turning a
        // recoverable interruption into permanent loss. Recover, and say so.
        //
        // Resetting therefore means removing the .bak too; the message says
        // which file to remove.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let recovered = std::fs::read(&bak)
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            return match recovered {
                Some(v) => {
                    warn!(
                        target: "persist",
                        "{} is missing but {} is intact - recovering from it \
                         (delete {} too if you meant to reset)",
                        path.display(),
                        bak.display(),
                        bak.display()
                    );
                    let _ = write_atomic(path, &serde_json::to_vec(&v).unwrap_or_default());
                    Some(v)
                }
                None => None,
            };
        }
        Err(_) => {
            return std::fs::read(&bak)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok());
        }
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) => {
            if std::fs::read(&bak).map_or(true, |b| b != bytes) {
                let _ = write_atomic(&bak, &bytes);
            }
            Some(v)
        }
        Err(e) => {
            let kept = sibling(path, ".corrupt");
            let _ = std::fs::rename(path, &kept);
            warn!(
                target: "persist",
                "{} won't parse ({e}) - bytes kept at {}",
                path.display(),
                kept.display()
            );
            let good = std::fs::read(&bak)
                .ok()
                .and_then(|b| Some((serde_json::from_slice::<Value>(&b).ok()?, b)));
            match good {
                Some((v, b)) => {
                    warn!(target: "persist", "restored last good state from {}", bak.display());
                    let _ = write_atomic(path, &b);
                    Some(v)
                }
                None => {
                    // Not a warning: the queue/history this file held is
                    // gone, and nothing later recovers it.
                    error!(
                        target: "persist",
                        "no usable {} - starting empty ({} has the old bytes)",
                        bak.display(),
                        kept.display()
                    );
                    None
                }
            }
        }
    }
}

/// Like [`load_json_with_backup`] but for a USER-supplied config path that
/// may legitimately NOT be JSON - the runtime also accepts a SABnzbd `.ini`.
/// A parse failure here must NEVER quarantine the file: renaming a user's
/// live config to `.corrupt` on a mere read (server-editor open, setup
/// wizard) silently destroys it. Refreshes `.bak` on a good JSON parse;
/// returns None (leaving the file untouched) on anything else.
pub(crate) fn load_json_config(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) => {
            let bak = sibling(path, ".bak");
            if std::fs::read(&bak).map_or(true, |b| b != bytes) {
                let _ = write_atomic(&bak, &bytes);
            }
            Some(v)
        }
        // Not JSON (e.g. a SABnzbd .ini) - do not touch the file.
        Err(_) => None,
    }
}

/// Run a synchronous database closure without starving the async
/// runtime.
///
/// Measured 2026-08-05: the index deepen pass's three inline ingest
/// transactions, the tip watcher's ingest, and a predb fold each ran
/// their SQLite work directly on tokio worker threads - and with one
/// worker per core all occupied at once, the download runner (a ready
/// task whose 500 ms poll timer had expired) had no thread to resume
/// on for 38 seconds. Four queued jobs sat unstarted the whole time.
///
/// `block_in_place` demotes the current worker so the scheduler
/// backfills it; the closure (INCLUDING any mutex wait for a db handle,
/// which can be another writer's whole transaction) then costs this
/// thread, never the runtime. On a current-thread runtime - or none -
/// `block_in_place` would panic, so the closure just runs inline there,
/// which is the old behaviour in the contexts where it was already
/// fine.
///
/// THE BODY IS OUTLINED BEHIND `blocking_db_dyn`, AND THAT IS A COMPILE
/// COST FIX, NOT A STYLE ONE (TODO 276, 24 Aug 2026). `block_in_place`
/// is generic over the closure, so before this every instantiation of
/// this function monomorphised tokio's ENTIRE task harness -
/// `cancel_task<BlockingTask<Box<closure in block_in_place<closure in
/// ...>>>>` and its whole vtable neighbourhood, about ninety symbols a
/// site. The 12 generic `with_index*` helpers in
/// `daemon_index.rs` all call through here and have 264 call
/// sites between them, which put 11,220 of the test binary's 21,629
/// task-harness instantiations - 52% - and 2,767 KB of machine code
/// into that one 1,904-line file, 11.5% of nzbfast's own text.
///
/// `&mut dyn FnMut()` is itself `FnMut`, so the outlined form gives
/// `block_in_place` exactly ONE instantiation for the whole crate while
/// the generic wrapper above keeps every caller's signature. Measured
/// in CI's profile, control against treatment on one box: the
/// `nzbfast "bin" (test)` unit 42.49 s -> 31.71 s of CPU, `nzbfast
/// "bin"` 31.71 s -> 23.15 s, whole-build CPU 124.9 s -> 105.6 s, and
/// `cargo nextest archive` (the exact CI step) -13.7% wall / -13.2%
/// CPU at `-j4`, which is the runner's core count. Text symbols
/// 129,355 -> 105,055.
///
/// DO NOT "SIMPLIFY" THIS BACK to a single generic body: it reads as
/// one indirection too many and it is worth 13% of the CI build. The
/// runtime cost is one indirect call in front of work whose next act is
/// a SQLite transaction. The `Option` dance is what bridges the
/// caller's `FnOnce` to the `FnMut` a `dyn` receiver needs; `take()`
/// panics if anything ever calls the shim twice, which `block_in_place`
/// does not.
pub fn blocking_db<T>(f: impl FnOnce() -> T) -> T {
    let mut f = Some(f);
    let mut out: Option<T> = None;
    blocking_db_dyn(&mut || out = Some((f.take().expect("shim called twice"))()));
    out.expect("blocking_db_dyn did not run the closure")
}

/// The non-generic half of [`blocking_db`] - see its note for why the
/// split exists and what it is worth.
fn blocking_db_dyn(f: &mut dyn FnMut()) {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-persist-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn round_trip_and_bak_refresh() {
        let dir = scratch("rt");
        let p = dir.join("state.json");
        write_atomic(&p, b"{\"a\":1}").unwrap();
        assert_eq!(load_json_with_backup(&p), Some(json!({"a": 1})));
        // The load refreshed the .bak with the good bytes.
        assert_eq!(std::fs::read(sibling(&p, ".bak")).unwrap(), b"{\"a\":1}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_a_quiet_fresh_start() {
        let dir = scratch("fresh");
        assert_eq!(load_json_with_backup(&dir.join("state.json")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A crash between the temp write and the rename leaves no primary but an
    /// intact `.bak`. Returning None there made the caller rebuild from
    /// defaults and then save them over the last good state, so a survivable
    /// interruption became permanent loss.
    #[test]
    fn missing_primary_recovers_from_an_intact_backup() {
        let dir = scratch("missing-primary");
        let p = dir.join("state.json");
        write_atomic(&p, br#"{"queue": [7, 8, 9]}"#).unwrap();
        load_json_with_backup(&p).unwrap(); // seeds the .bak
        std::fs::remove_file(&p).unwrap(); // the rename never landed

        let got = load_json_with_backup(&p).expect("must recover from .bak");
        assert_eq!(got["queue"][0], 7);
        assert!(p.exists(), "recovery should also restore the primary");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...but a genuine reset - both files gone - still resets.
    #[test]
    fn removing_both_files_is_still_a_reset() {
        let dir = scratch("full-reset");
        let p = dir.join("state.json");
        write_atomic(&p, br#"{"queue": [1]}"#).unwrap();
        load_json_with_backup(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        std::fs::remove_file(sibling(&p, ".bak")).unwrap();

        assert_eq!(load_json_with_backup(&p), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_file_falls_back_to_bak_and_next_save_keeps_data() {
        let dir = scratch("torn");
        let p = dir.join("state.json");
        write_atomic(&p, br#"{"queue": [1, 2, 3]}"#).unwrap();
        load_json_with_backup(&p).unwrap(); // seeds the .bak
        // ENOSPC / crash mid-write: the file survives truncated.
        let full = std::fs::read(&p).unwrap();
        std::fs::write(&p, &full[..full.len() / 2]).unwrap();
        // The loader refuses the torn file and serves the last good parse…
        assert_eq!(load_json_with_backup(&p), Some(json!({"queue": [1, 2, 3]})));
        // …quarantines the torn bytes, and self-heals the main file.
        assert!(sibling(&p, ".corrupt").is_file());
        assert_eq!(std::fs::read(&p).unwrap(), full);
        // The usual mutate-and-save cycle now writes last-good + the
        // change - nothing erased.
        let mut v = load_json_with_backup(&p).unwrap();
        v["extra"] = json!(true);
        write_atomic(&p, serde_json::to_string(&v).unwrap().as_bytes()).unwrap();
        let re = load_json_with_backup(&p).unwrap();
        assert_eq!(re["queue"], json!([1, 2, 3]));
        assert_eq!(re["extra"], json!(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zero_byte_file_without_bak_preserves_bytes() {
        let dir = scratch("zero");
        let p = dir.join("state.json");
        std::fs::write(&p, b"").unwrap(); // torn to nothing, no .bak yet
        assert_eq!(load_json_with_backup(&p), None);
        // The (empty) evidence is set aside, not silently overwritten.
        assert!(sibling(&p, ".corrupt").is_file());
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
