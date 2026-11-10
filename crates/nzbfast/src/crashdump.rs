//! A Windows minidump when the process dies of an unhandled exception
//! (Weaver parity F7, TODO 358 hygiene).
//!
//! WHY. A Windows crash used to leave one line in the tray's
//! `daemon.log` (the child's NTSTATUS) and an Event Viewer request to the
//! user (TODO 165's idle crash still has one open). A minidump beside the
//! log is the cheaper diagnostic: one file, a few hundred KB, that names
//! the faulting thread, its stack and the loaded modules.
//!
//! WHAT IT COVERS. An unhandled SEH exception: an access violation in
//! FFI code (rapidyenc, aws-lc, sqlite), an illegal instruction, and a
//! stack overflow - Rust's own overflow handler prints its line and then
//! lets the exception continue to the top-level filter, which is here.
//! NOT covered, and stated so nobody reads silence as coverage:
//! - a Rust PANIC is not an exception. A worker's panic kills that thread
//!   only and is logged by the hook in `cli_main`; a main-thread panic
//!   exits with status 101 the ordinary way.
//! - a Rust ABORT (a panic while panicking, an allocation failure) goes
//!   through `__fastfail`, which skips every user-mode filter by design.
//!   Windows Error Reporting's LocalDumps is the only thing that sees it.
//!
//! HOW. `SetUnhandledExceptionFilter` installs [`filter`], and a thread
//! is spawned at install time to do the writing. The filter itself only
//! records the exception pointers and the faulting thread, signals the
//! writer and waits: the faulting thread may be out of stack (an
//! overflow) or holding the heap lock, so it must not allocate, format
//! or open a file. `MiniDumpWriteDump` is documented to be called from a
//! DIFFERENT thread for exactly that reason. The filter then returns
//! `EXCEPTION_CONTINUE_SEARCH`, so the process dies exactly as it did
//! before - same exit code, same WER behaviour - with one more file.
//! The writer is held to the same rule as far as it can be (the
//! faulting thread is parked holding whatever it held): the dump's path
//! is converted to UTF-16 at start and only copied at crash time, the
//! file is opened with `CreateFileW`, and its one log line goes to the
//! raw stderr handle rather than through `eprintln!`'s lock. It writes
//! under a `.part` name and renames on success, so a dump cut off by
//! the faulting thread's timeout is never kept as one.
//!
//! WHERE. Only once a data directory is known: `serve` hands over the
//! folder its settings file lives in, which is where every launcher puts
//! `daemon.log`, so the dump lands next to the log a user is asked for.
//! A CLI run with no data directory writes nothing. The newest
//! [`KEEP`] dumps are kept and older ones pruned at the next start, so a
//! crash loop cannot fill a disk.
//!
//! NEVER UPLOADED. Nothing here, or anywhere else, sends a dump off the
//! machine: it is a local file a user may choose to attach to an issue.
//! A dump holds stack memory, which can carry paths and fragments of
//! whatever a thread was handling, which is why it stays the user's call.
//!
//! OPT OUT with `NZBFAST_NO_MINIDUMP=1` (read once, at install). The
//! filter is then never installed and Windows behaves as before.

use std::path::{Path, PathBuf};

/// How many dumps are kept in the data directory. Five covers "it crashed
/// a few times this week" without letting a crash loop grow the folder.
pub(crate) const KEEP: usize = 5;

/// File-name prefix and suffix of a dump, and the only shape [`prune`]
/// ever deletes - a user's own `.dmp` in that folder is never touched.
const PREFIX: &str = "nzbfast-crash-";
const SUFFIX: &str = ".dmp";

/// The opt-out variable, `1`/`true` (any case) to disable.
#[cfg_attr(not(windows), expect(dead_code))]
pub(crate) const ENV: &str = "NZBFAST_NO_MINIDUMP";

/// Whether the opt-out value turns dumps off.
// Not #[expect]: dead in the non-Windows LIB build only; the unit
// tests below call it, so under cfg(test) an expectation goes unfulfilled.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn opted_out(value: Option<&str>) -> bool {
    value.is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Where one dump goes: `<dir>/nzbfast-crash-<unix secs>-<pid>.dmp`.
///
/// Seconds first and zero-padded, so a plain name sort is a time sort -
/// [`prune`] relies on that rather than on file times, which a copy or a
/// restore rewrites. The pid tells two processes that died in the same
/// second apart (a daemon and a CLI run sharing a folder). The reference
/// SHAPE only: the Windows writer builds the same name allocation-free
/// with [`dump_name_wide`], and the tests hold the two to each other.
#[cfg_attr(not(test), expect(dead_code))]
pub(crate) fn dump_path(dir: &Path, unix_secs: u64, pid: u32) -> PathBuf {
    dir.join(format!("{PREFIX}{unix_secs:012}-{pid}{SUFFIX}"))
}

/// Appended to a dump's name while it is being written; the writer
/// renames it away only once `MiniDumpWriteDump` has returned success.
const PART: &str = ".part";

/// Capacity, in UTF-16 units, of the stack buffer the writer thread
/// builds a dump's path in. Comfortably past `MAX_PATH`; a data
/// directory longer than this writes no dump at all.
// Not #[expect]: dead in the non-Windows LIB build only; the unit
// tests below use it, so under cfg(test) an expectation goes unfulfilled.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const NAME_CAP: usize = 2048;

/// The data directory as UTF-16 with a trailing separator, computed once
/// by [`set_dir`] so the writer thread never converts a path itself
/// (`Path::join` and `File::create` both allocate). A separator is added
/// only when the directory does not already end in one, as `join` does.
fn wide_dir_prefix(dir: &Path) -> Vec<u16> {
    #[cfg(windows)]
    let mut w: Vec<u16> = {
        use std::os::windows::ffi::OsStrExt;
        dir.as_os_str().encode_wide().collect()
    };
    #[cfg(not(windows))]
    let mut w: Vec<u16> = dir.to_string_lossy().encode_utf16().collect();
    let sep = |u: u16| u == u16::from(b'/') || u == u16::from(b'\\');
    if !w.last().copied().is_some_and(sep) {
        w.push(std::path::MAIN_SEPARATOR as u16);
    }
    w
}

/// [`dump_path`] built into `out` without allocating, NUL-terminated for
/// a Win32 call, with [`PART`] appended when `part`. Returns the length
/// before the NUL, or None when it does not fit.
// Not #[expect]: dead in the non-Windows LIB build only; the unit
// tests below call it, so under cfg(test) an expectation goes unfulfilled.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn dump_name_wide(
    prefix: &[u16],
    secs: u64,
    pid: u32,
    part: bool,
    out: &mut [u16],
) -> Option<usize> {
    struct W<'a> {
        out: &'a mut [u16],
        n: usize,
    }
    impl W<'_> {
        fn put(&mut self, u: u16) -> Option<()> {
            *self.out.get_mut(self.n)? = u;
            self.n += 1;
            Some(())
        }
        fn ascii(&mut self, s: &str) -> Option<()> {
            s.bytes().try_for_each(|b| self.put(u16::from(b)))
        }
        /// Decimal, most significant digit first, zero-padded to `width`
        /// exactly as `{:012}` pads (never truncating a longer number).
        fn digits(&mut self, mut v: u64, width: usize) -> Option<()> {
            let mut d = [0u8; 20];
            let mut k = 0;
            loop {
                d[k] = b'0' + (v % 10) as u8;
                k += 1;
                v /= 10;
                if v == 0 {
                    break;
                }
            }
            for _ in k..width {
                self.put(u16::from(b'0'))?;
            }
            d[..k]
                .iter()
                .rev()
                .try_for_each(|&b| self.put(u16::from(b)))
        }
    }
    let mut w = W { out, n: 0 };
    prefix.iter().try_for_each(|&u| w.put(u))?;
    w.ascii(PREFIX)?;
    w.digits(secs, 12)?;
    w.ascii("-")?;
    w.digits(u64::from(pid), 0)?;
    w.ascii(SUFFIX)?;
    if part {
        w.ascii(PART)?;
    }
    w.put(0)?;
    Some(w.n - 1)
}

/// Whether `name` is a dump this module wrote.
fn is_ours(name: &str) -> bool {
    name.strip_prefix(PREFIX)
        .and_then(|r| r.strip_suffix(SUFFIX))
        .is_some_and(|mid| {
            let mut it = mid.splitn(2, '-');
            matches!(
                (it.next(), it.next()),
                (Some(s), Some(p)) if s.len() == 12
                    && s.bytes().all(|b| b.is_ascii_digit())
                    && !p.is_empty()
                    && p.bytes().all(|b| b.is_ascii_digit())
            )
        })
}

/// Delete all but the newest `keep` dumps in `dir`; returns what is left,
/// oldest first. Best effort: an unreadable folder or a delete that fails
/// leaves things as they were, because nothing here may stop a start.
pub(crate) fn prune(dir: &Path, keep: usize) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut ours: Vec<PathBuf> = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if is_ours(name) {
            ours.push(e.path());
        } else if name.strip_suffix(PART).is_some_and(is_ours) {
            // A dump the process died in the middle of writing (the
            // faulting thread's wait ran out first). Never evidence and
            // never one of the kept: swept, and only ever our own shape.
            let _ = std::fs::remove_file(e.path());
        }
    }
    ours.sort();
    let excess = ours.len().saturating_sub(keep);
    for old in ours.drain(..excess) {
        let _ = std::fs::remove_file(old);
    }
    ours
}

/// The data directory a dump is written to, once `serve` knows it, as
/// [`wide_dir_prefix`] gives it: converted here, at start, so the writer
/// thread only copies it into a stack buffer.
static DIR: std::sync::Mutex<Option<Vec<u16>>> = std::sync::Mutex::new(None);

/// Tell the crash writer where the data directory is, prune old dumps,
/// and say once in the log if any are there. Called by `serve` as soon as
/// its settings path is resolved. Harmless on every platform: off Windows
/// nothing ever writes a dump, so the folder simply has none to report.
pub fn set_dir(dir: &Path) {
    let left = prune(dir, KEEP);
    if let Some(newest) = left.last() {
        tracing::info!(
            target: "crash",
            "{} crash dump(s) from earlier runs are in {} (newest: {}). They \
             stay on this machine; attach one to a bug report if you are asked",
            left.len(),
            dir.display(),
            newest.display()
        );
    }
    let wide = wide_dir_prefix(dir);
    if let Ok(mut g) = DIR.lock() {
        *g = Some(wide);
    }
}

/// Build the in-progress and final dump paths into `part` and `fin`
/// from the directory [`set_dir`] stored, without allocating: the lock
/// is a plain mutex nothing but `set_dir` (at start) ever takes, and the
/// stored prefix is copied, never cloned. False when no directory is
/// known or the names do not fit. Read only by the Windows writer.
#[cfg_attr(not(windows), expect(dead_code))]
fn dump_names(secs: u64, pid: u32, part: &mut [u16], fin: &mut [u16]) -> bool {
    let Ok(g) = DIR.lock() else {
        return false;
    };
    let Some(prefix) = g.as_deref() else {
        return false;
    };
    dump_name_wide(prefix, secs, pid, true, part).is_some()
        && dump_name_wide(prefix, secs, pid, false, fin).is_some()
}

/// Install the unhandled-exception filter and its writer thread. Call
/// once, early, from `cli_main`. A no-op off Windows and when opted out.
pub fn install() {
    // No early `return` here: off Windows the call below is stripped and a
    // trailing `return` trips clippy's needless_return on the host lint.
    #[cfg(windows)]
    if !opted_out(std::env::var(ENV).ok().as_deref()) {
        win::install();
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        EXCEPTION_POINTERS, MINIDUMP_EXCEPTION_INFORMATION, MiniDumpNormal, MiniDumpWithThreadInfo,
        MiniDumpWithUnloadedModules, MiniDumpWriteDump, SetUnhandledExceptionFilter,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, INFINITE,
        SetEvent, WaitForSingleObject,
    };

    /// `EXCEPTION_CONTINUE_SEARCH`: let the default handling (WER, the
    /// process exit code) run after us, so a dump is the only difference.
    const CONTINUE_SEARCH: i32 = 0;
    /// How long the faulting thread waits for the writer. A dump of a
    /// process this size takes well under a second; the cap only matters
    /// if the writer itself is wedged, and then the process must still die.
    const WRITE_WAIT_MS: u32 = 30_000;

    /// Signalled by the filter: "a dump is wanted, the pointers are set".
    static REQUEST: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    /// Signalled by the writer when the dump is on disk (or failed).
    static DONE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    static POINTERS: AtomicPtr<EXCEPTION_POINTERS> = AtomicPtr::new(std::ptr::null_mut());
    static FAULT_TID: AtomicU32 = AtomicU32::new(0);
    static WRITER_TID: AtomicU32 = AtomicU32::new(0);
    /// One dump per process: a second exception while the first is being
    /// handled (or in another thread a moment later) goes straight on.
    static FIRED: AtomicBool = AtomicBool::new(false);

    pub(super) fn install() {
        // SAFETY: plain Win32 calls with null security attributes and no
        // name; the handles are process-lifetime and never closed, because
        // the filter may need them at any moment until exit.
        let (req, done) = unsafe {
            (
                CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()),
                CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()),
            )
        };
        if req.is_null() || done.is_null() {
            return;
        }
        REQUEST.store(req, Ordering::Release);
        DONE.store(done, Ordering::Release);
        let (req_u, done_u) = (req as usize, done as usize);
        let spawned = std::thread::Builder::new()
            .name("nzbfast-crashdump".into())
            .spawn(move || writer(req_u, done_u));
        if spawned.is_err() {
            return;
        }
        // SAFETY: `filter` has the LPTOP_LEVEL_EXCEPTION_FILTER signature
        // and touches only atomics and two event handles that live for the
        // rest of the process.
        unsafe {
            SetUnhandledExceptionFilter(Some(filter));
        }
    }

    /// The writer thread: parked until a crash, then writes one dump.
    /// Handles travel as `usize` because a raw pointer is not `Send`.
    fn writer(req: usize, done: usize) {
        let (req, done) = (req as HANDLE, done as HANDLE);
        // SAFETY: trivially safe Win32 call.
        WRITER_TID.store(unsafe { GetCurrentThreadId() }, Ordering::Release);
        // SAFETY: `req` is a live event handle owned for the process's life.
        unsafe { WaitForSingleObject(req, INFINITE) };
        write_dump();
        // SAFETY: as above, for `done`.
        unsafe { SetEvent(done) };
    }

    /// Writes the dump WITHOUT ALLOCATING and without taking stderr's
    /// lock: the faulting thread is parked in `filter` and may hold
    /// either (a fault inside the allocator, or mid-`eprintln!`), and a
    /// writer that waits on it waits out `WRITE_WAIT_MS` and writes
    /// nothing. So the path is copied into stack buffers from the UTF-16
    /// prefix `set_dir` converted at start, the file is opened with
    /// `CreateFileW` rather than `File::create` (which converts the path
    /// on the heap), and the closing line goes to the raw stderr handle.
    /// `MiniDumpWriteDump` itself is dbghelp's and outside this rule.
    ///
    /// The dump is written under a `.part` name and renamed only on
    /// success, so one the process died in the middle of is never read
    /// as evidence or kept as one of the five; `prune` sweeps it.
    fn write_dump() {
        use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CREATE_ALWAYS, CreateFileW, DeleteFileW, FILE_ATTRIBUTE_NORMAL,
            MOVEFILE_REPLACE_EXISTING, MoveFileExW,
        };
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // SAFETY: trivially safe Win32 call.
        let pid = unsafe { GetCurrentProcessId() };
        let mut part = [0u16; super::NAME_CAP];
        let mut fin = [0u16; super::NAME_CAP];
        if !super::dump_names(secs, pid, &mut part, &mut fin) {
            return;
        }
        // SAFETY: `part` is a NUL-terminated UTF-16 path on this stack
        // frame; null security attributes and template are allowed.
        let file = unsafe {
            CreateFileW(
                part.as_ptr(),
                GENERIC_WRITE,
                0,
                std::ptr::null(),
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if file == INVALID_HANDLE_VALUE {
            return;
        }
        let info = MINIDUMP_EXCEPTION_INFORMATION {
            ThreadId: FAULT_TID.load(Ordering::Acquire),
            ExceptionPointers: POINTERS.load(Ordering::Acquire),
            // The pointers are in THIS process's address space.
            ClientPointers: 0,
        };
        // SAFETY: the process handle is the pseudo-handle for ourselves,
        // `file` is open for writing until the CloseHandle below, and
        // `info` points at the faulting thread's exception record, which
        // stays valid because that thread is blocked in `filter` until we
        // signal.
        let ok = unsafe {
            MiniDumpWriteDump(
                GetCurrentProcess(),
                pid,
                file,
                MiniDumpNormal | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules,
                &info,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        // SAFETY: `file` is the handle opened above, closed once. Both
        // paths are NUL-terminated buffers on this frame.
        let renamed = unsafe {
            CloseHandle(file);
            ok != 0 && MoveFileExW(part.as_ptr(), fin.as_ptr(), MOVEFILE_REPLACE_EXISTING) != 0
        };
        if !renamed {
            // A half-written dump is worse than none: it reads as evidence.
            // SAFETY: as above.
            unsafe { DeleteFileW(part.as_ptr()) };
            return;
        }
        // The raw stderr handle, not `eprintln!` (whose lock the faulting
        // thread may hold): the tray captures this into daemon.log, and
        // the next start's `set_dir` line names the file itself. Wrapped
        // in ManuallyDrop so the process's stderr handle is never closed.
        use std::io::Write as _;
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        let raw = std::io::stderr().as_raw_handle();
        if !raw.is_null() {
            // SAFETY: a live handle the process owns for its lifetime,
            // never closed here (ManuallyDrop).
            let f = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(raw) });
            let _ = (&*f).write_all(
                b"[crash] wrote a crash dump (nzbfast-crash-*.dmp) beside the settings file\r\n",
            );
        }
    }

    /// The top-level filter. Allocation-free: it may run on a thread with
    /// no stack left or one that holds the heap lock.
    unsafe extern "system" fn filter(info: *const EXCEPTION_POINTERS) -> i32 {
        if FIRED.swap(true, Ordering::AcqRel) {
            return CONTINUE_SEARCH;
        }
        // SAFETY: trivially safe Win32 call.
        let me = unsafe { GetCurrentThreadId() };
        // The writer crashing cannot wait for itself.
        if me == WRITER_TID.load(Ordering::Acquire) {
            return CONTINUE_SEARCH;
        }
        let (req, done) = (
            REQUEST.load(Ordering::Acquire),
            DONE.load(Ordering::Acquire),
        );
        if req.is_null() || done.is_null() {
            return CONTINUE_SEARCH;
        }
        POINTERS.store(info.cast_mut(), Ordering::Release);
        FAULT_TID.store(me, Ordering::Release);
        // SAFETY: both are live event handles for the process's lifetime.
        unsafe {
            SetEvent(req);
            WaitForSingleObject(done, WRITE_WAIT_MS);
        }
        CONTINUE_SEARCH
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The opt-out reads like every other `NZBFAST_NO_*` switch: `1` or
    /// `true` turns dumps off, and anything else - including the variable
    /// being absent - leaves them on.
    #[test]
    fn the_opt_out_takes_one_or_true() {
        assert!(opted_out(Some("1")));
        assert!(opted_out(Some("true")));
        assert!(opted_out(Some("TRUE")));
        assert!(!opted_out(None));
        assert!(!opted_out(Some("0")));
        assert!(!opted_out(Some("")));
        assert!(!opted_out(Some("yes please")));
    }

    /// A dump is named so that a NAME sort is a TIME sort (the seconds are
    /// zero-padded to twelve digits, past the year 33,000), it lands in the
    /// directory it was given, and `prune` recognises exactly that shape.
    #[test]
    fn a_dump_path_sorts_by_time_and_is_recognised() {
        let dir = Path::new("/data/nzbfast");
        let a = dump_path(dir, 999, 42);
        let b = dump_path(dir, 1_762_700_000, 7);
        assert_eq!(a.parent(), Some(dir));
        assert_eq!(
            a.file_name().unwrap().to_str().unwrap(),
            "nzbfast-crash-000000000999-42.dmp"
        );
        assert!(a < b, "an earlier crash must sort first: {a:?} {b:?}");
        for p in [&a, &b] {
            assert!(is_ours(p.file_name().unwrap().to_str().unwrap()), "{p:?}");
        }
        for not in [
            "nzbfast-crash-.dmp",
            "nzbfast-crash-123-4.dmp",
            "nzbfast-crash-000000000999-.dmp",
            "nzbfast-crash-000000000999-42.dmp.txt",
            "my-own.dmp",
            "daemon.log",
        ] {
            assert!(!is_ours(not), "{not} must never be pruned as ours");
        }
    }

    /// Pruning keeps the newest `keep` dumps and nothing else of ours,
    /// and never touches a file it did not write - a user's own `.dmp`
    /// in the data folder, or the log beside it.
    #[test]
    fn prune_keeps_the_newest_and_only_touches_its_own() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-crashdump-prune-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for s in 1..=7u64 {
            std::fs::write(dump_path(&dir, s * 100, 9), b"x").unwrap();
        }
        std::fs::write(dir.join("my-own.dmp"), b"mine").unwrap();
        std::fs::write(dir.join("daemon.log"), b"log").unwrap();

        let left = prune(&dir, 5);
        let want: Vec<PathBuf> = (3..=7u64).map(|s| dump_path(&dir, s * 100, 9)).collect();
        assert_eq!(left, want, "the five newest, oldest first");
        for s in 1..=2u64 {
            assert!(!dump_path(&dir, s * 100, 9).exists(), "old dump {s} kept");
        }
        assert!(dir.join("my-own.dmp").exists());
        assert!(dir.join("daemon.log").exists());
        // Idempotent, and a missing folder is an empty answer, not a panic.
        assert_eq!(prune(&dir, 5), want);
        assert!(prune(&dir.join("absent"), 5).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A dump is written under a `.part` name and renamed only once it
    /// is complete, so one the process died in the middle of (the writer
    /// still going when the faulting thread's wait ran out) is never
    /// taken for evidence and never counts toward the five kept. The
    /// next start sweeps those leftovers, and still only its own.
    #[test]
    fn prune_sweeps_unfinished_dumps_and_never_counts_them() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-crashdump-part-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let done = dump_path(&dir, 500, 9);
        std::fs::write(&done, b"x").unwrap();
        let mut part = done.clone().into_os_string();
        part.push(".part");
        let part = PathBuf::from(part);
        std::fs::write(&part, b"half").unwrap();
        std::fs::write(dir.join("my-own.dmp.part"), b"mine").unwrap();

        let left = prune(&dir, 5);
        assert_eq!(left, vec![done], "a finished dump only");
        assert!(!part.exists(), "an unfinished dump of ours is swept");
        assert!(dir.join("my-own.dmp.part").exists(), "never a user's file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The writer thread builds both names into a stack buffer, with no
    /// allocation (the faulting thread may hold the heap lock), and they
    /// must be exactly the names [`dump_path`] gives and [`prune`] reads.
    #[test]
    fn the_wide_dump_names_match_dump_path() {
        for dir in [Path::new("/data/nzbfast"), Path::new("/data/nzbfast/")] {
            let prefix = wide_dir_prefix(dir);
            for (secs, pid) in [(999u64, 42u32), (1_762_700_000, 7), (u64::MAX, u32::MAX)] {
                let mut buf = [0u16; NAME_CAP];
                let want = dump_path(dir, secs, pid);
                let n = dump_name_wide(&prefix, secs, pid, false, &mut buf).expect("fits");
                assert_eq!(
                    String::from_utf16(&buf[..n]).unwrap(),
                    want.to_str().unwrap()
                );
                assert_eq!(buf[n], 0, "NUL-terminated for the Win32 call");
                let n = dump_name_wide(&prefix, secs, pid, true, &mut buf).expect("fits");
                assert_eq!(
                    String::from_utf16(&buf[..n]).unwrap(),
                    format!("{}{PART}", want.to_str().unwrap())
                );
            }
        }
        // A directory too long for the buffer writes no dump rather than
        // a truncated path somewhere else.
        let long = wide_dir_prefix(Path::new(&"d".repeat(NAME_CAP)));
        let mut buf = [0u16; NAME_CAP];
        assert_eq!(dump_name_wide(&long, 1, 1, false, &mut buf), None);
    }
}
