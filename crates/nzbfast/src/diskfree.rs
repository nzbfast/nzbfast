//! Free-space measurement: one `disk_stat` per platform, the
//! walk-upward fallback for a directory that does not exist yet, and
//! the `free_bytes` every guard in the crate actually asks.
//!
//! At the crate root rather than under `serve/` since TODO 276 item 3.
//! Four modules that have nothing to do with the daemon - `eatvol`,
//! `get`, `lanegate` and `rarfix` - ask how much room is left before
//! they commit to writing, and reaching `crate::serve::free_bytes` to
//! do it put all four inside the dependency cycle `serve` sits in. The
//! quota ledger BUILT on this stayed in `serve/disk.rs`, which is
//! genuinely daemon state.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 before that; the code
//! is still verbatim, only visibility and address have changed.

/// (free, total) bytes of the filesystem holding `path`.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: libc::statvfs is a plain C struct of integers, so the
    // zeroed value is a valid one; it is only read below after the call
    // that fills it returned 0.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: the path is a NUL-terminated CString that outlives the
    // call, and the out-parameter is a live local of exactly the type
    // the signature names. Spelled out per block rather than once for
    // the function: this arm is `cfg(all(unix, not(macos)))`, so no mac
    // or Windows lane compiles it and `undocumented_unsafe_blocks` fires
    // only on the Linux `check` job - which is what held main red.
    (unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0).then(|| {
        (
            s.f_bavail as u64 * s.f_frsize as u64,
            s.f_blocks as u64 * s.f_frsize as u64,
        )
    })
}
/// macOS carries statvfs block counts in a 32-bit `fsblkcnt_t`, so a
/// volume past 2^32 blocks (16 TiB at APFS's 4 KiB) wraps and we read a
/// number reduced modulo that: a 22 TB drive measures 4.4 TB, and free
/// can come out LARGER than total. Everything downstream believes it -
/// the dashboard, the SAB/nzbget diskspace fields the *arrs read, the
/// min-free guard, and the extraction bomb budget, which then aborts a
/// healthy unpack as a "decompression bomb" on a disk with terabytes
/// spare. statfs(2) reports the same counts in uint64_t fields, and its
/// f_bsize is the same allocation block size, so ask it instead.
#[cfg(target_os = "macos")]
pub(crate) fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `libc::statfs` is a C struct of integers and fixed-size
    // char arrays, so all-zero is a valid bit pattern for it, and the
    // call below fills it before any field is read.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a live `CString` that outlives the call, so
    // `c.as_ptr()` is a valid NUL-terminated path; `&mut s` is a live,
    // exclusively borrowed struct of exactly the type statfs(2) writes.
    // The fields are only read on the `== 0` success path.
    (unsafe { libc::statfs(c.as_ptr(), &mut s) } == 0)
        .then(|| (s.f_bavail * s.f_bsize as u64, s.f_blocks * s.f_bsize as u64))
}
/// Windows has no statvfs. GetDiskFreeSpaceExW takes a directory (a
/// file path fails, which the ancestor walk in `free_bytes` absorbs by
/// stepping up) and answers per-volume, including for UNC shares and
/// mounted folders - so a download dir on a mapped NAS is measured on
/// the NAS, not on C:.
///
/// "Free" is bytes-available-TO-THE-CALLER, the statvfs f_bavail
/// analogue: under a disk quota that is the number the guard must use,
/// since it's what this process can actually write.
#[cfg(windows)]
pub(crate) fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    // An interior NUL would silently truncate the path and measure the
    // wrong volume; reject rather than answer about somewhere else.
    if wide.contains(&0) {
        return None;
    }
    wide.push(0);
    let (mut free, mut total) = (0u64, 0u64);
    // SAFETY: `wide` is a live NUL-terminated UTF-16 buffer (the push
    // above supplies the terminator, and an interior NUL was rejected),
    // and the two out-pointers are live, exclusively borrowed `u64`s -
    // exactly the ULARGE_INTEGER the API writes. The third out-pointer
    // is optional and NULL is the documented way to decline it. The
    // values are only read on the success path.
    let ok =
        unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, std::ptr::null_mut()) };
    (ok != 0).then_some((free, total))
}
#[cfg(not(any(unix, windows)))]
pub(crate) fn disk_stat(_path: &std::path::Path) -> Option<(u64, u64)> {
    None
}

/// Free bytes of the filesystem that holds - or will hold - `path`.
///
/// `statvfs` needs a path that EXISTS, and the output directory often
/// doesn't yet: first run before anything has been downloaded, a
/// per-category subfolder created at job time, or (the dangerous one) a
/// NAS mount point whose share isn't mounted. A bare `disk_stat` returns
/// None there, and None silently DISABLES the min-free guard - the
/// download then fills the very disk the guard was set up to protect.
/// The filesystem that will hold `path` is the one holding its nearest
/// existing ancestor, so fall back to asking that.
pub(crate) fn free_bytes(path: &std::path::Path) -> Option<u64> {
    if let Some(fake) = free_bytes_override() {
        return Some(fake);
    }
    disk_stat_walk(path).map(|(free, _)| free)
}

/// Test-only injection seam: what every caller of [`free_bytes`] is told
/// the disk holds, read from `NZBFAST_TEST_FREE_BYTES`.
///
/// TODO 222. The decompression-bomb guard is a FREE-SPACE test - the
/// native pass budgets `free - EXTRACT_RESERVE` and
/// [`crate::rarfix::preflight::declared_exceeds_free`] compares the
/// declared unpacked size against the same number - so the only way to
/// reach either refusal is to be on a disk too small for the archive.
/// The 22 Aug 2026 repro did that with a 1.5 GB APFS sparse image and a
/// 2 GB-of-zeros RAR5, and nothing in CI could follow: a tmpfs of a
/// chosen size needs root on Linux, `hdiutil` on macOS, and neither
/// exists on the Windows runners. Injecting the ANSWER is portable
/// everywhere, and it is the same number the whole ladder reads, so the
/// routes it drives are the production routes.
///
/// An env var rather than a process-local cell (the shape
/// `requeue_gate_barrier` and `Extractor::seed_dropped_volume` take)
/// because the test that needs it is a DAEMON test: the ladder runs in
/// a spawned `nzbfast` binary, and a cell in the test process cannot
/// reach it. That is the same reasoning - and the same rung of the same
/// argument - as `NZBFAST_TEST_FORBID_UNRAR`, which the integration
/// suites set per spawned child for exactly this reason (see
/// [`crate::rarfix::external_unrar_closed`]).
///
/// Scoped to `free_bytes` and NOT to [`disk_stat_walk`] beside it, so
/// the injection moves the GUARDS (min-free, the bomb budget, the
/// preflight, the eating forecast) and leaves the (free, total) pair
/// the dashboard and the NZBGet status report render alone. A test that
/// wants to see the daemon's own reading of the real disk still can.
///
/// Announced on the log the first time it is read, because a daemon
/// whose free-space guards are reading fiction must say so - and it is
/// how the daemon suite proves the seam is armed in the spawned
/// process at all.
///
/// # Two spellings, and why the second one exists
///
/// A BARE INTEGER is the original and is unchanged in every respect:
/// parsed once, cached, and answered to every caller on every thread
/// for the life of the process. The value must not change under a job
/// that measured it at the top of its tail, and a per-call `getenv` on
/// a path the min-free guard polls is a syscall nobody asked for.
///
/// A COMMA-SEPARATED SCHEDULE (`"9000000000,200000000"`) answers its
/// entries in read order and then STAYS on the last one. It exists for
/// the one contract a fixed number provably cannot reach: the third
/// rung of the named-RAR arm ([`crate::rarfix::try_rar_rr_repair_why`],
/// TODO §249 item 1) is entered only when the two attempts above it
/// failed for a reason that was NOT the disk, so any number low enough
/// to bomb the third bombs the first and the job never arrives. §249's
/// closing note is explicit that proving that rung end to end needs a
/// seam that can answer differently on successive reads, and this is
/// it: roomy while the ladder discovers the archive is damaged, tight
/// once the recovery records have put it right.
///
/// The schedule is consumed PER THREAD, and that is the whole reason it
/// is usable in a live daemon rather than only in a unit test. The
/// ladder's rungs run one after another on ONE blocking thread (the
/// tail runs under `off_worker`), while the daemon's own free-space
/// readers - the min-free park probe, the download runner's tick, the
/// indexer's headroom check and the SAB status handler - poll from
/// others at a rate no test can predict. A single global cursor would
/// be eaten by those pollers before the ladder reached its second rung.
/// Per-thread, every one of them sees entry one, which is the roomy
/// answer, so the min-free hold stands down exactly as the bare-integer
/// spelling arranges it to.
///
/// A changing answer breaks the invariant the paragraph above states,
/// deliberately and only under a test that OWNS the schedule: the
/// authoring test drives one job through one ladder and asserts the
/// route the verdict came out of, so a rung that starts reading free
/// space one more or one fewer time fails that test loudly rather than
/// quietly moving which rung refuses. Each consumed entry says so on
/// the log with its ordinal, which is what makes the failure a
/// one-line diagnosis. Unset - the shipped case, and every case that is
/// not a test - the cache holds `None`, no thread-local is touched, and
/// this stays one relaxed load ahead of the real walk.
fn free_bytes_override() -> Option<u64> {
    match free_bytes_injection()? {
        FreeInjection::Fixed(free) => Some(*free),
        FreeInjection::Schedule(steps) => Some(schedule_step(steps)),
    }
}

/// What `NZBFAST_TEST_FREE_BYTES` parsed to, once, for the process.
///
/// A schedule of ONE entry is a [`FreeInjection::Fixed`], not a
/// one-entry schedule: the two are indistinguishable in what they
/// answer, and collapsing them keeps the bare-integer spelling off the
/// thread-local and off the per-read log line entirely.
enum FreeInjection {
    Fixed(u64),
    Schedule(Vec<u64>),
}

/// Parse and announce, once. An entry that is not a `u64` voids the
/// whole variable, which is what a bare unparseable value has always
/// done - a seam nobody can see is worse than no seam.
fn free_bytes_injection() -> Option<&'static FreeInjection> {
    static OVERRIDE: std::sync::OnceLock<Option<FreeInjection>> = std::sync::OnceLock::new();
    OVERRIDE
        .get_or_init(|| {
            let raw = std::env::var("NZBFAST_TEST_FREE_BYTES").ok()?;
            let steps: Option<Vec<u64>> = raw
                .split(',')
                .map(|v| v.trim().parse::<u64>().ok())
                .collect();
            match steps?.as_slice() {
                [] => None,
                [free] => {
                    tracing::warn!(
                        target: "disk",
                        "NZBFAST_TEST_FREE_BYTES is set: every free-space reading in this \
                         process is {free} bytes, not what the filesystem says"
                    );
                    Some(FreeInjection::Fixed(*free))
                }
                steps => {
                    tracing::warn!(
                        target: "disk",
                        "NZBFAST_TEST_FREE_BYTES is set to a schedule: successive free-space \
                         readings on each thread answer {steps:?} bytes and then stay on the \
                         last, not what the filesystem says"
                    );
                    Some(FreeInjection::Schedule(steps.to_vec()))
                }
            }
        })
        .as_ref()
}

/// The schedule's answer for THIS read on THIS thread, and the log line
/// that makes a misplaced entry diagnosable.
///
/// Sticky at the last entry rather than falling back to the real disk:
/// a schedule that ran out and started telling the truth would make the
/// guards flip back mid-job, on a box whose real free space nothing in
/// the test knows.
fn schedule_step(steps: &[u64]) -> u64 {
    thread_local! {
        static READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }
    let n = READS.with(|c| {
        let n = c.get();
        c.set(n.saturating_add(1));
        n
    });
    let free = steps[n.min(steps.len() - 1)];
    // Bounded by the schedule's own length, so the pollers that never
    // leave entry one contribute one line each and the ladder's thread
    // contributes exactly as many as there are entries to place.
    if n < steps.len() {
        tracing::warn!(
            target: "disk",
            "NZBFAST_TEST_FREE_BYTES schedule: free-space reading {} on thread {:?} answers \
             {free} bytes",
            n + 1,
            std::thread::current().id()
        );
    }
    free
}

/// (free, total) of the filesystem that holds - or will hold - `path`,
/// via the same nearest-existing-ancestor walk. The dashboard and the
/// NZBGet-compat status report went through bare `disk_stat` instead
/// and turned "directory not created yet" into "0 MB free on disk" -
/// which the *arrs read as a full disk.
pub(crate) fn disk_stat_walk(path: &std::path::Path) -> Option<(u64, u64)> {
    let mut p = path;
    loop {
        if let Some(stat) = disk_stat(p) {
            return Some(stat);
        }
        p = match p.parent() {
            // A relative path runs out of ancestors at ""; the cwd is the
            // filesystem it resolves against.
            Some(q) if q.as_os_str().is_empty() => std::path::Path::new("."),
            Some(q) => q,
            None => return None,
        };
        if p == std::path::Path::new(".") {
            return disk_stat(p);
        }
    }
}
