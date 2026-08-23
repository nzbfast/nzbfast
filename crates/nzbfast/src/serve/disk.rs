//! Free-space measurement (one `disk_stat` per platform, plus the
//! walk-upward fallback for a directory that does not exist yet) and the
//! rolling daily/monthly quota ledger built on it.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// (free, total) bytes of the filesystem holding `path`.
#[cfg(all(unix, not(target_os = "macos")))]
pub(super) fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
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
pub(super) fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
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
pub(super) fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
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
    let ok =
        unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, std::ptr::null_mut()) };
    (ok != 0).then_some((free, total))
}
#[cfg(not(any(unix, windows)))]
pub(super) fn disk_stat(_path: &std::path::Path) -> Option<(u64, u64)> {
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
/// the disk holds, parsed once from `NZBFAST_TEST_FREE_BYTES`.
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
/// Parsed ONCE and cached: the value must not change under a job that
/// measured it at the top of its tail, and a per-call `getenv` on a
/// path the min-free guard polls is a syscall nobody asked for. Unset
/// (the shipped case, and every case that is not a test) the cache
/// holds `None` and this is one relaxed load ahead of the real walk.
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
fn free_bytes_override() -> Option<u64> {
    static OVERRIDE: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *OVERRIDE.get_or_init(|| {
        let v = std::env::var("NZBFAST_TEST_FREE_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok());
        if let Some(free) = v {
            tracing::warn!(
                target: "disk",
                "NZBFAST_TEST_FREE_BYTES is set: every free-space reading in this \
                 process is {free} bytes, not what the filesystem says"
            );
        }
        v
    })
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

/// Downloaded-bytes ledger for the quota window, persisted in the spool
/// so restarts don't forget a spent budget.
pub(super) struct QuotaLedger {
    pub(super) path: PathBuf,
    pub(super) period: char,
    pub(super) start: u64,
    pub(super) bytes: u64,
}

impl QuotaLedger {
    pub(super) fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Today's civil date (year, month, day) in the machine's LOCAL
    /// timezone - people budget a quota around their own calendar, and
    /// SABnzbd and NZBGet both reset on local time (issue #25). Falls
    /// back to UTC where local time isn't available, same as
    /// `local_minute_of_week`.
    fn local_civil_today() -> (i64, u32, u32) {
        #[cfg(unix)]
        {
            let t = Self::now() as libc::time_t;
            let mut tm: libc::tm = unsafe { std::mem::zeroed() };
            // localtime_r does not imply tzset (POSIX) - without it,
            // macOS ignores a TZ set on the environment, and TZ is how
            // Docker users pin their timezone. Not in the libc crate,
            // so declared here.
            unsafe extern "C" {
                fn tzset();
            }
            unsafe { tzset() };
            if !unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
                return (
                    tm.tm_year as i64 + 1900,
                    tm.tm_mon as u32 + 1,
                    tm.tm_mday as u32,
                );
            }
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::SYSTEMTIME;
            use windows_sys::Win32::System::SystemInformation::GetLocalTime;
            let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
            unsafe { GetLocalTime(&mut st) };
            if st.wYear != 0 {
                return (st.wYear as i64, st.wMonth as u32, st.wDay as u32);
            }
        }
        civil_from_days((Self::now() / 86_400) as i64)
    }

    /// Identity token for the current quota period: daily quotas roll at
    /// LOCAL midnight, weekly ones on the local Monday, monthly ones on
    /// the local 1st. Encoded as days*86_400 of the period's first
    /// (local) civil day - a pure function of the civil date, so it is
    /// stable across DST shifts inside a period, and identical to the
    /// old UTC-based values on a UTC machine, so upgrading doesn't
    /// spuriously reset the ledger.
    pub(super) fn period_start(period: char) -> u64 {
        Self::period_start_on(period, Self::local_civil_today())
    }

    /// The pure half of `period_start` - see the timezone-boundary tests.
    pub(super) fn period_start_on(period: char, (y, m, d): (i64, u32, u32)) -> u64 {
        // A clock set before 1970 gives negative days; the straight
        // `as u64` cast wrapped huge and the multiply overflowed (debug
        // panic in the download runner's tick). Clamp to epoch - the
        // token only has to CHANGE when the period rolls.
        let days = match period {
            'm' => days_from_civil(y, m, 1),
            // §129 2g: back to the most recent Monday. Epoch day 0 was
            // a Thursday, so (days + 3) mod 7 is the Monday-based
            // weekday; rem_euclid keeps pre-epoch dates from going
            // negative before the clamp.
            'w' => {
                let days = days_from_civil(y, m, d);
                days - (days.rem_euclid(7) + 3) % 7
            }
            _ => days_from_civil(y, m, d),
        };
        days.max(0) as u64 * 86_400
    }

    pub(super) fn open(spool: &std::path::Path, period: char) -> Self {
        let path = spool.join("quota.json");
        let mut led = QuotaLedger {
            path,
            period,
            start: Self::period_start(period),
            bytes: 0,
        };
        // Opened from the download runner's tick, which is a tokio task:
        // the read (and the .bak refresh it may write) is disk IO that
        // must not run undemoted on a worker thread.
        if let Some(v) =
            crate::persist::blocking_db(|| crate::persist::load_json_with_backup(&led.path))
        {
            let start = v["start"].as_u64().unwrap_or(0);
            // Migration (issue #25 follow-up): pre-local ledgers tokened
            // the UTC civil date. On a non-UTC machine the local token
            // differs around the timezone boundary, and refusing the
            // saved bytes would grant a metered account a second
            // allowance inside the same billing window. A LEGACY ledger
            // (no "local" marker) whose token matches what the old
            // scheme would compute right now is the current period's
            // spend - carry it into the local window. New-format
            // ledgers stay strict equality: a stale one from yesterday
            // must not ride a coincidental UTC-token match.
            let keep = Self::carry_persisted(
                start,
                v["local"].as_bool().unwrap_or(false),
                led.start,
                Self::period_start_on(period, civil_from_days((Self::now() / 86_400) as i64)),
            );
            if keep {
                led.bytes = v["bytes"].as_u64().unwrap_or(0);
            }
        }
        led
    }

    /// Whether a persisted ledger's bytes belong to the CURRENT period.
    /// `new_start` is today's local-calendar token; `legacy_now_start`
    /// is the token the pre-#25 UTC scheme would compute right now.
    /// A new-format ledger (`is_local`) must match exactly - a stale
    /// one from yesterday must not ride a coincidental UTC match. A
    /// LEGACY ledger also carries when it matches the legacy scheme's
    /// current token: same wall-clock window, written by the old code
    /// moments before the upgrade - dropping it granted a metered
    /// account a second allowance inside one billing window.
    pub(super) fn carry_persisted(
        persisted: u64,
        is_local: bool,
        new_start: u64,
        legacy_now_start: u64,
    ) -> bool {
        persisted == new_start || (!is_local && persisted == legacy_now_start)
    }

    /// Roll the window if a new period began; returns bytes spent so far.
    pub(super) fn spent(&mut self) -> u64 {
        let cur = Self::period_start(self.period);
        if cur != self.start {
            self.start = cur;
            self.bytes = 0;
            self.save();
        }
        self.bytes
    }

    pub(super) fn add(&mut self, n: u64) {
        self.spent();
        self.bytes += n;
        self.save();
    }

    pub(super) fn save(&self) {
        // "local": the format marker the migration path in `open` keys
        // off. A ledger without it predates the local-calendar tokens
        // (issue #25) and may carry a UTC-day token instead.
        let _ = crate::persist::write_atomic(
            &self.path,
            json!({"start": self.start, "bytes": self.bytes, "local": true})
                .to_string()
                .as_bytes(),
        );
    }
}

/// (year, month, day) from days-since-epoch - Howard Hinnant's civil
/// calendar algorithm, used for monthly quota rollover.
pub(super) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days-since-epoch from (year, month, day) - the inverse of
/// `civil_from_days`, same Hinnant civil-calendar algorithm.
pub(super) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - (m <= 2) as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Mid-download disk full (the fast halt in get/workers.rs): when the
/// min-free guard is armed AND the output volume is still under its
/// floor, prefer the guard's existing hold over a hard Failed - the job
/// goes back to the queue like a pause, the runner's own pick gate then
/// pauses everything with the live "disk" hold until space frees, and
/// the resume continues from the journal without refetching a byte.
/// Returns true when the job was parked (the caller returns). False =
/// guard off, probe unavailable, or space already freed: the caller
/// falls through and files the distinct failure instead - requeueing
/// then would just re-pick and re-fail in a loop (a quota or a
/// read-only share never comes back on its own). Lifted verbatim out of
/// `spawn_download_worker`'s tail task in tasks.rs for the size gate
/// (the §91 rule: the gate forces fixes into helpers), and it lives
/// with the free-space measurement it is built on.
pub(crate) async fn park_on_full_disk(
    d: &Arc<Daemon>,
    job: &Arc<Mutex<Job>>,
    err: Option<&anyhow::Error>,
    on_disk_bytes: u64,
) -> bool {
    let disk_full_hold = err.is_some_and(|e| crate::serve::disk_full_mid_download(&e.to_string()))
        && !job.lock_ok().tombstone
        && {
            let min = d.min_free.load(Ordering::Relaxed);
            min > 0 && {
                let out = d.out_dir();
                let probe = tokio::task::spawn_blocking(move || free_bytes(&out));
                matches!(
                    tokio::time::timeout(std::time::Duration::from_secs(2), probe).await,
                    Ok(Ok(Some(free))) if free < min
                )
            }
        };
    if !disk_full_hold {
        return false;
    }
    {
        let mut j = job.lock_ok();
        j.state = JobState::Queued;
        j.downloaded_bytes = on_disk_bytes;
        // Same as the pause requeue: the abort's whyslow verdict and
        // tail figures belong to the stint that stopped, not the job.
        j.clear_attempt_verdicts();
        info!(
            target: "guard",
            "{} stopped on a full disk - parked back in the queue \
             ({:.2} GB already on disk); the min-free hold takes it \
             from here",
            j.nzo_id,
            on_disk_bytes as f64 / 1e9
        );
    }
    d.note_event(
        "disk",
        "a download stopped early because the disk filled - it is \
         back in the queue and resumes once space is freed"
            .to_string(),
    );
    d.save_queue();
    true
}
