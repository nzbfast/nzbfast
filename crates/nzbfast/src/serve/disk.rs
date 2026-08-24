//! The rolling daily/monthly quota ledger, and the park that holds a
//! job off a full disk.
//!
//! The free-space measurement these are built on (`disk_stat`,
//! `disk_stat_walk`, `free_bytes`) moved to `crate::diskfree` in TODO
//! 276 item 3 and is re-exported below: it is asked by four modules
//! that owe the daemon nothing, and answering them from here made them
//! depend on it. What is left is daemon state.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

// The measurement itself moved to `crate::diskfree` (TODO 276 item 3);
// re-exported through this module's glob so every `serve` caller still
// spells it `free_bytes` / `disk_stat` / `disk_stat_walk`.
pub(crate) use crate::diskfree::{disk_stat_walk, free_bytes};

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
