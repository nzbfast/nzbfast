//! The machine's LOCAL civil time - the one clock the weekly scheduler
//! and the quota ledger both have to read the same way.
//!
//! They used to have a `#[cfg(unix)]` block each, and the two had
//! already drifted apart in both directions. The quota ledger called
//! `tzset()` before `localtime_r` (POSIX does not imply it, and without
//! it macOS ignores a `TZ` set on the environment - which is how a
//! container pins its timezone) and the scheduler did not; the quota
//! ledger carried a `#[cfg(windows)]` `GetLocalTime` arm and the
//! scheduler carried **no Windows arm at all**, so every Windows build
//! ran its weekly schedule on UTC while `web/dashboard.html` and
//! `docs/MANUAL.html` both promised the machine's local time. A rule
//! entered as 09:00 in New York fired at 05:00, and rules near midnight
//! picked the wrong local weekday. Found by the 10 September 2026
//! read-only sweep, whose write-up is in the private tree.
//!
//! One copy, so a platform arm added for one caller cannot go missing
//! for the other. Everything here is either a pure function of an
//! injected offset - which is what makes a non-UTC timezone testable on
//! a UTC build box - or the single platform call that reads the real
//! one.

use crate::logging::civil_from_days;

/// Broken-down civil time: the fields a person reads off a wall clock.
///
/// Deliberately not a timestamp: the whole point of this type is the
/// LOCAL rendering, and turning one back into a unix second needs the
/// timezone database that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    /// 1..=12.
    pub month: u32,
    /// 1..=31.
    pub day: u32,
    /// 0..=23.
    pub hour: u32,
    /// 0..=59.
    pub minute: u32,
    /// Monday = 0 .. Sunday = 6 - the numbering `SchedEntry::days` uses,
    /// and the reason neither platform arm can hand back its own.
    pub weekday_mon0: u32,
}

impl Civil {
    /// Minute-of-week: Monday 00:00 = 0 .. Sunday 23:59 = 10079.
    pub fn minute_of_week(&self) -> u32 {
        self.weekday_mon0 * 1440 + self.hour * 60 + self.minute
    }

    /// (year, month, day), for the callers that only budget by date.
    pub fn date(&self) -> (i64, u32, u32) {
        (self.year, self.month, self.day)
    }
}

/// Civil time `offset_secs` east of UTC at `unix_secs`.
///
/// Pure, and the seam the timezone tests are written against: a UTC
/// build box cannot be moved to New York, but it can be asked what
/// -4 * 3600 makes of a given second. `offset_secs` is a whole UTC
/// offset including whatever DST rule was in force - this function has
/// no timezone database and does not want one.
pub fn civil_at_offset(unix_secs: i64, offset_secs: i64) -> Civil {
    let local = unix_secs.saturating_add(offset_secs);
    let days = local.div_euclid(86_400);
    let secs = local.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        hour: (secs / 3600) as u32,
        minute: (secs / 60 % 60) as u32,
        // 1970-01-01 was a Thursday, which is 3 in Monday-zero numbering.
        weekday_mon0: (days + 3).rem_euclid(7) as u32,
    }
}

/// Civil time at UTC - the control arm, and the fallback below.
pub fn utc_civil(unix_secs: i64) -> Civil {
    civil_at_offset(unix_secs, 0)
}

/// Seconds since the unix epoch, or 0 if the system clock is before it.
pub fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The machine's local civil time RIGHT NOW, or `None` on a platform
/// with no arm here (and on a Unix box whose `localtime_r` fails).
///
/// "Now" and not "at `t`" on purpose: Windows answers this with
/// `GetLocalTime`, which only ever reports the current moment, and an
/// argument this function could not honour there would be a lie the
/// type system would not catch. Both callers want now.
pub fn local_civil_now() -> Option<Civil> {
    #[cfg(unix)]
    {
        // `as _` and NOT `as libc::time_t`, which is DEPRECATED on
        // musl: libc's alias is still 32-bit on 32-bit musl while musl
        // itself went 64-bit in 1.2.0, so libc has announced it will
        // change the alias (libc #1848) and warns at every naming of it.
        // The warning fires on musl ONLY, so no documented local line and
        // no CI job in this repo could see it - it was found in an
        // aarch64-musl build log on 17 Sep 2026 and is why the musl-cross
        // job in nightly.yml builds with `-D warnings`.
        //
        // Hardcoding a width is the wrong fix in BOTH directions: `i64`
        // is a type mismatch on 32-bit musl today (libc's alias there is
        // i32), and `i32` breaks everywhere else. `as _` takes its target
        // from `localtime_r`'s own signature below, so it is whatever the
        // libc we link says today and whatever it says after the change.
        let t = unix_secs() as _;
        // SAFETY: `libc::tm` is a plain C struct of integers and a
        // pointer; all-zero is a valid bit pattern for it, and
        // localtime_r overwrites it before anything is read.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // localtime_r does not imply tzset (POSIX) - without it, macOS
        // ignores a TZ set on the environment, and TZ is how Docker
        // users pin their timezone. Not in the libc crate, so declared
        // here.
        // SAFETY: this signature matches POSIX's `void tzset(void)`
        // exactly, so the declaration cannot disagree with the libc the
        // process links (which is also what `clashing_extern_declarations`
        // is denied workspace-wide to keep true).
        unsafe extern "C" {
            fn tzset();
        }
        // SAFETY: tzset takes no arguments and touches no memory of
        // ours; it only reads TZ and updates libc's own timezone state,
        // which localtime_r below is the consumer of.
        unsafe { tzset() };
        // SAFETY: both pointers are live locals of the expected types
        // and cannot overlap (one is an exclusive borrow).
        if !unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
            return Some(Civil {
                year: tm.tm_year as i64 + 1900,
                month: tm.tm_mon as u32 + 1,
                day: tm.tm_mday as u32,
                hour: tm.tm_hour as u32,
                minute: tm.tm_min as u32,
                // tm_wday: 0 = Sunday.
                weekday_mon0: (tm.tm_wday as u32 + 6) % 7,
            });
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::SYSTEMTIME;
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        // SAFETY: SYSTEMTIME is a struct of sixteen u16 fields, so
        // all-zero is a valid bit pattern, and GetLocalTime fills it
        // before anything is read.
        let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
        // SAFETY: `&mut st` is a live, exclusively borrowed SYSTEMTIME -
        // the one thing GetLocalTime requires - and the call only writes
        // to it.
        unsafe { GetLocalTime(&mut st) };
        // wYear == 0 is not a date Windows can be in; it is the shape a
        // zeroed struct keeps if the call did nothing.
        if st.wYear != 0 {
            return Some(Civil {
                year: st.wYear as i64,
                month: st.wMonth as u32,
                day: st.wDay as u32,
                hour: st.wHour as u32,
                minute: st.wMinute as u32,
                // wDayOfWeek: 0 = Sunday, same as tm_wday.
                weekday_mon0: (st.wDayOfWeek as u32 + 6) % 7,
            });
        }
    }
    None
}

/// The machine's local civil time, falling back to UTC where local time
/// is not available. The form every production caller wants.
pub fn local_or_utc_civil() -> Civil {
    local_civil_now().unwrap_or_else(|| utc_civil(unix_secs() as i64))
}

#[cfg(test)]
#[path = "localtime_tests.rs"]
mod localtime_tests;
