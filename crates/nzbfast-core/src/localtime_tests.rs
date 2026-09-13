//! F2's regressions: the local clock the scheduler and the quota ledger
//! share. The offset arm is pure, so a UTC build box can be asked what
//! New York would have said; the platform arm is asserted against the
//! real machine, which is the half only a Windows run can answer.

use super::*;

/// 2026-09-10 13:00:00Z, a Thursday.
const THU_1300Z: i64 = 1_789_045_200;
/// 2026-09-14 03:30:00Z, a Monday - the week's own boundary.
const MON_0330Z: i64 = 1_789_356_600;
/// 2026-11-01 05:30:00Z, the Sunday US DST ends (01:30 EDT, then EST).
const DST_BACK_SUN: i64 = 1_793_511_000;
/// 2026-03-08 07:30:00Z, the Sunday US DST starts (02:30 EST -> 03:30 EDT).
const DST_FWD_SUN: i64 = 1_772_955_000;

const UTC: i64 = 0;
const EDT: i64 = -4 * 3600;
const EST: i64 = -5 * 3600;
/// Chatham Islands, the widest offset anyone actually lives at: +12:45.
const CHATHAM: i64 = 12 * 3600 + 45 * 60;

#[test]
fn the_utc_control_reads_the_wall_clock_it_was_given() {
    let c = utc_civil(THU_1300Z);
    assert_eq!(c.date(), (2026, 9, 10));
    assert_eq!((c.hour, c.minute), (13, 0));
    // Thursday.
    assert_eq!(c.weekday_mon0, 3);
    assert_eq!(c.minute_of_week(), 3 * 1440 + 13 * 60);
}

#[test]
fn a_western_offset_moves_the_hour_back() {
    // The report's own case: a rule entered as 09:00 by someone in New
    // York is 13:00Z, and a UTC reading of it fires four hours early.
    let ny = civil_at_offset(THU_1300Z, EDT);
    assert_eq!((ny.hour, ny.minute), (9, 0));
    assert_eq!(ny.weekday_mon0, 3);
    assert_eq!(
        utc_civil(THU_1300Z).minute_of_week() - ny.minute_of_week(),
        4 * 60,
        "the UTC fallback fires four hours off the local rule"
    );
}

#[test]
fn an_offset_across_midnight_selects_the_other_local_weekday() {
    // 03:30 Monday UTC is still Sunday 23:30 in New York, so a rule for
    // "sun" and a rule for "mon" swap places across the boundary.
    let utc = utc_civil(MON_0330Z);
    assert_eq!((utc.weekday_mon0, utc.hour), (0, 3));
    let ny = civil_at_offset(MON_0330Z, EDT);
    assert_eq!(ny.date(), (2026, 9, 13));
    assert_eq!((ny.weekday_mon0, ny.hour, ny.minute), (6, 23, 30));
    assert_eq!(ny.minute_of_week(), 6 * 1440 + 23 * 60 + 30);
}

#[test]
fn an_eastern_offset_can_carry_into_the_next_local_week() {
    // Chatham is +12:45 and 23:30Z Sunday there is 12:15 Monday - the
    // minute-of-week wraps from the end of the week to the start of it.
    let utc = utc_civil(1_789_342_200); // 2026-09-13 23:30:00Z, a Sunday
    assert_eq!(utc.weekday_mon0, 6);
    let ch = civil_at_offset(1_789_342_200, CHATHAM);
    assert_eq!(ch.date(), (2026, 9, 14));
    assert_eq!((ch.weekday_mon0, ch.hour, ch.minute), (0, 12, 15));
    assert!(ch.minute_of_week() < utc.weekday_mon0 * 1440);
}

#[test]
fn a_dst_offset_change_moves_the_local_hour_and_nothing_else() {
    // Fall back: the same instant reads 01:30 on EDT and 00:30 on EST,
    // and both are the same local Sunday. This is what the scheduler's
    // discontinuity guard has to survive - see sched::classify_tick.
    let before = civil_at_offset(DST_BACK_SUN, EDT);
    let after = civil_at_offset(DST_BACK_SUN, EST);
    assert_eq!((before.hour, before.minute), (1, 30));
    assert_eq!((after.hour, after.minute), (0, 30));
    assert_eq!(before.date(), after.date());
    assert_eq!(before.weekday_mon0, after.weekday_mon0);
    assert_eq!(before.minute_of_week() - after.minute_of_week(), 60);

    // Spring forward: 02:30 EST does not exist, and the same instant is
    // 03:30 EDT.
    assert_eq!(
        (
            civil_at_offset(DST_FWD_SUN, EST).hour,
            civil_at_offset(DST_FWD_SUN, EDT).hour
        ),
        (2, 3)
    );
}

#[test]
fn the_offset_arm_agrees_with_the_utc_arm_at_zero() {
    for t in [0_i64, THU_1300Z, MON_0330Z, DST_BACK_SUN, 2_000_000_000] {
        assert_eq!(civil_at_offset(t, UTC), utc_civil(t), "t={t}");
    }
}

#[test]
fn the_epoch_is_a_thursday_and_negative_seconds_still_read() {
    assert_eq!(utc_civil(0).date(), (1970, 1, 1));
    assert_eq!(utc_civil(0).weekday_mon0, 3);
    // One minute before the epoch is the last minute of 1969, and a
    // Wednesday - `div_euclid` and not a truncating divide.
    let c = utc_civil(-60);
    assert_eq!(c.date(), (1969, 12, 31));
    assert_eq!((c.hour, c.minute, c.weekday_mon0), (23, 59, 2));
}

#[test]
fn minute_of_week_covers_the_week_and_nothing_past_it() {
    // Sunday 23:59 is the last minute; nothing this function returns may
    // reach 7 * 1440, because `SchedEntry::fires_at` indexes `days` with
    // `mow / 1440`.
    for day in 0..7 {
        let start = THU_1300Z - 3 * 86_400 + day * 86_400;
        for min in [0_i64, 1, 719, 1_439] {
            let c = utc_civil(start - 13 * 3600 + min * 60);
            assert!(c.minute_of_week() < 7 * 1440, "{c:?}");
            assert_eq!(c.minute_of_week() / 1440, c.weekday_mon0);
        }
    }
}

/// F2 itself: the platform arm must EXIST on every platform this ships
/// to. Before the shared helper there was no `#[cfg(windows)]` branch in
/// the scheduler's local clock at all, and no host test could see it -
/// this one fails on a Windows build the moment the arm goes missing
/// again.
#[test]
fn every_shipped_platform_has_a_local_clock() {
    let c = local_civil_now().expect(
        "no local-time arm for this platform - the weekly scheduler and the quota ledger \
         would both silently fall back to UTC while the UI promises local time",
    );
    assert!((1..=12).contains(&c.month), "{c:?}");
    assert!((1..=31).contains(&c.day), "{c:?}");
    assert!(c.hour < 24 && c.minute < 60, "{c:?}");
    assert!(c.weekday_mon0 < 7, "{c:?}");
    assert!(c.year >= 2020, "{c:?}");
}

/// The platform arm's weekday must agree with the platform arm's own
/// date. A wrong Sunday-vs-Monday base (`tm_wday` and `wDayOfWeek` are
/// both Sunday-zero, and this crate's numbering is Monday-zero) shows up
/// here and nowhere else.
#[test]
fn the_platform_weekday_agrees_with_the_platform_date() {
    let c = local_or_utc_civil();
    // Find the day-count whose civil date is the one the platform gave.
    // The local date is within a day of the UTC one either way.
    let utc_days = (unix_secs() / 86_400) as i64;
    let days = (utc_days - 1..=utc_days + 1)
        .find(|d| civil_from_days(*d) == c.date())
        .unwrap_or_else(|| panic!("local date {:?} is not within a day of UTC", c.date()));
    assert_eq!(
        c.weekday_mon0,
        (days + 3).rem_euclid(7) as u32,
        "platform weekday disagrees with platform date {:?}",
        c.date()
    );
}

/// The fallback must be the UTC arm and not something else: a platform
/// with no local clock still has to produce a usable minute-of-week.
#[test]
fn the_fallback_is_the_utc_reading_of_the_same_second() {
    let now = unix_secs() as i64;
    let utc = utc_civil(now);
    let local = local_or_utc_civil();
    // Whatever the offset, the two are within 26 hours of each other -
    // the widest real offset is +14:00 / -12:00.
    let diff = (local.minute_of_week() as i64 - utc.minute_of_week() as i64).rem_euclid(7 * 1440);
    assert!(
        diff <= 15 * 60 || diff >= 7 * 1440 - 13 * 60,
        "local {local:?} is not a plausible offset from UTC {utc:?}"
    );
}
