//! The SAB value formats, held to SAB's OWN algorithm rather than to
//! what we happen to emit.
//!
//! `crates/nzbfast/tests/daemon_facade` already pins both payloads key
//! by key with the type each key carries, and that census is complete:
//! measured 31 Aug 2026 against SAB 5.1.2, the queue body, the queue
//! slot, the history body and the history slot have between them ZERO
//! keys SAB sends and we do not. Every defect the audit that day found
//! was therefore invisible to it, because a wrong string is still a
//! string. These are the tests that can see one.
//!
//! `to_units` is re-implemented here, from `sabnzbd/misc.py`, and
//! `sab_to_units` is checked against it over the boundaries rather than
//! against a frozen list of strings. A frozen list is a second copy of
//! the answer and drifts with the first; an independent implementation
//! of the ORACLE disagrees the moment either side moves.

use super::*;

/// SAB's `to_units`, transliterated from `sabnzbd/misc.py` (5.1.2).
///
/// Deliberately written in Python's shape - `trunc(log2(val)/10)`, the
/// round-then-re-check carry, the `n == 0 and postfix == ""` arm - so
/// that a reader can diff it against the source rather than against
/// prose. It is NOT the implementation under test refactored; if the
/// two are ever made to share code this test stops being a test.
fn oracle_to_units(val: f64, postfix: &str) -> String {
    let (sign, mut val) = if val < 0.0 { ("-", -val) } else { ("", val) };
    let mut n: usize = if val < 1024.0 {
        0
    } else {
        ((val.log2() / 10.0).trunc() as usize).min(5)
    };
    let mut decimals = if n > 1 { 1 } else { 0 };
    let round = |v: f64, d: usize| {
        let f = 10f64.powi(d as i32);
        (v * f).round() / f
    };
    val = round(val / 2f64.powi(10 * n as i32), decimals);
    if n < 5 && val >= 1024.0 {
        n += 1;
        if n > 1 {
            decimals = 1;
        }
        val = round(val / 1024.0, decimals);
    }
    let tab = ["", "K", "M", "G", "T", "P"];
    let units = if n == 0 && postfix.is_empty() {
        String::new()
    } else {
        format!(" {}{}", tab[n], postfix)
    };
    format!("{sign}{val:.decimals$}{units}")
}

/// Every tier boundary, and the three shapes that were live on
/// origin/main before 31 Aug 2026.
///
/// The values are chosen, not swept, because the interesting inputs are
/// exactly the ones a sweep is least likely to land on: one byte under
/// each power of 1024 (the carry) and one byte over it (the tier).
#[test]
fn sab_to_units_matches_sabnzbds_own_to_units() {
    let cases: [f64; 22] = [
        0.0,
        1.0,
        512.0,
        999.0,
        1023.0,
        1024.0,
        1_000_000.0,
        // The carry SAB documents in its own source: this must read
        // "1.0 M", never "1024 K".
        1_048_575.0,
        1_048_576.0,
        1_073_741_823.0,
        1_073_741_824.0,
        // A 5 GB job, and a 2 TB output disk - the `diskspace1_norm`
        // that read "2089.6 G" against SAB's "2.0 T".
        5_368_709_120.0,
        2_000_000_000_000.0,
        // 1 TiB either side: "1024.0 GB" was live here against "1.0 TB".
        1_099_511_627_775.0,
        1_099_511_627_776.0,
        // A lifetime history total on a real install.
        44_236_800_000_000.0,
        1_125_899_906_842_623.0,
        1_125_899_906_842_624.0,
        // Past the top tier, which does not carry any further.
        1_152_921_504_606_846_976.0,
        // Negative: nothing here produces one, but SAB signs it and so
        // must we, or the shape stops being SAB's the day something does.
        -1.0,
        -1_048_576.0,
        -1_099_511_627_776.0,
    ];
    for v in cases {
        assert_eq!(
            sab_units(v),
            oracle_to_units(v, ""),
            "bare form disagrees with SAB at {v}"
        );
        assert_eq!(
            sab_units_b(v),
            oracle_to_units(v, "B"),
            "byte form disagrees with SAB at {v}"
        );
    }
}

/// The three specific strings that were WRONG on origin/main, named so
/// a regression fails as itself rather than as "case 8 of 22".
///
/// Every one is a value the oracle above already covers; they are
/// spelled out because the oracle proves agreement and this proves
/// which agreement, and because each is a sentence a reader can check
/// against SAB's source in a few seconds.
#[test]
fn the_three_shapes_that_were_live_before_the_port() {
    // Was "2089.6 G": the tier table stopped at G.
    assert_eq!(sab_units(2_000_000_000_000.0), "1.8 T");
    // Was "1024.0 GB": the same, one field over.
    assert_eq!(sab_units_b(1_099_511_627_776.0), "1.0 TB");
    // Was "1024 K": the rounding was not carried up a tier.
    assert_eq!(sab_units(1_048_575.0), "1.0 M");
    // Was "0 ": a sub-1024 value with no postfix carries no unit, and
    // therefore no space. This is the shape `queue.speed` and the four
    // `*_size` totals in the history body take.
    assert_eq!(sab_units(0.0), "0");
    assert_eq!(sab_units(999.0), "999");
    // ...and the postfix brings its own space, in both.
    assert_eq!(sab_units_b(0.0), "0 B");
}

/// A NaN is not a size. Nothing here produces one - every caller casts
/// an integer counter - but `sab_units` takes an f64, so the guard is
/// the difference between "0" and a payload key reading "NaN".
#[test]
fn a_nan_reads_as_zero_rather_than_reaching_the_wire() {
    assert_eq!(sab_units(f64::NAN), "0");
    assert_eq!(sab_units_b(f64::NAN), "0 B");
}

/// SAB's `pause_int` is `"minutes:seconds"` (its own docstring), or
/// `"0"` when no pause is scheduled. This published bare whole minutes
/// until 31 Aug 2026, so five minutes read `"5"` against SAB's `"5:00"`.
///
/// Driven through the public helper against a real `Daemon`, because
/// the None arm - the one that must stay the bare `"0"` and not become
/// `"0:00"` - is a property of the daemon's `pause_until` being unset,
/// and a pure-function test could not reach it.
#[test]
fn pause_int_is_sabs_minutes_colon_seconds() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pauseint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    // `test_daemon` seeds the config this daemon reads. Without one,
    // `Config::load` falls through to a SABnzbd install's `sabnzbd.ini`
    // under $HOME - see tools/host-config-gate.py.
    let d = crate::testutil::test_daemon(&dir);
    {
        let d = &d;
        // Nothing scheduled: SAB returns the bare "0", NOT "0:00".
        assert_eq!(pause_int(d), "0");

        for (secs, want_mins) in [(300u64, 5u64), (59, 0), (60, 1), (3661, 61)] {
            *d.pause_until.lock_ok() = Some(Instant::now() + std::time::Duration::from_secs(secs));
            let got = pause_int(d);
            let (m, s) = got
                .split_once(':')
                .unwrap_or_else(|| panic!("pause_int must be minutes:seconds, got {got:?}"));
            assert_eq!(s.len(), 2, "seconds are zero-padded to two: {got:?}");
            let m: u64 = m.parse().expect("minutes parse");
            let s: u64 = s.parse().expect("seconds parse");
            assert!(s < 60, "seconds never reach 60: {got:?}");
            // The clock moves between arming and reading, so the answer
            // is the interval and not an equality - one second of slack
            // either way, which is the whole of what can elapse here.
            let total = m * 60 + s;
            assert!(
                (secs.saturating_sub(1)..=secs).contains(&total),
                "pause_int should be about {secs}s, got {got:?}"
            );
            assert!(
                m == want_mins || m + 1 == want_mins || m == want_mins + 1,
                "the minutes field should be about {want_mins}, got {got:?}"
            );
        }
        // A pause already expired reads "0:00" and never a negative:
        // `saturating_duration_since` floors the interval at zero.
        *d.pause_until.lock_ok() = Some(Instant::now() - std::time::Duration::from_secs(90));
        assert_eq!(pause_int(d), "0:00");
    }
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The queue slot's `priority` never leaves SAB's own
/// `INTERFACE_PRIORITIES` vocabulary.
///
/// SAB's five words are Force, Repair, High, Normal and Low, and it
/// keeps a state OUT of that field by construction:
/// `NzbObject.set_priority` applies the state and then calls
/// `set_stateless_priority`, whose docstring says it is "for jobs to
/// fall back to after their priority was set to PAUSED or DUP". We
/// published a sixth word, `Duplicate`, live on an ordinary
/// duplicate-held row.
///
/// The dashboard's own `priority_name` KEEPS that word - the page has a
/// sentence to write about a held row - so this test is what says the
/// two are allowed to differ on exactly one value and no other.
#[test]
fn the_wire_priority_stays_inside_sabs_five_words() {
    const SAB_WORDS: [&str; 5] = ["Force", "Repair", "High", "Normal", "Low"];
    let mut j = crate::job_from_json(&json!({
        "nzo_id": "p1", "name": "n", "out_dir": "/tmp/x",
        "nzb_path": "/tmp/x.nzb", "state": "Queued",
    }))
    .expect("job");
    // Every priority the enqueue path can settle on, plus the sentinels
    // and the out-of-range values `priority_name` folds to Normal.
    for p in [
        2,
        1,
        0,
        -1,
        crate::job::DUPE_PRIORITY,
        crate::job::SAB_DEFAULT_PRIORITY,
        -2,
        -4,
        3,
        7,
        i32::MIN,
        i32::MAX,
    ] {
        j.priority = p;
        let w = sab_priority_name(&j);
        assert!(
            SAB_WORDS.contains(&w),
            "priority {p} published {w:?}, which is not one of SAB's \
             INTERFACE_PRIORITIES words {SAB_WORDS:?}"
        );
    }
    // And the one value the two spellings disagree on, named: the hold
    // reports SAB's stateless fallback here and keeps its own word for
    // the dashboard. `labels` is where the hold actually goes - see
    // `slot_json`.
    j.priority = crate::job::DUPE_PRIORITY;
    assert_eq!(sab_priority_name(&j), "Normal");
    assert_eq!(crate::job::priority_name(j.priority), "Duplicate");
}

/// SAB's `calc_age` vocabulary, and the two dates its own `except` arm
/// catches.
///
/// The tokens are what a client already renders for a real SAB, so a
/// unit different from theirs is a row that reads wrong rather than one
/// that fails - which is why this pins the SPELLING and not just that
/// something came back.
#[test]
fn sab_age_speaks_sabs_own_day_hour_minute_tokens() {
    assert_eq!(sab_elapsed(0), "0m");
    assert_eq!(sab_elapsed(59), "0m");
    assert_eq!(sab_elapsed(60), "1m");
    assert_eq!(sab_elapsed(3_599), "59m");
    assert_eq!(sab_elapsed(3_600), "1h");
    assert_eq!(sab_elapsed(86_399), "23h");
    assert_eq!(sab_elapsed(86_400), "1d");
    assert_eq!(sab_elapsed(90 * 86_400), "90d");
    // Negative cannot reach `sab_age`, but `sab_elapsed` is public to
    // the module and a caller subtracting two clocks can hand it one.
    assert_eq!(sab_elapsed(-5), "0m");
    // The two SAB answers "-" for: no date attribute (our parser stores
    // 0) and a date in the future, which is a negative timedelta there.
    assert_eq!(sab_age(0), "-");
    assert_eq!(sab_age(-1), "-");
    let now = crate::epoch_secs() as i64;
    assert_eq!(sab_age(now + 3_600), "-");
    assert_eq!(sab_age(now - 7_200), "2h");
}
