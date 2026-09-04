//! The fleet-cap half of `conntune`'s tests: what
//! `PoolConfig::line_cap_uncapped` publishes when a knee sits under the
//! fleet cap's share, and the note that says so.
//!
//! A sibling file rather than more of `conntune.rs` because that file
//! was at 2,949 of the size gate's 3,000-line ceiling on 28 Aug 2026,
//! and these two are one subject.

use super::*;

/// A fixed instant, so an age is arithmetic and never the wall clock.
const NOW: u64 = 1_754_600_000;

/// The same fixture `conntune::tests` builds, kept here rather than
/// exported so this file is one `#[path]` away from being deleted with
/// the functions it covers.
fn knee(n: usize, suspect: bool) -> Tuned {
    Tuned {
        connections: n,
        granted: n,
        asked: n,
        gbps: 1.0,
        checked: NOW,
        source: "auto".into(),
        suspect,
        limit: 50,
        v: SCHEMA,
        ..Default::default()
    }
}

/// The counterfactual `PoolConfig::line_cap_uncapped` publishes has
/// the knee in it, and the arm the live tuner takes does not. The
/// second case is the whole reason the function exists: a knee of 20
/// under a fleet-cap share of 25 dials 20 with the cap on and 20
/// with it off, so a ceiling published as 40 claims the cap is
/// costing twenty sockets that were never on offer.
#[test]
fn the_published_ceiling_carries_the_knee_but_not_the_live_seed() {
    let k = knee(20, false);
    let d = |base, pinned, live, t| dialable_ceiling(base, pinned, live, t, NOW);
    assert_eq!(d(40, false, false, None), 40);
    assert_eq!(d(40, false, false, Some(&k)), 20);
    // A pin is a statement and beats every measurement; under live
    // tuning the knee seeds rather than caps.
    assert_eq!(d(40, true, false, Some(&k)), 40);
    assert_eq!(d(40, false, true, Some(&k)), 40);
    // A single connection has no live arm to take, so the knee
    // applies there even under live tuning - matching the arm
    // `get::fleet` would really have taken.
    assert_eq!(d(1, false, true, Some(&k)), 1);
    // Suspect and expired knees are not applied by anybody.
    let suspect = knee(20, true);
    assert_eq!(d(40, false, false, Some(&suspect)), 40);
    let stale = Tuned {
        checked: NOW - EXPIRE_SECS - 1,
        ..knee(20, false)
    };
    assert_eq!(d(40, false, false, Some(&stale)), 40);
}

/// The note clause fires exactly when the KNEE is what binds, and
/// stays out of the way when the fleet cap is off or is the lower
/// of the two.
#[test]
fn the_note_names_the_fleet_cap_only_when_the_knee_is_under_it() {
    let note = knee_under_cap_note(32, Some(50), 50);
    assert!(note.contains("50"), "{note}");
    assert!(note.contains("not what is holding it back"), "{note}");
    // The cap is the lower of the two: the "line cap" line in
    // `get::fleet` is the one that explains this server, and two
    // sentences claiming to explain one number is worse than one.
    assert_eq!(knee_under_cap_note(32, Some(25), 25), "");
    // Equal is not under: the cap is exactly what the knee grants,
    // so neither is holding anything the other is not.
    assert_eq!(knee_under_cap_note(25, Some(25), 25), "");
    // The rule is off, so there is no fleet size to call inert.
    assert_eq!(knee_under_cap_note(32, None, 0), "");
    // House copy rules, and the bench rig's positional match on the
    // text this is APPENDED to: no dash punctuation, and the clause
    // starts a new one rather than reopening the sentence before it.
    assert!(
        !note.contains('\u{2014}') && !note.contains('\u{2013}'),
        "{note}"
    );
    assert!(note.starts_with("; "), "{note}");
}
