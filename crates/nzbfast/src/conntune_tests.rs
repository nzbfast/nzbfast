//! Unit tests for the connection auto-tune store (`conntune.rs`).
//!
//! Split out of that file verbatim when TODO 312 item 7's `stale_knee`
//! took it past the 3,000-line ceiling (TODO 106, the `check_tests.rs`
//! pattern). Behaviour unchanged: this is still `conntune`'s own child
//! module, so `use super::*` reaches its private items exactly as it did
//! in place.

use super::*;

fn bucket(b: u8, target: usize, epochs: u64, checked: u64) -> Bucket {
    Bucket {
        b,
        target,
        per_conn_bps: 10e6,
        rate_bps: 100e6,
        epochs,
        checked,
        limit: 24,
        source: "live".into(),
    }
}

const NOW: u64 = 1_754_600_000;

/// The seed order of design §5.1: an evidenced unexpired bucket
/// outranks the knee, a thin or expired one does not, and with
/// nothing usable the configured count stands.
#[test]
fn seeding_prefers_evidence_in_the_designed_order() {
    // No entry at all: configured.
    assert_eq!(seed_connections(None, 2, NOW, 16), 16);
    // Trusted knee, no buckets: the knee.
    let t = entry(8, false);
    assert_eq!(seed_connections(Some(&t), 2, NOW, 16), 8);
    // A SUSPECT knee is a low reading awaiting corroboration and
    // must not seed - the configured count stands.
    let t = entry(8, true);
    assert_eq!(seed_connections(Some(&t), 2, NOW, 16), 16);
    // An evidenced bucket beats the knee.
    let mut t = entry(8, false);
    t.buckets = vec![bucket(2, 14, 40, NOW - 3600)];
    assert_eq!(seed_connections(Some(&t), 2, NOW, 16), 14);
    // ...but a 2-epoch bucket is a hint, and the knee wins.
    t.buckets = vec![bucket(2, 14, 2, NOW - 3600)];
    assert_eq!(seed_connections(Some(&t), 2, NOW, 16), 8);
    // An expired bucket falls through to an adjacent unexpired one.
    t.buckets = vec![
        bucket(2, 14, 40, NOW - BUCKET_STALE_SECS - 1),
        bucket(1, 11, 40, NOW - 3600),
    ];
    assert_eq!(seed_connections(Some(&t), 2, NOW, 16), 11);
    // The seed never exceeds the ceiling the user typed.
    t.buckets = vec![bucket(2, 14, 40, NOW - 3600)];
    assert_eq!(seed_connections(Some(&t), 2, NOW, 6), 6);
}

/// The live half writes back through the same file, accumulates
/// evidence, and never manufactures a knee: a host that has only
/// ever been live-tuned must not start capping jobs.
#[test]
fn bucket_write_back_learns_without_capping() {
    let dir = std::env::temp_dir().join(format!("nzbfast-buckets-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    let upd = |target, epochs_add, now| BucketUpdate {
        target,
        per_conn_bps: 12e6,
        rate_bps: 120e6,
        epochs_add,
        limit: 20,
        now,
    };
    update_bucket(&cfg, "live.example.com", 1, upd(10, 6, NOW));
    update_bucket(&cfg, "live.example.com", 1, upd(12, 6, NOW + 60));
    let m = load(&cfg);
    let t = &m["live.example.com"];
    let b = t.buckets.iter().find(|b| b.b == 1).unwrap();
    assert_eq!(b.target, 12, "latest kept target wins");
    assert_eq!(b.epochs, 12, "evidence accumulates");
    assert_eq!(b.checked, NOW + 60);
    // The knee half stays empty, so nothing here can cap a job.
    assert_eq!(t.connections, 0);
    assert_eq!(applied_connections(20, false, Some(t), NOW), 20);
    // ...and the ceiling sweep has nothing to reopen on it.
    assert_eq!(reopen_low_knees(&cfg, |_| Some(40)), Reopened::default());
    // Evidence does not survive an expiry gap: a bucket coming
    // back after a fortnight restarts its count.
    update_bucket(
        &cfg,
        "live.example.com",
        1,
        upd(9, 3, NOW + 60 + BUCKET_STALE_SECS + 1),
    );
    let m = load(&cfg);
    let b = m["live.example.com"]
        .buckets
        .iter()
        .find(|b| b.b == 1)
        .unwrap();
    assert_eq!(b.epochs, 3, "expired evidence must not carry weight");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A trusted ladder refreshes the current bucket's seed (a user-run
/// Test must never be ignored by the live layer) and clears the
/// decay flag (a fresh reference). A parked suspect reading does
/// neither, and the live half survives every ladder verdict.
#[test]
fn a_ladder_refreshes_the_seed_and_clears_the_flag() {
    let dir = std::env::temp_dir().join(format!("nzbfast-refresh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    // Live evidence first: an evidenced bucket 14 and a raised flag.
    update_bucket(
        &cfg,
        "h.example.com",
        2,
        BucketUpdate {
            target: 14,
            per_conn_bps: 10e6,
            rate_bps: 100e6,
            epochs_add: 40,
            limit: 24,
            now: NOW,
        },
    );
    set_shaped(
        &cfg,
        "h.example.com",
        Some(Shaped {
            since: NOW,
            ref_per_conn_bps: 140e6,
        }),
        false,
    );
    assert!(load(&cfg)["h.example.com"].shaped.is_some());
    // A SUSPECT ladder result parks and touches neither half.
    let mut sus = entry(4, true);
    sus.checked = NOW + 100;
    record_at(&cfg, "h.example.com", sus, 2);
    let t = &load(&cfg)["h.example.com"];
    assert!(t.shaped.is_some(), "a suspect ladder is not a reference");
    let b = t.buckets.iter().find(|b| b.b == 2).unwrap();
    assert_eq!(b.target, 14, "a suspect ladder must not touch the seed");
    assert_eq!(b.epochs, 40, "live evidence survives");
    // A TRUSTED ladder refreshes the bucket seed and clears shaped.
    let mut ok = entry(9, false);
    ok.checked = NOW + 200;
    ok.source = "manual".into();
    record_at(&cfg, "h.example.com", ok, 2);
    let t = &load(&cfg)["h.example.com"];
    assert!(t.shaped.is_none(), "a trusted ladder is a fresh reference");
    let b = t.buckets.iter().find(|b| b.b == 2).unwrap();
    assert_eq!(b.target, 9, "the user-run Test seeds the live layer");
    assert_eq!(b.source, "manual");
    assert_eq!(b.epochs, 40, "a ladder measures a curve, not epochs");
    assert_eq!(
        b.per_conn_bps, 0.0,
        "a confirmation ladder retires the fallen-from reference"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The decay reference must not erode into the decayed rate it is
/// supposed to expose: a write-back median that would itself trip
/// the raise bar is evidence for the detector, not a new normal.
/// Milder falls (the 20% dip, gradual slowdowns) still track.
#[test]
fn a_decayed_median_never_becomes_the_reference() {
    let dir = std::env::temp_dir().join(format!("nzbfast-refkeep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    let upd = |per_conn: f64, now: u64| BucketUpdate {
        target: 12,
        per_conn_bps: per_conn,
        rate_bps: per_conn * 12.0,
        epochs_add: 10,
        limit: 20,
        now,
    };
    update_bucket(&cfg, "h.example.com", 1, upd(100e6, NOW));
    // A decayed stretch writes back a 12% median: frozen out.
    update_bucket(&cfg, "h.example.com", 1, upd(12e6, NOW + 600));
    let per = |cfg: &Path| {
        load(cfg)["h.example.com"]
            .buckets
            .iter()
            .find(|b| b.b == 1)
            .unwrap()
            .per_conn_bps
    };
    assert_eq!(
        per(&cfg),
        100e6,
        "the reference must survive the decay it measures"
    );
    // An 80% median is ordinary weather and tracks.
    update_bucket(&cfg, "h.example.com", 1, upd(80e6, NOW + 1200));
    assert_eq!(per(&cfg), 80e6);
    // Recovery above the old figure tracks freely too.
    update_bucket(&cfg, "h.example.com", 1, upd(110e6, NOW + 1800));
    assert_eq!(per(&cfg), 110e6);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The James rule generalized to the live half: raising the ceiling
/// well past a stored bucket target invalidates that bucket for
/// seeding - once, not on every sweep.
#[test]
fn a_raised_ceiling_invalidates_low_buckets_once() {
    let dir = std::env::temp_dir().join(format!("nzbfast-bsweep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    update_bucket(
        &cfg,
        "h.example.com",
        0,
        BucketUpdate {
            target: 6,
            per_conn_bps: 10e6,
            rate_bps: 60e6,
            epochs_add: 30,
            limit: 12,
            now: NOW,
        },
    );
    reopen_low_knees(&cfg, |_| Some(24));
    let t = &load(&cfg)["h.example.com"];
    let b = t.buckets.iter().find(|b| b.b == 0).unwrap();
    assert_eq!(
        b.checked, 0,
        "a low bucket under a raised ceiling stops seeding"
    );
    assert_eq!(b.epochs, 0);
    assert_eq!(b.limit, 24, "judged against the ceiling now in force");
    assert_eq!(b.target, 6, "retained for history");
    assert_eq!(
        seed_connections(Some(t), 0, NOW, 24),
        24,
        "the invalidated bucket must not seed"
    );
    // Write fresh evidence under the new ceiling: the same ceiling
    // must not invalidate it again.
    update_bucket(
        &cfg,
        "h.example.com",
        0,
        BucketUpdate {
            target: 6,
            per_conn_bps: 10e6,
            rate_bps: 60e6,
            epochs_add: 15,
            limit: 24,
            now: NOW + 60,
        },
    );
    reopen_low_knees(&cfg, |_| Some(24));
    let t = &load(&cfg)["h.example.com"];
    let b = t.buckets.iter().find(|b| b.b == 0).unwrap();
    assert_eq!(b.checked, NOW + 60, "same ceiling, no second sweep");
    assert_eq!(b.epochs, 15);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Files written before the live half existed still parse, and the
/// new fields stay off the wire while empty (an old build reading a
/// new file must see the shape it knows).
#[test]
fn bucketless_files_round_trip() {
    let t: Tuned = serde_json::from_str(
        r#"{"connections":6,"granted":6,"asked":6,"gbps":0.2,
            "checked":1754000000,"source":"auto"}"#,
    )
    .unwrap();
    assert!(t.buckets.is_empty());
    assert!(t.shaped.is_none());
    let s = serde_json::to_string(&t).unwrap();
    assert!(
        !s.contains("buckets"),
        "empty live half stays off the wire: {s}"
    );
    assert!(!s.contains("shaped"));
}

fn entry(n: usize, suspect: bool) -> Tuned {
    Tuned {
        connections: n,
        granted: n,
        asked: n,
        gbps: 1.0,
        checked: 100,
        source: "auto".into(),
        suspect,
        pending: None,
        buckets: Vec::new(),
        shaped: None,
        capped: None,
        limit: 24,
        v: SCHEMA,
    }
}

/// M6: a parked reading is an OUTSTANDING QUESTION, and the TTL
/// picker has to see it. `reconcile` deliberately leaves `suspect`
/// false on these - the old knee stays in force - so a picker that
/// only reads `suspect` puts the second opinion on the seven-day
/// clock and the parked candidate is never resolved.
#[test]
fn a_parked_candidate_is_an_open_question() {
    let applied = entry(8, false);
    let held = reconcile(Some(&applied), entry(21, true));
    assert!(!held.suspect, "the cap must stay applied");
    assert_eq!(held.pending, Some(21));
    // What the TTL picker in tasks.rs asks. Both halves matter: this
    // entry is NOT suspect, so `pending` is the only thing that can
    // put it back on the short clock.
    let short = held.suspect || held.pending.is_some();
    assert!(short, "a parked candidate must re-probe on the SHORT clock");
    // …and a settled entry stays on the long one.
    let settled = reconcile(Some(&applied), entry(9, false));
    assert!(
        !(settled.suspect || settled.pending.is_some()),
        "a corroborated knee must not re-probe every six hours"
    );
}

/// The regression the jagged term introduced: an unproven reading
/// must not be able to REMOVE a cap that is currently working.
///
/// Jobs skip suspect entries, so overwriting an applied {8} with a
/// suspect {21} does not change the cap - it deletes it, and the
/// provider runs at the full configured count in the over-asking
/// direction the feature exists to prevent.
#[test]
fn a_suspect_reading_never_unapplies_a_working_cap() {
    let applied = entry(8, false);
    let mut noisy = entry(21, true);
    noisy.checked = 999;
    let out = reconcile(Some(&applied), noisy);
    assert_eq!(out.connections, 8, "the working cap must survive");
    assert!(!out.suspect, "and must still be applied");
    assert_eq!(
        out.pending,
        Some(21),
        "the new reading waits for a second opinion"
    );
    assert_eq!(
        out.checked, 999,
        "on the short clock, so it is re-probed soon"
    );
}

/// …but a knee that really has moved still gets there, in two
/// probes. The second reading is compared against the PARKED one,
/// not against the applied value it disagreed with - otherwise
/// corroboration could only ever fail and the cap would be frozen
/// forever.
#[test]
fn a_parked_reading_can_still_win_on_the_next_probe() {
    let mut held = entry(8, false);
    held.pending = Some(21);
    assert!(
        corroborates(Some(&held), 21),
        "a repeat of the parked reading agrees"
    );
    assert!(corroborates(Some(&held), 19), "and so does one within 25%");
    assert!(
        !corroborates(Some(&held), 8),
        "the applied value is not the yardstick now"
    );
    // Corroborated, so the caller records it trusted - which replaces
    // outright and clears the parking space.
    let out = reconcile(Some(&held), entry(21, false));
    assert_eq!(out.connections, 21);
    assert!(!out.suspect);
    assert_eq!(out.pending, None, "nothing left to wait for");
}

/// With nothing applied yet there is nothing to protect, and a
/// suspect reading is stored as-is so it can be corroborated.
#[test]
fn a_suspect_reading_stands_when_no_cap_is_in_force() {
    let out = reconcile(None, entry(6, true));
    assert_eq!(out.connections, 6);
    assert!(out.suspect);
    // Replacing one suspect entry with another is fine too: neither
    // is applied, so nothing is lost.
    let out = reconcile(Some(&entry(6, true)), entry(9, true));
    assert_eq!(out.connections, 9);
}

/// `checked: NOW` rather than 0, because an entry no ladder ever
/// timestamped is EXPIRED (`is_expired`) and would be waved through
/// by every assertion below for the wrong reason.
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
        pending: None,
        buckets: Vec::new(),
        shaped: None,
        capped: None,
    }
}

/// The escape hatch, and the only reason it exists: a knee the user
/// has measured to be wrong must not be able to touch them.
#[test]
fn a_pinned_server_ignores_the_knee() {
    let low = knee(6, false);
    assert_eq!(
        applied_connections(40, false, Some(&low), NOW),
        6,
        "unpinned: capped"
    );
    assert_eq!(
        applied_connections(40, true, Some(&low), NOW),
        40,
        "pinned: the user wins"
    );
}

/// Pinning is not a licence to exceed the account: it makes the
/// user's OWN number authoritative, and that number is already the
/// global setting capped by this server's limit.
#[test]
fn a_pin_does_not_raise_the_ceiling() {
    assert_eq!(applied_connections(8, true, Some(&knee(30, false)), NOW), 8);
    assert_eq!(applied_connections(8, true, None, NOW), 8);
}

/// Unpinned behaviour is untouched, including the suspect rule.
#[test]
fn an_unpinned_server_still_obeys_a_trusted_knee_only() {
    assert_eq!(
        applied_connections(40, false, Some(&knee(6, true)), NOW),
        40,
        "suspect: not applied"
    );
    assert_eq!(
        applied_connections(40, false, Some(&knee(0, false)), NOW),
        40,
        "no knee recorded"
    );
    assert_eq!(applied_connections(40, false, None, NOW), 40);
}

/// THE DEFECT (23 Aug 2026): `STALE_SECS` existed from the start and
/// only the daemon's idle re-prober ever read it. Nothing consulted
/// it where the knee is APPLIED, so on a box whose prober never runs
/// - a plain CLI `nzbfast get`, a daemon that is never idle - one
/// ladder capped every job forever. Measured on a bench box: a knee
/// of 32 written FIFTEEN days earlier still capping a leg that asked
/// for 48, while the account granted 64 the moment it was pinned
/// away.
///
/// A knee past its appointment still caps (a busy daemon's knee is
/// due, not disproven). One past `EXPIRE_SECS` does not.
#[test]
fn an_expired_knee_does_not_silently_cap() {
    let aged = |secs: u64| Tuned {
        checked: NOW - secs,
        ..knee(32, false)
    };
    assert_eq!(
        applied_connections(48, false, Some(&aged(3_600)), NOW),
        32,
        "fresh: capped"
    );
    assert_eq!(
        applied_connections(48, false, Some(&aged(STALE_SECS + 1)), NOW),
        32,
        "overdue but not disproven: still capped"
    );
    assert_eq!(
        applied_connections(48, false, Some(&aged(EXPIRE_SECS + 1)), NOW),
        48,
        "four missed appointments: the user's own number, not the knee"
    );
    // The measured instance, to the day.
    assert_eq!(
        applied_connections(48, false, Some(&aged(15 * 86_400)), NOW),
        32,
        "15d is stale, not expired - the log line is what saves this one"
    );
    // An entry no ladder timestamped cannot be vouched for as fresh.
    assert_eq!(
        applied_connections(
            48,
            false,
            Some(&Tuned {
                checked: 0,
                ..knee(32, false)
            }),
            NOW
        ),
        48,
        "no probe time: treated as expired, not as new"
    );
    // A clock that went backwards (NTP step, a restored home
    // directory) must not read as an age of half a century.
    assert_eq!(
        applied_connections(
            48,
            false,
            Some(&Tuned {
                checked: NOW + 600,
                ..knee(32, false)
            }),
            NOW
        ),
        32,
        "a knee stamped in the future is not expired"
    );
}

/// The three-way verdict every surface reads, held to its own
/// boundaries so a future edit cannot quietly move one of them.
#[test]
fn stale_and_expired_are_separate_verdicts() {
    let aged = |secs: u64| Tuned {
        checked: NOW - secs,
        ..knee(8, false)
    };
    assert!(!is_stale(&aged(STALE_SECS), NOW));
    assert!(is_stale(&aged(STALE_SECS + 1), NOW));
    assert!(!is_expired(&aged(STALE_SECS + 1), NOW));
    assert!(!is_expired(&aged(EXPIRE_SECS), NOW));
    assert!(is_expired(&aged(EXPIRE_SECS + 1), NOW));
    // Unknown age fails both, in the safe direction.
    let untimed = Tuned {
        checked: 0,
        ..knee(8, false)
    };
    assert!(is_stale(&untimed, NOW) && is_expired(&untimed, NOW));
    assert_eq!(age_secs(&untimed, NOW), None);
    assert_eq!(age_str(None), "unknown age");
    assert_eq!(age_str(age_secs(&aged(15 * 86_400), NOW)), "15d");
    assert_eq!(age_str(age_secs(&aged(5 * 3_600), NOW)), "5h");
    assert_eq!(age_str(age_secs(&aged(120), NOW)), "2m");
    // Suspect and expired are independent reasons to stand down.
    assert!(!knee_applies(&aged(EXPIRE_SECS + 1), NOW));
    assert!(knee_applies(&aged(1), NOW));
    assert!(!knee_applies(&knee(8, true), NOW));
    assert!(!knee_applies(&knee(0, false), NOW));
}

fn step(connections: usize, gbps: f64) -> nzbkit::sysbench::LadderStep {
    nzbkit::sysbench::LadderStep {
        connections,
        granted: connections,
        gbps,
        bytes: 0,
        saturated: false,
    }
}

/// A ladder that moved nothing is NOT a knee of 2.
///
/// `gbps >= peak * 0.9` with a peak of 0.0 is `0.0 >= 0.0`, which the
/// first rung passes - so an all-zero ladder used to record a knee of
/// 2 and cap every job on that provider. The auto path called that
/// `suspect` and waited for a second probe, but the cause (an account
/// that answers GROUP/OVER and then serves no bodies) is structural,
/// so the re-probe reproduced it exactly and CORROBORATED it. The
/// manual path wrote `suspect: false` and applied it immediately.
#[test]
fn a_ladder_that_moved_nothing_yields_no_knee() {
    let dead = [step(2, 0.0), step(4, 0.0), step(8, 0.0)];
    assert!(
        knee_of(&dead).is_none(),
        "an all-zero ladder is not a knee of 2"
    );

    // A trickle is the same story: still far below anything a real
    // provider serves, and it would pick rung one just as readily.
    let trickle = [step(2, 0.0001), step(4, 0.0002)];
    assert!(knee_of(&trickle).is_none());

    // An empty ladder has no peak at all.
    assert!(knee_of(&[]).is_none());

    // NaN must not sail through the comparison into rung one.
    assert!(knee_of(&[step(2, f64::NAN), step(4, f64::NAN)]).is_none());
}

/// One unusable rung must not throw away the rungs that measured
/// fine: `total_cmp` ranks NaN above every real rate, so a NaN
/// allowed to set the peak would discard the whole ladder.
#[test]
fn a_single_nan_rung_does_not_discard_the_ladder() {
    let steps = [step(2, 1.0), step(4, 2.0), step(8, 4.0), step(16, f64::NAN)];
    let k = knee_of(&steps).expect("a NaN rung sank a usable ladder");
    assert_eq!(k.connections, 8);
    assert_eq!(k.peak_at, 8);
}

/// The real behaviour is untouched: smallest rung within 90% of the
/// peak, which is the point of the ladder.
#[test]
fn a_real_ladder_still_finds_its_knee() {
    let steps = [step(2, 1.0), step(4, 2.0), step(8, 4.0), step(16, 4.1)];
    let k = knee_of(&steps).expect("a real ladder has a knee");
    assert_eq!(k.connections, 8);
    assert_eq!(k.gbps, 4.1);
    assert!(!k.jagged);

    // A flat-from-the-start ladder genuinely knees at its first rung,
    // and that must still be reported - the guard is about zero
    // throughput, not about low connection counts.
    let flat = [step(2, 3.0), step(4, 3.05), step(8, 3.1)];
    let k = knee_of(&flat).expect("a flat ladder still knees at rung one");
    assert_eq!(k.connections, 2);
    assert_eq!(k.gbps, 3.1);
}

/// MB/s as the dashboard shows it → a ladder step with its own
/// granted count.
fn rung(connections: usize, granted: usize, mbps: f64) -> nzbkit::sysbench::LadderStep {
    nzbkit::sysbench::LadderStep {
        connections,
        granted,
        gbps: mbps * 8.0 / 1000.0,
        bytes: 0,
        saturated: false,
    }
}

/// The ladder that started this: 16c read 30 MB/s, then
/// 24c and 28c read 25 and 20, then 32c - on only 21 granted sockets
/// - read 32. The bottom-up scan answered 16: it took the first rung
/// over the bar and never looked at the two refinement probes that
/// had just priced the rungs above it UNDER the bar.
#[test]
fn the_knee_is_not_read_across_a_dip() {
    let steps = [
        rung(2, 2, 7.0),
        rung(4, 4, 13.0),
        rung(8, 8, 19.0),
        rung(16, 16, 30.0),
        rung(24, 24, 25.0),
        rung(28, 28, 20.0),
        rung(32, 21, 32.0),
    ];
    let k = knee_of(&steps).expect("a ladder this fast has a knee");
    // 30 clears 0.9×32=28.8, but 24c and 28c sit under it - the knee
    // cannot reach down past that dip to claim them.
    assert_eq!(k.asked, 32, "the knee was read across a dip");
    // …and that rung only ever ran on 21 sockets, so 21 is the
    // number. Asking for 32 is the 3-4×-slower direction.
    assert_eq!(k.connections, 21, "the knee was not clamped to granted");
    assert!(k.jagged, "a curve crossing the bar twice is jagged");
}

/// The cheap-rung trade still has to work: on a clean curve the knee
/// is the LOWEST rung within 10% of the peak, not the peak itself.
#[test]
fn a_clean_curve_still_knees_at_the_cheapest_fast_rung() {
    let steps = [
        rung(2, 2, 7.0),
        rung(4, 4, 13.0),
        rung(8, 8, 19.0),
        rung(16, 16, 30.0),
        rung(32, 32, 31.0),
    ];
    let k = knee_of(&steps).expect("a clean ladder has a knee");
    assert_eq!(k.connections, 16);
    assert_eq!(k.peak_at, 32);
    assert!(!k.jagged, "a monotonic curve must not read as jagged");
}

/// The contested list is exactly the rungs whose readings make the
/// curve impossible - the sub-bar dip, plus the peak that sets the
/// bar and is the one rung the climb already sampled twice keeping
/// the better. Re-measuring the pick and the peak alone would not
/// settle anything: what makes this curve jagged is 24c and 28c.
#[test]
fn a_jagged_ladder_nominates_the_rungs_that_disagree() {
    let steps = [
        rung(2, 2, 7.0),
        rung(8, 8, 19.0),
        rung(16, 16, 30.0),
        rung(24, 24, 25.0),
        rung(28, 28, 20.0),
        rung(32, 21, 32.0),
    ];
    let k = knee_of(&steps).expect("a ladder this fast has a knee");
    assert_eq!(k.contested, vec![24, 28, 32]);

    // A clean ladder pays nothing: nothing to re-measure.
    let clean = [rung(2, 2, 7.0), rung(8, 8, 19.0), rung(16, 16, 30.0)];
    assert!(knee_of(&clean).expect("clean ladder").contested.is_empty());
}

/// A second sample of the dip settles it. Re-measured free of
/// whatever was interfering, 24c and 28c clear the bar, the curve
/// stops contradicting itself, and the cheap rung is honestly the
/// knee - the answer the single jittery sample only guessed at.
#[test]
fn a_settled_dip_hands_back_the_cheap_rung() {
    let steps = [
        rung(2, 2, 7.0),
        rung(8, 8, 19.0),
        rung(16, 16, 30.0),
        rung(24, 24, 25.0),
        rung(28, 28, 20.0),
        rung(32, 21, 32.0),
    ];
    // The dip was noise: it re-reads in line with its neighbours.
    let extra = [rung(24, 24, 31.0), rung(28, 28, 31.0), rung(32, 21, 31.0)];
    let merged = merge_samples(&steps, &extra);
    let k = knee_of(&merged).expect("a merged ladder still has a knee");
    assert!(
        !k.jagged,
        "the dip was re-measured away but still reads jagged"
    );
    // 24, not the 16 this expected while the bar was 10%. Settled,
    // the curve reads 16c 30, 24c 31, 28c 31, 32c 32 MB/s - and 16c
    // is 6% off the best, which is precisely the gap the tightened
    // bar exists to stop giving away. The cheap rung wins when it is
    // genuinely as fast; this one is not.
    assert_eq!(
        k.connections, 24,
        "a settled curve must yield the cheapest FAST rung"
    );
}

/// A dip that reproduces is real, and the knee stays on the safe
/// side of it rather than reaching down past a rate the line
/// genuinely does not hold.
#[test]
fn a_dip_that_reproduces_keeps_the_conservative_knee() {
    let steps = [
        rung(2, 2, 7.0),
        rung(8, 8, 19.0),
        rung(16, 16, 30.0),
        rung(24, 24, 25.0),
        rung(28, 28, 20.0),
        rung(32, 21, 32.0),
    ];
    let extra = [rung(24, 24, 24.0), rung(28, 28, 21.0), rung(32, 21, 32.0)];
    let merged = merge_samples(&steps, &extra);
    let k = knee_of(&merged).expect("a merged ladder still has a knee");
    assert!(k.jagged, "a reproducing dip is still a dip");
    assert_eq!(k.connections, 21);
}

/// Bytes from BOTH samples are owed to the usage ledger, and the
/// rate is the less-interfered-with of the two.
#[test]
fn merging_takes_the_better_rate_and_sums_the_bytes() {
    let mut a = rung(16, 16, 30.0);
    a.bytes = 1_000;
    let mut b = rung(16, 14, 20.0);
    b.bytes = 700;
    let m = merge_samples(&[a], &[b]);
    assert_eq!(m[0].bytes, 1_700, "the ledger is owed both transfers");
    assert_eq!(m[0].granted, 16);
    assert!(
        (m[0].gbps - 30.0 * 8.0 / 1000.0).abs() < 1e-9,
        "rate is the better sample"
    );

    // A NaN re-read must not win a comparison it cannot lose.
    let m = merge_samples(&[rung(16, 16, 30.0)], &[rung(16, 16, f64::NAN)]);
    assert!((m[0].gbps - 30.0 * 8.0 / 1000.0).abs() < 1e-9);

    // A rung with no second sample is passed through untouched.
    let solo = merge_samples(&[rung(8, 8, 19.0)], &[rung(16, 16, 30.0)]);
    assert_eq!(solo.len(), 1);
    assert_eq!(solo[0].connections, 8);
    assert!((solo[0].gbps - 19.0 * 8.0 / 1000.0).abs() < 1e-9);
}

/// Sockets a provider refuses by ones and twos are ordinary timing,
/// not an account ceiling - don't ratchet the knee down for them.
#[test]
fn a_socket_short_of_the_ask_is_not_a_ceiling() {
    let steps = [rung(2, 2, 7.0), rung(8, 8, 19.0), rung(16, 15, 30.0)];
    let k = knee_of(&steps).expect("a real ladder has a knee");
    assert_eq!(k.connections, 16);
}

/// The lifetime cap ledger: one row per DAY, the worst ceiling
/// kept, and no disk write when nothing moved.
///
/// The last part is not tidiness. The caller folds on a watchdog
/// tick for the whole length of a download, so a ledger that
/// rewrote itself on every call would be a read-modify-write of
/// conntune.json a second, forever, for a fact that changes once a
/// day.
#[test]
fn cap_ledger_banks_a_day_at_a_time() {
    let dir = std::env::temp_dir().join(format!("nzbfast-capledger-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    let day = 20_000u64 * 86_400;
    // First sighting creates the host entry outright: a provider
    // that caps us is exactly the kind no clean ladder ever ran
    // against.
    assert!(note_capped(&cfg, "gn.example.com", 38, day + 3_600));
    // Same day, same ceiling - nothing to say, nothing written.
    assert!(!note_capped(&cfg, "gn.example.com", 38, day + 7_200));
    // A WORSE ceiling the same day is news even though the day is not.
    assert!(note_capped(&cfg, "gn.example.com", 21, day + 9_000));
    assert!(note_capped(&cfg, "gn.example.com", 40, day + 86_400));

    let c = load(&cfg)["gn.example.com"].capped.clone().expect("ledger");
    assert_eq!(
        c.days,
        vec![20_000, 20_001],
        "one row per day, not per call"
    );
    assert_eq!(c.granted_hi, 40);
    // The low is the number a support ticket is about.
    assert_eq!(c.granted_lo, 21);
    assert_eq!(c.first, day + 3_600);
    assert_eq!(c.last, day + 86_400);
    // The knee half stays empty, which every knee consumer already
    // reads as "nothing measured" - the ledger must not fabricate
    // a connection count nothing ever probed.
    assert_eq!(load(&cfg)["gn.example.com"].connections, 0);

    // The window is bounded, oldest dropped.
    for d in 2..40u64 {
        note_capped(&cfg, "gn.example.com", 38, day + d * 86_400);
    }
    let c = load(&cfg)["gn.example.com"].capped.clone().expect("ledger");
    assert_eq!(c.days.len(), CAP_DAYS);
    assert_eq!(*c.days.last().unwrap(), 20_039);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep 6, N7: the chip shows a WINDOW of days, so the
/// number beside it has to come from the same window.
///
/// `granted_lo` is a lifetime minimum and nothing raises it when old
/// days drain out of the ledger's 30-event retention, and the
/// dashboard then filters that list to the last 30 CALENDAR days.
/// A refusal at 10 a hundred days ago plus one at 38 today therefore
/// rendered "capped at 10 today" - the oldest number in the file,
/// presented as this morning's observation, on the one row that
/// exists to be evidence.
#[test]
fn each_capped_day_carries_its_own_low() {
    let dir = std::env::temp_dir().join(format!("nzbfast-capdaylo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    let d0 = 20_000u64;

    // A hundred days ago: refused at 10.
    assert!(note_capped(&cfg, "gn.example.com", 10, d0 * 86_400));
    // Today: refused at 38, then at 30 - the same day's own low
    // moves even though the LIFETIME low (10) does not.
    assert!(note_capped(&cfg, "gn.example.com", 38, (d0 + 100) * 86_400));
    assert!(
        note_capped(&cfg, "gn.example.com", 30, (d0 + 100) * 86_400 + 3_600),
        "a lower ceiling on a day already recorded is still news"
    );

    let c = load(&cfg)["gn.example.com"].capped.clone().expect("ledger");
    assert_eq!(c.days, vec![d0 as u32, d0 as u32 + 100]);
    assert_eq!(
        c.day_lo,
        vec![10, 30],
        "index for index with the days the chip filters"
    );
    assert_eq!(c.granted_lo, 10, "the lifetime figure is unchanged");

    // The two columns stay aligned when the window trims.
    for d in 101..140u64 {
        note_capped(
            &cfg,
            "gn.example.com",
            20 + (d % 5) as usize,
            (d0 + d) * 86_400,
        );
    }
    let c = load(&cfg)["gn.example.com"].capped.clone().expect("ledger");
    assert_eq!(c.days.len(), CAP_DAYS);
    assert_eq!(c.day_lo.len(), c.days.len(), "trimmed in lockstep");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A ledger written before the per-day column existed still loads,
/// and the days already in it are marked unknown rather than given
/// a number none of them was observed at.
///
/// Codex sweep 7, H1b: backfilling those days with the LIFETIME low
/// told N7's lie again, in a column that from then on claims to be
/// per-day - so the invented figure outlived the transitional state
/// that produced it and was believed by every later reader.
#[test]
fn an_older_cap_ledger_gains_the_per_day_column() {
    let dir = std::env::temp_dir().join(format!("nzbfast-capdayold-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    let d0 = 20_000u64;
    // Long ago and far lower than anything since: the lifetime low.
    note_capped(&cfg, "h", 10, d0 * 86_400);
    note_capped(&cfg, "h", 22, (d0 + 1) * 86_400);

    // Strip the column, as a ledger from before 1.1.5 has it.
    {
        let mut m = load(&cfg);
        let c = m.get_mut("h").unwrap().capped.as_mut().unwrap();
        c.day_lo.clear();
        save(&cfg, &m);
    }
    assert!(note_capped(&cfg, "h", 38, (d0 + 2) * 86_400));
    let c = load(&cfg)["h"].capped.clone().expect("ledger");
    assert_eq!(
        c.day_lo,
        vec![DAY_LO_UNKNOWN, DAY_LO_UNKNOWN, 38],
        "unknown for what was never recorded, per day from here on"
    );
    assert_eq!(
        c.granted_lo, 10,
        "the lifetime figure is still the lifetime figure"
    );
    assert!(
        !c.day_lo[..2].contains(&c.granted_lo),
        "the lifetime low must not be presented as any day's own observation"
    );

    // A second refusal on a day that is only there as unknown takes
    // the real number: `min` against the sentinel is the observation.
    assert!(note_capped(&cfg, "h", 31, (d0 + 2) * 86_400 + 3_600));
    let c = load(&cfg)["h"].capped.clone().expect("ledger");
    assert_eq!(c.day_lo, vec![DAY_LO_UNKNOWN, DAY_LO_UNKNOWN, 31]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A ladder verdict says nothing about what the provider refused
/// last week, so it must not erase the ledger on its way past.
#[test]
fn a_ladder_result_does_not_wipe_the_cap_ledger() {
    let dir = std::env::temp_dir().join(format!("nzbfast-capkeep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    note_capped(&cfg, "h", 38, 20_000 * 86_400);
    record(
        &cfg,
        "h",
        Tuned {
            connections: 12,
            granted: 12,
            asked: 16,
            gbps: 4.0,
            checked: 9,
            source: "auto".into(),
            limit: 20,
            v: SCHEMA,
            ..Default::default()
        },
    );
    let t = &load(&cfg)["h"];
    assert_eq!(t.connections, 12, "the ladder result landed");
    assert_eq!(
        t.capped.as_ref().map(|c| c.granted_hi),
        Some(38),
        "the ladder wiped a record only a refusal may write"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn record_and_load_round_trip() {
    let dir = std::env::temp_dir().join(format!("nzbfast-conntune-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    assert!(load(&cfg).is_empty());
    record(
        &cfg,
        "news.example.com",
        Tuned {
            connections: 12,
            granted: 12,
            asked: 12,
            gbps: 4.9,
            checked: 1,
            source: "auto".into(),
            suspect: false,
            limit: 20,
            v: SCHEMA,
            pending: None,
            buckets: Vec::new(),
            shaped: None,
            capped: None,
        },
    );
    record(
        &cfg,
        "fill.example.com",
        Tuned {
            connections: 4,
            granted: 4,
            asked: 4,
            gbps: 0.8,
            checked: 2,
            source: "manual".into(),
            suspect: true,
            limit: 8,
            v: SCHEMA,
            pending: None,
            buckets: Vec::new(),
            shaped: None,
            capped: None,
        },
    );
    let m = load(&cfg);
    assert_eq!(m.len(), 2);
    assert_eq!(m["news.example.com"].connections, 12);
    assert!(!m["news.example.com"].suspect);
    assert_eq!(m["fill.example.com"].source, "manual");
    assert!(m["fill.example.com"].suspect);
    // No settings.json in the dir: the toggle defaults ON.
    assert!(enabled(&cfg));
    std::fs::write(
        cfg.with_file_name("settings.json"),
        br#"{"auto_connections":false}"#,
    )
    .unwrap();
    assert!(!enabled(&cfg));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 312 item 1: the precedence, pinned on the pure resolver so
/// no test in this process has to write the environment.
///
/// **The env var wins, and losing that is the expensive failure.**
/// Every §208-family bench driver exports `NZBFAST_LINE_CAP` per
/// leg to select its A/B arm, and the rig library reads the same
/// variable back to decide whether to warn about a leg that did not
/// run the fleet it dialled. A setting that
/// overrode it would silently re-point every one of those rounds on
/// any box that happens to have a number saved in its dashboard,
/// and nothing in a round log would say so.
#[test]
fn the_env_var_still_wins_over_the_fleet_setting() {
    const GIGABIT: u64 = 125_000_000;
    // A 1 Gbit line: the curve is at its floor there (a line has to
    // read above 3.75 Gbit before it grows at all), which is the
    // whole reason TODO 312 exists.
    let curve = nzbkit::pool::linecap::fleet_for_line(GIGABIT);
    assert_eq!(curve, nzbkit::pool::linecap::LINE_CAP_DEFAULT_FLEET);

    // Neither dial: the curve.
    assert_eq!(line_cap_resolve(None, None, GIGABIT, 0), curve);
    assert!(line_cap_auto_resolve(None, None));

    // The setting alone.
    assert_eq!(line_cap_resolve(None, Some(140), GIGABIT, 0), 140);
    assert_eq!(line_cap_resolve(None, Some(0), GIGABIT, 0), 0);
    // ...and a typed fleet pins the governor, exactly as a typed
    // env var does: the number is a fleet size, not a floor.
    assert!(!line_cap_auto_resolve(None, Some(140)));
    assert!(!line_cap_auto_resolve(None, Some(0)));

    // Both: the environment, whichever way they disagree.
    assert_eq!(line_cap_resolve(Some("40"), Some(140), GIGABIT, 0), 40);
    assert_eq!(line_cap_resolve(Some("0"), Some(140), GIGABIT, 0), 0);
    assert_eq!(line_cap_resolve(Some("140"), Some(0), GIGABIT, 0), 140);
    assert!(!line_cap_auto_resolve(Some("40"), None));
    assert!(!line_cap_auto_resolve(Some("40"), Some(140)));

    // The env var's UNIT trap (23 Aug 2026): a box still exporting
    // the old per-Mbit `0.5` does not parse and reads as OFF, and a
    // setting behind it must not rescue it into meaning something
    // else - the control arm is the safe direction and a leg that
    // silently ran the dashboard's number instead would be a round
    // nobody could reproduce.
    assert_eq!(line_cap_resolve(Some("0.5"), Some(140), GIGABIT, 0), 0);
    assert_eq!(line_cap_resolve(Some(""), Some(140), GIGABIT, 0), 0);

    // TODO 275 item 1 part 2 meets TODO 312 item 1: a banked carry
    // is a second candidate for the CURVE and must not touch a
    // number somebody typed, from either dial. A carry this low
    // wants the ceiling on its own, so a setting the fold could
    // reach would come back as 50 rather than as what was typed -
    // which is the whole difference between a fleet size and a
    // floor.
    let slow = 1_000_000;
    assert!(line_cap_resolve(None, None, GIGABIT, slow) > curve);
    assert_eq!(line_cap_resolve(None, Some(6), GIGABIT, slow), 6);
    assert_eq!(line_cap_resolve(None, Some(0), GIGABIT, slow), 0);
    assert_eq!(line_cap_resolve(Some("6"), None, GIGABIT, slow), 6);
}

/// The setting reaches the resolver off settings.json, and an
/// absent key is the automatic curve rather than a fleet of zero -
/// the difference between "we did not say" and "turn the rule off".
#[test]
fn the_fleet_setting_is_read_from_settings_json() {
    let dir = std::env::temp_dir().join(format!("nzbfast-fleetset-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    let settings = cfg.with_file_name("settings.json");

    // No settings.json at all, and a settings.json without the key:
    // both are "no setting".
    assert_eq!(line_cap_setting(&cfg), None);
    std::fs::write(&settings, br#"{"auto_connections":true}"#).unwrap();
    assert_eq!(line_cap_setting(&cfg), None);

    std::fs::write(&settings, br#"{"line_cap_fleet":140}"#).unwrap();
    assert_eq!(line_cap_setting(&cfg), Some(140));
    // 0 is a value, not an absence: it is how the setting says OFF.
    std::fs::write(&settings, br#"{"line_cap_fleet":0}"#).unwrap();
    assert_eq!(line_cap_setting(&cfg), Some(0));
    // Anything that is not a whole number is not a fleet size, and
    // reads as no setting rather than as 0 - a torn or hand-edited
    // file must fall back to the shipped rule, never silently
    // uncap the install.
    std::fs::write(&settings, br#"{"line_cap_fleet":"140"}"#).unwrap();
    assert_eq!(line_cap_setting(&cfg), None);
    std::fs::write(&settings, br#"{"line_cap_fleet":null}"#).unwrap();
    assert_eq!(line_cap_setting(&cfg), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The v1.0.14 field case, end to end on the file.
///
/// A pre-guard entry (v0, no `suspect`, no `limit`) holding a knee
/// of 6 must stop capping the moment the sweep sees it, and must be
/// queued for a re-probe rather than deleted - if 6 really is this
/// provider's knee, one probe puts it back. Since SCHEMA 2 the v0
/// entry retires under the probe-group rule (it was measured there
/// too), which subsumes the old ceiling-raise reason.
#[test]
fn a_raised_ceiling_reopens_a_low_pre_guard_knee() {
    let dir = std::env::temp_dir().join(format!("nzbfast-reopen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    // Exactly the shape v1.0.14 wrote: no `suspect`, no `limit`, no `v`.
    std::fs::write(
        path_for(&cfg),
        br#"{"news.newsdemon.com":{"connections":6,"granted":6,"gbps":0.24,
             "checked":1754000000,"source":"auto"}}"#,
    )
    .unwrap();
    let before = load(&cfg);
    assert!(!before["news.newsdemon.com"].suspect, "v0 entry applies");
    assert_eq!(before["news.newsdemon.com"].v, 0);

    let moved = reopen_low_knees(&cfg, |_| Some(24));
    assert_eq!(moved.retired, vec!["news.newsdemon.com".to_string()]);
    assert!(moved.raised.is_empty(), "retirement, not a ceiling raise");
    let after = load(&cfg);
    let t = &after["news.newsdemon.com"];
    assert!(t.suspect, "a reopened knee must stop capping jobs");
    assert_eq!(t.checked, 0, "and must be eligible for an immediate probe");
    assert_eq!(t.limit, 24, "judged against the ceiling now in force");
    assert_eq!(t.v, SCHEMA);
    // And the retired number is gone rather than left as the
    // yardstick the next probe would be measured against - see
    // `corroborates`, which falls back to `connections`.
    assert_eq!(t.connections, 0);

    // Idempotent: the same ceiling must not reopen it a second time
    // (a settings save, or every daemon restart, would otherwise
    // re-arm a knee the probe loop had just cleared).
    assert_eq!(reopen_low_knees(&cfg, |_| Some(24)), Reopened::default());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The SCHEMA 2 sweep, end to end on the file: a v1 entry - healthy
/// knee, corroborated, applied, exactly what a v1.0.15+ build wrote
/// after the James fixes - was still measured on the synthetic probe
/// group, which is known to misread a provider 17x. It must be
/// retired ONCE: suspect (jobs stop applying it), checked zeroed
/// (the prober re-measures on the short clock), and BOTH readings
/// dropped - parked pending and applied knee alike, because
/// `corroborates` falls back to `connections` when `pending` is
/// None, so a surviving probe-group number would agree with the
/// first low real-article ladder and promote it on the spot. The
/// retirement exists to withhold exactly that agreement.
#[test]
fn a_probe_group_knee_is_retired_once_for_real_articles() {
    let dir = std::env::temp_dir().join(format!("nzbfast-retire-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    // The exact shape a v1 build persisted: applied knee, a parked
    // pending reading, judged limit, v:1.
    std::fs::write(
        path_for(&cfg),
        br#"{"reader.xsnews.nl":{"connections":8,"granted":8,"asked":8,
             "gbps":0.20,"checked":1754600000,"source":"auto",
             "suspect":false,"limit":24,"v":1,"pending":21},
            "news.eweka.nl":{"connections":20,"granted":20,"asked":20,
             "gbps":2.2,"checked":1754600000,"source":"manual",
             "suspect":false,"limit":24,"v":1}}"#,
    )
    .unwrap();

    let moved = reopen_low_knees(&cfg, |_| Some(24));
    assert_eq!(
        moved.retired,
        vec!["news.eweka.nl".to_string(), "reader.xsnews.nl".to_string()],
        "EVERY pre-v2 knee retires, healthy-looking ones included - \
         the 17x error is invisible from the stored numbers"
    );
    assert!(moved.raised.is_empty());
    let after = load(&cfg);
    for host in ["reader.xsnews.nl", "news.eweka.nl"] {
        let t = &after[host];
        assert!(t.suspect, "{host}: jobs must stop applying the old knee");
        assert_eq!(t.checked, 0, "{host}: re-probe on the short clock");
        assert_eq!(t.pending, None, "{host}: probe-group pending cleared");
        assert_eq!(t.v, SCHEMA, "{host}: stamped, so the sweep is one-time");
        assert_eq!(
            t.connections, 0,
            "{host}: the probe-group knee must not stay as a yardstick"
        );
        assert!(
            !corroborates(Some(t), 8),
            "{host}: a retired entry corroborates nothing"
        );
    }

    // One-time means one-time: nothing moves on the next call.
    assert_eq!(reopen_low_knees(&cfg, |_| Some(24)), Reopened::default());

    // A v2 entry the prober has since written back is never touched
    // again, even by a later restart.
    record(&cfg, "reader.xsnews.nl", entry(20, false));
    assert_eq!(reopen_low_knees(&cfg, |_| Some(24)), Reopened::default());
    assert!(!load(&cfg)["reader.xsnews.nl"].suspect);

    // An UNCONFIGURED host is left alone AND unstamped, so a server
    // that is re-added later still gets its retirement then.
    std::fs::write(
        path_for(&cfg),
        br#"{"news.oldfill.com":{"connections":4,"granted":4,"gbps":0.1,
             "checked":1754600000,"source":"auto","suspect":false,
             "limit":8,"v":1}}"#,
    )
    .unwrap();
    assert_eq!(reopen_low_knees(&cfg, |_| None), Reopened::default());
    assert_eq!(load(&cfg)["news.oldfill.com"].v, 1, "unstamped while gone");
    let back = reopen_low_knees(&cfg, |_| Some(8));
    assert_eq!(back.retired, vec!["news.oldfill.com".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The retirement has to survive the very next ladder: a retired
/// entry is not evidence, so a real-article knee that happens to
/// land on the same low number as the retired probe-group one is
/// still the FIRST reading and must be parked for a second opinion.
/// While `connections` survived the sweep, `corroborates` compared
/// against it (its fallback when `pending` is None) and promoted
/// that first reading immediately - the 17x probe-group error
/// laundering itself into a trusted knee in one step.
#[test]
fn a_retired_entry_does_not_corroborate_the_next_low_ladder() {
    let dir = std::env::temp_dir().join(format!("nzbfast-retire-corr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    std::fs::write(
        path_for(&cfg),
        br#"{"news.eweka.nl":{"connections":6,"granted":6,"asked":6,
             "gbps":0.2,"checked":1754600000,"source":"auto",
             "suspect":false,"limit":24,"v":1}}"#,
    )
    .unwrap();
    assert_eq!(
        reopen_low_knees(&cfg, |_| Some(24)).retired,
        vec!["news.eweka.nl".to_string()]
    );

    let retired = load(&cfg);
    let prior = retired.get("news.eweka.nl");
    assert!(
        !corroborates(prior, 6),
        "the retired number must not agree with a knee that matches it"
    );
    // ...so the ladder result is unproven and parks, exactly as it
    // would on a host with no history at all.
    assert!(is_suspect(6, 24, false, prior));

    let mut fresh = entry(6, true);
    fresh.checked = 1754700000;
    record(&cfg, "news.eweka.nl", fresh);
    let after = &load(&cfg)["news.eweka.nl"];
    assert!(
        after.suspect,
        "the first real-article reading must wait for a second one, \
         and stays out of jobs until it lands"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Knees the user's ceiling has NOT outgrown are left alone: a knee
/// at or near the ceiling is the tuner agreeing with the user, and a
/// host that isn't a configured server is none of this code's
/// business.
#[test]
fn reopen_leaves_settled_knees_alone() {
    let dir = std::env::temp_dir().join(format!("nzbfast-reopen2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.local.json");
    let mk = |c: usize, limit: usize| Tuned {
        connections: c,
        granted: c,
        asked: c,
        gbps: 1.0,
        checked: 9,
        source: "auto".into(),
        suspect: false,
        limit,
        v: SCHEMA,
        pending: None,
        buckets: Vec::new(),
        shaped: None,
        capped: None,
    };
    record(&cfg, "near.example.com", mk(20, 24)); // 20 of 24: agrees
    record(&cfg, "low.example.com", mk(6, 24)); // already judged at 24
    record(&cfg, "gone.example.com", mk(2, 24)); // no longer configured
    let moved = reopen_low_knees(&cfg, |h| (h != "gone.example.com").then_some(24));
    assert_eq!(moved, Reopened::default(), "nothing should have moved");
    let m = load(&cfg);
    assert!(m.values().all(|t| !t.suspect));
    assert_eq!(m["gone.example.com"].checked, 9);

    // But raise the ceiling past the one they were judged at and the
    // low knee - and only the low knee - reopens: 20 of 26 is still
    // the tuner agreeing with the user, 6 of 26 is not.
    let moved = reopen_low_knees(&cfg, |h| (h != "gone.example.com").then_some(26));
    assert_eq!(moved.raised, vec![("low.example.com".into(), 6, 26)]);
    assert!(moved.retired.is_empty(), "v2 entries never retire");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 277: a leg that TYPED a fleet size gets no spawn headroom -
/// it pinned the in-run governor too, so there is no raise to make
/// room for, and spawning past its rung would move the shard layout
/// of every A/B arm on every §208 ladder. The auto case is the
/// curve's ceiling whatever the cap in force is, which is what the
/// governor may grow to.
#[test]
fn only_an_auto_cap_gets_room_to_grow_into() {
    let max = nzbkit::pool::linecap::LINE_CAP_MAX_FLEET;
    for cap in [
        nzbkit::pool::linecap::LINE_CAP_DEFAULT_FLEET,
        30,
        max,
        0,
        15,
    ] {
        assert_eq!(line_cap_headroom_fleet(cap, true), max, "auto cap {cap}");
        assert_eq!(line_cap_headroom_fleet(cap, false), cap, "typed cap {cap}");
    }
}

/// The spawn count is the headroom share held to this server's own
/// ceilings and to its measured knee, and never below what the run
/// already dials.
#[test]
fn the_spawn_headroom_is_bounded_by_the_account_and_by_the_knee() {
    let knee = |c: usize| Tuned {
        connections: c,
        granted: c,
        asked: c,
        gbps: 1.0,
        checked: 100,
        source: "auto".into(),
        suspect: false,
        limit: 100,
        v: SCHEMA,
        pending: None,
        buckets: Vec::new(),
        shaped: None,
        capped: None,
    };
    // The ordinary five-provider case: dialling its share of the
    // curve's floor, ten slots born for it.
    assert_eq!(line_cap_spawn_slots(5, 10, 100, false, None, 100), 10);
    // An account that grants fewer than the headroom share never
    // has more slots born than it grants.
    assert_eq!(line_cap_spawn_slots(5, 10, 7, false, None, 100), 7);
    // A measured knee bounds it too: a slot past the knee is one
    // the governor could only ever wake into a refusal. It bounds
    // `applied` as well, so the two stay in step.
    assert_eq!(
        line_cap_spawn_slots(4, 10, 100, false, Some(&knee(4)), 100),
        4
    );
    // Never below the dial: a pin (which skips the knee) and a
    // server already at the ceiling both spawn what they run.
    assert_eq!(line_cap_spawn_slots(60, 10, 100, true, None, 100), 60);
    assert_eq!(line_cap_spawn_slots(10, 10, 100, false, None, 100), 10);
}
