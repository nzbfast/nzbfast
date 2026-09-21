//! Plan 4.2 item 1: the progress a repair reports WHILE it folds, and
//! the cancel the fold honours - a child module of `unit_tests` for the
//! same two reasons as its neighbours (the parent's size-gate entry, and
//! `use super::*` reaching the real PAR2 fixtures).
//!
//! THE SETS HERE ARE BUILT BY THIS CRATE'S OWN GENERATORS, not by an
//! external `par2` - `par2_index` / `par2_volume` in the parent, the
//! very code the repair reads back - so nothing in this file needs a
//! `have_par2()` guard, which is what `tools/par2-gate.py` looks for at
//! this line.
//!
//! What is asserted is OBSERVABLE BEHAVIOUR and not the presence of a
//! hook: a fraction that rises and lands, a cancel that ends a repair
//! sooner than it would have ended, and a directory a re-run recovers
//! from. A test that only checked the sink was called would pass over a
//! bar that never moves, which is the defect this work removes.

use super::*;
use crate::par2repair::control::{PauseGate, ProgressSink, RepairControl, RepairPhase, SolveArm};
// `lock_ok()` (already in scope through `use super::*`) rather than the
// unwrapping form, even though this is test code and
// `tools/lock-gate.py` exempts tests. Its walk is ONE level - a file is
// test-only when a PARENT declares it `#[cfg(test)] mod` - and this
// file is a grandchild, declared by `unit_tests.rs`, which is itself
// the cfg'd module. The gate cannot see that and reports these as
// production sites - and it scans the raw line, so spelling the
// offending form inside this very comment is a hit too, which is why
// it is described rather than written. Taking the gate's preferred form
// is the cheap answer; widening the walk is a change to a gate and
// wants its own case.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Every call the repair made, in order.
#[derive(Default)]
struct Rec {
    calls: Mutex<Vec<(RepairPhase, u64, u64)>>,
    /// Every `slab(index, of)`, and WHERE in `calls` it landed - which
    /// is the half that says it was announced BEFORE the sweep it
    /// frames rather than somewhere inside it.
    slabs: Mutex<Vec<(usize, usize, usize)>>,
    /// Every `solve_arm(arm)`, and WHERE in `calls` it landed - the
    /// same pairing the sweeps get, and for the same reason: an arm
    /// announced after the entry it frames would be read in the wrong
    /// band. See `control::SolveArm`.
    arms: Mutex<Vec<(SolveArm, usize)>>,
    /// Raised when `at` of the named phase has been passed, so a test
    /// can cancel FROM INSIDE the phase it wants to interrupt rather
    /// than by racing a timer.
    trip: Option<(RepairPhase, u64, Arc<PauseGate>)>,
}

impl ProgressSink for Rec {
    fn slab(&self, index: usize, of: usize) {
        let at = self.calls.lock_ok().len();
        self.slabs.lock_ok().push((index, of, at));
    }

    fn solve_arm(&self, arm: SolveArm) {
        let at = self.calls.lock_ok().len();
        self.arms.lock_ok().push((arm, at));
    }

    fn progress(&self, phase: RepairPhase, done: u64, total: u64) {
        self.calls.lock_ok().push((phase, done, total));
        if let Some((want, at, gate)) = self.trip.as_ref()
            && phase == *want
            && done >= *at
        {
            gate.cancel();
        }
    }
}

impl Rec {
    fn calls(&self) -> Vec<(RepairPhase, u64, u64)> {
        self.calls.lock_ok().clone()
    }
    fn of(&self, phase: RepairPhase) -> Vec<(u64, u64)> {
        self.calls()
            .into_iter()
            .filter(|c| c.0 == phase)
            .map(|c| (c.1, c.2))
            .collect()
    }
}

/// The observer every test here passes: it says `Repair` and hands the
/// engine the control. Nothing else.
struct Watch {
    control: RepairControl,
    surveys: AtomicUsize,
}

impl SurveyObserver for Watch {
    fn after_survey(&mut self, _members: &[MemberSurvey]) -> AfterSurvey {
        self.surveys.fetch_add(1, Ordering::Relaxed);
        AfterSurvey::Repair
    }
    fn control(&self) -> RepairControl {
        self.control.clone()
    }
}

/// A set big enough that the fold has several batches in it and small
/// enough to be free: four members over 64-byte blocks, with parity for
/// every block. Returns the directory and the members' true bytes.
fn damaged_set(tag: &str, damage: &[(usize, usize)]) -> (PathBuf, Vec<(String, Vec<u8>)>) {
    // Parity for a third of the set - far more than any test here
    // damages, so a shortfall can never be the reason a repair stops -
    // and CONSECUTIVE, which is what every real poster writes and what
    // sends the repair down the structured (Forney) arm.
    let exps: Vec<u32> = (0..60u32).collect();
    damaged_set_with_exps(tag, damage, &exps)
}

/// [`damaged_set`] with the recovery exponents named.
///
/// Separated 20 Sep 2026 for the one test that needs the UNSTRUCTURED
/// arm: `selection_structured` sends a consecutive exponent run (and a
/// relabelable progression) to Forney, which computes no matrix inverse
/// at all, so a set built the ordinary way cannot exercise the
/// Gauss-Jordan half of `control::SolveArm`.
///
/// Both drivers pick the SMALLEST available exponents, so it is the
/// smallest `m` of these that decides the arm - and a PROGRESSION is
/// relabelled onto the structured arm too, so `[0, 4, 8, 12]` is not
/// enough and `[0, 1, 3, 7]` is.
fn damaged_set_with_exps(
    tag: &str,
    damage: &[(usize, usize)],
    exps: &[u32],
) -> (PathBuf, Vec<(String, Vec<u8>)>) {
    let dir = tmpdir(tag);
    let files: Vec<(String, Vec<u8>)> = (0..4)
        .map(|i| (format!("member{i}.bin"), payload(BS * 40, 7 + i as u64)))
        .collect();
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, &refs)).unwrap();
    std::fs::write(
        format!("{}/set.vol000+{}.par2", dir.display(), exps.len()),
        par2_volume(SET, BS, &refs, exps),
    )
    .unwrap();
    for (name, data) in &files {
        std::fs::write(dir.join(name), data).unwrap();
    }
    // Damage by BLOCK, so every hit is one block the repair must rebuild
    // and the `missing` count is exactly `damage.len()`.
    for &(fi, bi) in damage {
        let p = dir.join(&files[fi].0);
        let mut bytes = std::fs::read(&p).unwrap();
        for b in &mut bytes[bi * BS..(bi + 1) * BS] {
            *b ^= 0xFF;
        }
        std::fs::write(&p, bytes).unwrap();
    }
    (dir, files)
}

fn watching(sink: Arc<Rec>, gate: Option<Arc<PauseGate>>) -> Watch {
    Watch {
        control: RepairControl::new(Some(sink), gate),
        surveys: AtomicUsize::new(0),
    }
}

fn intact(dir: &Path, files: &[(String, Vec<u8>)]) -> bool {
    files
        .iter()
        .all(|(n, d)| std::fs::read(dir.join(n)).is_ok_and(|got| got == *d))
}

/// THE HEADLINE. A repair reports a rising fraction through the fold and
/// through the write, and every phase lands on full - which is the thing
/// that was false until 12 Sep 2026, when a bar stopped moving the
/// moment the verify half ended and sat there for the whole repair.
#[test]
fn a_repair_reports_a_rising_fraction_through_the_fold_and_the_write() {
    let (dir, files) = damaged_set("control-progress", &[(0, 3), (1, 7), (2, 11), (3, 19)]);
    let rec = Arc::new(Rec::default());
    let mut o = watching(rec.clone(), Some(PauseGate::new()));
    let status = repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
        .expect("the repair runs")
        .expect("the observer said Repair");
    assert!(
        matches!(status, RepairStatus::Repaired(_)),
        "the set has ample parity: {status:?}"
    );
    assert!(intact(&dir, &files), "the repair is byte-exact");

    for phase in [RepairPhase::Verify, RepairPhase::Fold, RepairPhase::Write] {
        let seen = rec.of(phase);
        assert!(
            seen.len() >= 2,
            "{phase:?} reported {} call(s) - a phase that is announced and never \
             updated is the bar that does not move",
            seen.len()
        );
        assert_eq!(seen[0].0, 0, "{phase:?} sizes its bar before it starts");
        let (last, total) = *seen.last().unwrap();
        assert_eq!(
            last, total,
            "{phase:?} ended at {last}/{total} - a fraction that never reaches one reads \
             as a wedge, which is the complaint this work answers"
        );
        assert!(total > 0, "{phase:?} has a whole to be a fraction of");
        let mut prev = 0;
        for (done, _) in &seen {
            assert!(*done >= prev, "{phase:?} went backwards: {prev} -> {done}");
            prev = *done;
        }
    }
    // The solve on this shape is a structured one and is bracketed
    // rather than counted (see `finish_blocks_reported`), so it is
    // announced and landed and that is all this asserts.
    let solve = rec.of(RepairPhase::Solve);
    assert!(!solve.is_empty(), "the solve is announced");
    assert_eq!(solve.last().map(|s| s.0), solve.last().map(|s| s.1));
}

/// THE OTHER HEADLINE. A cancel raised from inside the fold ends the
/// repair, and it ends it WITHOUT writing - the fold is the only phase
/// running, so the directory comes out exactly as the survey found it.
///
/// RETENTION IS FORCED OFF, and that is what makes this a test of the
/// in-fold check rather than of the gate after it. The verify pass
/// keeps every block it proves on a set this small, so by default the
/// whole fold is one hand-over from memory and the reader threads - the
/// site that actually polls the cancel block by block, and the site
/// every large repair goes through - never run at all. Forcing the
/// budget to zero puts the present blocks back on disk where a real
/// repair's are. `census::testing::record()` is held for the duration
/// because `retain::force_policy` is process-global and names that lock
/// as the one its callers serialize on.
#[test]
fn a_cancel_raised_mid_fold_ends_the_repair_before_it_writes() {
    let _rec_lock = crate::par2repair::census::testing::record();
    let _no_retain = crate::par2repair::retain::force_policy(0, true);
    let damage = [(0, 3), (1, 7), (2, 11), (3, 19)];
    let (dir, files) = damaged_set("control-cancel-fold", &damage);
    let before: Vec<Vec<u8>> = files
        .iter()
        .map(|(n, _)| std::fs::read(dir.join(n)).unwrap())
        .collect();

    let gate = PauseGate::new();
    let rec = Arc::new(Rec {
        calls: Mutex::new(Vec::new()),
        slabs: Mutex::new(Vec::new()),
        arms: Mutex::new(Vec::new()),
        // From INSIDE the fold, at the phase's SIZING call - a timer
        // would either fire before the fold or after the repair on a
        // box of a different speed.
        //
        // `0` AND NOT `1`, since 17 Sep 2026. The fold's figure counts
        // bytes FOLDED now rather than bytes handed to the syndrome
        // worker, and the grain it can report at is one unit of the
        // tiled fold's grid: a set with 64-byte blocks has a column
        // narrower than `MIN_COL_WORDS` and so exactly one unit, which
        // means its first NON-ZERO fold figure is also its last. The
        // phase's opening is published by the driver before the readers
        // below start, and it is the cue that still lands inside the
        // feed on a fixture this small.
        //
        // WHAT THE PAIR BELOW STILL DISCRIMINATES, exactly: an in-fold
        // stop from a pre-patch one. It no longer singles out the
        // READERS' per-block poll, because a cancel this early also
        // reaches the syndrome worker, which drains its channel instead
        // of folding - verified by deleting `gate_if_held` from the
        // reader loop, which leaves this test green. The reader loop's
        // own poll is pinned by the pause test below, which that same
        // deletion DOES fail: nothing on the worker side parks.
        trip: Some((RepairPhase::Fold, 0, gate.clone())),
    });
    let mut o = watching(rec.clone(), Some(gate.clone()));
    let err = repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
        .expect_err("a cancelled repair is not a verdict");
    assert!(
        matches!(err, RepairError::Cancelled),
        "a cancel must not be reported as a broken set: {err:?}"
    );
    let fold = rec.of(RepairPhase::Fold);
    assert!(
        !fold.is_empty(),
        "the cancel was raised from inside the fold, so the fold was reached"
    );
    // THE DISCRIMINATING ASSERTION, and the reason the two above are not
    // enough on their own. A cancel honoured ONLY at the pre-patch gate
    // would produce exactly the same verdict, the same untouched
    // directory and the same empty write phase - the repair would just
    // have folded the whole set first, which is precisely the wait this
    // work removes. The fold's own counter is what tells the two apart:
    // an unfinished phase never reaches its total, because
    // `control.finish(Fold)` sits past the `?` that carries the cancel
    // out of the reader scope.
    let (last, total) = *fold.last().unwrap();
    assert!(
        last < total,
        "the fold ran to completion ({last}/{total}) under a cancel raised inside it - the          in-fold check is not being honoured and the cancel is landing at the pre-patch gate"
    );
    assert!(
        rec.of(RepairPhase::Solve).is_empty(),
        "the solve ran under a cancel raised in the fold before it - the whole point of          cutting the fold short is not paying for what comes after it"
    );
    assert!(
        rec.of(RepairPhase::Write).is_empty(),
        "a cancel before the patch must not open the write phase at all"
    );

    // NOTHING WAS WRITTEN. Every member is byte-for-byte what it was,
    // damage included, and no repair temp was left behind.
    for ((name, _), was) in files.iter().zip(&before) {
        assert_eq!(
            &std::fs::read(dir.join(name)).unwrap(),
            was,
            "{name} changed under a repair that was cancelled before the patch"
        );
    }
    assert!(!any_repair_temp(&dir), "a repair temp survived the cancel");

    // AND IT IS RE-RUNNABLE, which is the whole of what a cancel owes.
    let mut o2 = watching(Arc::new(Rec::default()), None);
    let status = repair_dir_set_surveyed(&dir, &SET, &[], &mut o2)
        .expect("the re-run repairs")
        .expect("the observer said Repair");
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert!(intact(&dir, &files), "the re-run is byte-exact");
}

/// THE FOLD BAR MEASURES THE FOLD, and not the hand-over that feeds it.
///
/// The discriminating case is the MEMORY-RETAINED one, which is why
/// retention is forced ON here and OFF in the two neighbours. When the
/// verify pass kept the corpus there is no read to pace the feed: the
/// driver hands the whole thing to the syndrome worker as a few
/// memcpys, and until 17 Sep 2026 it stepped `Fold` as it did so. So
/// the phase counted bytes HANDED OVER, and a bar that had been given
/// the fold's own byte total emptied at hand-over speed - 40 to 80 ms
/// whatever the payload, 0.04 s on 384 MB and 0.08 s on 1.5 GB, with
/// every Galois-field operation it was meant to be measuring still to
/// come (`research/SAB-PARFAST-METER-DROPIN-2026-09-17.md`).
///
/// A cancel raised at the phase's SIZING call is what turns that into
/// an assertion with no clock in it. `begin(Fold, total)` runs on the
/// driver thread before the syndrome worker exists, so when the gate
/// trips NOT ONE BYTE has been folded and none ever will be - the
/// worker drains the channel instead. A phase that nevertheless reports
/// its total has reported work that did not happen. Against the
/// stepping this replaces the assertion below fails, `total/total`
/// against a fold that never ran.
///
/// It has to be the retained path or it proves nothing: on the
/// streaming path the reader loop's own `gate_if_held` returns before
/// the first block is read, so the old accounting never got to step
/// either. The census is asked whether the corpus was really retained
/// for exactly that reason - a box or a future default that quietly
/// stopped retaining would leave this passing over the wrong path.
#[test]
fn a_fold_that_never_ran_does_not_report_a_finished_fold() {
    let census = crate::par2repair::census::testing::record();
    // Ample for this set (160 blocks of 64 bytes) and EXPLICIT, so the
    // corpus-size ceiling cannot refuse it. `census::testing::record()`
    // above is the process-wide lock these two seams share.
    let _retained = crate::par2repair::retain::force_policy(1 << 20, true);
    let damage = [(0, 3), (1, 7), (2, 11), (3, 19)];
    let (dir, files) = damaged_set("control-fold-counts-work", &damage);
    let before: Vec<Vec<u8>> = files
        .iter()
        .map(|(n, _)| std::fs::read(dir.join(n)).unwrap())
        .collect();

    let gate = PauseGate::new();
    let rec = Arc::new(Rec {
        calls: Mutex::new(Vec::new()),
        slabs: Mutex::new(Vec::new()),
        arms: Mutex::new(Vec::new()),
        // `at` of ZERO: the phase's own sizing call, which is the first
        // thing anybody hears about the fold.
        trip: Some((RepairPhase::Fold, 0, gate.clone())),
    });
    let mut o = watching(rec.clone(), Some(gate.clone()));
    let err = repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
        .expect_err("a cancelled repair is not a verdict");
    assert!(matches!(err, RepairError::Cancelled), "{err:?}");

    let retained_blocks = census
        .of_kind("survey")
        .last()
        .and_then(|e| e["retained_blocks"].as_u64())
        .unwrap_or(0);
    assert!(
        retained_blocks > 0,
        "the verify pass retained nothing, so this repair took the STREAMING path and the \
         assertion below is not about the hand-over at all"
    );

    let fold = rec.of(RepairPhase::Fold);
    assert_eq!(
        fold.first().map(|f| f.0),
        Some(0),
        "the phase sizes its bar before it starts: {fold:?}"
    );
    let (last, total) = *fold.last().expect("the fold phase was announced");
    assert!(
        last < total,
        "the fold reported {last}/{total} on a repair cancelled before the syndrome worker \
         existed - nothing was folded, so the phase is counting the hand-over that feeds \
         the fold rather than the fold"
    );
    assert!(
        rec.of(RepairPhase::Solve).is_empty() && rec.of(RepairPhase::Write).is_empty(),
        "nothing past the fold may run under a cancel raised at the top of it"
    );

    // AND THE ORDINARY PROMISES A CANCEL MAKES, on this path as on the
    // other two: nothing written, no temp left, a re-run repairs.
    for ((name, _), was) in files.iter().zip(&before) {
        assert_eq!(
            &std::fs::read(dir.join(name)).unwrap(),
            was,
            "{name} changed under a repair that was cancelled before the patch"
        );
    }
    assert!(!any_repair_temp(&dir), "a repair temp survived the cancel");
    let mut o2 = watching(Arc::new(Rec::default()), None);
    let status = repair_dir_set_surveyed(&dir, &SET, &[], &mut o2)
        .expect("the re-run repairs")
        .expect("the observer said Repair");
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert!(intact(&dir, &files), "the re-run is byte-exact");
}

/// A cancel raised during the WRITE is the hard case, and what it owes
/// is not "nothing was touched" but "a re-run recovers". The patch only
/// ever writes blocks the verify pass found MISSING, so an interrupted
/// in-place patch is monotone; temps are removed and nothing is renamed
/// in. Both halves are asserted through the one thing a user cares
/// about: run it again and the set is whole.
#[test]
fn a_cancel_raised_mid_write_leaves_a_directory_a_re_run_recovers() {
    let damage: Vec<(usize, usize)> = (0..4)
        .flat_map(|f| (0..8).map(move |b| (f, b * 3)))
        .collect();
    let (dir, files) = damaged_set("control-cancel-write", &damage);
    let gate = PauseGate::new();
    let rec = Arc::new(Rec {
        calls: Mutex::new(Vec::new()),
        slabs: Mutex::new(Vec::new()),
        arms: Mutex::new(Vec::new()),
        trip: Some((RepairPhase::Write, 1, gate.clone())),
    });
    let mut o = watching(rec.clone(), Some(gate.clone()));
    let err = repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
        .expect_err("a cancelled repair is not a verdict");
    assert!(matches!(err, RepairError::Cancelled), "{err:?}");
    let write = rec.of(RepairPhase::Write);
    assert!(
        !write.is_empty(),
        "the cancel was raised from inside the write phase"
    );
    let (last, total) = *write.last().unwrap();
    assert!(
        last < total,
        "the patch wrote every block ({last}/{total}) under a cancel raised inside it - a          cancel that waits for the write it was meant to stop is not a cancel"
    );
    assert!(
        !any_repair_temp(&dir),
        "a repair temp survived a cancel taken during the patch - the cleanup path did \
         not run, and the next repair inherits a stale staging file"
    );

    let mut o2 = watching(Arc::new(Rec::default()), None);
    let status = repair_dir_set_surveyed(&dir, &SET, &[], &mut o2)
        .expect("the re-run repairs")
        .expect("the observer said Repair");
    assert!(
        matches!(status, RepairStatus::Repaired(_) | RepairStatus::NoDamage),
        "{status:?}"
    );
    assert!(intact(&dir, &files), "the re-run is byte-exact");
}

/// A cancel raised before the survey answers stops the repair in the
/// hashing loop. The point is the PROMPTNESS: the verify pass is the
/// stretch a big set spends reading itself, and a cancel there must not
/// wait for it.
#[test]
fn a_cancel_raised_before_the_repair_starts_stops_it_in_the_verify_pass() {
    let (dir, files) = damaged_set("control-cancel-early", &[(0, 3)]);
    let gate = PauseGate::new();
    gate.cancel();
    let rec = Arc::new(Rec::default());
    let mut o = watching(rec.clone(), Some(gate));
    let err = repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
        .expect_err("a cancelled repair is not a verdict");
    assert!(matches!(err, RepairError::Cancelled), "{err:?}");
    assert_eq!(
        o.surveys.load(Ordering::Relaxed),
        0,
        "the survey is not even offered - the pass it would describe never finished"
    );
    assert!(
        rec.of(RepairPhase::Fold).is_empty() && rec.of(RepairPhase::Write).is_empty(),
        "nothing past the verify pass may run"
    );
    assert!(
        std::fs::read(dir.join(&files[0].0)).unwrap() != files[0].1,
        "the damaged member is untouched, damage and all"
    );
}

/// Pause parks the repair and resume releases it, and the repair that
/// comes out the other side is the same repair. The park is at the
/// engine's own driver boundary - see `control::PauseGate` for why it
/// cannot be finer - so this asserts that it HELD, not where.
#[test]
fn a_paused_repair_parks_and_the_resume_finishes_it() {
    let (dir, files) = damaged_set("control-pause", &[(0, 3), (2, 11)]);
    let gate = PauseGate::new();
    gate.set_paused(true);
    let rec = Arc::new(Rec::default());
    let control = RepairControl::new(Some(rec.clone()), Some(gate.clone()));
    let d2 = dir.clone();
    let h = std::thread::spawn(move || {
        let mut o = Watch {
            control,
            surveys: AtomicUsize::new(0),
        };
        repair_dir_set_surveyed(&d2, &SET, &[], &mut o)
    });
    // Long enough that an unpaused repair of this size is over.
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert!(
        !h.is_finished(),
        "a paused repair ran to completion - the gate did not hold"
    );
    assert!(gate.is_paused());
    gate.set_paused(false);
    let status = h
        .join()
        .expect("repair thread")
        .expect("the repair runs")
        .expect("the observer said Repair");
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert!(intact(&dir, &files), "the resumed repair is byte-exact");
}

/// PAUSE IS HONOURED INSIDE THE FOLD, at the feed's reader loop - the
/// one site in the fold where a thread holds nothing another thread
/// could take. Retention is forced off for the same reason as the
/// in-fold cancel test above: it is what puts the present blocks back on
/// disk and makes the readers run at all.
///
/// The discriminating fact is the fold's own counter. A pause honoured
/// ONLY at the driver's boundaries would let this repair fold every
/// byte and then park before the patch, so the fold would read
/// `total/total`; parked inside it, the fold is short and stays short
/// for as long as the pause is held.
#[test]
fn a_pause_raised_mid_fold_parks_the_readers_inside_it() {
    let _rec_lock = crate::par2repair::census::testing::record();
    let _no_retain = crate::par2repair::retain::force_policy(0, true);
    let (dir, files) = damaged_set("control-pause-fold", &[(0, 3), (1, 7), (2, 11), (3, 19)]);

    let gate = PauseGate::new();
    // A sink that pauses from INSIDE the fold, at the phase's sizing
    // call - the same cue and the same reason as the in-fold cancel
    // test above, and it still pins the READERS specifically: the
    // syndrome worker never parks, so a feed that did not park would
    // fold every byte and the counter below would read `total/total`.
    struct PauseAt {
        gate: Arc<PauseGate>,
        calls: Mutex<Vec<(RepairPhase, u64, u64)>>,
        /// ONCE. Pausing on every fold report would re-pause the instant
        /// the test resumed, and the repair would never finish - which
        /// is how the first spelling of this test wedged.
        armed: AtomicUsize,
    }
    impl ProgressSink for PauseAt {
        fn progress(&self, phase: RepairPhase, done: u64, total: u64) {
            self.calls.lock_ok().push((phase, done, total));
            if phase == RepairPhase::Fold && self.armed.fetch_add(1, Ordering::Relaxed) == 0 {
                self.gate.set_paused(true);
            }
        }
    }
    let sink = Arc::new(PauseAt {
        gate: gate.clone(),
        calls: Mutex::new(Vec::new()),
        armed: AtomicUsize::new(0),
    });
    let control = RepairControl::new(Some(sink.clone()), Some(gate.clone()));
    let d2 = dir.clone();
    let h = std::thread::spawn(move || {
        let mut o = Watch {
            control,
            surveys: AtomicUsize::new(0),
        };
        repair_dir_set_surveyed(&d2, &SET, &[], &mut o)
    });
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert!(
        !h.is_finished(),
        "the repair ran to completion - the pause was not honoured anywhere"
    );
    let mid: Vec<(u64, u64)> = sink
        .calls
        .lock_ok()
        .iter()
        .filter(|c| c.0 == RepairPhase::Fold)
        .map(|c| (c.1, c.2))
        .collect();
    let (last, total) = *mid.last().expect("the fold was announced");
    assert!(
        last < total,
        "the fold finished ({last}/{total}) before the repair parked - the pause landed at          a driver boundary and not inside the feed"
    );
    gate.set_paused(false);
    let status = h
        .join()
        .expect("repair thread")
        .expect("the repair runs")
        .expect("the observer said Repair");
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert!(intact(&dir, &files), "the resumed repair is byte-exact");
}

/// A cancel raised WHILE the repair is parked must end it there. The
/// alternative - taking effect at the resume - is the same as not
/// having a cancel, because nobody is going to press resume.
#[test]
fn a_cancel_while_paused_ends_the_repair_without_a_resume() {
    let (dir, _files) = damaged_set("control-pause-cancel", &[(0, 3)]);
    let gate = PauseGate::new();
    gate.set_paused(true);
    let control = RepairControl::new(None, Some(gate.clone()));
    let d2 = dir.clone();
    let h = std::thread::spawn(move || {
        let mut o = Watch {
            control,
            surveys: AtomicUsize::new(0),
        };
        repair_dir_set_surveyed(&d2, &SET, &[], &mut o)
    });
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert!(!h.is_finished(), "the gate did not hold");
    gate.cancel();
    let err = h
        .join()
        .expect("repair thread")
        .expect_err("a cancelled repair is not a verdict");
    assert!(matches!(err, RepairError::Cancelled), "{err:?}");
    assert!(!any_repair_temp(&dir));
}

/// The twelve call sites that pass no observer, and the observers
/// written before this existed: an inert control must change NOTHING.
/// This is the arm that keeps the widening a widening.
#[test]
fn a_repair_with_no_control_is_the_repair_it_always_was() {
    let (dir, files) = damaged_set("control-inert", &[(1, 5), (3, 9)]);
    // A bare closure observer - the pre-12-Sep shape, which gets the
    // defaulted `control()` and never mentions it.
    let mut o = |_: &[MemberSurvey]| AfterSurvey::Repair;
    let status = repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
        .expect("the repair runs")
        .expect("the observer said Repair");
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert!(intact(&dir, &files));
}

/// A repair with a sink and NO gate is a legitimate half: report
/// everything, refuse nothing. It must not be a cancel that never
/// fires - it must be no cancel at all.
#[test]
fn a_control_with_no_gate_reports_and_cannot_be_cancelled() {
    let (dir, files) = damaged_set("control-report-only", &[(0, 1)]);
    let rec = Arc::new(Rec::default());
    let mut o = watching(rec.clone(), None);
    let status = repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
        .expect("the repair runs")
        .expect("the observer said Repair");
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert!(intact(&dir, &files));
    assert!(!rec.of(RepairPhase::Fold).is_empty(), "it still reports");
}

/// THE DAEMON'S DOOR. Everything above goes through
/// `repair_dir_set_surveyed`, which is the CLI's entry: a lazy catalog,
/// names settled after the scan, an `after_survey` refusal hook and an
/// `Ok(None)` verdict for it. The daemon wants none of those and takes
/// `repair_dir_set_with_donors_controlled_as` instead - the same
/// complete-catalog call it has always made, plus the control.
///
/// So this asserts the control arrives through THAT door too, on the
/// same two properties the headlines above assert for the surveying one:
/// a fraction that rises and lands in every phase, and a cancel raised
/// inside the fold that ends the repair before the fold finishes and
/// before a byte is written. Without this the daemon could be wired up
/// and the hook could be reached by nothing.
#[test]
fn the_controlled_entry_carries_progress_and_a_cancel_of_its_own() {
    let _rec_lock = crate::par2repair::census::testing::record();
    // See the fold-cancel headline: with retention on, a set this small
    // hands the whole fold over from memory and the reader threads that
    // poll the cancel per block never run.
    let _no_retain = crate::par2repair::retain::force_policy(0, true);
    let damage = [(0, 3), (1, 7), (2, 11), (3, 19)];

    // First: it REPORTS. Four phases, each announced, each landing on
    // its own total.
    let (dir, files) = damaged_set("controlled-entry-progress", &damage);
    let rec = Arc::new(Rec::default());
    let status = repair_dir_set_with_donors_controlled_as(
        &dir,
        &SET,
        &[],
        RetentionCaller::default(),
        RepairControl::new(Some(rec.clone()), Some(PauseGate::new())),
    )
    .expect("the repair runs");
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert!(intact(&dir, &files), "the repair is byte-exact");
    for phase in [
        RepairPhase::Verify,
        RepairPhase::Fold,
        RepairPhase::Solve,
        RepairPhase::Write,
    ] {
        let seen = rec.of(phase);
        assert!(!seen.is_empty(), "{phase:?} was never announced");
        let (last, total) = *seen.last().unwrap();
        assert_eq!(last, total, "{phase:?} ended at {last}/{total}");
    }

    // Second: it CANCELS, from inside the fold, before the patch.
    let (dir2, files2) = damaged_set("controlled-entry-cancel", &damage);
    let before: Vec<Vec<u8>> = files2
        .iter()
        .map(|(n, _)| std::fs::read(dir2.join(n)).unwrap())
        .collect();
    let gate = PauseGate::new();
    let rec2 = Arc::new(Rec {
        calls: Mutex::new(Vec::new()),
        slabs: Mutex::new(Vec::new()),
        arms: Mutex::new(Vec::new()),
        // The phase's sizing call, for the reason the surveying
        // headline's own trip gives.
        trip: Some((RepairPhase::Fold, 0, gate.clone())),
    });
    let err = repair_dir_set_with_donors_controlled_as(
        &dir2,
        &SET,
        &[],
        RetentionCaller::default(),
        RepairControl::new(Some(rec2.clone()), Some(gate.clone())),
    )
    .expect_err("a cancelled repair is not a verdict");
    assert!(
        matches!(err, RepairError::Cancelled),
        "a cancel must not be reported as a broken set: {err:?}"
    );
    // THE DISCRIMINATING PAIR, as in the surveying headline: a cancel
    // honoured only at the pre-patch gate would give the same verdict
    // and the same untouched directory, having folded the whole set
    // first.
    let (last, total) = *rec2.of(RepairPhase::Fold).last().unwrap();
    assert!(
        last < total,
        "the fold ran to completion ({last}/{total}) under a cancel raised inside it"
    );
    assert!(
        rec2.of(RepairPhase::Write).is_empty(),
        "a cancel before the patch must not open the write phase"
    );
    for ((name, _), was) in files2.iter().zip(&before) {
        assert_eq!(&std::fs::read(dir2.join(name)).unwrap(), was, "{name}");
    }
    assert!(!any_repair_temp(&dir2), "a repair temp survived the cancel");

    // ...and it is re-runnable through the same door with no control at
    // all, which is the uncontrolled call this entry has to stay equal
    // to.
    let again = repair_dir_set_with_donors_controlled_as(
        &dir2,
        &SET,
        &[],
        RetentionCaller::default(),
        RepairControl::default(),
    )
    .expect("the re-run repairs");
    assert!(matches!(again, RepairStatus::Repaired(_)), "{again:?}");
    assert!(intact(&dir2, &files2), "the re-run is byte-exact");
}

/// The repair's staging name, as `repair_dir_set_inner` spells it. A
/// test that looked for `*.tmp` would miss it and pass over a leak.
fn any_repair_temp(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().contains("nzbfast-repair"))
}

/// A SLABBED repair announces every sweep, and announces it BEFORE the
/// sweep reports anything.
///
/// The count is the half that cannot be inferred and the whole reason
/// this method exists: a sink that weighs the four phases into one bar
/// has to reserve the room for sweeps 2..N before sweep 1 spends it, or
/// take the bar backwards to make room. Until 16 Sep 2026 nothing
/// carried it and the daemon's bar froze at the literal pair
/// `("solve", 950)` for 41.5% to 70.3% of a slabbed repair's wall
/// (`research/REPAIR-SLABBED-BAR-2026-09-16.md`).
///
/// Driven through `ForcedSlabWidth` rather than through the memory
/// budget, for the reason that seam exists: the budget route needs a
/// multi-GiB corpus to trip, and this fixture is 64-byte blocks.
#[test]
fn a_slabbed_repair_announces_every_sweep_before_the_sweep_reports() {
    use crate::par2repair::reconstruct::ForcedSlabWidth;
    // BS is 64, so a forced 16-byte cut is four sweeps of the payload.
    const SLABS: usize = 4;
    let (dir, files) = damaged_set("control-slab-announce", &[(0, 3), (1, 7), (2, 11), (3, 19)]);
    let rec = Arc::new(Rec::default());
    let mut o = watching(rec.clone(), Some(PauseGate::new()));
    let status = {
        let _w = ForcedSlabWidth::set(BS / SLABS);
        repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
            .expect("the repair runs")
            .expect("the observer said Repair")
    };
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert!(intact(&dir, &files), "a slabbed repair is byte-exact");

    let slabs = rec.slabs.lock_ok().clone();
    assert_eq!(
        slabs.iter().map(|&(i, of, _)| (i, of)).collect::<Vec<_>>(),
        (0..SLABS).map(|i| (i, SLABS)).collect::<Vec<_>>(),
        "the sweeps were not announced once each, in order, with the count"
    );

    // AND EACH ONE CAME FIRST. The fold of sweep `i` is the first call
    // after its announcement, so the announcement's position in the
    // call list must be the index of a `Fold` sizing call - which is
    // what lets a sink weigh that fold in the frame it belongs to
    // rather than in the previous sweep's.
    let calls = rec.calls();
    for &(i, _, at) in &slabs {
        let (phase, done, _) = *calls
            .get(at)
            .unwrap_or_else(|| panic!("sweep {i} announced past the end of the repair"));
        assert_eq!(
            (phase, done),
            (RepairPhase::Fold, 0),
            "sweep {i} was announced at call {at}, which is not the opening of its fold - a \
             sink that read it there would weigh part of the sweep in the wrong frame"
        );
    }

    // THE FOLD IS ENTERED ONCE PER SWEEP - the shape the announcement
    // is the frame for. Counting the SIZING calls (`done == 0`), since
    // `begin` is the one call a phase makes exactly once per entry.
    let entries = |phase| {
        calls
            .iter()
            .filter(|&&(p, d, _)| p == phase && d == 0)
            .count()
    };
    assert_eq!(
        entries(RepairPhase::Fold),
        SLABS,
        "the fold was not entered once per sweep"
    );
    // THE SOLVE IS ENTERED MORE THAN ONCE PER SWEEP, and that is the
    // engine's own shape rather than a slab effect: the dense arm
    // reports its Gauss-Jordan inverse and its back-substitution as two
    // Solve entries (`reconstruct.rs`, `begin(Solve, missing.len())`
    // during construction and `begin(Solve, m)` in the back-substitution
    // itself), so a one-sweep repair on this arm reports two as well.
    // Asserted as a MULTIPLE so this stays a statement about sweeps: a
    // sink weighs every entry of a phase into that sweep's band, and
    // a re-entry inside one band is the case `repairprog` has handled
    // since it was written.
    let solves = entries(RepairPhase::Solve);
    assert!(
        solves >= SLABS && solves % SLABS == 0,
        "the solve was entered {solves} time(s) over {SLABS} sweep(s) - not a whole \
         number of entries per sweep, so this is no longer per-sweep behaviour"
    );
}

/// THE TWO SOLVE ARMS ANNOUNCE THEMSELVES, in the order they run, and
/// the inverse announces BEFORE the fold it precedes.
///
/// `RepairPhase::Solve` is entered twice within one sweep on the
/// unstructured arm - the Gauss-Jordan inverse of the explicit m x m
/// during construction, in matrix COLUMNS, and the back-substitution
/// after the feed, in fold UNITS - and from the `progress` calls alone
/// the two are indistinguishable. A sink that weighs the phases into
/// one bar gave them one band, so the first walked it to the top and
/// the monotone bar swallowed the second whole: measured 18 Sep 2026 on
/// the m = 10,000 gapped fixture, the queue row read `95%` unchanged
/// for 19.0 s of a 63.7 s repair (TODO 352).
///
/// The POSITIONS are the half that matters as much as the order. The
/// inverse is announced before its own sizing call and before the first
/// folded byte, which is what lets a band table put it UNDER the fold
/// rather than over it - banded above the feed it publishes past every
/// fold reading of an unstructured repair, and a monotone bar discards
/// them all.
#[test]
fn the_two_solve_arms_announce_themselves_around_the_fold_between_them() {
    // NOT `damaged_set`: its consecutive exponents are structured, and
    // the structured arms compute no inverse. These are scattered far
    // enough apart to be neither a run nor a relabelable progression.
    let exps = [0u32, 5, 11, 20, 34, 55, 89, 144];
    let (dir, files) = damaged_set_with_exps(
        "control-solve-arms",
        &[(0, 3), (1, 7), (2, 11), (3, 19)],
        &exps,
    );
    let rec = Arc::new(Rec::default());
    let mut o = watching(rec.clone(), Some(PauseGate::new()));
    let status = repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
        .expect("the repair runs")
        .expect("the observer said Repair");
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert!(intact(&dir, &files), "the unstructured arm is byte-exact");

    let arms = rec.arms.lock_ok().clone();
    assert_eq!(
        arms.iter().map(|&(a, _)| a).collect::<Vec<_>>(),
        vec![SolveArm::Inverse, SolveArm::BackSub],
        "the unstructured arm did not announce its two solves once each, in order - if          this set stopped taking the dense arm the test is measuring nothing"
    );
    let (inv_at, back_at) = (arms[0].1, arms[1].1);

    // EACH ANNOUNCEMENT SIZES THE ENTRY IT FRAMES. `begin` is the one
    // call a phase makes exactly once per entry (`done == 0`), so the
    // call sitting at the announcement's index is that arm's own
    // opening - a sink reading the arm at any later call would weigh
    // part of it in the previous arm's band.
    let calls = rec.calls();
    for (what, at) in [("inverse", inv_at), ("back-substitution", back_at)] {
        let (phase, done, _) = *calls
            .get(at)
            .unwrap_or_else(|| panic!("the {what} was announced past the end of the repair"));
        assert_eq!(
            (phase, done),
            (RepairPhase::Solve, 0),
            "the {what} was announced at call {at}, which is not the opening of a solve"
        );
    }

    // AND THE FOLD IS BETWEEN THEM, which is why one band cannot hold
    // both: the inverse runs before a block has been read and the
    // back-substitution after the whole feed is in.
    let folded = |lo: usize, hi: usize| {
        calls[lo..hi]
            .iter()
            .any(|&(p, d, _)| p == RepairPhase::Fold && d > 0)
    };
    assert!(
        folded(inv_at, back_at),
        "no fold byte was reported between the two solve arms: {calls:?}"
    );
    assert!(
        !folded(0, inv_at),
        "the fold had already reported bytes before the inverse announced itself - the          inverse is supposed to run ahead of the feed, and a band under the fold would          then be a bar going backwards: {calls:?}"
    );
}

/// TODO 353: a slabbed repair builds its back-substitution plan ONCE,
/// not once per sweep - and on the unstructured arm that plan is the
/// `O(m^3)` Gauss-Jordan inverse.
///
/// THE READING THAT OPENED 353, and what it cost. Both drivers call
/// `Reconstructor::new_controlled` inside their slab loop, and until
/// 20 Sep 2026 that constructor derived the whole plan itself. The plan
/// is a function of the recovery EXPONENTS and the input base logs, both
/// drivers pin one recovery selection for the whole repair (the disk
/// driver refuses outright if it changes between slabs), and a slab is a
/// byte range over that same system - so every sweep past the first
/// rebuilt a plan it already had. This test run against the code as it
/// stood saw the inverse built FOUR times over four sweeps, with `m`
/// identical and only the slab WIDTH moving, which is the input the plan
/// does not read. At m = 10,000 that inverse was 39.6 s of a 61.6 s
/// repair at ONE slab (`research/REPAIR-ROW-ACCEPTANCE-2026-09-18.md`).
///
/// What is asserted now is the contract after the hoist: `SLABS` sweeps,
/// ONE computed plan, `SLABS - 1` reuses. The pre-hoist code fails the
/// count, which is what makes this a regression guard rather than a
/// restatement of the fix.
///
/// It does NOT assert a cost. This fixture is 64-byte blocks and `m` is
/// 4, where the inverse is microseconds; the saving is measured at size
/// and written up in `research/REPAIR-BACKSUB-HOIST-2026-09-20.md`.
#[test]
fn a_slabbed_repair_builds_one_backsub_plan_for_all_its_sweeps() {
    use crate::par2repair::reconstruct::{BacksubPlanTally, ForcedSlabWidth};
    const SLABS: usize = 4;
    // Neither consecutive nor an arithmetic progression, so the four
    // smallest - which is what a four-block repair selects - land on
    // the arm with no structure to exploit.
    let (dir, files) = damaged_set_with_exps(
        "control-slab-backsub",
        &[(0, 3), (1, 7), (2, 11), (3, 19)],
        &[0, 1, 3, 7, 12, 20, 33, 47],
    );
    let rec = Arc::new(Rec::default());
    let mut o = watching(rec.clone(), Some(PauseGate::new()));
    let tally = BacksubPlanTally::take();
    let status = {
        let _w = ForcedSlabWidth::set(BS / SLABS);
        repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
            .expect("the repair runs")
            .expect("the observer said Repair")
    };
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    // THE ANSWER IS STILL RIGHT, which is the half a count cannot say:
    // a hoisted plan that had gone stale between sweeps would write
    // bytes that look repaired and are not.
    assert!(intact(&dir, &files), "a slabbed repair is byte-exact");
    assert_eq!(
        rec.slabs.lock_ok().len(),
        SLABS,
        "the fixture did not slab, so this test says nothing about slabs"
    );

    let plans = tally.plans();
    // THE FIXTURE'S OWN PRECONDITION. A consecutive exponent run takes
    // the Vandermonde or Forney arm, where the plan is cheap and 353
    // does not bite; a test that silently landed there would pass for
    // the wrong reason.
    assert!(
        plans.iter().all(|&(label, _, _)| label == "gauss-jordan"),
        "the fixture left the unstructured arm: {plans:?}"
    );
    // ONE CONSTRUCTION PER SWEEP - the shape the hoist has to preserve.
    // A test that only counted computations would also pass if slabbing
    // itself had broken.
    assert_eq!(
        plans.len(),
        SLABS,
        "the constructor was entered {} time(s) over {SLABS} sweep(s)",
        plans.len()
    );
    // ...AND EXACTLY ONE OF THEM SOLVED A SYSTEM. This was `SLABS`
    // before the hoist, which is the number 353 was opened over.
    let computed = tally.computed();
    assert_eq!(
        computed, 1,
        "the O(m^3) inverse was built {computed} time(s) for one answer"
    );
    // ...AND THE SWEEPS REALLY DID RUN AT DIFFERENT SLAB WIDTHS' worth
    // of payload over one unmoving system: `m` is what the inverse is
    // cubic in, and the slab width is the only input that moves.
    let ms: Vec<usize> = plans.iter().map(|&(_, m, _)| m).collect();
    assert_eq!(ms, vec![4; SLABS], "the missing set moved between sweeps");
    let widths: Vec<usize> = plans.iter().map(|&(_, _, w)| w).collect();
    assert_eq!(
        widths,
        vec![BS / SLABS; SLABS],
        "the sweeps did not all run at the forced slab width"
    );

    // AND THE ONE INVERSE THAT IS LEFT IS STILL INSIDE SWEEP 0's FRAME.
    // This is what makes the hoist invisible to a sink that weighs the
    // phases into per-sweep bands: sweep 0 reports exactly what it
    // always reported, and sweeps 1..N stop announcing an inverse,
    // which is the "no inverse" case such a sink already handles. The
    // plan is therefore filled INSIDE the slab loop and not above it -
    // above it, the inverse would report before the first
    // `slab(0, of)` and land in no sweep's frame at all.
    let calls = rec.calls();
    let sweep_at: Vec<usize> = rec.slabs.lock_ok().iter().map(|&(.., at)| at).collect();
    let solve_opens: Vec<usize> = calls
        .iter()
        .enumerate()
        .filter(|&(_, &(p, d, _))| p == RepairPhase::Solve && d == 0)
        .map(|(i, _)| i)
        .collect();
    // The dense arm opens Solve TWICE in the sweep that computes the
    // plan (the inverse, then the back-substitution) and once in every
    // other sweep.
    // The dense arm opens Solve TWICE per sweep in the back-substitution
    // alone - once sized in missing blocks and once re-sized to the
    // fold's unit grid, which is finer (`finish_blocks_reported`) - and
    // the sweep that computes the plan opens it a THIRD time for the
    // Gauss-Jordan inverse. So the shape is 3 in sweep 0 and 2 after,
    // where before the hoist it was 3 in every sweep.
    assert_eq!(
        solve_opens.len(),
        3 + 2 * (SLABS - 1),
        "solve was opened {} time(s) over {SLABS} sweep(s); {} before the hoist",
        solve_opens.len(),
        3 * SLABS
    );
    let in_sweep = |at: usize| sweep_at.iter().rposition(|&s| s <= at);
    let per_sweep = (0..SLABS)
        .map(|i| {
            solve_opens
                .iter()
                .filter(|&&at| in_sweep(at) == Some(i))
                .count()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        per_sweep,
        std::iter::once(3usize)
            .chain(std::iter::repeat_n(2, SLABS - 1))
            .collect::<Vec<_>>(),
        "the surviving inverse did not land in sweep 0's frame"
    );
}

/// A repair that does NOT slab announces exactly one sweep, of one -
/// so a sink never has to treat "no announcement" and "one sweep"
/// differently, and the ordinary bar is the pre-slab bar.
#[test]
fn an_ordinary_repair_announces_one_sweep_of_one() {
    let (dir, files) = damaged_set("control-slab-single", &[(0, 3), (2, 11)]);
    let rec = Arc::new(Rec::default());
    let mut o = watching(rec.clone(), Some(PauseGate::new()));
    let status = repair_dir_set_surveyed(&dir, &SET, &[], &mut o)
        .expect("the repair runs")
        .expect("the observer said Repair");
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert!(intact(&dir, &files));
    assert_eq!(
        rec.slabs
            .lock_ok()
            .iter()
            .map(|&(i, of, _)| (i, of))
            .collect::<Vec<_>>(),
        vec![(0, 1)]
    );
}

// ---------------------------------------------------------------------------
// The two doors opened 16 Sep 2026 (claim
// `repair-control-two-censused-sites-16sep`), which are the two the
// 12 Sep census named as the reason `serve/mod.rs` still set an
// unattended unstructured ceiling: the no-set obfuscated arm's
// directory walk, and the MAPPED in-stream driver. The assertions are
// the same ones this file makes of the doors above it - a fraction that
// rises and lands, and a cancel that ends a repair sooner than it would
// have ended and leaves a directory a re-run recovers from - because a
// test that only checked the sink was called would pass over a bar that
// never moves.
// ---------------------------------------------------------------------------

/// A whole-file buffer set behind a [`VolumeIo`], for the mapped
/// driver: that driver never touches the caller's disk, so its rig is
/// memory and the recovery packets on disk are the only files.
struct BufIo(Vec<Mutex<Vec<u8>>>);

impl VolumeIo for BufIo {
    fn read(&self, f: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let d = self.0[f].lock_ok();
        let off = off as usize;
        buf.copy_from_slice(&d[off..off + buf.len()]);
        Ok(())
    }
    fn write(&self, f: usize, off: u64, data: &[u8]) -> std::io::Result<()> {
        let mut d = self.0[f].lock_ok();
        let off = off as usize;
        d[off..off + data.len()].copy_from_slice(data);
        Ok(())
    }
}

/// The mapped driver's rig: a real recovery set on disk (so
/// `PacketCatalog::build` has something to validate), the members'
/// TRUE bytes, and the damaged copies behind a [`BufIo`] with their
/// present vectors.
///
/// 200 blocks a member rather than `damaged_set`'s 40, and that is
/// about the FOLD: the feed reports per block and the sink is reached
/// once per `STEPS` bucket, so a set small enough to fold in two
/// buckets cannot show a rising fraction and cannot be cancelled
/// mid-feed either. Still 38 KB, which is free.
fn mapped_rig(
    tag: &str,
    damage: &[(usize, usize)],
) -> (PathBuf, Vec<Vec<u8>>, Vec<(Par2File, Vec<bool>)>, BufIo) {
    mapped_rig_sized(tag, BS, 200, damage)
}

/// [`mapped_rig`] over a chosen BLOCK SIZE and block count.
///
/// The size is a parameter because one test needs the fold to have more
/// than one work unit in it, and the block is what decides that: the
/// tiled fold refuses to split a column narrower than `MIN_COL_WORDS`
/// (2,048 words, `linalg`), so a set whose whole block is 32 words has
/// exactly one unit per fold call however many cores or missing blocks
/// it has - and a phase that reports per unit can then only say `0` and
/// `total`. A block wider than that splits on every box and every
/// architecture, which is what makes the requirement statable at all.
fn mapped_rig_sized(
    tag: &str,
    bs: usize,
    blocks: usize,
    damage: &[(usize, usize)],
) -> (PathBuf, Vec<Vec<u8>>, Vec<(Par2File, Vec<bool>)>, BufIo) {
    let dir = tmpdir(tag);
    let whole: Vec<Vec<u8>> = (0..3)
        .map(|i| payload(bs * blocks, 31 + i as u64))
        .collect();
    let names: Vec<String> = (0..3).map(|i| format!("m{i}.bin")).collect();
    let refs: Vec<(&str, &[u8])> = names
        .iter()
        .zip(&whole)
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    std::fs::write(dir.join("set.par2"), par2_index(SET, bs, &refs)).unwrap();
    let exps: Vec<u32> = (0..32u32).collect();
    std::fs::write(
        dir.join("set.vol0+32.par2"),
        par2_volume(SET, bs, &refs, &exps),
    )
    .unwrap();
    let metas: Vec<Par2File> = names
        .iter()
        .zip(&whole)
        .map(|(n, d)| meta_for(n, d, bs))
        .collect();
    let mut damaged = whole.clone();
    let mut present: Vec<Vec<bool>> = metas
        .iter()
        .map(|m| vec![true; m.length.div_ceil(bs as u64) as usize])
        .collect();
    for &(fi, bi) in damage {
        present[fi][bi] = false;
        for b in &mut damaged[fi][bi * bs..(bi + 1) * bs] {
            *b ^= 0xFF;
        }
    }
    let files: Vec<(Par2File, Vec<bool>)> = metas.into_iter().zip(present).collect();
    let io = BufIo(damaged.into_iter().map(Mutex::new).collect());
    (dir, whole, files, io)
}

/// THE MAPPED DRIVER REPORTS ITS FOUR PHASES. Until 16 Sep 2026 this
/// driver carried no control at all - not a counter, not a poll - and
/// it is the route a downloading job actually takes, so it was the
/// longest silent stretch left in the pipeline.
///
/// FOUR - including `Verify`, which was left silent by decision until
/// this same day. This driver has no pre-fold verify pass - its
/// present-block ledger was earned off the wire - so its only proof is
/// the SELF-PROVE after the patch, and the disk driver's own Verify band
/// is sized for a phase that runs FIRST
/// (`nzbfast_core::repairprog::band` gives it `[0.0, 0.45)`). The first
/// cut of this work published it there anyway and had to be backed out:
/// it landed behind a Write that had already reached full, a monotone
/// bar discarded it, and the row sat at `write, 100%` through the whole
/// of a full-set reread - the stall this mechanism exists to remove.
///
/// The fix is `RepairRoute::Mapped`
/// (`nzbfast_core::repairprog::band`'s route match), which this test
/// does not reach - it is engine-level, and the route only changes WHERE
/// a caller's band table puts the reading, not whether this driver
/// reports it. What this test pins is the engine's own contract: the
/// self-prove now calls `begin`/`step`/`finish` on `Verify` like every
/// other phase, landing on full, and it does so AFTER `Write` - which is
/// the ordering a route-aware band table depends on.
#[test]
fn the_mapped_driver_reports_a_rising_fraction_through_all_four_phases() {
    // A WIDER BLOCK THAN ITS NEIGHBOURS, and 16 of them rather than
    // 200 so the fixture costs the same: this is the only test here
    // that holds the fold to a RISING fraction rather than to a
    // landing, and since 17 Sep 2026 the fold reports per unit of its
    // own work grid. `mapped_rig_sized` carries why 64-byte blocks
    // cannot have more than one such unit.
    const WIDE: usize = 8192;
    let (dir, whole, files, io) =
        mapped_rig_sized("mapped-progress", WIDE, 16, &[(0, 3), (1, 7), (2, 11)]);
    let rec = Arc::new(Rec::default());
    let control = RepairControl::new(Some(rec.clone()), Some(PauseGate::new()));
    let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
    let n = super::super::repair_mapped_catalog_resumed_controlled(
        &files,
        WIDE,
        &mut cat,
        &SET,
        &io,
        false,
        &[],
        &control,
    )
    .expect("the set has ample parity");
    assert_eq!(n, 3, "one block rebuilt per damaged member");
    for (fi, want) in whole.iter().enumerate() {
        assert_eq!(&*io.0[fi].lock_ok(), want, "member {fi} is byte-exact");
    }

    for phase in [
        RepairPhase::Fold,
        RepairPhase::Solve,
        RepairPhase::Write,
        RepairPhase::Verify,
    ] {
        let seen = rec.of(phase);
        assert!(
            !seen.is_empty(),
            "{phase:?} reported nothing - this driver reported nothing at all before \
             16 Sep 2026 and the whole point of the control is that it now does"
        );
        let (done, total) = *seen.last().expect("non-empty");
        assert_eq!(
            done, total,
            "{phase:?} must land on full, or a bar stops at whatever bucket the last \
             batch happened to cross: {seen:?}"
        );
    }
    // The FOLD is the phase this exists for, so it alone is held to a
    // rising fraction rather than merely to a landing.
    //
    // WHAT IS ASSERTED HERE IS "THE BAR MOVED", AND NOT A SAMPLE COUNT.
    // It read `fold.len() >= 3` from 17 Sep 2026 until 18 Sep, and that
    // number is a property of the MACHINE rather than of the reporting
    // code: the fold reports once per unit of its own work grid, and
    // that grid's width comes from `mem::fold_workers()`, from the L2
    // the part reports, and from how many batches the feed merged the
    // read into - none of which this fixture controls. It reddened
    // `windows-unit` shard 1/6 on main on 18 Sep 2026 (run 35368239605,
    // sha 6cfd0136, claim `red-windows-unit-6cfd0136`), where the whole
    // feed arrived as ONE batch over a ONE-unit grid and the phase
    // reported exactly its announcement and its landing: two samples,
    // 0 and full.
    //
    // THAT IS HONEST BEHAVIOUR FOR A 360 KB FIXTURE AND NOT THE DEFECT
    // THIS TEST GUARDS. A real repair's grid is many units wide, so the
    // bar moves there; a fixture this small cannot force a multi-unit
    // grid on a machine whose cores or cache geometry answer otherwise,
    // and no sizing of it can - `col_splits` is clamped to
    // `words.div_ceil(MIN_COL_WORDS)`, which is 1 for any block this
    // test could afford, so the grid's only dimension left is rows, and
    // rows chunk by core count. MEASURED on the dev Mac by pinning the
    // width with `mem::FoldWidthCap`: widths 1 and 2 report exactly
    // THREE samples, one above the old floor, and widths 3, 4 and 8
    // report five. So `>= 3` was passing by one sample on ordinary
    // hardware and was never a statement the code could keep.
    //
    // AND THE WIDTH IS NOT EVEN THE DISCRIMINATOR - re-measured 20 Sep
    // 2026, twenty COLD processes per box (nextest gives every test its
    // own process, so a cold one is what CI runs), the same fixture:
    //
    //   aarch64 desktop, 32 cores, loaded  : 3 (x3), 5 (x15), 7, 11
    //   x86_64 Linux, 12-core Xeon D-1531  : 4 (x7), 5 (x13)
    //   the 18 Sep windows-unit runner     : 2
    //
    // The count varies RUN TO RUN at a FIXED pinned width (width 2 read
    // 3 on one process and 5 on the next two), so the table above is a
    // set of single samples and not a function of the width: what moves
    // it is how many batches the feed merged the read into, which is a
    // scheduling outcome. THE LINUX x86 MARGIN, which the 18 Sep handoff
    // left unmeasured, is 2 samples above this floor at its worst of
    // twenty; the aarch64 desktop's is 1.
    //
    // THE FLOOR OF 2 IS THE REPORTING CODE'S STRUCTURAL MINIMUM, which
    // is why it is the right number: `linalg::fold_parallel_controlled`'s
    // own doc says a grid of ONE unit "says its bytes once, at the end",
    // so the fewest a passing run can emit is the phase announcement plus
    // that one report - 0 and full. A floor of 1 would assert nothing;
    // anything above 2 is the box's number and not the code's, which is
    // the mistake this comment records.
    //
    // AND THE FLOOR IS SAFE FOR A SECOND REASON, MEASURED 20 Sep 2026 ON
    // A WINDOWS BOX (claim `fold-grid-windows-one-unit-why-20sep`), which
    // matters because it holds at ANY grid width: `RepairControl::announce`
    // reads `done` FRESH under its lock and says nothing when another
    // worker has already reported a larger bucket, so a MULTI-unit grid
    // can report exactly twice as well. That is what the 18 Sep runner
    // did - see the assertion's own note below. No sample-count floor
    // above 2 is safe at any core count or any fixture size, and sizing
    // the fixture up would not buy one.
    //
    // The two things that ARE the code's to keep, and that the failure
    // message named all along, are asserted instead: the phase must be
    // updated after it is announced, and the fraction it reports must
    // actually RISE. A run that announces and never updates is one
    // sample; a run that reports a flat sequence is caught by the strict
    // rise, which the old count-based floor would have passed. NOT a
    // loosening to make a red agree: it is the same property, stated in
    // terms of the bar rather than of the box the test happened to run
    // on.
    //
    // THAT RUNNER'S GRID WAS NEVER ONE UNIT WIDE - chased to a line on a
    // Windows box 20 Sep 2026, claim `fold-grid-windows-one-unit-why-20sep`,
    // and all three of the candidates this comment used to list are wrong.
    // An ASUS Zenbook (Core Ultra 9 386H, 16 cores, no SMT, Windows 11)
    // builds the same TWO-unit grid this fixture gets everywhere -
    // rows=3, words=4096, row_threads=1, col_splits=2 - and reads
    // `available_parallelism` 16, `mem::fold_workers()` 16,
    // `linalg::physical_cores()` Some(16) and `unit_dst_budget()` the
    // 512 KiB default off a 4 MiB L2. Twenty unpinned cold runs there
    // gave 5 samples nineteen times and 4 once. The red reproduces at
    // that ORDINARY core count once the fold is oversubscribed: 50 cold
    // runs with the process on four CPUs and six spinners on the same
    // four gave 2 (x4), 3 (x7), 4 (x9), 5 (x30), and every samples=2 run
    // was ONE merged feed batch over a TWO-unit grid whose two
    // announcements coalesced in `announce`. A one-core fold does give 2
    // samples as well (`NZBFAST_CPU_WORKERS=1`, 3 of 3, `col_splits`
    // falling to 1 with it) but nothing needs it to explain the red.
    // `l2_per_core_bytes()` cannot reach this fixture at all: its budget
    // is consulted only on the `rows >= cores` branch, which three rows
    // do not take on any box with four cores or more.
    let fold = rec.of(RepairPhase::Fold);
    assert!(
        fold.len() >= 2,
        "the fold reported {} call(s) - a phase announced and never updated is the \
         bar that does not move",
        fold.len()
    );
    assert!(
        fold[0].0 < fold[fold.len() - 1].0,
        "the fold's fraction never rose - it was announced and landed with nothing \
         in between, which is a bar that does not move: {fold:?}"
    );
    assert!(
        fold.windows(2).all(|w| w[0].0 <= w[1].0),
        "the fold's fraction went backwards: {fold:?}"
    );
    // ORDER: fold, then solve, then write, then the self-prove - VERIFY
    // LAST is the whole point of `RepairRoute::Mapped`, and it is what a
    // route-aware band table depends on to place this reading after a
    // full Write rather than before an empty Fold.
    let calls = rec.calls();
    let last_fold = calls
        .iter()
        .rposition(|c| c.0 == RepairPhase::Fold)
        .expect("a fold happened");
    let first_write = calls
        .iter()
        .position(|c| c.0 == RepairPhase::Write)
        .expect("a write happened");
    let last_write = calls
        .iter()
        .rposition(|c| c.0 == RepairPhase::Write)
        .expect("a write happened");
    let first_verify = calls
        .iter()
        .position(|c| c.0 == RepairPhase::Verify)
        .expect("the self-prove happened");
    assert!(
        last_fold < first_write,
        "the patch must not begin reporting before the fold has finished: {calls:?}"
    );
    assert!(
        last_write < first_verify,
        "the self-prove must not begin reporting before the patch has finished - it \
         reads the bytes the patch just wrote: {calls:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A CANCEL RAISED MID-FOLD ENDS THE MAPPED REPAIR BEFORE IT WRITES,
/// and the buffers are left exactly as they were.
///
/// Tripped from INSIDE the fold's own sink rather than on a timer -
/// the same device every cancel test in this file uses, and the reason
/// is measured: a watcher that presses on a clock loses the whole
/// repair to one timeslice on a loaded box and sees it come back
/// repaired.
#[test]
fn a_cancel_raised_mid_fold_ends_the_mapped_repair_before_it_writes() {
    let (dir, whole, files, io) = mapped_rig("mapped-cancel", &[(0, 3), (1, 17), (2, 41)]);
    let before: Vec<Vec<u8>> = io.0.iter().map(|m| m.lock_ok().clone()).collect();
    let gate = PauseGate::new();
    let rec = Arc::new(Rec {
        // The phase's SIZING call, for the reason the surveying
        // headline's own trip gives: the fold reports per unit of its
        // work grid now, and a 64-byte block has exactly one such unit,
        // so its first non-zero figure is also its last. This is the
        // cue that still lands before the reader loop's first block.
        trip: Some((RepairPhase::Fold, 0, gate.clone())),
        ..Rec::default()
    });
    let control = RepairControl::new(Some(rec.clone()), Some(gate.clone()));
    let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
    let err = super::super::repair_mapped_catalog_resumed_controlled(
        &files,
        BS,
        &mut cat,
        &SET,
        &io,
        false,
        &[],
        &control,
    )
    .expect_err("a cancelled repair is not a verdict");
    assert!(
        matches!(err, RepairError::Cancelled),
        "a user's Cancel must not be reported as a set that could not be repaired: {err:?}"
    );
    // IT STOPPED EARLY, which is the claim a mere `Cancelled` does not
    // make: the fold's counter never reached its total.
    let fold = rec.of(RepairPhase::Fold);
    let (done, total) = *fold.last().expect("the fold reported before it was cut");
    assert!(
        done < total,
        "the fold ran to completion anyway ({done}/{total}) - the cancel was not \
         polled inside the feed"
    );
    assert!(
        rec.of(RepairPhase::Write).is_empty(),
        "nothing may be written after a cancel that landed in the fold"
    );
    for (fi, was) in before.iter().enumerate() {
        assert_eq!(
            &*io.0[fi].lock_ok(),
            was,
            "member {fi} was touched by a repair that never solved"
        );
    }

    // AND IT IS RE-RUNNABLE, which is the whole of what a cancel owes a
    // user who changes their mind - through a FRESH control, because
    // the cancelled gate is sticky by design.
    let again = super::super::repair_mapped_catalog_resumed_controlled(
        &files,
        BS,
        &mut cat,
        &SET,
        &io,
        false,
        &[],
        &RepairControl::new(None, Some(PauseGate::new())),
    )
    .expect("the re-run repairs");
    assert_eq!(again, 3);
    for (fi, want) in whole.iter().enumerate() {
        assert_eq!(&*io.0[fi].lock_ok(), want, "the re-run is byte-exact");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
/// A CANCEL RAISED INSIDE THE SOLVE ENDS THE MAPPED REPAIR BEFORE IT
/// WRITES - the window between the driver's pre-solve `check` and its
/// patch, which until 17 Sep 2026 had no poll in it at all.
///
/// THE SIBLING ABOVE DOES NOT COVER THIS AND CANNOT. It trips on the
/// fold and asserts `done < total`; this one trips on the SOLVE'S OWN
/// SIZING CALL and asserts the fold landed on FULL, which is what
/// places the cancel after `control.check()?` and after
/// `finish_owned_reported` has joined the syndrome worker. A cancel
/// raised early passes on either side of the fix and proves nothing.
///
/// WHY THE BYTES ARE NOT A REPAIR. Every stretch inside
/// `finish_owned_reported` abandons its work on a cancel and returns
/// NORMALLY - it hands back a tuple, not a `Result` - so nothing about
/// a half-solved set reaches the driver as an error: the fold worker
/// DRAINS its channel instead of folding (`Reconstructor::build`'s
/// worker loop), `ntt_syndromes_into`'s stripe workers `break`, and
/// `linalg::fold_parallel_opts`'s unit drain returns leaving the output
/// grid part-computed. Each of those sites says in a comment that it is
/// legal because "the driver refuses before the patch" - which was true
/// of `repair_dir_set_inner`, whose check sits at the head of its patch,
/// and was NOT true here.
///
/// THIS FIXTURE TAKES THE DENSE ARM (m = 3 is below
/// `forney::backsub_min_missing`, so consecutive exponents go to
/// `invert_vandermonde` rather than to a `ForneyPlan`), so before the
/// fix the patch wrote a grid the unit drain left at zero and the
/// self-prove reported `VerifyFailed("m0.bin")` - a user who pressed
/// Cancel told their set could not be repaired, and a verdict
/// `repair_dir_set_inner`'s retry ladder reads as a reason to try
/// again. The Forney arms poll nothing at all (`forney.rs` holds no
/// cancel site; `finish_blocks_reported` calls them "bracketed rather
/// than instrumented"), so on a set that took one of those the same
/// cancel produced CORRECT blocks and a completed repair - milder, and
/// still not what Cancel means. The assertions below hold either way,
/// which is why the test does not pin the arm.
#[test]
fn a_cancel_raised_inside_the_solve_ends_the_mapped_repair_before_it_writes() {
    let (dir, whole, files, io) = mapped_rig("mapped-cancel-solve", &[(0, 3), (1, 17), (2, 41)]);
    let before: Vec<Vec<u8>> = io.0.iter().map(|m| m.lock_ok().clone()).collect();
    let gate = PauseGate::new();
    let rec = Arc::new(Rec {
        // THE SOLVE'S SIZING CALL, which `finish_blocks_reported` makes
        // on the driver thread after the syndrome worker has been
        // joined and the retained tail transformed - so the cancel
        // lands inside the window, synchronously, with no clock in it.
        // The consecutive-exponent arm this fixture takes never reports
        // `Solve` during construction (only the Gauss-Jordan arm does,
        // and that one is reached when recovery packets were themselves
        // lost), so the first `Solve` call a sink sees here is the one
        // past the driver's `check`. The fold assertion below is what
        // proves it rather than assuming it.
        trip: Some((RepairPhase::Solve, 0, gate.clone())),
        ..Rec::default()
    });
    let control = RepairControl::new(Some(rec.clone()), Some(gate.clone()));
    let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
    let err = super::super::repair_mapped_catalog_resumed_controlled(
        &files,
        BS,
        &mut cat,
        &SET,
        &io,
        false,
        &[],
        &control,
    )
    .expect_err("a cancelled repair is not a verdict");
    assert!(
        matches!(err, RepairError::Cancelled),
        "a user's Cancel must not be reported as a set that could not be repaired: {err:?}"
    );
    // THE CANCEL LANDED PAST THE FOLD, which is the half that makes
    // this a test of the pre-patch window rather than a second copy of
    // the mid-fold test above.
    let fold = rec.of(RepairPhase::Fold);
    let (done, total) = *fold
        .last()
        .expect("the fold reported before the solve began");
    assert_eq!(
        done, total,
        "the fold did not land ({done}/{total}) - this cancel was raised before the \
         driver's pre-solve check and so proves nothing about the window after it"
    );
    assert!(
        rec.of(RepairPhase::Write).is_empty(),
        "nothing may be written after a cancel that landed in the solve: {:?}",
        rec.of(RepairPhase::Write)
    );
    // AND THE BUFFERS ARE UNTOUCHED. This is the claim that matters:
    // the mapped driver's writes go through `VolumeIo` into a LIVE
    // extractor slot, and a half-applied slab has no caller-visible
    // rollback the way the disk driver's temp-staged rename does.
    for (fi, was) in before.iter().enumerate() {
        assert_eq!(
            &*io.0[fi].lock_ok(),
            was,
            "member {fi} was patched with blocks an abandoned solve produced"
        );
    }

    // AND IT IS RE-RUNNABLE through a fresh control, the same thing the
    // mid-fold cancel owes: the gate is sticky by design.
    let again = super::super::repair_mapped_catalog_resumed_controlled(
        &files,
        BS,
        &mut cat,
        &SET,
        &io,
        false,
        &[],
        &RepairControl::new(None, Some(PauseGate::new())),
    )
    .expect("the re-run repairs");
    assert_eq!(again, 3);
    for (fi, want) in whole.iter().enumerate() {
        assert_eq!(&*io.0[fi].lock_ok(), want, "the re-run is byte-exact");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A CANCELLED HANDLE REFUSES A MAPPED REPAIR WITHOUT BUYING THE
/// CORPUS. `load_mapped_recovery` preads and re-proves one block per
/// missing slice before a single syndrome is folded, so the check that
/// matters sits AHEAD of it - and the NTT fallback runs that closure a
/// second time, which is the shape that would otherwise pay twice for
/// a repair already called off.
#[test]
fn a_cancelled_handle_refuses_a_mapped_repair_before_it_loads_recovery() {
    let (dir, _whole, files, io) = mapped_rig("mapped-sticky", &[(0, 3)]);
    let gate = PauseGate::new();
    gate.cancel();
    let rec = Arc::new(Rec::default());
    let control = RepairControl::new(Some(rec.clone()), Some(gate));
    let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
    let err = super::super::repair_mapped_catalog_resumed_controlled(
        &files,
        BS,
        &mut cat,
        &SET,
        &io,
        false,
        &[],
        &control,
    )
    .expect_err("a cancelled handle does not repair");
    assert!(matches!(err, RepairError::Cancelled), "{err:?}");
    assert!(
        rec.calls().is_empty(),
        "no phase may be announced by a repair that never started: {:?}",
        rec.calls()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE NO-SET ARM'S DOOR ASKS FOR A CONTROL ONCE PER SET, which is the
/// property the supplier shape exists for: this walks EVERY qualifying
/// set in the directory, and a caller handed one control for the
/// directory would draw a bar that sat at 100% for every set after the
/// first - the "Repairing, 100%" stall the whole mechanism removes, on
/// a repair that is genuinely running.
///
/// Two sets in one directory, so "once per set" is distinguishable
/// from "once".
#[test]
fn the_present_or_renamed_sets_door_asks_for_a_control_once_per_set() {
    let dir = tmpdir("norenamed-per-set");
    let asked = AtomicUsize::new(0);
    for (si, id) in [[4u8; 16], [5u8; 16]].into_iter().enumerate() {
        let name = format!("s{si}.bin");
        let data = payload(BS * 40, 71 + si as u64);
        let refs: &[(&str, &[u8])] = &[(name.as_str(), &data)];
        std::fs::write(dir.join(format!("s{si}.par2")), par2_index(id, BS, refs)).unwrap();
        let exps: Vec<u32> = (0..16u32).collect();
        std::fs::write(
            dir.join(format!("s{si}.vol0+16.par2")),
            par2_volume(id, BS, refs, &exps),
        )
        .unwrap();
        let mut damaged = data.clone();
        for b in &mut damaged[BS * 3..BS * 4] {
            *b ^= 0xFF;
        }
        std::fs::write(dir.join(&name), &damaged).unwrap();
    }
    let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
    let outcomes = cat
        .repair_present_or_renamed_sets_controlled(&|| {
            asked.fetch_add(1, Ordering::Relaxed);
            RepairControl::new(Some(Arc::new(Rec::default())), Some(PauseGate::new()))
        })
        .expect("the walk runs");
    assert_eq!(outcomes.len(), 2, "both sets were attempted: {outcomes:?}");
    for o in &outcomes {
        assert!(
            matches!(o.status, Ok(RepairStatus::Repaired(_))),
            "each set has ample parity: {:?}",
            o.status
        );
    }
    assert_eq!(
        asked.load(Ordering::Relaxed),
        2,
        "the control must be asked for once per SET, at that set's own boundary - \
         one clone for the directory is a bar that reads full for every set but the first"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A CANCEL ENDS THE NO-SET ARM'S WALK ON THE SET IT LANDED IN, and the
/// walk does not go on to report the sets behind it as unreadable.
///
/// The renamed-fallback arm of `repair_sets_catalog` is a SECOND loop
/// with its own set edge, and this door is the only production caller
/// that can reach it - so the break is pinned here rather than left to
/// the sibling door's test, which only ever drives the first loop.
#[test]
fn a_cancelled_no_set_walk_stops_on_its_set_and_is_not_a_run_of_broken_ones() {
    let dir = tmpdir("norenamed-cancel");
    let mut truth: Vec<(String, Vec<u8>)> = Vec::new();
    for (si, id) in [[6u8; 16], [7u8; 16]].into_iter().enumerate() {
        let name = format!("t{si}.bin");
        let data = payload(BS * 200, 91 + si as u64);
        let refs: &[(&str, &[u8])] = &[(name.as_str(), &data)];
        std::fs::write(dir.join(format!("t{si}.par2")), par2_index(id, BS, refs)).unwrap();
        let exps: Vec<u32> = (0..16u32).collect();
        std::fs::write(
            dir.join(format!("t{si}.vol0+16.par2")),
            par2_volume(id, BS, refs, &exps),
        )
        .unwrap();
        let mut damaged = data.clone();
        for b in &mut damaged[BS * 3..BS * 4] {
            *b ^= 0xFF;
        }
        std::fs::write(dir.join(&name), &damaged).unwrap();
        truth.push((name, data));
    }
    let gate = PauseGate::new();
    let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
    let outcomes = cat
        .repair_present_or_renamed_sets_controlled(&|| {
            RepairControl::new(
                Some(Arc::new(Rec {
                    trip: Some((RepairPhase::Fold, 1, gate.clone())),
                    ..Rec::default()
                })),
                Some(gate.clone()),
            )
        })
        .expect("the walk itself does not error");
    assert_eq!(
        outcomes.len(),
        1,
        "the walk must BREAK on the cancelled set rather than carry a sticky gate into \
         the next one - a run of `Cancelled` verdicts reads like N unreadable sets over \
         a directory where the user simply pressed Cancel: {outcomes:?}"
    );
    assert!(
        matches!(outcomes[0].status, Err(RepairError::Cancelled)),
        "{:?}",
        outcomes[0].status
    );

    // AND THE DIRECTORY IS RE-RUNNABLE, through a fresh gate: both sets
    // repair, including the one the cancelled walk never reached.
    let again = cat
        .repair_present_or_renamed_sets_controlled(&|| {
            RepairControl::new(None, Some(PauseGate::new()))
        })
        .expect("the re-run walks");
    assert_eq!(again.len(), 2, "{again:?}");
    assert!(intact(&dir, &truth), "the re-run is byte-exact");
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 332 at the DRIVER: an armed veto turns a long repair into
/// `RepairError::Deferred` and leaves the directory bit-for-bit alone.
///
/// # Why the set is this shape, which is the whole of the test's design
///
/// The veto fires on `RepairForecast::is_long` - an UNSTRUCTURED solve
/// past `MAX_REPAIR_DIM` - so a test of the real path needs more than
/// 8,192 missing blocks. Blocks are four bytes here, the format's own
/// floor, so 8,193 of them is 32 KB of payload.
///
/// The recovery set is deliberately SHORT (three scattered exponents)
/// rather than full-with-a-gap, and that is a price rather than a
/// shortcut: parity for 8,193 blocks costs the generator an 8,193 x
/// 8,194 fold, which is minutes in a unit suite, while three exponents
/// is instant. It reaches the same forecast by the same route -
/// `select_consecutive_run` cannot return a consecutive run of 8,193
/// out of three, so `solve` is `Unstructured` and `is_long` is true.
///
/// AND IT DOCUMENTS A REAL PROPERTY rather than dodging one: the
/// forecast is ADVISORY and is taken BEFORE the recovery slices are
/// picked, so a set that is going to turn out short defers first and
/// reports the shortfall on the pass after. That is exactly as true of
/// the "large repair ahead" WARN this veto acts on, and deliberately so
/// - the whole design is a caller acting on the same fact the log
/// already prints, at the same instant, rather than on a second one.
#[test]
fn an_armed_veto_stops_a_long_repair_before_a_byte_is_written() {
    const B: usize = 4;
    const N: usize = crate::par2repair::MAX_REPAIR_DIM + 1;
    let dir = tmpdir("defer-long");
    let data = payload(B * N, 31);
    let files: Vec<(&str, &[u8])> = vec![("long.bin", data.as_slice())];
    std::fs::write(dir.join("set.par2"), par2_index(SET, B, &files)).unwrap();
    std::fs::write(
        dir.join("set.vol000+03.par2"),
        par2_volume(SET, B, &files, &[0u32, 5, 9]),
    )
    .unwrap();
    // Every block wrong, so `missing` is the whole set.
    let wrecked = vec![0xA5u8; B * N];
    std::fs::write(dir.join("long.bin"), &wrecked).unwrap();

    let gate = crate::par2repair::DeferGate::armed();
    let control = RepairControl::new(Some(Arc::new(Rec::default())), Some(PauseGate::new()))
        .with_defer(Some(gate.clone()));
    let err = crate::par2repair::repair_dir_set_with_donors_controlled_as(
        &dir,
        &SET,
        &[],
        Default::default(),
        control,
    )
    .expect_err("an armed veto refuses a long repair");
    match err {
        crate::par2repair::RepairError::Deferred { missing_blocks, .. } => {
            assert_eq!(missing_blocks, N as u64);
        }
        other => panic!("expected Deferred, got {other:?}"),
    }
    assert_eq!(
        gate.fired().map(|d| d.missing_blocks),
        Some(N as u64),
        "the gate carries what it stopped, so the caller can say WHY"
    );
    assert_eq!(
        std::fs::read(dir.join("long.bin")).unwrap(),
        wrecked,
        "NOTHING IS WRITTEN. The veto is answered before the fold, the \
         solve and the patch, so the payload is bit-for-bit what the \
         download left and the next pass repairs it from the same \
         recovery data"
    );

    // AND WITH NO GATE the identical call reaches the shortfall it
    // always did - the negative control, without which the assertions
    // above would pass over a door that refused everything.
    let plain = crate::par2repair::repair_dir_set_with_donors_controlled_as(
        &dir,
        &SET,
        &[],
        Default::default(),
        RepairControl::default(),
    );
    assert!(
        matches!(plain, Ok(RepairStatus::Unrepairable { .. })),
        "an unarmed caller sees this set's real verdict: {plain:?}"
    );
}
