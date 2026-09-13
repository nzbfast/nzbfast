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
use crate::par2repair::control::{PauseGate, ProgressSink, RepairControl, RepairPhase};
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
    /// Raised when `at` of the named phase has been passed, so a test
    /// can cancel FROM INSIDE the phase it wants to interrupt rather
    /// than by racing a timer.
    trip: Option<(RepairPhase, u64, Arc<PauseGate>)>,
}

impl ProgressSink for Rec {
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
    let dir = tmpdir(tag);
    let files: Vec<(String, Vec<u8>)> = (0..4)
        .map(|i| (format!("member{i}.bin"), payload(BS * 40, 7 + i as u64)))
        .collect();
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, &refs)).unwrap();
    // Parity for a third of the set - far more than any test here
    // damages, so a shortfall can never be the reason a repair stops.
    let exps: Vec<u32> = (0..60u32).collect();
    std::fs::write(
        dir.join("set.vol000+60.par2"),
        par2_volume(SET, BS, &refs, &exps),
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
        // From INSIDE the fold, at the first bucket it crosses - a
        // timer would either fire before the fold or after the repair
        // on a box of a different speed.
        trip: Some((RepairPhase::Fold, 1, gate.clone())),
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
        fold.len() >= 2,
        "the cancel was raised from inside the fold, so the fold ran"
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
    // A sink that pauses from INSIDE the fold, at its first bucket.
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
            if phase == RepairPhase::Fold
                && done > 0
                && self.armed.fetch_add(1, Ordering::Relaxed) == 0
            {
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
        trip: Some((RepairPhase::Fold, 1, gate.clone())),
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
