//! What a DAEMON repair is doing, while it does it.
//!
//! The companion of [`crate::unpackprog`] one stage earlier in the
//! tail, and it exists for the identical reason. The disk unpack ladder
//! used to publish one static word for however many minutes it ran,
//! which reads as a hang; so did the repair, and the daemon's own
//! source said so out loud. `serve/mod.rs` capped what a daemon would
//! even START at `MAX_REPAIR_DIM` because "the queue row has read
//! `Repairing, 100%, timeleft 0:00:00` through exactly that kind of
//! stall before", and `par2repair.rs`'s forecast warn ended "and
//! nothing reports progress while it runs".
//!
//! The engine grew the channel on 12 Sep 2026
//! (`nzbkit::par2repair::control`, whose module doc carries the whole
//! design). This is the daemon's end of it: a [`ProgressSink`] that
//! publishes into a value the queue payload reads on every poll, plus
//! the band decision the engine deliberately refuses to make.
//!
//! # Where the CANCEL half lives, and why it is not here
//!
//! On [`crate::streamhub::SideCancel`], which is the one per-owner
//! handle every daemon repair site already receives and the daemon
//! already publishes per nzo_id. A repair gate of its own here would be
//! a SECOND cancel bit for one button - the host presses Cancel, one of
//! them is set, and whether the fold stops depends on which. That is
//! the mistake `parfast_session::runner::Control` was rewritten to
//! remove on the very day the engine's gate landed, and it is not worth
//! re-making one crate over. `SideCancel::repair_control` is where the
//! two halves are put together.
//!
//! # Why the fraction is stored and not recomputed
//!
//! The engine reports four phases in four different UNITS and refuses
//! to weigh them (`par2repair::RepairPhase`), because only a caller
//! knows what its user is waiting on. The queue payload is polled far
//! more often than the sink is called, so the weighing happens once per
//! sink call - at most 256 times a phase - rather than once per poll,
//! and a `fetch_max` makes it monotone across phases without a lock.
//! A bar that went back to 85% because a slabbed solve re-entered its
//! phase would read as a restart.
//!
//! # Cost
//!
//! Nothing in this module is on a hot path and no hook of its own is
//! added to one. The engine's rate limit is what makes that true: four
//! relaxed stores and a `fetch_max` per sink call, and the sink is
//! reached at most `control::STEPS` times per phase however many
//! batches there were (pinned by
//! `a_million_steps_reach_the_sink_at_most_steps_times`). The per-batch
//! cost is the engine's own and was measured when the hooks landed: on
//! a real 1 GiB set with 200 blocks of damage, mirrored A B B A x 4,
//! +0.82% of CPU-seconds against an A/A floor of +0.59% measured on the
//! same box in the same round - inside the floor, with the ranges
//! overlapping almost entirely. The CONTROLLED path has no A/B of its
//! own yet: per site it is one relaxed `fetch_add`, one relaxed load
//! and a compare per fed block and per fold unit, which is a bound
//! rather than a measurement.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// The four phases, as the token the dashboard maps to a sentence.
///
/// Zero is "no repair in flight", which is a state the payload needs a
/// shape for: `hub.activity` says `repairing` for the whole repair
/// SECTION - the recovery-volume side-fetches included - and only part
/// of that section is inside the engine.
const PHASE_NONE: u8 = 0;

/// One job's live repair progress, as both the sink the engine writes
/// to and the value the queue payload reads.
///
/// One type rather than a publisher and a snapshot, because there is
/// nothing to snapshot: every field is an atomic the payload can read
/// at any instant, so the engine advances it in place and nobody has to
/// remember to publish.
#[derive(Default, Debug)]
pub struct RepairProgress {
    /// `PHASE_NONE`, or 1-4 for Verify/Fold/Solve/Write.
    phase: AtomicU8,
    /// The current phase's own `(done, total)`, in ITS units - bytes for
    /// Verify, Fold and Write, fold units or matrix columns for Solve
    /// (see `par2repair::RepairPhase`). Published for a caller that
    /// wants to say more than a percentage, and for the tests.
    done: AtomicU64,
    total: AtomicU64,
    /// The whole repair's progress in per-mille, banded (see [`band`])
    /// and monotone for the life of one [`RepairRun`].
    permille: AtomicU64,
}

/// `(bar offset, bar span)` for a phase.
///
/// THE SAME WEIGHTS `parfast_session::runner::RepairProgress` TOOK, and
/// deliberately so: the engine refuses to weigh its four phases, so
/// each caller decides - and two products of the same repair engine
/// disagreeing about what 60% means is a worse outcome than either
/// choice. The verify half is the first 45% of a repair's bar, the fold
/// the next 40%, the solve 10% and the write the last 5%. That is the
/// shape of an ordinary damaged repair on the measured corpus, and it
/// is a LABELLING choice rather than a prediction: a bar honest about
/// which phase is running and monotone within it beats one that lies
/// smoothly.
fn band(phase: nzbkit::par2repair::RepairPhase) -> (f64, f64) {
    use nzbkit::par2repair::RepairPhase as P;
    match phase {
        P::Verify => (0.0, 0.45),
        P::Fold => (0.45, 0.40),
        P::Solve => (0.85, 0.10),
        P::Write => (0.95, 0.05),
    }
}

fn code(phase: nzbkit::par2repair::RepairPhase) -> u8 {
    use nzbkit::par2repair::RepairPhase as P;
    match phase {
        P::Verify => 1,
        P::Fold => 2,
        P::Solve => 3,
        P::Write => 4,
    }
}

impl RepairProgress {
    /// Which phase is running, as the token the dashboard maps to a
    /// translated sentence, or None when no repair is inside the engine
    /// right now.
    ///
    /// `None` is not "nothing is happening": the recovery-volume
    /// side-fetches run under the same `repairing` activity word and
    /// are not a phase of the engine's repair. The page keeps saying
    /// the bare word for those, which is what it said before any of
    /// this existed.
    pub fn phase(&self) -> Option<&'static str> {
        match self.phase.load(Ordering::Relaxed) {
            1 => Some("verify"),
            2 => Some("fold"),
            3 => Some("solve"),
            4 => Some("write"),
            _ => None,
        }
    }

    /// The current phase's `done`, in that phase's own units.
    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    /// The current phase's `total`, in that phase's own units.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// The whole repair, 0-1000. Monotone for one [`RepairRun`].
    pub fn permille(&self) -> u64 {
        self.permille.load(Ordering::Relaxed)
    }

    /// Arm reporting for one repair call, and disarm it when the guard
    /// drops.
    ///
    /// A job makes SEVERAL engine repair calls - the adoption probe,
    /// the pass after the recovery fetch, and the escalation's second
    /// go - and each is its own bar: the probe's verify pass is not
    /// 45% of the repair that follows it. So the counters go back to
    /// zero here rather than accumulating, and the guard is what says
    /// "no repair is inside the engine" for the stretches in between,
    /// which is most of a slow tail's wall.
    pub fn enter(&self) -> RepairRun<'_> {
        self.clear();
        RepairRun(self)
    }

    /// Put the bar back for the NEXT set of a multi-set pass, without
    /// closing the window.
    ///
    /// [`enter`](Self::enter) is the same clear WITH a guard, and it is
    /// what a caller that owns its own loop uses per set (`get::
    /// latesets` does). The nested extraction ladder cannot: its pass
    /// repairs EVERY present set in the directory and the loop is the
    /// ENGINE's, so the only set boundary it has is the control supplier
    /// `par2repair::repair_present_sets_controlled_as` calls once per
    /// set - a `Fn`, which cannot hold a guard. This is that boundary's
    /// opening half; the directory's single [`RepairRun`] is what closes
    /// the window when the ladder leaves the level.
    ///
    /// Without it the bar would read 100% for every set after the
    /// first: `permille` is monotone by `fetch_max` (a slabbed solve
    /// re-entering its phase must not read as a restart), which is the
    /// right rule inside one repair and the wrong one across two.
    pub fn restart(&self) {
        self.clear();
    }

    fn clear(&self) {
        self.phase.store(PHASE_NONE, Ordering::Relaxed);
        self.done.store(0, Ordering::Relaxed);
        self.total.store(0, Ordering::Relaxed);
        self.permille.store(0, Ordering::Relaxed);
    }
}

/// One engine repair call's reporting window. See
/// [`RepairProgress::enter`].
pub struct RepairRun<'a>(&'a RepairProgress);

impl Drop for RepairRun<'_> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl nzbkit::par2repair::ProgressSink for RepairProgress {
    fn progress(&self, phase: nzbkit::par2repair::RepairPhase, done: u64, total: u64) {
        let (base, span) = band(phase);
        let frac = if total == 0 {
            0.0
        } else {
            (done as f64 / total as f64).clamp(0.0, 1.0)
        };
        // The phase and its pair are stored plainly: they are ABOUT the
        // phase, so a later phase's smaller `done` is correct rather
        // than a step backwards. Only the whole-repair figure has to be
        // monotone, and `fetch_max` is what makes it so without taking
        // a lock the engine has already taken for ordering.
        self.phase.store(code(phase), Ordering::Relaxed);
        self.done.store(done, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        let pm = ((base + span * frac) * 1000.0).round() as u64;
        self.permille.fetch_max(pm.min(1000), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nzbkit::par2repair::{ProgressSink, RepairPhase};

    #[test]
    fn nothing_is_reported_until_a_phase_arrives() {
        let p = RepairProgress::default();
        assert_eq!(
            (p.phase(), p.done(), p.total(), p.permille()),
            (None, 0, 0, 0)
        );
    }

    /// The four phases each land in their own band and the whole-repair
    /// figure climbs through all of them - which is the thing the queue
    /// row could not do and the whole point of this module.
    #[test]
    fn the_four_phases_each_move_their_own_band_of_one_rising_bar() {
        let p = RepairProgress::default();
        let _run = p.enter();
        let mut last = 0;
        for (phase, tok, top) in [
            (RepairPhase::Verify, "verify", 450),
            (RepairPhase::Fold, "fold", 850),
            (RepairPhase::Solve, "solve", 950),
            (RepairPhase::Write, "write", 1000),
        ] {
            p.progress(phase, 0, 100);
            assert_eq!(p.phase(), Some(tok));
            for done in [25u64, 50, 75, 100] {
                p.progress(phase, done, 100);
                assert!(
                    p.permille() >= last,
                    "{tok} at {done}: {} went below {last}",
                    p.permille()
                );
                last = p.permille();
            }
            assert_eq!(p.permille(), top, "{tok} lands on the top of its band");
        }
    }

    /// A slabbed solve re-enters `Solve` from zero. The phase pair goes
    /// back with it - it is about the phase - and the whole-repair bar
    /// must NOT, because a bar that fell from 95% to 85% reads as a
    /// restart.
    #[test]
    fn a_re_entered_phase_does_not_take_the_whole_repair_bar_backwards() {
        let p = RepairProgress::default();
        let _run = p.enter();
        p.progress(RepairPhase::Solve, 50, 50);
        assert_eq!(p.permille(), 950);
        p.progress(RepairPhase::Solve, 0, 50);
        assert_eq!(p.done(), 0, "the phase pair is about the phase");
        assert_eq!(p.permille(), 950, "the whole-repair bar is monotone");
    }

    /// The probe pass and the real pass are separate bars, and the
    /// stretch between two engine calls - the recovery-volume fetch,
    /// which runs under the same `repairing` word - reports no phase at
    /// all rather than the last one it saw.
    #[test]
    fn each_engine_call_is_its_own_bar_and_the_gap_between_them_is_silent() {
        let p = RepairProgress::default();
        {
            let _probe = p.enter();
            p.progress(RepairPhase::Verify, 100, 100);
            assert_eq!(p.permille(), 450);
        }
        assert_eq!(p.phase(), None, "no repair is inside the engine");
        assert_eq!(p.permille(), 0);
        {
            let _real = p.enter();
            p.progress(RepairPhase::Verify, 10, 100);
            assert_eq!(p.phase(), Some("verify"));
            assert_eq!(p.permille(), 45, "not 450 carried over from the probe");
        }
    }

    /// A damaged recovery set in a scratch dir, and the id of the set
    /// in it. Four members over 8 KiB blocks with 25% parity, damaged
    /// one block per member, which is enough fold for the engine to
    /// cross several buckets and free enough to run anywhere.
    fn damaged_set(
        tag: &str,
    ) -> (
        crate::testscratch::ScratchDir,
        [u8; 16],
        Vec<(String, Vec<u8>)>,
    ) {
        let dir = crate::testscratch::ScratchDir::attach(
            &std::env::temp_dir().join(format!("nzbfast-repairprog-{tag}-{}", std::process::id())),
        );
        let files: Vec<(String, Vec<u8>)> = (0..4u8)
            .map(|i| {
                // A deterministic, incompressible-enough payload: the
                // repair reads every byte either way, so what matters
                // is only that two members differ.
                let mut v = vec![0u8; 8_192 * 24];
                let mut x = 0x9E37_79B9u32.wrapping_add(i as u32);
                for b in &mut v {
                    x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    *b = (x >> 24) as u8;
                }
                (format!("member{i}.bin"), v)
            })
            .collect();
        let members: Vec<nzbkit::par2gen::Member> = files
            .iter()
            .map(|(n, d)| {
                std::fs::write(dir.join(n), d).unwrap();
                nzbkit::par2gen::Member {
                    name: n.clone(),
                    path: dir.join(n),
                }
            })
            .collect();
        nzbkit::par2gen::create_into(
            &dir,
            &members,
            "set",
            &nzbkit::par2gen::Par2Spec {
                redundancy_pct: 25,
                block_size: Some(8_192),
            },
        )
        .expect("par2 set written");
        for (n, _) in &files {
            let p = dir.join(n);
            let mut bytes = std::fs::read(&p).unwrap();
            for b in &mut bytes[8_192 * 3..8_192 * 4] {
                *b ^= 0xFF;
            }
            std::fs::write(&p, bytes).unwrap();
        }
        let id = *nzbkit::par2repair::disk_set_ids(&dir)
            .expect("the set is readable")
            .first()
            .expect("one set");
        (dir, id, files)
    }

    fn intact(dir: &std::path::Path, files: &[(String, Vec<u8>)]) -> bool {
        files
            .iter()
            .all(|(n, d)| std::fs::read(dir.join(n)).is_ok_and(|got| got == *d))
    }

    /// THE HEADLINE, end to end from the daemon's own side: the handle
    /// the daemon registers per job, the control it builds from it, the
    /// real engine, a real damaged set - and a queue row that moves
    /// through four phases where it used to read `Repairing, 100%,
    /// timeleft 0:00:00` for the whole fold.
    ///
    /// It goes through `SideCancel` rather than building a
    /// `RepairControl` by hand on purpose. That handle is the one wire
    /// between the delete path and the fold, and a test that assembled
    /// the control itself would pass with the daemon wired to nothing.
    #[test]
    fn a_daemon_repair_moves_a_bar_through_four_phases() {
        let (dir, id, files) = damaged_set("phases");
        let sc = crate::streamhub::SideCancel::new();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, u64)>::new()));
        // Sampled from the sink's own thread through a second sink is
        // not available - the control carries one. So the phases are
        // read the way the QUEUE PAYLOAD reads them, off the published
        // value, from a watcher thread: that is the surface this whole
        // change exists to fill, so it is the surface asserted.
        let watch = {
            let seen = seen.clone();
            let prog = sc.repair_progress().clone();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop2 = stop.clone();
            let h = std::thread::spawn(move || {
                while !stop2.load(Ordering::Relaxed) {
                    if let Some(ph) = prog.phase() {
                        let mut g = seen.lock().unwrap();
                        let pm = prog.permille();
                        if g.last().map(|l| (l.0.as_str(), l.1)) != Some((ph, pm)) {
                            g.push((ph.to_string(), pm));
                        }
                    }
                    std::thread::yield_now();
                }
            });
            (stop, h)
        };
        // Read INSIDE the run's scope: `permille` is a high-water mark
        // for the life of the `RepairRun`, and the guard clears it.
        let (status, landed) = {
            let _run = sc.repair_progress().enter();
            let st = nzbkit::par2repair::repair_dir_set_with_donors_controlled_as(
                &dir,
                &id,
                &[],
                nzbkit::par2repair::RetentionCaller::default(),
                sc.repair_control(),
            )
            .expect("the repair runs");
            (st, sc.repair_progress().permille())
        };
        watch.0.store(true, Ordering::Relaxed);
        watch.1.join().expect("watcher");
        assert!(
            matches!(status, nzbkit::par2repair::RepairStatus::Repaired(_)),
            "{status:?}"
        );
        assert!(intact(&dir, &files), "the repair is byte-exact");

        // THE BAR LANDED ON FULL, which only the Write band's own
        // `finish` can reach (see [`band`]) - so the repair went
        // through all four phases and the last of them completed.
        // Asserted from the high-water mark rather than from the
        // poller, because WHICH phases a poller happens to catch is a
        // property of the poller: the write half of a four-block repair
        // is microseconds, and the dashboard polls once a second. That
        // the four phases each report and each land is the engine door's
        // own test (`the_controlled_entry_carries_progress_and_a_cancel_
        // of_its_own`), and that each lands at the top of its band is
        // `the_four_phases_each_move_their_own_band_of_one_rising_bar`
        // above. This test is the third link: the real handle carries
        // them.
        assert_eq!(
            landed, 1000,
            "the bar did not land on full - a fraction that never reaches one reads as \
             a wedge, which is the complaint this whole change answers"
        );

        let seen = seen.lock().unwrap().clone();
        // IT MOVED, and it never went backwards, and the phase it spent
        // its time in is the FOLD - the dominant phase of a real repair
        // and the one the queue row could not see at all.
        let order = ["verify", "fold", "solve", "write"];
        let mut last = 0u64;
        let mut at = 0usize;
        for (ph, pm) in &seen {
            assert!(
                *pm >= last,
                "the bar fell: {last} -> {pm} in {ph}, {seen:?}"
            );
            last = *pm;
            let Some(i) = order.iter().position(|o| o == ph) else {
                panic!("unknown phase {ph} in {seen:?}");
            };
            assert!(
                i >= at,
                "phase {ph} came after {} in {seen:?} - the four only ever advance",
                order[at]
            );
            at = i;
        }
        assert!(
            seen.iter().any(|(ph, _)| ph == "fold"),
            "the fold was never visible: {seen:?}"
        );
        assert!(
            seen.len() >= 4,
            "{} distinct readings is not a bar that moves: {seen:?}",
            seen.len()
        );
        // And it is CLEARED when the engine leaves, so the recovery
        // fetches between two passes do not keep showing a stale phase.
        assert_eq!(sc.repair_progress().phase(), None);
        assert_eq!(sc.repair_progress().permille(), 0);
    }

    /// THE OTHER HEADLINE: the Cancel the daemon's delete path presses
    /// ends a running repair.
    ///
    /// `SideCancel::cancel` is what `postproc::cancel_tail_fetches`
    /// calls, so this is the real button on the real handle. Before
    /// 12 Sep 2026 it stopped the recovery fetches and nothing else -
    /// that function's own doc said "A repair already patching bytes
    /// runs to its end and parks".
    ///
    /// WHAT THIS DOES AND DOES NOT PROVE. It presses the button once
    /// the published phase says `fold`, which is the earliest moment a
    /// watcher on the daemon's own side can know the engine is folding.
    /// On a set this small the fold is microseconds, so the press may
    /// land at the next driver boundary rather than block-by-block
    /// inside the fold - and that is fine here, because the
    /// DISCRIMINATING test for the in-fold check is the engine's
    /// (`control_tests::a_cancel_raised_mid_fold_ends_the_repair_
    /// before_it_writes`, which trips from inside the sink and asserts
    /// the fold's counter never reached its total). What this one is
    /// for is the wire: that the daemon's handle carries the cancel at
    /// all, that the verdict is `Cancelled` and not a broken set, and
    /// that the directory is re-runnable afterwards.
    #[test]
    fn the_delete_paths_cancel_ends_a_running_repair() {
        let (dir, id, files) = damaged_set("cancel");
        let before: Vec<Vec<u8>> = files
            .iter()
            .map(|(n, _)| std::fs::read(dir.join(n)).unwrap())
            .collect();
        let sc = std::sync::Arc::new(crate::streamhub::SideCancel::new());
        // Pressed from a watcher the moment the FOLD is running, which
        // is where a timer would be a race on a box of another speed.
        let pressed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let h = {
            let sc = sc.clone();
            let pressed = pressed.clone();
            std::thread::spawn(move || {
                // BOUNDED, so a poller that never sees the fold ends
                // the test with a readable assertion rather than
                // hanging a shard - the wedge-that-exits-0 shape
                // CLAUDE.md warns about. The repair on this set is
                // milliseconds; the bound is three orders of magnitude
                // over it.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while std::time::Instant::now() < deadline {
                    if sc.repair_progress().phase() == Some("fold") {
                        sc.cancel();
                        pressed.store(true, Ordering::Relaxed);
                        return;
                    }
                    std::thread::yield_now();
                }
            })
        };
        let err = {
            let _run = sc.repair_progress().enter();
            nzbkit::par2repair::repair_dir_set_with_donors_controlled_as(
                &dir,
                &id,
                &[],
                nzbkit::par2repair::RetentionCaller::default(),
                sc.repair_control(),
            )
            .expect_err("a cancelled repair is not a verdict")
        };
        h.join().expect("watcher");
        assert!(pressed.load(Ordering::Relaxed), "the cancel never fired");
        assert!(
            matches!(err, nzbkit::par2repair::RepairError::Cancelled),
            "a user's Cancel must not be reported as a broken set: {err:?}"
        );
        assert!(sc.repair_cancelled(), "the gate stayed up");
        // Nothing was renamed in and no member is worse than it was -
        // the contract on `RepairError::Cancelled`. Cancelled in the
        // fold, nothing is written at all.
        for ((name, _), was) in files.iter().zip(&before) {
            assert_eq!(&std::fs::read(dir.join(name)).unwrap(), was, "{name}");
        }
        // AND IT IS RE-RUNNABLE, which is the whole of what a cancel
        // owes a user who changes their mind - through a FRESH handle,
        // because the cancelled one is sticky by design.
        let sc2 = crate::streamhub::SideCancel::new();
        let again = nzbkit::par2repair::repair_dir_set_with_donors_controlled_as(
            &dir,
            &id,
            &[],
            nzbkit::par2repair::RetentionCaller::default(),
            sc2.repair_control(),
        )
        .expect("the re-run repairs");
        assert!(
            matches!(again, nzbkit::par2repair::RepairStatus::Repaired(_)),
            "{again:?}"
        );
        assert!(intact(&dir, &files), "the re-run is byte-exact");
    }

    /// A cancelled handle refuses a LATER repair too, without running
    /// it: the latch is sticky, which is what stops a deleted job's
    /// second set from being folded after the first was called off.
    #[test]
    fn a_cancelled_handle_refuses_the_next_set_as_well() {
        let (dir, id, _files) = damaged_set("sticky");
        let sc = crate::streamhub::SideCancel::new();
        sc.cancel();
        let err = nzbkit::par2repair::repair_dir_set_with_donors_controlled_as(
            &dir,
            &id,
            &[],
            nzbkit::par2repair::RetentionCaller::default(),
            sc.repair_control(),
        )
        .expect_err("a cancelled handle does not repair");
        assert!(
            matches!(err, nzbkit::par2repair::RepairError::Cancelled),
            "{err:?}"
        );
    }

    /// The control the daemon hands over is ATTENDED, which is what
    /// lifts the unattended unstructured ceiling for it
    /// (`reconstruct::check_repair_dim_dense`). A half-wired handle
    /// would still repair and would silently stay capped, so this is
    /// pinned rather than left to the engine's own test of the
    /// predicate.
    #[test]
    fn the_handle_the_daemon_registers_builds_an_attended_control() {
        let sc = crate::streamhub::SideCancel::new();
        assert!(sc.repair_control().is_attended());
        assert!(sc.repair_control().is_active());
    }

    /// A phase whose total was an estimate must not report over 100%.
    #[test]
    fn an_overrunning_phase_clamps_at_its_band() {
        let p = RepairProgress::default();
        let _run = p.enter();
        p.progress(RepairPhase::Write, 500, 100);
        assert_eq!(p.permille(), 1000);
        p.progress(RepairPhase::Verify, 0, 0);
        assert_eq!(p.permille(), 1000, "and a zero total is not a division");
    }
}
