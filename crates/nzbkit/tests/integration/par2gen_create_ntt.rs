//! The CREATE-side NTT, actually running.
//!
//! ## Why this file exists
//!
//! Until 8 Sep 2026 no test anywhere in this repository executed the
//! creator's transform. Not "no test asserted on it" - no test REACHED
//! it. Measured rather than surveyed: `ntt_range::plan` is the one door
//! every create-side plan construction goes through, and a build with a
//! `panic!` as its first statement was run over the whole per-push
//! sweep (8,011 tests, 29 binaries), the heavy `par2gen_large_set`
//! suite, the e2e suite (451 tests) and the daemon suite (195). Not one
//! test hit it. So `ntt_range::plan`, the mapped transform branch in
//! `par2gen::recovery_slices`, the copied-window loop beside it, the
//! whole of `crates/nzbkit-base/src/par2gen/stripe_first.rs` and the
//! high-redundancy subfloor clause were production code no automated
//! run executed, on any box, in any suite, per push or nightly.
//!
//! It is a sharper case than the default-off features that class
//! usually describes, because the SHIPPED DEFAULTS do not reach it
//! either: `default_block_size` targets 2,000 input slices by
//! construction and the default redundancy is 5%, so a default create
//! asks for about 100 recovery rows at every payload size, under the
//! row gate at both ends. The create-side transform serves
//! raised-redundancy or hand-set-block-size creates only - `parfast`,
//! `postfast` profiles, a user who sets one. Measured 8 Sep 2026 at
//! 1.5 GB and at 16 GiB, both reporting zero plan builds through the
//! counter [`ntt_range::cold_builds_for_tests`] reads.
//!
//! ## What is asserted
//!
//! The transform has no verify-and-retry behind it the way a repair
//! does - a wrong recovery set is written and shipped - so the only
//! assertion worth making is that the transform and the fold write the
//! SAME BYTES for the same set. The engine already believes that: both
//! transform branches fold one probe row and compare, and recompute
//! everything by the fold when it disagrees. These tests hold the whole
//! set to it, across the four shapes that dispatch differently, and
//! then repair a damaged member from the transform's own slices, which
//! is the only thing that proves the exponent bookkeeping.
//!
//! ## Why the fixtures are small, and why that is not a lowered gate
//!
//! The gates are on the INPUT-SLICE count and the RECOVERY-ROW count -
//! never on the payload size - so a fixture at a 128-byte block crosses
//! them honestly for a quarter of a megabyte. Nothing here sets
//! `NZBFAST_CREATE_NTT_MIN_ROWS` or `NZBFAST_CREATE_NTT_MIN_PRESENT`:
//! the shapes come from [`ntt_range::floor_shape_for_tests`] and
//! [`ntt_range::subfloor_shape_for_tests`], which are the shipped gates
//! themselves, so these run at their measured per-arch value (1,024
//! inputs and 192 rows on aarch64, 2,048 and 256 or 320 on x86) and
//! re-size themselves if a gate is ever re-derived.
//!
//! What a 128-byte block does NOT reach is the stripe geometry: one
//! stripe, one worker, where a real block gives 512-word stripes over
//! every core. That half is
//! `crates/nzbkit-base/tests/par2gen_large_set.rs`'s
//! `the_transform_writes_the_fold_s_bytes_at_a_real_block_size`, which
//! is heavy-gated and runs nightly because its fixture is thirty times
//! the payload for the same slice count. The split is deliberate: the
//! cheap shapes gate every push, the honest one gates the night.
//!
//! Measured 8 Sep 2026 on the dev Mac (32 cores, arm64), DEBUG build:
//! the four tests here 0.5 s together, the nightly one 0.7 s. Both are
//! parallel folds, so a 4 vCPU runner pays several times that - which is
//! the ratio the split is drawn on, not an absolute.
//!
//! ## Process-global state
//!
//! The arms are pinned through `ntt_range`'s test doors rather than
//! through `NZBFAST_NTT` / `NZBFAST_PAR2GEN_MAP`, because
//! `std::env::set_var` is sound only in a binary that owns its process
//! and this is a module of the shared `integration` target - and
//! because the mapping knob is latched in a `OnceLock`, so the first
//! create in the process would decide that arm for every test after it.
//! The doors are atomics; [`crate::par2gen_arms::Arms`] serialises the
//! tests that move them and lifts every pin on the way out. Under nextest
//! each test is its own process and the lock is free; under `cargo test`
//! and CI's `unit-one-process` job this whole binary is ONE process, which
//! is the run it is for - and the serializer lives one module over rather
//! than here BECAUSE that is the run it is for: `par2gen_cancel` runs
//! creates over these same globals, and a lock private to this file
//! ordered this file against itself while that module raced it. See that
//! module's header for what it cost.

use std::path::{Path, PathBuf};

use crate::par2gen_arms::Arms;
use nzbkit::par2gen::{
    CreatePlan, Member, VolumePlan, accum_budget_bytes, create_into_exact, ntt_range,
    pin_accum_budget_for_tests,
};

/// Small enough that a gate-crossing fixture is a quarter of a megabyte
/// and cheap enough to run on every push, and a multiple of 4 as the
/// spec requires. See the module header for what it does not reach.
const BS: u64 = 128;

/// Deterministic, non-periodic payload. The period matters: a fixture
/// whose full blocks are identical to each other defeats a repairer's
/// sliding scan, which is the trap `par2gen_interop::payload` next door
/// records in full.
fn payload(len: usize, seed: u8) -> Vec<u8> {
    let mut x = (seed as u64) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "nzbfast-create-ntt-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A payload of exactly `slices` input slices at [`BS`], as two members:
/// one long member of full blocks and a short one whose only block is a
/// PARTIAL tail, because the tail is what the mapped path copies into
/// its pad arena rather than reading out of the mapping.
fn fixture(dir: &Path, slices: usize) -> Vec<Member> {
    fixture_at(dir, slices, BS)
}

/// One arm: its own directory holding its own copy of the payload (a
/// PAR2 set names its members relative to its own directory, so an arm
/// that is going to be repaired has to sit beside them), the set built
/// into it, and how many transform plans that create constructed.
///
/// `rows` is an EXACT recovery count rather than a percentage: the gates
/// are stated in rows, and a percentage would round to a number beside
/// the one the fixture is sized for.
fn arm(
    t: &Tmp,
    tag: &str,
    slices: usize,
    rows: usize,
    plan: CreatePlan,
) -> (Vec<(String, Vec<u8>)>, u64) {
    arm_at(t, tag, slices, rows, plan, BS)
}

/// Damage a member of `tag`'s arm well past one block and repair it from
/// that arm's own recovery slices. The transform computed those slices,
/// so this is what proves their exponents are the ones the repairer
/// expects - a set that is merely self-consistent would verify and fail
/// here.
fn repairs_real_damage(t: &Tmp, tag: &str) {
    let dir = t.0.join(tag);
    let victim = dir.join("payload.bin");
    let good = std::fs::read(&victim).unwrap();
    let mut broken = good.clone();
    let n = broken.len();
    broken[1_000..9_000].fill(0);
    broken[n - 3_000..].fill(0xff);
    std::fs::write(&victim, &broken).unwrap();
    let status = nzbkit::par2repair::repair_dir(&dir).expect("repair runs");
    assert!(
        matches!(status, nzbkit::par2repair::RepairStatus::Repaired(_)),
        "{status:?}"
    );
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        good,
        "victim not byte-exact"
    );
}

/// `cold` builds over an arm that was supposed to take the transform.
/// A zero here is the whole finding this file was written about, so it
/// says what to do about it rather than just failing.
fn assert_transformed(cold: u64, what: &str, slices: usize, rows: usize) {
    assert!(
        cold >= 1,
        "the {what} arm built NO transform plan at {slices} inputs x {rows} rows - the shipped \
         gates refused a fixture sized from those same gates. Re-size the fixture against \
         ntt_range's admission (or find out why it now refuses); do not delete the assertion, \
         which is the only thing standing between this file and covering nothing at all"
    );
}

#[test]
fn the_mapped_transform_writes_the_fold_s_bytes_and_the_set_repairs() {
    let _arms = Arms::take();
    let (slices, rows) = ntt_range::floor_shape_for_tests(BS as usize);
    let t = Tmp::new("mapped");

    ntt_range::pin_transform_off_for_tests(true);
    let (fold, cold_fold) = arm(&t, "fold", slices, rows, CreatePlan::ENGINE);
    assert_eq!(cold_fold, 0, "the fold arm must build no transform plan");

    ntt_range::pin_transform_off_for_tests(false);
    let (ntt, cold_ntt) = arm(&t, "ntt", slices, rows, CreatePlan::ENGINE);
    assert_transformed(cold_ntt, "mapped", slices, rows);
    assert_eq!(
        cold_ntt, 1,
        "the mapped path maps the whole corpus, so one create builds ONE plan"
    );

    assert_eq!(
        fold, ntt,
        "the transform and the fold must write the same recovery set"
    );
    repairs_real_damage(&t, "ntt");
}

#[test]
fn the_copied_window_fallback_writes_the_fold_s_bytes() {
    // The branch a box without usable mappings takes. It is a second
    // implementation of the same transform - its own window loop, its
    // own XOR accumulation, its own probe - and only the mapped one runs
    // by default, so nothing else here would ever compile-and-run it.
    let _arms = Arms::take();
    let (slices, rows) = ntt_range::floor_shape_for_tests(BS as usize);
    let t = Tmp::new("copied");

    ntt_range::pin_transform_off_for_tests(true);
    let (fold, cold_fold) = arm(&t, "fold", slices, rows, CreatePlan::ENGINE);
    assert_eq!(cold_fold, 0, "the fold arm must build no transform plan");

    ntt_range::pin_transform_off_for_tests(false);
    ntt_range::pin_map_off_for_tests(true);
    let sweeps = ntt_range::band_sweeps_for_tests();
    let (ntt, cold_ntt) = arm(&t, "ntt", slices, rows, CreatePlan::ENGINE);
    assert_transformed(cold_ntt, "copied-window", slices, rows);
    // One batch whose corpus fits one window stays on the copied windows:
    // the band route would be one plan either way. Were this ever to
    // sweep bands, the window loop would be covered by nothing.
    assert_eq!(
        ntt_range::band_sweeps_for_tests() - sweeps,
        0,
        "the copied-window fixture took the band route, so this test no longer reaches the \
         window loop - give it a shape the band route refuses, do not delete the assertion"
    );

    assert_eq!(
        fold, ntt,
        "the copied-window transform and the fold must write the same recovery set"
    );
}

#[test]
fn the_high_redundancy_subfloor_clause_runs_a_create_through_the_transform() {
    // Below the input floor the transform is still the cheaper arm when
    // the row count is high enough, which is what the subfloor clause
    // admits. `ntt_range::subfloor_tests` covers its arithmetic; nothing
    // ran a create through it.
    let _arms = Arms::take();
    let (floor_slices, _) = ntt_range::floor_shape_for_tests(BS as usize);
    let (slices, rows) = ntt_range::subfloor_shape_for_tests();
    assert!(
        slices < floor_slices,
        "the subfloor clause must sit below the input floor, or this test is the floor test again"
    );
    let t = Tmp::new("subfloor");

    ntt_range::pin_transform_off_for_tests(true);
    let (fold, cold_fold) = arm(&t, "fold", slices, rows, CreatePlan::ENGINE);
    assert_eq!(cold_fold, 0, "the fold arm must build no transform plan");

    ntt_range::pin_transform_off_for_tests(false);
    let (ntt, cold_ntt) = arm(&t, "ntt", slices, rows, CreatePlan::ENGINE);
    assert_transformed(cold_ntt, "subfloor", slices, rows);

    assert_eq!(
        fold, ntt,
        "the subfloor transform and the fold must write the same recovery set"
    );
    repairs_real_damage(&t, "ntt");
}

#[test]
fn the_stripe_first_path_plans_every_row_once_across_several_batches() {
    // `stripe_first` is the one-pass writer for a create the accumulator
    // budget would otherwise split into batches: it plans ALL the rows
    // at once and writes each row's chunk straight into its packet.
    //
    // The budget is pinned so the batch loop has to group, and the
    // volume split is `Even(8)` so the grouping is arithmetic rather
    // than a doubling sequence: eight volumes of `rows / 8`, a budget of
    // `rows / 4` slices, so two volumes per batch and four batches.
    //
    // That shape is also what makes `cold == 1` a PROOF that stripe-first
    // ran, rather than a coincidence: every individual batch is
    // `rows / 4` rows, far under the row gate, so the batched path would
    // build no transform plan at all in any of its four passes. One plan
    // over the whole set can only have come from `stripe_first::run`.
    let _arms = Arms::take();
    let (slices, rows) = ntt_range::floor_shape_for_tests(BS as usize);
    let plan = CreatePlan {
        volumes: VolumePlan::Even(8),
        ..CreatePlan::ENGINE
    };
    let per_batch = rows / 4;
    pin_accum_budget_for_tests(per_batch as u64 * BS);
    assert_eq!(
        (accum_budget_bytes() / BS).max(1) as usize,
        per_batch,
        "the pin must land where the batch arithmetic expects it"
    );
    assert!(
        rows / 8 <= per_batch && per_batch < rows,
        "{rows} rows over eight volumes must group two-per-batch under a {per_batch}-slice \
         budget - re-size the fixture, do not delete the assertion"
    );
    let t = Tmp::new("stripefirst");

    ntt_range::pin_transform_off_for_tests(true);
    let (fold, cold_fold) = arm(&t, "fold", slices, rows, plan);
    assert_eq!(cold_fold, 0, "the fold arm must build no transform plan");

    ntt_range::pin_transform_off_for_tests(false);
    let (ntt, cold_ntt) = arm(&t, "ntt", slices, rows, plan);
    assert_eq!(
        cold_ntt, 1,
        "a batched create reaching the transform builds ONE plan over all {rows} rows only on \
         the stripe-first path - {cold_ntt} says the batch loop ran instead"
    );

    assert_eq!(
        fold, ntt,
        "the stripe-first writer must lay its volumes out exactly as the batched writer does"
    );
    repairs_real_damage(&t, "ntt");
}

/// A Pause pressed while the STRIPE-FIRST arm is transforming stops it
/// there too.
///
/// # Why this arm needs its own test
///
/// `stripe_first` did not produce the create that found the pause
/// defect - it is refused on `batches < 2` and that create had one
/// batch - but it had the same hole, and a fix that left the two arms
/// answering a Pause differently would be worse than either answer on
/// its own. It is also the arm where the park is least obvious: the
/// driver parks while every worker is blocked on a `Barrier`, which is
/// a shape worth pinning rather than reasoning about, because the
/// failure if it is wrong is a wedge and not a wrong answer.
///
/// The fixture is `the_stripe_first_path_plans_every_row_once_across_
/// several_batches`'s, for its reasons - see that test's header for why
/// the budget pin and `Even(8)` are what make this arm run at all.
#[test]
fn a_pause_parks_the_stripe_first_arm_and_a_resume_finishes_it() {
    use nzbkit::par2gen::control::{CreateControl, CreatePhase};
    use nzbkit::par2gen::create_into_exact_controlled;
    use nzbkit::par2repair::{PauseGate, ProgressSink};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    let _arms = Arms::take();
    let (slices, rows) = ntt_range::floor_shape_for_tests(BS as usize);
    let plan = CreatePlan {
        volumes: VolumePlan::Even(8),
        ..CreatePlan::ENGINE
    };
    let per_batch = rows / 4;
    pin_accum_budget_for_tests(per_batch as u64 * BS);
    let t = Tmp::new("stripefirst-pause");

    // The reference arm, unwatched and timed: its bytes are what the
    // resumed create must match, and its wall is what the "did not
    // finish" window below is scaled from.
    let t_plain = std::time::Instant::now();
    let (reference, cold) = arm(&t, "plain", slices, rows, plan);
    let unpaused = t_plain.elapsed();
    assert_eq!(
        cold, 1,
        "the reference arm did not take stripe-first ({cold} plans), so this test would pause \
         a different arm - re-size the fixture, do not delete the assertion"
    );

    struct PauseOnFold {
        gate: Arc<PauseGate>,
        armed: AtomicU64,
        tx: std::sync::mpsc::Sender<()>,
    }
    impl ProgressSink for PauseOnFold {
        fn progress(&self, phase: CreatePhase, _done: u64, _total: u64) {
            if phase == CreatePhase::Fold && self.armed.fetch_add(1, Ordering::SeqCst) == 0 {
                self.gate.set_paused(true);
                let _ = self.tx.send(());
            }
        }
    }

    // `stripe_first::run` sizes its fold phase AFTER its workers are
    // spawned and blocked on the start barrier and BEFORE the first
    // chunk, so a pause raised from that report is answered at the
    // chunk boundary and nowhere else.
    let dir = t.0.join("paused");
    std::fs::create_dir_all(&dir).unwrap();
    let members = fixture(&dir, slices);
    let gate = PauseGate::new();
    let (tx, paused_rx) = std::sync::mpsc::channel();
    let sink: Arc<dyn ProgressSink> = Arc::new(PauseOnFold {
        gate: gate.clone(),
        armed: AtomicU64::new(0),
        tx,
    });
    let control = CreateControl::new(Some(sink), Some(gate.clone()));
    let run_dir = dir.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let r = create_into_exact_controlled(
            &run_dir,
            &members,
            "set",
            Some(BS),
            rows,
            plan,
            None,
            &control,
        );
        let _ = done_tx.send(r);
    });

    paused_rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the create never reported a fold, so nothing was paused");
    let budget = (unpaused * 20).max(std::time::Duration::from_millis(500));
    assert!(
        done_rx.recv_timeout(budget).is_err(),
        "a PAUSED stripe-first create ran to completion in {budget:?} \
         (an unpaused one takes {unpaused:?})"
    );

    gate.set_paused(false);
    let names = done_rx
        .recv_timeout(std::time::Duration::from_secs(120))
        .expect(
            "the resumed create never finished - the driver parked while its workers were \
                 on the start barrier, and one of the two did not come back",
        )
        .expect("the resumed create failed");
    worker.join().expect("the create thread panicked");
    let resumed: Vec<(String, Vec<u8>)> = names
        .iter()
        .map(|n| (n.clone(), std::fs::read(dir.join(n)).unwrap()))
        .collect();
    let mut resumed = resumed;
    resumed.sort();
    assert_eq!(
        resumed, reference,
        "a paused-and-resumed stripe-first create wrote a different set"
    );
}

/// The block size the band tests run at. 550 words is two stripes at the
/// 512-word stripe a sub-MiB block gets on every arch, the second one
/// partial, and [`fixture_at`]'s tail member (half a block, 550 bytes)
/// ends inside the FIRST band - so one band read pads that slice
/// mid-band and the next reads nothing of it at all. At [`BS`] there is
/// one stripe and a band is the whole block, which would prove nothing
/// about bands.
const BAND_BS: u64 = 1100;

/// [`fixture`] at a block size of the caller's.
fn fixture_at(dir: &Path, slices: usize, bs: u64) -> Vec<Member> {
    let bs = bs as usize;
    [
        ("payload.bin", payload((slices - 1) * bs, 7)),
        ("tail.bin", payload(bs / 2, 11)),
    ]
    .into_iter()
    .map(|(name, bytes)| {
        let path = dir.join(name);
        std::fs::write(&path, &bytes).unwrap();
        Member {
            name: name.to_string(),
            path,
        }
    })
    .collect()
}

/// [`arm`] at a block size of the caller's.
fn arm_at(
    t: &Tmp,
    tag: &str,
    slices: usize,
    rows: usize,
    plan: CreatePlan,
    bs: u64,
) -> (Vec<(String, Vec<u8>)>, u64) {
    let dir = t.0.join(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let members = fixture_at(&dir, slices, bs);
    let before = ntt_range::cold_builds_for_tests();
    let names = create_into_exact(&dir, &members, "set", Some(bs), rows, plan).unwrap();
    let cold = ntt_range::cold_builds_for_tests() - before;
    assert!(names.len() > 2, "expected an index and volumes: {names:?}");
    // The NAMES travel with the bytes: a volume split that came out
    // differently would otherwise compare equal file for file.
    let blobs = names
        .iter()
        .map(|n| (n.clone(), std::fs::read(dir.join(n)).unwrap()))
        .collect();
    (blobs, cold)
}

#[test]
fn the_band_pass_over_copies_writes_the_fold_s_bytes_in_one_batch() {
    // The route an over-RAM create takes (TODO 345 C): members read
    // through copies because a mapping would not stay resident
    // (`par2gen::mapped_payload_fits_memory`), a corpus bigger than one of
    // the copied transform's windows, and so ONE plan over every source
    // with the sources read a band of stripes at a time. Map-off stands in
    // for the fit gate, which reads the box's available memory and cannot
    // be set from here; the band pin stands in for a corpus over the
    // window, and holds a band to one stripe so there are two of them.
    let _arms = Arms::take();
    let (slices, rows) = ntt_range::floor_shape_for_tests(BAND_BS as usize);
    let t = Tmp::new("bands-one");

    ntt_range::pin_transform_off_for_tests(true);
    let (fold, cold_fold) = arm_at(&t, "fold", slices, rows, CreatePlan::ENGINE, BAND_BS);
    assert_eq!(cold_fold, 0, "the fold arm must build no transform plan");

    ntt_range::pin_transform_off_for_tests(false);
    ntt_range::pin_map_off_for_tests(true);
    ntt_range::pin_band_corpus_for_tests(slices * 1024);
    let before = ntt_range::band_sweeps_for_tests();
    let (bands, cold) = arm_at(&t, "bands", slices, rows, CreatePlan::ENGINE, BAND_BS);
    let swept = ntt_range::band_sweeps_for_tests() - before;
    assert_transformed(cold, "band", slices, rows);
    assert_eq!(
        swept, 2,
        "a one-stripe band over {BAND_BS}-byte blocks is two sweeps; {swept} says the copied \
         windows ran instead, or the stripe width moved - re-size BAND_BS, do not delete the \
         assertion"
    );
    assert_eq!(cold, 1, "the band route builds ONE plan over every source");

    assert_eq!(
        fold, bands,
        "the band pass and the fold must write the same recovery set"
    );
    repairs_real_damage(&t, "bands");
}

#[test]
fn the_band_pass_over_copies_plans_every_row_once_across_several_batches() {
    // The 15% shape of TODO 345: a batched create over copies ran the
    // copied windows once PER BATCH. The fixture and budget pin are
    // `the_stripe_first_path_plans_every_row_once_across_several_batches`'s,
    // for its reasons, and `cold == 1` is a proof for the same one: every
    // batch alone is under the row gate. The pinned budget also holds a
    // chunk to one stripe (a stripe of every row is more than the budget),
    // so the two stripes are two sweeps.
    let _arms = Arms::take();
    let (slices, rows) = ntt_range::floor_shape_for_tests(BAND_BS as usize);
    let plan = CreatePlan {
        volumes: VolumePlan::Even(8),
        ..CreatePlan::ENGINE
    };
    let per_batch = rows / 4;
    pin_accum_budget_for_tests(per_batch as u64 * BAND_BS);
    let t = Tmp::new("bands-batched");

    ntt_range::pin_transform_off_for_tests(true);
    let (fold, cold_fold) = arm_at(&t, "fold", slices, rows, plan, BAND_BS);
    assert_eq!(cold_fold, 0, "the fold arm must build no transform plan");

    ntt_range::pin_transform_off_for_tests(false);
    ntt_range::pin_map_off_for_tests(true);
    let before = ntt_range::band_sweeps_for_tests();
    let (bands, cold) = arm_at(&t, "bands", slices, rows, plan, BAND_BS);
    let swept = ntt_range::band_sweeps_for_tests() - before;
    assert_eq!(
        cold, 1,
        "a batched create over copies builds ONE plan over all {rows} rows only on the band \
         route - {cold} says the batch loop ran instead"
    );
    assert_eq!(
        swept, 2,
        "two stripes under a one-stripe chunk are two sweeps; {swept} says otherwise"
    );

    assert_eq!(
        fold, bands,
        "the band pass must lay its volumes out exactly as the batched writer does"
    );
    repairs_real_damage(&t, "bands");
}

/// A PANIC in a stripe-first transform worker crashes the create; it does
/// not hang it.
///
/// The workers meet the driver at two `Barrier`s per chunk, and a worker
/// that unwound out of the transform left the barrier one party short: the
/// driver waited on the end gate forever and `std::thread::scope` then
/// waited on the driver, so a bug that should have been a crash was a
/// wedged job with its bar frozen (parfast sweep, 9 Nov 2026). The worker
/// now catches its panic, still reaches the gate, and the driver re-raises
/// it once every worker has been released.
///
/// And the run's files go with it: a panic never reaches the trail's
/// `settle`, so until the unwind guard the staged index and every volume -
/// still carrying the all-zero placeholder critical block, under ordinary
/// `<base>.vol*.par2` names a verify's sibling scan picks up - were left.
///
/// The panic is planted through `ntt_range`'s test door, keyed to this
/// create's own directory so no other test's create can see it; the shape
/// is the stripe-first fixture above, for that test's reasons.
#[test]
fn a_panicking_stripe_first_worker_crashes_the_create_rather_than_hanging_it() {
    let _arms = Arms::take();
    struct Unpin;
    impl Drop for Unpin {
        fn drop(&mut self) {
            ntt_range::pin_stripe_worker_panic_for_tests(None);
        }
    }
    let _unpin = Unpin;
    let (slices, rows) = ntt_range::floor_shape_for_tests(BS as usize);
    let plan = CreatePlan {
        volumes: VolumePlan::Even(8),
        ..CreatePlan::ENGINE
    };
    pin_accum_budget_for_tests((rows / 4) as u64 * BS);
    let t = Tmp::new("stripefirst-panic");
    // The control: the same shape really takes stripe-first, so a panic
    // below is that arm's and not some other route's.
    let (_, cold) = arm(&t, "plain", slices, rows, plan);
    assert_eq!(
        cold, 1,
        "the fixture did not take stripe-first ({cold} plans) - re-size it, do not delete the \
         assertion"
    );

    let dir = t.0.join("panics");
    std::fs::create_dir_all(&dir).unwrap();
    let members = fixture(&dir, slices);
    let before: Vec<String> = names_in(&dir);
    ntt_range::pin_stripe_worker_panic_for_tests(Some(&dir));
    let (tx, rx) = std::sync::mpsc::channel();
    let run_dir = dir.clone();
    let worker = std::thread::spawn(move || {
        let dir = run_dir;
        let r = std::panic::catch_unwind(|| {
            create_into_exact(&dir, &members, "set", Some(BS), rows, plan)
        });
        let _ = tx.send(r.is_err());
    });
    let panicked = rx
        .recv_timeout(std::time::Duration::from_secs(120))
        .expect("a create whose transform worker panicked never returned - it is wedged");
    assert!(panicked, "the worker's panic was swallowed into a result");
    worker.join().expect("the create thread");
    assert_eq!(
        names_in(&dir),
        before,
        "a create that panicked left its staged index or placeholder volumes behind"
    );
}

/// Every name in `dir`, hidden ones included, sorted.
fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Every SET file in `dir` (the index, the volumes and anything hidden),
/// with its bytes - what a re-create must leave exactly as it was.
fn set_files_in(dir: &Path) -> Vec<(String, Vec<u8>)> {
    names_in(dir)
        .into_iter()
        .filter(|n| n.starts_with("set.") || n.starts_with('.'))
        .map(|n| {
            let b = std::fs::read(dir.join(&n)).unwrap();
            (n, b)
        })
        .collect()
}

/// A STRIPE-FIRST re-create that does not finish leaves the previous set
/// whole, and one that does writes what a fresh create writes.
///
/// The route that matters most here: stripe-first lays EVERY volume out
/// before its transform starts (`stripe_first::lay_out_volumes`), so for
/// the whole of a long transform every volume of the new set is open - and
/// until 9 Nov 2026 an overwriting re-create had truncated every previous
/// volume of the same name by then (the 9 Nov 2026 parfast sweep handoff,
/// E4). The same plan both times, so every name collides and every file is
/// staged; the fixture and the budget pin are the stripe-first test's,
/// and `cold == 1` proves this route ran both the first create and the
/// finished re-create.
#[test]
fn a_stripe_first_re_create_keeps_the_previous_set_until_it_is_whole() {
    use nzbkit::par2gen::control::{CreateControl, CreatePhase};
    use nzbkit::par2gen::{Par2GenError, create_into_exact_controlled};
    use nzbkit::par2repair::{PauseGate, ProgressSink};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let _arms = Arms::take();
    struct Unpin;
    impl Drop for Unpin {
        fn drop(&mut self) {
            ntt_range::pin_stripe_worker_panic_for_tests(None);
        }
    }
    let _unpin = Unpin;
    let (slices, rows) = ntt_range::floor_shape_for_tests(BS as usize);
    let plan = CreatePlan {
        volumes: VolumePlan::Even(8),
        ..CreatePlan::ENGINE
    };
    pin_accum_budget_for_tests((rows / 4) as u64 * BS);
    let t = Tmp::new("stripefirst-recreate");
    let dir = t.0.join("set");
    std::fs::create_dir_all(&dir).unwrap();
    let members = fixture(&dir, slices);
    let cold0 = ntt_range::cold_builds_for_tests();
    create_into_exact(&dir, &members, "set", Some(BS), rows, plan).unwrap();
    assert_eq!(
        ntt_range::cold_builds_for_tests() - cold0,
        1,
        "the previous set did not take stripe-first - re-size the fixture, do not delete the \
         assertion"
    );
    let before = set_files_in(&dir);
    // New bytes, same shape: every name of the new set is one of the old.
    let changed = payload((slices - 1) * BS as usize, 99);
    std::fs::write(&members[0].path, &changed).unwrap();

    // CANCELLED once the transform is sized - every volume laid out by then.
    struct CancelOnFold {
        gate: Arc<PauseGate>,
        dir: PathBuf,
        staged_seen: AtomicBool,
    }
    impl ProgressSink for CancelOnFold {
        fn progress(&self, phase: CreatePhase, _done: u64, _total: u64) {
            if phase == CreatePhase::Fold && !self.gate.is_cancelled() {
                let staged = names_in(&self.dir)
                    .iter()
                    .any(|n| n.starts_with(".set.vol") && n.ends_with(".tmp"));
                self.staged_seen.store(staged, Ordering::SeqCst);
                self.gate.cancel();
            }
        }
    }
    let gate = PauseGate::new();
    let sink = Arc::new(CancelOnFold {
        gate: gate.clone(),
        dir: dir.clone(),
        staged_seen: AtomicBool::new(false),
    });
    let progress: Arc<dyn ProgressSink> = sink.clone();
    let e = create_into_exact_controlled(
        &dir,
        &members,
        "set",
        Some(BS),
        rows,
        plan,
        None,
        &CreateControl::new(Some(progress), Some(gate)),
    )
    .expect_err("a cancelled stripe-first re-create must not report success");
    assert!(matches!(e, Par2GenError::Cancelled), "{e:?}");
    assert!(
        sink.staged_seen.load(Ordering::SeqCst),
        "no volume was staged when the cancel landed, so this did not reach the laid-out \
         volumes it is about"
    );
    assert_eq!(
        set_files_in(&dir),
        before,
        "a cancelled re-create changed the previous set"
    );

    // PANICKING in the transform: the unwind guard, not `settle`.
    ntt_range::pin_stripe_worker_panic_for_tests(Some(&dir));
    let r =
        std::panic::catch_unwind(|| create_into_exact(&dir, &members, "set", Some(BS), rows, plan));
    ntt_range::pin_stripe_worker_panic_for_tests(None);
    assert!(
        r.is_err(),
        "the planted worker panic did not unwind the create"
    );
    assert_eq!(
        set_files_in(&dir),
        before,
        "a panicking re-create changed the previous set"
    );

    // FINISHED: exactly the set a fresh create of the same inputs writes.
    let cold0 = ntt_range::cold_builds_for_tests();
    let names = create_into_exact(&dir, &members, "set", Some(BS), rows, plan).unwrap();
    assert_eq!(
        ntt_range::cold_builds_for_tests() - cold0,
        1,
        "not stripe-first"
    );
    let fresh = t.0.join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    let fresh_members = fixture(&fresh, slices);
    std::fs::write(&fresh_members[0].path, &changed).unwrap();
    let fresh_names =
        create_into_exact(&fresh, &fresh_members, "set", Some(BS), rows, plan).unwrap();
    assert_eq!(names, fresh_names);
    assert_eq!(
        set_files_in(&dir),
        set_files_in(&fresh),
        "the finished re-create is not the fresh create"
    );
}
