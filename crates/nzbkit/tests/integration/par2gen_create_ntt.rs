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
//! The doors are atomics; [`Arms`] serialises the tests that move them
//! and lifts every pin on the way out. Under nextest each test is its
//! own process and the lock is free; under `cargo test` and CI's
//! `unit-one-process` job this whole binary is ONE process, which is
//! the run it is for.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

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

/// The tests that pin a create-side process-global, one at a time, with
/// every pin lifted on the way out however the test leaves. The guard is
/// taken through `into_inner` so one failing test does not turn the rest
/// into poisoned-lock failures that hide it.
struct Arms(Option<MutexGuard<'static, ()>>);

static ARMS: Mutex<()> = Mutex::new(());

impl Arms {
    fn take() -> Arms {
        Arms(Some(ARMS.lock().unwrap_or_else(|e| e.into_inner())))
    }
}

impl Drop for Arms {
    fn drop(&mut self) {
        ntt_range::pin_transform_off_for_tests(false);
        ntt_range::pin_map_off_for_tests(false);
        pin_accum_budget_for_tests(0);
        drop(self.0.take());
    }
}

/// A payload of exactly `slices` input slices at [`BS`], as two members:
/// one long member of full blocks and a short one whose only block is a
/// PARTIAL tail, because the tail is what the mapped path copies into
/// its pad arena rather than reading out of the mapping.
fn fixture(dir: &Path, slices: usize) -> Vec<Member> {
    let bs = BS as usize;
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
    let dir = t.0.join(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let members = fixture(&dir, slices);
    let before = ntt_range::cold_builds_for_tests();
    let names = create_into_exact(&dir, &members, "set", Some(BS), rows, plan).unwrap();
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
    let (slices, rows) = ntt_range::floor_shape_for_tests();
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
    let (slices, rows) = ntt_range::floor_shape_for_tests();
    let t = Tmp::new("copied");

    ntt_range::pin_transform_off_for_tests(true);
    let (fold, cold_fold) = arm(&t, "fold", slices, rows, CreatePlan::ENGINE);
    assert_eq!(cold_fold, 0, "the fold arm must build no transform plan");

    ntt_range::pin_transform_off_for_tests(false);
    ntt_range::pin_map_off_for_tests(true);
    let (ntt, cold_ntt) = arm(&t, "ntt", slices, rows, CreatePlan::ENGINE);
    assert_transformed(cold_ntt, "copied-window", slices, rows);

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
    let (floor_slices, _) = ntt_range::floor_shape_for_tests();
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
    let (slices, rows) = ntt_range::floor_shape_for_tests();
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
    let (slices, rows) = ntt_range::floor_shape_for_tests();
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
