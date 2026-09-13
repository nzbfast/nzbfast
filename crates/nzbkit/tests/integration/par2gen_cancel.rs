//! A create that is called off mid-run, and the progress it reports on
//! the way.
//!
//! Landed 12 Sep 2026 with `par2gen::control` (claim
//! `par2gen-create-control`). Until then nothing under `par2gen` polled
//! anything: a Ctrl-C on `parfast c` was a plain kill and the partial
//! volumes it left named no member, because a volume is written to its
//! FINAL name with the critical packets patched in LAST.
//!
//! # Why these tests cannot be flaky
//!
//! Nothing here sleeps or guesses. The cancel is raised FROM THE
//! PROGRESS SINK - the engine tells the test it has reached a phase,
//! and the test's answer is to cancel - so "cancelled during the fold"
//! means exactly that on any machine at any speed. A create that
//! somehow finished anyway would fail the `Cancelled` assertion rather
//! than pass on the other route, which is the rule the repair side's
//! `cancel.rs` states for its own signal tests.
//!
//! # What is NOT here
//!
//! The MULTI-PASS cancel (a set batched across several passes, where a
//! cancel in a later pass has to remove the earlier passes' volumes)
//! lives in `nzbkit-base/tests/par2gen_large_set.rs`, because reaching
//! the batch boundary means pinning the process-wide accumulator budget
//! and this binary's `main.rs` refuses a module that leaves a
//! product-global behind it.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nzbkit::par2gen::control::{CreateControl, CreatePhase};
use nzbkit::par2gen::{
    CreatePlan, Member, create_into_exact, create_into_exact_controlled, ntt_range,
};
use nzbkit::par2repair::{PauseGate, ProgressSink};

/// A payload with no repeating period a fold could accidentally cancel
/// against.
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

struct Tmp(std::path::PathBuf);
impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "nzbfast-par2gen-cancel-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn write(&self, name: &str, data: &[u8]) -> Member {
        let path = self.0.join(name);
        std::fs::write(&path, data).unwrap();
        Member {
            name: name.to_string(),
            path,
        }
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every `.par2` in a directory, with its bytes - the whole of what a
/// create is allowed to have touched.
fn set_on_disk(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .expect("read dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".par2"))
        .map(|n| {
            let b = std::fs::read(dir.join(&n)).expect("read set file");
            (n, b)
        })
        .collect();
    out.sort();
    out
}

/// A sink that cancels the create the `nth` time it is told about
/// `phase`, and records every call for the assertions.
struct CancelOn {
    phase: CreatePhase,
    nth: u64,
    seen: AtomicU64,
    gate: Arc<PauseGate>,
    calls: Mutex<Vec<(CreatePhase, u64, u64)>>,
}

impl CancelOn {
    fn arm(phase: CreatePhase, nth: u64) -> (Arc<CancelOn>, CreateControl) {
        let gate = PauseGate::new();
        let s = Arc::new(CancelOn {
            phase,
            nth,
            seen: AtomicU64::new(0),
            gate: gate.clone(),
            calls: Mutex::new(Vec::new()),
        });
        let sink: Arc<dyn ProgressSink> = s.clone();
        (s, CreateControl::new(Some(sink), Some(gate)))
    }

    fn saw(&self, phase: CreatePhase) -> bool {
        self.calls.lock().unwrap().iter().any(|c| c.0 == phase)
    }
}

impl ProgressSink for CancelOn {
    fn progress(&self, phase: CreatePhase, done: u64, total: u64) {
        self.calls.lock().unwrap().push((phase, done, total));
        if phase == self.phase && self.seen.fetch_add(1, Ordering::SeqCst) + 1 >= self.nth {
            // Raised from inside the engine's own report, which is what
            // makes "cancelled during this phase" exact.
            self.gate.cancel();
        }
    }
}

/// A recording sink that never cancels.
#[derive(Default)]
struct Rec(Mutex<Vec<(CreatePhase, u64, u64)>>);
impl ProgressSink for Rec {
    fn progress(&self, phase: CreatePhase, done: u64, total: u64) {
        self.0.lock().unwrap().push((phase, done, total));
    }
}

#[test]
fn a_cancelled_create_removes_every_file_it_wrote() {
    let t = Tmp::new("fold");
    let a = payload(600_000, 7);
    let b = payload(300_000, 11);
    let members = vec![t.write("a.bin", &a), t.write("b.bin", &b)];
    let (sink, control) = CancelOn::arm(CreatePhase::Fold, 1);
    let err = create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(4096),
        64,
        CreatePlan::ENGINE,
        None,
        &control,
    )
    .expect_err("a create cancelled in its fold must not report success");
    assert!(
        matches!(err, nzbkit::par2gen::Par2GenError::Cancelled),
        "{err:?}"
    );
    assert!(
        sink.saw(CreatePhase::Fold),
        "the fold reported before it was cancelled"
    );
    // THE PROMISE: nothing of the set is left, index included. A
    // partial set is worse than none - its volumes carry a placeholder
    // critical block, so they name no member and verify against
    // nothing.
    assert_eq!(
        set_on_disk(&t.0),
        Vec::new(),
        "a cancelled create left part of a recovery set on disk"
    );
    // And the payload is untouched: a create only ever reads it.
    assert_eq!(std::fs::read(&members[0].path).unwrap(), a);
    assert_eq!(std::fs::read(&members[1].path).unwrap(), b);
}

/// The cancel that has something to undo: a volume is on disk by the
/// time it lands, and the trail has to take it back.
#[test]
fn a_cancel_after_a_volume_has_been_written_removes_that_volume_too() {
    let t = Tmp::new("write");
    let a = payload(600_000, 41);
    let members = vec![t.write("a.bin", &a)];
    // The SECOND report of the write phase: the first is the `(0,
    // total)` a bar sizes itself from, so this one is a volume that has
    // really been written and sealed.
    let (sink, control) = CancelOn::arm(CreatePhase::Write, 2);
    let err = create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(4096),
        64,
        CreatePlan::ENGINE,
        None,
        &control,
    )
    .expect_err("a create cancelled while writing volumes must not report success");
    assert!(
        matches!(err, nzbkit::par2gen::Par2GenError::Cancelled),
        "{err:?}"
    );
    let progressed = sink
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|&(p, done, _)| p == CreatePhase::Write && done > 0);
    assert!(
        progressed,
        "the cancel landed before a single volume was written, so this test proved nothing"
    );
    assert_eq!(
        set_on_disk(&t.0),
        Vec::new(),
        "a volume written before the cancel was left behind"
    );
}

#[test]
fn a_cancelled_index_only_create_leaves_no_index() {
    let t = Tmp::new("indexonly");
    let a = payload(400_000, 3);
    let members = vec![t.write("a.bin", &a)];
    let (sink, control) = CancelOn::arm(CreatePhase::Verify, 1);
    let err = create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(4096),
        // Zero recovery blocks is the index-only set: one scan, one
        // file, and the ONLY path where the member hashing is the whole
        // of the work.
        0,
        CreatePlan::ENGINE,
        None,
        &control,
    )
    .expect_err("a cancelled index-only create must not report success");
    assert!(
        matches!(err, nzbkit::par2gen::Par2GenError::Cancelled),
        "{err:?}"
    );
    assert!(sink.saw(CreatePhase::Verify));
    assert_eq!(set_on_disk(&t.0), Vec::new());
    assert_eq!(std::fs::read(&members[0].path).unwrap(), a);
}

#[test]
fn a_cancelled_extend_keeps_the_volumes_it_was_extending() {
    let t = Tmp::new("extend");
    let a = payload(600_000, 19);
    let members = vec![t.write("a.bin", &a)];
    // The set to extend, written in full.
    let first = create_into_exact(&t.0, &members, "set", Some(4096), 16, CreatePlan::ENGINE)
        .expect("the first create");
    let before = set_on_disk(&t.0);
    assert!(before.len() > 1, "{first:?}");
    // `-f 16`: sixteen more exponents onto the same set, cancelled in
    // the fold.
    let plan = CreatePlan {
        first_exponent: 16,
        ..CreatePlan::ENGINE
    };
    let (_sink, control) = CancelOn::arm(CreatePhase::Fold, 1);
    let err =
        create_into_exact_controlled(&t.0, &members, "set", Some(4096), 16, plan, None, &control)
            .expect_err("a cancelled extend must not report success");
    assert!(
        matches!(err, nzbkit::par2gen::Par2GenError::Cancelled),
        "{err:?}"
    );
    let after = set_on_disk(&t.0);
    // Every VOLUME the set already had is byte-identical, and none of
    // the extend's own is there.
    for (name, bytes) in &before {
        if name == "set.par2" {
            continue;
        }
        let found = after.iter().find(|(n, _)| n == name);
        assert_eq!(
            found.map(|(_, b)| b),
            Some(bytes),
            "{name} is not what it was before the cancelled extend"
        );
    }
    assert!(
        after.iter().all(|(n, _)| !n.starts_with("set.vol016")),
        "the extend's own volumes survived a cancel: {:?}",
        after.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    // THE ONE THING AN EXTEND DOES LOSE, stated rather than implied:
    // the index. Every create rewrites `<base>.par2` (with a
    // placeholder critical block it backfills at the end), so the index
    // IS a file this run wrote and the cancel takes it - which is
    // better than leaving a placeholder that names no member. The
    // volumes each repeat the critical block, so the set is still
    // nameable, and re-running the create writes the index again.
    assert!(
        !t.0.join("set.par2").exists(),
        "a cancelled create must not leave the placeholder index it wrote"
    );
}

#[test]
fn a_watched_create_writes_the_same_set_as_an_unwatched_one() {
    // The control decides nothing about the bytes, and this is the
    // claim `create_into_exact_controlled`'s doc makes.
    let t = Tmp::new("parity");
    let a = payload(600_000, 23);
    let b = payload(90_001, 29);
    let members = vec![t.write("a.bin", &a), t.write("b.bin", &b)];
    let plain = Tmp::new("parity-plain");
    let watched = Tmp::new("parity-watched");
    create_into_exact(
        &plain.0,
        &members,
        "set",
        Some(4096),
        48,
        CreatePlan::ENGINE,
    )
    .expect("the unwatched create");
    let rec = Arc::new(Rec::default());
    let sink: Arc<dyn ProgressSink> = rec.clone();
    create_into_exact_controlled(
        &watched.0,
        &members,
        "set",
        Some(4096),
        48,
        CreatePlan::ENGINE,
        None,
        &CreateControl::new(Some(sink), Some(PauseGate::new())),
    )
    .expect("the watched create");
    assert_eq!(set_on_disk(&plain.0), set_on_disk(&watched.0));
    assert!(
        !rec.0.lock().unwrap().is_empty(),
        "a watched create that reported nothing proves nothing here"
    );
}

#[test]
fn the_create_reports_its_phases_and_lands_each_one_on_full() {
    let t = Tmp::new("phases");
    let a = payload(600_000, 31);
    let members = vec![t.write("a.bin", &a)];
    let rec = Arc::new(Rec::default());
    let sink: Arc<dyn ProgressSink> = rec.clone();
    create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(4096),
        32,
        CreatePlan::ENGINE,
        None,
        &CreateControl::new(Some(sink), Some(PauseGate::new())),
    )
    .expect("create");
    let calls = rec.0.lock().unwrap().clone();
    for phase in [CreatePhase::Verify, CreatePhase::Fold, CreatePhase::Write] {
        let mine: Vec<_> = calls.iter().filter(|c| c.0 == phase).collect();
        assert!(!mine.is_empty(), "{phase:?} never reported: {calls:?}");
        let (_, done, total) = mine.last().expect("a phase with calls has a last one");
        assert_eq!(
            done, total,
            "{phase:?} stopped short of full: {done}/{total}"
        );
    }
    assert!(
        !calls.iter().any(|c| c.0 == CreatePhase::Solve),
        "a create has nothing to solve: {calls:?}"
    );
}

/// The block size the transform fixture below is cut at. 128 bytes is
/// `par2gen_create_ntt`'s, and for its reason: the shipped gates are on
/// the SLICE and ROW counts and never on the payload, so a fixture that
/// crosses them honestly is a quarter of a megabyte.
const NTT_BS: u64 = 128;

/// A payload of exactly `slices` input slices at [`NTT_BS`], as one long
/// member of full blocks and one short member whose only block is a
/// PARTIAL tail - the shape `par2gen_create_ntt::fixture` uses, because
/// the tail is what the mapped arm copies into its pad arena.
fn ntt_fixture(t: &Tmp, slices: usize) -> Vec<Member> {
    let bs = NTT_BS as usize;
    vec![
        t.write("payload.bin", &payload((slices - 1) * bs, 7)),
        t.write("tail.bin", &payload(bs / 2, 11)),
    ]
}

/// A sink that PAUSES the create the first time it is told `phase` has
/// reported anything, and tells the test on `tx` that it has.
struct PauseOn {
    phase: CreatePhase,
    gate: Arc<PauseGate>,
    armed: AtomicU64,
    tx: std::sync::mpsc::Sender<()>,
}

impl ProgressSink for PauseOn {
    fn progress(&self, phase: CreatePhase, _done: u64, _total: u64) {
        if phase == self.phase && self.armed.fetch_add(1, Ordering::SeqCst) == 0 {
            // Raised from inside the engine's own report, so "paused
            // during the fold" is exact on any machine at any speed -
            // the rule this file's header states for the cancels.
            self.gate.set_paused(true);
            let _ = self.tx.send(());
        }
    }
}

/// A Pause pressed while the create's ARITHMETIC is running stops it
/// there, rather than at the end of it.
///
/// # Why this shape and not a smaller one
///
/// The fixture is sized from `ntt_range::floor_shape_for_tests`, the
/// shipped admission gates themselves, so this create takes a TRANSFORM
/// arm on whatever box runs it (the mapped one on unix, the copied
/// windows elsewhere) and re-sizes itself if a gate is ever re-derived.
/// That matters because the transform is the only part of a create that
/// had no park site: the batch loop's own boundary gates, and the fold's
/// window loop gates, and until 12 Sep 2026 the stripe workers between
/// them did not. A one-batch create that took the transform therefore
/// had NO park point anywhere inside the whole of its arithmetic - a
/// measured 10.73 s of a 12.85 s run - and a Pause pressed during it
/// did nothing at all: the job read Paused, and then wrote its complete
/// set with Resume never pressed.
///
/// # Why the pause is raised on the FOLD report and why that is exact
///
/// `recovery_slices` calls `begin(Fold, ..)` AFTER the batch loop's own
/// gate and BEFORE it dispatches to an arm, so a pause raised from that
/// report cannot be honoured at the batch boundary - it has already
/// been passed. Only a park inside the arm can answer it. No sleep
/// decides anything here.
///
/// # The one timed window, and why it cannot pass by being slow
///
/// Proving a negative - "it did NOT finish" - needs a window, and a
/// window that is too short passes vacuously. So the budget is not a
/// constant: an UNPAUSED create of the same fixture is run and timed
/// first, and the paused one must still be unfinished after twenty
/// times that. A loaded box slows both halves together.
#[test]
fn a_pause_raised_inside_the_transform_parks_the_create() {
    let (slices, rows) = ntt_range::floor_shape_for_tests();

    // The control arm: the same create, unwatched, timed - and kept, so
    // the resumed create below can be held to its bytes.
    let plain = Tmp::new("pause-plain");
    let members = ntt_fixture(&plain, slices);
    let t_plain = std::time::Instant::now();
    create_into_exact(
        &plain.0,
        &members,
        "set",
        Some(NTT_BS),
        rows,
        CreatePlan::ENGINE,
    )
    .expect("the unpaused create");
    let unpaused = t_plain.elapsed();

    let t = Tmp::new("pause-parks");
    let members = ntt_fixture(&t, slices);
    let gate = PauseGate::new();
    let (tx, paused_rx) = std::sync::mpsc::channel();
    let sink: Arc<dyn ProgressSink> = Arc::new(PauseOn {
        phase: CreatePhase::Fold,
        gate: gate.clone(),
        armed: AtomicU64::new(0),
        tx,
    });
    let control = CreateControl::new(Some(sink), Some(gate.clone()));
    let dir = t.0.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let r = create_into_exact_controlled(
            &dir,
            &members,
            "set",
            Some(NTT_BS),
            rows,
            CreatePlan::ENGINE,
            None,
            &control,
        );
        let _ = done_tx.send(r.is_ok());
    });

    paused_rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the create never reported a fold, so nothing was paused");

    // Twenty times an unpaused run of the same bytes on this same box.
    let budget = (unpaused * 20).max(std::time::Duration::from_millis(500));
    assert!(
        done_rx.recv_timeout(budget).is_err(),
        "a PAUSED create ran to completion in {budget:?} (an unpaused one takes {unpaused:?})"
    );
    // The index placeholder IS on disk by now and is meant to be: it
    // is written before the fold, carries a placeholder critical block
    // until the backfill at the very end, and is noted in the trail so
    // a cancel takes it (the test below holds it to that). What a
    // create parked in its arithmetic cannot have is a VOLUME - those
    // are written from `slices`, which is what the parked call has not
    // returned yet.
    let volumes: Vec<String> = set_on_disk(&t.0)
        .into_iter()
        .map(|(n, _)| n)
        .filter(|n| n.contains(".vol"))
        .collect();
    assert!(
        volumes.is_empty(),
        "a create parked in its fold has written no volumes yet: {volumes:?}"
    );

    // ...and it is parked, not wedged: lifting the pause finishes it,
    // and finishes it on the unpaused arm's own bytes.
    gate.set_paused(false);
    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .expect("the resumed create never finished"),
        "the resumed create failed"
    );
    worker.join().expect("the create thread panicked");
    assert_eq!(
        set_on_disk(&t.0),
        set_on_disk(&plain.0),
        "a paused-and-resumed create wrote different bytes"
    );
}

/// A CANCEL raised while the create is parked releases it, which is the
/// half a park must never take away: a user who pauses and then changes
/// their mind must not have to resume first.
#[test]
fn a_cancel_reaches_a_create_parked_in_its_transform() {
    let (slices, rows) = ntt_range::floor_shape_for_tests();
    let t = Tmp::new("pause-cancel");
    let members = ntt_fixture(&t, slices);
    let gate = PauseGate::new();
    let (tx, paused_rx) = std::sync::mpsc::channel();
    let sink: Arc<dyn ProgressSink> = Arc::new(PauseOn {
        phase: CreatePhase::Fold,
        gate: gate.clone(),
        armed: AtomicU64::new(0),
        tx,
    });
    let control = CreateControl::new(Some(sink), Some(gate.clone()));
    let dir = t.0.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let r = create_into_exact_controlled(
            &dir,
            &members,
            "set",
            Some(NTT_BS),
            rows,
            CreatePlan::ENGINE,
            None,
            &control,
        );
        let _ = done_tx.send(r);
    });
    paused_rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the create never reported a fold, so nothing was paused");
    gate.cancel();
    let r = done_rx
        .recv_timeout(std::time::Duration::from_secs(120))
        .expect("a cancel did not release the parked create");
    worker.join().expect("the create thread panicked");
    assert!(
        matches!(r, Err(nzbkit::par2gen::Par2GenError::Cancelled)),
        "expected Cancelled, got {r:?}"
    );
    assert!(
        set_on_disk(&t.0).is_empty(),
        "a cancelled create leaves nothing: {:?}",
        set_on_disk(&t.0)
    );
}

/// What a FUSED create tells a sink - the arm nothing had run until
/// 12 Sep 2026, and the one a reported defect turned out not to have.
///
/// # Why this is `#[ignore]`d
///
/// The fused arm's own gates decide the fixture and they are the point:
/// a single member of at least 1 GiB at a block of at least 1 MiB, on
/// unix, with a row count under the transform's crossover. The floors
/// can be lowered with `NZBFAST_PAR2GEN_FUSE=1`, but this is a MODULE
/// of the shared `integration` target and `std::env::set_var` is sound
/// only in a binary that owns its process - the reason `ntt_range`
/// states for using test doors instead. So this builds the real thing,
/// which is a 1.2 GiB write and several seconds, and runs by hand:
///
/// ```text
/// cargo nextest run -p nzbkit -E 'binary(integration)' \
///     --run-ignored only -E 'test(fused_create)'
/// ```
///
/// # What it settles
///
/// A defect was reported against this arm on 12 Sep 2026 and the chain
/// was: a fused create never calls `begin(Verify, ..)` (true - see
/// `create_body`), `meter()` returns a meter whether or not `begin` ran
/// (true), `step` reads `total.max(1)` so an unsized meter's FIRST step
/// crosses every bucket and announces a full phase (true), and
/// `scan.rs` steps Verify regardless (FALSE, and it is the whole
/// finding). Those five `step(Verify, ..)` sites are all inside the
/// four arms of `scan_all`, which `create_body` spawns only when
/// `fused_scan.is_none()`. The fused reader is `FusedScan`, which is
/// never handed a `CreateControl` at all and so cannot step anything.
/// The chain is sound and its second link does not execute on the arm
/// it was written about.
///
/// What IS true is the tail of it: the unconditional
/// `finish(CreatePhase::Verify)` at the end of `create_body` reaches an
/// unsized meter and announces `(0, 0)`. That is not the reported
/// defect and is not one: a sink is told a phase is over with a total
/// of zero, which the session crate's `CreateProgress` already reads as
/// a zero fraction under a `max`, and the `finish(Write)` one line
/// later lands the bar on full regardless. Asserted below so that if
/// anyone ever DOES size the fused Verify meter, they find out here
/// that its shape is deliberate.
#[test]
#[ignore = "builds a 1.2 GiB fixture: the fused arm's own size gate, run by hand"]
fn a_fused_create_reports_no_verify_progress_and_that_is_not_a_meter_bug() {
    let t = Tmp::new("fused");
    // 1.2 GiB clears FUSED_SOURCE_MIN_BYTES; ONE member is the unix
    // fusion shape; a 1 MiB block clears FUSED_SOURCE_MIN_BLOCK_BYTES;
    // 24 rows sits far under the transform's row gate, which is what
    // leaves fusion admitted rather than displaced.
    let block = 1u64 << 20;
    let members = vec![t.write("one.bin", &payload(1200 << 20, 17))];
    let rec = Arc::new(Rec::default());
    let sink: Arc<dyn ProgressSink> = rec.clone();
    create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(block),
        24,
        CreatePlan::ENGINE,
        None,
        &CreateControl::new(Some(sink), Some(PauseGate::new())),
    )
    .expect("the fused create");

    let calls = rec.0.lock().unwrap().clone();
    let verify: Vec<_> = calls
        .iter()
        .filter(|c| c.0 == CreatePhase::Verify)
        .collect();
    // If this fires, the create was NOT fused and the test proved
    // nothing about the fused arm - re-check the gates in
    // `scan::source_fusion_shape_admitted`, do not delete the assertion.
    assert!(
        !calls.is_empty() && calls.iter().any(|c| c.0 == CreatePhase::Fold),
        "no fold was reported at all: {calls:?}"
    );
    assert_eq!(
        verify.len(),
        1,
        "a fused create's only Verify call is the unconditional finish: {verify:?}"
    );
    assert_eq!(
        (verify[0].1, verify[0].2),
        (0, 0),
        "the fused Verify meter is deliberately UNSIZED - a non-zero total here means somebody \
         began it, and the reported-full-on-first-step chain becomes reachable"
    );
    // And the bar still lands on full, which is what makes the above
    // harmless rather than a defect.
    let write: Vec<_> = calls.iter().filter(|c| c.0 == CreatePhase::Write).collect();
    let last = write.last().expect("a create writes volumes");
    assert_eq!(last.1, last.2, "Write stopped short of full: {last:?}");
}
