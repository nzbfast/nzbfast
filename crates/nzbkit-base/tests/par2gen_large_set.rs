//! `par2gen` at a scale the unit tests cannot afford.
//!
//! The tests beside the creator are all small on purpose - they run on
//! every push - and the biggest committed PAR2 fixture in this tree is
//! 180 KB. Three things had therefore never been exercised anywhere:
//! a set of MANY members, thousands of slices at the block size the
//! creator actually picks, and the accumulator budget biting at a block
//! size that is not a toy. (`a_set_batched_across_several_passes_still_
//! repairs` does drive the multi-batch path, but with a 4,000-byte block
//! chosen to force it, which is not the shape a real set has.)
//!
//! ## Why this is a heavy target rather than a unit test
//!
//! Its fixtures are tens of megabytes and its arithmetic is seconds of
//! Reed-Solomon, and NIGHTLY BUILDS DEBUG - where this crate's GF(2^16)
//! fold runs roughly 40x slower than release. Measured 31 Aug 2026 on a
//! 32-core arm64 machine, one 256 MB set at 10% redundancy: 4.07 s
//! release against 119.7 s debug. So every fixture below is sized
//! against the DEBUG number, and none of them is committed: they are
//! generated into a temp directory and deleted, which is also the only
//! honest way to ship a fixture this size in a repository already large
//! enough to evict its own CI cache.
//!
//! `required-features = ["heavy-tests"]` in `Cargo.toml` is what keeps
//! per-push CI from BUILDING it (TODO 116b) - nextest's `-E 'not
//! binary(...)'` filters running only. Run it locally with:
//!
//! ```text
//! cargo test --release -p nzbkit --test par2gen_large_set --features heavy-tests
//! ```
//!
//! `--release` because a debug GF16 number is not a number anybody
//! should quote, and because the whole suite is seconds there.

use std::path::{Path, PathBuf};
use std::process::Command;

use nzbkit_base::par2gen::{
    CreatePlan, Member, Par2Spec, accum_budget_bytes, create_into, create_into_exact, ntt_range,
    pin_accum_budget_for_tests,
};

/// The tests here that touch a create-side PROCESS-GLOBAL, one at a time:
/// the transform arm pins, the band arena pin, and the accumulator budget
/// pin. Taken through `into_inner` so one failing test does not poison the
/// rest into failures that hide it.
///
/// The plan and band counters are monotone and process-global, and
/// nightly's one-process run puts this whole binary in ONE process. The
/// ACCUMULATOR pin is worse than a counter, because it decides where the
/// batch boundary falls: `the_accumulator_budget_really_splits_a_set_into_
/// several_passes` pins 64 MiB and then reads `accum_budget_bytes()` back
/// to prove its fixture crossed that boundary, while
/// `a_cancel_in_a_later_pass_removes_the_earlier_passes_volumes` LIFTS the
/// same pin at its end - so run in parallel, the first can read the host's
/// unpinned 8 GiB and fail an assertion about a set it really did split.
/// Measured 15 Sep 2026: "fixture no longer crosses the budget: 81
/// recovery slices against a 8192-slice batch (8589934592 B budget)",
/// failing in the target and passing alone. That race predates the band
/// route; adding an eighth test to this binary is what made it show.
static PROCESS_PINS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The accumulator budget pinned to `bytes` for as long as this is held,
/// [`PROCESS_PINS`] with it, and the pin LIFTED however the test leaves -
/// which is what the two tests above did not do for each other.
struct PinnedAccum(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

impl PinnedAccum {
    fn new(bytes: u64) -> PinnedAccum {
        let held = PROCESS_PINS.lock().unwrap_or_else(|e| e.into_inner());
        pin_accum_budget_for_tests(bytes);
        PinnedAccum(held)
    }
}

impl Drop for PinnedAccum {
    fn drop(&mut self) {
        pin_accum_budget_for_tests(0);
    }
}

/// A payload with no long runs and no repeating period a fold could
/// accidentally cancel against - a zero-filled fixture would pass a
/// Reed-Solomon test that a wrong coefficient should have failed.
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

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "nzbfast-par2gen-large-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn write(&self, name: &str, data: &[u8]) -> Member {
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
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

/// par2cmdline is not installed everywhere - some machines in this fleet
/// have none - so anything that shells out to it asks first. Nightly
/// installs it on purpose and sets `NZBFAST_REQUIRE_PAR2`.
///
/// AND UNTIL 4 SEP 2026 THIS PROBE DID NOT READ THAT VARIABLE, so the
/// sentence above was a claim about the workflow and nothing enforced
/// it: the two jobs that run this target (`long-suites` and
/// `one-process-heavy`, both nightly - it is heavy-gated out of every
/// per-push archive) would have skipped every assertion here and
/// reported green if their apt install had ever left no binary behind.
/// Same assert the three `par2repair_*` modules in nzbkit carry. Found
/// alongside the postfast catalog guard that ran on no job at all,
/// claim `postfast-par2-conformance-runs-nowhere`.
fn have_par2() -> bool {
    let ok = Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        ok || std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
        "NZBFAST_REQUIRE_PAR2 is set but `par2 -V` does not run - the PAR2 tests \
         would have skipped and the run would have looked green"
    );
    ok
}

/// The reference's own version, from `par2cmdline version 1.3.0`.
///
/// WHICH par2 answered is load-bearing here and nothing else in this
/// tree records it: the runner's `apt-get install par2` gives ubuntu's
/// 0.8.1, two majors behind every box in this fleet, and the two are
/// not interchangeable on the shape below. `None` means the banner did
/// not parse, which is treated as OLD - a reference we cannot identify
/// is not one to make a version-dependent claim about.
fn par2_version() -> Option<(u32, u32, u32)> {
    let out = Command::new("par2").arg("-V").output().ok()?;
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    let tok = text.split_whitespace().find(|w| {
        let mut parts = w.split('.');
        parts.clone().count() == 3
            && parts.all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    })?;
    let mut it = tok.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    Some((it.next()?, it.next()?, it.next()?))
}

/// Does this par2cmdline understand a set that DESCRIBES a 0-byte
/// member?
///
/// Nothing about that set is off spec and no par2cmdline can create
/// one: `par2 create` prints "Skipping 0 byte file" and omits the
/// member outright at every version, which is the measured hole
/// (`research/NORAR-DEOBF-MATRIX-2026-08-29.md` F3) that `par2gen`
/// exists to fill for `nzbfast post --allow-empty`. On the VERIFY side
/// upstream carried a defect until 1.0.0 - ChangeLog issue #128,
/// "Problem with empty (0 Bytes) files", workaround via PR #200 - where
/// `Par2Repairer::ScanDataFile` takes an early return on any empty file
/// and so never marks that target complete. 0.8.1 therefore calls an
/// entirely intact set "Repair is required / 1 file(s) exist but are
/// damaged" and exits 1, and `par2 repair` on the same set exits 5
/// "Repair Failed" without touching a byte of payload. 1.0.0 added the
/// `GetTargetExists()` guard in front of that return and accepts it.
///
/// Measured 1 Sep 2026, all three built from their upstream tags on one
/// box against one set: 0.8.1 refuses, 1.0.0 accepts, 1.3.0 accepts;
/// and the SAME set minus the 0-byte member is accepted by all three.
/// `research/NIGHTLY-PAR2GEN-INTEROP-RED-2026-09-01.md`.
fn par2_describes_empty_members() -> bool {
    par2_version().is_some_and(|v| v >= (1, 0, 0))
}

fn sha_of(dir: &Path, names: &[String]) -> Vec<(String, [u8; 16])> {
    names
        .iter()
        .map(|n| {
            let b = std::fs::read(dir.join(n)).unwrap();
            (n.clone(), md5_of(&b))
        })
        .collect()
}

/// A digest is all this needs - it is comparing two builds of the same
/// set, not defending against a forgery.
fn md5_of(b: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    Md5::digest(b).into()
}

/// ~24 MB over six members with awkward shapes: a partial tail block on
/// every one, a 0-byte placeholder (the shape par2cmdline refuses to
/// describe at all, which is why this creator exists), a member smaller
/// than one block, and a nested path.
///
/// `with_empty` drops the placeholder, and the member is not written to
/// disk at all rather than merely left undescribed - an unnamed file
/// beside the set is an "extra file" to par2cmdline, which is a
/// different test. The only caller that passes `false` is the interop
/// one against a par2 older than [`par2_describes_empty_members`], and
/// the five members it keeps still carry every other awkward shape.
fn wide_set(t: &Tmp, with_empty: bool) -> Vec<Member> {
    let mut members = vec![
        t.write("VIDEO_TS/VTS_01_1.VOB", &payload(9_000_001, 1)),
        t.write("VIDEO_TS/VTS_01_2.VOB", &payload(8_500_003, 2)),
        t.write("VIDEO_TS/VTS_01_3.VOB", &payload(6_250_007, 3)),
        t.write("sample/sample.mkv", &payload(250_011, 4)),
        t.write("readme.nfo", &payload(913, 5)),
    ];
    if with_empty {
        members.push(t.write("VIDEO_TS/VIDEO_TS.BUP", b""));
    }
    members
}

#[test]
fn a_wide_set_at_the_creator_s_own_block_size_repairs_real_damage() {
    // The shape nothing else covers: six members, the block size the
    // creator PICKS rather than one chosen to force a code path, and
    // enough slices that the RS constant walk is at a real post's scale.
    let t = Tmp::new("wide");
    let members = wide_set(&t, true);
    // Beside the payload: a PAR2 set names its members RELATIVE to its
    // own directory, so a set written into a subdirectory of its own
    // describes files that are not there.
    let out = t.0.clone();
    let names = create_into(
        &out,
        &members,
        "big",
        &Par2Spec {
            redundancy_pct: 5,
            block_size: None,
        },
    )
    .unwrap();
    assert!(names.len() > 4, "expected an index and volumes: {names:?}");

    // Our own reader names every member, the 0-byte one included.
    let blobs: Vec<Vec<u8>> = names
        .iter()
        .map(|n| std::fs::read(out.join(n)).unwrap())
        .collect();
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    let set = nzbkit_base::par2::Par2Set::parse(&refs).expect("our own parser reads our own set");
    assert_eq!(set.files.len(), 6, "{:?}", set.files.len());
    assert!(
        set.files
            .iter()
            .any(|f| f.name.ends_with("VIDEO_TS.BUP") && f.length == 0),
        "the 0-byte placeholder must be described"
    );
    // Thousands of slices, not dozens: this is what the default block
    // size is FOR, and no other test reaches it.
    let slices: usize = set.files.iter().map(|f| f.blocks.len()).sum();
    assert!(
        slices > 1_500,
        "expected a real post's slice count, got {slices}"
    );

    // Damage spread across two members and both ends of a file, so the
    // repair has to place blocks rather than truncate-and-refill.
    let victim = &members[0].path;
    let good = std::fs::read(victim).unwrap();
    let mut broken = good.clone();
    let n = broken.len();
    broken[1_000..40_000].fill(0);
    broken[n - 20_000..].fill(0xff);
    std::fs::write(victim, &broken).unwrap();
    let other = &members[3].path;
    let good_other = std::fs::read(other).unwrap();
    std::fs::write(other, payload(good_other.len(), 99)).unwrap();

    let status = nzbkit_base::par2repair::repair_dir(&out).expect("repair runs");
    assert!(
        matches!(status, nzbkit_base::par2repair::RepairStatus::Repaired(_)),
        "{status:?}"
    );
    assert_eq!(
        std::fs::read(victim).unwrap(),
        good,
        "victim not byte-exact"
    );
    assert_eq!(
        std::fs::read(other).unwrap(),
        good_other,
        "second member not byte-exact"
    );
}

#[test]
fn the_accumulator_budget_really_splits_a_set_into_several_passes() {
    // The budget scales with the box's RAM since 2 Sep 2026; pin it at
    // the 64 MiB this fixture was sized against so the boundary is
    // where the assertion below expects it, whatever the machine. The
    // guard also holds [`PROCESS_PINS`], because the pin is
    // process-global and the cancel test below lifts it.
    let _pins = PinnedAccum::new(64 << 20);
    // The multi-batch path at a block size that is not a toy. Getting
    // there is a fixed trade and this picks the cheap end of it: a batch
    // holds at most `ACCUM_BUDGET / block_size` recovery slices, so
    // crossing it needs EITHER a large block with heavy redundancy over
    // a small payload, or a realistic redundancy over ~650 MB of it.
    // 900% over 8 MB is not a shape any poster would choose; it is the
    // only shape that reaches this arithmetic for a couple of seconds of
    // debug-build fold, and the arithmetic is what is under test.
    let t = Tmp::new("batches");
    let block = 1u64 << 20;
    let members = vec![
        t.write("a.bin", &payload(5 << 20, 7)),
        t.write("b.bin", &payload((3 << 20) + 4_097, 8)),
    ];
    let out = t.0.clone();
    let names = create_into(
        &out,
        &members,
        "batched",
        &Par2Spec {
            redundancy_pct: 900,
            block_size: Some(block),
        },
    )
    .unwrap();

    // PROVE the crossing rather than assume it. Read against the real
    // budget, so if that const ever moves this fails loudly here instead
    // of leaving the suite silently covering a single pass.
    let per_batch = (accum_budget_bytes() / block).max(1) as usize;
    let blobs: Vec<Vec<u8>> = names
        .iter()
        .map(|n| std::fs::read(out.join(n)).unwrap())
        .collect();
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    let set = nzbkit_base::par2::Par2Set::parse(&refs).expect("parse");
    let n_recovery: usize = set.recovery_blocks_seen;
    let budget = accum_budget_bytes();
    assert!(
        n_recovery > per_batch,
        "fixture no longer crosses the budget: {n_recovery} recovery slices against a \
         {per_batch}-slice batch ({budget} B budget / {block} B block) - \
         re-size the fixture, do not delete the assertion"
    );

    // And it still repairs, which is the only thing that proves the
    // exponent bookkeeping stitched the passes together correctly.
    let victim = &members[1].path;
    let good = std::fs::read(victim).unwrap();
    let mut broken = good.clone();
    broken[0..(2 << 20)].fill(0);
    std::fs::write(victim, &broken).unwrap();
    let status = nzbkit_base::par2repair::repair_dir(&out).expect("repair runs");
    assert!(
        matches!(status, nzbkit_base::par2repair::RepairStatus::Repaired(_)),
        "{status:?}"
    );
    assert_eq!(std::fs::read(victim).unwrap(), good);
}

/// A cancel in a LATER pass has to remove the EARLIER passes' volumes.
///
/// This is the one cancel claim the light suite
/// (`nzbkit/tests/integration/par2gen_cancel.rs`) cannot make, and it
/// lives here for the same reason its neighbour above does: reaching a
/// second pass means pinning the process-wide accumulator budget, which
/// the merged integration binary refuses to have left behind it. The
/// shape is that neighbour's, at the same pinned budget so the two
/// cannot disagree about where the boundary is.
#[test]
fn a_cancel_in_a_later_pass_removes_the_earlier_passes_volumes() {
    use nzbkit_base::par2gen::control::{CreateControl, CreatePhase};
    use nzbkit_base::par2repair::{PauseGate, ProgressSink};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    let _pins = PinnedAccum::new(64 << 20);
    let t = Tmp::new("cancelpass");
    let block = 1u64 << 20;
    let members = vec![
        t.write("a.bin", &payload(5 << 20, 7)),
        t.write("b.bin", &payload((3 << 20) + 4_097, 8)),
    ];
    let out = t.0.clone();
    let n_slices = 8 + 4; // 5 MiB + 3 MiB + a tail, at a 1 MiB block
    let per_batch = (accum_budget_bytes() / block).max(1) as usize;
    // Nine passes' worth of rows at the pinned budget, so a cancel in
    // the SECOND pass has a first pass's volumes to take back.
    let rows = per_batch * 3;
    assert!(
        rows > per_batch,
        "fixture no longer crosses the budget ({rows} rows, {per_batch}-row batch) - \
         re-size it, do not delete the assertion"
    );

    /// Cancels the create the second time the fold phase is SIZED -
    /// which is the second pass, exactly (`recovery_slices` begins the
    /// phase once per batch), and records what it was told.
    struct OnSecondPass {
        begins: AtomicU64,
        gate: Arc<PauseGate>,
        volumes_written: Mutex<u64>,
    }
    impl ProgressSink for OnSecondPass {
        fn progress(&self, phase: CreatePhase, done: u64, _total: u64) {
            if phase == CreatePhase::Write && done > 0 {
                *self.volumes_written.lock().unwrap() = done;
            }
            if phase == CreatePhase::Fold && done == 0 {
                // `(Fold, 0, total)` is a pass sizing its bar.
                if self.begins.fetch_add(1, Ordering::SeqCst) + 1 >= 2 {
                    self.gate.cancel();
                }
            }
        }
    }

    let gate = PauseGate::new();
    let sink = Arc::new(OnSecondPass {
        begins: AtomicU64::new(0),
        gate: gate.clone(),
        volumes_written: Mutex::new(0),
    });
    let progress: Arc<dyn ProgressSink> = sink.clone();
    let err = nzbkit_base::par2gen::create_into_exact_controlled(
        &out,
        &members,
        "cset",
        Some(block),
        rows,
        CreatePlan::ENGINE,
        None,
        &CreateControl::new(Some(progress), Some(gate)),
    )
    .expect_err("a create cancelled in its second pass must not report success");
    assert!(
        matches!(err, nzbkit_base::par2gen::Par2GenError::Cancelled),
        "{err:?}"
    );
    assert!(
        *sink.volumes_written.lock().unwrap() > 0,
        "the cancel landed before the first pass wrote a volume, so this proved nothing"
    );
    let left: Vec<String> = std::fs::read_dir(&out)
        .expect("read dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".par2"))
        .collect();
    assert!(
        left.is_empty(),
        "a cancel in a later pass left the earlier passes' volumes: {left:?}"
    );
    assert_eq!(n_slices, 12, "the fixture's slice count is a constant here");
    pin_accum_budget_for_tests(0);
}

#[test]
fn two_builds_of_one_set_are_byte_identical() {
    // The fold is PARALLEL and its work is split by a grid derived from
    // the machine's core count, so "the same input gives the same bytes"
    // stopped being free the day it stopped being a loop. A racing
    // accumulator would still VERIFY - it is a valid recovery set for
    // whatever it computed - so verification cannot catch this and only
    // a byte comparison can.
    let t = Tmp::new("determinism");
    let members = vec![
        t.write("a.bin", &payload(3_000_001, 21)),
        t.write("b/c.bin", &payload(1_500_003, 22)),
        t.write("empty.bin", b""),
    ];
    let mut runs = Vec::new();
    for i in 0..2 {
        let out = t.0.join(format!("run{i}"));
        std::fs::create_dir_all(&out).unwrap();
        let names = create_into(
            &out,
            &members,
            "det",
            &Par2Spec {
                redundancy_pct: 30,
                block_size: Some(16_384),
            },
        )
        .unwrap();
        assert!(names.len() > 3, "{names:?}");
        runs.push(sha_of(&out, &names));
    }
    assert_eq!(
        runs[0], runs[1],
        "the same set built twice must be the same bytes"
    );
}

#[test]
fn the_slice_ceilings_refuse_before_anything_is_built() {
    // Both PAR2 ceilings, neither of which any other test reaches. Sized
    // to exceed them by a wide margin rather than by one, so raising
    // either limit does not silently stop covering it.
    let t = Tmp::new("ceilings");
    let out = t.0.join("set");
    std::fs::create_dir_all(&out).unwrap();

    // 4-byte blocks over 800 KB is 200,000 input slices against a 32,768
    // ceiling - the cheapest way to reach it, and the reason a ceiling
    // test needs no large fixture at all.
    let members = vec![t.write("many.bin", &payload(800_000, 31))];
    let err = create_into(
        &out,
        &members,
        "over",
        &Par2Spec {
            redundancy_pct: 10,
            block_size: Some(4),
        },
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("input slices"), "{msg}");
    assert!(msg.contains("raise the block size"), "{msg}");

    // And the RECOVERY ceiling, which is a different refusal: the slice
    // count is legal and the redundancy asks for more exponents than the
    // coprime sequence has. 20,000 slices at 400% is 80,000 of them.
    let small = vec![t.write("few.bin", &payload(80_000, 32))];
    let err = create_into(
        &out,
        &small,
        "overrec",
        &Par2Spec {
            redundancy_pct: 400,
            block_size: Some(4),
        },
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("recovery slices"), "{msg}");
    assert!(msg.contains("lower the redundancy"), "{msg}");
}

#[test]
fn the_transform_writes_the_fold_s_bytes_at_a_real_block_size() {
    // The create-side NTT at a block size that is not a toy, which is the
    // half `crates/nzbkit/tests/integration/par2gen_create_ntt.rs` cannot
    // afford on every push. That file covers all four dispatch shapes -
    // mapped, copied windows, the subfloor clause, stripe-first - at a
    // 128-byte block, where the transform runs as ONE stripe on ONE
    // worker: `ntt_create_stripe_geometry` cuts a block into 512-word stripes
    // and hands them to every core, so at 128 bytes there is a single
    // stripe and the atomic claim loop, the per-worker scratch and the
    // cross-worker column split never run at all.
    //
    // 4,096 bytes gives four stripes over as many workers as the box
    // has, which is the geometry a real set is built at. The price is
    // why it lives here rather than beside them: the same slice count at
    // a real block is thirty times the payload, folded twice over (both
    // arms). Measured 8 Sep 2026 on the dev Mac (32 cores, arm64), DEBUG
    // build: 0.7 s here against 0.5 s for all four of the per-push
    // tests - both parallel folds, so a 4 vCPU runner pays several times
    // that.
    //
    // The shape comes from the shipped gates rather than from numbers
    // copied out of them, so it re-sizes itself if a gate is
    // re-derived; the assertion that a plan was really built is what
    // makes that safe.
    //
    // The arm pin and the plan counter are process-global. Until 15 Sep
    // 2026 this test took no lock over them, because none of the five
    // tests beside it was anywhere near the gates - the widest is ~1,500
    // slices at 75 rows - so nothing else in this binary built a plan or
    // cared which arm was pinned. The band route's real-block test below
    // (TODO 345 C) is exactly the large-shape test that breaks that: the
    // counter is monotone, so a concurrent plan build would inflate this
    // test's difference and fail it LOUDLY rather than pass on somebody
    // else's transform. Both now take [`PROCESS_PINS`], the shared
    // serializer this comment always said the fix would be, the way
    // `par2gen_create_ntt` next door carries one - and the two
    // accumulator-pin tests take it as well, for a race of their own that
    // predates either of them (see that static).
    let _serial = PROCESS_PINS.lock().unwrap_or_else(|e| e.into_inner());
    let bs = 4_096u64;
    let (slices, rows) = ntt_range::floor_shape_for_tests(bs as usize);
    let t = Tmp::new("createntt");
    // Two members, the second a PARTIAL tail block - the block the
    // mapped path copies into its pad arena instead of reading out of
    // the mapping. Each arm gets its own copy beside its own set,
    // because a PAR2 set names its members relative to its own
    // directory and the transform arm is repaired below.
    // The NAMES travel with the bytes: a volume split that came out
    // differently would otherwise compare equal file for file.
    let mut built: Vec<Vec<(String, Vec<u8>)>> = Vec::new();
    for (tag, fold) in [("fold", true), ("ntt", false)] {
        ntt_range::pin_transform_off_for_tests(fold);
        let dir = t.0.join(tag);
        std::fs::create_dir_all(&dir).unwrap();
        let members = vec![
            {
                let path = dir.join("payload.bin");
                std::fs::write(&path, payload((slices - 1) * bs as usize, 41)).unwrap();
                Member {
                    name: "payload.bin".into(),
                    path,
                }
            },
            {
                let path = dir.join("tail.bin");
                std::fs::write(&path, payload(bs as usize / 2, 42)).unwrap();
                Member {
                    name: "tail.bin".into(),
                    path,
                }
            },
        ];
        let before = ntt_range::cold_builds_for_tests();
        let names =
            create_into_exact(&dir, &members, "set", Some(bs), rows, CreatePlan::ENGINE).unwrap();
        let cold = ntt_range::cold_builds_for_tests() - before;
        assert_eq!(
            cold,
            u64::from(!fold),
            "the {tag} arm built {cold} transform plan(s) at {slices} inputs x {rows} rows - if \
             this is the transform arm the shipped gates refused a fixture sized from those same \
             gates, so re-size the fixture; do not delete the assertion"
        );
        built.push(
            names
                .iter()
                .map(|n| (n.clone(), std::fs::read(dir.join(n)).unwrap()))
                .collect(),
        );
    }
    ntt_range::pin_transform_off_for_tests(false);
    assert_eq!(
        built[0], built[1],
        "the transform and the fold must write the same recovery set"
    );

    // And it repairs, which is the only thing that proves the exponents
    // the transform produced are the ones the repairer expects.
    let victim = t.0.join("ntt").join("payload.bin");
    let good = std::fs::read(&victim).unwrap();
    let mut broken = good.clone();
    let n = broken.len();
    broken[10_000..300_000].fill(0);
    broken[n - 50_000..].fill(0xff);
    std::fs::write(&victim, &broken).unwrap();
    let status = nzbkit_base::par2repair::repair_dir(&t.0.join("ntt")).expect("repair runs");
    assert!(
        matches!(status, nzbkit_base::par2repair::RepairStatus::Repaired(_)),
        "{status:?}"
    );
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        good,
        "victim not byte-exact"
    );
}

#[test]
fn the_band_route_writes_the_fold_s_bytes_at_a_real_block_size() {
    // The band route over copies (`par2gen/stripe_first.rs`, module doc
    // "Bands"; TODO 345 C) at the geometry a real set is built at - the
    // half `par2gen_create_ntt`'s band tests cannot afford per push, where
    // a 1,100-byte block is two stripes on two workers. 4,096 bytes is
    // four 512-word stripes over every core, and the band arena pinned to
    // ONE stripe of every slice makes four sweeps, so the chunk's offset
    // into the arena (`c - c0`) is exercised at every stripe rather than
    // only at zero.
    //
    // Map-off stands in for the fit gate, which reads the box's available
    // memory and cannot be set from here; the corpus pin stands in for a
    // payload over the copied transform's window. Every pin is lifted
    // however the test leaves. The fold arm is the reference, as in the
    // transform test above.
    struct Unpin;
    impl Drop for Unpin {
        fn drop(&mut self) {
            ntt_range::pin_transform_off_for_tests(false);
            ntt_range::pin_map_off_for_tests(false);
            ntt_range::pin_band_corpus_for_tests(0);
        }
    }
    let _serial = PROCESS_PINS.lock().unwrap_or_else(|e| e.into_inner());
    let _unpin = Unpin;
    let bs = 4_096u64;
    let (slices, rows) = ntt_range::floor_shape_for_tests(bs as usize);
    let t = Tmp::new("bandsreal");
    // The NAMES travel with the bytes, as in the transform test above.
    let mut built: Vec<Vec<(String, Vec<u8>)>> = Vec::new();
    for (tag, fold) in [("fold", true), ("bands", false)] {
        ntt_range::pin_transform_off_for_tests(fold);
        ntt_range::pin_map_off_for_tests(!fold);
        ntt_range::pin_band_corpus_for_tests(if fold { 0 } else { slices * 1024 });
        let dir = t.0.join(tag);
        std::fs::create_dir_all(&dir).unwrap();
        let members = vec![
            {
                let path = dir.join("payload.bin");
                std::fs::write(&path, payload((slices - 1) * bs as usize, 43)).unwrap();
                Member {
                    name: "payload.bin".into(),
                    path,
                }
            },
            {
                let path = dir.join("tail.bin");
                std::fs::write(&path, payload(bs as usize / 2, 44)).unwrap();
                Member {
                    name: "tail.bin".into(),
                    path,
                }
            },
        ];
        let cold0 = ntt_range::cold_builds_for_tests();
        let sweeps0 = ntt_range::band_sweeps_for_tests();
        let names =
            create_into_exact(&dir, &members, "set", Some(bs), rows, CreatePlan::ENGINE).unwrap();
        let cold = ntt_range::cold_builds_for_tests() - cold0;
        let swept = ntt_range::band_sweeps_for_tests() - sweeps0;
        let want = if fold { (0, 0) } else { (1, 4) };
        assert_eq!(
            (cold, swept),
            want,
            "the {tag} arm built {cold} plan(s) over {swept} band sweep(s) at {slices} inputs x \
             {rows} rows; the band arm must build ONE plan over four one-stripe sweeps - re-size \
             the fixture against the gates, do not delete the assertion"
        );
        built.push(
            names
                .iter()
                .map(|n| (n.clone(), std::fs::read(dir.join(n)).unwrap()))
                .collect(),
        );
    }
    assert_eq!(
        built[0], built[1],
        "the band route and the fold must write the same recovery set"
    );

    // And it repairs, which is what proves the exponents are the ones the
    // repairer expects.
    let victim = t.0.join("bands").join("payload.bin");
    let good = std::fs::read(&victim).unwrap();
    let mut broken = good.clone();
    let n = broken.len();
    broken[10_000..300_000].fill(0);
    broken[n - 50_000..].fill(0xff);
    std::fs::write(&victim, &broken).unwrap();
    let status = nzbkit_base::par2repair::repair_dir(&t.0.join("bands")).expect("repair runs");
    assert!(
        matches!(status, nzbkit_base::par2repair::RepairStatus::Repaired(_)),
        "{status:?}"
    );
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        good,
        "victim not byte-exact"
    );
}

#[test]
fn the_reference_implementation_verifies_a_wide_set_we_wrote() {
    // The only assertion in this file that is not self-consistent: our
    // own parser and our own repair share this creator's understanding
    // of the spec, so they would pass a shared mistake together. At the
    // scale here - thousands of slices across several members -
    // par2cmdline is the only thing that can say the set is really a
    // PAR2 set.
    if !have_par2() {
        eprintln!("SKIP: no par2 binary on this box");
        return;
    }
    // The 0-byte member is asked for only where the reference can
    // answer for it. This is NOT a version floor on the test - the
    // five-member set below still puts ~2,000 slices, a partial tail
    // block on every member, a sub-block member and a nested path in
    // front of whatever par2 the box has, which is the interop this
    // file is for. What an old reference cannot grade is one shape, and
    // it says which one on the way past rather than quietly covering
    // less. See `par2_describes_empty_members` for the upstream defect
    // and the three-version measurement.
    let empty_member = par2_describes_empty_members();
    let version = par2_version();
    if !empty_member {
        eprintln!(
            "par2 {version:?} predates the empty-member fix (upstream #128, fixed 1.0.0): \
             grading the wide set WITHOUT its 0-byte member"
        );
    }
    let t = Tmp::new("interop");
    let members = wide_set(&t, empty_member);
    // par2cmdline verifies members relative to the PAR2 file's own
    // directory, so the set is written where the payload lives.
    let names = create_into(
        &t.0,
        &members,
        "big",
        &Par2Spec {
            redundancy_pct: 5,
            block_size: None,
        },
    )
    .unwrap();
    let out = Command::new("par2")
        .arg("verify")
        .arg(t.0.join(&names[0]))
        .current_dir(&t.0)
        .output()
        .expect("run par2");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "par2 {version:?} verify refused a set we wrote (empty member: {empty_member}):\n{text}"
    );
    // An exit of 0 is not on its own evidence that anything was graded:
    // par2 is happy to succeed over a set whose members it never
    // matched, so pin that every one of them was named and none was
    // reported missing. Without this the degraded arm above could grade
    // nothing at all and still read as interop.
    for m in &members {
        assert!(
            text.contains(m.name.as_str()),
            "par2 {version:?} never named {}:\n{text}",
            m.name
        );
        assert!(
            !text.contains(&format!("{}\" - missing", m.name)),
            "par2 {version:?} could not find {}:\n{text}",
            m.name
        );
    }
}
