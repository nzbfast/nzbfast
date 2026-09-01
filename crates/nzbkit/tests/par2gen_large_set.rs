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

use nzbkit::par2gen::{ACCUM_BUDGET_BYTES, Member, Par2Spec, create_into};

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
fn have_par2() -> bool {
    Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
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
fn wide_set(t: &Tmp) -> Vec<Member> {
    vec![
        t.write("VIDEO_TS/VTS_01_1.VOB", &payload(9_000_001, 1)),
        t.write("VIDEO_TS/VTS_01_2.VOB", &payload(8_500_003, 2)),
        t.write("VIDEO_TS/VTS_01_3.VOB", &payload(6_250_007, 3)),
        t.write("sample/sample.mkv", &payload(250_011, 4)),
        t.write("readme.nfo", &payload(913, 5)),
        t.write("VIDEO_TS/VIDEO_TS.BUP", b""),
    ]
}

#[test]
fn a_wide_set_at_the_creator_s_own_block_size_repairs_real_damage() {
    // The shape nothing else covers: six members, the block size the
    // creator PICKS rather than one chosen to force a code path, and
    // enough slices that the RS constant walk is at a real post's scale.
    let t = Tmp::new("wide");
    let members = wide_set(&t);
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
    let set = nzbkit::par2::Par2Set::parse(&refs).expect("our own parser reads our own set");
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

    let status = nzbkit::par2repair::repair_dir(&out).expect("repair runs");
    assert!(
        matches!(status, nzbkit::par2repair::RepairStatus::Repaired(_)),
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
    let per_batch = (ACCUM_BUDGET_BYTES / block).max(1) as usize;
    let blobs: Vec<Vec<u8>> = names
        .iter()
        .map(|n| std::fs::read(out.join(n)).unwrap())
        .collect();
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    let set = nzbkit::par2::Par2Set::parse(&refs).expect("parse");
    let n_recovery: usize = set.recovery_blocks_seen;
    assert!(
        n_recovery > per_batch,
        "fixture no longer crosses the budget: {n_recovery} recovery slices against a \
         {per_batch}-slice batch ({ACCUM_BUDGET_BYTES} B budget / {block} B block) - \
         re-size the fixture, do not delete the assertion"
    );

    // And it still repairs, which is the only thing that proves the
    // exponent bookkeeping stitched the passes together correctly.
    let victim = &members[1].path;
    let good = std::fs::read(victim).unwrap();
    let mut broken = good.clone();
    broken[0..(2 << 20)].fill(0);
    std::fs::write(victim, &broken).unwrap();
    let status = nzbkit::par2repair::repair_dir(&out).expect("repair runs");
    assert!(
        matches!(status, nzbkit::par2repair::RepairStatus::Repaired(_)),
        "{status:?}"
    );
    assert_eq!(std::fs::read(victim).unwrap(), good);
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
fn the_reference_implementation_verifies_a_wide_set_we_wrote() {
    // The only assertion in this file that is not self-consistent: our
    // own parser and our own repair share this creator's understanding
    // of the spec, so they would pass a shared mistake together. At the
    // scale here - thousands of slices across six members with a 0-byte
    // one among them - par2cmdline is the only thing that can say the
    // set is really a PAR2 set.
    if !have_par2() {
        eprintln!("SKIP: no par2 binary on this box");
        return;
    }
    let t = Tmp::new("interop");
    let members = wide_set(&t);
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
    assert!(
        out.status.success(),
        "par2 verify refused a set we wrote:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
