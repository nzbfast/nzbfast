//! Claim `proven-spent-majority-bar`, measured 31 Aug 2026: what
//! [`super::proven_spent`]'s damaged-twin arm can and cannot decide.
//!
//! `research/PROVEN-SPENT-MAJORITY-2026-08-31.md` leaves one question
//! open - is `fed_by_ci * 2 > t.n_slices` the right bar for a WHOLLY
//! MISSING target, where the arm performs zero byte comparisons and the
//! whole test degenerates to a slice count? - and says to price it
//! before moving anything. These pins are that pricing. They are
//! deliberately pins on the SHIPPED rule rather than a change to it:
//! what they establish is that the bar cannot be improved with the
//! evidence this function is given, so moving it is not a tuning
//! question at all.
//!
//! THE ARITHMETIC. Per slice of a same-length target the arm classifies
//! four ways: fed by THIS candidate at this offset (`F`, proof by
//! construction), fed by ANOTHER candidate (`O`, byte-compared),
//! PRESENT pre-repair (`P`, byte-compared against `t.path`), or in
//! `rebuilt_set` (`R`, `continue` - never read). `F + O + P + R = n`,
//! and the candidate is proven over `(n - R)` slices.
//!
//! On a wholly missing target - the class that turns adoption on in the
//! first place - `t.path` holds nothing to compare against, so every
//! slice is in `F` or in `R` and `R = n - F` exactly. A tightening to
//! "prove the CANDIDATE rather than a majority of the TARGET", which is
//! the direction the write-up names, is `R = 0`; on this class that is
//! `F = n`, which is the FULLY-DONATED arm below it firing on its own.
//! So on the only class where the majority rule is weak there is no
//! middle setting: the choice is today's bar or no twin arm at all, and
//! no twin arm is finding F9 again - a damaged twin cannot feed every
//! slice, being damaged is the difference.
//!
//! WHY NO FUNCTION OF THE COUNTS HELPS EITHER, which is the sharper
//! half and is what `a_mixed_donor_and_a_damaged_twin_are_one_input`
//! demonstrates rather than argues: the arm never READS the `R` slices,
//! so a genuine damaged twin and a donor carrying a NEIGHBOURING set's
//! payload can be byte-different exactly there and identical in every
//! value this function receives. They are one input. No bar over those
//! inputs can separate them, and a bar is all this seam has.
//!
//! WHAT WOULD SEPARATE THEM is evidence from outside this set - whether
//! those bytes are somebody else's declared payload - which is
//! `DirContext`'s business and is claim `latesets-empty-dircontext`,
//! open and held elsewhere. That is also why X5-10 fixed the sweep's
//! TIMING rather than this bar. Do not tune the two in opposite
//! directions; the write-up says so from its side too.

use super::*;

const BS: usize = 64;
const N: usize = 8;
const LEN: u64 = (BS * N) as u64;
/// Slices donated by the candidate under test: 5 of 8 clears
/// `fed_by_ci * 2 > n_slices` with the smallest margin the rule allows.
const FED: usize = 5;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-adoptspend-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn bytes(seed: u8, n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| seed.wrapping_mul(31).wrapping_add(i as u8))
        .collect()
}

/// A target of `LEN` bytes at `path`. `exists` false is the wholly
/// missing shape; true with `present` set is a target the verify found
/// on disk, which is what makes the byte-comparing arms reachable.
fn target(path: PathBuf, exists: bool, present: Vec<bool>) -> Target {
    Target {
        file: Par2File {
            file_id: [3u8; 16],
            name: "a.bin".into(),
            length: LEN,
            md5: [0u8; 16],
            md5_16k: [0u8; 16],
            blocks: Vec::new(),
        },
        path,
        first_slice: 0,
        n_slices: N,
        present,
        intact: false,
        exists,
        resume: None,
    }
}

/// Slices `0..FED` donated by candidate 0 at their own offsets.
fn donated() -> HashMap<usize, AdoptSrc> {
    (0..FED)
        .map(|li| {
            (
                li,
                AdoptSrc {
                    cand: 0,
                    offset: (li as u64) * BS as u64,
                },
            )
        })
        .collect()
}

/// THE MEASUREMENT. Two candidates that differ only in the bytes the
/// arm never reads - one a damaged twin, one a donor whose tail is a
/// neighbouring set's payload - and one verdict between them.
///
/// The tail is rewritten in place three times with the candidate table,
/// the adoption map and the target all held fixed, so the assertion is
/// not "these two fixtures agree" but "this input does not include
/// those bytes at all". That is what makes any re-tuning of
/// `fed_by_ci * 2 > t.n_slices` futile rather than merely risky: the
/// counts are equal because the evidence is equal.
#[test]
fn a_mixed_donor_and_a_damaged_twin_are_one_input() {
    let dir = tmpdir("oneinput");
    // Wholly missing: no file at t.path, so the `None` arm can only be
    // reached through `rebuilt_set` - the zero-read path.
    let t = [target(dir.join("a.bin"), false, vec![false; N])];
    let adopted = donated();
    let rebuilt: HashSet<usize> = (FED..N).collect();
    let cand = dir.join("cand.bin");
    let cands = [(cand.clone(), LEN)];

    let head = bytes(11, BS * FED);
    let mut verdicts = Vec::new();
    for tail_seed in [11u8, 200u8, 77u8] {
        let mut c = head.clone();
        c.extend_from_slice(&bytes(tail_seed, BS * (N - FED)));
        std::fs::write(&cand, &c).unwrap();
        verdicts.push(proven_spent(
            &cand, LEN, 0, &t, &adopted, &rebuilt, &cands, BS,
        ));
    }
    assert_eq!(
        verdicts,
        vec![true, true, true],
        "the twin arm answered on the donated slices alone; three different \
         tails - a twin's damage, a neighbour's payload, junk in no target \
         at all - are one input to it, so no threshold over these counts \
         can tell them apart"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The CONTROL, and the reason the pin above is not vacuous. Give the
/// arm slices it CAN read - a target the verify found on disk, so the
/// unfed slices take the `present` arm instead of `rebuilt_set` - and
/// the same three tails stop being one input: the matching one is a
/// twin and the other two are refused.
#[test]
fn the_same_tails_are_three_inputs_once_the_arm_may_read_them() {
    let dir = tmpdir("readable");
    let path = dir.join("a.bin");
    let head = bytes(11, BS * FED);
    let mut on_disk = head.clone();
    on_disk.extend_from_slice(&bytes(11, BS * (N - FED)));
    std::fs::write(&path, &on_disk).unwrap();
    let mut present = vec![false; N];
    present[FED..].fill(true);
    let t = [target(path, true, present)];
    let adopted = donated();
    let rebuilt: HashSet<usize> = HashSet::new();
    let cand = dir.join("cand.bin");
    let cands = [(cand.clone(), LEN)];

    let mut verdicts = Vec::new();
    for tail_seed in [11u8, 200u8, 77u8] {
        let mut c = head.clone();
        c.extend_from_slice(&bytes(tail_seed, BS * (N - FED)));
        std::fs::write(&cand, &c).unwrap();
        verdicts.push(proven_spent(
            &cand, LEN, 0, &t, &adopted, &rebuilt, &cands, BS,
        ));
    }
    assert_eq!(
        verdicts,
        vec![true, false, false],
        "with the unfed slices readable the arm discriminates, which is \
         what the majority rule is standing in for when it cannot"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the pricing: the tightening the write-up names -
/// prove the CANDIDATE, not a majority of the TARGET - is `R = 0`, and
/// on a wholly missing target that is `F = n`. So it does not narrow
/// the twin arm, it deletes it: the shape F9 exists for stops being
/// proven at all, while the shape it would still admit is the
/// fully-donated arm's own and is already proven one arm down.
#[test]
fn proving_the_candidate_would_leave_the_twin_arm_with_nothing_to_do() {
    let dir = tmpdir("wholecover");
    let t = [target(dir.join("a.bin"), false, vec![false; N])];
    let cand = dir.join("cand.bin");
    let cands = [(cand.clone(), LEN)];
    std::fs::write(&cand, bytes(11, BS * N)).unwrap();

    // A damaged twin: it donated a majority and NOT everything, because
    // the blocks it did not donate are the ones the damage cost it.
    let rebuilt: HashSet<usize> = (FED..N).collect();
    assert!(
        proven_spent(&cand, LEN, 0, &t, &donated(), &rebuilt, &cands, BS),
        "today's bar proves the twin"
    );
    // The same candidate with every slice donated - `R = 0`, the only
    // way a coverage bar is satisfied here. The FULLY-DONATED arm below
    // reaches this on its own, with merged span coverage of the whole
    // candidate and no majority rule involved.
    let all: HashMap<usize, AdoptSrc> = (0..N)
        .map(|li| {
            (
                li,
                AdoptSrc {
                    cand: 0,
                    offset: (li as u64) * BS as u64,
                },
            )
        })
        .collect();
    assert!(
        proven_spent(&cand, LEN, 0, &t, &all, &HashSet::new(), &cands, BS),
        "a wholly donated candidate is proven without the twin arm, so a \
         coverage bar on the twin arm is the twin arm deleted"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
