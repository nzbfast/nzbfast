//! Unit pins for the volume-payload rescue's SCREEN - the half that
//! decides what wire it is allowed to spend, and the half a wrong band
//! makes silently useless (nothing selected, no rescue, and a log line
//! nobody reads because it never prints).
//!
//! The end-to-end proof is `e2e_norar::polyglot`'s
//! `a_payload_posted_under_a_recovery_volume_name_is_rescued` and its
//! two control arms; these pin the arithmetic those cannot reach
//! cheaply - the exclusions, the budget, and the fixture's own measured
//! sizes.

use super::*;
use nzbkit::par2::{Par2File, Par2Set};

fn desc(name: &str, length: u64) -> Par2File {
    Par2File {
        file_id: [0u8; 16],
        name: name.to_string(),
        length,
        md5: [0u8; 16],
        md5_16k: [0u8; 16],
        blocks: Vec::new(),
    }
}

/// An NZB of one-segment files: the screen reads only the subject and
/// the declared byte total, so a single segment says everything it asks.
fn nzb_of(files: &[(&str, u64)]) -> Nzb {
    let mut nzb = Nzb {
        files: Vec::new(),
        meta: Vec::new(),
    };
    for (i, (subject, bytes)) in files.iter().enumerate() {
        nzb.files.push(nzbkit::nzb::NzbFile {
            subject: (*subject).to_string(),
            segments: vec![nzbkit::nzb::Segment {
                bytes: *bytes,
                number: 1,
                message_id: format!("m{i}"),
            }],
            ..Default::default()
        });
    }
    nzb
}

/// A scratch directory of this case's own. Named for the case rather
/// than for the process, the convention `shortfall_gate_tests` states:
/// these run in one process alongside ~1750 others and a pid-only name
/// is one directory two cases share.
fn scratch(tag: &str) -> crate::testscratch::ScratchDir {
    crate::testscratch::ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbfast-volpayload-{tag}-{}", std::process::id())),
    )
}

fn set_of(files: Vec<Par2File>) -> Par2Set {
    Par2Set {
        recovery_set_id: [0u8; 16],
        block_size: 76,
        files,
        nonrecovery: Vec::new(),
        recovery_blocks_seen: 0,
    }
}

/// THE MEASURED FIXTURE, and the case the whole module exists for: a
/// 150,000-byte payload posted as `abc123.vol000+50.par2` declares
/// 155,281 wire bytes (+3.52%), and the nine real volumes of the set
/// beside it declare 41,540 through 350,106. Only the phantom is in the
/// band, so only the phantom is bought.
///
/// The figures are not invented - they come off the origin/main
/// reproduction on 31 Aug 2026, printed out of `recovery_candidates`.
#[test]
fn the_measured_fixture_admits_the_phantom_and_none_of_the_nine_real_volumes() {
    let mut names: Vec<(String, u64)> = vec![("abc123.vol000+50.par2".to_string(), 155_281)];
    for (i, b) in [
        41_540u64, 82_696, 124_289, 166_038, 208_362, 251_872, 297_748, 348_382, 350_106,
    ]
    .into_iter()
    .enumerate()
    {
        names.push((format!("testset.vol{i:03}+01.par2"), b));
    }
    let refs: Vec<(&str, u64)> = names.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    let nzb = nzb_of(&refs);
    let d = desc("Vol.Subject.mkv", 150_000);
    let absent = vec![&d];
    assert_eq!(
        payload_shaped_volumes(&nzb, &[], &absent),
        vec![0],
        "the band must admit the payload-shaped volume and nothing else"
    );
}

/// A set with nothing missing spends nothing, whatever the NZB carries.
/// This is the arithmetic behind the e2e control arm: on a healthy post
/// there is no absent FileDesc, so the screen returns before it looks at
/// a single NZB file.
#[test]
fn nothing_absent_buys_nothing() {
    let nzb = nzb_of(&[("abc123.vol000+50.par2", 155_281)]);
    assert!(payload_shaped_volumes(&nzb, &[], &[]).is_empty());
}

/// A file the NZB does not call a recovery volume is not this module's
/// business however well it fits: a payload slot already has a slot, and
/// every rescue in `get/settle.rs` can reach it.
#[test]
fn only_volumes_are_candidates() {
    let nzb = nzb_of(&[("abc123.mkv", 155_281), ("abc123.par2", 155_281)]);
    let d = desc("Vol.Subject.mkv", 150_000);
    assert!(payload_shaped_volumes(&nzb, &[], &[&d]).is_empty());
}

/// Bytes already on disk are never bought again - the same rule
/// `recovery_candidates` applies, and what keeps an elected bootstrap
/// volume out of this on every path that records one.
#[test]
fn an_already_fetched_volume_is_not_bought_again() {
    let nzb = nzb_of(&[("abc123.vol000+50.par2", 155_281)]);
    let d = desc("Vol.Subject.mkv", 150_000);
    assert!(payload_shaped_volumes(&nzb, &[0], &[&d]).is_empty());
}

/// The band is two-sided, and both sides are load-bearing. yEnc never
/// shrinks, so a volume declaring far LESS than the missing length
/// cannot hold it; and a volume declaring far more is recovery data
/// sized by its own block count, not a copy of one file.
#[test]
fn the_band_refuses_both_directions() {
    let d = desc("Vol.Subject.mkv", 1_000_000);
    let absent = vec![&d];
    // 10% under: no yEnc encoding produces this.
    let under = nzb_of(&[("a.vol000+01.par2", 900_000)]);
    assert!(payload_shaped_volumes(&under, &[], &absent).is_empty());
    // 25% over: outside anything a posting tool's overhead explains.
    let over = nzb_of(&[("a.vol000+01.par2", 1_250_000)]);
    assert!(payload_shaped_volumes(&over, &[], &absent).is_empty());
    // The measured 3.5%, and the outer edges of the band itself.
    for b in [
        encoded_lower(1_000_000),
        1_035_200,
        encoded_upper(1_000_000),
    ] {
        let ok = nzb_of(&[("a.vol000+01.par2", b)]);
        assert_eq!(
            payload_shaped_volumes(&ok, &[], &absent),
            vec![0],
            "{b} should be inside the band"
        );
    }
}

/// THE BUDGET IS THE COST STATEMENT and it has to bite: this rescue may
/// never spend more wire than the payload it is trying to rescue is
/// worth. Four in-band candidates against ONE missing 1 MB file buys
/// one of them, cheapest first, not four.
#[test]
fn the_budget_caps_what_a_swarm_of_in_band_volumes_can_cost() {
    let d = desc("Vol.Subject.mkv", 1_000_000);
    let absent = vec![&d];
    let nzb = nzb_of(&[
        ("a.vol000+01.par2", 1_060_000),
        ("b.vol000+01.par2", 1_030_000),
        ("c.vol000+01.par2", 1_040_000),
        ("d.vol000+01.par2", 1_050_000),
    ]);
    let got = payload_shaped_volumes(&nzb, &[], &absent);
    assert_eq!(
        got,
        vec![1],
        "cheapest first, and only what the budget buys"
    );
    let spent: u64 = got.iter().fold(0, |a, &fi| a + nzb.files[fi].bytes());
    assert!(
        spent <= encoded_upper(1_000_000),
        "spent {spent} over a budget of {}",
        encoded_upper(1_000_000)
    );
}

/// Two missing files raise the budget, so a post that really did lose
/// two members can still probe two candidates. The budget is a function
/// of what is at stake and not a fixed cap.
#[test]
fn two_missing_files_raise_the_budget_to_match() {
    let d1 = desc("one.mkv", 1_000_000);
    let d2 = desc("two.mkv", 1_000_000);
    let absent = vec![&d1, &d2];
    let nzb = nzb_of(&[
        ("a.vol000+01.par2", 1_030_000),
        ("b.vol000+01.par2", 1_040_000),
    ]);
    assert_eq!(payload_shaped_volumes(&nzb, &[], &absent), vec![0, 1]);
}

/// `absent_files` asks about the name the SET declares, sanitized the
/// way everything downstream writes it - a file present under that name
/// is not absent, and a set member with nothing there is.
#[test]
fn absent_is_decided_at_the_declared_name() {
    let dir = scratch("declared-name");
    std::fs::write(dir.join("here.mkv"), b"x").unwrap();
    let set = set_of(vec![desc("here.mkv", 1), desc("gone.mkv", 150_000)]);
    let absent = absent_files(&dir, &set);
    assert_eq!(absent.len(), 1);
    assert_eq!(absent[0].name, "gone.mkv");
}

/// A zero-length FileDesc is excluded outright: there is no band around
/// zero and nothing to rescue, and admitting it would make every volume
/// in the post a candidate through the lower bound.
#[test]
fn a_zero_length_member_is_not_something_to_rescue() {
    let dir = scratch("zero-length");
    let set = set_of(vec![desc("empty.bin", 0)]);
    assert!(absent_files(&dir, &set).is_empty());
}

/// The proof is CONTENT and never length alone, which is what keeps a
/// damaged or foreign candidate out. Same evidence M4-28 uses: the exact
/// declared length plus the FileDesc's md5-16k over the first 16 KiB.
#[test]
fn identify_needs_the_head_hash_as_well_as_the_length() {
    let dir = scratch("identify");
    let body: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let p = dir.join("candidate.bin");
    std::fs::write(&p, &body).unwrap();
    let h = nzbkit::par2::md5_16k_of_head(&body, body.len() as u64).unwrap();

    let mut right = desc("Real.mkv", body.len() as u64);
    right.md5_16k = h;
    assert_eq!(
        identify(&p, &[&right]).map(|d| d.name.as_str()),
        Some("Real.mkv")
    );

    // Right length, wrong head: a different file that happens to be the
    // same size, or the same file with a damaged head.
    let mut wrong_head = desc("Other.mkv", body.len() as u64);
    wrong_head.md5_16k = [7u8; 16];
    assert!(identify(&p, &[&wrong_head]).is_none());

    // Right head, wrong length: a truncated candidate.
    let mut wrong_len = desc("Short.mkv", body.len() as u64 + 1);
    wrong_len.md5_16k = h;
    assert!(identify(&p, &[&wrong_len]).is_none());

    assert!(identify(&dir.join("nope.bin"), &[&right]).is_none());
}

/// The L1 residue (31 Aug 2026): PUBLISHED and LEFT BEHIND are
/// complements, and the caller reports the second set to the failing
/// job's quarantine.
///
/// Pinned here rather than only end to end because
/// [`publish_if_payload`] has FIVE ways out and only one of them is a
/// publish. Nothing else can see the other four: the fetched candidate
/// has no slot (`build_fetch_plan` skips a non-bootstrap `Par2Volume`
/// before a slot exists, the whole reason this module exists) and it was
/// never extracted, so `quarantine_failed_payload`'s two other arms are
/// blind to it and a bare `false` here means a file left wearing an
/// importable name on a failed job.
#[test]
fn a_candidate_is_published_or_it_is_left_behind_and_never_neither() {
    let dir = scratch("publish");
    let body: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let h = nzbkit::par2::md5_16k_of_head(&body, body.len() as u64).unwrap();
    let mut want = desc("Real.mkv", body.len() as u64);
    want.md5_16k = h;

    // DECLINED by the content proof - the case the measurement observed.
    let junk = dir.join("set.vol007+008.par2");
    std::fs::write(&junk, vec![9u8; body.len()]).unwrap();
    let mut rescued: Vec<String> = Vec::new();
    assert!(!publish_if_payload(&junk, &[&want], &dir, &mut rescued));
    assert!(rescued.is_empty());
    // Not deleted: the bytes are what the quarantine keeps.
    assert!(junk.exists());

    // PROVED and published, so the file is gone from the yEnc name and
    // is at the one the set gives it.
    let cand = dir.join("set.vol000+050.par2");
    std::fs::write(&cand, &body).unwrap();
    assert!(publish_if_payload(&cand, &[&want], &dir, &mut rescued));
    assert_eq!(rescued, vec!["Real.mkv".to_string()]);
    assert!(!cand.exists());
    assert_eq!(std::fs::read(dir.join("Real.mkv")).unwrap(), body);

    // PROVED and NOT publishable, twice over: the name is taken (by the
    // publish above), and the name has already been rescued this pass.
    // Both leave the bytes at the yEnc name, so both are left behind.
    let dup = dir.join("set.vol100+050.par2");
    std::fs::write(&dup, &body).unwrap();
    assert!(!publish_if_payload(&dup, &[&want], &dir, &mut rescued));
    assert!(dup.exists());
    assert_eq!(rescued.len(), 1, "a second copy must not re-report a name");
    let taken = dir.join("set.vol200+050.par2");
    std::fs::write(&taken, &body).unwrap();
    assert!(!publish_if_payload(&taken, &[&want], &dir, &mut Vec::new()));
    assert!(taken.exists());
}
