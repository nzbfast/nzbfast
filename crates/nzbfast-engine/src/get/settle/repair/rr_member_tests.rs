//! Read-only sweep A2 (9 Nov 2026): what the RAR recovery-record rung's
//! `Ok` may and may not speak for.
//!
//! A CHILD of `repair.rs` for the same size-gate reason `band_tests.rs`
//! gives. What is pinned here is [`rr_unhealed_members`], the predicate
//! the rung's `Ok` arm now consults before it sets `all_good`. The arm
//! itself needs a whole settle (servers, a verifier, a damaged posted set)
//! to reach; the end-to-end shape - a RAR set plus a set-covered plain file
//! that lost an article, on a post whose parity is short - is the e2e
//! fixture this predicate still wants in `crates/nzbfast/tests`.

use super::*;
use md5::Digest as _;

fn scratch(tag: &str) -> crate::testscratch::ScratchDir {
    let d = std::env::temp_dir().join(format!("nzbfast-rrmember-{tag}-{}", std::process::id()));
    crate::testscratch::ScratchDir::attach(&d)
}

fn desc(name: &str, whole: &[u8]) -> nzbkit::par2::Par2File {
    nzbkit::par2::Par2File {
        file_id: [0u8; 16],
        name: name.to_string(),
        length: whole.len() as u64,
        md5: md5::Md5::digest(whole).into(),
        md5_16k: md5::Md5::digest(&whole[..whole.len().min(16 * 1024)]).into(),
        blocks: Vec::new(),
    }
}

fn set(files: Vec<nzbkit::par2::Par2File>) -> nzbkit::par2::Par2Set {
    nzbkit::par2::Par2Set {
        comment: None,
        recovery_set_id: [0u8; 16],
        block_size: 4096,
        files,
        nonrecovery: Vec::new(),
        undescribed: Vec::new(),
        recovery_blocks_seen: 0,
    }
}

fn report(name: Option<&str>, bad: &[usize], length: u64) -> nzbkit::live::SlotReport {
    nzbkit::live::SlotReport {
        par2_name: name.map(str::to_string),
        total_blocks: 4,
        bad_blocks: bad.to_vec(),
        live_blocks: 0,
        readback_blocks: 0,
        length,
        prefix_md5: None,
    }
}

fn names(v: &[&str]) -> std::collections::HashSet<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// The defect: a RAR set the rung extracted, plus a set-covered plain file
/// whose report carries a bad block and whose bytes on disk are still
/// holed. The volume is the rung's to vouch for; the plain file is not,
/// and it must come back as unhealed - before this predicate existed the
/// arm answered `true` for this exact state.
#[test]
fn a_damaged_plain_member_the_rung_never_walked_is_unhealed() {
    let d = scratch("plain");
    let good = vec![7u8; 16_000];
    let mut holed = good.clone();
    holed[4096..8192].fill(0);
    std::fs::write(d.join("sample.mkv"), &holed).unwrap();
    std::fs::write(d.join("movie.part01.rar"), b"volume").unwrap();
    let s = set(vec![
        desc("sample.mkv", &good),
        desc("movie.part01.rar", b"volume"),
    ]);
    let reports = vec![
        (0, report(Some("sample.mkv"), &[1], 16_000)),
        (1, report(Some("movie.part01.rar"), &[0], 6)),
    ];
    let left = rr_unhealed_members(
        &[&s],
        &reports,
        &names(&["movie.part01.rar"]),
        &[],
        &d,
        |_| None,
    );
    assert_eq!(left, vec!["sample.mkv".to_string()]);
}

/// The guards against a false RED. A damaged report whose file now reads
/// back byte-exact (a member the failed repair published whole anyway, or
/// one the second-entry fill healed after the reports were taken), and a
/// member another set's repair already proved, are both whole and must not
/// fail the job.
#[test]
fn a_member_proved_by_its_md5_or_by_another_set_is_not_unhealed() {
    let d = scratch("proved");
    let good = vec![9u8; 12_000];
    std::fs::write(d.join("extras.mkv"), &good).unwrap();
    let s = set(vec![desc("extras.mkv", &good), desc("other.nfo", b"x")]);
    let reports = vec![
        (0, report(Some("extras.mkv"), &[2], 12_000)),
        (1, report(Some("other.nfo"), &[0], 1)),
    ];
    let left = rr_unhealed_members(
        &[&s],
        &reports,
        &names(&[]),
        &["other.nfo".to_string()],
        &d,
        |_| None,
    );
    assert!(left.is_empty(), "{left:?}");
}

/// A clean report has nothing to heal, and a report that names no
/// FileDesc has no MD5 to be held to - both stay out of the list, as they
/// stay out of the rung's own hint.
#[test]
fn clean_and_unnamed_reports_are_not_judged() {
    let d = scratch("clean");
    let s = set(vec![desc("a.bin", b"aaaa")]);
    let reports = vec![
        (0, report(Some("a.bin"), &[], 4)),
        (1, report(None, &[0, 1], 0)),
    ];
    let left = rr_unhealed_members(&[&s], &reports, &names(&[]), &[], &d, |_| None);
    assert!(left.is_empty(), "{left:?}");
}

/// A RAR volume still sitting under its POSTED name (a GH #63 deferral
/// kept the honest subject over a hash FileDesc) is matched by its slot's
/// live path, so the extraction's proof reaches it exactly as it reaches
/// a volume under its FileDesc name.
#[test]
fn a_volume_under_its_posted_name_is_the_rungs_to_vouch_for() {
    let d = scratch("posted");
    let live = d.join("movie.part02.rar");
    std::fs::write(&live, b"vol2").unwrap();
    let s = set(vec![desc("c238183c9ea852006dbc09ffa6a26e98", b"vol2-good")]);
    let reports = vec![(3, report(Some("c238183c9ea852006dbc09ffa6a26e98"), &[0], 9))];
    let left = rr_unhealed_members(
        &[&s],
        &reports,
        &names(&["movie.part02.rar"]),
        &[],
        &d,
        |i| (i == 3).then(|| live.clone()),
    );
    assert!(left.is_empty(), "{left:?}");
}
