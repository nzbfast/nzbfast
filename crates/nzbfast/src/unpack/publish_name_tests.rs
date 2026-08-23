//! The PAR2 verified-name publish is a rename that REPLACES its target -
//! right for a previous run's copy, and silent data loss when the target
//! is a file this same job put there.
//!
//! Codex read-only sweep of 3 Aug 2026 listed "sanitized output-name
//! collisions can still overwrite on disk" among three older items it
//! rechecked and left undispositioned. Re-derived 23 Aug 2026: the
//! sanitizer itself is the wrong place to look (it is many-to-one by
//! design, and every OTHER consumer of a posted name already dedupes -
//! `Extractor::claim_name` for output files, the journal's `used_names`
//! for `S` lines). `publish_verified_name` was the one path that chose an
//! output path with no claim at all.
//!
//! Both shapes below leave one file where two payloads were, with both
//! publishes reporting success.

use super::*;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-pubname-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Every byte written into `dir`, by content, so an assertion can say
/// "both payloads are still here" without caring which name each wears.
fn payloads(dir: &std::path::Path) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    v.sort();
    v
}

/// `sanitize_filename` is many-to-one: a PAR2 FileDesc name is
/// poster-typed bytes, and `sub/movie.mkv` and `sub_movie.mkv` are two
/// legal, distinct set members that map to one on-disk name. Publishing
/// both renamed the second over the first.
#[test]
fn two_verified_names_that_sanitize_alike_keep_both_payloads() {
    let dir = temp_dir("sanitize");
    std::fs::write(dir.join("aaa.bin"), b"FIRST").unwrap();
    std::fs::write(dir.join("bbb.bin"), b"SECOND").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    let a = publish_verified_name(&dir.join("aaa.bin"), "sub/movie.mkv", &dir, 0, &mut taken);
    let b = publish_verified_name(&dir.join("bbb.bin"), "sub_movie.mkv", &dir, 1, &mut taken);
    assert_eq!(
        a.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        Some("sub_movie.mkv".to_string()),
        "the first claimant must get the plain name"
    );
    assert_eq!(
        b.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        Some("001-sub_movie.mkv".to_string()),
        "the second must be pushed off it, in the extractor's own form"
    );
    assert_eq!(
        payloads(&dir),
        vec![b"FIRST".to_vec(), b"SECOND".to_vec()],
        "a payload was renamed over"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// No sanitizer involved: on a case-insensitive volume `README.nfo` and
/// `readme.nfo` name ONE filesystem object, and a set built on a
/// case-sensitive box carries both names legitimately. This is the shape
/// an ordinary release can hit without any crafting at all.
///
/// Asserted by PAYLOAD rather than by name, so it means the same thing on
/// case-sensitive Linux CI (where the two are distinct files and neither
/// is renamed) and on the case-insensitive Mac and Windows boxes - the
/// trap `name_collision_key` and `case_probe_agrees_with_the_real_filesystem`
/// were both written for.
#[test]
fn two_verified_names_differing_only_in_case_keep_both_payloads() {
    let dir = temp_dir("case");
    std::fs::write(dir.join("aaa.bin"), b"FIRST").unwrap();
    std::fs::write(dir.join("bbb.bin"), b"SECOND").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    publish_verified_name(&dir.join("aaa.bin"), "README.nfo", &dir, 0, &mut taken);
    publish_verified_name(&dir.join("bbb.bin"), "readme.nfo", &dir, 1, &mut taken);
    assert_eq!(
        payloads(&dir),
        vec![b"FIRST".to_vec(), b"SECOND".to_vec()],
        "a payload was renamed over"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The seed half: a slot that simply KEPT its posted name owns that name,
/// so another slot's verified name is pushed off it. Without the seed the
/// deobfuscation rename replaced a perfectly good file that no PAR2 pass
/// had asked it to touch.
#[test]
fn a_seeded_slot_name_is_not_renamed_over() {
    let dir = temp_dir("seed");
    std::fs::write(dir.join("movie.mkv"), b"POSTED-NAME-PAYLOAD").unwrap();
    std::fs::write(dir.join("0Bf3qZ.bin"), b"OBFUSCATED-PAYLOAD").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    taken.seed(0, "movie.mkv");
    let b = publish_verified_name(&dir.join("0Bf3qZ.bin"), "movie.mkv", &dir, 1, &mut taken);
    assert_eq!(
        b.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        Some("001-movie.mkv".to_string()),
    );
    assert_eq!(
        payloads(&dir),
        vec![
            b"OBFUSCATED-PAYLOAD".to_vec(),
            b"POSTED-NAME-PAYLOAD".to_vec()
        ],
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The exemption that must SURVIVE the fix: a previous run's copy at the
/// real name is replaced, because the bytes this run just PAR2-verified
/// are the authoritative ones. Nothing in this job claimed that name, so
/// nothing pushes the publish off it.
#[test]
fn a_previous_runs_copy_is_still_replaced() {
    let dir = temp_dir("prev");
    std::fs::write(dir.join("movie.mkv"), b"STALE-PREVIOUS-RUN").unwrap();
    std::fs::write(dir.join("0Bf3qZ.bin"), b"VERIFIED").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    let p = publish_verified_name(&dir.join("0Bf3qZ.bin"), "movie.mkv", &dir, 0, &mut taken);
    assert_eq!(
        p.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        Some("movie.mkv".to_string()),
    );
    assert_eq!(payloads(&dir), vec![b"VERIFIED".to_vec()]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A slot already sitting at its verified name claims it and publishes
/// nothing - and the claim still binds, so a LATER slot of the same job
/// cannot rename over it.
#[test]
fn a_no_op_publish_still_claims_the_name() {
    let dir = temp_dir("noop");
    std::fs::write(dir.join("movie.mkv"), b"ALREADY-RIGHT").unwrap();
    std::fs::write(dir.join("other.bin"), b"SECOND").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    assert!(
        publish_verified_name(&dir.join("movie.mkv"), "movie.mkv", &dir, 0, &mut taken).is_none(),
        "nothing to rename"
    );
    publish_verified_name(&dir.join("other.bin"), "movie.mkv", &dir, 1, &mut taken);
    assert_eq!(
        payloads(&dir),
        vec![b"ALREADY-RIGHT".to_vec(), b"SECOND".to_vec()],
    );
    let _ = std::fs::remove_dir_all(&dir);
}
