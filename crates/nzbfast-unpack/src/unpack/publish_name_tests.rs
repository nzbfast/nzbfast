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

fn temp_dir(tag: &str) -> crate::testscratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-pubname-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    crate::testscratch::ScratchDir::attach(&dir)
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

/// `sanitize_out_name` is many-to-one: a PAR2 FileDesc name is
/// poster-typed bytes, and `sub//movie.mkv` (empty component, so the
/// flatten fallback owns it) and `sub__movie.mkv` are two legal,
/// distinct set members that map to one on-disk name. Publishing both
/// renamed the second over the first.
#[test]
fn two_verified_names_that_sanitize_alike_keep_both_payloads() {
    let dir = temp_dir("sanitize");
    std::fs::write(dir.join("aaa.bin"), b"FIRST").unwrap();
    std::fs::write(dir.join("bbb.bin"), b"SECOND").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    let a = publish_verified_name(&dir.join("aaa.bin"), "sub//movie.mkv", &dir, 0, &mut taken);
    let b = publish_verified_name(&dir.join("bbb.bin"), "sub__movie.mkv", &dir, 1, &mut taken);
    assert_eq!(
        a.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        Some("sub__movie.mkv".to_string()),
        "the first claimant must get the plain name"
    );
    assert_eq!(
        b.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        Some("001-sub__movie.mkv".to_string()),
        "the second must be pushed off it, in the extractor's own form"
    );
    assert_eq!(
        payloads(&dir),
        vec![b"FIRST".to_vec(), b"SECOND".to_vec()],
        "a payload was renamed over"
    );
}

/// Tree preservation (the relpath-preserve ruling, 29 Aug 2026): a
/// provably safe FileDesc
/// path publishes INTO its directory - the whole point of the ruling is
/// that `VIDEO_TS/VTS_01_1.VOB` has to land as a tree to play - and a
/// second publish of the same path is pushed off it with the
/// disambiguating prefix on the whole relative name.
#[test]
fn a_safe_filedesc_path_publishes_as_a_tree() {
    let dir = temp_dir("tree");
    std::fs::write(dir.join("aaa.bin"), b"FIRST").unwrap();
    std::fs::write(dir.join("bbb.bin"), b"SECOND").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    let a = publish_verified_name(
        &dir.join("aaa.bin"),
        "VIDEO_TS/VTS_01_1.VOB",
        &dir,
        0,
        &mut taken,
    );
    assert_eq!(
        a.as_deref(),
        Some(dir.join("VIDEO_TS").join("VTS_01_1.VOB").as_path()),
        "the safe path must keep its tree"
    );
    assert_eq!(
        std::fs::read(dir.join("VIDEO_TS").join("VTS_01_1.VOB")).unwrap(),
        b"FIRST"
    );
    let b = publish_verified_name(
        &dir.join("bbb.bin"),
        "VIDEO_TS\\VTS_01_1.VOB",
        &dir,
        1,
        &mut taken,
    );
    assert_eq!(
        b.as_deref(),
        Some(dir.join("001-VIDEO_TS").join("VTS_01_1.VOB").as_path()),
        "the second claimant of one tree path is pushed off it"
    );
    assert_eq!(
        std::fs::read(dir.join("001-VIDEO_TS").join("VTS_01_1.VOB")).unwrap(),
        b"SECOND"
    );
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
}

/// Every byte under `dir` RECURSIVELY, by content - the tree rows below
/// land payload inside subdirectories, which `payloads` cannot see.
fn payloads_deep(dir: &std::path::Path) -> Vec<Vec<u8>> {
    fn walk(d: &std::path::Path, v: &mut Vec<Vec<u8>>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, v);
            } else {
                v.push(std::fs::read(&p).unwrap());
            }
        }
    }
    let mut v = Vec::new();
    walk(dir, &mut v);
    v.sort();
    v
}

/// W4-17 (codex Wave 4, 30 Aug 2026), FLAT FIRST. `node` and
/// `node/child.bin` are two valid FileDesc members that share no
/// complete string, so the claim's equality test saw no collision at
/// all - and then the child's `create_out_dirs` met a REGULAR FILE
/// where it needed a directory, warned, and left the payload under its
/// hash.
#[test]
fn a_flat_name_and_its_would_be_child_both_publish() {
    let dir = temp_dir("nodeflat");
    std::fs::write(dir.join("aaa.bin"), b"FLAT").unwrap();
    std::fs::write(dir.join("bbb.bin"), b"CHILD").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    publish_verified_name(&dir.join("aaa.bin"), "node", &dir, 0, &mut taken);
    publish_verified_name(&dir.join("bbb.bin"), "node/child.bin", &dir, 1, &mut taken);
    assert_eq!(
        payloads_deep(&dir),
        vec![b"CHILD".to_vec(), b"FLAT".to_vec()],
        "one of the two payloads was lost to the file/directory collision"
    );
    assert!(
        dir.join("node").is_file(),
        "the first claimant must keep the plain name"
    );
    assert!(
        dir.join("001-node/child.bin").is_file(),
        "the child must move its whole subtree, not just its leaf"
    );
    assert!(
        taken.unlanded_why(|_| true).is_none(),
        "nothing was stranded"
    );
}

/// W4-17, CHILD FIRST - the other completion order, where the flat name
/// is the one that has to move because publishing it met a NONEMPTY
/// DIRECTORY. `node` is spoken for as a directory by a name it does not
/// equal, which is the half a leaf-only claim map cannot represent.
#[test]
fn a_child_name_and_its_would_be_flat_parent_both_publish() {
    let dir = temp_dir("nodechild");
    std::fs::write(dir.join("aaa.bin"), b"CHILD").unwrap();
    std::fs::write(dir.join("bbb.bin"), b"FLAT").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    publish_verified_name(&dir.join("aaa.bin"), "node/child.bin", &dir, 0, &mut taken);
    publish_verified_name(&dir.join("bbb.bin"), "node", &dir, 1, &mut taken);
    assert_eq!(
        payloads_deep(&dir),
        vec![b"CHILD".to_vec(), b"FLAT".to_vec()],
        "one of the two payloads was lost to the directory/file collision"
    );
    assert!(dir.join("node/child.bin").is_file());
    assert!(dir.join("001-node").is_file());
    assert!(
        taken.unlanded_why(|_| true).is_none(),
        "nothing was stranded"
    );
}

/// Two members that need the SAME directory are not a collision -
/// `node` is shared, not owned, so widening the claim must not start
/// disambiguating an ordinary disc tree.
#[test]
fn two_members_of_one_directory_are_not_a_collision() {
    let dir = temp_dir("nodesibs");
    std::fs::write(dir.join("aaa.bin"), b"A").unwrap();
    std::fs::write(dir.join("bbb.bin"), b"B").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    publish_verified_name(
        &dir.join("aaa.bin"),
        "VIDEO_TS/VTS_01_1.VOB",
        &dir,
        0,
        &mut taken,
    );
    publish_verified_name(
        &dir.join("bbb.bin"),
        "VIDEO_TS/VIDEO_TS.IFO",
        &dir,
        1,
        &mut taken,
    );
    assert!(dir.join("VIDEO_TS/VTS_01_1.VOB").is_file());
    assert!(dir.join("VIDEO_TS/VIDEO_TS.IFO").is_file());
    assert!(taken.unlanded_why(|_| true).is_none());
}

/// X5-09: a publish that could NOT happen is charged, so the verdict
/// can see it. Injected the one way that needs no permissions and no
/// second filesystem - the source is gone, so `fs::rename` fails - and
/// the arm it exercises is the same one EXDEV, EACCES and a Windows
/// sharing violation take.
#[test]
fn a_failed_publish_is_charged_to_the_verdict() {
    let dir = temp_dir("x509fail");
    let mut taken = PublishedNames::for_dir(&dir);
    assert!(
        publish_verified_name(&dir.join("gone.bin"), "movie.mkv", &dir, 7, &mut taken).is_none()
    );
    let why = taken
        .unlanded_why(|s| s == 7)
        .expect("a failed publish must reach the verdict");
    assert!(
        why.contains("movie.mkv"),
        "the failure must name what could not be published: {why}"
    );
    // ...and only while those bytes really are still sitting there. A
    // slot the unpack ladder has since consumed stranded nothing.
    assert!(
        taken.unlanded_why(|_| false).is_none(),
        "a slot whose file is gone must not fail the job"
    );
}

/// A weaker naming tier landing the slot AFTER a stronger one failed is
/// a recovery, not a job to fail: the bytes are under a real name.
#[test]
fn a_later_successful_publish_clears_an_earlier_failure() {
    let dir = temp_dir("x509clear");
    let mut taken = PublishedNames::for_dir(&dir);
    publish_verified_name(&dir.join("gone.bin"), "movie.mkv", &dir, 3, &mut taken);
    assert!(taken.unlanded_why(|_| true).is_some());
    std::fs::write(dir.join("0Bf3qZ.bin"), b"BYTES").unwrap();
    assert!(
        publish_verified_name(&dir.join("0Bf3qZ.bin"), "movie.mkv", &dir, 3, &mut taken).is_some()
    );
    assert!(
        taken.unlanded_why(|_| true).is_none(),
        "the slot's bytes are under a real name now"
    );
}

/// The WEAK tier's belt (W4-03): a file already at the target is not
/// replaced, even by a name the registry has never heard of. That last
/// clause is the whole point - `land_duplicate_filedescs` copies output
/// files without going through the registry, and the late-set disk repair
/// creates them with no slot behind them, so a seeded registry cannot be
/// the only guard. Contrast `a_previous_runs_copy_is_still_replaced`
/// above: the PAR2 tier replaces exactly this, on purpose.
#[test]
fn a_weak_name_never_replaces_a_file_the_registry_never_saw() {
    let dir = temp_dir("weak");
    std::fs::write(dir.join("movie.mkv"), b"ALREADY-THERE").unwrap();
    std::fs::write(dir.join("0Bf3qZ.bin"), b"CRC32-SAYS-SO").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    assert!(
        publish_weak_name(&dir.join("0Bf3qZ.bin"), "movie.mkv", &dir, 1, &mut taken).is_none(),
        "the weak tier must decline an occupied name, not rename over it"
    );
    assert_eq!(
        payloads(&dir),
        vec![b"ALREADY-THERE".to_vec(), b"CRC32-SAYS-SO".to_vec()],
    );
}

/// The weak tier shares the registry, so a SEEDED name pushes it to the
/// disambiguated form rather than to a refusal: both payloads survive and
/// the deobfuscated one is still recognisable. Refusing would be
/// acceptable too; landing under `{slot:03}-` is strictly better, and
/// this pins which of the two the tier actually does.
#[test]
fn a_weak_name_disambiguates_off_a_seeded_slot() {
    let dir = temp_dir("weakseed");
    std::fs::write(dir.join("movie.mkv"), b"POSTED-NAME-PAYLOAD").unwrap();
    std::fs::write(dir.join("0Bf3qZ.bin"), b"OBFUSCATED-PAYLOAD").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    taken.seed(0, "movie.mkv");
    let p = publish_weak_name(&dir.join("0Bf3qZ.bin"), "movie.mkv", &dir, 1, &mut taken);
    assert_eq!(
        p.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        Some("001-movie.mkv".to_string()),
    );
    assert_eq!(
        payloads(&dir),
        vec![
            b"OBFUSCATED-PAYLOAD".to_vec(),
            b"POSTED-NAME-PAYLOAD".to_vec()
        ],
    );
}

/// Every directory entry in `dir`, by its STORED name. Multiplicity is
/// the grader X5-20 needs: a content-only check sees two correct files
/// and misses that one of them should not be there at all.
fn entries(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// X5-20 (codex Extreme Wave 5, 30 Aug 2026), the pin for the fix.
/// CONFIRMED red against origin/main before it: publish reported
/// `Some(".../Real.Name.mkv")` and BOTH directory entries survived.
/// Renaming one hardlink over another name for one inode is a POSIX
/// no-op that still returns `Ok(())`, and the code graded the rename by
/// that alone - so the obfuscated alias stayed in the output directory
/// next to the correct name, under a log line claiming a publish.
#[cfg(unix)]
#[test]
fn publishing_over_a_hardlink_of_the_same_inode_leaves_one_entry() {
    let dir = temp_dir("sameino");
    let bytes = b"the verified payload".to_vec();
    let hash = dir.join("Ya6fZq31Cp");
    std::fs::write(&hash, &bytes).unwrap();
    std::fs::hard_link(&hash, dir.join("Real.Name.mkv")).unwrap();

    let mut taken = PublishedNames::for_dir(&dir);
    let published = publish_verified_name(&hash, "Real.Name.mkv", &dir, 0, &mut taken);

    assert_eq!(
        published.as_deref(),
        Some(dir.join("Real.Name.mkv").as_path()),
    );
    assert_eq!(entries(&dir), vec!["Real.Name.mkv".to_string()]);
    assert_eq!(std::fs::read(dir.join("Real.Name.mkv")).unwrap(), bytes);
    // The name landed, so nothing is owed - X5-09 must not fail this job.
    assert_eq!(taken.unlanded_why(|_| true), None);
}

/// The same shape through the WEAK tier, which used to decline on
/// `target.exists()` and leave the identical stale alias. There are no
/// other bytes for the W4-03 refusal to protect when the file already at
/// the name IS this file.
#[cfg(unix)]
#[test]
fn a_weak_publish_over_a_hardlink_of_the_same_inode_leaves_one_entry() {
    let dir = temp_dir("sameinow");
    let bytes = b"the verified payload".to_vec();
    let hash = dir.join("Ya6fZq31Cp");
    std::fs::write(&hash, &bytes).unwrap();
    std::fs::hard_link(&hash, dir.join("Real.Name.mkv")).unwrap();

    let mut taken = PublishedNames::for_dir(&dir);
    let published = publish_weak_name(&hash, "Real.Name.mkv", &dir, 0, &mut taken);

    assert_eq!(
        published.as_deref(),
        Some(dir.join("Real.Name.mkv").as_path()),
    );
    assert_eq!(entries(&dir), vec!["Real.Name.mkv".to_string()]);
    assert_eq!(std::fs::read(dir.join("Real.Name.mkv")).unwrap(), bytes);
}

/// X5-20 (control): two distinct inodes. The rename really moves the
/// entry and exactly one name is left - so a green here beside the pin
/// above is what makes the fix specific to the same-inode case rather
/// than to "publish leaves one entry".
#[test]
fn publishing_over_a_distinct_inode_leaves_one_entry() {
    let dir = temp_dir("distinctino");
    let bytes = b"the verified payload".to_vec();
    let hash = dir.join("Ya6fZq31Cp");
    std::fs::write(&hash, &bytes).unwrap();
    std::fs::write(dir.join("Real.Name.mkv"), b"an older copy").unwrap();

    let mut taken = PublishedNames::for_dir(&dir);
    let published = publish_verified_name(&hash, "Real.Name.mkv", &dir, 0, &mut taken);

    assert_eq!(
        published.as_deref(),
        Some(dir.join("Real.Name.mkv").as_path()),
    );
    assert_eq!(entries(&dir), vec!["Real.Name.mkv".to_string()]);
    assert_eq!(std::fs::read(dir.join("Real.Name.mkv")).unwrap(), bytes);
}

/// X5-20 (the counter-control, and the one that keeps the fix from
/// eating a payload). On a case-INSENSITIVE volume `readme.nfo` and
/// `README.nfo` are one inode reached by two spellings, so the identity
/// test that catches the hardlink above matches here too - and unlinking
/// the source would destroy the file's ONLY name. `is_redundant_link`
/// therefore asks the directory for STORED names, which are exact, and
/// refuses to call this a second link. The rename does what it always
/// did: on a case-sensitive volume it moves the entry, on a
/// case-insensitive one it re-cases it. Either way the bytes survive
/// under exactly one name.
#[test]
fn publishing_under_a_case_variant_of_its_own_name_keeps_the_payload() {
    let dir = temp_dir("casevariant");
    let bytes = b"the verified payload".to_vec();
    let posted = dir.join("readme.nfo");
    std::fs::write(&posted, &bytes).unwrap();

    let mut taken = PublishedNames::for_dir(&dir);
    let published = publish_verified_name(&posted, "README.nfo", &dir, 0, &mut taken);

    let left = entries(&dir);
    assert_eq!(
        left.len(),
        1,
        "the payload's only name went missing: {left:?}"
    );
    assert_eq!(std::fs::read(dir.join(&left[0])).unwrap(), bytes);
    assert!(published.is_some());
}

/// M4-61 - two FileDesc names that `PublishedNames::key` reads as
/// distinct and the VOLUME reads as one file.
///
/// MEASURED on APFS on the 30 Aug 2026 dev box, before the disk belt in
/// `collides_on_disk`: `ſ.mkv` (U+017F long s) then `s.mkv` reported two
/// successful publishes - `ſ.mkv` and `s.mkv` - and left ONE file on
/// disk holding the SECOND payload. The first was gone, rc would be 0,
/// two "renamed" lines in the log. Same for `ς.mkv` then `σ.mkv` (final
/// sigma). `str::to_lowercase` maps `ſ` to itself and `ς` to itself,
/// while APFS folds both, so the claim map saw no collision at all.
///
/// The two pairs BESIDE them are the control, and they are why the row
/// cannot be closed by swapping in a different fold: the Kelvin sign and
/// the capital sharp s were already handled correctly by `to_lowercase`,
/// and `to_uppercase().to_lowercase()` - the obvious fix for the two
/// failing pairs - breaks the sharp-s pair instead. Every pair here was
/// verified against the real filesystem first (write one spelling, stat
/// the other); this test asserts a property of the OUTPUT rather than of
/// any fold, so it holds on a case-SENSITIVE volume too, where all four
/// pairs are legitimately two files and every publish takes its own
/// plain name.
///
/// `two_verified_names_that_sanitize_alike_keep_both_payloads` above is
/// the CONTROL for the machinery: a collision the string map DOES see
/// still disambiguates. So a red here is the fold hole, not the claim.
#[test]
fn unicode_twins_the_volume_folds_keep_both_payloads() {
    for (first, second, label) in [
        ("\u{17F}.mkv", "s.mkv", "long-s"),
        ("\u{3C2}.mkv", "\u{3C3}.mkv", "final-sigma"),
        ("\u{212A}.mkv", "K.mkv", "kelvin"),
        ("\u{1E9E}.mkv", "\u{DF}.mkv", "capital-sharp-s"),
    ] {
        let dir = temp_dir(label);
        std::fs::write(dir.join("aaa.bin"), b"FIRST").unwrap();
        std::fs::write(dir.join("bbb.bin"), b"SECOND").unwrap();
        let mut taken = PublishedNames::for_dir(&dir);
        let a = publish_verified_name(&dir.join("aaa.bin"), first, &dir, 0, &mut taken);
        let b = publish_verified_name(&dir.join("bbb.bin"), second, &dir, 1, &mut taken);
        assert!(a.is_some() && b.is_some(), "{label}: both must publish");
        assert_eq!(
            payloads(&dir),
            vec![b"FIRST".to_vec(), b"SECOND".to_vec()],
            "{label}: a publish renamed over another slot's payload"
        );
        // The FIRST claimant keeps the plain name whichever way the
        // volume answers; only the second may be pushed onto a prefix.
        assert_eq!(
            a.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
            Some(first.to_string()),
            "{label}: the first claimant must get the plain name"
        );
    }
}

/// M4-61's other half: the belt must NOT stop the strong tier replacing
/// a PREVIOUS run's copy, which is the whole reason
/// `publish_verified_name` replaces at all.
///
/// The file at the target here is one this job never touched - it is in
/// neither `seed` nor any earlier claim - so `collides_on_disk` finds
/// nothing of ours behind it and the rename goes through, exactly as it
/// did before the belt existed.
#[test]
fn the_disk_belt_still_lets_a_previous_runs_copy_be_replaced() {
    let dir = temp_dir("prev-run");
    std::fs::write(dir.join("Real.Name.mkv"), b"STALE").unwrap();
    std::fs::write(dir.join("aaa.bin"), b"FRESH").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    let got = publish_verified_name(&dir.join("aaa.bin"), "Real.Name.mkv", &dir, 0, &mut taken);
    assert_eq!(
        got.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        Some("Real.Name.mkv".to_string()),
        "the verified bytes must take the name a previous run's copy held"
    );
    assert_eq!(payloads(&dir), vec![b"FRESH".to_vec()]);
}

/// X5-20 residue 1, the weak-tier half (decided 31 Aug 2026, claim
/// `publish-exists-dangling-decision`). CONFIRMED red against
/// origin/main before the fix: `target.exists()` follows the link, so
/// `existed` was false, the W4-03 refusal never fired and the weak tier
/// renamed over the user's symlink on the authority of a 32-bit
/// checksum. A dangling link holds no bytes, so this is NOT the X5-07
/// containment class - the argument for declining is that the harms are
/// not symmetric, and it is written out at the site.
#[cfg(unix)]
#[test]
fn a_weak_publish_declines_over_a_dangling_symlink() {
    let dir = temp_dir("weakdangle");
    std::fs::write(dir.join("0Bf3qZ.bin"), b"CRC32-SAYS-SO").unwrap();
    std::os::unix::fs::symlink("/nzbfast-no-such-target", dir.join("movie.mkv")).unwrap();

    let mut taken = PublishedNames::for_dir(&dir);
    assert!(
        publish_weak_name(&dir.join("0Bf3qZ.bin"), "movie.mkv", &dir, 1, &mut taken).is_none(),
        "a dangling link is still an entry, and a 32-bit checksum may not delete it"
    );
    // Both entries, and the link is still a link pointing where it did.
    assert_eq!(
        entries(&dir),
        vec!["0Bf3qZ.bin".to_string(), "movie.mkv".to_string()]
    );
    assert_eq!(
        std::fs::read_link(dir.join("movie.mkv")).unwrap(),
        std::path::Path::new("/nzbfast-no-such-target"),
    );
    assert_eq!(
        std::fs::read(dir.join("0Bf3qZ.bin")).unwrap(),
        b"CRC32-SAYS-SO".to_vec()
    );
    // A decline is a correct outcome, not a publish failure - X5-09 must
    // not fail a job over it.
    assert_eq!(taken.unlanded_why(|_| true), None);
}

/// The control that keeps the arm above specific to the WEAK tier. A
/// PAR2 MD5 pair really is authoritative over a broken link, so the
/// strong tier replaces it and the payload lands under its real name -
/// which is also what makes this a decision about the refusal rather
/// than about `exists()` being wrong everywhere.
#[cfg(unix)]
#[test]
fn the_strong_tier_still_replaces_a_dangling_symlink() {
    let dir = temp_dir("strongdangle");
    let hash = dir.join("Ya6fZq31Cp");
    std::fs::write(&hash, b"the verified payload").unwrap();
    std::os::unix::fs::symlink("/nzbfast-no-such-target", dir.join("Real.Name.mkv")).unwrap();

    let mut taken = PublishedNames::for_dir(&dir);
    let published = publish_verified_name(&hash, "Real.Name.mkv", &dir, 0, &mut taken);

    assert_eq!(
        published.as_deref(),
        Some(dir.join("Real.Name.mkv").as_path()),
    );
    assert_eq!(entries(&dir), vec!["Real.Name.mkv".to_string()]);
    assert!(!dir.join("Real.Name.mkv").is_symlink());
    assert_eq!(
        std::fs::read(dir.join("Real.Name.mkv")).unwrap(),
        b"the verified payload".to_vec()
    );
    assert_eq!(taken.unlanded_why(|_| true), None);
}

/// The log half of the same residue, pinned without a tracing
/// subscriber. Three answers and not two: `(replaced the previous copy)`
/// was false in BOTH symlink directions, because `rename(2)` removes the
/// link and leaves what it pointed at alone.
#[test]
fn the_renamed_line_tells_a_symlink_from_a_previous_copy() {
    let dir = temp_dir("suffix");
    assert_eq!(displaced_suffix(None), "");

    let file = dir.join("previous.mkv");
    std::fs::write(&file, b"a previous run's copy").unwrap();
    let m = std::fs::symlink_metadata(&file).unwrap();
    assert_eq!(displaced_suffix(Some(&m)), " (replaced the previous copy)");

    #[cfg(unix)]
    {
        // Both directions, because the resolving one was wrong too: the
        // copy at the far end of that link survives the rename.
        for (tag, at) in [
            ("dangling", std::path::Path::new("/nzbfast-no-such-target")),
            ("resolving", file.as_path()),
        ] {
            let link = dir.join(format!("link-{tag}"));
            std::os::unix::fs::symlink(at, &link).unwrap();
            let m = std::fs::symlink_metadata(&link).unwrap();
            assert_eq!(
                displaced_suffix(Some(&m)),
                " (replaced a symlink that was there)",
                "the {tag} link"
            );
        }
    }
}

/// The weak tier's refusal is a CLAIM and not a look, so a rename that
/// then fails must not leave the claim behind. A leaked placeholder is a
/// zero-byte file wearing the name this slot failed to take, and
/// `PublishedNames::for_dir` seeds the next run from the directory - so
/// it would turn one recoverable failure into a permanent decline for
/// every later run, on a name nothing owns.
///
/// The rename is made to fail the way `a_failed_publish_is_charged...`
/// above makes it fail, with a source that is not there.
#[test]
fn a_weak_publish_whose_rename_fails_leaves_no_placeholder_behind() {
    let dir = temp_dir("weakresidue");
    let mut taken = PublishedNames::for_dir(&dir);
    assert!(
        publish_weak_name(&dir.join("gone.bin"), "movie.mkv", &dir, 3, &mut taken).is_none(),
        "a source that is not there cannot publish"
    );
    assert!(
        std::fs::symlink_metadata(dir.join("movie.mkv")).is_err(),
        "the claim this publish took must be gone with it, not left \
         wearing the name as a zero-byte file"
    );
}

/// The window itself: an entry created between the occupancy question
/// and the rename used to be renamed over, which is the W4-03 harm
/// arriving through a race instead of through a missing guard. MEASURED
/// on APFS 31 Aug 2026 before the fix - 14,340 of 20,000 publishes lost
/// their adversary's entry, 96.8% of every arrival that got the name at
/// all - because the `lstat` is 968 ns and the `openat` walk plus rename
/// behind it are ~112 us, so the guard covered about 1% of its own
/// interval. Full numbers in
/// `research/PUBLISH-OCCUPANCY-WINDOW-2026-08-31.md`.
///
/// The claim closes it because it IS the occupancy question, asked
/// atomically: `create_new` answers `AlreadyExists` for a regular file,
/// a dangling link, a link out of the directory and a directory - the
/// same four answers `symlink_metadata` gives.
///
/// BOUNDED and not a timing assertion: 300 trials, ~0.2 s, and
/// what is asserted is an INVARIANT that must hold in every one of them.
/// The adversary's own claim count is FLOORED, because an adversary that
/// never got the name would make this pass having raced nothing, which
/// is the vacuous green this repo keeps writing gates about. Verified
/// RED against the pre-claim code: ~72% of trials lost.
#[test]
fn a_weak_publish_never_renames_over_an_entry_created_beside_it() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const TRIALS: usize = 300;
    let dir = temp_dir("weakrace");
    let go = Arc::new(AtomicBool::new(false));
    let claimed = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));

    // `to_path_buf`, not `clone`: `temp_dir` hands back a `ScratchDir`
    // guard that removes the tree on drop, so the adversary takes a plain
    // copy of the PATH and the guard stays on this thread.
    let (advdir, g, c, st) = (dir.to_path_buf(), go.clone(), claimed.clone(), stop.clone());
    let adversary = std::thread::spawn(move || {
        let target = advdir.join("movie.mkv");
        loop {
            while !g.load(Ordering::Acquire) {
                if st.load(Ordering::Relaxed) {
                    return;
                }
                std::hint::spin_loop();
            }
            // `create_new`, so "I got the name" is the filesystem's
            // answer and not a guess: it can only succeed while nothing
            // is there, which makes the classification below exact.
            let ok = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .is_ok();
            c.store(ok, Ordering::Release);
            g.store(false, Ordering::Release);
        }
    });

    let mut adversary_got_the_name = 0usize;
    for i in 0..TRIALS {
        let src = dir.join("0Bf3qZ.bin");
        std::fs::write(&src, b"SRC").unwrap();
        let _ = std::fs::remove_file(dir.join("movie.mkv"));
        let mut taken = PublishedNames::for_dir(&dir);
        claimed.store(false, Ordering::Relaxed);
        // Swept, so the adversary's create lands at every point across
        // the publish rather than always at the same one.
        for _ in 0..(i % 400) * 3 {
            std::hint::spin_loop();
        }
        go.store(true, Ordering::Release);
        let published = publish_weak_name(&src, "movie.mkv", &dir, 1, &mut taken).is_some();
        while go.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        if claimed.load(Ordering::Acquire) {
            adversary_got_the_name += 1;
            assert!(
                !published,
                "trial {i}: the weak tier renamed over an entry that was \
                 created beside it - the W4-03 harm through the window"
            );
        }
        let _ = std::fs::remove_file(dir.join("movie.mkv"));
        let _ = std::fs::remove_file(&src);
    }
    stop.store(true, Ordering::Release);
    go.store(true, Ordering::Release);
    let _ = adversary.join();

    assert!(
        adversary_got_the_name >= TRIALS / 20,
        "the adversary claimed the name only {adversary_got_the_name} times in \
         {TRIALS}, so this run raced nothing and its green means nothing"
    );
}

/// A weak-tier name carrying DIRECTORIES still publishes as a tree.
///
/// New ground rather than a restatement: the weak tier's claim goes
/// through `open_out_leaf_under`, which walks the destination's
/// directories itself, and every other weak pin in this file uses a
/// flat name. `a_safe_filedesc_path_publishes_as_a_tree` covers the
/// same shape for the STRONG tier, which takes no claim, so it says
/// nothing about this path.
#[test]
fn a_weak_tier_tree_name_still_publishes_into_its_subdirectory() {
    let dir = temp_dir("weaktree");
    std::fs::write(dir.join("0Bf3qZ.bin"), b"CRC32-SAYS-SO").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    let p = publish_weak_name(
        &dir.join("0Bf3qZ.bin"),
        "sub/movie.mkv",
        &dir,
        1,
        &mut taken,
    );
    assert_eq!(
        p.as_deref(),
        Some(dir.join("sub").join("movie.mkv").as_path()),
        "a weak tree name must land under its directory, not be refused \
         by the claim that now asks the occupancy question"
    );
    assert_eq!(
        std::fs::read(dir.join("sub").join("movie.mkv")).unwrap(),
        b"CRC32-SAYS-SO"
    );
    // And the refusal still fires one level down, where the claim has to
    // walk before it can ask.
    std::fs::write(dir.join("other.bin"), b"SECOND").unwrap();
    assert!(
        publish_weak_name(&dir.join("other.bin"), "sub/movie.mkv", &dir, 2, &mut taken).is_none()
            || std::fs::read(dir.join("sub").join("movie.mkv")).unwrap() == b"CRC32-SAYS-SO",
        "the first payload must survive whichever way the registry \
         disambiguates the second"
    );
}

/// M4-44 site 1: the per-job claim key folds the way the VOLUME does,
/// and `str::to_lowercase` - what this site used until 31 Aug 2026 - is
/// weaker than that.
///
/// Each pair below is ONE file object on APFS (measured 31 Aug 2026 by
/// creating both and reading the inodes) and every one but the last was
/// TWO keys before this site moved to `disk::case_fold_key`. Two keys
/// means `free_for` sees no collision, both slots claim the plain name,
/// and the second publish renames over the first at rc=0.
///
/// This is the STRING half, and it is not redundant with M4-61's disk
/// belt beside it: `collides_on_disk` is the strong tier's flag alone
/// and only fires once something is already ON DISK at the name, while
/// `taken` and `dirs` cover names this job has claimed and not landed.
/// `unicode_twins_the_volume_folds_keep_both_payloads` above is the
/// end-to-end half and asserts a property of the OUTPUT, so it holds on
/// a case-sensitive volume too; this one asks the key directly and so
/// has to pass the volume's answer rather than probe for it.
///
/// The `fold = false` half is not decoration: on a case-sensitive volume
/// these ARE distinct files, and a fold applied unconditionally would
/// disambiguate one of them for nothing.
#[test]
fn the_publish_claim_key_folds_the_way_the_volume_does() {
    let one_object = [
        ("Straße.mkv", "STRASSE.MKV"),
        ("ﬁle.txt", "file.txt"),
        ("ſample.nfo", "sample.nfo"),
        ("README.NFO", "readme.nfo"),
    ];
    for (a, b) in one_object {
        assert_eq!(
            PublishedNames::fold_key(true, a),
            PublishedNames::fold_key(true, b),
            "{a:?} and {b:?} name ONE object on a case-insensitive volume; \
             two keys here means the second publish renames over the first"
        );
        assert_ne!(
            PublishedNames::fold_key(false, a),
            PublishedNames::fold_key(false, b),
            "{a:?} and {b:?} are distinct files on a case-sensitive volume"
        );
    }
}

/// The over-fold direction, which APFS keeps apart. `to_uppercase` maps
/// `ı` to `I` (the TURKIC tailoring rather than the default fold), so a
/// fold without `case_fold_key`'s hold-out merges these - and a merge
/// costs this site a needless `{slot:03}-` prefix on a name that did not
/// need one. Bounded and visible, which is why folding harder is the
/// right trade HERE; in `nzbfast::rarfix`, which resolves a collision by
/// DROPPING an entry, the same merge costs a file, and that is why that
/// site deliberately still lowercases.
#[test]
fn the_publish_claim_key_keeps_the_turkic_i_apart() {
    assert_ne!(
        PublishedNames::fold_key(true, "I.txt"),
        PublishedNames::fold_key(true, "ı.txt")
    );
}

/// A name at the 255-byte component cap plus a `001-` prefix is 259
/// bytes, and `renameat` refuses it - so the SECOND claimant's publish
/// landed in `could_not_publish` and its verified payload stayed under
/// its posted hash, with the job charged an unlanded file.
///
/// Reachability is the ordinary collision path and not a corner: two
/// FileDesc names that sanitize alike is what `claim` exists for, and
/// the name is AT the cap precisely because capping is what produced
/// it. Measured on APFS 31 Aug 2026: a 255-byte component creates and
/// 256 is `ENAMETOOLONG` for both `mkdir` and `create`.
#[test]
fn a_disambiguated_name_at_the_cap_still_publishes() {
    let dir = temp_dir("capprefix");
    std::fs::write(dir.join("aaa.bin"), b"FIRST").unwrap();
    std::fs::write(dir.join("bbb.bin"), b"SECOND").unwrap();
    // Two distinct FileDesc names that sanitize to ONE name at exactly
    // the cap: the empty component puts both on the flatten fallback,
    // and `cap_component` maps any overlong stem to exactly 255.
    let long = "y".repeat(400);
    let first = format!("sub//{long}");
    let second = format!("sub__{long}");
    let one = nzbkit::disk::sanitize_out_name(&first);
    assert_eq!(one.len(), 255, "the premise moved");
    assert_eq!(one, nzbkit::disk::sanitize_out_name(&second));

    let mut taken = PublishedNames::for_dir(&dir);
    let a = publish_verified_name(&dir.join("aaa.bin"), &first, &dir, 0, &mut taken);
    let b = publish_verified_name(&dir.join("bbb.bin"), &second, &dir, 1, &mut taken);

    assert_eq!(a.as_deref(), Some(dir.join(&one).as_path()));
    let b = b.expect("the second claimant must publish too");
    assert_ne!(b, dir.join(&one));
    assert_eq!(
        b.file_name().map(|n| n.len()),
        Some(255),
        "the disambiguated name must be capped, not 259 bytes"
    );
    assert_eq!(taken.unlanded_why(|_| true), None);
    assert_eq!(payloads(&dir), vec![b"FIRST".to_vec(), b"SECOND".to_vec()]);
}

/// X5-22. The DECISION half of publication durability: which directories
/// a publish changed, and in what order they must be flushed.
///
/// The guarantee itself is not testable here - the row's oracle is an
/// ext4/XFS image under `dm-log-writes` replaying only acknowledged
/// writes, and no box on this fleet has one - so what is pinned is the
/// thing a reviewer gets wrong instead: the canonical entry's directory
/// FIRST (a cut after it leaves at worst a duplicate name, where the
/// other order can leave the payload reachable under none), the ancestor
/// chain up to and INCLUDING `out_dir` for a tree-preserved name, and no
/// second fsync of a directory already in the list.
#[test]
fn a_publication_flushes_the_canonical_directory_first_and_stops_at_out_dir() {
    let out = std::path::Path::new("/jobs/out");

    // The flat post, which is nearly every post: one directory holds the
    // canonical name AND the posted-name alias, so one fsync covers the
    // entry that arrived and the entry that went.
    assert_eq!(
        publication_dirs(out, &out.join("Real.Name.mkv"), Some(&out.join("hash.bin"))),
        vec![out.to_path_buf()],
        "a flat publish is ONE directory, not two"
    );

    // A tree-preserved FileDesc name renames into a directory
    // `create_out_dirs` may have just made, so its own entry in `out` is
    // a second metadata change - walked rather than left to the
    // filesystem's journal ordering.
    assert_eq!(
        publication_dirs(
            out,
            &out.join("TREE/deep/Real.Name.mkv"),
            Some(&out.join("hash.bin")),
        ),
        vec![out.join("TREE/deep"), out.join("TREE"), out.to_path_buf(),],
        "the canonical directory leads and the chain stops at out_dir"
    );

    // The alias's own directory joins the list only when the walk above
    // did not already reach it, and it goes LAST: its unlink is the one
    // change that is safe to lose.
    assert_eq!(
        publication_dirs(
            out,
            &out.join("TREE/Real.Name.mkv"),
            Some(&out.join("OTHER/hash.bin")),
        ),
        vec![out.join("TREE"), out.to_path_buf(), out.join("OTHER")],
    );

    // No alias at all - the ordinary rename with nothing left behind.
    assert_eq!(
        publication_dirs(out, &out.join("Real.Name.mkv"), None),
        vec![out.to_path_buf()],
    );

    // A target that is not under `out_dir` cannot arrive through
    // `rename_out_under`'s bound walk, and the guard is here because the
    // alternative to stopping is walking to `/` and fsyncing every
    // directory on the way.
    assert_eq!(
        publication_dirs(out, std::path::Path::new("/elsewhere/a/b.bin"), None),
        vec![std::path::PathBuf::from("/elsewhere/a")],
        "the walk must stop rather than climb out of the job directory"
    );
}

/// X5-22, the funnel. Each of `publish`'s three landed exits must go
/// through `landed`, so each must FLUSH - and it is the flush that is
/// asserted, not merely that the publish still works. An exit put back
/// to a bare `note_landed` + `Some(target)` lands its file exactly as
/// well and is not durable, which is the whole defect; `take_flushed`
/// is what tells the two apart.
#[test]
fn every_landed_exit_flushes_the_directory_it_changed() {
    let dir = temp_dir("x5_22_funnel");
    let _ = take_flushed();

    // Exit 3, the ordinary rename, with the POSTED name in a directory
    // the canonical name's own chain never reaches. Every other rename
    // case here is flat on the source side, so the directory the entry
    // was renamed OUT of is already in the list and naming it costs
    // nothing - this is the shape where it does.
    std::fs::create_dir_all(dir.join("POSTED")).unwrap();
    std::fs::write(dir.join("POSTED/zzz.bin"), b"FROM A SUBDIR").unwrap();
    let mut split_src = PublishedNames::for_dir(&dir);
    let _ = take_flushed();
    assert_eq!(
        publish_verified_name(
            &dir.join("POSTED/zzz.bin"),
            "TREE3/Real.Six.mkv",
            &dir,
            0,
            &mut split_src,
        )
        .as_deref(),
        Some(dir.join("TREE3/Real.Six.mkv").as_path()),
    );
    assert!(!dir.join("POSTED/zzz.bin").exists());
    assert_eq!(
        take_flushed(),
        vec![dir.join("TREE3"), dir.to_path_buf(), dir.join("POSTED")],
        "a rename touches both directories - the entry that went owes a \
         flush as much as the one that arrived"
    );

    // Exit 3, the ordinary rename.
    std::fs::write(dir.join("aaa.bin"), b"PAYLOAD").unwrap();
    let mut taken = PublishedNames::for_dir(&dir);
    assert_eq!(
        publish_verified_name(&dir.join("aaa.bin"), "Real.One.mkv", &dir, 0, &mut taken).as_deref(),
        Some(dir.join("Real.One.mkv").as_path()),
    );
    assert_eq!(taken.unlanded_why(|_| true), None);
    assert_eq!(
        take_flushed(),
        vec![dir.to_path_buf()],
        "the ordinary rename must flush the directory it renamed into"
    );

    // Exit 3 again, into a tree-preserved name - the arm whose ancestor
    // chain the test above pins.
    std::fs::write(dir.join("bbb.bin"), b"TREE PAYLOAD").unwrap();
    assert_eq!(
        publish_verified_name(
            &dir.join("bbb.bin"),
            "TREE/Real.Two.mkv",
            &dir,
            1,
            &mut taken
        )
        .as_deref(),
        Some(dir.join("TREE/Real.Two.mkv").as_path()),
    );
    assert_eq!(
        std::fs::read(dir.join("TREE/Real.Two.mkv")).unwrap(),
        b"TREE PAYLOAD"
    );
    assert_eq!(
        take_flushed(),
        vec![dir.join("TREE"), dir.to_path_buf()],
        "a freshly created parent owes its own entry in out_dir a flush"
    );

    // Exit 1, the pre-rename identity arm: one inode, two names, so the
    // rename would be a POSIX no-op (X5-20). The redundant posted-name
    // entry goes and the canonical one stays.
    std::fs::write(dir.join("Real.Three.mkv"), b"ALREADY").unwrap();
    std::fs::hard_link(dir.join("Real.Three.mkv"), dir.join("ccc.bin")).unwrap();
    assert_eq!(
        publish_verified_name(&dir.join("ccc.bin"), "Real.Three.mkv", &dir, 2, &mut taken)
            .as_deref(),
        Some(dir.join("Real.Three.mkv").as_path()),
    );
    assert!(!dir.join("ccc.bin").exists(), "the alias must be unlinked");
    assert_eq!(
        std::fs::read(dir.join("Real.Three.mkv")).unwrap(),
        b"ALREADY"
    );
    assert_eq!(taken.unlanded_why(|_| true), None);
    assert_eq!(
        take_flushed(),
        vec![dir.to_path_buf()],
        "the pre-rename identity arm must flush the alias removal too - \
         it is the arm whose canonical entry somebody else created"
    );

    // The same identity arm through the WEAK tier, which reaches it by a
    // different door - its `CreateNew` claim never runs, because the
    // decline is held out ahead of it on purpose.
    //
    // The belt AFTER the rename is deliberately not driven here and
    // cannot be: it exists for the window between the check above and
    // the `renameat`, which only a racing thread can open. Both arms are
    // one function (`publish_redundant`) for exactly that reason, so
    // this test pins the mechanism the belt uses.
    std::fs::write(dir.join("Real.Four.mkv"), b"BELT").unwrap();
    std::fs::hard_link(dir.join("Real.Four.mkv"), dir.join("ddd.bin")).unwrap();
    let mut weak = PublishedNames::for_dir(&dir);
    let _ = take_flushed();
    assert_eq!(
        publish_weak_name(&dir.join("ddd.bin"), "Real.Four.mkv", &dir, 0, &mut weak).as_deref(),
        Some(dir.join("Real.Four.mkv").as_path()),
    );
    assert!(!dir.join("ddd.bin").exists());
    assert_eq!(
        take_flushed(),
        vec![dir.to_path_buf()],
        "the weak tier's identity arm is a landed exit and owes the same flush"
    );

    // The identity arm with the alias in a directory the canonical
    // name's own chain never reaches. Every case above is flat on one
    // side or the other, so the alias directory is already in the list
    // and dropping it costs nothing - this is the shape where it does.
    std::fs::create_dir_all(dir.join("OTHER")).unwrap();
    std::fs::create_dir_all(dir.join("TREE2")).unwrap();
    std::fs::write(dir.join("TREE2/Real.Five.mkv"), b"SPLIT").unwrap();
    std::fs::hard_link(dir.join("TREE2/Real.Five.mkv"), dir.join("OTHER/eee.bin")).unwrap();
    let mut split = PublishedNames::for_dir(&dir);
    let _ = take_flushed();
    assert_eq!(
        publish_verified_name(
            &dir.join("OTHER/eee.bin"),
            "TREE2/Real.Five.mkv",
            &dir,
            0,
            &mut split,
        )
        .as_deref(),
        Some(dir.join("TREE2/Real.Five.mkv").as_path()),
    );
    assert!(!dir.join("OTHER/eee.bin").exists());
    assert_eq!(
        take_flushed(),
        vec![dir.join("TREE2"), dir.to_path_buf(), dir.join("OTHER")],
        "the directory the alias was unlinked from owes a flush of its own"
    );
}
