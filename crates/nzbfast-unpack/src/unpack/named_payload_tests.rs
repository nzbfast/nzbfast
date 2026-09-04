//! Issue #40 pins for the RAR/7z families: a file that arrives
//! NAMED `.cbr`/`.cb7` is the payload, never packaging. Split out
//! of `unpack.rs` to keep it under its size-gate ceiling; it is
//! the same module, only its text moved.
use super::*;

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-payload-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_with_head(dir: &std::path::Path, name: &str, head: &[u8]) -> PathBuf {
    let mut data = head.to_vec();
    data.resize(4096, 0u8);
    let p = dir.join(name);
    std::fs::write(&p, &data).unwrap();
    p
}

const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const SEVENZ: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

#[test]
fn a_named_cbr_is_never_an_obfuscated_volume() {
    let d = dir("obf");
    write_with_head(&d, "Event Leviathan 01.cbr", RAR5);
    // An obfuscated volume beside it must still be collected: the
    // guard keys on the named extension, never on content.
    let obf = write_with_head(&d, "a1b2c3d4e5f6", RAR5);
    assert_eq!(collect_obfuscated_rar_volumes(&d).unwrap(), vec![obf]);
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn payload_files_are_not_extractable_archives() {
    let d = dir("extractable");
    let cbr = write_with_head(&d, "comic.cbr", RAR5);
    let cb7 = write_with_head(&d, "comic.cb7", SEVENZ);
    assert!(!is_extractable_archive(&cbr));
    assert!(!is_extractable_archive(&cb7));
    // Obfuscated names keep the sniff.
    let bin = write_with_head(&d, "payload.bin", RAR5);
    assert!(is_extractable_archive(&bin));
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn a_named_cb7_is_never_collected_as_sevenz() {
    let d = dir("cb7");
    write_with_head(&d, "comic.cb7", SEVENZ);
    assert!(collect_sevenz_archives(&d).unwrap().is_empty());
    // A named .7z and an obfuscated 7z both still collect.
    write_with_head(&d, "release.7z", SEVENZ);
    write_with_head(&d, "deadbeef.bin", SEVENZ);
    assert_eq!(collect_sevenz_archives(&d).unwrap().len(), 2);
    std::fs::remove_dir_all(&d).unwrap();
}

/// Codex sweep 13 Aug U3: a `.cbr` beside the set must not suppress a
/// genuinely nested extensionless RAR.
///
/// The `pre_obfuscated` census read "any RAR magic without RAR grammar"
/// as "the outer set is obfuscated", and a comic is exactly that shape -
/// so an extensionless RAR produced from `outer.zip` was classed as a
/// rebuilt member of an outer set that never existed, and the recursion
/// that would have opened it was skipped: `hello.txt` never appeared and
/// the job still reported success.
#[test]
fn a_cbr_beside_the_set_does_not_suppress_a_nested_extensionless_rar() {
    let d = dir("cbr-nested");
    let comic = write_with_head(&d, "Event Leviathan 02.cbr", RAR5);
    let comic_bytes = std::fs::read(&comic).unwrap();
    let inner = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
    ))
    .unwrap();
    let z =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("deadbeef", &inner)]);
    std::fs::write(d.join("outer.zip"), &z).unwrap();

    assert_eq!(extract_nested(&d, None, 0).unwrap(), NestOutcome::Produced);
    assert!(
        d.join("hello.txt").is_file() && d.join("tiny.txt").is_file(),
        "the nested extensionless RAR must be recursed into"
    );
    // ...and the comic is untouched: excluding it from the census must
    // not turn it back into packaging.
    assert_eq!(std::fs::read(&comic).unwrap(), comic_bytes);
    std::fs::remove_dir_all(&d).unwrap();
}

/// The whole-ladder pin: a directory whose only archive-headed file
/// is a `.cbr` has NOTHING to unpack - `Ok(None)`, not the stray
/// "looks like an archive but no extractor claimed it" failure, and
/// the comic survives byte-identical.
#[test]
fn a_cbr_only_dir_has_nothing_to_unpack_and_keeps_the_comic() {
    let d = dir("ladder");
    let p = write_with_head(&d, "Event Leviathan 01 (2019).cbr", RAR5);
    let before = std::fs::read(&p).unwrap();
    assert_eq!(extract_one_level(&d, None, 0).unwrap(), None);
    assert_eq!(std::fs::read(&p).unwrap(), before);
    std::fs::remove_dir_all(&d).unwrap();
}

/// Matrix row M4-90's DISK half (31 Aug 2026). The in-stream sniff
/// learned on 30 Aug that a name identifying content overrules archive
/// magic; the post-pass gated RAR and 7z on `is_final_file` alone, so
/// every name below answered `extractable = true` and the file was
/// unpacked and swept - which is why closing the stream half alone did
/// not change the job-level outcome at all.
///
/// The `.bin` and hash rows are the CONTROL and are the load-bearing
/// half of this test: this product's own model of an obfuscated post is
/// `bbbb1234.bin`, so anybody who answers a future polyglot report by
/// widening the deny list onto `.bin` or onto extensionless names takes
/// every obfuscated set in production with it. There is deliberately no
/// row asserting `extractable == true` for a payload name: that would
/// pin the defect.
#[test]
fn a_payload_name_is_never_an_extractable_archive_on_disk() {
    let d = dir("m490-disk");
    for name in [
        "Movie.mkv",
        "Movie.mp4",
        "disc.iso",
        "Subs.srt",
        "cover.jpg",
        "release.nfo",
        "track.flac",
        "comic.cbr",
    ] {
        let p = write_with_head(&d, name, RAR5);
        assert!(!is_extractable_archive(&p), "RAR magic under {name}");
        std::fs::remove_file(&p).unwrap();
        let p = write_with_head(&d, name, SEVENZ);
        assert!(!is_extractable_archive(&p), "7z magic under {name}");
        std::fs::remove_file(&p).unwrap();
    }
    // CONTROL: the obfuscated shapes keep the sniff under both magics.
    for name in ["payload.bin", "a1b2c3d4e5f6", "deadbeef.001"] {
        let p = write_with_head(&d, name, RAR5);
        assert!(is_extractable_archive(&p), "RAR magic under {name}");
        std::fs::remove_file(&p).unwrap();
    }
    for name in ["payload.bin", "a1b2c3d4e5f6"] {
        let p = write_with_head(&d, name, SEVENZ);
        assert!(is_extractable_archive(&p), "7z magic under {name}");
        std::fs::remove_file(&p).unwrap();
    }
    // And a genuinely named container is untouched by the name rule.
    let p = write_with_head(&d, "release.7z", SEVENZ);
    assert!(is_extractable_archive(&p));
    std::fs::remove_dir_all(&d).unwrap();
}

/// The two collectors that reach the same files WITHOUT going through
/// [`is_extractable_archive`], both measured holding the same hole on
/// 31 Aug 2026: a directory of `Movie.mkv` + `Subs.srt` under RAR5
/// heads came back as two obfuscated volumes, and the 7z twin came back
/// as two extraction jobs. `collect_obfuscated_rar_volumes` is the one
/// that mattered most - its caller DELETES what it spends.
#[test]
fn the_sibling_collectors_carry_the_same_payload_name_rule() {
    let d = dir("m490-collectors");
    write_with_head(&d, "Movie.mkv", RAR5);
    write_with_head(&d, "Subs.srt", RAR5);
    write_with_head(&d, "disc.iso", SEVENZ);
    assert!(collect_obfuscated_rar_volumes(&d).unwrap().is_empty());
    assert!(collect_sevenz_archives(&d).unwrap().is_empty());
    // CONTROL: a real obfuscated volume beside them still collects, and
    // the payload files are not swallowed into its set.
    let obf = write_with_head(&d, "a1b2c3d4e5f6", RAR5);
    assert_eq!(collect_obfuscated_rar_volumes(&d).unwrap(), vec![obf]);
    std::fs::remove_dir_all(&d).unwrap();
}

/// The consequence that had to move WITH the gate. `extract_one_level`
/// closes with a stray-archive door - "looks like an archive but no
/// extractor claimed it" - which reports the level FAILED. Every arm now
/// declines a payload name, so without widening that door too, closing
/// this hole would have turned a job that correctly kept its movie into
/// a failed one. `Ok(None)` is "nothing here to unpack", which is the
/// job done right.
#[test]
fn a_declined_payload_polyglot_is_not_a_failed_level() {
    let d = dir("m490-stray");
    let p = write_with_head(&d, "Movie.mkv", RAR5);
    let before = std::fs::read(&p).unwrap();
    assert_eq!(extract_one_level(&d, None, 0).unwrap(), None);
    assert_eq!(std::fs::read(&p).unwrap(), before, "the movie must survive");
    std::fs::remove_dir_all(&d).unwrap();
}

/// `looks_like_named_rar` was checked for this rule and needs none: its
/// grammar (`.rar`, `.rNN`, `[s-z]NN` and 2-4 bare digits) is DISJOINT
/// from every payload-content name, so the two predicates cannot
/// disagree. Pinned rather than asserted, because a widening of either
/// list is exactly how that stops being true - `.sub`, `.idx` and `.ts`
/// are the near misses, each one letter or one digit from the rollover
/// and numeric tails.
#[test]
fn the_named_rar_grammar_cannot_collide_with_a_payload_name() {
    let d = dir("m490-disjoint");
    for name in [
        "Movie.mkv",
        "disc.iso",
        "Subs.srt",
        "x.sub",
        "x.idx",
        "x.ts",
        "x.img",
        "x.nfo",
        "x.sfv",
        "comic.cbr",
    ] {
        let p = write_with_head(&d, name, RAR5);
        assert!(!looks_like_named_rar(&p), "{name}");
        assert!(!nzbkit::extract::archive_sniff_eligible(&p), "{name}");
        std::fs::remove_file(&p).unwrap();
    }
    // The other side: every name the RAR grammar claims stays eligible.
    for name in ["set.rar", "set.r00", "set.r100", "set.s00", "set.001"] {
        let p = write_with_head(&d, name, RAR5);
        assert!(looks_like_named_rar(&p), "{name}");
        assert!(nzbkit::extract::archive_sniff_eligible(&p), "{name}");
        std::fs::remove_file(&p).unwrap();
    }
    std::fs::remove_dir_all(&d).unwrap();
}
