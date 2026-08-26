//! Plain split-file joining. Lives in a sibling file so splitjoin.rs stays
//! well under the size-gate ceiling (the mod name matches the file, so the
//! gate classifies these as test code).

use super::*;
use crate::unpack::{NestOutcome, extract_nested, extract_one_level};

fn split_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-splitjoin-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A payload that is not any archive's magic and does not repeat, so a
/// truncated or reordered join cannot hash equal to the whole.
fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[i % 4])
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Write `total` as `name.001`, `.002`, … in `chunk`-byte parts.
fn write_parts(dir: &std::path::Path, name: &str, total: &[u8], chunk: usize) -> Vec<PathBuf> {
    total
        .chunks(chunk)
        .enumerate()
        .map(|(i, c)| {
            let p = dir.join(format!("{name}.{:03}", i + 1));
            std::fs::write(&p, c).unwrap();
            p
        })
        .collect()
}

/// The headline case: a real three-part split of a known file joins, hashes
/// byte-identical to the original, and the parts are consumed.
#[test]
fn a_three_part_split_joins_and_hashes_correctly() {
    let dir = split_dir("three-part");
    let total = payload(300_000);
    let parts = write_parts(&dir, "Movie.mkv", &total, 120_000);
    assert_eq!(parts.len(), 3, "120,000-byte chunks of 300,000 bytes");

    let sets = collect_split_sets(&dir).unwrap();
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].base, "Movie.mkv");
    assert_eq!(sets[0].parts.len(), 3);
    assert_eq!(sets[0].total, total.len() as u64);

    assert!(join_split_sets(&dir, &sets));
    let joined = dir.join("Movie.mkv");
    assert_eq!(
        sha256(&std::fs::read(&joined).unwrap()),
        sha256(&total),
        "the joined file is the original, byte for byte"
    );
    for p in &parts {
        assert!(!p.exists(), "{} is spent and removed", p.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The whole reason the detector is conservative: a hole in the run must
/// refuse the SET, not publish a silently truncated file. Every part stays
/// on disk for the retry (or the hand-join) that can still save it.
#[test]
fn a_missing_middle_part_refuses_and_keeps_the_parts() {
    let dir = split_dir("missing-middle");
    let total = payload(400_000);
    let parts = write_parts(&dir, "Movie.mkv", &total, 100_000);
    assert_eq!(parts.len(), 4);
    std::fs::remove_file(&parts[2]).unwrap(); // .003 - a MIDDLE part

    assert!(
        collect_split_sets(&dir).unwrap().is_empty(),
        "a gap in the run refuses the whole set"
    );
    // And the pass over the directory leaves it exactly as it found it.
    assert_eq!(extract_one_level(&dir, None, 0).unwrap(), None);
    for p in [&parts[0], &parts[1], &parts[3]] {
        assert!(p.exists(), "{} is untouched", p.display());
    }
    assert!(!dir.join("Movie.mkv").exists(), "nothing was published");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `.001` set that DOES carry the Rar! magic is a numeric RAR volume set -
/// `rarfix`'s `stem_volume_set` owns it, and it must reach the RAR arm with
/// its volumes intact. The joiner refusing on the magic is half of that; the
/// arm being last-resort is the other half.
#[test]
fn a_numeric_set_carrying_rar_magic_routes_to_the_rar_arm() {
    use nzbkit::rar::fixtures;
    let dir = split_dir("rar-magic");
    let total = payload(400_000);
    // One extra byte in the first half so the volumes come out 200,051 and
    // 200,050: the SIZE rule (every part but the last identical, the last no
    // larger) is then satisfied, and the Rar! magic is the only thing left
    // refusing the set. Sized the other way round the test passes without
    // ever reaching the magic gate.
    let half = total.len() / 2 + 1;
    let n = total.len() as u64;
    let vols = [
        fixtures::rar5_volume_n(&[("film.mkv", n, &total[..half], false, true)], 0),
        fixtures::rar5_volume_n(&[("film.mkv", n, &total[half..], true, false)], 1),
    ];
    std::fs::write(dir.join("film.001"), &vols[0]).unwrap();
    std::fs::write(dir.join("film.002"), &vols[1]).unwrap();
    assert!(
        vols[0].len() >= vols[1].len(),
        "the size rule must not be what refuses this set"
    );

    assert!(
        collect_split_sets(&dir).unwrap().is_empty(),
        "the Rar! magic disqualifies the set from the joiner"
    );
    // And the RAR arm - not the joiner - is what produces the payload:
    // `film.mkv` is the archive MEMBER, and a concatenation of the two
    // volumes would have been published as a bare `film` instead.
    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    assert!(!dir.join("film").exists(), "the joiner never ran");
    let _ = std::fs::remove_dir_all(&dir);
}

/// End to end through the ladder: the arm fires from `extract_one_level`,
/// which is what the get tail's nested pass and the offline `extract` both
/// call.
#[test]
fn the_ladder_joins_a_split_set_nothing_else_claims() {
    let dir = split_dir("via-ladder");
    let total = payload(250_000);
    write_parts(&dir, "Show.S01E01.mkv", &total, 100_000);
    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert_eq!(
        sha256(&std::fs::read(dir.join("Show.S01E01.mkv")).unwrap()),
        sha256(&total)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The unpadded rollover form (`.1` … `.9`, `.10`) is one set, and mixing
/// widths for one base is not.
#[test]
fn unpadded_parts_join_but_mixed_widths_refuse() {
    let dir = split_dir("unpadded");
    let total = payload(30_000);
    for (i, c) in total.chunks(10_000).enumerate() {
        std::fs::write(dir.join(format!("Clip.avi.{}", i + 1)), c).unwrap();
    }
    let sets = collect_split_sets(&dir).unwrap();
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].parts.len(), 3);

    // Re-spell part 2 as `.02`: two files now claim index 2 in one base,
    // and neither width rule holds across the run.
    std::fs::rename(dir.join("Clip.avi.2"), dir.join("Clip.avi.02")).unwrap();
    assert!(
        collect_split_sets(&dir).unwrap().is_empty(),
        "a mixed-width run is not a set we understand"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sizes are the cheapest evidence that a run of names is one payload. A
/// middle part of a different size is not a byte split.
#[test]
fn ragged_part_sizes_refuse() {
    let dir = split_dir("ragged");
    std::fs::write(dir.join("Notes.txt.001"), payload(10_000)).unwrap();
    std::fs::write(dir.join("Notes.txt.002"), payload(9_000)).unwrap();
    std::fs::write(dir.join("Notes.txt.003"), payload(10_000)).unwrap();
    assert!(collect_split_sets(&dir).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// An evenly divided payload leaves the LAST part full-size. That is a
/// normal split, not a ragged one.
#[test]
fn an_evenly_divided_payload_still_joins() {
    let dir = split_dir("even");
    let total = payload(200_000);
    write_parts(&dir, "Even.bin", &total, 100_000);
    let sets = collect_split_sets(&dir).unwrap();
    assert_eq!(sets.len(), 1);
    assert!(join_split_sets(&dir, &sets));
    assert_eq!(std::fs::read(dir.join("Even.bin")).unwrap(), total);
    let _ = std::fs::remove_dir_all(&dir);
}

/// PAR2 recovery data is an INPUT to repair and is never joinable payload -
/// by packet magic, by `.par2` name, and by the `.volNNN+NNN` slice marker.
/// The joiner deletes what it joins, so all three have to hold.
#[test]
fn par2_recovery_data_is_never_joined() {
    let dir = split_dir("par2");
    // By magic: extensionless obfuscated recovery volumes named `.00N`.
    let mut packet = b"PAR2\x00PKT".to_vec();
    packet.extend(payload(10_000 - 8));
    std::fs::write(dir.join("obf.001"), &packet).unwrap();
    std::fs::write(dir.join("obf.002"), payload(10_000)).unwrap();
    // By name: a `.par2` base, and a `.vol` slice base.
    for base in ["set.par2", "set.vol000+01"] {
        std::fs::write(dir.join(format!("{base}.001")), payload(10_000)).unwrap();
        std::fs::write(dir.join(format!("{base}.002")), payload(10_000)).unwrap();
    }
    assert!(collect_split_sets(&dir).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Bases the RAR/7z/zip arms own are refused by NAME as well as by magic,
/// so a headerless first part (a decoy, a truncated grab) is left for the
/// arm that owns it to report rather than joined into an opaque blob.
#[test]
fn bases_other_arms_own_are_refused_by_name() {
    let dir = split_dir("owned-bases");
    for base in ["a.rar", "b.7z", "c.zip", "d.r01", "e.z01", "f.rev"] {
        std::fs::write(dir.join(format!("{base}.001")), payload(10_000)).unwrap();
        std::fs::write(dir.join(format!("{base}.002")), payload(5_000)).unwrap();
    }
    assert!(collect_split_sets(&dir).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A run that does not start at 1 is not a split set - and `.000` first is
/// the shape a junk same-stem file makes, which is exactly how a valid set
/// once got dropped on the zip side.
#[test]
fn a_run_that_does_not_start_at_one_refuses() {
    let dir = split_dir("no-start");
    std::fs::write(dir.join("Movie.mkv.002"), payload(10_000)).unwrap();
    std::fs::write(dir.join("Movie.mkv.003"), payload(5_000)).unwrap();
    assert!(collect_split_sets(&dir).unwrap().is_empty());
    std::fs::write(dir.join("Movie.mkv.000"), payload(10_000)).unwrap();
    assert!(
        collect_split_sets(&dir).unwrap().is_empty(),
        "index 0 does not make the run start at 1"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Joining is never an overwrite: an existing file with the base's name
/// refuses the set outright.
#[test]
fn an_existing_output_name_refuses_the_set() {
    let dir = split_dir("collide");
    let total = payload(20_000);
    write_parts(&dir, "Movie.mkv", &total, 10_000);
    std::fs::write(dir.join("Movie.mkv"), b"something already here").unwrap();
    assert!(collect_split_sets(&dir).unwrap().is_empty());
    assert_eq!(
        std::fs::read(dir.join("Movie.mkv")).unwrap(),
        b"something already here"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A lone part is not a set, and neither is a name that merely ends in
/// digits.
#[test]
fn a_single_part_and_a_long_digit_tail_are_not_sets() {
    let dir = split_dir("not-sets");
    std::fs::write(dir.join("Movie.mkv.001"), payload(10_000)).unwrap();
    std::fs::write(dir.join("Movie.2019.12345"), payload(10_000)).unwrap();
    std::fs::write(dir.join("Movie.2019.12346"), payload(10_000)).unwrap();
    assert!(collect_split_sets(&dir).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// M10 (read-only sweep 2): an archive somewhere in the directory used to
/// suppress the join of a completely unrelated split payload, because the
/// arm ran only when nothing above it had claimed anything. A `subs.zip`
/// beside a byte-split `Movie.mkv` therefore exited 0 with the subtitles
/// extracted, both parts still on disk, and no `Movie.mkv` at all.
#[test]
fn a_zip_beside_a_plain_split_does_not_suppress_the_join() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let dir = split_dir("zip-beside-split");
    let subs = payload(4_000);
    std::fs::write(
        dir.join("subs.zip"),
        zip_of(&[Spec::stored("subs.srt", &subs)]),
    )
    .unwrap();
    let total = payload(250_000);
    let parts = write_parts(&dir, "Movie.mkv", &total, 100_000);

    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert_eq!(
        std::fs::read(dir.join("subs.srt")).unwrap(),
        subs,
        "the zip arm still produced its payload"
    );
    assert_eq!(
        sha256(&std::fs::read(dir.join("Movie.mkv")).unwrap()),
        sha256(&total),
        "the unrelated split was joined too"
    );
    for p in &parts {
        assert!(!p.exists(), "{} is spent and removed", p.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same suppression through the RAR arm, which is the one that fires
/// first and is by far the commonest thing to find beside a split payload.
#[test]
fn a_rar_beside_a_plain_split_does_not_suppress_the_join() {
    use nzbkit::rar::fixtures;
    let dir = split_dir("rar-beside-split");
    let extra = payload(9_000);
    let n = extra.len() as u64;
    std::fs::write(
        dir.join("sample.rar"),
        fixtures::rar5_volume(&[("sample.mkv", n, &extra, false, false)]),
    )
    .unwrap();
    let total = payload(250_000);
    let parts = write_parts(&dir, "Movie.mkv", &total, 100_000);

    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert_eq!(
        std::fs::read(dir.join("sample.mkv")).unwrap(),
        extra,
        "the RAR arm still produced its member"
    );
    assert_eq!(
        sha256(&std::fs::read(dir.join("Movie.mkv")).unwrap()),
        sha256(&total),
        "the unrelated split was joined too"
    );
    for p in &parts {
        assert!(!p.exists(), "{} is spent and removed", p.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of M10, and the reason the arm was gated in the first
/// place: numeric parts an EARLIER ARM PRODUCED are output, never input.
/// An archive whose members happen to be named `.001`/`.002` must land
/// them and stop - joining them would fabricate a file the post never had
/// and delete the two the user actually downloaded.
#[test]
fn numeric_parts_an_arm_produced_are_never_joined() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let dir = split_dir("produced-parts");
    let inner = payload(60_000);
    std::fs::write(
        dir.join("pack.zip"),
        zip_of(&[
            Spec::stored("Nested.bin.001", &inner[..30_000]),
            Spec::stored("Nested.bin.002", &inner[30_000..]),
        ]),
    )
    .unwrap();

    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert!(dir.join("Nested.bin.001").exists(), "part 1 landed");
    assert!(dir.join("Nested.bin.002").exists(), "part 2 landed");
    assert!(
        !dir.join("Nested.bin").exists(),
        "an arm's OUTPUT is never the joiner's input"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A set that was refused for a reason of its own is still refused when an
/// unrelated archive shares the directory: the hoisted collector changes
/// WHEN the set is looked for, never WHICH sets are safe.
#[test]
fn a_holed_split_beside_an_archive_is_still_refused() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let dir = split_dir("holed-beside-zip");
    let subs = payload(4_000);
    std::fs::write(
        dir.join("subs.zip"),
        zip_of(&[Spec::stored("subs.srt", &subs)]),
    )
    .unwrap();
    let total = payload(400_000);
    let parts = write_parts(&dir, "Movie.mkv", &total, 100_000);
    std::fs::remove_file(&parts[2]).unwrap(); // a MIDDLE part

    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert!(
        !dir.join("Movie.mkv").exists(),
        "a hole in the run refuses the set, archive or no archive"
    );
    for p in [&parts[0], &parts[1], &parts[3]] {
        assert!(p.exists(), "{} is untouched", p.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Write `total` as `name.001`/`.002` in two parts, the first the larger.
fn write_two_parts(dir: &std::path::Path, name: &str, total: &[u8]) -> Vec<PathBuf> {
    write_parts(dir, name, total, total.len().div_ceil(2))
}

/// M11 (read-only sweep 2): a byte-split `.cbz` is a split of the
/// DELIVERABLE, not a split archive to open. The final-name guard looked
/// at the on-disk filename - whose extension is `.001` - so it never saw
/// `cbz`, bare numeric grouping sniffed the zip magic in part 1, and the
/// set was routed through zip extraction. The joiner refused it in the
/// same breath, for carrying archive magic. Result: `page.bin` extracted,
/// `comic.cbz` never created.
#[test]
fn a_split_cbz_is_rejoined_not_unpacked() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let dir = split_dir("split-cbz");
    let page = payload(120_000);
    let cbz = zip_of(&[Spec::stored("page.bin", &page)]);
    let parts = write_two_parts(&dir, "comic.cbz", &cbz);
    assert_eq!(parts.len(), 2);

    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert_eq!(
        sha256(&std::fs::read(dir.join("comic.cbz")).unwrap()),
        sha256(&cbz),
        "the comic is the payload, reassembled byte for byte"
    );
    assert!(
        !dir.join("page.bin").exists(),
        "a final payload's INSIDES are never extracted"
    );
    for p in &parts {
        assert!(!p.exists(), "{} is spent and removed", p.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same routing covers every ZIP-backed entry in `FINAL_FILE_EXTS`,
/// so the fix is the extension list, not a `.cbz` special case.
#[test]
fn split_epub_and_office_payloads_are_rejoined_too() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    for (name, member) in [
        ("book.epub", "OEBPS/ch1.xhtml"),
        ("sheet.xlsx", "xl/worksheets/sheet1.xml"),
    ] {
        let dir = split_dir(&format!("split-{name}"));
        let body = payload(90_000);
        let bytes = zip_of(&[Spec::stored(member, &body)]);
        write_two_parts(&dir, name, &bytes);

        assert_eq!(
            extract_one_level(&dir, None, 0).unwrap(),
            Some(NestOutcome::Produced),
            "{name}"
        );
        assert_eq!(
            sha256(&std::fs::read(dir.join(name)).unwrap()),
            sha256(&bytes),
            "{name} is reassembled, not opened"
        );
        assert!(
            !dir.join(member).exists() && !dir.join("OEBPS").exists() && !dir.join("xl").exists(),
            "{name} was unpacked"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The other direction, and the one the standing rules protect: a real
/// byte-split ZIP CONTAINER still belongs to the zip arm. Neither the
/// declared `.zip.001` spelling nor the bare-numeric one may fall through
/// to the joiner and be published as an opaque blob.
#[test]
fn a_split_zip_container_still_routes_to_the_zip_arm() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let inner = payload(80_000);
    for base in ["release.zip", "blob"] {
        let dir = split_dir(&format!("split-container-{base}"));
        let bytes = zip_of(&[Spec::stored("inner.bin", &inner)]);
        write_two_parts(&dir, base, &bytes);

        assert_eq!(
            extract_one_level(&dir, None, 0).unwrap(),
            Some(NestOutcome::Produced),
            "{base}"
        );
        assert_eq!(
            std::fs::read(dir.join("inner.bin")).unwrap(),
            inner,
            "{base} was opened by the zip arm"
        );
        assert!(
            !dir.join(base).exists(),
            "{base} was never joined into a blob"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// TODO 212, the ladder-level half. A header-encrypted `.7z.NNN` set the
/// 7z arm cannot open (wrong password) must NOT then be rejoined by step
/// 7's container rescue: the arm already read the parts as one byte-space
/// and a join publishes the same bytes, so the rescue could only write
/// the payload a second time and delete the parts. The parts stay, byte
/// for byte, and nothing else appears. The same set opens with its key,
/// through the same arm, with nothing joined along the way.
#[test]
fn a_split_header_encrypted_7z_is_never_rejoined_by_the_rescue() {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, Password, encoder_options::AesEncoderOptions};
    let inner = payload(120_000);
    let bytes = {
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.set_encrypt_header(true);
        w.set_content_methods(vec![
            AesEncoderOptions::new(Password::from("todo-212-ladder")).into(),
        ]);
        w.push_archive_entry(ArchiveEntry::new_file("inner.bin"), Some(&inner[..]))
            .unwrap();
        w.finish().unwrap().into_inner()
    };
    for (pw, opens) in [(Some("wrong"), false), (Some("todo-212-ladder"), true)] {
        let dir = split_dir(&format!("mhe-7z-{}", if opens { "key" } else { "nokey" }));
        write_two_parts(&dir, "release.7z", &bytes);
        let before = sha256(
            &[
                std::fs::read(dir.join("release.7z.001")).unwrap(),
                std::fs::read(dir.join("release.7z.002")).unwrap(),
            ]
            .concat(),
        );
        let verdict = extract_one_level(&dir, pw, 0).unwrap();
        assert!(
            !dir.join("release.7z").exists(),
            "{pw:?}: the parts were joined into release.7z"
        );
        if opens {
            assert_eq!(verdict, Some(NestOutcome::Produced), "{pw:?}");
            assert_eq!(std::fs::read(dir.join("inner.bin")).unwrap(), inner);
        } else {
            assert_ne!(verdict, Some(NestOutcome::Produced), "{pw:?}");
            assert!(!dir.join("inner.bin").exists());
            let after = sha256(
                &[
                    std::fs::read(dir.join("release.7z.001")).unwrap(),
                    std::fs::read(dir.join("release.7z.002")).unwrap(),
                ]
                .concat(),
            );
            assert_eq!(
                before, after,
                "the parts must be left exactly as they landed"
            );
            let mut names: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            assert_eq!(
                names,
                ["release.7z.001", "release.7z.002"],
                "nothing else may be left behind"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A split final payload gets no relaxation it has not earned: the set
/// still has to be a set. A hole in the run refuses it, and the parts stay
/// exactly where they landed.
#[test]
fn a_holed_split_cbz_is_still_refused() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let dir = split_dir("holed-cbz");
    let page = payload(180_000);
    let cbz = zip_of(&[Spec::stored("page.bin", &page)]);
    let parts = write_parts(&dir, "comic.cbz", &cbz, cbz.len().div_ceil(3));
    assert_eq!(parts.len(), 3);
    std::fs::remove_file(&parts[1]).unwrap(); // the MIDDLE part

    extract_one_level(&dir, None, 0).unwrap();
    assert!(!dir.join("comic.cbz").exists(), "a holed run is not a set");
    assert!(!dir.join("page.bin").exists(), "and it is not unpacked");
    for p in [&parts[0], &parts[2]] {
        assert!(p.exists(), "{} is untouched", p.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 211, the headline case: a single store `.rar` cut into numbered
/// parts. Part 1 is a RAR head over a fraction of an archive, so the RAR
/// arm fails on it (`input is too short`) exactly as it does in the field;
/// the container rescue then joins the parts, the ordinary path extracts
/// the archive, and the payload lands. Measured before the fix: rc=1 with
/// every part still on disk and nothing delivered.
///
/// "The RAR arm fails" is a two-rung ladder, and the second rung is the
/// external `unrar` subprocess. This test needs BOTH to fail before the
/// rescue is reached, and the exact-listing assertions below need the
/// failed attempts to have left nothing behind. That used to hold only
/// because no dev box and no CI runner has an `unrar` on `$PATH`; it
/// holds by construction now, because the hatch is closed for the whole
/// unit-test build (`rarfix::external_unrar_closed`, which carries the
/// reasoning).
#[test]
fn a_split_of_a_single_rar_is_joined_once_the_rar_arm_fails() {
    use nzbkit::rar::fixtures;
    let dir = split_dir("rar-split");
    let total = payload(240_000);
    let archive = fixtures::rar5_volume(&[("film.mkv", total.len() as u64, &total, false, false)]);
    let parts = write_parts(&dir, "stage.rar", &archive, archive.len().div_ceil(4));
    assert_eq!(parts.len(), 4);

    // The strict scan refuses it twice over - the head on part 1 and the
    // `.rar` base - and the container scan is the only thing that sees it.
    assert!(collect_split_sets(&dir).unwrap().is_empty());
    assert_eq!(collect_container_split_sets(&dir).unwrap().len(), 1);

    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert_eq!(
        sha256(&std::fs::read(dir.join("film.mkv")).unwrap()),
        sha256(&total),
        "the archive member is delivered byte for byte"
    );
    for p in &parts {
        assert!(!p.exists(), "{} is spent and removed", p.display());
    }
    assert!(
        !dir.join("stage.rar").exists(),
        "the container the rescue built is spent too"
    );
    assert!(
        !dir.join(".nzbfast-nest").exists(),
        "the scratch dir is gone"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The rescue replaces the RAR arms' verdict on the container it joined,
/// and ONLY theirs: an unrelated broken archive beside the split set
/// keeps its own failure (Codex F-01). Before the fix the level said
/// `Produced` with the 7z still sitting there unopened.
#[test]
fn a_split_container_rescue_does_not_absolve_an_unrelated_broken_archive() {
    use nzbkit::rar::fixtures;
    let dir = split_dir("rar-split-plus-broken-7z");
    let total = payload(240_000);
    let archive = fixtures::rar5_volume(&[("film.mkv", total.len() as u64, &total, false, false)]);
    write_parts(&dir, "stage.rar", &archive, archive.len().div_ceil(4));
    // A 7z signature over eight bytes: the 7z arm opens it and fails.
    std::fs::write(dir.join("broken.7z"), b"7z\xBC\xAF\x27\x1C\x00\x04").unwrap();

    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Failed),
        "the broken 7z was laundered by the split rescue"
    );
    assert_eq!(
        sha256(&std::fs::read(dir.join("film.mkv")).unwrap()),
        sha256(&total),
        "the rescue itself still delivers the split archive's member"
    );
    assert!(
        dir.join("broken.7z").exists(),
        "a failed archive is never removed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex F-01, 23 Aug 2026. Two container-split sets in one directory: a
/// named final payload (`comic.cb7`, real 7z bytes, byte-split) and an
/// ordinary split `.rar`. The rescue joins both, and the scratch pass
/// returns ONE verdict for the directory. The RAR extracts, so that
/// verdict is `Produced` - and the cleanup loop then deleted every joined
/// file, including the `.cb7` no arm can ever claim (both the 7z arm and
/// the stray-archive door refuse a final name). Its parts had gone with
/// the join, so the deliverable was lost outright. Now it survives, byte
/// for byte, while the spent RAR input is still removed.
#[test]
fn a_joined_final_payload_survives_a_sibling_sets_success() {
    use nzbkit::rar::fixtures;
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
    let dir = split_dir("cb7-beside-rar-split");

    let page = payload(120_000);
    let cb7 = {
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.push_archive_entry(ArchiveEntry::new_file("page.bin"), Some(&page[..]))
            .unwrap();
        w.finish().unwrap().into_inner()
    };
    let cb7_parts = write_two_parts(&dir, "comic.cb7", &cb7);

    let total = payload(240_000);
    let archive = fixtures::rar5_volume(&[("film.mkv", total.len() as u64, &total, false, false)]);
    let rar_parts = write_parts(&dir, "stage.rar", &archive, archive.len().div_ceil(4));

    // Both sets reach the rescue, and only the rescue: the strict scan
    // refuses each of them.
    assert!(collect_split_sets(&dir).unwrap().is_empty());
    assert_eq!(collect_container_split_sets(&dir).unwrap().len(), 2);

    // `Failed`, not `Produced`: the 7z arm sniffed `comic.cb7.001` as an
    // obfuscated single container before the rescue ran and failed on the
    // truncated read, and that verdict is one of the `others` the rescue
    // is not allowed to overwrite. Stale, but conservative - and beside
    // the point here, which is what is left on disk.
    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Failed)
    );
    assert_eq!(
        sha256(&std::fs::read(dir.join("film.mkv")).unwrap()),
        sha256(&total),
        "the split RAR's member is still delivered"
    );
    assert_eq!(
        sha256(&std::fs::read(dir.join("comic.cb7")).unwrap()),
        sha256(&cb7),
        "the joined final payload survives, byte for byte"
    );
    assert!(
        !dir.join("stage.rar").exists(),
        "the spent RAR input is still removed"
    );
    for p in cb7_parts.iter().chain(rar_parts.iter()) {
        assert!(!p.exists(), "{} is spent and removed", p.display());
    }
    assert!(
        !dir.join(".nzbfast-nest").exists(),
        "the scratch dir is gone"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The discriminator, in both directions. A GENUINE numbered volume set
/// carries the `Rar!` signature on every member, and concatenating those
/// would publish garbage and delete the volumes - so a head on any part
/// past the first refuses the set in the container reading too, which is
/// the only reading that forgives a head at all.
#[test]
fn a_head_past_part_one_refuses_the_container_reading() {
    use nzbkit::rar::fixtures;
    let dir = split_dir("headed-parts");
    let total = payload(400_000);
    let half = total.len() / 2 + 1;
    let n = total.len() as u64;
    // A real two-volume set, sized so only the head rule can refuse it.
    std::fs::write(
        dir.join("film.001"),
        fixtures::rar5_volume_n(&[("film.mkv", n, &total[..half], false, true)], 0),
    )
    .unwrap();
    std::fs::write(
        dir.join("film.002"),
        fixtures::rar5_volume_n(&[("film.mkv", n, &total[half..], true, false)], 1),
    )
    .unwrap();
    assert!(
        collect_container_split_sets(&dir).unwrap().is_empty(),
        "every part carries a head: this is a volume set, not a byte split"
    );
    // And a headless part 1 is not a container split either - a decoy or a
    // truncated grab stays with the arm its name names.
    let bare = split_dir("headless-container");
    write_parts(&bare, "release.rar", &payload(60_000), 20_000);
    assert!(collect_container_split_sets(&bare).unwrap().is_empty());
    assert!(collect_split_sets(&bare).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&bare);
}

/// Recovery data never joins, in either reading: the rescue deletes what it
/// joins, and a `.par2`/`.rev` set is an INPUT to the repair that could
/// still save the job.
#[test]
fn the_container_reading_still_refuses_recovery_data() {
    let dir = split_dir("container-par2");
    let mut packet = b"PAR2\x00PKT".to_vec();
    packet.extend(payload(10_000 - 8));
    for base in ["set.par2", "set.rev", "set.vol000+01"] {
        std::fs::write(dir.join(format!("{base}.001")), &packet).unwrap();
        std::fs::write(dir.join(format!("{base}.002")), payload(10_000)).unwrap();
    }
    assert!(collect_container_split_sets(&dir).unwrap().is_empty());
    assert!(collect_split_sets(&dir).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex F-12, the detection half. The rescue has spent the parts by the
/// time it stages the joined container, so a container that cannot be
/// moved into the scratch dir is the ONLY copy of that payload and it is
/// sitting in the output directory unopened. `stage_joined_into` must
/// say so rather than hand the extraction a shorter list.
///
/// A mode-500 scratch directory is a real `EACCES` from `rename(2)` -
/// creating an entry needs write permission on the destination directory
/// - which is why the F-12 audit's "add an injected rename-failure seam"
/// is not needed here. Unix only: Windows has no equivalent that a test
/// can set without an ACL dance.
#[cfg(unix)]
#[test]
fn a_joined_container_that_cannot_be_staged_is_reported_not_dropped() {
    use std::os::unix::fs::PermissionsExt;
    let dir = split_dir("stage-eacces");
    let ok = dir.join("moves.bin");
    let stuck = dir.join("stays.bin");
    std::fs::write(&ok, payload(64)).unwrap();
    std::fs::write(&stuck, payload(64)).unwrap();
    let sub = dir.join("scratch");
    std::fs::create_dir(&sub).unwrap();

    // The positive control, in the same scratch dir while it is still
    // writable: the file moves, comes back in the list, and `moved_all`
    // stands.
    let (staged, moved_all) = stage_joined_into(vec![ok.clone()], &sub);
    assert!(moved_all, "a writable scratch dir stages everything");
    assert_eq!(staged, vec![ok.clone()]);
    assert!(sub.join("moves.bin").is_file() && !ok.exists());

    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(sub.join("probe"), b"x").is_ok() {
        // A root-owned CI container ignores the mode bits, so there is no
        // EACCES to force and the assertions below would be vacuous. Say
        // so rather than pass silently.
        eprintln!("skipping: this process writes a mode-500 directory (running as root?)");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let (staged, moved_all) = stage_joined_into(vec![stuck.clone()], &sub);
    assert!(
        !moved_all,
        "a container that could not be staged must be reported"
    );
    assert!(
        staged.is_empty(),
        "and must not be offered to the extraction as if it had moved"
    );
    assert!(
        stuck.is_file(),
        "the only copy of the joined payload stays exactly where it was"
    );

    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex F-12, the fold half - the part the detection above is useless
/// without. An empty scratch dir extracts to `None`, which is also how
/// the honest "nobody claimed it, so the joined container IS the
/// payload" ending reads; before the fix both mapped to `Produced` and a
/// rescue that had staged nothing certified the job.
///
/// The neighbouring inputs are pinned in the same table so the F-12 arm
/// cannot be widened into one of them by accident.
#[test]
fn an_unstaged_container_is_never_certified_as_the_payload() {
    // Nothing went wrong and nobody claimed the join: the container is
    // the payload, and this is the one `None` that means success.
    assert_eq!(
        rescue_verdict(true, true, None, true),
        NestOutcome::Produced
    );
    // The same `None`, because the container never reached the scratch
    // dir at all.
    assert_eq!(
        rescue_verdict(true, false, None, true),
        NestOutcome::Failed,
        "an empty scratch dir read as a delivered payload (F-12)"
    );
    // And a staging failure is not absolved by a SECOND container that
    // did move and did extract - the first one is still unopened.
    assert_eq!(
        rescue_verdict(true, false, Some(NestOutcome::Produced), true),
        NestOutcome::Failed
    );
    // The two neighbours: a set that would not join, and a lift-back
    // that left output stranded in the scratch dir.
    assert_eq!(
        rescue_verdict(false, true, Some(NestOutcome::Produced), true),
        NestOutcome::Failed
    );
    assert_eq!(
        rescue_verdict(true, true, Some(NestOutcome::Produced), false),
        NestOutcome::Failed
    );
    // A zip gap is carried through rather than promoted to a failure or
    // laundered into a success.
    assert_eq!(
        rescue_verdict(true, true, Some(NestOutcome::ZipGap), true),
        NestOutcome::ZipGap
    );
}

/// The reachability finding TODO 299 asked for, pinned end to end: a
/// plain split set reaches the cleanup sweep with a CLEAN, successful
/// nested pass in front of it - no failure of any kind.
///
/// `extract_nested_why` seeds its recursion with directories that gained
/// a new EXTRACTABLE ARCHIVE, plus the ones that already held one. A
/// subdirectory holding nothing but headless parts is neither, so the
/// join arm never runs there and the pass reports `Produced` - a job that
/// completes. `keep_media_only` then sweeps top level AND one directory
/// down, which is where the parts are.
///
/// Both halves are asserted, because both are load-bearing: the pass must
/// leave the set alone (it is not this arm's to join from up there), and
/// the sweep must then spare it. Before `split_part_set` the second half
/// deleted all three parts and the job still reported Completed.
#[test]
fn a_plain_split_in_a_subfolder_survives_a_clean_nested_pass_and_the_sweep() {
    let _steady = crate::smart::trash_globals_steady();
    let dir = split_dir("subfolder-reach");
    // The video that arms the sweep - here it stands for whatever the
    // outer archive delivered beside the folder it wrote.
    std::fs::write(dir.join("Movie.mkv"), vec![0u8; 8192]).unwrap();
    let sub = dir.join("Extras");
    std::fs::create_dir_all(&sub).unwrap();
    let total = payload(300_000);
    let parts = write_parts(&sub, "Bonus.mkv", &total, 120_000);
    assert_eq!(parts.len(), 3);

    assert_eq!(
        extract_nested(&dir, None, 0).unwrap(),
        NestOutcome::Produced,
        "a clean pass - nothing here failed, and that is the point"
    );
    for p in &parts {
        assert!(
            p.exists(),
            "{} was not joined from the level above",
            p.display()
        );
    }
    crate::smart::keep_media_only(&dir);
    for p in &parts {
        assert!(
            p.exists(),
            "{} is a part of the only copy of that payload",
            p.display()
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
