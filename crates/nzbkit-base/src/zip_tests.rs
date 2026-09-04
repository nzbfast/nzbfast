use super::*;

fn write(dir: &Path, name: &str, head: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, head).unwrap();
    p
}

fn tmp(tag: &str) -> crate::testscratch::ScratchDir {
    let d = std::env::temp_dir().join(format!("nzbkit-zip-{tag}-{}", std::process::id()));
    crate::testscratch::ScratchDir::attach(&d)
}

const PK: &[u8] = b"PK\x03\x04rest of a local file header";

#[test]
fn single_named_zip() {
    let d = tmp("single");
    write(&d, "movie.zip", PK);
    let f = scan(&d);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].shape, Shape::Single);
    assert_eq!(f[0].name, "movie.zip");
}

#[test]
fn final_files_are_never_containers() {
    let d = tmp("final");
    for n in ["comic.cbz", "book.epub", "sheet.xlsx", "app.apk", "lib.jar"] {
        write(&d, n, PK);
    }
    assert!(
        scan(&d).is_empty(),
        "payload formats must never be unpacked"
    );
    assert!(!is_container(&d.join("comic.cbz")));
    assert!(!name_is_zip_shaped("comic.cbz"));
}

/// T6: `Path::extension()` answers `Some("")` on `comic.cbz.` and
/// `Some("cbz ")` on `comic.cbz ` - neither matches the deny list, so
/// both used to read as "not a payload file" and earned the zip chase,
/// which is exactly the data loss `final_files_are_never_containers`
/// exists to prevent. The RAR-family twin is pinned in
/// `extract::mod_tests::a_trailing_dot_or_space_does_not_defeat_is_final_name`.
#[test]
fn a_trailing_dot_or_space_does_not_defeat_final_file_names() {
    let d = tmp("final-trailing");
    for n in ["comic.cbz.", "comic.cbz..", "comic.cbz ", "comic.CBZ"] {
        write(&d, n, PK);
    }
    assert!(
        scan(&d).is_empty(),
        "payload names with a trailing dot, space or bare case change must never be unpacked"
    );
}

#[test]
fn named_non_zip_is_never_sniffed() {
    // A .bin/.dat that happens to start with PK is not ours to open:
    // sniffing named files is exactly how a .cbz gets destroyed.
    let d = tmp("named");
    write(&d, "payload.bin", PK);
    assert!(scan(&d).is_empty());
    assert!(!is_container(&d.join("payload.bin")));
}

#[test]
fn spanned_set_puts_the_zip_last() {
    // The trailing `.zip` holds the central directory: read order is
    // z01, z02, …, zip - NOT lexical order.
    let d = tmp("spanned");
    write(&d, "movie.z02", b"part two");
    write(&d, "movie.zip", b"central directory");
    write(&d, "movie.z01", PK);
    let f = scan(&d);
    assert_eq!(f.len(), 1, "one set, not three containers");
    assert_eq!(f[0].shape, Shape::Spanned);
    assert_eq!(f[0].name, "movie.zip");
    let names: Vec<String> = f[0].parts.iter().map(|p| file_name(p)).collect();
    assert_eq!(names, ["movie.z01", "movie.z02", "movie.zip"]);
}

#[test]
fn byte_split_named_parts() {
    // The shape that matched nothing before and completed silently.
    let d = tmp("split");
    write(&d, "movie.zip.002", b"two");
    write(&d, "movie.zip.001", PK);
    let f = scan(&d);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].shape, Shape::ByteSplit);
    let names: Vec<String> = f[0].parts.iter().map(|p| file_name(p)).collect();
    assert_eq!(names, ["movie.zip.001", "movie.zip.002"]);
}

#[test]
fn bare_numeric_parts_need_the_magic() {
    let d = tmp("numeric");
    write(&d, "movie.001", PK);
    write(&d, "movie.002", b"two");
    // A RAR numeric set in the same directory must not be claimed.
    write(&d, "other.001", b"Rar!\x1a\x07\x01\x00");
    write(&d, "other.002", b"two");
    let f = scan(&d);
    assert_eq!(f.len(), 1, "only the PK-headed set is a zip");
    assert_eq!(f[0].name, "movie.001");
    let names: Vec<String> = f[0].parts.iter().map(|p| file_name(p)).collect();
    assert_eq!(names, ["movie.001", "movie.002"]);
}

#[test]
fn a_junk_dot_000_does_not_hide_the_valid_set() {
    // Codex sweep 3 Aug M8: `.000` grouped with `.001`/`.002` and,
    // sorting first, was the one part the magic gate sniffed - a
    // junk same-stem `.000` made the whole valid split set vanish.
    let d = tmp("numeric-000");
    write(&d, "movie.000", b"junk sidecar, not an archive");
    write(&d, "movie.001", PK);
    write(&d, "movie.002", b"two");
    let f = scan(&d);
    assert_eq!(f.len(), 1, "the .001/.002 set must still be found");
    assert_eq!(f[0].shape, Shape::ByteSplit);
    let names: Vec<String> = f[0].parts.iter().map(|p| file_name(p)).collect();
    assert_eq!(names, ["movie.001", "movie.002"], ".000 is not a part");
}

#[test]
fn a_split_final_payload_is_not_a_container() {
    // Read-only sweep 2 M11: `comic.cbz.001`/`.002` is a byte-split of
    // the COMIC. The final-name rule looked at the on-disk name, whose
    // extension is `.001`, so it never saw `cbz` - the set grouped here,
    // part 1 sniffed the zip magic, and the pages were extracted while
    // `comic.cbz` was never written. The name survives the suffix.
    let d = tmp("final-split");
    for base in ["comic.cbz", "book.epub", "sheet.xlsx", "app.apk"] {
        write(&d, &format!("{base}.001"), PK);
        write(&d, &format!("{base}.002"), b"two");
    }
    assert!(
        scan(&d).is_empty(),
        "a split payload is the plain joiner's, not the zip arm's"
    );
    // And the stream side, which declares its sets from the NZB's own
    // file list before a byte lands.
    for base in ["comic.cbz", "book.epub", "sheet.xlsx", "app.apk"] {
        assert!(
            numeric_split_part_name(&format!("{base}.001")).is_none(),
            "{base}.001 must not declare a zip split"
        );
    }
    // The shapes either side of it are untouched: a bare-numeric set with
    // no final extension is still a zip candidate, and a declared
    // `.zip.NNN` set still is too.
    assert_eq!(
        numeric_split_part_name("Movie.001"),
        Some(("movie".into(), 1))
    );
    assert_eq!(
        split_part_name("comic.cbz.zip.001"),
        Some(("comic.cbz.zip".into(), 1)),
        "a real zip OF a comic is still a container"
    );
}

#[test]
fn obfuscated_extensionless_container() {
    let d = tmp("obf");
    write(&d, "a3f9c1d2e", PK);
    write(&d, "b7e2", b"not an archive at all");
    let f = scan(&d);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].name, "a3f9c1d2e");
}

#[test]
fn spanning_markers_count_as_magic() {
    let d = tmp("marker");
    write(&d, "marked", b"PK\x07\x08rest");
    write(&d, "marked2", b"PK00rest");
    assert_eq!(scan(&d).len(), 2);
}

#[test]
fn empty_archive_signature_is_not_enough() {
    let d = tmp("eocd");
    write(&d, "nothing", b"PK\x05\x06\x00\x00\x00\x00");
    assert!(scan(&d).is_empty());
}

#[test]
fn two_independent_zips_are_two_findings() {
    let d = tmp("two");
    write(&d, "a.zip", PK);
    write(&d, "b.zip", PK);
    assert_eq!(scan(&d).len(), 2);
}

#[test]
fn name_shape_covers_what_a_nzb_can_show() {
    for n in [
        "Movie.zip",
        "MOVIE.ZIP",
        "movie.zipx",
        "movie.z01",
        "movie.zip.001",
    ] {
        assert!(name_is_zip_shaped(n), "{n} should read as zip-packed");
    }
    for n in [
        "movie.rar",
        "movie.r01",
        "movie.7z",
        "movie.7z.001",
        "movie.001",
        "movie",
    ] {
        assert!(!name_is_zip_shaped(n), "{n} must not read as zip-packed");
    }
}

// -- reader ---------------------------------------------------------

use fixtures::Spec;

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Write a container to disk and open it.
fn open_bytes(
    tag: &str,
    bytes: &[u8],
) -> (crate::testscratch::ScratchDir, Result<Archive, ZipError>) {
    let d = tmp(tag);
    let p = write(&d, "c.zip", bytes);
    let a = Archive::open(&[p]);
    (d, a)
}

fn extract(a: &Archive, i: usize) -> Result<Vec<u8>, ZipError> {
    let mut out = Vec::new();
    a.read_entry_to(&a.entries()[i], &mut out)?;
    Ok(out)
}

#[test]
fn stored_and_deflated_entries_round_trip() {
    let a_data = payload(50_000, 3);
    let b_data = payload(30_000, 9);
    let z = fixtures::zip_of(&[
        Spec::stored("a.bin", &a_data),
        Spec::deflated("b.bin", &b_data),
    ]);
    let (_d, ar) = open_bytes("rd-ok", &z);
    let ar = ar.unwrap();
    assert_eq!(ar.entries().len(), 2);
    assert_eq!(extract(&ar, 0).unwrap(), a_data);
    assert_eq!(extract(&ar, 1).unwrap(), b_data);
}

/// The CRC is the only thing standing between a damaged-before-posting
/// archive and output that looks successful, so a mismatch must be an
/// ERROR - never bytes the caller goes on to publish.
#[test]
fn a_wrong_stored_crc_is_an_error_not_output() {
    let data = payload(20_000, 5);
    let z = fixtures::zip_of(&[Spec {
        crc_override: Some(0xDEAD_BEEF),
        ..Spec::stored("a.bin", &data)
    }]);
    let (_d, ar) = open_bytes("rd-crc", &z);
    let ar = ar.unwrap();
    assert!(matches!(extract(&ar, 0), Err(ZipError::BadCrc { .. })));
}

/// Declined shapes must name what they hit: "not supported" with no
/// noun is what phase 0 already said, and it taught the user nothing.
#[test]
fn declined_methods_and_encryption_say_which() {
    let data = payload(1000, 7);
    // zstd stands in for the undecodable class now that bzip2 and
    // lzma are decoded (see `bzip2_entries_decode_on_the_disk_path`).
    let z = fixtures::zip_of(&[Spec {
        method: 93,
        ..Spec::stored("a.bin", &data)
    }]);
    let (_d, ar) = open_bytes("rd-zstd", &z);
    let e = extract(&ar.unwrap(), 0).unwrap_err();
    assert!(
        matches!(&e, ZipError::Unsupported(m) if m.contains("zstd")),
        "{e}"
    );

    let z = fixtures::zip_of(&[Spec {
        flags: 0x0001,
        ..Spec::stored("a.bin", &data)
    }]);
    let (_d, ar) = open_bytes("rd-enc", &z);
    let ar = ar.unwrap();
    assert!(ar.entries()[0].is_encrypted());
    let e = extract(&ar, 0).unwrap_err();
    assert!(
        matches!(&e, ZipError::Unsupported(m) if m.contains("password")),
        "{e}"
    );
}

/// bzip2 (method 12) decodes on the disk path too. The chase and the
/// disk reader share one decoder factory, but this is the fallback
/// every declined shape lands on, so it is worth pinning directly.
#[test]
fn bzip2_entries_decode_on_the_disk_path() {
    // Compressible: bzip2 EXPANDS random bytes.
    let data: Vec<u8> = (0..90_000u32).map(|i| (i / 613 % 241) as u8).collect();
    let z = fixtures::zip_of(&[Spec::bzip2("a.bin", &data)]);
    let (_d, ar) = open_bytes("rd-bz-ok", &z);
    assert_eq!(extract(&ar.unwrap(), 0).unwrap(), data);
}

/// lzma (method 14) decodes on the disk path too - same decoder
/// factory as the chase, pinned directly for the same reason as
/// bzip2 above.
#[test]
fn lzma_entries_decode_on_the_disk_path() {
    let data: Vec<u8> = (0..90_000u32).map(|i| (i / 613 % 241) as u8).collect();
    let z = fixtures::zip_of(&[Spec::lzma("a.bin", &data)]);
    let (_d, ar) = open_bytes("rd-lzma-ok", &z);
    assert_eq!(extract(&ar.unwrap(), 0).unwrap(), data);
}

/// A symlink entry stores its TARGET as payload; materializing one
/// plants a link pointing wherever the archive likes.
#[test]
fn symlink_entries_are_identifiable() {
    let z = fixtures::zip_of(&[Spec {
        external: 0xA1FF_0000,
        ..Spec::stored("link", b"/etc/passwd")
    }]);
    let (_d, ar) = open_bytes("rd-link", &z);
    assert!(ar.unwrap().entries()[0].is_symlink());
}

#[test]
fn zip64_sizes_are_read_from_the_extra_field() {
    let data = payload(40_000, 11);
    let z = fixtures::zip_of(&[Spec {
        zip64: true,
        ..Spec::stored("big.bin", &data)
    }]);
    let (_d, ar) = open_bytes("rd-z64", &z);
    let ar = ar.unwrap();
    assert_eq!(ar.entries()[0].uncompressed_size, data.len() as u64);
    assert_eq!(extract(&ar, 0).unwrap(), data);
}

/// A stored entry can contain the end-of-central-directory signature.
/// The scan takes the LAST match, so the real record still wins.
#[test]
fn an_eocd_signature_inside_payload_does_not_win() {
    let mut data = payload(5_000, 13);
    data.extend_from_slice(b"PK\x05\x06");
    data.extend_from_slice(&[0u8; 40]);
    let z = fixtures::zip_of(&[Spec::stored("a.bin", &data)]);
    let (_d, ar) = open_bytes("rd-sig", &z);
    let ar = ar.unwrap();
    assert_eq!(ar.entries().len(), 1);
    assert_eq!(extract(&ar, 0).unwrap(), data);
}

/// Build a 22-byte end-of-central-directory record that describes
/// only the FIRST entry of `good`, to be parked in that archive's
/// comment. `stretch` inflates the declared directory size so that
/// the directory "ends" exactly where the forged record begins.
fn forged_eocd(good: &[u8], stretch: bool) -> Vec<u8> {
    let real_at = good.len() - 22;
    let cd_off = rd_u32(&good[real_at + 16..]);
    let rec = cd_off as usize;
    // One central-directory record: 46 + name + extra + comment.
    let one = 46
        + rd_u16(&good[rec + 28..]) as u32
        + rd_u16(&good[rec + 30..]) as u32
        + rd_u16(&good[rec + 32..]) as u32;
    // The comment starts at `good.len()`, so that is where the
    // forged record will sit once it is appended.
    let cd_size = if stretch {
        good.len() as u32 - cd_off
    } else {
        one
    };
    let mut f = Vec::new();
    f.extend_from_slice(b"PK\x05\x06");
    f.extend_from_slice(&0u16.to_le_bytes()); // this disk
    f.extend_from_slice(&0u16.to_le_bytes()); // disk with the directory
    f.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
    f.extend_from_slice(&1u16.to_le_bytes()); // entries in total
    f.extend_from_slice(&cd_size.to_le_bytes());
    f.extend_from_slice(&cd_off.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes()); // comment len
    f
}

/// A forged end-of-central-directory record parked in the archive's
/// own (legal) comment sits AFTER the real one, so the last-match
/// scan picks it - and it can name fewer entries than the directory
/// really holds. Nothing downstream would notice: the entries it
/// does name still pass their CRC, so the job reports success having
/// silently dropped a file. unzip, 7z and bsdtar all read both
/// entries on these bytes; only geometry checks on the record catch
/// it here.
#[test]
fn a_forged_eocd_in_the_comment_never_wins() {
    let a = payload(1_000, 5);
    let b = payload(1_500, 7);
    let specs = [Spec::stored("a.bin", &a), Spec::stored("b.bin", &b)];
    let good = fixtures::zip_of(&specs);
    let (_d, ar) = open_bytes("rd-forge-clean", &good);
    assert_eq!(
        ar.unwrap().entries().len(),
        2,
        "the untouched archive still opens"
    );
    for (tag, stretch) in [("short", false), ("stretched", true)] {
        let z = fixtures::zip_of_with_comment(&specs, &forged_eocd(&good, stretch));
        let (_d, ar) = open_bytes(&format!("rd-forge-{tag}"), &z);
        match ar {
            Err(_) => {}
            Ok(a) => panic!(
                "{tag}: a forged directory opened with {} entries, b.bin vanished silently",
                a.entries().len()
            ),
        }
    }
}

/// A zip that does not start at byte 0. Concatenating a stub in
/// front of a container is how every self-extracting zip is built,
/// and the offsets inside it stay relative to the ARCHIVE - so a
/// reader anchored to byte 0 looks for the directory 511 bytes too
/// low. `unzip` says "extra bytes at beginning or within zipfile"
/// and reads it; 7-Zip says "the archive is open with offset"; we
/// used to decline it as a directory that does not end at its own
/// end record, which described the arithmetic rather than the file.
/// TODO 159 item 2 (`unarr-test_compat_zip_4.zip`, libarchive).
#[test]
fn a_zip_behind_a_prepended_stub_opens_and_extracts() {
    let a = payload(9_000, 21);
    let b = payload(4_000, 22);
    let z = fixtures::zip_of(&[Spec::stored("a.bin", &a), Spec::deflated("b.bin", &b)]);
    for stub in [1usize, 511, 200_000] {
        let mut with = payload(stub, 77);
        with.extend_from_slice(&z);
        let (_d, ar) = open_bytes(&format!("rd-stub-{stub}"), &with);
        let ar = ar.unwrap_or_else(|e| panic!("stub {stub}: {e}"));
        assert_eq!(ar.entries().len(), 2, "stub {stub}");
        assert_eq!(extract(&ar, 0).unwrap(), a, "stub {stub}");
        assert_eq!(extract(&ar, 1).unwrap(), b, "stub {stub}");
    }
}

/// The entry gate for self-extracting zips, and why it reads the
/// TAIL. A forward scan for `PK\x03\x04` is how the RAR and 7z SFX
/// arms find their payload, and for zip it is unusable: stapling a
/// zip onto a binary is the standard way to bundle resources, so the
/// scan claims ordinary programs. Measured over 1,810 real binaries
/// on a Windows box in daily use (1,497 executables, a real
/// `Downloads` history, our own shipped `nzbfast.exe` among them) a
/// head scan claims 98 - every Edge, Chrome and Defender binary on
/// the machine - and this claims 1, the one file that really does
/// carry an appended zip, because only a real archive can satisfy
/// the geometry.
#[test]
fn a_stubbed_zip_is_recognised_and_a_bare_one_is_not() {
    let a = payload(3_000, 51);
    let z = fixtures::zip_of(&[Spec::stored("a.bin", &a)]);
    let d = tmp("stubbed-gate");

    for stub in [1usize, 200_000] {
        let mut with = payload(stub, 81);
        with.extend_from_slice(&z);
        let p = write(&d, "release.exe", &with);
        assert_eq!(
            stubbed_archive(&p),
            Some(Stubbed::Packaging { base: stub as u64 }),
            "stub {stub}"
        );
    }
    // An archive at byte 0 is a bare zip wearing the wrong name, not
    // a self-extractor - the same offset-0 rule the RAR and 7z arms
    // are held to, and the caller routes it elsewhere.
    assert_eq!(stubbed_archive(&write(&d, "bare.exe", &z)), None);
    // Junk cannot pass: there is no end record to anchor to, and a
    // planted one has no directory sitting where its shift implies.
    assert_eq!(
        stubbed_archive(&write(&d, "prog.exe", &payload(100_000, 82))),
        None
    );
    let mut planted = payload(50_000, 83);
    planted.extend_from_slice(b"PK\x05\x06");
    planted.extend_from_slice(&[0u8; 18]);
    assert_eq!(stubbed_archive(&write(&d, "planted.exe", &planted)), None);
}

/// The one shape that DOES satisfy the geometry and must still be
/// left alone: a launcher stub in front of a jar (Launch4j, JSmooth,
/// exe4j), an NW.js resource bundle, or an InstallAnywhere installer.
/// The zip is genuine, so no structural test can refuse it - but it
/// is the deliverable, not packaging, and spraying its contents over
/// the release directory is the data loss `is_final_file` already
/// refuses by extension. The name is gone here, consumed by the stub,
/// so the same list is applied to the entries instead.
///
/// The InstallAnywhere pair is the only one of these found in the
/// wild rather than constructed: TODO 159 item 8 swept a Windows box
/// in daily use and the single structural claim over 1,810 binaries
/// was a vendor installer that unpacked to 7,411 files.
#[test]
fn a_launcher_in_front_of_a_jar_is_the_deliverable_not_packaging() {
    let d = tmp("stubbed-final");
    let cls = payload(2_000, 61);
    for (marker, what) in [
        ("META-INF/MANIFEST.MF", "a Java archive"),
        ("package.json", "an application resource bundle"),
        ("AndroidManifest.xml", "an Android package"),
        ("[Content_Types].xml", "an Office Open XML document"),
        ("mimetype", "an EPUB or OpenDocument file"),
        (
            "InstallerData/IAClasses.zip",
            "an InstallAnywhere installer",
        ),
        (
            "InstallerData/laxmanifest.txt",
            "an InstallAnywhere installer",
        ),
    ] {
        let z = fixtures::zip_of(&[
            Spec::stored(marker, b"marker"),
            Spec::deflated("com/acme/App.class", &cls),
        ]);
        let mut with = payload(4_096, 84);
        with.extend_from_slice(&z);
        let p = write(&d, "app.exe", &with);
        assert_eq!(
            stubbed_archive(&p),
            Some(Stubbed::FinalFile { base: 4_096, what }),
            "{marker} must read as the deliverable"
        );
    }
    // The markers are anchored: a similar name deeper in the tree is
    // payload, not a claim about the container.
    let z = fixtures::zip_of(&[
        Spec::stored("Show.S01E01/mimetype", b"x"),
        Spec::stored("Show.S01E01/notes.txt", b"y"),
    ]);
    let mut with = payload(4_096, 85);
    with.extend_from_slice(&z);
    assert_eq!(
        stubbed_archive(&write(&d, "rel.exe", &with)),
        Some(Stubbed::Packaging { base: 4_096 })
    );
}

/// The prepended stub and zip64 in the SAME archive - each covered
/// on its own, never together. A zip64 writer puts the end record
/// between the directory and the EOCD, so the directory no longer
/// ends where the shortfall arithmetic assumes; with a stub in front
/// the record's own pointer is archive-relative too, and the reader
/// looked for both a byte-count too low. Real writers emit this shape
/// (`zip64_unsaturated.zip` came from Info-ZIP reading stdin);
/// `7zz t` and Python `zipfile` both read the prefixed file.
#[test]
fn a_zip64_archive_behind_a_prepended_stub_opens_and_extracts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip");
    for name in ["zip64_unsaturated.zip", "zip64.zip"] {
        let z = std::fs::read(root.join(name)).unwrap();
        for stub in [1usize, 511, 200_000] {
            let mut with = payload(stub, 77);
            with.extend_from_slice(&z);
            let (_d, ar) = open_bytes(&format!("rd-z64-stub-{stub}"), &with);
            let ar = ar.unwrap_or_else(|e| panic!("{name} stub {stub}: {e}"));
            assert_eq!(ar.entries().len(), 1, "{name} stub {stub}");
            let e = &ar.entries()[0];
            let mut out = Vec::new();
            ar.read_entry_to(e, &mut out)
                .unwrap_or_else(|err| panic!("{name} stub {stub}: {err}"));
            assert_eq!(out.len() as u64, e.uncompressed_size, "{name} stub {stub}");
        }
    }
}

/// The prefixed archive with a SATURATED end record: the geometry
/// comes from the zip64 record, and the locator that points at it
/// stores an archive-relative offset, so following it on a stubbed
/// archive read 511 bytes short of the record.
#[test]
fn a_saturated_zip64_archive_behind_a_prepended_stub_opens_and_extracts() {
    let a = payload(9_000, 21);
    let z = fixtures::zip_of(&[Spec::stored("a.bin", &a)]);
    // Splice a zip64 end record + locator between the directory and
    // the EOCD, and saturate every 32-bit EOCD field, the shape a
    // writer emits once an archive really is too big for them.
    let eocd = z.len() - 22;
    let cd_size = u32::from_le_bytes(z[eocd + 12..eocd + 16].try_into().unwrap()) as u64;
    let cd_off = u32::from_le_bytes(z[eocd + 16..eocd + 20].try_into().unwrap()) as u64;
    let mut out = z[..eocd].to_vec();
    out.extend_from_slice(b"PK\x06\x06");
    out.extend_from_slice(&44u64.to_le_bytes()); // size of the rest
    out.extend_from_slice(&45u16.to_le_bytes()); // version made by
    out.extend_from_slice(&45u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u32.to_le_bytes()); // this disk
    out.extend_from_slice(&0u32.to_le_bytes()); // directory's disk
    out.extend_from_slice(&1u64.to_le_bytes()); // entries on this disk
    out.extend_from_slice(&1u64.to_le_bytes()); // entries total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(b"PK\x06\x07");
    out.extend_from_slice(&0u32.to_le_bytes()); // record's disk
    out.extend_from_slice(&(cd_off + cd_size).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // total disks
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&u16::MAX.to_le_bytes());
    out.extend_from_slice(&u16::MAX.to_le_bytes());
    out.extend_from_slice(&u32::MAX.to_le_bytes());
    out.extend_from_slice(&u32::MAX.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length

    // Unstubbed first: the fixture itself has to be a legal archive.
    let (_d0, ar) = open_bytes("rd-z64sat", &out);
    assert_eq!(extract(&ar.unwrap(), 0).unwrap(), a);
    for stub in [1usize, 511, 200_000] {
        let mut with = payload(stub, 77);
        with.extend_from_slice(&out);
        let (_d, ar) = open_bytes(&format!("rd-z64sat-{stub}"), &with);
        let ar = ar.unwrap_or_else(|e| panic!("stub {stub}: {e}"));
        assert_eq!(extract(&ar, 0).unwrap(), a, "stub {stub}");
    }
}

/// Splice a zip64 end record and its locator between the directory
/// and the EOCD of a plain 32-bit archive, giving the record an
/// extensible data sector of `sector` bytes. `saturate` writes the
/// EOCD's 32-bit copies as -1, the shape a writer emits once the
/// archive really is too big for them.
///
/// §4.3.6 declares the sector's length in ONE place - the record's
/// own size field, which counts every byte after it - so a reader
/// that assumes the record is 56 bytes cannot see the sector at all.
/// The caller supplies the sector's bytes, so a test can plant
/// whatever it likes in there.
fn splice_zip64_end_record(z: &[u8], sector: &[u8], saturate: bool) -> Vec<u8> {
    let eocd = z.len() - 22;
    let entries = rd_u16(&z[eocd + 10..]) as u64;
    let cd_size = rd_u32(&z[eocd + 12..]) as u64;
    let cd_off = rd_u32(&z[eocd + 16..]) as u64;
    let mut out = z[..eocd].to_vec();
    let rec_at = out.len() as u64;
    out.extend_from_slice(b"PK\x06\x06");
    // Size of the record after this field: 44 fixed bytes + the sector.
    out.extend_from_slice(&(44 + sector.len() as u64).to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes()); // version made by
    out.extend_from_slice(&45u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u32.to_le_bytes()); // this disk
    out.extend_from_slice(&0u32.to_le_bytes()); // directory's disk
    out.extend_from_slice(&entries.to_le_bytes()); // entries on this disk
    out.extend_from_slice(&entries.to_le_bytes()); // entries in total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(sector); // the extensible data sector
    out.extend_from_slice(b"PK\x06\x07"); // locator
    out.extend_from_slice(&0u32.to_le_bytes()); // record's disk
    out.extend_from_slice(&rec_at.to_le_bytes()); // ARCHIVE-relative
    out.extend_from_slice(&1u32.to_le_bytes()); // total disks
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    if saturate {
        out.extend_from_slice(&u16::MAX.to_le_bytes());
        out.extend_from_slice(&u16::MAX.to_le_bytes());
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.extend_from_slice(&u32::MAX.to_le_bytes());
    } else {
        out.extend_from_slice(&(entries as u16).to_le_bytes());
        out.extend_from_slice(&(entries as u16).to_le_bytes());
        out.extend_from_slice(&(cd_size as u32).to_le_bytes());
        out.extend_from_slice(&(cd_off as u32).to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

/// The fixture §162 item 3 asked for, and the result it defines.
///
/// A zip64 end record may carry an "extensible data sector" (§4.3.6),
/// which makes the record longer than 56 bytes; its length lives in
/// the record's own size field and nowhere else. Unprefixed, this
/// already opened - the directory's own end names the record's
/// position - so this half is the control, and it is what says the
/// fixture is a legal archive before the prefixed half is asked to
/// open it.
///
/// The sector sizes are 8 (the smallest a writer would bother with),
/// 64, and 1000 (past a single 512-byte block, and past every
/// candidate the fixed-position probe could reach).
#[test]
fn a_zip64_record_with_an_extensible_data_sector_opens() {
    let a = payload(9_000, 21);
    let z = fixtures::zip_of(&[Spec::stored("a.bin", &a)]);
    for saturate in [false, true] {
        for sector in [0usize, 8, 64, 1000] {
            let out = splice_zip64_end_record(&z, &payload(sector, 66), saturate);
            let tag = format!("sec{sector}-sat{saturate}");
            let (_d, ar) = open_bytes(&format!("rd-z64sec-{tag}"), &out);
            let ar = ar.unwrap_or_else(|e| panic!("{tag}: {e}"));
            assert_eq!(ar.entries().len(), 1, "{tag}");
            assert_eq!(extract(&ar, 0).unwrap(), a, "{tag}");
        }
    }
}

/// The same archive with a stub in front - §162 item 3 itself.
///
/// Everything the directory stores is archive-relative, so on a
/// prefixed archive the record's own pointer misses by the stub and
/// the reader has to find the record PHYSICALLY. §4.3.6 puts it
/// immediately before the 20-byte locator, which sits immediately
/// before the EOCD, so its END is pinned at `eocd_at - 20` whatever
/// its length - and its length is what the size field says. A probe
/// that instead assumes 56 bytes reads at `eocd_at - 76`, which is
/// the record's home only when the sector is empty; with a sector it
/// lands INSIDE the record and finds nothing, and the archive is
/// refused.
///
/// The fixture is a legal archive and that is established OUTSIDE
/// this reader, which is the whole point of item 3 asking for one:
/// measured 23 Aug 2026, Python 3.14.6 `zipfile`, Info-ZIP `unzip`
/// 6.00 and 7-Zip 26.02 all open it unprefixed, and `zipfile` opens
/// it again once the 511-byte stub is sliced off. What none of them
/// does is open it PREFIXED. `zipfile` takes its prepended-data
/// branch under the comment "Assume no 'zip64 extensible data'" and
/// raises `BadZipFile`; `unzip` dies with "read failure while
/// seeking for End-of-centdir-64 signature"; 7-Zip declines every
/// prefixed variant of this fixture, sector or not, so it has no
/// opinion on the sector either way. Each of the three reads the
/// sector and the prefix separately and none of them reads both, so
/// the expected result here is the payload - not a parity with any
/// of them.
#[test]
fn a_prefixed_zip64_record_with_an_extensible_data_sector_opens() {
    let a = payload(9_000, 21);
    let z = fixtures::zip_of(&[Spec::stored("a.bin", &a)]);
    for saturate in [false, true] {
        for sector in [8usize, 64, 1000] {
            let out = splice_zip64_end_record(&z, &payload(sector, 66), saturate);
            for stub in [1usize, 511, 200_000] {
                let mut with = payload(stub, 77);
                with.extend_from_slice(&out);
                let tag = format!("sec{sector}-sat{saturate}-stub{stub}");
                let (_d, ar) = open_bytes(&format!("rd-z64sec-stub-{tag}"), &with);
                let ar = ar.unwrap_or_else(|e| panic!("{tag}: {e}"));
                assert_eq!(ar.entries().len(), 1, "{tag}");
                assert_eq!(extract(&ar, 0).unwrap(), a, "{tag}");
            }
        }
    }
}

/// What makes the physical probe safe to widen, now that it no
/// longer reads one fixed position. A sector is arbitrary bytes, so
/// it can carry the end-record signature; a bare signature match
/// would let those bytes name the record's start and shift the whole
/// directory under the parse. Two plants, one for each half of the
/// answer, and the archive must open on the real record either way.
///
/// The first wears the signature and declares a length that does NOT
/// reach the locator, which is the arithmetic doing the work: §4.3.6
/// pins the record's end there, so a candidate whose own `12 + size`
/// lands anywhere else is not the record.
///
/// The second is the harder one - a complete 56-byte record sitting
/// exactly 56 bytes before the locator, so its length DOES reach it
/// and the arithmetic cannot separate the two. What separates them is
/// containment: it is inside the real record's declared extent, and a
/// sector's bytes are data, so the outer match is the record and the
/// inner one is something it carries.
#[test]
fn a_planted_end_record_inside_the_sector_is_not_the_record() {
    let a = payload(9_000, 21);
    let z = fixtures::zip_of(&[Spec::stored("a.bin", &a)]);
    let plant = |reaches: bool| {
        let mut sector = payload(200, 66);
        let at = sector.len() - 56;
        sector[at..at + 4].copy_from_slice(b"PK\x06\x06");
        // 44 puts the plant's end on the locator, which is what makes
        // it a real rival; 40 puts it four bytes short.
        let sz: u64 = if reaches { 44 } else { 40 };
        sector[at + 4..at + 12].copy_from_slice(&sz.to_le_bytes());
        sector
    };
    for reaches in [false, true] {
        for saturate in [false, true] {
            let out = splice_zip64_end_record(&z, &plant(reaches), saturate);
            for stub in [1usize, 511] {
                let mut with = payload(stub, 77);
                with.extend_from_slice(&out);
                let tag = format!("reaches{reaches}-sat{saturate}-stub{stub}");
                let (_d, ar) = open_bytes(&format!("rd-z64plant-{tag}"), &with);
                let ar = ar.unwrap_or_else(|e| panic!("{tag}: {e}"));
                assert_eq!(extract(&ar, 0).unwrap(), a, "{tag}");
            }
        }
    }
}

/// The probe is a bounded READ as well as a bounded accept: the
/// one-pass source blocks on bytes that have not arrived, so how far
/// back of the EOCD it will look is capped. A sector past that cap
/// is refused rather than chased, and the refusal names the shape.
#[test]
fn a_sector_past_the_probe_bound_is_refused_by_name() {
    let a = payload(9_000, 21);
    let z = fixtures::zip_of(&[Spec::stored("a.bin", &a)]);
    let out = splice_zip64_end_record(&z, &payload(8_192, 66), false);
    let mut with = payload(511, 77);
    with.extend_from_slice(&out);
    let (_d, ar) = open_bytes("rd-z64sec-huge", &with);
    match ar {
        Err(ZipError::Malformed(m)) => assert!(
            m.contains("does not start at the beginning of the file"),
            "the reason must name the shape: {m}"
        ),
        Err(e) => panic!("expected the shape to be named, got {e}"),
        Ok(_) => panic!("a sector past the bound opened"),
    }
}

/// The other prepended-stub shape, and the one the libarchive
/// fixture actually is: the stub is there but the writer rewrote
/// every offset to be absolute, so the archive reads from byte 0
/// with no shift at all. It opened before this work and must keep
/// opening - a base offset inferred where none is needed would move
/// the directory out from under the parse.
#[test]
fn a_stub_whose_offsets_were_already_fixed_up_still_opens() {
    let a = payload(3_000, 31);
    let z = fixtures::zip_of(&[Spec::stored("a.bin", &a)]);
    let stub = 511usize;
    let mut with = payload(stub, 78);
    with.extend_from_slice(&z);
    // Rewrite the two directory offsets to absolute: the EOCD's
    // pointer at the directory, and each record's pointer at its
    // local header.
    let eocd = with.len() - 22;
    let cd_off = rd_u32(&with[eocd + 16..]) as usize;
    let abs = (cd_off + stub) as u32;
    with[eocd + 16..eocd + 20].copy_from_slice(&abs.to_le_bytes());
    let rec = cd_off + stub;
    let local = rd_u32(&with[rec + 42..]) as usize + stub;
    with[rec + 42..rec + 46].copy_from_slice(&(local as u32).to_le_bytes());
    let (_d, ar) = open_bytes("rd-stub-absolute", &with);
    let ar = ar.unwrap();
    assert_eq!(ar.entries().len(), 1);
    assert_eq!(extract(&ar, 0).unwrap(), a);
}

/// The shift is inferred from arithmetic, so it is a candidate and
/// not an answer: a directory that is not where the shift implies
/// gets declined, and the reason names the shape instead of blaming
/// an entry. The forged-record defence above rides on this - a
/// planted end record produces a plausible shift too.
#[test]
fn an_implied_shift_with_no_directory_under_it_declines_by_name() {
    let a = payload(2_000, 41);
    let z = fixtures::zip_of(&[Spec::stored("a.bin", &a)]);
    let mut with = payload(511, 79);
    with.extend_from_slice(&z);
    // Overstate the directory's SIZE by 8. The shift is the
    // shortfall between where the directory says it ends and where
    // the end record is, so this moves the implied start 8 bytes
    // below the real one - where no record begins. (Overstating the
    // OFFSET instead would be absorbed: the shift is computed from
    // the pair, so a wrong pointer with a right size still lands on
    // the directory.)
    let eocd = with.len() - 22;
    let cd_size = rd_u32(&with[eocd + 12..]);
    with[eocd + 12..eocd + 16].copy_from_slice(&(cd_size + 8).to_le_bytes());
    let (_d, ar) = open_bytes("rd-stub-nodir", &with);
    match ar {
        Err(ZipError::Malformed(m)) => assert!(
            m.contains("does not start at the beginning of the file"),
            "the reason must name the shape: {m}"
        ),
        Err(e) => panic!("expected the shape to be named, got {e}"),
        Ok(a) => panic!(
            "a directory that is not there opened with {} entries",
            a.entries().len()
        ),
    }
}

/// Junk appended after the record is tolerated today and must stay
/// tolerated: the directory is anchored to the record's position,
/// not to the end of the file.
#[test]
fn appended_junk_after_the_record_still_opens() {
    let a = payload(400, 3);
    let b = payload(600, 4);
    let mut z = fixtures::zip_of(&[Spec::stored("a.bin", &a), Spec::stored("b.bin", &b)]);
    z.extend_from_slice(&payload(520, 99));
    let (_d, ar) = open_bytes("rd-junk", &z);
    assert_eq!(ar.unwrap().entries().len(), 2);
}

/// Once the 32-bit fields saturate, the zip64 end record is the
/// authority on the directory's SIZE and per-disk count too, not
/// just its offset and entry total. The committed zip64.zip never
/// reaches this branch (its EOCD fields all fit), so the shape is
/// hand-built here - getting the source of those two fields wrong
/// would refuse every genuinely large archive.
#[test]
fn a_zip64_end_record_supplies_the_directory_geometry() {
    let a = payload(2_000, 11);
    let b = payload(3_000, 12);
    let specs = [Spec::stored("a.bin", &a), Spec::stored("b.bin", &b)];
    let good = fixtures::zip_of(&specs);
    let real_at = good.len() - 22;
    let cd_size = rd_u32(&good[real_at + 12..]) as u64;
    let cd_off = rd_u32(&good[real_at + 16..]) as u64;
    let mut z = good[..real_at].to_vec();
    let z64_at = z.len() as u64;
    z.extend_from_slice(b"PK\x06\x06");
    z.extend_from_slice(&44u64.to_le_bytes()); // size of the rest
    z.extend_from_slice(&45u16.to_le_bytes()); // version made by
    z.extend_from_slice(&45u16.to_le_bytes()); // version needed
    z.extend_from_slice(&0u32.to_le_bytes()); // this disk
    z.extend_from_slice(&0u32.to_le_bytes()); // disk with the directory
    z.extend_from_slice(&2u64.to_le_bytes()); // entries on this disk
    z.extend_from_slice(&2u64.to_le_bytes()); // entries in total
    z.extend_from_slice(&cd_size.to_le_bytes());
    z.extend_from_slice(&cd_off.to_le_bytes());
    z.extend_from_slice(b"PK\x06\x07"); // locator
    z.extend_from_slice(&0u32.to_le_bytes()); // disk holding the record
    z.extend_from_slice(&z64_at.to_le_bytes());
    z.extend_from_slice(&1u32.to_le_bytes()); // total disks
    // Every field the zip64 record supersedes is written saturated,
    // exactly as the spec requires, so a reader that reaches for the
    // 32-bit copy of any of them gets a nonsense answer.
    z.extend_from_slice(b"PK\x05\x06");
    z.extend_from_slice(&0u16.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z.extend_from_slice(&u16::MAX.to_le_bytes());
    z.extend_from_slice(&u16::MAX.to_le_bytes());
    z.extend_from_slice(&u32::MAX.to_le_bytes());
    z.extend_from_slice(&u32::MAX.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    let (_d, ar) = open_bytes("rd-z64-end", &z);
    let ar = ar.unwrap();
    assert_eq!(ar.entries().len(), 2);
    assert_eq!(extract(&ar, 0).unwrap(), a);
    assert_eq!(extract(&ar, 1).unwrap(), b);
}

/// The sibling shape, and the one REAL writers actually emit: a
/// zip64 end record and locator with every 32-bit EOCD field still
/// unsaturated. Info-ZIP writes it whenever the archive used zip64
/// anywhere - a member of 4 GiB or more, or an input of unknown size
/// piped in on stdin - and so does libarchive; the 76 bytes of
/// record plus locator then sit between the directory's end and the
/// EOCD. The directory legally ends at the record, not at the EOCD.
#[test]
fn an_unsaturated_zip64_end_record_is_a_legal_anchor() {
    let a = payload(2_000, 21);
    let b = payload(3_000, 22);
    let specs = [Spec::stored("a.bin", &a), Spec::stored("b.bin", &b)];
    let good = fixtures::zip_of(&specs);
    let real_at = good.len() - 22;
    let cd_size = rd_u32(&good[real_at + 12..]) as u64;
    let cd_off = rd_u32(&good[real_at + 16..]) as u64;
    let mut z = good[..real_at].to_vec();
    let z64_at = z.len() as u64;
    z.extend_from_slice(b"PK\x06\x06");
    z.extend_from_slice(&44u64.to_le_bytes()); // size of the rest
    z.extend_from_slice(&45u16.to_le_bytes()); // version made by
    z.extend_from_slice(&45u16.to_le_bytes()); // version needed
    z.extend_from_slice(&0u32.to_le_bytes()); // this disk
    z.extend_from_slice(&0u32.to_le_bytes()); // disk with the directory
    z.extend_from_slice(&2u64.to_le_bytes()); // entries on this disk
    z.extend_from_slice(&2u64.to_le_bytes()); // entries in total
    z.extend_from_slice(&cd_size.to_le_bytes());
    z.extend_from_slice(&cd_off.to_le_bytes());
    z.extend_from_slice(b"PK\x06\x07"); // locator
    z.extend_from_slice(&0u32.to_le_bytes()); // disk holding the record
    z.extend_from_slice(&z64_at.to_le_bytes());
    z.extend_from_slice(&1u32.to_le_bytes()); // total disks
    // Nothing saturates: the 32-bit copies all fit, which is exactly
    // what makes this the shape the saturation branch never sees.
    z.extend_from_slice(&good[real_at..]);
    let (_d, ar) = open_bytes("rd-z64-unsat", &z);
    let ar = ar.unwrap_or_else(|e| panic!("a legal Info-ZIP-shaped archive was refused: {e}"));
    assert_eq!(ar.entries().len(), 2);
    assert_eq!(extract(&ar, 0).unwrap(), a);
    assert_eq!(extract(&ar, 1).unwrap(), b);
}

#[test]
fn a_directory_entry_is_flagged_and_not_payload() {
    let z = fixtures::zip_of(&[
        Spec::stored("Pack/", b""),
        Spec::stored("Pack/a.bin", b"hello"),
    ]);
    let (_d, ar) = open_bytes("rd-dir", &z);
    let ar = ar.unwrap();
    assert!(ar.entries()[0].is_dir);
    assert!(!ar.entries()[1].is_dir);
}

/// Truncation and junk must be refused, never panic - this parser
/// eats untrusted input.
#[test]
fn malformed_containers_are_refused_without_panicking() {
    let good = fixtures::zip_of(&[Spec::stored("a.bin", &payload(2_000, 17))]);
    let a = payload(700, 19);
    let b = payload(900, 23);
    let two = [Spec::stored("a.bin", &a), Spec::stored("b.bin", &b)];
    let two_bytes = fixtures::zip_of(&two);
    for (tag, bytes) in [
        ("empty", Vec::new()),
        ("tiny", b"PK".to_vec()),
        ("no-eocd", payload(3_000, 1)),
        ("head-only", good[..good.len() / 2].to_vec()),
        (
            "eocd-only",
            b"PK\x05\x06".iter().copied().chain([0u8; 18]).collect(),
        ),
        (
            "forged-eocd-short",
            fixtures::zip_of_with_comment(&two, &forged_eocd(&two_bytes, false)),
        ),
        (
            "forged-eocd-stretched",
            fixtures::zip_of_with_comment(&two, &forged_eocd(&two_bytes, true)),
        ),
    ] {
        let d = tmp(&format!("rd-bad-{tag}"));
        let p = write(&d, "c.zip", &bytes);
        let r = Archive::open(&[p]);
        assert!(r.is_err(), "{tag} should not open");
    }
    // Every byte-prefix of a healthy container: open may succeed or
    // fail, extraction may fail, but nothing may panic.
    for cut in (0..good.len()).step_by(97) {
        let d = tmp("rd-prefix");
        let p = write(&d, "c.zip", &good[..cut]);
        if let Ok(a) = Archive::open(&[p]) {
            for e in a.entries() {
                let mut sink = Vec::new();
                let _ = a.read_entry_to(e, &mut sink);
            }
        }
    }
}

/// A byte-split set is one container cut arbitrarily, so the reader
/// must span the parts without any joining step (no scratch copy).
#[test]
fn a_byte_split_set_reads_across_parts() {
    let data = payload(60_000, 23);
    let z = fixtures::zip_of(&[Spec::deflated("a.bin", &data)]);
    let d = tmp("rd-split");
    let cut = z.len() / 3;
    let p1 = write(&d, "c.zip.001", &z[..cut]);
    let p2 = write(&d, "c.zip.002", &z[cut..cut * 2]);
    let p3 = write(&d, "c.zip.003", &z[cut * 2..]);
    let ar = Archive::open(&[p1, p2, p3]).unwrap();
    assert_eq!(extract(&ar, 0).unwrap(), data);
}

/// Interop: read archives produced by a REAL zip writer (Python's
/// `zipfile`), not just by our own fixture builder - a hand-rolled
/// reader that only ever meets its own writer proves very little.
/// These same files seed the `zip_parse` fuzz corpus.
///
/// Regenerate with `tools/gen-zip-fixtures.py`.
#[test]
fn reads_archives_written_by_a_real_zip_writer() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip");
    let cases = [
        ("store_deflate.zip", 3usize),
        ("commented.zip", 1),
        ("zip64.zip", 1),
        // Written by Info-ZIP from stdin, so the input size was
        // unknown and it emitted a zip64 end record and locator with
        // every 32-bit EOCD field still fitting. No Python-written
        // fixture has that shape, and it is what real writers emit.
        ("zip64_unsaturated.zip", 1),
        ("empty_dirs.zip", 2),
    ];
    for (name, want) in cases {
        let p = root.join(name);
        let a = Archive::open(&[p]).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(a.entries().len(), want, "{name} entry count");
        for e in a.entries() {
            if e.is_dir {
                continue;
            }
            let mut out = Vec::new();
            a.read_entry_to(e, &mut out)
                .unwrap_or_else(|err| panic!("{name}/{}: {err}", e.name));
            // read_entry_to already checks the stored CRC and the
            // declared size, so reaching here IS the assertion.
            assert_eq!(out.len() as u64, e.uncompressed_size);
        }
    }
    // The commented archive is the one that pins the EOCD scan: its
    // record sits ~900 bytes before the end of the file.
    let a = Archive::open(&[root.join("commented.zip")]).unwrap();
    assert_eq!(a.entries()[0].name, "a.bin");
}

/// Interop for phase 3: encrypted archives written by a REAL writer
/// (7-Zip; Python's zipfile cannot write encryption). Same payload,
/// same password, both schemes - ZipCrypto and WinZip AE.
/// Regenerate with `tools/gen-zip-fixtures.py` (needs 7zz).
#[test]
fn reads_encrypted_archives_written_by_a_real_zip_writer() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip");
    let want: Vec<u8> = (0..20000u32).map(|i| ((i * 37 + 11) % 256) as u8).collect();
    for name in ["zipcrypto.zip", "aes256.zip"] {
        let a = Archive::open(&[root.join(name)]).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(a.entries().len(), 1, "{name}");
        let e = &a.entries()[0];
        assert!(e.is_encrypted(), "{name}");
        let mut out = Vec::new();
        a.read_entry_to_with(e, &mut out, Some("SECRET"))
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(out, want, "{name} payload");
        let mut sink = Vec::new();
        assert!(
            matches!(
                a.read_entry_to_with(e, &mut sink, Some("wrong")),
                Err(ZipError::WrongPassword { .. })
            ),
            "{name} must refuse a wrong password"
        );
    }
    // The AES fixture must actually be AE, not ZipCrypto in disguise.
    let a = Archive::open(&[root.join("aes256.zip")]).unwrap();
    assert!(
        a.entries()[0].aes.is_some(),
        "aes256.zip lacks the AE extra field"
    );
}

// -- phase 3: encrypted entries ------------------------------------

fn extract_pw(a: &Archive, i: usize, pw: Option<&str>) -> Result<Vec<u8>, ZipError> {
    let mut out = Vec::new();
    a.read_entry_to_with(&a.entries()[i], &mut out, pw)?;
    Ok(out)
}

/// ZipCrypto round-trips under both methods; the wrong password is
/// refused by the check byte, and no password declines by name.
#[test]
fn zipcrypto_entries_round_trip() {
    let a_data = payload(40_000, 31);
    let b_data = payload(25_000, 33);
    let z = fixtures::zip_of(&[
        Spec {
            encrypt: Some(fixtures::Encrypt::ZipCrypto { password: "s3cret" }),
            ..Spec::stored("a.bin", &a_data)
        },
        Spec {
            encrypt: Some(fixtures::Encrypt::ZipCrypto { password: "s3cret" }),
            ..Spec::deflated("b.bin", &b_data)
        },
    ]);
    let (_d, ar) = open_bytes("zc-ok", &z);
    let ar = ar.unwrap();
    assert!(ar.entries()[0].is_encrypted());
    assert_eq!(extract_pw(&ar, 0, Some("s3cret")).unwrap(), a_data);
    assert_eq!(extract_pw(&ar, 1, Some("s3cret")).unwrap(), b_data);
    assert!(matches!(
        extract_pw(&ar, 0, Some("wrong")),
        Err(ZipError::WrongPassword { .. })
    ));
    let e = extract_pw(&ar, 0, None).unwrap_err();
    assert!(
        matches!(&e, ZipError::Unsupported(m) if m.contains("password-protected")),
        "{e}"
    );
}

/// WinZip AE round-trips at every strength and both vendor
/// versions; AE-2's zeroed CRC field must not fail the check, a
/// wrong password is refused by the verifier, and a tampered
/// ciphertext byte is caught by the HMAC even though CTR would
/// happily decrypt it.
#[test]
fn ae_entries_round_trip_verify_and_authenticate() {
    let data = payload(50_000, 37);
    for (strength, ver) in [(1u8, 1u16), (2, 1), (3, 1), (3, 2)] {
        let z = fixtures::zip_of(&[Spec {
            encrypt: Some(fixtures::Encrypt::Ae {
                password: "hunter2",
                strength,
                vendor_version: ver,
            }),
            ..Spec::deflated("a.bin", &data)
        }]);
        let (_d, ar) = open_bytes(&format!("ae-{strength}-{ver}"), &z);
        let ar = ar.unwrap();
        let e = &ar.entries()[0];
        assert!(e.is_encrypted(), "s{strength} v{ver}");
        if ver == 2 {
            assert_eq!(e.crc32, 0, "AE-2 zeroes the CRC field by spec");
        }
        assert_eq!(
            extract_pw(&ar, 0, Some("hunter2")).unwrap(),
            data,
            "s{strength} v{ver}"
        );
        assert!(matches!(
            extract_pw(&ar, 0, Some("wrong")),
            Err(ZipError::WrongPassword { .. })
        ));
    }
    // Tamper: the verifier accepts (password is right), the HMAC
    // must refuse - never publish unauthenticated plaintext.
    let z = fixtures::zip_of(&[Spec {
        encrypt: Some(fixtures::Encrypt::Ae {
            password: "hunter2",
            strength: 3,
            vendor_version: 2,
        }),
        tamper: true,
        ..Spec::stored("a.bin", &data)
    }]);
    let (_d, ar) = open_bytes("ae-tamper", &z);
    let e = extract_pw(&ar.unwrap(), 0, Some("hunter2")).unwrap_err();
    assert!(
        matches!(&e, ZipError::Io(err) if err.to_string().contains("authentication failed")),
        "{e}"
    );
}

/// The candidate probe the extraction ladder sweeps a passwords file
/// with: it must answer from each scheme's own verifier, accept the
/// right password and refuse a wrong one, for both schemes.
#[test]
fn password_opens_answers_from_the_entry_verifier() {
    let data = payload(40_000, 11);
    for (tag, enc) in [
        (
            "zipcrypto",
            fixtures::Encrypt::ZipCrypto { password: "pw123" },
        ),
        (
            "ae",
            fixtures::Encrypt::Ae {
                password: "pw123",
                strength: 3,
                vendor_version: 2,
            },
        ),
    ] {
        let d = tmp(&format!("pwopens-{tag}"));
        let p = write(
            &d,
            "c.zip",
            &fixtures::zip_of(&[Spec {
                encrypt: Some(enc),
                ..Spec::deflated("a.bin", &data)
            }]),
        );
        let parts = [p];
        assert!(needs_password(&parts), "{tag}: the lock must be visible");
        assert!(password_opens(&parts, Some("pw123")), "{tag}");
        assert!(!password_opens(&parts, Some("wrong")), "{tag}");
        // No password at all is not a match either - the caller uses
        // this to decide whether it holds the key, and "None opens
        // it" would make every locked container look unlocked.
        assert!(!password_opens(&parts, None), "{tag}");
    }
}

/// A container with nothing encrypted in it needs no password and is
/// opened by any - including none. The extraction ladder relies on
/// that to leave plain zips alone.
#[test]
fn a_plain_container_needs_no_password_and_any_password_opens_it() {
    let data = payload(9_000, 3);
    let d = tmp("pwopens-plain");
    let p = write(
        &d,
        "c.zip",
        &fixtures::zip_of(&[Spec::stored("a.bin", &data)]),
    );
    let parts = [p];
    assert!(!needs_password(&parts));
    assert!(password_opens(&parts, None));
    assert!(password_opens(&parts, Some("anything")));
}

/// An entry whose declared size disagrees with what actually decodes
/// must fail rather than publish a short or over-long file.
#[test]
fn a_size_that_disagrees_with_the_data_is_refused() {
    let data = payload(10_000, 29);
    let mut z = fixtures::zip_of(&[Spec::stored("a.bin", &data)]);
    // Shrink the CD's uncompressed size by one byte (offset 24 of the
    // central record, which starts right after the entry data).
    let cd = z
        .windows(4)
        .position(|w| w == b"PK\x01\x02")
        .expect("central directory");
    let orig = u32::from_le_bytes([z[cd + 24], z[cd + 25], z[cd + 26], z[cd + 27]]);
    z[cd + 24..cd + 28].copy_from_slice(&(orig - 1).to_le_bytes());
    let (_d, ar) = open_bytes("rd-size", &z);
    assert!(extract(&ar.unwrap(), 0).is_err());
}

/// The `LZMA_DICT_MAX` boundary, pinned in BOTH directions.
///
/// The upper half is the ordinary guard: a header may not declare an
/// arbitrary window. The lower half is the one that matters and the
/// reason this test exists - 256 MiB is exactly what `7zz -tzip
/// -mm=LZMA -mx=9` emits (`-mx=7` emits half of it), so a future
/// session "hardening" this constant downward would start REFUSING
/// archives written by stock 7-Zip on Ultra. That failure would look
/// like a user's zip becoming unextractable, which is a worse bug than
/// the allocation the cap exists to bound. Fail loudly instead.
///
/// Both cases declare a one-byte entry, so `LzmaReader` clamps the
/// window to the uncompressed size and neither case allocates a real
/// dictionary - this pins the ACCEPT/REFUSE decision, not the window.
#[test]
fn the_lzma_dictionary_cap_admits_7zips_top_preset_and_nothing_above_it() {
    fn declare(dict: u32) -> std::io::Result<()> {
        let e = Entry {
            name: "a.bin".into(),
            method: METHOD_LZMA,
            crc32: 0,
            compressed_size: 64,
            uncompressed_size: 1,
            is_dir: false,
            flags: 0,
            dos_time: 0,
            aes: None,
            unix_mode: 0,
            local_offset: 0,
        };
        // zip's method-14 framing: version (2), props length (2), then
        // the lc/lp/pb byte and the dictionary size.
        let mut src = vec![0x10, 0x02, 0x05, 0x00, 0x5d];
        src.extend_from_slice(&dict.to_le_bytes());
        src.extend_from_slice(&[0u8; 32]);
        decoder(&e, std::io::Cursor::new(src)).map(|_| ())
    }
    assert!(
        declare(LZMA_DICT_MAX).is_ok(),
        "a 256 MiB dictionary is what 7-Zip's -mx=9 writes - refusing it \
         makes ordinary Ultra-compressed zips unextractable"
    );
    assert!(
        declare(128 << 20).is_ok(),
        "128 MiB is 7-Zip's -mx=7 (Maximum) preset"
    );
    let err = declare(LZMA_DICT_MAX + 1).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("dictionary"), "{err}");
}

/// libFuzzer `zip_parse` artifact
/// `oom-437816e14944e2fc4658651e31e35851fe966516` (21 Aug 2026), kept
/// as an ordinary test because a seed alone only bites on a machine
/// with nightly + cargo-fuzz.
///
/// 139 bytes declaring a 128 MiB dictionary over an 84-byte body and a
/// 2.9 GiB uncompressed size. It is NOT a crash and NOT a leak: the
/// window is refused or honoured by policy (`LZMA_DICT_MAX` admits
/// this one, see above), the stream is then rejected on its own
/// merits, and the point of the pin is that a hostile header leaves by
/// the ordinary error path rather than panicking, aborting or hanging.
/// The fuzzer only flagged it because that lane ran the zip targets
/// under `-malloc_limit_mb=128`, which `fuzz-smoke.yml` applies to the
/// 7z targets alone.
#[test]
fn the_lzma_oom_seed_leaves_by_the_ordinary_error_path() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../nzbkit/fuzz/seeds/zip_parse/oom-437816e14944e2fc4658651e31e35851fe966516"
    ))
    .expect("committed fuzz seed");
    assert_eq!(bytes.len(), 139);
    let (_d, ar) = open_bytes("rd-lzma-oom-seed", &bytes);
    let ar = ar.expect("the central directory itself is well-formed");
    for i in 0..ar.entries().len() {
        // No unwrap: a clean Err is the whole assertion. A panic or an
        // abort here is the regression.
        assert!(
            extract(&ar, i).is_err(),
            "a 2.9 GiB claim behind 84 compressed bytes must not decode"
        );
    }
}

/// The two committed fixtures for §162 item 3, byte-for-byte what
/// [`splice_zip64_end_record`] builds above at a 64-byte sector and a
/// 511-byte stub. They are here because `fuzz-smoke.yml` copies
/// `tests/fixtures/zip/*.zip` into the `zip_parse` corpus, and this
/// shape sits behind a signature AND an exact 8-byte length that has
/// to land on the locator, which no mutator reaches from cold.
///
/// So the pin: a regenerated file must not be allowed to stop being
/// this shape while the test still passes. Both halves are asserted
/// structurally - there is no end record where a 56-byte one would
/// sit (that is the sector), and the locator's pointer does not name
/// a physical position (that is the prefix) - before either is asked
/// to open.
#[test]
fn the_committed_prefixed_sector_fixtures_keep_their_meaning() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip");
    let a = payload(300, 21);
    for name in [
        "zip64_sector_prefixed.zip",
        "zip64_sector_prefixed_saturated.zip",
    ] {
        let blob = std::fs::read(root.join(name)).unwrap();
        let eocd = blob.len() - 22;
        assert_eq!(&blob[eocd..eocd + 4], b"PK\x05\x06", "{name}: no EOCD last");
        assert_eq!(
            &blob[eocd - 20..eocd - 16],
            b"PK\x06\x07",
            "{name}: no locator"
        );
        assert_ne!(
            &blob[eocd - 76..eocd - 72],
            b"PK\x06\x06",
            "{name}: a record at eocd-76 means the sector is gone"
        );
        let reloff = rd_u64(&blob[eocd - 12..]) as usize;
        assert_ne!(
            &blob[reloff..reloff + 4],
            b"PK\x06\x06",
            "{name}: the locator's pointer resolves, so the prefix is gone"
        );
        let (_d, ar) = open_bytes(&format!("rd-z64sec-fx-{name}"), &blob);
        let ar = ar.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(extract(&ar, 0).unwrap(), a, "{name}");
    }
}
