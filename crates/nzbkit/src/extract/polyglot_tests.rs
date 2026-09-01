//! Archive magic at byte 0 of a file that is not packaging - the
//! offset-0 sniff's name rule, from both sides.
//!
//! Matrix rows M4-75 (hash-named payload) and M4-90 (NAMED payload) are
//! one question asked in two directions, which is why they are one
//! module: whether a name may overrule a container signature. The answer
//! and its reasoning live at [`archive_sniff_eligible_name`]; these are
//! the measurements behind it, and the control arm that keeps the
//! obfuscated path alive.
//!
//! EVERY TEST HERE READS THE ROUTING DECISION, not just the output tree,
//! and that is the point of `slot_plain_by_sniff`. A slot the sniff
//! DECLINED and a slot it attached, chased and then demoted both end as
//! the same byte-exact file on disk, so a test that only reads the tree
//! cannot tell a name gate that held from a container engine that
//! happened to fail. Three of the four arms were measured "safe" that
//! way during this work and were nothing of the kind - the harness had
//! never called `anchor()`, so no chase could run at all.

use super::testutil::*;
use super::*;
use crate::rar::fixtures;

/// Feed one whole file as articles and report (sniff declined, file
/// still byte-identical, what was extracted out of it).
fn route(tag: &str, name: &str, body: &[u8], art: usize) -> (bool, bool, Vec<(String, u64)>) {
    let dir = tmpdir(tag);
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    // Without this the chase arms all decline on `self_weak` and every
    // container fixture reads as safe - see the module note.
    let mut s = 0usize;
    while s < body.len() {
        let e = (s + art).min(body.len());
        ex.write(0, name, body.len() as u64, s as u64, &body[s..e])
            .unwrap();
        s = e;
    }
    let declined = ex.slot_plain_by_sniff(0);
    let rep = finish_within(&ex, 30).unwrap();
    let intact = std::fs::read(dir.join(name))
        .map(|b| b == body)
        .unwrap_or(false);
    let _ = std::fs::remove_dir_all(&dir);
    (declined, intact, rep.extracted)
}

/// A real RAR5 volume holding one inner file.
fn rar_volume() -> Vec<u8> {
    let inner = payload(5_000, 21);
    fixtures::rar5_volume(&[("inner.mkv", 5_000, &inner, false, false)])
}

/// M4-90: a payload name the poster actually gave the file is not
/// overruled by four bytes of container magic.
///
/// Measured on origin/main 30 Aug 2026, before the gate: every one of
/// these was unpacked, `inner.mkv` published, and the named file GONE
/// from the tree, with the job reporting success. The harm is total and
/// silent, which is why the name wins - declining costs the one-pass
/// path and nothing else, since the volume materializes whole and the
/// disk post-pass still unpacks it by magic.
#[test]
fn a_named_payload_is_never_read_as_a_rar_container() {
    let vol = rar_volume();
    for n in [
        "Movie.mkv",
        "Movie.mp4",
        "disc.iso",
        "Subs.srt",
        "Track.flac",
    ] {
        let (declined, intact, extracted) = route(&format!("m490-rar-{n}"), n, &vol, 8_000);
        assert!(declined, "{n}: the sniff must not attach a RAR mapper");
        assert!(intact, "{n}: the named payload must survive byte-exact");
        assert!(
            extracted.is_empty(),
            "{n}: nothing may be unpacked out of it"
        );
    }
}

/// M4-90's other half, and the reason both rows are one lane: the 7z
/// attach carried no name rule either. Same fixture shape, same verdict.
#[test]
fn a_named_payload_is_never_read_as_a_sevenz_container() {
    let f = payload(400_000, 102);
    let arch = sevenz_archive(&[("F.bin", &f)], None, false);
    for n in ["Movie.mkv", "Subs.srt", "disc.img"] {
        let (declined, intact, extracted) = route(&format!("m490-7z-{n}"), n, &arch, 6_000);
        assert!(declined, "{n}: the sniff must not attach a 7z chase");
        assert!(intact, "{n}: the named payload must survive byte-exact");
        assert!(
            extracted.is_empty(),
            "{n}: nothing may be unpacked out of it"
        );
    }
}

/// M4-75, and THE CONTROL ARM for both tests above: a hash name is the
/// ABSENCE of evidence, not weaker evidence, so the magic is the
/// strongest thing available and still finalizes. This is what stops
/// anybody closing a future polyglot report by widening the deny list
/// onto `.bin` or onto extensionless names - doing so takes every
/// obfuscated set in production with it, and this test says so.
///
/// It is also what makes the two tests above mean anything. The SAME
/// bytes are fed here, so a fixture that had quietly stopped being a
/// container would fail HERE rather than passing there for the wrong
/// reason.
#[test]
fn an_obfuscated_payload_still_earns_the_magic_sniff() {
    let vol = rar_volume();
    for n in [
        "d41d8cd98f00b204",
        "bbbb1234.bin",
        "v.rar",
        "v.r00",
        "v.001",
    ] {
        let (declined, _, extracted) = route(&format!("m475-rar-{n}"), n, &vol, 8_000);
        assert!(!declined, "{n}: an unidentified name must still be sniffed");
        assert_eq!(
            extracted,
            vec![("inner.mkv".to_string(), 5_000)],
            "{n}: the container must still extract"
        );
    }
    let f = payload(400_000, 102);
    let arch = sevenz_archive(&[("F.bin", &f)], None, false);
    for n in ["d41d8cd98f00b204", "bbbb1234.bin", "pack.7z"] {
        let (declined, _, extracted) = route(&format!("m475-7z-{n}"), n, &arch, 6_000);
        assert!(!declined, "{n}: an unidentified name must still be sniffed");
        assert_eq!(
            extracted,
            vec![("F.bin".to_string(), 400_000)],
            "{n}: the container must still extract"
        );
    }
}

/// The predicate itself. `.bin` is the load-bearing entry and it is an
/// EXCLUSION: this product's own model of an obfuscated post is
/// `bbbb1234.bin`, so denying it would break the path the whole one-pass
/// design exists for. `.cbr`/`.cb7` are excluded by `is_final_name`
/// instead, which is a different statement (an archive that IS the
/// deliverable) and must not be merged into this list.
#[test]
fn only_a_name_that_identifies_content_refuses_the_sniff() {
    for n in [
        "Movie.mkv",
        "MOVIE.MKV",
        "s01e01.mp4",
        "disc.iso",
        "Subs.srt",
        "Track.flac",
        "art.jpg",
        "info.nfo",
        "list.sfv",
        "comic.cbr",
        "book.cb7",
    ] {
        assert!(!archive_sniff_eligible_name(n), "{n} identifies content");
    }
    for n in [
        "d41d8cd98f00b204",
        "bbbb1234.bin",
        "v.rar",
        "v.part01.rar",
        "v.r00",
        "v.z99",
        "v.001",
        "pack.7z",
        "pack.7z.001",
        "setup.exe",
        "Movie.mkv.rar",
    ] {
        assert!(archive_sniff_eligible_name(n), "{n} identifies nothing");
    }
}

/// The two arms that ALREADY had this rule, pinned from both sides so a
/// later lane cannot "simplify" one of the four into disagreeing with
/// the others. Their verdicts on the same bytes are what showed the RAR
/// and 7z arms were the odd ones out.
#[test]
fn the_zip_and_tar_arms_answer_a_named_payload_the_same_way() {
    let mut t = vec![0u8; 512];
    t[..9].copy_from_slice(b"inner.bin");
    t[100..107].copy_from_slice(b"0000644");
    t[124..135].copy_from_slice(b"00000002000");
    t[136..147].copy_from_slice(b"00000000000");
    t[148..156].copy_from_slice(b"        ");
    t[156] = b'0';
    t[257..265].copy_from_slice(b"ustar\x0000");
    let sum: u32 = t.iter().map(|&c| c as u32).sum();
    t[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    t.extend(payload(200_000 - 512, 9));
    assert!(crate::tar::looks_like_tar(&t), "the tar fixture must parse");

    let mut z = b"PK\x03\x04".to_vec();
    z.extend(payload(199_996, 7));

    for (kind, body) in [("tar", &t), ("zip", &z)] {
        assert!(
            route(&format!("m495-{kind}-mkv"), "Movie.mkv", body, 8_000).0,
            "{kind}: a named payload must be declined"
        );
        assert!(
            !route(
                &format!("m495-{kind}-hash"),
                "d41d8cd98f00b204",
                body,
                8_000
            )
            .0,
            "{kind}: an obfuscated name must still be sniffed"
        );
    }
}
