//! TODO 94 C: self-extractors in the one-pass stream. The offset-0 sniff
//! scans the first article for a CONFIRMED archive signature behind a
//! launcher stub and starts the RAR mapper or the 7z chase there; every
//! other shape - a program that is only a program, a stub longer than
//! the article, a compressed RAR the chase cannot take, the wrong name,
//! an SFX one level down - lands on disk byte for byte, which is where
//! the disk post-pass's SFX arm has always found it.

use super::*;
use crate::extract::chase::file_watermark;
use crate::rar::fixtures;

use super::testutil::*;

/// A launcher stub: a structurally valid PE32 image - DOS header with
/// `e_lfanew`, `PE\0\0`, COFF header, optional header, one `.text`
/// section whose raw data fills the rest - generated here rather than
/// checked in as a binary (§116.4c). The section body carries the decoy
/// constants a real stub does (both magics, nothing parseable behind
/// them), so the scan has to step over them to find anything.
///
/// Every field a loader checks first is real: `e_magic`, `e_lfanew`,
/// the signature, machine i386, the 0x10b PE32 magic, section and file
/// alignment, `SizeOfHeaders`, the console subsystem. What is not here
/// is an import table, so it would not RUN - it does not need to; the
/// sniff never executes anything and neither does the post-pass.
pub(super) fn stub(len: usize) -> Vec<u8> {
    assert!(
        len >= 0x400,
        "the headers alone take 0x200, the section starts at 0x200"
    );
    let mut s = vec![0u8; 0x200];
    let le16 = |s: &mut Vec<u8>, at: usize, v: u16| s[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let le32 = |s: &mut Vec<u8>, at: usize, v: u32| s[at..at + 4].copy_from_slice(&v.to_le_bytes());
    // IMAGE_DOS_HEADER: e_magic, e_cblp/e_cp, e_cparhdr, e_lfanew.
    s[0..2].copy_from_slice(b"MZ");
    le16(&mut s, 2, 0x90);
    le16(&mut s, 4, 3);
    le16(&mut s, 8, 4);
    le32(&mut s, 0x3c, 0x80);
    s[0x40..0x40 + 14].copy_from_slice(b"This program\r\n");
    // IMAGE_NT_HEADERS32 at 0x80: signature, IMAGE_FILE_HEADER.
    let nt = 0x80;
    s[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let fh = nt + 4;
    le16(&mut s, fh, 0x14c); // Machine: i386
    le16(&mut s, fh + 2, 1); // NumberOfSections
    le16(&mut s, fh + 16, 0xe0); // SizeOfOptionalHeader (PE32)
    le16(&mut s, fh + 18, 0x0102); // EXECUTABLE_IMAGE | 32BIT_MACHINE
    // IMAGE_OPTIONAL_HEADER32.
    let oh = fh + 20;
    let text_raw = 0x200u32;
    let text_len = (len - 0x200) as u32;
    le16(&mut s, oh, 0x10b); // Magic: PE32
    le32(&mut s, oh + 4, text_len); // SizeOfCode
    le32(&mut s, oh + 16, 0x1000); // AddressOfEntryPoint
    le32(&mut s, oh + 20, 0x1000); // BaseOfCode
    le32(&mut s, oh + 28, 0x0040_0000); // ImageBase
    le32(&mut s, oh + 32, 0x1000); // SectionAlignment
    le32(&mut s, oh + 36, 0x200); // FileAlignment
    le16(&mut s, oh + 40, 4); // MajorOperatingSystemVersion
    le16(&mut s, oh + 48, 4); // MajorSubsystemVersion
    le32(&mut s, oh + 56, 0x1000 + text_len.next_multiple_of(0x1000)); // SizeOfImage
    le32(&mut s, oh + 60, 0x200); // SizeOfHeaders
    le16(&mut s, oh + 68, 3); // Subsystem: console
    le32(&mut s, oh + 72, 0x10_0000); // SizeOfStackReserve
    le32(&mut s, oh + 76, 0x1000); // SizeOfStackCommit
    le32(&mut s, oh + 80, 0x10_0000); // SizeOfHeapReserve
    le32(&mut s, oh + 84, 0x1000); // SizeOfHeapCommit
    le32(&mut s, oh + 92, 16); // NumberOfRvaAndSizes
    // IMAGE_SECTION_HEADER for .text, right after the optional header.
    let sh = oh + 0xe0;
    s[sh..sh + 5].copy_from_slice(b".text");
    le32(&mut s, sh + 8, text_len); // VirtualSize
    le32(&mut s, sh + 12, 0x1000); // VirtualAddress
    le32(&mut s, sh + 16, text_len); // SizeOfRawData
    le32(&mut s, sh + 20, text_raw); // PointerToRawData
    le32(&mut s, sh + 36, 0x6000_0020); // CODE | EXECUTE | READ
    // .text: an entry that returns, the decoys, then filler.
    s.push(0xc3);
    s.extend_from_slice(b"Rar!\x1a\x07\x01\x00");
    s.extend(std::iter::repeat_n(0u8, 40));
    s.extend_from_slice(crate::nameprobe::SEVENZ_MAGIC);
    s.extend(std::iter::repeat_n(0xffu8, 40));
    while s.len() < len {
        let i = s.len();
        s.push((i as u8).wrapping_mul(13).wrapping_add(0x41));
    }
    s.truncate(len);
    s
}

/// The generator's own pin: the head it writes is what a PE parser
/// reads, so a stub that stopped being one would fail here first.
#[test]
fn the_generated_stub_is_a_well_formed_pe32() {
    let s = stub(4_096);
    assert_eq!(&s[..2], b"MZ");
    let lfanew = u32::from_le_bytes(s[0x3c..0x40].try_into().unwrap()) as usize;
    assert_eq!(&s[lfanew..lfanew + 4], b"PE\0\0");
    assert_eq!(
        u16::from_le_bytes(s[lfanew + 4..lfanew + 6].try_into().unwrap()),
        0x14c
    );
    let oh = lfanew + 24;
    assert_eq!(u16::from_le_bytes(s[oh..oh + 2].try_into().unwrap()), 0x10b);
    let sh = oh + 0xe0;
    assert_eq!(&s[sh..sh + 5], b".text");
    let raw = u32::from_le_bytes(s[sh + 20..sh + 24].try_into().unwrap()) as usize;
    let raw_len = u32::from_le_bytes(s[sh + 16..sh + 20].try_into().unwrap()) as usize;
    assert_eq!(raw + raw_len, s.len(), "the section runs to the stub's end");
    assert_eq!(s[raw], 0xc3, "entry point is a `ret`");
    assert_eq!(
        crate::sfx::sfx_payload_at(&s),
        None,
        "decoys alone are not an archive"
    );
}

pub(super) fn sfx(stub_len: usize, archive: &[u8]) -> Vec<u8> {
    let mut f = stub(stub_len);
    f.extend_from_slice(archive);
    f
}

fn run(
    tag: &str,
    name: &str,
    file: &[u8],
    seed: u64,
) -> (crate::testscratch::ScratchDir, ExtractReport) {
    let dir = tmpdir(tag);
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    feed(&ex, 0, name, file, 7000, seed);
    let rep = ex.finish().unwrap();
    (dir, rep)
}

/// A store RAR behind a stub maps in-stream, both dialects: the inner
/// file comes out byte-exact and the `.exe` never touches disk.
#[test]
fn a_store_rar_sfx_maps_in_stream_for_both_dialects() {
    let data = payload(200_000, 31);
    for (t, vol) in [
        fixtures::rar5_volume(&[("a.bin", 0, &data, false, false)]),
        fixtures::rar4_volume(&[("a.bin", 0, &data, false, false)]),
    ]
    .into_iter()
    .enumerate()
    {
        let file = sfx(3_000, &vol);
        let (dir, rep) = run(&format!("sfx-rar{t}"), "pack.exe", &file, 11 + t as u64);
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), data);
        assert_eq!(dir_files(&dir), vec!["a.bin".to_string()]);
    }
}

/// A 7z behind a stub chases in-stream from the stub's length.
#[test]
fn a_seven_zip_sfx_chases_in_stream() {
    let f = payload(150_000, 77);
    let arch = sevenz_archive(&[("F.bin", &f)], None, false);
    let file = sfx(2_500, &arch);
    let (dir, rep) = run("sfx-7z", "pack.exe", &file, 21);
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
}

/// The strict failure mode: a file that looks like a program and has no
/// confirmed archive behind its decoy constants is a plain file, written
/// whole - never mapped from a garbage offset, never demoted.
#[test]
fn a_pe_lookalike_with_no_archive_is_written_whole() {
    let file = stub(40_000);
    let (dir, rep) = run("sfx-pe-only", "setup.exe", &file, 31);
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("setup.exe")).unwrap(), file);
    assert_eq!(dir_files(&dir), vec!["setup.exe".to_string()]);
}

/// Out of the sniff's reach - a stub longer than the offset-0 article,
/// the wrong extension - and the file goes to disk intact for the
/// post-pass, exactly as before.
#[test]
fn a_deep_stub_or_a_non_sfx_name_lands_on_disk_intact() {
    let data = payload(60_000, 5);
    let vol = fixtures::rar5_volume(&[("a.bin", 0, &data, false, false)]);
    for (tag, name, file) in [
        ("sfx-deep", "pack.exe", sfx(9_000, &vol)),
        ("sfx-name", "pack.dat", sfx(3_000, &vol)),
    ] {
        let (dir, rep) = run(tag, name, &file, 41);
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), file, "{tag}");
        assert_eq!(dir_files(&dir), vec![name.to_string()]);
    }
}

/// A COMPRESSED RAR behind a stub chases in-stream (TODO 94 C
/// follow-up): rars' stream parsers want the signature at range 0, so
/// the chase serves the volume through an `OffsetSource` that shifts
/// every read by the stub's length. The member comes out byte-exact and
/// the `.exe` never touches disk - before this the volume demoted whole
/// for the disk post-pass's SFX arm to carve.
#[test]
fn a_compressed_rar_sfx_chases_in_stream() {
    let data = noisy(120_000, 9);
    let vol = rars_compressed_volume(&[("a.bin", &data)]);
    assert_not_store(&vol);
    let file = sfx(3_000, &vol);
    let (dir, rep) = run("sfx-rar-comp", "pack.exe", &file, 51);
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), data);
    assert_eq!(dir_files(&dir), vec!["a.bin".to_string()]);
}

/// The same shape with the chase switched OFF still lands the posted
/// `.exe` on disk byte for byte, stub included - the disk post-pass's
/// SFX arm carves that, and it is the route every compressed SFX took
/// before the chase learned the offset.
#[test]
fn a_compressed_rar_sfx_demotes_to_the_whole_exe_with_the_chase_off() {
    let data = noisy(120_000, 9);
    let vol = rars_compressed_volume(&[("a.bin", &data)]);
    assert_not_store(&vol);
    let file = sfx(3_000, &vol);
    let dir = tmpdir("sfx-rar-comp-off");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_top_level_chase(false);
    feed(&ex, 0, "pack.exe", &file, 7000, 52);
    let rep = ex.finish().unwrap();
    assert_eq!(std::fs::read(dir.join("pack.exe")).unwrap(), file);
    assert_eq!(dir_files(&dir), vec!["pack.exe".to_string()]);
    // ...and the demote says whose it is. The `.exe` on disk is the SFX
    // arm's input, so the caller's RAR unrar ladder has to leave it alone:
    // unmarked, this reason's "compressed" ran that ladder's first arm -
    // `unrar` over a directory holding one `.exe` - which cannot succeed
    // and failed the job. Measured against the real libarchive stub on
    // 23 Aug 2026; the same file with the stub past the first article, so
    // the sniff never fired, unpacked.
    assert_eq!(rep.fallbacks.len(), 1, "{:?}", rep.fallbacks);
    let why = &rep.fallbacks[0].1;
    assert!(
        why.starts_with(crate::extract::SFX_DISK_FALLBACK_PREFIX),
        "{why}"
    );
    assert!(
        why.contains("compressed"),
        "the reason stays readable: {why}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The marker follows the MAPPER'S BASE, not the bytes: the same file
/// under a name the sniff does not gate on is never started inside the
/// stub, so its demote is an ordinary one and the unrar ladder must still
/// claim it. Marking a demote whose volumes ARE that ladder's input would
/// leave a job with loose volumes and no payload.
#[test]
fn the_same_bytes_under_a_non_sfx_name_demote_unmarked() {
    let data = noisy(120_000, 9);
    let vol = rars_compressed_volume(&[("a.bin", &data)]);
    let file = sfx(3_000, &vol);
    let (dir, rep) = run("sfx-name-comp", "pack.dat", &file, 53);
    assert_eq!(std::fs::read(dir.join("pack.dat")).unwrap(), file);
    for (_, why) in &rep.fallbacks {
        assert!(
            !why.starts_with(crate::extract::SFX_DISK_FALLBACK_PREFIX),
            "{why}"
        );
    }
}

/// The engine's watermark comes back in archive coordinates; the trim
/// reads file ones. The whole-volume marker must survive the shift.
#[test]
fn the_watermark_translation_keeps_the_whole_volume_marker() {
    assert_eq!(file_watermark(0, 500), 500);
    assert_eq!(file_watermark(3_000, 500), 3_500);
    assert_eq!(file_watermark(3_000, 0), 3_000);
    assert_eq!(file_watermark(3_000, u64::MAX), u64::MAX);
    assert_eq!(file_watermark(u64::MAX, u64::MAX - 1), u64::MAX);
}

/// The posted-top-level-only rule: an SFX that is a MEMBER of a posted
/// archive is a deliverable (a release's own installer), never sniffed,
/// never exploded. The outer store RAR maps; `setup.exe` comes out whole.
#[test]
fn an_sfx_one_level_down_is_delivered_not_exploded() {
    let data = payload(50_000, 3);
    let inner = fixtures::rar5_volume(&[("secret.bin", 0, &data, false, false)]);
    let installer = sfx(3_000, &inner);
    let outer = store_outer("setup.exe", &installer);
    let (dir, rep) = run("sfx-nested", "release.rar", &outer, 61);
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("setup.exe")).unwrap(), installer);
    assert_eq!(dir_files(&dir), vec!["setup.exe".to_string()]);
}

/// A DUMP is not a self-extractor, whatever it is called: M4-101.
///
/// Reproduced on origin/main 31 Aug 2026 with this exact fixture - the
/// `.bin` was gone from the output tree, `inner.mkv` published in its
/// place, and the job reported success. A `mode=raw` or Blu-ray STREAM
/// dump that happens to carry an archive is that shape, and the
/// extension gate cannot tell it from a real installer.
///
/// The row's own remedy - deny `.bin` - is refuted (it is this
/// product's obfuscated-volume extension), so the rule is structural:
/// `nzbkit::sfx::is_launcher_stub`. Both names below carry the same
/// bytes at the same offset; only the PREFIX differs, so this test
/// fails if the rule ever goes back to reading the name.
#[test]
fn a_dump_that_merely_carries_an_archive_lands_on_disk_whole() {
    let data = payload(80_000, 17);
    let vol = fixtures::rar5_volume(&[("inner.mkv", 0, &data, false, false)]);
    // Transport-stream sync bytes: a program header nowhere in sight.
    let mut dump: Vec<u8> = (0..1024)
        .map(|i| {
            if i % 188 == 0 {
                0x47
            } else {
                (i as u8).wrapping_mul(7)
            }
        })
        .collect();
    dump.extend_from_slice(&vol);
    for (tag, name) in [("m4101-bin", "feature.bin"), ("m4101-exe", "feature.exe")] {
        let (dir, rep) = run(tag, name, &dump, 91);
        assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), dump, "{tag}");
        assert_eq!(dir_files(&dir), vec![name.to_string()], "{tag}");
    }
}

/// ...and the SAME archive at the SAME offset behind a real program is
/// still chased, so the rule narrows rather than switching the feature
/// off. The negative control for the test above.
#[test]
fn the_same_archive_behind_a_real_program_still_maps_in_stream() {
    let data = payload(80_000, 17);
    let vol = fixtures::rar5_volume(&[("inner.mkv", 0, &data, false, false)]);
    let mut file = stub(1_024);
    file.extend_from_slice(&vol);
    let (dir, rep) = run("m4101-control", "feature.bin", &file, 92);
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("inner.mkv")).unwrap(), data);
    assert_eq!(dir_files(&dir), vec!["inner.mkv".to_string()]);
}
