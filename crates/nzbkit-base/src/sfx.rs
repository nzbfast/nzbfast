//! Locating the archive behind a self-extractor's launcher stub.
//!
//! An SFX is an executable with a real archive appended, so its payload
//! is found by SIGNATURE, never by extension, and never at offset 0
//! (that is a bare archive wearing the wrong name). The one scan here
//! serves two callers that must agree on what an SFX is: the disk
//! post-pass (`nzbfast`'s `sfx.rs`, which carves the stub off and unpacks
//! the rest) and the one-pass mapper's offset-0 sniff (TODO 94 C), which
//! starts the RAR mapper or the 7z chase at the offset this returns
//! instead of sending the file to disk.
//!
//! **Every match is CONFIRMED, and the scan does not stop at the first
//! one.** Both magics occur as constants inside ordinary programs - the
//! 7-Zip CLI carries the 7z magic, and so does every binary this project
//! ships - so a bare substring hit claimed 25 of 1,105 real binaries.
//! Each candidate has to have a CRC-valid main header sitting behind it
//! (`rar::archive_starts_here`, `nameprobe::sevenz_start`), and one that
//! has not is stepped over rather than believed - which is the half that
//! matters, since the decoy constant in those binaries comes BEFORE any
//! real payload would. A file that merely looks like a program and has
//! no confirmed archive behind it is `None`, and the callers leave it
//! exactly as they found it.

/// How much of a candidate's head is scanned for an appended archive.
///
/// 4 MiB, not 1: a 7-Zip PE stub alone is ~200 KB and RAR's own installer
/// stubs run past a megabyte, so the old window could sit entirely inside
/// the stub and conclude "not an archive".
pub const SFX_SCAN_WINDOW: usize = 4 << 20;

/// Ceiling on how many signature matches one file may have confirmed.
///
/// Confirmation is cheap - a type byte and a size word reject almost
/// everything before a CRC is computed - but the number of matches is
/// attacker-chosen, so the total work must not be. A file that spends this
/// budget on decoys and puts its real archive after them is not unpacked;
/// that is a delivered `.exe`, which is what happens today for every
/// self-extractor, so the failure is the benign direction.
pub const SFX_MAX_CANDIDATES: usize = 256;

/// Which archive family sits behind the stub. Zip is absent on purpose:
/// a zip is located from its TAIL (`zip::stubbed_archive`), because a
/// forward scan for a zip signature claims ordinary programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfxFamily {
    Rar,
    SevenZ,
}

/// Does this name look like a self-extractor? The extension gate is
/// free, and it narrows the population before anything is read - but it
/// is NOT the safety gate, and reading it as one is what M4-101 was: a
/// data file can legitimately CONTAIN an archive - a disk image, a
/// backup, a `mode=raw` or Blu-ray STREAM dump - and a header check says
/// only that one is there, never that unpacking it is what the user
/// wanted. `.bin` is the extension where that bites, and it cannot be
/// removed from this list: it is also this product's commonest
/// OBFUSCATED-volume extension (nine nzbkit tests model an obfuscated
/// post as `bbbb1234.bin`, which is why `.bin` is deliberately absent
/// from `extract::names::PAYLOAD_CONTENT_EXTS`), so denying it here
/// breaks the obfuscated path outright. [`is_launcher_stub`] is the
/// answer that is not a name.
pub fn is_sfx_name(name: &str) -> bool {
    std::path::Path::new(name).extension().is_some_and(|x| {
        let x = x.to_string_lossy().to_lowercase();
        x == "exe" || x == "bin" || x == "sfx"
    })
}

/// Where a stub's real archive starts, and which family it is, scanning
/// at most [`SFX_SCAN_WINDOW`] bytes of `head`. The EARLIEST CONFIRMED
/// signature wins: a 7z stub can mention "Rar!" in its own error strings
/// and vice versa, so position decides between two real archives, and
/// the header decides whether a match is a real archive at all. Offset 0
/// is a possible answer - a bare archive - and every caller refuses it.
pub fn sfx_payload_at(head: &[u8]) -> Option<(usize, SfxFamily)> {
    let mut spent = 0usize;
    for off in 0..head.len().min(SFX_SCAN_WINDOW) {
        let rest = &head[off..];
        let family =
            if rest.starts_with(b"Rar!\x1a\x07\x00") || rest.starts_with(b"Rar!\x1a\x07\x01") {
                SfxFamily::Rar
            } else if rest.starts_with(crate::nameprobe::SEVENZ_MAGIC) {
                SfxFamily::SevenZ
            } else {
                continue;
            };
        spent += 1;
        if spent > SFX_MAX_CANDIDATES {
            break;
        }
        let real = match family {
            SfxFamily::Rar => crate::rar::archive_starts_here(rest),
            SfxFamily::SevenZ => crate::nameprobe::sevenz_start(rest).is_some(),
        };
        if real {
            return Some((off, family));
        }
    }
    None
}

/// Does this file BEGIN with a launcher stub - that is, with a program?
///
/// M4-101, reproduced 31 Aug 2026 and fixed here: a `feature.bin` of
/// ordinary dump bytes with a real RAR5 volume sitting at offset 1024
/// was chased as a self-extractor, the volume's inner file published,
/// and the `.bin` the user asked for gone from the output tree - with
/// the job reporting success. A `mode=raw` or Blu-ray STREAM dump is
/// exactly that shape. The row's own remedy - deny `.bin` - is REFUTED
/// at [`is_sfx_name`]; this is the structural answer instead.
///
/// **A self-extractor is a PROGRAM.** That is the whole rule, and it is
/// the one property a data file that merely carries an archive cannot
/// have. Four executable formats a posted self-extractor can plausibly
/// be: PE (every WinRAR and 7-Zip SFX module), ELF, Mach-O, and a Unix
/// shell script (the `makeself` family, which is where the `.bin`
/// installer convention came from in the first place).
///
/// PE is checked STRUCTURALLY - `MZ`, then `e_lfanew`, then `PE\0\0`
/// where it points - rather than on the two-byte magic alone. `MZ` by
/// itself already kills the realistic false-positive population (a
/// transport stream opens 0x47, an ISO 0x00, a boot sector 0xeb or
/// 0x33), so the extra branch is there for the coincidence rather than
/// for the census, and it costs one comparison.
///
/// DIRECTION OF FAILURE, which is why this narrows rather than widens:
/// a self-extractor this declines is not destroyed, it materializes
/// whole and the disk post-pass's SFX arm can still open it - the same
/// route every SFX whose stub outruns the first article already takes. A
/// self-extractor this WRONGLY accepted takes the user's file away.
///
/// The other candidate M4-101 named - require the archive to run to
/// END OF FILE - was rejected on two counts, both of them measurable
/// rather than aesthetic. It is not computable at the offset-0 sniff,
/// which holds one article and cannot know a RAR volume chain's total
/// length; and a SIGNED self-extractor's Authenticode certificate table
/// is appended AFTER the payload, so the rule would decline precisely
/// the installers that are signed. It also never asks the question that
/// matters: a dump whose tail happens to be an archive still passes it.
pub fn is_launcher_stub(head: &[u8]) -> bool {
    // PE (Windows): the format every WinRAR and 7-Zip SFX module is.
    if head.starts_with(b"MZ") && head.len() >= 0x40 {
        let lfanew = u32::from_le_bytes(head[0x3c..0x40].try_into().unwrap()) as usize;
        if lfanew >= 0x40
            && lfanew.checked_add(4).is_some_and(|e| e <= head.len())
            && &head[lfanew..lfanew + 4] == b"PE\0\0"
        {
            return true;
        }
    }
    // ELF, and Mach-O in all four thin spellings plus the two fat ones.
    const PROGRAM_MAGICS: &[&[u8]] = &[
        b"\x7fELF",
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    ];
    if PROGRAM_MAGICS.iter().any(|m| head.starts_with(m)) {
        return true;
    }
    // A shell-script self-extractor: a shebang, with the interpreter
    // path it must name. `#!` alone is two bytes of nothing.
    head.starts_with(b"#!/") || head.starts_with(b"#! /")
}

/// A stub behind which a real archive sits at a NON-ZERO offset, for a
/// file whose name passes [`is_sfx_name`]: the whole predicate both
/// callers apply, in one place.
///
/// [`is_launcher_stub`] runs FIRST, before the scan: it is the half that
/// carries the safety (M4-101), and a file that is not a program needs
/// no 4 MiB search for something it must not act on either way.
pub fn sfx_archive_behind_stub(name: &str, head: &[u8]) -> Option<(usize, SfxFamily)> {
    if !is_sfx_name(name) || !is_launcher_stub(head) {
        return None;
    }
    sfx_payload_at(head).filter(|&(off, _)| off > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal 7z container: start header with a CRC-valid geometry
    /// that places an (empty-bodied) end header right behind it.
    fn tiny_7z() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(crate::nameprobe::SEVENZ_MAGIC);
        v.extend_from_slice(&[0, 4]);
        let mut geom = Vec::new();
        geom.extend_from_slice(&0u64.to_le_bytes());
        geom.extend_from_slice(&2u64.to_le_bytes());
        geom.extend_from_slice(&crc32fast::hash(&[0x01, 0x00]).to_le_bytes());
        v.extend_from_slice(&crc32fast::hash(&geom).to_le_bytes());
        v.extend_from_slice(&geom);
        v.extend_from_slice(&[0x01, 0x00]);
        v
    }

    #[test]
    fn a_pe_lookalike_with_no_archive_is_left_alone() {
        // A real program, so this fails on the ARCHIVE being absent and
        // not on `is_launcher_stub` - the two refusals are different
        // findings and a fixture that trips both proves neither.
        let mut stub = minimal_pe(3002);
        // Decoy magics with nothing parseable behind them.
        stub.extend_from_slice(b"Rar!\x1a\x07\x01\x00");
        stub.extend(std::iter::repeat_n(0u8, 64));
        stub.extend_from_slice(crate::nameprobe::SEVENZ_MAGIC);
        stub.extend(std::iter::repeat_n(0xffu8, 64));
        assert_eq!(sfx_payload_at(&stub), None);
        assert_eq!(sfx_archive_behind_stub("setup.exe", &stub), None);
    }

    #[test]
    fn a_stubbed_7z_is_found_past_decoys_and_offset_0_is_refused() {
        // A real PE header, not the bare `MZ` this fixture carried until
        // M4-101: `is_launcher_stub` reads the structure, so a stub that
        // is only two bytes of program is no longer a stub.
        let mut file = minimal_pe(1002);
        file.extend_from_slice(crate::nameprobe::SEVENZ_MAGIC);
        file.extend(std::iter::repeat_n(0u8, 40));
        let base = file.len();
        file.extend_from_slice(&tiny_7z());
        assert_eq!(sfx_payload_at(&file), Some((base, SfxFamily::SevenZ)));
        assert_eq!(
            sfx_archive_behind_stub("pack.exe", &file),
            Some((base, SfxFamily::SevenZ))
        );
        assert_eq!(sfx_archive_behind_stub("pack.7z", &file), None, "name gate");
        assert_eq!(
            sfx_archive_behind_stub("bare.exe", &tiny_7z()),
            None,
            "offset 0"
        );
    }

    /// The minimum a stub has to be for [`is_launcher_stub`]: the three
    /// fields it reads, and nothing else. `extract::sfx_tests::stub`
    /// builds the full PE32 a loader would accept; this is what the RULE
    /// looks at, so a change to either one is visible against the other.
    fn minimal_pe(len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len.max(0x44)];
        v[0..2].copy_from_slice(b"MZ");
        v[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        v[0x40..0x44].copy_from_slice(b"PE\0\0");
        v
    }

    /// A dump: the shape M4-101 destroyed. Transport-stream sync bytes,
    /// no program header anywhere, a real archive sitting inside it.
    fn dump(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                if i % 188 == 0 {
                    0x47
                } else {
                    (i as u8).wrapping_mul(7)
                }
            })
            .collect()
    }

    #[test]
    fn a_launcher_stub_is_a_program_and_a_dump_is_not() {
        assert!(is_launcher_stub(&minimal_pe(0x400)));
        assert!(is_launcher_stub(b"\x7fELF\x02\x01\x01\x00"));
        assert!(is_launcher_stub(b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01"));
        assert!(is_launcher_stub(b"\xca\xfe\xba\xbe\x00\x00\x00\x02"));
        assert!(is_launcher_stub(b"#!/bin/sh\nexit 0\n"));
        assert!(is_launcher_stub(b"#! /bin/sh\nexit 0\n"));

        assert!(!is_launcher_stub(&dump(4096)), "a transport-stream dump");
        assert!(!is_launcher_stub(&[0u8; 4096]), "an ISO's zero lead-in");
        assert!(!is_launcher_stub(b""), "nothing at all");
        assert!(!is_launcher_stub(b"#!"), "a shebang with no interpreter");
        // `MZ` alone is not the rule: the PE arm is STRUCTURAL, so the
        // two bytes with nothing behind them do not satisfy it.
        let mut bare_mz = vec![0x90u8; 0x400];
        bare_mz[0..2].copy_from_slice(b"MZ");
        assert!(!is_launcher_stub(&bare_mz), "MZ with no PE header");
        // ...nor does an `e_lfanew` that points at something else, or
        // out of the buffer entirely.
        let mut wrong = minimal_pe(0x400);
        wrong[0x40..0x44].copy_from_slice(b"NE\0\0");
        assert!(!is_launcher_stub(&wrong), "e_lfanew points at no PE");
        let mut far = minimal_pe(0x400);
        far[0x3c..0x40].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        assert!(!is_launcher_stub(&far), "e_lfanew past the buffer");
        let mut low = minimal_pe(0x400);
        low[0x3c..0x40].copy_from_slice(&4u32.to_le_bytes());
        assert!(!is_launcher_stub(&low), "e_lfanew inside the DOS header");
    }

    /// M4-101: the whole predicate, both halves. The same archive at the
    /// same offset under the same name is an SFX behind a program and
    /// NOT one behind a dump - which is the distinction the extension
    /// gate alone could never make.
    #[test]
    fn a_dump_carrying_an_archive_is_not_a_self_extractor() {
        let arch = tiny_7z();
        let mut real = minimal_pe(1024);
        real.extend_from_slice(&arch);
        let mut fake = dump(1024);
        fake.extend_from_slice(&arch);

        // The scan itself is unchanged - it finds the archive in both.
        assert_eq!(sfx_payload_at(&real), Some((1024, SfxFamily::SevenZ)));
        assert_eq!(sfx_payload_at(&fake), Some((1024, SfxFamily::SevenZ)));

        for name in ["feature.bin", "pack.exe", "thing.sfx"] {
            assert_eq!(
                sfx_archive_behind_stub(name, &real),
                Some((1024, SfxFamily::SevenZ)),
                "{name} behind a program"
            );
            assert_eq!(
                sfx_archive_behind_stub(name, &fake),
                None,
                "{name} behind a dump"
            );
        }
    }

    /// The refuted remedy, pinned so nobody re-derives it: `.bin` stays
    /// in the name gate, because it is also this product's obfuscated-
    /// volume extension. An obfuscated volume is a BARE archive, so it
    /// is refused by the offset-0 rule and never reaches the SFX arm at
    /// all - the two questions do not collide.
    #[test]
    fn the_obfuscated_bin_convention_is_untouched() {
        assert!(is_sfx_name("bbbb1234.bin"));
        assert_eq!(
            sfx_archive_behind_stub("bbbb1234.bin", &tiny_7z()),
            None,
            "a bare archive is not an SFX, whatever it is called"
        );
    }

    #[test]
    fn the_name_gate_is_case_insensitive_and_narrow() {
        assert!(is_sfx_name("a.EXE"));
        assert!(is_sfx_name("a.bin"));
        assert!(is_sfx_name("a.Sfx"));
        assert!(!is_sfx_name("a.rar"));
        assert!(!is_sfx_name("a.exe.part1"));
        assert!(!is_sfx_name("noext"));
    }
}
