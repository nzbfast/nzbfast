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
/// free, and it is a SAFETY gate even with every match confirmed: a data
/// file can legitimately CONTAIN an archive - a disk image, a backup, a
/// nested container someone posted whole - and a header check says only
/// that one is there, never that unpacking it is what the user wanted.
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

/// A stub behind which a real archive sits at a NON-ZERO offset, for a
/// file whose name passes [`is_sfx_name`]: the whole predicate both
/// callers apply, in one place.
pub fn sfx_archive_behind_stub(name: &str, head: &[u8]) -> Option<(usize, SfxFamily)> {
    if !is_sfx_name(name) {
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
        let mut stub = b"MZ".to_vec();
        stub.extend(std::iter::repeat_n(0x90u8, 3000));
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
        let mut file = b"MZ".to_vec();
        file.extend(std::iter::repeat_n(0x90u8, 1000));
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
