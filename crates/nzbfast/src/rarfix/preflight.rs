//! The free-space preflight the external `unrar` subprocess cannot do
//! for itself.
//!
//! [`super::try_unrar_spent`]'s native pass carries the disk-side
//! decompression-bomb guard ([`BombGuardWriter`], bounded at free space
//! less [`EXTRACT_RESERVE`]), and 7c67419d made its verdict the floor of
//! the unpack ladder rather than one more rung to fall past. But that
//! whole pass is SKIPPED when [`nzbkit::extract::prefer_external_unrar`]
//! is set - the daemon setting, or its `NZBFAST_NO_NATIVE_UNRAR` env
//! override. With it on, no budgeted engine runs at all, so no verdict
//! is ever raised for the ladder to stop at, and the set goes straight
//! to a subprocess that has no ceiling of any kind: it writes into the
//! staging directory until the device says ENOSPC, exits 5, and the job
//! reports "encrypted or damaged?" - the disk blamed on the archive,
//! which is the exact failure 7c67419d was written to end. That setting
//! chooses an ENGINE. It was never a switch for the guard.
//!
//! # Why a preflight rather than a budget
//!
//! unrar has nothing to offer here. Its command line carries no size or
//! space ceiling; `-vp` is an interactive pause before each volume, and
//! this ladder spawns it with stdin null precisely so nothing can
//! prompt; and its own out-of-space diagnostic arrives only once the
//! volume is already full, which is the outcome, not a guard against
//! it. Wrapping the subprocess in a watcher that kills it partway would
//! leave a half-written member behind and still have done the writing.
//!
//! So the bound has to be taken BEFORE the spawn, and there is exactly
//! one thing to take it from: what the RAR headers declare the set will
//! unpack to.
//!
//! # A declared size is a floor, not a proof
//!
//! `unpacked_size` is a poster's claim in an untrusted header vint. A
//! lying header defeats this preflight completely, which is why it
//! replaces neither writer-side guard: the in-stream [`nzbkit::disk`]
//! budget still runs ahead of every disk route and [`BombGuardWriter`]
//! still bounds the native pass, and both charge bytes actually
//! delivered. What a declaration does catch is the honest bomb - the
//! 22 Aug 2026 repro states its 2 GB of zeros truthfully in 88 KB of
//! posted bytes - and, just as load-bearing, every real large release
//! declares its real size too, which is the case that must go through.
//!
//! Unreadable headers therefore fail OPEN. A damaged set, or a
//! header-encrypted one whose password we do not have, parses to
//! nothing at all; refusing on "could not tell" would fail exactly the
//! sets this fallback exists to rescue.

use super::*;

/// What the RAR headers of `volumes` declare the set will unpack to, or
/// `None` when they cannot be read.
///
/// Parsed WITH the password, like [`try_rars_native`] - a
/// header-encrypted (`-hp`) set cannot be read at all without one - and
/// through one [`rars::ReadSession`] for the whole set, so a shared
/// (salt, kdf count) derivation runs once instead of once per volume.
///
/// Reading headers is not extracting. This seeks the volume chain and
/// touches no compressed byte, so it costs the same on a 2 GB bomb as
/// on the 88 KB that was posted for it, and it costs it once per group
/// rather than once per member.
///
/// The sum is [`crate::unpackprog::unpacked_total`] and deliberately not
/// a second walk of the same members: a file SPLIT across volumes
/// repeats its whole-file header in every volume it spans, so a naive
/// fold over `members()` multiplies the commonest shape of all by its
/// volume count - and here that inflation would read as a bomb and
/// refuse a set that fits.
pub(crate) fn declared_unpacked_size(volumes: &[PathBuf], password: Option<&str>) -> Option<u64> {
    if volumes.is_empty() {
        return None;
    }
    let options = nzbkit::mem::rar_read_options(password.map(str::as_bytes));
    let mut parse = rars::ReadSession::new(options);
    let archives = volumes
        .iter()
        .map(|path| parse.read_path(path))
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    Some(crate::unpackprog::unpacked_total(&archives))
}

/// Does a set declaring `declared` unpacked bytes exceed what the target
/// filesystem can give it?
///
/// The same line [`BombGuardWriter`] draws - free space less
/// [`EXTRACT_RESERVE`] - asked ahead of the write instead of during it,
/// so that both routes agree about which archives fit. Anything else
/// would make the answer depend on which engine the setting picked,
/// which is the defect, not the fix.
///
/// Two ways to answer "it fits" without measuring anything:
///
/// * `free` is `None` - `statfs` did not answer. `BombBudget::fixed`
///   runs unbounded on that disk too (`unwrap_or(u64::MAX)`), and a
///   guess in either direction here would be worse than the writer-side
///   guard that is still standing behind this.
/// * `declared` is 0 - the set declares nothing, or holds only
///   directories. Unreadable headers arrive as 0 for the same reason:
///   [`declared_unpacked_size`] answers `None` and the caller must fail
///   open.
///
/// A `free` under the reserve refuses everything, and that is not an
/// accident of the saturating arithmetic. `BombBudget::fixed` saturates
/// to a limit of 0 on that same disk and [`BombGuardWriter`] then aborts
/// on the first byte of any set at all, so the native route has always
/// behaved this way. This route is not allowed to be the lenient one -
/// being lenient here is the whole defect.
pub(crate) fn declared_exceeds_free(declared: u64, free: Option<u64>) -> bool {
    let Some(free) = free else {
        return false;
    };
    declared > 0 && declared > free.saturating_sub(EXTRACT_RESERVE)
}

/// The preflight as the unrar loop asks it: may this volume set be
/// handed to a subprocess that carries no budget?
///
/// Says so on the console when it refuses, with both figures, because
/// the numbers ARE the diagnosis - a user looking at "encrypted or
/// damaged?" had no way to tell that the archive was fine and the disk
/// was not. The sentence carries the distinctive tail
/// [`nzbkit::disk::bomb_verdict`] matches, so it reads as the same
/// refusal as the two writer-side guards wherever it is quoted back.
///
/// Refusing is per GROUP, like the password resolution beside it: a
/// directory holding a decoy bomb and a real release must still unpack
/// the release. The caller lists a refused group with the rest of its
/// leftovers - and, when nothing in the directory produced, carries the
/// verdict out as the JOB's failure rather than letting the tail word
/// it as a bad archive. See [`super::try_unrar_spent_why`].
pub(crate) fn unrar_would_bomb(
    dir: &std::path::Path,
    volumes: &[PathBuf],
    password: Option<&str>,
) -> bool {
    let declared = declared_unpacked_size(volumes, password).unwrap_or(0);
    let free = crate::serve::free_bytes(dir);
    if !declared_exceeds_free(declared, free) {
        return false;
    }
    println!(
        "⚠ this archive declares {:.1} GB unpacked and only {:.1} GB is usable here \
         - unpacking it needs more space than the disk has (possible decompression \
         bomb), so unrar was not run and the volumes were kept",
        declared as f64 / 1e9,
        free.unwrap_or(0).saturating_sub(EXTRACT_RESERVE) as f64 / 1e9,
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored RAR5 member split across two volumes, as
    /// `repair::repair_tests` builds one - the shape whose whole-file
    /// header repeats in every volume it spans.
    fn split_set(dir: &std::path::Path, total: &[u8]) -> Vec<PathBuf> {
        use nzbkit::rar::fixtures;
        let n = total.len() as u64;
        let half = total.len() / 2;
        let vols = [
            fixtures::rar5_volume_n(&[("film.mkv", n, &total[..half], false, true)], 0),
            fixtures::rar5_volume_n(&[("film.mkv", n, &total[half..], true, false)], 1),
        ];
        let paths = vec![dir.join("set.part1.rar"), dir.join("set.part2.rar")];
        for (p, v) in paths.iter().zip(vols.iter()) {
            std::fs::write(p, v).unwrap();
        }
        paths
    }

    fn scratch(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-preflight-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// What the headers say, read once for the whole set - and each file
    /// counted ONCE. Both volumes of a split member declare the member's
    /// full 400,000 bytes, so a fold over every fragment would answer
    /// 800,000 here, call a set twice its real size, and refuse an
    /// archive that fits on exactly the commonest multi-volume shape
    /// there is.
    #[test]
    fn a_split_member_declares_its_size_once_across_its_volumes() {
        let dir = scratch("split");
        let total: Vec<u8> = (0..400_000u32)
            .map(|i| (i as u8).wrapping_mul(23).wrapping_add(5))
            .collect();
        let vols = split_set(&dir, &total);
        assert_eq!(
            declared_unpacked_size(&vols, None),
            Some(400_000),
            "the set declares one member, not one per volume"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A COMPRESSED set is the shape this route actually carries - the
    /// native pass declining a compressed archive is why the ladder
    /// reaches unrar at all - and its headers still declare what it
    /// unpacks to. Pinned because a preflight that could only measure
    /// stored sets would fail open on every set it was written for: the
    /// same WinRAR `-m3` fixture the `prefer_external_unrar` route test
    /// downloads, whose 10 KB of archive declare 64 KB of payload.
    #[test]
    fn a_compressed_archive_still_declares_what_it_unpacks_to() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/rars/tests/fixtures/rar50/m3_default.rar");
        let declared = declared_unpacked_size(std::slice::from_ref(&fixture), None)
            .expect("a valid RAR5 archive must parse");
        assert!(
            declared >= 64 * 1024,
            "compression hid the declared size: {declared}"
        );
        // …and it is the DECLARATION, not the file: 10 KB on disk.
        let on_disk = std::fs::metadata(&fixture).unwrap().len();
        assert!(
            declared > on_disk * 4,
            "declared {declared} vs {on_disk} on disk - the ratio is the whole point"
        );
    }

    /// Headers that cannot be read must not refuse anything. A damaged
    /// set, or a header-encrypted one we have no password for, is
    /// precisely what this fallback exists to have a second go at - and
    /// "could not tell" is not a bomb.
    #[test]
    fn unreadable_headers_fail_open() {
        let dir = scratch("unreadable");
        let bad = dir.join("set.rar");
        std::fs::write(&bad, b"Rar!\x1a\x07\x01\x00 and then nothing that parses").unwrap();
        assert_eq!(
            declared_unpacked_size(std::slice::from_ref(&bad), None),
            None
        );
        assert_eq!(declared_unpacked_size(&[], None), None);
        // …and `None` reaching the predicate as 0 is what carries that
        // through to the answer the caller acts on.
        assert!(
            !declared_exceeds_free(0, Some(0)),
            "a set we could not measure must still be offered to unrar"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The line itself, at the 22 Aug 2026 incident's own numbers and at
    /// the honest large release it must not touch.
    #[test]
    fn the_preflight_draws_the_same_line_the_writer_side_guard_does() {
        const GB: u64 = 1_000_000_000;
        // The repro: 2 GB of zeros declared in 88 KB of posted bytes,
        // 730 MB free. Refused before the subprocess exists, where
        // before it was refused twice and written anyway.
        assert!(declared_exceeds_free(2 * GB, Some(730_000_000)));
        // A real 50 GB release on a disk that can hold it, reserve and
        // all. This is the case the guard is judged by.
        assert!(!declared_exceeds_free(50 * GB, Some(60 * GB)));
        // The boundary is free space LESS the reserve, exactly as
        // `BombBudget::fixed` computes it.
        let free = 10 * GB;
        let budget = free - EXTRACT_RESERVE;
        assert!(!declared_exceeds_free(budget, Some(free)));
        assert!(declared_exceeds_free(budget + 1, Some(free)));
        // No `statfs` answer is not a refusal: the writer-side guard runs
        // unbounded on that disk too, and it is still standing.
        assert!(!declared_exceeds_free(u64::MAX, None));
        // A disk with less free than the reserve refuses everything, and
        // it has to: `BombGuardWriter` aborts on the first byte there,
        // so a lenient answer here would be the whole defect back again -
        // the route the setting picks deciding whether the guard exists.
        assert!(declared_exceeds_free(1, Some(EXTRACT_RESERVE - 1)));
        assert!(!declared_exceeds_free(0, Some(EXTRACT_RESERVE - 1)));
    }
}
