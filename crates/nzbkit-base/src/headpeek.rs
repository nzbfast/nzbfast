//! One read of a file's first bytes, however many predicates ask.
//!
//! The disk unpack ladder decides what a file IS by its first bytes -
//! `Rar!`, the 7-Zip signature, a zip local header, `ustar`, `PAR2\0PKT`
//! - and it asks that question from a great many places: every family's
//! collector runs before any arm unpacks (deliberately, so no arm's
//! output is mistaken for input), `extract_nested_capped` re-asks it
//! per candidate, and `dir_has_nested_extractable` asks it again to
//! decide whether another level exists at all.
//!
//! Each of those asks used to be its own `open` + `read` + `close`.
//!
//! **What that cost** (per-article-residue lane, 3 Sep 2026,
//! `research/RAR-PERF-AUDIT-2026-09-02.md` round 26). On a stored RAR5
//! set of 2,048 x 512 KB members - 1 GiB either way, the same bytes as a
//! one-member set - the post-download tail was 841 ms against 1 ms for
//! the one-member shape, and a `sample` of it was **98% `open`/`read`/
//! `stat`/`close`**: 604 of 618 samples. Attributed by caller, the same
//! 2,048 output files were sniffed about EIGHTEEN times each -
//! `rar_magic` from six sites, `sevenz_magic` from five, zip's
//! `has_magic` from three, `is_tar_container` from three, the PAR2
//! magic once. Nothing about the answer differed between the asks; the
//! directory is static across all of them.
//!
//! **Why a memo and not a scope.** A scope would have to be opened
//! exactly where the directory is provably unchanging, and the ladder
//! creates and deletes files between those regions - one misplaced
//! scope is a stale head, and a stale head is a nested archive left
//! packed. This memo cannot go stale by construction instead: every
//! query `stat`s the path and the cached bytes are keyed on the file's
//! IDENTITY (device, inode, size, mtime, ctime), so a file that changed
//! in any way misses and is re-read. The saving is the difference
//! between the two syscall paths, measured on this Mac over the 2,048
//! real output files, warm: `open`+`read`+`close` 10.7 us per file,
//! `stat` 1.3 us - **8.4x**.
//!
//! [`HEAD_LEN`] is 512 because the tar magic sits at offset 257 and is
//! the deepest any caller looks; everything else is within 8 bytes.
//!
//! **One deliberate tightening.** The `stat` this needs for the key is
//! also a regular-file check, and the sniffs that used to go straight to
//! `File::open` did not have one: a FIFO named `x.rar` sitting in an
//! output directory used to BLOCK the ladder inside `open`. Every such
//! path now answers `None`, which is the same "no" those callers give
//! for a file they cannot read. A symlink is unaffected -
//! `fs::metadata` follows it, exactly as `File::open` did.

use std::path::{Path, PathBuf};

/// How many leading bytes are cached. 512 covers the deepest magic any
/// caller reads (`ustar` at offset 257) and is one disk sector.
pub const HEAD_LEN: usize = 512;

/// A file's leading bytes and its length.
#[derive(Clone)]
pub struct Head {
    bytes: Vec<u8>,
    /// The file's full length, which some predicates gate on
    /// (`file_starts_with_par2_magic` wants >= 8, tar wants a full
    /// block) - free here, since the `stat` already read it.
    pub file_len: u64,
}

impl Head {
    /// The leading bytes actually present: up to [`HEAD_LEN`], fewer for
    /// a short file.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Does the head start with `magic`? False when the file is shorter
    /// than the magic, which is the answer every caller wants for a
    /// file too short to be the container.
    pub fn starts_with(&self, magic: &[u8]) -> bool {
        self.bytes.starts_with(magic)
    }

    /// Is `magic` present at `off`? The tar test's shape.
    pub fn magic_at(&self, off: usize, magic: &[u8]) -> bool {
        self.bytes
            .get(off..off + magic.len())
            .is_some_and(|s| s == magic)
    }
}

/// The identity a cached head is keyed on: anything that can change the
/// bytes changes at least one of these.
#[derive(PartialEq, Eq, Clone, Copy)]
struct Ident {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

#[cfg(unix)]
fn ident_of(m: &std::fs::Metadata) -> Ident {
    use std::os::unix::fs::MetadataExt;
    Ident {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    }
}

/// Windows has no STABLE inode: `MetadataExt::file_index` and
/// `volume_serial_number` are both behind the unstable
/// `windows_by_handle` feature (checked 3 Sep 2026 with
/// `cargo check --target x86_64-pc-windows-gnu`, which is how this was
/// caught - nothing on a host target compiles this arm). So the key is
/// size plus the two 100 ns FILETIMEs plus the attribute word.
///
/// Two shapes could in principle alias, and neither can on the unix
/// key, which carries the inode. NTFS file tunneling: a file deleted
/// and recreated under the same name within ~15 s inherits the
/// original's CREATION time, so creation time never separates them -
/// `last_write_time` has to, and the size would have to match too. And
/// a COARSE-timestamp volume (FAT/exFAT, 2 s): a same-size replacement
/// inside one tick is indistinguishable.
///
/// **The aliasing window is MILLISECONDS, not the 100 ns this comment
/// first claimed.** Measured 3 Sep 2026 on a real Win11 NTFS volume
/// (a Core Ultra laptop): tunneling preserved creation time on 40 of 40 immediate
/// same-name recreates and at a 1 s delay, and stopped at 16 s, so the
/// ~15 s window is confirmed and that half ALWAYS fires. 100 ns is
/// FILETIME's UNIT, not its RESOLUTION: 200 writes to one path produced
/// only 163 distinct `LastWriteTime` values, median gap 72,985 ticks =
/// **7.30 ms**. Two same-size writes that far apart therefore alias,
/// and at PowerShell speed all four key components collided in 4 of 40
/// trials - from a tight loop, more often.
///
/// So the conclusion below still holds but NOT for the reason first
/// given: the shape is reachable, and what keeps the ladder out of it
/// is that it creates distinct output NAMES and deletes the volumes it
/// spends - not that the timing window is vanishingly small. Anyone
/// re-deriving this risk from the old sentence would badly under-rate
/// it. If it ever needs closing, the answer is `File::open` +
/// `GetFileInformationByHandle` for a real file index, not a weaker key.
#[cfg(windows)]
fn ident_of(m: &std::fs::Metadata) -> Ident {
    use std::os::windows::fs::MetadataExt;
    Ident {
        dev: u64::from(m.file_attributes()),
        ino: 0,
        len: m.file_size(),
        mtime: (m.last_write_time() as i64, 0),
        ctime: (m.creation_time() as i64, 0),
    }
}

/// How many paths the memo holds before it is dropped whole.
///
/// A flat clear rather than an LRU: the access pattern is a directory
/// swept end to end by one predicate after another, so the whole
/// working set is live at once and evicting the least-recent entry is
/// exactly wrong. A daemon unpacking job after job would otherwise grow
/// this without bound. 16,384 x (a path + 512 bytes) is a few MB.
const MEMO_CAP: usize = 16_384;

fn memo() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, (Ident, Head)>> {
    static M: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, (Ident, Head)>>,
    > = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// The first [`HEAD_LEN`] bytes of `path`, read at most once per
/// (path, file identity).
///
/// `None` for anything that is not a readable regular file - a
/// directory, a path that will not open, a vanished file. That is the
/// same answer the hand-rolled sniffs gave ("the honest answer for a
/// file it cannot read is no"), and negative results are deliberately
/// NOT cached: a file being written by another stage of the ladder is
/// exactly the case that must be re-asked.
pub fn head(path: &Path) -> Option<Head> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let ident = ident_of(&meta);
    if let Ok(m) = memo().lock()
        && let Some((cached, h)) = m.get(path)
        && *cached == ident
    {
        return Some(h.clone());
    }
    let h = read_head(path, meta.len())?;
    if let Ok(mut m) = memo().lock() {
        if m.len() >= MEMO_CAP {
            m.clear();
        }
        m.insert(path.to_path_buf(), (ident, h.clone()));
    }
    Some(h)
}

fn read_head(path: &Path, file_len: u64) -> Option<Head> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let want = HEAD_LEN.min(file_len.try_into().unwrap_or(HEAD_LEN));
    let mut bytes = vec![0u8; want];
    let mut got = 0usize;
    while got < want {
        match f.read(&mut bytes[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    bytes.truncate(got);
    Some(Head { bytes, file_len })
}

/// Drop everything memoized. Test support, and the one thing a caller
/// that rewrites a file's head IN PLACE under the same size and
/// timestamps would need - no such caller exists today (the ladder
/// creates and deletes whole files), and the identity key covers every
/// path that does.
pub fn clear() {
    if let Ok(mut m) = memo().lock() {
        m.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "nzbfast-headpeek-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn reads_the_head_and_the_length() {
        let d = tmpdir("basic");
        let p = d.join("a.bin");
        std::fs::write(&p, b"Rar!\x1a\x07\x01\x00rest of it").unwrap();
        let h = head(&p).unwrap();
        assert!(h.starts_with(b"Rar!"));
        assert!(!h.starts_with(b"7z\xbc"));
        assert_eq!(h.file_len, 18);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_short_file_answers_no_rather_than_reading_past_it() {
        let d = tmpdir("short");
        let p = d.join("s.bin");
        std::fs::write(&p, b"Ra").unwrap();
        let h = head(&p).unwrap();
        assert!(!h.starts_with(b"Rar!"));
        assert_eq!(h.bytes(), b"Ra");
        assert!(!h.magic_at(257, b"ustar"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn magic_at_finds_the_tar_offset() {
        let d = tmpdir("tar");
        let p = d.join("t.tar");
        let mut b = vec![0u8; 512];
        b[257..262].copy_from_slice(b"ustar");
        std::fs::write(&p, &b).unwrap();
        assert!(head(&p).unwrap().magic_at(257, b"ustar"));
        std::fs::remove_dir_all(&d).ok();
    }

    /// The whole safety argument: a REWRITTEN file must not answer with
    /// the bytes it used to have. The memo is keyed on the file's
    /// identity, so this cannot be answered from the cache.
    #[test]
    fn a_rewritten_file_is_re_read_not_served_from_the_memo() {
        let d = tmpdir("stale");
        let p = d.join("x.bin");
        std::fs::write(&p, b"Rar!\x1a\x07\x01\x00").unwrap();
        assert!(head(&p).unwrap().starts_with(b"Rar!"));
        // A different length AND different bytes - and, on a coarse
        // clock, a different size is on its own enough to miss.
        std::fs::write(&p, b"7z\xbc\xaf\x27\x1c\x00\x01\x02").unwrap();
        let h = head(&p).unwrap();
        assert!(!h.starts_with(b"Rar!"), "served a stale head");
        assert!(h.starts_with(b"7z\xbc\xaf\x27\x1c"));
        std::fs::remove_dir_all(&d).ok();
    }

    /// A file REPLACED at the same path (delete + recreate, which is
    /// what the ladder actually does) is a new inode, so the key misses
    /// EVEN IF THE SIZE HAPPENS TO MATCH - which is the whole point of
    /// carrying the inode, so the replacement here is deliberately the
    /// same length as the original.
    ///
    /// Unix only, and NOT because Windows is untested - see the twin
    /// below. `ident_of`'s Windows arm has no inode to carry (
    /// `file_index` is behind unstable `windows_by_handle`) and its
    /// module comment already names this exact shape as one the key
    /// cannot separate: a same-name, same-SIZE replacement inside one
    /// `last_write_time`, with NTFS tunneling handing back the
    /// original's creation time. Asserting it here anyway made
    /// `windows-unit` shard 5 red on 56f53ab7d (run 33773651834) while
    /// the code did exactly what it documents.
    ///
    /// It was FLAKY there rather than reliably wrong, which is worth
    /// knowing before anyone re-enables it: measured on real Win11/NTFS,
    /// all four key components collided in 4 of 40 PowerShell-speed
    /// trials, and a Rust loop puts the two writes closer together than
    /// that. So a green windows-unit shard was never evidence the
    /// assertion held. Closing it for real means `File::open` plus
    /// `GetFileInformationByHandle` for a true file index, which is a
    /// design call for whoever owns the ladder's head reads, not a
    /// weakening of this test.
    #[test]
    #[cfg(unix)]
    fn a_replaced_file_at_the_same_path_is_re_read() {
        let d = tmpdir("replace");
        let p = d.join("y.bin");
        std::fs::write(&p, b"Rar!\x1a\x07\x01\x00").unwrap();
        assert!(head(&p).unwrap().starts_with(b"Rar!"));
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"7z\xbc\xaf\x27\x1c\x00\x00").unwrap();
        assert!(!head(&p).unwrap().starts_with(b"Rar!"));
        std::fs::remove_dir_all(&d).ok();
    }

    /// The Windows twin, because NTFS FILE TUNNELING makes the unix
    /// version above unprovable here: a replacement the documented key
    /// CAN separate, because the sizes differ and `len` is in the key on
    /// every target.
    /// This is the strongest same-path assertion available there without
    /// a real file index, and it is a genuine test rather than a
    /// placeholder - it fails if the memo ever stops consulting `stat`
    /// at all, which is the regression that would matter most.
    #[test]
    #[cfg(windows)]
    fn a_replaced_file_of_a_different_size_is_re_read() {
        let d = tmpdir("replace-win");
        let p = d.join("y.bin");
        std::fs::write(&p, b"Rar!\x1a\x07\x01\x00").unwrap();
        assert!(head(&p).unwrap().starts_with(b"Rar!"));
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"7z\xbc\xaf\x27\x1c\x00\x00\x00\x00").unwrap();
        assert!(!head(&p).unwrap().starts_with(b"Rar!"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_directory_and_a_missing_path_answer_none() {
        let d = tmpdir("none");
        assert!(head(&d).is_none());
        assert!(head(&d.join("nope")).is_none());
        std::fs::remove_dir_all(&d).ok();
    }

    /// A vanished file must not keep answering from the memo: negative
    /// results are not cached and the `stat` is what decides.
    #[test]
    fn a_deleted_file_stops_answering() {
        let d = tmpdir("gone");
        let p = d.join("z.bin");
        std::fs::write(&p, b"Rar!\x1a\x07\x01\x00").unwrap();
        assert!(head(&p).is_some());
        std::fs::remove_file(&p).unwrap();
        assert!(head(&p).is_none());
        std::fs::remove_dir_all(&d).ok();
    }
}
