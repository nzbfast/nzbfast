//! SFV, MD5, SHA-1 and SHA-256 files: read, write and check.
//!
//! # Why this is not `nzbfast-engine`'s parser
//!
//! There is one SFV/MD5 reader in this workspace already, in
//! `nzbfast-engine/src/get/sfvname.rs`, and its module doc forbids
//! growing it: it exists to learn a NAME out of a sidecar during a
//! download, it is `pub(super)`, and it is deliberately incurious about
//! anything else in the file. What a checksum pane needs is the
//! opposite - every line, in order, with its expected digest, its
//! resolved path and a verdict per row - so this is a second reader on
//! purpose and not by omission.
//!
//! # The two line shapes
//!
//! SFV is `name hex`, digest LAST, because that is how `cksfv` and
//! every Usenet poster has written it since the 1990s. The three
//! digest formats are `hex *name` or `hex  name`, digest FIRST, which
//! is `md5sum`'s shape and what `sha256sum -c` reads back. A `;`
//! comment is SFV's; a `#` comment is nobody's standard but every tool
//! in the field tolerates it, so both are skipped.
//!
//! Names are stored with forward slashes whatever the platform, which
//! is what makes a file written on Windows check on macOS.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::job::ChecksumFormat;

/// One line of a checksum file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The name exactly as the file spells it, forward slashes and all.
    pub name: String,
    /// The expected digest, lower-case hex. A CRC32 is eight hex
    /// digits; the rest are their own lengths.
    pub digest: String,
}

/// A parsed checksum file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumFile {
    pub format: ChecksumFormat,
    pub entries: Vec<Entry>,
}

/// What one row came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowStatus {
    Ok,
    Mismatch,
    Missing,
}

/// One row of the verify table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    pub name: String,
    pub expected: String,
    /// What the file on disk actually came to; empty when it is not
    /// there.
    pub actual: String,
    pub status: RowStatus,
}

/// Why a checksum file could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn err(code: &'static str, message: impl Into<String>) -> ChecksumError {
    ChecksumError {
        code,
        message: message.into(),
    }
}

/// Parse a checksum file's TEXT.
///
/// `hint` is what the file's extension implied, or `None`. The CONTENT
/// decides whichever way: a `.md5` holding SFV lines is an SFV file,
/// because what a tool has to do with it depends on where the digest
/// is and not on what somebody named it. The digest LENGTH then picks
/// between MD5, SHA-1 and SHA-256, which is unambiguous - 32, 40 and 64
/// hex digits.
pub fn parse(text: &str, hint: Option<ChecksumFormat>) -> Result<ChecksumFile, ChecksumError> {
    let mut entries = Vec::new();
    let mut format: Option<ChecksumFormat> = None;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches(['\r', '\n']).trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let (name, digest, shape) = split_line(line).ok_or_else(|| {
            err(
                "bad_line",
                format!("line {}: not a checksum line: {line}", n + 1),
            )
        })?;
        if let Some(prev) = format
            && prev != shape
        {
            {
                return Err(err(
                    "mixed_formats",
                    format!(
                        "line {}: this file holds {} lines and {} lines; a checksum file carries \
                         one format",
                        n + 1,
                        prev.extension(),
                        shape.extension()
                    ),
                ));
            }
        }
        format = Some(shape);
        entries.push(Entry {
            name: name.replace('\\', "/"),
            digest: digest.to_ascii_lowercase(),
        });
    }
    // NO LINES IS NOT A FORMAT AND IT IS NOT A CHECK. The extension hint
    // used to rescue an entry-less file, so `empty.sha256` holding one
    // comment parsed, verified zero of zero, and came back Done with a
    // green tick - while the identical text named `empty.txt` was
    // refused. Which of those two answers a user got turned on the
    // spelling of the file name, and "nothing was checked" is not a
    // successful check under either. The hint still decides the format
    // of a file that HAS lines it cannot otherwise place.
    if entries.is_empty() {
        return Err(err(
            "empty",
            "this file holds no checksum lines".to_string(),
        ));
    }
    let format = format
        .or(hint)
        .ok_or_else(|| err("empty", "this file holds no checksum lines".to_string()))?;
    Ok(ChecksumFile { format, entries })
}

/// One line into `(name, digest, the format its shape implies)`.
///
/// The discriminator is WHERE the hex is, and it is decided per line
/// rather than per file so a hand-edited file with a stray line fails
/// on that line instead of being read as the other format entirely.
fn split_line(line: &str) -> Option<(&str, &str, ChecksumFormat)> {
    // `hex *name` / `hex  name`: digest first.
    if let Some((head, rest)) = line.split_once(char::is_whitespace)
        && let Some(f) = digest_format(head)
    {
        let name = rest.trim_start();
        let name = name.strip_prefix('*').unwrap_or(name);
        if !name.is_empty() {
            return Some((name, head, f));
        }
    }
    // `name hex`: digest last, which is SFV's. The name may hold
    // spaces, so split at the LAST whitespace run and not the first.
    let trimmed = line.trim_end();
    let idx = trimmed.rfind(char::is_whitespace)?;
    let (name, tail) = trimmed.split_at(idx);
    let tail = tail.trim_start();
    let name = name.trim_end();
    if name.is_empty() || !is_hex(tail, 8) {
        return None;
    }
    Some((name, tail, ChecksumFormat::Sfv))
}

/// The format a digest-first token's LENGTH implies, or `None` for a
/// token that is not a digest at all.
fn digest_format(tok: &str) -> Option<ChecksumFormat> {
    match tok.len() {
        32 if is_hex(tok, 32) => Some(ChecksumFormat::Md5),
        40 if is_hex(tok, 40) => Some(ChecksumFormat::Sha1),
        64 if is_hex(tok, 64) => Some(ChecksumFormat::Sha256),
        _ => None,
    }
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The digest of one file, in the format's own hex.
pub fn digest_of(path: &Path, format: ChecksumFormat) -> std::io::Result<String> {
    // TWO `Digest` traits, from the two `digest` versions this
    // workspace already resolves - see the `md-5` entry in Cargo.toml.
    // Named rather than glob-imported so it is obvious at each call
    // site which one is in play.
    use md5::Digest as Md5Digest;
    use sha2::Digest as _;

    let mut file = std::fs::File::open(path)?;
    // 1 MiB: big enough that the syscall is not the cost and small
    // enough that a hundred of these in a queue is not a hundred MiB.
    let mut buf = vec![0u8; 1 << 20];
    match format {
        ChecksumFormat::Sfv => {
            let mut crc = 0u32;
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                // The engine's own CRC32, which is the SIMD one the
                // download path uses - not a second table here.
                crc = nzbkit::yenc_simd::crc32(&buf[..n], crc);
            }
            Ok(format!("{crc:08x}"))
        }
        ChecksumFormat::Md5 => {
            // `nzbkit::md5fast::Md5` is the workspace's MD5 and
            // implements the same digest traits `sha2` does, so it
            // drives through the identical loop.
            let mut h = nzbkit::md5fast::Md5::default();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                Md5Digest::update(&mut h, &buf[..n]);
            }
            Ok(hex(&Md5Digest::finalize(h)))
        }
        ChecksumFormat::Sha1 => {
            let mut h = sha1::Sha1::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(hex(&h.finalize()))
        }
        ChecksumFormat::Sha256 => {
            let mut h = sha2::Sha256::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(hex(&h.finalize()))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The text of a checksum file over these `(name, path)` pairs.
///
/// `name` is what goes IN the file; the caller decided whether that is
/// a basename or a relative path, because only the caller knows where
/// the output file will sit.
pub fn write_text(
    entries: &[(String, PathBuf)],
    format: ChecksumFormat,
) -> std::io::Result<String> {
    write_text_watched(entries, format, |_| true)
}

/// [`write_text`] with a per-file callback: it is handed the index of
/// the file about to be hashed and answers whether to carry on.
///
/// This is where a checksum create's cancellation actually has to live.
/// The runner's control loop ran BEFORE this call and only built a list
/// of paths, so every byte of hashing happened inside one uninterruptible
/// call afterwards: a Cancel pressed during a 200 GiB folder was noticed
/// when the last file finished, and the progress bar had already read
/// 100% before the first one started. API.md promises cancellation
/// between files, which is exactly the grain this gives it.
pub fn write_text_watched(
    entries: &[(String, PathBuf)],
    format: ChecksumFormat,
    mut before_each: impl FnMut(usize) -> bool,
) -> std::io::Result<String> {
    let mut out = String::new();
    if format == ChecksumFormat::Sfv {
        // The one comment `cksfv` itself writes. A reader that chokes
        // on it chokes on every SFV in the field.
        out.push_str("; Generated by parfast\n");
    }
    for (i, (name, path)) in entries.iter().enumerate() {
        if !before_each(i) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        let d = digest_of(path, format)?;
        let name = name.replace('\\', "/");
        if format == ChecksumFormat::Sfv {
            out.push_str(&format!("{name} {d}\n"));
        } else {
            // The binary-mode star, which is what `md5sum -c` expects
            // back from a file `md5sum -b` wrote and what every tool
            // accepts either way.
            out.push_str(&format!("{d} *{name}\n"));
        }
    }
    Ok(out)
}

/// The file a checksum line's `name` refers to, relative to `base`, or
/// `None` for a name this reader refuses to follow.
///
/// # Why this is not `disk::sanitize_out_name`
///
/// It was, and that was a category error. `sanitize_out_name` is the
/// DOWNLOAD path's name function: it takes a name declared by a stranger
/// in an NZB, a PAR2 FileDesc or an archive entry and answers what to
/// CREATE on disk for it, so it is free to rewrite anything awkward -
/// it trims leading whitespace, folds trailing dots and spaces the way
/// Windows would, maps a leading dot to `_`, and caps long components.
/// That is right for a name being invented and wrong for a name being
/// LOOKED UP: every one of those rewrites names a DIFFERENT file from
/// the one the checksum line points at.
///
/// The damage is not theoretical and does not need a hostile file. Write
/// a checksum file over `" report.txt"` with this very crate and check it
/// in place, and the read resolves `"report.txt"`: a file that exists,
/// was just hashed, and is reported Missing. `.config` checks as
/// `_config`. A verifier that silently nominates a neighbouring file is
/// worse than one that finds nothing, because both of its answers are
/// wrong - Missing for a file that is there, and, where the rewritten
/// name happens to exist, a verdict about a file nobody asked about.
///
/// So the traversal rules are kept and the renaming is dropped: an
/// absolute name, a drive or UNC prefix, and any `.`, `..` or empty
/// component are refused outright (`None`), and every other component is
/// joined onto `base` EXACTLY as the file spells it. Windows keeps its
/// own restrictions for free - a name it cannot open simply does not
/// open, and that is a Missing row rather than a rewrite.
pub fn resolve(base: &Path, name: &str) -> Option<PathBuf> {
    // Both separators: a checksum file written on Windows carries `\`,
    // and `parse` has already folded those to `/`. Doing it again here
    // means a caller resolving a raw name is held to the same rule.
    if name.is_empty() || name.starts_with('/') || name.starts_with('\\') {
        return None;
    }
    // `C:...`, and the `\\?\` / `\\server\share` forms, both of which
    // `Path::join` would let win over `base` outright.
    let mut chars = name.chars();
    if chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.next() == Some(':') {
        return None;
    }
    let mut out = base.to_path_buf();
    let mut any = false;
    for part in name.split(['/', '\\']) {
        if part.is_empty() || part == "." || part == ".." {
            return None;
        }
        out.push(part);
        any = true;
    }
    // Belt for a platform whose `Path::push` reads something in a
    // component as a root after all.
    if !any || !out.starts_with(base) {
        return None;
    }
    Some(out)
}

/// Check every entry against the files beside `base`.
pub fn check(file: &ChecksumFile, base: &Path) -> std::io::Result<Vec<Row>> {
    let mut rows = Vec::with_capacity(file.entries.len());
    for e in &file.entries {
        // A name from a checksum file is untrusted text like any other
        // sidecar's, so it is resolved and not simply joined - but by
        // [`resolve`], which refuses what it cannot follow instead of
        // rewriting it into some other file. See there.
        let (actual, status) = match resolve(base, &e.name)
            .ok_or_else(|| std::io::Error::other("unusable name"))
            .and_then(|path| digest_of(&path, file.format))
        {
            Ok(d) if d == e.digest => (d, RowStatus::Ok),
            Ok(d) => (d, RowStatus::Mismatch),
            Err(_) => (String::new(), RowStatus::Missing),
        };
        rows.push(Row {
            name: e.name.clone(),
            expected: e.digest.clone(),
            actual,
            status,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    /// An SFV written by `cksfv`, with its comment header and a name
    /// holding a space. Digest LAST.
    #[test]
    fn a_cksfv_file_parses() {
        let f = parse(&fixture("cksfv.sfv"), Some(ChecksumFormat::Sfv)).expect("parses");
        assert_eq!(f.format, ChecksumFormat::Sfv);
        assert_eq!(
            f.entries,
            vec![
                Entry {
                    name: "alpha.bin".into(),
                    digest: "3d08bb4a".into()
                },
                Entry {
                    name: "two words.bin".into(),
                    digest: "0b3c4d5e".into()
                },
                Entry {
                    name: "sub/beta.bin".into(),
                    digest: "ffffffff".into()
                },
            ]
        );
    }

    /// `md5sum -b` output: digest FIRST, a star before the name.
    #[test]
    fn an_md5sum_file_parses() {
        let f = parse(&fixture("md5sum.md5"), None).expect("parses");
        assert_eq!(f.format, ChecksumFormat::Md5);
        assert_eq!(f.entries.len(), 2);
        assert_eq!(f.entries[0].name, "alpha.bin");
        assert_eq!(f.entries[0].digest, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(f.entries[1].name, "two words.bin");
    }

    /// `sha256sum` output, two spaces and no star, upper-case hex
    /// folded down.
    #[test]
    fn a_sha256sum_file_parses_and_folds_its_hex() {
        let f = parse(&fixture("sha256sum.sha256"), None).expect("parses");
        assert_eq!(f.format, ChecksumFormat::Sha256);
        assert_eq!(f.entries.len(), 2);
        assert!(
            f.entries[1].digest.chars().all(|c| !c.is_ascii_uppercase()),
            "upper-case hex is folded so a comparison is a comparison"
        );
    }

    #[test]
    fn a_sha1sum_file_parses() {
        let f = parse(&fixture("sha1sum.sha1"), None).expect("parses");
        assert_eq!(f.format, ChecksumFormat::Sha1);
        assert_eq!(f.entries.len(), 1);
        assert_eq!(f.entries[0].digest.len(), 40);
    }

    /// The CONTENT decides, not the name: an SFV saved as `.md5` is
    /// still an SFV, because where the digest sits is what a checker
    /// has to know.
    #[test]
    fn the_content_decides_the_format_and_not_the_extension() {
        let f = parse("alpha.bin 3d08bb4a\n", Some(ChecksumFormat::Md5)).expect("parses");
        assert_eq!(f.format, ChecksumFormat::Sfv);
    }

    #[test]
    fn a_file_that_mixes_two_shapes_is_refused_at_the_line_that_mixes_them() {
        let e = parse(
            "alpha.bin 3d08bb4a\nd41d8cd98f00b204e9800998ecf8427e *beta.bin\n",
            None,
        )
        .expect_err("mixed shapes refuse");
        assert_eq!(e.code, "mixed_formats");
        assert!(e.message.contains("line 2"), "{}", e.message);
    }

    #[test]
    fn comments_and_blank_lines_are_skipped_in_both_dialects() {
        let f = parse("; a comment\n\n# another\nalpha.bin 3d08bb4a\n", None).expect("parses");
        assert_eq!(f.entries.len(), 1);
    }

    /// The round trip over real bytes, in all four formats: write the
    /// file, check it, then damage one byte and check again.
    #[test]
    fn every_format_round_trips_and_catches_a_single_flipped_byte() {
        let d = std::env::temp_dir().join(format!(
            "parfast-session-ck-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        std::fs::write(d.join("a.bin"), b"the quick brown fox").expect("a");
        std::fs::write(d.join("b b.bin"), vec![9u8; 5000]).expect("b");
        let entries = vec![
            ("a.bin".to_string(), d.join("a.bin")),
            ("b b.bin".to_string(), d.join("b b.bin")),
        ];
        for format in [
            ChecksumFormat::Sfv,
            ChecksumFormat::Md5,
            ChecksumFormat::Sha1,
            ChecksumFormat::Sha256,
        ] {
            let text = write_text(&entries, format).expect("write");
            let parsed = parse(&text, Some(format)).expect("re-parse");
            assert_eq!(parsed.format, format, "{format:?}");
            assert_eq!(parsed.entries.len(), 2, "{format:?}: {text}");
            let rows = check(&parsed, &d).expect("check");
            assert!(
                rows.iter().all(|r| r.status == RowStatus::Ok),
                "{format:?}: {rows:?}"
            );

            std::fs::write(d.join("a.bin"), b"the quick brown fax").expect("damage");
            let rows = check(&parsed, &d).expect("check");
            assert_eq!(rows[0].status, RowStatus::Mismatch, "{format:?}");
            assert_eq!(rows[1].status, RowStatus::Ok, "{format:?}");
            std::fs::write(d.join("a.bin"), b"the quick brown fox").expect("restore");
        }
        // And a name nothing answers is Missing rather than an error
        // that stops the whole table.
        let f = ChecksumFile {
            format: ChecksumFormat::Sfv,
            entries: vec![Entry {
                name: "nothing.bin".into(),
                digest: "00000000".into(),
            }],
        };
        assert_eq!(check(&f, &d).expect("check")[0].status, RowStatus::Missing);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Lead 3 of the 17 Sep sweep: hashing stops when the caller says
    /// stop, BETWEEN files, which is the grain API.md advertises.
    ///
    /// The runner's control loop ran before the hashing rather than
    /// around it, so the whole pass happened inside one uninterruptible
    /// call: a Cancel on a large folder was honoured when the last file
    /// finished. Deterministic here - the callback refuses at a known
    /// index and the test reads back which files were opened at all.
    #[test]
    fn hashing_stops_between_files_when_the_caller_says_so() {
        let d = std::env::temp_dir().join(format!(
            "parfast-session-ck-cancel-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        let entries: Vec<(String, PathBuf)> = (0..4)
            .map(|i| {
                let name = format!("f{i}.bin");
                std::fs::write(d.join(&name), vec![i as u8; 64]).expect("fixture");
                (name, d.join(format!("f{i}.bin")))
            })
            .collect();

        let mut seen = Vec::new();
        let err = write_text_watched(&entries, ChecksumFormat::Sha256, |i| {
            seen.push(i);
            i < 2
        })
        .expect_err("a refused callback must stop the pass");
        assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(
            seen,
            vec![0, 1, 2],
            "the pass must stop AT the refusal, not after the list"
        );

        // ...and an accepting callback still sees every file, in order.
        let mut seen = Vec::new();
        let text = write_text_watched(&entries, ChecksumFormat::Sha256, |i| {
            seen.push(i);
            true
        })
        .expect("write");
        assert_eq!(seen, vec![0, 1, 2, 3]);
        assert_eq!(text.lines().count(), 4);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A name that tries to walk out of the directory is resolved by
    /// the engine's own sanitizer, exactly as a FileDesc name is.
    #[test]
    fn a_traversing_name_cannot_reach_outside_the_base() {
        let d = std::env::temp_dir().join(format!(
            "parfast-session-ck-esc-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        let f = ChecksumFile {
            format: ChecksumFormat::Md5,
            entries: vec![Entry {
                name: "../../../../etc/passwd".into(),
                digest: "d41d8cd98f00b204e9800998ecf8427e".into(),
            }],
        };
        let rows = check(&f, &d).expect("check");
        assert_eq!(rows[0].status, RowStatus::Missing, "{rows:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The known-answer digests, so a wiring mistake between the four
    /// implementations is caught by value and not only by round trip.
    #[test]
    fn the_four_digests_are_the_known_answers_for_abc() {
        let d = std::env::temp_dir().join(format!(
            "parfast-session-ck-kat-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        let p = d.join("abc");
        std::fs::write(&p, b"abc").expect("abc");
        assert_eq!(digest_of(&p, ChecksumFormat::Sfv).expect("crc"), "352441c2");
        assert_eq!(
            digest_of(&p, ChecksumFormat::Md5).expect("md5"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            digest_of(&p, ChecksumFormat::Sha1).expect("sha1"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            digest_of(&p, ChecksumFormat::Sha256).expect("sha256"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
