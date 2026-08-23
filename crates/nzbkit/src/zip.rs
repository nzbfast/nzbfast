//! Zip container detection: the one place that answers "is there a zip
//! here, and which files make it up".
//!
//! Detection lived in three hand-rolled copies scattered through the
//! extraction paths, and they disagreed. The disagreements were not
//! cosmetic: a byte-split `name.zip.001` set matched none of them, so a
//! job whose entire payload was still packed completed *silently*, and
//! a zip sitting in a release subfolder was never looked at because the
//! recursion only seeded subdirs holding RAR or 7z magic. One detector
//! that every path shares is what keeps those shapes from reappearing.
//!
//! Shapes recognised:
//! - single `.zip` / `.zipx` container;
//! - obfuscated single container - extension stripped, identified by
//!   magic (the same trick the RAR and 7z paths use);
//! - WinZip-spanned sets: `.z01`, `.z02`, … with the *final* segment
//!   named `.zip` (that trailing `.zip` is the one holding the central
//!   directory, so it sorts LAST, not first);
//! - byte-split sets: `name.zip.001`/`.002`, or bare `.001`/`.002` where
//!   the first part carries the magic.
//!
//! Two rules the detectors must never break, both learned from real
//! posts:
//!
//! 1. **A named file is never magic-sniffed.** Comics, ebooks, office
//!    documents and java/android bundles are all zip containers wearing
//!    a different extension, and unpacking one destroys the very file
//!    the user downloaded. Sniffing is for files whose name has already
//!    failed to identify them - extensionless, or a bare numeric part.
//! 2. **`.cbz` and friends are payload, not packaging.** Even if a
//!    future caller starts sniffing more widely, [`is_final_name`] is
//!    the explicit stop.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Zip container start signatures we accept at offset 0.
///
/// - `PK\x03\x04` local file header: the ordinary case.
/// - `PK\x07\x08` and `PK00`: spanning markers, written ahead of the
///   first local header in the first segment of a spanned set.
///
/// `PK\x05\x06` (end-of-central-directory) is deliberately absent: alone
/// it means an EMPTY archive, and four bytes is too weak a signal to
/// spend on a container with nothing in it.
const MAGICS: [&[u8; 4]; 3] = [b"PK\x03\x04", b"PK\x07\x08", b"PK00"];

/// Extensions whose bytes ARE a zip container but whose file is the
/// deliverable. Unpacking one is data loss, not extraction.
const FINAL_FILE_EXTS: &[&str] = &[
    "cbz", "epub", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "odt", "ods", "odp", "odg",
    "jar", "war", "aar", "apk", "ipa", "xpi", "crx", "vsix", "whl", "kra", "ora", "sketch", "usdz",
];

/// How the container is laid out on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// One self-contained file (named, or obfuscated by magic).
    Single,
    /// WinZip-spanned: `.z01`, `.z02`, …, `.zip`.
    Spanned,
    /// Raw byte split: `.zip.001`/`.002`, or bare `.001`/`.002`.
    ByteSplit,
}

impl Shape {
    /// Short label for logs and the dashboard note.
    pub fn label(self) -> &'static str {
        match self {
            Shape::Single => "zip",
            Shape::Spanned => "spanned zip",
            Shape::ByteSplit => "split zip",
        }
    }
}

/// One zip container found in a directory: every on-disk part that forms
/// it, in the order they must be read.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The name to show a user - the recognisable member of the set
    /// (the trailing `.zip` for a spanned set, else the first part).
    pub name: String,
    /// Parts in read order. Single containers hold exactly one.
    pub parts: Vec<PathBuf>,
    pub shape: Shape,
}

/// Does the file start with a zip container signature? Reads 4 bytes.
///
/// Callers must have established that the NAME does not already identify
/// the file (see the module note on never sniffing named files).
pub fn has_magic(path: &Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok_and(|()| MAGICS.contains(&&b))
}

/// A zip-container file whose extension marks it as the payload itself
/// (`.cbz`, `.epub`, `.docx`, …). Never unpack one.
pub fn is_final_file(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| is_final_name(&n.to_string_lossy().to_ascii_lowercase()))
}

/// [`is_final_file`] over an already-lowercased file name.
fn is_final_name(lower: &str) -> bool {
    Path::new(lower)
        .extension()
        .is_some_and(|e| FINAL_FILE_EXTS.contains(&&*e.to_string_lossy()))
}

/// WinZip-spanned continuation part: `.z01` … (letter z + at least two
/// digits). `.zip` itself is the set's LAST segment and is matched
/// separately - `ip` is not digits, so it never lands here.
fn spanned_part(lower: &str) -> Option<(String, u32)> {
    let (head, tail) = lower.rsplit_once('.')?;
    let digits = tail.strip_prefix('z')?;
    if digits.len() < 2 || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((head.to_string(), digits.parse().ok()?))
}

/// Byte-split part of a named zip: `movie.zip.001`. Mirrors the 7z
/// `split_7z_part` grammar exactly, with `.zip`/`.zipx` as the stem.
fn split_part(lower: &str) -> Option<(String, u32)> {
    let (head, tail) = lower.rsplit_once('.')?;
    if tail.is_empty() || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    (head.ends_with(".zip") || head.ends_with(".zipx"))
        .then(|| (head.to_string(), tail.parse().ok().unwrap_or(u32::MAX)))
}

/// Bare numeric part: `movie.001`. Ambiguous by name alone (RAR numeric
/// volumes and hjsplit use the same grammar), so the caller gates the
/// set on the first part carrying zip magic.
///
/// Index 0 is rejected, matching [`numeric_split_part_name`]'s stream
/// grammar: no split tool numbers from zero, and accepting a junk
/// same-stem `.000` sorted it FIRST in the group, so the magic gate
/// sniffed the junk file and silently dropped the whole valid
/// `.001`/`.002` set (Codex sweep 3 Aug M8).
fn numeric_part(lower: &str) -> Option<(String, u32)> {
    let (head, tail) = lower.rsplit_once('.')?;
    if !(2..=4).contains(&tail.len()) || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let idx: u32 = tail.parse().ok()?;
    (idx >= 1).then(|| (head.to_string(), idx))
}

/// Is this single path part of a zip container? Name-identified shapes
/// answer without touching the disk; extensionless files and bare
/// numeric parts need the magic.
///
/// This is the per-path predicate the extraction recursion uses to
/// decide "is there something extractable here", so it deliberately says
/// yes to a lone member of a split set - a directory holding only
/// `movie.zip.002` still has an archive problem worth reporting.
pub fn is_container(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    let lower = name.to_string_lossy().to_ascii_lowercase();
    if is_final_name(&lower) {
        return false;
    }
    if lower.ends_with(".zip") || lower.ends_with(".zipx") {
        return true;
    }
    if spanned_part(&lower).is_some() || split_part(&lower).is_some() {
        return true;
    }
    let sniffable = path.extension().is_none() || numeric_part(&lower).is_some();
    sniffable && has_magic(path)
}

/// `<base>.zip.<NNN>` (or `.zipx`) - a byte-split zip container part,
/// in the strict grammar the in-stream chase accepts. Returns the
/// lowercased base and the 1-based part index.
///
/// Three or four digits only, mirroring `sevenz_part_name` exactly and
/// for the same reason: accepting one and two digits lets `foo.zip.1`
/// parse as part 1 of the same base as `foo.zip.001` - two files each
/// claiming to be the container's first part. The disk-path collector's
/// `split_part` stays looser on purpose (it reads what is already on
/// disk; this decides what may stream).
pub fn split_part_name(name: &str) -> Option<(String, u32)> {
    let (head, tail) = name.rsplit_once('.')?;
    if tail.len() < 3 || tail.len() > 4 || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let lower_head = head.to_ascii_lowercase();
    if !(lower_head.ends_with(".zip") || lower_head.ends_with(".zipx")) {
        return None;
    }
    let idx: u32 = tail.parse().ok()?;
    (idx >= 1).then_some((lower_head, idx))
}

/// Bare-numeric split part for the STREAM: `movie.001`, no `.zip.`
/// infix. Same digit discipline as [`split_part_name`], plus an
/// ownership fence: a head naming another family's container is never a
/// zip-split candidate, whatever the NZB looks like - `.7z.NNN` belongs
/// to the 7z chase's grammar, and RAR/PAR2 heads carry their own magic,
/// which classifies before the zip arm is ever consulted. The name
/// alone proves nothing (RAR numeric volumes and hjsplit output share
/// it), so the attach gates the DECLARED set on part 1 sniffing
/// `PK\x03\x04` and forfeits otherwise, exactly as a declared
/// `.zip.001` set does.
pub fn numeric_split_part_name(name: &str) -> Option<(String, u32)> {
    let (head, tail) = name.rsplit_once('.')?;
    if tail.len() < 3 || tail.len() > 4 || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let lower_head = head.to_ascii_lowercase();
    if [".zip", ".zipx", ".7z", ".rar", ".par2"]
        .iter()
        .any(|s| lower_head.ends_with(s))
    {
        return None;
    }
    // Rule 2 reaches through the numeric suffix. `comic.cbz.001` is a
    // byte-split of the COMIC: the deliverable's own name is still there,
    // one extension along, and part 1 sniffing `PK\x03\x04` is what a
    // `.cbz` looks like rather than evidence of packaging. Chasing it
    // unpacked the comic and never wrote it (read-only sweep 2 M11); the
    // disk path's plain-split joiner owns this shape.
    if is_final_name(&lower_head) {
        return None;
    }
    let idx: u32 = tail.parse().ok()?;
    (idx >= 1).then_some((lower_head, idx))
}

/// May the in-stream chase consider this POSTED file a single zip
/// container (subject to the magic check the caller performs)?
///
/// Carries phase 0's two standing rules into the streaming layer:
/// a `.cbz`/`.epub`/office file is payload and never attaches, and a
/// NAMED non-zip file (`payload.bin` that happens to start with `PK`)
/// is never magic-sniffed - only an extensionless name earns the sniff.
/// Multi-part shapes (`.z01`, `.zip.001`, bare `.001`) deliberately say
/// no: v1 chases single containers only, and a lone part materializing
/// is exactly what the disk path expects to find.
pub fn chase_eligible_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if is_final_name(&lower) {
        return false;
    }
    lower.ends_with(".zip") || lower.ends_with(".zipx") || Path::new(&lower).extension().is_none()
}

/// Name-only test, for deciding BEFORE anything is on disk whether a
/// post is zip-packed (the NZB's file list at enqueue). Magic-only
/// shapes - obfuscated containers, bare numeric parts - cannot be
/// answered from a name and are deliberately not guessed here.
pub fn name_is_zip_shaped(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if is_final_name(&lower) {
        return false;
    }
    lower.ends_with(".zip")
        || lower.ends_with(".zipx")
        || spanned_part(&lower).is_some()
        || split_part(&lower).is_some()
}

/// Every zip container directly under `dir` (one level, like the 7z
/// collector), each with its parts in read order.
pub fn scan(dir: &Path) -> Vec<Finding> {
    // `.zip`/`.zipx` singles, keyed by stem so a spanned set can claim
    // its trailing segment back out of here.
    let mut named: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut spanned: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    let mut split: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    let mut numeric: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    let mut obfuscated: Vec<PathBuf> = Vec::new();

    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    for e in rd.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = e.path();
        let lower = e.file_name().to_string_lossy().to_ascii_lowercase();
        if is_final_name(&lower) {
            continue;
        }
        if let Some((stem, n)) = spanned_part(&lower) {
            spanned.entry(stem).or_default().insert(n, path);
        } else if let Some((stem, n)) = split_part(&lower) {
            split.entry(stem).or_default().insert(n, path);
        } else if lower.ends_with(".zip") || lower.ends_with(".zipx") {
            let stem = lower
                .rsplit_once('.')
                .map(|(h, _)| h.to_string())
                .unwrap_or(lower);
            named.insert(stem, path);
        } else if let Some((stem, n)) = numeric_part(&lower) {
            // A `.001` whose STEM is a final payload name (`comic.cbz`,
            // `book.epub`, an office document) is a byte-split of that
            // payload. Grouping it here sniffed the zip magic in part 1
            // and unpacked the comic instead of rebuilding it, while the
            // plain-split joiner refused the same set for carrying
            // archive magic - so the file simply never appeared
            // (read-only sweep 2 M11). Rule 2 above is a NAME rule, and
            // the name survives the numeric suffix.
            if is_final_name(&stem) {
                continue;
            }
            numeric.entry(stem).or_default().insert(n, path);
        } else if path.extension().is_none() && has_magic(&path) {
            obfuscated.push(path);
        }
    }

    let mut out = Vec::new();
    // Spanned first, so each one can take its trailing `.zip` before the
    // singles pass sees it.
    for (stem, parts) in spanned {
        let mut parts: Vec<PathBuf> = parts.into_values().collect();
        let tail = named.remove(&stem);
        let name = match &tail {
            Some(z) => file_name(z),
            None => file_name(&parts[0]),
        };
        parts.extend(tail);
        out.push(Finding {
            name,
            parts,
            shape: Shape::Spanned,
        });
    }
    for (_stem, parts) in split {
        let parts: Vec<PathBuf> = parts.into_values().collect();
        out.push(Finding {
            name: file_name(&parts[0]),
            parts,
            shape: Shape::ByteSplit,
        });
    }
    // Bare numeric parts are only a zip set if the first part says so -
    // `.001` is also how RAR numeric volumes and hjsplit name themselves.
    for (_stem, parts) in numeric {
        let parts: Vec<PathBuf> = parts.into_values().collect();
        if !has_magic(&parts[0]) {
            continue;
        }
        out.push(Finding {
            name: file_name(&parts[0]),
            parts,
            shape: Shape::ByteSplit,
        });
    }
    for (_stem, path) in named {
        out.push(Finding {
            name: file_name(&path),
            parts: vec![path],
            shape: Shape::Single,
        });
    }
    for path in obfuscated {
        out.push(Finding {
            name: file_name(&path),
            parts: vec![path],
            shape: Shape::Single,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The first zip container in `dir`, if any - the question every
/// reporting path asks.
pub fn first(dir: &Path) -> Option<Finding> {
    scan(dir).into_iter().next()
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

/// Does this container hold at least one password-protected entry?
///
/// The sibling of `rar::needs_password` / `nameprobe::sevenz_needs_password`,
/// and the reason it exists: an encrypted zip is the one locked shape the
/// post-processing surface could not SEE, so a job carrying nothing but
/// one reported "an archive was left packed" and offered the folder,
/// while the whole remedy was a password we may already hold.
///
/// A container we cannot even open is not "locked" - say no and let the
/// ordinary unpack path report why it could not be read.
pub fn needs_password(parts: &[PathBuf]) -> bool {
    Archive::open(parts).is_ok_and(|a| a.entries().iter().any(|e| e.is_encrypted()))
}

/// Does `password` open this container's encrypted entries?
///
/// Cheap by construction: it reads each scheme's own verifier out of the
/// entry framing (WinZip AE's 2-byte password-verification value, or
/// ZipCrypto's check byte) and decodes nothing. That is the same first
/// gate [`Archive::read_entry_to_with`] applies, with the same standing:
/// a verifier hit is a CANDIDATE, and the CRC32 or the AE HMAC over the
/// real extraction remains the authority. A ZipCrypto check byte is one
/// byte, so it accepts a wrong password once in 256 tries - which is why
/// no caller may treat this as proof, only as "worth spending an
/// extraction on".
///
/// An unencrypted container answers `true` for any password: nothing is
/// locked, so nothing can be wrong.
pub fn password_opens(parts: &[PathBuf], password: Option<&str>) -> bool {
    let Ok(archive) = Archive::open(parts) else {
        return false;
    };
    archive
        .entries()
        .iter()
        .filter(|e| e.is_encrypted())
        .all(|e| {
            archive
                .entry_data_offset(e)
                .ok()
                .and_then(|data| {
                    let end = data.checked_add(e.compressed_size)?;
                    Some(entry_crypto(&archive.parts, e, data, end, password).is_ok())
                })
                .unwrap_or(false)
        })
}

/// What a self-extracting stub has behind it, when the payload is a zip.
///
/// Both variants mean the same STRUCTURAL fact - a readable zip archive
/// begins `base` bytes into the file, which is what a self-extracting zip
/// is - and differ only on whether unpacking it would be extraction or
/// vandalism. See [`stubbed_archive`] for why that second question has to
/// be asked here rather than by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stubbed {
    /// Packaging: the archive is a wrapper around a payload, and getting
    /// the payload out means unpacking it.
    Packaging { base: u64 },
    /// The archive IS the deliverable - a Java archive, an Android
    /// package, an Office document - and the executable in front of it is
    /// a launcher for it, not a self-extractor. `what` names the shape for
    /// the log line.
    FinalFile { base: u64, what: &'static str },
}

/// Entry names that identify a zip as the deliverable itself.
///
/// This is the content-side twin of `FINAL_FILE_EXTS`, and it exists for
/// the same reason: unpacking one of these destroys the very file the user
/// downloaded. The extension check cannot do the work here because the
/// name has been consumed by the stub in front - a Launch4j or JSmooth
/// wrapper is `app.exe`, and the jar inside it has no name at all.
///
/// Each marker is anchored: a root entry, or the one fixed path its format
/// mandates. A merely SIMILAR name deeper in the tree is payload.
const FINAL_CONTENT_MARKERS: &[(&str, &str)] = &[
    // Launch4j, JSmooth, exe4j, one-jar: an executable stub whose appended
    // zip is a jar. This is the shape that makes a zip stub-probe risky at
    // all, and the only one measured in the wild.
    ("META-INF/MANIFEST.MF", "a Java archive"),
    ("AndroidManifest.xml", "an Android package"),
    ("[Content_Types].xml", "an Office Open XML document"),
    // EPUB and OpenDocument both mandate a stored root `mimetype` entry.
    ("mimetype", "an EPUB or OpenDocument file"),
    // NW.js concatenates `package.nw` - the app's own resources - onto
    // nw.exe. Same class as the jar: the zip is the program, not a wrapper.
    ("package.json", "an application resource bundle"),
    // InstallAnywhere (Flexera) is the one installer builder measured to
    // append its payload as a PLAINTEXT zip rather than keeping it in a
    // private container the way NSIS and Inno do - a bundled JRE, the
    // native launchers, and the media archives, all readable. Found on
    // a Windows box (TODO 159 item 8) in a vendor installer sitting in
    // Downloads, which exploded to 7,411 files. Same class as the jar:
    // the zip IS the program. Two markers because both are fixed paths
    // the builder writes, and either alone would be a single-sample bet.
    (
        "InstallerData/IAClasses.zip",
        "an InstallAnywhere installer",
    ),
    (
        "InstallerData/laxmanifest.txt",
        "an InstallAnywhere installer",
    ),
];

/// Does a zip archive start somewhere OTHER than byte 0 of this file, and
/// if so is it packaging or the deliverable?
///
/// The entry gate for self-extracting zips, and the reason it is
/// structural rather than a signature scan: `PK\x03\x04` is the universal
/// way to staple data onto a binary, so scanning an executable's head for
/// one claims ordinary programs. Measured over 1,810 real binaries on a
/// Windows box the household actually uses - 1,497 executables, a real
/// `Downloads` history and 36 vendor directories under `Program Files` -
/// a head scan for `PK\x03\x04` past offset 0 claims 98, among them every
/// copy of Edge, Chrome and Windows Defender on the machine. This claims
/// ONE, because it asks the question the format can actually answer:
/// locate the end-of-central-directory record, take the shortfall to
/// where the directory says it ends as the prefix's length, and CONFIRM
/// a directory record is sitting there (`find_central_directory`, which
/// every reader already shares). Junk bytes cannot pass that; only a real
/// archive can.
///
/// What a real archive passing it does NOT establish is that unpacking it
/// is the right thing to do, and the one claim on that corpus is exactly
/// that case: an InstallAnywhere installer whose payload really is a
/// plaintext zip. A jar stapled to a launcher stub is a genuine appended
/// zip too. Hence the second half, and hence this returning a verdict
/// rather than a bool: the caller has to be able to say "left alone, that
/// is a Java archive" instead of silently declining.
///
/// `None` for an archive starting at byte 0 (a bare zip wearing the wrong
/// name - a different path's business), for a spanned set, and for
/// anything that is not a readable zip.
pub fn stubbed_archive(path: &Path) -> Option<Stubbed> {
    let parts = [path.to_path_buf()];
    let parts = Parts::open(&parts).ok()?;
    let dir = find_central_directory(&parts).ok()?;
    if dir.base == 0 || dir.multi_disk {
        return None;
    }
    let entries = parse_central_directory(&parts, &dir).ok()?;
    if entries.is_empty() {
        return None;
    }
    let base = dir.base;
    for (marker, what) in FINAL_CONTENT_MARKERS {
        if entries.iter().any(|e| e.name == *marker) {
            return Some(Stubbed::FinalFile { base, what });
        }
    }
    Some(Stubbed::Packaging { base })
}

// ---------------------------------------------------------------------------
// Reader: central-directory driven extraction (disk path)
// ---------------------------------------------------------------------------
//
// Deliberately NOT a streaming reader. The disk path has the whole
// container, so it reads the CENTRAL DIRECTORY, which is the format's
// authoritative index - written after every entry's real size is known.
// That side-steps the two traps that make zip nasty to stream: an entry
// whose local header carries zero sizes with the real ones in a trailing
// data descriptor (general-purpose flag bit 3), and the fact that the
// only way to find the next local header without sizes is to scan for a
// signature that also occurs inside stored payload. Neither can bite a
// reader that never trusts a local header for anything but where the
// bytes begin.
//
// Multi-part sets are read through one logical byte-space rather than
// being concatenated into a scratch file first (the way the 7z path
// does): a split set therefore needs no second copy on disk. For a
// WinZip-SPANNED set the central directory addresses entries as
// (disk number, offset within that disk), so the part lengths are what
// turn those back into logical offsets - see `Parts::logical`.

/// Why a zip could not be read or extracted. Every variant is a
/// sentence fragment the caller prints after "…could not be unpacked: ".
#[derive(Debug)]
pub enum ZipError {
    Io(std::io::Error),
    /// Structurally not a zip we can read (no end-of-central-directory,
    /// truncated headers, offsets outside the file).
    Malformed(&'static str),
    /// Readable, but this entry uses something we deliberately decline.
    /// Carries the user-facing reason.
    Unsupported(String),
    /// An entry's bytes did not match its stored CRC32.
    BadCrc {
        name: String,
    },
    /// An encrypted entry's password check refused the supplied
    /// password (ZipCrypto check byte / AE verifier).
    WrongPassword {
        name: String,
    },
}

impl std::fmt::Display for ZipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZipError::Io(e) => write!(f, "{e}"),
            ZipError::Malformed(w) => write!(f, "malformed zip ({w})"),
            ZipError::Unsupported(w) => write!(f, "{w}"),
            ZipError::BadCrc { name } => {
                write!(f, "{name} failed its stored CRC - the archive is damaged")
            }
            ZipError::WrongPassword { name } => {
                write!(f, "the password does not open {name}")
            }
        }
    }
}

impl From<std::io::Error> for ZipError {
    fn from(e: std::io::Error) -> ZipError {
        ZipError::Io(e)
    }
}

/// Compression methods this reader decodes. Everything else is declined
/// BY NAME so the user learns which one they hit, instead of a blanket
/// "not supported" (store + deflate is ~99% of real zips).
pub(crate) const METHOD_STORE: u16 = 0;
pub(crate) const METHOD_DEFLATE: u16 = 8;
/// bzip2 (method 12). Its decoder is already in the dependency tree for
/// 7z, and a bzip2 zip used to FAIL the job outright - neither the
/// streaming chase nor the disk reader could open one - so carrying it
/// costs nothing and turns a dead shape into a working one.
pub(crate) const METHOD_BZIP2: u16 = 12;
/// LZMA (method 14). Same bargain as bzip2: `lzma-rust2` is already in
/// the dependency tree for 7z's LZMA streams (via sevenz-rust2), so
/// decoding it costs no new code in the binary that was not there
/// already.
pub(crate) const METHOD_LZMA: u16 = 14;

/// The largest LZMA dictionary a zip entry may declare. The field is a
/// hostile u32 from a downloaded header, so an absurd declaration is
/// refused up front rather than honoured at read time.
///
/// 256 MiB is not slack, it is exactly 7-Zip's top preset - MEASURED
/// 21 Aug 2026 with `7zz a -tzip -mm=LZMA -mx=N` over a payload larger
/// than the window (7-Zip shrinks the dictionary to fit its input, so a
/// small fixture reports the input size and tells you nothing):
///
/// | `-mx` | 1      | 3     | 5      | 7       | 9       |
/// |-------|--------|-------|--------|---------|---------|
/// | dict  | 256 KiB| 4 MiB | 32 MiB | 128 MiB | 256 MiB |
///
/// So LOWERING this rejects real archives: anything written with 7-Zip
/// on "Ultra" lands exactly on the cap, and "Maximum" at half of it.
/// Only a hand-passed `-md=` exceeds it (7-Zip will emit 1 GiB if
/// asked), and refusing those is the line this constant draws. Do not
/// tighten it without re-running that table.
///
/// What it costs when honoured: `LzDecoder::ensure_capacity` allocates
/// the WHOLE window in one `try_reserve_exact` on the first read - it
/// does not grow lazily, whatever the name suggests - so a valid
/// `-mx=9` entry spends 256 MiB of untracked RSS (untracked because it
/// lives inside the decoder, not in `MemBudget`) for as long as that
/// entry decodes. `LzmaReader` first clamps the window to the entry's
/// declared uncompressed size, so the real allocation is
/// `min(dict, uncompressed_size)` and a small entry cannot buy a large
/// window - only a LYING header can, which is what the cap bounds.
///
/// A tiny entry declaring the maximum is therefore a ~1,900,000x
/// amplification (see the `oom-4378...` seed and the test over it), and
/// that is accepted deliberately: an attacker who wants the same 256 MiB
/// from a well-formed header needs only ~150 KiB of real compressed body
/// (1 GiB of zeros compresses to 151,548 bytes at `-mx=9`, dictionary
/// 256 MiB - measured the same day), which is a fraction of one article.
/// The ratio is not the attacker's constraint here, so capping the ratio
/// buys nothing a padded archive would not walk straight through, while
/// risking a false refusal on genuinely compressible payloads.
const LZMA_DICT_MAX: u32 = 1 << 28;

/// Can the tree decode this method? One predicate, because the chase and
/// the disk reader must agree: a method the chase declines but the disk
/// pass accepts merely costs a materialize, but the reverse ships a job
/// that streamed nothing and then failed.
pub(crate) fn method_supported(m: u16) -> bool {
    matches!(
        m,
        METHOD_STORE | METHOD_DEFLATE | METHOD_BZIP2 | METHOD_LZMA
    )
}

/// The dictionary-window bytes an LZMA (method 14) entry will allocate,
/// matching `lzma-rust2`'s own sizing: the window is
/// `min(declared_dict, uncompressed_size)`, rounded up to a 16-byte
/// multiple and floored at 4 KiB, allocated whole on first read. Used to
/// charge the process budget in [`decoder`] (TODO 209).
pub(crate) fn lzma_window_bytes(dict_size: u32, uncompressed_size: u64) -> u64 {
    let eff = dict_size.min(u32::try_from(uncompressed_size).unwrap_or(u32::MAX));
    (u64::from(eff).max(4096) + 15) & !15
}

/// An `LzmaReader` that holds a [`crate::mem::LzmaDictCharge`] for its
/// dictionary window, releasing the budget when the decoder drops.
struct BudgetedLzma<R> {
    inner: lzma_rust2::LzmaReader<R>,
    _charge: crate::mem::LzmaDictCharge,
}

impl<R: std::io::Read> std::io::Read for BudgetedLzma<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

/// The decoder for `e`'s real method, wrapping an already-decrypted byte
/// source. Only ever called for a method [`method_supported`] accepted.
/// Construction can read from `src` - zip's LZMA framing puts a
/// properties header in front of the stream - so it can fail like any
/// other read; callers report it with the entry's name the way they do
/// body reads.
pub(crate) fn decoder<'a, R: std::io::Read + 'a>(
    e: &Entry,
    src: R,
) -> std::io::Result<Box<dyn std::io::Read + 'a>> {
    decoder_with(e, src, DictAdmit::TryOnce)
}

/// How a method-14 decode asks for its dictionary window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DictAdmit {
    /// Ask once; a refusal is an error the caller demotes (the chase).
    TryOnce,
    /// Wait for the window. For a caller with no lower rung: the
    /// sequential disk read IS the demotion target, so refusing it files
    /// a valid archive as a gap. See `mem::charge_lzma_dict_waiting`.
    Wait,
}

/// [`decoder`], with the dictionary admission mode named.
pub(crate) fn decoder_with<'a, R: std::io::Read + 'a>(
    e: &Entry,
    mut src: R,
    admit: DictAdmit,
) -> std::io::Result<Box<dyn std::io::Read + 'a>> {
    use std::io::{Error, ErrorKind::InvalidData};
    Ok(match real_method(e) {
        METHOD_STORE => Box::new(src),
        METHOD_BZIP2 => Box::new(bzip2::read::BzDecoder::new(src)),
        METHOD_LZMA => {
            // Zip method 14 prefixes the raw LZMA stream with its own
            // header: a writer version (2 bytes, ignored), the length
            // of the properties blob (2 bytes, spec value 5), then the
            // blob - the lc/lp/pb byte plus the dictionary size. The
            // uncompressed size is NOT in the stream; the entry header
            // carries it, so the decoder is told where to stop instead
            // of trusted to find an end marker (a stream that carries
            // one anyway leaves it for the caller's drain, like any
            // other source tail).
            let mut hdr = [0u8; 4];
            src.read_exact(&mut hdr)?;
            let psize = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
            if psize < 5 {
                return Err(Error::new(InvalidData, "lzma properties are too short"));
            }
            let mut props = vec![0u8; psize];
            src.read_exact(&mut props)?;
            let dict_size = u32::from_le_bytes(props[1..5].try_into().unwrap());
            if dict_size > LZMA_DICT_MAX {
                return Err(Error::new(InvalidData, "lzma dictionary is too large"));
            }
            if e.uncompressed_size == 0 {
                // Nothing to decode, and the known-size decode loop is
                // not defined for a zero-byte target.
                return Ok(Box::new(std::io::empty()));
            }
            // Charge the decode window against the process budget before
            // allocating it (TODO 209 items 2 & 3). The window is
            // `min(dict, uncompressed_size)`, allocated whole on first
            // read; a nested one-pass chase stacks one per level (measured
            // 5 x 256 MiB = 1.25 GiB). Under `TryOnce` an additional
            // concurrent window that would breach the budget is refused
            // here and the chase demotes the container to disk (identical
            // output, sequential decode). The disk read has no such lower
            // rung and asks with `Wait`, because the gauge is process-wide
            // and a refusal there fails a valid archive.
            let window = lzma_window_bytes(dict_size, e.uncompressed_size);
            let charge = match admit {
                DictAdmit::Wait => crate::mem::charge_lzma_dict_waiting(window),
                DictAdmit::TryOnce => crate::mem::charge_lzma_dict(window).ok_or_else(|| {
                    Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "lzma dictionary budget exhausted by concurrent nested decode; \
the disk pass unpacks this container sequentially",
                    )
                })?,
            };
            let reader = lzma_rust2::LzmaReader::new_with_props(
                src,
                e.uncompressed_size,
                props[0],
                dict_size,
                None,
            )?;
            Box::new(BudgetedLzma {
                inner: reader,
                _charge: charge,
            })
        }
        // Deflate by elimination - `method_supported` gates every caller.
        _ => Box::new(flate2::read::DeflateDecoder::new(src)),
    })
}

pub(crate) fn method_name(m: u16) -> &'static str {
    match m {
        0 => "store",
        1 => "shrink",
        6 => "implode",
        8 => "deflate",
        9 => "deflate64",
        12 => "bzip2",
        14 => "lzma",
        93 => "zstd",
        95 => "xz",
        98 => "ppmd",
        99 => "AES",
        _ => "an unknown method",
    }
}

/// Refuse absurd directories rather than allocating for them: a crafted
/// header can claim 4 billion entries in 22 bytes.
const MAX_ENTRIES: u64 = 200_000;
/// Longest entry name we will even consider (the sanitizer still has the
/// final say on where it may land).
const MAX_NAME: usize = 4096;
/// How far back from the end-of-central-directory record a zip64 end
/// record is still allowed to sit and count as the directory's end. The
/// record and its locator are 76 bytes, so this is slack for an
/// extensible data sector and nothing more. It is a bound on where the
/// probe will READ, not just on what it will accept: the one-pass source
/// blocks on bytes that have not arrived, and the EOCD is itself within
/// 65557 bytes of the end, so this keeps the read inside the tail that
/// both callers have already promoted.
const MAX_Z64_TAIL_GAP: u64 = 4096;
/// The zip64 end record's FIXED part (§4.3.6). Anything past it is the
/// extensible data sector, whose length is declared by the record's own
/// size field and nowhere else - so this is the record's minimum length,
/// never its length.
const Z64_FIXED: u64 = 56;

/// One central-directory record, already Zip64-resolved.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Name exactly as stored. NOT yet safe as a path - the caller must
    /// put it through its own sanitizer (zip-slip, drive letters,
    /// backslashes) before touching the filesystem.
    pub name: String,
    pub(crate) method: u16,
    pub(crate) crc32: u32,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    /// Whether the entry is a directory marker (trailing `/`, or the
    /// MS-DOS directory attribute).
    pub is_dir: bool,
    /// General-purpose bit flags (bit 0 = encrypted).
    pub(crate) flags: u16,
    /// DOS modification time - kept because it doubles as ZipCrypto's
    /// password-check byte when bit 3 is set (the CRC was unknown when
    /// the local header was written).
    dos_time: u16,
    /// WinZip AE parameters (method 99), from the 0x9901 extra field.
    aes: Option<AesSpec>,
    /// Unix mode from the external attributes' high half, when the
    /// archive was written on a unix-ish host - `0xA000` marks a symlink.
    unix_mode: u16,
    /// Where this entry's LOCAL header starts, in logical byte-space.
    local_offset: u64,
}

/// WinZip AE (AES) parameters carried by the 0x9901 extra field of a
/// method-99 entry.
#[derive(Debug, Clone, Copy)]
pub struct AesSpec {
    /// 1 = AE-1 (CRC present and checked), 2 = AE-2 (CRC field is
    /// zero BY SPEC; the HMAC is the integrity check).
    pub(crate) vendor_version: u16,
    /// 1 = AES-128, 2 = AES-192, 3 = AES-256.
    pub(crate) strength: u8,
    /// The REAL compression method of the plaintext (store/deflate/…).
    pub method: u16,
}

impl AesSpec {
    /// AE-2 zeroes the CRC field, so the post-decode CRC comparison
    /// must be skipped for it - comparing against 0 would fail every
    /// healthy entry.
    pub fn skips_crc(self) -> bool {
        self.vendor_version == 2
    }
}

impl Entry {
    /// General-purpose bit 0: the entry's payload is encrypted. Both
    /// schemes we read set it (WinZip AE and ZipCrypto), so it is the
    /// question "does this need a password", not "is this refused" - the
    /// wording it carried before [`Archive::read_entry_to_with`] learned
    /// to decrypt.
    pub fn is_encrypted(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// The entry's declared uncompressed size - what a successful
    /// extraction writes, and therefore what an "is this already
    /// unpacked beside its container" test compares against.
    pub fn size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Where this entry's LOCAL header starts, in logical byte-space.
    /// The in-stream chase sorts entries by it (ascending = the order
    /// the articles arrive in) and resolves the data offset through
    /// [`entry_data_offset`].
    pub(crate) fn local_offset(&self) -> u64 {
        self.local_offset
    }

    /// A symlink entry stores its TARGET as its payload; materializing
    /// one would plant a link pointing anywhere the archive likes, so
    /// they are refused outright (the plan's safety checklist).
    pub fn is_symlink(&self) -> bool {
        self.unix_mode & 0xF000 == 0xA000
    }
}

/// A byte source the directory parser reads through. The disk path's
/// [`Parts`] is one; the in-stream chase's blocking view (extract.rs) is
/// the other - which is what lets ONE parser serve both, instead of the
/// three hand-rolled detection copies this module exists to prevent.
pub(crate) trait Source {
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<(), ZipError>;
    /// Total logical size of the container.
    fn total(&self) -> u64;
    /// Can this source resolve the per-disk offsets of a WinZip-spanned
    /// set? Defaults to no: only a source holding the ordered parts (the
    /// disk path) can; a single-file view declines the shape by name
    /// instead of misreading its offsets.
    fn spanning_supported(&self) -> bool {
        false
    }
    /// Turn a central-directory (disk, offset) address into a logical
    /// offset. See the [`Parts`] impl for the two multi-part shapes;
    /// a single-file source never sees `multi_disk` (gated by
    /// [`Self::spanning_supported`] before any address is resolved).
    fn logical(&self, multi_disk: bool, _disk: u32, off: u64) -> Option<u64> {
        (!multi_disk && off <= self.total()).then_some(off)
    }
}

/// The parts of one container as a single logical byte-space.
struct Parts {
    /// (file, logical start offset, length)
    files: Vec<(std::fs::File, u64, u64)>,
    total: u64,
}

impl Parts {
    fn open(parts: &[PathBuf]) -> Result<Parts, ZipError> {
        let mut files = Vec::with_capacity(parts.len());
        let mut at = 0u64;
        for p in parts {
            let f = std::fs::File::open(p)?;
            let len = f.metadata()?.len();
            files.push((f, at, len));
            at += len;
        }
        if at == 0 {
            return Err(ZipError::Malformed("empty container"));
        }
        Ok(Parts { files, total: at })
    }

    fn read_exact_at_impl(&self, off: u64, buf: &mut [u8]) -> Result<(), ZipError> {
        if off.saturating_add(buf.len() as u64) > self.total {
            return Err(ZipError::Malformed("read past end of container"));
        }
        let mut done = 0usize;
        let mut pos = off;
        while done < buf.len() {
            let (f, start, len) = self
                .files
                .iter()
                .find(|(_, s, l)| pos >= *s && pos < *s + *l)
                .ok_or(ZipError::Malformed("gap in container parts"))?;
            let within = pos - start;
            let n = ((len - within) as usize).min(buf.len() - done);
            crate::disk::read_exact_at(f, &mut buf[done..done + n], within)?;
            done += n;
            pos += n as u64;
        }
        Ok(())
    }
}

impl Source for Parts {
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<(), ZipError> {
        self.read_exact_at_impl(off, buf)
    }

    fn total(&self) -> u64 {
        self.total
    }

    fn spanning_supported(&self) -> bool {
        // The parts of a spanned set are all on disk here, so the
        // per-disk geometry below can answer.
        true
    }

    /// Turn a central-directory (disk, offset-within-disk) address into a
    /// logical offset.
    ///
    /// The two multi-part shapes address entries DIFFERENTLY and the part
    /// count cannot tell them apart:
    ///
    /// - a byte-split set (`.zip.001`/`.002`) is one single-disk archive
    ///   cut at arbitrary points after the fact, so its offsets already
    ///   span the whole concatenation and its disk numbers are all 0;
    /// - a WinZip-SPANNED set (`.z01`/`.z02`/`.zip`) is genuinely
    ///   multi-disk, so each offset is relative to the disk that holds it.
    ///
    /// `multi_disk` comes from the end-of-central-directory record's own
    /// disk number, which is the only authority on which shape this is.
    fn logical(&self, multi_disk: bool, disk: u32, off: u64) -> Option<u64> {
        if !multi_disk {
            return (off <= self.total).then_some(off);
        }
        let (_, start, len) = self.files.get(disk as usize)?;
        (off <= *len).then_some(start + off)
    }
}

/// A zip container opened for extraction.
pub struct Archive {
    parts: Parts,
    entries: Vec<Entry>,
}

fn rd_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn rd_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn rd_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

impl Archive {
    /// Open a container from its parts in read order (one entry for a
    /// single container; the ordered segments for a spanned or byte-split
    /// set - exactly what [`Finding::parts`] holds).
    pub fn open(parts: &[PathBuf]) -> Result<Archive, ZipError> {
        let parts = Parts::open(parts)?;
        let dir = find_central_directory(&parts)?;
        let entries = parse_central_directory(&parts, &dir)?;
        if entries.is_empty() {
            // A zero-entry archive is legal, but "unpacked successfully"
            // having produced nothing is the silent-success shape this
            // codebase refuses everywhere else. Say so instead.
            return Err(ZipError::Malformed("archive contains no entries"));
        }
        Ok(Archive { parts, entries })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Decode one entry into `w`, verifying its stored CRC32 and its
    /// declared uncompressed size before returning Ok.
    ///
    /// The CRC check is the point, not a nicety: it is the only thing
    /// standing between a damaged-before-posting archive and output that
    /// looks like a successful extraction (the same rule the RAR store
    /// path enforces). A mismatch is an error, so the caller deletes the
    /// staged output instead of publishing it.
    pub fn read_entry_to(&self, e: &Entry, w: &mut dyn std::io::Write) -> Result<(), ZipError> {
        self.read_entry_to_with(e, w, None)
    }

    /// [`Self::read_entry_to`] with a password (zip phase 3): ZipCrypto
    /// and WinZip AE (AES) entries decrypt when it matches. Integrity
    /// per scheme: ZipCrypto keeps the plaintext CRC32 check; AE
    /// verifies the HMAC-SHA1 over the ciphertext, and AE-1 the CRC on
    /// top, while AE-2 zeroes the CRC field BY SPEC and must skip that
    /// comparison. A wrong password fails loudly (the check byte /
    /// verifier first, the CRC or HMAC as the real gate) - ciphertext
    /// is never published as output.
    pub fn read_entry_to_with(
        &self,
        e: &Entry,
        w: &mut dyn std::io::Write,
        password: Option<&str>,
    ) -> Result<(), ZipError> {
        use std::io::Read as _;
        // The REAL compression method: an AE entry stores 99 in the
        // method field and the truth in its extra field.
        let real_method = real_method(e);
        if e.method == 99 && e.aes.is_none() {
            return Err(ZipError::Malformed("AES entry without its AE extra field"));
        }
        if !method_supported(real_method) {
            return Err(ZipError::Unsupported(format!(
                "{} uses {} compression, which is not built in",
                e.name,
                method_name(real_method)
            )));
        }
        if e.is_encrypted() && password.is_none() {
            return Err(ZipError::Unsupported(format!(
                "{} is password-protected and the job has no password",
                e.name
            )));
        }
        let data = self.entry_data_offset(e)?;
        let end = data
            .checked_add(e.compressed_size)
            .filter(|&v| v <= self.parts.total())
            .ok_or(ZipError::Malformed("entry size overflows"))?;
        // Build the (possibly decrypting) compressed-byte source.
        // Crypto framing + password check, shared verbatim with the
        // in-stream chase (see `entry_crypto`).
        let crypto = entry_crypto(&self.parts, e, data, end, password)?;
        let mut rd_src: Box<dyn std::io::Read + '_> = Box::new(crypto.cipher.wrap(RangeReader {
            parts: &self.parts,
            pos: data + crypto.head,
            end: end - crypto.tail,
        }));
        let mut crc = crc32fast::Hasher::new();
        let mut written = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        // One code path for both methods: `store` is just the identity
        // decoder, so the CRC/size accounting below cannot drift between
        // them.
        let mut rd = decoder_with(e, RdAdapter(&mut rd_src), DictAdmit::Wait)?;
        loop {
            let n = rd.read(&mut buf)?;
            if n == 0 {
                break;
            }
            written += n as u64;
            if written > e.uncompressed_size {
                return Err(ZipError::Malformed("entry longer than its declared size"));
            }
            crc.update(&buf[..n]);
            w.write_all(&buf[..n])?;
        }
        // A deflate decoder stops at its stream end, which for an AE
        // entry can leave the HMAC verification (raised at the source's
        // EOF) unreached - drain the source so authentication always
        // runs before success is reported.
        drop(rd);
        loop {
            let n = rd_src.read(&mut buf)?;
            if n == 0 {
                break;
            }
        }
        if written != e.uncompressed_size {
            return Err(ZipError::Malformed("entry shorter than its declared size"));
        }
        // AE-2 zeroes the CRC field by spec - its HMAC is the check.
        let check_crc = e.aes.is_none_or(|a| !a.skips_crc());
        if check_crc && crc.finalize() != e.crc32 {
            return Err(ZipError::BadCrc {
                name: e.name.clone(),
            });
        }
        Ok(())
    }

    /// Where this entry's DATA begins - see [`entry_data_offset`].
    fn entry_data_offset(&self, e: &Entry) -> Result<u64, ZipError> {
        entry_data_offset(&self.parts, e)
    }
}

/// Where an entry's DATA begins: the local header tells us, and it is
/// the only thing we take from it. Its name and extra fields may differ
/// in LENGTH from the central directory's copy (writers pad extra
/// fields differently in the two places), so the lengths must be read
/// here rather than reused.
pub(crate) fn entry_data_offset<S: Source + ?Sized>(parts: &S, e: &Entry) -> Result<u64, ZipError> {
    let mut hdr = [0u8; 30];
    parts.read_exact_at(e.local_offset, &mut hdr)?;
    if &hdr[0..4] != b"PK\x03\x04" {
        return Err(ZipError::Malformed(
            "entry does not start with a local header",
        ));
    }
    let name_len = rd_u16(&hdr[26..]) as u64;
    let extra_len = rd_u16(&hdr[28..]) as u64;
    e.local_offset
        .checked_add(30 + name_len + extra_len)
        .filter(|&o| o <= parts.total())
        .ok_or(ZipError::Malformed(
            "entry data starts past end of container",
        ))
}

/// Reads a bounded logical range, so a decoder can never run past the
/// entry it was given.
struct RangeReader<'a> {
    parts: &'a Parts,
    pos: u64,
    end: u64,
}

impl std::io::Read for RangeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.end.saturating_sub(self.pos);
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let n = (left as usize).min(buf.len());
        self.parts
            .read_exact_at(self.pos, &mut buf[..n])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// ZipCrypto layer over an entry's data range (12-byte header already
/// consumed and checked by the caller).
pub(crate) struct ZipCryptoReader<R> {
    src: R,
    zc: crate::zipcrypt::ZipCrypto,
}

impl<R: std::io::Read> std::io::Read for ZipCryptoReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.src.read(buf)?;
        self.zc.decrypt(&mut buf[..n]);
        Ok(n)
    }
}

/// WinZip AE layer over an entry's CIPHERTEXT range (salt/verifier
/// before it, auth code after it - both handled by the caller). The
/// HMAC accumulates over the ciphertext (encrypt-then-MAC) and is
/// verified exactly once, at the source's end: a mismatch surfaces as
/// a read error, so no caller can reach "success" past a bad tag.
pub(crate) struct AeReader<R> {
    src: R,
    ctr: crate::zipcrypt::AeCtr,
    mac: Option<crate::zipcrypt::AeMac>,
    want: [u8; crate::zipcrypt::AE_AUTH_LEN],
}

impl<R: std::io::Read> std::io::Read for AeReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.src.read(buf)?;
        if n == 0 {
            if let Some(mac) = self.mac.take()
                && mac.finalize() != self.want
            {
                return Err(std::io::Error::other(
                    "AES authentication failed (wrong password, or the archive is damaged)",
                ));
            }
            return Ok(0);
        }
        if let Some(mac) = self.mac.as_mut() {
            mac.update(&buf[..n]);
        }
        self.ctr.xor(&mut buf[..n]);
        Ok(n)
    }
}

/// One encrypted entry's crypto layer, resolved and password-checked
/// but not yet attached to a byte source.
///
/// This exists so the DISK reader and the in-stream chase share one
/// implementation. They cannot share a range reader - the disk path
/// reads through `Parts`, the chase blocks on arriving articles and
/// tracks a low-water mark that drives its drop-behind trim - but the
/// cipher, the framing arithmetic and the password check are identical,
/// and those are the parts worth having exactly once.
pub(crate) enum EntryCipher {
    None,
    ZipCrypto(crate::zipcrypt::ZipCrypto),
    Ae {
        ctr: crate::zipcrypt::AeCtr,
        mac: crate::zipcrypt::AeMac,
        want: [u8; crate::zipcrypt::AE_AUTH_LEN],
    },
}

/// Where an entry's real payload sits inside its data range, and how to
/// decrypt it. `head`/`tail` are the crypto framing bytes to skip at
/// each end (salt + verifier, or the ZipCrypto header; and the AE
/// authentication code), so the caller reads `[data + head, end - tail)`.
pub(crate) struct EntryCrypto {
    pub(crate) head: u64,
    pub(crate) tail: u64,
    pub cipher: EntryCipher,
}

impl EntryCipher {
    /// Wrap a plaintext-or-ciphertext byte source in this layer.
    pub(crate) fn wrap<R: std::io::Read>(self, src: R) -> CryptoReader<R> {
        match self {
            EntryCipher::None => CryptoReader::Plain(src),
            EntryCipher::ZipCrypto(zc) => CryptoReader::Zc(ZipCryptoReader { src, zc }),
            EntryCipher::Ae { ctr, mac, want } => CryptoReader::Ae(AeReader {
                src,
                ctr,
                mac: Some(mac),
                want,
            }),
        }
    }
}

/// The three decrypt layers as one concrete reader, so neither caller
/// has to box (and so the AE authentication still fires at EOF through
/// whatever decoder sits on top).
pub(crate) enum CryptoReader<R> {
    Plain(R),
    Zc(ZipCryptoReader<R>),
    Ae(AeReader<R>),
}

impl<R: std::io::Read> std::io::Read for CryptoReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            CryptoReader::Plain(r) => r.read(buf),
            CryptoReader::Zc(r) => r.read(buf),
            CryptoReader::Ae(r) => r.read(buf),
        }
    }
}

/// The compression method an entry REALLY uses: a WinZip AE entry stores
/// 99 in the method field and the truth in its AE extra field.
pub(crate) fn real_method(e: &Entry) -> u16 {
    match &e.aes {
        Some(a) => a.method,
        None => e.method,
    }
}

/// Does this entry's stored CRC32 vouch for anything? WinZip AE-2
/// zeroes the field BY SPEC and relies on its HMAC instead, so comparing
/// against it would fail every AE-2 entry; AE-1 and ZipCrypto keep the
/// real CRC.
pub(crate) fn crc_is_authoritative(e: &Entry) -> bool {
    e.aes.is_none_or(|a| !a.skips_crc())
}

/// Resolve an entry's crypto framing and VERIFY the password, reading
/// the salt/verifier (AE) or the 12-byte header (ZipCrypto) and the
/// trailing authentication code through `src`.
///
/// The pre-checks here are cheap and wrong-password-shaped; neither is
/// the real gate. ZipCrypto's check byte is ONE byte, so a wrong
/// password survives it 1 time in 256, and AE's verifier is two. What
/// actually vouches for the output is the CRC32 (ZipCrypto, AE-1) or the
/// HMAC-SHA1 (AE), both raised before any caller can report success.
pub(crate) fn entry_crypto<S: Source>(
    src: &S,
    e: &Entry,
    data: u64,
    end: u64,
    password: Option<&str>,
) -> Result<EntryCrypto, ZipError> {
    if !e.is_encrypted() {
        return Ok(EntryCrypto {
            head: 0,
            tail: 0,
            cipher: EntryCipher::None,
        });
    }
    let Some(pw) = password else {
        return Err(ZipError::Unsupported(format!(
            "{} is password-protected and the job has no password",
            e.name
        )));
    };
    match &e.aes {
        Some(spec) => {
            let (key_len, salt_len) =
                crate::zipcrypt::ae_strength_lens(spec.strength).ok_or_else(|| {
                    ZipError::Unsupported(format!(
                        "{} uses an unknown AES strength ({})",
                        e.name, spec.strength
                    ))
                })?;
            let head = (salt_len + crate::zipcrypt::AE_VERIFY_LEN) as u64;
            let overhead = head + crate::zipcrypt::AE_AUTH_LEN as u64;
            if e.compressed_size < overhead {
                return Err(ZipError::Malformed("AES entry too short for its framing"));
            }
            let mut hd = vec![0u8; head as usize];
            src.read_exact_at(data, &mut hd)?;
            let keys = crate::zipcrypt::ae_derive(pw.as_bytes(), &hd[..salt_len], key_len);
            if hd[salt_len..] != keys.verify {
                return Err(ZipError::WrongPassword {
                    name: e.name.clone(),
                });
            }
            let mut want = [0u8; crate::zipcrypt::AE_AUTH_LEN];
            src.read_exact_at(end - crate::zipcrypt::AE_AUTH_LEN as u64, &mut want)?;
            let ctr = crate::zipcrypt::AeCtr::new(&keys.enc_key)
                .ok_or(ZipError::Malformed("AES key size"))?;
            Ok(EntryCrypto {
                head,
                tail: crate::zipcrypt::AE_AUTH_LEN as u64,
                cipher: EntryCipher::Ae {
                    ctr,
                    mac: crate::zipcrypt::AeMac::new(&keys.mac_key),
                    want,
                },
            })
        }
        None => {
            if e.compressed_size < 12 {
                return Err(ZipError::Malformed(
                    "ZipCrypto entry too short for its header",
                ));
            }
            let mut hdr = [0u8; 12];
            src.read_exact_at(data, &mut hdr)?;
            let mut zc = crate::zipcrypt::ZipCrypto::new(pw.as_bytes());
            zc.decrypt(&mut hdr);
            if hdr[11] != crate::zipcrypt::zipcrypto_check_byte(e.flags, e.crc32, e.dos_time) {
                return Err(ZipError::WrongPassword {
                    name: e.name.clone(),
                });
            }
            Ok(EntryCrypto {
                head: 12,
                tail: 0,
                cipher: EntryCipher::ZipCrypto(zc),
            })
        }
    }
}

/// A `Read` view over a boxed reader the caller keeps ownership of, so
/// the decode loop can hand the SAME source to either a deflate decoder
/// or the store identity path and still drain it afterwards (the AE
/// authentication fires at the source's EOF).
struct RdAdapter<'a, 'b>(&'a mut Box<dyn std::io::Read + 'b>);

impl std::io::Read for RdAdapter<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

/// Where a container's central directory is, and how to read the
/// offsets it holds - everything [`parse_central_directory`] needs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Directory {
    /// Logical offset the first central-directory record starts at,
    /// [`Directory::base`] already applied.
    pub(crate) at: u64,
    /// How many records the end record says are there.
    pub(crate) count: u64,
    /// How many bytes the end record says they occupy.
    pub(crate) size: u64,
    /// A genuinely WinZip-spanned set (per-disk addresses).
    pub(crate) multi_disk: bool,
    /// Bytes of non-zip data before the archive proper - a prepended
    /// self-extracting stub, or anything else concatenated in front of
    /// it. Every offset the directory stores is relative to the archive,
    /// so this is added to each one. Zero for an archive that starts at
    /// byte 0, which is every archive but the prepended-stub shape.
    pub(crate) base: u64,
}

/// Where a zip64 end record physically sits, on an archive whose own
/// pointers cannot say - one that does not start at byte 0, so every
/// stored offset is short by the prefix.
///
/// §4.3.6 fixes the tail's layout - record, 20-byte locator, EOCD - so
/// the record's END is pinned at `eocd_at - 20` whatever its length,
/// derived from the EOCD this reader already trusts rather than from
/// any stored pointer. Its LENGTH is not fixed: the record may carry
/// an extensible data sector after its 56 fixed bytes, and that
/// sector's size is declared in the record's own size field and
/// nowhere else. Reading the single position a 56-byte record occupies
/// therefore lands INSIDE any record that carries one, which refused a
/// legal archive (§162 item 3, and Python 3.14.6's `zipfile` and Info-ZIP
/// `unzip` 6.00 both still do - measured 23 Aug 2026).
///
/// So the start is searched for, and what makes that safe is not the
/// signature - a sector is arbitrary bytes and may carry one - but the
/// record's own arithmetic: `12 + size` has to land its end exactly on
/// the locator. Two positions can satisfy that, and the OUTER one is
/// the record: whatever the outer one's size field covers is its
/// sector, and a sector's bytes are data by definition, so an inner
/// match is something the record CONTAINS. An empty sector still
/// resolves at `eocd_at - 76`, precisely where the old probe read.
/// Still only a CANDIDATE either way: [`prepended_base`] has to find a
/// real directory record at the offset it implies before any of it
/// counts, and measuring to the EOCD is tried after it.
fn physical_zip64_record<S: Source + ?Sized>(parts: &S, eocd_at: u64) -> Option<u64> {
    let locator_at = eocd_at.checked_sub(20)?;
    // Read no further back than the gap the caller will ACCEPT: the
    // one-pass source blocks on bytes that have not arrived, so this is
    // what keeps the probe inside the tail both callers have promoted.
    let lowest = eocd_at.saturating_sub(MAX_Z64_TAIL_GAP);
    let span = locator_at.checked_sub(lowest)?;
    if span < Z64_FIXED {
        return None;
    }
    let mut win = vec![0u8; span as usize];
    parts.read_exact_at(lowest, &mut win).ok()?;
    // `i` is a candidate record START, so the size field it declares
    // must span the whole of the rest of the window. Lowest first: see
    // the outer-wins argument above.
    (0..=(span - Z64_FIXED))
        .find(|&i| {
            let i = i as usize;
            &win[i..i + 4] == b"PK\x06\x06"
                && rd_u64(&win[i + 4..]).checked_add(12) == Some(span - i as u64)
        })
        .map(|i| lowest + i)
}

/// Locate the end-of-central-directory record and describe the
/// directory it names.
///
/// The EOCD sits at the very end, except for a trailing comment of up to
/// 64 KiB - so it is found by scanning backwards over that window. The
/// LAST match wins: a stored entry can contain the signature, and on a
/// self-extracting or concatenated container so can earlier junk.
///
/// A comment is attacker-chosen bytes, so the LAST match can also be a
/// forged record planted there, naming a shorter directory than the
/// archive really holds. Every entry it does name still passes its CRC,
/// so the omission would be completely silent - the shape this codebase
/// refuses everywhere else, and one unzip, 7-Zip and bsdtar all reject.
/// The defence is the record's own geometry: the directory it describes
/// must end exactly where that record begins, and the record must agree
/// with itself about how many entries there are.
pub(crate) fn find_central_directory<S: Source + ?Sized>(parts: &S) -> Result<Directory, ZipError> {
    const EOCD_MIN: u64 = 22;
    let total = parts.total();
    if total < EOCD_MIN {
        return Err(ZipError::Malformed("too small to be a zip"));
    }
    let window = (EOCD_MIN + u16::MAX as u64).min(total);
    let start = total - window;
    let mut buf = vec![0u8; window as usize];
    parts.read_exact_at(start, &mut buf)?;
    let pos = (0..=(buf.len() - EOCD_MIN as usize))
        .rev()
        .find(|&i| &buf[i..i + 4] == b"PK\x05\x06")
        .ok_or(ZipError::Malformed("no end-of-central-directory record"))?;
    let eocd = &buf[pos..];
    let disk = rd_u16(&eocd[4..]) as u32;
    let cd_disk = rd_u16(&eocd[6..]) as u32;
    // The EOCD's own disk number is the only authority on whether this is
    // a genuinely spanned set (per-disk offsets) or a single-disk archive
    // that merely arrived as several files (logical offsets).
    let multi_disk = disk != 0 || cd_disk != 0;
    if multi_disk && !parts.spanning_supported() {
        // A single-file view of a spanned set (its trailing `.zip`
        // segment read alone): every offset below is per-disk and would
        // be misread as logical. Name the shape instead.
        return Err(ZipError::Unsupported(
            "a WinZip-spanned zip set is unpacked from disk".to_string(),
        ));
    }
    let mut per_disk = rd_u16(&eocd[8..]) as u64;
    let mut entries = rd_u16(&eocd[10..]) as u64;
    let mut cd_size = rd_u32(&eocd[12..]) as u64;
    let mut cd_off = rd_u32(&eocd[16..]) as u64;
    let mut cd_disk_no = cd_disk;

    // Zip64: any saturated field means the real ones live in the Zip64
    // record, found through a locator 20 bytes ahead of the EOCD. Never
    // trust the 32-bit copies once that record exists - `cd_size` and
    // the per-disk count included, since the checks below now read them
    // and a saturated copy would fail every genuinely large archive.
    let eocd_at = start + pos as u64;
    let mut anchor = eocd_at;
    // A writer emits the zip64 record and locator whenever the archive
    // used zip64 ANYWHERE - a member of 4 GiB or more, or an input of
    // unknown size piped in - even when every 32-bit EOCD field still
    // fits. Info-ZIP and libarchive both do, and the branch below never
    // sees those archives. Their 76 bytes sit between the directory's end
    // and the EOCD, so the record, not the EOCD, is where the directory
    // ends: a SECOND legal anchor. Probed by looking for the signature at
    // the position the 32-bit fields already name, never by following the
    // locator's pointer - so nothing attacker-chosen decides where to
    // read, and the read stays a bounded step behind the EOCD, inside the
    // tail both callers have already promoted (the one-pass source BLOCKS
    // on bytes that have not arrived). A miss is silent and leaves the
    // EOCD anchor alone; the geometry still comes from the 32-bit fields,
    // which are authoritative whenever they fit.
    let mut z64_anchor = None;
    if let Some(ends) = cd_off.checked_add(cd_size)
        && ends < eocd_at
        && eocd_at - ends <= MAX_Z64_TAIL_GAP
    {
        let mut sig = [0u8; 4];
        if parts.read_exact_at(ends, &mut sig).is_ok() && &sig == b"PK\x06\x06" {
            z64_anchor = Some(ends);
        }
    }
    // …and the same record's PHYSICAL home when the archive does not
    // start at byte 0. The probe above reads at an ARCHIVE-relative
    // position, so on a stubbed archive it lands short by the stub and
    // finds nothing - and the shortfall arithmetic below then measured
    // the stub as if the record and locator were part of it, putting
    // the directory 76 bytes past where it is.
    if z64_anchor.is_none() {
        z64_anchor = physical_zip64_record(parts, eocd_at);
    }
    if entries == u16::MAX as u64
        || per_disk == u16::MAX as u64
        || cd_size == u32::MAX as u64
        || cd_off == u32::MAX as u64
        || disk == u16::MAX as u32
    {
        if eocd_at < 20 {
            return Err(ZipError::Malformed("zip64 locator does not fit"));
        }
        let mut loc = [0u8; 20];
        parts.read_exact_at(eocd_at - 20, &mut loc)?;
        if &loc[0..4] != b"PK\x06\x07" {
            return Err(ZipError::Malformed("zip64 sizes without a zip64 locator"));
        }
        let z64_disk = rd_u32(&loc[4..]);
        let z64_off = rd_u64(&loc[8..]);
        let mut z64 = [0u8; 56];
        let at_ptr = parts.logical(multi_disk, z64_disk, z64_off);
        let found = at_ptr
            .filter(|&at| parts.read_exact_at(at, &mut z64).is_ok() && &z64[0..4] == b"PK\x06\x06");
        // The locator's pointer is ARCHIVE-relative, so on an archive
        // that does not start at byte 0 it does not name a physical
        // position at all. Fall back to the record's fixed home behind
        // the locator - the same signature-confirmed candidate the
        // unsaturated path probes, and the only other place §4.3.6
        // allows - rather than declaring a real archive malformed.
        let z64_at = match found.or(z64_anchor) {
            Some(at) => at,
            None => {
                return Err(ZipError::Malformed(
                    "zip64 end record not where the locator says",
                ));
            }
        };
        if found.is_none() {
            parts.read_exact_at(z64_at, &mut z64)?;
        }
        per_disk = rd_u64(&z64[24..]);
        entries = rd_u64(&z64[32..]);
        cd_size = rd_u64(&z64[40..]);
        cd_off = rd_u64(&z64[48..]);
        cd_disk_no = rd_u32(&z64[20..]);
        // The zip64 record is what now describes the directory, so it,
        // not the 22-byte EOCD, is what the directory must end at: the
        // locator and the EOCD follow it.
        anchor = z64_at;
        // Once the record is authoritative there is exactly one legal
        // place for the directory to end, so drop the second anchor and
        // leave this path governed by the same strict rule as before.
        z64_anchor = None;
    }
    if entries > MAX_ENTRIES {
        return Err(ZipError::Unsupported(format!(
            "the archive declares {entries} entries, more than this build will open"
        )));
    }
    // Both checks are single-disk only. On a genuinely spanned set the
    // directory legally lives on another disk than the record that
    // describes it, and the per-disk count is legitimately a subset of
    // the total - and there is no spanned-read test in the tree to catch
    // a wrong guess, so do not guess.
    let mut base = 0u64;
    if !multi_disk {
        // Two legal places to end: at the record the geometry came from,
        // or - only on the unsaturated path - at a zip64 end record that
        // the geometry itself points at.
        let ends_at = cd_off.checked_add(cd_size);
        if ends_at != Some(anchor) && z64_anchor != ends_at {
            // Everything the directory stores is relative to the ARCHIVE,
            // and an archive need not start at byte 0 - a self-extracting
            // stub or any other concatenated prefix sits in front of it.
            // The shortfall IS that prefix's length, and the shape is
            // confirmed by reading a directory record where it lands.
            //
            // Measure to the zip64 end record when there is one: that is
            // where the directory ends on a zip64 archive, and measuring
            // to the EOCD instead would fold the record and its locator
            // into the stub and shift every offset by 76.
            //
            // The 76-back probe is only a CANDIDATE: on a non-zip64
            // archive, four directory-tail bytes (a filename is arbitrary
            // bytes) can coincidentally wear the signature. If no real
            // directory record sits where the candidate implies, it does
            // not count - measure to the EOCD anchor before refusing an
            // archive every other reader opens (14 Aug sweep).
            base = match z64_anchor {
                Some(cand) => prepended_base(parts, cand, cd_off, cd_size)
                    .or_else(|_| prepended_base(parts, anchor, cd_off, cd_size))?,
                None => prepended_base(parts, anchor, cd_off, cd_size)?,
            };
        }
        if per_disk != entries {
            return Err(ZipError::Malformed(
                "the end-of-central-directory record disagrees with itself about the entry count",
            ));
        }
    }
    let cd = cd_off
        .checked_add(base)
        .and_then(|off| parts.logical(multi_disk, cd_disk_no, off))
        .ok_or(ZipError::Malformed(
            "central directory outside the container",
        ))?;
    Ok(Directory {
        at: cd,
        count: entries,
        size: cd_size,
        multi_disk,
        base,
    })
}

/// How many bytes of non-zip data sit in front of an archive whose
/// directory does not end where the end record does - the prepended-stub
/// shape (`7zz` calls it "the archive is open with offset", `unzip`
/// "extra bytes at beginning or within zipfile"), and the reason a
/// self-extracting zip built by concatenation reads at all.
///
/// The shortfall between where the directory says it ends and where it
/// actually ends is a CANDIDATE, not an answer: a forged end record
/// planted in the comment produces one too, and honouring it blindly
/// would undo the geometry defence the caller just applied. So the
/// candidate is confirmed structurally - a central-directory record has
/// to be sitting at the shifted offset - and rejected otherwise, with a
/// reason that names the shape instead of blaming the entries.
fn prepended_base<S: Source + ?Sized>(
    parts: &S,
    anchor: u64,
    cd_off: u64,
    cd_size: u64,
) -> Result<u64, ZipError> {
    // A directory claiming to end at or past its own end record is not
    // shifted, it is wrong: keep the wording that shape already had.
    let short = || {
        ZipError::Malformed(
            "the central directory does not end at the end-of-central-directory record",
        )
    };
    let base = cd_off
        .checked_add(cd_size)
        .and_then(|ends| anchor.checked_sub(ends))
        .filter(|&b| b > 0)
        .ok_or_else(short)?;
    let at = cd_off.checked_add(base).ok_or_else(short)?;
    let mut sig = [0u8; 4];
    parts.read_exact_at(at, &mut sig).map_err(|_| short())?;
    if &sig != b"PK\x01\x02" {
        // The offsets ARE shifted by something - the arithmetic says so -
        // but not by this, so nothing here is trustworthy. Say what was
        // seen rather than letting a later check invent a different fault.
        return Err(ZipError::Malformed(
            "the zip does not start at the beginning of the file, and no central directory sits where that implies",
        ));
    }
    Ok(base)
}

/// Walk the central directory into [`Entry`] records.
///
/// `count` and `cd_size` are two independent statements about the same
/// directory, so the walk must land on exactly `cd_size` bytes or the
/// record is describing a different directory than the one that is
/// there - the other half of the forged-record defence above, and the
/// check CPython's `zipfile` makes.
pub(crate) fn parse_central_directory<S: Source + ?Sized>(
    parts: &S,
    dir: &Directory,
) -> Result<Vec<Entry>, ZipError> {
    let &Directory {
        at: cd_off,
        count,
        size: cd_size,
        multi_disk,
        base,
    } = dir;
    let mut out = Vec::with_capacity(count.min(4096) as usize);
    let mut at = cd_off;
    for _ in 0..count {
        let mut hdr = [0u8; 46];
        parts.read_exact_at(at, &mut hdr)?;
        if &hdr[0..4] != b"PK\x01\x02" {
            return Err(ZipError::Malformed("central directory record expected"));
        }
        let flags = rd_u16(&hdr[8..]);
        let method = rd_u16(&hdr[10..]);
        let dos_time = rd_u16(&hdr[12..]);
        let crc32 = rd_u32(&hdr[16..]);
        let mut csize = rd_u32(&hdr[20..]) as u64;
        let mut usize_ = rd_u32(&hdr[24..]) as u64;
        let name_len = rd_u16(&hdr[28..]) as usize;
        let extra_len = rd_u16(&hdr[30..]) as usize;
        let comment_len = rd_u16(&hdr[32..]) as usize;
        let mut disk = rd_u16(&hdr[34..]) as u32;
        let external = rd_u32(&hdr[38..]);
        let mut local_off = rd_u32(&hdr[42..]) as u64;
        if name_len > MAX_NAME {
            return Err(ZipError::Malformed("entry name is implausibly long"));
        }
        let mut rest = vec![0u8; name_len + extra_len + comment_len];
        parts.read_exact_at(at + 46, &mut rest)?;
        let name = String::from_utf8_lossy(&rest[..name_len]).into_owned();

        // Zip64 extra field (0x0001): present exactly when one of the
        // 32-bit fields above is saturated, and holds only the saturated
        // ones, in this fixed order. The same walk picks up the WinZip
        // AE field (0x9901) of a method-99 entry.
        let extra = &rest[name_len..name_len + extra_len];
        let mut aes: Option<AesSpec> = None;
        let mut i = 0usize;
        while i + 4 <= extra.len() {
            let tag = rd_u16(&extra[i..]);
            let len = rd_u16(&extra[i + 2..]) as usize;
            let body_at = i + 4;
            if body_at + len > extra.len() {
                break;
            }
            if tag == 0x9901 && len >= 7 {
                let body = &extra[body_at..body_at + len];
                // vendor version u16, vendor id "AE", strength u8,
                // real method u16.
                if &body[2..4] == b"AE" {
                    aes = Some(AesSpec {
                        vendor_version: rd_u16(&body[0..]),
                        strength: body[4],
                        method: rd_u16(&body[5..]),
                    });
                }
                i = body_at + len;
                continue;
            }
            if tag == 0x0001 {
                let body = &extra[body_at..body_at + len];
                let mut p = 0usize;
                let take = |p: &mut usize| -> Option<u64> {
                    if *p + 8 <= body.len() {
                        let v = rd_u64(&body[*p..]);
                        *p += 8;
                        Some(v)
                    } else {
                        None
                    }
                };
                if usize_ == u32::MAX as u64 {
                    usize_ = take(&mut p).ok_or(ZipError::Malformed("zip64 field truncated"))?;
                }
                if csize == u32::MAX as u64 {
                    csize = take(&mut p).ok_or(ZipError::Malformed("zip64 field truncated"))?;
                }
                if local_off == u32::MAX as u64 {
                    local_off = take(&mut p).ok_or(ZipError::Malformed("zip64 field truncated"))?;
                }
                if disk == u16::MAX as u32 && p + 4 <= body.len() {
                    disk = rd_u32(&body[p..]);
                }
                // No break: the AE field (0x9901) may follow zip64, and
                // stopping here would silently miss it.
            }
            i = body_at + len;
        }

        // The DOS directory attribute is believed only when the entry
        // also CLAIMS to be empty, which every real directory entry does.
        // The bit is unauthenticated central-directory data: an entry
        // describing 8 GiB of deflate with a CRC while carrying 0x10 is
        // not a directory, and honouring the bit made the disk extractor
        // create an empty directory of that name, skip the payload
        // entirely, and still report the job Completed - the one field in
        // this record whose corruption was SILENT, where a bad CRC, size
        // or offset all fail loudly. Every mainstream writer emits the
        // trailing slash, so the term costs nothing on real archives.
        let dos_dir = external & 0x10 != 0;
        let is_dir =
            name.ends_with('/') || name.ends_with('\\') || (dos_dir && usize_ == 0 && csize == 0);
        out.push(Entry {
            name,
            method,
            crc32,
            compressed_size: csize,
            uncompressed_size: usize_,
            is_dir,
            flags,
            dos_time,
            aes,
            unix_mode: (external >> 16) as u16,
            // Archive-relative, like every offset the directory holds -
            // `base` is zero unless a stub sits in front of the archive.
            local_offset: local_off
                .checked_add(base)
                .and_then(|off| parts.logical(multi_disk, disk, off))
                .ok_or(ZipError::Malformed("entry starts outside the container"))?,
        });
        at = at
            .checked_add(46 + (name_len + extra_len + comment_len) as u64)
            .ok_or(ZipError::Malformed("central directory overflows"))?;
    }
    // A difference, so this holds in the single-disk and the per-disk
    // address space alike.
    if at.checked_sub(cd_off) != Some(cd_size) {
        return Err(ZipError::Malformed(
            "the central directory's entry count and size disagree",
        ));
    }
    Ok(out)
}

/// Fuzz seam for the CHASE's reader path (`zip_parse` covers the disk
/// one). Both drive the same `Source`-generic parser, but only through
/// this entry point are the pieces exercised in the ORDER and shape the
/// in-stream worker uses them: `entry_data_offset` against a
/// non-`Parts` source, `entry_crypto` resolving framing by reading
/// ABOVE the body it is about to stream, and the explicit drain that
/// reaches an AE HMAC a deflate decoder would otherwise stop short of.
///
/// It matters now that a zip chases at every depth: the bytes reaching
/// this path can come from inside another archive, so nothing upstream
/// has validated them either.
///
/// Mirrors `Extractor::zip_run` minus the extractor - keep the two in
/// step when either changes.
#[doc(hidden)]
pub fn fuzz_stream_pass(data: &[u8], password: Option<&str>) {
    struct SliceSource<'a>(&'a [u8]);
    impl Source for SliceSource<'_> {
        fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<(), ZipError> {
            let at = usize::try_from(off).map_err(|_| ZipError::Malformed("offset overflow"))?;
            let end = at
                .checked_add(buf.len())
                .filter(|&e| e <= self.0.len())
                .ok_or(ZipError::Malformed("read past end of container"))?;
            buf.copy_from_slice(&self.0[at..end]);
            Ok(())
        }
        fn total(&self) -> u64 {
            self.0.len() as u64
        }
    }
    use std::io::Read as _;
    let src = SliceSource(data);
    let total = src.total();
    let Ok(dir) = find_central_directory(&src) else {
        return;
    };
    let Ok(entries) = parse_central_directory(&src, &dir) else {
        return;
    };
    let mut buf = vec![0u8; 64 * 1024];
    for e in entries.iter().filter(|e| !e.is_dir && !e.is_symlink()) {
        if !method_supported(real_method(e)) {
            continue;
        }
        let Ok(data_at) = entry_data_offset(&src, e) else {
            continue;
        };
        let Some(end) = data_at
            .checked_add(e.compressed_size)
            .filter(|&v| v <= total)
        else {
            continue;
        };
        let Ok(crypto) = entry_crypto(&src, e, data_at, end, password) else {
            continue;
        };
        // Bound the sink the same way `zip_parse` does: a valid header
        // may legitimately claim a huge entry, and the fuzzer should not
        // be measuring RAM.
        let mut left: u64 = 1 << 20;
        let mut rd_src = crypto.cipher.wrap(SourceRangeReader {
            src: &src,
            pos: data_at + crypto.head,
            end: end.saturating_sub(crypto.tail),
        });
        if let Ok(mut rd) = decoder(e, &mut rd_src) {
            while left > 0 {
                match rd.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => left = left.saturating_sub(n as u64),
                }
            }
        }
        // The drain that authenticates an AE entry, exactly as the
        // worker does it.
        while let Ok(n) = rd_src.read(&mut buf) {
            if n == 0 {
                break;
            }
        }
    }
}

/// Bounded `io::Read` over a range of a [`Source`], for
/// [`fuzz_stream_pass`] - the in-memory twin of the chase's
/// `BlockingRangeReader`. Distinct from this module's disk-path
/// `RangeReader`, which reads through `Parts`.
struct SourceRangeReader<'a, S: Source + ?Sized> {
    src: &'a S,
    pos: u64,
    end: u64,
}

impl<S: Source + ?Sized> std::io::Read for SourceRangeReader<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.end.saturating_sub(self.pos);
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let take = (left as usize).min(buf.len());
        self.src
            .read_exact_at(self.pos, &mut buf[..take])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.pos += take as u64;
        Ok(take)
    }
}

/// Minimal zip WRITER, for unit tests and the fuzz corpus - the same
/// role `rar::fixtures` plays for RAR. Deliberately hand-rolled so the
/// reader is tested against bytes we control completely, including the
/// malformed and declined shapes no real writer would produce.
#[doc(hidden)]
pub mod fixtures {
    /// How a fixture entry is encrypted (phase 3 coverage).
    pub enum Encrypt<'a> {
        /// Legacy PKWARE stream cipher.
        ZipCrypto { password: &'a str },
        /// WinZip AE: `vendor_version` 1 (CRC kept) or 2 (CRC zeroed),
        /// `strength` 1/2/3 for AES-128/192/256.
        Ae {
            password: &'a str,
            strength: u8,
            vendor_version: u16,
        },
    }

    /// One entry to encode: (name, payload, method, flags, external attrs).
    pub struct Spec<'a> {
        pub name: &'a str,
        pub data: &'a [u8],
        pub method: u16,
        pub flags: u16,
        pub external: u32,
        /// Override the stored CRC (damage simulation).
        pub crc_override: Option<u32>,
        /// Write the 32-bit size fields saturated and add a Zip64 extra
        /// field carrying the real ones.
        pub zip64: bool,
        pub encrypt: Option<Encrypt<'a>>,
        /// Flip one ciphertext byte after encryption (tamper
        /// simulation - the AE HMAC must catch it).
        pub tamper: bool,
        /// Declared LZMA dictionary size written into the method-14
        /// framing, INDEPENDENT of the size the encoder actually used.
        /// The decode-side window is `min(declared, uncompressed_size)`
        /// and is sized from this field, not from the stream's real
        /// match distances - so a small-dict encode with a large
        /// declaration reproduces a genuine `-mx=9` archive's decode
        /// memory at a fraction of the encode cost (dict-window RSS rig,
        /// TODO 209). `None` keeps the historical 64 KiB fixtures dict.
        pub dict_size: Option<u32>,
    }

    impl<'a> Spec<'a> {
        pub fn stored(name: &'a str, data: &'a [u8]) -> Spec<'a> {
            Spec {
                name,
                data,
                method: super::METHOD_STORE,
                flags: 0,
                external: 0,
                crc_override: None,
                zip64: false,
                encrypt: None,
                tamper: false,
                dict_size: None,
            }
        }
        pub fn deflated(name: &'a str, data: &'a [u8]) -> Spec<'a> {
            Spec {
                method: super::METHOD_DEFLATE,
                ..Spec::stored(name, data)
            }
        }
        pub fn bzip2(name: &'a str, data: &'a [u8]) -> Spec<'a> {
            Spec {
                method: super::METHOD_BZIP2,
                ..Spec::stored(name, data)
            }
        }
        pub fn lzma(name: &'a str, data: &'a [u8]) -> Spec<'a> {
            Spec {
                method: super::METHOD_LZMA,
                ..Spec::stored(name, data)
            }
        }
        /// A method-14 entry that DECLARES `dict_size` in its framing.
        /// The stream is still encoded with the cheap fixtures dict, so
        /// the declaration exceeds the real match distances - which is
        /// exactly the decode-memory shape this exercises.
        pub fn lzma_with_dict(name: &'a str, data: &'a [u8], dict_size: u32) -> Spec<'a> {
            Spec {
                method: super::METHOD_LZMA,
                dict_size: Some(dict_size),
                ..Spec::stored(name, data)
            }
        }
    }

    fn u16le(v: u16, out: &mut Vec<u8>) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn u32le(v: u32, out: &mut Vec<u8>) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn u64le(v: u64, out: &mut Vec<u8>) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn body(s: &Spec) -> Vec<u8> {
        match s.method {
            super::METHOD_DEFLATE => {
                use std::io::Write as _;
                let mut e =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(s.data).unwrap();
                e.finish().unwrap()
            }
            super::METHOD_BZIP2 => {
                use std::io::Write as _;
                let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                e.write_all(s.data).unwrap();
                e.finish().unwrap()
            }
            super::METHOD_LZMA => {
                use std::io::Write as _;
                // The override path (dict-window RSS rig) feeds hundreds
                // of MiB of incompressible bytes, so it takes the fast
                // preset; the default fixtures keep preset 6 byte-for-
                // byte. Either way the ENCODE dict stays 64 KiB - the
                // large window is a framing DECLARATION, not real match
                // distance (see `Spec::dict_size`).
                let preset = if s.dict_size.is_some() { 1 } else { 6 };
                let mut opts = lzma_rust2::LzmaOptions::with_preset(preset);
                opts.dict_size = 1 << 16;
                let mut w =
                    lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &opts, false).unwrap();
                w.write_all(s.data).unwrap();
                let props = w.props();
                let stream = w.finish().unwrap();
                // Declared dictionary: the override when present,
                // otherwise the (small) dict the encoder actually used.
                let declared_dict = s.dict_size.unwrap_or(opts.dict_size);
                // Method 14's framing: writer version, properties
                // length, the 5-byte properties blob, then the raw
                // stream. No end marker - sizes are declared, so the
                // decoder is told where to stop, like real writers do.
                let mut out = Vec::with_capacity(stream.len() + 9);
                u16le(0x0014, &mut out);
                u16le(5, &mut out);
                out.push(props);
                u32le(declared_dict, &mut out);
                out.extend_from_slice(&stream);
                out
            }
            _ => s.data.to_vec(),
        }
    }

    /// Encrypt an entry's already-compressed bytes per its spec:
    /// `(payload, stored method, stored crc, extra-field bytes)`.
    fn encrypted(s: &Spec, comp: Vec<u8>, crc: u32) -> (Vec<u8>, u16, u32, Vec<u8>) {
        match &s.encrypt {
            None => (comp, s.method, crc, Vec::new()),
            Some(Encrypt::ZipCrypto { password }) => {
                // 12-byte header: 11 arbitrary (deterministic) bytes +
                // the check byte (high byte of the CRC; fixtures never
                // set bit 3).
                let mut payload = vec![0u8; 12];
                for (i, b) in payload.iter_mut().enumerate().take(11) {
                    *b = (i as u8).wrapping_mul(73).wrapping_add(29);
                }
                payload[11] = (crc >> 24) as u8;
                payload.extend_from_slice(&comp);
                let mut z = crate::zipcrypt::ZipCrypto::new(password.as_bytes());
                z.encrypt(&mut payload);
                (payload, s.method, crc, Vec::new())
            }
            Some(Encrypt::Ae {
                password,
                strength,
                vendor_version,
            }) => {
                let (kl, sl) = crate::zipcrypt::ae_strength_lens(*strength).expect("strength");
                let salt: Vec<u8> = (0..sl)
                    .map(|i| (i as u8).wrapping_mul(41).wrapping_add(7))
                    .collect();
                let keys = crate::zipcrypt::ae_derive(password.as_bytes(), &salt, kl);
                let mut ct = comp;
                crate::zipcrypt::AeCtr::new(&keys.enc_key)
                    .expect("key")
                    .xor(&mut ct);
                let mut mac = crate::zipcrypt::AeMac::new(&keys.mac_key);
                mac.update(&ct);
                let auth = mac.finalize();
                let mut payload = salt;
                payload.extend_from_slice(&keys.verify);
                payload.extend_from_slice(&ct);
                payload.extend_from_slice(&auth);
                let mut extra = Vec::new();
                u16le(0x9901, &mut extra);
                u16le(7, &mut extra);
                u16le(*vendor_version, &mut extra);
                extra.extend_from_slice(b"AE");
                extra.push(*strength);
                u16le(s.method, &mut extra);
                // AE-2 zeroes the CRC field by spec.
                let crc_field = if *vendor_version == 2 { 0 } else { crc };
                (payload, 99, crc_field, extra)
            }
        }
    }

    /// Build a complete single-container zip.
    pub fn zip_of(specs: &[Spec]) -> Vec<u8> {
        zip_of_with_comment(specs, b"")
    }

    /// [`zip_of`] with a trailing archive comment. The comment is legal
    /// container bytes the reader must scan PAST, so it is also how a
    /// forged end-of-central-directory record gets appended after the
    /// real one.
    pub fn zip_of_with_comment(specs: &[Spec], comment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for s in specs {
            let comp = body(s);
            let crc = s.crc_override.unwrap_or_else(|| crc32fast::hash(s.data));
            let (mut payload, method, crc_field, ae_extra) = encrypted(s, comp, crc);
            if s.tamper {
                // Flip one ciphertext byte mid-payload (past any
                // salt/verifier framing).
                let at = payload.len() / 2;
                payload[at] ^= 0x40;
            }
            let flags = s.flags | if s.encrypt.is_some() { 0x0001 } else { 0 };
            let local_off = out.len() as u32;
            let (c32, u32_) = if s.zip64 {
                (u32::MAX, u32::MAX)
            } else {
                (payload.len() as u32, s.data.len() as u32)
            };
            let mut extra = Vec::new();
            if s.zip64 {
                u16le(0x0001, &mut extra);
                u16le(16, &mut extra);
                u64le(s.data.len() as u64, &mut extra);
                u64le(payload.len() as u64, &mut extra);
            }
            extra.extend_from_slice(&ae_extra);
            // Local header
            out.extend_from_slice(b"PK\x03\x04");
            u16le(if s.zip64 { 45 } else { 20 }, &mut out);
            u16le(flags, &mut out);
            u16le(method, &mut out);
            u16le(0, &mut out); // time
            u16le(0, &mut out); // date
            u32le(crc_field, &mut out);
            u32le(c32, &mut out);
            u32le(u32_, &mut out);
            u16le(s.name.len() as u16, &mut out);
            u16le(extra.len() as u16, &mut out);
            out.extend_from_slice(s.name.as_bytes());
            out.extend_from_slice(&extra);
            out.extend_from_slice(&payload);
            // Central directory record
            cd.extend_from_slice(b"PK\x01\x02");
            u16le(if s.zip64 { 45 } else { 20 }, &mut cd);
            u16le(if s.zip64 { 45 } else { 20 }, &mut cd);
            u16le(flags, &mut cd);
            u16le(method, &mut cd);
            u16le(0, &mut cd);
            u16le(0, &mut cd);
            u32le(crc_field, &mut cd);
            u32le(c32, &mut cd);
            u32le(u32_, &mut cd);
            u16le(s.name.len() as u16, &mut cd);
            u16le(extra.len() as u16, &mut cd);
            u16le(0, &mut cd); // comment len
            u16le(0, &mut cd); // disk
            u16le(0, &mut cd); // internal attrs
            u32le(s.external, &mut cd);
            u32le(local_off, &mut cd);
            cd.extend_from_slice(s.name.as_bytes());
            cd.extend_from_slice(&extra);
        }
        let cd_off = out.len() as u32;
        let cd_size = cd.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06");
        u16le(0, &mut out);
        u16le(0, &mut out);
        u16le(specs.len() as u16, &mut out);
        u16le(specs.len() as u16, &mut out);
        u32le(cd_size, &mut out);
        u32le(cd_off, &mut out);
        u16le(comment.len() as u16, &mut out);
        out.extend_from_slice(comment);
        out
    }
}

// Sibling test file, not inline: zip.rs sits under the size-gate
// ceiling (TODO 106) and test growth belongs beside it, same pattern
// as release_tests.rs.
#[cfg(test)]
#[path = "zip_tests.rs"]
mod zip_tests;
