//! SFX self-extractors: an `.exe`/`.bin`/`.sfx` with a real archive
//! appended behind a launcher stub. Detection, the entry gate, the
//! extraction arm and the stub carve - split out of unpack.rs whole
//! (size gate; nothing here changed in the move).
//!
//! Three families, found two different ways. RAR and 7-Zip are located by
//! scanning the head for their magic; zip is located from its TAIL, by
//! `nzbkit::zip::stubbed_archive`, because a forward scan for a zip
//! signature claims ordinary programs (see [`sfx_kind`] for the numbers).
//! Zip is also the one family that is never carved - its reader takes the
//! stub's length from the container's own geometry.
//!
//! Whichever way a candidate is found, it is CONFIRMED against the
//! container's own checksums before anything is claimed. A magic number
//! is a string that appears inside ordinary programs; a valid header
//! behind it is not.
//!
//! The two callers are `extract_one_level` step 3 (depth 0, the offline
//! `extract` command's top level) and the get tail's downloaded-slot arm.
//! Neither is reachable from the nested pass by design: a payload's own
//! `setup.exe` is very often a legitimate WinRAR SFX installer, and must
//! never be auto-exploded.

use crate::*;
use tracing::{info, warn};

/// How much of a candidate's head is scanned for an appended archive.
/// Owned by `nzbkit::sfx` since TODO 94 C, because the one-pass mapper's
/// offset-0 sniff runs the same scan and the two must agree.
use nzbkit::sfx::SFX_SCAN_WINDOW;

/// The shape vocabulary the disk arm reports into - see
/// [`sfx_disk_shape`].
use nzbkit::extract::DiskArchive;

/// Read past the scan window by this much, so a signature sitting at the
/// window's very last byte still has its whole main header in the buffer
/// to be confirmed against. Without it, confirmation would turn the
/// window's edge into a silent "not an archive" for the one archive that
/// straddles it.
const SFX_HEADER_SLACK: usize = 64 << 10;

/// Is this file an SFX self-extractor - an executable-ish name with a real
/// archive sitting behind the launcher stub?
///
/// The extension gate comes first because it is free, and because it is
/// still a SAFETY gate even now that every match is confirmed: a data file
/// can legitimately CONTAIN an archive - a disk image, a backup, a nested
/// container someone posted whole - and a header check says only that one
/// is there, never that unpacking it is what the user wanted.
///
/// An archive starting AT offset 0 is a bare one wearing the wrong name,
/// not a self-extractor - there is no stub to carve, `carve_sfx` declines
/// it, and the SFX arm would report a failure over a file the ordinary
/// paths can open. All three families are held to that rule; only RAR was
/// before, so a bare 7z named `.exe` was collected as an SFX and failed.
///
/// One tail read plus at most one head read per candidate, so this is
/// cheap enough for a directory gate: a release carries a handful of
/// executables at most.
pub(crate) fn is_sfx_archive(path: &std::path::Path) -> bool {
    sfx_kind(path).is_some()
}

/// [`is_sfx_archive`] with the answer the extraction arm needs: which
/// family sits behind the stub.
///
/// All three answers are CONFIRMED against the container's own checksums
/// - zip from its tail geometry (`nzbkit::zip::stubbed_archive`), RAR and
/// 7-Zip from a main header behind the signature (`sfx_payload_at`). None
/// of the three can be satisfied by bytes that are not an archive, which
/// is the property the gate needs: over 1,105 real binaries a bare
/// substring rule claims 25, and confirmation takes the whole sweep to 10,
/// all of them real self-extractors (TODO 159 items 6 and 7).
///
/// Zip is probed first only because its test is the cheapest to run to a
/// verdict - one tail read, no scan - so a stubbed zip never pays for a
/// 4 MiB head read it does not need.
///
/// A zip whose entries say it is the DELIVERABLE - a jar behind a Launch4j
/// launcher, an NW.js resource bundle - is not an SFX for our purposes and
/// is declined here, with a line saying so, because leaving it packed is
/// the correct outcome and a silent decline reads as "we saw nothing".
pub(crate) fn sfx_kind(path: &std::path::Path) -> Option<SfxKind> {
    let sfx_ext = path
        .file_name()
        .is_some_and(|n| nzbkit::sfx::is_sfx_name(&n.to_string_lossy()));
    if !sfx_ext {
        return None;
    }
    match nzbkit::zip::stubbed_archive(path) {
        Some(nzbkit::zip::Stubbed::Packaging { .. }) => return Some(SfxKind::Zip),
        Some(nzbkit::zip::Stubbed::FinalFile { what, .. }) => {
            info!(
                target: "extract",
                "  {} carries {what} rather than packaging - left as it is",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            return None;
        }
        None => {}
    }
    let head = read_head(path, SFX_SCAN_WINDOW + SFX_HEADER_SLACK);
    match sfx_payload_at(&head) {
        Some((off, kind)) if off > 0 => Some(kind),
        _ => None,
    }
}

/// What the disk SFX arm is about to unpack, for the shape badge.
///
/// The badge is what a user reads to understand why a job was fast or
/// slow, and this route left it EMPTY: a self-extractor whose stub runs
/// past the offset-0 article is a plain data file to the in-stream sniff,
/// so nothing archive-shaped is ever classified and the queue row, the
/// history entry and the download report all say nothing about a payload
/// that was demonstrably an archive. Measured 23 Aug 2026 on the
/// libarchive `test_read_format_rar5_sfx.exe` fixture at `--article-size
/// 128K`, beside an `sfx7z` reading `7z one-pass` and a `comp5` reading
/// `rar5 compressed on-disk`.
///
/// The FAMILY only, and RAR's dialect from its signature: this arm hands
/// a whole archive to a reader and never parses a per-entry method, so
/// there is no honest store/compressed token to add and
/// `ArchiveShape::from_bits` renders none. `one-pass` would be a lie -
/// these bytes landed on disk and were unpacked afterwards, which is
/// what [`nzbkit::extract::Extractor::note_disk_archive`] latches.
///
/// Its own head read, like `sfx_kind` and `carve_sfx` before it: a
/// release carries a handful of executables at most, and this runs on a
/// path that is about to carve and unpack the whole payload.
pub(crate) fn sfx_disk_shape(path: &std::path::Path) -> Option<DiskArchive> {
    match sfx_kind(path)? {
        SfxKind::Zip => Some(DiskArchive::Zip),
        SfxKind::SevenZ => Some(DiskArchive::SevenZ),
        SfxKind::Rar => {
            let head = read_head(path, SFX_SCAN_WINDOW + SFX_HEADER_SLACK);
            let (off, _) = sfx_payload_at(&head)?;
            match nzbkit::rar::signature_version(&head[off..])? {
                5 => Some(DiskArchive::Rar5),
                _ => Some(DiskArchive::Rar4),
            }
        }
    }
}

/// Read up to `cap` bytes from the start of `path`, looping until the
/// buffer is full or the file ends. A single `read` may legally return
/// short of a 4 MiB request, and a signature sitting past that boundary
/// would then read as "no archive here" on some runs and not others.
fn read_head(path: &std::path::Path, cap: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; cap];
    let mut n = 0;
    if let Ok(mut f) = std::fs::File::open(path) {
        while n < buf.len() {
            match f.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(_) => break,
            }
        }
    }
    buf.truncate(n);
    buf
}

/// SFX self-extractor candidates sitting directly in `dir`.
pub(crate) fn collect_sfx_archives(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_file()) && is_sfx_archive(&path) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Where an SFX stub's real archive starts, and which kind it is.
///
/// An SFX is an executable with an archive appended, so the payload is
/// found by SIGNATURE, not by extension - and it is never at offset 0
/// (that is a bare archive, which the caller has already routed
/// elsewhere). Both families ship one: WinRAR writes `Rar!` and 7-Zip
/// writes the 7z magic after their respective stubs.
///
/// Only RAR was recognised before, so a 7z SFX was not merely
/// unextractable, it was invisible: nothing collected it and nothing
/// said why. The 12 Aug competitor round found no client that unpacks
/// either shape.
///
/// **Every match is CONFIRMED, and the scan does not stop at the first
/// one.** Both magics occur as constants inside ordinary programs - the
/// 7-Zip CLI carries the 7z magic, and so does every binary this project
/// ships - so a bare substring hit claimed 25 of 1,105 real binaries,
/// and a false claim is not cosmetic: `extract_sfx` fails on it and
/// the get tail turns that into a Failed job. Each candidate now has to
/// have a CRC-valid main header sitting behind it
/// (`rar::archive_starts_here`, `nameprobe::sevenz_start`), and a
/// candidate that has not is stepped over rather than believed - which is
/// the half that matters, since the decoy constant in those binaries comes
/// BEFORE any real payload would. TODO 159 item 7.
pub(crate) fn sfx_payload_at(head: &[u8]) -> Option<(usize, SfxKind)> {
    // The scan itself lives in `nzbkit::sfx` since TODO 94 C - the
    // one-pass mapper's offset-0 sniff runs the very same one, so what
    // this gate calls an SFX and what the stream maps cannot disagree.
    nzbkit::sfx::sfx_payload_at(head).map(|(off, f)| {
        let kind = match f {
            nzbkit::sfx::SfxFamily::Rar => SfxKind::Rar,
            nzbkit::sfx::SfxFamily::SevenZ => SfxKind::SevenZ,
        };
        (off, kind)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SfxKind {
    Rar,
    SevenZ,
    /// Found by [`sfx_kind`], never by [`sfx_payload_at`] - a zip is
    /// located from its tail, not by a forward signature scan.
    Zip,
}

impl SfxKind {
    fn label(self) -> &'static str {
        match self {
            SfxKind::Rar => "RAR",
            SfxKind::SevenZ => "7-Zip",
            SfxKind::Zip => "zip",
        }
    }

    /// What the carve names the archive it cuts out of the stub.
    ///
    /// `None` for zip, which never carves: the zip reader takes the
    /// prefix's length from the container's own geometry and reads the
    /// archive where it lies, so copying the tail out would buy nothing
    /// but a second copy of the payload on disk.
    fn carved_name(self) -> Option<&'static str> {
        match self {
            SfxKind::Rar => Some("carved.rar"),
            SfxKind::SevenZ => Some("carved.7z"),
            SfxKind::Zip => None,
        }
    }
}

/// Extract each SFX archive standalone (rars locates the archive past the
/// stub itself).
pub(crate) fn extract_sfx(
    dir: &std::path::Path,
    archives: &[PathBuf],
    password: Option<&str>,
) -> bool {
    let options = nzbkit::mem::rar_read_options(password.map(str::as_bytes));
    let mut all_ok = true;
    for path in archives {
        // TODO 205 follow-up: one SFX archive is one SET on the queue
        // row's unpack lane, however many ways this loop body tries to
        // open it - the carve fallback below is a second go at this very
        // file, and banking it as a new set reported twice the bytes the
        // archive can produce. See [`crate::unpackprog::mark`].
        let mark = crate::unpackprog::mark();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        // A stubbed zip needs no carve and no second reader: the zip
        // reader infers the stub's length from the container's geometry
        // and opens the archive where it sits, so this hands the file
        // itself to the ordinary zip arm - the same staging, the same
        // zip-slip and bomb guards, the same CRC gate.
        if sfx_kind(path) == Some(SfxKind::Zip) {
            info!(target: "extract", "unpacking self-extracting zip {name}…");
            let job = nzbkit::zip::Finding {
                name: name.to_string(),
                parts: vec![path.clone()],
                shape: nzbkit::zip::Shape::Single,
            };
            all_ok &= crate::rarfix::extract_zip(dir, &[job], password);
            continue;
        }
        info!(target: "extract", "unpacking SFX archive {name} natively…");
        let direct = rars::ArchiveReader::read_path_with_options(path, options)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .and_then(|archive| write_archives_to(dir, &[archive], password));
        match direct {
            Ok(()) => {
                info!(target: "extract", "SFX unpack complete ✔");
                continue;
            }
            Err(e) => {
                // Another go at THIS archive, so the lane goes back to
                // where the loop body found it (see `mark` above).
                mark.rewind();
                // The reader could not seek past this stub - or the
                // payload is a 7z, which it cannot read at all. Carve
                // the archive out by signature and extract THAT. Kept
                // as a fallback rather than the first move so the
                // common case still streams through rars without
                // writing a second copy of the payload to disk.
                match carve_sfx(path) {
                    Some((carved, kind)) => {
                        let carved_path = carved.dir.join(kind.carved_name().unwrap_or_default());
                        let ok = match kind {
                            SfxKind::Rar => {
                                rars::ArchiveReader::read_path_with_options(&carved_path, options)
                                    .map_err(|e| anyhow::anyhow!("{e}"))
                                    .and_then(|a| write_archives_to(dir, &[a], password))
                                    .is_ok()
                            }
                            SfxKind::SevenZ => crate::rarfix::extract_sevenz(
                                dir,
                                &[vec![carved_path.clone()]],
                                password,
                            ),
                            // Unreachable: the carve locates its payload
                            // with `sfx_payload_at`, which knows only the
                            // two head-scanned families. Zip is handled
                            // above and never carved at all.
                            SfxKind::Zip => false,
                        };
                        if ok {
                            info!(target: "extract", "SFX unpack complete ✔ (carved past the stub)");
                        } else {
                            warn!(
                                target: "extract",
                                "SFX unpack failed ({e}), and the carved archive \
                                 did not extract either"
                            );
                            all_ok = false;
                        }
                    }
                    None => {
                        warn!(target: "extract", "SFX unpack failed ({e})");
                        all_ok = false;
                    }
                }
            }
        }
    }
    all_ok
}

/// Copy an SFX's appended archive out to its own file, dropping the
/// executable stub in front of it.
///
/// Returns the scratch copy (deleted when the handle drops) and what
/// kind of archive it holds. None when no signature is found, which for
/// a file this far down the path means it was never an SFX.
///
/// The whole tail is copied because both readers want a file they can
/// seek within, and the stub is the only part that must go: an offset
/// reader would be leaner but would have to be threaded through two
/// unrelated extractors, and an SFX payload is bounded by the post we
/// already downloaded.
fn carve_sfx(path: &std::path::Path) -> Option<(ExtractStaging, SfxKind)> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let (off, kind) = sfx_payload_at(&read_head(path, SFX_SCAN_WINDOW + SFX_HEADER_SLACK))?;
    let mut f = std::fs::File::open(path).ok()?;
    if off == 0 {
        // Already a bare archive: the direct read above failed for some
        // other reason and carving would just copy it verbatim.
        return None;
    }
    // Beside the payload, on the same filesystem, under the `.nzbfast`
    // prefix the nested pass's walkers already skip as scratch.
    let scratch = ExtractStaging::new(path.parent()?).ok()?;
    let out = scratch.dir.join(kind.carved_name()?);
    f.seek(SeekFrom::Start(off as u64)).ok()?;
    let mut w = std::io::BufWriter::new(std::fs::File::create(&out).ok()?);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => w.write_all(&buf[..k]).ok()?,
            Err(_) => return None,
        }
    }
    w.flush().ok()?;
    info!(
        target: "extract",
        "  carved {} archive from the SFX stub at offset {off}",
        kind.label()
    );
    Some((scratch, kind))
}

#[cfg(test)]
mod sfx_tests {
    use super::*;
    use nzbkit::zip::fixtures::Spec;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-sfx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Build a self-extractor the way the real ones are built: an
    /// executable stub with the archive appended. Synthesised rather
    /// than vendored so the test owns its inputs (and no third-party
    /// fixture rides into this repo for it).
    fn sfx_from(fixture: &str, out: &std::path::Path, stub_len: usize) {
        let arch = std::fs::read(fixture).unwrap();
        let mut stub = vec![0x4du8, 0x5a]; // "MZ", so it looks like a PE
        stub.extend(std::iter::repeat_n(0x90u8, stub_len));
        stub.extend(arch);
        std::fs::write(out, stub).unwrap();
    }

    /// The payload is found by SIGNATURE and past the stub. RAR was the
    /// only family recognised before, so a 7z SFX was invisible: nothing
    /// collected it and nothing said why (12 Aug competitor round -
    /// advO, which NO client unpacked).
    #[test]
    fn a_stubbed_archive_is_located_by_signature_for_both_families() {
        let rar = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
        ))
        .unwrap();
        let mut buf = vec![0x90u8; 4096];
        buf.extend(&rar);
        assert_eq!(sfx_payload_at(&buf), Some((4096, SfxKind::Rar)));

        let sevenz = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../nzbkit/tests/fixtures/sevenz/store-single.7z"
        ))
        .unwrap();
        let mut buf = vec![0x90u8; 2048];
        buf.extend(&sevenz);
        assert_eq!(sfx_payload_at(&buf), Some((2048, SfxKind::SevenZ)));

        // A bare archive is not an SFX: offset 0 is the caller's other
        // path, and carve_sfx declines it rather than copying it.
        assert_eq!(sfx_payload_at(&rar), Some((0, SfxKind::Rar)));
        assert_eq!(sfx_payload_at(b"no archive in here at all"), None);
    }

    /// A signature is a CANDIDATE, never an answer, and the scan does not
    /// stop at the first one.
    ///
    /// Both magics live as constants inside ordinary programs: the 7-Zip
    /// CLI carries the 7z magic in its own code, and so does every Windows
    /// binary this project ships. The old gate took the first match on
    /// faith, so `nzbfast extract` over a directory holding our own
    /// `nzbfast.exe` carved at offset 1934516, failed, and - through
    /// `reextract_failed` in the get tail - failed the JOB. Measured: the
    /// bare substring rule claims 25 of 1,105 real binaries, this one
    /// claims 10, and all 10 are real self-extractors (TODO 159 item 7).
    ///
    /// Stepping OVER a bad candidate rather than giving up on it is the
    /// half that matters: in every one of those binaries the decoy
    /// constant sits early, where a real payload would come later.
    #[test]
    fn a_signature_without_a_header_behind_it_is_stepped_over() {
        let rar = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
        ))
        .unwrap();
        let sevenz = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../nzbkit/tests/fixtures/sevenz/store-single.7z"
        ))
        .unwrap();

        // A magic constant with nothing behind it is what a program's own
        // code looks like. Claiming one used to fail the job.
        let mut decoys = vec![0x90u8; 512];
        decoys.extend(b"Rar!\x1a\x07\x01\x00");
        decoys.extend([0u8; 64]);
        decoys.extend(b"Rar!\x1a\x07\x00");
        decoys.extend([0u8; 64]);
        decoys.extend(nzbkit::nameprobe::SEVENZ_MAGIC);
        decoys.extend([0u8; 64]);
        assert_eq!(sfx_payload_at(&decoys), None, "no header, no claim");

        // ...and the real archive BEHIND the decoys is still found, at its
        // own offset. A scan that stopped at the first match would answer
        // "not an archive" for exactly the file that is one.
        for (payload, kind) in [(&rar, SfxKind::Rar), (&sevenz, SfxKind::SevenZ)] {
            let mut buf = decoys.clone();
            let at = buf.len();
            buf.extend(payload);
            assert_eq!(sfx_payload_at(&buf), Some((at, kind)));
        }

        // A real archive whose stored header checksum disagrees is not
        // claimed either. `solid.rar` is RAR5, so its CRC32 sits in the
        // four bytes straight after the 8-byte signature: corrupting those
        // leaves every size and type field intact, so the CRC is the only
        // thing that can refuse it.
        let mut broken = vec![0x90u8; 512];
        broken.extend(&rar);
        broken[512 + 8] ^= 0xff;
        assert_eq!(
            sfx_payload_at(&broken),
            None,
            "a damaged header is no claim"
        );
    }

    /// Collection keys on the signature, not the extension's promise -
    /// and the window has to outrun the stub. A 7-Zip PE stub alone is
    /// ~200 KB and the old 1 MiB read could sit entirely inside one.
    #[test]
    fn a_seven_zip_sfx_is_collected_and_a_deep_stub_still_found() {
        let dir = tmp("collect");
        sfx_from(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../nzbkit/tests/fixtures/sevenz/store-single.7z"
            ),
            &dir.join("release.exe"),
            1_500_000,
        );
        let found = collect_sfx_archives(&dir).unwrap();
        assert_eq!(found.len(), 1, "a 7z SFX past 1 MiB of stub must be seen");
        assert!(found[0].ends_with("release.exe"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ENTRY gate, which is what advO actually needed: a post whose
    /// only members are SFX executables used to finish as "2 files
    /// complete" with two `.exe`s as the payload, because nothing
    /// upstream of the extractor recognised the shape - the in-stream
    /// mapper sniffs offset 0, and a stub reads as a plain data file.
    ///
    /// The extension is a SAFETY gate, not a convenience: the head scan
    /// is a substring search, so run over arbitrary payload it would
    /// eventually match a data file that merely contains the bytes.
    #[test]
    fn the_entry_gate_takes_an_sfx_and_leaves_plain_files_alone() {
        let dir = tmp("gate");
        let sevenz = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../nzbkit/tests/fixtures/sevenz/store-single.7z"
        );
        sfx_from(sevenz, &dir.join("release.exe"), 4096);
        assert!(is_sfx_archive(&dir.join("release.exe")));

        // Same bytes under a payload extension: never scanned, never
        // exploded. A `.mkv` carrying an appended archive is a `.mkv`.
        sfx_from(sevenz, &dir.join("movie.mkv"), 4096);
        assert!(!is_sfx_archive(&dir.join("movie.mkv")));

        // A bare archive that happens to be named .exe is the normal
        // path's business (magic at offset 0), not this one.
        std::fs::copy(sevenz, dir.join("bare.exe")).unwrap();
        assert!(
            !is_sfx_archive(&dir.join("bare.exe")),
            "offset 0 is not a stub"
        );
        // ...and the OTHER half of that sentence, which is the
        // user-visible consequence: SFX routing runs BEFORE the normal 7z
        // magic path, so a bare archive this gate wrongly claimed was not
        // merely mis-labelled - the direct read failed, `carve_sfx`
        // declined offset 0, and extraction reported false without the
        // plain path ever seeing the file. Every one of these extensions,
        // because the gate lists three (Codex sweep 12 Aug F13).
        for name in ["bare2.bin", "bare3.sfx"] {
            std::fs::copy(sevenz, dir.join(name)).unwrap();
            assert!(!is_sfx_archive(&dir.join(name)), "{name}: offset 0");
        }
        let claimed = crate::rarfix::collect_sevenz_archives(&dir).unwrap();
        assert_eq!(
            claimed.len(),
            3,
            "the normal 7z path must claim all three bare copies: {claimed:?}"
        );
        // The rule is about offset 0, not about 7-Zip: a bare RAR under
        // an SFX extension is the RAR path's business the same way.
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
            ),
            dir.join("movie.exe"),
        )
        .unwrap();
        assert!(
            !is_sfx_archive(&dir.join("movie.exe")),
            "a bare RAR named .exe is not a stub either"
        );
        // Nothing above left a candidate behind, at any extension.
        assert!(
            collect_sfx_archives(&dir)
                .unwrap()
                .iter()
                .all(|p| p.file_name().is_some_and(|n| n == "release.exe")),
            "only the real self-extractor is collected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Build a self-extracting ZIP the way one is really built - a stub
    /// with the container concatenated on - and return the container's
    /// bytes so the caller can also write it bare.
    fn zip_sfx(dir: &std::path::Path, name: &str, stub_len: usize, specs: &[Spec]) -> Vec<u8> {
        let z = nzbkit::zip::fixtures::zip_of(specs);
        let mut buf = vec![0x4du8, 0x5a];
        buf.extend(std::iter::repeat_n(0x90u8, stub_len));
        buf.extend(&z);
        std::fs::write(dir.join(name), buf).unwrap();
        z
    }

    /// A self-extracting zip is collected and unpacked, with no carve:
    /// the reader takes the stub's length from the container's own
    /// geometry, so the archive is opened where it lies and the `.exe`
    /// is left intact beside the payload it produced.
    #[test]
    fn a_self_extracting_zip_is_collected_and_unpacked_in_place() {
        let dir = tmp("zipsfx");
        let bare = zip_sfx(
            &dir,
            "release.exe",
            300_000,
            &[
                Spec::stored("Show.S01E01.mkv", b"the payload"),
                Spec::deflated("Show.S01E01.nfo", b"about the payload"),
            ],
        );
        let exe = dir.join("release.exe");
        assert_eq!(sfx_kind(&exe), Some(SfxKind::Zip));
        assert_eq!(collect_sfx_archives(&dir).unwrap(), vec![exe.clone()]);

        assert!(extract_sfx(&dir, std::slice::from_ref(&exe), None));
        assert_eq!(
            std::fs::read(dir.join("Show.S01E01.mkv")).unwrap(),
            b"the payload"
        );
        assert_eq!(
            std::fs::read(dir.join("Show.S01E01.nfo")).unwrap(),
            b"about the payload"
        );
        assert!(exe.exists(), "the self-extractor itself must survive");

        // Offset 0 is the same rule the other two families follow: a bare
        // container wearing an executable name has no stub to get past,
        // so this arm must not claim it.
        std::fs::write(dir.join("bare.exe"), &bare).unwrap();
        assert_eq!(sfx_kind(&dir.join("bare.exe")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The false positive the zip arm exists in tension with, and the one
    /// shape a structural test cannot refuse on structure: a launcher in
    /// front of a jar is a genuine appended zip. Exploding it would spray
    /// an application's own class files over the release directory, so it
    /// is refused on CONTENT - the content-side twin of the `.jar`/`.apk`
    /// entry in `FINAL_FILE_EXTS`, which cannot fire here because the
    /// stub has taken the name.
    #[test]
    fn a_launcher_wrapping_a_jar_is_never_collected() {
        let dir = tmp("zipsfx-jar");
        zip_sfx(
            &dir,
            "app.exe",
            150_000,
            &[
                Spec::stored("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
                Spec::deflated("com/acme/Main.class", b"\xca\xfe\xba\xbe not really"),
            ],
        );
        assert_eq!(sfx_kind(&dir.join("app.exe")), None);
        assert!(
            collect_sfx_archives(&dir).unwrap().is_empty(),
            "a Launch4j-style wrapper is the deliverable, not packaging"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The boundary the depth-0 restriction rests on. `is_extractable_
    /// archive` drives nested DESCENT - `is_new_nested_archive`,
    /// `dir_has_nested_extractable`, and `entry_archives`, whose
    /// spent-intermediate sweep DELETES what it lists. Teaching it about
    /// SFX would make a release's own `setup.exe` a nested layer and then
    /// disposable furniture, so the SFX gate stays separate and is only
    /// ever applied to files we know were DOWNLOADED.
    #[test]
    fn an_sfx_is_never_a_nested_descent_target() {
        let dir = tmp("descent");
        let exe = dir.join("setup.exe");
        sfx_from(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
            ),
            &exe,
            4096,
        );
        assert!(is_sfx_archive(&exe));
        assert!(
            !is_extractable_archive(&exe),
            "a produced setup.exe must never be re-exploded by the nested pass"
        );
        assert!(!dir_has_nested_extractable(&dir).unwrap());
        // Same boundary for the zip family. It is the one whose payload
        // is genuinely common inside ordinary programs, so teaching
        // descent about it would be the worst version of this mistake.
        let dir2 = tmp("descent-zip");
        zip_sfx(
            &dir2,
            "installer.exe",
            4096,
            &[Spec::stored("data/app.dll", b"resources")],
        );
        let exe2 = dir2.join("installer.exe");
        assert_eq!(sfx_kind(&exe2), Some(SfxKind::Zip));
        assert!(!is_extractable_archive(&exe2));
        assert!(!dir_has_nested_extractable(&dir2).unwrap());
        assert!(
            nzbkit::zip::scan(&dir2).is_empty(),
            "the zip collector must not start claiming executables either"
        );
        let _ = std::fs::remove_dir_all(&dir2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The shape badge for this route, which used to be blank. A job
    /// that unpacked through the disk SFX arm reported an EMPTY
    /// `archive_shape` - queue row, history and the download report all
    /// silent about a payload that was demonstrably an archive - because
    /// the extractor only ever saw a plain data file and this arm noted
    /// nothing. Measured 23 Aug 2026 against an `sfx7z` reading `7z
    /// one-pass` and a `comp5` reading `rar5 compressed on-disk`.
    ///
    /// The RAR dialect comes off the signature past the stub, so the
    /// badge distinguishes RAR4 from RAR5 the way the mapper-fed routes
    /// do rather than settling for a family word the dashboard would
    /// have to learn.
    #[test]
    fn the_disk_arm_names_the_family_it_is_about_to_unpack() {
        let dir = tmp("diskshape");
        sfx_from(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
            ),
            &dir.join("rar5.exe"),
            8192,
        );
        assert_eq!(
            sfx_disk_shape(&dir.join("rar5.exe")),
            Some(DiskArchive::Rar5)
        );

        sfx_from(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vendor/rars/tests/fixtures/rar15_40/rars_generated/stored.rar"
            ),
            &dir.join("rar4.exe"),
            8192,
        );
        assert_eq!(
            sfx_disk_shape(&dir.join("rar4.exe")),
            Some(DiskArchive::Rar4)
        );

        sfx_from(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../nzbkit/tests/fixtures/sevenz/store-single.7z"
            ),
            &dir.join("sevenz.exe"),
            8192,
        );
        assert_eq!(
            sfx_disk_shape(&dir.join("sevenz.exe")),
            Some(DiskArchive::SevenZ)
        );

        zip_sfx(
            &dir,
            "zip.exe",
            8192,
            &[Spec::stored("Show.S01E01.mkv", b"the payload")],
        );
        assert_eq!(sfx_disk_shape(&dir.join("zip.exe")), Some(DiskArchive::Zip));

        // Everything the entry gate declines has no shape either: the
        // badge must never claim an archive over a file this arm is
        // going to leave exactly as it found it.
        std::fs::write(dir.join("plain.exe"), b"MZ not an archive at all").unwrap();
        assert_eq!(sfx_disk_shape(&dir.join("plain.exe")), None);
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
            ),
            dir.join("bare.exe"),
        )
        .unwrap();
        assert_eq!(sfx_disk_shape(&dir.join("bare.exe")), None, "offset 0");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The carve drops the stub and leaves a plain archive the readers
    /// can open, with the scratch dir cleaning up after itself.
    #[test]
    fn carving_yields_a_readable_archive_and_cleans_up() {
        let dir = tmp("carve");
        let exe = dir.join("payload.exe");
        sfx_from(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
            ),
            &exe,
            8192,
        );
        let scratch_dir;
        {
            let (scratch, kind) = carve_sfx(&exe).expect("signature is present");
            assert_eq!(kind, SfxKind::Rar);
            let carved = scratch.dir.join("carved.rar");
            scratch_dir = scratch.dir.clone();
            let head = std::fs::read(&carved).unwrap();
            assert!(head.starts_with(b"Rar!"), "the stub must be gone");
            assert!(
                rars::ArchiveReader::read_path_with_options(
                    &carved,
                    nzbkit::mem::rar_read_options(None)
                )
                .is_ok(),
                "the carved archive must open"
            );
        }
        assert!(!scratch_dir.exists(), "scratch must not outlive the carve");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
