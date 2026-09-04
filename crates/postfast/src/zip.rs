//! The zip half of the container plane (H1), over the `zip` crate's
//! writer.
//!
//! **The archives are written by a library, exactly as the RAR and 7z
//! halves are, and never by hand.** `crate::container`'s header states
//! the rule and the reason; this module is the third writer it reaches
//! for rather than an exception to it. That distinction is sharper here
//! than anywhere else in the crate, because a STORED zip is four record
//! types and looks temptingly easy to emit: a local file header per
//! member, the payload, a central directory entry per member, and an
//! end-of-central-directory. Assembling those by hand would produce a
//! fixture that agrees with our own reader and with nothing else, which
//! is the exact failure the oracle exists to catch rather than to
//! commit.
//!
//! # There IS a zip writer in this tree already, and it is the wrong one
//!
//! `nzbkit::zip::fixtures` writes zips, and its own doc comment says
//! what it is for: "Deliberately hand-rolled so the reader is tested
//! against bytes we control completely, including the malformed and
//! declined shapes no real writer would produce." It is the READER's
//! test writer. Using it here would make every catalog zip row a round
//! trip between one author's writer and the same author's reader -
//! and `tools/gen-zip-fixtures.py`'s header already names that failure
//! in as many words, which is why the committed zip interop fixtures
//! are written by Python's `zipfile` instead. A catalog row is graded
//! by the real client, so its bytes have to come from a writer with no
//! stake in our reader.
//!
//! # The dependency, which the 7z arm did not need
//!
//! `research/POSTFAST-VS-NESTED-CORPUS-2026-09-03.md`'s H1 said "a
//! vendored 7z or zip writer is a dependency decision", and for 7z that
//! turned out to be wrong - `vendor/sevenz-rust2` was already in the
//! tree. For zip it was right: nothing in this repo wrote one. What it
//! cost is written out in `crates/postfast/Cargo.toml` beside the
//! `zip` line; the short version is MIT, one genuinely new transitive
//! crate with `default-features = false`, and no shipped binary, since
//! postfast is `publish = false` test infrastructure.
//!
//! It is a crates.io dependency and NOT a `vendor/` entry, which is the
//! shape the chip that built this arm priced first. `vendor/` in this
//! workspace is for crates this repo FORKS - `rars`, `sevenz-rust2`,
//! `lzma-rust2`, `rapidyenc`, `tiny_http` all carry local changes and a
//! `README-nzbfast.md` saying what they are. Nothing here needs to
//! change a line of the zip crate, so vendoring it would buy a second
//! copy to keep in sync and no capability at all.
//!
//! # Determinism, and why the feature flag alone is not enough
//!
//! `zip::DateTime::default_for_write()` has two `#[cfg]` arms: with the
//! crate's `time` feature it reads the clock, and without it returns
//! the constant 1980-01-01. The manifest turns `time` off, so the
//! default is already the constant - but feature unification is a
//! workspace-wide question and no crate can promise that a future
//! dependency will not turn `time` on somewhere else in the graph. So
//! [`write_archive`] sets the timestamp EXPLICITLY rather than relying
//! on the default, and `container.rs`'s
//! `wrapping_twice_is_byte_identical` is the assertion either way.
//! Nothing else in a zip record is drawn from the OS: no permissions
//! are set, and the writer has no entropy to seed.
//!
//! # A byte-split zip, and the shape that is refused beside it
//!
//! `nzbkit::zip` reads TWO multi-part shapes, and only one of them is
//! emitable here.
//!
//! - **Byte-split** (`name.zip.001`, `.002`, ...): the finished archive
//!   cut into fixed-size pieces. `nzbkit::zip::Parts` opens the ordered
//!   parts as one contiguous logical byte space and reads the container
//!   out of it, so concatenating them gives the archive back byte for
//!   byte. That is the same definition a split 7z has, and the cut is
//!   `crate::sevenz::split_parts` for both - one copy of a chunking
//!   rule that knows nothing about either format.
//! - **WinZip-spanned** (`.z01`, `.z02`, ..., `.zip`, with the trailing
//!   `.zip` sorting LAST because it holds the central directory): a
//!   grammar of its own. A spanned set needs a spanning marker ahead of
//!   the first local header and a per-entry disk number in the central
//!   directory, and the `zip` crate's writer emits neither. So it is
//!   refused by name in `container.rs` rather than approximated - a
//!   `.z01` set assembled by hand is precisely the fixture this module
//!   header opens by refusing.
//!
//! # Compression
//!
//! Deflate, which is what every zip tool writes by default, against
//! Stored. The method is recorded per ENTRY in both the local header
//! and the central directory, and this writer does not fall back to
//! Stored for an entry that did not shrink - so a deflated archive over
//! incompressible `[source]` bytes is still an archive the client must
//! run the inflate over, which is what C3 is for, and it comes out
//! slightly larger than the payload. That is the 7z arm's property and
//! not the RAR arm's; [`declared_methods`] is what makes the claim
//! checkable, and `container.rs` asserts it for the same reason it
//! asserts the other two: a fixture whose plane was never applied is
//! the failure the whole crate exists to refuse.

use std::io::{Cursor, Read, Write};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

/// The method a stored entry declares, for the guard's comparison.
///
/// The zip parallel of `crate::sevenz::COPY_ID`.
pub const STORED: CompressionMethod = CompressionMethod::Stored;

/// Write one zip archive holding `members`, in the order given.
///
/// `compressed` picks the per-entry method: Deflate, which is what
/// every zip tool writes by default, against Stored, which is what
/// `zip -0` writes and what the nested corpus's own `r5-zip` leg
/// carries.
///
/// Deterministic by construction, and it has to be: the timestamp is
/// pinned to the format's own 1980-01-01 epoch rather than left to the
/// crate's default (the module header says why that distinction
/// matters), no permissions are set, and nothing here draws from the OS
/// entropy the way the RAR encryption arms do.
pub fn write_archive(members: &[(String, Vec<u8>)], compressed: bool) -> Result<Vec<u8>, String> {
    let method = if compressed {
        CompressionMethod::Deflated
    } else {
        CompressionMethod::Stored
    };
    // `DateTime::DEFAULT` and not `DateTime::default_for_write()`: the
    // second reads the clock when the crate's `time` feature is on
    // anywhere in the graph, and this crate cannot promise it never
    // will be.
    let opts = SimpleFileOptions::default()
        .compression_method(method)
        .last_modified_time(DateTime::DEFAULT)
        .unix_permissions(0o644);
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in members {
        // `start_file` and not `add_directory` for the parents of a
        // nested name: a zip carries the relative path on the entry
        // itself, and a real archiver writing `sample/s.bin` from a
        // file list emits one entry, not a directory entry beside it.
        // `extract_set` asserts the count either way.
        w.start_file(name.as_str(), opts)
            .map_err(|e| format!("the zip writer refused {name:?}: {e}"))?;
        w.write_all(bytes)
            .map_err(|e| format!("the zip writer would not take {name:?}: {e}"))?;
    }
    let out = w
        .finish()
        .map_err(|e| format!("the zip writer could not finish: {e}"))?;
    Ok(out.into_inner())
}

/// Extract a whole zip set - one archive, or the ordered parts of a
/// byte-split one - into (name, bytes) in archive order.
///
/// The parts are concatenated because that is what the split shape IS,
/// and it is how the client reads one: `nzbkit::zip::Parts` opens the
/// ordered files as a single logical byte space rather than joining
/// them on disk. Here the payloads are kilobytes and the check runs at
/// generation, so the in-memory join is the simple reading of the same
/// thing.
pub fn extract_set(set: &[Vec<u8>]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let joined: Vec<u8> = set.concat();
    let mut r = ZipArchive::new(Cursor::new(joined))
        .map_err(|e| format!("the zip set does not parse: {e}"))?;
    let mut out = Vec::new();
    for i in 0..r.len() {
        let mut e = r
            .by_index(i)
            .map_err(|e| format!("the zip set has no entry {i}: {e}"))?;
        // A directory entry is not a member and would show up as an
        // extra name in the round trip. Nothing this writer emits
        // should be one - it writes exactly the entries it was handed -
        // so this is the assertion that says so rather than a filter:
        // a directory appearing here means the writer grew a behaviour
        // the round trip would otherwise have absorbed.
        if e.is_dir() {
            return Err(format!(
                "the zip set holds a DIRECTORY entry {:?}, which this writer never emits - \
                 the zip crate grew a behaviour that would make every member count wrong",
                e.name()
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(e.size()).unwrap_or(0));
        e.read_to_end(&mut bytes)
            .map_err(|err| format!("the zip entry {:?} does not extract: {err}", e.name()))?;
        out.push((e.name().to_string(), bytes));
    }
    Ok(out)
}

/// The method each entry DECLARES, in archive order.
///
/// Read off the central directory rather than inferred from the emitted
/// size, because size is exactly the wrong question here: a deflated
/// archive over incompressible bytes is LARGER than its payload and is
/// still an archive the client must run the inflate over. Per entry and
/// not per archive, which is where zip differs from 7z: the method is
/// an entry's own property, so a writer that stored one member of
/// several would be a partial C3 and is caught by looking at all of
/// them.
pub fn declared_methods(bytes: &[u8]) -> Result<Vec<CompressionMethod>, String> {
    let mut r = ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| format!("the zip archive does not parse: {e}"))?;
    let mut out = Vec::with_capacity(r.len());
    for i in 0..r.len() {
        let e = r
            .by_index(i)
            .map_err(|e| format!("the zip archive has no entry {i}: {e}"))?;
        out.push(e.compression());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members() -> Vec<(String, Vec<u8>)> {
        vec![
            (
                "movie.bin".to_string(),
                (0u8..=255).cycle().take(9000).collect(),
            ),
            ("sample/s.bin".to_string(), vec![7u8; 3000]),
        ]
    }

    /// The stored arm writes an archive that reads back with the same
    /// names, the same order and the same bytes - the tree entry
    /// included, under its relative path and with no directory entry
    /// invented beside it.
    #[test]
    fn a_stored_archive_round_trips() {
        let m = members();
        let bytes = write_archive(&m, false).expect("the writer builds a stored archive");
        assert!(bytes.starts_with(b"PK\x03\x04"));
        assert_eq!(extract_set(&[bytes]).expect("it reads back"), m);
    }

    /// ...and so does the compressed one, whose whole point is that the
    /// reader had to inflate to say so.
    #[test]
    fn a_compressed_archive_round_trips_and_declares_deflate() {
        let m = members();
        let bytes = write_archive(&m, true).expect("the writer builds a compressed archive");
        assert_eq!(
            extract_set(std::slice::from_ref(&bytes)).expect("it reads back"),
            m
        );
        let methods = declared_methods(&bytes).expect("the archive parses");
        assert_eq!(methods.len(), m.len());
        assert!(
            !methods.contains(&STORED),
            "an entry declared Stored, so nothing would inflate: {methods:?}"
        );
    }

    /// The stored arm declares Stored on every entry, which is the
    /// control for the test above: without it, an assertion that
    /// "compressed is not Stored" would pass over a writer that never
    /// emitted Stored at all.
    #[test]
    fn the_stored_arm_declares_stored() {
        let bytes = write_archive(&members(), false).expect("the writer builds it");
        let methods = declared_methods(&bytes).expect("the archive parses");
        assert_eq!(methods, vec![STORED; members().len()]);
    }

    /// Deflate over INCOMPRESSIBLE bytes stays deflate and is bigger
    /// than its payload, which is the fact the module header rests on
    /// and the difference from the RAR writers.
    ///
    /// Written as a measurement rather than a comment: if a future bump
    /// made the zip writer fall back to Stored the way the RAR writers
    /// do, this is what says so.
    #[test]
    fn deflate_over_incompressible_bytes_still_declares_deflate() {
        // `[source]`'s own bytes, drawn from this crate's stream rather
        // than approximated, for the reason the 7z twin of this test
        // gives: a hand-made "noise" pattern is exactly the thing a
        // compressor is good at.
        let mut noise = vec![0u8; 40_000];
        crate::rng::Rng::from_seed(0x00C3_2190).fill(&mut noise);
        let m = vec![("noise.bin".to_string(), noise.clone())];
        let bytes = write_archive(&m, true).expect("the writer builds it");
        assert!(
            bytes.len() > noise.len(),
            "the payload compressed to {} bytes from {}, so it was not incompressible and \
             this test is measuring the wrong thing",
            bytes.len(),
            noise.len()
        );
        assert!(
            !declared_methods(&bytes)
                .expect("it parses")
                .contains(&STORED),
            "the writer stored what it could not shrink, which is the RAR behaviour this \
             module's header says zip does NOT have"
        );
        assert_eq!(extract_set(&[bytes]).expect("it reads back"), m);
    }

    /// Two runs over one input produce one archive, byte for byte.
    /// Nothing here may draw from a clock or from the OS entropy.
    #[test]
    fn writing_twice_is_byte_identical() {
        for compressed in [false, true] {
            let a = write_archive(&members(), compressed).unwrap();
            let b = write_archive(&members(), compressed).unwrap();
            assert_eq!(a, b, "compressed = {compressed}");
        }
    }

    /// The written timestamp is the format's 1980-01-01 epoch and not
    /// the clock, which is the property `writing_twice_is_byte_identical`
    /// would only catch if the two runs straddled a two-second DOS-time
    /// tick. Asserted at the source instead.
    #[test]
    fn every_entry_carries_the_1980_epoch() {
        let bytes = write_archive(&members(), false).unwrap();
        let mut r = ZipArchive::new(Cursor::new(bytes)).unwrap();
        for i in 0..r.len() {
            let e = r.by_index(i).unwrap();
            assert_eq!(
                e.last_modified(),
                Some(DateTime::DEFAULT),
                "entry {i} carries a timestamp that is not the pinned epoch"
            );
        }
    }

    /// A byte-split set is the archive's own bytes cut up, so
    /// concatenating the parts gives the archive back and the set
    /// extracts - which is exactly how `nzbkit::zip::Parts` reads one.
    #[test]
    fn a_byte_split_set_is_the_archive_cut_and_reads_back_joined() {
        let m = members();
        let whole = write_archive(&m, false).unwrap();
        let parts = crate::sevenz::split_parts(&whole, 4096);
        assert!(parts.len() >= 3, "got {} parts", parts.len());
        assert_eq!(parts.concat(), whole);
        // Only part one carries the local-header signature, and the
        // central directory is at the END rather than the start - which
        // is why an opaquely-named split zip is unrecoverable and
        // `container.rs` refuses one.
        assert!(parts[0].starts_with(b"PK\x03\x04"));
        assert!(!parts[1].starts_with(b"PK\x03\x04"));
        assert_eq!(extract_set(&parts).expect("the set reads back"), m);
    }
}
