//! The ONE place this crate's test binaries reach the RAR engine's
//! WRITER.
//!
//! A sibling module the way `payloads/`, `harness/` and `scratch/` are,
//! and for the same reason those exist: the shapes below were written
//! out longhand in six suites across the `e2e`, `daemon` and
//! `leak_soak` binaries, every copy spelling the engine's entry types
//! by hand.
//!
//! Every function here is named for the archive SHAPE it builds - a
//! stored archive, a compressed volume set, a set carrying a recovery
//! record, an encrypted set - and never for the engine call that builds
//! it. That is the point: the RAR engine is being replaced (cutover
//! plan `research/RARKIT-CUTOVER-PLAN-2026-09-18.md`, preparation item
//! P3), the replacement's writer has a different surface, and a test
//! that says "I want a compressed multivolume set with a 20% record"
//! does not care which library makes one. When the swap happens only
//! the BODIES below move; no test site does.
//!
//! The counterpart modules are `nzbkit::extract::testutil`,
//! `nzbfast_unpack::rarfixtures` and `postfast::container::rarfixtures`.
//! They are deliberate DUPLICATES rather than one shared crate: a
//! dev-dependency edge between these crates would move the workspace's
//! feature resolution for the engine, which is the trap CLAUDE.md's
//! `rars` line describes, and P3 is meant to cost nothing at all today.
//!
//! # The two header conventions, and why both survive
//!
//! Call sites stamp one of exactly two (host, attributes) pairs on a
//! member, and the choice changes the archive's BYTES. Fixtures that
//! predate this module were written with whichever the author reached
//! for, so [`Member::unix`] and [`Member::bare`] keep both rather than
//! picking a winner. Do not "tidy" a site from one to the other.
//!
//! # What was collapsed, and on what evidence
//!
//! Sites here built the same shape through three different option
//! spellings: `WriterOptions::default()`, `WriterOptions::new(Rar50,
//! FeatureSet::store_only())`, and `store_only()` with
//! `recovery_record` set by hand. All three were measured to emit
//! BYTE-IDENTICAL archives for the stored, compressed and
//! compressed-with-record shapes (19 Sep 2026, against the payloads
//! these fixtures use), so this module carries one builder per shape
//! rather than three. A feature flag that ever starts moving a byte
//! will report as a changed fixture in the suites below, not silently.
// Not #[expect]: this file is compiled into three test BINARIES and
// `e2e` reaches every builder below (its children do the rest), where
// `daemon` reaches two and `leak_soak` one - so there is no lint state
// true of all three, and an expectation would go unfulfilled in `e2e`
// and redden that build. Its sibling `harness/mod.rs` CAN use #[expect]
// because each of its six binaries leaves at least one item unused;
// measured here on 19 Sep 2026 and this module cannot.
#![allow(dead_code)]

use rars::rar50::{
    CompressedEntry, EncryptedCompressedEntry, Rar50VolumeWriter, Rar50Writer, StoredEntry,
    WriterOptions,
};

/// One member of a fixture archive: a name, its bytes, and which of the
/// two header conventions the module documents to stamp on it.
#[derive(Clone, Copy)]
pub struct Member<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    unix_host: bool,
}

impl<'a> Member<'a> {
    /// Unix host (`host_os = 1`) with the mode in the attribute field
    /// (`0o100644`) - what a real `rar` run on this box writes.
    pub fn unix(name: &'a [u8], data: &'a [u8]) -> Self {
        Self {
            name,
            data,
            unix_host: true,
        }
    }

    /// Host 0, attributes 0 - the minimal header, used by every fixture
    /// whose verdict is about the pipeline rather than about a file mode
    /// surviving extraction.
    pub fn bare(name: &'a [u8], data: &'a [u8]) -> Self {
        Self {
            name,
            data,
            unix_host: false,
        }
    }

    fn attributes(&self) -> u64 {
        if self.unix_host { 0o100644 } else { 0 }
    }

    fn host_os(&self) -> u64 {
        u64::from(self.unix_host)
    }

    fn stored(&self) -> StoredEntry<'a> {
        StoredEntry {
            name: self.name,
            data: self.data,
            mtime: None,
            attributes: self.attributes(),
            host_os: self.host_os(),
        }
    }

    fn compressed(&self) -> CompressedEntry<'a> {
        CompressedEntry {
            name: self.name,
            data: self.data,
            mtime: None,
            attributes: self.attributes(),
            host_os: self.host_os(),
        }
    }
}

/// A recovery record's size as a percentage of the archive, or none.
pub type Recovery = Option<u64>;

/// The encoder's SEARCH EFFORT, or the writer's own default.
///
/// `Some(1)` is several times cheaper than the default in a debug
/// build and nothing a DECODER reads differs between them - the
/// measurement, and the one suite where the packed size is asserted on
/// and so must not move, are written up at
/// `nzbkit::extract::testutil::compressed_volume_set_at_effort`. Legs
/// whose whole wall is the fixture pass `Some(1)`.
pub type Effort = Option<u8>;

// ---------------------------------------------------------------------------
// Single archives
// ---------------------------------------------------------------------------

/// One STORE-mode RAR 5 archive holding `members`. The whole-file CRC
/// rides the member header, so a test may damage these bytes and trust
/// that an extraction of them refuses.
pub fn stored_archive(members: &[Member<'_>]) -> Vec<u8> {
    let entries: Vec<StoredEntry<'_>> = members.iter().map(Member::stored).collect();
    Rar50Writer::new(WriterOptions::default())
        .stored_entries(&entries)
        .finish()
        .expect("the stored writer builds an archive")
}

/// One COMPRESSED RAR 5 archive holding `members` - a real LZ bitstream
/// with valid checksums.
///
/// The writer falls back to STORING a member it cannot shrink, so a
/// test whose subject is the compressed path must keep its payload
/// compressible and assert that the fallback did not happen.
pub fn compressed_archive(members: &[Member<'_>]) -> Vec<u8> {
    compressed_archive_with_recovery(members, None)
}

/// [`compressed_archive`] carrying a recovery record of `recovery`
/// percent - the shape `rar a -rrNp` writes.
pub fn compressed_archive_with_recovery(members: &[Member<'_>], recovery: Recovery) -> Vec<u8> {
    let entries: Vec<CompressedEntry<'_>> = members.iter().map(Member::compressed).collect();
    Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&entries)
        .recovery_percent(recovery)
        .finish()
        .expect("the compressed writer builds an archive")
}

// ---------------------------------------------------------------------------
// Volume sets
// ---------------------------------------------------------------------------

/// A COMPRESSED RAR 5 multivolume set over `members`, each volume
/// capped at `per_volume` payload bytes, returned in set order.
pub fn compressed_volume_set(members: &[Member<'_>], per_volume: usize) -> Vec<Vec<u8>> {
    compressed_volume_set_full(members, per_volume, None, None)
}

/// [`compressed_volume_set`] at a named encoder effort - for the legs
/// whose whole wall clock is the fixture build. See [`Effort`].
pub fn compressed_volume_set_at_effort(
    members: &[Member<'_>],
    per_volume: usize,
    effort: Effort,
) -> Vec<Vec<u8>> {
    compressed_volume_set_full(members, per_volume, None, effort)
}

/// [`compressed_volume_set`] with a recovery record of `recovery`
/// percent in EVERY volume.
pub fn compressed_volume_set_with_recovery(
    members: &[Member<'_>],
    per_volume: usize,
    recovery: Recovery,
) -> Vec<Vec<u8>> {
    compressed_volume_set_full(members, per_volume, recovery, None)
}

fn compressed_volume_set_full(
    members: &[Member<'_>],
    per_volume: usize,
    recovery: Recovery,
    effort: Effort,
) -> Vec<Vec<u8>> {
    let entries: Vec<CompressedEntry<'_>> = members.iter().map(Member::compressed).collect();
    let mut options = WriterOptions::default();
    if let Some(level) = effort {
        options = options.with_compression_level(level);
    }
    Rar50VolumeWriter::new(options)
        .compressed_entries(&entries)
        .max_payload_per_volume(per_volume)
        .recovery_percent(recovery)
        .finish()
        .expect("the compressed volume writer builds the set")
}

/// An ENCRYPTED, compressed RAR 5 multivolume set: every member is both
/// deflated and AES-encrypted under `password`, and the headers stay in
/// the clear (`rar a -p`, not `-hp`).
///
/// The writer refuses a single-volume encrypted set, so `per_volume`
/// must be small enough against the payload to produce at least two.
pub fn encrypted_compressed_volume_set(
    members: &[Member<'_>],
    per_volume: usize,
    password: &[u8],
) -> Vec<Vec<u8>> {
    let mut features = rars::FeatureSet::store_only();
    features.file_encryption = true;
    let entries: Vec<EncryptedCompressedEntry<'_>> = members
        .iter()
        .map(|m| EncryptedCompressedEntry {
            name: m.name,
            data: m.data,
            mtime: None,
            attributes: m.attributes(),
            host_os: m.host_os(),
            password,
        })
        .collect();
    Rar50VolumeWriter::new(WriterOptions::new(rars::ArchiveVersion::Rar50, features))
        .encrypted_compressed_entries(&entries)
        .max_payload_per_volume(per_volume)
        .finish()
        .expect("the encrypted volume writer builds the set")
}
