//! The ONE place this crate's tests reach the RAR engine's WRITER.
//!
//! Every function here is named for the archive SHAPE it builds - a
//! stored archive, a compressed volume set, a set carrying a recovery
//! record, a RAR 4 classic set - and never for the engine call that
//! builds it. That is the whole point of the module: the RAR engine is
//! being replaced (cutover plan
//! `research/RARKIT-CUTOVER-PLAN-2026-09-18.md`, preparation item P3),
//! the replacement's writer has a different surface, and a test that
//! says "I want a compressed multivolume set with a 20% record" does
//! not care which library makes one. When the swap happens only the
//! BODIES below move; no test site does.
//!
//! The counterpart modules are `nzbkit::extract::testutil` (which owns
//! the same shapes for the one-pass path), `crates/nzbfast/tests/rarfixtures`
//! for the bin crate's three test binaries, and
//! `postfast::container::rarfixtures`. They are deliberate DUPLICATES
//! rather than one shared crate: a dev-dependency edge between these
//! crates would move the workspace's feature resolution for the engine,
//! which is the trap CLAUDE.md's `rars` line describes, and P3 is meant
//! to cost nothing at all today.
//!
//! # The two header conventions, and why both survive
//!
//! Call sites here stamp one of exactly two (host, attributes) pairs on
//! a member, and the choice changes the archive's BYTES. Fixtures that
//! predate this module were written with whichever the author reached
//! for, several tests hash or size-compare what comes out, and P3 is a
//! move and not a re-cut - so [`Member::unix`] and [`Member::bare`]
//! keep both rather than picking a winner. Do not "tidy" a site from
//! one to the other.

use rars::rar50::{
    CompressedEntry, Rar50VolumeWriter, Rar50Writer, StoredEntry, WriterOptions as Rar50Options,
};

/// One member of a fixture archive: a name, its bytes, and which of the
/// two header conventions the module documents to stamp on it.
#[derive(Clone, Copy)]
pub(crate) struct Member<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) data: &'a [u8],
    unix_host: bool,
}

impl<'a> Member<'a> {
    /// Unix host (`host_os = 1`) with the mode in the attribute field
    /// (`0o100644`) - what a real `rar` run on this box writes, and what
    /// every fixture that is later handed to an EXTERNAL unrar uses.
    pub(crate) fn unix(name: &'a [u8], data: &'a [u8]) -> Self {
        Self {
            name,
            data,
            unix_host: true,
        }
    }

    /// Host 0, attributes 0 - the minimal header. Used by every fixture
    /// whose verdict is about the pipeline's own handling rather than
    /// about a file's mode surviving extraction.
    pub(crate) fn bare(name: &'a [u8], data: &'a [u8]) -> Self {
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
/// `Some(n)` is `rar a -rrNp`; `None` is an archive with no record at
/// all, which several legs here need as their control.
pub(crate) type Recovery = Option<u64>;

// ---------------------------------------------------------------------------
// Single archives
// ---------------------------------------------------------------------------

/// One STORE-mode RAR 5 archive holding `members`, built with the
/// feature set that offers nothing but storing - no encryption, no
/// recovery record, no solid chain.
///
/// The whole-file CRC rides the member header here, so a test may damage
/// these bytes and trust that an extraction of them refuses. (That is
/// NOT true of every fixture in this repo - see the warning on
/// `nzbkit::rar::fixtures::rar5_volume_n`.)
pub(crate) fn stored_archive(members: &[Member<'_>]) -> Vec<u8> {
    let entries: Vec<StoredEntry<'_>> = members.iter().map(Member::stored).collect();
    Rar50Writer::new(Rar50Options::new(
        rars::ArchiveVersion::Rar50,
        rars::FeatureSet::store_only(),
    ))
    .stored_entries(&entries)
    .finish()
    .expect("the store-only writer builds an archive")
}

/// One COMPRESSED RAR 5 archive holding `members` - a real LZ bitstream
/// with valid checksums, not a header shell.
///
/// The writer falls back to storing a member it cannot shrink, so a test
/// whose subject is the compressed path must keep its payload
/// compressible and say so.
pub(crate) fn compressed_archive(members: &[Member<'_>]) -> Vec<u8> {
    compressed_archive_with_recovery(members, None)
}

/// [`compressed_archive`] carrying a recovery record of `recovery`
/// percent, the shape `rar a -rrNp` writes and the repair ladder's
/// recovery-record rung exists for.
pub(crate) fn compressed_archive_with_recovery(
    members: &[Member<'_>],
    recovery: Recovery,
) -> Vec<u8> {
    let entries: Vec<CompressedEntry<'_>> = members.iter().map(Member::compressed).collect();
    Rar50Writer::new(Rar50Options::default())
        .compressed_entries(&entries)
        .recovery_percent(recovery)
        .finish()
        .expect("the compressed writer builds an archive")
}

// ---------------------------------------------------------------------------
// Volume sets
// ---------------------------------------------------------------------------

/// A STORE-mode RAR 5 multivolume set over `members`, each volume
/// capped at `per_volume` payload bytes, returned in set order.
///
/// A member longer than the cap is SPLIT across the boundary; a set
/// whose members each fit ends a volume on a whole member instead, which
/// is a different shape and one several tests here select on purpose by
/// choosing their sizes. The volume-number field is stamped on every
/// volume including the first, where the RAR 5 specification makes it
/// optional - `unpack::obfuscated` documents why that matters.
pub(crate) fn stored_volume_set(members: &[Member<'_>], per_volume: usize) -> Vec<Vec<u8>> {
    stored_volume_set_with_recovery(members, per_volume, None)
}

/// [`stored_volume_set`] with a recovery record of `recovery` percent in
/// EVERY volume.
pub(crate) fn stored_volume_set_with_recovery(
    members: &[Member<'_>],
    per_volume: usize,
    recovery: Recovery,
) -> Vec<Vec<u8>> {
    let entries: Vec<StoredEntry<'_>> = members.iter().map(Member::stored).collect();
    Rar50VolumeWriter::new(Rar50Options::default())
        .stored_entries(&entries)
        .max_payload_per_volume(per_volume)
        .recovery_percent(recovery)
        .finish()
        .expect("the stored volume writer builds the set")
}

/// A COMPRESSED RAR 5 multivolume set over `members`, each volume capped
/// at `per_volume` payload bytes, returned in set order.
pub(crate) fn compressed_volume_set(members: &[Member<'_>], per_volume: usize) -> Vec<Vec<u8>> {
    compressed_volume_set_with_recovery(members, per_volume, None)
}

/// [`compressed_volume_set`] with a recovery record of `recovery`
/// percent in EVERY volume - the fixture the hinted recovery-record scan
/// runs against.
pub(crate) fn compressed_volume_set_with_recovery(
    members: &[Member<'_>],
    per_volume: usize,
    recovery: Recovery,
) -> Vec<Vec<u8>> {
    let entries: Vec<CompressedEntry<'_>> = members.iter().map(Member::compressed).collect();
    Rar50VolumeWriter::new(Rar50Options::default())
        .compressed_entries(&entries)
        .max_payload_per_volume(per_volume)
        .recovery_percent(recovery)
        .finish()
        .expect("the compressed volume writer builds the set")
}

// ---------------------------------------------------------------------------
// RAR 4 (the classic generation)
// ---------------------------------------------------------------------------

/// A STORE-mode RAR 4 multivolume set over one member, `per_volume`
/// packed bytes each, under the DEFAULT writer options - which is
/// classic `.rar`/`.rNN` numbering rather than `.partNN.rar`.
///
/// Header convention here is host 0 / attributes 0, not the `0x20` DOS
/// pair the compressed RAR 4 builder below uses: these two shapes have
/// always been written that way and several tests compare their bytes,
/// so the difference is preserved rather than unified.
pub(crate) fn rar4_stored_volume_set(name: &[u8], data: &[u8], per_volume: usize) -> Vec<Vec<u8>> {
    rars::rar15_40::write_stored_volumes(
        rars::rar15_40::StoredEntry {
            name,
            data,
            file_time: 0,
            file_attr: 0,
            host_os: 0,
            password: None,
            file_comment: None,
        },
        rars::rar15_40::WriterOptions::default(),
        per_volume,
    )
    .expect("the RAR 4 stored volume writer builds the set")
}

/// A COMPRESSED RAR 4 (2.9/3.x) archive over `members` - a real LZ
/// bitstream with valid checksums. DOS host (`host_os = 3`) with the
/// archive attribute (`0x20`), which is what a real `rar` for Windows
/// writes and what the sibling builder in `nzbkit::extract::testutil`
/// uses.
///
/// The writer falls back to storing what it cannot shrink, so a test
/// whose subject is the compressed layer must assert the fallback did
/// not happen.
pub(crate) fn rar4_compressed_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    let entries: Vec<rars::rar15_40::FileEntry<'_>> = members
        .iter()
        .map(|&(name, data)| rars::rar15_40::FileEntry {
            name: name.as_bytes(),
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        })
        .collect();
    rars::rar15_40::write_compressed_archive(
        &entries,
        rars::rar15_40::WriterOptions::new(
            rars::ArchiveVersion::Rar29,
            rars::FeatureSet::store_only(),
        ),
    )
    .expect("the RAR 4 compressed writer builds an archive")
}

// ---------------------------------------------------------------------------
// `.rev` parity
// ---------------------------------------------------------------------------

/// The parity rows a `.rev` recovery set carries over `shards`, which
/// must already be equal-length and even-length (the RAR 5 rev format
/// pads both ways).
///
/// This is the one engine call here that is not a writer: a `.rev`
/// volume's HEADER is hand-built by its caller, and only the parity
/// block underneath it comes from the engine's Reed-Solomon encoder.
pub(crate) fn rev_parity_rows(shards: &[&[u8]], recovery_count: usize) -> Vec<Vec<u8>> {
    rars::recovery::rar5::encode_parity_shards(shards, recovery_count)
        .expect("the rev parity encoder accepts equal-length shards")
}
