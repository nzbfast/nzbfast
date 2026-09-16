use super::*;
pub use crate::codec::rar50::Rar50FilterKind as FilterKind;
use crate::codec::rar50::{EncodeOptions, EncoderScratchPool};
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys};
use crate::recovery::rar5::build_structural_inline_recovery_data_with_progress;
use crate::write_entropy::{Entropy, EntropyScope};
use crate::write_progress::{ProgressReporter, WorkTracker};
use crate::{WriteOperation, WriteProgress, WriteProgressEvent};

mod filter_policy;
pub mod reference;
pub mod rev;
pub mod stream;
mod volume;
#[cfg(test)]
use filter_policy::encode_member_with_filter_policy;
#[cfg(test)]
use filter_policy::encode_with_solid_reset_policy;
use filter_policy::{
    compression_info, compression_method_for_level, dictionary_size_for_options,
    dictionary_size_for_payload, encode_member_with_filter_policy_candidates_and_progress,
    encode_member_with_filter_specs_candidates_and_progress, encode_option_candidates_for_level,
    encode_options_for_level, filter_policy_attempt_count, rar50_algorithm_version,
    sampled_incompressible, should_store_compressed_payload, validate_compression_level,
    working_memory_for,
};
use reference::SERVICE_HOST_OS;
use volume::{
    write_compressed_volume_set_impl, write_encrypted_compressed_volume_set_impl,
    write_encrypted_stored_volume_set_impl, write_encrypted_stored_volumes_impl,
    write_stored_volume_set_impl, write_stored_volumes_impl,
};

const MAX_MATCH_CANDIDATES_DEFAULT: usize = 256;
/// The dictionary a compressed RAR 5 member is written with when the
/// caller names none. **2 MiB since 8 Sep 2026**, decided on the level
/// ladder measured the day before; it was 128 KiB (the format's floor)
/// until 7 Sep 2026 and 32 MiB briefly after that. What the archive
/// DECLARES is then fitted to the payload the way rar fits it
/// (`fitted_dictionary_size`), so a small post asks a small window of
/// every extractor; that reduction is orthogonal to this number and is
/// kept.
///
/// Why 2 MiB and not 32: the ladder priced each rung on an idle box, on
/// the 1 GiB mixed payload. 128 KiB to 2 MiB is -6.3% of bytes for 1.8x
/// the encode CPU and 1.7x the wall. The NEXT step, 2 MiB to 4 MiB, is a
/// further -4.0% for 3.2x the CPU and 10.6x the WALL, and the only thing
/// that changes there is that the tree match finder arms (it arms at
/// 4 MiB). At 32 MiB the same member is 111 s of wall against 5.65 s at
/// 2 MiB. The payload fit does not rescue that case: it only ever
/// reduces, so a member LARGER than the default - which a RAR volume of
/// a real post usually is - still pays the full search. On members
/// smaller than 2 MiB the fit makes the two numbers behave alike, which
/// is why the 400-file shape measured the same bytes and CPU at 2, 4 and
/// 32 MiB.
///
/// 32 MiB is the better RATIO (-19.9% more on that payload) and remains
/// the intended destination once the search is cheaper; it is not the
/// default today for the wall-clock reason above, not for a format or
/// compatibility one - RAR 5.0 and later read to 4 GB.
const DEFAULT_RAR50_DICTIONARY_SIZE: u64 = 2 * 1024 * 1024;
/// The RAR 5.0 dictionary's floor and quantum: a v0 dictionary is a
/// power-of-two multiple of this.
const RAR50_DICTIONARY_QUANTUM: u64 = 128 * 1024;

/// What `fitted_dictionary_size` fits to: the largest member of a
/// non-solid set, the whole set of a solid one (its window spans them).
fn largest_payload(sizes: impl Iterator<Item = u64>, solid: bool) -> u64 {
    if solid {
        sizes.fold(0u64, u64::saturating_add)
    } else {
        sizes.max().unwrap_or(0)
    }
}
const AUTO_DELTA_EDGE_SKIP: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriterOptions {
    pub target: crate::ArchiveVersion,
    pub features: crate::FeatureSet,
    pub compression_level: Option<u8>,
    pub dictionary_size: Option<u64>,
    /// Where the encryption salt and the initialisation vectors come
    /// from. [`Entropy::Os`] by default; see [`Entropy::Seeded`] before
    /// changing it.
    pub entropy: Entropy,
    /// Which checksum every file header carries for its payload.
    /// [`HashRecord::Crc32Only`] by default, which is what `rar` writes
    /// unless asked for `-htb`; see [`HashRecord`].
    pub hash_record: HashRecord,
    /// Parse by least total estimated bits rather than greedily with a
    /// lazy re-probe: the level above the default parser, smaller and
    /// dearer. See [`EncodeOptions::optimal_parse`]. (nzbfast-local
    /// change, 7 Sep 2026; see VENDORING.md.)
    pub optimal_parse: bool,
    /// Whether the compressed members cut their entropy blocks where the
    /// exact encoded cost says to (`codec::rar50::boundaries`) rather than
    /// every 256 KiB of input. `true` by default - measured -0.76% on the
    /// mixed corpus and -1.1 to -1.3% on member sets, for a few percent of
    /// encode CPU. A caller that needs the older byte layout, or is
    /// measuring against it, sets it `false`.
    /// (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
    pub adaptive_entropy_blocks: bool,
    /// Memory allowance for this writer, or `None` for the host-sized
    /// defaults. Bounds the encoder's block wave and parse hints, and
    /// REDUCES [`Self::dictionary_size`] to what the allowance can index.
    /// See [`crate::Rar50WritePolicy`] for why the writer needs one at all.
    /// (nzbfast-local change, 8 Sep 2026; see VENDORING.md.)
    pub write_policy: Option<crate::Rar50WritePolicy>,
    /// Price every 4 MiB region of a compressed member both as one
    /// tokenizer block and as 1 MiB tokenizer blocks, and keep whichever
    /// encoded smaller. `false` by default: it encodes every region
    /// twice, and it is a maximum-ratio LEVEL rather than a constant, the
    /// way `optimal_parse` is. It cannot cost a byte on any shape,
    /// because the arm it is measured against is always a candidate.
    /// Measured on the first 256 MiB of the mixed corpus at a 32 MiB
    /// dictionary with `optimal_parse`: 112,865,011 -> 111,617,844 bytes
    /// (-1.11%), for 33% more encode CPU and 22% more wall on an idle
    /// 20-core box; on a set of members under a region it is -1.15% for
    /// twice the wall, because there the parallel unit is the member and
    /// there is no other region to overlap the second encode with. See
    /// [`EncodeOptions::tokenizer_horizon_choice`] for the solid members
    /// it does not reach.
    /// (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
    pub tokenizer_horizon_choice: bool,
    /// Whether level 5 ALSO encodes each compressed member at levels 4
    /// down to 1 and keeps whichever came out smallest. `true` by default,
    /// which is what level 5 has always meant in this writer. Measured
    /// 14 Sep 2026 on rarbench's 256 MiB text at a 32 MiB dictionary it
    /// bought 66 bytes (625,354 against 625,420) for 151 s against 22 s,
    /// so `rarfast -m5` turns it off. Off, level 5 is one encode at its own
    /// settings, and the streamed writers accept it.
    /// (nzbfast-local change, 14 Sep 2026; see VENDORING.md.)
    pub level_five_fallbacks: bool,
}

/// The checksum a file header carries for its payload.
///
/// Every RAR 5 file header has a CRC32 of the unpacked data. A header can
/// ALSO carry a BLAKE2sp digest of the same data in an extra "hash
/// record", which `rar` writes only when asked (`-htb`), and which a reader
/// that finds it verifies INSTEAD of the CRC32. Until 5 Sep 2026 this
/// writer put the record on every header: on a stored member the digest
/// was 85% of the creation cost (one thread at 2.4 GB/s on the 8-lane
/// kernel, and it cannot be split across threads - the eight leaf chains
/// are already the lanes), and every reader of the archive pays the same
/// hash over every extracted byte, where CRC32 is hardware and near free.
/// Nothing in the Usenet pipeline relies on the record: transmission
/// damage is caught by the yEnc and article checks and repaired by PAR2,
/// and CRC32 is the header's own last line. So the default is what `rar`
/// writes, and BLAKE2sp is there for the caller that wants the `-htb`
/// shape. Encrypted members follow the same choice: their MAC covers the
/// CRC32 always and the BLAKE2sp only when the record is on.
/// (nzbfast-local change, 5 Sep 2026; see VENDORING.md.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashRecord {
    /// CRC32 in the file header only - `rar`'s default.
    #[default]
    Crc32Only,
    /// CRC32 plus a BLAKE2sp hash record - `rar -htb`.
    Blake2sp,
}

impl WriterOptions {
    pub const fn new(target: crate::ArchiveVersion, features: crate::FeatureSet) -> Self {
        Self {
            target,
            features,
            compression_level: None,
            dictionary_size: None,
            entropy: Entropy::Os,
            hash_record: HashRecord::Crc32Only,
            optimal_parse: false,
            adaptive_entropy_blocks: true,
            write_policy: None,
            tokenizer_horizon_choice: false,
            level_five_fallbacks: true,
        }
    }

    /// Chooses which payload checksum the file headers carry; see
    /// [`HashRecord`].
    pub const fn with_hash_record(mut self, hash_record: HashRecord) -> Self {
        self.hash_record = hash_record;
        self
    }

    /// Whether level 5 also tries every lower level; see
    /// [`Self::level_five_fallbacks`].
    pub const fn with_level_five_fallbacks(mut self, enabled: bool) -> Self {
        self.level_five_fallbacks = enabled;
        self
    }

    /// Chooses where the writer draws its encryption salt and
    /// initialisation vectors.
    ///
    /// Leave it alone for a real archive. [`Entropy::Seeded`] is for
    /// reproducible test generation and weakens what it feeds.
    pub const fn with_entropy(mut self, entropy: Entropy) -> Self {
        self.entropy = entropy;
        self
    }

    pub const fn with_compression_level(mut self, level: u8) -> Self {
        self.compression_level = Some(level);
        self
    }

    pub const fn with_dictionary_size(mut self, size: u64) -> Self {
        self.dictionary_size = Some(size);
        self
    }

    /// Turns on the cost-based parse; see [`WriterOptions::optimal_parse`].
    pub const fn with_optimal_parse(mut self, enabled: bool) -> Self {
        self.optimal_parse = enabled;
        self
    }

    /// Chooses how the compressed members cut their entropy blocks; see
    /// [`WriterOptions::adaptive_entropy_blocks`].
    pub const fn with_adaptive_entropy_blocks(mut self, enabled: bool) -> Self {
        self.adaptive_entropy_blocks = enabled;
        self
    }

    /// Turns on the per-region tokenizer horizon choice; see
    /// [`WriterOptions::tokenizer_horizon_choice`].
    /// Bounds this writer's working memory and the dictionary it will
    /// index; see [`crate::Rar50WritePolicy`]. `None` (the default) keeps
    /// the host-sized allowances.
    /// (nzbfast-local change, 8 Sep 2026; see VENDORING.md.)
    pub const fn with_write_policy(mut self, policy: Option<crate::Rar50WritePolicy>) -> Self {
        self.write_policy = policy;
        self
    }

    pub const fn with_tokenizer_horizon_choice(mut self, enabled: bool) -> Self {
        self.tokenizer_horizon_choice = enabled;
        self
    }
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: crate::ArchiveVersion::Rar50,
            features: crate::FeatureSet::store_only(),
            compression_level: None,
            dictionary_size: None,
            entropy: Entropy::Os,
            hash_record: HashRecord::Crc32Only,
            optimal_parse: false,
            adaptive_entropy_blocks: true,
            write_policy: None,
            tokenizer_horizon_choice: false,
            level_five_fallbacks: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredServiceEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntryWithServices<'a> {
    pub entry: StoredEntry<'a>,
    pub services: &'a [StoredServiceEntry<'a>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedStoredServiceEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedStoredEntryWithServices<'a> {
    pub entry: EncryptedStoredEntry<'a>,
    pub services: &'a [EncryptedStoredServiceEntry<'a>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveMetadataEntry<'a> {
    pub name: Option<&'a [u8]>,
    pub creation_time: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedStoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedCompressedEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedArchiveCommentEntry<'a> {
    pub data: &'a [u8],
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilterPolicy {
    None,
    AutoSize,
    Explicit(FilterKind),
    /// Sample-guided regional filters: every 262,143-byte region of a
    /// member votes for a filter kind (or none) on three cheap 16 KiB
    /// probes, and one encode carries the winners as ranged specs. A member
    /// no region votes for is resolved exactly as `None`. Compressed,
    /// non-solid members only, as the other filtering policies are.
    /// (nzbfast-local change, 7 Sep 2026; see VENDORING.md and
    /// `filter_policy::select_sampled_filters`.)
    Sampled,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rar50Writer<'a> {
    options: WriterOptions,
    members: Vec<Rar50WriteMember<'a>>,
    archive_comment: Option<ArchiveComment<'a>>,
    archive_metadata: Option<ArchiveMetadataEntry<'a>>,
    filter_policy: FilterPolicy,
    recovery_percent: Option<u64>,
    recovery_password: Option<&'a [u8]>,
    progress: Option<ProgressReporter<'a>>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rar50VolumeWriter<'a> {
    options: WriterOptions,
    entries: Option<Rar50VolumeEntries<'a>>,
    max_payload_per_volume: Option<usize>,
    recovery_percent: Option<u64>,
    filter_policy: FilterPolicy,
    progress: Option<ProgressReporter<'a>>,
}

#[derive(Debug, Clone)]
enum Rar50VolumeEntries<'a> {
    Stored(StoredEntry<'a>),
    StoredSet(&'a [StoredEntry<'a>]),
    Compressed(&'a [CompressedEntry<'a>]),
    EncryptedStored(EncryptedStoredEntry<'a>),
    EncryptedStoredSet(&'a [EncryptedStoredEntry<'a>]),
    EncryptedCompressed(&'a [EncryptedCompressedEntry<'a>]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveComment<'a> {
    Plain(&'a [u8]),
    Encrypted(EncryptedArchiveCommentEntry<'a>),
}

impl<'a> ArchiveComment<'a> {
    fn encrypted(self) -> Option<EncryptedArchiveCommentEntry<'a>> {
        match self {
            Self::Plain(_) => None,
            Self::Encrypted(comment) => Some(comment),
        }
    }

    fn password(self) -> Option<&'a [u8]> {
        self.encrypted().map(|comment| comment.password)
    }

    fn plain_only(self) -> Option<Self> {
        matches!(self, Self::Plain(_)).then_some(self)
    }

    fn encrypted_only(self) -> Option<Self> {
        matches!(self, Self::Encrypted(_)).then_some(self)
    }
}

impl<'a> Rar50VolumeWriter<'a> {
    pub fn new(options: WriterOptions) -> Self {
        Self {
            options,
            entries: None,
            max_payload_per_volume: None,
            recovery_percent: None,
            filter_policy: FilterPolicy::None,
            progress: None,
        }
    }

    pub fn stored_entry(mut self, entry: StoredEntry<'a>) -> Self {
        self.entries = Some(Rar50VolumeEntries::Stored(entry));
        self
    }

    /// A split STORED set holding SEVERAL members.
    ///
    /// [`Self::stored_entry`] splits ONE member across the volumes,
    /// which is the shape a single big file makes. This arm takes a
    /// slice the way [`Self::compressed_entries`] already does, so a
    /// set can carry several files with only the member that lands on
    /// a volume boundary actually split - the commonest layout a
    /// poster puts on the wire, and the one nothing here could emit
    /// before (nzbfast-local change, 4 Sep 2026; see
    /// vendor/rars/VENDORING.md).
    pub fn stored_entries(mut self, entries: &'a [StoredEntry<'a>]) -> Self {
        self.entries = Some(Rar50VolumeEntries::StoredSet(entries));
        self
    }

    pub fn compressed_entries(mut self, entries: &'a [CompressedEntry<'a>]) -> Self {
        self.entries = Some(Rar50VolumeEntries::Compressed(entries));
        self
    }

    pub fn encrypted_stored_entry(mut self, entry: EncryptedStoredEntry<'a>) -> Self {
        self.entries = Some(Rar50VolumeEntries::EncryptedStored(entry));
        self
    }

    /// A split ENCRYPTED STORED set holding SEVERAL members.
    ///
    /// [`Self::encrypted_stored_entry`] splits ONE member across the
    /// volumes and was the only encrypted STORED volume arm, which is
    /// why an encrypted multi-member split set used to be emitable
    /// compressed and not stored - `::encrypted_compressed_entries` has
    /// always taken a slice. This is the missing plural (nzbfast-local
    /// change, 4 Sep 2026; see vendor/rars/VENDORING.md).
    pub fn encrypted_stored_entries(mut self, entries: &'a [EncryptedStoredEntry<'a>]) -> Self {
        self.entries = Some(Rar50VolumeEntries::EncryptedStoredSet(entries));
        self
    }

    pub fn encrypted_compressed_entries(
        mut self,
        entries: &'a [EncryptedCompressedEntry<'a>],
    ) -> Self {
        self.entries = Some(Rar50VolumeEntries::EncryptedCompressed(entries));
        self
    }

    pub fn max_payload_per_volume(mut self, size: usize) -> Self {
        self.max_payload_per_volume = Some(size);
        self
    }

    pub fn recovery_percent(mut self, percent: Option<u64>) -> Self {
        self.recovery_percent = percent;
        self
    }

    /// [`Rar50Writer::filter_policy`] for a volume set: `None` (the
    /// default) or `Sampled`, compressed entries, not solid. The other
    /// policies are refused here. (nzbfast-local change, 7 Sep 2026; see
    /// VENDORING.md.)
    pub fn filter_policy(mut self, policy: FilterPolicy) -> Self {
        self.filter_policy = policy;
        self
    }

    pub fn progress(mut self, progress: &'a dyn WriteProgress) -> Self {
        self.progress = Some(ProgressReporter(progress));
        self
    }

    pub fn finish(self) -> Result<Vec<Vec<u8>>> {
        // Held for the whole archive: the salt and IV draws below read
        // it back off this thread. Never `let _ =`, which would drop it
        // here and put the writer back on OS entropy.
        let _entropy = EntropyScope::install(self.options.entropy);
        let max_payload_per_volume = self.max_payload_per_volume.ok_or(Error::InvalidHeader(
            "RAR 5 volume payload size is required",
        ))?;
        let entries = self.entries.ok_or(Error::InvalidHeader(
            "RAR 5 volume writer needs an entry set",
        ))?;
        let (compressed, total_bytes, total_entries) = match &entries {
            Rar50VolumeEntries::Compressed(entries) => (
                true,
                entries.iter().map(|entry| entry.data.len() as u64).sum(),
                entries.len(),
            ),
            Rar50VolumeEntries::EncryptedCompressed(entries) => (
                true,
                entries.iter().map(|entry| entry.data.len() as u64).sum(),
                entries.len(),
            ),
            Rar50VolumeEntries::Stored(entry) => (false, entry.data.len() as u64, 1),
            Rar50VolumeEntries::StoredSet(entries) => (
                false,
                entries.iter().map(|entry| entry.data.len() as u64).sum(),
                entries.len(),
            ),
            Rar50VolumeEntries::EncryptedStored(entry) => (false, entry.data.len() as u64, 1),
            Rar50VolumeEntries::EncryptedStoredSet(entries) => (
                false,
                entries.iter().map(|entry| entry.data.len() as u64).sum(),
                entries.len(),
            ),
        };
        let total_work = if compressed && self.options.features.solid {
            match &entries {
                Rar50VolumeEntries::Compressed(entries) => entries
                    .iter()
                    .enumerate()
                    .map(|(index, entry)| entry.data.len() as u64 * if index == 0 { 1 } else { 2 })
                    .sum(),
                Rar50VolumeEntries::EncryptedCompressed(entries) => entries
                    .iter()
                    .enumerate()
                    .map(|(index, entry)| entry.data.len() as u64 * if index == 0 { 1 } else { 2 })
                    .sum(),
                _ => total_bytes,
            }
        } else {
            total_bytes
        };
        if compressed {
            report_operation_started(
                self.progress,
                WriteOperation::Compression,
                total_work,
                total_entries,
                1,
            );
        }
        let work = WorkTracker::new(self.progress, WriteOperation::Compression, total_work);
        let result = match entries {
            Rar50VolumeEntries::Stored(entry) => write_stored_volumes_impl(
                entry,
                self.options,
                max_payload_per_volume,
                self.recovery_percent,
            ),
            Rar50VolumeEntries::StoredSet(entries) => write_stored_volume_set_impl(
                entries,
                self.options,
                max_payload_per_volume,
                self.recovery_percent,
            ),
            Rar50VolumeEntries::Compressed(entries) => write_compressed_volume_set_impl(
                entries,
                self.options,
                max_payload_per_volume,
                self.recovery_percent,
                self.filter_policy,
                (compressed && self.progress.is_some()).then_some(&work),
            ),
            Rar50VolumeEntries::EncryptedStored(entry) => write_encrypted_stored_volumes_impl(
                entry,
                self.options,
                max_payload_per_volume,
                self.recovery_percent,
            ),
            Rar50VolumeEntries::EncryptedStoredSet(entries) => {
                write_encrypted_stored_volume_set_impl(
                    entries,
                    self.options,
                    max_payload_per_volume,
                    self.recovery_percent,
                )
            }
            Rar50VolumeEntries::EncryptedCompressed(entries) => {
                write_encrypted_compressed_volume_set_impl(
                    entries,
                    self.options,
                    max_payload_per_volume,
                    self.recovery_percent,
                    self.filter_policy,
                    (compressed && self.progress.is_some()).then_some(&work),
                )
            }
        };
        if compressed {
            if result.is_ok() && !work.finish() {
                return Err(Error::Cancelled);
            }
            report_operation_finished(
                self.progress,
                WriteOperation::Compression,
                total_work,
                total_entries,
                1,
            );
        }
        result
    }
}

impl<'a> Rar50Writer<'a> {
    pub fn new(options: WriterOptions) -> Self {
        Self {
            options,
            members: Vec::new(),
            archive_comment: None,
            archive_metadata: None,
            filter_policy: FilterPolicy::None,
            recovery_percent: None,
            recovery_password: None,
            progress: None,
        }
    }

    pub fn stored_entries(mut self, entries: &[StoredEntry<'a>]) -> Self {
        self.members
            .extend(entries.iter().copied().map(Rar50WriteMember::Stored));
        self
    }

    pub fn compressed_entries(mut self, entries: &[CompressedEntry<'a>]) -> Self {
        self.members
            .extend(entries.iter().copied().map(Rar50WriteMember::Compressed));
        self
    }

    pub fn encrypted_stored_entries(mut self, entries: &[EncryptedStoredEntry<'a>]) -> Self {
        self.members.extend(
            entries
                .iter()
                .copied()
                .map(Rar50WriteMember::EncryptedStored),
        );
        self
    }

    pub fn stored_entries_with_services(mut self, entries: &[StoredEntryWithServices<'a>]) -> Self {
        self.members.extend(
            entries
                .iter()
                .copied()
                .map(Rar50WriteMember::StoredWithServices),
        );
        self
    }

    pub fn encrypted_compressed_entries(
        mut self,
        entries: &[EncryptedCompressedEntry<'a>],
    ) -> Self {
        self.members.extend(
            entries
                .iter()
                .copied()
                .map(Rar50WriteMember::EncryptedCompressed),
        );
        self
    }

    pub fn encrypted_stored_entries_with_services(
        mut self,
        entries: &[EncryptedStoredEntryWithServices<'a>],
    ) -> Self {
        self.members.extend(
            entries
                .iter()
                .copied()
                .map(Rar50WriteMember::EncryptedStoredWithServices),
        );
        self
    }

    pub fn archive_comment(mut self, comment: Option<&'a [u8]>) -> Self {
        self.archive_comment = comment.map(ArchiveComment::Plain);
        self
    }

    pub fn encrypted_archive_comment(
        mut self,
        comment: Option<EncryptedArchiveCommentEntry<'a>>,
    ) -> Self {
        self.archive_comment = comment.map(ArchiveComment::Encrypted);
        self
    }

    pub fn archive_metadata(mut self, metadata: Option<ArchiveMetadataEntry<'a>>) -> Self {
        self.archive_metadata = metadata;
        self
    }

    pub fn filter_policy(mut self, policy: FilterPolicy) -> Self {
        self.filter_policy = policy;
        self
    }

    pub fn recovery_percent(mut self, percent: Option<u64>) -> Self {
        self.recovery_percent = percent;
        self
    }

    pub fn recovery_password(mut self, password: Option<&'a [u8]>) -> Self {
        self.recovery_password = password;
        self
    }

    pub fn progress(mut self, progress: &'a dyn WriteProgress) -> Self {
        self.progress = Some(ProgressReporter(progress));
        self
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        // See the note on Rar50VolumeWriter::finish: this must outlive
        // every draw the archive makes.
        let _entropy = EntropyScope::install(self.options.entropy);
        let progress = self.progress;
        let compressed = self.members.first().is_some_and(|member| {
            matches!(
                member.kind(),
                Rar50WriteMemberKind::Compressed | Rar50WriteMemberKind::EncryptedCompressed
            )
        });
        let total_bytes = self.members.iter().map(Rar50WriteMember::input_size).sum();
        let total_entries = self.members.len();
        let total_work = if compressed {
            let mut candidates = encode_option_candidates_for_level(
                self.options.compression_level,
                dictionary_size_for_options(self.options)?,
                self.options.optimal_parse,
                self.options.adaptive_entropy_blocks,
                self.options.tokenizer_horizon_choice,
                working_memory_for(self.options),
            )?;
            if !self.options.level_five_fallbacks {
                candidates.truncate(1);
            }
            compression_work_total(
                &self.members,
                self.options.features.solid,
                self.filter_policy,
                candidates.len() as u64,
            )
        } else {
            total_bytes
        };
        if compressed {
            report_operation_started(
                progress,
                WriteOperation::Compression,
                total_work,
                total_entries,
                1,
            );
        }
        let work = WorkTracker::new(progress, WriteOperation::Compression, total_work);
        let resolved = self.resolve((compressed && progress.is_some()).then_some(&work));
        if compressed && resolved.is_ok() && !work.finish() {
            return Err(Error::Cancelled);
        }
        if compressed {
            report_operation_finished(
                progress,
                WriteOperation::Compression,
                total_work,
                total_entries,
                1,
            );
        }
        let plan = resolved?;
        emit_resolved_writer_plan_with_progress(plan, progress)
    }

    fn resolve(
        self,
        compression_progress: Option<&WorkTracker<'_>>,
    ) -> Result<ResolvedRar50WritePlan<'a>> {
        let total_entries = self.members.len();
        let member_kind = self.members.iter().try_fold(None, |seen, member| {
            let kind = member.kind();
            if seen.is_some_and(|seen| seen != kind) {
                return Err(Error::UnsupportedFeature {
                    version: self.options.target,
                    feature: "RAR 5 mixed stored/compressed writer plan",
                });
            }
            Ok(Some(kind))
        })?;
        if self.options.features.quick_open {
            validate_options(self.options)?;
        }
        if let Some(recovery_percent) = self.recovery_percent {
            validate_recovery_percent(recovery_percent)?;
            if self.options.features.quick_open
                || self.options.features.archive_comment
                || self.archive_comment.is_some()
            {
                return Err(Error::UnsupportedFeature {
                    version: self.options.target,
                    feature: "RAR 5 recovery writer option combination",
                });
            }
        }
        let algorithm_version = rar50_algorithm_version(self.options)?;
        let compression_method = compression_method_for_level(self.options.compression_level)?;
        let dictionary_size = dictionary_size_for_payload(
            self.options,
            largest_payload(
                self.members.iter().map(Rar50WriteMember::input_size),
                self.options.features.solid,
            ),
        )?;
        let encode_options = encode_options_for_level(
            self.options.compression_level,
            dictionary_size,
            self.options.optimal_parse,
            self.options.adaptive_entropy_blocks,
            self.options.tokenizer_horizon_choice,
            working_memory_for(self.options),
        )?;
        let mut encode_option_candidates = encode_option_candidates_for_level(
            self.options.compression_level,
            dictionary_size,
            self.options.optimal_parse,
            self.options.adaptive_entropy_blocks,
            self.options.tokenizer_horizon_choice,
            working_memory_for(self.options),
        )?;
        if !self.options.level_five_fallbacks {
            encode_option_candidates.truncate(1);
        }

        let mut resolved_members = Vec::with_capacity(self.members.len());
        match member_kind.unwrap_or(Rar50WriteMemberKind::Stored) {
            Rar50WriteMemberKind::Stored => {
                if self.filter_policy != FilterPolicy::None {
                    return Err(Error::UnsupportedFeature {
                        version: self.options.target,
                        feature: "RAR 5 stored writer filter policy",
                    });
                }
                if self.recovery_percent.is_some() {
                    validate_recovery_options(self.options)?;
                } else {
                    validate_options(self.options)?;
                }
                for member in self.members {
                    let entry = member.into_stored(self.options.target)?;
                    validate_entry(&entry)?;
                    resolved_members.push(ResolvedRar50WriteMember::Stored(entry));
                }
                Ok(ResolvedRar50WritePlan {
                    hash_record: self.options.hash_record,
                    main_flags: 0,
                    archive_comment: self.archive_comment.and_then(ArchiveComment::plain_only),
                    archive_metadata: self.archive_metadata,
                    quick_open: self.options.features.quick_open,
                    recovery_percent: self.recovery_percent,
                    header_keys: None,
                    members: resolved_members,
                })
            }
            Rar50WriteMemberKind::StoredWithServices => {
                if self.archive_comment.is_some()
                    || self.archive_metadata.is_some()
                    || self.recovery_percent.is_some()
                    || self.filter_policy != FilterPolicy::None
                {
                    return Err(Error::UnsupportedFeature {
                        version: self.options.target,
                        feature: "RAR 5 stored file-service writer option combination",
                    });
                }
                validate_file_service_options(self.options)?;
                for member in self.members {
                    let entry = member.into_stored_with_services(self.options.target)?;
                    validate_entry(&entry.entry)?;
                    for service in entry.services {
                        validate_file_service(service)?;
                    }
                    resolved_members.push(ResolvedRar50WriteMember::StoredWithServices(entry));
                }
                Ok(ResolvedRar50WritePlan {
                    hash_record: self.options.hash_record,
                    main_flags: 0,
                    archive_comment: None,
                    archive_metadata: None,
                    quick_open: false,
                    recovery_percent: None,
                    header_keys: None,
                    members: resolved_members,
                })
            }
            Rar50WriteMemberKind::Compressed => {
                if self.options.features.quick_open {
                    return Err(Error::UnsupportedFeature {
                        version: self.options.target,
                        feature: "RAR 5 compressed quick-open writer",
                    });
                }
                if self.recovery_percent.is_some() {
                    validate_compressed_recovery_options(self.options)?;
                } else {
                    validate_compressed_options(self.options)?;
                }
                if self.filter_policy != FilterPolicy::None && self.options.features.solid {
                    return Err(Error::UnsupportedFeature {
                        version: self.options.target,
                        feature: "RAR 5 solid filtered compressed writer",
                    });
                }
                if self.filter_policy != FilterPolicy::None
                    && (self.archive_comment.is_some() || self.archive_metadata.is_some())
                {
                    return Err(Error::UnsupportedFeature {
                        version: self.options.target,
                        feature: "RAR 5 filtered compressed writer service or metadata",
                    });
                }
                if self.options.features.solid {
                    // A solid set: every member's two arms on the pool, the
                    // walk only decides (`resolve_solid_members`); it used
                    // to encode both arms of every member on one thread.
                    let entries = self
                        .members
                        .into_iter()
                        .map(|member| member.into_compressed(self.options.target))
                        .collect::<Result<Vec<_>>>()?;
                    for entry in &entries {
                        validate_compressed_entry(entry)?;
                    }
                    let resolved = if compression_method == 0 {
                        None
                    } else {
                        let datas: Vec<&[u8]> = entries.iter().map(|entry| entry.data).collect();
                        Some(filter_policy::resolve_solid_members(
                            &datas,
                            algorithm_version,
                            encode_options,
                            compression_progress,
                        )?)
                    };
                    let mut resolved = resolved.map(Vec::into_iter);
                    for (index, entry) in entries.into_iter().enumerate() {
                        let entry_name = entry.name;
                        let entry_size = entry.data.len() as u64;
                        if let Some(progress) = compression_progress {
                            progress.entry_started(index, total_entries, entry_name, entry_size);
                        }
                        let Some((packed, solid_continuation)) =
                            resolved.as_mut().and_then(Iterator::next)
                        else {
                            resolved_members
                                .push(ResolvedRar50WriteMember::StoredCompressed(entry));
                            continue;
                        };
                        if should_store_compressed_payload(
                            entry.data,
                            &packed,
                            true,
                            self.filter_policy,
                        ) {
                            resolved_members
                                .push(ResolvedRar50WriteMember::StoredCompressed(entry));
                        } else {
                            resolved_members.push(ResolvedRar50WriteMember::Compressed {
                                entry,
                                packed,
                                algorithm_version,
                                compression_method,
                                dictionary_size,
                                solid_continuation,
                                digests: None,
                            });
                        }
                        if let Some(progress) = compression_progress {
                            progress.entry_finished(index, total_entries, entry_name, entry_size);
                        }
                    }
                } else {
                    resolved_members = resolve_compressed_members(
                        self.members,
                        self.options.target,
                        compression_method,
                        algorithm_version,
                        dictionary_size,
                        self.filter_policy,
                        &encode_option_candidates,
                        compression_progress,
                        self.options.hash_record,
                    )?;
                }
                Ok(ResolvedRar50WritePlan {
                    hash_record: self.options.hash_record,
                    main_flags: if self.options.features.solid {
                        ARCHIVE_IS_SOLID
                    } else {
                        0
                    },
                    archive_comment: self.archive_comment.and_then(ArchiveComment::plain_only),
                    archive_metadata: self.archive_metadata,
                    quick_open: false,
                    recovery_percent: self.recovery_percent,
                    header_keys: None,
                    members: resolved_members,
                })
            }
            Rar50WriteMemberKind::EncryptedStored => {
                if self.recovery_percent.is_some() {
                    validate_encrypted_recovery_options(self.options)?;
                } else {
                    validate_encrypted_options(self.options)?;
                }
                let header_keys = if self.options.features.header_encryption {
                    let password = header_encryption_password(
                        self.members
                            .iter()
                            .map(|member| member.encrypted_stored_password(self.options.target))
                            .collect::<Result<Vec<_>>>()?
                            .into_iter()
                            .chain(self.archive_comment.and_then(ArchiveComment::password))
                            .chain(self.recovery_password),
                    )?;
                    Some(header_encryption_keys(password)?)
                } else {
                    None
                };
                for member in self.members {
                    let entry = member.into_encrypted_stored(self.options.target)?;
                    validate_encrypted_entry(&entry)?;
                    let encrypted = encrypted_stored_payload(
                        entry.data,
                        entry.password,
                        self.options.hash_record,
                    )?;
                    resolved_members
                        .push(ResolvedRar50WriteMember::EncryptedStored { entry, encrypted });
                }
                Ok(ResolvedRar50WritePlan {
                    hash_record: self.options.hash_record,
                    main_flags: 0,
                    archive_comment: self
                        .archive_comment
                        .and_then(ArchiveComment::encrypted_only),
                    archive_metadata: self.archive_metadata,
                    quick_open: false,
                    recovery_percent: self.recovery_percent,
                    header_keys,
                    members: resolved_members,
                })
            }
            Rar50WriteMemberKind::EncryptedStoredWithServices => {
                if self.archive_comment.is_some()
                    || self.archive_metadata.is_some()
                    || self.recovery_percent.is_some()
                    || self.filter_policy != FilterPolicy::None
                {
                    return Err(Error::UnsupportedFeature {
                        version: self.options.target,
                        feature: "RAR 5 encrypted stored file-service writer option combination",
                    });
                }
                validate_encrypted_file_service_options(self.options)?;
                let header_keys = if self.options.features.header_encryption {
                    let mut passwords = Vec::new();
                    for member in &self.members {
                        let entry =
                            member.encrypted_stored_with_services_ref(self.options.target)?;
                        passwords.push(entry.entry.password);
                        passwords.extend(entry.services.iter().map(|service| service.password));
                    }
                    let password = header_encryption_password(passwords.into_iter())?;
                    Some(header_encryption_keys(password)?)
                } else {
                    None
                };
                for member in self.members {
                    let entry = member.into_encrypted_stored_with_services(self.options.target)?;
                    validate_encrypted_entry(&entry.entry)?;
                    for service in entry.services {
                        validate_encrypted_file_service(service)?;
                    }
                    let encrypted = encrypted_stored_payload(
                        entry.entry.data,
                        entry.entry.password,
                        self.options.hash_record,
                    )?;
                    resolved_members.push(ResolvedRar50WriteMember::EncryptedStoredWithServices {
                        entry,
                        encrypted,
                    });
                }
                Ok(ResolvedRar50WritePlan {
                    hash_record: self.options.hash_record,
                    main_flags: 0,
                    archive_comment: None,
                    archive_metadata: None,
                    quick_open: false,
                    recovery_percent: None,
                    header_keys,
                    members: resolved_members,
                })
            }
            Rar50WriteMemberKind::EncryptedCompressed => {
                if self.recovery_percent.is_some() {
                    validate_encrypted_compressed_recovery_options(self.options)?;
                } else {
                    validate_encrypted_compressed_options(self.options)?;
                }
                let header_keys = if self.options.features.header_encryption {
                    let password = header_encryption_password(
                        self.members
                            .iter()
                            .map(|member| member.encrypted_compressed_password(self.options.target))
                            .collect::<Result<Vec<_>>>()?
                            .into_iter()
                            .chain(self.archive_comment.and_then(ArchiveComment::password)),
                    )?;
                    Some(header_encryption_keys(password)?)
                } else {
                    None
                };
                if self.options.features.solid {
                    // The solid arms on the pool first (`resolve_solid_members`),
                    // then the encryption in member order: salts and IVs are
                    // drawn from the entropy in that order.
                    let entries = self
                        .members
                        .into_iter()
                        .map(|member| member.into_encrypted_compressed(self.options.target))
                        .collect::<Result<Vec<_>>>()?;
                    for entry in &entries {
                        validate_encrypted_compressed_entry(entry)?;
                    }
                    let resolved = if compression_method == 0 {
                        None
                    } else {
                        let datas: Vec<&[u8]> = entries.iter().map(|entry| entry.data).collect();
                        Some(filter_policy::resolve_solid_members(
                            &datas,
                            algorithm_version,
                            encode_options,
                            compression_progress,
                        )?)
                    };
                    let mut resolved = resolved.map(Vec::into_iter);
                    for (index, entry) in entries.into_iter().enumerate() {
                        let entry_name = entry.name;
                        let entry_size = entry.data.len() as u64;
                        if let Some(progress) = compression_progress {
                            progress.entry_started(index, total_entries, entry_name, entry_size);
                        }
                        let Some((packed, solid_continuation)) =
                            resolved.as_mut().and_then(Iterator::next)
                        else {
                            let encrypted = encrypted_stored_payload(
                                entry.data,
                                entry.password,
                                self.options.hash_record,
                            )?;
                            resolved_members.push(
                                ResolvedRar50WriteMember::EncryptedStoredCompressed {
                                    entry,
                                    encrypted,
                                },
                            );
                            continue;
                        };
                        if should_store_compressed_payload(
                            entry.data,
                            &packed,
                            true,
                            FilterPolicy::None,
                        ) {
                            let encrypted = encrypted_stored_payload(
                                entry.data,
                                entry.password,
                                self.options.hash_record,
                            )?;
                            resolved_members.push(
                                ResolvedRar50WriteMember::EncryptedStoredCompressed {
                                    entry,
                                    encrypted,
                                },
                            );
                        } else {
                            let encrypted = encrypted_payload(
                                packed,
                                entry.data,
                                entry.password,
                                self.options.hash_record,
                            )?;
                            resolved_members.push(ResolvedRar50WriteMember::EncryptedCompressed {
                                entry,
                                encrypted,
                                algorithm_version,
                                compression_method,
                                dictionary_size,
                                solid_continuation,
                            });
                        }
                        if let Some(progress) = compression_progress {
                            progress.entry_finished(index, total_entries, entry_name, entry_size);
                        }
                    }
                } else {
                    resolved_members = resolve_encrypted_compressed_members(
                        self.members,
                        self.options.target,
                        compression_method,
                        algorithm_version,
                        dictionary_size,
                        &encode_option_candidates,
                        compression_progress,
                        self.options.hash_record,
                    )?;
                }
                Ok(ResolvedRar50WritePlan {
                    hash_record: self.options.hash_record,
                    main_flags: if self.options.features.solid {
                        ARCHIVE_IS_SOLID
                    } else {
                        0
                    },
                    archive_comment: self
                        .archive_comment
                        .and_then(ArchiveComment::encrypted_only),
                    archive_metadata: self.archive_metadata,
                    quick_open: false,
                    recovery_percent: self.recovery_percent,
                    header_keys,
                    members: resolved_members,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rar50WriteMemberKind {
    Stored,
    StoredWithServices,
    Compressed,
    EncryptedStored,
    EncryptedStoredWithServices,
    EncryptedCompressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rar50WriteMember<'a> {
    Stored(StoredEntry<'a>),
    StoredWithServices(StoredEntryWithServices<'a>),
    Compressed(CompressedEntry<'a>),
    EncryptedStored(EncryptedStoredEntry<'a>),
    EncryptedStoredWithServices(EncryptedStoredEntryWithServices<'a>),
    EncryptedCompressed(EncryptedCompressedEntry<'a>),
}

impl<'a> Rar50WriteMember<'a> {
    fn kind(self) -> Rar50WriteMemberKind {
        match self {
            Self::Stored(_) => Rar50WriteMemberKind::Stored,
            Self::StoredWithServices(_) => Rar50WriteMemberKind::StoredWithServices,
            Self::Compressed(_) => Rar50WriteMemberKind::Compressed,
            Self::EncryptedStored(_) => Rar50WriteMemberKind::EncryptedStored,
            Self::EncryptedStoredWithServices(_) => {
                Rar50WriteMemberKind::EncryptedStoredWithServices
            }
            Self::EncryptedCompressed(_) => Rar50WriteMemberKind::EncryptedCompressed,
        }
    }

    fn input_size(&self) -> u64 {
        match self {
            Self::Stored(entry) => entry.data.len() as u64,
            Self::StoredWithServices(entry) => entry.entry.data.len() as u64,
            Self::Compressed(entry) => entry.data.len() as u64,
            Self::EncryptedStored(entry) => entry.data.len() as u64,
            Self::EncryptedStoredWithServices(entry) => entry.entry.data.len() as u64,
            Self::EncryptedCompressed(entry) => entry.data.len() as u64,
        }
    }

    fn input_data(&self) -> &'a [u8] {
        match self {
            Self::Stored(entry) => entry.data,
            Self::StoredWithServices(entry) => entry.entry.data,
            Self::Compressed(entry) => entry.data,
            Self::EncryptedStored(entry) => entry.data,
            Self::EncryptedStoredWithServices(entry) => entry.entry.data,
            Self::EncryptedCompressed(entry) => entry.data,
        }
    }

    fn into_stored(self, target: crate::ArchiveVersion) -> Result<StoredEntry<'a>> {
        match self {
            Self::Stored(entry) => Ok(entry),
            _ => Err(mixed_member_plan_error(target)),
        }
    }

    fn into_stored_with_services(
        self,
        target: crate::ArchiveVersion,
    ) -> Result<StoredEntryWithServices<'a>> {
        match self {
            Self::StoredWithServices(entry) => Ok(entry),
            _ => Err(mixed_member_plan_error(target)),
        }
    }

    fn into_compressed(self, target: crate::ArchiveVersion) -> Result<CompressedEntry<'a>> {
        match self {
            Self::Compressed(entry) => Ok(entry),
            _ => Err(mixed_member_plan_error(target)),
        }
    }

    fn into_encrypted_stored(
        self,
        target: crate::ArchiveVersion,
    ) -> Result<EncryptedStoredEntry<'a>> {
        match self {
            Self::EncryptedStored(entry) => Ok(entry),
            _ => Err(mixed_member_plan_error(target)),
        }
    }

    fn into_encrypted_stored_with_services(
        self,
        target: crate::ArchiveVersion,
    ) -> Result<EncryptedStoredEntryWithServices<'a>> {
        match self {
            Self::EncryptedStoredWithServices(entry) => Ok(entry),
            _ => Err(mixed_member_plan_error(target)),
        }
    }

    fn into_encrypted_compressed(
        self,
        target: crate::ArchiveVersion,
    ) -> Result<EncryptedCompressedEntry<'a>> {
        match self {
            Self::EncryptedCompressed(entry) => Ok(entry),
            _ => Err(mixed_member_plan_error(target)),
        }
    }

    fn encrypted_stored_password(&self, target: crate::ArchiveVersion) -> Result<&'a [u8]> {
        match self {
            Self::EncryptedStored(entry) => Ok(entry.password),
            _ => Err(mixed_member_plan_error(target)),
        }
    }

    fn encrypted_stored_with_services_ref(
        &self,
        target: crate::ArchiveVersion,
    ) -> Result<&EncryptedStoredEntryWithServices<'a>> {
        match self {
            Self::EncryptedStoredWithServices(entry) => Ok(entry),
            _ => Err(mixed_member_plan_error(target)),
        }
    }

    fn encrypted_compressed_password(&self, target: crate::ArchiveVersion) -> Result<&'a [u8]> {
        match self {
            Self::EncryptedCompressed(entry) => Ok(entry.password),
            _ => Err(mixed_member_plan_error(target)),
        }
    }
}

fn mixed_member_plan_error(target: crate::ArchiveVersion) -> Error {
    Error::UnsupportedFeature {
        version: target,
        feature: "RAR 5 mixed stored/compressed writer plan",
    }
}

fn compression_work_total(
    members: &[Rar50WriteMember<'_>],
    solid: bool,
    filter_policy: FilterPolicy,
    option_candidates: u64,
) -> u64 {
    members
        .iter()
        .enumerate()
        .map(|(index, member)| {
            let attempts = if solid {
                if index == 0 {
                    1
                } else {
                    2
                }
            } else {
                option_candidates.saturating_mul(filter_policy_attempt_count(
                    member.input_data(),
                    filter_policy,
                ))
            };
            member.input_size().saturating_mul(attempts)
        })
        .sum()
}

fn report_operation_started(
    progress: Option<ProgressReporter<'_>>,
    operation: WriteOperation,
    total_bytes: u64,
    total_entries: usize,
    pass: usize,
) {
    if let Some(progress) = progress {
        progress.report(WriteProgressEvent::OperationStarted {
            operation,
            total_bytes: Some(total_bytes),
            total_entries: Some(total_entries),
            pass,
        });
    }
}

fn report_operation_finished(
    progress: Option<ProgressReporter<'_>>,
    operation: WriteOperation,
    total_bytes: u64,
    total_entries: usize,
    pass: usize,
) {
    if let Some(progress) = progress {
        progress.report(WriteProgressEvent::OperationFinished {
            operation,
            total_bytes: Some(total_bytes),
            total_entries: Some(total_entries),
            pass,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_compressed_members<'a>(
    members: Vec<Rar50WriteMember<'a>>,
    target: crate::ArchiveVersion,
    compression_method: u8,
    algorithm_version: u8,
    dictionary_size: u64,
    filter_policy: FilterPolicy,
    encode_option_candidates: &[EncodeOptions],
    progress: Option<&WorkTracker<'_>>,
    hash_record: HashRecord,
) -> Result<Vec<ResolvedRar50WriteMember<'a>>> {
    let total_entries = members.len();
    let members: Vec<_> = members.into_iter().enumerate().collect();
    // One scratch pool for the set (see `encode_lz_member_pooled`).
    let scratch = EncoderScratchPool::new();
    let resolve = |(index, member)| {
        resolve_compressed_member(
            member,
            index,
            total_entries,
            target,
            compression_method,
            algorithm_version,
            dictionary_size,
            filter_policy,
            encode_option_candidates,
            progress,
            hash_record,
            &scratch,
        )
    };
    #[cfg(feature = "parallel")]
    {
        if members.len() > 1 {
            crate::parallel::map_collect_bounded(
                members,
                filter_policy::members_in_flight_for(encode_option_candidates),
resolve)
        } else {
            members.into_iter().map(resolve).collect()
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        members.into_iter().map(resolve).collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_compressed_member<'a>(
    member: Rar50WriteMember<'a>,
    index: usize,
    total_entries: usize,
    target: crate::ArchiveVersion,
    compression_method: u8,
    algorithm_version: u8,
    dictionary_size: u64,
    filter_policy: FilterPolicy,
    encode_option_candidates: &[EncodeOptions],
    progress: Option<&WorkTracker<'_>>,
    hash_record: HashRecord,
    scratch: &EncoderScratchPool,
) -> Result<ResolvedRar50WriteMember<'a>> {
    let entry = member.into_compressed(target)?;
    let entry_name = entry.name;
    let entry_size = entry.data.len() as u64;
    if let Some(progress) = progress {
        progress.entry_started(index, total_entries, entry_name, entry_size);
    }
    validate_compressed_entry(&entry)?;
    if compression_method == 0 {
        if let Some(progress) = progress {
            progress.entry_finished(index, total_entries, entry_name, entry_size);
        }
        return Ok(ResolvedRar50WriteMember::StoredCompressed(entry));
    }
    // `Sampled` reads its regions ONCE, here, and a member no region votes
    // a filter for is resolved exactly as `None` from this line on: the
    // pooled unfiltered encoder, the store sampling, the same bytes.
    // (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
    let sampled_filters = match (filter_policy, encode_option_candidates.first()) {
        (FilterPolicy::Sampled, Some(&first)) => {
            filter_policy::select_sampled_filters(entry.data, first)
        }
        _ => Vec::new(),
    };
    let filter_policy = if filter_policy == FilterPolicy::Sampled && sampled_filters.is_empty() {
        FilterPolicy::None
    } else {
        filter_policy
    };
    // The sampling and the encode on one side, both payload digests on the
    // other: the hash is the cost of storing and a sixth of compressing, and
    // it used to run serially after the encode, at emission.
    let sample_then_encode = || -> Result<Option<Vec<u8>>> {
        if filter_policy == FilterPolicy::None
            && encode_option_candidates
                .first()
                .is_some_and(|&first| sampled_incompressible(entry.data, algorithm_version, first))
        {
            return Ok(None);
        }
        if filter_policy == FilterPolicy::None {
            encode_candidates_with_progress(
                entry.data,
                algorithm_version,
                encode_option_candidates,
                progress,
                scratch,
            )
            .map(Some)
        } else {
            Ok(None)
        }
    };
    #[cfg(feature = "parallel")]
    let (encoded, digests) = rayon::join(sample_then_encode, || {
        payload_digests(entry.data, hash_record)
    });
    #[cfg(not(feature = "parallel"))]
    let (encoded, digests) = (
        sample_then_encode(),
        payload_digests(entry.data, hash_record),
    );
    let encoded = encoded?;
    if filter_policy == FilterPolicy::None && encoded.is_none() {
        if let Some(progress) = progress {
            if !progress.advance(entry_size) {
                return Err(Error::Cancelled);
            }
            progress.entry_finished(index, total_entries, entry_name, entry_size);
        }
        return Ok(ResolvedRar50WriteMember::StoredCompressedWithDigests { entry, digests });
    }
    let packed = if let Some(packed) = encoded {
        packed
    } else {
        let mut last = 0usize;
        let mut report = |position: usize| {
            if position < last {
                last = 0;
            }
            let delta = position.saturating_sub(last);
            last = position;
            progress.is_none_or(|progress| progress.advance(delta as u64))
        };
        if filter_policy == FilterPolicy::Sampled {
            encode_member_with_filter_specs_candidates_and_progress(
                entry.data,
                algorithm_version,
                &sampled_filters,
                encode_option_candidates,
                Some(&mut report),
            )?
        } else {
            encode_member_with_filter_policy_candidates_and_progress(
                entry.data,
                algorithm_version,
                filter_policy,
                encode_option_candidates,
                Some(&mut report),
            )?
        }
    };
    if should_store_compressed_payload(entry.data, &packed, false, filter_policy) {
        let resolved = ResolvedRar50WriteMember::StoredCompressedWithDigests { entry, digests };
        if let Some(progress) = progress {
            progress.entry_finished(index, total_entries, entry_name, entry_size);
        }
        Ok(resolved)
    } else {
        let resolved = ResolvedRar50WriteMember::Compressed {
            entry,
            packed,
            algorithm_version,
            compression_method,
            dictionary_size,
            solid_continuation: false,
            digests: Some(digests),
        };
        if let Some(progress) = progress {
            progress.entry_finished(index, total_entries, entry_name, entry_size);
        }
        Ok(resolved)
    }
}

fn encode_candidates_with_progress(
    data: &[u8],
    algorithm_version: u8,
    candidates: &[EncodeOptions],
    progress: Option<&WorkTracker<'_>>,
    scratch: &EncoderScratchPool,
) -> Result<Vec<u8>> {
    let (first, rest) = candidates.split_first().ok_or(Error::InvalidHeader(
        "RAR 5 compression level has no encoder options",
    ))?;
    // nzbfast-local change, 5 Sep 2026 — preserve the absent reporter down
    // to the block encoder instead of supplying a no-op callback. Option
    // order and smallest-payload selection stay unchanged. See VENDORING.md.
    if progress.is_none() {
        let mut best = filter_policy::encode_safe_lz_member_pooled(
            data,
            algorithm_version,
            *first,
            None,
            scratch,
        )?;
        for &options in rest {
            let packed = filter_policy::encode_safe_lz_member_pooled(
                data,
                algorithm_version,
                options,
                None,
                scratch,
            )?;
            if packed.len() < best.len() {
                best = packed;
            }
        }
        return Ok(best);
    }
    let mut last = 0usize;
    let mut report = |position: usize| {
        if position < last {
            last = 0;
        }
        let delta = position.saturating_sub(last);
        last = position;
        progress.is_none_or(|progress| progress.advance(delta as u64))
    };
    let mut best = match filter_policy::encode_safe_lz_member_pooled(
        data,
        algorithm_version,
        *first,
        Some(&mut report),
        scratch,
    ) {
        Err(Error::Codec(crate::codec::Error::Cancelled)) => return Err(Error::Cancelled),
        result => result?,
    };
    for options in rest {
        if progress.is_some_and(WorkTracker::is_cancelled) {
            return Err(Error::Cancelled);
        }
        let packed = match filter_policy::encode_safe_lz_member_pooled(
            data,
            algorithm_version,
            *options,
            Some(&mut report),
            scratch,
        ) {
            Err(Error::Codec(crate::codec::Error::Cancelled)) => return Err(Error::Cancelled),
            result => result?,
        };
        if packed.len() < best.len() {
            best = packed;
        }
    }
    Ok(best)
}

// Eight, and each one a separate part of the encode contract: the
// members, the target, the method, the algorithm version, the
// dictionary, the option candidates, the progress tracker and the hash
// record. The unencrypted twin above already carries this allow.
#[allow(clippy::too_many_arguments)]
fn resolve_encrypted_compressed_members<'a>(
    members: Vec<Rar50WriteMember<'a>>,
    target: crate::ArchiveVersion,
    compression_method: u8,
    algorithm_version: u8,
    dictionary_size: u64,
    encode_option_candidates: &[EncodeOptions],
    progress: Option<&WorkTracker<'_>>,
    hash_record: HashRecord,
) -> Result<Vec<ResolvedRar50WriteMember<'a>>> {
    let total_entries = members.len();
    let members: Vec<_> = members.into_iter().enumerate().collect();
    #[cfg(feature = "parallel")]
    {
        if members.len() > 1 {
            crate::parallel::map_collect_bounded(
                members,
                filter_policy::members_in_flight_for(encode_option_candidates),
|(index, member)| {
                resolve_encrypted_compressed_member(
                    member,
                    index,
                    total_entries,
                    target,
                    compression_method,
                    algorithm_version,
                    dictionary_size,
                    encode_option_candidates,
                    progress,
                    hash_record,
                )
            })
        } else {
            members
                .into_iter()
                .map(|(index, member)| {
                    resolve_encrypted_compressed_member(
                        member,
                        index,
                        total_entries,
                        target,
                        compression_method,
                        algorithm_version,
                        dictionary_size,
                        encode_option_candidates,
                        progress,
                        hash_record,
                    )
                })
                .collect()
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        members
            .into_iter()
            .map(|(index, member)| {
                resolve_encrypted_compressed_member(
                    member,
                    index,
                    total_entries,
                    target,
                    compression_method,
                    algorithm_version,
                    dictionary_size,
                    encode_option_candidates,
                    progress,
                    hash_record,
                )
            })
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_encrypted_compressed_member<'a>(
    member: Rar50WriteMember<'a>,
    index: usize,
    total_entries: usize,
    target: crate::ArchiveVersion,
    compression_method: u8,
    algorithm_version: u8,
    dictionary_size: u64,
    encode_option_candidates: &[EncodeOptions],
    progress: Option<&WorkTracker<'_>>,
    hash_record: HashRecord,
) -> Result<ResolvedRar50WriteMember<'a>> {
    let entry = member.into_encrypted_compressed(target)?;
    let entry_name = entry.name;
    let entry_size = entry.data.len() as u64;
    if let Some(progress) = progress {
        progress.entry_started(index, total_entries, entry_name, entry_size);
    }
    validate_encrypted_compressed_entry(&entry)?;
    if compression_method == 0 {
        let encrypted = encrypted_stored_payload(entry.data, entry.password, hash_record)?;
        if let Some(progress) = progress {
            progress.entry_finished(index, total_entries, entry_name, entry_size);
        }
        return Ok(ResolvedRar50WriteMember::EncryptedStoredCompressed { entry, encrypted });
    }
    if encode_option_candidates
        .first()
        .is_some_and(|&first| sampled_incompressible(entry.data, algorithm_version, first))
    {
        let encrypted = encrypted_stored_payload(entry.data, entry.password, hash_record)?;
        if let Some(progress) = progress {
            if !progress.advance(entry_size) {
                return Err(Error::Cancelled);
            }
            progress.entry_finished(index, total_entries, entry_name, entry_size);
        }
        return Ok(ResolvedRar50WriteMember::EncryptedStoredCompressed { entry, encrypted });
    }
    let packed = encode_candidates_with_progress(
        entry.data,
        algorithm_version,
        encode_option_candidates,
        progress,
        &EncoderScratchPool::new(),
    )?;
    let resolved =
        if should_store_compressed_payload(entry.data, &packed, false, FilterPolicy::None) {
            let encrypted = encrypted_stored_payload(entry.data, entry.password, hash_record)?;
            ResolvedRar50WriteMember::EncryptedStoredCompressed { entry, encrypted }
        } else {
            let encrypted = encrypted_payload(packed, entry.data, entry.password, hash_record)?;
            ResolvedRar50WriteMember::EncryptedCompressed {
                entry,
                encrypted,
                algorithm_version,
                compression_method,
                dictionary_size,
                solid_continuation: false,
            }
        };
    if let Some(progress) = progress {
        progress.entry_finished(index, total_entries, entry_name, entry_size);
    }
    Ok(resolved)
}

struct ResolvedRar50WritePlan<'a> {
    main_flags: u64,
    archive_comment: Option<ArchiveComment<'a>>,
    archive_metadata: Option<ArchiveMetadataEntry<'a>>,
    quick_open: bool,
    recovery_percent: Option<u64>,
    header_keys: Option<HeaderEncryptionKeys>,
    members: Vec<ResolvedRar50WriteMember<'a>>,
    hash_record: HashRecord,
}

/// The two digests a file header carries for its payload: the CRC32 in the
/// file header and the BLAKE2sp hash record in the extra area.
///
/// The BLAKE2sp over a large member is a third of what STORING it costs
/// and about 15% of COMPRESSING it (2.4 GB/s on the 8-lane kernel, one
/// thread), and the emitters used to compute both digests after the encode
/// had finished, serially. The single-volume compressed resolver now
/// computes them beside the encode on the pool (`rayon::join`) and hands
/// them down; every other path still computes at emission, as before.
/// (nzbfast-local change, 5 Sep 2026; see VENDORING.md.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PayloadDigests {
    crc32: u32,
    /// `None` when the header carries CRC32 only.
    blake2sp: Option<[u8; 32]>,
}

fn payload_digests(data: &[u8], hash_record: HashRecord) -> PayloadDigests {
    PayloadDigests {
        crc32: crc32(data),
        blake2sp: match hash_record {
            HashRecord::Crc32Only => None,
            HashRecord::Blake2sp => Some(blake2sp::hash(data)),
        },
    }
}

enum ResolvedRar50WriteMember<'a> {
    Stored(StoredEntry<'a>),
    StoredWithServices(StoredEntryWithServices<'a>),
    StoredCompressed(CompressedEntry<'a>),
    /// A compressed entry stored after all, with the payload digests the
    /// resolver computed alongside the encode (or the sampling) - see
    /// [`PayloadDigests`].
    StoredCompressedWithDigests {
        entry: CompressedEntry<'a>,
        digests: PayloadDigests,
    },
    Compressed {
        entry: CompressedEntry<'a>,
        packed: Vec<u8>,
        algorithm_version: u8,
        compression_method: u8,
        dictionary_size: u64,
        solid_continuation: bool,
        /// Computed alongside the encode when the resolver could, so the
        /// emitter does not hash the payload a second time, serially.
        digests: Option<PayloadDigests>,
    },
    EncryptedStored {
        entry: EncryptedStoredEntry<'a>,
        encrypted: EncryptedStoredPayload,
    },
    EncryptedStoredWithServices {
        entry: EncryptedStoredEntryWithServices<'a>,
        encrypted: EncryptedStoredPayload,
    },
    EncryptedStoredCompressed {
        entry: EncryptedCompressedEntry<'a>,
        encrypted: EncryptedStoredPayload,
    },
    EncryptedCompressed {
        entry: EncryptedCompressedEntry<'a>,
        encrypted: EncryptedStoredPayload,
        algorithm_version: u8,
        compression_method: u8,
        dictionary_size: u64,
        solid_continuation: bool,
    },
}

fn emit_resolved_writer_plan_with_progress(
    plan: ResolvedRar50WritePlan<'_>,
    progress: Option<ProgressReporter<'_>>,
) -> Result<Vec<u8>> {
    if plan.quick_open {
        return resolve_writer_plan_offset(
            |quick_open_offset, _| {
                emit_resolved_writer_plan_pass(
                    &plan,
                    Some(quick_open_offset),
                    None,
                    progress,
                    1,
                    false,
                )
                .map(|(out, next_quick_open_offset, _)| (out, next_quick_open_offset))
            },
            "RAR 5 quick-open pass did not report an offset",
            "RAR 5 quick-open offset did not converge",
        );
    }
    if plan.recovery_percent.is_some() {
        if let Some(out) = emit_resolved_writer_plan_recovery_direct(&plan, progress)? {
            return Ok(out);
        }
        return resolve_writer_plan_offset(
            |recovery_offset, pass| {
                emit_resolved_writer_plan_pass(
                    &plan,
                    None,
                    Some(recovery_offset),
                    progress,
                    pass,
                    false,
                )
                .map(|(out, _, next_recovery_offset)| (out, next_recovery_offset))
            },
            "RAR 5 recovery pass did not report an offset",
            "RAR 5 recovery offset did not converge",
        );
    }
    emit_resolved_writer_plan_pass(&plan, None, None, progress, 1, false).map(|(out, _, _)| out)
}

/// A recovery-record archive in ONE real emission.
///
/// The recovery record's offset lives in the main header's locator as a
/// varint, so the record's position depends on the header's length, which
/// depends on the offset. The pass loop above resolved that by emitting
/// the whole archive at offset 0, reading where the record landed, and
/// emitting again - up to four times, each time copying every payload and
/// generating the Reed-Solomon parity over the whole archive again: a
/// 1 GiB stored archive with `-rr3` cost 2.6 s and 9.2 CPU-seconds where
/// the store alone is 0.6 s. Everything after the main header is the same
/// length whatever the offset is, so one MEASURING pass (offset 0, a
/// zero-filled record of the right size in place of the parity) gives the
/// length of that fixed body, the offset is then solved on header lengths
/// alone, and the archive is emitted once with the real parity. The result
/// is the fixed point the old loop converged to, so the bytes are the
/// same; `None` (never expected) hands back to the loop.
/// (nzbfast-local change, 6 Sep 2026; see VENDORING.md.)
fn emit_resolved_writer_plan_recovery_direct(
    plan: &ResolvedRar50WritePlan<'_>,
    progress: Option<ProgressReporter<'_>>,
) -> Result<Option<Vec<u8>>> {
    let (_, _, measured) = emit_resolved_writer_plan_pass(plan, None, Some(0), None, 1, true)?;
    let Some(measured) = measured else {
        return Ok(None);
    };
    let head_at = |offset: u64| -> Result<u64> {
        Ok((resolved_archive_head_len(plan, None, Some(offset))? - RAR50_SIGNATURE.len()) as u64)
    };
    let Some(fixed_body) = measured.checked_sub(head_at(0)?) else {
        return Ok(None);
    };
    let mut offset = measured;
    let mut converged = false;
    for _ in 0..4 {
        let next = head_at(offset)? + fixed_body;
        if next == offset {
            converged = true;
            break;
        }
        offset = next;
    }
    if !converged {
        return Ok(None);
    }
    let (out, _, observed) =
        emit_resolved_writer_plan_pass(plan, None, Some(offset), progress, 1, false)?;
    Ok((observed == Some(offset)).then_some(out))
}

/// Bytes from the archive's start to the end of its main header, for the
/// given locator offsets: the only part of the archive whose length
/// depends on them.
fn resolved_archive_head_len(
    plan: &ResolvedRar50WritePlan<'_>,
    quick_open_offset: Option<u64>,
    recovery_offset: Option<u64>,
) -> Result<usize> {
    let mut head = Vec::new();
    head.extend_from_slice(RAR50_SIGNATURE);
    let main_extra =
        resolved_main_extra(plan.archive_metadata, quick_open_offset, recovery_offset)?;
    let main_flags = resolved_main_flags(plan);
    if let Some(header_keys) = &plan.header_keys {
        write_head_crypt(&mut head, header_keys)?;
        head.extend_from_slice(&encrypted_main_header_block(
            &header_keys.keys,
            main_flags,
            None,
            &main_extra,
        )?);
    } else {
        write_main_header(&mut head, main_flags, None, &main_extra)?;
    }
    Ok(head.len())
}

fn resolved_main_flags(plan: &ResolvedRar50WritePlan<'_>) -> u64 {
    plan.main_flags
        | if plan.recovery_percent.is_some() {
            ARCHIVE_HAS_RECOVERY_RECORD
        } else {
            0
        }
}

fn resolve_writer_plan_offset<F>(
    mut pass: F,
    missing_offset_error: &'static str,
    convergence_error: &'static str,
) -> Result<Vec<u8>>
where
    F: FnMut(u64, usize) -> Result<(Vec<u8>, Option<u64>)>,
{
    let mut offset = 0;
    for pass_index in 1..=4 {
        let (out, next_offset) = pass(offset, pass_index)?;
        if next_offset == Some(offset) {
            return Ok(out);
        }
        offset = next_offset.ok_or(Error::InvalidHeader(missing_offset_error))?;
    }
    Err(Error::InvalidHeader(convergence_error))
}

fn emit_resolved_writer_plan_pass(
    plan: &ResolvedRar50WritePlan<'_>,
    quick_open_offset: Option<u64>,
    recovery_offset: Option<u64>,
    progress: Option<ProgressReporter<'_>>,
    recovery_pass: usize,
    recovery_placeholder: bool,
) -> Result<(Vec<u8>, Option<u64>, Option<u64>)> {
    let mut out = Vec::new();
    let mut cached_headers = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    let main_extra =
        resolved_main_extra(plan.archive_metadata, quick_open_offset, recovery_offset)?;
    let main_flags = resolved_main_flags(plan);
    if let Some(header_keys) = &plan.header_keys {
        write_head_crypt(&mut out, header_keys)?;
        out.extend_from_slice(&encrypted_main_header_block(
            &header_keys.keys,
            main_flags,
            None,
            &main_extra,
        )?);
    } else {
        write_main_header(&mut out, main_flags, None, &main_extra)?;
    }
    if let Some(comment) = plan.archive_comment {
        match comment {
            ArchiveComment::Plain(comment) => {
                if plan.quick_open {
                    write_stored_service_with_cache(
                        &mut out,
                        &mut cached_headers,
                        b"CMT",
                        comment,
                    )?;
                } else {
                    write_stored_service(&mut out, b"CMT", comment)?;
                }
            }
            ArchiveComment::Encrypted(comment) => {
                write_encrypted_stored_service_with_header_keys(
                    &mut out,
                    b"CMT",
                    comment,
                    plan.header_keys.as_ref().map(|keys| &keys.keys),
                    plan.hash_record,
                )?;
            }
        }
    }
    for member in &plan.members {
        match member {
            ResolvedRar50WriteMember::Stored(entry) => {
                if plan.quick_open {
                    write_stored_entry_with_cache(
                        &mut out,
                        &mut cached_headers,
                        entry,
                        plan.hash_record,
                    )?;
                } else {
                    write_stored_entry(&mut out, entry, plan.hash_record)?;
                }
            }
            ResolvedRar50WriteMember::StoredWithServices(entry) => {
                write_stored_entry(&mut out, &entry.entry, plan.hash_record)?;
                for service in entry.services {
                    write_stored_service(&mut out, service.name, service.data)?;
                }
            }
            ResolvedRar50WriteMember::StoredCompressed(entry) => {
                write_stored_compressed_entry(&mut out, entry, plan.hash_record)?;
            }
            ResolvedRar50WriteMember::StoredCompressedWithDigests { entry, digests } => {
                validate_compressed_entry(entry)?;
                let stored = stored_entry_from_compressed_entry(entry);
                validate_entry(&stored)?;
                write_stored_entry_fragment_with_digests(
                    &mut out,
                    &stored,
                    stored.data,
                    stored.data.len() as u64,
                    Some(digests.crc32),
                    false,
                    false,
                    plan.hash_record,
                    digests.blake2sp,
                )?;
            }
            ResolvedRar50WriteMember::Compressed {
                entry,
                packed,
                algorithm_version,
                compression_method,
                dictionary_size,
                solid_continuation,
                digests,
            } => write_compressed_entry_payload(
                &mut out,
                entry,
                packed,
                *algorithm_version,
                *compression_method,
                *dictionary_size,
                *solid_continuation,
                *digests,
                plan.hash_record,
            )?,
            ResolvedRar50WriteMember::EncryptedStored { entry, encrypted } => {
                let mut stream = encrypted.stream();
                write_encrypted_stored_entry_fragment_with_header_keys(
                    &mut out,
                    entry,
                    BlockData::Encrypt {
                        plain: entry.data,
                        end: encrypted.stream_len(),
                        stream: &mut stream,
                    },
                    encrypted,
                    false,
                    false,
                    plan.header_keys.as_ref().map(|keys| &keys.keys),
                )?
            }
            ResolvedRar50WriteMember::EncryptedStoredWithServices { entry, encrypted } => {
                let mut stream = encrypted.stream();
                write_encrypted_stored_entry_fragment_with_header_keys(
                    &mut out,
                    &entry.entry,
                    BlockData::Encrypt {
                        plain: entry.entry.data,
                        end: encrypted.stream_len(),
                        stream: &mut stream,
                    },
                    encrypted,
                    false,
                    false,
                    plan.header_keys.as_ref().map(|keys| &keys.keys),
                )?;
                for service in entry.services {
                    write_encrypted_stored_service_with_header_keys(
                        &mut out,
                        service.name,
                        EncryptedArchiveCommentEntry {
                            data: service.data,
                            password: service.password,
                        },
                        plan.header_keys.as_ref().map(|keys| &keys.keys),
                        plan.hash_record,
                    )?;
                }
            }
            ResolvedRar50WriteMember::EncryptedStoredCompressed { entry, encrypted } => {
                write_encrypted_stored_compressed_entry_with_header_keys(
                    &mut out,
                    entry,
                    encrypted,
                    plan.header_keys.as_ref().map(|keys| &keys.keys),
                )?;
            }
            ResolvedRar50WriteMember::EncryptedCompressed {
                entry,
                encrypted,
                algorithm_version,
                compression_method,
                dictionary_size,
                solid_continuation,
            } => write_encrypted_compressed_entry_fragment_with_header_keys(
                &mut out,
                EncryptedCompressedFragment {
                    entry,
                    data: BlockData::Bytes(&encrypted.data),
                    encrypted,
                    algorithm_version: *algorithm_version,
                    compression_method: *compression_method,
                    dictionary_size: *dictionary_size,
                    solid_continuation: *solid_continuation,
                    split_before: false,
                    split_after: false,
                },
                plan.header_keys.as_ref().map(|keys| &keys.keys),
            )?,
        }
    }
    let next_quick_open_offset = if plan.quick_open {
        let qo_pos = out.len();
        let qo_payload = quick_open_payload(&cached_headers, qo_pos)?;
        write_stored_service(&mut out, b"QO", &qo_payload)?;
        Some((qo_pos - RAR50_SIGNATURE.len()) as u64)
    } else {
        None
    };
    let next_recovery_offset = if let Some(recovery_percent) = plan.recovery_percent {
        let rr_pos = out.len();
        if let Some(header_keys) = &plan.header_keys {
            write_header_encrypted_recovery_service(
                &mut out,
                recovery_percent,
                &header_keys.keys,
                progress,
                recovery_pass,
                recovery_placeholder,
            )?;
        } else {
            write_recovery_service(
                &mut out,
                recovery_percent,
                progress,
                recovery_pass,
                recovery_placeholder,
            )?;
        }
        Some((rr_pos - RAR50_SIGNATURE.len()) as u64)
    } else {
        None
    };
    if let Some(header_keys) = &plan.header_keys {
        append_encrypted_header_block(
            &mut out,
            &header_keys.keys,
            BLOCK_TYPE_END_OF_ARCHIVE,
            0,
            None,
            &end_header_specific(0),
            &[],
            &[],
        )?;
    } else {
        write_end_header(&mut out, 0)?;
    }
    Ok((out, next_quick_open_offset, next_recovery_offset))
}

fn resolved_main_extra(
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
    quick_open_offset: Option<u64>,
    recovery_offset: Option<u64>,
) -> Result<Vec<u8>> {
    let mut main_extra = Vec::new();
    let locator_quick_open_offset = quick_open_offset.or_else(|| archive_metadata.map(|_| 0));
    if locator_quick_open_offset.is_some() || recovery_offset.is_some() {
        write_locator_record(&mut main_extra, locator_quick_open_offset, recovery_offset);
    }
    if let Some(archive_metadata) = archive_metadata {
        main_extra.extend_from_slice(&archive_metadata_record(archive_metadata)?);
    }
    Ok(main_extra)
}

fn write_main_header(
    out: &mut Vec<u8>,
    archive_flags: u64,
    volume_number: Option<u64>,
    extra: &[u8],
) -> Result<()> {
    let mut specific = Vec::new();
    write_vint(&mut specific, archive_flags);
    if let Some(volume_number) = volume_number {
        write_vint(&mut specific, volume_number);
    }
    write_block(
        out,
        BLOCK_TYPE_MAIN,
        if extra.is_empty() {
            0
        } else {
            BLOCK_HAS_EXTRA_AREA
        },
        None,
        &specific,
        extra,
        &[],
    )
}

fn encrypted_main_header_block(
    keys: &Rar50Keys,
    archive_flags: u64,
    volume_number: Option<u64>,
    extra: &[u8],
) -> Result<Vec<u8>> {
    let mut specific = Vec::new();
    write_vint(&mut specific, archive_flags);
    if let Some(volume_number) = volume_number {
        write_vint(&mut specific, volume_number);
    }
    encrypted_header_block(
        keys,
        BLOCK_TYPE_MAIN,
        if extra.is_empty() {
            0
        } else {
            BLOCK_HAS_EXTRA_AREA
        },
        None,
        &specific,
        extra,
        &[],
    )
}

fn validate_options(options: WriterOptions) -> Result<()> {
    validate_plain_options(options, false)
}

fn validate_recovery_options(options: WriterOptions) -> Result<()> {
    validate_plain_options(options, true)
}

fn validate_plain_options(options: WriterOptions, allow_recovery_record: bool) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.archive_comment = options.features.archive_comment;
    allowed.quick_open = options.features.quick_open;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 writer feature",
        });
    }
    Ok(())
}

fn validate_file_service_options(options: WriterOptions) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_comment = options.features.file_comment;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 stored file-service writer feature",
        });
    }
    Ok(())
}

fn validate_compressed_options(options: WriterOptions) -> Result<()> {
    validate_compressed_feature_options(options, false)
}

fn validate_compressed_recovery_options(options: WriterOptions) -> Result<()> {
    validate_compressed_feature_options(options, true)
}

fn validate_compressed_feature_options(
    options: WriterOptions,
    allow_recovery_record: bool,
) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.solid = options.features.solid;
    allowed.archive_comment = options.features.archive_comment;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 compressed writer feature",
        });
    }
    Ok(())
}

fn validate_encrypted_compressed_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_compressed_feature_options(options, false)
}

fn validate_encrypted_compressed_recovery_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_compressed_feature_options(options, true)
}

fn validate_encrypted_compressed_feature_options(
    options: WriterOptions,
    allow_recovery_record: bool,
) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_encryption = true;
    allowed.header_encryption = options.features.header_encryption;
    allowed.solid = options.features.solid;
    allowed.archive_comment = options.features.archive_comment;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 encrypted compressed writer feature",
        });
    }
    Ok(())
}

struct CachedHeader {
    offset: usize,
    header: Vec<u8>,
}

struct BlockParts<'a> {
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &'a [u8],
    extra: &'a [u8],
    data: &'a [u8],
}

fn validate_encrypted_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_feature_options(options, false)
}

fn validate_encrypted_recovery_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_feature_options(options, true)
}

fn validate_encrypted_feature_options(
    options: WriterOptions,
    allow_recovery_record: bool,
) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_encryption = true;
    allowed.header_encryption = options.features.header_encryption;
    allowed.archive_comment = options.features.archive_comment;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 encrypted stored writer feature",
        });
    }
    Ok(())
}

fn validate_encrypted_file_service_options(options: WriterOptions) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_encryption = true;
    allowed.header_encryption = options.features.header_encryption;
    allowed.file_comment = options.features.file_comment;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 encrypted stored file-service writer feature",
        });
    }
    Ok(())
}

struct HeaderEncryptionKeys {
    keys: Rar50Keys,
    salt: [u8; 16],
}

fn header_encryption_keys(password: &[u8]) -> Result<HeaderEncryptionKeys> {
    let mut salt = [0u8; 16];
    crate::write_entropy::fill(&mut salt, "RAR 5 writer could not generate encryption salt")?;
    let keys = Rar50Keys::derive(password, salt, 0).map_err(super::map_rar50_crypto_error)?;
    Ok(HeaderEncryptionKeys { keys, salt })
}

fn header_encryption_password<'a>(
    mut passwords: impl Iterator<Item = &'a [u8]>,
) -> Result<&'a [u8]> {
    let first = passwords.next().ok_or(Error::NeedPassword)?;
    for password in passwords {
        if password != first {
            return Err(Error::InvalidHeader(
                "RAR 5 header-encrypted writer needs one shared password",
            ));
        }
    }
    Ok(first)
}

fn write_head_crypt(out: &mut Vec<u8>, header_keys: &HeaderEncryptionKeys) -> Result<()> {
    let mut specific = Vec::new();
    write_vint(&mut specific, 0);
    write_vint(&mut specific, 0x0001);
    specific.push(0);
    specific.extend_from_slice(&header_keys.salt);
    specific.extend_from_slice(&header_keys.keys.password_check_record());
    write_block(out, BLOCK_TYPE_ENCRYPTION, 0, None, &specific, &[], &[])
}

fn archive_metadata_record(metadata: ArchiveMetadataEntry<'_>) -> Result<Vec<u8>> {
    if metadata.name.is_none() && metadata.creation_time.is_none() {
        return Err(Error::InvalidHeader(
            "RAR 5 archive metadata writer needs a name or creation time",
        ));
    }
    if metadata.name.is_some() && metadata.creation_time.is_none() {
        return Err(Error::InvalidHeader(
            "RAR 5 archive metadata name needs a creation time",
        ));
    }
    let mut flags = 0;
    if metadata.name.is_some() {
        flags |= METADATA_HAS_ARCHIVE_NAME;
    }
    if metadata.creation_time.is_some() {
        flags |= METADATA_HAS_CREATION_TIME;
    }

    let mut record = Vec::new();
    write_vint(&mut record, flags);
    if let Some(name) = metadata.name {
        if name.is_empty() {
            return Err(Error::InvalidHeader("RAR 5 archive metadata name is empty"));
        }
        write_vint(&mut record, name.len() as u64);
        record.extend_from_slice(name);
    }
    if let Some(creation_time) = metadata.creation_time {
        record.extend_from_slice(&creation_time.to_le_bytes());
    }

    let mut extra = Vec::new();
    write_extra_record(&mut extra, MAIN_EXTRA_METADATA, &record);
    Ok(extra)
}

fn write_locator_record(
    out: &mut Vec<u8>,
    quick_open_offset: Option<u64>,
    recovery_record_offset: Option<u64>,
) {
    let mut flags = 0;
    if quick_open_offset.is_some() {
        flags |= LOCATOR_HAS_QUICK_OPEN_OFFSET;
    }
    if recovery_record_offset.is_some() {
        flags |= LOCATOR_HAS_RECOVERY_RECORD_OFFSET;
    }

    let mut record = Vec::new();
    write_vint(&mut record, flags);
    if let Some(quick_open_offset) = quick_open_offset {
        write_vint(&mut record, quick_open_offset);
    }
    if let Some(recovery_record_offset) = recovery_record_offset {
        write_vint(&mut record, recovery_record_offset);
    }
    write_extra_record(out, MAIN_EXTRA_LOCATOR, &record);
}

fn write_stored_entry(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    hash_record: HashRecord,
) -> Result<()> {
    validate_entry(entry)?;
    write_stored_entry_fragment(
        out,
        entry,
        entry.data,
        entry.data.len() as u64,
        Some(crc32(entry.data)),
        false,
        false,
        hash_record,
    )
}

fn write_stored_compressed_entry(
    out: &mut Vec<u8>,
    entry: &CompressedEntry<'_>,
    hash_record: HashRecord,
) -> Result<()> {
    validate_compressed_entry(entry)?;
    let stored = stored_entry_from_compressed_entry(entry);
    write_stored_entry(out, &stored, hash_record)
}

fn stored_entry_from_compressed_entry<'a>(entry: &CompressedEntry<'a>) -> StoredEntry<'a> {
    StoredEntry {
        name: entry.name,
        data: entry.data,
        mtime: entry.mtime,
        attributes: entry.attributes,
        host_os: entry.host_os,
    }
}

#[allow(clippy::too_many_arguments)]
fn write_compressed_entry_payload(
    out: &mut Vec<u8>,
    entry: &CompressedEntry<'_>,
    packed: &[u8],
    algorithm_version: u8,
    compression_method: u8,
    dictionary_size: u64,
    solid_continuation: bool,
    digests: Option<PayloadDigests>,
    hash_record: HashRecord,
) -> Result<()> {
    let digests = digests.unwrap_or_else(|| payload_digests(entry.data, hash_record));
    let mut extra = Vec::new();
    if let Some(hash) = digests.blake2sp {
        write_hash_record_with_value(&mut extra, hash);
    }
    let compression_info = compression_info(
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
    )?;
    let (specific, time_extra) = file_specific(
        entry.name,
        entry.data.len() as u64,
        Some(digests.crc32),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    extra.extend_from_slice(&time_extra);
    let flags = if extra.is_empty() {
        BLOCK_HAS_DATA_AREA
    } else {
        BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA
    };
    write_block(
        out,
        BLOCK_TYPE_FILE,
        flags,
        Some(packed.len() as u64),
        &specific,
        &extra,
        packed,
    )
}

struct CompressedFragment<'a, 'b> {
    entry: &'a CompressedEntry<'b>,
    data: &'a [u8],
    algorithm_version: u8,
    compression_method: u8,
    dictionary_size: u64,
    solid_continuation: bool,
    split_before: bool,
    split_after: bool,
    hash_record: HashRecord,
    /// The member's digests when the resolver computed them beside the
    /// encode; `None` computes them here, on the last fragment.
    digests: Option<PayloadDigests>,
}

fn write_compressed_entry_fragment(
    out: &mut Vec<u8>,
    fragment: CompressedFragment<'_, '_>,
) -> Result<()> {
    let CompressedFragment {
        entry,
        data,
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
        split_before,
        split_after,
        hash_record,
        digests,
    } = fragment;

    let mut extra = Vec::new();
    if !split_after && hash_record == HashRecord::Blake2sp {
        match digests.and_then(|digests| digests.blake2sp) {
            Some(hash) => write_hash_record_with_value(&mut extra, hash),
            None => write_hash_record(&mut extra, entry.data),
        }
    }
    let compression_info = compression_info(
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
    )?;
    let (specific, time_extra) = file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then(|| digests.map_or_else(|| crc32(entry.data), |digests| digests.crc32)),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    extra.extend_from_slice(&time_extra);
    let mut block_flags = BLOCK_HAS_DATA_AREA;
    if split_before {
        block_flags |= BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME;
    }
    if split_after {
        block_flags |= BLOCK_CONTINUES_IN_NEXT_VOLUME;
    }
    if !extra.is_empty() {
        block_flags |= BLOCK_HAS_EXTRA_AREA;
    }

    write_block(
        out,
        BLOCK_TYPE_FILE,
        block_flags,
        Some(data.len() as u64),
        &specific,
        &extra,
        data,
    )
}

fn write_stored_entry_with_cache(
    out: &mut Vec<u8>,
    cached_headers: &mut Vec<CachedHeader>,
    entry: &StoredEntry<'_>,
    hash_record: HashRecord,
) -> Result<()> {
    validate_entry(entry)?;
    let mut extra = Vec::new();
    if hash_record == HashRecord::Blake2sp {
        write_hash_record(&mut extra, entry.data);
    }
    let (specific, time_extra) = stored_file_specific(
        entry.name,
        entry.data.len() as u64,
        Some(crc32(entry.data)),
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    extra.extend_from_slice(&time_extra);
    write_block_with_cache(
        out,
        cached_headers,
        BlockParts {
            header_type: BLOCK_TYPE_FILE,
            flags: if extra.is_empty() {
                BLOCK_HAS_DATA_AREA
            } else {
                BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA
            },
            data_size: Some(entry.data.len() as u64),
            type_specific: &specific,
            extra: &extra,
            data: entry.data,
        },
    )
}

/// An encrypted member's key material and digests, with its ciphertext
/// either held (a COMPRESSED member: the packed bytes are encrypted in the
/// buffer the encoder produced them in) or produced at emission (a STORED
/// member: `data` is empty, and the fragment writers encrypt the caller's
/// plaintext straight into the archive through a [`CipherStream`]).
///
/// Until 6 Sep 2026 every encrypted member was copied into a padded
/// buffer, encrypted there, and copied again into the archive - a stored
/// 1 GiB member held three gigabytes and cost 6.8 s on an 8-vCPU KVM
/// guest against rar's 2.3, most of it page faults. The bytes are the
/// same either way: CBC over the same plaintext under the same key and IV.
/// (nzbfast-local change, 6 Sep 2026; see VENDORING.md.)
struct EncryptedStoredPayload {
    /// The ciphertext, when it was produced up front; empty for a stored
    /// member, whose `stream_len` bytes are produced at emission.
    data: Vec<u8>,
    /// The padded stream's length when `data` is empty.
    padded_len: usize,
    key: [u8; 32],
    salt: [u8; 16],
    iv: [u8; 16],
    check_value: [u8; 12],
    crc32_mac: u32,
    /// `None` when the header carries the CRC32 MAC only.
    blake2sp_mac: Option<[u8; 32]>,
}

impl EncryptedStoredPayload {
    /// The length of the ciphertext stream the archive carries.
    fn stream_len(&self) -> usize {
        if self.data.is_empty() {
            self.padded_len
        } else {
            self.data.len()
        }
    }

    /// A fresh cipher over this member's stream, for emission from the
    /// plaintext; every fragment of one member goes through one stream.
    fn stream(&self) -> CipherStream {
        CipherStream::new(self.key, self.iv)
    }
}

/// AES-CBC over one member's padded plaintext, emitted straight into the
/// archive in fragments of any length: whole blocks are encrypted in place
/// where they land in the output, and a block that straddles a fragment
/// boundary is encrypted once into `pending` and paid out across the two
/// fragments.
struct CipherStream {
    cipher: Rar50Cipher,
    /// Ciphertext bytes emitted so far.
    emitted: usize,
    pending: [u8; 16],
    /// Bytes of `pending` (its tail) still owed to the next fragment.
    pending_len: usize,
}

impl CipherStream {
    fn new(key: [u8; 32], iv: [u8; 16]) -> Self {
        Self {
            cipher: Rar50Cipher::new(key, iv),
            emitted: 0,
            pending: [0; 16],
            pending_len: 0,
        }
    }

    /// The plaintext of the padded stream from `from`, `len` bytes, zero
    /// past the member's end.
    fn append_plain(out: &mut Vec<u8>, plain: &[u8], from: usize, len: usize) {
        let available = plain.len().saturating_sub(from).min(len);
        out.extend_from_slice(&plain[from..from + available]);
        out.resize(out.len() + (len - available), 0);
    }

    /// Append the ciphertext bytes from the last emitted one up to `end`.
    fn emit(&mut self, out: &mut Vec<u8>, plain: &[u8], end: usize) -> Result<()> {
        let padded_len = plain
            .len()
            .checked_add(15)
            .ok_or(Error::InvalidHeader("RAR 5 encrypted data size overflows"))?
            & !15;
        if end > padded_len || end < self.emitted {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted fragment is outside the member's stream",
            ));
        }
        if self.pending_len > 0 {
            let take = self.pending_len.min(end - self.emitted);
            let from = 16 - self.pending_len;
            out.extend_from_slice(&self.pending[from..from + take]);
            self.pending_len -= take;
            self.emitted += take;
        }
        let whole = (end - self.emitted) / 16 * 16;
        if whole > 0 {
            let start = out.len();
            Self::append_plain(out, plain, self.emitted, whole);
            self.cipher
                .encrypt_in_place(&mut out[start..])
                .map_err(super::map_rar50_crypto_error)?;
            self.emitted += whole;
        }
        let remainder = end - self.emitted;
        if remainder > 0 {
            let mut block = Vec::with_capacity(16);
            Self::append_plain(&mut block, plain, self.emitted, 16);
            self.cipher
                .encrypt_in_place(&mut block)
                .map_err(super::map_rar50_crypto_error)?;
            out.extend_from_slice(&block[..remainder]);
            self.pending.copy_from_slice(&block);
            self.pending_len = 16 - remainder;
            self.emitted += remainder;
        }
        Ok(())
    }
}

/// A block's data area: bytes in hand (plain, or ciphertext produced up
/// front), or plaintext to be encrypted into the archive up to stream
/// offset `end`.
enum BlockData<'a> {
    Bytes(&'a [u8]),
    Encrypt {
        plain: &'a [u8],
        end: usize,
        stream: &'a mut CipherStream,
    },
}

impl BlockData<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Bytes(data) => data.len(),
            Self::Encrypt { end, stream, .. } => end - stream.emitted,
        }
    }

    fn append_to(self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Bytes(data) => {
                out.extend_from_slice(data);
                Ok(())
            }
            Self::Encrypt { plain, end, stream } => stream.emit(out, plain, end),
        }
    }
}

/// A stored member's key material and digests; the ciphertext is produced
/// at emission from the same `data`.
fn encrypted_stored_payload(
    data: &[u8],
    password: &[u8],
    hash_record: HashRecord,
) -> Result<EncryptedStoredPayload> {
    let (keys, salt, iv) = encryption_keys(password)?;
    let padded_len = data
        .len()
        .checked_add(15)
        .ok_or(Error::InvalidHeader("RAR 5 encrypted data size overflows"))?
        & !15;
    Ok(encrypted_payload_with_keys(
        Vec::new(),
        padded_len,
        keys,
        salt,
        iv,
        data,
        hash_record,
    ))
}

/// A compressed member's packed bytes, encrypted in the buffer they came in.
fn encrypted_payload(
    mut packed_data: Vec<u8>,
    integrity_data: &[u8],
    password: &[u8],
    hash_record: HashRecord,
) -> Result<EncryptedStoredPayload> {
    let (keys, salt, iv) = encryption_keys(password)?;
    let padded_len = packed_data
        .len()
        .checked_add(15)
        .ok_or(Error::InvalidHeader("RAR 5 encrypted data size overflows"))?
        & !15;
    packed_data.resize(padded_len, 0);
    Rar50Cipher::new(keys.key, iv)
        .encrypt_in_place(&mut packed_data)
        .map_err(super::map_rar50_crypto_error)?;
    Ok(encrypted_payload_with_keys(
        packed_data,
        padded_len,
        keys,
        salt,
        iv,
        integrity_data,
        hash_record,
    ))
}

/// Salt and IV from the writer's entropy (in that order, which fixtures
/// under seeded entropy depend on), and the keys derived from them.
fn encryption_keys(password: &[u8]) -> Result<(Rar50Keys, [u8; 16], [u8; 16])> {
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    crate::write_entropy::fill(&mut salt, "RAR 5 writer could not generate encryption salt")?;
    crate::write_entropy::fill(&mut iv, "RAR 5 writer could not generate encryption IV")?;
    let keys = Rar50Keys::derive(password, salt, 0).map_err(super::map_rar50_crypto_error)?;
    Ok((keys, salt, iv))
}

fn encrypted_payload_with_keys(
    data: Vec<u8>,
    padded_len: usize,
    keys: Rar50Keys,
    salt: [u8; 16],
    iv: [u8; 16],
    integrity_data: &[u8],
    hash_record: HashRecord,
) -> EncryptedStoredPayload {
    EncryptedStoredPayload {
        data,
        padded_len,
        key: keys.key,
        salt,
        iv,
        check_value: keys.password_check_record(),
        crc32_mac: keys.mac_crc32(crc32(integrity_data)),
        blake2sp_mac: match hash_record {
            HashRecord::Crc32Only => None,
            HashRecord::Blake2sp => Some(keys.mac_hash32(blake2sp::hash(integrity_data))),
        },
    }
}

fn write_encrypted_stored_entry_fragment_with_header_keys(
    out: &mut Vec<u8>,
    entry: &EncryptedStoredEntry<'_>,
    data: BlockData<'_>,
    encrypted: &EncryptedStoredPayload,
    split_before: bool,
    split_after: bool,
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    let mut extra = Vec::new();
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    if !split_after {
        if let Some(mac) = encrypted.blake2sp_mac {
            write_hash_record_with_value(&mut extra, mac);
        }
    }

    let (specific, time_extra) = stored_file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(encrypted.crc32_mac),
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    extra.extend_from_slice(&time_extra);
    let mut block_flags = BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA;
    if split_before {
        block_flags |= BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME;
    }
    if split_after {
        block_flags |= BLOCK_CONTINUES_IN_NEXT_VOLUME;
    }

    let data_size = Some(data.len() as u64);
    if let Some(header_keys) = header_keys {
        append_encrypted_header_block_with(
            out,
            header_keys,
            BLOCK_TYPE_FILE,
            block_flags,
            data_size,
            &specific,
            &extra,
            data,
        )
    } else {
        write_block_with(
            out,
            BLOCK_TYPE_FILE,
            block_flags,
            data_size,
            &specific,
            &extra,
            data,
        )
    }
}

fn write_encrypted_stored_compressed_entry_with_header_keys(
    out: &mut Vec<u8>,
    entry: &EncryptedCompressedEntry<'_>,
    encrypted: &EncryptedStoredPayload,
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    validate_encrypted_compressed_entry(entry)?;
    let stored = encrypted_stored_entry_from_compressed_entry(entry);
    let mut stream = encrypted.stream();
    write_encrypted_stored_entry_fragment_with_header_keys(
        out,
        &stored,
        BlockData::Encrypt {
            plain: entry.data,
            end: encrypted.stream_len(),
            stream: &mut stream,
        },
        encrypted,
        false,
        false,
        header_keys,
    )
}

fn encrypted_stored_entry_from_compressed_entry<'a>(
    entry: &EncryptedCompressedEntry<'a>,
) -> EncryptedStoredEntry<'a> {
    EncryptedStoredEntry {
        name: entry.name,
        data: entry.data,
        mtime: entry.mtime,
        attributes: entry.attributes,
        host_os: entry.host_os,
        password: entry.password,
    }
}

struct EncryptedCompressedFragment<'a, 'b> {
    entry: &'a EncryptedCompressedEntry<'b>,
    data: BlockData<'a>,
    encrypted: &'a EncryptedStoredPayload,
    algorithm_version: u8,
    compression_method: u8,
    dictionary_size: u64,
    solid_continuation: bool,
    split_before: bool,
    split_after: bool,
}

fn write_encrypted_compressed_entry_fragment_with_header_keys(
    out: &mut Vec<u8>,
    fragment: EncryptedCompressedFragment<'_, '_>,
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    let EncryptedCompressedFragment {
        entry,
        data,
        encrypted,
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
        split_before,
        split_after,
    } = fragment;

    let mut extra = Vec::new();
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    if !split_after {
        if let Some(mac) = encrypted.blake2sp_mac {
            write_hash_record_with_value(&mut extra, mac);
        }
    }

    let compression_info = compression_info(
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
    )?;
    let (specific, time_extra) = file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(encrypted.crc32_mac),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    extra.extend_from_slice(&time_extra);
    let mut block_flags = BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA;
    if split_before {
        block_flags |= BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME;
    }
    if split_after {
        block_flags |= BLOCK_CONTINUES_IN_NEXT_VOLUME;
    }

    let data_size = Some(data.len() as u64);
    if let Some(header_keys) = header_keys {
        append_encrypted_header_block_with(
            out,
            header_keys,
            BLOCK_TYPE_FILE,
            block_flags,
            data_size,
            &specific,
            &extra,
            data,
        )?;
        Ok(())
    } else {
        write_block_with(
            out,
            BLOCK_TYPE_FILE,
            block_flags,
            data_size,
            &specific,
            &extra,
            data,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn write_stored_entry_fragment(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    data: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    split_before: bool,
    split_after: bool,
    hash_record: HashRecord,
) -> Result<()> {
    write_stored_entry_fragment_with_digests(
        out,
        entry,
        data,
        unpacked_size,
        data_crc32,
        split_before,
        split_after,
        hash_record,
        None,
    )
}

/// `blake2sp` is the whole-payload hash when the caller already has it;
/// `None` computes it here when the record is on, as every fragment writer
/// did before.
#[allow(clippy::too_many_arguments)]
fn write_stored_entry_fragment_with_digests(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    data: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    split_before: bool,
    split_after: bool,
    hash_record: HashRecord,
    blake2sp: Option<[u8; 32]>,
) -> Result<()> {
    let mut extra = Vec::new();
    if !split_before && !split_after && hash_record == HashRecord::Blake2sp {
        match blake2sp {
            Some(hash) => write_hash_record_with_value(&mut extra, hash),
            None => write_hash_record(&mut extra, data),
        }
    }
    let (specific, time_extra) = stored_file_specific(
        entry.name,
        unpacked_size,
        data_crc32,
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    extra.extend_from_slice(&time_extra);
    let mut block_flags = BLOCK_HAS_DATA_AREA;
    if split_before {
        block_flags |= BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME;
    }
    if split_after {
        block_flags |= BLOCK_CONTINUES_IN_NEXT_VOLUME;
    }
    if !extra.is_empty() {
        block_flags |= BLOCK_HAS_EXTRA_AREA;
    }

    write_block(
        out,
        BLOCK_TYPE_FILE,
        block_flags,
        Some(data.len() as u64),
        &specific,
        &extra,
        data,
    )
}

fn write_stored_service(out: &mut Vec<u8>, name: &[u8], data: &[u8]) -> Result<()> {
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FILE_EXTRA_SERVICE_DATA, &[]);
    let (specific, _no_time) =
        stored_file_specific(
            name,
            data.len() as u64,
            Some(crc32(data)),
            0,
            None,
            SERVICE_HOST_OS,
        )?;

    write_block(
        out,
        BLOCK_TYPE_SERVICE,
        BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA,
        Some(data.len() as u64),
        &specific,
        &extra,
        data,
    )
}

/// The recovery record's data over the archive so far - or, for a
/// MEASURING pass, zeros of exactly its length, so the block that follows
/// has the length the real one will and no parity is generated (see
/// `emit_resolved_writer_plan_recovery_direct`).
fn recovery_record_data(
    archive_prefix: &[u8],
    recovery_percent: u64,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
    placeholder: bool,
) -> Result<Vec<u8>> {
    if placeholder {
        let plan = crate::recovery::rar5::plan_inline_recovery(
            archive_prefix.len() as u64,
            recovery_percent,
        )?;
        let len = usize::try_from(plan.payload_size()?)
            .map_err(|_| Error::InvalidHeader("RAR 5 recovery record size overflows"))?;
        return Ok(vec![0u8; len]);
    }
    Ok(build_structural_inline_recovery_data_with_progress(
        archive_prefix,
        recovery_percent,
        progress,
        pass,
    )?)
}

fn write_recovery_service(
    out: &mut Vec<u8>,
    recovery_percent: u64,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
    placeholder: bool,
) -> Result<()> {
    let extra = recovery_service_extra(recovery_percent);
    let data = recovery_record_data(out, recovery_percent, progress, pass, placeholder)?;
    write_recovery_service_record(out, &extra, &data)
}

/// The recovery service block around a record already built: the streamed
/// stored writers compute the record from the bytes as they pass
/// (`InlineRecoveryFolder`) and append it through this.
pub(super) fn write_recovery_service_record(
    out: &mut Vec<u8>,
    extra: &[u8],
    data: &[u8],
) -> Result<()> {
    let (specific, _no_time) =
        stored_file_specific(
            b"RR",
            data.len() as u64,
            Some(crc32(data)),
            0,
            None,
            SERVICE_HOST_OS,
        )?;
    write_block(
        out,
        BLOCK_TYPE_SERVICE,
        BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA,
        Some(data.len() as u64),
        &specific,
        extra,
        data,
    )
}

/// The extra area of the recovery service block: the record's percentage.
pub(super) fn recovery_service_extra(recovery_percent: u64) -> Vec<u8> {
    let mut service_data = Vec::new();
    write_vint(&mut service_data, recovery_percent);
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FILE_EXTRA_SERVICE_DATA, &service_data);
    extra
}

fn write_stored_service_with_cache(
    out: &mut Vec<u8>,
    cached_headers: &mut Vec<CachedHeader>,
    name: &[u8],
    data: &[u8],
) -> Result<()> {
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FILE_EXTRA_SERVICE_DATA, &[]);
    let (specific, _no_time) =
        stored_file_specific(
            name,
            data.len() as u64,
            Some(crc32(data)),
            0,
            None,
            SERVICE_HOST_OS,
        )?;

    write_block_with_cache(
        out,
        cached_headers,
        BlockParts {
            header_type: BLOCK_TYPE_SERVICE,
            flags: BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA,
            data_size: Some(data.len() as u64),
            type_specific: &specific,
            extra: &extra,
            data,
        },
    )
}

fn write_encrypted_stored_service_with_header_keys(
    out: &mut Vec<u8>,
    name: &[u8],
    comment: EncryptedArchiveCommentEntry<'_>,
    header_keys: Option<&Rar50Keys>,
    hash_record: HashRecord,
) -> Result<()> {
    write_encrypted_service_with_header_keys(
        out,
        name,
        comment.data,
        &[],
        comment.password,
        header_keys,
        hash_record,
    )
}

fn write_header_encrypted_recovery_service(
    out: &mut Vec<u8>,
    recovery_percent: u64,
    header_keys: &Rar50Keys,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
    placeholder: bool,
) -> Result<()> {
    let mut service_data = Vec::new();
    write_vint(&mut service_data, recovery_percent);
    let data = recovery_record_data(out, recovery_percent, progress, pass, placeholder)?;
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FILE_EXTRA_SERVICE_DATA, &service_data);
    let (specific, _no_time) =
        stored_file_specific(
            b"RR",
            data.len() as u64,
            Some(crc32(&data)),
            0,
            None,
            SERVICE_HOST_OS,
        )?;
    append_encrypted_header_block(
        out,
        header_keys,
        BLOCK_TYPE_SERVICE,
        BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA,
        Some(data.len() as u64),
        &specific,
        &extra,
        &data,
    )?;
    Ok(())
}

fn write_encrypted_service_with_header_keys(
    out: &mut Vec<u8>,
    name: &[u8],
    data: &[u8],
    service_data: &[u8],
    password: &[u8],
    header_keys: Option<&Rar50Keys>,
    hash_record: HashRecord,
) -> Result<()> {
    validate_nonempty_password(password)?;
    let encrypted = encrypted_stored_payload(data, password, hash_record)?;
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FILE_EXTRA_SERVICE_DATA, service_data);
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    if let Some(mac) = encrypted.blake2sp_mac {
        write_hash_record_with_value(&mut extra, mac);
    }
    let (specific, _no_time) = stored_file_specific(
        name,
        data.len() as u64,
        Some(encrypted.crc32_mac),
        0,
        None,
        SERVICE_HOST_OS,
    )?;

    let stream_len = encrypted.stream_len();
    let mut stream = encrypted.stream();
    let data_size = Some(stream_len as u64);
    if let Some(header_keys) = header_keys {
        append_encrypted_header_block_with(
            out,
            header_keys,
            BLOCK_TYPE_SERVICE,
            BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA,
            data_size,
            &specific,
            &extra,
            BlockData::Encrypt {
                plain: data,
                end: stream_len,
                stream: &mut stream,
            },
        )
    } else {
        write_block_with(
            out,
            BLOCK_TYPE_SERVICE,
            BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA,
            data_size,
            &specific,
            &extra,
            BlockData::Encrypt {
                plain: data,
                end: stream_len,
                stream: &mut stream,
            },
        )
    }
}

fn stored_file_specific(
    name: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    attributes: u64,
    mtime: Option<u32>,
    host_os: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    file_specific(
        name,
        unpacked_size,
        data_crc32,
        attributes,
        mtime,
        0,
        host_os,
    )
}

/// The host-OS byte a member written on Windows carries.
const HOST_OS_WINDOWS: u64 = 0;

/// TIME extra record flag: the modification time is present. The
/// unix-format bit (0x01) beside it is what a Windows member leaves
/// CLEAR, which is how eight bytes of FILETIME are told from four of
/// Unix seconds.
const TIME_RECORD_HAS_MTIME: u64 = 0x02;

/// Unix epoch as a Windows FILETIME: 100-nanosecond ticks from
/// 1601-01-01 to 1970-01-01.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// The file-header type-specific bytes, and the TIME extra record that
/// has to go with them.
///
/// The second half is empty for a Unix member, whose whole-second time
/// fits the header's own `FILE_HAS_UNIX_MTIME` field. It is NOT empty for
/// a WINDOWS member: that field is Unix seconds by definition, and `rar`
/// on Windows carries the time as a Windows FILETIME in an extra record
/// instead - measured against rar 7.23 on an x86-64 Windows 11 box, 16 Sep 2026
/// (research/RARFAST-WINDOWS-CREATED-BYTES-2026-09-16.md).
///
/// It is returned rather than written, and the return type is a PAIR
/// rather than one buffer, so that every caller has to say what it does
/// with the record. Dropping the field without adding the record would
/// lose the member's time silently, at whichever site was missed.
fn file_specific(
    name: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    attributes: u64,
    mtime: Option<u32>,
    compression_info: u64,
    host_os: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file name is empty"));
    }
    let windows = host_os == HOST_OS_WINDOWS;
    let mut file_flags = if data_crc32.is_some() {
        FILE_HAS_CRC32
    } else {
        0
    };
    if mtime.is_some() && !windows {
        file_flags |= FILE_HAS_UNIX_MTIME;
    }
    let mut time_extra = Vec::new();
    if let Some(secs) = mtime.filter(|_| windows) {
        let mut record = Vec::new();
        write_vint(&mut record, TIME_RECORD_HAS_MTIME);
        let ticks = u64::from(secs) * 10_000_000 + FILETIME_UNIX_EPOCH;
        record.extend_from_slice(&ticks.to_le_bytes());
        write_extra_record(&mut time_extra, FILE_EXTRA_TIME, &record);
    }

    let mut specific = Vec::new();
    write_vint(&mut specific, file_flags);
    write_vint(&mut specific, unpacked_size);
    write_vint(&mut specific, attributes);
    if let Some(mtime) = mtime.filter(|_| !windows) {
        specific.extend_from_slice(&mtime.to_le_bytes());
    }
    if let Some(data_crc32) = data_crc32 {
        specific.extend_from_slice(&data_crc32.to_le_bytes());
    }
    write_vint(&mut specific, compression_info);
    write_vint(&mut specific, host_os);
    write_vint(&mut specific, name.len() as u64);
    specific.extend_from_slice(name);
    Ok((specific, time_extra))
}

fn validate_entry(entry: &StoredEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)
}

fn validate_compressed_entry(entry: &CompressedEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)
}

fn validate_encrypted_entry(entry: &EncryptedStoredEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)?;
    if entry.password.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted writer needs a non-empty password",
        ));
    }
    Ok(())
}

fn validate_encrypted_compressed_entry(entry: &EncryptedCompressedEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)?;
    if entry.password.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted writer needs a non-empty password",
        ));
    }
    Ok(())
}

fn validate_file_service(service: &StoredServiceEntry<'_>) -> Result<()> {
    if !matches!(service.name, b"ACL" | b"STM" | b"CMT") {
        return Err(Error::UnsupportedFeature {
            version: crate::ArchiveVersion::Rar50,
            feature: "RAR 5 stored file service name",
        });
    }
    if service.data.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 stored file service data is empty",
        ));
    }
    Ok(())
}

fn validate_encrypted_file_service(service: &EncryptedStoredServiceEntry<'_>) -> Result<()> {
    if !matches!(service.name, b"CMT") {
        return Err(Error::UnsupportedFeature {
            version: crate::ArchiveVersion::Rar50,
            feature: "RAR 5 encrypted stored file service name",
        });
    }
    if service.data.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted stored file service data is empty",
        ));
    }
    validate_nonempty_password(service.password)
}

fn validate_recovery_percent(percent: u64) -> Result<()> {
    if !(1..=100).contains(&percent) {
        return Err(Error::InvalidHeader(
            "RAR 5 recovery percent must be in 1..=100",
        ));
    }
    Ok(())
}

fn validate_nonempty_password(password: &[u8]) -> Result<()> {
    if password.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted writer needs a non-empty password",
        ));
    }
    Ok(())
}

fn validate_file_entry(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file name is empty"));
    }
    Ok(())
}

fn write_block(
    out: &mut Vec<u8>,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: &[u8],
) -> Result<()> {
    write_block_with(
        out,
        header_type,
        flags,
        data_size,
        type_specific,
        extra,
        BlockData::Bytes(data),
    )
}

/// `write_block` whose data area may be encrypted into place as it lands.
fn write_block_with(
    out: &mut Vec<u8>,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: BlockData<'_>,
) -> Result<()> {
    let header = block_header_image(header_type, flags, data_size, type_specific, extra)?;
    out.extend_from_slice(&header);
    data.append_to(out)
}

pub(super) fn write_end_header(out: &mut Vec<u8>, end_flags: u64) -> Result<()> {
    let header = block_header_image(
        BLOCK_TYPE_END_OF_ARCHIVE,
        0,
        None,
        &end_header_specific(end_flags),
        &[],
    )?;
    // The payload can fill the vector exactly. Geometric growth for this
    // final small header would retain a second archive's worth of capacity.
    out.reserve_exact(header.len());
    out.extend_from_slice(&header);
    Ok(())
}

pub(super) fn end_header_specific(end_flags: u64) -> Vec<u8> {
    let mut specific = Vec::new();
    write_vint(&mut specific, end_flags);
    specific
}

fn write_block_with_cache(
    out: &mut Vec<u8>,
    cached_headers: &mut Vec<CachedHeader>,
    parts: BlockParts<'_>,
) -> Result<()> {
    let offset = out.len();
    let header = block_header_image(
        parts.header_type,
        parts.flags,
        parts.data_size,
        parts.type_specific,
        parts.extra,
    )?;
    cached_headers.push(CachedHeader {
        offset,
        header: header.clone(),
    });
    out.extend_from_slice(&header);
    out.extend_from_slice(parts.data);
    Ok(())
}

fn quick_open_payload(cached_headers: &[CachedHeader], qo_pos: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for cached in cached_headers {
        let offset = qo_pos
            .checked_sub(cached.offset)
            .ok_or(Error::InvalidHeader(
                "RAR 5 quick-open cached header is after QO header",
            ))?;
        let mut body = Vec::new();
        write_vint(&mut body, 0);
        write_vint(&mut body, offset as u64);
        write_vint(&mut body, cached.header.len() as u64);
        body.extend_from_slice(&cached.header);

        out.extend_from_slice(&crc32(&body).to_le_bytes());
        write_vint(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
    }
    Ok(out)
}

fn encrypted_header_block(
    keys: &Rar50Keys,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_encrypted_header_block(
        &mut out,
        keys,
        header_type,
        flags,
        data_size,
        type_specific,
        extra,
        data,
    )?;
    Ok(out)
}

// nzbfast-local change, 5 Sep 2026 — see VENDORING.md.
// Write into the archive directly so encrypted member data is not copied
// through a second full-payload temporary buffer.
// The RAR 5 header shape, argument for argument: type, flags, data
// size, type-specific bytes, extra area and data, plus the output and
// the keys. A struct here would restate the format's own field list
// under a second set of names.
#[allow(clippy::too_many_arguments)]
fn append_encrypted_header_block(
    out: &mut Vec<u8>,
    keys: &Rar50Keys,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: &[u8],
) -> Result<()> {
    append_encrypted_header_block_with(
        out,
        keys,
        header_type,
        flags,
        data_size,
        type_specific,
        extra,
        BlockData::Bytes(data),
    )
}

/// `append_encrypted_header_block` whose data area may be encrypted into
/// place as it lands.
#[allow(clippy::too_many_arguments)]
fn append_encrypted_header_block_with(
    out: &mut Vec<u8>,
    keys: &Rar50Keys,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: BlockData<'_>,
) -> Result<()> {
    let header = block_header_image(header_type, flags, data_size, type_specific, extra)?;
    let mut iv = [0u8; 16];
    crate::write_entropy::fill(&mut iv, "RAR 5 writer could not generate encryption IV")?;
    let padded_len = header.len().checked_add(15).ok_or(Error::InvalidHeader(
        "RAR 5 encrypted header size overflows",
    ))? & !15;
    let mut encrypted_header = header;
    encrypted_header.resize(padded_len, 0);
    Rar50Cipher::new(keys.key, iv)
        .encrypt_in_place(&mut encrypted_header)
        .map_err(super::map_rar50_crypto_error)?;
    out.reserve(16 + encrypted_header.len() + data.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&encrypted_header);
    data.append_to(out)
}

fn block_header_image(
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    write_vint(&mut body, header_type);
    write_vint(&mut body, flags);
    if flags & BLOCK_HAS_EXTRA_AREA != 0 {
        write_vint(&mut body, extra.len() as u64);
    }
    if let Some(data_size) = data_size {
        write_vint(&mut body, data_size);
    }
    body.extend_from_slice(type_specific);
    body.extend_from_slice(extra);

    let mut header_size = Vec::new();
    write_vint(&mut header_size, body.len() as u64);

    let mut header = Vec::with_capacity(4 + header_size.len() + body.len());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&header_size);
    header.extend_from_slice(&body);
    let header_crc = crc32(&header[4..]);
    header[..4].copy_from_slice(&header_crc.to_le_bytes());
    Ok(header)
}

fn write_extra_record(out: &mut Vec<u8>, record_type: u64, data: &[u8]) {
    let mut body = Vec::new();
    write_vint(&mut body, record_type);
    body.extend_from_slice(data);
    write_vint(out, body.len() as u64);
    out.extend_from_slice(&body);
}

fn write_hash_record(out: &mut Vec<u8>, data: &[u8]) {
    write_hash_record_with_value(out, blake2sp::hash(data));
}

fn write_hash_record_with_value(out: &mut Vec<u8>, hash: [u8; 32]) {
    let mut record = Vec::new();
    write_vint(&mut record, 0);
    record.extend_from_slice(&hash);
    write_extra_record(out, FILE_EXTRA_HASH, &record);
}

fn write_file_encryption_record(
    out: &mut Vec<u8>,
    salt: [u8; 16],
    iv: [u8; 16],
    check_value: [u8; 12],
) {
    let mut record = Vec::new();
    write_vint(&mut record, 0);
    write_vint(&mut record, 0x0003);
    record.push(0);
    record.extend_from_slice(&salt);
    record.extend_from_slice(&iv);
    record.extend_from_slice(&check_value);
    write_extra_record(out, FILE_EXTRA_ENCRYPTION, &record);
}

fn write_vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::filter_policy::{
        auto_delta_filter_range, disjoint_filter_ranges, encode_member_with_auto_size_filter,
        encode_member_with_filter_policy_candidates, encode_member_with_filter_spec,
        encode_member_with_filter_specs,
    };
    use super::*;
    use crate::codec::rar50::Unpack50Encoder;
    use crate::codec::rar50::{encode_literal_only, encode_lz_member};
    use crate::codec::rar50::{encode_lz_member_with_options, EncodeOptions, Rar50FilterSpec};
    use crate::x86_filter_scan::auto_x86_filter_ranges;

    /// A member written with the WINDOWS host byte carries its time as a
    /// FILETIME in a TIME extra record, and leaves the header's own
    /// Unix-seconds field out - which is what `rar` 7.23 does on Windows,
    /// measured on an x86-64 Windows 11 box on 16 Sep 2026
    /// (research/RARFAST-WINDOWS-CREATED-BYTES-2026-09-16.md). This
    /// writer is the one the VOLUME set and the streamed routes go
    /// through; the reference-layout writer's own goldens are in
    /// `rar50::write::reference`.
    ///
    /// The check is on the header rather than on the whole archive
    /// because this writer's layout is the fork's own in other respects;
    /// the byte-for-byte claim for a volume set is the conformance leg's
    /// `add-volumes` row.
    #[test]
    fn a_windows_stored_member_carries_a_filetime_record_and_no_mtime_field() {
        fn one_member(host_os: u64) -> Vec<u8> {
            Rar50Writer::new(WriterOptions::new(
                ArchiveVersion::Rar50,
                FeatureSet::store_only(),
            ))
            .stored_entries(&[StoredEntry {
                name: b"a.txt",
                data: b"hello\n",
                mtime: Some(1_000_000_000),
                attributes: 0x20,
                host_os,
            }])
            .finish()
            .unwrap()
        }
        // 2001-09-09 01:46:40 UTC as a FILETIME, little-endian, behind
        // the record's size, type and flags bytes.
        let record = [
            0x0a, 0x03, 0x02, 0x00, 0x80, 0xff, 0x44, 0xd1, 0x38, 0xc1, 0x01,
        ];
        let windows = one_member(0);
        assert!(
            windows.windows(record.len()).any(|w| w == record),
            "a windows member should carry the FILETIME record"
        );
        // The Unix member does the opposite: the whole second sits in the
        // header field and there is no record at all.
        let unix = one_member(1);
        assert!(
            !unix.windows(record.len()).any(|w| w == record),
            "a unix member should not carry a FILETIME record"
        );
        assert!(
            unix.windows(4).any(|w| w == 1_000_000_000u32.to_le_bytes()),
            "a unix member keeps the whole second in the header's own field"
        );
        assert!(
            !windows
                .windows(4)
                .any(|w| w == 1_000_000_000u32.to_le_bytes()),
            "and a windows member does not, because that field is Unix seconds"
        );
    }

    /// Every service block this writer emits carries the WRITER's host
    /// byte, which is the opposite rule to the member beside it.
    ///
    /// The member here is given the OPPOSITE byte to this platform's, so
    /// the two rules are separated on Windows and on Unix alike rather
    /// than agreeing by coincidence on one of them - and the value is
    /// then pinned to the REFERENCE-layout writer's own service block
    /// rather than to a literal, because a literal is exactly what was
    /// wrong here. This writer wrote a hardcoded `0` in every service
    /// block from the start until 16 Sep 2026: the Windows answer, and
    /// invisible from a Mac by observation, which is the mirror of the
    /// bug `reference::SERVICE_HOST_OS` was named for.
    ///
    /// `CMT`, `QO` and `RR` are all three here because they are three
    /// different functions - `write_stored_service`,
    /// `write_stored_service_with_cache` and
    /// `write_recovery_service_record` - and the class of bug is one of
    /// them being missed. The member data is text so that the only
    /// pseudo-random region in the archive is the recovery parity, which
    /// FOLLOWS every header searched for below.
    #[test]
    fn every_service_block_carries_the_writers_host_os_not_the_members() {
        let platform_host = reference::SERVICE_HOST_OS as u8;
        let member_host = u64::from(1 - platform_host);
        let data = b"the quick brown fox jumps over the lazy dog\n".repeat(200);

        let mut features = FeatureSet::store_only();
        features.archive_comment = true;
        features.quick_open = true;
        let archive = Rar50Writer::new(WriterOptions::new(ArchiveVersion::Rar50, features))
            .stored_entries(&[StoredEntry {
                name: b"payload.txt",
                data: &data,
                mtime: Some(1_000_000_000),
                attributes: 0,
                host_os: member_host,
            }])
            .archive_comment(Some(b"a comment"))
            .finish()
            .expect("writes");

        // `RR` needs an archive of its own: the writer refuses a
        // recovery record beside a comment or a quick-open block.
        let with_recovery = Rar50Writer::new(WriterOptions::new(
            ArchiveVersion::Rar50,
            FeatureSet::store_only(),
        ))
        .stored_entries(&[StoredEntry {
            name: b"payload.txt",
            data: &data,
            mtime: Some(1_000_000_000),
            attributes: 0,
            host_os: member_host,
        }])
        .recovery_percent(Some(5))
        .finish()
        .expect("writes");

        // A service header's name is preceded by its length, and the
        // host-OS vint sits before that.
        fn service_host(archive: &[u8], name: &[u8]) -> u8 {
            let at = (2..archive.len() - name.len())
                .find(|&i| {
                    &archive[i..i + name.len()] == name && archive[i - 1] == name.len() as u8
                })
                .unwrap_or_else(|| {
                    panic!("no {} service header", String::from_utf8_lossy(name))
                });
            archive[at - 2]
        }

        for (blob, name) in [
            (&archive, &b"CMT"[..]),
            (&archive, b"QO"),
            (&with_recovery, b"RR"),
        ] {
            assert_eq!(
                service_host(blob, name),
                platform_host,
                "{} follows the writer, not the member's {member_host}",
                String::from_utf8_lossy(name),
            );
        }

        // And the same value the REFERENCE-layout writer reaches, read
        // out of its own quick-open block rather than compared against a
        // constant: the two writers disagreeing is how this arrives
        // again, and that is what cost nineteen conformance rows once.
        let big = vec![7u8; 4097];
        let reference_archive = reference::write_reference_stored(
            &[reference::ReferenceMember {
                name: "big.bin",
                data: &big,
                mtime: None,
                attributes: 0,
                host_os: member_host,
                is_dir: false,
            }],
            reference::ReferenceHash::Crc32,
            reference::ReferenceQuickOpen::All,
        )
        .expect("writes");
        assert_eq!(
            service_host(&reference_archive, b"QO"),
            platform_host,
            "the two service writers are one rule, not two",
        );
    }

    #[test]
    fn finishing_a_large_archive_does_not_double_its_capacity() {
        let data = vec![42u8; 1 << 20];
        let archive = Rar50Writer::new(WriterOptions::new(
            ArchiveVersion::Rar50,
            FeatureSet::default(),
        ))
        .stored_entries(&[StoredEntry {
            name: b"payload.bin",
            data: &data,
            mtime: None,
            attributes: 0,
            host_os: 3,
        }])
        .finish()
        .unwrap();
        assert!(archive.len() > data.len());
        assert!(
            archive.capacity() <= archive.len() + 4096,
            "finished archive retains {} bytes for {} bytes of output",
            archive.capacity(),
            archive.len()
        );
    }

    use crate::{ArchiveVersion, FeatureSet};
    use std::cell::RefCell;
    use std::fs;
    use std::io::{Result as IoResult, Write};
    use std::process::Command;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn compressed_writer_without_reporter_matches_reporting_archive_bytes() {
        let data: Vec<u8> = (0..4 * 1024 * 1024 + 513)
            .map(|i| (i % 251) as u8)
            .collect();
        let entry = CompressedEntry {
            name: b"payload.bin",
            data: &data,
            mtime: None,
            attributes: 0,
            host_os: 3,
        };
        let reporter = |_: WriteProgressEvent<'_>| {};
        for level in [1, 5] {
            let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::default())
                .with_compression_level(level);
            let plain = Rar50Writer::new(options)
                .compressed_entries(&[entry])
                .finish()
                .unwrap();
            let reporting = Rar50Writer::new(options)
                .compressed_entries(&[entry])
                .progress(&reporter)
                .finish()
                .unwrap();
            assert_eq!(plain, reporting, "compression level {level}");
        }
    }

    struct CollectWriter(Rc<RefCell<Vec<u8>>>);

    #[test]
    fn compressed_writer_reports_determinate_progress() {
        let data: Vec<u8> = (0usize..128 * 1024)
            .map(|i| (i.wrapping_mul(37) % 251) as u8)
            .collect();
        let entry = CompressedEntry {
            name: b"payload.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 1,
        };
        let last = std::sync::atomic::AtomicU64::new(0);
        let advances = AtomicUsize::new(0);
        let intermediate = std::sync::atomic::AtomicBool::new(false);
        let reporter = |event: WriteProgressEvent<'_>| {
            if let WriteProgressEvent::Advanced {
                operation: WriteOperation::Compression,
                completed_bytes,
                total_bytes,
                ..
            } = event
            {
                assert!(completed_bytes >= last.swap(completed_bytes, Ordering::Relaxed));
                assert!(completed_bytes <= total_bytes);
                if completed_bytes < total_bytes {
                    intermediate.store(true, Ordering::Relaxed);
                }
                advances.fetch_add(1, Ordering::Relaxed);
            }
        };

        Rar50Writer::new(WriterOptions::new(
            ArchiveVersion::Rar70,
            FeatureSet::default(),
        ))
        .compressed_entries(&[entry])
        .filter_policy(FilterPolicy::AutoSize)
        .progress(&reporter)
        .finish()
        .unwrap();

        assert!(advances.load(Ordering::Relaxed) >= 1);
        assert!(intermediate.load(Ordering::Relaxed));
        assert!(last.load(Ordering::Relaxed) > data.len() as u64);
    }

    /// A member with a numeric middle: text, 4-byte counter records, noise,
    /// one filter region each side of the records.
    fn sampled_filter_member() -> Vec<u8> {
        let region = super::filter_policy::SAMPLED_FILTER_REGION;
        let mut data = Vec::with_capacity(region * 4);
        while data.len() < region {
            data.extend_from_slice(b"a text region that wants no filter at all, only matches\n");
        }
        data.truncate(region);
        let mut counter: u32 = 0x4000_0000;
        while data.len() < region * 3 {
            data.extend_from_slice(&counter.to_le_bytes());
            counter = counter.wrapping_add(6011);
        }
        data.truncate(region * 3);
        let mut seed = 0x9e37_79b9u32;
        while data.len() < region * 4 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            data.push(seed as u8);
        }
        data
    }

    fn extract_volume_bytes(volumes: &[Vec<u8>]) -> Vec<u8> {
        use std::cell::RefCell;
        use std::rc::Rc;
        struct Shared(Rc<RefCell<Vec<u8>>>);
        impl std::io::Write for Shared {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let parsed: Vec<Archive> = volumes
            .iter()
            .map(|volume| Archive::parse(volume).unwrap())
            .collect();
        let captured = Rc::new(RefCell::new(Vec::new()));
        let sink = captured.clone();
        crate::rar50::extract_volumes_to(
            &parsed,
            crate::ArchiveReadOptions::default(),
            move |_meta| Ok(Box::new(Shared(sink.clone()))),
        )
        .unwrap();
        let out = captured.borrow().clone();
        out
    }

    /// `FilterPolicy::Sampled` reaches both writers: the archive and the
    /// volume set are smaller than under `None`, extract to the input, and
    /// the solid forms of both refuse the policy as they refuse every
    /// filtering policy.
    #[test]
    fn sampled_filter_policy_reaches_the_archive_and_the_volume_set() {
        let data = sampled_filter_member();
        let entry = CompressedEntry {
            name: b"records.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        };
        let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::default())
            .with_dictionary_size(4 << 20);
        let archive = |policy| {
            Rar50Writer::new(options)
                .compressed_entries(std::slice::from_ref(&entry))
                .filter_policy(policy)
                .finish()
                .unwrap()
        };
        let plain = archive(FilterPolicy::None);
        let sampled = archive(FilterPolicy::Sampled);
        assert!(
            sampled.len() < plain.len(),
            "{} vs {}",
            sampled.len(),
            plain.len()
        );
        assert_eq!(extract_volume_bytes(std::slice::from_ref(&sampled)), data);

        let volumes = |policy| {
            Rar50VolumeWriter::new(options)
                .max_payload_per_volume(200_000)
                .compressed_entries(std::slice::from_ref(&entry))
                .filter_policy(policy)
                .finish()
                .unwrap()
        };
        let plain = volumes(FilterPolicy::None);
        let sampled = volumes(FilterPolicy::Sampled);
        let total = |set: &[Vec<u8>]| set.iter().map(Vec::len).sum::<usize>();
        assert!(sampled.len() > 1, "the set splits");
        assert!(total(&sampled) < total(&plain));
        assert_eq!(extract_volume_bytes(&sampled), data);

        let solid = FeatureSet {
            solid: true,
            ..FeatureSet::default()
        };
        let solid = WriterOptions::new(ArchiveVersion::Rar50, solid).with_dictionary_size(4 << 20);
        assert!(matches!(
            Rar50Writer::new(solid)
                .compressed_entries(std::slice::from_ref(&entry))
                .filter_policy(FilterPolicy::Sampled)
                .finish(),
            Err(Error::UnsupportedFeature { .. })
        ));
        assert!(matches!(
            Rar50VolumeWriter::new(solid)
                .max_payload_per_volume(200_000)
                .compressed_entries(std::slice::from_ref(&entry))
                .filter_policy(FilterPolicy::Sampled)
                .finish(),
            Err(Error::UnsupportedFeature { .. })
        ));
        assert!(matches!(
            Rar50VolumeWriter::new(options)
                .max_payload_per_volume(200_000)
                .compressed_entries(std::slice::from_ref(&entry))
                .filter_policy(FilterPolicy::AutoSize)
                .finish(),
            Err(Error::UnsupportedFeature { .. })
        ));
    }

    /// The in-memory volume writer sets the END header's next-volume flag
    /// on every volume but the last - including a volume a member ends
    /// EXACTLY on, the shape native unrar 7.23 stopped at when every
    /// volume said "last" (7 Sep 2026; the fixture is Codex's probe: two
    /// 64-byte members in two 119-byte volumes). Native `rar x` extracts
    /// both members from this writer's output now; here our reader does.
    #[test]
    fn volume_sets_flag_the_next_volume_on_every_volume_but_the_last() {
        let end_flags = |volume: &Vec<u8>| *volume.last().unwrap();
        static A: [u8; 64] = [b'A'; 64];
        static B: [u8; 64] = [b'B'; 64];
        let (a, b) = (&A, &B);
        let entry = |name: &'static [u8], data: &'static [u8]| StoredEntry {
            name,
            data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        };
        let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
        let two = [entry(b"payload0.bin", a), entry(b"payload1.bin", b)];
        let volumes = Rar50VolumeWriter::new(options)
            .max_payload_per_volume(64)
            .stored_entries(&two)
            .finish()
            .unwrap();
        assert_eq!(
            volumes.iter().map(|v| v.len()).collect::<Vec<_>>(),
            vec![119, 119]
        );
        assert_eq!(
            volumes.iter().map(end_flags).collect::<Vec<_>>(),
            vec![1, 0]
        );
        assert_eq!(
            extract_volume_bytes(&volumes),
            [a.as_slice(), b.as_slice()].concat()
        );

        // A member split over three volumes: [next, next, last].
        let long: &'static [u8] = Box::leak(vec![b'C'; 150].into_boxed_slice());
        let volumes = Rar50VolumeWriter::new(options)
            .max_payload_per_volume(64)
            .stored_entries(&[entry(b"long.bin", long)])
            .finish()
            .unwrap();
        assert_eq!(
            volumes.iter().map(end_flags).collect::<Vec<_>>(),
            vec![1, 1, 0]
        );

        // With a recovery record, which takes the body-then-wrap path.
        let mut with_record = FeatureSet::store_only();
        with_record.recovery_record = true;
        let volumes =
            Rar50VolumeWriter::new(WriterOptions::new(ArchiveVersion::Rar50, with_record))
                .max_payload_per_volume(64)
                .recovery_percent(Some(3))
                .stored_entries(&two)
                .finish()
                .unwrap();
        assert_eq!(
            volumes.iter().map(end_flags).collect::<Vec<_>>(),
            vec![1, 0]
        );
        assert_eq!(
            extract_volume_bytes(&volumes),
            [a.as_slice(), b.as_slice()].concat()
        );

        // Compressed entries of the same shape: noise, which the writer
        // stores, so the fragments cut exactly as the stored set's did.
        let noise = |seed: u32| -> &'static [u8] {
            let mut x = seed;
            Box::leak(
                (0..64)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 17;
                        x ^= x << 5;
                        x as u8
                    })
                    .collect::<Vec<u8>>()
                    .into_boxed_slice(),
            )
        };
        let compressed = [
            CompressedEntry {
                name: b"payload0.bin",
                data: noise(7),
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
            CompressedEntry {
                name: b"payload1.bin",
                data: noise(11),
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
        ];
        let volumes = Rar50VolumeWriter::new(WriterOptions::new(
            ArchiveVersion::Rar50,
            FeatureSet::default(),
        ))
        .max_payload_per_volume(64)
        .compressed_entries(&compressed)
        .finish()
        .unwrap();
        assert_eq!(
            volumes.iter().map(end_flags).collect::<Vec<_>>(),
            vec![1, 0]
        );
    }

    #[test]
    fn recovery_writer_reports_determinate_pass_progress() {
        let entry = StoredEntry {
            name: b"payload.bin",
            data: b"recovery progress payload",
            mtime: None,
            attributes: 0x20,
            host_os: 1,
        };
        let starts = AtomicUsize::new(0);
        let advances = AtomicUsize::new(0);
        let finishes = AtomicUsize::new(0);
        let reporter = |event: WriteProgressEvent<'_>| match event {
            WriteProgressEvent::OperationStarted {
                operation: WriteOperation::Recovery,
                total_bytes: Some(total),
                ..
            } => {
                assert!(total > 0);
                starts.fetch_add(1, Ordering::Relaxed);
            }
            WriteProgressEvent::Advanced {
                operation: WriteOperation::Recovery,
                completed_bytes,
                total_bytes,
                ..
            } => {
                assert!(completed_bytes <= total_bytes);
                advances.fetch_add(1, Ordering::Relaxed);
            }
            WriteProgressEvent::OperationFinished {
                operation: WriteOperation::Recovery,
                ..
            } => {
                finishes.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        };
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;

        Rar50Writer::new(WriterOptions::new(ArchiveVersion::Rar50, features))
            .stored_entries(&[entry])
            .recovery_percent(Some(10))
            .progress(&reporter)
            .finish()
            .unwrap();

        assert!(starts.load(Ordering::Relaxed) >= 1);
        assert!(advances.load(Ordering::Relaxed) >= 1);
        assert_eq!(
            starts.load(Ordering::Relaxed),
            finishes.load(Ordering::Relaxed)
        );
    }

    impl Write for CollectWriter {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CollectedEntry {
        name: Vec<u8>,
        data: Vec<u8>,
        file_time: u32,
        attr: u64,
        host_os: u64,
        is_directory: bool,
    }

    fn collect_extract(archive: &Archive) -> Result<Vec<CollectedEntry>> {
        collect_extract_with_options(archive, crate::ArchiveReadOptions::default())
    }

    fn collect_extract_with_options(
        archive: &Archive,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        archive.extract_to(options, |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter(data)))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                attr: meta.attr,
                host_os: meta.host_os,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    #[test]
    fn writer_plan_offset_resolution_errors_if_offset_never_converges() {
        let mut offsets = Vec::new();
        let result = resolve_writer_plan_offset(
            |offset, _| {
                offsets.push(offset);
                Ok((Vec::new(), Some(offset + 1)))
            },
            "missing offset",
            "did not converge",
        );

        assert!(matches!(
            result,
            Err(Error::InvalidHeader("did not converge"))
        ));
        assert_eq!(offsets, [0, 1, 2, 3]);
    }

    #[test]
    fn writer_plan_offset_resolution_rejects_missing_reported_offset() {
        let result = resolve_writer_plan_offset(
            |_, _| Ok((Vec::new(), None)),
            "missing offset",
            "did not converge",
        );

        assert!(matches!(
            result,
            Err(Error::InvalidHeader("missing offset"))
        ));
    }

    #[test]
    fn internal_literal_only_compressed_member_round_trips_through_rar50_reader() {
        let data = b"RAR5 literal-only compressed format-layer experiment\n";
        let packed = encode_literal_only(data, 0).unwrap();
        let name = b"compressed.txt";

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR50_SIGNATURE);
        write_main_header(&mut archive, 0, None, &[]).unwrap();

        let mut extra = Vec::new();
        write_hash_record(&mut extra, data);
        let compression_info = 1 << 7; // RAR5 v0, non-solid, method m1, 128 KiB dictionary.
        let (specific, _no_time) = file_specific(
            name,
            data.len() as u64,
            Some(crc32(data)),
            0x20,
            None,
            compression_info,
            0,
        )
        .unwrap();
        write_block(
            &mut archive,
            BLOCK_TYPE_FILE,
            BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA,
            Some(packed.len() as u64),
            &specific,
            &extra,
            &packed,
        )
        .unwrap();
        write_end_header(&mut archive, 0).unwrap();

        let parsed = Archive::parse(&archive).unwrap();
        let file = parsed.files().next().unwrap();
        let info = file.decoded_compression_info().unwrap();
        assert_eq!(info.method, 1);
        assert_eq!(info.dictionary_size, 128 * 1024);

        let extracted = collect_extract(&parsed).unwrap();
        assert_eq!(extracted[0].name, name);
        assert_eq!(extracted[0].data, data);
    }

    /// The hash record is off by default and on request, on every member
    /// kind the single-volume writer emits, and a reader extracts either
    /// way: with the record off it verifies the CRC32 (the MAC'd CRC32 for
    /// an encrypted member), with it on it verifies the BLAKE2sp.
    #[test]
    fn hash_record_off_by_default_and_on_request() {
        let data: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog "
            .iter()
            .copied()
            .cycle()
            .take(200_000)
            .collect();
        for (hash_record, expect_record) in [
            (None, false),
            (Some(HashRecord::Crc32Only), false),
            (Some(HashRecord::Blake2sp), true),
        ] {
            let mut options =
                WriterOptions::new(crate::ArchiveVersion::Rar50, crate::FeatureSet::default());
            if let Some(hash_record) = hash_record {
                options = options.with_hash_record(hash_record);
            }
            let stored = Rar50Writer::new(options)
                .stored_entries(&[StoredEntry {
                    name: b"stored.bin",
                    data: &data,
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                }])
                .finish()
                .unwrap();
            let compressed = Rar50Writer::new(options)
                .compressed_entries(&[
                    CompressedEntry {
                        name: b"text.bin",
                        data: &text,
                        mtime: None,
                        attributes: 0,
                        host_os: 3,
                    },
                    CompressedEntry {
                        name: b"noise.bin",
                        data: &data,
                        mtime: None,
                        attributes: 0,
                        host_os: 3,
                    },
                ])
                .finish()
                .unwrap();
            let features = crate::FeatureSet {
                file_encryption: true,
                ..crate::FeatureSet::default()
            };
            let mut encrypted_options = WriterOptions::new(crate::ArchiveVersion::Rar50, features);
            if let Some(hash_record) = hash_record {
                encrypted_options = encrypted_options.with_hash_record(hash_record);
            }
            let encrypted = Rar50Writer::new(encrypted_options)
                .encrypted_stored_entries(&[EncryptedStoredEntry {
                    name: b"secret.bin",
                    data: &data,
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                    password: b"pw",
                }])
                .finish()
                .unwrap();
            for (label, archive, password) in [
                ("stored", &stored, None),
                ("compressed", &compressed, None),
                ("encrypted", &encrypted, Some(&b"pw"[..])),
            ] {
                let parsed = match password {
                    Some(pw) => Archive::parse_with_options(
                        archive,
                        crate::ArchiveReadOptions::with_password(pw),
                    )
                    .unwrap(),
                    None => Archive::parse(archive).unwrap(),
                };
                for file in parsed.files() {
                    assert_eq!(
                        file.hash.is_some(),
                        expect_record,
                        "{label} {hash_record:?}: hash record presence"
                    );
                    if let Some(hash) = &file.hash {
                        assert_eq!((hash.hash_type, hash.data.len()), (0, 32), "{label}");
                    }
                }
                let extracted = match password {
                    Some(pw) => collect_extract_with_options(
                        &parsed,
                        crate::ArchiveReadOptions::with_password(pw),
                    )
                    .unwrap(),
                    None => collect_extract(&parsed).unwrap(),
                };
                assert!(!extracted.is_empty(), "{label}");
                assert!(
                    extracted.iter().any(|entry| entry.data == data),
                    "{label} {hash_record:?}: the noise member reads back"
                );
            }
        }
    }

    #[test]
    fn writer_stamps_requested_rar50_dictionary_size() {
        // Past half the request, so the payload fit leaves the request
        // alone (a 2.7 KB fixture would declare the 128 KiB floor).
        let data = b"RAR5 dictionary-size writer option fixture".repeat(7_000);
        assert!(data.len() as u64 * 2 > 512 * 1024);
        let options =
            WriterOptions::new(crate::ArchiveVersion::Rar50, crate::FeatureSet::default())
                .with_dictionary_size(512 * 1024);
        let entries = [CompressedEntry {
            name: b"dict.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let archive = Rar50Writer::new(options)
            .compressed_entries(&entries)
            .finish()
            .unwrap();

        let parsed = Archive::parse(&archive).unwrap();
        let info = parsed
            .files()
            .next()
            .unwrap()
            .decoded_compression_info()
            .unwrap();
        let extracted = collect_extract(&parsed).unwrap();

        assert_eq!(info.algorithm_version, 0);
        assert_eq!(info.dictionary_size, 512 * 1024);
        assert_eq!(extracted[0].data, data);
    }

    /// The declared dictionary is fitted to the payload as rar fits it,
    /// on every writer: the single archive, the volume set, the streamed
    /// archive; a solid set fits its total; a member that can use the whole
    /// default keeps it. The expectations below are written against
    /// `DEFAULT_RAR50_DICTIONARY_SIZE` rather than a literal, so that moving
    /// the default moves the test with it instead of reddening it - which is
    /// what happened when the default went 32 MiB to 2 MiB on 8 Sep 2026.
    /// (7 Sep 2026.)
    /// Bounding the writer's memory is a MEMORY decision and never a ratio
    /// one: the allowance chooses how many blocks are in flight, and the
    /// same bytes come out at any width. This is the property that lets a
    /// small target set a policy at all, so it is pinned on a payload wide
    /// enough to run a real wave.
    #[test]
    fn a_write_policy_narrows_the_wave_without_moving_the_archive() {
        let data: Vec<u8> = (0..340_000u32)
            .flat_map(|line| format!("record {line:08} of a compressible member\n").into_bytes())
            .collect();
        assert!(
            data.len() > 3 * crate::codec::rar50::MAX_COMPRESSED_BLOCK_OUTPUT,
            "wide enough for several blocks in flight, not one"
        );
        let entries = [CompressedEntry {
            name: b"payload.txt",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let base = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::default());
        // 200 MiB: half of it is under two 72 MiB blocks in flight, so the
        // wave narrows to one - while a quarter of it still admits a
        // dictionary far wider than this payload's fitted one, which keeps
        // this a test of the wave and not of the dictionary clamp.
        let policy = crate::Rar50WritePolicy::from_working_memory(200 << 20);
        assert!(policy.max_dictionary >= DEFAULT_RAR50_DICTIONARY_SIZE);
        let bounded = base.with_write_policy(Some(policy));
        // Without this the equality below could pass by both arms choosing
        // the same width, which is the shape of a test that verifies
        // nothing. On a single-core box the widths agree legitimately, so
        // this only asserts a difference where one is available.
        let width = |working| {
            crate::codec::rar50::encode_block_wave_width_for_budget(
                DEFAULT_RAR50_DICTIONARY_SIZE as usize,
                false,
                working,
            )
        };
        if width(None) > 1 {
            assert!(
                width(Some(200 << 20)) < width(None),
                "the allowance did not narrow the wave ({} against {}), so the \
                 equality below would prove nothing",
                width(Some(200 << 20)),
                width(None),
            );
        }

        let unbounded_archive = Rar50Writer::new(base)
            .compressed_entries(&entries)
            .finish()
            .unwrap();
        let bounded_archive = Rar50Writer::new(bounded)
            .compressed_entries(&entries)
            .finish()
            .unwrap();
        assert_eq!(
            unbounded_archive,
            bounded_archive,
            "a memory allowance moved {} bytes of archive",
            unbounded_archive.len(),
        );
    }

    /// The allowance REDUCES a dictionary it cannot index and never raises
    /// one, it lands on a legal power-of-two size, and it stops at the
    /// format's own floor rather than inventing something smaller.
    #[test]
    fn a_write_policy_admits_only_the_dictionary_it_can_index() {
        use super::filter_policy::admitted_dictionary_size;
        let admitted = |working: u64, requested: u64| {
            admitted_dictionary_size(
                ArchiveVersion::Rar50,
                requested,
                Some(crate::Rar50WritePolicy::from_working_memory(working)),
            )
        };
        // No policy is no reduction.
        assert_eq!(
            admitted_dictionary_size(ArchiveVersion::Rar50, 32 << 20, None),
            32 << 20
        );
        // A quarter of the allowance, at ten tree bytes per dictionary byte:
        // 1 GiB admits 25.6 MiB, so a 32 MiB request halves once.
        assert_eq!(admitted(1 << 30, 32 << 20), 16 << 20);
        // A budget that affords the request keeps every byte of it.
        assert_eq!(admitted(16 << 30, 32 << 20), 32 << 20);
        // Never raises what the caller asked for.
        assert_eq!(admitted(16 << 30, 1 << 20), 1 << 20);
        // Never below the format floor, however small the allowance.
        assert_eq!(
            admitted(1 << 20, 32 << 20),
            crate::Rar50WritePolicy::MIN_DICTIONARY
        );
        // Every reduction is still a legal RAR 5 dictionary.
        for shift in 17..=32 {
            let size = admitted(3 << 30, 1u64 << shift);
            super::filter_policy::validate_dictionary_size(ArchiveVersion::Rar50, size).unwrap();
        }
    }

    /// A policy charges each member's match-finder tree by narrowing how
    /// many members encode at once, and that is a MEMORY decision like the
    /// wave: the same archive comes out at any member width. Pinned at a
    /// dictionary the tree arms at, on a set of several members, through
    /// the single archive and the volume set - the two `map_collect`
    /// admission sites postfast reaches. (15 Sep 2026, TODO 349 B.)
    #[test]
    fn a_policy_charges_member_trees_without_moving_the_archive() {
        use super::filter_policy::{encode_options_for_level, members_in_flight_for};
        const DICTIONARY: u64 = 4 << 20;
        let member = |seed: u32| -> Vec<u8> {
            (0..80_000u32)
                .flat_map(|line| {
                    format!("member {seed} record {line:08} {}\n", line.wrapping_mul(2_654_435_761) % 997)
                        .into_bytes()
                })
                .collect()
        };
        let datas = [member(1), member(2), member(3)];
        assert!(
            datas.iter().all(|data| data.len() as u64 > DICTIONARY / 2),
            "every member wide enough that the payload fit keeps the 4 MiB the tree arms at"
        );
        let entries: Vec<_> = datas
            .iter()
            .enumerate()
            .map(|(index, data)| CompressedEntry {
                name: [b"a.txt", b"b.txt", b"c.txt"][index],
                data,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            })
            .collect();

        // 160 MiB: a quarter is 40 MiB, one 4 MiB tree, so it admits the
        // whole dictionary and ONE member at a time. An unbounded allowance
        // admits every member of the set at once. Without these the equality
        // below could pass by both arms choosing the same width.
        //
        // Unbounded is `usize::MAX`, not `64 << 30`: on 32-bit that literal
        // is not flagged (the shift is under the width) and wraps to 0,
        // which admits one member and failed the armv7-cross RUN.
        // `members_in_flight_for` only divides the allowance, so the
        // maximum cannot overflow it. (nzbfast-local change, 15 Sep 2026;
        // see VENDORING.md.)
        let width = |working: Option<usize>| {
            members_in_flight_for(&[encode_options_for_level(
                None,
                DICTIONARY,
                false,
                true,
                false,
                working,
            )
            .unwrap()])
        };
        assert_eq!(width(Some(160 << 20)), 1);
        assert!(width(Some(usize::MAX)) >= entries.len());
        assert_eq!(width(None), usize::MAX, "no policy, no bound");
        assert_eq!(
            members_in_flight_for(&[encode_options_for_level(
                None,
                DICTIONARY / 2,
                false,
                true,
                false,
                Some(160 << 20),
            )
            .unwrap()]),
            usize::MAX,
            "a dictionary under the tree's arming point holds no tree to charge"
        );

        let base = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::default())
            .with_dictionary_size(DICTIONARY);
        let narrow = base.with_write_policy(Some(crate::Rar50WritePolicy::from_working_memory(
            160 << 20,
        )));
        let wide = base.with_write_policy(Some(crate::Rar50WritePolicy::from_working_memory(
            64 << 30,
        )));
        let archive = |options| {
            Rar50Writer::new(options)
                .compressed_entries(&entries)
                .finish()
                .unwrap()
        };
        let one_at_a_time = archive(narrow);
        let declared: Vec<u64> = Archive::parse(&one_at_a_time)
            .unwrap()
            .files()
            .map(|file| file.decoded_compression_info().unwrap().dictionary_size)
            .collect();
        assert_eq!(declared, vec![DICTIONARY; 3], "the tree armed on every member");
        assert_eq!(archive(wide), one_at_a_time, "member width moved the single archive");
        assert_eq!(archive(base), one_at_a_time, "the policy moved the single archive");

        let volumes = |options| {
            Rar50VolumeWriter::new(options)
                .max_payload_per_volume(16 << 10)
                .compressed_entries(&entries)
                .finish()
                .unwrap()
        };
        assert_eq!(volumes(wide), volumes(narrow), "member width moved the volume set");

        // And the streamed writer's small-member queue, the third site,
        // which is byte-identical to the in-memory writer at any width.
        let streamed = |options| {
            let mut sources: Vec<_> = entries
                .iter()
                .map(|entry| {
                    let (size, crc32) = crc32_of_reader(&mut &entry.data[..]).unwrap();
                    StreamedStoredEntry {
                        name: entry.name,
                        mtime: None,
                        attributes: 0x20,
                        host_os: 3,
                        size,
                        crc32,
                        source: std::io::Cursor::new(entry.data),
                    }
                })
                .collect();
            let mut out = Vec::new();
            write_compressed_archive_streamed(options, &mut sources, &mut out).unwrap();
            out
        };
        assert_eq!(streamed(narrow), one_at_a_time, "the streamed queue moved the archive");
        assert_eq!(streamed(wide), one_at_a_time, "member width moved the streamed archive");
    }

    #[test]
    fn writers_declare_a_dictionary_fitted_to_the_payload() {
        let declared = |archive: &[u8]| {
            Archive::parse(archive)
                .unwrap()
                .files()
                .map(|file| file.decoded_compression_info().unwrap().dictionary_size)
                .collect::<Vec<_>>()
        };
        let small: Vec<u8> = (0..6_000)
            .flat_map(|line| format!("line {line:06} of a small member\n").into_bytes())
            .collect();
        assert!(small.len() > 128 * 1024 && small.len() < 256 * 1024);
        let entry = |data: &'static [u8], name: &'static [u8]| CompressedEntry {
            name,
            data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        };
        let small: &'static [u8] = Box::leak(small.into_boxed_slice());
        let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::default());
        assert_eq!(
            dictionary_size_for_options(options).unwrap(),
            DEFAULT_RAR50_DICTIONARY_SIZE
        );

        // 200 KB member: the default fits down to 256 KiB.
        let entries = [entry(small, b"small.txt")];
        let archive = Rar50Writer::new(options)
            .compressed_entries(&entries)
            .finish()
            .unwrap();
        assert_eq!(declared(&archive), vec![256 * 1024]);
        let volumes = Rar50VolumeWriter::new(options)
            .max_payload_per_volume(2048)
            .compressed_entries(&entries)
            .finish()
            .unwrap();
        assert!(volumes.len() > 1);
        assert_eq!(declared(&volumes[0]), vec![256 * 1024]);
        let mut streamed = Vec::new();
        let mut sources = [stream::StreamedStoredEntry {
            name: b"small.txt",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            size: small.len() as u64,
            crc32: stream::crc32_of_reader(&mut std::io::Cursor::new(small))
                .unwrap()
                .1,
            source: std::io::Cursor::new(small),
        }];
        stream::write_compressed_archive_streamed(options, &mut sources, &mut streamed).unwrap();
        assert_eq!(declared(&streamed), vec![256 * 1024]);

        // Two such members in a solid set fit their TOTAL (400 KB -> 512 KiB),
        // and every member declares the same size.
        let solid = FeatureSet {
            solid: true,
            ..FeatureSet::default()
        };
        let entries = [entry(small, b"one.txt"), entry(small, b"two.txt")];
        let archive = Rar50Writer::new(WriterOptions::new(ArchiveVersion::Rar50, solid))
            .compressed_entries(&entries)
            .finish()
            .unwrap();
        assert_eq!(declared(&archive), vec![512 * 1024, 512 * 1024]);

        // A member past half the request keeps the request; every member
        // of the set declares it, as rar does.
        let big: &'static [u8] = Box::leak(
            b"a member big enough to use a real window\n"
                .repeat(600_000)
                .into_boxed_slice(),
        );
        assert!(big.len() as u64 * 2 > DEFAULT_RAR50_DICTIONARY_SIZE);
        let entries = [entry(big, b"big.txt"), entry(small, b"small.txt")];
        let archive = Rar50Writer::new(options)
            .compressed_entries(&entries)
            .finish()
            .unwrap();
        assert_eq!(
            declared(&archive),
            vec![DEFAULT_RAR50_DICTIONARY_SIZE, DEFAULT_RAR50_DICTIONARY_SIZE]
        );
        let collected = collect_extract(&Archive::parse(&archive).unwrap()).unwrap();
        assert_eq!(collected[0].data, big);
        assert_eq!(collected[1].data, small);
    }

    #[test]
    fn writer_uses_rar7_dictionary_fields_when_size_needs_v1_encoding() {
        let data = b"RAR7 dictionary-size writer option fixture".repeat(64);
        let options =
            WriterOptions::new(crate::ArchiveVersion::Rar70, crate::FeatureSet::default())
                .with_dictionary_size(192 * 1024);
        let entries = [CompressedEntry {
            name: b"dict7.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let archive = Rar50Writer::new(options)
            .compressed_entries(&entries)
            .finish()
            .unwrap();

        let parsed = Archive::parse(&archive).unwrap();
        let info = parsed
            .files()
            .next()
            .unwrap()
            .decoded_compression_info()
            .unwrap();
        let extracted = collect_extract(&parsed).unwrap();

        assert_eq!(info.algorithm_version, 1);
        assert_eq!(info.dictionary_size, 192 * 1024);
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn writer_rejects_unencodable_rar50_dictionary_size() {
        let options =
            WriterOptions::new(crate::ArchiveVersion::Rar50, crate::FeatureSet::default())
                .with_dictionary_size(192 * 1024);
        let entries = [CompressedEntry {
            name: b"bad.bin",
            data: b"data data data data",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];

        assert!(matches!(
            Rar50Writer::new(options)
                .compressed_entries(&entries)
                .finish(),
            Err(Error::InvalidHeader(
                "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB"
            ))
        ));
    }

    #[test]
    fn non_solid_level_five_considers_lower_level_parse_fallbacks() {
        let long_tail = b"stable long match payload for RAR5 best-level search ".repeat(10);
        let mut data = Vec::new();
        data.extend_from_slice(b"abc");
        data.extend_from_slice(&long_tail);
        for index in 0..320usize {
            data.extend_from_slice(b"abc");
            data.push((index as u8).wrapping_mul(37));
            data.extend_from_slice(b" near same-hash decoy ");
            data.extend_from_slice(&(index as u32).to_le_bytes());
        }
        data.extend_from_slice(b"abc");
        data.extend_from_slice(&long_tail);

        let level_five = encode_options_for_level(
            Some(5),
            DEFAULT_RAR50_DICTIONARY_SIZE,
            false,
            true,
            false,
            None,
        )
        .unwrap();
        let fallback_candidates = encode_option_candidates_for_level(
            Some(5),
            DEFAULT_RAR50_DICTIONARY_SIZE,
            false,
            true,
            false,
            None,
        )
        .unwrap();
        assert!(fallback_candidates.len() > 1);

        let level_five_only =
            encode_member_with_filter_policy(&data, 0, FilterPolicy::None, level_five).unwrap();
        let chosen = encode_member_with_filter_policy_candidates(
            &data,
            0,
            FilterPolicy::None,
            &fallback_candidates,
        )
        .unwrap();

        assert!(
            chosen.len() <= level_five_only.len(),
            "candidate fallback should not choose a larger parse: level5={} chosen={}",
            level_five_only.len(),
            chosen.len()
        );

        let mut decoder = crate::codec::rar50::Unpack50Decoder::new();
        let output = decoder
            .decode_member(
                &chosen,
                0,
                data.len(),
                false,
                crate::codec::rar50::DecodeMode::Lz,
            )
            .unwrap();
        assert_eq!(output, data);
    }

    #[test]
    fn auto_x86_filter_ranges_select_dense_opcode_clusters() {
        let mut data = vec![0u8; 100_000];
        data[1_000] = 0xe8;
        data[7_000] = 0xe9;
        for pos in [50_000, 50_064, 50_128, 50_192] {
            data[pos] = 0xe8;
        }
        for pos in [70_000, 70_064, 70_128, 70_192] {
            data[pos] = 0xe9;
        }

        let e8_ranges = auto_x86_filter_ranges(&data, false);
        assert!(e8_ranges
            .iter()
            .any(|range| range.start <= 50_000 && range.end >= 50_197));
        assert!(!e8_ranges
            .iter()
            .any(|range| range.start <= 1_000 && range.end >= 1_005));

        let e8e9_ranges = auto_x86_filter_ranges(&data, true);
        assert!(e8e9_ranges
            .iter()
            .any(|range| range.start <= 70_000 && range.end >= 70_197));
    }

    #[test]
    fn auto_x86_filter_policy_can_emit_multiple_disjoint_ranges() {
        let mut data = vec![0x41u8; 80_000];
        for cluster_start in [8_000, 60_000] {
            for index in 0..8 {
                let pos = cluster_start + index * 64;
                data[pos] = 0xe8;
                data[pos + 1..pos + 5].copy_from_slice(&(0x2000u32 + index as u32).to_le_bytes());
            }
        }
        let ranges = disjoint_filter_ranges(auto_x86_filter_ranges(&data, false));
        let filters: Vec<_> = ranges
            .into_iter()
            .map(|range| Rar50FilterSpec::range(FilterKind::E8, range))
            .collect();

        let packed =
            encode_member_with_filter_specs(&data, 0, &filters, EncodeOptions::default()).unwrap();
        let mut decoder = crate::codec::rar50::Unpack50Decoder::new();
        let output = decoder
            .decode_member(
                &packed,
                0,
                data.len(),
                false,
                crate::codec::rar50::DecodeMode::Lz,
            )
            .unwrap();

        assert_eq!(filters.len(), 2);
        assert_eq!(output, data);
    }

    #[test]
    fn auto_delta_filter_range_skips_container_edges_and_aligns_channels() {
        let data = vec![0u8; 512];

        let range = auto_delta_filter_range(&data, 3).unwrap();

        assert!(range.start >= AUTO_DELTA_EDGE_SKIP);
        assert!(range.end <= data.len() - AUTO_DELTA_EDGE_SKIP);
        assert_eq!(range.start % 3, 0);
        assert_eq!((range.end - range.start) % 3, 0);
        assert!(auto_delta_filter_range(&data[..80], 3).is_none());
    }

    #[test]
    fn auto_filter_policy_considers_ranged_delta_candidates() {
        let mut data = vec![0x55u8; AUTO_DELTA_EDGE_SKIP];
        for sample in 0..256u16 {
            let left = sample as u8;
            let right = left.wrapping_add(1);
            data.extend_from_slice(&[left, right]);
        }
        data.extend(std::iter::repeat_n(0xaa, AUTO_DELTA_EDGE_SKIP));
        let options = EncodeOptions::default();

        let plain = encode_lz_member_with_options(&data, 0, options).unwrap();
        let ranged = encode_member_with_filter_spec(
            &data,
            0,
            Rar50FilterSpec::range(
                FilterKind::Delta { channels: 2 },
                auto_delta_filter_range(&data, 2).unwrap(),
            ),
            options,
        )
        .unwrap();
        let auto = encode_member_with_auto_size_filter(&data, 0, options).unwrap();

        assert!(ranged.len() < plain.len());
        assert!(auto.len() <= ranged.len());
        let mut decoder = crate::codec::rar50::Unpack50Decoder::new();
        let output = decoder
            .decode_member(
                &auto,
                0,
                data.len(),
                false,
                crate::codec::rar50::DecodeMode::Lz,
            )
            .unwrap();
        assert_eq!(output, data);
    }

    #[test]
    fn explicit_filters_accept_large_members_after_filter_ranges_are_split() {
        let data = vec![0u8; 4 * 1024 * 1024 + 1];
        let packed = encode_member_with_filter_policy(
            &data,
            0,
            FilterPolicy::Explicit(FilterKind::Delta { channels: 1 }),
            EncodeOptions::new(0),
        )
        .unwrap();
        let mut decoder = crate::codec::rar50::Unpack50Decoder::new();

        assert_eq!(
            decoder
                .decode_member(
                    &packed,
                    0,
                    data.len(),
                    false,
                    crate::codec::rar50::DecodeMode::Lz
                )
                .unwrap(),
            data
        );
    }

    #[test]
    fn solid_reset_policy_chooses_smaller_of_continued_and_fresh_streams() {
        let options = EncodeOptions::default();
        let first = b"solid reset policy unrelated prefix data\n".repeat(32);
        let second = b"second member second member second member\n".repeat(16);
        let mut encoder = Unpack50Encoder::with_options(options);
        encoder.encode_member(&first, 0).unwrap();

        let mut continued = encoder.clone();
        let continued_packed = continued.encode_member(&second, 0).unwrap();
        let mut fresh = Unpack50Encoder::with_options(options);
        let fresh_packed = fresh.encode_member(&second, 0).unwrap();
        let expected_fresh = fresh_packed.len() < continued_packed.len();
        let expected_len = continued_packed.len().min(fresh_packed.len());

        let (packed, solid_continuation) =
            encode_with_solid_reset_policy(&mut encoder, &second, 0, options, 1).unwrap();

        assert_eq!(packed.len(), expected_len);
        assert_eq!(solid_continuation, !expected_fresh);
    }

    #[test]
    #[ignore = "requires local rar command; used for reference-validating experimental RAR5 compressed output"]
    fn reference_rar_accepts_internal_literal_only_compressed_member() {
        let data = b"RAR5 literal-only compressed reference experiment\n";
        let packed = encode_literal_only(data, 0).unwrap();
        let name = b"compressed.txt";

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR50_SIGNATURE);
        write_main_header(&mut archive, 0, None, &[]).unwrap();

        let mut extra = Vec::new();
        write_hash_record(&mut extra, data);
        let (specific, _no_time) = file_specific(
            name,
            data.len() as u64,
            Some(crc32(data)),
            0x20,
            None,
            1 << 7,
            0,
        )
        .unwrap();
        write_block(
            &mut archive,
            BLOCK_TYPE_FILE,
            BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA,
            Some(packed.len() as u64),
            &specific,
            &extra,
            &packed,
        )
        .unwrap();
        write_end_header(&mut archive, 0).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!(
            "rars-rar50-literal-only-{}.rar",
            std::process::id()
        ));
        fs::write(&path, archive).unwrap();
        let output = match Command::new("rar").arg("t").arg(&path).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping reference test: local `rar` command is not installed");
                return;
            }
            Err(error) => panic!("failed to run rar: {error}"),
        };
        if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_none() {
            let _ = fs::remove_file(&path);
        }

        assert!(
            output.status.success(),
            "rar rejected experimental RAR5 compressed output\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "requires local rar command; used for reference-validating experimental RAR5 match output"]
    fn reference_rar_accepts_internal_match_compressed_member() {
        let data = b"RAR5 match compressed reference experiment\n".repeat(8);
        let packed = encode_lz_member(&data, 0).unwrap();
        let name = b"compressed.txt";

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR50_SIGNATURE);
        write_main_header(&mut archive, 0, None, &[]).unwrap();

        let mut extra = Vec::new();
        write_hash_record(&mut extra, &data);
        let (specific, _no_time) = file_specific(
            name,
            data.len() as u64,
            Some(crc32(&data)),
            0x20,
            None,
            1 << 7,
            0,
        )
        .unwrap();
        write_block(
            &mut archive,
            BLOCK_TYPE_FILE,
            BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA,
            Some(packed.len() as u64),
            &specific,
            &extra,
            &packed,
        )
        .unwrap();
        write_end_header(&mut archive, 0).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("rars-rar50-match-{}.rar", std::process::id()));
        fs::write(&path, archive).unwrap();
        let output = match Command::new("rar").arg("t").arg(&path).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping reference test: local `rar` command is not installed");
                return;
            }
            Err(error) => panic!("failed to run rar: {error}"),
        };
        if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_none() {
            let _ = fs::remove_file(&path);
        }

        assert!(
            output.status.success(),
            "rar rejected experimental RAR5 match output\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn writer_options_default_targets_rar50_with_store_only_features() {
        let options = WriterOptions::default();
        assert_eq!(options.target, crate::ArchiveVersion::Rar50);
        assert_eq!(options.features, crate::FeatureSet::store_only());
    }

    #[test]
    fn writer_rejects_mixed_member_kinds_without_panicking() {
        let stored = [StoredEntry {
            name: b"stored.txt",
            data: b"stored",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let compressed = [CompressedEntry {
            name: b"compressed.txt",
            data: b"compressed compressed compressed",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let result = Rar50Writer::new(WriterOptions::new(
            crate::ArchiveVersion::Rar50,
            crate::FeatureSet::store_only(),
        ))
        .stored_entries(&stored)
        .compressed_entries(&compressed)
        .finish();

        assert!(matches!(
            result,
            Err(Error::UnsupportedFeature {
                version: crate::ArchiveVersion::Rar50,
                feature: "RAR 5 mixed stored/compressed writer plan",
            })
        ));
    }
}
