use super::*;
pub use crate::codec::rar50::Rar50FilterKind as FilterKind;
use crate::codec::rar50::{EncodeOptions, Unpack50Encoder};
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys};
use crate::recovery::rar5::build_structural_inline_recovery_data_with_progress;
use crate::write_entropy::{Entropy, EntropyScope};
use crate::write_progress::{ProgressReporter, WorkTracker};
use crate::{WriteOperation, WriteProgress, WriteProgressEvent};

mod filter_policy;
pub mod reference;
pub mod rev;
mod volume;
#[cfg(test)]
use filter_policy::encode_member_with_filter_policy;
#[cfg(test)]
use filter_policy::encode_with_solid_reset_policy;
use filter_policy::{
    compression_info, compression_method_for_level, dictionary_size_for_options,
    encode_member_with_filter_policy_candidates_and_progress, encode_option_candidates_for_level,
    encode_options_for_level, encode_safe_lz_member_with_progress,
    encode_with_solid_reset_policy_and_progress, filter_policy_attempt_count,
    rar50_algorithm_version, should_store_compressed_payload, validate_compression_level,
};
use volume::{
    write_compressed_volume_set_impl, write_encrypted_compressed_volume_set_impl,
    write_encrypted_stored_volume_set_impl, write_encrypted_stored_volumes_impl,
    write_stored_volume_set_impl, write_stored_volumes_impl,
};

const MAX_MATCH_CANDIDATES_DEFAULT: usize = 256;
const DEFAULT_RAR50_DICTIONARY_SIZE: u64 = 128 * 1024;
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
}

impl WriterOptions {
    pub const fn new(target: crate::ArchiveVersion, features: crate::FeatureSet) -> Self {
        Self {
            target,
            features,
            compression_level: None,
            dictionary_size: None,
            entropy: Entropy::Os,
        }
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
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: crate::ArchiveVersion::Rar50,
            features: crate::FeatureSet::store_only(),
            compression_level: None,
            dictionary_size: None,
            entropy: Entropy::Os,
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
                compressed.then_some(&work),
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
                    compressed.then_some(&work),
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
            compression_work_total(
                &self.members,
                self.options.features.solid,
                self.filter_policy,
                encode_option_candidates_for_level(
                    self.options.compression_level,
                    dictionary_size_for_options(self.options)?,
                )?
                .len() as u64,
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
        let resolved = self.resolve(compressed.then_some(&work));
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
        let dictionary_size = dictionary_size_for_options(self.options)?;
        let encode_options =
            encode_options_for_level(self.options.compression_level, dictionary_size)?;
        let encode_option_candidates =
            encode_option_candidates_for_level(self.options.compression_level, dictionary_size)?;

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
                let mut solid_encoder = self
                    .options
                    .features
                    .solid
                    .then(|| Unpack50Encoder::with_options(encode_options));
                if let Some(encoder) = solid_encoder.as_mut() {
                    for (index, member) in self.members.into_iter().enumerate() {
                        let entry = member.into_compressed(self.options.target)?;
                        let entry_name = entry.name;
                        let entry_size = entry.data.len() as u64;
                        if let Some(progress) = compression_progress {
                            progress.entry_started(index, total_entries, entry_name, entry_size);
                        }
                        validate_compressed_entry(&entry)?;
                        if compression_method == 0 {
                            resolved_members
                                .push(ResolvedRar50WriteMember::StoredCompressed(entry));
                            continue;
                        }
                        let mut last = 0usize;
                        let mut report = |position: usize| {
                            if position < last {
                                last = 0;
                            }
                            let delta = position.saturating_sub(last);
                            last = position;
                            compression_progress
                                .is_none_or(|progress| progress.advance(delta as u64))
                        };
                        let (packed, solid_continuation) =
                            encode_with_solid_reset_policy_and_progress(
                                encoder,
                                entry.data,
                                algorithm_version,
                                encode_options,
                                index,
                                Some(&mut report),
                            )?;
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
                    )?;
                }
                Ok(ResolvedRar50WritePlan {
                    main_flags: if self.options.features.solid {
                        MHFL_SOLID
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
                    let encrypted = encrypted_stored_payload(entry.data, entry.password)?;
                    resolved_members
                        .push(ResolvedRar50WriteMember::EncryptedStored { entry, encrypted });
                }
                Ok(ResolvedRar50WritePlan {
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
                    let encrypted =
                        encrypted_stored_payload(entry.entry.data, entry.entry.password)?;
                    resolved_members.push(ResolvedRar50WriteMember::EncryptedStoredWithServices {
                        entry,
                        encrypted,
                    });
                }
                Ok(ResolvedRar50WritePlan {
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
                let mut solid_encoder = self
                    .options
                    .features
                    .solid
                    .then(|| Unpack50Encoder::with_options(encode_options));
                if let Some(encoder) = solid_encoder.as_mut() {
                    for (index, member) in self.members.into_iter().enumerate() {
                        let entry = member.into_encrypted_compressed(self.options.target)?;
                        let entry_name = entry.name;
                        let entry_size = entry.data.len() as u64;
                        if let Some(progress) = compression_progress {
                            progress.entry_started(index, total_entries, entry_name, entry_size);
                        }
                        validate_encrypted_compressed_entry(&entry)?;
                        if compression_method == 0 {
                            let encrypted = encrypted_stored_payload(entry.data, entry.password)?;
                            resolved_members.push(
                                ResolvedRar50WriteMember::EncryptedStoredCompressed {
                                    entry,
                                    encrypted,
                                },
                            );
                            continue;
                        }
                        let mut last = 0usize;
                        let mut report = |position: usize| {
                            if position < last {
                                last = 0;
                            }
                            let delta = position.saturating_sub(last);
                            last = position;
                            compression_progress
                                .is_none_or(|progress| progress.advance(delta as u64))
                        };
                        let (packed, solid_continuation) =
                            encode_with_solid_reset_policy_and_progress(
                                encoder,
                                entry.data,
                                algorithm_version,
                                encode_options,
                                index,
                                Some(&mut report),
                            )?;
                        if should_store_compressed_payload(
                            entry.data,
                            &packed,
                            true,
                            FilterPolicy::None,
                        ) {
                            let encrypted = encrypted_stored_payload(entry.data, entry.password)?;
                            resolved_members.push(
                                ResolvedRar50WriteMember::EncryptedStoredCompressed {
                                    entry,
                                    encrypted,
                                },
                            );
                        } else {
                            let encrypted = encrypted_payload(&packed, entry.data, entry.password)?;
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
                    )?;
                }
                Ok(ResolvedRar50WritePlan {
                    main_flags: if self.options.features.solid {
                        MHFL_SOLID
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
) -> Result<Vec<ResolvedRar50WriteMember<'a>>> {
    let total_entries = members.len();
    let members: Vec<_> = members.into_iter().enumerate().collect();
    #[cfg(feature = "parallel")]
    {
        if members.len() > 1 {
            crate::parallel::map_collect(members, |(index, member)| {
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
                )
            })
        } else {
            members
                .into_iter()
                .map(|(index, member)| {
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
                )
            })
            .collect()
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
    let packed = if filter_policy == FilterPolicy::None {
        encode_candidates_with_progress(
            entry.data,
            algorithm_version,
            encode_option_candidates,
            progress,
        )?
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
        encode_member_with_filter_policy_candidates_and_progress(
            entry.data,
            algorithm_version,
            filter_policy,
            encode_option_candidates,
            Some(&mut report),
        )?
    };
    if should_store_compressed_payload(entry.data, &packed, false, filter_policy) {
        let resolved = ResolvedRar50WriteMember::StoredCompressed(entry);
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
) -> Result<Vec<u8>> {
    let (first, rest) = candidates.split_first().ok_or(Error::InvalidHeader(
        "RAR 5 compression level has no encoder options",
    ))?;
    let mut last = 0usize;
    let mut report = |position: usize| {
        if position < last {
            last = 0;
        }
        let delta = position.saturating_sub(last);
        last = position;
        progress.is_none_or(|progress| progress.advance(delta as u64))
    };
    let mut best =
        match encode_safe_lz_member_with_progress(data, algorithm_version, *first, &mut report) {
            Err(Error::Codec(crate::codec::Error::Cancelled)) => return Err(Error::Cancelled),
            result => result?,
        };
    for options in rest {
        if progress.is_some_and(WorkTracker::is_cancelled) {
            return Err(Error::Cancelled);
        }
        let packed = match encode_safe_lz_member_with_progress(
            data,
            algorithm_version,
            *options,
            &mut report,
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

fn resolve_encrypted_compressed_members<'a>(
    members: Vec<Rar50WriteMember<'a>>,
    target: crate::ArchiveVersion,
    compression_method: u8,
    algorithm_version: u8,
    dictionary_size: u64,
    encode_option_candidates: &[EncodeOptions],
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<ResolvedRar50WriteMember<'a>>> {
    let total_entries = members.len();
    let members: Vec<_> = members.into_iter().enumerate().collect();
    #[cfg(feature = "parallel")]
    {
        if members.len() > 1 {
            crate::parallel::map_collect(members, |(index, member)| {
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
) -> Result<ResolvedRar50WriteMember<'a>> {
    let entry = member.into_encrypted_compressed(target)?;
    let entry_name = entry.name;
    let entry_size = entry.data.len() as u64;
    if let Some(progress) = progress {
        progress.entry_started(index, total_entries, entry_name, entry_size);
    }
    validate_encrypted_compressed_entry(&entry)?;
    if compression_method == 0 {
        let encrypted = encrypted_stored_payload(entry.data, entry.password)?;
        if let Some(progress) = progress {
            progress.entry_finished(index, total_entries, entry_name, entry_size);
        }
        return Ok(ResolvedRar50WriteMember::EncryptedStoredCompressed { entry, encrypted });
    }
    let packed = encode_candidates_with_progress(
        entry.data,
        algorithm_version,
        encode_option_candidates,
        progress,
    )?;
    let resolved =
        if should_store_compressed_payload(entry.data, &packed, false, FilterPolicy::None) {
            let encrypted = encrypted_stored_payload(entry.data, entry.password)?;
            ResolvedRar50WriteMember::EncryptedStoredCompressed { entry, encrypted }
        } else {
            let encrypted = encrypted_payload(&packed, entry.data, entry.password)?;
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
}

enum ResolvedRar50WriteMember<'a> {
    Stored(StoredEntry<'a>),
    StoredWithServices(StoredEntryWithServices<'a>),
    StoredCompressed(CompressedEntry<'a>),
    Compressed {
        entry: CompressedEntry<'a>,
        packed: Vec<u8>,
        algorithm_version: u8,
        compression_method: u8,
        dictionary_size: u64,
        solid_continuation: bool,
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
                emit_resolved_writer_plan_pass(&plan, Some(quick_open_offset), None, progress, 1)
                    .map(|(out, next_quick_open_offset, _)| (out, next_quick_open_offset))
            },
            "RAR 5 quick-open pass did not report an offset",
            "RAR 5 quick-open offset did not converge",
        );
    }
    if plan.recovery_percent.is_some() {
        return resolve_writer_plan_offset(
            |recovery_offset, pass| {
                emit_resolved_writer_plan_pass(&plan, None, Some(recovery_offset), progress, pass)
                    .map(|(out, _, next_recovery_offset)| (out, next_recovery_offset))
            },
            "RAR 5 recovery pass did not report an offset",
            "RAR 5 recovery offset did not converge",
        );
    }
    emit_resolved_writer_plan_pass(&plan, None, None, progress, 1).map(|(out, _, _)| out)
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
) -> Result<(Vec<u8>, Option<u64>, Option<u64>)> {
    let mut out = Vec::new();
    let mut cached_headers = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    let main_extra =
        resolved_main_extra(plan.archive_metadata, quick_open_offset, recovery_offset)?;
    let main_flags = plan.main_flags
        | if plan.recovery_percent.is_some() {
            MHFL_RECOVERY
        } else {
            0
        };
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
                )?;
            }
        }
    }
    for member in &plan.members {
        match member {
            ResolvedRar50WriteMember::Stored(entry) => {
                if plan.quick_open {
                    write_stored_entry_with_cache(&mut out, &mut cached_headers, entry)?;
                } else {
                    write_stored_entry(&mut out, entry)?;
                }
            }
            ResolvedRar50WriteMember::StoredWithServices(entry) => {
                write_stored_entry(&mut out, &entry.entry)?;
                for service in entry.services {
                    write_stored_service(&mut out, service.name, service.data)?;
                }
            }
            ResolvedRar50WriteMember::StoredCompressed(entry) => {
                write_stored_compressed_entry(&mut out, entry)?;
            }
            ResolvedRar50WriteMember::Compressed {
                entry,
                packed,
                algorithm_version,
                compression_method,
                dictionary_size,
                solid_continuation,
            } => write_compressed_entry_payload(
                &mut out,
                entry,
                packed,
                *algorithm_version,
                *compression_method,
                *dictionary_size,
                *solid_continuation,
            )?,
            ResolvedRar50WriteMember::EncryptedStored { entry, encrypted } => {
                write_encrypted_stored_entry_fragment_with_header_keys(
                    &mut out,
                    entry,
                    &encrypted.data,
                    encrypted,
                    false,
                    false,
                    plan.header_keys.as_ref().map(|keys| &keys.keys),
                )?
            }
            ResolvedRar50WriteMember::EncryptedStoredWithServices { entry, encrypted } => {
                write_encrypted_stored_entry_fragment_with_header_keys(
                    &mut out,
                    &entry.entry,
                    &encrypted.data,
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
                    data: &encrypted.data,
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
            )?;
        } else {
            write_recovery_service(&mut out, recovery_percent, progress, recovery_pass)?;
        }
        Some((rr_pos - RAR50_SIGNATURE.len()) as u64)
    } else {
        None
    };
    if let Some(header_keys) = &plan.header_keys {
        out.extend_from_slice(&encrypted_header_block(
            &header_keys.keys,
            HEAD_END,
            0,
            None,
            &end_header_specific(0),
            &[],
            &[],
        )?);
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
        HEAD_MAIN,
        if extra.is_empty() { 0 } else { HFL_EXTRA },
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
        HEAD_MAIN,
        if extra.is_empty() { 0 } else { HFL_EXTRA },
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
    crate::write_entropy::fill(
        &mut salt,
        "RAR 5 writer could not generate encryption salt",
    )?;
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
    write_block(out, HEAD_CRYPT, 0, None, &specific, &[], &[])
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
        flags |= MHEXTRA_ARCHIVE_METADATA_NAME;
    }
    if metadata.creation_time.is_some() {
        flags |= MHEXTRA_ARCHIVE_METADATA_TIME;
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
    write_extra_record(&mut extra, MHEXTRA_ARCHIVE_METADATA, &record);
    Ok(extra)
}

fn write_locator_record(
    out: &mut Vec<u8>,
    quick_open_offset: Option<u64>,
    recovery_record_offset: Option<u64>,
) {
    let mut flags = 0;
    if quick_open_offset.is_some() {
        flags |= MHEXTRA_LOCATOR_QUICK_OPEN;
    }
    if recovery_record_offset.is_some() {
        flags |= MHEXTRA_LOCATOR_RECOVERY;
    }

    let mut record = Vec::new();
    write_vint(&mut record, flags);
    if let Some(quick_open_offset) = quick_open_offset {
        write_vint(&mut record, quick_open_offset);
    }
    if let Some(recovery_record_offset) = recovery_record_offset {
        write_vint(&mut record, recovery_record_offset);
    }
    write_extra_record(out, MHEXTRA_LOCATOR, &record);
}

fn write_stored_entry(out: &mut Vec<u8>, entry: &StoredEntry<'_>) -> Result<()> {
    validate_entry(entry)?;
    write_stored_entry_fragment(
        out,
        entry,
        entry.data,
        entry.data.len() as u64,
        Some(crc32(entry.data)),
        false,
        false,
    )
}

fn write_stored_compressed_entry(out: &mut Vec<u8>, entry: &CompressedEntry<'_>) -> Result<()> {
    validate_compressed_entry(entry)?;
    let stored = stored_entry_from_compressed_entry(entry);
    write_stored_entry(out, &stored)
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

fn write_compressed_entry_payload(
    out: &mut Vec<u8>,
    entry: &CompressedEntry<'_>,
    packed: &[u8],
    algorithm_version: u8,
    compression_method: u8,
    dictionary_size: u64,
    solid_continuation: bool,
) -> Result<()> {
    let mut extra = Vec::new();
    write_hash_record(&mut extra, entry.data);
    let compression_info = compression_info(
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
    )?;
    let specific = file_specific(
        entry.name,
        entry.data.len() as u64,
        Some(crc32(entry.data)),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    write_block(
        out,
        HEAD_FILE,
        HFL_EXTRA | HFL_DATA,
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
    } = fragment;

    let mut extra = Vec::new();
    if !split_after {
        write_hash_record(&mut extra, entry.data);
    }
    let compression_info = compression_info(
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
    )?;
    let specific = file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(crc32(entry.data)),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    let mut block_flags = HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }
    if !extra.is_empty() {
        block_flags |= HFL_EXTRA;
    }

    write_block(
        out,
        HEAD_FILE,
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
) -> Result<()> {
    validate_entry(entry)?;
    let mut extra = Vec::new();
    write_hash_record(&mut extra, entry.data);
    let specific = stored_file_specific(
        entry.name,
        entry.data.len() as u64,
        Some(crc32(entry.data)),
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    write_block_with_cache(
        out,
        cached_headers,
        BlockParts {
            header_type: HEAD_FILE,
            flags: HFL_EXTRA | HFL_DATA,
            data_size: Some(entry.data.len() as u64),
            type_specific: &specific,
            extra: &extra,
            data: entry.data,
        },
    )
}

struct EncryptedStoredPayload {
    data: Vec<u8>,
    salt: [u8; 16],
    iv: [u8; 16],
    check_value: [u8; 12],
    crc32_mac: u32,
    blake2sp_mac: [u8; 32],
}

fn encrypted_stored_payload(data: &[u8], password: &[u8]) -> Result<EncryptedStoredPayload> {
    encrypted_payload(data, data, password)
}

fn encrypted_payload(
    packed_data: &[u8],
    integrity_data: &[u8],
    password: &[u8],
) -> Result<EncryptedStoredPayload> {
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    crate::write_entropy::fill(
        &mut salt,
        "RAR 5 writer could not generate encryption salt",
    )?;
    crate::write_entropy::fill(&mut iv, "RAR 5 writer could not generate encryption IV")?;
    let keys = Rar50Keys::derive(password, salt, 0).map_err(super::map_rar50_crypto_error)?;

    let mut encrypted_data = packed_data.to_vec();
    let padded_len = encrypted_data
        .len()
        .checked_add(15)
        .ok_or(Error::InvalidHeader("RAR 5 encrypted data size overflows"))?
        & !15;
    encrypted_data.resize(padded_len, 0);
    Rar50Cipher::new(keys.key, iv)
        .encrypt_in_place(&mut encrypted_data)
        .map_err(super::map_rar50_crypto_error)?;

    Ok(EncryptedStoredPayload {
        data: encrypted_data,
        salt,
        iv,
        check_value: keys.password_check_record(),
        crc32_mac: keys.mac_crc32(crc32(integrity_data)),
        blake2sp_mac: keys.mac_hash32(blake2sp::hash(integrity_data)),
    })
}

fn write_encrypted_stored_entry_fragment_with_header_keys(
    out: &mut Vec<u8>,
    entry: &EncryptedStoredEntry<'_>,
    data: &[u8],
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
        write_hash_record_with_value(&mut extra, encrypted.blake2sp_mac);
    }

    let specific = stored_file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(encrypted.crc32_mac),
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    let mut block_flags = HFL_EXTRA | HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }

    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            header_keys,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )?);
        Ok(())
    } else {
        write_block(
            out,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
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
    write_encrypted_stored_entry_fragment_with_header_keys(
        out,
        &stored,
        &encrypted.data,
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
    data: &'a [u8],
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
        write_hash_record_with_value(&mut extra, encrypted.blake2sp_mac);
    }

    let compression_info = compression_info(
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
    )?;
    let specific = file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(encrypted.crc32_mac),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    let mut block_flags = HFL_EXTRA | HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }

    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            header_keys,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )?);
        Ok(())
    } else {
        write_block(
            out,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )
    }
}

fn write_stored_entry_fragment(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    data: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    split_before: bool,
    split_after: bool,
) -> Result<()> {
    let mut extra = Vec::new();
    if !split_before && !split_after {
        write_hash_record(&mut extra, data);
    }
    let specific = stored_file_specific(
        entry.name,
        unpacked_size,
        data_crc32,
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    let mut block_flags = HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }
    if !extra.is_empty() {
        block_flags |= HFL_EXTRA;
    }

    write_block(
        out,
        HEAD_FILE,
        block_flags,
        Some(data.len() as u64),
        &specific,
        &extra,
        data,
    )
}

fn write_stored_service(out: &mut Vec<u8>, name: &[u8], data: &[u8]) -> Result<()> {
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &[]);
    let specific = stored_file_specific(name, data.len() as u64, Some(crc32(data)), 0, None, 0)?;

    write_block(
        out,
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data.len() as u64),
        &specific,
        &extra,
        data,
    )
}

fn write_recovery_service(
    out: &mut Vec<u8>,
    recovery_percent: u64,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
) -> Result<()> {
    let mut service_data = Vec::new();
    write_vint(&mut service_data, recovery_percent);
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &service_data);

    let data =
        build_structural_inline_recovery_data_with_progress(out, recovery_percent, progress, pass)?;
    let specific = stored_file_specific(b"RR", data.len() as u64, Some(crc32(&data)), 0, None, 0)?;
    write_block(
        out,
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data.len() as u64),
        &specific,
        &extra,
        &data,
    )
}

fn write_stored_service_with_cache(
    out: &mut Vec<u8>,
    cached_headers: &mut Vec<CachedHeader>,
    name: &[u8],
    data: &[u8],
) -> Result<()> {
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &[]);
    let specific = stored_file_specific(name, data.len() as u64, Some(crc32(data)), 0, None, 0)?;

    write_block_with_cache(
        out,
        cached_headers,
        BlockParts {
            header_type: HEAD_SERVICE,
            flags: HFL_EXTRA | HFL_DATA,
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
) -> Result<()> {
    write_encrypted_service_with_header_keys(
        out,
        name,
        comment.data,
        &[],
        comment.password,
        header_keys,
    )
}

fn write_header_encrypted_recovery_service(
    out: &mut Vec<u8>,
    recovery_percent: u64,
    header_keys: &Rar50Keys,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
) -> Result<()> {
    let mut service_data = Vec::new();
    write_vint(&mut service_data, recovery_percent);
    let data =
        build_structural_inline_recovery_data_with_progress(out, recovery_percent, progress, pass)?;
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &service_data);
    let specific = stored_file_specific(b"RR", data.len() as u64, Some(crc32(&data)), 0, None, 0)?;
    out.extend_from_slice(&encrypted_header_block(
        header_keys,
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data.len() as u64),
        &specific,
        &extra,
        &data,
    )?);
    Ok(())
}

fn write_encrypted_service_with_header_keys(
    out: &mut Vec<u8>,
    name: &[u8],
    data: &[u8],
    service_data: &[u8],
    password: &[u8],
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    validate_nonempty_password(password)?;
    let encrypted = encrypted_stored_payload(data, password)?;
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, service_data);
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    write_hash_record_with_value(&mut extra, encrypted.blake2sp_mac);
    let specific = stored_file_specific(
        name,
        data.len() as u64,
        Some(encrypted.crc32_mac),
        0,
        None,
        0,
    )?;

    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            header_keys,
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(encrypted.data.len() as u64),
            &specific,
            &extra,
            &encrypted.data,
        )?);
        Ok(())
    } else {
        write_block(
            out,
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(encrypted.data.len() as u64),
            &specific,
            &extra,
            &encrypted.data,
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
) -> Result<Vec<u8>> {
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

fn file_specific(
    name: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    attributes: u64,
    mtime: Option<u32>,
    compression_info: u64,
    host_os: u64,
) -> Result<Vec<u8>> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file name is empty"));
    }
    let mut file_flags = if data_crc32.is_some() { FHFL_CRC32 } else { 0 };
    if mtime.is_some() {
        file_flags |= FHFL_MTIME;
    }

    let mut specific = Vec::new();
    write_vint(&mut specific, file_flags);
    write_vint(&mut specific, unpacked_size);
    write_vint(&mut specific, attributes);
    if let Some(mtime) = mtime {
        specific.extend_from_slice(&mtime.to_le_bytes());
    }
    if let Some(data_crc32) = data_crc32 {
        specific.extend_from_slice(&data_crc32.to_le_bytes());
    }
    write_vint(&mut specific, compression_info);
    write_vint(&mut specific, host_os);
    write_vint(&mut specific, name.len() as u64);
    specific.extend_from_slice(name);
    Ok(specific)
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
    let header = block_header_image(header_type, flags, data_size, type_specific, extra)?;
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    Ok(())
}

pub(super) fn write_end_header(out: &mut Vec<u8>, end_flags: u64) -> Result<()> {
    write_block(
        out,
        HEAD_END,
        0,
        None,
        &end_header_specific(end_flags),
        &[],
        &[],
    )
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
    let mut out = Vec::with_capacity(16 + encrypted_header.len() + data.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&encrypted_header);
    out.extend_from_slice(data);
    Ok(out)
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
    if flags & HFL_EXTRA != 0 {
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
    write_extra_record(out, FHEXTRA_HASH, &record);
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
    write_extra_record(out, FHEXTRA_CRYPT, &record);
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
    use crate::codec::rar50::{encode_literal_only, encode_lz_member};
    use crate::codec::rar50::{encode_lz_member_with_options, EncodeOptions, Rar50FilterSpec};
    use crate::x86_filter_scan::auto_x86_filter_ranges;
    use crate::{ArchiveVersion, FeatureSet};
    use std::cell::RefCell;
    use std::fs;
    use std::io::{Result as IoResult, Write};
    use std::process::Command;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        let entries = RefCell::new(Vec::new());
        archive.extract_to(crate::ArchiveReadOptions::default(), |meta| {
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
        let specific = file_specific(
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
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
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

    #[test]
    fn writer_stamps_requested_rar50_dictionary_size() {
        let data = b"RAR5 dictionary-size writer option fixture".repeat(64);
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

        let level_five = encode_options_for_level(Some(5), DEFAULT_RAR50_DICTIONARY_SIZE).unwrap();
        let fallback_candidates =
            encode_option_candidates_for_level(Some(5), DEFAULT_RAR50_DICTIONARY_SIZE).unwrap();
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
        let specific = file_specific(
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
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
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
        let specific = file_specific(
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
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
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
