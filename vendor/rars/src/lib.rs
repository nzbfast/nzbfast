//! High-level RAR archive API.
//!
//! This crate is the supported public Rust API for `rars`. It is the facade
//! over the version-specific format modules, detects archive families, exposes
//! common member metadata, and streams extraction or recovery output to
//! caller-provided writers without requiring callers to buffer whole archives
//! in memory. New Rust users should depend on this crate rather than the
//! lower-level `rars-*` implementation crates, which ended at 0.3.x.

#![cfg_attr(feature = "fast", feature(portable_simd))]

#[doc(hidden)]
pub mod codec;
pub mod crc32;
#[doc(hidden)]
pub mod crypto;
pub mod detect;
pub mod error;
mod fast;
pub mod features;
mod io_util;
#[cfg(feature = "parallel")]
mod parallel;
pub mod rar13;
pub mod rar15_40;
pub mod rar50;
#[doc(hidden)]
pub mod recovery;
mod source;
pub mod version;
mod volume_extract;
mod write_progress;
mod x86_filter_scan;

pub use detect::{detect_archive_family, find_archive_start, ArchiveSignature, SFX_SCAN_LIMIT};
pub use error::{Error, Result};
pub use features::FeatureSet;
pub use source::{BlockingRangeSource, GrowableBuffer};
use std::io::{Read, Write};
use std::path::Path;
pub use version::{ArchiveFamily, ArchiveVersion};
pub use write_progress::{WriteOperation, WriteProgress, WriteProgressEvent};

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Options used while parsing or extracting archives.
pub struct ArchiveReadOptions<'a> {
    /// Password bytes used for encrypted headers or payloads.
    pub password: Option<&'a [u8]>,
    /// Optional RAR 5 whole-member buffered decode limit.
    ///
    /// Filtered RAR 5 members need whole-member transforms. Compressed members
    /// above this limit use the streaming path and reject filtered streams
    /// with an unsupported-feature error instead of buffering the full member.
    pub rar50_buffered_decode_limit: Option<u64>,
    /// Optional ceiling on the RAR 5/7 streaming match window (bytes).
    ///
    /// The streaming decoder's ring can grow to the archive's declared
    /// dictionary; RAR 7 permits dictionaries far larger than most hosts can
    /// afford. Members whose back-references stay within this limit still
    /// decode; one that genuinely needs a wider window fails with
    /// `Rar50WindowLimitExceeded` instead of attempting the allocation. `None`
    /// uses a built-in default (see `DEFAULT_STREAM_WINDOW_LIMIT`).
    pub rar50_max_window: Option<u64>,
    /// Optional RAR 5 execution policy: how much working memory and worker
    /// parallelism extraction may use. `None` keeps the library's built-in
    /// behavior (a fixed 256 MiB solid-chain flat budget, worker counts from
    /// the host CPU count). Applications with their own memory accounting
    /// pass a policy so a memory-constrained host never selects a flat plan
    /// it cannot afford, and a large host may exceed the built-in flat cap.
    pub rar50_execution_policy: Option<Rar50ExecutionPolicy>,
    /// How an incrementally decoded RAR 5 split member seeds its BLAKE2sp.
    ///
    /// Only the growing-chain path reads this (the volume-sequence driver
    /// behind `extract_volume_sequence_to*`); every walk that already holds
    /// the whole set reads the finish fragment's header and is unaffected.
    pub rar50_split_hash_seeding: Rar50SplitHashSeeding,
}

/// Whether an incrementally decoded split member may take its FIRST
/// fragment's header as the set's answer on whether a BLAKE2sp record
/// exists at all.
///
/// A split member's expected BLAKE2sp lives in its LAST fragment's header,
/// and the growing-chain decode has to decide whether to hash before it has
/// read that fragment. `Unconditional` therefore hashes the whole payload
/// and throws the digest away when the finish fragment turns out to carry
/// no record - which is `rar`'s and WinRAR's DEFAULT (`Pack-CRC32` and no
/// hash line), so the common set pays a whole-payload BLAKE2sp that nothing
/// ever checks. Measured on an Apple M3 at +4.22 G instructions per GB
/// unpacked and +5.83 G paced, against ~42 G for the decode itself.
///
/// `FirstFragment` skips the hasher when the first fragment carries no
/// BLAKE2sp record. That is exact for both writers whose split sets have
/// been measured here: WinRAR 7.21 and rar 7.23 stamp EVERY fragment of a
/// `-htb` set (the non-final ones with that fragment's own packed digest -
/// see `FileHeader::split_fragment_packed_digests`) and stamp none without
/// it, so the first fragment and the finish fragment always agree. It is
/// not exact for the rars writer, which stamps only the finish fragment: on
/// such a set the BLAKE2sp goes unchecked and the member is verified by its
/// CRC32 alone, exactly as an unstamped set is. Callers whose archives come
/// from WinRAR or rar should choose it; callers that read rars-written
/// split sets should not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Rar50SplitHashSeeding {
    /// Always hash, and discard the digest if the finish fragment carries
    /// no record to check it against.
    #[default]
    Unconditional,
    /// Hash only when the split member's first fragment carries a BLAKE2sp
    /// record.
    FirstFragment,
}

/// Memory and parallelism allowances for RAR 5 extraction.
///
/// The policy is advisory in the sense that it selects between decode
/// strategies (flat buffers vs the bounded streaming ring, worker counts);
/// it never changes output bytes or error semantics, and it does not
/// override the separate `rar50_max_window` safety valve - a match that
/// genuinely needs a wider window than that limit still errors rather than
/// silently truncating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rar50ExecutionPolicy {
    /// Total decoder working-memory allowance in bytes: flat output buffers,
    /// the retained solid window, in-flight tapes, and pipe scratch are
    /// estimated against this before a flat plan is admitted.
    pub working_memory_limit: u64,
    /// Largest output held in one flat allocation (a member or a whole
    /// solid chain group); larger outputs stream through the bounded ring.
    pub flat_output_limit: u64,
    /// Cap on decode workers (tape workers and the member pool).
    pub max_workers: usize,
}

impl Rar50ExecutionPolicy {
    /// A policy from a total working-memory allowance: half of it may sit in
    /// one flat allocation, and constrained allowances also shed workers.
    pub fn from_working_memory(working_memory_limit: u64) -> Self {
        Self {
            working_memory_limit,
            flat_output_limit: working_memory_limit / 2,
            max_workers: if working_memory_limit < 256 << 20 { 2 } else { 8 },
        }
    }
}

impl<'a> ArchiveReadOptions<'a> {
    /// Creates read options without a password.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates read options with a password.
    pub fn with_password(password: &'a [u8]) -> Self {
        Self {
            password: Some(password),
            ..Self::default()
        }
    }

    /// Creates read options with an optional password.
    pub fn with_optional_password(password: Option<&'a [u8]>) -> Self {
        Self {
            password,
            ..Self::default()
        }
    }

    /// Sets the RAR 5 whole-member buffered decode limit.
    pub fn with_rar50_buffered_decode_limit(mut self, limit: u64) -> Self {
        self.rar50_buffered_decode_limit = Some(limit);
        self
    }

    /// Sets the RAR 5/7 streaming match-window ceiling (bytes).
    pub fn with_rar50_max_window(mut self, limit: u64) -> Self {
        self.rar50_max_window = Some(limit);
        self
    }

    /// Sets the RAR 5 execution policy (memory and worker allowances).
    pub fn with_rar50_execution_policy(mut self, policy: Rar50ExecutionPolicy) -> Self {
        self.rar50_execution_policy = Some(policy);
        self
    }

    /// Sets how an incrementally decoded RAR 5 split member seeds its
    /// BLAKE2sp - see [`Rar50SplitHashSeeding`].
    pub fn with_rar50_split_hash_seeding(mut self, seeding: Rar50SplitHashSeeding) -> Self {
        self.rar50_split_hash_seeding = seeding;
        self
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// A parsed RAR archive, preserving the concrete archive family.
pub enum Archive {
    /// RAR 1.3/1.4 archive.
    Rar13(rar13::Archive),
    /// RAR 1.5 through RAR 4.x archive.
    Rar15To40(rar15_40::Archive),
    /// RAR 5.0 or later archive, including RAR 7 archives.
    Rar50Plus(rar50::Archive),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Metadata supplied to streaming extraction callbacks.
pub struct ExtractedEntryMeta {
    /// Raw entry name bytes as stored by the archive family.
    pub name: Vec<u8>,
    /// DOS/FAT timestamp when the archive family exposes one.
    pub file_time: u32,
    /// File attributes widened to a common integer type.
    pub file_attr: u64,
    /// Whether the entry is a directory.
    pub is_directory: bool,
}

impl ExtractedEntryMeta {
    /// Creates common metadata for extraction callbacks.
    pub fn new(name: Vec<u8>, file_time: u32, file_attr: u64, is_directory: bool) -> Self {
        Self {
            name,
            file_time,
            file_attr,
            is_directory,
        }
    }

    /// Raw entry name bytes as stored by the archive family.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the entry name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Common member view plus family-specific detail.
pub struct ArchiveMember {
    /// Metadata shared across archive families.
    pub meta: ArchiveMemberMeta,
    /// Extra metadata that is meaningful only for one archive family.
    pub detail: ArchiveMemberDetail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Family-independent metadata for a file-like archive member.
pub struct ArchiveMemberMeta {
    /// Archive family that produced this member.
    pub family: ArchiveFamily,
    /// Raw entry name bytes as stored by the archive.
    pub name: Vec<u8>,
    /// Packed payload size in bytes.
    pub packed_size: u64,
    /// Unpacked file size in bytes.
    pub unpacked_size: u64,
    /// DOS/FAT timestamp when present.
    pub file_time: Option<u32>,
    /// File attributes widened to a common integer type.
    pub file_attr: u64,
    /// Host OS discriminator when present in the archive format.
    pub host_os: Option<u64>,
    /// Whether the member is a directory.
    pub is_directory: bool,
    /// Whether the member payload is encrypted.
    pub is_encrypted: bool,
    /// Whether the member payload is stored without compression.
    pub is_stored: bool,
    /// Whether the member continues from a previous volume.
    pub is_split_before: bool,
    /// Whether the member continues into the next volume.
    pub is_split_after: bool,
}

impl ArchiveMemberMeta {
    /// Raw member name bytes as stored by the archive family.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the member name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Family-specific member metadata.
pub enum ArchiveMemberDetail {
    /// RAR 1.3/1.4 member fields.
    #[non_exhaustive]
    Rar13 {
        /// Compression method byte from the file header.
        method: u8,
        /// Minimum unpacker version byte from the file header.
        unpack_version: u8,
        /// Legacy 16-bit file checksum.
        file_checksum: u16,
        /// Whether the member carries a file-comment extension.
        has_file_comment: bool,
    },
    /// RAR 1.5 through RAR 4.x member fields.
    #[non_exhaustive]
    Rar15To40 {
        /// Compression method byte from the file header.
        method: u8,
        /// Minimum unpacker version byte from the file header.
        unpack_version: u8,
        /// Stored CRC-32 of the unpacked data.
        crc32: u32,
        /// Whether this member participates in a solid stream.
        solid: bool,
        /// Per-file salt when file encryption is used.
        salt: Option<[u8; 8]>,
        /// Whether the member carries a file-comment extension.
        has_file_comment: bool,
    },
    /// RAR 5.0 and later member fields.
    #[non_exhaustive]
    Rar50Plus {
        /// Raw compression-info field from the RAR5 file header.
        compression_info: u64,
        /// Stored CRC-32 when present.
        crc32: Option<u32>,
        /// Strong file hash when present.
        hash: Option<ArchiveMemberHash>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Strong hash metadata attached to an archive member.
pub enum ArchiveMemberHash {
    /// RAR5 BLAKE2sp file hash.
    Blake2sp([u8; 32]),
    /// Unknown hash record retained for inspection.
    Other { hash_type: u64, data: Vec<u8> },
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Lazy iterator returned by [`Archive::members`].
pub struct ArchiveMembers<'a> {
    inner: ArchiveMembersInner<'a>,
    index: usize,
}

#[derive(Debug, Clone)]
enum ArchiveMembersInner<'a> {
    Rar13(&'a [rar13::Entry]),
    Rar15To40(&'a [rar15_40::Block]),
    Rar50Plus(&'a [rar50::Block]),
}

impl Iterator for ArchiveMembers<'_> {
    type Item = ArchiveMember;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner {
            ArchiveMembersInner::Rar13(entries) => {
                let entry = entries.get(self.index)?;
                self.index += 1;
                Some(rar13_member(entry))
            }
            ArchiveMembersInner::Rar15To40(blocks) => {
                while let Some(block) = blocks.get(self.index) {
                    self.index += 1;
                    if let rar15_40::Block::File(file) = block {
                        return Some(rar15_40_member(file));
                    }
                }
                None
            }
            ArchiveMembersInner::Rar50Plus(blocks) => {
                while let Some(block) = blocks.get(self.index) {
                    self.index += 1;
                    if let rar50::Block::File(file) = block {
                        return Some(rar50_member(file));
                    }
                }
                None
            }
        }
    }
}

impl Archive {
    /// Returns the detected archive family.
    pub fn family(&self) -> ArchiveFamily {
        match self {
            Self::Rar13(_) => ArchiveFamily::Rar13,
            Self::Rar15To40(_) => ArchiveFamily::Rar15To40,
            Self::Rar50Plus(_) => ArchiveFamily::Rar50Plus,
        }
    }

    /// Returns the byte offset where the RAR archive begins after any SFX stub.
    pub fn sfx_offset(&self) -> usize {
        match self {
            Self::Rar13(archive) => archive.sfx_offset,
            Self::Rar15To40(archive) => archive.sfx_offset,
            Self::Rar50Plus(archive) => archive.sfx_offset,
        }
    }

    /// Iterates over file-like members using a common cross-version metadata view.
    pub fn members(&self) -> ArchiveMembers<'_> {
        match self {
            Self::Rar13(archive) => ArchiveMembers {
                inner: ArchiveMembersInner::Rar13(&archive.entries),
                index: 0,
            },
            Self::Rar15To40(archive) => ArchiveMembers {
                inner: ArchiveMembersInner::Rar15To40(&archive.blocks),
                index: 0,
            },
            Self::Rar50Plus(archive) => ArchiveMembers {
                inner: ArchiveMembersInner::Rar50Plus(&archive.blocks),
                index: 0,
            },
        }
    }

    /// Streams extracted entries to caller-provided writers.
    pub fn extract_to<F>(&self, password: Option<&[u8]>, open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_to_with_options(read_options(password), open)
    }

    /// Streams extracted entries to caller-provided writers with read options.
    pub fn extract_to_with_options<F>(
        &self,
        options: ArchiveReadOptions<'_>,
        mut open: F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        match self {
            Self::Rar13(archive) => {
                archive.extract_to(options.password, |meta| open(&rar13_meta(meta)))
            }
            Self::Rar15To40(archive) => {
                archive.extract_to(options, |meta| open(&rar15_40_meta(meta)))
            }
            Self::Rar50Plus(archive) => archive.extract_to(options, |meta| open(&rar50_meta(meta))),
        }
    }

    /// Extracts independent non-solid members in parallel, buffering decoded
    /// file bytes before replaying writes in archive order.
    ///
    /// Solid archives, split members, multivolume sets, and RAR 1.3/1.4
    /// archives use the regular streaming extractor.
    #[cfg(feature = "parallel")]
    pub fn extract_to_parallel_buffered<F>(&self, password: Option<&[u8]>, open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_to_parallel_buffered_with_options(read_options(password), open)
    }

    /// Extracts independent non-solid members in parallel with read options.
    #[cfg(feature = "parallel")]
    pub fn extract_to_parallel_buffered_with_options<F>(
        &self,
        options: ArchiveReadOptions<'_>,
        mut open: F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        match self {
            Self::Rar13(archive) => {
                archive.extract_to(options.password, |meta| open(&rar13_meta(meta)))
            }
            Self::Rar15To40(archive) => {
                archive.extract_to_parallel_buffered(options, |meta| open(&rar15_40_meta(meta)))
            }
            Self::Rar50Plus(archive) => {
                archive.extract_to_parallel_buffered(options, |meta| open(&rar50_meta(meta)))
            }
        }
    }

    /// Returns full repaired archive bytes using the archive's embedded
    /// recovery records.
    pub fn repair_recovery(&self) -> Result<Vec<u8>> {
        let mut repaired = Vec::new();
        self.repair_recovery_to(&mut repaired)?;
        Ok(repaired)
    }

    /// Streams full repaired archive bytes to `writer` using embedded recovery
    /// records.
    pub fn repair_recovery_to(&self, writer: &mut dyn Write) -> Result<()> {
        match self {
            Self::Rar15To40(archive) => {
                writer.write_all(&archive.repair_protect_head()?)?;
                Ok(())
            }
            Self::Rar50Plus(archive) => archive.repair_recovery_to(writer),
            Self::Rar13(_) => Err(Error::UnsupportedFamilyFeature {
                family: ArchiveFamily::Rar13,
                feature: "recovery repair for RAR 1.3/1.4 archives",
            }),
        }
    }

    /// Repairs this archive into `dest` from its embedded recovery records,
    /// streaming, with working memory bounded by `budget`.
    ///
    /// Unlike [`Self::repair_recovery_to`], no part of the archive is held:
    /// `dest` gets a copy and is patched in place over the damaged ranges.
    /// This is what a volume-sized archive should use - an 8-20 GB volume
    /// through the buffered path needs more than twice its size in RAM.
    ///
    /// Returns the data-shard indices that were rebuilt (empty when the
    /// recovery record says nothing is damaged). The archive itself is never
    /// written to; publishing `dest` is the caller's decision.
    pub fn repair_recovery_to_file(
        &self,
        dest: &mut std::fs::File,
        password: Option<&[u8]>,
        budget: u64,
    ) -> Result<Vec<usize>> {
        match self {
            // RAR 2/3 protect records were designed for small archives, but
            // the volumes carrying them are not: a legacy volume through the
            // buffered path needs over twice its size resident. The
            // streaming form scans 512-byte sectors by bounded range reads
            // and patches only the damaged ones.
            Self::Rar15To40(archive) => archive.repair_protect_to_file(dest, budget),
            Self::Rar50Plus(archive) => archive.repair_recovery_to_file(dest, password, budget),
            Self::Rar13(_) => Err(Error::UnsupportedFamilyFeature {
                family: ArchiveFamily::Rar13,
                feature: "recovery repair for RAR 1.3/1.4 archives",
            }),
        }
    }

    /// [`Self::repair_recovery_to_file`] for a caller that owns the
    /// destination path. For a RAR5 archive opened from a file this lets
    /// the initial whole-volume copy become a filesystem clone (APFS,
    /// btrfs/XFS reflink) instead of a full read+write; other families and
    /// source shapes behave exactly like the file form.
    pub fn repair_recovery_to_path(
        &self,
        dest: &std::path::Path,
        password: Option<&[u8]>,
        budget: u64,
    ) -> Result<Vec<usize>> {
        match self {
            Self::Rar50Plus(archive) => archive.repair_recovery_to_path(dest, password, budget),
            // The path form matters for the legacy families too: their
            // whole-volume prefill becomes a filesystem clone where the
            // platform supports one.
            Self::Rar15To40(archive) => archive.repair_protect_to_path(dest, budget),
            Self::Rar13(_) => Err(Error::UnsupportedFamilyFeature {
                family: ArchiveFamily::Rar13,
                feature: "recovery repair for RAR 1.3/1.4 archives",
            }),
        }
    }

    /// Returns the concrete RAR 1.3/1.4 archive when this archive has that family.
    pub fn as_rar13(&self) -> Option<&rar13::Archive> {
        match self {
            Self::Rar13(archive) => Some(archive),
            Self::Rar15To40(_) => None,
            Self::Rar50Plus(_) => None,
        }
    }

    /// Returns the concrete RAR 1.5 through RAR 4.x archive when applicable.
    pub fn as_rar15_40(&self) -> Option<&rar15_40::Archive> {
        match self {
            Self::Rar13(_) => None,
            Self::Rar15To40(archive) => Some(archive),
            Self::Rar50Plus(_) => None,
        }
    }

    /// Returns the concrete RAR 5.0 or later archive when applicable.
    pub fn as_rar50(&self) -> Option<&rar50::Archive> {
        match self {
            Self::Rar13(_) | Self::Rar15To40(_) => None,
            Self::Rar50Plus(archive) => Some(archive),
        }
    }
}

fn rar13_member(entry: &rar13::Entry) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar13,
            name: entry.name.clone(),
            packed_size: u64::from(entry.header.pack_size),
            unpacked_size: u64::from(entry.header.unp_size),
            file_time: Some(entry.header.file_time),
            file_attr: u64::from(entry.header.file_attr),
            host_os: None,
            is_directory: entry.is_directory(),
            is_encrypted: entry.is_encrypted(),
            is_stored: entry.is_stored(),
            is_split_before: entry.is_split_before(),
            is_split_after: entry.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar13 {
            method: entry.header.method,
            unpack_version: entry.header.unp_ver,
            file_checksum: entry.header.file_crc,
            has_file_comment: entry.has_file_comment(),
        },
    }
}

fn rar15_40_member(file: &rar15_40::FileHeader) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar15To40,
            name: file.name.clone(),
            packed_size: file.pack_size,
            unpacked_size: file.unp_size,
            file_time: Some(file.file_time),
            file_attr: u64::from(file.attr),
            host_os: Some(u64::from(file.host_os)),
            is_directory: file.is_directory(),
            is_encrypted: file.is_encrypted(),
            is_stored: file.is_stored(),
            is_split_before: file.is_split_before(),
            is_split_after: file.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar15To40 {
            method: file.method,
            unpack_version: file.unp_ver,
            crc32: file.file_crc,
            solid: file.is_solid(),
            salt: file.salt,
            has_file_comment: file.has_file_comment(),
        },
    }
}

fn rar50_member(file: &rar50::FileHeader) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar50Plus,
            name: file.name.clone(),
            packed_size: file.packed_size(),
            unpacked_size: file.unpacked_size,
            file_time: file.mtime,
            file_attr: file.attributes,
            host_os: Some(file.host_os),
            is_directory: file.is_directory(),
            is_encrypted: file.encrypted,
            is_stored: file.is_stored(),
            is_split_before: file.is_split_before(),
            is_split_after: file.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar50Plus {
            compression_info: file.compression_info,
            crc32: file.data_crc32,
            hash: file.hash.as_ref().map(rar50_member_hash),
        },
    }
}

fn rar50_member_hash(hash: &rar50::FileHash) -> ArchiveMemberHash {
    match hash.hash_type {
        0 if hash.data.len() == 32 => {
            let mut data = [0; 32];
            data.copy_from_slice(&hash.data);
            ArchiveMemberHash::Blake2sp(data)
        }
        _ => ArchiveMemberHash::Other {
            hash_type: hash.hash_type,
            data: hash.data.clone(),
        },
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Archive reader facade with signature-based dispatch.
pub struct ArchiveReader;

/// A parse session over one password/options set: every archive read
/// through it shares one RAR 5 key-derivation cache, so a multi-volume
/// encrypted set derives each (salt, kdf count) once for the whole set
/// instead of once per volume - on a 500-volume set the repeated PBKDF2
/// dwarfs the parsing itself. Per-member and per-header password checks
/// still run for every volume; the cache holds keys only as long as the
/// session lives (Rar50Keys zeroize on drop), and sessions never share
/// state with each other or any global.
pub struct ReadSession<'a> {
    options: ArchiveReadOptions<'a>,
    key_cache: rar50::Rar50KeyCache,
}

impl<'a> ReadSession<'a> {
    pub fn new(options: ArchiveReadOptions<'a>) -> Self {
        Self {
            options,
            key_cache: rar50::Rar50KeyCache::default(),
        }
    }

    /// Parse one archive; repeated (salt, kdf count) derivations are
    /// served from the session cache.
    pub fn read_path(&mut self, path: impl AsRef<Path>) -> Result<Archive> {
        ArchiveReader::read_path_dispatch(path, self.options, &mut self.key_cache)
    }

    /// Actual PBKDF2 runs this session performed (cache misses).
    #[cfg(test)]
    fn derive_count(&self) -> usize {
        self.key_cache.derives
    }
}

impl ArchiveReader {
    /// Detects the archive signature in a byte slice.
    pub fn detect(input: &[u8]) -> Result<ArchiveSignature> {
        detect_archive_family(input).ok_or(Error::UnsupportedSignature)
    }

    /// Parses an archive from memory with default read options.
    pub fn read(input: &[u8]) -> Result<Archive> {
        Self::read_with_options(input, ArchiveReadOptions::default())
    }

    /// Parses an archive from an owned memory buffer with default read options.
    pub fn read_owned(input: Vec<u8>) -> Result<Archive> {
        Self::read_owned_with_options(input, ArchiveReadOptions::default())
    }

    /// Parses an archive from memory using explicit read options.
    pub fn read_with_options(input: &[u8], options: ArchiveReadOptions<'_>) -> Result<Archive> {
        let signature =
            find_archive_start(input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse(input)?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_with_options(input, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(rar50::Archive::parse_with_options(
                input, options,
            )?)),
        }
    }

    /// Parses an archive from an owned memory buffer using explicit read options.
    pub fn read_owned_with_options(
        input: Vec<u8>,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Archive> {
        let signature =
            find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse_owned(input)?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_owned_with_options(input, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(
                rar50::Archive::parse_owned_with_options(input, options)?,
            )),
        }
    }

    /// Parses an archive from a path with default read options.
    pub fn read_path(path: impl AsRef<Path>) -> Result<Archive> {
        Self::read_path_with_options(path, ArchiveReadOptions::default())
    }

    /// Parses an archive from a path using explicit read options.
    pub fn read_path_with_options(
        path: impl AsRef<Path>,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Archive> {
        ReadSession::new(options).read_path(path)
    }

    fn read_path_dispatch(
        path: impl AsRef<Path>,
        options: ArchiveReadOptions<'_>,
        key_cache: &mut rar50::Rar50KeyCache,
    ) -> Result<Archive> {
        let path = path.as_ref();
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        let mut scan = vec![0; len.min(SFX_SCAN_LIMIT as u64) as usize];
        file.read_exact(&mut scan)?;
        let signature =
            find_archive_start(&scan, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse_path_with_signature(
                path, signature,
            )?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_path_with_signature(path, signature, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(
                rar50::Archive::parse_path_with_signature_in_session(
                    path,
                    signature,
                    options.password,
                    key_cache,
                )?,
            )),
        }
    }

    /// Parses an archive from a source whose bytes are still arriving.
    ///
    /// `expected_len` is the archive's final size, known to the caller up
    /// front. Reads BLOCK until the requested bytes arrive, so both this
    /// call and extraction from the returned archive wait at the data
    /// frontier instead of failing; the source's abort path unblocks them
    /// with an error (see [`BlockingRangeSource`]).
    ///
    /// Streaming sources are supported for the RAR 5 and RAR 1.5-4.x
    /// families, and the signature must sit at offset 0 (no SFX stub
    /// scan). RAR 1.3/1.4 fails with a clean unsupported-feature error.
    pub fn read_stream(
        source: std::sync::Arc<dyn BlockingRangeSource>,
        expected_len: u64,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Archive> {
        // Peek just the signature: the longest one is 8 bytes, so this
        // blocks only until the very first bytes arrive.
        let peek_len = detect::RAR50_SIGNATURE
            .len()
            .min(usize::try_from(expected_len).unwrap_or(usize::MAX));
        let mut peek = vec![0u8; peek_len];
        source::stream_read_exact(source.as_ref(), 0, &mut peek)?;
        let signature = detect_archive_family(&peek).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(rar50::Archive::parse_stream(
                source,
                expected_len,
                options,
            )?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(rar15_40::Archive::parse_stream(
                source,
                expected_len,
                options,
            )?)),
            family @ ArchiveFamily::Rar13 => Err(Error::UnsupportedFamilyFeature {
                family,
                feature: "streaming archive source",
            }),
        }
    }
}

fn read_options(password: Option<&[u8]>) -> ArchiveReadOptions<'_> {
    match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    }
}

/// Streams a multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(archives: &[Archive], password: Option<&[u8]>, open: F) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volumes_to_with_options(archives, read_options(password), open)
}

/// Streams a multivolume archive set to caller-provided writers with read options.
pub fn extract_volumes_to_with_options<F>(
    archives: &[Archive],
    options: ArchiveReadOptions<'_>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let Some(first) = archives.first() else {
        return Err(Error::InvalidHeader("volume set is empty"));
    };

    match first.family() {
        ArchiveFamily::Rar13 => {
            let typed = rar13_volumes(archives)?;
            rar13::extract_volumes_to(&typed, options.password, |meta| open(&rar13_meta(meta)))
        }
        ArchiveFamily::Rar15To40 => {
            let typed = rar15_40_volumes(archives)?;
            rar15_40::extract_volumes_to(&typed, options, |meta| open(&rar15_40_meta(meta)))
        }
        ArchiveFamily::Rar50Plus => {
            let typed = rar50_volumes(archives)?;
            rar50::extract_volumes_to(&typed, options, |meta| open(&rar50_meta(meta)))
        }
    }
}

/// [`extract_volumes_to_with_options`] reporting each volume the engine
/// is finished with.
///
/// `consumed(volume_index)` indexes `archives`, arrives in increasing
/// order once each, and promises that no read will ever touch that
/// volume again - so a caller holding the set on disk can delete it
/// there and then. A split member spanning many volumes releases them
/// PROGRESSIVELY as its chain advances (RAR 1.5-4 and RAR 5; RAR 1.3
/// still releases the backlog after the member completes), so the
/// single-split-member movie shape extracts without ever holding the
/// whole set and the payload at once. See
/// [`rar50::extract_volumes_to_with_progress`] for what makes the
/// promise true (and, for RAR 5, what it costs: the parallel member pool
/// is off while the watermark is armed). The callback can run on the
/// decode thread, hence `Send`.
///
/// The volumes are handed to the family extractors in the order given,
/// which is the order the set is read in, so the index the callback
/// carries is an index into the caller's own list.
pub fn extract_volumes_to_with_progress<F, C>(
    archives: &[Archive],
    options: ArchiveReadOptions<'_>,
    mut open: F,
    consumed: C,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    C: FnMut(usize) + Send,
{
    let Some(first) = archives.first() else {
        return Err(Error::InvalidHeader("volume set is empty"));
    };

    match first.family() {
        ArchiveFamily::Rar13 => {
            let typed = rar13_volumes(archives)?;
            rar13::extract_volumes_to_with_progress(
                &typed,
                options.password,
                |meta| open(&rar13_meta(meta)),
                consumed,
            )
        }
        ArchiveFamily::Rar15To40 => {
            let typed = rar15_40_volumes(archives)?;
            rar15_40::extract_volumes_to_with_progress(
                &typed,
                options,
                |meta| open(&rar15_40_meta(meta)),
                consumed,
            )
        }
        ArchiveFamily::Rar50Plus => {
            let typed = rar50_volumes(archives)?;
            rar50::extract_volumes_to_with_progress(
                &typed,
                options,
                |meta| open(&rar50_meta(meta)),
                consumed,
            )
        }
    }
}

fn rar13_meta(meta: &rar13::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: meta.file_time,
        file_attr: u64::from(meta.file_attr),
        is_directory: meta.is_directory,
    }
}

fn rar15_40_meta(meta: &rar15_40::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: meta.file_time,
        file_attr: u64::from(meta.attr),
        is_directory: meta.is_directory,
    }
}

fn rar50_meta(meta: &rar50::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: meta.file_time,
        file_attr: meta.attr,
        is_directory: meta.is_directory,
    }
}

fn rar13_volumes(archives: &[Archive]) -> Result<Vec<rar13::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar13(archive) => Ok(archive.clone()),
            Archive::Rar15To40(_) | Archive::Rar50Plus(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

fn rar15_40_volumes(archives: &[Archive]) -> Result<Vec<rar15_40::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar15To40(archive) => Ok(archive.clone()),
            Archive::Rar13(_) | Archive::Rar50Plus(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

fn rar50_volumes(archives: &[Archive]) -> Result<Vec<rar50::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar50Plus(archive) => Ok(archive.clone()),
            Archive::Rar13(_) | Archive::Rar15To40(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    struct CollectWriter {
        data: Rc<RefCell<Vec<u8>>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CollectedEntry {
        name: Vec<u8>,
        data: Vec<u8>,
        file_time: u32,
        file_attr: u64,
        is_directory: bool,
    }

    fn deterministic_noise(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    fn rar15_40_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar15_40")
            .join(name)
    }

    #[test]
    fn extracted_entry_meta_exposes_raw_and_lossy_names() {
        let meta = ExtractedEntryMeta {
            name: vec![0xff, b'.', b't', b'x', b't'],
            file_time: 0,
            file_attr: 0,
            is_directory: false,
        };

        assert_eq!(meta.name_bytes(), [0xff, b'.', b't', b'x', b't']);
        assert_eq!(meta.name_lossy(), "\u{fffd}.txt");
    }

    impl Write for CollectWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.data.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn collect_extract(archive: &Archive, password: Option<&[u8]>) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        archive.extract_to(password, |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: meta.file_attr,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_rar15_40(archive: &rar15_40::Archive) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        archive.extract_to(ArchiveReadOptions::default(), |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: u64::from(meta.attr),
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_rar15_40_volumes(
        archives: &[rar15_40::Archive],
        password: Option<&[u8]>,
    ) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        rar15_40::extract_volumes_to(archives, read_options(password), |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: u64::from(meta.attr),
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_rar50_volumes(
        archives: &[rar50::Archive],
        password: Option<&[u8]>,
    ) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        rar50::extract_volumes_to(archives, read_options(password), |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: meta.attr,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_rar50_file(
        archive: &rar50::Archive,
        file: &rar50::FileHeader,
    ) -> Result<CollectedEntry> {
        let meta = file.metadata();
        let data = Rc::new(RefCell::new(Vec::new()));
        file.write_to(
            archive,
            None,
            &mut CollectWriter {
                data: Rc::clone(&data),
            },
        )?;
        let data = data.borrow().clone();
        Ok(CollectedEntry {
            name: meta.name,
            data,
            file_time: meta.file_time,
            file_attr: meta.attr,
            is_directory: meta.is_directory,
        })
    }

    fn rar13_options(target: ArchiveVersion) -> rar13::WriterOptions {
        rar13::WriterOptions::new(target, FeatureSet::store_only())
    }

    fn rar15_options(target: ArchiveVersion) -> rar15_40::WriterOptions {
        rar15_options_with_features(target, FeatureSet::store_only())
    }

    fn rar15_options_with_features(
        target: ArchiveVersion,
        features: FeatureSet,
    ) -> rar15_40::WriterOptions {
        rar15_40::WriterOptions::new(target, features)
    }

    fn rar50_options(target: ArchiveVersion) -> rar50::WriterOptions {
        rar50_options_with_features(target, FeatureSet::store_only())
    }

    fn rar50_options_with_features(
        target: ArchiveVersion,
        features: FeatureSet,
    ) -> rar50::WriterOptions {
        rar50::WriterOptions::new(target, features)
    }

    fn write_rar29_filter(
        options: rar15_40::WriterOptions,
        entries: &[rar15_40::FileEntry<'_>],
        kind: rar15_40::FilterKind,
    ) -> Result<Vec<u8>> {
        rar15_40::write_rar29_compressed_archive_with_filter_policy(
            entries,
            options,
            rar15_40::FilterPolicy::Explicit(rar15_40::FilterSpec::whole(kind)),
        )
    }

    fn write_rar29_filter_range(
        options: rar15_40::WriterOptions,
        entries: &[rar15_40::FileEntry<'_>],
        kind: rar15_40::FilterKind,
        range: std::ops::Range<usize>,
    ) -> Result<Vec<u8>> {
        rar15_40::write_rar29_compressed_archive_with_filter_policy(
            entries,
            options,
            rar15_40::FilterPolicy::Explicit(rar15_40::FilterSpec::range(kind, range)),
        )
    }

    fn assert_rar50_volume_recovery_records(archives: &[rar50::Archive], percent: u64) {
        assert!(archives.iter().all(|archive| archive.main.is_volume()));
        assert!(archives
            .iter()
            .all(|archive| archive.main.has_recovery_record()));
        for archive in archives {
            let service = archive.services().next().unwrap();
            assert_eq!(service.name, b"RR");
            assert_eq!(service.recovery_record().unwrap().unwrap().percent, percent);
            let data = collect_rar50_file(archive, service).unwrap().data;
            assert!(data.starts_with(b"{RB}"));
            assert_eq!(
                u32::from_le_bytes(data[0x0c..0x10].try_into().unwrap()) as usize,
                data.len()
            );
        }
    }

    #[test]
    fn direct_writer_creates_rar15_stored_archive() {
        let bytes = rar15_40::write_stored_archive(
            &[rar15_40::StoredEntry {
                name: b"hello.txt",
                data: b"hello via facade\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar15),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].data, b"hello via facade\n");
    }

    #[test]
    fn archive_reader_accepts_owned_buffers_without_changing_dispatch() {
        let rar13_bytes = rar13::write_stored_archive(
            &[rar13::StoredEntry {
                name: b"old.txt",
                data: b"owned rar13\n",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            }],
            rar13_options(ArchiveVersion::Rar14),
        )
        .unwrap();
        let rar13_archive = ArchiveReader::read_owned(rar13_bytes).unwrap();
        assert_eq!(rar13_archive.family(), ArchiveFamily::Rar13);
        assert_eq!(
            collect_extract(&rar13_archive, None).unwrap()[0].data,
            b"owned rar13\n"
        );

        let rar15_bytes = rar15_40::write_stored_archive(
            &[rar15_40::StoredEntry {
                name: b"mid.txt",
                data: b"owned rar15\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar15),
        )
        .unwrap();
        let rar15_archive = ArchiveReader::read_owned(rar15_bytes).unwrap();
        assert_eq!(rar15_archive.family(), ArchiveFamily::Rar15To40);
        assert_eq!(
            collect_extract(&rar15_archive, None).unwrap()[0].data,
            b"owned rar15\n"
        );

        let rar50_bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .stored_entries(&[rar50::StoredEntry {
                name: b"new.txt",
                data: b"owned rar50\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .finish()
            .unwrap();
        let rar50_archive = ArchiveReader::read_owned(rar50_bytes).unwrap();
        assert_eq!(rar50_archive.family(), ArchiveFamily::Rar50Plus);
        assert_eq!(
            collect_extract(&rar50_archive, None).unwrap()[0].data,
            b"owned rar50\n"
        );
    }

    #[test]
    fn direct_writer_keeps_rar13_methods_version_typed() {
        let err =
            rar13::write_stored_archive(&[], rar13_options(ArchiveVersion::Rar15)).unwrap_err();

        assert!(matches!(
            err,
            Error::UnsupportedVersion(ArchiveVersion::Rar15)
        ));
    }

    #[test]
    fn archive_members_exposes_rar13_common_metadata_and_typed_detail() {
        let bytes = rar13::write_stored_archive(
            &[rar13::StoredEntry {
                name: b"old.txt",
                data: b"old rar member",
                file_time: 0x1234_5678,
                file_attr: 0x20,
                password: None,
                file_comment: Some(b"note"),
            }],
            rar13_options(ArchiveVersion::Rar14),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let members: Vec<_> = archive.members().collect();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].meta.family, ArchiveFamily::Rar13);
        assert_eq!(members[0].meta.name, b"old.txt");
        assert_eq!(members[0].meta.name_bytes(), b"old.txt");
        assert_eq!(members[0].meta.name_lossy(), "old.txt");
        assert_eq!(members[0].meta.packed_size, b"old rar member".len() as u64);
        assert_eq!(
            members[0].meta.unpacked_size,
            b"old rar member".len() as u64
        );
        assert_eq!(members[0].meta.file_time, Some(0x1234_5678));
        assert_eq!(members[0].meta.file_attr, 0x20);
        assert_eq!(members[0].meta.host_os, None);
        assert!(members[0].meta.is_stored);
        assert!(!members[0].meta.is_encrypted);
        assert!(!members[0].meta.is_split_before);
        assert!(!members[0].meta.is_split_after);
        assert!(matches!(
            members[0].detail,
            ArchiveMemberDetail::Rar13 {
                method: 0,
                unpack_version: _,
                file_checksum: _,
                has_file_comment: true,
            }
        ));
    }

    #[test]
    fn archive_members_exposes_rar15_40_common_metadata_and_typed_detail() {
        let mut features = FeatureSet::store_only();
        features.file_comment = true;
        let payload = b"rar 2.9 member metadata ".repeat(32);
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"newer.txt",
                data: &payload,
                file_time: 0x0102_0304,
                file_attr: 0x20,
                host_os: 2,
                password: None,
                file_comment: Some(b"rar29 note"),
            }],
            rar15_options_with_features(ArchiveVersion::Rar29, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let members: Vec<_> = archive.members().collect();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].meta.family, ArchiveFamily::Rar15To40);
        assert_eq!(members[0].meta.name, b"newer.txt");
        assert_eq!(members[0].meta.unpacked_size, payload.len() as u64);
        assert_eq!(members[0].meta.file_time, Some(0x0102_0304));
        assert_eq!(members[0].meta.file_attr, 0x20);
        assert_eq!(members[0].meta.host_os, Some(2));
        assert!(!members[0].meta.is_stored);
        assert!(!members[0].meta.is_encrypted);
        assert!(matches!(
            members[0].detail,
            ArchiveMemberDetail::Rar15To40 {
                method: 0x33 | 0x35,
                unpack_version: 29,
                crc32: _,
                solid: false,
                salt: None,
                has_file_comment: true,
            }
        ));
    }

    #[test]
    fn archive_members_exposes_rar50_common_metadata_and_typed_detail() {
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .stored_entries(&[rar50::StoredEntry {
                name: b"five.txt",
                data: b"rar 5 member metadata",
                mtime: Some(0x1111_2222),
                attributes: 0x1_0000_0020,
                host_os: 3,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let members: Vec<_> = archive.members().collect();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].meta.family, ArchiveFamily::Rar50Plus);
        assert_eq!(members[0].meta.name, b"five.txt");
        assert_eq!(
            members[0].meta.packed_size,
            b"rar 5 member metadata".len() as u64
        );
        assert_eq!(
            members[0].meta.unpacked_size,
            b"rar 5 member metadata".len() as u64
        );
        assert_eq!(members[0].meta.file_time, Some(0x1111_2222));
        assert_eq!(members[0].meta.file_attr, 0x1_0000_0020);
        assert_eq!(members[0].meta.host_os, Some(3));
        assert!(members[0].meta.is_stored);
        assert!(!members[0].meta.is_encrypted);
        assert!(matches!(
            members[0].detail,
            ArchiveMemberDetail::Rar50Plus {
                compression_info: _,
                crc32: _,
                hash: _,
            }
        ));
    }

    #[test]
    fn extraction_metadata_preserves_rar50_u64_file_attributes() {
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .stored_entries(&[rar50::StoredEntry {
                name: b"wide-attrs.txt",
                data: b"wide RAR5 file attributes",
                mtime: Some(0),
                attributes: 0x1_0000_0020,
                host_os: 3,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();

        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"wide-attrs.txt");
        assert_eq!(extracted[0].file_attr, 0x1_0000_0020);
    }

    #[test]
    fn direct_writer_creates_rar15_compressed_archive() {
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"text.txt",
                data: b"facade compressed facade compressed facade compressed\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar15),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade compressed facade compressed facade compressed\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar29_compressed_archive_with_default_auto_policy() {
        let payload =
            b"facade rar29 default auto text alpha beta gamma alpha beta gamma\n".repeat(256);
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar29-default-auto.txt",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar29),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert_eq!(raw.files().next().unwrap().method, 0x35);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar29 e8 filter payload\n".repeat(12);
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_auto_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar29 auto filter payload\n".repeat(12);
        let bytes = rar15_40::write_rar29_compressed_archive_with_filter_policy(
            &[rar15_40::FileEntry {
                name: b"rar29-auto.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar29),
            rar15_40::FilterPolicy::Auto,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_ppmd_compressed_archive() {
        let payload = b"facade rar29 ppmd text payload alpha beta gamma\n".repeat(64);
        let bytes = rar15_40::write_rar29_compressed_archive_with_filter_policy(
            &[rar15_40::FileEntry {
                name: b"rar29-ppmd.txt",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar29),
            rar15_40::FilterPolicy::Ppmd,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.method, 0x35);
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_segmented_e8_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before x86 segment ".to_vec();
        let filter_start = payload.len();
        payload.extend_from_slice(b"\xe8\0\0\0\0facade segmented e8 filter payload\n");
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after x86 segment\n");
        let bytes = write_rar29_filter_range(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_solid_e8_filtered_compressed_archive() {
        let first = b"\xe8\0\0\0\0facade rar29 solid e8 first payload\n".repeat(12);
        let second = b"\xe8\0\0\0\0facade rar29 solid e8 second payload\n".repeat(12);
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes = write_rar29_filter(
            rar15_options_with_features(ArchiveVersion::Rar29, features),
            &[
                rar15_40::FileEntry {
                    name: b"rar29-solid-e8-first.bin",
                    data: &first,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"rar29-solid-e8-second.bin",
                    data: &second,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn direct_writer_creates_rar29_encrypted_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar29 encrypted e8 payload\n".repeat(12);
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = write_rar29_filter(
            rar15_options_with_features(ArchiveVersion::Rar29, features),
            &[rar15_40::FileEntry {
                name: b"rar29-encrypted-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert!(file.is_encrypted());
        assert!(file.salt.is_some());
        assert!(matches!(
            collect_extract(&archive, Some(b"wrong")),
            Err(Error::WrongPasswordOrCorruptData)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar30_header_encrypted_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar30 header encrypted e8 payload\n".repeat(12);
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let bytes = write_rar29_filter(
            rar15_options_with_features(ArchiveVersion::Rar30, features),
            &[rar15_40::FileEntry {
                name: b"rar30-header-encrypted-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_encrypted_headers());
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_e8e9_filtered_compressed_archive() {
        let payload = b"\xe9\0\0\0\0facade rar29 e8e9 filter payload\n".repeat(12);
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-e8e9.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::E8E9,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_delta_filtered_compressed_archive() {
        let payload: Vec<u8> = (0..384).map(|index| (index * 19 + 5) as u8).collect();
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-delta.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Delta { channels: 3 },
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_segmented_delta_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before delta segment ".to_vec();
        let filter_start = payload.len();
        payload.extend((0..384).map(|index| (index * 19 + 5) as u8));
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after delta segment\n");
        let bytes = write_rar29_filter_range(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-delta.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Delta { channels: 3 },
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_itanium_filtered_compressed_archive() {
        let mut payload = vec![0u8; 48];
        payload[16] = 22;
        payload[21] = 20;
        payload.extend_from_slice(b"facade rar29 itanium filter payload\n");
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-itanium.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Itanium,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_segmented_itanium_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before itanium segment ".to_vec();
        let filter_start = payload.len();
        payload.extend_from_slice(&[0; 48]);
        payload[filter_start + 16] = 22;
        payload[filter_start + 21] = 20;
        payload.extend_from_slice(b"facade segmented itanium filter payload\n");
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after itanium segment\n");
        let bytes = write_rar29_filter_range(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-itanium.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Itanium,
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_rgb_filtered_compressed_archive() {
        let width = 12;
        let payload: Vec<u8> = (0..96).map(|index| (index * 37 + 17) as u8).collect();
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-rgb.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Rgb { width, pos_r: 0 },
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_segmented_rgb_filtered_compressed_archive() {
        let width = 12;
        let mut payload = b"facade unfiltered prefix before rgb segment ".to_vec();
        let filter_start = payload.len();
        payload.extend((0..96).map(|index| (index * 37 + 17) as u8));
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after rgb segment\n");
        let bytes = write_rar29_filter_range(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-rgb.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Rgb { width, pos_r: 0 },
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_audio_filtered_compressed_archive() {
        let payload: Vec<u8> = (0..160)
            .map(|index| (index * 11 + index / 7) as u8)
            .collect();
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-audio.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Audio { channels: 2 },
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_segmented_audio_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before audio segment ".to_vec();
        let filter_start = payload.len();
        payload.extend((0..160).map(|index| (index * 11 + index / 7) as u8));
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after audio segment\n");
        let bytes = write_rar29_filter_range(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-audio.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Audio { channels: 2 },
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar20_compressed_archive() {
        let payload = b"facade rar20 literal compressed payload\n".repeat(32);
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar20.txt",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar20),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 20);
        assert_eq!(file.method, 0x33);
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_compressed_archive() {
        let payload = b"facade rar29 literal compressed payload\n".repeat(32);
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar29.txt",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar29),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 29);
        assert!(matches!(file.method, 0x33 | 0x35));
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes = rar15_40::write_compressed_archive(
            &[
                rar15_40::FileEntry {
                    name: b"one.txt",
                    data: b"facade rar29 solid one alpha beta\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"two.txt",
                    data: b"facade rar29 solid two alpha beta\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ],
            rar15_options_with_features(ArchiveVersion::Rar29, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.is_solid());
        let files: Vec<_> = raw.files().collect();
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar29 solid one alpha beta\n");
        assert_eq!(extracted[1].data, b"facade rar29 solid two alpha beta\n");
    }

    #[test]
    fn direct_writer_creates_rar20_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let first = b"facade rar20 solid shared line alpha beta gamma\n".repeat(48);
        let second = b"facade rar20 solid shared line alpha beta gamma\nsecond\n".repeat(24);
        let bytes = rar15_40::write_compressed_archive(
            &[
                rar15_40::FileEntry {
                    name: b"one.txt",
                    data: &first,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"two.txt",
                    data: &second,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ],
            rar15_options_with_features(ArchiveVersion::Rar20, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.is_solid());
        let files: Vec<_> = raw.files().collect();
        assert_eq!(files[0].unp_ver, 20);
        assert_eq!(files[1].unp_ver, 20);
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn direct_writer_creates_rar15_archive_comment() {
        let mut features = FeatureSet::store_only();
        features.archive_comment = true;
        let bytes = rar15_40::write_compressed_archive_with_comment(
            &[rar15_40::FileEntry {
                name: b"commented.txt",
                data: b"facade commented payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar15, features),
            Some(b"facade note\n"),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let archive = archive.as_rar15_40().unwrap();
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&b"facade note\n"[..])
        );
        assert_eq!(
            collect_rar15_40(archive).unwrap()[0].data,
            b"facade commented payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar15_file_comment() {
        let mut features = FeatureSet::store_only();
        features.file_comment = true;
        let bytes = rar15_40::write_stored_archive(
            &[rar15_40::StoredEntry {
                name: b"file-comment.txt",
                data: b"facade file comment payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: Some(b"facade file note"),
            }],
            rar15_options_with_features(ArchiveVersion::Rar15, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let archive = archive.as_rar15_40().unwrap();
        let file = archive.files().next().unwrap();
        assert_eq!(
            file.file_comment().unwrap().as_deref(),
            Some(&b"facade file note"[..])
        );
        assert_eq!(
            collect_rar15_40(archive).unwrap()[0].data,
            b"facade file comment payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar20_old_style_comments() {
        let mut archive_features = FeatureSet::store_only();
        archive_features.archive_comment = true;
        let bytes = rar15_40::write_compressed_archive_with_comment(
            &[rar15_40::FileEntry {
                name: b"rar20-commented.txt",
                data: b"facade rar20 archive comment payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar20, archive_features),
            Some(b"facade rar20 archive note"),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_archive_comment());
        assert_eq!(
            raw.archive_comment().unwrap().as_deref(),
            Some(b"facade rar20 archive note".as_slice())
        );

        let mut file_features = FeatureSet::store_only();
        file_features.file_comment = true;
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar20-file-commented.txt",
                data: b"facade rar20 file comment payload payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: Some(b"facade rar20 file note"),
            }],
            rar15_options_with_features(ArchiveVersion::Rar20, file_features),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 20);
        assert_eq!(
            file.file_comment().unwrap().as_deref(),
            Some(b"facade rar20 file note".as_slice())
        );
    }

    #[test]
    fn direct_writer_creates_rar29_old_style_comments() {
        let mut archive_features = FeatureSet::store_only();
        archive_features.archive_comment = true;
        let bytes = rar15_40::write_compressed_archive_with_comment(
            &[rar15_40::FileEntry {
                name: b"rar29-commented.txt",
                data: b"facade rar29 archive comment payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar29, archive_features),
            Some(b"facade rar29 archive note"),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_archive_comment());
        assert_eq!(
            raw.archive_comment().unwrap().as_deref(),
            Some(b"facade rar29 archive note".as_slice())
        );

        let mut file_features = FeatureSet::store_only();
        file_features.file_comment = true;
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar29-file-commented.txt",
                data: b"facade rar29 file comment payload payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: Some(b"facade rar29 file note"),
            }],
            rar15_options_with_features(ArchiveVersion::Rar29, file_features),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 29);
        assert_eq!(
            file.file_comment().unwrap().as_deref(),
            Some(b"facade rar29 file note".as_slice())
        );
    }

    #[test]
    fn direct_writer_creates_rar30_newsub_archive_comment() {
        let mut features = FeatureSet::store_only();
        features.archive_comment = true;
        let bytes = rar15_40::write_compressed_archive_with_comment(
            &[rar15_40::FileEntry {
                name: b"rar30-commented.txt",
                data: b"facade rar30 NEWSUB archive comment payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar30, features),
            Some(b"facade rar30 NEWSUB note"),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(!raw.main.has_archive_comment());
        let subblock = raw.new_subs().next().unwrap();
        assert_eq!(subblock.kind, rar15_40::NewSubKind::ArchiveComment);
        assert_eq!(subblock.file.name, b"CMT");
        assert_eq!(
            raw.archive_comment().unwrap().as_deref(),
            Some(b"facade rar30 NEWSUB note".as_slice())
        );
    }

    #[test]
    fn direct_writer_creates_rar15_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes = rar15_40::write_compressed_archive(
            &[
                rar15_40::FileEntry {
                    name: b"one.txt",
                    data: b"shared facade prefix one\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"two.txt",
                    data: b"shared facade prefix two\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ],
            rar15_options_with_features(ArchiveVersion::Rar15, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"shared facade prefix one\n");
        assert_eq!(extracted[1].data, b"shared facade prefix two\n");
    }

    #[test]
    fn direct_writer_creates_rar15_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"secret.txt",
                data: b"facade encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar15, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade encrypted payload\n");
    }

    /// A split STORED member carries the whole-file CRC on its last
    /// fragment, and a corrupted fragment is refused on extraction. The
    /// volume writer's stored branches passed `None` for the CRC, so a
    /// set built over incompressible data (which the compressed writer
    /// also stores) had no checksum anywhere and extracted corrupt bytes
    /// as a success. (nzbfast-local change, 22 Aug 2026.)
    #[test]
    fn stored_split_volumes_carry_a_final_crc_and_refuse_corruption() {
        let payload: Vec<u8> = (0..50_000u32)
            .flat_map(|i| i.wrapping_mul(2_654_435_761).to_le_bytes())
            .collect();
        for parts in [
            rar50::Rar50VolumeWriter::new(rar50_options(ArchiveVersion::Rar50))
                .stored_entry(rar50::StoredEntry {
                    name: b"split.bin",
                    data: &payload,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                })
                .max_payload_per_volume(64 * 1024)
                .finish()
                .unwrap(),
            rar50::Rar50VolumeWriter::new(rar50_options(ArchiveVersion::Rar50))
                .compressed_entries(&[rar50::CompressedEntry {
                    name: b"split.bin",
                    data: &payload,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                }])
                .max_payload_per_volume(64 * 1024)
                .finish()
                .unwrap(),
        ] {
            assert!(parts.len() >= 3, "the set must split across volumes");
            let archives: Vec<_> = parts
                .iter()
                .map(|part| rar50::Archive::parse(part).unwrap())
                .collect();
            let crcs: Vec<Option<u32>> = archives
                .iter()
                .flat_map(|a| a.files().map(|f| f.data_crc32))
                .collect();
            assert_eq!(crcs.last().copied().flatten(), Some(crc32::crc32(&payload)));
            assert!(crcs[..crcs.len() - 1].iter().all(Option::is_none));
            let pristine = collect_rar50_volumes(&archives, None).unwrap();
            assert_eq!(pristine[0].data, payload);

            let mut damaged = parts.clone();
            let mid = damaged[1].len() / 2;
            damaged[1][mid] ^= 0x5a;
            let archives: Vec<_> = damaged
                .iter()
                .map(|part| rar50::Archive::parse(part).unwrap())
                .collect();
            let err = collect_rar50_volumes(&archives, None).unwrap_err();
            assert!(
                err.to_string().contains("checksum mismatch"),
                "expected a checksum failure, got {err}"
            );
        }
    }

    #[test]
    fn direct_writer_creates_rar15_stored_volumes() {
        let parts = rar15_40::write_stored_volumes(
            rar15_40::StoredEntry {
                name: b"split.bin",
                data: b"abcdefghijklmnopqrstuvwxyz0123456789",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_options(ArchiveVersion::Rar15),
            10,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let extracted = collect_rar15_40_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split.bin");
        assert_eq!(extracted[0].data, b"abcdefghijklmnopqrstuvwxyz0123456789");
    }

    #[test]
    fn direct_writer_creates_rar20_compressed_volumes() {
        let data = b"facade rar20 split phrase alpha beta gamma\n".repeat(32);
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-rar20.txt",
                data: &data,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_options(ArchiveVersion::Rar20),
            8,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let first_file = archives[0].files().next().unwrap();
        assert_eq!(first_file.unp_ver, 20);
        assert!(first_file.is_split_after());

        let extracted = collect_rar15_40_volumes(&archives, None).unwrap();
        assert_eq!(extracted[0].name, b"split-rar20.txt");
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn direct_writer_creates_rar29_compressed_volumes() {
        let data = b"facade rar29 split phrase alpha beta gamma\n".repeat(32);
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-rar29.txt",
                data: &data,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_options(ArchiveVersion::Rar29),
            8,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let first_file = archives[0].files().next().unwrap();
        assert_eq!(first_file.unp_ver, 29);
        assert!(first_file.is_split_after());

        let extracted = collect_rar15_40_volumes(&archives, None).unwrap();
        assert_eq!(extracted[0].name, b"split-rar29.txt");
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn rar15_40_parse_stream_matches_the_seekable_parse() {
        let mut seed = 0x2545f4914f6cdd1du64;
        let data: Vec<u8> = (0..48_000)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (seed >> 33) as u8
            })
            .collect();
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"stream.bin",
                data: &data,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_options(ArchiveVersion::Rar29),
            16_000,
        )
        .unwrap();
        assert!(parts.len() >= 2, "the set must actually split");
        for part in &parts {
            let seekable = rar15_40::Archive::parse(part).unwrap();
            let buffer = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
            buffer.append(part);
            let streamed = rar15_40::Archive::parse_stream(
                buffer,
                part.len() as u64,
                ArchiveReadOptions::default(),
            )
            .unwrap();
            let seekable_files: Vec<_> = seekable.files().collect();
            let streamed_files: Vec<_> = streamed.files().collect();
            assert_eq!(seekable_files, streamed_files);
        }
    }

    /// The RAR4 twin of `rar50_incremental_parse_converges_on_the_blocking_walk`,
    /// over WinRAR-made volumes, which carry the ENDARC tail the eager
    /// walk waits on: half a volume trickled stops the incremental walk
    /// short, and `enumerate_rest` then ends with the eager walk's blocks.
    #[test]
    fn rar15_40_incremental_parse_converges_on_the_blocking_walk() {
        let names = [
            "rar300/compressed_multivol_prng_rar300.rar",
            "rar300/compressed_multivol_prng_rar300.r00",
            "rar300/multivol_newnaming_rar300.part01.rar",
        ];
        for name in names {
            let part = std::fs::read(rar15_40_fixture(name)).unwrap();
            assert_eq!(part[part.len() - 5], 0x7b, "{name}: no ENDARC tail");
            let full = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
            full.append(&part);
            let blocking = rar15_40::Archive::parse_stream(
                std::sync::Arc::clone(&full) as _,
                part.len() as u64,
                ArchiveReadOptions::default(),
            )
            .unwrap();
            let complete = rar15_40::Archive::parse_stream_incremental(
                full,
                part.len() as u64,
                ArchiveReadOptions::default(),
            )
            .unwrap();
            assert!(!complete.is_partially_enumerated(), "{name}");
            assert_eq!(complete.blocks, blocking.blocks, "{name}");

            let trickle = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
            let head = part.len() / 2;
            trickle.append(&part[..head]);
            let mut partial = rar15_40::Archive::parse_stream_incremental(
                std::sync::Arc::clone(&trickle) as _,
                part.len() as u64,
                ArchiveReadOptions::default(),
            )
            .unwrap();
            assert!(
                partial.is_partially_enumerated(),
                "{name}: the walk ran past the frontier into the tail"
            );
            trickle.append(&part[head..]);
            partial.enumerate_rest(None).unwrap();
            assert!(!partial.is_partially_enumerated(), "{name}");
            assert_eq!(partial.blocks, blocking.blocks, "{name}");
            assert_eq!(partial.main, blocking.main, "{name}");
        }
    }

    #[test]
    fn rar15_40_volume_sequence_extracts_a_streamed_compressed_set() {
        // Splits force the sequence driver through the cross-volume split
        // machinery; the feeder thread trickles bytes so the parse and the
        // member reads genuinely BLOCK at the arrival frontier.
        let mut seed = 0x9e3779b97f4a7c15u64;
        let data: Vec<u8> = (0..96_000)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (seed >> 33) as u8
            })
            .collect();
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"seq.bin",
                data: &data,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_options(ArchiveVersion::Rar29),
            24_000,
        )
        .unwrap();
        assert!(parts.len() >= 3, "the set must split across volumes");

        let reference_archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let reference = collect_rar15_40_volumes(&reference_archives, None).unwrap();
        assert_eq!(reference.len(), 1);
        assert_eq!(reference[0].data, data);

        let entries = RefCell::new(Vec::new());
        let parts_ref = &parts;
        let mut feeders: Vec<std::thread::JoinHandle<()>> = Vec::new();
        rar15_40::extract_volume_sequence_to(
            |index| {
                if index >= parts_ref.len() {
                    return Ok(None);
                }
                let part = parts_ref[index].clone();
                let buffer = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
                let feed = std::sync::Arc::clone(&buffer);
                feeders.push(std::thread::spawn(move || {
                    for chunk in part.chunks(97) {
                        feed.append(chunk);
                        std::thread::yield_now();
                    }
                }));
                Ok(Some(rar15_40::Archive::parse_stream(
                    buffer,
                    parts_ref[index].len() as u64,
                    ArchiveReadOptions::default(),
                )?))
            },
            read_options(None),
            |meta| {
                let data = Rc::new(RefCell::new(Vec::new()));
                entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
                Ok(Box::new(CollectWriter { data }))
            },
        )
        .unwrap();
        for feeder in feeders {
            feeder.join().unwrap();
        }

        let streamed = entries.into_inner();
        assert_eq!(streamed.len(), reference.len());
        assert_eq!(streamed[0].0.name, reference[0].name);
        assert_eq!(*streamed[0].1.borrow(), reference[0].data);
    }

    /// [`rar50_sequence_collect`] for the RAR 1.5-4.x twin.
    fn rar15_40_sequence_collect(
        parts: &[Vec<u8>],
        password: Option<&[u8]>,
    ) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, Vec<(usize, u64)>)> {
        let entries = RefCell::new(Vec::new());
        let reports = std::sync::Mutex::new(Vec::new());
        let mut feeders: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let parts_ref = parts;
        let result = rar15_40::extract_volume_sequence_to_with_progress(
            |index| {
                if index >= parts_ref.len() {
                    return Ok(None);
                }
                let part = parts_ref[index].clone();
                let buffer = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
                let feed = std::sync::Arc::clone(&buffer);
                feeders.push(std::thread::spawn(move || {
                    for chunk in part.chunks(97) {
                        feed.append(chunk);
                        std::thread::yield_now();
                    }
                }));
                rar15_40::Archive::parse_stream(
                    buffer,
                    parts_ref[index].len() as u64,
                    ArchiveReadOptions::with_optional_password(password),
                )
                .map(Some)
            },
            read_options(password),
            |meta| {
                let data = Rc::new(RefCell::new(Vec::new()));
                entries
                    .borrow_mut()
                    .push((meta.name.clone(), Rc::clone(&data)));
                Ok(Box::new(CollectWriter { data }))
            },
            |index, offset| reports.lock().unwrap().push((index, offset)),
        );
        for feeder in feeders {
            feeder.join().unwrap();
        }
        result?;
        Ok((
            entries
                .into_inner()
                .into_iter()
                .map(|(name, data)| (name, data.borrow().clone()))
                .collect(),
            reports.into_inner().unwrap(),
        ))
    }

    /// The RAR4 twin of
    /// [`rar50_volume_sequence_incremental_split_matches_the_whole_set_walk`]
    /// over the WinRAR 3.00 fixtures - compressed, encrypted and stored
    /// split sets, both volume naming schemes.
    #[test]
    fn rar15_40_volume_sequence_incremental_split_matches_the_whole_set_walk() {
        let shapes: [(&[&str], Option<&[u8]>); 4] = [
            (
                &[
                    "rar300/compressed_multivol_prng_rar300.rar",
                    "rar300/compressed_multivol_prng_rar300.r00",
                    "rar300/compressed_multivol_prng_rar300.r01",
                    "rar300/compressed_multivol_prng_rar300.r02",
                    "rar300/compressed_multivol_prng_rar300.r03",
                ],
                None,
            ),
            (
                &[
                    "rar300/multivol_newnaming_rar300.part01.rar",
                    "rar300/multivol_newnaming_rar300.part02.rar",
                ],
                None,
            ),
            (
                &[
                    "rar300/multivol_oldnaming_rar300.rar",
                    "rar300/multivol_oldnaming_rar300.r00",
                ],
                None,
            ),
            (
                &[
                    "rar300/stored_multivol_rar300.rar",
                    "rar300/stored_multivol_rar300.r00",
                    "rar300/stored_multivol_rar300.r01",
                    "rar300/stored_multivol_rar300.r02",
                ],
                None,
            ),
        ];
        for (names, password) in shapes {
            let parts: Vec<Vec<u8>> = names
                .iter()
                .map(|name| std::fs::read(rar15_40_fixture(name)).unwrap())
                .collect();
            let archives: Vec<_> = parts
                .iter()
                .map(|part| rar15_40::Archive::parse(part).unwrap())
                .collect();
            let reference = collect_rar15_40_volumes(&archives, password).unwrap();
            let (streamed, reports) = rar15_40_sequence_collect(&parts, password).unwrap();

            assert_eq!(streamed.len(), reference.len(), "{names:?}");
            for (got, want) in streamed.iter().zip(&reference) {
                assert_eq!(got.0, want.name, "{names:?}");
                assert_eq!(got.1, want.data, "{names:?}");
            }
            assert_eq!(
                watermarks_of(&reports, parts.len()),
                vec![u64::MAX; parts.len()],
                "{names:?}: {reports:?}"
            );
        }
    }

    /// Rewrites a volume's split fragment header so its packed-data CRC
    /// field lies, restamping the header CRC so the volume still parses -
    /// the shape of one damaged volume in an otherwise sound set. The
    /// packed bytes themselves stay intact, so nothing but the
    /// per-fragment check can notice.
    fn corrupt_rar15_40_fragment_crc(volume: &mut [u8]) {
        let (offset, head_size) = {
            let archive = rar15_40::Archive::parse(volume).unwrap();
            let file = archive
                .files()
                .next()
                .expect("the volume carries the split fragment");
            assert!(file.is_split_before() && file.is_split_after(), "middle fragment");
            (file.block.offset, file.block.head_size as usize)
        };
        // file_crc sits at +16..+20 of the file block (after head_crc,
        // type, flags, head_size, pack_size, unp_size, host_os).
        for byte in &mut volume[offset + 16..offset + 20] {
            *byte ^= 0x5a;
        }
        let head_crc = (crc32::crc32(&volume[offset + 2..offset + head_size]) & 0xffff) as u16;
        volume[offset..offset + 2].copy_from_slice(&head_crc.to_le_bytes());
    }

    /// unrar parity: a damaged middle volume fails the set at THAT
    /// fragment, naming it, instead of decoding the whole member and
    /// failing on the final unpacked CRC. Exercised on the whole-set walk
    /// for both the compressed and the stored split shape.
    #[test]
    fn rar15_40_whole_set_walk_fails_a_damaged_middle_fragment_naming_its_volume() {
        let shapes: [&[&str]; 2] = [
            &[
                "rar300/compressed_multivol_prng_rar300.rar",
                "rar300/compressed_multivol_prng_rar300.r00",
                "rar300/compressed_multivol_prng_rar300.r01",
                "rar300/compressed_multivol_prng_rar300.r02",
                "rar300/compressed_multivol_prng_rar300.r03",
            ],
            &[
                "rar300/stored_multivol_rar300.rar",
                "rar300/stored_multivol_rar300.r00",
                "rar300/stored_multivol_rar300.r01",
                "rar300/stored_multivol_rar300.r02",
            ],
        ];
        for names in shapes {
            let mut parts: Vec<Vec<u8>> = names
                .iter()
                .map(|name| std::fs::read(rar15_40_fixture(name)).unwrap())
                .collect();
            corrupt_rar15_40_fragment_crc(&mut parts[2]);
            let archives: Vec<_> = parts
                .iter()
                .map(|part| rar15_40::Archive::parse(part).unwrap())
                .collect();

            let error = collect_rar15_40_volumes(&archives, None).unwrap_err();
            assert!(
                matches!(error, Error::SplitFragmentCrc32Mismatch { volume: 2, .. }),
                "{names:?}: {error:?}"
            );
        }
    }

    /// [`rar15_40_whole_set_walk_fails_a_damaged_middle_fragment_naming_its_volume`]
    /// for the volume sequence walk: the compressed shape takes the
    /// incremental chase, the stored shape takes the Finish-fragment
    /// reassembly, and both must land the same volume-naming error.
    #[test]
    fn rar15_40_volume_sequence_fails_a_damaged_middle_fragment_naming_its_volume() {
        let shapes: [&[&str]; 2] = [
            &[
                "rar300/compressed_multivol_prng_rar300.rar",
                "rar300/compressed_multivol_prng_rar300.r00",
                "rar300/compressed_multivol_prng_rar300.r01",
                "rar300/compressed_multivol_prng_rar300.r02",
                "rar300/compressed_multivol_prng_rar300.r03",
            ],
            &[
                "rar300/stored_multivol_rar300.rar",
                "rar300/stored_multivol_rar300.r00",
                "rar300/stored_multivol_rar300.r01",
                "rar300/stored_multivol_rar300.r02",
            ],
        ];
        for names in shapes {
            let mut parts: Vec<Vec<u8>> = names
                .iter()
                .map(|name| std::fs::read(rar15_40_fixture(name)).unwrap())
                .collect();
            corrupt_rar15_40_fragment_crc(&mut parts[2]);

            let error = rar15_40_sequence_collect(&parts, None).unwrap_err();
            assert!(
                matches!(error, Error::SplitFragmentCrc32Mismatch { volume: 2, .. }),
                "{names:?}: {error:?}"
            );
        }
    }

    /// The RAR4 twin of the two structural pins: the split sink opens at
    /// the START fragment, and the chain publishes mid-volume progress
    /// while it is still reading.
    #[test]
    fn rar15_40_volume_sequence_decodes_a_split_member_incrementally() {
        let names = [
            "rar300/compressed_multivol_prng_rar300.rar",
            "rar300/compressed_multivol_prng_rar300.r00",
            "rar300/compressed_multivol_prng_rar300.r01",
            "rar300/compressed_multivol_prng_rar300.r02",
            "rar300/compressed_multivol_prng_rar300.r03",
        ];
        let parts: Vec<Vec<u8>> = names
            .iter()
            .map(|name| std::fs::read(rar15_40_fixture(name)).unwrap())
            .collect();

        let (_, reports) = rar15_40_sequence_collect(&parts, None).unwrap();
        assert!(
            reports
                .iter()
                .any(|&(_, offset)| offset > 0 && offset != u64::MAX),
            "no partial watermark anywhere: {reports:?}"
        );
        let mut seen: std::collections::BTreeMap<usize, u64> = std::collections::BTreeMap::new();
        for &(index, offset) in &reports {
            let previous = seen.entry(index).or_insert(0);
            assert!(
                offset >= *previous,
                "volume {index} watermark went backwards ({previous} -> {offset}): {reports:?}"
            );
            *previous = offset;
        }

        #[derive(Debug, PartialEq, Eq)]
        enum Event {
            Volume(usize),
            Open,
        }
        let log = std::sync::Mutex::new(Vec::new());
        let parts_ref = &parts;
        rar15_40::extract_volume_sequence_to(
            |index| {
                log.lock().unwrap().push(Event::Volume(index));
                if index >= parts_ref.len() {
                    return Ok(None);
                }
                rar15_40::Archive::parse(&parts_ref[index]).map(Some)
            },
            read_options(None),
            |_| {
                log.lock().unwrap().push(Event::Open);
                Ok(Box::new(std::io::sink()) as Box<dyn std::io::Write>)
            },
        )
        .unwrap();
        let log = log.into_inner().unwrap();
        let opened = log.iter().position(|e| *e == Event::Open).expect("opened");
        let second = log
            .iter()
            .position(|e| *e == Event::Volume(1))
            .expect("pulled volume 1");
        assert!(
            opened < second,
            "the split sink opened only after the set was pulled: {log:?}"
        );
    }

    /// The RAR4 twin of the broken-chain pin.
    #[test]
    fn rar15_40_volume_sequence_incremental_split_rejects_a_broken_chain() {
        let read = |name: &str| std::fs::read(rar15_40_fixture(name)).unwrap();

        let renamed = vec![
            read("rar300/compressed_multivol_prng_rar300.rar"),
            read("rar300/multivol_oldnaming_rar300.r00"),
        ];
        let error = rar15_40_sequence_collect(&renamed, None).unwrap_err();
        assert!(
            matches!(
                error,
                Error::InvalidHeader("RAR 1.5 split entry name changed")
            ),
            "{error:?}"
        );

        let truncated = vec![
            read("rar300/compressed_multivol_prng_rar300.rar"),
            read("rar300/compressed_multivol_prng_rar300.r00"),
        ];
        let error = rar15_40_sequence_collect(&truncated, None).unwrap_err();
        assert!(
            matches!(
                error,
                Error::InvalidHeader("RAR 1.5 split entry is incomplete")
            ),
            "{error:?}"
        );
    }

    /// Drive a RAR 5 volume set through the sequence extractor, trickling
    /// every volume's bytes through a `GrowableBuffer` so the header parse
    /// AND every payload read genuinely block at the arrival frontier -
    /// which is what makes the incremental split path do its real job.
    /// Returns the entries in open() order plus every consumption report
    /// the engine published, in order.
    fn rar50_sequence_collect(
        parts: &[Vec<u8>],
        password: Option<&[u8]>,
    ) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, Vec<(usize, u64)>)> {
        let entries = RefCell::new(Vec::new());
        let reports = std::sync::Mutex::new(Vec::new());
        let mut feeders: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let parts_ref = parts;
        let result = rar50::extract_volume_sequence_to_with_progress(
            |index| {
                if index >= parts_ref.len() {
                    return Ok(None);
                }
                let part = parts_ref[index].clone();
                let buffer = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
                let feed = std::sync::Arc::clone(&buffer);
                feeders.push(std::thread::spawn(move || {
                    for chunk in part.chunks(97) {
                        feed.append(chunk);
                        std::thread::yield_now();
                    }
                }));
                rar50::Archive::parse_stream(
                    buffer,
                    parts_ref[index].len() as u64,
                    ArchiveReadOptions::with_optional_password(password),
                )
                .map(Some)
            },
            read_options(password),
            |meta| {
                let data = Rc::new(RefCell::new(Vec::new()));
                entries
                    .borrow_mut()
                    .push((meta.name.clone(), Rc::clone(&data)));
                Ok(Box::new(CollectWriter { data }))
            },
            |index, offset| reports.lock().unwrap().push((index, offset)),
        );
        for feeder in feeders {
            feeder.join().unwrap();
        }
        result?;
        Ok((
            entries
                .into_inner()
                .into_iter()
                .map(|(name, data)| (name, data.borrow().clone()))
                .collect(),
            reports.into_inner().unwrap(),
        ))
    }

    /// Compressible-but-not-trivial bytes. Straight LCG noise is
    /// incompressible, and the volume writer STORES a member it cannot
    /// shrink - which would quietly take these tests off the compressed
    /// split path they exist to cover.
    fn deterministic_squashable(len: usize) -> Vec<u8> {
        deterministic_noise(len)
            .into_iter()
            .enumerate()
            .map(|(index, byte)| if index % 3 == 0 { byte } else { 0 })
            .collect()
    }

    /// Highest offset reported for each volume of a `parts.len()` set.
    fn watermarks_of(reports: &[(usize, u64)], volumes: usize) -> Vec<u64> {
        let mut marks = vec![0u64; volumes];
        for &(index, offset) in reports {
            if let Some(mark) = marks.get_mut(index) {
                *mark = (*mark).max(offset);
            }
        }
        marks
    }

    /// The incremental split decode has to land the same bytes as the
    /// whole-set walk on every shape a chased set can carry - and the
    /// WinRAR-made fixtures are the oracle for all four.
    ///
    /// Under `cfg(test)` the buffered decode limit is 1 KB, so every one
    /// of these compressed members takes the incremental path.
    #[test]
    fn rar50_volume_sequence_incremental_split_matches_the_whole_set_walk() {
        let shapes: [(&[&str], Option<&[u8]>); 5] = [
            (
                &["multivol.part1.rar", "multivol.part2.rar", "multivol.part3.rar"],
                None,
            ),
            (
                // rar 7.23 with the default CRC32 records - the only set
                // whose fragments carry data_crc32 instead of BLAKE2sp.
                &[
                    "crc32_multivol.part01.rar",
                    "crc32_multivol.part02.rar",
                    "crc32_multivol.part03.rar",
                    "crc32_multivol.part04.rar",
                    "crc32_multivol.part05.rar",
                ],
                None,
            ),
            (
                &[
                    "solid_multivol.part01.rar",
                    "solid_multivol.part02.rar",
                    "solid_multivol.part03.rar",
                    "solid_multivol.part04.rar",
                    "solid_multivol.part05.rar",
                    "solid_multivol.part06.rar",
                ],
                None,
            ),
            (
                &[
                    "encrypted_multivol.part1.rar",
                    "encrypted_multivol.part2.rar",
                    "encrypted_multivol.part3.rar",
                ],
                Some(b"password"),
            ),
            (
                &[
                    "stored_multivol.part1.rar",
                    "stored_multivol.part2.rar",
                    "stored_multivol.part3.rar",
                ],
                None,
            ),
        ];
        for (names, password) in shapes {
            let parts: Vec<Vec<u8>> = names
                .iter()
                .map(|name| std::fs::read(rar50_fixture(name)).unwrap())
                .collect();
            let archives: Vec<_> = parts
                .iter()
                .map(|part| rar50::Archive::parse_with_password(part, password).unwrap())
                .collect();
            let reference = collect_rar50_volumes(&archives, password).unwrap();
            let (streamed, _) = rar50_sequence_collect(&parts, password).unwrap();

            assert_eq!(streamed.len(), reference.len(), "{names:?}");
            for (got, want) in streamed.iter().zip(&reference) {
                assert_eq!(got.0, want.name, "{names:?}");
                assert_eq!(got.1, want.data, "{names:?}");
            }
        }
    }

    /// The incremental header walk ends where the blocking one does: fed
    /// to completion, `parse_stream_incremental` + `enumerate_rest` holds
    /// the same blocks as `parse_stream`, on every multivolume shape
    /// above, encrypted and stored included - and a walk over a source
    /// that is already complete is whole from the first call.
    #[test]
    fn rar50_incremental_parse_converges_on_the_blocking_walk() {
        let names = [
            "multivol.part1.rar",
            "multivol.part2.rar",
            "multivol.part3.rar",
            "solid_multivol.part01.rar",
            "encrypted_multivol.part1.rar",
            "stored_multivol.part1.rar",
        ];
        for name in names {
            let part = std::fs::read(rar50_fixture(name)).unwrap();
            let password: Option<&[u8]> =
                name.starts_with("encrypted").then_some(b"password".as_slice());
            let full = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
            full.append(&part);
            let blocking = rar50::Archive::parse_stream(
                std::sync::Arc::clone(&full) as _,
                part.len() as u64,
                ArchiveReadOptions::with_optional_password(password),
            )
            .unwrap();
            let complete = rar50::Archive::parse_stream_incremental(
                full,
                part.len() as u64,
                ArchiveReadOptions::with_optional_password(password),
            )
            .unwrap();
            assert!(
                !complete.is_partially_enumerated(),
                "{name}: a complete source walks whole in one call"
            );
            assert_eq!(complete.blocks, blocking.blocks, "{name}");

            // Trickled: the first call stops at the frontier, and the
            // rest is walked once it has landed. Half the volume, so
            // the headers at the front are in and the END record at
            // the tail is not.
            let trickle = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
            let head = part.len() / 2;
            trickle.append(&part[..head]);
            let mut partial = rar50::Archive::parse_stream_incremental(
                std::sync::Arc::clone(&trickle) as _,
                part.len() as u64,
                ArchiveReadOptions::with_optional_password(password),
            )
            .unwrap();
            assert!(
                partial.is_partially_enumerated(),
                "{name}: the walk ran past the frontier into the tail"
            );
            trickle.append(&part[head..]);
            partial.enumerate_rest(password).unwrap();
            assert!(!partial.is_partially_enumerated(), "{name}");
            assert_eq!(partial.blocks, blocking.blocks, "{name}");
            assert_eq!(partial.main, blocking.main, "{name}");
        }
    }

    /// A [`BlockingRangeSource`] that has RELEASED everything below
    /// `base`, the way nzbkit's chase frontier drops the bytes behind
    /// the engine's watermark: a read there is an error, not a wait.
    #[derive(Debug)]
    struct TrimmedSource {
        inner: std::sync::Arc<GrowableBuffer>,
        base: std::sync::atomic::AtomicU64,
    }

    impl BlockingRangeSource for TrimmedSource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let base = self.base.load(std::sync::atomic::Ordering::Relaxed);
            if offset < base {
                return Err(std::io::Error::other(format!(
                    "read {offset} behind the trim point {base}"
                )));
            }
            self.inner.read_at(offset, buf)
        }
        fn known_len(&self) -> u64 {
            self.inner.known_len()
        }
        fn total_len(&self) -> Option<u64> {
            self.inner.total_len()
        }
    }

    /// nzbkit TODO 220 / 250: finishing a stopped walk must not read
    /// BEHIND where it stopped. The caller the incremental parse exists
    /// for releases every byte under the engine's watermark before it
    /// asks for the rest of the volume, so `enumerate_rest` starting
    /// over from the signature met a refused read at offset 8 on every
    /// leg of the set it was built for (2.002x -> 3.001x, 23 Aug 2026).
    /// Half of each volume arrives, the walk stops, the source then
    /// refuses everything below that frontier - the stop offset is the
    /// last enumerated block's data end, which is at or past it - and
    /// the resumed walk must still converge on the blocking walk's
    /// blocks. A header-encrypted archive is in the list because the
    /// HEAD_CRYPT block that carries the header keys' salt sits at
    /// offset 8, behind the trim: the resume has to have kept the keys.
    #[test]
    fn rar50_enumerate_rest_reads_nothing_behind_the_stop() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let payload: Vec<u8> = (0..6000u32).map(|i| (i * 7919 % 251) as u8).collect();
        let header_encrypted = rar50::Rar50Writer::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
            name: b"secret.bin",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        }])
        .finish()
        .unwrap();
        let fixtures: Vec<(&str, Vec<u8>, Option<&[u8]>)> = vec![
            ("multivol.part1.rar", std::fs::read(rar50_fixture("multivol.part1.rar")).unwrap(), None),
            ("multivol.part2.rar", std::fs::read(rar50_fixture("multivol.part2.rar")).unwrap(), None),
            ("multivol.part3.rar", std::fs::read(rar50_fixture("multivol.part3.rar")).unwrap(), None),
            (
                "solid_multivol.part01.rar",
                std::fs::read(rar50_fixture("solid_multivol.part01.rar")).unwrap(),
                None,
            ),
            (
                "encrypted_multivol.part1.rar",
                std::fs::read(rar50_fixture("encrypted_multivol.part1.rar")).unwrap(),
                Some(b"password"),
            ),
            (
                "stored_multivol.part1.rar",
                std::fs::read(rar50_fixture("stored_multivol.part1.rar")).unwrap(),
                None,
            ),
            ("header_encrypted (writer)", header_encrypted, Some(b"password")),
        ];
        for (name, part, password) in fixtures {
            let full = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
            full.append(&part);
            let blocking = rar50::Archive::parse_stream(
                full as _,
                part.len() as u64,
                ArchiveReadOptions::with_optional_password(password),
            )
            .unwrap();

            let inner = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
            let head = part.len() / 2;
            inner.append(&part[..head]);
            let trimmed = std::sync::Arc::new(TrimmedSource {
                inner: std::sync::Arc::clone(&inner),
                base: std::sync::atomic::AtomicU64::new(0),
            });
            let mut partial = rar50::Archive::parse_stream_incremental(
                std::sync::Arc::clone(&trimmed) as _,
                part.len() as u64,
                ArchiveReadOptions::with_optional_password(password),
            )
            .unwrap();
            assert!(
                partial.is_partially_enumerated(),
                "{name}: the walk ran past the frontier into the tail"
            );
            // The rest lands, and everything the walk has already been
            // over is released underneath it.
            inner.append(&part[head..]);
            trimmed
                .base
                .store(head as u64, std::sync::atomic::Ordering::Relaxed);
            partial
                .enumerate_rest(password)
                .unwrap_or_else(|e| panic!("{name}: the resumed walk read behind the stop: {e}"));
            assert!(!partial.is_partially_enumerated(), "{name}");
            assert_eq!(partial.blocks, blocking.blocks, "{name}");
            assert_eq!(partial.main, blocking.main, "{name}");
        }
    }

    /// nzbkit TODO 220: a caller holding volumes under a retention cap
    /// needs the engine to START a volume before the volume's tail has
    /// arrived, or a volume larger than the cap can never be released.
    /// The feeder withholds volume 0's second half until the engine has
    /// published a watermark for it. The blocking `parse_stream` waits
    /// for the end header at the tail and can never get there (checked:
    /// swapping it in fails this test at the 30 s bound), so the wait is
    /// bounded and aborts the source - a regression fails here instead
    /// of hanging.
    #[test]
    fn rar50_incremental_parse_reports_a_volume_before_its_tail_arrives() {
        let names = ["multivol.part1.rar", "multivol.part2.rar", "multivol.part3.rar"];
        let parts: Vec<Vec<u8>> = names
            .iter()
            .map(|name| std::fs::read(rar50_fixture(name)).unwrap())
            .collect();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, None).unwrap())
            .collect();
        let reference = collect_rar50_volumes(&archives, None).unwrap();

        let reports = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(usize, u64)>::new()));
        let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let entries = RefCell::new(Vec::new());
        let mut feeders: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let parts_ref = &parts;
        let result = rar50::extract_volume_sequence_to_with_progress(
            |index| {
                if index >= parts_ref.len() {
                    return Ok(None);
                }
                let part = parts_ref[index].clone();
                let buffer = std::sync::Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
                let feed = std::sync::Arc::clone(&buffer);
                let reports = std::sync::Arc::clone(&reports);
                let timed_out = std::sync::Arc::clone(&timed_out);
                feeders.push(std::thread::spawn(move || {
                    let half = part.len() / 2;
                    feed.append(&part[..half]);
                    if index == 0 {
                        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                        while !reports.lock().unwrap().iter().any(|&(volume, _)| volume == 0) {
                            if std::time::Instant::now() >= deadline {
                                timed_out.store(true, std::sync::atomic::Ordering::SeqCst);
                                feed.abort("no watermark before the tail");
                                return;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                    }
                    feed.append(&part[half..]);
                }));
                rar50::Archive::parse_stream_incremental(
                    buffer,
                    parts_ref[index].len() as u64,
                    ArchiveReadOptions::with_optional_password(None),
                )
                .map(Some)
            },
            read_options(None),
            |meta| {
                let data = Rc::new(RefCell::new(Vec::new()));
                entries
                    .borrow_mut()
                    .push((meta.name.clone(), Rc::clone(&data)));
                Ok(Box::new(CollectWriter { data }))
            },
            |index, offset| reports.lock().unwrap().push((index, offset)),
        );
        for feeder in feeders {
            feeder.join().unwrap();
        }
        assert!(
            !timed_out.load(std::sync::atomic::Ordering::SeqCst),
            "the engine published nothing for volume 0 before its tail arrived"
        );
        result.unwrap();
        let streamed: Vec<_> = entries
            .into_inner()
            .into_iter()
            .map(|(name, data)| (name, data.borrow().clone()))
            .collect();
        assert_eq!(streamed.len(), reference.len());
        for (got, want) in streamed.iter().zip(&reference) {
            assert_eq!(got.0, want.name);
            assert_eq!(got.1, want.data);
        }
        // The mark that let the tail through was a PARTIAL one: the
        // whole-volume report can only follow the tail.
        let first_for_zero = reports
            .lock()
            .unwrap()
            .iter()
            .find(|&&(volume, _)| volume == 0)
            .map(|&(_, offset)| offset)
            .unwrap();
        assert!(
            first_for_zero < parts[0].len() as u64,
            "first report for volume 0 was {first_for_zero}, not a partial offset"
        );
    }

    /// Rewrites a middle volume's split fragment header so its packed-data
    /// digest record lies, restamping the block header CRC so the volume
    /// still parses - the shape of one damaged volume in an otherwise
    /// sound set. The packed bytes themselves stay intact, so nothing but
    /// the per-fragment check can notice.
    fn corrupt_rar50_fragment_digest(volume: &mut [u8]) {
        let (header_start, header_end, record) = {
            let archive = rar50::Archive::parse(volume).unwrap();
            let file = archive
                .files()
                .next()
                .expect("the volume carries the split fragment");
            assert!(file.is_split_before() && file.is_split_after(), "middle fragment");
            let record = match &file.hash {
                Some(hash) => hash.data.clone(),
                None => file
                    .data_crc32
                    .expect("fragment carries a digest record")
                    .to_le_bytes()
                    .to_vec(),
            };
            // The block header spans its leading CRC32 through the last
            // extra-area byte; the payload starts right after it.
            (file.block.offset, file.block.data_range.start, record)
        };
        let position = volume[header_start + 4..header_end]
            .windows(record.len())
            .position(|window| window == record)
            .expect("digest record bytes are in the header");
        volume[header_start + 4 + position] ^= 0x5a;
        let header_crc = crc32::crc32(&volume[header_start + 4..header_end]);
        volume[header_start..header_start + 4].copy_from_slice(&header_crc.to_le_bytes());
    }

    /// The three RAR 5 split shapes with per-fragment packed digests:
    /// compressed and stored BLAKE2sp (WinRAR 7.21 fixtures), and
    /// compressed CRC32 (rar 7.23). `true` marks the CRC32 flavor.
    fn rar50_split_digest_shapes() -> [(&'static [&'static str], bool); 3] {
        [
            (
                &["multivol.part1.rar", "multivol.part2.rar", "multivol.part3.rar"],
                false,
            ),
            (
                &[
                    "stored_multivol.part1.rar",
                    "stored_multivol.part2.rar",
                    "stored_multivol.part3.rar",
                ],
                false,
            ),
            (
                &[
                    "crc32_multivol.part01.rar",
                    "crc32_multivol.part02.rar",
                    "crc32_multivol.part03.rar",
                    "crc32_multivol.part04.rar",
                    "crc32_multivol.part05.rar",
                ],
                true,
            ),
        ]
    }

    /// unrar parity (UIERROR_CHECKSUMPACKED): a damaged middle volume
    /// fails the RAR 5 set at THAT fragment, naming it, instead of
    /// decoding the whole member and failing on the final unpacked
    /// digest. Exercised on the whole-set walk for both digest flavors
    /// and both the compressed and the stored split shape.
    #[test]
    fn rar50_whole_set_walk_fails_a_damaged_middle_fragment_naming_its_volume() {
        for (names, crc32_flavor) in rar50_split_digest_shapes() {
            let mut parts: Vec<Vec<u8>> = names
                .iter()
                .map(|name| std::fs::read(rar50_fixture(name)).unwrap())
                .collect();
            corrupt_rar50_fragment_digest(&mut parts[1]);
            let archives: Vec<_> = parts
                .iter()
                .map(|part| rar50::Archive::parse(part).unwrap())
                .collect();

            let error = collect_rar50_volumes(&archives, None).unwrap_err();
            if crc32_flavor {
                assert!(
                    matches!(error, Error::SplitFragmentCrc32Mismatch { volume: 1, .. }),
                    "{names:?}: {error:?}"
                );
            } else {
                assert!(
                    matches!(error, Error::SplitFragmentHashMismatch { volume: 1 }),
                    "{names:?}: {error:?}"
                );
            }
        }
    }

    /// [`rar50_whole_set_walk_fails_a_damaged_middle_fragment_naming_its_volume`]
    /// for the volume sequence walk: the compressed shapes take the
    /// incremental chase, the stored shape takes the Finish-fragment
    /// reassembly, and all must land the same volume-naming error.
    #[test]
    fn rar50_volume_sequence_fails_a_damaged_middle_fragment_naming_its_volume() {
        for (names, crc32_flavor) in rar50_split_digest_shapes() {
            let mut parts: Vec<Vec<u8>> = names
                .iter()
                .map(|name| std::fs::read(rar50_fixture(name)).unwrap())
                .collect();
            corrupt_rar50_fragment_digest(&mut parts[1]);

            let error = rar50_sequence_collect(&parts, None).unwrap_err();
            if crc32_flavor {
                assert!(
                    matches!(error, Error::SplitFragmentCrc32Mismatch { volume: 1, .. }),
                    "{names:?}: {error:?}"
                );
            } else {
                assert!(
                    matches!(error, Error::SplitFragmentHashMismatch { volume: 1 }),
                    "{names:?}: {error:?}"
                );
            }
        }
    }

    /// The drop-behind contract, which is the whole point of the
    /// incremental split: as the chain moves off a volume it says so,
    /// and while it is still reading one it reports a byte offset inside
    /// that volume rather than "all of it". Nothing downstream may
    /// release bytes it has not been told about.
    #[test]
    fn rar50_volume_sequence_reports_volumes_consumed_behind_the_decode() {
        // Six volumes of a WinRAR-made solid set: enough fragments that
        // the decoder is producing output long before the chain reaches
        // the last one, which is when partial watermarks appear.
        let names = [
            "solid_multivol.part01.rar",
            "solid_multivol.part02.rar",
            "solid_multivol.part03.rar",
            "solid_multivol.part04.rar",
            "solid_multivol.part05.rar",
            "solid_multivol.part06.rar",
        ];
        let parts: Vec<Vec<u8>> = names
            .iter()
            .map(|name| std::fs::read(rar50_fixture(name)).unwrap())
            .collect();
        let (_, reports) = rar50_sequence_collect(&parts, None).unwrap();

        // Mid-fragment progress: only the growing chain publishes a
        // watermark that is neither zero nor "the whole volume", so this
        // is what proves the member decoded incrementally rather than at
        // its Finish fragment. (The walk only ever says `u64::MAX`.)
        assert!(
            reports
                .iter()
                .any(|&(_, offset)| offset > 0 && offset != u64::MAX),
            "no partial watermark anywhere: {reports:?}"
        );
        // Per volume the watermark only ever moves forward - a caller
        // acting on it releases bytes, so a report that went backwards
        // would be a promise broken after the fact.
        let mut seen: std::collections::BTreeMap<usize, u64> = std::collections::BTreeMap::new();
        for &(index, offset) in &reports {
            let previous = seen.entry(index).or_insert(0);
            assert!(
                offset >= *previous,
                "volume {index} watermark went backwards ({previous} -> {offset}): {reports:?}"
            );
            *previous = offset;
        }
        // And every volume ends up wholly consumed - the last one once
        // the driver has walked it out, which is why the WALK reports it
        // rather than the chain.
        assert_eq!(
            watermarks_of(&reports, parts.len()),
            vec![u64::MAX; parts.len()],
            "{reports:?}"
        );
    }

    /// The structural claim the whole feature rests on: the sink for a
    /// split member opens at its START fragment, so decoding begins while
    /// the later volumes are still arriving. The old walk opened it at
    /// the FINISH fragment, after every volume had been pulled and
    /// retained.
    #[test]
    fn rar50_volume_sequence_opens_the_split_sink_before_pulling_the_next_volume() {
        let parts: Vec<Vec<u8>> = [
            "multivol.part1.rar",
            "multivol.part2.rar",
            "multivol.part3.rar",
        ]
        .iter()
        .map(|name| std::fs::read(rar50_fixture(name)).unwrap())
        .collect();

        #[derive(Debug, PartialEq, Eq)]
        enum Event {
            Volume(usize),
            Open,
        }
        let log = std::sync::Mutex::new(Vec::new());
        let parts_ref = &parts;
        rar50::extract_volume_sequence_to(
            |index| {
                log.lock().unwrap().push(Event::Volume(index));
                if index >= parts_ref.len() {
                    return Ok(None);
                }
                rar50::Archive::parse(&parts_ref[index]).map(Some)
            },
            read_options(None),
            |_| {
                log.lock().unwrap().push(Event::Open);
                Ok(Box::new(std::io::sink()) as Box<dyn std::io::Write>)
            },
        )
        .unwrap();

        let log = log.into_inner().unwrap();
        let opened = log.iter().position(|e| *e == Event::Open).expect("opened");
        let second = log
            .iter()
            .position(|e| *e == Event::Volume(1))
            .expect("pulled volume 1");
        assert!(
            opened < second,
            "the split sink opened only after the set was pulled: {log:?}"
        );
    }

    /// A member split across a set the chain drives to the very end while
    /// a LATER member sits behind it in the finishing volume: the walk has
    /// to resume inside that volume, not skip to the next one.
    #[test]
    fn rar50_volume_sequence_resumes_the_finishing_volume_after_a_split() {
        let payload = deterministic_squashable(40_000);
        let tail = deterministic_squashable(3_000);
        let entries = [
            rar50::CompressedEntry {
                name: b"split.bin",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
            rar50::CompressedEntry {
                name: b"after.bin",
                data: &tail,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
        ];
        let parts = rar50::Rar50VolumeWriter::new(rar50_options(ArchiveVersion::Rar50))
            .compressed_entries(&entries)
        .max_payload_per_volume(9_000)
        .finish()
        .unwrap();
        assert!(parts.len() >= 3, "the set must split across volumes");

        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        let reference = collect_rar50_volumes(&archives, None).unwrap();
        let (streamed, reports) = rar50_sequence_collect(&parts, None).unwrap();

        assert_eq!(streamed.len(), 2);
        assert_eq!(streamed[0].0, b"split.bin");
        assert_eq!(streamed[0].1, payload);
        assert_eq!(streamed[1].0, b"after.bin");
        assert_eq!(streamed[1].1, tail);
        assert_eq!(streamed.len(), reference.len());
        assert_eq!(
            watermarks_of(&reports, parts.len()),
            vec![u64::MAX; parts.len()]
        );
    }

    /// The whole-set consumption watermark: every volume reported once,
    /// in order, and nothing reported while a SMALL split member is still
    /// pending - a member inside the buffered ceiling keeps its filter
    /// bail retry, whose buffered path reads every fragment back, so a
    /// caller deleting on the watermark would otherwise destroy the
    /// fragments that retry is entitled to. (A member ABOVE the ceiling,
    /// or a stored one, has no retry and releases progressively instead -
    /// see the progressive-release tests beside this one.)
    #[test]
    fn extract_volumes_to_with_progress_reports_each_volume_once_and_never_early() {
        let payload = deterministic_squashable(40_000);
        let tail = deterministic_squashable(3_000);
        let entries = [
            rar50::CompressedEntry {
                name: b"split.bin",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
            rar50::CompressedEntry {
                name: b"after.bin",
                data: &tail,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
        ];
        let parts = rar50::Rar50VolumeWriter::new(rar50_options(ArchiveVersion::Rar50))
            .compressed_entries(&entries)
            .max_payload_per_volume(9_000)
            .finish()
            .unwrap();
        assert!(parts.len() >= 3, "the set must split across volumes");
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();

        // One interleaved log, so "was volume 0 released before the split
        // member was written?" is answerable rather than inferred.
        #[derive(Debug, PartialEq)]
        enum Event {
            Opened(Vec<u8>),
            Consumed(usize),
        }
        let log = std::sync::Mutex::new(Vec::new());
        rar50::extract_volumes_to_with_progress(
            &archives,
            ArchiveReadOptions::new(),
            |meta| {
                log.lock().unwrap().push(Event::Opened(meta.name.clone()));
                Ok(Box::new(std::io::sink()) as Box<dyn Write>)
            },
            |index| log.lock().unwrap().push(Event::Consumed(index)),
        )
        .unwrap();

        let log = log.into_inner().unwrap();
        let consumed: Vec<usize> = log
            .iter()
            .filter_map(|e| match e {
                Event::Consumed(i) => Some(*i),
                _ => None,
            })
            .collect();
        assert_eq!(
            consumed,
            (0..parts.len()).collect::<Vec<_>>(),
            "every volume exactly once, in order"
        );
        let first_consumed = log
            .iter()
            .position(|e| matches!(e, Event::Consumed(_)))
            .unwrap();
        let split_written = log
            .iter()
            .position(|e| e == &Event::Opened(b"split.bin".to_vec()))
            .unwrap();
        assert!(
            split_written < first_consumed,
            "a volume was released while the split member was still pending: {log:?}"
        );
    }

    /// A writer whose budget is the disk-eating guard in miniature: it
    /// starts with `base` bytes of headroom and gains a volume's bytes
    /// only when `credit` releases that volume. A single split member
    /// larger than `base` can therefore only extract if the engine
    /// releases volumes PROGRESSIVELY, while the member is still
    /// writing - which is exactly the H1 shape (one film split across
    /// every volume, extracted into a fraction of its size in free
    /// space).
    struct VolumeBudgetWriter {
        budget: std::sync::Arc<std::sync::atomic::AtomicU64>,
        out: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl Write for VolumeBudgetWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            use std::sync::atomic::Ordering;
            let need = buf.len() as u64;
            if self.budget.load(Ordering::SeqCst) < need {
                return Err(std::io::Error::other(
                    "budget exhausted - the spent volumes were not released progressively",
                ));
            }
            self.budget.fetch_sub(need, Ordering::SeqCst);
            self.out.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs the whole-set watermark walk over `parts` under a volume
    /// budget of `base` bytes, crediting each volume's size as it is
    /// reported consumed. Returns the extracted bytes and the consumed
    /// order.
    fn rar50_extract_under_volume_budget(
        parts: &[Vec<u8>],
        options: ArchiveReadOptions<'_>,
        base: u64,
    ) -> (Vec<u8>, Vec<usize>) {
        use std::sync::atomic::Ordering;
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        let volume_sizes: Vec<u64> = parts.iter().map(|part| part.len() as u64).collect();
        let budget = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(base));
        let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let consumed_order = std::sync::Mutex::new(Vec::new());
        let writer_budget = std::sync::Arc::clone(&budget);
        let writer_out = std::sync::Arc::clone(&out);
        rar50::extract_volumes_to_with_progress(
            &archives,
            options,
            move |_meta| {
                Ok(Box::new(VolumeBudgetWriter {
                    budget: std::sync::Arc::clone(&writer_budget),
                    out: std::sync::Arc::clone(&writer_out),
                }) as Box<dyn Write>)
            },
            |index| {
                consumed_order.lock().unwrap().push(index);
                budget.fetch_add(volume_sizes[index], Ordering::SeqCst);
            },
        )
        .unwrap();
        let out = out.lock().unwrap().clone();
        (out, consumed_order.into_inner().unwrap())
    }

    /// TODO 101's H1 residual, closed: ONE STORED member split across
    /// every volume - the dominant movie shape - extracts under a budget
    /// of roughly two volumes, because each fragment's volume is
    /// released the moment the chain has read it out. Before progressive
    /// release nothing was reported until the whole member had written,
    /// so this budget failed at the third volume.
    #[test]
    fn whole_set_progress_releases_a_stored_split_member_progressively() {
        let payload = deterministic_noise(60_000);
        let entry = rar50::StoredEntry {
            name: b"film.bin",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        };
        let parts = rar50::Rar50VolumeWriter::new(rar50_options(ArchiveVersion::Rar50))
            .stored_entry(entry)
            .max_payload_per_volume(9_000)
            .finish()
            .unwrap();
        assert!(parts.len() >= 4, "the member must span several volumes");

        // Two volumes of headroom, nowhere near the payload.
        let base: u64 = parts.iter().take(2).map(|part| part.len() as u64).sum();
        assert!(base < payload.len() as u64 / 2, "budget must be tight");
        let (out, consumed) =
            rar50_extract_under_volume_budget(&parts, ArchiveReadOptions::new(), base);

        assert_eq!(out, payload, "extracted bytes must survive the budget");
        assert_eq!(
            consumed,
            (0..parts.len()).collect::<Vec<_>>(),
            "every volume exactly once, in order"
        );
    }

    /// The compressed twin: a member ABOVE the buffered-decode ceiling
    /// has no filter-bail retry, so its fragments release progressively
    /// too. The ceiling is forced down so a small test member takes the
    /// no-retry streaming path a film-sized member takes in production.
    #[test]
    fn whole_set_progress_releases_a_compressed_split_member_progressively() {
        let payload = deterministic_squashable(40_000);
        let entries = [rar50::CompressedEntry {
            name: b"film.bin",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let parts = rar50::Rar50VolumeWriter::new(rar50_options(ArchiveVersion::Rar50))
            .compressed_entries(&entries)
            .max_payload_per_volume(9_000)
            .finish()
            .unwrap();
        assert!(parts.len() >= 3, "the member must span several volumes");

        // The decode pipeline may buffer the whole (small) output before
        // the writer sees a byte, so unlike the stored test the budget
        // cannot be a plain two volumes: every early credit can land
        // before the first write. What it must NOT cover is the payload
        // on its own - that is what distinguishes progressive release
        // from the old release-at-finish behavior.
        let early_credit: u64 = parts
            .iter()
            .take(parts.len() - 1)
            .map(|part| part.len() as u64)
            .sum();
        let base = (payload.len() as u64 + 1_024).saturating_sub(early_credit);
        assert!(
            base < payload.len() as u64,
            "budget must not cover the payload up front"
        );
        let options = ArchiveReadOptions::new().with_rar50_buffered_decode_limit(4_096);
        let (out, consumed) = rar50_extract_under_volume_budget(&parts, options, base);

        assert_eq!(out, payload, "extracted bytes must survive the budget");
        assert_eq!(
            consumed,
            (0..parts.len()).collect::<Vec<_>>(),
            "every volume exactly once, in order"
        );
    }

    /// The RAR4 twin over the WinRAR 3.00 stored fixture: volumes free
    /// while the split member is still writing (RAR4 split decodes never
    /// re-read a fragment, so both stored and compressed release
    /// progressively).
    #[test]
    fn rar15_40_whole_set_progress_releases_split_volumes_before_the_member_completes() {
        let names = [
            "rar300/stored_multivol_rar300.rar",
            "rar300/stored_multivol_rar300.r00",
            "rar300/stored_multivol_rar300.r01",
            "rar300/stored_multivol_rar300.r02",
        ];
        let parts: Vec<Vec<u8>> = names
            .iter()
            .map(|name| std::fs::read(rar15_40_fixture(name)).unwrap())
            .collect();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let reference = collect_rar15_40_volumes(&archives, None).unwrap();
        let split_len: u64 = reference.iter().map(|entry| entry.data.len() as u64).sum();

        // Interleaved log: how many payload bytes had been written when
        // each volume was released.
        let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let consumed_at = std::sync::Mutex::new(Vec::new());
        struct CountingSink(std::sync::Arc<std::sync::atomic::AtomicU64>);
        impl Write for CountingSink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .fetch_add(buf.len() as u64, std::sync::atomic::Ordering::SeqCst);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let writer_written = std::sync::Arc::clone(&written);
        rar15_40::extract_volumes_to_with_progress(
            &archives,
            ArchiveReadOptions::new(),
            move |_meta| {
                Ok(Box::new(CountingSink(std::sync::Arc::clone(&writer_written))) as Box<dyn Write>)
            },
            |index| {
                consumed_at
                    .lock()
                    .unwrap()
                    .push((index, written.load(std::sync::atomic::Ordering::SeqCst)));
            },
        )
        .unwrap();

        let consumed_at = consumed_at.into_inner().unwrap();
        assert_eq!(
            consumed_at.iter().map(|&(index, _)| index).collect::<Vec<_>>(),
            (0..parts.len()).collect::<Vec<_>>(),
            "every volume exactly once, in order"
        );
        assert!(
            consumed_at[0].1 < split_len,
            "volume 0 must be released before the split member finishes writing: {consumed_at:?}"
        );
    }

    /// A continuation that disagrees with the Start fragment must abort
    /// the decode with the SAME error the whole-set walk raises, even
    /// though the incremental path has already emitted bytes by then -
    /// and a set that simply ends early must say so, not hang or claim
    /// success.
    #[test]
    fn rar50_volume_sequence_incremental_split_rejects_a_broken_chain() {
        let read = |name: &str| std::fs::read(rar50_fixture(name)).unwrap();

        // A continuation belonging to a DIFFERENT member: every header is
        // well formed and CRC-valid, the chain is not.
        let renamed = vec![
            read("multivol.part1.rar"),
            read("solid_multivol.part02.rar"),
        ];
        let error = rar50_sequence_collect(&renamed, None).unwrap_err();
        assert!(
            matches!(error, Error::InvalidHeader("RAR 5 split entry name changed")),
            "{error:?}"
        );

        // The set ends before the finish fragment - the chase's "bytes
        // never arrived" shape. The whole-set walk answers the same way.
        let truncated = vec![read("multivol.part1.rar"), read("multivol.part2.rar")];
        let error = rar50_sequence_collect(&truncated, None).unwrap_err();
        assert!(
            matches!(
                error,
                Error::InvalidHeader("RAR 5 split entry is incomplete")
            ),
            "{error:?}"
        );
        let archives: Vec<_> = truncated
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        let walk = collect_rar50_volumes(&archives, None).unwrap_err();
        assert!(
            matches!(walk, Error::InvalidHeader("RAR 5 split entry is incomplete")),
            "{walk:?}"
        );
    }

    #[test]
    fn direct_writer_creates_rar29_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-rar29-secret.txt",
                data: b"facade rar29 encrypted split facade rar29 encrypted split\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
            rar15_options_with_features(ArchiveVersion::Rar29, features),
            8,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();

        assert!(matches!(
            collect_rar15_40_volumes(&archives, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_rar15_40_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-rar29-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade rar29 encrypted split facade rar29 encrypted split\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar15_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-secret.txt",
                data: b"facade encrypted split facade encrypted split\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
            rar15_options_with_features(ArchiveVersion::Rar15, features),
            8,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();

        assert!(matches!(
            collect_rar15_40_volumes(&archives, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_rar15_40_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade encrypted split facade encrypted split\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar30_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-rar30-secret.txt",
                data: b"facade rar30 encrypted split facade rar30 encrypted split\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
            rar15_options_with_features(ArchiveVersion::Rar30, features),
            8,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();

        assert!(matches!(
            collect_rar15_40_volumes(&archives, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_rar15_40_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-rar30-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade rar30 encrypted split facade rar30 encrypted split\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar30_header_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-rar30-header-secret.txt",
                data: b"facade rar30 header encrypted split facade rar30 header encrypted split\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
            rar15_options_with_features(ArchiveVersion::Rar30, features),
            8,
        )
        .unwrap();
        assert!(matches!(
            rar15_40::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = collect_rar15_40_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-rar30-header-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade rar30 header encrypted split facade rar30 header encrypted split\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar30_aes_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar30-secret.txt",
                data: b"facade rar30 aes encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar30, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar30 aes encrypted payload\n");
    }

    #[test]
    fn direct_writer_creates_rar29_aes_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar29-secret.txt",
                data: b"facade rar29 aes encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar29, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 29);
        assert!(file.is_encrypted());
        assert!(file.salt.is_some());
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar29 aes encrypted payload\n");
    }

    #[test]
    fn direct_writer_creates_rar20_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar20-secret.txt",
                data: b"facade rar20 encrypted payload payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar20, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 20);
        assert!(file.is_encrypted());
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar20 encrypted payload payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar30_header_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar30-header-secret.txt",
                data: b"facade rar30 header encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar30, features),
        )
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_encrypted_headers());
        assert_eq!(raw.files().next().unwrap().name, b"rar30-header-secret.txt");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar30 header encrypted payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar30_solid_header_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.solid = true;
        let bytes = rar15_40::write_compressed_archive(
            &[
                rar15_40::FileEntry {
                    name: b"solid-header-one.txt",
                    data: b"facade solid header encrypted one one one\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"solid-header-two.txt",
                    data: b"facade solid header encrypted two two two\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                },
            ],
            rar15_options_with_features(ArchiveVersion::Rar30, features),
        )
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade solid header encrypted one one one\n"
        );
        assert_eq!(
            extracted[1].data,
            b"facade solid header encrypted two two two\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_stored_archive() {
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .stored_entries(&[rar50::StoredEntry {
                name: b"rar5-store.txt",
                data: b"facade rar5 stored payload\n",
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar50Plus);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 stored payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_compressed_archive() {
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-compressed.txt",
                data: b"facade rar5 compressed payload\nfacade rar5 compressed payload\n",
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.decoded_compression_info().unwrap().method, 1);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 compressed payload\nfacade rar5 compressed payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let first = b"facade rar50 solid shared phrase alpha beta gamma\n".repeat(16);
        let second = b"facade rar50 solid shared phrase alpha beta gamma\nsecond\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .compressed_entries(&[
                    rar50::CompressedEntry {
                        name: b"rar5-solid-one.txt",
                        data: &first,
                        mtime: Some(0),
                        attributes: 0x20,
                        host_os: 3,
                    },
                    rar50::CompressedEntry {
                        name: b"rar5-solid-two.txt",
                        data: &second,
                        mtime: Some(0),
                        attributes: 0x20,
                        host_os: 3,
                    },
                ])
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(!files[0].decoded_compression_info().unwrap().solid);
        assert!(files[1].decoded_compression_info().unwrap().solid);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn direct_writer_creates_rar50_delta_filtered_compressed_archive() {
        let payload: Vec<u8> = (0..180)
            .map(|index| (index * 11 + index / 5) as u8)
            .collect();
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-delta-filtered.bin",
                data: &payload,
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .filter_policy(rar50::FilterPolicy::Explicit(rar50::FilterKind::Delta {
                channels: 3,
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar5 e8 filter payload".to_vec();
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-e8-filtered.bin",
                data: &payload,
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .filter_policy(rar50::FilterPolicy::Explicit(rar50::FilterKind::E8))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_arm_filtered_compressed_archive() {
        let payload = [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!'];
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-arm-filtered.bin",
                data: &payload,
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .filter_policy(rar50::FilterPolicy::Explicit(rar50::FilterKind::Arm))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_auto_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar5 auto filter payload\n".repeat(16);
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-auto-filtered.bin",
                data: &payload,
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .filter_policy(rar50::FilterPolicy::AutoSize)
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_stored_archive_with_comment_service() {
        let mut features = FeatureSet::store_only();
        features.archive_comment = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .stored_entries(&[rar50::StoredEntry {
                    name: b"rar5-commented.txt",
                    data: b"facade rar5 comment payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                }])
                .archive_comment(Some(b"facade rar5 comment\n"))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, b"CMT");
        assert_eq!(
            collect_rar50_file(raw, services[0]).unwrap().data,
            b"facade rar5 comment\n"
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 comment payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_stored_file_comment_service() {
        let services = [rar50::StoredServiceEntry {
            name: b"CMT",
            data: b"facade rar5 file comment\n",
        }];
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .stored_entries_with_services(&[rar50::StoredEntryWithServices {
                entry: rar50::StoredEntry {
                    name: b"rar5-file-commented.txt",
                    data: b"facade rar5 file comment payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                },
                services: &services,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, b"CMT");
        assert_eq!(
            collect_rar50_file(raw, services[0]).unwrap().data,
            b"facade rar5 file comment\n"
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 file comment payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_file_comment_service() {
        let services = [rar50::EncryptedStoredServiceEntry {
            name: b"CMT",
            data: b"facade encrypted rar5 file comment\n",
            password: b"password",
        }];
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.file_comment = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_stored_entries_with_services(&[
                    rar50::EncryptedStoredEntryWithServices {
                        entry: rar50::EncryptedStoredEntry {
                            name: b"rar5-encrypted-file-commented.txt",
                            data: b"facade encrypted rar5 file comment payload\n",
                            mtime: None,
                            attributes: 0x20,
                            host_os: 3,
                            password: b"password",
                        },
                        services: &services,
                    },
                ])
                .finish()
                .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let service = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(service.data, b"facade encrypted rar5 file comment\n");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade encrypted rar5 file comment payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_file_comment_service() {
        let services = [rar50::EncryptedStoredServiceEntry {
            name: b"CMT",
            data: b"facade header encrypted rar5 file comment\n",
            password: b"password",
        }];
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.file_comment = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_stored_entries_with_services(&[
                    rar50::EncryptedStoredEntryWithServices {
                        entry: rar50::EncryptedStoredEntry {
                            name: b"rar5-header-file-commented.txt",
                            data: b"facade header encrypted rar5 file comment payload\n",
                            mtime: None,
                            attributes: 0x20,
                            host_os: 3,
                            password: b"password",
                        },
                        services: &services,
                    },
                ])
                .finish()
                .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let service = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(service.data, b"facade header encrypted rar5 file comment\n");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade header encrypted rar5 file comment payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_stored_archive_with_quick_open_service() {
        let mut features = FeatureSet::store_only();
        features.quick_open = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .stored_entries(&[rar50::StoredEntry {
                    name: b"rar5-qo.txt",
                    data: b"facade rar5 quick-open payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                }])
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.locator().unwrap().quick_open_offset.unwrap() > 0);
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, b"QO");
        assert!(!collect_rar50_file(raw, services[0])
            .unwrap()
            .data
            .is_empty());
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 quick-open payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_stored_archive_with_file_services() {
        let services = [
            rar50::StoredServiceEntry {
                name: b"ACL",
                data: b"facade acl",
            },
            rar50::StoredServiceEntry {
                name: b"STM",
                data: b"facade stream",
            },
        ];
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .stored_entries_with_services(&[rar50::StoredEntryWithServices {
                entry: rar50::StoredEntry {
                    name: b"rar5-services.txt",
                    data: b"facade rar5 service payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                },
                services: &services,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].name, b"ACL");
        assert_eq!(services[1].name, b"STM");
        assert_eq!(
            collect_rar50_file(raw, services[0]).unwrap().data,
            b"facade acl"
        );
        assert_eq!(
            collect_rar50_file(raw, services[1]).unwrap().data,
            b"facade stream"
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 service payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_stored_archive_with_recovery_service() {
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .stored_entries(&[rar50::StoredEntry {
                    name: b"rar5-recovery.txt",
                    data: b"facade rar5 recovery payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                }])
                .recovery_percent(Some(9))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        let recovery = service.recovery_record().unwrap().unwrap();
        assert_eq!(recovery.percent, 9);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 recovery payload\n");
    }

    #[test]
    fn archive_facade_repairs_rar50_inline_recovery_damage() {
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;
        let payload = b"facade rar5 repair payload\n".repeat(64);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .stored_entries(&[rar50::StoredEntry {
                    name: b"rar5-repair.txt",
                    data: &payload,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                }])
                .recovery_percent(Some(20))
                .finish()
                .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let data_range = archive
            .as_rar50()
            .unwrap()
            .files()
            .next()
            .unwrap()
            .block
            .data_range
            .clone();
        let mut damaged = bytes.clone();
        damaged[data_range.start + 4..data_range.start + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();
        assert!(collect_extract(&damaged_archive, None).is_err());

        let mut repaired = Vec::new();
        damaged_archive.repair_recovery_to(&mut repaired).unwrap();

        assert_eq!(repaired, bytes);
        let repaired_archive = ArchiveReader::read(&repaired).unwrap();
        assert_eq!(
            collect_extract(&repaired_archive, None).unwrap()[0].data,
            payload
        );
    }

    #[test]
    fn archive_facade_reports_rar13_family_for_unsupported_recovery_repair() {
        let bytes = rar13::write_stored_archive(
            &[rar13::StoredEntry {
                name: b"old.txt",
                data: b"old rar payload",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            }],
            rar13_options(ArchiveVersion::Rar13),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let mut repaired = Vec::new();
        let err = archive.repair_recovery_to(&mut repaired).unwrap_err();

        assert_eq!(
            err,
            Error::UnsupportedFamilyFeature {
                family: ArchiveFamily::Rar13,
                feature: "recovery repair for RAR 1.3/1.4 archives"
            }
        );
    }

    /// Fixture with an oversubscribed RAR 2.9 main Huffman table: a
    /// complete table plus one junk length-15 entry on the unused tail
    /// symbol 298, the shape old WinRAR 2.x encoders emitted for unused
    /// alphabet slots (seen in the wild on the 11 Aug 2026 soak set).
    /// unrar never validates subscription and extracts it (verified with
    /// UNRAR 7.21); rars used to refuse with "RAR 2.9 oversubscribed
    /// Huffman table". The tolerant fallback must decode it CRC-clean.
    #[test]
    fn rar29_oversubscribed_huffman_table_extracts_like_unrar() {
        let archive =
            ArchiveReader::read_path(rar15_40_fixture("rars_generated/oversubscribed_main_tail.rar"))
                .unwrap();
        let entries = collect_extract(&archive, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"big.dat");
        assert_eq!(entries[0].data.len(), 171_847);
        // The stored member CRC gates the extraction above; pin the
        // payload here too so a silent decode change cannot hide.
        assert_eq!(crc32::crc32(&entries[0].data), 0x4974_dc39);
    }

    /// A RAR 2.x unix-owner sub-block (`0x77`, sub type `UO_HEAD`) declares
    /// an owner and a group name size but stores the names themselves in the
    /// block's DATA area, past `head_size` - and the `HEAD_CRC` WinRAR
    /// stamped covers them, because unrar reads both into the same raw
    /// header buffer before checksumming it. Checksumming only `head_size`
    /// refused the whole archive at parse time with "checksum mismatch:
    /// expected 0x1fc3, got 0x974d" (torture round 4 finding 4), where `rar`
    /// 7.23 extracts it.
    #[test]
    fn rar2_unix_owner_subblock_crc_covers_the_names_in_its_data_area() {
        let bytes = std::fs::read(rar15_40_fixture("external/rar2_unix_owner.rar")).unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let entries = collect_extract(&archive, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"file.txt");
        assert_eq!(entries[0].data, b"foo\n");

        // The seekable walk reads one block header at a time, sized by
        // `head_size`, so it has to reach past it for the names on its own.
        let walked = ArchiveReader::read_path(rar15_40_fixture("external/rar2_unix_owner.rar"))
            .and_then(|archive| collect_extract(&archive, None))
            .unwrap();
        assert_eq!(walked[0].data, b"foo\n");

        // The range was extended, not dropped. Byte 0x5f is the first byte
        // of the owner name, which lives OUTSIDE `head_size`: damaging it
        // has to be caught, or the sub-block would have been quietly exempt
        // from its own checksum.
        let mut damaged = bytes.clone();
        damaged[0x5f] ^= 0x20;
        assert!(matches!(
            ArchiveReader::read(&damaged),
            Err(Error::CrcMismatch {
                expected: 0x1fc3,
                ..
            })
        ));

        // Truncating the archive so the names are gone leaves nothing to
        // checksum against. The header check stands down (a CRC over a range
        // the writer never covered would be a libel), and the block is
        // refused for what it actually is: short of its own data area.
        assert!(matches!(
            ArchiveReader::read(&bytes[..0x5f]),
            Err(Error::TooShort)
        ));
    }

    #[test]
    fn archive_facade_repairs_rar15_40_recovery_as_full_archive_bytes() {
        let bytes = std::fs::read(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
        let mut damaged = bytes.clone();
        damaged[512 + 16..512 + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();
        assert!(collect_extract(&damaged_archive, None).is_err());

        let mut repaired = Vec::new();
        damaged_archive.repair_recovery_to(&mut repaired).unwrap();

        assert_eq!(repaired, bytes);
        let repaired_archive = ArchiveReader::read(&repaired).unwrap();
        assert_eq!(
            collect_extract(&repaired_archive, None).unwrap()[0].name,
            b"BIG.BIN"
        );
    }

    #[test]
    fn archive_facade_repairs_rar3_newsub_recovery_as_full_archive_bytes() {
        let bytes = std::fs::read(rar15_40_fixture("rar300/with_recovery_rar300.rar")).unwrap();
        let mut damaged = bytes.clone();
        damaged[512 + 16..512 + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();
        assert!(collect_extract(&damaged_archive, None).is_err());

        let mut repaired = Vec::new();
        damaged_archive.repair_recovery_to(&mut repaired).unwrap();

        assert_eq!(repaired, bytes);
        let repaired_archive = ArchiveReader::read(&repaired).unwrap();
        assert_eq!(
            collect_extract(&repaired_archive, None).unwrap()[0].name,
            b"bigtext_64k.bin"
        );
    }

    /// Runs the streaming legacy repair over `bytes` through BOTH public
    /// shapes - opened from a file via `repair_recovery_to_path` (the
    /// clone-prefill path the daemon uses) and opened from memory via
    /// `repair_recovery_to_file` (the streaming-copy path) - asserts the two
    /// agree, and returns the repaired bytes plus rebuilt sector indices.
    fn protect_repair_streaming(bytes: &[u8], budget: u64) -> Result<(Vec<u8>, Vec<usize>)> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let src = dir.join(format!("rars-protect-src-{pid}-{seq}.rar"));
        let path_dst = dir.join(format!("rars-protect-pathdst-{pid}-{seq}.rar"));
        let file_dst = dir.join(format!("rars-protect-filedst-{pid}-{seq}.rar"));
        std::fs::write(&src, bytes).unwrap();

        let from_path = ArchiveReader::read_path(&src)
            .and_then(|archive| archive.repair_recovery_to_path(&path_dst, None, budget))
            .map(|rebuilt| (std::fs::read(&path_dst).unwrap(), rebuilt));
        let from_file = ArchiveReader::read(bytes).and_then(|archive| {
            let mut dest = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&file_dst)?;
            let rebuilt = archive.repair_recovery_to_file(&mut dest, None, budget)?;
            Ok((std::fs::read(&file_dst).unwrap(), rebuilt))
        });
        for path in [&src, &path_dst, &file_dst] {
            let _ = std::fs::remove_file(path);
        }
        assert_eq!(
            from_path, from_file,
            "file-backed and memory-backed streaming repairs disagree"
        );
        from_path
    }

    #[test]
    fn streaming_protect_repair_matches_buffered_for_rar2() {
        let bytes = std::fs::read(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
        let mut damaged = bytes.clone();
        // Two damaged sectors in distinct parity groups (rec_sectors = 5).
        damaged[512 + 16..512 + 80].fill(0xa5);
        damaged[7 * 512 + 10..7 * 512 + 200].fill(0x5a);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();
        assert!(collect_extract(&damaged_archive, None).is_err());

        let buffered = damaged_archive
            .as_rar15_40()
            .unwrap()
            .repair_protect_head()
            .unwrap();
        let (streamed, rebuilt) = protect_repair_streaming(&damaged, u64::MAX).unwrap();
        assert_eq!(rebuilt, vec![1, 7]);
        assert_eq!(streamed, buffered);
        assert_eq!(streamed, bytes);
        assert_eq!(
            collect_extract(&ArchiveReader::read(&streamed).unwrap(), None).unwrap()[0].data,
            collect_extract(&ArchiveReader::read(&bytes).unwrap(), None).unwrap()[0].data
        );
    }

    #[test]
    fn streaming_protect_repair_passes_through_rar2_with_no_repairable_sectors() {
        // rr1's PROTECT_HEAD sits at offset 111, so no complete sector
        // precedes it and nothing is repairable; the streaming path must
        // still hand back a byte-complete copy, exactly like the buffered
        // path's undamaged passthrough.
        let bytes = std::fs::read(rar15_40_fixture("rar250_protect_head_rr1.rar")).unwrap();
        let (streamed, rebuilt) = protect_repair_streaming(&bytes, u64::MAX).unwrap();
        assert_eq!(rebuilt, Vec::<usize>::new());
        assert_eq!(streamed, bytes);
    }

    #[test]
    fn streaming_protect_repair_matches_buffered_for_rar3_newsub() {
        let bytes = std::fs::read(rar15_40_fixture("rar300/with_recovery_rar300.rar")).unwrap();
        let mut damaged = bytes.clone();
        // Sector 1, and the PARTIAL final protected sector: the RR block
        // starts at 9819, so sector 19 covers bytes 9728..9819 and is
        // zero-padded for CRC/XOR purposes.
        damaged[512 + 16..512 + 80].fill(0xa5);
        damaged[9750..9800].fill(0x5a);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();
        assert!(collect_extract(&damaged_archive, None).is_err());

        let buffered = damaged_archive
            .as_rar15_40()
            .unwrap()
            .repair_protect_head()
            .unwrap();
        let (streamed, rebuilt) = protect_repair_streaming(&damaged, u64::MAX).unwrap();
        assert_eq!(rebuilt, vec![1, 19]);
        assert_eq!(streamed, buffered);
        assert_eq!(streamed, bytes);
        assert_eq!(
            collect_extract(&ArchiveReader::read(&streamed).unwrap(), None).unwrap()[0].data,
            collect_extract(&ArchiveReader::read(&bytes).unwrap(), None).unwrap()[0].data
        );
    }

    #[test]
    fn streaming_protect_repair_matches_buffered_for_rar3_newsub_behind_sfx_stub() {
        // A genuine archive behind an SFX stub: the protected sectors start
        // at sfx_offset, not 0, and the record still repairs them because
        // the archive bytes are unchanged.
        let bytes = std::fs::read(rar15_40_fixture("rar300/with_recovery_rar300.rar")).unwrap();
        let mut stub = vec![0x4du8; 1024];
        stub[1] = 0x5a; // "MZ" without any RAR signature in the stub
        let mut sfx = stub.clone();
        sfx.extend_from_slice(&bytes);
        let mut damaged = sfx.clone();
        damaged[1024 + 512 + 16..1024 + 512 + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();

        let buffered = damaged_archive
            .as_rar15_40()
            .unwrap()
            .repair_protect_head()
            .unwrap();
        let (streamed, rebuilt) = protect_repair_streaming(&damaged, u64::MAX).unwrap();
        assert_eq!(rebuilt, vec![1]);
        assert_eq!(streamed, buffered);
        assert_eq!(streamed, sfx);
    }

    #[test]
    fn streaming_protect_repair_matches_buffered_for_rar3_compressed_newsub() {
        let bytes = std::fs::read(rar15_40_fixture(
            "rar300/with_compressed_recovery_rar300.rar",
        ))
        .unwrap();
        let mut damaged = bytes.clone();
        damaged[512 + 16..512 + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();

        let buffered = damaged_archive
            .as_rar15_40()
            .unwrap()
            .repair_protect_head()
            .unwrap();
        let (streamed, rebuilt) = protect_repair_streaming(&damaged, u64::MAX).unwrap();
        assert_eq!(rebuilt, vec![1]);
        assert_eq!(streamed, buffered);
        assert_eq!(streamed, bytes);
    }

    #[test]
    fn streaming_protect_repair_reports_budget_exhaustion() {
        // A damaged stored-record repair whose working set cannot fit.
        let bytes = std::fs::read(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
        let mut damaged = bytes.clone();
        damaged[512 + 16..512 + 80].fill(0xa5);
        assert_eq!(
            protect_repair_streaming(&damaged, 1).unwrap_err(),
            Error::LegacyRepairTooLarge
        );

        // A compressed NEWSUB record is refused BEFORE its decode allocates.
        let bytes = std::fs::read(rar15_40_fixture(
            "rar300/with_compressed_recovery_rar300.rar",
        ))
        .unwrap();
        assert_eq!(
            protect_repair_streaming(&bytes, 1).unwrap_err(),
            Error::LegacyRepairTooLarge
        );
    }

    #[test]
    fn streaming_protect_repair_rejects_damage_beyond_parity_like_buffered() {
        // Six damaged sectors against five parity sectors: the streaming
        // path must refuse with the same error the buffered path raises.
        let bytes = std::fs::read(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
        let mut damaged = bytes.clone();
        for sector in 1..=6usize {
            damaged[sector * 512 + 16..sector * 512 + 80].fill(0xa5);
        }
        let buffered_err = ArchiveReader::read(&damaged)
            .unwrap()
            .as_rar15_40()
            .unwrap()
            .repair_protect_head()
            .unwrap_err();
        assert_eq!(
            protect_repair_streaming(&damaged, u64::MAX).unwrap_err(),
            buffered_err
        );
    }

    #[test]
    fn direct_writer_creates_rar50_compressed_archive_with_recovery_service() {
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;
        let payload = b"facade rar5 compressed recovery payload repeated repeated\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .compressed_entries(&[rar50::CompressedEntry {
                    name: b"rar5-compressed-recovery.txt",
                    data: &payload,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                }])
                .recovery_percent(Some(9))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 9);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar70_stored_archive_with_metadata() {
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar70))
            .stored_entries(&[rar50::StoredEntry {
                name: b"rar7-metadata.txt",
                data: b"facade rar7 metadata payload\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar7 metadata payload\n");
    }

    #[test]
    fn direct_writer_creates_rar70_compressed_archive_with_metadata() {
        let payload = b"facade rar7 compressed metadata payload repeated\n".repeat(8);
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar70))
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar7-compressed-metadata.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-compressed-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-compressed-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_compressed_archive_with_comment() {
        let payload = b"facade rar5 compressed archive comment payload repeated\n".repeat(8);
        let mut features = FeatureSet::store_only();
        features.archive_comment = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .compressed_entries(&[rar50::CompressedEntry {
                    name: b"rar5-compressed-comment.txt",
                    data: &payload,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                }])
                .archive_comment(Some(b"facade compressed comment\n"))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(comment.data, b"facade compressed comment\n");
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar70_encrypted_stored_archive_with_metadata() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar70, features))
                .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                    name: b"rar7-encrypted-metadata.txt",
                    data: b"facade rar7 encrypted metadata payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                    name: Some(b"facade-encrypted-metadata.rar"),
                    creation_time: Some(0x01dcd60e_662d7a32),
                }))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-encrypted-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar7 encrypted metadata payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar70_encrypted_compressed_archive_with_metadata() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let payload = b"facade rar7 encrypted compressed metadata payload repeated\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar70, features))
                .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                    name: b"rar7-encrypted-compressed-metadata.txt",
                    data: &payload,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                    name: Some(b"facade-encrypted-compressed-metadata.rar"),
                    creation_time: Some(0x01dcd60e_662d7a32),
                }))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-encrypted-compressed-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar70_header_encrypted_stored_archive_with_metadata() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar70, features))
                .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                    name: b"rar7-header-metadata.txt",
                    data: b"facade rar7 header encrypted metadata payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                    name: Some(b"facade-header-metadata.rar"),
                    creation_time: Some(0x01dcd60e_662d7a32),
                }))
                .finish()
                .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-header-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar7 header encrypted metadata payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar70_header_encrypted_compressed_archive_with_metadata() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let payload =
            b"facade rar7 header encrypted compressed metadata payload repeated\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar70, features))
                .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                    name: b"rar7-header-compressed-metadata.txt",
                    data: &payload,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                    name: Some(b"facade-header-compressed-metadata.rar"),
                    creation_time: Some(0x01dcd60e_662d7a32),
                }))
                .finish()
                .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-header-compressed-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                    name: b"rar5-secret.txt",
                    data: b"facade rar5 encrypted stored payload\n",
                    mtime: Some(0),
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::AtEntry { source, .. }) if matches!(*source, Error::NeedPassword)
        ));
        assert!(matches!(
            collect_extract(&archive, Some(b"wrong")),
            Err(Error::AtEntry { source, .. })
                if matches!(*source, Error::WrongPasswordOrCorruptData)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 encrypted stored payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let payload = b"facade rar5 encrypted compressed\n".repeat(16);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                    name: b"rar5-secret-compressed.txt",
                    data: &payload,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let file = raw.files().next().unwrap();
        assert!(file.encrypted);
        assert_eq!(file.decoded_compression_info().unwrap().method, 1);
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.solid = true;
        let first = b"facade rar50 encrypted solid shared phrase alpha beta gamma\n".repeat(12);
        let second =
            b"facade rar50 encrypted solid shared phrase alpha beta gamma\nsecond\n".repeat(6);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_compressed_entries(&[
                    rar50::EncryptedCompressedEntry {
                        name: b"rar5-encrypted-solid-one.txt",
                        data: &first,
                        mtime: None,
                        attributes: 0x20,
                        host_os: 3,
                        password: b"password",
                    },
                    rar50::EncryptedCompressedEntry {
                        name: b"rar5-encrypted-solid-two.txt",
                        data: &second,
                        mtime: None,
                        attributes: 0x20,
                        host_os: 3,
                        password: b"password",
                    },
                ])
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(files.iter().all(|file| file.encrypted));
        assert!(!files[0].decoded_compression_info().unwrap().solid);
        assert!(files[1].decoded_compression_info().unwrap().solid);
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let bytes = rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
            .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                name: b"rar5-header-secret-compressed.txt",
                data: b"facade rar5 header encrypted compressed\nfacade rar5 header encrypted compressed\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .finish()
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let file = raw.files().next().unwrap();
        assert!(file.encrypted);
        assert_eq!(file.decoded_compression_info().unwrap().method, 1);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted compressed\nfacade rar5 header encrypted compressed\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.solid = true;
        let first =
            b"facade rar50 header encrypted solid shared phrase alpha beta gamma\n".repeat(12);
        let second =
            b"facade rar50 header encrypted solid shared phrase alpha beta gamma\nsecond\n"
                .repeat(6);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_compressed_entries(&[
                    rar50::EncryptedCompressedEntry {
                        name: b"rar5-header-solid-one.txt",
                        data: &first,
                        mtime: None,
                        attributes: 0x20,
                        host_os: 3,
                        password: b"password",
                    },
                    rar50::EncryptedCompressedEntry {
                        name: b"rar5-header-solid-two.txt",
                        data: &second,
                        mtime: None,
                        attributes: 0x20,
                        host_os: 3,
                        password: b"password",
                    },
                ])
                .finish()
                .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(files.iter().all(|file| file.encrypted));
        assert!(!files[0].decoded_compression_info().unwrap().solid);
        assert!(files[1].decoded_compression_info().unwrap().solid);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_archive_with_comment() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.archive_comment = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                    name: b"rar5-secret.txt",
                    data: b"facade rar5 encrypted stored payload\n",
                    mtime: Some(0),
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .encrypted_archive_comment(Some(rar50::EncryptedArchiveCommentEntry {
                    data: b"facade encrypted comment\n",
                    password: b"password",
                }))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(comment.data, b"facade encrypted comment\n");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 encrypted stored payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_compressed_archive_with_comment() {
        let payload = b"facade rar5 encrypted compressed comment payload\n".repeat(8);
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.archive_comment = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                    name: b"rar5-encrypted-compressed-comment.txt",
                    data: &payload,
                    mtime: Some(0),
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .encrypted_archive_comment(Some(rar50::EncryptedArchiveCommentEntry {
                    data: b"facade encrypted compressed comment\n",
                    password: b"password",
                }))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(comment.data, b"facade encrypted compressed comment\n");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                    name: b"rar5-header-secret.txt",
                    data: b"facade rar5 header encrypted stored payload\n",
                    mtime: Some(0),
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .finish()
                .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        assert!(matches!(
            ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"wrong")),
            Err(Error::WrongPasswordOrCorruptData)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted stored payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_archive_with_comment() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.archive_comment = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                    name: b"rar5-header-comment-secret.txt",
                    data: b"facade rar5 header encrypted comment payload\n",
                    mtime: Some(0),
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .encrypted_archive_comment(Some(rar50::EncryptedArchiveCommentEntry {
                    data: b"facade header encrypted comment\n",
                    password: b"password",
                }))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(comment.data, b"facade header encrypted comment\n");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted comment payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_compressed_archive_with_comment() {
        let payload = b"facade rar5 header encrypted compressed comment payload\n".repeat(8);
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.archive_comment = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                    name: b"rar5-header-compressed-comment-secret.txt",
                    data: &payload,
                    mtime: Some(0),
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .encrypted_archive_comment(Some(rar50::EncryptedArchiveCommentEntry {
                    data: b"facade header encrypted compressed comment\n",
                    password: b"password",
                }))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(
            comment.data,
            b"facade header encrypted compressed comment\n"
        );
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_archive_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.recovery_record = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                    name: b"rar5-encrypted-recovery.txt",
                    data: b"facade rar5 encrypted recovery payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .recovery_percent(Some(6))
                .recovery_password(Some(b"password"))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 6);
        let recovery_data = collect_rar50_file(raw, service).unwrap().data;
        assert!(recovery_data.starts_with(b"{RB}"));
        assert_eq!(
            u32::from_le_bytes(recovery_data[0x0c..0x10].try_into().unwrap()) as usize,
            recovery_data.len()
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 encrypted recovery payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_compressed_archive_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.recovery_record = true;
        let payload = b"facade rar5 encrypted compressed recovery payload repeated\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                    name: b"rar5-encrypted-compressed-recovery.txt",
                    data: &payload,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .recovery_percent(Some(6))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 6);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_archive_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.recovery_record = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                    name: b"rar5-header-recovery.txt",
                    data: b"facade rar5 header encrypted recovery payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .recovery_percent(Some(4))
                .recovery_password(Some(b"password"))
                .finish()
                .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert!(!service.encrypted);
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 4);
        let recovery_data = collect_rar50_file(raw, service).unwrap().data;
        assert!(recovery_data.starts_with(b"{RB}"));
        assert_eq!(
            u32::from_le_bytes(recovery_data[0x0c..0x10].try_into().unwrap()) as usize,
            recovery_data.len()
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted recovery payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_compressed_archive_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.recovery_record = true;
        let payload =
            b"facade rar5 header encrypted compressed recovery payload repeated\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                    name: b"rar5-header-compressed-recovery.txt",
                    data: &payload,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                }])
                .recovery_percent(Some(4))
                .finish()
                .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert!(!service.encrypted);
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 4);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let payload = b"facade rar5 encrypted split payload\n".repeat(12);
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_stored_entry(rar50::EncryptedStoredEntry {
            name: b"split-secret50.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        })
        .max_payload_per_volume(16)
        .finish()
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.recovery_record = true;
        let payload = b"facade rar5 encrypted recovery split payload\n".repeat(12);
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_stored_entry(rar50::EncryptedStoredEntry {
            name: b"split-secret50-rr.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        })
        .max_payload_per_volume(16)
        .recovery_percent(Some(8))
        .finish()
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.recovery_record = true;
        let payload = b"facade rar5 header encrypted recovery split payload\n".repeat(4);
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_stored_entry(rar50::EncryptedStoredEntry {
            name: b"split-header-secret50-rr.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        })
        .max_payload_per_volume(16)
        .recovery_percent(Some(8))
        .finish()
        .unwrap();
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-header-secret50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let payload = b"facade rar5 header encrypted split payload\n".repeat(12);
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_stored_entry(rar50::EncryptedStoredEntry {
            name: b"split-header-secret50.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        })
        .max_payload_per_volume(16)
        .finish()
        .unwrap();
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-header-secret50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let payload = b"facade rar5 encrypted compressed split payload\n".repeat(12);
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_compressed_entries(std::slice::from_ref(&rar50::EncryptedCompressedEntry {
            name: b"split-secret-compressed50.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        }))
        .max_payload_per_volume(32)
        .finish()
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_compressed_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.recovery_record = true;
        let payload = b"facade rar5 encrypted compressed recovery split payload\n".repeat(12);
        let entries = [rar50::EncryptedCompressedEntry {
            name: b"split-secret-compressed50-rr.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        }];
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_compressed_entries(&entries)
        .max_payload_per_volume(32)
        .recovery_percent(Some(8))
        .finish()
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret-compressed50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_compressed_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.recovery_record = true;
        let payload =
            b"facade rar5 header encrypted compressed recovery split payload\n".repeat(12);
        let entries = [rar50::EncryptedCompressedEntry {
            name: b"split-header-secret-compressed50-rr.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        }];
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_compressed_entries(&entries)
        .max_payload_per_volume(32)
        .recovery_percent(Some(8))
        .finish()
        .unwrap();
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].name,
            b"split-header-secret-compressed50-rr.txt"
        );
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.solid = true;
        let payload = b"facade rar5 encrypted solid compressed split payload\n".repeat(12);
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_compressed_entries(std::slice::from_ref(&rar50::EncryptedCompressedEntry {
            name: b"split-solid-secret-compressed50.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        }))
        .max_payload_per_volume(32)
        .finish()
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-solid-secret-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let payload: Vec<u8> = (0..512).map(|index| (index * 37 + 11) as u8).collect();
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_compressed_entries(std::slice::from_ref(&rar50::EncryptedCompressedEntry {
            name: b"split-header-secret-compressed50.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        }))
        .max_payload_per_volume(64)
        .finish()
        .unwrap();
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = collect_rar50_volumes(&archives, None).unwrap();
        assert_eq!(extracted[0].name, b"split-header-secret-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.solid = true;
        let payload = b"facade rar5 header encrypted solid compressed split payload\n".repeat(12);
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .encrypted_compressed_entries(std::slice::from_ref(&rar50::EncryptedCompressedEntry {
            name: b"split-header-solid-secret-compressed50.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        }))
        .max_payload_per_volume(32)
        .finish()
        .unwrap();
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));

        let extracted = collect_rar50_volumes(&archives, None).unwrap();
        assert_eq!(
            extracted[0].name,
            b"split-header-solid-secret-compressed50.txt"
        );
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_stored_volumes() {
        let payload = b"facade rar5 stored split payload\n".repeat(20);
        let parts = rar50::Rar50VolumeWriter::new(rar50_options(ArchiveVersion::Rar50))
            .stored_entry(rar50::StoredEntry {
                name: b"split50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            })
            .max_payload_per_volume(80)
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_stored_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;
        let payload = b"facade rar5 stored recovery split payload\n".repeat(20);
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .stored_entry(rar50::StoredEntry {
            name: b"split50-rr.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        })
        .max_payload_per_volume(80)
        .recovery_percent(Some(8))
        .finish()
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_compressed_volumes() {
        let payload: Vec<u8> = (0..512).map(|index| (index * 53 + 17) as u8).collect();
        let parts = rar50::Rar50VolumeWriter::new(rar50_options(ArchiveVersion::Rar50))
            .compressed_entries(std::slice::from_ref(&rar50::CompressedEntry {
                name: b"split-compressed50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }))
            .max_payload_per_volume(64)
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_compressed_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;
        let payload: Vec<u8> = (0..512).map(|index| (index * 53 + 17) as u8).collect();
        let entries = [rar50::CompressedEntry {
            name: b"split-compressed50-rr.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .compressed_entries(&entries)
        .max_payload_per_volume(64)
        .recovery_percent(Some(8))
        .finish()
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split-compressed50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let payload = b"facade rar5 solid compressed split payload\n".repeat(12);
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .compressed_entries(std::slice::from_ref(&rar50::CompressedEntry {
            name: b"split-solid-compressed50.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }))
        .max_payload_per_volume(32)
        .finish()
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split-solid-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_multi_file_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let mut first = b"facade rar5 multi-file solid split shared phrase\n"
            .repeat(8)
            .to_vec();
        first.extend_from_slice(&deterministic_noise(2048));
        let mut second = b"facade rar5 multi-file solid split shared phrase\nsecond\n"
            .repeat(8)
            .to_vec();
        second.extend_from_slice(&deterministic_noise(2048));
        let entries = [
            rar50::CompressedEntry {
                name: b"solid-volume-one.txt",
                data: &first,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
            rar50::CompressedEntry {
                name: b"solid-volume-two.txt",
                data: &second,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
        ];
        let parts = rar50::Rar50VolumeWriter::new(rar50_options_with_features(
            ArchiveVersion::Rar50,
            features,
        ))
        .compressed_entries(&entries)
        .max_payload_per_volume(512)
        .finish()
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"solid-volume-one.txt");
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].name, b"solid-volume-two.txt");
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn archive_as_rar13_returns_some_only_for_rar13_family() {
        let bytes = rar13::write_stored_archive(
            &[rar13::StoredEntry {
                name: b"old.txt",
                data: b"r13 downcast",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            }],
            rar13_options(ArchiveVersion::Rar14),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar13().unwrap();
        assert_eq!(raw.entries[0].name, b"old.txt");
        assert!(archive.as_rar15_40().is_none());
        assert!(archive.as_rar50().is_none());

        // Other-family archives should refuse the rar13 downcast.
        let rar15_bytes = rar15_40::write_stored_archive(
            &[rar15_40::StoredEntry {
                name: b"mid.txt",
                data: b"r15 downcast",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar15),
        )
        .unwrap();
        let rar15_archive = ArchiveReader::read(&rar15_bytes).unwrap();
        assert!(rar15_archive.as_rar13().is_none());

        let rar50_bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .stored_entries(&[rar50::StoredEntry {
                name: b"new.txt",
                data: b"r50 downcast",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .finish()
            .unwrap();
        let rar50_archive = ArchiveReader::read(&rar50_bytes).unwrap();
        assert!(rar50_archive.as_rar13().is_none());
    }

    #[test]
    fn archive_facade_repair_recovery_returns_full_repaired_archive_bytes() {
        let bytes = std::fs::read(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
        let mut damaged = bytes.clone();
        damaged[512 + 16..512 + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();

        let repaired = damaged_archive.repair_recovery().unwrap();
        assert_eq!(repaired, bytes);
    }

    #[test]
    fn archive_facade_repair_recovery_rejects_rar13_archives() {
        let bytes = rar13::write_stored_archive(
            &[rar13::StoredEntry {
                name: b"old.txt",
                data: b"old data",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            }],
            rar13_options(ArchiveVersion::Rar14),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(
            archive.repair_recovery(),
            Err(Error::UnsupportedFamilyFeature {
                family: ArchiveFamily::Rar13,
                feature: "recovery repair for RAR 1.3/1.4 archives",
            })
        );
    }

    #[test]
    fn archive_reader_read_path_dispatches_to_default_options() {
        // Existing tests cover read_path_with_options; this ensures the
        // zero-arg convenience wrapper actually delegates to it.
        let archive =
            ArchiveReader::read_path(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        assert!(archive.as_rar15_40().unwrap().main.has_recovery_record());
    }

    // --- member-parallel pool differentials (rar50/pool_members.rar:
    //     8 x 2KB compressed + 1 stored + 1 empty + 1 x 30KB member) -----

    fn rar50_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar50")
            .join(name)
    }

    /// Extract a volume set through the public multivolume API, collecting
    /// (name, bytes) in open() order.
    fn collect_volumes_with_options(
        volumes: &[Archive],
        options: ArchiveReadOptions<'_>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let entries = RefCell::new(Vec::new());
        extract_volumes_to_with_options(volumes, options, |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries
                .borrow_mut()
                .push((meta.name.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(name, data)| (name, data.borrow().clone()))
            .collect())
    }

    /// The pooled path (high buffered limit -> members decode on workers
    /// under the `parallel` feature) must produce the same entries, in the
    /// same open() order, with the same bytes, as the fully-streaming
    /// serial path (limit 0 -> nothing is pool-eligible).
    #[test]
    fn pooled_volume_extract_matches_serial_output_and_order() {
        let volumes = vec![ArchiveReader::read_path(rar50_fixture("pool_members.rar")).unwrap()];
        let pooled = collect_volumes_with_options(
            &volumes,
            ArchiveReadOptions::new().with_rar50_buffered_decode_limit(512 * 1024),
        )
        .unwrap();
        let serial = collect_volumes_with_options(
            &volumes,
            ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0),
        )
        .unwrap();
        assert_eq!(pooled.len(), 11);
        assert_eq!(pooled, serial);
        // sanity: the mixed shapes all made it
        let names: Vec<&[u8]> = pooled.iter().map(|(n, _)| n.as_slice()).collect();
        assert!(names.contains(&b"stored.bin".as_slice()));
        assert!(names.contains(&b"empty.dat".as_slice()));
        assert!(names.contains(&b"big.txt".as_slice()));
    }

    /// Under the cfg(test) 8KB in-flight budget the feeder must block and
    /// resume (the fixture decodes to ~46KB); repeated runs must stay
    /// byte-identical and ordered - reorder pressure is not allowed to
    /// change observable behavior.
    #[test]
    fn pooled_volume_extract_is_deterministic_under_backpressure() {
        let volumes = vec![ArchiveReader::read_path(rar50_fixture("pool_members.rar")).unwrap()];
        let options = ArchiveReadOptions::new().with_rar50_buffered_decode_limit(512 * 1024);
        let first = collect_volumes_with_options(&volumes, options).unwrap();
        for _ in 0..8 {
            let again = collect_volumes_with_options(&volumes, options).unwrap();
            assert_eq!(first, again);
        }
    }

    /// Solid-chain differential: the chain decodes a whole solid group as
    /// one stream (flat-apply when it fits the budget, ring-streaming
    /// otherwise); both variants must match the serial per-member path
    /// byte-for-byte, including entry order. `Archive::extract_to` is the
    /// serial baseline (the chain is wired into the volume path only).
    #[test]
    fn solid_chain_extract_matches_serial() {
        let archive = ArchiveReader::read_path(rar50_fixture("solid.rar")).unwrap();
        let serial: Vec<(Vec<u8>, Vec<u8>)> = collect_extract(&archive, None)
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.data))
            .collect();
        let volumes = vec![archive];
        // Streaming chain (tiny cfg(test) buffered limit keeps flat off).
        let streaming = collect_volumes_with_options(&volumes, ArchiveReadOptions::new()).unwrap();
        // Flat chain (limit far above the fixture's total size).
        let flat = collect_volumes_with_options(
            &volumes,
            ArchiveReadOptions::new().with_rar50_buffered_decode_limit(512 * 1024 * 1024),
        )
        .unwrap();
        assert!(!serial.is_empty());
        assert_eq!(streaming, serial, "streaming chain diverged from serial");
        assert_eq!(flat, serial, "flat chain diverged from serial");
    }

    /// The RAR4 budgeted pool survives a panic in the coordinator too.
    ///
    /// Same defect and same guard as the RAR5 twin's
    /// `a_coordinator_panic_does_not_hang_the_member_pool`, reached through the
    /// public facade. Also reproduces: revert the `PoolAbortGuard` in
    /// `rar15_40::extract_to_parallel_buffered` and this fails on the timeout.
    /// Two 8 KiB members against the `cfg(test)` 8 KiB budget is what parks the
    /// feeder on the condvar - it charges the first member, then has to wait for
    /// the coordinator to write it, and the coordinator panics instead.
    #[test]
    #[cfg(feature = "parallel")]
    fn rar4_parallel_pool_coordinator_panic_does_not_hang() {
        let member = vec![b'x'; 8 << 10];
        let entries: Vec<_> = [b"a.bin", b"b.bin"]
            .iter()
            .map(|name| rar15_40::StoredEntry {
                name: *name,
                data: &member,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            })
            .collect();
        let bytes =
            rar15_40::write_stored_archive(&entries, rar15_options(ArchiveVersion::Rar15)).unwrap();

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let archive = ArchiveReader::read(&bytes).unwrap();
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                archive.extract_to_parallel_buffered(None, |_meta| -> Result<Box<dyn Write>> {
                    panic!("open panicked")
                })
            }))
            .is_err();
            let _ = done_tx.send(panicked);
        });

        match done_rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(panicked) => assert!(panicked, "the coordinator panic must propagate"),
            Err(_) => panic!(
                "RAR4 parallel extraction did not return within 30s - the feeder is parked on \
                 the budget condvar and the scoped join is deadlocked"
            ),
        }
    }

    /// A failing writer surfaces an error and returns.
    ///
    /// HONEST SCOPE: this is a smoke test, NOT a regression test for the
    /// parked-producer hang fixed alongside it. It was written for that and
    /// does not achieve it - `solid.rar` decodes to less than the pipeline's
    /// 3 x 1 MiB pool, so the producer finishes before it can park on the
    /// drained pool channel, and this passes with the fix reverted. Making
    /// it bite needs a fixture whose decoded output exceeds the pool, or a
    /// test-only pool size - and shrinking constants under cfg(test) is
    /// what hid the equivalent rar15_40 deadlock, so that trade was
    /// declined. The timeout is kept because it costs nothing and a hang
    /// here would at least fail loudly rather than wedging the suite.
    #[test]
    fn solid_chain_writer_failure_does_not_hang() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("writer failed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let archive = ArchiveReader::read_path(rar50_fixture("solid.rar")).unwrap();
            let volumes = vec![archive];
            let result = extract_volumes_to(&volumes, None, |_entry| {
                Ok(Box::new(FailingWriter) as Box<dyn Write>)
            });
            let _ = tx.send(result.is_err());
        });

        match rx.recv_timeout(std::time::Duration::from_secs(20)) {
            Ok(errored) => assert!(errored, "a failing writer must surface an error"),
            Err(_) => panic!(
                "solid chain did not return within 20s - the producer is parked on the \
                 drained pool channel and the scoped join is deadlocked"
            ),
        }
    }

    /// One session, many volumes: the (salt, kdf count) ladder runs once
    /// for the whole set, per-member checks still run per archive, a fresh
    /// session derives again, and a wrong-password session fails even
    /// after another session succeeded.
    #[test]
    fn read_session_shares_key_derivations_across_archives() {
        let password: &[u8] = b"testpass";
        let mut session = ReadSession::new(ArchiveReadOptions::with_password(password));
        let first = session.read_path(rar50_fixture("encrypted_solid.rar")).unwrap();
        let second = session.read_path(rar50_fixture("encrypted_solid.rar")).unwrap();
        assert_eq!(session.derive_count(), 1, "shared salt must derive once");
        assert_eq!(collect_extract(&first, Some(password)).unwrap().len(), 6);
        assert_eq!(collect_extract(&second, Some(password)).unwrap().len(), 6);

        let mut fresh = ReadSession::new(ArchiveReadOptions::with_password(password));
        fresh.read_path(rar50_fixture("encrypted_solid.rar")).unwrap();
        assert_eq!(fresh.derive_count(), 1, "sessions do not share caches");

        let mut wrong = ReadSession::new(ArchiveReadOptions::with_password(b"nottheone"));
        assert!(
            wrong.read_path(rar50_fixture("encrypted_solid.rar")).is_err(),
            "wrong password must fail its own session"
        );

        // No password: parse succeeds (visible headers), nothing derives.
        let mut bare = ReadSession::new(ArchiveReadOptions::new());
        bare.read_path(rar50_fixture("encrypted_solid.rar")).unwrap();
        assert_eq!(bare.derive_count(), 0);
    }

    /// Encrypted solid archives were the one chain shape still fully serial:
    /// with the password supplied, both chain modes must reproduce the
    /// serial per-member decode (the scan thread decrypts, workers see
    /// plaintext, the consumer MACs digests with the parse-time keys), and
    /// with no password the set must fail with the serial path's error.
    #[test]
    fn encrypted_solid_chain_matches_serial() {
        let password: &[u8] = b"testpass";
        let archive = ArchiveReader::read_path_with_options(
            rar50_fixture("encrypted_solid.rar"),
            ArchiveReadOptions::with_password(password),
        )
        .unwrap();
        let serial: Vec<(Vec<u8>, Vec<u8>)> = collect_extract(&archive, Some(password))
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.data))
            .collect();
        assert_eq!(serial.len(), 6);

        let volumes = vec![archive];
        for limit in [512 * 1024u64, 512 * 1024 * 1024] {
            let got = collect_volumes_with_options(
                &volumes,
                ArchiveReadOptions::with_password(password)
                    .with_rar50_buffered_decode_limit(limit),
            )
            .unwrap();
            assert_eq!(got, serial, "encrypted solid chain diverged at limit {limit}");
        }

        // Corruption parity: a flipped payload byte must fail through the
        // chain path with the serial path's outcome (the chain retries the
        // group serially after restoring the snapshot).
        let clean = std::fs::read(rar50_fixture("encrypted_solid.rar")).unwrap();
        let mut damaged = clean.clone();
        let pos = clean.len() / 2;
        damaged[pos] ^= 0xFF;
        if let Ok(archive) = ArchiveReader::read_owned_with_options(
            damaged,
            ArchiveReadOptions::with_password(password),
        ) {
            let serial_result = collect_extract(&archive, Some(password));
            let chain_result = collect_volumes_with_options(
                &vec![archive.clone()],
                ArchiveReadOptions::with_password(password)
                    .with_rar50_buffered_decode_limit(512 * 1024 * 1024),
            );
            assert_eq!(
                serial_result.is_ok(),
                chain_result.is_ok(),
                "outcome diverged on corruption at {pos}"
            );
        }

        // No password: parsing succeeds, extraction reports NeedPassword
        // (serial semantics) rather than a chain artifact.
        let no_password =
            ArchiveReader::read_path(rar50_fixture("encrypted_solid.rar")).unwrap();
        let result = collect_volumes_with_options(
            &vec![no_password],
            ArchiveReadOptions::new().with_rar50_buffered_decode_limit(512 * 1024 * 1024),
        );
        assert!(result.is_err(), "missing password must fail");
    }

    /// The execution policy selects strategies (flat vs ring, worker
    /// counts), never bytes: every policy corner must produce the same
    /// entries as the default configuration on both a solid archive (chain
    /// paths) and a pooled non-solid one.
    #[test]
    fn execution_policy_never_changes_output() {
        for fixture in ["solid.rar", "pool_members.rar"] {
            let volumes = vec![ArchiveReader::read_path(rar50_fixture(fixture)).unwrap()];
            let baseline = collect_volumes_with_options(
                &volumes,
                ArchiveReadOptions::new().with_rar50_buffered_decode_limit(512 * 1024 * 1024),
            )
            .unwrap();
            let policies = [
                // Tiny allowance: nothing admits flat, workers shed to 1.
                Rar50ExecutionPolicy {
                    working_memory_limit: 1 << 20,
                    flat_output_limit: 0,
                    max_workers: 1,
                },
                // Flat allowed but only two workers.
                Rar50ExecutionPolicy {
                    working_memory_limit: 1 << 30,
                    flat_output_limit: 512 << 20,
                    max_workers: 2,
                },
                // Generous: everything admitted.
                Rar50ExecutionPolicy::from_working_memory(4 << 30),
            ];
            for policy in policies {
                let got = collect_volumes_with_options(
                    &volumes,
                    ArchiveReadOptions::new()
                        .with_rar50_buffered_decode_limit(512 * 1024 * 1024)
                        .with_rar50_execution_policy(policy),
                )
                .unwrap();
                assert_eq!(got, baseline, "{fixture} diverged under {policy:?}");
            }
        }
    }

    /// A mixed set (a solid archive alongside a poolable non-solid one) used
    /// to lose the member pool entirely - one solid volume disabled it for
    /// the whole set. Now the non-solid volume pools, the solid volume
    /// chains inside the pooled coordinator, and the result must match the
    /// per-archive extractions exactly, in both volume orders and in both
    /// chain modes (streaming under the tiny cfg(test) limit, flat under a
    /// large one).
    #[test]
    fn mixed_solid_and_pooled_set_extracts_both_fast_paths() {
        let pool = ArchiveReader::read_path(rar50_fixture("pool_members.rar")).unwrap();
        let solid = ArchiveReader::read_path(rar50_fixture("solid.rar")).unwrap();
        let per_archive = |archive: &Archive| -> Vec<(Vec<u8>, Vec<u8>)> {
            collect_extract(archive, None)
                .unwrap()
                .into_iter()
                .map(|e| (e.name, e.data))
                .collect()
        };
        let pool_expected = per_archive(&pool);
        let solid_expected = per_archive(&solid);

        for (volumes, expected) in [
            (
                vec![
                    ArchiveReader::read_path(rar50_fixture("pool_members.rar")).unwrap(),
                    ArchiveReader::read_path(rar50_fixture("solid.rar")).unwrap(),
                ],
                [pool_expected.clone(), solid_expected.clone()].concat(),
            ),
            (
                vec![
                    ArchiveReader::read_path(rar50_fixture("solid.rar")).unwrap(),
                    ArchiveReader::read_path(rar50_fixture("pool_members.rar")).unwrap(),
                ],
                [solid_expected.clone(), pool_expected.clone()].concat(),
            ),
        ] {
            for limit in [512 * 1024u64, 512 * 1024 * 1024] {
                let got = collect_volumes_with_options(
                    &volumes,
                    ArchiveReadOptions::new().with_rar50_buffered_decode_limit(limit),
                )
                .unwrap();
                assert_eq!(got, expected, "mixed set diverged at limit {limit}");
            }
        }
    }

    /// Corruption differential: flipping a byte at several positions in the
    /// archive must produce the SAME outcome (same output, or same first
    /// error in archive order) from the pooled and serial paths.
    #[test]
    fn pooled_volume_extract_error_parity_on_corruption() {
        let clean = std::fs::read(rar50_fixture("pool_members.rar")).unwrap();
        let mut compared = 0usize;
        for pos in (clean.len() / 8..clean.len()).step_by(clean.len() / 12) {
            let mut bytes = clean.clone();
            bytes[pos] ^= 0xFF;
            // Parsing is shared by both paths; a parse error is parity too.
            let Ok(archive) = ArchiveReader::read_owned(bytes) else {
                continue;
            };
            let volumes = vec![archive];
            let pooled = collect_volumes_with_options(
                &volumes,
                ArchiveReadOptions::new().with_rar50_buffered_decode_limit(512 * 1024),
            );
            let serial = collect_volumes_with_options(
                &volumes,
                ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0),
            );
            match (pooled, serial) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "outputs diverged at flip {pos}"),
                (Err(a), Err(b)) => {
                    assert_eq!(a.to_string(), b.to_string(), "errors diverged at flip {pos}");
                }
                (a, b) => panic!(
                    "outcome diverged at flip {pos}: pooled {:?} vs serial {:?}",
                    a.map(|v| v.len()),
                    b.map(|v| v.len())
                ),
            }
            compared += 1;
        }
        assert!(compared >= 4, "too few comparable corruptions ({compared})");
    }
}
