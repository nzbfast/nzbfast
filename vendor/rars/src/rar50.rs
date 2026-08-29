use crate::crc32::crc32;
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys};
use crate::detect::{find_archive_start, ArchiveSignature, RAR50_SIGNATURE, SFX_SCAN_LIMIT};
use crate::error::{Error, Result};
use crate::io_util::{align16 as checked_align16, read_exact_at, read_u32};
pub(crate) use crate::source::ArchiveSource;
use crate::version::ArchiveFamily;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

mod blake2sp;
mod extract;
mod write;

pub use extract::{
    extract_volume_sequence_to, extract_volume_sequence_to_with_progress, extract_volumes_to,
    extract_volumes_to_with_progress, extract_volumes_to_with_redirections,
};
pub use write::{
    ArchiveMetadataEntry, CompressedEntry, EncryptedArchiveCommentEntry, EncryptedCompressedEntry,
    EncryptedStoredEntry, EncryptedStoredEntryWithServices, EncryptedStoredServiceEntry,
    FilterKind, FilterPolicy, Rar50VolumeWriter, Rar50Writer, StoredEntry, StoredEntryWithServices,
    StoredServiceEntry, WriterOptions,
};

const HEAD_MAIN: u64 = 1;
const HEAD_FILE: u64 = 2;
const HEAD_SERVICE: u64 = 3;
const HEAD_CRYPT: u64 = 4;
const HEAD_END: u64 = 5;
const REV5_SIGNATURE: &[u8] = b"Rar!\x1aRev";

const HFL_EXTRA: u64 = 0x0001;
const HFL_DATA: u64 = 0x0002;
const HFL_SPLIT_BEFORE: u64 = 0x0008;
const HFL_SPLIT_AFTER: u64 = 0x0010;

const MHFL_VOLUME: u64 = 0x0001;
const MHFL_VOLUME_NUMBER: u64 = 0x0002;
const MHFL_SOLID: u64 = 0x0004;
const MHFL_RECOVERY: u64 = 0x0008;
const MHFL_LOCKED: u64 = 0x0010;

const FHFL_DIRECTORY: u64 = 0x0001;
const FHFL_MTIME: u64 = 0x0002;
const FHFL_CRC32: u64 = 0x0004;

const MHEXTRA_LOCATOR: u64 = 0x01;
const MHEXTRA_LOCATOR_QUICK_OPEN: u64 = 0x0001;
const MHEXTRA_LOCATOR_RECOVERY: u64 = 0x0002;

const FHEXTRA_CRYPT: u64 = 0x01;
const FHEXTRA_HASH: u64 = 0x02;
const FHEXTRA_REDIR: u64 = 0x05;
const FHEXTRA_SUBDATA: u64 = 0x07;
const MHEXTRA_ARCHIVE_METADATA: u64 = 0x02;
const MHEXTRA_ARCHIVE_METADATA_NAME: u64 = 0x0001;
const MHEXTRA_ARCHIVE_METADATA_TIME: u64 = 0x0002;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Archive {
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub blocks: Vec<Block>,
    source: ArchiveSource,
    /// Where the header walk stopped because the next block header sat
    /// beyond the bytes that had arrived, or `None` when `blocks` is the
    /// whole archive. Only [`Archive::parse_stream_incremental`] ever
    /// sets it; [`Archive::enumerate_rest`] clears it.
    pending: Option<PendingWalk>,
}

/// A header walk stopped at the arrival frontier, with what resuming it
/// needs. The walk RESUMES at `from` rather than starting over: on a
/// chased volume the caller has, by the time the rest is wanted, released
/// every byte behind the engine's watermark (that release is the whole
/// point of the incremental parse), so a re-walk from the signature reads
/// into bytes that are gone - measured 23 Aug 2026 as `chase source read
/// 8 behind the trim point` on every leg of the set the parse was built
/// for, 2.002x -> 3.001x. The stop offset is the end of the last block's
/// data area, which is at or above any watermark the engine can have
/// published for that block, so a resumed read never crosses the trim.
/// The header-encryption keys are the one piece of walk state a resume
/// cannot re-derive, because the HEAD_CRYPT block that carries their salt
/// sits at offset 8 - behind the trim. Boxed for the reason the key cache
/// gives: moving the archive must not memcpy AES keys around the heap.
#[derive(Debug, Clone)]
struct PendingWalk {
    from: usize,
    header_keys: Option<Box<Rar50Keys>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MainHeader {
    pub block: BlockHeader,
    pub archive_flags: u64,
    pub volume_number: Option<u64>,
    pub extras: Vec<MainExtraRecord>,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.archive_flags & MHFL_VOLUME != 0
    }

    pub fn is_solid(&self) -> bool {
        self.archive_flags & MHFL_SOLID != 0
    }

    pub fn has_recovery_record(&self) -> bool {
        self.archive_flags & MHFL_RECOVERY != 0
    }

    pub fn is_locked(&self) -> bool {
        self.archive_flags & MHFL_LOCKED != 0
    }

    pub fn locator(&self) -> Option<&LocatorRecord> {
        self.extras.iter().find_map(|record| match record {
            MainExtraRecord::Locator(locator) => Some(locator),
            _ => None,
        })
    }

    pub fn archive_metadata(&self) -> Option<&ArchiveMetadataRecord> {
        self.extras.iter().find_map(|record| match record {
            MainExtraRecord::ArchiveMetadata(metadata) => Some(metadata),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MainExtraRecord {
    Locator(LocatorRecord),
    ArchiveMetadata(ArchiveMetadataRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LocatorRecord {
    pub flags: u64,
    pub quick_open_offset: Option<u64>,
    pub recovery_record_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveMetadataRecord {
    pub flags: u64,
    pub name: Option<Vec<u8>>,
    pub creation_time: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Block {
    File(FileHeader),
    Service(FileHeader),
    End(BlockHeader),
    Unknown(BlockHeader),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockHeader {
    pub header_crc: u32,
    pub header_size: u64,
    pub header_type: u64,
    pub flags: u64,
    pub extra_area_size: Option<u64>,
    pub data_size: Option<u64>,
    pub offset: usize,
    // Type-specific header bytes are archive-relative. Payload bytes are
    // source-absolute so SFX-prefixed archives can be read directly.
    pub header_range: Range<usize>,
    pub data_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHeader {
    pub block: BlockHeader,
    pub file_flags: u64,
    pub unpacked_size: u64,
    pub attributes: u64,
    pub mtime: Option<u32>,
    pub data_crc32: Option<u32>,
    pub compression_info: u64,
    pub host_os: u64,
    pub name: Vec<u8>,
    pub hash: Option<FileHash>,
    pub redirection: Option<FileRedirection>,
    pub service_data: Option<Vec<u8>>,
    pub encrypted: bool,
    pub encryption: Option<FileEncryption>,
    crypto: Option<FileCryptoState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileRedirection {
    pub redirection_type: u64,
    pub flags: u64,
    pub target_name: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHash {
    pub hash_type: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryRecord {
    pub percent: u64,
    pub payload_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileEncryption {
    pub version: u64,
    pub flags: u64,
    pub kdf_count: u8,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    pub check_value: Option<[u8; 12]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileCryptoState {
    keys: Rar50Keys,
    iv: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rev5Volume {
    pub version: u8,
    pub data_count: u16,
    pub recovery_count: u16,
    pub recovery_number: u16,
    pub payload_crc32: u32,
    pub payload_size: u64,
    pub payload: Vec<u8>,
    pub data_volumes: Vec<Rev5DataVolume>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rev5VolumeMeta {
    pub version: u8,
    pub data_count: u16,
    pub recovery_count: u16,
    pub recovery_number: u16,
    pub payload_crc32: u32,
    pub payload_size: u64,
    pub data_volumes: Vec<Rev5DataVolume>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rev5DataVolume {
    pub file_size: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CompressionInfo {
    pub algorithm_version: u8,
    pub solid: bool,
    pub method: u8,
    pub dictionary_power: u8,
    pub dictionary_fraction: u8,
    pub rar5_compat: bool,
    pub dictionary_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub attr: u64,
    pub host_os: u64,
    pub is_directory: bool,
    /// The entry's declared unpacked size, 0 for a directory. Every
    /// fragment of a split member repeats the member's total, so a
    /// caller that opens the sink at the Start fragment still learns the
    /// whole size.
    ///
    /// Carried here rather than left to the caller to read off the parsed
    /// headers, because a chasing caller may not have it to read: a
    /// volume parsed by [`Archive::parse_stream_incremental`] enumerates
    /// only as far as its bytes had arrived, so the entry the engine asks
    /// to open can be one that caller has never seen.
    pub unpacked_size: u64,
}

impl FileHeader {
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the file name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    pub fn is_split_before(&self) -> bool {
        self.block.flags & HFL_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.block.flags & HFL_SPLIT_AFTER != 0
    }

    pub fn is_directory(&self) -> bool {
        self.file_flags & FHFL_DIRECTORY != 0
    }

    pub fn is_stored(&self) -> bool {
        compression_method(self.compression_info) == 0
    }

    pub fn is_redirection(&self) -> bool {
        self.redirection.is_some()
    }

    pub fn decoded_compression_info(&self) -> Result<CompressionInfo> {
        decode_compression_info(self.compression_info)
    }

    pub fn packed_size(&self) -> u64 {
        self.block.data_size.unwrap_or(0)
    }

    pub fn packed_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        archive.read_range(self.block.data_range.clone())
    }

    pub fn verify_crc32(&self, data: &[u8]) -> Result<()> {
        let Some(expected) = self.data_crc32 else {
            return Ok(());
        };
        if self.uses_hash_mac() {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted CRC32 verification needs encryption keys",
            ));
        }
        let actual = crc32(data);
        if actual == expected {
            Ok(())
        } else {
            Err(Error::Crc32Mismatch { expected, actual })
        }
    }

    pub fn verify_hash(&self, data: &[u8]) -> Result<()> {
        let Some(hash) = &self.hash else {
            return Ok(());
        };
        if self.uses_hash_mac() {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted hash verification needs encryption keys",
            ));
        }
        match hash.hash_type {
            0 if hash.data.len() == 32 => {
                let actual = blake2sp::hash(data);
                if hash.data == actual {
                    Ok(())
                } else {
                    Err(Error::HashMismatch { hash_type: 0 })
                }
            }
            0 => Err(Error::InvalidHeader(
                "RAR 5 BLAKE2sp hash record has invalid length",
            )),
            _ => Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 unknown file hash type",
            }),
        }
    }

    pub fn verify_integrity(&self, data: &[u8]) -> Result<()> {
        self.verify_crc32(data)?;
        self.verify_hash(data)
    }

    fn uses_hash_mac(&self) -> bool {
        self.encryption
            .as_ref()
            .is_some_and(|encryption| encryption.flags & 0x0002 != 0)
    }

    pub fn recovery_record(&self) -> Result<Option<RecoveryRecord>> {
        if self.name != b"RR" {
            return Ok(None);
        }
        let Some(data) = &self.service_data else {
            return Err(Error::InvalidHeader(
                "RAR 5 recovery service is missing service data",
            ));
        };
        let (percent, len) = read_vint_at(data, 0, data.len())?;
        if len != data.len() {
            return Err(Error::InvalidHeader(
                "RAR 5 recovery service data has trailing bytes",
            ));
        }
        Ok(Some(RecoveryRecord {
            percent,
            payload_size: self.packed_size(),
        }))
    }
}

impl Archive {
    pub fn parse(input: &[u8]) -> Result<Self> {
        Self::parse_with_options(input, crate::ArchiveReadOptions::default())
    }

    pub fn parse_owned(input: Vec<u8>) -> Result<Self> {
        Self::parse_owned_with_options(input, crate::ArchiveReadOptions::default())
    }

    pub fn parse_with_options(
        input: &[u8],
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        let data: Arc<[u8]> = Arc::from(input.to_vec().into_boxed_slice());
        Self::parse_shared(data, options.password)
    }

    pub fn parse_owned_with_options(
        input: Vec<u8>,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        Self::parse_shared(Arc::from(input.into_boxed_slice()), options.password)
    }

    pub fn parse_with_password(input: &[u8], password: Option<&[u8]>) -> Result<Self> {
        Self::parse_with_options(
            input,
            crate::ArchiveReadOptions::with_optional_password(password),
        )
    }

    pub fn parse_owned_with_password(input: Vec<u8>, password: Option<&[u8]>) -> Result<Self> {
        Self::parse_owned_with_options(
            input,
            crate::ArchiveReadOptions::with_optional_password(password),
        )
    }

    pub fn parse_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::parse_path_with_options(path, crate::ArchiveReadOptions::default())
    }

    pub fn parse_path_with_options(
        path: impl AsRef<Path>,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        Self::parse_path_with_password(path, options.password)
    }

    pub fn parse_path_with_password(
        path: impl AsRef<Path>,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        let path = Arc::new(path.as_ref().to_path_buf());
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        let scan_len = len.min(SFX_SCAN_LIMIT as u64) as usize;
        let mut scan = vec![0; scan_len];
        file.read_exact(&mut scan)?;
        let sig = find_archive_start(&scan, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedSignature);
        }
        let archive_len = usize::try_from(len)
            .map_err(|_| Error::InvalidHeader("RAR 5 archive size overflows usize"))?
            .checked_sub(sig.offset)
            .ok_or(Error::TooShort)?;
        Self::parse_file_backed(
            &mut file,
            archive_len,
            sig.offset,
            ArchiveSource::File(path),
            password,
            &mut Rar50KeyCache::default(),
        )
    }

    pub fn parse_path_with_signature(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        Self::parse_path_with_signature_and_password(path, signature, options.password)
    }

    pub fn parse_path_with_signature_and_password(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        Self::parse_path_with_signature_in_session(
            path,
            signature,
            password,
            &mut Rar50KeyCache::default(),
        )
    }

    /// Like [`Self::parse_path_with_signature_and_password`], with the key
    /// derivation cache supplied by the caller - a multi-volume set parsed
    /// through one session derives each (salt, kdf count) once instead of
    /// once per volume (the PBKDF2 ladder dwarfs the parse itself on
    /// 500-volume encrypted sets).
    pub(crate) fn parse_path_with_signature_in_session(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        password: Option<&[u8]>,
        key_cache: &mut Rar50KeyCache,
    ) -> Result<Self> {
        if signature.family != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedSignature);
        }
        let path = Arc::new(path.as_ref().to_path_buf());
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        let archive_len = usize::try_from(len)
            .map_err(|_| Error::InvalidHeader("RAR 5 archive size overflows usize"))?
            .checked_sub(signature.offset)
            .ok_or(Error::TooShort)?;
        Self::parse_file_backed(
            &mut file,
            archive_len,
            signature.offset,
            ArchiveSource::File(path),
            password,
            key_cache,
        )
    }

    fn parse_shared(input: Arc<[u8]>, password: Option<&[u8]>) -> Result<Self> {
        let sig = find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedSignature);
        }
        let archive = input.get(sig.offset..).ok_or(Error::TooShort)?;
        let mut parsed = Self::parse_seekable(
            archive,
            sig.offset,
            ArchiveSource::Memory(Arc::clone(&input)),
            password,
        )?;
        parsed.sfx_offset = sig.offset;
        Ok(parsed)
    }

    fn parse_seekable(
        input: &[u8],
        sfx_offset: usize,
        source: ArchiveSource,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        if !input.starts_with(RAR50_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let archive_len = input.len();
        let mut key_cache = Rar50KeyCache::default();
        let (main, blocks, _) = parse_archive_blocks(
            archive_len,
            password,
            &mut key_cache,
            |offset| parse_block_header_bytes(input, offset, archive_len, sfx_offset),
            |offset, keys| {
                parse_encrypted_block_header_bytes(input, offset, archive_len, sfx_offset, keys)
            },
            None,
        )?;

        Ok(Self {
            sfx_offset,
            main,
            blocks,
            source,
            pending: None,
        })
    }

    /// Parses an archive whose bytes are still arriving.
    ///
    /// `expected_len` is the archive's final size (the caller knows it up
    /// front, e.g. from an enclosing container's headers) and bounds every
    /// read; the source only needs to deliver bytes toward it. Reads BLOCK
    /// at the data frontier, so this call, and any later extraction from
    /// the returned archive, waits for missing bytes instead of failing.
    ///
    /// Parse strategy: header enumeration runs as one blocking forward walk
    /// over the same source ("blocking parse") rather than as a resumable
    /// incremental parser. Each member's header precedes its data and the
    /// walk skips data areas arithmetically, so the parse cursor trails the
    /// arrival frontier by design and completes once the end header (at the
    /// archive tail) is readable - i.e. when this volume has fully arrived.
    ///
    /// Concurrency story: `parse_stream` therefore returns when THIS volume
    /// is complete, and chasing happens at volume granularity. A caller
    /// feeding a multivolume set parses volume k+1 (blocking on its arrival)
    /// while members of volumes 1..=k, already parsed, extract through the
    /// same blocking sources - see `extract_volume_sequence_to`. **A caller
    /// that holds the arrivals in memory should not use this**: waiting for
    /// the tail pins the whole volume before the engine reads a byte, which
    /// is a hard floor on retention of one volume and was measured costing a
    /// chase its whole set. [`Self::parse_stream_incremental`] is that
    /// caller's entry point. Sources
    /// that expose header ranges ahead of a not-yet-complete data area
    /// (e.g. a hole awaiting repair) additionally block the member DATA
    /// reads at the hole while parse and other members proceed.
    ///
    /// The archive signature must sit at offset 0: streaming sources carry
    /// payloads whose start is already known, so no SFX stub scan is done.
    pub fn parse_stream(
        source: std::sync::Arc<dyn crate::source::BlockingRangeSource>,
        expected_len: u64,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        Self::parse_stream_impl(source, expected_len, options, false)
    }

    /// [`Self::parse_stream`] that does NOT wait for the volume's tail.
    ///
    /// The blocking parse above completes only once the END header at the
    /// archive tail is readable, because the walk skips each member's data
    /// area arithmetically and the next header therefore sits a whole
    /// member ahead. On a volume still arriving that means the WHOLE
    /// volume: a caller holding the arrivals in RAM pins every byte of it
    /// before the engine reads one. Measured 22 Aug 2026 on a compressed
    /// set whose volumes were larger than the caller's retention budget,
    /// the budget broke during that wait, with no packed byte read and so
    /// no consumption watermark published at all - the set could not be
    /// chased at any budget under the volume size, at any arrival rate,
    /// and quartering the line rate changed nothing.
    ///
    /// So this stops the header walk where the arrived bytes stop and
    /// reports the archive PARTIALLY ENUMERATED
    /// ([`Self::is_partially_enumerated`]). What comes back is every
    /// entry that could be read without waiting - on a chased volume,
    /// the split fragment the engine is about to decode.
    /// [`Self::enumerate_rest`] finishes the walk, blocking, and is what
    /// a caller must call before treating `files()` as the whole volume.
    /// [`extract_volume_sequence_to_with_progress`] does exactly that, at
    /// the point its walk runs past the entries it has - by which time
    /// the fragment has decoded and the caller has released its bytes, so
    /// the deferred wait costs no retention.
    ///
    /// [`extract_volume_sequence_to_with_progress`]: crate::rar50::extract_volume_sequence_to_with_progress
    pub fn parse_stream_incremental(
        source: std::sync::Arc<dyn crate::source::BlockingRangeSource>,
        expected_len: u64,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        Self::parse_stream_impl(source, expected_len, options, true)
    }

    fn parse_stream_impl(
        source: std::sync::Arc<dyn crate::source::BlockingRangeSource>,
        expected_len: u64,
        options: crate::ArchiveReadOptions<'_>,
        incremental: bool,
    ) -> Result<Self> {
        let archive_len = usize::try_from(expected_len)
            .map_err(|_| Error::InvalidHeader("RAR 5 archive size overflows host address size"))?;
        let frontier = source.clone();
        let source = ArchiveSource::Stream {
            source,
            len: archive_len,
        };
        let signature = source.read_range(0..RAR50_SIGNATURE.len())?;
        if signature != *RAR50_SIGNATURE {
            return Err(Error::UnsupportedSignature);
        }
        let password = options.password;
        let mut key_cache = Rar50KeyCache::default();
        // Clamped to the declared length: a source reporting more arrived
        // than the volume holds must not lift the stop above the walk's
        // own bound.
        let arrived = move || frontier.known_len().min(expected_len) as usize;
        let (main, blocks, pending) = parse_archive_blocks(
            archive_len,
            password,
            &mut key_cache,
            |offset| read_block_header_from_source(&source, offset, archive_len, 0),
            |offset, keys| {
                read_encrypted_block_header_from_source(&source, offset, archive_len, 0, keys)
            },
            incremental.then_some(&arrived as &dyn Fn() -> usize),
        )?;

        Ok(Self {
            sfx_offset: 0,
            main,
            blocks,
            source,
            pending,
        })
    }

    /// Has the header walk stopped short of the archive's end because the
    /// bytes it would have to read had not arrived? See
    /// [`Self::parse_stream_incremental`]; false for every other parse.
    pub fn is_partially_enumerated(&self) -> bool {
        self.pending.is_some()
    }

    /// Finish a walk [`Self::parse_stream_incremental`] stopped early,
    /// BLOCKING on the bytes it needs, and leave the archive fully
    /// enumerated. A no-op on any other archive.
    ///
    /// Resumes at the stop offset and APPENDS to `blocks`, so the entries
    /// already enumerated keep their indices and a caller's
    /// `(volume, file_index)` pairs stay valid - and nothing behind the
    /// stop is read again, which is what lets a caller that has released
    /// those bytes call this at all (see [`PendingWalk`]).
    pub fn enumerate_rest(&mut self, password: Option<&[u8]>) -> Result<()> {
        self.resume_walk(password, None)
    }

    /// Walk ONE step past the stop: read the header at the stop offset,
    /// blocking on it, then carry on up to the arrival frontier exactly
    /// as the incremental parse does. For a caller that needs the NEXT
    /// entry of a still-arriving volume (a split continuation) without
    /// waiting for the volume's tail - which [`Self::enumerate_rest`]
    /// would, pinning the whole volume, the wait the incremental parse
    /// exists to avoid. A no-op on a fully enumerated archive.
    pub fn enumerate_next(&mut self, password: Option<&[u8]>) -> Result<()> {
        let frontier = match &self.source {
            ArchiveSource::Stream { source, len } => {
                let len = *len;
                let source = source.clone();
                move || (source.known_len() as usize).min(len)
            }
            // Unreachable: only the streaming parse stops early.
            _ => return Ok(()),
        };
        self.resume_walk(password, Some(&frontier as &dyn Fn() -> usize))
    }

    fn resume_walk(
        &mut self,
        password: Option<&[u8]>,
        arrived: Option<&dyn Fn() -> usize>,
    ) -> Result<()> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        let archive_len = match &self.source {
            ArchiveSource::Stream { len, .. } => *len,
            // Unreachable: only the streaming parse stops early.
            _ => return Ok(()),
        };
        let source = &self.source;
        let mut key_cache = Rar50KeyCache::default();
        let mut blocks = std::mem::take(&mut self.blocks);
        let walked = walk_archive_blocks(
            pending.from,
            archive_len,
            password,
            &mut key_cache,
            pending.header_keys.as_deref(),
            |offset| read_block_header_from_source(source, offset, archive_len, 0),
            |offset, keys| {
                read_encrypted_block_header_from_source(source, offset, archive_len, 0, keys)
            },
            arrived,
            &mut blocks,
            // The header at the stop offset is what the caller came for:
            // a bounded resume reads it unconditionally and lets the
            // frontier stop the walk only after it.
            arrived.is_some(),
        );
        self.blocks = blocks;
        let stopped = walked?;
        debug_assert!(
            arrived.is_some() || stopped.is_none(),
            "an unbounded walk cannot stop short"
        );
        self.pending = stopped.map(|from| PendingWalk {
            from,
            header_keys: pending.header_keys,
        });
        Ok(())
    }

    fn parse_file_backed(
        file: &mut File,
        archive_len: usize,
        sfx_offset: usize,
        source: ArchiveSource,
        password: Option<&[u8]>,
        key_cache: &mut Rar50KeyCache,
    ) -> Result<Self> {
        let signature = read_exact_at(file, sfx_offset, RAR50_SIGNATURE.len())?;
        if signature != *RAR50_SIGNATURE {
            return Err(Error::UnsupportedSignature);
        }

        let file_cell = std::cell::RefCell::new(file);
        let (main, blocks, _) = parse_archive_blocks(
            archive_len,
            password,
            key_cache,
            |offset| {
                read_block_header_at(&mut file_cell.borrow_mut(), offset, archive_len, sfx_offset)
            },
            |offset, keys| {
                read_encrypted_block_header_at(
                    &mut file_cell.borrow_mut(),
                    offset,
                    archive_len,
                    sfx_offset,
                    keys,
                )
            },
            None,
        )?;

        Ok(Self {
            sfx_offset,
            main,
            blocks,
            source,
            pending: None,
        })
    }

    fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>> {
        self.source.read_range(range)
    }

    fn source_len(&self) -> Result<usize> {
        self.source.len()
    }

    fn range_reader(&self, range: Range<usize>) -> Result<Box<dyn Read + Send + '_>> {
        self.source.range_reader(range)
    }

    /// [`Self::range_reader`] with no borrow of this archive - the growing
    /// split chain needs a cursor that outlives a `Vec<Archive>` push.
    pub(crate) fn owned_range_reader(
        &self,
        range: Range<usize>,
    ) -> Result<crate::source::OwnedRangeReader> {
        self.source.owned_range_reader(range)
    }

    fn copy_range_to(&self, range: Range<usize>, writer: &mut dyn Write) -> Result<()> {
        let source_len = self.source_len()?;
        if range.start > range.end || range.end > source_len {
            return Err(Error::InvalidHeader("RAR 5 repair range is out of bounds"));
        }
        let mut reader = self.range_reader(range)?;
        std::io::copy(&mut reader, writer)?;
        Ok(())
    }

    pub fn files(&self) -> impl Iterator<Item = &FileHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::File(file) => Some(file),
            _ => None,
        })
    }

    pub fn services(&self) -> impl Iterator<Item = &FileHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::Service(service) => Some(service),
            _ => None,
        })
    }

    /// Decodes the archive-level `CMT` service payload, if any.
    ///
    /// RAR 5 stores comments as `Service` blocks named `CMT`. Archive-level
    /// comments appear before any `File` block; service blocks attached to a
    /// specific file follow that file. This returns only the former.
    pub fn archive_comment(&self) -> Result<Option<Vec<u8>>> {
        self.archive_comment_with_password(None)
    }

    /// Same as [`Self::archive_comment`] but supplies a password for
    /// individually-encrypted comment services.
    pub fn archive_comment_with_password(
        &self,
        password: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        for block in &self.blocks {
            match block {
                Block::File(_) => return Ok(None),
                Block::Service(service) if service.name == b"CMT" => {
                    return service.decoded_data_unverified(self, password).map(Some);
                }
                _ => {}
            }
        }
        Ok(None)
    }

    pub fn repair_recovery(&self) -> Result<Vec<u8>> {
        let mut repaired = Vec::new();
        self.repair_recovery_to(&mut repaired)?;
        Ok(repaired)
    }

    pub fn repair_recovery_to(&self, writer: &mut dyn Write) -> Result<()> {
        // No caller budget: the archive's own size remains the only bound on
        // the recovery-record decode, which is what this API has always done.
        self.repair_recovery_to_within(writer, None, u64::MAX)
    }

    /// [`Self::repair_recovery_to`] held to a working-memory budget.
    ///
    /// This form still materializes each repaired shard, so its working set
    /// is `damaged * group_count` - for a 20 GB volume split 200 ways that
    /// is 100 MB per damaged shard. It is kept for callers that only have a
    /// `Write` sink; anything volume-sized should use
    /// [`Self::repair_recovery_to_file`], which patches a seekable
    /// destination in place and needs only a stripe.
    pub fn repair_recovery_to_within(
        &self,
        writer: &mut dyn Write,
        password: Option<&[u8]>,
        budget: u64,
    ) -> Result<()> {
        let recovery = self
            .services()
            .find(|service| matches!(service.recovery_record(), Ok(Some(_))))
            .ok_or(Error::InvalidHeader(
                "RAR 5 archive does not contain an inline recovery record",
            ))?;
        let prefix_start = self.sfx_offset;
        let prefix_end = recovery
            .block
            .offset
            .checked_sub(prefix_start)
            .and_then(|relative| prefix_start.checked_add(relative))
            .ok_or(Error::InvalidHeader(
                "RAR 5 recovery prefix range overflows archive bounds",
            ))?;
        let source_len = self.source_len()?;
        if prefix_end > source_len {
            return Err(Error::InvalidHeader(
                "RAR 5 recovery prefix is out of bounds",
            ));
        }
        // A recovery record protects a prefix of THIS archive, so its decoded
        // size cannot legitimately exceed the archive holding it - a bound we
        // already have on hand, and one no real record comes close to (parity
        // is a percentage of the protected prefix, not a multiple of it).
        //
        // Without it this decode is unbounded: `decoded_data_unverified`
        // buffers the whole packed member and grows its output to the
        // service's own declared `unpacked_size`, consulting neither the
        // buffered-decode limit nor the window limit that ordinary extraction
        // applies, and never reaching `BombGuardWriter` at all. A small
        // parseable archive carrying a compressible `RR` service that claims
        // gigabytes therefore aborts the process - reached automatically,
        // because RR repair is what runs after an extraction failure.
        let recovery_data = recovery
            .decoded_data_unverified_bounded(self, password, (source_len as u64).min(budget))
            .map_err(|error| error.at_entry(recovery.name.clone(), "reading recovery data"))?;
        let prefix_len = prefix_end
            .checked_sub(prefix_start)
            .ok_or(Error::InvalidHeader(
                "RAR 5 recovery prefix range overflows archive bounds",
            ))?;
        let repaired_shards = crate::recovery::rar5::repair_inline_recovery_prefix_shards(
            prefix_len,
            &recovery_data,
            |range| {
                let start = prefix_start
                    .checked_add(range.start)
                    .ok_or(crate::recovery::rar5::Error::PlanOverflow)?;
                let end = prefix_start
                    .checked_add(range.end)
                    .ok_or(crate::recovery::rar5::Error::PlanOverflow)?;
                self.read_range(start..end)
                    .map_err(|_| crate::recovery::rar5::Error::BadRecoveryChunk)
            },
        )?;

        self.copy_range_to(0..prefix_start, writer)?;
        let mut cursor = 0usize;
        for (range, data) in repaired_shards {
            if range.start < cursor || range.end > prefix_len || range.len() != data.len() {
                return Err(Error::InvalidHeader(
                    "RAR 5 recovery shard range is invalid",
                ));
            }
            self.copy_range_to(prefix_start + cursor..prefix_start + range.start, writer)?;
            writer.write_all(&data)?;
            cursor = range.end;
        }
        self.copy_range_to(prefix_start + cursor..prefix_end, writer)?;
        self.copy_range_to(prefix_end..source_len, writer)?;
        Ok(())
    }

    /// Repairs this archive's protected prefix into `dest`, streaming.
    ///
    /// `dest` receives a full copy of the archive and is then patched in
    /// place over the damaged shard ranges, so peak memory is a stripe of
    /// the caller's choosing rather than the volume. Nothing is written back
    /// to the archive itself - publishing the result is the caller's job,
    /// after whatever verification it wants.
    ///
    /// Returns the data-shard indices that were rebuilt (empty when the
    /// recovery record says the prefix is already intact).
    ///
    /// `RepairTooLarge` when `budget` cannot fund even a minimum stripe -
    /// the signal to report an unsupported repair rather than attempt one
    /// that would have to be unbounded.
    pub fn repair_recovery_to_file(
        &self,
        dest: &mut std::fs::File,
        password: Option<&[u8]>,
        budget: u64,
    ) -> Result<Vec<usize>> {
        self.repair_recovery_impl(dest, password, budget, false)
    }

    /// [`Self::repair_recovery_to_file`] for a caller that owns the
    /// destination PATH rather than an open handle.
    ///
    /// When the archive itself was opened from a file, the initial
    /// whole-volume copy becomes a filesystem clone where the platform
    /// supports one (APFS, btrfs/XFS reflink) - near-free instead of a
    /// full read+write. Any other source shape, and any box where the
    /// clone is unavailable, takes the same streaming copy as the file
    /// form.
    pub fn repair_recovery_to_path(
        &self,
        dest: &std::path::Path,
        password: Option<&[u8]>,
        budget: u64,
    ) -> Result<Vec<usize>> {
        use crate::recovery::stream;

        let prefilled = match &self.source {
            ArchiveSource::File(path) => stream::clone_prefill(path, dest)?,
            _ => false,
        };
        // O_NOFOLLOW (sweep 8, M10): a prefill that DECLINED leaves
        // whatever is at `dest` alone, so a plain open would hand the
        // streaming path the symlink escape the clone no longer has.
        let mut out = stream::open_repair_dest(dest)?;
        if !prefilled {
            out.set_len(0)?;
        }
        self.repair_recovery_impl(&mut out, password, budget, prefilled)
    }

    fn repair_recovery_impl(
        &self,
        dest: &mut std::fs::File,
        password: Option<&[u8]>,
        budget: u64,
        dest_prefilled: bool,
    ) -> Result<Vec<usize>> {
        use crate::recovery::stream;

        let recovery = self
            .services()
            .find(|service| matches!(service.recovery_record(), Ok(Some(_))))
            .ok_or(Error::InvalidHeader(
                "RAR 5 archive does not contain an inline recovery record",
            ))?;
        let prefix_start = self.sfx_offset as u64;
        let prefix_end = recovery.block.offset as u64;
        let source_len = self.source_len()? as u64;
        if prefix_end < prefix_start || prefix_end > source_len {
            return Err(Error::InvalidHeader(
                "RAR 5 recovery prefix is out of bounds",
            ));
        }
        let archive = ArchiveRangeSource(&self.source, source_len);

        // The recovery data is normally STORED, which means it is already
        // sitting in this file and can be read by range - no decode, no
        // buffer, no ceiling to trip. Only a compressed or encrypted record
        // has to be materialized, and that path is the bounded one.
        let (recovery_source, scan) = if recovery.is_stored() && !recovery.encrypted {
            let range = recovery.block.data_range.start as u64..recovery.block.data_range.end as u64;
            let scan = stream::scan_inline_recovery_chunks_in(&archive, range, budget)?;
            (None, scan)
        } else {
            // Two independent ceilings, and the tighter one wins. The
            // archive's own length is a CORRECTNESS bound - a recovery record
            // cannot legitimately be larger than the archive carrying it - and
            // it is what bounds the buffered path. The budget is an
            // affordability bound. Passing only the budget here would accept a
            // 2 MB archive declaring a 400 MB recovery service on any box
            // whose repair slice is that wide, which is exactly the ceiling
            // the buffered path already refuses.
            let data = recovery
                .decoded_data_unverified_bounded(self, password, source_len.min(budget))
                .map_err(|error| error.at_entry(recovery.name.clone(), "reading recovery data"))?;
            let source = stream::MemorySource(data);
            let scan = stream::scan_inline_recovery_chunks(&source, budget)?;
            (Some(source), scan)
        };

        let protected = scan
            .protected_size()
            .ok_or(Error::InvalidHeader("RAR 5 recovery record is unusable"))?;
        if protected != prefix_end - prefix_start {
            return Err(Error::InvalidHeader(
                "RAR 5 recovery record protects a different prefix than this archive has",
            ));
        }

        let parity: &dyn stream::RangeSource = match &recovery_source {
            Some(source) => source,
            None => &archive,
        };
        if dest_prefilled {
            stream::repair_prefix_streaming_prefilled(&archive, prefix_start, &scan, parity, dest, budget)
        } else {
            stream::repair_prefix_streaming(&archive, prefix_start, &scan, parity, dest, budget)
        }
    }
}

/// [`stream::RangeSource`] view over an already-parsed archive's backing
/// store, so the streaming repair reads through whatever the archive was
/// opened on (file, memory, or an arriving stream) without a second handle.
struct ArchiveRangeSource<'a>(&'a ArchiveSource, u64);

impl crate::recovery::stream::RangeSource for ArchiveRangeSource<'_> {
    fn len(&self) -> u64 {
        self.1
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.0.read_range_into(offset, buf)
    }
}

impl Rev5Volume {
    pub fn parse(input: &[u8]) -> Result<Self> {
        let (meta, payload_range) = Rev5VolumeMeta::parse_with_payload_range(input)?;
        let payload = &input[payload_range];
        let actual_payload_crc = crc32(payload);
        if actual_payload_crc != meta.payload_crc32 {
            return Err(Error::Crc32Mismatch {
                expected: meta.payload_crc32,
                actual: actual_payload_crc,
            });
        }

        Ok(Self {
            version: meta.version,
            data_count: meta.data_count,
            recovery_count: meta.recovery_count,
            recovery_number: meta.recovery_number,
            payload_crc32: meta.payload_crc32,
            payload_size: meta.payload_size,
            payload: payload.to_vec(),
            data_volumes: meta.data_volumes,
        })
    }
}

impl Rev5VolumeMeta {
    pub fn parse(input: &[u8]) -> Result<Self> {
        Self::parse_with_payload_range(input).map(|(meta, _)| meta)
    }

    fn parse_with_payload_range(input: &[u8]) -> Result<(Self, Range<usize>)> {
        if !input.starts_with(REV5_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }
        if input.len() < 16 {
            return Err(Error::TooShort);
        }
        let header_crc = read_u32(input, 8)?;
        let header_size = read_u32(input, 12)? as usize;
        if header_size <= 5 || header_size > 0x100000 {
            return Err(Error::InvalidHeader("RAR 5 REV header size is invalid"));
        }
        let header_end = 16usize
            .checked_add(header_size)
            .ok_or(Error::InvalidHeader("RAR 5 REV header size overflows"))?;
        if header_end > input.len() {
            return Err(Error::TooShort);
        }
        let actual_header_crc = crc32(&input[12..header_end]);
        if actual_header_crc != header_crc {
            return Err(Error::Crc32Mismatch {
                expected: header_crc,
                actual: actual_header_crc,
            });
        }

        let body = &input[16..header_end];
        if body.len() < 11 {
            return Err(Error::TooShort);
        }
        let mut reader = SliceReader::new(body, 0, body.len());
        let version = reader.read_byte()?;
        if version != 1 {
            return Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 REV version",
            });
        }
        let data_count = reader.read_u16()?;
        let recovery_count = reader.read_u16()?;
        let recovery_number = reader.read_u16()?;
        let payload_crc32 = reader.read_u32()?;
        let first_recovery_number = u32::from(data_count);
        let recovery_end = first_recovery_number + u32::from(recovery_count);
        let recovery_number = u32::from(recovery_number);
        if recovery_count == 0
            || recovery_number < first_recovery_number
            || recovery_number >= recovery_end
        {
            return Err(Error::InvalidHeader("RAR 5 REV volume number is invalid"));
        }
        // The same rules `StripeRepairPlan::new` enforces, applied where the
        // counts come off the wire so a hostile header dies at parse time.
        // `data_count` is deliberately NOT capped on its own: a large release
        // legitimately spans thousands of data volumes, and the repair cost
        // scales with the recovery/damage side, not the slot count. The two
        // together must still fit the GF(2^16) code word, which is the bound
        // no REV set - real or forged - can escape.
        if usize::from(recovery_count) > crate::recovery::rar5::MAX_RECONSTRUCTION_SHARDS {
            return Err(Error::InvalidHeader(
                "RAR 5 REV recovery volume count is implausibly large",
            ));
        }
        if usize::from(data_count) + usize::from(recovery_count)
            > crate::recovery::rar5::FIELD_SIZE
        {
            return Err(Error::InvalidHeader(
                "RAR 5 REV volume counts exceed the recovery field",
            ));
        }

        let expected_table_len = data_count as usize * 12;
        let expected_table_end =
            11usize
                .checked_add(expected_table_len)
                .ok_or(Error::InvalidHeader(
                    "RAR 5 REV metadata table size overflows",
                ))?;
        if body.len() < expected_table_end {
            return Err(Error::InvalidHeader(
                "RAR 5 REV metadata table size is invalid",
            ));
        }
        let mut data_volumes = Vec::with_capacity(data_count as usize);
        for _ in 0..data_count {
            let file_size = reader.read_u64()?;
            let crc = reader.read_u32()?;
            data_volumes.push(Rev5DataVolume {
                file_size,
                crc32: crc,
            });
        }

        Ok((
            Self {
                version,
                data_count,
                recovery_count,
                recovery_number: recovery_number as u16,
                payload_crc32,
                payload_size: (input.len() - header_end) as u64,
                data_volumes,
            },
            header_end..input.len(),
        ))
    }
}

impl From<&Rev5Volume> for Rev5VolumeMeta {
    fn from(volume: &Rev5Volume) -> Self {
        Self {
            version: volume.version,
            data_count: volume.data_count,
            recovery_count: volume.recovery_count,
            recovery_number: volume.recovery_number,
            payload_crc32: volume.payload_crc32,
            payload_size: volume.payload_size,
            data_volumes: volume.data_volumes.clone(),
        }
    }
}

impl From<Rev5Volume> for Rev5VolumeMeta {
    fn from(volume: Rev5Volume) -> Self {
        Self {
            version: volume.version,
            data_count: volume.data_count,
            recovery_count: volume.recovery_count,
            recovery_number: volume.recovery_number,
            payload_crc32: volume.payload_crc32,
            payload_size: volume.payload_size,
            data_volumes: volume.data_volumes,
        }
    }
}

pub fn repair_rev5_volumes_to<F>(
    data_volumes: &[Option<&[u8]>],
    recovery_volumes: &[Rev5Volume],
    mut write: F,
) -> Result<()>
where
    F: FnMut(usize, &[u8]) -> Result<()>,
{
    let first = recovery_volumes.first().ok_or(Error::InvalidHeader(
        "RAR 5 REV recovery volume set is empty",
    ))?;
    let data_count = usize::from(first.data_count);
    if data_volumes.len() != data_count {
        return Err(Error::InvalidHeader(
            "RAR 5 REV data volume count does not match metadata",
        ));
    }
    if recovery_volumes.iter().any(|rev| {
        rev.version != first.version
            || rev.data_count != first.data_count
            || rev.recovery_count != first.recovery_count
            || rev.data_volumes != first.data_volumes
            || rev.payload.len() != first.payload.len()
    }) {
        return Err(Error::InvalidHeader(
            "RAR 5 REV recovery volume metadata differs across files",
        ));
    }

    let mut shards = Vec::with_capacity(data_count);
    for (index, data) in data_volumes.iter().enumerate() {
        let Some(data) = data else {
            shards.push(None);
            continue;
        };
        let meta = &first.data_volumes[index];
        if data.len() as u64 != meta.file_size || crc32(data) != meta.crc32 {
            shards.push(None);
        } else {
            shards.push(Some(*data));
        }
    }

    let recovery_rows: Vec<_> = recovery_volumes
        .iter()
        .map(|rev| {
            let row = usize::from(rev.recovery_number)
                .checked_sub(data_count)
                .ok_or(Error::InvalidHeader("RAR 5 REV recovery number is invalid"))?;
            Ok((row, rev.payload.as_slice()))
        })
        .collect::<Result<_>>()?;
    let mut seen_recovery_rows = std::collections::HashSet::with_capacity(recovery_rows.len());
    if recovery_rows
        .iter()
        .any(|(row, _)| !seen_recovery_rows.insert(*row))
    {
        return Err(Error::InvalidHeader(
            "RAR 5 REV recovery volume set contains duplicate recovery rows",
        ));
    }
    let repaired = crate::recovery::rar5::reconstruct_data_shards(&shards, &recovery_rows)?;

    for (index, (mut shard, meta)) in repaired.into_iter().zip(&first.data_volumes).enumerate() {
        let file_size = usize::try_from(meta.file_size)
            .map_err(|_| Error::InvalidHeader("RAR 5 REV data volume size overflows usize"))?;
        if shard.len() < file_size {
            return Err(Error::InvalidHeader(
                "RAR 5 REV repaired shard is shorter than data volume size",
            ));
        }
        shard.truncate(file_size);
        let actual = crc32(&shard);
        if actual != meta.crc32 {
            return Err(Error::Crc32Mismatch {
                expected: meta.crc32,
                actual,
            });
        }
        write(index, &shard)?;
    }
    Ok(())
}

/// A `.rev` recovery volume located on disk: its metadata, and where its
/// payload lives - not the payload itself.
///
/// [`Rev5Volume`] carries `payload: Vec<u8>`, so reading a REV set meant
/// holding every recovery volume in RAM before a single byte was repaired.
/// A payload is one padded data-volume's worth, which for a 60x1 GB set is
/// 1 GB per `.rev`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rev5VolumeRef {
    pub meta: Rev5VolumeMeta,
    pub payload: Range<u64>,
}

impl Rev5VolumeRef {
    /// The recovery row this volume supplies, i.e. its index among the
    /// parity shards rather than among all shards.
    pub fn row(&self) -> Result<usize> {
        usize::from(self.meta.recovery_number)
            .checked_sub(usize::from(self.meta.data_count))
            .ok_or(Error::InvalidHeader("RAR 5 REV recovery number is invalid"))
    }
}

/// Reads a `.rev`'s metadata from a bounded prefix of the file.
///
/// The REV header is capped at 1 MiB by the format, so locating the payload
/// costs that at most - no matter how large the payload is.
pub fn read_rev5_meta(src: &dyn crate::recovery::stream::RangeSource) -> Result<Rev5VolumeRef> {
    let len = src.len();
    if len < 16 {
        return Err(Error::TooShort);
    }
    let mut head = [0u8; 16];
    src.read_at(0, &mut head)?;
    let header_size = read_u32(&head, 12)? as usize;
    if header_size <= 5 || header_size > 0x100000 {
        return Err(Error::InvalidHeader("RAR 5 REV header size is invalid"));
    }
    let header_end = 16usize
        .checked_add(header_size)
        .ok_or(Error::InvalidHeader("RAR 5 REV header size overflows"))?;
    if header_end as u64 > len {
        return Err(Error::TooShort);
    }
    // Parse the header exactly as the whole-file path does, by handing it a
    // buffer that ends where the payload begins. `parse_with_payload_range`
    // derives `payload_size` from the input length, so it is corrected below
    // against the file's real length.
    let mut header = vec![0u8; header_end];
    src.read_at(0, &mut header)?;
    let (mut meta, range) = Rev5VolumeMeta::parse_with_payload_range(&header)?;
    meta.payload_size = len - range.start as u64;
    Ok(Rev5VolumeRef {
        meta,
        payload: range.start as u64..len,
    })
}

/// Streams a `.rev`'s payload to confirm it matches the CRC32 its header
/// declares. A recovery volume that fails this cannot be trusted as an
/// equation and must be dropped before planning.
pub fn verify_rev5_payload(
    src: &dyn crate::recovery::stream::RangeSource,
    volume: &Rev5VolumeRef,
) -> Result<bool> {
    let mut crc = crate::crc32::Crc32::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut position = volume.payload.start;
    while position < volume.payload.end {
        // Clamp in u64 BEFORE narrowing: on a 32-bit target a remaining span
        // that is a multiple of 4 GiB casts to 0 and the loop never advances.
        // (nzbfast-local change, 27 Aug 2026 - re-apply on the next rars
        // re-sync, see vendor/rars/VENDORING.md.)
        let take = (volume.payload.end - position).min(buf.len() as u64) as usize;
        src.read_at(position, &mut buf[..take])?;
        crc.update(&buf[..take]);
        position += take as u64;
    }
    Ok(crc.finish() == volume.meta.payload_crc32)
}

/// The on-disk data volumes feeding a REV reconstruction: one entry per
/// declared slot, `None` where that volume is missing or failed the checksum
/// its metadata declares.
pub type Rev5DataSources<'a> = [Option<&'a dyn crate::recovery::stream::RangeSource>];

/// Receives rebuilt volume bytes as `(slot, offset, bytes)`, in ascending
/// offset order per slot, clipped to the slot's real file size.
pub type Rev5RebuildSink<'a> = dyn FnMut(usize, u64, &[u8]) -> Result<()> + 'a;

/// One recovery volume feeding a streaming REV reconstruction.
pub struct Rev5RecoverySource<'a> {
    pub row: usize,
    pub source: &'a dyn crate::recovery::stream::RangeSource,
    pub payload: Range<u64>,
}

/// Rebuilds missing data volumes from `.rev` recovery volumes in bounded
/// stripes.
///
/// `intact[i]` is the on-disk volume already verified against slot `i`, or
/// `None` when that slot must be rebuilt. Rebuilt bytes arrive through
/// `write(slot_index, offset, bytes)` in ascending offset order, clipped to
/// the slot's real file size so the code word's zero padding is not written
/// out. Nothing is retained between stripes.
///
/// Returns the slot indices that were rebuilt. The caller must CRC-verify
/// each one against its metadata before publishing it.
pub fn repair_rev5_volumes_streaming(
    slots: &[Rev5DataVolume],
    intact: &Rev5DataSources<'_>,
    recovery: &[Rev5RecoverySource<'_>],
    recovery_count: usize,
    budget: u64,
    write: &mut Rev5RebuildSink<'_>,
) -> Result<Vec<usize>> {
    use crate::recovery::rar5::{repair_shards_striped, StripeRepairPlan};

    if intact.len() != slots.len() {
        return Err(Error::InvalidHeader(
            "RAR 5 REV data volume count does not match metadata",
        ));
    }
    let missing: Vec<usize> = (0..slots.len()).filter(|&i| intact[i].is_none()).collect();
    if missing.is_empty() {
        return Ok(Vec::new());
    }

    // Feasibility before anything is planned or read: one distinct recovery
    // row rebuilds one missing volume, so more damage than equations is
    // unrepairable arithmetic. Duplicate rows collapse - the same .rev twice
    // is one equation - and would otherwise produce a singular system.
    let mut rows: Vec<usize> = recovery.iter().map(|source| source.row).collect();
    rows.sort_unstable();
    rows.dedup();
    if missing.len() > rows.len() {
        return Err(crate::recovery::rar5::Error::TooManyDamagedShards.into());
    }

    // Every payload is one padded shard; they must agree or the code word is
    // not well formed.
    let shard_len = recovery
        .first()
        .map(|source| source.payload.end - source.payload.start)
        .ok_or(crate::recovery::rar5::Error::TooManyDamagedShards)?;
    if recovery
        .iter()
        .any(|source| source.payload.end - source.payload.start != shard_len)
    {
        return Err(crate::recovery::rar5::Error::ShardSizeMismatch.into());
    }
    let shard_len_usize =
        usize::try_from(shard_len).map_err(|_| crate::recovery::rar5::Error::PlanOverflow)?;
    if slots
        .iter()
        .any(|slot| slot.file_size > shard_len)
    {
        return Err(crate::recovery::rar5::Error::ShardSizeMismatch.into());
    }

    // One equation per missing volume, lowest rows first so the choice is
    // deterministic across runs.
    let mut chosen: Vec<usize> = Vec::with_capacity(missing.len());
    let mut used = std::collections::HashSet::new();
    let mut order: Vec<usize> = (0..recovery.len()).collect();
    order.sort_by_key(|&index| recovery[index].row);
    for index in order {
        if used.insert(recovery[index].row) {
            chosen.push(index);
            if chosen.len() == missing.len() {
                break;
            }
        }
    }
    let row_indices: Vec<usize> = chosen.iter().map(|&i| recovery[i].row).collect();

    let plan = StripeRepairPlan::new(
        slots.len(),
        recovery_count,
        shard_len_usize,
        &missing,
        &row_indices,
    )?;
    let stripe = plan.stripe_len_for_budget(budget)?;

    let mut error: Option<Error> = None;
    let result = repair_shards_striped(
        &plan,
        stripe,
        |index, offset, buf| {
            // Past a volume's real length is the code word's zero padding,
            // not file content: volumes in a set need not be equal length.
            let source = intact[index].expect("intact source for an undamaged slot");
            let available = slots[index]
                .file_size
                .saturating_sub(offset as u64)
                .min(buf.len() as u64) as usize;
            if available > 0 {
                source
                    .read_at(offset as u64, &mut buf[..available])
                    .map_err(|_| crate::recovery::rar5::Error::BadRecoveryChunk)?;
            }
            buf[available..].fill(0);
            Ok(())
        },
        |slot, offset, buf| {
            let source = &recovery[chosen[slot]];
            source
                .source
                .read_at(source.payload.start + offset as u64, buf)
                .map_err(|_| crate::recovery::rar5::Error::BadRecoveryChunk)
        },
        |slot, offset, bytes| {
            let index = missing[slot];
            let offset = offset as u64;
            if offset >= slots[index].file_size {
                return Ok(());
            }
            let take = (slots[index].file_size - offset).min(bytes.len() as u64) as usize;
            if let Err(failed) = write(slot, offset, &bytes[..take]) {
                error = Some(failed);
                return Err(crate::recovery::rar5::Error::BadRecoveryChunk);
            }
            Ok(())
        },
    );
    if let Some(failed) = error {
        return Err(failed);
    }
    result?;
    Ok(missing)
}

pub fn repair_inline_recovery_bytes(input: &[u8]) -> Result<Vec<u8>> {
    repair_inline_recovery_bytes_with_options(input, crate::ArchiveReadOptions::default())
}

/// Raw byte-level RR repair, validated with the caller's read options.
///
/// The options matter because this is the last-chance path: headers were too
/// damaged for a normal parse, so the caller falls back to scanning for
/// recovery records. Validating the reconstruction with a PASSWORDLESS parse
/// meant a header-encrypted (`-hp`) archive - whose recovery data is
/// plaintext and whose reconstruction may well have succeeded - came back
/// `NeedPassword` and was reported as unrepairable, discarding a good repair
/// for want of the password the caller already had.
pub fn repair_inline_recovery_bytes_with_options(
    input: &[u8],
    options: crate::ArchiveReadOptions<'_>,
) -> Result<Vec<u8>> {
    if !input.starts_with(RAR50_SIGNATURE) {
        return Err(Error::UnsupportedSignature);
    }
    let repaired =
        crate::recovery::rar5::repair_inline_recovery_archive(input).map_err(Error::from)?;
    let parse_target = if repaired == input { input } else { &repaired };
    let _ = Archive::parse_with_options(parse_target, options)?;
    Ok(repaired)
}

/// Raw RR repair over a FILE, for volumes too large to hold.
///
/// Same last-chance role as [`repair_inline_recovery_bytes_with_options`] -
/// headers too damaged to parse, so the recovery records are found by
/// scanning - but nothing is read whole. The byte-based form needed the
/// volume resident, a clone of it to repair into, and a third copy for the
/// caller to write out; at 8-20 GB per volume that is over twice the
/// volume's size in RAM, none of it inside the daemon's memory budget.
///
/// `dest` receives the repaired volume and is verified by re-parsing it with
/// `options` before this returns, so a caller can publish it as-is. The
/// source file is never written to.
///
/// Returns the data-shard indices that were rebuilt.
pub fn repair_inline_recovery_path(
    src: &std::path::Path,
    dest: &std::path::Path,
    options: crate::ArchiveReadOptions<'_>,
    budget: u64,
) -> Result<Vec<usize>> {
    use crate::recovery::stream;
    use crate::recovery::stream::RangeSource as _;

    let source = stream::FileSource::open(src)?;
    let mut signature = [0u8; 8];
    if source.len() < signature.len() as u64 {
        return Err(Error::TooShort);
    }
    source.read_at(0, &mut signature)?;
    if signature != *RAR50_SIGNATURE {
        return Err(Error::UnsupportedSignature);
    }

    let scan = stream::scan_inline_recovery_chunks(&source, budget)?;
    let repaired = {
        let prefilled = stream::clone_prefill(src, dest)?;
        // O_NOFOLLOW - see `repair_recovery_to_path`.
        let mut out = stream::open_repair_dest(dest)?;
        let repaired = if prefilled {
            stream::repair_prefix_streaming_prefilled(&source, 0, &scan, &source, &mut out, budget)?
        } else {
            out.set_len(0)?;
            stream::repair_prefix_streaming(&source, 0, &scan, &source, &mut out, budget)?
        };
        out.sync_all()?;
        repaired
    };

    if std::fs::metadata(dest)?.len() != source.len() {
        return Err(Error::InvalidHeader("RAR 5 repaired volume changed length"));
    }
    // Validate the reconstruction the same way the byte path does: by
    // parsing it. The caller's options carry the password, because a
    // header-encrypted archive's recovery data is plaintext - its repair may
    // well have succeeded, and a passwordless check would report
    // `NeedPassword` and throw that repair away.
    let _ = crate::ArchiveReader::read_path_with_options(dest, options)?;
    Ok(repaired)
}

fn parse_main_header_bytes(parsed: &ParsedBlockHeader) -> Result<MainHeader> {
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let archive_flags = reader.read_vint()?;
    let volume_number = if archive_flags & MHFL_VOLUME_NUMBER != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let extras = parse_main_extra_area(&parsed.header, parsed.extra_range.clone())?;
    Ok(MainHeader {
        block: parsed.block.clone(),
        archive_flags,
        volume_number,
        extras,
    })
}

fn parse_main_extra_area(input: &[u8], range: Range<usize>) -> Result<Vec<MainExtraRecord>> {
    let mut records = Vec::new();
    parse_extra_records(input, range, |record_type, data| match record_type {
        MHEXTRA_LOCATOR => {
            let mut reader = SliceReader::new(input, data.start, data.end);
            let flags = reader.read_vint()?;
            let quick_open_offset = if flags & MHEXTRA_LOCATOR_QUICK_OPEN != 0 {
                Some(reader.read_vint()?)
            } else {
                None
            };
            let recovery_record_offset = if flags & MHEXTRA_LOCATOR_RECOVERY != 0 {
                Some(reader.read_vint()?)
            } else {
                None
            };
            // LOCATOR records are intentionally forward-compatible: known
            // offsets are parsed and any trailing bytes remain reserved for
            // future flags.
            records.push(MainExtraRecord::Locator(LocatorRecord {
                flags,
                quick_open_offset,
                recovery_record_offset,
            }));
            Ok(())
        }
        MHEXTRA_ARCHIVE_METADATA => {
            let mut reader = SliceReader::new(input, data.start, data.end);
            let flags = reader.read_vint()?;
            let name = if flags & MHEXTRA_ARCHIVE_METADATA_NAME != 0 {
                let name_len = usize_from_u64(
                    reader.read_vint()?,
                    "RAR 5 archive metadata name length overflows usize",
                )?;
                Some(reader.read_bytes(name_len)?.to_vec())
            } else {
                None
            };
            let creation_time = if flags & MHEXTRA_ARCHIVE_METADATA_TIME != 0 {
                Some(reader.read_u64()?)
            } else {
                None
            };
            if reader.pos != reader.end {
                return Err(Error::InvalidHeader(
                    "RAR 5 archive metadata record has trailing bytes",
                ));
            }
            records.push(MainExtraRecord::ArchiveMetadata(ArchiveMetadataRecord {
                flags,
                name,
                creation_time,
            }));
            Ok(())
        }
        _ => Ok(()),
    })?;
    Ok(records)
}

fn parse_file_header_bytes(parsed: &ParsedBlockHeader) -> Result<FileHeader> {
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let file_flags = reader.read_vint()?;
    let unpacked_size = reader.read_vint()?;
    let attributes = reader.read_vint()?;
    let mtime = if file_flags & FHFL_MTIME != 0 {
        Some(reader.read_u32()?)
    } else {
        None
    };
    let data_crc32 = if file_flags & FHFL_CRC32 != 0 {
        Some(reader.read_u32()?)
    } else {
        None
    };
    let compression_info = reader.read_vint()?;
    let host_os = reader.read_vint()?;
    let name_len = usize_from_u64(
        reader.read_vint()?,
        "RAR 5 file name length overflows usize",
    )?;
    let name = reader.read_bytes(name_len)?.to_vec();
    let mut file = FileHeader {
        block: parsed.block.clone(),
        file_flags,
        unpacked_size,
        attributes,
        mtime,
        data_crc32,
        compression_info,
        host_os,
        name,
        hash: None,
        redirection: None,
        service_data: None,
        encrypted: false,
        encryption: None,
        crypto: None,
    };
    parse_file_extra_area(&parsed.header, parsed.extra_range.clone(), &mut file)?;
    Ok(file)
}

fn parse_file_extra_area(input: &[u8], range: Range<usize>, file: &mut FileHeader) -> Result<()> {
    if file.block.extra_area_size.is_none() {
        return Ok(());
    }
    parse_extra_records(input, range, |record_type, data| {
        match record_type {
            FHEXTRA_CRYPT => {
                file.encrypted = true;
                file.encryption = Some(parse_file_encryption_record(input, data)?);
            }
            FHEXTRA_HASH => {
                let (hash_type, hash_type_len) = read_vint_at(input, data.start, data.end)?;
                file.hash = Some(FileHash {
                    hash_type,
                    data: input[data.start + hash_type_len..data.end].to_vec(),
                });
            }
            FHEXTRA_REDIR => {
                file.redirection = Some(parse_file_redirection_record(input, data)?);
            }
            FHEXTRA_SUBDATA => {
                file.service_data = Some(input[data].to_vec());
            }
            _ => {}
        }
        Ok(())
    })
}

fn parse_file_redirection_record(input: &[u8], range: Range<usize>) -> Result<FileRedirection> {
    let (redirection_type, type_len) = read_vint_at(input, range.start, range.end)?;
    let flags_start = range.start + type_len;
    let (flags, flags_len) = read_vint_at(input, flags_start, range.end)?;
    let name_len_start = flags_start + flags_len;
    let (name_len, name_len_len) = read_vint_at(input, name_len_start, range.end)?;
    let name_start = name_len_start + name_len_len;
    let name_len = usize::try_from(name_len).map_err(|_| {
        Error::InvalidHeader("RAR 5 file redirection target length overflows host address size")
    })?;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(Error::InvalidHeader(
            "RAR 5 file redirection target length overflows",
        ))?;
    if name_end != range.end {
        return Err(Error::InvalidHeader(
            "RAR 5 file redirection record has trailing bytes",
        ));
    }
    Ok(FileRedirection {
        redirection_type,
        flags,
        target_name: input[name_start..name_end].to_vec(),
    })
}

fn parse_file_encryption_record(input: &[u8], range: Range<usize>) -> Result<FileEncryption> {
    let (version, version_len) = read_vint_at(input, range.start, range.end)?;
    let flags_pos = range.start + version_len;
    let (flags, flags_len) = read_vint_at(input, flags_pos, range.end)?;
    let mut pos = flags_pos + flags_len;
    if pos >= range.end {
        return Err(Error::TooShort);
    }
    let kdf_count = input[pos];
    pos += 1;
    let salt = read_array_at::<16>(input, &mut pos, range.end)?;
    let iv = read_array_at::<16>(input, &mut pos, range.end)?;
    let check_value = if flags & 0x0001 != 0 {
        Some(read_array_at::<12>(input, &mut pos, range.end)?)
    } else {
        None
    };
    if pos != range.end {
        return Err(Error::InvalidHeader(
            "RAR 5 file encryption record has trailing bytes",
        ));
    }
    Ok(FileEncryption {
        version,
        flags,
        kdf_count,
        salt,
        iv,
        check_value,
    })
}

fn parse_archive_encryption_header(
    parsed: &ParsedBlockHeader,
    password: Option<&[u8]>,
    key_cache: &mut Rar50KeyCache,
) -> Result<Rar50Keys> {
    let password = password.ok_or(Error::NeedPassword)?;
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let version = reader.read_vint()?;
    if version != 0 {
        return Err(Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 unknown header encryption version",
        });
    }
    let flags = reader.read_vint()?;
    let kdf_count = reader.read_byte()?;
    let salt = reader.read_array::<16>()?;
    let check_value = if flags & 0x0001 != 0 {
        Some(reader.read_array::<12>()?)
    } else {
        None
    };
    if reader.pos != reader.range.end {
        return Err(Error::InvalidHeader(
            "RAR 5 archive encryption header has trailing bytes",
        ));
    }
    let keys = key_cache.get_or_derive(password, salt, kdf_count)?;
    if let Some(check_value) = check_value {
        keys.check_password(&check_value)
            .map_err(map_rar50_crypto_error)?;
    }
    Ok(keys)
}

/// Parse-scoped memo for derived file keys. Every member of an archive
/// normally shares one (salt, kdf count), yet the PBKDF2 ladder ran once per
/// encrypted member; a thousand-member encrypted archive paid a thousand
/// 2^15-iteration derivations for one key. The cache lives for a single
/// `parse_blocks` walk, so keys never outlive the parse that needed them.
/// Per-member password checks still run against each member's own
/// check value.
#[derive(Default)]
pub(crate) struct Rar50KeyCache {
    /// Keys are BOXED, not stored inline. `Rar50Keys` is ZeroizeOnDrop, but
    /// that only clears the live value: growing a Vec of them memcpys the
    /// AES-256 file and MAC keys into a new allocation and frees the old one
    /// with the key material intact. A session that derives two or more
    /// distinct (salt, kdf_count) pairs - scanning a directory holding two
    /// different encrypted sets - reallocates and leaves the first set's keys
    /// in freed heap. Boxing moves only the pointer, so the keys never move.
    entries: Vec<([u8; 16], u8, Box<Rar50Keys>)>,
    /// Actual PBKDF2 runs (cache misses) - the session tests assert a
    /// multi-volume set derives once, by count rather than by timing.
    #[cfg(test)]
    pub(crate) derives: usize,
}

impl Rar50KeyCache {
    pub(crate) fn get_or_derive(
        &mut self,
        password: &[u8],
        salt: [u8; 16],
        kdf_count: u8,
    ) -> Result<Rar50Keys> {
        if let Some((_, _, keys)) = self
            .entries
            .iter()
            .find(|&&(cached_salt, cached_count, _)| cached_salt == salt && cached_count == kdf_count)
        {
            return Ok((**keys).clone());
        }
        #[cfg(test)]
        {
            self.derives += 1;
        }
        let keys =
            Rar50Keys::derive(password, salt, kdf_count).map_err(map_rar50_crypto_error)?;
        self.entries.push((salt, kdf_count, Box::new(keys.clone())));
        Ok(keys)
    }
}

fn attach_file_crypto(
    file: &mut FileHeader,
    password: Option<&[u8]>,
    key_cache: &mut Rar50KeyCache,
) -> Result<()> {
    if !file.encrypted || file.crypto.is_some() {
        return Ok(());
    }
    let Some(password) = password else {
        return Ok(());
    };
    let encryption = file.encryption.as_ref().ok_or(Error::InvalidHeader(
        "RAR 5 encrypted file is missing encryption record",
    ))?;
    if encryption.version != 0 {
        return Err(Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 unknown file encryption version",
        });
    }
    let keys = key_cache.get_or_derive(password, encryption.salt, encryption.kdf_count)?;
    if let Some(check_value) = encryption.check_value {
        keys.check_password(&check_value)
            .map_err(map_rar50_crypto_error)?;
    }
    file.crypto = Some(FileCryptoState {
        keys,
        iv: encryption.iv,
    });
    Ok(())
}

fn attach_service_crypto(
    service: &mut FileHeader,
    password: Option<&[u8]>,
    key_cache: &mut Rar50KeyCache,
) -> Result<()> {
    // WinRAR can emit encrypted QO metadata whose service-local password
    // check does not validate with the archive password. QuickOpen is an
    // optional cache, so keep archive parsing and file extraction independent
    // from that service.
    if service.name == b"QO" {
        return Ok(());
    }
    attach_file_crypto(service, password, key_cache)
}

fn map_rar50_crypto_error(error: crate::crypto::rar50::Error) -> Error {
    match error {
        crate::crypto::rar50::Error::KdfCountTooLarge => Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 KDF count",
        },
        crate::crypto::rar50::Error::BadPassword => Error::WrongPasswordOrCorruptData,
        crate::crypto::rar50::Error::UnalignedInput => {
            Error::InvalidHeader("RAR 5 AES input is not block aligned")
        }
    }
}

fn read_array_at<const N: usize>(input: &[u8], pos: &mut usize, end: usize) -> Result<[u8; N]> {
    if pos.checked_add(N).is_none_or(|next| next > end) {
        return Err(Error::TooShort);
    }
    let mut out = [0; N];
    out.copy_from_slice(&input[*pos..*pos + N]);
    *pos += N;
    Ok(out)
}

/// Walks an archive's header chain.
///
/// `arrived`, when given, is the source's contiguous arrival frontier,
/// re-read before every block header: a walk that would have to read
/// past it STOPS and hands the offset back as the third return value,
/// instead of blocking there. That is the whole of what makes a chase
/// over a volume larger than its retention budget possible - see
/// [`Archive::parse_stream_incremental`], the only caller that passes it.
fn parse_archive_blocks<F, G>(
    archive_len: usize,
    password: Option<&[u8]>,
    key_cache: &mut Rar50KeyCache,
    mut read_block: F,
    mut read_encrypted_block: G,
    arrived: Option<&dyn Fn() -> usize>,
) -> Result<(MainHeader, Vec<Block>, Option<PendingWalk>)>
where
    F: FnMut(usize) -> Result<ParsedBlockHeader>,
    G: FnMut(usize, &Rar50Keys) -> Result<ParsedBlockHeader>,
{
    let mut pos = RAR50_SIGNATURE.len();
    let first = read_block(pos).map_err(|error| error.at_archive_offset(pos))?;
    let header_keys = if first.block.header_type == HEAD_CRYPT {
        pos = first.next_offset;
        Some(parse_archive_encryption_header(&first, password, key_cache)?)
    } else {
        None
    };

    let main_pos = pos;
    let main_block;
    let first = if let Some(keys) = &header_keys {
        main_block =
            read_encrypted_block(pos, keys).map_err(|error| error.at_archive_offset(pos))?;
        &main_block
    } else {
        &first
    };
    if first.block.header_type != HEAD_MAIN {
        return Err(Error::InvalidHeader("RAR 5 main header is missing"));
    }
    let main = parse_main_header_bytes(first).map_err(|error| error.at_archive_offset(main_pos))?;
    pos = first.next_offset;

    let mut blocks = Vec::new();
    let stopped = walk_archive_blocks(
        pos,
        archive_len,
        password,
        key_cache,
        header_keys.as_ref(),
        read_block,
        read_encrypted_block,
        arrived,
        &mut blocks,
        false,
    )?;
    let pending = stopped.map(|from| PendingWalk {
        from,
        header_keys: header_keys.map(Box::new),
    });
    Ok((main, blocks, pending))
}

/// The block walk behind [`parse_archive_blocks`], from `pos` (the first
/// block after the main header, or wherever an earlier walk stopped) to
/// the END record, appending to `blocks`. With `arrived` it stops short
/// at the first header the source has not delivered and returns that
/// offset; `read_first` makes it read the header at `pos` regardless, so
/// a resumed walk can be asked for one more entry without waiting for
/// the volume's tail.
#[allow(clippy::too_many_arguments)]
fn walk_archive_blocks<F, G>(
    mut pos: usize,
    archive_len: usize,
    password: Option<&[u8]>,
    key_cache: &mut Rar50KeyCache,
    header_keys: Option<&Rar50Keys>,
    mut read_block: F,
    mut read_encrypted_block: G,
    arrived: Option<&dyn Fn() -> usize>,
    blocks: &mut Vec<Block>,
    read_first: bool,
) -> Result<Option<usize>>
where
    F: FnMut(usize) -> Result<ParsedBlockHeader>,
    G: FnMut(usize, &Rar50Keys) -> Result<ParsedBlockHeader>,
{
    let mut first = read_first;
    while pos < archive_len {
        // The header at `pos` has not arrived: stop rather than block on
        // it. A file block's data area is skipped arithmetically, so the
        // next header sits a whole member's packed length ahead - on a
        // chased volume that is the rest of the volume, which is exactly
        // the wait this exists to avoid.
        if let Some(arrived) = arrived {
            if !first && pos >= arrived() {
                return Ok(Some(pos));
            }
        }
        first = false;
        let parsed = if let Some(keys) = header_keys {
            read_encrypted_block(pos, keys).map_err(|error| error.at_archive_offset(pos))?
        } else {
            read_block(pos).map_err(|error| error.at_archive_offset(pos))?
        };
        let next = parsed.next_offset;
        match parsed.block.header_type {
            HEAD_FILE => {
                let mut file = parse_file_header_bytes(&parsed)
                    .map_err(|error| error.at_archive_offset(pos))?;
                attach_file_crypto(&mut file, password, key_cache)
                    .map_err(|error| error.at_archive_offset(pos))?;
                blocks.push(Block::File(file));
            }
            HEAD_SERVICE => {
                let mut service = parse_file_header_bytes(&parsed)
                    .map_err(|error| error.at_archive_offset(pos))?;
                attach_service_crypto(&mut service, password, key_cache)
                    .map_err(|error| error.at_archive_offset(pos))?;
                blocks.push(Block::Service(service));
            }
            HEAD_CRYPT => {
                return Err(Error::UnsupportedFeature {
                    version: crate::version::ArchiveVersion::Rar50,
                    feature: "RAR 5 encrypted headers",
                });
            }
            HEAD_END => {
                blocks.push(Block::End(parsed.block));
                break;
            }
            _ => blocks.push(Block::Unknown(parsed.block)),
        }
        pos = next;
    }

    Ok(None)
}

fn parse_extra_records<F>(input: &[u8], range: Range<usize>, mut handle: F) -> Result<()>
where
    F: FnMut(u64, Range<usize>) -> Result<()>,
{
    let mut pos = range.start;
    while pos < range.end {
        let record_start = pos;
        let (record_size, size_len) = read_vint_at(input, pos, range.end)?;
        pos += size_len;
        let record_payload_len =
            usize_from_u64(record_size, "RAR 5 extra record size overflows usize")?;
        let record_end = pos
            .checked_add(record_payload_len)
            .ok_or(Error::InvalidHeader(
                "RAR 5 extra record size overflows usize",
            ))?;
        if record_end > range.end {
            return Err(Error::TooShort);
        }
        let (record_type, type_len) = read_vint_at(input, pos, record_end)?;
        let data_start = pos + type_len;
        handle(record_type, data_start..record_end)?;
        if record_end <= record_start {
            return Err(Error::InvalidHeader("RAR 5 extra record does not advance"));
        }
        pos = record_end;
    }
    Ok(())
}

struct ParsedBlockHeader {
    block: BlockHeader,
    header: Vec<u8>,
    type_specific_range: Range<usize>,
    extra_range: Range<usize>,
    next_offset: usize,
}

fn parse_block_header_bytes(
    input: &[u8],
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 5 {
        return Err(Error::TooShort);
    }
    let header_crc = read_u32(input, offset)?;
    let after_crc = offset
        .checked_add(4)
        .ok_or(Error::InvalidHeader("RAR 5 header offset overflows usize"))?;
    let (header_size, header_size_len) = read_vint_at(input, after_crc, archive_len)?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    if header_total > remaining {
        return Err(Error::TooShort);
    }
    let header_end = offset
        .checked_add(header_total)
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    let header = input
        .get(offset..header_end)
        .ok_or(Error::TooShort)?
        .to_vec();
    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        header_total,
    )
}

fn parse_encrypted_block_header_bytes(
    input: &[u8],
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    keys: &Rar50Keys,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 32 {
        return Err(Error::TooShort);
    }
    let first = input.get(offset..offset + 32).ok_or(Error::TooShort)?;
    let mut iv = [0; 16];
    iv.copy_from_slice(&first[..16]);
    let mut first_plain = first[16..32].to_vec();
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut first_plain)
        .map_err(map_rar50_crypto_error)?;
    let header_crc = read_u32(&first_plain, 0)?;
    let (header_size, header_size_len) = read_vint_at(&first_plain, 4, first_plain.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    let encrypted_len = checked_align16(header_total, "RAR 5 encrypted header size overflows")?;
    let disk_header_len = 16usize
        .checked_add(encrypted_len)
        .ok_or(Error::InvalidHeader(
            "RAR 5 encrypted header size overflows",
        ))?;
    if disk_header_len > remaining {
        return Err(Error::TooShort);
    }
    let encrypted = input
        .get(offset + 16..offset + disk_header_len)
        .ok_or(Error::TooShort)?;
    let mut header = encrypted.to_vec();
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut header)
        .map_err(map_rar50_crypto_error)?;
    header.truncate(header_total);

    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        disk_header_len,
    )
}

fn read_block_header_at(
    file: &mut File,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 5 {
        return Err(Error::TooShort);
    }
    let prefix_len = remaining.min(14);
    let prefix = read_exact_at(file, sfx_offset + offset, prefix_len)?;
    let header_crc = read_u32(&prefix, 0)?;
    let (header_size, header_size_len) = read_vint_at(&prefix, 4, prefix.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    if header_total > remaining {
        return Err(Error::TooShort);
    }

    let header = read_exact_at(file, sfx_offset + offset, header_total)?;
    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        header_total,
    )
}

fn read_encrypted_block_header_at(
    file: &mut File,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    keys: &Rar50Keys,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 32 {
        return Err(Error::TooShort);
    }
    let first = read_exact_at(file, sfx_offset + offset, 32)?;
    let mut iv = [0; 16];
    iv.copy_from_slice(&first[..16]);
    let mut first_plain = first[16..32].to_vec();
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut first_plain)
        .map_err(map_rar50_crypto_error)?;
    let header_crc = read_u32(&first_plain, 0)?;
    let (header_size, header_size_len) = read_vint_at(&first_plain, 4, first_plain.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    let encrypted_len = checked_align16(header_total, "RAR 5 encrypted header size overflows")?;
    let disk_header_len = 16usize
        .checked_add(encrypted_len)
        .ok_or(Error::InvalidHeader(
            "RAR 5 encrypted header size overflows",
        ))?;
    if disk_header_len > remaining {
        return Err(Error::TooShort);
    }
    let encrypted = read_exact_at(file, sfx_offset + offset + 16, encrypted_len)?;
    let mut header = encrypted;
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut header)
        .map_err(map_rar50_crypto_error)?;
    header.truncate(header_total);

    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        disk_header_len,
    )
}

// Source-backed twins of read_block_header_at / read_encrypted_block_header_at
// used by the streaming parse path. Reads go through ArchiveSource, so on a
// Stream source each header fetch blocks until those bytes have arrived; the
// existing memory and file paths keep their direct readers untouched.
fn read_block_header_from_source(
    source: &ArchiveSource,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 5 {
        return Err(Error::TooShort);
    }
    let prefix_len = remaining.min(14);
    let prefix = source.read_range(sfx_offset + offset..sfx_offset + offset + prefix_len)?;
    let header_crc = read_u32(&prefix, 0)?;
    let (header_size, header_size_len) = read_vint_at(&prefix, 4, prefix.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    if header_total > remaining {
        return Err(Error::TooShort);
    }

    let header = source.read_range(sfx_offset + offset..sfx_offset + offset + header_total)?;
    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        header_total,
    )
}

fn read_encrypted_block_header_from_source(
    source: &ArchiveSource,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    keys: &Rar50Keys,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 32 {
        return Err(Error::TooShort);
    }
    let first = source.read_range(sfx_offset + offset..sfx_offset + offset + 32)?;
    let mut iv = [0; 16];
    iv.copy_from_slice(&first[..16]);
    let mut first_plain = first[16..32].to_vec();
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut first_plain)
        .map_err(map_rar50_crypto_error)?;
    let header_crc = read_u32(&first_plain, 0)?;
    let (header_size, header_size_len) = read_vint_at(&first_plain, 4, first_plain.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    let encrypted_len = checked_align16(header_total, "RAR 5 encrypted header size overflows")?;
    let disk_header_len = 16usize
        .checked_add(encrypted_len)
        .ok_or(Error::InvalidHeader(
            "RAR 5 encrypted header size overflows",
        ))?;
    if disk_header_len > remaining {
        return Err(Error::TooShort);
    }
    let start = sfx_offset + offset + 16;
    let mut header = source.read_range(start..start + encrypted_len)?;
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut header)
        .map_err(map_rar50_crypto_error)?;
    header.truncate(header_total);

    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        disk_header_len,
    )
}

fn parse_block_header_image(
    header: Vec<u8>,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    header_crc: u32,
    disk_header_len: usize,
) -> Result<ParsedBlockHeader> {
    let header_total = header.len();
    let (decoded_header_size, header_size_len) = read_vint_at(&header, 4, header_total)?;
    validate_block_header_crc(&header, header_crc)?;
    let type_start = 4 + header_size_len;
    let mut reader = SliceReader::new(&header, type_start, header_total);
    let header_type = reader.read_vint()?;
    let flags = reader.read_vint()?;
    let extra_area_size = if flags & HFL_EXTRA != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let data_size = if flags & HFL_DATA != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let extra_len = extra_area_size
        .map(|size| usize_from_u64(size, "RAR 5 extra area size overflows usize"))
        .transpose()?
        .unwrap_or(0);
    if extra_len > header_total.saturating_sub(reader.pos) {
        return Err(Error::TooShort);
    }
    let type_specific_end = header_total - extra_len;
    let data_len = data_size
        .map(|size| usize_from_u64(size, "RAR 5 data size overflows usize"))
        .transpose()?
        .unwrap_or(0);
    let next_offset = offset
        .checked_add(disk_header_len)
        .and_then(|pos| pos.checked_add(data_len))
        .ok_or(Error::InvalidHeader("RAR 5 data size overflows usize"))?;
    if next_offset > archive_len {
        return Err(Error::TooShort);
    }
    let type_specific_start = reader.pos;
    let data_start = sfx_offset
        .checked_add(offset)
        .and_then(|pos| pos.checked_add(disk_header_len))
        .ok_or(Error::InvalidHeader("RAR 5 data offset overflows usize"))?;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(Error::InvalidHeader("RAR 5 data size overflows usize"))?;

    Ok(ParsedBlockHeader {
        block: BlockHeader {
            header_crc,
            header_size: decoded_header_size,
            header_type,
            flags,
            extra_area_size,
            data_size,
            offset: sfx_offset + offset,
            header_range: (offset + type_specific_start)..(offset + type_specific_end),
            data_range: data_start..data_end,
        },
        header,
        type_specific_range: type_specific_start..type_specific_end,
        extra_range: type_specific_end..header_total,
        next_offset,
    })
}

fn validate_block_header_crc(header: &[u8], expected: u32) -> Result<()> {
    let actual = crc32(header.get(4..).ok_or(Error::TooShort)?);
    if actual != expected {
        return Err(Error::Crc32Mismatch { expected, actual });
    }
    Ok(())
}

struct HeaderReader<'a> {
    input: &'a [u8],
    range: Range<usize>,
    pos: usize,
}

impl<'a> HeaderReader<'a> {
    fn new(input: &'a [u8], range: Range<usize>) -> Result<Self> {
        if range.end > input.len() {
            return Err(Error::TooShort);
        }
        Ok(Self {
            input,
            pos: range.start,
            range,
        })
    }

    fn read_vint(&mut self) -> Result<u64> {
        let (value, len) = read_vint_at(self.input, self.pos, self.range.end)?;
        self.pos += len;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let value = read_u32(self.input, self.pos)?;
        self.pos += 4;
        Ok(value)
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.range.end {
            return Err(Error::TooShort);
        }
        let value = self.input[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        read_array_at::<N>(self.input, &mut self.pos, self.range.end)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::InvalidHeader("RAR 5 field size overflows usize"))?;
        if end > self.range.end {
            return Err(Error::TooShort);
        }
        let bytes = &self.input[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
}

struct SliceReader<'a> {
    input: &'a [u8],
    end: usize,
    pos: usize,
}

impl<'a> SliceReader<'a> {
    fn new(input: &'a [u8], pos: usize, end: usize) -> Self {
        Self { input, pos, end }
    }

    fn read_vint(&mut self) -> Result<u64> {
        let (value, len) = read_vint_at(self.input, self.pos, self.end)?;
        self.pos += len;
        Ok(value)
    }

    fn read_byte(&mut self) -> Result<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::InvalidHeader("RAR 5 field size overflows usize"))?;
        if end > self.end {
            return Err(Error::TooShort);
        }
        let bytes = &self.input[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
}

fn read_vint_at(input: &[u8], offset: usize, end: usize) -> Result<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for i in 0..10 {
        let pos = offset.checked_add(i).ok_or(Error::TooShort)?;
        if pos >= end {
            return Err(Error::TooShort);
        }
        let byte = *input.get(pos).ok_or(Error::TooShort)?;
        if shift == 63 && byte & 0x7e != 0 {
            return Err(Error::InvalidHeader("RAR 5 vint overflows u64"));
        }
        value = value
            .checked_add(((byte & 0x7f) as u64) << shift)
            .ok_or(Error::InvalidHeader("RAR 5 vint overflows u64"))?;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(Error::InvalidHeader("RAR 5 vint is too long"))
}

fn usize_from_u64(value: u64, message: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::InvalidHeader(message))
}

fn compression_method(compression_info: u64) -> u64 {
    (compression_info >> 7) & 0x07
}

fn decode_compression_info(raw: u64) -> Result<CompressionInfo> {
    let algorithm_version = (raw & 0x3f) as u8;
    if algorithm_version > 1 {
        return Err(Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 unknown compression algorithm version",
        });
    }

    let dictionary_power = ((raw >> 10) & 0x1f) as u8;
    let dictionary_fraction = ((raw >> 15) & 0x1f) as u8;
    let rar5_compat = raw & 0x100000 != 0;
    if algorithm_version == 0 && (dictionary_fraction != 0 || rar5_compat) {
        return Err(Error::InvalidHeader(
            "RAR 5 v0 compression info uses v1 dictionary fields",
        ));
    }
    if algorithm_version == 0 && dictionary_power > 15 {
        return Err(Error::InvalidHeader(
            "RAR 5 v0 dictionary power exceeds 4 GiB limit",
        ));
    }

    let dictionary_size = if algorithm_version == 1 {
        u64::from(dictionary_fraction + 32)
            .checked_shl(u32::from(dictionary_power) + 12)
            .ok_or(Error::InvalidHeader("RAR 5 dictionary size overflows u64"))?
    } else {
        (128 * 1024_u64)
            .checked_shl(u32::from(dictionary_power))
            .ok_or(Error::InvalidHeader("RAR 5 dictionary size overflows u64"))?
    };

    Ok(CompressionInfo {
        algorithm_version,
        solid: raw & 0x40 != 0,
        method: ((raw >> 7) & 0x07) as u8,
        dictionary_power,
        dictionary_fraction,
        rar5_compat,
        dictionary_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parse-scoped key cache must hand back the same keys `derive` would
    /// have produced, hit on a repeated (salt, kdf count), and keep distinct
    /// salts or counts on distinct derivations.
    #[test]
    fn key_cache_matches_direct_derivation_and_discriminates_inputs() {
        let mut cache = Rar50KeyCache::default();
        let password = b"hunter2";
        let salt_a = [0x11; 16];
        let salt_b = [0x22; 16];

        let first = cache.get_or_derive(password, salt_a, 4).unwrap();
        assert_eq!(first, Rar50Keys::derive(password, salt_a, 4).unwrap());
        assert_eq!(cache.entries.len(), 1);

        // Same salt and count: served from the cache, identical keys.
        let repeat = cache.get_or_derive(password, salt_a, 4).unwrap();
        assert_eq!(repeat, first);
        assert_eq!(cache.entries.len(), 1);

        // A different salt or a different count is a different derivation.
        let other_salt = cache.get_or_derive(password, salt_b, 4).unwrap();
        assert_ne!(other_salt, first);
        let other_count = cache.get_or_derive(password, salt_a, 5).unwrap();
        assert_ne!(other_count, first);
        assert_eq!(cache.entries.len(), 3);
    }

    #[test]
    fn read_vint_at_honors_logical_end_before_decoding() {
        assert_eq!(read_vint_at(&[0x01], 0, 0), Err(Error::TooShort));
        assert_eq!(read_vint_at(&[0x81, 0x01], 0, 1), Err(Error::TooShort));
        assert_eq!(read_vint_at(&[0x81, 0x01], 0, 2).unwrap(), (129, 2));
    }

    #[test]
    fn read_vint_at_rejects_values_wider_than_u64() {
        let max = [0xff; 9].into_iter().chain([0x01]).collect::<Vec<_>>();
        assert_eq!(read_vint_at(&max, 0, max.len()).unwrap(), (u64::MAX, 10));

        let overflow = [0xff; 9].into_iter().chain([0x02]).collect::<Vec<_>>();
        assert_eq!(
            read_vint_at(&overflow, 0, overflow.len()),
            Err(Error::InvalidHeader("RAR 5 vint overflows u64"))
        );
    }

    #[test]
    fn parses_file_redirection_extra_record() {
        let input = [1, 1, 6, b't', b'a', b'r', b'g', b'e', b't'];
        let record = parse_file_redirection_record(&input, 0..input.len()).unwrap();

        assert_eq!(record.redirection_type, 1);
        assert_eq!(record.flags, 1);
        assert_eq!(record.target_name, b"target");
    }

    #[test]
    fn rejects_file_redirection_record_with_trailing_bytes() {
        let input = [1, 0, 3, b'f', b'o', b'o', 0];

        assert!(matches!(
            parse_file_redirection_record(&input, 0..input.len()),
            Err(Error::InvalidHeader(
                "RAR 5 file redirection record has trailing bytes"
            ))
        ));
    }

    #[test]
    fn file_header_name_bytes_preserve_non_utf8_names() {
        let file = FileHeader {
            block: BlockHeader {
                header_crc: 0,
                header_size: 0,
                header_type: HEAD_FILE,
                flags: 0,
                extra_area_size: None,
                data_size: Some(0),
                offset: 0,
                header_range: 0..0,
                data_range: 0..0,
            },
            file_flags: 0,
            unpacked_size: 0,
            attributes: 0,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 0,
            name: vec![0xff, b'.', b'b', b'i', b'n'],
            hash: None,
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        };

        assert_eq!(file.name_bytes(), [0xff, b'.', b'b', b'i', b'n']);
        assert_eq!(file.name_lossy(), "\u{fffd}.bin");
    }

    fn build_archive_with_optional_comment(comment: Option<&[u8]>) -> Archive {
        use crate::FeatureSet;
        let mut features = FeatureSet::store_only();
        features.archive_comment = comment.is_some();
        let entries = [crate::rar50::StoredEntry {
            name: b"payload.txt",
            data: b"payload bytes",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let bytes = crate::rar50::Rar50Writer::new(crate::rar50::WriterOptions::new(
            crate::version::ArchiveVersion::Rar50,
            features,
        ))
        .stored_entries(&entries)
        .archive_comment(comment)
        .finish()
        .unwrap();
        Archive::parse(&bytes).unwrap()
    }

    #[test]
    fn archive_comment_returns_none_for_archive_without_a_cmt_service() {
        let archive = build_archive_with_optional_comment(None);
        assert!(archive.archive_comment().unwrap().is_none());
    }

    #[test]
    fn archive_comment_decodes_the_cmt_service_payload_text() {
        let comment_text = b"archive comment from rars unit test\n";
        let archive = build_archive_with_optional_comment(Some(comment_text));
        let comment = archive.archive_comment().unwrap();
        assert_eq!(comment.as_deref(), Some(&comment_text[..]));
    }

    #[test]
    fn archive_comment_ignores_cmt_services_attached_to_files() {
        // Service blocks that follow a File block belong to that file, not the
        // archive — archive_comment should not surface them.
        use crate::FeatureSet;
        let services = [crate::rar50::StoredServiceEntry {
            name: b"CMT",
            data: b"per-file comment",
        }];
        let entry = crate::rar50::StoredEntryWithServices {
            entry: crate::rar50::StoredEntry {
                name: b"payload.txt",
                data: b"payload bytes",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
            services: &services,
        };
        let mut features = FeatureSet::store_only();
        features.file_comment = true;
        let bytes = crate::rar50::Rar50Writer::new(crate::rar50::WriterOptions::new(
            crate::version::ArchiveVersion::Rar50,
            features,
        ))
        .stored_entries_with_services(std::slice::from_ref(&entry))
        .finish()
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert!(archive.archive_comment().unwrap().is_none());
    }

    /// Build a CRC-valid `.rev` with arbitrary counts, so the hostile-input
    /// test below never has to construct (or allocate) the volume set the file
    /// merely *declares*. Every slot is described as `payload.len()` bytes.
    fn forged_rev(
        data_count: u16,
        recovery_count: u16,
        recovery_number: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::with_capacity(11 + usize::from(data_count) * 12);
        body.push(1); // format version
        body.extend_from_slice(&data_count.to_le_bytes());
        body.extend_from_slice(&recovery_count.to_le_bytes());
        body.extend_from_slice(&recovery_number.to_le_bytes());
        body.extend_from_slice(&crc32(payload).to_le_bytes());
        for _ in 0..data_count {
            body.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
        }

        let mut out = REV5_SIGNATURE.to_vec();
        out.extend_from_slice(&[0; 4]); // header CRC, filled in below
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        let header_crc = crc32(&out[12..]);
        out[8..12].copy_from_slice(&header_crc.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Resident bytes for this process, or `None` where we cannot ask cheaply.
    /// A regression that reserves the grid instead of refusing it shows up here
    /// even on an allocator that hands back address space without aborting.
    #[cfg(unix)]
    fn resident_bytes() -> Option<u64> {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        let kib: u64 = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
        Some(kib * 1024)
    }

    #[cfg(not(unix))]
    fn resident_bytes() -> Option<u64> {
        None
    }

    /// A REV volume declares its data-volume count in a `u16`, and the metadata
    /// table for the maximum 65,535 slots is 786,420 bytes - under the 1 MiB
    /// header cap. Reconstruction pads one payload-sized buffer per slot, so a
    /// CRC-valid 1.8 MiB file used to ask for ~64 GiB before checking whether a
    /// single recovery row could repair 65,535 missing volumes. Rust answers
    /// allocation failure with abort, and this path runs by itself once
    /// extraction fails, so that was the daemon killed by a downloaded file.
    #[test]
    fn rev5_reconstruction_refuses_a_slot_count_nothing_backs() {
        let payload = vec![0x5a; 1024 * 1024];
        // 65_535 data volumes plus even one recovery volume cannot fit the
        // GF(2^16) code word, so that shape now dies at parse time.
        assert!(
            Rev5Volume::parse(&forged_rev(65_535, 1, 65_535, &payload)).is_err(),
            "a REV set wider than the recovery field must not parse"
        );

        // The widest declaration the field admits still claims a grid no
        // whole-set reconstruction can afford.
        let rev = forged_rev(65_534, 1, 65_534, &payload);
        assert_eq!(
            65_534u64 * payload.len() as u64,
            68_717_379_584,
            "the file claims a 64 GiB grid"
        );
        assert!(
            rev.len() < 2 * 1024 * 1024,
            "but the fixture stays under 2 MiB ({} bytes)",
            rev.len()
        );

        let volume = Rev5Volume::parse(&rev).unwrap();
        assert_eq!(volume.data_volumes.len(), 65_534);
        let slots: Vec<Option<&[u8]>> = vec![None; 65_534];

        let before = resident_bytes();
        let result = repair_rev5_volumes_to(&slots, &[volume], |_, _| Ok(()));
        let after = resident_bytes();

        assert!(
            matches!(
                result,
                Err(Error::Rar5Recovery(
                    crate::recovery::rar5::Error::ReconstructionTooLarge
                ))
            ),
            "expected a bounded refusal, got {result:?}"
        );
        if let (Some(before), Some(after)) = (before, after) {
            let grew = after.saturating_sub(before);
            assert!(
                grew < 256 * 1024 * 1024,
                "refusing the grid grew RSS by {grew} bytes - it was reserved, not refused"
            );
        }
    }
}

#[cfg(test)]
mod rev_stream_tests {
    use super::*;
    use crate::crc32::crc32;
    use crate::recovery::rar5::encode_parity_shards;
    use crate::recovery::stream::MemorySource;

    /// Builds a synthetic REV set: `sizes` data volumes and `recovery_count`
    /// `.rev` volumes over them. Returns the data volumes and the `.rev`
    /// files, both as raw bytes.
    fn build_rev_set(sizes: &[usize], recovery_count: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let data: Vec<Vec<u8>> = sizes
            .iter()
            .enumerate()
            .map(|(index, &len)| {
                (0..len)
                    .map(|byte| (byte * 7 + index * 29 + 11) as u8)
                    .collect()
            })
            .collect();

        // One code word: every volume padded to the longest, rounded up to
        // an even length so the GF16 symbol walk stays in bounds.
        let mut shard_len = *sizes.iter().max().unwrap();
        shard_len += shard_len & 1;
        let padded: Vec<Vec<u8>> = data
            .iter()
            .map(|volume| {
                let mut shard = vec![0u8; shard_len];
                shard[..volume.len()].copy_from_slice(volume);
                shard
            })
            .collect();
        let refs: Vec<&[u8]> = padded.iter().map(Vec::as_slice).collect();
        let parity = encode_parity_shards(&refs, recovery_count).unwrap();

        let data_count = data.len() as u16;
        let revs = (0..recovery_count)
            .map(|row| {
                let payload = &parity[row];
                let mut body = Vec::new();
                body.push(1u8); // version
                body.extend_from_slice(&data_count.to_le_bytes());
                body.extend_from_slice(&(recovery_count as u16).to_le_bytes());
                body.extend_from_slice(&(data_count as usize + row).to_le_bytes()[..2]);
                body.extend_from_slice(&crc32(payload).to_le_bytes());
                for volume in &data {
                    body.extend_from_slice(&(volume.len() as u64).to_le_bytes());
                    body.extend_from_slice(&crc32(volume).to_le_bytes());
                }

                let mut rev = Vec::new();
                rev.extend_from_slice(REV5_SIGNATURE);
                rev.extend_from_slice(&[0u8; 4]); // header crc, filled below
                rev.extend_from_slice(&(body.len() as u32).to_le_bytes());
                rev.extend_from_slice(&body);
                let header_crc = crc32(&rev[12..16 + body.len()]);
                rev[8..12].copy_from_slice(&header_crc.to_le_bytes());
                rev.extend_from_slice(payload);
                rev
            })
            .collect();
        (data, revs)
    }

    #[test]
    fn rev_metadata_is_read_without_the_payload() {
        let (data, revs) = build_rev_set(&[600, 512, 480], 2);
        let source = MemorySource(revs[0].clone());
        let volume = read_rev5_meta(&source).unwrap();

        assert_eq!(volume.meta.data_count, 3);
        assert_eq!(volume.meta.recovery_count, 2);
        assert_eq!(volume.row().unwrap(), 0);
        assert_eq!(volume.meta.data_volumes.len(), 3);
        for (slot, volume_bytes) in volume.meta.data_volumes.iter().zip(&data) {
            assert_eq!(slot.file_size, volume_bytes.len() as u64);
            assert_eq!(slot.crc32, crc32(volume_bytes));
        }
        // The payload was located, not loaded.
        assert_eq!(volume.payload.end, revs[0].len() as u64);
        assert!(verify_rev5_payload(&source, &volume).unwrap());
    }

    #[test]
    fn rev_payload_crc_rejects_a_corrupt_recovery_volume() {
        let (_, mut revs) = build_rev_set(&[600, 512, 480], 2);
        let last = revs[0].len() - 1;
        revs[0][last] ^= 0xff;
        let source = MemorySource(revs[0].clone());
        let volume = read_rev5_meta(&source).unwrap();
        assert!(!verify_rev5_payload(&source, &volume).unwrap());
    }

    #[test]
    fn streaming_rev_rebuilds_missing_volumes_byte_for_byte() {
        // Uneven sizes on purpose: REV pads every volume to the longest, and
        // the padding must never reach the rebuilt file.
        let (data, revs) = build_rev_set(&[600, 512, 480, 640], 2);
        let rev_sources: Vec<MemorySource> =
            revs.iter().map(|bytes| MemorySource(bytes.clone())).collect();
        let metas: Vec<Rev5VolumeRef> = rev_sources
            .iter()
            .map(|source| read_rev5_meta(source).unwrap())
            .collect();
        let slots = metas[0].meta.data_volumes.clone();

        for missing in [vec![1usize], vec![0, 3], vec![2, 3]] {
            let sources: Vec<MemorySource> =
                data.iter().map(|bytes| MemorySource(bytes.clone())).collect();
            let intact: Vec<Option<&dyn crate::recovery::stream::RangeSource>> = (0..data.len())
                .map(|index| {
                    if missing.contains(&index) {
                        None
                    } else {
                        Some(&sources[index] as &dyn crate::recovery::stream::RangeSource)
                    }
                })
                .collect();
            let recovery: Vec<Rev5RecoverySource<'_>> = rev_sources
                .iter()
                .zip(&metas)
                .take(missing.len())
                .map(|(source, meta)| Rev5RecoverySource {
                    row: meta.row().unwrap(),
                    source,
                    payload: meta.payload.clone(),
                })
                .collect();

            let mut rebuilt: Vec<Vec<u8>> = missing
                .iter()
                .map(|&index| vec![0u8; data[index].len()])
                .collect();
            let indices = repair_rev5_volumes_streaming(
                &slots,
                &intact,
                &recovery,
                metas[0].meta.recovery_count as usize,
                64 << 10,
                &mut |slot, offset, bytes| {
                    let start = offset as usize;
                    rebuilt[slot][start..start + bytes.len()].copy_from_slice(bytes);
                    Ok(())
                },
            )
            .unwrap();

            assert_eq!(indices, missing);
            for (slot, &index) in missing.iter().enumerate() {
                assert_eq!(rebuilt[slot], data[index], "missing set {missing:?}");
                assert_eq!(crc32(&rebuilt[slot]), slots[index].crc32);
            }
        }
    }

    /// A REV set the size real releases actually reach: a 100 GB release cut
    /// into 15 MB volumes is ~6,800 data volumes, well past
    /// MAX_RECONSTRUCTION_SHARDS. The striped planner's first cap refused
    /// the slot count outright (`ReconstructionTooLarge`), turning a repair
    /// this crate used to perform into a hard failure - the matrix only ever
    /// costs `damaged * data_count`, so the slot count alone must never be
    /// the reason a repair is refused. Volumes are tiny here so only the
    /// GEOMETRY is large; the repair math is identical.
    #[test]
    fn streaming_rev_repairs_a_set_with_thousands_of_data_volumes() {
        let sizes: Vec<usize> = (0..6_800).map(|index| 24 + (index % 3) * 2).collect();
        let (data, revs) = build_rev_set(&sizes, 2);
        let rev_sources: Vec<MemorySource> =
            revs.iter().map(|bytes| MemorySource(bytes.clone())).collect();
        let metas: Vec<Rev5VolumeRef> = rev_sources
            .iter()
            .map(|source| read_rev5_meta(source).unwrap())
            .collect();
        assert_eq!(metas[0].meta.data_count, 6_800);
        let slots = metas[0].meta.data_volumes.clone();

        let missing = vec![13usize, 5_431];
        let sources: Vec<MemorySource> =
            data.iter().map(|bytes| MemorySource(bytes.clone())).collect();
        let intact: Vec<Option<&dyn crate::recovery::stream::RangeSource>> = (0..data.len())
            .map(|index| {
                (!missing.contains(&index))
                    .then_some(&sources[index] as &dyn crate::recovery::stream::RangeSource)
            })
            .collect();
        let recovery: Vec<Rev5RecoverySource<'_>> = rev_sources
            .iter()
            .zip(&metas)
            .map(|(source, meta)| Rev5RecoverySource {
                row: meta.row().unwrap(),
                source,
                payload: meta.payload.clone(),
            })
            .collect();

        let mut rebuilt: Vec<Vec<u8>> = missing
            .iter()
            .map(|&index| vec![0u8; data[index].len()])
            .collect();
        let indices = repair_rev5_volumes_streaming(
            &slots,
            &intact,
            &recovery,
            metas[0].meta.recovery_count as usize,
            64 << 10,
            &mut |slot, offset, bytes| {
                let start = offset as usize;
                rebuilt[slot][start..start + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(indices, missing);
        for (slot, &index) in missing.iter().enumerate() {
            assert_eq!(rebuilt[slot], data[index], "volume {index} not rebuilt");
            assert_eq!(crc32(&rebuilt[slot]), slots[index].crc32);
        }
    }

    /// The hostile counterpart: headers wider than the GF(2^16) code word,
    /// or dragging a reconstruction-cap recovery count, must die at parse
    /// time - quickly, and before anything is sized from them.
    #[test]
    fn rev_parse_rejects_wire_scale_volume_counts() {
        let (_, revs) = build_rev_set(&[600, 512, 480], 2);
        let started = std::time::Instant::now();

        // 65_535 data + 1 recovery volumes cannot fit the field.
        let mut over_field = revs[0].clone();
        forge_counts(&mut over_field, 65_535, 1, 65_535);
        assert!(read_rev5_meta(&MemorySource(over_field)).is_err());

        // A recovery volume count past the reconstruction cap.
        let mut over_cap = revs[0].clone();
        forge_counts(&mut over_cap, 3, 60_000, 3);
        assert!(read_rev5_meta(&MemorySource(over_cap)).is_err());

        assert!(
            started.elapsed().as_millis() < 500,
            "hostile headers must be refused before anything is sized"
        );
    }

    /// Rewrites a built `.rev`'s count fields and re-CRCs the header, so the
    /// hostile-header tests never build the set the header merely declares.
    fn forge_counts(rev: &mut [u8], data_count: u16, recovery_count: u16, recovery_number: u16) {
        // Header body starts at 16; version byte, then the three u16s.
        rev[17..19].copy_from_slice(&data_count.to_le_bytes());
        rev[19..21].copy_from_slice(&recovery_count.to_le_bytes());
        rev[21..23].copy_from_slice(&recovery_number.to_le_bytes());
        let header_size =
            u32::from_le_bytes(rev[12..16].try_into().unwrap()) as usize;
        let header_crc = crc32(&rev[12..16 + header_size]);
        rev[8..12].copy_from_slice(&header_crc.to_le_bytes());
    }

    /// The 5-volume RAR5 set and its 2 recovery volumes that WinRAR itself
    /// produced (`rar rv`), in `tests/fixtures/rar50`.
    fn winrar_fixture_set() -> (Vec<Vec<u8>>, Vec<std::path::PathBuf>) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar50");
        let volumes = (1..=5)
            .map(|n| std::fs::read(dir.join(format!("multivol_rev.part{n}.rar"))).unwrap())
            .collect();
        let revs = (1..=2)
            .map(|n| dir.join(format!("multivol_rev.part{n}.rev")))
            .collect();
        (volumes, revs)
    }

    #[test]
    fn streaming_rev_rebuilds_real_winrar_volumes_byte_for_byte() {
        // Ground truth. Every other REV test here builds its own fixture with
        // this crate's own encoder, so a misunderstanding of the format would
        // be shared by the builder and the parser and pass unnoticed. These
        // files came out of WinRAR: if our Cauchy matrix, row numbering, shard
        // padding or symbol order disagreed with it in any way, this fails.
        let (volumes, rev_paths) = winrar_fixture_set();
        let rev_sources: Vec<crate::recovery::stream::FileSource> = rev_paths
            .iter()
            .map(|path| crate::recovery::stream::FileSource::open(path).unwrap())
            .collect();
        let metas: Vec<Rev5VolumeRef> = rev_sources
            .iter()
            .map(|source| read_rev5_meta(source).unwrap())
            .collect();

        // The metadata must describe the set WinRAR actually wrote.
        assert_eq!(metas[0].meta.data_count, 5);
        assert_eq!(metas[0].meta.recovery_count, 2);
        assert_eq!(metas[0].row().unwrap(), 0);
        assert_eq!(metas[1].row().unwrap(), 1);
        let slots = metas[0].meta.data_volumes.clone();
        for (slot, volume) in slots.iter().zip(&volumes) {
            assert_eq!(slot.file_size, volume.len() as u64);
            assert_eq!(slot.crc32, crc32(volume));
        }
        for (source, meta) in rev_sources.iter().zip(&metas) {
            assert!(verify_rev5_payload(source, meta).unwrap());
        }

        // Slot 4 is the short trailing volume (1032 bytes against a 4096-byte
        // code word), so these cases also pin that the padding WinRAR encoded
        // over never reaches the rebuilt file.
        for missing in [vec![1usize], vec![0, 4], vec![3, 4]] {
            let sources: Vec<MemorySource> =
                volumes.iter().map(|v| MemorySource(v.clone())).collect();
            let intact: Vec<Option<&dyn crate::recovery::stream::RangeSource>> = (0..volumes.len())
                .map(|index| {
                    (!missing.contains(&index))
                        .then_some(&sources[index] as &dyn crate::recovery::stream::RangeSource)
                })
                .collect();
            let recovery: Vec<Rev5RecoverySource<'_>> = rev_sources
                .iter()
                .zip(&metas)
                .take(missing.len())
                .map(|(source, meta)| Rev5RecoverySource {
                    row: meta.row().unwrap(),
                    source,
                    payload: meta.payload.clone(),
                })
                .collect();

            let mut rebuilt: Vec<Vec<u8>> =
                missing.iter().map(|&i| vec![0u8; volumes[i].len()]).collect();
            let indices = repair_rev5_volumes_streaming(
                &slots,
                &intact,
                &recovery,
                metas[0].meta.recovery_count as usize,
                64 << 10,
                &mut |slot, offset, bytes| {
                    let start = offset as usize;
                    rebuilt[slot][start..start + bytes.len()].copy_from_slice(bytes);
                    Ok(())
                },
            )
            .unwrap();

            assert_eq!(indices, missing);
            for (slot, &index) in missing.iter().enumerate() {
                assert_eq!(
                    rebuilt[slot], volumes[index],
                    "WinRAR volume {} was not rebuilt byte for byte (missing {missing:?})",
                    index + 1
                );
            }
        }
    }

    #[test]
    fn rev_metadata_of_a_multi_gigabyte_volume_is_read_from_its_header_alone() {
        // A genuine multi-gigabyte declared volume, on disk, parsed inside a
        // tiny ceiling. Only the header is ever written, and only the header
        // is ever read - which is the whole claim. The old path called
        // Rev5Volume::parse on std::fs::read of this file, so the declared
        // size IS the assertion: shrink it and a regression to reading the
        // whole volume passes unnoticed.
        //
        // The extension below is sparse on APFS and ext4 but NOT on NTFS,
        // which reserves the clusters unless the file is flagged sparse
        // first (see the fsutil call). That flag is best-effort, so budget
        // for the 8 GB landing on the Windows CI runner's temp volume for
        // real: it fits alone, it is not budget for a second test of this
        // shape. Filling that disk is os error 112 (StorageFull), which is
        // what nzbname_tests.rs once did.
        let (_, revs) = build_rev_set(&[600, 512, 480], 2);
        let header_end = {
            let source = MemorySource(revs[0].clone());
            read_rev5_meta(&source).unwrap().payload.start
        };

        let mut path = std::env::temp_dir();
        path.push(format!("rars-sparse-rev-{}", std::process::id()));
        let declared = 8u64 << 30;
        {
            let mut file = std::fs::File::create(&path).unwrap();
            // "Sparse" is a POSIX assumption. APFS and ext4 give a hole
            // away for free, but NTFS RESERVES every cluster a declared
            // length covers unless the file carries the sparse
            // attribute - so `set_len` below answered ERROR_DISK_FULL
            // (os error 112) on the Windows CI runner, where this test
            // shares a temp volume with the rest of the suite. The
            // attribute is only settable through FSCTL_SET_SPARSE, and
            // this crate forbids `unsafe_code`, so it goes via fsutil
            // rather than DeviceIoControl. Best-effort by design, and
            // silent: a filesystem or a box that refuses just keeps the
            // reserving behaviour, which is still correct wherever the
            // 8 GB is there. Must run before `set_len`, on the created
            // file.
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("fsutil")
                    .args(["sparse", "setflag"])
                    .arg(&path)
                    .output();
            }
            std::io::Write::write_all(&mut file, &revs[0][..header_end as usize]).unwrap();
            // Only the header is ever written; the declared payload is a hole.
            file.set_len(declared).unwrap();
            file.sync_all().unwrap();
        }

        let source = crate::recovery::stream::FileSource::open(&path).unwrap();
        let volume = read_rev5_meta(&source).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(volume.meta.data_count, 3);
        assert_eq!(volume.payload.start, header_end);
        assert_eq!(volume.payload.end, declared);
        assert_eq!(volume.meta.payload_size, declared - header_end);
        assert_eq!(volume.meta.data_volumes.len(), 3);
    }

    #[test]
    fn streaming_rev_refuses_more_missing_volumes_than_recovery_rows() {
        let (data, revs) = build_rev_set(&[600, 512, 480, 640], 2);
        let rev_source = MemorySource(revs[0].clone());
        let meta = read_rev5_meta(&rev_source).unwrap();
        let slots = meta.meta.data_volumes.clone();
        let sources: Vec<MemorySource> =
            data.iter().map(|bytes| MemorySource(bytes.clone())).collect();

        // Three gone, one equation.
        let intact: Vec<Option<&dyn crate::recovery::stream::RangeSource>> = vec![
            None,
            None,
            None,
            Some(&sources[3] as &dyn crate::recovery::stream::RangeSource),
        ];
        let recovery = vec![Rev5RecoverySource {
            row: meta.row().unwrap(),
            source: &rev_source,
            payload: meta.payload.clone(),
        }];
        let error = repair_rev5_volumes_streaming(
            &slots,
            &intact,
            &recovery,
            meta.meta.recovery_count as usize,
            64 << 10,
            &mut |_, _, _| Ok(()),
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Rar5Recovery(crate::recovery::rar5::Error::TooManyDamagedShards)
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn streaming_rev_reports_a_budget_it_cannot_run_in() {
        let (data, revs) = build_rev_set(&[600, 512, 480, 640], 2);
        let rev_source = MemorySource(revs[0].clone());
        let meta = read_rev5_meta(&rev_source).unwrap();
        let slots = meta.meta.data_volumes.clone();
        let sources: Vec<MemorySource> =
            data.iter().map(|bytes| MemorySource(bytes.clone())).collect();
        let intact: Vec<Option<&dyn crate::recovery::stream::RangeSource>> = (0..4)
            .map(|index| {
                (index != 1).then_some(&sources[index] as &dyn crate::recovery::stream::RangeSource)
            })
            .collect();
        let recovery = vec![Rev5RecoverySource {
            row: meta.row().unwrap(),
            source: &rev_source,
            payload: meta.payload.clone(),
        }];

        // A budget under one minimum stripe is a clean refusal, never an
        // attempt that would have to be unbounded.
        let error = repair_rev5_volumes_streaming(
            &slots, &intact, &recovery,
            meta.meta.recovery_count as usize,
            16,
            &mut |_, _, _| Ok(()),
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Rar5Recovery(crate::recovery::rar5::Error::RepairTooLarge)
            ),
            "unexpected error: {error}"
        );
    }
}
