use crate::codec::rar13::Unpack15;
use crate::codec::rar20::Unpack20;
use crate::codec::rar29::Unpack29;
use crate::crc32::{crc32, Crc32};
use crate::crypto::rar15::Rar15Cipher;
use crate::crypto::rar20::Rar20Cipher;
use crate::crypto::rar30::{Error as Rar30Error, Rar30Cipher};
use crate::detect::{find_archive_start, ArchiveSignature, RAR15_SIGNATURE, SFX_SCAN_LIMIT};
use crate::error::{Error, Result};
use crate::features::FeatureSet;
use crate::io_util::{align16 as checked_align16, read_exact_at, read_u16, read_u32};
pub(crate) use crate::source::ArchiveSource;
use crate::version::ArchiveFamily;
use crate::write_entropy::Entropy;
use crate::ArchiveVersion;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

mod extract;
mod write;
pub use extract::{
    extract_volume_sequence_to, extract_volume_sequence_to_with_progress, extract_volumes_to,
    extract_volumes_to_with_progress,
};
use extract::{DecoderSession, DecryptingReader};
pub use write::{
    write_compressed_archive, write_compressed_archive_with_comment,
    write_compressed_archive_with_comment_and_progress, write_compressed_volume_set,
    write_compressed_volumes, write_compressed_volumes_with_progress,
    write_rar29_compressed_archive_with_filter_policy,
    write_rar29_compressed_archive_with_filter_policy_and_progress, write_stored_archive,
    write_stored_archive_with_comment, write_stored_volume_set, write_stored_volumes, FilterKind,
    FilterPolicy, FilterSpec,
};

const MARK_HEAD: u8 = 0x72;
const MAIN_HEAD: u8 = 0x73;
const FILE_HEAD: u8 = 0x74;
const COMM_HEAD: u8 = 0x75;
const SUB_HEAD: u8 = 0x77;
const PROTECT_HEAD: u8 = 0x78;
const NEWSUB_HEAD: u8 = 0x7a;
const ENDARC_HEAD: u8 = 0x7b;

/// Sub type of a RAR 2.x unix-owner sub-block (unrar's `UO_HEAD`), stored at
/// `+11` of a `SUB_HEAD` block.
const UO_HEAD: u16 = 0x0101;
/// Fixed part of a unix-owner sub-block: the 7-byte short header, the 4-byte
/// data size (`SUB_HEAD` always carries `LONG_BLOCK`), sub type, level, and
/// the two name sizes (unrar's `SIZEOF_UOWNERHEAD`).
const SIZEOF_UOWNERHEAD: usize = 18;

const LONG_BLOCK: u16 = 0x8000;
/// A block a reader may skip whole when it does not know the type. Set
/// on the recovery-record NEWSUB, exactly as `rar` sets it, so a reader
/// that has never heard of `RR` steps over it rather than refusing the
/// archive.
const SKIP_IF_UNKNOWN: u16 = 0x4000;
const MHD_VOLUME: u16 = 0x0001;
const MHD_COMMENT: u16 = 0x0002;
const MHD_SOLID: u16 = 0x0008;
const MHD_NEWNUMBERING: u16 = 0x0010;
const MHD_PROTECT: u16 = 0x0040;
const MHD_PASSWORD: u16 = 0x0080;
const MHD_FIRSTVOLUME: u16 = 0x0100;
const MHD_ENCRYPTVER: u16 = 0x0200;

/// End-of-archive flag: another volume of this set follows.
///
/// A reader that reaches an `ENDARC` without it treats the set as
/// finished, which is how a multi-member volume set loses every member
/// after the first (see `write::finish_volume`).
const EARC_NEXT_VOLUME: u16 = 0x0001;
const FHD_SPLIT_BEFORE: u16 = 0x0001;
const FHD_SPLIT_AFTER: u16 = 0x0002;
const FHD_PASSWORD: u16 = 0x0004;
const FHD_COMMENT: u16 = 0x0008;
const FHD_SOLID: u16 = 0x0010;
const FHD_LARGE: u16 = 0x0100;
const FHD_UNICODE: u16 = 0x0200;
const FHD_SALT: u16 = 0x0400;
const FHD_EXTTIME: u16 = 0x1000;
const FHD_DIRECTORY_MASK: u16 = 0x00e0;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Archive {
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub blocks: Vec<Block>,
    source: ArchiveSource,
    /// Archive-relative offset of the first block the header walk did
    /// not read, when [`Self::parse_stream_incremental`] stopped at the
    /// arrival frontier; `None` for a fully enumerated archive.
    pending_from: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MainHeader {
    pub head_crc: u16,
    pub flags: u16,
    pub head_size: u16,
    pub reserved1: u16,
    pub reserved2: u32,
    pub encrypt_version: Option<u8>,
}

impl MainHeader {
    pub fn has_archive_comment(&self) -> bool {
        self.flags & MHD_COMMENT != 0
    }

    pub fn is_volume(&self) -> bool {
        self.flags & MHD_VOLUME != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHD_SOLID != 0
    }

    pub fn uses_new_numbering(&self) -> bool {
        self.flags & MHD_NEWNUMBERING != 0
    }

    pub fn has_recovery_record(&self) -> bool {
        self.flags & MHD_PROTECT != 0
    }

    pub fn has_encrypted_headers(&self) -> bool {
        self.flags & MHD_PASSWORD != 0
    }

    pub fn is_first_volume(&self) -> bool {
        self.flags & MHD_FIRSTVOLUME != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Block {
    File(FileHeader),
    Comment(CommentHeader),
    Protect(ProtectHeader),
    NewSub(NewSubHeader),
    End(BlockHeader),
    Unknown(BlockHeader),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockHeader {
    pub head_crc: u16,
    pub head_type: u8,
    pub flags: u16,
    pub head_size: u16,
    pub add_size: Option<u64>,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHeader {
    pub block: BlockHeader,
    pub pack_size: u64,
    pub unp_size: u64,
    pub host_os: u8,
    pub file_crc: u32,
    pub file_time: u32,
    pub unp_ver: u8,
    pub method: u8,
    pub name: Vec<u8>,
    pub attr: u32,
    pub salt: Option<[u8; 8]>,
    pub file_comment: Vec<u8>,
    pub ext_time: Vec<u8>,
    pub packed_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewSubHeader {
    pub file: FileHeader,
    pub kind: NewSubKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommentHeader {
    pub block: BlockHeader,
    pub unp_size: u16,
    pub unp_ver: u8,
    pub method: u8,
    pub comment_crc: u16,
    pub packed_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProtectHeader {
    pub block: BlockHeader,
    pub version: u8,
    pub rec_sectors: u16,
    pub total_blocks: u32,
    pub mark: [u8; 8],
    pub data_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NewSubKind {
    ArchiveComment,
    RecoveryRecord,
    Unknown(Vec<u8>),
}

/// How the volumes of a set are NAMED on disk.
///
/// The writer never sees a file name - it returns one byte vector per
/// volume and the caller decides what to call each one - so the naming
/// convention cannot be inferred here and has to be declared. It matters
/// because a reference reader finds the next volume by computing its
/// NAME, and `MHD_NEWNUMBERING` in the main header is what tells it
/// which rule to compute with.
///
/// Measured against `unrar` 7.23 on 4 Sep 2026, with the real RAR 3.00
/// sets in `tests/fixtures/rar15_40/rar300/` as the reference for what
/// `rar` itself writes (`multivol_oldnaming_*` clears the bit on every
/// volume, `multivol_newnaming_*` sets it on every volume, and the two
/// sets differ by nothing else but their header CRCs and a two-second
/// file time):
///
/// | volumes named | bit clear | bit set |
/// |---|---|---|
/// | `set.rar`, `set.r00`, ... | extracts | extracts |
/// | `set.part01.rar`, ... | **refuses** | extracts |
/// | `set.001`, `set.002`, ... | extracts | extracts |
///
/// The refusal is `Cannot find volume set.part01.r00` - unrar swaps the
/// EXTENSION of the first volume's name, so `set.part01` reads as the
/// stem - followed by a checksum error on the member it had to
/// truncate. It exits 6.
///
/// So the bit is REQUIRED for `.partNN.rar` and merely tolerated
/// elsewhere; leaving it clear under that naming produces a set only a
/// reader that is told the volume list can follow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum VolumeNumbering {
    /// `set.rar`, `set.r00`, `set.r01`, ... `MHD_NEWNUMBERING` clear.
    ///
    /// The default, because it is what every volume this writer has ever
    /// emitted claims, and changing what an existing caller writes is
    /// not this type's job.
    #[default]
    Classic,
    /// `set.part01.rar`, `set.part02.rar`, ... `MHD_NEWNUMBERING` set on
    /// EVERY volume of the set, which is what `rar` does.
    NewStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriterOptions {
    pub target: ArchiveVersion,
    pub features: FeatureSet,
    pub compression_level: Option<u8>,
    pub dictionary_size: Option<usize>,
    /// Where the encryption salt comes from. [`Entropy::Os`] by
    /// default; see [`Entropy::Seeded`] before changing it.
    pub entropy: Entropy,
    /// What the caller will NAME the volumes, which decides
    /// `MHD_NEWNUMBERING`. Read by the four volume writers
    /// ([`write_stored_volumes`], [`write_compressed_volumes`],
    /// [`write_stored_volume_set`], [`write_compressed_volume_set`])
    /// and by nothing else - a single-archive write has no volumes to
    /// number and ignores it.
    pub volume_numbering: VolumeNumbering,
    /// Percent of the archive to spend on an embedded ("Protect+")
    /// recovery record, or `None` for no record. Requires
    /// `features.recovery_record`; see
    /// [`WriterOptions::with_recovery_percent`].
    pub recovery_percent: Option<u32>,
}

impl WriterOptions {
    pub const fn new(target: ArchiveVersion, features: FeatureSet) -> Self {
        Self {
            target,
            features,
            compression_level: None,
            dictionary_size: None,
            entropy: Entropy::Os,
            volume_numbering: VolumeNumbering::Classic,
            recovery_percent: None,
        }
    }

    /// Chooses where the writer draws its encryption salt.
    ///
    /// Leave it alone for a real archive. [`Entropy::Seeded`] is for
    /// reproducible test generation and weakens what it feeds.
    pub const fn with_entropy(mut self, entropy: Entropy) -> Self {
        self.entropy = entropy;
        self
    }

    /// Declares what the caller will name the volumes.
    ///
    /// Must AGREE with the names the caller then writes: see
    /// [`VolumeNumbering`] for the measured table of what a reference
    /// reader does with each pairing.
    pub const fn with_volume_numbering(mut self, numbering: VolumeNumbering) -> Self {
        self.volume_numbering = numbering;
        self
    }

    pub const fn with_compression_level(mut self, level: u8) -> Self {
        self.compression_level = Some(level);
        self
    }

    pub const fn with_dictionary_size(mut self, size: usize) -> Self {
        self.dictionary_size = Some(size);
        self
    }

    /// Asks for an embedded recovery record of `percent` of the archive.
    ///
    /// This is only half the request: `features.recovery_record` has to
    /// be on as well, and the writer refuses the pair when it cannot
    /// build one (a RAR 1.5 or 2.0 target, a header-encrypted archive, a
    /// volume set). Setting the percent alone writes no record - the
    /// feature flag is what the validators compare against, and a
    /// percent with the flag off is refused rather than ignored.
    pub const fn with_recovery_percent(mut self, percent: u32) -> Self {
        self.recovery_percent = Some(percent);
        self
    }
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: ArchiveVersion::Rar15,
            features: FeatureSet::store_only(),
            compression_level: None,
            dictionary_size: None,
            entropy: Entropy::Os,
            volume_numbering: VolumeNumbering::Classic,
            recovery_percent: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u32,
    pub host_os: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u32,
    pub host_os: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub attr: u32,
    pub host_os: u8,
    pub is_directory: bool,
    /// The member's declared unpacked size (every fragment of a split
    /// member repeats the total).
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
        self.block.flags & FHD_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.block.flags & FHD_SPLIT_AFTER != 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.block.flags & FHD_PASSWORD != 0
    }

    pub fn is_solid(&self) -> bool {
        self.block.flags & FHD_SOLID != 0
    }

    pub fn is_directory(&self) -> bool {
        self.block.flags & FHD_DIRECTORY_MASK == FHD_DIRECTORY_MASK
    }

    pub fn has_ext_time(&self) -> bool {
        self.block.flags & FHD_EXTTIME != 0
    }

    pub fn has_file_comment(&self) -> bool {
        self.block.flags & FHD_COMMENT != 0 && !self.file_comment.is_empty()
    }

    pub fn file_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.has_file_comment() {
            return Ok(None);
        }
        let size = read_u16(&self.file_comment, 0)? as usize;
        let start = 2usize;
        let end = start
            .checked_add(size)
            .ok_or(Error::InvalidHeader("RAR 1.5 file comment size overflows"))?;
        let comment = self.file_comment.get(start..end).ok_or(Error::TooShort)?;
        Ok(Some(comment.to_vec()))
    }

    pub fn is_stored(&self) -> bool {
        self.method == 0x30
    }

    pub fn packed_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        archive.read_range(self.packed_range.clone())
    }

    pub fn write_packed_data(&self, archive: &Archive, out: &mut impl Write) -> Result<()> {
        archive.copy_range_to(self.packed_range.clone(), out)
    }

    pub(crate) fn stored_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        self.stored_data_with_password(archive, None)
    }

    pub(crate) fn stored_data_with_password(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if !self.is_stored() {
            return Err(self.unsupported_compression());
        }
        if !self.is_encrypted() && self.pack_size != self.unp_size {
            return Err(Error::InvalidHeader(
                "RAR 1.5 stored file has mismatched packed and unpacked sizes",
            ));
        }
        let mut data = self.packed_data_for_decode(archive, password)?;
        if self.is_encrypted() {
            data.truncate(
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?,
            );
        }
        Ok(data)
    }

    pub(crate) fn unpacked_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        if self.is_stored() {
            return self.stored_data(archive);
        }
        let mut session = DecoderSession::new(false);
        session.decode_file_data(archive, self)
    }

    pub(crate) fn unpacked_data_with_rar29(
        &self,
        archive: &Archive,
        decoder: &mut Unpack29,
        solid: bool,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            return self.stored_data(archive);
        }
        if self.is_encrypted() {
            return Err(self.unsupported_encryption());
        }
        if self.unp_ver < 29 {
            return Err(self.unsupported_compression());
        }
        let packed = self.packed_data(archive)?;
        let target = usize::try_from(self.unp_size)
            .map_err(|_| Error::InvalidHeader("RAR 2.9 unpacked size overflows usize"))?;
        if solid {
            decoder.decode_member(&packed, target)
        } else {
            decoder.decode_non_solid_member(&packed, target)
        }
        .map_err(Into::into)
    }

    pub(crate) fn unpacked_data_with_unpack15(
        &self,
        archive: &Archive,
        decoder: &mut Unpack15,
        solid: bool,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            return self.stored_data(archive);
        }
        if self.is_encrypted() {
            return Err(self.unsupported_encryption());
        }
        if self.unp_ver != 15 {
            return Err(self.unsupported_compression());
        }
        decoder
            .decode_member(
                &self.packed_data(archive)?,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?,
                solid,
            )
            .map_err(Into::into)
    }

    pub(crate) fn unpacked_data_with_unpack20(
        &self,
        archive: &Archive,
        decoder: &mut Unpack20,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            return self.stored_data_with_password(archive, password);
        }
        if self.unp_ver != 20 && self.unp_ver != 26 {
            return Err(self.unsupported_compression());
        }
        let mut packed = self.packed_reader_for_decode(archive, password)?;
        let mut out = Vec::new();
        decoder
            .decode_member_from_reader(
                &mut packed,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 2.0 unpacked size overflows usize"))?,
                &mut out,
            )
            .map(|_| out)
            .map_err(Into::into)
    }

    fn packed_data_for_decode(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut reader = self.packed_reader_for_decode(archive, password)?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(data)
    }

    pub(super) fn packed_reader_for_decode<'a>(
        &self,
        archive: &'a Archive,
        password: Option<&[u8]>,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        let reader = archive.range_reader(self.packed_range.clone())?;
        if !self.is_encrypted() {
            return Ok(reader);
        }
        let Some(password) = password else {
            return Err(Error::NeedPassword);
        };
        if (self.unp_ver == 20 || self.unp_ver == 26 || self.unp_ver >= 29)
            && !self.packed_range.len().is_multiple_of(16)
        {
            return Err(Error::InvalidHeader(
                "RAR encrypted payload is not block aligned",
            ));
        }
        Ok(Box::new(DecryptingReader::new(
            reader,
            self.unp_ver,
            password,
            self.salt,
        )?))
    }

    pub fn verify_crc32(&self, data: &[u8]) -> Result<()> {
        let actual = crc32(data);
        if actual == self.file_crc {
            Ok(())
        } else {
            Err(Error::Crc32Mismatch {
                expected: self.file_crc,
                actual,
            })
        }
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: self.is_directory(),
            unpacked_size: self.unp_size,
        }
    }

    pub fn write_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_directory() {
            return Ok(());
        }
        let mut session = DecoderSession::new_with_password(false, password);
        session.write_file_to(archive, self, out)
    }

    fn write_stored_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if !self.is_stored() {
            return Err(self.unsupported_compression());
        }
        if !self.is_encrypted() && self.pack_size != self.unp_size {
            return Err(Error::InvalidHeader(
                "RAR 1.5 stored file has mismatched packed and unpacked sizes",
            ));
        }
        let mut reader = self
            .packed_reader_for_decode(archive, password)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        let expected_len = usize::try_from(self.unp_size)
            .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?;
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        let copied = std::io::copy(
            &mut reader.by_ref().take(expected_len as u64),
            &mut crc_writer,
        )?;
        if copied != expected_len as u64 {
            return Err(self.map_encrypted_payload_error(
                password,
                Error::InvalidHeader("RAR 1.5 stored file ended before unpacked size"),
            ));
        }
        let actual = crc.finish();
        if actual == self.file_crc {
            Ok(())
        } else {
            Err(self.map_encrypted_payload_error(
                password,
                Error::Crc32Mismatch {
                    expected: self.file_crc,
                    actual,
                },
            ))
        }
    }

    fn map_encrypted_payload_error(&self, password: Option<&[u8]>, error: Error) -> Error {
        if !self.is_encrypted() || password.is_none() {
            return error;
        }
        match error {
            Error::NeedPassword => Error::NeedPassword,
            Error::UnsupportedSignature
            | Error::UnsupportedVersion(_)
            | Error::UnsupportedFeature { .. }
            | Error::Rar50BufferedDecodeLimitExceeded { .. }
            | Error::Rar50WindowLimitExceeded { .. }
            | Error::UnsupportedFamilyFeature { .. }
            | Error::UnsupportedCompression { .. }
            | Error::UnsupportedEncryption { .. }
            | Error::TooShort
            | Error::Io(_)
            | Error::AtArchiveOffset { .. }
            | Error::AtEntry { .. }
            // The fragment CRC covers the PACKED bytes as stored - the
            // ciphertext for an encrypted member - so a mismatch proves
            // on-disk damage and is never a wrong-password symptom.
            | Error::SplitFragmentCrc32Mismatch { .. }
            | Error::SplitFragmentHashMismatch { .. }
            // A repair budget shortfall is a resource condition, never a
            // wrong-password symptom.
            | Error::LegacyRepairTooLarge
            | Error::Cancelled => error,
            Error::InvalidHeader(_)
            | Error::Codec(_)
            | Error::Rar3Recovery(_)
            | Error::Rar5Recovery(_)
            | Error::Rar20Crypto(_)
            | Error::Rar30Crypto(_)
            | Error::Rar50Crypto(_)
            | Error::CrcMismatch { .. }
            | Error::Crc32Mismatch { .. }
            | Error::HashMismatch { .. }
            | Error::WrongPasswordOrCorruptData => Error::WrongPasswordOrCorruptData,
        }
    }

    fn entry_error(&self, operation: &'static str, error: Error) -> Error {
        if matches!(
            error,
            Error::NeedPassword | Error::WrongPasswordOrCorruptData
        ) {
            return error;
        }
        error.at_entry(self.name.clone(), operation)
    }

    fn crc_result(&self, actual: u32, password: Option<&[u8]>) -> Result<()> {
        if actual == self.file_crc {
            Ok(())
        } else {
            Err(self.map_encrypted_payload_error(
                password,
                Error::Crc32Mismatch {
                    expected: self.file_crc,
                    actual,
                },
            ))
        }
    }

    fn write_rar29_to(
        &self,
        archive: &Archive,
        decoder: &mut Unpack29,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() {
            return self.write_stored_to(archive, None, out);
        }
        if self.is_encrypted() {
            return Err(self.unsupported_encryption());
        }
        if self.unp_ver < 29 {
            return Err(self.unsupported_compression());
        }

        let mut packed = archive.range_reader(self.packed_range.clone())?;
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        decoder
            .decode_member_from_reader(
                &mut packed,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?,
                &mut crc_writer,
            )
            .map_err(Error::from)?;
        let actual = crc.finish();
        if actual == self.file_crc {
            Ok(())
        } else {
            Err(Error::Crc32Mismatch {
                expected: self.file_crc,
                actual,
            })
        }
    }

    fn write_unpack15_to(
        &self,
        archive: &Archive,
        decoder: &mut Unpack15,
        solid: bool,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() {
            return self.write_stored_to(archive, password, out);
        }
        if self.unp_ver != 15 {
            return Err(self.unsupported_compression());
        }

        let mut input = self
            .packed_reader_for_decode(archive, password)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        self.write_unpack15_decoded(decoder, solid, &mut input, out, password)
            .map_err(|error| self.map_encrypted_payload_error(password, error))
    }

    fn write_unpack15_decoded(
        &self,
        decoder: &mut Unpack15,
        solid: bool,
        input: &mut impl Read,
        out: &mut impl Write,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        decoder
            .decode_member_from_reader(
                input,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?,
                solid,
                &mut crc_writer,
            )
            .map_err(Error::from)?;
        let actual = crc.finish();
        self.crc_result(actual, password)
    }

    fn write_unpack20_to(
        &self,
        archive: &Archive,
        decoder: &mut Unpack20,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() {
            return self.write_stored_to(archive, password, out);
        }
        if self.unp_ver != 20 && self.unp_ver != 26 {
            return Err(self.unsupported_compression());
        }

        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        let target = usize::try_from(self.unp_size)
            .map_err(|_| Error::InvalidHeader("RAR 2.0 unpacked size overflows usize"))?;
        let mut packed = self
            .packed_reader_for_decode(archive, password)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        decoder
            .decode_member_from_reader(&mut packed, target, &mut crc_writer)
            .map_err(Error::from)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        let actual = crc.finish();
        self.crc_result(actual, password)
    }

    fn unsupported_compression(&self) -> Error {
        Error::UnsupportedCompression {
            family: "RAR 1.5-4.x",
            unpack_version: self.unp_ver,
            method: self.method,
        }
    }

    fn unsupported_encryption(&self) -> Error {
        Error::UnsupportedEncryption {
            family: "RAR 1.5-4.x",
            unpack_version: self.unp_ver,
        }
    }
}

impl NewSubHeader {
    pub fn name_bytes(&self) -> &[u8] {
        self.file.name_bytes()
    }

    /// Returns the service-block name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        self.file.name_lossy()
    }
}

impl CommentHeader {
    fn packed_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        archive.read_range(self.packed_range.clone())
    }

    fn unpacked_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        let target = usize::from(self.unp_size);
        let data = if self.method == 0x30 {
            let data = self.packed_data(archive)?;
            if data.len() != target {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 stored comment has mismatched packed and unpacked sizes",
                ));
            }
            data
        } else if self.unp_ver == 15 {
            Unpack15::default().decode_member(&self.packed_data(archive)?, target, false)?
        } else {
            return Err(Error::UnsupportedCompression {
                family: "RAR 1.5 comment",
                unpack_version: self.unp_ver,
                method: self.method,
            });
        };
        let actual = (crc32(&data) & 0xffff) as u16;
        if actual == self.comment_crc {
            Ok(data)
        } else {
            Err(Error::CrcMismatch {
                expected: self.comment_crc,
                actual,
            })
        }
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
        if sig.family != ArchiveFamily::Rar15To40 {
            return Err(Error::UnsupportedSignature);
        }
        Self::parse_seekable(file, len, sig.offset, ArchiveSource::File(path), password)
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
        if signature.family != ArchiveFamily::Rar15To40 {
            return Err(Error::UnsupportedSignature);
        }
        let path = Arc::new(path.as_ref().to_path_buf());
        let file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        Self::parse_seekable(
            file,
            len,
            signature.offset,
            ArchiveSource::File(path),
            password,
        )
    }

    fn parse_shared(input: Arc<[u8]>, password: Option<&[u8]>) -> Result<Self> {
        let sig = find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar15To40 {
            return Err(Error::UnsupportedSignature);
        }

        let archive = &input[sig.offset..];
        if !archive.starts_with(RAR15_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let marker = parse_block_header(archive, 0)?;
        if marker.head_type != MARK_HEAD || marker.head_size != RAR15_SIGNATURE.len() as u16 {
            return Err(Error::InvalidHeader("RAR 1.5 marker block is invalid"));
        }

        let main_block = parse_block_header(archive, marker.head_size as usize)?;
        if main_block.head_type != MAIN_HEAD {
            return Err(Error::InvalidHeader("RAR 1.5 main header is missing"));
        }
        let main = parse_main_header(archive, &main_block)?;
        let mut pos = main_block.offset + main_block.head_size as usize;
        let mut blocks = Vec::new();
        let mut encrypted_header_ciphers = EncryptedHeaderCipherCache::default();

        while pos < archive.len() {
            if archive.len() - pos < 7 {
                break;
            }
            let (block, header, total) = if main.has_encrypted_headers() {
                let password = password.ok_or(Error::NeedPassword)?;
                let encrypted = decrypt_encrypted_header_at(
                    archive,
                    pos,
                    password,
                    &mut encrypted_header_ciphers,
                )?;
                (encrypted.block, encrypted.header, encrypted.total_size)
            } else {
                let block = parse_block_header(archive, pos)?;
                let total = block_total_size(&block)?;
                let header = archive[pos..pos + block.head_size as usize].to_vec();
                (block, header, total)
            };
            match block.head_type {
                FILE_HEAD => {
                    let mut file = parse_file_like_header(&header, relative_block(&block), 0)?;
                    let total = file_block_total_size(&block, total, file.pack_size)?;
                    let next = checked_block_next(&block, total, archive.len())?;
                    file.block.offset = block.offset;
                    file.packed_range =
                        packed_range(sig.offset, block.offset, total, file.pack_size)?;
                    blocks.push(Block::File(file));
                    pos = next;
                }
                NEWSUB_HEAD => {
                    let mut file = parse_file_like_header(&header, relative_block(&block), 0)?;
                    let total = file_block_total_size(&block, total, file.pack_size)?;
                    let next = checked_block_next(&block, total, archive.len())?;
                    file.block.offset = block.offset;
                    file.packed_range =
                        packed_range(sig.offset, block.offset, total, file.pack_size)?;
                    let kind = classify_new_sub(&file.name);
                    blocks.push(Block::NewSub(NewSubHeader { file, kind }));
                    pos = next;
                }
                COMM_HEAD => {
                    let next = checked_block_next(&block, total, archive.len())?;
                    let mut comment = parse_comment_header(&header, relative_block(&block))?;
                    comment.block.offset = block.offset;
                    comment.packed_range =
                        sig.offset + block.offset + 13..sig.offset + block.offset + total;
                    blocks.push(Block::Comment(comment));
                    pos = next;
                }
                PROTECT_HEAD => {
                    let next = checked_block_next(&block, total, archive.len())?;
                    let protect = parse_protect_header(&header, &block, sig.offset, total)?;
                    blocks.push(Block::Protect(protect));
                    pos = next;
                }
                ENDARC_HEAD => {
                    let _next = checked_block_next(&block, total, archive.len())?;
                    blocks.push(Block::End(block));
                    break;
                }
                _ => {
                    let next = checked_block_next(&block, total, archive.len())?;
                    blocks.push(Block::Unknown(block));
                    pos = next;
                }
            }
        }

        Ok(Self {
            sfx_offset: sig.offset,
            main,
            blocks,
            source: ArchiveSource::Memory(input),
            pending_from: None,
        })
    }

    /// Parses an archive whose bytes are still arriving.
    ///
    /// `expected_len` is the archive's final size (the caller knows it up
    /// front) and bounds every read; the source only needs to deliver bytes
    /// toward it. Reads BLOCK at the data frontier - through
    /// [`ArchiveSource::read_range`] - so this call, and any later
    /// extraction from the returned archive, waits for missing bytes
    /// instead of failing. Same walk as the file-backed parse: each
    /// member's header precedes its data and data areas are skipped
    /// arithmetically, so the parse cursor trails the arrival frontier and
    /// returns once this volume's headers (through the end of the file
    /// list) are readable.
    ///
    /// The archive signature must sit at offset 0: streaming sources carry
    /// payloads whose start is already known, so no SFX stub scan is done.
    pub fn parse_stream(
        source: std::sync::Arc<dyn crate::source::BlockingRangeSource>,
        expected_len: u64,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        let archive_len = usize::try_from(expected_len).map_err(|_| {
            Error::InvalidHeader("RAR 1.5 archive size overflows host address size")
        })?;
        let source = ArchiveSource::Stream {
            source,
            len: archive_len,
        };
        let signature = source.read_range(0..RAR15_SIGNATURE.len())?;
        if signature != *RAR15_SIGNATURE {
            return Err(Error::UnsupportedSignature);
        }
        let mut walk = SourceWalk {
            source: source.clone(),
            len: expected_len,
        };
        Self::parse_walk(&mut walk, 0, source, options.password, None)
    }

    /// [`Self::parse_stream`] that does not wait for the volume's tail.
    ///
    /// The RAR4 twin of `rar50::Archive::parse_stream_incremental`, for
    /// the same reason (nzbkit TODO 220): the eager walk's last read is
    /// the end block at the volume TAIL, so a caller holding the volume
    /// under a retention cap could not start decoding it until all of
    /// it had arrived, and a volume larger than the cap breached the cap
    /// with nothing to release. This walk stops where the arrived bytes
    /// stop (`BlockingRangeSource::known_len`) and reports the archive
    /// [`Self::is_partially_enumerated`]; [`Self::enumerate_rest`]
    /// finishes it, blocking, and must run before `files()` is read as
    /// the whole volume. The volume-sequence driver does exactly that.
    pub fn parse_stream_incremental(
        source: std::sync::Arc<dyn crate::source::BlockingRangeSource>,
        expected_len: u64,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        let archive_len = usize::try_from(expected_len).map_err(|_| {
            Error::InvalidHeader("RAR 1.5 archive size overflows host address size")
        })?;
        let frontier = source.clone();
        let source = ArchiveSource::Stream {
            source,
            len: archive_len,
        };
        let signature = source.read_range(0..RAR15_SIGNATURE.len())?;
        if signature != *RAR15_SIGNATURE {
            return Err(Error::UnsupportedSignature);
        }
        let mut walk = SourceWalk {
            source: source.clone(),
            len: expected_len,
        };
        // Clamped to the declared length: a source reporting more
        // arrived than the volume holds must not lift the stop above
        // the walk's own bound.
        let arrived = move || frontier.known_len().min(expected_len) as usize;
        Self::parse_walk(&mut walk, 0, source, options.password, Some(&arrived))
    }

    /// Has the header walk stopped short of the archive's end because
    /// the bytes it would have to read had not arrived? See
    /// [`Self::parse_stream_incremental`]; false for every other parse.
    pub fn is_partially_enumerated(&self) -> bool {
        self.pending_from.is_some()
    }

    /// Finish a walk [`Self::parse_stream_incremental`] stopped early,
    /// BLOCKING on the bytes it needs. A no-op on any other archive.
    ///
    /// RESUMES at the stop offset, keeping the main header and every
    /// block already parsed - NOT a re-walk from the signature, which is
    /// what the first cut of the RAR5 twin did and what nzbkit TODO 250
    /// measured costing a chase 1.0x of payload: by the time the deferred
    /// walk runs the caller has released the volume's prefix (that is the
    /// point of deferring it), so a read at the signature lands behind
    /// the trim point and the chase fails. The stop offset itself is safe to
    /// read: it is where the last enumerated member's packed data ENDS,
    /// which is exactly the engine's consumption watermark, and a trim
    /// releases only bytes below that. The already-enumerated prefix is
    /// untouched by construction, so the `(volume, file_index)` pairs a
    /// caller holds keep pointing at the same entries.
    pub fn enumerate_rest(&mut self, password: Option<&[u8]>) -> Result<()> {
        let Some(pos) = self.pending_from else {
            return Ok(());
        };
        let len = match &self.source {
            ArchiveSource::Stream { len, .. } => *len as u64,
            // Unreachable: only the stream-source parse stops early.
            _ => return Ok(()),
        };
        let mut walk = SourceWalk {
            source: self.source.clone(),
            len,
        };
        let pending_from = walk_blocks(
            &mut walk,
            self.sfx_offset,
            &self.main,
            pos,
            &mut self.blocks,
            password,
            None,
        )?;
        debug_assert!(
            pending_from.is_none(),
            "an unbounded walk cannot stop short"
        );
        self.pending_from = None;
        Ok(())
    }

    fn parse_seekable(
        file: File,
        file_len: u64,
        sfx_offset: usize,
        source: ArchiveSource,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        let mut walk = FileWalk {
            file,
            len: file_len,
        };
        Self::parse_walk(&mut walk, sfx_offset, source, password, None)
    }

    /// `arrived`, when given, is how many bytes of the source are
    /// readable without blocking; the walk stops before the first block
    /// header at or past it (after reading at least one block) and
    /// records where in `pending_from`.
    fn parse_walk(
        file: &mut impl WalkSource,
        sfx_offset: usize,
        source: ArchiveSource,
        password: Option<&[u8]>,
        arrived: Option<&dyn Fn() -> usize>,
    ) -> Result<Self> {
        let file_len = file.source_len();
        let marker = read_block_header_at(file, file_len, sfx_offset, 0)?;
        if marker.head_type != MARK_HEAD || marker.head_size != RAR15_SIGNATURE.len() as u16 {
            return Err(Error::InvalidHeader("RAR 1.5 marker block is invalid"));
        }

        let main_block = read_block_header_at(file, file_len, sfx_offset, marker.head_size as usize)?;
        if main_block.head_type != MAIN_HEAD {
            return Err(Error::InvalidHeader("RAR 1.5 main header is missing"));
        }
        let main_header = file.read_at(
            sfx_offset + main_block.offset,
            main_block.head_size as usize,
        )?;
        let main = parse_main_header(&main_header, &relative_block(&main_block))?;
        let pos = main_block.offset + main_block.head_size as usize;
        let mut blocks = Vec::new();
        let pending_from =
            walk_blocks(file, sfx_offset, &main, pos, &mut blocks, password, arrived)?;

        Ok(Self {
            sfx_offset,
            main,
            blocks,
            source,
            pending_from,
        })
    }

    fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>> {
        self.source.read_range(range)
    }

    fn copy_range_to(&self, range: Range<usize>, out: &mut impl Write) -> Result<()> {
        self.source.copy_range_to(range, out)
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

    pub fn files(&self) -> impl Iterator<Item = &FileHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::File(file) => Some(file),
            _ => None,
        })
    }

    pub fn new_subs(&self) -> impl Iterator<Item = &NewSubHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::NewSub(sub) => Some(sub),
            _ => None,
        })
    }

    pub fn protect_records(&self) -> impl Iterator<Item = &ProtectHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::Protect(protect) => Some(protect),
            _ => None,
        })
    }

    fn source_bytes(&self) -> Result<Vec<u8>> {
        self.source.bytes()
    }

    pub fn repair_protect_head(&self) -> Result<Vec<u8>> {
        if let Some(recovery) = self
            .new_subs()
            .find(|sub| sub.kind == NewSubKind::RecoveryRecord)
        {
            return repair_newsub_recovery_bytes(
                &self.source_bytes()?,
                self.sfx_offset,
                self,
                recovery,
            );
        }
        let protect = self.protect_records().next().ok_or(Error::InvalidHeader(
            "RAR 2.x archive does not contain a PROTECT_HEAD recovery record",
        ))?;
        repair_protect_head_bytes(&self.source_bytes()?, self.sfx_offset, protect)
    }

    /// Streaming form of [`Self::repair_protect_head`]: `dest` receives a
    /// full copy of the archive and is then patched in place over the
    /// damaged 512-byte sectors, so no part of the volume is ever fully
    /// resident. [`Self::repair_protect_head`] holds the source plus a
    /// repaired copy - over 2x a volume - which is fine for the small
    /// archives these records were designed around and fatal for a
    /// multi-GB usenet volume.
    ///
    /// `budget` bounds the working set (a compressed RAR 3.x NEWSUB record
    /// must be decoded whole, and each damaged sector holds one 512-byte
    /// accumulator); a repair that cannot fit returns
    /// [`Error::LegacyRepairTooLarge`]. (nzbfast-local change, 20 Aug 2026 -
    /// this and the `ProtectPlan` machinery below; see
    /// vendor/rars/VENDORING.md.)
    ///
    /// Returns the damaged sector indices that were rebuilt (empty when the
    /// recovery record says nothing is damaged). The archive itself is never
    /// written to; publishing `dest` is the caller's decision.
    pub fn repair_protect_to_file(&self, dest: &mut File, budget: u64) -> Result<Vec<usize>> {
        self.repair_protect_impl(dest, false, budget)
    }

    /// [`Self::repair_protect_to_file`] for a caller that owns the
    /// destination PATH. When the archive was opened from a file the initial
    /// whole-volume copy becomes a filesystem clone where the platform
    /// supports one (APFS, btrfs/XFS reflink); any other source shape takes
    /// the same streaming copy as the file form.
    pub fn repair_protect_to_path(&self, dest: &Path, budget: u64) -> Result<Vec<usize>> {
        let prefilled = match &self.source {
            ArchiveSource::File(path) => crate::recovery::stream::clone_prefill(path, dest)?,
            _ => false,
        };
        // O_NOFOLLOW - see `Rar50Archive::repair_recovery_to_path`.
        let mut out = crate::recovery::stream::open_repair_dest(dest)?;
        if !prefilled {
            out.set_len(0)?;
        }
        self.repair_protect_impl(&mut out, prefilled, budget)
    }

    fn repair_protect_impl(
        &self,
        dest: &mut File,
        dest_prefilled: bool,
        budget: u64,
    ) -> Result<Vec<usize>> {
        use std::io::{Seek as _, SeekFrom};

        let source_len = self.source.len()?;
        // Same record precedence as repair_protect_head: a RAR 3.x NEWSUB
        // recovery record wins over an old-style RAR 2.x PROTECT_HEAD.
        let (plan, recovery) = if let Some(recovery) = self
            .new_subs()
            .find(|sub| sub.kind == NewSubKind::RecoveryRecord)
        {
            newsub_protect_plan(self, recovery, source_len, budget)?
        } else {
            let protect = self.protect_records().next().ok_or(Error::InvalidHeader(
                "RAR 2.x archive does not contain a PROTECT_HEAD recovery record",
            ))?;
            protect_head_plan(self, protect, source_len)?
        };

        if dest_prefilled {
            // The caller cloned the source into `dest` already; all this
            // pass owes is the guarantee the copy below provides - that the
            // file being patched is exactly `source_len` bytes of source.
            if dest.metadata()?.len() != source_len as u64 {
                return Err(Error::InvalidHeader(
                    "repair destination is not a byte-complete copy of the archive",
                ));
            }
        } else {
            dest.seek(SeekFrom::Start(0))?;
            self.source.copy_range_to(0..source_len, dest)?;
            dest.set_len(source_len as u64)?;
        }

        repair_protect_sectors(self, &plan, &recovery, dest, budget)
    }

    /// Streams extracted entries to caller-provided writers.
    pub fn extract_to<F>(&self, options: crate::ArchiveReadOptions<'_>, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let password = options.password;
        let mut session = DecoderSession::new_with_password(self.main.is_solid(), password);
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry requires multivolume extraction",
                ));
            }
            let meta = file.metadata();
            if meta.is_directory {
                let _ = open(&meta)?;
                continue;
            }
            let mut writer = open(&meta)?;
            if file.is_stored() {
                file.write_stored_to(self, password, &mut writer)
                    .map_err(|error| file.entry_error("extracting", error))?;
            } else {
                session
                    .write_file_to(self, file, &mut writer)
                    .map_err(|error| file.entry_error("extracting", error))?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "parallel")]
    pub fn extract_to_parallel_buffered<F>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        mut open: F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        if self.main.is_solid()
            || self
                .files()
                .any(|file| file.is_solid() || file.is_split_before() || file.is_split_after())
        {
            return self.extract_to(options, open);
        }

        let password = options.password;
        let files: Vec<_> = self.files().collect();
        if files.len() < 2 {
            return self.extract_to(options, open);
        }

        // Budgeted worker pool (the rar50 member-pool shape): the old
        // rayon map_collect buffered EVERY member's bytes at once, so peak
        // memory was the whole unpacked archive. Workers now decode under
        // an in-flight byte budget and the coordinator writes in archive
        // order as members complete - which also matches the serial path's
        // incremental write semantics (first failing member in archive
        // order wins, earlier members are already written).
        use std::collections::BTreeMap;
        use std::sync::mpsc;
        use std::sync::{Arc, Condvar, Mutex};

        #[cfg(not(test))]
        const INFLIGHT_BUDGET: u64 = 64 << 20;
        #[cfg(test)]
        const INFLIGHT_BUDGET: u64 = 8 * 1024;

        let workers = std::thread::available_parallelism()
            .map_or(4, |n| n.get())
            .saturating_sub(1)
            .clamp(1, 8)
            .min(files.len());
        let budget = Arc::new((Mutex::new((0u64, false)), Condvar::new()));
        let (work_tx, work_rx) = mpsc::sync_channel::<usize>(workers * 2);
        let work_rx = Arc::new(Mutex::new(work_rx));
        let (result_tx, result_rx) =
            mpsc::channel::<(usize, Result<ParallelExtractedEntry>)>();

        let outcome = std::thread::scope(|scope| {
            {
                let budget = Arc::clone(&budget);
                let files = &files;
                scope.spawn(move || {
                    for (index, file) in files.iter().enumerate() {
                        let size = file.unp_size;
                        let (lock, cvar) = &*budget;
                        let mut state = lock.lock().expect("pool budget lock");
                        while !state.1 && state.0 > 0 && state.0 + size > INFLIGHT_BUDGET {
                            state = cvar.wait(state).expect("pool budget wait");
                        }
                        if state.1 {
                            return;
                        }
                        state.0 += size;
                        drop(state);
                        if work_tx.send(index).is_err() {
                            return;
                        }
                    }
                });
            }
            for _ in 0..workers {
                let work_rx = Arc::clone(&work_rx);
                let result_tx = result_tx.clone();
                let files = &files;
                scope.spawn(move || loop {
                    let index = match work_rx.lock().expect("pool work lock").recv() {
                        Ok(index) => index,
                        Err(_) => return,
                    };
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        decode_parallel_entry(self, files[index], password)
                    }))
                    .unwrap_or(Err(Error::InvalidHeader(
                        "RAR member decode worker panicked",
                    )));
                    if result_tx.send((index, result)).is_err() {
                        return;
                    }
                });
            }
            drop(result_tx);
            // Drop the outer receiver handle so the workers hold the ONLY
            // ones. This is what frees a feeder blocked on a full
            // `work_tx.send`: `drop(result_rx)` below makes every worker return
            // WITHOUT draining the work channel, so while an Arc clone stayed
            // alive in the enclosing frame that send could never fail and
            // `thread::scope` never returned.
            //
            // Narrower than it looks, and measured rather than reasoned about:
            // an ordinary Err from the coordinator never hung here, even before
            // this drop existed. The worker that delivers the failing result
            // pops one more item on its way out, which frees the very slot the
            // blocked send wants, and the feeder re-checks the abort flag at
            // the top of its next iteration. What hangs is a coordinator PANIC,
            // which unwinds past every explicit wake-up - and covering it takes
            // BOTH this drop and `_abort` below, because the feeder parks in
            // two different places and each ignores the other's signal.
            //
            // The rar50 twin (extract_volumes_pooled) terminates without this
            // only because it never drops its result receiver, so its workers
            // keep draining the work queue.
            drop(work_rx);
            // The feeder's other parking spot: `cvar.wait` on the byte budget,
            // which only a notify frees. `write_parallel_entry` calls the
            // caller's `open` and then its `Write`, either of which can panic,
            // and the explicit abort-and-notify this replaces sat below the
            // coordinator where an unwind skipped it.
            let _abort = crate::parallel::PoolAbortGuard::new(&budget);

            let mut pending: BTreeMap<usize, Result<ParallelExtractedEntry>> = BTreeMap::new();
            let mut run = || -> Result<()> {
                for (index, file) in files.iter().enumerate() {
                    let result = loop {
                        if let Some(result) = pending.remove(&index) {
                            break result;
                        }
                        match result_rx.recv() {
                            Ok((got, result)) if got == index => break result,
                            Ok((got, result)) => {
                                pending.insert(got, result);
                            }
                            Err(_) => {
                                return Err(Error::InvalidHeader(
                                    "RAR member decode pool disconnected",
                                ));
                            }
                        }
                    };
                    write_parallel_entry(result?, &mut open)?;
                    let (lock, cvar) = &*budget;
                    let mut state = lock.lock().expect("pool budget lock");
                    state.0 = state.0.saturating_sub(file.unp_size);
                    drop(state);
                    cvar.notify_all();
                }
                Ok(())
            };
            let outcome = run();
            // Unblock a worker mid-send; `_abort` handles the feeder.
            drop(result_rx);
            outcome
        });
        outcome
    }

    pub fn archive_comment(&self) -> Result<Option<Vec<u8>>> {
        if let Some(comment) = self.blocks.iter().find_map(|block| match block {
            Block::Comment(comment) => Some(comment),
            _ => None,
        }) {
            return comment.unpacked_data(self).map(Some);
        }

        let Some(comment) = self
            .new_subs()
            .find(|sub| sub.kind == NewSubKind::ArchiveComment)
        else {
            return Ok(None);
        };
        let data = comment.file.unpacked_data(self)?;
        comment.file.verify_crc32(&data)?;
        Ok(Some(data))
    }
}

#[cfg(feature = "parallel")]
enum ParallelExtractedEntry {
    Directory(ExtractedEntryMeta),
    File {
        meta: ExtractedEntryMeta,
        data: Vec<u8>,
    },
}

#[cfg(feature = "parallel")]
fn decode_parallel_entry(
    archive: &Archive,
    file: &FileHeader,
    password: Option<&[u8]>,
) -> Result<ParallelExtractedEntry> {
    if file.is_split_before() || file.is_split_after() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry requires multivolume extraction",
        ));
    }
    let meta = file.metadata();
    if meta.is_directory {
        return Ok(ParallelExtractedEntry::Directory(meta));
    }
    let mut data = Vec::new();
    if file.is_stored() {
        file.write_stored_to(archive, password, &mut data)
            .map_err(|error| file.entry_error("extracting", error))?;
    } else {
        let mut session = DecoderSession::new_with_password(false, password);
        session
            .write_file_to(archive, file, &mut data)
            .map_err(|error| file.entry_error("extracting", error))?;
    }
    Ok(ParallelExtractedEntry::File { meta, data })
}

#[cfg(feature = "parallel")]
fn write_parallel_entry<F>(entry: ParallelExtractedEntry, open: &mut F) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    match entry {
        ParallelExtractedEntry::Directory(meta) => {
            let _ = open(&meta)?;
        }
        ParallelExtractedEntry::File { meta, data } => {
            let mut writer = open(&meta)?;
            writer.write_all(&data)?;
        }
    }
    Ok(())
}

fn classify_new_sub(name: &[u8]) -> NewSubKind {
    match name {
        b"CMT" => NewSubKind::ArchiveComment,
        b"RR" => NewSubKind::RecoveryRecord,
        _ => NewSubKind::Unknown(name.to_vec()),
    }
}

fn parse_main_header(input: &[u8], block: &BlockHeader) -> Result<MainHeader> {
    if block.head_size < 13 {
        return Err(Error::InvalidHeader("RAR 1.5 main header is too short"));
    }
    let start = block.offset;
    let head_end = start + block.head_size as usize;
    if head_end > input.len() {
        return Err(Error::TooShort);
    }

    let encrypt_version = if block.flags & MHD_ENCRYPTVER != 0 {
        Some(*input.get(start + 13).ok_or(Error::TooShort)?)
    } else {
        None
    };

    Ok(MainHeader {
        head_crc: block.head_crc,
        flags: block.flags,
        head_size: block.head_size,
        reserved1: read_u16(input, start + 7)?,
        reserved2: read_u32(input, start + 9)?,
        encrypt_version,
    })
}

fn parse_comment_header(input: &[u8], block: BlockHeader) -> Result<CommentHeader> {
    if block.head_size < 13 {
        return Err(Error::InvalidHeader("RAR 1.5 comment header is too short"));
    }
    let start = block.offset;
    Ok(CommentHeader {
        block,
        unp_size: read_u16(input, start + 7)?,
        unp_ver: *input.get(start + 9).ok_or(Error::TooShort)?,
        method: *input.get(start + 10).ok_or(Error::TooShort)?,
        comment_crc: read_u16(input, start + 11)?,
        packed_range: 0..0,
    })
}

fn parse_protect_header(
    input: &[u8],
    block: &BlockHeader,
    archive_offset: usize,
    total_size: usize,
) -> Result<ProtectHeader> {
    if block.head_size != 26 {
        return Err(Error::InvalidHeader(
            "RAR 2.x recovery header size is invalid",
        ));
    }
    let add_size = block.add_size.ok_or(Error::InvalidHeader(
        "RAR 2.x recovery header is missing data size",
    ))?;
    let rec_sectors = read_u16(input, 12)?;
    let total_blocks = read_u32(input, 14)?;
    let expected_add_size = u64::from(total_blocks)
        .checked_mul(2)
        .and_then(|size| size.checked_add(u64::from(rec_sectors) * 512))
        .ok_or(Error::InvalidHeader("RAR 2.x recovery data size overflows"))?;
    if add_size != expected_add_size {
        return Err(Error::InvalidHeader(
            "RAR 2.x recovery data size does not match header",
        ));
    }
    let mark: [u8; 8] = input
        .get(18..26)
        .ok_or(Error::TooShort)?
        .try_into()
        .expect("RAR protect mark size");
    let data_start = archive_offset
        .checked_add(block.offset)
        .and_then(|offset| offset.checked_add(block.head_size as usize))
        .ok_or(Error::InvalidHeader(
            "RAR 2.x recovery data range overflows",
        ))?;
    let data_end = archive_offset
        .checked_add(block.offset)
        .and_then(|offset| offset.checked_add(total_size))
        .ok_or(Error::InvalidHeader(
            "RAR 2.x recovery data range overflows",
        ))?;
    Ok(ProtectHeader {
        block: block.clone(),
        version: *input.get(11).ok_or(Error::TooShort)?,
        rec_sectors,
        total_blocks,
        mark,
        data_range: data_start..data_end,
    })
}

fn repair_protect_head_bytes(
    source: &[u8],
    sfx_offset: usize,
    protect: &ProtectHeader,
) -> Result<Vec<u8>> {
    if protect.rec_sectors == 0 {
        return Err(Error::InvalidHeader(
            "RAR 2.x recovery record has no parity sectors",
        ));
    }
    if protect.mark != *b"Protect!" {
        return Err(Error::InvalidHeader("RAR 2.x recovery mark is invalid"));
    }
    let protected_start = sfx_offset;
    let protected_len = usize::try_from(protect.total_blocks)
        .ok()
        .and_then(|blocks| blocks.checked_mul(512))
        .ok_or(Error::InvalidHeader(
            "RAR 2.x protected sector size overflows",
        ))?;
    let protected_end = protected_start
        .checked_add(protected_len)
        .ok_or(Error::InvalidHeader(
            "RAR 2.x protected sector range overflows",
        ))?;
    if protected_end > source.len() {
        return Err(Error::InvalidHeader(
            "RAR 2.x protected sector range is invalid",
        ));
    }
    let recovery_data = source
        .get(protect.data_range.clone())
        .ok_or(Error::TooShort)?;
    let declared_blocks = usize::try_from(protect.total_blocks).map_err(|_| {
        Error::InvalidHeader("RAR 2.x recovery protected sector count overflows usize")
    })?;
    let tag_len = declared_blocks
        .checked_mul(2)
        .ok_or(Error::InvalidHeader("RAR 2.x recovery tag size overflows"))?;
    let parity_len =
        usize::from(protect.rec_sectors)
            .checked_mul(512)
            .ok_or(Error::InvalidHeader(
                "RAR 2.x recovery parity size overflows",
            ))?;
    if recovery_data.len() != tag_len + parity_len {
        return Err(Error::InvalidHeader(
            "RAR 2.x recovery data size is invalid",
        ));
    }
    let tags = &recovery_data[..tag_len];
    let parity = &recovery_data[tag_len..];
    // RAR 2.50 records may declare a final sector that starts before
    // PROTECT_HEAD but overlaps the recovery block. Only complete sectors
    // before the recovery block are safely repairable.
    let repairable_blocks = declared_blocks.min(protect.block.offset / 512);

    let mut damaged = Vec::new();
    for index in 0..repairable_blocks {
        let sector_start = protected_start + index * 512;
        let sector = &source[sector_start..sector_start + 512];
        let actual = (!crc32(sector) & 0xffff) as u16;
        let expected = read_u16(tags, index * 2)?;
        if actual != expected {
            damaged.push(index);
        }
    }
    if damaged.is_empty() {
        return Ok(source.to_vec());
    }
    if damaged.len() > usize::from(protect.rec_sectors) {
        return Err(Error::InvalidHeader(
            "RAR 2.x recovery damage exceeds parity sector count",
        ));
    }

    let mut used_slots = vec![false; usize::from(protect.rec_sectors)];
    for &index in &damaged {
        let slot = index % usize::from(protect.rec_sectors);
        if used_slots[slot] {
            return Err(Error::InvalidHeader(
                "RAR 2.x recovery cannot repair multiple sectors in the same parity group",
            ));
        }
        used_slots[slot] = true;
    }

    let mut repaired = source.to_vec();
    for &missing_index in &damaged {
        let slot = missing_index % usize::from(protect.rec_sectors);
        let mut sector = parity[slot * 512..slot * 512 + 512].to_vec();
        for index in (slot..repairable_blocks).step_by(usize::from(protect.rec_sectors)) {
            if index == missing_index {
                continue;
            }
            let sector_start = protected_start + index * 512;
            for (out, byte) in sector
                .iter_mut()
                .zip(&repaired[sector_start..sector_start + 512])
            {
                *out ^= *byte;
            }
        }
        let sector_start = protected_start + missing_index * 512;
        repaired[sector_start..sector_start + 512].copy_from_slice(&sector);
        let actual = (!crc32(&sector) & 0xffff) as u16;
        let expected = u16::from_le_bytes(
            tags[missing_index * 2..missing_index * 2 + 2]
                .try_into()
                .unwrap(),
        );
        if actual != expected {
            return Err(Error::CrcMismatch { expected, actual });
        }
    }
    Ok(repaired)
}

fn repair_newsub_recovery_bytes(
    source: &[u8],
    sfx_offset: usize,
    archive: &Archive,
    recovery: &NewSubHeader,
) -> Result<Vec<u8>> {
    let recovery_data = newsub_recovery_data(archive, recovery)?;
    let expected_unpacked = usize::try_from(recovery.file.unp_size)
        .map_err(|_| Error::InvalidHeader("RAR 3.x recovery unpacked size overflows usize"))?;
    if recovery_data.len() != expected_unpacked {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery data size does not match unpacked size",
        ));
    }
    let protected_start = sfx_offset;
    let protected_end =
        sfx_offset
            .checked_add(recovery.file.block.offset)
            .ok_or(Error::InvalidHeader(
                "RAR 3.x recovery protected range overflows",
            ))?;
    if protected_end > source.len() || protected_start > protected_end {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery protected range is invalid",
        ));
    }
    let protected_len = protected_end - protected_start;
    let protected_sectors = protected_len.div_ceil(512);
    if protected_sectors == 0 {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery record has no protected sectors",
        ));
    }
    let tag_len = protected_sectors
        .checked_mul(2)
        .ok_or(Error::InvalidHeader("RAR 3.x recovery tag size overflows"))?;
    if recovery_data.len() <= tag_len || !(recovery_data.len() - tag_len).is_multiple_of(512) {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery data size is invalid",
        ));
    }
    let parity_sectors = (recovery_data.len() - tag_len) / 512;
    if parity_sectors == 0 {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery record has no parity sectors",
        ));
    }
    let tags = &recovery_data[..tag_len];
    let parity = &recovery_data[tag_len..];

    let mut damaged = Vec::new();
    for index in 0..protected_sectors {
        let sector = protected_sector(source, protected_start, protected_len, index)?;
        let actual = (!crc32(&sector) & 0xffff) as u16;
        let expected = read_u16(tags, index * 2)?;
        if actual != expected {
            damaged.push(index);
        }
    }
    if damaged.is_empty() {
        return Ok(source.to_vec());
    }
    if damaged.len() > parity_sectors {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery damage exceeds parity sector count",
        ));
    }

    let mut used_slots = vec![false; parity_sectors];
    for &index in &damaged {
        let slot = index % parity_sectors;
        if used_slots[slot] {
            return Err(Error::InvalidHeader(
                "RAR 3.x recovery cannot repair multiple sectors in the same parity group",
            ));
        }
        used_slots[slot] = true;
    }

    let mut repaired = source.to_vec();
    for &missing_index in &damaged {
        let slot = missing_index % parity_sectors;
        let mut sector = parity[slot * 512..slot * 512 + 512].to_vec();
        for index in (slot..protected_sectors).step_by(parity_sectors) {
            if index == missing_index {
                continue;
            }
            let other = protected_sector(&repaired, protected_start, protected_len, index)?;
            for (out, byte) in sector.iter_mut().zip(other) {
                *out ^= byte;
            }
        }
        let actual = (!crc32(&sector) & 0xffff) as u16;
        let expected = u16::from_le_bytes(
            tags[missing_index * 2..missing_index * 2 + 2]
                .try_into()
                .unwrap(),
        );
        if actual != expected {
            return Err(Error::CrcMismatch { expected, actual });
        }
        let sector_start = protected_start + missing_index * 512;
        let write_len = 512.min(protected_end - sector_start);
        repaired[sector_start..sector_start + write_len].copy_from_slice(&sector[..write_len]);
    }

    Ok(repaired)
}

fn newsub_recovery_data(archive: &Archive, recovery: &NewSubHeader) -> Result<Vec<u8>> {
    if recovery.file.is_encrypted() {
        return Err(Error::UnsupportedFeature {
            version: ArchiveVersion::Rar30,
            feature: "encrypted RAR 3.x NEWSUB recovery record",
        });
    }
    if recovery.file.method == 0x30 {
        if recovery.file.pack_size != recovery.file.unp_size {
            return Err(Error::InvalidHeader(
                "RAR 3.x recovery record packed size does not match unpacked size",
            ));
        }
        return recovery.file.stored_data(archive);
    }
    let mut session = DecoderSession::new(false);
    session.decode_file_data(archive, &recovery.file)
}

/// Sectors per streaming window: 256 KiB of source and 1 KiB of CRC tags,
/// which keeps sequential scans cheap and is irrelevant next to any budget.
const PROTECT_WINDOW_SECTORS: usize = 512;

/// Geometry of one legacy recovery record, resolved against the archive:
/// where the protected sector run and the parity sectors live, plus the
/// family-specific messages (`InvalidHeader` carries a `&'static str`, so a
/// shared core cannot format the family in).
struct ProtectPlan {
    /// Absolute source offset of protected sector 0.
    protected_start: usize,
    /// Bytes the scanned sectors cover; the final sector may be partial
    /// (RAR 3.x) and is zero-padded for CRC/XOR purposes.
    protected_len: usize,
    /// Sectors to scan. RAR 2.x may declare more than are repairable; only
    /// these are scanned, exactly as the buffered path repairs.
    sectors: usize,
    parity_sectors: usize,
    /// Byte offset of the parity sectors within the recovery data (the CRC
    /// tag table sits at 0 and is 2 bytes per DECLARED sector).
    parity_offset: usize,
    exceeds_parity: &'static str,
    slot_collision: &'static str,
}

/// Recovery data for a legacy record. RAR 2.x PROTECT_HEAD and a stored
/// RAR 3.x NEWSUB record live in the archive itself and are read by range;
/// only a compressed NEWSUB record has to be materialized, and that decode
/// is budgeted before it happens.
enum ProtectRecoveryBytes<'a> {
    InArchive {
        archive: &'a Archive,
        range: Range<usize>,
    },
    Decoded(Vec<u8>),
}

impl ProtectRecoveryBytes<'_> {
    fn resident_len(&self) -> u64 {
        match self {
            Self::InArchive { .. } => 0,
            Self::Decoded(data) => data.len() as u64,
        }
    }

    fn read_into(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        match self {
            Self::InArchive { archive, range } => {
                let end = offset.checked_add(buf.len()).ok_or(Error::TooShort)?;
                if end > range.len() {
                    return Err(Error::TooShort);
                }
                archive
                    .source
                    .read_range_into((range.start + offset) as u64, buf)
            }
            Self::Decoded(data) => {
                let end = offset.checked_add(buf.len()).ok_or(Error::TooShort)?;
                buf.copy_from_slice(data.get(offset..end).ok_or(Error::TooShort)?);
                Ok(())
            }
        }
    }

    fn read_tag(&self, index: usize) -> Result<u16> {
        let mut tag = [0u8; 2];
        self.read_into(index * 2, &mut tag)?;
        Ok(u16::from_le_bytes(tag))
    }
}

/// Resolves a RAR 2.x PROTECT_HEAD record into a [`ProtectPlan`], with the
/// same validation and messages as [`repair_protect_head_bytes`].
fn protect_head_plan<'a>(
    archive: &'a Archive,
    protect: &ProtectHeader,
    source_len: usize,
) -> Result<(ProtectPlan, ProtectRecoveryBytes<'a>)> {
    if protect.rec_sectors == 0 {
        return Err(Error::InvalidHeader(
            "RAR 2.x recovery record has no parity sectors",
        ));
    }
    if protect.mark != *b"Protect!" {
        return Err(Error::InvalidHeader("RAR 2.x recovery mark is invalid"));
    }
    let protected_start = archive.sfx_offset;
    let protected_len = usize::try_from(protect.total_blocks)
        .ok()
        .and_then(|blocks| blocks.checked_mul(512))
        .ok_or(Error::InvalidHeader(
            "RAR 2.x protected sector size overflows",
        ))?;
    let protected_end = protected_start
        .checked_add(protected_len)
        .ok_or(Error::InvalidHeader(
            "RAR 2.x protected sector range overflows",
        ))?;
    if protected_end > source_len {
        return Err(Error::InvalidHeader(
            "RAR 2.x protected sector range is invalid",
        ));
    }
    if protect.data_range.start > protect.data_range.end || protect.data_range.end > source_len {
        return Err(Error::TooShort);
    }
    let declared_blocks = usize::try_from(protect.total_blocks).map_err(|_| {
        Error::InvalidHeader("RAR 2.x recovery protected sector count overflows usize")
    })?;
    let tag_len = declared_blocks
        .checked_mul(2)
        .ok_or(Error::InvalidHeader("RAR 2.x recovery tag size overflows"))?;
    let parity_len =
        usize::from(protect.rec_sectors)
            .checked_mul(512)
            .ok_or(Error::InvalidHeader(
                "RAR 2.x recovery parity size overflows",
            ))?;
    if protect.data_range.len() != tag_len + parity_len {
        return Err(Error::InvalidHeader(
            "RAR 2.x recovery data size is invalid",
        ));
    }
    // RAR 2.50 records may declare a final sector that starts before
    // PROTECT_HEAD but overlaps the recovery block. Only complete sectors
    // before the recovery block are safely repairable.
    let repairable_blocks = declared_blocks.min(protect.block.offset / 512);
    Ok((
        ProtectPlan {
            protected_start,
            protected_len: repairable_blocks * 512,
            sectors: repairable_blocks,
            parity_sectors: usize::from(protect.rec_sectors),
            parity_offset: tag_len,
            exceeds_parity: "RAR 2.x recovery damage exceeds parity sector count",
            slot_collision:
                "RAR 2.x recovery cannot repair multiple sectors in the same parity group",
        },
        ProtectRecoveryBytes::InArchive {
            archive,
            range: protect.data_range.clone(),
        },
    ))
}

/// Resolves a RAR 3.x NEWSUB recovery record into a [`ProtectPlan`], with
/// the same validation and messages as [`repair_newsub_recovery_bytes`]. A
/// stored record stays in the archive and is read by range; a compressed
/// one is decoded, counted against `budget` first.
fn newsub_protect_plan<'a>(
    archive: &'a Archive,
    recovery: &NewSubHeader,
    source_len: usize,
    budget: u64,
) -> Result<(ProtectPlan, ProtectRecoveryBytes<'a>)> {
    if recovery.file.is_encrypted() {
        return Err(Error::UnsupportedFeature {
            version: ArchiveVersion::Rar30,
            feature: "encrypted RAR 3.x NEWSUB recovery record",
        });
    }
    let expected_unpacked = usize::try_from(recovery.file.unp_size)
        .map_err(|_| Error::InvalidHeader("RAR 3.x recovery unpacked size overflows usize"))?;
    let recovery_bytes = if recovery.file.method == 0x30 {
        if recovery.file.pack_size != recovery.file.unp_size {
            return Err(Error::InvalidHeader(
                "RAR 3.x recovery record packed size does not match unpacked size",
            ));
        }
        let range = recovery.file.packed_range.clone();
        if range.start > range.end || range.end > source_len {
            return Err(Error::TooShort);
        }
        if range.len() != expected_unpacked {
            return Err(Error::InvalidHeader(
                "RAR 3.x recovery data size does not match unpacked size",
            ));
        }
        ProtectRecoveryBytes::InArchive { archive, range }
    } else {
        // The decode buffers the packed record and grows its output to the
        // declared unpacked size; both must fit the budget BEFORE the
        // allocation happens, or a small hostile header aborts the process.
        if recovery
            .file
            .pack_size
            .saturating_add(recovery.file.unp_size)
            > budget
        {
            return Err(Error::LegacyRepairTooLarge);
        }
        let mut session = DecoderSession::new(false);
        let data = session.decode_file_data(archive, &recovery.file)?;
        if data.len() != expected_unpacked {
            return Err(Error::InvalidHeader(
                "RAR 3.x recovery data size does not match unpacked size",
            ));
        }
        ProtectRecoveryBytes::Decoded(data)
    };
    let protected_start = archive.sfx_offset;
    let protected_end = archive
        .sfx_offset
        .checked_add(recovery.file.block.offset)
        .ok_or(Error::InvalidHeader(
            "RAR 3.x recovery protected range overflows",
        ))?;
    if protected_end > source_len || protected_start > protected_end {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery protected range is invalid",
        ));
    }
    let protected_len = protected_end - protected_start;
    let protected_sectors = protected_len.div_ceil(512);
    if protected_sectors == 0 {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery record has no protected sectors",
        ));
    }
    let tag_len = protected_sectors
        .checked_mul(2)
        .ok_or(Error::InvalidHeader("RAR 3.x recovery tag size overflows"))?;
    if expected_unpacked <= tag_len || !(expected_unpacked - tag_len).is_multiple_of(512) {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery data size is invalid",
        ));
    }
    let parity_sectors = (expected_unpacked - tag_len) / 512;
    if parity_sectors == 0 {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery record has no parity sectors",
        ));
    }
    Ok((
        ProtectPlan {
            protected_start,
            protected_len,
            sectors: protected_sectors,
            parity_sectors,
            parity_offset: tag_len,
            exceeds_parity: "RAR 3.x recovery damage exceeds parity sector count",
            slot_collision:
                "RAR 3.x recovery cannot repair multiple sectors in the same parity group",
        },
        recovery_bytes,
    ))
}

/// Fills `buf` with `count` sectors starting at `first`, reading the source
/// by range and zero-padding a partial final sector - the streaming
/// equivalent of [`protected_sector`]. Returns the filled window.
fn read_sector_window<'b>(
    archive: &Archive,
    plan: &ProtectPlan,
    first: usize,
    count: usize,
    buf: &'b mut [u8],
) -> Result<&'b [u8]> {
    let window = &mut buf[..count * 512];
    let start = first * 512;
    let end = (start + count * 512).min(plan.protected_len);
    let take = end.saturating_sub(start);
    archive
        .source
        .read_range_into((plan.protected_start + start) as u64, &mut window[..take])?;
    window[take..].fill(0);
    Ok(window)
}

/// The streaming core shared by both legacy families: scan the protected
/// sectors against the CRC tag table, XOR-accumulate each damaged sector's
/// parity group in one more sequential pass, verify, and patch `dest` in
/// place. Peak memory is the scan window plus one 512-byte accumulator per
/// damaged sector (plus the decoded record when it was compressed), never
/// the volume.
fn repair_protect_sectors(
    archive: &Archive,
    plan: &ProtectPlan,
    recovery: &ProtectRecoveryBytes<'_>,
    dest: &mut File,
    budget: u64,
) -> Result<Vec<usize>> {
    use std::io::{Seek as _, SeekFrom};

    let mut window_buf = vec![0u8; PROTECT_WINDOW_SECTORS * 512];
    let mut tag_buf = vec![0u8; PROTECT_WINDOW_SECTORS * 2];

    // Pass 1: damage detection by streaming CRC.
    let mut damaged: Vec<usize> = Vec::new();
    let mut index = 0usize;
    while index < plan.sectors {
        let count = PROTECT_WINDOW_SECTORS.min(plan.sectors - index);
        let window = read_sector_window(archive, plan, index, count, &mut window_buf)?;
        recovery.read_into(index * 2, &mut tag_buf[..count * 2])?;
        for s in 0..count {
            let sector = &window[s * 512..s * 512 + 512];
            let actual = (!crc32(sector) & 0xffff) as u16;
            let expected = u16::from_le_bytes([tag_buf[s * 2], tag_buf[s * 2 + 1]]);
            if actual != expected {
                damaged.push(index + s);
                // Repair is provably impossible past one mismatch per
                // parity sector, so stop collecting the moment the
                // count crosses that line. Without this bail the list
                // grows one usize per bad sector for the WHOLE volume
                // (source_len/64 bytes - hundreds of MB on a large
                // corrupt volume) before any check runs, breaking the
                // documented peak-memory contract above. Same error
                // value as the post-scan check so the streaming and
                // buffered paths stay observably identical.
                if damaged.len() > plan.parity_sectors {
                    return Err(Error::InvalidHeader(plan.exceeds_parity));
                }
            }
        }
        index += count;
    }
    if damaged.is_empty() {
        return Ok(Vec::new());
    }

    // Working set from here: the accumulators, the scan buffers, the slot
    // bitmap (the bare `+ plan.parity_sectors` term), and (for a
    // compressed NEWSUB record) the decoded recovery data. Checked BEFORE
    // the bitmap below is allocated, so rejection precedes allocation.
    let working = recovery
        .resident_len()
        .saturating_add(damaged.len() as u64 * 512)
        .saturating_add((window_buf.len() + tag_buf.len() + plan.parity_sectors) as u64);
    if working > budget {
        return Err(Error::LegacyRepairTooLarge);
    }

    let mut used_slots = vec![false; plan.parity_sectors];
    for &missing in &damaged {
        let slot = missing % plan.parity_sectors;
        if used_slots[slot] {
            return Err(Error::InvalidHeader(plan.slot_collision));
        }
        used_slots[slot] = true;
    }

    // Seed each damaged sector's accumulator with its parity sector.
    let mut accumulators: Vec<[u8; 512]> = Vec::with_capacity(damaged.len());
    for &missing in &damaged {
        let slot = missing % plan.parity_sectors;
        let mut acc = [0u8; 512];
        recovery.read_into(plan.parity_offset + slot * 512, &mut acc)?;
        accumulators.push(acc);
    }
    let by_slot: std::collections::HashMap<usize, usize> = damaged
        .iter()
        .enumerate()
        .map(|(n, &missing)| (missing % plan.parity_sectors, n))
        .collect();

    // Pass 2: one more sequential sweep XORs every intact group-mate into
    // its slot's accumulator. Each parity group holds at most one damaged
    // sector (checked above), so intact group-mates read from the source
    // equal what the buffered path reads from its progressively patched
    // copy.
    index = 0;
    while index < plan.sectors {
        let count = PROTECT_WINDOW_SECTORS.min(plan.sectors - index);
        let window = read_sector_window(archive, plan, index, count, &mut window_buf)?;
        for s in 0..count {
            let sector_index = index + s;
            if let Some(&n) = by_slot.get(&(sector_index % plan.parity_sectors)) {
                if damaged[n] != sector_index {
                    let sector = &window[s * 512..s * 512 + 512];
                    for (out, byte) in accumulators[n].iter_mut().zip(sector) {
                        *out ^= *byte;
                    }
                }
            }
        }
        index += count;
    }

    // Verify every rebuilt sector against its tag, then patch `dest`.
    for (n, &missing) in damaged.iter().enumerate() {
        let sector = &accumulators[n];
        let actual = (!crc32(sector) & 0xffff) as u16;
        let expected = recovery.read_tag(missing)?;
        if actual != expected {
            return Err(Error::CrcMismatch { expected, actual });
        }
        let sector_start = missing * 512;
        let write_len = 512.min(plan.protected_len - sector_start);
        dest.seek(SeekFrom::Start(
            (plan.protected_start + sector_start) as u64,
        ))?;
        dest.write_all(&sector[..write_len])?;
    }
    Ok(damaged)
}

fn protected_sector(
    source: &[u8],
    protected_start: usize,
    protected_len: usize,
    index: usize,
) -> Result<[u8; 512]> {
    let sector_offset = index.checked_mul(512).ok_or(Error::InvalidHeader(
        "RAR 3.x recovery sector offset overflows",
    ))?;
    if sector_offset >= protected_len {
        return Err(Error::InvalidHeader(
            "RAR 3.x recovery sector offset is invalid",
        ));
    }
    let sector_start = protected_start
        .checked_add(sector_offset)
        .ok_or(Error::InvalidHeader(
            "RAR 3.x recovery sector range overflows",
        ))?;
    let available = 512.min(protected_len - sector_offset);
    let mut sector = [0u8; 512];
    sector[..available].copy_from_slice(
        source
            .get(sector_start..sector_start + available)
            .ok_or(Error::TooShort)?,
    );
    Ok(sector)
}

pub fn repair_rev3_volumes_to<F>(
    data_volumes: &[Option<&[u8]>],
    recovery_count: usize,
    recovery_volumes: &[(usize, &[u8])],
    mut write: F,
) -> Result<()>
where
    F: FnMut(usize, &[u8]) -> Result<()>,
{
    for (index, bytes) in crate::recovery::rar3::reconstruct_data_volumes(
        data_volumes,
        recovery_count,
        recovery_volumes,
    )
    .map_err(Error::from)?
    .into_iter()
    .enumerate()
    {
        let bytes = truncate_repaired_rev3_volume(bytes)?;
        write(index, &bytes)?;
    }
    Ok(())
}

fn truncate_repaired_rev3_volume(mut bytes: Vec<u8>) -> Result<Vec<u8>> {
    let Ok(archive) = Archive::parse(&bytes) else {
        return Ok(bytes);
    };
    let Some(end) = archive.blocks.iter().find_map(|block| match block {
        Block::End(end) => Some(end),
        _ => None,
    }) else {
        return Ok(bytes);
    };
    let end_pos = archive
        .sfx_offset
        .checked_add(end.offset)
        .and_then(|offset| offset.checked_add(block_total_size(end).ok()?))
        .ok_or(Error::InvalidHeader(
            "RAR 3 repaired volume end offset overflows",
        ))?;
    if end_pos < bytes.len() && bytes[end_pos..].iter().all(|&byte| byte == 0) {
        bytes.truncate(end_pos);
    }
    Ok(bytes)
}

struct EncryptedHeader {
    block: BlockHeader,
    header: Vec<u8>,
    total_size: usize,
}

#[derive(Default)]
struct EncryptedHeaderCipherCache {
    salt: Option<[u8; 8]>,
    cipher: Option<Rar30Cipher>,
}

impl EncryptedHeaderCipherCache {
    fn cipher(&mut self, password: &[u8], salt: [u8; 8]) -> Result<Rar30Cipher> {
        if self.salt != Some(salt) {
            self.salt = Some(salt);
            self.cipher =
                Some(Rar30Cipher::new(password, Some(salt)).map_err(map_rar30_crypto_error)?);
        }
        Ok(self
            .cipher
            .as_ref()
            .expect("RAR 3 encrypted header cipher cache initialized")
            .clone())
    }
}

fn map_rar30_crypto_error(error: Rar30Error) -> Error {
    Error::from(error)
}

fn decrypt_encrypted_header_at(
    archive: &[u8],
    offset: usize,
    password: &[u8],
    cipher_cache: &mut EncryptedHeaderCipherCache,
) -> Result<EncryptedHeader> {
    let salt = read_header_salt(archive, offset)?;
    let first_ciphertext = archive
        .get(offset + 8..offset + 24)
        .ok_or(Error::TooShort)?;
    let mut cipher = cipher_cache.cipher(password, salt)?;
    let mut first_block = [0u8; 16];
    first_block.copy_from_slice(first_ciphertext);
    cipher
        .decrypt_in_place(&mut first_block)
        .map_err(map_rar30_crypto_error)?;
    let head_size = read_u16(&first_block, 5)? as usize;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    let encrypted_header_size = checked_align16(head_size, "RAR 1.5 block size overflows usize")?;
    let encrypted_start = offset
        .checked_add(8)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    let encrypted_end = encrypted_start
        .checked_add(encrypted_header_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let encrypted_rest = archive
        .get(offset + 24..encrypted_end)
        .ok_or(Error::TooShort)?;
    let mut header = Vec::with_capacity(encrypted_header_size);
    header.extend_from_slice(&first_block);
    header.extend_from_slice(encrypted_rest);
    cipher
        .decrypt_in_place(&mut header[16..])
        .map_err(map_rar30_crypto_error)?;
    header.truncate(head_size);

    let mut block = parse_block_header(&header, 0)?;
    block.offset = offset;
    let payload_size = usize::try_from(block.add_size.unwrap_or(0))
        .map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let total_size = 8usize
        .checked_add(encrypted_header_size)
        .and_then(|size| size.checked_add(payload_size))
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    Ok(EncryptedHeader {
        block,
        header,
        total_size,
    })
}

/// The block walk shared by every parse: the archive's header chain from
/// `pos` (relative to `sfx_offset`) forward, APPENDED to `blocks`.
/// `arrived`, when given, is how many bytes of the source are readable
/// without blocking; the walk stops before the first block header at or
/// past it (after reading at least one block) and returns that offset.
/// `None` back means the walk reached the END record or the file's end.
/// Only the incremental streaming walk ever stops short;
/// [`Archive::enumerate_rest`] calls back in here at that offset to
/// finish, which is why `blocks` is appended to rather than built.
fn walk_blocks(
    file: &mut impl WalkSource,
    sfx_offset: usize,
    main: &MainHeader,
    mut pos: usize,
    blocks: &mut Vec<Block>,
    password: Option<&[u8]>,
    arrived: Option<&dyn Fn() -> usize>,
) -> Result<Option<usize>> {
    let file_len = file.source_len();
    let mut encrypted_header_ciphers = EncryptedHeaderCipherCache::default();
    let mut pending_from = None;

    while (sfx_offset + pos) as u64 + 7 <= file_len {
        if !blocks.is_empty() && arrived.is_some_and(|arrived| sfx_offset + pos >= arrived()) {
            pending_from = Some(pos);
            break;
        }
        let (block, header, total) = if main.has_encrypted_headers() {
            let password = password.ok_or(Error::NeedPassword)?;
            let encrypted = read_encrypted_header_at(
                file,
                file_len,
                sfx_offset,
                pos,
                password,
                &mut encrypted_header_ciphers,
            )?;
            (encrypted.block, encrypted.header, encrypted.total_size)
        } else {
            let block = read_block_header_at(file, file_len, sfx_offset, pos)?;
            let total = block_total_size(&block)?;
            let header = file.read_at(sfx_offset + pos, block.head_size as usize)?;
            (block, header, total)
        };
        match block.head_type {
            FILE_HEAD => {
                let mut file_header = parse_file_like_header(&header, relative_block(&block), 0)?;
                let total = file_block_total_size(&block, total, file_header.pack_size)?;
                let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                file_header.block.offset = block.offset;
                file_header.packed_range =
                    packed_range(sfx_offset, block.offset, total, file_header.pack_size)?;
                blocks.push(Block::File(file_header));
                pos = next;
            }
            NEWSUB_HEAD => {
                let mut file_header = parse_file_like_header(&header, relative_block(&block), 0)?;
                let total = file_block_total_size(&block, total, file_header.pack_size)?;
                let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                file_header.block.offset = block.offset;
                file_header.packed_range =
                    packed_range(sfx_offset, block.offset, total, file_header.pack_size)?;
                let kind = classify_new_sub(&file_header.name);
                blocks.push(Block::NewSub(NewSubHeader {
                    file: file_header,
                    kind,
                }));
                pos = next;
            }
            COMM_HEAD => {
                let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                let mut comment = parse_comment_header(&header, relative_block(&block))?;
                comment.block.offset = block.offset;
                comment.packed_range =
                    sfx_offset + block.offset + 13..sfx_offset + block.offset + total;
                blocks.push(Block::Comment(comment));
                pos = next;
            }
            PROTECT_HEAD => {
                let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                let protect = parse_protect_header(&header, &block, sfx_offset, total)?;
                blocks.push(Block::Protect(protect));
                pos = next;
            }
            ENDARC_HEAD => {
                let _next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                blocks.push(Block::End(block));
                break;
            }
            _ => {
                let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                blocks.push(Block::Unknown(block));
                pos = next;
            }
        }
    }

    Ok(pending_from)
}

/// Positioned header reads for the block walk, over whichever backing the
/// archive has: one open file handle (the seekable parse) or an
/// [`ArchiveSource`] (the streaming parse, whose reads BLOCK at the
/// arrival frontier instead of failing).
trait WalkSource {
    fn source_len(&self) -> u64;
    fn read_at(&mut self, absolute: usize, len: usize) -> Result<Vec<u8>>;
}

struct FileWalk {
    file: File,
    len: u64,
}

impl WalkSource for FileWalk {
    fn source_len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, absolute: usize, len: usize) -> Result<Vec<u8>> {
        read_exact_at(&mut self.file, absolute, len)
    }
}

struct SourceWalk {
    source: ArchiveSource,
    len: u64,
}

impl WalkSource for SourceWalk {
    fn source_len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, absolute: usize, len: usize) -> Result<Vec<u8>> {
        let end = absolute
            .checked_add(len)
            .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
        self.source.read_range(absolute..end)
    }
}

fn read_encrypted_header_at(
    file: &mut impl WalkSource,
    file_len: u64,
    archive_offset: usize,
    offset: usize,
    password: &[u8],
    cipher_cache: &mut EncryptedHeaderCipherCache,
) -> Result<EncryptedHeader> {
    let absolute = archive_offset
        .checked_add(offset)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    if absolute as u64 + 24 > file_len {
        return Err(Error::TooShort);
    }
    let first = file.read_at(absolute, 24)?;
    let salt = read_header_salt(&first, 0)?;
    let mut cipher = cipher_cache.cipher(password, salt)?;
    let mut first_block = [0u8; 16];
    first_block.copy_from_slice(&first[8..24]);
    cipher
        .decrypt_in_place(&mut first_block)
        .map_err(map_rar30_crypto_error)?;
    let head_size = read_u16(&first_block, 5)? as usize;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    let encrypted_header_size = checked_align16(head_size, "RAR 1.5 block size overflows usize")?;
    let encrypted_start = absolute
        .checked_add(8)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    if encrypted_start as u64 + encrypted_header_size as u64 > file_len {
        return Err(Error::TooShort);
    }
    let encrypted_rest = file.read_at(encrypted_start + 16, encrypted_header_size - 16)?;
    let mut header = Vec::with_capacity(encrypted_header_size);
    header.extend_from_slice(&first_block);
    header.extend_from_slice(&encrypted_rest);
    cipher
        .decrypt_in_place(&mut header[16..])
        .map_err(map_rar30_crypto_error)?;
    header.truncate(head_size);

    let mut block = parse_block_header(&header, 0)?;
    block.offset = offset;
    let payload_size = usize::try_from(block.add_size.unwrap_or(0))
        .map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let total_size = 8usize
        .checked_add(encrypted_header_size)
        .and_then(|size| size.checked_add(payload_size))
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    Ok(EncryptedHeader {
        block,
        header,
        total_size,
    })
}

fn read_header_salt(input: &[u8], offset: usize) -> Result<[u8; 8]> {
    input
        .get(offset..offset + 8)
        .ok_or(Error::TooShort)
        .map(|salt| salt.try_into().expect("RAR 3 salt size"))
}

fn parse_file_like_header(
    input: &[u8],
    block: BlockHeader,
    archive_offset: usize,
) -> Result<FileHeader> {
    if block.head_size < 32 {
        return Err(Error::InvalidHeader("RAR 1.5 file header is too short"));
    }
    if block.flags & LONG_BLOCK == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 file header is missing packed data size",
        ));
    }

    let start = block.offset;
    let head_end = start + block.head_size as usize;
    if head_end > input.len() {
        return Err(Error::TooShort);
    }

    let pack_low = read_u32(input, start + 7)? as u64;
    let unp_low = read_u32(input, start + 11)? as u64;
    let host_os = input[start + 15];
    let file_crc = read_u32(input, start + 16)?;
    let file_time = read_u32(input, start + 20)?;
    let unp_ver = input[start + 24];
    let method = input[start + 25];
    let name_size = read_u16(input, start + 26)? as usize;
    let attr = read_u32(input, start + 28)?;
    let mut pos = start + 32;

    let (pack_size, unp_size) = if block.flags & FHD_LARGE != 0 {
        let high_pack = read_u32(input, pos)? as u64;
        let high_unp = read_u32(input, pos + 4)? as u64;
        pos += 8;
        ((high_pack << 32) | pack_low, (high_unp << 32) | unp_low)
    } else {
        (pack_low, unp_low)
    };

    let name_end = pos
        .checked_add(name_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 file name size overflows"))?;
    if name_end > head_end {
        return Err(Error::InvalidHeader(
            "RAR 1.5 file name extends beyond header",
        ));
    }
    let name = decode_file_name(&input[pos..name_end], block.flags);
    pos = name_end;

    let salt = if block.flags & FHD_SALT != 0 {
        let salt_end = pos
            .checked_add(8)
            .ok_or(Error::InvalidHeader("RAR 1.5 salt size overflows"))?;
        if salt_end > head_end {
            return Err(Error::InvalidHeader(
                "RAR 1.5 salt extends beyond file header",
            ));
        }
        let salt_bytes = input.get(pos..salt_end).ok_or(Error::TooShort)?;
        pos = salt_end;
        Some(
            salt_bytes
                .try_into()
                .expect("RAR 1.5 salt slice has fixed length"),
        )
    } else {
        None
    };

    let file_comment = if block.flags & FHD_COMMENT != 0 {
        if pos + 2 <= head_end {
            let comment_len = read_u16(input, pos)? as usize;
            let comment_total = comment_len
                .checked_add(2)
                .ok_or(Error::InvalidHeader("RAR 1.5 file comment size overflows"))?;
            let comment_end = pos
                .checked_add(comment_total)
                .ok_or(Error::InvalidHeader("RAR 1.5 file comment size overflows"))?;
            if comment_end <= head_end {
                let comment = input[pos..comment_end].to_vec();
                pos = comment_end;
                comment
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let ext_time = if block.flags & FHD_EXTTIME != 0 {
        input[pos..head_end].to_vec()
    } else {
        Vec::new()
    };
    let data_start = head_end;
    let data_len = usize::try_from(pack_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed file size overflows usize"))?;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(Error::InvalidHeader(
            "RAR 1.5 packed file size overflows usize",
        ))?;
    Ok(FileHeader {
        block,
        pack_size,
        unp_size,
        host_os,
        file_crc,
        file_time,
        unp_ver,
        method,
        name,
        attr,
        salt,
        file_comment,
        ext_time,
        packed_range: archive_offset + data_start..archive_offset + data_end,
    })
}

fn decode_file_name(raw: &[u8], flags: u16) -> Vec<u8> {
    if flags & FHD_UNICODE == 0 {
        return raw.to_vec();
    }

    let Some(zero_pos) = raw.iter().position(|byte| *byte == 0) else {
        return raw.to_vec();
    };
    if zero_pos + 1 >= raw.len() {
        return raw[..zero_pos].to_vec();
    }

    let fallback = &raw[..zero_pos];
    let high_byte = raw[zero_pos + 1];
    let encoded = &raw[zero_pos + 2..];
    let mut pos = 0usize;
    let mut flag_byte = 0u8;
    let mut flag_bits = 0u8;
    let mut dst_pos = 0usize;
    let mut units = Vec::new();

    // WinRAR's decoder stops at `MaxDecSize` (NM). Without that ceiling a
    // mode-3 run emits up to 129 output units per encoded byte, so a single
    // u16-bounded header (~65 KB) decodes to ~6.7 MB of retained String -
    // ~100x amplification from attacker-supplied archive bytes. A real RAR4
    // name never approaches this.
    const MAX_NAME_UNITS: usize = 2048;
    while pos < encoded.len() && units.len() < MAX_NAME_UNITS {
        if flag_bits == 0 {
            flag_byte = encoded[pos];
            pos += 1;
            flag_bits = 8;
        }
        let mode = flag_byte >> 6;
        flag_byte <<= 2;
        flag_bits -= 2;

        match mode {
            0 => {
                let Some(&low) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                units.push(u16::from(low));
                dst_pos += 1;
            }
            1 => {
                let Some(&low) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                units.push((u16::from(high_byte) << 8) | u16::from(low));
                dst_pos += 1;
            }
            2 => {
                let Some((&low, &high)) = encoded.get(pos).zip(encoded.get(pos + 1)) else {
                    return raw.to_vec();
                };
                pos += 2;
                units.push((u16::from(high) << 8) | u16::from(low));
                dst_pos += 1;
            }
            3 => {
                let Some(&length_byte) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                let (count, correction, high) = if length_byte & 0x80 != 0 {
                    let Some(&correction) = encoded.get(pos) else {
                        return raw.to_vec();
                    };
                    pos += 1;
                    ((length_byte & 0x7f) as usize + 2, correction, high_byte)
                } else {
                    (length_byte as usize + 2, 0, 0)
                };
                // Clamp the run to the same ceiling - the loop guard above
                // only sees whole iterations, and one run can emit 129 units.
                let count = count.min(MAX_NAME_UNITS - units.len());
                for _ in 0..count {
                    let low = fallback
                        .get(dst_pos)
                        .copied()
                        .unwrap_or(b'?')
                        .wrapping_add(correction);
                    units.push((u16::from(high) << 8) | u16::from(low));
                    dst_pos += 1;
                }
            }
            _ => unreachable!("2-bit filename mode"),
        }
    }

    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .into_bytes()
}

fn read_block_header_at(
    file: &mut impl WalkSource,
    file_len: u64,
    archive_offset: usize,
    offset: usize,
) -> Result<BlockHeader> {
    let absolute = archive_offset
        .checked_add(offset)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    if absolute as u64 + 7 > file_len {
        return Err(Error::TooShort);
    }
    let base = file.read_at(absolute, 7)?;
    let head_size = read_u16(&base, 5)? as usize;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    if absolute as u64 + head_size as u64 > file_len {
        return Err(Error::TooShort);
    }
    let mut header = if head_size == 7 {
        base
    } else {
        file.read_at(absolute, head_size)?
    };
    // A unix-owner sub-block is checksummed over its trailing owner and group
    // names, which live past `head_size` in the data area - read them in, or
    // `parse_block_header` has to skip the check for want of the bytes.
    let head_type = header[2];
    let flags = read_u16(&header, 3)?;
    if let Some(extra) = unix_owner_crc_extra(&header, 0, head_type, flags, head_size as u16)? {
        let want = head_size
            .checked_add(extra)
            .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
        if absolute as u64 + want as u64 <= file_len {
            header = file.read_at(absolute, want)?;
        }
    }
    let mut block = parse_block_header(&header, 0)?;
    block.offset = offset;
    Ok(block)
}

fn relative_block(block: &BlockHeader) -> BlockHeader {
    let mut relative = block.clone();
    relative.offset = 0;
    relative
}

struct CrcWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    crc: &'a mut Crc32,
}

impl<W: Write + ?Sized> Write for CrcWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.crc.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn parse_block_header(input: &[u8], offset: usize) -> Result<BlockHeader> {
    if input.len() < offset + 7 {
        return Err(Error::TooShort);
    }
    let head_crc = read_u16(input, offset)?;
    let head_type = input[offset + 2];
    let flags = read_u16(input, offset + 3)?;
    let head_size = read_u16(input, offset + 5)?;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    let add_size = if flags & LONG_BLOCK != 0 {
        Some(read_u32(input, offset + 7)? as u64)
    } else {
        None
    };
    if offset + head_size as usize > input.len() {
        return Err(Error::TooShort);
    }
    if head_type != MARK_HEAD && should_validate_header_crc(head_type) {
        // `None` means the covered range runs past the bytes we were handed -
        // only reachable for a unix-owner sub-block whose trailing names sit
        // outside the buffer (a truncated archive, or the encrypted-header
        // window, which is decrypted and cut to `head_size`). Skipping beats
        // checksumming a range the writer never checksummed.
        if let Some(header_end) = header_crc_end(input, offset, head_type, flags, head_size)? {
            let actual = (crc32(&input[offset + 2..header_end]) & 0xffff) as u16;
            if actual != head_crc {
                return Err(Error::CrcMismatch {
                    expected: head_crc,
                    actual,
                });
            }
        }
    }
    validate_legacy_auth_block_size(head_type, head_size)?;

    Ok(BlockHeader {
        head_crc,
        head_type,
        flags,
        head_size,
        add_size,
        offset,
    })
}

/// End of the byte range the block's `HEAD_CRC` covers, or `None` when that
/// range is not fully present in `input`.
fn header_crc_end(
    input: &[u8],
    offset: usize,
    head_type: u8,
    flags: u16,
    head_size: u16,
) -> Result<Option<usize>> {
    let full_end = offset + head_size as usize;
    if let Some(extra) = unix_owner_crc_extra(input, offset, head_type, flags, head_size)? {
        let end = full_end
            .checked_add(extra)
            .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
        return Ok((end <= input.len()).then_some(end));
    }
    let fixed_end = match head_type {
        MAIN_HEAD if flags & MHD_COMMENT != 0 => Some(offset + 13),
        COMM_HEAD => Some(offset + 13),
        FILE_HEAD if flags & FHD_COMMENT != 0 => Some(file_header_comment_crc_end(input, offset)?),
        _ => None,
    };
    Ok(Some(fixed_end.unwrap_or(full_end).min(full_end)))
}

/// How many bytes PAST `head_size` the `HEAD_CRC` of a RAR 2.x unix-owner
/// sub-block covers, or `None` when the block is not one.
///
/// `UO_HEAD` (`0x77` sub type `0x0101`) declares an owner and a group name
/// size in its fixed part but stores the names themselves in the block's data
/// area, past `head_size`. unrar reads both names into the same raw header
/// buffer before checksumming it (`Raw.Read(OwnerNameSize)` /
/// `Raw.Read(GroupNameSize)`, then `Raw.GetCRC15(false)` over the whole
/// buffer), so the CRC WinRAR stamped covers them too. Checksumming only
/// `head_size` rejects archives `rar`, `unrar` and `7z` all read - it is what
/// made `rar2-unix-owner.rar` fail with `expected 0x1fc3, got 0x974d`.
///
/// The extension is deliberately keyed on the sub type, not on the block's
/// data size: other sub-block flavours (`EA_HEAD`, `NTACL_HEAD`, `STREAM_HEAD`)
/// carry a payload their header CRC does not cover, and this fixture cannot
/// tell the two rules apart because its names happen to fill the data area
/// exactly.
fn unix_owner_crc_extra(
    input: &[u8],
    offset: usize,
    head_type: u8,
    flags: u16,
    head_size: u16,
) -> Result<Option<usize>> {
    if head_type != SUB_HEAD
        || flags & LONG_BLOCK == 0
        || (head_size as usize) < SIZEOF_UOWNERHEAD
        || input.len() < offset + SIZEOF_UOWNERHEAD
    {
        return Ok(None);
    }
    if read_u16(input, offset + 11)? != UO_HEAD {
        return Ok(None);
    }
    let owner_name_size = read_u16(input, offset + 14)? as usize;
    let group_name_size = read_u16(input, offset + 16)? as usize;
    Ok(Some(owner_name_size + group_name_size))
}

fn file_header_comment_crc_end(input: &[u8], offset: usize) -> Result<usize> {
    if input.len() < offset + 32 {
        return Err(Error::TooShort);
    }
    let flags = read_u16(input, offset + 3)?;
    let name_size = read_u16(input, offset + 26)? as usize;
    let mut end = offset + 32;
    if flags & FHD_LARGE != 0 {
        end = end
            .checked_add(8)
            .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    }
    end = end
        .checked_add(name_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    if flags & FHD_SALT != 0 {
        end = end
            .checked_add(8)
            .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    }
    Ok(end)
}

fn should_validate_header_crc(head_type: u8) -> bool {
    // Historical AV/SIGN blocks are documented with inconsistent CRC fields in
    // real archives, so readers must not reject them solely on HEAD_CRC.
    !matches!(head_type, 0x76 | 0x79)
}

fn validate_legacy_auth_block_size(head_type: u8, head_size: u16) -> Result<()> {
    let minimum = match head_type {
        0x76 => 21,
        0x79 => 182,
        _ => return Ok(()),
    };
    if head_size < minimum {
        return Err(Error::InvalidHeader(
            "RAR legacy authenticity block is too short",
        ));
    }
    Ok(())
}

fn block_total_size(block: &BlockHeader) -> Result<usize> {
    let total = block.head_size as u64 + block.add_size.unwrap_or(0);
    usize::try_from(total).map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))
}

fn file_block_total_size(
    block: &BlockHeader,
    default_total: usize,
    pack_size: u64,
) -> Result<usize> {
    let low_payload_size = usize::try_from(block.add_size.unwrap_or(0))
        .map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let header_prefix = default_total
        .checked_sub(low_payload_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let pack_size = usize::try_from(pack_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed file size overflows usize"))?;
    header_prefix
        .checked_add(pack_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))
}

fn checked_block_next(block: &BlockHeader, total: usize, archive_len: usize) -> Result<usize> {
    let next = block
        .offset
        .checked_add(total)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    if next > archive_len {
        return Err(Error::TooShort);
    }
    Ok(next)
}

fn checked_file_block_next(
    sfx_offset: usize,
    block: &BlockHeader,
    total: usize,
    file_len: u64,
) -> Result<usize> {
    let next = block
        .offset
        .checked_add(total)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let absolute_next = sfx_offset
        .checked_add(next)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    if absolute_next as u64 > file_len {
        return Err(Error::TooShort);
    }
    Ok(next)
}

fn packed_range(
    archive_offset: usize,
    block_offset: usize,
    total: usize,
    pack_size: u64,
) -> Result<Range<usize>> {
    let pack_size = usize::try_from(pack_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed file size overflows usize"))?;
    let block_end = archive_offset
        .checked_add(block_offset)
        .and_then(|start| start.checked_add(total))
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let block_start = block_end
        .checked_sub(pack_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    Ok(block_start..block_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_write_main_header(out: &mut Vec<u8>, flags: u16) {
        let start = out.len();
        out.extend_from_slice(&0u16.to_le_bytes());
        out.push(MAIN_HEAD);
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&13u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        test_write_header_crc(out, start);
    }

    fn test_write_header_crc(out: &mut [u8], start: usize) {
        let crc = (crc32(&out[start + 2..]) & 0xffff) as u16;
        out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
    }

    fn legacy_auth_block(head_type: u8, head_size: u16) -> Vec<u8> {
        let mut block = vec![0; head_size as usize];
        block[2] = head_type;
        block[5..7].copy_from_slice(&head_size.to_le_bytes());
        block
    }

    #[test]
    fn rejects_too_short_legacy_auth_blocks_even_without_crc_check() {
        assert!(matches!(
            parse_block_header(&legacy_auth_block(0x76, 20), 0),
            Err(Error::InvalidHeader(
                "RAR legacy authenticity block is too short"
            ))
        ));
        assert!(matches!(
            parse_block_header(&legacy_auth_block(0x79, 181), 0),
            Err(Error::InvalidHeader(
                "RAR legacy authenticity block is too short"
            ))
        ));
    }

    #[test]
    fn accepts_minimum_legacy_auth_block_sizes_with_bad_crc() {
        assert_eq!(
            parse_block_header(&legacy_auth_block(0x76, 21), 0)
                .unwrap()
                .head_size,
            21
        );
        assert_eq!(
            parse_block_header(&legacy_auth_block(0x79, 182), 0)
                .unwrap()
                .head_size,
            182
        );
    }

    #[test]
    fn parses_fhd_large_high_size_fields_from_file_header() {
        let name = b"large.bin";
        let head_size = 32 + 8 + name.len();
        let mut header = Vec::new();
        header.extend_from_slice(&0u16.to_le_bytes());
        header.push(FILE_HEAD);
        header.extend_from_slice(&(LONG_BLOCK | FHD_LARGE).to_le_bytes());
        header.extend_from_slice(&(head_size as u16).to_le_bytes());
        header.extend_from_slice(&0x89ab_cdefu32.to_le_bytes());
        header.extend_from_slice(&0x7654_3210u32.to_le_bytes());
        header.push(3);
        header.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        header.extend_from_slice(&0x5a21_0000u32.to_le_bytes());
        header.push(29);
        header.push(0x35);
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&0x20u32.to_le_bytes());
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&2u32.to_le_bytes());
        header.extend_from_slice(name);

        let block = BlockHeader {
            head_crc: 0,
            head_type: FILE_HEAD,
            flags: LONG_BLOCK | FHD_LARGE,
            head_size: head_size as u16,
            add_size: Some(0x89ab_cdef),
            offset: 0,
        };
        // The declared packed size is 0x1_89ab_cdef (~6.6 GB), which is a
        // legal FHD_LARGE value and does not fit a 32-bit `usize`.
        // `packed_range` is a `Range<usize>`, so a 32-bit host (armv7)
        // cannot represent this extent and the parser REFUSES the header
        // rather than truncating it - the shape asserted below. That
        // refusal is the whole point: a wrapped range would hand the
        // extractor a window into the wrong bytes.
        #[cfg(target_pointer_width = "32")]
        {
            assert!(matches!(
                parse_file_like_header(&header, block, 0),
                Err(Error::InvalidHeader(
                    "RAR 1.5 packed file size overflows usize"
                ))
            ));
        }
        #[cfg(not(target_pointer_width = "32"))]
        {
            let file = parse_file_like_header(&header, block, 0).unwrap();

            assert_eq!(file.pack_size, 0x0000_0001_89ab_cdef);
            assert_eq!(file.unp_size, 0x0000_0002_7654_3210);
            assert_eq!(file.name, name);
            assert_eq!(
                file.packed_range,
                head_size..head_size + 0x0000_0001_89ab_cdef_usize
            );
        }
    }

    #[test]
    fn fhd_large_archive_extent_uses_high_packed_size_without_underflowing() {
        let name = b"large-zero-low.bin";
        let head_size = 32 + 8 + name.len();
        let mut archive = Vec::from(RAR15_SIGNATURE);
        test_write_main_header(&mut archive, 0);

        let start = archive.len();
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.push(FILE_HEAD);
        archive.extend_from_slice(&(LONG_BLOCK | FHD_LARGE).to_le_bytes());
        archive.extend_from_slice(&(head_size as u16).to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.push(3);
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&0x5a21_0000u32.to_le_bytes());
        archive.push(29);
        archive.push(0x35);
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0x20u32.to_le_bytes());
        archive.extend_from_slice(&1u32.to_le_bytes());
        archive.extend_from_slice(&1u32.to_le_bytes());
        archive.extend_from_slice(name);
        test_write_header_crc(&mut archive, start);

        // pack_size is 0x1_0000_0000 - low word zero, high word one - so a
        // parser that ignored the high word would compute a ZERO-length
        // extent and sail past. It must refuse. WHICH refusal depends on
        // the pointer width and both are correct: 64-bit builds the 4 GiB
        // extent and finds the archive too short for it, while 32-bit
        // cannot represent the extent at all and says so at the cast.
        // What must never happen on either is Ok.
        #[cfg(target_pointer_width = "32")]
        assert!(matches!(
            Archive::parse(&archive),
            Err(Error::InvalidHeader(
                "RAR 1.5 packed file size overflows usize"
            ))
        ));
        #[cfg(not(target_pointer_width = "32"))]
        assert!(matches!(Archive::parse(&archive), Err(Error::TooShort)));
    }

    fn block_header_with(flags: u16) -> BlockHeader {
        BlockHeader {
            head_crc: 0,
            head_type: FILE_HEAD,
            flags,
            head_size: 32,
            add_size: None,
            offset: 0,
        }
    }

    fn file_header_with(flags: u16) -> FileHeader {
        FileHeader {
            block: block_header_with(flags),
            pack_size: 0,
            unp_size: 0,
            host_os: 0,
            file_crc: 0,
            file_time: 0,
            unp_ver: 29,
            method: 0x30,
            name: b"entry".to_vec(),
            attr: 0,
            salt: None,
            file_comment: Vec::new(),
            ext_time: Vec::new(),
            packed_range: 0..0,
        }
    }

    fn main_header_with(flags: u16) -> MainHeader {
        MainHeader {
            head_crc: 0,
            flags,
            head_size: 13,
            reserved1: 0,
            reserved2: 0,
            encrypt_version: None,
        }
    }

    #[test]
    fn main_header_predicates_match_each_flag_bit() {
        let cases = [
            (MHD_VOLUME, MainHeader::is_volume as fn(&MainHeader) -> bool),
            (MHD_COMMENT, MainHeader::has_archive_comment),
            (MHD_SOLID, MainHeader::is_solid),
            (MHD_NEWNUMBERING, MainHeader::uses_new_numbering),
            (MHD_PROTECT, MainHeader::has_recovery_record),
            (MHD_PASSWORD, MainHeader::has_encrypted_headers),
            (MHD_FIRSTVOLUME, MainHeader::is_first_volume),
        ];
        let zero = main_header_with(0);
        for (bit, predicate) in cases {
            assert!(
                !predicate(&zero),
                "expected false when bit {bit:#x} is clear"
            );
            let one = main_header_with(bit);
            assert!(predicate(&one), "expected true when bit {bit:#x} is set");
        }
    }

    #[test]
    fn file_header_flag_predicates_track_each_bit() {
        let cases = [
            (
                FHD_SPLIT_BEFORE,
                FileHeader::is_split_before as fn(&FileHeader) -> bool,
            ),
            (FHD_SPLIT_AFTER, FileHeader::is_split_after),
            (FHD_PASSWORD, FileHeader::is_encrypted),
            (FHD_SOLID, FileHeader::is_solid),
            (FHD_EXTTIME, FileHeader::has_ext_time),
        ];
        let zero = file_header_with(0);
        for (bit, predicate) in cases {
            assert!(
                !predicate(&zero),
                "expected false on FileHeader for bit {bit:#x}"
            );
            let one = file_header_with(bit);
            assert!(
                predicate(&one),
                "expected true on FileHeader for bit {bit:#x}"
            );
        }

        let directory = file_header_with(FHD_DIRECTORY_MASK);
        assert!(directory.is_directory());
        assert!(!file_header_with(0).is_directory());

        let stored = file_header_with(0);
        assert!(stored.is_stored());
        let mut packed = file_header_with(0);
        packed.method = 0x33;
        assert!(!packed.is_stored());
    }

    #[test]
    fn file_header_comment_extracts_payload_after_two_byte_size_prefix() {
        let mut without_flag = file_header_with(0);
        without_flag.file_comment = vec![3, 0, b'a', b'b', b'c'];
        assert!(!without_flag.has_file_comment());
        assert_eq!(without_flag.file_comment().unwrap(), None);

        let mut with_flag = file_header_with(FHD_COMMENT);
        with_flag.file_comment = vec![3, 0, b'h', b'e', b'y'];
        assert!(with_flag.has_file_comment());
        assert_eq!(with_flag.file_comment().unwrap().unwrap(), b"hey");

        let mut empty_flagged = file_header_with(FHD_COMMENT);
        empty_flagged.file_comment.clear();
        assert!(!empty_flagged.has_file_comment());

        let mut truncated = file_header_with(FHD_COMMENT);
        truncated.file_comment = vec![10, 0, b'a'];
        assert!(matches!(truncated.file_comment(), Err(Error::TooShort)));
    }

    #[test]
    fn file_header_name_metadata_and_crc_helpers_describe_entry() {
        let mut header = file_header_with(0);
        header.name = b"r\xc3\xa9sum\xc3\xa9.txt".to_vec();
        header.file_crc = crc32(b"hello");
        header.attr = 0x20;
        header.host_os = 3;
        header.file_time = 0x5a21_0000;

        assert_eq!(header.name_bytes(), b"r\xc3\xa9sum\xc3\xa9.txt");
        assert_eq!(header.name_lossy(), "résumé.txt");
        let meta = header.metadata();
        assert_eq!(meta.name, header.name);
        assert_eq!(meta.attr, 0x20);
        assert_eq!(meta.host_os, 3);
        assert_eq!(meta.file_time, 0x5a21_0000);
        assert!(!meta.is_directory);

        header.verify_crc32(b"hello").unwrap();
        match header.verify_crc32(b"different") {
            Err(Error::Crc32Mismatch { expected, actual }) => {
                assert_eq!(expected, header.file_crc);
                assert_ne!(actual, expected);
            }
            other => panic!("expected Crc32Mismatch, got {other:?}"),
        }

        let directory = file_header_with(FHD_DIRECTORY_MASK);
        assert!(directory.metadata().is_directory);

        // Garbage bytes still produce a String through lossy decoding.
        let mut garbage = file_header_with(0);
        garbage.name = vec![0xff, 0xfe, b'/', 0x80, b'x'];
        let lossy = garbage.name_lossy();
        assert!(lossy.ends_with("/\u{fffd}x"), "got {lossy:?}");
    }

    #[test]
    fn newsub_header_name_lossy_delegates_to_inner_file_header() {
        let mut file = file_header_with(0);
        file.name = b"CMT".to_vec();
        let sub = NewSubHeader {
            file,
            kind: NewSubKind::ArchiveComment,
        };
        assert_eq!(sub.name_lossy(), "CMT");
    }

    #[test]
    fn writer_options_constructor_and_default_match_documented_targets() {
        let default = WriterOptions::default();
        assert_eq!(default.target, ArchiveVersion::Rar15);
        assert_eq!(default.features, FeatureSet::store_only());

        let explicit = WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only());
        assert_eq!(explicit.target, ArchiveVersion::Rar20);
        assert_eq!(explicit.features, FeatureSet::store_only());
    }

    fn stored_archive_bytes(name: &[u8], data: &[u8]) -> Vec<u8> {
        write_stored_archive(
            &[StoredEntry {
                name,
                data,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            WriterOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn archive_parse_owned_consumes_buffer_without_changing_dispatch() {
        let bytes = stored_archive_bytes(b"owned.txt", b"hello rar15 owned");
        let archive = Archive::parse_owned(bytes.clone()).unwrap();
        assert_eq!(archive.files().count(), 1);
        let file = archive.files().next().unwrap();
        assert_eq!(file.name, b"owned.txt");

        // Default ArchiveReadOptions delegate also drives the same code path.
        let with_options =
            Archive::parse_owned_with_options(bytes.clone(), crate::ArchiveReadOptions::default())
                .unwrap();
        assert_eq!(with_options.files().count(), 1);

        let no_password = Archive::parse_owned_with_password(bytes, None).unwrap();
        assert_eq!(no_password.files().count(), 1);
    }

    #[test]
    fn archive_parse_owned_with_password_unlocks_encrypted_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = write_stored_archive(
            &[StoredEntry {
                name: b"locked.txt",
                data: b"encrypted owned payload",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"pw"),
                file_comment: None,
            }],
            WriterOptions {
                target: ArchiveVersion::Rar20,
                features,
                compression_level: None,
                dictionary_size: None,
                entropy: Entropy::Os,
                volume_numbering: VolumeNumbering::Classic,
                recovery_percent: None,
            },
        )
        .unwrap();

        let archive = Archive::parse_owned_with_password(bytes, Some(b"pw")).unwrap();
        let file = archive.files().next().unwrap();
        assert!(file.is_encrypted());
    }

    #[test]
    fn file_header_write_packed_data_streams_through_writer() {
        let payload = b"write_packed_data direct dump";
        let bytes = stored_archive_bytes(b"dump.bin", payload);
        let archive = Archive::parse(&bytes).unwrap();
        let file = archive.files().next().unwrap();

        let mut sink = Vec::new();
        file.write_packed_data(&archive, &mut sink).unwrap();
        assert_eq!(sink, payload);
    }

    #[test]
    fn file_header_unsupported_compression_describes_method_and_unpack_version() {
        let mut header = file_header_with(0);
        header.method = 0x33;
        header.unp_ver = 26;
        let err = header.unsupported_compression();
        assert!(matches!(
            err,
            Error::UnsupportedCompression {
                family: "RAR 1.5-4.x",
                unpack_version: 26,
                method: 0x33,
            }
        ));
    }

    #[test]
    fn file_header_unsupported_encryption_describes_unpack_version() {
        let mut header = file_header_with(FHD_PASSWORD);
        header.unp_ver = 36;
        let err = header.unsupported_encryption();
        assert!(matches!(
            err,
            Error::UnsupportedEncryption {
                family: "RAR 1.5-4.x",
                unpack_version: 36,
            }
        ));
    }

    #[test]
    fn crc_writer_flush_propagates_to_inner_writer() {
        struct FlushSpy {
            data: Vec<u8>,
            flushed: usize,
        }
        impl Write for FlushSpy {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.data.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushed += 1;
                Ok(())
            }
        }
        let mut inner = FlushSpy {
            data: Vec::new(),
            flushed: 0,
        };
        let mut crc = Crc32::new();
        let mut writer = CrcWriter {
            inner: &mut inner,
            crc: &mut crc,
        };
        writer.write_all(b"hi").unwrap();
        writer.flush().unwrap();
        assert_eq!(inner.data, b"hi");
        assert_eq!(inner.flushed, 1);
    }

    #[test]
    fn parse_main_header_rejects_block_size_below_minimum() {
        let block = BlockHeader {
            head_crc: 0,
            head_type: MAIN_HEAD,
            flags: 0,
            head_size: 12,
            add_size: None,
            offset: 0,
        };
        let err = parse_main_header(&[0u8; 32], &block).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.5 main header is too short")
        );
    }

    #[test]
    fn parse_main_header_rejects_block_extending_past_input_buffer() {
        let block = BlockHeader {
            head_crc: 0,
            head_type: MAIN_HEAD,
            flags: 0,
            head_size: 13,
            add_size: None,
            offset: 8,
        };
        // Buffer is shorter than offset + head_size.
        let err = parse_main_header(&[0u8; 16], &block).unwrap_err();
        assert_eq!(err, Error::TooShort);
    }

    #[test]
    fn parse_main_header_reads_encrypt_version_when_flag_is_set() {
        // Build a synthetic main header at offset 0: 13 bytes of base + 1 byte
        // for the encrypt_version field at position 13.
        let mut input = vec![0u8; 14];
        input[13] = 0x29;
        let block = BlockHeader {
            head_crc: 0,
            head_type: MAIN_HEAD,
            flags: MHD_ENCRYPTVER,
            head_size: 14,
            add_size: None,
            offset: 0,
        };
        let main = parse_main_header(&input, &block).unwrap();
        assert_eq!(main.encrypt_version, Some(0x29));
    }

    #[test]
    fn decode_file_name_returns_raw_when_unicode_flag_is_clear() {
        let raw = b"plain.txt";
        let decoded = decode_file_name(raw, 0);
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_file_name_returns_raw_when_unicode_marker_is_missing() {
        // FHD_UNICODE set but no zero byte to split fallback from encoded
        // payload — the decoder falls back to the raw bytes.
        let raw = b"no-zero-marker";
        let decoded = decode_file_name(raw, FHD_UNICODE);
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_file_name_returns_fallback_when_no_encoded_payload_follows_zero() {
        // Zero byte present but nothing after it — the decoder returns just
        // the fallback prefix.
        let mut raw = b"fallback".to_vec();
        raw.push(0);
        let decoded = decode_file_name(&raw, FHD_UNICODE);
        assert_eq!(decoded, b"fallback");
    }

    #[test]
    fn decode_file_name_decodes_mode_zero_low_byte_only_units() {
        // Mode 0 emits one ASCII byte per code unit. Encoded payload format:
        //   high_byte, flag_byte, byte0, byte1, ...
        // flag_byte = 0b00_00_00_00 → four mode-0 emits.
        let mut raw = b"orig".to_vec();
        raw.push(0); // separator
        raw.push(0); // high_byte (unused for mode 0)
        raw.push(0b00_00_00_00); // flag_byte: four mode-0 codes
        raw.extend_from_slice(b"abcd");
        let decoded = decode_file_name(&raw, FHD_UNICODE);
        assert_eq!(decoded, b"abcd");
    }

    #[test]
    fn decode_file_name_decodes_mode_two_full_two_byte_units() {
        // Mode 2 reads (low, high) bytes for a full UTF-16 code unit.
        // Encode "Hi" via mode 2 twice: flag_byte = 0b10_10_00_00.
        let mut raw = b"".to_vec();
        raw.push(0); // separator (zero_pos = 0)
        raw.push(0); // high_byte placeholder
                     // Two mode-2 units, then two mode-0 units which we will not reach.
        raw.push(0b10_10_00_00);
        // First unit 'H' = U+0048: low=0x48, high=0x00
        raw.extend_from_slice(&[0x48, 0x00]);
        // Second unit 'i' = U+0069
        raw.extend_from_slice(&[0x69, 0x00]);
        let decoded = decode_file_name(&raw, FHD_UNICODE);
        // The decoder may emit further units from the trailing flag bits;
        // accept any output that begins with "Hi".
        assert!(decoded.starts_with(b"Hi"), "got {decoded:?}");
    }
}
