use crate::codec::rar13::{
    unpack15_decode, unpack15_encode, unpack15_encode_with_options_and_progress,
    EncodeOptions as Rar15EncodeOptions, Unpack15, Unpack15Encoder,
};
use crate::crypto::rar13::{Rar13Cipher, Rar13DecryptReader};
use crate::detect::{find_archive_start, ArchiveSignature, RAR13_SIGNATURE, SFX_SCAN_LIMIT};
use crate::error::{Error, Result};
use crate::features::FeatureSet;
use crate::io_util::{read_exact_at, read_u16, read_u32};
pub(crate) use crate::source::ArchiveSource;
use crate::version::{ArchiveFamily, ArchiveVersion};
use crate::volume_extract::{FragmentOpener, LazyChainedReader};
use crate::write_progress::{ProgressReporter, WorkTracker};
use crate::{WriteOperation, WriteProgress, WriteProgressEvent};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

const MAIN_HEAD_SIZE: u16 = 7;
const FILE_HEAD_BASE_SIZE: usize = 21;
const MHD_VOLUME: u8 = 0x01;
const MHD_COMMENT: u8 = 0x02;
const MHD_SOLID: u8 = 0x08;
const MHD_PACK_COMMENT: u8 = 0x10;
const MHD_AV: u8 = 0x20;
const MHD_ALWAYS_SET: u8 = 0x80;
const RAR13_AV_PREFIX: &[u8; 6] = b"\x1ai\x6d\x02\xda\xae";
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const LHD_SPLIT_BEFORE: u8 = 0x01;
const LHD_SPLIT_AFTER: u8 = 0x02;
const LHD_PASSWORD: u8 = 0x04;
const LHD_COMMENT: u8 = 0x08;
const LHD_SOLID: u8 = 0x10;
const METHOD_STORE: u8 = 0;
const METHOD_BEST: u8 = 5;
const DEFAULT_UNP_VER: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MainHeader {
    pub flags: u8,
    pub head_size: u16,
    pub extra: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHeader {
    pub flags: u8,
    pub pack_size: u32,
    pub unp_size: u32,
    pub file_crc: u16,
    pub file_time: u32,
    pub file_attr: u8,
    pub unp_ver: u8,
    pub method: u8,
    pub head_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    pub header: FileHeader,
    pub name: Vec<u8>,
    pub extra: Vec<u8>,
    pub packed_range: Range<usize>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Archive {
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub entries: Vec<Entry>,
    source: ArchiveSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthenticityVerification {
    pub size: u16,
    pub prefix: [u8; 6],
    pub cipher_body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticityVerificationStatus {
    Absent,
    StructurallyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub file_attr: u8,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriterOptions {
    pub target: ArchiveVersion,
    pub features: FeatureSet,
    pub compression_level: Option<u8>,
}

impl WriterOptions {
    pub const fn new(target: ArchiveVersion, features: FeatureSet) -> Self {
        Self {
            target,
            features,
            compression_level: None,
        }
    }

    pub const fn with_compression_level(mut self, level: u8) -> Self {
        self.compression_level = Some(level);
        self
    }
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: ArchiveVersion::Rar14,
            features: FeatureSet::store_only(),
            compression_level: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.flags & MHD_VOLUME != 0
    }

    pub fn has_archive_comment(&self) -> bool {
        self.flags & MHD_COMMENT != 0
    }

    pub fn has_packed_comment(&self) -> bool {
        self.flags & MHD_PACK_COMMENT != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHD_SOLID != 0
    }

    pub fn has_authenticity_verification(&self) -> bool {
        self.flags & MHD_AV != 0
    }

    fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < MAIN_HEAD_SIZE as usize {
            return Err(Error::TooShort);
        }
        if !input.starts_with(RAR13_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let head_size = read_u16(input, 4)?;
        let flags = input[6];
        if head_size < MAIN_HEAD_SIZE {
            return Err(Error::InvalidHeader(
                "RAR 1.3 main header is shorter than 7 bytes",
            ));
        }
        if head_size as usize > input.len() {
            return Err(Error::TooShort);
        }

        let extra = input[MAIN_HEAD_SIZE as usize..head_size as usize].to_vec();

        Ok(Self {
            flags,
            head_size,
            extra,
        })
    }
}

impl FileHeader {
    fn parse(input: &[u8]) -> Result<(Self, Vec<u8>, Vec<u8>, usize)> {
        if input.len() < FILE_HEAD_BASE_SIZE {
            return Err(Error::TooShort);
        }

        let pack_size = read_u32(input, 0)?;
        let unp_size = read_u32(input, 4)?;
        let file_crc = read_u16(input, 8)?;
        let head_size = read_u16(input, 10)?;
        let file_time = read_u32(input, 12)?;
        let file_attr = input[16];
        let flags = input[17];
        let unp_ver = input[18];
        let name_size = input[19] as usize;
        let method = input[20];
        let minimum_size = FILE_HEAD_BASE_SIZE + name_size;

        if (head_size as usize) < minimum_size {
            return Err(Error::InvalidHeader(
                "RAR 1.3 file header is shorter than its name",
            ));
        }
        if input.len() < head_size as usize {
            return Err(Error::TooShort);
        }

        let name = input[FILE_HEAD_BASE_SIZE..FILE_HEAD_BASE_SIZE + name_size].to_vec();
        let extra = input[minimum_size..head_size as usize].to_vec();
        Ok((
            Self {
                flags,
                pack_size,
                unp_size,
                file_crc,
                file_time,
                file_attr,
                unp_ver,
                method,
                head_size,
            },
            name,
            extra,
            head_size as usize,
        ))
    }
}

impl Archive {
    pub fn parse(input: &[u8]) -> Result<Self> {
        let data: Arc<[u8]> = Arc::from(input.to_vec().into_boxed_slice());
        Self::parse_shared(data)
    }

    pub fn parse_owned(input: Vec<u8>) -> Result<Self> {
        Self::parse_shared(Arc::from(input.into_boxed_slice()))
    }

    pub fn parse_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = Arc::new(path.as_ref().to_path_buf());
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        let scan_len = len.min(SFX_SCAN_LIMIT as u64) as usize;
        let mut scan = vec![0; scan_len];
        file.read_exact(&mut scan)?;
        let sig = find_archive_start(&scan, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }
        Self::parse_seekable(file, len, sig.offset, ArchiveSource::File(path))
    }

    pub fn parse_path_with_signature(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
    ) -> Result<Self> {
        if signature.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }
        let path = Arc::new(path.as_ref().to_path_buf());
        let file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        Self::parse_seekable(file, len, signature.offset, ArchiveSource::File(path))
    }

    fn parse_shared(input: Arc<[u8]>) -> Result<Self> {
        let sig = find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }

        let archive = &input[sig.offset..];
        let main = MainHeader::parse(archive)?;
        let mut pos = main.head_size as usize;
        let mut entries = Vec::new();

        while pos < archive.len() {
            if archive.len() - pos < FILE_HEAD_BASE_SIZE {
                break;
            }

            let (header, name, extra, consumed) = FileHeader::parse(&archive[pos..])?;
            let data_start = pos + consumed;
            let data_end =
                data_start
                    .checked_add(header.pack_size as usize)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.3 file data size overflows usize",
                    ))?;
            if data_end > archive.len() {
                return Err(Error::TooShort);
            }

            entries.push(Entry {
                header,
                name,
                extra,
                packed_range: sig.offset + data_start..sig.offset + data_end,
            });
            pos = data_end;
        }

        Ok(Self {
            sfx_offset: sig.offset,
            main,
            entries,
            source: ArchiveSource::Memory(input),
        })
    }

    fn parse_seekable(
        mut file: File,
        file_len: u64,
        sfx_offset: usize,
        source: ArchiveSource,
    ) -> Result<Self> {
        let main_prefix = read_exact_at(&mut file, sfx_offset, MAIN_HEAD_SIZE as usize)?;
        let head_size = read_u16(&main_prefix, 4)? as usize;
        let main_bytes = read_exact_at(&mut file, sfx_offset, head_size)?;
        let main = MainHeader::parse(&main_bytes)?;
        let mut pos = main.head_size as usize;
        let mut entries = Vec::new();

        while (sfx_offset + pos) as u64 + FILE_HEAD_BASE_SIZE as u64 <= file_len {
            let header_prefix = read_exact_at(&mut file, sfx_offset + pos, FILE_HEAD_BASE_SIZE)?;
            let head_size = read_u16(&header_prefix, 10)? as usize;
            let header_bytes = read_exact_at(&mut file, sfx_offset + pos, head_size)?;
            let (header, name, extra, consumed) = FileHeader::parse(&header_bytes)?;
            let data_start = pos + consumed;
            let data_end =
                data_start
                    .checked_add(header.pack_size as usize)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.3 file data size overflows usize",
                    ))?;
            if (sfx_offset + data_end) as u64 > file_len {
                return Err(Error::TooShort);
            }
            entries.push(Entry {
                header,
                name,
                extra,
                packed_range: sfx_offset + data_start..sfx_offset + data_end,
            });
            pos = data_end;
        }

        Ok(Self {
            sfx_offset,
            main,
            entries,
            source,
        })
    }

    fn copy_range_to(&self, range: Range<usize>, out: &mut impl Write) -> Result<()> {
        self.source.copy_range_to(range, out)
    }

    fn range_reader(&self, range: Range<usize>) -> Result<Box<dyn Read + Send + '_>> {
        self.source.range_reader(range)
    }

    fn copy_decrypted_range_to(
        &self,
        range: Range<usize>,
        mut cipher: Rar13Cipher,
        out: &mut impl Write,
    ) -> Result<()> {
        let mut buffer = [0u8; COPY_BUFFER_SIZE];
        match &self.source {
            ArchiveSource::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                for chunk in data.chunks(COPY_BUFFER_SIZE) {
                    buffer[..chunk.len()].copy_from_slice(chunk);
                    for byte in &mut buffer[..chunk.len()] {
                        *byte = cipher.decrypt_byte(*byte);
                    }
                    out.write_all(&buffer[..chunk.len()])?;
                }
            }
            ArchiveSource::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                let mut remaining = range.len();
                while remaining > 0 {
                    let to_read = remaining.min(buffer.len());
                    file.read_exact(&mut buffer[..to_read])?;
                    for byte in &mut buffer[..to_read] {
                        *byte = cipher.decrypt_byte(*byte);
                    }
                    out.write_all(&buffer[..to_read])?;
                    remaining -= to_read;
                }
            }
            // Streaming sources are constructed for the RAR 5 family only.
            ArchiveSource::Stream { .. } => {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 archives do not support streaming sources",
                ));
            }
        }
        Ok(())
    }

    /// Streams extracted entries to caller-provided writers.
    pub fn extract_to<F>(&self, password: Option<&[u8]>, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let mut unpack15 = Unpack15::new();
        let mut extracted_count = 0usize;
        for entry in &self.entries {
            if entry.is_split_before() || entry.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split entry requires multivolume extraction",
                ));
            }
            let meta = entry.metadata();
            if meta.is_directory {
                let _ = open(&meta)?;
                extracted_count += 1;
                continue;
            }
            let mut writer = open(&meta)?;
            if entry.is_stored() && !entry.is_encrypted() {
                entry
                    .write_stored_to(self, password, &mut writer)
                    .map_err(|error| entry.entry_error("extracting", error))?;
            } else {
                entry
                    .write_compressed_to(
                        self,
                        password,
                        &mut unpack15,
                        self.main.is_solid() && extracted_count != 0,
                        &mut writer,
                    )
                    .map_err(|error| entry.entry_error("extracting", error))?;
            }
            extracted_count += 1;
        }
        Ok(())
    }

    pub fn archive_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.main.has_archive_comment() {
            return Ok(None);
        }

        let length = read_u16(&self.main.extra, 0)? as usize;
        if self.main.has_packed_comment() {
            if length < 2 {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 packed archive comment is shorter than size field",
                ));
            }
            let unpacked_len = read_u16(&self.main.extra, 2)? as usize;
            let packed_len = length - 2;
            let packed_start = 4usize;
            let packed_end = packed_start
                .checked_add(packed_len)
                .ok_or(Error::InvalidHeader(
                    "RAR 1.3 archive comment size overflows",
                ))?;
            if packed_end > self.main.extra.len() {
                return Err(Error::TooShort);
            }

            let mut packed = self.main.extra[packed_start..packed_end].to_vec();
            Rar13Cipher::new_comment().decrypt_in_place(&mut packed);
            return Ok(Some(unpack15_decode(&packed, unpacked_len)?));
        }

        let comment_start = 2usize;
        let comment_end = comment_start
            .checked_add(length)
            .ok_or(Error::InvalidHeader(
                "RAR 1.3 archive comment size overflows",
            ))?;
        if comment_end > self.main.extra.len() {
            return Err(Error::TooShort);
        }
        Ok(Some(self.main.extra[comment_start..comment_end].to_vec()))
    }

    pub fn authenticity_verification(&self) -> Result<Option<AuthenticityVerification>> {
        if !self.main.has_authenticity_verification() {
            return Ok(None);
        }
        let size = read_u16(&self.main.extra, 0)?;
        if size < RAR13_AV_PREFIX.len() as u16 {
            return Err(Error::InvalidHeader("RAR 1.3 AV payload is too short"));
        }
        let payload_end = 2usize
            .checked_add(size as usize)
            .ok_or(Error::InvalidHeader("RAR 1.3 AV payload size overflows"))?;
        if payload_end > self.main.extra.len() {
            return Err(Error::TooShort);
        }
        let prefix_bytes = self
            .main
            .extra
            .get(2..2 + RAR13_AV_PREFIX.len())
            .ok_or(Error::TooShort)?;
        let prefix: [u8; 6] = prefix_bytes
            .try_into()
            .expect("RAR 1.3 AV prefix slice has fixed length");
        if &prefix != RAR13_AV_PREFIX {
            return Err(Error::InvalidHeader("RAR 1.3 AV prefix mismatch"));
        }
        Ok(Some(AuthenticityVerification {
            size,
            prefix,
            cipher_body: self.main.extra[2 + RAR13_AV_PREFIX.len()..payload_end].to_vec(),
        }))
    }

    pub fn authenticity_verification_status(&self) -> Result<AuthenticityVerificationStatus> {
        Ok(if self.authenticity_verification()?.is_some() {
            AuthenticityVerificationStatus::StructurallyPresent
        } else {
            AuthenticityVerificationStatus::Absent
        })
    }
}

impl Entry {
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the entry name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    pub fn is_encrypted(&self) -> bool {
        self.header.flags & LHD_PASSWORD != 0
    }

    pub fn is_split_before(&self) -> bool {
        self.header.flags & LHD_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.header.flags & LHD_SPLIT_AFTER != 0
    }

    pub fn is_directory(&self) -> bool {
        self.header.file_attr & 0x10 != 0
    }

    pub fn has_file_comment(&self) -> bool {
        self.header.flags & LHD_COMMENT != 0
    }

    pub fn file_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.has_file_comment() {
            return Ok(None);
        }
        let length = read_u16(&self.extra, 0)? as usize;
        let comment_start = 2usize;
        let comment_end = comment_start
            .checked_add(length)
            .ok_or(Error::InvalidHeader("RAR 1.3 file comment size overflows"))?;
        if comment_end > self.extra.len() {
            return Err(Error::TooShort);
        }
        Ok(Some(self.extra[comment_start..comment_end].to_vec()))
    }

    pub fn is_stored(&self) -> bool {
        self.header.method == METHOD_STORE
    }

    pub fn packed_data<'a>(&self, archive: &'a Archive) -> Result<&'a [u8]> {
        match &archive.source {
            ArchiveSource::Memory(data) => {
                data.get(self.packed_range.clone()).ok_or(Error::TooShort)
            }
            ArchiveSource::File(_) => Err(Error::InvalidHeader(
                "RAR 1.3 file-backed packed data requires owned read",
            )),
            // Streaming sources are constructed for the RAR 5 family only.
            ArchiveSource::Stream { .. } => Err(Error::InvalidHeader(
                "RAR 1.3 archives do not support streaming sources",
            )),
        }
    }

    pub fn write_packed_data(&self, archive: &Archive, out: &mut impl Write) -> Result<()> {
        archive.copy_range_to(self.packed_range.clone(), out)
    }

    pub fn verify_checksum(&self, data: &[u8]) -> Result<()> {
        let actual = file_checksum(data);
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.header.file_time,
            file_attr: self.header.file_attr,
            is_directory: self.is_directory(),
        }
    }

    fn write_stored_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if !self.is_stored() {
            return Err(Error::InvalidHeader("RAR 1.3 entry is not stored"));
        }
        // nzbfast: a STORED member's packed and unpacked sizes are the
        // same number by definition, and this is the only version that
        // did not say so - RAR 1.5+ (`rar15_40`) and RAR 5
        // (`rar50/extract`) both refuse the mismatch. Without it the
        // emitted length came from `pack_size` alone and the only thing
        // standing between a caller and a member of the wrong size was
        // the 16-bit rotate-add checksum, which is forgeable by
        // construction.
        //
        // Encrypted members are exempt for the same reason they are
        // elsewhere: the packed range is padded to the cipher's block
        // size, so the two legitimately differ and the truncation
        // downstream is what reconciles them. A SPLIT piece is exempt
        // too - its `pack_size` is this volume's fragment while
        // `unp_size` is the whole file - though no caller reaches here
        // with one today: the single-archive path refuses a split entry
        // outright and the multivolume path goes through `write_to`,
        // which checks the assembled total instead.
        if !self.is_encrypted()
            && !self.is_split_before()
            && !self.is_split_after()
            && self.header.pack_size != self.header.unp_size
        {
            return Err(Error::InvalidHeader(
                "RAR 1.3 stored file has mismatched packed and unpacked sizes",
            ));
        }
        if self.is_encrypted() {
            let password = password.ok_or(Error::NeedPassword)?;
            let mut checksum = Rar13Checksum::new();
            let mut checksum_writer = Rar13ChecksumWriter {
                inner: out,
                checksum: &mut checksum,
            };
            archive.copy_decrypted_range_to(
                self.packed_range.clone(),
                Rar13Cipher::new(password),
                &mut checksum_writer,
            )?;
            let actual = checksum.finish();
            return if actual == self.header.file_crc {
                Ok(())
            } else {
                Err(Error::CrcMismatch {
                    expected: self.header.file_crc,
                    actual,
                })
            };
        }
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: out,
            checksum: &mut checksum,
        };
        self.write_packed_data(archive, &mut checksum_writer)?;
        let actual = checksum.finish();
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    fn write_compressed_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        unpack15: &mut Unpack15,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() || self.is_directory() {
            return self.write_stored_to(archive, password, out);
        }
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: out,
            checksum: &mut checksum,
        };
        if self.is_encrypted() {
            let password = password.ok_or(Error::NeedPassword)?;
            let packed = archive.range_reader(self.packed_range.clone())?;
            let mut packed = Rar13DecryptReader::new(packed, Rar13Cipher::new(password));
            unpack15.decode_member_from_reader(
                &mut packed,
                self.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        } else {
            let mut packed = archive.range_reader(self.packed_range.clone())?;
            unpack15.decode_member_from_reader(
                &mut packed,
                self.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        }
        let actual = checksum.finish();
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    pub fn write_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        self.write_compressed_to(archive, password, &mut Unpack15::new(), false, out)
    }

    fn entry_error(&self, operation: &'static str, error: Error) -> Error {
        if matches!(
            error,
            Error::NeedPassword | Error::WrongPasswordOrCorruptData
        ) {
            return error;
        }
        if self.is_encrypted()
            && matches!(
                error,
                Error::InvalidHeader(_)
                    | Error::Codec(_)
                    | Error::CrcMismatch { .. }
                    | Error::Crc32Mismatch { .. }
                    | Error::HashMismatch { .. }
            )
        {
            return Error::WrongPasswordOrCorruptData;
        }
        error.at_entry(self.name.clone(), operation)
    }
}

/// Streams a multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(
    volumes: &[Archive],
    password: Option<&[u8]>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volumes_to_impl(volumes, password, &mut open, None)
}

/// [`extract_volumes_to`] reporting each volume the engine is finished
/// with - the RAR 1.3 twin of
/// [`crate::rar50::extract_volumes_to_with_progress`], same contract.
pub fn extract_volumes_to_with_progress<F, C>(
    volumes: &[Archive],
    password: Option<&[u8]>,
    mut open: F,
    mut consumed: C,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    C: FnMut(usize),
{
    extract_volumes_to_impl(volumes, password, &mut open, Some(&mut consumed))
}

fn extract_volumes_to_impl<F>(
    volumes: &[Archive],
    password: Option<&[u8]>,
    open: &mut F,
    mut consumed: Option<&mut dyn FnMut(usize)>,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let mut pending: Option<PendingSplitRefs> = None;
    let mut unpack15 = Unpack15::new();
    let mut extracted_count = 0usize;
    // Volumes already reported consumed - see the rar50 twin.
    let mut reported = 0usize;

    for (volume_index, archive) in volumes.iter().enumerate() {
        for (entry_index, entry) in archive.entries.iter().enumerate() {
            if !entry.is_split_before() && !entry.is_split_after() {
                if pending.is_some() {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry is interrupted by a regular entry",
                    ));
                }
                let meta = entry.metadata();
                if meta.is_directory {
                    let _ = open(&meta)?;
                    extracted_count += 1;
                    continue;
                }
                let mut writer = open(&meta)?;
                entry
                    .write_compressed_to(
                        archive,
                        password,
                        &mut unpack15,
                        archive.main.is_solid() && extracted_count != 0,
                        &mut writer,
                    )
                    .map_err(|error| entry.entry_error("extracting", error))?;
                extracted_count += 1;
                continue;
            }

            match (
                &mut pending,
                entry.is_split_before(),
                entry.is_split_after(),
            ) {
                (None, false, true) => {
                    pending = Some(PendingSplitRefs::new(entry, volume_index, entry_index));
                }
                (Some(current), true, true) => {
                    current.append(entry, volume_index, entry_index)?;
                }
                (Some(current), true, false) => {
                    current.append(entry, volume_index, entry_index)?;
                    let completed = pending.take().expect("pending split");
                    let solid = archive.main.is_solid() && extracted_count != 0;
                    completed
                        .write_to(volumes, entry, password, &mut unpack15, solid, &mut *open)
                        .map_err(|error| entry.entry_error("extracting", error))?;
                    extracted_count += 1;
                }
                _ => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry flags are inconsistent",
                    ));
                }
            }
        }
        if pending.is_none() {
            if let Some(consumed) = consumed.as_mut() {
                while reported <= volume_index {
                    consumed(reported);
                    reported += 1;
                }
            }
        }
    }

    if pending.is_some() {
        return Err(Error::InvalidHeader("RAR 1.3 split entry is incomplete"));
    }

    Ok(())
}

struct Rar13ChecksumWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    checksum: &'a mut Rar13Checksum,
}

impl<W: Write + ?Sized> Write for Rar13ChecksumWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.checksum.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct Rar13Checksum {
    value: u16,
}

impl Rar13Checksum {
    fn new() -> Self {
        Self { value: 0 }
    }

    fn update(&mut self, input: &[u8]) {
        for &byte in input {
            self.value = self.value.wrapping_add(byte as u16).rotate_left(1);
        }
    }

    fn finish(self) -> u16 {
        self.value
    }
}

struct PendingSplitRefs {
    name: Vec<u8>,
    fragments: Vec<(usize, usize)>,
    file_time: u32,
    file_attr: u8,
    method: u8,
    unp_ver: u8,
    was_encrypted: bool,
}

impl PendingSplitRefs {
    fn new(entry: &Entry, volume_index: usize, entry_index: usize) -> Self {
        Self {
            name: entry.name.clone(),
            fragments: vec![(volume_index, entry_index)],
            file_time: entry.header.file_time,
            file_attr: entry.header.file_attr,
            method: entry.header.method,
            unp_ver: entry.header.unp_ver,
            was_encrypted: entry.is_encrypted(),
        }
    }

    fn append(&mut self, entry: &Entry, volume_index: usize, entry_index: usize) -> Result<()> {
        if entry.name != self.name {
            return Err(Error::InvalidHeader("RAR 1.3 split entry name changed"));
        }
        if entry.header.method != self.method {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry compression method changed",
            ));
        }
        if entry.header.unp_ver != self.unp_ver {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry unpack version changed",
            ));
        }
        if entry.is_encrypted() != self.was_encrypted {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry encryption flag changed",
            ));
        }
        // Strictly increasing volumes only - two fragments of one member
        // inside one volume is a crafted shape (see the rar15/rar50
        // twins), and downstream consumption accounting relies on a
        // fragment never revisiting an earlier volume.
        if let Some(&(last_volume, _)) = self.fragments.last() {
            if volume_index <= last_volume {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split fragment does not advance to a later volume",
                ));
            }
        }
        self.fragments.push((volume_index, entry_index));
        Ok(())
    }

    fn write_to<F>(
        self,
        volumes: &[Archive],
        final_entry: &Entry,
        password: Option<&[u8]>,
        unpack15: &mut Unpack15,
        solid: bool,
        open: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let mut reader = self.fragment_reader(volumes, password)?;
        let meta = ExtractedEntryMeta {
            name: self.name,
            file_time: self.file_time,
            file_attr: self.file_attr,
            is_directory: false,
        };
        let mut writer = open(&meta)?;
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: &mut writer,
            checksum: &mut checksum,
        };
        if self.method == METHOD_STORE {
            // nzbfast: and the assembled length has to be the one the
            // header declared. The fragments are copied verbatim, so
            // without this the emitted size came from the packed ranges
            // alone and the only gate on it was the 16-bit rotate-add
            // checksum - forgeable by construction. RAR 1.5+ and RAR 5
            // both refuse a stored pack/unp mismatch; this is the same
            // rule for the shape that assembles from several volumes.
            let copied = std::io::copy(&mut reader, &mut checksum_writer)?;
            if copied != u64::from(final_entry.header.unp_size) {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 stored file assembled to a different size than its header declared",
                ));
            }
        } else {
            unpack15.decode_member_from_reader(
                &mut reader,
                final_entry.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        }
        let actual = checksum.finish();
        if actual == final_entry.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: final_entry.header.file_crc,
                actual,
            })
        }
    }

    /// The chain over this member's fragments, one volume open at a time.
    ///
    /// Every fragment is RESOLVED here - missing volume, missing entry and a
    /// missing password for an encrypted fragment all still fail before a
    /// byte is read - but the file itself is opened only when the chain
    /// reaches it. Building 300 live `File`s up front is how a large split
    /// member hit `EMFILE` before extraction started (see
    /// [`LazyChainedReader`]). Per-fragment cipher initialisation is
    /// preserved: RAR 1.3 keys each fragment on its own.
    fn fragment_reader<'a>(
        &self,
        volumes: &'a [Archive],
        password: Option<&'a [u8]>,
    ) -> Result<LazyChainedReader<'a>> {
        let mut openers: Vec<FragmentOpener<'a>> = Vec::with_capacity(self.fragments.len());
        for &(volume_index, entry_index) in &self.fragments {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 1.3 split volume is missing"))?;
            let entry = archive
                .entries
                .get(entry_index)
                .ok_or(Error::InvalidHeader("RAR 1.3 split entry is missing"))?;
            let range = entry.packed_range.clone();
            let fragment_password = if entry.is_encrypted() {
                Some(password.ok_or(Error::NeedPassword)?)
            } else {
                None
            };
            openers.push(Box::new(move || {
                let reader = archive
                    .range_reader(range)
                    .map_err(std::io::Error::other)?;
                Ok(match fragment_password {
                    Some(password) => {
                        Box::new(Rar13DecryptReader::new(reader, Rar13Cipher::new(password)))
                            as Box<dyn Read + Send + 'a>
                    }
                    None => reader,
                })
            }));
        }
        Ok(LazyChainedReader::new(openers))
    }
}

pub fn write_stored_archive(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_stored_archive_with_comment(entries, options, None)
}

pub fn write_stored_archive_with_comment(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_stored_writer_features(options.target, options.features)?;

    let mut out = Vec::new();
    write_main_header(&mut out, options.features, archive_comment)?;

    for entry in entries {
        validate_stored_entry(entry)?;
        write_stored_entry(&mut out, entry, options.features)?;
    }

    Ok(out)
}

pub fn write_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment(entries, options, None)
}

pub fn write_compressed_archive_with_comment(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment_and_progress(entries, options, archive_comment, None)
}

pub fn write_compressed_archive_with_comment_and_progress(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<u8>> {
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_compressed_writer_features(options.target, options.features)?;
    validate_compression_level(options)?;

    let mut out = Vec::new();
    write_main_header(&mut out, options.features, archive_comment)?;

    let encode_options = rar15_encode_options_for_level(options.compression_level)?;
    let mut solid_encoder = options
        .features
        .solid
        .then(|| Unpack15Encoder::with_options(encode_options));

    let total_bytes: u64 = entries.iter().map(|entry| entry.data.len() as u64).sum();
    let attempts = if options.features.solid || options.compression_level == Some(0) {
        1
    } else {
        rar15_encode_fallback_options(encode_options).len() as u64
    };
    let total_work = total_bytes.saturating_mul(attempts);
    report_compression_operation(progress, true, total_work, entries.len());
    let work = WorkTracker::new(
        progress.map(ProgressReporter),
        WriteOperation::Compression,
        total_work,
    );
    for (index, entry) in entries.iter().enumerate() {
        report_compression_entry(progress, true, index, entries.len(), entry);
        validate_file_entry(entry.name, entry.data)?;
        let solid = solid_encoder.is_some();
        let mut last = 0usize;
        let mut advance = |position: usize| {
            if position < last {
                last = 0;
            }
            let delta = position.saturating_sub(last);
            last = position;
            work.advance(delta as u64)
        };
        let mut packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder.encode_member_with_progress(entry.data, &mut advance)?
        } else if options.compression_level == Some(0) {
            entry.data.to_vec()
        } else {
            encode_verified_rar15_payload_with_progress(entry.data, encode_options, &mut advance)?
                .unwrap_or_else(|| entry.data.to_vec())
        };
        let method = if options.compression_level == Some(0)
            || (!solid && packed.len() >= entry.data.len())
        {
            packed = entry.data.to_vec();
            METHOD_STORE
        } else {
            METHOD_BEST
        };
        if let Some(password) = entry.password {
            Rar13Cipher::new(password).encrypt_in_place(&mut packed);
        }
        let mut flags = 0;
        if options.features.solid {
            flags |= LHD_SOLID;
        }
        if entry.password.is_some() {
            flags |= LHD_PASSWORD;
        }
        if entry.file_comment.is_some() {
            flags |= LHD_COMMENT;
        }
        let file_extra = encode_file_comment(entry.file_comment)?;
        write_file_entry(
            &mut out,
            FileEntryRecord {
                name: entry.name,
                unpacked_size: entry.data.len() as u32,
                file_crc: file_checksum(entry.data),
                packed: &packed,
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                flags,
                unp_ver: DEFAULT_UNP_VER,
                method,
                extra: &file_extra,
            },
        )?;
        report_compression_entry(progress, false, index, entries.len(), entry);
    }

    if !work.finish() {
        return Err(Error::Cancelled);
    }

    report_compression_operation(progress, false, total_work, entries.len());

    Ok(out)
}

pub fn write_stored_volumes(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_stored_writer_features(options.target, options.features)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;

    let body = entry.data.to_vec();
    write_split_volumes(SplitVolumeRecord {
        name: entry.name,
        unpacked: entry.data,
        packed: &body,
        file_time: entry.file_time,
        file_attr: entry.file_attr,
        method: METHOD_STORE,
        base_flags: 0,
        features: options.features,
        max_packed_per_volume,
    })
}

pub fn write_compressed_volumes(
    entry: FileEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    write_compressed_volumes_with_progress(entry, options, max_packed_per_volume, None)
}

pub fn write_compressed_volumes_with_progress(
    entry: FileEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<Vec<u8>>> {
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_compressed_writer_features(options.target, options.features)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;

    validate_compression_level(options)?;
    let encode_options = rar15_encode_options_for_level(options.compression_level)?;
    let total_work = (entry.data.len() as u64)
        .saturating_mul(rar15_encode_fallback_options(encode_options).len() as u64);
    report_compression_operation(progress, true, total_work, 1);
    let work = WorkTracker::new(
        progress.map(ProgressReporter),
        WriteOperation::Compression,
        total_work,
    );
    report_compression_entry(progress, true, 0, 1, &entry);
    let mut last = 0usize;
    let mut advance = |position: usize| {
        if position < last {
            last = 0;
        }
        let delta = position.saturating_sub(last);
        last = position;
        work.advance(delta as u64)
    };
    let mut packed =
        encode_verified_rar15_payload_with_progress(entry.data, encode_options, &mut advance)?
            .unwrap_or_else(|| entry.data.to_vec());
    let method = if packed.len() >= entry.data.len() {
        packed = entry.data.to_vec();
        METHOD_STORE
    } else {
        METHOD_BEST
    };
    let result = write_split_volumes(SplitVolumeRecord {
        name: entry.name,
        unpacked: entry.data,
        packed: &packed,
        file_time: entry.file_time,
        file_attr: entry.file_attr,
        method,
        base_flags: 0,
        features: options.features,
        max_packed_per_volume,
    });
    report_compression_entry(progress, false, 0, 1, &entry);
    if result.is_ok() && !work.finish() {
        return Err(Error::Cancelled);
    }
    report_compression_operation(progress, false, total_work, 1);
    result
}

fn report_compression_operation(
    progress: Option<&dyn WriteProgress>,
    started: bool,
    total_bytes: u64,
    total_entries: usize,
) {
    let Some(progress) = progress else { return };
    if started {
        progress.report(WriteProgressEvent::OperationStarted {
            operation: WriteOperation::Compression,
            total_bytes: Some(total_bytes),
            total_entries: Some(total_entries),
            pass: 1,
        });
    } else {
        progress.report(WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Compression,
            total_bytes: Some(total_bytes),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }
}

fn report_compression_entry(
    progress: Option<&dyn WriteProgress>,
    started: bool,
    index: usize,
    total_entries: usize,
    entry: &FileEntry<'_>,
) {
    let Some(progress) = progress else { return };
    if started {
        progress.report(WriteProgressEvent::EntryStarted {
            operation: WriteOperation::Compression,
            index,
            total_entries,
            name: entry.name,
            input_bytes: entry.data.len() as u64,
        });
    } else {
        progress.report(WriteProgressEvent::EntryFinished {
            operation: WriteOperation::Compression,
            index,
            total_entries,
            name: entry.name,
            input_bytes: entry.data.len() as u64,
        });
    }
}

fn validate_stored_writer_features(version: ArchiveVersion, features: FeatureSet) -> Result<()> {
    reject_writer_feature(version, features.sfx, "sfx")?;
    reject_writer_feature(
        version,
        features.authenticity_verification,
        "authenticity_verification",
    )?;
    Ok(())
}

fn validate_volume_writer_inputs(
    name: &[u8],
    data: &[u8],
    password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    options: WriterOptions,
) -> Result<()> {
    validate_file_entry(name, data)?;
    if password.is_some() {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_password",
        });
    }
    if file_comment.is_some() || options.features.file_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_file_comment",
        });
    }
    if options.features.archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_archive_comment",
        });
    }
    Ok(())
}

fn validate_compressed_writer_features(
    version: ArchiveVersion,
    features: FeatureSet,
) -> Result<()> {
    reject_writer_feature(version, features.sfx, "sfx")?;
    reject_writer_feature(
        version,
        features.authenticity_verification,
        "authenticity_verification",
    )?;
    Ok(())
}

fn validate_compression_level(options: WriterOptions) -> Result<()> {
    if matches!(options.compression_level, Some(level) if level > 5) {
        return Err(Error::InvalidHeader(
            "RAR compression level must be in the range 0..5",
        ));
    }
    Ok(())
}

fn rar15_encode_options_for_level(level: Option<u8>) -> Result<Rar15EncodeOptions> {
    let level = level.unwrap_or(5);
    // DOS RAR 1.402 rejects some streams produced with the old-distance
    // short-LZ codes, even though the rars decoder can read them. Keep the
    // writer on the older compatible subset until that encoding is pinned
    // against a real oracle.
    let compatible = Rar15EncodeOptions::new().with_old_distance_tokens(false);
    match level {
        0 => Ok(compatible
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(0)),
        1 => Ok(compatible
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(4 * 1024)),
        2 => Ok(compatible
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(8 * 1024)),
        3 => Ok(compatible
            .with_lazy_matching(false)
            .with_max_long_match_distance(16 * 1024)),
        4 => Ok(compatible
            .with_lazy_matching(false)
            .with_max_long_match_distance(24 * 1024)),
        5 => Ok(compatible.with_lazy_matching(false)),
        _ => Err(Error::InvalidHeader(
            "RAR compression level must be in the range 0..5",
        )),
    }
}

fn encode_verified_rar15_payload_with_progress(
    data: &[u8],
    options: Rar15EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Option<Vec<u8>>> {
    let mut candidates = rar15_encode_fallback_options(options).into_iter();
    let Some(first) = candidates.next() else {
        return Ok(None);
    };
    let packed = match unpack15_encode_with_options_and_progress(data, first, progress) {
        Err(crate::codec::Error::Cancelled) => return Err(Error::Cancelled),
        result => result?,
    };
    if unpack15_payload_matches(&packed, data)? {
        return Ok(Some(packed));
    }
    for candidate_options in candidates {
        let packed =
            match unpack15_encode_with_options_and_progress(data, candidate_options, progress) {
                Err(crate::codec::Error::Cancelled) => return Err(Error::Cancelled),
                result => result?,
            };
        if unpack15_payload_matches(&packed, data)? {
            return Ok(Some(packed));
        }
    }
    Ok(None)
}

fn rar15_encode_fallback_options(options: Rar15EncodeOptions) -> Vec<Rar15EncodeOptions> {
    let mut candidates = vec![options];
    let distance_limited = options.with_max_long_match_distance(24 * 1024);
    if distance_limited != options {
        candidates.push(distance_limited);
    }
    let conservative = options
        .with_lazy_matching(false)
        .with_stmode_literal_runs(false)
        .with_max_long_match_distance(8 * 1024);
    if !candidates.contains(&conservative) {
        candidates.push(conservative);
    }
    candidates
}

fn unpack15_payload_matches(packed: &[u8], data: &[u8]) -> Result<bool> {
    match unpack15_decode(packed, data.len()) {
        Ok(decoded) => Ok(decoded == data),
        Err(_) => Ok(false),
    }
}

fn reject_writer_feature(
    version: ArchiveVersion,
    enabled: bool,
    feature: &'static str,
) -> Result<()> {
    if enabled {
        Err(Error::UnsupportedFeature { version, feature })
    } else {
        Ok(())
    }
}

fn write_main_header(
    out: &mut Vec<u8>,
    features: FeatureSet,
    archive_comment: Option<&[u8]>,
) -> Result<()> {
    write_main_header_with_flags(out, features, archive_comment, 0)
}

fn write_main_header_with_flags(
    out: &mut Vec<u8>,
    features: FeatureSet,
    archive_comment: Option<&[u8]>,
    extra_flags: u8,
) -> Result<()> {
    let comment_extra = encode_archive_comment(archive_comment)?;
    let mut flags = MHD_ALWAYS_SET | extra_flags;
    if archive_comment.is_some() {
        flags |= MHD_COMMENT;
        flags |= MHD_PACK_COMMENT;
    }
    if features.solid {
        flags |= MHD_SOLID;
    }
    out.extend_from_slice(RAR13_SIGNATURE);
    let head_size = MAIN_HEAD_SIZE as usize + comment_extra.len();
    if head_size > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 main header comment extension is too large",
        ));
    }
    out.extend_from_slice(&(head_size as u16).to_le_bytes());
    out.push(flags);
    out.extend_from_slice(&comment_extra);
    Ok(())
}

fn write_stored_entry(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    features: FeatureSet,
) -> Result<()> {
    let mut flags = 0u8;
    if entry.password.is_some() {
        flags |= LHD_PASSWORD;
    }
    if entry.file_comment.is_some() {
        flags |= LHD_COMMENT;
    }
    if features.solid {
        flags |= LHD_SOLID;
    }

    let mut body = entry.data.to_vec();
    if let Some(password) = entry.password {
        Rar13Cipher::new(password).encrypt_in_place(&mut body);
    }

    let file_extra = encode_file_comment(entry.file_comment)?;
    write_file_entry(
        out,
        FileEntryRecord {
            name: entry.name,
            unpacked_size: entry.data.len() as u32,
            file_crc: file_checksum(entry.data),
            packed: &body,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            flags,
            unp_ver: DEFAULT_UNP_VER,
            method: METHOD_STORE,
            extra: &file_extra,
        },
    )?;
    Ok(())
}

fn validate_stored_entry(entry: &StoredEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name, entry.data)
}

struct FileEntryRecord<'a> {
    name: &'a [u8],
    unpacked_size: u32,
    file_crc: u16,
    packed: &'a [u8],
    file_time: u32,
    file_attr: u8,
    flags: u8,
    unp_ver: u8,
    method: u8,
    extra: &'a [u8],
}

fn write_file_entry(out: &mut Vec<u8>, entry: FileEntryRecord<'_>) -> Result<()> {
    let head_size = FILE_HEAD_BASE_SIZE + entry.name.len() + entry.extra.len();
    out.extend_from_slice(&(entry.packed.len() as u32).to_le_bytes());
    out.extend_from_slice(&entry.unpacked_size.to_le_bytes());
    out.extend_from_slice(&entry.file_crc.to_le_bytes());
    out.extend_from_slice(&(head_size as u16).to_le_bytes());
    out.extend_from_slice(&entry.file_time.to_le_bytes());
    out.push(entry.file_attr);
    out.push(entry.flags);
    out.push(entry.unp_ver);
    out.push(entry.name.len() as u8);
    out.push(entry.method);
    out.extend_from_slice(entry.name);
    out.extend_from_slice(entry.extra);
    out.extend_from_slice(entry.packed);
    Ok(())
}

struct SplitVolumeRecord<'a> {
    name: &'a [u8],
    unpacked: &'a [u8],
    packed: &'a [u8],
    file_time: u32,
    file_attr: u8,
    method: u8,
    base_flags: u8,
    features: FeatureSet,
    max_packed_per_volume: usize,
}

fn write_split_volumes(entry: SplitVolumeRecord<'_>) -> Result<Vec<Vec<u8>>> {
    if entry.max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.3 volume payload size must be non-zero",
        ));
    }
    if entry.packed.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.3 volume writer needs a non-empty packed payload",
        ));
    }

    let chunks: Vec<&[u8]> = entry.packed.chunks(entry.max_packed_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.3 volume writer needs at least two volumes",
        ));
    }

    let mut volumes = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let split_before = index > 0;
        let split_after = index + 1 < chunks.len();
        let mut flags = entry.base_flags;
        if split_before {
            flags |= LHD_SPLIT_BEFORE;
        }
        if split_after {
            flags |= LHD_SPLIT_AFTER;
        }
        if entry.features.solid {
            flags |= LHD_SOLID;
        }

        let mut out = Vec::new();
        write_main_header_with_flags(&mut out, entry.features, None, MHD_VOLUME)?;
        let checksum_data = if split_after { *chunk } else { entry.unpacked };
        write_file_entry(
            &mut out,
            FileEntryRecord {
                name: entry.name,
                unpacked_size: entry.unpacked.len() as u32,
                file_crc: file_checksum(checksum_data),
                packed: chunk,
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                flags,
                unp_ver: DEFAULT_UNP_VER,
                method: entry.method,
                extra: &[],
            },
        )?;
        volumes.push(out);
    }

    Ok(volumes)
}

fn encode_archive_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let Some(comment) = comment else {
        return Ok(Vec::new());
    };
    if comment.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 archive comment is longer than 65535 bytes",
        ));
    }
    let mut packed = unpack15_encode(comment)?;
    Rar13Cipher::new_comment().encrypt_in_place(&mut packed);
    let packed_field_len = packed.len().checked_add(2).ok_or(Error::InvalidHeader(
        "RAR 1.3 archive comment size overflows",
    ))?;
    if packed_field_len > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 packed archive comment is longer than 65535 bytes",
        ));
    }

    let mut out = Vec::with_capacity(4 + packed.len());
    out.extend_from_slice(&(packed_field_len as u16).to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(&packed);
    Ok(out)
}

fn encode_file_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let Some(comment) = comment else {
        return Ok(Vec::new());
    };
    if comment.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 file comment is longer than 65535 bytes",
        ));
    }
    let mut out = Vec::with_capacity(2 + comment.len());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    Ok(out)
}

fn validate_file_entry(name: &[u8], data: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.3 file name is empty"));
    }
    if name.len() > u8::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 file name is longer than 255 bytes",
        ));
    }
    if data.len() > u32::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 file is larger than 32-bit size fields",
        ));
    }
    Ok(())
}

pub fn file_checksum(input: &[u8]) -> u16 {
    let mut checksum = Rar13Checksum::new();
    checksum.update(input);
    checksum.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::rar13::{find_long_lz, LongLz};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    struct CollectWriter(Rc<RefCell<Vec<u8>>>);

    #[test]
    fn compressed_writer_reports_balanced_progress_events() {
        let entries = [
            FileEntry {
                name: b"one.txt",
                data: b"one one one one",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            FileEntry {
                name: b"two.txt",
                data: b"two two two two",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];
        let operation_starts = AtomicUsize::new(0);
        let operation_finishes = AtomicUsize::new(0);
        let entry_starts = AtomicUsize::new(0);
        let entry_finishes = AtomicUsize::new(0);
        let advances = AtomicUsize::new(0);
        let last_completed = AtomicU64::new(0);
        let expected_total = AtomicU64::new(0);
        let reporter = |event: WriteProgressEvent<'_>| match event {
            WriteProgressEvent::OperationStarted { total_bytes, .. } => {
                operation_starts.fetch_add(1, Ordering::Relaxed);
                expected_total.store(total_bytes.unwrap_or(0), Ordering::Relaxed);
            }
            WriteProgressEvent::OperationFinished { .. } => {
                operation_finishes.fetch_add(1, Ordering::Relaxed);
            }
            WriteProgressEvent::EntryStarted { .. } => {
                entry_starts.fetch_add(1, Ordering::Relaxed);
            }
            WriteProgressEvent::EntryFinished { .. } => {
                entry_finishes.fetch_add(1, Ordering::Relaxed);
            }
            WriteProgressEvent::Advanced {
                completed_bytes,
                total_bytes,
                ..
            } => {
                assert!(completed_bytes >= last_completed.swap(completed_bytes, Ordering::Relaxed));
                assert!(completed_bytes <= total_bytes);
                advances.fetch_add(1, Ordering::Relaxed);
            }
        };

        write_compressed_archive_with_comment_and_progress(
            &entries,
            WriterOptions::default(),
            None,
            Some(&reporter),
        )
        .unwrap();

        assert_eq!(operation_starts.load(Ordering::Relaxed), 1);
        assert_eq!(operation_finishes.load(Ordering::Relaxed), 1);
        assert_eq!(entry_starts.load(Ordering::Relaxed), entries.len());
        assert_eq!(entry_finishes.load(Ordering::Relaxed), entries.len());
        assert!(advances.load(Ordering::Relaxed) >= entries.len());
        assert_eq!(
            last_completed.load(Ordering::Relaxed),
            expected_total.load(Ordering::Relaxed)
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CollectedEntry {
        name: Vec<u8>,
        data: Vec<u8>,
        file_time: u32,
        file_attr: u8,
        is_directory: bool,
    }

    impl Write for CollectWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
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
            Ok(Box::new(CollectWriter(data)))
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

    fn collect_extract_volumes(
        volumes: &[Archive],
        password: Option<&[u8]>,
    ) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        extract_volumes_to(volumes, password, |meta| {
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
                file_attr: meta.file_attr,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn synthetic_log_payload(lines: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for index in 0..lines {
            data.extend_from_slice(
                format!(
                    "2026-05-12T12:{:02}:{:02}.000Z INFO worker-{:02} request_id={:04x}-{:05} path=/api/v1/items/{} status={} elapsed_ms={} bytes={} message=processed archive chunk retry={} user=service-{}\n",
                    index % 60,
                    (index * 7) % 60,
                    index % 16,
                    index % 10000,
                    (index * 17) % 100000,
                    index % 2048,
                    200 + (index % 5),
                    (index * 37) % 5000,
                    (index * 911) % 65536,
                    index % 3,
                    index % 32
                )
                .as_bytes(),
            );
        }
        data
    }

    #[test]
    fn writes_and_reads_stored_archive() {
        let input = [
            StoredEntry {
                name: b"README.md",
                data: b"hello rar 1.3",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            StoredEntry {
                name: b"docs",
                data: b"",
                file_time: 0,
                file_attr: 0x10,
                password: None,
                file_comment: None,
            },
        ];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.main.flags, 0x80);
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.entries[0].name_bytes(), b"README.md");
        assert_eq!(archive.entries[0].name_lossy(), "README.md");
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"hello rar 1.3");
        assert!(archive.entries[1].is_directory());
        assert!(extracted[1].is_directory);
    }

    /// nzbfast: a STORED member's packed and unpacked sizes are the same
    /// number by definition, and RAR 1.3 was the only version that did
    /// not say so - RAR 1.5+ and RAR 5 both refuse the mismatch. Without
    /// it the emitted length came from `pack_size` alone, and the only
    /// thing between a caller and a member of the wrong size was the
    /// 16-bit rotate-add checksum, which is forgeable by construction.
    ///
    /// NEGATIVE CONTROL, run: remove the pack/unp check from
    /// `write_stored_to` and this extracts happily, 4 bytes short of
    /// what its own header declared.
    #[test]
    fn a_stored_entry_whose_declared_sizes_disagree_is_refused() {
        let payload: &[u8] = b"rar13-size-mismatch-fixture";
        let input = [StoredEntry {
            name: b"F.bin",
            data: payload,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let good = write_stored_archive(&input, WriterOptions::default()).unwrap();
        // The round trip is fine to begin with, so the refusal below is
        // about the tamper and not about the fixture.
        let archive = Archive::parse(&good).unwrap();
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, payload);

        // The file header carries pack_size then unp_size, both LE u32
        // and both `payload.len()` for a stored entry - so the pair is a
        // unique eight-byte needle. Raise only the SECOND.
        let n = payload.len() as u32;
        let mut needle = Vec::new();
        needle.extend_from_slice(&n.to_le_bytes());
        needle.extend_from_slice(&n.to_le_bytes());
        let at = good
            .windows(8)
            .position(|w| w == needle.as_slice())
            .expect("the size pair must be findable");
        let mut bad = good.clone();
        bad[at + 4..at + 8].copy_from_slice(&(n + 4).to_le_bytes());

        let archive = Archive::parse(&bad).expect("the header still parses - it is the CONTENT");
        // Wrapped in `AtEntry` by the extract loop, which is what names
        // the member in the message a caller sees.
        let err = collect_extract(&archive, None).unwrap_err();
        assert!(
            matches!(
                &err,
                Error::AtEntry { source, .. }
                    if **source
                        == Error::InvalidHeader(
                            "RAR 1.3 stored file has mismatched packed and unpacked sizes"
                        )
            ),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_malformed_main_header_boundaries() {
        assert_eq!(MainHeader::parse(b"RE~"), Err(Error::TooShort));

        let mut too_small = Vec::from(&b"RE~^"[..]);
        too_small.extend_from_slice(&6u16.to_le_bytes());
        too_small.push(0x80);
        assert_eq!(
            MainHeader::parse(&too_small),
            Err(Error::InvalidHeader(
                "RAR 1.3 main header is shorter than 7 bytes"
            ))
        );

        let mut truncated_extra = Vec::from(&b"RE~^"[..]);
        truncated_extra.extend_from_slice(&8u16.to_le_bytes());
        truncated_extra.push(0x80);
        assert_eq!(MainHeader::parse(&truncated_extra), Err(Error::TooShort));

        assert!(matches!(
            Archive::parse(b"Rar!\x1a\x07\x00"),
            Err(Error::UnsupportedSignature)
        ));
    }

    #[test]
    fn rejects_file_header_shorter_than_its_name() {
        let mut bytes = Vec::from(&b"RE~^"[..]);
        bytes.extend_from_slice(&7u16.to_le_bytes());
        bytes.push(0x80);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(FILE_HEAD_BASE_SIZE as u16).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0x20);
        bytes.push(0);
        bytes.push(DEFAULT_UNP_VER);
        bytes.push(10);
        bytes.push(METHOD_STORE);

        assert!(matches!(
            Archive::parse(&bytes),
            Err(Error::InvalidHeader(
                "RAR 1.3 file header is shorter than its name"
            ))
        ));
    }

    #[test]
    fn rejects_truncated_file_payload_during_parse() {
        let input = [StoredEntry {
            name: b"hello.txt",
            data: b"hello",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let mut bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        bytes.pop();

        assert!(matches!(Archive::parse(&bytes), Err(Error::TooShort)));
    }

    #[test]
    fn returns_none_for_absent_archive_comment() {
        let bytes = write_stored_archive(&[], WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert_eq!(archive.archive_comment().unwrap(), None);
    }

    #[test]
    fn rejects_normal_extract_on_split_entries() {
        let entry = StoredEntry {
            name: b"split.bin",
            data: b"abcdefghijklmnopqrstuvwxyz",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let volumes = write_stored_volumes(entry, WriterOptions::default(), 8).unwrap();
        let first = Archive::parse(&volumes[0]).unwrap();

        assert_eq!(
            collect_extract(&first, None),
            Err(Error::InvalidHeader(
                "RAR 1.3 split entry requires multivolume extraction"
            ))
        );
        assert_eq!(
            collect_extract(&first, None),
            Err(Error::InvalidHeader(
                "RAR 1.3 split entry requires multivolume extraction"
            ))
        );
    }

    #[test]
    fn rejects_malformed_comment_extensions() {
        let packed_too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_COMMENT | MHD_PACK_COMMENT,
                head_size: MAIN_HEAD_SIZE,
                extra: 1u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(
            packed_too_short.archive_comment(),
            Err(Error::InvalidHeader(
                "RAR 1.3 packed archive comment is shorter than size field"
            ))
        );

        let unpacked_too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_COMMENT,
                head_size: MAIN_HEAD_SIZE,
                extra: 4u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(unpacked_too_short.archive_comment(), Err(Error::TooShort));
    }

    #[test]
    fn rejects_malformed_av_extensions() {
        let too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_AV,
                head_size: MAIN_HEAD_SIZE,
                extra: 5u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(
            too_short.authenticity_verification(),
            Err(Error::InvalidHeader("RAR 1.3 AV payload is too short"))
        );

        let bad_prefix = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_AV,
                head_size: MAIN_HEAD_SIZE,
                extra: {
                    let mut extra = 6u16.to_le_bytes().to_vec();
                    extra.extend_from_slice(b"badbad");
                    extra
                },
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(
            bad_prefix.authenticity_verification(),
            Err(Error::InvalidHeader("RAR 1.3 AV prefix mismatch"))
        );
    }

    #[test]
    fn writes_and_reads_encrypted_stored_archive() {
        let input = [StoredEntry {
            name: b"secret.txt",
            data: b"secret bytes",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pass"),
            file_comment: None,
        }];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].is_encrypted());
        match collect_extract(&archive, None) {
            Err(Error::NeedPassword) => {}
            Err(Error::AtEntry { source, .. }) if matches!(*source, Error::NeedPassword) => {}
            other => panic!("expected missing password error, got {other:?}"),
        }

        let extracted = collect_extract(&archive, Some(b"pass")).unwrap();
        assert_eq!(extracted[0].data, b"secret bytes");
    }

    #[test]
    fn writes_and_reads_archive_comment() {
        let input = [StoredEntry {
            name: b"README.md",
            data: b"hello rar 1.3",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_stored_archive_with_comment(
            &input,
            WriterOptions::default(),
            Some(b"This is an archive comment."),
        )
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.has_archive_comment());
        assert!(archive.main.has_packed_comment());
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&b"This is an archive comment."[..])
        );
        assert_eq!(
            collect_extract(&archive, None).unwrap()[0].data,
            b"hello rar 1.3"
        );
    }

    #[test]
    fn writes_and_reads_file_comment() {
        let input = [StoredEntry {
            name: b"README.md",
            data: b"hello rar 1.3",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: Some(b"file comment\r\n"),
        }];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].has_file_comment());
        assert_eq!(
            archive.entries[0].file_comment().unwrap().as_deref(),
            Some(&b"file comment\r\n"[..])
        );
        assert_eq!(
            collect_extract(&archive, None).unwrap()[0].data,
            b"hello rar 1.3"
        );
    }

    #[test]
    fn writes_and_reads_literal_only_compressed_archive() {
        let input = [FileEntry {
            name: b"tiny.txt",
            data: b"literal bytes over sixteen",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.main.flags, 0x80);
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, b"tiny.txt");
        assert!(archive.entries[0].is_stored());
        assert_eq!(archive.entries[0].header.method, METHOD_STORE);
        assert_eq!(
            archive.entries[0].header.pack_size,
            input[0].data.len() as u32
        );

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"literal bytes over sixteen");
    }

    #[test]
    fn writes_and_reads_literal_only_compressed_archive_with_repeated_stmode() {
        let data =
            b"this literal-only payload is long enough to enter and exit stmode more than once";
        let input = [FileEntry {
            name: b"long.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, METHOD_BEST);

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_levels_control_rar15_encoder_policy() {
        let mut data: Vec<_> = (0..5000).map(|index| (index * 73 + 19) as u8).collect();
        data.extend_from_within(..256);
        let input = [FileEntry {
            name: b"level-policy.bin",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let level_one =
            write_compressed_archive(&input, WriterOptions::default().with_compression_level(1))
                .unwrap();
        let level_five =
            write_compressed_archive(&input, WriterOptions::default().with_compression_level(5))
                .unwrap();
        let level_one = Archive::parse(&level_one).unwrap();
        let level_five = Archive::parse(&level_five).unwrap();
        let level_one_file = &level_one.entries[0];
        let level_five_file = &level_five.entries[0];

        assert_eq!(level_one_file.header.method, METHOD_BEST);
        assert_eq!(level_five_file.header.method, METHOD_BEST);
        assert!(level_five_file.header.pack_size < level_one_file.header.pack_size);
        assert_eq!(collect_extract(&level_one, None).unwrap()[0].data, data);
        assert_eq!(collect_extract(&level_five, None).unwrap()[0].data, data);
    }

    #[test]
    fn rar14_writer_uses_dos_compatible_old_distance_policy() {
        for level in 0..=5 {
            let options = rar15_encode_options_for_level(Some(level)).unwrap();
            assert!(
                !options.old_distance_tokens_enabled(),
                "RAR 1.4 level {level} must not emit old-distance tokens"
            );
        }
    }

    #[test]
    fn compressed_writer_keeps_adaptive_lz_planning_in_sync_after_literals() {
        let data = synthetic_log_payload(8000);
        let input = [FileEntry {
            name: b"synthetic.log",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes =
            write_compressed_archive(&input, WriterOptions::default().with_compression_level(2))
                .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();

        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_emits_short_lz_matches() {
        let data = b"abcabcabcabcabcabcabcabcabcabcabcabc";
        let input = [FileEntry {
            name: b"repeat.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, METHOD_BEST);
        assert!(
            archive.entries[0].header.pack_size < data.len() as u32,
            "ShortLZ should make the repeated payload smaller than stored data"
        );

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_emits_long_lz_matches() {
        let mut data = short_lz_resistant_prefix(300);
        data.extend_from_within(..32);
        assert_eq!(
            find_long_lz(&data, 300, 0x8000),
            Some(LongLz {
                distance: 300,
                length: 32
            })
        );
        let input = [FileEntry {
            name: b"far.txt",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let literal_only = Unpack15Encoder::new()
            .encode_literals_only(&data)
            .unwrap()
            .len();
        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, METHOD_BEST);
        assert!(
            (archive.entries[0].header.pack_size as usize) < literal_only,
            "LongLZ should make a >256-byte-distance repeat smaller than literal-only output"
        );

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_stores_incompressible_member_when_smaller() {
        let mut state = 0x8765_4321u32;
        let data: Vec<_> = (0..8192)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let input = [FileEntry {
            name: b"randomish.bin",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert_eq!(archive.entries[0].header.method, METHOD_STORE);
        assert_eq!(archive.entries[0].header.pack_size, data.len() as u32);
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, data);
    }

    #[test]
    fn compressed_writer_stores_tiny_incompressible_member_when_smaller() {
        let data = b"\x00\xff\x12\xed\x34\xcb\x56\xa9\x78\x87\x9a\x65\xbc\x43\xde\x21";
        let input = [FileEntry {
            name: b"tiny.bin",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert_eq!(archive.entries[0].header.method, METHOD_STORE);
        assert_eq!(archive.entries[0].header.pack_size, data.len() as u32);
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, data);
    }

    #[test]
    fn writes_and_reads_solid_compressed_archive() {
        let input = [
            FileEntry {
                name: b"first.txt",
                data: b"first member primes the adaptive unpack15 state",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            FileEntry {
                name: b"second.txt",
                data: b"second member is encoded without resetting that state",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
            ..WriterOptions::default()
        };

        let bytes = write_compressed_archive(&input, options).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.is_solid());
        assert_eq!(archive.entries.len(), 2);
        assert!(archive
            .entries
            .iter()
            .all(|entry| entry.header.flags & LHD_SOLID != 0));

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
        assert_eq!(extracted[1].data, input[1].data);
    }

    #[test]
    fn writes_and_reads_encrypted_compressed_archive() {
        let input = [FileEntry {
            name: b"secret.txt",
            data: b"secret compressed bytes over sixteen",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pass"),
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].is_encrypted());
        assert_eq!(archive.entries[0].header.method, METHOD_STORE);
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::NeedPassword)
        ));

        let extracted = collect_extract(&archive, Some(b"pass")).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
    }

    #[test]
    fn writes_and_reads_compressed_file_comment() {
        let input = [FileEntry {
            name: b"commented.txt",
            data: b"compressed member with file comment",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: Some(b"compressed file comment"),
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(
            archive.entries[0].file_comment().unwrap().as_deref(),
            Some(&b"compressed file comment"[..])
        );

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
    }

    #[test]
    fn writes_and_reads_stored_multivolume_archive() {
        let entry = StoredEntry {
            name: b"random.bin",
            data: b"abcdefghijklmnopqrstuvwxyz0123456789",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };

        let bytes = write_stored_volumes(entry, WriterOptions::default(), 10).unwrap();
        assert_eq!(bytes.len(), 4);
        let volumes: Vec<_> = bytes
            .iter()
            .map(|bytes| Archive::parse(bytes).unwrap())
            .collect();
        assert!(volumes.iter().all(|archive| archive.main.is_volume()));
        assert!(!volumes[0].entries[0].is_split_before());
        assert!(volumes[0].entries[0].is_split_after());
        assert!(volumes[1].entries[0].is_split_before());
        assert!(volumes[1].entries[0].is_split_after());
        assert!(volumes[3].entries[0].is_split_before());
        assert!(!volumes[3].entries[0].is_split_after());
        assert!(volumes.iter().all(|archive| archive.entries[0].is_stored()));

        let extracted = collect_extract_volumes(&volumes, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"random.bin");
        assert_eq!(extracted[0].data, entry.data);
    }

    #[test]
    fn writes_and_reads_compressed_multivolume_archive() {
        let data = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
        let entry = FileEntry {
            name: b"repeat.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };

        let bytes = write_compressed_volumes(entry, WriterOptions::default(), 8).unwrap();
        assert!(bytes.len() >= 2);
        let volumes: Vec<_> = bytes
            .iter()
            .map(|bytes| Archive::parse(bytes).unwrap())
            .collect();
        assert!(volumes.iter().all(|archive| archive.main.is_volume()));
        assert!(!volumes[0].entries[0].is_stored());
        assert!(volumes[0].entries[0].is_split_after());
        assert!(volumes.last().unwrap().entries[0].is_split_before());
        assert!(!volumes.last().unwrap().entries[0].is_split_after());

        let extracted = collect_extract_volumes(&volumes, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"repeat.txt");
        assert_eq!(extracted[0].data, data);
    }

    fn short_lz_resistant_prefix(len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            let next = (0u8..=u8::MAX)
                .find(|&candidate| {
                    if data.len() < 2 {
                        return true;
                    }
                    let start = data.len().saturating_sub(256);
                    !data[start..].windows(3).any(|window| {
                        window == [data[data.len() - 2], data[data.len() - 1], candidate]
                    })
                })
                .expect("byte alphabet can avoid local 3-byte repeats");
            data.push(next);
        }
        data
    }

    #[test]
    fn writes_empty_compressed_archive_member() {
        let input = [FileEntry {
            name: b"empty.bin",
            data: b"",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, METHOD_STORE);
        assert_eq!(archive.entries[0].header.pack_size, 0);

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"");
    }

    #[test]
    fn rejects_rar5_only_features_for_rar13() {
        let mut features = FeatureSet::store_only();
        features.quick_open = true;

        let options = WriterOptions {
            target: ArchiveVersion::Rar13,
            features,
            ..WriterOptions::default()
        };
        let err = write_stored_archive(&[], options).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar13,
                feature: "quick_open"
            }
        );
    }

    #[test]
    fn rejects_unimplemented_rar13_writer_features() {
        let mut features = FeatureSet::store_only();
        features.sfx = true;

        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
            ..WriterOptions::default()
        };
        let err = write_stored_archive(&[], options).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar14,
                feature: "sfx"
            }
        );
    }

    #[test]
    fn file_checksum_matches_rar13_algorithm() {
        assert_eq!(file_checksum(b""), 0x0000);
        assert_eq!(file_checksum(b"123456789"), 0xc78a);
    }

    #[test]
    fn rar13_checksum_writer_flush_propagates_to_inner_writer() {
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
        let mut checksum = Rar13Checksum::new();
        let mut writer = Rar13ChecksumWriter {
            inner: &mut inner,
            checksum: &mut checksum,
        };
        writer.write_all(b"hello").unwrap();
        writer.flush().unwrap();
        assert_eq!(inner.data, b"hello");
        assert_eq!(inner.flushed, 1);
    }

    #[test]
    fn entry_packed_data_returns_borrowed_slice_for_memory_archives() {
        let payload = b"packed_data direct accessor coverage";
        let input = [StoredEntry {
            name: b"slice.bin",
            data: payload,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let entry = &archive.entries[0];

        let packed = entry.packed_data(&archive).unwrap();
        assert_eq!(packed, payload);
        assert!(!packed.is_empty());
    }

    #[test]
    fn extract_volumes_to_annotates_failed_non_split_entry_with_at_entry() {
        let payload = b"corrupt-me-please";
        let input = [StoredEntry {
            name: b"plain.bin",
            data: payload,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let mut bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let range = archive.entries[0].packed_range.clone();
        // Flip a byte in the stored payload so the checksum no longer matches.
        bytes[range.start] ^= 0xff;

        let corrupted = Archive::parse(&bytes).unwrap();
        let err = collect_extract_volumes(std::slice::from_ref(&corrupted), None).unwrap_err();
        match err {
            Error::AtEntry {
                name,
                operation,
                source,
            } => {
                assert_eq!(name, b"plain.bin");
                assert_eq!(operation, "extracting");
                assert!(matches!(*source, Error::CrcMismatch { .. }));
            }
            other => panic!("expected AtEntry annotation, got {other:?}"),
        }
    }

    #[test]
    fn extract_volumes_to_annotates_failed_split_completion_with_at_entry() {
        let entry = StoredEntry {
            name: b"split.bin",
            data: b"abcdefghijklmnopqrstuvwxyz0123456789",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };

        let mut volume_bytes = write_stored_volumes(entry, WriterOptions::default(), 10).unwrap();
        assert!(
            volume_bytes.len() >= 2,
            "need at least two volumes to exercise the split-completion path"
        );

        // Corrupt the last fragment so PendingSplitRefs::write_to fails on assembly.
        let last_index = volume_bytes.len() - 1;
        let last_archive = Archive::parse(&volume_bytes[last_index]).unwrap();
        let last_range = last_archive.entries[0].packed_range.clone();
        volume_bytes[last_index][last_range.start] ^= 0x7f;

        let volumes: Vec<_> = volume_bytes
            .iter()
            .map(|bytes| Archive::parse(bytes).unwrap())
            .collect();

        let err = collect_extract_volumes(&volumes, None).unwrap_err();
        match err {
            Error::AtEntry {
                name,
                operation,
                source,
            } => {
                assert_eq!(name, b"split.bin");
                assert_eq!(operation, "extracting");
                assert!(
                    matches!(*source, Error::CrcMismatch { .. }),
                    "expected CrcMismatch source, got {source:?}"
                );
            }
            other => panic!("expected AtEntry annotation, got {other:?}"),
        }
    }

    #[test]
    fn entry_packed_data_refuses_to_buffer_file_backed_archives() {
        let payload = b"packed_data refuses file-backed";
        let input = [StoredEntry {
            name: b"file.bin",
            data: payload,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();

        let dir =
            std::env::temp_dir().join(format!("rars-rar13-packed-data-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("entry.rar");
        std::fs::write(&path, &bytes).unwrap();

        let archive = Archive::parse_path(&path).unwrap();
        let result = archive.entries[0].packed_data(&archive);
        assert_eq!(
            result,
            Err(Error::InvalidHeader(
                "RAR 1.3 file-backed packed data requires owned read"
            ))
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    fn parse_volumes(bytes: &[Vec<u8>]) -> Vec<Archive> {
        bytes.iter().map(|b| Archive::parse(b).unwrap()).collect()
    }

    fn split_volumes_for(name: &[u8], data: &[u8]) -> Vec<Vec<u8>> {
        write_stored_volumes(
            StoredEntry {
                name,
                data,
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            WriterOptions::default(),
            10,
        )
        .unwrap()
    }

    #[test]
    fn extract_volumes_to_rejects_pending_split_interrupted_by_regular_entry() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let mut volumes = parse_volumes(&bytes);

        // After volume 0's split_after entry, append a regular entry to the
        // same volume so the loop sees pending=Some when it hits a non-split.
        let mut intruder = volumes[0].entries[0].clone();
        intruder.header.flags &= !(LHD_SPLIT_BEFORE | LHD_SPLIT_AFTER);
        intruder.name = b"intruder.bin".to_vec();
        volumes[0].entries.push(intruder);

        let err = collect_extract_volumes(&volumes, None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.3 split entry is interrupted by a regular entry"),
        );
    }

    #[test]
    fn extract_volumes_to_rejects_split_with_inconsistent_flags() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let volumes = parse_volumes(&bytes);

        // Take just the *middle* volume in isolation: it has split_before=true
        // but no preceding pending state, which the match arm treats as
        // structurally inconsistent.
        let middle = volumes.into_iter().nth(1).unwrap();
        let err = collect_extract_volumes(std::slice::from_ref(&middle), None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.3 split entry flags are inconsistent"),
        );
    }

    #[test]
    fn extract_volumes_to_rejects_pending_split_left_incomplete_at_end() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let volumes = parse_volumes(&bytes);

        // Use only the first volume, which leaves pending=Some after the loop.
        let err = collect_extract_volumes(std::slice::from_ref(&volumes[0]), None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.3 split entry is incomplete")
        );
    }

    #[test]
    fn extract_volumes_to_rejects_split_fragments_with_drifted_attributes() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let mut volumes = parse_volumes(&bytes);

        // Mutate the second volume's entry name so PendingSplitRefs::append
        // refuses it on a name-mismatch.
        volumes[1].entries[0].name = b"different.bin".to_vec();

        let err = collect_extract_volumes(&volumes, None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.3 split entry name changed")
        );
    }

    #[test]
    fn extract_volumes_to_rejects_split_fragments_with_drifted_method() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let mut volumes = parse_volumes(&bytes);

        // Drift the compression method on the second fragment.
        volumes[1].entries[0].header.method = METHOD_BEST;
        let err = collect_extract_volumes(&volumes, None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.3 split entry compression method changed"),
        );
    }

    #[test]
    fn extract_volumes_to_carries_directory_entries_across_volume_array() {
        // A directory entry has zero-length data and gets the open() callback
        // invoked but no payload write. Putting it in a volumes array keeps
        // the directory branch in extract_volumes_to (rather than extract_to)
        // exercised.
        let input = [StoredEntry {
            name: b"docs",
            data: b"",
            file_time: 0,
            file_attr: 0x10,
            password: None,
            file_comment: None,
        }];
        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        let extracted = collect_extract_volumes(std::slice::from_ref(&archive), None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].is_directory);
        assert_eq!(extracted[0].name, b"docs");
    }

    #[test]
    fn extract_volumes_to_routes_pending_split_reader_through_fragment_chain() {
        // Larger payload over more volumes guarantees that the chained
        // fragment reader reads from each volume's range_reader at least once,
        // exercising the success arms of fragment_reader, write_to, and
        // LazyChainedReader::read across multiple volumes.
        let payload: Vec<u8> = (0..96).map(|i| ((i * 53) ^ 0xa5) as u8).collect();
        let bytes = split_volumes_for(b"chain.bin", &payload);
        assert!(
            bytes.len() >= 3,
            "need at least three volumes for the chain"
        );
        let volumes = parse_volumes(&bytes);

        let extracted = collect_extract_volumes(&volumes, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn write_compressed_archive_with_comment_round_trips_through_archive_comment() {
        let data = b"compressed archive comment payload payload payload";
        let comment = b"This is a compressed archive comment.";
        let input = [FileEntry {
            name: b"payload.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes =
            write_compressed_archive_with_comment(&input, WriterOptions::default(), Some(comment))
                .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.has_archive_comment());
        assert!(archive.main.has_packed_comment());
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&comment[..])
        );

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn write_compressed_archive_with_comment_emits_solid_compressed_archive() {
        let data1 = b"solid compressed payload one with overlap overlap overlap";
        let data2 = b"solid compressed payload two with overlap overlap overlap";
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
            ..WriterOptions::default()
        };
        let input = [
            FileEntry {
                name: b"a.txt",
                data: data1,
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            FileEntry {
                name: b"b.txt",
                data: data2,
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];

        let bytes = write_compressed_archive_with_comment(&input, options, None).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.is_solid());
        assert_eq!(archive.entries.len(), 2);

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, data1);
        assert_eq!(extracted[1].data, data2);
    }

    #[test]
    fn write_compressed_archive_with_comment_rejects_non_rar13_target() {
        let options = WriterOptions {
            target: ArchiveVersion::Rar15,
            ..WriterOptions::default()
        };
        let err = write_compressed_archive_with_comment(&[], options, None).unwrap_err();
        assert_eq!(err, Error::UnsupportedVersion(ArchiveVersion::Rar15));
    }

    #[test]
    fn parse_path_round_trips_multi_entry_archive_via_file_backed_seekable_path() {
        // Two entries plus an archive comment forces parse_seekable to walk
        // through more than one file-header read iteration.
        let input = [
            StoredEntry {
                name: b"first.txt",
                data: b"first payload",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            StoredEntry {
                name: b"second.txt",
                data: b"second payload",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];
        let bytes = write_stored_archive_with_comment(
            &input,
            WriterOptions::default(),
            Some(b"file-backed comment"),
        )
        .unwrap();

        let dir =
            std::env::temp_dir().join(format!("rars-rar13-parse-seekable-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("multi.rar");
        std::fs::write(&path, &bytes).unwrap();

        let archive = Archive::parse_path(&path).unwrap();
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.entries[0].name, b"first.txt");
        assert_eq!(archive.entries[1].name, b"second.txt");
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&b"file-backed comment"[..])
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn parse_path_rejects_files_without_rar13_signature() {
        let dir =
            std::env::temp_dir().join(format!("rars-rar13-parse-path-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("not_a_rar.bin");
        std::fs::write(&path, [0u8; 64]).unwrap();

        let err = Archive::parse_path(&path).unwrap_err();
        assert_eq!(err, Error::UnsupportedSignature);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn extract_to_encrypted_archive_reads_through_file_backed_decrypted_range() {
        // The Memory-backed path is already exercised; this test takes the
        // same encrypted archive out to disk so copy_decrypted_range_to runs
        // its ArchiveSource::File branch.
        let input = [StoredEntry {
            name: b"secret.bin",
            data: b"file-backed secret payload",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pw"),
            file_comment: None,
        }];
        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();

        let dir =
            std::env::temp_dir().join(format!("rars-rar13-decrypt-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("encrypted.rar");
        std::fs::write(&path, &bytes).unwrap();

        let archive = Archive::parse_path(&path).unwrap();
        let extracted = collect_extract(&archive, Some(b"pw")).unwrap();
        assert_eq!(extracted[0].data, b"file-backed secret payload");

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn write_stored_volumes_rejects_password_protected_entries() {
        let entry = StoredEntry {
            name: b"locked.bin",
            data: b"data",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pw"),
            file_comment: None,
        };
        let err = write_stored_volumes(entry, WriterOptions::default(), 16).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar14,
                feature: "volume_password",
            }
        );
    }

    #[test]
    fn write_compressed_volumes_rejects_archive_comment_feature() {
        let mut features = FeatureSet::store_only();
        features.archive_comment = true;
        let entry = FileEntry {
            name: b"with-comment.bin",
            data: b"data",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let err = write_compressed_volumes(
            entry,
            WriterOptions {
                target: ArchiveVersion::Rar14,
                features,
                ..WriterOptions::default()
            },
            16,
        )
        .unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar14,
                feature: "volume_archive_comment",
            }
        );
    }

    #[test]
    fn write_compressed_volumes_rejects_non_rar13_target() {
        let options = WriterOptions {
            target: ArchiveVersion::Rar20,
            ..WriterOptions::default()
        };
        let entry = FileEntry {
            name: b"x.bin",
            data: b"data",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let err = write_compressed_volumes(entry, options, 16).unwrap_err();
        assert_eq!(err, Error::UnsupportedVersion(ArchiveVersion::Rar20));
    }

    #[test]
    fn file_header_parse_rejects_input_below_base_size() {
        let err = FileHeader::parse(&[0u8; FILE_HEAD_BASE_SIZE - 1]).unwrap_err();
        assert_eq!(err, Error::TooShort);
    }

    #[test]
    fn file_header_parse_rejects_truncated_input_against_declared_head_size() {
        // Build a syntactically OK FILE_HEAD_BASE_SIZE buffer that declares a
        // head_size larger than the slice we pass in — exercises the
        // post-name-size length check at the end of FileHeader::parse.
        let mut header = [0u8; FILE_HEAD_BASE_SIZE];
        // pack_size, unp_size, file_crc, file_time stay zero.
        let declared_head_size: u16 = (FILE_HEAD_BASE_SIZE + 32) as u16;
        header[10..12].copy_from_slice(&declared_head_size.to_le_bytes());
        // name_size = 0 keeps minimum_size == FILE_HEAD_BASE_SIZE so the
        // earlier "shorter than its name" branch is bypassed.
        header[19] = 0;
        let err = FileHeader::parse(&header).unwrap_err();
        assert_eq!(err, Error::TooShort);
    }

    #[test]
    fn archive_comment_rejects_size_field_shorter_than_two_bytes() {
        // Build a valid stored archive then patch its main header so the
        // declared comment field is shorter than two bytes — exercises the
        // "packed archive comment is shorter than size field" arm.
        let input = [StoredEntry {
            name: b"file.bin",
            data: b"data",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let bytes =
            write_stored_archive_with_comment(&input, WriterOptions::default(), Some(b"hi"))
                .unwrap();
        let mut archive = Archive::parse(&bytes).unwrap();
        // The first two bytes of `main.extra` are the comment_field length —
        // overwrite them with 1 to declare a sub-2-byte payload while keeping
        // the packed-comment flag set.
        archive.main.extra[0] = 1;
        archive.main.extra[1] = 0;
        assert_eq!(
            archive.archive_comment(),
            Err(Error::InvalidHeader(
                "RAR 1.3 packed archive comment is shorter than size field"
            ))
        );
    }

    #[test]
    fn archive_comment_rejects_packed_payload_extending_past_extra_buffer() {
        let input = [StoredEntry {
            name: b"file.bin",
            data: b"data",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let bytes =
            write_stored_archive_with_comment(&input, WriterOptions::default(), Some(b"hi"))
                .unwrap();
        let mut archive = Archive::parse(&bytes).unwrap();
        // Pump the declared comment field length up so the packed range walks
        // past the end of `main.extra`.
        let inflated = (archive.main.extra.len() as u16 + 16).to_le_bytes();
        archive.main.extra[0] = inflated[0];
        archive.main.extra[1] = inflated[1];
        assert_eq!(archive.archive_comment(), Err(Error::TooShort));
    }
}
