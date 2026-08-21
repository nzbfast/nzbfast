use crate::version::{ArchiveFamily, ArchiveVersion};
use std::sync::Arc;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct IoError {
    pub kind: std::io::ErrorKind,
    pub message: String,
    source: Arc<std::io::Error>,
}

impl IoError {
    pub fn source(&self) -> &(dyn std::error::Error + 'static) {
        self.source.as_ref()
    }
}

impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}

impl Eq for IoError {}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    TooShort,
    UnsupportedSignature,
    InvalidHeader(&'static str),
    AtArchiveOffset {
        offset: usize,
        source: Box<Error>,
    },
    AtEntry {
        name: Vec<u8>,
        operation: &'static str,
        source: Box<Error>,
    },
    UnsupportedVersion(ArchiveVersion),
    UnsupportedFeature {
        version: ArchiveVersion,
        feature: &'static str,
    },
    Rar50BufferedDecodeLimitExceeded {
        limit: u64,
        required: u64,
    },
    Rar50WindowLimitExceeded {
        limit: u64,
        required: u64,
    },
    UnsupportedFamilyFeature {
        family: ArchiveFamily,
        feature: &'static str,
    },
    UnsupportedCompression {
        family: &'static str,
        unpack_version: u8,
        method: u8,
    },
    UnsupportedEncryption {
        family: &'static str,
        unpack_version: u8,
    },
    Io(IoError),
    NeedPassword,
    WrongPasswordOrCorruptData,
    /// Archive writing was cancelled by a progress callback.
    Cancelled,
    CrcMismatch {
        expected: u16,
        actual: u16,
    },
    Crc32Mismatch {
        expected: u32,
        actual: u32,
    },
    /// A split member's non-final fragment failed the packed-data CRC its
    /// own header carries, so the damage is located before the member
    /// finishes decoding. `volume` is the zero-based index of the bad
    /// volume within the set.
    SplitFragmentCrc32Mismatch {
        volume: usize,
        expected: u32,
        actual: u32,
    },
    /// [`Self::SplitFragmentCrc32Mismatch`] for a BLAKE2sp record (RAR 5
    /// sets written with -htb carry a hash instead of a CRC32).
    SplitFragmentHashMismatch {
        volume: usize,
    },
    HashMismatch {
        hash_type: u64,
    },
    /// A legacy (RAR 2/3) recovery-record repair is arithmetically possible
    /// but its working set does not fit the caller's memory budget. The
    /// legacy analogue of [`crate::recovery::rar5::Error::RepairTooLarge`]:
    /// answered by widening the budget, not by a different archive.
    /// (nzbfast-local change, 20 Aug 2026 - see vendor/rars/VENDORING.md.)
    LegacyRepairTooLarge,
    Codec(crate::codec::Error),
    Rar3Recovery(crate::recovery::rar3::Error),
    Rar5Recovery(crate::recovery::rar5::Error),
    Rar20Crypto(crate::crypto::rar20::Error),
    Rar30Crypto(crate::crypto::rar30::Error),
    Rar50Crypto(crate::crypto::rar50::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "input is too short"),
            Self::UnsupportedSignature => write!(f, "unsupported archive signature"),
            Self::InvalidHeader(msg) => write!(f, "invalid header: {msg}"),
            Self::AtArchiveOffset { offset, source } => {
                write!(f, "at archive offset {offset:#x}: {source}")
            }
            Self::AtEntry {
                name,
                operation,
                source,
            } => {
                write!(
                    f,
                    "while {operation} entry '{}': {source}",
                    String::from_utf8_lossy(name)
                )
            }
            Self::UnsupportedVersion(version) => write!(f, "unsupported version: {version:?}"),
            Self::UnsupportedFeature { version, feature } => {
                write!(f, "feature {feature} is not supported by {version:?}")
            }
            Self::Rar50BufferedDecodeLimitExceeded { limit, required } => write!(
                f,
                "RAR 5 filtered member requires buffered decoding of {required} bytes, above the configured limit of {limit} bytes"
            ),
            Self::Rar50WindowLimitExceeded { limit, required } => write!(
                f,
                "RAR 5 match needs a {required}-byte window, above the configured limit of {limit} bytes (raise rar50_max_window to decode this archive)"
            ),
            Self::UnsupportedFamilyFeature { family, feature } => {
                write!(f, "feature {feature} is not supported by {family:?}")
            }
            Self::UnsupportedCompression {
                family,
                unpack_version,
                method,
            } => write!(
                f,
                "{family} compression is not supported: unpack version {unpack_version}, method {method:#04x}"
            ),
            Self::UnsupportedEncryption {
                family,
                unpack_version,
            } => write!(
                f,
                "{family} encryption is not supported: unpack version {unpack_version}"
            ),
            Self::Io(error) => write!(f, "I/O error: {}", error.message),
            Self::NeedPassword => write!(f, "a password is required"),
            Self::WrongPasswordOrCorruptData => {
                write!(f, "wrong password or corrupt encrypted data")
            }
            Self::Cancelled => f.write_str("archive writing was cancelled"),
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#06x}, got {actual:#06x}"
                )
            }
            Self::Crc32Mismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
                )
            }
            Self::SplitFragmentCrc32Mismatch {
                volume,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "packed data checksum mismatch in split volume {volume}: expected {expected:#010x}, got {actual:#010x}"
                )
            }
            Self::SplitFragmentHashMismatch { volume } => {
                write!(f, "packed data hash mismatch in split volume {volume}")
            }
            Self::HashMismatch { hash_type } => {
                write!(f, "hash mismatch for hash type {hash_type}")
            }
            Self::LegacyRepairTooLarge => f.write_str(
                "legacy RAR recovery repair needs more working memory than the budget allows",
            ),
            Self::Codec(error) => write!(f, "{error}"),
            Self::Rar3Recovery(error) => write!(f, "{error}"),
            Self::Rar5Recovery(error) => write!(f, "{error}"),
            Self::Rar20Crypto(error) => write!(f, "{error}"),
            Self::Rar30Crypto(error) => write!(f, "{error}"),
            Self::Rar50Crypto(error) => write!(f, "{error}"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(IoError {
            kind: error.kind(),
            message: error.to_string(),
            source: Arc::new(error),
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AtArchiveOffset { source, .. } | Self::AtEntry { source, .. } => Some(source),
            Self::Codec(source) => Some(source),
            Self::Rar3Recovery(source) => Some(source),
            Self::Rar5Recovery(source) => Some(source),
            Self::Rar20Crypto(source) => Some(source),
            Self::Rar30Crypto(source) => Some(source),
            Self::Rar50Crypto(source) => Some(source),
            Self::Io(source) => Some(source.source()),
            _ => None,
        }
    }
}

impl Error {
    pub fn at_archive_offset(self, offset: usize) -> Self {
        Self::AtArchiveOffset {
            offset,
            source: Box::new(self),
        }
    }

    pub fn at_entry(self, name: Vec<u8>, operation: &'static str) -> Self {
        Self::AtEntry {
            name,
            operation,
            source: Box::new(self),
        }
    }
}

impl From<crate::codec::Error> for Error {
    fn from(error: crate::codec::Error) -> Self {
        Self::Codec(error)
    }
}

impl From<crate::recovery::rar5::Error> for Error {
    fn from(error: crate::recovery::rar5::Error) -> Self {
        Self::Rar5Recovery(error)
    }
}

impl From<crate::recovery::rar3::Error> for Error {
    fn from(error: crate::recovery::rar3::Error) -> Self {
        Self::Rar3Recovery(error)
    }
}

impl From<crate::crypto::rar20::Error> for Error {
    fn from(error: crate::crypto::rar20::Error) -> Self {
        Self::Rar20Crypto(error)
    }
}

impl From<crate::crypto::rar30::Error> for Error {
    fn from(error: crate::crypto::rar30::Error) -> Self {
        Self::Rar30Crypto(error)
    }
}

impl From<crate::crypto::rar50::Error> for Error {
    fn from(error: crate::crypto::rar50::Error) -> Self {
        Self::Rar50Crypto(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_offset_context_exposes_source_error() {
        let error = Error::InvalidHeader("bad block").at_archive_offset(0x1234);

        assert_eq!(
            error.to_string(),
            "at archive offset 0x1234: invalid header: bad block"
        );
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("invalid header: bad block".to_string())
        );
    }

    #[test]
    fn entry_context_exposes_source_error() {
        let error = Error::Crc32Mismatch {
            expected: 1,
            actual: 2,
        }
        .at_entry(b"hello.txt".to_vec(), "verifying");

        assert_eq!(
            error.to_string(),
            "while verifying entry 'hello.txt': checksum mismatch: expected 0x00000001, got 0x00000002"
        );
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("checksum mismatch: expected 0x00000001, got 0x00000002".to_string())
        );
    }

    #[test]
    fn io_error_preserves_error_kind() {
        let error = Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "locked",
        ));

        assert!(matches!(
            error,
            Error::Io(ref source) if source.kind == std::io::ErrorKind::PermissionDenied
        ));
        assert_eq!(error.to_string(), "I/O error: locked");
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("locked".to_string())
        );
    }

    #[test]
    fn io_error_partial_eq_compares_kind_and_message_ignoring_source_identity() {
        let permission = Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "locked",
        ));
        let permission_again = Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "locked",
        ));
        let different_kind =
            Error::from(std::io::Error::new(std::io::ErrorKind::NotFound, "locked"));
        let different_message = Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "elsewhere",
        ));

        // Same kind + same message → equal even though Arc<io::Error> differs.
        assert_eq!(permission, permission_again);
        // Differing kind or message → not equal.
        assert_ne!(permission, different_kind);
        assert_ne!(permission, different_message);
    }

    #[test]
    fn unsupported_codec_errors_are_not_reported_as_invalid_headers() {
        assert_eq!(
            Error::UnsupportedCompression {
                family: "RAR 1.5-4.x",
                unpack_version: 14,
                method: 0x33,
            }
            .to_string(),
            "RAR 1.5-4.x compression is not supported: unpack version 14, method 0x33"
        );
        assert_eq!(
            Error::UnsupportedEncryption {
                family: "RAR 1.5-4.x",
                unpack_version: 14,
            }
            .to_string(),
            "RAR 1.5-4.x encryption is not supported: unpack version 14"
        );
    }

    #[test]
    fn codec_errors_remain_inspectable_without_changing_display_text() {
        let error = Error::from(crate::codec::Error::NeedMoreInput);

        assert!(matches!(
            error,
            Error::Codec(crate::codec::Error::NeedMoreInput)
        ));
        assert_eq!(error.to_string(), "codec input is truncated");
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("codec input is truncated".to_string())
        );
    }

    #[test]
    fn recovery_errors_remain_inspectable_without_changing_display_text() {
        let error = Error::from(crate::recovery::rar5::Error::TooManyDamagedShards);

        assert!(matches!(
            error,
            Error::Rar5Recovery(crate::recovery::rar5::Error::TooManyDamagedShards)
        ));
        assert_eq!(
            error.to_string(),
            "RAR 5 recovery data cannot repair this many damaged shards"
        );
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("RAR 5 recovery data cannot repair this many damaged shards".to_string())
        );
    }

    #[test]
    fn rar3_recovery_errors_remain_in_source_chain() {
        let error = Error::from(crate::recovery::rar3::Error::DecodeFailed);

        assert_eq!(error.to_string(), "RAR 3 recovery decode failed");
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("RAR 3 recovery decode failed".to_string())
        );
    }

    #[test]
    fn rar30_crypto_errors_remain_in_source_chain() {
        let error = Error::from(crate::crypto::rar30::Error::UnalignedInput);

        assert!(matches!(
            error,
            Error::Rar30Crypto(crate::crypto::rar30::Error::UnalignedInput)
        ));
        assert_eq!(error.to_string(), "RAR 3.x AES input is not block aligned");
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("RAR 3.x AES input is not block aligned".to_string())
        );
    }

    #[test]
    fn rar20_crypto_errors_remain_in_source_chain() {
        let error = Error::from(crate::crypto::rar20::Error::UnalignedInput);

        assert!(matches!(
            error,
            Error::Rar20Crypto(crate::crypto::rar20::Error::UnalignedInput)
        ));
        assert_eq!(
            error.to_string(),
            "RAR 2.0 cipher input is not block aligned"
        );
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("RAR 2.0 cipher input is not block aligned".to_string())
        );
    }

    #[test]
    fn rar50_crypto_errors_remain_in_source_chain() {
        let error = Error::from(crate::crypto::rar50::Error::UnalignedInput);

        assert_eq!(error.to_string(), "RAR 5 AES input is not block aligned");
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("RAR 5 AES input is not block aligned".to_string())
        );
    }

    #[test]
    fn simple_display_variants_render_their_messages() {
        assert_eq!(Error::TooShort.to_string(), "input is too short");
        assert_eq!(
            Error::UnsupportedSignature.to_string(),
            "unsupported archive signature"
        );
        assert_eq!(Error::NeedPassword.to_string(), "a password is required");
        assert_eq!(
            Error::WrongPasswordOrCorruptData.to_string(),
            "wrong password or corrupt encrypted data"
        );
        assert_eq!(
            Error::HashMismatch { hash_type: 7 }.to_string(),
            "hash mismatch for hash type 7"
        );
        assert_eq!(
            Error::CrcMismatch {
                expected: 0xabcd,
                actual: 0x1234
            }
            .to_string(),
            "checksum mismatch: expected 0xabcd, got 0x1234"
        );
        assert_eq!(
            Error::SplitFragmentCrc32Mismatch {
                volume: 3,
                expected: 0xabcd_ef01,
                actual: 0x1234_5678,
            }
            .to_string(),
            "packed data checksum mismatch in split volume 3: expected 0xabcdef01, got 0x12345678"
        );
        assert_eq!(
            Error::SplitFragmentHashMismatch { volume: 3 }.to_string(),
            "packed data hash mismatch in split volume 3"
        );
        assert_eq!(
            Error::UnsupportedVersion(ArchiveVersion::Rar50).to_string(),
            "unsupported version: Rar50"
        );
        assert_eq!(
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar50,
                feature: "quantum compression",
            }
            .to_string(),
            "feature quantum compression is not supported by Rar50"
        );
        assert_eq!(
            Error::Rar50BufferedDecodeLimitExceeded {
                limit: 536_870_912,
                required: 734_003_200,
            }
            .to_string(),
            "RAR 5 filtered member requires buffered decoding of 734003200 bytes, above the configured limit of 536870912 bytes"
        );
    }

    #[test]
    fn rar3_recovery_errors_render_messages_through_from_conversion() {
        assert_eq!(
            Error::from(crate::recovery::rar3::Error::InvalidParitySize).to_string(),
            "RAR 3 recovery parity size is invalid"
        );
        assert_eq!(
            Error::from(crate::recovery::rar3::Error::InvalidCodewordSize).to_string(),
            "RAR 3 recovery codeword size is invalid"
        );
        assert_eq!(
            Error::from(crate::recovery::rar3::Error::TooManyErasures).to_string(),
            "RAR 3 recovery data cannot repair this many erasures"
        );
        assert_eq!(
            Error::from(crate::recovery::rar3::Error::DecodeFailed).to_string(),
            "RAR 3 recovery decode failed"
        );
    }

    #[test]
    fn rar5_recovery_errors_render_messages_for_every_named_variant() {
        let cases = [
            (
                crate::recovery::rar5::Error::BadRecoveryChunk,
                "RAR 5 recovery chunk is invalid",
            ),
            (
                crate::recovery::rar5::Error::OddShardSize,
                "RAR 5 recovery shard size is odd",
            ),
            (
                crate::recovery::rar5::Error::PlanOverflow,
                "RAR 5 recovery plan overflows",
            ),
            (
                crate::recovery::rar5::Error::PrefixExceedsPlan,
                "RAR 5 recovery prefix exceeds planned shard capacity",
            ),
            (
                crate::recovery::rar5::Error::ReconstructionTooLarge,
                "RAR 5 recovery shard grid exceeds the reconstruction budget",
            ),
            (
                crate::recovery::rar5::Error::ShardSizeMismatch,
                "RAR 5 recovery shard sizes differ",
            ),
            (
                crate::recovery::rar5::Error::TooManyShards,
                "RAR 5 recovery shard count is invalid",
            ),
            (
                crate::recovery::rar5::Error::SingularElement,
                "RAR 5 recovery matrix is singular",
            ),
        ];
        for (variant, expected) in cases {
            assert_eq!(Error::from(variant).to_string(), expected);
        }
    }

    #[test]
    fn rar50_crypto_errors_render_messages_through_from_conversion() {
        assert_eq!(
            Error::from(crate::crypto::rar50::Error::KdfCountTooLarge).to_string(),
            "RAR 5 KDF count is too large"
        );
        assert_eq!(
            Error::from(crate::crypto::rar50::Error::BadPassword).to_string(),
            "wrong password or corrupt encrypted data"
        );
    }

    #[test]
    fn codec_invalid_data_display_uses_inner_message() {
        assert_eq!(
            Error::from(crate::codec::Error::InvalidData("bad symbol")).to_string(),
            "bad symbol"
        );
    }

    #[test]
    fn unsupported_family_feature_display_renders_family_and_feature() {
        assert_eq!(
            Error::UnsupportedFamilyFeature {
                family: ArchiveFamily::Rar13,
                feature: "recovery repair for RAR 1.3/1.4 archives",
            }
            .to_string(),
            "feature recovery repair for RAR 1.3/1.4 archives is not supported by Rar13",
        );
    }

    #[test]
    fn rar50_crypto_unaligned_input_display_uses_named_message() {
        assert_eq!(
            Error::from(crate::crypto::rar50::Error::UnalignedInput).to_string(),
            "RAR 5 AES input is not block aligned"
        );
    }
}
