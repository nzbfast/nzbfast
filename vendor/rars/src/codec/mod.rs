//! RAR compression codecs, filters, PPMd, and RARVM components used by `rars`.

pub(crate) mod address_filters;
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub use address_filters::harness as address_filters_harness;
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub use address_filters::census as address_filters_census;
mod fast;
mod filters;
mod huffman;
mod match_index;
mod ppmd;
pub mod rar13;
pub mod rar20;
pub mod rar29;
pub mod rar50;
pub mod rarvm;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidData(&'static str),
    NeedMoreInput,
    Cancelled,
    /// A match is legal for the archive's dictionary but needs a wider window
    /// than the caller allowed (see `Rar50Decoder::set_window_limit`). The
    /// extract layer remaps this to `crate::Error::Rar50WindowLimitExceeded`.
    WindowLimitExceeded {
        limit: u64,
        required: u64,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidData(msg) => write!(f, "{msg}"),
            Self::NeedMoreInput => write!(f, "codec input is truncated"),
            Self::Cancelled => f.write_str("codec operation was cancelled"),
            Self::WindowLimitExceeded { limit, required } => write!(
                f,
                "RAR 5 match needs a {required}-byte window, above the configured limit of {limit} bytes"
            ),
        }
    }
}

impl std::error::Error for Error {}
