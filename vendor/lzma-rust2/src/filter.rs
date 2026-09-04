//! Implements filter used by both the 7z and XZ file format.

pub mod bcj;
pub mod bcj2;
pub mod delta;

use alloc::boxed::Box;

use crate::{
    error_unsupported,
    filter::{bcj::BcjFilter, delta::Delta},
};

/// Configuration for a filter in the XZ filter chain.
#[derive(Debug, Clone)]
pub struct FilterConfig {
    /// Filter type to use.
    pub filter_type: FilterType,
    /// Property to use.
    pub property: u32,
}

impl FilterConfig {
    /// Creates a new delta filter configuration.
    pub fn new_delta(distance: u32) -> Self {
        Self {
            filter_type: FilterType::Delta,
            property: distance,
        }
    }

    /// Creates a new BCJ x86 filter configuration.
    pub fn new_bcj_x86(start_pos: u32) -> Self {
        Self {
            filter_type: FilterType::BcjX86,
            property: start_pos,
        }
    }

    /// Creates a new BCJ ARM filter configuration.
    pub fn new_bcj_arm(start_pos: u32) -> Self {
        Self {
            filter_type: FilterType::BcjArm,
            property: start_pos,
        }
    }

    /// Creates a new BCJ ARM Thumb filter configuration.
    pub fn new_bcj_arm_thumb(start_pos: u32) -> Self {
        Self {
            filter_type: FilterType::BcjArmThumb,
            property: start_pos,
        }
    }

    /// Creates a new BCJ ARM64 filter configuration.
    pub fn new_bcj_arm64(start_pos: u32) -> Self {
        Self {
            filter_type: FilterType::BcjArm64,
            property: start_pos,
        }
    }

    /// Creates a new BCJ IA64 filter configuration.
    pub fn new_bcj_ia64(start_pos: u32) -> Self {
        Self {
            filter_type: FilterType::BcjIa64,
            property: start_pos,
        }
    }

    /// Creates a new BCJ PPC filter configuration.
    pub fn new_bcj_ppc(start_pos: u32) -> Self {
        Self {
            filter_type: FilterType::BcjPpc,
            property: start_pos,
        }
    }

    /// Creates a new BCJ SPARC filter configuration.
    pub fn new_bcj_sparc(start_pos: u32) -> Self {
        Self {
            filter_type: FilterType::BcjSparc,
            property: start_pos,
        }
    }

    /// Creates a new BCJ RISC-V filter configuration.
    pub fn new_bcj_risc_v(start_pos: u32) -> Self {
        Self {
            filter_type: FilterType::BcjRiscv,
            property: start_pos,
        }
    }
}

/// Supported filter types in XZ format.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FilterType {
    /// Delta filter
    Delta,
    /// BCJ x86 filter
    BcjX86,
    /// BCJ PowerPC filter
    BcjPpc,
    /// BCJ IA64 filter
    BcjIa64,
    /// BCJ ARM filter
    BcjArm,
    /// BCJ ARM Thumb
    BcjArmThumb,
    /// BCJ SPARC filter
    BcjSparc,
    /// BCJ ARM64 filter
    BcjArm64,
    /// BCJ RISC-V filter
    BcjRiscv,
    /// LZMA2 filter
    Lzma2,
}

impl TryFrom<u64> for FilterType {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0x03 => Ok(FilterType::Delta),
            0x04 => Ok(FilterType::BcjX86),
            0x05 => Ok(FilterType::BcjPpc),
            0x06 => Ok(FilterType::BcjIa64),
            0x07 => Ok(FilterType::BcjArm),
            0x08 => Ok(FilterType::BcjArmThumb),
            0x09 => Ok(FilterType::BcjSparc),
            0x0A => Ok(FilterType::BcjArm64),
            0x0B => Ok(FilterType::BcjRiscv),
            0x21 => Ok(FilterType::Lzma2),
            _ => Err(()),
        }
    }
}

/// A single filter for the sans-I/O decoders.
///
/// Decodes a slice in place. A BCJ filter can not classify the last bytes of a
/// slice before it knows what follows them, so it holds them back until more
/// data arrives or the stream ends.
pub struct StreamFilter {
    filter: Filter,
    held_back: usize,
}

enum Filter {
    Delta(Box<Delta>),
    Bcj(BcjFilter),
}

impl StreamFilter {
    /// Creates a new filter from its configuration.
    ///
    /// LZMA2 is not supported, as it is not a filter that decodes a slice in
    /// place.
    pub fn new(config: &FilterConfig) -> crate::Result<Self> {
        let property = config.property as usize;

        let filter = match config.filter_type {
            FilterType::Delta => Filter::Delta(Box::new(Delta::new(property))),
            FilterType::BcjX86 => Filter::Bcj(BcjFilter::new_x86(property, false)),
            FilterType::BcjPpc => Filter::Bcj(BcjFilter::new_power_pc(property, false)),
            FilterType::BcjIa64 => Filter::Bcj(BcjFilter::new_ia64(property, false)),
            FilterType::BcjArm => Filter::Bcj(BcjFilter::new_arm(property, false)),
            FilterType::BcjArmThumb => Filter::Bcj(BcjFilter::new_arm_thumb(property, false)),
            FilterType::BcjSparc => Filter::Bcj(BcjFilter::new_sparc(property, false)),
            FilterType::BcjArm64 => Filter::Bcj(BcjFilter::new_arm64(property, false)),
            FilterType::BcjRiscv => Filter::Bcj(BcjFilter::new_riscv(property, false)),
            FilterType::Lzma2 => {
                return Err(error_unsupported("LZMA2 is not supported as a filter"));
            }
        };

        Ok(Self {
            filter,
            held_back: 0,
        })
    }

    /// Decodes `buf` in place and returns how many bytes at its start are
    /// settled.
    ///
    /// The bytes after that are held back and have to be passed in again
    /// together with the data that follows them.
    pub fn decode(&mut self, buf: &mut [u8]) -> usize {
        let decoded = match &mut self.filter {
            Filter::Delta(delta) => {
                delta.decode(buf);
                buf.len()
            }
            Filter::Bcj(bcj) => bcj.code(buf),
        };

        self.held_back = buf.len() - decoded;
        decoded
    }

    /// Returns how many bytes at the end of the last [`Self::decode`] are held
    /// back.
    pub fn held_back(&self) -> usize {
        self.held_back
    }

    /// Settles the held back bytes at the end of the stream.
    ///
    /// Nothing follows them anymore, so they are used as they are and
    /// [`Self::held_back`] returns zero afterwards.
    pub fn finish(&mut self) {
        self.held_back = 0;
    }
}
