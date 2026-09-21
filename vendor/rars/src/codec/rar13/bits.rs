//! Bit input and output for the RAR 1.5 algorithm.
//!
//! Bits run most significant first within each byte. Past the end of the
//! packed bytes every bit reads as 0, which is never an error by itself; a
//! member ends when its output reaches its size, not when its input ends.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use super::super::{Error, Result};
use std::io::Read;

/// Size of the fixed buffer a reader source pulls packed bytes through.
const READ_BUFFER: usize = 64 * 1024;

/// Somewhere the bit reader loads whole bytes from.
pub(crate) trait ByteSource {
    /// Tops `bits` up to at least 57 valid bits (`count`) and returns both.
    /// `bits` holds its valid bits at the top; everything below `count` must
    /// stay either zero or the true bits that follow, so loading several
    /// bytes at once and ORing them in is idempotent. Past the end of input,
    /// bytes are zero. Values in and out rather than references, so the
    /// decoder's bit buffer never has its address taken and stays in a
    /// register.
    fn fill(&mut self, bits: u64, count: u32) -> Result<(u64, u32)>;
}

/// Loads up to eight bytes at once from the front of `data`; returns the
/// number of bytes consumed, or `None` when fewer than eight remain.
#[inline(always)]
fn fill_fast(data: &[u8], bits: u64, count: u32) -> Option<(u64, u32, usize)> {
    let chunk: [u8; 8] = data.get(..8)?.try_into().ok()?;
    let bytes = (63 - count) / 8;
    Some((
        bits | u64::from_be_bytes(chunk) >> count,
        count + bytes * 8,
        bytes as usize,
    ))
}

/// A byte-slice source.
pub(crate) struct SliceSource<'a> {
    data: &'a [u8],
}

impl<'a> SliceSource<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl ByteSource for SliceSource<'_> {
    #[inline(always)]
    fn fill(&mut self, bits: u64, count: u32) -> Result<(u64, u32)> {
        if let Some((bits, count, bytes)) = fill_fast(self.data, bits, count) {
            self.data = self.data.get(bytes..).unwrap_or_default();
            return Ok((bits, count));
        }
        let (data, bits, count) = fill_tail(self.data, bits, count);
        self.data = data;
        Ok((bits, count))
    }
}

/// Fewer than eight bytes left: load them one at a time, then zeros.
#[cold]
#[inline(never)]
fn fill_tail(mut data: &[u8], mut bits: u64, mut count: u32) -> (&[u8], u64, u32) {
    while count <= 56 {
        if let Some((&byte, rest)) = data.split_first() {
            bits |= u64::from(byte) << (56 - count);
            data = rest;
        }
        count += 8;
    }
    (data, bits, count)
}

/// A reader source, pulling packed bytes through a fixed buffer so memory
/// does not grow with the packed size. Reader EOF is the end of input.
pub(crate) struct ReaderSource<'r, R: Read> {
    reader: &'r mut R,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
}

impl<'r, R: Read> ReaderSource<'r, R> {
    pub(crate) fn new(reader: &'r mut R) -> Self {
        Self {
            reader,
            buffer: vec![0; READ_BUFFER],
            start: 0,
            end: 0,
            eof: false,
        }
    }

    fn read_more(&mut self) -> Result<()> {
        loop {
            match self.reader.read(&mut self.buffer) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(read) => {
                    self.start = 0;
                    self.end = read.min(self.buffer.len());
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Error::InvalidData("RAR 1.5 packed input read failed")),
            }
        }
    }
}

impl<R: Read> ByteSource for ReaderSource<'_, R> {
    #[inline(always)]
    fn fill(&mut self, bits: u64, count: u32) -> Result<(u64, u32)> {
        let pending = self.buffer.get(self.start..self.end).unwrap_or_default();
        if let Some((bits, count, bytes)) = fill_fast(pending, bits, count) {
            self.start += bytes;
            return Ok((bits, count));
        }
        self.fill_slow(bits, count)
    }
}

impl<R: Read> ReaderSource<'_, R> {
    /// The buffer holds fewer than eight bytes: load bytes one at a time,
    /// reading more from the reader as needed, then zeros past EOF.
    #[inline(never)]
    fn fill_slow(&mut self, mut bits: u64, mut count: u32) -> Result<(u64, u32)> {
        while count <= 56 {
            let pending = self.buffer.get(self.start..self.end).unwrap_or_default();
            if let Some((filled, total, bytes)) = fill_fast(pending, bits, count) {
                self.start += bytes;
                return Ok((filled, total));
            }
            if let Some(&byte) = pending.first() {
                bits |= u64::from(byte) << (56 - count);
                count += 8;
                self.start += 1;
            } else if self.eof {
                count = 64;
            } else {
                self.read_more()?;
            }
        }
        Ok((bits, count))
    }
}

/// Reads bits most significant first from a byte source.
pub(crate) struct BitReader<S> {
    bits: u64,
    count: u32,
    source: S,
}

impl<S: ByteSource> BitReader<S> {
    pub(crate) fn new(source: S) -> Self {
        Self {
            bits: 0,
            count: 0,
            source,
        }
    }

    /// The next `n` bits (1..=16) without consuming them.
    #[inline(always)]
    pub(crate) fn peek(&mut self, n: u32) -> Result<u32> {
        if self.count < n {
            (self.bits, self.count) = self.source.fill(self.bits, self.count)?;
        }
        Ok((self.bits >> (64 - n)) as u32)
    }

    /// Consumes `n` bits (at most the number the last peek made valid).
    #[inline(always)]
    pub(crate) fn skip(&mut self, n: u32) {
        self.bits <<= n;
        self.count -= n;
    }

    /// Reads `n` bits (1..=16).
    #[inline(always)]
    pub(crate) fn read(&mut self, n: u32) -> Result<u32> {
        let value = self.peek(n)?;
        self.skip(n);
        Ok(value)
    }
}

/// Where the encoder's bits go.
pub(crate) trait BitSink {
    /// Appends the low `count` bits of `value` (count 0..=32), most
    /// significant first.
    fn write_bits(&mut self, value: u32, count: u32);
}

/// Collects bits into bytes; the final partial byte is zero-padded.
#[derive(Default)]
pub(crate) struct BitWriter {
    out: Vec<u8>,
    pending: u64,
    pending_bits: u32,
}

impl BitWriter {
    pub(crate) fn finish(mut self) -> Vec<u8> {
        if self.pending_bits > 0 {
            self.out
                .push((self.pending << (8 - self.pending_bits)) as u8);
        }
        self.out
    }
}

impl BitSink for BitWriter {
    #[inline]
    fn write_bits(&mut self, value: u32, count: u32) {
        if count == 0 {
            return;
        }
        let masked = u64::from(value) & ((1u64 << count) - 1);
        self.pending = (self.pending << count) | masked;
        self.pending_bits += count;
        while self.pending_bits >= 8 {
            self.pending_bits -= 8;
            self.out.push((self.pending >> self.pending_bits) as u8);
        }
        self.pending &= (1u64 << self.pending_bits) - 1;
    }
}

/// Counts bits and stores nothing: an item written here costs what it would
/// cost in the real stream.
#[derive(Default)]
pub(crate) struct BitCounter {
    pub(crate) bits: u64,
}

impl BitSink for BitCounter {
    #[inline]
    fn write_bits(&mut self, _value: u32, count: u32) {
        self.bits += u64::from(count);
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    /// Returns bytes one to three at a time.
    struct Dribble<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Dribble<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.step = self.step % 3 + 1;
            let len = self.data.len().min(out.len()).min(self.step);
            out[..len].copy_from_slice(&self.data[..len]);
            self.data = &self.data[len..];
            Ok(len)
        }
    }

    fn reference_bit(data: &[u8], position: usize) -> u32 {
        data.get(position / 8)
            .map_or(0, |byte| u32::from(byte >> (7 - position % 8)) & 1)
    }

    fn reference(data: &[u8], position: usize, n: u32) -> u32 {
        (0..n as usize).fold(0, |value, offset| {
            value << 1 | reference_bit(data, position + offset)
        })
    }

    #[test]
    fn slice_and_reader_sources_match_a_bitwise_reference_past_the_end() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 151 + 7) as u8).collect();
        let widths = [1u32, 7, 12, 16, 5, 3, 15, 2, 9, 16, 16, 8];
        let mut slice = BitReader::new(SliceSource::new(&data));
        let mut dribble = Dribble {
            data: &data,
            step: 0,
        };
        let mut reader = BitReader::new(ReaderSource::new(&mut dribble));
        let mut position = 0usize;
        for round in 0..600 {
            let n = widths[round % widths.len()];
            let expected = reference(&data, position, n);
            assert_eq!(slice.peek(n).unwrap(), expected, "slice peek at {position}");
            assert_eq!(reader.read(n).unwrap(), expected, "reader at {position}");
            slice.skip(n);
            position += n as usize;
        }
        assert!(position > data.len() * 8, "the walk reaches past the end");
    }

    #[test]
    fn writer_pads_the_last_byte_with_zero_bits() {
        let mut writer = BitWriter::default();
        writer.write_bits(0b101, 3);
        writer.write_bits(0xabcd, 16);
        writer.write_bits(1, 1);
        writer.write_bits(0, 0);
        // 101 1010101111001101 1, then four zero bits of padding.
        assert_eq!(writer.finish(), vec![0b1011_0101, 0b0111_1001, 0b1011_0000]);
        let mut counter = BitCounter::default();
        counter.write_bits(0, 12);
        counter.write_bits(3, 2);
        assert_eq!(counter.bits, 14);
    }

    #[test]
    fn a_failing_reader_is_invalid_data() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("broken"))
            }
        }
        let mut broken = Broken;
        let mut reader = BitReader::new(ReaderSource::new(&mut broken));
        assert!(matches!(reader.peek(4), Err(Error::InvalidData(_))));
    }
}
