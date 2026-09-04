use alloc::vec::Vec;

use super::{
    Read,
    decoder::LzmaDecoder,
    error_eof, error_invalid_data, error_invalid_input, error_out_of_memory, error_unsupported,
    lz::LzDecoder,
    range_dec::{RangeDecoder, RangeDecoderBuffer},
};
use crate::{
    ByteReader, DICT_SIZE_MIN,
    filter::{FilterConfig, StreamFilter},
    lzma_reader::{InputEnd, Limits, LzmaCore, RC_INIT_SIZE},
    stream::{Action, Status, StreamResult},
};

pub const COMPRESSED_SIZE_MAX: u32 = 1 << 16;

/// How much one drain out of the dictionary moves at most.
const DRAIN_SIZE_MAX: usize = 4096;

/// A single-threaded LZMA2 decompressor.
///
/// # Examples
/// ```
/// use std::io::Read;
///
/// use lzma_rust2::{Lzma2Reader, LzmaOptions};
///
/// let compressed: Vec<u8> = vec![
///     1, 0, 12, 72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 0,
/// ];
/// let mut reader = Lzma2Reader::new(compressed.as_slice(), LzmaOptions::DICT_SIZE_DEFAULT, None);
/// let mut decompressed = Vec::new();
/// reader.read_to_end(&mut decompressed).unwrap();
/// assert_eq!(&decompressed[..], b"Hello, world!");
/// ```
pub struct Lzma2Reader<R> {
    inner: R,
    lz: LzDecoder,
    rc: RangeDecoder<RangeDecoderBuffer>,
    lzma: Option<LzmaDecoder>,
    uncompressed_size: usize,
    is_lzma_chunk: bool,
    need_dict_reset: bool,
    need_props: bool,
    end_reached: bool,
}

/// Calculates the memory usage in KiB required for LZMA2 decompression.
#[inline]
pub fn get_memory_usage(dict_size: u32) -> u32 {
    40 + COMPRESSED_SIZE_MAX / 1024 + get_dict_size(dict_size) / 1024
}

/// Calculates the memory usage in KiB required by [`Lzma2Stream`].
///
/// Unlike [`get_memory_usage`] this leaves out the range decoder buffer, which
/// the sans-I/O decoder does not have: it decodes straight out of the caller's
/// input.
#[inline]
pub(crate) fn get_stream_memory_usage(dict_size: u32) -> u32 {
    40 + get_dict_size(dict_size.max(DICT_SIZE_MIN)) / 1024
}

#[inline]
fn get_dict_size(dict_size: u32) -> u32 {
    if dict_size >= (u32::MAX - 15) {
        return u32::MAX;
    }

    (dict_size + 15) & !15
}

fn decode_lzma2_props(props: u8) -> crate::Result<LzmaDecoder> {
    if props > (4 * 5 + 4) * 9 + 8 {
        return Err(error_invalid_input("corrupted input data (LZMA2:3)"));
    }
    let pb = props / (9 * 5);
    let remainder = props - pb * 9 * 5;
    let lp = remainder / 9;
    let lc = remainder - lp * 9;
    if lc + lp > 4 {
        return Err(error_invalid_input("corrupted input data (LZMA2:4)"));
    }
    Ok(LzmaDecoder::new(lc as _, lp as _, pb as _))
}

impl<R> Lzma2Reader<R> {
    /// Unwraps the reader, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Returns a reference to the inner reader.
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the inner reader.
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read> Lzma2Reader<R> {
    /// Create a new LZMA2 reader.
    /// `inner` is the reader to read compressed data from.
    /// `dict_size` is the dictionary size in bytes.
    pub fn new(inner: R, dict_size: u32, preset_dict: Option<&[u8]>) -> Self {
        let has_preset = preset_dict.as_ref().map(|a| !a.is_empty()).unwrap_or(false);
        let lz = LzDecoder::new(get_dict_size(dict_size) as _, preset_dict);
        let rc = RangeDecoder::new_buffer(COMPRESSED_SIZE_MAX as _);
        Self {
            inner,
            lz,
            rc,
            lzma: None,
            uncompressed_size: 0,
            is_lzma_chunk: false,
            need_dict_reset: !has_preset,
            need_props: true,
            end_reached: false,
        }
    }

    // ### LZMA2 Control Byte Meaning
    //
    //  Control Byte    | Chunk Type      | Formal Action
    //  --------------- | --------------- | ----------------------------
    //  0x00            | End of Stream   | Terminates the LZMA2 stream.
    //  0x01            | Uncompressed    | Resets Dictionary.
    //  0x02            | Uncompressed    | Preserves Dictionary.
    //  0x03 – 0x7F     | Reserved        | Invalid stream.
    //  0x80 – 0xFF     | LZMA Compressed | Varies based on bits 6 and 5
    //
    // ### Detailed Breakdown of LZMA Compressed Chunks (0x80 - 0xFF)
    //
    //  Bits | Control Byte | Reset Action            | Suitable for Parallel Start? |
    //  ---- | ------------ | ----------------------- | ---------------------------- |
    //  00   | 0x80 – 0x9F  | None                    | No
    //  01   | 0xA0 – 0xBF  | Reset State             | No
    //  10   | 0xC0 – 0xDF  | Reset State & Props     | No
    //  11   | 0xE0 – 0xFF  | Reset Everything        | Yes
    fn decode_chunk_header(&mut self) -> crate::Result<()> {
        let control = self.inner.read_u8()?;

        if control == 0x00 {
            self.end_reached = true;
            return Ok(());
        }

        if control >= 0xE0 || control == 0x01 {
            self.need_props = true;
            self.need_dict_reset = false;
            // Reset dictionary
            self.lz.reset();
        } else if self.need_dict_reset {
            return Err(error_invalid_input("corrupted input data (LZMA2:0)"));
        }
        if control >= 0x80 {
            self.is_lzma_chunk = true;
            self.uncompressed_size = ((control & 0x1F) as usize) << 16;
            self.uncompressed_size += self.inner.read_u16_be()? as usize + 1;
            let compressed_size = self.inner.read_u16_be()? as usize + 1;

            if control >= 0xC0 {
                // Reset props and state (by re-creating it)
                self.need_props = false;
                self.decode_props()?;
            } else if self.need_props {
                return Err(error_invalid_input("corrupted input data (LZMA2:1)"));
            } else if control >= 0xA0 {
                // Reset state
                if let Some(l) = self.lzma.as_mut() {
                    l.reset()
                }
            }

            self.rc.prepare(&mut self.inner, compressed_size)?;
        } else if control > 0x02 {
            return Err(error_invalid_input("corrupted input data (LZMA2:2)"));
        } else {
            self.is_lzma_chunk = false;
            self.uncompressed_size = (self.inner.read_u16_be()? as usize) + 1;
        }
        Ok(())
    }

    fn decode_props(&mut self) -> crate::Result<()> {
        let props = self.inner.read_u8()?;
        self.lzma = Some(decode_lzma2_props(props)?);
        Ok(())
    }
}

impl<R: Read> Read for Lzma2Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.end_reached {
            return Ok(0);
        }

        self.lz.ensure_capacity()?;

        let mut size = 0;
        let mut len = buf.len();
        let mut off = 0;
        while len > 0 {
            if self.uncompressed_size == 0 {
                self.decode_chunk_header()?;
                if self.end_reached {
                    return Ok(size);
                }
            }

            let copy_size_max = self.uncompressed_size.min(len);
            if !self.is_lzma_chunk {
                self.lz.copy_uncompressed(&mut self.inner, copy_size_max)?;
            } else {
                self.lz.set_limit(copy_size_max);
                if let Some(lzma) = self.lzma.as_mut() {
                    lzma.decode(&mut self.lz, &mut self.rc)?;
                }
            }

            {
                let copied_size = self.lz.flush(buf, off)?;
                off = off.saturating_add(copied_size);
                len = len.saturating_sub(copied_size);
                size = size.saturating_add(copied_size);
                self.uncompressed_size = self.uncompressed_size.saturating_sub(copied_size);
                if self.uncompressed_size == 0 && (!self.rc.is_finished() || self.lz.has_pending())
                {
                    return Err(error_invalid_input("rc not finished or lz has pending"));
                }
            }
        }

        Ok(size)
    }
}

#[derive(Clone, Copy)]
enum Lzma2State {
    ChunkHeader,
    RcInit,
    CompressedData,
    UncompressedData { remaining: usize },
    DrainUncompressed { remaining: usize },
    DrainCompressed,
    DrainOutput,
    Finished,
}

/// Sans-I/O LZMA2 stream decoder.
///
/// Decodes a raw LZMA2 byte stream (no XZ container). Call `process()` repeatedly
/// with input/output buffers until `Status::StreamEnd` is returned.
pub struct Lzma2Stream {
    state: Lzma2State,
    accum: Vec<u8>,
    accum_needed: usize,
    lz: LzDecoder,
    lzma: Option<LzmaDecoder>,
    /// Decodes straight out of the caller's slice, one chunk at a time.
    core: LzmaCore,
    /// The current chunk's uncompressed and compressed budgets.
    limits: Limits,
    need_dict_reset: bool,
    need_props: bool,
    /// The pre-filter the decoded output runs through, if one was set.
    filter: Option<StreamFilter>,
    /// Decoded bytes waiting for the filter and the caller. Stays empty, and so
    /// unallocated, as long as no filter is set.
    filter_buf: Vec<u8>,
    /// How much of `filter_buf` the caller has been handed already.
    filter_pos: usize,
    /// Memory usage limit in KiB. `u32::MAX` means no limit.
    mem_limit_kb: u32,
    /// What the dictionary this stream was built for needs, in KiB.
    mem_need_kb: u32,
    /// Set once `process()` has returned an error. A failed stream stays failed.
    failed: bool,
    total_in: u64,
    total_out: u64,
}

impl Lzma2Stream {
    /// Create a new LZMA2 stream decoder with the given dictionary size.
    pub fn new(dict_size: u32) -> Self {
        let mem_need_kb = get_stream_memory_usage(dict_size);
        let dict_size = get_dict_size(dict_size.max(DICT_SIZE_MIN)) as usize;
        Self {
            state: Lzma2State::ChunkHeader,
            accum: Vec::with_capacity(8),
            accum_needed: 1,
            lz: LzDecoder::new(dict_size, None),
            lzma: None,
            core: LzmaCore::new(),
            limits: Limits {
                remaining_size: 0,
                compressed_left: Some(0),
                // Every LZMA2 chunk is sized, so an end of payload marker in one
                // is corruption.
                allow_end_marker: false,
                end_reached: false,
            },
            need_dict_reset: true,
            need_props: true,
            filter: None,
            filter_buf: Vec::new(),
            filter_pos: 0,
            mem_limit_kb: u32::MAX,
            mem_need_kb,
            failed: false,
            total_in: 0,
            total_out: 0,
        }
    }

    /// Create a new LZMA2 stream decoder with the given dictionary size and a
    /// memory usage limit.
    /// - `mem_limit_kb` - memory usage limit in kibibytes (KiB). `u32::MAX` means no limit.
    ///
    /// The dictionary is allocated on the first [`process()`] call, so a limit
    /// violation surfaces from there rather than here.
    ///
    /// [`process()`]: Lzma2Stream::process
    pub fn new_mem_limit(dict_size: u32, mem_limit_kb: u32) -> Self {
        Self {
            mem_limit_kb,
            ..Self::new(dict_size)
        }
    }

    /// Decode through a pre-filter, such as a BCJ or delta filter.
    ///
    /// At most one filter is supported. [`FilterType::Lzma2`] is not a
    /// pre-filter and is rejected, as this type is itself the LZMA2 stage. An
    /// empty slice leaves the stream unfiltered.
    ///
    /// Must be called before decoding starts.
    ///
    /// [`FilterType::Lzma2`]: crate::FilterType::Lzma2
    pub fn set_filters(&mut self, filters: &[FilterConfig]) -> crate::Result<()> {
        if self.total_in != 0 {
            return Err(error_invalid_input("filters set after decoding started"));
        }
        if filters.len() > 1 {
            return Err(error_unsupported("only one filter is supported"));
        }
        let Some(config) = filters.first() else {
            self.filter = None;
            return Ok(());
        };
        self.filter = Some(StreamFilter::new(config)?);
        Ok(())
    }

    /// Total bytes consumed from input across all `process()` calls.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// Total bytes produced to output across all `process()` calls.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// Returns true if the LZMA2 stream has been fully decoded.
    pub fn is_finished(&self) -> bool {
        matches!(self.state, Lzma2State::Finished)
    }

    /// Returns true if there is decoded output waiting to be flushed.
    pub fn has_output(&self) -> bool {
        self.lz.has_output() || self.filter_pos < self.settled_end()
    }

    /// Process available LZMA2 data from `input` into `output`.
    pub fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
    ) -> crate::Result<StreamResult> {
        if self.failed {
            return Err(error_invalid_data("LZMA2 stream already failed"));
        }

        let result = self.process_inner(input, output, action);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn process_inner(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
    ) -> crate::Result<StreamResult> {
        // The dictionary is allocated here rather than in the constructor, so
        // this is where a limit violation surfaces.
        if self.mem_limit_kb < self.mem_need_kb {
            return Err(error_out_of_memory(
                "needed memory too big for mem_limit_kb",
            ));
        }

        self.lz.ensure_capacity()?;

        let mut in_pos = 0;
        let mut out_pos = 0;
        // Set when a decode pass could make no progress at all. Without this
        // the loop spins forever on an empty input or a full output buffer.
        let mut stalled = false;

        loop {
            // Whatever the state, settled bytes in the staging buffer go out
            // first. They are already decoded and filtered, so holding them
            // back would look like a stall to the caller.
            if self.filter_pos < self.settled_end() && out_pos < output.len() {
                self.emit_filtered(output, &mut out_pos);
                continue;
            }

            match self.state {
                Lzma2State::Finished => {
                    // Nothing follows the last chunk, so the tail the filter
                    // held back is settled now and still has to be handed over.
                    self.finish_filter();
                    if self.filter_pos < self.settled_end() {
                        if out_pos >= output.len() {
                            return Ok(StreamResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: Status::Ok,
                            });
                        }
                        continue;
                    }
                    return Ok(StreamResult {
                        bytes_consumed: in_pos,
                        bytes_produced: out_pos,
                        status: Status::StreamEnd,
                    });
                }

                Lzma2State::DrainOutput
                | Lzma2State::DrainCompressed
                | Lzma2State::DrainUncompressed { .. } => {
                    if out_pos >= output.len() {
                        return Ok(StreamResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Status::Ok,
                        });
                    }
                    if self.filter.is_some() {
                        self.drain_and_filter();
                    } else if !self.flush_output(output, &mut out_pos) {
                        return Ok(StreamResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Status::Ok,
                        });
                    }
                }

                Lzma2State::CompressedData => {
                    if let Some(result) = self.process_compressed_data(
                        input,
                        action,
                        &mut in_pos,
                        out_pos,
                        &mut stalled,
                    )? {
                        return Ok(result);
                    }
                }

                Lzma2State::UncompressedData { remaining } => {
                    if let Some(result) = self.process_uncompressed_data(
                        input,
                        action,
                        &mut in_pos,
                        out_pos,
                        remaining,
                    )? {
                        return Ok(result);
                    }
                }

                Lzma2State::ChunkHeader => {
                    if let Some(result) = self.accumulate(input, action, &mut in_pos, out_pos)? {
                        return Ok(result);
                    }
                    self.process_chunk_header()?;
                }

                Lzma2State::RcInit => {
                    if let Some(result) = self.accumulate(input, action, &mut in_pos, out_pos)? {
                        return Ok(result);
                    }
                    self.init_range_coder()?;
                }
            }
        }
    }

    fn flush_output(&mut self, output: &mut [u8], out_pos: &mut usize) -> bool {
        let n = self.lz.flush_partial(&mut output[*out_pos..]);
        if n > 0 {
            *out_pos += n;
            self.total_out += n as u64;
        }
        if self.lz.has_output() {
            return false;
        }
        self.finish_drain();
        true
    }

    /// Where the settled bytes of the staging buffer end.
    ///
    /// A BCJ filter can not classify the last bytes of what it was given before
    /// it knows what follows them, so those stay behind until the next drain or
    /// the end of the stream.
    fn settled_end(&self) -> usize {
        self.filter_buf.len() - self.filter_held_back()
    }

    fn filter_held_back(&self) -> usize {
        self.filter.as_ref().map_or(0, |filter| filter.held_back())
    }

    fn finish_filter(&mut self) {
        if let Some(filter) = self.filter.as_mut() {
            filter.finish();
        }
    }

    /// Decodes into the staging buffer and runs the filter over what arrived.
    ///
    /// The bytes are counted as produced once they reach the caller in
    /// [`Self::emit_filtered`], not here.
    fn drain_and_filter(&mut self) {
        let filter_start = self.settled_end();
        let drained = Self::flush_to_buf(&mut self.lz, &mut self.filter_buf, DRAIN_SIZE_MAX);
        if drained > 0 {
            // The held back tail was never filtered, so it goes through again
            // together with what now follows it.
            let unfiltered = &mut self.filter_buf[filter_start..];
            if let Some(filter) = self.filter.as_mut() {
                filter.decode(unfiltered);
            }
        }
        if !self.lz.has_output() {
            self.finish_drain();
        }
    }

    /// Hands the settled bytes of the staging buffer to the caller.
    fn emit_filtered(&mut self, output: &mut [u8], out_pos: &mut usize) {
        let settled_end = self.settled_end();
        let n = (settled_end - self.filter_pos).min(output.len() - *out_pos);
        output[*out_pos..*out_pos + n]
            .copy_from_slice(&self.filter_buf[self.filter_pos..self.filter_pos + n]);
        *out_pos += n;
        self.total_out += n as u64;
        self.filter_pos += n;

        if self.filter_pos == settled_end {
            self.compact_filter_buf();
        }
    }

    /// Drops what the caller has taken, keeping the held back tail.
    fn compact_filter_buf(&mut self) {
        let held_back = self.filter_held_back();
        let tail_start = self.filter_buf.len() - held_back;
        if tail_start > 0 {
            self.filter_buf.copy_within(tail_start.., 0);
            self.filter_buf.truncate(held_back);
        }
        self.filter_pos = 0;
    }

    /// Moves decoded bytes into `buf`, up to `limit` of them. The caller decides
    /// whether they count towards `total_out`.
    fn flush_to_buf(lz: &mut LzDecoder, buf: &mut Vec<u8>, limit: usize) -> usize {
        let mut tmp = [0u8; DRAIN_SIZE_MAX];
        let cap = limit.min(tmp.len());
        let n = lz.flush_partial(&mut tmp[..cap]);
        if n > 0 {
            buf.extend_from_slice(&tmp[..n]);
        }
        n
    }

    /// Decodes what the caller handed us of the current chunk, in place.
    fn process_compressed_data(
        &mut self,
        input: &[u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: usize,
        stalled: &mut bool,
    ) -> crate::Result<Option<StreamResult>> {
        let compressed_left = self.limits.compressed_left.unwrap_or(0);

        // Nothing left to feed and the chunk is not over yet. A chunk whose
        // compressed size is used up still has to be finished off below, which
        // takes no input at all.
        if *in_pos >= input.len() && compressed_left > 0 {
            if action == Action::Finish {
                return Err(error_eof("unexpected end of LZMA2 stream"));
            }
            return Ok(Some(StreamResult {
                bytes_consumed: *in_pos,
                bytes_produced: out_pos,
                status: Status::Ok,
            }));
        }

        if *stalled {
            return Ok(Some(StreamResult {
                bytes_consumed: *in_pos,
                bytes_produced: out_pos,
                status: Status::Ok,
            }));
        }

        if self.lz.available_space() == 0 {
            self.state = Lzma2State::DrainCompressed;
            return Ok(None);
        }

        let available = &input[*in_pos..];
        // The chunk header says where the payload ends, so the core can be told
        // without the caller having to say `Action::Finish`. A symbol that then
        // runs past that end is corrupt data in a stream that arrived whole,
        // not a stream that was cut short.
        let input_end = if compressed_left <= available.len() as u64 {
            InputEnd::Length
        } else {
            InputEnd::More
        };

        let (consumed, produced) = {
            let Self {
                lz,
                lzma,
                core,
                limits,
                ..
            } = self;
            let lzma = lzma
                .as_mut()
                .ok_or_else(|| error_invalid_input("corrupted input data (LZMA2:1)"))?;
            core.feed(lz, lzma, available, limits, input_end)?
        };

        *in_pos += consumed;
        self.total_in += consumed as u64;

        if consumed == 0 && produced == 0 && !self.limits.end_reached {
            *stalled = true;
        }

        if self.limits.end_reached {
            // The chunk produced everything it declared, so its compressed size
            // must be used up and the range coder must have ended on zero.
            //
            // A used up budget is not enough on its own: the budget counts bytes
            // taken in, and the last few of those may still be sitting in the
            // carry unread. The buffered decoder compared the range coder's read
            // position against the chunk length, so it rejected a chunk that
            // declared more bytes than any symbol reached. Checking the carry is
            // empty is how that is said here.
            if self.limits.compressed_left != Some(0)
                || !self.core.unused_input().is_empty()
                || !self.core.rc_finished()
                || self.lz.has_pending()
            {
                return Err(error_invalid_input("rc not finished or lz has pending"));
            }
            self.state = Lzma2State::DrainOutput;
        } else {
            self.state = Lzma2State::DrainCompressed;
        }

        Ok(None)
    }

    fn process_uncompressed_data(
        &mut self,
        input: &[u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: usize,
        remaining: usize,
    ) -> crate::Result<Option<StreamResult>> {
        let lz_space = self.lz.available_space();
        if lz_space == 0 {
            self.state = Lzma2State::DrainUncompressed { remaining };
            return Ok(None);
        }
        if *in_pos >= input.len() {
            if action == Action::Finish {
                return Err(error_eof("unexpected end of LZMA2 stream"));
            }
            return Ok(Some(StreamResult {
                bytes_consumed: *in_pos,
                bytes_produced: out_pos,
                status: Status::Ok,
            }));
        }
        let available = &input[*in_pos..];
        let to_copy = remaining.min(available.len()).min(lz_space);
        self.lz
            .copy_uncompressed_from_slice(&available[..to_copy])?;
        *in_pos += to_copy;
        self.total_in += to_copy as u64;
        let new_remaining = remaining - to_copy;
        if new_remaining == 0 {
            self.state = Lzma2State::DrainOutput;
        } else if self.lz.available_space() == 0 {
            self.state = Lzma2State::DrainUncompressed {
                remaining: new_remaining,
            };
        } else {
            self.state = Lzma2State::UncompressedData {
                remaining: new_remaining,
            };
        }
        Ok(None)
    }

    /// Fills `accum` up to `accum_needed` bytes, returning a result to hand back
    /// to the caller when the input ran dry first.
    fn accumulate(
        &mut self,
        input: &[u8],
        action: Action,
        in_pos: &mut usize,
        out_pos: usize,
    ) -> crate::Result<Option<StreamResult>> {
        while self.accum.len() < self.accum_needed {
            if *in_pos >= input.len() {
                if action == Action::Finish {
                    return Err(error_eof("unexpected end of LZMA2 stream"));
                }
                return Ok(Some(StreamResult {
                    bytes_consumed: *in_pos,
                    bytes_produced: out_pos,
                    status: Status::Ok,
                }));
            }
            let need = self.accum_needed - self.accum.len();
            let to_copy = need.min(input.len() - *in_pos);
            self.accum
                .extend_from_slice(&input[*in_pos..*in_pos + to_copy]);
            *in_pos += to_copy;
            self.total_in += to_copy as u64;
        }
        Ok(None)
    }

    pub(crate) fn is_draining(&self) -> bool {
        matches!(
            self.state,
            Lzma2State::DrainOutput
                | Lzma2State::DrainCompressed
                | Lzma2State::DrainUncompressed { .. }
        )
    }

    pub(crate) fn drain_with_filter(&mut self, output: &mut [u8], out_pos: &mut usize) -> usize {
        if *out_pos >= output.len() {
            return 0;
        }
        let n = self.lz.flush_partial(&mut output[*out_pos..]);
        if n > 0 {
            *out_pos += n;
            self.total_out += n as u64;
        }
        if !self.lz.has_output() {
            self.finish_drain();
        }
        n
    }

    pub(crate) fn drain_to_buf(&mut self, buf: &mut Vec<u8>, limit: usize) -> usize {
        let n = Self::flush_to_buf(&mut self.lz, buf, limit);
        self.total_out += n as u64;
        if !self.lz.has_output() {
            self.finish_drain();
        }
        n
    }

    fn finish_drain(&mut self) {
        match self.state {
            Lzma2State::DrainUncompressed { remaining } => {
                self.state = Lzma2State::UncompressedData { remaining };
            }
            Lzma2State::DrainCompressed => {
                self.state = Lzma2State::CompressedData;
            }
            _ => {
                self.state = Lzma2State::ChunkHeader;
                self.accum.clear();
                self.accum_needed = 1;
            }
        }
    }

    fn process_chunk_header(&mut self) -> crate::Result<()> {
        let control = self.accum[0];
        if control == 0x00 {
            self.state = Lzma2State::Finished;
            Ok(())
        } else if control >= 0x80 {
            self.process_compressed_chunk_header(control)
        } else if control <= 0x02 {
            self.process_uncompressed_chunk_header(control)
        } else {
            Err(error_invalid_input("corrupted input data (LZMA2:2)"))
        }
    }

    fn process_compressed_chunk_header(&mut self, control: u8) -> crate::Result<()> {
        let needed = if control >= 0xC0 { 6 } else { 5 };
        if self.accum.len() < needed {
            self.accum_needed = needed;
            return Ok(());
        }

        if control >= 0xE0 {
            self.need_props = true;
            self.need_dict_reset = false;
            self.lz.reset();
        } else if self.need_dict_reset {
            return Err(error_invalid_input("corrupted input data (LZMA2:0)"));
        }

        let mut uncompressed_size = ((control & 0x1F) as usize) << 16;
        let uncompressed_hi = u16::from_be_bytes([self.accum[1], self.accum[2]]);
        uncompressed_size += uncompressed_hi as usize + 1;
        let compressed_size = u16::from_be_bytes([self.accum[3], self.accum[4]]) as usize + 1;

        if control >= 0xC0 {
            self.need_props = false;
            self.lzma = Some(decode_lzma2_props(self.accum[5])?);
        } else if self.need_props {
            return Err(error_invalid_input("corrupted input data (LZMA2:1)"));
        } else if control >= 0xA0 {
            if let Some(l) = self.lzma.as_mut() {
                l.reset();
            }
        }

        // The five range coder init bytes count towards the compressed size.
        if compressed_size < RC_INIT_SIZE {
            return Err(error_invalid_input("corrupted input data (LZMA2:5)"));
        }

        // The dictionary and the probability model carry over from the last
        // chunk, but the range coder starts again.
        self.core.reset();
        self.limits.remaining_size = uncompressed_size as u64;
        self.limits.compressed_left = Some((compressed_size - RC_INIT_SIZE) as u64);
        self.limits.end_reached = false;

        self.state = Lzma2State::RcInit;
        self.accum.clear();
        self.accum_needed = RC_INIT_SIZE;
        Ok(())
    }

    fn init_range_coder(&mut self) -> crate::Result<()> {
        let bytes: [u8; RC_INIT_SIZE] = self.accum[..]
            .try_into()
            .map_err(|_| error_invalid_input("corrupted input data (LZMA2:3)"))?;
        self.core.init_rc(&bytes)?;
        self.accum.clear();
        self.accum_needed = 0;
        self.state = Lzma2State::CompressedData;
        Ok(())
    }

    fn process_uncompressed_chunk_header(&mut self, control: u8) -> crate::Result<()> {
        if self.accum.len() < 3 {
            self.accum_needed = 3;
            return Ok(());
        }

        if control == 0x01 {
            self.need_props = true;
            self.need_dict_reset = false;
            self.lz.reset();
        } else if self.need_dict_reset {
            return Err(error_invalid_input("corrupted input data (LZMA2:0)"));
        }

        let uncompressed_size = u16::from_be_bytes([self.accum[1], self.accum[2]]) as usize + 1;

        self.state = Lzma2State::UncompressedData {
            remaining: uncompressed_size,
        };
        self.accum.clear();
        Ok(())
    }
}
