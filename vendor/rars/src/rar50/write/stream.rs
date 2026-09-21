//! RAR 5 archives written from `Read` sources into `Write` sinks with
//! bounded memory - the same bytes the in-memory writers produce, without
//! holding the member or the archive: stored members, encrypted members,
//! and (see the compressed section below) compressed members encoded a
//! segment at a time.
//!
//! Every RAR 5 writer in this crate takes its members as slices and hands
//! back the archive as a `Vec<u8>` (a `Vec` per volume), so a caller with a
//! file to archive reads it whole and then holds the archive whole beside
//! it: a 1 GiB stored member is two gigabytes of fresh pages before a byte
//! reaches the disk or the wire. On an 8-vCPU KVM guest, where every fresh
//! page is an EPT fault on top of the host's, that is 3.5 s for a store that
//! `rar` finishes in 1.3 s through a 30 MB working set (the 5 Sep 2026
//! public-position bench, and every measurement of the writer on that box
//! since). This module is the first cut at the writer `rar` has: a member is
//! copied from its source to the sink a megabyte at a time, headers are
//! built with the same functions the in-memory writers use, and nothing is
//! held.
//!
//! A file header carries its member's CRC32, and precedes the data, so a
//! sink that cannot seek needs the CRC before the copy starts: the caller
//! supplies it, and [`crc32_of_reader`] is the pre-pass that computes it
//! (a second read of the file, which the page cache makes cheap where the
//! two gigabytes of fresh pages were not).
//!
//! Stored members, plain or ENCRYPTED (the member data, and the headers
//! too when the feature says so): an encrypted member is enciphered a
//! megabyte at a time through the same chained AES-CBC the in-memory
//! writer uses, its salt and IV drawn in the same order, so the bytes
//! match under seeded entropy. COMPRESSED members are encoded from
//! windows of their source through the block pool (the notes at the
//! compressed section below say what is held and what is not). The
//! BLAKE2sp hash record, recovery records, solid sets, comments,
//! quick-open and encrypted compressed members are refused by name
//! rather than approximated. The output is byte-identical to
//! [`super::Rar50Writer`] / [`super::Rar50VolumeWriter`] for the same
//! members, and tests hold it there. (nzbfast-local addition, 6 Sep
//! 2026; see VENDORING.md.)

use std::io::{Read, Seek, SeekFrom, Write};

use super::filter_policy::{
    compression_info, compression_method_for_level, encode_options_for_level,
    incompressible_sample_windows, rar50_algorithm_version, samples_read_incompressible,
    working_memory_for,
};
use super::volume::{volume_head_len, write_volume_end, write_volume_head};
use crate::recovery::rar5::InlineRecoveryFolder;
use super::*;
use crate::codec::rar50::{
    encode_lz_member_pooled, encode_lz_member_window, encode_lz_member_with_options,
    member_window_blocks, member_window_segment_blocks, EncodeOptions, EncoderScratchPool,
    MAX_COMPRESSED_BLOCK_OUTPUT,
};

/// A stored member read from `source`: `size` bytes, whose CRC32 the
/// caller has computed (see [`crc32_of_reader`]).
pub struct StreamedStoredEntry<'a, R: Read> {
    pub name: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
    pub size: u64,
    pub crc32: u32,
    pub source: R,
}

/// The copy buffer: a megabyte, so the working set is that and the headers.
const STREAM_COPY_BYTES: usize = 1 << 20;

/// Read `source` to its end: its length and CRC32, for a header that
/// precedes the data it describes.
pub fn crc32_of_reader<R: Read>(source: &mut R) -> std::io::Result<(u64, u32)> {
    let mut buffer = vec![0u8; STREAM_COPY_BYTES];
    let mut hasher = crc32fast::Hasher::new();
    let mut total = 0u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total += read as u64;
    }
    Ok((total, hasher.finalize()))
}

/// The options every streamed writer accepts: `base` is the in-memory
/// writer's own check for the kind of archive (stored, encrypted,
/// compressed), and the features no streamed writer builds are refused
/// by name after it.
fn validate_streamed_options(
    options: WriterOptions,
    base: fn(WriterOptions) -> Result<()>,
) -> Result<()> {
    validate_streamed_options_allowing(options, base, false)
}

/// [`validate_streamed_options`] with the recovery record allowed when
/// `allow_recovery` (the stored writers compute it as the bytes pass).
fn validate_streamed_options_allowing(
    options: WriterOptions,
    base: fn(WriterOptions) -> Result<()>,
    allow_recovery: bool,
) -> Result<()> {
    base(options)?;
    let features = options.features;
    let refused = [
        (
            features.recovery_record && !allow_recovery,
            "RAR 5 streamed recovery records",
        ),
        (features.solid, "RAR 5 streamed solid sets"),
        (features.archive_comment, "RAR 5 streamed archive comments"),
        (features.quick_open, "RAR 5 streamed quick-open"),
        (
            options.hash_record == HashRecord::Blake2sp,
            "RAR 5 streamed BLAKE2sp hash records",
        ),
    ];
    for (on, feature) in refused {
        if on {
            return Err(Error::UnsupportedFeature {
                version: options.target,
                feature,
            });
        }
    }
    Ok(())
}

/// The file header of one fragment of a stored member, as the in-memory
/// writers build it (`write_stored_entry_fragment` with the CRC on the last
/// fragment only, the split flags on the others).
fn streamed_fragment_header<R: Read>(
    entry: &StreamedStoredEntry<'_, R>,
    fragment_len: u64,
    split_before: bool,
    split_after: bool,
) -> Result<Vec<u8>> {
    let (specific, time_extra) = stored_file_specific(
        entry.name,
        entry.size,
        (!split_after).then_some(entry.crc32),
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    let mut block_flags = BLOCK_HAS_DATA_AREA;
    if split_before {
        block_flags |= BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME;
    }
    if split_after {
        block_flags |= BLOCK_CONTINUES_IN_NEXT_VOLUME;
    }
    if !time_extra.is_empty() {
        block_flags |= BLOCK_HAS_EXTRA_AREA;
    }
    block_header_image(
        BLOCK_TYPE_FILE,
        block_flags,
        Some(fragment_len),
        &specific,
        &time_extra,
    )
}

/// Copy exactly `len` bytes from `source` to `sink`.
fn copy_exact<R: Read + ?Sized, W: Write + ?Sized>(
    source: &mut R,
    sink: &mut W,
    len: u64,
    buffer: &mut [u8],
) -> Result<()> {
    let mut left = len;
    while left > 0 {
        let want = buffer
            .len()
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        let read = source.read(&mut buffer[..want])?;
        if read == 0 {
            return Err(Error::InvalidHeader(
                "RAR 5 streamed member ended before its declared size",
            ));
        }
        sink.write_all(&buffer[..read])?;
        left -= read as u64;
    }
    Ok(())
}

/// One archive holding `entries`, stored, written to `sink`; returns the
/// bytes written. Byte-identical to `Rar50Writer::stored_entries` over the
/// same members.
pub fn write_stored_archive_streamed<R: Read, W: Write>(
    options: WriterOptions,
    entries: &mut [StreamedStoredEntry<'_, R>],
    sink: &mut W,
) -> Result<u64> {
    write_stored_archive_streamed_with_recovery(options, None, entries, sink)
}

/// [`write_stored_archive_streamed`] with a RECOVERY RECORD of
/// `recovery_percent` when the options ask for one: the record is
/// computed from the bytes as they pass ([`InlineRecoveryFolder`]) and
/// appended before the end header, at the offset the main header's locator
/// names, which is solved on header lengths alone because every length is
/// known before the first byte is written. Byte-identical to
/// `Rar50Writer::recovery_percent` over the same members (a test holds it);
/// the working set is the record's own size where the in-memory path held
/// the archive twice over. (nzbfast-local addition, 6 Sep 2026; see
/// VENDORING.md.)
pub fn write_stored_archive_streamed_with_recovery<R: Read, W: Write>(
    options: WriterOptions,
    recovery_percent: Option<u64>,
    entries: &mut [StreamedStoredEntry<'_, R>],
    sink: &mut W,
) -> Result<u64> {
    let _entropy = EntropyScope::install(options.entropy);
    let recovery_percent = streamed_recovery_percent(options, recovery_percent)?;
    validate_streamed_options_allowing(options, validate_recovery_options, true)?;
    // Every header first: their lengths fix the body's, which fixes the
    // record's offset and so the head's own length.
    let mut headers = Vec::with_capacity(entries.len());
    for entry in entries.iter() {
        headers.push(streamed_fragment_header(entry, entry.size, false, false)?);
    }
    let body_len: u64 = headers
        .iter()
        .zip(entries.iter())
        .map(|(header, entry)| header.len() as u64 + entry.size)
        .sum();
    let head_for = |offset: Option<u64>| -> Result<Vec<u8>> {
        let mut head = Vec::new();
        head.extend_from_slice(RAR50_SIGNATURE);
        let extra = resolved_main_extra(None, None, offset)?;
        let flags = if offset.is_some() { ARCHIVE_HAS_RECOVERY_RECORD } else { 0 };
        write_main_header(&mut head, flags, None, &extra)?;
        Ok(head)
    };
    let (head, mut folder) = match recovery_percent {
        None => (head_for(None)?, None),
        Some(percent) => {
            let offset = solve_recovery_offset(
                |offset| Ok((head_for(Some(offset))?.len() - RAR50_SIGNATURE.len()) as u64),
                body_len,
            )?;
            let head = head_for(Some(offset))?;
            let folder = InlineRecoveryFolder::with_thread_cap(
                head.len() as u64 + body_len,
                percent,
                options.recovery_fold_threads,
            )?;
            (head, Some(folder))
        }
    };
    let mut written = 0u64;
    {
        let mut sink = FoldingSink {
            inner: &mut *sink,
            folder: folder.as_mut(),
            written: &mut written,
        };
        sink.write_all(&head)?;
        let mut buffer = vec![0u8; STREAM_COPY_BYTES];
        for (entry, header) in entries.iter_mut().zip(&headers) {
            sink.write_all(header)?;
            copy_exact(&mut entry.source, &mut sink, entry.size, &mut buffer)?;
        }
    }
    let mut tail = Vec::new();
    if let (Some(folder), Some(percent)) = (folder, recovery_percent) {
        let record = folder.finish()?;
        write_recovery_service_record(&mut tail, &recovery_service_extra(percent), &record)?;
    }
    write_end_header(&mut tail, 0)?;
    sink.write_all(&tail)?;
    written += tail.len() as u64;
    sink.flush()?;
    Ok(written)
}

/// The percentage a streamed writer's record carries: the feature flag and
/// the percentage must agree, as the in-memory writers require.
fn streamed_recovery_percent(
    options: WriterOptions,
    recovery_percent: Option<u64>,
) -> Result<Option<u64>> {
    match (options.features.recovery_record, recovery_percent) {
        (false, None) => Ok(None),
        (true, Some(percent)) => Ok(Some(percent)),
        _ => Err(Error::InvalidHeader(
            "RAR 5 recovery record needs the feature flag and a percentage together",
        )),
    }
}

/// The recovery locator's offset for a head whose length depends on it:
/// `head_len(offset)` is the head's length past the signature for a given
/// offset, and the offset is that plus the body. Solved as the in-memory
/// writers solve it (`emit_resolved_writer_plan_recovery_direct`).
fn solve_recovery_offset(
    head_len: impl Fn(u64) -> Result<u64>,
    body_len: u64,
) -> Result<u64> {
    let mut offset = head_len(0)? + body_len;
    for _ in 0..4 {
        let next = head_len(offset)? + body_len;
        if next == offset {
            return Ok(offset);
        }
        offset = next;
    }
    Err(Error::InvalidHeader(
        "RAR 5 recovery locator offset did not converge",
    ))
}

/// A sink that folds every byte into the recovery record on its way out.
struct FoldingSink<'a, W: Write> {
    inner: &'a mut W,
    folder: Option<&'a mut InlineRecoveryFolder>,
    written: &'a mut u64,
}

impl<W: Write> Write for FoldingSink<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(folder) = self.folder.as_deref_mut() {
            folder
                .push(buf)
                .map_err(|_| std::io::Error::other("RAR 5 recovery record fold failed"))?;
        }
        self.inner.write_all(buf)?;
        *self.written += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A volume set holding `entries`, stored, each volume written to the sink
/// `open_volume(index)` returns, filled to `max_data_per_volume` bytes of
/// member data as `Rar50VolumeWriter::stored_entries` fills them; returns
/// the bytes written per volume. Byte-identical to that writer over the
/// same members, and like it refuses a set that does not reach two
/// volumes.
pub fn write_stored_volumes_streamed<R: Read, W: Write, F>(
    options: WriterOptions,
    max_data_per_volume: usize,
    entries: &mut [StreamedStoredEntry<'_, R>],
    open_volume: F,
) -> Result<Vec<u64>>
where
    F: FnMut(u64) -> std::io::Result<W>,
{
    write_stored_volumes_streamed_with_recovery(
        options,
        None,
        max_data_per_volume,
        entries,
        open_volume,
    )
}

/// [`write_stored_volumes_streamed`] with a RECOVERY RECORD per volume when
/// the options ask for one, each computed from that volume's bytes as they
/// pass and appended before its end header. The cuts are planned from the
/// member sizes first, so every volume's body length, and so its locator
/// offset, is known before its head is written. Byte-identical to
/// `Rar50VolumeWriter::recovery_percent` over the same members (a test
/// holds it). (nzbfast-local addition, 6 Sep 2026; see VENDORING.md.)
pub fn write_stored_volumes_streamed_with_recovery<R: Read, W: Write, F>(
    options: WriterOptions,
    recovery_percent: Option<u64>,
    max_data_per_volume: usize,
    entries: &mut [StreamedStoredEntry<'_, R>],
    mut open_volume: F,
) -> Result<Vec<u64>>
where
    F: FnMut(u64) -> std::io::Result<W>,
{
    let Some(percent) = streamed_recovery_percent(options, recovery_percent)? else {
        return write_stored_volumes_streamed_plain(options, max_data_per_volume, entries, open_volume);
    };
    let _entropy = EntropyScope::install(options.entropy);
    validate_streamed_options_allowing(options, validate_recovery_options, true)?;
    if max_data_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 volume payload size must be non-zero",
        ));
    }
    if entries.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 stored volume writer needs at least one entry",
        ));
    }
    if entries.iter().any(|entry| entry.size == 0) {
        return Err(Error::InvalidHeader(
            "RAR 5 volume writer needs a non-empty payload",
        ));
    }
    // The cuts, as `VolumeSetWriter::write_member` makes them: a volume
    // holds `max_data` bytes of member data, a member is split where one
    // fills. Each cut is (entry, start, end).
    let max_data = max_data_per_volume as u64;
    let mut volumes: Vec<Vec<(usize, u64, u64)>> = Vec::new();
    let mut room = 0u64;
    for (index, entry) in entries.iter().enumerate() {
        let mut start = 0u64;
        while start < entry.size {
            if room == 0 {
                volumes.push(Vec::new());
                room = max_data;
            }
            let fragment = room.min(entry.size - start);
            volumes
                .last_mut()
                .expect("a volume is open")
                .push((index, start, start + fragment));
            room -= fragment;
            start += fragment;
        }
    }
    if volumes.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 volume writer needs at least two volumes",
        ));
    }
    let mut buffer = vec![0u8; STREAM_COPY_BYTES];
    let mut sizes = Vec::with_capacity(volumes.len());
    for (number, cuts) in volumes.iter().enumerate() {
        let volume_number = number as u64;
        let mut headers = Vec::with_capacity(cuts.len());
        for &(index, start, end) in cuts {
            let entry = &entries[index];
            headers.push(streamed_fragment_header(
                entry,
                end - start,
                start > 0,
                end < entry.size,
            )?);
        }
        let body_len: u64 = headers
            .iter()
            .zip(cuts)
            .map(|(header, &(_, start, end))| header.len() as u64 + (end - start))
            .sum();
        let offset = solve_recovery_offset(
            |offset| {
                Ok((volume_head_len(volume_number, false, None, Some(offset))?
                    - RAR50_SIGNATURE.len()) as u64)
            },
            body_len,
        )?;
        let mut head = Vec::new();
        write_volume_head(&mut head, volume_number, false, None, Some(offset))?;
        let mut folder = InlineRecoveryFolder::with_thread_cap(
            head.len() as u64 + body_len,
            percent,
            options.recovery_fold_threads,
        )?;
        let mut sink = open_volume(volume_number)?;
        let mut written = 0u64;
        {
            let mut folding = FoldingSink {
                inner: &mut sink,
                folder: Some(&mut folder),
                written: &mut written,
            };
            folding.write_all(&head)?;
            for (&(index, start, end), header) in cuts.iter().zip(&headers) {
                folding.write_all(header)?;
                copy_exact(
                    &mut entries[index].source,
                    &mut folding,
                    end - start,
                    &mut buffer,
                )?;
            }
        }
        let record = folder.finish()?;
        let mut tail = Vec::new();
        write_recovery_service_record(&mut tail, &recovery_service_extra(percent), &record)?;
        write_volume_end(&mut tail, None, number + 1 < volumes.len())?;
        sink.write_all(&tail)?;
        sink.flush()?;
        sizes.push(written + tail.len() as u64);
    }
    Ok(sizes)
}

fn write_stored_volumes_streamed_plain<R: Read, W: Write, F>(
    options: WriterOptions,
    max_data_per_volume: usize,
    entries: &mut [StreamedStoredEntry<'_, R>],
    open_volume: F,
) -> Result<Vec<u64>>
where
    F: FnMut(u64) -> std::io::Result<W>,
{
    let _entropy = EntropyScope::install(options.entropy);
    validate_streamed_options(options, validate_options)?;
    if max_data_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 volume payload size must be non-zero",
        ));
    }
    if entries.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 stored volume writer needs at least one entry",
        ));
    }
    if entries.iter().any(|entry| entry.size == 0) {
        return Err(Error::InvalidHeader(
            "RAR 5 volume writer needs a non-empty payload",
        ));
    }
    let mut buffer = vec![0u8; STREAM_COPY_BYTES];
    let mut set = StreamedVolumeSet::new(open_volume, max_data_per_volume as u64);
    for entry in entries.iter_mut() {
        write_stored_member_streamed(&mut set, entry, &mut buffer)?;
    }
    set.finish()
}

/// A stored member into a volume set, cut where the volumes fill.
fn write_stored_member_streamed<R: Read, W: Write, F>(
    set: &mut StreamedVolumeSet<W, F>,
    entry: &mut StreamedStoredEntry<'_, R>,
    buffer: &mut [u8],
) -> Result<()>
where
    F: FnMut(u64) -> std::io::Result<W>,
{
    let mut start = 0u64;
    while start < entry.size {
        let (sink, room) = set.volume()?;
        let fragment = room.min(entry.size - start);
        let end = start + fragment;
        let header = streamed_fragment_header(entry, fragment, start > 0, end < entry.size)?;
        sink.write_all(&header)?;
        copy_exact(&mut entry.source, sink, fragment, buffer)?;
        set.wrote(header.len() as u64, fragment)?;
        start = end;
    }
    Ok(())
}

/// The volumes of a streamed set as [`VolumeSetWriter`] cuts them: a
/// volume holds `max_data` bytes of member data, the next is opened when
/// a fragment needs it, and a full one is closed with its end header at
/// once. Shared by the stored and the compressed streamed sets.
struct StreamedVolumeSet<W: Write, F: FnMut(u64) -> std::io::Result<W>> {
    open_volume: F,
    max_data: u64,
    sizes: Vec<u64>,
    /// The open volume and the bytes written to it.
    current: Option<(W, u64)>,
    /// A full volume and its bytes, held without its end header until
    /// the next volume opens or the set finishes (`END_OF_ARCHIVE_NOT_LAST_VOLUME`).
    closed: Option<(W, u64)>,
    payload_in_volume: u64,
}

impl<W: Write, F: FnMut(u64) -> std::io::Result<W>> StreamedVolumeSet<W, F> {
    fn new(open_volume: F, max_data: u64) -> Self {
        Self {
            open_volume,
            max_data,
            sizes: Vec::new(),
            current: None,
            closed: None,
            payload_in_volume: 0,
        }
    }

    /// The volume the next fragment goes to and the member data it has
    /// room for: the current one, or a fresh one when none is open.
    fn volume(&mut self) -> Result<(&mut W, u64)> {
        if self.current.is_none() {
            // Opening one is the proof the held one was not the last.
            self.seal_closed(true)?;
            let volume_number = self.sizes.len() as u64;
            let mut sink = (self.open_volume)(volume_number)?;
            let mut head = Vec::new();
            write_volume_head(&mut head, volume_number, false, None, None)?;
            sink.write_all(&head)?;
            self.current = Some((sink, head.len() as u64));
            self.payload_in_volume = 0;
        }
        let (sink, _) = self.current.as_mut().expect("a volume is open");
        Ok((sink, self.max_data - self.payload_in_volume))
    }

    /// Account for a fragment written to the open volume: `header_len`
    /// header bytes and `fragment` bytes of member data. A volume that is
    /// now full is closed.
    fn wrote(&mut self, header_len: u64, fragment: u64) -> Result<()> {
        let (_, written) = self.current.as_mut().expect("a volume is open");
        *written += header_len + fragment;
        self.payload_in_volume += fragment;
        if self.payload_in_volume == self.max_data {
            self.close_volume()?;
        }
        Ok(())
    }

    fn close_volume(&mut self) -> Result<()> {
        if let Some(current) = self.current.take() {
            debug_assert!(self.closed.is_none());
            self.closed = Some(current);
        }
        Ok(())
    }

    /// Seal the held volume with its end header, `next_volume` being what
    /// is now known: another volume opened after it, or the set finished.
    fn seal_closed(&mut self, next_volume: bool) -> Result<()> {
        if let Some((mut sink, written)) = self.closed.take() {
            let mut end = Vec::new();
            write_volume_end(&mut end, None, next_volume)?;
            sink.write_all(&end)?;
            sink.flush()?;
            self.sizes.push(written + end.len() as u64);
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u64>> {
        self.close_volume()?;
        self.seal_closed(false)?;
        if self.sizes.len() < 2 {
            return Err(Error::InvalidHeader(
                "RAR 5 volume writer needs at least two volumes",
            ));
        }
        Ok(self.sizes)
    }
}

// ---------------------------------------------------------------------------
// Compressed members.
//
// A compressed member is encoded a SEGMENT at a time from its source, with
// the previous segment's tail in front of it as history, through the block
// pool the in-memory writer uses (`encode_lz_member_window`): the packed
// bytes are the ones `Rar50Writer::compressed_entries` produces for the
// member, and the tests hold them there. Two windows are in flight at once
// so the pool never idles at a window's tail, which holds three windows
// (each the history, at least the dictionary, plus a segment of the pool's
// width in blocks) instead of the member and the archive.
//
// The single archive still holds one member's PACKED bytes: a file header
// carries the packed size and precedes the data, so the header cannot be
// written before the encode ends. The volume set holds a volume's worth.
//
// The sampler's verdict (`sampled_incompressible`) is taken from windows
// read out of the source, so the source must seek; the single archive
// rewinds it again when the whole encode failed to shrink the member and
// stores it instead, as the in-memory writer does. THE VOLUME SET CANNOT:
// its fragments are on the wire before the encode ends, so a member the
// sampler passed is written compressed even when the packed bytes reach
// the member's size, where `Rar50VolumeWriter` would have stored it. That
// needs three windows of at least 256 KiB each shrinking by over half a
// percent while the member as a whole does not, which no shape in the
// corpus produces; it is the one stated divergence, and the archive
// extracts the same either way. Level 5 (encode with every lower level
// and keep the smallest) is refused: it needs every packed candidate whole.
// (nzbfast-local addition, 6 Sep 2026; see VENDORING.md.)
// ---------------------------------------------------------------------------

/// The compression of one streamed archive, resolved as the in-memory
/// compressed writers resolve it.
#[derive(Clone, Copy)]
struct StreamedCompression {
    algorithm_version: u8,
    compression_method: u8,
    dictionary_size: u64,
    encode_options: EncodeOptions,
}

/// `largest_payload` is the largest entry's size: the declared dictionary
/// is fitted to it as the in-memory writers fit theirs (streamed sets are
/// never solid). (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
fn streamed_compression(
    options: WriterOptions,
    largest_payload: u64,
) -> Result<StreamedCompression> {
    if options.compression_level == Some(5) && options.level_five_fallbacks {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 streamed level-5 encoding (every lower level, smallest kept)",
        });
    }
    let dictionary_size =
        super::filter_policy::dictionary_size_for_payload(options, largest_payload)?;
    Ok(StreamedCompression {
        algorithm_version: rar50_algorithm_version(options)?,
        compression_method: compression_method_for_level(options.compression_level)?,
        dictionary_size,
        encode_options: encode_options_for_level(
            options.compression_level,
            dictionary_size,
            options.optimal_parse,
            options.adaptive_entropy_blocks,
            options.tokenizer_horizon_choice,
            working_memory_for(options),
        )?,
    })
}

fn streamed_member_len(size: u64) -> Result<usize> {
    usize::try_from(size).map_err(|_| {
        Error::InvalidHeader("RAR 5 streamed member exceeds this platform's address space")
    })
}

/// Whether the sampler stores `entry`: `sampled_incompressible`'s
/// windows, read from the source one at a time (the first that shrinks
/// ends the sampling, as there). The source is left at its start.
fn streamed_member_incompressible<R: Read + Seek>(
    entry: &mut StreamedStoredEntry<'_, R>,
    compression: StreamedCompression,
) -> Result<bool> {
    let Some(windows) =
        incompressible_sample_windows(streamed_member_len(entry.size)?, compression.encode_options)
    else {
        return Ok(false);
    };
    let mut sample = Vec::new();
    let mut incompressible = true;
    for window in &windows {
        entry.source.seek(SeekFrom::Start(window.start as u64))?;
        sample.resize(window.len(), 0);
        entry.source.read_exact(&mut sample)?;
        if !samples_read_incompressible(
            std::iter::once(sample.as_slice()),
            compression.algorithm_version,
            compression.encode_options,
        ) {
            incompressible = false;
            break;
        }
    }
    entry.source.seek(SeekFrom::Start(0))?;
    Ok(incompressible)
}

/// What a member's headers say about it, apart from its source.
#[derive(Clone, Copy)]
struct StreamedMemberInfo<'a> {
    name: &'a [u8],
    mtime: Option<u32>,
    attributes: u64,
    host_os: u64,
    size: u64,
    crc32: u32,
}

impl<'a, R: Read> StreamedStoredEntry<'a, R> {
    fn info(&self) -> StreamedMemberInfo<'a> {
        StreamedMemberInfo {
            name: self.name,
            mtime: self.mtime,
            attributes: self.attributes,
            host_os: self.host_os,
            size: self.size,
            crc32: self.crc32,
        }
    }
}

/// A directory entry in a streamed compressed archive: a file header with
/// the directory flag, a zero size and no data.
#[derive(Debug, Clone, Copy)]
pub struct StreamedDirectoryEntry<'a> {
    pub name: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
}

/// One member of [`write_compressed_members_streamed`]: a file read from
/// its source, or a directory.
///
/// The entry-slice writers take files only and refuse an EMPTY one. These
/// take both shapes a directory tree has in it that those cannot carry, so
/// `rar a -m3 -r dir` has a writer: a directory is a header, and an empty
/// file is stored, as the in-memory writer stores it. (nzbfast-local
/// addition, 14 Sep 2026; see VENDORING.md.)
pub enum StreamedMember<'a, R: Read> {
    File(StreamedStoredEntry<'a, R>),
    Directory(StreamedDirectoryEntry<'a>),
}

/// What [`write_members_streamed`] walks: the entry slices, whose members
/// are all files, and [`StreamedMember`] slices, which may hold directories.
trait StreamedItem<'a, R: Read> {
    /// Whether an empty file is refused, as the entry-slice writers always
    /// have refused one.
    const REFUSES_EMPTY: bool;
    fn item(&mut self) -> ItemRef<'_, 'a, R>;
    /// The file's size, `None` for a directory.
    fn file_size(&self) -> Option<u64>;
}

enum ItemRef<'m, 'a, R: Read> {
    File(&'m mut StreamedStoredEntry<'a, R>),
    Directory(StreamedDirectoryEntry<'a>),
}

impl<'a, R: Read> StreamedItem<'a, R> for StreamedStoredEntry<'a, R> {
    const REFUSES_EMPTY: bool = true;
    fn item(&mut self) -> ItemRef<'_, 'a, R> {
        ItemRef::File(self)
    }
    fn file_size(&self) -> Option<u64> {
        Some(self.size)
    }
}

impl<'a, R: Read> StreamedItem<'a, R> for StreamedMember<'a, R> {
    const REFUSES_EMPTY: bool = false;
    fn item(&mut self) -> ItemRef<'_, 'a, R> {
        match self {
            StreamedMember::File(entry) => ItemRef::File(entry),
            StreamedMember::Directory(directory) => ItemRef::Directory(*directory),
        }
    }
    fn file_size(&self) -> Option<u64> {
        match self {
            StreamedMember::File(entry) => Some(entry.size),
            StreamedMember::Directory(_) => None,
        }
    }
}

/// The directory flag in a file header's flags.
const FILE_IS_DIRECTORY: u64 = 0x0001;

/// A directory's file header: the directory flag, sizes of zero, no data
/// checksum, stored compression info, and an (empty) data area, the shape
/// the reference writes for one.
fn streamed_directory_header(directory: StreamedDirectoryEntry<'_>) -> Result<Vec<u8>> {
    validate_file_entry(directory.name)?;
    let mut file_flags = FILE_IS_DIRECTORY;
    if directory.mtime.is_some() {
        file_flags |= FILE_HAS_UNIX_MTIME;
    }
    let mut specific = Vec::new();
    write_vint(&mut specific, file_flags);
    write_vint(&mut specific, 0);
    write_vint(&mut specific, directory.attributes);
    if let Some(mtime) = directory.mtime {
        specific.extend_from_slice(&mtime.to_le_bytes());
    }
    write_vint(&mut specific, 0);
    write_vint(&mut specific, directory.host_os);
    write_vint(&mut specific, directory.name.len() as u64);
    specific.extend_from_slice(directory.name);
    block_header_image(BLOCK_TYPE_FILE, BLOCK_HAS_DATA_AREA, Some(0), &specific, &[])
}

/// The file header of one fragment of a compressed member, as
/// `write_compressed_entry_fragment` builds it.
fn streamed_compressed_fragment_header(
    entry: StreamedMemberInfo<'_>,
    compression: StreamedCompression,
    fragment_len: u64,
    split_before: bool,
    split_after: bool,
) -> Result<Vec<u8>> {
    let compression_info = compression_info(
        compression.algorithm_version,
        compression.compression_method,
        compression.dictionary_size,
        false,
    )?;
    let (specific, time_extra) = file_specific(
        entry.name,
        entry.size,
        (!split_after).then_some(entry.crc32),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    let mut block_flags = BLOCK_HAS_DATA_AREA;
    if split_before {
        block_flags |= BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME;
    }
    if split_after {
        block_flags |= BLOCK_CONTINUES_IN_NEXT_VOLUME;
    }
    if !time_extra.is_empty() {
        block_flags |= BLOCK_HAS_EXTRA_AREA;
    }
    block_header_image(
        BLOCK_TYPE_FILE,
        block_flags,
        Some(fragment_len),
        &specific,
        &time_extra,
    )
}

/// The two widths the streamed writer takes from the pool. They were one
/// number until 15 Sep 2026, and under a working-memory allowance that
/// number had to lose its floor of eight for the small members and took the
/// large member's window down with it (see [`member_window_segment_blocks`]).
/// (nzbfast-local change, 15 Sep 2026; see VENDORING.md.)
#[derive(Clone, Copy, Debug)]
struct StreamWindows {
    /// How many small members encode at once, at most, holding at most twice
    /// that many blocks, and the size under which a member is one of them.
    members: usize,
    /// How many blocks a large member's window encodes behind its history.
    segment: usize,
}

impl StreamWindows {
    fn for_options(options: EncodeOptions) -> Self {
        Self {
            members: member_window_blocks(options),
            segment: member_window_segment_blocks(options),
        }
    }

    /// One width for both, the shape every window was before the split.
    #[cfg(test)]
    fn uniform(blocks: usize) -> Self {
        Self {
            members: blocks,
            segment: blocks,
        }
    }
}

/// Encode a member from its source, handing `emit` each window's packed
/// bytes in member order with whether they are the member's last. A
/// member of one block or less takes the single-block path the in-memory
/// writer takes for it; a longer one is encoded from windows of
/// `segment_blocks` blocks (see the module notes above).
fn encode_streamed_member<R: Read>(
    source: &mut R,
    size: u64,
    compression: StreamedCompression,
    segment_blocks: usize,
    scratch: &EncoderScratchPool,
    mut emit: impl FnMut(Vec<u8>, bool) -> Result<()>,
) -> Result<()> {
    let size = streamed_member_len(size)?;
    let block = MAX_COMPRESSED_BLOCK_OUTPUT;
    if size <= block {
        let mut data = vec![0u8; size];
        source.read_exact(&mut data)?;
        let packed = encode_lz_member_with_options(
            &data,
            compression.algorithm_version,
            compression.encode_options,
        )?;
        return emit(packed, true);
    }
    let history_len = compression
        .encode_options
        .max_match_distance
        .div_ceil(block)
        .max(1)
        * block;
    let segment = segment_blocks.max(1) * block;
    let mut buffer = vec![0u8; STREAM_COPY_BYTES];
    std::thread::scope(|scope| -> Result<()> {
        let mut free: Vec<Vec<u8>> = (0..3)
            .map(|_| Vec::with_capacity(history_len + segment))
            .collect();
        let mut in_flight: std::collections::VecDeque<WindowJob<'_>> =
            std::collections::VecDeque::new();
        let mut window = free.pop().expect("three windows");
        let mut history = 0usize;
        let mut read_so_far = 0usize;
        loop {
            let take = segment.min(size - read_so_far);
            read_into(source, &mut window, take, &mut buffer)?;
            read_so_far += take;
            let final_segment = read_so_far == size;
            let next = if final_segment {
                None
            } else {
                let mut next = match free.pop() {
                    Some(next) => next,
                    None => {
                        let job = in_flight.pop_front().expect("a window in flight");
                        join_window(job, &mut emit, false)?
                    }
                };
                next.clear();
                let tail = window.len().min(history_len);
                next.extend_from_slice(&window[window.len() - tail..]);
                Some(next)
            };
            let first_block = history / block;
            in_flight.push_back(scope.spawn(move || {
                let packed = encode_lz_member_window(
                    &window,
                    first_block,
                    compression.algorithm_version,
                    compression.encode_options,
                    final_segment,
                    scratch,
                );
                (window, packed)
            }));
            match next {
                Some(next) => {
                    history = next.len();
                    window = next;
                }
                None => break,
            }
        }
        while let Some(job) = in_flight.pop_front() {
            let last = in_flight.is_empty();
            free.push(join_window(job, &mut emit, last)?);
        }
        Ok(())
    })
}

/// A window's encode in flight: hands back the window and its packed bytes.
type WindowJob<'s> =
    std::thread::ScopedJoinHandle<'s, (Vec<u8>, crate::codec::Result<Vec<u8>>)>;

/// Wait for a window's encode and hand its packed bytes to `emit`; the
/// window comes back for reuse.
fn join_window(
    job: WindowJob<'_>,
    emit: &mut dyn FnMut(Vec<u8>, bool) -> Result<()>,
    last: bool,
) -> Result<Vec<u8>> {
    let (window, packed) = job
        .join()
        .map_err(|_| Error::InvalidHeader("RAR 5 streamed member encoder panicked"))?;
    emit(packed.map_err(Error::from)?, last)?;
    Ok(window)
}

/// Append exactly `len` bytes from `source` to `out`.
fn read_into<R: Read>(
    source: &mut R,
    out: &mut Vec<u8>,
    len: usize,
    buffer: &mut [u8],
) -> Result<()> {
    let mut left = len;
    while left > 0 {
        let want = buffer.len().min(left);
        let read = source.read(&mut buffer[..want])?;
        if read == 0 {
            return Err(Error::InvalidHeader(
                "RAR 5 streamed member ended before its declared size",
            ));
        }
        out.extend_from_slice(&buffer[..read]);
        left -= read;
    }
    Ok(())
}

/// What a member resolved off its source came to: stored (the sampler's
/// verdict, or an encode that did not shrink it) or its packed bytes.
enum MemberResult {
    Stored,
    Packed(Vec<u8>),
}

/// A member held whole, resolved as the in-memory writer resolves it: the
/// sampler, the encode, the compare against its size.
/// Test-only panic seam. A member whose bytes open with this marker makes the
/// encoder panic, so the streamed writer's panic path is reachable from a test
/// WITHOUT a process-global flag another concurrently running test could
/// consume. Only `the_streamed_writer_reports_a_panicking_encoder_as_an_error`
/// builds a member that carries it.
#[cfg(test)]
pub(crate) const PANIC_MARKER: &[u8] = b"RARS-PANIC-HERE!";

fn resolve_member(
    data: &[u8],
    compression: StreamedCompression,
    scratch: &EncoderScratchPool,
) -> Result<MemberResult> {
    #[cfg(test)]
    if data.starts_with(PANIC_MARKER) {
        panic!("injected encoder panic (test marker)");
    }
    if super::filter_policy::sampled_incompressible(
        data,
        compression.algorithm_version,
        compression.encode_options,
    ) {
        return Ok(MemberResult::Stored);
    }
    let packed = encode_lz_member_pooled(
        data,
        &[],
        compression.algorithm_version,
        compression.encode_options,
        None,
        scratch,
    )?;
    Ok(if packed.len() >= data.len() {
        MemberResult::Stored
    } else {
        MemberResult::Packed(packed)
    })
}

/// A windowed member's encode is on the wire as it goes, or must be
/// stored after all (the single archive, when the packed bytes reached
/// the member's size).
enum WindowOutcome {
    Written,
    StoreInstead,
}

/// Where the members of a streamed compressed archive go: the single
/// archive or the volume set, each building the headers the in-memory
/// writer of its kind builds.
trait MemberSink {
    /// A stored member held whole.
    fn stored_slice(&mut self, info: StreamedMemberInfo<'_>, data: &[u8]) -> Result<()>;
    /// A stored member copied from its source, `info.size` bytes.
    fn stored_source(
        &mut self,
        info: StreamedMemberInfo<'_>,
        source: &mut dyn Read,
        buffer: &mut [u8],
    ) -> Result<()>;
    /// A compressed member whose packed bytes are all in hand.
    fn packed_slice(&mut self, info: StreamedMemberInfo<'_>, packed: &[u8]) -> Result<()>;
    /// One window's packed bytes of a member encoded from windows, in
    /// order; `last` closes the member.
    fn packed_window(
        &mut self,
        info: StreamedMemberInfo<'_>,
        bytes: Vec<u8>,
        last: bool,
    ) -> Result<WindowOutcome>;
    /// A directory entry: a header and no data.
    fn directory(&mut self, directory: StreamedDirectoryEntry<'_>) -> Result<()>;
}

/// The members of a streamed compressed archive, resolved and handed to
/// `sink` IN ORDER.
///
/// A member of up to one admission width (`windows.members` blocks) is read
/// whole and resolved on a thread
/// of its own ([`resolve_member`], which runs the block pool inside it for
/// a member of several blocks), several in flight at once - a set of small
/// members has no other parallelism, and the in-memory writer resolves
/// its members in parallel too (measured before this: 150 members of
/// 2.7 MB took 15.8 s one at a time against 1.0 s in memory). In flight
/// at once: at most `windows.members` members holding at most twice that
/// many blocks of member data. A longer member is encoded from windows of
/// `windows.segment` blocks ([`encode_streamed_member`]) after the jobs before it have drained, so
/// its blocks have the pool to themselves.
fn write_members_streamed<'a, R: Read + Seek, M: StreamedItem<'a, R>, S: MemberSink>(
    entries: &mut [M],
    compression: StreamedCompression,
    windows: StreamWindows,
    sink: &mut S,
) -> Result<()> {
    /// A parked encoder worker: hand it a member's bytes, take back the bytes
    /// and the encode. Reused across members rather than spawned per member,
    /// so a set of small members does not pay a thread launch each.
    type Job = (
        std::sync::mpsc::Sender<Vec<u8>>,
        std::sync::mpsc::Receiver<(Vec<u8>, Result<MemberResult>)>,
    );
    let block = MAX_COMPRESSED_BLOCK_OUTPUT;
    let segment_blocks = windows.members.max(1);
    let window_bytes = segment_blocks * block;
    let infos: Vec<Option<StreamedMemberInfo<'a>>> = entries
        .iter_mut()
        .map(|member| match member.item() {
            ItemRef::File(entry) => Some(entry.info()),
            ItemRef::Directory(_) => None,
        })
        .collect();
    let mut buffer = vec![0u8; STREAM_COPY_BYTES];
    // One scratch pool for the whole archive: a windowed member's
    // workers hand their buffers on from window to window and member to
    // member instead of faulting fresh ones in.
    let scratch = EncoderScratchPool::new();
    std::thread::scope(|scope| -> Result<()> {
        let mut queue: std::collections::VecDeque<(usize, usize, Job)> =
            std::collections::VecDeque::new();
        let mut blocks_in_flight = 0usize;
        let free_jobs = std::cell::RefCell::new(Vec::<Job>::new());
        let drain_one = |queue: &mut std::collections::VecDeque<(usize, usize, Job)>,
                             blocks_in_flight: &mut usize,
                             sink: &mut S|
         -> Result<()> {
            let Some((index, blocks, job)) = queue.pop_front() else {
                return Ok(());
            };
            *blocks_in_flight -= blocks;
            let (data, result) = job
                .1
                .recv()
                .map_err(|_| Error::InvalidHeader("RAR 5 streamed member encoder panicked"))?;
            free_jobs.borrow_mut().push(job);
            let info = infos[index].expect("only a file is queued for encoding");
            match result? {
                MemberResult::Stored => sink.stored_slice(info, &data),
                MemberResult::Packed(packed) => sink.packed_slice(info, &packed),
            }
        };
        for (index, member) in entries.iter_mut().enumerate() {
            let entry = match member.item() {
                ItemRef::File(entry) => entry,
                ItemRef::Directory(directory) => {
                    while !queue.is_empty() {
                        drain_one(&mut queue, &mut blocks_in_flight, sink)?;
                    }
                    sink.directory(directory)?;
                    continue;
                }
            };
            let info = entry.info();
            let size = streamed_member_len(info.size)?;
            if size == 0 {
                // Only a StreamedMember slice gets here: an empty file is
                // stored, as the in-memory writer stores one.
                while !queue.is_empty() {
                    drain_one(&mut queue, &mut blocks_in_flight, sink)?;
                }
                sink.stored_slice(info, &[])?;
                continue;
            }
            if compression.compression_method == 0 {
                while !queue.is_empty() {
                    drain_one(&mut queue, &mut blocks_in_flight, sink)?;
                }
                sink.stored_source(info, &mut entry.source, &mut buffer)?;
                continue;
            }
            if size <= window_bytes {
                let scratch = &scratch;
                let blocks = size.div_ceil(block).max(1);
                // Each queued member holds its own match-finder tree beside
                // its blocks, which the window does not count; under a
                // policy the trees share its tree quarter
                // (`members_in_flight_for`).
                let members_at_once = segment_blocks.min(
                    super::filter_policy::members_in_flight_for(&[compression.encode_options]),
                );
                while !queue.is_empty()
                    && (queue.len() >= members_at_once
                        || blocks_in_flight + blocks > 2 * segment_blocks)
                {
                    drain_one(&mut queue, &mut blocks_in_flight, sink)?;
                }
                let mut data = Vec::with_capacity(size);
                read_into(&mut entry.source, &mut data, size, &mut buffer)?;
                blocks_in_flight += blocks;
                let reused = free_jobs.borrow_mut().pop();
                let job = reused.unwrap_or_else(|| {
                    let (input_tx, input_rx) = std::sync::mpsc::channel::<Vec<u8>>();
                    let (output_tx, output_rx) = std::sync::mpsc::channel();
                    scope.spawn(move || {
                        while let Ok(data) = input_rx.recv() {
                            // Catch the panic HERE rather than at a join. A
                            // parked worker is never joined, and
                            // `thread::scope` panics at its end if a thread
                            // panicked and nothing consumed it - so without
                            // this the error below would never reach the
                            // caller, the scope would panic past it.
                            let result = std::panic::catch_unwind(
                                std::panic::AssertUnwindSafe(|| {
                                    resolve_member(&data, compression, scratch)
                                }),
                            )
                            .unwrap_or(Err(Error::InvalidHeader(
                                "RAR 5 streamed member encoder panicked",
                            )));
                            if output_tx.send((data, result)).is_err() {
                                break;
                            }
                        }
                    });
                    (input_tx, output_rx)
                });
                job.0.send(data).map_err(|_| {
                    Error::InvalidHeader("RAR 5 streamed member encoder panicked")
                })?;
                queue.push_back((index, blocks, job));
                continue;
            }
            while !queue.is_empty() {
                drain_one(&mut queue, &mut blocks_in_flight, sink)?;
            }
            if streamed_member_incompressible(entry, compression)? {
                sink.stored_source(info, &mut entry.source, &mut buffer)?;
                continue;
            }
            let mut store_instead = false;
            encode_streamed_member(
                &mut entry.source,
                info.size,
                compression,
                windows.segment,
                &scratch,
                |bytes, last| {
                    if let WindowOutcome::StoreInstead = sink.packed_window(info, bytes, last)? {
                        store_instead = true;
                    }
                    Ok(())
                },
            )?;
            if store_instead {
                // The encode did not shrink it: stored, from the source again.
                entry.source.seek(SeekFrom::Start(0))?;
                sink.stored_source(info, &mut entry.source, &mut buffer)?;
            }
        }
        while !queue.is_empty() {
            drain_one(&mut queue, &mut blocks_in_flight, sink)?;
        }
        Ok(())
    })
}

/// The file header of one fragment of a stored member from its fields.
fn streamed_stored_header(
    info: StreamedMemberInfo<'_>,
    fragment_len: u64,
    split_before: bool,
    split_after: bool,
) -> Result<Vec<u8>> {
    let (specific, time_extra) = stored_file_specific(
        info.name,
        info.size,
        (!split_after).then_some(info.crc32),
        info.attributes,
        info.mtime,
        info.host_os,
    )?;
    let mut block_flags = BLOCK_HAS_DATA_AREA;
    if split_before {
        block_flags |= BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME;
    }
    if split_after {
        block_flags |= BLOCK_CONTINUES_IN_NEXT_VOLUME;
    }
    if !time_extra.is_empty() {
        block_flags |= BLOCK_HAS_EXTRA_AREA;
    }
    block_header_image(
        BLOCK_TYPE_FILE,
        block_flags,
        Some(fragment_len),
        &specific,
        &time_extra,
    )
}

/// The single archive: every member is one block of header and data.
/// A windowed member's packed bytes are held until its encode ends,
/// because the header carries their length.
struct ArchiveSink<'w, W: Write> {
    sink: &'w mut W,
    written: u64,
    compression: StreamedCompression,
    pending: Vec<u8>,
}

impl<W: Write> ArchiveSink<'_, W> {
    fn block(&mut self, header: &[u8], data: &[u8]) -> Result<()> {
        self.sink.write_all(header)?;
        self.sink.write_all(data)?;
        self.written += header.len() as u64 + data.len() as u64;
        Ok(())
    }
}

impl<W: Write> MemberSink for ArchiveSink<'_, W> {
    fn stored_slice(&mut self, info: StreamedMemberInfo<'_>, data: &[u8]) -> Result<()> {
        let header = streamed_stored_header(info, info.size, false, false)?;
        self.block(&header, data)
    }

    fn stored_source(
        &mut self,
        info: StreamedMemberInfo<'_>,
        source: &mut dyn Read,
        buffer: &mut [u8],
    ) -> Result<()> {
        let header = streamed_stored_header(info, info.size, false, false)?;
        self.sink.write_all(&header)?;
        copy_exact(source, self.sink, info.size, buffer)?;
        self.written += header.len() as u64 + info.size;
        Ok(())
    }

    fn packed_slice(&mut self, info: StreamedMemberInfo<'_>, packed: &[u8]) -> Result<()> {
        let header = streamed_compressed_fragment_header(
            info,
            self.compression,
            packed.len() as u64,
            false,
            false,
        )?;
        self.block(&header, packed)
    }

    fn directory(&mut self, directory: StreamedDirectoryEntry<'_>) -> Result<()> {
        let header = streamed_directory_header(directory)?;
        self.block(&header, &[])
    }

    fn packed_window(
        &mut self,
        info: StreamedMemberInfo<'_>,
        bytes: Vec<u8>,
        last: bool,
    ) -> Result<WindowOutcome> {
        self.pending.extend_from_slice(&bytes);
        if !last {
            return Ok(WindowOutcome::Written);
        }
        let packed = std::mem::take(&mut self.pending);
        if packed.len() as u64 >= info.size {
            return Ok(WindowOutcome::StoreInstead);
        }
        self.packed_slice(info, &packed)?;
        Ok(WindowOutcome::Written)
    }
}

/// The volume set: a member is cut into fragments where the volumes fill,
/// as [`VolumeSetWriter::write_member`] cuts it. A windowed member's
/// packed bytes leave as each volume fills; the rest when its encode ends.
struct VolumeSetSink<W: Write, F: FnMut(u64) -> std::io::Result<W>> {
    set: StreamedVolumeSet<W, F>,
    compression: StreamedCompression,
    pending: Vec<u8>,
    split_before: bool,
}

impl<W: Write, F: FnMut(u64) -> std::io::Result<W>> VolumeSetSink<W, F> {
    /// Fragments of `data` onto the volumes: every one that fills a
    /// volume, and the remainder as the member's last when `finished`.
    /// Returns how many bytes left.
    fn fragments(
        &mut self,
        info: StreamedMemberInfo<'_>,
        compressed: bool,
        data: &[u8],
        finished: bool,
    ) -> Result<usize> {
        let mut consumed = 0usize;
        while consumed < data.len() {
            let (sink, room) = self.set.volume()?;
            let left = data.len() - consumed;
            let take = usize::try_from(room).unwrap_or(usize::MAX).min(left);
            // A fragment that does not fill the volume is the member's
            // last: until the encode ends, only full ones leave.
            if !finished && (take as u64) < room {
                break;
            }
            let split_after = !(finished && take == left);
            let header = if compressed {
                streamed_compressed_fragment_header(
                    info,
                    self.compression,
                    take as u64,
                    self.split_before,
                    split_after,
                )?
            } else {
                streamed_stored_header(info, take as u64, self.split_before, split_after)?
            };
            sink.write_all(&header)?;
            sink.write_all(&data[consumed..consumed + take])?;
            self.set.wrote(header.len() as u64, take as u64)?;
            consumed += take;
            self.split_before = !(finished && take == left);
        }
        Ok(consumed)
    }
}

impl<W: Write, F: FnMut(u64) -> std::io::Result<W>> MemberSink for VolumeSetSink<W, F> {
    fn stored_slice(&mut self, info: StreamedMemberInfo<'_>, data: &[u8]) -> Result<()> {
        self.split_before = false;
        if data.is_empty() {
            // An empty file has no fragment for `fragments` to cut, and
            // would leave no header at all: it is one header, whole.
            let header = streamed_stored_header(info, 0, false, false)?;
            let (sink, _) = self.set.volume()?;
            sink.write_all(&header)?;
            return self.set.wrote(header.len() as u64, 0);
        }
        self.fragments(info, false, data, true).map(|_| ())
    }

    fn stored_source(
        &mut self,
        info: StreamedMemberInfo<'_>,
        source: &mut dyn Read,
        buffer: &mut [u8],
    ) -> Result<()> {
        let mut start = 0u64;
        while start < info.size {
            let (sink, room) = self.set.volume()?;
            let fragment = room.min(info.size - start);
            let end = start + fragment;
            let header = streamed_stored_header(info, fragment, start > 0, end < info.size)?;
            sink.write_all(&header)?;
            copy_exact(source, sink, fragment, buffer)?;
            self.set.wrote(header.len() as u64, fragment)?;
            start = end;
        }
        Ok(())
    }

    fn packed_slice(&mut self, info: StreamedMemberInfo<'_>, packed: &[u8]) -> Result<()> {
        self.split_before = false;
        self.fragments(info, true, packed, true).map(|_| ())
    }

    fn directory(&mut self, directory: StreamedDirectoryEntry<'_>) -> Result<()> {
        let header = streamed_directory_header(directory)?;
        let (sink, _) = self.set.volume()?;
        sink.write_all(&header)?;
        self.set.wrote(header.len() as u64, 0)
    }

    fn packed_window(
        &mut self,
        info: StreamedMemberInfo<'_>,
        bytes: Vec<u8>,
        last: bool,
    ) -> Result<WindowOutcome> {
        self.pending.extend_from_slice(&bytes);
        let pending = std::mem::take(&mut self.pending);
        let consumed = self.fragments(info, true, &pending, last)?;
        self.pending = pending;
        self.pending.drain(..consumed);
        if last {
            self.split_before = false;
        }
        Ok(WindowOutcome::Written)
    }
}

/// A single archive holding `entries`, compressed at the options' level
/// and dictionary, written to `sink`; returns the bytes written.
/// Byte-identical to `Rar50Writer::compressed_entries` over the same
/// members (a member the sampler or the encode leaves stored is stored
/// there too). A member of up to one admission width
/// (`StreamWindows::members` blocks, from `member_window_blocks`: at least
/// eight with no allowance, as few as one under one) is read whole; a
/// longer one is read for the sampler's windows (the caller has
/// already read it once for its CRC32, [`crc32_of_reader`]), once for the
/// encode, and once more only when the encode did not shrink it. Holds
/// the members in flight and one windowed member's packed bytes.
pub fn write_compressed_archive_streamed<R: Read + Seek, W: Write>(
    options: WriterOptions,
    entries: &mut [StreamedStoredEntry<'_, R>],
    sink: &mut W,
) -> Result<u64> {
    write_compressed_archive_streamed_with_windows(
        options,
        entries,
        sink,
        StreamWindows::for_options(
            streamed_compression(options, largest_streamed(entries))?.encode_options,
        ),
    )
}

/// The largest entry of a streamed set, for the dictionary fit.
fn largest_streamed<'a, R: Read, M: StreamedItem<'a, R>>(entries: &[M]) -> u64 {
    entries
        .iter()
        .filter_map(|entry| entry.file_size())
        .max()
        .unwrap_or(0)
}

fn write_compressed_archive_streamed_with_windows<'a, R: Read + Seek, M: StreamedItem<'a, R>, W: Write>(
    options: WriterOptions,
    entries: &mut [M],
    sink: &mut W,
    windows: StreamWindows,
) -> Result<u64> {
    let _entropy = EntropyScope::install(options.entropy);
    validate_streamed_options(options, validate_compressed_options)?;
    let compression = streamed_compression(options, largest_streamed(entries))?;
    if M::REFUSES_EMPTY && entries.iter().any(|entry| entry.file_size() == Some(0)) {
        return Err(Error::InvalidHeader(
            "RAR 5 compressed writer needs a non-empty payload",
        ));
    }
    let mut head = Vec::new();
    head.extend_from_slice(RAR50_SIGNATURE);
    write_main_header(&mut head, 0, None, &[])?;
    sink.write_all(&head)?;
    let mut archive = ArchiveSink {
        sink,
        written: head.len() as u64,
        compression,
        pending: Vec::new(),
    };
    write_members_streamed(entries, compression, windows, &mut archive)?;
    let mut end = Vec::new();
    write_end_header(&mut end, 0)?;
    archive.sink.write_all(&end)?;
    let written = archive.written + end.len() as u64;
    archive.sink.flush()?;
    Ok(written)
}

/// A volume set holding `entries`, compressed, each volume written to the
/// sink `open_volume(index)` returns and filled to `max_packed_per_volume`
/// bytes of member data as `Rar50VolumeWriter::compressed_entries` fills
/// them; returns the bytes written per volume. Byte-identical to that
/// writer over the same members, except the one case the module notes
/// above state (a member longer than a window that the sampler passed and
/// the encode did not shrink is compressed here, stored there). Holds the
/// members in flight and a volume's worth of a windowed member's packed
/// bytes.
pub fn write_compressed_volumes_streamed<R: Read + Seek, W: Write, F>(
    options: WriterOptions,
    max_packed_per_volume: usize,
    entries: &mut [StreamedStoredEntry<'_, R>],
    open_volume: F,
) -> Result<Vec<u64>>
where
    F: FnMut(u64) -> std::io::Result<W>,
{
    write_compressed_volumes_streamed_with_windows(
        options,
        max_packed_per_volume,
        entries,
        open_volume,
        StreamWindows::for_options(
            streamed_compression(options, largest_streamed(entries))?.encode_options,
        ),
    )
}

fn write_compressed_volumes_streamed_with_windows<'a, R: Read + Seek, M: StreamedItem<'a, R>, W: Write, F>(
    options: WriterOptions,
    max_packed_per_volume: usize,
    entries: &mut [M],
    open_volume: F,
    windows: StreamWindows,
) -> Result<Vec<u64>>
where
    F: FnMut(u64) -> std::io::Result<W>,
{
    let _entropy = EntropyScope::install(options.entropy);
    validate_streamed_options(options, validate_compressed_options)?;
    let compression = streamed_compression(options, largest_streamed(entries))?;
    if max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 compressed volume payload size must be non-zero",
        ));
    }
    if entries.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 compressed volume writer needs at least one entry",
        ));
    }
    if M::REFUSES_EMPTY && entries.iter().any(|entry| entry.file_size() == Some(0)) {
        return Err(Error::InvalidHeader(
            "RAR 5 compressed volume writer needs a non-empty payload",
        ));
    }
    let mut volumes = VolumeSetSink {
        set: StreamedVolumeSet::new(open_volume, max_packed_per_volume as u64),
        compression,
        pending: Vec::new(),
        split_before: false,
    };
    write_members_streamed(entries, compression, windows, &mut volumes)?;
    volumes.set.finish()
}

/// [`write_compressed_archive_streamed`] over members that may be
/// DIRECTORIES or empty files, which a directory tree holds and the entry
/// slice cannot. Files come out byte-identical to that writer's (a test
/// holds it); a directory is a header with no data, and an empty file is
/// stored. (nzbfast-local addition, 14 Sep 2026; see VENDORING.md.)
pub fn write_compressed_members_streamed<R: Read + Seek, W: Write>(
    options: WriterOptions,
    members: &mut [StreamedMember<'_, R>],
    sink: &mut W,
) -> Result<u64> {
    let windows = StreamWindows::for_options(
        streamed_compression(options, largest_streamed(members))?.encode_options,
    );
    write_compressed_archive_streamed_with_windows(options, members, sink, windows)
}

/// [`write_compressed_volumes_streamed`] over members that may be
/// directories or empty files; see [`write_compressed_members_streamed`].
/// A directory takes no payload, so it never opens a volume on its own
/// account unless the one before it filled. (nzbfast-local addition,
/// 14 Sep 2026; see VENDORING.md.)
pub fn write_compressed_member_volumes_streamed<R: Read + Seek, W: Write, F>(
    options: WriterOptions,
    max_packed_per_volume: usize,
    members: &mut [StreamedMember<'_, R>],
    open_volume: F,
) -> Result<Vec<u64>>
where
    F: FnMut(u64) -> std::io::Result<W>,
{
    let windows = StreamWindows::for_options(
        streamed_compression(options, largest_streamed(members))?.encode_options,
    );
    write_compressed_volumes_streamed_with_windows(
        options,
        max_packed_per_volume,
        members,
        open_volume,
        windows,
    )
}

/// One member's encryption, chunk by chunk: chained AES-CBC over the
/// padded plaintext, whole blocks enciphered as they come, the partial
/// block at a chunk's end carried to the next, the last one zero-padded.
struct StreamCipher {
    cipher: Rar50Cipher,
    carry: Vec<u8>,
}

impl StreamCipher {
    fn new(key: [u8; 32], iv: [u8; 16]) -> Self {
        Self {
            cipher: Rar50Cipher::new(key, iv),
            carry: Vec::with_capacity(16),
        }
    }

    /// Cipher bytes for `chunk`, appended to `out`: every whole block the
    /// carry and the chunk make up.
    fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&self.carry);
        out.extend_from_slice(chunk);
        let whole = (out.len() - start) / 16 * 16;
        self.carry.clear();
        self.carry.extend_from_slice(&out[start + whole..]);
        out.truncate(start + whole);
        self.cipher
            .encrypt_in_place(&mut out[start..])
            .map_err(super::map_rar50_crypto_error)
    }

    /// The padded final block, if the member's length left one.
    fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if self.carry.is_empty() {
            return Ok(());
        }
        let start = out.len();
        out.extend_from_slice(&self.carry);
        out.resize(start + 16, 0);
        self.carry.clear();
        self.cipher
            .encrypt_in_place(&mut out[start..])
            .map_err(super::map_rar50_crypto_error)
    }
}

/// The key material of one streamed encrypted member: what
/// `encrypted_stored_payload` derives, from the caller's CRC instead of
/// the bytes (the BLAKE2sp record is refused for the stream).
fn streamed_encrypted_payload(
    entry_size: u64,
    entry_crc32: u32,
    password: &[u8],
) -> Result<EncryptedStoredPayload> {
    let (keys, salt, iv) = encryption_keys(password)?;
    let padded_len = entry_size
        .checked_add(15)
        .ok_or(Error::InvalidHeader("RAR 5 encrypted data size overflows"))?
        & !15;
    Ok(EncryptedStoredPayload {
        data: Vec::new(),
        padded_len: usize::try_from(padded_len)
            .map_err(|_| Error::InvalidHeader("RAR 5 encrypted data size overflows"))?,
        key: keys.key,
        salt,
        iv,
        check_value: keys.password_check_record(),
        crc32_mac: keys.mac_crc32(entry_crc32),
        blake2sp_mac: None,
    })
}

/// The file header of one fragment of an encrypted stored member, as
/// `write_encrypted_stored_entry_fragment_with_header_keys` builds it,
/// without its data.
fn streamed_encrypted_fragment_header<R: Read>(
    entry: &StreamedStoredEntry<'_, R>,
    encrypted: &EncryptedStoredPayload,
    fragment_len: u64,
    split_before: bool,
    split_after: bool,
    header_keys: Option<&HeaderEncryptionKeys>,
) -> Result<Vec<u8>> {
    let mut extra = Vec::new();
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    let (specific, time_extra) = stored_file_specific(
        entry.name,
        entry.size,
        (!split_after).then_some(encrypted.crc32_mac),
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    extra.extend_from_slice(&time_extra);
    let mut block_flags = BLOCK_HAS_EXTRA_AREA | BLOCK_HAS_DATA_AREA;
    if split_before {
        block_flags |= BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME;
    }
    if split_after {
        block_flags |= BLOCK_CONTINUES_IN_NEXT_VOLUME;
    }
    match header_keys {
        Some(header_keys) => {
            let mut header = Vec::new();
            append_encrypted_header_block_with(
                &mut header,
                &header_keys.keys,
                BLOCK_TYPE_FILE,
                block_flags,
                Some(fragment_len),
                &specific,
                &extra,
                BlockData::Bytes(&[]),
            )?;
            Ok(header)
        }
        None => block_header_image(
            BLOCK_TYPE_FILE,
            block_flags,
            Some(fragment_len),
            &specific,
            &extra,
        ),
    }
}

/// Read up to a buffer of `entry`'s plaintext and hand its cipher bytes
/// to `pending` (all of them once the member is exhausted); `Ok(false)`
/// when there is nothing left to produce.
fn next_cipher_chunk<R: Read>(
    entry: &mut StreamedStoredEntry<'_, R>,
    plain_left: &mut u64,
    cipher: &mut StreamCipher,
    buffer: &mut [u8],
    pending: &mut Vec<u8>,
) -> Result<bool> {
    pending.clear();
    if *plain_left > 0 {
        let want = buffer
            .len()
            .min(usize::try_from(*plain_left).unwrap_or(usize::MAX));
        let read = entry.source.read(&mut buffer[..want])?;
        if read == 0 {
            return Err(Error::InvalidHeader(
                "RAR 5 streamed member ended before its declared size",
            ));
        }
        *plain_left -= read as u64;
        cipher.push(&buffer[..read], pending)?;
    }
    if *plain_left == 0 {
        cipher.finish(pending)?;
    }
    Ok(!pending.is_empty())
}

/// One archive holding `entries`, stored and encrypted under `password`
/// (and its headers too when `options.features.header_encryption`),
/// written to `sink`. Byte-identical to
/// `Rar50Writer::encrypted_stored_entries` over the same members under the
/// same entropy: the header keys are drawn first, then each member's salt
/// and IV, as that writer draws them.
pub fn write_encrypted_stored_archive_streamed<R: Read, W: Write>(
    options: WriterOptions,
    password: &[u8],
    entries: &mut [StreamedStoredEntry<'_, R>],
    sink: &mut W,
) -> Result<u64> {
    let _entropy = EntropyScope::install(options.entropy);
    validate_streamed_options(options, validate_encrypted_options)?;
    validate_nonempty_password(password)?;
    let header_keys = if options.features.header_encryption {
        Some(header_encryption_keys(password)?)
    } else {
        None
    };
    let payloads = entries
        .iter()
        .map(|entry| streamed_encrypted_payload(entry.size, entry.crc32, password))
        .collect::<Result<Vec<_>>>()?;
    let mut head = Vec::new();
    head.extend_from_slice(RAR50_SIGNATURE);
    if let Some(header_keys) = &header_keys {
        write_head_crypt(&mut head, header_keys)?;
        head.extend_from_slice(&encrypted_main_header_block(
            &header_keys.keys,
            0,
            None,
            &[],
        )?);
    } else {
        write_main_header(&mut head, 0, None, &[])?;
    }
    sink.write_all(&head)?;
    let mut written = head.len() as u64;
    let mut buffer = vec![0u8; STREAM_COPY_BYTES];
    let mut pending = Vec::with_capacity(STREAM_COPY_BYTES + 16);
    for (entry, encrypted) in entries.iter_mut().zip(&payloads) {
        let header = streamed_encrypted_fragment_header(
            entry,
            encrypted,
            encrypted.stream_len() as u64,
            false,
            false,
            header_keys.as_ref(),
        )?;
        sink.write_all(&header)?;
        written += header.len() as u64;
        let mut cipher = StreamCipher::new(encrypted.key, encrypted.iv);
        let mut plain_left = entry.size;
        while next_cipher_chunk(
            entry,
            &mut plain_left,
            &mut cipher,
            &mut buffer,
            &mut pending,
        )? {
            sink.write_all(&pending)?;
            written += pending.len() as u64;
            if plain_left == 0 {
                break;
            }
        }
    }
    let mut end = Vec::new();
    if let Some(header_keys) = &header_keys {
        end.extend_from_slice(&encrypted_header_block(
            &header_keys.keys,
            BLOCK_TYPE_END_OF_ARCHIVE,
            0,
            None,
            &end_header_specific(0),
            &[],
            &[],
        )?);
    } else {
        write_end_header(&mut end, 0)?;
    }
    sink.write_all(&end)?;
    written += end.len() as u64;
    sink.flush()?;
    Ok(written)
}

/// A volume set holding `entries`, stored and encrypted under `password`
/// (headers too when the feature says so), each volume written to the sink
/// `open_volume(index)` returns and filled to `max_encrypted_per_volume`
/// cipher bytes as `Rar50VolumeWriter::encrypted_stored_entries` fills
/// them. Byte-identical to that writer under the same entropy: every
/// member's salt and IV are drawn first, then the header keys, as it draws
/// them.
pub fn write_encrypted_stored_volumes_streamed<R: Read, W: Write, F>(
    options: WriterOptions,
    password: &[u8],
    max_encrypted_per_volume: usize,
    entries: &mut [StreamedStoredEntry<'_, R>],
    mut open_volume: F,
) -> Result<Vec<u64>>
where
    F: FnMut(u64) -> std::io::Result<W>,
{
    let _entropy = EntropyScope::install(options.entropy);
    validate_streamed_options(options, validate_encrypted_options)?;
    validate_nonempty_password(password)?;
    if max_encrypted_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted volume payload size must be non-zero",
        ));
    }
    if entries.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted stored volume writer needs at least one entry",
        ));
    }
    if entries.iter().any(|entry| entry.size == 0) {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted volume writer needs a non-empty payload",
        ));
    }
    let payloads = entries
        .iter()
        .map(|entry| streamed_encrypted_payload(entry.size, entry.crc32, password))
        .collect::<Result<Vec<_>>>()?;
    let header_keys = if options.features.header_encryption {
        Some(header_encryption_keys(password)?)
    } else {
        None
    };
    let max_data = max_encrypted_per_volume as u64;
    let mut buffer = vec![0u8; STREAM_COPY_BYTES];
    let mut pending: Vec<u8> = Vec::with_capacity(STREAM_COPY_BYTES + 16);
    let mut sizes = Vec::new();
    let mut current: Option<(W, u64)> = None;
    // A full volume held without its end header until the next opens
    // (`END_OF_ARCHIVE_NOT_LAST_VOLUME` on) or the set ends on it (off).
    let mut closed: Option<(W, u64)> = None;
    let mut payload_in_volume = 0u64;
    for (entry, encrypted) in entries.iter_mut().zip(&payloads) {
        let stream_len = encrypted.stream_len() as u64;
        let mut cipher = StreamCipher::new(encrypted.key, encrypted.iv);
        let mut plain_left = entry.size;
        // Cipher bytes of this member handed to fragments so far, and how
        // much of the open fragment is still to come.
        let mut cipher_pos = 0u64;
        let mut fragment_left = 0u64;
        let mut pending_from = 0usize;
        pending.clear();
        while cipher_pos < stream_len {
            if pending_from == pending.len() {
                if !next_cipher_chunk(
                    entry,
                    &mut plain_left,
                    &mut cipher,
                    &mut buffer,
                    &mut pending,
                )? {
                    return Err(Error::InvalidHeader(
                        "RAR 5 streamed member produced fewer cipher bytes than its stream",
                    ));
                }
                pending_from = 0;
            }
            if fragment_left == 0 {
                if current.is_none() || payload_in_volume == max_data {
                    debug_assert!(current.is_none(), "a full volume is closed as it fills");
                    if let Some((mut sink, written)) = closed.take() {
                        sizes.push(finish_streamed_volume_with_keys(
                            &mut sink,
                            written,
                            header_keys.as_ref(),
                            true,
                        )?);
                    }
                    let volume_number = sizes.len() as u64;
                    let mut sink = open_volume(volume_number)?;
                    let mut head = Vec::new();
                    write_volume_head(&mut head, volume_number, false, header_keys.as_ref(), None)?;
                    sink.write_all(&head)?;
                    current = Some((sink, head.len() as u64));
                    payload_in_volume = 0;
                }
                let fragment = (max_data - payload_in_volume).min(stream_len - cipher_pos);
                let header = streamed_encrypted_fragment_header(
                    entry,
                    encrypted,
                    fragment,
                    cipher_pos > 0,
                    cipher_pos + fragment < stream_len,
                    header_keys.as_ref(),
                )?;
                let (sink, written) = current.as_mut().expect("a volume is open");
                sink.write_all(&header)?;
                *written += header.len() as u64;
                fragment_left = fragment;
            }
            let (sink, written) = current.as_mut().expect("a volume is open");
            let take = (pending.len() - pending_from)
                .min(usize::try_from(fragment_left).unwrap_or(usize::MAX));
            sink.write_all(&pending[pending_from..pending_from + take])?;
            pending_from += take;
            *written += take as u64;
            cipher_pos += take as u64;
            payload_in_volume += take as u64;
            fragment_left -= take as u64;
            if payload_in_volume == max_data {
                debug_assert!(closed.is_none());
                closed = current.take();
            }
        }
    }
    if let Some((mut sink, written)) = current.take().or_else(|| closed.take()) {
        sizes.push(finish_streamed_volume_with_keys(
            &mut sink,
            written,
            header_keys.as_ref(),
            false,
        )?);
    }
    if sizes.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted volume writer needs at least two volumes",
        ));
    }
    Ok(sizes)
}

fn finish_streamed_volume_with_keys<W: Write>(
    sink: &mut W,
    written: u64,
    header_keys: Option<&HeaderEncryptionKeys>,
    next_volume: bool,
) -> Result<u64> {
    let mut end = Vec::new();
    write_volume_end(&mut end, header_keys, next_volume)?;
    sink.write_all(&end)?;
    sink.flush()?;
    Ok(written + end.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn options() -> WriterOptions {
        WriterOptions::new(crate::ArchiveVersion::Rar50, crate::FeatureSet::default())
            .with_compression_level(0)
    }

    /// A plain END header is the volume's last block, `[crc][size=3][5][0][flags]`,
    /// so its flags are the last byte while they fit a vint byte.
    fn end_flags(volume: &[u8]) -> u8 {
        *volume.last().unwrap()
    }

    /// Volumes collected in memory, one `Vec` per opened volume.
    #[derive(Clone)]
    struct Collected(std::rc::Rc<std::cell::RefCell<Vec<Vec<u8>>>>);
    struct CollectedVolume(Collected, usize);
    impl Write for CollectedVolume {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 .0.borrow_mut()[self.1].extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Collected {
        fn new() -> Self {
            Self(std::rc::Rc::new(std::cell::RefCell::new(Vec::new())))
        }
        fn opener(&self) -> impl FnMut(u64) -> std::io::Result<CollectedVolume> + '_ {
            move |number| {
                let mut volumes = self.0.borrow_mut();
                assert_eq!(volumes.len(), number as usize);
                volumes.push(Vec::new());
                Ok(CollectedVolume(self.clone(), number as usize))
            }
        }
        fn flags(&self) -> Vec<u8> {
            self.0.borrow().iter().map(|v| end_flags(v)).collect()
        }
    }

    /// Every streamed volume writer sets the END header's next-volume
    /// flag on every volume but the last - including a volume a member
    /// ends EXACTLY on, which was the shape native unrar stopped at.
    #[test]
    fn streamed_volumes_flag_the_next_volume_on_every_volume_but_the_last() {
        let a = [b'A'; 64];
        let b = [b'B'; 64];
        let long = [b'C'; 150];

        // Two members, each exactly one volume: [next, last].
        let set = Collected::new();
        let mut entries = [streamed(b"a.bin", &a), streamed(b"b.bin", &b)];
        write_stored_volumes_streamed(options(), 64, &mut entries, set.opener()).unwrap();
        assert_eq!(set.flags(), vec![1, 0]);

        // One member split over three volumes: [next, next, last].
        let set = Collected::new();
        let mut entries = [streamed(b"long.bin", &long)];
        write_stored_volumes_streamed(options(), 64, &mut entries, set.opener()).unwrap();
        assert_eq!(set.flags(), vec![1, 1, 0]);

        // With a recovery record per volume (the cut list knows).
        let set = Collected::new();
        let mut entries = [streamed(b"a.bin", &a), streamed(b"b.bin", &b)];
        let with_record = crate::FeatureSet {
            recovery_record: true,
            ..crate::FeatureSet::default()
        };
        let recovery =
            WriterOptions::new(crate::ArchiveVersion::Rar50, with_record).with_compression_level(0);
        write_stored_volumes_streamed_with_recovery(
            recovery,
            Some(3),
            64,
            &mut entries,
            set.opener(),
        )
        .unwrap();
        assert_eq!(set.flags(), vec![1, 0]);

        // The compressed streamed set (members end mid-volume here; the
        // rule is the same: last volume only carries 0).
        let set = Collected::new();
        let noise = |seed: u32| -> Vec<u8> {
            let mut x = seed;
            (0..1_000)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect()
        };
        let (n1, n2) = (noise(7), noise(11));
        let mut entries = [streamed(b"n1.bin", &n1), streamed(b"n2.bin", &n2)];
        let compressed =
            WriterOptions::new(crate::ArchiveVersion::Rar50, crate::FeatureSet::default());
        write_compressed_volumes_streamed(compressed, 500, &mut entries, set.opener()).unwrap();
        let flags = set.flags();
        assert!(flags.len() >= 2);
        assert_eq!(flags.last(), Some(&0));
        assert!(
            flags[..flags.len() - 1].iter().all(|&f| f == 1),
            "{flags:?}"
        );

        // Encrypted data (plain headers): the same, on the exact shape.
        let set = Collected::new();
        let features = crate::FeatureSet {
            file_encryption: true,
            ..crate::FeatureSet::default()
        };
        let encrypted =
            WriterOptions::new(crate::ArchiveVersion::Rar50, features).with_compression_level(0);
        let mut entries = [streamed(b"a.bin", &a), streamed(b"b.bin", &b)];
        let sizes = write_encrypted_stored_volumes_streamed(
            encrypted,
            b"pw",
            // The cipher stream of a 64-byte member is 64 bytes plus its
            // padding; one member per volume.
            80,
            &mut entries,
            set.opener(),
        )
        .unwrap();
        assert_eq!(sizes.len(), set.flags().len());
        let flags = set.flags();
        assert_eq!(flags.last(), Some(&0));
        assert!(
            flags[..flags.len() - 1].iter().all(|&f| f == 1),
            "{flags:?}"
        );
    }

    fn streamed<'a>(name: &'a [u8], data: &'a [u8]) -> StreamedStoredEntry<'a, Cursor<&'a [u8]>> {
        let (size, crc) = crc32_of_reader(&mut Cursor::new(data)).unwrap();
        assert_eq!(size, data.len() as u64);
        StreamedStoredEntry {
            name,
            mtime: None,
            attributes: 0,
            host_os: 3,
            size,
            crc32: crc,
            source: Cursor::new(data),
        }
    }

    /// A member's bytes collected out of an extraction.
    struct Collect(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);
    impl Write for Collect {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Every member of `archive` as (name, is a directory, bytes).
    fn extract_all(archive: &[u8]) -> Vec<(Vec<u8>, bool, Vec<u8>)> {
        let parsed = crate::rar50::Archive::parse(archive).unwrap();
        let entries = std::cell::RefCell::new(Vec::new());
        parsed
            .extract_to(crate::ArchiveReadOptions::default(), |meta| {
                let data = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
                entries.borrow_mut().push((
                    meta.name.clone(),
                    meta.is_directory,
                    std::rc::Rc::clone(&data),
                ));
                Ok(Box::new(Collect(data)))
            })
            .unwrap();
        entries
            .into_inner()
            .into_iter()
            .map(|(name, is_dir, data)| (name, is_dir, data.borrow().clone()))
            .collect()
    }

    /// The member writer is the entry writer over files, the in-memory
    /// writer over an empty file, and over a tree carries the directory
    /// and the empty file the entry writer refuses - read back by the
    /// crate's own extractor, one volume set included.
    #[test]
    fn streamed_members_carry_directories_and_empty_files() {
        let text = b"a line of text that repeats. ".repeat(4_000);
        let noise = payload(50_000, 3);
        let compressed = WriterOptions::new(crate::ArchiveVersion::Rar50, crate::FeatureSet::default())
            .with_compression_level(3);

        let mut entries = [streamed(b"text.txt", &text), streamed(b"noise.bin", &noise)];
        let mut expected = Vec::new();
        write_compressed_archive_streamed(compressed, &mut entries, &mut expected).unwrap();
        let mut members = [
            StreamedMember::File(streamed(b"text.txt", &text)),
            StreamedMember::File(streamed(b"noise.bin", &noise)),
        ];
        let mut out = Vec::new();
        write_compressed_members_streamed(compressed, &mut members, &mut out).unwrap();
        assert_eq!(out, expected, "files alone are the entry writer's bytes");

        let expected = Rar50Writer::new(compressed)
            .compressed_entries(&[
                CompressedEntry {
                    name: b"text.txt",
                    data: &text,
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                },
                CompressedEntry {
                    name: b"empty.txt",
                    data: b"",
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                },
            ])
            .finish()
            .unwrap();
        let mut members = [
            StreamedMember::File(streamed(b"text.txt", &text)),
            StreamedMember::File(streamed(b"empty.txt", b"")),
        ];
        let mut out = Vec::new();
        write_compressed_members_streamed(compressed, &mut members, &mut out).unwrap();
        assert_eq!(out, expected, "an empty file is stored as the in-memory writer stores it");

        let dir = StreamedDirectoryEntry {
            name: b"sub",
            mtime: Some(1_000_000_000),
            attributes: 0o040_755,
            host_os: 1,
        };
        let mut members = [
            StreamedMember::File(streamed(b"sub/text.txt", &text)),
            StreamedMember::File(streamed(b"sub/empty.txt", b"")),
            StreamedMember::Directory(dir),
            StreamedMember::File(streamed(b"noise.bin", &noise)),
        ];
        let mut out = Vec::new();
        write_compressed_members_streamed(compressed, &mut members, &mut out).unwrap();
        let parsed = crate::rar50::Archive::parse(&out).unwrap();
        let listed: Vec<(Vec<u8>, bool)> = parsed
            .files()
            .map(|file| (file.name_bytes().to_vec(), file.is_directory()))
            .collect();
        assert_eq!(
            listed,
            vec![
                (b"sub/text.txt".to_vec(), false),
                (b"sub/empty.txt".to_vec(), false),
                (b"sub".to_vec(), true),
                (b"noise.bin".to_vec(), false),
            ]
        );
        for (name, is_dir, data) in extract_all(&out) {
            match name.as_slice() {
                b"sub/text.txt" => assert_eq!(data, text),
                b"sub/empty.txt" => assert!(data.is_empty() && !is_dir),
                b"sub" => assert!(is_dir && data.is_empty()),
                b"noise.bin" => assert_eq!(data, noise),
                other => panic!("unexpected member {:?}", String::from_utf8_lossy(other)),
            }
        }

        // Incompressible, so the set really does span volumes: the text
        // and the patterned payload above pack into a few kilobytes.
        let random = |len: usize, seed: u32| -> Vec<u8> {
            let mut x = seed;
            (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect()
        };
        let (first, second) = (random(9_000, 7), random(6_000, 11));
        let set = Collected::new();
        let mut members = [
            StreamedMember::File(streamed(b"sub/first.bin", &first)),
            StreamedMember::File(streamed(b"sub/empty.txt", b"")),
            StreamedMember::Directory(dir),
            StreamedMember::File(streamed(b"second.bin", &second)),
        ];
        write_compressed_member_volumes_streamed(compressed, 4_000, &mut members, set.opener())
            .unwrap();
        let volumes = set.0.borrow();
        assert!(volumes.len() >= 2, "{} volumes", volumes.len());
        let flags: Vec<u8> = volumes.iter().map(|v| end_flags(v)).collect();
        assert_eq!(flags.last(), Some(&0));
        assert!(flags[..flags.len() - 1].iter().all(|&f| f == 1), "{flags:?}");
        // Each header-only member lands in exactly one volume. The empty
        // file is the one that went missing first: the volume sink cut
        // members into fragments, and an empty one has none to cut.
        for (name, is_dir) in [(&b"sub"[..], true), (&b"sub/empty.txt"[..], false)] {
            let holding = volumes
                .iter()
                .filter(|v| {
                    crate::rar50::Archive::parse(v)
                        .map(|a| {
                            a.files()
                                .any(|f| f.is_directory() == is_dir && f.name_bytes() == name)
                        })
                        .unwrap_or(false)
                })
                .count();
            assert_eq!(holding, 1, "{} lands in exactly one volume", String::from_utf8_lossy(name));
        }
    }

    /// The streamed archive is the in-memory writer's archive, byte for byte.
    #[test]
    fn streamed_archive_matches_the_in_memory_writer() {
        let a = payload(300_000, 1);
        let b = payload(70_001, 2);
        let expected = Rar50Writer::new(options())
            .stored_entries(&[
                StoredEntry {
                    name: b"a.bin",
                    data: &a,
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                },
                StoredEntry {
                    name: b"b.bin",
                    data: &b,
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                },
            ])
            .finish()
            .unwrap();
        let mut out = Vec::new();
        let mut entries = [streamed(b"a.bin", &a), streamed(b"b.bin", &b)];
        let written = write_stored_archive_streamed(options(), &mut entries, &mut out).unwrap();
        assert_eq!(written, out.len() as u64);
        assert_eq!(out, expected);
    }

    /// The streamed volume set is the in-memory volume writer's set, byte
    /// for byte - including a member cut mid-volume and a partial last one.
    #[test]
    fn streamed_volumes_match_the_in_memory_volume_writer() {
        let a = payload(1_000_003, 5);
        let b = payload(250_000, 9);
        let per_volume = 300_000;
        let expected = Rar50VolumeWriter::new(options())
            .max_payload_per_volume(per_volume)
            .stored_entries(&[
                StoredEntry {
                    name: b"a.bin",
                    data: &a,
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                },
                StoredEntry {
                    name: b"b.bin",
                    data: &b,
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                },
            ])
            .finish()
            .unwrap();
        let mut entries = [streamed(b"a.bin", &a), streamed(b"b.bin", &b)];
        VOLUMES.with(|v| v.borrow_mut().clear());
        let mut opened = 0u64;
        let sizes = write_stored_volumes_streamed(options(), per_volume, &mut entries, |index| {
            assert_eq!(index, opened, "volumes are opened in order");
            opened += 1;
            Ok(VolumeSink(index as usize))
        })
        .unwrap();
        // The sink handles wrote into the thread-local store.
        let volumes = VOLUMES.with(|v| std::mem::take(&mut *v.borrow_mut()));
        assert_eq!(volumes.len(), expected.len(), "volume count");
        assert_eq!(
            sizes,
            volumes.iter().map(|v| v.len() as u64).collect::<Vec<_>>()
        );
        for (index, (ours, theirs)) in volumes.iter().zip(&expected).enumerate() {
            assert_eq!(ours, theirs, "volume {index}");
        }
    }

    /// Text-like bytes: words from a small vocabulary, so the member packs
    /// to a few times smaller and a split set cuts it across volumes.
    fn text(len: usize, seed: u64) -> Vec<u8> {
        let words: Vec<String> = (0..64)
            .map(|w| {
                (0..3 + w % 6)
                    .map(|c| (b'a' + ((w * 7 + c * 13) % 26) as u8) as char)
                    .collect()
            })
            .collect();
        let mut state = seed;
        let mut out = Vec::with_capacity(len + 16);
        while out.len() < len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            out.extend_from_slice(words[(state >> 58) as usize].as_bytes());
            out.push(if state >> 40 & 15 == 0 { b'\n' } else { b' ' });
        }
        out.truncate(len);
        out
    }

    /// Bytes no sampler window shrinks.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn compressed_options(dictionary: u64) -> WriterOptions {
        WriterOptions::new(crate::ArchiveVersion::Rar50, crate::FeatureSet::default())
            .with_compression_level(3)
            .with_dictionary_size(dictionary)
    }

    /// The members the compressed identity tests use: a text member of
    /// three blocks (encoded from several windows at the test's window of
    /// one block, cut across volumes), a member of one block (the
    /// single-block path), and a noise member the sampler stores.
    fn compressed_members() -> [(&'static [u8], Vec<u8>); 3] {
        let block = crate::codec::rar50::MAX_COMPRESSED_BLOCK_OUTPUT;
        [
            (b"text.txt", text(2 * block + 12_345, 7)),
            (b"small.txt", text(300_001, 11)),
            (
                b"noise.bin",
                noise(super::super::filter_policy::INCOMPRESSIBLE_SAMPLE_MIN + 9, 13),
            ),
        ]
    }

    /// A panicking encoder must come back as an ERROR, not as a panic.
    ///
    /// This is a regression test for the shape, not just the symptom. The
    /// workers are parked and REUSED across members, so nothing ever joins
    /// them - and `std::thread::scope` panics at its end whenever a thread
    /// panicked and nothing consumed the panic (`join` consumes it by taking
    /// the result out of the packet; a channel recv does not). So the
    /// `catch_unwind` inside the worker is what makes the error path in
    /// `drain_one` reachable at all. Delete it and this test panics instead
    /// of returning, which is exactly the regression it guards.
    #[test]
    fn the_streamed_writer_reports_a_panicking_encoder_as_an_error() {
        let block = crate::codec::rar50::MAX_COMPRESSED_BLOCK_OUTPUT;
        // Several small members, so the queue really does park and reuse a
        // worker rather than running one member on one thread.
        let mut poisoned = PANIC_MARKER.to_vec();
        poisoned.extend_from_slice(&text(200_003, 5));
        let members: Vec<(&[u8], Vec<u8>)> = vec![
            (b"a.txt", text(150_001, 3)),
            (b"b.txt", text(150_002, 4)),
            (b"poison.txt", poisoned),
            (b"d.txt", text(150_004, 6)),
        ];
        let options = compressed_options(128 << 10);
        let mut streamed: Vec<_> = members
            .iter()
            .map(|(name, data)| self::streamed(name, data))
            .collect();
        let mut out = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            write_compressed_archive_streamed_with_windows(
                options,
                &mut streamed,
                &mut out,
                StreamWindows::uniform(8),
            )
        }));
        let _ = block;
        match result {
            Ok(Err(Error::InvalidHeader(message))) => {
                assert!(
                    message.contains("encoder panicked"),
                    "unexpected error: {message}"
                );
            }
            Ok(Ok(_)) => panic!("the poisoned member encoded successfully"),
            Ok(Err(other)) => panic!("unexpected error: {other:?}"),
            Err(_) => panic!("the writer PANICKED instead of returning an error"),
        }
    }

    /// One cell of the streamed-writer identity table: the streamed
    /// compressed archive is `Rar50Writer::compressed_entries`' archive byte
    /// for byte - the windowed encode, the single-block path and the
    /// sampler's store all match.
    ///
    /// Each shape runs under BOTH parsers. The cost-based one reaches this
    /// writer through `encode_options_for_level` and carries state the
    /// greedy walk does not - a price model that settles on its own region
    /// boundaries, and a repeat state per program node - and the streamed
    /// writer encodes WINDOWS of whole blocks where the in-memory one holds
    /// the member, so a parse that carried anything across a block boundary
    /// would show up here and nowhere else.
    /// `the_cost_based_parse_reaches_the_streamed_writer` holds the
    /// `optimal_parse` arm to being a real arm, because two writers that
    /// both ignored the flag would agree here just as happily.
    /// (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
    ///
    /// ONE TEST PER CELL rather than a loop over the six shapes, and that is
    /// a wall-clock decision with no coverage in it: nightly's `armv7-cross`
    /// kills a test at 900 s under qemu and the loop was 531.1 s of that
    /// budget in ONE test (run 34583096699), a margin of 1.7x with nothing
    /// watching it. nextest gives each cell its own process and runs them
    /// concurrently, so the split moves work sideways: the worst cell is an
    /// estimated 228 s. Measured per cell on the emulated target, because
    /// the cost is NOT spread evenly over the table - the cells span 9x,
    /// from 4.46 s to 42.62 s, with `optimal_parse` worth 2x to 5x of it
    /// at a fixed dictionary. It costs about 19% more total CPU, since
    /// each cell now builds
    /// `compressed_members()` for itself (~3.8 s under qemu) where the loop
    /// built it once; that is paid in parallel and a `OnceLock` would buy
    /// nothing under nextest, which runs each test in its own process.
    /// Numbers, rig and what is scaled rather than measured: the host
    /// repo's `research/ARMV7-CROSS-TEST-CEILING-2026-09-11.md`.
    /// (nzbfast-local change, 11 Sep 2026.)
    fn streamed_compressed_matches_the_in_memory_writer(
        dictionary: u64,
        windows: StreamWindows,
        optimal_parse: bool,
    ) {
        let members = compressed_members();
        let options = compressed_options(dictionary).with_optimal_parse(optimal_parse);
        let entries: Vec<CompressedEntry<'_>> = members
            .iter()
            .map(|(name, data)| CompressedEntry {
                name,
                data,
                mtime: None,
                attributes: 0,
                host_os: 3,
            })
            .collect();
        let expected = Rar50Writer::new(options)
            .compressed_entries(&entries)
            .finish()
            .unwrap();
        let mut streamed: Vec<_> = members
            .iter()
            .map(|(name, data)| self::streamed(name, data))
            .collect();
        let mut out = Vec::new();
        let written = write_compressed_archive_streamed_with_windows(
            options,
            &mut streamed,
            &mut out,
            windows,
        )
        .unwrap();
        assert_eq!(written, out.len() as u64);
        assert_eq!(
            out, expected,
            "dictionary {dictionary}, windows {windows:?}, optimal {optimal_parse}"
        );
        assert!(
            out.len() < members.iter().map(|(_, d)| d.len()).sum::<usize>(),
            "the text members compressed"
        );
    }

    /// Two blocks of dictionary, so a window carries two history blocks.
    fn two_block_dictionary() -> u64 {
        2 * crate::codec::rar50::MAX_COMPRESSED_BLOCK_OUTPUT as u64
    }

    // A window of one block: the text member goes through windows, the
    // noise member through the seeking sampler.
    #[test]
    fn streamed_matches_the_in_memory_writer_at_a_sub_block_dictionary_lazily() {
        streamed_compressed_matches_the_in_memory_writer(128 << 10, StreamWindows::uniform(1), false);
    }

    #[test]
    fn streamed_matches_the_in_memory_writer_at_a_sub_block_dictionary_optimally() {
        streamed_compressed_matches_the_in_memory_writer(128 << 10, StreamWindows::uniform(1), true);
    }

    #[test]
    fn streamed_matches_the_in_memory_writer_at_a_two_block_dictionary_lazily() {
        streamed_compressed_matches_the_in_memory_writer(two_block_dictionary(), StreamWindows::uniform(1), false);
    }

    #[test]
    fn streamed_matches_the_in_memory_writer_at_a_two_block_dictionary_optimally() {
        streamed_compressed_matches_the_in_memory_writer(two_block_dictionary(), StreamWindows::uniform(1), true);
    }

    // One block of admission and windows of two, the split an allowance
    // makes (`StreamWindows`): the text member goes through windows wider
    // than the width that sent it there, behind two blocks of history.
    #[test]
    fn streamed_matches_the_in_memory_writer_in_windows_wider_than_admission_lazily() {
        let windows = StreamWindows {
            members: 1,
            segment: 2,
        };
        streamed_compressed_matches_the_in_memory_writer(two_block_dictionary(), windows, false);
    }

    #[test]
    fn streamed_matches_the_in_memory_writer_in_windows_wider_than_admission_optimally() {
        let windows = StreamWindows {
            members: 1,
            segment: 2,
        };
        streamed_compressed_matches_the_in_memory_writer(two_block_dictionary(), windows, true);
    }

    // A window of eight: every member is a job held whole, the noise
    // member sampled in hand.
    #[test]
    fn streamed_matches_the_in_memory_writer_in_windows_of_eight_lazily() {
        streamed_compressed_matches_the_in_memory_writer(128 << 10, StreamWindows::uniform(8), false);
    }

    #[test]
    fn streamed_matches_the_in_memory_writer_in_windows_of_eight_optimally() {
        streamed_compressed_matches_the_in_memory_writer(128 << 10, StreamWindows::uniform(8), true);
    }

    /// The `optimal_parse` arm of the six identity cells above has to BE
    /// an arm (one test per cell since 11 Sep 2026; it was one test with a
    /// table in it, and the `_optimally` half of those names is that arm):
    /// the flag travels from `WriterOptions` through
    /// `encode_options_for_level` into the tokenizer, and two writers that
    /// both dropped it on the way would agree with each other perfectly.
    /// So the flag has to change the bytes, and change them the way it is
    /// there for.
    #[test]
    fn the_cost_based_parse_reaches_the_streamed_writer() {
        let members = compressed_members();
        let mut packed = Vec::new();
        for optimal_parse in [false, true] {
            let options = compressed_options(128 << 10).with_optimal_parse(optimal_parse);
            let mut streamed: Vec<_> = members
                .iter()
                .map(|(name, data)| self::streamed(name, data))
                .collect();
            let mut out = Vec::new();
            write_compressed_archive_streamed_with_windows(options, &mut streamed, &mut out, StreamWindows::uniform(1))
                .unwrap();
            packed.push(out.len());
        }
        assert!(
            packed[1] < packed[0],
            "the cost-based parse wrote {} bytes against the lazy walk's {}",
            packed[1],
            packed[0]
        );
    }

    /// The per-region tokenizer horizon choice reaches this writer, and
    /// the windowed encode makes the SAME choices as the in-memory one.
    ///
    /// Both halves matter and neither covers the other. The streamed
    /// writer encodes windows of whole blocks, so a per-region choice that
    /// depended on anything but the region's own bytes and the raw member
    /// history in front of them would put the two writers' archives apart
    /// here. And "the two archives agree" is also what two writers that
    /// both dropped the flag would say, which is what the size assertion
    /// rules out: the member is material whose regions do not all want the
    /// same horizon (`codec::rar50::horizon_material`), so the switch has
    /// to write FEWER bytes, and it can never write more.
    /// (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
    #[test]
    fn the_region_horizon_choice_reaches_the_streamed_writer() {
        let block = crate::codec::rar50::MAX_COMPRESSED_BLOCK_OUTPUT;
        let data = crate::codec::rar50::horizon_material(block + 500_000);
        let mut packed = Vec::new();
        for horizon in [false, true] {
            let options = compressed_options(block as u64).with_tokenizer_horizon_choice(horizon);
            let expected = Rar50Writer::new(options)
                .compressed_entries(&[CompressedEntry {
                    name: b"mixed.bin",
                    data: &data,
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                }])
                .finish()
                .unwrap();
            let mut streamed = [self::streamed(b"mixed.bin", &data)];
            let mut out = Vec::new();
            write_compressed_archive_streamed_with_windows(options, &mut streamed, &mut out, StreamWindows::uniform(1))
                .unwrap();
            assert_eq!(out, expected, "horizon choice {horizon}");
            packed.push(out.len());
        }
        assert!(
            packed[1] < packed[0],
            "the horizon choice wrote {} bytes against {} with it off",
            packed[1],
            packed[0],
        );
    }

    /// The streamed compressed volume set is `Rar50VolumeWriter`'s set byte
    /// for byte, with the text member's packed bytes cut across volumes as
    /// they fill and the stored noise member cut likewise.
    #[test]
    fn streamed_compressed_volumes_match_the_in_memory_volume_writer() {
        for segment_blocks in [1usize, 8] {
            streamed_compressed_volumes_match_at(segment_blocks);
        }
    }

    fn streamed_compressed_volumes_match_at(segment_blocks: usize) {
        let members = compressed_members();
        let options = compressed_options(128 << 10);
        let per_volume = 700_000;
        let entries: Vec<CompressedEntry<'_>> = members
            .iter()
            .map(|(name, data)| CompressedEntry {
                name,
                data,
                mtime: None,
                attributes: 0,
                host_os: 3,
            })
            .collect();
        let expected = Rar50VolumeWriter::new(options)
            .max_payload_per_volume(per_volume)
            .compressed_entries(&entries)
            .finish()
            .unwrap();
        let mut streamed: Vec<_> = members
            .iter()
            .map(|(name, data)| self::streamed(name, data))
            .collect();
        VOLUMES.with(|v| v.borrow_mut().clear());
        let mut opened = 0u64;
        let sizes = write_compressed_volumes_streamed_with_windows(
            options,
            per_volume,
            &mut streamed,
            |index| {
                assert_eq!(index, opened, "volumes are opened in order");
                opened += 1;
                Ok(VolumeSink(index as usize))
            },
            StreamWindows::uniform(segment_blocks),
        )
        .unwrap();
        let volumes = VOLUMES.with(|v| std::mem::take(&mut *v.borrow_mut()));
        assert_eq!(volumes.len(), expected.len(), "volume count");
        assert!(volumes.len() > 4, "{} volumes", volumes.len());
        assert_eq!(
            sizes,
            volumes.iter().map(|v| v.len() as u64).collect::<Vec<_>>()
        );
        for (index, (ours, theirs)) in volumes.iter().zip(&expected).enumerate() {
            assert_eq!(ours, theirs, "volume {index}");
        }
    }

    /// Level 5 and the other features the streamed writers do not build
    /// are refused by name.
    #[test]
    fn streamed_compressed_writers_refuse_level_five() {
        let data = text(1000, 1);
        let mut entries = [streamed(b"a.txt", &data)];
        let mut out = Vec::new();
        let error = write_compressed_archive_streamed(
            compressed_options(128 << 10).with_compression_level(5),
            &mut entries,
            &mut out,
        )
        .unwrap_err();
        assert!(
            matches!(error, Error::UnsupportedFeature { feature, .. } if feature.contains("level-5")),
            "{error:?}"
        );
    }

    fn recovery_options() -> WriterOptions {
        let features = crate::FeatureSet {
            recovery_record: true,
            ..crate::FeatureSet::default()
        };
        WriterOptions::new(crate::ArchiveVersion::Rar50, features).with_compression_level(0)
    }

    /// The streamed stored archive with a recovery record is
    /// `Rar50Writer::recovery_percent`'s archive byte for byte: a member
    /// long enough for the record to span several groups (over 13 MB), an
    /// odd total length, and a small second member.
    #[test]
    fn streamed_stored_archive_with_recovery_matches_the_in_memory_writer() {
        let a = payload(14_000_001, 3);
        let b = payload(70_003, 4);
        let entries = [
            StoredEntry {
                name: b"a.bin",
                data: &a,
                mtime: None,
                attributes: 0,
                host_os: 3,
            },
            StoredEntry {
                name: b"b.bin",
                data: &b,
                mtime: None,
                attributes: 0,
                host_os: 3,
            },
        ];
        for percent in [3u64, 10] {
            let expected = Rar50Writer::new(recovery_options())
                .recovery_percent(Some(percent))
                .stored_entries(&entries)
                .finish()
                .unwrap();
            let mut out = Vec::new();
            let mut streamed = [streamed(b"a.bin", &a), streamed(b"b.bin", &b)];
            let written = write_stored_archive_streamed_with_recovery(
                recovery_options(),
                Some(percent),
                &mut streamed,
                &mut out,
            )
            .unwrap();
            assert_eq!(written, out.len() as u64);
            assert_eq!(out.len(), expected.len(), "percent {percent}: length");
            assert!(out == expected, "percent {percent}: bytes differ");
        }
    }

    /// The streamed stored volume set with recovery records is
    /// `Rar50VolumeWriter::recovery_percent`'s set byte for byte, each
    /// volume carrying its own record over its own bytes.
    #[test]
    fn streamed_stored_volumes_with_recovery_match_the_in_memory_volume_writer() {
        let a = payload(1_000_003, 5);
        let b = payload(250_000, 9);
        let per_volume = 300_000;
        let expected = Rar50VolumeWriter::new(recovery_options())
            .max_payload_per_volume(per_volume)
            .recovery_percent(Some(5))
            .stored_entries(&[
                StoredEntry {
                    name: b"a.bin",
                    data: &a,
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                },
                StoredEntry {
                    name: b"b.bin",
                    data: &b,
                    mtime: None,
                    attributes: 0,
                    host_os: 3,
                },
            ])
            .finish()
            .unwrap();
        let mut entries = [streamed(b"a.bin", &a), streamed(b"b.bin", &b)];
        VOLUMES.with(|v| v.borrow_mut().clear());
        let sizes = write_stored_volumes_streamed_with_recovery(
            recovery_options(),
            Some(5),
            per_volume,
            &mut entries,
            |index| Ok(VolumeSink(index as usize)),
        )
        .unwrap();
        let volumes = VOLUMES.with(|v| std::mem::take(&mut *v.borrow_mut()));
        assert_eq!(volumes.len(), expected.len(), "volume count");
        assert_eq!(
            sizes,
            volumes.iter().map(|v| v.len() as u64).collect::<Vec<_>>()
        );
        for (index, (ours, theirs)) in volumes.iter().zip(&expected).enumerate() {
            assert!(ours == theirs, "volume {index} differs");
        }
    }

    /// The feature flag and the percentage must come together.
    #[test]
    fn streamed_recovery_needs_the_flag_and_the_percentage_together() {
        let data = payload(1000, 1);
        let mut out = Vec::new();
        let mut entries = [streamed(b"a.bin", &data)];
        assert!(write_stored_archive_streamed_with_recovery(
            recovery_options(),
            None,
            &mut entries,
            &mut out
        )
        .is_err());
        let mut entries = [streamed(b"a.bin", &data)];
        assert!(
            write_stored_archive_streamed_with_recovery(options(), Some(3), &mut entries, &mut out)
                .is_err()
        );
    }

    thread_local! {
        static VOLUMES: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    /// A `Write` handle onto one volume in the thread-local store.
    struct VolumeSink(usize);

    impl Write for VolumeSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            VOLUMES.with(|v| {
                let mut v = v.borrow_mut();
                if v.len() <= self.0 {
                    v.resize(self.0 + 1, Vec::new());
                }
                v[self.0].extend_from_slice(buf);
            });
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn seeded(header_encryption: bool) -> WriterOptions {
        let features = crate::FeatureSet {
            file_encryption: true,
            header_encryption,
            ..crate::FeatureSet::default()
        };
        WriterOptions::new(crate::ArchiveVersion::Rar50, features)
            .with_compression_level(0)
            .with_entropy(crate::Entropy::Seeded([7u8; 32]))
    }

    /// The streamed encrypted archive is the in-memory writer's, byte for
    /// byte, under the same seeded entropy - headers plain and encrypted,
    /// a member whose length is not a block multiple.
    #[test]
    fn streamed_encrypted_archive_matches_the_in_memory_writer() {
        for header_encryption in [false, true] {
            let a = payload(300_001, 1);
            let b = payload(64_000, 2);
            let pw = b"benchpw";
            let expected = Rar50Writer::new(seeded(header_encryption))
                .encrypted_stored_entries(&[
                    EncryptedStoredEntry {
                        name: b"a.bin",
                        data: &a,
                        mtime: None,
                        attributes: 0,
                        host_os: 3,
                        password: pw,
                    },
                    EncryptedStoredEntry {
                        name: b"b.bin",
                        data: &b,
                        mtime: None,
                        attributes: 0,
                        host_os: 3,
                        password: pw,
                    },
                ])
                .finish()
                .unwrap();
            let mut out = Vec::new();
            let mut entries = [streamed(b"a.bin", &a), streamed(b"b.bin", &b)];
            let written = write_encrypted_stored_archive_streamed(
                seeded(header_encryption),
                pw,
                &mut entries,
                &mut out,
            )
            .unwrap();
            assert_eq!(written, out.len() as u64);
            assert_eq!(out, expected, "header_encryption {header_encryption}");
        }
    }

    /// ...and so is the streamed encrypted volume set, with cuts that fall
    /// inside cipher blocks and a member that straddles volumes.
    #[test]
    fn streamed_encrypted_volumes_match_the_in_memory_volume_writer() {
        for header_encryption in [false, true] {
            let a = payload(1_000_003, 5);
            let b = payload(250_007, 9);
            let per_volume = 300_005;
            let pw = b"benchpw";
            let expected = Rar50VolumeWriter::new(seeded(header_encryption))
                .max_payload_per_volume(per_volume)
                .encrypted_stored_entries(&[
                    EncryptedStoredEntry {
                        name: b"a.bin",
                        data: &a,
                        mtime: None,
                        attributes: 0,
                        host_os: 3,
                        password: pw,
                    },
                    EncryptedStoredEntry {
                        name: b"b.bin",
                        data: &b,
                        mtime: None,
                        attributes: 0,
                        host_os: 3,
                        password: pw,
                    },
                ])
                .finish()
                .unwrap();
            let mut entries = [streamed(b"a.bin", &a), streamed(b"b.bin", &b)];
            VOLUMES.with(|v| v.borrow_mut().clear());
            let sizes = write_encrypted_stored_volumes_streamed(
                seeded(header_encryption),
                pw,
                per_volume,
                &mut entries,
                |index| Ok(VolumeSink(index as usize)),
            )
            .unwrap();
            let volumes = VOLUMES.with(|v| std::mem::take(&mut *v.borrow_mut()));
            assert_eq!(volumes.len(), expected.len(), "volume count");
            assert_eq!(
                sizes,
                volumes.iter().map(|v| v.len() as u64).collect::<Vec<_>>()
            );
            for (index, (ours, theirs)) in volumes.iter().zip(&expected).enumerate() {
                assert_eq!(
                    ours, theirs,
                    "volume {index}, header_encryption {header_encryption}"
                );
            }
        }
    }

    #[test]
    fn a_short_source_is_refused_rather_than_padded() {
        let a = payload(1000, 3);
        let mut entry = streamed(b"a.bin", &a);
        entry.size = 1001;
        let mut out = Vec::new();
        assert!(write_stored_archive_streamed(options(), &mut [entry], &mut out).is_err());
    }

    #[test]
    fn features_the_first_cut_does_not_carry_are_refused_by_name() {
        let a = payload(100, 4);
        let features = crate::FeatureSet {
            recovery_record: true,
            ..crate::FeatureSet::default()
        };
        let options =
            WriterOptions::new(crate::ArchiveVersion::Rar50, features).with_compression_level(3);
        let mut out = Vec::new();
        // The compressed writer does not carry a recovery record.
        let err = write_compressed_archive_streamed(options, &mut [streamed(b"a", &a)], &mut out)
            .unwrap_err();
        assert!(matches!(err, Error::UnsupportedFeature { .. }), "{err:?}");
        let features = crate::FeatureSet {
            solid: true,
            ..crate::FeatureSet::default()
        };
        let options =
            WriterOptions::new(crate::ArchiveVersion::Rar50, features).with_compression_level(0);
        let err = write_stored_archive_streamed(options, &mut [streamed(b"a", &a)], &mut out)
            .unwrap_err();
        assert!(matches!(err, Error::UnsupportedFeature { .. }), "{err:?}");
    }
}
