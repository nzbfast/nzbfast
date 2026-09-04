use super::*;
use crate::write_entropy::EntropyScope;
use crate::codec::rar13::{
    unpack15_encode_with_options_and_progress, EncodeOptions as Rar15EncodeOptions, Unpack15Encoder,
};
use crate::codec::rar20::{
    unpack20_encode_auto_with_options_and_progress, EncodeOptions as Rar20EncodeOptions,
    Unpack20Encoder,
};
use crate::codec::rar29::{
    unpack29_encode_literals, unpack29_encode_literals_with_options,
    unpack29_encode_literals_with_options_and_progress, unpack29_encode_ppmd,
    unpack29_encode_ppmd_with_filter, EncodeOptions as Rar29EncodeOptions, Unpack29Encoder,
};
pub use crate::codec::rar29::{Rar29FilterKind as FilterKind, Rar29FilterSpec as FilterSpec};
use crate::io_util::align16 as checked_align16;
use crate::write_progress::{ProgressReporter, WorkTracker};
use crate::x86_filter_scan::auto_x86_filter_ranges;
use crate::{WriteOperation, WriteProgress, WriteProgressEvent};

const AUTO_RGB_WIDTHS: [usize; 4] = [24, 48, 96, 192];
const AUTO_DELTA_EDGE_SKIP: usize = 64;
const MIN_STORE_FALLBACK_SIZE: usize = 1024;
const RAR29_LARGE_TEXT_PPMD_THRESHOLD: usize = 16 * 1024 * 1024;
const RAR29_TEXT_SAMPLE_SIZE: usize = 8192;
const RAR29_AUDIO_SAMPLE_SIZE: usize = 8192;
const RAR29_LZ_BLOCK_SIZE: usize = 1024 * 1024;
const RAR15_ALIGN_OVERFLOW: &str = "RAR 1.5 block size overflows usize";

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
    // Held for the whole archive: the salt draw below reads it back off
    // this thread. Never `let _ =`, which would drop it here and put the
    // writer back on OS entropy. Only the five functions that do the
    // work install one - the wrappers above them delegate here, and a
    // second install would restart the seeded sequence mid-archive.
    let _entropy = EntropyScope::install(options.entropy);
    let has_file_comment = entries.iter().any(|entry| entry.file_comment.is_some());
    validate_stored_writer_options(options, archive_comment.is_some(), has_file_comment)?;
    if options.features.header_encryption {
        return write_header_encrypted_stored_archive(entries, options, archive_comment);
    }

    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    write_main_header(
        &mut out,
        recovery_main_flags(options)
            | if archive_comment.is_some() && uses_old_style_archive_comment(options.target) {
                MHD_COMMENT
            } else {
                0
            },
    );
    write_archive_comment(&mut out, archive_comment, options.target)?;
    for entry in entries {
        write_stored_entry(&mut out, entry, options)?;
    }
    append_recovery_record(&mut out, options)?;
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
    // Held for the whole archive: the salt draw below reads it back off
    // this thread. Never `let _ =`, which would drop it here and put the
    // writer back on OS entropy. Only the five functions that do the
    // work install one - the wrappers above them delegate here, and a
    // second install would restart the seeded sequence mid-archive.
    let _entropy = EntropyScope::install(options.entropy);
    let total_bytes: u64 = entries.iter().map(|entry| entry.data.len() as u64).sum();
    let total_work = if options.target == ArchiveVersion::Rar20 && !options.features.solid {
        total_bytes.saturating_mul(2)
    } else {
        total_bytes
    };
    report_compression_operation(progress, true, total_work, entries.len());
    let work = WorkTracker::new(
        progress.map(ProgressReporter),
        WriteOperation::Compression,
        total_work,
    );
    let result =
        write_compressed_archive_with_comment_impl(entries, options, archive_comment, Some(&work));
    if result.is_ok() && !work.finish() {
        return Err(Error::Cancelled);
    }
    report_compression_operation(progress, false, total_work, entries.len());
    result
}

fn write_compressed_archive_with_comment_impl(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<u8>> {
    let has_file_comment = entries.iter().any(|entry| entry.file_comment.is_some());
    validate_compressed_writer_options(options, archive_comment.is_some(), has_file_comment)?;
    if options.features.header_encryption {
        return write_header_encrypted_compressed_archive(entries, options, archive_comment);
    }

    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    let mut main_flags =
        recovery_main_flags(options) | if options.features.solid { MHD_SOLID } else { 0 };
    if archive_comment.is_some() && uses_old_style_archive_comment(options.target) {
        main_flags |= MHD_COMMENT;
    }
    write_main_header(&mut out, main_flags);
    write_archive_comment(&mut out, archive_comment, options.target)?;
    if options.features.solid {
        let mut solid_encoder = SolidEncoder::for_target(options, true)?;
        let mut solid_run_has_member = false;
        for entry in entries {
            let payload =
                encode_or_store_payload(entry.data, options, &mut solid_encoder, progress)?;
            let solid_continuation = payload.method != 0x30 && solid_run_has_member;
            write_compressed_entry(
                &mut out,
                entry,
                &payload.data,
                payload.method,
                options.target,
                dictionary_flags_for_options(options)?,
                solid_continuation,
            )?;
            solid_run_has_member = payload.method != 0x30;
        }
    } else {
        let payloads = encode_independent_payloads(entries, options, progress)?;
        for (entry, payload) in entries.iter().zip(&payloads) {
            write_compressed_entry(
                &mut out,
                entry,
                &payload.data,
                payload.method,
                options.target,
                dictionary_flags_for_options(options)?,
                false,
            )?;
        }
    }
    append_recovery_record(&mut out, options)?;
    Ok(out)
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum FilterPolicy {
    Lz,
    Auto,
    Explicit(FilterSpec),
    Ppmd,
    PpmdFiltered(FilterSpec),
}

pub fn write_rar29_compressed_archive_with_filter_policy(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    policy: FilterPolicy,
) -> Result<Vec<u8>> {
    write_rar29_compressed_archive_with_filter_policy_and_progress(entries, options, policy, None)
}

pub fn write_rar29_compressed_archive_with_filter_policy_and_progress(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    policy: FilterPolicy,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<u8>> {
    // Held for the whole archive: the salt draw below reads it back off
    // this thread. Never `let _ =`, which would drop it here and put the
    // writer back on OS entropy. Only the five functions that do the
    // work install one - the wrappers above them delegate here, and a
    // second install would restart the seeded sequence mid-archive.
    let _entropy = EntropyScope::install(options.entropy);
    let total_bytes = entries.iter().map(|entry| entry.data.len() as u64).sum();
    report_compression_operation(progress, true, total_bytes, entries.len());
    validate_rar29_filter_policy(&policy)?;
    let encode_options = rar29_encode_options_for_options(options)?;
    let lz_method = compression_method_for_level(options)?;
    let result = write_rar29_filtered_archive(entries, options, |entry| {
        encode_rar29_policy_filtered_payload(entry.data, &policy, encode_options, lz_method)
    });
    report_compression_operation(progress, false, total_bytes, entries.len());
    result
}

fn encode_rar29_policy_filtered_payload(
    data: &[u8],
    policy: &FilterPolicy,
    options: Rar29EncodeOptions,
    lz_method: u8,
) -> Result<EncodedPayload> {
    if lz_method == 0x30 {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    match policy {
        FilterPolicy::Lz => encode_rar29_lz_member(data, options, lz_method),
        FilterPolicy::Auto => encode_rar29_auto_filtered_member(data, options, lz_method, true),
        FilterPolicy::Explicit(filter) => Ok(EncodedPayload {
            data: encode_rar29_filtered_member(data, filter.clone(), options)?,
            method: lz_method,
        }),
        FilterPolicy::Ppmd => Ok(EncodedPayload {
            data: unpack29_encode_ppmd(data).map_err(Error::from)?,
            method: 0x35,
        }),
        FilterPolicy::PpmdFiltered(filter) => Ok(EncodedPayload {
            data: unpack29_encode_ppmd_with_filter(data, filter.clone()).map_err(Error::from)?,
            method: 0x35,
        }),
    }
}

fn validate_rar29_filter_policy(policy: &FilterPolicy) -> Result<()> {
    let filter = match policy {
        FilterPolicy::Explicit(filter) | FilterPolicy::PpmdFiltered(filter) => filter,
        FilterPolicy::Lz | FilterPolicy::Auto | FilterPolicy::Ppmd => return Ok(()),
    };
    match filter.kind {
        FilterKind::Delta { channels } => {
            if channels == 0 || channels > 32 {
                return Err(Error::InvalidHeader(
                    "RAR 2.9 DELTA filter channel count is invalid",
                ));
            }
        }
        FilterKind::Audio { channels } => {
            if channels == 0 || channels > 32 {
                return Err(Error::InvalidHeader(
                    "RAR 2.9 AUDIO filter channel count is invalid",
                ));
            }
        }
        FilterKind::Rgb { width, pos_r } => {
            if width == 0 || !width.is_multiple_of(3) || pos_r > 2 {
                return Err(Error::InvalidHeader(
                    "RAR 2.9 RGB filter parameters are invalid",
                ));
            }
        }
        FilterKind::E8 | FilterKind::E8E9 | FilterKind::Itanium => {}
    }
    Ok(())
}

fn encode_rar29_lz_member(
    data: &[u8],
    options: Rar29EncodeOptions,
    method: u8,
) -> Result<EncodedPayload> {
    let compressed = unpack29_encode_literals_with_options(data, options).map_err(Error::from)?;
    if compressed.len() >= data.len() {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    Ok(EncodedPayload {
        data: compressed,
        method,
    })
}

fn encode_rar29_filtered_member(
    data: &[u8],
    filter: FilterSpec,
    options: Rar29EncodeOptions,
) -> Result<Vec<u8>> {
    Unpack29Encoder::with_options(options)
        .encode_member_with_filter(data, filter)
        .map_err(Error::from)
}

fn encode_rar29_filtered_members(
    data: &[u8],
    filters: &[FilterSpec],
    options: Rar29EncodeOptions,
) -> Result<Vec<u8>> {
    Unpack29Encoder::with_options(options)
        .encode_member_with_filters(data, filters)
        .map_err(Error::from)
}

fn encode_rar29_auto_filtered_member(
    data: &[u8],
    options: Rar29EncodeOptions,
    lz_method: u8,
    include_ppmd: bool,
) -> Result<EncodedPayload> {
    if data.is_empty() {
        return Ok(EncodedPayload {
            data: Vec::new(),
            method: 0x30,
        });
    }
    if include_ppmd && is_large_text_ppmd_candidate(data) {
        return Ok(EncodedPayload {
            data: unpack29_encode_ppmd(data).map_err(Error::from)?,
            method: 0x35,
        });
    }
    let mut best = EncodedPayload {
        data: unpack29_encode_literals_with_options(data, options).map_err(Error::from)?,
        method: lz_method,
    };
    if include_ppmd && data.len() <= 1024 * 1024 && is_text_ppmd_candidate(data) {
        let ppmd = EncodedPayload {
            data: unpack29_encode_ppmd(data).map_err(Error::from)?,
            method: 0x35,
        };
        if ppmd.data.len() < best.data.len() {
            best = ppmd;
        }
        return Ok(best);
    }
    if is_text_ppmd_candidate(data) {
        return Ok(best);
    }
    let mut candidates = Vec::new();
    if include_ppmd && is_auto_ppmd_candidate(data) {
        candidates.push(EncodedPayload {
            data: unpack29_encode_ppmd(data).map_err(Error::from)?,
            method: 0x35,
        });
    }
    candidates.extend([
        EncodedPayload {
            data: encode_rar29_filtered_member(data, FilterSpec::whole(FilterKind::E8), options)?,
            method: lz_method,
        },
        EncodedPayload {
            data: encode_rar29_filtered_member(data, FilterSpec::whole(FilterKind::E8E9), options)?,
            method: lz_method,
        },
        EncodedPayload {
            data: encode_rar29_filtered_member(
                data,
                FilterSpec::whole(FilterKind::Itanium),
                options,
            )?,
            method: lz_method,
        },
    ]);
    let e8_candidates = auto_x86_filter_ranges(data, false);
    for range in e8_candidates.iter().cloned() {
        candidates.push(EncodedPayload {
            data: encode_rar29_filtered_member(
                data,
                FilterSpec::range(FilterKind::E8, range),
                options,
            )?,
            method: lz_method,
        });
    }
    let e8_ranges = disjoint_filter_ranges(e8_candidates);
    if e8_ranges.len() > 1 {
        let filters: Vec<_> = e8_ranges
            .into_iter()
            .map(|range| FilterSpec::range(FilterKind::E8, range))
            .collect();
        candidates.push(EncodedPayload {
            data: encode_rar29_filtered_members(data, &filters, options)?,
            method: lz_method,
        });
    }
    let e8e9_candidates = auto_x86_filter_ranges(data, true);
    for range in e8e9_candidates.iter().cloned() {
        candidates.push(EncodedPayload {
            data: encode_rar29_filtered_member(
                data,
                FilterSpec::range(FilterKind::E8E9, range),
                options,
            )?,
            method: lz_method,
        });
    }
    let e8e9_ranges = disjoint_filter_ranges(e8e9_candidates);
    if e8e9_ranges.len() > 1 {
        let filters: Vec<_> = e8e9_ranges
            .into_iter()
            .map(|range| FilterSpec::range(FilterKind::E8E9, range))
            .collect();
        candidates.push(EncodedPayload {
            data: encode_rar29_filtered_members(data, &filters, options)?,
            method: lz_method,
        });
    }
    for channels in 1..=4 {
        candidates.push(EncodedPayload {
            data: encode_rar29_filtered_member(
                data,
                FilterSpec::whole(FilterKind::Delta { channels }),
                options,
            )?,
            method: lz_method,
        });
        if is_audio_filter_candidate(data, channels) {
            candidates.push(EncodedPayload {
                data: encode_rar29_filtered_member(
                    data,
                    FilterSpec::whole(FilterKind::Audio { channels }),
                    options,
                )?,
                method: lz_method,
            });
        }
    }
    for channels in 1..=4 {
        if let Some(range) = auto_delta_filter_range(data, channels) {
            candidates.push(EncodedPayload {
                data: encode_rar29_filtered_member(
                    data,
                    FilterSpec::range(FilterKind::Delta { channels }, range),
                    options,
                )?,
                method: lz_method,
            });
        }
    }
    for width in AUTO_RGB_WIDTHS {
        if data.len() >= width {
            candidates.push(EncodedPayload {
                data: encode_rar29_filtered_member(
                    data,
                    FilterSpec::whole(FilterKind::Rgb { width, pos_r: 0 }),
                    options,
                )?,
                method: lz_method,
            });
        }
    }

    for candidate in candidates {
        if candidate.data.len() < best.data.len() {
            best = candidate;
        }
    }
    if best.data.len() >= data.len() {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    Ok(best)
}

fn is_large_text_ppmd_candidate(data: &[u8]) -> bool {
    data.len() >= RAR29_LARGE_TEXT_PPMD_THRESHOLD && is_text_ppmd_candidate(data)
}

fn is_auto_ppmd_candidate(data: &[u8]) -> bool {
    is_text_ppmd_candidate(data)
}

fn is_text_ppmd_candidate(data: &[u8]) -> bool {
    let mut printable = 0usize;
    let mut nul = 0usize;
    let mut total = 0usize;
    for start in text_sample_offsets(data.len()) {
        let end = start.saturating_add(RAR29_TEXT_SAMPLE_SIZE).min(data.len());
        for &byte in &data[start..end] {
            total += 1;
            if byte == 0 {
                nul += 1;
            }
            if byte.is_ascii_graphic() || matches!(byte, b'\n' | b'\r' | b'\t' | b' ') {
                printable += 1;
            }
        }
    }
    total != 0 && nul * 100 <= total && printable * 100 >= total * 85
}

fn text_sample_offsets(len: usize) -> [usize; 3] {
    [
        0,
        len.saturating_sub(RAR29_TEXT_SAMPLE_SIZE) / 2,
        len.saturating_sub(RAR29_TEXT_SAMPLE_SIZE),
    ]
}

fn is_audio_filter_candidate(data: &[u8], channels: usize) -> bool {
    if channels == 0 || channels > 4 || data.len() < channels * 64 {
        return false;
    }

    let mut total_delta = 0usize;
    let mut small_delta = 0usize;
    let mut compared = 0usize;
    for start in text_sample_offsets(data.len()) {
        let end = start
            .saturating_add(RAR29_AUDIO_SAMPLE_SIZE)
            .min(data.len());
        let aligned_start = start + ((channels - start % channels) % channels);
        if aligned_start + channels >= end {
            continue;
        }
        for channel in 0..channels {
            let mut previous = None;
            let mut index = aligned_start + channel;
            while index < end {
                let byte = data[index];
                if let Some(previous) = previous {
                    let delta = usize::from(byte.abs_diff(previous));
                    let delta = delta.min(256 - delta);
                    total_delta += delta;
                    small_delta += usize::from(delta <= 8);
                    compared += 1;
                }
                previous = Some(byte);
                index += channels;
            }
        }
    }

    compared != 0 && total_delta <= compared * 24 && small_delta * 100 >= compared * 55
}

fn auto_delta_filter_range(data: &[u8], channels: usize) -> Option<std::ops::Range<usize>> {
    if channels == 0 || data.len() <= AUTO_DELTA_EDGE_SKIP * 2 + channels * 8 {
        return None;
    }
    let start = AUTO_DELTA_EDGE_SKIP;
    let end = data.len() - AUTO_DELTA_EDGE_SKIP;
    let aligned_start = start + ((channels - start % channels) % channels);
    let aligned_end = end - (end - aligned_start) % channels;
    (aligned_start + channels * 8 <= aligned_end).then_some(aligned_start..aligned_end)
}

fn disjoint_filter_ranges(mut ranges: Vec<std::ops::Range<usize>>) -> Vec<std::ops::Range<usize>> {
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut disjoint: Vec<std::ops::Range<usize>> = Vec::new();
    for range in ranges {
        if disjoint.last().is_some_and(|last| range.start < last.end) {
            continue;
        }
        disjoint.push(range);
    }
    disjoint
}

fn write_rar29_filtered_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    encode: impl Fn(&FileEntry<'_>) -> Result<EncodedPayload> + Sync,
) -> Result<Vec<u8>> {
    validate_rar29_filtered_writer_options(options)?;
    if options.features.header_encryption {
        validate_header_encrypted_archive_options(options, false, options.features.solid)?;
    }
    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    let main_flags = if options.features.solid { MHD_SOLID } else { 0 }
        | if options.features.header_encryption {
            MHD_PASSWORD
        } else {
            0
        };
    write_main_header(&mut out, main_flags);
    let header_password = if options.features.header_encryption {
        Some(header_encryption_password(
            entries.iter().map(|entry| entry.password),
        )?)
    } else {
        None
    };
    if options.features.solid {
        let mut solid_run_has_member = false;
        for entry in entries {
            let payload = encode(entry)?;
            let solid_continuation = payload.method != 0x30 && solid_run_has_member;
            if let Some(password) = header_password {
                write_header_encrypted_compressed_entry(
                    &mut out,
                    entry,
                    &payload.data,
                    payload.method,
                    options,
                    solid_continuation,
                    password,
                )?;
            } else {
                write_compressed_entry(
                    &mut out,
                    entry,
                    &payload.data,
                    payload.method,
                    options.target,
                    dictionary_flags_for_options(options)?,
                    solid_continuation,
                )?;
            }
            solid_run_has_member = payload.method != 0x30;
        }
    } else {
        let payloads = encode_filtered_payloads(entries, &encode)?;
        for (entry, payload) in entries.iter().zip(&payloads) {
            if let Some(password) = header_password {
                write_header_encrypted_compressed_entry(
                    &mut out,
                    entry,
                    &payload.data,
                    payload.method,
                    options,
                    false,
                    password,
                )?;
            } else {
                write_compressed_entry(
                    &mut out,
                    entry,
                    &payload.data,
                    payload.method,
                    options.target,
                    dictionary_flags_for_options(options)?,
                    false,
                )?;
            }
        }
    }
    Ok(out)
}

fn write_header_encrypted_stored_archive(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    validate_header_encrypted_archive_options(options, archive_comment.is_some(), false)?;
    let password = header_encryption_password(entries.iter().map(|entry| entry.password))?;

    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    write_main_header(&mut out, MHD_PASSWORD);
    for entry in entries {
        write_header_encrypted_stored_entry(&mut out, entry, options, password)?;
    }
    Ok(out)
}

fn write_header_encrypted_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    validate_header_encrypted_archive_options(
        options,
        archive_comment.is_some(),
        options.features.solid,
    )?;
    let password = header_encryption_password(entries.iter().map(|entry| entry.password))?;

    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    let main_flags = MHD_PASSWORD | if options.features.solid { MHD_SOLID } else { 0 };
    write_main_header(&mut out, main_flags);
    if options.features.solid {
        let mut solid_encoder = SolidEncoder::for_target(options, true)?;
        let mut solid_run_has_member = false;
        for entry in entries {
            let payload = encode_or_store_payload(entry.data, options, &mut solid_encoder, None)?;
            let solid_continuation = payload.method != 0x30 && solid_run_has_member;
            write_header_encrypted_compressed_entry(
                &mut out,
                entry,
                &payload.data,
                payload.method,
                options,
                solid_continuation,
                password,
            )?;
            solid_run_has_member = payload.method != 0x30;
        }
    } else {
        let payloads = encode_independent_payloads(entries, options, None)?;
        for (entry, payload) in entries.iter().zip(&payloads) {
            write_header_encrypted_compressed_entry(
                &mut out,
                entry,
                &payload.data,
                payload.method,
                options,
                false,
                password,
            )?;
        }
    }
    Ok(out)
}

/// The main-header bit that declares the volume NAMING, which the four
/// volume writers OR into every volume they emit.
///
/// One place, because the bit has to be identical on every volume of a
/// set - real `rar` sets it on all of them, not just the first - and
/// because the pairing it stands for is measured rather than obvious;
/// [`VolumeNumbering`] carries the table.
fn numbering_flag(options: WriterOptions) -> u16 {
    match options.volume_numbering {
        VolumeNumbering::Classic => 0,
        VolumeNumbering::NewStyle => MHD_NEWNUMBERING,
    }
}

pub fn write_stored_volumes(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    // Held for the whole archive: the salt draw below reads it back off
    // this thread. Never `let _ =`, which would drop it here and put the
    // writer back on OS entropy. Only the five functions that do the
    // work install one - the wrappers above them delegate here, and a
    // second install would restart the seeded sequence mid-archive.
    let _entropy = EntropyScope::install(options.entropy);
    validate_stored_writer_options(options, false, false)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;
    if options.features.header_encryption {
        return write_header_encrypted_split_volumes(SplitVolumeRecord {
            name: entry.name,
            unpacked: entry.data,
            packed: entry.data,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target: options.target,
            method: 0x30,
            dictionary_flags: dictionary_flags_for_options(options)?,
            base_flags: writer_file_flags(entry.password, None, false),
            main_flags: numbering_flag(options),
            password: entry.password,
            max_packed_per_volume,
        });
    }

    write_split_volumes(SplitVolumeRecord {
        name: entry.name,
        unpacked: entry.data,
        packed: entry.data,
        file_time: entry.file_time,
        file_attr: entry.file_attr,
        host_os: entry.host_os,
        target: options.target,
        method: 0x30,
        dictionary_flags: dictionary_flags_for_options(options)?,
        base_flags: writer_file_flags(entry.password, None, false),
        main_flags: numbering_flag(options),
        password: entry.password,
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
    // Held for the whole archive: the salt draw below reads it back off
    // this thread. Never `let _ =`, which would drop it here and put the
    // writer back on OS entropy. Only the five functions that do the
    // work install one - the wrappers above them delegate here, and a
    // second install would restart the seeded sequence mid-archive.
    let _entropy = EntropyScope::install(options.entropy);
    let total_work = if options.target == ArchiveVersion::Rar20 && !options.features.solid {
        (entry.data.len() as u64).saturating_mul(2)
    } else {
        entry.data.len() as u64
    };
    report_compression_operation(progress, true, total_work, 1);
    let work = WorkTracker::new(
        progress.map(ProgressReporter),
        WriteOperation::Compression,
        total_work,
    );
    let result = write_compressed_volumes_impl(entry, options, max_packed_per_volume, Some(&work));
    if result.is_ok() && !work.finish() {
        return Err(Error::Cancelled);
    }
    report_compression_operation(progress, false, total_work, 1);
    result
}

fn write_compressed_volumes_impl(
    entry: FileEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<Vec<u8>>> {
    validate_compressed_writer_options(options, false, false)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;

    let mut solid_encoder = None;
    let payload = encode_or_store_payload(entry.data, options, &mut solid_encoder, progress)?;
    if options.features.header_encryption {
        return write_header_encrypted_split_volumes(SplitVolumeRecord {
            name: entry.name,
            unpacked: entry.data,
            packed: &payload.data,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target: options.target,
            method: payload.method,
            dictionary_flags: dictionary_flags_for_options(options)?,
            base_flags: writer_file_flags(entry.password, None, false),
            main_flags: numbering_flag(options)
                | if options.features.solid { MHD_SOLID } else { 0 },
            password: entry.password,
            max_packed_per_volume,
        });
    }

    write_split_volumes(SplitVolumeRecord {
        name: entry.name,
        unpacked: entry.data,
        packed: &payload.data,
        file_time: entry.file_time,
        file_attr: entry.file_attr,
        host_os: entry.host_os,
        target: options.target,
        method: payload.method,
        dictionary_flags: dictionary_flags_for_options(options)?,
        base_flags: writer_file_flags(entry.password, None, false),
        main_flags: numbering_flag(options) | if options.features.solid { MHD_SOLID } else { 0 },
        password: entry.password,
        max_packed_per_volume,
    })
}

/// A split STORED set holding SEVERAL members.
///
/// [`write_stored_volumes`] splits ONE member across the volumes, which
/// is the shape a single big file makes. This one walks a slice: members
/// pack end to end and only the member that lands on a volume boundary
/// carries the split flags, so `rar a -v50M set.rar a.mkv b.nfo` is
/// expressible at last. Nothing in the RAR 1.5-4 writer could emit it
/// before, and it is the commonest layout on the wire
/// (nzbfast-local change, 4 Sep 2026 - see vendor/rars/VENDORING.md).
///
/// Header encryption is reached from here exactly as it is from
/// [`write_compressed_volume_set`]: the per-volume main header carries
/// `MHD_PASSWORD` and every file header rides an encrypted block of its
/// own, one salt per block.
pub fn write_stored_volume_set(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    // Held for the whole archive: the per-member salt draws below read
    // it back off this thread. Never `let _ =`, which would drop it here
    // and put the writer back on OS entropy.
    let _entropy = EntropyScope::install(options.entropy);
    validate_stored_writer_options(options, false, false)?;
    if entries.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least one entry",
        ));
    }
    let mut members = Vec::with_capacity(entries.len());
    for entry in entries {
        validate_stored_entry(entry)?;
        validate_volume_writer_inputs(
            entry.name,
            entry.data,
            entry.password,
            entry.file_comment,
            options,
        )?;
        members.push(volume_set_member(VolumeSetMemberInput {
            name: entry.name,
            unpacked: entry.data,
            packed: entry.data,
            method: 0x30,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            password: entry.password,
            solid_continuation: false,
            target: options.target,
        })?);
    }
    write_volume_set(&members, options, numbering_flag(options), max_packed_per_volume)
}

/// A split COMPRESSED set holding SEVERAL members.
///
/// The stored twin above, over encoded payloads. Each member is encoded
/// on its own unless `features.solid` is set, in which case the members
/// share one encoder run and a continuation carries `FHD_SOLID`, exactly
/// as [`write_compressed_archive`] already does for an unsplit archive
/// (nzbfast-local change, 4 Sep 2026 - see vendor/rars/VENDORING.md).
pub fn write_compressed_volume_set(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    // Held for the whole archive: the per-member salt draws below read
    // it back off this thread. Never `let _ =`, which would drop it here
    // and put the writer back on OS entropy.
    let _entropy = EntropyScope::install(options.entropy);
    validate_compressed_writer_options(options, false, false)?;
    if entries.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least one entry",
        ));
    }
    for entry in entries {
        validate_volume_writer_inputs(
            entry.name,
            entry.data,
            entry.password,
            entry.file_comment,
            options,
        )?;
    }
    let mut members = Vec::with_capacity(entries.len());
    if options.features.solid {
        let mut solid_encoder = SolidEncoder::for_target(options, true)?;
        let mut solid_run_has_member = false;
        for entry in entries {
            let payload = encode_or_store_payload(entry.data, options, &mut solid_encoder, None)?;
            let solid_continuation = payload.method != 0x30 && solid_run_has_member;
            members.push(volume_set_member(VolumeSetMemberInput {
                name: entry.name,
                unpacked: entry.data,
                packed: &payload.data,
                method: payload.method,
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                host_os: entry.host_os,
                password: entry.password,
                solid_continuation,
                target: options.target,
            })?);
            solid_run_has_member = payload.method != 0x30;
        }
    } else {
        let payloads = encode_independent_payloads(entries, options, None)?;
        for (entry, payload) in entries.iter().zip(&payloads) {
            members.push(volume_set_member(VolumeSetMemberInput {
                name: entry.name,
                unpacked: entry.data,
                packed: &payload.data,
                method: payload.method,
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                host_os: entry.host_os,
                password: entry.password,
                solid_continuation: false,
                target: options.target,
            })?);
        }
    }
    let main_flags = numbering_flag(options) | if options.features.solid { MHD_SOLID } else { 0 };
    write_volume_set(&members, options, main_flags, max_packed_per_volume)
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

fn validate_stored_writer_options(
    options: WriterOptions,
    has_archive_comment: bool,
    has_file_comment: bool,
) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = FeatureSet::store_only();
    allowed.file_encryption =
        writer_supports_file_encryption(options.target) && options.features.file_encryption;
    allowed.header_encryption =
        writer_supports_header_encryption(options.target) && options.features.header_encryption;
    allowed.archive_comment = matches!(
        options.target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) && has_archive_comment;
    allowed.file_comment = matches!(
        options.target,
        ArchiveVersion::Rar15 | ArchiveVersion::Rar20 | ArchiveVersion::Rar29
    ) && has_file_comment;
    allowed.recovery_record = allows_recovery_record(options);
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 1.5 writer feature",
        });
    }
    Ok(())
}

fn validate_compressed_writer_options(
    options: WriterOptions,
    has_archive_comment: bool,
    has_file_comment: bool,
) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = FeatureSet::store_only();
    allowed.solid = matches!(
        options.target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) && options.features.solid;
    allowed.file_encryption =
        writer_supports_file_encryption(options.target) && options.features.file_encryption;
    allowed.header_encryption =
        writer_supports_header_encryption(options.target) && options.features.header_encryption;
    allowed.archive_comment = matches!(
        options.target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) && has_archive_comment;
    allowed.file_comment = matches!(
        options.target,
        ArchiveVersion::Rar15 | ArchiveVersion::Rar20 | ArchiveVersion::Rar29
    ) && has_file_comment;
    allowed.recovery_record = allows_recovery_record(options);
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 1.5 writer feature",
        });
    }
    Ok(())
}

fn validate_rar29_filtered_writer_options(options: WriterOptions) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = FeatureSet::store_only();
    allowed.solid = options.features.solid;
    allowed.file_encryption =
        writer_supports_file_encryption(options.target) && options.features.file_encryption;
    allowed.header_encryption =
        writer_supports_header_encryption(options.target) && options.features.header_encryption;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 2.9 RARVM-filtered compressed writer feature",
        });
    }
    Ok(())
}

fn validate_header_encrypted_archive_options(
    options: WriterOptions,
    has_archive_comment: bool,
    _solid: bool,
) -> Result<()> {
    if has_archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 3.x header-encrypted archive comments",
        });
    }
    if !options.features.file_encryption {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 3.x header encryption without file encryption",
        });
    }
    Ok(())
}

/// Whether the requested archive may carry a recovery record.
///
/// Answers a `FeatureSet` slot, so a `true` here is a promise that
/// `append_recovery_record` will actually write one on this path. The
/// two exclusions are real gaps and not spelling:
///
/// * RAR 1.5 and 2.0 want the old-style `PROTECT_HEAD` block instead
///   (`writer_supports_recovery_record`);
/// * a header-encrypted archive stores the record encrypted too, and
///   this writer would leave it in the clear - which the extractor
///   refuses to read back (`newsub_recovery_data`), so the archive
///   would carry a record no reader accepts.
///
/// The VOLUME writers share these validators and are refused separately
/// in `validate_volume_writer_inputs`: they reach the same `allowed`
/// set but never reach `append_recovery_record`, so passing here would
/// mean an archive claiming `MHD_PROTECT` with no record behind it.
fn allows_recovery_record(options: WriterOptions) -> bool {
    writer_supports_recovery_record(options.target)
        && !options.features.header_encryption
        && options.features.recovery_record
}

/// Refuses a percent with the feature flag off, and a flag with no percent.
///
/// Either half alone is a request the writer would answer by doing
/// nothing: a percent with `features.recovery_record` off is dropped by
/// `append_recovery_record`, and the flag with no percent has no size to
/// build. Both are far more likely to be a caller's mistake than an
/// intention, so both are named rather than ignored.
fn validate_recovery_request(options: WriterOptions) -> Result<()> {
    if options.recovery_percent.is_some() != options.features.recovery_record {
        return Err(Error::InvalidHeader(
            "RAR recovery record needs both features.recovery_record and a recovery percent",
        ));
    }
    if matches!(options.recovery_percent, Some(percent) if percent == 0 || percent > 100) {
        return Err(Error::InvalidHeader(
            "RAR recovery percent must be in the range 1..=100",
        ));
    }
    Ok(())
}

fn validate_compression_level(options: WriterOptions) -> Result<()> {
    // Every writer validator runs this first, which is why the recovery
    // pairing check rides here: a path that forgot to call it would be
    // a path that skipped the compression-level check too, and that is
    // visible in a diff.
    validate_recovery_request(options)?;
    if matches!(options.compression_level, Some(level) if level > 5) {
        return Err(Error::InvalidHeader(
            "RAR compression level must be in the range 0..5",
        ));
    }
    let _ = dictionary_flags_for_options(options)?;
    Ok(())
}

fn rar29_encode_options_for_level(level: Option<u8>) -> Result<Rar29EncodeOptions> {
    let level = level.unwrap_or(5);
    let candidates = match level {
        0 => 0,
        1 => 8,
        2 => 32,
        3 => 64,
        4 => 96,
        5 => 128,
        _ => {
            return Err(Error::InvalidHeader(
                "RAR compression level must be in the range 0..5",
            ))
        }
    };
    Ok(Rar29EncodeOptions::new(candidates)
        .with_lazy_matching(level >= 4)
        .with_lazy_lookahead(1)
        .with_block_size(RAR29_LZ_BLOCK_SIZE))
}

fn rar29_encode_options_for_options(options: WriterOptions) -> Result<Rar29EncodeOptions> {
    Ok(rar29_encode_options_for_level(options.compression_level)?
        .with_max_match_distance(dictionary_size_for_options(options)?))
}

fn rar20_encode_options_for_level(level: Option<u8>) -> Result<Rar20EncodeOptions> {
    match level {
        None | Some(3) => Ok(Rar20EncodeOptions::default()),
        Some(1) => Ok(Rar20EncodeOptions::new(16).with_try_audio(false)),
        Some(2) => Ok(Rar20EncodeOptions::new(64)),
        Some(4) => Ok(Rar20EncodeOptions::new(96).with_lazy_matching(false)),
        Some(5) => Ok(Rar20EncodeOptions::new(128).with_lazy_matching(false)),
        Some(0) => Ok(Rar20EncodeOptions::new(0)),
        Some(_) => Err(Error::InvalidHeader(
            "RAR compression level must be in the range 0..5",
        )),
    }
}

fn rar20_encode_options_for_options(options: WriterOptions) -> Result<Rar20EncodeOptions> {
    rar20_encode_options_for_level(options.compression_level)
}

fn rar15_encode_options_for_level(level: Option<u8>) -> Result<Rar15EncodeOptions> {
    let level = level.unwrap_or(5);
    match level {
        0 => Ok(Rar15EncodeOptions::new()
            .with_old_distance_tokens(false)
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(0)),
        1 => Ok(Rar15EncodeOptions::new()
            .with_old_distance_tokens(false)
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(4 * 1024)),
        2 => Ok(Rar15EncodeOptions::new()
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(8 * 1024)),
        3 => Ok(Rar15EncodeOptions::new()
            .with_lazy_matching(false)
            .with_max_long_match_distance(16 * 1024)),
        4 => Ok(Rar15EncodeOptions::new()
            .with_lazy_matching(false)
            .with_max_long_match_distance(24 * 1024)),
        5 => Ok(Rar15EncodeOptions::new().with_lazy_matching(false)),
        _ => Err(Error::InvalidHeader(
            "RAR compression level must be in the range 0..5",
        )),
    }
}

fn rar29_default_dictionary_size(target: ArchiveVersion) -> usize {
    match target {
        ArchiveVersion::Rar29 => 1024 * 1024,
        ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => 128 * 1024,
        _ => 64 * 1024,
    }
}

fn dictionary_size_for_options(options: WriterOptions) -> Result<usize> {
    options
        .dictionary_size
        .map(Ok)
        .unwrap_or_else(|| Ok(rar29_default_dictionary_size(options.target)))
}

fn dictionary_flags_for_options(options: WriterOptions) -> Result<u16> {
    dictionary_flags_for_size(dictionary_size_for_options(options)?)
}

fn dictionary_flags_for_size(size: usize) -> Result<u16> {
    let bits =
        match size {
            0x1_0000 => 0,
            0x2_0000 => 1,
            0x4_0000 => 2,
            0x8_0000 => 3,
            0x10_0000 => 4,
            0x20_0000 => 5,
            0x40_0000 => 6,
            _ => return Err(Error::InvalidHeader(
                "RAR 1.5-4.x dictionary size must be one of 64K, 128K, 256K, 512K, 1M, 2M, or 4M",
            )),
        };
    Ok((bits as u16) << 5)
}

fn compression_method_for_level(options: WriterOptions) -> Result<u8> {
    let Some(level) = options.compression_level else {
        return Ok(0x33);
    };
    if level > 5 {
        return Err(Error::InvalidHeader(
            "RAR compression level must be in the range 0..5",
        ));
    }
    if level == 0 {
        return Ok(0x30);
    }
    if matches!(
        options.target,
        ArchiveVersion::Rar20
            | ArchiveVersion::Rar15
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) {
        return Ok(0x30 + level);
    }
    Ok(0x33)
}

enum SolidEncoder {
    Rar15(Box<Unpack15Encoder>),
    Rar20(Unpack20Encoder),
    Rar29(Unpack29Encoder),
}

impl SolidEncoder {
    fn for_target(options: WriterOptions, solid: bool) -> Result<Option<Self>> {
        if !solid {
            return Ok(None);
        }
        let encoder = match options.target {
            ArchiveVersion::Rar15 => Self::Rar15(Box::new(Unpack15Encoder::with_options(
                rar15_encode_options_for_level(options.compression_level)?,
            ))),
            ArchiveVersion::Rar20 => Self::Rar20(Unpack20Encoder::with_options(
                rar20_encode_options_for_options(options)?,
            )),
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => Self::Rar29(
                Unpack29Encoder::with_options(rar29_encode_options_for_options(options)?),
            ),
            _ => return Ok(None),
        };
        Ok(Some(encoder))
    }
}

struct EncodedPayload {
    data: Vec<u8>,
    method: u8,
}

fn encode_independent_payload(
    data: &[u8],
    options: WriterOptions,
    progress: Option<&WorkTracker<'_>>,
) -> Result<EncodedPayload> {
    let mut solid_encoder = None;
    encode_or_store_payload(data, options, &mut solid_encoder, progress)
}

fn encode_independent_payloads(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<EncodedPayload>> {
    #[cfg(feature = "parallel")]
    {
        if entries.len() > 1 {
            crate::parallel::map_slice_collect(entries, |entry| {
                encode_independent_payload(entry.data, options, progress)
            })
        } else {
            entries
                .iter()
                .map(|entry| encode_independent_payload(entry.data, options, progress))
                .collect()
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        entries
            .iter()
            .map(|entry| encode_independent_payload(entry.data, options, progress))
            .collect()
    }
}

fn encode_filtered_payloads<F>(entries: &[FileEntry<'_>], encode: &F) -> Result<Vec<EncodedPayload>>
where
    F: Fn(&FileEntry<'_>) -> Result<EncodedPayload> + Sync,
{
    #[cfg(feature = "parallel")]
    {
        if entries.len() > 1 {
            crate::parallel::map_slice_collect(entries, encode)
        } else {
            entries.iter().map(encode).collect()
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        entries.iter().map(encode).collect()
    }
}

fn encode_or_store_payload(
    data: &[u8],
    options: WriterOptions,
    solid_encoder: &mut Option<SolidEncoder>,
    progress: Option<&WorkTracker<'_>>,
) -> Result<EncodedPayload> {
    let target = options.target;
    if options.compression_level == Some(0) {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    let solid = solid_encoder.is_some();
    if !solid
        && matches!(
            target,
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
        )
    {
        let encode_options = rar29_encode_options_for_options(options)?;
        let lz_method = compression_method_for_level(options)?;
        if matches!(options.compression_level, Some(1..=4)) {
            return encode_rar29_auto_filtered_member(data, encode_options, lz_method, false);
        }
        return encode_rar29_auto_filtered_member(data, encode_options, lz_method, true);
    }
    let compressed = encode_compressed_payload(data, options, solid_encoder.as_mut(), progress)?;
    if should_store_fallback(target, solid, data.len(), compressed.len()) {
        if solid {
            *solid_encoder = SolidEncoder::for_target(options, true)?;
        }
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    Ok(EncodedPayload {
        data: compressed,
        method: compression_method_for_level(options)?,
    })
}

fn encode_compressed_payload(
    data: &[u8],
    options: WriterOptions,
    solid_encoder: Option<&mut SolidEncoder>,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<u8>> {
    let target = options.target;
    let mut last = 0usize;
    let mut advance = |position: usize| {
        if position < last {
            last = 0;
        }
        let delta = position.saturating_sub(last);
        last = position;
        progress.is_none_or(|progress| progress.advance(delta as u64))
    };
    match (target, solid_encoder) {
        (ArchiveVersion::Rar15, Some(SolidEncoder::Rar15(encoder))) => encoder
            .encode_member_with_progress(data, &mut advance)
            .map_err(map_codec_cancel),
        (ArchiveVersion::Rar15, None) => unpack15_encode_with_options_and_progress(
            data,
            rar15_encode_options_for_level(options.compression_level)?,
            &mut advance,
        )
        .map_err(map_codec_cancel),
        (ArchiveVersion::Rar20, None) => unpack20_encode_auto_with_options_and_progress(
            data,
            rar20_encode_options_for_options(options)?,
            &mut advance,
        )
        .map_err(map_codec_cancel),
        (ArchiveVersion::Rar20, Some(SolidEncoder::Rar20(encoder))) => encoder
            .encode_member_with_progress(data, &mut advance)
            .map_err(map_codec_cancel),
        (ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40, None) => {
            unpack29_encode_literals_with_options_and_progress(
                data,
                Rar29EncodeOptions::default(),
                &mut advance,
            )
            .map_err(map_codec_cancel)
        }
        (
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40,
            Some(SolidEncoder::Rar29(encoder)),
        ) => encoder
            .encode_member_with_progress(data, &mut advance)
            .map_err(map_codec_cancel),
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

fn map_codec_cancel(error: crate::codec::Error) -> Error {
    if error == crate::codec::Error::Cancelled {
        Error::Cancelled
    } else {
        Error::from(error)
    }
}

fn should_store_fallback(
    target: ArchiveVersion,
    solid: bool,
    unpacked_len: usize,
    packed_len: usize,
) -> bool {
    if packed_len < unpacked_len {
        return false;
    }
    if !solid
        && matches!(
            target,
            ArchiveVersion::Rar20
                | ArchiveVersion::Rar29
                | ArchiveVersion::Rar30
                | ArchiveVersion::Rar40
        )
    {
        return true;
    }
    unpacked_len >= MIN_STORE_FALLBACK_SIZE
}

fn validate_volume_writer_inputs(
    name: &[u8],
    data: &[u8],
    password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    options: WriterOptions,
) -> Result<()> {
    validate_file_entry(name, data)?;
    if password.is_some()
        && !matches!(
            options.target,
            ArchiveVersion::Rar15
                | ArchiveVersion::Rar20
                | ArchiveVersion::Rar29
                | ArchiveVersion::Rar30
                | ArchiveVersion::Rar40
        )
    {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 2.9 encrypted volume writer",
        });
    }
    if file_comment.is_some() {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_file_comment",
        });
    }
    // The single-archive validators run before this one and now allow a
    // recovery record, so without this arm a volume set would pass every
    // check and be written with none: `write_split_volumes` never reaches
    // `append_recovery_record`. `rar` puts one record in EVERY volume,
    // over that volume's own bytes, which is a per-volume plan this
    // writer does not have.
    if options.features.recovery_record {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 3.x recovery record on a volume set",
        });
    }
    Ok(())
}

fn writer_file_flags(
    password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    solid_continuation: bool,
) -> u16 {
    let mut flags = 0;
    if password.is_some() {
        flags |= FHD_PASSWORD;
    }
    if file_comment.is_some() {
        flags |= FHD_COMMENT;
    }
    if solid_continuation {
        flags |= FHD_SOLID;
    }
    flags
}

fn encode_file_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let Some(comment) = comment else {
        return Ok(Vec::new());
    };
    if comment.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.5 file comment is longer than 65535 bytes",
        ));
    }
    let mut out = Vec::with_capacity(2 + comment.len());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    Ok(out)
}

fn encrypt_split_packed_data(
    data: &mut Vec<u8>,
    target: ArchiveVersion,
    password: &[u8],
) -> Result<Option<[u8; 8]>> {
    match target {
        ArchiveVersion::Rar15 => {
            Rar15Cipher::new(password).crypt_in_place(data);
            Ok(None)
        }
        ArchiveVersion::Rar20 => {
            let padded_len = checked_align16(data.len(), RAR15_ALIGN_OVERFLOW)?;
            data.resize(padded_len, 0);
            Rar20Cipher::new(password).encrypt_in_place(data)?;
            Ok(None)
        }
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
            let salt = random_rar30_salt()?;
            let padded_len = checked_align16(data.len(), RAR15_ALIGN_OVERFLOW)?;
            data.resize(padded_len, 0);
            Rar30Cipher::new(password, Some(salt))
                .map_err(super::map_rar30_crypto_error)?
                .encrypt_in_place(data)
                .map_err(super::map_rar30_crypto_error)?;
            Ok(Some(salt))
        }
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

fn writer_supports_file_encryption(target: ArchiveVersion) -> bool {
    matches!(
        target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    )
}

fn writer_supports_header_encryption(target: ArchiveVersion) -> bool {
    matches!(target, ArchiveVersion::Rar30 | ArchiveVersion::Rar40)
}

fn header_encryption_password<'a>(
    mut passwords: impl Iterator<Item = Option<&'a [u8]>>,
) -> Result<&'a [u8]> {
    let first = passwords.next().flatten().ok_or(Error::NeedPassword)?;
    for password in passwords {
        if password != Some(first) {
            return Err(Error::InvalidHeader(
                "RAR 3.x header-encrypted writer needs one shared password",
            ));
        }
    }
    Ok(first)
}

fn encrypt_packed_data_for_writer(
    data: &mut Vec<u8>,
    target: ArchiveVersion,
    password: Option<&[u8]>,
) -> Result<Option<[u8; 8]>> {
    let Some(password) = password else {
        return Ok(None);
    };
    validate_writer_password(target, Some(password))?;
    match target {
        ArchiveVersion::Rar15 => {
            Rar15Cipher::new(password).crypt_in_place(data);
            Ok(None)
        }
        ArchiveVersion::Rar20 => {
            let padded_len = checked_align16(data.len(), RAR15_ALIGN_OVERFLOW)?;
            data.resize(padded_len, 0);
            Rar20Cipher::new(password).encrypt_in_place(data)?;
            Ok(None)
        }
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
            let salt = random_rar30_salt()?;
            let padded_len =
                data.len()
                    .checked_add(15)
                    .map(|len| len & !15)
                    .ok_or(Error::InvalidHeader(
                        "RAR 3.x encrypted data size overflows",
                    ))?;
            data.resize(padded_len, 0);
            Rar30Cipher::new(password, Some(salt))
                .map_err(super::map_rar30_crypto_error)?
                .encrypt_in_place(data)
                .map_err(super::map_rar30_crypto_error)?;
            Ok(Some(salt))
        }
        _ => Err(Error::UnsupportedFeature {
            version: target,
            feature: "RAR writer file encryption",
        }),
    }
}

fn random_rar30_salt() -> Result<[u8; 8]> {
    let mut salt = [0; 8];
    crate::write_entropy::fill(
        &mut salt,
        "RAR 3.x writer could not generate encryption salt",
    )?;
    Ok(salt)
}

/// Whether this target carries an embedded recovery record as a `RR`
/// NEWSUB block.
///
/// RAR 2.0 and earlier protect an archive with an old-style
/// `PROTECT_HEAD` (`Protect!`) block instead, which is a different
/// layout with a different repair path; this writer builds only the
/// RAR 3.x form (`Protect+`), so those two targets are refused rather
/// than served something the extractor would read as the wrong record.
fn writer_supports_recovery_record(target: ArchiveVersion) -> bool {
    matches!(
        target,
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
    )
}

/// `MHD_PROTECT` when this archive will carry a recovery record.
///
/// The flag lives in the main header, which is INSIDE the region the
/// record protects, so it has to be right when the header is written -
/// setting it afterwards would move a byte the tags already cover and
/// leave sector 0 reading as damaged. Every caller therefore folds this
/// into its main flags rather than patching later.
fn recovery_main_flags(options: WriterOptions) -> u16 {
    if options.features.recovery_record {
        MHD_PROTECT
    } else {
        0
    }
}

/// Appends the `RR` NEWSUB recovery record over everything written so far.
///
/// Must be the last thing added to `out`: the record protects the bytes
/// that precede it and nothing else, and `rar15_40`'s repair path derives
/// the protected range from this block's own offset. Returns without
/// writing when the archive asked for no record.
fn append_recovery_record(out: &mut Vec<u8>, options: WriterOptions) -> Result<()> {
    if !options.features.recovery_record {
        return Ok(());
    }
    let percent = options.recovery_percent.ok_or(Error::InvalidHeader(
        "RAR 3.x recovery record requested with no percent",
    ))?;
    let plan = crate::recovery::rar3::plan_newsub_recovery(out.len(), percent)?;
    let data = crate::recovery::rar3::build_newsub_recovery_data(out, plan);
    let protected_sectors = u32::try_from(plan.protected_sectors)
        .map_err(|_| Error::InvalidHeader("RAR 3.x recovery protected sector count overflows"))?;
    let parity_sectors = u32::try_from(plan.parity_sectors)
        .map_err(|_| Error::InvalidHeader("RAR 3.x recovery parity sector count overflows"))?;
    // The 20 bytes `rar` writes after the `RR` name: the mark, the two
    // counts, then two reserved words. This crate's own repair path
    // reads none of them - it derives the geometry from the block
    // offset and the data length - but `rar` does, so a record that
    // omitted them would repair here and nowhere else.
    let mut extra = Vec::with_capacity(20);
    extra.extend_from_slice(b"Protect+");
    extra.extend_from_slice(&parity_sectors.to_le_bytes());
    extra.extend_from_slice(&protected_sectors.to_le_bytes());
    extra.extend_from_slice(&0u16.to_le_bytes());
    extra.extend_from_slice(&0u16.to_le_bytes());
    write_file_header_and_data(
        out,
        FileRecord {
            head_type: NEWSUB_HEAD,
            name: b"RR",
            unpacked_size: data.len(),
            file_crc: crc32(&data),
            packed: &data,
            file_time: 0,
            file_attr: 0,
            host_os: 3,
            target: ArchiveVersion::Rar30,
            method: 0x30,
            dictionary_flags: 0,
            flags: SKIP_IF_UNKNOWN,
            salt: None,
            extra: &extra,
        },
    )
}

fn write_main_header(out: &mut Vec<u8>, flags: u16) {
    let start = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(MAIN_HEAD);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&13u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    write_header_crc(out, start);
}

fn write_comment_header(out: &mut Vec<u8>, comment: Option<&[u8]>) -> Result<()> {
    let Some(comment) = comment else {
        return Ok(());
    };
    let unp_size = u16::try_from(comment.len())
        .map_err(|_| Error::InvalidHeader("RAR 1.5 archive comment is too long"))?;
    let head_size = 13usize
        .checked_add(comment.len())
        .ok_or(Error::InvalidHeader(
            "RAR 1.5 comment header size overflows",
        ))?;
    let head_size = u16::try_from(head_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 comment header size overflows"))?;

    let start = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(COMM_HEAD);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&head_size.to_le_bytes());
    out.extend_from_slice(&unp_size.to_le_bytes());
    out.push(15);
    out.push(0x30);
    out.extend_from_slice(&((crc32(comment) & 0xffff) as u16).to_le_bytes());
    out.extend_from_slice(comment);
    write_comment_header_crc(out, start);
    Ok(())
}

fn uses_old_style_archive_comment(target: ArchiveVersion) -> bool {
    matches!(
        target,
        ArchiveVersion::Rar15 | ArchiveVersion::Rar20 | ArchiveVersion::Rar29
    )
}

fn write_archive_comment(
    out: &mut Vec<u8>,
    comment: Option<&[u8]>,
    target: ArchiveVersion,
) -> Result<()> {
    if uses_old_style_archive_comment(target) {
        return write_comment_header(out, comment);
    }
    match target {
        ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => write_newsub_archive_comment(out, comment),
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

fn write_newsub_archive_comment(out: &mut Vec<u8>, comment: Option<&[u8]>) -> Result<()> {
    let Some(comment) = comment else {
        return Ok(());
    };
    let packed = unpack29_encode_literals(comment)?;
    write_file_header_and_data(
        out,
        FileRecord {
            head_type: NEWSUB_HEAD,
            name: b"CMT",
            unpacked_size: comment.len(),
            file_crc: crc32(comment),
            packed: &packed,
            file_time: 0,
            file_attr: 0,
            host_os: 3,
            target: ArchiveVersion::Rar30,
            method: 0x33,
            dictionary_flags: dictionary_flags_for_target(ArchiveVersion::Rar30),
            flags: 0,
            salt: None,
            extra: &[],
        },
    )
}

fn write_stored_entry(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    options: WriterOptions,
) -> Result<()> {
    let target = options.target;
    validate_stored_entry(entry)?;
    validate_writer_password(target, entry.password)?;
    let mut packed = entry.data.to_vec();
    let salt = encrypt_packed_data_for_writer(&mut packed, target, entry.password)?;
    let mut flags = writer_file_flags(entry.password, entry.file_comment, false);
    if salt.is_some() {
        flags |= FHD_SALT;
    }
    let file_comment = encode_file_comment(entry.file_comment)?;
    write_file_header_and_data(
        out,
        FileRecord {
            head_type: FILE_HEAD,
            name: entry.name,
            unpacked_size: entry.data.len(),
            file_crc: crc32(entry.data),
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target,
            method: 0x30,
            dictionary_flags: dictionary_flags_for_options(options)?,
            flags,
            salt,
            extra: &file_comment,
        },
    )
}

fn write_compressed_entry(
    out: &mut Vec<u8>,
    entry: &FileEntry<'_>,
    packed: &[u8],
    method: u8,
    target: ArchiveVersion,
    dictionary_flags: u16,
    solid_continuation: bool,
) -> Result<()> {
    validate_file_entry(entry.name, entry.data)?;
    validate_writer_password(target, entry.password)?;
    let mut packed = packed.to_vec();
    let salt = encrypt_packed_data_for_writer(&mut packed, target, entry.password)?;
    let mut flags = writer_file_flags(entry.password, entry.file_comment, solid_continuation);
    if salt.is_some() {
        flags |= FHD_SALT;
    }
    let file_comment = encode_file_comment(entry.file_comment)?;
    write_file_header_and_data(
        out,
        FileRecord {
            head_type: FILE_HEAD,
            name: entry.name,
            unpacked_size: entry.data.len(),
            file_crc: crc32(entry.data),
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target,
            method,
            dictionary_flags,
            flags,
            salt,
            extra: &file_comment,
        },
    )
}

fn write_header_encrypted_stored_entry(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    options: WriterOptions,
    header_password: &[u8],
) -> Result<()> {
    let target = options.target;
    validate_stored_entry(entry)?;
    validate_writer_password(target, entry.password)?;
    let mut packed = entry.data.to_vec();
    let salt = encrypt_packed_data_for_writer(&mut packed, target, entry.password)?;
    let mut flags = writer_file_flags(entry.password, entry.file_comment, false);
    if salt.is_some() {
        flags |= FHD_SALT;
    }
    let file_comment = encode_file_comment(entry.file_comment)?;
    let mut header = Vec::new();
    write_file_header(
        &mut header,
        &FileRecord {
            head_type: FILE_HEAD,
            name: entry.name,
            unpacked_size: entry.data.len(),
            file_crc: crc32(entry.data),
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target,
            method: 0x30,
            dictionary_flags: dictionary_flags_for_options(options)?,
            flags,
            salt,
            extra: &file_comment,
        },
    )?;
    write_encrypted_header_and_data(out, &header, &packed, header_password)
}

fn write_header_encrypted_compressed_entry(
    out: &mut Vec<u8>,
    entry: &FileEntry<'_>,
    packed: &[u8],
    method: u8,
    options: WriterOptions,
    solid_continuation: bool,
    header_password: &[u8],
) -> Result<()> {
    let target = options.target;
    validate_file_entry(entry.name, entry.data)?;
    validate_writer_password(target, entry.password)?;
    let mut packed = packed.to_vec();
    let salt = encrypt_packed_data_for_writer(&mut packed, target, entry.password)?;
    let mut flags = writer_file_flags(entry.password, entry.file_comment, solid_continuation);
    if salt.is_some() {
        flags |= FHD_SALT;
    }
    let file_comment = encode_file_comment(entry.file_comment)?;
    let mut header = Vec::new();
    write_file_header(
        &mut header,
        &FileRecord {
            head_type: FILE_HEAD,
            name: entry.name,
            unpacked_size: entry.data.len(),
            file_crc: crc32(entry.data),
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target,
            method,
            dictionary_flags: dictionary_flags_for_options(options)?,
            flags,
            salt,
            extra: &file_comment,
        },
    )?;
    write_encrypted_header_and_data(out, &header, &packed, header_password)
}

fn write_encrypted_header_and_data(
    out: &mut Vec<u8>,
    header: &[u8],
    data: &[u8],
    password: &[u8],
) -> Result<()> {
    let salt = random_rar30_salt()?;
    let encrypted_size = checked_align16(header.len(), RAR15_ALIGN_OVERFLOW)?;
    let mut encrypted_header = Vec::with_capacity(encrypted_size);
    encrypted_header.extend_from_slice(header);
    encrypted_header.resize(encrypted_size, 0);
    Rar30Cipher::new(password, Some(salt))
        .map_err(super::map_rar30_crypto_error)?
        .encrypt_in_place(&mut encrypted_header)
        .map_err(super::map_rar30_crypto_error)?;
    out.extend_from_slice(&salt);
    out.extend_from_slice(&encrypted_header);
    out.extend_from_slice(data);
    Ok(())
}

fn validate_writer_password(target: ArchiveVersion, password: Option<&[u8]>) -> Result<()> {
    if password.is_some() && !writer_supports_file_encryption(target) {
        return Err(Error::UnsupportedFeature {
            version: target,
            feature: "RAR writer file encryption",
        });
    }
    Ok(())
}

fn validate_stored_entry(entry: &StoredEntry<'_>) -> Result<()> {
    if entry.name.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 file name is empty"));
    }
    if entry.name.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader("RAR 1.5 file name is too long"));
    }
    if entry.data.len() > u32::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.5 store-only writer does not support large files",
        ));
    }
    Ok(())
}

fn validate_file_entry(name: &[u8], data: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 file name is empty"));
    }
    if name.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader("RAR 1.5 file name is too long"));
    }
    if data.len() > u32::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.5 writer does not support large files",
        ));
    }
    Ok(())
}

struct FileRecord<'a> {
    head_type: u8,
    name: &'a [u8],
    unpacked_size: usize,
    file_crc: u32,
    packed: &'a [u8],
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    target: ArchiveVersion,
    method: u8,
    dictionary_flags: u16,
    flags: u16,
    salt: Option<[u8; 8]>,
    extra: &'a [u8],
}

fn write_file_header_and_data(out: &mut Vec<u8>, record: FileRecord<'_>) -> Result<()> {
    write_file_header(out, &record)?;
    out.extend_from_slice(record.packed);
    Ok(())
}

fn write_file_header(out: &mut Vec<u8>, record: &FileRecord<'_>) -> Result<()> {
    let start = out.len();
    let flags = record.flags | record.dictionary_flags;
    let (host_os, file_attr) =
        rar15_compatible_metadata(record.target, record.host_os, record.file_attr);
    let packed_size = u32::try_from(record.packed.len())
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed size overflows u32"))?;
    let unpacked_size = u32::try_from(record.unpacked_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows u32"))?;
    let head_size = 32usize
        .checked_add(record.name.len())
        .and_then(|size| size.checked_add(if record.salt.is_some() { 8 } else { 0 }))
        .and_then(|size| size.checked_add(record.extra.len()))
        .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    let head_size = u16::try_from(head_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    let unp_ver = match record.target {
        ArchiveVersion::Rar15 => 15,
        ArchiveVersion::Rar20 => 20,
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => 29,
        _ => return Err(Error::UnsupportedVersion(record.target)),
    };
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(record.head_type);
    out.extend_from_slice(&(LONG_BLOCK | flags).to_le_bytes());
    out.extend_from_slice(&head_size.to_le_bytes());
    out.extend_from_slice(&packed_size.to_le_bytes());
    out.extend_from_slice(&unpacked_size.to_le_bytes());
    out.push(host_os);
    out.extend_from_slice(&record.file_crc.to_le_bytes());
    out.extend_from_slice(&record.file_time.to_le_bytes());
    out.push(unp_ver);
    out.push(record.method);
    out.extend_from_slice(&(record.name.len() as u16).to_le_bytes());
    out.extend_from_slice(&file_attr.to_le_bytes());
    out.extend_from_slice(record.name);
    if let Some(salt) = record.salt {
        out.extend_from_slice(&salt);
    }
    out.extend_from_slice(record.extra);
    write_file_header_crc(out, start, record.name.len(), flags);
    Ok(())
}

fn rar15_compatible_metadata(target: ArchiveVersion, host_os: u8, file_attr: u32) -> (u8, u32) {
    const HOST_DOS: u8 = 0;
    const HOST_UNIX: u8 = 3;
    const DOS_ARCHIVE: u32 = 0x20;
    const DOS_DIRECTORY: u32 = 0x10;
    const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
    const UNIX_DIRECTORY: u32 = 0o040000;

    if target == ArchiveVersion::Rar15 && host_os == HOST_UNIX {
        let dos_attr = if file_attr & UNIX_FILE_TYPE_MASK == UNIX_DIRECTORY {
            DOS_DIRECTORY
        } else {
            DOS_ARCHIVE
        };
        return (HOST_DOS, dos_attr);
    }
    (host_os, file_attr)
}

fn dictionary_flags_for_target(target: ArchiveVersion) -> u16 {
    ((rar29_default_dictionary_size(target).trailing_zeros() - 16) as u16) << 5
}

struct SplitVolumeRecord<'a> {
    name: &'a [u8],
    unpacked: &'a [u8],
    packed: &'a [u8],
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    target: ArchiveVersion,
    method: u8,
    dictionary_flags: u16,
    base_flags: u16,
    main_flags: u16,
    password: Option<&'a [u8]>,
    max_packed_per_volume: usize,
}

fn write_split_volumes(entry: SplitVolumeRecord<'_>) -> Result<Vec<Vec<u8>>> {
    if entry.max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume payload size must be non-zero",
        ));
    }
    if entry.packed.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs a non-empty packed payload",
        ));
    }

    let mut packed = entry.packed.to_vec();
    let split_salt = if let Some(password) = entry.password {
        encrypt_split_packed_data(&mut packed, entry.target, password)?
    } else {
        None
    };
    let base_flags = entry.base_flags | if split_salt.is_some() { FHD_SALT } else { 0 };

    let chunks: Vec<&[u8]> = packed.chunks(entry.max_packed_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least two volumes",
        ));
    }

    let mut volumes = Vec::with_capacity(chunks.len());
    let unpacked_crc = crc32(entry.unpacked);
    for (index, chunk) in chunks.iter().enumerate() {
        let split_before = index > 0;
        let split_after = index + 1 < chunks.len();
        let mut file_flags = base_flags;
        if split_before {
            file_flags |= FHD_SPLIT_BEFORE;
        }
        if split_after {
            file_flags |= FHD_SPLIT_AFTER;
        }

        let mut main_flags = MHD_VOLUME | entry.main_flags;
        if index == 0 {
            main_flags |= MHD_FIRSTVOLUME;
        }

        let mut out = Vec::new();
        out.extend_from_slice(RAR15_SIGNATURE);
        write_main_header(&mut out, main_flags);
        write_file_header_and_data(
            &mut out,
            FileRecord {
                head_type: FILE_HEAD,
                name: entry.name,
                unpacked_size: entry.unpacked.len(),
                file_crc: if split_after {
                    crc32(chunk)
                } else {
                    unpacked_crc
                },
                packed: chunk,
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                host_os: entry.host_os,
                target: entry.target,
                method: entry.method,
                dictionary_flags: entry.dictionary_flags,
                flags: file_flags,
                salt: split_salt,
                extra: &[],
            },
        )?;
        volumes.push(out);
    }

    Ok(volumes)
}

/// One member of a multi-member volume set, already packed and, where a
/// password was given, already encrypted.
///
/// The packed bytes are encrypted ONCE for the whole member and then cut
/// at the volume boundaries, which is what the single-member writer does
/// and what the reader expects: `validate_split_continuation_refs`
/// refuses a set whose fragments disagree about the salt, so a member
/// carries exactly one.
struct VolumeSetMember<'a> {
    name: &'a [u8],
    unpacked_len: usize,
    unpacked_crc: u32,
    packed: Vec<u8>,
    salt: Option<[u8; 8]>,
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    password: Option<&'a [u8]>,
    method: u8,
    base_flags: u16,
}

/// `'a` is what the built member keeps (its name and password); `'p` is
/// the payload, which the builder copies before returning, so a caller
/// may hand over an encoded buffer it is about to drop.
struct VolumeSetMemberInput<'a, 'p> {
    name: &'a [u8],
    unpacked: &'p [u8],
    packed: &'p [u8],
    method: u8,
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    password: Option<&'a [u8]>,
    solid_continuation: bool,
    target: ArchiveVersion,
}

fn volume_set_member<'a>(input: VolumeSetMemberInput<'a, '_>) -> Result<VolumeSetMember<'a>> {
    if input.packed.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs a non-empty packed payload",
        ));
    }
    let mut packed = input.packed.to_vec();
    let salt = match input.password {
        Some(password) => encrypt_split_packed_data(&mut packed, input.target, password)?,
        None => None,
    };
    let mut base_flags = writer_file_flags(input.password, None, input.solid_continuation);
    if salt.is_some() {
        base_flags |= FHD_SALT;
    }
    Ok(VolumeSetMember {
        name: input.name,
        unpacked_len: input.unpacked.len(),
        unpacked_crc: crc32(input.unpacked),
        packed,
        salt,
        file_time: input.file_time,
        file_attr: input.file_attr,
        host_os: input.host_os,
        password: input.password,
        method: input.method,
        base_flags,
    })
}

/// Pack several members end to end across the volumes.
///
/// [`write_split_volumes`] chunks ONE member's payload and gives each
/// chunk a volume of its own. This walks a payload cursor across the
/// members instead, so a volume can hold the tail of one member, whole
/// members, and the head of the next - the layout `rar a -v` writes and
/// the one [`crate::rar15_40::extract_volumes_to`] already reads, since
/// its split state machine is per file header and not per volume.
///
/// The whole-file CRC rides the LAST fragment of each member and a
/// middle fragment carries its own chunk CRC, exactly as the
/// single-member writer does.
fn write_volume_set(
    members: &[VolumeSetMember<'_>],
    options: WriterOptions,
    main_flags: u16,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    if max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume payload size must be non-zero",
        ));
    }
    if members.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least one entry",
        ));
    }
    let header_password = if options.features.header_encryption {
        validate_header_encrypted_archive_options(options, false, options.features.solid)?;
        Some(header_encryption_password(
            members.iter().map(|member| member.password),
        )?)
    } else {
        None
    };
    let dictionary_flags = dictionary_flags_for_options(options)?;

    let mut bodies: Vec<Vec<u8>> = Vec::new();
    let mut body: Option<Vec<u8>> = None;
    let mut packed_in_volume = 0usize;
    for member in members {
        let mut start = 0usize;
        let mut split_before = false;
        while start < member.packed.len() {
            if body.is_none() {
                body = Some(Vec::new());
                packed_in_volume = 0;
            }
            let room = max_packed_per_volume - packed_in_volume;
            let fragment = room.min(member.packed.len() - start);
            let end = start + fragment;
            let split_after = end < member.packed.len();
            let chunk = &member.packed[start..end];
            let mut flags = member.base_flags;
            if split_before {
                flags |= FHD_SPLIT_BEFORE;
            }
            if split_after {
                flags |= FHD_SPLIT_AFTER;
            }
            let record = FileRecord {
                head_type: FILE_HEAD,
                name: member.name,
                unpacked_size: member.unpacked_len,
                file_crc: if split_after {
                    crc32(chunk)
                } else {
                    member.unpacked_crc
                },
                packed: chunk,
                file_time: member.file_time,
                file_attr: member.file_attr,
                host_os: member.host_os,
                target: options.target,
                method: member.method,
                dictionary_flags,
                flags,
                salt: member.salt,
                extra: &[],
            };
            // Invariant: the branch above starts a body whenever none exists.
            let out = body.as_mut().expect("volume body started");
            match header_password {
                Some(password) => {
                    let mut header = Vec::new();
                    write_file_header(&mut header, &record)?;
                    write_encrypted_header_and_data(out, &header, chunk, password)?;
                }
                None => write_file_header_and_data(out, record)?,
            }
            packed_in_volume += fragment;
            start = end;
            split_before = true;
            if packed_in_volume == max_packed_per_volume {
                // Invariant: the body exists - this arm runs after a write into it.
                bodies.push(body.take().expect("volume body started"));
                packed_in_volume = 0;
            }
        }
    }
    if let Some(finished) = body.take() {
        bodies.push(finished);
    }
    if bodies.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least two volumes",
        ));
    }

    // The end headers are written here rather than inside the loop
    // because only the FULL set knows which body is the last one: a
    // member that ends exactly on a volume boundary closes its volume
    // with nothing following, and marking that one "next volume" would
    // send a reader looking for a volume that does not exist.
    let last = bodies.len() - 1;
    let mut volumes = Vec::with_capacity(bodies.len());
    for (index, body) in bodies.iter().enumerate() {
        volumes.push(finish_volume(
            body,
            index,
            main_flags,
            header_password,
            index == last,
        )?);
    }
    Ok(volumes)
}

/// Wrap one volume's file blocks in its own archive.
///
/// The end header is what chains the set. [`write_split_volumes`] omits
/// it and gets away with it because its single member is split across
/// EVERY volume, so `FHD_SPLIT_AFTER` alone tells a reader to continue.
/// A multi-member set has volumes whose last file is complete, and a
/// reference reader stops there unless an `ENDARC` block says another
/// volume follows - measured against unrar 7.23, which extracted only
/// the first member without it.
fn finish_volume(
    body: &[u8],
    index: usize,
    main_flags: u16,
    header_password: Option<&[u8]>,
    last: bool,
) -> Result<Vec<u8>> {
    let mut flags = MHD_VOLUME | main_flags;
    if index == 0 {
        flags |= MHD_FIRSTVOLUME;
    }
    if header_password.is_some() {
        flags |= MHD_PASSWORD;
    }
    let mut out = Vec::with_capacity(RAR15_SIGNATURE.len() + 20 + body.len());
    out.extend_from_slice(RAR15_SIGNATURE);
    write_main_header(&mut out, flags);
    out.extend_from_slice(body);
    let end_flags = if last { 0 } else { EARC_NEXT_VOLUME };
    match header_password {
        Some(password) => {
            let mut end = Vec::new();
            write_end_header(&mut end, end_flags);
            write_encrypted_header_and_data(&mut out, &end, &[], password)?;
        }
        None => write_end_header(&mut out, end_flags),
    }
    Ok(out)
}

fn write_end_header(out: &mut Vec<u8>, flags: u16) {
    let start = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(ENDARC_HEAD);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&7u16.to_le_bytes());
    write_header_crc(out, start);
}


fn write_header_encrypted_split_volumes(entry: SplitVolumeRecord<'_>) -> Result<Vec<Vec<u8>>> {
    validate_header_encrypted_archive_options(
        WriterOptions {
            target: entry.target,
            features: {
                let mut features = FeatureSet::store_only();
                features.file_encryption = entry.password.is_some();
                features.header_encryption = true;
                features.solid = entry.main_flags & MHD_SOLID != 0;
                features
            },
            compression_level: None,
            dictionary_size: None,
            // Validation only. The caller installed the real setting
            // before it reached here, and no draw reads this value.
            entropy: Entropy::Os,
            // Validation only, as above: the numbering already reached
            // the record's `main_flags` at the caller.
            volume_numbering: VolumeNumbering::Classic,
            // Same: a volume set never carries a recovery record
            // (`validate_volume_writer_inputs` refused one before this
            // function was reached), so there is nothing to validate.
            recovery_percent: None,
        },
        false,
        entry.main_flags & MHD_SOLID != 0,
    )?;
    let password = entry.password.ok_or(Error::NeedPassword)?;
    if entry.max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume payload size must be non-zero",
        ));
    }
    if entry.packed.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs a non-empty packed payload",
        ));
    }

    let mut packed = entry.packed.to_vec();
    let split_salt = encrypt_split_packed_data(&mut packed, entry.target, password)?;
    let base_flags = entry.base_flags | FHD_SALT;
    let chunks: Vec<&[u8]> = packed.chunks(entry.max_packed_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least two volumes",
        ));
    }

    let mut volumes = Vec::with_capacity(chunks.len());
    let unpacked_crc = crc32(entry.unpacked);
    for (index, chunk) in chunks.iter().enumerate() {
        let split_before = index > 0;
        let split_after = index + 1 < chunks.len();
        let mut file_flags = base_flags;
        if split_before {
            file_flags |= FHD_SPLIT_BEFORE;
        }
        if split_after {
            file_flags |= FHD_SPLIT_AFTER;
        }

        let mut main_flags = MHD_VOLUME | MHD_PASSWORD | entry.main_flags;
        if index == 0 {
            main_flags |= MHD_FIRSTVOLUME;
        }

        let mut out = Vec::new();
        out.extend_from_slice(RAR15_SIGNATURE);
        write_main_header(&mut out, main_flags);
        let mut header = Vec::new();
        write_file_header(
            &mut header,
            &FileRecord {
                head_type: FILE_HEAD,
                name: entry.name,
                unpacked_size: entry.unpacked.len(),
                file_crc: if split_after {
                    crc32(chunk)
                } else {
                    unpacked_crc
                },
                packed: chunk,
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                host_os: entry.host_os,
                target: entry.target,
                method: entry.method,
                dictionary_flags: entry.dictionary_flags,
                flags: file_flags,
                salt: split_salt,
                extra: &[],
            },
        )?;
        write_encrypted_header_and_data(&mut out, &header, chunk, password)?;
        volumes.push(out);
    }

    Ok(volumes)
}

fn write_header_crc(out: &mut [u8], start: usize) {
    let crc = (crc32(&out[start + 2..]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

fn write_file_header_crc(out: &mut [u8], start: usize, name_len: usize, flags: u16) {
    let end = if flags & FHD_COMMENT != 0 {
        start + 32 + name_len
    } else {
        out.len()
    };
    let crc = (crc32(&out[start + 2..end]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

fn write_comment_header_crc(out: &mut [u8], start: usize) {
    let end = start + 13;
    let crc = (crc32(&out[start + 2..end]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::{
        auto_delta_filter_range, auto_x86_filter_ranges, disjoint_filter_ranges,
        encode_rar29_auto_filtered_member, encode_rar29_filtered_member,
        encode_rar29_filtered_members, is_audio_filter_candidate, rar29_encode_options_for_options,
        FilterKind, FilterSpec, AUTO_DELTA_EDGE_SKIP, RAR29_LARGE_TEXT_PPMD_THRESHOLD,
    };
    use crate::codec::rar29::{unpack29_decode, EncodeOptions};
    use crate::{ArchiveVersion, FeatureSet};

    #[test]
    fn auto_x86_filter_ranges_select_dense_opcode_clusters() {
        let mut data = vec![0x41; 20_000];
        for pos in [1024, 1050, 1090, 1130] {
            data[pos] = 0xe8;
        }
        for pos in [12_000, 12_040, 12_080] {
            data[pos] = 0xe9;
        }

        let e8_ranges = auto_x86_filter_ranges(&data, false);
        assert_eq!(e8_ranges.len(), 1);
        assert!(e8_ranges[0].contains(&1024));
        assert!(e8_ranges[0].contains(&(1130 + 4)));
        assert!(!e8_ranges[0].contains(&12_000));

        let e8e9_ranges = auto_x86_filter_ranges(&data, true);
        assert_eq!(e8e9_ranges.len(), 3);
        assert!(e8e9_ranges[0].contains(&1024));
        assert!(e8e9_ranges[0].contains(&12_000));
        assert!(e8e9_ranges.iter().any(|range| range.contains(&1024)));
        assert!(e8e9_ranges.iter().any(|range| range.contains(&12_000)));
    }

    #[test]
    fn large_text_ppmd_candidate_accepts_html_like_payloads() {
        let mut data = vec![b'a'; RAR29_LARGE_TEXT_PPMD_THRESHOLD + 1];
        for index in (0..data.len()).step_by(79) {
            data[index] = b'\n';
        }
        data[..32].copy_from_slice(b"<html><body>RAR PPMd text sample");

        assert!(super::is_large_text_ppmd_candidate(&data));
    }

    #[test]
    fn large_text_ppmd_candidate_rejects_binary_payloads() {
        let mut data = vec![0u8; RAR29_LARGE_TEXT_PPMD_THRESHOLD + 1];
        for index in (0..data.len()).step_by(257) {
            data[index] = b'A';
        }

        assert!(!super::is_large_text_ppmd_candidate(&data));
    }

    #[test]
    fn auto_ppmd_candidate_rejects_binary_audio_shaped_payloads() {
        let mut data = Vec::new();
        for sample in 0..8192i16 {
            let left = sample.wrapping_mul(5).wrapping_add(200);
            let right = sample.wrapping_mul(7).wrapping_sub(200);
            data.extend_from_slice(&left.to_le_bytes());
            data.extend_from_slice(&right.to_le_bytes());
        }

        assert!(!super::is_auto_ppmd_candidate(&data));
    }

    #[test]
    fn auto_ppmd_candidate_accepts_text_payloads() {
        let data = b"fn main() {\n    println!(\"rar ppmd text candidate\");\n}\n".repeat(256);

        assert!(super::is_auto_ppmd_candidate(&data));
    }

    #[test]
    fn audio_filter_candidate_accepts_interleaved_pcm_like_payloads() {
        let mut data = Vec::new();
        for sample in 0..4096i16 {
            let left = sample.wrapping_mul(3).wrapping_add(200);
            let right = sample.wrapping_mul(3).wrapping_sub(200);
            data.extend_from_slice(&left.to_le_bytes());
            data.extend_from_slice(&right.to_le_bytes());
        }

        assert!(is_audio_filter_candidate(&data, 4));
        assert!(!is_audio_filter_candidate(&data, 3));
    }

    #[test]
    fn audio_filter_candidate_rejects_high_entropy_binary_payloads() {
        let mut state = 0xfeed_faceu32;
        let data: Vec<_> = (0..16_384)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();

        for channels in 1..=4 {
            assert!(!is_audio_filter_candidate(&data, channels));
        }
    }

    #[test]
    fn auto_filtered_rar29_large_text_uses_ppmd_before_lz_candidates() {
        let mut data = vec![b'x'; RAR29_LARGE_TEXT_PPMD_THRESHOLD + 1];
        for index in (0..data.len()).step_by(97) {
            data[index] = b' ';
        }

        assert!(super::is_large_text_ppmd_candidate(&data));
    }

    #[test]
    fn auto_x86_filter_ranges_include_code_section_spans() {
        let mut data = vec![0x41; 32_000];
        for pos in [4096, 4128, 4160] {
            data[pos] = 0xe8;
        }
        for pos in [14_000, 14_032, 14_064] {
            data[pos] = 0xe8;
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        assert!(ranges[0].contains(&4096));
        assert!(ranges[0].contains(&14_064));
        assert!(ranges.iter().any(|range| range.contains(&4096)));
        assert!(ranges.iter().any(|range| range.contains(&14_064)));
    }

    #[test]
    fn auto_x86_policy_can_encode_multiple_disjoint_ranges() {
        let mut data = vec![0x41u8; 80_000];
        for cluster_start in [8_000, 60_000] {
            for index in 0..8 {
                let pos = cluster_start + index * 64;
                data[pos] = 0xe8;
                data[pos + 1..pos + 5].copy_from_slice(&(0x2000u32 + index as u32).to_le_bytes());
            }
        }
        let filters: Vec<_> = disjoint_filter_ranges(auto_x86_filter_ranges(&data, false))
            .into_iter()
            .map(|range| FilterSpec::range(FilterKind::E8, range))
            .collect();

        let packed = encode_rar29_filtered_members(&data, &filters, EncodeOptions::default())
            .expect("multi-filter RAR29 member should encode");
        let decoded = unpack29_decode(&packed, data.len()).unwrap();

        assert_eq!(filters.len(), 2);
        assert!(
            decoded == data,
            "RAR 2.9 auto multi-filter E8 round-trip failed"
        );
    }

    #[test]
    fn auto_x86_policy_considers_tight_ranges_inside_sparse_spans() {
        let mut data = Vec::new();
        data.extend((0..1024).map(|index| (index * 37 + 11) as u8));
        let first_cluster_start = data.len();
        for index in 0..16usize {
            data.extend_from_slice(&[0x55, 0x8b, 0xec, 0x83, 0xec, (index & 0x7f) as u8]);
            let call_pos = data.len();
            data.push(0xe8);
            let target = first_cluster_start + 0x500;
            let relative = (target as i64 - (call_pos + 5) as i64) as i32;
            data.extend_from_slice(&relative.to_le_bytes());
            data.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5d, 0xc3]);
        }
        data.extend((0..3200).map(|index| (index * 251 + 17) as u8));
        let second_cluster_start = data.len();
        for index in 0..16usize {
            data.extend_from_slice(&[0x56, 0x8b, 0xf1, 0x83, 0xec, (index & 0x7f) as u8]);
            let call_pos = data.len();
            data.push(0xe8);
            let target = second_cluster_start + 0x500;
            let relative = (target as i64 - (call_pos + 5) as i64) as i32;
            data.extend_from_slice(&relative.to_le_bytes());
            data.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5e, 0xc3]);
        }
        data.extend((0..1024).map(|index| (index * 53 + 7) as u8));

        let ranges = disjoint_filter_ranges(auto_x86_filter_ranges(&data, false));
        let filters: Vec<_> = ranges
            .iter()
            .cloned()
            .map(|range| FilterSpec::range(FilterKind::E8, range))
            .collect();
        let broad_range = first_cluster_start..second_cluster_start + 16 * 16;
        let broad = encode_rar29_filtered_member(
            &data,
            FilterSpec::range(FilterKind::E8, broad_range),
            EncodeOptions::default(),
        )
        .unwrap();
        let tight = encode_rar29_filtered_members(&data, &filters, EncodeOptions::default())
            .expect("tight sparse x86 filters should encode");
        let auto = encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, false)
            .unwrap();

        assert!(
            tight.len() < broad.len(),
            "tight x86 ranges should avoid filtering sparse data gaps"
        );
        assert!(auto.data.len() <= tight.len());
        assert_eq!(unpack29_decode(&auto.data, data.len()).unwrap(), data);
    }

    #[test]
    fn auto_delta_filter_range_skips_container_edges_and_aligns_channels() {
        let data = vec![0u8; 512];

        let range = auto_delta_filter_range(&data, 3).unwrap();

        assert!(range.start >= AUTO_DELTA_EDGE_SKIP);
        assert!(range.end <= data.len() - AUTO_DELTA_EDGE_SKIP);
        assert_eq!(range.start % 3, 0);
        assert_eq!((range.end - range.start) % 3, 0);
        assert!(auto_delta_filter_range(&data[..80], 3).is_none());
    }

    #[test]
    fn auto_filter_policy_considers_ranged_delta_candidates() {
        let mut data = vec![0x55u8; AUTO_DELTA_EDGE_SKIP];
        for sample in 0..256u16 {
            let left = sample as u8;
            let right = left.wrapping_add(1);
            data.extend_from_slice(&[left, right]);
        }
        data.extend(std::iter::repeat_n(0xaa, AUTO_DELTA_EDGE_SKIP));
        let options = EncodeOptions::default();

        let plain =
            crate::codec::rar29::unpack29_encode_literals_with_options(&data, options).unwrap();
        let ranged = encode_rar29_filtered_member(
            &data,
            FilterSpec::range(
                FilterKind::Delta { channels: 2 },
                auto_delta_filter_range(&data, 2).unwrap(),
            ),
            options,
        )
        .unwrap();
        let auto = encode_rar29_auto_filtered_member(&data, options, 0x35, true).unwrap();

        assert!(ranged.len() < plain.len());
        assert!(auto.data.len() <= ranged.len());
    }

    #[test]
    fn rar29_options_cap_match_distance_to_target_dictionary() {
        assert_eq!(
            rar29_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
                    .with_compression_level(5)
            )
            .unwrap()
            .max_match_distance,
            1024 * 1024
        );
        assert_eq!(
            rar29_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only())
                    .with_compression_level(5)
            )
            .unwrap()
            .max_match_distance,
            128 * 1024
        );
        assert_eq!(
            rar29_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only())
                    .with_compression_level(5)
                    .with_dictionary_size(4 * 1024 * 1024)
            )
            .unwrap()
            .max_match_distance,
            4 * 1024 * 1024
        );
    }
}
