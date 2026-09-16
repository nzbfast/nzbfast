use super::*;
use crate::codec::rar50::EncoderScratchPool;

pub(super) fn write_stored_volumes_impl(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    max_data_per_volume: usize,
    recovery_percent: Option<u64>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_recovery_options(options)?;
    } else {
        validate_options(options)?;
    }
    validate_entry(&entry)?;
    if options.features.archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 volume comments",
        });
    }
    if max_data_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 volume payload size must be non-zero",
        ));
    }
    if entry.data.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 volume writer needs a non-empty payload",
        ));
    }

    let chunks: Vec<&[u8]> = entry.data.chunks(max_data_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 volume writer needs at least two volumes",
        ));
    }

    let mut writer = VolumeSetWriter::new(
        max_data_per_volume,
        options.features.solid,
        None,
        recovery_percent,
    );
    for (index, chunk) in chunks.iter().enumerate() {
        writer.write_member(
            chunk.len(),
            |out, start, end, _split_before, _split_after| {
                debug_assert_eq!(start, 0);
                debug_assert_eq!(end, chunk.len());
                // The whole-file CRC rides the LAST fragment, as the
                // compressed branch already does: a split stored member
                // with no checksum anywhere extracts corrupt bytes as a
                // success, which made every fixture built here over
                // incompressible data unverifiable. (nzbfast-local
                // change, 22 Aug 2026 - see vendor/rars/VENDORING.md.)
                let last = index + 1 >= chunks.len();
                write_stored_entry_fragment(
                    out,
                    &entry,
                    chunk,
                    entry.data.len() as u64,
                    last.then(|| crc32(entry.data)),
                    index > 0,
                    !last,
                    options.hash_record,
                )
            },
        )?;
    }

    writer.finish()
}

/// A split STORED set holding SEVERAL members.
///
/// [`write_stored_volumes_impl`] splits ONE member across the volumes.
/// This one walks a slice through the same [`VolumeSetWriter`] the
/// compressed set already uses, so members pack end to end and only the
/// one that lands on a volume boundary carries the split flags. That is
/// the shape a poster makes with `rar a -v50M set.rar a.mkv b.nfo`, and
/// nothing here could emit it before (nzbfast-local change, 4 Sep 2026 -
/// see vendor/rars/VENDORING.md).
///
/// The whole-file CRC rides the LAST fragment of each member and the
/// blake2sp hash record rides a member that was not split at all, both
/// exactly as the compressed set's stored arm does: a split stored
/// member with no checksum anywhere extracts corrupt bytes as a success.
pub(super) fn write_stored_volume_set_impl(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    max_data_per_volume: usize,
    recovery_percent: Option<u64>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_recovery_options(options)?;
    } else {
        validate_options(options)?;
    }
    if options.features.archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 volume comments",
        });
    }
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
    for entry in entries {
        validate_entry(entry)?;
        if entry.data.is_empty() {
            return Err(Error::InvalidHeader(
                "RAR 5 volume writer needs a non-empty payload",
            ));
        }
    }

    let mut writer = VolumeSetWriter::new(
        max_data_per_volume,
        options.features.solid,
        None,
        recovery_percent,
    );
    for entry in entries {
        writer.write_member(
            entry.data.len(),
            |out, start, end, split_before, split_after| {
                write_stored_entry_fragment(
                    out,
                    entry,
                    &entry.data[start..end],
                    entry.data.len() as u64,
                    (!split_after).then(|| crc32(entry.data)),
                    split_before,
                    split_after,
                    options.hash_record,
                )
            },
        )?;
    }
    let volumes = writer.finish()?;
    if volumes.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 volume writer needs at least two volumes",
        ));
    }
    Ok(volumes)
}

/// One member's progress reporter over the set's tracker: the encoder
/// reports positions within the member, the tracker takes deltas.
fn member_progress<'a>(progress: Option<&'a WorkTracker<'a>>) -> impl FnMut(usize) -> bool + 'a {
    let mut last = 0usize;
    move |position: usize| {
        if position < last {
            last = 0;
        }
        let delta = position.saturating_sub(last);
        last = position;
        progress.is_none_or(|progress| progress.advance(delta as u64))
    }
}

/// A non-solid member of a compressed volume set, resolved as the loop
/// above resolved it: validated, stored at level 0 or on the sampler's
/// verdict, else encoded and stored only when the packed bytes did not
/// shrink it.
#[allow(clippy::too_many_arguments)]
fn resolve_compressed_volume_member(
    index: usize,
    entry: &CompressedEntry<'_>,
    algorithm_version: u8,
    compression_method: u8,
    dictionary_size: u64,
    encode_options: EncodeOptions,
    filter_policy: FilterPolicy,
    progress: Option<&WorkTracker<'_>>,
    hash_record: HashRecord,
    scratch: &EncoderScratchPool,
) -> Result<CompressedVolumeMember> {
    validate_compressed_entry(entry)?;
    if compression_method == 0 {
        return Ok(CompressedVolumeMember::Stored {
            entry_index: index,
            digests: payload_digests(entry.data, hash_record),
        });
    }
    // `Sampled` votes once, here; a member no region votes for is the
    // unfiltered member below, store sampling included (nzbfast-local
    // change, 7 Sep 2026; see VENDORING.md).
    let sampled_filters = match filter_policy {
        FilterPolicy::Sampled => {
            super::filter_policy::select_sampled_filters(entry.data, encode_options)
        }
        _ => Vec::new(),
    };
    // The sampling and the encode on one side, the payload digests on the
    // other, as the single-archive resolver does: the digests used to be
    // computed at emission, after every member's encode had finished.
    let sample_then_encode = || -> Result<Option<Vec<u8>>> {
        let mut report = member_progress(progress);
        if !sampled_filters.is_empty() {
            return crate::codec::rar50::Unpack50Encoder::with_options(encode_options)
                .encode_member_with_filters_pooled(
                    entry.data,
                    algorithm_version,
                    &sampled_filters,
                    Some(&mut report),
                    scratch,
                )
                .map(Some)
                .map_err(Error::from);
        }
        if super::filter_policy::sampled_incompressible(
            entry.data,
            algorithm_version,
            encode_options,
        ) {
            if !report(entry.data.len()) {
                return Err(Error::Cancelled);
            }
            return Ok(None);
        }
        super::filter_policy::encode_safe_lz_member_pooled(
            entry.data,
            algorithm_version,
            encode_options,
            Some(&mut report),
            scratch,
        )
        .map(Some)
    };
    #[cfg(feature = "parallel")]
    let (encoded, digests) = rayon::join(sample_then_encode, || {
        payload_digests(entry.data, hash_record)
    });
    #[cfg(not(feature = "parallel"))]
    let (encoded, digests) = (
        sample_then_encode(),
        payload_digests(entry.data, hash_record),
    );
    let Some(packed) = encoded? else {
        return Ok(CompressedVolumeMember::Stored {
            entry_index: index,
            digests,
        });
    };
    if should_store_compressed_payload(entry.data, &packed, false, filter_policy) {
        Ok(CompressedVolumeMember::Stored {
            entry_index: index,
            digests,
        })
    } else {
        Ok(CompressedVolumeMember::Compressed {
            entry_index: index,
            packed,
            compression_method,
            dictionary_size,
            solid_continuation: false,
            digests,
        })
    }
}

pub(super) fn write_compressed_volume_set_impl(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    max_packed_per_volume: usize,
    recovery_percent: Option<u64>,
    filter_policy: FilterPolicy,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_compressed_recovery_options(options)?;
    } else {
        validate_compressed_options(options)?;
    }
    validate_volume_filter_policy(options, filter_policy)?;
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
    if entries.iter().any(|entry| entry.data.is_empty()) {
        return Err(Error::InvalidHeader(
            "RAR 5 compressed volume writer needs a non-empty payload",
        ));
    }

    let algorithm_version = rar50_algorithm_version(options)?;
    let compression_method = compression_method_for_level(options.compression_level)?;
    let dictionary_size = super::filter_policy::dictionary_size_for_payload(
        options,
        super::largest_payload(
            entries.iter().map(|entry| entry.data.len() as u64),
            options.features.solid,
        ),
    )?;
    let encode_options = encode_options_for_level(
        options.compression_level,
        dictionary_size,
        options.optimal_parse,
        options.adaptive_entropy_blocks,
        options.tokenizer_horizon_choice,
        super::filter_policy::working_memory_for(options),
    )?;

    let members = if options.features.solid {
        // A solid set: every member's two arms on the pool, the walk only
        // decides (`resolve_solid_members`); it used to encode both arms
        // of every member on one thread, one member after another.
        for entry in entries {
            validate_compressed_entry(entry)?;
        }
        let mut members = Vec::with_capacity(entries.len());
        if compression_method == 0 {
            for (index, entry) in entries.iter().enumerate() {
                members.push(CompressedVolumeMember::Stored {
                    entry_index: index,
                    digests: payload_digests(entry.data, options.hash_record),
                });
            }
            return finish_compressed_volume_set(entries, options, max_packed_per_volume, recovery_percent, members, algorithm_version);
        }
        let datas: Vec<&[u8]> = entries.iter().map(|entry| entry.data).collect();
        let resolved = super::filter_policy::resolve_solid_members(
            &datas,
            algorithm_version,
            encode_options,
            progress,
        )?;
        for (index, (entry, (packed, solid_continuation))) in
            entries.iter().zip(resolved).enumerate()
        {
            let digests = payload_digests(entry.data, options.hash_record);
            if should_store_compressed_payload(entry.data, &packed, true, FilterPolicy::None) {
                members.push(CompressedVolumeMember::Stored {
                    entry_index: index,
                    digests,
                });
            } else {
                members.push(CompressedVolumeMember::Compressed {
                    entry_index: index,
                    packed,
                    compression_method,
                    dictionary_size,
                    solid_continuation,
                    digests,
                });
            }
        }
        members
    } else {
        // Every other member stands alone, so the members are resolved on
        // the pool at once, as the single-archive writer resolves its own
        // (nzbfast-local change, 6 Sep 2026; see VENDORING.md - this loop
        // was serial, and a set of 150 members of 2.7 MB took 45 s on an
        // 8-vCPU guest against 7.3 s as a single archive).
        let scratch = EncoderScratchPool::new();
        let resolve = |index: usize| -> Result<CompressedVolumeMember> {
            resolve_compressed_volume_member(
                index,
                &entries[index],
                algorithm_version,
                compression_method,
                dictionary_size,
                encode_options,
                filter_policy,
                progress,
                options.hash_record,
                &scratch,
            )
        };
        #[cfg(feature = "parallel")]
        {
            if entries.len() > 1 {
                crate::parallel::map_collect_bounded(
                    (0..entries.len()).collect(),
                    super::filter_policy::members_in_flight_for(&[encode_options]),
                    resolve,
                )?
            } else {
                (0..entries.len()).map(resolve).collect::<Result<Vec<_>>>()?
            }
        }
        #[cfg(not(feature = "parallel"))]
        {
            (0..entries.len()).map(resolve).collect::<Result<Vec<_>>>()?
        }
    };

    finish_compressed_volume_set(entries, options, max_packed_per_volume, recovery_percent, members, algorithm_version)
}

/// The volume writers carry `None` or `Sampled`, and neither in a solid
/// set - as the single-archive writer refuses every filtering policy for
/// solid members (nzbfast-local change, 7 Sep 2026; see VENDORING.md).
fn validate_volume_filter_policy(options: WriterOptions, filter_policy: FilterPolicy) -> Result<()> {
    match filter_policy {
        FilterPolicy::None => Ok(()),
        FilterPolicy::Sampled if !options.features.solid => Ok(()),
        FilterPolicy::Sampled => Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 solid filtered compressed volume writer",
        }),
        _ => Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 compressed volume writer filter policy",
        }),
    }
}

/// The volumes of a resolved compressed set.
fn finish_compressed_volume_set(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    max_packed_per_volume: usize,
    recovery_percent: Option<u64>,
    members: Vec<CompressedVolumeMember>,
    algorithm_version: u8,
) -> Result<Vec<Vec<u8>>> {
    let mut writer = VolumeSetWriter::new(
        max_packed_per_volume,
        options.features.solid,
        None,
        recovery_percent,
    );
    for member in &members {
        match member {
            CompressedVolumeMember::Stored {
                entry_index,
                digests,
            } => {
                let entry = stored_entry_from_compressed_entry(&entries[*entry_index]);
                writer.write_member(
                    entry.data.len(),
                    |out, start, end, split_before, split_after| {
                        // Whole-file CRC on the last fragment (nzbfast-local
                        // change, 22 Aug 2026 - see the stored writer above).
                        write_stored_entry_fragment_with_digests(
                            out,
                            &entry,
                            &entry.data[start..end],
                            entry.data.len() as u64,
                            (!split_after).then_some(digests.crc32),
                            split_before,
                            split_after,
                            options.hash_record,
                            digests.blake2sp,
                        )
                    },
                )?;
            }
            CompressedVolumeMember::Compressed {
                entry_index,
                packed,
                compression_method,
                dictionary_size,
                solid_continuation,
                digests,
            } => {
                writer.write_member(
                    packed.len(),
                    |out, start, end, split_before, split_after| {
                        write_compressed_entry_fragment(
                            out,
                            CompressedFragment {
                                hash_record: options.hash_record,
                                entry: &entries[*entry_index],
                                data: &packed[start..end],
                                algorithm_version,
                                compression_method: *compression_method,
                                dictionary_size: *dictionary_size,
                                solid_continuation: *solid_continuation,
                                split_before,
                                split_after,
                                digests: Some(*digests),
                            },
                        )
                    },
                )?;
            }
        }
    }
    let volumes = writer.finish()?;
    if volumes.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 compressed volume writer needs at least two volumes",
        ));
    }
    Ok(volumes)
}

pub(super) fn write_encrypted_stored_volumes_impl(
    entry: EncryptedStoredEntry<'_>,
    options: WriterOptions,
    max_encrypted_per_volume: usize,
    recovery_percent: Option<u64>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_encrypted_recovery_options(options)?;
    } else {
        validate_encrypted_options(options)?;
    }
    validate_encrypted_entry(&entry)?;
    if options.features.archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 volume comments",
        });
    }
    if max_encrypted_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted volume payload size must be non-zero",
        ));
    }
    if entry.data.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted volume writer needs a non-empty payload",
        ));
    }

    let encrypted = encrypted_stored_payload(entry.data, entry.password, options.hash_record)?;
    let stream_len = encrypted.stream_len();
    let chunk_count = stream_len.div_ceil(max_encrypted_per_volume);
    if chunk_count < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted volume writer needs at least two volumes",
        ));
    }

    let header_keys = if options.features.header_encryption {
        Some(header_encryption_keys(entry.password)?)
    } else {
        None
    };

    let mut writer = VolumeSetWriter::new(
        max_encrypted_per_volume,
        options.features.solid,
        header_keys.as_ref(),
        recovery_percent,
    );
    let mut stream = encrypted.stream();
    for index in 0..chunk_count {
        let chunk_start = index * max_encrypted_per_volume;
        let chunk_len = max_encrypted_per_volume.min(stream_len - chunk_start);
        writer.write_member(chunk_len, |out, start, end, _split_before, _split_after| {
            debug_assert_eq!(start, 0);
            debug_assert_eq!(end, chunk_len);
            write_encrypted_stored_entry_fragment_with_header_keys(
                out,
                &entry,
                BlockData::Encrypt {
                    plain: entry.data,
                    end: chunk_start + end,
                    stream: &mut stream,
                },
                &encrypted,
                index > 0,
                index + 1 < chunk_count,
                header_keys.as_ref().map(|keys| &keys.keys),
            )
        })?;
    }

    writer.finish()
}

/// A split ENCRYPTED STORED set holding SEVERAL members.
///
/// [`write_encrypted_stored_volumes_impl`] splits ONE member across the
/// volumes. This one walks a slice through the same [`VolumeSetWriter`]
/// the encrypted compressed set already uses, so an encrypted split set
/// stops being compressed-only: each member is encrypted on its own key
/// material and only the member landing on a volume boundary carries the
/// split flags (nzbfast-local change, 4 Sep 2026 - see
/// vendor/rars/VENDORING.md).
pub(super) fn write_encrypted_stored_volume_set_impl(
    entries: &[EncryptedStoredEntry<'_>],
    options: WriterOptions,
    max_encrypted_per_volume: usize,
    recovery_percent: Option<u64>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_encrypted_recovery_options(options)?;
    } else {
        validate_encrypted_options(options)?;
    }
    if options.features.archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 volume comments",
        });
    }
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
    for entry in entries {
        validate_encrypted_entry(entry)?;
        if entry.data.is_empty() {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted volume writer needs a non-empty payload",
            ));
        }
    }

    let mut payloads = Vec::with_capacity(entries.len());
    for entry in entries {
        payloads.push(encrypted_stored_payload(
            entry.data,
            entry.password,
            options.hash_record,
        )?);
    }

    let password = header_encryption_password(entries.iter().map(|entry| entry.password))?;
    let header_keys = if options.features.header_encryption {
        Some(header_encryption_keys(password)?)
    } else {
        None
    };

    let mut writer = VolumeSetWriter::new(
        max_encrypted_per_volume,
        options.features.solid,
        header_keys.as_ref(),
        recovery_percent,
    );
    for (entry, encrypted) in entries.iter().zip(&payloads) {
        let mut stream = encrypted.stream();
        writer.write_member(
            encrypted.stream_len(),
            |out, _start, end, split_before, split_after| {
                write_encrypted_stored_entry_fragment_with_header_keys(
                    out,
                    entry,
                    BlockData::Encrypt {
                        plain: entry.data,
                        end,
                        stream: &mut stream,
                    },
                    encrypted,
                    split_before,
                    split_after,
                    header_keys.as_ref().map(|keys| &keys.keys),
                )
            },
        )?;
    }
    let volumes = writer.finish()?;
    if volumes.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted volume writer needs at least two volumes",
        ));
    }
    Ok(volumes)
}

pub(super) fn write_encrypted_compressed_volume_set_impl(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    max_encrypted_per_volume: usize,
    recovery_percent: Option<u64>,
    filter_policy: FilterPolicy,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_encrypted_compressed_recovery_options(options)?;
    } else {
        validate_encrypted_compressed_options(options)?;
    }
    validate_volume_filter_policy(options, filter_policy)?;
    if max_encrypted_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted compressed volume payload size must be non-zero",
        ));
    }
    if entries.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted compressed volume writer needs at least one entry",
        ));
    }
    if entries.iter().any(|entry| entry.data.is_empty()) {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted compressed volume writer needs a non-empty payload",
        ));
    }

    let algorithm_version = rar50_algorithm_version(options)?;
    let compression_method = compression_method_for_level(options.compression_level)?;
    let dictionary_size = super::filter_policy::dictionary_size_for_payload(
        options,
        super::largest_payload(
            entries.iter().map(|entry| entry.data.len() as u64),
            options.features.solid,
        ),
    )?;
    let encode_options = encode_options_for_level(
        options.compression_level,
        dictionary_size,
        options.optimal_parse,
        options.adaptive_entropy_blocks,
        options.tokenizer_horizon_choice,
        super::filter_policy::working_memory_for(options),
    )?;

    for entry in entries {
        validate_encrypted_compressed_entry(entry)?;
    }
    // The encodes first, on the pool (the solid arms through
    // `resolve_solid_members`, the others each on their own), then the
    // encryption in member order, because every member's salt and IV are
    // drawn from the entropy in that order and the bytes must not move
    // (nzbfast-local change, 6 Sep 2026; see VENDORING.md - the loop
    // encoded and encrypted one member after another).
    let datas: Vec<&[u8]> = entries.iter().map(|entry| entry.data).collect();
    let resolved: Vec<Option<(Vec<u8>, bool)>> = if compression_method == 0 {
        vec![None; entries.len()]
    } else if options.features.solid {
        super::filter_policy::resolve_solid_members(
            &datas,
            algorithm_version,
            encode_options,
            progress,
        )?
        .into_iter()
        .map(Some)
        .collect()
    } else {
        let scratch = EncoderScratchPool::new();
        let resolve = |index: usize| -> Result<Option<(Vec<u8>, bool)>> {
            let data = datas[index];
            let mut report = member_progress(progress);
            if filter_policy == FilterPolicy::Sampled {
                let sampled_filters =
                    super::filter_policy::select_sampled_filters(data, encode_options);
                if !sampled_filters.is_empty() {
                    let packed = crate::codec::rar50::Unpack50Encoder::with_options(encode_options)
                        .encode_member_with_filters_pooled(
                            data,
                            algorithm_version,
                            &sampled_filters,
                            Some(&mut report),
                            &scratch,
                        )?;
                    return Ok(Some((packed, false)));
                }
            }
            if super::filter_policy::sampled_incompressible(data, algorithm_version, encode_options)
            {
                if !report(data.len()) {
                    return Err(Error::Cancelled);
                }
                return Ok(None);
            }
            let packed = super::filter_policy::encode_safe_lz_member_pooled(
                data,
                algorithm_version,
                encode_options,
                Some(&mut report),
                &scratch,
            )?;
            Ok(Some((packed, false)))
        };
        #[cfg(feature = "parallel")]
        {
            if entries.len() > 1 {
                crate::parallel::map_collect_bounded(
                    (0..entries.len()).collect(),
                    super::filter_policy::members_in_flight_for(&[encode_options]),
                    resolve,
                )?
            } else {
                (0..entries.len()).map(resolve).collect::<Result<Vec<_>>>()?
            }
        }
        #[cfg(not(feature = "parallel"))]
        {
            (0..entries.len()).map(resolve).collect::<Result<Vec<_>>>()?
        }
    };
    let mut members = Vec::with_capacity(entries.len());
    for (index, (entry, resolved)) in entries.iter().zip(resolved).enumerate() {
        let Some((packed, solid_continuation)) = resolved else {
            let encrypted =
                encrypted_stored_payload(entry.data, entry.password, options.hash_record)?;
            members.push(EncryptedCompressedVolumeMember::Stored {
                entry_index: index,
                encrypted,
            });
            continue;
        };
        if should_store_compressed_payload(
            entry.data,
            &packed,
            options.features.solid,
            filter_policy,
        ) {
            let encrypted =
                encrypted_stored_payload(entry.data, entry.password, options.hash_record)?;
            members.push(EncryptedCompressedVolumeMember::Stored {
                entry_index: index,
                encrypted,
            });
        } else {
            let encrypted =
                encrypted_payload(packed, entry.data, entry.password, options.hash_record)?;
            members.push(EncryptedCompressedVolumeMember::Compressed {
                entry_index: index,
                encrypted,
                compression_method,
                dictionary_size,
                solid_continuation,
            });
        }
    }

    let password = header_encryption_password(entries.iter().map(|entry| entry.password))?;
    let header_keys = if options.features.header_encryption {
        Some(header_encryption_keys(password)?)
    } else {
        None
    };

    let mut writer = VolumeSetWriter::new(
        max_encrypted_per_volume,
        options.features.solid,
        header_keys.as_ref(),
        recovery_percent,
    );
    for member in &members {
        match member {
            EncryptedCompressedVolumeMember::Stored {
                entry_index,
                encrypted,
            } => {
                let entry = encrypted_stored_entry_from_compressed_entry(&entries[*entry_index]);
                let mut stream = encrypted.stream();
                writer.write_member(
                    encrypted.stream_len(),
                    |out, _start, end, split_before, split_after| {
                        write_encrypted_stored_entry_fragment_with_header_keys(
                            out,
                            &entry,
                            BlockData::Encrypt {
                                plain: entry.data,
                                end,
                                stream: &mut stream,
                            },
                            encrypted,
                            split_before,
                            split_after,
                            header_keys.as_ref().map(|keys| &keys.keys),
                        )
                    },
                )?;
            }
            EncryptedCompressedVolumeMember::Compressed {
                entry_index,
                encrypted,
                compression_method,
                dictionary_size,
                solid_continuation,
            } => {
                writer.write_member(
                    encrypted.data.len(),
                    |out, start, end, split_before, split_after| {
                        write_encrypted_compressed_entry_fragment_with_header_keys(
                            out,
                            EncryptedCompressedFragment {
                                entry: &entries[*entry_index],
                                data: BlockData::Bytes(&encrypted.data[start..end]),
                                encrypted,
                                algorithm_version,
                                compression_method: *compression_method,
                                dictionary_size: *dictionary_size,
                                solid_continuation: *solid_continuation,
                                split_before,
                                split_after,
                            },
                            header_keys.as_ref().map(|keys| &keys.keys),
                        )
                    },
                )?;
            }
        }
    }
    let volumes = writer.finish()?;
    if volumes.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted compressed volume writer needs at least two volumes",
        ));
    }
    Ok(volumes)
}

enum CompressedVolumeMember {
    Stored {
        entry_index: usize,
        /// The member's digests, computed beside its resolve rather than
        /// at emission (nzbfast-local change, 6 Sep 2026; see VENDORING.md).
        digests: PayloadDigests,
    },
    Compressed {
        entry_index: usize,
        packed: Vec<u8>,
        compression_method: u8,
        dictionary_size: u64,
        solid_continuation: bool,
        digests: PayloadDigests,
    },
}

enum EncryptedCompressedVolumeMember {
    Stored {
        entry_index: usize,
        encrypted: EncryptedStoredPayload,
    },
    Compressed {
        entry_index: usize,
        encrypted: EncryptedStoredPayload,
        compression_method: u8,
        dictionary_size: u64,
        solid_continuation: bool,
    },
}

struct VolumeSetWriter<'a> {
    max_payload_per_volume: usize,
    solid: bool,
    header_keys: Option<&'a HeaderEncryptionKeys>,
    recovery_percent: Option<u64>,
    volumes: Vec<Vec<u8>>,
    /// A full volume's body and number, held until the writer knows
    /// whether another volume follows it (see `END_OF_ARCHIVE_NOT_LAST_VOLUME`).
    pending: Option<(Vec<u8>, u64)>,
    current_body: Option<Vec<u8>>,
    current_payload_len: usize,
    current_volume_number: Option<u64>,
    next_volume_number: u64,
}

impl<'a> VolumeSetWriter<'a> {
    fn new(
        max_payload_per_volume: usize,
        solid: bool,
        header_keys: Option<&'a HeaderEncryptionKeys>,
        recovery_percent: Option<u64>,
    ) -> Self {
        Self {
            max_payload_per_volume,
            solid,
            header_keys,
            recovery_percent,
            volumes: Vec::new(),
            current_body: None,
            current_payload_len: 0,
            current_volume_number: None,
            pending: None,
            next_volume_number: 0,
        }
    }

    fn write_member<F>(&mut self, member_len: usize, mut write_fragment: F) -> Result<()>
    where
        F: FnMut(&mut Vec<u8>, usize, usize, bool, bool) -> Result<()>,
    {
        let mut start = 0;
        let mut split_before = false;
        while start < member_len {
            if self.current_body.is_none()
                || self.current_payload_len == self.max_payload_per_volume
            {
                self.start_volume()?;
            }
            let remaining_volume = self.max_payload_per_volume - self.current_payload_len;
            let remaining_member = member_len - start;
            let fragment_len = remaining_volume.min(remaining_member);
            let end = start + fragment_len;
            let split_after = end < member_len;

            // Invariant: the branch above starts a volume whenever no body exists.
            let out = self.current_body.as_mut().expect("volume started");
            write_fragment(out, start, end, split_before, split_after)?;
            self.current_payload_len += fragment_len;
            start = end;
            split_before = true;

            if self.current_payload_len == self.max_payload_per_volume {
                self.finish_current_volume()?;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<Vec<u8>>> {
        if self.current_body.is_some() {
            self.finish_current_volume()?;
        }
        self.seal_pending(false)?;
        Ok(self.volumes)
    }

    /// Seal the held volume with its end header, `next_volume` being what
    /// the writer now knows: another volume opened after it, or the set
    /// finished on it.
    fn seal_pending(&mut self, next_volume: bool) -> Result<()> {
        let Some((mut body, volume_number)) = self.pending.take() else {
            return Ok(());
        };
        let out = if self.direct() {
            write_volume_end(&mut body, self.header_keys, next_volume)?;
            body
        } else {
            write_volume_from_body(
                &body,
                volume_number,
                self.solid,
                self.header_keys,
                self.recovery_percent,
                next_volume,
            )?
        };
        self.volumes.push(out);
        Ok(())
    }

    /// A volume without a recovery record is built IN PLACE: its head is
    /// written first and the member fragments follow it in the same
    /// buffer, which `finish_current_volume` closes with the end header.
    /// The head's length depends on nothing the body decides, so nothing
    /// has to be copied to put it in front - where every volume used to be
    /// assembled as a body and then copied whole into a second buffer
    /// behind its head (a gigabyte copied and faulted in twice over a
    /// 16-volume set). A recovery-record volume keeps the body-then-wrap
    /// path, whose head carries the record's offset, which the body's
    /// length decides. (nzbfast-local change, 6 Sep 2026; see VENDORING.md.)
    fn direct(&self) -> bool {
        self.recovery_percent.is_none()
    }

    fn start_volume(&mut self) -> Result<()> {
        debug_assert!(self.current_body.is_none());
        // A volume opening is the proof the held one was not the last.
        self.seal_pending(true)?;
        let volume_number = self.next_volume_number;
        self.next_volume_number += 1;
        let mut body = Vec::new();
        if self.direct() {
            write_volume_head(&mut body, volume_number, self.solid, self.header_keys, None)?;
        }
        self.current_body = Some(body);
        self.current_payload_len = 0;
        self.current_volume_number = Some(volume_number);
        Ok(())
    }

    /// A full volume is HELD, not sealed: its end header says whether
    /// another volume follows, and only the next `start_volume` or
    /// `finish` knows (a member can end exactly on the volume boundary,
    /// where nothing else in the set says "continue").
    fn finish_current_volume(&mut self) -> Result<()> {
        // Invariant: callers only finish a current volume after start_volume created it.
        let body = self.current_body.take().expect("volume started");
        // Invariant: start_volume sets the matching volume number with the body.
        let volume_number = self
            .current_volume_number
            .take()
            .expect("volume number set");
        debug_assert!(self.pending.is_none());
        self.pending = Some((body, volume_number));
        self.current_payload_len = 0;
        Ok(())
    }
}

fn write_volume_from_body(
    body: &[u8],
    volume_number: u64,
    solid: bool,
    header_keys: Option<&HeaderEncryptionKeys>,
    recovery_percent: Option<u64>,
    next_volume: bool,
) -> Result<Vec<u8>> {
    // The record's offset is the volume head's length (which carries the
    // offset as a varint) plus the body's, so it is solved on head lengths
    // alone and the volume is emitted ONCE - the loop below emitted it up to
    // four times, generating the parity each time (see
    // `emit_resolved_writer_plan_recovery_direct` in mod.rs).
    if recovery_percent.is_some() {
        let head_at = |offset: u64| -> Result<u64> {
            Ok(
                (volume_head_len(volume_number, solid, header_keys, Some(offset))?
                    - RAR50_SIGNATURE.len()) as u64,
            )
        };
        let mut offset = head_at(0)? + body.len() as u64;
        let mut converged = false;
        for _ in 0..4 {
            let next = head_at(offset)? + body.len() as u64;
            if next == offset {
                converged = true;
                break;
            }
            offset = next;
        }
        if converged {
            let (out, observed) = write_volume_from_body_pass(
                body,
                volume_number,
                solid,
                header_keys,
                recovery_percent,
                offset,
                next_volume,
            )?;
            if observed == offset {
                return Ok(out);
            }
        }
    }
    let mut recovery_offset = 0;
    for _ in 0..4 {
        let (out, next_recovery_offset) = write_volume_from_body_pass(
            body,
            volume_number,
            solid,
            header_keys,
            recovery_percent,
            recovery_offset,
            next_volume,
        )?;
        if recovery_percent.is_none() || next_recovery_offset == recovery_offset {
            return Ok(out);
        }
        recovery_offset = next_recovery_offset;
    }
    write_volume_from_body_pass(
        body,
        volume_number,
        solid,
        header_keys,
        recovery_percent,
        recovery_offset,
        next_volume,
    )
    .map(|(out, _)| out)
}

/// Bytes from a volume's start to the end of its main header, for a given
/// recovery-record offset: the only part of the volume whose length
/// depends on it.
pub(super) fn volume_head_len(
    volume_number: u64,
    solid: bool,
    header_keys: Option<&HeaderEncryptionKeys>,
    recovery_offset: Option<u64>,
) -> Result<usize> {
    let mut head = Vec::new();
    write_volume_head(
        &mut head,
        volume_number,
        solid,
        header_keys,
        recovery_offset,
    )?;
    Ok(head.len())
}

fn write_volume_from_body_pass(
    body: &[u8],
    volume_number: u64,
    solid: bool,
    header_keys: Option<&HeaderEncryptionKeys>,
    recovery_percent: Option<u64>,
    recovery_offset: u64,
    next_volume: bool,
) -> Result<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    write_volume_head(
        &mut out,
        volume_number,
        solid,
        header_keys,
        recovery_percent.map(|_| recovery_offset),
    )?;
    out.extend_from_slice(body);
    let recovery_offset = if let Some(recovery_percent) = recovery_percent {
        let rr_pos = out.len();
        if let Some(header_keys) = header_keys {
            write_header_encrypted_recovery_service(
                &mut out,
                recovery_percent,
                &header_keys.keys,
                None,
                1,
                false,
            )?;
        } else {
            write_recovery_service(&mut out, recovery_percent, None, 1, false)?;
        }
        (rr_pos - RAR50_SIGNATURE.len()) as u64
    } else {
        0
    };
    write_volume_end(&mut out, header_keys, next_volume)?;
    Ok((out, recovery_offset))
}

/// A volume's start: the signature, the head-crypt block when the headers
/// are encrypted, and the main header with the recovery locator when the
/// volume carries a record at `recovery_offset`.
pub(super) fn write_volume_head(
    out: &mut Vec<u8>,
    volume_number: u64,
    solid: bool,
    header_keys: Option<&HeaderEncryptionKeys>,
    recovery_offset: Option<u64>,
) -> Result<()> {
    out.extend_from_slice(RAR50_SIGNATURE);
    let mut main_extra = Vec::new();
    if let Some(offset) = recovery_offset {
        write_locator_record(&mut main_extra, None, Some(offset));
    }
    let main_flags = ARCHIVE_IS_VOLUME
        | ARCHIVE_HAS_VOLUME_NUMBER
        | if solid { ARCHIVE_IS_SOLID } else { 0 }
        | if recovery_offset.is_some() {
            ARCHIVE_HAS_RECOVERY_RECORD
        } else {
            0
        };
    if let Some(header_keys) = header_keys {
        write_head_crypt(out, header_keys)?;
        out.extend_from_slice(&encrypted_main_header_block(
            &header_keys.keys,
            main_flags,
            Some(volume_number),
            &main_extra,
        )?);
    } else {
        write_main_header(out, main_flags, Some(volume_number), &main_extra)?;
    }
    Ok(())
}

/// The END header's "archive is a volume and not the last in the set" flag
/// (end of archive flags, bit 0x0001). Every volume of a set but the last carries it.
/// The writers wrote 0 on every volume until 7 Sep 2026, which native
/// unrar reads as "last volume" the moment a member ENDS exactly at a
/// volume's end: the file header's split flags are what carry it across
/// a volume boundary, and a member that closes on the boundary has none,
/// so unrar stopped there and the members in the later volumes were
/// never extracted (`unrar t` still exited 0). Found by a native probe on
/// two 64-byte members in two 119-byte volumes: with the flag the second
/// member extracts, without it unrar exits 10 with 0 bytes for it. So a
/// volume is sealed only once the writer KNOWS whether another follows:
/// when the next one opens, or at finish. (nzbfast-local change, 7 Sep
/// 2026; see VENDORING.md.)
const END_OF_ARCHIVE_NOT_LAST_VOLUME: u64 = 0x0001;

/// A volume's end header, plain or header-encrypted; `next_volume` is
/// whether another volume of the set follows this one.
pub(super) fn write_volume_end(
    out: &mut Vec<u8>,
    header_keys: Option<&HeaderEncryptionKeys>,
    next_volume: bool,
) -> Result<()> {
    let end_flags = if next_volume { END_OF_ARCHIVE_NOT_LAST_VOLUME } else { 0 };
    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            &header_keys.keys,
            BLOCK_TYPE_END_OF_ARCHIVE,
            0,
            None,
            &end_header_specific(end_flags),
            &[],
            &[],
        )?);
    } else {
        write_end_header(out, end_flags)?;
    }
    Ok(())
}
