use super::*;

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
                    last.then_some(crc32(entry.data)),
                    index > 0,
                    !last,
                )
            },
        )?;
    }

    writer.finish()
}

pub(super) fn write_compressed_volume_set_impl(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    max_packed_per_volume: usize,
    recovery_percent: Option<u64>,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_compressed_recovery_options(options)?;
    } else {
        validate_compressed_options(options)?;
    }
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
    let dictionary_size = dictionary_size_for_options(options)?;
    let encode_options = encode_options_for_level(options.compression_level, dictionary_size)?;

    let mut encoder = options
        .features
        .solid
        .then(|| Unpack50Encoder::with_options(encode_options));
    let mut members = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        validate_compressed_entry(entry)?;
        if compression_method == 0 {
            members.push(CompressedVolumeMember::Stored { entry_index: index });
            continue;
        }
        let mut last = 0usize;
        let mut report = |position: usize| {
            if position < last {
                last = 0;
            }
            let delta = position.saturating_sub(last);
            last = position;
            progress.is_none_or(|progress| progress.advance(delta as u64))
        };
        let (packed, solid_continuation) = if let Some(encoder) = encoder.as_mut() {
            encode_with_solid_reset_policy_and_progress(
                encoder,
                entry.data,
                algorithm_version,
                encode_options,
                index,
                Some(&mut report),
            )?
        } else {
            (
                encode_safe_lz_member_with_progress(
                    entry.data,
                    algorithm_version,
                    encode_options,
                    &mut report,
                )?,
                false,
            )
        };
        if should_store_compressed_payload(
            entry.data,
            &packed,
            options.features.solid,
            FilterPolicy::None,
        ) {
            members.push(CompressedVolumeMember::Stored { entry_index: index });
        } else {
            members.push(CompressedVolumeMember::Compressed {
                entry_index: index,
                packed,
                compression_method,
                dictionary_size,
                solid_continuation,
            });
        }
    }

    let mut writer = VolumeSetWriter::new(
        max_packed_per_volume,
        options.features.solid,
        None,
        recovery_percent,
    );
    for member in &members {
        match member {
            CompressedVolumeMember::Stored { entry_index } => {
                let entry = stored_entry_from_compressed_entry(&entries[*entry_index]);
                writer.write_member(
                    entry.data.len(),
                    |out, start, end, split_before, split_after| {
                        // Whole-file CRC on the last fragment (nzbfast-local
                        // change, 22 Aug 2026 - see the stored writer above).
                        write_stored_entry_fragment(
                            out,
                            &entry,
                            &entry.data[start..end],
                            entry.data.len() as u64,
                            (!split_after).then_some(crc32(entry.data)),
                            split_before,
                            split_after,
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
            } => {
                writer.write_member(
                    packed.len(),
                    |out, start, end, split_before, split_after| {
                        write_compressed_entry_fragment(
                            out,
                            CompressedFragment {
                                entry: &entries[*entry_index],
                                data: &packed[start..end],
                                algorithm_version,
                                compression_method: *compression_method,
                                dictionary_size: *dictionary_size,
                                solid_continuation: *solid_continuation,
                                split_before,
                                split_after,
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

    let encrypted = encrypted_stored_payload(entry.data, entry.password)?;
    let chunks: Vec<&[u8]> = encrypted.data.chunks(max_encrypted_per_volume).collect();
    if chunks.len() < 2 {
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
    for (index, chunk) in chunks.iter().enumerate() {
        writer.write_member(
            chunk.len(),
            |out, start, end, _split_before, _split_after| {
                debug_assert_eq!(start, 0);
                debug_assert_eq!(end, chunk.len());
                write_encrypted_stored_entry_fragment_with_header_keys(
                    out,
                    &entry,
                    chunk,
                    &encrypted,
                    index > 0,
                    index + 1 < chunks.len(),
                    header_keys.as_ref().map(|keys| &keys.keys),
                )
            },
        )?;
    }

    writer.finish()
}

pub(super) fn write_encrypted_compressed_volume_set_impl(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    max_encrypted_per_volume: usize,
    recovery_percent: Option<u64>,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_encrypted_compressed_recovery_options(options)?;
    } else {
        validate_encrypted_compressed_options(options)?;
    }
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
    let dictionary_size = dictionary_size_for_options(options)?;
    let encode_options = encode_options_for_level(options.compression_level, dictionary_size)?;

    let mut solid_encoder = options
        .features
        .solid
        .then(|| Unpack50Encoder::with_options(encode_options));
    let mut members = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        validate_encrypted_compressed_entry(entry)?;
        if compression_method == 0 {
            let encrypted = encrypted_stored_payload(entry.data, entry.password)?;
            members.push(EncryptedCompressedVolumeMember::Stored {
                entry_index: index,
                encrypted,
            });
            continue;
        }
        let mut last = 0usize;
        let mut report = |position: usize| {
            if position < last {
                last = 0;
            }
            let delta = position.saturating_sub(last);
            last = position;
            progress.is_none_or(|progress| progress.advance(delta as u64))
        };
        let (packed, solid_continuation) = if let Some(encoder) = solid_encoder.as_mut() {
            encode_with_solid_reset_policy_and_progress(
                encoder,
                entry.data,
                algorithm_version,
                encode_options,
                index,
                Some(&mut report),
            )?
        } else {
            (
                encode_safe_lz_member_with_progress(
                    entry.data,
                    algorithm_version,
                    encode_options,
                    &mut report,
                )?,
                false,
            )
        };
        if should_store_compressed_payload(
            entry.data,
            &packed,
            options.features.solid,
            FilterPolicy::None,
        ) {
            let encrypted = encrypted_stored_payload(entry.data, entry.password)?;
            members.push(EncryptedCompressedVolumeMember::Stored {
                entry_index: index,
                encrypted,
            });
        } else {
            let encrypted = encrypted_payload(&packed, entry.data, entry.password)?;
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
                writer.write_member(
                    encrypted.data.len(),
                    |out, start, end, split_before, split_after| {
                        write_encrypted_stored_entry_fragment_with_header_keys(
                            out,
                            &entry,
                            &encrypted.data[start..end],
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
                                data: &encrypted.data[start..end],
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
    },
    Compressed {
        entry_index: usize,
        packed: Vec<u8>,
        compression_method: u8,
        dictionary_size: u64,
        solid_continuation: bool,
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
    current_body: Option<Vec<u8>>,
    current_payload_len: usize,
    current_volume_number: Option<u64>,
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
        Ok(self.volumes)
    }

    fn start_volume(&mut self) -> Result<()> {
        debug_assert!(self.current_body.is_none());
        let volume_number = self.volumes.len() as u64;
        self.current_body = Some(Vec::new());
        self.current_payload_len = 0;
        self.current_volume_number = Some(volume_number);
        Ok(())
    }

    fn finish_current_volume(&mut self) -> Result<()> {
        // Invariant: callers only finish a current volume after start_volume created it.
        let body = self.current_body.take().expect("volume started");
        // Invariant: start_volume sets the matching volume number with the body.
        let volume_number = self
            .current_volume_number
            .take()
            .expect("volume number set");
        let out = write_volume_from_body(
            &body,
            volume_number,
            self.solid,
            self.header_keys,
            self.recovery_percent,
        )?;
        self.volumes.push(out);
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
) -> Result<Vec<u8>> {
    let mut recovery_offset = 0;
    for _ in 0..4 {
        let (out, next_recovery_offset) = write_volume_from_body_pass(
            body,
            volume_number,
            solid,
            header_keys,
            recovery_percent,
            recovery_offset,
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
    )
    .map(|(out, _)| out)
}

fn write_volume_from_body_pass(
    body: &[u8],
    volume_number: u64,
    solid: bool,
    header_keys: Option<&HeaderEncryptionKeys>,
    recovery_percent: Option<u64>,
    recovery_offset: u64,
) -> Result<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    let mut main_extra = Vec::new();
    if recovery_percent.is_some() {
        write_locator_record(&mut main_extra, None, Some(recovery_offset));
    }
    let main_flags = MHFL_VOLUME
        | MHFL_VOLUME_NUMBER
        | if solid { MHFL_SOLID } else { 0 }
        | if recovery_percent.is_some() {
            MHFL_RECOVERY
        } else {
            0
        };
    if let Some(header_keys) = header_keys {
        write_head_crypt(&mut out, header_keys)?;
        out.extend_from_slice(&encrypted_main_header_block(
            &header_keys.keys,
            main_flags,
            Some(volume_number),
            &main_extra,
        )?);
    } else {
        write_main_header(&mut out, main_flags, Some(volume_number), &main_extra)?;
    }
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
            )?;
        } else {
            write_recovery_service(&mut out, recovery_percent, None, 1)?;
        }
        (rr_pos - RAR50_SIGNATURE.len()) as u64
    } else {
        0
    };
    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            &header_keys.keys,
            HEAD_END,
            0,
            None,
            &end_header_specific(0),
            &[],
            &[],
        )?);
    } else {
        write_end_header(&mut out, 0)?;
    }
    Ok((out, recovery_offset))
}
