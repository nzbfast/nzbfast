use super::*;
use crate::volume_extract::{FragmentOpener, LazyChainedReader, SplitVolumeState, SplitVolumeStep};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

enum CodecState {
    Unpack15(Box<Unpack15>),
    Unpack20(Box<Unpack20>),
    Unpack29(Box<Unpack29>),
}

impl CodecState {
    fn new_for(file: &FileHeader) -> Result<Self> {
        if file.unp_ver >= 29 {
            return Ok(Self::Unpack29(Box::default()));
        }
        if file.unp_ver == 20 || file.unp_ver == 26 {
            return Ok(Self::Unpack20(Box::default()));
        }
        if file.unp_ver == 15 {
            return Ok(Self::Unpack15(Box::default()));
        }
        Err(Error::UnsupportedCompression {
            family: "RAR 1.5-4.x",
            unpack_version: file.unp_ver,
            method: file.method,
        })
    }

    fn supports(&self, file: &FileHeader) -> bool {
        match self {
            Self::Unpack15(_) => file.unp_ver == 15,
            Self::Unpack20(_) => file.unp_ver == 20 || file.unp_ver == 26,
            Self::Unpack29(_) => file.unp_ver >= 29,
        }
    }

    fn decode_file_data(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        solid: bool,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Unpack15(decoder) => {
                if file.is_encrypted() {
                    let mut packed = file
                        .packed_reader_for_decode(archive, password)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let mut out = Vec::new();
                    decoder
                        .decode_member_from_reader(
                            &mut packed,
                            usize::try_from(file.unp_size).map_err(|_| {
                                Error::InvalidHeader("RAR 1.5 unpacked size overflows usize")
                            })?,
                            solid,
                            &mut out,
                        )
                        .map(|_| out)
                        .map_err(Into::into)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))
                } else {
                    file.unpacked_data_with_unpack15(archive, decoder, solid)
                }
            }
            Self::Unpack20(decoder) => file.unpacked_data_with_unpack20(archive, decoder, password),
            Self::Unpack29(decoder) => {
                if file.is_encrypted() {
                    let mut packed = file
                        .packed_reader_for_decode(archive, password)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let mut out = Vec::new();
                    decoder
                        .decode_member_from_reader(
                            &mut packed,
                            usize::try_from(file.unp_size).map_err(|_| {
                                Error::InvalidHeader("RAR 2.9 unpacked size overflows usize")
                            })?,
                            &mut out,
                        )
                        .map(|_| out)
                        .map_err(Into::into)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))
                } else {
                    file.unpacked_data_with_rar29(archive, decoder, solid)
                }
            }
        }
    }

    fn write_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        solid: bool,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        match self {
            Self::Unpack15(decoder) => {
                file.write_unpack15_to(archive, decoder, solid, password, out)
            }
            Self::Unpack20(decoder) => file.write_unpack20_to(archive, decoder, password, out),
            Self::Unpack29(decoder) => {
                if file.is_encrypted() {
                    let mut crc = Crc32::new();
                    let mut crc_writer = CrcWriter {
                        inner: out,
                        crc: &mut crc,
                    };
                    let mut packed = file
                        .packed_reader_for_decode(archive, password)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let target = usize::try_from(file.unp_size).map_err(|_| {
                        Error::InvalidHeader("RAR 1.5 unpacked size overflows usize")
                    })?;
                    if solid {
                        decoder.decode_member_from_reader(&mut packed, target, &mut crc_writer)
                    } else {
                        decoder.decode_non_solid_member_from_reader(
                            &mut packed,
                            target,
                            &mut crc_writer,
                        )
                    }
                    .map_err(Error::from)
                    .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let actual = crc.finish();
                    file.crc_result(actual, password)
                } else {
                    file.write_rar29_to(archive, decoder, out)
                }
            }
        }
    }

    fn write_split_to(
        &mut self,
        input: &mut impl Read,
        file: &FileHeader,
        solid: bool,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        let actual = self.decode_split_to(input, file, solid, password, out)?;
        file.crc_result(actual, password)
    }

    /// [`Self::write_split_to`] stopping one step short: the CRC comes
    /// back instead of being checked here.
    ///
    /// A split member's expected CRC is its LAST fragment's - every
    /// earlier fragment carries the CRC of its own PACKED bytes instead
    /// (see [`FileHeader::split_fragment_packed_crc`]), measured on the
    /// RAR 3.00 multivolume fixtures - and the incremental split path
    /// drives the decode from the FIRST fragment's shape, which is all
    /// that is needed (name, method, unpack version and unpacked size
    /// repeat across fragments, and the walk validates that they do).
    fn decode_split_to(
        &mut self,
        input: &mut impl Read,
        file: &FileHeader,
        solid: bool,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<u32> {
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        let target = usize::try_from(file.unp_size)
            .map_err(|_| Error::InvalidHeader("RAR 1.5 split unpacked size overflows usize"))?;
        match self {
            Self::Unpack15(decoder) => decoder
                .decode_member_from_reader(input, target, solid, &mut crc_writer)
                .map_err(Error::from)
                .map_err(|error| file.map_encrypted_payload_error(password, error))?,
            Self::Unpack20(decoder) => decoder
                .decode_member_from_reader(input, target, &mut crc_writer)
                .map_err(Error::from)
                .map_err(|error| file.map_encrypted_payload_error(password, error))?,
            Self::Unpack29(decoder) => if solid {
                decoder.decode_member_from_reader(input, target, &mut crc_writer)
            } else {
                decoder.decode_non_solid_member_from_reader(input, target, &mut crc_writer)
            }
            .map_err(Error::from)
            .map_err(|error| file.map_encrypted_payload_error(password, error))?,
        }
        Ok(crc.finish())
    }
}

pub(super) struct DecoderSession<'a> {
    codec: Option<CodecState>,
    solid: bool,
    decoded_files: usize,
    password: Option<&'a [u8]>,
}

impl<'a> DecoderSession<'a> {
    pub(super) fn new(solid: bool) -> Self {
        Self::new_with_password(solid, None)
    }

    pub(super) fn new_with_password(solid: bool, password: Option<&'a [u8]>) -> Self {
        Self {
            codec: None,
            solid,
            decoded_files: 0,
            password,
        }
    }

    pub(super) fn write_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        out: &mut impl Write,
    ) -> Result<()> {
        if file.is_empty_compressed_payload() {
            file.crc_result(0, self.password)?;
            return Ok(());
        }
        let solid = self.file_is_solid(file);
        let password = self.password;
        self.codec_for(file)?
            .write_file_to(archive, file, solid, password, out)?;
        self.decoded_files += 1;
        Ok(())
    }

    fn write_split_to(
        &mut self,
        input: &mut impl Read,
        final_file: &FileHeader,
        out: &mut impl Write,
    ) -> Result<()> {
        let solid = self.file_is_solid(final_file);
        let password = self.password;
        self.codec_for(final_file)?
            .write_split_to(input, final_file, solid, password, out)?;
        self.decoded_files += 1;
        Ok(())
    }

    /// [`Self::write_split_to`] driven by the FIRST fragment's header,
    /// returning the CRC for the caller to check against the last one -
    /// the incremental split path has no last fragment yet.
    fn decode_split_to(
        &mut self,
        input: &mut impl Read,
        first_file: &FileHeader,
        out: &mut impl Write,
    ) -> Result<u32> {
        let solid = self.file_is_solid(first_file);
        let password = self.password;
        let crc = self
            .codec_for(first_file)?
            .decode_split_to(input, first_file, solid, password, out)?;
        self.decoded_files += 1;
        Ok(crc)
    }

    pub(super) fn decode_file_data(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
    ) -> Result<Vec<u8>> {
        if file.is_empty_compressed_payload() {
            file.crc_result(0, self.password)?;
            return Ok(Vec::new());
        }
        let solid = self.file_is_solid(file);
        let password = self.password;
        self.codec_for(file)?
            .decode_file_data(archive, file, solid, password)
    }

    fn file_is_solid(&self, file: &FileHeader) -> bool {
        if !self.solid || self.decoded_files == 0 {
            return false;
        }
        // FHD_SOLID is not meaningful for unpack version < 20; rely on the
        // archive-level MHD_SOLID flag in that case.
        file.unp_ver < 20 || file.is_solid()
    }

    fn codec_for(&mut self, file: &FileHeader) -> Result<&mut CodecState> {
        let reset = !self.file_is_solid(file)
            || self
                .codec
                .as_ref()
                .is_none_or(|codec| !codec.supports(file));
        if reset {
            self.codec = Some(CodecState::new_for(file)?);
        }
        self.codec
            .as_mut()
            .ok_or(Error::InvalidHeader("RAR 1.5 codec state is missing"))
    }
}

impl FileHeader {
    fn is_empty_compressed_payload(&self) -> bool {
        !self.is_stored() && self.pack_size == 0 && self.unp_size == 0
    }

    /// The CRC this fragment's PACKED bytes must hash to, when the header
    /// carries one. WinRAR stamps every NON-final fragment of a split
    /// member (unpack version 2.0 and later; 1.5x writes 0xffffffff
    /// there) with the CRC of that fragment's stored bytes - the raw
    /// ciphertext for encrypted members - while the FINAL fragment
    /// carries the whole member's unpacked CRC. unrar checks it at every
    /// volume boundary (UIERROR_CHECKSUMPACKED), which is what localizes
    /// damage to one volume instead of failing the member at its end;
    /// both split walks do the same. Measured on the RAR 1.54 and 3.00
    /// multivolume fixtures.
    fn split_fragment_packed_crc(&self) -> Option<u32> {
        (self.is_split_after() && self.unp_ver >= 20 && self.file_crc != 0xffff_ffff)
            .then_some(self.file_crc)
    }
}

/// Streams a multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volumes_to_impl(volumes, options, &mut open, None)
}

/// [`extract_volumes_to`] reporting each volume the engine is finished
/// with - the RAR4 twin of
/// [`crate::rar50::extract_volumes_to_with_progress`], with the same
/// contract: `consumed(volume_index)` means "no read will ever touch
/// that volume again", and indices arrive in increasing order, once
/// each. A split member releases its volumes progressively as its chain
/// streams forward - RAR4 split decodes never re-read a fragment (there
/// is no buffered filter retry in this family), so every fragment's
/// volume frees the moment the chain has read it out. The callback can
/// run on the decode thread, hence `Send`.
pub fn extract_volumes_to_with_progress<F, C>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    mut consumed: C,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    C: FnMut(usize) + Send,
{
    extract_volumes_to_impl(volumes, options, &mut open, Some(&mut consumed))
}

fn extract_volumes_to_impl<F>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    open: &mut F,
    mut consumed: Option<&mut (dyn FnMut(usize) + Send)>,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 volume set is empty"));
    }

    let password = options.password;
    let mut split = SplitVolumeState::new();
    let mut session = DecoderSession::new_with_password(
        volumes
            .first()
            .is_some_and(|archive| archive.main.is_solid()),
        password,
    );
    // This walk has no way to finish a header walk that stopped at an
    // arrival frontier, so a partially enumerated volume here would
    // silently skip members; only the sequence driver can complete one.
    if volumes.iter().any(|a| a.is_partially_enumerated()) {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume set has a partially enumerated volume",
        ));
    }
    // Volumes already reported consumed, so the catch-up after a split
    // member releases the whole backlog in order.
    let mut reported = 0usize;
    for (volume_index, archive) in volumes.iter().enumerate() {
        for (file_index, file) in archive.files().enumerate() {
            match split.advance(file.is_split_before(), file.is_split_after()) {
                SplitVolumeStep::Regular => {
                    let meta = file.metadata();
                    if meta.is_directory {
                        let _ = open(&meta)?;
                    } else {
                        let mut writer = open(&meta)?;
                        if file.is_stored() {
                            file.write_stored_to(archive, password, &mut writer)
                                .map_err(|error| file.entry_error("extracting", error))?;
                        } else {
                            session
                                .write_file_to(archive, file, &mut writer)
                                .map_err(|error| file.entry_error("extracting", error))?;
                        }
                    }
                }
                SplitVolumeStep::Start => {
                    validate_split_fragment(file, password)?;
                    split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                }
                SplitVolumeStep::Continue(current) => {
                    validate_split_continuation_refs(current, file, password)?;
                    current.append(file, volume_index, file_index)?;
                }
                SplitVolumeStep::Finish(mut completed) => {
                    validate_split_continuation_refs(&completed, file, password)?;
                    completed.append(file, volume_index, file_index)?;
                    // Progressive release, exactly as the rar50 twin: a
                    // fragment the chain has read out frees its volume
                    // (and any skipped ones before it) through the shared
                    // `reported` cursor. RAR4 split decodes never re-read
                    // a fragment, so the watermark is safe on both the
                    // stored and the compressed path. The finish volume
                    // stays held; the walk is still in it.
                    let reported = &mut reported;
                    let mut spent = consumed.as_deref_mut().map(|consumed| {
                        move |spent_volume: usize| {
                            while *reported <= spent_volume {
                                consumed(*reported);
                                *reported += 1;
                            }
                        }
                    });
                    completed.write_to(
                        volumes,
                        file,
                        password,
                        &mut session,
                        &mut *open,
                        spent
                            .as_mut()
                            .map(|spent| spent as &mut (dyn FnMut(usize) + Send)),
                    )?;
                }
                SplitVolumeStep::MissingFirst => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split entry is missing its first part",
                    ));
                }
                SplitVolumeStep::Interrupted => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split entry is interrupted by a regular entry",
                    ));
                }
            }
        }
        // Walked out of this volume - see the rar50 twin for why a
        // pending split holds the report back.
        if !split.is_pending() {
            if let Some(consumed) = consumed.as_mut() {
                while reported <= volume_index {
                    consumed(reported);
                    reported += 1;
                }
            }
        }
    }

    if split.is_pending() {
        return Err(Error::InvalidHeader("RAR 1.5 split entry is incomplete"));
    }

    Ok(())
}

/// Streams a RAR 1.5-4.x multivolume set whose volumes become available
/// one at a time, extracting each volume's members as soon as that volume
/// parses - the RAR4 twin of `rar50::extract_volume_sequence_to`.
///
/// `next_volume(index)` supplies volume `index`, blocking as needed (e.g.
/// an [`Archive::parse_stream`] call over a still-arriving source), and
/// returns `None` after the last volume. Members of volume k extract
/// before volume k+1 is requested, so extraction chases a progressive
/// download at volume granularity. Split members spanning volumes j..=k
/// decode when volume k appears, reading earlier fragments back through
/// the retained volumes, with the same semantics as
/// [`extract_volumes_to`]. Decoding is serial: RAR4 decode always is.
///
/// A COMPRESSED split member decodes INCREMENTALLY: its sink opens at the
/// Start fragment and its packed bytes feed the decoder as each volume
/// lands, instead of waiting for the Finish fragment and reading every
/// fragment back. The rar50 twin does the same thing the same way; see
/// [`extract_volume_sequence_to_with_progress`] for the per-volume
/// consumption watermark that goes with it.
pub fn extract_volume_sequence_to<P, F>(
    next_volume: P,
    options: crate::ArchiveReadOptions<'_>,
    open: F,
) -> Result<()>
where
    P: FnMut(usize) -> Result<Option<Archive>> + Send,
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volume_sequence_to_with_progress(next_volume, options, open, |_, _| {})
}

/// [`extract_volume_sequence_to`] reporting how much of each volume the
/// engine is finished with - the RAR4 twin of
/// [`crate::rar50::extract_volume_sequence_to_with_progress`], with the
/// same contract and the same guarantees:
///
/// - packed reads run strictly forward (the RAR 1.5-4 decoders pull their
///   input through one sequential reader, and `DecryptingReader` is a
///   sequential cipher over that same chain);
/// - `u64::MAX` means the whole volume;
/// - the callback runs on the decode thread as well as this one, hence
///   `Sync`.
///
/// Unlike RAR 5 there is no buffered filter retry to protect: the RAR4
/// split path always streams, so a member publishes from its first read.
pub fn extract_volume_sequence_to_with_progress<P, F, C>(
    mut next_volume: P,
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    consumed: C,
) -> Result<()>
where
    P: FnMut(usize) -> Result<Option<Archive>> + Send,
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    C: Fn(usize, u64) + Sync,
{
    let password = options.password;
    let mut split = SplitVolumeState::new();
    let mut session: Option<DecoderSession> = None;
    let mut volumes: Vec<Archive> = Vec::new();
    let mut reported = 0usize;
    let mut resume: Option<(usize, usize)> = None;

    loop {
        let (volume_index, start_at) = match resume.take() {
            Some(at) => at,
            None => {
                // The previous volume is walked out. Report it (and every
                // one before it) consumed - unless a NON-incremental split
                // is pending, which will read those fragments back at its
                // Finish.
                if !split.is_pending() {
                    while reported < volumes.len() {
                        consumed(reported, u64::MAX);
                        reported += 1;
                    }
                }
                let volume_index = volumes.len();
                let Some(archive) = next_volume(volume_index)? else {
                    break;
                };
                volumes.push(archive);
                (volume_index, 0)
            }
        };
        // The solid flag lives on the main header; the first volume's is
        // the set's (extract_volumes_to keys off volumes.first() the same
        // way).
        let solid_set = volumes[0].main.is_solid();
        session.get_or_insert_with(|| DecoderSession::new_with_password(solid_set, password));

        let mut chase_at: Option<usize> = None;
        {
            let session = session.as_mut().expect("session just created");
            // A resume loop, as in the RAR5 twin: running off the end of
            // a volume parsed by `Archive::parse_stream_incremental` does
            // NOT mean it is walked out - the header walk stopped at the
            // arrival frontier and is finished here, at the bottom, by
            // which time the split member has decoded and the caller has
            // released its bytes.
            let mut resume_at = start_at;
            'walk: loop {
                let archive = &volumes[volume_index];
                for (file_index, file) in archive.files().enumerate().skip(resume_at) {
                    resume_at = file_index + 1;
                    match split.advance(file.is_split_before(), file.is_split_after()) {
                        SplitVolumeStep::Regular => {
                            let meta = file.metadata();
                            if meta.is_directory {
                                let _ = open(&meta)?;
                            } else {
                                let mut writer = open(&meta)?;
                                if file.is_stored() {
                                    file.write_stored_to(archive, password, &mut writer)
                                        .map_err(|error| file.entry_error("extracting", error))?;
                                } else {
                                    session
                                        .write_file_to(archive, file, &mut writer)
                                        .map_err(|error| file.entry_error("extracting", error))?;
                                }
                            }
                        }
                        SplitVolumeStep::Start => {
                            validate_split_fragment(file, password)?;
                            // `advance` leaves the state untouched for Start
                            // (only `begin` arms it), so breaking out here is
                            // clean - the chain owns the member from now on.
                            if !file.is_stored() {
                                chase_at = Some(file_index);
                                // Left here and never walked again, and needs
                                // no completion: this entry is flagged
                                // SPLIT_AFTER, and nothing can follow a member
                                // that continues into the next volume but the
                                // end block.
                                break 'walk;
                            }
                            split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                        }
                        SplitVolumeStep::Continue(current) => {
                            validate_split_continuation_refs(current, file, password)?;
                            current.append(file, volume_index, file_index)?;
                        }
                        SplitVolumeStep::Finish(mut completed) => {
                            validate_split_continuation_refs(&completed, file, password)?;
                            completed.append(file, volume_index, file_index)?;
                            // The splits that land here are STORED members
                            // (the chase takes every compressed one). They
                            // stream forward exactly once, so each fragment
                            // frees its volume as the chain advances - the
                            // caller's retention window must not have to
                            // hold a 400-volume stored film whole.
                            let reported = &mut reported;
                            let consumed = &consumed;
                            let mut spent = move |spent_volume: usize| {
                                while *reported <= spent_volume {
                                    consumed(*reported, u64::MAX);
                                    *reported += 1;
                                }
                            };
                            completed.write_to(
                                &volumes,
                                file,
                                password,
                                session,
                                &mut open,
                                Some(&mut spent),
                            )?;
                        }
                        SplitVolumeStep::MissingFirst => {
                            return Err(Error::InvalidHeader(
                                "RAR 1.5 split entry is missing its first part",
                            ));
                        }
                        SplitVolumeStep::Interrupted => {
                            return Err(Error::InvalidHeader(
                                "RAR 1.5 split entry is interrupted by a regular entry",
                            ));
                        }
                    }
                }
                if !volumes[volume_index].is_partially_enumerated() {
                    break 'walk;
                }
                volumes[volume_index].enumerate_rest(password)?;
            }
        }

        if let Some(file_index) = chase_at {
            let finish = incremental_split_decode(
                &mut volumes,
                (volume_index, file_index),
                &mut next_volume,
                password,
                session.as_mut().expect("session just created"),
                &mut open,
                &consumed,
            )?;
            // The finishing volume may carry more members after the split
            // member, so the walk resumes inside it.
            resume = Some((finish.0, finish.1 + 1));
        }
    }

    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 volume set is empty"));
    }
    if split.is_pending() {
        return Err(Error::InvalidHeader("RAR 1.5 split entry is incomplete"));
    }

    Ok(())
}

/// Decode one compressed split member incrementally, starting at its
/// Start fragment and pulling the volumes that carry the rest. Returns
/// the FINISH fragment's coordinates so the caller can resume its entry
/// walk inside that volume. The rar50 twin of this is
/// `rar50::extract::incremental_split_decode`; keep them the same shape.
fn incremental_split_decode<P, F, C>(
    volumes: &mut Vec<Archive>,
    start: (usize, usize),
    next_volume: &mut P,
    password: Option<&[u8]>,
    session: &mut DecoderSession<'_>,
    open: &mut F,
    consumed: &C,
) -> Result<(usize, usize)>
where
    P: FnMut(usize) -> Result<Option<Archive>> + Send,
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    C: Fn(usize, u64) + Sync,
{
    let (start_volume, start_file) = start;
    // An owned copy of the Start fragment's header: it drives the whole
    // decode (name, method, unpack version, unpacked size and encryption
    // all repeat across a split member's fragments) and the chain owns
    // `volumes`.
    let first = volumes
        .get(start_volume)
        .and_then(|archive| archive.files().nth(start_file))
        .ok_or(Error::InvalidHeader("RAR 1.5 split entry is missing"))?
        .clone();
    let pending = PendingSplitRefs::new(&first, start_volume, start_file);
    let meta = ExtractedEntryMeta {
        name: pending.name.clone(),
        file_time: pending.file_time,
        attr: pending.attr,
        host_os: pending.host_os,
        is_directory: false,
        unpacked_size: first.unp_size,
    };
    let mut writer = open(&meta)?;

    let mut chain = GrowingChainedReader::new(
        std::mem::take(volumes),
        pending,
        &first,
        next_volume,
        password,
        consumed,
    );
    let decode = {
        let mut packed: Box<dyn Read + Send + '_> = if first.is_encrypted() {
            let Some(password) = password else {
                *volumes = chain.into_parts().1;
                return Err(Error::NeedPassword);
            };
            match DecryptingReader::new(&mut chain, first.unp_ver, password, first.salt) {
                Ok(reader) => Box::new(reader),
                Err(error) => {
                    *volumes = chain.into_parts().1;
                    return Err(error);
                }
            }
        } else {
            Box::new(&mut chain)
        };
        session.decode_split_to(&mut packed, &first, &mut writer)
    };

    match decode {
        Ok(actual) => {
            let (finish, volumes_back) = chain.finish()?;
            *volumes = volumes_back;
            let final_file = volumes[finish.0]
                .files()
                .nth(finish.1)
                .ok_or(Error::InvalidHeader("RAR 1.5 split entry is missing"))?;
            final_file
                .crc_result(actual, password)
                .map_err(|error| final_file.entry_error("extracting", error))?;
            Ok(finish)
        }
        Err(error) => {
            // A real rars error behind the io error the decoder saw (a
            // continuation that changed name or method, a volume that
            // never arrived) is the one to report - bare, exactly as the
            // whole-set walk reports it.
            let reported = chain.take_error();
            *volumes = chain.into_parts().1;
            match reported {
                Some(error) => Err(error),
                None => Err(first.entry_error("extracting", error)),
            }
        }
    }
}

/// The packed byte chain of a split member whose later fragments DO NOT
/// EXIST YET - the RAR4 twin of `rar50`'s reader of the same name, and
/// deliberately identical in shape.
///
/// `LazyChainedReader` serves a fragment list resolved up front; this one
/// pulls the next volume from the sequence driver when the fragment in
/// hand runs dry, which is what lets a split member start decoding at its
/// Start fragment instead of its Finish. Fragments are consumed strictly
/// forward and exactly once, one open cursor at a time.
struct GrowingChainedReader<'a, P, C> {
    volumes: Vec<Archive>,
    pending: PendingSplitRefs,
    next_volume: &'a mut P,
    consumed: &'a C,
    password: Option<&'a [u8]>,
    /// Identity every continuation is checked against.
    method: u8,
    unp_ver: u8,
    encrypted: bool,
    salt: Option<[u8; 8]>,
    unp_size: u64,
    /// Index into `pending.fragments` of the fragment the cursor is on.
    at: usize,
    cursor: Option<crate::source::OwnedRangeReader>,
    /// Volume-space start of that fragment's packed range, and how far in
    /// the decoder has read.
    frag_start: u64,
    frag_pos: u64,
    /// The fragment's packed length - `frag_pos` reaching it means the
    /// fragment is fully read even when no read ever drained the cursor.
    frag_len: u64,
    /// Running CRC of the fragment's packed bytes, checked against
    /// [`FileHeader::split_fragment_packed_crc`] when the fragment reads
    /// out - the check that localizes damage to one volume.
    frag_crc: Crc32,
    frag_expected_crc: Option<u32>,
    /// The finish fragment (no SPLIT_AFTER) has been appended.
    last_seen: bool,
    /// Fragments already reported wholly consumed.
    reported: usize,
    /// The rars error behind the io error handed to the decoder.
    error: Option<Error>,
}

impl<'a, P, C> GrowingChainedReader<'a, P, C>
where
    P: FnMut(usize) -> Result<Option<Archive>>,
    C: Fn(usize, u64),
{
    fn new(
        volumes: Vec<Archive>,
        pending: PendingSplitRefs,
        first: &FileHeader,
        next_volume: &'a mut P,
        password: Option<&'a [u8]>,
        consumed: &'a C,
    ) -> Self {
        Self {
            volumes,
            pending,
            next_volume,
            consumed,
            password,
            method: first.method,
            unp_ver: first.unp_ver,
            encrypted: first.is_encrypted(),
            salt: first.salt,
            unp_size: first.unp_size,
            at: 0,
            cursor: None,
            frag_start: 0,
            frag_pos: 0,
            frag_len: 0,
            frag_crc: Crc32::new(),
            frag_expected_crc: None,
            last_seen: !first.is_split_after(),
            reported: 0,
            error: None,
        }
    }

    fn take_error(&mut self) -> Option<Error> {
        self.error.take()
    }

    fn into_parts(self) -> (PendingSplitRefs, Vec<Archive>) {
        (self.pending, self.volumes)
    }

    /// Finish coordinates plus the volumes, once the decode has run to
    /// the end of the chain. A decoder that stopped early (its declared
    /// unpacked size short of what the fragments carry) still has to name
    /// the member's real end, so the walk resumes in the right volume.
    fn finish(mut self) -> Result<((usize, usize), Vec<Archive>)> {
        self.check_boundary_fragment()?;
        while !self.last_seen {
            self.pull_fragment()?;
        }
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        let finish = *self
            .pending
            .fragments
            .last()
            .expect("the chain always holds its start fragment");
        Ok((finish, self.volumes))
    }

    /// Publish how much of each volume the engine is finished with. The
    /// fragment the cursor is ON reports its own byte offset, never
    /// `u64::MAX`: the FINISHING volume carries the members after the
    /// split one, and the caller resumes its walk there.
    fn report(&mut self) {
        while self.reported < self.at {
            let (volume_index, _) = self.pending.fragments[self.reported];
            (self.consumed)(volume_index, u64::MAX);
            self.reported += 1;
        }
        if let Some(&(volume_index, _)) = self.pending.fragments.get(self.at) {
            (self.consumed)(volume_index, self.frag_start + self.frag_pos);
        }
    }

    /// Take the next volume from the driver and record its continuation
    /// fragment. Volumes with no file entries are skipped, exactly as the
    /// whole-set walk skips them.
    fn pull_fragment(&mut self) -> Result<()> {
        loop {
            let volume_index = self.volumes.len();
            let Some(archive) = (self.next_volume)(volume_index)? else {
                return Err(Error::InvalidHeader("RAR 1.5 split entry is incomplete"));
            };
            self.volumes.push(archive);
            // A volume parsed by `Archive::parse_stream_incremental` can
            // read as empty while it is merely still arriving, and
            // skipping THAT would drop a fragment of the member being
            // decoded - so an archive with no entries is pressed for the
            // truth first.
            let password = self.password;
            if self.volumes[volume_index].files().next().is_none() {
                self.volumes[volume_index].enumerate_rest(password)?;
            }
            let archive = &self.volumes[volume_index];
            let Some(file) = archive.files().next() else {
                continue;
            };
            if !file.is_split_before() {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry is interrupted by a regular entry",
                ));
            }
            validate_split_fragment(file, self.password)?;
            if file.name != self.pending.name {
                return Err(Error::InvalidHeader("RAR 1.5 split entry name changed"));
            }
            if file.method != self.method {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry compression method changed",
                ));
            }
            if file.unp_ver != self.unp_ver {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry unpack version changed",
                ));
            }
            if file.is_encrypted() != self.encrypted {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry encryption flag changed",
                ));
            }
            if self.encrypted && self.unp_ver >= 29 && file.salt != self.salt {
                return Err(Error::InvalidHeader("RAR 3.x split entry salt changed"));
            }
            // Not checked by the whole-set walk, which reads the size off
            // the LAST fragment; the incremental decode is already running
            // against the FIRST one's, so a disagreement has to be caught.
            // Every fragment of a split member repeats the total.
            if file.unp_size != self.unp_size {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry unpacked size changed",
                ));
            }
            self.last_seen = !file.is_split_after();
            self.pending.fragments.push((volume_index, 0));
            return Ok(());
        }
    }

    fn open_cursor(&mut self) -> Result<()> {
        let (volume_index, file_index) = self.pending.fragments[self.at];
        let archive = self
            .volumes
            .get(volume_index)
            .ok_or(Error::InvalidHeader("RAR 1.5 split volume is missing"))?;
        let file = archive
            .files()
            .nth(file_index)
            .ok_or(Error::InvalidHeader("RAR 1.5 split entry is missing"))?;
        let range = file.packed_range.clone();
        self.frag_start = range.start as u64;
        self.frag_pos = 0;
        self.frag_len = (range.end - range.start) as u64;
        self.frag_crc = Crc32::new();
        self.frag_expected_crc = file.split_fragment_packed_crc();
        self.cursor = Some(archive.owned_range_reader(range)?);
        Ok(())
    }

    /// The packed CRC check fires when a read drains the cursor, so a
    /// consumer that stops asking EXACTLY at a fragment's boundary (a
    /// stored member whose final fragment is pure encryption padding, a
    /// decoder that finishes at the byte) never issues the read that
    /// would run it. Every one of the fragment's bytes is hashed by
    /// then, so the check can run here without forcing a read the
    /// consumer did not want. A cursor stopped MID-fragment stays
    /// unchecked: its remaining bytes were never read, so there is
    /// nothing sound to compare.
    fn check_boundary_fragment(&mut self) -> Result<()> {
        if self.cursor.is_some() && self.frag_pos == self.frag_len {
            self.cursor = None;
            if let Some(expected) = self.frag_expected_crc.take() {
                let actual = self.frag_crc.finish();
                if actual != expected {
                    let (volume_index, _) = self.pending.fragments[self.at];
                    return Err(Error::SplitFragmentCrc32Mismatch {
                        volume: volume_index,
                        expected,
                        actual,
                    });
                }
            }
        }
        Ok(())
    }

    /// Record the real error and hand the decoder something to stop on.
    fn fail(&mut self, error: Error) -> std::io::Error {
        let message = error.to_string();
        if self.error.is_none() {
            self.error = Some(error);
        }
        std::io::Error::other(message)
    }
}

impl<P, C> Read for GrowingChainedReader<'_, P, C>
where
    P: FnMut(usize) -> Result<Option<Archive>>,
    C: Fn(usize, u64),
{
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        // A recorded failure latches, matching FragmentCrcReader: a
        // caller that swallowed the io error must keep failing here,
        // because the error surfaces with `at` unadvanced and the
        // cursor dropped - without the latch a retried read would
        // re-open the failed fragment and deliver its bytes again as
        // if nothing happened.
        if let Some(error) = self.error.as_ref() {
            return Err(std::io::Error::other(error.to_string()));
        }
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(cursor) = self.cursor.as_mut() {
                let read = cursor.read(out)?;
                if read != 0 {
                    self.frag_pos += read as u64;
                    self.frag_crc.update(&out[..read]);
                    self.report();
                    return Ok(read);
                }
                // Drop the finished fragment BEFORE opening the next one.
                self.cursor = None;
                // The fragment is read out; its own header says what its
                // packed bytes must hash to. Checked BEFORE the volume is
                // reported consumed - the caller may act on that report.
                if let Some(expected) = self.frag_expected_crc.take() {
                    let actual = self.frag_crc.finish();
                    if actual != expected {
                        let (volume_index, _) = self.pending.fragments[self.at];
                        return Err(self.fail(Error::SplitFragmentCrc32Mismatch {
                            volume: volume_index,
                            expected,
                            actual,
                        }));
                    }
                }
                if self.last_seen && self.at + 1 == self.pending.fragments.len() {
                    self.report();
                    return Ok(0);
                }
                self.at += 1;
            }
            if self.at >= self.pending.fragments.len() {
                if let Err(error) = self.pull_fragment() {
                    return Err(self.fail(error));
                }
            }
            if let Err(error) = self.open_cursor() {
                return Err(self.fail(error));
            }
        }
    }
}

fn validate_split_fragment(file: &FileHeader, password: Option<&[u8]>) -> Result<()> {
    if file.is_directory() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split directory entry is invalid",
        ));
    }
    if file.is_encrypted() && password.is_none() {
        return Err(Error::NeedPassword);
    }
    Ok(())
}

fn validate_split_continuation_refs(
    pending: &PendingSplitRefs,
    file: &FileHeader,
    password: Option<&[u8]>,
) -> Result<()> {
    validate_split_fragment(file, password)?;
    if file.name != pending.name {
        return Err(Error::InvalidHeader("RAR 1.5 split entry name changed"));
    }
    if file.method != pending.method {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry compression method changed",
        ));
    }
    if file.unp_ver != pending.unp_ver {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry unpack version changed",
        ));
    }
    if file.is_encrypted() != pending.encrypted {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry encryption flag changed",
        ));
    }
    if pending.encrypted && pending.unp_ver >= 29 && file.salt != pending.salt {
        return Err(Error::InvalidHeader("RAR 3.x split entry salt changed"));
    }
    Ok(())
}

/// The typed error behind the io error a [`FragmentCrcReader`] hands the
/// decoder - `Read::read` has no other channel, and the whole-set walk
/// recovers it after the decode stops (the incremental path has
/// [`GrowingChainedReader::take_error`] for the same job). Shared because
/// the wrapper lives inside a fragment opener while the walk holds the
/// other end.
type SharedFragmentError = Arc<Mutex<Option<Error>>>;

/// One split fragment's packed bytes, verified against the CRC the
/// fragment's OWN header carries as the chain reads it out - see
/// [`FileHeader::split_fragment_packed_crc`]. This is what fails a
/// damaged set at the first bad volume, naming it, instead of decoding
/// the whole member and failing on the final unpacked CRC.
struct FragmentCrcReader<'a> {
    inner: Box<dyn Read + Send + 'a>,
    crc: Crc32,
    expected: u32,
    volume: usize,
    slot: SharedFragmentError,
    failed: bool,
}

impl Read for FragmentCrcReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        // Keep failing on any read after a mismatch: a caller that
        // swallowed the first error must not see a clean EOF, advance the
        // chain and finish the member as if the fragment were sound.
        if self.failed {
            return Err(std::io::Error::other(
                "RAR 1.5 split fragment packed data checksum mismatch",
            ));
        }
        // An empty read must not look like fragment EOF and trigger the
        // check early.
        if out.is_empty() {
            return Ok(0);
        }
        let read = self.inner.read(out)?;
        if read != 0 {
            self.crc.update(&out[..read]);
            return Ok(read);
        }
        let actual = self.crc.finish();
        if actual != self.expected {
            self.failed = true;
            let error = Error::SplitFragmentCrc32Mismatch {
                volume: self.volume,
                expected: self.expected,
                actual,
            };
            let message = error.to_string();
            *self.slot.lock().unwrap() = Some(error);
            return Err(std::io::Error::other(message));
        }
        Ok(0)
    }
}

struct PendingSplitRefs {
    name: Vec<u8>,
    fragments: Vec<(usize, usize)>,
    file_time: u32,
    attr: u32,
    host_os: u8,
    method: u8,
    unp_ver: u8,
    encrypted: bool,
    salt: Option<[u8; 8]>,
}

impl PendingSplitRefs {
    fn new(file: &FileHeader, volume_index: usize, file_index: usize) -> Self {
        Self {
            name: file.name.clone(),
            fragments: vec![(volume_index, file_index)],
            file_time: file.file_time,
            attr: file.attr,
            host_os: file.host_os,
            method: file.method,
            unp_ver: file.unp_ver,
            encrypted: file.is_encrypted(),
            salt: file.salt,
        }
    }

    fn append(&mut self, _file: &FileHeader, volume_index: usize, file_index: usize) -> Result<()> {
        // Strictly increasing volumes only: a crafted archive with two
        // fragments of one member in the same volume would let the
        // consumption watermark report that volume spent while a later
        // fragment still needs to reopen it by path - the caller may
        // have deleted it on the report. No real archiver splits a
        // member twice within one volume.
        if let Some(&(last_volume, _)) = self.fragments.last() {
            if volume_index <= last_volume {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split fragment does not advance to a later volume",
                ));
            }
        }
        self.fragments.push((volume_index, file_index));
        Ok(())
    }

    fn write_to<F>(
        self,
        volumes: &[Archive],
        final_file: &FileHeader,
        password: Option<&[u8]>,
        session: &mut DecoderSession,
        open: &mut F,
        spent: Option<&mut (dyn FnMut(usize) + Send)>,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let meta = ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: false,
            unpacked_size: final_file.unp_size,
        };
        let mut writer = open(&meta)?;
        // Both arms below stream the chain forward exactly once (RAR4 has
        // no buffered filter retry), so the consumption watermark is safe
        // on either. Re-boxed so the fresh trait object's lifetime can
        // shrink to the volumes borrow.
        let spent = spent.map(|f| {
            Box::new(move |volume: usize| f(volume)) as Box<dyn FnMut(usize) + Send + '_>
        });
        let fragment_error: SharedFragmentError = Arc::default();
        let mut reader = self.fragment_reader(volumes, password, spent, &fragment_error)?;

        let result = (|| {
            if final_file.is_stored() {
                let expected_len = usize::try_from(final_file.unp_size).map_err(|_| {
                    Error::InvalidHeader("RAR 1.5 split unpacked size overflows usize")
                })?;
                let actual_len = self.packed_size(volumes)?;
                let expected_packed_len =
                    if self.encrypted && self.unp_ver >= 20 {
                        expected_len.checked_add(15).map(|len| len & !15).ok_or(
                            Error::InvalidHeader("RAR 2.x encrypted split stored size overflows"),
                        )?
                    } else {
                        expected_len
                    };
                if actual_len != expected_packed_len {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split stored file has wrong reassembled size",
                    ));
                }

                let mut crc = Crc32::new();
                let mut crc_writer = CrcWriter {
                    inner: &mut writer,
                    crc: &mut crc,
                };
                let copied =
                    std::io::copy(&mut reader.take(expected_len as u64), &mut crc_writer)?;
                if copied != expected_len as u64 {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split stored file ended before unpacked size",
                    ));
                }
                let actual = crc.finish();
                final_file
                    .crc_result(actual, password)
                    .map_err(|error| final_file.entry_error("extracting", error))
            } else {
                session
                    .write_split_to(&mut reader, final_file, &mut writer)
                    .map_err(|error| final_file.entry_error("extracting", error))
            }
        })();
        // A fragment CRC mismatch reaches here as the io error the decoder
        // (or the stored copy) stopped on; the typed error it wraps names
        // the bad volume and is the one to report - bare, exactly as the
        // incremental path reports it through `take_error`.
        result.map_err(|error| fragment_error.lock().unwrap().take().unwrap_or(error))
    }

    fn packed_size(&self, volumes: &[Archive]) -> Result<usize> {
        self.fragments
            .iter()
            .try_fold(0usize, |total, &(volume_index, file_index)| {
                let archive = volumes
                    .get(volume_index)
                    .ok_or(Error::InvalidHeader("RAR 1.5 split volume is missing"))?;
                let file = archive
                    .files()
                    .nth(file_index)
                    .ok_or(Error::InvalidHeader("RAR 1.5 split entry is missing"))?;
                total
                    .checked_add(usize::try_from(file.pack_size).map_err(|_| {
                        Error::InvalidHeader("RAR 1.5 split packed size overflows usize")
                    })?)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.5 split packed size overflows usize",
                    ))
            })
    }

    fn fragment_reader<'a>(
        &self,
        volumes: &'a [Archive],
        password: Option<&[u8]>,
        spent: Option<Box<dyn FnMut(usize) + Send + 'a>>,
        fragment_error: &SharedFragmentError,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        // Fragments are RESOLVED here (a missing volume or entry still fails
        // before a byte is read) but opened one at a time as the chain
        // advances - see [`LazyChainedReader`]. A ~300-volume split member
        // used to want 300 file descriptors at once. The whole-chain
        // decryptor below is unchanged: RAR 1.5-4 keys the member, not the
        // fragment.
        let mut openers: Vec<FragmentOpener<'a>> = Vec::with_capacity(self.fragments.len());
        // Consumption marks: each fragment frees its volume when read out,
        // except the LAST one - its volume carries the members after the
        // split one and the caller's walk resumes there.
        let mut marks: Vec<Option<usize>> = Vec::with_capacity(self.fragments.len());
        for (position, &(volume_index, file_index)) in self.fragments.iter().enumerate() {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 1.5 split volume is missing"))?;
            let file = archive
                .files()
                .nth(file_index)
                .ok_or(Error::InvalidHeader("RAR 1.5 split entry is missing"))?;
            let range = file.packed_range.clone();
            let expected_crc = file.split_fragment_packed_crc();
            let slot = Arc::clone(fragment_error);
            openers.push(Box::new(move || {
                let reader = archive.range_reader(range).map_err(std::io::Error::other)?;
                Ok(match expected_crc {
                    Some(expected) => Box::new(FragmentCrcReader {
                        inner: reader,
                        crc: Crc32::new(),
                        expected,
                        volume: volume_index,
                        slot,
                        failed: false,
                    }) as Box<dyn Read + Send + 'a>,
                    None => reader,
                })
            }));
            marks.push((position + 1 < self.fragments.len()).then_some(volume_index));
        }
        let reader = LazyChainedReader::with_spent(openers, marks, spent);
        if !self.encrypted {
            return Ok(Box::new(reader));
        }

        let Some(password) = password else {
            return Err(Error::NeedPassword);
        };
        Ok(Box::new(DecryptingReader::new(
            reader,
            self.unp_ver,
            password,
            self.salt,
        )?))
    }
}

enum SplitCipher {
    Rar15(Rar15Cipher),
    Rar20(Box<Rar20Cipher>),
    Rar30(Box<Rar30Cipher>),
}

impl SplitCipher {
    fn new(unp_ver: u8, password: &[u8], salt: Option<[u8; 8]>) -> Result<Self> {
        if unp_ver == 15 {
            return Ok(Self::Rar15(Rar15Cipher::new(password)));
        }
        if unp_ver == 20 || unp_ver == 26 {
            return Ok(Self::Rar20(Box::new(Rar20Cipher::new(password))));
        }
        if unp_ver >= 29 {
            return Ok(Self::Rar30(Box::new(
                Rar30Cipher::new(password, salt).map_err(super::map_rar30_crypto_error)?,
            )));
        }
        Err(Error::UnsupportedEncryption {
            family: "RAR 1.5-4.x split volume",
            unpack_version: unp_ver,
        })
    }
}

pub(super) struct DecryptingReader<R> {
    inner: R,
    cipher: SplitCipher,
    encrypted_block: Vec<u8>,
    decrypted: Vec<u8>,
    read_buffer: Option<Vec<u8>>,
    decrypted_pos: usize,
    eof: bool,
}

impl<R: Read> DecryptingReader<R> {
    pub(super) fn new(
        inner: R,
        unp_ver: u8,
        password: &[u8],
        salt: Option<[u8; 8]>,
    ) -> Result<Self> {
        let cipher = SplitCipher::new(unp_ver, password, salt)?;
        let read_buffer = matches!(cipher, SplitCipher::Rar15(_)).then(|| vec![0; 64 * 1024]);
        Ok(Self {
            inner,
            cipher,
            encrypted_block: Vec::new(),
            decrypted: Vec::new(),
            read_buffer,
            decrypted_pos: 0,
            eof: false,
        })
    }

    fn fill_decrypted(&mut self) -> std::io::Result<()> {
        if self.decrypted_pos < self.decrypted.len() || self.eof {
            return Ok(());
        }
        self.decrypted.clear();
        self.decrypted_pos = 0;

        match &mut self.cipher {
            SplitCipher::Rar15(cipher) => {
                let read_buffer = self
                    .read_buffer
                    .as_mut()
                    .expect("RAR 1.5 decrypting reader has a reusable buffer");
                let count = self.inner.read(read_buffer)?;
                if count == 0 {
                    self.eof = true;
                    return Ok(());
                }
                self.decrypted.extend_from_slice(&read_buffer[..count]);
                cipher.crypt_in_place(&mut self.decrypted);
            }
            SplitCipher::Rar20(_) | SplitCipher::Rar30(_) => self.fill_block_decrypted()?,
        }
        Ok(())
    }

    fn fill_block_decrypted(&mut self) -> std::io::Result<()> {
        while self.encrypted_block.len() < 16 && !self.eof {
            let mut buf = [0u8; 64 * 1024];
            let count = self.inner.read(&mut buf)?;
            if count == 0 {
                self.eof = true;
                break;
            }
            self.encrypted_block.extend_from_slice(&buf[..count]);
        }

        let full_len = (self.encrypted_block.len() / 16) * 16;
        if full_len != 0 {
            let tail = self.encrypted_block.split_off(full_len);
            let mut data = std::mem::replace(&mut self.encrypted_block, tail);
            match &mut self.cipher {
                SplitCipher::Rar15(_) => unreachable!("RAR 1.5 is byte-stream decrypted"),
                SplitCipher::Rar20(cipher) => cipher
                    .decrypt_in_place(&mut data)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?,
                SplitCipher::Rar30(cipher) => cipher
                    .decrypt_in_place(&mut data)
                    .map_err(super::map_rar30_crypto_error)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?,
            }
            self.decrypted = data;
            self.decrypted_pos = 0;
        } else if self.eof && !self.encrypted_block.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RAR encrypted payload is not block aligned",
            ));
        }
        Ok(())
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        self.fill_decrypted()?;
        if self.decrypted_pos == self.decrypted.len() {
            return Ok(0);
        }
        let count = out.len().min(self.decrypted.len() - self.decrypted_pos);
        out[..count]
            .copy_from_slice(&self.decrypted[self.decrypted_pos..self.decrypted_pos + count]);
        self.decrypted_pos += count;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ArchiveSource, Block, BlockHeader, MainHeader, FHD_DIRECTORY_MASK, FHD_PASSWORD,
        FHD_SPLIT_AFTER, FHD_SPLIT_BEFORE,
    };
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    fn block(flags: u16) -> BlockHeader {
        BlockHeader {
            head_crc: 0,
            head_type: 0x74,
            flags,
            head_size: 0,
            add_size: Some(0),
            offset: 0,
        }
    }

    fn file(name: &[u8], flags: u16) -> FileHeader {
        FileHeader {
            block: block(flags),
            pack_size: 0,
            unp_size: 0,
            host_os: 2,
            file_crc: 0,
            file_time: 0,
            unp_ver: 29,
            method: 0x30,
            name: name.to_vec(),
            attr: 0x20,
            salt: None,
            file_comment: Vec::new(),
            ext_time: Vec::new(),
            packed_range: 0..0,
        }
    }

    struct ChunkedReader<R> {
        inner: R,
        chunk: usize,
    }

    impl<R: Read> ChunkedReader<R> {
        fn new(inner: R, chunk: usize) -> Self {
            Self { inner, chunk }
        }
    }

    impl<R: Read> Read for ChunkedReader<R> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let take = out.len().min(self.chunk);
            self.inner.read(&mut out[..take])
        }
    }

    fn read_in_small_chunks(mut reader: impl Read) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 7];
        loop {
            let count = reader.read(&mut buf).unwrap();
            if count == 0 {
                break;
            }
            out.extend_from_slice(&buf[..count]);
        }
        out
    }

    #[test]
    fn decrypting_reader_streams_rar15_payload() {
        let plain = b"RAR 1.5 encrypted payload read in pieces";
        let mut encrypted = plain.to_vec();
        Rar15Cipher::new(b"pw").crypt_in_place(&mut encrypted);
        let mut reader = DecryptingReader::new(Cursor::new(encrypted), 15, b"pw", None).unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 3];

        loop {
            let count = reader.read(&mut buf).unwrap();
            if count == 0 {
                break;
            }
            out.extend_from_slice(&buf[..count]);
        }

        assert_eq!(out, plain);
    }

    #[test]
    fn decrypting_reader_streams_rar20_blocks_from_short_inner_reads() {
        let plain = *b"0123456789abcdefRAR2 block two!!";
        let mut encrypted = plain;
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let reader = DecryptingReader::new(
            ChunkedReader::new(Cursor::new(encrypted), 5),
            20,
            b"pw",
            None,
        )
        .unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    #[test]
    fn decrypting_reader_streams_rar30_blocks_from_short_inner_reads() {
        let salt = Some([7u8; 8]);
        let plain = *b"0123456789abcdefRAR3 block two!!";
        let mut encrypted = plain;
        Rar30Cipher::new(b"pw", salt)
            .unwrap()
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let reader = DecryptingReader::new(
            ChunkedReader::new(Cursor::new(encrypted), 5),
            29,
            b"pw",
            salt,
        )
        .unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    /// The per-fragment packed CRC gate: only NON-final fragments carry
    /// one, RAR 1.5x stamps 0xffffffff there instead of a hash, and the
    /// final fragment's CRC is the member's unpacked one - never a
    /// packed-bytes expectation.
    #[test]
    fn split_fragment_packed_crc_applies_to_nonfinal_modern_fragments_only() {
        let mut middle = file(b"a", FHD_SPLIT_BEFORE | FHD_SPLIT_AFTER);
        middle.file_crc = 0x1234_5678;
        assert_eq!(middle.split_fragment_packed_crc(), Some(0x1234_5678));

        let mut last = middle.clone();
        last.block.flags = FHD_SPLIT_BEFORE;
        assert_eq!(last.split_fragment_packed_crc(), None);

        let mut old = middle.clone();
        old.unp_ver = 15;
        assert_eq!(old.split_fragment_packed_crc(), None);

        let mut unstamped = middle.clone();
        unstamped.file_crc = 0xffff_ffff;
        assert_eq!(unstamped.split_fragment_packed_crc(), None);
    }

    #[test]
    fn validate_split_fragment_rejects_directories_and_demands_password_for_encrypted() {
        let dir = file(b"d", FHD_DIRECTORY_MASK | FHD_SPLIT_AFTER);
        assert!(matches!(
            validate_split_fragment(&dir, None),
            Err(Error::InvalidHeader(_))
        ));

        let encrypted = file(b"a", FHD_PASSWORD | FHD_SPLIT_AFTER);
        assert!(matches!(
            validate_split_fragment(&encrypted, None),
            Err(Error::NeedPassword)
        ));
        validate_split_fragment(&encrypted, Some(b"pw")).unwrap();

        let plain = file(b"a", FHD_SPLIT_AFTER);
        validate_split_fragment(&plain, None).unwrap();
    }

    #[test]
    fn validate_split_continuation_refs_rejects_property_drift_between_fragments() {
        let first = file(b"a.txt", FHD_SPLIT_AFTER);
        let pending = PendingSplitRefs::new(&first, 0, 0);

        let renamed = file(b"b.txt", FHD_SPLIT_BEFORE);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &renamed, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_method = file(b"a.txt", FHD_SPLIT_BEFORE);
        new_method.method = 0x35;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_method, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_version = file(b"a.txt", FHD_SPLIT_BEFORE);
        new_version.unp_ver = 20;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_version, None),
            Err(Error::InvalidHeader(_))
        ));

        let new_encryption = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_encryption, Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let same = file(b"a.txt", FHD_SPLIT_BEFORE);
        validate_split_continuation_refs(&pending, &same, None).unwrap();
    }

    #[test]
    fn validate_split_continuation_refs_rejects_salt_drift_for_rar3_encrypted_entries() {
        let mut first = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.salt = Some([1u8; 8]);
        let pending = PendingSplitRefs::new(&first, 0, 0);

        let mut other_salt = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        other_salt.salt = Some([2u8; 8]);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &other_salt, Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let mut same_salt = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        same_salt.salt = Some([1u8; 8]);
        validate_split_continuation_refs(&pending, &same_salt, Some(b"pw")).unwrap();
    }

    fn empty_archive() -> Archive {
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                head_crc: 0,
                flags: 0,
                head_size: 0,
                reserved1: 0,
                reserved2: 0,
                encrypt_version: None,
            },
            blocks: Vec::new(),
            source: ArchiveSource::Memory(Arc::from(Vec::new().into_boxed_slice())),
            pending_from: None,
        }
    }

    fn archive_with(blocks: Vec<Block>) -> Archive {
        let mut archive = empty_archive();
        archive.blocks = blocks;
        archive
    }

    fn archive_with_source(blocks: Vec<Block>, source: Vec<u8>) -> Archive {
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                head_crc: 0,
                flags: 0,
                head_size: 0,
                reserved1: 0,
                reserved2: 0,
                encrypt_version: None,
            },
            blocks,
            source: ArchiveSource::Memory(Arc::from(source.into_boxed_slice())),
            pending_from: None,
        }
    }

    #[test]
    fn encrypted_split_fragment_reader_decrypts_after_chaining_fragments() {
        let plain = *b"0123456789abcdefRAR2 block two!!";
        let mut encrypted = plain;
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let split = 7;

        let mut first = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = split as u64;
        first.packed_range = 0..split;
        // The non-final fragment's header CRC is the CRC of its own
        // PACKED bytes - the ciphertext - and the chain verifies it.
        first.file_crc = crate::crc32::crc32(&encrypted[..split]);

        let mut second = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = (encrypted.len() - split) as u64;
        second.packed_range = 0..(encrypted.len() - split);

        let mut pending = PendingSplitRefs::new(&first, 0, 0);
        pending.append(&second, 1, 0).unwrap();
        let volumes = vec![
            archive_with_source(vec![Block::File(first)], encrypted[..split].to_vec()),
            archive_with_source(vec![Block::File(second)], encrypted[split..].to_vec()),
        ];

        let reader = pending
            .fragment_reader(&volumes, Some(b"pw"), None, &Arc::default())
            .unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    /// Bug sweep 2026-08-06 (M7): a crafted volume holding two
    /// fragments of one member would let the consumption watermark
    /// report the volume spent while the next fragment still needed to
    /// reopen it by path - after a volume-eating caller hard-deleted
    /// it. Split fragments must advance strictly by volume.
    #[test]
    fn same_volume_split_fragments_are_rejected() {
        let first = file(b"a.txt", FHD_SPLIT_AFTER);
        let second = file(b"a.txt", FHD_SPLIT_BEFORE);
        let mut pending = PendingSplitRefs::new(&first, 0, 0);
        assert!(
            matches!(
                pending.append(&second, 0, 1),
                Err(Error::InvalidHeader(_))
            ),
            "a second fragment inside the same volume must be refused"
        );
        assert!(
            matches!(
                pending.append(&second, 1, 0),
                Ok(())
            ),
            "the ordinary next-volume fragment must still be accepted"
        );
    }

    /// After a fragment CRC mismatch the incremental chain must keep
    /// erroring on every later read, exactly as `FragmentCrcReader`
    /// does: the mismatch surfaces with `at` unadvanced and the cursor
    /// dropped, so without the latch a caller that swallowed the io
    /// error would be handed the failed fragment's bytes all over
    /// again.
    #[test]
    fn growing_chain_keeps_erroring_after_a_fragment_crc_mismatch() {
        let data = *b"0123456";
        let mut first = file(b"a.txt", FHD_SPLIT_AFTER);
        first.pack_size = data.len() as u64;
        first.packed_range = 0..data.len();
        first.file_crc = !crate::crc32::crc32(&data);

        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_source(
            vec![Block::File(first.clone())],
            data.to_vec(),
        )];
        let mut next_volume = |_: usize| -> Result<Option<Archive>> {
            panic!("the mismatch must surface before another volume is pulled");
        };
        let consumed = |_: usize, _: u64| {};
        let mut chain =
            GrowingChainedReader::new(volumes, pending, &first, &mut next_volume, None, &consumed);

        let mut got = Vec::new();
        let mut buf = [0u8; 16];
        loop {
            match chain.read(&mut buf) {
                Ok(count) => {
                    assert_ne!(count, 0, "the mismatch must error, never read as clean EOF");
                    got.extend_from_slice(&buf[..count]);
                }
                Err(_) => break,
            }
        }
        assert_eq!(got, data);

        // The latch: a retried read errors again, never delivers bytes.
        chain.read(&mut buf).unwrap_err();
        assert!(matches!(
            chain.take_error(),
            Some(Error::SplitFragmentCrc32Mismatch { volume: 0, .. })
        ));
    }

    /// A consumer that stops asking exactly at a non-final fragment's
    /// boundary never issues the read that drains the cursor, so the
    /// packed CRC check used to be skipped entirely. `finish` runs it
    /// over the fully-read fragment.
    #[test]
    fn finish_checks_a_fragment_left_exactly_at_its_boundary() {
        let data = *b"0123456";
        for (crc, expect_mismatch) in [
            (crate::crc32::crc32(&data), false),
            (!crate::crc32::crc32(&data), true),
        ] {
            let mut first = file(b"a.txt", FHD_SPLIT_AFTER);
            first.pack_size = data.len() as u64;
            first.packed_range = 0..data.len();
            first.file_crc = crc;

            let pending = PendingSplitRefs::new(&first, 0, 0);
            let volumes = vec![archive_with_source(
                vec![Block::File(first.clone())],
                data.to_vec(),
            )];
            let mut next_volume = |_: usize| -> Result<Option<Archive>> {
                Ok(Some(archive_with(vec![Block::File(file(
                    b"a.txt",
                    FHD_SPLIT_BEFORE,
                ))])))
            };
            let consumed = |_: usize, _: u64| {};
            let mut chain = GrowingChainedReader::new(
                volumes,
                pending,
                &first,
                &mut next_volume,
                None,
                &consumed,
            );

            // Read EXACTLY the fragment's bytes, then stop asking.
            let mut buf = [0u8; 7];
            let mut got = 0;
            while got < buf.len() {
                got += chain.read(&mut buf[got..]).unwrap();
            }
            assert_eq!(&buf, &data);

            let result = chain.finish();
            if expect_mismatch {
                assert!(matches!(
                    result,
                    Err(Error::SplitFragmentCrc32Mismatch { volume: 0, .. })
                ));
            } else {
                let ((finish_volume, finish_file), _) = result.unwrap();
                assert_eq!((finish_volume, finish_file), (1, 0));
            }
        }
    }

    fn never_open(_meta: &ExtractedEntryMeta) -> Result<Box<dyn Write>> {
        panic!("open should not be invoked for this test");
    }

    #[test]
    fn extract_volumes_to_rejects_split_state_violations() {
        let empty: Vec<Archive> = Vec::new();
        assert!(matches!(
            extract_volumes_to(&empty, crate::ArchiveReadOptions::default(), never_open),
            Err(Error::InvalidHeader(_))
        ));

        let only_continuation = vec![archive_with(vec![Block::File(file(
            b"a.txt",
            FHD_SPLIT_BEFORE,
        ))])];
        assert!(matches!(
            extract_volumes_to(
                &only_continuation,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));

        let interrupted = vec![archive_with(vec![
            Block::File(file(b"a.txt", FHD_SPLIT_AFTER)),
            Block::File(file(b"unrelated", 0)),
        ])];
        assert!(matches!(
            extract_volumes_to(
                &interrupted,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));

        let incomplete = vec![archive_with(vec![Block::File(file(
            b"a.txt",
            FHD_SPLIT_AFTER,
        ))])];
        assert!(matches!(
            extract_volumes_to(
                &incomplete,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));
    }

    #[test]
    fn codec_state_new_for_chooses_codec_by_unpack_version() {
        let mut f = file(b"a", 0);
        f.unp_ver = 15;
        assert!(matches!(
            CodecState::new_for(&f).unwrap(),
            CodecState::Unpack15(_)
        ));
        f.unp_ver = 20;
        assert!(matches!(
            CodecState::new_for(&f).unwrap(),
            CodecState::Unpack20(_)
        ));
        f.unp_ver = 26;
        assert!(matches!(
            CodecState::new_for(&f).unwrap(),
            CodecState::Unpack20(_)
        ));
        f.unp_ver = 29;
        assert!(matches!(
            CodecState::new_for(&f).unwrap(),
            CodecState::Unpack29(_)
        ));
        f.unp_ver = 36;
        assert!(matches!(
            CodecState::new_for(&f).unwrap(),
            CodecState::Unpack29(_)
        ));
        f.unp_ver = 14;
        f.method = 0x35;
        assert!(matches!(
            CodecState::new_for(&f),
            Err(Error::UnsupportedCompression {
                unpack_version: 14,
                method: 0x35,
                ..
            })
        ));
    }

    #[test]
    fn codec_state_supports_matches_codec_to_file_version() {
        let mut f = file(b"a", 0);

        f.unp_ver = 15;
        let unpack15 = CodecState::new_for(&f).unwrap();
        assert!(unpack15.supports(&f));
        f.unp_ver = 20;
        assert!(!unpack15.supports(&f));
        f.unp_ver = 29;
        assert!(!unpack15.supports(&f));

        f.unp_ver = 20;
        let unpack20 = CodecState::new_for(&f).unwrap();
        assert!(unpack20.supports(&f));
        f.unp_ver = 26;
        assert!(unpack20.supports(&f));
        f.unp_ver = 15;
        assert!(!unpack20.supports(&f));
        f.unp_ver = 29;
        assert!(!unpack20.supports(&f));

        f.unp_ver = 29;
        let unpack29 = CodecState::new_for(&f).unwrap();
        assert!(unpack29.supports(&f));
        f.unp_ver = 36;
        assert!(unpack29.supports(&f));
        f.unp_ver = 20;
        assert!(!unpack29.supports(&f));
    }

    #[test]
    fn decoder_session_empty_compressed_payload_does_not_reset_solid_codec() {
        let mut session = DecoderSession::new(true);
        let mut first = file(b"first.txt", 0);
        first.unp_ver = 29;
        first.method = 0x35;
        session.codec = Some(CodecState::new_for(&first).unwrap());
        session.decoded_files = 4;

        let mut empty = file(b"empty.txt", super::super::FHD_SOLID);
        empty.unp_ver = 20;
        empty.method = 0x33;
        empty.file_crc = 0;
        let archive = Archive {
            sfx_offset: 0,
            main: MainHeader {
                head_crc: 0,
                flags: super::super::MHD_SOLID,
                head_size: 13,
                reserved1: 0,
                reserved2: 0,
                encrypt_version: None,
            },
            blocks: vec![Block::File(empty.clone())],
            source: ArchiveSource::Memory(Arc::from([])),
            pending_from: None,
        };

        let mut out = Vec::new();
        session.write_file_to(&archive, &empty, &mut out).unwrap();

        assert!(out.is_empty());
        assert_eq!(session.decoded_files, 4);
        assert!(matches!(session.codec, Some(CodecState::Unpack29(_))));
    }

    #[test]
    fn split_cipher_new_rejects_unsupported_unpack_version() {
        for ver in [14u8, 16, 19, 25, 27, 28] {
            assert!(
                matches!(
                    SplitCipher::new(ver, b"pw", None),
                    Err(Error::UnsupportedEncryption { unpack_version, .. }) if unpack_version == ver
                ),
                "unp_ver {ver} should be rejected"
            );
        }
    }

    #[test]
    fn decrypting_reader_new_rejects_unsupported_unpack_version() {
        let result = DecryptingReader::new(Cursor::new(Vec::<u8>::new()), 25, b"pw", None);
        assert!(matches!(
            result,
            Err(Error::UnsupportedEncryption {
                unpack_version: 25,
                ..
            })
        ));
    }

    #[test]
    fn decrypting_reader_rejects_non_block_aligned_rar20_payload() {
        let mut payload = vec![0u8; 23];
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut payload[..16])
            .unwrap();
        let mut reader = DecryptingReader::new(Cursor::new(payload), 20, b"pw", None).unwrap();
        let mut buf = [0u8; 64];
        let err = loop {
            match reader.read(&mut buf) {
                Ok(0) => panic!("expected non-block-aligned data error"),
                Ok(_) => continue,
                Err(err) => break err,
            }
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn decrypting_reader_reports_rar30_body_crypto_errors_without_header_context() {
        let error = super::map_rar30_crypto_error(Rar30Error::UnalignedInput);
        assert!(matches!(
            error,
            Error::Rar30Crypto(Rar30Error::UnalignedInput)
        ));
        assert_eq!(error.to_string(), "RAR 3.x AES input is not block aligned");

        let mapped =
            file(b"encrypted.bin", FHD_PASSWORD).map_encrypted_payload_error(Some(b"pw"), error);
        assert_eq!(mapped, Error::WrongPasswordOrCorruptData);
    }

    #[test]
    fn pending_split_refs_packed_size_rejects_missing_volume_or_file() {
        let f = file(b"a.txt", FHD_SPLIT_AFTER);
        let pending = PendingSplitRefs::new(&f, 9, 0);
        let no_volumes: Vec<Archive> = Vec::new();
        assert!(matches!(
            pending.packed_size(&no_volumes),
            Err(Error::InvalidHeader(_))
        ));

        let mut pending = PendingSplitRefs::new(&f, 0, 7);
        pending.fragments[0] = (0, 7);
        let one_volume = vec![archive_with(vec![Block::File(f)])];
        assert!(matches!(
            pending.packed_size(&one_volume),
            Err(Error::InvalidHeader(_))
        ));
    }

    #[test]
    fn pending_split_refs_fragment_reader_rejects_missing_volume_or_file() {
        let f = file(b"a.txt", FHD_SPLIT_AFTER);
        let pending = PendingSplitRefs::new(&f, 9, 0);
        let no_volumes: Vec<Archive> = Vec::new();
        assert!(matches!(
            pending.fragment_reader(&no_volumes, None, None, &Arc::default()),
            Err(Error::InvalidHeader(_))
        ));

        let mut pending = PendingSplitRefs::new(&f, 0, 7);
        pending.fragments[0] = (0, 7);
        let one_volume = vec![archive_with(vec![Block::File(f)])];
        assert!(matches!(
            pending.fragment_reader(&one_volume, None, None, &Arc::default()),
            Err(Error::InvalidHeader(_))
        ));
    }

    #[test]
    fn pending_split_refs_fragment_reader_demands_password_for_encrypted() {
        let mut first = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.packed_range = 0..0;
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_source(vec![Block::File(first)], Vec::new())];
        assert!(matches!(
            pending.fragment_reader(&volumes, None, None, &Arc::default()),
            Err(Error::NeedPassword)
        ));
    }

    #[test]
    fn pending_split_refs_fragment_reader_chains_unencrypted_volumes() {
        let plain: &[u8] = b"hello, this string is split across two volumes!";
        let split = 11usize;

        let mut first = file(b"a.txt", FHD_SPLIT_AFTER);
        first.pack_size = split as u64;
        first.packed_range = 0..split;
        // The non-final fragment's header CRC is the CRC of its own
        // PACKED bytes, and the chain verifies it.
        first.file_crc = crate::crc32::crc32(&plain[..split]);
        let mut second = file(b"a.txt", FHD_SPLIT_BEFORE);
        second.pack_size = (plain.len() - split) as u64;
        second.packed_range = 0..(plain.len() - split);

        let mut pending = PendingSplitRefs::new(&first, 0, 0);
        pending.append(&second, 1, 0).unwrap();
        let volumes = vec![
            archive_with_source(vec![Block::File(first)], plain[..split].to_vec()),
            archive_with_source(vec![Block::File(second)], plain[split..].to_vec()),
        ];

        let reader = pending
            .fragment_reader(&volumes, None, None, &Arc::default())
            .unwrap();
        let out = read_in_small_chunks(reader);
        assert_eq!(out, plain);
    }

    /// A middle fragment whose packed bytes do not hash to its own
    /// header CRC fails the chain at THAT fragment, and the typed error
    /// naming the volume is recoverable from the shared slot.
    #[test]
    fn pending_split_refs_fragment_reader_fails_a_fragment_with_a_wrong_packed_crc() {
        let plain: &[u8] = b"hello, this string is split across two volumes!";
        let split = 11usize;

        let mut first = file(b"a.txt", FHD_SPLIT_AFTER);
        first.pack_size = split as u64;
        first.packed_range = 0..split;
        first.file_crc = crate::crc32::crc32(&plain[..split]) ^ 0xdead_beef;
        let mut second = file(b"a.txt", FHD_SPLIT_BEFORE);
        second.pack_size = (plain.len() - split) as u64;
        second.packed_range = 0..(plain.len() - split);

        let mut pending = PendingSplitRefs::new(&first, 0, 0);
        pending.append(&second, 1, 0).unwrap();
        let volumes = vec![
            archive_with_source(vec![Block::File(first)], plain[..split].to_vec()),
            archive_with_source(vec![Block::File(second)], plain[split..].to_vec()),
        ];

        let slot: SharedFragmentError = Arc::default();
        let mut reader = pending.fragment_reader(&volumes, None, None, &slot).unwrap();
        let mut out = Vec::new();
        let error = reader.read_to_end(&mut out).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(out.len(), split, "the chain stops at the bad boundary");
        assert!(matches!(
            slot.lock().unwrap().take(),
            Some(Error::SplitFragmentCrc32Mismatch { volume: 0, .. })
        ));
        // Any read after the mismatch keeps failing - the chain must not
        // resume as if the fragment were sound.
        assert!(reader.read(&mut [0u8; 4]).is_err());
    }

    #[test]
    fn pending_split_refs_packed_size_sums_fragment_pack_sizes() {
        let mut first = file(b"a.txt", FHD_SPLIT_AFTER);
        first.pack_size = 7;
        let mut second = file(b"a.txt", FHD_SPLIT_BEFORE);
        second.pack_size = 5;

        let mut pending = PendingSplitRefs::new(&first, 0, 0);
        pending.append(&second, 1, 0).unwrap();
        let volumes = vec![
            archive_with(vec![Block::File(first)]),
            archive_with(vec![Block::File(second)]),
        ];
        assert_eq!(pending.packed_size(&volumes).unwrap(), 12);
    }

    #[derive(Default, Clone)]
    struct Capture {
        bytes: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        opened: std::rc::Rc<std::cell::RefCell<Vec<ExtractedEntryMeta>>>,
    }

    struct CaptureWriter(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    impl Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Capture {
        fn opener(&self) -> impl FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>> + '_ {
            let bytes = self.bytes.clone();
            let opened = self.opened.clone();
            move |meta| {
                opened.borrow_mut().push(meta.clone());
                Ok(Box::new(CaptureWriter(bytes.clone())))
            }
        }
    }

    #[test]
    fn extract_volumes_to_invokes_open_for_directory_entries() {
        let dir = file(b"d", FHD_DIRECTORY_MASK);
        let volumes = vec![archive_with(vec![Block::File(dir)])];

        let capture = Capture::default();
        extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            capture.opener(),
        )
        .unwrap();

        let opened = capture.opened.borrow();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].name, b"d");
        assert!(opened[0].is_directory);
        assert!(capture.bytes.borrow().is_empty());
    }

    #[test]
    fn extract_volumes_to_writes_stored_file_payload_and_verifies_crc() {
        let payload = b"hello stored payload!".to_vec();
        let mut entry = file(b"hello.txt", 0);
        entry.unp_ver = 20;
        entry.pack_size = payload.len() as u64;
        entry.unp_size = payload.len() as u64;
        entry.packed_range = 0..payload.len();
        entry.file_crc = super::super::crc32(&payload);

        let volumes = vec![archive_with_source(
            vec![Block::File(entry)],
            payload.clone(),
        )];

        let capture = Capture::default();
        extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            capture.opener(),
        )
        .unwrap();

        assert_eq!(capture.bytes.borrow().as_slice(), payload.as_slice());
        let opened = capture.opened.borrow();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].name, b"hello.txt");
        assert!(!opened[0].is_directory);
    }

    #[test]
    fn extract_volumes_to_reports_stored_crc_mismatch_with_entry_context() {
        let payload = b"crc mismatch payload".to_vec();
        let mut entry = file(b"bad.txt", 0);
        entry.unp_ver = 20;
        entry.pack_size = payload.len() as u64;
        entry.unp_size = payload.len() as u64;
        entry.packed_range = 0..payload.len();
        entry.file_crc = super::super::crc32(&payload).wrapping_add(1);

        let volumes = vec![archive_with_source(
            vec![Block::File(entry)],
            payload.clone(),
        )];

        let capture = Capture::default();
        let err = extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            capture.opener(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::AtEntry { .. }),
            "expected Error::AtEntry, got {err:?}"
        );
    }

    #[test]
    fn extract_volumes_to_writes_split_stored_file_across_volumes() {
        let payload = b"this stored payload spans two volumes".to_vec();
        let split = 13usize;

        let mut first = file(b"split.txt", FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = split as u64;
        first.unp_size = payload.len() as u64;
        first.packed_range = 0..split;
        // A non-final fragment carries the CRC of its OWN packed bytes;
        // only the final one carries the member's unpacked CRC.
        first.file_crc = super::super::crc32(&payload[..split]);

        let mut second = file(b"split.txt", FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = (payload.len() - split) as u64;
        second.unp_size = payload.len() as u64;
        second.packed_range = 0..(payload.len() - split);
        second.file_crc = super::super::crc32(&payload);

        let volumes = vec![
            archive_with_source(vec![Block::File(first)], payload[..split].to_vec()),
            archive_with_source(vec![Block::File(second)], payload[split..].to_vec()),
        ];

        let capture = Capture::default();
        extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            capture.opener(),
        )
        .unwrap();

        assert_eq!(capture.bytes.borrow().as_slice(), payload.as_slice());
        let opened = capture.opened.borrow();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].name, b"split.txt");
    }

    #[test]
    fn extract_volumes_to_rejects_split_stored_size_mismatch() {
        let payload = b"split stored mismatch".to_vec();
        let split = 10usize;
        let truncated = payload.len() - 3;

        let mut first = file(b"a.txt", FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = split as u64;
        first.unp_size = payload.len() as u64;
        first.packed_range = 0..split;

        let mut second = file(b"a.txt", FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = (truncated - split) as u64;
        second.unp_size = payload.len() as u64;
        second.packed_range = 0..(truncated - split);

        let volumes = vec![
            archive_with_source(vec![Block::File(first)], payload[..split].to_vec()),
            archive_with_source(
                vec![Block::File(second)],
                payload[split..truncated].to_vec(),
            ),
        ];

        let capture = Capture::default();
        let err = extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            capture.opener(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(_)),
            "expected Error::InvalidHeader, got {err:?}"
        );
    }

    #[test]
    fn decoder_session_codec_for_resets_when_unpack_version_changes() {
        let mut session = DecoderSession::new(true);
        let mut f = file(b"a", 0);
        f.unp_ver = 20;
        assert!(matches!(
            session.codec_for(&f).unwrap(),
            CodecState::Unpack20(_)
        ));
        let mut g = file(b"b", 0);
        g.unp_ver = 29;
        assert!(matches!(
            session.codec_for(&g).unwrap(),
            CodecState::Unpack29(_)
        ));
        let mut h = file(b"c", 0);
        h.unp_ver = 15;
        assert!(matches!(
            session.codec_for(&h).unwrap(),
            CodecState::Unpack15(_)
        ));
    }

    #[test]
    fn decoder_session_codec_for_propagates_unsupported_compression() {
        let mut session = DecoderSession::new(false);
        let mut f = file(b"a", 0);
        f.unp_ver = 14;
        assert!(matches!(
            session.codec_for(&f),
            Err(Error::UnsupportedCompression {
                unpack_version: 14,
                ..
            })
        ));
    }

    #[test]
    fn decoder_session_codec_for_reuses_codec_in_solid_mode() {
        let mut session = DecoderSession::new(true);
        let mut f = file(b"a", 0);
        f.unp_ver = 29;
        let first = session.codec_for(&f).unwrap() as *const CodecState;
        let second = session.codec_for(&f).unwrap() as *const CodecState;
        assert_eq!(first, second);
    }

    #[test]
    fn decoder_session_decode_file_data_dispatches_to_stored_path_for_each_codec_version() {
        let payload = b"decode_file_data stored dispatch".to_vec();
        let crc = super::super::crc32(&payload);
        for unp_ver in [15u8, 20, 26, 29] {
            let mut entry = file(b"a.txt", 0);
            entry.unp_ver = unp_ver;
            entry.pack_size = payload.len() as u64;
            entry.unp_size = payload.len() as u64;
            entry.packed_range = 0..payload.len();
            entry.file_crc = crc;

            let archive = archive_with_source(vec![Block::File(entry.clone())], payload.clone());
            let mut session = DecoderSession::new(false);
            let data = session
                .decode_file_data(&archive, &entry)
                .unwrap_or_else(|err| panic!("decode for unp_ver {unp_ver}: {err:?}"));
            assert_eq!(data, payload, "unp_ver {unp_ver} payload mismatch");
        }
    }

    #[test]
    fn decrypting_reader_works_through_boxed_inner_reader() {
        let plain = *b"0123456789abcdefRAR2 block two!!";
        let mut encrypted = plain;
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let inner: Box<dyn Read> = Box::new(Cursor::new(encrypted.to_vec()));
        let reader = DecryptingReader::new(inner, 20, b"pw", None).unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    #[test]
    fn decrypting_reader_boxed_inner_rejects_non_block_aligned_eof() {
        let mut payload = vec![0u8; 32];
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut payload[..16])
            .unwrap();
        // 23 bytes of trailing data (not a multiple of 16) — should error at EOF.
        payload.truncate(23);
        let inner: Box<dyn Read> = Box::new(Cursor::new(payload));
        let mut reader = DecryptingReader::new(inner, 20, b"pw", None).unwrap();
        let mut buf = [0u8; 64];
        let err = loop {
            match reader.read(&mut buf) {
                Ok(0) => panic!("expected non-block-aligned data error"),
                Ok(_) => continue,
                Err(err) => break err,
            }
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn extract_volumes_to_assembles_encrypted_stored_split_across_two_volumes() {
        let payload: &[u8] = b"twenty-byte payload!"; // exactly 20 bytes
        let unpacked_len = payload.len();
        assert_eq!(unpacked_len, 20);
        let padded_len = (unpacked_len + 15) & !15; // 32
        let mut encrypted = vec![0u8; padded_len];
        encrypted[..unpacked_len].copy_from_slice(payload);
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let split = 13usize;
        let crc = super::super::crc32(payload);

        let mut first = file(b"split.bin", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = split as u64;
        first.unp_size = unpacked_len as u64;
        first.packed_range = 0..split;
        // A non-final fragment carries the CRC of its OWN packed bytes -
        // the ciphertext for an encrypted member; only the final one
        // carries the member's unpacked CRC.
        first.file_crc = super::super::crc32(&encrypted[..split]);

        let mut second = file(b"split.bin", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = (padded_len - split) as u64;
        second.unp_size = unpacked_len as u64;
        second.packed_range = 0..(padded_len - split);
        second.file_crc = crc;

        let volumes = vec![
            archive_with_source(vec![Block::File(first)], encrypted[..split].to_vec()),
            archive_with_source(vec![Block::File(second)], encrypted[split..].to_vec()),
        ];

        let capture = Capture::default();
        extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::with_password(b"pw"),
            capture.opener(),
        )
        .unwrap();

        assert_eq!(capture.bytes.borrow().as_slice(), payload);
    }

    #[test]
    fn extract_volumes_to_rejects_encrypted_stored_split_when_padded_size_disagrees() {
        let unpacked_len = 20usize;
        // Two volumes total only 30 bytes, but expected_packed_len == 32.
        let payload = [0u8; 30];

        let mut first = file(b"split.bin", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = 13;
        first.unp_size = unpacked_len as u64;
        first.packed_range = 0..13;

        let mut second = file(b"split.bin", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = 17;
        second.unp_size = unpacked_len as u64;
        second.packed_range = 0..17;

        let volumes = vec![
            archive_with_source(vec![Block::File(first)], payload[..13].to_vec()),
            archive_with_source(vec![Block::File(second)], payload[13..].to_vec()),
        ];

        let capture = Capture::default();
        let err = extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::with_password(b"pw"),
            capture.opener(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("wrong reassembled size")),
            "expected wrong reassembled size error, got {err:?}"
        );
    }
}
