use super::{blake2sp, Archive, ExtractedEntryMeta, FileHeader, FileRedirection};
use crate::codec::rar50::{DecodeMode, DecodedChunk, StreamDecodeError, Unpack50Decoder};
use crate::crc32::{crc32, Crc32};
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys};
use crate::error::{Error, Result};
use crate::source::OwnedRangeReader;
use crate::volume_extract::{SplitVolumeState, SplitVolumeStep};
use std::io::{Read, Write};

// Filtered RAR5 members still need whole-member byte transforms. Members at or
// below this boundary use the buffered path, while larger members stream once
// and reject filtered streams through the codec's typed sentinel.
#[cfg(not(test))]
const BUFFERED_DECODE_LIMIT: u64 = 512 * 1024 * 1024;
#[cfg(test)]
const BUFFERED_DECODE_LIMIT: u64 = 1024;

// Default ceiling on the streaming match window. RAR 7 dictionaries reach far
// past what a typical host can allocate (up to 64 GiB), and the streaming ring
// grows toward the declared dictionary; 1 GiB covers every real-world preset up
// to `-md1g` while capping the pathological cases at a ~2 GiB ring. Callers
// override via `ArchiveReadOptions::rar50_max_window`.
const DEFAULT_STREAM_WINDOW_LIMIT: u64 = 1024 * 1024 * 1024;

/// AES-CBC block size. Encrypted stored data is padded up to this
/// boundary, so an encrypted stored member may supply up to one block
/// more ciphertext than its declared unpacked size.
///
/// The pad CONTENT is not specified by the format, and unrar never looks
/// at it - it reads unpacked_size bytes and discards the rest. So any
/// content rule we impose here is one real unrar does not, and issue #24
/// is what that cost: an archive this crate rejected on ~30% of its
/// volumes extracted cleanly under unrar and Total Commander.
///
/// Note the residue was NOT reproduced locally: RARLAB's own `rar` 7.x
/// zero-pads, so a fixture built with it passes either rule. What is
/// certain is the direction, because accepting arbitrary content is
/// exactly what unrar does.
///
/// The LENGTH is still bounded, and that is the check worth keeping: it
/// stops a header/payload disagreement hiding megabytes behind "it is
/// only padding". Ciphertext is block-aligned, so a genuine pad is
/// always shorter than one block.
const AES_BLOCK: u64 = 16;

impl FileHeader {
    fn crypto_with_password(&self, password: Option<&[u8]>) -> Result<Option<Rar50Keys>> {
        self.crypto_with_password_cached(password, &mut super::Rar50KeyCache::default())
    }

    /// Like [`Self::crypto_with_password`], but repeated (salt, kdf count)
    /// pairs derive once through `cache` - a solid chain or member walk
    /// over an archive parsed WITHOUT its password would otherwise pay the
    /// full PBKDF2 ladder per member. Per-member password checks still run.
    fn crypto_with_password_cached(
        &self,
        password: Option<&[u8]>,
        cache: &mut super::Rar50KeyCache,
    ) -> Result<Option<Rar50Keys>> {
        if !self.encrypted {
            return Ok(None);
        }
        if let Some(crypto) = &self.crypto {
            return Ok(Some(crypto.keys.clone()));
        }
        let password = password.ok_or(Error::NeedPassword)?;
        let encryption = self.encryption.as_ref().ok_or(Error::InvalidHeader(
            "RAR 5 encrypted file is missing encryption record",
        ))?;
        if encryption.version != 0 {
            return Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 unknown file encryption version",
            });
        }
        let keys = cache.get_or_derive(password, encryption.salt, encryption.kdf_count)?;
        if let Some(check_value) = encryption.check_value {
            keys.check_password(&check_value)
                .map_err(super::map_rar50_crypto_error)?;
        }
        Ok(Some(keys))
    }

    /// Packed reader from already-derived keys (or `None` for plaintext) -
    /// the chain pre-derives once per member set instead of once per open.
    #[cfg(feature = "parallel")]
    fn packed_reader_with_keys<'a>(
        &self,
        archive: &'a Archive,
        keys: Option<&Rar50Keys>,
        cache: &mut crate::source::RangeReaderCache,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        let reader = archive.range_reader_cached(self.block.data_range.clone(), cache)?;
        if !self.encrypted {
            return Ok(reader);
        }
        if !self.packed_size().is_multiple_of(16) {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted file payload is not block aligned",
            ));
        }
        let keys = keys.ok_or(Error::InvalidHeader(
            "RAR 5 encrypted file is missing encryption keys",
        ))?;
        Ok(Box::new(Rar50DecryptingReader::new(
            reader,
            keys.key,
            self.encryption_iv()?,
        )))
    }

    fn encryption_iv(&self) -> Result<[u8; 16]> {
        if let Some(crypto) = &self.crypto {
            return Ok(crypto.iv);
        }
        self.encryption
            .as_ref()
            .map(|encryption| encryption.iv)
            .ok_or(Error::InvalidHeader(
                "RAR 5 encrypted file is missing encryption record",
            ))
    }

    fn packed_data_with_password(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        cache: &mut crate::source::RangeReaderCache,
    ) -> Result<(Vec<u8>, Option<Rar50Keys>)> {
        let (mut reader, keys) = self.packed_reader_with_password(archive, password, cache)?;
        let mut packed = Vec::new();
        reader.read_to_end(&mut packed)?;
        Ok((packed, keys))
    }

    fn packed_reader_with_password<'a>(
        &self,
        archive: &'a Archive,
        password: Option<&[u8]>,
        cache: &mut crate::source::RangeReaderCache,
    ) -> Result<(Box<dyn Read + Send + 'a>, Option<Rar50Keys>)> {
        let (reader, cipher, keys) = self.packed_reader_parts(archive, password, cache)?;
        match cipher {
            Some(cipher) => Ok((
                Box::new(Rar50DecryptingReader::with_cipher(reader, cipher)),
                keys,
            )),
            None => Ok((reader, keys)),
        }
    }

    /// The packed-byte reader and, for an encrypted entry, the CBC cipher
    /// as SEPARATE parts, so a caller with its own pipeline (the stored
    /// pipe) can run the read and the decrypt on different threads.
    fn packed_reader_parts<'a>(
        &self,
        archive: &'a Archive,
        password: Option<&[u8]>,
        cache: &mut crate::source::RangeReaderCache,
    ) -> Result<(Box<dyn Read + Send + 'a>, Option<Rar50Cipher>, Option<Rar50Keys>)> {
        let reader = archive.range_reader_cached(self.block.data_range.clone(), cache)?;
        if !self.encrypted {
            return Ok((reader, None, None));
        }
        if !self.packed_size().is_multiple_of(16) {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted file payload is not block aligned",
            ));
        }
        let keys = self
            .crypto_with_password(password)?
            .ok_or(Error::InvalidHeader(
                "RAR 5 encrypted file is missing encryption keys",
            ))?;
        let cipher = Rar50Cipher::new(keys.key, self.encryption_iv()?);
        Ok((reader, Some(cipher), Some(keys)))
    }

    fn verify_integrity_with_keys(&self, data: &[u8], keys: Option<&Rar50Keys>) -> Result<()> {
        // When both digests are requested and the buffer is large, compute
        // them on two threads — they are independent passes over `data`.
        let wants_blake2 = matches!(&self.hash, Some(hash) if hash.hash_type == 0);
        let parallel_digests = if self.data_crc32.is_some() && wants_blake2 && data.len() >= 1 << 22
        {
            Some(std::thread::scope(|scope| {
                let crc_task = scope.spawn(|| crc32(data));
                let hash_value = blake2sp::hash(data);
                let crc_value = crc_task.join().expect("crc32 digest thread panicked");
                (crc_value, hash_value)
            }))
        } else {
            None
        };

        if let Some(expected) = self.data_crc32 {
            let actual = match parallel_digests {
                Some((crc_value, _)) => crc_value,
                None => crc32(data),
            };
            let actual = if self.uses_hash_mac() {
                let keys = keys.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted hash MAC needs encryption keys",
                ))?;
                keys.mac_crc32(actual)
            } else {
                actual
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }

        let Some(hash) = &self.hash else {
            return Ok(());
        };
        match hash.hash_type {
            0 if hash.data.len() == 32 => {
                let actual = match parallel_digests {
                    Some((_, hash_value)) => hash_value,
                    None => blake2sp::hash(data),
                };
                let actual = if self.uses_hash_mac() {
                    let keys = keys.ok_or(Error::InvalidHeader(
                        "RAR 5 encrypted hash MAC needs encryption keys",
                    ))?;
                    keys.mac_hash32(actual)
                } else {
                    actual
                };
                if constant_time_eq(&hash.data, &actual) {
                    Ok(())
                } else {
                    Err(Error::HashMismatch { hash_type: 0 })
                }
            }
            0 => Err(Error::InvalidHeader(
                "RAR 5 BLAKE2sp hash record has invalid length",
            )),
            _ => Ok(()),
        }
    }

    fn verify_streaming_integrity(
        &self,
        crc: Crc32,
        hash: Option<([u8; 32], blake2sp::Hasher)>,
        keys: Option<&Rar50Keys>,
    ) -> Result<()> {
        if let Some(expected) = self.data_crc32 {
            let actual = if self.uses_hash_mac() {
                let keys = keys.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted hash MAC needs encryption keys",
                ))?;
                keys.mac_crc32(crc.finish())
            } else {
                crc.finish()
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }

        if let Some((expected, hasher)) = hash {
            let actual = if self.uses_hash_mac() {
                let keys = keys.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted hash MAC needs encryption keys",
                ))?;
                keys.mac_hash32(hasher.finalize())
            } else {
                hasher.finalize()
            };
            if !constant_time_eq(&expected, &actual) {
                return Err(Error::HashMismatch { hash_type: 0 });
            }
        }
        Ok(())
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.mtime.unwrap_or(0),
            attr: self.attributes,
            host_os: self.host_os,
            is_directory: self.is_directory(),
            unpacked_size: self.unpacked_size,
        }
    }

    pub fn write_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        let mut session = DecoderSession::new_with_password(password, BUFFERED_DECODE_LIMIT, DEFAULT_STREAM_WINDOW_LIMIT);
        session.write_file_to(archive, self, out)
    }

    pub(crate) fn decoded_data_unverified(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut decoder = Unpack50Decoder::new();
        let mut reader_cache = crate::source::RangeReaderCache::default();
        Ok(self
            .decoded_data_with_decoder(archive, &mut decoder, password, &mut reader_cache)?
            .data)
    }

    /// `decoded_data_unverified` with a ceiling on the DECLARED output size.
    ///
    /// The buffered decode path sizes its output from `self.unpacked_size`,
    /// which is a header field the archive author chooses, and the unverified
    /// entry point above consults neither `buffered_decode_limit` nor the
    /// stream window limit that the ordinary extraction path applies. So a
    /// small, perfectly parseable archive carrying a highly compressible
    /// member that declares a huge unpacked size decodes until the allocation
    /// fails - and Rust answers that with abort.
    ///
    /// That matters for service records specifically: they are decoded
    /// automatically, before any content check, on a path a damaged download
    /// reaches by itself.
    pub(crate) fn decoded_data_unverified_bounded(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        limit: u64,
    ) -> Result<Vec<u8>> {
        // Both sides are checked: the declared output, AND the packed input
        // that gets buffered whole to produce it. Bounding only the output
        // leaves the input allocation unchecked.
        if self.unpacked_size > limit {
            return Err(Error::Rar50BufferedDecodeLimitExceeded {
                limit,
                required: self.unpacked_size,
            });
        }
        if self.packed_size() > limit {
            return Err(Error::Rar50BufferedDecodeLimitExceeded {
                limit,
                required: self.packed_size(),
            });
        }
        self.decoded_data_unverified(archive, password)
    }

    fn decoded_data_with_decoder(
        &self,
        archive: &Archive,
        decoder: &mut Unpack50Decoder,
        password: Option<&[u8]>,
        cache: &mut crate::source::RangeReaderCache,
    ) -> Result<DecodedData> {
        let (packed, keys) = self.packed_data_with_password(archive, password, cache)?;
        let data = self.decode_packed_with_decoder(&packed, decoder)?;
        Ok(DecodedData { data, keys })
    }

    fn decoded_data_with_mode(
        &self,
        archive: &Archive,
        decoder: &mut Unpack50Decoder,
        password: Option<&[u8]>,
        mode: DecodeMode,
        cache: &mut crate::source::RangeReaderCache,
    ) -> Result<DecodedData> {
        let (packed, keys) = self.packed_data_with_password(archive, password, cache)?;
        let data = self.decode_packed_with_decoder_mode(&packed, decoder, mode)?;
        Ok(DecodedData { data, keys })
    }

    fn decode_packed_with_decoder(
        &self,
        packed: &[u8],
        decoder: &mut Unpack50Decoder,
    ) -> Result<Vec<u8>> {
        self.decode_packed_with_decoder_mode(packed, decoder, DecodeMode::Lz)
    }

    fn decode_packed_with_decoder_mode(
        &self,
        packed: &[u8],
        decoder: &mut Unpack50Decoder,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            if self.encrypted {
                let unpacked_size = usize::try_from(self.unpacked_size).map_err(|_| {
                    Error::InvalidHeader("RAR 5 unpacked size overflows host address size")
                })?;
                if packed.len() < unpacked_size {
                    return Err(Error::InvalidHeader(
                        "RAR 5 encrypted stored file is shorter than unpacked size",
                    ));
                }
                // The tail past unpacked_size is AES padding. Its content is
                // arbitrary (see AES_BLOCK), so only its length is checked.
                if (packed.len() - unpacked_size) as u64 >= AES_BLOCK {
                    return Err(Error::InvalidHeader(
                        "RAR 5 encrypted stored file supplies more data than one block of padding",
                    ));
                }
                return Ok(packed[..unpacked_size].to_vec());
            }
            if packed.len() as u64 != self.unpacked_size {
                return Err(Error::InvalidHeader(
                    "RAR 5 stored file has mismatched packed and unpacked sizes",
                ));
            }
            return Ok(packed.to_vec());
        }
        if self.unpacked_size == 0 && packed.is_empty() {
            return Ok(Vec::new());
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let output_size = checked_unpacked_size(self.unpacked_size)?;
        match decoder.decode_member_with_dictionary(
            packed,
            info.algorithm_version,
            output_size,
            dictionary_size,
            info.solid,
            mode,
        ) {
            Ok(data) => Ok(data),
            Err(error) => self.map_truncated_unverified_payload(error),
        }
    }

    fn map_truncated_unverified_payload(&self, error: crate::codec::Error) -> Result<Vec<u8>> {
        if matches!(error, crate::codec::Error::NeedMoreInput)
            && self.data_crc32.is_none()
            && self.hash.is_none()
        {
            return Ok(Vec::new());
        }
        Err(Error::from(error))
    }

    fn stream_packed_with_decoder<R: Read + Send>(
        &self,
        packed: &mut R,
        keys: Option<&Rar50Keys>,
        decoder: &mut Unpack50Decoder,
        buffered_decode_limit: u64,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let hash = streaming_hash_verifier(self)?;
        let (crc, hash) =
            self.stream_packed_digests(packed, decoder, buffered_decode_limit, writer, hash)?;
        self.verify_streaming_integrity(crc, hash, keys)
    }

    /// [`Self::stream_packed_with_decoder`] stopping one step short: the
    /// digests come back instead of being checked here.
    ///
    /// A split member's EXPECTED digests live in its LAST fragment's header
    /// (every earlier fragment carries the digest of its own PACKED bytes
    /// instead - see [`FileHeader::split_fragment_packed_digests`] - and
    /// the rars writer leaves the earlier ones out entirely), and the
    /// incremental split path does not have that header until the decode
    /// has already run. So it drives the stream from the FIRST fragment's
    /// shape - name, dictionary and unpacked size all repeat across
    /// fragments - passes its own `hash` seed, and verifies against the
    /// last fragment afterwards.
    fn stream_packed_digests<R: Read + Send>(
        &self,
        packed: &mut R,
        decoder: &mut Unpack50Decoder,
        buffered_decode_limit: u64,
        writer: &mut dyn Write,
        hash: Option<([u8; 32], blake2sp::Hasher)>,
    ) -> Result<(Crc32, Option<([u8; 32], blake2sp::Hasher)>)> {
        if self.is_stored() {
            return Err(Error::InvalidHeader(
                "RAR 5 stored file does not use streaming compressed decode",
            ));
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let output_size = usize::try_from(self.unpacked_size)
            .map_err(|_| Error::InvalidHeader("RAR 5 unpacked size overflows host address size"))?;
        let crc = Crc32::new();

        // Pipeline: the decoder runs on a spawned thread and hands coalesced
        // ~1 MB buffers over a bounded channel; writing stays on the calling
        // thread (so `writer` needs no Send bound), and checksumming runs on
        // a third thread downstream of the writer. Splitting the digests off
        // the write loop matters on shapes where decode is cheap: CRC32 and
        // write() were each ~half of the writer thread's time on a highly
        // repetitive archive, and running them serially made the writer the
        // bottleneck while the decoder sat blocked on backpressure. A small
        // recycling pool bounds the extra memory and provides backpressure;
        // one extra buffer over the old three keeps the deeper pipeline from
        // starving now that the writer and digester can each hold one.
        const PIPE_BUF: usize = 1 << 20;
        const POOL_BUFFERS: usize = 4;
        enum PipeChunk {
            Data(Vec<u8>),
            Repeated { byte: u8, len: usize },
        }
        fn pipe_closed<T>(_: T) -> std::io::Error {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "extraction pipeline closed")
        }

        // nzbfast-local change (3 Sep 2026): charge this member's decode
        // working memory to `crate::memtrack` for as long as it runs, so
        // the product's memory-floor attribution can name the rars term
        // instead of leaving it in `unattributed` (audit round 14
        // residue 1; round 35 measured it at 105 MB of a 2,246 MB
        // compressed-RAR chase peak). Two terms, both from the same
        // inputs the codec allocates from:
        //   - the sliding flat plan, when this member is admitted to the
        //     flat path (`flat_plan_bytes`, a function of the dictionary
        //     - `buffered_decode_limit` is the caller's flat cap, and a
        //     plan over it means the bounded ring runs instead and
        //     allocates the retained window rather than a plan);
        //   - the pipe's buffer pool below, which is exact.
        // The tape workers' buffers are NOT here: they are allocated in
        // `codec/rar50.rs`, which this change may not touch. See
        // `memtrack`'s header for what that leaves out and why it is
        // small.
        let plan = crate::codec::rar50::flat_plan_bytes(0, output_size, dictionary_size) as u64;
        let _decode_charge = crate::memtrack::Charge::new(
            if plan <= buffered_decode_limit {
                plan
            } else {
                dictionary_size as u64
            }
            .saturating_add((POOL_BUFFERS * PIPE_BUF) as u64),
        );

        let (data_tx, data_rx) = std::sync::mpsc::sync_channel::<PipeChunk>(POOL_BUFFERS + 1);
        let (digest_tx, digest_rx) = std::sync::mpsc::channel::<PipeChunk>();
        let (pool_tx, pool_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        for _ in 0..POOL_BUFFERS {
            let _ = pool_tx.send(Vec::with_capacity(PIPE_BUF));
        }

        let mut write_error: Option<Error> = None;
        let decode_result = std::thread::scope(|scope| {
            let handle = scope.spawn(move || {
                let mut current = pool_rx
                    .recv()
                    .map_err(|error| StreamDecodeError::Sink(pipe_closed(error)))?;
                let result = decoder.decode_member_from_reader_with_dictionary_to_sink(
                    packed,
                    info.algorithm_version,
                    output_size,
                    dictionary_size,
                    info.solid,
                    buffered_decode_limit,
                    |chunk| -> std::io::Result<()> {
                        match chunk {
                            DecodedChunk::Bytes(mut bytes) => {
                                while !bytes.is_empty() {
                                    let take = (PIPE_BUF - current.len()).min(bytes.len());
                                    current.extend_from_slice(&bytes[..take]);
                                    bytes = &bytes[take..];
                                    if current.len() == PIPE_BUF {
                                        data_tx
                                            .send(PipeChunk::Data(std::mem::take(&mut current)))
                                            .map_err(pipe_closed)?;
                                        current = pool_rx.recv().map_err(pipe_closed)?;
                                    }
                                }
                                Ok(())
                            }
                            DecodedChunk::Repeated { byte, len } => {
                                if !current.is_empty() {
                                    data_tx
                                        .send(PipeChunk::Data(std::mem::take(&mut current)))
                                        .map_err(pipe_closed)?;
                                    current = pool_rx.recv().map_err(pipe_closed)?;
                                }
                                data_tx
                                    .send(PipeChunk::Repeated { byte, len })
                                    .map_err(pipe_closed)
                            }
                        }
                    },
                );
                if result.is_ok() && !current.is_empty() {
                    data_tx
                        .send(PipeChunk::Data(current))
                        .map_err(pipe_closed)
                        .map_err(StreamDecodeError::Sink)?;
                }
                result
            });

            // The digester runs downstream of the writer: every chunk the
            // writer accepted flows here in write order (a single FIFO
            // carries both data buffers and repeated-run markers), gets
            // hashed, and only then does its buffer return to the pool. The
            // channel is unbounded but its depth is bounded by the pool:
            // only POOL_BUFFERS data buffers exist.
            let digester = scope.spawn(move || {
                let mut crc = crc;
                let mut hash = hash;
                for chunk in digest_rx {
                    match chunk {
                        PipeChunk::Data(buffer) => {
                            crc.update(&buffer);
                            if let Some((_, hasher)) = &mut hash {
                                hasher.update(&buffer);
                            }
                            let mut buffer = buffer;
                            buffer.clear();
                            let _ = pool_tx.send(buffer);
                        }
                        PipeChunk::Repeated { byte, len } => {
                            digest_repeated_chunk(&mut crc, &mut hash, byte, len);
                        }
                    }
                }
                // The pool sender drops with the digester, which is what
                // unblocks a producer parked on `pool_rx.recv()` after an
                // error (see below).
                (crc, hash)
            });

            for chunk in data_rx {
                let outcome = match chunk {
                    PipeChunk::Data(buffer) => {
                        let outcome = writer.write_all(&buffer);
                        if outcome.is_ok() {
                            let _ = digest_tx.send(PipeChunk::Data(buffer));
                        }
                        outcome
                    }
                    PipeChunk::Repeated { byte, len } => {
                        let outcome = write_repeated_bytes(writer, byte, len);
                        if outcome.is_ok() {
                            let _ = digest_tx.send(PipeChunk::Repeated { byte, len });
                        }
                        outcome
                    }
                };
                if let Err(error) = outcome {
                    write_error = Some(Error::from(error));
                    break;
                }
            }
            // Receiver is dropped here (loop finished or broke), which
            // unblocks a producer stuck on send; it then errors out and
            // the join below collects it.
            //
            // Dropping the data receiver is NOT sufficient on its own: the
            // producer can equally be parked on `pool_rx.recv()` with the
            // pool drained, and nothing above wakes that. The `Repeated`
            // arm holds no pooled buffer, so it recycles nothing - a
            // `Repeated` chunk plus POOL_BUFFERS queued `Data` buffers
            // exactly fills this channel and empties the pool, and if
            // the repeated write then fails (the bomb guard tripping,
            // ENOSPC, EPIPE) the break below would join a producer that can
            // never return. The pool sender now lives in the digester, so
            // dropping the digest sender ends the digester, whose exit drops
            // the pool sender and fails that recv.
            drop(digest_tx);
            let digests = digester.join().expect("streaming digest thread panicked");
            let decode = handle.join().expect("streaming decode thread panicked");
            (decode, digests)
        });
        let (decode_result, (crc, hash)) = decode_result;

        if let Some(error) = write_error {
            return Err(error);
        }
        decode_result.map_err(|error| match error {
            StreamDecodeError::Decode(crate::codec::Error::WindowLimitExceeded {
                limit,
                required,
            }) => Error::Rar50WindowLimitExceeded { limit, required },
            StreamDecodeError::Decode(error) => Error::from(error),
            StreamDecodeError::FilteredMember => Error::Rar50BufferedDecodeLimitExceeded {
                limit: buffered_decode_limit,
                required: self.unpacked_size,
            },
            StreamDecodeError::Sink(error) => Error::from(error),
        })?;
        Ok((crc, hash))
    }

    fn write_stored_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        reader_cache: &mut crate::source::RangeReaderCache,
        writer: &mut dyn Write,
    ) -> Result<()> {
        // A tiny plaintext range is already contiguous: in-memory archives
        // can lend their backing slice, and file archives can lend the
        // retained read-ahead window. Avoid a boxed reader plus a freshly
        // allocated/zeroed inline buffer and the extra copy through it.
        // (nzbfast-local change, 3 Sep 2026 - re-apply on the next rars
        // re-sync; see vendor/rars/VENDORING.md.)
        if !self.encrypted {
            let view = archive
                .small_range_view_cached(self.block.data_range.clone(), reader_cache)
                .map_err(|error| self.entry_error("decoding", error))?;
            if let Some(view) = view {
                let data = view.as_slice();
                let mut crc = Crc32::new();
                let mut hash = streaming_hash_verifier(self)
                    .map_err(|error| self.entry_error("decoding", error))?;
                let mut written = 0u64;
                let mut discarded = 0u64;
                // Match the inline reader's observable chunking on malformed
                // headers too. For packed data longer than the declared
                // output, that reader first writes/hashes the declared-size
                // prefix and rejects the extra bytes on its next read.
                let capacity = usize::try_from(self.unpacked_size)
                    .unwrap_or(STORED_INLINE_BUF)
                    .clamp(1, STORED_INLINE_BUF);
                for chunk in data.chunks(capacity) {
                    let content_len = self
                        .consume_stored_chunk(
                            chunk,
                            &mut written,
                            &mut discarded,
                            writer,
                        )
                        .map_err(|(operation, error)| self.entry_error(operation, error))?;
                    let content = &chunk[..content_len];
                    crc.update(content);
                    if let Some((_, hasher)) = &mut hash {
                        hasher.update(content);
                    }
                }
                if written != self.unpacked_size {
                    return Err(self.entry_error(
                        "decoding",
                        Error::InvalidHeader(
                            "RAR 5 stored file has mismatched packed and unpacked sizes",
                        ),
                    ));
                }
                return self
                    .verify_streaming_integrity(crc, hash, None)
                    .map_err(|error| self.entry_error("verifying", error));
            }
        }

        let (mut reader, cipher, keys) = self
            .packed_reader_parts(archive, password, reader_cache)
            .map_err(|error| self.entry_error("decoding", error))?;
        let crc = Crc32::new();
        let hash =
            streaming_hash_verifier(self).map_err(|error| self.entry_error("decoding", error))?;
        let mut written = 0u64;
        let mut discarded = 0u64;

        let (crc, hash) = match pipe_stored_chunks(
            &mut *reader,
            cipher,
            self.unpacked_size,
            |error| ("decoding", Error::from(error)),
            crc,
            hash,
            |buf| self.consume_stored_chunk(buf, &mut written, &mut discarded, writer),
        ) {
            Ok(digests) => digests,
            Err((operation, error)) => return Err(self.entry_error(operation, error)),
        };

        if written != self.unpacked_size {
            return Err(self.entry_error(
                "decoding",
                Error::InvalidHeader("RAR 5 stored file has mismatched packed and unpacked sizes"),
            ));
        }
        self.verify_streaming_integrity(crc, hash, keys.as_ref())
            .map_err(|error| self.entry_error("verifying", error))
    }

    /// Padding check and write for one stored-file chunk; the digest
    /// stage downstream checksums the accepted content. Returns how many
    /// leading bytes are file content (an encrypted stored tail past
    /// unpacked_size is AES padding, counted in `discarded` and not
    /// digested), or the failing operation label alongside the error.
    fn consume_stored_chunk(
        &self,
        buf: &[u8],
        written: &mut u64,
        discarded: &mut u64,
        writer: &mut dyn Write,
    ) -> std::result::Result<usize, (&'static str, Error)> {
        let remaining =
            usize::try_from(self.unpacked_size.saturating_sub(*written)).unwrap_or(usize::MAX);
        let chunk_len = buf.len().min(remaining);
        let chunk = &buf[..chunk_len];
        if self.encrypted {
            // Encrypted stored data is padded up to the AES block, so a tail
            // past unpacked_size is expected. Its content is arbitrary (see
            // AES_BLOCK); only the total length is bounded, and it is summed
            // across chunks because a whole chunk can land past the end.
            *discarded = discarded.saturating_add((buf.len() - chunk_len) as u64);
            if *discarded >= AES_BLOCK {
                return Err((
                    "decoding",
                    Error::InvalidHeader(
                        "RAR 5 encrypted stored file supplies more data than one block of padding",
                    ),
                ));
            }
        } else if buf.len() > remaining {
            // Unencrypted stored data has no padding, so extra bytes mean the
            // headers disagree with the payload. Rejecting here restores a
            // check that clamping silently removed: the split path used to
            // write the whole buffer, overshoot `written`, and get caught by
            // the `written != unpacked_size` comparison afterwards. Once the
            // clamp applied to both branches, `written` could never exceed
            // unpacked_size, so that comparison could only ever catch SHORT
            // data and an over-supplying entry extracted truncated and
            // reported success - silently, when the archive carries neither a
            // data_crc32 nor a BLAKE2sp record, both of which are optional.
            return Err((
                "decoding",
                Error::InvalidHeader(
                    "RAR 5 stored file supplies more data than its unpacked size",
                ),
            ));
        }
        *written = written
            .checked_add(chunk.len() as u64)
            .ok_or(Error::InvalidHeader("RAR 5 stored size overflows"))
            .map_err(|error| ("decoding", error))?;
        writer
            .write_all(chunk)
            .map_err(Error::from)
            .map_err(|error| ("writing", error))?;
        Ok(chunk_len)
    }

    fn entry_error(&self, operation: &'static str, error: Error) -> Error {
        error.at_entry(self.name.clone(), operation)
    }

    /// Whether this header carries a digest over the WHOLE member that
    /// [`Self::verify_streaming_integrity`] will actually check. An
    /// unknown hash type is ignored there, so it does not count here
    /// either - and a member with nothing to check must keep the
    /// per-fragment digests, which are then its only integrity check.
    fn has_whole_member_digest(&self) -> bool {
        self.data_crc32.is_some()
            || self
                .hash
                .as_ref()
                .is_some_and(|hash| hash.hash_type == 0 && hash.data.len() == 32)
    }
}

/// Bounded stored-data pipeline: a scoped producer thread reads (and
/// decrypts) into pooled buffers, `consume` runs each chunk's padding
/// check and write on the calling thread - the writer is a borrowed
/// `dyn Write` and must stay there - and a scoped digest thread
/// downstream of the writer checksums the accepted bytes and recycles
/// the buffers. `consume` returns how many leading bytes are file
/// content (the encrypted stored path can carry AES padding past it);
/// only those are digested. Splitting the digests off the write loop is
/// the same fix the compressed streaming path got: a stored extraction
/// is a straight copy, and CRC32 serial with write() made one thread
/// the whole leg. The data channel holds one slot more than the pool
/// has buffers, so a producer send can never block on a full channel;
/// when the consumer stops early, dropping the digest sender ends the
/// digester, whose exit drops the pool sender and wakes a producer
/// parked on the drained pool.
const STORED_PIPE_BUF: usize = 1 << 20;
const STORED_POOL: usize = 4;
// Below this size, allocating four 1 MiB buffers and creating a reader plus
// digest thread costs substantially more than the copy and integrity work.
// Keep tiny STORE members on the caller: this path is especially important
// for software/source archives with thousands of small independent files.
const STORED_INLINE_MAX: u64 = 256 * 1024;
const STORED_INLINE_BUF: usize = 64 * 1024;

fn pipe_stored_chunks<E>(
    reader: &mut (dyn Read + Send),
    cipher: Option<Rar50Cipher>,
    size_hint: u64,
    read_error: impl Fn(std::io::Error) -> E,
    crc: Crc32,
    hash: Option<([u8; 32], blake2sp::Hasher)>,
    mut consume: impl FnMut(&[u8]) -> std::result::Result<usize, E>,
) -> std::result::Result<(Crc32, Option<([u8; 32], blake2sp::Hasher)>), E> {
    if size_hint <= STORED_INLINE_MAX {
        let capacity = usize::try_from(size_hint)
            .unwrap_or(STORED_INLINE_BUF)
            .clamp(1, STORED_INLINE_BUF);
        // A whole number of AES blocks per read when a cipher rides along.
        let capacity = if cipher.is_some() { capacity.max(16) & !15 } else { capacity };
        let mut buf = vec![0u8; capacity];
        let mut crc = crc;
        let mut hash = hash;
        let mut cipher = cipher;
        loop {
            let count = match &mut cipher {
                Some(cipher) => {
                    let count = fill_ciphertext(reader, &mut buf).map_err(&read_error)?;
                    decrypt_slice(cipher, &mut buf[..count]).map_err(&read_error)?;
                    count
                }
                None => reader.read(&mut buf).map_err(&read_error)?,
            };
            if count == 0 {
                return Ok((crc, hash));
            }
            let chunk = &buf[..count];
            let content_len = consume(chunk)?;
            let content = &chunk[..content_len];
            crc.update(content);
            if let Some((_, hasher)) = &mut hash {
                hasher.update(content);
            }
        }
    }

    // A pooled buffer keeps its full `STORED_PIPE_BUF` length for its whole
    // life and the fill level rides beside it, so recycling one costs
    // nothing. It used to be truncated to the read count, cleared on the way
    // back to the pool, and grown again with `resize(STORED_PIPE_BUF, 0)`
    // before the next read - which memset the whole 1 MiB on EVERY round
    // trip, not just after a short read, for bytes `read` was about to
    // overwrite. (nzbfast-local change, 22 Aug 2026 - re-apply on the next
    // rars re-sync, see vendor/rars/VENDORING.md.)
    //
    // Stages, each on its own thread: producer (read, plus the fragment
    // digests inside a chained reader) -> [decrypt, encrypted entries only]
    // -> this thread (consume: the write) -> digester (CRC32 / BLAKE2sp),
    // which recycles the buffer. Until 2 Sep 2026 the decrypt ran INSIDE
    // the producer's read, in series with the syscall: an encrypted RAR5
    // store set read 0.25 s per GiB on an M1 Ultra against 0.15 s for the
    // same set unencrypted, and 0.52 against 0.30 on an i5-10600KF
    // (research/RAR-PERF-AUDIT-2026-09-02.md, round 3). The buffers come
    // from a thread-local pool that outlives the member, so a set of many
    // small members stops paying four fresh 1 MiB allocations (and their
    // page faults) per member.
    let (data_tx, data_rx) =
        std::sync::mpsc::sync_channel::<std::io::Result<(Vec<u8>, usize)>>(STORED_POOL + 1);
    let (digest_tx, digest_rx) = std::sync::mpsc::channel::<(Vec<u8>, usize)>();
    let (pool_tx, pool_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut pooled = take_stored_buffers();
    for buf in pooled.drain(..) {
        let _ = pool_tx.send(buf);
    }

    let mut outcome = Ok(());
    let (digests, reclaimed) = std::thread::scope(|scope| {
        let encrypted = cipher.is_some();
        let producer = scope.spawn(move || {
            loop {
                let Ok(mut buf) = pool_rx.recv() else {
                    break;
                };
                debug_assert_eq!(buf.len(), STORED_PIPE_BUF);
                let read = if encrypted {
                    // Whole buffers, so every chunk the decrypt stage sees
                    // is block-aligned except a truncated tail, which
                    // `fill_ciphertext` reports as the error it is.
                    fill_ciphertext(reader, &mut buf)
                } else {
                    reader.read(&mut buf)
                };
                match read {
                    Ok(0) => {
                        // Hand the untouched buffer straight back; the
                        // drain below collects it with the rest.
                        let _ = data_tx.send(Ok((buf, 0)));
                        break;
                    }
                    Ok(count) => {
                        if data_tx.send(Ok((buf, count))).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = data_tx.send(Err(error));
                        break;
                    }
                }
            }
            // Closing the data channel is what ends the downstream stages;
            // once the digester has recycled its last buffer the pool
            // sender drops and this drain ends with every surviving
            // buffer, which goes back to the thread-local pool.
            drop(data_tx);
            pool_rx.iter().collect::<Vec<Vec<u8>>>()
        });

        // The decrypt stage sits between producer and consumer only for an
        // encrypted entry; a plain one hands the producer's receiver
        // straight through, so it costs nothing where it does nothing.
        let consume_rx = match cipher {
            Some(mut cipher) => {
                let (dec_tx, dec_rx) = std::sync::mpsc::sync_channel::<
                    std::io::Result<(Vec<u8>, usize)>,
                >(STORED_POOL + 1);
                scope.spawn(move || {
                    for received in data_rx {
                        let forwarded = match received {
                            Ok((mut buf, count)) => {
                                decrypt_slice(&mut cipher, &mut buf[..count]).map(|()| (buf, count))
                            }
                            Err(error) => Err(error),
                        };
                        let stop = forwarded.is_err();
                        if dec_tx.send(forwarded).is_err() || stop {
                            return;
                        }
                    }
                });
                dec_rx
            }
            None => data_rx,
        };

        let digester = scope.spawn(move || {
            let mut crc = crc;
            let mut hash = hash;
            for (buf, content_len) in digest_rx {
                let chunk = &buf[..content_len];
                crc.update(chunk);
                if let Some((_, hasher)) = &mut hash {
                    hasher.update(chunk);
                }
                let _ = pool_tx.send(buf);
            }
            // The pool sender drops with the digester, which is what wakes
            // a producer parked on the drained pool after an early stop.
            (crc, hash)
        });

        for received in consume_rx {
            let (buf, count) = match received {
                Ok((buf, 0)) => {
                    let _ = digest_tx.send((buf, 0));
                    continue;
                }
                Ok(chunk) => chunk,
                Err(error) => {
                    outcome = Err(read_error(error));
                    break;
                }
            };
            match consume(&buf[..count]) {
                Ok(content_len) => {
                    // `consume` reports how many LEADING bytes of the chunk
                    // are file content, so it can never exceed the fill
                    // level. That used to fall out of the truncate; the
                    // pooled buffer now stays longer than the fill level, so
                    // the bound is stated here instead.
                    debug_assert!(content_len <= count);
                    let _ = digest_tx.send((buf, content_len.min(count)));
                }
                Err(error) => {
                    outcome = Err(error);
                    break;
                }
            }
        }
        // Consumption has stopped (EOF, read error, or consume error) and
        // the data receiver is gone, which unblocks a producer stuck on
        // send. A producer parked on `pool_rx.recv()` with the pool
        // drained needs more: dropping the digest sender ends the
        // digester, whose exit drops the pool sender and fails that recv.
        drop(digest_tx);
        let digests = digester.join().expect("stored digest thread panicked");
        let reclaimed = producer.join().expect("stored producer thread panicked");
        (digests, reclaimed)
    });
    // Whatever buffers survived go back to the thread-local pool for the
    // next member; ones lost to an early stop are simply reallocated.
    STORED_BUFFERS.with(|cell| *cell.borrow_mut() = reclaimed);
    outcome.map(|()| digests)
}

thread_local! {
    /// The stored pipe's buffers, kept between members on the thread that
    /// runs the pipe (the extraction walk is one thread per set).
    static STORED_BUFFERS: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// `STORED_POOL` buffers of `STORED_PIPE_BUF` bytes: reused from the
/// thread-local pool where it has them, freshly zeroed otherwise.
fn take_stored_buffers() -> Vec<Vec<u8>> {
    let mut bufs = STORED_BUFFERS.with(|cell| std::mem::take(&mut *cell.borrow_mut()));
    bufs.retain(|buf| buf.len() == STORED_PIPE_BUF);
    while bufs.len() < STORED_POOL {
        bufs.push(vec![0u8; STORED_PIPE_BUF]);
    }
    bufs.truncate(STORED_POOL);
    bufs
}

struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    written: u64,
}

impl Write for CountingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(buf)?;
        self.written += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn is_streaming_filter_bail(error: &Error) -> bool {
    match error {
        Error::Rar50BufferedDecodeLimitExceeded { .. } => true,
        Error::AtEntry { source, .. } => is_streaming_filter_bail(source),
        _ => false,
    }
}

fn write_repeated_bytes(writer: &mut dyn Write, byte: u8, mut len: usize) -> std::io::Result<()> {
    let buffer = [byte; 64 * 1024];
    while len > 0 {
        let take = len.min(buffer.len());
        writer.write_all(&buffer[..take])?;
        len -= take;
    }
    Ok(())
}

fn digest_repeated_chunk(
    crc: &mut Crc32,
    hash: &mut Option<([u8; 32], blake2sp::Hasher)>,
    byte: u8,
    len: usize,
) {
    if byte == 0 && hash.is_none() {
        crc.update_zeroes(len as u64);
        return;
    }
    let buffer = [byte; 64 * 1024];
    let mut len = len;
    while len > 0 {
        let take = len.min(buffer.len());
        let chunk = &buffer[..take];
        if byte == 0 {
            crc.update_zeroes(take as u64);
        } else {
            crc.update(chunk);
        }
        if let Some((_, hasher)) = hash.as_mut() {
            hasher.update(chunk);
        }
        len -= take;
    }
}

fn write_repeated_chunk(
    writer: &mut dyn Write,
    crc: &mut Crc32,
    hash: &mut Option<([u8; 32], blake2sp::Hasher)>,
    byte: u8,
    len: usize,
) -> std::io::Result<()> {
    write_repeated_bytes(writer, byte, len)?;
    digest_repeated_chunk(crc, hash, byte, len);
    Ok(())
}

impl Archive {
    pub fn extract_to<F>(&self, options: crate::ArchiveReadOptions<'_>, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_to_impl(options, &mut open, &mut |_, _| Ok(()), false)
    }

    pub fn extract_to_with_redirections<F, R>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        mut open: F,
        mut redirect: R,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
        R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
    {
        self.extract_to_impl(options, &mut open, &mut redirect, true)
    }

    fn extract_to_impl<F, R>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        open: &mut F,
        redirect: &mut R,
        emit_redirections: bool,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
        R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
    {
        // Single archives get the same member pool as volume sets (they were
        // the one entry point with no cross-member parallelism at all). The
        // split guard preserves this method's distinct error for split
        // members, which the volume walk would report differently.
        #[cfg(feature = "parallel")]
        if !self
            .files()
            .any(|file| file.is_split_before() || file.is_split_after())
        {
            if let Some(plan) = member_pool_plan(std::slice::from_ref(self), options) {
                return extract_volumes_pooled(
                    std::slice::from_ref(self),
                    options,
                    open,
                    redirect,
                    emit_redirections,
                    plan,
                );
            }
        }

        let buffered_decode_limit = rar50_buffered_decode_limit(options);
        let mut session = DecoderSession::new_with_password(
            options.password,
            buffered_decode_limit,
            rar50_max_window(options),
        )
        .with_policy(rar50_execution_policy(options));
        for file in self.files() {
            if let Some(redirection) = &file.redirection {
                if emit_redirections {
                    redirect(&file.metadata(), redirection)?;
                }
                continue;
            }
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry requires multivolume extraction",
                ));
            }
            let meta = file.metadata();
            let mut writer = open(&meta)?;
            if !meta.is_directory {
                session.write_file_to(self, file, &mut writer)?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "parallel")]
    pub fn extract_to_parallel_buffered<F>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        mut open: F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        if self.main.is_solid()
            || self.files().any(|file| {
                file.is_split_before()
                    || file.is_split_after()
                    || file.should_stream_decode(rar50_buffered_decode_limit(options))
                    || file.decoded_compression_info().is_ok_and(|info| info.solid)
            })
        {
            return self.extract_to(options, open);
        }

        let password = options.password;
        let buffered_decode_limit = rar50_buffered_decode_limit(options);
        let files: Vec<_> = self.files().collect();
        if files.len() < 2 {
            return self.extract_to(options, open);
        }
        let entries = crate::parallel::map_collect(files, |file| {
            decode_parallel_entry(self, file, password, buffered_decode_limit)
        })?;
        for entry in entries {
            write_parallel_entry(entry, &mut open, &mut |_, _| Ok(()))?;
        }
        Ok(())
    }
}

#[cfg(feature = "parallel")]
enum ParallelExtractedEntry {
    Directory(ExtractedEntryMeta),
    File {
        meta: ExtractedEntryMeta,
        data: Vec<u8>,
    },
    Redirection {
        meta: ExtractedEntryMeta,
        redirection: FileRedirection,
    },
}

#[cfg(feature = "parallel")]
fn decode_parallel_entry(
    archive: &Archive,
    file: &FileHeader,
    password: Option<&[u8]>,
    buffered_decode_limit: u64,
) -> Result<ParallelExtractedEntry> {
    if let Some(redirection) = &file.redirection {
        return Ok(ParallelExtractedEntry::Redirection {
            meta: file.metadata(),
            redirection: redirection.clone(),
        });
    }
    if file.is_split_before() || file.is_split_after() {
        return Err(Error::InvalidHeader(
            "RAR 5 split entry requires multivolume extraction",
        ));
    }
    let meta = file.metadata();
    if meta.is_directory {
        return Ok(ParallelExtractedEntry::Directory(meta));
    }
    let mut data = Vec::new();
    let mut session = DecoderSession::new_with_password(password, buffered_decode_limit, DEFAULT_STREAM_WINDOW_LIMIT);
    session.write_file_to(archive, file, &mut data)?;
    Ok(ParallelExtractedEntry::File { meta, data })
}

#[cfg(feature = "parallel")]
fn write_parallel_entry<F, R>(
    entry: ParallelExtractedEntry,
    open: &mut F,
    redirect: &mut R,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    match entry {
        ParallelExtractedEntry::Directory(meta) => {
            let _ = open(&meta)?;
        }
        ParallelExtractedEntry::File { meta, data } => {
            let mut writer = open(&meta)?;
            writer.write_all(&data)?;
        }
        ParallelExtractedEntry::Redirection { meta, redirection } => {
            redirect(&meta, &redirection)?;
        }
    }
    Ok(())
}

struct DecodedData {
    data: Vec<u8>,
    keys: Option<Rar50Keys>,
}

struct DecoderSession<'a> {
    decoder: Unpack50Decoder,
    reader_cache: crate::source::RangeReaderCache,
    password: Option<&'a [u8]>,
    buffered_decode_limit: u64,
    policy: Option<crate::Rar50ExecutionPolicy>,
    /// Whether a stored split member may leave its per-fragment packed
    /// digests to a second pass - see [`crate::Rar50SplitFragmentDigests`].
    /// Only the whole-set walks set it; every other session defaults to
    /// checking as it reads, which is what every caller did before.
    split_fragment_digests: crate::Rar50SplitFragmentDigests,
    /// Retained so a RESET decoder gets the caller's window limit back.
    /// `Unpack50Decoder::new()` defaults it to `usize::MAX`, so replacing the
    /// session's decoder with a bare one silently dropped the safety limit
    /// for that member and every member after it.
    max_window: u64,
}

/// Fixed part of a flat plan's peak beyond output + retained dictionary:
/// pipe scratch (~4 MiB), in-flight tapes, and headroom. Deliberately
/// generous - admission failing just means the bounded ring runs instead.
const FLAT_OVERHEAD_ESTIMATE: u64 = 24 << 20;

/// Whether a flat allocation of `output` bytes (retaining up to `dictionary`
/// of window afterwards) fits the policy's working-memory allowance.
fn flat_admitted(output: u64, dictionary: u64, policy: &crate::Rar50ExecutionPolicy) -> bool {
    // The plan slides (codec `flat_plan_bytes`), so what it allocates is a
    // function of the dictionary, not the member; `usize::MAX` stands in
    // for a window limit the session does not know here (the codec clamps
    // the real one, which only makes the plan smaller).
    let plan = crate::codec::rar50::flat_plan_bytes(
        0,
        usize::try_from(output).unwrap_or(usize::MAX),
        usize::try_from(dictionary).unwrap_or(usize::MAX),
    ) as u64;
    plan.saturating_add(dictionary)
        .saturating_add(FLAT_OVERHEAD_ESTIMATE)
        <= policy.working_memory_limit
}

impl<'a> DecoderSession<'a> {
    fn new_with_password(
        password: Option<&'a [u8]>,
        buffered_decode_limit: u64,
        max_window: u64,
    ) -> Self {
        let mut decoder = Unpack50Decoder::new();
        decoder.set_window_limit(usize::try_from(max_window).unwrap_or(usize::MAX));
        Self {
            decoder,
            reader_cache: crate::source::RangeReaderCache::default(),
            password,
            buffered_decode_limit,
            policy: None,
            split_fragment_digests: crate::Rar50SplitFragmentDigests::default(),
            max_window,
        }
    }

    fn with_split_fragment_digests(
        mut self,
        digests: crate::Rar50SplitFragmentDigests,
    ) -> Self {
        self.split_fragment_digests = digests;
        self
    }

    /// A fresh decoder carrying this session's policy - window limit and
    /// worker cap both reapplied.
    ///
    /// Every reset inside the session goes through here. A bare
    /// `Unpack50Decoder::new()` defaults `window_limit` and `mt_workers_cap`
    /// to `usize::MAX`, so the two reset paths (the zero-output
    /// streaming-filter fallback on a split member, and the LzNoFilters
    /// retry with no checkpoint to restore) handed the rest of the archive a
    /// decoder that answers to no caller-supplied resource limit at all - a
    /// match beyond the configured window stopped being rejected.
    fn fresh_decoder(&self) -> Unpack50Decoder {
        let mut decoder = Unpack50Decoder::new();
        decoder.set_window_limit(usize::try_from(self.max_window).unwrap_or(usize::MAX));
        if let Some(policy) = self.policy {
            decoder.set_mt_workers_cap(policy.max_tape_workers.min(policy.max_workers).max(1));
        }
        decoder
    }

    /// Attaches an execution policy: strategy selection (flat vs ring,
    /// worker counts) honors its allowances. Output bytes and error
    /// semantics never depend on it.
    fn with_policy(mut self, policy: Option<crate::Rar50ExecutionPolicy>) -> Self {
        self.policy = policy;
        if let Some(policy) = policy {
            self.decoder.set_mt_workers_cap(policy.max_tape_workers.min(policy.max_workers).max(1));
        }
        self
    }

    /// Flat gate for one member under the policy: the flat allocation is
    /// capped and admitted against the working-memory estimate; without a
    /// policy the buffered limit alone gates, exactly as before.
    fn member_flat_limit(&self, file: &FileHeader) -> u64 {
        let Some(policy) = &self.policy else {
            return self.buffered_decode_limit;
        };
        let dictionary = file
            .decoded_compression_info()
            .map_or(0, |info| info.dictionary_size);
        if !flat_admitted(file.unpacked_size, dictionary, policy) {
            return 0;
        }
        // The limit bounds the flat ALLOCATION (codec `flat_plan_bytes`,
        // which slides and so scales with the dictionary), not the member:
        // since 2 Sep 2026 a multi-GB member with a 32 MiB dictionary plans
        // ~96 MiB and takes the flat path under this same 512 MiB cap.
        self.buffered_decode_limit.min(policy.flat_output_limit)
    }

    fn write_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        writer: &mut dyn Write,
    ) -> Result<()> {
        if file.is_stored() {
            return file.write_stored_to(
                archive,
                self.password,
                &mut self.reader_cache,
                writer,
            );
        }
        // Non-solid archives never reference a previous member's window, so
        // skip history retention (and the decoder clones below that exist
        // only to protect it) — saves up to dictionary-size copies per file.
        let solid_archive = archive.main.is_solid();
        self.decoder.set_retain_history(solid_archive);
        if file.should_stream_decode(self.buffered_decode_limit) {
            let mut counting = CountingWriter { inner: writer, written: 0 };
            match self.stream_file_to(archive, file, &mut counting) {
                // The streaming decoder bails on pathological filters
                // (over-long hold spans, partial overlaps). If nothing
                // reached the writer yet and the member fits the buffered
                // ceiling, decode it buffered instead.
                Err(error)
                    if counting.written == 0
                        && file.unpacked_size <= self.buffered_decode_limit
                        && is_streaming_filter_bail(&error) => {}
                other => return other,
            }
        }
        // Solid members rewind via an O(1) checkpoint when the filtered
        // output fails verification - the old decoder clone copied the
        // whole multi-MB solid window once per member. Non-solid members
        // retry on a fresh decoder as before (they carry no state).
        let checkpoint = solid_archive.then(|| self.decoder.solid_checkpoint());
        let decoded = self
            .decoded_file_data(archive, file)
            .map_err(|error| file.entry_error("decoding", error))?;
        let decoded = match file.verify_integrity_with_keys(&decoded.data, decoded.keys.as_ref()) {
            Ok(()) => decoded,
            Err(filtered_error) => {
                let unfiltered = if let Some(cp) = &checkpoint {
                    self.decoder.restore_checkpoint(cp);
                    file.decoded_data_with_mode(
                        archive,
                        &mut self.decoder,
                        self.password,
                        DecodeMode::LzNoFilters,
                        &mut self.reader_cache,
                    )
                    .map_err(|error| file.entry_error("decoding", error))?
                } else {
                    let mut fresh = self.fresh_decoder();
                    let unfiltered = file
                        .decoded_data_with_mode(
                            archive,
                            &mut fresh,
                            self.password,
                            DecodeMode::LzNoFilters,
                            &mut self.reader_cache,
                        )
                        .map_err(|error| file.entry_error("decoding", error))?;
                    self.decoder = fresh;
                    unfiltered
                };
                file.verify_integrity_with_keys(&unfiltered.data, unfiltered.keys.as_ref())
                    .map_err(|_| file.entry_error("verifying", filtered_error))?;
                unfiltered
            }
        };
        if solid_archive {
            // Verified and final: reclaim the window buffer's dead front.
            self.decoder.commit_member();
        }
        writer
            .write_all(&decoded.data)
            .map_err(Error::from)
            .map_err(|error| file.entry_error("writing", error))
    }

    fn stream_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let (mut packed, keys) = file
            .packed_reader_with_password(
                archive,
                self.password,
                &mut self.reader_cache,
            )
            .map_err(|error| file.entry_error("reading", error))?;
        if archive.main.is_solid() {
            // Work on a clone so a failed stream leaves the session's
            // decoder (and its solid history) untouched for a retry.
            // Compact first so the clone carries only the live window,
            // not the offset buffer's dead front.
            self.decoder.commit_member();
            let mut streaming_decoder = self.decoder.clone();
            file.stream_packed_with_decoder(
                &mut packed,
                keys.as_ref(),
                &mut streaming_decoder,
                self.member_flat_limit(file),
                writer,
            )
            .map_err(|error| file.entry_error("decoding", error))?;
            self.decoder = streaming_decoder;
        } else {
            let flat_limit = self.member_flat_limit(file);
            file.stream_packed_with_decoder(
                &mut packed,
                keys.as_ref(),
                &mut self.decoder,
                flat_limit,
                writer,
            )
            .map_err(|error| file.entry_error("decoding", error))?;
        }
        Ok(())
    }

    fn decoded_file_data(&mut self, archive: &Archive, file: &FileHeader) -> Result<DecodedData> {
        file.decoded_data_with_decoder(
            archive,
            &mut self.decoder,
            self.password,
            &mut self.reader_cache,
        )
    }

    fn split_decryptor(
        &self,
        split: &PendingSplitRefs,
        volumes: &[Archive],
    ) -> Result<Option<SplitDecryptor>> {
        split.split_decryptor(volumes, self.password)
    }

    fn decode_split(
        &mut self,
        volumes: &[Archive],
        split: &PendingSplitRefs,
        final_file: &FileHeader,
        decryptor: Option<&SplitDecryptor>,
        fragment_error: &SharedFragmentError,
    ) -> Result<Vec<u8>> {
        final_file.decode_split_with_decoder(
            volumes,
            split,
            &mut self.decoder,
            decryptor,
            fragment_error,
        )
    }
}

// Streaming decode (ring window + pipelined hash/write) outperforms the
// buffered path well before memory becomes a concern, so members above this
// size stream by default; `buffered_decode_limit` remains the ceiling for
// the buffered fallback (pathological filters) and can only lower the bar.
const STREAMING_PREFERRED_MIN: u64 = 4 * 1024 * 1024;

impl FileHeader {
    fn should_stream_decode(&self, buffered_decode_limit: u64) -> bool {
        !self.is_stored() && self.unpacked_size > buffered_decode_limit.min(STREAMING_PREFERRED_MIN)
    }
}

fn rar50_execution_policy(
    options: crate::ArchiveReadOptions<'_>,
) -> Option<crate::Rar50ExecutionPolicy> {
    options.rar50_execution_policy
}

fn rar50_buffered_decode_limit(options: crate::ArchiveReadOptions<'_>) -> u64 {
    options
        .rar50_buffered_decode_limit
        .unwrap_or(BUFFERED_DECODE_LIMIT)
}

fn rar50_max_window(options: crate::ArchiveReadOptions<'_>) -> u64 {
    options
        .rar50_max_window
        .unwrap_or(DEFAULT_STREAM_WINDOW_LIMIT)
}

/// Streams a RAR 5 multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volumes_to_impl(volumes, options, &mut open, &mut |_, _| Ok(()), false, None)
}

/// [`extract_volumes_to`] reporting each volume the engine is finished
/// with - the WHOLE-SET twin of
/// [`extract_volume_sequence_to_with_progress`], for a set that is
/// already materialized rather than one still arriving.
///
/// `consumed(volume_index)` says "no read will ever touch
/// `volumes[volume_index]` again", and the indices arrive in increasing
/// order, once each. A caller holding the volumes on DISK uses this to
/// delete each one the moment it is spent, so a set extracts without
/// ever holding the volumes and the extracted payload at once. The
/// callback can run on the decode thread, hence `Send`.
///
/// Two things make the report safe to act on destructively:
///
/// - **The walk runs strictly forward.** Members are visited volume by
///   volume, and a member's packed bytes live in the volume that
///   declares it. Solid members change nothing: the window carries
///   across members in RAM, the packed bytes are still read once, in
///   order.
/// - **A split member releases its volumes as its chain advances** - a
///   middle fragment is the only entry of its volume, so once the chain
///   has read it out the volume is finished with. The one path that
///   reads fragments TWICE is the buffered retry behind a streaming
///   filter bail, so the per-fragment watermark arms only where that
///   retry is impossible: stored members (which never retry) and
///   members too big to buffer. Anything else holds its volumes until
///   the Finish has run, exactly as before - those members fit in the
///   buffered path's ceiling, so the space they briefly pin is bounded.
///
/// Arming this DISABLES the parallel member pool. That plan decodes
/// independent members across the whole set concurrently, which is
/// exactly the out-of-order reading the watermark promises does not
/// happen. The serial walk is what makes the promise true.
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
    extract_volumes_to_impl(
        volumes,
        options,
        &mut open,
        &mut |_, _| Ok(()),
        false,
        Some(&mut consumed),
    )
}

pub fn extract_volumes_to_with_redirections<F, R>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    mut redirect: R,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    extract_volumes_to_impl(volumes, options, &mut open, &mut redirect, true, None)
}

fn extract_volumes_to_impl<F, R>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    open: &mut F,
    redirect: &mut R,
    emit_redirections: bool,
    mut consumed: Option<&mut (dyn FnMut(usize) + Send)>,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 volume set is empty"));
    }
    // This walk visits every entry of every volume and has no way to
    // finish a header walk that stopped at an arrival frontier, so a
    // partially enumerated volume here would silently skip members. Only
    // `extract_volume_sequence_to_with_progress` knows how to complete
    // one; anything else must be handed whole archives.
    if volumes.iter().any(|a| a.is_partially_enumerated()) {
        return Err(Error::InvalidHeader(
            "RAR 5 volume set has a partially enumerated volume",
        ));
    }

    // Non-solid sets with several small compressed members decode them on a
    // worker pool (members are independent; unrar streams sequentially and
    // cannot). Writers and callbacks stay on this thread in archive order.
    //
    // Never under a consumption watermark: the pool reads members across
    // the whole set at once, so "the walk has left volume N" would stop
    // being true the moment a worker is still inside it. A caller that
    // asked for the watermark asked for the serial walk.
    #[cfg(feature = "parallel")]
    if consumed.is_none() {
        if let Some(plan) = member_pool_plan(volumes, options) {
            return extract_volumes_pooled(
                volumes,
                options,
                open,
                redirect,
                emit_redirections,
                plan,
            );
        }
    }

    let password = options.password;
    let mut split = SplitVolumeState::new();
    let buffered_decode_limit = rar50_buffered_decode_limit(options);
    let mut session = DecoderSession::new_with_password(
        password,
        buffered_decode_limit,
        rar50_max_window(options),
    )
    .with_policy(rar50_execution_policy(options))
    .with_split_fragment_digests(options.rar50_split_fragment_digests);
    // Solid archives: a run of chainable members decodes as ONE stream
    // through the MT pipeline instead of member-by-member on one thread.
    // Safe under a watermark, unlike the member pool above: a chain is
    // collected from the claiming member FORWARD and its members are
    // never split, so it reads ahead and never back.
    #[cfg(feature = "parallel")]
    let mut chain = SolidChainDriver::new();
    // Volumes already reported consumed, so the catch-up after a split
    // member releases the whole backlog in order.
    let mut reported = 0usize;

    for (volume_index, archive) in volumes.iter().enumerate() {
        for (file_index, file) in archive.files().enumerate() {
            match split.advance(file.is_split_before(), file.is_split_after()) {
                SplitVolumeStep::Regular => {
                    if let Some(redirection) = &file.redirection {
                        if emit_redirections {
                            redirect(&file.metadata(), redirection)?;
                        }
                        continue;
                    }
                    #[cfg(feature = "parallel")]
                    if chain.claim(
                        &mut session,
                        volumes,
                        archive,
                        (volume_index, file_index),
                        file,
                        open,
                    ) {
                        continue;
                    }
                    let meta = file.metadata();
                    let mut writer = open(&meta)?;
                    if !meta.is_directory {
                        session.write_file_to(archive, file, &mut writer)?;
                    }
                }
                SplitVolumeStep::Start => {
                    validate_split_fragment(file, password)?;
                    split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                }
                SplitVolumeStep::Continue(current) => {
                    validate_split_continuation_refs(current, file, password)?;
                    current.append(volume_index, file_index)?;
                }
                SplitVolumeStep::Finish(mut completed) => {
                    validate_split_continuation_refs(&completed, file, password)?;
                    completed.append(volume_index, file_index)?;
                    // Progressive release: as the split member's chain
                    // finishes with a fragment, its volume (and any
                    // skipped ones before it) reports consumed - through
                    // the shared `reported` cursor, so order and
                    // uniqueness survive the boundary catch-up below.
                    // The finish volume stays held; the walk is still in
                    // it.
                    let reported = &mut reported;
                    if consumed.is_some() {
                        session.reader_cache.clear();
                    }
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
                        &mut session,
                        &mut *open,
                        spent
                            .as_mut()
                            .map(|spent| spent as &mut (dyn FnMut(usize) + Send)),
                    )?;
                }
                SplitVolumeStep::MissingFirst => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is missing its first part",
                    ));
                }
                SplitVolumeStep::Interrupted => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is interrupted by a regular entry",
                    ));
                }
            }
        }
        // This volume is walked out. Report it - and every one still held
        // back behind a split that has since finished - unless a split is
        // pending right now, whose Finish will read those fragments back.
        if !split.is_pending() {
            if let Some(consumed) = consumed.as_mut() {
                session.reader_cache.clear();
                while reported <= volume_index {
                    consumed(reported);
                    reported += 1;
                }
            }
        }
    }

    if split.is_pending() {
        return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
    }

    Ok(())
}

/// Streams a RAR 5 multivolume set whose volumes become available one at a
/// time, extracting each volume's members as soon as that volume parses.
///
/// `next_volume(index)` supplies volume `index`, blocking as needed (e.g. an
/// `Archive::parse_stream` call over a still-arriving source), and returns
/// `None` after the last volume. Members of volume k extract before volume
/// k+1 is requested, so extraction chases a progressive download at volume
/// granularity: while volume k's members decode, the bytes of volume k+1
/// keep arriving, and the next `next_volume` call blocks only for whatever
/// has not landed yet. Split members spanning volumes j..=k decode when
/// volume k appears, reading earlier fragments back through the retained
/// volumes, with the same semantics as `extract_volumes_to`.
///
/// Decoding is serial by design: the parallel member-pool and solid-chain
/// plans inspect the whole set up front, and a chasing extraction is bound
/// by arrival rate rather than decode rate.
///
/// A split member large enough to stream decodes INCREMENTALLY: its sink
/// opens at the Start fragment and its packed bytes feed the decoder as
/// each volume lands, instead of waiting for the Finish fragment and
/// reading every fragment back. See
/// [`extract_volume_sequence_to_with_progress`], which is the same walk
/// with the per-volume consumption watermark exposed.
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
/// engine is finished with.
///
/// `consumed(volume_index, offset)` says "nothing at or below `offset` in
/// volume `volume_index` will be read again"; `u64::MAX` means the whole
/// volume. A caller holding volumes in memory (nzbkit's chase holds each
/// one in a frontier buffer) uses this to drop bytes behind the decode, so
/// a set larger than its retention budget still extracts in one pass.
///
/// Two guarantees make the watermark safe to act on:
///
/// - **Packed reads run strictly forward.** The streaming RAR 5 decode
///   pulls its packed input through one sequential reader and never seeks
///   back, and the AES-CBC reader over an encrypted member is sequential
///   by construction. Solid members change nothing here: the window
///   carries across members, but the packed bytes are still consumed once,
///   in order.
/// - **A watermark is a promise, and the decode keeps it.** The one thing
///   that could break it is the buffered retry that rescues a
///   pathological-filter bail by re-reading the whole chain, so the
///   incremental path only takes that retry when nothing has been
///   published yet - which in practice means a bail on the very first
///   read. A filtered member that bails later fails instead, and the
///   caller (nzbkit's chase) answers that the way it answers any decode
///   failure: materialize the volumes, let the disk ladder extract them.
///   Posted payload is already-compressed video, where RAR filters do
///   not appear at all.
///
/// The callback runs on the decode thread as well as this one, hence
/// `Sync`; it must not block for long and must not call back into the
/// extraction.
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
    let mut session = DecoderSession::new_with_password(
        password,
        rar50_buffered_decode_limit(options),
        rar50_max_window(options),
    )
    .with_policy(rar50_execution_policy(options));
    let mut volumes: Vec<Archive> = Vec::new();
    // Volumes already reported wholly consumed, and where to resume the
    // entry walk after an incremental split handed the volume back.
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
                    session.reader_cache.clear();
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

        // Set when the walk meets a split Start worth decoding
        // incrementally; the borrow of `volumes` has to end before the
        // chain can grow it.
        let mut chase_at: Option<usize> = None;
        {
            // Wrapped in a resume loop, because running off the end of a
            // volume parsed by `Archive::parse_stream_incremental` does
            // NOT mean the volume is walked out - it means the header
            // walk stopped at the arrival frontier and has to be finished
            // before that can be said. Deferring it to the bottom of this
            // loop is the point: by then the split member has decoded and
            // the caller has released its bytes, so the wait the eager
            // parse used to pay up front costs no retention here.
            let mut resume_at = start_at;
            'walk: loop {
                let archive = &volumes[volume_index];
                for (file_index, file) in archive.files().enumerate().skip(resume_at) {
                    resume_at = file_index + 1;
                    match split.advance(file.is_split_before(), file.is_split_after()) {
                        SplitVolumeStep::Regular => {
                            if file.redirection.is_some() {
                                continue;
                            }
                            let meta = file.metadata();
                            let mut writer = open(&meta)?;
                            if !meta.is_directory {
                                session.write_file_to(archive, file, &mut writer)?;
                            }
                        }
                        SplitVolumeStep::Start => {
                            validate_split_fragment(file, password)?;
                            // `advance` leaves the state untouched for Start
                            // (only `begin` arms it), so breaking out here is
                            // clean - the chain owns the member from now on.
                            if incremental_split_worthwhile(file, &session) {
                                chase_at = Some(file_index);
                                // The volume is left here and never walked
                                // again, and needs no completion: this entry
                                // is flagged SPLIT_AFTER, and by the format
                                // nothing can follow a member that continues
                                // into the next volume but the END record.
                                break 'walk;
                            }
                            split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                        }
                        SplitVolumeStep::Continue(current) => {
                            validate_split_continuation_refs(current, file, password)?;
                            current.append(volume_index, file_index)?;
                        }
                        SplitVolumeStep::Finish(mut completed) => {
                            validate_split_continuation_refs(&completed, file, password)?;
                            completed.append(volume_index, file_index)?;
                            // The splits that land here are the ones the
                            // incremental path declined - stored members and
                            // small ones. Stored fragments still stream
                            // forward exactly once, so they release their
                            // volumes as the chain advances (a 400-volume
                            // stored film must not pin the whole set in the
                            // caller's retention window); `write_to` keeps
                            // the watermark off any path that could re-read.
                            let reported = &mut reported;
                            let consumed = &consumed;
                            session.reader_cache.clear();
                            let mut spent = move |spent_volume: usize| {
                                while *reported <= spent_volume {
                                    consumed(*reported, u64::MAX);
                                    *reported += 1;
                                }
                            };
                            completed.write_to(
                                &volumes,
                                file,
                                &mut session,
                                &mut open,
                                Some(&mut spent),
                            )?;
                        }
                        SplitVolumeStep::MissingFirst => {
                            return Err(Error::InvalidHeader(
                                "RAR 5 split entry is missing its first part",
                            ));
                        }
                        SplitVolumeStep::Interrupted => {
                            return Err(Error::InvalidHeader(
                                "RAR 5 split entry is interrupted by a regular entry",
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
            session.reader_cache.clear();
            let finish = incremental_split_decode(
                &mut volumes,
                (volume_index, file_index),
                &mut next_volume,
                &options,
                &mut session,
                &mut open,
                &consumed,
            )?;
            // The finishing volume may carry more members after the split
            // member, so the walk resumes inside it rather than pulling
            // the next volume.
            resume = Some((finish.0, finish.1 + 1));
        }
    }

    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 volume set is empty"));
    }
    if split.is_pending() {
        return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
    }

    Ok(())
}

/// Is this split member worth decoding through the growing chain?
///
/// Exactly the members that would stream anyway. Below that bar a split
/// member is small enough that retaining its fragments costs nothing, and
/// the buffered whole-chain path stays the simpler answer.
fn incremental_split_worthwhile(file: &FileHeader, session: &DecoderSession<'_>) -> bool {
    file.redirection.is_none()
        && !file.is_stored()
        && file.should_stream_decode(session.buffered_decode_limit)
}

/// Decode one split member incrementally, starting at its Start fragment
/// and pulling the volumes that carry the rest.
///
/// Returns the coordinates of the FINISH fragment so the caller can resume
/// its entry walk inside that volume. `volumes` grows as the chain pulls;
/// it is handed back with every volume the member spanned still in it, at
/// its own index - the fragments are header structs, and keeping them is
/// what lets a streaming-filter bail fall back to the buffered whole-chain
/// decode exactly as `extract_volumes_to` would.
#[allow(clippy::too_many_arguments)]
fn incremental_split_decode<P, F, C>(
    volumes: &mut Vec<Archive>,
    start: (usize, usize),
    next_volume: &mut P,
    options: &crate::ArchiveReadOptions<'_>,
    session: &mut DecoderSession<'_>,
    open: &mut F,
    consumed: &C,
) -> Result<(usize, usize)>
where
    P: FnMut(usize) -> Result<Option<Archive>> + Send,
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    C: Fn(usize, u64) + Sync,
{
    let password = options.password;
    let (start_volume, start_file) = start;
    // An owned copy of the Start fragment's header: it drives the whole
    // decode (name, dictionary, unpacked size and encryption all repeat
    // across a split member's fragments) and the chain owns `volumes`.
    let first = volumes
        .get(start_volume)
        .and_then(|archive| archive.files().nth(start_file))
        .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?
        .clone();
    let pending = PendingSplitRefs::new(&first, start_volume, start_file);
    let decryptor = pending.split_decryptor(volumes, password)?;
    let meta = ExtractedEntryMeta {
        name: pending.name.clone(),
        file_time: pending.file_time,
        attr: pending.attr,
        host_os: pending.host_os,
        is_directory: false,
        unpacked_size: first.unpacked_size,
    };
    let mut writer = open(&meta)?;

    let solid = first
        .decoded_compression_info()
        .map_err(|error| first.entry_error("decoding", error))?
        .solid;
    // Whether the streaming-filter bail could still fall back to the
    // buffered whole-chain decode, which re-reads every fragment. It
    // cannot for a member over the buffered ceiling - that guard predates
    // this path - and once the chain has published a watermark it cannot
    // either, whatever the size.
    let retry_possible = first.unpacked_size <= session.buffered_decode_limit;
    let mut chain = GrowingChainedReader::new(
        std::mem::take(volumes),
        pending,
        &first,
        next_volume,
        password,
        consumed,
    );

    let flat_limit = session.member_flat_limit(&first);
    // The expected value is the LAST fragment's, and this decode must
    // decide whether to hash before it has read that fragment - the
    // fragments do not agree on whether a hash record even EXISTS: the
    // rars writer puts one only on the finish fragment, WinRAR stamps
    // every earlier one with the digest of that fragment's own PACKED
    // bytes (checked per fragment by the chain below).
    //
    // `Unconditional` therefore hashes regardless and drops the digest
    // below when the finish fragment carries nothing to check it against.
    // That is the safe answer and the default, and on `rar`'s DEFAULT set
    // - CRC32 only, no hash record anywhere, which is what a posted set
    // normally is - it is a whole-payload BLAKE2sp nobody ever reads:
    // measured at +4.22 G instructions per GB unpacked and +5.83 G paced
    // against ~42 G for the decode, and it is the whole reason the
    // volumes-on-disk walk (which HOLDS the finish fragment and so never
    // hashes an unstamped set) costs less per GB than this path.
    // `FirstFragment` takes the first fragment's header as the set's
    // answer - exact for every WinRAR 7.21 and rar 7.23 set measured
    // here, not for a rars-written one, see [`crate::Rar50SplitHashSeeding`].
    //
    // A malformed record on the first fragment still errors here under
    // either setting, exactly as the whole-set walk errors on it.
    let first_seed = streaming_hash_verifier(&first)?;
    let seed = match (first_seed, options.rar50_split_hash_seeding) {
        (Some(seed), _) => Some(seed),
        (None, crate::Rar50SplitHashSeeding::Unconditional) => {
            Some(([0u8; 32], blake2sp::Hasher::new()))
        }
        (None, crate::Rar50SplitHashSeeding::FirstFragment) => None,
    };
    let mut counting = CountingWriter {
        inner: &mut *writer,
        written: 0,
    };
    // Solid members decode on a clone so a failed stream leaves the
    // session's window untouched for the buffered retry below - the same
    // trade `PendingSplitRefs::write_to` makes.
    let mut streaming_decoder = solid.then(|| session.decoder.clone());
    let stream_result = {
        let decoder = streaming_decoder.as_mut().unwrap_or(&mut session.decoder);
        let mut packed: Box<dyn Read + Send + '_> = match &decryptor {
            Some(decryptor) => Box::new(Rar50DecryptingReader::new(
                &mut chain,
                decryptor.keys.key,
                decryptor.iv,
            )),
            None => Box::new(&mut chain),
        };
        first.stream_packed_digests(
            &mut packed,
            decoder,
            flat_limit,
            &mut counting,
            seed,
        )
    };
    let written = counting.written;

    match stream_result {
        Ok((crc, hash)) => {
            if let Some(decoder) = streaming_decoder {
                session.decoder = decoder;
            }
            let (finish, volumes_back) = chain.finish(written)?;
            *volumes = volumes_back;
            let final_file = volumes[finish.0]
                .files()
                .nth(finish.1)
                .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
            // The expected digests are the LAST fragment's; whatever the
            // earlier headers carry is not the file's. A set with no hash
            // record at all simply has nothing to check here - and so does
            // one whose finish fragment records a digest the seeding above
            // declined to compute (a rars-written set under
            // `FirstFragment`), which is why that setting is opt-in: the
            // member is then verified by its CRC32 alone. Nothing can be
            // recovered at this point, the payload having already gone to
            // the writer, so this must not become an error - it would fail
            // an archive that is intact.
            let hash = match (hash, streaming_hash_verifier(final_file)?) {
                (Some((_, hasher)), Some((expected, _))) => Some((expected, hasher)),
                _ => None,
            };
            final_file
                .verify_streaming_integrity(
                    crc,
                    hash,
                    decryptor.as_ref().map(|decryptor| &decryptor.keys),
                )
                .map_err(|error| final_file.entry_error("verifying", error))?;
            Ok(finish)
        }
        Err(error) => {
            // A real rars error behind the io error the decoder saw (a
            // continuation that changed name or method, a volume that never
            // arrived) is the one to report - bare, exactly as the
            // whole-set walk reports it.
            if let Some(error) = chain.take_error() {
                let (_, volumes_back) = chain.into_parts();
                *volumes = volumes_back;
                return Err(error);
            }
            // The chain's own record is what makes the retry safe: if it
            // published a watermark, the caller may already have released
            // bytes the buffered path would have to read again. `written`
            // alone is not enough - the decoder can emit (and so unblock
            // the chain) a chunk that is still sitting in the pipe.
            let retry = !chain.published()
                && written == 0
                && retry_possible
                && is_streaming_filter_bail(&error);
            if !retry {
                let (_, volumes_back) = chain.into_parts();
                *volumes = volumes_back;
                return Err(first.entry_error("decoding", error));
            }
            // Nothing reached the writer, so nothing was reported consumed
            // and every fragment is still readable: pull the rest of the
            // chain and take the buffered whole-member path, which is what
            // `PendingSplitRefs::write_to` does for the same bail.
            chain.drain()?;
            if let Some(error) = chain.take_error() {
                let (_, volumes_back) = chain.into_parts();
                *volumes = volumes_back;
                return Err(error);
            }
            let (pending, volumes_back) = chain.into_parts();
            *volumes = volumes_back;
            let finish = *pending
                .fragments
                .last()
                .expect("a drained chain has its finish fragment");
            if !solid {
                // A non-solid member must not see state the failed stream
                // left behind; through `fresh_decoder` so the retry keeps
                // the caller's window and worker limits.
                session.decoder = session.fresh_decoder();
            }
            let final_file = volumes[finish.0]
                .files()
                .nth(finish.1)
                .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
            let fragment_error: SharedFragmentError = Default::default();
            let data = session
                .decode_split(
                    volumes,
                    &pending,
                    final_file,
                    decryptor.as_ref(),
                    &fragment_error,
                )
                .map_err(|error| final_file.entry_error("decoding", error))
                .map_err(|error| fragment_error.lock().unwrap().take().unwrap_or(error))?;
            final_file
                .verify_integrity_with_keys(
                    &data,
                    decryptor.as_ref().map(|decryptor| &decryptor.keys),
                )
                .map_err(|error| final_file.entry_error("verifying", error))?;
            counting
                .write_all(&data)
                .map_err(Error::from)
                .map_err(|error| final_file.entry_error("writing", error))?;
            Ok(finish)
        }
    }
}

/// The packed byte chain of a split member whose later fragments DO NOT
/// EXIST YET.
///
/// `LazyChainedReader` serves a fragment list resolved up front; this one
/// pulls the next volume from the sequence driver when the fragment in
/// hand runs dry, which is what lets a split member start decoding at its
/// Start fragment instead of its Finish. Fragments are consumed strictly
/// forward and exactly once, one open cursor at a time.
///
/// Every volume it pulls stays in `volumes`, at its own index: those are
/// header structs (the payload lives in whatever source backs them), and
/// keeping them is what lets the caller fall back to the buffered
/// whole-chain decode when the streaming decoder bails on a filter.
struct GrowingChainedReader<'a, P, C> {
    volumes: Vec<Archive>,
    pending: PendingSplitRefs,
    next_volume: &'a mut P,
    consumed: &'a C,
    password: Option<&'a [u8]>,
    /// Identity every continuation is checked against.
    compression_info: u64,
    encrypted: bool,
    unpacked_size: u64,
    /// Index into `pending.fragments` of the fragment the cursor is on.
    at: usize,
    cursor: Option<OwnedRangeReader>,
    /// Volume-space start of that fragment's packed range, and how far in
    /// the decoder has read.
    frag_start: u64,
    frag_pos: u64,
    /// The fragment's packed length - `frag_pos` reaching it means the
    /// fragment is fully read even when no read ever drained the cursor.
    frag_len: u64,
    /// Running digests over the fragment the cursor is on, when its own
    /// header says what its packed bytes must hash to. The decryptor
    /// wraps OUTSIDE this chain, so these run over the stored bytes -
    /// exactly what the per-fragment records cover.
    frag_digest: Option<FragmentDigest>,
    /// The finish fragment (no SPLIT_AFTER) has been appended.
    last_seen: bool,
    /// Fragments already reported wholly consumed.
    reported: usize,
    /// Any watermark published at all - once true the caller may have
    /// released bytes, so the buffered whole-chain retry is off.
    published: bool,
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
            compression_info: first.compression_info,
            encrypted: first.encrypted,
            unpacked_size: first.unpacked_size,
            at: 0,
            cursor: None,
            frag_start: 0,
            frag_pos: 0,
            frag_len: 0,
            frag_digest: None,
            last_seen: !first.is_split_after(),
            reported: 0,
            published: false,
            error: None,
        }
    }

    fn take_error(&mut self) -> Option<Error> {
        self.error.take()
    }

    fn published(&self) -> bool {
        self.published
    }

    fn into_parts(self) -> (PendingSplitRefs, Vec<Archive>) {
        (self.pending, self.volumes)
    }

    /// Finish coordinates plus the volumes, once the decode has run to the
    /// end of the chain. A decode that declared success without draining
    /// the chain (a member whose declared unpacked size is short of what
    /// its fragments carry) is a malformed archive, not a success.
    fn finish(mut self, written: u64) -> Result<((usize, usize), Vec<Archive>)> {
        self.check_boundary_fragment()?;
        if !self.last_seen {
            // The decoder stopped early: pull the rest so the member's
            // real end is known, then report it.
            self.drain()?;
        }
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        if written != self.unpacked_size {
            return Err(Error::InvalidHeader(
                "RAR 5 split entry decoded to a different size than its header declares",
            ));
        }
        let finish = *self
            .pending
            .fragments
            .last()
            .expect("the chain always holds its start fragment");
        Ok((finish, self.volumes))
    }

    /// Pull every remaining fragment without reading payload - the
    /// buffered retry needs the whole list, and so does an early stop.
    fn drain(&mut self) -> Result<()> {
        while !self.last_seen {
            self.pull_fragment()?;
        }
        Ok(())
    }

    /// Publish how much of each volume the engine is finished with.
    ///
    /// Every fragment behind the cursor is wholly consumed. The fragment
    /// the cursor is ON reports its own byte offset, never `u64::MAX`:
    /// the FINISHING volume carries the members after the split one, and
    /// the caller resumes its walk there.
    fn report(&mut self) {
        while self.reported < self.at {
            let (volume_index, _) = self.pending.fragments[self.reported];
            (self.consumed)(volume_index, u64::MAX);
            self.reported += 1;
            self.published = true;
        }
        if let Some(&(volume_index, _)) = self.pending.fragments.get(self.at) {
            (self.consumed)(volume_index, self.frag_start + self.frag_pos);
            self.published = true;
        }
    }

    /// Take the next volume from the driver and record its continuation
    /// fragment. Volumes with no file entries are skipped, exactly as the
    /// whole-set walk skips them.
    fn pull_fragment(&mut self) -> Result<()> {
        loop {
            let volume_index = self.volumes.len();
            let Some(archive) = (self.next_volume)(volume_index)? else {
                return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
            };
            self.volumes.push(archive);
            // An EMPTY volume is skipped, exactly as the whole-set walk
            // skips one - but a volume parsed by
            // `Archive::parse_stream_incremental` can read as empty while
            // it is merely still arriving, and skipping THAT would drop a
            // fragment of the member being decoded. So an archive with no
            // entries has to be pressed for the truth first - one header
            // at a time (`enumerate_next`), never the whole walk: that
            // would block on the volume's END record, i.e. on the whole
            // volume arriving, which is the pin the incremental parse
            // exists to avoid.
            let password = self.password;
            while self.volumes[volume_index].files().next().is_none()
                && self.volumes[volume_index].is_partially_enumerated()
            {
                self.volumes[volume_index].enumerate_next(password)?;
            }
            let archive = &self.volumes[volume_index];
            let Some(file) = archive.files().next() else {
                continue;
            };
            if !file.is_split_before() {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry is interrupted by a regular entry",
                ));
            }
            validate_split_fragment(file, self.password)?;
            if file.name != self.pending.name {
                return Err(Error::InvalidHeader("RAR 5 split entry name changed"));
            }
            if file.compression_info != self.compression_info {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry compression info changed",
                ));
            }
            if file.encrypted != self.encrypted {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry encryption flag changed",
                ));
            }
            // Not checked by the whole-set walk, which reads the size off
            // the LAST fragment; the incremental decode is already running
            // against the FIRST one's, so a disagreement has to be caught.
            // Every fragment of a split member repeats the total.
            if file.unpacked_size != self.unpacked_size {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry unpacked size changed",
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
            .ok_or(Error::InvalidHeader("RAR 5 split volume is missing"))?;
        let file = archive
            .files()
            .nth(file_index)
            .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
        let range = file.block.data_range.clone();
        self.frag_start = range.start as u64;
        self.frag_pos = 0;
        self.frag_len = (range.end - range.start) as u64;
        self.frag_digest = file
            .split_fragment_packed_digests()
            .map(|expected| FragmentDigest::new(expected, volume_index));
        self.cursor = Some(archive.owned_range_reader(range)?);
        Ok(())
    }

    /// The packed digest check fires when a read drains the cursor, so
    /// a consumer that stops asking EXACTLY at a fragment's boundary (a
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
            if let Some(digest) = self.frag_digest.take() {
                digest.verify()?;
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
        // A recorded failure latches, matching the whole-set walk's
        // fragment readers: a caller that swallowed the io error must
        // keep failing here, because the error surfaces with `at`
        // unadvanced and the cursor dropped - without the latch a
        // retried read would re-open the failed fragment and deliver
        // its bytes again as if nothing happened.
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
                    if let Some(digest) = self.frag_digest.as_mut() {
                        digest.update(&out[..read]);
                    }
                    self.report();
                    return Ok(read);
                }
                // Drop the finished fragment BEFORE opening the next one.
                self.cursor = None;
                // The fragment is read out; its own header says what its
                // packed bytes must hash to. Checked BEFORE the volume is
                // reported consumed - the caller may act on that report.
                if let Some(digest) = self.frag_digest.take() {
                    if let Err(error) = digest.verify() {
                        return Err(self.fail(error));
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

// --- solid-chain MT decode (solid sets: one stream, cut at boundaries) -----
//
// A solid group is ONE continuous compressed stream split at member
// boundaries: tables, rep state, and the LZ window all carry across
// members. Chaining the members' packed readers through the existing MT
// scan/tape pipeline decodes the whole group with the worker pool the big
// single members already enjoy; this consumer cuts the emitted byte stream
// at member boundaries, opening each writer and verifying each member's
// digests (CRC32/BLAKE2sp) as the bytes stream past - exactly what the
// serial per-member path checks, at the same points.

/// One member of a solid chain group.
#[cfg(feature = "parallel")]
struct ChainMember<'a> {
    volume_index: usize,
    file_index: usize,
    file: &'a FileHeader,
    output_size: usize,
}

/// Is `file` shaped for chain membership? Splits, stored members,
/// directories, redirections, encrypted members (keyed digest MACs stay on
/// the serial path), and zero-size members all cut the chain.
#[cfg(feature = "parallel")]
fn chain_member_shape(file: &FileHeader, password_available: bool) -> bool {
    file.redirection.is_none()
        && !file.is_split_before()
        && !file.is_split_after()
        && !file.is_directory()
        && !file.is_stored()
        // Encrypted members chain when keys exist or can be derived (the
        // chain pre-derives once per member set): the scan thread owns
        // sequential decryption through the member's packed reader, workers
        // only ever see plaintext, and the consumer MACs digests with the
        // pre-derived keys. Without a password the member stays on the
        // serial path, which raises NeedPassword exactly as before.
        && (!file.encrypted || file.crypto.is_some() || password_available)
        && file.unpacked_size > 0
        && usize::try_from(file.unpacked_size).is_ok()
}

/// Chain attempts per set that may fail before chaining is disabled. A
/// failed chain restores the pre-group snapshot and retries that group
/// serially; the budget lets LATER groups still try the pipeline (a failure
/// is usually specific to one group's data), while repeated failures stop a
/// pathological archive from paying chain-then-serial on every group.
#[cfg(feature = "parallel")]
const SOLID_CHAIN_FAILURE_BUDGET: u32 = 2;

/// Shared solid-chain bookkeeping for the serial and pooled walks: which
/// members a chained group already emitted, and how many chains have failed.
#[cfg(feature = "parallel")]
struct SolidChainDriver {
    chained: std::collections::HashSet<(usize, usize)>,
    failures: u32,
}

#[cfg(feature = "parallel")]
impl SolidChainDriver {
    fn new() -> Self {
        Self {
            chained: std::collections::HashSet::new(),
            failures: 0,
        }
    }

    /// Returns true when the walk should skip this member: it was already
    /// emitted by a chained group, or a chain starting here just decoded
    /// (and emitted) a whole group through the MT pipeline. A failed chain
    /// restores the pre-group state, counts against the failure budget, and
    /// returns false so the caller's serial path re-decodes the group with
    /// its exact error semantics (writers are re-opened, so partially
    /// chained output is rewritten).
    fn claim<F>(
        &mut self,
        session: &mut DecoderSession<'_>,
        volumes: &[Archive],
        archive: &Archive,
        coords: (usize, usize),
        file: &FileHeader,
        open: &mut F,
    ) -> bool
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        if self.chained.contains(&coords) {
            return true;
        }
        let password_available = session.password.is_some();
        if self.failures >= SOLID_CHAIN_FAILURE_BUDGET
            || !archive.main.is_solid()
            || !chain_member_shape(file, password_available)
        {
            return false;
        }
        let members = collect_solid_chain(volumes, coords, password_available);
        let total: usize = members.iter().map(|m| m.output_size).sum();
        if members.len() < 2 || !session.decoder.solid_chain_worthwhile(total) {
            return false;
        }
        let snapshot = session.decoder.snapshot_solid_state();
        match stream_solid_chain(session, volumes, &members, open) {
            Ok(()) => {
                for member in &members {
                    self.chained.insert((member.volume_index, member.file_index));
                }
                true
            }
            Err(_) => {
                session.decoder.restore_solid_state(snapshot);
                self.failures += 1;
                false
            }
        }
    }
}

/// Collect the maximal solid chain group starting at `start` (inclusive):
/// consecutive members of matching shape, same algorithm and dictionary,
/// every member after the first carrying the solid flag. Stops at the
/// first ineligible member.
#[cfg(feature = "parallel")]
fn collect_solid_chain<'a>(
    volumes: &'a [Archive],
    start: (usize, usize),
    password_available: bool,
) -> Vec<ChainMember<'a>> {
    let mut members: Vec<ChainMember<'a>> = Vec::new();
    let mut base: Option<(u8, u64)> = None; // (algorithm_version, dictionary)
    'volumes: for (volume_index, archive) in volumes.iter().enumerate().skip(start.0) {
        for (file_index, file) in archive.files().enumerate() {
            if volume_index == start.0 && file_index < start.1 {
                continue;
            }
            if !chain_member_shape(file, password_available) {
                break 'volumes;
            }
            let Ok(info) = file.decoded_compression_info() else {
                break 'volumes;
            };
            match base {
                None => base = Some((info.algorithm_version, info.dictionary_size)),
                Some((alg, dict)) => {
                    if info.algorithm_version != alg || info.dictionary_size != dict || !info.solid
                    {
                        break 'volumes;
                    }
                }
            }
            members.push(ChainMember {
                volume_index,
                file_index,
                file,
                output_size: file.unpacked_size as usize,
            });
        }
    }
    members
}

/// Decode a chain group through the MT pipeline and stream each member out
/// through `open` in archive order, verifying digests at each boundary.
#[cfg(feature = "parallel")]
fn stream_solid_chain<F>(
    session: &mut DecoderSession<'_>,
    volumes: &[Archive],
    members: &[ChainMember<'_>],
    open: &mut F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let first_info = members[0].file.decoded_compression_info()?;
    let dictionary_size = usize::try_from(first_info.dictionary_size)
        .map_err(|_| Error::InvalidHeader("RAR 5 dictionary size overflows host address size"))?;
    // The decoder takes the sizes, not the total: it splits the group the
    // same way the digester below does, so a filter declared by a member
    // after the first translates addresses against that member's own start.
    let member_sizes: Vec<usize> = members.iter().map(|m| m.output_size).collect();
    let total: usize = member_sizes.iter().sum();
    // The window must persist for members after the group.
    session.decoder.set_retain_history(true);
    // A group under this budget takes the flat-apply fast path; larger
    // groups stream through the ring. Without a policy, a fixed cap bounds
    // what one solid group may hold in memory; a policy replaces the cap
    // with its own allowance and admission estimate, so a large host may
    // hold a bigger group flat and a constrained one refuses sooner.
    const CHAIN_FLAT_LIMIT: u64 = 256 << 20;
    let flat_limit = match &session.policy {
        Some(policy) => {
            if flat_admitted(total as u64, first_info.dictionary_size, policy) {
                session.buffered_decode_limit.min(policy.flat_output_limit)
            } else {
                0
            }
        }
        None => session.buffered_decode_limit.min(CHAIN_FLAT_LIMIT),
    };

    // Same pipe as stream_packed_with_decoder: decode on a spawned thread,
    // write on this thread (writers are not Send), and digest on a third
    // thread downstream of the writer - the same split that fixed the
    // repetitive shape, where CRC32 and write() running serially made this
    // thread the pipeline's bottleneck while the decoder sat on
    // backpressure. The digester re-splits the stream at member boundaries
    // with its own byte count (the split is deterministic from the members'
    // declared sizes) and performs each member's integrity check.
    const PIPE_BUF: usize = 1 << 20;
    const POOL_BUFFERS: usize = 4;
    enum PipeChunk {
        Data(Vec<u8>),
        Repeated { byte: u8, len: usize },
    }
    fn pipe_closed<T>(_: T) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "extraction pipeline closed")
    }

    let (data_tx, data_rx) = std::sync::mpsc::sync_channel::<PipeChunk>(POOL_BUFFERS + 1);
    let (digest_tx, digest_rx) = std::sync::mpsc::channel::<PipeChunk>();
    let (pool_tx, pool_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    for _ in 0..POOL_BUFFERS {
        let _ = pool_tx.send(Vec::with_capacity(PIPE_BUF));
    }

    // Pre-derive every encrypted member's keys, one PBKDF2 ladder per
    // distinct (salt, kdf count) rather than one per member: the scan
    // thread builds decrypting readers from these, and the consumer MACs
    // digests with them. A derive or check failure fails the chain here,
    // before any state moves; the serial retry then reproduces the exact
    // per-member error.
    let member_keys: Vec<Option<Rar50Keys>> = {
        let mut key_cache = super::Rar50KeyCache::default();
        members
            .iter()
            .map(|member| {
                member
                    .file
                    .crypto_with_password_cached(session.password, &mut key_cache)
            })
            .collect::<Result<_>>()?
    };
    let decoder = &mut session.decoder;
    let reader_cache = &mut session.reader_cache;
    let mut consume_error: Option<Error> = None;
    let member_keys_ref = &member_keys;
    let member_sizes_ref = &member_sizes;
    let scope_outcome = std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            // Member readers, yielded to the scan in order. An open failure
            // ends the chain early (the shortfall surfaces as
            // NeedMoreInput); the real error rides back beside the result.
            let mut next = 0usize;
            let mut reader_error: Option<Error> = None;
            let member_keys = member_keys_ref;
            let mut next_input = || {
                let member = members.get(next)?;
                let keys = member_keys[next].as_ref();
                next += 1;
                match member
                    .file
                    .packed_reader_with_keys(
                        &volumes[member.volume_index],
                        keys,
                        reader_cache,
                    )
                {
                    Ok(reader) => Some(reader),
                    Err(error) => {
                        reader_error = Some(error);
                        None
                    }
                }
            };
            let mut current = match pool_rx.recv() {
                Ok(buffer) => buffer,
                Err(error) => {
                    return (Err(StreamDecodeError::Sink(pipe_closed(error))), None);
                }
            };
            let result = decoder.decode_solid_chain_to_sink(
                &mut next_input,
                first_info.algorithm_version,
                member_sizes_ref,
                dictionary_size,
                !first_info.solid,
                flat_limit,
                |chunk| -> std::io::Result<()> {
                    match chunk {
                        DecodedChunk::Bytes(mut bytes) => {
                            while !bytes.is_empty() {
                                let take = (PIPE_BUF - current.len()).min(bytes.len());
                                current.extend_from_slice(&bytes[..take]);
                                bytes = &bytes[take..];
                                if current.len() == PIPE_BUF {
                                    data_tx
                                        .send(PipeChunk::Data(std::mem::take(&mut current)))
                                        .map_err(pipe_closed)?;
                                    current = pool_rx.recv().map_err(pipe_closed)?;
                                }
                            }
                            Ok(())
                        }
                        DecodedChunk::Repeated { byte, len } => {
                            if !current.is_empty() {
                                data_tx
                                    .send(PipeChunk::Data(std::mem::take(&mut current)))
                                    .map_err(pipe_closed)?;
                                current = pool_rx.recv().map_err(pipe_closed)?;
                            }
                            data_tx
                                .send(PipeChunk::Repeated { byte, len })
                                .map_err(pipe_closed)
                        }
                    }
                },
            );
            let result = if result.is_ok() && !current.is_empty() {
                data_tx
                    .send(PipeChunk::Data(current))
                    .map_err(pipe_closed)
                    .map_err(StreamDecodeError::Sink)
            } else {
                result
            };
            (result, reader_error)
        });

        // Digester: runs downstream of the writer in write order, re-splits
        // the stream at member boundaries by its own byte count, digests,
        // and verifies each member as its last byte passes. It owns the
        // buffer pool: a chunk's buffer returns to the pool only once it is
        // hashed. On a verification failure it exits early - the producer
        // then wakes via the failed pool recv, the writer via the ended
        // data stream, so nothing hangs (see the shutdown note below).
        let digester = scope.spawn(move || {
            let mut cursor = 0usize; // member index
            let mut error: Option<Error> = None;
            let mut member_state: Option<(Crc32, Option<([u8; 32], blake2sp::Hasher)>, usize)> =
                None;
            'digest: for chunk in digest_rx {
                let mut chunk = match chunk {
                    PipeChunk::Data(buffer) => ChunkCursor::Data(buffer, 0),
                    PipeChunk::Repeated { byte, len } => ChunkCursor::Repeated { byte, len },
                };
                while chunk.remaining() > 0 {
                    if member_state.is_none() {
                        // The writer bounds the stream to the members'
                        // declared total before forwarding, so running past
                        // the last member is unreachable here.
                        let Some(member) = members.get(cursor) else {
                            break 'digest;
                        };
                        match streaming_hash_verifier(member.file) {
                            Ok(hash) => {
                                member_state = Some((Crc32::new(), hash, member.output_size))
                            }
                            Err(inner) => {
                                error =
                                    Some(member.file.entry_error("verifying", inner));
                                break 'digest;
                            }
                        }
                    }
                    let (crc, hash, remaining) =
                        member_state.as_mut().expect("member state just set");
                    let take = (*remaining).min(chunk.remaining());
                    match &mut chunk {
                        ChunkCursor::Data(buffer, offset) => {
                            let slice = &buffer[*offset..*offset + take];
                            crc.update(slice);
                            if let Some((_, hasher)) = hash {
                                hasher.update(slice);
                            }
                            *offset += take;
                        }
                        ChunkCursor::Repeated { byte, len } => {
                            digest_repeated_chunk(crc, hash, *byte, take);
                            *len -= take;
                        }
                    }
                    *remaining -= take;
                    if *remaining == 0 {
                        let (crc, hash, _) =
                            member_state.take().expect("member state present");
                        if let Err(inner) = members[cursor].file.verify_streaming_integrity(
                            crc,
                            hash,
                            member_keys_ref[cursor].as_ref(),
                        ) {
                            error = Some(
                                members[cursor].file.entry_error("verifying", inner),
                            );
                            break 'digest;
                        }
                        cursor += 1;
                    }
                }
                // Recycle the hashed buffer so the producer never starves.
                if let ChunkCursor::Data(mut buffer, _) = chunk {
                    buffer.clear();
                    let _ = pool_tx.send(buffer);
                }
            }
            // The pool sender drops with the digester; an early exit above
            // relies on that to wake a producer parked on the drained pool.
            (cursor, error)
        });

        // Writer: open each member's writer in archive order and route the
        // byte stream across member boundaries; every chunk the writer
        // accepted is forwarded (whole) to the digester in write order.
        let mut cursor = 0usize; // member index
        let mut member_state: Option<(Box<dyn Write>, usize)> = None;
        'consume: for chunk in data_rx.iter() {
            let (mut chunk, forward_len) = match chunk {
                PipeChunk::Data(buffer) => {
                    let len = buffer.len();
                    (ChunkCursor::Data(buffer, 0), len)
                }
                PipeChunk::Repeated { byte, len } => {
                    (ChunkCursor::Repeated { byte, len }, len)
                }
            };
            while chunk.remaining() > 0 {
                if member_state.is_none() {
                    if cursor >= members.len() {
                        consume_error = Some(Error::InvalidHeader(
                            "RAR 5 solid chain produced more bytes than its members declare",
                        ));
                        break 'consume;
                    }
                    let member = &members[cursor];
                    match open(&member.file.metadata()) {
                        Ok(writer) => member_state = Some((writer, member.output_size)),
                        Err(error) => {
                            consume_error = Some(error);
                            break 'consume;
                        }
                    }
                }
                let (writer, remaining) =
                    member_state.as_mut().expect("member state just set");
                let take = (*remaining).min(chunk.remaining());
                let outcome = match &mut chunk {
                    ChunkCursor::Data(buffer, offset) => {
                        let outcome = writer
                            .write_all(&buffer[*offset..*offset + take])
                            .map_err(Error::from);
                        *offset += take;
                        outcome
                    }
                    ChunkCursor::Repeated { byte, len } => {
                        let outcome = write_repeated_bytes(writer.as_mut(), *byte, take)
                            .map_err(Error::from);
                        *len -= take;
                        outcome
                    }
                };
                if let Err(error) = outcome {
                    consume_error =
                        Some(members[cursor].file.entry_error("writing", error));
                    break 'consume;
                }
                *remaining -= take;
                if *remaining == 0 {
                    member_state = None;
                    cursor += 1;
                }
            }
            // Forward the fully written chunk for digesting; the digester
            // re-splits it with its own member cursor. A send failure means
            // the digester already exited on a verification failure - keep
            // writing, its recorded error surfaces after the join.
            match chunk {
                ChunkCursor::Data(buffer, _) => {
                    let _ = digest_tx.send(PipeChunk::Data(buffer));
                }
                ChunkCursor::Repeated { byte, .. } => {
                    let _ = digest_tx.send(PipeChunk::Repeated {
                        byte,
                        len: forward_len,
                    });
                }
            }
        }
        // Dropping the receiver here unblocks a producer stuck on send.
        drop(data_rx);
        // ...but a producer parked on `pool_rx.recv()` with the pool drained
        // is not waiting on the data channel, so that alone would hang the
        // join. Every `break 'consume` above jumps PAST the forward at the
        // foot of the loop, so the buffer in hand is dropped rather than
        // recycled - and the breaks are the ordinary failures, not exotic
        // ones: a write failure, a rejected entry path. The pool sender now
        // lives in the digester, so dropping the digest sender ends the
        // digester, whose exit drops the pool sender and fails that recv.
        drop(digest_tx);
        let (verified_members, digest_error) =
            digester.join().expect("solid chain digest thread panicked");
        let (decode, reader_error) =
            handle.join().expect("solid chain decode thread panicked");
        (decode, reader_error, verified_members, digest_error)
    });

    let (decode_result, reader_error, verified_members, digest_error) = scope_outcome;
    // A digest failure is the earliest failure in stream order: the
    // digester runs strictly behind the writer, so its member index is
    // never ahead of where any write error happened - the serial
    // consumer would have reported it first.
    if let Some(error) = digest_error {
        return Err(error);
    }
    if let Some(error) = consume_error {
        return Err(error);
    }
    let at = verified_members.min(members.len() - 1);
    if let Some(error) = reader_error {
        // A member's packed reader failed to open mid-chain; the decode
        // error below is just the resulting shortfall - surface the cause.
        return Err(members[at].file.entry_error("reading", error));
    }
    match decode_result {
        Ok(()) => {
            if verified_members == members.len() {
                Ok(())
            } else {
                // Decode declared success but the stream came up short.
                Err(members[at]
                    .file
                    .entry_error("decoding", Error::from(crate::codec::Error::NeedMoreInput)))
            }
        }
        Err(StreamDecodeError::Decode(crate::codec::Error::WindowLimitExceeded {
            limit,
            required,
        })) => Err(members[at].file.entry_error(
            "decoding",
            Error::Rar50WindowLimitExceeded { limit, required },
        )),
        Err(StreamDecodeError::Decode(error)) => {
            Err(members[at].file.entry_error("decoding", Error::from(error)))
        }
        Err(StreamDecodeError::FilteredMember) => Err(members[at].file.entry_error(
            "decoding",
            Error::InvalidHeader("RAR 5 solid chain member needs the buffered filter path"),
        )),
        Err(StreamDecodeError::Sink(error)) => Err(Error::from(error)),
    }
}

/// A pipe chunk being consumed across member boundaries.
#[cfg(feature = "parallel")]
enum ChunkCursor {
    Data(Vec<u8>, usize),
    Repeated { byte: u8, len: usize },
}

#[cfg(feature = "parallel")]
impl ChunkCursor {
    fn remaining(&self) -> usize {
        match self {
            Self::Data(buffer, offset) => buffer.len() - offset,
            Self::Repeated { len, .. } => *len,
        }
    }
}

// --- member-parallel decode pool (non-solid sets, small members) -----------
//
// Non-solid RAR5 members share no decoder state, so several can decode at
// once. The coordinator (caller thread) walks headers in archive order and
// owns every writer/callback; workers only turn packed bytes into verified
// member bytes. Results rejoin through a BTreeMap reorder, and a byte budget
// on decoded-but-unwritten members bounds RSS however fast the workers run
// ahead of the writer.

/// Ceiling on decoded-but-unwritten pooled bytes. The feeder blocks past
/// this, so a pathological archive of max-size pooled members cannot balloon
/// RSS. The tiny test value forces the backpressure path constantly.
#[cfg(all(feature = "parallel", not(test)))]
const POOL_INFLIGHT_BUDGET: u64 = 64 << 20;
#[cfg(all(feature = "parallel", test))]
const POOL_INFLIGHT_BUDGET: u64 = 8 * 1024;

/// Cap the number of adjacent members claimed through one work-channel
/// receive. Tiny-member archives otherwise spend one shared-receiver lock and
/// one budget-lock acquisition per few kilobytes of useful work. Keeping at
/// least eight batches per worker avoids starving the pool on smaller sets.
/// (nzbfast-local change, 2 Sep 2026 - re-apply on the next rars re-sync;
/// see vendor/rars/VENDORING.md.)
#[cfg(feature = "parallel")]
const POOL_WORK_BATCH_MAX: usize = 8;

/// Result-channel coalescing is intentionally narrower than work batching.
/// Eight 4 KiB members are the measured tiny-file shape where removing seven
/// sends/tree operations matters; waiting for the whole range once members
/// grow beyond that can hold an early result behind milliseconds of unrelated
/// decode work. Keeping the ceiling at exactly that 32 KiB range leaves the
/// tiny fast path unchanged and makes larger ranges publish each member as
/// soon as it finishes.
#[cfg(feature = "parallel")]
const POOL_RESULT_BATCH_BYTE_MAX: u64 = POOL_WORK_BATCH_MAX as u64 * (4 << 10);

#[cfg(feature = "parallel")]
fn pool_work_batch_size(members: usize, workers: usize) -> usize {
    (members / workers.saturating_mul(8).max(1)).clamp(1, POOL_WORK_BATCH_MAX)
}

#[cfg(feature = "parallel")]
fn pool_result_batchable(mut unpacked_sizes: impl Iterator<Item = u64>) -> bool {
    let mut members = 0usize;
    let total = unpacked_sizes.try_fold(0u64, |total, size| {
        members += 1;
        total.checked_add(size)
    });
    (2..=POOL_WORK_BATCH_MAX).contains(&members)
        && total.is_some_and(|total| total <= POOL_RESULT_BATCH_BYTE_MAX)
}

/// Select one contiguous work batch. The first member is always admitted so
/// an individually oversized entry can still make progress; subsequent
/// members must fit both the count cap and one worker's share of the global
/// in-flight byte budget.
#[cfg(feature = "parallel")]
fn pool_work_batch_shape(
    mut unpacked_sizes: impl Iterator<Item = u64>,
    member_limit: usize,
    byte_limit: u64,
) -> (usize, u64) {
    let Some(mut total) = unpacked_sizes.next() else {
        return (0, 0);
    };
    let mut members = 1;
    for size in unpacked_sizes.take(member_limit.saturating_sub(1)) {
        let Some(next_total) = total.checked_add(size) else {
            break;
        };
        if next_total > byte_limit {
            break;
        }
        total = next_total;
        members += 1;
    }
    (members, total)
}

/// One bounded worker result. The singleton arm avoids allocating a result
/// vector and, for ranges above `POOL_RESULT_BATCH_BYTE_MAX`, restores
/// per-member publication rather than holding the range behind its last
/// decode.
/// (nzbfast-local change, 3 Sep 2026 - re-apply on the next rars re-sync;
/// see vendor/rars/VENDORING.md.)
#[cfg(feature = "parallel")]
type PoolMemberResult = Result<Vec<u8>>;
#[cfg(feature = "parallel")]
type PoolResultIter = std::vec::IntoIter<PoolMemberResult>;

#[cfg(feature = "parallel")]
enum PoolResultPacket {
    Single(usize, PoolMemberResult),
    Batch(usize, PoolResultIter),
}

#[cfg(feature = "parallel")]
impl PoolResultPacket {
    fn start(&self) -> usize {
        match self {
            Self::Single(start, _) | Self::Batch(start, _) => *start,
        }
    }
}

/// Batch-granular out-of-order storage plus one cursor for the range currently
/// being emitted. Once a range reaches archive order, every later member in
/// that range is consumed without another channel receive or tree operation.
#[cfg(feature = "parallel")]
#[derive(Default)]
struct PoolResultReorder {
    pending: std::collections::BTreeMap<usize, PoolResultPacket>,
    ready: Option<(usize, PoolResultIter)>,
}

#[cfg(feature = "parallel")]
impl PoolResultReorder {
    fn next(
        &mut self,
        expected: usize,
        result_rx: &std::sync::mpsc::Receiver<PoolResultPacket>,
    ) -> Result<Vec<u8>> {
        loop {
            if let Some((next_seq, results)) = self.ready.as_mut() {
                if *next_seq != expected {
                    return Err(Error::InvalidHeader(
                        "RAR 5 member decode pool returned a non-contiguous batch",
                    ));
                }
                let result = results.next().ok_or(Error::InvalidHeader(
                    "RAR 5 member decode pool returned an empty batch",
                ))?;
                *next_seq += 1;
                if results.len() == 0 {
                    self.ready = None;
                }
                return result;
            }

            let packet = match self.pending.remove(&expected) {
                Some(packet) => packet,
                None => {
                    let packet = result_rx
                        .recv()
                        .map_err(|_| Error::InvalidHeader("RAR 5 member decode pool disconnected"))?;
                    let start = packet.start();
                    if start > expected {
                        if self.pending.insert(start, packet).is_some() {
                            return Err(Error::InvalidHeader(
                                "RAR 5 member decode pool returned a duplicate batch",
                            ));
                        }
                        continue;
                    }
                    if start < expected {
                        return Err(Error::InvalidHeader(
                            "RAR 5 member decode pool returned an overlapping batch",
                        ));
                    }
                    packet
                }
            };
            match packet {
                PoolResultPacket::Single(_, result) => return result,
                PoolResultPacket::Batch(start, results) => {
                    self.ready = Some((start, results));
                }
            }
        }
    }
}

/// One pooled member, resolved when the plan is built.
///
/// `Archive::files()` filters the block list, so it is not indexable:
/// recovering a member by ordinal walks the blocks from the start. The feeder
/// and every worker needed one member each, which made header lookup O(N²) in
/// the member count. Resolving once at plan time makes it O(1) per member.
#[cfg(feature = "parallel")]
struct PoolEntry<'a> {
    volume_index: usize,
    file: &'a FileHeader,
    unpacked_size: u64,
}

#[cfg(feature = "parallel")]
struct MemberPoolPlan<'a> {
    /// (volume_index, file_index) -> pool sequence number, archive order.
    seq_of: std::collections::HashMap<(usize, usize), usize>,
    /// Pool entries in feed order (archive order).
    order: Vec<PoolEntry<'a>>,
}

/// A member decodes on the pool when it is a regular compressed file that
/// does not engage the inline MT pipeline: not split, not stored, not a
/// directory or redirection, and either under the streaming threshold or in
/// the streaming band below the MT floor. Stored members stay inline (their
/// cost is I/O, not decode); MT-sized members stay inline (MT already uses
/// the cores; trap: a big member must not be stolen from inline-MT by the
/// pool).
#[cfg(feature = "parallel")]
fn member_pool_eligible(file: &FileHeader, buffered_decode_limit: u64) -> bool {
    file.redirection.is_none()
        && !file.is_split_before()
        && !file.is_split_after()
        && !file.is_directory()
        && !file.is_stored()
        && (!file.should_stream_decode(buffered_decode_limit)
            || pool_streaming_band(file.unpacked_size, buffered_decode_limit))
}

/// The streaming band the pool rescues: members that would stream SERIALLY
/// inline (above the buffered threshold, below the MT pipeline floor - 4 to
/// 16 MiB in release builds). They were the one size class with no
/// parallelism at all; a buffered pool decode under the in-flight budget is
/// strictly better than a serial inline stream. Members the MT pipeline
/// engages, and members too big to buffer at all, stay inline.
#[cfg(feature = "parallel")]
fn pool_streaming_band(unpacked_size: u64, buffered_decode_limit: u64) -> bool {
    unpacked_size <= buffered_decode_limit
        && usize::try_from(unpacked_size)
            .is_ok_and(|size| !Unpack50Decoder::mt_pipeline_engages(size))
}

/// Build the pool plan, or None when nothing pools: fewer than two eligible
/// members means a one-file archive must not pay any pool cost.
///
/// Solid ARCHIVES contribute no pooled members - their members share the
/// window and are handled by the chain/serial walk - but they no longer
/// disable the pool for the rest of a mixed set. Likewise a per-file solid
/// flag inside a non-solid archive makes THAT member ineligible (the serial
/// session decodes it against an empty window, exactly as the serial path
/// does, since history retention keys on the archive flag), not the whole
/// set: one stray solid member in a thousand-file set used to cost every
/// other member its parallelism.
#[cfg(feature = "parallel")]
fn member_pool_plan<'a>(
    volumes: &'a [Archive],
    options: crate::ArchiveReadOptions<'_>,
) -> Option<MemberPoolPlan<'a>> {
    let buffered_decode_limit = rar50_buffered_decode_limit(options);
    let mut seq_of = std::collections::HashMap::new();
    let mut order = Vec::new();
    for (volume_index, archive) in volumes.iter().enumerate() {
        if archive.main.is_solid() {
            continue;
        }
        for (file_index, file) in archive.files().enumerate() {
            if file
                .decoded_compression_info()
                .is_ok_and(|info| info.solid)
            {
                continue;
            }
            if member_pool_eligible(file, buffered_decode_limit) {
                seq_of.insert((volume_index, file_index), order.len());
                order.push(PoolEntry {
                    volume_index,
                    file,
                    unpacked_size: file.unpacked_size,
                });
            }
        }
    }
    (order.len() >= 2).then_some(MemberPoolPlan { seq_of, order })
}

/// Decode + verify one pooled member on a worker. Mirrors the serial
/// buffered branch of `write_file_to` for a non-solid member: fresh decoder,
/// integrity check, and the LzNoFilters retry against a fresh checkpoint
/// when the filtered output fails verification.
#[cfg(feature = "parallel")]
fn decode_pooled_member(
    archive: &Archive,
    file: &FileHeader,
    password: Option<&[u8]>,
    max_window: u64,
    reader_cache: &mut crate::source::RangeReaderCache,
) -> Result<Vec<u8>> {
    let fresh_decoder = || {
        let mut decoder = Unpack50Decoder::new();
        decoder.set_window_limit(usize::try_from(max_window).unwrap_or(usize::MAX));
        decoder.set_retain_history(false);
        decoder
    };
    let mut decoder = fresh_decoder();
    let decoded = file
        .decoded_data_with_decoder(archive, &mut decoder, password, reader_cache)
        .map_err(|error| file.entry_error("decoding", error))?;
    match file.verify_integrity_with_keys(&decoded.data, decoded.keys.as_ref()) {
        Ok(()) => Ok(decoded.data),
        Err(filtered_error) => {
            let mut unfiltered_decoder = fresh_decoder();
            let unfiltered = file
                .decoded_data_with_mode(
                    archive,
                    &mut unfiltered_decoder,
                    password,
                    DecodeMode::LzNoFilters,
                    reader_cache,
                )
                .map_err(|error| file.entry_error("decoding", error))?;
            file.verify_integrity_with_keys(&unfiltered.data, unfiltered.keys.as_ref())
                .map_err(|_| file.entry_error("verifying", filtered_error))?;
            Ok(unfiltered.data)
        }
    }
}

#[cfg(feature = "parallel")]
fn extract_volumes_pooled<F, R>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    open: &mut F,
    redirect: &mut R,
    emit_redirections: bool,
    plan: MemberPoolPlan,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    use std::sync::mpsc;
    use std::sync::{Arc, Condvar, Mutex};

    let password = options.password;
    let buffered_decode_limit = rar50_buffered_decode_limit(options);
    let max_window = rar50_max_window(options);
    let policy = rar50_execution_policy(options);
    let workers = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .saturating_sub(1)
        .clamp(1, 8)
        .min(policy.map_or(usize::MAX, |p| p.max_workers.max(1)))
        .min(plan.order.len());
    // A constrained policy also shrinks the in-flight allowance; it never
    // grows past the built-in budget, and the floor keeps one decoded
    // member of any admitted size able to make progress. The floor tracks
    // the cfg(test) shrunken budget so policy-carrying tests still exercise
    // constant backpressure.
    let inflight_budget = policy.map_or(POOL_INFLIGHT_BUDGET, |p| {
        let floor = POOL_INFLIGHT_BUDGET.min(8 << 20);
        POOL_INFLIGHT_BUDGET.min((p.working_memory_limit / 4).max(floor))
    });
    let work_batch_size = pool_work_batch_size(plan.order.len(), workers);
    let work_batch_byte_limit = inflight_budget / workers as u64;

    // in-flight budget: (bytes enqueued-or-decoded but not yet written, abort)
    let budget = Arc::new((Mutex::new((0u64, false)), Condvar::new()));
    // feeder -> workers; small buffer, the budget is the real regulator
    let (work_tx, work_rx) = mpsc::sync_channel::<std::ops::Range<usize>>(workers * 2);
    let work_rx = Arc::new(Mutex::new(work_rx));
    // workers -> coordinator
    let (result_tx, result_rx) = mpsc::channel::<PoolResultPacket>();

    let outcome = std::thread::scope(|scope| {
        // Feeder: pushes small ranges of pool sequence numbers in archive
        // order, blocking
        // while the in-flight byte budget is full. A single member larger
        // than the whole budget is still admitted alone (in_flight > 0
        // condition) so progress is always possible.
        {
            let budget = Arc::clone(&budget);
            let order = &plan.order;
            let work_tx = work_tx;
            scope.spawn(move || {
                let mut start = 0;
                while start < order.len() {
                    let (members, size) = pool_work_batch_shape(
                        order[start..].iter().map(|entry| entry.unpacked_size),
                        work_batch_size,
                        work_batch_byte_limit,
                    );
                    debug_assert!(members > 0);
                    let end = start + members;
                    let (lock, cvar) = &*budget;
                    let mut state = lock.lock().expect("pool budget lock");
                    while !state.1
                        && state.0 > 0
                        && state
                            .0
                            .checked_add(size)
                            .is_none_or(|charged| charged > inflight_budget)
                    {
                        state = cvar.wait(state).expect("pool budget wait");
                    }
                    if state.1 {
                        return; // coordinator aborted
                    }
                    state.0 = state
                        .0
                        .checked_add(size)
                        .expect("pool budget addition was guarded against overflow");
                    drop(state);
                    if work_tx.send(start..end).is_err() {
                        return; // workers gone (coordinator returned early)
                    }
                    start = end;
                }
            });
        }

        // Workers: decode + verify, results rejoin the coordinator. A panic
        // inside decode surfaces as an error result instead of deadlocking
        // the coordinator's recv.
        // Armed BEFORE the workers are spawned, not after: a `scope.spawn`
        // that panics (the OS refusing a thread) used to unwind out of this
        // closure with no guard in place at all, leaving the feeder parked on
        // the byte budget with nothing left to wake it.
        let _abort = crate::parallel::PoolAbortGuard::new(&budget);
        for _ in 0..workers {
            let work_rx = Arc::clone(&work_rx);
            let result_tx = result_tx.clone();
            let order = &plan.order;
            scope.spawn(move || {
                let mut reader_cache = crate::source::RangeReaderCache::default();
                loop {
                    let batch = match work_rx.lock().expect("pool work lock").recv() {
                        Ok(batch) => batch,
                        Err(_) => return,
                    };
                    let start = batch.start;
                    let batch_len = batch.len();
                    let mut decode = |seq: usize| {
                        let entry = &order[seq];
                        let archive = &volumes[entry.volume_index];
                        let file = entry.file;
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            decode_pooled_member(
                                archive,
                                file,
                                password,
                                max_window,
                                &mut reader_cache,
                            )
                        }))
                        .unwrap_or(Err(Error::InvalidHeader(
                            "RAR 5 member decode worker panicked",
                        )))
                    };
                    debug_assert!(batch_len <= POOL_WORK_BATCH_MAX);
                    if pool_result_batchable(batch.clone().map(|seq| order[seq].unpacked_size)) {
                        let packet = PoolResultPacket::Batch(
                            start,
                            batch.map(&mut decode).collect::<Vec<_>>().into_iter(),
                        );
                        if result_tx.send(packet).is_err() {
                            return; // coordinator gone
                        }
                    } else {
                        // Preserve the pre-result-batching publication shape
                        // for substantial work ranges: an early member can be
                        // written while this worker decodes the next one.
                        for seq in batch {
                            if result_tx
                                .send(PoolResultPacket::Single(seq, decode(seq)))
                                .is_err()
                            {
                                return; // coordinator gone
                            }
                        }
                    }
                }
            });
        }
        drop(result_tx);
        // ...and the work RECEIVER, the fifth instance of the pool-hang class
        // (181d06b8, 419c00ae, 48b21a0b). The feeder parks in TWO places and
        // the abort guard only covers one: it wakes a budget-condvar wait, but
        // a feeder blocked in `work_tx.send` on the full channel is woken only
        // by the channel disconnecting. Held here in the function frame, this
        // `Arc<Mutex<Receiver>>` outlives every worker, so if they all exit
        // (or die) the send never returns and `thread::scope` joins forever.
        // rar15_40's twin drops it inside the scope for exactly this reason.
        drop(work_rx);

        // Coordinator: the exact serial walk, with pooled members' bytes
        // pulled from the reorder map instead of decoded inline. Inline
        // members (stored, streaming/MT, splits) use the session as today.
        let mut results = PoolResultReorder::default();
        let mut split = SplitVolumeState::new();
        let mut session =
            DecoderSession::new_with_password(password, buffered_decode_limit, max_window)
                .with_policy(rar50_execution_policy(options))
                .with_split_fragment_digests(options.rar50_split_fragment_digests);
        // A mixed set can hold solid archives alongside the pooled ones;
        // their groups still chain through the MT pipeline here.
        let mut chain = SolidChainDriver::new();
        let mut run = || -> Result<()> {
            for (volume_index, archive) in volumes.iter().enumerate() {
                for (file_index, file) in archive.files().enumerate() {
                    match split.advance(file.is_split_before(), file.is_split_after()) {
                        SplitVolumeStep::Regular => {
                            if let Some(redirection) = &file.redirection {
                                if emit_redirections {
                                    redirect(&file.metadata(), redirection)?;
                                }
                                continue;
                            }
                            if chain.claim(
                                &mut session,
                                volumes,
                                archive,
                                (volume_index, file_index),
                                file,
                                &mut *open,
                            ) {
                                continue;
                            }
                            let meta = file.metadata();
                            if let Some(&seq) = plan.seq_of.get(&(volume_index, file_index)) {
                                let data = results.next(seq, &result_rx)?;
                                let mut writer = open(&meta)?;
                                writer
                                    .write_all(&data)
                                    .map_err(Error::from)
                                    .map_err(|error| file.entry_error("writing", error))?;
                                drop(writer);
                                let (lock, cvar) = &*budget;
                                let mut state = lock.lock().expect("pool budget lock");
                                // Credit exactly what the feeder charged, which is the
                                // declared size, not the decoded one: a member may
                                // legitimately decode short (a truncated payload with no
                                // integrity record yields no bytes at all), and crediting
                                // the shorter length would leak the difference until the
                                // feeder parked forever on a budget that never drains.
                                state.0 = state.0.saturating_sub(plan.order[seq].unpacked_size);
                                drop(state);
                                cvar.notify_all();
                            } else {
                                let mut writer = open(&meta)?;
                                if !meta.is_directory {
                                    session.write_file_to(archive, file, &mut writer)?;
                                }
                            }
                        }
                        SplitVolumeStep::Start => {
                            validate_split_fragment(file, password)?;
                            split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                        }
                        SplitVolumeStep::Continue(current) => {
                            validate_split_continuation_refs(current, file, password)?;
                            current.append(volume_index, file_index)?;
                        }
                        SplitVolumeStep::Finish(mut completed) => {
                            validate_split_continuation_refs(&completed, file, password)?;
                            completed.append(volume_index, file_index)?;
                            // The pool never runs under a consumption
                            // watermark, so there is nothing to report.
                            completed.write_to(volumes, file, &mut session, &mut *open, None)?;
                        }
                        SplitVolumeStep::MissingFirst => {
                            return Err(Error::InvalidHeader(
                                "RAR 5 split entry is missing its first part",
                            ));
                        }
                        SplitVolumeStep::Interrupted => {
                            return Err(Error::InvalidHeader(
                                "RAR 5 split entry is interrupted by a regular entry",
                            ));
                        }
                    }
                }
            }
            if split.is_pending() {
                return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
            }
            Ok(())
        };
        // `_abort` wakes the feeder out of any budget wait and lets every
        // thread drain; dropping result_rx (on scope exit) unblocks workers
        // mid-send.
        run()
    });
    outcome
}

fn validate_split_fragment(file: &FileHeader, password: Option<&[u8]>) -> Result<()> {
    if file.is_directory() {
        return Err(Error::InvalidHeader(
            "RAR 5 split directory entry is invalid",
        ));
    }
    if file.encrypted && password.is_none() && file.crypto.is_none() {
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
        return Err(Error::InvalidHeader("RAR 5 split entry name changed"));
    }
    if file.compression_info != pending.compression_info {
        return Err(Error::InvalidHeader(
            "RAR 5 split entry compression info changed",
        ));
    }
    if file.encrypted != pending.encrypted {
        return Err(Error::InvalidHeader(
            "RAR 5 split entry encryption flag changed",
        ));
    }
    Ok(())
}

struct PendingSplitRefs {
    name: Vec<u8>,
    fragments: Vec<(usize, usize)>,
    file_time: u32,
    attr: u64,
    host_os: u64,
    compression_info: u64,
    encrypted: bool,
}

impl PendingSplitRefs {
    fn new(file: &FileHeader, volume_index: usize, file_index: usize) -> Self {
        Self {
            name: file.name.clone(),
            fragments: vec![(volume_index, file_index)],
            file_time: file.mtime.unwrap_or(0),
            attr: file.attributes,
            host_os: file.host_os,
            compression_info: file.compression_info,
            encrypted: file.encrypted,
        }
    }

    fn append(&mut self, volume_index: usize, file_index: usize) -> Result<()> {
        // Strictly increasing volumes only: a crafted archive with two
        // fragments of one member in the same volume would let the
        // consumption watermark report that volume spent while a later
        // fragment still needs to reopen it by path - the caller may
        // have deleted it on the report. No real archiver splits a
        // member twice within one volume.
        if let Some(&(last_volume, _)) = self.fragments.last() {
            if volume_index <= last_volume {
                return Err(Error::InvalidHeader(
                    "RAR 5 split fragment does not advance to a later volume",
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
        session: &mut DecoderSession<'_>,
        open: &mut F,
        mut spent: Option<&mut (dyn FnMut(usize) + Send)>,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let decryptor = session.split_decryptor(&self, volumes)?;
        let meta = ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: false,
            unpacked_size: final_file.unpacked_size,
        };
        let mut writer = open(&meta)?;
        // A fragment digest mismatch reaches the decode paths below as the
        // io error the chain stopped on; the typed error it wraps names
        // the bad volume and is the one to report - bare, exactly as the
        // incremental path reports it through `take_error`.
        let fragment_error: SharedFragmentError = Default::default();
        // Hash each byte ONCE where the format allows it. The final
        // fragment's record is the member's verdict; the non-final
        // fragments' records only say WHICH volume broke a verdict that
        // has already failed. So skip them on the fast path and pay a
        // second read for the diagnosis, but only when both halves hold:
        // the member really does carry a whole-member digest (or nothing
        // would check these bytes at all), and nobody is releasing
        // volumes behind this read (`spent`), because a released volume
        // may be deleted and cannot be read twice.
        //
        // Three conditions, all mechanical, plus the caller's opt-in:
        // the member is STORED, so the two records really do cover the
        // same bytes (a compressed member's packed and unpacked digests
        // are two different checks); it carries a whole-member digest at
        // all, or nothing else would ever check these bytes; and nobody
        // is releasing volumes behind this read (`spent`), because a
        // released volume may be deleted and cannot be read twice.
        let digests = if session.split_fragment_digests
            == crate::Rar50SplitFragmentDigests::DeferForStoredMembers
            && final_file.is_stored()
            && spent.is_none()
            && final_file.has_whole_member_digest()
        {
            FragmentDigests::Defer
        } else {
            FragmentDigests::Check
        };
        let recover_fragment_error = |error: Error| {
            if let Some(fragment) = fragment_error.lock().unwrap().take() {
                return fragment;
            }
            if digests == FragmentDigests::Defer && is_member_digest_mismatch(&error) {
                if let Some(fragment) = self.localize_fragment_damage(volumes) {
                    return fragment;
                }
            }
            error
        };
        if final_file.is_stored() {
            // A stored split streams its fragments forward exactly once
            // (no retry path exists), so the consumption watermark is
            // safe unconditionally.
            return self
                .write_stored_to(
                    volumes,
                    final_file,
                    decryptor.as_ref(),
                    &mut writer,
                    spent,
                    &fragment_error,
                    digests,
                )
                .map_err(|error| final_file.entry_error("extracting", error))
                .map_err(recover_fragment_error);
        }

        // Stream large split members through the same pipelined decoder as
        // single-volume files (checksums verified in stream, no whole-member
        // buffer). Pathological filters bail to the buffered path below,
        // mirroring write_file_to.
        if final_file.should_stream_decode(session.buffered_decode_limit) {
            let solid = final_file
                .decoded_compression_info()
                .map_err(|error| final_file.entry_error("decoding", error))?
                .solid;
            let keys = decryptor.as_ref().map(|decryptor| &decryptor.keys);
            // The filter-bail retry below re-reads every fragment, so the
            // consumption watermark may only arm when that retry is
            // impossible - a member too big for the buffered path. Smaller
            // members release their volumes at the next volume boundary,
            // exactly as before.
            let watermark = if final_file.unpacked_size > session.buffered_decode_limit {
                spent.as_deref_mut().map(|f| {
                    Box::new(move |volume: usize| f(volume)) as Box<dyn FnMut(usize) + Send + '_>
                })
            } else {
                None
            };
            let mut reader = self
                .fragment_reader(
                    volumes,
                    decryptor.as_ref(),
                    watermark,
                    &fragment_error,
                    // Compressed: the two records cover different bytes.
                    FragmentDigests::Check,
                )
                .map_err(|error| final_file.entry_error("reading", error))?;
            let mut counting = CountingWriter {
                inner: &mut *writer,
                written: 0,
            };
            let stream_result = if solid {
                // Work on a clone so a failed stream leaves the session's
                // decoder (and its solid history) untouched for the retry.
                let mut streaming_decoder = session.decoder.clone();
                let result = final_file.stream_packed_with_decoder(
                    &mut reader,
                    keys,
                    &mut streaming_decoder,
                    session.member_flat_limit(final_file),
                    &mut counting,
                );
                if result.is_ok() {
                    session.decoder = streaming_decoder;
                }
                result
            } else {
                let flat_limit = session.member_flat_limit(final_file);
                final_file.stream_packed_with_decoder(
                    &mut reader,
                    keys,
                    &mut session.decoder,
                    flat_limit,
                    &mut counting,
                )
            };
            match stream_result {
                Ok(()) => return Ok(()),
                Err(error)
                    if counting.written == 0
                        && final_file.unpacked_size <= session.buffered_decode_limit
                        && is_streaming_filter_bail(&error) =>
                {
                    // Buffered retry below; a non-solid member must not see
                    // state the failed stream may have left behind. Through
                    // `fresh_decoder` so the retry (and every later member)
                    // keeps the caller's window and worker limits.
                    if !solid {
                        session.decoder = session.fresh_decoder();
                    }
                }
                Err(error) => {
                    return Err(recover_fragment_error(
                        final_file.entry_error("decoding", error),
                    ))
                }
            }
        }

        let data = session
            .decode_split(
                volumes,
                &self,
                final_file,
                decryptor.as_ref(),
                &fragment_error,
            )
            .map_err(|error| final_file.entry_error("decoding", error))
            .map_err(recover_fragment_error)?;
        final_file
            .verify_integrity_with_keys(&data, decryptor.as_ref().map(|decryptor| &decryptor.keys))
            .map_err(|error| final_file.entry_error("verifying", error))
            // The buffered path verifies the member HERE rather than in
            // stream, so this is where a deferred set's damage surfaces.
            .map_err(recover_fragment_error)?;
        writer
            .write_all(&data)
            .map_err(Error::from)
            .map_err(|error| final_file.entry_error("writing", error))?;
        Ok(())
    }

    fn write_stored_to(
        &self,
        volumes: &[Archive],
        final_file: &FileHeader,
        decryptor: Option<&SplitDecryptor>,
        writer: &mut dyn Write,
        spent: Option<&mut (dyn FnMut(usize) + Send)>,
        fragment_error: &SharedFragmentError,
        digests: FragmentDigests,
    ) -> Result<()> {
        let spent = spent.map(|f| {
            Box::new(move |volume: usize| f(volume)) as Box<dyn FnMut(usize) + Send + '_>
        });
        // The chained reader stays RAW here; the cipher rides into the pipe
        // as its own stage (one CBC chain runs unbroken across fragment
        // seams, so the split needs nothing seam-aware).
        let mut reader = self.fragment_reader(volumes, None, spent, fragment_error, digests)?;
        let cipher = decryptor.map(|d| Rar50Cipher::new(d.keys.key, d.iv));
        let crc = Crc32::new();
        let hash = streaming_hash_verifier(final_file)?;
        let mut written = 0u64;
        let mut discarded = 0u64;

        // Same bounded pipeline as the non-split stored path; the split
        // caller wraps every error as "extracting", so the per-chunk
        // operation label is dropped rather than double-wrapped.
        let (crc, hash) = pipe_stored_chunks(
            &mut *reader,
            cipher,
            final_file.unpacked_size,
            Error::from,
            crc,
            hash,
            |buf| {
                final_file
                    .consume_stored_chunk(buf, &mut written, &mut discarded, writer)
                    .map_err(|(_operation, error)| error)
            },
        )?;

        if written != final_file.unpacked_size {
            return Err(Error::InvalidHeader(
                "RAR 5 stored split file has mismatched packed and unpacked sizes",
            ));
        }
        // Checksums are MAC-converted only when the encryption record's
        // 0x0002 flag says so (`uses_hash_mac`) - `encrypted` alone is the
        // wrong test: header-encrypted (-hp) members are encrypted but
        // store PLAIN checksums unless the flag is set, and MACing them
        // anyway failed verification on byte-perfect output. Mirrors
        // verify_streaming_integrity / verify_integrity_with_keys.
        if let Some(expected) = final_file.data_crc32 {
            let actual = if final_file.uses_hash_mac() {
                let decryptor = decryptor.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted split CRC needs encryption keys",
                ))?;
                decryptor.keys.mac_crc32(crc.finish())
            } else {
                crc.finish()
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }
        if let Some((expected, hasher)) = hash {
            let actual = if final_file.uses_hash_mac() {
                let decryptor = decryptor.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted split hash needs encryption keys",
                ))?;
                decryptor.keys.mac_hash32(hasher.finalize())
            } else {
                hasher.finalize()
            };
            if !constant_time_eq(&expected, &actual) {
                return Err(Error::HashMismatch { hash_type: 0 });
            }
        }
        Ok(())
    }

    fn split_decryptor(
        &self,
        volumes: &[Archive],
        password: Option<&[u8]>,
    ) -> Result<Option<SplitDecryptor>> {
        if !self.encrypted {
            return Ok(None);
        }
        let (volume_index, file_index) = self.fragments[0];
        let archive = volumes
            .get(volume_index)
            .ok_or(Error::InvalidHeader("RAR 5 split volume is missing"))?;
        let file = archive
            .files()
            .nth(file_index)
            .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
        let keys = file
            .crypto_with_password(password)?
            .ok_or(Error::InvalidHeader(
                "RAR 5 encrypted split file is missing encryption keys",
            ))?;
        Ok(Some(SplitDecryptor {
            keys,
            iv: file.encryption_iv()?,
        }))
    }

    /// Read the packed bytes again, hashing only the per-fragment
    /// records, and name the first fragment whose own header says it is
    /// damaged. Called ONLY after the member's whole-member digest has
    /// already failed under [`FragmentDigests::Defer`], so that a
    /// deferred set still reports the unrar-parity
    /// [`Error::SplitFragmentCrc32Mismatch`] /
    /// [`Error::SplitFragmentHashMismatch`] naming the volume.
    ///
    /// The chain that carries these digests sits INSIDE any decryptor, so
    /// this reads the stored bytes raw and needs no password. Anything
    /// that stops it - a volume gone since the first pass, a short read -
    /// returns `None` and leaves the caller's original error standing:
    /// this is a diagnosis, and a diagnosis that cannot be made must not
    /// replace the finding it was meant to explain.
    fn localize_fragment_damage(&self, volumes: &[Archive]) -> Option<Error> {
        for &(volume_index, file_index) in &self.fragments {
            let file = volumes.get(volume_index)?.files().nth(file_index)?;
            let expected = match file.split_fragment_packed_digests() {
                Some(expected) => expected,
                None => continue,
            };
            let mut digest = FragmentDigest::new(expected, volume_index);
            let mut reader = volumes[volume_index]
                .range_reader(file.block.data_range.clone())
                .ok()?;
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(count) => digest.update(&buf[..count]),
                    Err(_) => return None,
                }
            }
            if let Err(error) = digest.verify() {
                return Some(error);
            }
        }
        None
    }

    fn fragment_reader<'r>(
        &self,
        volumes: &'r [Archive],
        decryptor: Option<&SplitDecryptor>,
        spent: Option<Box<dyn FnMut(usize) + Send + 'r>>,
        fragment_error: &SharedFragmentError,
        digests: FragmentDigests,
    ) -> Result<Box<dyn Read + Send + 'r>> {
        // Fragment METADATA validates eagerly (a missing volume or entry
        // still surfaces before any output is written), but at most ONE
        // fragment is OPEN at a time: a file-backed range reader holds a
        // descriptor, and opening every fragment up front exhausted the
        // default 256-descriptor limit on real p99 sets (500-1,200
        // volumes). The single decrypting reader stays OUTSIDE the lazy
        // sequence so CBC state runs unbroken across fragment seams -
        // which also means the chain digests each fragment's STORED
        // bytes, exactly what the per-fragment records cover.
        let mut fragments = Vec::with_capacity(self.fragments.len());
        for &(volume_index, file_index) in &self.fragments {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 5 split volume is missing"))?;
            let file = archive
                .files()
                .nth(file_index)
                .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
            fragments.push((
                volume_index,
                file.block.data_range.clone(),
                match digests {
                    FragmentDigests::Check => file.split_fragment_packed_digests(),
                    FragmentDigests::Defer => None,
                },
            ));
        }
        let chained = LazyChainedReader {
            volumes,
            fragments,
            next: 0,
            current: None,
            digest: None,
            fragment_error: std::sync::Arc::clone(fragment_error),
            failed: false,
            spent,
        };
        if let Some(decryptor) = decryptor {
            Ok(Box::new(Rar50DecryptingReader::new(
                chained,
                decryptor.keys.key,
                decryptor.iv,
            )))
        } else {
            Ok(Box::new(chained))
        }
    }
}

/// Whether the split chain hashes each fragment's packed bytes as it
/// reads them, or leaves that to a second pass taken only when the
/// member's own digest has already gone against it.
///
/// (nzbfast-local change, 3 Sep 2026 - re-apply on the next rars re-sync,
/// see vendor/rars/VENDORING.md.)
///
/// The per-fragment records are unrar's damage LOCALIZER, not the
/// verdict: a member whose FINAL digest proves cannot have had a bad
/// fragment, so on a sound set every one of those hashes is work whose
/// answer was already known. On a `-htb` set they are a second whole
/// BLAKE2sp pass over every byte, on the producer thread, in series with
/// the read - measured on an M3 Ultra over a 1 GiB stored `-v50m` member,
/// audit round 25.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FragmentDigests {
    /// Hash and check every fragment as it reads, failing at the bad
    /// volume. The only choice when the member carries no whole-member
    /// digest of its own (nothing else would ever check these bytes), and
    /// when the caller is releasing volumes behind the read and so cannot
    /// be asked to read one a second time.
    Check,
    /// Do not hash the fragments at all. A failure is localized
    /// afterwards by [`PendingSplitRefs::localize_fragment_damage`],
    /// which re-reads the packed bytes - one extra pass, on a set that is
    /// already going to repair.
    Defer,
}

/// The digests a non-final split fragment's PACKED bytes must produce,
/// when its own header carries them - see
/// [`FileHeader::split_fragment_packed_digests`].
#[derive(Clone, Copy)]
struct SplitFragmentDigests {
    crc32: Option<u32>,
    blake2: Option<[u8; 32]>,
}

impl FileHeader {
    /// The digests this fragment's PACKED bytes must produce, when the
    /// header carries them. WinRAR stamps every NON-final fragment of a
    /// split member with the digest of that fragment's stored bytes -
    /// CRC32 and/or BLAKE2sp, whichever the set uses; the raw CIPHERTEXT
    /// for encrypted members, and never MAC-keyed (the encryption
    /// record's 0x0002 flag is per fragment and WinRAR sets it only on
    /// the final one) - while the FINAL fragment carries the whole
    /// member's unpacked digests. unrar checks it at every volume
    /// boundary (UIERROR_CHECKSUMPACKED), which is what localizes damage
    /// to one volume instead of failing the member at its end; both
    /// split walks do the same. Measured on the WinRAR 7.21 rar50
    /// multivolume fixtures (plain, solid, encrypted, .rev) and rar
    /// 7.23-written sets in both digest flavors, plain, -p and -hp. The
    /// rars writer stamps no records on non-final fragments, so its sets
    /// simply have nothing to check before the finish.
    ///
    /// A ciphertext digest is checkable without the password, and a
    /// mismatch proves on-disk damage - never a wrong-password symptom.
    fn split_fragment_packed_digests(&self) -> Option<SplitFragmentDigests> {
        if !self.is_split_after() || self.uses_hash_mac() {
            return None;
        }
        let blake2 = self.hash.as_ref().and_then(|hash| {
            (hash.hash_type == 0 && hash.data.len() == 32).then(|| {
                let mut expected = [0u8; 32];
                expected.copy_from_slice(&hash.data);
                expected
            })
        });
        if self.data_crc32.is_none() && blake2.is_none() {
            return None;
        }
        Some(SplitFragmentDigests {
            crc32: self.data_crc32,
            blake2,
        })
    }
}

/// Running digests over one fragment's packed bytes, verified when the
/// fragment reads out. This is what fails a damaged set at the first bad
/// volume, naming it, instead of decoding the whole member and failing
/// on the final unpacked digest.
struct FragmentDigest {
    expected: SplitFragmentDigests,
    crc: Crc32,
    hasher: Option<blake2sp::Hasher>,
    volume: usize,
}

impl FragmentDigest {
    fn new(expected: SplitFragmentDigests, volume: usize) -> Self {
        Self {
            expected,
            crc: Crc32::new(),
            hasher: expected.blake2.is_some().then(blake2sp::Hasher::new),
            volume,
        }
    }

    fn update(&mut self, data: &[u8]) {
        if self.expected.crc32.is_some() {
            self.crc.update(data);
        }
        if let Some(hasher) = self.hasher.as_mut() {
            hasher.update(data);
        }
    }

    fn verify(self) -> Result<()> {
        if let Some(expected) = self.expected.crc32 {
            let actual = self.crc.finish();
            if actual != expected {
                return Err(Error::SplitFragmentCrc32Mismatch {
                    volume: self.volume,
                    expected,
                    actual,
                });
            }
        }
        if let (Some(expected), Some(hasher)) = (self.expected.blake2, self.hasher) {
            if !constant_time_eq(&expected, &hasher.finalize()) {
                return Err(Error::SplitFragmentHashMismatch {
                    volume: self.volume,
                });
            }
        }
        Ok(())
    }
}

/// The typed error behind the io error [`LazyChainedReader`] hands the
/// decoder on a fragment digest mismatch - `Read::read` has no other
/// channel, and the whole-set walk recovers it after the decode stops
/// (the incremental path has [`GrowingChainedReader::take_error`] for
/// the same job).
type SharedFragmentError = std::sync::Arc<std::sync::Mutex<Option<Error>>>;

/// Sequential reader over a split entry's fragments that opens each
/// fragment only when the previous one is exhausted, and drops it before
/// opening the next - one descriptor in flight regardless of volume
/// count. An open failure surfaces at the seam it belongs to, as an
/// ordinary read error.
struct LazyChainedReader<'a> {
    volumes: &'a [Archive],
    /// (volume index, data range, expected packed digests), validated at
    /// construction.
    fragments: Vec<(usize, std::ops::Range<usize>, Option<SplitFragmentDigests>)>,
    next: usize,
    current: Option<Box<dyn Read + Send + 'a>>,
    /// Running digests over the fragment `current` reads, when its own
    /// header says what its packed bytes must hash to. The chain sits
    /// INSIDE any decryptor, so these run over the stored bytes.
    digest: Option<FragmentDigest>,
    /// Typed-error channel to the walk holding the other end.
    fragment_error: SharedFragmentError,
    /// Keep failing on any read after a mismatch: a caller that
    /// swallowed the first error must not see a clean EOF, advance the
    /// chain and finish the member as if the fragment were sound.
    failed: bool,
    /// Fires with the volume index of each fragment read to its end -
    /// except the LAST fragment, whose volume carries the members after
    /// the split one and stays live. A middle fragment is the only file
    /// entry of its volume, so exhausting it proves the whole volume is
    /// finished with; the caller arms this only on paths that never read
    /// a fragment twice (see `PendingSplitRefs::write_to`). Runs on
    /// whichever thread drives the read, hence `Send`. Boxed because a
    /// `&mut dyn` hook's trait-object lifetime is invariant and refuses
    /// to shrink alongside the volumes borrow.
    spent: Option<Box<dyn FnMut(usize) + Send + 'a>>,
}

impl Read for LazyChainedReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.failed {
            return Err(std::io::Error::other(
                "RAR 5 split fragment packed data digest mismatch",
            ));
        }
        // An empty read must not look like fragment EOF: it would advance
        // the chain past unread bytes - and, with the watermark armed,
        // report a volume spent that is still needed.
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(reader) = self.current.as_mut() {
                let read = reader.read(out)?;
                if read != 0 {
                    if let Some(digest) = self.digest.as_mut() {
                        digest.update(&out[..read]);
                    }
                    return Ok(read);
                }
                self.current = None;
                // The fragment is read out; its own header says what its
                // packed bytes must hash to. Checked BEFORE the volume is
                // reported spent - the caller may act on that report.
                if let Some(digest) = self.digest.take() {
                    if let Err(error) = digest.verify() {
                        self.failed = true;
                        let message = error.to_string();
                        *self.fragment_error.lock().unwrap() = Some(error);
                        return Err(std::io::Error::other(message));
                    }
                }
                // The fragment just exhausted is `next - 1`; report its
                // volume unless it is the chain's last.
                if self.next < self.fragments.len() {
                    if let Some(spent) = self.spent.as_mut() {
                        spent(self.fragments[self.next - 1].0);
                    }
                }
            }
            let Some((volume_index, range, expected)) = self.fragments.get(self.next) else {
                return Ok(0);
            };
            self.next += 1;
            self.digest = (*expected).map(|expected| FragmentDigest::new(expected, *volume_index));
            let reader = self.volumes[*volume_index]
                .range_reader(range.clone())
                .map_err(std::io::Error::other)?;
            self.current = Some(reader);
        }
    }
}

struct SplitDecryptor {
    keys: Rar50Keys,
    iv: [u8; 16],
}

fn streaming_hash_verifier(file: &FileHeader) -> Result<Option<([u8; 32], blake2sp::Hasher)>> {
    let Some(hash) = &file.hash else {
        return Ok(None);
    };
    match hash.hash_type {
        0 if hash.data.len() == 32 => {
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&hash.data);
            Ok(Some((expected, blake2sp::Hasher::new())))
        }
        0 => Err(Error::InvalidHeader(
            "RAR 5 BLAKE2sp hash record has invalid length",
        )),
        _ => Ok(None),
    }
}

fn checked_unpacked_size(size: u64) -> Result<usize> {
    usize::try_from(size)
        .map_err(|_| Error::InvalidHeader("RAR 5 unpacked size overflows host address size"))
}

/// Is this the member's own digest failing - the one failure that a
/// deferred set can explain by naming a volume? Peels the entry and
/// offset wrappers `entry_error` adds.
fn is_member_digest_mismatch(error: &Error) -> bool {
    match error {
        Error::Crc32Mismatch { .. } | Error::HashMismatch { .. } => true,
        Error::AtEntry { source, .. } | Error::AtArchiveOffset { source, .. } => {
            is_member_digest_mismatch(source)
        }
        _ => false,
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&left, &right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

impl FileHeader {
    fn decode_split_with_decoder(
        &self,
        volumes: &[Archive],
        split: &PendingSplitRefs,
        decoder: &mut Unpack50Decoder,
        decryptor: Option<&SplitDecryptor>,
        fragment_error: &SharedFragmentError,
    ) -> Result<Vec<u8>> {
        // The buffered path never defers: `write_to` sends every stored
        // split down `write_stored_to`, so a member reaching here is
        // compressed, and its packed and unpacked digests then cover
        // DIFFERENT bytes - two checks, not one done twice.
        let digests = FragmentDigests::Check;
        if self.is_stored() {
            let mut data = Vec::new();
            let mut reader =
                split.fragment_reader(volumes, decryptor, None, fragment_error, digests)?;
            reader.read_to_end(&mut data)?;
            if data.len() as u64 != self.unpacked_size {
                return Err(Error::InvalidHeader(
                    "RAR 5 stored split file has mismatched packed and unpacked sizes",
                ));
            }
            return Ok(data);
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let mut reader =
            split.fragment_reader(volumes, decryptor, None, fragment_error, digests)?;
        let output_size = checked_unpacked_size(self.unpacked_size)?;
        decoder
            .decode_member_from_reader_with_dictionary(
                &mut reader,
                info.algorithm_version,
                output_size,
                dictionary_size,
                info.solid,
                DecodeMode::Lz,
            )
            .map_err(Error::from)
    }
}

struct Rar50DecryptingReader<R> {
    inner: R,
    cipher: Rar50Cipher,
    // Whole-block window: reading and decrypting 16 bytes at a time costs a
    // syscall plus a cipher dispatch per AES block; this batches both.
    buffer: Vec<u8>,
    pos: usize,
    len: usize,
}

const DECRYPT_WINDOW_BYTES: usize = 64 * 1024;

impl<R: Read> Rar50DecryptingReader<R> {
    fn new(inner: R, key: [u8; 32], iv: [u8; 16]) -> Self {
        Self::with_cipher(inner, Rar50Cipher::new(key, iv))
    }

    fn with_cipher(inner: R, cipher: Rar50Cipher) -> Self {
        Self {
            inner,
            cipher,
            buffer: vec![0; DECRYPT_WINDOW_BYTES],
            pos: 0,
            len: 0,
        }
    }

    fn fill_buffer(&mut self) -> std::io::Result<bool> {
        let read = fill_ciphertext(&mut self.inner, &mut self.buffer)?;
        if read == 0 {
            return Ok(false);
        }
        decrypt_slice(&mut self.cipher, &mut self.buffer[..read])?;
        self.pos = 0;
        self.len = read;
        Ok(true)
    }

    fn drain_buffered(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.len - self.pos);
        out[..count].copy_from_slice(&self.buffer[self.pos..self.pos + count]);
        self.pos += count;
        count
    }
}

impl<R: Read> Read for Rar50DecryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        // Leftover plaintext from an earlier sub-block request goes out
        // first, so direct reads never reorder against the window.
        if self.pos < self.len {
            return Ok(self.drain_buffered(out));
        }
        let direct = out.len() & !15;
        if direct == 0 {
            // Sub-block request: decrypt a whole window internally and
            // serve from it.
            if !self.fill_buffer()? {
                return Ok(0);
            }
            return Ok(self.drain_buffered(out));
        }
        // Whole AES blocks decrypt straight into the caller's buffer - the
        // internal window would only add a plaintext copy per byte.
        let read = fill_ciphertext(&mut self.inner, &mut out[..direct])?;
        if read == 0 {
            return Ok(0);
        }
        decrypt_slice(&mut self.cipher, &mut out[..read])?;
        Ok(read)
    }
}

fn decrypt_slice(cipher: &mut Rar50Cipher, data: &mut [u8]) -> std::io::Result<()> {
    cipher
        .decrypt_in_place(data)
        .map_err(super::map_rar50_crypto_error)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

/// Read ciphertext into `target` until it is full or the stream ends,
/// riding across short reads (fragment seams deliver them). The total must
/// end AES-block aligned; a trailing partial block is a truncated stream.
fn fill_ciphertext(inner: &mut dyn Read, target: &mut [u8]) -> std::io::Result<usize> {
    let mut read = 0;
    while read < target.len() {
        let count = inner.read(&mut target[read..])?;
        if count == 0 {
            break;
        }
        read += count;
    }
    if read != 0 && !read.is_multiple_of(16) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated RAR 5 encrypted stream",
        ));
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::super::{
        ArchiveSource, Block, BlockHeader, CompressedEntry, FileEncryption, FileHash, FilterKind,
        FilterPolicy, MainHeader, Rar50Writer, WriterOptions, HEAD_FILE, HFL_SPLIT_AFTER,
        HFL_SPLIT_BEFORE,
    };
    use super::*;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;
    use std::sync::Arc;

    fn plain_file(name: &[u8], data: &[u8], hash: Option<FileHash>) -> FileHeader {
        FileHeader {
            block: empty_block(HEAD_FILE, 0, 0..0),
            file_flags: 0,
            unpacked_size: data.len() as u64,
            attributes: 0x20,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 2,
            name: name.to_vec(),
            hash,
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        }
    }

    /// The per-fragment packed digest gate: NON-final fragments only,
    /// never when the record is MAC-keyed, and only records that are
    /// actually present and well formed.
    #[test]
    fn split_fragment_packed_digests_apply_to_nonfinal_unkeyed_fragments_only() {
        let hash = FileHash {
            hash_type: 0,
            data: vec![0xab; 32],
        };
        let mut middle = plain_file(b"a.bin", b"data", Some(hash));
        middle.block.flags = HFL_SPLIT_BEFORE | HFL_SPLIT_AFTER;
        middle.data_crc32 = Some(0x1234_5678);
        let digests = middle
            .split_fragment_packed_digests()
            .expect("middle fragment carries digests");
        assert_eq!(digests.crc32, Some(0x1234_5678));
        assert_eq!(digests.blake2, Some([0xab; 32]));

        let mut last = middle.clone();
        last.block.flags = HFL_SPLIT_BEFORE;
        assert!(last.split_fragment_packed_digests().is_none());

        // The 0x0002 encryption flag keys the digests; WinRAR sets it only
        // on final fragments, and a keyed record is not checkable here.
        let mut keyed = middle.clone();
        keyed.encryption = Some(FileEncryption {
            version: 0,
            flags: 0x0002,
            kdf_count: 15,
            salt: [0; 16],
            iv: [0; 16],
            check_value: None,
        });
        assert!(keyed.split_fragment_packed_digests().is_none());

        let mut unstamped = middle.clone();
        unstamped.data_crc32 = None;
        unstamped.hash = None;
        assert!(unstamped.split_fragment_packed_digests().is_none());

        // A malformed hash record length never becomes a check; the
        // final-fragment verify paths are the ones that error on it.
        let mut short_hash = middle.clone();
        short_hash.data_crc32 = None;
        short_hash.hash = Some(FileHash {
            hash_type: 0,
            data: vec![0xab; 16],
        });
        assert!(short_hash.split_fragment_packed_digests().is_none());
    }

    /// The two real fixture sets the split-hash-seeding tests drive, and
    /// the shapes they carry (asserted in
    /// `rar50_split_hash_seeding_reads_the_first_fragment`): the WinRAR
    /// `-htb` set stamps a BLAKE2sp record on EVERY fragment and carries
    /// no CRC32 at all, while rar 7.23's DEFAULT set carries CRC32
    /// everywhere and no BLAKE2sp anywhere - which is what a posted set
    /// normally is, and so the set that was paying a whole-payload
    /// BLAKE2sp nothing could ever check.
    const HTB_SPLIT_SET: [&str; 3] = [
        "multivol.part1.rar",
        "multivol.part2.rar",
        "multivol.part3.rar",
    ];
    /// rar's `-p` set: BLAKE2sp records throughout, the finish
    /// fragment's MAC-keyed and the earlier ones not.
    const ENCRYPTED_SPLIT_SET: [&str; 3] = [
        "encrypted_multivol.part1.rar",
        "encrypted_multivol.part2.rar",
        "encrypted_multivol.part3.rar",
    ];
    const CRC32_SPLIT_SET: [&str; 5] = [
        "crc32_multivol.part01.rar",
        "crc32_multivol.part02.rar",
        "crc32_multivol.part03.rar",
        "crc32_multivol.part04.rar",
        "crc32_multivol.part05.rar",
    ];

    fn split_fixture_set(names: &[&str]) -> Vec<Archive> {
        names
            .iter()
            .map(|name| {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/rar50")
                    .join(name);
                let bytes = std::fs::read(&path).expect("fixture is readable");
                Archive::parse(&bytes).expect("fixture parses")
            })
            .collect()
    }

    /// Edit one volume's split-member header. The seeding decision is made
    /// from header records, and no single writer produces every
    /// combination of them, so the disagreement shapes are built by
    /// editing parsed headers rather than by finding a fixture.
    fn edit_split_header(archive: &mut Archive, edit: impl FnOnce(&mut FileHeader)) {
        for block in &mut archive.blocks {
            if let Block::File(file) = block {
                edit(file);
                return;
            }
        }
        panic!("volume carries no file header");
    }

    fn split_header(archive: &Archive) -> &FileHeader {
        archive.files().next().expect("volume carries a file header")
    }

    fn corrupt_blake2sp(file: &mut FileHeader) {
        file.hash
            .as_mut()
            .expect("header carries a BLAKE2sp record")
            .data[0] ^= 0xff;
    }

    fn seeding_options<'a>(
        seeding: crate::Rar50SplitHashSeeding,
    ) -> crate::ArchiveReadOptions<'a> {
        seeding_options_with_password(seeding, None)
    }

    fn seeding_options_with_password(
        seeding: crate::Rar50SplitHashSeeding,
        password: Option<&[u8]>,
    ) -> crate::ArchiveReadOptions<'_> {
        crate::ArchiveReadOptions::with_optional_password(password)
            .with_rar50_split_hash_seeding(seeding)
    }

    /// Run a parsed volume set through `extract_volume_sequence_to_with_progress`
    /// - the only caller of `incremental_split_decode` - and return the
    /// single split member's bytes.
    fn sequence_split_member(
        archives: Vec<Archive>,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Vec<u8>> {
        struct SharedWriter(Rc<RefCell<Vec<u8>>>);

        impl Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut archives: Vec<Option<Archive>> = archives.into_iter().map(Some).collect();
        let out = Rc::new(RefCell::new(Vec::new()));
        let sink = Rc::clone(&out);
        extract_volume_sequence_to_with_progress(
            |index| Ok(archives.get_mut(index).and_then(Option::take)),
            options,
            |_meta| Ok(Box::new(SharedWriter(Rc::clone(&sink))) as Box<dyn Write>),
            |_, _| {},
        )?;
        let bytes = out.borrow().clone();
        Ok(bytes)
    }

    /// The extractor labels a verification failure with the entry it
    /// happened on; the tests below care about the failure itself.
    fn at_entry_source(error: Error) -> Error {
        match error {
            Error::AtEntry { source, .. } => *source,
            other => other,
        }
    }

    fn both_seedings() -> [crate::Rar50SplitHashSeeding; 2] {
        [
            crate::Rar50SplitHashSeeding::Unconditional,
            crate::Rar50SplitHashSeeding::FirstFragment,
        ]
    }

    /// What the seeding reads, and that reading it changes no output.
    ///
    /// The shape assertions are the load-bearing half: `FirstFragment` is
    /// exact only because both measured writers make the FIRST fragment
    /// and the FINISH fragment agree about whether a BLAKE2sp record
    /// exists. If a fixture ever stops matching this, the seeding's
    /// premise has stopped holding, not the test.
    #[test]
    fn rar50_split_hash_seeding_reads_the_first_fragment() {
        let htb = split_fixture_set(&HTB_SPLIT_SET);
        for (index, archive) in htb.iter().enumerate() {
            let file = split_header(archive);
            assert!(
                file.hash.is_some(),
                "the -htb set stamps every fragment, including {index}"
            );
            assert!(file.data_crc32.is_none(), "-htb replaces the CRC32");
        }
        let crc32 = split_fixture_set(&CRC32_SPLIT_SET);
        for (index, archive) in crc32.iter().enumerate() {
            let file = split_header(archive);
            assert!(
                file.hash.is_none(),
                "the default set records no BLAKE2sp on fragment {index}"
            );
            assert!(file.data_crc32.is_some(), "the default set records CRC32");
        }

        // Both sets must genuinely reach the growing-chain decode, or
        // these tests measure the whole-set walk instead.
        for archive in [&htb[0], &crc32[0]] {
            let file = split_header(archive);
            assert!(!file.is_stored(), "fixture member must be compressed");
            assert!(
                file.should_stream_decode(BUFFERED_DECODE_LIMIT),
                "fixture member must take the streaming path"
            );
        }

        // The encrypted set rides along because that is where the hash
        // record's MAC keying lives: its non-final fragments carry a
        // PLAIN ciphertext digest and only the finish fragment is keyed,
        // so the seeding still reads a record on the first fragment.
        let sets: [(&[&str], Option<&[u8]>); 3] = [
            (&HTB_SPLIT_SET[..], None),
            (&CRC32_SPLIT_SET[..], None),
            (&ENCRYPTED_SPLIT_SET[..], Some(b"password")),
        ];
        for (names, password) in sets {
            let mut bytes = Vec::new();
            for seeding in both_seedings() {
                bytes.push(
                    sequence_split_member(
                        split_fixture_set(names),
                        seeding_options_with_password(seeding, password),
                    )
                    .expect("intact set extracts"),
                );
            }
            assert!(!bytes[0].is_empty());
            assert_eq!(bytes[0], bytes[1], "seeding must not change output bytes");
        }
    }

    /// A `-htb` set keeps its BLAKE2sp verification byte for byte: its
    /// first fragment carries a record, so `FirstFragment` seeds the
    /// hasher exactly as `Unconditional` does.
    #[test]
    fn rar50_split_hash_seeding_keeps_htb_verification() {
        for seeding in both_seedings() {
            let mut set = split_fixture_set(&HTB_SPLIT_SET);
            let last = set.len() - 1;
            edit_split_header(&mut set[last], corrupt_blake2sp);
            let error = at_entry_source(
                sequence_split_member(set, seeding_options(seeding))
                    .expect_err("a wrong expected digest must fail"),
            );
            assert!(
                matches!(error, Error::HashMismatch { hash_type: 0 }),
                "{seeding:?}: {error:?}"
            );
        }
    }

    /// An unstamped set is still verified - by the CRC32 the finish
    /// fragment carries, which is the only whole-member record it has.
    #[test]
    fn rar50_split_hash_seeding_leaves_crc32_verification_alone() {
        for seeding in both_seedings() {
            let mut set = split_fixture_set(&CRC32_SPLIT_SET);
            let last = set.len() - 1;
            edit_split_header(&mut set[last], |file| {
                file.data_crc32 = Some(file.data_crc32.expect("finish fragment has a CRC32") ^ 1);
            });
            let error = at_entry_source(
                sequence_split_member(set, seeding_options(seeding))
                    .expect_err("a wrong expected CRC32 must fail"),
            );
            assert!(
                matches!(error, Error::Crc32Mismatch { .. }),
                "{seeding:?}: {error:?}"
            );
        }
    }

    /// The case the seeding comment is written for: fragments that
    /// DISAGREE about whether a hash record exists.
    ///
    /// Shape one is the rars writer's - a record on the finish fragment
    /// only - and it is the whole reason `Unconditional` is the default
    /// and has to stay it: the decode has no way to learn about that
    /// record before it has streamed the payload past. `FirstFragment`
    /// declines the digest on such a set and the member is left to its
    /// CRC32, which is the trade that setting names.
    ///
    /// Shape two - records on the earlier fragments but none on the
    /// finish - has never had a whole-member digest to check under either
    /// setting (the expected value is the LAST fragment's), and the
    /// per-fragment packed digests those earlier records really are still
    /// fire, so damage is still caught and still localized to its volume.
    #[test]
    fn rar50_split_hash_seeding_on_fragments_that_disagree() {
        let payload = sequence_split_member(
            split_fixture_set(&CRC32_SPLIT_SET),
            seeding_options(crate::Rar50SplitHashSeeding::Unconditional),
        )
        .expect("intact set extracts");
        let digest = blake2sp::hash(&payload);

        // Shape one: a BLAKE2sp on the FINISH fragment and nowhere else.
        let finish_only = |expected: [u8; 32]| {
            let mut set = split_fixture_set(&CRC32_SPLIT_SET);
            let last = set.len() - 1;
            edit_split_header(&mut set[last], |file| {
                file.hash = Some(FileHash {
                    hash_type: 0,
                    data: expected.to_vec(),
                });
            });
            set
        };
        let mut wrong = digest;
        wrong[0] ^= 0xff;

        for seeding in both_seedings() {
            assert_eq!(
                sequence_split_member(finish_only(digest), seeding_options(seeding))
                    .expect("a correct finish digest extracts"),
                payload,
                "{seeding:?}"
            );
        }
        let error = at_entry_source(
            sequence_split_member(
                finish_only(wrong),
                seeding_options(crate::Rar50SplitHashSeeding::Unconditional),
            )
            .expect_err("the default seeding checks a finish-only record"),
        );
        assert!(
            matches!(error, Error::HashMismatch { hash_type: 0 }),
            "{error:?}"
        );
        assert_eq!(
            sequence_split_member(
                finish_only(wrong),
                seeding_options(crate::Rar50SplitHashSeeding::FirstFragment),
            )
            .expect("FirstFragment never computed the digest, so it cannot fail on it"),
            payload,
        );
        // ...and that member is still covered, by its CRC32.
        let mut crc_broken = finish_only(digest);
        let last = crc_broken.len() - 1;
        edit_split_header(&mut crc_broken[last], |file| {
            file.data_crc32 = Some(file.data_crc32.expect("finish fragment has a CRC32") ^ 1);
        });
        let error = at_entry_source(
            sequence_split_member(
                crc_broken,
                seeding_options(crate::Rar50SplitHashSeeding::FirstFragment),
            )
            .expect_err("the CRC32 still guards a set whose BLAKE2sp was declined"),
        );
        assert!(
            matches!(error, Error::Crc32Mismatch { .. }),
            "{error:?}"
        );

        // Shape two: records on the earlier fragments, none on the finish.
        for seeding in both_seedings() {
            let mut set = split_fixture_set(&HTB_SPLIT_SET);
            let last = set.len() - 1;
            edit_split_header(&mut set[last], |file| file.hash = None);
            let bytes = sequence_split_member(set, seeding_options(seeding))
                .expect("no finish record means nothing to check");
            assert!(!bytes.is_empty(), "{seeding:?}");

            // The earlier records are per-fragment packed digests, and
            // they still fail the set at the volume that is damaged.
            let mut set = split_fixture_set(&HTB_SPLIT_SET);
            let last = set.len() - 1;
            edit_split_header(&mut set[last], |file| file.hash = None);
            edit_split_header(&mut set[0], corrupt_blake2sp);
            let error = at_entry_source(
                sequence_split_member(set, seeding_options(seeding))
                    .expect_err("a wrong per-fragment digest must fail"),
            );
            assert!(
                matches!(error, Error::SplitFragmentHashMismatch { volume: 0 }),
                "{seeding:?}: {error:?}"
            );
        }
    }

    /// After a fragment digest mismatch the incremental chain must keep
    /// erroring on every later read, exactly as the whole-set walk's
    /// fragment readers do: the mismatch surfaces with `at` unadvanced
    /// and the cursor dropped, so without the latch a caller that
    /// swallowed the io error would be handed the failed fragment's
    /// bytes all over again.
    #[test]
    fn growing_chain_keeps_erroring_after_a_fragment_digest_mismatch() {
        let data = *b"0123456";
        let mut first = split_fragment_file(b"a.bin", HFL_SPLIT_AFTER);
        first.block.data_range = 0..data.len();
        first.data_crc32 = Some(!crc32(&data));

        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_blocks(
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
    /// packed digest check used to be skipped entirely. `finish` runs
    /// it over the fully-read fragment.
    #[test]
    fn finish_checks_a_fragment_left_exactly_at_its_boundary() {
        let data = *b"0123456";
        for (crc, expect_mismatch) in [(crc32(&data), false), (!crc32(&data), true)] {
            let mut first = split_fragment_file(b"a.bin", HFL_SPLIT_AFTER);
            first.block.data_range = 0..data.len();
            first.data_crc32 = Some(crc);

            let pending = PendingSplitRefs::new(&first, 0, 0);
            let volumes = vec![archive_with_blocks(
                vec![Block::File(first.clone())],
                data.to_vec(),
            )];
            let mut next_volume = |_: usize| -> Result<Option<Archive>> {
                Ok(Some(archive_with_blocks(
                    vec![Block::File(split_fragment_file(
                        b"a.bin",
                        HFL_SPLIT_BEFORE,
                    ))],
                    Vec::new(),
                )))
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

            let result = chain.finish(0);
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

    #[test]
    fn decrypting_reader_streams_rar50_blocks() {
        let key = [3u8; 32];
        let iv = [4u8; 16];
        let plain = *b"0123456789abcdefRAR5 block two!!";
        let mut encrypted = plain;
        Rar50Cipher::new(key, iv)
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let mut reader = Rar50DecryptingReader::new(Cursor::new(encrypted), key, iv);
        let mut out = Vec::new();
        let mut buf = [0u8; 5];

        loop {
            let count = reader.read(&mut buf).unwrap();
            if count == 0 {
                break;
            }
            out.extend_from_slice(&buf[..count]);
        }

        assert_eq!(out, plain);
    }

    /// Delivers its data in caller-visible chunks of at most the scheduled
    /// sizes, cycling the schedule - a stand-in for fragment seams and
    /// short network reads, including seams inside an AES block.
    struct ShortReader {
        data: Vec<u8>,
        pos: usize,
        sizes: Vec<usize>,
        next: usize,
    }

    impl Read for ShortReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.pos == self.data.len() {
                return Ok(0);
            }
            let step = self.sizes[self.next % self.sizes.len()];
            self.next += 1;
            let count = out.len().min(step).min(self.data.len() - self.pos);
            out[..count].copy_from_slice(&self.data[self.pos..self.pos + count]);
            self.pos += count;
            Ok(count)
        }
    }

    fn cipher_fixture(len: usize) -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 16]) {
        assert!(len.is_multiple_of(16));
        let key = [7u8; 32];
        let iv = [9u8; 16];
        let plain: Vec<u8> = (0..len).map(|index| (index * 31 % 251) as u8).collect();
        let mut encrypted = plain.clone();
        Rar50Cipher::new(key, iv)
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        (plain, encrypted, key, iv)
    }

    fn read_with_pattern(reader: &mut dyn Read, pattern: &[usize]) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut next = 0;
        loop {
            let size = pattern[next % pattern.len()];
            next += 1;
            let mut buf = vec![0u8; size];
            let count = reader.read(&mut buf)?;
            if count == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..count]);
        }
    }

    #[test]
    fn decrypting_reader_matches_reference_across_read_patterns() {
        let (plain, encrypted, key, iv) = cipher_fixture(160 * 16);
        let patterns: &[&[usize]] = &[
            &[1],
            &[2],
            &[15],
            &[16],
            &[20],
            &[33],
            &[64],
            &[1024],
            &[plain.len()],
            // Mixed sub-block and direct requests: leftovers from the
            // internal window must drain before any direct decryption.
            &[5, 1024, 3, 64, 1, 16],
            &[15, 4096, 7],
        ];
        for pattern in patterns {
            let mut reader =
                Rar50DecryptingReader::new(Cursor::new(encrypted.clone()), key, iv);
            let out = read_with_pattern(&mut reader, pattern).unwrap();
            assert_eq!(out, plain, "pattern {pattern:?}");
        }
    }

    #[test]
    fn decrypting_reader_survives_short_reads_and_mid_block_seams() {
        let (plain, encrypted, key, iv) = cipher_fixture(64 * 16);
        for sizes in [vec![1], vec![7], vec![10, 7, 1, 30], vec![15, 17]] {
            let inner = ShortReader {
                data: encrypted.clone(),
                pos: 0,
                sizes: sizes.clone(),
                next: 0,
            };
            let mut reader = Rar50DecryptingReader::new(inner, key, iv);
            let out = read_with_pattern(&mut reader, &[600]).unwrap();
            assert_eq!(out, plain, "underlying sizes {sizes:?}");
        }
    }

    #[test]
    fn decrypting_reader_rejects_truncated_ciphertext_on_both_paths() {
        let (_, encrypted, key, iv) = cipher_fixture(16 * 16);
        let truncated = &encrypted[..encrypted.len() - 8];

        // Direct path: whole-block request.
        let mut reader = Rar50DecryptingReader::new(Cursor::new(truncated.to_vec()), key, iv);
        let err = read_with_pattern(&mut reader, &[4096]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        // Buffered path: sub-block requests.
        let mut reader = Rar50DecryptingReader::new(Cursor::new(truncated.to_vec()), key, iv);
        let err = read_with_pattern(&mut reader, &[5]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn decrypting_reader_returns_zero_at_eof_on_both_paths() {
        let (plain, encrypted, key, iv) = cipher_fixture(4 * 16);
        let mut reader = Rar50DecryptingReader::new(Cursor::new(encrypted), key, iv);
        let out = read_with_pattern(&mut reader, &[32]).unwrap();
        assert_eq!(out, plain);
        assert_eq!(reader.read(&mut [0u8; 64]).unwrap(), 0);
        assert_eq!(reader.read(&mut [0u8; 5]).unwrap(), 0);
    }

    fn two_fragment_split(
        payload: &[u8],
        encrypted: bool,
        unpacked_size: u64,
        crc: Option<u32>,
    ) -> (PendingSplitRefs, FileHeader, Vec<Archive>) {
        let half = payload.len() / 2;
        let mut first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        first.block.data_range = 0..half;
        first.block.data_size = Some(half as u64);
        first.encrypted = encrypted;
        let mut second = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        second.block.data_range = 0..payload.len() - half;
        second.block.data_size = Some((payload.len() - half) as u64);
        second.encrypted = encrypted;
        second.unpacked_size = unpacked_size;
        second.data_crc32 = crc;
        let final_file = second.clone();
        let mut pending = PendingSplitRefs::new(&first, 0, 0);
        pending.append(1, 0).unwrap();
        let volumes = vec![
            archive_with_blocks(vec![Block::File(first)], payload[..half].to_vec()),
            archive_with_blocks(vec![Block::File(second)], payload[half..].to_vec()),
        ];
        (pending, final_file, volumes)
    }

    #[test]
    fn stored_split_pipeline_reports_writer_failure_without_deadlock() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("sink failed"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // Larger than the whole buffer pool, so the producer is still
        // sending when the consumer stops on the first write failure. A
        // producer blocked on a full data channel would deadlock the
        // thread-scope teardown; the timeout turns that into a failure.
        let payload = vec![0x5Au8; 8 << 20];
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (pending, final_file, volumes) =
                two_fragment_split(&payload, false, payload.len() as u64, None);
            let outcome = pending
                .write_stored_to(&volumes, &final_file, None, &mut FailingWriter, None, &Default::default(), FragmentDigests::Check)
                .map_err(|error| error.to_string());
            let _ = done_tx.send(outcome);
        });

        let outcome = done_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("split stored pipeline deadlocked on early writer failure");
        let error = outcome.expect_err("writer failure must surface");
        assert!(error.contains("sink failed"), "unexpected error: {error}");
    }

    #[test]
    fn stored_pipeline_reports_writer_failure_without_deadlock() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("sink failed"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // The non-split twin of the split test below: same pipeline, same
        // parked-producer hazard on an early writer failure.
        let payload = vec![0xA5u8; 8 << 20];
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut file = plain_file(b"big.bin", &payload, None);
            file.block.data_range = 0..payload.len();
            file.block.data_size = Some(payload.len() as u64);
            let archive = archive_with_blocks(vec![Block::File(file.clone())], payload);
            let outcome = file
                .write_stored_to(
                    &archive,
                    None,
                    &mut crate::source::RangeReaderCache::default(),
                    &mut FailingWriter,
                )
                .map_err(|error| error.to_string());
            let _ = done_tx.send(outcome);
        });

        let outcome = done_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("stored pipeline deadlocked on early writer failure");
        let error = outcome.expect_err("writer failure must surface");
        assert!(error.contains("sink failed"), "unexpected error: {error}");
    }

    #[test]
    fn tiny_stored_view_writes_and_verifies_the_exact_member() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("tiny sink failed"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let payload: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
        let mut file = plain_file(b"tiny.bin", &payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.data_crc32 = Some(crc32(&payload));
        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.clone());
        let mut out = Vec::new();
        file.write_stored_to(
            &archive,
            None,
            &mut crate::source::RangeReaderCache::default(),
            &mut out,
        )
        .unwrap();
        assert_eq!(out, payload);

        let error = file
            .write_stored_to(
                &archive,
                None,
                &mut crate::source::RangeReaderCache::default(),
                &mut FailingWriter,
            )
            .unwrap_err();
        assert!(error.to_string().contains("tiny sink failed"));

        file.data_crc32 = Some(!crc32(&payload));
        let error = file
            .write_stored_to(
                &archive,
                None,
                &mut crate::source::RangeReaderCache::default(),
                &mut Vec::new(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            Error::AtEntry { source, .. } if matches!(*source, Error::Crc32Mismatch { .. })
        ));

        file.data_crc32 = None;
        file.hash = Some(FileHash {
            hash_type: 0,
            data: blake2sp::hash(&payload).to_vec(),
        });
        file.write_stored_to(
            &archive,
            None,
            &mut crate::source::RangeReaderCache::default(),
            &mut Vec::new(),
        )
        .unwrap();
        file.hash.as_mut().unwrap().data[0] ^= 1;
        let error = file
            .write_stored_to(
                &archive,
                None,
                &mut crate::source::RangeReaderCache::default(),
                &mut Vec::new(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            Error::AtEntry { source, .. } if matches!(*source, Error::HashMismatch { hash_type: 0 })
        ));

        file.hash = None;
        file.unpacked_size = payload.len() as u64 - 1;
        let mut over_out = Vec::new();
        let over = file
            .write_stored_to(
                &archive,
                None,
                &mut crate::source::RangeReaderCache::default(),
                &mut over_out,
            )
            .unwrap_err();
        assert!(over.to_string().contains("supplies more data"));
        assert_eq!(over_out, payload[..payload.len() - 1]);

        // A growing source cannot lend a direct view, so it exercises the
        // prior boxed-reader path against the identical malformed header.
        // Both paths must write the declared prefix before rejecting the
        // extra packed byte, and must surface the same entry-scoped error.
        let stream = Arc::new(crate::source::GrowableBuffer::with_total_len(
            payload.len() as u64,
        ));
        stream.append(&payload);
        let mut forced_archive =
            archive_with_blocks(vec![Block::File(file.clone())], Vec::new());
        forced_archive.source = ArchiveSource::Stream {
            source: stream,
            len: payload.len(),
        };
        let mut forced_out = Vec::new();
        let forced = file
            .write_stored_to(
                &forced_archive,
                None,
                &mut crate::source::RangeReaderCache::default(),
                &mut forced_out,
            )
            .unwrap_err();
        assert_eq!(forced.to_string(), over.to_string());
        assert_eq!(forced_out, over_out);

        file.unpacked_size = payload.len() as u64 + 1;
        let mut short_out = Vec::new();
        let short = file
            .write_stored_to(
                &archive,
                None,
                &mut crate::source::RangeReaderCache::default(),
                &mut short_out,
            )
            .unwrap_err();
        assert!(short.to_string().contains("mismatched packed and unpacked"));
        assert_eq!(short_out, payload);
    }

    // A reader that hands back far less than it was asked for is what a
    // socket-backed stored member looks like, and it is the shape the fill
    // level is carried for: the pooled buffer stays longer than its
    // contents, so nothing but `count` may reach the consumer or the
    // digest. The schedule includes a 1-byte read on purpose - the shorter
    // the read, the more of the previous round is still sitting there.
    // (nzbfast-local change, 22 Aug 2026 - re-apply on the next rars
    // re-sync, see vendor/rars/VENDORING.md.)
    #[test]
    fn stored_pipeline_delivers_exactly_the_bytes_each_short_read_returned() {
        let content: Vec<u8> = (0..3_000_003u32).map(|index| (index % 251) as u8).collect();
        let mut reader = ShortReader {
            data: content.clone(),
            pos: 0,
            sizes: vec![1 << 20, 7, 300_000, 1, 999_999],
            next: 0,
        };
        let mut seen: Vec<u8> = Vec::with_capacity(content.len());

        let (crc, hash) = pipe_stored_chunks(
            &mut reader,
            None,
            content.len() as u64,
            |error: std::io::Error| error,
            Crc32::new(),
            None,
            |chunk: &[u8]| {
                seen.extend_from_slice(chunk);
                Ok::<usize, std::io::Error>(chunk.len())
            },
        )
        .expect("stored pipeline");

        assert!(hash.is_none());
        assert_eq!(seen, content);
        assert_eq!(crc.finish(), crc32(&content));
    }

    #[test]
    // unrar never inspects the pad, so a non-zero tail must extract rather
    // than fail (see AES_BLOCK). This is the shape that failed on ~30% of a
    // reporter's encrypted stored volumes while unrar took all of them.
    fn stored_split_accepts_nonzero_encrypted_padding() {
        let mut payload = b"encrypted split payload!".repeat(4);
        let logical = payload.len() as u64 - 6;
        let last = payload.len() - 1;
        payload[last] = 1; // non-zero pad byte
        let expected = payload[..logical as usize].to_vec();
        let (pending, final_file, volumes) =
            two_fragment_split(&payload, true, logical, Some(crc32(&expected)));

        let mut out: Vec<u8> = Vec::new();
        pending
            .write_stored_to(&volumes, &final_file, None, &mut out, None, &Default::default(), FragmentDigests::Check)
            .expect("non-zero AES padding must extract");
        assert_eq!(out, expected);
    }

    #[test]
    // The length bound is what survives: padding may not exceed one AES
    // block, so a header/payload disagreement cannot hide behind it.
    fn stored_split_rejects_padding_past_one_aes_block() {
        let payload = b"encrypted split payload!".repeat(4);
        let logical = payload.len() as u64 - AES_BLOCK;
        let (pending, final_file, volumes) =
            two_fragment_split(&payload, true, logical, None);

        let mut out: Vec<u8> = Vec::new();
        let err = pending
            .write_stored_to(&volumes, &final_file, None, &mut out, None, &Default::default(), FragmentDigests::Check)
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("one block of padding")),
            "expected over-length padding rejection, got {err:?}"
        );
    }

    #[test]
    fn stored_split_trims_zero_encrypted_padding_and_verifies_crc() {
        let payload = b"encrypted split payload!".repeat(4);
        let logical = payload.len() - 6;
        let mut padded = payload[..logical].to_vec();
        padded.resize(payload.len(), 0);
        let (pending, final_file, volumes) = two_fragment_split(
            &padded,
            true,
            logical as u64,
            Some(crc32(&padded[..logical])),
        );

        let mut out: Vec<u8> = Vec::new();
        pending
            .write_stored_to(&volumes, &final_file, None, &mut out, None, &Default::default(), FragmentDigests::Check)
            .unwrap();
        assert_eq!(out, &padded[..logical]);
    }

    #[test]
    fn stored_split_entries_stream_fragments_to_writer() {
        struct SharedWriter(Rc<RefCell<Vec<u8>>>);

        impl Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let first = b"stored ";
        let second = b"split payload";
        let full = [first.as_slice(), second.as_slice()].concat();
        let expected_crc = crc32(&full);
        let volumes = vec![
            stored_split_archive(first, &full, expected_crc, HFL_SPLIT_AFTER),
            stored_split_archive(second, &full, expected_crc, HFL_SPLIT_BEFORE),
        ];
        let captured = Rc::new(RefCell::new(Vec::new()));
        let sink = captured.clone();

        extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            move |_meta| Ok(Box::new(SharedWriter(sink.clone()))),
        )
        .unwrap();

        assert_eq!(&*captured.borrow(), &full);
    }

    #[test]
    fn bounded_filtered_members_use_buffered_decode() {
        let mut data = Vec::new();
        while data.len() + 29 <= BUFFERED_DECODE_LIMIT as usize {
            data.extend_from_slice(b"\xe8\0\0\0\0filtered payload block\n");
        }
        assert!(data.len() as u64 <= BUFFERED_DECODE_LIMIT);

        let archive = Rar50Writer::new(WriterOptions {
            target: crate::ArchiveVersion::Rar50,
            features: crate::FeatureSet::store_only(),
            compression_level: None,
            dictionary_size: None,
            entropy: crate::Entropy::Os,
        })
        .compressed_entries(&[CompressedEntry {
            name: b"filtered.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }])
        .filter_policy(FilterPolicy::Explicit(FilterKind::E8))
        .finish()
        .unwrap();
        let archive = Archive::parse(&archive).unwrap();
        let file = archive.files().next().unwrap();
        assert!(!file.should_stream_decode(BUFFERED_DECODE_LIMIT));

        let mut out = Vec::new();
        file.write_to(&archive, None, &mut out).unwrap();

        assert_eq!(out, data);
    }

    #[test]
    fn streaming_filtered_members_extract_in_stream() {
        let mut data = Vec::new();
        while data.len() as u64 <= BUFFERED_DECODE_LIMIT {
            data.extend_from_slice(b"\xe8\0\0\0\0filtered payload block\n");
        }

        let archive = Rar50Writer::new(WriterOptions {
            target: crate::ArchiveVersion::Rar50,
            features: crate::FeatureSet::store_only(),
            compression_level: None,
            dictionary_size: None,
            entropy: crate::Entropy::Os,
        })
        .compressed_entries(&[CompressedEntry {
            name: b"filtered.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }])
        .filter_policy(FilterPolicy::Explicit(FilterKind::E8))
        .finish()
        .unwrap();
        let archive = Archive::parse(&archive).unwrap();
        let file = archive.files().next().unwrap();
        assert!(file.should_stream_decode(BUFFERED_DECODE_LIMIT));

        let mut out = Vec::new();
        file.write_to(&archive, None, &mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn streaming_crc32_zero_advance_matches_byte_update() {
        let mut bytewise = Crc32::new();
        bytewise.update(&vec![0; 100_000]);

        let mut skipped = Crc32::new();
        skipped.update_zeroes(100_000);

        assert_eq!(skipped.finish(), bytewise.finish());
    }

    #[test]
    fn repeated_chunk_does_not_advance_crc_after_sink_error() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("sink failed"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = FailingWriter;
        let mut crc = Crc32::new();
        let expected = Crc32::new().finish();

        assert!(write_repeated_chunk(&mut writer, &mut crc, &mut None, 0, 1024).is_err());
        assert_eq!(crc.finish(), expected);
    }

    #[test]
    fn encrypted_stored_decode_bounds_discarded_padding_by_length_not_content() {
        let mut file = plain_file(b"secret.txt", b"secret", None);
        file.encrypted = true;
        file.unpacked_size = 6;
        let mut decoder = Unpack50Decoder::new();

        assert_eq!(
            file.decode_packed_with_decoder(b"secret\0\0", &mut decoder)
                .unwrap(),
            b"secret"
        );
        // Residue, not zeroes, is what WinRAR actually writes.
        assert_eq!(
            file.decode_packed_with_decoder(b"secret\0\x01", &mut decoder)
                .unwrap(),
            b"secret"
        );
        // A whole block or more past the end is a size disagreement.
        assert!(matches!(
            file.decode_packed_with_decoder(b"secret0123456789abcdef", &mut decoder),
            Err(Error::InvalidHeader(
                "RAR 5 encrypted stored file supplies more data than one block of padding"
            ))
        ));
    }

    #[test]
    fn checked_unpacked_size_rejects_values_above_host_usize() {
        assert_eq!(checked_unpacked_size(123).unwrap(), 123usize);

        let overflowing = usize::MAX as u128 + 1;
        if overflowing <= u64::MAX as u128 {
            assert!(checked_unpacked_size(overflowing as u64).is_err());
        }
    }

    #[test]
    fn constant_time_hash_comparison_keeps_hash_validation_behaviour() {
        let data = b"hash me";
        let file = FileHeader {
            block: empty_block(HEAD_FILE, 0, 0..0),
            file_flags: 0,
            unpacked_size: data.len() as u64,
            attributes: 0x20,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 2,
            name: b"hash.txt".to_vec(),
            hash: Some(FileHash {
                hash_type: 0,
                data: blake2sp::hash(data).to_vec(),
            }),
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        };

        file.verify_integrity_with_keys(data, None).unwrap();

        let mut wrong = file;
        wrong.hash.as_mut().unwrap().data[31] ^= 0x01;
        assert!(matches!(
            wrong.verify_integrity_with_keys(data, None),
            Err(Error::HashMismatch { hash_type: 0 })
        ));
    }

    #[test]
    fn verify_integrity_rejects_bad_blake2sp_length_and_ignores_unknown_hash_type() {
        let data = b"hash me";
        let mut bad_length = plain_file(
            b"a.txt",
            data,
            Some(FileHash {
                hash_type: 0,
                data: vec![0u8; 16],
            }),
        );
        assert!(matches!(
            bad_length.verify_integrity_with_keys(data, None),
            Err(Error::InvalidHeader(_))
        ));

        bad_length.hash.as_mut().unwrap().hash_type = 99;
        bad_length.hash.as_mut().unwrap().data = vec![0u8; 32];
        bad_length.verify_integrity_with_keys(data, None).unwrap();
    }

    #[test]
    fn streaming_hash_verifier_rejects_bad_blake2sp_length_and_ignores_unknown_hash_type() {
        let mut file = plain_file(
            b"a.txt",
            b"",
            Some(FileHash {
                hash_type: 0,
                data: vec![0u8; 16],
            }),
        );
        assert!(matches!(
            streaming_hash_verifier(&file),
            Err(Error::InvalidHeader(_))
        ));

        file.hash.as_mut().unwrap().hash_type = 7;
        file.hash.as_mut().unwrap().data = vec![0u8; 32];
        assert!(matches!(streaming_hash_verifier(&file), Ok(None)));

        let nohash = plain_file(b"a.txt", b"", None);
        assert!(matches!(streaming_hash_verifier(&nohash), Ok(None)));
    }

    #[test]
    fn crypto_with_password_short_circuits_for_unencrypted_or_unsupported_versions() {
        let plain = plain_file(b"a.txt", b"", None);
        assert!(plain.crypto_with_password(None).unwrap().is_none());
        assert!(plain.crypto_with_password(Some(b"pw")).unwrap().is_none());

        let mut missing = plain_file(b"a.txt", b"", None);
        missing.encrypted = true;
        assert!(matches!(
            missing.crypto_with_password(None),
            Err(Error::NeedPassword)
        ));
        assert!(matches!(
            missing.crypto_with_password(Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let mut bad_version = plain_file(b"a.txt", b"", None);
        bad_version.encrypted = true;
        bad_version.encryption = Some(FileEncryption {
            version: 1,
            flags: 0,
            kdf_count: 0,
            salt: [0u8; 16],
            iv: [0u8; 16],
            check_value: None,
        });
        assert!(matches!(
            bad_version.crypto_with_password(Some(b"pw")),
            Err(Error::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn crypto_with_password_handles_missing_check_value() {
        let mut file = plain_file(b"a.txt", b"", None);
        file.encrypted = true;
        file.encryption = Some(FileEncryption {
            version: 0,
            flags: 0,
            kdf_count: 0,
            salt: [0u8; 16],
            iv: [0u8; 16],
            check_value: None,
        });
        assert!(file.crypto_with_password(Some(b"pw")).unwrap().is_some());
    }

    #[test]
    fn decode_packed_rejects_stored_size_mismatch() {
        let mut decoder = Unpack50Decoder::new();

        let mut file = plain_file(b"a.txt", &[0u8; 32], None);
        file.unpacked_size = 32;
        let short = vec![0u8; 16];
        assert!(matches!(
            file.decode_packed_with_decoder(&short, &mut decoder),
            Err(Error::InvalidHeader(_))
        ));

        let mut encrypted = plain_file(b"b.txt", &[0u8; 32], None);
        encrypted.encrypted = true;
        encrypted.unpacked_size = 30;
        let too_short = vec![0u8; 16];
        assert!(matches!(
            encrypted.decode_packed_with_decoder(&too_short, &mut decoder),
            Err(Error::InvalidHeader(_))
        ));

        // Ciphertext is block-aligned, so the tail for a 30-byte member is
        // the 2 bytes of padding that round it up to 32 - and it is trimmed.
        let exact = vec![0u8; 32];
        let trimmed = encrypted
            .decode_packed_with_decoder(&exact, &mut decoder)
            .unwrap();
        assert_eq!(trimmed.len(), encrypted.unpacked_size as usize);
    }

    #[test]
    fn verify_streaming_integrity_validates_crc_and_hash() {
        let payload = b"streaming";
        let crc_value = crc32(payload);
        let hash_value = blake2sp::hash(payload);

        let mut file = plain_file(b"s.txt", payload, None);
        file.data_crc32 = Some(crc_value);
        file.hash = Some(FileHash {
            hash_type: 0,
            data: hash_value.to_vec(),
        });

        let make_state = || {
            let mut crc = Crc32::new();
            crc.update(payload);
            let mut hasher = blake2sp::Hasher::new();
            hasher.update(payload);
            (crc, Some((hash_value, hasher)))
        };

        let (crc, hash) = make_state();
        file.verify_streaming_integrity(crc, hash, None).unwrap();

        let (crc, hash) = make_state();
        let mut bad = file.clone();
        bad.data_crc32 = Some(crc_value ^ 0x1);
        assert!(matches!(
            bad.verify_streaming_integrity(crc, hash, None),
            Err(Error::Crc32Mismatch { .. })
        ));

        let (crc, _) = make_state();
        let mut wrong_expected = hash_value;
        wrong_expected[0] ^= 0xff;
        let mut hasher = blake2sp::Hasher::new();
        hasher.update(payload);
        let mut bad_hash = file.clone();
        bad_hash.data_crc32 = None;
        assert!(matches!(
            bad_hash.verify_streaming_integrity(crc, Some((wrong_expected, hasher)), None),
            Err(Error::HashMismatch { hash_type: 0 })
        ));

        let empty = plain_file(b"e.txt", b"", None);
        empty
            .verify_streaming_integrity(Crc32::new(), None, None)
            .unwrap();
    }

    #[test]
    fn write_repeated_chunk_updates_crc_hash_and_writer() {
        let mut writer = Vec::new();
        let mut crc_zero = Crc32::new();
        let mut hash = Some(([0u8; 32], blake2sp::Hasher::new()));
        write_repeated_chunk(&mut writer, &mut crc_zero, &mut hash, 0, 70_000).unwrap();
        assert_eq!(writer.len(), 70_000);
        let zero_crc = crc_zero.finish();

        let mut bytewise = Crc32::new();
        bytewise.update(&vec![0u8; 70_000]);
        assert_eq!(zero_crc, bytewise.finish());

        let mut writer = Vec::new();
        let mut crc_ff = Crc32::new();
        let mut hash_none: Option<([u8; 32], blake2sp::Hasher)> = None;
        write_repeated_chunk(&mut writer, &mut crc_ff, &mut hash_none, 0xff, 1024).unwrap();
        assert_eq!(writer, vec![0xffu8; 1024]);
    }

    #[test]
    fn map_rar50_crypto_error_translates_kdf_count() {
        assert!(matches!(
            super::super::map_rar50_crypto_error(crate::crypto::rar50::Error::KdfCountTooLarge),
            Error::UnsupportedFeature { .. }
        ));
        assert!(matches!(
            super::super::map_rar50_crypto_error(crate::crypto::rar50::Error::BadPassword),
            Error::WrongPasswordOrCorruptData
        ));
    }

    #[test]
    fn constant_time_eq_returns_false_for_length_mismatch() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    fn stored_split_archive(data: &[u8], full: &[u8], crc: u32, flags: u64) -> Archive {
        // Real archivers stamp NON-final fragments with the digests of
        // that fragment's own packed bytes (see
        // split_fragment_packed_digests); only the final fragment carries
        // the whole member's unpacked digests, and the chain now rejects
        // a fragment whose packed bytes miss its own record.
        let (crc, hash) = if flags & HFL_SPLIT_AFTER != 0 {
            (crc32(data), blake2sp::hash(data))
        } else {
            (crc, blake2sp::hash(full))
        };
        let source: Arc<[u8]> = Arc::from(data.to_vec().into_boxed_slice());
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                block: empty_block(1, 0, 0..0),
                archive_flags: 0,
                volume_number: None,
                extras: Vec::new(),
            },
            blocks: vec![Block::File(FileHeader {
                block: empty_block(HEAD_FILE, flags, 0..data.len()),
                file_flags: 0,
                unpacked_size: full.len() as u64,
                attributes: 0x20,
                mtime: None,
                data_crc32: Some(crc),
                compression_info: 0,
                host_os: 2,
                name: b"split.txt".to_vec(),
                hash: Some(FileHash {
                    hash_type: 0,
                    data: hash.to_vec(),
                }),
                redirection: None,
                service_data: None,
                encrypted: false,
                encryption: None,
                crypto: None,
            })],
            source: ArchiveSource::Memory(source),
            pending: None,
            tail: crate::rar50::TailPolicy::Strict,
            truncated_tail: false,
        }
    }

    fn empty_block(
        header_type: u64,
        flags: u64,
        data_range: std::ops::Range<usize>,
    ) -> BlockHeader {
        BlockHeader {
            header_crc: 0,
            header_size: 0,
            header_type,
            flags,
            extra_area_size: None,
            data_size: Some(data_range.len() as u64),
            offset: 0,
            header_range: 0..0,
            data_range,
        }
    }

    fn split_fragment_file(name: &[u8], hfl_flags: u64) -> FileHeader {
        FileHeader {
            block: empty_block(HEAD_FILE, hfl_flags, 0..0),
            file_flags: 0,
            unpacked_size: 0,
            attributes: 0x20,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 2,
            name: name.to_vec(),
            hash: None,
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        }
    }

    fn archive_with_blocks(blocks: Vec<Block>, source: Vec<u8>) -> Archive {
        let bytes: Arc<[u8]> = Arc::from(source.into_boxed_slice());
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                block: empty_block(1, 0, 0..0),
                archive_flags: 0,
                volume_number: None,
                extras: Vec::new(),
            },
            blocks,
            source: ArchiveSource::Memory(bytes),
            pending: None,
            tail: crate::rar50::TailPolicy::Strict,
            truncated_tail: false,
        }
    }

    fn never_open(_meta: &ExtractedEntryMeta) -> Result<Box<dyn Write>> {
        panic!("open should not be invoked for this test");
    }

    #[test]
    fn extract_volumes_to_rejects_volume_state_violations() {
        let empty: Vec<Archive> = Vec::new();
        assert!(matches!(
            extract_volumes_to(&empty, crate::ArchiveReadOptions::default(), never_open),
            Err(Error::InvalidHeader(_))
        ));

        let only_continuation = vec![archive_with_blocks(
            vec![Block::File(split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE))],
            Vec::new(),
        )];
        assert!(matches!(
            extract_volumes_to(
                &only_continuation,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));

        let interrupted = vec![archive_with_blocks(
            vec![
                Block::File(split_fragment_file(b"a.txt", HFL_SPLIT_AFTER)),
                Block::File(plain_file(b"other.txt", b"", None)),
            ],
            Vec::new(),
        )];
        assert!(matches!(
            extract_volumes_to(
                &interrupted,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));

        let incomplete = vec![archive_with_blocks(
            vec![Block::File(split_fragment_file(b"a.txt", HFL_SPLIT_AFTER))],
            Vec::new(),
        )];
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
    fn validate_split_fragment_rejects_directories_and_demands_password_for_encrypted() {
        let mut dir = split_fragment_file(b"d", HFL_SPLIT_AFTER);
        dir.file_flags = 0x0001;
        assert!(matches!(
            validate_split_fragment(&dir, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut encrypted = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        encrypted.encrypted = true;
        assert!(matches!(
            validate_split_fragment(&encrypted, None),
            Err(Error::NeedPassword)
        ));
        validate_split_fragment(&encrypted, Some(b"pw")).unwrap();

        let plain = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        validate_split_fragment(&plain, None).unwrap();
    }

    #[test]
    fn validate_split_continuation_refs_rejects_property_drift_between_fragments() {
        let first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        let pending = PendingSplitRefs::new(&first, 0, 0);

        let renamed = split_fragment_file(b"b.txt", HFL_SPLIT_BEFORE);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &renamed, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_compression = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        new_compression.compression_info = 0x123;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_compression, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_encryption = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        new_encryption.encrypted = true;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_encryption, Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let same = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        validate_split_continuation_refs(&pending, &same, None).unwrap();
    }

    #[test]
    fn archive_extract_to_rejects_split_entries_in_single_volume_archive() {
        let split = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        let archive = archive_with_blocks(vec![Block::File(split)], Vec::new());
        let err = archive
            .extract_to(crate::ArchiveReadOptions::default(), never_open)
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("requires multivolume")),
            "expected multivolume error, got {err:?}"
        );
    }

    #[test]
    fn archive_extract_to_skips_redirection_entries_without_opening_writer() {
        let mut redirect = plain_file(b"link", b"", None);
        redirect.redirection = Some(super::super::FileRedirection {
            redirection_type: 1,
            flags: 0,
            target_name: b"target".to_vec(),
        });
        let archive = archive_with_blocks(vec![Block::File(redirect)], Vec::new());
        archive
            .extract_to(crate::ArchiveReadOptions::default(), never_open)
            .unwrap();
    }

    #[test]
    fn archive_extract_to_with_redirections_reports_redirection_entries() {
        let mut redirect = plain_file(b"link", b"", None);
        redirect.redirection = Some(super::super::FileRedirection {
            redirection_type: 1,
            flags: 0,
            target_name: b"target".to_vec(),
        });
        let archive = archive_with_blocks(vec![Block::File(redirect)], Vec::new());
        let mut seen = Vec::new();
        archive
            .extract_to_with_redirections(
                crate::ArchiveReadOptions::default(),
                never_open,
                |meta, redirection| {
                    seen.push((meta.name.clone(), redirection.target_name.clone()));
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(seen, vec![(b"link".to_vec(), b"target".to_vec())]);
    }

    #[test]
    fn extract_volumes_to_skips_redirection_entries_without_opening_writer() {
        let mut redirect = plain_file(b"link", b"", None);
        redirect.redirection = Some(super::super::FileRedirection {
            redirection_type: 1,
            flags: 0,
            target_name: b"target".to_vec(),
        });
        let volumes = vec![archive_with_blocks(vec![Block::File(redirect)], Vec::new())];
        extract_volumes_to(&volumes, crate::ArchiveReadOptions::default(), never_open).unwrap();
    }

    #[test]
    fn extract_volumes_to_with_redirections_reports_redirection_entries() {
        let mut redirect = plain_file(b"link", b"", None);
        redirect.redirection = Some(super::super::FileRedirection {
            redirection_type: 5,
            flags: 0,
            target_name: b"target".to_vec(),
        });
        let volumes = vec![archive_with_blocks(vec![Block::File(redirect)], Vec::new())];
        let mut seen = Vec::new();
        extract_volumes_to_with_redirections(
            &volumes,
            crate::ArchiveReadOptions::default(),
            never_open,
            |meta, redirection| {
                seen.push((meta.name.clone(), redirection.target_name.clone()));
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(seen, vec![(b"link".to_vec(), b"target".to_vec())]);
    }

    /// A member the decode pool accepts: v0 algorithm, non-solid, method 3,
    /// no CRC32 and no hash. It carries no packed bytes at all, so its decode
    /// ends short and the missing integrity record turns that into an empty
    /// payload instead of an error.
    #[cfg(feature = "parallel")]
    fn truncated_pooled_file(name: &[u8], unpacked_size: u64) -> FileHeader {
        let mut file = plain_file(name, b"", None);
        file.compression_info = 0x180;
        file.unpacked_size = unpacked_size;
        file
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn member_pool_batches_do_not_reserve_another_workers_byte_share() {
        let worker_share = (64u64 << 20) / 8;

        // Eight 8 MiB members must remain eight separately claimable jobs;
        // one worker may not reserve the pool's entire 64 MiB allowance.
        assert_eq!(
            pool_work_batch_shape([worker_share; 8].into_iter(), 8, worker_share),
            (1, worker_share)
        );
        // The always-admit-one rule also keeps an above-share member moving,
        // without attaching even a tiny second member to it.
        assert_eq!(
            pool_work_batch_shape([worker_share + 1, 1].into_iter(), 8, worker_share),
            (1, worker_share + 1)
        );

        let tiny = 4u64 << 10;
        assert_eq!(
            pool_work_batch_shape([tiny; 8].into_iter(), 8, worker_share),
            (8, tiny * 8)
        );
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn member_pool_result_batching_is_reserved_for_tiny_ranges() {
        let tiny = 4u64 << 10;

        // The measured 10,000 x 4 KiB shape keeps exactly the same eight-way
        // result packets as the unrestricted batching candidate.
        assert!(pool_result_batchable(
            [tiny; POOL_WORK_BATCH_MAX].into_iter()
        ));
        assert!(pool_result_batchable(
            [POOL_RESULT_BATCH_BYTE_MAX / 2; 2].into_iter()
        ));

        // Empty/singleton ranges never allocate a result vector, and crossing
        // the byte ceiling by one byte restores immediate Single packets.
        assert!(!pool_result_batchable(std::iter::empty()));
        assert!(!pool_result_batchable([tiny].into_iter()));
        assert!(!pool_result_batchable(
            [
                POOL_RESULT_BATCH_BYTE_MAX / 2,
                POOL_RESULT_BATCH_BYTE_MAX / 2 + 1
            ]
            .into_iter()
        ));

        // Common ~MiB members and hostile totals cannot enter the delayed
        // collection path; checked addition also makes overflow fail closed.
        assert!(!pool_result_batchable([1u64 << 20; 6].into_iter()));
        assert!(!pool_result_batchable(
            [1u64; POOL_WORK_BATCH_MAX + 1].into_iter()
        ));
        assert!(!pool_result_batchable([u64::MAX, 1].into_iter()));
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn member_pool_result_packets_reorder_and_drain_at_batch_granularity() {
        let packet = |start: usize| {
            PoolResultPacket::Batch(
                start,
                vec![Ok(vec![start as u8]), Ok(vec![(start + 1) as u8])].into_iter(),
            )
        };
        let (tx, rx) = std::sync::mpsc::channel();
        // Complete three contiguous ranges in reverse order. Waiting for zero
        // receives all three messages and stores only TWO tree nodes; the
        // second member of every range then drains from the ready cursor.
        assert!(tx.send(packet(4)).is_ok());
        assert!(tx.send(packet(2)).is_ok());
        assert!(tx.send(packet(0)).is_ok());
        let single = PoolResultPacket::Single(6, Ok(vec![6]));
        assert!(matches!(&single, PoolResultPacket::Single(..)));
        assert!(tx.send(single).is_ok());
        drop(tx);

        let mut reorder = PoolResultReorder::default();
        assert_eq!(reorder.next(0, &rx).unwrap(), [0]);
        // Two future BATCHES occupy two tree nodes, not four member nodes.
        assert_eq!(reorder.pending.len(), 2);
        assert!(reorder.ready.is_some());
        let tail: Vec<u8> = (1..=6)
            .map(|seq| reorder.next(seq, &rx).unwrap()[0])
            .collect();
        assert_eq!(tail, [1, 2, 3, 4, 5, 6]);
        assert!(reorder.pending.is_empty());
        assert!(reorder.ready.is_none());
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn member_pool_result_packets_preserve_first_error_in_member_order() {
        let batch = |start, first: PoolMemberResult, second: PoolMemberResult| {
            PoolResultPacket::Batch(start, vec![first, second].into_iter())
        };
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(tx
            .send(batch(
                2,
                Err(Error::InvalidHeader("later member failed")),
                Ok(vec![3]),
            ))
            .is_ok());
        assert!(tx
            .send(PoolResultPacket::Single(
                4,
                Err(Error::InvalidHeader("latest single member failed")),
            ))
            .is_ok());
        assert!(tx
            .send(batch(
                0,
                Ok(vec![0]),
                Err(Error::InvalidHeader("first member failed")),
            ))
            .is_ok());
        drop(tx);

        let mut reorder = PoolResultReorder::default();
        assert_eq!(reorder.next(0, &rx).unwrap(), [0]);
        assert!(reorder
            .next(1, &rx)
            .unwrap_err()
            .to_string()
            .contains("first member failed"));
        // The future batch is still intact: no out-of-order error can replace
        // the archive-order error the coordinator observes first.
        assert!(reorder
            .next(2, &rx)
            .unwrap_err()
            .to_string()
            .contains("later member failed"));
        assert_eq!(reorder.next(3, &rx).unwrap(), [3]);
        assert!(reorder
            .next(4, &rx)
            .unwrap_err()
            .to_string()
            .contains("latest single member failed"));
    }

    /// Exercise the batched work-channel path against the serial extractor,
    /// including the cfg(test) byte budget that forces feeder backpressure.
    #[test]
    #[cfg(feature = "parallel")]
    fn batched_member_pool_matches_serial_bytes_and_order() {
        struct SharedWriter(Rc<RefCell<Vec<u8>>>);

        impl Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        fn collect(
            archive: &Archive,
            options: crate::ArchiveReadOptions<'_>,
        ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            let entries = RefCell::new(Vec::new());
            extract_volumes_to(std::slice::from_ref(archive), options, |meta| {
                let data = Rc::new(RefCell::new(Vec::new()));
                entries
                    .borrow_mut()
                    .push((meta.name.clone(), Rc::clone(&data)));
                Ok(Box::new(SharedWriter(data)))
            })?;
            Ok(entries
                .into_inner()
                .into_iter()
                .map(|(name, data)| (name, data.borrow().clone()))
                .collect())
        }

        let names: Vec<Vec<u8>> = (0..128)
            .map(|index| format!("member-{index:03}.bin").into_bytes())
            .collect();
        let payloads: Vec<Vec<u8>> = (0..128)
            .map(|index| {
                (0..512)
                    .map(|offset| b'a' + ((index + offset % 17) % 26) as u8)
                    .collect()
            })
            .collect();
        let compressed: Vec<_> = names
            .iter()
            .zip(&payloads)
            .map(|(name, data)| CompressedEntry {
                name,
                data,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            })
            .collect();
        let bytes = Rar50Writer::new(WriterOptions::new(
            crate::ArchiveVersion::Rar50,
            crate::FeatureSet::default(),
        ))
        .compressed_entries(&compressed)
        .finish()
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.files().all(|file| !file.is_stored()));

        let pooled_options = crate::ArchiveReadOptions::new()
            .with_rar50_buffered_decode_limit(BUFFERED_DECODE_LIMIT);
        let plan = member_pool_plan(std::slice::from_ref(&archive), pooled_options).unwrap();
        assert_eq!(plan.order.len(), 128);
        assert!((1..=8).all(|workers| pool_work_batch_size(plan.order.len(), workers) > 1));

        let pooled = collect(&archive, pooled_options).unwrap();
        let serial = collect(
            &archive,
            crate::ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0),
        )
        .unwrap();
        assert_eq!(pooled, serial);
    }

    /// A panic in the coordinator still lets `thread::scope` return.
    ///
    /// This one DOES reproduce: revert the `PoolAbortGuard` and it fails on the
    /// timeout below rather than passing. The feeder charges the first member,
    /// parks in `cvar.wait` because the budget is now full, and the panic
    /// unwinds past the abort-and-notify that used to sit at the foot of the
    /// scope - so nothing ever wakes it and the join never completes. The panic
    /// is raised from the caller's `open`, which is the shortest route to it;
    /// the `Write` impl and the coordinator's own inline decode reach the same
    /// place.
    #[test]
    #[cfg(feature = "parallel")]
    fn a_coordinator_panic_does_not_hang_the_member_pool() {
        let member = BUFFERED_DECODE_LIMIT;
        let count = (POOL_INFLIGHT_BUDGET / member + 2) as usize;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let blocks = (0..count)
                .map(|index| {
                    Block::File(truncated_pooled_file(
                        format!("m{index}.bin").as_bytes(),
                        member,
                    ))
                })
                .collect();
            let volumes = vec![archive_with_blocks(blocks, Vec::new())];
            // Deliberate panic inside the coordinator, standing in for any of
            // open / Write / inline decode blowing up. AssertUnwindSafe: the
            // borrows do not outlive the catch.
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                extract_volumes_to(
                    &volumes,
                    crate::ArchiveReadOptions::default(),
                    |_meta| -> Result<Box<dyn Write>> { panic!("open panicked") },
                )
            }))
            .is_err();
            let _ = done_tx.send(panicked);
        });

        match done_rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(panicked) => assert!(panicked, "the coordinator panic must propagate"),
            Err(_) => panic!(
                "pooled extraction did not return within 30s - the feeder is parked on the \
                 budget condvar and the scoped join is deadlocked"
            ),
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn pooled_members_that_decode_short_still_release_their_budget() {
        // Enough members to charge the whole in-flight budget and one more,
        // every one of them decoding to nothing. Crediting the decoded length
        // rather than the charged size leaves the budget full forever, so the
        // feeder parks and the extraction never finishes.
        let member = BUFFERED_DECODE_LIMIT;
        let count = (POOL_INFLIGHT_BUDGET / member + 1) as usize;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let blocks = (0..count)
                .map(|index| {
                    Block::File(truncated_pooled_file(
                        format!("m{index}.bin").as_bytes(),
                        member,
                    ))
                })
                .collect();
            let volumes = vec![archive_with_blocks(blocks, Vec::new())];
            let mut opened = 0usize;
            let outcome = extract_volumes_to(
                &volumes,
                crate::ArchiveReadOptions::default(),
                |_meta| -> Result<Box<dyn Write>> {
                    opened += 1;
                    Ok(Box::new(Vec::new()))
                },
            );
            let _ = done_tx.send(outcome.map(|()| opened).map_err(|error| error.to_string()));
        });

        assert_eq!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("pooled extraction deadlocked"),
            Ok(count)
        );
    }

    #[test]
    fn stream_packed_with_decoder_rejects_stored_files() {
        let file = plain_file(b"stored.txt", b"hello", None);
        assert!(file.is_stored());
        let mut decoder = Unpack50Decoder::new();
        let mut out: Vec<u8> = Vec::new();
        let err = file
            .stream_packed_with_decoder(
                &mut Cursor::new(Vec::<u8>::new()),
                None,
                &mut decoder,
                BUFFERED_DECODE_LIMIT,
                &mut out,
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("does not use streaming")),
            "expected streaming-rejection error, got {err:?}"
        );
    }

    #[test]
    fn pending_split_refs_write_stored_to_rejects_unpacked_size_mismatch() {
        let payload: &[u8] = b"unmatched-size payload";
        let mut first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        first.block.data_range = 0..payload.len();
        first.block.data_size = Some(payload.len() as u64);
        first.unpacked_size = (payload.len() + 5) as u64; // mismatch
        let final_file = first.clone();
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_blocks(
            vec![Block::File(first)],
            payload.to_vec(),
        )];

        let mut out: Vec<u8> = Vec::new();
        let err = pending
            .write_stored_to(&volumes, &final_file, None, &mut out, None, &Default::default(), FragmentDigests::Check)
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("mismatched packed and unpacked")),
            "expected size mismatch error, got {err:?}"
        );
    }

    #[test]
    fn pending_split_refs_write_stored_to_rejects_crc_mismatch_on_unencrypted() {
        let payload: &[u8] = b"crc-mismatch payload";
        // The FINAL fragment: its records are the whole member's unpacked
        // digests, which is the check this test exercises. A SPLIT_AFTER
        // fragment's records would be per-fragment packed digests and hit
        // the volume-boundary check instead.
        let mut first = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        first.block.data_range = 0..payload.len();
        first.block.data_size = Some(payload.len() as u64);
        first.unpacked_size = payload.len() as u64;
        first.data_crc32 = Some(crc32(payload).wrapping_add(1));
        let final_file = first.clone();
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_blocks(
            vec![Block::File(first)],
            payload.to_vec(),
        )];

        let mut out: Vec<u8> = Vec::new();
        let err = pending
            .write_stored_to(&volumes, &final_file, None, &mut out, None, &Default::default(), FragmentDigests::Check)
            .unwrap_err();
        assert!(
            matches!(err, Error::Crc32Mismatch { .. }),
            "expected CRC mismatch, got {err:?}"
        );
    }

    #[test]
    fn pending_split_refs_write_stored_to_rejects_hash_mismatch_on_unencrypted() {
        let payload: &[u8] = b"hash-mismatch payload";
        let mut wrong_hash = blake2sp::hash(payload);
        wrong_hash[0] ^= 0xff;

        // The FINAL fragment, for the same reason as the CRC twin above.
        let mut first = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        first.block.data_range = 0..payload.len();
        first.block.data_size = Some(payload.len() as u64);
        first.unpacked_size = payload.len() as u64;
        first.data_crc32 = Some(crc32(payload));
        first.hash = Some(FileHash {
            hash_type: 0,
            data: wrong_hash.to_vec(),
        });
        let final_file = first.clone();
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_blocks(
            vec![Block::File(first)],
            payload.to_vec(),
        )];

        let mut out: Vec<u8> = Vec::new();
        let err = pending
            .write_stored_to(&volumes, &final_file, None, &mut out, None, &Default::default(), FragmentDigests::Check)
            .unwrap_err();
        assert!(
            matches!(err, Error::HashMismatch { hash_type: 0 }),
            "expected hash mismatch, got {err:?}"
        );
    }

    #[test]
    fn decoded_data_with_mode_dispatches_through_decode_packed_for_stored_files() {
        let payload = b"decoded_data_with_mode stored payload";
        let mut file = plain_file(b"a.txt", payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = payload.len() as u64;

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.to_vec());
        let mut decoder = Unpack50Decoder::new();
        let mut reader_cache = crate::source::RangeReaderCache::default();
        let decoded = file
            .decoded_data_with_mode(
                &archive,
                &mut decoder,
                None,
                DecodeMode::Lz,
                &mut reader_cache,
            )
            .unwrap();
        assert_eq!(decoded.data, payload);
        assert!(decoded.keys.is_none());

        // LzNoFilters dispatches through the same stored short-circuit.
        let mut decoder = Unpack50Decoder::new();
        let decoded = file
            .decoded_data_with_mode(
                &archive,
                &mut decoder,
                None,
                DecodeMode::LzNoFilters,
                &mut reader_cache,
            )
            .unwrap();
        assert_eq!(decoded.data, payload);
    }

    #[test]
    fn decoded_data_unverified_returns_stored_payload_without_crc_check() {
        let payload = b"decoded_data_unverified stored payload";
        let mut file = plain_file(b"a.txt", payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = payload.len() as u64;
        // Set wrong CRC — unverified path must not check it.
        file.data_crc32 = Some(crc32(payload).wrapping_add(1));

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.to_vec());
        let decoded = file.decoded_data_unverified(&archive, None).unwrap();
        assert_eq!(decoded, payload);
    }

    /// The unverified decode sizes its output from a header field the archive
    /// author picks, and consults neither the buffered-decode limit nor the
    /// window limit that ordinary extraction applies. A member that is tiny on
    /// the wire but claims gigabytes therefore decodes until the allocation
    /// fails, which in Rust is an abort - and for a service record that
    /// happens automatically, before any content check.
    #[test]
    fn decoded_data_unverified_bounded_refuses_an_oversized_declared_size() {
        let payload = b"tiny on the wire, enormous in the header";
        let mut file = plain_file(b"RR", payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = 8 * 1024 * 1024 * 1024; // 8 GiB claimed

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.to_vec());
        let err = file
            .decoded_data_unverified_bounded(&archive, None, payload.len() as u64)
            .unwrap_err();
        assert!(
            matches!(err, Error::Rar50BufferedDecodeLimitExceeded { .. }),
            "expected a bounded refusal, got {err:?}"
        );
    }

    /// An archive whose `RR` service is COMPRESSED, which is the branch a
    /// stored recovery record never reaches.
    ///
    /// The prefix is real bytes; the service declares `declared_unpacked` as
    /// its output. Nothing here has to decode successfully - the property
    /// under test is which ceiling gets applied before the decode is even
    /// attempted.
    fn archive_with_compressed_rr(prefix_len: usize, declared_unpacked: u64) -> (Archive, usize) {
        let mut source = vec![0xABu8; prefix_len];
        let packed = vec![0u8; 64];
        let service_offset = source.len();
        source.extend_from_slice(&packed);

        let mut service = plain_file(b"RR", &packed, None);
        // Method 1 (not stored), so `is_stored()` is false and the streaming
        // repair takes its decode branch instead of reading in place.
        service.compression_info = 1 << 7;
        service.unpacked_size = declared_unpacked;
        service.block = empty_block(
            crate::rar50::HEAD_SERVICE,
            0,
            service_offset..service_offset + packed.len(),
        );
        service.block.offset = service_offset;
        // `recovery_record()` wants a single vint percent and nothing after.
        service.service_data = Some(vec![5u8]);

        let total = source.len();
        (
            archive_with_blocks(vec![Block::Service(service)], source),
            total,
        )
    }

    #[test]
    fn streaming_repair_bounds_a_compressed_rr_service_by_the_archive_not_the_budget() {
        // The compressed-RR branch is unreachable from our own writer, which
        // always stores recovery records - so this is the only way to pin the
        // ceiling it applies. Two independent bounds exist: the archive's own
        // length (a recovery record cannot legitimately be larger than the
        // archive carrying it) and the caller's memory budget. Passing only
        // the budget would accept a tiny archive declaring a huge recovery
        // service on any box whose repair slice happens to be wide, which is
        // exactly what the buffered path already refuses.
        let (archive, source_len) = archive_with_compressed_rr(4096, 512 * 1024 * 1024);
        assert!(
            archive
                .services()
                .any(|s| !s.is_stored() && matches!(s.recovery_record(), Ok(Some(_)))),
            "fixture must actually exercise the compressed-RR branch"
        );

        let mut path = std::env::temp_dir();
        path.push(format!("rars-cmpr-rr-{}", std::process::id()));
        let mut dest = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        // A budget far WIDER than the archive: only the archive-size bound can
        // refuse this, so it proves which one is binding.
        let err = archive
            .repair_recovery_to_file(&mut dest, None, u64::MAX)
            .unwrap_err();
        std::fs::remove_file(&path).ok();
        let text = err.to_string();
        assert!(
            text.contains("buffered decode limit") || text.contains("limit"),
            "expected the archive-size ceiling to refuse, got: {text}"
        );
        assert!(
            source_len < 512 * 1024 * 1024,
            "the declared service must exceed the archive for this to mean anything"
        );
    }

    #[test]
    fn streaming_repair_lets_a_compressed_rr_service_inside_both_bounds_through() {
        // The mirror of the test above: a service declaring less than the
        // archive holds must get PAST the ceiling and fail later on the
        // recovery data itself. Without this, a ceiling that refused
        // everything would look identical.
        let (archive, _) = archive_with_compressed_rr(4096, 128);
        let mut path = std::env::temp_dir();
        path.push(format!("rars-cmpr-rr-ok-{}", std::process::id()));
        let mut dest = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let err = archive
            .repair_recovery_to_file(&mut dest, None, u64::MAX)
            .unwrap_err();
        std::fs::remove_file(&path).ok();
        let text = err.to_string();
        assert!(
            !text.contains("buffered decode limit"),
            "a service inside both bounds must not be refused by the ceiling: {text}"
        );
    }

    #[test]
    fn decoded_data_unverified_bounded_refuses_an_oversized_packed_member() {
        // The declared output is not the only allocation: the packed member
        // is buffered WHOLE to produce it, so a member that is small in its
        // header but large on the wire has to be refused on the input side
        // too. Bounding only `unpacked_size` left half of it unchecked.
        let payload = vec![0u8; 4096];
        let mut file = plain_file(b"RR", &payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = 16; // modest claim, large body

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.clone());
        let err = file
            .decoded_data_unverified_bounded(&archive, None, 64)
            .unwrap_err();
        assert!(
            matches!(err, Error::Rar50BufferedDecodeLimitExceeded { .. }),
            "expected a bounded refusal on the packed side, got {err:?}"
        );
    }

    /// ...and the bound must not cost a legitimate record anything.
    #[test]
    fn decoded_data_unverified_bounded_still_decodes_within_the_limit() {
        let payload = b"an honest recovery record";
        let mut file = plain_file(b"RR", payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = payload.len() as u64;

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.to_vec());
        let decoded = file
            .decoded_data_unverified_bounded(&archive, None, payload.len() as u64)
            .unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decoded_data_unverified_accepts_empty_compressed_member() {
        let mut file = plain_file(b"empty.txt", b"", None);
        file.compression_info = 5 << 7;
        file.data_crc32 = Some(0);

        let archive = archive_with_blocks(vec![Block::File(file.clone())], Vec::new());
        let decoded = file.decoded_data_unverified(&archive, None).unwrap();

        assert!(decoded.is_empty());
    }

    #[test]
    fn map_truncated_unverified_payload_swallows_need_more_input_when_no_integrity_record() {
        let mut file = plain_file(b"a.txt", b"", None);
        file.data_crc32 = None;
        file.hash = None;
        assert!(file
            .map_truncated_unverified_payload(crate::codec::Error::NeedMoreInput)
            .unwrap()
            .is_empty());

        file.data_crc32 = Some(0);
        assert!(file
            .map_truncated_unverified_payload(crate::codec::Error::NeedMoreInput)
            .is_err());
    }

    #[test]
    fn encryption_iv_falls_back_to_encryption_record_and_errors_when_missing() {
        let mut with_record = plain_file(b"a.txt", b"", None);
        with_record.encrypted = true;
        with_record.encryption = Some(FileEncryption {
            version: 0,
            flags: 0,
            kdf_count: 0,
            salt: [0u8; 16],
            iv: [5u8; 16],
            check_value: None,
        });
        assert_eq!(with_record.encryption_iv().unwrap(), [5u8; 16]);

        let missing = plain_file(b"a.txt", b"", None);
        assert!(matches!(
            missing.encryption_iv(),
            Err(Error::InvalidHeader(_))
        ));
    }
}
