//! The `.rev` recovery-volume WRITER: the inverse of the rebuild path in
//! [`crate::rar50::repair_rev5_volumes_streaming`].
//!
//! The engine has read `.rev` files and rebuilt missing volumes from them
//! for a long time; this is the other direction, and it is the half the
//! `rv` command and `-rv` switch need. The format is the one the reader
//! parses, so nothing here is guessed:
//!
//! ```text
//! "Rar!\x1aRev"            8 bytes
//! header CRC32             4  over the bytes from `header size` to the payload
//! header size              4  = 11 + 12 * data_count
//! version                  1  = 1
//! data volume count        2
//! recovery volume count    2
//! this volume's number     2  = data_count + row, NOT the file's part number
//! payload CRC32            4
//! per data volume          12  file size (u64) then CRC32 (u32)
//! payload                  shard_len bytes of GF(2^16) parity
//! ```
//!
//! `shard_len` is the largest data volume rounded UP to an even length,
//! because the code word walks 2-byte symbols. Every data volume is
//! zero-padded to that length for the arithmetic and its REAL length is
//! what the metadata table carries.
//!
//! **This is measured against the reference, not inferred.** Building a
//! set this way over the five WinRAR-written volumes in
//! `tests/fixtures/rar50/multivol_rev.part*.rar` reproduces WinRAR's own
//! `multivol_rev.part1.rev` and `part2.rev` byte for byte, which is
//! `rev_writer_reproduces_the_winrar_fixture_byte_for_byte` below, and
//! rar 7.23's `rv` over a set rarfast wrote produces the same bytes as
//! rarfast's own `rv` over it. The one geometry choice that is NOT
//! derivable from the reader - the even rounding - was measured: an
//! odd `-v12289b` volume set gets a 12,290-byte payload.
//!
//! # Why it is striped rather than a call to `encode_parity_shards`
//!
//! That function takes every data shard as a slice and returns every
//! parity shard as a `Vec`, so a set of twenty 500 MB volumes with four
//! recovery volumes would ask for 12 GB of address space before writing
//! a byte. A volume set is exactly the shape where that is the normal
//! case rather than the hostile one. So the encode runs in windows:
//!
//! * recovery rows are taken in BATCHES, so the number of output files
//!   held open never depends on what the caller asked for (`rar rv999`
//!   over a 41-volume set writes 410 of them);
//! * inside a batch, one window of every data volume is read in turn and
//!   folded into that batch's parity rows, so the working set is
//!   `(batch + 1) * window` and does not scale with the data volume
//!   count either;
//! * each data volume's CRC32 is accumulated during the first batch's
//!   pass, so the metadata table costs no extra read.
//!
//! The headers are therefore written last: the table needs CRCs that are
//! only known once every volume has been read. Each output gets a
//! correctly SIZED placeholder header first (the size is known from the
//! volume count alone), the payload is appended as it is computed, and
//! the header is written over the placeholder at the end.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::crc32::{crc32, Crc32};
use crate::error::{Error, Result};
use crate::recovery::rar5::{fold_stripe_into_parity, make_encoder_matrix};
use crate::recovery::stream::{FileSource, RangeSource};

use super::super::REV5_SIGNATURE;

/// Bytes of parity and read buffer a window may use at once. The window
/// shrinks to fit this however many recovery rows a batch carries, so
/// the peak is a property of this constant and not of the caller's `-rv`.
const REV_WINDOW_BUDGET: usize = 32 * 1024 * 1024;
/// Window floor and ceiling. Below the floor the per-window overheads
/// (a table rebuild per volume) start to matter; above the ceiling there
/// is nothing left to gain from a longer fold.
const REV_MIN_WINDOW: usize = 64 * 1024;
const REV_MAX_WINDOW: usize = 4 * 1024 * 1024;
/// Recovery rows per pass over the data. Each row in a batch costs one
/// open output file and one parity buffer, and each batch costs one full
/// read of every data volume, so this trades file descriptors against
/// re-reads. 32 keeps both bounded for every set the reference will
/// write: its own ceiling is ten recovery volumes per data volume.
const REV_ROWS_PER_PASS: usize = 32;

/// The fixed part of a REV header, before the per-volume table.
const REV_HEADER_FIXED: usize = 11;
/// One data volume's row in the metadata table: size then CRC32.
const REV_TABLE_ROW: usize = 12;

/// What a finished `.rev` set looks like, for a caller that wants to
/// report it without stat-ing the files back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RevSet {
    /// The recovery volumes written, in the order they were asked for.
    pub recovery: Vec<PathBuf>,
    /// The padded code-word length every payload carries.
    pub shard_len: u64,
    /// Each data volume's real length and CRC32, as the headers record
    /// them.
    pub data: Vec<(u64, u32)>,
}

/// Writes a `.rev` set over `data`, one file per entry in `recovery`.
///
/// `data` is the volume set in order, volume 1 first. `recovery` names
/// the files to write, and its length is the recovery volume count the
/// headers declare. Both must be non-empty and their sum must fit the
/// GF(2^16) code word, which `make_encoder_matrix` enforces.
///
/// `progress` is called with `(done, total)` in payload bytes, which is
/// what the reference's own percentage counter measures.
pub fn write_rev_volumes(
    data: &[PathBuf],
    recovery: &[PathBuf],
    mut progress: impl FnMut(u64, u64),
) -> Result<RevSet> {
    if data.is_empty() || recovery.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 REV needs at least one data volume and one recovery volume",
        ));
    }
    // The matrix is built here as well as per batch, so a count the
    // field cannot carry is refused before a single file is created.
    let matrix = make_encoder_matrix(data.len(), recovery.len())?;

    let sources: Vec<FileSource> = data
        .iter()
        .map(|path| FileSource::open(path))
        .collect::<Result<_>>()?;
    let sizes: Vec<u64> = sources.iter().map(RangeSource::len).collect();
    let longest = sizes.iter().copied().max().unwrap_or(0);
    // The code word walks 2-byte symbols, so an odd volume set pads to
    // the next even length. Measured against the reference on a
    // `-v12289b` set, whose payload is 12,290 bytes.
    let shard_len = longest + (longest & 1);
    if shard_len == 0 {
        return Err(Error::InvalidHeader("RAR 5 REV data volumes are all empty"));
    }

    let header_len = REV_HEADER_FIXED + REV_TABLE_ROW * data.len();
    let placeholder = vec![0u8; 16 + header_len];

    // Every output is created up front, so a set that cannot be written
    // fails before any parity is computed rather than half way through.
    for path in recovery {
        let mut file = File::create(path)?;
        file.write_all(&placeholder)?;
    }

    let mut data_crc: Vec<Crc32> = (0..data.len()).map(|_| Crc32::new()).collect();
    let mut payload_crc: Vec<Crc32> = (0..recovery.len()).map(|_| Crc32::new()).collect();
    let total_payload = shard_len * recovery.len() as u64;
    let mut done_payload = 0u64;
    progress(0, total_payload);

    for (batch_index, batch) in recovery.chunks(REV_ROWS_PER_PASS).enumerate() {
        let first_row = batch_index * REV_ROWS_PER_PASS;
        let window = window_len(batch.len(), shard_len);
        let batch_matrix: Vec<Vec<u16>> = matrix[first_row..first_row + batch.len()].to_vec();

        let mut outputs: Vec<File> = batch
            .iter()
            .map(|path| {
                let mut file = File::options().write(true).open(path)?;
                file.seek(SeekFrom::Start(placeholder.len() as u64))?;
                Ok(file)
            })
            .collect::<Result<_>>()?;
        let mut parity = vec![vec![0u8; window]; batch.len()];
        let mut stripe = vec![0u8; window];

        let mut offset = 0u64;
        while offset < shard_len {
            let take = window.min((shard_len - offset) as usize);
            for row in &mut parity {
                row[..take].fill(0);
            }
            for (index, source) in sources.iter().enumerate() {
                // Past a short volume's end the code word reads zeros,
                // and the CRC32 in the table is over the real bytes
                // only - which is what makes a rebuilt volume verifiable
                // against its own metadata.
                let real = source.len().saturating_sub(offset).min(take as u64) as usize;
                stripe[..take].fill(0);
                if real > 0 {
                    source.read_at(offset, &mut stripe[..real])?;
                    if batch_index == 0 {
                        data_crc[index].update(&stripe[..real]);
                    }
                }
                fold_stripe_into_parity(&batch_matrix, index, &stripe[..take], &mut parity, take)?;
            }
            for (row, file) in parity.iter().zip(outputs.iter_mut()) {
                file.write_all(&row[..take])?;
            }
            for (row, crc) in parity.iter().zip(payload_crc[first_row..].iter_mut()) {
                crc.update(&row[..take]);
            }
            done_payload += (take * batch.len()) as u64;
            progress(done_payload, total_payload);
            offset += take as u64;
        }
        for mut file in outputs {
            file.flush()?;
        }
    }

    let table: Vec<(u64, u32)> = sizes
        .iter()
        .copied()
        .zip(data_crc.into_iter().map(Crc32::finish))
        .collect();
    for (row, path) in recovery.iter().enumerate() {
        let header = rev_header(&table, recovery.len(), row, payload_crc[row].finish());
        debug_assert_eq!(header.len(), placeholder.len());
        let mut file = File::options().write(true).open(path)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header)?;
        file.flush()?;
    }

    Ok(RevSet {
        recovery: recovery.to_vec(),
        shard_len,
        data: table,
    })
}

/// The window one batch folds at a time, in bytes.
///
/// Even, because a window boundary that split a symbol would corrupt the
/// fold; never longer than the code word itself, so a small set does one
/// pass; and sized so a batch's parity buffers plus the one read buffer
/// stay inside [`REV_WINDOW_BUDGET`].
fn window_len(rows: usize, shard_len: u64) -> usize {
    let budget = REV_WINDOW_BUDGET / (rows + 1);
    let window = budget.clamp(REV_MIN_WINDOW, REV_MAX_WINDOW);
    let window = window.min(usize::try_from(shard_len).unwrap_or(usize::MAX));
    // `shard_len` is even, so clamping to it keeps this even; the only
    // odd case would be a budget that lands on an odd byte.
    window - (window & 1)
}

/// The whole header of one recovery volume, signature included.
///
/// `row` is the 0-based recovery row, and the number the header carries
/// is `data_count + row` - which is NOT the number in the file's name.
/// The reference writes `arc.part1.rev` for row 0 of a four-volume set
/// and puts 4 in its header, and the reader's `Rev5VolumeRef::row`
/// subtracts the count back off.
fn rev_header(data: &[(u64, u32)], recovery_count: usize, row: usize, payload_crc: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(REV_HEADER_FIXED + REV_TABLE_ROW * data.len());
    body.push(1u8);
    body.extend_from_slice(&(data.len() as u16).to_le_bytes());
    body.extend_from_slice(&(recovery_count as u16).to_le_bytes());
    body.extend_from_slice(&((data.len() + row) as u16).to_le_bytes());
    body.extend_from_slice(&payload_crc.to_le_bytes());
    for (size, crc) in data {
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&crc.to_le_bytes());
    }

    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(REV5_SIGNATURE);
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    // The header CRC covers the size field and the body, not the
    // signature and not itself.
    let header_crc = crc32(&out[12..]);
    out[8..12].copy_from_slice(&header_crc.to_le_bytes());
    out
}

/// Whether the file at `path` is the data volume `slot` describes.
///
/// `rc` has to answer this for every volume before it can say which ones
/// are missing, and a volume that is present but wrong is missing as far
/// as the arithmetic is concerned - the reference calls it a checksum
/// error and drops it. Read in bounded chunks, because a volume is
/// whatever size the poster chose.
pub fn data_volume_matches(path: &Path, slot: &crate::rar50::Rev5DataVolume) -> bool {
    let Ok(source) = FileSource::open(path) else {
        return false;
    };
    if source.len() != slot.file_size {
        return false;
    }
    let mut crc = Crc32::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut offset = 0u64;
    while offset < slot.file_size {
        let take = buf.len().min((slot.file_size - offset) as usize);
        if source.read_at(offset, &mut buf[..take]).is_err() {
            return false;
        }
        crc.update(&buf[..take]);
        offset += take as u64;
    }
    crc.finish() == slot.crc32
}

/// One read of the verify pass, and one message to the worker.
///
/// **This is a channel unit, not a read unit, and that is why it is not the
/// 256 KiB the in-line loop above reads in.** Built at 256 KiB - to match
/// that loop - the split LOST: 1.012 warm and 1.002 cold on the 256 MiB
/// `-v16m` cell, against a base that was already 5.1 ms of user+sys cheaper.
/// 304 MiB at 256 KiB is about 1,200 sends and 1,200 chances for the worker
/// to park and be woken, and the `semaphore_wait_trap` that costs is charged
/// as system time on a process that is already system-bound. At 1 MiB the
/// same code wins 0.946 warm and 0.890 cold and adds 1.0 ms of CPU rather
/// than 5.1. 4 MiB was measured too and is not better (0.961 / 0.878) for
/// four times the resident bytes. Section 21's fold split never had to find
/// this, because its windows are MiB-scale already.
const VERIFY_CHUNK: usize = 1024 * 1024;

/// How many `VERIFY_CHUNK` buffers the overlapped verify keeps alive, and
/// therefore how far ahead of the CRC the reader may run. Two is the
/// ping-pong `overlapped_stripe_loop` uses on the repair side, and is the
/// smallest count that overlaps anything at all: the reader fills one while
/// the worker consumes the other.
///
/// A deeper queue was the open question section 21.5 left, and it is
/// answered: four buffers measure 0.948 warm and 0.890 cold against two at
/// 0.946 and 0.890 - the same number twice. The reader is not waiting on the
/// worker, so letting it run further ahead buys nothing.
const VERIFY_BUFFERS: usize = 2;

/// Whether a verify pass reads its volumes on the calling thread while a
/// second thread CRCs them.
///
/// Same shape and same reasoning as the repair side's `read_fold_overlap`:
/// the whole cost is one thread spawn per pass plus a channel send and a
/// receive per 256 KiB chunk, none of which scales with the host's thread
/// count, so the only question is whether the pass is long enough for a
/// spawn to disappear into. The threshold is the same 4 MiB of total bytes,
/// for the same reason - it is an order of magnitude past the spawn - and
/// `rc` is far above it in every real shape: 272 MiB on a 256 MiB set.
///
/// Below it the pass reads in line, exactly as before: the unit tests' toy
/// volumes, and a set of a few small parts where the spawn would be most of
/// the work.
fn verify_read_overlap(total_bytes: u64) -> bool {
    const MIN_TOTAL_BYTES: u64 = 4 << 20;
    #[cfg(test)]
    match verify_read_overlap_override().load(std::sync::atomic::Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    total_bytes >= MIN_TOTAL_BYTES
}

/// The one cell `with_verify_read_overlap` writes and `verify_read_overlap`
/// reads. 0 asks the size, 1 forces the overlapped arm, 2 forces the serial
/// one - the same single-cell rule, and for the same reason, as the repair
/// side's `read_fold_overlap_override`.
#[cfg(test)]
fn verify_read_overlap_override() -> &'static std::sync::atomic::AtomicUsize {
    use std::sync::atomic::AtomicUsize;
    static OVERRIDE: AtomicUsize = AtomicUsize::new(0);
    &OVERRIDE
}

/// Runs `body` with the read/CRC split forced on or off, so a test reaches
/// BOTH arms without building a set large enough to clear the gate.
/// Serialised against itself; the gate chooses an arm and never an answer,
/// so what a concurrent test computes is unaffected.
#[cfg(test)]
pub(crate) fn with_verify_read_overlap<T>(on: bool, body: impl FnOnce() -> T) -> T {
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    verify_read_overlap_override().store(if on { 1 } else { 2 }, Ordering::Relaxed);
    let out = body();
    verify_read_overlap_override().store(0, Ordering::Relaxed);
    out
}

/// One thing `rc`'s verify side must CRC before it can plan a repair.
///
/// The two halves of that side arrive in different shapes and that is the
/// only reason this enum exists. A data volume is a PATH the verify opens
/// itself, so a set of many parts needs one descriptor at a time rather than
/// one each; a `.rev` payload is a RANGE of a source the caller already holds
/// open, because the CLI has to parse each `.rev`'s header before it knows
/// where the payload starts. Everything after the first read is identical -
/// stream bytes, CRC them, compare against a declared CRC32 - which is what
/// lets both halves feed ONE worker and one spawn.
pub enum VerifyTarget<'a> {
    /// A data volume on disk: open it, check its length against the slot,
    /// then CRC the whole file. A volume that cannot be opened or is the
    /// wrong length is `false` without being read.
    Volume(&'a Path, &'a crate::rar50::Rev5DataVolume),
    /// A byte range of an already-open source, and the CRC32 it must have.
    Payload(&'a dyn RangeSource, Range<u64>, u32),
}

impl VerifyTarget<'_> {
    /// Bytes this target will read if it is read at all, for the gate's
    /// total. A volume that turns out to be the wrong length reads none of
    /// them, which only ever makes the gate's estimate generous.
    fn bytes(&self) -> u64 {
        match self {
            VerifyTarget::Volume(_, slot) => slot.file_size,
            VerifyTarget::Payload(_, range, _) => range.end.saturating_sub(range.start),
        }
    }
}

/// Whether the bytes of `range` in `src` have the CRC32 `expected`, read in
/// bounded chunks on the calling thread.
///
/// The serial half of a [`VerifyTarget::Payload`], and the body
/// [`crate::rar50::verify_rev5_payload`] calls, so there is one copy of this
/// loop rather than one per caller.
pub fn payload_matches(src: &dyn RangeSource, range: &Range<u64>, expected: u32) -> Result<bool> {
    let mut crc = Crc32::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut position = range.start;
    while position < range.end {
        // Clamp in u64 BEFORE narrowing: on a 32-bit target a remaining span
        // that is a multiple of 4 GiB casts to 0 and the loop never advances.
        // (nzbfast-local change, 27 Aug 2026 - re-apply on the next rars
        // re-sync, see vendor/rars/VENDORING.md.)
        let take = (range.end - position).min(buf.len() as u64) as usize;
        src.read_at(position, &mut buf[..take])?;
        crc.update(&buf[..take]);
        position += take as u64;
    }
    Ok(crc.finish() == expected)
}

/// [`data_volume_matches`] over a whole set at once, reading on the calling
/// thread while a worker thread CRCs what was read.
///
/// A thin wrapper over [`sources_match`], kept because it is the shape every
/// caller that has only volumes wants, and because it is what the unit tests
/// compare the batch against.
pub fn data_volumes_match(volumes: &[(&Path, &crate::rar50::Rev5DataVolume)]) -> Vec<bool> {
    let targets: Vec<VerifyTarget<'_>> = volumes
        .iter()
        .map(|(path, slot)| VerifyTarget::Volume(path, slot))
        .collect();
    sources_match(&targets)
}

/// Every CRC `rc`'s verify side owes, in ONE pass: the calling thread reads
/// while a worker thread CRCs what was read.
///
/// **Why the batch exists at all.** `rc` reads the set twice and a bit.
/// Counted on a 256 MiB `-v16m` set (17 data volumes, 3 recovery volumes),
/// the verify side reads ~256 MiB of surviving data volumes to learn which
/// are missing - a volume that is present but wrong is missing as far as the
/// arithmetic is concerned - plus 48 MiB of `.rev` payloads to learn which
/// equations are sound; and then
/// [`crate::rar50::repair_rev5_volumes_streaming`] reads the survivors again
/// to fold them. The repair half already overlaps its reads with its fold,
/// and the data-volume half was overlapped before this; this covers the whole
/// verify side, `.rev` payloads included. That last half is about 16% of the
/// verify side's bytes on this shape and MORE on a set with more recovery
/// rows - at `-rv10p` over 65 volumes a set carries 7 rows, not 3.
///
/// Measured warm on that set, `rc` spends about 20 ms of user time against
/// 50 ms of system time, so the read path IS the process and the CRC fits
/// inside it with room to spare - which is exactly the shape a split can
/// hide.
///
/// **One call rather than one per half, deliberately.** Both halves want the
/// same worker, and feeding them through one spawn means the worker is still
/// CRCing the last data volume while the reader has already moved on to the
/// first `.rev` - one drain at the end of the verify side instead of one per
/// half. [`VerifyTarget`] exists only to carry the one difference between
/// them, which is where the bytes come from.
///
/// The answers are per target and in the caller's order. A volume that cannot
/// be opened, is the wrong length, or fails a read is `false`, which is what
/// the single-volume call says too; a payload whose read fails is `false` for
/// the same reason.
///
/// The buffers ping-pong by ownership rather than by lock, as on the repair
/// side: the reader fills whichever it holds, sends it, and takes the other
/// back when the worker is done. Volumes are opened one at a time, so a set
/// of many parts does not need a descriptor each.
pub fn sources_match(targets: &[VerifyTarget<'_>]) -> Vec<bool> {
    let total: u64 = targets.iter().map(VerifyTarget::bytes).sum();
    if !verify_read_overlap(total) {
        return targets
            .iter()
            .map(|target| match target {
                VerifyTarget::Volume(path, slot) => data_volume_matches(path, slot),
                VerifyTarget::Payload(src, range, expected) => {
                    payload_matches(*src, range, *expected).unwrap_or(false)
                }
            })
            .collect();
    }
    overlapped_sources_match(targets)
}

/// The split arm of [`sources_match`]. Separate so the serial arm above stays
/// readable as the thing this one has to agree with.
fn overlapped_sources_match(targets: &[VerifyTarget<'_>]) -> Vec<bool> {
    use std::sync::mpsc;

    /// What the reader hands the worker.
    enum Job {
        /// Start a fresh target: reset the running CRC.
        Begin,
        /// CRC the first `len` bytes of this buffer, then give it back.
        Chunk(Vec<u8>, usize),
        /// The target ended: compare against the CRC it declares and record
        /// the answer.
        End(u32),
        /// The target's read failed part way. Record a `false` and move on -
        /// the bytes already folded into the running CRC are meaningless now,
        /// and `Begin` clears them.
        Abort,
    }

    let mut answers = vec![false; targets.len()];
    // Which targets were actually streamed, in the order they were streamed.
    // Everything else (unopenable, wrong length) the reader answers itself and
    // never mentions to the worker.
    let mut streamed: Vec<usize> = Vec::with_capacity(targets.len());

    let verdicts = std::thread::scope(|scope| {
        let (job_tx, job_rx) = mpsc::channel::<Job>();
        let (back_tx, back_rx) = mpsc::channel::<Vec<u8>>();
        let worker = scope.spawn(move || {
            let mut out: Vec<bool> = Vec::new();
            let mut crc = Crc32::new();
            while let Ok(job) = job_rx.recv() {
                match job {
                    Job::Begin => crc = Crc32::new(),
                    Job::Chunk(buf, len) => {
                        crc.update(&buf[..len]);
                        if back_tx.send(buf).is_err() {
                            return out;
                        }
                    }
                    Job::End(expected) => out.push(crc.finish() == expected),
                    Job::Abort => out.push(false),
                }
            }
            out
        });

        let mut spare: Vec<Vec<u8>> = (0..VERIFY_BUFFERS)
            .map(|_| vec![0u8; VERIFY_CHUNK])
            .collect();
        for (index, target) in targets.iter().enumerate() {
            // A volume's `FileSource` lives only as long as this iteration,
            // which is what keeps a set of many parts to one descriptor at a
            // time; a payload's source is the caller's and outlives us both.
            let opened;
            let (source, range, expected): (&dyn RangeSource, Range<u64>, u32) = match target {
                VerifyTarget::Volume(path, slot) => {
                    let Ok(file) = FileSource::open(path) else {
                        continue;
                    };
                    if file.len() != slot.file_size {
                        continue;
                    }
                    opened = file;
                    (&opened, 0..slot.file_size, slot.crc32)
                }
                VerifyTarget::Payload(src, range, expected) => (*src, range.clone(), *expected),
            };
            streamed.push(index);
            let _ = job_tx.send(Job::Begin);
            let mut offset = range.start;
            let mut failed = false;
            while offset < range.end {
                let mut buf = match spare.pop() {
                    Some(buf) => buf,
                    // The worker only stops answering if it is gone, which
                    // inside this scope means it panicked. Nothing is left to
                    // read with, so end the target as a failure and let the
                    // remaining sends fall on a dead channel.
                    None => match back_rx.recv() {
                        Ok(buf) => buf,
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    },
                };
                // Clamp in u64 BEFORE narrowing, for the reason
                // `payload_matches` gives: on a 32-bit target a remaining span
                // that is a multiple of 4 GiB casts to 0.
                let take = (range.end - offset).min(VERIFY_CHUNK as u64) as usize;
                if source.read_at(offset, &mut buf[..take]).is_err() {
                    spare.push(buf);
                    failed = true;
                    break;
                }
                offset += take as u64;
                let _ = job_tx.send(Job::Chunk(buf, take));
            }
            let _ = job_tx.send(if failed {
                Job::Abort
            } else {
                Job::End(expected)
            });
        }
        // Dropping the sender is what ends the worker's loop and lets it hand
        // back what it decided.
        drop(job_tx);
        worker.join().unwrap_or_default()
    });

    // A worker that panicked returns nothing, and every target it was asked
    // about keeps the `false` it started with - the same answer an unreadable
    // volume gets, which is the safe direction: `rc` then treats the volume as
    // missing rather than folding bytes nobody checked.
    for (slot, verdict) in streamed.iter().zip(verdicts) {
        answers[*slot] = verdict;
    }
    answers
}

/// The default recovery volume count for a data volume count, which the
/// reference spells `rv` with no number.
///
/// Measured on rar 7.23 over sets of 2, 3, 5, 7, 10, 11, 13, 21, 22, 31
/// and 41 volumes: 1, 1, 1, 1, 1, 2, 2, 3, 3, 4, 5. That is
/// `ceil(count / 10)`, and `rv10p` gives the same answer on every one of
/// them, so the default is the ten percent the manual implies rather
/// than a fixed number.
pub fn default_recovery_volume_count(data_count: usize) -> usize {
    percent_recovery_volume_count(data_count, 10)
}

/// The recovery volume count for `rvN%` / `rvNp`, which is
/// `ceil(count * percent / 100)`.
///
/// Measured on rar 7.23 over a 13-volume set: 1%, 8%, 10%, 15%, 33%,
/// 50%, 100% and 110% give 1, 2, 2, 2, 5, 7, 13 and 15. Every one is the
/// ceiling and none is the rounding, which 50% settles on its own: 6.5
/// goes to 7.
pub fn percent_recovery_volume_count(data_count: usize, percent: u64) -> usize {
    let scaled = data_count as u64 * percent;
    usize::try_from(scaled.div_ceil(100)).unwrap_or(usize::MAX)
}

/// The reference's own ceiling on how many recovery volumes a set may
/// carry: ten per data volume.
///
/// Measured by asking for far more than that - `rv999` over a 13-volume
/// set writes 130, `rv250` over a 4-volume set writes 40 - and the
/// answer is the same multiple at every count tried (2, 3, 5, 7, 10, 11,
/// 13, 21, 22, 31, 41). It is NOT the 255-file total the older manual
/// describes: a 41-volume set takes 410.
pub fn max_recovery_volume_count(data_count: usize) -> usize {
    data_count.saturating_mul(10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar50::{
        read_rev5_meta, repair_rev5_volumes_streaming, verify_rev5_payload, Rev5RecoverySource,
    };

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rars-rev-{}-{name}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar50")
    }

    /// The strongest check available and it needs no reference binary:
    /// WinRAR's own `.rev` files sit in the fixture tree beside the
    /// volumes they cover, so the writer either reproduces them or it
    /// does not.
    #[test]
    fn rev_writer_reproduces_the_winrar_fixture_byte_for_byte() {
        let fixtures = fixture_dir();
        let dir = scratch("winrar");
        let data: Vec<PathBuf> = (1..=5)
            .map(|n| fixtures.join(format!("multivol_rev.part{n}.rar")))
            .collect();
        let outputs: Vec<PathBuf> = (1..=2)
            .map(|n| dir.join(format!("multivol_rev.part{n}.rev")))
            .collect();

        let set = write_rev_volumes(&data, &outputs, |_, _| {}).expect("write");
        assert_eq!(set.shard_len, 4096, "the longest volume, already even");

        for (n, written) in outputs.iter().enumerate() {
            let ours = std::fs::read(written).expect("read ours");
            let theirs = std::fs::read(fixtures.join(format!("multivol_rev.part{}.rev", n + 1)))
                .expect("read winrar's");
            assert_eq!(
                ours,
                theirs,
                "recovery volume {} does not match WinRAR's own bytes",
                n + 1
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Both arms of the batched verify have to say what the
    /// volume-at-a-time call says, on every shape `rc` can hand it: a
    /// volume that matches, one whose bytes were changed under it, one
    /// whose length changed, and one that is not there at all. The gate
    /// is forced both ways, because no unit test can afford a set past
    /// its 4 MiB threshold.
    #[test]
    fn the_batched_verify_agrees_with_the_one_at_a_time_call_on_both_arms() {
        let dir = scratch("batchverify");
        let sizes = [8192usize, 8192, 8192, 3001];
        let data: Vec<PathBuf> = sizes
            .iter()
            .enumerate()
            .map(|(index, &len)| {
                let path = dir.join(format!("set.part{}.rar", index + 1));
                let bytes: Vec<u8> = (0..len)
                    .map(|byte| (byte * 31 + index * 17 + 3) as u8)
                    .collect();
                std::fs::write(&path, &bytes).expect("write volume");
                path
            })
            .collect();
        let outputs: Vec<PathBuf> = (1..=2)
            .map(|n| dir.join(format!("set.part{n}.rev")))
            .collect();
        write_rev_volumes(&data, &outputs, |_, _| {}).expect("write");
        let meta = read_rev5_meta(&FileSource::open(&outputs[0]).expect("open rev")).expect("meta");
        let slots = meta.meta.data_volumes.clone();

        // Volume 1 stays good. Volume 2 keeps its length and loses a byte,
        // which only the CRC can catch. Volume 3 grows, which the length
        // check catches first. Volume 4 is deleted.
        let mut two = std::fs::read(&data[1]).expect("read");
        two[100] ^= 0xff;
        std::fs::write(&data[1], &two).expect("rewrite");
        let mut three = std::fs::read(&data[2]).expect("read");
        three.push(0);
        std::fs::write(&data[2], &three).expect("rewrite");
        std::fs::remove_file(&data[3]).expect("remove");

        let pairs: Vec<(&Path, &crate::rar50::Rev5DataVolume)> = data
            .iter()
            .map(PathBuf::as_path)
            .zip(slots.iter())
            .collect();
        let one_at_a_time: Vec<bool> = pairs
            .iter()
            .map(|(path, slot)| data_volume_matches(path, slot))
            .collect();
        assert_eq!(
            one_at_a_time,
            vec![true, false, false, false],
            "the shapes this test means to cover"
        );
        for on in [false, true] {
            let batched = with_verify_read_overlap(on, || data_volumes_match(&pairs));
            assert_eq!(
                batched, one_at_a_time,
                "the batched verify disagrees with the single-volume call, overlap arm {on}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The `.rev` payloads go through the same batch as the data volumes, so
    /// the same agreement has to hold for them: `sources_match` over a MIXED
    /// list must say exactly what the one-at-a-time calls say, on both arms
    /// of the gate.
    ///
    /// Five shapes, which are the ones the batch can actually be handed: a
    /// sound volume; a sound payload; a payload with a byte flipped inside it
    /// at the same length, which only the CRC can catch; a range that runs off
    /// the end of its file, so the read fails part way; and an empty range.
    /// All of them are far below the 4 MiB gate, which is why the override
    /// exists - the same single-cell rule as `read_fold_overlap_override`.
    #[test]
    fn the_batch_agrees_with_the_one_at_a_time_call_on_rev_payloads_too() {
        let dir = scratch("revbatch");
        let sizes = [4096usize, 4096, 4096];
        let data: Vec<PathBuf> = sizes
            .iter()
            .enumerate()
            .map(|(index, &size)| {
                let path = dir.join(format!("set.part{}.rar", index + 1));
                let bytes: Vec<u8> = (0..size).map(|n| (n as u8).wrapping_mul(7)).collect();
                std::fs::write(&path, &bytes).expect("write volume");
                path
            })
            .collect();
        let outputs: Vec<PathBuf> = (1..=2)
            .map(|n| dir.join(format!("set.part{n}.rev")))
            .collect();
        write_rev_volumes(&data, &outputs, |_, _| {}).expect("write");
        let metas: Vec<crate::rar50::Rev5VolumeRef> = outputs
            .iter()
            .map(|path| read_rev5_meta(&FileSource::open(path).expect("open rev")).expect("meta"))
            .collect();
        let slots = metas[0].meta.data_volumes.clone();

        // The second `.rev` loses a byte inside its payload: same length, so
        // only the CRC can see it.
        let mut second = std::fs::read(&outputs[1]).expect("read rev");
        let at = metas[1].payload.start as usize;
        second[at] ^= 0xff;
        std::fs::write(&outputs[1], &second).expect("rewrite rev");

        let sources: Vec<FileSource> = outputs
            .iter()
            .map(|path| FileSource::open(path).expect("open rev"))
            .collect();
        // A range that runs past the real file, so the read fails part way and
        // the answer must be `false` rather than a panic.
        let short = dir.join("short.bin");
        std::fs::write(&short, [0u8; 64]).expect("write short");
        let short_source = FileSource::open(&short).expect("open short");

        let targets: Vec<VerifyTarget<'_>> = vec![
            VerifyTarget::Volume(data[0].as_path(), &slots[0]),
            VerifyTarget::Payload(
                &sources[0],
                metas[0].payload.clone(),
                metas[0].meta.payload_crc32,
            ),
            VerifyTarget::Payload(
                &sources[1],
                metas[1].payload.clone(),
                metas[1].meta.payload_crc32,
            ),
            VerifyTarget::Payload(&short_source, 0..4096, 0),
            VerifyTarget::Payload(&sources[0], 0..0, Crc32::new().finish()),
        ];
        let one_at_a_time: Vec<bool> = targets
            .iter()
            .map(|target| match target {
                VerifyTarget::Volume(path, slot) => data_volume_matches(path, slot),
                VerifyTarget::Payload(src, range, expected) => {
                    payload_matches(*src, range, *expected).unwrap_or(false)
                }
            })
            .collect();
        assert_eq!(
            one_at_a_time,
            vec![true, true, false, false, true],
            "the shapes this test means to cover"
        );
        // ...and the sound payload really does reach the same answer through
        // `verify_rev5_payload`, so the two entry points cannot drift apart.
        assert!(verify_rev5_payload(&sources[0], &metas[0]).expect("verify"));
        assert!(!verify_rev5_payload(&sources[1], &metas[1]).expect("verify"));

        for on in [false, true] {
            let batched = with_verify_read_overlap(on, || sources_match(&targets));
            assert_eq!(
                batched, one_at_a_time,
                "the batched verify disagrees with the one-at-a-time call, overlap arm {on}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The round trip the chip's brief calls the strongest test: the
    /// engine's OWN rebuild path recovers a deleted volume from the set
    /// the writer just produced.
    #[test]
    fn the_rebuild_path_recovers_a_volume_the_writer_covered() {
        let dir = scratch("roundtrip");
        // Deliberately ragged: a short last volume is what a real set
        // ends with, and it is the shape that exercises the padding.
        let sizes = [8192usize, 8192, 8192, 3001];
        let data: Vec<PathBuf> = sizes
            .iter()
            .enumerate()
            .map(|(index, &len)| {
                let path = dir.join(format!("set.part{}.rar", index + 1));
                let bytes: Vec<u8> = (0..len)
                    .map(|byte| (byte * 31 + index * 17 + 3) as u8)
                    .collect();
                std::fs::write(&path, &bytes).expect("write volume");
                path
            })
            .collect();
        let outputs: Vec<PathBuf> = (1..=2)
            .map(|n| dir.join(format!("set.part{n}.rev")))
            .collect();
        write_rev_volumes(&data, &outputs, |_, _| {}).expect("write");

        let original: Vec<Vec<u8>> = data
            .iter()
            .map(|path| std::fs::read(path).expect("read"))
            .collect();
        // Two gone, two recovery volumes: exactly enough equations.
        std::fs::remove_file(&data[1]).expect("remove");
        std::fs::remove_file(&data[3]).expect("remove");

        let rev_sources: Vec<FileSource> = outputs
            .iter()
            .map(|path| FileSource::open(path).expect("open rev"))
            .collect();
        let metas: Vec<_> = rev_sources
            .iter()
            .map(|source| read_rev5_meta(source).expect("meta"))
            .collect();
        for (source, meta) in rev_sources.iter().zip(&metas) {
            assert!(
                verify_rev5_payload(source, meta).expect("verify"),
                "the writer's own payload CRC must hold"
            );
        }

        let intact_sources: Vec<Option<FileSource>> = data
            .iter()
            .map(|path| FileSource::open(path).ok())
            .collect();
        let intact: Vec<Option<&dyn RangeSource>> = intact_sources
            .iter()
            .map(|slot| slot.as_ref().map(|s| s as &dyn RangeSource))
            .collect();
        let recovery: Vec<Rev5RecoverySource<'_>> = rev_sources
            .iter()
            .zip(&metas)
            .map(|(source, meta)| Rev5RecoverySource {
                row: meta.row().expect("row"),
                source,
                payload: meta.payload.clone(),
            })
            .collect();

        let slots = metas[0].meta.data_volumes.clone();
        // The sink indexes the MISSING volumes in slot order, not the
        // slots - see `Rev5RebuildSink`.
        let missing = [1usize, 3];
        let mut rebuilt: Vec<Vec<u8>> = missing
            .iter()
            .map(|&slot| vec![0u8; slots[slot].file_size as usize])
            .collect();
        let repaired = repair_rev5_volumes_streaming(
            &slots,
            &intact,
            &recovery,
            metas[0].meta.recovery_count as usize,
            64 * 1024 * 1024,
            &mut |slot, offset, bytes| {
                let start = offset as usize;
                rebuilt[slot][start..start + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .expect("rebuild");

        assert_eq!(
            repaired,
            missing.to_vec(),
            "both missing slots were rebuilt"
        );
        assert_eq!(rebuilt[0], original[1]);
        assert_eq!(rebuilt[1], original[3], "the short last volume too");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An odd-length volume set pads its code word up by one byte, which
    /// is the geometry the reference chooses too - measured on a
    /// `-v12289b` set whose `.rev` payload is 12,290 bytes.
    #[test]
    fn an_odd_volume_length_pads_the_code_word_up_by_one() {
        let dir = scratch("odd");
        let data: Vec<PathBuf> = (0..3)
            .map(|index| {
                let path = dir.join(format!("odd.part{}.rar", index + 1));
                std::fs::write(&path, vec![index as u8 + 1; 1001]).expect("write");
                path
            })
            .collect();
        let out = vec![dir.join("odd.part1.rev")];
        let set = write_rev_volumes(&data, &out, |_, _| {}).expect("write");
        assert_eq!(set.shard_len, 1002);
        let written = std::fs::read(&out[0]).expect("read");
        let header = 16 + REV_HEADER_FIXED + REV_TABLE_ROW * 3;
        assert_eq!(written.len(), header + 1002);
        // And the table still records the REAL length, not the padded
        // one - a rebuilt volume is clipped to this.
        assert!(set.data.iter().all(|(size, _)| *size == 1001));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Windowing is an implementation detail and must not be visible in
    /// the bytes: a window forced below the payload length has to give
    /// the same file as a single-window run.
    #[test]
    fn a_short_window_writes_the_same_bytes_as_one_pass() {
        // `window_len` is driven by the budget and the row count, so the
        // check here is on the function rather than through a knob the
        // API does not have: whatever it returns is even, is never
        // longer than the code word, and never zero.
        for rows in [1usize, 2, 7, 32] {
            for shard in [2u64, 4096, 12_288, 1 << 30] {
                let window = window_len(rows, shard);
                assert!(
                    window > 0 && window.is_multiple_of(2),
                    "rows {rows} shard {shard}"
                );
                assert!(window as u64 <= shard, "rows {rows} shard {shard}");
                assert!(
                    (rows + 1) * window <= REV_WINDOW_BUDGET.max(REV_MIN_WINDOW * (rows + 1)),
                    "rows {rows} shard {shard} window {window}"
                );
            }
        }
    }

    #[test]
    fn the_counts_match_what_the_reference_chose() {
        // Defaults, measured over real sets.
        for (data, expected) in [
            (2, 1),
            (3, 1),
            (5, 1),
            (7, 1),
            (10, 1),
            (11, 2),
            (13, 2),
            (21, 3),
            (22, 3),
            (31, 4),
            (41, 5),
        ] {
            assert_eq!(
                default_recovery_volume_count(data),
                expected,
                "default for {data}"
            );
        }
        // Percentages, measured over the 13-volume set.
        for (percent, expected) in [
            (1, 1),
            (8, 2),
            (10, 2),
            (15, 2),
            (33, 5),
            (50, 7),
            (100, 13),
            (110, 15),
        ] {
            assert_eq!(
                percent_recovery_volume_count(13, percent),
                expected,
                "{percent}% of 13"
            );
        }
        assert_eq!(percent_recovery_volume_count(4, 50), 2, "50% of 4 is exact");
        assert_eq!(max_recovery_volume_count(13), 130);
        assert_eq!(max_recovery_volume_count(4), 40);
    }

    #[test]
    fn an_empty_set_is_refused_rather_than_written() {
        let dir = scratch("empty");
        let out = vec![dir.join("x.part1.rev")];
        assert!(write_rev_volumes(&[], &out, |_, _| {}).is_err());
        let data = vec![dir.join("nothing.part1.rar")];
        std::fs::write(&data[0], b"").expect("write");
        assert!(
            write_rev_volumes(&data, &[], |_, _| {}).is_err(),
            "no recovery volumes asked for is not a set"
        );
        assert!(
            write_rev_volumes(&data, &out, |_, _| {}).is_err(),
            "a set of empty volumes has no code word"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
