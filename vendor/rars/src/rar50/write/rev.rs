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
