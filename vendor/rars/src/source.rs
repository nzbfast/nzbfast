use crate::error::{Error, Result};
use crate::io_util::read_exact_at;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};

/// A byte source whose contents may still be arriving.
///
/// Reads BLOCK until the requested offset is populated instead of reporting
/// a premature end, which lets the forward-only decode paths chase a data
/// frontier that advances while extraction runs (bytes arriving over the
/// network, being decoded upstream, and so on).
///
/// Contract:
/// - `read_at` returns at least one byte once data exists at `offset`,
///   blocking until then. It returns `Ok(0)` only when the source is known
///   to end at or before `offset` (its final length is set and reached).
/// - A producer that cannot finish MUST fail the source so blocked readers
///   wake with an error; otherwise they wait forever. Concrete sources
///   expose this as an abort/fail operation (see [`GrowableBuffer::abort`]),
///   which is also how callers cancel an in-flight extraction.
/// - Implementations must be safe to read from several threads at once;
///   readers at different offsets must not starve each other.
pub trait BlockingRangeSource: Send + Sync + std::fmt::Debug {
    /// Reads bytes at `offset`, blocking until at least one is available,
    /// the source ends at or before `offset` (`Ok(0)`), or the source is
    /// aborted (`Err`).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Bytes currently available from the start of the source.
    fn known_len(&self) -> u64;

    /// The declared final length, once known.
    fn total_len(&self) -> Option<u64>;
}

#[derive(Debug, Clone)]
pub(crate) enum ArchiveSource {
    Memory(Arc<[u8]>),
    File(Arc<PathBuf>),
    Stream {
        source: Arc<dyn BlockingRangeSource>,
        len: usize,
    },
}

impl ArchiveSource {
    pub(crate) fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>> {
        match self {
            Self::Memory(data) => data
                .get(range)
                .map(|data| data.to_vec())
                .ok_or(Error::TooShort),
            Self::File(path) => {
                let mut file = File::open(path.as_ref())?;
                read_exact_at(&mut file, range.start, range.len())
            }
            Self::Stream { source, len } => {
                if range.start > range.end || range.end > *len {
                    return Err(Error::TooShort);
                }
                let mut data = vec![0; range.len()];
                stream_read_exact(source.as_ref(), range.start as u64, &mut data)?;
                Ok(data)
            }
        }
    }

    pub(crate) fn copy_range_to(&self, range: Range<usize>, writer: &mut dyn Write) -> Result<()> {
        match self {
            Self::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                writer.write_all(data)?;
            }
            Self::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                let mut limited = file.take(range.len() as u64);
                std::io::copy(&mut limited, writer)?;
            }
            Self::Stream { .. } => {
                let mut reader = self.range_reader(range)?;
                std::io::copy(&mut reader, writer)?;
            }
        }
        Ok(())
    }

    pub(crate) fn range_reader(&self, range: Range<usize>) -> Result<Box<dyn Read + Send + '_>> {
        match self {
            Self::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                Ok(Box::new(Cursor::new(data)))
            }
            Self::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                Ok(Box::new(file.take(range.len() as u64)))
            }
            Self::Stream { source, len } => {
                if range.start > range.end || range.end > *len {
                    return Err(Error::TooShort);
                }
                Ok(Box::new(BlockingRangeReader {
                    source: Arc::clone(source),
                    pos: range.start as u64,
                    end: range.end as u64,
                }))
            }
        }
    }

    /// Fills `buf` from `offset` without allocating.
    ///
    /// [`read_range`](Self::read_range) hands back a fresh `Vec` per call,
    /// which is fine for a header but not for the streaming repair paths:
    /// those read a whole volume one window at a time, and a 256 KB
    /// allocation per window is pure churn on a 20 GB file.
    pub(crate) fn read_range_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| Error::TooShort)?;
        let end = start.checked_add(buf.len()).ok_or(Error::TooShort)?;
        match self {
            Self::Memory(data) => {
                buf.copy_from_slice(data.get(start..end).ok_or(Error::TooShort)?);
                Ok(())
            }
            Self::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(buf)?;
                Ok(())
            }
            Self::Stream { source, len } => {
                if end > *len {
                    return Err(Error::TooShort);
                }
                stream_read_exact(source.as_ref(), offset, buf)
            }
        }
    }

    /// [`range_reader`](Self::range_reader) without the borrow.
    ///
    /// The growing split chain (`extract_volume_sequence_to`'s incremental
    /// path) holds a cursor over volume k's fragment while it keeps pulling
    /// volume k+1 into the same `Vec<Archive>` - a borrowing reader would
    /// pin that Vec against the push. Every variant can serve one range
    /// from an owned handle, so the chain carries no lifetime at all.
    pub(crate) fn owned_range_reader(&self, range: Range<usize>) -> Result<OwnedRangeReader> {
        if range.start > range.end {
            return Err(Error::TooShort);
        }
        match self {
            Self::Memory(data) => {
                if range.end > data.len() {
                    return Err(Error::TooShort);
                }
                Ok(OwnedRangeReader::Memory {
                    data: Arc::clone(data),
                    pos: range.start,
                    end: range.end,
                })
            }
            Self::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                Ok(OwnedRangeReader::File {
                    file,
                    remaining: range.len() as u64,
                })
            }
            Self::Stream { source, len } => {
                if range.end > *len {
                    return Err(Error::TooShort);
                }
                Ok(OwnedRangeReader::Stream {
                    source: Arc::clone(source),
                    pos: range.start as u64,
                    end: range.end as u64,
                })
            }
        }
    }

    pub(crate) fn len(&self) -> Result<usize> {
        match self {
            Self::Memory(data) => Ok(data.len()),
            Self::File(path) => usize::try_from(std::fs::metadata(path.as_ref())?.len())
                .map_err(|_| Error::InvalidHeader("archive size overflows host address size")),
            Self::Stream { len, .. } => Ok(*len),
        }
    }

    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Memory(data) => Ok(data.to_vec()),
            Self::File(path) => Ok(std::fs::read(path.as_ref())?),
            Self::Stream { len, .. } => self.read_range(0..*len),
        }
    }
}

/// Sequential `Read` over one range of a source, owning whatever handle it
/// needs - see [`ArchiveSource::owned_range_reader`]. A file-backed reader
/// holds exactly one descriptor and the caller drops it before opening the
/// next range, so descriptor use stays O(1) over a many-fragment member.
#[derive(Debug)]
pub(crate) enum OwnedRangeReader {
    Memory {
        data: Arc<[u8]>,
        pos: usize,
        end: usize,
    },
    File {
        file: File,
        remaining: u64,
    },
    Stream {
        source: Arc<dyn BlockingRangeSource>,
        pos: u64,
        end: u64,
    },
}

impl Read for OwnedRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self {
            Self::Memory { data, pos, end } => {
                let take = buf.len().min(*end - *pos);
                if take == 0 {
                    return Ok(0);
                }
                buf[..take].copy_from_slice(&data[*pos..*pos + take]);
                *pos += take;
                Ok(take)
            }
            Self::File { file, remaining } => {
                let take = buf
                    .len()
                    .min(usize::try_from(*remaining).unwrap_or(usize::MAX));
                if take == 0 {
                    return Ok(0);
                }
                let read = file.read(&mut buf[..take])?;
                if read == 0 {
                    return Err(short_range());
                }
                *remaining -= read as u64;
                Ok(read)
            }
            Self::Stream { source, pos, end } => {
                let remaining = end.saturating_sub(*pos);
                if remaining == 0 {
                    return Ok(0);
                }
                let take = buf
                    .len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                let read = source.read_at(*pos, &mut buf[..take])?;
                if read == 0 {
                    return Err(short_range());
                }
                *pos += read as u64;
                Ok(read)
            }
        }
    }
}

/// A range that ended before the bytes it declared.
///
/// (nzbfast-local change, 26 Aug 2026 - re-apply on the next rars
/// re-sync, see vendor/rars/VENDORING.md.) The sequential
/// readers above report it as an ERROR rather than as EOF, and that
/// distinction is the whole point of the helper: `Ok(0)` on a range with
/// bytes still owed is indistinguishable from a clean end, so a
/// sequential consumer treats it as one and walks on to the next
/// fragment - `rar50::extract` and `rar15_40::extract` both do. A volume
/// whose payload was cut short (a chase whose yEnc size fell short of the
/// header's range, a file truncated after parse) then "extracted": later
/// members were decoded from the following fragment's first bytes, and a
/// member with no CRC of its own was written truncated with nothing
/// saying so. The exact-range path has always failed closed here
/// ([`stream_read_exact`] below); this is the sequential path agreeing
/// with it.
fn short_range() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "archive range ended before its declared length",
    )
}

/// Fills `buf` from a blocking source, mapping a source that ends short of
/// the requested range to the same error the in-memory path reports.
pub(crate) fn stream_read_exact(
    source: &dyn BlockingRangeSource,
    mut offset: u64,
    mut buf: &mut [u8],
) -> Result<()> {
    while !buf.is_empty() {
        let read = source.read_at(offset, buf)?;
        if read == 0 {
            return Err(Error::TooShort);
        }
        offset += read as u64;
        buf = &mut buf[read..];
    }
    Ok(())
}

/// Sequential `Read` over one range of a blocking source. Each `read` call
/// blocks until the source has bytes at the cursor, so a decoder pulling
/// from this reader waits at the data frontier instead of failing.
struct BlockingRangeReader {
    source: Arc<dyn BlockingRangeSource>,
    pos: u64,
    end: u64,
}

impl Read for BlockingRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.end.saturating_sub(self.pos);
        if remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let take = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = self.source.read_at(self.pos, &mut buf[..take])?;
        // A blocking source waits at the frontier, so a zero read here is
        // not "not yet" - it is the source declaring it will never reach
        // this offset. Same argument as `short_range` above.
        if read == 0 {
            return Err(short_range());
        }
        self.pos += read as u64;
        Ok(read)
    }
}

/// Reference [`BlockingRangeSource`]: an in-memory buffer that grows at a
/// contiguous frontier while readers block for bytes that have not arrived.
///
/// A producer thread calls [`append`](Self::append) as bytes arrive and
/// either declares the final size up front or via
/// [`set_total_len`](Self::set_total_len); readers on other threads block
/// inside [`read_at`](BlockingRangeSource::read_at) until the frontier
/// passes the requested offset. [`abort`](Self::abort) fails the source and
/// wakes every blocked reader with an error, which is the cancel path for
/// an in-flight extraction.
#[derive(Debug, Default)]
pub struct GrowableBuffer {
    state: Mutex<GrowableState>,
    arrived: Condvar,
}

#[derive(Debug, Default)]
struct GrowableState {
    data: Vec<u8>,
    total_len: Option<u64>,
    abort_reason: Option<String>,
    blocked_waits: u64,
}

impl GrowableBuffer {
    /// Creates an empty buffer whose final length is not yet known.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty buffer with a declared final length.
    pub fn with_total_len(total_len: u64) -> Self {
        let buffer = Self::new();
        buffer.state.lock().expect(POISONED).total_len = Some(total_len);
        buffer
    }

    /// Appends bytes at the contiguous frontier and wakes blocked readers.
    pub fn append(&self, bytes: &[u8]) {
        let mut state = self.state.lock().expect(POISONED);
        debug_assert!(
            state.abort_reason.is_none(),
            "append after abort is discarded"
        );
        debug_assert!(
            state
                .total_len
                .is_none_or(|total| state.data.len() as u64 + bytes.len() as u64 <= total),
            "append advances the frontier past the declared total length"
        );
        state.data.extend_from_slice(bytes);
        drop(state);
        self.arrived.notify_all();
    }

    /// Declares the final length, waking readers blocked at or past it.
    pub fn set_total_len(&self, total_len: u64) {
        let mut state = self.state.lock().expect(POISONED);
        debug_assert!(
            total_len >= state.data.len() as u64,
            "total length is below the already-arrived frontier"
        );
        state.total_len = Some(total_len);
        drop(state);
        self.arrived.notify_all();
    }

    /// Fails the source: every current and future blocked read returns an
    /// error carrying `reason`. This is the cancel path.
    pub fn abort(&self, reason: impl Into<String>) {
        let mut state = self.state.lock().expect(POISONED);
        if state.abort_reason.is_none() {
            state.abort_reason = Some(reason.into());
        }
        drop(state);
        self.arrived.notify_all();
    }

    /// How many times a reader had to block for bytes that had not arrived.
    pub fn blocked_waits(&self) -> u64 {
        self.state.lock().expect(POISONED).blocked_waits
    }
}

const POISONED: &str = "growable buffer lock poisoned";

impl BlockingRangeSource for GrowableBuffer {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.lock().expect(POISONED);
        loop {
            if let Some(reason) = &state.abort_reason {
                return Err(std::io::Error::other(format!(
                    "stream source aborted: {reason}"
                )));
            }
            let frontier = state.data.len() as u64;
            if offset < frontier {
                let start = offset as usize;
                let take = buf.len().min(state.data.len() - start);
                buf[..take].copy_from_slice(&state.data[start..start + take]);
                return Ok(take);
            }
            if state.total_len.is_some_and(|total| offset >= total) {
                return Ok(0);
            }
            state.blocked_waits += 1;
            state = self.arrived.wait(state).expect(POISONED);
        }
    }

    fn known_len(&self) -> u64 {
        self.state.lock().expect(POISONED).data.len() as u64
    }

    fn total_len(&self) -> Option<u64> {
        self.state.lock().expect(POISONED).total_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn growable_buffer_read_blocks_until_bytes_arrive() {
        let buffer = Arc::new(GrowableBuffer::with_total_len(6));
        buffer.append(b"abc");

        let reader = Arc::clone(&buffer);
        let handle = std::thread::spawn(move || {
            let mut out = [0u8; 6];
            let mut offset = 0u64;
            while offset < 6 {
                let read = reader.read_at(offset, &mut out[offset as usize..]).unwrap();
                assert_ne!(read, 0);
                offset += read as u64;
            }
            out
        });

        // Wait on the CONDITION, never on the clock. A fixed sleep here is
        // standing in for "the reader has reached the point where it must
        // wait", and thread start-up plus scheduling can outrun it on a
        // loaded machine - the writer then appends first, the reader finds
        // all six bytes on its first call, and `blocked_waits` is
        // legitimately 0. That is a flake, not a bug, and it took main red
        // on windows-unit on 25 Aug 2026 (shard 4/6 of six concurrent test
        // shards). Blocking is what the test is named for, so wait for it.
        // (nzbfast-local change, 25 Aug 2026 - re-apply on the next rars
        // re-sync, see vendor/rars/VENDORING.md.)
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while buffer.blocked_waits() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "reader never blocked at the 3-byte frontier within 30s"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        buffer.append(b"def");
        assert_eq!(&handle.join().unwrap(), b"abcdef");
        assert!(buffer.blocked_waits() > 0);
    }

    #[test]
    fn growable_buffer_returns_zero_at_declared_end() {
        let buffer = GrowableBuffer::with_total_len(3);
        buffer.append(b"xyz");
        let mut buf = [0u8; 4];
        assert_eq!(buffer.read_at(3, &mut buf).unwrap(), 0);
        assert_eq!(buffer.read_at(0, &mut buf).unwrap(), 3);
    }

    #[test]
    fn growable_buffer_abort_unblocks_waiting_reader() {
        let buffer = Arc::new(GrowableBuffer::new());
        buffer.append(b"partial");

        let reader = Arc::clone(&buffer);
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 8];
            reader.read_at(100, &mut buf)
        });

        std::thread::sleep(Duration::from_millis(20));
        buffer.abort("cancelled by test");
        let error = handle.join().unwrap().unwrap_err();
        assert!(error.to_string().contains("cancelled by test"));
    }

    #[test]
    fn stream_source_range_reader_reads_across_appends() {
        let buffer = Arc::new(GrowableBuffer::with_total_len(10));
        let source = ArchiveSource::Stream {
            source: Arc::clone(&buffer) as Arc<dyn BlockingRangeSource>,
            len: 10,
        };
        let producer = Arc::clone(&buffer);
        let handle = std::thread::spawn(move || {
            for chunk in b"0123456789".chunks(3) {
                std::thread::sleep(Duration::from_millis(5));
                producer.append(chunk);
            }
        });

        let mut reader = source.range_reader(2..9).unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        handle.join().unwrap();

        assert_eq!(out, b"2345678");
        assert_eq!(source.read_range(0..10).unwrap(), b"0123456789");
        assert!(source.read_range(0..11).is_err());
    }

    /// A range that ends short of its declared length is an ERROR on the
    /// sequential readers, not a clean EOF.
    ///
    /// It used to answer `Ok(0)` with bytes still owed, which every
    /// sequential consumer reads as "this fragment is finished" - the two
    /// extract walks then move to the next fragment and decode a member
    /// from the wrong bytes. A member with no CRC of its own is written
    /// truncated with nothing anywhere saying so. The exact-range path
    /// (`stream_read_exact`) has always failed closed on the same input.
    /// (nzbfast-local change, 26 Aug 2026 - re-apply on the next rars
    /// re-sync, see vendor/rars/VENDORING.md.)
    #[test]
    fn a_range_that_ends_early_fails_rather_than_reading_as_eof() {
        // A blocking source that has DECLARED its total and stopped
        // short: `read_at` past the end answers 0 forever.
        let buffer = Arc::new(GrowableBuffer::with_total_len(4));
        buffer.append(b"0123");
        let source = ArchiveSource::Stream {
            source: Arc::clone(&buffer) as Arc<dyn BlockingRangeSource>,
            len: 8,
        };

        for mut reader in [
            Box::new(source.range_reader(0..8).unwrap()) as Box<dyn Read>,
            Box::new(source.owned_range_reader(0..8).unwrap()) as Box<dyn Read>,
        ] {
            let mut out = Vec::new();
            let error = reader
                .read_to_end(&mut out)
                .expect_err("a short range must not read as a clean end");
            assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
            assert_eq!(out, b"0123", "the bytes that DID arrive are delivered");
        }

        // And the file-backed reader, whose range is taken on trust from
        // the header rather than checked against the file's length.
        let dir = std::env::temp_dir().join(format!(
            "rars-short-range-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("short.rar");
        std::fs::write(&path, b"0123").unwrap();
        let file_source = ArchiveSource::File(path.clone().into());
        let mut reader = file_source.owned_range_reader(0..8).unwrap();
        let mut out = Vec::new();
        let error = reader
            .read_to_end(&mut out)
            .expect_err("a truncated volume must not read as a clean end");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(out, b"0123");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
