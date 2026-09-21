//! The random-access view of a file that may still be downloading.
//!
//! The probe ([`super::LiveProbeReader`]) reads through `Read + Seek`
//! and never waits: it is driven by a dashboard poll, so "not here yet"
//! is an answer. The remuxer is driven by a `<video>` element holding a
//! socket open, and for it "not here yet" is a *reason to wait a little*
//! - the article is usually seconds away and the alternative is a stall
//! the viewer reads as a broken file.
//!
//! So the remux path reads through this trait instead. It is offsets
//! rather than a cursor (the muxer alternates between a cluster walk and
//! an index lookup in the tail, and a shared cursor between them is only
//! a bug waiting to happen), it takes an explicit wait budget per read,
//! and it can tell the download which bytes to fetch next.
//!
//! ## The contract
//!
//! - `read_at_wait` fills the WHOLE buffer or fails. A partial read is
//!   never reported as success, because every caller here is reading a
//!   structure whose length it already knows.
//! - [`std::io::ErrorKind::WouldBlock`] means "these bytes have not
//!   arrived within the budget" and is always retryable.
//! - [`std::io::ErrorKind::UnexpectedEof`] means "past the end of the
//!   file" and never is.
//!
//! Keeping those two apart is the whole point: the first is a pause and
//! the second is the end of the stream, and a remuxer that confuses them
//! either truncates a good file or spins forever on a finished one.

use std::io;
use std::time::Duration;

/// Bytes at offsets, with a wait budget and a prefetch hint.
///
/// `Send` because the session runs on its own thread; deliberately NOT
/// `Sync`, since nothing here shares one across threads and requiring it
/// would rule out perfectly reasonable implementations.
pub trait Source: Send {
    /// Fill `buf` from `off`, waiting up to `wait` for bytes that have
    /// not landed. `WouldBlock` when the budget runs out,
    /// `UnexpectedEof` past [`Source::size`].
    fn read_at_wait(&self, off: u64, buf: &mut [u8], wait: Duration) -> io::Result<()>;

    /// Is `[off, off+len)` readable right now? Never waits.
    fn covered(&self, off: u64, len: u64) -> bool;

    /// The file's FINAL size, which for a download is known from the
    /// NZB long before the bytes are. Everything structural (a trailing
    /// `moov`, Matroska Cues) is located relative to it.
    fn size(&self) -> u64;

    /// "I will want `[off, off+len)` shortly." Fire and forget: an
    /// implementation that cannot steer a download does nothing, and
    /// the remuxer's correctness never depends on it.
    fn prefetch(&self, off: u64, len: u64) {
        let _ = (off, len);
    }
}

/// `WouldBlock`, spelled once so every producer and every `is_pending`
/// check agree on it.
pub fn would_block() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "bytes not downloaded yet")
}

/// True for the one error that means "ask again later".
pub fn is_pending(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock
}

fn past_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "past end of file")
}

/// Read `len` bytes at `off` into a fresh `Vec`, refusing to allocate
/// for a length the file cannot possibly hold.
///
/// Every declared length in this module comes off Usenet, so the
/// allocation is sized by what the FILE can supply rather than by what
/// the byte in front of us claims. A 4 GB element size in a 700 MB file
/// is rejected before a single byte is reserved.
pub fn read_vec(src: &dyn Source, off: u64, len: u64, wait: Duration) -> io::Result<Vec<u8>> {
    if len > src.size().saturating_sub(off.min(src.size())) {
        return Err(past_eof());
    }
    // Belt for the caller that asks for a whole file: the remuxer never
    // reads a structure larger than this in one piece.
    if len > MAX_READ_VEC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "declared length is implausibly large",
        ));
    }
    let mut v = vec![0u8; len as usize];
    src.read_at_wait(off, &mut v, wait)?;
    Ok(v)
}

/// Ceiling on any single `read_vec`. Sample payloads, index elements and
/// configuration records are all far below it; nothing legitimate in a
/// container needs one allocation this big.
pub const MAX_READ_VEC: u64 = 64 << 20;

// ---------------------------------------------------------------------------
// Test and fuzz sources
// ---------------------------------------------------------------------------

/// A whole file in memory: the finished-download case, and what the
/// byte-identity tests measure everything else against.
pub struct MemSource(pub Vec<u8>);

impl Source for MemSource {
    fn read_at_wait(&self, off: u64, buf: &mut [u8], _wait: Duration) -> io::Result<()> {
        let end = off.saturating_add(buf.len() as u64);
        if end > self.0.len() as u64 {
            return Err(past_eof());
        }
        buf.copy_from_slice(&self.0[off as usize..end as usize]);
        Ok(())
    }
    fn covered(&self, off: u64, len: u64) -> bool {
        off.saturating_add(len) <= self.0.len() as u64
    }
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

/// The same bytes with holes in them, and a wait that never succeeds.
///
/// This is the arrival-pattern harness: a test writes the spans it wants
/// present, pulls until `WouldBlock`, writes more, and resumes. Because
/// the wait here can never be satisfied by the passage of time, a test
/// that passes has proved the session makes progress on COVERAGE alone -
/// which is the property that has to hold on a real download, where the
/// session's own waiting is only ever an optimisation.
pub struct PartialSource {
    bytes: Vec<u8>,
    /// Sorted, non-overlapping half-open spans that have "arrived".
    spans: std::sync::Mutex<Vec<(u64, u64)>>,
    /// Every `prefetch` call, so a test can assert promotion happened.
    pub prefetched: std::sync::Mutex<Vec<(u64, u64)>>,
}

impl PartialSource {
    /// A source over `bytes` with NOTHING landed yet. Every read
    /// answers "not arrived" until `land` or `land_all` says otherwise.
    pub fn new(bytes: Vec<u8>) -> Self {
        PartialSource {
            bytes,
            spans: std::sync::Mutex::new(Vec::new()),
            prefetched: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Mark `[off, off+len)` as arrived.
    pub fn land(&self, off: u64, len: u64) {
        let end = off.saturating_add(len).min(self.bytes.len() as u64);
        if off >= end {
            return;
        }
        let mut s = self.spans.lock().unwrap_or_else(|e| e.into_inner());
        s.push((off, end));
        s.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(s.len());
        for (a, b) in s.iter().copied() {
            match merged.last_mut() {
                Some(last) if a <= last.1 => last.1 = last.1.max(b),
                _ => merged.push((a, b)),
            }
        }
        *s = merged;
    }

    /// Mark the whole buffer as arrived, which makes this behave like
    /// an ordinary complete file.
    pub fn land_all(&self) {
        self.land(0, self.bytes.len() as u64);
    }
}

impl Source for PartialSource {
    fn read_at_wait(&self, off: u64, buf: &mut [u8], _wait: Duration) -> io::Result<()> {
        let end = off.saturating_add(buf.len() as u64);
        if end > self.bytes.len() as u64 {
            return Err(past_eof());
        }
        if !self.covered(off, buf.len() as u64) {
            return Err(would_block());
        }
        buf.copy_from_slice(&self.bytes[off as usize..end as usize]);
        Ok(())
    }
    fn covered(&self, off: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let end = off.saturating_add(len);
        self.spans
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|&(a, b)| a <= off && end <= b)
    }
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn prefetch(&self, off: u64, len: u64) {
        self.prefetched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((off, len));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_source_reads_and_refuses_past_the_end() {
        let s = MemSource(b"0123456789".to_vec());
        let mut b = [0u8; 4];
        s.read_at_wait(2, &mut b, Duration::ZERO).unwrap();
        assert_eq!(&b, b"2345");
        assert_eq!(
            s.read_at_wait(8, &mut b, Duration::ZERO)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(s.covered(0, 10));
        assert!(!s.covered(0, 11));
    }

    /// The two errors a remuxer must never confuse: a hole is a pause,
    /// the end of the file is not.
    #[test]
    fn a_hole_is_wouldblock_and_the_end_is_eof() {
        let s = PartialSource::new(vec![7u8; 100]);
        s.land(0, 50);
        let mut b = [0u8; 10];
        assert!(s.read_at_wait(0, &mut b, Duration::ZERO).is_ok());
        assert_eq!(
            s.read_at_wait(45, &mut b, Duration::ZERO)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            s.read_at_wait(95, &mut b, Duration::ZERO)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn landing_spans_merges_them() {
        let s = PartialSource::new(vec![0u8; 100]);
        s.land(0, 20);
        s.land(20, 20);
        assert!(s.covered(0, 40));
        assert!(!s.covered(0, 41));
        s.land(60, 10);
        assert!(!s.covered(30, 40));
        s.land(40, 20);
        assert!(s.covered(0, 70));
    }

    /// A declared length larger than the file it indexes never reaches
    /// the allocator.
    #[test]
    fn read_vec_rejects_a_length_the_file_cannot_hold() {
        let s = MemSource(vec![0u8; 1024]);
        assert_eq!(
            read_vec(&s, 0, 1 << 40, Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            read_vec(&s, 1000, 100, Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(read_vec(&s, 0, 16, Duration::ZERO).unwrap().len(), 16);
    }
}
