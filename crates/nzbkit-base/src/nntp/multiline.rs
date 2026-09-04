//! The multiline response readers (TODO 106 size-gate split out of
//! nntp.rs): the bulk chunk-scanning dot-terminator loop, its paced
//! and size-capped variants, and the A6 mid-body rate floor that
//! rides them. A child module so `super::` keeps the private
//! internals (`idle_bounded_for`, the timeouts) reachable; nntp.rs
//! glob-re-exports it, so every existing spelling is unchanged.

use super::{MAX_MULTILINE_BYTES, NntpError, STREAM_IDLE_TIMEOUT};

/// Rolling minimum-progress floor for a multiline read (error-detection
/// audit A6). The idle bound above resets on ANY byte, so a connection
/// dribbling one byte per few seconds holds an 800 KB article, and the
/// connection slot with it, for the rest of a run - none of the
/// between-articles rescuers (slope recycle, over-target trim) ever
/// reach a read that never finishes. The floor is the in-read bound: in
/// every rolling `window` the body must deliver at least `min_bytes`,
/// or the read fails exactly like an idle expiry and the session takes
/// the stall teardown (requeue, census slot 3).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RateFloor {
    /// Length of the rolling window.
    pub window: std::time::Duration,
    /// Least bytes a live transfer must deliver per window.
    pub min_bytes: u64,
}

/// Default of `NZBFAST_BODY_RATE_FLOOR`, bytes/sec. Deliberately far
/// below any honest link: 64 B/s is under 1% of one connection's share
/// of a 56k modem line split 100 ways, so a legitimately slow VPN never
/// trips it, while the wedge shape it exists for (a byte every few
/// seconds, crafted or pathological) sits two orders of magnitude
/// under it.
const BODY_RATE_FLOOR_BPS: u64 = 64;

/// Default of `NZBFAST_BODY_RATE_WINDOW_SECS`. Tens of seconds, so the
/// floor judges a sustained average rather than one bad TCP hiccup;
/// bursty links that alternate a quiet second with a fast one pass on
/// their average.
const BODY_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// The BODY path's [`RateFloor`], from env (cached once):
/// `NZBFAST_BODY_RATE_FLOOR` bytes/sec (0 disables) over
/// `NZBFAST_BODY_RATE_WINDOW_SECS`. Only the article body read uses
/// it - scans, probes and the flat path (whole-response capped by
/// `read_timeout`) pass no floor.
pub(crate) fn body_rate_floor() -> Option<RateFloor> {
    static F: std::sync::OnceLock<Option<RateFloor>> = std::sync::OnceLock::new();
    *F.get_or_init(|| {
        let bps = std::env::var("NZBFAST_BODY_RATE_FLOOR")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(BODY_RATE_FLOOR_BPS);
        if bps == 0 {
            return None;
        }
        let window = std::env::var("NZBFAST_BODY_RATE_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| s > 0)
            .map_or(BODY_RATE_WINDOW, std::time::Duration::from_secs);
        Some(RateFloor {
            window,
            min_bytes: bps.saturating_mul(window.as_secs().max(1)),
        })
    })
}

/// The mid-body no-progress deadline a paced read holds each socket
/// wait to. `Fixed` is the historical shape - one figure for the whole
/// response, armed once per wait. `Live` asks the caller again once a
/// second DURING a silence (TODO 208.2, the warm-up gap): the pool's
/// share-aware stall bound is derived from a line gauge that trains
/// during the first bodies of a run, so a bound sampled once at read
/// start on a slow line carries the flat 8 s floor for a body that
/// takes 30 s to arrive - exactly the window in which a 360-way slow
/// start starves connections hardest - and evidence that lands while
/// the connection is already quiet could never reach a wait armed
/// before it. Re-asking costs one wake per idle second per connection
/// (tokio's `BufReader::fill_buf` is cancel-safe, so a sliced wait
/// loses nothing), and lets a silence that began under the floor be
/// judged by the trained bound.
pub enum StallBound<'a> {
    Fixed(std::time::Duration),
    Live(&'a (dyn Fn() -> std::time::Duration + Sync)),
}

impl From<std::time::Duration> for StallBound<'_> {
    fn from(d: std::time::Duration) -> Self {
        StallBound::Fixed(d)
    }
}

impl<'a> From<&'a (dyn Fn() -> std::time::Duration + Sync)> for StallBound<'a> {
    fn from(f: &'a (dyn Fn() -> std::time::Duration + Sync)) -> Self {
        StallBound::Live(f)
    }
}

/// How often a `Live` bound is re-read during one silence.
const LIVE_SLICE: std::time::Duration = std::time::Duration::from_secs(1);

/// The socket wait a [`StallBound`] runs. An enum rather than a
/// closure: a future returned by an async closure carries a
/// higher-ranked lifetime the compiler cannot prove `Send` across
/// `tokio::spawn`, and every pool worker is spawned.
enum Fetch<'r, R> {
    /// Wait until the source has a chunk buffered (`fill_buf`); the
    /// caller takes it with a second, I/O-free `fill_buf`.
    Fill(&'r mut R),
    /// Read straight into the `Vec`, at most `usize` bytes, appended.
    Direct(&'r mut R, &'r mut Vec<u8>, usize),
}

impl StallBound<'_> {
    /// Run one socket wait under this bound; returns the bytes a
    /// `Direct` fetch appended (0 for `Fill`). Returns the same
    /// [`NntpError::Timeout`] a flat idle expiry does, once the silence
    /// has outlasted the bound as it reads AT THAT MOMENT. The fetch
    /// is re-awaited per slice, so it must be cancel-safe: a poll that
    /// returns Pending has taken nothing off the wire (true of
    /// `fill_buf` and of a `read_buf` into spare capacity).
    async fn bounded<R: MultilineSource>(&self, mut op: Fetch<'_, R>) -> Result<usize, NntpError> {
        use tokio::io::AsyncBufReadExt as _;
        let quiet_since = tokio::time::Instant::now();
        loop {
            let bound = match self {
                StallBound::Fixed(d) => *d,
                StallBound::Live(f) => f(),
            };
            let left = bound.saturating_sub(quiet_since.elapsed());
            if left.is_zero() {
                return Err(NntpError::Timeout);
            }
            let slice = match self {
                StallBound::Fixed(_) => left,
                StallBound::Live(_) => left.min(LIVE_SLICE),
            };
            let fetch = async {
                match &mut op {
                    Fetch::Fill(r) => r.fill_buf().await.map(|_| 0).map_err(NntpError::from),
                    Fetch::Direct(r, out, cap) => read_direct(*r, out, *cap).await,
                }
            };
            match tokio::time::timeout(slice, fetch).await {
                Ok(r) => return r,
                Err(_) if matches!(self, StallBound::Live(_)) => continue,
                Err(_) => return Err(NntpError::Timeout),
            }
        }
    }
}

/// What a multiline read reads from. Every `AsyncBufRead` can be one
/// (the defaults describe a source with no direct path: the reader
/// copies out of its buffer chunk by chunk, as it always has); a
/// source that overrides `direct_cap` lets the body land straight in
/// the caller's `Vec` and takes the overrun back through `unread`.
/// No blanket impl, deliberately: `Wire` is itself an `AsyncBufRead`
/// and needs its own, so each reader type names itself here (the
/// three the tests drive are below, the wire ones beside their
/// types).
pub(crate) trait MultilineSource:
    tokio::io::AsyncBufRead + tokio::io::AsyncRead + Unpin
{
    /// The most bytes one direct read may take, or 0 for a source
    /// with no direct path. A direct read happens only while
    /// [`buffered`](Self::buffered) is empty, and its overrun (the
    /// bytes past the terminator) is at most this, so `unread` can
    /// always take it.
    fn direct_cap(&self) -> usize {
        0
    }

    /// Bytes read and not yet consumed, without touching the socket.
    /// Consulted only when `direct_cap` is non-zero.
    fn buffered(&self) -> &[u8] {
        &[]
    }

    /// Take back the tail of a direct read that belongs to the next
    /// response. Called only after a direct read, with at most
    /// `direct_cap` bytes.
    fn unread(&mut self, tail: &[u8]) {
        unreachable!(
            "unread of {} bytes on a source with no direct path",
            tail.len()
        );
    }
}

impl<T: tokio::io::AsyncRead + Unpin> MultilineSource for tokio::io::BufReader<T> {}
impl<T: AsRef<[u8]> + Unpin> MultilineSource for std::io::Cursor<T> {}
impl MultilineSource for &[u8] {}

impl<T: tokio::io::AsyncRead + Unpin> MultilineSource for super::wirebuf::WireBuf<T> {
    fn direct_cap(&self) -> usize {
        self.capacity()
    }
    fn buffered(&self) -> &[u8] {
        self.buffer()
    }
    fn unread(&mut self, tail: &[u8]) {
        super::wirebuf::WireBuf::unread(self, tail);
    }
}

/// Below this much spare capacity a direct read grows the `Vec` first
/// (by `cap`, so Vec's doubling applies - the same growth an
/// `extend_from_slice` past capacity took). Above it the read fits
/// what is there: the pooled body buffer is sized to the article
/// (`body_buf_bytes`, 800 KiB against a ~762 KB wire body), and an
/// unconditional `reserve(cap)` near its end doubled every one of
/// them to 1.6 MB on first use - a realloc copy per buffer, page
/// reclaims up a third, and twice the raw-body footprint fleet-wide
/// (measured on the loopback rig, 2 Sep 2026: sys time +0.06 s/GiB
/// against the copy it removed).
const DIRECT_MIN_SPARE: usize = 4 * 1024;

/// One read off `reader` into `out`'s spare capacity, at most `cap`
/// bytes, appended. Cancel-safe: `read_buf` advances the `Vec` only on
/// a Ready poll.
async fn read_direct<R>(reader: &mut R, out: &mut Vec<u8>, cap: usize) -> Result<usize, NntpError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use bytes::BufMut as _;
    use tokio::io::AsyncReadExt as _;
    if out.capacity() - out.len() < DIRECT_MIN_SPARE {
        out.reserve(cap);
    }
    let limit = cap.min(out.capacity() - out.len());
    let mut limited = (&mut *out).limit(limit);
    Ok(reader.read_buf(&mut limited).await?)
}

/// Find the response terminator across `block` (the body so far) and
/// `chunk` (the bytes just arrived, not yet part of it): a `.` that
/// begins a line (the block's first byte, or right after a `\n`),
/// followed by CRLF or bare LF. Only the block's last two bytes can
/// still matter - a terminator whose dot sits earlier was decidable
/// when those bytes arrived - so the scan is the chunk plus that
/// tail, and a terminator split across reads (`.` then `\r\n`, `.\r`
/// then `\n`, `\n` then `.\r\n`) falls out of the same check as one
/// that lands whole. Returns the dot's index in the virtual
/// `block ++ chunk` (so under `block.len()` means the dot is already
/// in the block) and the terminator's length after the dot (2 for
/// CRLF, 1 for LF).
fn find_terminator(block: &[u8], chunk: &[u8]) -> Option<(usize, usize)> {
    let t = block.len();
    let at = |i: usize| -> Option<u8> {
        if i < t {
            Some(block[i])
        } else {
            chunk.get(i - t).copied()
        }
    };
    let confirm = |d: usize| -> Option<(usize, usize)> {
        match at(d + 1) {
            Some(b'\r') if at(d + 2) == Some(b'\n') => Some((d, 2)),
            Some(b'\n') => Some((d, 1)),
            _ => None,
        }
    };
    let lo = t.saturating_sub(2);
    if lo == 0
        && at(0) == Some(b'.')
        && let Some(hit) = confirm(0)
    {
        return Some(hit);
    }
    // Newline-led dots whose newline is still in the block (at most
    // the last two bytes), then every newline in the chunk.
    for nl in lo.saturating_sub(1)..t {
        if block[nl] == b'\n'
            && at(nl + 1) == Some(b'.')
            && let Some(hit) = confirm(nl + 1)
        {
            return Some(hit);
        }
    }
    for nl in memchr::memchr_iter(b'\n', chunk) {
        let d = t + nl + 1;
        if at(d) == Some(b'.')
            && let Some(hit) = confirm(d)
        {
            return Some(hit);
        }
    }
    None
}

/// See [`super::Connection::read_multiline_into`]; generic so tests can
/// drive it with tiny buffer capacities to hit every chunk-boundary case.
pub(crate) async fn read_multiline_generic<R>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> Result<(), NntpError>
where
    R: MultilineSource,
{
    read_multiline_paced(reader, out, STREAM_IDLE_TIMEOUT).await
}

/// [`read_multiline_generic`] with a caller-chosen per-read no-progress
/// deadline. Any byte arriving resets it, so a slow-but-alive transfer
/// never trips; only a genuine mid-body stall does. No rate floor: the
/// callers here (scans, capabilities, the serial path) are bounded
/// elsewhere or tolerant of a dribble.
pub(crate) async fn read_multiline_paced<R>(
    reader: &mut R,
    out: &mut Vec<u8>,
    stall: std::time::Duration,
) -> Result<(), NntpError>
where
    R: MultilineSource,
{
    read_multiline_paced_max(reader, out, stall, MAX_MULTILINE_BYTES, None).await
}

/// [`read_multiline_paced`] with a caller-chosen SIZE ceiling as well.
///
/// The download path wants [`MAX_MULTILINE_BYTES`] (256 MiB): that bound
/// exists to stop an unterminated response, not to budget anything. A
/// CURIOSITY probe has a real budget - pre-flight's block-size probe
/// allows itself 8 MiB total - and a budget checked after the whole
/// response is buffered is not a budget: one well-formed 256 MiB body
/// lands whole, 32x over, and is then decoded into a second body-sized
/// Vec before the caller's accounting ever sees the length. Passing the
/// caller's remaining allowance down here is what makes it real.
///
/// `floor`, when given, adds the A6 rolling minimum-progress bound on
/// top of the idle bound: the idle deadline resets on any byte, so on
/// its own it lets a connection dribble a byte every few seconds and
/// hold the read (and the slot) for the rest of a run. Every arriving
/// chunk feeds a window accumulator; when the window has elapsed, a
/// total under `floor.min_bytes` fails the read as [`NntpError::Timeout`]
/// - the same error as an idle expiry, so the session takes the
/// existing stall teardown. Checked only when a chunk arrives WITHOUT
/// finishing the response: a total stall is already the idle bound's to
/// catch, and a body whose terminator has landed is delivered even if
/// its final chunk crossed a window boundary under the floor.
pub(crate) async fn read_multiline_paced_max<'a, R>(
    reader: &mut R,
    out: &mut Vec<u8>,
    stall: impl Into<StallBound<'a>>,
    max: usize,
    floor: Option<RateFloor>,
) -> Result<(), NntpError>
where
    R: MultilineSource,
{
    read_multiline_paced_noting(reader, out, stall, max, floor, None).await
}

/// A sink for the bytes a paced read takes off the wire, called once
/// per chunk AS IT ARRIVES with the count consumed (payload and
/// terminator alike - what the line carried, not what the body is
/// worth). TODO 208.2 over-read: the pool's line gauge used to be fed
/// once per delivered BODY, so every body in flight at the gauge's
/// first fold landed in a clump credited to a window that had barely
/// opened - a trained `line peak` of 695 KB/s for a 400 KB/s line on
/// the fault rig, +10-35% on the banked shaped legs - and the mirror
/// artefact would have bitten any earlier origin instead (bytes in
/// flight at the READING instant are invisible to a per-body fold, so
/// the peak under-reads until the EWMA forgets, and the §208.1 cap
/// sheds a CLI fleet on the dip). Crediting bytes when they land
/// leaves nothing in flight at either instant. `None` = no sink.
pub type Arrivals<'a> = Option<&'a (dyn Fn(u64) + Sync)>;

/// [`read_multiline_paced_max`] reporting every consumed chunk to
/// `arrivals` the moment it is taken off the wire.
///
/// Bytes land in `out` once. Each pass either copies what the source
/// already holds (the leftover of the read that brought the status
/// line, or a source with no direct path) or, with nothing buffered,
/// reads the socket straight into `out`'s spare capacity; then the
/// terminator is looked for IN `out`, over the new bytes plus the two
/// before them, so a terminator split across reads needs no special
/// case. Whatever follows the terminator is the next response: on the
/// buffered pass it was copied but never consumed and is simply
/// truncated away, on a direct pass it goes back to the source
/// through [`MultilineSource::unread`]. Only that overrun - at most
/// one read - is ever copied twice. (The direct path is off unless
/// `NZBFAST_WIRE_DIRECT` turns it on: `wirebuf::direct_read_cap`
/// carries the measurement.)
pub(crate) async fn read_multiline_paced_noting<'a, R>(
    reader: &mut R,
    out: &mut Vec<u8>,
    stall: impl Into<StallBound<'a>>,
    max: usize,
    floor: Option<RateFloor>,
    arrivals: Arrivals<'_>,
) -> Result<(), NntpError>
where
    R: MultilineSource,
{
    use tokio::io::AsyncBufReadExt;
    let stall = stall.into();
    let arrived = |n: usize| {
        if let Some(f) = arrivals {
            f(n as u64);
        }
    };
    let start = out.len();
    let cap = reader.direct_cap();
    // A6 rate floor: the window opens at the first arrival. Every loop
    // pass either consumes the whole chunk or returns, so counting the
    // chunk here never double-counts.
    let mut win_start: Option<tokio::time::Instant> = None;
    let mut win_bytes: u64 = 0;
    loop {
        let before = out.len();
        let direct = cap > 0 && reader.buffered().is_empty();
        // The chunk: direct, it is already in `out` past `before`;
        // buffered, it is the source's buffer and only the payload
        // part is ever copied (an overrun copied and truncated would
        // still have grown a pooled body buffer past its capacity).
        let (n, found) = if direct {
            let n = stall.bounded(Fetch::Direct(reader, out, cap)).await?;
            if n == 0 {
                return Err(NntpError::Closed);
            }
            let (block, chunk) = out[start..].split_at(before - start);
            (n, find_terminator(block, chunk))
        } else {
            stall.bounded(Fetch::Fill(reader)).await?;
            // A wait that returns Ok has left the chunk in the reader's
            // buffer; this second `fill_buf` hands it back without I/O
            // (and an EOF reads as EOF again).
            let buf = reader.fill_buf().await?;
            if buf.is_empty() {
                return Err(NntpError::Closed);
            }
            let found = find_terminator(&out[start..], buf);
            match found {
                Some((dot, _)) => {
                    // Payload only: the dot's chunk-relative index when
                    // the dot is in the chunk, nothing when the block
                    // already holds it.
                    let t = before - start;
                    if dot > t {
                        out.extend_from_slice(&buf[..dot - t]);
                    }
                }
                None => out.extend_from_slice(buf),
            }
            (buf.len(), found)
        };

        match found {
            Some((dot, term)) => {
                // The cap binds here too. Checking it only in the
                // no-terminator arm below made the bound depend on how
                // the response happened to be chunked: the wire reads
                // through a 256 KiB buffer, so any response that lands
                // terminator-and-all inside one chunk returned Ok
                // having never compared against `max`. A 200 KB body
                // under an 8 KiB cap passed on Linux and macOS purely
                // because the loopback split it across reads, and
                // failed on Windows, which did not - so the probe
                // budget was inert exactly when the server answered
                // fastest.
                if dot > max {
                    return Err(NntpError::TooLarge(max));
                }
                // What this read consumed: up to and including the
                // terminator, never the overrun (a straddled terminator
                // was begun by an earlier chunk, already credited).
                let used = dot + 1 + term - (before - start);
                if direct {
                    reader.unread(&out[before + used..]);
                } else {
                    reader.consume(used);
                }
                out.truncate(start + dot);
                arrived(used);
                return Ok(());
            }
            None => {
                if !direct {
                    reader.consume(n);
                }
                arrived(n);
                // A6 rate floor - checked ONLY here, on a chunk that
                // did not finish the response: a body whose terminator
                // has already arrived is delivered, never torn down at
                // a window boundary it happened to cross on its final
                // chunk.
                if let Some(f) = floor {
                    let now = tokio::time::Instant::now();
                    let opened = *win_start.get_or_insert(now);
                    win_bytes = win_bytes.saturating_add(n as u64);
                    if now.duration_since(opened) >= f.window {
                        if win_bytes < f.min_bytes {
                            return Err(NntpError::Timeout);
                        }
                        win_start = Some(now);
                        win_bytes = 0;
                    }
                }
                // What THIS response appended, not what the caller's
                // buffer already held - same as the compressed path. A
                // trailing PARTIAL terminator (`.` or `.\r` at the
                // chunk edge, resolved by the scan on the NEXT
                // iteration) is provisional, not payload: count it and
                // a body of exactly `max` passes or fails by where TCP
                // split the last three bytes - the same
                // chunking-dependence the arm above was cured of.
                // Excluding it buffers at most 2 bytes past `max`.
                let b = &out[start..];
                let pend = if b.ends_with(b"\n.\r") || b == b".\r" {
                    2
                } else if b.ends_with(b"\n.") || b == b"." {
                    1
                } else {
                    0
                };
                if out.len() - start - pend > max {
                    // Either the terminator never came (protocol fault;
                    // the pool requeues elsewhere instead of buffering
                    // unboundedly) or the caller set a tighter budget
                    // than the wire bound and the response has just
                    // blown it.
                    return Err(NntpError::TooLarge(max));
                }
            }
        }
    }
}
