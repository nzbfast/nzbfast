//! The multiline response readers (TODO 106 size-gate split out of
//! nntp.rs): the bulk chunk-scanning dot-terminator loop, its paced
//! and size-capped variants, and the A6 mid-body rate floor that
//! rides them. A child module so `super::` keeps the private
//! internals (`idle_bounded_for`, the timeouts) reachable; nntp.rs
//! glob-re-exports it, so every existing spelling is unchanged.

use super::{MAX_MULTILINE_BYTES, NntpError, STREAM_IDLE_TIMEOUT, idle_bounded_for};

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

/// See [`Connection::read_multiline_into`]; generic so tests can drive
/// it with tiny buffer capacities to hit every chunk-boundary case.
pub(crate) async fn read_multiline_generic<R>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> Result<(), NntpError>
where
    R: tokio::io::AsyncBufRead + Unpin,
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
    R: tokio::io::AsyncBufRead + Unpin,
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
pub(crate) async fn read_multiline_paced_max<R>(
    reader: &mut R,
    out: &mut Vec<u8>,
    stall: std::time::Duration,
    max: usize,
    floor: Option<RateFloor>,
) -> Result<(), NntpError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    {
        use tokio::io::AsyncBufReadExt;
        let start = out.len();
        // A6 rate floor: the window opens at the first arrival. Every
        // loop pass either consumes the whole chunk or returns, so
        // counting `buf.len()` here never double-counts.
        let mut win_start: Option<tokio::time::Instant> = None;
        let mut win_bytes: u64 = 0;
        loop {
            let buf = idle_bounded_for(stall, reader.fill_buf()).await?;
            if buf.is_empty() {
                return Err(NntpError::Closed);
            }
            let block = &out[start..];

            // A terminator begun in the previous chunk: the block so far
            // ends with a dot line under construction. `drop` bytes come
            // back off `out`, `consume` bytes complete it from `buf`.
            let after_nl = |b: &[u8]| b.is_empty() || b.ends_with(b"\n");
            let strad: Option<(usize, usize)> = if block.ends_with(b"\n.") || block == b"." {
                if buf.starts_with(b"\r\n") {
                    Some((1, 2))
                } else if buf[0] == b'\n' {
                    Some((1, 1))
                } else {
                    None
                }
            } else if block.ends_with(b"\n.\r") || block == b".\r" {
                (buf[0] == b'\n').then_some((2, 1))
            } else {
                None
            };
            if let Some((drop, consume)) = strad {
                out.truncate(out.len() - drop);
                reader.consume(consume);
                return Ok(());
            }

            // Scan this chunk for a terminator wholly inside it: a '.'
            // at chunk start (when the block so far ends on a newline)
            // or right after any '\n', followed by CRLF or bare LF. A
            // candidate too close to the chunk end to confirm is left
            // for the straddle logic next round.
            let mut found: Option<(usize, usize)> = None; // (dot idx, term len)
            let confirm = |d: usize| -> Option<(usize, usize)> {
                match buf.get(d + 1) {
                    Some(b'\r') if buf.get(d + 2) == Some(&b'\n') => Some((d, 2)),
                    Some(b'\n') => Some((d, 1)),
                    _ => None,
                }
            };
            if buf[0] == b'.' && after_nl(block) {
                found = confirm(0);
            }
            if found.is_none() {
                for nl in memchr::memchr_iter(b'\n', buf) {
                    if buf.get(nl + 1) == Some(&b'.')
                        && let Some(hit) = confirm(nl + 1)
                    {
                        found = Some(hit);
                        break;
                    }
                }
            }

            match found {
                Some((dot, term)) => {
                    // The cap binds here too. Checking it only in the
                    // no-terminator arm below made the bound depend on
                    // how the response happened to be chunked: the wire
                    // reads through a 256 KiB buffer, so any response
                    // that lands terminator-and-all inside one chunk
                    // returned Ok having never compared against `max`.
                    // A 200 KB body under an 8 KiB cap passed on Linux
                    // and macOS purely because the loopback split it
                    // across reads, and failed on Windows, which did
                    // not - so the probe budget was inert exactly when
                    // the server answered fastest.
                    if out.len() - start + dot > max {
                        return Err(NntpError::TooLarge(max));
                    }
                    out.extend_from_slice(&buf[..dot]);
                    reader.consume(dot + 1 + term);
                    return Ok(());
                }
                None => {
                    let n = buf.len();
                    out.extend_from_slice(buf);
                    reader.consume(n);
                    // A6 rate floor - checked ONLY here, on a chunk that
                    // did not finish the response: a body whose
                    // terminator has already arrived is delivered, never
                    // torn down at a window boundary it happened to
                    // cross on its final chunk.
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
                    // buffer already held - same as the compressed path.
                    // A trailing PARTIAL terminator (`.` or `.\r` at the
                    // chunk edge, resolved by the straddle logic on the
                    // NEXT iteration) is provisional, not payload: count
                    // it and a body of exactly `max` passes or fails by
                    // where TCP split the last three bytes - the same
                    // chunking-dependence the arm above was cured of.
                    // Excluding it buffers at most 2 bytes past `max`.
                    // Same predicates as the straddle detection above.
                    let b = &out[start..];
                    let pend = if b.ends_with(b"\n.\r") || b == b".\r" {
                        2
                    } else if b.ends_with(b"\n.") || b == b"." {
                        1
                    } else {
                        0
                    };
                    if out.len() - start - pend > max {
                        // Either the terminator never came (protocol
                        // fault; the pool requeues elsewhere instead of
                        // buffering unboundedly) or the caller set a
                        // tighter budget than the wire bound and the
                        // response has just blown it.
                        return Err(NntpError::TooLarge(max));
                    }
                }
            }
        }
    }
}
