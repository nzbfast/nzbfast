//! The direct body read (2 Sep 2026, one-pass lane finding 5): with
//! nothing buffered, the multiline reader reads the socket straight
//! into the caller's `Vec` and finds the terminator there, handing the
//! overrun back to the source. These drive it through
//! [`WireBuf`](super::wirebuf::WireBuf) with scripted read sizes, so
//! every way a terminator can split across reads is walked, and the
//! overrun is checked byte for byte against a line-at-a-time oracle.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use super::wirebuf::WireBuf;
use super::{MAX_MULTILINE_BYTES, NntpError, StallBound, read_multiline_paced_noting};

/// A source that answers each `poll_read` with the next scripted
/// chunk, whole (or what fits, keeping the rest), then EOF; with `gap`
/// set it sleeps that long before every chunk.
struct Scripted {
    chunks: VecDeque<Vec<u8>>,
    gap: Option<std::time::Duration>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Scripted {
    fn new(chunks: &[&[u8]]) -> Self {
        Scripted {
            chunks: chunks.iter().map(|c| c.to_vec()).collect(),
            gap: None,
            sleep: None,
        }
    }
}

impl AsyncRead for Scripted {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if me.chunks.is_empty() {
            return Poll::Ready(Ok(()));
        }
        if let Some(gap) = me.gap {
            let s = me
                .sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(gap)));
            std::task::ready!(s.as_mut().poll(cx));
            me.sleep = None;
        }
        let front = me.chunks.front_mut().unwrap();
        let n = buf.remaining().min(front.len());
        buf.put_slice(&front[..n]);
        front.drain(..n);
        if front.is_empty() {
            me.chunks.pop_front();
        }
        Poll::Ready(Ok(()))
    }
}

/// The line-at-a-time truth: payload before the terminator line, and
/// the bytes after it.
fn oracle(wire: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut out = Vec::new();
    let mut rest = wire;
    loop {
        let nl = memchr::memchr(b'\n', rest).expect("oracle: no terminator");
        let (line, after) = rest.split_at(nl + 1);
        rest = after;
        if line == b".\r\n" || line == b".\n" {
            return (out, rest.to_vec());
        }
        out.extend_from_slice(line);
    }
}

async fn read_direct_noting<'a>(
    r: &mut WireBuf<Scripted>,
    out: &mut Vec<u8>,
    stall: impl Into<StallBound<'a>>,
    sink: Option<&(dyn Fn(u64) + Sync)>,
) -> Result<(), NntpError> {
    read_multiline_paced_noting(r, out, stall, MAX_MULTILINE_BYTES, None, sink).await
}

/// Every split of a terminator across reads, and the three shapes the
/// task named: the terminator split between two reads, a terminator
/// at the very start of the body, and a line of exactly one dot - on
/// the wire that IS the terminator, and a stuffed `..` line (a body
/// line of one dot, kept raw for the decoder) must not be mistaken
/// for it whichever side of a read boundary its second dot lands.
#[tokio::test]
async fn the_in_place_scan_finds_a_terminator_split_any_way_across_reads() {
    let scripts: &[&[&[u8]]] = &[
        // Split between two reads, at each of the three seams.
        &[b"abc\r\n.", b"\r\nNEXT"],
        &[b"abc\r\n.\r", b"\nNEXT"],
        &[b"abc\r\n", b".\r\nNEXT"],
        &[b"abc\r\n.", b"\r", b"\nNEXT"],
        &[b"abc\r", b"\n.", b"\r\n"],
        // At the very start.
        &[b".\r\nNEXT"],
        &[b".", b"\r\nNEXT"],
        &[b".\r", b"\nNEXT"],
        &[b".", b"\r", b"\n"],
        // Bare LF, split.
        &[b"a\n.", b"\nNEXT"],
        &[b"a\n", b".\n"],
        &[b".", b"\n"],
        // A line of exactly one dot, stuffed on the wire as `..`.
        &[b"..\r\n.\r\nNEXT"],
        &[b".", b".\r\n.\r\nNEXT"],
        &[b"..", b"\r\n", b".", b"\r\n"],
        &[b"x\r\n.", b".\r\n.\r\nN"],
        &[b"x\r\n.", b".", b"\r\n.\r\n"],
        // Dot-stuffed data before, data after: nothing else trips.
        &[b"..stuffed\r\n...also\r\n.here\r\n.\r\n222 next\r\n"],
        &[
            b"=ybegin part=1\r\n\x01\x02.\x03\r\n",
            b".\r\n220 0 <x>\r\nmore",
        ],
        // A chunk that is only the terminator's tail after a dot line
        // ending in CR that was NOT a terminator.
        &[b"a.\r", b"\n.\r\n"],
    ];
    for script in scripts {
        let wire: Vec<u8> = script.concat();
        let (want_out, want_rest) = oracle(&wire);
        let mut r = WireBuf::with_capacity(1 << 20, Scripted::new(script));
        let mut out = b"held".to_vec();
        let seen = std::sync::atomic::AtomicU64::new(0);
        let sink = |n: u64| {
            seen.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        };
        read_direct_noting(
            &mut r,
            &mut out,
            std::time::Duration::from_secs(5),
            Some(&sink),
        )
        .await
        .unwrap_or_else(|e| panic!("{script:?}: {e:?}"));
        assert_eq!(&out[..4], b"held", "{script:?}: the caller's prefix");
        assert_eq!(&out[4..], &want_out[..], "{script:?}: payload");
        // The overrun went back to the source: what its buffer holds
        // is the start of the rest, and reading on yields the rest.
        assert!(
            want_rest.starts_with(r.buffer()),
            "{script:?}: buffer {:?} is not a prefix of {:?}",
            r.buffer(),
            want_rest
        );
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, want_rest, "{script:?}: the unconsumed tail");
        // The sink saw the wire up to and including the terminator,
        // nothing of the overrun.
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::Relaxed),
            (wire.len() - want_rest.len()) as u64,
            "{script:?}: sink total"
        );
    }
}

/// Every read size from 1 to 16 over the oracle cases, direct: the
/// terminator walks across every boundary, and the buffer holds
/// exactly the overrun of the last read.
#[tokio::test]
async fn direct_reads_match_the_line_oracle_at_every_read_size() {
    let cases: &[&[u8]] = &[
        b"hello\r\nworld\r\n.\r\nNEXT",
        b".\r\nNEXT",
        b"..stuffed\r\n...also\r\n.\r\nNEXT",
        b"bare\nlf lines\n.\nNEXT",
        b"mixed\r\nbare\n.\r\nNEXT",
        b"trailing dot data.\r\n.here\r\n.\r\nNEXT",
        b"a\r\n\r\n.\r\nNEXT",
        b"x.\r\n.y\r\n.\r\n",
        b"=ybegin part=1\r\n\x01\x02.\x03\r\n.\r\n220 0 <x>\r\nmore",
    ];
    for wire in cases {
        let (want_out, want_rest) = oracle(wire);
        for cap in 1..=16usize {
            let mut r = WireBuf::with_capacity(cap, Scripted::new(&[wire]));
            let mut out = Vec::new();
            read_direct_noting(&mut r, &mut out, std::time::Duration::from_secs(5), None)
                .await
                .unwrap_or_else(|e| panic!("cap {cap} on {wire:?}: {e:?}"));
            assert_eq!(out, want_out, "content, cap {cap}, wire {wire:?}");
            // Reads are `cap` long, so the overrun is what the last
            // read carried past the terminator - never more than the
            // buffer, which is what makes `unread` total.
            let consumed = wire.len() - want_rest.len();
            let last_read_end = consumed.div_ceil(cap) * cap;
            let want_buffered = &wire[consumed..last_read_end.min(wire.len())];
            assert_eq!(
                r.buffer(),
                want_buffered,
                "overrun, cap {cap}, wire {wire:?}"
            );
            let mut rest = Vec::new();
            r.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest, want_rest, "unconsumed tail, cap {cap}, wire {wire:?}");
        }
    }
}

/// The overrun of one body is the start of the next: a pipelined pair
/// read back to back through one source comes out as two bodies and
/// the status line between them, the second body's first pass copying
/// out of the buffer and the rest landing direct.
#[tokio::test]
async fn a_pipelined_pair_reads_back_to_back_through_the_overrun() {
    let wire = b"one\r\n.\r\n222 0 <b>\r\ntwo\r\nlines\r\n.\r\n205 bye\r\n";
    for cap in [3usize, 7, 11, 64] {
        let mut r = WireBuf::with_capacity(cap, Scripted::new(&[wire]));
        let mut a = Vec::new();
        read_direct_noting(&mut r, &mut a, std::time::Duration::from_secs(5), None)
            .await
            .unwrap();
        assert_eq!(a, b"one\r\n");
        let mut status = Vec::new();
        {
            use tokio::io::AsyncBufReadExt as _;
            r.read_until(b'\n', &mut status).await.unwrap();
        }
        assert_eq!(status, b"222 0 <b>\r\n", "cap {cap}");
        let mut b = Vec::new();
        read_direct_noting(&mut r, &mut b, std::time::Duration::from_secs(5), None)
            .await
            .unwrap();
        assert_eq!(b, b"two\r\nlines\r\n", "cap {cap}");
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"205 bye\r\n", "cap {cap}");
    }
}

/// EOF mid-body on the direct path is `Closed`, with what arrived kept.
#[tokio::test]
async fn eof_before_the_terminator_is_closed_on_the_direct_path() {
    let mut r = WireBuf::with_capacity(64, Scripted::new(&[b"partial\r\n", b"more"]));
    let mut out = Vec::new();
    let err = read_direct_noting(&mut r, &mut out, std::time::Duration::from_secs(5), None)
        .await
        .expect_err("EOF must not read as a body");
    assert!(matches!(err, NntpError::Closed), "{err:?}");
    assert_eq!(out, b"partial\r\nmore");
}

/// The size cap binds identically on the direct path, whether the
/// terminator lands in the same read as the excess or a later one.
#[tokio::test]
async fn the_cap_binds_on_the_direct_path_however_the_body_is_read() {
    let body = vec![b'x'; 200];
    let mut wire = body.clone();
    wire.extend_from_slice(b"\r\n.\r\n");
    for cap in [8usize, 64, 4096] {
        let mut r = WireBuf::with_capacity(cap, Scripted::new(&[&wire]));
        let mut out = Vec::new();
        let err = read_multiline_paced_noting(
            &mut r,
            &mut out,
            std::time::Duration::from_secs(5),
            100,
            None,
            None,
        )
        .await
        .expect_err("200 bytes under a 100 byte cap");
        assert!(
            matches!(err, NntpError::TooLarge(100)),
            "cap {cap}: {err:?}"
        );
        // And exactly at the cap it is delivered whole.
        let mut r = WireBuf::with_capacity(cap, Scripted::new(&[&wire]));
        let mut out = Vec::new();
        read_multiline_paced_noting(
            &mut r,
            &mut out,
            std::time::Duration::from_secs(5),
            202,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("cap {cap}: {e:?}"));
        assert_eq!(out.len(), 202);
    }
}

/// A `Live` bound re-arms once a second during a silence; each slice
/// drops and re-creates the direct read. A source that pauses longer
/// than a slice before every chunk but never as long as the bound
/// must deliver everything: a slice expiring mid-read takes nothing
/// off the wire.
#[tokio::test(start_paused = true)]
async fn a_live_bound_slice_expiring_mid_direct_read_loses_nothing() {
    let script: Vec<Vec<u8>> = (0..20)
        .map(|i| format!("line {i}\r\n").into_bytes())
        .chain(std::iter::once(b".\r\nNEXT".to_vec()))
        .collect();
    let refs: Vec<&[u8]> = script.iter().map(|c| c.as_slice()).collect();
    let mut src = Scripted::new(&refs);
    src.gap = Some(std::time::Duration::from_millis(2500));
    let mut r = WireBuf::with_capacity(1 << 16, src);
    fn bound() -> std::time::Duration {
        std::time::Duration::from_secs(4)
    }
    let live: &(dyn Fn() -> std::time::Duration + Sync) = &bound;
    let mut out = Vec::new();
    let t0 = tokio::time::Instant::now();
    read_direct_noting(&mut r, &mut out, live, None)
        .await
        .expect("a slow but live direct stream must complete");
    let want: Vec<u8> = script[..20].concat();
    assert_eq!(out, want);
    assert_eq!(r.buffer(), b"NEXT");
    assert!(
        t0.elapsed() >= std::time::Duration::from_secs(50),
        "the gaps were not waited through: {:?}",
        t0.elapsed()
    );
}

/// And a silence that does outlast a `Fixed` bound mid-body trips it,
/// with the bytes before the silence kept.
#[tokio::test(start_paused = true)]
async fn a_fixed_bound_trips_on_a_silence_mid_direct_read() {
    let mut src = Scripted::new(&[b"first\r\n", b"never\r\n.\r\n"]);
    src.gap = Some(std::time::Duration::from_secs(12));
    let mut r = WireBuf::with_capacity(1 << 16, src);
    let mut out = Vec::new();
    // Bound of 8 s: the FIRST chunk's 12 s gap already outlasts it.
    let err = read_direct_noting(&mut r, &mut out, std::time::Duration::from_secs(8), None)
        .await
        .expect_err("a 12 s silence under an 8 s bound");
    assert!(matches!(err, NntpError::Timeout), "{err:?}");
    assert!(out.is_empty());
}
