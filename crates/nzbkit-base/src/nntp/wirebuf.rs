//! The plain-socket read buffer (2 Sep 2026, RAR perf audit, one-pass
//! lane finding 5): tokio's `BufReader` with one extra move, `unread`,
//! which is what lets a multiline body land straight in the caller's
//! `Vec` instead of being copied out of the buffer chunk by chunk.
//!
//! The steady-state plain path used to be socket -> `BufReader` (256
//! KiB) -> `extend_from_slice` per chunk into the pooled body `Vec` ->
//! rapidyenc. The middle copy was pure overhead (~0.1 core-s/GB on an
//! M-series core), and it existed only because an NNTP response has no
//! length: with pipelining, the read that brings the terminator also
//! brings the start of the NEXT response, and a `BufReader` is the one
//! place that overrun could live. `unread` gives it that place - the
//! multiline reader reads the socket straight into the `Vec`'s spare
//! capacity, finds the terminator in place, and hands the tail beyond
//! it back here for the next status read. Only the overrun is copied
//! (bounded by one read, [`capacity`](Self::capacity)), against every
//! byte before.
//!
//! Reads never exceed the capacity when they go direct, so an overrun
//! always fits; `unread` asserts both halves of that contract. The
//! direct path is OFF unless `NZBFAST_WIRE_DIRECT` says otherwise -
//! see [`direct_read_cap`] for the measurement that decided it.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

/// The most one direct read takes: `NZBFAST_WIRE_DIRECT` in KiB, and
/// OFF (0, every chunk copies out of the buffer) when unset. Read
/// once.
///
/// Off by default because it MEASURED as a loss on macOS (loopback
/// mock rig, 1 GiB of 740 KB articles, 16 connections, 3 paired
/// rounds x 3 benches, 2 Sep 2026): -4.5% instructions retired
/// (4.94 G -> 4.72 G) and -0.015 s user per GiB, but +0.065 s sys, so
/// +0.05 s (+8%) of client CPU per GiB and no wall change. The saved
/// memcpy is real; the kernel's copyout into the body `Vec` costs more
/// than the same copyout into the hot 256 KiB buffer did, and a
/// standalone rig could not pin why (destination coldness, alignment
/// and a 12.8 MB cycling ring all measured the same as the hot buffer;
/// only a fresh-page destination cost more, +0.05 s/GiB, and after
/// the pool's warm-up the body buffers are resident). Linux's
/// `copy_to_user` and fault-around are a different kernel: an A/B on
/// the bench farm with `NZBFAST_WIRE_DIRECT=256` is the open question,
/// and this knob exists so that A/B is one variable.
pub(crate) fn direct_read_cap() -> usize {
    static CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        std::env::var("NZBFAST_WIRE_DIRECT")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map_or(DIRECT_READ_DEFAULT, |kib| kib.saturating_mul(1024))
    })
}

/// On Linux the direct read is ON: the same 24 GB loopback download on
/// an 8-vCPU EPYC VPS (Ubuntu 24.04, kernel 6.8) read 12.4 / 13.1 /
/// 14.2 s of user CPU through the read buffer and 9.3 / 9.2 / 9.8 s
/// direct, -27% in three of three pairs, with system time unmoved
/// (66.8 -> 66.5, 61.1 -> 50.6, 64.3 -> 67.7 s) - copy_to_user into the
/// body buffer costs Linux nothing extra where macOS's copyout charged
/// +8% (research/RAR-PERF-AUDIT-2026-09-02.md, round 6). Off elsewhere.
///
/// AND IT REACHES A PLAIN SESSION ONLY, which is not where most real
/// bytes arrive (3 Sep 2026, round 15). `Wire::direct_cap` answers 0
/// for `Wire::Tls` by construction - rustls hands plaintext out of its
/// own buffer, so on 563 there is no second copy for this to skip and
/// the constant below is never consulted. Nothing here is wrong and
/// nothing needs changing; the note exists because "-27% user CPU on
/// Linux" reads like a claim about production downloads and is not one.
/// What TLS costs instead, and where it goes, is round 15.
#[cfg(target_os = "linux")]
const DIRECT_READ_DEFAULT: usize = 256 * 1024;
#[cfg(not(target_os = "linux"))]
const DIRECT_READ_DEFAULT: usize = 0;

pub(crate) struct WireBuf<T> {
    inner: T,
    buf: Box<[u8]>,
    pos: usize,
    filled: usize,
}

impl<T> WireBuf<T> {
    /// A buffer of `cap` bytes (at least 1: an empty buffer would read
    /// as a permanent EOF) over `inner`.
    pub(crate) fn with_capacity(cap: usize, inner: T) -> Self {
        WireBuf {
            inner,
            buf: vec![0u8; cap.max(1)].into_boxed_slice(),
            pos: 0,
            filled: 0,
        }
    }

    /// Bytes read from the socket and not yet consumed.
    pub(crate) fn buffer(&self) -> &[u8] {
        &self.buf[self.pos..self.filled]
    }

    /// The buffer's size, which is also the most one direct read may
    /// take (so that its overrun can always be given back).
    pub(crate) fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn into_inner(self) -> T {
        self.inner
    }

    /// Give back the tail of a direct read: `tail` was read off the
    /// socket past the end of the response being assembled and belongs
    /// to whatever comes next. Legal only while nothing is buffered
    /// (the multiline reader goes direct only then) and for at most
    /// [`capacity`](Self::capacity) bytes (a direct read is capped
    /// there); either violated is a logic error, not a wire condition.
    pub(crate) fn unread(&mut self, tail: &[u8]) {
        assert!(
            self.pos == self.filled,
            "unread over {} buffered bytes",
            self.filled - self.pos
        );
        assert!(
            tail.len() <= self.buf.len(),
            "unread of {} bytes into a {} byte buffer",
            tail.len(),
            self.buf.len()
        );
        self.buf[..tail.len()].copy_from_slice(tail);
        self.pos = 0;
        self.filled = tail.len();
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for WireBuf<T> {
    /// Buffered bytes first; with none, the socket is read straight
    /// into the caller's buffer whatever its size - this is the direct
    /// path, and a small read here would be a caller's choice.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if me.pos < me.filled {
            let n = buf.remaining().min(me.filled - me.pos);
            buf.put_slice(&me.buf[me.pos..me.pos + n]);
            me.pos += n;
            return Poll::Ready(Ok(()));
        }
        me.pos = 0;
        me.filled = 0;
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + Unpin> AsyncBufRead for WireBuf<T> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        let me = self.get_mut();
        if me.pos >= me.filled {
            let mut rb = ReadBuf::new(&mut me.buf);
            std::task::ready!(Pin::new(&mut me.inner).poll_read(cx, &mut rb))?;
            me.filled = rb.filled().len();
            me.pos = 0;
        }
        Poll::Ready(Ok(&me.buf[me.pos..me.filled]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.get_mut();
        me.pos = (me.pos + amt).min(me.filled);
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for WireBuf<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
