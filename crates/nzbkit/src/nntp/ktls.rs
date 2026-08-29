//! Kernel TLS: after the rustls handshake, hand the traffic keys to the
//! kernel and let it do the record crypto.
//!
//! Every downloaded byte crosses this path, and userspace TLS charges
//! three things for it (measured 26 Jul, +43% CPU/GB over plain TCP):
//! the AEAD ~0.120 cpu-s/GB, one extra `recvmsg` per record ~0.079, and
//! one extra copy per record ~0.081 - rustls decrypts in place and then
//! `Payload::into_vec()`s the plaintext out, and it stops reading the
//! socket the moment one record's worth is buffered, so a read is one
//! ~16 KB record and never more. `setsockopt(TCP_ULP, "tls")` plus the
//! extracted `TLS_TX`/`TLS_RX` keys turns the socket back into an
//! ordinary one that happens to return plaintext: the AEAD stays (the
//! kernel runs it on the same AES-NI), the copy goes, and one `read()`
//! can drain every record the kernel has.
//!
//! Opt-in twice over - the `ktls` cargo feature has to be built in AND
//! `NZBFAST_KTLS=1` set - because the fallback matters more than the
//! win: NAS firmware kernels predate TLS_RX, containers may not be able
//! to autoload the `tls` module, and a kernel that refuses must cost a
//! user nothing.
//!
//! What the kernel will NOT do is renegotiate. A post-handshake
//! KeyUpdate arrives as a control record the kernel cannot act on, so
//! [`KtlsWire`] treats one as a dead connection: the pool reconnects,
//! and that connection finishes in userspace.
//!
//! Its own child module rather than a block inside `nntp/tls.rs`: it is
//! one platform and one cargo feature, `#[cfg]`-gated at the `mod`
//! declaration in nntp.rs so nothing inside needs an attribute of its
//! own, and everything in it is about the KERNEL taking the record
//! layer over - which is a different subject from what suite and which
//! trust anchors the handshake offers.

use std::sync::atomic::{AtomicBool, Ordering};

// `KtlsWire`'s two impls need these traits IN SCOPE, and they leaned on
// nntp.rs's own `use` line until the TODO 106 split moved them into this
// file (the same commit that left the `ktls_offload::` call sites behind
// - E0405 here, E0433 there, both invisible for the same reason: nothing
// on this fleet and no CI job builds `--features ktls` on linux). Their
// EXTENSION traits deliberately stay out: this type only implements the
// two, and `AsyncReadExt`'s methods on it are the caller's business.
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use super::Wire;

/// `NZBFAST_KTLS=1` opts in. Read once, before the first
/// `ClientConfig` exists - [`super::tls::ktls_wanted`] bakes the answer
/// into that config's `enable_secret_extraction`.
pub(super) fn wanted() -> bool {
    static WANTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *WANTED.get_or_init(|| {
        matches!(
            std::env::var("NZBFAST_KTLS").as_deref(),
            Ok("1") | Ok("true")
        )
    })
}

/// Latched the first time a kernel refuses the handoff. One process
/// talks to one kernel, so the second refusal would tell us nothing
/// the first did not - and every attempt costs a spent socket.
static OFF: AtomicBool = AtomicBool::new(false);

pub(super) fn active() -> bool {
    wanted() && !OFF.load(Ordering::Relaxed)
}

/// Silent and total, one log line the first time. This is the whole
/// point of the opt-in: an old kernel just downloads in userspace.
pub(super) fn disable(why: &dyn std::fmt::Display) {
    if !OFF.swap(true, Ordering::Relaxed) {
        info!(target: "ktls", "kernel declined the handoff ({why}); TLS stays in userspace");
    }
}

/// Handshake with rustls, then hand the socket to the kernel.
///
/// - `Ok(Some(wire))` - kTLS is live on this connection.
/// - `Ok(None)` - the kernel refused. kTLS is off for the rest of
///   the process and the caller must redial: draining rustls spent
///   this socket.
/// - `Err(e)` - the TLS handshake itself failed, exactly as it
///   would have without kTLS, and the caller's existing ladder
///   (pinned suite → full cipher list) applies unchanged.
pub(super) async fn connect(
    name: rustls::pki_types::ServerName<'static>,
    tcp: tokio::net::TcpStream,
    pin_fast_suite: bool,
) -> std::io::Result<Option<Wire>> {
    let connector = tokio_rustls::TlsConnector::from(super::tls::tls_client_config(pin_fast_suite));
    // The cork is load-bearing. rustls reads whatever the socket
    // has, so by the time `connect` returns it can be holding a
    // PARTIAL record - and the kernel, handed keys that start at a
    // record boundary, could never decrypt the remainder. A corked
    // stream stops at each boundary, which lets the drain below end
    // exactly where the kernel begins.
    let stream = connector.connect(name, ktls::CorkStream::new(tcp)).await?;
    match ktls::config_ktls_client(stream).await {
        Ok(k) => {
            // Say so once. "It downloaded" is not evidence that the
            // kernel took the socket - the fallback is silent and
            // looks identical from the outside.
            static LOGGED: AtomicBool = AtomicBool::new(false);
            if !LOGGED.swap(true, Ordering::Relaxed) {
                info!(target: "ktls", "kernel TLS active - record crypto moved into the kernel");
            }
            // Whatever rustls decrypted before the handoff (the NNTP
            // greeting usually arrives in the same flight) rides
            // along inside the stream and comes out of the first
            // reads, ahead of anything the kernel produces.
            let (drained, tcp) = k.into_raw();
            Ok(Some(Wire::buffered(Box::new(KtlsWire::new(tcp, drained)))))
        }
        Err(e) => {
            disable(&e);
            Ok(None)
        }
    }
}

/// A socket the kernel decrypts: ordinary `read`/`write`, plaintext on
/// both sides, plus whatever rustls had already decrypted when the
/// kernel took over.
///
/// It exists instead of `ktls::KtlsStream` for one reason: control
/// records. A `read()` on a kTLS socket fails with `EIO` for any record
/// that is not application data, and the only way to see what it was is
/// `recvmsg` with room for a `TLS_GET_RECORD_TYPE` control message. The
/// crate's own stream does that too, but answers the awkward cases -
/// an unexpected `cmsg`, a two-byte alert that arrives as one byte, a
/// `change_cipher_spec` - with `panic!`. A panic in a pool worker takes
/// the download with it (an `Err` never hangs the pool; a panic does),
/// and every one of those cases is reachable from the far end of a
/// socket, which is untrusted input. Here they are all errors, and an
/// error just costs that one connection.
struct KtlsWire {
    tcp: tokio::net::TcpStream,
    fd: std::os::fd::RawFd,
    /// Plaintext rustls decrypted before the handoff (the NNTP greeting
    /// usually), and how much of it has been handed out.
    drained: Option<(usize, Vec<u8>)>,
}

impl KtlsWire {
    /// `SOL_TLS` and `TLS_GET_RECORD_TYPE` from the kernel's
    /// `include/uapi/linux/tls.h`; libc does not export them.
    const SOL_TLS: libc::c_int = 282;
    const TLS_GET_RECORD_TYPE: libc::c_int = 2;
    const RECORD_ALERT: u8 = 21;
    const RECORD_HANDSHAKE: u8 = 22;
    const ALERT_CLOSE_NOTIFY: u8 = 0;
    const HANDSHAKE_NEW_SESSION_TICKET: u8 = 4;
    const HANDSHAKE_KEY_UPDATE: u8 = 24;

    fn new(tcp: tokio::net::TcpStream, drained: Option<Vec<u8>>) -> Self {
        use std::os::fd::AsRawFd as _;
        let fd = tcp.as_raw_fd();
        Self {
            tcp,
            fd,
            // An EMPTY leftover is no leftover: kept as `Some(vec![])` it
            // would fill nothing on the first `poll_read` and return
            // `Ready(Ok(()))`, which every reader above reads as EOF.
            drained: drained.filter(|d| !d.is_empty()).map(|d| (0, d)),
        }
    }

    /// Consume the one non-data record the kernel is holding, and say
    /// what to do next. Until it is consumed, nothing behind it can be
    /// read.
    ///
    /// `scratch` is the caller's own read buffer, borrowed and then
    /// discarded: a control record's contents are never application
    /// data, so nothing here is ever handed upward.
    fn take_control_record(&mut self, scratch: &mut [u8]) -> std::io::Result<ControlRecord> {
        // A union with the header, not a byte array: `CMSG_FIRSTHDR`
        // casts this buffer to a `cmsghdr`, so it has to carry that
        // type's alignment. A `[u8; N]` is 1-aligned and reads as a
        // misaligned dereference - which a release build happily runs
        // and a debug build aborts on (it did, first run).
        union CmsgSpace {
            _hdr: libc::cmsghdr,
            bytes: [u8; 64],
        }
        let mut cmsg_space = CmsgSpace { bytes: [0u8; 64] };
        let cmsg_len = std::mem::size_of::<CmsgSpace>();
        // SAFETY: every pointer handed to recvmsg points at a live local
        // buffer, the lengths match those buffers, and the cmsg walk uses
        // the kernel's own macros over the header recvmsg filled in.
        let (n, record_type) = unsafe {
            let mut iov = libc::iovec {
                iov_base: scratch.as_mut_ptr().cast(),
                iov_len: scratch.len(),
            };
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.bytes.as_mut_ptr().cast();
            msg.msg_controllen = cmsg_len as _;
            let n = libc::recvmsg(self.fd, &mut msg, libc::MSG_DONTWAIT);
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut ty = None;
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == Self::SOL_TLS && (*c).cmsg_type == Self::TLS_GET_RECORD_TYPE {
                    ty = Some(*libc::CMSG_DATA(c));
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            (n as usize, ty)
        };
        let Some(record_type) = record_type else {
            // No record-type control message means this was not the
            // control record we were told about. Nothing sane left to
            // do with the connection.
            return Err(std::io::Error::other(
                "kTLS: EIO on read with no TLS record type",
            ));
        };
        let body = &scratch[..n];
        match record_type {
            Self::RECORD_ALERT => match body {
                // A close_notify is the peer hanging up cleanly, which
                // is exactly EOF. Every other alert aborts the session
                // by definition, so it is an error either way.
                [_, Self::ALERT_CLOSE_NOTIFY] | [Self::ALERT_CLOSE_NOTIFY] => {
                    Ok(ControlRecord::Eof)
                }
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "kTLS: TLS alert",
                )),
            },
            Self::RECORD_HANDSHAKE => match body.first().copied() {
                // Session tickets: the ordinary post-handshake traffic
                // of any TLS 1.3 server. The kernel cannot use them and
                // neither can we now that rustls is out of the loop, so
                // resumption is a cost kTLS connections pay - one extra
                // round-trip on the NEXT connect to that host.
                Some(Self::HANDSHAKE_NEW_SESSION_TICKET) => Ok(ControlRecord::Skip),
                // A rekey. The kernel holds one set of keys and cannot
                // be handed another mid-stream, so this connection is
                // over - and a server that rekeys once will do it
                // again, so stop using kTLS for the rest of the run.
                Some(Self::HANDSHAKE_KEY_UPDATE) => {
                    disable(&"server sent a TLS KeyUpdate");
                    Err(std::io::Error::other(
                        "kTLS: TLS KeyUpdate cannot be applied",
                    ))
                }
                _ => Ok(ControlRecord::Skip),
            },
            // change_cipher_spec (20) after the handshake, or anything
            // else: not something a TLS 1.3 peer sends on a live
            // connection.
            other => Err(std::io::Error::other(format!(
                "kTLS: unexpected TLS record type {other}"
            ))),
        }
    }
}

/// What a consumed control record means for the read that hit it.
enum ControlRecord {
    /// Ignorable; read again.
    Skip,
    /// The peer closed cleanly.
    Eof,
}

impl AsyncRead for KtlsWire {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        // Pre-handoff plaintext first - it sits in front of everything
        // the kernel will ever produce.
        if let Some((at, d)) = &mut me.drained {
            let n = (d.len() - *at).min(buf.remaining());
            buf.put_slice(&d[*at..*at + n]);
            *at += n;
            if *at >= d.len() {
                me.drained = None;
            }
            return std::task::Poll::Ready(Ok(()));
        }
        match std::pin::Pin::new(&mut me.tcp).poll_read(cx, buf) {
            std::task::Poll::Ready(Err(e)) if e.raw_os_error() == Some(libc::EIO) => {
                // Not a failure: the kernel is holding a record it will
                // not hand over as data, and says so with EIO.
                match me.take_control_record(buf.initialize_unfilled()) {
                    Ok(ControlRecord::Skip) => {
                        // The record is consumed; whatever is behind it
                        // may be readable right now, so try again
                        // rather than wait for the next readiness edge.
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                    // Nothing filled == EOF.
                    Ok(ControlRecord::Eof) => std::task::Poll::Ready(Ok(())),
                    Err(e) => std::task::Poll::Ready(Err(e)),
                }
            }
            other => other,
        }
    }
}

impl AsyncWrite for KtlsWire {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().tcp).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().tcp).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}
