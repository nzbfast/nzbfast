//! TLS front end for the chaos mock (§129 3b): terminates a real rustls
//! handshake in front of [`crate::mock::MockServer`] and injects the
//! fault shapes that only exist BELOW the NNTP conversation - a broken
//! handshake, a mid-body cut with no `close_notify`, a corrupted record,
//! and a kill-then-fail-the-reconnect sequence.
//!
//! Every chaos profile the fault matrix races today runs plain TCP, so
//! the transport real users are actually on - every provider is port 563
//! - has never been faulted. These knobs sit in the acceptor wrapper, not
//! in [`crate::mock::Chaos`]: the NNTP logic is transport-agnostic and
//! stays that way, so all existing Chaos fields work unchanged under TLS.
//!
//! Shape: the front owns the public port, terminates TLS, and pipes
//! plaintext to the mock on its own loopback port. Nothing in mock.rs
//! changes - which also means the plain-TCP path every published rig
//! number was measured on is byte-for-byte the same code as before.
//!
//! The server config comes from [`crate::benchserve::tls_config`] (one
//! PEM loader, one acceptor in the tree); clients trust the rig's
//! certificate through `NZBFAST_EXTRA_CA`, exactly as the TLS bench leg
//! already does.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// How a handshake gets broken.
#[derive(Clone)]
pub enum HandshakeFault {
    /// Accept the TCP connection, read the ClientHello, then close the
    /// socket mid-handshake - no alert, no answer. What a load balancer
    /// dropping the flow looks like.
    Close,
    /// Run the handshake with a certificate that does not match the name
    /// the client dialled. The handshake reaches the client's verifier
    /// and is refused there (rustls: `NotValidForName`) - a different
    /// classification path from [`HandshakeFault::Close`], which is why
    /// both variants exist.
    WrongCert(Arc<rustls::ServerConfig>),
}

/// TLS-layer failure injection. All byte counts are PER CONNECTION and
/// all are off at zero/None, so a default front is a plain TLS endpoint.
#[derive(Clone, Default)]
pub struct TlsChaos {
    /// Break the handshake on accepted connections. `None` = never.
    pub handshake_fail: Option<HandshakeFault>,
    /// Accepts served normally before the handshake faults begin.
    pub handshake_fail_after: u64,
    /// How many accepts to break once they begin (`u64::MAX` = all).
    pub handshake_fail_count: u64,
    /// After this many PLAINTEXT bytes have gone to the client on a
    /// connection, close the TCP socket with NO `close_notify` - the
    /// truncation-attack shape. The bytes already delivered are a
    /// partial article; a client that treats the stream end as an
    /// ordinary EOF completes a short body. 0 = off.
    ///
    /// Counts every plaintext byte the mock sends, greeting and status
    /// lines included, so pick a budget comfortably past the greeting.
    pub truncate_after_bytes: u64,
    /// After this many CIPHERTEXT bytes have gone out post-handshake,
    /// flip a bit in the encrypted stream so the record's AEAD tag
    /// fails at the client. 0 = off.
    pub corrupt_record_after_bytes: u64,
    /// Kill the connection after this many plaintext bytes (as
    /// `truncate_after_bytes`, no `close_notify`) AND arm a one-shot
    /// handshake failure, so the client's reconnect fails to dial once
    /// before it can resume. Exercises dial-retry and resume together,
    /// which neither knob does alone. `None` = off.
    pub fault_during_resume: Option<u64>,
}

/// What the front actually did, for tests and rig logs: a profile that
/// silently fails to engage looks exactly like a client that handled it.
#[derive(Default)]
pub struct TlsCounts {
    /// TCP connections accepted by the front.
    pub accepted: AtomicU64,
    /// Handshakes completed.
    pub handshakes: AtomicU64,
    /// Handshakes broken on purpose (both variants, resume included).
    pub handshake_faults: AtomicU64,
    /// Connections cut mid-stream with no `close_notify`.
    pub truncations: AtomicU64,
    /// Records corrupted post-encryption.
    pub corruptions: AtomicU64,
}

/// A running TLS front. Dropping it stops the listener (the mock behind
/// it is a separate object with the same discipline).
pub struct TlsFront {
    pub addr: SocketAddr,
    pub counts: Arc<TlsCounts>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for TlsFront {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl TlsFront {
    /// Listen on `bind`, terminate TLS with `tls`, and pipe plaintext to
    /// `backend` (a plain-TCP [`crate::mock::MockServer`]).
    pub async fn start(
        bind: &str,
        backend: SocketAddr,
        tls: Arc<rustls::ServerConfig>,
        chaos: TlsChaos,
    ) -> io::Result<TlsFront> {
        let listener = TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        let counts: Arc<TlsCounts> = Default::default();
        let counts_loop = counts.clone();
        let handle = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(tls);
            // Set by a resume kill, taken by the next accept: the point
            // of `fault_during_resume` is the ORDER (kill, then a dial
            // that fails, then service), which no single-connection knob
            // can express.
            let resume_armed = Arc::new(AtomicBool::new(false));
            // Budget for the configured handshake-fault window, kept
            // apart from the public tally so resume faults do not spend
            // it.
            let faults_spent = Arc::new(AtomicU64::new(0));
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let nth = counts_loop.accepted.fetch_add(1, Ordering::Relaxed) + 1;
                let (chaos, counts, acceptor) =
                    (chaos.clone(), counts_loop.clone(), acceptor.clone());
                let (resume_armed, faults_spent) = (resume_armed.clone(), faults_spent.clone());
                tokio::spawn(async move {
                    let _ = front_conn(
                        sock,
                        backend,
                        acceptor,
                        chaos,
                        counts,
                        Conn {
                            nth,
                            resume_armed,
                            faults_spent,
                        },
                    )
                    .await;
                });
            }
        });
        Ok(TlsFront {
            addr,
            counts,
            handle,
        })
    }

    /// The mock's own [`crate::config::ServerConfig`], re-pointed at this
    /// front with TLS on. `host` must be a name the rig certificate
    /// covers - the client really verifies it.
    pub fn server_config(
        &self,
        host: &str,
        mock: &crate::mock::MockServer,
    ) -> crate::config::ServerConfig {
        crate::config::ServerConfig {
            host: host.to_string(),
            port: self.addr.port(),
            tls: true,
            ..mock.server_config()
        }
    }
}

/// Per-connection state the accept loop hands down.
struct Conn {
    nth: u64,
    resume_armed: Arc<AtomicBool>,
    faults_spent: Arc<AtomicU64>,
}

async fn front_conn(
    sock: TcpStream,
    backend: SocketAddr,
    acceptor: TlsAcceptor,
    chaos: TlsChaos,
    counts: Arc<TlsCounts>,
    conn: Conn,
) -> io::Result<()> {
    let _ = sock.set_nodelay(true);

    // A resume kill armed this dial to fail: spend it first, and spend
    // it whatever the configured window says.
    if conn.resume_armed.swap(false, Ordering::Relaxed) {
        counts.handshake_faults.fetch_add(1, Ordering::Relaxed);
        return break_handshake(sock, &HandshakeFault::Close).await;
    }
    if let Some(fault) = &chaos.handshake_fail
        && conn.nth > chaos.handshake_fail_after
        && conn
            .faults_spent
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < chaos.handshake_fail_count).then_some(n + 1)
            })
            .is_ok()
    {
        counts.handshake_faults.fetch_add(1, Ordering::Relaxed);
        return break_handshake(sock, fault).await;
    }

    let back = TcpStream::connect(backend).await?;
    let _ = back.set_nodelay(true);
    let mut tls = acceptor
        .accept(ChaosSock::new(
            sock,
            chaos.corrupt_record_after_bytes,
            counts.clone(),
        ))
        .await?;
    counts.handshakes.fetch_add(1, Ordering::Relaxed);
    // Ciphertext corruption counts only AFTER the handshake: flipping a
    // byte of the ServerHello would just be a second handshake fault.
    tls.get_mut().0.arm();

    // Truncation budget. `truncate_after_bytes` wins if both are set -
    // a profile asking for both shapes at once wants the simpler one.
    let (budget, arm_resume) = match (chaos.truncate_after_bytes, chaos.fault_during_resume) {
        (0, Some(n)) => (Some(n), true),
        (0, None) => (None, false),
        (n, _) => (Some(n), false),
    };
    let cut = pump(tls, back, budget).await?;
    if cut {
        counts.truncations.fetch_add(1, Ordering::Relaxed);
        if arm_resume {
            conn.resume_armed.store(true, Ordering::Relaxed);
        }
    }
    Ok(())
}

/// Break a handshake, one variant each way.
async fn break_handshake(mut sock: TcpStream, fault: &HandshakeFault) -> io::Result<()> {
    match fault {
        HandshakeFault::Close => {
            // Read the ClientHello first: closing before the client has
            // said anything is a connect failure, not a handshake one,
            // and the two classify differently.
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
            drop(sock);
        }
        HandshakeFault::WrongCert(cfg) => {
            // Present the mismatched chain and let the client's verifier
            // do the refusing; the error it raises is the whole point.
            let _ = TlsAcceptor::from(cfg.clone()).accept(sock).await;
        }
    }
    Ok(())
}

/// Pipe plaintext both ways until one side ends. Returns true when the
/// connection was CUT at the byte budget - closed hard, with no
/// `close_notify` written, which is the security-relevant shape.
async fn pump(
    tls: tokio_rustls::server::TlsStream<ChaosSock>,
    back: TcpStream,
    budget: Option<u64>,
) -> io::Result<bool> {
    let (mut cr, mut cw) = tokio::io::split(tls);
    let (mut br, mut bw) = back.into_split();
    // Client -> mock, in its own task so it keeps draining the socket
    // while the response side runs; an unread receive queue at close
    // time turns our FIN into an RST and the cut stops being clean.
    let up = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match cr.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if bw.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    });

    let mut buf = vec![0u8; 32 << 10];
    let mut sent = 0u64;
    let mut cut = false;
    loop {
        let n = match br.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let take = match budget {
            Some(limit) if sent + n as u64 >= limit => (limit - sent) as usize,
            _ => n,
        };
        // `write_all` is NOT delivery on a TLS stream, and the whole
        // stall class this rig produced lives in that gap. tokio-rustls'
        // `poll_write` accepts plaintext into the rustls session and
        // then flushes what it can; when the socket write would block it
        // returns `Ok(n)` for the plaintext it TOOK while the ciphertext
        // tail stays queued in `sendable_tls`. `write_all` sees every
        // byte consumed and returns happy, and nothing drains that queue
        // until the next write - so a relay that goes straight back to
        // `br.read()` and parks there (the mock has finished the body it
        // was serving) strands the end of an article inside the front.
        // The client is then waiting on a session carrying NO injected
        // fault, and only its flat 30 s `read_timeout` ends it - which is
        // exactly the `ends.stall` seen on windows-unit, where a loopback
        // write really can block and a mac/Linux one at these sizes
        // essentially never does. Flush before parking.
        if cw.write_all(&buf[..take]).await.is_err() {
            break;
        }
        if cw.flush().await.is_err() {
            break;
        }
        sent += take as u64;
        if budget.is_some_and(|limit| sent >= limit) {
            // Flush the partial body out, give it a moment to land, then
            // drop everything. NEVER `shutdown()`: that is what writes
            // close_notify, and its absence is what this reproduces.
            let _ = cw.flush().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            cut = true;
            break;
        }
    }
    up.abort();
    Ok(cut)
}

/// The client socket, with a bit flipped in the ciphertext once the
/// stream passes `after` post-handshake bytes. Below rustls on purpose:
/// corrupting plaintext would just be a damaged article (the mock's
/// `corrupt` knob already does that), while corrupting the encrypted
/// stream is what a broken middlebox or a bad NIC does, and it must fail
/// the record's AEAD tag rather than deliver garbage.
pub struct ChaosSock {
    inner: TcpStream,
    armed: bool,
    after: u64,
    written: u64,
    done: bool,
    counts: Arc<TlsCounts>,
    scratch: Vec<u8>,
}

impl ChaosSock {
    fn new(inner: TcpStream, after: u64, counts: Arc<TlsCounts>) -> ChaosSock {
        ChaosSock {
            inner,
            armed: false,
            after,
            written: 0,
            done: false,
            counts,
            scratch: Vec::new(),
        }
    }

    fn arm(&mut self) {
        self.armed = true;
    }

    /// Off, already fired, or the threshold is past this write.
    fn passthrough(&self, len: usize) -> bool {
        !self.armed || self.done || self.after == 0 || self.written + len as u64 <= self.after
    }
}

impl AsyncRead for ChaosSock {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChaosSock {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        if me.passthrough(buf.len()) {
            let n = std::task::ready!(Pin::new(&mut me.inner).poll_write(cx, buf))?;
            if me.armed {
                me.written += n as u64;
            }
            return Poll::Ready(Ok(n));
        }
        // This write crosses the threshold: send the same bytes with one
        // bit flipped at the crossing point. Rebuilt from `buf` every
        // poll, so a Pending here cannot smear the damage.
        let off = crate::disk::chunk_len(me.after.saturating_sub(me.written), buf.len() - 1);
        me.scratch.clear();
        me.scratch.extend_from_slice(buf);
        me.scratch[off] ^= 0x40;
        let (inner, scratch) = (&mut me.inner, &me.scratch);
        let n = std::task::ready!(Pin::new(inner).poll_write(cx, scratch))?;
        me.written += n as u64;
        // Only claim the corruption once the flipped byte really left.
        if n > off {
            me.done = true;
            me.counts.corruptions.fetch_add(1, Ordering::Relaxed);
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
