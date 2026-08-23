//! The userspace TLS socket (TODO 70C): the ciphertext read buffer the
//! download connections read through, and the handshake rung that puts
//! it under rustls. Split out of `nntp.rs` for the size gate.

use tokio::io::BufReader;

use super::Wire;

/// What a userspace TLS connection reads its ciphertext through: the
/// socket behind a read buffer of [`TLS_WIRE_READ_BUF`] bytes. Writes
/// pass straight through (`BufReader` forwards `AsyncWrite`), so the
/// command path is unchanged.
pub(super) type TlsSocket = BufReader<tokio::net::TcpStream>;

/// Ciphertext read buffer under the userspace TLS stream (TODO 70C,
/// measured 22 Aug 2026 on the loopback mock rig, 8 connections).
///
/// rustls' own deframer asks the socket for one record at a time: the
/// unbuffered rig counted 131,179 `read()`s for 2.12 GB, 16,133 bytes
/// each. With 64 KB here that is 35,486 reads at 59,637 bytes (3.7x
/// fewer), and the client's CPU for the same 2.05 GB download went
/// 2.405 -> 2.28 cpu-s (-5.2%, 8 wins / 1 loss over 20 interleaved
/// rounds; the sys term -0.18 s, the user term +0.06 s for the one
/// extra memcpy a buffer under rustls costs). 256 KB measured the same
/// (2.30 cpu-s, 13.7x fewer reads) for 4x the memory per connection,
/// so 64 KB is the knee: the per-read cost is what was being paid, and
/// four records per read already recovers most of it. Per-connection
/// memory is this figure, touched in full on a busy link, so a 360-way
/// fleet carries ~23 MB here rather than ~92 MB.
///
/// This is the half of §70 lever C that rustls 0.23 can deliver. The
/// other half - plaintext decrypted straight into our buffer - needs
/// in-place decryption in rustls' `unbuffered` API, and 0.23.43's
/// `ReadTraffic::next_record` still hands out the same `into_vec()`
/// copy the buffered `Reader` does (its source says so: "to support
/// in-place decryption in the future"). Revisit when a rustls release
/// decrypts in place; until then an unbuffered port would ADD a copy.
pub(super) const TLS_WIRE_READ_BUF: usize = 64 * 1024;

/// The buffer actually used: `NZBFAST_TLS_READBUF` in KiB when set,
/// else [`TLS_WIRE_READ_BUF`]. `0` is the pre-70C raw socket, kept for
/// A/B - tokio's `BufReader` hands a read straight to the inner stream
/// whenever the caller's buffer is at least its own, so at capacity 0
/// every read bypasses and nothing is copied. Read once.
pub(super) fn tls_read_buf() -> usize {
    static SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SIZE.get_or_init(|| {
        std::env::var("NZBFAST_TLS_READBUF")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map_or(TLS_WIRE_READ_BUF, |kib| kib.saturating_mul(1024))
    })
}

/// The plain userspace rung: rustls owns the record layer, as it has
/// on every platform since the beginning.
pub(super) async fn userspace_tls(
    name: rustls::pki_types::ServerName<'static>,
    tcp: tokio::net::TcpStream,
    pin_fast_suite: bool,
) -> std::io::Result<Wire> {
    let connector = tokio_rustls::TlsConnector::from(super::tls_client_config(pin_fast_suite));
    let socket = BufReader::with_capacity(tls_read_buf(), tcp);
    Ok(Wire::Tls(Box::new(connector.connect(name, socket).await?)))
}
