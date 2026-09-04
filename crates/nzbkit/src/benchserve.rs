//! Loopback ceiling bench: a purpose-built local NNTP server fast
//! enough that the CLIENT is always the bottleneck. Serves a synthetic
//! release of any size from ~1 MB of RAM: every full-size part of every
//! file carries the SAME payload chunk, so the yEnc body block and its
//! CRC are encoded once and each article is assembled per request as
//! [unique =ybegin/=ypart lines] + [shared pre-encoded block] + [=yend].
//! The encoder escapes a column-0 '.', so the block needs no wire-level
//! dot-stuffing either. Plain TCP, no auth required (accepted if sent).
//!
//! Speaks enough NNTP for a standard downloader: BODY, ARTICLE, STAT, HEAD,
//! GROUP, MODE READER, CAPABILITIES, AUTHINFO, DATE, QUIT - the commands any
//! newsreader fetches article bodies over.
//!
//! TLS leg (`serve_with`): plain TCP was the only mode for a long time, so
//! every loopback and constrained-CPU number we have describes a path NO
//! real user is on - providers are port 563, and the TLS receive path has
//! a completely different per-byte cost (record-sized socket reads, an
//! extra plaintext copy inside rustls, AEAD). The cert/key come from PEM
//! files rather than a generator dependency: the harness makes them with
//! `openssl req -x509`, so the shipped binary gains no new crate.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

use crate::md5fast::{Digest, Md5};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const LINE_LEN: usize = 128;
/// Name of the synthetic PAR2 index when `--par2` is on.
const PAR2_NAME: &str = "bench.par2";

/// yEnc-encode `data` as a body block (no header/trailer lines), same
/// escaping rules as [`crate::yenc::encode`]. Ends with CRLF.
fn encode_block(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 32 + 16);
    let mut col = 0usize;
    for &b in data {
        let enc = b.wrapping_add(42);
        let critical = matches!(enc, 0x00 | 0x0A | 0x0D | b'=') || (col == 0 && enc == b'.');
        if critical {
            out.push(b'=');
            out.push(enc.wrapping_add(64));
            col += 2;
        } else {
            out.push(enc);
            col += 1;
        }
        if col >= LINE_LEN {
            out.extend_from_slice(b"\r\n");
            col = 0;
        }
    }
    if col > 0 {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Deterministic, incompressible-ish payload (matches the mockserv
/// example's generator so the bytes aren't trivially runs of zeros).
fn payload(len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
        .collect()
}

/// One PAR2 packet: magic ‖ len ‖ MD5(set_id‖type‖body) ‖ set_id ‖ type ‖
/// body. `body` must already be padded to a multiple of 4.
fn par2_packet(set_id: &[u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    debug_assert_eq!(body.len() % 4, 0);
    let mut md5 = Md5::new();
    md5.update(set_id);
    md5.update(ptype);
    md5.update(body);
    let mut out = Vec::with_capacity(64 + body.len());
    out.extend_from_slice(crate::par2::MAGIC);
    out.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    out.extend_from_slice(&md5.finalize());
    out.extend_from_slice(set_id);
    out.extend_from_slice(ptype);
    out.extend_from_slice(body);
    out
}

/// Build a verify-only PAR2 index (Main + FileDesc + IFSC per file +
/// Creator; no recovery slices - live verify needs checksums, not
/// parity) describing the synthetic set. Every file carries identical
/// bytes (payload() is prefix-stable, so content at offset o is
/// g(o mod article)), so the expensive hashing pass runs ONCE for one
/// file and is reused across all of them - only names/file-ids differ.
/// The block size is deliberately misaligned with the article size
/// (3/4 of it) so boundary blocks exercise the verifier's partials
/// path, not just whole-block hashing.
fn build_par2(files: u32, file_size: u64, article: usize) -> Vec<u8> {
    let bs = ((article * 3 / 4) & !3).max(4);
    let full = payload(article);
    let nblocks = file_size.div_ceil(bs as u64) as usize;

    // One streaming pass: per-block MD5+CRC (last block zero-padded per
    // spec), whole-file MD5, first-16k MD5 (short file: = whole MD5).
    let mut checks: Vec<([u8; 16], u32)> = Vec::with_capacity(nblocks);
    let mut whole = Md5::new();
    let mut head = Md5::new();
    let mut buf = vec![0u8; bs];
    for bi in 0..nblocks {
        let start = bi as u64 * bs as u64;
        let len = (file_size - start).min(bs as u64) as usize;
        // Fill from the periodic content: copy article-aligned spans.
        let mut done = 0usize;
        while done < len {
            let src = ((start + done as u64) % article as u64) as usize;
            let n = (article - src).min(len - done);
            buf[done..done + n].copy_from_slice(&full[src..src + n]);
            done += n;
        }
        whole.update(&buf[..len]);
        if start < 16384 {
            head.update(&buf[..len.min((16384 - start as usize).min(len))]);
        }
        buf[len..].fill(0);
        checks.push((Md5::digest(&buf).into(), crc32fast::hash(&buf)));
    }
    let md5_whole: [u8; 16] = whole.finalize().into();
    let md5_16k: [u8; 16] = head.finalize().into();

    // Per-file identity: null-padded name, file id = MD5(hash16k‖len‖name).
    let mut fids: Vec<([u8; 16], Vec<u8>)> = (0..files)
        .map(|fi| {
            let mut name = BenchSet::file_name(fi).into_bytes();
            name.resize(name.len().div_ceil(4) * 4, 0);
            let mut id = Md5::new();
            id.update(md5_16k);
            id.update(file_size.to_le_bytes());
            id.update(&name);
            (id.finalize().into(), name)
        })
        .collect();
    fids.sort_by_key(|a| a.0); // Main lists ids sorted

    let mut main_body = Vec::with_capacity(12 + fids.len() * 16);
    main_body.extend_from_slice(&(bs as u64).to_le_bytes());
    main_body.extend_from_slice(&(files).to_le_bytes());
    for (fid, _) in &fids {
        main_body.extend_from_slice(fid);
    }
    let set_id: [u8; 16] = Md5::digest(&main_body).into();

    let mut blob = par2_packet(&set_id, crate::par2::TYPE_MAIN, &main_body);
    let mut ifsc_body_tail = Vec::with_capacity(checks.len() * 20);
    for (m, c) in &checks {
        ifsc_body_tail.extend_from_slice(m);
        ifsc_body_tail.extend_from_slice(&c.to_le_bytes());
    }
    for (fid, name) in &fids {
        let mut fd = Vec::with_capacity(56 + name.len());
        fd.extend_from_slice(fid);
        fd.extend_from_slice(&md5_whole);
        fd.extend_from_slice(&md5_16k);
        fd.extend_from_slice(&file_size.to_le_bytes());
        fd.extend_from_slice(name);
        blob.extend_from_slice(&par2_packet(&set_id, crate::par2::TYPE_FILEDESC, &fd));
        let mut ifsc = Vec::with_capacity(16 + ifsc_body_tail.len());
        ifsc.extend_from_slice(fid);
        ifsc.extend_from_slice(&ifsc_body_tail);
        blob.extend_from_slice(&par2_packet(&set_id, crate::par2::TYPE_IFSC, &ifsc));
    }
    let mut creator = b"nzbfast benchserve".to_vec();
    creator.resize(creator.len().div_ceil(4) * 4, 0);
    blob.extend_from_slice(&par2_packet(&set_id, b"PAR 2.0\0Creator\0", &creator));
    blob
}

pub struct BenchSet {
    pub(crate) files: u32,
    pub(crate) file_size: u64,
    pub(crate) article: usize,
    parts_per_file: u32,
    tail_len: usize,
    full_block: Arc<Vec<u8>>,
    full_crc: u32,
    tail_block: Arc<Vec<u8>>,
    tail_crc: u32,
    /// BODY/ARTICLE requests served.
    pub served: Arc<AtomicU64>,
    /// Wire payload bytes written (status+headers+block+trailer).
    pub bytes: Arc<AtomicU64>,
    /// `--par2`: the synthetic PAR2 index (verify-only: Main + FileDesc +
    /// IFSC + Creator, no recovery slices) plus its own part count. Gives
    /// the client real live-verify MD5/CRC load - without it the rig only
    /// exercises decode+write, which is why the A6 first-cut regression
    /// was visible here but the A6 upside never could be.
    par2: Option<Par2Meta>,
}

struct Par2Meta {
    blob: Arc<Vec<u8>>,
    parts: u32,
}

impl BenchSet {
    pub fn new(files: u32, file_size: u64, article: usize) -> BenchSet {
        Self::with_par2(files, file_size, article, false)
    }

    pub fn with_par2(files: u32, file_size: u64, article: usize, par2: bool) -> BenchSet {
        let article = article.clamp(4096, 4 << 20);
        let file_size = file_size.max(article as u64);
        let parts_per_file = file_size.div_ceil(article as u64) as u32;
        let tail_len = (file_size - (parts_per_file as u64 - 1) * article as u64) as usize;
        let full = payload(article);
        let tail = payload(tail_len);
        let par2 = par2.then(|| {
            let blob = build_par2(files, file_size, article);
            let parts = (blob.len().max(1)).div_ceil(article) as u32;
            Par2Meta {
                blob: Arc::new(blob),
                parts,
            }
        });
        BenchSet {
            files,
            file_size,
            article,
            parts_per_file,
            tail_len,
            full_crc: crc32fast::hash(&full),
            full_block: Arc::new(encode_block(&full)),
            tail_crc: crc32fast::hash(&tail),
            tail_block: Arc::new(encode_block(&tail)),
            served: Arc::new(AtomicU64::new(0)),
            bytes: Arc::new(AtomicU64::new(0)),
            par2,
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.files as u64 * self.file_size
    }

    fn file_name(fi: u32) -> String {
        format!("bench-f{fi:04}.bin")
    }

    /// The matching NZB for the whole set.
    pub fn nzb(&self) -> String {
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        let approx_full = self.full_block.len() as u64 + 160;
        let approx_tail = self.tail_block.len() as u64 + 160;
        for fi in 0..self.files {
            let name = Self::file_name(fi);
            out.push_str(&format!(
                "<file poster=\"bench@nzbfast\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n\
                 <groups><group>alt.binaries.bench</group></groups>\n<segments>\n",
                self.parts_per_file
            ));
            for p in 1..=self.parts_per_file {
                let bytes = if p == self.parts_per_file {
                    approx_tail
                } else {
                    approx_full
                };
                out.push_str(&format!(
                    "<segment bytes=\"{bytes}\" number=\"{p}\">f{fi}-p{p}@bench</segment>\n"
                ));
            }
            out.push_str("</segments>\n</file>\n");
        }
        if let Some(p) = &self.par2 {
            out.push_str(&format!(
                "<file poster=\"bench@nzbfast\" date=\"0\" subject=\"&quot;{PAR2_NAME}&quot; yEnc (1/{})\">\n\
                 <groups><group>alt.binaries.bench</group></groups>\n<segments>\n",
                p.parts
            ));
            for part in 1..=p.parts {
                let start = (part as usize - 1) * self.article;
                let len = p.blob.len().saturating_sub(start).min(self.article);
                out.push_str(&format!(
                    "<segment bytes=\"{}\" number=\"{part}\">par2-p{part}@bench</segment>\n",
                    len + len / 30 + 160
                ));
            }
            out.push_str("</segments>\n</file>\n");
        }
        out.push_str("</nzb>\n");
        out
    }

    /// `<f12-p3@bench>` (brackets optional) → (file, part), if valid.
    /// The PAR2 index (when enabled) is file `u32::MAX`: `par2-p1@bench`.
    fn parse_id(&self, id: &str) -> Option<(u32, u32)> {
        let id = id.trim().trim_start_matches('<').trim_end_matches('>');
        if let Some(rest) = id.strip_prefix("par2-p") {
            let part = rest.strip_suffix("@bench")?.parse::<u32>().ok()?;
            let p = self.par2.as_ref()?;
            return (part >= 1 && part <= p.parts).then_some((u32::MAX, part));
        }
        let rest = id.strip_prefix('f')?.strip_suffix("@bench")?;
        let (fi, part) = rest.split_once("-p")?;
        let (fi, part) = (fi.parse::<u32>().ok()?, part.parse::<u32>().ok()?);
        (fi < self.files && part >= 1 && part <= self.parts_per_file).then_some((fi, part))
    }

    /// Render one article of the PAR2 index (real yEnc, tiny blob - no
    /// need for the shared-block trick the data files use).
    fn par2_article(&self, part: u32) -> Vec<u8> {
        let p = self.par2.as_ref().expect("par2 article without --par2");
        let start = (part as usize - 1) * self.article;
        let end = (start + self.article).min(p.blob.len());
        let mut art = crate::yenc::encode(
            PAR2_NAME,
            p.blob.len() as u64,
            Some((part, p.parts)),
            start as u64 + 1,
            &p.blob[start..end],
        );
        art.extend_from_slice(b".\r\n");
        art
    }

    fn name_for(&self, fi: u32) -> String {
        if fi == u32::MAX {
            PAR2_NAME.into()
        } else {
            Self::file_name(fi)
        }
    }

    /// Assemble one article: (header lines, shared body block, trailer).
    fn article(&self, fi: u32, part: u32) -> (String, Arc<Vec<u8>>, String) {
        let last = part == self.parts_per_file;
        let (len, crc, block) = if last {
            (self.tail_len, self.tail_crc, self.tail_block.clone())
        } else {
            (self.article, self.full_crc, self.full_block.clone())
        };
        let begin = (part as u64 - 1) * self.article as u64 + 1;
        let end = begin + len as u64 - 1;
        let head = format!(
            "=ybegin part={part} total={} line={LINE_LEN} size={} name={}\r\n\
             =ypart begin={begin} end={end}\r\n",
            self.parts_per_file,
            self.file_size,
            Self::file_name(fi),
        );
        let tail = format!("=yend size={len} part={part} pcrc32={crc:08x}\r\n.\r\n");
        (head, block, tail)
    }
}

/// Build a server TLS config from PEM cert-chain and private-key files.
/// The provider is named explicitly for the same reason the client's is
/// (see `nntp::connect_unbounded`): the tree links both aws-lc-rs and
/// ring, so rustls cannot pick a process default and a bare `builder()`
/// panics at runtime.
pub fn tls_config(
    cert_pem: &std::path::Path,
    key_pem: &std::path::Path,
) -> std::io::Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::pem::PemObject;
    let certs = rustls::pki_types::CertificateDer::pem_file_iter(cert_pem)
        .map_err(|e| std::io::Error::other(format!("{}: {e}", cert_pem.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| std::io::Error::other(format!("{}: {e}", cert_pem.display())))?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(key_pem)
        .map_err(|e| std::io::Error::other(format!("{}: {e}", key_pem.display())))?;
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(std::io::Error::other)?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(std::io::Error::other)?;
    Ok(Arc::new(cfg))
}

/// Serve forever on `bind`, plain TCP. Never the bottleneck: per request
/// it writes two small formatted strings and one shared Arc'd block.
pub async fn serve(bind: &str, set: Arc<BenchSet>) -> std::io::Result<()> {
    serve_with(bind, set, None).await
}

/// As [`serve`], with optional implicit TLS (the port-563 shape: the
/// handshake starts the moment the socket is accepted, no STARTTLS).
pub async fn serve_with(
    bind: &str,
    set: Arc<BenchSet>,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> std::io::Result<()> {
    // Big socket buffers: accepted sockets inherit the listener's on
    // BSD/macOS, and a ~128 KB default forces an 800 KB article into a
    // dozen buffer-full stalls per body on loopback.
    let addr: std::net::SocketAddr = bind
        .parse()
        .map_err(|e| std::io::Error::other(format!("bind {bind:?}: {e}")))?;
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    let _ = socket.set_send_buffer_size(4 << 20);
    let _ = socket.set_recv_buffer_size(1 << 20);
    let _ = socket.set_reuseaddr(true);
    socket.bind(addr)?;
    let listener: TcpListener = socket.listen(1024)?;
    info!(
        target: "benchserve",
        "NNTP on {} ({})",
        listener.local_addr()?,
        if tls.is_some() { "TLS" } else { "plain" }
    );
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    loop {
        let (sock, _) = listener.accept().await?;
        let set = set.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            sock.set_nodelay(true)?;
            match acceptor {
                // `into_split` on the plain path deliberately: it is the
                // long-standing baseline every published loopback number
                // was measured on, and `tokio::io::split`'s BiLock would
                // quietly move it.
                None => {
                    let (r, w) = sock.into_split();
                    serve_conn(r, w, set).await
                }
                Some(a) => {
                    let stream = a.accept(sock).await?;
                    let (r, w) = tokio::io::split(stream);
                    serve_conn(r, w, set).await
                }
            }
        });
    }
}

async fn serve_conn<R, W>(r: R, w: W, set: Arc<BenchSet>) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::with_capacity(4096, r);
    let mut w = tokio::io::BufWriter::with_capacity(1 << 20, w);
    w.write_all(b"200 nzbfast benchserve ready (posting prohibited)\r\n")
        .await?;
    w.flush().await?;
    loop {
        // Cap the command line: a client streaming bytes with no newline would
        // otherwise grow the buffer unbounded until OOM (this tool can be told
        // to bind 0.0.0.0). 8 KiB dwarfs any real NNTP command.
        let mut lb = Vec::new();
        let n = {
            use tokio::io::AsyncReadExt as _;
            (&mut reader).take(8192).read_until(b'\n', &mut lb).await?
        };
        if n == 0 || lb.last() != Some(&b'\n') {
            return Ok(());
        }
        let line = String::from_utf8_lossy(&lb);
        let cmd = line.trim_end();
        let upper_word = cmd
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let arg = cmd.split_whitespace().nth(1).unwrap_or("");
        match upper_word.as_str() {
            "BODY" | "ARTICLE" => match set.parse_id(arg) {
                None => w.write_all(b"430 no such article\r\n").await?,
                Some((fi, part)) => {
                    let id = arg.trim();
                    if upper_word == "BODY" {
                        w.write_all(format!("222 0 {id}\r\n").as_bytes()).await?;
                    } else {
                        // Minimal but well-formed header section.
                        w.write_all(format!("220 0 {id}\r\n").as_bytes()).await?;
                        w.write_all(
                            format!(
                                "Message-ID: {id}\r\nFrom: bench@nzbfast\r\n\
                                 Newsgroups: alt.binaries.bench\r\n\
                                 Subject: {} yEnc ({part}/{})\r\n\r\n",
                                set.name_for(fi),
                                set.parts_per_file
                            )
                            .as_bytes(),
                        )
                        .await?;
                    }
                    if fi == u32::MAX {
                        let art = set.par2_article(part);
                        w.write_all(&art).await?;
                        set.served.fetch_add(1, Ordering::Relaxed);
                        set.bytes.fetch_add(art.len() as u64, Ordering::Relaxed);
                    } else {
                        let (head, block, tail) = set.article(fi, part);
                        w.write_all(head.as_bytes()).await?;
                        w.write_all(&block).await?;
                        w.write_all(tail.as_bytes()).await?;
                        set.served.fetch_add(1, Ordering::Relaxed);
                        set.bytes.fetch_add(
                            (head.len() + block.len() + tail.len()) as u64,
                            Ordering::Relaxed,
                        );
                    }
                }
            },
            "STAT" => {
                if set.parse_id(arg).is_some() {
                    w.write_all(format!("223 0 {}\r\n", arg.trim()).as_bytes())
                        .await?;
                } else {
                    w.write_all(b"430 no such article\r\n").await?;
                }
            }
            "HEAD" => match set.parse_id(arg) {
                None => w.write_all(b"430 no such article\r\n").await?,
                Some((fi, part)) => {
                    w.write_all(
                        format!(
                            "221 0 {}\r\nMessage-ID: {}\r\nSubject: {} yEnc ({part}/{})\r\n.\r\n",
                            arg.trim(),
                            arg.trim(),
                            set.name_for(fi),
                            set.parts_per_file
                        )
                        .as_bytes(),
                    )
                    .await?;
                }
            },
            "GROUP" => {
                w.write_all(b"211 1000 1 1000 alt.binaries.bench\r\n")
                    .await?;
            }
            "MODE" => w.write_all(b"200 reader, posting prohibited\r\n").await?,
            "CAPABILITIES" => {
                w.write_all(b"101 capabilities\r\nVERSION 2\r\nREADER\r\n.\r\n")
                    .await?;
            }
            "AUTHINFO" => {
                let sub = arg.to_ascii_uppercase();
                if sub == "USER" {
                    w.write_all(b"381 password required\r\n").await?;
                } else {
                    w.write_all(b"281 welcome\r\n").await?;
                }
            }
            "DATE" => w.write_all(b"111 20260722000000\r\n").await?,
            "QUIT" => {
                w.write_all(b"205 bye\r\n").await?;
                w.flush().await?;
                return Ok(());
            }
            _ => w.write_all(b"500 command not recognized\r\n").await?,
        }
        w.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every assembled article must decode with the SHIPPING decoder to
    /// the exact bytes the NZB placement expects - the whole bench is
    /// meaningless if the synthetic articles aren't valid yEnc.
    #[test]
    fn articles_decode_with_the_real_decoder() {
        let set = BenchSet::new(2, 1_000_000, 300_000); // 4 parts, short tail
        assert_eq!(set.parts_per_file, 4);
        for part in 1..=4u32 {
            let (head, block, tail) = set.article(1, part);
            let mut art = head.into_bytes();
            art.extend_from_slice(&block);
            // Strip the NNTP terminator; the decoder sees the article only.
            let t = tail.strip_suffix(".\r\n").unwrap();
            art.extend_from_slice(t.as_bytes());
            let dec = crate::yenc::decode(&art).expect("valid yEnc");
            let expect_len = if part == 4 { 100_000 } else { 300_000 };
            assert_eq!(dec.data.len(), expect_len, "part {part}");
            assert_eq!(dec.offset(), (part as u64 - 1) * 300_000);
            assert_eq!(dec.file_size, 1_000_000);
            assert_eq!(dec.data, payload(expect_len), "payload round-trips");
        }
    }

    /// The generated PAR2 must round-trip through OUR OWN parser and
    /// verify the synthetic content all-green - otherwise a --par2 rig
    /// run would "verify" garbage and every bench conclusion with it.
    #[test]
    fn par2_index_parses_and_verifies_the_synthetic_content() {
        let files = 3u32;
        let (file_size, article) = (1_000_000u64, 300_000usize);
        let set = BenchSet::with_par2(files, file_size, article, true);
        let meta = set.par2.as_ref().expect("par2 built");
        let parsed = crate::par2::Par2Set::parse(&[&meta.blob]).expect("parses");
        assert_eq!(parsed.files.len(), files as usize);
        assert_eq!(parsed.block_size, ((article * 3 / 4) & !3) as u64);
        assert_eq!(parsed.recovery_blocks_seen, 0);

        // Materialize what the articles decode to: parts of payload().
        let mut content = Vec::with_capacity(file_size as usize);
        for p in 1..=set.parts_per_file {
            let len = if p == set.parts_per_file {
                set.tail_len
            } else {
                article
            };
            content.extend_from_slice(&payload(len));
        }
        assert_eq!(content.len() as u64, file_size);

        let names: Vec<&str> = parsed.files.iter().map(|f| f.name.as_str()).collect();
        for fi in 0..files {
            assert!(
                names.contains(&BenchSet::file_name(fi).as_str()),
                "{names:?}"
            );
        }
        for f in &parsed.files {
            assert_eq!(f.length, file_size);
            assert!(!f.blocks.is_empty(), "IFSC present");
            let v = crate::par2::verify_file(f, parsed.block_size, &content);
            assert!(v.md5_ok, "whole-file MD5");
            assert!(v.md5_16k_ok, "first-16k MD5");
            assert!(v.blocks.iter().all(|&b| b), "every block verifies");
            // And damage is caught.
            let mut bad = content.clone();
            bad[123_456] ^= 0x5A;
            let vb = crate::par2::verify_file_blocks(f, parsed.block_size, &bad);
            assert!(!vb.iter().all(|&b| b), "corruption must fail a block");
        }

        // The par2 articles themselves decode with the shipping decoder
        // and reassemble to the exact blob.
        let mut got = Vec::new();
        for part in 1..=meta.parts {
            let art = set.par2_article(part);
            let stripped = &art[..art.len() - 3]; // drop ".\r\n"
            let dec = crate::yenc::decode(stripped).expect("par2 article decodes");
            assert_eq!(dec.offset(), got.len() as u64);
            got.extend_from_slice(&dec.data);
        }
        assert_eq!(&got, meta.blob.as_ref(), "blob reassembles");

        // NZB lists the par2 file + its segments.
        let nzb = set.nzb();
        assert!(nzb.contains(PAR2_NAME));
        assert!(nzb.contains("par2-p1@bench"));
        assert_eq!(set.parse_id("<par2-p1@bench>"), Some((u32::MAX, 1)));
        assert_eq!(set.parse_id("<par2-p99@bench>"), None);
    }

    #[test]
    fn nzb_lists_every_segment_and_ids_parse() {
        let set = BenchSet::new(3, 1_000_000, 300_000);
        let nzb = set.nzb();
        assert_eq!(nzb.matches("<file ").count(), 3);
        assert_eq!(nzb.matches("<segment ").count(), 12);
        assert_eq!(set.parse_id("<f2-p4@bench>"), Some((2, 4)));
        assert_eq!(set.parse_id("f0-p1@bench"), Some((0, 1)));
        assert_eq!(set.parse_id("<f3-p1@bench>"), None, "file out of range");
        assert_eq!(set.parse_id("<f0-p5@bench>"), None, "part out of range");
    }
}
