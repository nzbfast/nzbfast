//! Lib-level unit tests for the NNTP read ladders (coverage §122.5).
//!
//! A child module of `nntp` (the pool/unit_tests.rs pattern) so nntp.rs
//! itself stays inside its size-gate entry while the private internals
//! remain reachable through `super::*`. Two ladders live here:
//!
//! - the compressed-overview reader (`read_gzip_multiline_generic`),
//!   whose framing sniff (gzip / zlib / raw deflate), gzip header-flag
//!   walk, trailer check and three terminator shapes were reachable
//!   only through a live Highwinds-style server;
//! - the `Connection` convenience commands (HEAD / STAT / DATE /
//!   GROUP / BODY miss) against the mock, whose refusal arms no other
//!   lib test walks.

use super::*;
use crate::mock::{Chaos, MockServer, make_file_articles};
use std::io::Write as _;

/// Raw-deflate-compress `payload` (no framing byte, no trailer).
fn deflate(payload: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(payload).unwrap();
    enc.finish().unwrap()
}

/// Drive the compressed reader over an in-memory wire image.
async fn read_compressed(wire: &[u8]) -> Result<Vec<u8>, NntpError> {
    let mut r = tokio::io::BufReader::new(wire);
    let mut out = Vec::new();
    read_gzip_multiline_generic(&mut r, &mut out, None).await?;
    Ok(out)
}

#[tokio::test]
async fn zlib_framed_overview_ends_on_the_instream_terminator() {
    // 0x78 first byte = zlib framing; the dot line rides INSIDE the
    // compressed stream and is stripped from the output.
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(b"1\tsubject\r\n2\tanother\r\n.\r\n").unwrap();
    let wire = enc.finish().unwrap();
    assert_eq!(wire[0], 0x78, "zlib framing is what this test is about");
    let out = read_compressed(&wire).await.expect("clean zlib stream");
    assert_eq!(out, b"1\tsubject\r\n2\tanother\r\n");
}

#[tokio::test]
async fn raw_deflate_with_external_terminator_and_tolerated_blank_line() {
    // No framing byte at all (raw deflate), terminator as plain text on
    // the wire AFTER the compressed block - with the one tolerated
    // blank line some servers emit before the dot.
    let body = b"10\talpha\r\n11\tbeta\r\n";
    let mut wire = deflate(body);
    assert!(
        wire[0] != 0x1f && wire[0] != 0x78,
        "raw deflate must not look like gzip/zlib framing"
    );
    wire.extend_from_slice(b"\r\n.\r\n");
    let out = read_compressed(&wire).await.expect("raw deflate stream");
    assert_eq!(out, body);
}

/// Build a gzip member around `payload` with every optional header
/// field present (FEXTRA + FNAME + FCOMMENT + FHCRC), and an ISIZE
/// trailer of `isize`.
fn gzip_wire(payload: &[u8], isize: u32) -> Vec<u8> {
    let mut wire = vec![0x1f, 0x8b, 8, 4 | 8 | 16 | 2, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(&3u16.to_le_bytes()); // FEXTRA: 3 bytes
    wire.extend_from_slice(b"xtr");
    wire.extend_from_slice(b"name\0"); // FNAME
    wire.extend_from_slice(b"comment\0"); // FCOMMENT
    wire.extend_from_slice(&[0xab, 0xcd]); // FHCRC (unchecked)
    wire.extend_from_slice(&deflate(payload));
    // Real CRC32: the reader verifies it since the chip-6 fix (a zero
    // here now fails every test that uses this helper, correctly).
    wire.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
    wire.extend_from_slice(&isize.to_le_bytes());
    wire
}

#[tokio::test]
async fn gzip_with_every_header_flag_decodes_and_checks_the_trailer() {
    // Bare-LF terminator variant inside the stream, all header flags
    // walked, ISIZE verified.
    let payload = b"20\tgamma\r\n.\n";
    let wire = gzip_wire(payload, payload.len() as u32);
    let out = read_compressed(&wire).await.expect("full gzip member");
    assert_eq!(out, b"20\tgamma\r\n");
}

#[tokio::test]
async fn an_empty_overview_with_an_instream_terminator_is_valid() {
    // A range whose articles all expired answers 224 with a body that
    // is JUST the dot line. Compressed in-stream that decodes to
    // b".\r\n" - no preceding newline, so the suffix checks alone
    // rejected it and the connection was marked desynced.
    for terminator in [&b".\r\n"[..], &b".\n"[..]] {
        let wire = gzip_wire(terminator, terminator.len() as u32);
        let out = read_compressed(&wire).await.expect("empty overview");
        assert_eq!(out, b"", "terminator {terminator:?} must strip to empty");
    }
    // Same shape under zlib framing.
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(b".\r\n").unwrap();
    let wire = enc.finish().unwrap();
    let out = read_compressed(&wire).await.expect("empty zlib overview");
    assert_eq!(out, b"");
}

#[tokio::test]
async fn gzip_trailer_length_mismatch_is_an_error_not_a_short_read() {
    let payload = b"21\tdelta\r\n.\r\n";
    let wire = gzip_wire(payload, payload.len() as u32 + 7);
    let err = read_compressed(&wire).await.expect_err("wrong ISIZE");
    match err {
        NntpError::Unexpected { line, .. } => {
            assert!(line.contains("gzip length mismatch"), "got: {line}")
        }
        other => panic!("expected Unexpected, got {other:?}"),
    }
}

#[tokio::test]
async fn a_gzip_first_byte_with_a_broken_header_is_rejected() {
    // 0x1f promises gzip; the second byte breaks the promise.
    let wire = [0x1f, 0x00, 8, 0, 0, 0, 0, 0, 0, 0];
    let err = read_compressed(&wire).await.expect_err("bad gzip header");
    match err {
        NntpError::Unexpected { line, .. } => {
            assert!(line.contains("gzip header"), "got: {line}")
        }
        other => panic!("expected Unexpected, got {other:?}"),
    }
}

#[tokio::test]
async fn junk_where_the_external_terminator_should_be_is_an_error() {
    // The stream decodes but does not end in a dot line, and the wire
    // then carries a non-dot line: protocol fault, named as such.
    let mut wire = deflate(b"30\tepsilon\r\n");
    wire.extend_from_slice(b"garbage\r\n");
    let err = read_compressed(&wire).await.expect_err("junk terminator");
    assert!(matches!(err, NntpError::Unexpected { .. }));
}

#[tokio::test]
async fn two_blank_lines_and_no_terminator_is_an_error() {
    // The tolerated-blank-line search is capped at two lines: a peer
    // that never sends the dot is a protocol fault, not a hang.
    let mut wire = deflate(b"31\tzeta\r\n");
    wire.extend_from_slice(b"\r\n\r\n");
    let err = read_compressed(&wire).await.expect_err("no terminator");
    match err {
        NntpError::Unexpected { line, .. } => {
            assert!(line.contains("no terminator"), "got: {line}")
        }
        other => panic!("expected Unexpected, got {other:?}"),
    }
}

#[tokio::test]
async fn head_stat_date_group_ladders_answer_hit_and_miss() {
    // One article with a header plane; every convenience-command ladder
    // gets its hit AND its refusal against the same session.
    let mut articles = std::collections::HashMap::new();
    make_file_articles("h.bin", &[7u8; 900], 1_000, "hd", &mut articles);
    let id = articles.keys().next().unwrap().clone();
    let mut headers = std::collections::HashMap::new();
    headers.insert(
        id.clone(),
        b"Subject: ladder\r\nMessage-ID: <hd-1@mock>\r\n".to_vec(),
    );
    let srv = MockServer::start_full(articles, headers, Vec::new(), Chaos::default()).await;
    let (mut conn, _) = Connection::connect(&srv.server_config())
        .await
        .expect("connect to mock");
    // HEAD: 221 multiline on a hit, 430 None on a miss.
    let head = conn.head(&id).await.expect("HEAD hit");
    assert!(
        head.expect("headers present")
            .windows(7)
            .any(|w| w == b"Subject"),
        "the header block came through"
    );
    assert_eq!(conn.head("<absent@mock>").await.expect("HEAD miss"), None);
    // STAT: 223 true / 430 false, the preflight probe's whole alphabet.
    conn.send_stat(&id).await.expect("send STAT");
    assert!(conn.read_stat().await.expect("read STAT hit"));
    conn.send_stat("<absent@mock>").await.expect("send STAT");
    assert!(!conn.read_stat().await.expect("read STAT miss"));
    // DATE: the warm pool's liveness probe.
    assert_eq!(conn.date().await.expect("DATE").code, 111);
    // GROUP: the mock reports its default span for any name.
    let g = conn.group("mock.group").await.expect("GROUP");
    assert!(g.high >= g.low);
    // BODY convenience ladder: a 430 is a miss, not an error.
    assert_eq!(conn.body("<absent@mock>").await.expect("BODY miss"), None);
    let body = conn.body(&id).await.expect("BODY hit");
    assert!(!body.expect("article present").is_empty());
    conn.quit().await;
}

// The mods below moved verbatim from nntp.rs (6 Aug, same size-gate
// rule as above): kept as nested mods, only their `use super::...`
// lines rewritten to `use crate::nntp::...` for the new depth.
mod echoed_id_tests {
    use crate::nntp::{NntpError, Status, check_echoed_id, echoed_message_id};

    #[test]
    fn plausible_ids_only() {
        fn id(line: &str) -> Option<&[u8]> {
            echoed_message_id(line.as_bytes())
        }
        fn want(s: &str) -> Option<&[u8]> {
            Some(s.as_bytes())
        }
        // RFC shape: code, number, id, prose - for BODY (222), ARTICLE
        // (220) and an id-echoing refusal alike.
        assert_eq!(id("222 0 <a@b> body follows"), want("<a@b>"));
        assert_eq!(id("220 0 <a@b> article follows"), want("<a@b>"));
        assert_eq!(id("430 <a@b> no such article"), want("<a@b>"));
        // Providers that echo 0 or nothing: no evidence, no id.
        assert_eq!(id("222 0 0 body follows"), None);
        assert_eq!(id("430 no such article"), None);
        // A bare "<>" is not a plausible id.
        assert_eq!(id("222 0 <> body"), None);
        // Runs of whitespace (some servers pad) do not become tokens.
        assert_eq!(id("222  0   <a@b>  body"), want("<a@b>"));
    }

    #[test]
    fn mismatch_is_a_session_error_and_absence_is_not() {
        let st = |line: &str| Status::new(222, line);
        // Match (and case-insensitive match) pass.
        assert!(check_echoed_id(&st("222 0 <a@b> ok"), Some("<a@b>")).is_ok());
        assert!(check_echoed_id(&st("222 0 <A@B> ok"), Some("<a@b>")).is_ok());
        // No expected id, or no echoed id: never an error.
        assert!(check_echoed_id(&st("222 0 <a@b> ok"), None).is_ok());
        assert!(check_echoed_id(&st("222 0 0 ok"), Some("<a@b>")).is_ok());
        // A different id is the desync signal.
        let err = check_echoed_id(&st("222 0 <other@b> ok"), Some("<a@b>"))
            .expect_err("a different echoed id must error");
        assert!(matches!(err, NntpError::IdMismatch { .. }), "{err:?}");
    }
}

/// The status line stops allocating on the per-article path (R4): the
/// text rides inline when it fits and only spills to a `String` on the
/// long lines, and `from_wire` still trims and classifies exactly what
/// the old `from_utf8_lossy().trim_end().to_string()` did.
mod status_line_tests {
    use crate::nntp::{STATUS_INLINE, Status};

    /// The inline buffer is a deliberate size trade (see
    /// `STATUS_INLINE`), so pin it: a `Status` that quietly grew past
    /// this would be moving more bytes per article than the allocation
    /// it replaced.
    #[test]
    fn status_stays_small_enough_to_move() {
        // The overhead over the inline buffer is a length and a
        // discriminant-plus-padding word, so it is TWO POINTER WIDTHS
        // and not a constant 16: that literal was the 64-bit answer
        // written on a 64-bit box, and it took the `armv7-cross`
        // nightly job red from 21 Aug 2026 (6514 of 6515 passing, this
        // the only failure) where the same struct measures 96, not 104.
        assert_eq!(
            std::mem::size_of::<Status>(),
            STATUS_INLINE + 2 * std::mem::size_of::<usize>()
        );
        assert!(std::mem::size_of::<Status>() <= 128);
    }

    #[test]
    fn from_wire_trims_and_reads_the_code() {
        let st = Status::from_wire(b"222 0 <a@b> body follows\r\n");
        assert_eq!(st.code, 222);
        assert_eq!(st.line(), "222 0 <a@b> body follows");
        assert_eq!(st.line_bytes(), b"222 0 <a@b> body follows");
        // Bare LF, and trailing spaces, trim the same way.
        assert_eq!(Status::from_wire(b"223 0 <a@b>  \n").line(), "223 0 <a@b>");
        // A line with no leading three-digit number is code 0, not a
        // panic - same as the old `get(..3).parse().unwrap_or(0)`.
        assert_eq!(Status::from_wire(b"hi\r\n").code, 0);
        assert_eq!(Status::from_wire(b"\r\n").line(), "");
    }

    #[test]
    fn long_lines_spill_to_the_heap_intact() {
        let long = format!("500 {}", "x".repeat(STATUS_INLINE * 2));
        let st = Status::from_wire(format!("{long}\r\n").as_bytes());
        assert_eq!(st.code, 500);
        assert_eq!(st.line(), long);
        assert_eq!(st.clone().into_line(), long);
        // And the boundary either side of the inline capacity.
        for len in [STATUS_INLINE - 1, STATUS_INLINE, STATUS_INLINE + 1] {
            let text = "y".repeat(len);
            let st = Status::new(0, &text);
            assert_eq!(st.line(), text, "len {len}");
            assert_eq!(st.into_line(), text, "len {len}");
        }
    }

    #[test]
    fn invalid_utf8_is_repaired_once_like_the_old_lossy_path() {
        let st = Status::from_wire(b"430 caf\xe9 gone\r\n");
        assert_eq!(st.code, 430);
        assert_eq!(st.line(), "430 caf\u{fffd} gone");
        // The stored bytes are the repaired text, so the byte readers
        // never see a broken sequence.
        assert_eq!(st.line_bytes(), "430 caf\u{fffd} gone".as_bytes());
    }
}

mod date_tests {
    use crate::nntp::parse_nntp_date;

    #[test]
    fn rfc5322_variants() {
        // RFC 2822's own example date.
        assert_eq!(
            parse_nntp_date("Fri, 21 Nov 1997 09:55:06 -0600"),
            Some(880127706)
        );
        // Trailing zone comment; weekday optional; single-digit day.
        assert_eq!(
            parse_nntp_date("Fri, 21 Nov 1997 09:55:06 -0600 (CST)"),
            Some(880127706)
        );
        assert_eq!(parse_nntp_date("2 May 2024 12:34:56 GMT"), Some(1714653296));
        assert_eq!(
            parse_nntp_date("Thu, 02 May 2024 12:34:56 +0000"),
            Some(1714653296)
        );
        assert_eq!(
            parse_nntp_date("Thu, 1 Jan 2026 00:00:00 GMT"),
            Some(1767225600)
        );
        // Obsolete two-digit year; missing seconds.
        assert_eq!(parse_nntp_date("01 Jan 70 00:00 GMT"), Some(0));
        // Non-ASCII 5-BYTE zone: z[1..3] used to slice mid-char and
        // panic the OVER consumer (Usenet-controlled text). "+€x" is 5
        // bytes. Must parse (zone ignored) or reject - never panic.
        let _ = parse_nntp_date("Thu, 02 May 2024 12:34:56 +\u{20ac}x");
        // Garbage → None, never a bogus epoch.
        assert_eq!(parse_nntp_date(""), None);
        assert_eq!(parse_nntp_date("not a date"), None);
    }
}

mod quit_tests {
    use crate::mock::{Chaos, MockServer};
    use crate::nntp::Connection;
    use std::collections::HashMap;

    #[tokio::test]
    async fn quit_is_bounded_when_the_server_never_answers() {
        // Regression (the 190 GB exit-path hang): quit()'s goodbye read
        // must not wait forever on a peer that takes the QUIT silently.
        let srv = MockServer::start(
            HashMap::new(),
            Chaos {
                mute_quit: true,
                ..Default::default()
            },
        )
        .await;
        let (conn, _) = Connection::connect(&srv.server_config())
            .await
            .expect("connect");
        let t0 = std::time::Instant::now();
        conn.quit().await;
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(3),
            "quit not bounded: {:?}",
            t0.elapsed()
        );
    }

    // Paused clock: the greeting read parks on IO, tokio auto-advances to
    // the CONNECT_TIMEOUT deadline, and the test finishes in milliseconds.
    #[tokio::test(start_paused = true)]
    async fn connect_is_bounded_when_the_server_never_greets() {
        // A listener that accepts and then says nothing - connect() must
        // time out instead of waiting forever on the greeting.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let _keep = std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept() {
                held.push(s); // hold the socket open, never write
            }
        });
        let server = crate::config::ServerConfig {
            host: "127.0.0.1".into(),
            port,
            tls: false,
            username: None,
            password: None,
            connections: 1,
            pin_connections: false,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 0,
            block_bytes: None,
            block_account: false,
            bind_ip: None,
            socks5: None,
            enabled: true,
            warm_pool: false,
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
        };
        let r = Connection::connect(&server).await;
        assert!(r.is_err(), "connect to a mute server must error, got Ok");
    }

    /// Providers reject over-cap connections in the GREETING as often as
    /// at AUTHINFO. That must reach the pool as AuthFailed(Capacity) -
    /// the one-at-a-time yield path - while a non-capacity greeting
    /// refusal stays Unexpected (guessing Permanent would blacklist a
    /// server over transient wording).
    #[tokio::test]
    async fn capacity_greeting_takes_the_yield_path() {
        use crate::nntp::{AuthRefusal, NntpError};
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for greet in [
                "502 too many connections for your account\r\n",
                "502 access denied\r\n",
            ] {
                if let Ok((mut s, _)) = listener.accept() {
                    let _ = s.write_all(greet.as_bytes());
                    let _ = s.flush();
                    // Hold briefly so the client reads before FIN races it.
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        });
        let server = crate::config::ServerConfig {
            host: "127.0.0.1".into(),
            port,
            tls: false,
            username: None,
            password: None,
            connections: 1,
            pin_connections: false,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 0,
            block_bytes: None,
            block_account: false,
            bind_ip: None,
            socks5: None,
            enabled: true,
            warm_pool: false,
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
        };
        match Connection::connect(&server).await {
            Err(NntpError::AuthFailed { kind, .. }) => assert_eq!(kind, AuthRefusal::Capacity),
            Err(e) => panic!("capacity greeting must classify as AuthFailed, got {e:?}"),
            Ok(_) => panic!("capacity greeting must classify as AuthFailed, got Ok"),
        }
        match Connection::connect(&server).await {
            Err(NntpError::Unexpected { cmd, .. }) => assert_eq!(cmd, "<greeting>"),
            Err(e) => panic!("non-capacity greeting must stay Unexpected, got {e:?}"),
            Ok(_) => panic!("non-capacity greeting must stay Unexpected, got Ok"),
        }
    }

    /// A pair of connected loopback sockets with `preload` already sitting
    /// in the client's receive buffer and the server end held open and
    /// silent forever. Set up with blocking std sockets so the handshake
    /// cannot race tokio's auto-advancing paused clock; the server half is
    /// returned so the caller keeps it alive (dropping it would send FIN
    /// and turn the hang into a clean `Closed`).
    fn mute_after(preload: &[u8]) -> (tokio::net::TcpStream, std::net::TcpStream) {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");
        server.write_all(preload).expect("preload");
        server.flush().expect("flush");
        client.set_nonblocking(true).expect("nonblocking");
        (
            tokio::net::TcpStream::from_std(client).expect("from_std"),
            server,
        )
    }

    /// Regression (the index-scan hang): a peer that answers "224 overview
    /// follows", dribbles part of the body and then goes silent - process
    /// death without an RST, an LB failover, a NAT idle-timer eviction -
    /// used to park the multiline reader forever. `MAX_MULTILINE_BYTES`
    /// never bit because no more bytes ever arrived. A wedged scan worker
    /// then held its channel sender for the process lifetime and no
    /// further scan pass could ever start.
    ///
    /// Paused clock: the reader parks on IO, tokio auto-advances to the
    /// STREAM_IDLE_TIMEOUT deadline, and the test finishes in milliseconds.
    #[tokio::test(start_paused = true)]
    async fn multiline_read_is_bounded_when_the_peer_goes_mute_mid_stream() {
        let (client, _server) = mute_after(b"1\tsubject one\tposter\r\n2\tsubject t");
        let mut reader = tokio::io::BufReader::new(client);
        {
            // Pull the dribbled bytes into the BufReader first, while no
            // timer is armed: with a paused clock the runtime auto-advances
            // whenever it would otherwise block, including on IO readiness,
            // so a read racing a timer can jump the deadline before the
            // socket ever reports ready. With nothing to advance TO, this
            // await parks on IO for real and the body read below starts
            // from buffered data.
            use tokio::io::AsyncBufReadExt as _;
            let n = reader.fill_buf().await.expect("preload").len();
            assert_eq!(n, 33, "preload should be buffered whole");
        }
        let mut out = Vec::new();
        let t0 = tokio::time::Instant::now();
        let err = super::read_multiline_generic(&mut reader, &mut out)
            .await
            .expect_err("a mute peer must not read successfully");
        assert!(
            matches!(err, super::NntpError::Timeout),
            "expected Timeout, got {err:?}"
        );
        // Progress made before the silence is still accounted for, proving
        // the deadline fired on the *idle* read and not on total duration.
        assert_eq!(out, b"1\tsubject one\tposter\r\n2\tsubject t");
        assert!(
            t0.elapsed() >= super::STREAM_IDLE_TIMEOUT,
            "fired early: {:?}",
            t0.elapsed()
        );
    }

    /// A reader that hands over one chunk per `gap` of (virtual) time and
    /// parks in between - a slow-but-alive provider.
    struct Dribble {
        chunks: std::collections::VecDeque<Vec<u8>>,
        cur: Vec<u8>,
        pos: usize,
        gap: std::time::Duration,
        sleep: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    }

    impl tokio::io::AsyncBufRead for Dribble {
        fn poll_fill_buf(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<&[u8]>> {
            let me = self.get_mut();
            if me.pos >= me.cur.len() {
                if me.chunks.is_empty() {
                    return std::task::Poll::Ready(Ok(&[]));
                }
                let s = me
                    .sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(me.gap)));
                std::task::ready!(s.as_mut().poll(cx));
                me.sleep = None;
                me.cur = me.chunks.pop_front().unwrap();
                me.pos = 0;
            }
            std::task::Poll::Ready(Ok(&me.cur[me.pos..]))
        }
        fn consume(self: std::pin::Pin<&mut Self>, amt: usize) {
            self.get_mut().pos += amt;
        }
    }

    impl tokio::io::AsyncRead for Dribble {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            use tokio::io::AsyncBufRead as _;
            let n = {
                let avail = std::task::ready!(self.as_mut().poll_fill_buf(cx))?;
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                n
            };
            self.consume(n);
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// The deadline must be an IDLE one, not a total-duration one. A real
    /// header scan asks for up to 100k articles at a time and a slow link
    /// can legitimately spend many minutes streaming that body. Here the
    /// stream takes 10x STREAM_IDLE_TIMEOUT end to end but never pauses
    /// for more than a fraction of it - a total-duration bound would kill
    /// a perfectly healthy download.
    #[tokio::test(start_paused = true)]
    async fn a_slow_but_never_silent_stream_is_not_cut_off() {
        let gap = super::STREAM_IDLE_TIMEOUT / 2;
        let mut chunks: std::collections::VecDeque<Vec<u8>> = (0..20)
            .map(|i| format!("{i}\tsubject {i}\tposter\r\n").into_bytes())
            .collect();
        chunks.push_back(b".\r\n".to_vec());
        let mut reader = Dribble {
            chunks,
            cur: Vec::new(),
            pos: 0,
            gap,
            sleep: None,
        };
        let mut out = Vec::new();
        let t0 = tokio::time::Instant::now();
        super::read_multiline_generic(&mut reader, &mut out)
            .await
            .expect("a slow but live stream must complete");
        assert!(out.starts_with(b"0\tsubject 0\tposter\r\n"));
        assert!(out.ends_with(b"19\tsubject 19\tposter\r\n"));
        assert!(
            t0.elapsed() > super::STREAM_IDLE_TIMEOUT * 5,
            "test did not actually outlast the idle deadline: {:?}",
            t0.elapsed()
        );
    }

    /// The paced reader's stall bound is the parameter, not the 120 s
    /// default: a peer that goes mute mid-body trips at the caller's
    /// deadline (the adaptive fetch path runs 8 s, not 120).
    #[tokio::test(start_paused = true)]
    async fn paced_multiline_stalls_at_the_callers_bound() {
        let (client, _server) = mute_after(b"1\tsubject one\tposter\r\n2\tsubject t");
        let mut reader = tokio::io::BufReader::new(client);
        {
            use tokio::io::AsyncBufReadExt as _;
            let n = reader.fill_buf().await.expect("preload").len();
            assert_eq!(n, 33, "preload should be buffered whole");
        }
        let stall = std::time::Duration::from_secs(8);
        let mut out = Vec::new();
        let t0 = tokio::time::Instant::now();
        let err = super::read_multiline_paced(&mut reader, &mut out, stall)
            .await
            .expect_err("a mute peer must not read successfully");
        assert!(matches!(err, super::NntpError::Timeout), "got {err:?}");
        assert!(t0.elapsed() >= stall, "fired early: {:?}", t0.elapsed());
        assert!(
            t0.elapsed() < super::STREAM_IDLE_TIMEOUT,
            "the caller's bound was ignored: {:?}",
            t0.elapsed()
        );
    }

    /// The A6 contract, half one: a transfer that stays ABOVE the rate
    /// floor survives, however long it takes end to end. The stall bound
    /// alone would let it live anyway (each gap is under 8 s); the point
    /// pinned here is that the FLOOR does not kill it either - 256 B/s
    /// against a 64 B/s floor, across several full windows.
    #[tokio::test(start_paused = true)]
    async fn paced_slow_but_above_the_floor_survives() {
        let stall = std::time::Duration::from_secs(8);
        let gap = std::time::Duration::from_secs(4);
        let floor = super::RateFloor {
            window: std::time::Duration::from_secs(30),
            min_bytes: 64 * 30,
        };
        // 1 KiB every 4 s = 256 B/s, four times the floor, for over
        // three minutes - long enough to cross the window repeatedly.
        let mut chunks: std::collections::VecDeque<Vec<u8>> =
            (0..50).map(|_| vec![b'x'; 1024]).collect();
        chunks.push_back(b"\r\n.\r\n".to_vec());
        let mut reader = Dribble {
            chunks,
            cur: Vec::new(),
            pos: 0,
            gap,
            sleep: None,
        };
        let mut out = Vec::new();
        let t0 = tokio::time::Instant::now();
        super::read_multiline_paced_max(
            &mut reader,
            &mut out,
            stall,
            super::MAX_MULTILINE_BYTES,
            Some(floor),
        )
        .await
        .expect("a slow but above-floor stream must complete");
        assert_eq!(out.len(), 50 * 1024 + 2);
        assert!(
            t0.elapsed() > floor.window * 5,
            "test did not outlast the floor window: {:?}",
            t0.elapsed()
        );
    }

    /// TODO 208.2 warm-up: a LIVE stall bound is consulted during the
    /// silence, so evidence that arrives after a connection has gone
    /// quiet still reaches the wait. One 12 s gap; the bound reads 8 s
    /// when the silence starts and 20 s from 3 s in. A fixed 8 s bound
    /// kills the read at 8 s; the live one lets the body land.
    #[tokio::test(start_paused = true)]
    async fn a_live_stall_bound_read_during_the_silence_saves_the_body() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let bound_ms = std::sync::Arc::new(AtomicU64::new(8_000));
        let raise = {
            let b = bound_ms.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                b.store(20_000, Ordering::Relaxed);
            }
        };
        let mk = || Dribble {
            chunks: [vec![b'x'; 1024], b"\r\n.\r\n".to_vec()].into(),
            cur: Vec::new(),
            pos: 0,
            gap: std::time::Duration::from_secs(12),
            sleep: None,
        };
        // Fixed: the 12 s silence outlasts 8 s and the read is torn down.
        let mut out = Vec::new();
        let err = super::read_multiline_paced_max(
            &mut mk(),
            &mut out,
            std::time::Duration::from_secs(8),
            super::MAX_MULTILINE_BYTES,
            None,
        )
        .await
        .expect_err("a fixed 8 s bound must kill a 12 s silence");
        assert!(matches!(err, super::NntpError::Timeout), "got {err:?}");
        // Live: the same silence, the same 8 s at its start - and the
        // bound that has grown to 20 s by the time the 8 s would have
        // fired is the one that judges it.
        let live = {
            let b = bound_ms.clone();
            move || std::time::Duration::from_millis(b.load(Ordering::Relaxed))
        };
        let live: &(dyn Fn() -> std::time::Duration + Sync) = &live;
        let mut out = Vec::new();
        let mut reader = mk();
        let t0 = tokio::time::Instant::now();
        let (r, ()) = tokio::join!(
            super::read_multiline_paced_max(
                &mut reader,
                &mut out,
                live,
                super::MAX_MULTILINE_BYTES,
                None,
            ),
            raise
        );
        r.expect("the live bound must carry the body through the gap");
        assert_eq!(out.len(), 1024 + 2, "the whole body landed: {}", out.len());
        let took = t0.elapsed();
        assert!(
            took >= std::time::Duration::from_secs(24),
            "two 12 s gaps (one per chunk) are the floor: {took:?}"
        );
        // And a live bound that SHRINKS under a silence still fires at
        // the figure it reads, not at the one it started with.
        bound_ms.store(30_000, Ordering::Relaxed);
        let shrink = {
            let b = bound_ms.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                b.store(5_000, Ordering::Relaxed);
            }
        };
        let mut out = Vec::new();
        let mut reader = mk();
        let t0 = tokio::time::Instant::now();
        let (r, ()) = tokio::join!(
            super::read_multiline_paced_max(
                &mut reader,
                &mut out,
                live,
                super::MAX_MULTILINE_BYTES,
                None,
            ),
            shrink
        );
        assert!(matches!(r, Err(super::NntpError::Timeout)), "got {r:?}");
        let took = t0.elapsed();
        assert!(
            took < std::time::Duration::from_secs(7),
            "a bound cut to 5 s fired at {took:?}, not within a slice of 5 s"
        );
    }

    /// The A6 contract, half two: a dribble UNDER the floor is torn
    /// down even though every gap resets the idle deadline. This is the
    /// shape the floor exists for - one small chunk every 7 s survives
    /// an 8 s stall bound forever, and before the floor a unit test
    /// here pinned exactly that survival as the contract.
    #[tokio::test(start_paused = true)]
    async fn paced_dribble_under_the_floor_is_torn_down() {
        let stall = std::time::Duration::from_secs(8);
        let gap = std::time::Duration::from_secs(7);
        let floor = super::RateFloor {
            window: std::time::Duration::from_secs(30),
            min_bytes: 64 * 30,
        };
        // 8 bytes every 7 s ≈ 1 B/s, two orders under the floor, and an
        // endless supply - without the floor this read never returns.
        let mut chunks: std::collections::VecDeque<Vec<u8>> =
            (0..10_000).map(|_| vec![b'x'; 8]).collect();
        chunks.push_back(b"\r\n.\r\n".to_vec());
        let mut reader = Dribble {
            chunks,
            cur: Vec::new(),
            pos: 0,
            gap,
            sleep: None,
        };
        let mut out = Vec::new();
        let t0 = tokio::time::Instant::now();
        let err = super::read_multiline_paced_max(
            &mut reader,
            &mut out,
            stall,
            super::MAX_MULTILINE_BYTES,
            Some(floor),
        )
        .await
        .expect_err("a dribble under the floor must be torn down");
        assert!(matches!(err, super::NntpError::Timeout), "got {err:?}");
        // Torn down at the first window boundary reached by an arrival,
        // not hours later and not before the window had a fair chance.
        assert!(
            t0.elapsed() >= floor.window,
            "fired before the window elapsed: {:?}",
            t0.elapsed()
        );
        assert!(
            t0.elapsed() < floor.window * 2,
            "fired far too late: {:?}",
            t0.elapsed()
        );
    }

    /// Drive the capped reader over explicit chunk boundaries.
    async fn read_capped_split(
        chunks: Vec<Vec<u8>>,
        max: usize,
    ) -> Result<Vec<u8>, super::NntpError> {
        let mut reader = Dribble {
            chunks: chunks.into(),
            cur: Vec::new(),
            pos: 0,
            gap: std::time::Duration::from_millis(1),
            sleep: None,
        };
        let mut out = Vec::new();
        super::read_multiline_paced_max(
            &mut reader,
            &mut out,
            std::time::Duration::from_secs(8),
            max,
            None,
        )
        .await
        .map(|()| out)
    }

    /// An exact-cap body must not pass or fail by where TCP split its
    /// terminator. The provisional `.` / `.\r` at a chunk edge used to
    /// be counted as payload before the next iteration's straddle
    /// logic removed it, so a payload of exactly `max` returned
    /// TooLarge under one split and Ok under every other - the same
    /// chunking-dependence the wholly-present-terminator arm was cured
    /// of on 10 Aug.
    #[tokio::test(start_paused = true)]
    async fn an_exact_cap_body_is_immune_to_terminator_splits() {
        let max = 1024usize;
        // Payload of exactly `max` bytes, its own trailing CRLF included.
        let mut payload = vec![b'x'; max - 2];
        payload.extend_from_slice(b"\r\n");

        // Split A: [payload + "."]["\r\n"] - the bare provisional dot.
        let mut a1 = payload.clone();
        a1.push(b'.');
        let out = read_capped_split(vec![a1, b"\r\n".to_vec()], max)
            .await
            .expect("payload == max with a split `.` must succeed");
        assert_eq!(out.len(), max);

        // Split B: [payload + ".\r"]["\n"] - the two-byte provisional.
        let mut b1 = payload.clone();
        b1.extend_from_slice(b".\r");
        let out = read_capped_split(vec![b1, b"\n".to_vec()], max)
            .await
            .expect("payload == max with a split `.\\r` must succeed");
        assert_eq!(out.len(), max);

        // Control: one byte OVER the cap still fails, terminator split
        // identically - the exclusion is the provisional bytes only.
        let mut over = vec![b'x'; max - 1];
        over.extend_from_slice(b"\r\n.");
        let err = read_capped_split(vec![over, b"\r\n".to_vec()], max)
            .await
            .expect_err("payload == max + 1 must still be refused");
        assert!(matches!(err, super::NntpError::TooLarge(_)), "got {err:?}");
    }

    /// Two-phase body read, pre-byte half: a connection whose status
    /// line never arrives dies at the caller's first-byte budget - the
    /// adaptive path's seconds, not the flat timeout's 30.
    #[tokio::test]
    async fn two_phase_first_byte_budget_bounds_a_dead_connection() {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.write_all(b"200 ok\r\n");
                let _ = s.flush();
                // Swallow the BODY command and go mute, holding the
                // socket open - the dead-connection shape.
                let mut sink = [0u8; 512];
                loop {
                    match s.read(&mut sink) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            }
        });
        let server = crate::config::ServerConfig {
            host: "127.0.0.1".into(),
            port,
            tls: false,
            username: None,
            password: None,
            connections: 1,
            pin_connections: false,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 0,
            block_bytes: None,
            block_account: false,
            bind_ip: None,
            socks5: None,
            enabled: true,
            warm_pool: false,
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
        };
        let (mut conn, _) = Connection::connect(&server).await.expect("connect");
        conn.send("BODY <x@test>").await.expect("send");
        let budget = std::time::Duration::from_millis(300);
        let mut out = Vec::new();
        let t0 = std::time::Instant::now();
        let err = conn
            .read_body_into_two_phase(&mut out, None, budget, std::time::Duration::from_secs(8))
            .await
            .expect_err("a statusless connection must time out");
        assert!(matches!(err, super::NntpError::Timeout), "got {err:?}");
        assert!(t0.elapsed() >= budget, "fired early: {:?}", t0.elapsed());
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(5),
            "budget not honored: {:?}",
            t0.elapsed()
        );
    }

    /// Same silence, compressed-header path (`XFEATURE COMPRESS GZIP`):
    /// the gzip framing reads are `read_exact`/`read_until`, which park
    /// just as hard as `fill_buf` on a peer that stops mid-header.
    #[tokio::test(start_paused = true)]
    async fn gzip_multiline_read_is_bounded_when_the_peer_goes_mute() {
        let (client, _server) = mute_after(&[0x1f, 0x8b, 0x08]); // gzip header, cut short
        let mut reader = tokio::io::BufReader::new(client);
        let mut out = Vec::new();
        let err = super::read_gzip_multiline_generic(&mut reader, &mut out, None)
            .await
            .expect_err("a mute peer must not read successfully");
        assert!(
            matches!(err, super::NntpError::Timeout),
            "expected Timeout, got {err:?}"
        );
    }

    /// Differential test for the bulk multiline reader: the OLD
    /// line-at-a-time implementation is the oracle, and every buffer
    /// capacity from 1 byte up forces the terminator across every
    /// possible chunk boundary. Also asserts pipelined bytes AFTER the
    /// terminator are left unconsumed.
    #[tokio::test]
    async fn bulk_multiline_matches_line_oracle_at_every_boundary() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

        async fn oracle(wire: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let mut r = BufReader::new(wire);
            let (mut out, mut line) = (Vec::new(), Vec::new());
            loop {
                line.clear();
                let n = r.read_until(b'\n', &mut line).await.unwrap();
                assert!(n > 0, "oracle hit EOF before terminator");
                if line == b".\r\n" || line == b".\n" {
                    break;
                }
                out.extend_from_slice(&line);
            }
            let mut rest = Vec::new();
            r.read_to_end(&mut rest).await.unwrap();
            (out, rest)
        }

        let cases: &[&[u8]] = &[
            b"hello\r\nworld\r\n.\r\nNEXT",
            b".\r\nNEXT",                         // empty block
            b"..stuffed\r\n...also\r\n.\r\nNEXT", // dot-stuffing preserved raw
            b"bare\nlf lines\n.\nNEXT",           // bare-LF form
            b"mixed\r\nbare\n.\r\nNEXT",
            b"trailing dot data.\r\n.here\r\n.\r\nNEXT", // '.' mid/odd positions (stuffed-ish)
            b"a\r\n\r\n.\r\nNEXT",                       // empty line before terminator
            b"x.\r\n.y\r\n.\r\n",                        // no pipelined rest
            b"=ybegin part=1\r\n\x01\x02.\x03\r\n.\r\n220 0 <x>\r\nmore",
        ];
        for wire in cases {
            let (want_out, want_rest) = oracle(wire).await;
            for cap in 1..=16usize {
                let mut r = BufReader::with_capacity(cap, *wire);
                let mut out = Vec::new();
                super::read_multiline_generic(&mut r, &mut out)
                    .await
                    .unwrap_or_else(|e| panic!("cap {cap} on {wire:?}: {e:?}"));
                assert_eq!(out, want_out, "content, cap {cap}, wire {wire:?}");
                let mut rest = Vec::new();
                r.read_to_end(&mut rest).await.unwrap();
                assert_eq!(rest, want_rest, "unconsumed tail, cap {cap}, wire {wire:?}");
            }
        }

        // EOF before terminator errors instead of hanging.
        let mut r = BufReader::with_capacity(4, &b"no terminator here\r\n"[..]);
        let mut out = Vec::new();
        assert!(
            super::read_multiline_generic(&mut r, &mut out)
                .await
                .is_err()
        );
    }

    /// TODO 208.2 over-read: the `Arrivals` sink sees every byte the
    /// paced read takes off the wire, as it is consumed - payload,
    /// terminator and a straddled terminator alike - and nothing the
    /// read leaves for the next response. Every buffer capacity from 1
    /// to 16 walks the terminator across every chunk boundary, so all
    /// three consume sites report.
    #[tokio::test]
    async fn the_arrivals_sink_sees_exactly_the_wire_bytes_consumed() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use tokio::io::{AsyncReadExt, BufReader};
        let cases: &[(&[u8], u64)] = &[
            (b"hello\r\nworld\r\n.\r\nNEXT", 17),
            (b".\r\nNEXT", 3),
            (b"bare\nlf lines\n.\nNEXT", 16),
            (b"x.\r\n.y\r\n.\r\n", 11),
        ];
        for (wire, want) in cases {
            for cap in 1..=16usize {
                let seen = AtomicU64::new(0);
                let calls = AtomicU64::new(0);
                let sink = |n: u64| {
                    seen.fetch_add(n, Ordering::Relaxed);
                    calls.fetch_add(1, Ordering::Relaxed);
                };
                let mut r = BufReader::with_capacity(cap, *wire);
                let mut out = Vec::new();
                super::read_multiline_paced_noting(
                    &mut r,
                    &mut out,
                    std::time::Duration::from_secs(5),
                    super::MAX_MULTILINE_BYTES,
                    None,
                    Some(&sink),
                )
                .await
                .unwrap_or_else(|e| panic!("cap {cap} on {wire:?}: {e:?}"));
                let mut rest = Vec::new();
                r.read_to_end(&mut rest).await.unwrap();
                assert_eq!(
                    seen.load(Ordering::Relaxed),
                    *want,
                    "cap {cap}, wire {wire:?}: sink total"
                );
                assert_eq!(
                    seen.load(Ordering::Relaxed) + rest.len() as u64,
                    wire.len() as u64,
                    "cap {cap}, wire {wire:?}: consumed plus left over is the wire"
                );
                assert!(
                    calls.load(Ordering::Relaxed) >= (*want).div_ceil(cap as u64),
                    "cap {cap}: the sink is called per chunk, not once at the end"
                );
            }
        }
        // No sink: the same read, nothing to report to.
        let mut r = BufReader::with_capacity(3, &b"a\r\n.\r\n"[..]);
        let mut out = Vec::new();
        super::read_multiline_paced_noting(
            &mut r,
            &mut out,
            std::time::Duration::from_secs(5),
            super::MAX_MULTILINE_BYTES,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(out, b"a\r\n");
    }

    /// M32: Connection::connect rides a SOCKS5 proxy when the server
    /// carries one, sending the HOSTNAME to the proxy (ATYP=DOMAIN, no
    /// local DNS) and speaking NNTP through the tunnel afterwards.
    #[tokio::test]
    async fn connects_through_socks5_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Target: greets like an NNTP server.
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taddr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = target.accept().await.unwrap();
            s.write_all(b"200 tunnel ok\r\n").await.unwrap();
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
        });
        // Proxy: minimal SOCKS5 server side, records the requested domain.
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let paddr = proxy.local_addr().unwrap();
        let (dom_tx, dom_rx) = std::sync::mpsc::channel::<String>();
        tokio::spawn(async move {
            let (mut c, _) = proxy.accept().await.unwrap();
            let mut hello = [0u8; 2];
            c.read_exact(&mut hello).await.unwrap();
            let mut methods = vec![0u8; hello[1] as usize];
            c.read_exact(&mut methods).await.unwrap();
            c.write_all(&[0x05, 0x00]).await.unwrap(); // no-auth
            let mut head = [0u8; 5];
            c.read_exact(&mut head).await.unwrap();
            assert_eq!(
                &head[..4],
                &[0x05, 0x01, 0x00, 0x03],
                "domain CONNECT expected"
            );
            let mut dom = vec![0u8; head[4] as usize];
            c.read_exact(&mut dom).await.unwrap();
            let mut port = [0u8; 2];
            c.read_exact(&mut port).await.unwrap();
            dom_tx.send(String::from_utf8(dom).unwrap()).unwrap();
            c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut t = tokio::net::TcpStream::connect(taddr).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut c, &mut t).await;
        });
        let server = crate::config::ServerConfig {
            // Deliberately unresolvable: only the proxy sees this name.
            host: "nntp.behind-the-proxy.invalid".into(),
            port: taddr.port(),
            tls: false,
            username: None,
            password: None,
            connections: 1,
            pin_connections: false,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 0,
            block_bytes: None,
            block_account: false,
            bind_ip: None,
            socks5: Some(format!("127.0.0.1:{}", paddr.port())),
            enabled: true,
            warm_pool: false,
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
        };
        let (_conn, greeting) = Connection::connect(&server)
            .await
            .expect("connect through proxy");
        assert_eq!(greeting.code, 200);
        assert_eq!(
            dom_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            "nntp.behind-the-proxy.invalid",
            "hostname must be resolved by the proxy, not locally"
        );
    }
}

#[tokio::test]
async fn corruption_mid_deflate_stream_is_an_error_not_garbage_rows() {
    // §123 chip 6: a broken cache node hands back a gzip member whose
    // header is intact but whose deflate payload is damaged. The
    // inflater must surface an error the session can requeue on -
    // accepting whatever inflates before the damage would hand the
    // scan loop silently truncated overview rows.
    let payload = b"22\tepsilon\r\n.\r\n";
    let mut wire = gzip_wire(payload, payload.len() as u32);
    let mid = wire.len() - 12; // inside the deflate body, before the trailer
    wire[mid] ^= 0x01;
    // Any of these is a clean session-level error the caller requeues
    // on (Closed: the inflater consumed the damaged tail hunting for
    // the deflate stream's end and hit EOF). What must NOT happen is
    // Ok - rows assembled from whatever inflated before the damage.
    let err = read_compressed(&wire)
        .await
        .expect_err("corrupt deflate must not decode");
    match err {
        NntpError::Unexpected { .. } | NntpError::Io(_) | NntpError::Closed => {}
        other => panic!("expected a clean read error, got {other:?}"),
    }
}

#[tokio::test]
async fn gzip_corrupt_overview_fails_the_read_cleanly_end_to_end() {
    // Same fault through the whole stack: mock accepts XFEATURE, then
    // serves a gzip overview stream with one bit flipped mid-stream
    // (Chaos::gzip_corrupt). The OVER call must return Err - not hang
    // on the missing terminator, not return partial rows.
    let rows: Vec<crate::mock::OverRow> = (1..=5)
        .map(|n| crate::mock::OverRow {
            number: n,
            subject: format!("post {n}"),
            from: "a@b".into(),
            message_id: format!("<g{n}@x>"),
            bytes: 1000,
        })
        .collect();
    let srv = MockServer::start_full(
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        rows,
        Chaos {
            gzip_headers: true,
            gzip_corrupt: true,
            ..Default::default()
        },
    )
    .await;
    let (mut conn, _) = Connection::connect(&srv.server_config())
        .await
        .expect("connect");
    conn.group("mock.group").await.expect("group");
    assert!(conn.enable_header_gzip().await, "290 must enable");
    let res = tokio::time::timeout(std::time::Duration::from_secs(10), conn.over(1, 5)).await;
    let inner = res.expect("corrupt stream must not hang the reader");
    assert!(
        inner.is_err(),
        "a damaged compressed stream must not yield rows: {:?}",
        inner.map(|v| v.len())
    );
    // Bug sweep 2026-08-07: the failed body read can leave response
    // bytes (a TERMINATOR-variant's plain-text "." line) unread on the
    // wire, so every later status would be attributed to the WRONG
    // command - callers that keep the conn across an over() error (the
    // scan bisect, nettools probes) then silently file the previous
    // range's rows as the next range's answer. The connection must
    // refuse further commands instead, as a dead socket would.
    let again = tokio::time::timeout(std::time::Duration::from_secs(10), conn.over(1, 5))
        .await
        .expect("a desynced conn must answer immediately, not hang");
    assert!(
        matches!(again, Err(super::NntpError::Closed)),
        "a desynced conversation must refuse, got {:?}",
        again.map(|v| v.len())
    );
}

// ---------------------------------------------------------------------
// Untrusted-input parsers (coverage §122). Every field below arrives on
// an OVER row or a LIST body - poster- or provider-controlled text - and
// each guard here exists because something in that text once reached
// arithmetic or an index that could not take it.
// ---------------------------------------------------------------------

/// The Date header of every overview row. The alpha-zone table, the
/// two-digit year rule and the four range guards are all reachable from
/// a post nobody vetted, and the guards are what keep the civil-days
/// arithmetic (`era * 146097`, `days * 86400`) inside i64 - a wrapped
/// timestamp is stored as `first_posted` and then drives retention
/// masking and the oracle's age bucket.
#[test]
fn nntp_dates_take_alpha_zones_short_years_and_refuse_the_rest() {
    let utc = parse_nntp_date("Thu, 02 May 2024 12:34:56 +0000").expect("the ordinary shape");
    // A named zone is an offset like any other: same instant, spelled
    // differently. EST is -5 h, so the local clock reads five hours
    // earlier for the same moment.
    assert_eq!(
        parse_nntp_date("Thu, 02 May 2024 07:34:56 EST"),
        Some(utc),
        "EST must resolve to -5 h, not to UTC"
    );
    assert_eq!(parse_nntp_date("2 May 2024 08:34:56 EDT"), Some(utc));
    assert_eq!(parse_nntp_date("2 May 2024 06:34:56 CST"), Some(utc));
    assert_eq!(parse_nntp_date("2 May 2024 07:34:56 CDT"), Some(utc));
    assert_eq!(parse_nntp_date("2 May 2024 05:34:56 MST"), Some(utc));
    assert_eq!(parse_nntp_date("2 May 2024 06:34:56 MDT"), Some(utc));
    assert_eq!(parse_nntp_date("2 May 2024 04:34:56 PST"), Some(utc));
    assert_eq!(parse_nntp_date("2 May 2024 05:34:56 PDT"), Some(utc));
    // Unknown or absent zones are UTC, and a trailing comment is cut
    // before tokenising ever sees it.
    assert_eq!(parse_nntp_date("2 May 2024 12:34:56 UT (GMT)"), Some(utc));
    assert_eq!(parse_nntp_date("2 May 2024 12:34:56"), Some(utc));
    // Two-digit years: 70-99 are last century, everything else this one.
    let y1999 = parse_nntp_date("1 Jan 1999 00:00:00 +0000").expect("1999");
    assert_eq!(parse_nntp_date("1 Jan 99 00:00:00 +0000"), Some(y1999));
    let y2024 = parse_nntp_date("1 Jan 2024 00:00:00 +0000").expect("2024");
    assert_eq!(parse_nntp_date("1 Jan 24 00:00:00 +0000"), Some(y2024));
    // Seconds are optional; a leap second is in range.
    assert_eq!(
        parse_nntp_date("2 May 2024 12:34 +0000"),
        Some(utc - 56),
        "a missing seconds field is zero, not a rejection"
    );
    assert!(parse_nntp_date("31 Dec 2016 23:59:60 +0000").is_some());
    // And the refusals - each of these is an arithmetic hazard, not a
    // cosmetic complaint.
    for hostile in [
        "2 May 300000000000 12:34:56 +0000", // year overflows the maths
        "2 May 1969 12:34:56 +0000",         // before the epoch floor
        "32 May 2024 12:34:56 +0000",        // no such day
        "0 May 2024 12:34:56 +0000",
        "2 May 2024 99:34:56 +0000", // no such hour
        "2 May 2024 12:99:56 +0000",
        "2 May 2024 12:34:99 +0000",
        "May 2024 12:34:56 +0000", // no day before the month
        "2 Foo 2024 12:34:56 +0000",
        "not a date at all",
        "",
    ] {
        assert_eq!(
            parse_nntp_date(hostile),
            None,
            "accepted a hostile date: {hostile:?}"
        );
    }
    // A non-ascii zone used to panic the OVER consumer on a byte slice.
    assert!(parse_nntp_date("2 May 2024 12:34:56 +€x").is_some());
}

/// `LIST ACTIVE` and `LIST NEWSGROUPS` bodies. Same ingress rules as
/// GROUP: a name must be ascii, the numbers must parse, and a high-water
/// mark near 2^62 is a poisoned line (the scan cursor is a wrapping
/// `fetch_add`, so a poisoned high would walk the whole u64 space in
/// OVER requests).
#[test]
fn the_list_parsers_drop_poisoned_rows_and_empty_descriptions() {
    let raw = b"alt.bin.good 42 7 y\n\
                alt.bin.moderated 9 1 m\n\
                alt.bin.nostatus 5 1\n\
                \n\
                alt.bin.short 5\n\
                alt.bin.\xc3\xa9 9 1 y\n\
                alt.bin.nan high low y\n\
                alt.bin.poisoned 4611686018427387904 1 y\n";
    let groups = parse_list_active(raw);
    let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["alt.bin.good", "alt.bin.moderated", "alt.bin.nostatus"],
        "only well-formed ascii rows survive"
    );
    assert_eq!((groups[0].high, groups[0].low), (42, 7));
    assert_eq!(groups[1].status, 'm');
    assert_eq!(
        groups[2].status, 'y',
        "a row without a status field posts as usual"
    );

    let raw = b"alt.bin.a\tthe first group\n\
                alt.bin.b   spaced description\n\
                alt.bin.c\t?\n\
                alt.bin.d\t\n\
                \tno name at all\n";
    assert_eq!(
        parse_list_newsgroups(raw),
        vec![
            ("alt.bin.a".to_string(), "the first group".to_string()),
            ("alt.bin.b".to_string(), "spaced description".to_string()),
        ],
        "placeholder and empty descriptions carry nothing"
    );
}

// ---------------------------------------------------------------------
// Scripted servers. The mock implements the download ladder; these cover
// the command ladders it does not (LIST, CAPABILITIES, COMPRESS) and the
// SOCKS5 tunnel, neither of which any lib test could reach before.
// ---------------------------------------------------------------------

/// Greet, then answer each command line with the first canned response
/// whose (upper-cased) prefix matches, or "500" if none does. One
/// connection at a time, which is all these ladders need.
fn scripted(greeting: &'static str, script: &'static [(&'static str, &'static str)]) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        while let Ok((s, _)) = listener.accept() {
            let mut w = s.try_clone().expect("clone");
            if w.write_all(greeting.as_bytes()).is_err() {
                continue;
            }
            let mut r = BufReader::new(s);
            let mut line = String::new();
            while r.read_line(&mut line).unwrap_or(0) > 0 {
                let cmd = line.trim_end().to_ascii_uppercase();
                line.clear();
                let resp = script
                    .iter()
                    .find(|(p, _)| cmd.starts_with(p))
                    .map_or("500 unknown command\r\n", |(_, r)| *r);
                if w.write_all(resp.as_bytes()).is_err() {
                    break;
                }
            }
        }
    });
    port
}

fn at(port: u16) -> crate::config::ServerConfig {
    crate::config::ServerConfig {
        host: "127.0.0.1".into(),
        port,
        tls: false,
        username: None,
        password: None,
        connections: 1,
        pin_connections: false,
        rcvbuf: None,
        level: 0,
        group: None,
        retention_days: 0,
        block_bytes: None,
        block_account: false,
        bind_ip: None,
        socks5: None,
        enabled: true,
        warm_pool: false,
        idle_release_secs: None,
        idle_keep: None,
        max_source_ips: None,
    }
}

/// The three list-shaped commands the indexer's discovery path leans on.
/// Each is "check the code, then read the multiline body", and each has
/// a rejection arm callers rely on: LIST NEWSGROUPS is optional on most
/// binary providers, and treating its refusal as a fault would take the
/// whole discovery run down over descriptions nobody needs.
#[tokio::test]
async fn the_list_and_capabilities_ladders_answer_hit_and_miss() {
    const SCRIPT: &[(&str, &str)] = &[
        (
            "CAPABILITIES",
            "101 capability list follows\r\nVERSION 2\r\nCOMPRESS DEFLATE\r\n.\r\n",
        ),
        (
            "LIST ACTIVE",
            "215 groups follow\r\nalt.bin.a 12 3 y\r\nalt.bin.b 4 1 n\r\n.\r\n",
        ),
        ("LIST NEWSGROUPS", "503 no descriptions here\r\n"),
        ("XFEATURE COMPRESS GZIP", "290 ok\r\n"),
    ];
    let port = scripted("200 scripted ready\r\n", SCRIPT);
    let (mut conn, greeting) = Connection::connect(&at(port)).await.expect("connect");
    assert_eq!(greeting.code, 200);
    let caps = conn.capabilities().await.expect("CAPABILITIES");
    assert_eq!(caps, vec!["VERSION 2", "COMPRESS DEFLATE"]);
    assert!(
        caps_support_compress_deflate(&caps),
        "the advert callers gate COMPRESS on must read out of this list"
    );
    let groups = conn.list_active().await.expect("LIST ACTIVE");
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].name, "alt.bin.a");
    assert_eq!(groups[1].status, 'n');
    // The optional one, refused: an error the caller can read as "no
    // descriptions", never a parse of the refusal line.
    match conn.list_newsgroups().await {
        Err(NntpError::Unexpected { cmd, line }) => {
            assert_eq!(cmd, "LIST NEWSGROUPS");
            assert!(line.starts_with("503"), "{line}");
        }
        other => panic!("expected the refusal to surface, got {other:?}"),
    }
    // Header compression is a latch: the second call must not spend
    // another round trip on a server that already said yes.
    assert!(conn.enable_header_gzip().await, "290 enables");
    assert!(conn.header_gzip());
    assert!(conn.enable_header_gzip().await, "already on, no round trip");
    conn.quit().await;

    // And the same three commands on a server that refuses them all.
    const REFUSER: &[(&str, &str)] = &[];
    let port = scripted("200 refuser ready\r\n", REFUSER);
    let (mut conn, _) = Connection::connect(&at(port)).await.expect("connect");
    assert!(matches!(
        conn.capabilities().await,
        Err(NntpError::Unexpected { .. })
    ));
    assert!(matches!(
        conn.list_active().await,
        Err(NntpError::Unexpected { .. })
    ));
    assert!(
        !conn.enable_header_gzip().await,
        "a rejected XFEATURE leaves the connection in plain mode"
    );
    conn.quit().await;
}

/// R4: `send_body`/`send_stat` stopped `format!`ing a command String per
/// article and write the verb, the id and the CRLF as three pieces into
/// the buffered writer. The bytes on the wire must not have moved by a
/// byte - a pipelined peer attributes responses positionally, so a
/// mangled command is a desync, not a parse error - and the CR/LF
/// backstop must still cover the untrusted half.
#[tokio::test]
async fn the_per_article_commands_put_the_same_bytes_on_the_wire() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let (s, _) = listener.accept().expect("accept");
        let mut w = s.try_clone().expect("clone");
        w.write_all(b"200 recorder ready\r\n").expect("greet");
        let mut r = BufReader::new(s);
        let mut line = String::new();
        while r.read_line(&mut line).unwrap_or(0) > 0 {
            if tx.send(line.clone()).is_err() {
                break;
            }
            line.clear();
            if w.write_all(b"430 no such article\r\n").is_err() {
                break;
            }
        }
    });
    let (mut conn, _) = Connection::connect(&at(port)).await.expect("connect");
    conn.send_body("<a@b>").await.expect("BODY");
    conn.send_stat("<c@d>").await.expect("STAT");
    conn.flush().await.expect("flush");
    assert_eq!(rx.recv().expect("BODY line"), "BODY <a@b>\r\n");
    assert_eq!(rx.recv().expect("STAT line"), "STAT <c@d>\r\n");

    // The untrusted half still cannot smuggle a second command in, and
    // the refusal happens BEFORE anything reaches the writer.
    let err = conn
        .send_body("<a@b>\r\nQUIT")
        .await
        .expect_err("an embedded CRLF must be refused");
    assert!(matches!(err, NntpError::Unexpected { .. }), "{err:?}");
    conn.send_body("<e@f>").await.expect("BODY");
    conn.flush().await.expect("flush");
    assert_eq!(
        rx.recv().expect("third line"),
        "BODY <e@f>\r\n",
        "the refused command must not have left a partial write behind"
    );
    conn.quit().await;
}

/// A server that refuses at AUTHINFO USER rather than at PASS - the
/// shape a capacity refusal usually takes, since the account is fine and
/// the server simply will not open another session. The refusal must
/// carry its CLASSIFICATION, not just its code: a capacity refusal and a
/// wrong password share 481/502 and want opposite responses (§15e).
#[tokio::test]
async fn a_refusal_at_the_user_line_is_classified_not_just_reported() {
    const CAPPED: &[(&str, &str)] = &[(
        "AUTHINFO USER",
        "502 max number of simultaneous IP addresses reached\r\n",
    )];
    let port = scripted("200 capped ready\r\n", CAPPED);
    let mut sc = at(port);
    sc.username = Some("u".into());
    sc.password = Some("p".into());
    match Connection::connect(&sc).await {
        Err(NntpError::AuthFailed { kind, line }) => {
            assert_eq!(kind, AuthRefusal::Capacity, "{line}");
        }
        other => panic!(
            "expected a classified refusal, got {}",
            other.err().map_or("a connection", |_| "another error")
        ),
    }

    // The other side of the same door: a server that authenticates on
    // the USER line alone (281 without ever asking for a password).
    const ONE_STEP: &[(&str, &str)] =
        &[("AUTHINFO USER", "281 welcome\r\n"), ("DATE", "111 0\r\n")];
    let port = scripted("200 one-step ready\r\n", ONE_STEP);
    let mut sc = at(port);
    sc.username = Some("u".into());
    sc.password = Some("p".into());
    let (mut conn, _) = Connection::connect(&sc)
        .await
        .expect("281 at USER is a complete login");
    assert_eq!(conn.date().await.expect("DATE").code, 111);
    conn.quit().await;

    // And a permanent one, so the taxonomy's other arm is pinned here
    // too: same code, different words, opposite remedy.
    const WRONG_PW: &[(&str, &str)] = &[
        ("AUTHINFO USER", "381 password required\r\n"),
        ("AUTHINFO PASS", "481 authentication failed\r\n"),
    ];
    let port = scripted("200 strict ready\r\n", WRONG_PW);
    let mut sc = at(port);
    sc.username = Some("u".into());
    sc.password = Some("nope".into());
    match Connection::connect(&sc).await {
        Err(NntpError::AuthFailed { kind, .. }) => assert_eq!(kind, AuthRefusal::Permanent),
        other => panic!(
            "expected a permanent refusal, got {}",
            other.err().map_or("a connection", |_| "another error")
        ),
    }
}

/// Refusal lines copied VERBATIM off the wire, not paraphrased, because
/// the classification turns on a provider's exact choice of words and a
/// tidied-up version of the string is a test of nothing. Giganews's own
/// line is the reason this test exists: "maximum number of connections"
/// slipped past both "maximum connections" and "max connections", so a
/// capacity refusal read as a dead credential and the pool benched a
/// provider that was working (18 Aug 2026). The account tag in the
/// line below is redacted - only its SHAPE matters to the matcher.
#[test]
fn real_provider_refusal_lines_land_on_the_right_arm() {
    use crate::nntp::{AuthRefusal, classify_auth_refusal};
    const CAPACITY: &[&str] = &[
        "481 (remote) (aucl:gn;gnXXXXXXX) exceeded maximum number of connections per user",
        "481 max simultaneous IP addresses reached",
        "502 max number of simultaneous IP addresses reached",
        "481 Connection limit reached",
        "502 too many connections",
    ];
    for line in CAPACITY {
        assert_eq!(
            classify_auth_refusal(line),
            AuthRefusal::Capacity,
            "should be a capacity refusal: {line}"
        );
    }
    // The conservative default still has to hold: anything not
    // recognisably about capacity stays Permanent, because retrying a
    // bad credential forever is the worse failure.
    const PERMANENT: &[&str] = &[
        "481 authentication failed",
        "481 Invalid username or password",
        "502 Authentication rejected",
    ];
    for line in PERMANENT {
        assert_eq!(
            classify_auth_refusal(line),
            AuthRefusal::Permanent,
            "should stay permanent: {line}"
        );
    }

    // Same control-flow arm, different FACT. Telemetry that reads an
    // IP-limit refusal as a socket count reports an incidental number as
    // the account's connection ceiling and offers the wrong remedy
    // (Codex sweep 5, M9).
    use crate::nntp::{CapacityLimit, capacity_limit};
    assert_eq!(
        capacity_limit("481 max simultaneous IP addresses reached"),
        CapacityLimit::SourceIps
    );
    assert_eq!(
        capacity_limit("502 max number of simultaneous IP addresses reached"),
        CapacityLimit::SourceIps
    );
    assert_eq!(
        capacity_limit(
            "481 (remote) (aucl:gn;gnXXXXXXX) exceeded maximum number of connections per user"
        ),
        CapacityLimit::Connections
    );
    assert_eq!(
        capacity_limit("502 too many connections"),
        CapacityLimit::Connections
    );
}

// ---------------------------------------------------------------------
// SOCKS5 (RFC 1928 CONNECT + RFC 1929 user/pass). M32 routes ALL traffic
// through it, DNS included - the hostname goes to the proxy verbatim as
// ATYP=DOMAIN - so every arm below is on the path of a proxied download.
// ---------------------------------------------------------------------

/// A scripted proxy. It reads exactly what the client's framing says it
/// will send, records it for the assertions, and answers with the given
/// plan. `auth_reply` is only used when `method_reply` selects user/pass.
fn socks5_proxy(
    method_reply: &'static [u8],
    auth_reply: &'static [u8],
    connect_reply: &'static [u8],
) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = seen.clone();
    std::thread::spawn(move || {
        use std::io::Read;
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        let take = |s: &mut std::net::TcpStream, n: usize| -> Option<Vec<u8>> {
            let mut b = vec![0u8; n];
            s.read_exact(&mut b).ok()?;
            recorder.lock().expect("recorder").extend_from_slice(&b);
            Some(b)
        };
        let mut serve = || -> Option<()> {
            // Greeting: VER, NMETHODS, then that many method bytes.
            let head = take(&mut s, 2)?;
            take(&mut s, head[1] as usize)?;
            s.write_all(method_reply).ok()?;
            if method_reply.len() >= 2 && method_reply[1] == 0x02 {
                // RFC 1929: VER, ULEN, user, PLEN, pass.
                let h = take(&mut s, 2)?;
                take(&mut s, h[1] as usize)?;
                let p = take(&mut s, 1)?;
                take(&mut s, p[0] as usize)?;
                s.write_all(auth_reply).ok()?;
                if auth_reply.len() >= 2 && auth_reply[1] != 0x00 {
                    return None;
                }
            }
            // CONNECT: VER, CMD, RSV, ATYP, then a domain literal.
            take(&mut s, 4)?;
            let l = take(&mut s, 1)?;
            take(&mut s, l[0] as usize + 2)?;
            s.write_all(connect_reply).ok()?;
            Some(())
        };
        let _ = serve();
        // Hold the socket so the client's read never races a FIN.
        std::thread::sleep(std::time::Duration::from_millis(200));
    });
    (port, seen)
}

#[tokio::test]
async fn socks5_tunnels_the_hostname_and_survives_both_reply_shapes() {
    // No credentials: offer method 0 only, and drain an IPv4 BND.ADDR.
    let (port, seen) = socks5_proxy(
        &[0x05, 0x00],
        &[],
        &[0x05, 0, 0, 0x01, 127, 0, 0, 1, 0, 119],
    );
    let sc = at(0);
    socks5_connect(&format!("127.0.0.1:{port}"), "news.example.com", 119, &sc)
        .await
        .expect("a clean no-auth tunnel");
    let sent = seen.lock().expect("recorder").clone();
    assert_eq!(
        &sent[..3],
        &[0x05, 0x01, 0x00],
        "with no credentials the client offers method 0 only"
    );
    let domain = [&[0x03u8, 16][..], b"news.example.com"].concat();
    assert!(
        sent.windows(domain.len()).any(|w| w == domain),
        "the hostname must go out as a DOMAIN literal so the PROXY \
         resolves it - resolving here would leak the lookup: {sent:?}"
    );
    assert_eq!(
        &sent[sent.len() - 2..],
        &119u16.to_be_bytes(),
        "the port rides the request big-endian"
    );

    // Credentials, and a DOMAIN-shaped reply address to drain.
    let mut reply = vec![0x05, 0, 0, 0x03, 5];
    reply.extend_from_slice(b"proxy");
    reply.extend_from_slice(&119u16.to_be_bytes());
    let reply: &'static [u8] = Box::leak(reply.into_boxed_slice());
    let (port, seen) = socks5_proxy(&[0x05, 0x02], &[0x01, 0x00], reply);
    socks5_connect(
        &format!("user:secret@127.0.0.1:{port}"),
        "news.example.com",
        563,
        &sc,
    )
    .await
    .expect("a clean user/pass tunnel");
    let sent = seen.lock().expect("recorder").clone();
    assert_eq!(
        &sent[..4],
        &[0x05, 0x02, 0x00, 0x02],
        "with credentials the client offers user/pass beside no-auth"
    );
    assert!(
        sent.windows(6).any(|w| w == b"secret"),
        "the password reaches the proxy over the RFC 1929 sub-negotiation"
    );
}

#[tokio::test]
async fn every_socks5_refusal_is_reported_without_leaking_the_password() {
    let sc = at(0);
    // A port typo: the error reaches the log file, the logtee ring and
    // bench_history.json, so it must name the PROXY part only.
    let e = socks5_connect("user:hunter2@127.0.0.1", "news.example.com", 119, &sc)
        .await
        .expect_err("host:port is required");
    let msg = e.to_string();
    assert!(msg.contains("expected host:port"), "{msg}");
    assert!(
        !msg.contains("hunter2"),
        "a malformed spec must not persist the credential: {msg}"
    );

    // The proxy wants auth we were never given.
    let (port, _) = socks5_proxy(&[0x05, 0x02], &[], &[]);
    let e = socks5_connect(&format!("127.0.0.1:{port}"), "news.example.com", 119, &sc)
        .await
        .expect_err("no credentials to answer with");
    assert!(e.to_string().contains("wants auth"), "{e}");

    // The proxy rejects the credentials it asked for.
    let (port, _) = socks5_proxy(&[0x05, 0x02], &[0x01, 0x01], &[]);
    let e = socks5_connect(
        &format!("u:p@127.0.0.1:{port}"),
        "news.example.com",
        119,
        &sc,
    )
    .await
    .expect_err("rejected credentials");
    assert!(e.to_string().contains("auth rejected"), "{e}");

    // No method in common (0xFF).
    let (port, _) = socks5_proxy(&[0x05, 0xFF], &[], &[]);
    let e = socks5_connect(&format!("127.0.0.1:{port}"), "news.example.com", 119, &sc)
        .await
        .expect_err("no usable method");
    assert!(e.to_string().contains("no usable auth method"), "{e}");

    // The tunnel itself is refused - the code is what a user needs.
    let (port, _) = socks5_proxy(&[0x05, 0x00], &[], &[0x05, 0x05, 0, 0x01, 0, 0, 0, 0, 0, 0]);
    let e = socks5_connect(&format!("127.0.0.1:{port}"), "news.example.com", 119, &sc)
        .await
        .expect_err("refused CONNECT");
    assert!(e.to_string().contains("refused (code 5)"), "{e}");

    // A reply address type nothing can drain: fail, never guess a length.
    let (port, _) = socks5_proxy(&[0x05, 0x00], &[], &[0x05, 0x00, 0, 0x09, 0, 0, 0, 0]);
    let e = socks5_connect(&format!("127.0.0.1:{port}"), "news.example.com", 119, &sc)
        .await
        .expect_err("unknown ATYP");
    assert!(e.to_string().contains("ATYP 9 unknown"), "{e}");

    // A hostname no SOCKS5 request can carry (one length byte). The
    // proxy is live and negotiated: the refusal is about the REQUEST,
    // not about reaching the proxy.
    let (port, _) = socks5_proxy(&[0x05, 0x00], &[], &[0x05, 0x00, 0, 0x01, 0, 0, 0, 0, 0, 0]);
    let long = "a".repeat(256);
    let e = socks5_connect(&format!("127.0.0.1:{port}"), &long, 119, &sc)
        .await
        .expect_err("over-long hostname");
    assert!(e.to_string().contains("too long for socks5"), "{e}");
}

// ---------------------------------------------------------------------
// RFC 8054 COMPRESS DEFLATE. The scan path's compressed transport: raw
// deflate in both directions, each write ended with Z_SYNC_FLUSH so the
// peer can decode a command without waiting for a block boundary.
// ---------------------------------------------------------------------

/// Raw-deflate a chunk the way a compliant peer does: sync-flushed, so
/// everything written is decodable immediately.
fn sync_flush(enc: &mut flate2::Compress, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 64);
    enc.compress_vec(data, &mut out, flate2::FlushCompress::None)
        .expect("compress");
    loop {
        let cap = out.capacity();
        out.reserve(1024);
        enc.compress_vec(&[], &mut out, flate2::FlushCompress::Sync)
            .expect("sync flush");
        if out.len() < cap.max(out.capacity()) {
            break;
        }
    }
    out
}

/// The transport against an INDEPENDENT deflate peer (flate2 directly,
/// not another `DeflateTransport`), which is what makes this an interop
/// test rather than a mirror. Covers the three things RFC 8054 asks of
/// it: bytes the buffered reader slurped past the 206 are already
/// stream bytes and must seed the decoder; a write is decodable by the
/// peer as soon as it is flushed; and a response arriving in several
/// wire chunks decodes as one.
#[tokio::test]
async fn the_deflate_transport_interoperates_with_a_plain_deflate_peer() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let mut enc = flate2::Compress::new(flate2::Compression::default(), false);
    // The greeting the reader slurped with the 206 line: already
    // compressed, and the transport has to start from it.
    let leftover = sync_flush(&mut enc, b"215 rows follow\r\n");
    let mut t = DeflateTransport::new(client, leftover);
    let mut head = vec![0u8; 17];
    t.read_exact(&mut head)
        .await
        .expect("leftover seeds the decoder");
    assert_eq!(&head, b"215 rows follow\r\n");

    // A command out: the peer must be able to decode it immediately,
    // which is the whole point of the sync flush in `poll_flush`.
    t.write_all(b"LIST ACTIVE\r\n").await.expect("write");
    t.flush().await.expect("flush");
    let mut wire = vec![0u8; 4096];
    let n = peer.read(&mut wire).await.expect("peer read");
    let mut dec = flate2::Decompress::new(false);
    // `decompress_vec` only fills SPARE capacity - an unreserved Vec
    // decodes to nothing at all.
    let mut plain = Vec::with_capacity(4096);
    dec.decompress_vec(&wire[..n], &mut plain, flate2::FlushDecompress::Sync)
        .expect("the peer decodes a flushed command");
    assert_eq!(plain, b"LIST ACTIVE\r\n");

    // A response split across two wire writes decodes as one body.
    let a = sync_flush(&mut enc, b"alt.bin.a 5 1 y\r\n");
    let b = sync_flush(&mut enc, b".\r\n");
    peer.write_all(&a).await.expect("peer write");
    peer.flush().await.expect("peer flush");
    peer.write_all(&b).await.expect("peer write");
    peer.flush().await.expect("peer flush");
    let mut body = vec![0u8; 20];
    t.read_exact(&mut body).await.expect("read the split reply");
    assert_eq!(&body, b"alt.bin.a 5 1 y\r\n.\r\n");
    t.shutdown().await.expect("shutdown flushes and closes");
}

/// A corrupt compressed stream must fail the connection cleanly - the
/// caller reconnects uncompressed - never surface garbage as overview
/// rows, and never spin on an inflater that cannot progress.
#[tokio::test]
async fn a_corrupt_deflate_stream_fails_the_connection_instead_of_parsing() {
    use tokio::io::AsyncReadExt as _;
    let (client, mut peer) = tokio::io::duplex(4096);
    let mut t = DeflateTransport::new(client, Vec::new());
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        let _ = peer.write_all(&[0xff; 64]).await;
        let _ = peer.flush().await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });
    let mut out = [0u8; 64];
    let e = tokio::time::timeout(std::time::Duration::from_secs(5), t.read(&mut out))
        .await
        .expect("a damaged stream must not hang the reader")
        .expect_err("garbage must not decode");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
}

/// The negotiation around it: 206 wraps the connection for the rest of
/// its life, and anything else leaves the caller a plain error to
/// reconnect on (the half-negotiated stream is dropped, never reused).
#[tokio::test]
async fn compress_deflate_is_refused_cleanly_when_the_server_says_no() {
    const NO_COMPRESS: &[(&str, &str)] = &[("COMPRESS DEFLATE", "403 not available\r\n")];
    let port = scripted("200 plain ready\r\n", NO_COMPRESS);
    let (conn, _) = Connection::connect(&at(port)).await.expect("connect");
    match conn.enable_compression().await {
        Err(NntpError::Unexpected { cmd, line }) => {
            assert_eq!(cmd, "COMPRESS DEFLATE");
            assert!(line.starts_with("403"), "{line}");
        }
        other => panic!(
            "expected the refusal, got {}",
            other.map(|_| "a wrapped conn").unwrap_or("an error")
        ),
    }
}
