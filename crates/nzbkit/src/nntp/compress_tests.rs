//! Compression-negotiation and read-path tests, moved whole out of
//! nntp.rs (the `unit_tests` child-module pattern) so the file stays
//! inside its size-gate entry. `super::*` keeps the private internals
//! reachable exactly as the inline module had them.

use super::{Connection, caps_support_compress_deflate};

#[test]
fn list_active_parses_and_skips_junk() {
    let raw = b"alt.binaries.teevee 9000 100 y\n\
                rec.autos.sport.f1 555 12 m\n\
                broken-line\n\
                bad.numbers x y z\n\
                huge.high 4611686018427387904 1 y\n\
                no.status 50 10\n";
    let g = super::parse_list_active(raw);
    assert_eq!(g.len(), 3);
    assert_eq!(g[0].name, "alt.binaries.teevee");
    assert_eq!((g[0].high, g[0].low, g[0].status), (9000, 100, 'y'));
    assert_eq!(g[1].status, 'm');
    assert_eq!((g[2].name.as_str(), g[2].status), ("no.status", 'y'));
}

#[test]
fn list_newsgroups_parses_tab_and_space_and_drops_placeholders() {
    let raw = b"rec.autos.sport.f1\tFormula 1 motor racing.\n\
                alt.binaries.sounds.mp3 Music binaries.\n\
                alt.empty.desc\t?\n\
                alt.no.desc\n";
    let d = super::parse_list_newsgroups(raw);
    assert_eq!(d.len(), 2);
    assert_eq!(
        d[0],
        (
            "rec.autos.sport.f1".into(),
            "Formula 1 motor racing.".into()
        )
    );
    assert_eq!(d[1].1, "Music binaries.");
}

fn caps(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|s| s.to_string()).collect()
}

#[test]
fn detects_compress_deflate_capability() {
    assert!(caps_support_compress_deflate(&caps(&[
        "VERSION 2",
        "COMPRESS DEFLATE"
    ])));
    // Case-insensitive; DEFLATE may be one of several algorithms.
    assert!(caps_support_compress_deflate(&caps(&[
        "compress shrink deflate"
    ])));
    assert!(!caps_support_compress_deflate(&caps(&[
        "VERSION 2",
        "OVER"
    ])));
    assert!(!caps_support_compress_deflate(&caps(&["COMPRESS SHRINK"])));
    // Label must be exactly COMPRESS, not merely contain it.
    assert!(!caps_support_compress_deflate(&caps(&[
        "XCOMPRESS DEFLATE"
    ])));
    assert!(!caps_support_compress_deflate(&[]));
}

fn test_server_config(port: u16) -> crate::config::ServerConfig {
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

/// Read one CRLF line a byte at a time - deliberately unbuffered so
/// the plain→compressed switch can't strand bytes in a reader.
fn read_line<R: std::io::Read>(r: &mut R) -> std::io::Result<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = r.read(&mut b)?;
        if n == 0 || b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    while line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Minimal RFC 8054 server: plain greeting/CAPABILITIES, then after
/// COMPRESS DEFLATE → 206 both directions become raw deflate.
/// `rows` controls the size of each OVER block so tests can push the
/// adapter past its internal 16 KiB staging buffers.
fn spawn_deflate_server(rows: u64, refuse_compress: bool) -> u16 {
    fn handle(
        mut sock: std::net::TcpStream,
        rows: u64,
        refuse_compress: bool,
    ) -> std::io::Result<()> {
        use std::io::Write;
        sock.write_all(b"200 deflate test server\r\n")?;
        loop {
            match read_line(&mut sock)?.as_str() {
                "CAPABILITIES" => {
                    sock.write_all(b"101 caps\r\nVERSION 2\r\nCOMPRESS DEFLATE\r\n.\r\n")?
                }
                "COMPRESS DEFLATE" => {
                    if refuse_compress {
                        sock.write_all(b"502 compression not available\r\n")?;
                        continue;
                    }
                    sock.write_all(b"206 compression active\r\n")?;
                    break;
                }
                "QUIT" => return sock.write_all(b"205 bye\r\n"),
                "" => return Ok(()), // client hung up
                _ => sock.write_all(b"500 what\r\n")?,
            }
        }
        // Compressed phase. flate2's blocking wrappers do the
        // server-side framing: DeflateEncoder::flush is a sync
        // flush, matching what the client adapter expects.
        // The decoder MUST sit under a BufReader: miniz consumes a
        // whole input frame eagerly and parks decoded bytes in its
        // window, and flate2's read::DeflateDecoder blocks for MORE
        // wire input before draining that window when handed tiny
        // dst buffers - so read_line's 1-byte reads yield one byte
        // and then deadlock on a socket that stays open. Reading
        // through BufReader makes each decoder call an 8 KiB read,
        // which drains whole lines per frame. (Found the hard way -
        // this exact line was the round-trip "deadlock".)
        let mut rd = std::io::BufReader::new(flate2::read::DeflateDecoder::new(sock.try_clone()?));
        let mut wr = flate2::write::DeflateEncoder::new(sock, flate2::Compression::default());
        loop {
            let cmd = read_line(&mut rd)?;
            if cmd.starts_with("GROUP ") {
                write!(wr, "211 {rows} 1 {rows} mock.group\r\n")?;
            } else if cmd.starts_with("OVER ") || cmd.starts_with("XOVER ") {
                wr.write_all(b"224 overview follows\r\n")?;
                for n in 1..=rows {
                    write!(
                        wr,
                        "{n}\tpost {n} with a subject long enough to be worth \
                         compressing\ta@b\tThu, 02 May 2024 12:34:56 +0000\t\
                         <m{n}@x>\t\t1000\t10\r\n"
                    )?;
                }
                wr.write_all(b".\r\n")?;
            } else if cmd == "QUIT" || cmd.is_empty() {
                let _ = wr.write_all(b"205 bye\r\n");
                let _ = wr.flush();
                return Ok(());
            } else {
                wr.write_all(b"500 what\r\n")?;
            }
            wr.flush()?;
        }
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        // Sequential accepts: the refusal test reconnects after the
        // failed COMPRESS exchange drops the first connection.
        for sock in listener.incoming() {
            let Ok(sock) = sock else { return };
            let _ = handle(sock, rows, refuse_compress);
        }
    });
    port
}

/// Adapter-only round trip over an in-memory duplex: no mock TCP
/// server, no flate2 blocking codecs on the far side - the test
/// itself decompresses what the adapter wrote and hand-compresses
/// the response. Isolates DeflateTransport correctness from the
/// mock-server plumbing when hunting the round-trip deadlock.
#[tokio::test]
async fn deflate_transport_duplex_isolated() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client_end, mut wire_end) = tokio::io::duplex(64 * 1024);
    let boxed: Box<dyn super::Transport> = Box::new(client_end);
    let wrapped: Box<dyn super::Transport> =
        Box::new(super::DeflateTransport::new(boxed, Vec::new()));
    let (mut r, mut w) = tokio::io::split(wrapped);

    // Client → wire: write a command + flush, then read the raw
    // compressed bytes off the far end and inflate them by hand.
    w.write_all(b"GROUP mock.group\r\n").await.unwrap();
    w.flush().await.unwrap();
    let mut raw = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), wire_end.read(&mut raw))
        .await
        .expect("adapter never wrote to the wire after flush")
        .unwrap();
    assert!(n > 0, "flush wrote nothing");
    let mut dec = flate2::Decompress::new(false);
    let mut out = Vec::with_capacity(1024);
    dec.decompress_vec(&raw[..n], &mut out, flate2::FlushDecompress::None)
        .expect("client frame inflates");
    assert_eq!(&out, b"GROUP mock.group\r\n", "sync-flushed frame decodes");

    // Wire → client: hand-compress a response with a sync flush and
    // read it back through the adapter.
    let mut enc = flate2::Compress::new(flate2::Compression::default(), false);
    let mut frame = Vec::with_capacity(1024);
    enc.compress_vec(
        b"211 5 1 5 mock.group\r\n",
        &mut frame,
        flate2::FlushCompress::Sync,
    )
    .unwrap();
    wire_end.write_all(&frame).await.unwrap();
    let mut got = vec![0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), r.read(&mut got))
        .await
        .expect("adapter never yielded decompressed bytes")
        .unwrap();
    assert_eq!(&got[..n], b"211 5 1 5 mock.group\r\n");
}

// (The 24 Jul "deadlock" here was the MOCK SERVER's read pattern -
// 1-byte reads through a raw read::DeflateDecoder block for wire
// input while decoded bytes sit in miniz's window; see the BufReader
// note in spawn_deflate_server. The shipping adapter was never at
// fault - deflate_transport_duplex_isolated pins that directly.)
#[tokio::test]
async fn deflate_round_trip_group_and_over() {
    // 2000 rows ≈ 250 KB of overview text - well past the adapter's
    // 16 KiB staging buffers, so the chunked-decompress path runs.
    let port = spawn_deflate_server(2000, false);
    let cfg = test_server_config(port);
    let (mut conn, _) = Connection::connect(&cfg).await.expect("connect");
    let caps = conn.capabilities().await.expect("capabilities");
    assert!(caps_support_compress_deflate(&caps));
    let mut conn = conn.enable_compression().await.expect("206 + wrap");
    let g = conn.group("mock.group").await.expect("group over deflate");
    assert_eq!(g.high, 2000);
    let es = conn.over(1, 2000).await.expect("over over deflate");
    assert_eq!(es.len(), 2000);
    assert_eq!(es[0].message_id, "<m1@x>");
    assert_eq!(es[1999].number, 2000);
    // A second command proves stream continuity across sync-flush
    // boundaries - RFC 8054 is one continuous deflate stream, not
    // per-response streams.
    let es = conn.over(1, 2000).await.expect("second over");
    assert_eq!(es.len(), 2000);
    conn.quit().await;
}

/// A removed article answered with Giganews's nonstandard 451 is a
/// MISS, not a protocol error. `read_stat` has always known that; the
/// BODY path did not, and there it costs far more: a protocol error
/// drops the session and charges the session-backoff ladder, so a
/// takedown (hundreds of adjacent articles) retired every worker on
/// the server against the give-up ceiling and failed the whole job
/// instead of just the removed file.
#[tokio::test]
async fn a_451_takedown_on_body_is_a_miss_not_a_protocol_error() {
    fn spawn_451_server() -> u16 {
        use std::io::Write;
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((mut sock, _)) = l.accept() else {
                return;
            };
            let _ = sock.write_all(b"200 takedown test server\r\n");
            loop {
                let Ok(line) = read_line(&mut sock) else {
                    return;
                };
                if line.is_empty() {
                    return;
                }
                if line == "QUIT" {
                    let _ = sock.write_all(b"205 bye\r\n");
                    return;
                }
                if line.starts_with("BODY ") {
                    let _ = sock.write_all(b"451 0 <gone@example>\r\n");
                } else {
                    let _ = sock.write_all(b"500 what\r\n");
                }
            }
        });
        port
    }

    let cfg = test_server_config(spawn_451_server());
    let (mut conn, _) = Connection::connect(&cfg).await.expect("connect");
    conn.send_body("<gone@example>").await.expect("send BODY");
    let mut raw = Vec::new();
    // Expected id supplied: the 451 echoes the SAME id, so the
    // echoed-id check must stay quiet and the miss must stand.
    let id_echoed = std::sync::atomic::AtomicBool::new(false);
    let takedown = std::sync::atomic::AtomicBool::new(false);
    let got = conn
        .read_body_into(
            &mut raw,
            Some("<gone@example>"),
            None,
            &id_echoed,
            &takedown,
        )
        .await;
    assert!(
        matches!(got, Ok(false)),
        "451 must read as a missing article, got {got:?}"
    );
    assert!(
        id_echoed.load(std::sync::atomic::Ordering::Acquire),
        "an id-echoing refusal must report a confirmed echo"
    );
    assert!(
        takedown.load(std::sync::atomic::Ordering::Acquire),
        "a 451 is a removed article and must carry the takedown hint"
    );
    assert!(raw.is_empty(), "a miss must append no body bytes");
    // The session survives: that is the whole point, since dropping it
    // is what charged the backoff ladder.
    conn.send_body("<gone2@example>")
        .await
        .expect("reuse session");
    let mut raw2 = Vec::new();
    // This rigged server echoes <gone@example> whatever was asked;
    // the serial caller passes None, so no enforcement applies.
    let id_echoed2 = std::sync::atomic::AtomicBool::new(false);
    let takedown2 = std::sync::atomic::AtomicBool::new(false);
    assert!(matches!(
        conn.read_body_into(&mut raw2, None, None, &id_echoed2, &takedown2)
            .await,
        Ok(false)
    ));
    conn.quit().await;
}

/// The takedown classifier over real-world refusal shapes: the code
/// 451 arm (Giganews's documented DMCA answer) fires on the code
/// alone, the text arm catches refusals that name a removal, and
/// the everyday "no such article" stays a plain miss. Non-refusal
/// codes are never classified whatever their text says.
#[test]
fn takedown_flavour_is_read_off_the_refusal_line() {
    use super::takedown_flavoured;
    // Giganews / Supernews: "451 0 <msgid>", text optional.
    assert!(takedown_flavoured(451, b"451 0 <a@x>"));
    assert!(takedown_flavoured(451, b"451 DMCA Removed <a@x>"));
    // Refusal text naming the removal, on the generic codes.
    assert!(takedown_flavoured(430, b"430 Article removed due to DMCA"));
    assert!(takedown_flavoured(430, b"430 <a@x> DMCA takedown"));
    assert!(takedown_flavoured(430, b"430 article was taken down"));
    assert!(takedown_flavoured(423, b"423 removed"));
    // The everyday refusals stay plain misses.
    assert!(!takedown_flavoured(430, b"430 no such article"));
    assert!(!takedown_flavoured(430, b"430 No Such Article Here <a@x>"));
    assert!(!takedown_flavoured(
        423,
        b"423 no such article number in this group"
    ));
    assert!(!takedown_flavoured(430, b"430 DBLD not found"));
    // Non-refusal codes carry no takedown meaning.
    assert!(!takedown_flavoured(223, b"223 0 <a@x> removed"));
    assert!(!takedown_flavoured(222, b"222 0 <a@x> dmca"));
}

/// §129 3g: `id_echoed` reports the echo on a HIT too, not only on a
/// refusal. The pool needs it there: a response whose id it could
/// check is proof the socket was still aligned at that point, which
/// is what bounds the window of bare refusals a later desync can
/// discredit. Reporting it only on misses left a bare-refusing
/// provider with no alignment proof at all between its refusals.
#[tokio::test]
async fn a_hit_reports_its_echoed_id_as_well_as_a_miss() {
    fn spawn_echoing_body_server() -> u16 {
        use std::io::Write;
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((mut sock, _)) = l.accept() else {
                return;
            };
            let _ = sock.write_all(b"200 echo test server\r\n");
            loop {
                let Ok(line) = read_line(&mut sock) else {
                    return;
                };
                if line.is_empty() || line == "QUIT" {
                    let _ = sock.write_all(b"205 bye\r\n");
                    return;
                }
                if line.starts_with("BODY ") {
                    let _ = sock.write_all(b"222 0 <a@example> body\r\nhello\r\n.\r\n");
                } else {
                    let _ = sock.write_all(b"500 what\r\n");
                }
            }
        });
        port
    }

    let cfg = test_server_config(spawn_echoing_body_server());
    let (mut conn, _) = Connection::connect(&cfg).await.expect("connect");
    conn.send_body("<a@example>").await.expect("send BODY");
    let mut raw = Vec::new();
    let id_echoed = std::sync::atomic::AtomicBool::new(false);
    let takedown = std::sync::atomic::AtomicBool::new(false);
    let got = conn
        .read_body_into(&mut raw, Some("<a@example>"), None, &id_echoed, &takedown)
        .await;
    assert!(matches!(got, Ok(true)), "222 must read as a hit: {got:?}");
    assert!(
        id_echoed.load(std::sync::atomic::Ordering::Acquire),
        "a hit that echoed the id we asked for is the pool's proof \
         that this session was reading the right slot"
    );
    conn.quit().await;
}

/// §129 3g: the alignment fence reads a slot, and what may live in
/// that slot is the whole point. A server's own answer to DATE - or
/// its refusal to implement it - means the stream is where we think
/// it is; a BODY's answer means a response went missing upstream and
/// everything since has been one slot early.
#[tokio::test]
async fn the_fence_accepts_any_answer_that_is_not_a_bodys() {
    fn spawn_fence_server(reply: &'static str) -> u16 {
        use std::io::Write;
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((mut sock, _)) = l.accept() else {
                return;
            };
            let _ = sock.write_all(b"200 fence test server\r\n");
            loop {
                let Ok(line) = read_line(&mut sock) else {
                    return;
                };
                if line.is_empty() || line == "QUIT" {
                    let _ = sock.write_all(b"205 bye\r\n");
                    return;
                }
                let _ = sock.write_all(reply.as_bytes());
            }
        });
        port
    }

    // The ordinary answer, and the answer of a server that has never
    // heard of DATE. Both say the same thing: this slot is the
    // fence's, so the response before it was the body's.
    for reply in ["111 20260719000000\r\n", "500 unknown command\r\n"] {
        let cfg = test_server_config(spawn_fence_server(reply));
        let (mut conn, _) = Connection::connect(&cfg).await.expect("connect");
        conn.send_fence().await.expect("send DATE");
        conn.flush().await.expect("flush");
        assert!(
            conn.read_fence().await.is_ok(),
            "{reply:?} is the fence's own answer, not a body's"
        );
        conn.quit().await;
    }

    // And the shapes that mean a response was dropped upstream: a
    // body's answer arriving where the fence's belongs.
    for reply in [
        "222 0 <a@example> body\r\n",
        "430 no such article\r\n",
        "451 0 <gone@example>\r\n",
    ] {
        let cfg = test_server_config(spawn_fence_server(reply));
        let (mut conn, _) = Connection::connect(&cfg).await.expect("connect");
        conn.send_fence().await.expect("send DATE");
        conn.flush().await.expect("flush");
        assert!(
            matches!(
                conn.read_fence().await,
                Err(super::NntpError::Unexpected { .. })
            ),
            "{reply:?} in the fence's slot means the stream is off by one"
        );
        conn.quit().await;
    }
}

#[tokio::test]
async fn refused_compress_errors_and_a_plain_reconnect_works() {
    // A server that advertises COMPRESS but refuses the exchange:
    // enable_compression must fail cleanly (connection consumed),
    // and a fresh uncompressed connection must still work - the
    // provider-tolerance contract the scan path relies on.
    let port = spawn_deflate_server(5, true);
    let cfg = test_server_config(port);
    let (conn, _) = Connection::connect(&cfg).await.expect("connect");
    let err = conn
        .enable_compression()
        .await
        .err()
        .expect("502 must error");
    assert!(
        matches!(err, super::NntpError::Unexpected { .. }),
        "{err:?}"
    );
    let (conn2, _) = Connection::connect(&cfg).await.expect("plain reconnect");
    conn2.quit().await;
}
