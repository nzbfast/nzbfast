//! TODO 358 item 14 through `Connection::connect`: the bind-address
//! kill switch refusing by name with no connection made anywhere, and
//! NNTP sessions over the HTTP CONNECT tunnel against the mock server.
//! `route.rs`'s own tests cover the pure halves (the table predicate,
//! base64, the error's wrapping).

use super::route::BindAddressDown;
use super::*;
use crate::mock::{Chaos, MockServer, make_file_articles};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A listener that must never be dialled, and the check that it was not.
async fn untouched_listener() -> (tokio::net::TcpListener, u16) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

async fn assert_never_dialled(l: &tokio::net::TcpListener, why: &str) {
    let got = tokio::time::timeout(Duration::from_millis(300), l.accept()).await;
    assert!(got.is_err(), "{why}: a connection reached the listener");
}

fn expect_kill_switch(r: Result<(Connection, Status), NntpError>, addr: &str) -> String {
    let e = match r {
        Ok(_) => panic!("the dial must refuse a bind address that is not up"),
        Err(e) => e,
    };
    let d = BindAddressDown::of(&e).unwrap_or_else(|| panic!("not the named refusal: {e:?}"));
    assert_eq!(d.addr, addr.parse::<std::net::IpAddr>().unwrap());
    let msg = e.to_string();
    assert!(msg.contains("kill switch") && msg.contains(addr), "{msg}");
    msg
}

/// TEST-NET-1 (RFC 5737) is on no box. The dial refuses with the named
/// error and NOTHING reaches the target - not the bare-line fallback a
/// silent bind failure would invite, not a second address.
#[tokio::test]
async fn a_missing_v4_bind_address_refuses_and_dials_nothing() {
    let (l, port) = untouched_listener().await;
    let mut server = MockServer::start(Default::default(), Chaos::default())
        .await
        .server_config();
    server.host = "127.0.0.1".into();
    server.port = port;
    server.bind_ip = Some("192.0.2.77".into());
    expect_kill_switch(Connection::connect(&server).await, "192.0.2.77");
    assert_never_dialled(&l, "kill switch tripped").await;
}

/// The IPv6 twin, on an unassigned ULA.
#[tokio::test]
async fn a_missing_v6_bind_address_refuses_by_name() {
    let mut server = MockServer::start(Default::default(), Chaos::default())
        .await
        .server_config();
    server.host = "::1".into();
    server.bind_ip = Some("fd00:dead:beef::77".into());
    expect_kill_switch(Connection::connect(&server).await, "fd00:dead:beef::77");
}

/// The check runs BEFORE the DNS lookup: a dead tunnel must not leak the
/// provider's name to the bare line's resolver. `.invalid` never
/// resolves, so a lookup that ran first would surface as a resolve
/// error instead of the named refusal.
#[tokio::test]
async fn the_kill_switch_trips_before_any_dns_lookup() {
    let mut server = MockServer::start(Default::default(), Chaos::default())
        .await
        .server_config();
    server.host = "nntp.kill-switch.invalid".into();
    server.bind_ip = Some("192.0.2.77".into());
    expect_kill_switch(Connection::connect(&server).await, "192.0.2.77");
}

/// A proxy is dialled with the server's `bind_ip` too, so the switch
/// covers it: the proxy listener sees nothing.
#[tokio::test]
async fn the_kill_switch_also_guards_the_proxy_dial() {
    let (l, port) = untouched_listener().await;
    let mut server = MockServer::start(Default::default(), Chaos::default())
        .await
        .server_config();
    server.bind_ip = Some("192.0.2.77".into());
    server.http_proxy = Some(format!("127.0.0.1:{port}"));
    expect_kill_switch(Connection::connect(&server).await, "192.0.2.77");
    assert_never_dialled(&l, "proxy behind a tripped switch").await;
}

/// The other side: an address that IS up (loopback) dials and serves.
#[tokio::test]
async fn a_present_bind_address_dials_normally() {
    let mut articles = std::collections::HashMap::new();
    make_file_articles("k.bin", &[3u8; 900], 1_000, "ks", &mut articles);
    let id = articles.keys().next().unwrap().clone();
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut server = srv.server_config();
    server.bind_ip = Some("127.0.0.1".into());
    let (mut conn, greeting) = Connection::connect(&server).await.expect("loopback is up");
    assert!(matches!(greeting.code, 200 | 201));
    assert!(conn.body(&id).await.expect("BODY").is_some());
    conn.quit().await;
}

/// What the in-test proxy saw of one CONNECT.
#[derive(Debug)]
struct Seen {
    target: String,
    auth: Option<String>,
}

/// A minimal HTTP CONNECT proxy: reads the head, records the target and
/// any `Proxy-Authorization`, then either answers `refuse` verbatim or
/// says 200 and splices to `upstream` - WHATEVER the request named, so a
/// test can ask for an unresolvable host and prove the name was never
/// looked up locally. `want_auth` makes it demand that exact header.
async fn connect_proxy(
    upstream: std::net::SocketAddr,
    want_auth: Option<&'static str>,
) -> (u16, tokio::sync::mpsc::UnboundedReceiver<Seen>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = l.accept().await else {
                return;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if c.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let text = String::from_utf8(head).unwrap();
                let mut lines = text.split("\r\n");
                let first = lines.next().unwrap().to_string();
                let auth = lines
                    .filter_map(|l| l.split_once(": "))
                    .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
                    .map(|(_, v)| v.to_string());
                let target = first
                    .strip_prefix("CONNECT ")
                    .and_then(|r| r.strip_suffix(" HTTP/1.1"))
                    .unwrap_or("<not a CONNECT>")
                    .to_string();
                let _ = tx.send(Seen {
                    target,
                    auth: auth.clone(),
                });
                if let Some(want) = want_auth
                    && auth.as_deref() != Some(want)
                {
                    let _ = c
                        .write_all(
                            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                              Proxy-Authenticate: Basic realm=\"test\"\r\n\r\n",
                        )
                        .await;
                    return;
                }
                let mut up = tokio::net::TcpStream::connect(upstream).await.unwrap();
                // A header after the status line, so the client must
                // read to the blank line rather than stop at the first.
                c.write_all(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
            });
        }
    });
    (port, rx)
}

async fn mock_with_one_article() -> (MockServer, String) {
    let mut articles = std::collections::HashMap::new();
    make_file_articles("p.bin", &[9u8; 900], 1_000, "px", &mut articles);
    let id = articles.keys().next().unwrap().clone();
    (MockServer::start(articles, Chaos::default()).await, id)
}

/// An open proxy: the tunnel is asked for by NAME (the proxy resolves
/// it), carries no credential, and a full NNTP session runs through it.
#[tokio::test]
async fn an_nntp_session_runs_through_an_open_http_connect_proxy() {
    let (srv, id) = mock_with_one_article().await;
    let (pport, mut seen) = connect_proxy(srv.addr, None).await;
    let mut server = srv.server_config();
    server.host = "nntp.behind-the-proxy.invalid".into();
    server.http_proxy = Some(format!("127.0.0.1:{pport}"));
    let (mut conn, greeting) = Connection::connect(&server)
        .await
        .expect("connect via proxy");
    assert!(matches!(greeting.code, 200 | 201));
    let body = conn.body(&id).await.expect("BODY through the tunnel");
    assert!(!body.expect("article present").is_empty());
    conn.quit().await;
    let s = seen.recv().await.unwrap();
    assert_eq!(
        s.target,
        format!("nntp.behind-the-proxy.invalid:{}", srv.addr.port()),
        "the proxy must be handed the hostname, never a local lookup"
    );
    assert_eq!(s.auth, None, "no credential configured, none sent");
}

/// With a user and password: Basic `Proxy-Authorization` (RFC 7617's
/// own example pair), then the same session.
#[tokio::test]
async fn an_nntp_session_runs_through_an_authenticating_proxy() {
    let (srv, id) = mock_with_one_article().await;
    let (pport, mut seen) =
        connect_proxy(srv.addr, Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")).await;
    let mut server = srv.server_config();
    server.http_proxy = Some(format!("Aladdin:open sesame@127.0.0.1:{pport}"));
    let (mut conn, _) = Connection::connect(&server)
        .await
        .expect("authenticated tunnel");
    assert!(conn.body(&id).await.expect("BODY").is_some());
    conn.quit().await;
    let s = seen.recv().await.unwrap();
    assert_eq!(
        s.auth.as_deref(),
        Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
    );
}

/// A 407 is a clear sentence in both of its shapes, and neither ever
/// carries the password that was offered.
#[tokio::test]
async fn a_407_names_the_sign_in_and_never_the_password() {
    let (srv, _) = mock_with_one_article().await;
    let (pport, _seen) = connect_proxy(srv.addr, Some("Basic never-matches")).await;
    let mut server = srv.server_config();

    server.http_proxy = Some(format!("127.0.0.1:{pport}"));
    let e = Connection::connect(&server)
        .await
        .err()
        .expect("407 without creds");
    let msg = e.to_string();
    assert!(
        msg.contains("407") && msg.contains("wants a sign-in"),
        "{msg}"
    );

    server.http_proxy = Some(format!("pxu:hunter2-secret@127.0.0.1:{pport}"));
    let e = Connection::connect(&server)
        .await
        .err()
        .expect("407 with wrong creds");
    let msg = e.to_string();
    assert!(
        msg.contains("407") && msg.contains("rejected the proxy sign-in"),
        "{msg}"
    );
    assert!(
        !msg.contains("hunter2-secret") && !msg.contains("pxu"),
        "{msg}"
    );
    assert!(
        msg.contains(&format!("127.0.0.1:{pport}")),
        "names the proxy: {msg}"
    );
}

/// One proxy or none: both set is refused rather than one picked.
#[tokio::test]
async fn a_server_naming_both_proxies_is_refused() {
    let (srv, _) = mock_with_one_article().await;
    let mut server = srv.server_config();
    server.socks5 = Some("127.0.0.1:1".into());
    server.http_proxy = Some("127.0.0.1:1".into());
    let msg = Connection::connect(&server)
        .await
        .err()
        .expect("refused")
        .to_string();
    assert!(msg.contains("both a SOCKS5 and an HTTP proxy"), "{msg}");
}

/// TODO 358 sweep: the server form takes a bracketed IPv6 proxy address
/// (`[::1]:8080`, the only unambiguous way to write one with a port), so
/// both proxy dials must reach it. Before the fix the brackets went to
/// the resolver verbatim and every dial failed as an unresolvable name.
/// Only reachability is asserted: the listener accepts and hangs up, so
/// the handshake fails afterwards, which is not what is under test.
#[tokio::test]
async fn a_bracketed_ipv6_proxy_address_is_dialled() {
    let Ok(l) = tokio::net::TcpListener::bind("[::1]:0").await else {
        eprintln!("no IPv6 loopback on this box; skipping");
        return;
    };
    let pport = l.local_addr().unwrap().port();
    let (srv, _) = mock_with_one_article().await;
    for which in ["socks5", "http"] {
        let mut server = srv.server_config();
        let spec = format!("[::1]:{pport}");
        if which == "socks5" {
            server.socks5 = Some(spec);
        } else {
            server.http_proxy = Some(spec);
        }
        let dial = tokio::spawn(async move {
            let r = Connection::connect(&server).await;
            r.err().map(|e| e.to_string())
        });
        let got = tokio::time::timeout(Duration::from_secs(5), l.accept()).await;
        let reached = matches!(got, Ok(Ok(_)));
        drop(got);
        let err = dial.await.unwrap();
        assert!(
            reached,
            "{which}: the proxy at [::1] was never dialled ({err:?})"
        );
    }
}
