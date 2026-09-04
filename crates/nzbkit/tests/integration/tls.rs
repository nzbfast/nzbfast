//! The TLS receive path, end to end against a real handshake.
//!
//! Every provider is on port 563 and every downloaded byte crosses this
//! code, and until this file existed none of it had a single test: the
//! unit tests reach `tls_provider` but stop short of the handshake, and
//! the mock server the daemon suite drives is plain TCP. What is
//! covered here is the whole ladder in `Connection::connect` - trust
//! anchors, the pinned single-suite offer, the handshake, and a body
//! read over the encrypted stream.
//!
//! On Linux with `--features ktls` and `NZBFAST_KTLS=1` this same test
//! covers the kernel-TLS rung instead, including the handoff of
//! whatever plaintext rustls had already decrypted (the greeting is
//! nearly always in that flight).
//!
//! It brings its own CA, which is process-wide state: see
//! `crate::tls_env`, whose guard is what keeps this module and
//! `tls_chaos` from being each other's trust anchors. This file was its
//! own test binary until 23 Aug 2026 for exactly that reason, and the
//! reason turned out to be a defect in the client rather than a fact
//! about tests - `tls_client_config` latched the anchors of whoever
//! built the first config, so a second CA in the same process was
//! silently ignored. The cache is keyed by the CA path now.

use crate::scratch;
use crate::tls_env;

use std::sync::Arc;

use nzbkit::benchserve::BenchSet;
use nzbkit::config::ServerConfig;
use nzbkit::nntp::Connection;

/// A CA and a leaf signed by it, PEM, written to `dir`.
///
/// Not one self-signed certificate: webpki refuses a CA:TRUE
/// certificate presented as an end entity (`CaUsedAsEndEntity`) even
/// though `openssl s_client` accepts it, which has cost this project a
/// bench rig once already.
fn cert_chain(
    dir: &std::path::Path,
    san: &str,
) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "nzbkit test ca");
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let mut leaf_params =
        rcgen::CertificateParams::new(vec![san.to_string()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, san);
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf cert");

    let ca_pem = dir.join(format!("ca-{san}.pem"));
    let cert_pem = dir.join(format!("leaf-{san}.pem"));
    let key_pem = dir.join(format!("leaf-{san}.key"));
    std::fs::write(&ca_pem, ca_cert.pem()).expect("write ca");
    std::fs::write(&cert_pem, leaf_cert.pem()).expect("write cert");
    std::fs::write(&key_pem, leaf_key.serialize_pem()).expect("write key");
    (cert_pem, key_pem, ca_pem.to_string_lossy().into_owned())
}

/// A port nothing is listening on. Racy in principle, like every other
/// version of this in the tree; the window is one bind.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("probe addr")
        .port()
}

#[tokio::test]
async fn downloads_a_body_over_tls() {
    let dir = std::env::temp_dir().join(format!("nzbkit-tls-test-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (cert, key, ca) = cert_chain(&dir, "localhost");

    // Ours for the rest of the test. The guard serialises this module
    // against `tls_chaos`, which brings a CA of its own.
    let _ca = tls_env::extra_ca(std::path::Path::new(&ca));

    let port = free_port();
    let set = Arc::new(BenchSet::new(1, 2 << 20, 128 << 10));
    let nzb = set.nzb();
    let tls = nzbkit::benchserve::tls_config(&cert, &key).expect("server tls config");
    let bind = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let _ = nzbkit::benchserve::serve_with(&bind, set, Some(tls)).await;
    });

    // The message-id of the set's first article, straight out of the
    // NZB the server generated.
    let parsed = nzbkit::nzb::Nzb::parse(nzb.as_bytes()).expect("parse nzb");
    let id = parsed.files[0].segments[0].message_id.clone();

    // "localhost", not 127.0.0.1: the certificate carries a DNS SAN, and
    // the point of the test is that verification really happens.
    let server = ServerConfig {
        host: "localhost".into(),
        port,
        tls: true,
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
        address_family: Default::default(),
        tls_hostname: None,
        warm_reserve: None,
    };
    // The listener may not be up on the first tick.
    let mut conn = None;
    for _ in 0..50 {
        match Connection::connect(&server).await {
            Ok((c, _)) => {
                conn = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    let mut conn = conn.expect("connect over TLS");

    let body = conn
        .body(&id)
        .await
        .expect("BODY over TLS")
        .expect("article present");
    // A yEnc article: header, payload, trailer. Decoding it proves the
    // bytes crossed the encrypted transport intact, not merely that a
    // handshake happened.
    let decoded = nzbkit::yenc::decode(&body).expect("yenc decode");
    assert_eq!(
        decoded.data.len(),
        128 << 10,
        "one article's worth of payload"
    );
}

/// A TLS listener that records the SNI of every ClientHello it sees and
/// then answers an NNTP greeting.
///
/// It reads the name out of the ClientHello through
/// `LazyConfigAcceptor` rather than off a finished session, and that is
/// deliberate: the interesting case below is a handshake the CLIENT
/// refuses, so a reader that only sees completed sessions would have
/// nothing to report for exactly the connection under test.
///
/// Returns the port and the shared log of what each accept announced.
async fn sni_recording_server(
    tls: std::sync::Arc<rustls::ServerConfig>,
) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>) {
    use tokio::io::AsyncWriteExt as _;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind spy");
    let port = listener.local_addr().expect("spy addr").port();
    let seen: std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>> = Default::default();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let tls = tls.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let start = match tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    tcp,
                )
                .await
                {
                    Ok(s) => s,
                    Err(_) => return,
                };
                log.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(start.client_hello().server_name().map(str::to_string));
                if let Ok(mut stream) = start.into_stream(tls).await {
                    let _ = stream.write_all(b"200 nzbkit test server ready\r\n").await;
                    let _ = stream.flush().await;
                    // Hold the session open: the client is about to hang
                    // up on its own, and closing first would race the
                    // greeting it is still reading.
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            });
        }
    });
    (port, seen)
}

/// §291 / issue #60, box 2: `tls_hostname` decides the name the TLS
/// handshake CHECKS THE CERTIFICATE AGAINST and the name it ANNOUNCES
/// as SNI - and this asserts both at the handshake itself, not at the
/// config struct.
///
/// That distinction is the whole reason this test is shaped like this.
/// The sibling box shipped `the_preference_keeps_the_other_family_as_a_
/// fallback`, which passed throughout a day in which the invariant it is
/// named for was broken, because it asserted the candidate LIST while
/// the defect was in the walked WINDOW (fixed in `db2523936`). A test
/// named for an invariant, passing, over a broken invariant is worse
/// than no test: it is what stops the next person looking. So nothing
/// here inspects a `ServerConfig`. The certificate is valid for ONE name
/// and that name is not the address dialled, so only a handshake that
/// really used the override can complete - and the server reports the
/// SNI it really received.
///
/// The two halves must not be able to disagree, which is why they are
/// asserted together against one connection: a session verified against
/// one name while announcing another fails on precisely the
/// virtual-host and reverse-proxy deployments this field exists for,
/// because those pick their certificate BY the SNI.
///
/// The negative control comes first, so "the override is what did it"
/// is measured rather than assumed - and it doubles as the composition
/// pin. The dial goes to a LITERAL either way: `tls_hostname` moves the
/// name, never the destination, so it cannot fight `bind_ip` or
/// `address_family`, which decide the destination and nothing else.
#[tokio::test]
async fn the_tls_name_override_is_what_the_handshake_verifies_and_announces() {
    let dir = std::env::temp_dir().join(format!("nzbkit-tlsname-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    // Valid for this name and nothing else - no `localhost`, no IP SAN.
    const CERT_NAME: &str = "news.override.example";
    let (cert, key, ca) = cert_chain(&dir, CERT_NAME);
    let _ca = tls_env::extra_ca(std::path::Path::new(&ca));

    let tls = nzbkit::benchserve::tls_config(&cert, &key).expect("server tls config");
    let (port, seen) = sni_recording_server(tls).await;

    let server = |tls_hostname: Option<&str>| ServerConfig {
        // A literal, which is the shape that has no certificate of its
        // own: provider and self-hosted certs carry no IP SAN.
        host: "127.0.0.1".into(),
        port,
        tls: true,
        tls_hostname: tls_hostname.map(str::to_string),
        warm_reserve: None,
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
        address_family: Default::default(),
    };

    // WITHOUT the override: the certificate is not valid for the name
    // dialled, so the handshake must be refused. If this ever passes,
    // the test below proves nothing.
    let refused = Connection::connect(&server(None)).await;
    assert!(
        refused.is_err(),
        "a certificate valid only for {CERT_NAME} must not verify against the address dialled"
    );
    // And an address announces no SNI at all - rustls turns one into an
    // `IpAddress` name, which carries no server_name extension. A
    // virtual-host front end has nothing to select on.
    let announced = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        !announced.is_empty() && announced.iter().all(|s| s.is_none()),
        "dialling a literal must announce no SNI, saw {announced:?}"
    );

    // WITH it: same address, same certificate, and now it verifies.
    let mut conn = None;
    for _ in 0..50 {
        match Connection::connect(&server(Some(CERT_NAME))).await {
            Ok((c, _)) => {
                conn = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    assert!(
        conn.is_some(),
        "the override must be the name the certificate is checked against"
    );
    let announced = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        announced.last().cloned().flatten().as_deref(),
        Some(CERT_NAME),
        "the override must also be the name announced as SNI, saw {announced:?}"
    );
}
