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
fn cert_chain(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "nzbkit test ca");
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let mut leaf_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf cert");

    let ca_pem = dir.join("ca.pem");
    let cert_pem = dir.join("leaf.pem");
    let key_pem = dir.join("leaf.key");
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
    let (cert, key, ca) = cert_chain(&dir);

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

    let _ = std::fs::remove_dir_all(&dir);
}
