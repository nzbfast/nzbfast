//! TODO §129 phase 2a: opt-in native HTTPS for the daemon UI/API.
//!
//! With `--tls-cert`/`--tls-key` the ONE listener answers https instead
//! of http (rustls acceptor on tiny_http's own accept loop - see
//! vendor/tiny_http VENDORING.md patch 13). This file pins:
//!
//!  * the dashboard (/) and the API (/api?mode=version) answer over a
//!    verified TLS session - the client trusts exactly the test CA, so a
//!    handshake that completes proves the configured chain is served;
//!  * the startup banner says https, so launchers and users get the
//!    scheme the listener actually speaks;
//!  * plain HTTP against the TLS listener gets no HTTP answer;
//!  * a certificate file that is not a certificate refuses startup with
//!    the file NAMED, and an expired certificate refuses startup saying
//!    it is expired - not a browser error on another machine later.
//!
//! The test chain is CA + leaf, not one self-signed cert: webpki refuses
//! a CA:TRUE certificate presented as an end entity (CaUsedAsEndEntity),
//! the exact trap the 8 Aug bench profiling hit. rcgen leaves the leaf
//! CA:FALSE by construction.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

// The https test is on the shared harness as of 23 Aug 2026, when TODO
// §242 item 5 stopped `harness::wait_ready` hardcoding `http://` - until
// then it would have waited its full 60 s on a daemon that came up
// perfectly and then panicked "daemon never came up". The scheme
// assertion the private launcher used to make implicitly (by blocking on
// the `https://` banner) is now made outright, below, because the
// harness deliberately accepts either scheme.
//
// `bad_or_expired_cert_refuses_startup_naming_the_file` stays on the raw
// spawn and cannot move: it REQUIRES the daemon to exit, which
// `serve_blocking` reads as a lost-port race and retries three times
// before failing. That is not a per-suite launch policy a `build`
// closure can carry.
use crate::harness::{KillOnDrop, free_port, serve_blocking};

/// A CA and a localhost leaf signed by it, PEM, written to `dir`.
/// Returns (cert, key, ca) paths.
fn cert_chain(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "nzbfast test ca");
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let mut leaf_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let ca_pem = dir.join("ca.pem");
    std::fs::write(&ca_pem, ca_cert.pem()).expect("write ca");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf cert");

    let cert_pem = dir.join("cert.pem");
    let key_pem = dir.join("key.pem");
    std::fs::write(&cert_pem, leaf_cert.pem()).expect("write cert");
    std::fs::write(&key_pem, leaf_key.serialize_pem()).expect("write key");
    (cert_pem, key_pem, ca_pem)
}

/// An ALREADY-EXPIRED localhost leaf (validity ended before it began to
/// be checked), self-issued: expiry must be diagnosed before signature
/// chains matter, so no CA is needed.
fn expired_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    let cert_pem = dir.join("expired.pem");
    let key_pem = dir.join("expired.key");
    std::fs::write(&cert_pem, cert.pem()).expect("write cert");
    std::fs::write(&key_pem, key.serialize_pem()).expect("write key");
    (cert_pem, key_pem)
}

/// A TLS-serving daemon command for `dir` on `port`. Stdout and stderr
/// are the caller's business: `harness::serve_blocking` sets its own and
/// would overwrite any set here.
fn tls_cmd(dir: &Path, port: u16, cert: &Path, key: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    cmd.env("NZBFAST_NO_ENRICH", "1")
        .env_remove("NZBFAST_OPEN")
        .arg("--config")
        .arg(dir.join("config.json"))
        .arg("serve")
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--tls-cert")
        .arg(cert)
        .arg("--tls-key")
        .arg(key)
        .arg("--out")
        .arg(dir.join("complete"));
    cmd
}

/// The raw spawn, for the one test that needs the daemon to DIE rather
/// than come up. Logs to a fixed `daemon.log` because that test reads the
/// file by name after the child has exited, and there is no `Daemon` to
/// ask.
fn spawn_daemon(dir: &Path, port: u16, cert: &Path, key: &Path) -> KillOnDrop {
    let log = dir.join("daemon.log");
    let out = std::fs::File::create(&log).unwrap();
    let err = out.try_clone().unwrap();
    let mut cmd = tls_cmd(dir, port, cert, key);
    cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
    KillOnDrop(crate::harness::spawn_under_test(&mut cmd))
}

/// GET `path` over TLS, trusting exactly `ca`; returns (head, body) with
/// the body de-chunked. A completed handshake here IS the verification
/// half of the test: the client refuses anything not chaining to the CA.
fn https_get(port: u16, ca: &Path, path: &str) -> (String, Vec<u8>) {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for der in rustls::pki_types::CertificateDer::pem_file_iter(ca).unwrap() {
        roots.add(der.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let server = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(cfg), server).unwrap();
    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect daemon");
    let mut tls = rustls::StreamOwned::new(conn, sock);
    write!(
        tls,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = tls.read_to_end(&mut raw); // close_notify may be skipped; data is in
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers");
    let (head, body) = raw.split_at(at + 4);
    let head = String::from_utf8_lossy(head).to_string();
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body)
    } else {
        body.to_vec()
    };
    (head, body)
}

/// Minimal chunked decoder, same shape as webasset.rs's.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = b.windows(2).position(|w| w == b"\r\n") {
        let line = String::from_utf8_lossy(&b[..nl]);
        let n = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        let (start, end) = (nl + 2, nl + 2 + n);
        if end > b.len() {
            out.extend_from_slice(&b[start.min(b.len())..]);
            break;
        }
        out.extend_from_slice(&b[start..end]);
        b = &b[(end + 2).min(b.len())..];
    }
    out
}

#[test]
fn dashboard_and_api_answer_over_https() {
    let dir = std::env::temp_dir().join(format!("nzbfast-tls-{}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    let (cert, key, ca) = cert_chain(&dir);

    // THE HARNESS ITSELF IS UNDER TEST HERE. `serve_blocking` returning
    // at all is the assertion TODO §242 item 5 asked for: before 23 Aug
    // 2026 its readiness needle carried `http://` verbatim, so this call
    // would have polled a healthy TLS daemon for sixty seconds and then
    // panicked "daemon never came up on :PORT" - with the banner it
    // failed to match sitting in the log it printed as evidence. There is
    // no shorter way to catch that: it is a string mismatch in a poll, so
    // it compiles, and this is the only suite that serves TLS.
    let d = serve_blocking(&dir, |port| tls_cmd(&dir, port, &cert, &key));
    let port = d.port;

    // And the banner says https. The harness now accepts either scheme by
    // design, so waiting on it no longer proves this the way the private
    // launcher's needle did - the assertion has to be made outright.
    let log = d.log();
    assert!(
        log.contains(&format!("open the dashboard at  https://localhost:{port}/")),
        "the banner must name the scheme the listener speaks: {log}"
    );

    // The dashboard, over a verified session.
    let (head, body) = https_get(port, &ca, "/");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        String::from_utf8_lossy(&body).contains("nzbfast"),
        "the https body is the dashboard"
    );

    // The API. mode=version answers unauthenticated by design.
    let (head, body) = https_get(port, &ca, "/api?mode=version&output=json");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let v: serde_json::Value = serde_json::from_slice(&body).expect("version JSON");
    assert!(v.get("version").is_some(), "{v}");

    // Plain HTTP against the TLS listener: whatever comes back (usually
    // nothing before the close - a TLS alert at most), it is not HTTP.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    assert!(
        !raw.starts_with(b"HTTP/1.1"),
        "a TLS listener answered plaintext HTTP: {}",
        String::from_utf8_lossy(&raw)
    );
}

/// A cert file that is not a certificate, and an expired one: both must
/// refuse startup with the FILE named (and "expired" said when it is),
/// because the alternative is a daemon that starts fine and then every
/// client refuses with its own wording somewhere else.
#[test]
fn bad_or_expired_cert_refuses_startup_naming_the_file() {
    let dir = std::env::temp_dir().join(format!("nzbfast-tls-bad-{}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();

    let run = |label: &str, cert: &Path, key: &Path| -> String {
        let sub = dir.join(label);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("config.json"), "{\"servers\":[]}").unwrap();
        let mut daemon = spawn_daemon(&sub, free_port(), cert, key);
        let status = (0..300)
            .find_map(|_| {
                let s = daemon.0.try_wait().ok().flatten();
                if s.is_none() {
                    std::thread::sleep(Duration::from_millis(100));
                }
                s
            })
            .expect("daemon should exit on a bad certificate");
        assert!(!status.success(), "{label}: exit status should be failure");
        std::fs::read_to_string(sub.join("daemon.log")).unwrap_or_default()
    };

    // Garbage where a certificate should be.
    let garbage = dir.join("not-a-cert.pem");
    std::fs::write(&garbage, "this is not PEM").unwrap();
    let (_, real_key, _) = cert_chain(&dir);
    let log = run("garbage", &garbage, &real_key);
    assert!(
        log.contains("not-a-cert.pem"),
        "the error names the file: {log}"
    );

    // Expired.
    let (exp_cert, exp_key) = expired_cert(&dir);
    let log = run("expired", &exp_cert, &exp_key);
    assert!(
        log.contains("expired.pem"),
        "the error names the file: {log}"
    );
    assert!(log.contains("expired"), "the error says WHY: {log}");
}
