//! `out_dir` really moves the downloads, and really leaves the engine's
//! own state behind in `config_dir`.
//!
//! ITS OWN TARGET, like `reclaim.rs` and `stop_bound.rs` beside it, and
//! for the reason those are: `ENGINE` is a process-global, so two tests
//! that start an engine in one binary see each other's - measured here
//! the moment this was written next to `cycle.rs`, where the second
//! start answered -1 ("already running") against a test that had started
//! nothing. `cargo test` runs the tests of ONE binary on threads and
//! nextest gives every test its own process, so the split is what makes
//! the answer the same under both.

use std::ffi::CString;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn http_version_ok(port: u16, apikey: &str) -> bool {
    let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let req = format!(
        "GET /api?mode=version&output=json&apikey={apikey} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
    );
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut body = String::new();
    let _ = s.read_to_string(&mut body);
    body.contains("version")
}

/// The `out_dir` argument really moves the downloads, and really leaves
/// the engine's own state behind in `config_dir`.
///
/// This is the iOS split (TODO 281 IO1) asserted from the host: on that
/// platform `UIFileSharingEnabled` exposes exactly one directory to the
/// Files app, so the payload must be under Documents while
/// `config.local.json`, `settings.json`, `runtime.json` and `.spool` must
/// not be. An argument nothing drives is an argument that can quietly
/// stop being wired, and the failure would be silent in the direction
/// that matters - downloads landing back inside the app's private state,
/// where the user cannot reach them and nothing says so.
///
/// The engine is ASKED where it will put things rather than watched for a
/// side effect: `mode=get_config` answers `misc.complete_dir`, which is
/// `Daemon::out_dir` - the same value every mover and every history row
/// resolves against - so this cannot pass on a directory that merely
/// happens to exist.
#[test]
fn an_explicit_out_dir_moves_the_downloads_and_leaves_the_state_behind() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("probe port")
        .local_addr()
        .expect("addr")
        .port();
    let root = std::env::temp_dir().join(format!("nzbfast-ffi-outdir-{port}"));
    let cfg_dir = root.join("state");
    let out_dir = root.join("visible");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    // Seeded for the reason `CONFIG_FILE`'s note gives: a missing config
    // is not "no config", it is the BOX's SABnzbd install.
    std::fs::write(
        cfg_dir.join(nzbfast_ffi::CONFIG_FILE),
        r#"{"servers":[{"host":"flat.example","enabled":true}]}"#,
    )
    .expect("seed config");
    let cfg_c = CString::new(cfg_dir.to_str().expect("utf8 dir")).unwrap();
    let out_c = CString::new(out_dir.to_str().expect("utf8 out")).unwrap();
    let key = "testkey";
    let key_c = CString::new(key).unwrap();

    assert_eq!(
        // SAFETY: all three pointers come from `CString`s that live for
        // the whole test, so each is a valid NUL-terminated UTF-8 string
        // for the duration of the call - the whole of `nzbfast_start`'s
        // safety contract.
        unsafe {
            nzbfast_ffi::nzbfast_start(cfg_c.as_ptr(), out_c.as_ptr(), port, key_c.as_ptr(), 0)
        },
        0,
        "start with an explicit out_dir"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !http_version_ok(port, key) {
        assert!(Instant::now() < deadline, "mode=version never answered");
        std::thread::sleep(Duration::from_millis(100));
    }

    let cfgjson = http_body(
        port,
        &format!("/api?mode=get_config&output=json&apikey={key}"),
    );
    assert!(
        cfgjson.contains(out_dir.to_str().expect("utf8 out")),
        "the engine's complete_dir must be the out_dir it was handed, got: {cfgjson}"
    );

    assert_eq!(nzbfast_ffi::nzbfast_stop(), 0, "stop");

    // The state stayed behind. `runtime.json` is the one the host reads
    // back to learn the port, so it has to be in the directory the host
    // named for state and not in the one it exposes to the user.
    assert!(
        cfg_dir.join("runtime.json").is_file(),
        "runtime.json belongs in the config dir"
    );
    assert!(
        !cfg_dir.join("downloads").exists(),
        "the derived downloads path must not be used when out_dir was given"
    );
    assert!(
        !out_dir.join("runtime.json").exists(),
        "engine state must not appear in the user-visible download folder"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// GET a path from the engine and hand back the body.
fn http_body(port: u16, path: &str) -> String {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let req = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
    s.write_all(req.as_bytes()).expect("write");
    let mut body = String::new();
    let _ = s.read_to_string(&mut body);
    body
}
