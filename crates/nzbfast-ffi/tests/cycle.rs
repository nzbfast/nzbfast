//! The FFI contract, exercised on the host: start answers HTTP from
//! inside this process, stop releases the port, and the cycle repeats
//! without crashing - the exact acceptance the iOS Simulator harness
//! re-proves on-target (research/SPIKE-IOS-STATICLIB-2026-08-05.md).

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

#[test]
fn start_stop_cycles_release_the_port() {
    // A free port, found the usual way.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("probe port")
        .local_addr()
        .expect("addr")
        .port();
    let dir = std::env::temp_dir().join(format!("nzbfast-ffi-cycle-{port}"));
    std::fs::create_dir_all(&dir).expect("config dir");
    // Seed the config the engine loads. A MISSING one is not "no
    // config": it falls back to a SABnzbd install's ini found through
    // `$HOME`, so an unseeded run tests the BOX - the developer's real
    // server list on this fleet, nothing at all on a CI runner. See
    // `CONFIG_FILE`'s note in the crate root for why that is not
    // cosmetic. Flat-rate and unreachable on purpose: nothing here
    // queues a job, so the list only has to be ours.
    std::fs::write(
        dir.join(nzbfast_ffi::CONFIG_FILE),
        r#"{"servers":[{"host":"flat.example","enabled":true}]}"#,
    )
    .expect("seed config");
    let dir_c = CString::new(dir.to_str().expect("utf8 dir")).unwrap();
    let key = "testkey";
    let key_c = CString::new(key).unwrap();

    for cycle in 0..3 {
        assert_eq!(
            // SAFETY: both pointers come from `CString`s that live for
            // the whole test, so each is a valid NUL-terminated UTF-8
            // string for the duration of the call - the whole of
            // `nzbfast_start`'s safety contract.
            unsafe { nzbfast_ffi::nzbfast_start(dir_c.as_ptr(), port, key_c.as_ptr()) },
            0,
            "start (cycle {cycle})"
        );
        // Double start must refuse, not wedge.
        assert_eq!(
            // SAFETY: both pointers come from `CString`s that live for
            // the whole test, so each is a valid NUL-terminated UTF-8
            // string for the duration of the call - the whole of
            // `nzbfast_start`'s safety contract.
            unsafe { nzbfast_ffi::nzbfast_start(dir_c.as_ptr(), port, key_c.as_ptr()) },
            -1,
            "second start refused (cycle {cycle})"
        );
        assert_eq!(nzbfast_ffi::nzbfast_is_up(), 1, "is_up (cycle {cycle})");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !http_version_ok(port, key) {
            assert!(
                Instant::now() < deadline,
                "mode=version never answered (cycle {cycle})"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(nzbfast_ffi::nzbfast_stop(), 0, "stop (cycle {cycle})");
        assert_eq!(
            nzbfast_ffi::nzbfast_is_up(),
            0,
            "down after stop (cycle {cycle})"
        );
        // The port must come free: the HTTP workers wind up within one
        // accept tick of the stop flag; give them a bounded grace.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match std::net::TcpListener::bind(("127.0.0.1", port)) {
                Ok(l) => {
                    drop(l);
                    break;
                }
                Err(e) => {
                    assert!(
                        Instant::now() < deadline,
                        "port {port} still held after stop (cycle {cycle}): {e}"
                    );
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
    assert_eq!(nzbfast_ffi::nzbfast_stop(), -1, "stop when already stopped");
    let _ = std::fs::remove_dir_all(&dir);
}
