//! Codex read-only sweep H2: an FFI stop must reclaim the WHOLE daemon
//! generation, not just the engine thread.
//!
//! `nzbfast_stop()` joins the engine thread and shuts the runtime down,
//! which covers the tokio tasks and the HTTP workers - but every run
//! also spawns plain OS threads (update check, scheduled bench,
//! auto-tune, the signal wait, the hook dispatcher, the metadata lanes
//! on a full build). Those are invisible to `shutdown_timeout`, and the
//! ones that slept for hours between passes held an `Arc<Daemon>` while
//! they did. Each iOS start/stop cycle therefore left a whole daemon
//! graph alive: stale workers still reading config and still touching
//! the network after the host API had reported stopped.
//!
//! `tests/cycle.rs` proves the port comes back and `is_up` flips. It
//! cannot see this - a leaked generation rebinds nothing and answers
//! nothing. So the census is the deliverable: `live_daemons()` counts
//! generations whose `Arc` still has a strong holder, `live_aux_threads()`
//! names the long-lived threads still running, and both must return to
//! their pre-start baseline after every stop.
//!
//! Its own test binary, i.e. its own process: the engine is
//! process-global, so sharing a binary with `cycle.rs` would mean two
//! tests racing one engine and one set of censuses.
//!
//! This is the slim (no-indexer) build the phones ship, so no metadata
//! worker exists here to need `NZBFAST_NO_ENRICH=1`. The full build's
//! enrichment lanes take the same stop token; they are covered by
//! reading, not by this test.

use std::ffi::CString;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// Cycles to run. Three is enough to distinguish "leaks one per cycle"
/// from "leaks once at boot"; four costs a second more and makes the
/// arithmetic unambiguous either way.
const CYCLES: usize = 4;

/// How long a lane may take to notice the stop and unwind. Generous on
/// purpose: the point is that reclamation HAPPENS, and a tight bound
/// here would just make the test flaky on a loaded CI box. A real leak
/// never clears, so it fails at the full deadline every time.
const RECLAIM_GRACE: Duration = Duration::from_secs(15);

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

fn aux_lanes() -> String {
    let live = nzbfast::serve::live_aux_threads();
    if live.is_empty() {
        return "none".into();
    }
    live.iter()
        .map(|(name, n)| format!("{name} x{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[test]
fn a_stop_reclaims_the_whole_generation() {
    // Nothing has run yet, so the censuses start empty - which is also
    // what makes "back to baseline" below mean "back to zero".
    assert_eq!(
        nzbfast::serve::live_daemons(),
        0,
        "daemons before any start"
    );
    assert!(
        nzbfast::serve::live_aux_threads().is_empty(),
        "aux lanes before any start: {}",
        aux_lanes()
    );

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("probe port")
        .local_addr()
        .expect("addr")
        .port();
    let dir = std::env::temp_dir().join(format!("nzbfast-ffi-reclaim-{port}"));
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

    for cycle in 0..CYCLES {
        assert_eq!(
            // SAFETY: both non-NULL pointers come from `CString`s that
            // live for the whole test, so each is a valid NUL-terminated
            // UTF-8 string for the duration of the call, and a NULL
            // `out_dir` is explicitly allowed - the whole of
            // `nzbfast_start`'s safety contract.
            unsafe {
                nzbfast_ffi::nzbfast_start(
                    dir_c.as_ptr(),
                    std::ptr::null(),
                    port,
                    key_c.as_ptr(),
                    0,
                )
            },
            0,
            "start (cycle {cycle})"
        );
        // Answering HTTP is what proves the generation is fully up:
        // the daemon exists and the lanes have been spawned. Asserting
        // the census before that would race the boot.
        let deadline = Instant::now() + Duration::from_secs(30);
        while !http_version_ok(port, key) {
            assert!(
                Instant::now() < deadline,
                "mode=version never answered (cycle {cycle})"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        // Exactly one generation live, and it really did spawn lanes -
        // otherwise "reclaimed everything" would be trivially true
        // because there was nothing to reclaim.
        assert_eq!(
            nzbfast::serve::live_daemons(),
            1,
            "one live daemon while up (cycle {cycle})"
        );
        assert!(
            !nzbfast::serve::live_aux_threads().is_empty(),
            "the run spawned no auxiliary lane at all (cycle {cycle}) - \
             either the census stopped covering them or boot is broken"
        );

        assert_eq!(nzbfast_ffi::nzbfast_stop(), 0, "stop (cycle {cycle})");

        // A lane wakes on the stop condvar, finishes whatever call it
        // was in, and returns; the last one to return drops the last
        // `Arc<Daemon>`. Both censuses must therefore come back to
        // zero, not merely stop growing - "stops growing" is what a
        // leak that saturates looks like.
        let deadline = Instant::now() + RECLAIM_GRACE;
        while !nzbfast::serve::live_aux_threads().is_empty() {
            assert!(
                Instant::now() < deadline,
                "auxiliary lanes survived the stop (cycle {cycle}): {} \
                 [{} daemon generation(s) still live]. A lane that is not \
                 itself the leak can be pinned by one that is: the hook \
                 dispatcher only exits once the last Arc<Daemon> drops.",
                aux_lanes(),
                nzbfast::serve::live_daemons()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let deadline = Instant::now() + RECLAIM_GRACE;
        while nzbfast::serve::live_daemons() != 0 {
            assert!(
                Instant::now() < deadline,
                "{} daemon generation(s) still alive after stop (cycle {cycle}) - \
                 something is holding an Arc<Daemon> past its run",
                nzbfast::serve::live_daemons()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // Belt and braces: after the last cycle nothing at all is left, so
    // the loop above cannot have been passing on a stale reading.
    assert_eq!(
        nzbfast::serve::live_daemons(),
        0,
        "daemons after {CYCLES} cycles"
    );
    assert!(
        nzbfast::serve::live_aux_threads().is_empty(),
        "aux lanes after {CYCLES} cycles: {}",
        aux_lanes()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
