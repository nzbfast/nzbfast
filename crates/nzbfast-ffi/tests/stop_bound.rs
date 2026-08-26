//! TODO 307 item 3: `nzbfast_stop` promises a BOUNDED stop, and until
//! 26 Aug 2026 it did not have one - it held the ENGINE lock across an
//! unbounded `JoinHandle::join`, so a wedged `serve()` hung the host app
//! in stop forever and hung `nzbfast_is_up` behind the same lock. On iOS
//! that is the only stop path there is.
//!
//! The bound itself cannot be tested by wedging a real engine: nothing
//! cheap makes `serve()` hang, and a test that arranged one would be
//! testing the wedge rather than the bound. So this drives the identical
//! code path from the other end, through `stop_within`, whose deadline
//! is a parameter for exactly this reason. A zero-length wait against a
//! HEALTHY engine takes the timeout arm deterministically: between
//! `request_stop()` and the non-blocking receive one statement later,
//! the engine thread would have to notice the stop epoch (up to one
//! 500 ms accept tick), leave the serve loop and tear a whole tokio
//! runtime down. There is no machine on which that fits in the gap.
//!
//! What is actually pinned here is the CONTRACT around -2, which is the
//! half that protects the process: a timed-out stop must leave the
//! engine registered, so `nzbfast_start` refuses rather than arming the
//! process-global stop baseline under a still-live engine, and
//! `nzbfast_is_up` keeps answering 1 so a host can poll for the end.
//!
//! Its own test binary, i.e. its own process, for `reclaim.rs`'s stated
//! reason: the engine is process-global, so sharing a binary would mean
//! two tests racing one engine.

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
fn a_stop_that_runs_out_of_time_says_so_and_keeps_the_engine_claimed() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("probe port")
        .local_addr()
        .expect("addr")
        .port();
    let dir = std::env::temp_dir().join(format!("nzbfast-ffi-stopbound-{port}"));
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

    // Nothing running yet.
    assert_eq!(nzbfast_ffi::nzbfast_stop(), -1, "stop before any start");

    assert_eq!(
        // SAFETY: both pointers come from `CString`s that live for the
        // whole test, so each is a valid NUL-terminated UTF-8 string
        // for the duration of the call - the whole of
        // `nzbfast_start`'s safety contract.
        unsafe { nzbfast_ffi::nzbfast_start(dir_c.as_ptr(), port, key_c.as_ptr()) },
        0,
        "start"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !http_version_ok(port, key) {
        assert!(Instant::now() < deadline, "mode=version never answered");
        std::thread::sleep(Duration::from_millis(100));
    }

    // The timeout arm. See the module note for why zero is deterministic
    // here rather than merely likely.
    assert_eq!(
        nzbfast_ffi::stop_within(Duration::ZERO),
        -2,
        "a stop with no time to wait must report -2, not block and not lie"
    );

    // -2 leaves the engine CLAIMED, and these two are why that matters.
    // `is_up` also proves the ENGINE lock came back: before the bound
    // existed this call is where a host hung.
    assert_eq!(
        nzbfast_ffi::nzbfast_is_up(),
        1,
        "the engine thread is still alive after a timed-out stop, so is_up must say so"
    );
    assert_eq!(
        // SAFETY: the same two live `CString`s as the start above.
        unsafe { nzbfast_ffi::nzbfast_start(dir_c.as_ptr(), port, key_c.as_ptr()) },
        -1,
        "start must REFUSE while the timed-out engine's thread is alive - re-arming the \
         process-global stop baseline underneath it is the failure this guards"
    );

    // And a second stop is how a host waits longer: same request, full
    // budget, and it must land inside that budget rather than at it.
    let t0 = Instant::now();
    assert_eq!(nzbfast_ffi::nzbfast_stop(), 0, "second stop completes");
    assert!(
        t0.elapsed() < Duration::from_secs(12),
        "the second stop took {:?}, which is the bound rather than the engine",
        t0.elapsed()
    );
    assert_eq!(nzbfast_ffi::nzbfast_is_up(), 0, "down after a real stop");
    assert_eq!(nzbfast_ffi::nzbfast_stop(), -1, "stop when already stopped");

    let _ = std::fs::remove_dir_all(&dir);
}
