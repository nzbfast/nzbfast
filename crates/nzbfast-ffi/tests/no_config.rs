//! The engine may only be configured out of the directory it was handed.
//!
//! `nzbkit::config::Config::load` answers a MISSING config by going and
//! finding a SABnzbd install's `sabnzbd.ini` through `$HOME`. That is
//! deliberate on a desktop - a machine already running SAB needs no
//! configuration at all - and it is exactly wrong through this ABI,
//! where it means the host app's downloads run through whatever server
//! list the BOX happens to have: the developer's real providers on this
//! fleet, nothing at all on a CI runner. Both shipped callers seed the
//! file, so what is pinned here is the FORWARD guard for the third one,
//! whose failure would otherwise be silent - a working engine dialling
//! somebody else's providers.

use std::ffi::CString;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let n = std::process::id();
    let dir = std::env::temp_dir().join(format!("nzbfast-ffi-noconfig-{tag}-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("config dir");
    dir
}

/// Start with `c` as the config dir, on a port nothing will answer on:
/// every call here is expected to be refused before a listener exists.
fn start_in(dir: &std::path::Path) -> i32 {
    let dir_c = CString::new(dir.to_str().expect("utf8 dir")).unwrap();
    // SAFETY: the pointer comes from a `CString` that outlives the call,
    // so it is a valid NUL-terminated UTF-8 string; NULL `out_dir` and
    // NULL `apikey` are both explicitly allowed - the whole of
    // `nzbfast_start`'s safety contract.
    //
    // host-config-gate: NOT seeding the config is the SUBJECT of this
    // test. The refusal it asserts is the very guard that stops an
    // unseeded start reading the box, so a seed here would test nothing.
    unsafe { nzbfast_ffi::nzbfast_start(dir_c.as_ptr(), std::ptr::null(), 0, std::ptr::null(), 0) }
}

/// ONE test function, and both halves inside it, deliberately: `ENGINE`
/// and the stop epoch are process-global, so a second `#[test]` in this
/// binary would run on another thread of the same process and its engine
/// would be live while the first half asserts that none is. Integration
/// test FILES are separate binaries under both `cargo test` and nextest,
/// so the other suites in this crate are unaffected either way.
#[test]
fn the_engine_is_configured_from_its_own_directory_or_not_at_all() {
    let dir = tmpdir("bare");
    assert_eq!(start_in(&dir), -3, "an empty config dir must be refused");
    assert_eq!(
        nzbfast_ffi::nzbfast_is_up(),
        0,
        "no engine may have started"
    );
    // A refusal writes nothing: the directory is the caller's, and a
    // seed here would also close the sabnzbd.ini import below by putting
    // a file where that search would have looked.
    let left: Vec<_> = std::fs::read_dir(&dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert!(left.is_empty(), "a refused start left {left:?} behind");
    let _ = std::fs::remove_dir_all(&dir);

    // The adjacent-ini import (issue #15) stays open: what is refused is
    // the NEXT step of the same search, the `$HOME` locations that are
    // some other application's install. This asserts the guard lets the
    // start through - not that the engine comes up, which the cycle
    // suite covers - so it stops the engine straight away.
    let dir = tmpdir("sabini");
    std::fs::write(
        dir.join("sabnzbd.ini"),
        "[servers]\n[[flat.example]]\nhost = flat.example\nenable = 1\n",
    )
    .expect("seed ini");
    assert_eq!(
        start_in(&dir),
        0,
        "a sabnzbd.ini in the directory we were handed is configuration"
    );
    assert_eq!(nzbfast_ffi::nzbfast_stop(), 0, "stop the accepted engine");
    let _ = std::fs::remove_dir_all(&dir);
}
