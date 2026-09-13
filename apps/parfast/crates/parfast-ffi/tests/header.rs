//! The committed header is what a signature change has to go through.
//!
//! `include/parfast_ffi.h` is cbindgen's output and is checked in. Two
//! UI lanes compile against it - the macOS app through a bridging
//! header, the Windows app by hand-translating it into P/Invoke
//! declarations - so a changed signature that nobody noticed is a
//! corrupted stack frame in a shipped app rather than a compile error.
//!
//! This test regenerates it and compares byte for byte. To ACCEPT a
//! change, regenerate on purpose:
//!
//! ```sh
//! PARFAST_FFI_WRITE_HEADER=1 cargo test -p parfast-ffi --test header
//! ```
//!
//! and read the diff before committing it. That is the whole point: the
//! header is generated, and then it is reviewed.

use std::path::PathBuf;

fn header_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include/parfast_ffi.h")
}

fn generate() -> String {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml"))
        .expect("cbindgen.toml is part of this crate");
    let mut out = Vec::new();
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen could not read this crate")
        .write(&mut out);
    String::from_utf8(out).expect("cbindgen emits UTF-8")
}

#[test]
fn the_committed_header_is_what_cbindgen_generates() {
    let generated = generate();
    let path = header_path();
    if std::env::var_os("PARFAST_FFI_WRITE_HEADER").is_some() {
        std::fs::write(&path, generated.as_bytes()).expect("write the header");
        return;
    }
    let committed =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    if committed == generated {
        return;
    }
    // The FIRST DIFFERING LINE and not the two whole files. `assert_eq!`
    // on a 9 KB header prints 18 KB of one line, which is unreadable in
    // a CI log and in a terminal - and the point of this test is that a
    // human reads what changed.
    let (a, b): (Vec<&str>, Vec<&str>) = (committed.lines().collect(), generated.lines().collect());
    let at = (0..a.len().max(b.len()))
        .find(|&i| a.get(i) != b.get(i))
        .unwrap_or(0);
    panic!(
        "include/parfast_ffi.h is not what cbindgen generates from src/lib.rs.\n\
         First difference at line {}:\n\
         \x20 committed: {:?}\n\
         \x20 generated: {:?}\n\
         ({} lines committed, {} generated)\n\
         Regenerate it on purpose and READ THE DIFF:\n\
         \x20 PARFAST_FFI_WRITE_HEADER=1 cargo test -p parfast-ffi --test header\n\
         Two UI lanes compile against this file.",
        at + 1,
        a.get(at).unwrap_or(&"(end of file)"),
        b.get(at).unwrap_or(&"(end of file)"),
        a.len(),
        b.len(),
    );
}

/// Every function section 4.5 names must be IN the header under that
/// exact spelling. cbindgen omitting one - a macro it could not parse,
/// a `#[cfg]` it did not resolve - would produce a header that compiles
/// and a host that cannot call half the library, which the byte
/// comparison above cannot see because it would compare two equally
/// incomplete files.
#[test]
fn the_header_declares_every_function_the_contract_names() {
    let h = std::fs::read_to_string(header_path()).expect("the committed header");
    for name in [
        "pf_session_new",
        "pf_session_free",
        "pf_session_set_wake",
        "pf_job_submit",
        "pf_job_snapshot",
        "pf_queue_snapshot",
        "pf_job_cancel",
        "pf_job_pause",
        "pf_job_resume",
        "pf_job_remove",
        "pf_job_run_next",
        "pf_job_set_low_priority",
        "pf_queue_set_paused",
        "pf_queue_set_concurrency",
        "pf_queue_set_post_action",
        "pf_plan_preview",
        "pf_capabilities",
        "pf_settings_get",
        "pf_settings_set",
        "pf_last_error",
        "pf_string_free",
    ] {
        assert!(
            h.contains(name),
            "{name} is in the contract (plan 4.5) and not in the header"
        );
    }
}
