//! Drives `tests/smoke.c`, which is the real test: one whole PAR2 life
//! cycle - preview, create, damage, verify, cancel, repair, verify -
//! through the C ABI and the committed header, compiled by a C
//! compiler. See the comment at the top of that file.
//!
//! This side does three things and no more: writes the payload (which
//! is not part of the ABI), calls in, and prints what came back.

use std::ffi::CStr;
use std::path::PathBuf;

// SAFETY: both are defined in tests/smoke.c, compiled and linked by
// build.rs, with exactly these signatures - `pf_smoke_run` takes a
// NUL-terminated path and answers a step number, `pf_smoke_why`
// answers a pointer to a static buffer valid until the next run.
unsafe extern "C" {
    fn pf_smoke_run(dir: *const std::ffi::c_char) -> i32;
    fn pf_smoke_why() -> *const std::ffi::c_char;
}

/// Keep every exported symbol alive for the linker.
///
/// An rlib is not an archive of everything: rustc pulls in only what
/// something references, and `#[unsafe(no_mangle)]` does not make an
/// item referenced. So a C translation unit calling `pf_job_cancel`
/// links against nothing at all unless the RUST side of the same
/// binary mentions it - which is what this does, through `black_box`
/// so the optimiser cannot decide the addresses are unused after all.
///
/// It doubles as a compile-time check that every function in the
/// contract still exists under its own name and signature: a rename
/// fails here, in this crate, rather than in an app three weeks later.
fn keep_every_symbol() {
    use std::hint::black_box;
    black_box(parfast_ffi::pf_session_new as *const () as usize);
    black_box(parfast_ffi::pf_session_free as *const () as usize);
    black_box(parfast_ffi::pf_session_set_wake as *const () as usize);
    black_box(parfast_ffi::pf_job_submit as *const () as usize);
    black_box(parfast_ffi::pf_job_snapshot as *const () as usize);
    black_box(parfast_ffi::pf_queue_snapshot as *const () as usize);
    black_box(parfast_ffi::pf_job_cancel as *const () as usize);
    black_box(parfast_ffi::pf_job_pause as *const () as usize);
    black_box(parfast_ffi::pf_job_resume as *const () as usize);
    black_box(parfast_ffi::pf_job_remove as *const () as usize);
    black_box(parfast_ffi::pf_job_run_next as *const () as usize);
    black_box(parfast_ffi::pf_job_set_low_priority as *const () as usize);
    black_box(parfast_ffi::pf_queue_set_paused as *const () as usize);
    black_box(parfast_ffi::pf_queue_set_concurrency as *const () as usize);
    black_box(parfast_ffi::pf_queue_set_post_action as *const () as usize);
    black_box(parfast_ffi::pf_queue_clear_post_action as *const () as usize);
    black_box(parfast_ffi::pf_queue_open_store as *const () as usize);
    black_box(parfast_ffi::pf_plan_preview as *const () as usize);
    black_box(parfast_ffi::pf_capabilities as *const () as usize);
    black_box(parfast_ffi::pf_settings_get as *const () as usize);
    black_box(parfast_ffi::pf_settings_set as *const () as usize);
    black_box(parfast_ffi::pf_last_error as *const () as usize);
    black_box(parfast_ffi::pf_string_free as *const () as usize);
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(seed as usize * 7)) as u8)
        .collect()
}

#[test]
fn the_whole_life_cycle_through_the_c_abi() {
    keep_every_symbol();
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "parfast-ffi-smoke-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    // Three members of different lengths, none a whole number of
    // blocks, so the slice grid has a remainder in every one of them.
    for (name, len, seed) in [
        ("a.bin", 30_001usize, 2u8),
        ("b.bin", 41_000, 8),
        ("c.bin", 5_003, 19),
    ] {
        std::fs::write(dir.join(name), payload(len, seed)).expect("fixture");
    }

    let c_dir =
        std::ffi::CString::new(dir.to_string_lossy().as_ref()).expect("a temp path holds no NUL");
    // SAFETY: `c_dir` is a live NUL-terminated string for the duration
    // of the call, which is the C function's only precondition.
    let step = unsafe { pf_smoke_run(c_dir.as_ptr()) };
    if step != 0 {
        // SAFETY: the C side filled its static buffer before
        // returning non-zero, and it stays valid until the next call -
        // which cannot happen while this thread holds the result.
        let why = unsafe { CStr::from_ptr(pf_smoke_why()) }
            .to_string_lossy()
            .into_owned();
        panic!("the C smoke test failed at step {step}: {why}");
    }
    // The repair really happened on disk, not only in the snapshots.
    let repaired = std::fs::read(dir.join("b.bin")).expect("the repaired member");
    assert_eq!(repaired, payload(41_000, 8), "b.bin was not restored");
    let _ = std::fs::remove_dir_all(&dir);
}
