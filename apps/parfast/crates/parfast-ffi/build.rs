//! Compiles the C smoke test's translation unit and offers it to the
//! linker.
//!
//! WHY A BUILD SCRIPT AND NOT A STEP INSIDE THE TEST: a C program that
//! exercises this ABI has to be LINKED against it, and a Rust
//! integration test binary is already linked against the rlib - so the
//! one arrangement that needs no second cargo invocation, no
//! `dlopen`, and no guessing where `libparfast_ffi.a` landed is to
//! compile the C here and let the test call into it.
//!
//! The archive is offered to EVERY target of this crate, including the
//! shipped `staticlib` and `cdylib`, and that costs them nothing: a
//! linker pulls an archive MEMBER in only when something references a
//! symbol it defines, and nothing outside `tests/c_smoke.rs`
//! references `pf_smoke_run`. So the shipped artefacts do not carry it.

fn main() {
    println!("cargo:rerun-if-changed=tests/smoke.c");
    println!("cargo:rerun-if-changed=include/parfast_ffi.h");
    cc::Build::new()
        .file("tests/smoke.c")
        .include("include")
        .warnings(true)
        .compile("pf_smoke");
    // AND EXPLICITLY FOR THE TEST TARGETS. `cc`'s own
    // `cargo:rustc-link-lib` reaches this package's LIB targets, and
    // the search path reaches the integration tests, but the `-l` does
    // not: an integration test links the rlib, and the native library
    // an rlib records is not re-emitted for it here. Measured, not
    // assumed - without these two lines the link fails with
    // `Undefined symbols: _pf_smoke_run`, with the search path already
    // on the command line.
    let out = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    println!("cargo:rustc-link-arg-tests=-L{out}");
    println!("cargo:rustc-link-arg-tests=-lpf_smoke");
}
