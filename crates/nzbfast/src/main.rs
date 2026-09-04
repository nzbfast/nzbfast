//! The binary: an allocator choice and one call into the library.
//!
//! Everything this crate is lives in `lib.rs` - the module tree, the
//! CLI, `cli_main`. This file was the real root until the crate-split
//! step 4.5 (2 Sep 2026); see the header of `lib.rs` for why it stopped
//! being one and what that bought.
//!
//! Keep it a SHIM. Anything added here compiles in the bin unit only,
//! where it is invisible to the lib's `cfg(test)` build and to every
//! `tests/` binary - which is the arrangement step 4.5 exists to end.

// mimalloc on macOS + Linux: faster under the pipeline's alloc/free churn on
// constrained-CPU Linux boxes (ARM NAS, Celeron, Pi), and on macOS it lets
// the post-job idle trim (tasks.rs) hand freed memory back to the OS.
// Windows keeps the system allocator. See the note in Cargo.toml.
//
// IN THE BIN AND NOT THE LIB, deliberately. A `#[global_allocator]` is a
// whole-program choice, and the lib is linked into a HOST app by
// `crates/nzbfast-ffi` - an iOS app that gained our allocator because it
// embedded our engine would be a decision nobody made. The cost is that
// `cargo test --lib` runs on the system allocator where the shipped
// binary runs on mimalloc; nothing in the suite asserts an allocator,
// and `nzbkit::mem::trim()` is a no-op either way.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> anyhow::Result<()> {
    nzbfast::cli_main()
}
