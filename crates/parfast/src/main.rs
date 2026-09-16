//! The `parfast` binary: argv in, exit code out.
//!
//! Everything is in the library so the unit tests can drive a run
//! without building and shelling out to a binary - the exact text of
//! these lines is what this crate is for, and a test that can only see
//! it through a process boundary is a slower test that proves less.

use std::process::ExitCode;

// Fast mem ops for the static musl x86_64 download, which otherwise links
// zig compiler_rt's byte-at-a-time `memset` / `memcmp` / `bcmp`. Stamped
// into the BIN and not linked from the library because `compiler_rt`'s
// definitions are weak but an rlib is an archive: see
// `nzbkit_base::memops`'s module docs, which also carry the measurements.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_env = "musl"
))]
nzbkit::fast_mem_ops!();

fn main() -> ExitCode {
    let mut argv = std::env::args();
    // argv[0] selects the command for the `par2create` / `par2verify` /
    // `par2repair` spellings, which scripts invoke by name.
    let argv0 = argv.next().unwrap_or_else(|| "parfast".to_string());
    let args: Vec<String> = argv.collect();
    fix_mmap_threshold_when_bounded(&argv0, &args);
    ExitCode::from(parfast::run(&argv0, &args))
}

/// Fix glibc's mmap threshold at 4 MiB, before any work, on a run whose
/// memory is bounded (`parfast::memory_bounded`: `-m`, or a cgroup limit
/// below RAM). Left dynamic, the threshold climbs to the size of each
/// freed mmapped block up to 32 MiB, so a 25.2 MB `-m192` feed batch
/// lands in an arena heap that stays resident and ratchets slab after
/// slab - +39 to +90 MiB at the cell that was OOM-killed inside a 512 MiB
/// cgroup. Fixed, that cell held 271-274 MiB where the default reached
/// 417-506 and was killed, and every tight cell fell by 63-243 MiB.
///
/// Only when bounded, because the fix is not free: every feed batch and
/// window becomes an mmap / munmap with fresh zeroed pages, measured at
/// +6.3% wall and +4.4% CPU on an unbounded 64 KiB repair (where the heap
/// holds its batches either way and the saving is ~2%) and ~1% CPU on a
/// budgeted one. Setting the parameter disables the dynamic adjustment
/// exactly as `GLIBC_TUNABLES=glibc.malloc.mmap_threshold` does
/// (research/PARFAST-512MB-M192-KILL-ATTRIBUTION-2026-09-15.md, the rank
/// 1 addendum, rounds 1 and 2).
///
/// Here and not in the engine or the library: a host that links them -
/// the desktop GUI's session crate, the nzbfast daemon on mimalloc - keeps
/// its own heap. The static musl download never compiles this arm, and
/// was measured not to need it (the same note's musl addendum).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn fix_mmap_threshold_when_bounded(argv0: &str, args: &[String]) {
    if parfast::memory_bounded(argv0, args) {
        // SAFETY: mallopt takes two integers and reads no pointers; glibc
        // documents it as callable at any time, and no other thread exists
        // yet.
        unsafe {
            libc::mallopt(libc::M_MMAP_THRESHOLD, 4 << 20);
        }
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn fix_mmap_threshold_when_bounded(_argv0: &str, _args: &[String]) {}
