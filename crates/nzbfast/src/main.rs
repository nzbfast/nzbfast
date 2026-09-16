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

// Fast mem ops for the static musl x86_64 download - the linux-x64 tarball
// and the ghcr.io images, which packaging/build-linux-tarballs.sh cross-
// builds with cargo-zigbuild and upload-release-assets.sh refuses if they
// are not static. Zig's bundled musl ships no `src/string` mem routines at
// all, so those binaries link `compiler_rt`'s, whose `memset`, `memcmp` and
// `bcmp` are one-byte-per-iteration loops. IN THE BIN for the same reason
// the allocator above is: the symbols only win the link from an object that
// is linked whole. `nzbkit_base::memops` carries the algorithms, the
// measurements and why it cannot be fixed at link time instead; the glibc,
// macOS and Windows builds compile none of this.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_env = "musl"
))]
nzbkit::fast_mem_ops!();

// Cut mimalloc's purge delay when something BOUNDS the heap, and only then.
//
// mimalloc v3 serves every allocation over 512 KiB from arena slices and
// purges a freed slice only after `purge_delay` (1,000 ms by default). A
// slabbed PAR2 repair churns feed batches and NTT windows faster than
// that, so freed slices stack up as anonymous pages and the repair's own
// peak climbs to within ~10 MiB of a tight limit. Measured on this
// binary inside `MemoryMax=512M`: the default delay was OOM-killed in 5
// of 12 jobs, and 10 ms took the same box to 0 kills in 27, 24 of them
// on a daemon already carrying a previous repair, with 63-152 MiB of
// headroom left. The lever is the PEAK (down ~120-130 MiB), not the
// carried retention, which a purge delay only reaches partway
// (research/PARFAST-512MB-M192-KILL-ATTRIBUTION-2026-09-15.md, the
// purge-delay and mimalloc-plateau addenda).
//
// 10 ms and not 0: both measured 0 kills, and 10 ms keeps a purge BATCH
// where 0 is an `madvise` plus freshly zeroed pages per free. That is
// the cost side, and it is not free - on parfast, purge 0 ran minor
// faults 10-46x the default arm's at the heavy cells.
//
// ONLY UNDER A LIMIT. An unbudgeted run is untouched, byte for byte of
// behaviour, which is the shape the glibc mmap-threshold twin already
// ships in (`crates/parfast/src/lib.rs`, claim
// `parfast-mmap-threshold-bounded-15sep`): an allocator setting that
// buys memory when memory is bounded and may cost speed when it is not,
// applied only where something bounds the heap.
//
// The test is a cgroup limit BELOW physical RAM, which is that twin's
// cgroup arm spelled the same way (`parfast::bounded`): a limit at or
// above RAM is a container given the whole machine and bounds nothing,
// so paying an allocator cost there would buy nothing, and a limit with
// RAM unreadable is taken at its word. What this does NOT count as
// bounded, where the twin does, is a PUBLISHED budget - `--mem-limit`,
// the `mem_limit` setting, an embedded host's `mem_limit_bytes`. Those
// bound what the engine plans for, not what the kernel will kill for,
// and every kill this change exists to prevent was a `CONSTRAINT_MEMCG`
// against a hard cap. On macOS `cgroup_mem_limit()` is the non-Linux
// stub and always answers None, so this is a no-op there rather than
// cfg'd out: reaching mimalloc's options is harmless on either platform
// the allocator above is installed on, and one cfg that matches the
// allocator's reads better than two that do not.
//
// `set_default` and not `set`, deliberately: it declines when an option
// was already initialized FROM THE ENVIRONMENT, so `MIMALLOC_PURGE_DELAY`
// still wins over this line. Every arm of the round above was set that
// way and the lane measuring the next one has to be able to override it.
// `MIMALLOC_VERBOSE=1` prints `option 'purge_delay'` and is how to check
// which of the two is in force.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn bounded_heap_purge_delay() {
    let bounded = match (nzbkit::mem::cgroup_mem_limit(), nzbkit::mem::physical_ram()) {
        (Some(limit), Some(ram)) => limit < ram,
        (Some(_), None) => true,
        (None, _) => false,
    };
    if !bounded {
        return;
    }
    // An explicit setting wins, and leaving NOW rather than relying on
    // `set_default` to decline is what keeps the readback below honest: a
    // lane running the `=500` arm of some future round would otherwise
    // read 500, fail the readback's test and be told its option index
    // looks wrong, which is a false alarm on stderr at every container
    // start. mimalloc looks its variables up under the lower-case name
    // first and the upper-case one second, and `purge_delay` still
    // answers to the legacy `reset_delay`, so all four spellings count.
    // A spelling missed here is not a correctness bug, only a return to
    // the readback path.
    if ["MIMALLOC_PURGE_DELAY", "MIMALLOC_RESET_DELAY"]
        .iter()
        .any(|k| std::env::var_os(k).is_some() || std::env::var_os(k.to_lowercase()).is_some())
    {
        return;
    }
    // `libmimalloc-sys` does not export `mi_option_purge_delay` - its
    // option constants are a hand-maintained sparse subset - and the
    // indices are positions in a C table, so a wrong one would set a
    // DIFFERENT option in silence. Two things stop that. The index is
    // derived from the neighbour the sys crate does export
    // unconditionally: purge_delay sits immediately before
    // use_numa_nodes in the table, in both the v2 and the v3 sources
    // the crate vendors, so a shift above it moves both together.
    // (`mi_option_eager_commit_delay`, the neighbour on the other side,
    // is `feature = "v2"` only - v3 renamed that slot deprecated - so it
    // is not an anchor.) And the value is read back first: with nothing
    // set in the environment - which the early return above has already
    // established - purge_delay is the only option in that neighbourhood
    // defaulting to 1,000 (v3) or 10 (v2), so anything else means the
    // table was REORDERED and we decline rather than write to whatever
    // now lives there. Failing to find is failing, so say so on the way
    // out.
    const PURGE_DELAY: libmimalloc_sys::mi_option_t = libmimalloc_sys::mi_option_use_numa_nodes - 1;
    // SAFETY: both calls take a plain `c_int` option index and touch
    // only mimalloc's own option table. mimalloc documents them as not
    // thread safe; this runs on the main thread before any work starts.
    // The index is checked by the readback below before anything is set.
    unsafe {
        let current = libmimalloc_sys::mi_option_get(PURGE_DELAY);
        if current != 1000 && current != 10 {
            eprintln!(
                "nzbfast: mimalloc purge_delay option index looks wrong (read {current}); \
                 leaving the allocator alone. See crates/nzbfast/src/main.rs."
            );
            return;
        }
        libmimalloc_sys::mi_option_set_default(PURGE_DELAY, 10);
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn bounded_heap_purge_delay() {}

fn main() -> anyhow::Result<()> {
    bounded_heap_purge_delay();
    nzbfast::cli_main()
}
