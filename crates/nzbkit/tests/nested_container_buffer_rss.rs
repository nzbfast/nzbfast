//! The nested-chase CONTAINER buffer: does the one-pass chase hold a
//! whole inner container in RAM, and is that buffer bounded by anything?
//!
//! Follow-up to the TODO 209 dict-window rig
//! (`research/NOTE-2026-08-22-lzma-dict-window-rss.md`), which surfaced a
//! ~512 MiB "largest single alloc" that was NOT the LZMA dictionary
//! window: it was present before and after the window fix and it scales
//! with CONTAINER size, not dictionary size.
//!
//! Deliberately LZMA-free - every level is a STORE entry over
//! incompressible bytes - so the container term is measured on its own,
//! with no dictionary window anywhere in the process.
//!
//!   cargo test -p nzbkit --release --features heavy-tests \
//!     --test nested_container_buffer_rss -- --ignored --nocapture
//!
//! `#[ignore]` because each arm allocates hundreds of MiB.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

use nzbkit::extract::Extractor;
use nzbkit::mem::MemBudget;
use nzbkit::zip::fixtures;

// ---- tracking global allocator -------------------------------------------

struct Track;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static BIG: AtomicUsize = AtomicUsize::new(0);

// SAFETY: `GlobalAlloc`'s contract is that the implementation behaves as
// an allocator: every pointer it returns is either null or a fresh block
// fitting the requested `Layout`, and `dealloc`/`realloc` are given back
// exactly the (pointer, layout) pairs it handed out. This one delegates
// all three to `System`, which upholds all of that, and adds only
// relaxed atomic counter arithmetic - no allocation of its own, so it
// cannot re-enter, and no pointer is derived or altered here.
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: `l` is forwarded untouched to the system allocator,
        // and this function's own caller already owes it the validity
        // `GlobalAlloc::alloc` requires (a non-zero-size layout).
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let cur = LIVE.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(cur, Relaxed);
            BIG.fetch_max(l.size(), Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: `alloc`/`realloc` above return `System`'s own
        // pointers unchanged, so the (p, l) pair the caller hands back
        // is one `System` itself issued under the same layout.
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        // SAFETY: same argument as `dealloc` - `p` came from `System`
        // under layout `l` - and `new` is passed through unchanged, so
        // the caller's guarantee that it is a valid size for `l`'s
        // alignment carries straight over.
        let np = unsafe { System.realloc(p, l, new) };
        if !np.is_null() {
            if new >= l.size() {
                let cur = LIVE.fetch_add(new - l.size(), Relaxed) + (new - l.size());
                PEAK.fetch_max(cur, Relaxed);
            } else {
                LIVE.fetch_sub(l.size() - new, Relaxed);
            }
            BIG.fetch_max(new, Relaxed);
        }
        np
    }
}

#[global_allocator]
static A: Track = Track;

fn live() -> usize {
    LIVE.load(Relaxed)
}
fn reset_peak() {
    PEAK.store(live(), Relaxed);
    BIG.store(0, Relaxed);
}
fn peak() -> usize {
    PEAK.load(Relaxed)
}
fn big() -> usize {
    BIG.load(Relaxed)
}

const MIB: usize = 1 << 20;

fn incompressible(n: usize, mut seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; n];
    for chunk in v.chunks_mut(8) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let b = seed.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
    v
}

/// A `depth`-deep nest of STORE zips over `payload_mib` of
/// incompressible bytes. Store keeps every level ~the same size, so the
/// container term is the same at every level and a stacking sum is
/// unmistakable.
fn nested_store_zip(depth: usize, payload_mib: usize) -> Vec<u8> {
    let mut cur = incompressible(payload_mib * MIB, 0xfeed_1234);
    let mut name = String::from("payload.bin");
    for lvl in (0..depth).rev() {
        cur = fixtures::zip_of(&[fixtures::Spec::stored(&name, &cur)]);
        name = format!("l{lvl}.zip");
    }
    cur
}

/// Feed `container` to slot 0 front-to-back, one ~700 KB article at a
/// time - the arrival order the chase actually sees for a body it is
/// downloading in order.
fn feed(ex: &Extractor, name: &str, container: &[u8]) {
    let art = 700_000usize;
    let total = container.len() as u64;
    let mut off = 0usize;
    while off < container.len() {
        let end = (off + art).min(container.len());
        ex.write(0, name, total, off as u64, &container[off..end])
            .unwrap();
        off = end;
    }
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbkit-ctnrss-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct Arm {
    peak_delta_mib: usize,
    largest_mib: usize,
    retained_peak_mib: usize,
    fallbacks: usize,
    first_fallback: String,
}

/// Run one nest at one holds cap. `cap` None = the PRE-TODO-260 bare
/// `Extractor::new` default, a flat 2 GiB - the shape the 209 rig
/// unknowingly measured; Some(c) = what `get` wires from
/// `MemBudget::holds_cap()` in production.
///
/// Since TODO 260 the ctor takes its default from the published process
/// budget, so `None` has to say the 2 GiB out loud to keep reproducing
/// the unwired arm at all - which is the whole point of the fix: nothing
/// gets that cap by accident any more.
fn run(tag: &str, depth: usize, payload_mib: usize, cap: Option<usize>) -> Arm {
    let z = nested_store_zip(depth, payload_mib);
    let top_mib = z.len() / MIB;
    let dir = tmp(tag);
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_nested_max_depth(6);
    ex.set_holds_cap(cap.unwrap_or(2 << 30));

    // Sample the CHARGED retained bytes (this extractor and every child)
    // beside the allocator peak: if the two move together the container
    // buffer is tracked, and if the allocator peak runs far ahead of the
    // charge there is an untracked term.
    let stop = Arc::new(AtomicBool::new(false));
    let retained_peak = Arc::new(AtomicUsize::new(0));
    let watcher = {
        let ex = ex.clone();
        let stop = stop.clone();
        let rp = retained_peak.clone();
        std::thread::spawn(move || {
            while !stop.load(Relaxed) {
                rp.fetch_max(ex.chase_retained_bytes(), Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            rp.fetch_max(ex.chase_retained_bytes(), Relaxed);
        })
    };

    let base = live();
    reset_peak();
    let t0 = std::time::Instant::now();
    let c0 = nzbkit::mem::cpu_user_sys_secs();
    feed(&ex, "release.zip", &z);
    let rep = ex.finish().unwrap();
    let elapsed = t0.elapsed();
    let c1 = nzbkit::mem::cpu_user_sys_secs();
    let cpu = match (c0, c1) {
        (Some((u0, s0)), Some((u1, s1))) => (u1 - u0) + (s1 - s0),
        _ => f64::NAN,
    };
    let pk = peak();
    let biggest = big();
    stop.store(true, Relaxed);
    watcher.join().unwrap();

    let arm = Arm {
        peak_delta_mib: pk.saturating_sub(base) / MIB,
        largest_mib: biggest / MIB,
        retained_peak_mib: retained_peak.load(Relaxed) / MIB,
        fallbacks: rep.fallbacks.len(),
        first_fallback: rep
            .fallbacks
            .first()
            .map(|f| format!("{f:?}"))
            .unwrap_or_default(),
    };
    eprintln!(
        "[{tag}] depth={depth} payload={payload_mib} MiB top_container={top_mib} MiB cap={} \
         peak_delta={} MiB largest_alloc={} MiB retained_peak={} MiB fallbacks={} {} elapsed={:?} cpu_s={:.3}",
        cap.map_or("default(2 GiB)".to_string(), |c| format!("{} MiB", c / MIB)),
        arm.peak_delta_mib,
        arm.largest_mib,
        arm.retained_peak_mib,
        arm.fallbacks,
        arm.first_fallback,
        elapsed,
        cpu,
    );
    let _ = std::fs::remove_dir_all(&dir);
    arm
}

/// Does the peak scale with DEPTH at a fixed container size? If each
/// level's container is buffered whole, the peak is ~depth x container.
#[test]
#[ignore = "allocates >1 GiB; the nested-container-buffer reproducer"]
fn nested_container_buffer_scales_with_depth() {
    nzbkit::mem::set_process_budget(MemBudget::with_total(256 * MIB as u64));
    let mut peaks = Vec::new();
    for depth in 1..=5 {
        let a = run(&format!("depth{depth}"), depth, 100, None);
        peaks.push(a.peak_delta_mib);
    }
    eprintln!("[depth-ladder] peak_delta per depth (MiB): {peaks:?}");
}

/// The production wiring: `get` calls `set_holds_cap(budget.holds_cap())`
/// (crates/nzbfast-engine/src/get/vrig.rs). Does the existing trim/forfeit
/// ladder bound the container buffer once the cap is actually wired?
#[test]
#[ignore = "allocates >1 GiB; the nested-container-buffer reproducer"]
fn production_holds_cap_bounds_the_nested_container_buffer() {
    let budget = MemBudget::with_total(256 * MIB as u64);
    nzbkit::mem::set_process_budget(budget);
    let cap = MemBudget::with_total(256 * MIB as u64).holds_cap();
    eprintln!("[prod] holds_cap = {} MiB", cap / MIB);
    let bare = run("pre-260-default-cap", 5, 100, None);
    let wired = run("prod-cap", 5, 100, Some(cap));
    eprintln!(
        "[prod] default-cap peak {} MiB vs wired-cap peak {} MiB (cap {} MiB)",
        bare.peak_delta_mib,
        wired.peak_delta_mib,
        cap / MIB
    );
}

/// WHERE the big allocation comes from. `FrontierState::data` is a plain
/// `Vec<u8>` grown by `extend_from_slice`, so its capacity is the
/// doubling ladder of the FIRST span it ever accepted:
///
///   * the ROOT container's spans are articles (700 KB here), ladder
///     700_000 x 2^k -> ..., 85.4, 170.9, 341.8 MiB
///   * a CHILD container's spans are the parent chase's copy buffer
///     (64 KiB, `extract/zip.rs`), ladder 65_536 x 2^k -> ..., 128, 256,
///     512 MiB
///
/// The prediction this test stands on: at a ~140 MiB container, depth 1
/// (root only) allocates 170.9 MiB, while depth 2 puts a ~140 MiB
/// container on the CHILD ladder, whose next rung above 128 MiB is 256 -
/// so the largest allocation JUMPS to 256 MiB even though not one byte
/// more is retained. If the peak were a separate whole-container buffer
/// rather than this growth overshoot, the two would not differ.
#[test]
#[ignore = "allocates >1 GiB; the nested-container-buffer reproducer"]
fn the_big_alloc_is_the_frontier_vec_growth_ladder() {
    nzbkit::mem::set_process_budget(MemBudget::with_total(256 * MIB as u64));
    for payload in [60usize, 100, 140] {
        let d1 = run(&format!("ladder-d1-{payload}"), 1, payload, None);
        let d2 = run(&format!("ladder-d2-{payload}"), 2, payload, None);
        eprintln!(
            "[ladder] payload={payload} MiB  depth1_largest={} MiB  depth2_largest={} MiB  \
             depth1_retained={} MiB  depth2_retained={} MiB",
            d1.largest_mib, d2.largest_mib, d1.retained_peak_mib, d2.retained_peak_mib
        );
    }
}
