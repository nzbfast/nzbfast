//! TODO 209 items 2 & 3 - the dict-window RSS rig.
//!
//! Measures, with a tracking global allocator, whether the LZMA decode
//! windows of a nested chain of zip method-14 containers are LIVE at the
//! same time (item 2: do outer and inner dictionaries STACK across
//! `nested_max_depth`?) and whether that RSS is bounded by `MemBudget`
//! (item 3: the window is allocated inside the decoder, invisible to the
//! budget whose auto floor is one dictionary's worth).
//!
//! Not settled by reading, per the section. Run with:
//!   cargo test -p nzbkit --features heavy-tests --test lzma_dict_window_rss -- --ignored --nocapture
//! The two tests are `#[ignore]` because each allocates >1 GiB and takes
//! seconds; they are the committed reproducer, not a per-push regression
//! (the remedy carries its own fast test).
//!
//! Method - the decode window is `min(declared_dict, uncompressed_size)`
//! allocated in ONE `try_reserve_exact` (verified in lzma-rust2's
//! `LzDecoder::ensure_capacity`), and its size is independent of the
//! stream's real match distances. So each level is incompressible random
//! bytes (keeps every level's uncompressed content above the window) that
//! the fixtures encode with a cheap 64 KiB dict while DECLARING the big
//! window - byte-identical decode-side RSS to a genuine `-mx=9` archive.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

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
/// Re-baseline the peak to the current live count (after the fixtures are
/// built) so the reported peak is the extraction's, not the build's.
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

/// Fill `n` bytes of incompressible data with a cheap xorshift PRNG.
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

/// One method-14 container declaring `dict` over `data`.
fn lzma_container(name: &str, data: &[u8], dict: u32) -> Vec<u8> {
    fixtures::zip_of(&[fixtures::Spec::lzma_with_dict(name, data, dict)])
}

/// Feed `container` to `ex` slot 0 as `name`, one article at a time in
/// natural (front-to-back) arrival order.
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
    let d = std::env::temp_dir().join(format!("nzbkit-dictrss-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Item 3 - a SINGLE legitimate -mx=9-shaped entry spends one full 256 MiB
/// window, and it does so under a 256 MB process budget without refusal:
/// the window is not charged to `MemBudget`.
#[test]
#[ignore = "allocates 256 MiB; the dict-window RSS reproducer"]
fn single_window_is_one_dictionary_and_unbudgeted() {
    // Auto floor is 256 MB == exactly one dictionary. Pin the budget AT
    // the floor and watch a single window spend the whole thing, unseen.
    nzbkit::mem::set_process_budget(MemBudget::with_total(256 * MIB as u64));

    let dict = 256 * MIB as u32;
    let payload = incompressible(260 * MIB, 0x1234_5678);
    let z = lzma_container("payload.bin", &payload, dict);
    drop(payload);

    let dir = tmp("single");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    // TODO 260 made the ctor inherit the published budget's 45% holds
    // slice, which here would be 115 MiB - tight enough to demote and
    // confound the one term this rig exists to isolate. Pin the
    // pre-260 flat default explicitly so the banked numbers stay
    // reproducible; pricing the window UNDER the production cap is a
    // different measurement, and a separate one.
    ex.set_holds_cap(2 << 30);

    let base = live();
    reset_peak();
    feed(&ex, "release.zip", &z);
    let rep = ex.finish().unwrap();
    let pk = peak();
    let biggest = big();

    eprintln!(
        "[single] budget=256 MiB  baseline={} MiB  peak={} MiB  delta={} MiB  largest_alloc={} MiB  WINDOW_PEAK={} MiB",
        base / MIB,
        pk / MIB,
        pk.saturating_sub(base) / MIB,
        biggest / MIB,
        nzbkit::mem::lzma_dict_peak() as usize / MIB
    );
    assert!(
        rep.fallbacks.is_empty(),
        "chase should not demote: {:?}",
        rep.fallbacks
    );
    // The single window is ~256 MiB and it is the largest allocation.
    assert!(
        biggest >= 240 * MIB,
        "expected a ~256 MiB window, saw {} MiB",
        biggest / MIB
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Item 2 - the windows STACK. A 5-deep nest of method-14 containers, each
/// declaring 256 MiB, drives five chase levels whose windows are live at
/// once. Peak should approach 5 x 256 MiB = 1.25 GiB.
#[test]
#[ignore = "allocates >1 GiB; the dict-window RSS reproducer"]
fn nested_windows_stack_across_depth() {
    nzbkit::mem::set_process_budget(MemBudget::with_total(256 * MIB as u64));

    let dict = 256 * MIB as u32;
    // Innermost payload just over one window so its container's declared
    // window is fully sized; every wrapping level is ~the same size
    // (incompressible), so all five windows are 256 MiB.
    let mut cur = incompressible(260 * MIB, 0xdead_beef);
    let mut name = String::from("payload.bin");
    for lvl in (0..5).rev() {
        cur = lzma_container(&name, &cur, dict);
        name = format!("l{lvl}.zip");
    }
    eprintln!("[nested] top container = {} MiB", cur.len() / MIB);

    let dir = tmp("nested");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    // Default nested_max_depth is 5; make it explicit.
    ex.set_nested_max_depth(5);
    // TODO 260 made the ctor inherit the published budget's 45% holds
    // slice, which here would be 115 MiB - tight enough to demote and
    // confound the one term this rig exists to isolate. Pin the
    // pre-260 flat default explicitly so the banked numbers stay
    // reproducible; pricing the window UNDER the production cap is a
    // different measurement, and a separate one.
    ex.set_holds_cap(2 << 30);

    let base = live();
    reset_peak();
    feed(&ex, "release.zip", &cur);
    let rep = ex.finish().unwrap();
    let pk = peak();
    let biggest = big();

    let delta = pk.saturating_sub(base) / MIB;
    let win_peak = nzbkit::mem::lzma_dict_peak() as usize / MIB;
    eprintln!(
        "[nested] budget=256 MiB  baseline={} MiB  peak_rss={} MiB  delta_rss={} MiB  largest_alloc={} MiB  WINDOW_PEAK={} MiB",
        base / MIB,
        pk / MIB,
        delta,
        biggest / MIB,
        win_peak
    );
    eprintln!("[nested] fallbacks: {:?}", rep.fallbacks);

    // Post-fix (mem::charge_lzma_dict): the 256 MiB budget admits one
    // window; a second concurrent window would make 512 MiB > cap, so it
    // is refused and its container demotes to the sequential disk pass.
    // The direct measure of item 2 is the WINDOW peak (the gauge), not
    // total RSS - the residual RSS is the child extractor's per-level
    // container buffering, a SEPARATE untracked allocation this rig
    // surfaced (see the research note; out of scope for the dict window).
    // Pre-fix the window peak was 1280 MiB (5 x 256); it is now one
    // window, and the demotions are visible as fallbacks.
    assert!(
        !rep.fallbacks.is_empty(),
        "the deeper windows should demote, not stack"
    );
    assert!(
        win_peak <= 2 * 256,
        "windows still stacking: window_peak={win_peak} MiB (pre-fix 1280)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 260 follow-up - the same 5-deep nest with NO `set_holds_cap`
/// call, so the extractor runs at the cap it inherits from the published
/// budget (45% of 256 MiB = 115 MiB), which is what production does.
/// Settles whether the holds cap incidentally bounds the window stack
/// (ladder demotes before the nest reaches depth 5) or whether the window
/// term is independent of it. No assertions on the shape beyond
/// completion: this arm REPORTS, the two above pin the banked numbers.
///
/// `mem::lzma_dict_peak()` is a process-wide high-water that nothing
/// resets, so when all three arms share a process this arm inherits the
/// nested arm's 256 MiB. Run it ALONE for an honest WINDOW_PEAK
/// (measured 23 Aug 2026: 0 MiB alone, 256 MiB in the shared run).
#[test]
#[ignore = "allocates >1 GiB; the dict-window RSS reproducer, production holds cap"]
fn nested_windows_under_production_holds_cap() {
    nzbkit::mem::set_process_budget(MemBudget::with_total(256 * MIB as u64));

    let dict = 256 * MIB as u32;
    let mut cur = incompressible(260 * MIB, 0xdead_beef);
    let mut name = String::from("payload.bin");
    for lvl in (0..5).rev() {
        cur = lzma_container(&name, &cur, dict);
        name = format!("l{lvl}.zip");
    }
    eprintln!("[prodcap] top container = {} MiB", cur.len() / MIB);

    let dir = tmp("prodcap");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_nested_max_depth(5);
    // Deliberately NO set_holds_cap: inherit the production slice.
    let cap = ex.holds_cap();

    let base = live();
    reset_peak();
    let t0 = std::time::Instant::now();
    feed(&ex, "release.zip", &cur);
    let rep = ex.finish().unwrap();
    let secs = t0.elapsed().as_secs_f64();
    let pk = peak();
    let biggest = big();

    eprintln!(
        "[prodcap] budget=256 MiB  holds_cap={} MiB  holds_peak={} MiB  baseline={} MiB  peak_rss={} MiB  delta_rss={} MiB  largest_alloc={} MiB  WINDOW_PEAK={} MiB  wall={secs:.1}s",
        cap / MIB,
        ex.holds_peak() / MIB,
        base / MIB,
        pk / MIB,
        pk.saturating_sub(base) / MIB,
        biggest / MIB,
        nzbkit::mem::lzma_dict_peak() as usize / MIB
    );
    eprintln!("[prodcap] fallbacks: {:?}", rep.fallbacks);
    assert!(
        cap < 2 << 30,
        "this arm must run at the inherited cap, not the pinned 2 GiB (got {} MiB)",
        cap / MIB
    );

    let _ = std::fs::remove_dir_all(&dir);
}
