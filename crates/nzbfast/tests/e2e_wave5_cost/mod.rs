//! Extreme Wave 5, the arithmetic-and-cost rows: regression pins for
//! X5-17 and X5-18.
//!
//! These landed WITH their fixes, which is what separates them from the
//! verification probes they were extracted from - a probe that asserts
//! the correct behavior of an unfixed row is red by design and belongs
//! on a branch. The subject-scoped module name (rather than a shared
//! `e2e_wave5`) is deliberate: four other Wave 5 lanes were fixing
//! unrelated rows in parallel and each owns its own files, so nobody
//! merges a 74 KB probe file against anybody.
//!
//! X5-16's own pins cannot live here - `pick_volumes` is `pub(crate)` -
//! so they are in-crate at `crates/nzbfast/src/repair/wave5_probe_tests.rs`.
//!
//! BOTH rows are graded as a RATIO over geometric N and never as a wall
//! clock. That is not caution about slow CI, it is the only grading that
//! means anything here: this box routinely runs several lanes' cargo
//! builds at once, so an absolute limit measures the box's load, while
//! the ratio between two sizes of the SAME work on the SAME box does
//! not. If you tighten either bar, keep the ratio form. Both also carry
//! a guard that says the timed loop reached the thing it is timing, so a
//! run that measured nothing shows a zero rather than a pass - do not
//! remove those.
//!
//! # Three rules this file learned the hard way (31 Aug 2026)
//!
//! X5-18 was flaky - 2 runs in 8 over its bar, and once inside a full
//! `--test e2e` run where nextest RETRIED it and reported "331 passed
//! (1 flaky)" at exit 0. `--test e2e` is one of the seven heavy-tests
//! targets CLAUDE.md's documented sweep excludes BY NAME, so per-push CI
//! never runs this file and only nightly's `long-suites` would ever have
//! seen it. Three things came out of fixing it, and every one of them
//! applies to the next cost row anybody adds here:
//!
//! 1. **Take the MINIMUM of several trials, never one sample.** The
//!    failure was one descheduled instant inside a single-sample
//!    measurement of a few milliseconds - the 4.39x run had a nominal
//!    7.5 ms `a` and a 33 ms `b` against a nominal 17 ms. See
//!    [`TRIALS`].
//! 2. **Keep count-independent constants out of the timed region.** Both
//!    a whole-block hash on completion and per-byte work over a larger
//!    payload land identically in both halves of a ratio, so they can
//!    only dilute the verdict - a bigger payload makes the measurement
//!    longer and the test BLINDER. Lengthen with repetitions
//!    ([`REPS`]), which scale both halves equally. See
//!    [`feed_disjoint_secs`].
//! 3. **Derive the bar by measuring the REGRESSION, not by taste.** Both
//!    X5-18 bars below sit between a measured span for the current tree
//!    and a measured span for the pre-fix shape re-injected into the same
//!    paths, near the geometric mean of the two. A bar with no measured
//!    distance to a regressed tree is a bar that cannot say it catches
//!    anything - the 3.0 this row shipped with had 19% of clearance on
//!    each side, which is how it came to fail 2 runs in 8.

use super::*;
use md5::Digest as _;

// ------------------------------------------------ packet construction

/// Build one structurally valid PAR2 packet: header + body, sealed with
/// the packet MD5 the scanner checks (MD5 of set id + type + body).
fn build_packet(set_id: &[u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    assert!(
        body.len().is_multiple_of(4),
        "PAR2 packet bodies are 4-byte aligned"
    );
    let len = 64 + body.len();
    let mut p = Vec::with_capacity(len);
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&(len as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // md5, filled below
    p.extend_from_slice(set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let digest: [u8; 16] = md5::Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&digest);
    p
}

/// A RecvSlic packet: body is the exponent (u32 LE) then the slice data.
fn recvslic(set_id: &[u8; 16], exponent: u32, slice: &[u8]) -> Vec<u8> {
    let mut body = exponent.to_le_bytes().to_vec();
    body.extend_from_slice(slice);
    build_packet(set_id, b"PAR 2.0\0RecvSlic", &body)
}

// ---------------------------------------------------------------- X5-17

/// X5-17: the recovery census must stay near-linear in DISTINCT
/// grouping keys. `recovery_slice_census` runs `out.iter_mut().find(..)`
/// over every key it has already seen before pushing a new one, so a
/// buffer of packets with all-distinct `(set_id, slice_data_length)`
/// keys costs O(N^2) comparisons.
///
/// Graded as a RATIO over geometric N rather than an absolute wall time,
/// so the verdict does not move with the host: at 4x the packets, a
/// linear census costs ~4x and a quadratic one ~16x. The bar is 8x -
/// generous enough that load cannot manufacture a red, tight enough
/// that quadratic cannot hide.
///
/// CHARACTERISED 31 Aug 2026 (dev Mac, debug, load average 21-39), which
/// it never had been - it was landed on one 4,000/16,000 pair and "it has
/// not failed yet", which is exactly what its sibling X5-18 below was
/// before that row went flaky at 2 runs in 8. Median of 9, one packet
/// buffer per size: 1,000: 2.61 ms; 2,000: 5.29; 4,000: 10.68; 8,000:
/// 20.49; 16,000: 45.5; 32,000: 95.1. That is 2.0x per doubling over five
/// doublings - genuinely linear, unlike X5-18's, so the counts here can
/// be raised freely if the measurement ever needs lengthening. The 4x
/// step measures 4.24x against the 8.0 bar, 1.9x of headroom.
///
/// It takes the same minimum-over-[`TRIALS`] estimator as X5-18 anyway.
/// The flake there was not a wrong bar, it was one descheduled instant
/// landing in a single sample, and nothing about this row is immune to
/// that: `b` here need only be interfered with by 1.9x to manufacture a
/// red on a healthy tree.
///
/// AND IT DID, the same day the sentence above was written. Observed
/// 31 Aug 2026 by the M4-75/M4-90 lane, which was running the e2e suite
/// while FOUR other worktrees ran it too: this row was the only failure
/// in 333, on both nextest attempts, and it passed SOLO in 0.763 s
/// immediately afterwards on the same tree. So the 1.9x is not a
/// theoretical margin - ordinary fleet load reaches it, and this box
/// routinely carries several sessions at once.
///
/// Recorded rather than acted on, deliberately: the row is CORRECT and
/// the tree was healthy, so there is nothing here to fix in the census.
/// The remedy if it recurs is the one this comment already names - raise
/// [`TRIALS`], or raise the counts, both of which are free here because
/// the cost is genuinely linear. Do NOT raise the 8.0 bar; that is the
/// only number in the row that carries the finding, and X5-18's own flake
/// was fixed by lengthening the measurement rather than by widening the
/// verdict.
#[test]
fn x5_17_the_recovery_census_must_not_be_quadratic_in_distinct_keys() {
    /// One buffer of `n` RecvSlic packets, each with its own set id, so
    /// every packet is a new grouping key. Slice bytes are tiny: this
    /// row is about comparisons, not about hashing volume.
    fn buffer(n: u32) -> Vec<u8> {
        let mut v = Vec::with_capacity(n as usize * 76);
        for i in 0..n {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&i.to_le_bytes());
            v.extend_from_slice(&recvslic(&id, i, &[0u8; 8]));
        }
        v
    }
    fn census_secs(buf: &[u8]) -> f64 {
        let t = std::time::Instant::now();
        let out = nzbkit::par2repair::recovery_slice_census(buf);
        let d = t.elapsed().as_secs_f64();
        assert!(!out.is_empty(), "census reached no packets");
        d
    }
    /// The cheapest of [`TRIALS`] runs - see that constant for why the
    /// minimum and not one sample. No `REPS` here: one census of 4,000
    /// packets is already ~10 ms, so the timed region needs no
    /// lengthening.
    fn census_best(buf: &[u8]) -> f64 {
        (0..TRIALS)
            .map(|_| census_secs(buf))
            .fold(f64::INFINITY, f64::min)
    }

    let small = buffer(4_000);
    let large = buffer(16_000);
    assert_eq!(
        nzbkit::par2repair::recovery_slice_census(&large).len(),
        16_000,
        "every packet must be its own key for this to measure the find()"
    );
    // Warm both paths once so allocation/first-touch is not in the ratio.
    let _ = census_secs(&small);
    let _ = census_secs(&large);
    let a = census_best(&small).max(1e-6);
    let b = census_best(&large);
    let ratio = b / a;
    assert!(
        ratio < 8.0,
        "census cost grew {ratio:.1}x for 4x the distinct keys \
         ({a:.4}s -> {b:.4}s): the per-packet linear scan over already \
         seen keys is quadratic"
    );
}

// ---------------------------------------------------------------- X5-18

/// Build a real PAR2 set over `data` with an explicit block size, and
/// return (index bytes, the payload's member name).
fn par2_over(dir: &Path, name: &str, data: &[u8], block: u64) -> Vec<u8> {
    std::fs::write(dir.join(name), data).unwrap();
    let st = Command::new("par2")
        .args(["create", &format!("-s{block}"), "-r5", "-q", "x18set", name])
        .current_dir(dir)
        .status();
    assert!(
        st.map(|s| s.success()).unwrap_or(false),
        "par2 create failed"
    );
    std::fs::read(dir.join("x18set.par2")).unwrap()
}

/// Drive `frags` disjoint fragments of one large PAR2 block into a live
/// verifier in an every-other-then-fill order (so almost nothing merges
/// until late) and return the wall time of the FEED alone.
///
/// The head is delivered whole first: the matcher claims a slot on the
/// md5-16k of its first 16 KiB, and until it does the slot belongs to no
/// file, no block map exists and the interval tracker this row is about
/// is never reached. Head bytes are outside the timed region.
///
/// The LAST fragment is deliberately withheld, so the block never
/// completes inside the timed region. That is not tidiness - completion
/// runs a hash of the WHOLE BLOCK, a cost proportional to the payload and
/// INDEPENDENT of the fragment count, and it lands identically in both
/// halves of the ratio, so it can only ever dilute the verdict. Measured
/// 31 Aug 2026 on the dev Mac: the full-MD5 arm at 4,096 fragments over a
/// 1 MiB block read 15.4 ms with the block completing and 3.0 ms without,
/// i.e. 80% of what that arm was timing was one MD5 that says nothing
/// about interval tracking. Withholding it also removes an ugly
/// discontinuity - `rest / frags` tiles the block exactly only when it
/// divides, so the constant dropped in and out as the count changed
/// (16,384 fragments: 17.2 ms; 32,768: 53.8 ms; 65,536: 184.6 ms with the
/// same total bytes, because the first tiles and the other two do not).
fn feed_disjoint_secs(par2: &[u8], name: &str, data: &[u8], frags: usize, lean: bool) -> f64 {
    let (v, order, step) = prime(par2, name, data, frags, lean);
    let t = std::time::Instant::now();
    for i in order {
        let off = HEAD + i * step;
        v.on_data(
            0,
            name,
            data.len() as u64,
            off as u64,
            &data[off..off + step],
        );
    }
    t.elapsed().as_secs_f64()
}

const HEAD: usize = 16 * 1024;

/// A verifier with the head delivered and the slot claimed, plus the
/// arrival order and fragment size the timed loop walks. Everything here
/// is setup and must stay OUTSIDE the timer.
fn prime(
    par2: &[u8],
    name: &str,
    data: &[u8],
    frags: usize,
    lean: bool,
) -> (nzbkit::live::LiveVerifier, Vec<usize>, usize) {
    let v = nzbkit::live::LiveVerifier::new(1);
    // `fast_verify` off is the FULL-MD5 byte-buffer path (`Partial`);
    // on is the default CRC composition path (`CrcParts`).
    v.set_fast_verify(lean);
    v.set_name_hint(0, name);
    v.activate(&[par2]).expect("set activates");
    v.on_data(0, name, data.len() as u64, 0, &data[..HEAD]);
    assert!(
        v.slot_in_set(0),
        "slot 0 never claimed a set member, so the feed below measures \
         nothing (this guard is why an inert run cannot read as a pass)"
    );
    let step = (data.len() - HEAD) / frags;
    let order: Vec<usize> = (0..frags)
        .step_by(2)
        .chain((1..frags).step_by(2))
        .filter(|&i| i != frags - 1)
        .collect();
    (v, order, step)
}

/// How many feeds are summed inside one timed measurement, and how many
/// such measurements are taken. The MINIMUM of the sums is the estimate.
///
/// Both numbers exist because of one measured failure. On 31 Aug 2026
/// this row was flaky at 2 runs in 8 (4.05x and 4.39x against a 3.0 bar)
/// and it failed inside a full `--test e2e` run and PASSED on nextest's
/// retry, so the run reported "331 passed (1 flaky)" at exit 0 - a wedge
/// that reaches no job's verdict, which is CLAUDE.md's FORTY-FIRST gate's
/// whole subject. Neither half of the estimator is optional:
///
///   * `REPS` makes the timed region long enough to be a measurement.
///     A stall of a single scheduler quantum is a large fraction of one
///     short feed, and the short feed is the SMALL half of the ratio -
///     which is the half a stall inflates the verdict from. It was 16
///     while X5-18 measured 1,024 fragments against 4,096, where one feed
///     was 1.7 ms; the counts are 16,128 and 64,512 since the tracking
///     became near-linear (31 Aug 2026) and one feed is now 33 ms, so
///     two of them is already a longer timed region than sixteen used to
///     be. Lowering it was not an economy - at 16 this file would take
///     over a minute.
///   * `TRIALS` with a MINIMUM is what actually kills the flake. Summing
///     is not robust - one descheduled instant lands in the sum - while
///     the minimum over independent trials is the standard estimator for
///     "what this work costs when nothing else is on the box". This
///     machine routinely runs several lanes' cargo builds at once; the
///     spread that produced the 4.39x is real and must be discarded, not
///     averaged in. Measured at load average 21-39: min-of-7 moved by
///     3-7% run to run where a single sample moved by 2.6x.
///
/// Their PRODUCT is bounded by the run cost, so the split between them
/// matters and was measured rather than picked. 32x5 and 16x9 cost the
/// same wall clock; the second is better, because what defeats a minimum
/// is interference that outlives a whole TRIAL, so short trials taken
/// often dodge a burst that long trials taken rarely all sit inside. At
/// 32x5 one full-MD5 run in eight read 7.02x against its 8.0 bar with
/// every other run at 4.4-4.5x - one burst spanning all five trials. Do
/// not trade TRIALS away for REPS.
const REPS: usize = 2;
const TRIALS: usize = 9;

/// The two fragment counts both X5-18 arms grade over, a 4x step apart.
///
/// Shared by the arms rather than spelled twice: the pair is one decision
/// (see the CRC arm's `Why the counts are 16,128 and 64,512`), and a lane
/// that raised one arm's counts without the other would silently be
/// comparing two different questions against two bars derived for a third.
/// They are also both exact divisors of the 1,032,192-byte payload past
/// the head - do not round them to powers of two, which is the one edit
/// that looks tidier and quietly re-introduces the tiling discontinuity
/// [`feed_disjoint_secs`] documents.
const SMALL: usize = 16_128;
const LARGE: usize = 64_512;

/// The cost of tracking `frags` disjoint fragments: the smallest sum of
/// [`REPS`] feeds over [`TRIALS`] independent trials.
fn tracking_secs(par2: &[u8], name: &str, data: &[u8], frags: usize, lean: bool) -> f64 {
    // Warm the path once so first-touch allocation is in nobody's sum.
    let _ = feed_disjoint_secs(par2, name, data, frags, lean);
    (0..TRIALS)
        .map(|_| {
            (0..REPS)
                .map(|_| feed_disjoint_secs(par2, name, data, frags, lean))
                .sum::<f64>()
        })
        .fold(f64::INFINITY, f64::min)
        .max(1e-6)
}

/// The guard that says the timed loop above tracked anything at all.
///
/// `slot_in_set` only proves the slot found its member; it says nothing
/// about whether the fragments then reached the interval tracker, and a
/// block can be dropped out of tracking silently - `CrcParts::insert`
/// answers false on an overlap and the caller abandons the block, and a
/// byte partial over the global budget is spilled to read-back. Either
/// leaves a feed that costs almost nothing and a ratio that reads as a
/// pass. So: deliver the withheld fragment too, and require the block to
/// come back VERIFIED. Only a losslessly tracked block can, because the
/// verdict is composed from exactly the fragments the tracker held.
///
/// Run once per (count, mode) and never inside the timed loop - for the
/// full-MD5 arm this is the whole-block hash the timing deliberately
/// excludes.
fn assert_tracking_is_lossless(par2: &[u8], name: &str, data: &[u8], frags: usize, lean: bool) {
    let (v, order, step) = prime(par2, name, data, frags, lean);
    for i in order.into_iter().chain(std::iter::once(frags - 1)) {
        let off = HEAD + i * step;
        v.on_data(
            0,
            name,
            data.len() as u64,
            off as u64,
            &data[off..off + step],
        );
    }
    let (verified, bad) = v.live_counts();
    let (_, spilled) = v.partials_stats();
    assert!(
        verified >= 1 && bad == 0 && spilled == 0,
        "{frags} fragments (lean={lean}) did not compose into a verified \
         block: verified={verified} bad={bad} spilled={spilled}. The timed \
         loop was therefore not measuring interval tracking"
    );
}

/// X5-18: partial-block interval tracking must not be quadratic in the
/// number of disjoint fragments. `Partial::fill` rebuilt AND SORTED the
/// whole interval vector for every fragment, and `CrcParts::insert` moves
/// elements with `Vec::insert`, so a deliberately disjoint arrival order
/// over one legal large block makes total work quadratic even though the
/// payload is small.
///
/// # The geometry, and why it is 4x and not 2x
///
/// A ratio over a 2x step separates linear (2x) from quadratic (4x) by a
/// factor of two, and there is no room in that for a bar. A 4x step
/// separates linear (4x) from quadratic (16x) by a factor of four, which
/// is the shape X5-17 above already uses.
///
/// # Why the counts are 16,128 and 64,512
///
/// They are high because THIS TEST IS DILUTED and the dilution is
/// unavoidable here. Every fragment goes through `on_data` - slot lock,
/// block-map lookup, a CRC32 of the fragment - and all of that is linear
/// in the fragment count, so it lands in both halves of the ratio and
/// drags the verdict toward 4x whatever the tracker is doing. Measured
/// 31 Aug 2026 at the OLD 1,024->4,096 counts, healthy against the
/// Vec-only shape re-injected: **3.60x against 3.61x**. The two are
/// indistinguishable, because at 4,096 fragments the tracker is a small
/// fraction of the feed and the Vec has not begun to hurt. At
/// 4,096->16,384 it is 4.10x against 5.58x - a 1.36x separation, which is
/// the clearance this row already went flaky on once.
///
/// So the counts sit where the quadratic term is actually the cost.
/// Measured over a 1 MiB block, current code against `RUNS_TREE_AT` set
/// to `usize::MAX` - i.e. exactly the sorted `Vec` that would come back if
/// somebody deleted the hybrid's promotion:
///
/// | step             | now   | Vec-only |
/// |------------------|-------|----------|
/// | 16,128 -> 64,512 | 4.24x | 8.97x    |
///
/// and the full-MD5 arm below reads 4.32x against 9.29x over the same
/// pair. The bar of **6.0** sits 1.42x above the healthy measurement and
/// 1.50x below the regressed one, which is where the old bar sat relative
/// to its own pair (1.47x / 1.51x) - so the clearance is preserved and
/// only the counts moved. The pre-`d5ad32c15` rebuild-and-sort is not
/// measured here because it does not need to be: it is the same O(n^2)
/// with a re-sort and an allocation ON TOP, so anything below the Vec-only
/// number catches it too.
///
/// BOTH COUNTS TILE THE BLOCK EXACTLY, and that is not a coincidence -
/// see [`feed_disjoint_secs`], which pays a constant that drops in and out
/// as the count divides or does not. The payload past the head is
/// 1,032,192 bytes = 2^14 x 63, so 65,536 does NOT divide it and 64,512
/// (63 x 1,024, step 16) does, with 16,128 (63 x 256, step 64) exactly a
/// quarter of it.
///
/// # What a and b measure
///
/// `a` and `b` are [`REPS`] feeds summed and minimised over [`TRIALS`],
/// so each is 2x one feed. On the dev Mac (M-series, debug build, load
/// average ~20) one feed is 33 ms at 16,128 fragments and 136 ms at
/// 64,512, so `a` reads about **65 ms** and `b` about **270 ms**. If they
/// move by a lot that is a re-measurement on a different box and not
/// necessarily a regression; the RATIO is the verdict.
///
/// The whole file runs in about 10 s on a quiet box, against 3-6 s at the
/// old counts. Read a much larger figure as LOAD and not as a regression -
/// it was measured at 98-135 s at load average 20-48, because wall time is
/// the SUM of every trial while the estimate is the MINIMUM of them, so
/// the two diverge by exactly the contention the minimum exists to throw
/// away. Five consecutive runs in that window still measured 4.17x to
/// 4.38x here and 4.29x to 4.36x on the full-MD5 arm.
///
/// # The tracking IS near-linear now, which it was not when this landed
///
/// `d5ad32c15`'s message said "the CRC arm was near-linear throughout",
/// and that was inferred from the single 4,096/8,192 pair this pin used
/// to measure. Over a curve it was false of both arms: what that commit
/// removed was the per-fragment re-sort and its allocation - a large
/// constant and a log factor - and not the ORDER, which stayed O(n^2)
/// because both paths still merged with `Vec::insert` into the middle of
/// a sorted vector. `crates/nzbkit/src/live/runs.rs` is where that was
/// fixed and its header carries the curve; the claim is true now, and the
/// per-doubling ratio through THIS path reads 1.88 / 1.89 / 2.10 / 2.06 /
/// 2.10 from 1,024 to 32,768 where it used to march toward 4.
#[test]
fn x5_18_disjoint_fragment_tracking_must_not_be_quadratic() {
    if !have_par2() {
        eprintln!("x5_18: par2 unavailable - skipping");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-wave5-x518-{}", std::process::id()));
    let _g = scratch::ScratchDir::attach(&dir);
    // One 1 MiB payload under one 1 MiB block: every fragment is a
    // partial of the SAME block, which is the row's shape.
    let data = payload(1 << 20, 17);
    let par2 = par2_over(&dir, "Big.bin", &data, 1 << 20);

    assert_tracking_is_lossless(&par2, "Big.bin", &data, SMALL, true);
    assert_tracking_is_lossless(&par2, "Big.bin", &data, LARGE, true);
    let a = tracking_secs(&par2, "Big.bin", &data, SMALL, true);
    let b = tracking_secs(&par2, "Big.bin", &data, LARGE, true);
    let ratio = b / a;
    eprintln!("x5_18 crc: {a:.4}s -> {b:.4}s ({ratio:.2}x)");
    assert!(
        ratio < 6.0,
        "CRC interval tracking cost grew {ratio:.1}x for 4x the disjoint \
         fragments ({a:.4}s -> {b:.4}s); linear is ~4x, a healthy tree \
         measured 4.2x and the sorted-Vec shape measured 9.0x"
    );
}

/// X5-18 (full-MD5 arm): the byte-buffer path, where `Partial::fill`
/// re-sorted the interval list on every fragment. This is the arm that
/// moved in `d5ad32c15`; the CRC arm above is the control that says which
/// half moved.
///
/// Its own bar is derived the same way, over the same 16,128 -> 64,512
/// pair the CRC arm above explains at length. At that pair a healthy tree
/// measured **4.32x** and the Vec-only shape **9.29x** (dev Mac, 31 Aug
/// 2026, load average ~20), so the bar of 6.0 sits 1.39x above the healthy
/// measurement and 1.55x below the regressed one. One feed is 26 ms at
/// 16,128 fragments and 111 ms at 64,512, so `a` reads about **52 ms** and
/// `b` about **222 ms**.
///
/// It is the SAME bar as the CRC arm's now, and that is a measurement
/// rather than a tidy-up: the two used to differ (6.0 against 8.0) because
/// the byte path's regression was textbook quadratic where the CRC path's
/// was diluted at the counts then in use. At these counts both paths are
/// near-linear and both regress to the same sorted `Vec`, so the two pairs
/// of numbers came out within 8% of each other. Keep deriving them
/// separately anyway - the two do different work per fragment, and the day
/// one of them moves is the day the shared value stops being right.
#[test]
fn x5_18_disjoint_fragment_tracking_must_not_be_quadratic_in_full_md5_mode() {
    if !have_par2() {
        eprintln!("x5_18 md5: par2 unavailable - skipping");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-wave5-x518m-{}", std::process::id()));
    let _g = scratch::ScratchDir::attach(&dir);
    let data = payload(1 << 20, 17);
    let par2 = par2_over(&dir, "Big.bin", &data, 1 << 20);

    assert_tracking_is_lossless(&par2, "Big.bin", &data, SMALL, false);
    assert_tracking_is_lossless(&par2, "Big.bin", &data, LARGE, false);
    let a = tracking_secs(&par2, "Big.bin", &data, SMALL, false);
    let b = tracking_secs(&par2, "Big.bin", &data, LARGE, false);
    let ratio = b / a;
    eprintln!("x5_18 md5: {a:.4}s -> {b:.4}s ({ratio:.2}x)");
    assert!(
        ratio < 6.0,
        "byte-buffer interval tracking cost grew {ratio:.1}x for 4x the \
         disjoint fragments ({a:.4}s -> {b:.4}s); linear is ~4x, a healthy \
         tree measured 4.3x and the sorted-Vec shape measured 9.3x"
    );
}
