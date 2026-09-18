//! One pass over the payload for ALL the recovery rows when the
//! accumulator budget would otherwise batch them.
//!
//! Why: the creator builds recovery slices in batches sized to the
//! accumulator budget (an eighth of RAM, 256 MiB to 8 GiB), each batch a
//! pass over the payload. On the transform that is worse than a pass:
//! the leaf work does not depend on the row count (every leaf computes
//! all 257 outputs, the combine prunes), so three batches cost three
//! transforms where one pass over all the rows would cost about one.
//! Measured 5 Sep 2026 on the M3 Ultra, 10 x 1 GiB / 4 MiB / 768 rows:
//! 13.6 / 16.8 s in three batches under a 1 GiB budget, 6.2 / 5.8 s in
//! one batch of the same 768 rows (the review's staged-create campaign
//! confirmed the shape independently: their temp-file staging read
//! -40..-53% against the batched path on an M1 and the i5). And a
//! batched create is the LARGE job on an ordinary box - 20 GiB of
//! payload at 10% on 16 GB of RAM, 40 GiB on 32 GB.
//!
//! How: the mapped transform already produces its outputs a STRIPE at a
//! time (W = 512 words of every row per worker call), so the rows never
//! need to exist whole. Workers transform a chunk of stripes for all the
//! rows into a staging buffer; each row's chunk is then written straight
//! into its recovery packet's payload at the right offset (the volume
//! files are laid out up front, headers first, MD5 fields zero) and fed
//! to that packet's running MD5; the seal is patched into the header
//! after the last chunk. The transform's independent check - row `first`
//! by the fold over the same sources - is computed before the chunks
//! and compared chunk by chunk; a disagreement returns `None` and the
//! caller runs the batched path, which recreates every volume.
//! Staging is bounded (64 MiB); nothing else grows with the row count
//! but the per-worker `out` (rows x W words).
//!
//! The flush OVERLAPS the next chunk's transform: staging is two
//! buffers (each within half the budget), the workers fill one while
//! the main thread and its writer lanes drain the other. The flush is
//! one positional write per row per chunk (8,192 rows x 16 chunks =
//! 131k writes on the 8 GiB / 256 KiB shape) and every lane writes the
//! same few volume files, so it is syscall- and lock-bound rather than
//! bandwidth-bound: the review's priority-queue tranche (6 Sep 2026, M1
//! Ultra) read its wall as proportional to the chunk COUNT, 3.2 s at 16
//! chunks against 0.7 s at 4, in series with 4.8 s of transform. Off the
//! critical path it costs nothing but the second buffer.
//!
//! `NZBFAST_CREATE_STRIPE_FIRST=0` keeps the batched path (the A/B arm);
//! `NZBFAST_CREATE_STAGE_OVERLAP=0` flushes in series from one buffer.
//!
//! # Bands: the same one pass over COPIES (TODO 345 C, 15 Sep 2026)
//!
//! A create whose payload would not stay resident as a mapping
//! (`mapped_payload_fits_memory`) reads through copies, and until this
//! arm that meant the batched path's copied WINDOWS: a whole plan's leaf
//! and combine work per window, per batch. On a 32 GB Core Ultra 9 laptop
//! that was 72 s of a 102 s create, one 45 GiB member at 32,768 slices
//! and 5%, all sixteen threads beside the whole-file MD5 chain the create
//! waits on anyway; at 15% it was three batches of windows
//! (research/PARFAST-OVER-RAM-CREATE-2026-09-15.md). The same member on
//! the M3 Ultra under `-m8192`, copies forced: seven windows transformed
//! in 17.6 s where the mapped single plan took 9.8, the create 540 user
//! CPU-seconds against 318.
//!
//! The transform never needs a whole source, only one column of every
//! slice per stripe, so the copy is cut along STRIPES instead of blocks:
//! per chunk, bytes `[c0 * 2W, c1 * 2W)` of every slice land in one arena
//! ([`read_band`]), the workers run THE plan over all the sources on those
//! stripes, and the flush below is the mapped arm's. One plan and one pass
//! over the payload whatever the batch count, read in sequential band
//! sweeps, the arena bounded by the copied windows' own corpus budget.
//! The probe row is folded per band. One batch is admitted too when the
//! corpus does not fit one window, because the copied windows' "single
//! pass" is then still several plans. `NZBFAST_CREATE_STRIPE_BANDS=0`
//! keeps the copied windows (the A/B arm).

use super::{
    CreateControl, CreatePhase, CreateTrail, CriticalIndex, CriticalPatch, MappedPlan,
    Par2GenError, io, ntt_range,
};
use crate::md5fast::{Digest, Md5};
use crate::par2::TYPE_RECVSLIC;
use std::path::{Path, PathBuf};

/// The staging buffer's floor: rows x stripes-per-chunk x W words. A
/// chunk also holds at least two stripes per transform worker (a 64 MiB
/// buffer over 8,192 rows at W = 512 is eight stripes for twenty
/// workers, and the flush is a 4 KiB write per row: the review's stripe
/// audit, 6 Sep 2026, measured 128 MiB at -41% on an 8 GiB / 256 KiB /
/// 8,192-row create and +4% for 32 MiB at 768 rows), bounded by the
/// accumulator budget the create was given, which is the memory the
/// batched path would have held anyway.
const STAGING_BYTES: usize = 64 << 20;

fn enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_CREATE_STRIPE_FIRST").as_deref() != Ok("0"))
}

/// Two staging buffers, the flush of one under the transform of the
/// other; off, one buffer and the flush in series (the A/B arm).
fn overlap_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_CREATE_STAGE_OVERLAP").as_deref() != Ok("0"))
}

/// One chunk's flush: every row's span to its packet's payload at
/// column offset `at`, and into that packet's running seal, across
/// `lanes` writer threads.
#[allow(clippy::too_many_arguments)]
fn flush_chunk(
    dir: &Path,
    staging: &[u16],
    stride: usize,
    chunk_words: usize,
    at: u64,
    lanes: usize,
    files: &[std::fs::File],
    names: &[String],
    place: &[(usize, u64)],
    seals: &mut [Md5],
) -> Result<(), Par2GenError> {
    let rows = seals.len();
    let lanes = lanes.clamp(1, rows);
    let per = rows.div_ceil(lanes);
    let mut results: Vec<Result<(), Par2GenError>> = Vec::new();
    std::thread::scope(|sc| {
        let handles: Vec<_> = staging
            .chunks(per * stride)
            .zip(seals.chunks_mut(per))
            .enumerate()
            .map(|(li, (rows_bytes, seal))| {
                sc.spawn(move || -> Result<(), Par2GenError> {
                    for (k, m) in seal.iter_mut().enumerate() {
                        let r = li * per + k;
                        let span = &rows_bytes[k * stride..k * stride + chunk_words];
                        let bytes = crate::gf16::words_as_bytes(span);
                        let (vi, hdr) = place[r];
                        crate::disk::write_all_at(&files[vi], bytes, hdr + 68 + at)
                            .map_err(io(&dir.join(&names[vi])))?;
                        m.update(bytes);
                    }
                    Ok(())
                })
            })
            .collect();
        results = handles
            .into_iter()
            .map(|h| h.join().expect("stripe-first writer panicked"))
            .collect();
    });
    results
        .into_iter()
        .find_map(|r| r.err())
        .map_or(Ok(()), Err)
}

/// How many batches the accumulator budget makes of this layout: the
/// grouping the batch loop applies (whole volumes, as many as fit).
pub(super) fn batches(layout: &[(usize, usize)], per_batch: usize) -> usize {
    let mut n = 0usize;
    let mut vi = 0usize;
    while vi < layout.len() {
        let mut held = 0usize;
        while vi < layout.len() && (held == 0 || held + layout[vi].1 <= per_batch) {
            held += layout[vi].1;
            vi += 1;
        }
        n += 1;
    }
    n
}

/// The band route over copies (module doc); off, the copied windows.
fn bands_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_CREATE_STRIPE_BANDS").as_deref() != Ok("0"))
}

/// Where the one pass reads its sources from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Corpus {
    /// Every full block straight out of the members' mappings.
    Mapped,
    /// Stripe bands copied out of the members into an arena of at most
    /// `bytes` per chunk (module doc, "Bands").
    Bands { bytes: usize },
}

/// Stripes per chunk on the band route: as many as one arena of `bytes`
/// holds across every one of `n_slices` sources, at least one, at most
/// all of them.
fn band_stripes(bytes: usize, n_slices: usize, w: usize, stripes: usize) -> usize {
    (bytes / n_slices.max(1).saturating_mul(w * 2).max(1)).clamp(1, stripes.max(1))
}

/// Whether this create takes the one-pass route, and over which corpus:
/// no fused scan, the transform admissible for every row at once, and
/// either mapped members over several batches or copied members whose
/// corpus would otherwise take more than one plan. Names its verdict on
/// the timing channel either way.
///
/// # Every refusal reports, which three of them did not
///
/// Until 12 Sep 2026 the report below sat AFTER an
/// `if !enabled() || batches < 2 || fused { return false }`, so the
/// three COMMONEST refusals printed nothing at all: the knob off, a
/// single-batch create, a fused one. A reader then had to infer the arm
/// from a line that was not about the arm, and silence is not evidence
/// of anything. That inference is what a create's Pause defect cost a
/// day to explain: four mechanisms were proposed for two observations
/// and three of them were wrong, each a correctly-verified chain of
/// code links inside a branch that did not run for the job shape being
/// explained. The chain still SHORT-CIRCUITS, so the window plan is
/// priced at most once and only when the cheap gates have passed.
pub(super) fn admissible(
    batches: usize,
    fused: bool,
    bs: usize,
    n_slices: usize,
    first: usize,
    rows: usize,
) -> Option<Corpus> {
    let window = || super::ntt_range::create_ntt_window(bs, n_slices, first, rows);
    let mut corpus = None;
    // The mapped arm's cheap gates still come before its window is priced;
    // the band arm has to price the window to know whether one plan would
    // have held the corpus anyway.
    let why = if !enabled() {
        Some("the knob is off (NZBFAST_CREATE_STRIPE_FIRST=0)")
    } else if fused {
        Some("the scan is fused into the fold")
    // NO HEADROOM TERM HERE, and that is measured rather than an oversight.
    // `mapped_payload_fits_memory` takes one since 16 Sep 2026 (its own
    // docstring), but this call is not the fold's map-or-copy decision - it
    // picks the CORPUS SHAPE, and a refusal here falls to the BANDS arm below
    // rather than to the copied windows the gate itself falls to. Feeding the
    // term in was measured that day on an 8-core x86_64 Linux box, one 2 GiB
    // member at 5% in a 2,150 MiB cgroup: it diverted a ONE-BATCH create out of the main
    // path's copied windows (5.5 s, three reps) and into bands (8.6-9.2 s),
    // -56%, because the bands arm's own single-batch refusal is narrower than
    // the mapped arm's. Narrowing THIS question is a claim about the bands
    // arm and wants that arm's evidence, so the gate got stricter and this
    // prediction did not; what is left is that a MULTI-batch create in the
    // band between the two answers can still take `Corpus::Mapped` where the
    // fold's own gate would refuse - unchanged from before the term, and
    // stated as owed in research/PAR2GEN-GATE-CGROUP-BLIND-2026-09-16.md.
    } else if super::map_inputs_enabled()
        && super::mapped_payload_fits_memory(n_slices as u64 * bs as u64, 0)
    {
        if batches < 2 {
            Some("one batch - the batched path already makes a single pass")
        } else if window().is_none() {
            Some("the transform is not admitted for all rows at once")
        } else {
            corpus = Some(Corpus::Mapped);
            None
        }
    } else if !bands_enabled() {
        Some(
            "the members are read through copies (not mapped, or the payload would not stay \
             resident - see mapped_payload_fits_memory) and bands are off \
             (NZBFAST_CREATE_STRIPE_BANDS=0)",
        )
    } else {
        match window() {
            None => Some("the transform is not admitted for all rows at once"),
            Some(window) => {
                let bytes = super::ntt_range::band_corpus_bytes(window.saturating_mul(bs));
                // THIS REFUSAL IS DELIBERATELY NARROWER THAN THE MAPPED ARM'S,
                // and it stays that way: it declines a one-batch create only
                // when one window would have held the WHOLE corpus, so the
                // copied transform really is one plan. A one-batch create whose
                // corpus takes SEVERAL windows is admitted, and that case is
                // the band route's headline win rather than an oversight -
                // 45 GiB at 5% is `batches=1` on both the boxes TODO 345 C was
                // accepted on. Core Ultra 9 laptop, 31.4 GB, the payload
                // genuinely over memory: 60.2 s / 265 CPU-s / 105.9 GB read in
                // 6 band sweeps against the copied windows' 91.0 s / 829 CPU-s
                // / 113.7 GB in 6 windows, one set digest across both arms
                // (research/PARFAST-OVER-RAM-BAND-ROUTE-2026-09-15.md section
                // 5). M3 Ultra, same shape: transform 11.4 s against 18.9,
                // create CPU 312 against 546 (section 4). Matching the mapped
                // arm's refusal here gives all of that back.
                //
                // The contrary reading in section 8.4 of
                // research/PAR2GEN-GATE-CGROUP-BLIND-2026-09-16.md - bands at
                // 8.6-9.2 s where the copied windows do 5.5 - is real and is
                // NOT about the batch count. Re-read off that round's own legs
                // (research/par2gen-map-headroom-2026-09-16/legs-r1.jsonl,
                // cg2150m): its losing cell is a 2 GiB payload that FITS
                // memory, reached only through `NZBFAST_PAR2GEN_MAP=0`, where
                // the copied windows are served from the page cache and the
                // band read is pure addition - 10.85 s of a 13.08 s transform,
                // against the windows' whole 5.10 s. Every `def` leg in that
                // round refuses stripe-first ABOVE, at the mapped arm's strict
                // one-batch line, and never asks this question: in production
                // `map_inputs_enabled()` is only off by knob, so this arm is
                // reached exactly when the payload is genuinely over memory -
                // which is the regime the two wins above were measured in.
                //
                // The axis that separates them is the band READ against the
                // plans it saves, `(sweeps - 1) * per-plan transform` against
                // the read: 5 x 0.85 s against 10.85 s on the losing cell, 5 x
                // ~10 s against 41.2 s on the laptop. Its shape-side proxy is
                // the contiguous run each sweep takes from a slice, written
                // `bs / sweeps` when it was first derived (12 KiB of a 64 KiB
                // block losing, 241 KiB of a 1.44 MiB block winning). WRITE IT
                // THE OTHER WAY: `band_corpus_bytes / n_slices` with the
                // window `budget / bs`, and the block size CANCELS -
                //
                //     run = budget / n_slices
                //
                // the memory budget per slice, and nothing else. The two forms
                // are the same identity and do not suggest the same
                // experiment, which is why `band_run_floor_tests` below pins
                // this one. It also has a FLOOR: `create_ntt_window` refuses a
                // window under NTT_WINDOW_MIN = 1,024 slices and
                // MAX_INPUT_SLICES is 32,768, so `run >= bs / 32` for every
                // create that reaches this arm at all. Asking for less budget
                // does not sweep harder, it stops the arm being reached.
                // 15 one-batch cells on the M3 Ultra over that proxy (4 KiB to
                // 247 KiB of run, 2 to 16 sweeps, 8 and 32 threads, 3 reps,
                // one set digest per block size across both arms) put bands
                // ahead on CPU in every one, by 1.4% at 2 sweeps to 39% at 16;
                // they cannot see the read side, because 512 GB of RAM holds
                // the corpus. THE READ SIDE IS PRICED on an 8-core x86_64
                // Linux box with a SLOW disk (0.5-0.7 GB/s), 36 legs over
                // both arms, the fixture dropped from the page cache before
                // every leg and one set digest per shape across both arms: an
                // 8 GiB corpus in a 2,560 MiB cgroup for the short runs, a
                // 32 GiB corpus bare on 31 GB of RAM for the long ones. It
                // SPLITS THE TWO COLUMNS, which no cell before it could.
                // BANDS WIN CPU IN EVERY CELL, 1.37x to 2.33x. BANDS LOSE
                // WALL AT A SHORT RUN: 2.4x at 9 KiB of run, 1.5x at
                // 13-17 KiB, level by 34 KiB, level again at 62-128 KiB.
                // The mechanism is in the cgroup's own counters rather than
                // inferred: at 9 KiB the band arm refaults 4.40M file pages
                // against the windows' 1.79M and reads 25.5 GB off the device
                // against their 15.4 GB, for an 8 GiB payload, and both
                // converge as the run grows. A strided sweep pays the
                // device's readahead granularity per run, and at 9 KiB most
                // of what is faulted in is discarded before it is used.
                // SO THE 1.5x WALL WIN ABOVE IS A FAST-DISK RESULT - that
                // laptop read 105.9 GB at 1.76 GB/s - and the CPU win is not.
                // The regime this arm is actually REACHED in is the over-RAM
                // one, where the slice cap forces a long run and bands are
                // level on wall and 2.2x on CPU, so the rule is right there.
                // Round, ladder and verdict:
                // research/STRIPE-FIRST-BANDS-OVERRAM-LADDER-2026-09-16.md.
                // NO THRESHOLD ON THE RUN IS SET HERE, and that is still
                // deliberate: the three rungs that differ ONLY in the run
                // never cross, and the 34 KiB parity point moves the block
                // count and the redundancy too, so the pair straddling the
                // crossing differs in more than the axis. Two points and a
                // gap, and this repo's rule is that an interpolated crossing
                // is not a thing to set a constant from.
                if batches < 2 && bytes >= n_slices.saturating_mul(bs) {
                    Some(
                        "one batch in one resident window - the copied transform is one plan already",
                    )
                } else {
                    corpus = Some(Corpus::Bands { bytes });
                    None
                }
            }
        }
    };
    if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
        match (why, corpus) {
            (Some(why), _) => tracing::info!(
                target: "repair-timing",
                "create stripe-first refused: {why} ({batches} batch(es), {rows} rows, n={n_slices}, fused={fused})"
            ),
            (None, Some(Corpus::Bands { bytes })) => tracing::info!(
                target: "repair-timing",
                "create stripe-first admitted: {batches} batch(es), {rows} rows, n={n_slices}, bands of up to {bytes} B over copies"
            ),
            (None, _) => tracing::info!(
                target: "repair-timing",
                "create stripe-first admitted: {batches} batches, {rows} rows, n={n_slices}"
            ),
        }
    }
    corpus
}

pub(super) struct Args<'a> {
    pub control: &'a CreateControl,
    /// Every volume laid out below is opened THROUGH this and noted the
    /// moment the open succeeds, so a cancel removes it - and a volume
    /// the trail REFUSED (no-clobber over a file already there) is
    /// never noted and so never removed. See `control::CreateTrail`.
    pub trail: &'a CreateTrail,
    pub scanned: &'a [(PathBuf, u64)],
    pub bs: usize,
    pub n_slices: usize,
    pub first: usize,
    pub rows: usize,
    pub layout: &'a [(usize, usize)],
    pub dir: &'a Path,
    pub base: &'a str,
    pub set_id: &'a [u8; 16],
    /// The critical block every volume starts with (the placeholder the
    /// caller backfills, or the real one).
    pub head: &'a [u8],
    pub complete: bool,
    /// The interleaved layout's packet index; None for the head layout.
    pub cidx: Option<&'a CriticalIndex>,
    /// The accumulator budget in bytes: the staging buffer's ceiling.
    pub accum: u64,
    /// Where the sources are read from ([`admissible`]'s verdict).
    pub corpus: Corpus,
}

/// The batch loop's one call: admission, then [`run`].
#[allow(clippy::too_many_arguments)]
pub(super) fn try_run(
    control: &CreateControl,
    trail: &CreateTrail,
    scanned: &[(PathBuf, u64)],
    bs: usize,
    n_slices: usize,
    first: usize,
    rows: usize,
    layout: &[(usize, usize)],
    per_batch: usize,
    fused: bool,
    cidx: Option<&CriticalIndex>,
    dir: &Path,
    base: &str,
    set_id: &[u8; 16],
    ready_critical: Option<&Vec<u8>>,
    critical_shape: &[u8],
) -> Result<Option<Vec<(String, CriticalPatch)>>, Par2GenError> {
    let Some(corpus) = admissible(batches(layout, per_batch), fused, bs, n_slices, first, rows)
    else {
        return Ok(None);
    };
    run(&Args {
        corpus,
        control,
        trail,
        scanned,
        bs,
        n_slices,
        first,
        rows,
        layout,
        dir,
        base,
        set_id,
        head: ready_critical.map_or(critical_shape, |v| v.as_slice()),
        complete: ready_critical.is_some(),
        cidx,
        accum: per_batch as u64 * bs as u64,
    })
}

/// Bytes `[b0, b0 + slot)` of every source slice into `arena`, slice `i`'s
/// at `i * slot`: the band of stripes the next chunk transforms (module
/// doc, "Bands"). A slice whose data ends inside or before the band - a
/// member's tail block - is zero-padded from there, which is the padding
/// the mapped arm gives its tails. Positional reads over `readers`
/// contiguous runs of the plan, sharing one handle per member:
/// `disk::read_exact_at` takes its offset per call on every platform (see
/// `scan::scan_parallel_positional`).
#[allow(clippy::too_many_arguments)]
fn read_band(
    control: &CreateControl,
    files: &[std::fs::File],
    scanned: &[(PathBuf, u64)],
    plan: &[(usize, u64, usize)],
    b0: usize,
    slot: usize,
    arena: &mut [u8],
    readers: usize,
) -> Result<(), Par2GenError> {
    let per = plan.len().div_ceil(readers.max(1)).max(1);
    let mut results: Vec<Result<(), Par2GenError>> = Vec::new();
    std::thread::scope(|sc| {
        let handles: Vec<_> = plan
            .chunks(per)
            .zip(arena.chunks_mut(per * slot))
            .map(|(jobs, slots)| {
                sc.spawn(move || -> Result<(), Par2GenError> {
                    for (k, &(mi, off, want)) in jobs.iter().enumerate() {
                        // Cancel only: a reader owns its run of slots and
                        // nothing else, and the driver parks between chunks.
                        if control.cancelled() {
                            return Err(Par2GenError::Cancelled);
                        }
                        let dst = &mut slots[k * slot..(k + 1) * slot];
                        let have = want.saturating_sub(b0).min(slot);
                        if have > 0 {
                            crate::disk::read_exact_at(
                                &files[mi],
                                &mut dst[..have],
                                off + b0 as u64,
                            )
                            .map_err(io(&scanned[mi].0))?;
                        }
                        dst[have..].fill(0);
                    }
                    Ok(())
                })
            })
            .collect();
        results = handles
            .into_iter()
            .map(|h| h.join().expect("stripe-first band reader panicked"))
            .collect();
    });
    super::ntt_range::note_band_sweep();
    results
        .into_iter()
        .find_map(|r| r.err())
        .map_or(Ok(()), Err)
}

/// Row `first` by the fold over `srcs`, `words` columns of it: the check
/// the transform's rows are compared against. The fold is linear column
/// by column, so over a band's sources this is exactly that band's
/// columns of the whole row.
fn probe_row(srcs: &[&[u8]], logs: &[u32], first: usize, words: usize) -> Vec<u16> {
    let mut probe = vec![vec![0u16; words]];
    // `None`: no honest creator `Sub` - see `fold_parallel`.
    crate::par2repair::linalg::fold_parallel(
        &mut probe,
        srcs,
        &|_, i| crate::gf16::pow2(logs[i] as u64 * first as u64 % crate::gf16::ORDER as u64),
        None,
    );
    probe.pop().expect("one probe row")
}

/// One chunk's band: its stripes of every slice read into the arena, and
/// the probe row's columns folded over them, both while the workers are
/// parked at the start gate. `None` on the mapped corpus, which reads its
/// sources through the mapping and folds one probe for the whole run.
///
/// Split out of [`run`]'s chunk loop for the size gate's 500-line function
/// ceiling, which that loop's band arm left three lines clear of.
#[allow(clippy::too_many_arguments)]
fn band_chunk(
    a: &Args,
    mapped: bool,
    band: *mut u8,
    slot: usize,
    plan: &[(usize, u64, usize)],
    logs: &[u32],
    sources: &[std::fs::File],
    readers: usize,
    c0: usize,
    w: usize,
    chunk_words: usize,
    t_read: &mut std::time::Duration,
    t_probe: &mut std::time::Duration,
) -> Result<Option<Vec<u16>>, Par2GenError> {
    if mapped {
        return Ok(None);
    }
    let t_band = std::time::Instant::now();
    // SAFETY: the workers are parked at the start gate, so the arena is
    // the driver's alone until the chunk is posted.
    let arena = unsafe { std::slice::from_raw_parts_mut(band, a.n_slices * slot) };
    read_band(
        a.control,
        sources,
        a.scanned,
        plan,
        c0 * w * 2,
        slot,
        arena,
        readers,
    )?;
    *t_read += t_band.elapsed();
    let t0 = std::time::Instant::now();
    let srcs: Vec<&[u8]> = arena
        .chunks_exact(slot)
        .map(|s| &s[..chunk_words * 2])
        .collect();
    let probe = probe_row(&srcs, logs, a.first, chunk_words);
    *t_probe += t0.elapsed();
    Ok(Some(probe))
}

/// The volume files `run` folds into, laid out and header-written before
/// the first payload byte exists.
struct Volumes {
    files: Vec<std::fs::File>,
    names: Vec<String>,
    patches: Vec<CriticalPatch>,
    /// Per row: (volume, offset of the packet header in that file).
    place: Vec<(usize, u64)>,
}

/// Create every volume file, size it, and write the head and each
/// recovery packet's header (MD5 fields zero, patched after the last
/// chunk) - split out of [`run`] on 17 Sep 2026 for the 500-line
/// function ceiling, not because it is reused anywhere else.
///
/// It reads nothing but [`Args`], and it runs to completion before any
/// transform does, which is what makes it a seam rather than a slice of
/// the fold: the whole point of this path is that the layout exists up
/// front so each chunk can be written straight into its packet at a
/// known offset.
fn lay_out_volumes(a: &Args) -> Result<Volumes, Par2GenError> {
    let packet = 68 + a.bs as u64;
    let mut files: Vec<std::fs::File> = Vec::with_capacity(a.layout.len());
    let mut names: Vec<String> = Vec::with_capacity(a.layout.len());
    let mut patches: Vec<CriticalPatch> = Vec::with_capacity(a.layout.len());
    // Per row: (volume, offset of the packet header in that file).
    let mut place: Vec<(usize, u64)> = vec![(0, 0); a.rows];
    for (vi, &(vfirst, count)) in a.layout.iter().enumerate() {
        let name = format!("{}.vol{vfirst:03}+{count:02}.par2", a.base);
        let path = a.dir.join(&name);
        // Opened and noted in ONE call - see `CreateTrail::create`. A
        // no-clobber trail answers `AlreadyExists` here, and unwinds
        // through the same `io(&path)` as any other open failure.
        let f = a.trail.create(a.dir, &name).map_err(io(&path))?;
        let header_at = |e: usize, at: u64| -> std::io::Result<()> {
            let mut header = [0u8; 68];
            header[..8].copy_from_slice(crate::par2::MAGIC);
            header[8..16].copy_from_slice(&packet.to_le_bytes());
            header[32..48].copy_from_slice(a.set_id);
            header[48..64].copy_from_slice(TYPE_RECVSLIC);
            header[64..68].copy_from_slice(&(e as u32).to_le_bytes());
            crate::disk::write_all_at(&f, &header, at)
        };
        // Sized through the disk layer BEFORE the first positional write:
        // on NTFS a write past the valid data length zero-fills up to it,
        // and the header pass below writes every packet's header first,
        // ~3 GiB of skipped payload on a 768 x 4 MiB set; the helper marks
        // the file sparse (the article writer's measured remedy,
        // `NZBFAST_WIN_SPARSE=0` the old behaviour) and sets the length.
        let patch = match a.cidx {
            None => {
                crate::disk::preallocate_output(
                    &f,
                    a.head.len() as u64 + count as u64 * packet,
                    u64::MAX,
                )
                .map_err(io(&path))?;
                crate::disk::write_all_at(&f, a.head, 0).map_err(io(&path))?;
                for i in 0..count {
                    let at = a.head.len() as u64 + i as u64 * packet;
                    header_at(vfirst + i, at).map_err(io(&path))?;
                    place[vfirst + i - a.first] = (vi, at);
                }
                if a.complete {
                    CriticalPatch::Complete
                } else {
                    CriticalPatch::Head
                }
            }
            Some(cidx) => {
                let after = super::interleave_schedule(count, cidx.cycle.len());
                let owed: usize = after.iter().sum();
                let total = count as u64 * packet
                    + (0..owed)
                        .map(|t| cidx.cycle[t % cidx.cycle.len()].1 as u64)
                        .sum::<u64>()
                    + cidx.creator.1 as u64;
                crate::disk::preallocate_output(&f, total, u64::MAX).map_err(io(&path))?;
                let mut offsets = Vec::with_capacity(owed);
                let mut pos = 0u64;
                let mut turn = 0usize;
                for (i, owed) in after.iter().enumerate() {
                    header_at(vfirst + i, pos).map_err(io(&path))?;
                    place[vfirst + i - a.first] = (vi, pos);
                    pos += packet;
                    for _ in 0..*owed {
                        let (o, l) = cidx.cycle[turn % cidx.cycle.len()];
                        crate::disk::write_all_at(&f, &a.head[o..o + l], pos).map_err(io(&path))?;
                        offsets.push(pos);
                        pos += l as u64;
                        turn += 1;
                    }
                }
                let (o, l) = cidx.creator;
                crate::disk::write_all_at(&f, &a.head[o..o + l], pos).map_err(io(&path))?;
                pos += l as u64;
                debug_assert_eq!(pos, total, "the interleaved walk matches its own size");
                if a.complete {
                    CriticalPatch::Complete
                } else {
                    CriticalPatch::Interleaved(offsets)
                }
            }
        };
        files.push(f);
        names.push(name);
        patches.push(patch);
    }
    Ok(Volumes {
        files,
        names,
        patches,
        place,
    })
}

/// `Ok(Some(volumes))` with every volume written and sealed;
/// `Ok(None)` when the transform's check disagreed or the mapping could
/// not be built - the caller runs the batched path.
pub(super) fn run(a: &Args) -> Result<Option<Vec<(String, CriticalPatch)>>, Par2GenError> {
    let t0 = std::time::Instant::now();
    let bs = a.bs;
    let words = bs / 2;
    let logs = crate::par2repair::input_base_logs(a.n_slices)
        .map_err(|e| Par2GenError::Other(format!("assigning RS constants: {e}")))?;
    let present: Vec<(u32, crate::par2ntt::SrcId)> = logs
        .iter()
        .enumerate()
        .map(|(i, &l)| (l, i as crate::par2ntt::SrcId))
        .collect();
    let Ok((ntt, out_first)) = ntt_range::plan(&present, a.first, a.rows) else {
        return Ok(None);
    };
    let Some(window) = super::ntt_range::create_ntt_window(bs, a.n_slices, a.first, a.rows) else {
        return Ok(None);
    };
    // The block list in input-slice order, as `recovery_slices` builds it.
    let mut plan: Vec<(usize, u64, usize)> = Vec::with_capacity(a.n_slices);
    for (mi, &(_, length)) in a.scanned.iter().enumerate() {
        let mut off = 0u64;
        while off < length {
            let want = (length - off).min(bs as u64) as usize;
            plan.push((mi, off, want));
            off += want as u64;
        }
    }
    // Mapped: the sources, and the independent check - row `first` by the
    // fold over the same sources, compared chunk by chunk below - up
    // front. Bands: one read handle per member now, the check per band.
    let (maps, sources) = match a.corpus {
        Corpus::Mapped => {
            let Some(maps) = MappedPlan::open(a.scanned, &plan, bs, window.saturating_mul(bs))
            else {
                return Ok(None);
            };
            (Some(maps), Vec::new())
        }
        Corpus::Bands { .. } => {
            let sources = a
                .scanned
                .iter()
                .map(|(path, _)| std::fs::File::open(path).map_err(io(path)))
                .collect::<Result<Vec<_>, _>>()?;
            (None, sources)
        }
    };
    let probe: Vec<u16> = maps.as_ref().map_or_else(Vec::new, |maps| {
        let srcs: Vec<&[u8]> = (0..a.n_slices).map(|i| maps.block(i, bs)).collect();
        probe_row(&srcs, &logs, a.first, words)
    });

    // Volumes laid out up front, exactly as the batched writer lays them
    // (its shape is what the backfill patches): the head layout puts the
    // critical block first and the packets after it; the interleaved
    // layout (par2cmdline's, the CLI's default) puts each recovery
    // packet, then the critical packets the schedule owes at that point,
    // and the Creator once at the end, recording every critical copy's
    // offset. Recovery headers go in with their MD5 field zero; the
    // payloads and seals follow.
    let Volumes {
        files,
        names,
        patches,
        place,
    } = lay_out_volumes(a)?;
    let mut seals: Vec<Md5> = (0..a.rows)
        .map(|r| {
            let mut m = Md5::new();
            m.update(a.set_id);
            m.update(TYPE_RECVSLIC);
            m.update(((a.first + r) as u32).to_le_bytes());
            m
        })
        .collect();

    let (w, threads) =
        crate::par2repair::ntt_create_stripe_geometry(bs, Some(ntt.median_leaf_kernel()));
    let stripes = words.div_ceil(w);
    ntt_range::note_stripes(stripes);
    let stripe_bytes = a.rows * w * 2;
    let natural = match a.corpus {
        Corpus::Mapped => (STAGING_BYTES / stripe_bytes)
            .max(threads * 2)
            .clamp(1, stripes),
        // A band chunk is a sweep over the whole payload, which costs far
        // more than the flush's per-write overhead the mapped chunk is
        // sized against: as many stripes as the arena holds.
        Corpus::Bands { bytes } => band_stripes(bytes, a.n_slices, w, stripes),
    };
    // Two buffers when a pair of natural-sized chunks fits the budget;
    // otherwise one, cut to the budget. Never two half-sized ones: the
    // flush is per-write overhead, so halving the chunk to afford the
    // pair costs more than the overlap hides (M3 Ultra, 8 GiB / 256 KiB
    // / 8,192 rows at a 256 MiB budget: 5.5 s against 4.5 in series,
    // and 4.2 with the pair at the full chunk).
    let bufs = if overlap_enabled() && (2 * natural * stripe_bytes) as u64 <= a.accum {
        2
    } else {
        1
    };
    let by_budget = (a.accum / stripe_bytes as u64).max(1) as usize;
    let per_chunk = if bufs == 2 {
        natural
    } else {
        natural.min(by_budget)
    };
    let stride = per_chunk * w;
    let buf_words = a.rows * stride;
    let mut staging = vec![0u16; bufs * buf_words];
    struct Rows(*mut u16);
    // SAFETY: workers write disjoint column ranges of every row (one
    // stripe per atomic claim), so sharing the staging pointer across
    // the scope's threads races nothing.
    unsafe impl Send for Rows {}
    // SAFETY: as above.
    unsafe impl Sync for Rows {}
    // The band arena: slice `i`'s stripes from the chunk's first at
    // `i * slot`. The driver refills it through `band` while the workers
    // are parked at the start gate; they only read it once it is posted.
    let slot = per_chunk * w * 2;
    let mut band_arena = vec![0u8; if maps.is_some() { 0 } else { a.n_slices * slot }];
    struct Band(*mut u8);
    // SAFETY: the workers only read the arena, between the gates, and the
    // driver writes it only outside them.
    unsafe impl Send for Band {}
    // SAFETY: as above.
    unsafe impl Sync for Band {}
    let band = Band(band_arena.as_mut_ptr());
    let readers = super::create_readers(false);
    let mut t_band_read = std::time::Duration::ZERO;
    let mut t_band_probe = std::time::Duration::ZERO;
    // Workers live for the whole run - their transform scratch (~15 MB
    // each at the production stripe) and output rows are allocated once,
    // not once per chunk (the review's read of the first landing: 49 chunks
    // times twelve workers re-faulting that scratch on the i5). Each
    // chunk: the main thread posts its stripe range, the workers claim
    // stripes, and two barriers bracket the chunk so the flush below sees
    // a finished staging buffer.
    let mut chunks = 0usize;
    let rows = Rows(staging.as_mut_ptr());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let end = std::sync::atomic::AtomicUsize::new(0);
    let chunk_start = std::sync::atomic::AtomicUsize::new(0);
    let buf_base = std::sync::atomic::AtomicUsize::new(0);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let start_gate = std::sync::Barrier::new(threads + 1);
    let end_gate = std::sync::Barrier::new(threads + 1);
    let mut verdict: Option<Result<(), Par2GenError>> = None;
    std::thread::scope(|sc| {
        for _ in 0..threads {
            let ntt = &ntt;
            let rows = &rows;
            let table = maps.as_ref();
            let band = &band;
            let (next, end, chunk_start, stop) = (&next, &end, &chunk_start, &stop);
            let buf_base = &buf_base;
            let (start_gate, end_gate) = (&start_gate, &end_gate);
            sc.spawn(move || {
                let mut scratch = ntt.new_scratch(w);
                let mut out = vec![0u16; ntt.needed * w];
                loop {
                    start_gate.wait();
                    if stop.load(std::sync::atomic::Ordering::Acquire) {
                        return;
                    }
                    let c0 = chunk_start.load(std::sync::atomic::Ordering::Acquire);
                    let c1 = end.load(std::sync::atomic::Ordering::Acquire);
                    let base = buf_base.load(std::sync::atomic::Ordering::Acquire);
                    loop {
                        let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if c >= c1 {
                            break;
                        }
                        let len = w.min(words - c * w);
                        // SAFETY: the transform's src_of contract, 2*len
                        // readable bytes from the pointer. Mapped: every
                        // table entry is readable for `bs` bytes and
                        // c*w*2 + 2*len <= bs. Bands: slot `id` holds
                        // `slot` bytes starting at stripe c0, and
                        // (c - c0)*w*2 + 2*len <= slot because c < c1 <=
                        // c0 + per_chunk.
                        let src_of = |id: crate::par2ntt::SrcId| unsafe {
                            match table {
                                Some(t) => t.table[id as usize].add(c * w * 2),
                                None => {
                                    band.0.add(id as usize * slot + (c - c0) * w * 2) as *const u8
                                }
                            }
                        };
                        ntt.transform(&src_of, len, &mut scratch, &mut out);
                        for j in 0..a.rows {
                            let e = out_first + j;
                            // SAFETY: row j's span of the posted buffer
                            // is `stride` words and (c - c0) * w + len
                            // <= stride; stripe c is this worker's alone.
                            let dst = unsafe {
                                std::slice::from_raw_parts_mut(
                                    rows.0.add(base + j * stride + (c - c0) * w),
                                    len,
                                )
                            };
                            dst.copy_from_slice(&out[e * len..(e + 1) * len]);
                        }
                    }
                    end_gate.wait();
                }
            });
        }
        let mut c0 = 0usize;
        // This arm has no window loop to count bytes in - the payload
        // is mapped and every chunk sweeps ALL of it - so its fold
        // phase counts STRIPES of the output, which is what it actually
        // walks. `control`'s module doc says so.
        a.control.begin(CreatePhase::Fold, stripes as u64);
        let release = |stop: &std::sync::atomic::AtomicBool| {
            stop.store(true, std::sync::atomic::Ordering::Release);
            start_gate.wait();
        };
        // A chunk transformed and probe-checked, its flush still owed:
        // (first stripe, words, buffer base). It drains while the
        // workers fill the other buffer.
        let mut owed: Option<(usize, usize, usize)> = None;
        let lanes = threads;
        while c0 < stripes {
            // PER CHUNK, which is this arm's grain: one relaxed load
            // per transform of `per_chunk` stripes across every row.
            // It PARKS here as well as cancelling, and this is the one
            // place in the whole create where the driver may:
            //
            // The workers are all blocked in `start_gate.wait()` at
            // this instant, having claimed nothing - the driver has
            // not posted the next chunk's range yet. So the state a
            // park freezes is the state a pause WANTS: nobody holds a
            // stripe, nobody holds a lock, nobody spins. The driver is
            // the only hand that can free them and it is the hand that
            // will, when the gate lifts. A cancel raised while it is
            // parked comes back out of `gate` as an error and takes
            // the same `release` the poll below it always took, so the
            // workers are freed on that path too.
            //
            // The comment here until 12 Sep 2026 said this had to be
            // cancel-only "because the workers are parked at the start
            // gate and it is `release` that frees them, so a park here
            // would have to be undone by the same hand". The second
            // half is true and is not an objection: being undone by
            // the same hand is what a driver-side park IS. Workers
            // waiting on a barrier are not workers starved of work.
            // This arm did not produce the create that found the
            // defect - it is refused on `batches < 2` and that create
            // had one batch - but it had the same hole, and leaving
            // the two arms answering a Pause differently is worse than
            // either answer.
            if a.control.gate().is_err() {
                verdict = Some(Err(Par2GenError::Cancelled));
                release(&stop);
                return;
            }
            let c1 = (c0 + per_chunk).min(stripes);
            let chunk_words = (c1 - c0 - 1) * w + w.min(words - (c1 - 1) * w);
            let base = (chunks % bufs) * buf_words;
            // Bands: this chunk's stripes of every slice into the arena,
            // and the probe row's columns over them, before the chunk is
            // posted.
            let band_probe = match band_chunk(
                a,
                maps.is_some(),
                band.0,
                slot,
                &plan,
                &logs,
                &sources,
                readers,
                c0,
                w,
                chunk_words,
                &mut t_band_read,
                &mut t_band_probe,
            ) {
                Ok(probe) => probe,
                Err(e) => {
                    verdict = Some(Err(e));
                    release(&stop);
                    return;
                }
            };
            chunk_start.store(c0, std::sync::atomic::Ordering::Release);
            end.store(c1, std::sync::atomic::Ordering::Release);
            next.store(c0, std::sync::atomic::Ordering::Release);
            buf_base.store(base, std::sync::atomic::Ordering::Release);
            start_gate.wait();
            if let Some((f0, fw, fb)) = owed.take() {
                // SAFETY: the workers write the buffer at `base` only,
                // and fb != base (two buffers, alternating).
                let flushed: &[u16] =
                    unsafe { std::slice::from_raw_parts(rows.0.add(fb), buf_words) };
                let at = f0 as u64 * w as u64 * 2;
                if let Err(e) = flush_chunk(
                    a.dir, flushed, stride, fw, at, lanes, &files, &names, &place, &mut seals,
                ) {
                    end_gate.wait();
                    verdict = Some(Err(e));
                    release(&stop);
                    return;
                }
                // The recovery payload this chunk put on disk, against
                // the whole-create total `create_body` sized.
                a.control
                    .step(CreatePhase::Write, a.rows as u64 * fw as u64 * 2);
            }
            end_gate.wait();
            // The workers are parked at the start gate; the buffer they
            // just filled is ours until it is posted again.
            // SAFETY: no worker touches `staging` between the gates.
            let staging: &[u16] =
                unsafe { std::slice::from_raw_parts(rows.0.add(base), buf_words) };
            // Row `first` is staging row 0: the fold's answer or nothing.
            let expect = band_probe
                .as_deref()
                .unwrap_or_else(|| &probe[c0 * w..c0 * w + chunk_words]);
            if staging[..chunk_words] != expect[..chunk_words] {
                tracing::warn!(
                    target: "repair-timing",
                    "create stripe-first: probe row DISAGREES with the fold at stripe {c0} - recomputing every row by the batched path"
                );
                verdict = Some(Err(Par2GenError::Other(String::new())));
                release(&stop);
                return;
            }
            owed = Some((c0, chunk_words, base));
            if bufs == 1 {
                // In series: drain before the buffer is posted again.
                let (f0, fw, fb) = owed.take().expect("just set");
                // SAFETY: the workers are parked at the start gate; the
                // one buffer is ours until the next chunk is posted.
                let flushed: &[u16] =
                    unsafe { std::slice::from_raw_parts(rows.0.add(fb), buf_words) };
                let at = f0 as u64 * w as u64 * 2;
                if let Err(e) = flush_chunk(
                    a.dir, flushed, stride, fw, at, lanes, &files, &names, &place, &mut seals,
                ) {
                    verdict = Some(Err(e));
                    release(&stop);
                    return;
                }
                a.control
                    .step(CreatePhase::Write, a.rows as u64 * fw as u64 * 2);
            }
            chunks += 1;
            a.control.step(CreatePhase::Fold, (c1 - c0) as u64);
            c0 = c1;
        }
        if let Some((f0, fw, fb)) = owed.take() {
            // SAFETY: the workers are parked; the buffer is ours.
            let flushed: &[u16] = unsafe { std::slice::from_raw_parts(rows.0.add(fb), buf_words) };
            let at = f0 as u64 * w as u64 * 2;
            if let Err(e) = flush_chunk(
                a.dir, flushed, stride, fw, at, lanes, &files, &names, &place, &mut seals,
            ) {
                verdict = Some(Err(e));
                release(&stop);
                return;
            }
            a.control
                .step(CreatePhase::Write, a.rows as u64 * fw as u64 * 2);
        }
        release(&stop);
        verdict = Some(Ok(()));
    });
    match verdict {
        Some(Ok(())) => {}
        // The probe mismatch is signalled with an empty message; a real
        // write error carries its path.
        Some(Err(Par2GenError::Other(m))) if m.is_empty() => return Ok(None),
        Some(Err(e)) => return Err(e),
        None => unreachable!("the chunk loop always sets a verdict"),
    }
    let corpus = match &maps {
        Some(_) => "mapped".to_string(),
        None => format!(
            "bands of {} B over copies, read {:.2?}, probe {:.2?}, {readers} reader(s)",
            band_arena.len(),
            t_band_read,
            t_band_probe
        ),
    };
    drop(maps);
    drop(band_arena);
    drop(sources);
    a.control.finish(CreatePhase::Fold);
    for (r, m) in seals.into_iter().enumerate() {
        let digest: [u8; 16] = m.finalize().into();
        let (vi, hdr) = place[r];
        crate::disk::write_all_at(&files[vi], &digest, hdr + 16)
            .map_err(io(&a.dir.join(&names[vi])))?;
    }
    for (f, name) in files.iter().zip(&names) {
        f.sync_data().map_err(io(&a.dir.join(name)))?;
    }
    if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
        tracing::info!(
            target: "repair-timing",
            "create stripe-first: {} rows in {chunks} chunk(s) of {per_chunk} stripes (n={}, {corpus}, W={w}, threads={threads}, probe ok): {:.2?}",
            a.rows,
            a.n_slices,
            t0.elapsed()
        );
    }
    Ok(Some(names.into_iter().zip(patches).collect()))
}

/// The BAND RUN'S FLOOR, which is what bounds the shape the bands arm can
/// ever be asked about (claim `stripe-first-bands-sweep-ladder-overram`,
/// 16 Sep 2026). Pinned against the two constants it falls out of rather
/// than against a measured number, so a change to either is a test
/// failure and not a silent change of regime.
#[cfg(test)]
mod band_run_floor_tests {
    use super::super::ntt_range::{NTT_WINDOW_MIN, create_ntt_window_with_budget};
    use crate::par2repair::MAX_INPUT_SLICES;

    /// `run = band_corpus_bytes / n_slices` - the contiguous stretch each
    /// sweep takes from one slice, and the proxy section 3 of
    /// research/STRIPE-FIRST-BANDS-ONE-BATCH-2026-09-16.md derives as the
    /// axis separating the band route's win from its loss.
    ///
    /// IT CANNOT GO BELOW `bs / 32`, and that is arithmetic rather than a
    /// measurement: `create_ntt_window_with_budget` admits only a window
    /// of at least `NTT_WINDOW_MIN` slices, the arena is `window * bs`, and
    /// `n_slices` cannot exceed `MAX_INPUT_SLICES`, so
    /// `run >= NTT_WINDOW_MIN * bs / MAX_INPUT_SLICES = bs / 32`. A budget
    /// below `NTT_WINDOW_MIN * bs` does not give a SHORTER run - it gives
    /// no transform at all, and both arms fall to the fold, which is the
    /// other half of this test.
    ///
    /// WHY IT MATTERS. Section 6 of that write-up named the unmeasured
    /// risk as "a small-memory box creating a very large set", worked as
    /// 384 MiB of band over 45 GiB - 120 sweeps and a 12 KiB run, the
    /// losing cell's geometry at a winning cell's size. That cell does not
    /// exist. A 45 GiB corpus at the slice cap is 1.44 MiB blocks, so
    /// 384 MiB of budget buys 266 slices, the window is refused, and the
    /// shortest run that shape can reach is 46 KiB - four times the losing
    /// cell's 12 KiB and a fifth of the winning cell's 241 KiB. A 12 KiB
    /// run needs a block of 384 KiB or less, i.e. a corpus of at most
    /// 12 GiB at the cap: the short-run geometry is reachable only where
    /// the whole corpus is small, so "over RAM" and "short run" are
    /// available together only on a genuinely small-memory box.
    #[test]
    fn the_band_run_cannot_fall_below_a_thirty_second_of_the_block() {
        // An ordinary create's row count, comfortably over the row gate
        // `shape_possible` applies: the question here is the WINDOW, and a
        // shape refused for its rows would not exercise it.
        const ROWS: usize = 1638; // 5% of the slice cap
        for &bs in &[64 << 10, 256 << 10, 1 << 20, 4 << 20] {
            for &n_slices in &[1024usize, 4096, 16384, MAX_INPUT_SLICES] {
                let mut admitted = 0;
                // Walk the budget from under the floor to the whole corpus.
                for step in 1..=64usize {
                    let budget = step * NTT_WINDOW_MIN * bs / 8;
                    let Some(window) =
                        create_ntt_window_with_budget(bs, n_slices, ROWS, ROWS, budget)
                    else {
                        continue;
                    };
                    admitted += 1;
                    assert!(
                        window >= NTT_WINDOW_MIN.min(n_slices),
                        "bs={bs} n={n_slices} budget={budget}: window {window} under the floor"
                    );
                    let run = window.saturating_mul(bs) / n_slices;
                    assert!(
                        run >= bs / 32,
                        "bs={bs} n={n_slices} budget={budget}: run {run} under bs/32 ({})",
                        bs / 32
                    );
                }
                assert!(
                    admitted > 0,
                    "bs={bs} n={n_slices}: no budget in the walk admitted a window - \
                     the walk has stopped exercising the rule it pins"
                );
            }
        }
    }

    /// The other half: below `NTT_WINDOW_MIN * bs` of budget the window is
    /// REFUSED outright. This is why a short run cannot be bought by
    /// shrinking the band budget - the arm simply stops being reached, and
    /// a round that asks for such a rung measures the fold in both arms.
    #[test]
    fn a_budget_under_the_window_floor_is_refused_rather_than_swept_harder() {
        let bs = 1_474_560; // a 45 GiB corpus at the slice cap: 1.44 MiB.
        let n = MAX_INPUT_SLICES;
        let rows = 1638;
        assert_eq!(
            create_ntt_window_with_budget(bs, n, rows, rows, 384 << 20),
            None,
            "384 MiB over 45 GiB buys {} slices, under the {NTT_WINDOW_MIN}-slice floor, \
             so section 6's 120-sweep cell cannot be reached",
            (384 << 20) / bs
        );
        // And the smallest budget that IS admitted gives a run far above
        // the 12 KiB the losing cell measured.
        let window = create_ntt_window_with_budget(bs, n, rows, rows, NTT_WINDOW_MIN * bs)
            .expect("the floor itself admits");
        assert_eq!(window, NTT_WINDOW_MIN);
        assert_eq!(window * bs / n, bs / 32);
        assert!((44 << 10..48 << 10).contains(&(window * bs / n)));
    }
}
