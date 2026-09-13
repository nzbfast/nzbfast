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

/// Whether this create takes the one-pass route: several batches, no
/// fused scan, mapped members, and the transform admissible for every
/// row at once. Names its verdict on the timing channel either way.
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
) -> bool {
    let why = if !enabled() {
        Some("the knob is off (NZBFAST_CREATE_STRIPE_FIRST=0)")
    } else if batches < 2 {
        Some("one batch - the batched path already makes a single pass")
    } else if fused {
        Some("the scan is fused into the fold")
    } else if !super::map_inputs_enabled() {
        Some("the members are not mapped")
    } else if super::ntt_range::create_ntt_window(bs, n_slices, first, rows).is_none() {
        Some("the transform is not admitted for all rows at once")
    } else {
        None
    };
    if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
        match why {
            Some(why) => tracing::info!(
                target: "repair-timing",
                "create stripe-first refused: {why} ({batches} batch(es), {rows} rows, n={n_slices}, fused={fused})"
            ),
            None => tracing::info!(
                target: "repair-timing",
                "create stripe-first admitted: {batches} batches, {rows} rows, n={n_slices}"
            ),
        }
    }
    why.is_none()
}

pub(super) struct Args<'a> {
    pub control: &'a CreateControl,
    /// Every volume laid out below is noted here before its
    /// `File::create`, so a cancel removes it - see
    /// `control::CreateTrail`.
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
    if !admissible(batches(layout, per_batch), fused, bs, n_slices, first, rows) {
        return Ok(None);
    }
    run(&Args {
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
    let Some(maps) = MappedPlan::open(a.scanned, &plan, bs, window.saturating_mul(bs)) else {
        return Ok(None);
    };
    // The independent check: row `first` by the fold over the same
    // sources, compared chunk by chunk below.
    let mut probe = vec![vec![0u16; words]];
    {
        let srcs: Vec<&[u8]> = (0..a.n_slices).map(|i| maps.block(i, bs)).collect();
        // `None`: no honest creator `Sub` - see `fold_parallel`.
        crate::par2repair::linalg::fold_parallel(
            &mut probe,
            &srcs,
            &|_, i| crate::gf16::pow2(logs[i] as u64 * a.first as u64 % crate::gf16::ORDER as u64),
            None,
        );
    }
    let probe = &probe[0];

    // Volumes laid out up front, exactly as the batched writer lays them
    // (its shape is what the backfill patches): the head layout puts the
    // critical block first and the packets after it; the interleaved
    // layout (par2cmdline's, the CLI's default) puts each recovery
    // packet, then the critical packets the schedule owes at that point,
    // and the Creator once at the end, recording every critical copy's
    // offset. Recovery headers go in with their MD5 field zero; the
    // payloads and seals follow.
    let packet = 68 + bs as u64;
    let mut files: Vec<std::fs::File> = Vec::with_capacity(a.layout.len());
    let mut names: Vec<String> = Vec::with_capacity(a.layout.len());
    let mut patches: Vec<CriticalPatch> = Vec::with_capacity(a.layout.len());
    // Per row: (volume, offset of the packet header in that file).
    let mut place: Vec<(usize, u64)> = vec![(0, 0); a.rows];
    for (vi, &(vfirst, count)) in a.layout.iter().enumerate() {
        let name = format!("{}.vol{vfirst:03}+{count:02}.par2", a.base);
        let path = a.dir.join(&name);
        a.trail.note(&name);
        let f = std::fs::File::create(&path).map_err(io(&path))?;
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
    let mut seals: Vec<Md5> = (0..a.rows)
        .map(|r| {
            let mut m = Md5::new();
            m.update(a.set_id);
            m.update(TYPE_RECVSLIC);
            m.update(((a.first + r) as u32).to_le_bytes());
            m
        })
        .collect();

    let (w, threads) = crate::par2repair::ntt_stripe_geometry(bs);
    let stripes = words.div_ceil(w);
    ntt_range::note_stripes(stripes);
    let stripe_bytes = a.rows * w * 2;
    let natural = (STAGING_BYTES / stripe_bytes)
        .max(threads * 2)
        .clamp(1, stripes);
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
            let table = &maps;
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
                        // SAFETY: every table entry is readable for `bs`
                        // bytes and c*w*2 + 2*len <= bs - the transform's
                        // src_of contract.
                        let src_of = |id: crate::par2ntt::SrcId| unsafe {
                            table.table[id as usize].add(c * w * 2)
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
            if staging[..chunk_words] != probe[c0 * w..c0 * w + chunk_words] {
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
    drop(maps);
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
            "create stripe-first: {} rows in {chunks} chunk(s) of {per_chunk} stripes (n={}, mapped, W={w}, threads={threads}, probe ok): {:.2?}",
            a.rows,
            a.n_slices,
            t0.elapsed()
        );
    }
    Ok(Some(names.into_iter().zip(patches).collect()))
}
