//! The two transform arms of [`super::recovery_slices`]: the mapped
//! single-window attempt (unix, every full block read straight out of
//! the members' mappings) and the copied-window attempt behind it.
//!
//! Split out of `par2gen.rs` on 9 Sep 2026 (claim
//! `par2gen-size-split-9sep`) when `recovery_slices` sat 13 lines under
//! the size gate's 500-line function ceiling. Both bodies moved
//! verbatim; the only rewrite is the one a call boundary forces, `return
//! Ok(acc)` becoming `return Ok(true)` - the caller owns `acc` and
//! returns it itself. `false` means "the transform did not produce these
//! rows, take the fold below", which is what a refused mapping, an
//! unbuildable plan and a probe row that DISAGREES all mean.
//!
//! Two `&` also came off, for the same reason and no other: `plan` and
//! `acc` were owned locals in `recovery_slices` and arrive here already
//! borrowed, so `&plan` and `&mut acc` at their call sites would be the
//! double borrow `clippy::needless_borrow` refuses.

use super::*;

/// Everything both arms read out of [`super::recovery_slices`]. A
/// struct rather than eleven positional parameters, for the same reason
/// [`super::FoldWindows`] is one.
pub(super) struct NttArms<'a> {
    pub(super) control: &'a CreateControl,
    pub(super) read_window: &'a (
            dyn Fn(
        usize,
        usize,
        &mut [u8],
        Option<&[std::fs::File]>,
        bool,
        usize,
    ) -> Result<(), Par2GenError>
                + Sync
        ),
    pub(super) scanned: &'a [(PathBuf, u64)],
    pub(super) plan: &'a [(usize, u64, usize)],
    pub(super) logs: &'a [u32],
    pub(super) bs: usize,
    pub(super) words: usize,
    pub(super) n_slices: usize,
    pub(super) first: usize,
    pub(super) count: usize,
    pub(super) ntt_window: usize,
    pub(super) per_read: usize,
}

/// The mapped single-window attempt. `Ok(true)` means `acc` holds the
/// finished rows and the caller is done.
pub(super) fn mapped_attempt(
    a: &NttArms<'_>,
    acc: &mut [Vec<u16>],
    arena: &mut [u8],
) -> Result<bool, Par2GenError> {
    let &NttArms {
        control,
        read_window,
        scanned,
        plan,
        logs,
        bs,
        words,
        n_slices,
        first,
        count,
        ntt_window,
        per_read,
    } = a;
    let t_ntt = std::time::Instant::now();
    if let Some(mp) = MappedPlan::open(scanned, plan, bs, ntt_window.saturating_mul(bs)) {
        let tails = mp.tails;
        let maps = mp;
        {
            let present: Vec<(u32, crate::par2ntt::SrcId)> = logs
                .iter()
                .enumerate()
                .map(|(i, &l)| (l, i as crate::par2ntt::SrcId))
                .collect();
            if let Ok((ntt, out_first)) = ntt_range::plan(&present, first, count) {
                let (w, threads) = crate::par2repair::ntt_stripe_geometry(bs);
                let stripes = words.div_ceil(w);
                ntt_range::note_stripes(stripes);
                struct Rows(Vec<*mut u16>);
                // SAFETY: raw pointers into the accumulator rows; workers
                // write disjoint column ranges only (one stripe per
                // atomic claim), so sharing them across the scope's
                // threads races nothing.
                unsafe impl Send for Rows {}
                // SAFETY: as above.
                unsafe impl Sync for Rows {}
                let rows = Rows(acc.iter_mut().map(|r| r.as_mut_ptr()).collect());
                let table = &maps;
                let next = std::sync::atomic::AtomicUsize::new(0);
                std::thread::scope(|sc| {
                    for _ in 0..threads {
                        let ntt = &ntt;
                        let rows = &rows;
                        let table = &table;
                        let next = &next;
                        sc.spawn(move || {
                            let mut scratch = ntt.new_scratch(w);
                            let mut out = vec![0u16; ntt.needed * w];
                            loop {
                                // THE PARK SITE OF THIS ARM, and it is
                                // BEFORE the claim below on purpose: a
                                // worker here has finished its last
                                // stripe and not yet taken another, so
                                // it holds nothing any other worker
                                // could take and nothing any other
                                // worker is waiting on. That is exactly
                                // what `control::PauseGate` asks, and
                                // it is why this one site may park
                                // where the site one line down may not.
                                //
                                // It cost nothing to add: `gate` is
                                // `gate_if_held`, one RELAXED LOAD of
                                // the `paused || cancelled` mirror -
                                // the same single load the bare
                                // `cancelled()` poll here used to be -
                                // and it takes the mutex only when
                                // somebody is actually holding the
                                // create. So this honours BOTH controls
                                // at the price the cancel alone cost.
                                //
                                // Until 12 Sep 2026 it was that bare
                                // cancel poll, and a create's Pause did
                                // nothing WHATEVER in consequence: this
                                // transform is the whole of a create's
                                // arithmetic, the only other park sites
                                // are the batch boundary before it and
                                // the window loop it does not use, so a
                                // one-batch mapped create had no park
                                // point anywhere inside 10.73 s of a
                                // 12.85 s run. The job went to Paused,
                                // some threads stalled, and it then ran
                                // to completion and wrote the whole set
                                // with Resume never pressed. Measured
                                // three times, the third with CPU
                                // accounting.
                                if control.gate().is_err() {
                                    break;
                                }
                                let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if c >= stripes {
                                    break;
                                }
                                let len = w.min(words - c * w);
                                // SAFETY: every table entry is readable
                                // for `bs` bytes (full blocks inside a
                                // mapping, tails inside the pad arena),
                                // and c*w*2 + 2*len <= bs - transform's
                                // src_of contract.
                                let src_of = |id: crate::par2ntt::SrcId| unsafe {
                                    table.table[id as usize].add(c * w * 2)
                                };
                                ntt.transform(&src_of, len, &mut scratch, &mut out);
                                for (j, &row) in rows.0.iter().enumerate() {
                                    let e = out_first + j;
                                    // SAFETY: row j is `words` long and
                                    // c*w + len <= words; stripe c is
                                    // this worker's alone.
                                    let dst = unsafe {
                                        std::slice::from_raw_parts_mut(row.add(c * w), len)
                                    };
                                    dst.copy_from_slice(&out[e * len..(e + 1) * len]);
                                }
                            }
                        });
                    }
                });
                // A cancelled transform leaves `acc` part-written,
                // and the probe below would read that as a DISAGREEING
                // transform and recompute every row by the fold - which
                // is exactly what a cancel must not do. So it unwinds
                // here, before the check.
                if control.cancelled() {
                    drop(maps);
                    return Err(Par2GenError::Cancelled);
                }
                // The check: row `first` again, by the fold, over the
                // same sources.
                let mut probe = vec![vec![0u16; words]];
                // SAFETY: every table entry is readable for `bs` bytes
                // (see above) and nothing writes through them.
                let srcs: Vec<&[u8]> = (0..n_slices).map(|i| maps.block(i, bs)).collect();
                // `None`: no honest creator `Sub` - see `fold_parallel`.
                let c = |_: usize, i: usize| row_coeff(logs[i], first);
                crate::par2repair::linalg::fold_parallel(&mut probe, &srcs, &c, None);
                drop(srcs);
                if probe[0] == acc[0] {
                    if std::env::var_os("NZBFAST_NTT_PROFILE").is_some() {
                        let r = crate::par2ntt::FlatPlan::profile_report();
                        tracing::info!(
                            target: "repair-timing",
                            "ntt profile (inclusive thread-seconds): depth0 {:.2} depth1 {:.2} depth2 {:.2} leaves {:.2}",
                            r[0], r[1], r[2], r[3]
                        );
                    }
                    if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                        tracing::info!(
                            target: "repair-timing",
                            "create ntt rows {first}+{count} (n={n_slices}, mapped, {tails} tail(s) padded, W={w}, {stripes} stripe(s), threads={threads}, probe ok): {:.2?}",
                            t_ntt.elapsed()
                        );
                    }
                    drop(maps);
                    return Ok(true);
                }
                tracing::warn!(
                    target: "repair-timing",
                    "create ntt rows {first}+{count} (mapped): probe row DISAGREES with the fold - recomputing every row by the fold"
                );
                for row in acc.iter_mut() {
                    row.fill(0);
                }
                drop(maps);
                // Straight to the fold: a disagreeing transform is not
                // retried through the windows.
                let mut w0 = 0usize;
                control.begin(CreatePhase::Fold, n_slices as u64 * bs as u64);
                while w0 < n_slices {
                    control.gate()?;
                    let w1 = (w0 + per_read).min(n_slices);
                    let window = &plan[w0..w1];
                    read_window(
                        w0,
                        w1,
                        &mut arena[..window.len() * bs],
                        None,
                        false,
                        create_readers(false),
                    )?;
                    let held: Vec<u32> = logs[w0..w1].to_vec();
                    fold_batch(acc, &arena[..window.len() * bs], bs, &held, first, false);
                    control.step(CreatePhase::Fold, (w1 - w0) as u64 * bs as u64);
                    w0 = w1;
                }
                return Ok(true);
            }
        }
        // Mapping failed or the plan is unbuildable: the copied
        // windows below take it.
    }
    Ok(false)
}

/// The copied-window attempt: the transform over resident windows of
/// the payload, outputs XORed together. `Ok(true)` means `acc` holds the
/// finished rows; on `Ok(false)` its rows have been zeroed again for the
/// fold.
pub(super) fn windowed_attempt(
    a: &NttArms<'_>,
    acc: &mut [Vec<u16>],
) -> Result<bool, Par2GenError> {
    let &NttArms {
        control,
        read_window,
        logs,
        bs,
        words,
        n_slices,
        first,
        count,
        ntt_window,
        ..
    } = a;
    let t_ntt = std::time::Instant::now();
    let (w, threads) = crate::par2repair::ntt_stripe_geometry(bs);
    let stripes = words.div_ceil(w);
    let mut corpus = vec![0u8; ntt_window * bs];
    // The check: row `first` again, by the fold, over the same
    // windows, accumulated the same way.
    let mut probe = vec![vec![0u16; words]];
    let mut ok = true;
    let mut windows = 0usize;
    // All windows request the same output rows and stripe width. Retain
    // each worker's arenas across plans instead of allocating and faulting
    // them again for every window. Input pointers never live in Scratch.
    let mut workers: Vec<Option<(crate::par2ntt::Scratch, Vec<u16>)>> =
        (0..threads).map(|_| None).collect();
    let mut w0 = 0usize;
    while w0 < n_slices {
        // Between two transform windows on the driver thread: the park
        // site of this arm, and its cancel grain.
        control.gate()?;
        let w1 = (w0 + ntt_window).min(n_slices);
        let wn = w1 - w0;
        read_window(
            w0,
            w1,
            &mut corpus[..wn * bs],
            None,
            false,
            create_readers(false),
        )?;
        let present: Vec<(u32, crate::par2ntt::SrcId)> = logs[w0..w1]
            .iter()
            .enumerate()
            .map(|(i, &l)| (l, i as crate::par2ntt::SrcId))
            .collect();
        let Ok((ntt, out_first)) = ntt_range::plan(&present, first, count) else {
            ok = false;
            break;
        };
        ntt_range::note_stripes(stripes);
        struct Rows(Vec<*mut u16>);
        // SAFETY: raw pointers into the accumulator rows; workers
        // write disjoint column ranges only (one stripe per atomic
        // claim), so sharing them across the scope's threads races
        // nothing.
        unsafe impl Send for Rows {}
        // SAFETY: as above - every write is confined to the claiming
        // worker's stripe columns.
        unsafe impl Sync for Rows {}
        let rows = Rows(acc.iter_mut().map(|r| r.as_mut_ptr()).collect());
        let corpus_ref = &corpus;
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|sc| {
            for worker in &mut workers {
                let ntt = &ntt;
                let rows = &rows;
                let next = &next;
                sc.spawn(move || {
                    let (scratch, out) = worker
                        .get_or_insert_with(|| (ntt.new_scratch(w), vec![0u16; ntt.needed * w]));
                    loop {
                        // Parks before the claim, for the reason the
                        // mapped arm above states at length. This arm
                        // ALSO gates on its driver thread between two
                        // windows, so a pause was already bounded by
                        // one window here - but a window of a large
                        // set is seconds, and there is no reason for
                        // the two arms to answer a Pause differently.
                        if control.gate().is_err() {
                            break;
                        }
                        let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if c >= stripes {
                            break;
                        }
                        let len = w.min(words - c * w);
                        // SAFETY: slot `id` holds a full block of
                        // `bs` bytes in `corpus`, and c*w*2 + 2*len
                        // <= bs because len = w.min(words - c*w) -
                        // transform's src_of contract.
                        let src_of = |id: crate::par2ntt::SrcId| unsafe {
                            corpus_ref.as_ptr().add(id as usize * bs + c * w * 2)
                        };
                        ntt.transform(&src_of, len, scratch, out);
                        for (j, &row) in rows.0.iter().enumerate() {
                            let e = out_first + j;
                            // SAFETY: row j is `words` long and c*w +
                            // len <= words; stripe c is this worker's
                            // alone, so no other thread touches these
                            // columns.
                            let dst =
                                unsafe { std::slice::from_raw_parts_mut(row.add(c * w), len) };
                            for (d, o) in dst.iter_mut().zip(&out[e * len..(e + 1) * len]) {
                                *d ^= *o;
                            }
                        }
                    }
                });
            }
        });
        let srcs: Vec<&[u8]> = (0..wn).map(|i| &corpus[i * bs..][..bs]).collect();
        let c = |_: usize, i: usize| row_coeff(logs[w0 + i], first);
        crate::par2repair::linalg::fold_parallel(&mut probe, &srcs, &c, None);
        windows += 1;
        control.step(CreatePhase::Fold, wn as u64 * bs as u64);
        w0 = w1;
    }
    drop(workers);
    drop(corpus);
    // As in the mapped arm: a part-transformed `acc` must not reach the
    // probe, which would read it as a disagreement and recompute.
    control.check()?;
    if ok && probe[0] == acc[0] {
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            tracing::info!(
                target: "repair-timing",
                "create ntt rows {first}+{count} (n={n_slices}, {windows} window(s) of {ntt_window}, W={w}, {stripes} stripe(s), threads={threads}, probe ok): {:.2?}",
                t_ntt.elapsed()
            );
        }
        return Ok(true);
    }
    tracing::warn!(
        target: "repair-timing",
        "create ntt rows {first}+{count}: {} - recomputing every row by the fold",
        if ok { "probe row DISAGREES with the fold" } else { "plan unbuildable for a window" }
    );
    for row in acc.iter_mut() {
        row.fill(0);
    }
    Ok(false)
}
