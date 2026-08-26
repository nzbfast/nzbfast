//! The recovery-side speculation: what the run does about damage that
//! is already certain, rather than about the payload it is still
//! fetching. Three tasks and their arithmetic - the M2c.5 speculative
//! recovery prefetch and its smallest-first ladder, the dark PAR2-race
//! experiment, and the §146 tail give-up - lifted out of workers.rs
//! whole and in file order (TODO 106, 24 Aug 2026). They share one
//! question and one currency: how many recovery blocks are on hand
//! against how many the observed damage will cost.

use super::*;

// M2c.5 speculative recovery prefetch: the moment ANY article goes
// terminally Missing/Failed, damage is certain - fetch the smallest
// recovery volume on a tiny side pool (1 conn/server; the main pool
// owns the provider grants) so the post-settle exact-fit pass starts
// with recovery blocks already on disk. The daemon gates this via
// hub.spec_prefetch (off when a quota is configured - mirrors the
// sidecar-prefetch guard); CLI runs opt out with
// NZBFAST_NO_SPEC_PREFETCH=1. Risk is bounded to one small volume of
// possibly-wasted bytes. Skipped when the set bootstraps from a
// volume (one is already inbound) or the NZB ships no volumes.
#[expect(clippy::too_many_arguments)]
pub(super) fn spawn_spec_prefetch(
    allowed: bool,
    has_main: bool,
    nzb: &Arc<Nzb>,
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    slots: &[Arc<FileSlot>],
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    prefetch_stop: &Arc<std::sync::atomic::AtomicBool>,
    // §146: the tail give-up's standing order, in recovery SLICES - the
    // 2x ceiling it needs on hand before it may abandon the walkers.
    // Terminal missing is a TRAILING indicator paced by the very ladder
    // the give-up exists to skip, so escalating on it alone always
    // arrives too late; walkers at queue-dry are refused-somewhere
    // articles on an idle wire, and covering them is the same certain-
    // damage bet one rung earlier.
    tail_demand: &Arc<std::sync::atomic::AtomicUsize>,
) -> Option<tokio::task::JoinHandle<()>> {
    let target = (allowed && has_main)
        .then(|| {
            nzb.files
                .iter()
                .enumerate()
                .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
                .min_by_key(|(_, f)| f.bytes())
                .map(|(fi, f)| (fi, f.bytes()))
        })
        .flatten();
    target.map(|_| {
        // Smallest-first ladder of every recovery volume: (fi,
        // declared/estimated slice count, bytes). The watcher escalates
        // one rung at a time while the missing count outruns the blocks
        // already prefetched - missing articles are CERTAIN damage,
        // so cover for the observed count is never wasted bytes.
        //
        // C5: the ladder retains ONLY these three words per volume. A
        // rung's `ArticleReq`s and id map are built by `volume_reqs`
        // at rung selection, from the `Arc<Nzb>` the task holds - the
        // eager form retained ~166 bytes per recovery segment (4.1 MB
        // measured at 25k recovery segments, `c5_spec_ladder_rss_at_
        // field_scale`) for the whole run, and a healthy run read none
        // of it. Healthy runs now build zero recovery requests.
        let ladder = spec_ladder(nzb);
        let nzb2 = Arc::clone(nzb);
        let side_servers = side_pool_servers(servers);
        // §146: the fleet a DEMAND rung runs on. The 1-conn side pool
        // exists so a prefetch never provokes a provider's connection
        // cap while the main fleet holds this account's grants - but a
        // demand rung only fires at queue-dry, when the main fleet is
        // holding those grants IDLE over nothing but refusal walkers.
        // Borrowing up to 8 connections per server (never above the
        // user's own configured budget) fetches hundreds of MB of
        // recovery data in the seconds the give-up needs, instead of
        // trickling it through one connection per server while the
        // ladder it exists to retire walks to completion first. An
        // account genuinely at its cap refuses the extra dials and the
        // capacity machinery parks them - degrading to the old pace,
        // not failing.
        let tail_servers: Vec<(ServerConfig, nzbkit::pool::PoolConfig)> = side_servers
            .iter()
            .map(|(sc, pc)| {
                let mut sc = sc.clone();
                let mut pc = pc.clone();
                let width = servers
                    .iter()
                    .find(|(s, _)| s.host == sc.host && s.port == sc.port)
                    .map(|(s, _)| s.connections.clamp(1, 8))
                    .unwrap_or(1);
                sc.connections = width;
                pc.connections = width as usize;
                (sc, pc)
            })
            .collect();
        let slots2 = slots.to_vec();
        let out2 = out_dir.to_path_buf();
        let bp = buf_pool.clone();
        let vol_cap = volume_prealloc_cap(nzb);
        let pre = prefetched.clone();
        let stop = prefetch_stop.clone();
        let demand = tail_demand.clone();
        tokio::spawn(async move {
            // Codex 5 Aug M3: a rung used to run with no cancellation
            // handle, so a blackholed side provider held drain_network's
            // unconditional await - and with it Cancel/Pause - through
            // the side pool's whole multi-session retry ladder. The
            // latch-plus-re-abort watcher that fixed it now lives in
            // `SideCancel`, inside the one driver every side-fetch goes
            // through (§129 residue 2 needed the same wire for the
            // lane's repair fetches). `over` shares THIS ladder's own
            // stop flag, so the loop below still reads it directly and
            // there is only ever one latch.
            let cancel = crate::repair::SideCancel::over(stop.clone());
            let body = async {
            let mut covered = 0usize;
            let mut ladder = ladder;
            loop {
                if stop.load(Ordering::Acquire) {
                    return; // network phase over - settle takes it from here
                }
                let miss: usize =
                    slots2.iter().map(|s| s.missing.load(Ordering::Relaxed)).sum();
                // The give-up's standing order outranks the terminal
                // count when it is larger - see the parameter doc.
                let want = miss.max(demand.load(Ordering::Acquire));
                if want > covered {
                    let deficit = want - covered;
                    if ladder.is_empty() {
                        return; // every volume already prefetched
                    }
                    let at = pick_rung(&ladder, deficit);
                    let (fi, count, bytes) = ladder.remove(at);
                    // C5: this rung's requests are born here, at
                    // selection - microseconds against a 250 ms poll,
                    // so the loss-to-first-recovery-BODY latency is
                    // unchanged.
                    let mut reqs = Vec::new();
                    let mut idm = std::collections::HashMap::new();
                    // Sweep 9, finding 7: the omitted-duplicate count
                    // is part of this rung's completeness, exactly as
                    // it is for `fetch_volumes` (Codex F-02). A segment
                    // whose message-id an earlier segment of this same
                    // volume already claimed is never requested, so no
                    // `Missing`/`Failed` outcome comes back for it and
                    // `f.total()` reads 0 over a volume that is short.
                    // Recorded complete, settle strikes the whole
                    // volume off the post-settle fetch list and the
                    // slices that lived only on those ids can never be
                    // asked for again. One volume per rung and a fresh
                    // id map each time, so this is intra-volume
                    // duplication only - a malformed or hostile
                    // recovery set, never a healthy NZB.
                    let omitted =
                        crate::repair::volume_reqs(&nzb2, fi, &mut reqs, &mut idm);
                    if want > miss {
                        info!(
                            target: "repair",
                            "{miss} article(s) terminally missing and {want} recovery \
                             block(s) wanted to retire the refusal ladder - prefetching \
                             recovery volume ({:.1} MB)",
                            bytes as f64 / 1e6
                        );
                    } else {
                        info!(
                            target: "repair",
                            "{miss} article(s) terminally missing - prefetching recovery volume ({:.1} MB) alongside the download",
                            bytes as f64 / 1e6
                        );
                    }
                    // A demand rung rides the borrowed-width fleet; an
                    // ordinary terminal-missing rung keeps the polite
                    // 1-conn side pool.
                    let fleet = if want > miss {
                        &tail_servers
                    } else {
                        &side_servers
                    };
                    let fetched = fetch_volume_articles(
                        fleet,
                        reqs,
                        idm,
                        &out2,
                        &bp,
                        vol_cap,
                        Some(&cancel),
                    )
                    .await;
                    if stop.load(Ordering::Acquire) {
                        // The handle aborted this rung mid-flight. An
                        // aborted run's unresolved articles emit NO
                        // outcome, so the failure count can read 0 over
                        // a volume that is actually incomplete - credit
                        // or record it and the whole volume is struck
                        // off the post-settle fetch list with slices
                        // missing (the H2 false-shortfall shape). Leave
                        // the rung unrecorded; unrecorded is always
                        // safe, the post-settle ladder refetches it.
                        return;
                    }
                    match fetched {
                        // One rung is one volume, so the fetch-wide
                        // total and this file's own count are the same
                        // number here - `total()` reads it without
                        // threading the rung's file index in.
                        Ok((f, paths))
                            if f.total().saturating_add(omitted) == 0 && !paths.is_empty() =>
                        {
                            covered += count.max(1);
                            pre.lock_ok().push((fi, paths));
                        }
                        Ok((f, paths)) if !paths.is_empty() => {
                            let failures = f.total().saturating_add(omitted);
                            // A PARTIAL volume: some articles failed.
                            // Recording its file index would strike the
                            // WHOLE volume off the post-settle fetch
                            // list while its missing slices can never
                            // be refetched - a repairable job then
                            // reports a false shortfall. Leave it
                            // unrecorded and uncredited: the next rung
                            // runs now, and the post-settle ladder can
                            // still fetch this volume in full.
                            info!(
                                target: "repair",
                                "that volume landed partially ({failures} article \
                                 failure(s)) - leaving it fetchable and trying the next rung"
                            );
                        }
                        Ok(_) => {
                            // Not one byte of that volume landed (every
                            // article failed, or it was unwritable).
                            // Claiming its blocks as covered would stall
                            // escalation, and recording the file index
                            // would strike it off the post-settle fetch
                            // list - so do neither and try the next rung.
                            info!(
                                target: "repair",
                                "that volume produced no file - trying the next one"
                            );
                        }
                        Err(e) => {
                            info!(
                                target: "repair",
                                "speculative prefetch failed ({e}) - the post-settle fetch covers it"
                            );
                            return;
                        }
                    }
                    continue; // re-check immediately - miss may have grown
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            };
            body.await;
        })
    })
}

/// The speculative ladder's retained form (C5): one `(file index,
/// declared/estimated slice count, encoded bytes)` triple per recovery
/// volume, smallest first. Requests and the id map are built at rung
/// selection by [`crate::repair::volume_reqs`], never here.
pub(in crate::get) fn spec_ladder(nzb: &Nzb) -> Vec<(usize, usize, u64)> {
    let mut ladder: Vec<(usize, usize, u64)> = nzb
        .files
        .iter()
        .enumerate()
        .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
        .map(|(fi, f)| {
            let name = f.filename_hint().unwrap_or(&f.subject);
            // Conservative when the name doesn't declare a count:
            // claim 1 so escalation keeps going rather than stopping
            // on an inflated estimate.
            (fi, vol_count_from_name(name).unwrap_or(1), f.bytes())
        })
        .collect();
    ladder.sort_by_key(|&(_, _, bytes)| bytes);
    ladder
}

/// §282 item 3: what each recovery volume DECLARES, as
/// `(count read off the name, encoded bytes)` per volume.
///
/// Deliberately not [`spec_ladder`]'s pre-summed count. That ladder
/// floors an undeclared volume at 1 so escalation keeps going, which is
/// the conservative direction for a prefetch and exactly the wrong way
/// round for a projection that compares against the post's total
/// recovery: an undercount there fires the doom warning on a post that
/// repairs comfortably. The `.vol-NN.par2` form is the live shape - it
/// numbers the volume without sizing it. So the count is left as
/// `None` here and the size-based estimate is substituted in
/// [`DamageWatch::project`], where the block size is known.
pub(in crate::get) fn declared_volumes(nzb: &Nzb) -> Vec<(Option<usize>, u64)> {
    nzb.files
        .iter()
        .filter(|f| f.kind() == FileKind::Par2Volume)
        .map(|f| {
            let name = f.filename_hint().unwrap_or(&f.subject);
            (vol_count_from_name(name), f.bytes())
        })
        .collect()
}

/// Exact-fit rung: the smallest unfetched volume covering the whole
/// deficit, else the biggest left - the pure smallest-first ladder
/// over-fetched ~2x once the damage count ran ahead of the rungs.
/// `ladder` is non-empty and sorted smallest-first ([`spec_ladder`]).
pub(super) fn pick_rung(ladder: &[(usize, usize, u64)], deficit: usize) -> usize {
    ladder
        .iter()
        .position(|&(_, count, _)| count >= deficit)
        .unwrap_or(ladder.len() - 1)
}

/// Par-race candidate selection and damage arithmetic (Codex 5 Aug
/// M2), held still where a test can reach it.
pub(super) struct RaceEstimate {
    /// Cancellable ids: only articles of payload files the recovery
    /// set COVERS - repair heals nothing else, so abandoning an
    /// uncovered companion converts a fetchable file into permanent
    /// damage settle then rightly rejects.
    pub(super) want: std::collections::HashSet<Arc<str>>,
    /// id → (slot index, declared segment bytes).
    pub(super) bytes_of: std::collections::HashMap<Arc<str>, (usize, u64)>,
    /// EXPECTED remaining bytes (per-file average) - the eta
    /// estimator, where under-racing is the conservative direction.
    pub(super) out_bytes: u64,
    /// WORST-CASE damage blocks: which `remaining` segments are still
    /// unresolved is the pool's knowledge, not ours, so charge each
    /// file its `remaining` LARGEST declared segments at their exact
    /// bytes. The old per-file average let one 100 MiB straggler hide
    /// behind 99 tiny finished segments.
    pub(super) out_blocks: usize,
}

pub(super) fn par_race_estimate(
    set_names: &std::collections::HashSet<String>,
    block: usize,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Nzb,
) -> RaceEstimate {
    let mut est = RaceEstimate {
        want: std::collections::HashSet::new(),
        bytes_of: std::collections::HashMap::new(),
        out_bytes: 0,
        out_blocks: 0,
    };
    for (sidx, s) in slots.iter().enumerate() {
        let rem = s.remaining.load(Ordering::Relaxed);
        if s.is_par2() || rem == 0 {
            continue;
        }
        // Same name normalization settle itself uses; an obfuscated
        // alias not yet reconciled simply stays out of the race.
        if !set_names.contains(&nzbkit::disk::sanitize_filename(&s.hint).to_lowercase()) {
            continue;
        }
        let f = &nzb.files[slot_file[sidx]];
        let per = (f.bytes() / f.segments.len().max(1) as u64).max(1);
        est.out_bytes += rem as u64 * per;
        let mut sizes: Vec<u64> = f.segments.iter().map(|seg| seg.bytes).collect();
        sizes.sort_unstable_by(|a, b| b.cmp(a));
        est.out_blocks += sizes
            .iter()
            .take(rem)
            .map(|b| (*b as usize).div_ceil(block) + 1)
            .sum::<usize>();
        for seg in &f.segments {
            // R9: interned here rather than looked up in `id_to_slot`.
            // This census only runs in the tail-stall state (every
            // pending article a refusal-walker) or under the dark
            // par-race flag, so it is not one of the paths the
            // interning was measured on, and reaching the plan's map
            // would mean threading it through four spawn signatures for
            // no steady-state gain. The allocation count is exactly
            // what it was; the handles it hands out are shared from
            // here on.
            let b: Arc<str> = format!("<{}>", seg.message_id).into();
            est.bytes_of.insert(b.clone(), (sidx, seg.bytes));
            est.want.insert(b);
        }
    }
    est
}

/// Worst-case block cost of the articles already terminally missing.
/// WHICH articles went missing is unknown, so bound each slot's share
/// by its own largest declared segment rather than a cross-file
/// average that a big-article file dilutes (Codex 5 Aug M2).
pub(super) fn par_race_missing_blocks(
    block: usize,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Nzb,
) -> usize {
    slots
        .iter()
        .enumerate()
        .filter(|(_, s)| !s.is_par2())
        .map(|(sidx, s)| {
            let m = s.missing.load(Ordering::Relaxed);
            if m == 0 {
                return 0;
            }
            let max_per = nzb.files[slot_file[sidx]]
                .segments
                .iter()
                .map(|seg| seg.bytes)
                .max()
                .unwrap_or(0) as usize;
            m * (max_per.div_ceil(block) + 1)
        })
        .sum()
}

// PAR2-race experiment (dark, NZBFAST_PAR_RACE=1): once the set is
// active, if the recovery blocks already on hand cover the WORST
// CASE of every still-queued payload article being abandoned - with
// 2x margin - and the line is slow enough that the remainder is
// >30 s away, cancel the queued stragglers and let repair finish
// the job: the math beats the network. Conservative on every axis:
// on-hand is the activation count plus prefetched volumes counted
// off disk; per-article damage is the whole-block ceiling plus one
// (the block its edges straddle); in-flight articles are untouched
// (`cancel` only removes QUEUED work) and resolve normally. The
// articles removed get no pool outcome, so this owns the accounting
// exactly as a sniff deferral does: remaining down, abandoned up,
// fetch_done credited. Settle needs no new damage arithmetic - the
// final read-back finds the absent blocks and the repair self-proves
// by re-reading the whole set (the invariant this leans on).
// Fires at most once per run.
#[expect(clippy::too_many_arguments)]
pub(super) fn spawn_par_race(
    slots: &[Arc<FileSlot>],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    prefetch_stop: &Arc<std::sync::atomic::AtomicBool>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    fetch_done: &Arc<AtomicU64>,
    decoded_bytes: &Arc<AtomicU64>,
    slot_file: &[usize],
    nzb: &Arc<Nzb>,
) -> Option<tokio::task::JoinHandle<()>> {
    std::env::var("NZBFAST_PAR_RACE")
        .is_ok_and(|v| v == "1")
        .then(|| {
            let slots2 = slots.to_vec();
            let verifier2 = verifier.clone();
            let queue_ctl2 = queue_ctl.clone();
            let stop = prefetch_stop.clone();
            let pre = prefetched.clone();
            let fetch_done2 = fetch_done.clone();
            let bytes_now = decoded_bytes.clone();
            let slot_file2 = slot_file.to_vec();
            let nzb2 = nzb.clone();
            tokio::spawn(async move {
                use std::collections::{HashSet, VecDeque};
                let mut win: VecDeque<(std::time::Instant, u64)> = VecDeque::new();
                loop {
                    if stop.load(Ordering::Acquire) {
                        return; // network phase over - settle owns it now
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let Some(set) = verifier2.set() else { continue };
                    // Rolling 10 s decode-rate window.
                    let now = std::time::Instant::now();
                    win.push_back((now, bytes_now.load(Ordering::Relaxed)));
                    while win
                        .front()
                        .is_some_and(|(t, _)| now.duration_since(*t).as_secs() > 10)
                    {
                        win.pop_front();
                    }
                    let (Some(&(t0, b0)), Some(&(t1, b1))) = (win.front(), win.back()) else {
                        continue;
                    };
                    let span = t1.duration_since(t0).as_secs_f64();
                    if span < 8.0 {
                        continue;
                    }
                    let rate = b1.saturating_sub(b0) as f64 / span;
                    // Candidates + damage arithmetic live in
                    // par_race_estimate / par_race_missing_blocks (the
                    // Codex 5 Aug M2 fixes), where tests can hold them
                    // still.
                    let set_names: HashSet<String> = set
                        .files
                        .iter()
                        .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
                        .collect();
                    let block = set.block_size.max(1) as usize;
                    let est = par_race_estimate(&set_names, block, &slots2, &slot_file2, &nzb2);
                    let (want, bytes_of) = (est.want, est.bytes_of);
                    let (out_bytes, out_blocks) = (est.out_bytes, est.out_blocks);
                    if want.is_empty() {
                        continue;
                    }
                    // The line must be slow enough that repair clearly
                    // wins; a healthy line finishes the remainder before
                    // any repair could start its verify pass.
                    let eta = if rate > 0.0 {
                        out_bytes as f64 / rate
                    } else {
                        f64::INFINITY
                    };
                    if eta < 30.0 {
                        continue;
                    }
                    // Damage ceiling if every unresolved article is lost:
                    // the queued ones we would cancel plus the already
                    // bad or terminally missing.
                    let (_, live_bad) = verifier2.live_counts();
                    let missing_blocks =
                        par_race_missing_blocks(block, &slots2, &slot_file2, &nzb2);
                    let damage_ceiling = out_blocks + live_bad as usize + missing_blocks;
                    let mut on_hand = set.recovery_blocks_seen;
                    for (_, paths) in pre.lock_ok().iter() {
                        for p in paths {
                            if let Ok(bytes) = std::fs::read(p) {
                                on_hand += nzbkit::par2repair::recovery_slice_locators(
                                    &bytes,
                                    &set.recovery_set_id,
                                )
                                .into_iter()
                                .filter(|(_, _, len)| *len == block)
                                .count();
                            }
                        }
                    }
                    if on_hand < damage_ceiling.saturating_mul(2) {
                        continue;
                    }
                    // Race. Cancel is best-effort under queue contention
                    // (bounded try_lock) - same retry shape as the sniff
                    // deferral.
                    let mut removed = Vec::new();
                    for attempt in 0..3 {
                        removed = queue_ctl2.cancel(&want);
                        if !removed.is_empty() {
                            break;
                        }
                        if attempt < 2 {
                            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                        }
                    }
                    if removed.is_empty() {
                        continue; // everything already in flight or done
                    }
                    // The cancel is the first moment the EXACT straggler
                    // set is known - re-run the 2x guard on it with the
                    // ids' declared bytes and a fresh live_bad (damage
                    // can grow in the second between estimate and
                    // cancel). The worst-case estimate above makes a
                    // failure here rare, not impossible.
                    let exact_blocks: usize = removed
                        .iter()
                        .filter_map(|id| bytes_of.get(&**id))
                        .map(|&(_, b)| (b as usize).div_ceil(block) + 1)
                        .sum();
                    let (_, live_bad_now) = verifier2.live_counts();
                    let exact_ceiling = exact_blocks + live_bad_now as usize + missing_blocks;
                    if on_hand < exact_ceiling.saturating_mul(2) {
                        if queue_ctl2.requeue(&removed) > 0 {
                            continue; // rolled back whole - no race this tick
                        }
                        // requeue's all-or-nothing rollback found the run
                        // already winding down, so the cancel is now
                        // irreversible. Fall through to the abandonment
                        // accounting so the bar stays truthful - settle
                        // prices the damage honestly either way.
                        warn!(
                            target: "repair",
                            "par-race: exact damage outgrew the estimate and the rollback \
                             found the run winding down - proceeding with {} abandoned \
                             article(s)",
                            removed.len()
                        );
                    }
                    let mut freed = 0u64;
                    for id in &removed {
                        if let Some(&(sidx, b)) = bytes_of.get(&**id) {
                            slots2[sidx].remaining.fetch_sub(1, Ordering::AcqRel);
                            slots2[sidx].abandoned.fetch_add(1, Ordering::Relaxed);
                            freed += b;
                        }
                    }
                    // No outcome will ever arrive for these - settle the
                    // bar here, exactly like a sniff deferral.
                    fetch_done2.fetch_add(freed, Ordering::Relaxed);
                    info!(
                        target: "repair",
                        "par-race: abandoned {} queued straggler article(s) ({:.1} MB) - \
                         {on_hand} recovery blocks on hand cover the {damage_ceiling}-block \
                         worst case at 2x, and repair beats the ~{eta:.0}s fetch remainder",
                        removed.len(),
                        freed as f64 / 1e6,
                    );
                    return;
                }
            })
        })
}

/// §146 tail give-up, the decision half - held still where a test can
/// reach it. `true` when EVERY walker article belongs to a file the
/// active recovery set covers AND the recovery blocks on hand cover the
/// exact walker set - plus the damage already priced in - at 2x. One
/// uncovered walker vetoes the whole trade: repair rebuilds nothing
/// outside its own set, so abandoning that article would convert a
/// fetchable file into permanent damage.
pub(super) fn tail_giveup_covered(
    walkers: &[nzbkit::pool::Walker],
    est: &RaceEstimate,
    block: usize,
    live_bad: usize,
    missing_blocks: usize,
    on_hand: usize,
) -> bool {
    let mut exact_blocks = 0usize;
    for w in walkers {
        let Some(&(_, b)) = est.bytes_of.get(&*w.id) else {
            return false; // a walker repair cannot rebuild - keep walking
        };
        exact_blocks += (b as usize).div_ceil(block) + 1;
    }
    let ceiling = exact_blocks + live_bad + missing_blocks;
    on_hand >= ceiling.saturating_mul(2)
}

/// §146 tail give-up: recovery slices already decoded into the job dir
/// by the MAIN pool (volumes that were never deferred, so the side
/// prefetch never saw them). Walks `.par2` files up to three levels
/// deep, skips paths the caller already counted, and re-reads a file
/// only when its length has moved since the cached count - a damaged
/// volume's holes simply truncate the packet scan, which undercounts,
/// and undercounting is the safe direction for a 2x margin.
fn disk_recovery_blocks(
    dir: &Path,
    set_id: &[u8; 16],
    block: usize,
    skip: &std::collections::HashSet<PathBuf>,
    cache: &mut std::collections::HashMap<PathBuf, (u64, std::time::SystemTime, usize)>,
) -> usize {
    fn walk(dir: &Path, depth: u8, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if depth > 0 {
                    walk(&p, depth - 1, out);
                }
            } else if p
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
            {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, 3, &mut files);
    let mut total = 0usize;
    for p in files {
        if skip.contains(&p) {
            continue;
        }
        total += cached_recovery_blocks(&p, set_id, block, cache);
    }
    total
}

/// A file is only trusted into the census cache once it has been QUIET
/// this long. Volume writers preallocate (`set_len`) at creation, so a
/// mid-write file already reports its final length and the length can
/// never invalidate an entry; the file's mtime is what still moves while
/// articles land. Two seconds also rides out coarse-mtime filesystems
/// (FAT stamps at 2 s), where a scan and a later write can share one
/// visible timestamp.
pub(super) const CENSUS_QUIET: std::time::Duration = std::time::Duration::from_secs(2);

/// Slices of `set_id` at `block` bytes inside one `.par2` file, counted
/// at most once per (length, mtime) the file has held - and only
/// remembered at all once the file has been quiet for [`CENSUS_QUIET`].
///
/// Both census roads share it - the prefetched list and the job-dir walk
/// - so a tick over settled volumes costs a `stat` each rather than
/// re-reading and re-scanning every recovery volume on disk, which is
/// what the 200 ms tail-stall tick was doing for as long as the stall
/// lasted.
///
/// The quiet gate is the R1 lesson (20 Aug 2026), and it took two rounds
/// to learn. Recovery volumes are preallocated to their FULL length at
/// the first article, so "a length that moves invalidates the entry"
/// never held for them: a scan taken while the side-fetch was still
/// writing counted only the slices that had landed (17 of 128 on one
/// traced leg, 6 on another) and that undercount was served for the rest
/// of the job - the 2x margin never cleared, the tail give-up never
/// fired, and damaged posts walked the refusal ladder 32-68% slower with
/// FLAT cpu. The first fix refused to cache only a ZERO scan, and R1
/// step 3 falsified it: a nonzero mid-write undercount is poisoned all
/// the same. What actually separates a scan worth remembering from one
/// that is not is whether the writer might still be active, and mtime is
/// the signal for that: a busy file's scan is returned but never cached
/// (base's re-read-every-tick behavior, self-healing), a quiet file's
/// scan - zero included, the index par2 genuinely has no slices - is
/// cached and costs a stat from then on.
pub(super) fn cached_recovery_blocks(
    p: &Path,
    set_id: &[u8; 16],
    block: usize,
    cache: &mut std::collections::HashMap<PathBuf, (u64, std::time::SystemTime, usize)>,
) -> usize {
    let Ok(meta) = std::fs::metadata(p) else {
        return 0;
    };
    let len = meta.len();
    let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    if let Some(&(l, t, n)) = cache.get(p)
        && l == len
        && t == mtime
    {
        return n;
    }
    let Ok(bytes) = std::fs::read(p) else {
        return 0;
    };
    let n = nzbkit::par2repair::recovery_slice_locators(&bytes, set_id)
        .into_iter()
        .filter(|(_, _, l)| *l == block)
        .count();
    // An unreadable mtime lands on UNIX_EPOCH, which reads as ancient -
    // deliberately: a filesystem that cannot report mtime cannot feed
    // the quiet gate, and permanent re-reads there would resurrect the
    // cost A5 removed.
    if mtime.elapsed().is_ok_and(|e| e >= CENSUS_QUIET) {
        cache.insert(p.to_path_buf(), (len, mtime, n));
    }
    n
}

// §146 tail give-up (default ON, kill switch NZBFAST_NO_TAIL_GIVEUP=1):
// the zero-throughput tail in front of repair on a damaged post is 60
// articles serially buying "no such article" verdicts from every
// backbone - measured 13-15 s on a real five-provider fleet, FLAT
// across a 10x connection sweep, while the recovery volumes sat
// prefetched and repair itself cost 2.2 s. Those verdicts buy nothing:
// when the recovery blocks on hand already cover every still-walking
// article, repair rebuilds their bytes EXACTLY whether the ladder ends
// in Missing or in a fifth backbone's surprise copy. So the moment the
// pool reports that nothing but 430-walkers remain (verdict_walkers -
// which is also what keeps this OFF the corrupt-body damage class:
// those refetches carry tried_fail, never tried_430) and the coverage
// maths holds at 2x, give the walkers up and let settle start repair
// NOW. Same accounting contract as the par-race above: no outcome ever
// arrives for a given-up article, so the bar is settled here, and the
// repair self-proves by re-reading the whole set. Loops rather than
// firing once - an article that slipped one census (mid-requeue
// between two locks) is caught by the next tick.
pub(super) fn spawn_tail_giveup(
    slots: &[Arc<FileSlot>],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    prefetch_stop: &Arc<std::sync::atomic::AtomicBool>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    fetch_done: &Arc<AtomicU64>,
    slot_file: &[usize],
    nzb: &Arc<Nzb>,
    out_dir: &Path,
    // The standing order to the spec prefetch (see its parameter doc):
    // set to the 2x block ceiling whenever the census is open but the
    // margin is short, so the prefetch fetches toward exactly the
    // coverage that lets the give-up fire.
    tail_demand: &Arc<std::sync::atomic::AtomicUsize>,
) -> Option<tokio::task::JoinHandle<()>> {
    if std::env::var_os("NZBFAST_NO_TAIL_GIVEUP").is_some() {
        return None;
    }
    let slots2 = slots.to_vec();
    let verifier2 = verifier.clone();
    let queue_ctl2 = queue_ctl.clone();
    let stop = prefetch_stop.clone();
    let pre = prefetched.clone();
    let fetch_done2 = fetch_done.clone();
    let slot_file2 = slot_file.to_vec();
    let nzb2 = nzb.clone();
    let dir = out_dir.to_path_buf();
    let demand = tail_demand.clone();
    Some(tokio::spawn(async move {
        use std::collections::{HashMap, HashSet};
        // Recovery volumes reach disk by TWO roads and the on-hand
        // census must count both: the M2c.5 side prefetch (the
        // `prefetched` list), and the main pool fetching them INLINE -
        // which is what happens whenever damage shows up early enough
        // that the volumes are never deferred. `recovery_blocks_seen`
        // is frozen at activation (usually the index alone: 0 slices),
        // so without the disk walk the gate read "0 on hand" against a
        // job whose volumes were all sitting decoded in the out dir.
        // Cached by (path -> len, mtime, count), quiet files only - see
        // cached_recovery_blocks. Steady-state ticks cost one readdir.
        let mut disk_cache: HashMap<PathBuf, (u64, std::time::SystemTime, usize)> = HashMap::new();
        let mut cache_key: Option<([u8; 16], usize)> = None;
        // Why the ladder is still being walked, said ONCE per run: a
        // veto here is deliberate (uncovered walker, thin margin), and
        // an operator watching a zero-throughput tail deserves the
        // numbers behind it rather than silence.
        let mut veto_said = false;
        loop {
            if stop.load(Ordering::Acquire) {
                return; // network phase over - settle owns it now
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let Some(set) = verifier2.set() else { continue };
            // The census gates everything: Some only when EVERY pending
            // article is a refusal-walker, which is exactly the state
            // the tail stall consists of. A single clean payload
            // article anywhere keeps this closed.
            let Some(walkers) = queue_ctl2.verdict_walkers() else {
                continue;
            };
            let set_names: HashSet<String> = set
                .files
                .iter()
                .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
                .collect();
            let block = set.block_size.max(1) as usize;
            // Counts are only meaningful for the set and block size they
            // were taken under, so a re-activation onto a different set
            // starts the census from scratch rather than crediting the
            // old set's slices.
            if cache_key != Some((set.recovery_set_id, block)) {
                disk_cache.clear();
                cache_key = Some((set.recovery_set_id, block));
            }
            let est = par_race_estimate(&set_names, block, &slots2, &slot_file2, &nzb2);
            let (_, live_bad) = verifier2.live_counts();
            let missing_blocks = par_race_missing_blocks(block, &slots2, &slot_file2, &nzb2);
            // On hand: blocks the activation saw, plus prefetched
            // volumes, plus inline-fetched volumes decoded into the job
            // dir - deduped by path so a volume on both lists is never
            // counted twice toward the margin.
            let mut on_hand = set.recovery_blocks_seen;
            let mut counted: HashSet<PathBuf> = HashSet::new();
            for (_, paths) in pre.lock_ok().iter() {
                for p in paths {
                    if !counted.insert(p.clone()) {
                        continue;
                    }
                    on_hand +=
                        cached_recovery_blocks(p, &set.recovery_set_id, block, &mut disk_cache);
                }
            }
            on_hand +=
                disk_recovery_blocks(&dir, &set.recovery_set_id, block, &counted, &mut disk_cache);
            if !tail_giveup_covered(
                &walkers,
                &est,
                block,
                live_bad as usize,
                missing_blocks,
                on_hand,
            ) {
                let uncovered = walkers
                    .iter()
                    .filter(|w| !est.bytes_of.contains_key(&*w.id))
                    .count();
                let exact: usize = walkers
                    .iter()
                    .filter_map(|w| est.bytes_of.get(&*w.id))
                    .map(|&(_, b)| (b as usize).div_ceil(block) + 1)
                    .sum();
                // Coverage exists but the margin is short: hand the
                // spec prefetch a standing order for the full 2x
                // ceiling, so the next rungs fetch toward exactly the
                // number that lets this fire. An UNCOVERED walker is a
                // hard veto - no amount of prefetch changes it.
                if uncovered == 0 {
                    let ceiling = exact + live_bad as usize + missing_blocks;
                    demand.store(ceiling.saturating_mul(2), Ordering::Release);
                }
                if !veto_said {
                    veto_said = true;
                    info!(
                        target: "repair",
                        "tail give-up held back: {} walker(s), {uncovered} outside the \
                         recovery set, {exact}+{}+{missing_blocks} blocks against \
                         {on_hand} on hand (needs 2x) - walking the ladder instead",
                        walkers.len(),
                        live_bad,
                    );
                }
                continue; // not covered (or not covered ENOUGH) - the ladder must finish
            }
            let claimed = queue_ctl2.give_up_covered(&walkers);
            if claimed.is_empty() {
                continue;
            }
            let mut freed = 0u64;
            for id in &claimed {
                if let Some(&(sidx, b)) = est.bytes_of.get(&**id) {
                    slots2[sidx].remaining.fetch_sub(1, Ordering::AcqRel);
                    slots2[sidx].abandoned.fetch_add(1, Ordering::Relaxed);
                    freed += b;
                }
            }
            // No outcome will ever arrive for these - settle the bar
            // here, exactly like a sniff deferral or the par-race.
            fetch_done2.fetch_add(freed, Ordering::Relaxed);
            info!(
                target: "repair",
                "tail give-up: parity already covers the last {} article(s) still \
                 walking the refusal ladder ({on_hand} recovery blocks on hand, \
                 {live_bad} bad + {missing_blocks} missing blocks priced in) - \
                 stopped asking and moved to repair",
                claimed.len(),
            );
        }
    }))
}
