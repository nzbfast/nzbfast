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
    // Which adopted set the VERIFIER reconciled each slot to
    // (`LiveVerifier::slot_sets`), and which set this estimate is for.
    // `si: None` asks the name question alone - the shape this had while
    // there was only ever one set, and what the pure tests drive.
    claimed: &[Option<usize>],
    si: Option<usize>,
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
        // TODO 311 follow-on B. The name just tested is the NZB
        // SUBJECT's; the verifier matched this slot to a par2 file entry
        // by the yEnc header name, or by md5-16k when the post is
        // obfuscated, and THAT is the predicate settle and repair charge
        // damage with. On a one-set post the two can only agree or the
        // slot is not a candidate at all, so nothing was riding on it;
        // across sets a disagreement would let one set abandon articles
        // another set's parity is the only thing that rebuilds, which is
        // the single permanent loss this whole trade must never take. So
        // the verifier's answer wins as a VETO. A slot it has not
        // matched yet - no article of it has landed - has no answer to
        // give, and the name still speaks for it exactly as before.
        if let (Some(si), Some(Some(claim))) = (si, claimed.get(sidx).copied())
            && claim != si
        {
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

/// [`par_race_missing_blocks`] charged PER SET (TODO 311 follow-on B):
/// each slot's worst case priced in the block size of the set that
/// claims it, indexed the way `LiveVerifier::sets` is.
///
/// A slot NO set claims is priced to nobody, and that is the point
/// rather than an omission: its blocks sit outside every adopted set,
/// so no parity on hand rebuilds them and charging them to a set makes
/// that set's margin answer a question about damage its volumes cannot
/// heal. The job-wide sum the singular takes is right for the damage
/// projection, which states one figure for the whole post; it is wrong
/// for a margin, because on a per-file-set post it inflates every set's
/// ceiling by its seventeen siblings' damage and nothing ever clears.
pub(super) fn par_race_missing_blocks_by_set(
    blocks: &[usize],
    claimed: &[Option<usize>],
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Nzb,
) -> Vec<usize> {
    let mut out = vec![0usize; blocks.len()];
    for (sidx, s) in slots.iter().enumerate() {
        if s.is_par2() {
            continue;
        }
        let m = s.missing.load(Ordering::Relaxed);
        if m == 0 {
            continue;
        }
        let Some(si) = claimed.get(sidx).copied().flatten() else {
            continue;
        };
        let Some(&block) = blocks.get(si) else {
            continue;
        };
        let max_per = nzb.files[slot_file[sidx]]
            .segments
            .iter()
            .map(|seg| seg.bytes)
            .max()
            .unwrap_or(0) as usize;
        out[si] += m * (max_per.div_ceil(block.max(1)) + 1);
    }
    out
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
                let mut cache = CensusCache::new();
                loop {
                    if stop.load(Ordering::Acquire) {
                        return; // network phase over - settle owns it now
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
                    // par_race_estimate / par_race_missing_blocks_by_set
                    // (the Codex 5 Aug M2 fixes), where tests can hold
                    // them still - now once per adopted set (TODO 311
                    // follow-on B), so a post carrying one recovery set
                    // per file races each set against its OWN parity
                    // rather than reading the largest set's slices and
                    // declining. The side prefetch is the only road a
                    // volume reaches disk by while the download is still
                    // live, so there is no job-dir walk here; the tail
                    // give-up, which runs after the wire has gone quiet,
                    // passes `Some(dir)`.
                    let tails = census_sets(
                        &verifier2,
                        &slots2,
                        &slot_file2,
                        &nzb2,
                        &pre,
                        None,
                        &mut cache,
                    );
                    if tails.is_empty() {
                        continue;
                    }
                    // The line must be slow enough that repair clearly
                    // wins; a healthy line finishes the remainder before
                    // any repair could start its verify pass. The
                    // remainder is the JOB's, summed over every set,
                    // because that is what the run is actually waiting
                    // on - cancelling one set's stragglers shortens a
                    // job only while some other set is still the thing
                    // holding it open.
                    let out_bytes: u64 = tails.iter().map(|t| t.est.out_bytes).sum();
                    if tails.iter().all(|t| t.est.want.is_empty()) {
                        continue;
                    }
                    let eta = if rate > 0.0 {
                        out_bytes as f64 / rate
                    } else {
                        f64::INFINITY
                    };
                    if eta < 30.0 {
                        continue;
                    }
                    // Damage ceiling per set if every unresolved article
                    // of that set is lost: the queued ones we would
                    // cancel plus that set's own bad or terminally
                    // missing blocks.
                    let eligible: Vec<usize> = (0..tails.len())
                        .filter(|&si| {
                            !tails[si].est.want.is_empty()
                                && tails[si].covers(tails[si].race_ceiling())
                        })
                        .collect();
                    if eligible.is_empty() {
                        continue;
                    }
                    // Through `sole_set`, so an article TWO sets both
                    // name reaches NEITHER cancel list. It cannot be
                    // dropped from `want` later instead: `cancel`
                    // answers one id list, and an id cancelled that no
                    // set then owns is one nothing decrements
                    // `remaining` for - a run that never finishes. The
                    // ambiguity is the verifier not having adjudicated
                    // the slot yet, and the ladder finishing its
                    // articles is the right answer to that.
                    let mut want: HashSet<std::sync::Arc<str>> = HashSet::new();
                    for &si in &eligible {
                        for id in &tails[si].est.want {
                            if sole_set(&tails, id) == Some(si) {
                                want.insert(id.clone());
                            }
                        }
                    }
                    if want.is_empty() {
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
                    // failure here rare, not impossible. Per set, and
                    // the rollback is per set with it: one set's damage
                    // outgrowing its estimate must not cost a sibling
                    // set the race its own parity has already paid for.
                    let live_bad_now = verifier2.live_bad_by_set();
                    let mut keep: Vec<std::sync::Arc<str>> = Vec::new();
                    for &si in &eligible {
                        let t = &tails[si];
                        let mine: Vec<std::sync::Arc<str>> = removed
                            .iter()
                            .filter(|id| sole_set(&tails, id) == Some(si))
                            .cloned()
                            .collect();
                        if mine.is_empty() {
                            continue;
                        }
                        let exact: usize = mine
                            .iter()
                            .filter_map(|id| t.est.bytes_of.get(&**id))
                            .map(|&(_, b)| (b as usize).div_ceil(t.block) + 1)
                            .sum();
                        let ceiling = exact
                            + live_bad_now.get(si).copied().unwrap_or(0) as usize
                            + t.missing_blocks;
                        if !t.covers(ceiling) {
                            if queue_ctl2.requeue(&mine) > 0 {
                                continue; // rolled this set back whole - no race for it
                            }
                            // requeue's all-or-nothing rollback found the
                            // run already winding down, so the cancel is
                            // now irreversible. Fall through to the
                            // abandonment accounting so the bar stays
                            // truthful - settle prices the damage
                            // honestly either way.
                            warn!(
                                target: "repair",
                                "par-race: set {si}'s exact damage outgrew the estimate and \
                                 the rollback found the run winding down - proceeding with \
                                 {} abandoned article(s)",
                                mine.len()
                            );
                        }
                        keep.extend(mine);
                    }
                    if keep.is_empty() {
                        continue; // every set rolled back - no race this tick
                    }
                    let mut freed = 0u64;
                    for id in &keep {
                        // The id belongs to exactly one set - `sole_set`
                        // is what let it into `want` - so the first map
                        // that knows it is the one that priced it.
                        if let Some(&(sidx, b)) =
                            tails.iter().find_map(|t| t.est.bytes_of.get(&**id))
                        {
                            slots2[sidx].remaining.fetch_sub(1, Ordering::AcqRel);
                            slots2[sidx].abandoned.fetch_add(1, Ordering::Relaxed);
                            freed += b;
                        }
                    }
                    // No outcome will ever arrive for these - settle the
                    // bar here, exactly like a sniff deferral.
                    fetch_done2.fetch_add(freed, Ordering::Relaxed);
                    let on_hand: usize = eligible.iter().map(|&si| tails[si].on_hand).sum();
                    let ceiling: usize = eligible.iter().map(|&si| tails[si].race_ceiling()).sum();
                    info!(
                        target: "repair",
                        "par-race: abandoned {} queued straggler article(s) ({:.1} MB) across \
                         {} recovery set(s) - {on_hand} recovery blocks on hand cover the \
                         {ceiling}-block worst case at 2x, and repair beats the ~{eta:.0}s \
                         fetch remainder",
                        keep.len(),
                        freed as f64 / 1e6,
                        eligible.len(),
                    );
                    return;
                }
            })
        })
}

/// One adopted set's side of a §146 tail give-up or par-race trade -
/// its candidates, its block size, the damage already charged to it,
/// and the recovery slices of ITS set id on hand.
///
/// TODO 311 follow-on B: every field here used to be a job-wide figure
/// read off one representative set. Both arms are margin decisions, so
/// the single-set form was conservative rather than wrong on the
/// on-hand side - but the CANDIDATE side is not a margin at all, and
/// that is what made the give-up inert rather than merely cautious: a
/// walker for a file the representative set does not cover is not in
/// its `bytes_of`, which read as "repair cannot rebuild this" and
/// vetoed the whole trade. On GH #63's eighteen one-file sets that is
/// seventeen tracks out of eighteen, at any amount of parity on hand.
pub(super) struct SetTail {
    pub(super) est: RaceEstimate,
    pub(super) block: usize,
    pub(super) live_bad: usize,
    pub(super) missing_blocks: usize,
    pub(super) on_hand: usize,
}

impl SetTail {
    /// Worst-case blocks this set must be able to rebuild if every one
    /// of `ids` is abandoned, plus the damage already priced against it.
    pub(super) fn ceiling<'a>(&self, ids: impl Iterator<Item = &'a str>) -> usize {
        let exact: usize = ids
            .filter_map(|id| self.est.bytes_of.get(id))
            .map(|&(_, b)| (b as usize).div_ceil(self.block.max(1)) + 1)
            .sum();
        exact + self.live_bad + self.missing_blocks
    }

    /// The par-race's ceiling: EVERY unresolved candidate article of
    /// this set lost - the ones it would cancel - plus the damage
    /// already charged to it. The tail give-up prices a named list of
    /// walkers instead, through [`Self::ceiling`].
    pub(super) fn race_ceiling(&self) -> usize {
        self.est.out_blocks + self.live_bad + self.missing_blocks
    }

    /// The 2x margin, the one number both arms trade at.
    pub(super) fn covers(&self, ceiling: usize) -> bool {
        self.on_hand >= ceiling.saturating_mul(2)
    }
}

/// Which single adopted set may speak for an article, or `None`.
///
/// `None` covers two shapes and they are deliberately not told apart,
/// because the answer for both is the same: keep fetching. NO set
/// claims the article - repair rebuilds nothing outside its own set, so
/// abandoning it would convert a fetchable file into permanent damage -
/// or MORE THAN ONE does, which on a post whose sets share a filename
/// means the verifier has not yet adjudicated it and picking a set
/// would be a guess at whose parity heals it.
pub(super) fn sole_set(sets: &[SetTail], id: &str) -> Option<usize> {
    let mut hit = None;
    for (si, s) in sets.iter().enumerate() {
        if s.est.bytes_of.contains_key(id) {
            if hit.is_some() {
                return None;
            }
            hit = Some(si);
        }
    }
    hit
}

/// What one tick of the §146 tail give-up decided, per set.
pub(super) struct TailVerdict {
    /// The walkers that may be abandoned NOW.
    pub(super) claim: Vec<nzbkit::pool::Walker>,
    /// Walkers no single adopted set speaks for. A hard veto per
    /// ARTICLE - no amount of prefetch changes it - and no longer a
    /// veto on its neighbours.
    pub(super) uncovered: usize,
    /// `(set index, its walkers, its full ceiling in blocks)` for every
    /// set that HAS walkers and did not clear the 2x margin: what the
    /// spec prefetch has to fetch toward, and the numbers the held-back
    /// line reports.
    pub(super) short: Vec<(usize, usize, usize)>,
}

/// §146 tail give-up, the decision half - held still where a test can
/// reach it, and widened across every adopted set by TODO 311
/// follow-on B.
///
/// The claim is the union, over the sets whose OWN recovery slices
/// cover their OWN walkers plus their OWN damage at 2x.
///
/// The veto is per WALKER where it used to be per trade, and that is a
/// correction rather than a relaxation: what makes abandoning an
/// uncovered article unsound is that nothing rebuilds THAT article, and
/// it says nothing about its neighbour whose parity is already on disk.
/// The all-or-nothing shape came from the COMMIT, which took the whole
/// census list; `give_up_covered` has always accepted a subset, so the
/// cancel list is per set now and an uncovered straggler costs only its
/// own file the shortcut. That reaches a ONE-set post too, where an
/// uncovered companion - an .nfo, a sample the set never covered - used
/// to hold the give-up shut for the files the set does cover.
pub(super) fn tail_giveup_verdict(
    walkers: &[nzbkit::pool::Walker],
    sets: &[SetTail],
) -> TailVerdict {
    let mut mine: Vec<Vec<&nzbkit::pool::Walker>> = vec![Vec::new(); sets.len()];
    let mut v = TailVerdict {
        claim: Vec::new(),
        uncovered: 0,
        short: Vec::new(),
    };
    for w in walkers {
        match sole_set(sets, &w.id) {
            Some(si) => mine[si].push(w),
            None => v.uncovered += 1,
        }
    }
    for (si, ws) in mine.iter().enumerate() {
        if ws.is_empty() {
            continue;
        }
        let ceiling = sets[si].ceiling(ws.iter().map(|w| &*w.id));
        if sets[si].covers(ceiling) {
            v.claim.extend(ws.iter().map(|w| (*w).clone()));
        } else {
            v.short.push((si, ws.len(), ceiling));
        }
    }
    v
}

/// §146 tail give-up: every `.par2` file in the job dir, up to three
/// levels deep - the recovery volumes the MAIN pool decoded inline
/// because they were never deferred, so the side prefetch never saw
/// them.
///
/// The WALK, not the counting, since TODO 311 follow-on B: the census
/// runs it once per tick and counts the files it finds for every
/// adopted set, where a per-set counter re-walked the whole tree once
/// per set five times a second.
fn disk_recovery_volumes(dir: &Path) -> Vec<PathBuf> {
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
    files
}

/// A file is only trusted into the census cache once it has been QUIET
/// this long. Volume writers preallocate (`set_len`) at creation, so a
/// mid-write file already reports its final length and the length can
/// never invalidate an entry; the file's mtime is what still moves while
/// articles land. Two seconds also rides out coarse-mtime filesystems
/// (FAT stamps at 2 s), where a scan and a later write can share one
/// visible timestamp.
pub(super) const CENSUS_QUIET: std::time::Duration = std::time::Duration::from_secs(2);

/// What one `.par2` file on disk contributes to a census, taken in ONE
/// read: the `(set id, slice length, count)` groups its packets hold,
/// under the `(length, mtime)` the file had when they were counted.
///
/// A file's answer is stored for EVERY set at once rather than for the
/// set that happened to ask (TODO 311 follow-on B), and that is the
/// whole point of the struct. A volume belongs to exactly one set, so a
/// per-set memo makes the census read the same bytes once per adopted
/// set to answer 0 for all but one of them - an N-squared read of every
/// volume on disk on exactly the per-file-set post this widening is
/// for. It is also what makes a SHARED cache safe: keying a raw count by
/// path alone would answer set 3 with set 0's count, an OVER-count, and
/// over-counting is the one direction that fires the give-up on parity
/// that is not there. Measured while this landed: sharing a path-keyed
/// count across sets left the whole multi-set e2e suite green.
#[derive(Debug)]
pub(super) struct CensusEntry {
    pub(super) len: u64,
    pub(super) mtime: std::time::SystemTime,
    /// `(set id, slice data length, how many)`, from
    /// [`nzbkit::par2repair::recovery_slice_census`].
    groups: Vec<([u8; 16], usize, usize)>,
}

impl CensusEntry {
    /// Slices of `set_id` at exactly `block` bytes - the same question
    /// [`recovery_slice_locators`](nzbkit::par2repair::recovery_slice_locators)
    /// answers, off the one read.
    pub(super) fn count(&self, set_id: &[u8; 16], block: usize) -> usize {
        self.groups
            .iter()
            .filter(|(id, l, _)| id == set_id && *l == block)
            .map(|(_, _, n)| *n)
            .sum()
    }
}

/// Memo for [`cached_recovery_blocks`], one entry per `.par2` file and
/// shared by every adopted set and both census roads.
pub(super) type CensusCache = std::collections::HashMap<PathBuf, CensusEntry>;

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
    cache: &mut CensusCache,
) -> usize {
    let Ok(meta) = std::fs::metadata(p) else {
        return 0;
    };
    let len = meta.len();
    let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    if let Some(e) = cache.get(p)
        && e.len == len
        && e.mtime == mtime
    {
        return e.count(set_id, block);
    }
    let Ok(bytes) = std::fs::read(p) else {
        return 0;
    };
    let groups = nzbkit::par2repair::recovery_slice_census(&bytes);
    let entry = CensusEntry { len, mtime, groups };
    let n = entry.count(set_id, block);
    // An unreadable mtime lands on UNIX_EPOCH, which reads as ancient -
    // deliberately: a filesystem that cannot report mtime cannot feed
    // the quiet gate, and permanent re-reads there would resurrect the
    // cost A5 removed.
    if mtime.elapsed().is_ok_and(|e| e >= CENSUS_QUIET) {
        cache.insert(p.to_path_buf(), entry);
    }
    n
}

/// Every adopted set's [`SetTail`] for one tick: its candidates, its
/// block size, the damage charged to it, and the recovery slices of its
/// OWN set id on hand.
///
/// `dir` is `Some` for the tail give-up, which must also count volumes
/// the MAIN pool decoded inline into the job dir - `recovery_blocks_seen`
/// is frozen at activation, so without the walk the gate reads "0 on
/// hand" against a job whose volumes are all sitting decoded in the out
/// dir. The par-race runs while the download is live and counts the side
/// prefetch alone.
///
/// `cache` is shared by every set and by both roads: a [`CensusEntry`]
/// holds a file's slices GROUPED by set id, so one read answers every
/// set, a count taken for one set is never served to another, and a
/// re-activation onto a different set answers 0 rather than crediting
/// the old one's slices.
pub(super) fn census_sets(
    verifier: &nzbkit::live::LiveVerifier,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Nzb,
    prefetched: &std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>,
    dir: Option<&Path>,
    cache: &mut CensusCache,
) -> Vec<SetTail> {
    let sets = verifier.sets();
    if sets.is_empty() {
        return Vec::new();
    }
    let claimed = verifier.slot_sets();
    let live_bad = verifier.live_bad_by_set();
    let blocks: Vec<usize> = sets.iter().map(|s| s.block_size.max(1) as usize).collect();
    let missing = par_race_missing_blocks_by_set(&blocks, &claimed, slots, slot_file, nzb);
    // One snapshot of the prefetched list for the whole tick, so the
    // lock is taken once rather than once per set.
    let pre: std::collections::HashSet<PathBuf> = prefetched
        .lock_ok()
        .iter()
        .flat_map(|(_, ps)| ps.iter().cloned())
        .collect();
    // And the job dir walked ONCE for the tick, deduped against the
    // prefetched list so a volume on both roads is never counted twice
    // toward a margin.
    let on_disk: Vec<PathBuf> = dir
        .map(disk_recovery_volumes)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| !pre.contains(p))
        .collect();
    sets.iter()
        .enumerate()
        .map(|(si, set)| {
            let block = blocks[si];
            let set_names: std::collections::HashSet<String> = set
                .files
                .iter()
                .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
                .collect();
            let est =
                par_race_estimate(&set_names, &claimed, Some(si), block, slots, slot_file, nzb);
            let mut on_hand = set.recovery_blocks_seen;
            for p in pre.iter().chain(on_disk.iter()) {
                on_hand += cached_recovery_blocks(p, &set.recovery_set_id, block, cache);
            }
            SetTail {
                est,
                block,
                live_bad: live_bad.get(si).copied().unwrap_or(0) as usize,
                missing_blocks: missing.get(si).copied().unwrap_or(0),
                on_hand,
            }
        })
        .collect()
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
        // Shared by every adopted set since TODO 311 follow-on B, and
        // safe to share because a CensusEntry holds a file's slices
        // grouped BY set id - so one read answers every set, and no set
        // can be served another's count. Keyed on the raw count instead,
        // that would have been the caller's discipline rather than a
        // property of the map.
        let mut cache = CensusCache::new();
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
            // The census gates everything: Some only when EVERY pending
            // article is a refusal-walker, which is exactly the state
            // the tail stall consists of. A single clean payload
            // article anywhere keeps this closed.
            let Some(walkers) = queue_ctl2.verdict_walkers() else {
                continue;
            };
            // EVERY adopted set, each with its own candidates, its own
            // block size, its own damage and its own slices on hand
            // (TODO 311 follow-on B). Taking one representative set here
            // did not merely understate the margin: a walker for a file
            // that set does not cover is not in its candidate map at
            // all, which reads as "repair cannot rebuild this" and used
            // to veto the whole trade - so on a post carrying one set
            // per file the give-up could never fire for any file but
            // one, at any amount of parity on hand.
            let tails = census_sets(
                &verifier2,
                &slots2,
                &slot_file2,
                &nzb2,
                &pre,
                Some(&dir),
                &mut cache,
            );
            if tails.is_empty() {
                continue;
            }
            let v = tail_giveup_verdict(&walkers, &tails);
            // The standing order to the spec prefetch: the SUM of the
            // short sets' 2x ceilings, so the next rungs fetch toward
            // exactly the number that lets them fire. The ladder is
            // set-blind - it walks every recovery volume in the post
            // smallest-first - so the sum is the figure that funds N
            // sets at once where the max would fund only the largest.
            //
            // FUNDS, not COVERS, and the difference was MEASURED on
            // 28 Aug 2026 (claim `prefetch-ladder-per-set`, written up
            // in research/PREFETCH-LADDER-PER-SET-2026-08-28.md). A
            // budget big enough for N sets is spent wherever the
            // smallest-first ladder points, which is not where the
            // shortfall is, because the ladder's own `covered` counter
            // is credited from the volume NAME and is set-blind while
            // `SetTail::on_hand` is counted per set from the volume's
            // CONTENT. On the live two-set rig the ladder parked with
            // set0 at 473 of the 520 it needed and twelve of twenty
            // volumes never fetched; one set of two fired. Worse, a set
            // that clears leaves `short`, so this sum FALLS while
            // `covered` cannot, which is what stranded set0. Nothing is
            // lost on disk - the post-settle pass still repairs every
            // set - only the wait §146 exists to remove. Fixing it
            // needs the ladder to know each rung's set; the two reasons
            // that is not a one-liner are in that document.
            //
            // Set OUTSIDE the not-covered branch since TODO 311
            // follow-on B, because "some set is short" and "no set
            // fired" stopped being the same statement: on a per-file-set
            // post one set's margin clearing says nothing about its
            // seventeen siblings, and leaving the order unset while any
            // of them fires would stall the prefetch on exactly the run
            // that most needs it. An UNCOVERED walker no longer
            // suppresses it either - it is a hard veto on ITS OWN
            // article and nothing else now, so fetching toward a sibling
            // set's ceiling is as useful as it would be with no
            // uncovered walker in the census at all.
            if !v.short.is_empty() {
                let want: usize = v.short.iter().map(|&(_, _, c)| c.saturating_mul(2)).sum();
                demand.store(want, Ordering::Release);
            }
            if v.claim.is_empty() {
                if !veto_said {
                    veto_said = true;
                    let short: Vec<String> = v
                        .short
                        .iter()
                        .map(|&(si, n, c)| {
                            format!("set {si}: {n} walker(s) against a {c}-block ceiling")
                        })
                        .collect();
                    info!(
                        target: "repair",
                        "tail give-up held back: {} walker(s), {} outside every recovery \
                         set; {} - each needs 2x on hand - walking the ladder instead",
                        walkers.len(),
                        v.uncovered,
                        if short.is_empty() {
                            "no set has a claimable walker".to_string()
                        } else {
                            short.join("; ")
                        },
                    );
                }
                continue; // not covered (or not covered ENOUGH) - the ladder must finish
            }
            let claimed = queue_ctl2.give_up_covered(&v.claim);
            if claimed.is_empty() {
                continue;
            }
            let mut freed = 0u64;
            for id in &claimed {
                // The id belongs to exactly one set - `sole_set` is what
                // put it in the claim - so the first map that knows it
                // is the one that priced it.
                if let Some(&(sidx, b)) = tails.iter().find_map(|t| t.est.bytes_of.get(&**id)) {
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
                "tail give-up: parity already covers {} of the article(s) still walking \
                 the refusal ladder ({} recovery block(s) on hand across {} set(s), \
                 {} walker(s) left uncovered) - stopped asking for them",
                claimed.len(),
                tails.iter().map(|t| t.on_hand).sum::<usize>(),
                tails.len(),
                v.uncovered,
            );
        }
    }))
}
