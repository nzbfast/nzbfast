//! Recovery-volume side-fetches: the small, budget-exempt pool a repair
//! uses to pull par2 volumes down after the main run has drained.
//!
//! Split out of `repair.rs` whole (§129 residue 2) so the cancel wire
//! below has a home and its parent file drops back under the size gate.
//! Everything here is re-exported from `crate::repair`, so callers and
//! `super::*` importers are unchanged.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn};

/// A sticky cancel handle for one owner's recovery-volume side-fetches.
///
/// Two halves, because neither alone is a cancel wire:
///
/// - `QueueControl::abort` only reaches the pool the handle is attached
///   to RIGHT NOW. A cancel arriving between two volumes, or in the
///   window before `fetch_all_multi_ctl` attaches, is a silent no-op and
///   the fetch runs to completion - which is the bug this exists to
///   close, just narrower. So the latch is the durable half: once set it
///   refuses every later side-fetch outright and keeps re-aborting the
///   one in flight (see [`SideCancel::guard`]).
/// - The latch alone cannot drop an in-flight read. A blackholed
///   provider's retry ladder is minutes long; only the pool abort ends
///   it promptly.
///
/// The speculative prefetch (get/workers.rs) shares its own `stop` flag
/// through [`SideCancel::over`] rather than carrying a second mechanism.
pub(crate) struct SideCancel {
    flag: Arc<AtomicBool>,
    ctl: Arc<nzbkit::pool::QueueControl>,
}

impl SideCancel {
    /// A handle with its own latch - what the daemon registers per job.
    pub(crate) fn new() -> Self {
        SideCancel::over(Arc::new(AtomicBool::new(false)))
    }

    /// A handle over a latch the caller already owns and reads itself.
    pub(crate) fn over(flag: Arc<AtomicBool>) -> Self {
        SideCancel {
            flag,
            ctl: Arc::new(nzbkit::pool::QueueControl::default()),
        }
    }

    /// Stop this owner's side-fetches: refuse the ones not yet started,
    /// drop the reads of the one in flight. Idempotent.
    pub(crate) fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
        self.ctl.abort();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// Run one side-fetch under this handle, keeping the pool abort
    /// live for its whole duration.
    ///
    /// The ticker is not laziness about a wake-up primitive: the pool a
    /// `cancel()` needs to abort may not be attached yet when the call
    /// arrives, so the abort has to be re-tried until the fetch returns.
    /// Same shape, same reason as the prefetch watcher this replaces
    /// (Codex 5 Aug M3) - 250 ms is well inside a user's patience and
    /// costs one timer per volume.
    async fn guard<T>(&self, fut: impl std::future::Future<Output = T>) -> T {
        let flag = self.flag.clone();
        let ctl = self.ctl.clone();
        let watcher = tokio::spawn(async move {
            loop {
                if flag.load(Ordering::Acquire) {
                    ctl.abort();
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        });
        let out = fut.await;
        watcher.abort();
        out
    }
}

/// `.volNNN+MM.par2` / `.volNNN-MMM.par2` → declared recovery-slice count.
pub(crate) fn vol_count_from_name(name: &str) -> Option<usize> {
    nzbkit::nzb::par2_vol_count(name)
}

/// What one recovery side-fetch asked a provider for, and what it got.
///
/// §282 item 4. Before 24 Aug 2026 a recovery fetch handed its caller a
/// bare failure COUNT, and every caller read it as a boolean: zero means
/// the volumes are whole, nonzero means at least one is partial. That
/// answers "may this batch be excluded from the escalation" and nothing
/// else - and the escalation is the decision that actually costs money.
///
/// The live incident this exists for (§282, 24 Aug 2026): a fetch asked
/// for 1024 MB of recovery data and 68.9 MB arrived, 1206 article
/// failures against a payload that was 99.8% intact. The daemon read
/// "nonzero" and escalated to every remaining volume from the same
/// provider, three times over, for 46 minutes. A ratio says what a
/// boolean cannot: this source is not short of a few articles, it will
/// not serve this recovery set at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct VolumeYield {
    /// Articles this fetch was responsible for - every segment of every
    /// chosen volume, including the ones `volume_reqs` did not put on
    /// the wire because an earlier file already owned the message id.
    pub(crate) asked: u32,
    /// Of those, the ones that produced no bytes. Counted the same way,
    /// so an omitted duplicate is a failure here exactly as it is for
    /// the "did this volume land whole" question - see [`volume_reqs`].
    ///
    /// COMPLETENESS, not evidence: `failed == 0` is still the only
    /// value that means every chosen volume landed whole, whoever lost
    /// the articles. The verdict about the SOURCE reads [`Self::ours`]
    /// out of this first - see [`Self::source_asked`].
    pub(crate) failed: u32,
    /// Of [`Self::failed`], the ones that are evidence about US rather
    /// than about the source. TODO 307 item 1's residue, 26 Aug 2026.
    ///
    /// Until this field existed a `FetchOutcome::Failed` was charged
    /// identically to a `Missing`, so two opposite facts arrived in one
    /// number. A `Missing` is every live server having been asked and
    /// having answered 430/423, which is exactly what this type is for.
    /// A `Failed` is the pool giving up without a body, and NOT ONE of
    /// `FailCode`'s four variants is the source refusing: two of them
    /// (`FleetExhausted`, `WorkerPanic`) mean nobody ever asked at all,
    /// and the other two (`Transport`, `ReadStall`) are the link
    /// between us and the provider, which `FailKind::Transport` exists
    /// one layer up to keep out of verdicts about a post. Our own disk
    /// refusing a volume writer is the same class again, and so is an
    /// omitted duplicate: no request goes out for one, so no provider
    /// declined anything.
    ///
    /// What that cost, and it is the whole reason for the field:
    /// [`Self::source_will_not_serve`] drives
    /// `RepairShortfall::Unservable`, whose clause tells the user "the
    /// payload is not the problem here, so a different source for the
    /// same release is what would fix it". A fleet that wound down mid
    /// recovery-fetch could reach that sentence, sending the reader
    /// after another release for a failure that was ours.
    ///
    /// Always a subset of `failed`; every derived number clamps it so a
    /// miscount cannot invent delivered articles.
    pub(crate) ours: u32,
}

/// §282 item 4: the share of a recovery fetch's articles that must
/// arrive before asking the SAME source for the rest is worth the wall
/// clock.
///
/// The escalation's premise is that par2's own damage accounting can
/// run ahead of the block ledger's, so a little more parity closes a
/// small gap. It buys the remaining volumes from the provider that just
/// answered the last request, so at measured yield `f` those volumes
/// come back at about `f` too. One half is where "short a few articles"
/// stops being a fair reading and "this source will not serve this set"
/// starts; the incident measured 6.7%, an order of magnitude under it,
/// and the one shape the e2e suite pins as a legitimate partial - a
/// single lost article of one large volume - is up near 99%.
pub(crate) const MIN_RECOVERY_YIELD: f64 = 0.5;

/// Requested articles below which a yield RATIO is noise rather than
/// evidence: one lost article of a two-article volume is 50% and says
/// nothing at all about the source.
pub(crate) const MIN_RECOVERY_YIELD_SAMPLE: u32 = 16;

impl VolumeYield {
    /// Articles that produced bytes.
    pub(crate) fn delivered(&self) -> u32 {
        self.asked.saturating_sub(self.failed)
    }

    /// [`Self::ours`], held to its contract: never more than
    /// [`Self::failed`]. Clamped rather than trusted because every
    /// number below is derived by subtracting it, and an `ours` past
    /// `failed` would report MORE articles delivered than were asked
    /// for - a yield over 100% and a verdict that can never fire.
    fn ours_capped(&self) -> u32 {
        self.ours.min(self.failed)
    }

    /// The articles this fetch actually put a question to the source
    /// about: [`Self::asked`] minus the ones that failed on our side.
    ///
    /// This is the denominator, and taking OURS out of it is as
    /// deliberate as taking them out of the numerator. The two go
    /// together: a fetch of 1000 articles that lost 900 to a fleet
    /// wind-down asked the source about 100, and the honest sample is
    /// 100 - not 1000, which would read as a 10% yield and condemn the
    /// provider, and not 1000-with-900-forgiven either, which would
    /// read as 100% and forgive a source that really did refuse the
    /// hundred it was asked. Shrinking the sample also puts
    /// [`MIN_RECOVERY_YIELD_SAMPLE`] back in charge: a fetch that only
    /// ever reached the source with four articles is refused as a
    /// verdict, which is the same floor and the same reason as a fetch
    /// that only ASKED for four.
    pub(crate) fn source_asked(&self) -> u32 {
        self.asked.saturating_sub(self.ours_capped())
    }

    /// Delivered over what the source was actually asked, or 1.0 when
    /// the source was asked nothing (an empty ask has demonstrated
    /// nothing about the source, and the safe reading of "nothing
    /// demonstrated" is "carry on" - which is also the right answer for
    /// a fetch whose every loss was ours).
    pub(crate) fn fraction(&self) -> f64 {
        let asked = self.source_asked();
        if asked == 0 {
            return 1.0;
        }
        f64::from(self.delivered()) / f64::from(asked)
    }

    /// §282 item 4: has this source demonstrated it will not serve this
    /// recovery set? A terminal verdict on the job, and the trigger for
    /// hunting an alternate once §282 section C lands.
    ///
    /// Deliberately NOT a timeout. §146's tail give-up already owns
    /// "this is taking too long" and reasons about it with a 2x parity
    /// margin; conflating the two would let a slow-but-serving provider
    /// be declared dead, which is the §275 mistake wearing a new hat.
    /// This fires only on what the wire actually returned, which since
    /// 26 Aug 2026 is a claim the arithmetic can keep: OUR OWN losses
    /// are held out of both halves of the ratio (see [`Self::ours`]),
    /// so a fleet that wound down mid-fetch cannot be read as a
    /// provider that refused.
    pub(crate) fn source_will_not_serve(&self) -> bool {
        self.source_asked() >= MIN_RECOVERY_YIELD_SAMPLE && self.fraction() < MIN_RECOVERY_YIELD
    }

    /// The clause a log line or a job verdict states this in.
    ///
    /// Over the SOURCE sample, so the numbers a user reads are the
    /// numbers the verdict was reached on. Our own losses are named
    /// separately rather than dropped: a console line that said "12 of
    /// 200 arrived" about a fetch of 1000 would leave the other 788
    /// unaccounted for, and the point of the split is to be able to say
    /// which half of it was whose. With no losses of ours - every shape
    /// the e2e suite pins, and the §282 incident itself - this is the
    /// sentence it always was, character for character.
    pub(crate) fn describe(&self) -> String {
        let ours = self.ours_capped();
        let mut s = format!(
            "{} of {} recovery article(s) arrived ({:.1}%)",
            self.delivered(),
            self.source_asked(),
            self.fraction() * 100.0
        );
        if ours > 0 {
            s.push_str(&format!(
                ", plus {ours} that failed on our side rather than the provider's"
            ));
        }
        s
    }
}

/// Download the chosen recovery volumes to `out_dir` (same decode→pwrite
/// path as the main run). Shared by the disk repair path and the mapped
/// (into-the-output) path.
///
/// Returns what was asked for beside what failed. `failed == 0` is the
/// only value that means every chosen volume landed whole; any nonzero
/// count means at least one of them is PARTIAL, and only a complete
/// volume may ever enter a whole-file exclusion list (the escalation
/// fetch strips excluded files, so excluding a partial one makes its
/// missing slices unreachable for the rest of the job). The `asked`
/// half is §282 item 4's: see [`VolumeYield`].
pub(crate) async fn fetch_volumes(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    file_indexes: &[usize],
    cancel: Option<&SideCancel>,
) -> Result<VolumeYield> {
    let mut ids: Vec<nzbkit::pool::ArticleReq> = Vec::new();
    let mut id_to_file: std::collections::HashMap<Arc<str>, usize> =
        std::collections::HashMap::new();
    let mut omitted = 0u32;
    for &fi in file_indexes {
        omitted = omitted.saturating_add(volume_reqs(nzb, fi, &mut ids, &mut id_to_file));
    }
    // The omitted duplicates never reach the wire, so they are in the
    // ask (this fetch was responsible for them) and in the failures
    // (nothing here will produce their bytes) alike. They are OURS as
    // well, and that third counting is what finally makes the sentence
    // above true: no request goes out for an omitted duplicate, so no
    // provider ever declined it, and a source verdict that counted them
    // would read a repeated message-id in the POSTER's own recovery set
    // as a provider refusing to serve it. Charged to both halves of the
    // source ratio, they cancel, which is what "leaves the ratio
    // exactly where it would be without them" has to mean - charged to
    // the denominator alone, as they were until 26 Aug 2026, they drag
    // it down.
    let asked = (ids.len() as u32).saturating_add(omitted);
    fetch_volume_articles(
        servers,
        ids,
        id_to_file,
        out_dir,
        buf_pool,
        volume_prealloc_cap(nzb),
        cancel,
    )
    .await
    .map(|(failures, _paths)| VolumeYield {
        asked,
        failed: failures.total().saturating_add(omitted),
        ours: failures.ours().saturating_add(omitted),
    })
}

/// One volume's `ArticleReq`s and id → file-index entries, appended to
/// the caller's holders. R9: one interned handle per id, shared with
/// the ArticleReq (and so with the Work, the in-flight entry and the
/// outcome). Every caller is a side pool of its own - the disk/mapped
/// repair fetch after the main run's plan is gone, and the speculative
/// prefetch, which builds a rung's requests only AT RUNG SELECTION
/// (C5) - so it interns at its own birth site rather than borrowing
/// the plan's.
///
/// Returns how many of this file's declared segments were NOT requested
/// because an earlier file already owned the message id. That count is
/// the only trace such a segment leaves anywhere, so a caller that
/// judges a volume complete has to add it to the article failures the
/// fetch reports (Codex F-02).
///
/// `#[must_use]`, and that attribute is the regression (sweep 9,
/// finding 7): F-02 converted `fetch_volumes` and left the speculative
/// prefetch reading `f.total() == 0` over a discarded count, so a
/// volume that repeated a message-id inside itself was recorded
/// complete and struck off the post-settle fetch list with slices it
/// never held. Nothing about that omission was visible - no request
/// goes out, so no `Missing`/`Failed` comes back. A third caller
/// written the same way is now a compile error rather than a false
/// completeness, which is the only place this class can be caught
/// cheaply.
#[must_use = "add the omitted-duplicate count to the article failures before judging a volume complete"]
pub(crate) fn volume_reqs(
    nzb: &Nzb,
    fi: usize,
    ids: &mut Vec<nzbkit::pool::ArticleReq>,
    id_to_file: &mut std::collections::HashMap<Arc<str>, usize>,
) -> u32 {
    let age_days = nzb_age_days(nzb.files[fi].date);
    let mut omitted = 0u32;
    for seg in &nzb.files[fi].segments {
        let b: Arc<str> = format!("<{}>", seg.message_id).into();
        // Sweep 8, L3: FIRST owner wins, and a later claim on the same
        // message-id is simply not requested.
        //
        // This map used to be last-owner-wins while the pool's own
        // request dedup keeps the FIRST request - two rules pointing
        // opposite ways across the same id. A malformed or hostile
        // recovery set that repeats an id across volumes therefore had
        // the one delivered body routed to the LATER file index while
        // the writer for that index was created from the FIRST body's
        // yEnc name, so the later volume's genuinely unique articles
        // landed in a file named after the earlier one. Two damaged
        // recovery volumes out of one duplicate.
        //
        // Matching the pool's rule makes the duplicate simply MISSING
        // for the later volume, which is honest: that volume comes back
        // short, is not credited with slices it does not have, and the
        // repair asks for another one.
        if let std::collections::hash_map::Entry::Vacant(slot) = id_to_file.entry(b.clone()) {
            slot.insert(fi);
        } else {
            // Codex F-02 (23 Aug 2026): the skip has to be COUNTED, not
            // just taken. Nothing downstream can see it otherwise - no
            // request goes out, so no `Missing`/`Failed` outcome comes
            // back, so `VolumeFailures::for_file(fi)` stays 0 and the
            // dropped-volume refetch reads this short volume as whole
            // and renames a sparse file over the demoted copy that
            // holds every byte the trim kept.
            omitted = omitted.saturating_add(1);
            continue;
        }
        ids.push(nzbkit::pool::ArticleReq {
            id: b,
            age_days,
            part: seg.number,
            file: u32::MAX,
        });
    }
    omitted
}

/// Reservation ceiling for a recovery-volume side-fetch, the same bound
/// `main` hands the extractor: a recovery volume cannot legitimately
/// exceed the whole post, and the yEnc `size=` it declares is a poster-
/// controlled number that on Linux turns into a real `fallocate`. The
/// posted byte count is itself an untrusted attribute (and 0 means the
/// NZB carried no byte attributes at all - unknown, not zero), so the
/// post's article GEOMETRY bounds it either way: reserving more space
/// requires declaring more articles, which the download is then held
/// accountable for. See [`Nzb::geometry_bytes`].
pub(crate) fn volume_prealloc_cap(nzb: &Nzb) -> u64 {
    let geometry = nzb.geometry_bytes();
    match nzb.total_bytes() {
        0 => geometry,
        posted => posted.min(geometry),
    }
}

/// Shrink the download fleet to the one-connection-per-server side pool the
/// M2c.5 speculative prefetch runs on. The main pool already holds this
/// account's grants, so the prefetch may add exactly one connection per
/// server or the provider starts refusing them.
pub(crate) fn side_pool_servers(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
) -> Vec<(ServerConfig, nzbkit::pool::PoolConfig)> {
    servers
        .iter()
        .map(|(sc, pc)| {
            let mut sc = sc.clone();
            sc.connections = 1;
            let mut pc = pc.clone();
            // The POOL config is what spawns workers (pool::fetch_all_multi);
            // ServerConfig.connections was consumed when this config was
            // built, far above. Setting only that one leaves the "tiny side
            // pool" a full second fleet, opened mid-download.
            pc.connections = 1;
            // Same reason it must stay small: side-pool workers are not part
            // of the download, so they must not move the dashboard's
            // per-server gauges either.
            pc.live = None;
            // fetch_volume_articles strips the rest itself (the 7 Aug
            // 2026 wedge came in through a caller that bypassed this
            // helper); applied here too so the side pool's config
            // states its own contract.
            strip_side_pool_seams(&mut pc);
            (sc, pc)
        })
        .collect()
}

/// Everything a cloned MAIN-fleet config must give up before a side
/// pool may run on it. Called from the one driver every side-fetch goes
/// through, so no caller can reintroduce one of these by cloning the
/// download's configs and skipping [`side_pool_servers`].
fn strip_side_pool_seams(pc: &mut nzbkit::pool::PoolConfig) {
    // TODO 114: the steer seam defers each Done's completion until the
    // consumer's note_decoded verdict - and the side-fetch consumer
    // (consume_volume_articles) never gives one (it has no QueueControl
    // at all), so a cloned crc_steer would park every delivery forever
    // and hang the volume fetch. arrival_ack is the same seam one step
    // further on: note_settled never comes either. Damaged side-fetched
    // volumes already have their own answer - incomplete volumes stay
    // fetchable and repair proves the bytes.
    pc.crc_steer = false;
    pc.arrival_ack = false;
    // This consumer never releases the fetch->decode channel gauge, so
    // it must not charge it: a cloned Some leaks the gauge upward for
    // every side-fetched article.
    pc.channel_gauge = None;
    // And the side pool must not hold the line cap's steering wheel.
    // `live_target` is the MAIN fleet's shared ConnTarget (these configs
    // are a clone of the download's), while `connections` here is the
    // side pool's own tiny width - 1 for the speculative prefetch, up to
    // 8 for the §146 demand rung. LineCap::new pairs the two as
    // (target, ceiling), so the first line_cap_tick a delivered body
    // drives computes `want = share.min(ceiling)` = the SIDE pool's
    // width and, with the cloned anchor permitting the shed, writes it
    // into the main fleet's targets: every main worker then parks down
    // to one connection for the rest of the job, and the main pool's own
    // tick cannot raise it back (the target no longer holds the value
    // that tick set). Clearing the targets is enough on its own -
    // line_cap_tick returns at its all-None guard - but the knobs go too
    // so the config states its own contract. `line_anchor_bps` stays:
    // the stall bound sizes an article's share from it, and it moves
    // nothing once there are no targets left to move.
    pc.live_target = None;
    pc.line_cap_fleet = 0;
    pc.line_cap_auto = false;
}

/// Inner driver for recovery-volume side-fetches: downloads the given
/// article set on its own small pool and assembles the volume file(s)
/// in `out_dir`. Returns ([`VolumeFailures`], paths written) - the
/// failure count is how a caller tells a COMPLETE volume from a
/// partial one, and only a complete volume may ever enter a whole-file
/// exclusion list (a partial one must stay fetchable for its missing
/// articles). A caller holding more than one volume asks per file
/// index rather than reading the total, or one short volume condemns
/// every whole one beside it.
pub(crate) async fn fetch_volume_articles(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    ids: Vec<nzbkit::pool::ArticleReq>,
    id_to_file: std::collections::HashMap<Arc<str>, usize>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    prealloc_cap: u64,
    cancel: Option<&SideCancel>,
) -> Result<(VolumeFailures, Vec<PathBuf>)> {
    fetch_volume_articles_with(
        servers,
        ids,
        id_to_file,
        out_dir,
        buf_pool,
        prealloc_cap,
        cancel,
        VolumeOpen::Fresh,
    )
    .await
}

/// How the side-fetch consumer opens each volume it writes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum VolumeOpen {
    /// Truncate: the volume is fetched from nothing (recovery volumes,
    /// the speculative prefetch).
    Fresh,
    /// Never truncate: the file already holds good bytes at their
    /// final offsets and this fetch only fills what is missing. The
    /// dropped-volume refetch (`get/dropped.rs`) writes over a volume
    /// the demote materialized minus its dropped ranges; a truncating
    /// open there turned one failed article into a hole where the
    /// bytes had been correct, with no retry behind it (bug sweep
    /// 22 Aug 2026).
    Additive,
}

/// [`fetch_volume_articles`] with the open mode chosen by the caller.
#[expect(clippy::too_many_arguments)]
pub(crate) async fn fetch_volume_articles_with(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    ids: Vec<nzbkit::pool::ArticleReq>,
    id_to_file: std::collections::HashMap<Arc<str>, usize>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    // Ceiling on what one volume writer may RESERVE - see
    // [`volume_prealloc_cap`]. u64::MAX = no ceiling.
    prealloc_cap: u64,
    // Cancellation handle for callers that must be able to stop a
    // side-fetch mid-volume: the speculative prefetch (Codex 5 Aug M3 -
    // it could hold Cancel/Pause through a blackholed provider's whole
    // retry ladder) and, since §129, the postproc lane's tail, whose
    // repair fetches used to outlive the job the user deleted. See
    // [`SideCancel`]. None = uncancellable, which is only the CLI.
    cancel: Option<&SideCancel>,
    open: VolumeOpen,
) -> Result<(VolumeFailures, Vec<PathBuf>)> {
    use nzbkit::pool::{FetchOutcome, fetch_all_multi_ctl};
    // Refuse outright rather than fetch and discard: a cancelled owner
    // may still have a ladder of volumes queued behind this one, and
    // every rung of it is now bytes nobody will read.
    if cancel.is_some_and(SideCancel::is_cancelled) {
        anyhow::bail!("recovery fetch cancelled");
    }
    // This driver's consumer never gives the pool a verdict:
    // consume_volume_articles has no QueueControl, so it calls neither
    // note_decoded (the crc_steer seam) nor note_settled (arrival_ack).
    // A caller that hands in the MAIN fleet's configs - crc_steer is ON
    // by default on a multi-server setup - parks every delivered body's
    // completion behind an ack that can never come: the volume lands
    // fully on disk while the pool never drains, and the job hangs in
    // "Repairing" with the whole finalize chain wedged behind it (the
    // 7 Aug 2026 daemon wedge). The same clone also carries the line
    // cap's live targets, which a 1-connection side pool would shed the
    // whole main fleet down to. side_pool_servers already strips both
    // for the speculative prefetch, but the strip belongs HERE, at the
    // single driver every side-fetch goes through, so no caller can
    // reintroduce either. See [`strip_side_pool_seams`].
    let servers: Vec<(ServerConfig, nzbkit::pool::PoolConfig)> = servers
        .iter()
        .map(|(sc, pc)| {
            let mut pc = pc.clone();
            strip_side_pool_seams(&mut pc);
            (sc.clone(), pc)
        })
        .collect();
    let servers = servers.as_slice();
    // Side-fetch: small volume sets, fast disk-writer consumer - a
    // modest fixed depth (≈25 MB) instead of the old 256 (~200 MB of
    // budget-exempt bytes on a box that may only have 256 MB total).
    let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(32);
    let out_dir2 = out_dir.to_path_buf();
    let pool2 = buf_pool.clone();
    let consumer = tokio::spawn(async move {
        consume_volume_articles(rx, id_to_file, out_dir2, pool2, prealloc_cap, open).await
    });
    let t0 = Instant::now();
    let stats = match cancel {
        Some(c) => {
            c.guard(fetch_all_multi_ctl(servers, ids, tx, Some(&c.ctl)))
                .await
        }
        None => fetch_all_multi_ctl(servers, ids, tx, None).await,
    };
    let (failures, paths) = consumer.await?;
    let failed = failures.total();
    // An aborted run's unresolved articles emit NO outcome, so `failures`
    // can read 0 over a volume that is actually short - the H2
    // false-shortfall shape. Never hand that back as a clean result: a
    // caller allowed to believe it would strike the whole volume off its
    // fetch list. The written paths are abandoned on disk exactly as an
    // interrupted download's partials are, and the sweep owns them.
    if cancel.is_some_and(SideCancel::is_cancelled) {
        anyhow::bail!("recovery fetch cancelled after {:.2?}", t0.elapsed());
    }
    let raw: u64 = stats.iter().map(|s| s.bytes).sum();
    info!(
        target: "repair",
        "fetched {:.1} MB of recovery data in {:.2?}{}",
        raw as f64 / 1e6,
        t0.elapsed(),
        if failed > 0 {
            format!(" ({failed} article failures)")
        } else {
            String::new()
        }
    );
    Ok((failures, paths))
}

/// Article failures from one side-fetch, attributed to the volume each
/// one belongs to.
///
/// A fetch-wide total cannot say WHICH volume came back short, and a
/// caller that installs per file then has to assume the worst: the
/// dropped-volume refetch (`get/dropped.rs`) discarded EVERY renamed
/// install whenever any article anywhere in the fetch failed, so one
/// lost article of volume A threw away a complete volume B (Codex F-05,
/// 22 Aug 2026).
///
/// Every arm that knows the file index charges it. An outcome whose id
/// resolves to no file index cannot be charged to anyone, so it is
/// counted apart and taints EVERY file: nothing here can say which
/// volume lost it, and calling a whole volume short costs a refetch
/// while calling a short one whole destroys good bytes.
///
/// Since 26 Aug 2026 every charge also carries a [`Blame`], and the two
/// axes answer DIFFERENT questions - see [`Self::ours`]. The
/// attribution axis (`total` / `for_file`) is unchanged and still
/// counts every failure whoever lost it, because "is this volume
/// complete" does not care whose fault a hole is.
#[derive(Debug, Default)]
pub(crate) struct VolumeFailures {
    per_file: std::collections::HashMap<usize, u32>,
    unattributed: u32,
    ours: u32,
}

/// Whether one failed recovery article is evidence about the SOURCE or
/// about US. The second axis of [`VolumeFailures`], and the whole of
/// what [`VolumeYield::source_will_not_serve`] may reason about.
///
/// Not a shade of the attribution axis and not a replacement for it: a
/// volume that lost an article to our own wound-down fleet is just as
/// PARTIAL as one the provider refused, and `fetch_volumes`' contract
/// that only a complete volume may enter a whole-file exclusion list
/// rests on that. Two questions, two counters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Blame {
    /// A provider was asked and did not produce the bytes. Evidence
    /// about this source's willingness to serve this recovery set.
    Source,
    /// Nobody asked, or our own side lost it. Evidence about us.
    Ours,
}

impl VolumeFailures {
    /// One failure that belongs to file index `fi`.
    fn charge(&mut self, fi: usize, blame: Blame) {
        let n = self.per_file.entry(fi).or_insert(0);
        *n = n.saturating_add(1);
        self.charge_blame(blame);
    }

    /// One failure no file index could be found for.
    fn charge_unattributed(&mut self, blame: Blame) {
        self.unattributed = self.unattributed.saturating_add(1);
        self.charge_blame(blame);
    }

    /// One failure charged to whichever file owns `id`, or to nobody
    /// when the id resolves to none - the lookup both terminal outcomes
    /// do, in one place so a new outcome arm cannot spell it a third
    /// way.
    fn charge_id(
        &mut self,
        id_to_file: &std::collections::HashMap<Arc<str>, usize>,
        id: &str,
        blame: Blame,
    ) {
        match id_to_file.get(id) {
            Some(&fi) => self.charge(fi, blame),
            None => self.charge_unattributed(blame),
        }
    }

    fn charge_blame(&mut self, blame: Blame) {
        if blame == Blame::Ours {
            self.ours = self.ours.saturating_add(1);
        }
    }

    /// Every failure in the fetch, however it was attributed - what a
    /// caller that only wants "did this fetch land whole" reads.
    pub(crate) fn total(&self) -> u32 {
        self.per_file
            .values()
            .copied()
            .sum::<u32>()
            .saturating_add(self.unattributed)
    }

    /// Of [`Self::total`], the ones that demonstrated nothing about the
    /// source. Always a subset. See [`VolumeYield::ours`] for what
    /// reading them as a provider's refusal used to cost.
    pub(crate) fn ours(&self) -> u32 {
        self.ours
    }

    /// Failures that may have cost `fi` bytes: its own, plus every
    /// unattributable one.
    pub(crate) fn for_file(&self, fi: usize) -> u32 {
        self.per_file
            .get(&fi)
            .copied()
            .unwrap_or(0)
            .saturating_add(self.unattributed)
    }
}

/// Decode side-fetched articles onto their volume files. Returns
/// ([`VolumeFailures`], paths actually written) - split out of
/// [`fetch_volume_articles`] so the writer-failure path is reachable from
/// a test without a server.
///
/// A volume whose writer cannot be created is DROPPED, not fatal: the
/// declared name is attacker-influenced (it may sanitise to something
/// unopenable) and the disk may be full or read-only. Panicking here took
/// the consumer task down and, with it, every other volume in the same
/// side-fetch. Absent from the returned paths means "we did not get that
/// volume", which every caller already handles - the slices are counted
/// from the files that actually landed, so nothing is over-credited.
pub(crate) async fn consume_volume_articles(
    mut rx: tokio::sync::mpsc::Receiver<nzbkit::pool::FetchOutcome>,
    id_to_file: std::collections::HashMap<Arc<str>, usize>,
    out_dir: PathBuf,
    buf_pool: Arc<nzbkit::pool::BufPool>,
    prealloc_cap: u64,
    open: VolumeOpen,
) -> (VolumeFailures, Vec<PathBuf>) {
    use nzbkit::disk::{FileWriter, sanitize_filename};
    use nzbkit::pool::FetchOutcome;
    use std::collections::hash_map::Entry;
    use std::collections::{HashMap, HashSet};

    let mut writers: HashMap<usize, (PathBuf, Arc<FileWriter>)> = HashMap::new();
    // Volumes whose writer could not be opened. Remembered so the create
    // is attempted ONCE per volume rather than once per article - on a
    // full disk that would be thousands of failing opens - and so the
    // failure is reported once.
    let mut unwritable: HashSet<usize> = HashSet::new();
    let mut failures = VolumeFailures::default();
    while let Some(outcome) = rx.recv().await {
        match outcome {
            FetchOutcome::Done { id, raw } => {
                // Guarded the moment it leaves the channel, so every arm
                // below returns it without having to remember to.
                let raw = buf_pool.adopt(raw);
                let Some(&fi) = id_to_file.get(&*id) else {
                    continue;
                };
                match nzbkit::yenc_simd::decode(&raw) {
                    // The wire produced bytes and they would not decode
                    // - a truncated body, a broken yEnc frame, a pcrc32
                    // that does not check out. That IS a fact about
                    // what this source served, and it is the reading
                    // the main run already takes (a `DecodeReport::Bad`
                    // sends the article to another server). So it
                    // charges the source, exactly as it did before the
                    // blame axis existed.
                    Err(_) => failures.charge(fi, Blame::Source),
                    // A volume this consumer already failed to open.
                    // The provider served the article; our disk, or the
                    // name it sanitised to, is what lost it.
                    Ok(_) if unwritable.contains(&fi) => failures.charge(fi, Blame::Ours),
                    Ok(dec) => {
                        let w = match writers.entry(fi) {
                            Entry::Occupied(e) => Some(&e.into_mut().1),
                            Entry::Vacant(slot) => {
                                let path = out_dir.join(sanitize_filename(&dec.name));
                                // The declared `size=` is the poster's
                                // number and on Linux preallocation is a
                                // real fallocate, so it reserves only up
                                // to the ceiling. `size` itself stays
                                // unclamped (the writer reports it).
                                let made = match open {
                                    VolumeOpen::Fresh => FileWriter::create_capped(
                                        &path,
                                        dec.file_size,
                                        prealloc_cap,
                                    ),
                                    VolumeOpen::Additive => FileWriter::create_resume_capped(
                                        &path,
                                        dec.file_size,
                                        prealloc_cap,
                                    ),
                                };
                                match made {
                                    Ok(f) => Some(&slot.insert((path, Arc::new(f))).1),
                                    Err(e) => {
                                        warn!(
                                            target: "repair",
                                            "cannot write recovery volume {} ({e}) - skipping it",
                                            path.display()
                                        );
                                        unwritable.insert(fi);
                                        None
                                    }
                                }
                            }
                        };
                        match w {
                            Some(w) if w.write_at(dec.offset(), &dec.data).is_ok() => {}
                            // The writer could not be created (full,
                            // read-only, unopenable name) or the write
                            // failed. Both are this end, so neither is
                            // evidence about the source.
                            _ => failures.charge(fi, Blame::Ours),
                        }
                    }
                }
            }
            // Both remaining variants carry the id, so a terminal
            // article failure lands on its own volume. Matched by name
            // rather than `_` so a new outcome variant has to be
            // attributed here by hand instead of silently tainting the
            // whole fetch.
            //
            // They are charged to the same file and to OPPOSITE sides
            // of the blame axis, which is the 26 Aug 2026 fix: until
            // then one arm covered both and `VolumeYield::failed` mixed
            // "every live server refused this" with "our fleet wound
            // down before anyone asked". See [`VolumeYield::ours`].
            FetchOutcome::Missing { id, .. } => {
                // Every server still live was asked and answered
                // 430/423, or the article is past every configured
                // server's retention so this source's coverage of the
                // set says the same thing without a round trip. Either
                // way asking this source for MORE of the set is what
                // the gate exists to refuse, and either way an
                // alternate source is the remedy the clause names.
                failures.charge_id(&id_to_file, &id, Blame::Source);
            }
            FetchOutcome::Failed { id, code, .. } => {
                // NOT ONE of these is the source refusing, and the
                // match is spelled out variant by variant rather than
                // collapsed so a FIFTH `FailCode` has to be classified
                // here by hand. The identical right-hand sides are the
                // finding, not a redundancy to tidy away.
                let blame = match code {
                    // Nobody ever asked: the fleet wound down with work
                    // still queued, or a worker panicked holding it.
                    // `FleetExhausted` is the shape that reached the
                    // user as "a different source would fix it".
                    nzbkit::fail::FailCode::FleetExhausted
                    | nzbkit::fail::FailCode::WorkerPanic => Blame::Ours,
                    // The link between us and the provider failed, or
                    // OUR read deadline ended the session. Says nothing
                    // about whether the article is there, which is why
                    // `FailKind::Transport` is kept out of dead-post
                    // reporting one layer up for the same reason.
                    nzbkit::fail::FailCode::Transport | nzbkit::fail::FailCode::ReadStall => {
                        Blame::Ours
                    }
                };
                failures.charge_id(&id_to_file, &id, blame);
            }
        }
    }
    (failures, writers.into_values().map(|(p, _)| p).collect())
}

/// What a side pool may NOT inherit from the download's configs. Every
/// side-fetch runs on a clone of the MAIN fleet's configs, so each of
/// these is a seam the download owns and the side pool would drive.
#[cfg(test)]
mod side_pool_strip_tests {
    use super::*;

    /// A main-fleet config as `get::fleet` builds it for a daemon job:
    /// five connections, the line cap armed, and a live target the whole
    /// download's workers read.
    fn main_fleet_config(target: &Arc<nzbkit::pool::ConnTarget>) -> nzbkit::pool::PoolConfig {
        nzbkit::pool::PoolConfig {
            connections: 5,
            crc_steer: true,
            arrival_ack: true,
            live_target: Some(target.clone()),
            line_cap_fleet: 25,
            line_cap_auto: true,
            line_anchor_bps: 12_500_000,
            ..Default::default()
        }
    }

    /// The bug: the side pool's clone kept `live_target`, so LineCap
    /// paired the MAIN fleet's shared ConnTarget with the SIDE pool's
    /// own width as its ceiling. One second of volume delivery later the
    /// shed wrote that width into the download's target and every main
    /// worker parked, for the rest of the job, with no raise arm able to
    /// undo it. The anchor stays - the stall bound sizes an article's
    /// share from it and it moves nothing once the targets are gone.
    #[test]
    fn a_side_pool_never_holds_the_main_fleets_conn_target() {
        let target = nzbkit::pool::ConnTarget::new(5);
        let mut pc = main_fleet_config(&target);
        strip_side_pool_seams(&mut pc);
        assert!(pc.live_target.is_none(), "side pool kept the main target");
        assert_eq!(pc.line_cap_fleet, 0);
        assert!(!pc.line_cap_auto);
        assert_eq!(pc.line_anchor_bps, 12_500_000, "the stall bound wants it");
        // And the seams the 7 Aug 2026 wedge came in through.
        assert!(!pc.crc_steer);
        assert!(!pc.arrival_ack);
        assert!(pc.channel_gauge.is_none());
        assert_eq!(target.get(), 5, "the download's own target moved");
    }
}

/// §282 item 4's gate, on its own. Arithmetic only - the wire shapes
/// that produce these numbers are `recovery_volume_tests` below and the
/// `a_recovery_set_the_source_will_not_serve_*` e2e legs.
#[cfg(test)]
mod volume_yield_tests {
    use super::*;

    /// The incident, in this type's terms: a 1024 MB ask that returned
    /// 6.7% of its articles. Everything after that measurement was the
    /// daemon asking the same provider for MORE.
    #[test]
    fn the_incident_fetch_says_the_source_will_not_serve() {
        let y = VolumeYield {
            asked: 1293,
            failed: 1206,
            ours: 0,
        };
        assert!(y.source_will_not_serve());
        assert!(y.fraction() < 0.07, "{}", y.fraction());
        assert!(y.describe().contains("87 of 1293"), "{}", y.describe());
    }

    /// The shape the e2e suite pins as a LEGITIMATE partial, and the
    /// reason the threshold is one half rather than something tighter:
    /// one lost article of a large volume must still escalate, because
    /// the escalation is what refetches it.
    #[test]
    fn one_lost_article_of_a_large_volume_still_escalates() {
        let y = VolumeYield {
            asked: 180,
            failed: 1,
            ours: 0,
        };
        assert!(!y.source_will_not_serve());
    }

    /// A ratio needs a denominator. One lost article of a two-article
    /// volume is 50% and says nothing at all about the provider, so the
    /// sample floor refuses it - which is the difference between a gate
    /// and a coin toss on every small recovery set.
    #[test]
    fn a_tiny_fetch_is_never_a_verdict_about_the_source() {
        for asked in 1..MIN_RECOVERY_YIELD_SAMPLE {
            let y = VolumeYield {
                asked,
                failed: asked,
                ours: 0,
            };
            assert!(
                !y.source_will_not_serve(),
                "{asked} article(s) is not a sample"
            );
        }
        // One more article and the same total refusal IS a verdict.
        let y = VolumeYield {
            asked: MIN_RECOVERY_YIELD_SAMPLE,
            failed: MIN_RECOVERY_YIELD_SAMPLE,
            ours: 0,
        };
        assert!(y.source_will_not_serve());
    }

    /// An empty ask has demonstrated nothing, and the safe reading of
    /// "nothing demonstrated" is "carry on" - a default-constructed
    /// yield is what `fetch_and_repair` starts every run holding.
    #[test]
    fn an_empty_ask_is_not_a_refusal() {
        let y = VolumeYield::default();
        assert_eq!(y.fraction(), 1.0);
        assert!(!y.source_will_not_serve());
    }

    /// TODO 307 item 1's residue, and the case that was missing: a
    /// fetch whose every loss was OURS says nothing whatsoever about
    /// the provider, and must not reach `RepairShortfall::Unservable`.
    ///
    /// Before 26 Aug 2026 this was the §282 incident's own arithmetic -
    /// 1293 asked, 1206 failed, 6.7% - and it fired, because a
    /// `FetchOutcome::Failed` was charged exactly like a `Missing`. The
    /// user was then told the payload was fine and a different source
    /// for the same release would fix it, for a fleet that wound down
    /// with the articles still queued.
    #[test]
    fn a_fetch_whose_losses_are_all_ours_is_not_a_verdict_about_the_source() {
        let y = VolumeYield {
            asked: 1293,
            failed: 1206,
            ours: 1206,
        };
        assert!(
            !y.source_will_not_serve(),
            "our own fleet winding down was read as a provider refusing: {}",
            y.describe()
        );
        // The source was asked about 87 articles and served all 87.
        assert_eq!(y.source_asked(), 87);
        assert_eq!(y.fraction(), 1.0);
        // ...and the volume is still PARTIAL, which is the other
        // question and must not have moved: only a COMPLETE volume may
        // enter a whole-file exclusion list, whoever lost the articles.
        assert_ne!(y.failed, 0);
        assert_eq!(y.delivered(), 87);
    }

    /// The same `asked` and `failed`, three readings of who lost them,
    /// three different verdicts. The middle one is the point: a fetch
    /// that reads 40% when our own losses are counted reads 57% when
    /// they are not, and 57% is the honest number to price the
    /// escalation against.
    #[test]
    fn a_mixed_fetch_is_judged_on_the_source_half_alone() {
        let all_theirs = VolumeYield {
            asked: 100,
            failed: 60,
            ours: 0,
        };
        assert!(all_theirs.source_will_not_serve());

        let half_ours = VolumeYield {
            asked: 100,
            failed: 60,
            ours: 30,
        };
        assert!(!half_ours.source_will_not_serve());
        assert!(
            (half_ours.fraction() - 40.0 / 70.0).abs() < 1e-9,
            "{}",
            half_ours.fraction()
        );

        let all_ours = VolumeYield {
            asked: 100,
            failed: 60,
            ours: 60,
        };
        assert!(!all_ours.source_will_not_serve());
        assert_eq!(all_ours.fraction(), 1.0);
    }

    /// The sample floor moved onto the SOURCE half with the ratio, and
    /// that pairing is deliberate: a fetch of a thousand articles that
    /// only ever reached the provider with fifteen of them has taken a
    /// fifteen-article sample, and fifteen is exactly what
    /// [`MIN_RECOVERY_YIELD_SAMPLE`] exists to refuse to judge on.
    #[test]
    fn the_sample_floor_applies_to_the_source_half() {
        let under = VolumeYield {
            asked: 1000,
            failed: 999,
            ours: 985,
        };
        assert_eq!(under.source_asked(), MIN_RECOVERY_YIELD_SAMPLE - 1);
        assert!(
            under.fraction() < MIN_RECOVERY_YIELD,
            "{}",
            under.fraction()
        );
        assert!(
            !under.source_will_not_serve(),
            "a fifteen-article sample is not a verdict about a provider"
        );
        // One more article that the source itself refused, and the same
        // refusal IS a verdict.
        let over = VolumeYield {
            asked: 1000,
            failed: 999,
            ours: 984,
        };
        assert_eq!(over.source_asked(), MIN_RECOVERY_YIELD_SAMPLE);
        assert!(over.source_will_not_serve());
    }

    /// Our own losses are NAMED, never silently dropped: the clause
    /// states the sample the verdict was reached on, and then says what
    /// happened to the rest of the fetch. A reader who saw "1 of 200"
    /// about a thousand-article fetch and nothing else would have no
    /// way to account for the other 800.
    #[test]
    fn our_own_losses_are_named_in_the_clause() {
        let y = VolumeYield {
            asked: 1000,
            failed: 999,
            ours: 800,
        };
        let d = y.describe();
        assert!(d.starts_with("1 of 200 recovery article(s) arrived"), "{d}");
        assert!(d.contains("plus 800 that failed on our side"), "{d}");
        // And with nothing of ours in it - every shape the e2e suite
        // pins, and the §282 incident - the sentence is the one it
        // always was, character for character.
        let clean = VolumeYield {
            asked: 1293,
            failed: 1206,
            ours: 0,
        };
        assert_eq!(
            clean.describe(),
            "87 of 1293 recovery article(s) arrived (6.7%)"
        );
    }

    /// `ours` is a SUBSET of `failed` and the arithmetic holds it to
    /// that rather than trusting a caller: an `ours` past `failed`
    /// would subtract more from the denominator than from the
    /// numerator, report over 100% of the articles delivered, and leave
    /// a verdict that can never fire whatever the provider does.
    #[test]
    fn ours_can_never_exceed_failed() {
        let y = VolumeYield {
            asked: 10,
            failed: 2,
            ours: 7,
        };
        assert_eq!(y.source_asked(), 8);
        assert_eq!(y.fraction(), 1.0);
        assert!(y.describe().starts_with("8 of 8"), "{}", y.describe());
    }

    /// Exactly at the threshold is not under it: the gate refuses the
    /// escalation only once the source has served LESS than half.
    #[test]
    fn the_threshold_is_strict() {
        let half = VolumeYield {
            asked: 100,
            failed: 50,
            ours: 0,
        };
        assert!(!half.source_will_not_serve());
        let under = VolumeYield {
            asked: 100,
            failed: 51,
            ours: 0,
        };
        assert!(under.source_will_not_serve());
    }
}

#[cfg(test)]
mod recovery_volume_tests {
    use super::*;
    use nzbkit::pool::{BufPool, FetchOutcome};
    use std::collections::HashMap;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nzbfast-vol-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// One complete single-part yEnc article body, exactly as the fetch
    /// pool hands it to the consumer. `declared` is the `size=` field -
    /// the number the POSTER controls, which is the whole point here.
    fn article(name: &str, declared: u64, data: &[u8]) -> Vec<u8> {
        nzbkit::yenc::encode(name, declared, Some((1, 1)), 1, data)
    }

    /// Drive the real consumer over `arts` = (file index, article body).
    async fn consume(
        dir: &Path,
        arts: Vec<(usize, Vec<u8>)>,
        cap: u64,
    ) -> (VolumeFailures, Vec<PathBuf>) {
        let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(16);
        let mut id_to_file = HashMap::new();
        for (n, (fi, body)) in arts.into_iter().enumerate() {
            let id: Arc<str> = format!("<a{n}@test>").into();
            id_to_file.insert(id.clone(), fi);
            tx.send(FetchOutcome::Done { id, raw: body }).await.unwrap();
        }
        drop(tx);
        // Spawned, so a panic in the consumer surfaces as a JoinError
        // instead of unwinding the test itself - that is the assertion
        // for the panic regression below.
        tokio::spawn(consume_volume_articles(
            rx,
            id_to_file,
            dir.to_path_buf(),
            BufPool::new(4),
            cap,
            VolumeOpen::Fresh,
        ))
        .await
        .expect("the recovery-volume consumer task must not panic")
    }

    /// BUG (HIGH): the PAR2 recovery-volume side-fetch preallocated the
    /// attacker-declared yEnc `size=` with NO ceiling - `FileWriter::create`
    /// -> `create_capped(.., u64::MAX)` -> `set_len` plus a real Linux
    /// `fallocate`. It bypassed the ceiling the extractor already had, so a
    /// small post could reserve the victim's free space on ext4/XFS.
    #[tokio::test]
    async fn a_recovery_volume_cannot_reserve_past_the_posted_ceiling() {
        let dir = temp_dir("cap");
        const HUGE: u64 = 8 << 40; // 8 TiB "declared"
        const POSTED: u64 = 1 << 20; // what the NZB actually posted
        let payload = vec![0x5Au8; 4096];

        let (failures, paths) = consume(
            &dir,
            vec![(0, article("set.vol000+01.par2", HUGE, &payload))],
            POSTED,
        )
        .await;

        assert_eq!(failures.total(), 0);
        assert_eq!(paths.len(), 1);
        let len = std::fs::metadata(&paths[0]).unwrap().len();
        assert_eq!(
            len, POSTED,
            "a poster-declared volume size must not reserve past the posted ceiling"
        );
        // The cap bounds the RESERVATION only - the article's bytes still
        // land at their offset, byte for byte.
        assert_eq!(
            &std::fs::read(&paths[0]).unwrap()[..payload.len()],
            &payload[..]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// THE test that matters: a wrong fix here silently de-optimises every
    /// real download. A genuine recovery volume, whose declared size fits
    /// under the posted ceiling, must still be reserved IN FULL from the
    /// first article - not clamped to the bytes that have arrived.
    #[tokio::test]
    async fn a_legitimate_recovery_volume_still_preallocates_in_full() {
        let dir = temp_dir("cap-ok");
        const SIZE: u64 = 4_000_000; // the volume's real size
        const POSTED: u64 = 64_000_000; // the NZB's posted bytes
        let first_part = vec![0x11u8; 8192];

        let (failures, paths) = consume(
            &dir,
            vec![(0, article("set.vol000+02.par2", SIZE, &first_part))],
            POSTED,
        )
        .await;
        assert_eq!(failures.total(), 0);
        assert_eq!(
            std::fs::metadata(&paths[0]).unwrap().len(),
            SIZE,
            "a legitimate volume under the ceiling must be preallocated in full, \
             not clamped to the bytes received so far"
        );
        std::fs::remove_dir_all(&dir).unwrap();

        // And with no ceiling at all: byte-for-byte the old behaviour.
        let dir = temp_dir("cap-none");
        let (_, paths) = consume(
            &dir,
            vec![(0, article("set.vol000+02.par2", SIZE, &first_part))],
            u64::MAX,
        )
        .await;
        assert_eq!(std::fs::metadata(&paths[0]).unwrap().len(), SIZE);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The ceiling for an NZB without byte attributes (0 posted bytes
    /// means "unknown", not zero) used to be NO ceiling at all - which
    /// let a poster omit `bytes=` and reserve the declared yEnc `size=`
    /// unbounded. The post's article geometry bounds it instead: one
    /// declared article justifies one article's worth of reservation,
    /// never a 0 ceiling (which would reserve nothing for every volume
    /// of such a post).
    #[test]
    fn an_nzb_without_byte_attributes_is_bounded_by_its_geometry() {
        let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="set.vol000+01.par2 yEnc (1/1)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment number="1">a@test</segment></segments>
 </file>
</nzb>"#;
        let nzb = nzbkit::nzb::Nzb::parse(xml).unwrap();
        assert_eq!(nzb.total_bytes(), 0);
        assert_eq!(volume_prealloc_cap(&nzb), 16 << 20);
    }

    /// Bug sweep 22 Aug 2026: the dropped-volume refetch writes over a
    /// file the demote already materialized minus its dropped ranges.
    /// An `Additive` open keeps the bytes already on disk; the `Fresh`
    /// open is the truncating one, and a fetch that then loses an
    /// article would leave a hole where the bytes had been correct.
    #[tokio::test]
    async fn an_additive_open_keeps_the_bytes_already_on_disk() {
        for (mode, expect_kept) in [(VolumeOpen::Additive, true), (VolumeOpen::Fresh, false)] {
            let dir = temp_dir(if expect_kept { "additive" } else { "fresh" });
            let path = dir.join("vol.rar");
            // 2 KB already on disk at offsets 0..2048 (the good prefix),
            // the refetch delivers only part 2 (a single-part article at
            // offset 0 of size 512 stands in for "some other range").
            std::fs::write(&path, vec![0xAAu8; 2048]).unwrap();
            let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(4);
            let mut id_to_file = HashMap::new();
            let id: Arc<str> = "<p@test>".into();
            id_to_file.insert(id.clone(), 0usize);
            tx.send(FetchOutcome::Done {
                id,
                raw: article("vol.rar", 2048, &vec![0xBBu8; 512]),
            })
            .await
            .unwrap();
            drop(tx);
            let (failures, _) = consume_volume_articles(
                rx,
                id_to_file,
                dir.clone(),
                BufPool::new(4),
                u64::MAX,
                mode,
            )
            .await;
            assert_eq!(failures.total(), 0);
            let got = std::fs::read(&path).unwrap();
            assert_eq!(got.len(), 2048, "{mode:?}");
            assert!(got[..512].iter().all(|&b| b == 0xBB), "{mode:?}");
            let tail_kept = got[512..].iter().all(|&b| b == 0xAA);
            assert_eq!(tail_kept, expect_kept, "{mode:?}: tail bytes");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Drive the real consumer over a list of terminal outcomes,
    /// returning what it charged. The `Done` path has its own helper
    /// above; this one is for the two failure variants, which is where
    /// the blame axis lives.
    async fn consume_outcomes(
        dir: &Path,
        outs: Vec<(usize, FetchOutcome)>,
    ) -> (VolumeFailures, Vec<PathBuf>) {
        let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(256);
        let mut id_to_file = HashMap::new();
        for (fi, out) in outs {
            let id: Arc<str> = match &out {
                FetchOutcome::Done { id, .. }
                | FetchOutcome::Missing { id, .. }
                | FetchOutcome::Failed { id, .. } => id.clone(),
            };
            id_to_file.insert(id, fi);
            tx.send(out).await.unwrap();
        }
        drop(tx);
        consume_volume_articles(
            rx,
            id_to_file,
            dir.to_path_buf(),
            BufPool::new(4),
            u64::MAX,
            VolumeOpen::Fresh,
        )
        .await
    }

    fn refused(n: usize) -> FetchOutcome {
        FetchOutcome::Missing {
            id: format!("<t{n}@test>").into(),
            cause: nzbkit::pool::MissingCause::Gone { takedown: false },
        }
    }

    fn gave_up(n: usize, code: nzbkit::fail::FailCode) -> FetchOutcome {
        FetchOutcome::Failed {
            id: format!("<o{n}@test>").into(),
            code,
            error: code.reason().to_string(),
        }
    }

    /// TODO 307 item 1's residue, at the wire: the consumer's two axes
    /// answer different questions and must stay independent.
    ///
    /// `FetchOutcome::Missing` is every live server having been asked
    /// and having answered 430/423 - evidence about the source.
    /// `FetchOutcome::Failed` is the pool giving up without a body, and
    /// not one of `FailCode`'s four variants is the source refusing;
    /// until 26 Aug 2026 ONE match arm charged both of them, so the
    /// two arrived in the caller as one number.
    ///
    /// The completeness half is asserted here too, because the fix must
    /// not buy the blame axis with it: both volumes are still PARTIAL,
    /// and `fetch_volumes`' contract that only a COMPLETE volume may
    /// enter a whole-file exclusion list rests on that count including
    /// the articles nobody ever asked for.
    #[tokio::test]
    async fn the_consumer_keeps_completeness_and_blame_apart() {
        let dir = temp_dir("blame-mixed");
        let mut outs: Vec<(usize, FetchOutcome)> = Vec::new();
        // Volume 0: 40 articles the wound-down fleet never asked for.
        for i in 0..40 {
            outs.push((0, gave_up(i, nzbkit::fail::FailCode::FleetExhausted)));
        }
        // Volume 1: 20 the provider was asked for and refused.
        for i in 0..20 {
            outs.push((1, refused(i)));
        }
        let (failures, _paths) = consume_outcomes(&dir, outs).await;

        // COMPLETENESS, unmoved: 60 articles produced no bytes and both
        // volumes are short. `get/dropped.rs` and the speculative
        // prefetch read exactly these two numbers.
        assert_eq!(failures.total(), 60);
        assert_eq!(failures.for_file(0), 40);
        assert_eq!(failures.for_file(1), 20);
        // BLAME, the new axis.
        assert_eq!(failures.ours(), 40);

        // The yield a caller builds off it, exactly as `fetch_volumes`
        // does. The provider was asked about 20 and served none, so the
        // verdict still fires - on the twenty it was actually asked,
        // not on sixty it mostly never heard about.
        let y = VolumeYield {
            asked: 60,
            failed: failures.total(),
            ours: failures.ours(),
        };
        assert_eq!(y.source_asked(), 20);
        assert!(y.source_will_not_serve(), "{}", y.describe());
        assert!(y.describe().starts_with("0 of 20"), "{}", y.describe());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The flip, at the wire: a fetch the provider was never asked
    /// about must not report the provider.
    ///
    /// This is the shape that reached the user. `source_will_not_serve`
    /// drives `RepairShortfall::Unservable`, whose clause says "the
    /// payload is not the problem here, so a different source for the
    /// same release is what would fix it" - so before this fix a fleet
    /// that wound down mid recovery-fetch, or a link that failed, sent
    /// the reader after another release for a failure that was ours.
    ///
    /// Both blame families are driven: `FleetExhausted` (nobody asked)
    /// and `Transport` (the link between us and the provider). All four
    /// `FailCode` variants are Ours, and the classification is spelled
    /// out variant by variant in the consumer so a fifth has to be
    /// judged by hand.
    #[tokio::test]
    async fn a_wound_down_fleet_is_not_a_provider_refusing() {
        let dir = temp_dir("blame-ours");
        let outs: Vec<(usize, FetchOutcome)> = (0..40)
            .map(|i| {
                let code = if i % 2 == 0 {
                    nzbkit::fail::FailCode::FleetExhausted
                } else {
                    nzbkit::fail::FailCode::Transport
                };
                (0usize, gave_up(i, code))
            })
            .collect();
        let (failures, _paths) = consume_outcomes(&dir, outs).await;
        assert_eq!(failures.total(), 40, "the volume is still short 40");
        assert_eq!(failures.ours(), 40, "not one of them reached a provider");
        let y = VolumeYield {
            asked: 40,
            failed: failures.total(),
            ours: failures.ours(),
        };
        // Sixteen or more articles and 0% delivered: everything the
        // gate needs, except that none of it is about the provider.
        assert!(y.asked >= MIN_RECOVERY_YIELD_SAMPLE);
        assert!(
            !y.source_will_not_serve(),
            "our own pool giving up was reported as a provider refusing: {}",
            y.describe()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex H3: the posted `bytes=` total is as poster-controlled as
    /// the yEnc `size=`, so "min(size, posted)" was the attacker picking
    /// both sides - one tiny article declaring two 100 GB numbers became
    /// a real fallocate. The article geometry caps it: a single-segment
    /// post can never justify more than one article's worth.
    #[test]
    fn an_inflated_posted_byte_count_is_bounded_by_its_geometry() {
        let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="set.vol000+01.par2 yEnc (1/1)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="109951162777600" number="1">a@test</segment></segments>
 </file>
</nzb>"#;
        let nzb = nzbkit::nzb::Nzb::parse(xml).unwrap();
        assert_eq!(volume_prealloc_cap(&nzb), 16 << 20);
        // And a genuine posted count under the geometry passes through.
        let xml2 = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="set.vol000+01.par2 yEnc (1/2)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="750000" number="1">a@test</segment>
   <segment bytes="750000" number="2">b@test</segment>
  </segments>
 </file>
</nzb>"#;
        let nzb2 = nzbkit::nzb::Nzb::parse(xml2).unwrap();
        assert_eq!(volume_prealloc_cap(&nzb2), 1_500_000);
    }

    /// Sweep 8, L3: a message-id repeated across recovery volumes stays
    /// with its FIRST owner, and the later volume simply comes back
    /// short.
    ///
    /// The routing map was last-owner-wins while the pool's own request
    /// dedup keeps the FIRST request - two rules pointing opposite ways
    /// across the same id. A malformed or hostile recovery set that
    /// repeats one therefore had the single delivered body routed to the
    /// LATER file index, while the writer for that index was created
    /// from the FIRST body's yEnc name; the later volume's genuinely
    /// unique articles then landed inside a file named after the earlier
    /// one, damaging both.
    #[tokio::test]
    async fn a_duplicate_id_across_volumes_stays_with_its_first_owner() {
        let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="set.vol000+01.par2 yEnc (1/2)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="4000" number="1">shared@test</segment>
   <segment bytes="4000" number="2">uniq-a@test</segment>
  </segments>
 </file>
 <file subject="set.vol001+02.par2 yEnc (1/2)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="4000" number="1">shared@test</segment>
   <segment bytes="4000" number="2">uniq-b@test</segment>
  </segments>
 </file>
</nzb>"#;
        let nzb = nzbkit::nzb::Nzb::parse(xml).unwrap();
        let mut ids = Vec::new();
        let mut id_to_file: HashMap<Arc<str>, usize> = HashMap::new();
        let omitted_0 = volume_reqs(&nzb, 0, &mut ids, &mut id_to_file);
        let omitted_1 = volume_reqs(&nzb, 1, &mut ids, &mut id_to_file);
        assert_eq!(omitted_0, 0, "the first owner skips nothing");
        assert_eq!(
            omitted_1, 1,
            "the segment the second volume lost to the first owner must be \
             COUNTED - it is never requested, so no Missing outcome comes back \
             and the failure map alone reads this volume as whole (Codex F-02)"
        );

        assert_eq!(
            id_to_file.get("<shared@test>"),
            Some(&0),
            "the first volume that named the id keeps it - the same rule the \
             pool's request dedup already follows"
        );
        assert_eq!(id_to_file.get("<uniq-a@test>"), Some(&0));
        assert_eq!(id_to_file.get("<uniq-b@test>"), Some(&1));
        let requested: Vec<&str> = ids.iter().map(|r| &*r.id).collect();
        assert_eq!(
            requested,
            ["<shared@test>", "<uniq-a@test>", "<uniq-b@test>"],
            "the duplicate is requested ONCE, so the second volume is short by \
             one article rather than being handed the first volume's body"
        );

        // And through the consumer: each volume writes its own file,
        // named from its own body. The second is incomplete, which is
        // the honest outcome - it is not credited with a slice it never
        // received.
        let dir = temp_dir("dupid");
        let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(8);
        for (id, name, byte) in [
            ("<shared@test>", "set.vol000+01.par2", 0x11u8),
            ("<uniq-a@test>", "set.vol000+01.par2", 0x11),
            ("<uniq-b@test>", "set.vol001+02.par2", 0x22),
        ] {
            tx.send(FetchOutcome::Done {
                id: id.into(),
                raw: article(name, 4096, &vec![byte; 512]),
            })
            .await
            .unwrap();
        }
        drop(tx);
        let (failures, mut paths) = consume_volume_articles(
            rx,
            id_to_file,
            dir.clone(),
            BufPool::new(4),
            u64::MAX,
            VolumeOpen::Fresh,
        )
        .await;
        paths.sort();
        let names: Vec<String> = paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            ["set.vol000+01.par2", "set.vol001+02.par2"],
            "no mixed writer: the second volume is named from its OWN body"
        );
        assert!(
            std::fs::read(dir.join("set.vol001+02.par2"))
                .unwrap()
                .contains(&0x22),
            "and it holds its own bytes, not the first volume's"
        );
        // Codex F-02: the consumer charges only outcomes it receives,
        // and an article that was never requested produces none - so
        // the omitted count is the ONLY thing that makes the second
        // volume's shortfall visible to a caller that installs per file.
        assert_eq!(
            failures.for_file(1),
            0,
            "an unrequested article cannot come back as a failure"
        );
        assert!(
            failures.for_file(1).saturating_add(omitted_1) > 0,
            "the skipped duplicate must make the later volume incomplete"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Codex F-05 (22 Aug 2026): the consumer kept ONE fetch-wide
    /// failure count, so a caller installing per volume could not tell a
    /// volume that came back short from a whole one in the same fetch.
    /// The dropped-volume refetch therefore discarded EVERY renamed
    /// install as soon as any article anywhere failed, throwing away
    /// good bytes the demote had kept. A failed article is charged to
    /// its own file: A short by one, B clean.
    #[tokio::test]
    async fn a_failed_article_is_charged_to_its_own_volume() {
        let dir = temp_dir("attribute");
        let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(8);
        let mut id_to_file: HashMap<Arc<str>, usize> = HashMap::new();
        for (id, fi) in [
            ("<a-ok@test>", 0usize),
            ("<a-bad@test>", 0),
            ("<b-ok@test>", 1),
        ] {
            id_to_file.insert(id.into(), fi);
        }
        tx.send(FetchOutcome::Done {
            id: "<a-ok@test>".into(),
            raw: article("set.vol000+01.par2", 1024, &[0x11u8; 512]),
        })
        .await
        .unwrap();
        tx.send(FetchOutcome::Failed {
            id: "<a-bad@test>".into(),
            code: nzbkit::fail::FailCode::Transport,
            error: "transport gave up".into(),
        })
        .await
        .unwrap();
        tx.send(FetchOutcome::Done {
            id: "<b-ok@test>".into(),
            raw: article("set.vol001+02.par2", 512, &[0x22u8; 512]),
        })
        .await
        .unwrap();
        drop(tx);

        let (failures, mut paths) = consume_volume_articles(
            rx,
            id_to_file,
            dir.clone(),
            BufPool::new(4),
            u64::MAX,
            VolumeOpen::Fresh,
        )
        .await;

        assert_eq!(failures.total(), 1, "one article failed in the whole fetch");
        assert_eq!(
            failures.for_file(0),
            1,
            "and it belongs to the volume that lost it"
        );
        assert_eq!(
            failures.for_file(1),
            0,
            "the complete volume beside it must not inherit the other's failure -              a caller reading this as short throws away good bytes"
        );
        paths.sort();
        assert_eq!(paths.len(), 2, "both volumes opened a writer");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An outcome whose id is in no file's request set cannot be charged
    /// to anyone, and guessing is the destructive direction: a caller
    /// told a short volume is whole renames a sparse file over good
    /// bytes. So an unattributable failure taints EVERY file, at the
    /// cost of one refetch.
    #[tokio::test]
    async fn an_unattributable_failure_taints_every_volume() {
        let dir = temp_dir("attribute-unknown");
        let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(4);
        let mut id_to_file: HashMap<Arc<str>, usize> = HashMap::new();
        id_to_file.insert("<known@test>".into(), 0usize);
        tx.send(FetchOutcome::Done {
            id: "<known@test>".into(),
            raw: article("set.vol000+01.par2", 512, &[0x33u8; 512]),
        })
        .await
        .unwrap();
        tx.send(FetchOutcome::Missing {
            id: "<stranger@test>".into(),
            cause: nzbkit::pool::MissingCause::Gone { takedown: false },
        })
        .await
        .unwrap();
        drop(tx);

        let (failures, paths) = consume_volume_articles(
            rx,
            id_to_file,
            dir.clone(),
            BufPool::new(4),
            u64::MAX,
            VolumeOpen::Fresh,
        )
        .await;

        assert_eq!(failures.total(), 1);
        assert_eq!(
            failures.for_file(0),
            1,
            "the file that did land is still reported short"
        );
        assert_eq!(
            failures.for_file(7),
            1,
            "and so is a file the fetch never even wrote"
        );
        assert_eq!(paths.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// BUG (LOW): the writer was created with `.expect("create recovery
    /// volume")` inside the consumer task, so a volume that could not be
    /// opened - a name that sanitises to something unopenable, a full or
    /// read-only disk - panicked the task and took every OTHER volume in
    /// the same side-fetch with it. An unwritable volume is a volume we
    /// did not get, nothing more.
    #[tokio::test]
    async fn an_unwritable_recovery_volume_does_not_panic_the_consumer() {
        let dir = temp_dir("unwritable");
        // A directory sitting exactly where the volume file must go: the
        // create fails, deterministically, on every platform.
        std::fs::create_dir_all(dir.join("set.vol000+01.par2")).unwrap();
        let good = vec![0x22u8; 2048];

        let (failures, paths) = consume(
            &dir,
            vec![
                (0, article("set.vol000+01.par2", 1 << 20, &[1u8; 512])),
                // A second article for the SAME dead volume: the create
                // must not be retried per article, and it must still not
                // panic.
                (0, article("set.vol000+01.par2", 1 << 20, &[2u8; 512])),
                (1, article("set.vol001+02.par2", 2048, &good)),
            ],
            1 << 30,
        )
        .await;

        assert_eq!(
            failures.for_file(0),
            2,
            "both articles of the dead volume count as failures"
        );
        assert_eq!(
            failures.for_file(1),
            0,
            "and none of them lands on the healthy volume beside it"
        );
        assert_eq!(
            paths.len(),
            1,
            "the healthy volume of the same fetch still lands"
        );
        assert!(paths[0].ends_with("set.vol001+02.par2"));
        assert_eq!(std::fs::read(&paths[0]).unwrap(), good);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
