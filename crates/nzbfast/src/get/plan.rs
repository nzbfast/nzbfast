//! The fetch plan (TODO 106 phase 2.1, cut 7): one pass over the NZB's
//! files building the slot table, the article-id ownership map, the
//! honest-percentage byte plan, the per-slot seek ladders, the queue
//! order (par2 main first, then heads, then data with the M11 head+tail
//! burst), and the resume bookkeeping. Body is a verbatim move from the
//! orchestrator.

use crate::*;
use nzbkit::nzb::FileKind;
use nzbkit::pool::ArticleReq;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use tracing::{info, warn};

/// Everything the rest of the run needs from planning. Field names match
/// the local bindings the inline code used; the orchestrator
/// destructures them back under the same names.
pub(super) struct FetchPlan {
    pub(super) resume_sniffed_slots: Vec<usize>,
    pub(super) resume_deferred_arts: usize,
    pub(super) resume_deferred_bytes: u64,
    pub(super) resume_have_bytes: u64,
    pub(super) slots: Vec<Arc<FileSlot>>,
    /// Shared, not cloned: the map is complete when the plan returns and
    /// every consumer only reads it, so the decode fleet takes an `Arc`
    /// clone instead of a deep copy per thread (§A1). At ~110-130 B per
    /// entry a 128k-article job used to carry four to six extra copies -
    /// 75-90 MiB - for the life of the download.
    pub(super) id_to_slot: Arc<crate::unpack::IdSlots>,
    pub(super) slot_file: Vec<usize>,
    pub(super) slot_arts: Vec<(Vec<(u64, std::sync::Arc<str>)>, u64)>,
    pub(super) ids: Vec<ArticleReq>,
    pub(super) fetch_done: Arc<AtomicU64>,
}

pub(super) fn build_fetch_plan(
    nzb: &Arc<Nzb>,
    hub: &Option<Arc<StreamHub>>,
    completed: &HashSet<String>,
    resuming: bool,
    bootstrap_vol: Option<usize>,
    resume_vols: &HashMap<usize, PathBuf>,
    // The "skip sample files" setting, sampled once for this job. On, a
    // file the sample classifier recognises has NONE of its articles
    // queued - the point of the setting is that its bytes never cross
    // the wire, so the decision has to be made here and nowhere later.
    skip_samples: bool,
    // §293 plan-side adoption (TODO 305 item 2), by NZB FILE index: this
    // file's bytes are already in `out_dir`, taken whole and byte-exact
    // off a failed predecessor by `get::donor`, so NONE of its articles
    // may be queued. Empty (or all false) on every job that is not a
    // switch. Booked exactly as the resume branch below books a
    // journal-completed article, because the situation is the same one:
    // the bytes are on disk and the settle pass verifies them.
    donated: &[bool],
) -> FetchPlan {
    // Which DATA files this run will decline to fetch. Computed over the
    // whole file list up front because the answer is comparative: a
    // sample is only a sample beside something bigger, so no single file
    // can be judged on its own as the loop reaches it. PAR2 entries are
    // dropped first - recovery data is never a sample - and their slots
    // read `false` through the `is_par2` arm below.
    let sample_skip: Vec<bool> = if skip_samples {
        let data: Vec<(String, u64)> = nzb
            .files
            .iter()
            .map(|f| {
                if f.kind() == FileKind::Data {
                    (
                        f.filename_hint_lenient().unwrap_or_default().to_string(),
                        f.bytes(),
                    )
                } else {
                    (String::new(), 0)
                }
            })
            .collect();
        crate::smart::skippable_samples(&data)
    } else {
        vec![false; nzb.files.len()]
    };
    let mut resume_sniffed_slots: Vec<usize> = Vec::new();
    let mut resume_deferred_arts = 0usize;
    let mut resume_deferred_bytes = 0u64;
    // Bytes of articles this resume will SKIP because the journal already
    // has them on disk. Published on the hub below (never added into the
    // progress counter) so the queue row can pick the bar up where the
    // last run left it - see the publish site for why the two stay apart.
    let mut resume_have_bytes = 0u64;
    // What the sample skip declined, for the banner. Deliberately NOT
    // folded into `resume_deferred_*`: those seed the in-stream PAR2
    // deferral ledger, which reports itself as "recovery data not
    // downloaded", and a teaser is not recovery data.
    let mut skipped_sample_arts = 0usize;
    let mut skipped_sample_bytes = 0u64;
    let mut skipped_sample_names: Vec<String> = Vec::new();
    // What plan-side adoption struck out, for the banner. Kept apart
    // from the resume counters so the log can say which of the two it
    // was: a resumed job continues its own work, a donated one starts
    // on somebody else's bytes.
    let mut donated_arts = 0usize;
    let mut donated_bytes = 0u64;
    let mut donated_names: Vec<String> = Vec::new();
    let mut slots: Vec<Arc<FileSlot>> = Vec::new();
    let mut id_to_slot: crate::unpack::IdSlots = HashMap::new();
    // UX §15 honest percentage. `fetch_plan` is the declared NZB byte
    // size of every article this run is responsible for, `fetch_done`
    // the same measure for the ones already accounted for. Both count
    // ONE thing - declared bytes of the eager article set - so the bar
    // reaches exactly 100% when the fetch drains and can never pass it.
    //
    // The pair it replaces on the queue row could do neither: the
    // numerator was decoded payload (all slots, PAR2 included), the
    // denominator the NZB's encoded bytes minus recovery volumes. A
    // clean download therefore stopped around 97% still claiming a
    // gigabyte "left" that did not exist, and a damaged one - where the
    // extra recovery bytes land on the numerator alone - pinned at
    // 100% / 0 left with articles still in flight.
    let mut plan_bytes = 0u64;
    // Slot index → NZB file index, for the in-stream sniff and the repair
    // planner (slots skip NZB-classified volumes, so the numberings differ).
    let mut slot_file: Vec<usize> = Vec::new();
    // M11: per-slot article ladder (encoded cumulative offset → id) for
    // seek promotion; aligned with `slots` (empty for par2 slots).
    let mut slot_arts: Vec<(Vec<(u64, std::sync::Arc<str>)>, u64)> = Vec::new();
    let mut par2_ids: Vec<ArticleReq> = Vec::new();
    // Each data file's FIRST segment goes right after the par2 index:
    // the offset-0 article carries the RAR signature + headers, so the
    // extractor classifies every slot within the first round-trips instead
    // of holding gigabytes of unclassifiable spans (M3 scheduling rule).
    let mut head_ids: Vec<ArticleReq> = Vec::new();
    let mut data_ids: Vec<ArticleReq> = Vec::new();
    let mut dup_segments = 0usize;
    for (fi, f) in nzb.files.iter().enumerate() {
        // Articles inherit their file's post date; per-server retention
        // routing (M14e) keys off this age.
        let age_days = nzb_age_days(f.date);
        let is_bootstrap = bootstrap_vol == Some(fi);
        if f.kind() == FileKind::Par2Volume && !is_bootstrap {
            continue;
        }
        let is_par2_main = f.kind() == FileKind::Par2Main || is_bootstrap;
        // A bootstrap volume is recovery data by election, so it can
        // never be a skipped sample however it is named.
        let sample_skipped = sample_skip[fi] && !is_par2_main;
        // Never a par2 slot: the main index is refetched on every run
        // (activation needs its packets in memory) and a recovery volume
        // is not a recovery-set MEMBER, so nothing can have donated it.
        let file_donated = !is_par2_main && donated.get(fi).copied().unwrap_or(false);
        let idx = slots.len();
        let resume_sniffed = !is_par2_main && resume_vols.contains_key(&idx);
        if resume_sniffed {
            resume_sniffed_slots.push(idx);
        }
        slot_file.push(fi);
        // Lenient on purpose (issue #55): a poster who quotes nothing
        // still usually writes the real filename in the subject, and
        // `file{idx:03}` is what discarding it costs - every downstream
        // namer (PAR2 FileDesc aside) then has nothing to work from.
        let posted_name = f.filename_hint_lenient();
        slots.push(Arc::new(FileSlot {
            hint: posted_name
                .map(str::to_string)
                .unwrap_or_else(|| format!("file{idx:03}")),
            // GH #63: whether the subject gave a name worth defending
            // against a hash arriving later, decided HERE because the
            // placeholder above is indistinguishable from a real name
            // once it is in the string.
            hint_is_posted_name: posted_name.is_some_and(nzbkit::release::stem_is_a_name),
            name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
            is_par2_main,
            sample_skipped,
            par2_sniffed: std::sync::atomic::AtomicBool::new(resume_sniffed),
            // A parser-dropped segment (empty or wire-unsafe message-id)
            // is one this slot can never fetch: it counts toward the
            // total and starts out missing, so the file either repairs
            // through PAR2 or fails the job - it must not vanish from
            // the manifest and finish green zero-filled.
            total_segments: f.segments.len() + f.dropped_segments,
            remaining: AtomicUsize::new(f.segments.len()),
            missing: AtomicUsize::new(f.dropped_segments),
            errors: AtomicUsize::new(0),
            deferred: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(is_par2_main.then(Vec::new)),
        }));
        if sample_skipped {
            skipped_sample_names.push(slots[idx].hint.clone());
        }
        if file_donated {
            donated_names.push(slots[idx].hint.clone());
        }
        let mut arts: Vec<(u64, std::sync::Arc<str>)> = Vec::new();
        let mut enc_cum = 0u64;
        for (si, seg) in f.segments.iter().enumerate() {
            // R9: the run's ONE heap copy of this bracketed id. Every
            // later holder - `id_to_slot`, the seek ladder, the pool's
            // queue item and its in-flight/steer maps, the outcome the
            // decode consumer receives - takes a handle to this
            // allocation, so an id costs one `format!` per run instead
            // of the six to nine copies the plain `String` cost.
            // `Segment.message_id` stays an unbracketed `String` inside
            // the retained `Arc<Nzb>`: nothing downstream points into
            // the manifest, so dropping payload segments from it stays
            // a separate, independent win.
            let bracketed: std::sync::Arc<str> = format!("<{}>", seg.message_id).into();
            // Malformed NZBs repeat a message-id, within one file or across
            // two. The pool fetches each id exactly once (a second request
            // would never turn terminal - the duplicate-id forever-hang),
            // so a repeat is settled here: the FIRST occurrence owns the
            // article. A same-file repeat is covered by that one fetch
            // (yEnc offsets come from the article, not the NZB); a
            // cross-file repeat means these bytes never reach THIS file -
            // count it missing and let PAR2 repair fill the hole.
            if let Some(&(owner, _)) = id_to_slot.get(&*bracketed) {
                dup_segments += 1;
                slots[idx].remaining.fetch_sub(1, Ordering::Relaxed);
                if owner as usize != idx {
                    slots[idx].missing.fetch_add(1, Ordering::Relaxed);
                }
                enc_cum = enc_cum.saturating_add(seg.bytes);
                continue;
            }
            id_to_slot.insert(bracketed.clone(), (idx as u32, seg.bytes));
            // Every article with an owner is this run's responsibility -
            // including the ones already satisfied below, which are added
            // to `have_bytes` as well so a resumed job's bar starts where
            // its bytes actually are instead of at zero. A duplicate id
            // (the `continue` above) is fetched once under its first
            // owner and never counted twice; a segment the parser dropped
            // has no entry at all and so cannot hold the bar short of
            // 100%.
            // Saturating sums, like Nzb::total_bytes: `bytes` is an
            // attacker-typed u64 straight from the NZB, and a plain sum
            // panics in debug and wraps in release on absurd claims.
            plan_bytes = plan_bytes.saturating_add(seg.bytes);
            if !is_par2_main {
                arts.push((enc_cum, bracketed.clone()));
            }
            enc_cum = enc_cum.saturating_add(seg.bytes);
            // The sample skip, ahead of the resume and sniff branches
            // because it is a decision about the FILE rather than about
            // this article: a job resumed after the setting was turned
            // on must stop fetching the rest of the teaser, not finish
            // it because some of it is already down.
            //
            // Booked exactly as a resume-recognised recovery volume is -
            // off `remaining`, onto `deferred` - so every consumer that
            // already knows "deferred is a choice, not damage" needs no
            // teaching: the census's completeness walk sees zero missing
            // and zero unresolved, its size-lie scan sits the slot out,
            // and settle's uncovered-hole partition never picks it up.
            if sample_skipped {
                slots[idx].remaining.fetch_sub(1, Ordering::Relaxed);
                slots[idx].deferred.fetch_add(1, Ordering::Relaxed);
                skipped_sample_arts += 1;
                skipped_sample_bytes = skipped_sample_bytes.saturating_add(seg.bytes);
                continue;
            }
            // §293: the whole file came off a donor. Same booking as
            // the resume branch under it and for the same reason - the
            // bytes are on disk and the settle pass verifies them - but
            // ahead of it, because this is a decision about the FILE:
            // there is no article of a donated file worth fetching, and
            // a switch job's journal knows nothing about any of them.
            if file_donated {
                slots[idx].remaining.fetch_sub(1, Ordering::Relaxed);
                resume_have_bytes = resume_have_bytes.saturating_add(seg.bytes);
                donated_arts += 1;
                donated_bytes = donated_bytes.saturating_add(seg.bytes);
                continue;
            }
            // On resume, journal-completed data articles are skipped -
            // their bytes are on disk and the settle pass verifies them.
            // Par2-main articles always refetch (tiny; activation needs
            // the packets in memory).
            if !is_par2_main && completed.contains(&*bracketed) {
                slots[idx].remaining.fetch_sub(1, Ordering::Relaxed);
                resume_have_bytes = resume_have_bytes.saturating_add(seg.bytes);
                continue;
            }
            // A resume-recognised recovery volume: everything not already
            // on disk is deferred outright - never queued.
            if resume_sniffed {
                slots[idx].remaining.fetch_sub(1, Ordering::Relaxed);
                slots[idx].deferred.fetch_add(1, Ordering::Relaxed);
                resume_deferred_arts += 1;
                resume_deferred_bytes = resume_deferred_bytes.saturating_add(seg.bytes);
                continue;
            }
            let req = ArticleReq {
                id: bracketed,
                age_days,
                // Segment number = expected yEnc part; the CRC-retry
                // gate uses it to spot a valid-but-wrong body.
                part: seg.number,
                file: idx as u32,
            };
            if is_par2_main {
                par2_ids.push(req);
            } else if si == 0 {
                head_ids.push(req);
            } else {
                data_ids.push(req);
            }
        }
        slot_arts.push((arts, enc_cum));
    }
    if dup_segments > 0 {
        warn!(target: "get", "NZB repeats {dup_segments} segment id(s) - each article is fetched once");
    }
    // Publish the fetch plan before the first article can land. The
    // daemon zeroed both counters at the Downloading transition, and the
    // queue payload treats a zero plan as "not ready yet" and falls back
    // to the old arithmetic, so the window between the two is covered.
    // `fetch_done` is the local handle either way: a CLI run has no hub
    // and pays one uncontended atomic add per terminal article.
    let counters = hub.as_ref().map(|h| h.fetch_counters());
    let fetch_done = counters
        .as_ref()
        .map(|c| c.done.clone())
        .unwrap_or_default();
    if donated_arts > 0 {
        info!(
            target: "repair",
            "plan-side adoption: {} file(s) already on disk from the predecessor - {} article(s), {:.1} MB will not be fetched: {}",
            donated_names.len(),
            donated_arts,
            donated_bytes as f64 / 1e6,
            donated_names.join(", ")
        );
    }
    if skipped_sample_arts > 0 {
        info!(
            target: "get",
            "skipping {} sample file(s) - {} article(s), {:.1} MB never fetched: {}",
            skipped_sample_names.len(),
            skipped_sample_arts,
            skipped_sample_bytes as f64 / 1e6,
            skipped_sample_names.join(", ")
        );
    }
    // Seeded with what is in hand before a byte moves: the articles the
    // journal already satisfied, plus the recovery volumes a resume
    // recognised on disk and deliberately never queued, plus the samples
    // this run has decided not to fetch at all. All three are bytes of
    // the plan this run is responsible for, so a resumed job's bar
    // continues from where it stopped instead of restarting at 0% - and
    // no terminal outcome will ever credit a skipped article back, so
    // without the third the percentage and the SAB-compatible
    // `Remaining` would sit short by the sample for the whole job.
    fetch_done.store(
        resume_have_bytes
            .saturating_add(resume_deferred_bytes)
            .saturating_add(skipped_sample_bytes),
        Ordering::Relaxed,
    );
    if let Some(h) = hub.as_ref() {
        if let Some(c) = &counters {
            c.plan.store(plan_bytes, Ordering::Relaxed);
        }
        // §129 4b: the post's own age, for the LIVE verdict. The
        // youngest article is the newest date in the set, and the whole
        // set has to be dated for the answer to mean anything - an NZB
        // with one undated file is exactly the case `take_census`
        // resolves to "age 0, do not call this gone", so it reaches the
        // live surface as 0 = unknown rather than as a date derived from
        // the files that happened to carry one.
        h.post_unix.store(
            match nzb.files.iter().all(|f| f.date > 0) {
                true => nzb.files.iter().map(|f| f.date).max().unwrap_or(0),
                false => 0,
            },
            Ordering::Relaxed,
        );
    }
    // M11 head+tail burst (hub-attached runs, i.e. the daemon): the first
    // volume's opening ~16 MB and the last volume's closing ~8 MB jump the
    // data queue, so a media player gets the container header AND the
    // end-of-file seek index (MKV Cues / MP4 moov both live at the end)
    // within seconds of queue-add. These are ordinary file bytes - nothing
    // is wasted if nobody ever streams.
    if hub.is_some() {
        let mut data_slots: Vec<usize> = slots
            .iter()
            .enumerate()
            // A skipped sample has no queued articles, so letting it
            // win "first" or "last" here would spend the burst on
            // nothing and leave the real opening volume unprioritised.
            .filter(|(_, s)| !s.is_par2_main && !s.sample_skipped)
            .map(|(i, _)| i)
            .collect();
        data_slots.sort_by_key(|&i| nzbkit::extract::vol_sort_key(&slots[i].hint));
        let mut burst: std::collections::HashSet<&str> = Default::default();
        if let Some(&first) = data_slots.first() {
            for (off, id) in &slot_arts[first].0 {
                if *off >= 16_000_000 {
                    break;
                }
                burst.insert(&**id);
            }
        }
        if let Some(&last) = data_slots.last() {
            let (arts, total) = &slot_arts[last];
            for (off, id) in arts.iter().rev() {
                if off + 8_000_000 <= *total {
                    break;
                }
                burst.insert(&**id);
            }
        }
        if !burst.is_empty() {
            let (mut early, rest): (Vec<_>, Vec<_>) =
                data_ids.into_iter().partition(|r| burst.contains(&*r.id));
            early.extend(rest);
            data_ids = early;
        }
    }
    let mut ids = par2_ids;
    ids.extend(head_ids);
    ids.extend(data_ids);
    // Memory-floor gauge (instrument-first): the plan's whole-job
    // per-segment metadata, ESTIMATED from the structures' fixed costs.
    // Per unique id: the one interned Arc<str> heap allocation (len + a
    // 16 B Arc header), its id_to_slot entry (~48 B with hashbrown
    // overhead), the manifest's unbracketed String copy (~len + 24 B),
    // the seek ladder handle (24 B) and the pool's queued Work (~56 B).
    // The r9_plan_rss ignored test measured ~9.4 MB per 100k segments
    // for the plan's three holders; this estimate is the same order and
    // exists so the summary can NAME the term rather than price it
    // exactly.
    {
        let id_heap: u64 = id_to_slot.keys().map(|k| k.len() as u64 + 16).sum();
        let per_entry = (id_to_slot.len() as u64) * (48 + 24 + 24 + 56);
        nzbkit::memgauge::set_at_least(nzbkit::memgauge::Sub::JobMeta, id_heap * 2 + per_entry);
    }
    if resuming {
        info!(
            target: "resume",
            "{} article(s) already on disk, {} to fetch",
            completed.len(),
            ids.len()
        );
    }
    FetchPlan {
        resume_sniffed_slots,
        resume_deferred_arts,
        resume_deferred_bytes,
        resume_have_bytes,
        slots,
        id_to_slot: Arc::new(id_to_slot),
        slot_file,
        slot_arts,
        ids,
        fetch_done,
    }
}

/// Everything read and resolved before a byte moves: the server pool
/// (filtered and oracle-routed), the parsed NZB, the archive password
/// in priority order, and the crash-resume journal state. Field names
/// match the local bindings the inline code used.
pub(super) struct Intake {
    pub(super) cfg_all: Config,
    pub(super) nzb: Arc<Nzb>,
    pub(super) job_family: String,
    pub(super) job_posted: Option<i64>,
    pub(super) password: Option<String>,
    pub(super) journal: Arc<nzbkit::journal::Journal>,
    /// Resume seeds only: `build_intake` MOVES `restored.ids` into
    /// `completed`, so this arrives with an empty id set. Every consumer
    /// (rig.rs, tail.rs) reads `.seeds`; ask `completed` for the ids.
    pub(super) restored: nzbkit::journal::Restored,
    /// The resume id set, read once by `build_fetch_plan` and dropped
    /// immediately after - never held across the fetch.
    pub(super) completed: HashSet<String>,
    pub(super) resuming: bool,
    pub(super) has_main: bool,
    pub(super) bootstrap_vol: Option<usize>,
    pub(super) resume_vols: HashMap<usize, PathBuf>,
    /// §94 A: does this run replay its restored spans through the
    /// one-pass path? Decided in `build_intake` because the restore
    /// itself depends on it - see `resume_map_admitted`.
    pub(super) resume_map: bool,
    /// TODO 309: the same decision as `resume_map`, with the figures the
    /// gate weighed, for the daemon to put on the job's download report.
    /// `None` where the gate had nothing to weigh - a fresh run, or a
    /// resumed compressed set, whose journal describes no bytes on disk.
    /// Purely reportorial: nothing in the engine reads it.
    pub(super) resume_route: Option<crate::streamhub::ResumeRoute>,
    /// The journal state the restore above was built FROM, kept for one
    /// consumer: a §293 donation lands after this intake and forces the
    /// run off the mapped shape, and the restore then has to be re-run
    /// MATERIALISING - the map-shape restore wrote no volume bytes, and
    /// the adopt path hands every restored seed to the extractor as
    /// spans sitting in the volume files. `completed` has already been
    /// moved out of it (`restore_for` never reads that field); `get()`
    /// drops this right after the donation step.
    pub(super) resume_state: nzbkit::journal::ResumeState,
}

/// M29 routing: sink every predicted-gone server to one tier below the
/// config's deepest level, so it is asked only after every server the
/// ledger has NOT written off has already 430'd the article.
///
/// Demotion, not removal (14 Aug 2026). Removal made a wrong verdict cost
/// the download: a Star Trek job lost 4 of its 6 providers and died with
/// "5019 of 14986 segment(s) never arrived", while direct STAT showed 12
/// other releases in the very same (hdtv, bucket 2) cell were 36/36
/// available on five of those providers - a ~92% false-skip rate, because
/// the ledger counts ARTICLES and one doomed release supplies ~15,000
/// perfectly correlated ones. A level bump buys back two properties:
///
/// - A wrong verdict costs only latency again. `required_mask`
///   (nzbkit::pool) hands a level-N server the article once every live
///   lower-level server has missed it, so nothing becomes unreachable.
///   "Missed" has to mean more than a 430 for that to hold: a primary
///   that resets or stalls on one article answers no question and files
///   no refusal, so the gate also opens for a server that has spent its
///   whole retry budget on the article (`Shared::spent`, M5). Without
///   that, a demoted-but-healthy server watched the article die on a
///   server that could not fetch it.
/// - The red cell can heal. `OracleSink` binds to the POOL's servers
///   (see fleet.rs), so a REMOVED server recorded neither hits nor
///   misses: the only healer left was the idle STAT sampler at 5
///   STAT/min/server, needing ~82,000 hits to clear one poisoned cell.
///   A demoted server keeps recording, and real download traffic drains
///   the absorbing state for free.
///
/// The accepted cost is the pipelined 430s the skip used to avoid on
/// genuinely doomed content, now paid at the end of the ladder.
///
/// There is deliberately no "only if at least one server survives" guard.
/// It counted SERVERS while verdicts are per BACKBONE - 3 Highwinds
/// mirrors plus 1 Abavia passes it and drops 3 of 4 - and it is
/// redundant here:
/// if every server is predicted gone they all land on the SAME new level,
/// every `required_mask` is empty, and the run is exactly what it would
/// have been with no verdict at all.
fn demote_predicted_gone(servers: &mut [ServerConfig], gone: &[String], family: &str, age: u32) {
    if gone.is_empty() {
        return;
    }
    // Computed over ALL servers before any mutation, so a config that
    // already has fill tiers keeps them strictly ahead of the demoted set.
    let Some(sunk) = servers
        .iter()
        .map(|s| s.level)
        .max()
        .map(|m| m.saturating_add(1))
    else {
        return;
    };
    for s in servers.iter_mut().filter(|s| gone.contains(&s.host)) {
        info!(
            target: "oracle",
            "{} predicted gone for {family} (age {age}d) - demoted to level {sunk}, it is asked only after every other server has missed",
            s.host
        );
        s.level = sunk;
    }
}

pub(super) fn build_intake(
    config: &Path,
    nzb_path: &Path,
    out_dir: &Path,
    password: Option<String>,
    no_extract: bool,
    hub: &Option<Arc<StreamHub>>,
) -> Result<Intake> {
    // This pre-header stretch (config read, NZB read+parse, journal
    // open/restore) is synchronous disk and CPU work on the caller's
    // tokio worker - on a big resumed job the journal restore alone
    // copies substantial data. Each leg runs under blocking_db so the
    // worker is demoted for the duration (inline off the runtime, e.g.
    // the CLI path).
    let mut cfg_all = crate::persist::blocking_db(|| Config::load(config))?;
    // Which servers were taken OUT of the pool, and why. Only ever read
    // when the pool ends up empty: "no usable servers" named nothing at
    // all, so the one failure whose cause is entirely inside the user's
    // own settings was also the one that said least about itself.
    let mut sidelined: Vec<String> = Vec::new();
    // Soft-disabled servers never join a pool.
    cfg_all.servers.retain(|s| {
        if !s.enabled {
            info!(target: "config", "{} disabled - not in the pool", s.host);
            sidelined.push(format!("{} (switched off)", s.host));
        }
        s.enabled
    });
    // Exhausted block accounts (daemon-computed): out of the pool.
    if let Some(h) = &hub {
        let excluded = h.excluded_hosts.lock_ok().clone();
        if !excluded.is_empty() {
            cfg_all.servers.retain(|s| {
                let keep = !excluded.contains(&s.host);
                if !keep {
                    // The exclusion list carries three different reasons
                    // (busy with the active job, auth-refused, or a spent
                    // block account) - saying "exhausted" for all of them
                    // sent a bench investigation chasing a phantom quota
                    // bug, so say what it means.
                    info!(
                        target: "block",
                        "{} excluded for this download (busy with the active job, refused, or block-exhausted)",
                        s.host
                    );
                    sidelined
                        .push(format!("{} (busy, refused the login, or out of block data)", s.host));
                }
                keep
            });
        }
    }
    if cfg_all.servers.is_empty() {
        // Opens with the same four words either way: `fail_hint` keys the
        // dashboard's "open Server settings" button on that prefix.
        if sidelined.is_empty() {
            anyhow::bail!(
                "no usable servers: none are set up yet - add your provider in Server settings"
            );
        }
        anyhow::bail!(
            "no usable servers: every one you have set up is out of the pool right now - {}",
            sidelined.join(", ")
        );
    }
    let xml = crate::persist::blocking_db(|| std::fs::read(nzb_path))
        .with_context(|| format!("reading {}", nzb_path.display()))?;
    // Arc'd because the in-stream PAR2 sniff (issue #14) needs the file
    // list on the decode threads, which outlive this scope's borrows.
    // Parsing is CPU-bound and scales with the segment count - a large
    // NZB is worth demoting for too.
    let nzb = Arc::new(crate::persist::blocking_db(|| Nzb::parse(&xml)).context("parsing NZB")?);

    // The release's dominant group family - one NZB ≈ one family. Used
    // both for the oracle routing gate below and the ledger sink context.
    let job_family = {
        let mut freq: HashMap<&str, usize> = HashMap::new();
        for f in &nzb.files {
            for g in &f.groups {
                *freq.entry(g.as_str()).or_default() += 1;
            }
        }
        freq.into_iter()
            .max_by_key(|(_, n)| *n)
            .map(|(g, _)| nzbkit::oracle::group_family(g))
            .unwrap_or_else(|| "misc".into())
    };
    // Newest article post date, or None when the release is fully undated.
    // Undated jobs carry no usable age, so the oracle IGNORES them entirely
    // (no routing verdict, no ledger recording): an undated outcome would
    // otherwise mis-file as bucket 0 ("fresh") for the writer but read back
    // as bucket 6 ("3y+") on every read - a split-brain that can even
    // false-flag an undated retention-expired family as "being reaped".
    let job_posted: Option<i64> = nzb
        .files
        .iter()
        .filter_map(|f| (f.date > 0).then_some(f.date))
        .max();

    // M29 opt-in routing (`oracle_route`, OFF unless the daemon installed
    // a snapshot): DEMOTE enabled servers whose backbone the availability
    // ledger is confident is GONE for this release's (family, age-bucket),
    // so the doomed round-trips on takedown'd content are paid at the END
    // of the ladder instead of the front. Guarded two ways: needs an
    // installed snapshot, and needs a real post date to pick an age
    // bucket.
    if let Some(snap) = hub.as_ref().and_then(|h| h.route_gone.lock_ok().clone())
        && let Some(date) = job_posted
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        let age = ((now - date).max(0) / 86_400) as u32;
        let gone: Vec<String> = cfg_all
            .servers
            .iter()
            .filter(|s| snap.backbone_gone(&nzbkit::oracle::backbone_of(&s.host), &job_family, age))
            .map(|s| s.host.clone())
            .collect();
        demote_predicted_gone(&mut cfg_all.servers, &gone, &job_family, age);
    }

    // Archive password, in priority order: explicit > NZB meta > filename
    // convention. Only consulted if the set turns out to be encrypted.
    let password: Option<String> = match password {
        Some(p) => {
            info!(target: "password", "using supplied archive password");
            Some(p)
        }
        None => {
            if let Some(p) = nzb.password() {
                info!(target: "password", "NZB carries an archive password (meta)");
                Some(p.to_string())
            } else if let Some(p) = braces_password(nzb_path) {
                info!(target: "password", "archive password taken from {{{{…}}}} in the NZB filename");
                Some(p)
            } else {
                None
            }
        }
    };

    // Crash-resume journal: completed articles from a previous run of this
    // exact NZB are already on disk - at final offsets in their own file
    // (v1 lines) or at journal-recorded placements (direct-extracted
    // spans), which the restore pass copies back into volume files now.
    // A previous attempt that FAILED renamed its unverified payload out
    // of the way (see quarantine_partials). Put the names back first:
    // the placement records below address fragments by their offsets
    // inside those files, so a resume that ran with the suffix still on
    // would refetch every direct-extracted article instead of copying it
    // off the local disk. Before Journal::open, so nothing in the resume
    // path ever sees the quarantined name.
    for name in nzbkit::journal::unquarantine_partials(out_dir) {
        info!(target: "resume", "{name}: restoring the previous attempt's partial for resume");
    }
    let (journal, mut resume_state) =
        crate::persist::blocking_db(|| nzbkit::journal::Journal::open(out_dir, &xml))?;
    let journal = Arc::new(journal);
    // §94 A: the resume-mapping decision has to be made HERE, before
    // the restore, not later in build_rig - because what it decides is
    // whether the restore materialises volume files at all. A run that
    // is going to replay the placements straight out of the outputs
    // they already sit in must not have them copied into volumes first;
    // that copy plus the read-back was a full extra pass over the
    // resumed fraction.
    //
    // The byte count is the journal's own upper bound (every fragment
    // of every placement record, before any of them are admitted), so
    // the gate reads pessimistically, which is the right direction: it
    // decides whether the replay can be held in RAM without breaching
    // the held-span cap, and a set that cannot afford it takes the
    // ordinary materialize-and-extract path instead of mapping, filling
    // the cap and paying for the demote on top.
    let (resume_map, resume_route) = resume_map_admitted(
        &resume_state,
        out_dir,
        no_extract,
        nzbkit::mem::process_budget(),
    );
    // Plaintext-once (`D`) records re-encrypt through the password; with
    // no password those articles refetch instead - never guessed.
    let mut restored = crate::persist::blocking_db(|| {
        nzbkit::journal::restore_for(out_dir, &resume_state, password.as_deref(), !resume_map)
    });
    // Taken rather than moved: `resume_state` rides the Intake so a
    // donation can re-run the restore materialising (see the field's
    // doc), and `restore_for` never reads `completed`.
    let mut completed = std::mem::take(&mut resume_state.completed);
    if !restored.ids.is_empty() {
        let moved: u64 = restored
            .seeds
            .iter()
            .flat_map(|s| s.spans.iter().map(|&(_, l)| l))
            .sum();
        info!(
            target: "resume",
            "restored {} article(s) ({:.1} MB) from previous run's output files",
            restored.ids.len(),
            moved as f64 / 1e6
        );
        // Move the ids in rather than cloning each one: the set is dead to
        // `restored` after this (every later consumer - rig.rs, tail.rs -
        // reads only `.seeds`), and a clone would hold a full second copy
        // of every restored id alive for the whole run. The len() above is
        // read BEFORE the take, so the banner is unchanged.
        completed.extend(std::mem::take(&mut restored.ids));
    }
    // TODO 309(b), 28 Aug 2026. The restore is allowed to refuse an
    // article whose bytes are not where the journal says - that is the
    // safe answer and the article simply refetches. What it was not
    // allowed to do is refuse it in SILENCE, which is what it did: the
    // banner above reports what was restored, so a job whose partial
    // output had been moved, truncated or deleted by something outside
    // nzbfast between the pause and the unpause resumed looking exactly
    // like an ordinary resume, one with fewer articles on disk. The
    // bytes went back on the wire and nothing named the reason.
    //
    // Two lines rather than one because the two causes are answered
    // differently by whoever reads them: the first is a question about
    // this machine's disk, the second is a question about the password.
    if restored.dropped_source.0 > 0 {
        warn!(
            target: "resume",
            "{} article(s) ({:.1} MB) were recorded on disk by the previous run but their \
             bytes are no longer there - the file was moved, shortened or deleted since, so \
             they are fetched from the wire again",
            restored.dropped_source.0,
            restored.dropped_source.1 as f64 / 1e6
        );
    }
    if restored.dropped_crypto > 0 {
        warn!(
            target: "resume",
            "{} article(s) recorded on disk cannot be restored without the archive password \
             the previous run used - they are fetched from the wire again",
            restored.dropped_crypto
        );
    }
    // Computed while `completed` is still whole - `get()` drops it as soon
    // as the fetch plan is built.
    let resuming = !completed.is_empty();

    // Eager set: everything except PAR2 recovery volumes (minimality layer 1).
    // Par2-main segments go FIRST in the queue so the recovery set activates
    // within the first round-trips and verification runs in-stream.
    //
    // Obfuscated posts often ship recovery volumes but no plain `.par2`
    // index. The critical packets (Main/FileDesc/IFSC) are duplicated in
    // every volume, so bootstrap the set from the smallest volume instead -
    // its recovery slices also count toward any later repair.
    let has_main = nzb.files.iter().any(|f| f.kind() == FileKind::Par2Main);
    // `par2_seed_file` answers "cheapest file whose head carries the
    // critical packets", which with no index in the NZB IS the smallest
    // volume. Shared with `nzbfast check`, which asks the same question
    // to find the set's block size (nzb.rs).
    let bootstrap_vol: Option<usize> = if has_main { None } else { nzb.par2_seed_file() };
    if let Some(bi) = bootstrap_vol {
        info!(
            target: "par2",
            "no main .par2 in NZB - bootstrapping set from smallest volume ({:.1} MB)",
            nzb.files[bi].bytes() as f64 / 1e6
        );
    }
    // Issue #14 on resume: a journal-completed head article never
    // re-decodes, so the in-stream sniff cannot fire for it - but its
    // bytes are on disk (restore() just wrote them), so classify restored
    // slots by reading the first bytes of their files instead. Slots
    // recognised here are deferred AT BUILD TIME (their unfetched
    // articles never enter the queue) and never elected bootstrap: a
    // resumed run settles and repairs from disk anyway, and an on-disk
    // volume needs no capture.
    let resume_vols: HashMap<usize, PathBuf> = crate::persist::blocking_db(|| {
        restored
            .seeds
            .iter()
            .filter(|s| s.spans.iter().any(|&(o, l)| o == 0 && l >= 8))
            .filter_map(|s| {
                use std::io::Read;
                let p = out_dir.join(&s.name);
                let mut buf = [0u8; 8];
                (std::fs::File::open(&p)
                    .and_then(|mut f| f.read_exact(&mut buf))
                    .is_ok()
                    && &buf == nzbkit::par2::MAGIC)
                    .then_some((s.slot, p))
            })
            .collect()
    });
    Ok(Intake {
        cfg_all,
        nzb,
        job_family,
        job_posted,
        password,
        journal,
        restored,
        completed,
        resuming,
        has_main,
        bootstrap_vol,
        resume_vols,
        resume_map,
        resume_route,
        resume_state,
    })
}

/// §94 A's admission gate, and the one place the answer is computed -
/// `build_intake` needs it before the restore and `build_rig` needs the
/// same answer afterwards, so it is decided once and carried on
/// [`Intake`].
///
/// Map a resumed job in-stream unless the restored bytes cannot fit the
/// held-span cap. A resumed run that maps and then breaches that cap
/// pays for the attempt AND for the demote - it writes the replay into
/// the output, materializes every volume, and runs the disk unpack on
/// top, measured at 3.84x payload on a 512 MB budget against 2.59x for
/// never having mapped at all. Declining up front lands it on exactly
/// the path it would have taken before §94 A existed.
///
/// The estimate is deliberately the pessimistic one: every fragment of
/// every placement record, before `restore` decides which articles are
/// actually admissible, and against the whole cap rather than the ~40%
/// of the replay that is held at the peak in practice.
///
/// **The total is not the only way in, since TODO 309(a) (27 Aug 2026),
/// and the reason is measured.** A job that cannot fit its whole restored
/// set under the cap can still fit what the replay will actually HOLD,
/// and those are different quantities by up to 200x. See
/// [`resume_map_admits`] for the rule and the ladder behind it.
///
/// Returns the decision, and beside it the [`crate::streamhub::ResumeRoute`]
/// the daemon puts on the job's download report (TODO 309). The second
/// half is reportorial only - nothing in the engine reads it, and it is
/// `None` wherever the gate had nothing to weigh.
///
/// `budget` is passed in rather than read from
/// [`nzbkit::mem::process_budget`] here, so the gate can be driven both
/// ways over a real journal from a test without moving a process-global
/// static (which two tests sharing it would then read out of each
/// other). The one production caller passes exactly what this used to
/// read, so the decision is unchanged.
fn resume_map_admitted(
    resume: &nzbkit::journal::ResumeState,
    out_dir: &Path,
    no_extract: bool,
    budget: nzbkit::mem::MemBudget,
) -> (bool, Option<crate::streamhub::ResumeRoute>) {
    // The two overrides answer FIRST and report NOTHING, and the order
    // is deliberate rather than incidental. It keeps the decision itself
    // byte-identical to what it was before this returned a route at all
    // - `resume_map` also selects `restore_for`'s materialize flag, so a
    // reordering that let a v1-form journal (placements empty, articles
    // trusted in place) take a different early answer under `no_extract`
    // would be a real behaviour change made for a report line. And
    // neither override has a route worth reporting: `no_extract` is the
    // retention-insurance banking run, which never unpacks anything, so
    // "unpacked from volumes on disk" would be flatly wrong for it, and
    // the kill switch is a developer override whose reader already knows
    // they set it.
    if no_extract || std::env::var("NZBFAST_NO_RESUME_MAP").is_ok_and(|v| v == "1") {
        return (false, None);
    }
    let restored_bytes = resume.placement_bytes();
    if restored_bytes == 0 {
        // Nothing to replay: either a fresh run or a v1-form journal
        // whose articles are all trusted in place. `resume_map` still
        // says "map this run" - there is simply no replay to do, and no
        // route to report either, which is what keeps a non-resumed
        // job's download report unchanged. A resumed COMPRESSED set
        // lands here too: its output bytes are decoded bytes, so no
        // fragment can be described as sitting on disk (TODO 309(b)).
        //
        // That second shape is the one worth a sentence (TODO 309(b)'s
        // warning half): a previous attempt exists - the journal has
        // records - yet shields no placed payload, so its wire spend is
        // spent again. Measured 27 Aug 2026 (RESUME-ONEPASS-EDGES
        // section 7.5): a 2.1 GB compressed set SIGKILLed mid-run
        // leaves a 72-byte journal and the rerun refetches 100% of the
        // set. The sentence names what IS shielded, so it stays true
        // for the other record-bearing shape that lands here, a v1-form
        // journal whose completed articles are all trusted in place.
        if !resume.completed.is_empty() {
            info!(
                target: "resume",
                "the previous attempt's journal shields {} article(s) and no placed \
                 payload - a set that unpacks as it downloads leaves nothing on disk \
                 for a resume to pick up, so everything else it fetched is fetched \
                 from the wire again",
                resume.completed.len()
            );
        }
        return (true, None);
    }
    let cap = budget.holds_cap() as u64;
    // What a budget joining the daemon's ledger right now would keep of
    // that cap. `None` for `nzbfast get`, the repair path and the unit
    // tests, which install no ledger and see the raw cap - so a CLI leg
    // is byte-identical to reading `holds_cap()` directly. The TOTAL arm
    // deliberately keeps reading the RAW cap, so every job this gate
    // admitted before TODO 309(a) is still admitted on the same terms;
    // only the new volume arm spends the remainder.
    let seatable = nzbkit::extract::process_ledger()
        .map_or(cap, |l| cap.saturating_sub(l.live_bytes() as u64));
    let route = crate::streamhub::ResumeRoute {
        mapped: resume_map_admits(restored_bytes, resume.largest_slot_bytes(), cap, seatable),
        restored_bytes,
        budget_bytes: cap,
        widest_slot_bytes: resume.largest_slot_bytes(),
        seatable_bytes: seatable,
    };
    if route.mapped {
        return (true, Some(route));
    }
    // TODO 309(d): the cost is named, not merely the decision. This line
    // and the demotion watchdog's `defer_reason` clause
    // (`serve/tasks/stall.rs`) are the two ends of the same fact - one
    // says a requeue WILL be expensive, this one says a rerun IS - and
    // before they existed a job could take this route with nothing
    // anywhere saying what it had cost.
    info!(
        target: "resume",
        "{:.1} MB restored over the {:.1} MB held-span budget, and its widest volume ({:.1} MB) does not fit {RESUME_MAP_VOLUME_MARGIN}x into the {:.1} MB a new pipeline could seat - extracting from volumes on disk rather than mapping in-stream (TODO 94 A: 2.53x payload of device I/O against 1.02x)",
        restored_bytes as f64 / 1e6,
        cap as f64 / 1e6,
        resume.largest_slot_bytes() as f64 / 1e6,
        seatable as f64 / 1e6
    );
    let _ = out_dir;
    (false, Some(route))
}

/// How many times the widest replayed volume must fit the holds budget
/// before the volume arm of [`resume_map_admits`] will spend it.
///
/// Measured, not chosen. On the F4 rig (4.000 GiB store RAR5 set,
/// SIGKILL at ~0.51, resume under one device counter) the mapped route
/// beats the disk route until the budget drops to about ONE volume, and
/// then loses:
///
/// | volumes | budget | budget / volume | mapped | declined |
/// | --- | --- | ---: | --- | --- |
/// | 256 MB | 1930 MB | 7.5 | **1.02-1.04** | 2.53-2.54 |
/// | 256 MB | 970 MB | 3.8 | **1.03-1.03** | 2.53 |
/// | 256 MB | 500 MB | 1.95 | **1.03-1.20** | 2.53-2.56 |
/// | 256 MB | 400 MB | 1.56 | **1.03-1.37** | - |
/// | 256 MB | 300 MB | 1.17 | **1.03-1.28** | - |
/// | 256 MB | 250 MB | 0.98 | 1.06 / **2.89** / **3.00** | 2.54-2.55 |
/// | 64 MB | 250 MB | 3.9 | **1.06-1.10** | 2.55-2.56 |
/// | 64 MB | 50 MB | 0.78 | 1.04 / **2.99** / **2.99** | 2.54 |
///
/// Two volume sizes, the same crossover in `budget / volume` and not in
/// `budget / restored`, which is what makes this a margin on the VOLUME.
/// A margin of 2 sits a full octave above the highest budget that ever
/// lost (0.98) and one step above the lowest that won (1.17), and the
/// rows at 1.17 and 1.56 are why it is not 4: they win, so 2 is already
/// conservative rather than merely safe.
const RESUME_MAP_VOLUME_MARGIN: u64 = 2;

/// TODO 94 A's admission rule, as a pure function so the decision is
/// testable without a journal on disk.
///
/// `cap` is the raw holds budget and `seatable` what a pipeline joining
/// the process ledger now would keep of it (equal to `cap` outside the
/// daemon). Two independent ways in:
///
/// 1. **The total fits.** Unchanged since TODO 94 A, and read against the
///    RAW cap so nothing this gate used to admit stops being admitted.
/// 2. **The widest volume fits [`RESUME_MAP_VOLUME_MARGIN`] times over.**
///    TODO 309(a). The replay's held bytes track ONE VOLUME, not the
///    total: at a fixed ~2.1 GB replayed over 48 F4 legs the peak went
///    from 9 MB at 32 MB volumes to 1782 MB at 256 MB volumes, a 200x
///    spread in a number arm 1 sees as constant. That is what the
///    per-slot deferral predicts - `rig.rs ReplayPending::try_drain`
///    feeds a slot only once `slot_can_place` says its bytes will be
///    placed - so what can be resident is bounded by the volumes that
///    cannot yet place, and never by how much was restored in total.
///    This arm reads `seatable` because it is the one spending headroom
///    the gate has not got a seat for yet.
///
/// The arm is a UNION and not a replacement, which is what makes it
/// never-worse by construction: it can only turn a decline into an
/// admission, and every admission it adds was measured on the rig at
/// 1.02-1.37x payload of device I/O against the 2.53x the decline costs.
/// The one place the mapped route is worse - a budget under one volume -
/// is the place the margin refuses.
///
/// `pub(crate)` for exactly one second reader: the demotion watchdog's
/// `requeue_cost` (`serve/tasks/stall.rs`), which predicts this gate's
/// answer before causing the requeue that will ask it for real. It
/// passes `seatable == cap`, because at demote time the judged job's
/// own pipeline still holds the ledger's bytes and the rerun-time
/// ledger is unknowable; erring toward "it will map" only softens a
/// warning, while the rerun's own call here still decides with the
/// real ledger.
pub(crate) fn resume_map_admits(
    restored_bytes: u64,
    widest_slot: u64,
    cap: u64,
    seatable: u64,
) -> bool {
    if restored_bytes <= cap {
        return true;
    }
    // A journal with placements but no slot size to read is not something
    // this arm can judge, so it declines to - arm 1 has already spoken.
    widest_slot > 0 && widest_slot.saturating_mul(RESUME_MAP_VOLUME_MARGIN) <= seatable
}

/// The B4 small-RAM concurrency clamp and the rotational-output
/// decoder pick. A clamp on the effective values, not a config
/// rewrite - settings stay portable and apply in full on bigger
/// hardware.
pub(super) fn clamp_concurrency(
    connections: usize,
    window: usize,
    decoders: usize,
    out_dir: &Path,
) -> (usize, usize, usize) {
    // B4: on small-RAM boxes clamp job concurrency to the machine's tier
    // - spill-churn on an HDD costs more than the connections buy, so
    // consistency wins over peak. A clamp on the effective values, not a
    // config rewrite: settings stay portable and apply in full on bigger
    // hardware. Above 1 GB the caps are None and nothing changes.
    let (connections, window, decoders) = match nzbkit::mem::concurrency_caps() {
        Some(caps) => {
            let clamped = caps.apply(connections, window, decoders);
            if clamped != (connections, window, decoders) {
                info!(
                    target: "mem",
                    "small-RAM machine: clamping to {} conns × window {} × {} decoders (was {connections}×{window}×{decoders})",
                    clamped.0, clamped.1, clamped.2
                );
            }
            clamped
        }
        None => (connections, window, decoders),
    };
    // Rotational output on a NAS-class box: one decoder, so the article
    // lanes stop being seek lanes. See disk::decoders_for_storage for why
    // it is gated on the box as well as the disk.
    let decoders = {
        // cpu-workers-gate: how BIG this box is, which is what the
        // rotational-storage rule is gated on, and what the log line then
        // prints. Not a pool width - `decoders_for_storage` decides that.
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        let storage = nzbkit::disk::detect_storage(out_dir);
        let picked = nzbkit::disk::decoders_for_storage(storage, cores, decoders);
        if picked != decoders {
            info!(
                target: "disk",
                "rotational output on a {cores}-core box: {picked} decoder \
                 (was {decoders}) to keep writes in order - override with \
                 NZBFAST_STORAGE=ssd"
            );
        }
        picked
    };
    (connections, window, decoders)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nzb(xml: &str) -> Arc<Nzb> {
        Arc::new(Nzb::parse(xml.as_bytes()).expect("test NZB parses"))
    }

    fn plan(
        n: &Arc<Nzb>,
        completed: &HashSet<String>,
        bootstrap_vol: Option<usize>,
        resume_vols: &HashMap<usize, PathBuf>,
    ) -> FetchPlan {
        plan_with(n, completed, bootstrap_vol, resume_vols, false)
    }

    fn plan_with(
        n: &Arc<Nzb>,
        completed: &HashSet<String>,
        bootstrap_vol: Option<usize>,
        resume_vols: &HashMap<usize, PathBuf>,
        skip_samples: bool,
    ) -> FetchPlan {
        build_fetch_plan(
            n,
            &None,
            completed,
            !completed.is_empty(),
            bootstrap_vol,
            resume_vols,
            skip_samples,
            &[],
        )
    }

    /// GH #63: the plan decides, once, whether the SUBJECT gave this
    /// slot a name worth defending against a hash arriving later in a
    /// yEnc header or a PAR2 FileDesc.
    ///
    /// It has to be decided here because the answer is not recoverable
    /// from `hint` afterwards: a subject that names nothing falls back
    /// to `file{idx:03}`, and that placeholder reads as a perfectly good
    /// name to `stem_is_a_name`. The three subject shapes below are the
    /// three that exist - a real name in the clear (#63's own post, and
    /// #55's), a real name quoted (every honest post), and prose that
    /// names nothing.
    #[test]
    fn the_plan_records_whether_the_subject_named_the_file() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="01-duo_something_bi-noir.mp3 (1/0)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">a@t</segment></segments>
 </file>
 <file subject='"Some.Film.2026-GRP.part01.rar" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">b@t</segment></segments>
 </file>
 <file subject="Great Album Name yEnc (1/15)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">c@t</segment></segments>
 </file>
 <file subject="2137d880a074c9f1e0b3a5d6c7e8f901 yEnc (1/1)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">d@t</segment></segments>
 </file>
</nzb>"#);
        let p = plan(&n, &HashSet::new(), None, &HashMap::new());

        // Unquoted and real - the shape that lost every name on #63.
        assert_eq!(p.slots[0].hint, "01-duo_something_bi-noir.mp3");
        assert!(p.slots[0].hint_is_posted_name);

        // Quoted and real - the ordinary honest post, unchanged.
        assert_eq!(p.slots[1].hint, "Some.Film.2026-GRP.part01.rar");
        assert!(p.slots[1].hint_is_posted_name);

        // Prose names nothing, so the placeholder stands - and must NOT
        // be defended, or an obfuscated post gets strictly worse names
        // than before the guard existed.
        assert_eq!(p.slots[2].hint, "file002");
        assert!(!p.slots[2].hint_is_posted_name);

        // A subject that IS the hash: #43/#47/#55's polarity, where the
        // yEnc name and the FileDesc are the only evidence there is and
        // both must keep winning.
        assert!(!p.slots[3].hint_is_posted_name);
    }

    /// §129 4b: the post's own date reaches the hub, so the LIVE
    /// verdict can tell "not here yet" from "not here any more". The
    /// youngest article is the NEWEST date in the set.
    #[test]
    fn the_hub_gets_the_youngest_article_date() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"m.part1.rar" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">a@t</segment></segments>
 </file>
 <file subject='"m.part2.rar" yEnc (1/1)' date="1700086400">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">b@t</segment></segments>
 </file>
</nzb>"#);
        let hub = Arc::new(crate::streamhub::StreamHub::default());
        let opt = Some(hub.clone());
        build_fetch_plan(
            &n,
            &opt,
            &HashSet::new(),
            false,
            None,
            &HashMap::new(),
            false,
            &[],
        );
        assert_eq!(
            hub.post_unix.load(Ordering::Relaxed),
            1_700_086_400,
            "the newest date in the set is the youngest article"
        );
    }

    /// One undated file and the whole answer is UNKNOWN, not a date
    /// derived from the files that happened to carry one. Mirrors what
    /// `take_census` does with the same NZB (its per-file minimum age
    /// collapses to 0), and unknown must never read as "posted just
    /// now" - that would promise a wait that may never end.
    #[test]
    fn one_undated_file_makes_the_post_date_unknown() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"m.part1.rar" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">a@t</segment></segments>
 </file>
 <file subject='"m.part2.rar" yEnc (1/1)'>
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">b@t</segment></segments>
 </file>
</nzb>"#);
        let hub = Arc::new(crate::streamhub::StreamHub::default());
        let opt = Some(hub.clone());
        build_fetch_plan(
            &n,
            &opt,
            &HashSet::new(),
            false,
            None,
            &HashMap::new(),
            false,
            &[],
        );
        assert_eq!(hub.post_unix.load(Ordering::Relaxed), 0);
    }

    fn ids_of(p: &FetchPlan) -> Vec<&str> {
        p.ids.iter().map(|r| &*r.id).collect()
    }

    fn plan_donated(n: &Arc<Nzb>, donated: &[bool]) -> FetchPlan {
        build_fetch_plan(
            n,
            &None,
            &HashSet::new(),
            false,
            None,
            &HashMap::new(),
            false,
            donated,
        )
    }

    /// §293 plan-side adoption (TODO 305 item 2): a donated file's
    /// articles are struck out of the plan ENTIRELY - none is queued,
    /// its head is not promoted to the head burst either - and the par2
    /// main's are untouched beside them. The slot survives with nothing
    /// remaining and nothing missing, which is the same shape a fully
    /// resumed file has, so the settle read-back is what proves the
    /// bytes.
    #[test]
    fn a_donated_file_queues_none_of_its_articles() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"m.part1.rar" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="100" number="1">a@t</segment>
   <segment bytes="200" number="2">b@t</segment>
  </segments>
 </file>
 <file subject='"m.par2" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="50" number="1">p1@t</segment></segments>
 </file>
 <file subject='"m.part2.rar" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="400" number="1">d@t</segment>
   <segment bytes="500" number="2">e@t</segment>
  </segments>
 </file>
</nzb>"#);
        let none = plan_donated(&n, &[]);
        assert_eq!(
            ids_of(&none),
            ["<p1@t>", "<a@t>", "<d@t>", "<b@t>", "<e@t>"],
            "control: nothing donated, the whole post is planned"
        );

        let p = plan_donated(&n, &[true, false, false]);
        assert_eq!(
            ids_of(&p),
            ["<p1@t>", "<d@t>", "<e@t>"],
            "the donated file contributes no article at any priority"
        );
        assert_eq!(p.slots[0].remaining.load(Ordering::Relaxed), 0);
        assert_eq!(p.slots[0].missing.load(Ordering::Relaxed), 0);
        assert_eq!(
            p.slots[0].deferred.load(Ordering::Relaxed),
            0,
            "a donated file is HELD, not deferred - it must not report as \
             recovery data nobody downloaded"
        );
        assert_eq!(
            p.resume_have_bytes, 300,
            "its declared bytes seed the bar, so the row does not start at 0%"
        );
    }

    /// The par2 MAIN is never donatable however the flags arrive: its
    /// packets have to be in memory for the set to activate, and a
    /// recovery volume is not a member of the set it protects. A caller
    /// that flags one anyway (a name collision, a future bug) must not
    /// be able to strike the index out of the plan.
    #[test]
    fn a_donation_can_never_strike_out_the_par2_index() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"m.par2" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="50" number="1">p1@t</segment></segments>
 </file>
 <file subject='"m.part1.rar" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">a@t</segment></segments>
 </file>
</nzb>"#);
        let p = plan_donated(&n, &[true, true]);
        assert_eq!(
            ids_of(&p),
            ["<p1@t>"],
            "the index is still fetched; only the payload file is struck out"
        );
    }

    /// Queue order: the par2 main's articles first (the recovery set
    /// activates in the first round-trips), then every file's head
    /// segment (offset-0 carries the archive signature), then data.
    #[test]
    fn par2_main_then_heads_then_data() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"m.part1.rar" yEnc (1/3)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="100" number="1">a@t</segment>
   <segment bytes="200" number="2">b@t</segment>
   <segment bytes="300" number="3">c@t</segment>
  </segments>
 </file>
 <file subject='"m.par2" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="50" number="1">p1@t</segment>
   <segment bytes="60" number="2">p2@t</segment>
  </segments>
 </file>
 <file subject='"m.part2.rar" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="400" number="1">d@t</segment>
   <segment bytes="500" number="2">e@t</segment>
  </segments>
 </file>
</nzb>"#);
        let p = plan(&n, &HashSet::new(), None, &HashMap::new());
        assert_eq!(
            ids_of(&p),
            [
                "<p1@t>", "<p2@t>", "<a@t>", "<d@t>", "<b@t>", "<c@t>", "<e@t>"
            ]
        );
        assert_eq!(p.slot_file, [0, 1, 2]);
        assert!(p.slots[1].is_par2_main);
        assert!(
            p.slots[1].capture.lock_ok().is_some(),
            "par2 main captures in memory"
        );
        // Per-slot seek ladder: cumulative encoded offsets, empty for par2.
        assert_eq!(
            p.slot_arts[0].0,
            vec![
                (0, std::sync::Arc::<str>::from("<a@t>")),
                (100, std::sync::Arc::<str>::from("<b@t>")),
                (300, std::sync::Arc::<str>::from("<c@t>"))
            ]
        );
        assert_eq!(p.slot_arts[0].1, 600);
        assert!(p.slot_arts[1].0.is_empty());
        // Fresh run: nothing pre-credited on the progress counter.
        assert_eq!(p.fetch_done.load(Ordering::Relaxed), 0);
    }

    /// R9 measurement (ignored - it is a number, not a gate). Builds a
    /// plan for a 100k-segment job and reports the process RSS the
    /// plan's three id holders cost: `id_to_slot`, the seek ladder, and
    /// the queued `ArticleReq`s.
    ///
    /// Measured 20 Aug 2026, release, M-series, three runs each and
    /// stable to +/-16 KB: 28,768 KB before the interning against 9,392
    /// KB after, so 67% of the plan's id memory (19.4 MB at this size)
    /// was the two duplicate copies. That is the RETAINED half of R9's
    /// win only - the pool's per-article churn (inflight, done_ok, the
    /// handed pair, promoted_ids) is transient and does not show here.
    ///
    /// Re-run on any tree, including one without the interning, since
    /// the body is type-agnostic:
    /// `cargo test -p nzbfast --release --bin nzbfast r9_plan_rss -- --ignored --nocapture`
    /// macOS: ps is the portable-enough RSS read for a one-shot.
    fn rss_kb() -> u64 {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(0)
    }

    /// A field-scale NZB for the ignored RSS measurements: `files` rar
    /// parts of `segs` segments each, with representative ~50-byte
    /// (bracketed) powerpost message-ids.
    fn field_scale_xml(files: usize, segs: usize) -> String {
        let mut xml = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for f in 0..files {
            xml.push_str(&format!(
                " <file subject='\"big.part{f:03}.rar\" yEnc (1/{segs})' date=\"1700000000\">\n\
                 <groups><group>alt.binaries.test</group></groups>\n<segments>\n"
            ));
            for s in 0..segs {
                xml.push_str(&format!(
                    "<segment bytes=\"768000\" number=\"{}\">part{f:03}seg{s:04}.\
                     aBcDeFgHiJkLmNoPqRsT@powerpost.local</segment>\n",
                    s + 1
                ));
            }
            xml.push_str("</segments>\n </file>\n");
        }
        xml.push_str("</nzb>\n");
        xml
    }

    #[test]
    #[ignore]
    fn r9_plan_rss_at_field_scale() {
        const FILES: usize = 100;
        const SEGS: usize = 1000;
        let xml = field_scale_xml(FILES, SEGS);
        let n = nzb(&xml);
        drop(xml);
        let before = rss_kb();
        let p = plan(&n, &HashSet::new(), None, &HashMap::new());
        let after = rss_kb();
        let ids: usize = p.slot_arts.iter().map(|(a, _)| a.len()).sum();
        eprintln!(
            "R9 plan RSS: {} segments, {} ladder entries, {} queued; \
             RSS {} -> {} KB (delta {} KB)",
            FILES * SEGS,
            ids,
            p.ids.len(),
            before,
            after,
            after as i64 - before as i64
        );
        assert_eq!(p.ids.len(), FILES * SEGS);
    }

    /// C6 measurement (ignored - it is a number, not a gate). Prices
    /// what the retained `Arc<Nzb>` itself holds at field scale: parse
    /// one 100k-segment NZB to warm the allocator, then hold three more
    /// copies and divide the RSS delta - the per-copy figure is the
    /// manifest's retained footprint, dominated by `Segment` structs
    /// and their unbracketed `message_id` Strings (which do NOT share
    /// the plan's interned bracketed handles - see the R9 note at the
    /// interning site above).
    ///
    /// Run: `cargo test -p nzbfast --release --bin nzbfast c6_nzb -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn c6_nzb_retained_rss_at_field_scale() {
        const FILES: usize = 100;
        const SEGS: usize = 1000;
        const COPIES: usize = 3;
        let xml = field_scale_xml(FILES, SEGS);
        let warm = nzb(&xml);
        let before = rss_kb();
        let held: Vec<_> = (0..COPIES).map(|_| nzb(&xml)).collect();
        let after = rss_kb();
        eprintln!(
            "C6 Arc<Nzb> retained: {} segments; {COPIES} extra copies cost \
             RSS {before} -> {after} KB ({} KB per copy)",
            FILES * SEGS,
            (after as i64 - before as i64) / COPIES as i64,
        );
        assert_eq!(warm.files.len(), FILES);
        drop(held);
    }

    /// R9: the plan interns each bracketed id ONCE, and the three
    /// holders it hands out share that one allocation. Pointer
    /// equality, not string equality - the whole point of the change is
    /// that `id_to_slot`, the seek ladder and the queued `ArticleReq`
    /// stop being three full copies of the run's id set, and only
    /// `Arc::ptr_eq` can tell a shared handle from an equal string. A
    /// future `format!("<{}>", ..)` re-introduced on any of these paths
    /// still passes every other test in this file; it fails here.
    #[test]
    fn the_plan_interns_each_id_once() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"m.part1.rar" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="100" number="1">a@t</segment>
   <segment bytes="200" number="2">b@t</segment>
  </segments>
 </file>
</nzb>"#);
        let p = plan(&n, &HashSet::new(), None, &HashMap::new());
        // Every ladder entry is the same allocation as its `id_to_slot`
        // key and as the `ArticleReq` the pool was handed.
        let ladder = &p.slot_arts[0].0;
        assert_eq!(ladder.len(), 2, "both segments on the ladder");
        for (_, id) in ladder {
            let (key, _) = p
                .id_to_slot
                .get_key_value(&**id)
                .expect("every ladder id owns a slot");
            assert!(
                std::sync::Arc::ptr_eq(key, id),
                "{id}: the ladder holds a COPY of the id_to_slot key, not the handle"
            );
            let req = p
                .ids
                .iter()
                .find(|r| *r.id == **id)
                .expect("every ladder id is queued");
            assert!(
                std::sync::Arc::ptr_eq(&req.id, id),
                "{id}: the ArticleReq holds a COPY of the ladder id, not the handle"
            );
        }
        // And the count is exactly one strong reference per holder, so
        // a fourth copy cannot hide behind an equal string either.
        assert_eq!(
            std::sync::Arc::strong_count(&ladder[0].1),
            3,
            "id_to_slot + ladder + ArticleReq, and nothing else"
        );
    }

    /// The sample skip, end to end at plan level: the teaser's articles
    /// never reach the queue, its slot carries the flag settle reads,
    /// and its bytes are credited to the progress counter up front - a
    /// skipped article gets no terminal outcome, so nothing else ever
    /// will, and the bar would otherwise sit short of 100% for the
    /// whole job.
    #[test]
    fn a_skipped_sample_is_never_queued() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"Movie.2024.1080p-GRP.mkv" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="800000" number="1">a@t</segment>
   <segment bytes="800000" number="2">b@t</segment>
  </segments>
 </file>
 <file subject='"Movie.2024.1080p-GRP-sample.mkv" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="1000" number="1">s1@t</segment>
   <segment bytes="1000" number="2">s2@t</segment>
  </segments>
 </file>
</nzb>"#);
        // Off: today's behaviour, every article queued.
        let off = plan(&n, &HashSet::new(), None, &HashMap::new());
        assert_eq!(ids_of(&off).len(), 4);
        assert!(!off.slots[1].sample_skipped);
        assert_eq!(off.fetch_done.load(Ordering::Relaxed), 0);

        // On: the teaser's two articles are gone from the queue.
        let on = plan_with(&n, &HashSet::new(), None, &HashMap::new(), true);
        assert_eq!(ids_of(&on), ["<a@t>", "<b@t>"]);
        assert!(on.slots[1].sample_skipped);
        assert!(!on.slots[0].sample_skipped, "the feature is untouched");
        // Booked as a CHOICE, not damage: this is what keeps the census
        // and the uncovered-hole scan from failing the job over it.
        assert_eq!(on.slots[1].deferred.load(Ordering::Relaxed), 2);
        assert_eq!(on.slots[1].missing.load(Ordering::Relaxed), 0);
        assert_eq!(on.slots[1].remaining.load(Ordering::Relaxed), 0);
        // The slot still exists and still declares its segments - the
        // manifest must not shrink, or a skipped file would be
        // indistinguishable from one the NZB never named.
        assert_eq!(on.slots[1].total_segments, 2);
        assert_eq!(on.fetch_done.load(Ordering::Relaxed), 2000);
    }

    /// The two ways the classifier declines, at plan level: a
    /// sample-named file big enough to be the feature, and a job whose
    /// ONLY video is sample-named. Both fetch in full with the setting
    /// on - the gate errs toward downloading, and the post-download
    /// sweep (which can read the running time) decides from there.
    #[test]
    fn the_gate_errs_toward_downloading() {
        let sole = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"Proof.2005.1080p.BluRay-GRP.mkv" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="900000" number="1">v@t</segment></segments>
 </file>
 <file subject='"Proof.2005.1080p.BluRay-GRP.nfo" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="900" number="1">n@t</segment></segments>
 </file>
</nzb>"#);
        let p = plan_with(&sole, &HashSet::new(), None, &HashMap::new(), true);
        assert_eq!(ids_of(&p), ["<v@t>", "<n@t>"]);
        assert!(p.slots.iter().all(|s| !s.sample_skipped));

        // Sample-named, but 40% of the feature: too much to throw away
        // on a name.
        let big = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"Movie.2024.1080p-GRP.mkv" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="1000000" number="1">a@t</segment></segments>
 </file>
 <file subject='"Movie.2024.1080p-GRP.sample.mkv" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="400000" number="1">s@t</segment></segments>
 </file>
</nzb>"#);
        let p = plan_with(&big, &HashSet::new(), None, &HashMap::new(), true);
        assert_eq!(ids_of(&p), ["<a@t>", "<s@t>"]);
        assert!(p.slots.iter().all(|s| !s.sample_skipped));
    }

    /// A repeated message-id is fetched once, under its FIRST owner. The
    /// same-file repeat only decrements remaining; the cross-file repeat
    /// also counts as missing for the losing file.
    #[test]
    fn duplicate_ids_are_owned_once() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"dup.part1.rar" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="100" number="1">a@t</segment>
   <segment bytes="150" number="2">a@t</segment>
  </segments>
 </file>
 <file subject='"dup.part2.rar" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="100" number="1">a@t</segment>
   <segment bytes="200" number="2">b@t</segment>
  </segments>
 </file>
</nzb>"#);
        let p = plan(&n, &HashSet::new(), None, &HashMap::new());
        assert_eq!(p.id_to_slot.len(), 2, "each id has exactly one owner");
        assert_eq!(p.id_to_slot["<a@t>"].0, 0, "the first occurrence owns");
        assert_eq!(
            ids_of(&p),
            ["<a@t>", "<b@t>"],
            "a dup is never queued twice"
        );
        // Same-file repeat: covered by the one fetch, not damage.
        assert_eq!(p.slots[0].remaining.load(Ordering::Relaxed), 1);
        assert_eq!(p.slots[0].missing.load(Ordering::Relaxed), 0);
        // Cross-file repeat: these bytes never reach THIS file.
        assert_eq!(p.slots[1].remaining.load(Ordering::Relaxed), 1);
        assert_eq!(p.slots[1].missing.load(Ordering::Relaxed), 1);
        assert_eq!(p.slots[0].total_segments, 2);
        assert_eq!(p.slots[1].total_segments, 2);
    }

    /// A parser-dropped segment (empty message-id) still counts toward
    /// the total and starts out missing - it must not vanish from the
    /// manifest and finish green zero-filled.
    #[test]
    fn parser_dropped_segments_start_missing() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"gap.rar" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="100" number="1"></segment>
   <segment bytes="200" number="2">ok@t</segment>
  </segments>
 </file>
</nzb>"#);
        assert_eq!(n.files[0].dropped_segments, 1);
        let p = plan(&n, &HashSet::new(), None, &HashMap::new());
        assert_eq!(
            p.slots[0].total_segments,
            n.files[0].segments.len() + n.files[0].dropped_segments
        );
        assert_eq!(p.slots[0].missing.load(Ordering::Relaxed), 1);
        assert_eq!(p.slots[0].remaining.load(Ordering::Relaxed), 1);
        assert_eq!(ids_of(&p), ["<ok@t>"]);
    }

    /// Resume: journal-completed ids land in resume_have_bytes and stay
    /// out of the queue; a resume-recognised recovery volume defers every
    /// unfetched article; fetch_done is seeded with have + deferred.
    #[test]
    fn resume_credits_have_and_deferred_bytes() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"r.part1.rar" yEnc (1/3)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="1000" number="1">a@t</segment>
   <segment bytes="2000" number="2">b@t</segment>
   <segment bytes="3000" number="3">c@t</segment>
  </segments>
 </file>
 <file subject='"obfhash1" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="500" number="1">d@t</segment>
   <segment bytes="700" number="2">e@t</segment>
  </segments>
 </file>
</nzb>"#);
        let completed: HashSet<String> = ["<a@t>".to_string()].into();
        let resume_vols: HashMap<usize, PathBuf> =
            [(1usize, PathBuf::from("/nonexistent/vol"))].into();
        let p = plan(&n, &completed, None, &resume_vols);
        assert_eq!(p.resume_have_bytes, 1000);
        assert_eq!(p.resume_deferred_arts, 2);
        assert_eq!(p.resume_deferred_bytes, 1200);
        assert_eq!(p.resume_sniffed_slots, [1]);
        assert!(p.slots[1].par2_sniffed.load(Ordering::Relaxed));
        assert_eq!(p.slots[1].deferred.load(Ordering::Relaxed), 2);
        assert_eq!(p.slots[1].remaining.load(Ordering::Relaxed), 0);
        // Only slot 0's unfetched data articles remain in the queue.
        assert_eq!(ids_of(&p), ["<b@t>", "<c@t>"]);
        assert_eq!(p.slots[0].remaining.load(Ordering::Relaxed), 2);
        assert_eq!(p.fetch_done.load(Ordering::Relaxed), 1000 + 1200);
        // Completed and deferred ids still have owners in the manifest.
        assert_eq!(p.id_to_slot.len(), 5);
    }

    /// A Par2Volume gets a slot only as the elected bootstrap, so slot
    /// indices diverge from NZB file indices and slot_file records the
    /// mapping.
    #[test]
    fn only_the_elected_bootstrap_volume_gets_a_slot() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"m.part1.rar" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">a@t</segment></segments>
 </file>
 <file subject='"m.vol000+01.par2" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="50" number="1">v1@t</segment></segments>
 </file>
 <file subject='"m.vol001+02.par2" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="80" number="1">v2@t</segment></segments>
 </file>
</nzb>"#);
        let p = plan(&n, &HashSet::new(), Some(1), &HashMap::new());
        assert_eq!(p.slots.len(), 2, "the non-elected volume never gets a slot");
        assert_eq!(
            p.slot_file,
            [0, 1],
            "slot index maps back to NZB file index"
        );
        assert!(
            p.slots[1].is_par2_main,
            "the bootstrap is treated as par2 main"
        );
        assert_eq!(
            ids_of(&p),
            ["<v1@t>", "<a@t>"],
            "bootstrap articles queue first"
        );
        // No election at all: both volumes are skipped.
        let p = plan(&n, &HashSet::new(), None, &HashMap::new());
        assert_eq!(p.slots.len(), 1);
        assert_eq!(p.slot_file, [0]);
    }

    /// A subject with no quoted filename falls back to file{idx:03}.
    #[test]
    fn hint_falls_back_to_the_slot_index() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="no quotes anywhere yEnc (1/1)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="10" number="1">x@t</segment></segments>
 </file>
</nzb>"#);
        let p = plan(&n, &HashSet::new(), None, &HashMap::new());
        assert_eq!(p.slots[0].hint, "file000");
    }

    /// ...but an UNQUOTED subject that plainly ends in a filename names
    /// the slot (issue #55: `10-Track Name-8c63a701.flac (1/0)`, no
    /// quotes at all - the whole album landed as fileNNN with the real
    /// names discarded, and only the one track a PAR2 set covered ever
    /// got its name back).
    #[test]
    fn hint_reads_an_unquoted_subject_filename() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="10-Track Name-8c63a701.flac (1/0)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="10" number="1">x@t</segment></segments>
 </file>
</nzb>"#);
        let p = plan(&n, &HashSet::new(), None, &HashMap::new());
        assert_eq!(p.slots[0].hint, "10-Track Name-8c63a701.flac");
    }

    /// Build a ServerConfig through serde so the test survives new
    /// `#[serde(default)]` fields being added to the struct.
    fn srv(host: &str, level: u32) -> ServerConfig {
        serde_json::from_value(serde_json::json!({
            "host": host,
            "port": 563,
            "tls": true,
            "connections": 10,
            "level": level,
            "enabled": true,
        }))
        .unwrap()
    }

    fn levels(servers: &[ServerConfig]) -> Vec<(&str, u32)> {
        servers.iter().map(|s| (s.host.as_str(), s.level)).collect()
    }

    /// The 14 Aug 2026 shape: 4 of 6 backbones written off. They must all
    /// still be in the pool, just last in line - a wrong verdict costs
    /// round-trips, never the download.
    #[test]
    fn predicted_gone_servers_are_demoted_not_removed() {
        let mut servers = vec![
            srv("news.newshosting.com", 0),
            srv("news.eweka.nl", 0),
            srv("news.tweaknews.eu", 0),
            srv("news.usenetexpress.com", 0),
            srv("news.giganews.com", 0),
            srv("news.xsnews.nl", 0),
        ];
        let gone: Vec<String> = [
            "news.newshosting.com",
            "news.eweka.nl",
            "news.tweaknews.eu",
            "news.usenetexpress.com",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        demote_predicted_gone(&mut servers, &gone, "hdtv", 20);
        assert_eq!(servers.len(), 6, "no server may leave the pool");
        assert_eq!(
            levels(&servers),
            vec![
                ("news.newshosting.com", 1),
                ("news.eweka.nl", 1),
                ("news.tweaknews.eu", 1),
                ("news.usenetexpress.com", 1),
                ("news.giganews.com", 0),
                ("news.xsnews.nl", 0),
            ]
        );
    }

    /// Every backbone written off: they all land on the SAME new level,
    /// so every `required_mask` is empty and the run is identical to one
    /// with no verdict at all. This is why the old "only skip if at least
    /// one survives" guard is not needed.
    #[test]
    fn all_gone_is_a_no_op() {
        let mut servers = vec![
            srv("a.example", 0),
            srv("b.example", 0),
            srv("c.example", 0),
        ];
        let gone: Vec<String> = servers.iter().map(|s| s.host.clone()).collect();
        demote_predicted_gone(&mut servers, &gone, "hdtv", 20);
        assert_eq!(servers.len(), 3);
        let ls: Vec<u32> = servers.iter().map(|s| s.level).collect();
        assert!(ls.iter().all(|l| *l == ls[0]), "all on one level: {ls:?}");
    }

    /// The guard the old code had counted SERVERS while verdicts are per
    /// BACKBONE: three mirrors of one backbone plus one other provider
    /// passed it and lost 3 of 4. Demotion keeps all four.
    #[test]
    fn three_mirrors_plus_one_keeps_every_server() {
        let mut servers = vec![
            srv("news.mirror-a.example", 0),
            srv("news.mirror-b.example", 0),
            srv("news.mirror-c.example", 0),
            srv("news.xsnews.nl", 0),
        ];
        let gone: Vec<String> = servers[..3].iter().map(|s| s.host.clone()).collect();
        demote_predicted_gone(&mut servers, &gone, "hdtv", 20);
        assert_eq!(servers.len(), 4);
        assert_eq!(servers[3].level, 0, "the surviving backbone stays primary");
        assert!(servers[..3].iter().all(|s| s.level == 1));
    }

    /// An existing level-1 fill server must stay AHEAD of a demoted
    /// primary: the new tier is one below the config's deepest, not a
    /// flat "level 1".
    #[test]
    fn existing_fill_servers_stay_above_the_demoted() {
        let mut servers = vec![
            srv("primary.example", 0),
            srv("other-primary.example", 0),
            srv("block-fill.example", 1),
        ];
        demote_predicted_gone(&mut servers, &["primary.example".to_string()], "hdtv", 20);
        assert_eq!(
            levels(&servers),
            vec![
                ("primary.example", 2),
                ("other-primary.example", 0),
                ("block-fill.example", 1),
            ]
        );
    }

    #[test]
    fn no_verdict_changes_nothing() {
        let mut servers = vec![srv("a.example", 0), srv("b.example", 1)];
        demote_predicted_gone(&mut servers, &[], "hdtv", 20);
        assert_eq!(levels(&servers), vec![("a.example", 0), ("b.example", 1)]);
    }

    /// CRC steering (fleet.rs) keys on a same-LEVEL peer, so demotion can
    /// switch it off. The measured 4-of-6 and 5-of-6 splits both leave a
    /// pair somewhere, but a two-primary config demoted 1 of 2 leaves each
    /// server alone on its level - and turning the steer off there is
    /// correct, because the lone peer's pickup gate would not let it take
    /// the article anyway.
    #[test]
    fn demotion_can_leave_a_server_alone_on_its_level() {
        // 4 of 6 gone: still a pair on each level, steer stays on.
        let mut six = vec![
            srv("a.example", 0),
            srv("b.example", 0),
            srv("c.example", 0),
            srv("d.example", 0),
            srv("e.example", 0),
            srv("f.example", 0),
        ];
        let gone: Vec<String> = six[..4].iter().map(|s| s.host.clone()).collect();
        demote_predicted_gone(&mut six, &gone, "hdtv", 20);
        assert!(crate::get::fleet::has_steer_peer(&six));

        // 5 of 6 gone: the survivor is alone on level 0, but the five
        // demoted share level 1, so an elsewhere still exists.
        let mut five = vec![
            srv("a.example", 0),
            srv("b.example", 0),
            srv("c.example", 0),
            srv("d.example", 0),
            srv("e.example", 0),
            srv("f.example", 0),
        ];
        let gone: Vec<String> = five[..5].iter().map(|s| s.host.clone()).collect();
        demote_predicted_gone(&mut five, &gone, "hdtv", 20);
        assert!(crate::get::fleet::has_steer_peer(&five));

        // Two primaries, one demoted: nobody has a same-level peer.
        let mut pair = vec![srv("a.example", 0), srv("b.example", 0)];
        assert!(crate::get::fleet::has_steer_peer(&pair));
        demote_predicted_gone(&mut pair, &["a.example".to_string()], "hdtv", 20);
        assert_eq!(levels(&pair), vec![("a.example", 1), ("b.example", 0)]);
        assert!(!crate::get::fleet::has_steer_peer(&pair));
    }

    /// TODO 94 A's original rule, unchanged: the whole restored set under
    /// the RAW cap admits, whatever the volumes look like. Pinned because
    /// TODO 309(a) added a second arm beside it and the never-worse claim
    /// is that this one still answers first.
    #[test]
    fn the_whole_restored_set_under_the_cap_still_admits_on_its_own() {
        // Widest slot deliberately absurd: arm 1 must not consult it.
        assert!(resume_map_admits(1_000, u64::MAX, 2_000, 2_000));
        // And a seatable of zero cannot take arm 1 away - a total that
        // fits the raw cap was admitted before the ledger existed.
        assert!(resume_map_admits(1_000, u64::MAX, 2_000, 0));
    }

    /// TODO 309(a): the volume arm, at the two shipping budgets the
    /// section's table complains about. 256 MB volumes, ~2.2 GB restored
    /// - far over the cap either way, so arm 1 declines both.
    #[test]
    fn a_set_over_the_cap_still_maps_when_its_widest_volume_fits_twice() {
        let restored = 2_236_500_000;
        let vol = 256_000_000;
        // 8 GB box: cap 0.97 GB. 2 x 256 MB = 512 MB, fits.
        assert!(!resume_map_admits(restored, 0, 970_000_000, 970_000_000));
        assert!(resume_map_admits(restored, vol, 970_000_000, 970_000_000));
        // 16 GB box: more room again.
        assert!(resume_map_admits(
            restored,
            vol,
            1_930_000_000,
            1_930_000_000
        ));
    }

    /// The half the measurement exists to protect: at a budget under one
    /// volume the mapped route was measured at 2.89-3.00x against the
    /// decline's 2.53x, so the margin must refuse it. The boundary is
    /// stated in `RESUME_MAP_VOLUME_MARGIN`'s own ladder.
    #[test]
    fn a_budget_that_cannot_hold_two_volumes_declines() {
        let restored = 2_236_500_000;
        let vol = 256_000_000;
        // 250 MB - under one volume, the budget that lost on the rig.
        assert!(!resume_map_admits(restored, vol, 250_000_000, 250_000_000));
        // 500 MB - just under two volumes, so still refused. Conservative
        // on purpose: this budget WON on the rig (1.03-1.20x), and the
        // margin buys the octave rather than the last decibel.
        assert!(!resume_map_admits(restored, vol, 500_000_000, 500_000_000));
        // Exactly two fits.
        assert!(resume_map_admits(restored, vol, 512_000_000, 512_000_000));
        // 64 MB volumes at the same 50 MB budget that lost on the rig.
        assert!(!resume_map_admits(
            restored, 64_000_000, 50_000_000, 50_000_000
        ));
        assert!(resume_map_admits(
            restored,
            64_000_000,
            250_000_000,
            250_000_000
        ));
    }

    /// The volume arm spends the LEDGER remainder, not the raw cap: in
    /// the daemon a predecessor pipeline is still holding while the
    /// resumed job sets up, and admitting against a cap somebody else is
    /// occupying is how a mapped resume breaches and pays twice.
    #[test]
    fn the_volume_arm_declines_when_a_predecessor_is_holding_the_budget() {
        let restored = 2_236_500_000;
        let vol = 256_000_000;
        let cap = 970_000_000;
        assert!(resume_map_admits(restored, vol, cap, cap));
        // Same cap, but 700 MB of it is held by a senior seat.
        assert!(!resume_map_admits(restored, vol, cap, cap - 700_000_000));
    }

    /// A placement journal that names no slot size cannot be judged by
    /// the volume arm, and a gate that cannot judge must not admit.
    #[test]
    fn a_journal_with_no_slot_size_falls_back_to_the_total_arm_alone() {
        assert!(!resume_map_admits(2_000, 0, 1_000, 1_000));
        // Overflow is not an admission either.
        assert!(!resume_map_admits(2_000, u64::MAX, 1_000, 1_000));
    }

    fn route_scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-resroute-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The resume state a rerun would read: `n` placed articles of `len`
    /// bytes in ONE slot whose recorded size is the whole of them, which
    /// is the volume the gate's second arm weighs.
    ///
    /// Written and then re-opened, because it is the SECOND open that
    /// parses the records back into a `ResumeState` - the same thing a
    /// resumed run does. Same fingerprint both times, or the open would
    /// truncate what the first one wrote.
    fn resume_state_of(dir: &Path, n: usize, len: u64) -> nzbkit::journal::ResumeState {
        let size = n as u64 * len;
        {
            let (j, _) = nzbkit::journal::Journal::open(dir, b"<nzb/>").unwrap();
            for i in 0..n {
                j.record_placed(
                    0,
                    &format!("<a{i}@x>"),
                    None,
                    "vol.part01.rar",
                    size,
                    &[nzbkit::extract::Frag::identity(
                        "vol.part01.rar",
                        i as u64 * len,
                        len,
                    )],
                );
            }
            j.flush();
        }
        nzbkit::journal::Journal::open(dir, b"<nzb/>").unwrap().1
    }

    /// TODO 309: the ADMITTED half of the report's fact, over a real
    /// journal. The gate says map, and the route it hands back says the
    /// same thing with the figures beside it - a route whose `mapped`
    /// disagreed with the decision would put a sentence in the download
    /// report about a run that took the other path.
    #[test]
    fn a_resume_that_maps_reports_the_one_pass_route_and_what_the_gate_weighed() {
        let dir = route_scratch("mapped");
        // 8 MB placed against a ~30 MB replay budget: arm 1 admits.
        let st = resume_state_of(&dir, 8, 1_000_000);
        let budget = nzbkit::mem::MemBudget::with_total(nzbkit::mem::MemBudget::MIN);
        let cap = budget.holds_cap() as u64;
        assert!(cap > 8_000_000, "the fixture must be under the budget");

        let (map, route) = resume_map_admitted(&st, &dir, false, budget);
        assert!(map);
        let r = route.expect("a journal with placements always has a route");
        assert!(r.mapped);
        assert_eq!(r.restored_bytes, 8_000_000);
        assert_eq!(r.budget_bytes, cap);
        // The whole of it is one slot, so the widest part IS the total.
        assert_eq!(r.widest_slot_bytes, 8_000_000);
        // No process ledger in a unit test, so nothing is holding a seat
        // and the volume arm sees the raw cap - the CLI leg's case.
        assert_eq!(r.seatable_bytes, cap);
    }

    /// ...and the DECLINED half, which is the one the report exists for:
    /// this is the 2.53x route, and until the report carried it the only
    /// trace was one `info!` hours before anybody complained.
    ///
    /// Both arms have to refuse for the decision to be a decline, so the
    /// fixture is over the total budget AND its single volume is the
    /// whole of that total, which cannot fit the margin twice over.
    #[test]
    fn a_resume_that_declines_reports_the_on_disk_route_and_what_the_gate_weighed() {
        let dir = route_scratch("declined");
        // 60 MB in one volume against a ~30 MB replay budget. The
        // FRAGMENT LENGTHS are what the gate weighs, so this is a few KB
        // of actual file.
        let st = resume_state_of(&dir, 60, 1_000_000);
        let budget = nzbkit::mem::MemBudget::with_total(nzbkit::mem::MemBudget::MIN);
        let cap = budget.holds_cap() as u64;
        assert!(cap < 60_000_000, "the fixture must be over the budget");

        let (map, route) = resume_map_admitted(&st, &dir, false, budget);
        assert!(!map);
        let r = route.expect("a journal with placements always has a route");
        assert!(!r.mapped);
        assert_eq!(r.restored_bytes, 60_000_000);
        assert_eq!(r.budget_bytes, cap);
        assert_eq!(r.widest_slot_bytes, 60_000_000);
    }

    /// A run with nothing to replay reports NO route, which is what
    /// keeps a non-resumed job's download report byte-for-byte what it
    /// was. A resumed COMPRESSED set lands here too - its output bytes
    /// are decoded bytes, so the journal describes no fragment on disk
    /// (TODO 309(b)) - and saying "one pass" for either would be a claim
    /// about a gate that never weighed anything.
    #[test]
    fn a_run_with_nothing_restored_reports_no_route_at_all() {
        let dir = route_scratch("fresh");
        let st = nzbkit::journal::Journal::open(&dir, b"<nzb/>").unwrap().1;
        assert_eq!(st.placement_bytes(), 0);
        let budget = nzbkit::mem::MemBudget::with_total(nzbkit::mem::MemBudget::MIN);

        let (map, route) = resume_map_admitted(&st, &dir, false, budget);
        assert!(map, "nothing to replay still maps - there is no replay");
        assert!(route.is_none());
    }

    /// The two overrides answer before the gate and report nothing, and
    /// that is deliberate at both ends. `no_extract` is the retention
    /// insurance banking run, which never unpacks anything, so "unpacked
    /// from volumes on disk" would be flatly wrong on its report; the
    /// kill switch is a developer override. Both must also leave the
    /// DECISION exactly as it was before this function returned a route,
    /// because `resume_map` selects `restore_for`'s materialize flag.
    #[test]
    fn the_overrides_decline_without_reporting_a_route() {
        let dir = route_scratch("noextract");
        let st = resume_state_of(&dir, 8, 1_000_000);
        let budget = nzbkit::mem::MemBudget::with_total(nzbkit::mem::MemBudget::MIN);
        // The very same state maps when nothing overrides it.
        assert!(resume_map_admitted(&st, &dir, false, budget).0);
        let (map, route) = resume_map_admitted(&st, &dir, true, budget);
        assert!(!map);
        assert!(route.is_none());
    }
}

#[cfg(test)]
#[path = "plan_route_rig.rs"]
mod plan_route_rig;
