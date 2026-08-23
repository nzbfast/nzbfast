//! StreamHub and SeekCtl: the read-side coordination handles the daemon's /stream path shares with the download pipeline.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;

/// The UX §15 plan pair for ONE run - see [`StreamHub::fetch`].
#[derive(Debug, Default)]
pub struct FetchCounters {
    pub plan: Arc<std::sync::atomic::AtomicU64>,
    pub done: Arc<std::sync::atomic::AtomicU64>,
}

impl FetchCounters {
    /// (accounted-for, planned, still to fetch), or None before the plan
    /// is published.
    pub fn left(&self) -> Option<(u64, u64, u64)> {
        use std::sync::atomic::Ordering;
        let plan = self.plan.load(Ordering::Relaxed);
        if plan == 0 {
            return None;
        }
        // Clamped, not trusted: the two counters are independent atomics
        // and a reader can land between the plan store and the adds that
        // follow it. Better a percentage that pauses at 100 than one that
        // prints 103% or an underflowed remainder.
        let done = self.done.load(Ordering::Relaxed).min(plan);
        Some((done, plan, plan - done))
    }
}

/// Live handle the daemon's streaming endpoint uses to reach the active
/// download's output writers (M11). `get` installs its extractor here for
/// the duration of the run.
#[derive(Default)]
pub(crate) struct StreamHub {
    /// The active download's extractor, tagged with its owning nzo_id ("" for
    /// a CLI download with no daemon owner). The tag lets a /stream request
    /// clone the extractor and confirm ownership in ONE lock acquisition
    /// (see [`StreamHub::extractor_for`]), so a job transition can never hand
    /// a request another job's extractor between the owner check and the
    /// clone.
    pub extractor: std::sync::Mutex<Option<(String, Arc<nzbkit::extract::Extractor>)>>,
    /// UX §15 fetch progress for the queue row, in the ONE unit the
    /// queue's denominator is quoted in: bytes as the NZB declares them.
    /// `fetch_plan` is what the active run is responsible for, `fetch_done`
    /// how much of it is accounted for (arrived, already on disk from a
    /// resume, or terminally missing). The percentage they make therefore
    /// reaches exactly 100% at net-drain and cannot exceed it - unlike the
    /// decoded-payload-over-encoded-minus-recovery fraction it replaced,
    /// which stopped near 97% on clean sets and pinned at 100% with
    /// articles still in flight on damaged ones.
    ///
    /// The daemon zeroes both at the Downloading transition and
    /// `get_with_progress` publishes the plan before the first article can
    /// land; a zero plan means "no run owns these yet" and every reader
    /// falls back rather than dividing by it.
    ///
    /// One PAIR PER RUN, behind a lock, since the cross-job hand-over
    /// (`nzbkit::pool::handoff`): job N's pipeline keeps adding its last
    /// in-flight articles to the `done` handle it took at its start for
    /// seconds after job N+1 has claimed the hub, so a shared counter
    /// zeroed at the transition credited N's tail to N+1's bar. The
    /// daemon installs a fresh pair at every transition
    /// (`fresh_fetch_counters`); a pipeline clones the handles once
    /// (`fetch_counters`) and never looks at the hub for them again.
    pub fetch: std::sync::Mutex<Arc<FetchCounters>>,
    /// Unix seconds of the YOUNGEST article in the ACTIVE run's NZB, or
    /// 0 for "we do not know" - which is NOT the same as "posted just
    /// now" and must never be read as it.
    ///
    /// The live twin of [`crate::diag::LossCauses::post_age_days`], and
    /// deliberately the same reading: a post nobody carries YET and a
    /// post nobody carries ANY MORE are the same picture from inside the
    /// pool (every article 430, nothing arriving), and only the calendar
    /// tells them apart. The failure summary has had that calendar since
    /// 16 Aug; §129 4b's live verdict had no way to reach it, so a
    /// download slowed to a crawl by a release that was minutes old read
    /// exactly like one slowed by a takedown - and the user's move is
    /// opposite in the two cases.
    ///
    /// Unknown when ANY file in the NZB carries no usable date, matching
    /// what `take_census` does with a partially-dated NZB (its per-file
    /// minimum age collapses to 0 for exactly that reason). Published by
    /// `build_fetch_plan` beside `fetch_plan` and zeroed with it at the
    /// Downloading transition, so no reader can pair one job's date with
    /// another job's counters.
    pub post_unix: std::sync::atomic::AtomicI64,
    /// M14h dashboard feeds: in-stream verifier + per-server pool gauges
    /// of the ACTIVE download.
    pub verifier: std::sync::Mutex<Option<Arc<nzbkit::live::LiveVerifier>>>,
    pub pool_live: std::sync::Mutex<Option<Arc<nzbkit::pool::LiveStats>>>,
    /// Pool-level speed limiter (M14g), shared with every server's pool of
    /// the active download; the daemon adjusts it live via mode=config.
    pub rate: Arc<nzbkit::pool::RateLimit>,
    /// M11 hot lane: number of /stream readers currently attached. The
    /// pool reserves a slice of connections for promoted (seek) work
    /// while this is non-zero.
    pub stream_readers: Arc<std::sync::atomic::AtomicUsize>,
    /// Stream request generation: bumped per /stream request. Only the
    /// newest ALIVE reader may promote - an abandoned pre-seek reader
    /// parked at the write frontier would otherwise keep re-promoting its
    /// stale window, fighting the live seek's window for the hot lane
    /// (each promote rewrites the promoted set). Tracked as a set of
    /// live generations so a short probe that comes and goes hands
    /// promote rights BACK to the player it briefly outranked.
    pub stream_gen: Arc<std::sync::atomic::AtomicU64>,
    pub stream_alive: Arc<std::sync::Mutex<std::collections::BTreeSet<u64>>>,
    /// M11 seek re-prioritization: installed per run; the /stream layer
    /// promotes the articles under a player's read position through it.
    pub seek: std::sync::Mutex<Option<Arc<SeekCtl>>>,
    /// User-cancel of the ACTIVE download: the daemon flips the flag and
    /// aborts the pool through the control; get_with_progress bails
    /// ("stopped by user") instead of settling/extracting partial data.
    pub abort: std::sync::Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>,
    pub queue_ctl: std::sync::Mutex<Option<Arc<nzbkit::pool::QueueControl>>>,
    /// §129: per-owning-nzo_id cancel handle for a run's recovery-volume
    /// side-fetches, keyed exactly like `activity` below and removed at
    /// the same place (`Daemon::park`).
    ///
    /// It cannot be `queue_ctl`, and that is the whole reason this map
    /// exists: `queue_ctl` and `abort` are overwritten per job and carry
    /// no owner tag, so they belong to whatever is DOWNLOADING now. Once
    /// the postproc lane let a tail outlive its download slot, the job
    /// whose repair is pulling parity is routinely not that job - and
    /// deleting it aborted a healthy unrelated download while its own
    /// side-fetch ran on, which is the hazard `owns_hub` was written for.
    pub tail_cancel:
        std::sync::Mutex<std::collections::HashMap<String, Arc<crate::repair::SideCancel>>>,
    /// Connections parked between jobs (see `nzbkit::warmpool`). Lives on
    /// the hub because it must outlive any single download - that is the
    /// entire point. Daemon only: a one-shot CLI `get` has no second job
    /// to hand them to, so it keeps the old connect-and-QUIT behaviour.
    pub warm: std::sync::OnceLock<Arc<nzbkit::warmpool::WarmPool>>,
    /// Cross-job connection hand-over (`nzbkit::pool::handoff`): the
    /// per-host connection leases every primary run on this hub takes
    /// its sockets from, so job N's drain and job N+1's start never hold
    /// more than one job's cap between them. Set once by the daemon at
    /// boot; absent on a CLI run and on a sidecar's private hub, whose
    /// fleet is bounded by `host_conn_caps` instead.
    pub conn_budget: std::sync::OnceLock<Arc<nzbkit::pool::handoff::ConnBudget>>,
    /// The run that owns this hub publishes its hand-over signal here
    /// (installed by the runner before the fetch spawns, read once by
    /// the fleet builder). Latched when that run's fleet starts going
    /// idle after queue-dry - the runner's cue to start the next job.
    pub handoff: std::sync::Mutex<Option<Arc<nzbkit::pool::handoff::HandoffSignal>>>,
    /// Hosts the daemon has ruled out for the NEXT download (exhausted
    /// block accounts); get_with_progress skips them at pool build.
    pub excluded_hosts: std::sync::Mutex<Vec<String>>,
    /// Per-host connection caps for THIS hub's pool build. Set only on a
    /// prefetch sidecar's hub when it BORROWS a slice of a server that is
    /// busy on the active job (no healthy idle server exists): the host
    /// stays in the fleet but its pool opens at most this many
    /// connections, so the active job keeps its budget. Exclusion stays
    /// all-or-nothing (`excluded_hosts`); this is the bounded middle.
    pub host_conn_caps: std::sync::Mutex<std::collections::HashMap<String, usize>>,
    /// §96.5: remaining prepaid bytes per host for the NEXT download's
    /// pool build - the configured block minus what the ledger says is
    /// already spent, only for hosts with bytes left (a spent block
    /// goes in `excluded_hosts` instead). The fleet build seeds each
    /// server's mid-run budget from this, so a block that runs out
    /// DURING a job releases the server there and then. Recomputed by
    /// the runner at every job start, like `excluded_hosts`.
    pub host_byte_budgets: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// TODO 112 (dark, NZBFAST_LIVE_TUNE=1): per-host live connection
    /// targets, shared between each job's pool build and the epoch
    /// controller in tasks.rs. On the hub rather than per job because
    /// the controller's belief must survive job boundaries - that is
    /// the whole point of a live tuner over the offline snapshot. A
    /// prefetch sidecar runs on a fresh hub, so sidecars are never
    /// live-tuned. State, never a setting: nothing here is persisted.
    pub live_targets:
        std::sync::Mutex<std::collections::HashMap<String, Arc<nzbkit::pool::ConnTarget>>>,
    /// TODO 208 item 1: the link anchor in bytes/s the NEXT download's
    /// pool build sizes its fleet from (`linkpeak.effective`: the
    /// persisted measured peak, else the typed line speed), 0 = none.
    /// Written by the runner at every job start beside `excluded_hosts`;
    /// stays 0 on a CLI run and on a prefetch sidecar's fresh hub, where
    /// the pool's own gauge does the capping within the run instead.
    pub line_anchor_bps: std::sync::atomic::AtomicU64,
    /// The `live_tune` setting, mirrored here by the daemon (settings
    /// apply + restart restore) because the pool build in get/fleet.rs
    /// reaches the hub, not the daemon. False on a CLI run and on a
    /// prefetch sidecar's fresh hub - sidecars are never live-tuned.
    pub live_tune: std::sync::atomic::AtomicBool,
    /// M2c.5: may this run speculatively prefetch a recovery volume the
    /// moment an article goes terminally Missing? The daemon enables it
    /// per MAIN job when no quota is configured (mirrors the sidecar-
    /// prefetch guard); defaults false so sidecar/other hub users never
    /// side-fetch. CLI runs (no hub) are governed by the
    /// NZBFAST_NO_SPEC_PREFETCH env instead.
    pub spec_prefetch: std::sync::atomic::AtomicBool,
    /// M29 availability oracle: the daemon installs a fresh sink per
    /// job; get_with_progress hands it to every server's pool config and
    /// stamps the job context (pool host order + group family). The
    /// daemon drains it into the ledger at net-drain.
    pub oracle: std::sync::Mutex<Option<Arc<nzbkit::oracle::OracleSink>>>,
    /// M29 opt-in routing (`oracle_route`, OFF by default): when the
    /// daemon installs a ledger snapshot here, get_with_progress DEMOTES
    /// any enabled server whose backbone is confidently GONE for this
    /// release's (family, age-bucket) to the bottom of the level ladder,
    /// so the doomed round-trips on takedown'd content are paid last
    /// rather than first. Nothing leaves the pool, so a wrong verdict
    /// costs only latency however many backbones it writes off. See
    /// `get::plan::demote_predicted_gone` for why removal was wrong.
    pub route_gone: std::sync::Mutex<Option<nzbkit::oracle::Snapshot>>,
    /// "What is the pipeline doing right now", per owning nzo_id - the
    /// queue row's sub-line. Keyed rather than a single slot because job
    /// N's tail (verify/repair/unpack) overlaps job N+1's fetch, and both
    /// rows are live at once. Values are short tokens the dashboard maps
    /// to i18n phrases ("fetching", "verifying", "repairing",
    /// "extracting", "preflight"); the pipeline writes one at each
    /// section transition, never per article. Entries are removed at
    /// `Daemon::park`, so the map never outgrows the queue. A CLI run
    /// has no hub and a prefetch sidecar writes to its own hub, which
    /// the queue payload never reads.
    pub activity: std::sync::Mutex<std::collections::HashMap<String, &'static str>>,
    /// TODO 205: live DISK-unpack progress, per owning nzo_id and for
    /// exactly the same reason `activity` is keyed that way - job N's
    /// unpack ladder runs while job N+1 downloads, so a single slot
    /// would be the wrong job's within seconds. The in-stream path
    /// needs no entry here: its writers are on `extractor`, which
    /// belongs to whatever is downloading now, and that IS the job it
    /// is reporting for. Entries appear and vanish with the ladder's
    /// own `unpackprog::UnpackArm`, and `Daemon::park` sweeps beside
    /// `activity` as a backstop.
    pub unpack:
        std::sync::Mutex<std::collections::HashMap<String, Arc<crate::unpackprog::UnpackProgress>>>,
    /// Bytes this run will NOT fetch because the journal already has
    /// those articles on disk (a resume).
    ///
    /// Added to the shared progress counter by whoever wants "how much
    /// of this release is on disk" - the queue row, so a resumed
    /// download's bar continues from where it stopped instead of
    /// restarting at 0%. Restarting flatly contradicted the "nothing is
    /// re-downloaded" promise the failure copy makes in three places,
    /// and had testers reporting lost journals that had worked perfectly.
    ///
    /// Kept BESIDE that counter rather than added into it, because the
    /// counter is every other consumer's idea of "bytes off the wire
    /// this run": the quota ledger bills it, history divides it by
    /// network seconds, the resulting average feeds the stall watchdog's
    /// `best_rate_bps` reference, and both the CLI ticker and the
    /// daemon's rolling speed window difference it between samples. A
    /// resume that folded 40 GB into it in one instant would answer all
    /// of those with a rate no line has ever run at. Set once, before
    /// the pool starts; the daemon zeroes it per job.
    pub resume_seeded: std::sync::atomic::AtomicU64,
    /// M24 late attach (C1): a password set via mode=set_password AFTER
    /// the active download started, tagged with its owning nzo_id. The
    /// download task captures `j.password` once at the Downloading
    /// transition, so without this cell a mid-download password reached
    /// nothing until the job had already failed. `get_with_progress`
    /// re-reads it at the network-drain boundary and again at the
    /// fallback ladder, so the finish tail unlocks with it in ONE run.
    /// Owner-tagged for the same reason `extractor` is: a job
    /// transition must never hand this to the next download.
    pub late_password: std::sync::Mutex<Option<(String, String)>>,
    /// SAB-parity passwords file: the daemon mirrors the resolved
    /// `password_file` path here so the in-stream password probe can
    /// re-read it per invocation (the operator may add the password
    /// WHILE the download runs). None on CLI runs and sidecar hubs.
    pub unpack_password_file: std::sync::Mutex<Option<std::path::PathBuf>>,
    /// §99 try-order hint: the host the active job's NZB was fetched
    /// from (the failure-link origin), owner-tagged like
    /// `late_password`, so the in-stream probe can put the password
    /// last associated with that site at the head of the file's
    /// candidates. None on CLI runs and for uploaded NZBs.
    pub pw_assoc_site: std::sync::Mutex<Option<(String, String)>>,
    /// The password the in-stream probe VERIFIED for this owner (from
    /// the passwords file or a harvested sidecar). The set decrypts
    /// one-pass, so finalize never meets an encrypted volume - this
    /// cell is how the winner still gets recorded onto the Job
    /// (has_password, retry reuse), keeping the file's promise that a
    /// password that works is kept on that download.
    pub password_found: std::sync::Mutex<Option<(String, String)>>,
    /// Live "this download wants a password" signal, owner-tagged like
    /// `late_password`: set when the in-stream probe ran out of
    /// candidates for an encrypted set, cleared when one verifies (or at
    /// job teardown). queue_json surfaces it on the owning slot so the
    /// dashboard's "ask at once" mode can prompt mid-download.
    pub password_wanted: std::sync::Mutex<Option<String>>,
    /// A2 playback contract: what the byte-serving path has had to do
    /// for the player, for the mobile clients' health overlay.
    pub stream_stats: Arc<StreamStats>,
}

/// Counters the /stream read path keeps so a client can show WHY
/// playback looks the way it does (workstream A2; the hardening round
/// that produced these numbers is research/STREAM-HARDENING-2026-08.md).
///
/// Process-wide rather than per job: a reader is attached to at most one
/// job at a time and the numbers are read beside that job's own state,
/// so a second job's history cannot be mistaken for this one's - but
/// they are cumulative since start, so a client that wants a rate
/// differences two polls rather than reading an absolute.
#[derive(Default)]
pub(crate) struct StreamStats {
    /// Reads that had to wait for their span to land: the server-side
    /// count of what a viewer experiences as buffering.
    pub blocked_reads: std::sync::atomic::AtomicU64,
    /// Bytes served as zeros because the articles under them were
    /// terminally missing and nothing in flight carried them (the
    /// dead-span path). Non-zero means the picture is degraded, which
    /// no player can tell a client on its own.
    pub zero_filled_bytes: std::sync::atomic::AtomicU64,
}

impl StreamHub {
    /// UX §15: (accounted-for, planned, still to fetch) for the run that
    /// owns this hub, all three in declared NZB bytes. `None` when no run
    /// has published a plan - the gap between the daemon zeroing the pair
    /// at the Downloading transition and the pipeline filling it, where a
    /// caller must fall back rather than divide by a plan belonging to
    /// nobody.
    pub fn fetch_left(&self) -> Option<(u64, u64, u64)> {
        self.fetch_counters().left()
    }

    /// The pair the run that owns this hub counts into. A pipeline takes
    /// this once at its start and keeps the handles.
    pub fn fetch_counters(&self) -> Arc<FetchCounters> {
        self.fetch.lock_ok().clone()
    }

    /// Install a zeroed pair for the job taking the hub over and return
    /// it. The previous owner's handles keep counting into the previous
    /// pair, which nothing reads any more.
    pub fn fresh_fetch_counters(&self) -> Arc<FetchCounters> {
        let fresh = Arc::new(FetchCounters::default());
        *self.fetch.lock_ok() = fresh.clone();
        fresh
    }

    /// Clone the installed extractor, but only when it belongs to `want`.
    /// `want = None` is the M11 active-download stream, which owns whatever
    /// is installed. For `want = Some(id)` the tag must match, so the owner
    /// check and the clone happen under ONE lock - a job transition that has
    /// published the new owner but not yet installed its extractor (or still
    /// has the old one installed) returns None here, so a request never
    /// receives another job's extractor.
    pub fn extractor_for(&self, want: Option<&str>) -> Option<Arc<nzbkit::extract::Extractor>> {
        let g = self.extractor.lock_ok();
        let (owner, ex) = g.as_ref()?;
        match want {
            Some(id) if id != owner => None,
            _ => Some(ex.clone()),
        }
    }

    /// The late-attached password, when it belongs to `owner` - same
    /// ownership rule as [`Self::extractor_for`]. A peek, not a take:
    /// the finish tail consults it at two points (network drain and the
    /// fallback ladder) and both must see it; the next job never can,
    /// because its owner tag differs and job start clears the cell.
    pub fn late_password_for(&self, owner: &str) -> Option<String> {
        let g = self.late_password.lock_ok();
        let (tag, pw) = g.as_ref()?;
        (tag == owner).then(|| pw.clone())
    }

    /// §99: the NZB source host for `owner`, same ownership rule - a
    /// stale hint must never order another job's candidates.
    pub fn pw_assoc_site_for(&self, owner: &str) -> Option<String> {
        let g = self.pw_assoc_site.lock_ok();
        let (tag, host) = g.as_ref()?;
        (tag == owner).then(|| host.clone())
    }

    /// The warm connection pool, created on first use (it spawns a
    /// keepalive tick, so it needs a runtime and cannot be built by
    /// `Default`). `NZBFAST_WARM_POOL=0` forces it off everywhere.
    ///
    /// §36: this only ever runs for a server whose own `warm_pool` is
    /// set - the caller gates it. Reaching here does NOT mean pooling is
    /// on for the job, only that this server asked for it.
    ///
    /// The per-server cap is deliberately generous rather than tied to
    /// the configured `connections`: the fleet that parks connections was
    /// already sized by the account limit, so it cannot overshoot, while
    /// a cap read from a config that has since SHRUNK would silently
    /// evict live connections mid-run. Shrinking `connections` instead
    /// resolves itself through the idle timeout.
    pub fn warm(&self) -> Option<Arc<nzbkit::warmpool::WarmPool>> {
        if std::env::var("NZBFAST_WARM_POOL").is_ok_and(|v| v == "0") {
            return None;
        }
        Some(
            self.warm
                .get_or_init(|| {
                    nzbkit::warmpool::WarmPool::new(
                        nzbkit::warmpool::DEFAULT_MAX_IDLE,
                        nzbkit::warmpool::MAX_PER_SERVER,
                    )
                })
                .clone(),
        )
    }
}

/// M11: translates OUTPUT-file byte ranges (what a media player reads)
/// back to pending pool articles and moves them to the queue front. Line
/// rate ≫ any media bitrate, so a promoted 32 MB window lands in well
/// under a second of line time - seeks feel instant.
pub(crate) struct SeekCtl {
    /// Per slot: (encoded cumulative start, bracketed message-id) per
    /// segment in file order - empty for par2 slots - plus the slot's
    /// total encoded bytes. Offsets are NZB-declared (encoded) sizes;
    /// callers scale decoded positions proportionally, and ±2 articles of
    /// slack absorb the yEnc-overhead estimate error.
    ///
    /// R9: the ids are the interned handles the fetch plan built, not a
    /// second copy of the id set. This ladder covers EVERY data segment
    /// in the job, so as `String` it was a full duplicate of the run's
    /// ids - ~8-15 MB at 100k segments, allocated on every run whether
    /// or not anything ever streamed - and every span read cloned its
    /// slice of it again.
    pub(crate) slot_articles: Vec<(Vec<(u64, Arc<str>)>, u64)>,
    pub(crate) ctl: Arc<nzbkit::pool::QueueControl>,
    pub(crate) extractor: Arc<nzbkit::extract::Extractor>,
    /// Volume-sorted non-par2 slot indices (NZB metadata, known before a
    /// single article lands). The last-resort span mapping: the
    /// extractor's map needs at least each volume's parsed header, so a
    /// span in a not-yet-classified volume (the file TAIL at play start,
    /// racing the header probes) would otherwise map to nothing - and a
    /// promote missing the tail displaces the tail-burst articles.
    pub(crate) vol_slots: Vec<usize>,
    /// Sanitized NZB filename hint → slot, non-par2 slots only. A promote
    /// for a slot FILE that hasn't classified (the extractor's offset-0
    /// probe, a top-level chase) maps to nothing in `map_output_range`;
    /// resolving it against that one slot's own article ladder beats the
    /// zero-knowledge fallback, which scales the span across the
    /// concatenation of EVERY volume and lands in the wrong file for any
    /// multi-slot set. Hint-keyed; the promote's name is the yEnc one
    /// (`sanitize_filename(slot.name)`), so an obfuscated post whose
    /// yEnc names differ from its subject hints misses here and resolves
    /// through `observed_by_name` instead.
    pub(crate) slot_by_name: std::collections::HashMap<String, usize>,
    /// Sanitized yEnc-declared name → slot, the obfuscated-post overlay
    /// for the same lookup: garbage subjects, real yEnc names. The
    /// decode consumers register each slot's observed name here via
    /// [`Self::note_slot_name`] before the write that can fire the
    /// slot's offset-0 probe, so a slot-FILE promote resolves against
    /// the right slot's own ladder instead of the every-volume fallback.
    pub(crate) observed_by_name: std::sync::RwLock<std::collections::HashMap<String, usize>>,
    /// Per-slot latch for `note_slot_name` (aligned with
    /// `slot_articles`): set (Release) only AFTER the name is in the
    /// map, so a decoder that skips on the fast path can trust the map
    /// is populated before its own write's probe fires.
    pub(crate) observed: Vec<std::sync::atomic::AtomicBool>,
}

impl SeekCtl {
    /// A live /stream reader touched us: keep the pool's stream mode
    /// (shallow pipelines, see pool.rs) fresh so any promotion - this
    /// read's or a later seek's - preempts instead of queueing behind
    /// deep in-flight windows.
    pub fn note_stream(&self) {
        self.ctl.note_stream_active();
    }

    /// Promote the pending articles carrying output bytes of `name` (a
    /// slot file or an extracted inner file) for every span, in span
    /// order - promote() front-loads the queue in exactly the order
    /// given, which is the order the player reads (playhead span first,
    /// then the file tail). One promote per call: the stream layer keeps
    /// the playhead window AND the still-uncovered tail (MKV Cues / MP4
    /// moov) hot together - a playhead-only promote would displace the
    /// tail-burst articles a player is about to ask for. `file_size`
    /// (the caller's writer knows it) anchors the NZB-ladder fallback
    /// for spans in volumes the extractor hasn't classified yet.
    /// `engage_stream` passes through to the pool: streaming readers and
    /// blocked chase workers flip it into shallow pipelines; the
    /// extractor's non-urgent offset-0 probes only reorder the queue.
    pub fn promote_output_spans(
        &self,
        name: &str,
        file_size: u64,
        spans: &[(u64, u64)],
        engage_stream: bool,
    ) -> usize {
        let ids = self.map_span_ids(name, file_size, spans);
        // promote() ranks by first occurrence, so cross-span duplicates
        // are harmless.
        self.ctl.promote_opts(&ids, engage_stream)
    }

    /// Can any byte of output span [start, start+len) of `name` still be
    /// delivered by the fetch run attached right now?
    ///
    /// - `Some(true)`: something live carries it (or we cannot rule that
    ///   out - an unmapped span and a missed lock both land here).
    /// - `Some(false)`: the span maps to articles and NONE of them is
    ///   pending or in flight - all terminal (430'd everywhere, out of
    ///   retries), so nothing short of settle-side repair will ever
    ///   cover those bytes.
    /// - `None`: no pool attached - the run ended (or has not started);
    ///   only repair can change the file now, and the caller decides how
    ///   long repair deserves.
    ///
    /// The mapping carries the same ±article slack the promotes use, and
    /// slack articles count as live - so a span is only ever declared
    /// dead a little LATE, never early.
    pub fn span_deliverable(
        &self,
        name: &str,
        file_size: u64,
        start: u64,
        len: u64,
    ) -> Option<bool> {
        let ids = self.map_span_ids(name, file_size, &[(start, start + len)]);
        if ids.is_empty() {
            return Some(true);
        }
        self.ctl.any_live(&ids)
    }

    /// The pending-article ids carrying output bytes of `name` for every
    /// span, in span order - the mapping behind [`Self::promote_output_spans`]
    /// and [`Self::span_deliverable`].
    pub(crate) fn map_span_ids(
        &self,
        name: &str,
        file_size: u64,
        spans: &[(u64, u64)],
    ) -> Vec<Arc<str>> {
        let mut ids: Vec<Arc<str>> = Vec::new();
        for &(start, end) in spans {
            if start >= end {
                continue;
            }
            let mapped = self.extractor.map_output_range(name, start, end);
            if mapped.is_empty() {
                // Not an output the extractor can map. When the name is a
                // SLOT file (offset-0 probe / top-level chase before
                // classification), its byte space is that one slot's -
                // resolve against its own ladder.
                let si = self.slot_by_name.get(name).copied().or_else(|| {
                    // Obfuscated set: the promote's name is the yEnc-
                    // declared one and the subject hints are garbage -
                    // fall to the names the decode consumers observed.
                    self.observed_by_name.read_ok().get(name).copied()
                });
                if let Some(si) = si
                    && let Some((arts, enc_total)) = self.slot_articles.get(si)
                    && !arts.is_empty()
                    && *enc_total > 0
                    && file_size > 0
                {
                    let scale = |v: u64| (v as f64 / file_size as f64 * *enc_total as f64) as u64;
                    let (es, ee) = (scale(start), scale(end.min(file_size)));
                    let lo = arts.partition_point(|(o, _)| *o <= es).saturating_sub(2);
                    // +3 of forward slack (one more than the
                    // mapped path): the offset-0 probe's rotation
                    // guess undershoots by however many articles
                    // beat the head to the slot, never overshoots.
                    let hi = (arts.partition_point(|(o, _)| *o < ee) + 3).min(arts.len());
                    for (_, id) in &arts[lo..hi] {
                        ids.push(id.clone());
                    }
                    continue;
                }
                // No volume covering this span has classified yet (its
                // header article is still in flight - routine in the
                // first seconds, exactly when the player probes the
                // tail). Estimate from NZB metadata alone.
                self.ladder_fallback(file_size, start, end, &mut ids);
                continue; // next span
            }
            // map_output_range returns pieces sorted by output offset, so
            // pushing in iteration order preserves player-read order.
            for (slot, vs, ve, vsize) in mapped {
                let Some((arts, enc_total)) = self.slot_articles.get(slot) else {
                    continue;
                };
                if arts.is_empty() || *enc_total == 0 {
                    continue;
                }
                // Decoded volume offset → encoded article ladder
                // (proportional; yEnc overhead is uniform within a file).
                let scale = |v: u64| {
                    if vsize > 0 {
                        (v as f64 / vsize as f64 * *enc_total as f64) as u64
                    } else {
                        v
                    }
                };
                let (es, ee) = (scale(vs), scale(ve));
                let lo = arts.partition_point(|(o, _)| *o <= es).saturating_sub(2);
                let hi = (arts.partition_point(|(o, _)| *o < ee) + 1).min(arts.len());
                for (_, id) in &arts[lo..hi] {
                    ids.push(id.clone());
                }
            }
        }
        ids
    }

    /// Register the yEnc-declared name observed for `slot`'s articles.
    /// The decode consumers call this once per article BEFORE the
    /// `write_verified` that can fire the slot's offset-0 probe (the
    /// probe promotes by `sanitize_filename(slot.name)`, i.e. exactly
    /// this name); the latch makes the steady-state cost one atomic
    /// load. Without it, an obfuscated multi-volume set's probe missed
    /// the hint-keyed map and scaled its span across EVERY volume -
    /// promoting the wrong file's articles, so each slot classified
    /// only when its true head arrived naturally and spilled first.
    pub fn note_slot_name(&self, slot: usize, name: &str) {
        let Some(flag) = self.observed.get(slot) else {
            return;
        };
        if flag.load(Ordering::Acquire) {
            return;
        }
        let key = nzbkit::disk::sanitize_filename(name);
        // Skip the overlay when the hint map already resolves this name
        // to this slot (honest posts - the overlay stays empty). First
        // insertion wins on a cross-slot duplicate, like the hint map.
        if self.slot_by_name.get(&key) != Some(&slot) {
            self.observed_by_name.write_ok().entry(key).or_insert(slot);
        }
        flag.store(true, Ordering::Release);
    }

    /// Zero-knowledge span mapping: scale output-file offsets onto the
    /// concatenated encoded ladders of the volume-sorted data slots (pure
    /// NZB metadata). Coarser than the extractor's map - yEnc overhead
    /// and volume headers skew it slightly - so take a generous ±4
    /// articles of slack per edge.
    pub(crate) fn ladder_fallback(
        &self,
        file_size: u64,
        start: u64,
        end: u64,
        ids: &mut Vec<Arc<str>>,
    ) {
        let total_enc: u64 = self
            .vol_slots
            .iter()
            .filter_map(|&s| self.slot_articles.get(s))
            .map(|(_, t)| t)
            .sum();
        if file_size == 0 || total_enc == 0 {
            return;
        }
        let to_enc = |v: u64| (v as f64 / file_size as f64 * total_enc as f64) as u64;
        let (gs, ge) = (to_enc(start), to_enc(end.min(file_size)));
        let mut base = 0u64;
        for &si in &self.vol_slots {
            let Some((arts, enc_total)) = self.slot_articles.get(si) else {
                continue;
            };
            if *enc_total == 0 || arts.is_empty() {
                continue;
            }
            let (slot_lo, slot_hi) = (base, base + enc_total);
            base += enc_total;
            if ge <= slot_lo || gs >= slot_hi {
                continue;
            }
            let (es, ee) = (gs.saturating_sub(slot_lo), (ge - slot_lo).min(*enc_total));
            let lo = arts.partition_point(|(o, _)| *o <= es).saturating_sub(4);
            let hi = (arts.partition_point(|(o, _)| *o < ee) + 4).min(arts.len());
            for (_, id) in &arts[lo..hi] {
                ids.push(id.clone());
            }
        }
    }
}
