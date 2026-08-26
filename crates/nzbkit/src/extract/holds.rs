//! Pre-sniff holds and their relief valve: the held-bytes budget,
//! the scratch file held spans page to when the cap is hit, the
//! drain that replays held bytes into the parser, and the spill of
//! never-classified slots to plain files.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43
//! recipe: a verbatim move, not a redesign.

use super::*;
use crate::sync::MutexExt;
use std::sync::OnceLock;
use tracing::info;

/// Default total bytes of held (not-yet-mappable) spans before a group
/// falls back to materialized volumes, used when NOTHING published a
/// process budget. Memory is the cache tier and the header-first
/// scheduling keeps real holds small; this is the safety net. Overridden
/// by the MemBudget slice (`set_holds_cap`), and by
/// [`default_holds_cap`] whenever an entry point sized the process.
pub(super) const HOLDS_DEFAULT_CAP: usize = 2 << 30;

/// Floor under any holds cap, raw (`set_holds_cap`) or ledger-reduced.
pub(super) const HOLDS_CAP_FLOOR: usize = 8 << 20;

/// The cap a freshly-built [`Extractor`] starts with: the published
/// budget's 45% slice if an entry point sized this process, else the flat
/// [`HOLDS_DEFAULT_CAP`] (TODO 260).
///
/// The asymmetry this closes cost a measurement day. `set_process_budget`
/// is read implicitly by the repair paths, `rar_read_options` and the
/// LZMA gauge, so it LOOKS like the way to size a pipeline - but the
/// extractor took its cap only from `set_holds_cap`, which lives on the
/// download path alone (`crates/nzbfast/src/get/vrig.rs`). The TODO 209
/// dict-window rig pinned 256 MiB, built a bare `Extractor::new`, and
/// actually chased against 2 GiB; the unbounded container buffering that
/// produced was written up as an untracked allocation wanting a new
/// budget tier or a disk spill. It was neither - wiring the production
/// cap let the existing trim/forfeit ladder bound it, 315 -> 187 MiB peak
/// with one demote (TODO 256,
/// `research/NOTE-2026-08-22-nested-container-buffer-rss.md`).
///
/// Reading [`crate::mem::published_budget`] rather than
/// [`crate::mem::process_budget`] is the whole design. `process_budget`
/// falls back to `MemBudget::auto` - RAM/4, clamped to [256 MiB, 16 GiB] -
/// so a default routed through it would hand a 4 GB CI runner a 460 MiB
/// cap and this dev box a 7.2 GiB one, and every holds-sensitive extract
/// test would pass or demote according to the host it ran on. Nothing
/// publishes a budget in a unit test, so `None` keeps the whole existing
/// suite byte-identical to the flat 2 GiB it was written against, while
/// every real entry point (`serve`, the CLI's `run`, `embedded_init`) and
/// any rig that says `set_process_budget` gets the honest slice.
///
/// Considered and rejected: making the omission loud instead (a
/// `debug_assert` on the download path, or a `new_with_budget` ctor). The
/// download path is the ONE site that already sets the cap, so an assert
/// there guards the case that was never wrong; and a second constructor
/// only moves the choice, leaving `Extractor::new` still silently
/// generous for the next rig that reaches for it.
pub(super) fn default_holds_cap() -> usize {
    crate::mem::published_budget()
        .map(|b| b.holds_cap())
        .unwrap_or(HOLDS_DEFAULT_CAP)
        .max(HOLDS_CAP_FLOOR)
}

/// Held-span accounting shared across the whole extractor CHAIN: a child
/// extractor's holds charge the same budget as its parent's, so a nested
/// post can't balloon RSS to depth x cap. Atomics rather than a field
/// under the routing lock because parent and child each have their own
/// lock; peak reporting is naturally the chain-wide peak.
pub(super) struct HoldsBudget {
    pub(super) bytes: AtomicUsize,
    pub(super) cap: AtomicUsize,
    pub(super) peak: AtomicUsize,
    /// Process-wide sharing seat ([`HoldsLedger`]): set once when the
    /// root extractor joins the daemon's ledger, never for `get`, the
    /// repair path or unit tests. Unset, `cap()` is the raw cap.
    pub(super) seat: OnceLock<(Arc<HoldsLedger>, u64)>,
}

impl HoldsBudget {
    pub(super) fn new(cap: usize) -> HoldsBudget {
        HoldsBudget {
            bytes: AtomicUsize::new(0),
            cap: AtomicUsize::new(cap),
            peak: AtomicUsize::new(0),
            seat: OnceLock::new(),
        }
    }

    pub(super) fn add(&self, n: usize) {
        let now = self.bytes.fetch_add(n, Ordering::Relaxed) + n;
        self.peak.fetch_max(now, Ordering::Relaxed);
        // Memory-floor gauge mirror (instrument-first): process-wide twin
        // of this budget's charge, sampled beside the untracked tiers.
        crate::memgauge::add(crate::memgauge::Sub::Holds, n as u64);
    }

    pub(super) fn sub(&self, n: usize) {
        self.bytes.fetch_sub(n, Ordering::Relaxed);
        crate::memgauge::sub(crate::memgauge::Sub::Holds, n as u64);
    }

    pub(super) fn over(&self) -> bool {
        self.bytes.load(Ordering::Relaxed) > self.cap()
    }

    /// The EFFECTIVE cap: the raw cap, less whatever the pipelines
    /// senior to this one on the process ledger currently hold, floored
    /// at the 8 MB `set_holds_cap` floors at. Unseated (no ledger, or
    /// the eldest seat) this is the raw cap exactly - the single-job
    /// behaviour is byte-identical to before the ledger existed.
    pub(super) fn cap(&self) -> usize {
        let raw = self.cap.load(Ordering::Relaxed);
        match self.seat.get() {
            None => raw,
            Some((ledger, id)) => raw
                .saturating_sub(ledger.senior_bytes(*id))
                .max(HOLDS_CAP_FLOOR),
        }
    }

    pub(super) fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    pub(super) fn len(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }
}

/// One held span's bytes: in RAM (charging [`HoldsBudget`]) or paged out
/// to the chain's scratch file (charging [`HoldsScratch`]). Paging is the
/// budget-breach relief valve: the span keeps its slot MAPPED - it stays
/// visible to `covered`/`read_at` and re-feeds on drain exactly like a RAM
/// span, with one pread - so a set that would have demoted on the cap
/// still extracts one-pass.
pub(super) enum HoldSpan {
    Ram(Vec<u8>),
    Paged { off: u64, len: usize },
}

impl HoldSpan {
    pub(super) fn len(&self) -> usize {
        match self {
            HoldSpan::Ram(b) => b.len(),
            HoldSpan::Paged { len, .. } => *len,
        }
    }
}

/// Same-directory scratch prefix for paged held spans. The leading
/// `.nzbfast` is the established internal-scratch marker - it keeps the
/// cleanup walkers and the keep-media-only sweep off the file - and pid +
/// counter make each name unique to one run of one process. The finish
/// decrypt's `DEC_TMP_PREFIX` was the other user of the convention until
/// TODO 27 phase 3 deleted that pass.
pub(super) const HOLDS_TMP_PREFIX: &str = ".nzbfast-holds.";

/// Remove holds scratch left behind by a killed run. Root construction
/// only - a child sweeping would unlink the root's live file.
pub(super) fn sweep_holds_scratch(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        if e.file_name()
            .to_string_lossy()
            .starts_with(HOLDS_TMP_PREFIX)
        {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The chain's held-span scratch file, shared root-to-children like the
/// [`HoldsBudget`] it relieves. Created lazily on first page; regions are
/// append-only and WRITE-ONCE (a region is never rewritten while any
/// span references it), which is what makes the deferred preads in
/// `read_at` safe off the routing lock. Space reclaim is deliberately
/// crude: when nothing live remains and no reader is pinned, the cursor
/// resets and the file truncates - bounding the drain/re-hold/re-page
/// ping-pong without a free-list.
///
/// EVERY piece of mutable state (file, cursor, live, pins) lives under
/// the one `state` mutex, on purpose. "Under the routing lock" is not a
/// synchronization boundary here: the scratch is CHAIN-shared while
/// routing locks are per-level, so a parent release and a child append
/// run concurrently. An earlier draft kept `live`/`pins` as Relaxed
/// atomics checked partly outside the mutex - the 31 Jul race audit
/// found a reachable interleaving where a reader pin born inside
/// `release`'s check-to-truncate window was ignored and a planned pread
/// read truncated (or reused) bytes. Every path that touches this state
/// is cold (paging, drains, planning a paged read), so the mutex costs
/// nothing and makes the gates sequentially consistent by construction.
pub(super) struct HoldsScratch {
    pub(super) dir: PathBuf,
    pub(super) state: Mutex<ScratchState>,
    /// Bytes ever paged (diagnostics/tests; monotonic).
    pub(super) paged_total: AtomicU64,
    /// Reads served through [`Self::read`] - the route that preads
    /// while its caller still holds a lock (monotonic). A deferred
    /// `Plan::S` goes straight to the handle and never bumps this,
    /// which is the difference the chase-arm test stands on. Test-only:
    /// nothing in production reads it, so it costs a release build
    /// neither the field nor the increment.
    #[cfg(test)]
    pub(super) locked_reads: AtomicU64,
    /// Hard ceiling on the append cursor. 0 = auto (4x the holds RAM cap,
    /// resolved at page time so a later `set_holds_cap` is respected).
    pub(super) cap: AtomicU64,
    /// Latched on any scratch I/O error: paging is off for the rest of
    /// the run and every breach demotes exactly as before paging existed.
    pub(super) dead: AtomicBool,
    /// First-engage log line, once per run.
    pub(super) announced: AtomicBool,
}

pub(super) struct ScratchState {
    /// Lazily-created file. The `Arc` is what a deferred read plan
    /// carries out from under the locks.
    pub(super) file: Option<Arc<(PathBuf, File)>>,
    /// Append cursor; resets to 0 when idle (live == 0, pins == 0).
    pub(super) cursor: u64,
    /// Bytes of live paged spans - every `HoldSpan::Paged` anywhere in
    /// the chain holds exactly one charge here. Nonzero blocks the idle
    /// reset, so a referenced region is never overwritten or truncated.
    pub(super) live: u64,
    /// Readers holding deferred pread plans (pinned at plan time,
    /// released after the preads land). Nonzero blocks the idle reset,
    /// protecting a planned region whose span has since been released.
    pub(super) pins: usize,
}

impl HoldsScratch {
    pub(super) fn new(dir: &Path) -> HoldsScratch {
        HoldsScratch {
            dir: dir.to_path_buf(),
            state: Mutex::new(ScratchState {
                file: None,
                cursor: 0,
                live: 0,
                pins: 0,
            }),
            paged_total: AtomicU64::new(0),
            #[cfg(test)]
            locked_reads: AtomicU64::new(0),
            cap: AtomicU64::new(0),
            dead: AtomicBool::new(false),
            announced: AtomicBool::new(false),
        }
    }

    /// Poison-tolerant state lock: the readers/releasers must keep
    /// working after some other thread panicked mid-scratch (same
    /// argument as [`Extractor::inner_read`]).
    pub(super) fn st(&self) -> std::sync::MutexGuard<'_, ScratchState> {
        self.state.lock_ok()
    }

    /// Append one span's bytes; `cap` is the effective ceiling (the
    /// caller resolves auto). Returns the region offset, or None when the
    /// ceiling refuses (caller demotes with today's reason) - an I/O
    /// error additionally latches the scratch dead.
    pub(super) fn append(&self, bytes: &[u8], cap: u64) -> Option<u64> {
        if self.dead.load(Ordering::Relaxed) {
            return None;
        }
        let mut st = self.st();
        if st.file.is_none() {
            match Self::create(&self.dir) {
                Ok(pf) => st.file = Some(Arc::new(pf)),
                Err(_) => {
                    self.dead.store(true, Ordering::Relaxed);
                    return None;
                }
            }
        }
        // Idle reset: nothing live and nobody reading - every byte below
        // the cursor is dead, so reuse the space.
        if st.live == 0 && st.pins == 0 {
            st.cursor = 0;
        }
        if st.cursor.saturating_add(bytes.len() as u64) > cap {
            return None;
        }
        let f = st.file.as_ref().unwrap().clone();
        if crate::disk::write_all_at(&f.1, bytes, st.cursor).is_err() {
            self.dead.store(true, Ordering::Relaxed);
            return None;
        }
        let off = st.cursor;
        st.cursor += bytes.len() as u64;
        st.live += bytes.len() as u64;
        self.paged_total
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Some(off)
    }

    pub(super) fn create(dir: &Path) -> io::Result<(PathBuf, File)> {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let pid = std::process::id();
        for _ in 0..4096 {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("{HOLDS_TMP_PREFIX}{pid}.{n}.tmp"));
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(f) => return Ok((path, f)),
                // PermissionDenied too: on classic-delete-semantics
                // Windows (pre-1903, FAT/exFAT, SMB) a swept-but-still-
                // open stale file is delete-pending, and create_new on
                // that name reports ERROR_ACCESS_DENIED rather than
                // AlreadyExists - advance to the next seq instead of
                // latching paging dead for the whole run.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "no free holds scratch name in the output directory",
        ))
    }

    /// The file handle for deferred reads, cloned out at plan time (pin
    /// first - see `ScratchState::pins`).
    pub(super) fn handle(&self) -> Option<Arc<(PathBuf, File)>> {
        self.st().file.clone()
    }

    /// Read a paged region back (drain paths, under some routing lock).
    pub(super) fn read(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        #[cfg(test)]
        self.locked_reads.fetch_add(1, Ordering::Relaxed);
        let f = self
            .handle()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "holds scratch file missing"))?;
        crate::disk::read_exact_at(&f.1, buf, off)
    }

    /// Transfer a rebind's live charge in (see `rebind_subranges`): the
    /// subrange keeps referencing its region, so the region's protection
    /// must be added BEFORE the original span's `release` subtracts.
    pub(super) fn add_live(&self, len: usize) {
        self.st().live += len as u64;
    }

    /// A paged span was consumed (drained, discarded, abandoned). When
    /// the last live byte goes and no reader is pinned, the file
    /// truncates - space back, handle and name kept for a later page.
    /// Both gates read under the state mutex: a pin is taken under this
    /// same mutex, so a reader that planned before we got here is always
    /// visible (the earlier outside-the-mutex pins check was the race
    /// the 31 Jul audit caught).
    pub(super) fn release(&self, len: usize) {
        let mut st = self.st();
        st.live -= len as u64;
        if st.live == 0 && st.pins == 0 {
            st.cursor = 0;
            if let Some(f) = st.file.as_ref() {
                let _ = f.1.set_len(0);
            }
        }
    }

    /// Root finish/Drop: unlink the scratch NAME but keep the handle, so
    /// a straggler read of a still-paged span (a healthy group's header
    /// stash outlives settle) is served through the open file until the
    /// extractor drops. The disk space goes with the last handle; the
    /// construction-time sweep covers a killed run.
    pub(super) fn cleanup(&self) {
        let st = self.st();
        if let Some(f) = st.file.as_ref() {
            let _ = std::fs::remove_file(&f.0);
        }
    }
}

/// Spans smaller than this stay in RAM at page time - not worth the
/// syscall, and tiny spans are exactly the ones about to resolve.
pub(super) const HOLDS_PAGE_MIN: usize = 4 * 1024;

/// Reader pin over the holds scratch: taken (under the state mutex) when
/// `read_at` plans a pread of a paged span, released after the pread
/// lands. While any pin is held the scratch never resets its cursor or
/// truncates, so a planned region stays byte-stable off the locks.
pub(super) struct ScratchPin(Option<Arc<HoldsScratch>>);

impl ScratchPin {
    pub(super) fn none() -> ScratchPin {
        ScratchPin(None)
    }

    pub(super) fn pin(&mut self, sc: &Arc<HoldsScratch>) {
        if self.0.is_none() {
            sc.st().pins += 1;
            self.0 = Some(sc.clone());
        }
    }
}

impl Drop for ScratchPin {
    fn drop(&mut self) {
        if let Some(sc) = &self.0 {
            sc.st().pins -= 1;
        }
    }
}

/// `NZBFAST_NO_HOLDS_PAGE=1` restores the pre-paging behavior: every
/// budget breach demotes. Split for testability like the chase gates.
pub(super) fn holds_page_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

pub(super) fn holds_page_env_off() -> bool {
    holds_page_env_off_value(std::env::var("NZBFAST_NO_HOLDS_PAGE").ok().as_deref())
}

/// How many offset-0 probes ONE slot may fire (see
/// [`Extractor::probe_offset0`]). One is the old one-shot; the rest are
/// re-issues, each paid for by a strictly lower arrived offset.
pub(super) const PROBE0_MAX: u8 = 4;

/// How deep into a slot a re-issue may still fire, in held spans. The
/// correction a re-issue is chasing is the slot's own `head_ids`
/// article arriving late, which is a first-round-trips event; past this
/// many of the slot's articles, a lower offset is likelier the ladder
/// WRAPPING - under a rot-k ladder the declared positions PAST the head
/// carry offsets `0..(k-1)*A`, below the head_ids article's `k*A`, so
/// re-aiming on one walks the guess PAST the head instead of onto it
/// (`map_span_ids` allows only 2 articles of backward slack). A real
/// volume is hundreds of articles, so its wrap can never reach this
/// window; a file small enough that it can is a couple of articles of
/// misfetch either way.
pub(super) const PROBE0_WINDOW: usize = 16;

/// `NZBFAST_NO_HEAD_GRACE=1` restores the pre-grace behaviour: a slot
/// still waiting for its offset-0 sniff spills at [`unclassified_spill`]
/// even when the holds slice has room for it. Split for testability like
/// the paging gate above.
pub(super) fn head_grace_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

pub(super) fn head_grace_env_off() -> bool {
    head_grace_env_off_value(std::env::var("NZBFAST_NO_HEAD_GRACE").ok().as_deref())
}

/// Per-slot budget for spans held while a slot is still unclassified
/// (waiting for its offset-0 sniff). Honest posts fetch each file's first
/// segment within the first round-trips (M3 scheduling), so real holds
/// stay a few articles deep; an NZB with synthesized segment numbering
/// never delivers offset 0 early and would pile the whole file here.
/// A quarter of the holds slice, floored at 4 MB.
///
/// The ceiling scales with the budget on purpose - it used to be a flat
/// 64 MB, and that flat number was a 3x I/O bug on damaged jobs
/// (bench settle round, 11 Aug 2026, a big-RAM desktop against five
/// real backbones): one RAR volume whose offset-0
/// article ran late spilled to Plain at 64 MB against a 7.7 GB holds
/// slice, and a damaged-but-unmapped file makes `try_mapped_repair`
/// decline the WHOLE set - every volume then materialized for a
/// disk-fed repair + re-extract pass (~18 GB of disk traffic for a
/// 6.5 GB post, at 96% free budget). A box with gigabytes of holds
/// room should ride out a late sniff; a small-RAM box keeps today's
/// early spill because its budget slice is small, and a global breach
/// still pages to scratch (or demotes) exactly as before.
pub(super) fn unclassified_spill(holds_cap: usize) -> usize {
    (holds_cap / 4).max(4 << 20)
}

/// Chain-wide RAM window for spans parked while a password probe may
/// still rescue their slot (`pw_await`). Parked ciphertext is cold by
/// construction - nothing reads it until a probe hit or finish - so it
/// must not ride RAM up to the holds cap: a header-encrypted set with
/// no password parks its ENTIRE payload, and on a big-RAM box the 45%
/// budget slice let a 1.6 GB set sit fully resident (the 2026-08-10
/// bench's peak-RSS outlier). The 64 MB ceiling is deliberate and must
/// scale with NOTHING: unlike a late-sniff hold, paging parked spans
/// never costs the set its one-pass rescue (a probe hit re-feeds them
/// from scratch), so a bigger budget buys no reason to keep more of
/// them resident.
pub(super) fn pw_await_spill(holds_cap: usize) -> usize {
    (holds_cap / 4).clamp(4 << 20, 64 << 20)
}

/// Chain-wide RAM window for a chased RAR set once the job has articles
/// with TERMINAL verdicts (430 everywhere, out of retention, transport
/// dead). The sequential decode wedges at the first unfillable gap, so
/// every frontier byte beyond it is as cold as parked ciphertext - the
/// pw_await argument exactly - yet it used to ride RAM to the holds cap:
/// 45% of a big box's budget let a damaged 3.5 GB compressed set sit
/// fully resident for the whole download (the 11 Aug 2026 soak's RSS
/// stair). Beyond this window the cold spans page to the holds scratch
/// ([`Extractor::page_wedged_chase`]); a gap that later fills (retry,
/// PAR2 repair) reads them back through the frontier buffer's paged
/// serving, and a demote materializes volumes from scratch byte-exact.
/// Same deliberate non-scaling ceiling as [`pw_await_spill`], for the
/// same reason: paging cold chase bytes never costs the set anything
/// but preads on the rescue path, so a bigger budget buys no reason to
/// keep more of them resident.
/// Is this posted name shaped like an archive volume - one of a
/// numbered set ([`vol_sort_key`] ranks everything except `u64::MAX`),
/// or a bare `.zip`/`.7z` container? The late-head grace's population:
/// these are the slots whose sniff is worth waiting for, because losing
/// it costs the set its in-place extraction rather than just deferring
/// a plain file's writes.
pub(super) fn volume_shaped_name(name: &str) -> bool {
    if vol_sort_key(name).0 != u64::MAX {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".zip") || lower.ends_with(".7z")
}

pub(super) fn chase_stall_spill(holds_cap: usize) -> usize {
    (holds_cap / 4).clamp(4 << 20, 64 << 20)
}

impl Extractor {
    /// M15: set the held-span budget slice (spill: materialize volumes).
    /// The budget is shared with any nested children.
    pub fn set_holds_cap(&self, cap: usize) {
        self.inner
            .lock_ok()
            .budget
            .cap
            .store(cap.max(HOLDS_CAP_FLOOR), Ordering::Relaxed);
    }

    /// Seat this extractor's holds budget on a process-wide
    /// [`HoldsLedger`] so pipelines alive at once share ONE cap (TODO
    /// 219 follow-up). Root only, once; a nested child shares the
    /// parent's budget and so its seat. Joining twice keeps the first
    /// seat.
    pub fn join_holds_ledger(&self, ledger: &Arc<HoldsLedger>) {
        let budget = self.inner.lock_ok().budget.clone();
        let _ = budget
            .seat
            .get_or_init(|| (ledger.clone(), ledger.join(&budget)));
    }

    /// The chain's holds budget - ledger tests only.
    #[cfg(test)]
    pub(super) fn holds_budget_for_tests(&self) -> Arc<HoldsBudget> {
        self.inner.lock_ok().budget.clone()
    }

    /// Holds-paging gate (see `NZBFAST_NO_HOLDS_PAGE`, latched at
    /// construction; default on). Same set-before-spans discipline as the
    /// other gates. Off: a holds-budget breach demotes exactly as before
    /// paging existed.
    pub fn set_holds_paging(&self, on: bool) {
        self.inner.lock_ok().holds_page_on = on;
    }

    /// Late-head grace gate (see `NZBFAST_NO_HEAD_GRACE`, latched at
    /// construction; default on). Off: a slot whose offset-0 sniff has
    /// not arrived spills at [`unclassified_spill`] exactly as it did
    /// before the grace existed.
    pub fn set_head_grace(&self, on: bool) {
        self.inner.lock_ok().head_grace_on = on;
    }

    /// Hard ceiling on the held-span scratch file, shared down the chain
    /// like the RAM cap it relieves. Unset (0) means auto: 4x the holds
    /// RAM cap, resolved at page time. The daemon wires a free-space-
    /// aware value here next to `set_extract_budget`. Exceeding the
    /// ceiling demotes with the same "held-bytes cap" reasons as a RAM
    /// breach with paging off.
    pub fn set_holds_scratch_cap(&self, bytes: u64) {
        self.inner
            .lock_ok()
            .scratch
            .cap
            .store(bytes, Ordering::Relaxed);
    }

    /// Bytes ever paged to the holds scratch (whole chain; monotonic).
    /// Test/diagnostic hook.
    pub fn holds_paged_total(&self) -> u64 {
        self.inner
            .lock_ok()
            .scratch
            .paged_total
            .load(Ordering::Relaxed)
    }

    /// Bytes of live paged spans right now. Test/diagnostic hook.
    pub fn holds_paged_live(&self) -> u64 {
        let scratch = self.inner.lock_ok().scratch.clone();

        scratch.st().live
    }

    /// Peak held-span bytes across the whole nesting chain - end-of-run
    /// mem summary (M15).
    pub fn holds_peak(&self) -> usize {
        self.inner.lock_ok().budget.peak()
    }

    /// The chain's EFFECTIVE held-span cap right now: what
    /// [`Self::set_holds_cap`] last stored (or [`default_holds_cap`] at
    /// construction), less any senior ledger seat's charge. The figure a
    /// memory rig should print beside its peak so a run that never got
    /// the production cap says so out loud (TODO 260).
    pub fn holds_cap(&self) -> usize {
        self.inner.lock_ok().budget.cap()
    }

    /// Budget-breach relief: move RAM-held spans - holds and header
    /// stash alike, every slot - out to the chain's scratch file until
    /// the budget sits at half its cap. Returns whether the budget is
    /// back under the cap; `false` (gate off, ceiling refused, scratch
    /// dead, or the remaining RAM belongs to spans this pass cannot
    /// touch - a chase frontier, sub-4K slivers, another level's holds)
    /// sends the caller down the exact demote it performs today, with
    /// the same reason string.
    pub(super) fn page_out_holds(&self, inner: &mut Inner) -> bool {
        if !inner.holds_page_on {
            return false;
        }
        let budget = inner.budget.clone();
        let scratch = inner.scratch.clone();
        // Auto ceiling: 4x the RAM cap, resolved per pass so a later
        // set_holds_cap is respected and an explicit ceiling wins.
        let cap = match scratch.cap.load(Ordering::Relaxed) {
            0 => 4 * budget.cap() as u64,
            c => c,
        };
        let low_water = budget.cap() / 2;
        let mut paged_any = false;
        'outer: for si in 0..inner.slots.len() {
            let s = &mut inner.slots[si];
            for store in [&mut s.holds, &mut s.header_spans] {
                for (_, span) in store.iter_mut() {
                    let HoldSpan::Ram(bytes) = span else { continue };
                    if bytes.len() < HOLDS_PAGE_MIN {
                        continue;
                    }
                    let Some(off) = scratch.append(bytes, cap) else {
                        // Ceiling or scratch death: whatever is still in
                        // RAM stays there; the verdict below demotes.
                        break 'outer;
                    };
                    let len = bytes.len();
                    budget.sub(len);
                    *span = HoldSpan::Paged { off, len };
                    paged_any = true;
                    if budget.bytes.load(Ordering::Relaxed) <= low_water {
                        break 'outer;
                    }
                }
            }
        }
        if paged_any && !scratch.announced.swap(true, Ordering::Relaxed) {
            info!(
                target: "extract",
                "💾 held spans over the RAM cap - paging to scratch, set stays one-pass"
            );
        }
        !budget.over()
    }

    /// Page password-parked slots' RAM spans to scratch, down to the
    /// [`pw_await_spill`] window. Unlike [`Self::page_out_holds`] this
    /// is not budget-breach relief - parked ciphertext goes to disk
    /// long before the cap, keeping a password-less set's resident
    /// footprint at the window instead of the payload. A refusal (gate
    /// off, ceiling, scratch death) leaves spans in RAM, where the cap
    /// arbiter still stands exactly as before.
    ///
    /// `first` is the slot that just parked: it is walked before the
    /// others, newest span first, so the steady state (budget hovering
    /// at the window) pages exactly the arriving span and stops -
    /// without that ordering, every park rescans the thousands of
    /// already-paged spans of a large set, and the per-article cost
    /// goes quadratic in the payload.
    pub(super) fn page_pw_holds(&self, inner: &mut Inner, first: usize) {
        if !inner.holds_page_on {
            return;
        }
        let budget = inner.budget.clone();
        let scratch = inner.scratch.clone();
        let cap = match scratch.cap.load(Ordering::Relaxed) {
            0 => 4 * budget.cap() as u64,
            c => c,
        };
        let window = pw_await_spill(budget.cap());
        let mut paged_any = false;
        let order: Vec<usize> = std::iter::once(first)
            .chain((0..inner.slots.len()).filter(|&si| si != first))
            .collect();
        'outer: for si in order {
            if inner.slots[si].pw_await.is_none() {
                continue;
            }
            let s = &mut inner.slots[si];
            for store in [&mut s.holds, &mut s.header_spans] {
                for (_, span) in store.iter_mut().rev() {
                    let HoldSpan::Ram(bytes) = span else { continue };
                    if bytes.len() < HOLDS_PAGE_MIN {
                        continue;
                    }
                    let Some(off) = scratch.append(bytes, cap) else {
                        break 'outer;
                    };
                    let len = bytes.len();
                    budget.sub(len);
                    *span = HoldSpan::Paged { off, len };
                    paged_any = true;
                    if budget.len() <= window {
                        break 'outer;
                    }
                }
            }
        }
        if paged_any && !scratch.announced.swap(true, Ordering::Relaxed) {
            info!(target: "extract", "🔒 spans parked for a password are paging to scratch");
        }
    }

    /// Take one held span's bytes back into RAM, releasing whichever
    /// store held them (budget for RAM, scratch live-count for paged -
    /// read BEFORE release, so an idle truncate can never beat the
    /// pread, and released on BOTH outcomes since the span is consumed
    /// either way). The caller feeds them onward; a re-hold re-charges as a
    /// fresh RAM span. Routing lock held.
    pub(super) fn reclaim_span(inner: &Inner, span: HoldSpan) -> io::Result<Vec<u8>> {
        match span {
            HoldSpan::Ram(b) => {
                inner.budget.sub(b.len());
                Ok(b)
            }
            HoldSpan::Paged { off, len } => {
                let mut b = vec![0u8; len];
                let r = inner.scratch.read(off, &mut b);
                // The span is consumed either way, so its live charge
                // goes either way. Still AFTER the read (an idle
                // truncate must not beat the pread), just no longer
                // only on success: every caller drops the span on Err,
                // so a `?` here leaked the reservation for the life of
                // the run (Fable sweep 15 Aug).
                inner.scratch.release(len);
                r.map(|()| b)
            }
        }
    }

    /// Drop-only release (discard/abandon paths): uncharge a held span
    /// without a read-back.
    pub(super) fn uncharge_span(inner: &Inner, span: &HoldSpan) {
        match span {
            HoldSpan::Ram(b) => inner.budget.sub(b.len()),
            HoldSpan::Paged { len, .. } => inner.scratch.release(*len),
        }
    }

    /// Flush held spans through the slot's current mode.
    ///
    /// Runs with `refeed_active` raised: the under-lock write sites
    /// report every plain placement into `late_placements`, which is
    /// how an article that was parked whole (Persist::Held) still gets
    /// its journal record once its bytes land. Saved/restored, not
    /// set/cleared - drains nest (reresolve firing inside a feed).
    pub(super) fn drain_holds(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        let prev = inner.refeed_active;
        inner.refeed_active = true;
        let r = self.drain_holds_feed(inner, slot);
        inner.refeed_active = prev;
        r
    }

    fn drain_holds_feed(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        // The holds are OUT of the slot the moment this takes them, so
        // every early exit below has to put the accounting back: a span
        // the loop never reaches, and the in-hand span the loop failed
        // on, are both charged to the budget (RAM) or the scratch live
        // count (paged) and nothing else will ever uncharge them. A
        // leaked charge is not just a number - it makes the extractor
        // demote on a ceiling it is no longer using, and keeps the
        // scratch file from truncating for the rest of the run.
        let mut rest = std::mem::take(&mut inner.slots[slot].holds).into_iter();
        inner.slots[slot].pre_bytes = 0;
        let mut failed = None;
        for (off, span) in rest.by_ref() {
            // A paged span reads back but is NOT released until after the
            // feed: whatever the feed re-holds is a subrange of these very
            // bytes, and rebinding those to the still-valid scratch region
            // (below) is what keeps a drain cycle from re-appending the
            // same bytes - unbounded churn would eat the scratch ceiling
            // on exactly the big-transient-window sets paging exists for.
            let (bytes, paged_at) = match span {
                HoldSpan::Ram(b) => {
                    inner.budget.sub(b.len());
                    (b, None)
                }
                HoldSpan::Paged { off: po, len } => {
                    let mut b = vec![0u8; len];
                    if let Err(e) = inner.scratch.read(po, &mut b) {
                        // Consumed either way, so the live charge goes
                        // either way - the same rule `reclaim_span`
                        // already follows for its own failed pread.
                        inner.scratch.release(len);
                        failed = Some(e);
                        break;
                    }
                    (b, Some((po, len)))
                }
            };
            let held_before = inner.slots[slot].holds.len();
            let stash_before = inner.slots[slot].header_spans.len();
            let fed = match inner.slots[slot].mode {
                // No article CRC: a held span is a SUBSET of some earlier
                // article's bytes, re-fed later, so that article's CRC does
                // not describe it.
                SlotMode::Rar => self.rar_span(inner, slot, off, &bytes, None, false, None),
                // TODO 211 (b): an alias's holds feed its head; any
                // re-hold lands on the head (so `rebind_subranges`
                // below finds nothing here and the bytes stay in RAM
                // until the next breach, the documented benign case).
                SlotMode::SplitPart => {
                    let (head, logical) = Self::split_target(inner, slot, off);
                    self.rar_span(inner, head, logical, &bytes, None, false, None)
                }
                SlotMode::RarChase | SlotMode::SevenZ => self.chase_span(inner, slot, off, &bytes),
                SlotMode::Discard => Ok(()),
                _ => self.plain_span(inner, slot, off, &bytes),
            };
            if let Err(e) = fed {
                // Release WITHOUT rebinding: a partial feed's re-holds
                // are charged as fresh RAM spans of their own, so once
                // this region is released nothing references it.
                if let Some((_, len)) = paged_at {
                    inner.scratch.release(len);
                }
                failed = Some(e);
                break;
            }
            if let Some((po, len)) = paged_at {
                Self::rebind_subranges(inner, slot, held_before, stash_before, off, po, &bytes);
                inner.scratch.release(len);
            }
        }
        if let Some(e) = failed {
            for (_, span) in rest {
                Self::uncharge_span(inner, &span);
            }
            return Err(e);
        }
        Ok(())
    }

    /// After re-feeding a PAGED span, point any re-held subrange of it
    /// back at its scratch region instead of a fresh RAM copy: the
    /// region is write-once and still live (released only after this
    /// runs, so the live-count never falsely hits zero), and the re-held
    /// bytes are subslices of the bytes read from it. Pure accounting -
    /// no new appends, no I/O - which is what bounds the drain/re-hold
    /// ping-pong at one scratch write per unique byte.
    ///
    /// The subslice premise is CHECKED, not assumed: a re-entrant drain
    /// (reresolve firing inside the feed) can repopulate the vectors and
    /// stale the `*_before` indices, and a repair span parked behind the
    /// original may overlap the fed range with DIFFERENT bytes -
    /// rebinding either would silently swap its bytes for the region's.
    /// An entry only rebinds when its bytes equal the fed slice at its
    /// offset; anything else stays in RAM with its charge (correct,
    /// just unpaged until the next breach).
    pub(super) fn rebind_subranges(
        inner: &mut Inner,
        slot: usize,
        held_before: usize,
        stash_before: usize,
        fed_off: u64,
        po: u64,
        fed: &[u8],
    ) {
        let budget = inner.budget.clone();
        let scratch = inner.scratch.clone();
        let s = &mut inner.slots[slot];
        for (vec, from) in [
            (&mut s.holds, held_before),
            (&mut s.header_spans, stash_before),
        ] {
            for (ho, hs) in vec.iter_mut().skip(from) {
                let HoldSpan::Ram(b) = hs else { continue };
                let Some(rel) = ho.checked_sub(fed_off) else {
                    continue;
                };
                let rel = rel as usize;
                let Some(end) = rel.checked_add(b.len()) else {
                    continue;
                };
                if end > fed.len() || fed[rel..end] != b[..] {
                    continue;
                }
                scratch.add_live(b.len());
                budget.sub(b.len());
                *hs = HoldSpan::Paged {
                    off: po + rel as u64,
                    len: b.len(),
                };
            }
        }
    }

    /// A span for a slot that has not sniffed yet, arriving at some
    /// offset other than 0: park it, ask for the head, and decide
    /// whether this slot has held enough to give up on mapping it.
    /// Hoisted out of `write_impl_scratched` (size gate, 22 Aug 2026);
    /// the caller still owns the off-lock promote flush and the `Held`
    /// return.
    pub(super) fn hold_presniff_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        inner.budget.add(data.len());
        inner.slots[slot].pre_bytes += data.len();
        inner.slots[slot]
            .holds
            .push((offset, HoldSpan::Ram(data.to_vec())));
        self.probe_offset0(inner, slot, offset);
        let spill = inner.slots[slot].pre_bytes > unclassified_spill(inner.budget.cap());
        // The chase ladder BEFORE the shotgun below, and this is the
        // call site TODO 251 was filed for. `overflow_to_plain` flips
        // EVERY Unknown slot holding bytes to Plain, and an unsniffed
        // volume of a live chased set is exactly that: flipped, it can
        // never join the set, the engine reaches it and the whole chase
        // dies - twenty volumes on disk and no payload, for one 7 KB
        // pre-sniff span (`relieve_by_own_chase`). The trim rung
        // releases what the engine has already consumed, which is what
        // the arrival order that CAUSES these holds keeps producing.
        if inner.budget.over() && !self.page_out_holds(inner) && !self.relieve_by_chase(inner, slot)
        {
            self.overflow_to_plain(inner)?;
        } else if spill && !Self::split_waiting(inner, slot) && !self.head_grace(inner, slot) {
            // The offset-0 sniff hasn't arrived after this much of the
            // slot, and the grace above has run out - synthesized
            // segment numbering can put it anywhere in the queue. Give
            // up mapping THIS slot: plain writes are always correct (a
            // real RAR volume simply materializes on disk, the pre-M3
            // behavior), while holding on livelocks the pipeline in RAM
            // with nothing on disk, in stats, or in the journal.
            self.spill_unclassified_slot(inner, slot)?;
        }
        Ok(())
    }

    /// Front-load the article carrying this slot's offset 0, from a span
    /// that arrived while the slot is still Unknown. Two guesses ride
    /// every promote, re-issues included - the honest one costs a single
    /// id that is either already fetched or exactly what we want
    /// re-fronted, and a probe keeps one recognisable shape:
    ///   `(0, 1)` - offset 0 where the NZB ladder says it is; pulls a
    ///     late/retried head article forward when the ladder is honest.
    ///   `(size-min, +1)` - the rotation guess, root only: if numbering
    ///     preserved posting order but started mid-sequence (the
    ///     indexer-synthesized norm), the article at declared byte 0
    ///     carrying actual offset X puts actual offset 0 at declared
    ///     byte `size-X`. The ladder's ±slack absorbs a couple of
    ///     articles of arrival jitter.
    ///
    /// The estimator is the MINIMUM offset the slot has held, not the
    /// first one it saw, and the promote RE-ISSUES whenever that minimum
    /// strictly falls. A span arriving at declared position p under a
    /// rot-k ladder carries offset `(k+p)*A`, so `size-offset`
    /// undershoots the head's declared byte by `p*A` - and
    /// `map_span_ids` allows only +3 articles of forward slack. p is
    /// normally 0 (`plan.rs` puts every file's `si == 0` segment in the
    /// `head_ids` burst, so that article is normally the slot's first
    /// arrival); when it is late or retried and four of the slot's own
    /// articles beat it in, the first guess misses. Its eventual arrival
    /// carries a LOWER offset than everything that beat it, which is
    /// exactly the correction - so re-aim on it rather than latching on
    /// the first sighting (2026-08-22 late-head-grace note, section 1).
    ///
    /// Bounded at [`PROBE0_MAX`] promotes per slot, because a promote
    /// must not fight the M11 stream reader, whose newest-alive
    /// generation re-promotes its rolling window every few MB
    /// (`LiveRangeReader`, in nzbfast's serve/stream.rs) and so always
    /// ends up in front. A handful of monotonically-improving re-issues
    /// keeps that property; a per-article promote would not. Honest
    /// ladders pay nothing: their arrivals climb, so the minimum never
    /// falls and the first probe is the only one.
    /// `spill_unclassified_slot` stays the backstop.
    ///
    /// The minimum is tracked incrementally rather than scanned off
    /// `Slot.holds` - every held span passes through here, so the two
    /// agree, and the scan would be quadratic over a slot's articles.
    pub(super) fn probe_offset0(&self, inner: &mut Inner, slot: usize, offset: u64) {
        let s = &mut inner.slots[slot];
        if offset >= s.probe0_min || s.probe0_promotes >= PROBE0_MAX {
            return;
        }
        let (first, size) = (s.probe0_promotes == 0, s.size);
        // Keep the estimator honest either way - the guards below only
        // decide whether this fall is worth a promote.
        s.probe0_min = offset;
        if !first && s.holds.len() > PROBE0_WINDOW {
            return;
        }
        // Rotation is a posting-layer phenomenon: below the root a
        // slot's byte space is an archive's, not a poster's ladder. No
        // rotation guess there, so nothing to re-aim - the first probe
        // is the only one, exactly as before.
        let root = self.parent.upgrade().is_none();
        if !first && !root {
            return;
        }
        let mut spans = vec![(0u64, 1u64)];
        if root && offset < size {
            spans.push((size - offset, size - offset + 1));
        }
        inner.slots[slot].probe0_promotes += 1;
        inner.pending_promote.push((slot, spans, false));
    }

    /// May slot `slot` WAIT for the offset-0 article its probe
    /// front-loaded, instead of spilling at [`unclassified_spill`]?
    ///
    /// The race this arbitrates (measured 22 Aug 2026 on a 1 GbE line,
    /// five releases x three reps on a rotated-ladder fixture, 4 legs
    /// one-pass and 11 partly on disk with the SAME binaries): when a
    /// slot's first span arrives out of order, [`Self::probe_offset0`]
    /// promotes the article carrying byte 0. `promote()`
    /// only reorders the PENDING queue - an article already dispatched
    /// is untouched - and the plan queues each file's declared segments
    /// contiguously, so for the handful of volumes that fit inside the
    /// opening in-flight window (connections x pipeline depth) the
    /// offset-0 article is ALREADY on the wire when its own promote
    /// runs. The promote is then a no-op and the head arrives at a
    /// uniformly random point in that volume's own arrival generation.
    /// Whether it beats `unclassified_spill` - a QUARTER of the slice -
    /// is a coin flip the wire decides, and losing it costs the whole
    /// set its in-place extraction.
    ///
    /// So a slot that is still expecting a head gets the rest of the
    /// slice rather than a quarter of it. The bound is the existing
    /// budget, not a timer and not a new constant: at `budget.cap()` the
    /// grace ends and the spill fires exactly as before, so one slot can
    /// never hold more than the whole chain-wide slice, and the global
    /// arbiter above (page to scratch, else demote every Unknown slot)
    /// is untouched. A head that never arrives therefore costs a bounded
    /// four-fold-larger hold and then degrades on the same path.
    ///
    /// Only for a slot whose NAME is volume-shaped ([`vol_sort_key`]
    /// ranks it, or it is a bare container). That is the whole point of
    /// waiting: a late head on a volume costs the SET its in-place
    /// extraction, while a late head on an ordinary payload file costs
    /// nothing but incremental writes - its bytes go to disk either way.
    /// The 2026-07-20 live case the per-slot spill was written for (an
    /// obfuscated single file, subject and numbering both lying, nothing
    /// on disk or in the journal for the whole run) is a payload slot,
    /// and it keeps today's early spill. Pre-sniff the name is all there
    /// is to go on, which is the same trade the sniff branch itself
    /// makes with `is_final_name`.
    ///
    /// Denied outright when paging is off (the relief valve the extra
    /// holds lean on is gone, so keep the early spill), and below the
    /// root (a nested level's spans come from its parent's mapper, not
    /// from a fetch queue - there is no in-flight article to wait for).
    /// The root test is `depth`, not `parent.upgrade()`: an extractor
    /// nobody anchored into an `Arc` has an empty parent Weak at EVERY
    /// level, so the upgrade test the rotation guess uses reads a
    /// depth-1 child as the root.
    pub(super) fn head_grace(&self, inner: &mut Inner, slot: usize) -> bool {
        if !inner.head_grace_on || !inner.holds_page_on {
            return false;
        }
        if self.depth != 0 {
            return false;
        }
        let s = &inner.slots[slot];
        if s.probe0_promotes == 0 || s.pre_bytes > inner.budget.cap() {
            return false;
        }
        if !volume_shaped_name(&s.name) {
            return false;
        }
        if !inner.grace_announced {
            inner.grace_announced = true;
            info!(
                target: "extract",
                "⏳ offset-0 article late - holding for the sniff rather than \
                 materializing the volume"
            );
        }
        true
    }

    /// One Unknown slot exceeded the per-slot pre-classification budget -
    /// flip just that slot to Plain and flush its holds to disk. Same
    /// safety argument as [`Self::overflow_to_plain`], applied before the
    /// GLOBAL cap wedges the whole pipeline on one unsniffable slot.
    pub(super) fn spill_unclassified_slot(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        if !matches!(inner.slots[slot].mode, SlotMode::Unknown) {
            return Ok(());
        }
        if inner.protect_sources {
            let name = inner.slots[slot].name.clone();
            inner
                .slot_fallbacks
                .push((name, "unclassified-holds budget".to_string()));
            self.discard_slot(inner, slot);
            return Ok(());
        }
        inner.slots[slot].mode = SlotMode::Plain;
        self.split_slot_plain(inner, slot)?;
        self.drain_holds(inner, slot)
    }

    /// Holds cap exceeded before sniffing finished - flip every Unknown
    /// slot to Plain (writes are safe; RAR mapping just won't happen).
    pub(super) fn overflow_to_plain(&self, inner: &mut Inner) -> io::Result<()> {
        for si in 0..inner.slots.len() {
            if matches!(inner.slots[si].mode, SlotMode::Unknown)
                && !inner.slots[si].holds.is_empty()
            {
                if inner.protect_sources {
                    let name = inner.slots[si].name.clone();
                    inner
                        .slot_fallbacks
                        .push((name, "held-bytes cap".to_string()));
                    self.discard_slot(inner, si);
                    continue;
                }
                inner.slots[si].mode = SlotMode::Plain;
                self.split_slot_plain(inner, si)?;
                self.drain_holds(inner, si)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar::fixtures;

    use crate::extract::testutil::*;

    /// Sweep 2 L8, the RAM half. `drain_holds_feed` takes the whole
    /// retained pile OUT of the slot before it feeds anything, so an
    /// error partway is the only thing that will ever see the rest of
    /// it: dropping the vector frees the memory but leaves every
    /// unvisited span charged to the budget, and the in-hand paged span
    /// charged to the scratch live count. An overstated budget demotes
    /// later sets on a ceiling nothing is using, and a live count that
    /// never reaches zero keeps the scratch file from truncating for the
    /// rest of the run.
    ///
    /// Both injected errors are deterministic: a directory sitting on
    /// the plain writer's output name, and a scratch whose file handle
    /// is gone.
    #[test]
    fn a_failed_refeed_leaves_no_retained_span_charged() {
        // (label, kill the scratch handle before draining?)
        for (tag, kill_scratch) in [("feed", false), ("pread", true)] {
            let dir = tmpdir(&format!("holds-refeed-err-{tag}"));
            let ex = Extractor::new(&dir, 1, true);
            ex.set_holds_scratch_cap(1 << 20);
            // The feed itself cannot succeed: a DIRECTORY on the plain
            // writer's output name fails `ensure_plain_writer`.
            std::fs::create_dir(dir.join("v.rar")).unwrap();
            let (a, b, c) = (vec![0xA1u8; 4096], vec![0xB2u8; 4096], vec![0xC3u8; 4096]);
            {
                let mut g = ex.inner.lock_ok();
                let inner = &mut *g;
                inner.slots[0].mode = SlotMode::Plain;
                inner.slots[0].name = "v.rar".to_string();
                inner.slots[0].size = 12_288;
                // Paged FIRST, so the failing iteration is holding a
                // scratch charge as well as leaving two behind.
                let off = inner.scratch.append(&a, 1 << 20).unwrap();
                inner.slots[0]
                    .holds
                    .push((0, HoldSpan::Paged { off, len: a.len() }));
                inner.budget.add(b.len());
                inner.slots[0].holds.push((4096, HoldSpan::Ram(b)));
                inner.budget.add(c.len());
                inner.slots[0].holds.push((8192, HoldSpan::Ram(c)));
            }
            assert_eq!(ex.holds_paged_live(), 4096, "{tag}: setup");
            assert_eq!(ex.inner.lock_ok().budget.len(), 8192, "{tag}: setup");
            if kill_scratch {
                // The pread now fails instead of the feed - the other
                // early exit out of the same loop.
                ex.inner.lock_ok().scratch.st().file = None;
            }
            let err = {
                let mut g = ex.inner.lock_ok();
                let inner = &mut *g;
                ex.drain_holds(inner, 0).unwrap_err()
            };
            assert_eq!(
                ex.holds_paged_live(),
                0,
                "{tag}: a failed refeed left the scratch charged ({err})"
            );
            assert_eq!(
                ex.inner.lock_ok().budget.len(),
                0,
                "{tag}: a failed refeed left the RAM budget charged ({err})"
            );
            drop(ex);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The other direction: a refeed that SUCCEEDS still charges and
    /// uncharges exactly as before - every span released, the bytes
    /// written where they were held, and no double-uncharge (which the
    /// budget would report as a wrapped, enormous length).
    #[test]
    fn a_clean_refeed_still_releases_exactly_once() {
        let dir = tmpdir("holds-refeed-ok");
        let ex = Extractor::new(&dir, 1, true);
        ex.set_holds_scratch_cap(1 << 20);
        let (a, b) = (vec![0xA1u8; 4096], vec![0xB2u8; 4096]);
        {
            let mut g = ex.inner.lock_ok();
            let inner = &mut *g;
            inner.slots[0].mode = SlotMode::Plain;
            inner.slots[0].name = "v.rar".to_string();
            inner.slots[0].size = 8192;
            let off = inner.scratch.append(&a, 1 << 20).unwrap();
            inner.slots[0]
                .holds
                .push((0, HoldSpan::Paged { off, len: a.len() }));
            inner.budget.add(b.len());
            inner.slots[0].holds.push((4096, HoldSpan::Ram(b.clone())));
        }
        {
            let mut g = ex.inner.lock_ok();
            let inner = &mut *g;
            ex.drain_holds(inner, 0).unwrap();
        }
        assert_eq!(ex.holds_paged_live(), 0, "paged span still charged");
        assert_eq!(ex.inner.lock_ok().budget.len(), 0, "RAM span still charged");
        drop(ex);
        let mut want = a.clone();
        want.extend_from_slice(&b);
        assert_eq!(
            std::fs::read(dir.join("v.rar")).unwrap(),
            want,
            "a clean refeed must still land every held byte"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Holds paging (the budget-breach relief valve, default ON): the
    /// same neither-end-parsed window that demotes with paging off pages
    /// to scratch instead and the set still extracts one-pass,
    /// byte-exact - no volume ever touches disk, and the scratch file
    /// itself is gone after finish.
    #[test]
    fn paged_holds_keep_a_tight_budget_set_one_pass() {
        let inner = "late2.mkv";
        let (data, vols, names) = uniform_store_set(inner, 300_000, 44, 200_000, 31);
        let mut order = shuffled_zero_last(vols.len(), 0xC0FFEE);
        let tail = vols.len() - 1;
        let at = order.iter().position(|&v| v == tail).unwrap();
        order.remove(at);
        order.insert(order.len() - 1, tail);
        let dir = tmpdir("holds-paged-onepass");
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_holds_cap(8 << 20);
        for &vi in &order {
            feed(&ex, vi, &names[vi], &vols[vi], 9000, 70 + vi as u64);
        }
        assert!(ex.holds_paged_total() > 0, "paging never engaged");
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
        for n in &names {
            assert!(!dir.join(n).exists(), "volume {n} materialized");
        }
        // Close the scratch handle before asserting the name is gone:
        // finish() unlinks with the handle deliberately open, and on
        // classic-delete-semantics filesystems (pre-1903 Windows, SMB)
        // the name stays listed until last close.
        drop(ex);
        // Only the payload survives - the scratch must not outlive finish.
        assert_eq!(dir_files(&dir), vec![inner.to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Mapped PAR2 repair sees paged spans: bytes parked behind an
    /// unresolvable base page out under the cap, and `covered`/`read_at`
    /// still serve them byte-exactly - repair reads through exactly these
    /// paths to rebuild the blocks that free the holds. The set then
    /// completes one-pass once the neighbours land.
    #[test]
    fn mapped_repair_reads_a_paged_span() {
        let dir = tmpdir("holds-paged-readat");
        let total = payload(30_000_000, 13);
        let vols = [
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[..7_000_000], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[(
                    "film.mkv",
                    30_000_000,
                    &total[7_000_000..22_000_000],
                    true,
                    true,
                )],
                1,
            ),
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[22_000_000..], true, false)],
                2,
            ),
        ];
        let ex = Extractor::new(&dir, 3, true);
        ex.set_holds_cap(1); // floors at 8 MB - part2's data area exceeds it
        let feed_seq = |slot: usize, name: &str, vol: &[u8]| {
            for (i, chunk) in vol.chunks(65_000).enumerate() {
                ex.write(slot, name, vol.len() as u64, (i * 65_000) as u64, chunk)
                    .unwrap();
            }
        };
        // Middle volume first: a middle piece is neither its file's head
        // nor its tail, so nothing resolves its base and the whole data
        // area holds - and pages.
        feed_seq(1, "x.part2.rar", &vols[1]);
        assert!(ex.holds_paged_total() > 0, "paging never engaged");
        // A mid-volume range that can only live in (paged) holds now.
        let (off, len) = (5_000_000u64, 200_000usize);
        assert!(
            ex.covered(1, off, len as u64),
            "paged span invisible to covered"
        );
        let mut got = vec![0u8; len];
        ex.read_at(1, off, &mut got).unwrap();
        assert_eq!(&got[..], &vols[1][off as usize..off as usize + len]);
        // The whole volume reconstructs too (headers + RAM + paged spans).
        let mut whole = vec![0u8; vols[1].len()];
        ex.read_at(1, 0, &mut whole).unwrap();
        assert_eq!(whole, vols[1]);
        // With the neighbours fed, the paged spans drain into place and
        // the set finishes one-pass.
        feed_seq(0, "x.part1.rar", &vols[0]);
        feed_seq(2, "x.part3.rar", &vols[2]);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        // Handle closed before the name-absence check (delete-pending
        // filesystems keep the unlinked name listed until last close).
        drop(ex);
        assert_eq!(dir_files(&dir), vec!["film.mkv".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The scratch has a hard ceiling of its own: exceeding it demotes
    /// with the SAME "held-bytes cap" reason as a RAM breach with paging
    /// off. The finish ladder keys volume-level remediation off that
    /// substring, so the wording is load-bearing - a novel string would
    /// demote the volumes and then ship the job with no payload, exit 0.
    #[test]
    fn scratch_ceiling_demotes_with_the_unchanged_reason() {
        let dir = tmpdir("holds-paged-ceiling");
        let total = payload(30_000_000, 13);
        let vols = [
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[..7_000_000], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[(
                    "film.mkv",
                    30_000_000,
                    &total[7_000_000..22_000_000],
                    true,
                    true,
                )],
                1,
            ),
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[22_000_000..], true, false)],
                2,
            ),
        ];
        let ex = Extractor::new(&dir, 3, true);
        ex.set_holds_cap(1); // floors at 8 MB
        ex.set_holds_scratch_cap(2 << 20); // far below part2's window
        let feed_seq = |slot: usize, name: &str, vol: &[u8]| {
            for (i, chunk) in vol.chunks(65_000).enumerate() {
                ex.write(slot, name, vol.len() as u64, (i * 65_000) as u64, chunk)
                    .unwrap();
            }
        };
        feed_seq(1, "x.part2.rar", &vols[1]);
        feed_seq(0, "x.part1.rar", &vols[0]);
        feed_seq(2, "x.part3.rar", &vols[2]);
        let rep = ex.finish().unwrap();
        assert!(ex.holds_paged_total() > 0, "paging never engaged");
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("held-bytes cap") && !w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        // Demoting is not losing: every volume byte-exact on disk, and
        // the scratch gone with the demote (its spans all drained).
        for (vi, vol) in vols.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(format!("x.part{}.rar", vi + 1))).unwrap(),
                vol,
                "volume {vi}"
            );
        }
        // Handle closed before the name-absence check (delete-pending
        // filesystems keep the unlinked name listed until last close).
        drop(ex);
        assert!(
            !dir_files(&dir)
                .iter()
                .any(|n| n.starts_with(HOLDS_TMP_PREFIX)),
            "scratch left behind: {:?}",
            dir_files(&dir)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The paging gate: NZBFAST_NO_HOLDS_PAGE=1 parses as off (asserted
    /// on the pure helper for the parallel-runner reason the chase gates
    /// established); the runtime setter drives the same latch and is
    /// exercised by the paging-off legs above.
    #[test]
    fn holds_paging_env_parse() {
        assert!(holds_page_env_off_value(Some("1")));
        assert!(!holds_page_env_off_value(Some("0")));
        assert!(!holds_page_env_off_value(None));
    }

    /// The scratch's reader-pin contract, pinned directly (the 31 Jul
    /// race audit's finding was a gate that consulted `pins` outside
    /// the state mutex): a pin taken at plan time must block BOTH
    /// reclaim gates - the release-side truncate and the append-side
    /// cursor reset - for a planned pread of a since-released region,
    /// and must stop blocking once dropped.
    #[test]
    fn scratch_pin_blocks_idle_reclaim() {
        let dir = tmpdir("scratch-pin");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let payload = b"exact bytes a planned pread must still see";
        let off = sc.append(payload, 1 << 20).expect("first append");
        // A reader plans: pin, then the span is consumed (released)
        // before the pread lands - the exact window of the race.
        let mut pin = ScratchPin::none();
        pin.pin(&sc);
        sc.release(payload.len());
        // live == 0, but the pin blocks the truncate: the planned pread
        // still sees the bytes...
        let mut buf = vec![0u8; payload.len()];
        sc.read(off, &mut buf).unwrap();
        assert_eq!(&buf, payload);
        // ...and a new append must not reset the cursor onto the
        // planned region either.
        let off2 = sc.append(b"XXXX", 1 << 20).expect("append under pin");
        assert_ne!(off2, off, "cursor reset under a live pin");
        sc.read(off, &mut buf).unwrap();
        assert_eq!(&buf, payload, "planned region overwritten under a live pin");
        // Pin dropped and everything released: the idle reset may fire.
        drop(pin);
        sc.release(4);
        let off3 = sc.append(b"YYYY", 1 << 20).expect("append after idle");
        assert_eq!(off3, 0, "idle reset never fired once unpinned");
        sc.release(4);
        sc.cleanup();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A held span can carry the NEXT file's header bytes while the parse
    /// window is still megabytes behind (stash keeps only bytes near the
    /// cursor). Draining holds must re-FEED the mapper, not just retry
    /// extraction - otherwise mapping stalls and a healthy group falls
    /// back at finish().
    #[test]
    fn held_header_bytes_reach_the_parser_on_drain() {
        let dir = tmpdir("farheader");
        // Data areas > MAX_WIN (4 MiB) so each later header starts
        // outside the parse window of the previous cursor position.
        let f1 = payload(5_100_000, 41);
        let f2 = payload(5_100_000, 42);
        let f3 = payload(4_000, 43);
        let vol = fixtures::rar5_volume(&[
            ("one.bin", 5_100_000, &f1, false, false),
            ("two.bin", 5_100_000, &f2, false, false),
            ("three.bin", 4_000, &f3, false, false),
        ]);
        let art = 65_536;
        let ex = Extractor::new(&dir, 1, true);
        let write_art = |i: usize| {
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        };
        let n_arts = vol.len().div_ceil(art);
        // Article 0: sniff + file-1 header → cursor jumps to ~5.1 MB.
        write_art(0);
        // The article carrying file-3's header (~10.2 MB) arrives while
        // the window sits at ~5.1 MB - its bytes miss the stash and the
        // span is held.
        write_art(n_arts - 1);
        // Everything else in order; file-2's header advances the cursor
        // to file-3's header, which now only exists in that held span.
        for i in 1..n_arts - 1 {
            write_art(i);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("three.bin")).unwrap(), f3);
        assert_eq!(std::fs::read(dir.join("one.bin")).unwrap(), f1);
        assert_eq!(std::fs::read(dir.join("two.bin")).unwrap(), f2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Live 2026-07-20 (Seinfeld S08E05, 12,109 segments): synthesized
    /// segment numbering means "segment 1" isn't the yEnc offset-0
    /// article, so the sniff may come LAST - every span piled into
    /// pre-classification holds, nothing reached disk/stats/journal for
    /// the whole run. The per-slot spill must flip the slot Plain and
    /// flush once its held bytes pass the budget, long before offset 0.
    #[test]
    fn unclassified_slot_spills_to_plain_before_sniff() {
        let dir = tmpdir("prespill");
        let data = payload(6_000_000, 9);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_holds_cap(8 << 20); // spill budget = clamp(2M, 4M..) = 4 MB
        // No `set_head_grace(false)` on purpose: `video.bin` is not a
        // volume-shaped name, so the late-head grace never covers this
        // slot and the early spill stands. That is half of what the
        // grace's name rule is for, pinned here.
        let art = 40_000;
        // Everything EXCEPT the offset-0 article, in scrambled order.
        let mut offs: Vec<usize> = (1..data.len().div_ceil(art)).map(|i| i * art).collect();
        let mut state = 77u64;
        for i in (1..offs.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            offs.swap(i, (state >> 33) as usize % (i + 1));
        }
        for s in offs {
            let e = (s + art).min(data.len());
            ex.write(0, "video.bin", data.len() as u64, s as u64, &data[s..e])
                .unwrap();
        }
        // The slot must have spilled: file on disk BEFORE the sniff, and
        // held bytes bounded by the budget (one article of slack), not
        // the ~6 MB the whole tail would have piled up.
        let path = dir.join("video.bin");
        assert!(path.exists(), "spill never created the plain file");
        assert!(
            ex.holds_peak() <= (4 << 20) + art,
            "holds peaked at {} - slot never spilled",
            ex.holds_peak()
        );
        // Offset 0 arrives dead last; the slot is already Plain.
        ex.write(0, "video.bin", data.len() as u64, 0, &data[..art])
            .unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(&path).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Same scramble on a real RAR volume: giving up on the sniff must
    /// still be CORRECT - the volume materializes byte-identical on disk
    /// (in-stream extraction is forfeited, not the data).
    #[test]
    fn unclassified_spill_of_rar_volume_materializes_it() {
        let dir = tmpdir("prespill-rar");
        let data = payload(6_000_000, 10);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 6_000_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_holds_cap(8 << 20);
        // `v.rar` IS volume-shaped, and 6 MB fits inside an 8 MB slice,
        // so the grace would ride this out. Gate off: this test pins the
        // spill, `a_late_head_inside_the_slice_waits_for_it` pins the
        // grace that now precedes it.
        ex.set_head_grace(false);
        let art = 40_000;
        let mut offs: Vec<usize> = (1..vol.len().div_ceil(art)).map(|i| i * art).collect();
        let mut state = 78u64;
        for i in (1..offs.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            offs.swap(i, (state >> 33) as usize % (i + 1));
        }
        for s in offs {
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        }
        ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art])
            .unwrap();
        ex.finish().unwrap();
        assert_eq!(
            std::fs::read(dir.join("v.rar")).unwrap(),
            vol,
            "materialized volume must be byte-identical"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The unclassified ceiling scales with the holds budget (the
    /// 11 Aug 2026 settle-round 3x-I/O bug): a RAR volume whose
    /// offset-0 article runs late must NOT spill to Plain at a flat
    /// 64 MB while the budget has gigabytes free - it holds, sniffs on
    /// the late head, and the set still extracts one-pass with no
    /// volume file ever touching disk. The small-budget spill is
    /// pinned by `unclassified_slot_spills_to_plain_before_sniff`
    /// above, which is the degradation this must not disturb.
    #[test]
    fn a_late_sniff_on_a_big_budget_holds_instead_of_spilling() {
        let dir = tmpdir("latesniff-bigbudget");
        let inner = "movie.mkv";
        // Bigger than the old flat 64 MB ceiling, far under cap/4.
        let data = payload(72 << 20, 11);
        let vol = fixtures::rar5_volume(&[(inner, (72 << 20) as u64, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_holds_cap(1 << 30); // spill budget = max(256 MB, 4 MB)
        let art = 256 * 1024;
        let n = vol.len().div_ceil(art);
        // Every article except offset-0, reversed - the whole volume
        // piles into pre-classification holds.
        for i in (1..n).rev() {
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        }
        assert!(
            ex.holds_peak() > 64 << 20,
            "fixture lost its teeth: holds peaked at {} - the old flat \
             ceiling was never exceeded",
            ex.holds_peak()
        );
        assert!(
            !dir.join("v.rar").exists(),
            "slot spilled to Plain under a nearly-empty budget"
        );
        // The head arrives dead last: sniff, map, drain, one-pass.
        ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art])
            .unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
        assert!(
            !dir.join("v.rar").exists(),
            "volume materialized despite the late sniff arriving"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The late-head grace, wire-free, in the shape the 21 Aug hold lab
    /// drove over the wire: one RAR volume whose declared ladder is
    /// ROTATED, so every article except the one carrying byte 0 arrives
    /// first and the whole volume piles into pre-classification holds.
    ///
    /// The volume is bigger than `unclassified_spill` (a quarter of the
    /// slice) and smaller than the slice itself, which is exactly the
    /// 22 Aug wire fixture's shape (~108 MB volumes against a 231 MB
    /// holds slice). Before the grace, whether this set kept its
    /// in-place extraction was a race between the spill and an offset-0
    /// article the promote could not reach because it was already on the
    /// wire; the same binary went one-pass on 4 legs of 15 and to disk on
    /// the other 11. Now it is decided by the budget, so both arms below
    /// are deterministic: grace on rides it out, grace off materializes.
    #[test]
    fn a_late_head_inside_the_slice_waits_for_it() {
        for grace in [true, false] {
            let dir = tmpdir(&format!("headgrace-{grace}"));
            let inner = "movie.mkv";
            let payload_len = 24 << 20;
            let data = payload(payload_len, 12);
            let vol = fixtures::rar5_volume(&[(inner, payload_len as u64, &data, false, false)]);
            let ex = Extractor::new(&dir, 1, true);
            // Slice 64 MB: spill window 16 MB, grace ceiling 64 MB, and
            // the volume sits between them.
            ex.set_holds_cap(64 << 20);
            ex.set_head_grace(grace);
            assert!(
                vol.len() > (16 << 20) && vol.len() < (64 << 20),
                "fixture must sit between the spill window and the slice: {}",
                vol.len()
            );
            let art = 512 * 1024;
            let n = vol.len().div_ceil(art);
            // The rotated ladder: declared segment 1 carries byte `art`,
            // and byte 0 is announced last.
            for i in 1..n {
                let s = i * art;
                let e = (s + art).min(vol.len());
                ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                    .unwrap();
            }
            assert_eq!(
                dir.join("v.rar").exists(),
                !grace,
                "grace={grace}: spill decision flipped"
            );
            // The head, dead last.
            ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art])
                .unwrap();
            let rep = ex.finish().unwrap();
            assert!(
                rep.fallbacks.is_empty(),
                "grace={grace}: {:?}",
                rep.fallbacks
            );
            if grace {
                // Rode the late head out: extracted in place, and the
                // volume never touched disk.
                assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
                assert!(!dir.join("v.rar").exists(), "volume materialized");
            } else {
                // Spilled, and a spill is still CORRECT - the volume is
                // byte-identical on disk for the post-pass to extract.
                assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
                assert!(!dir.join(inner).exists(), "spilled slot extracted");
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The grace's bound is the budget, not patience: a volume LARGER
    /// than the whole holds slice still spills, so one unsniffable slot
    /// can never hold more than the slice and the global arbiter above
    /// it keeps its arithmetic. Same fixture as the test above with the
    /// slice moved under the volume rather than over it.
    #[test]
    fn a_late_head_past_the_slice_spills_anyway() {
        let dir = tmpdir("headgrace-past-slice");
        let payload_len = 24 << 20;
        let data = payload(payload_len, 13);
        let vol = fixtures::rar5_volume(&[("movie.mkv", payload_len as u64, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        // Slice 8 MB (the setter's floor) against a ~24 MB volume.
        ex.set_holds_cap(8 << 20);
        let art = 512 * 1024;
        let n = vol.len().div_ceil(art);
        for i in 1..n {
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        }
        assert!(
            dir.join("v.rar").exists(),
            "the grace outlasted the holds slice - it must end at the cap"
        );
        assert!(
            ex.holds_peak() <= (8 << 20) + art,
            "holds peaked at {} - past the slice the grace must stop",
            ex.holds_peak()
        );
        ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art])
            .unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The grace needs the relief valve it leans on: with paging off a
    /// breach demotes instead of spilling to scratch, so the early
    /// per-slot spill must stay exactly where it was.
    #[test]
    fn head_grace_stands_down_when_paging_is_off() {
        let dir = tmpdir("headgrace-nopaging");
        let payload_len = 24 << 20;
        let data = payload(payload_len, 14);
        let vol = fixtures::rar5_volume(&[("movie.mkv", payload_len as u64, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_holds_cap(64 << 20);
        ex.set_holds_paging(false);
        let art = 512 * 1024;
        let n = vol.len().div_ceil(art);
        for i in 1..n {
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        }
        assert!(
            dir.join("v.rar").exists(),
            "the grace ran with no paging behind it"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The grace's population, pinned directly: every volume naming the
    /// extractor already sorts sets by, plus the two bare containers -
    /// and nothing that is merely a posted payload file. The last case
    /// is the 2026-07-20 live regression the per-slot spill exists for,
    /// which must keep its early spill.
    #[test]
    fn volume_shaped_names_are_the_graces_population() {
        for n in [
            "movie.mkv.part07.rar",
            "v.rar",
            "abcdef0123456789.42",
            "set.7z.001",
            "old.r09",
            "big.s00",
            "x.zip",
            "x.7z",
        ] {
            assert!(volume_shaped_name(n), "{n} should be volume-shaped");
        }
        for n in [
            "video.bin",
            "movie.mkv",
            "comic.cbr",
            "comic.cb7",
            "notes.txt",
            "file000",
            "",
        ] {
            assert!(!volume_shaped_name(n), "{n} should NOT be volume-shaped");
        }
    }

    /// The grace gate: NZBFAST_NO_HEAD_GRACE=1 parses as off, on the
    /// pure helper for the same parallel-runner reason as the paging
    /// gate above; the runtime setter is exercised by both arms of
    /// `a_late_head_inside_the_slice_waits_for_it`.
    #[test]
    fn head_grace_env_parse() {
        assert!(head_grace_env_off_value(Some("1")));
        assert!(!head_grace_env_off_value(Some("0")));
        assert!(!head_grace_env_off_value(None));
    }

    /// The spill budget's shape, pinned directly: floor for small
    /// slices, scaling (not a flat 64 MB) above it.
    #[test]
    fn unclassified_spill_scales_with_the_budget() {
        assert_eq!(unclassified_spill(8 << 20), 4 << 20); // floor
        assert_eq!(unclassified_spill(256 << 20), 64 << 20);
        assert_eq!(unclassified_spill(1 << 30), 256 << 20); // past the old flat ceiling
        // The field shape: 45% of a 16 GiB budget held a 64 MB window.
        // A `holds_cap` that large is a 64-bit-only quantity - it does not
        // fit a 32-bit `usize`, and `MemBudget` caps the budget below it
        // there anyway - so writing it as `(16u64 << 30) as usize` on
        // armv7 silently yields ZERO and pins nothing.
        #[cfg(not(target_pointer_width = "32"))]
        {
            let field_holds = (16u64 << 30) as usize / 100 * 45;
            assert!(unclassified_spill(field_holds) > 1 << 30);
        }
        // The 32-bit field shape: the largest holds_cap the budget ceiling
        // permits still scales rather than sitting on the floor.
        assert_eq!(unclassified_spill((1 << 30) / 100 * 45), 120_795_952);
    }

    /// The stalled-chase window's shape, pinned directly: floored for
    /// small slices, and NEVER scaling past 64 MB - a bigger budget
    /// buys no reason to keep cold frontier bytes resident (the same
    /// deliberate ceiling as `pw_await_spill`).
    #[test]
    fn chase_stall_spill_window_shape() {
        assert_eq!(chase_stall_spill(8 << 20), 4 << 20); // floor
        assert_eq!(chase_stall_spill(256 << 20), 64 << 20);
        // The ceiling holds however large the slice gets. Spelled with a
        // `usize` argument, so the 16 GiB case is 64-bit only: on armv7
        // `16 << 30` is 0, which would assert the FLOOR while reading
        // like the ceiling.
        #[cfg(not(target_pointer_width = "32"))]
        assert_eq!(chase_stall_spill(16 << 30), 64 << 20); // the field shape
        assert_eq!(chase_stall_spill((1 << 30) / 100 * 45), 64 << 20);
    }

    /// TODO 100 follow-up: an article that arrives before the offset-0
    /// sniff establishes the store mapper parks whole (`Persist::Held`)
    /// and its bytes land only when the sniff arrives and the holds
    /// drain, INSIDE the extractor. Those drained writes must surface
    /// through `drain_late_placements`, or the journal writer has
    /// nothing to record and every crash/ENOSPC resume refetches
    /// fully-written payload articles - seen as nondeterministically
    /// missing `R` records in the §100 e2e.
    #[test]
    fn held_then_drained_articles_surface_their_placements() {
        let dir = tmpdir("holds-late-placements");
        let inner = "movie.mkv";
        let data = payload(600_000, 9);
        let vol = fixtures::rar5_volume(&[(inner, 600_000, &data, false, false)]);
        let art = 100_000usize;
        let n = vol.len().div_ceil(art);
        let ex = Extractor::new(&dir, 1, true);
        // Every article except offset-0, in reverse: no sniff yet, so
        // each parks whole and must say so.
        let mut held: Vec<(u64, u64)> = Vec::new();
        for i in (1..n).rev() {
            let s = i * art;
            let e = ((i + 1) * art).min(vol.len());
            match ex
                .write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap()
            {
                Persist::Held(frags) => {
                    assert!(frags.is_empty(), "a pre-sniff hold has nothing on disk");
                    held.push((s as u64, (e - s) as u64));
                }
                _ => panic!("article {i} arrived pre-sniff and must park as Held"),
            }
        }
        assert!(
            ex.drain_late_placements().is_empty(),
            "nothing has drained - nothing may be reported"
        );
        // The offset-0 article: the sniff maps the volume and the drain
        // writes every held payload byte into the inner file.
        ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art])
            .unwrap();
        let late = ex.drain_late_placements();
        assert!(
            late.iter().all(|p| p.slot == 0 && p.frag.file == inner),
            "store payload places into the inner file: {late:?}"
        );
        // Every held article lying fully inside the data area (the last
        // one also carries the end-of-archive block, which legitimately
        // never lands in an output file) must now be fully covered.
        let covered = |off: u64, len: u64| {
            let mut iv: Vec<(u64, u64)> = late
                .iter()
                .map(|p| (p.frag.vol_off, p.frag.vol_off + p.frag.len))
                .filter(|&(s, e)| s >= off && e <= off + len)
                .collect();
            iv.sort_unstable();
            let mut to = off;
            for (s, e) in iv {
                if s > to {
                    return false;
                }
                to = to.max(e);
            }
            to >= off + len
        };
        let mut payload_articles = 0;
        for &(off, len) in held.iter().filter(|&&(o, l)| o + l < vol.len() as u64) {
            assert!(
                covered(off, len),
                "held article at {off}+{len} drained fully but its placement \
                 was not reported"
            );
            payload_articles += 1;
        }
        assert!(payload_articles >= 3, "fixture geometry lost its teeth");
        // A second drain reports nothing new, and the set still
        // finishes one-pass, byte-exact.
        assert!(ex.drain_late_placements().is_empty());
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
