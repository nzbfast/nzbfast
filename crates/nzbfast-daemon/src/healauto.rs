//! §310: the SCHEDULED heal - verify the library on a cadence and repair
//! what the settle manifests convict, without anybody clicking.
//!
//! [`super::heal`] is the manual road and this module changes none of
//! it: [`plan`](super::heal::plan) reads a folder's `.nzbfast.manifest`
//! and groups the damage by the post that proved it, and
//! [`Daemon::heal_one`] queues one repair with that folder as a donor.
//! The header on that file predicted this module in a sentence - "a
//! scheduler would call the same two functions" - and that part was
//! right. What it did not say is the part this file is mostly about.
//!
//! # The clicked road's cost argument does NOT survive automation
//!
//! `heal::MAX_HEAL_JOBS` bounds a click at 16 posts, and the reason
//! written beside it is that "the offer states the full count before
//! anything is spent, so a user who means it can heal the rest by
//! asking again". §282's copy cap and byte ceiling are skipped on the
//! same grounds: a person asked. Every clause of that is about a human
//! being in the loop, and there is no human in this loop. So this road
//! carries ceilings of its own, and they are the feature:
//!
//! 1. **It is OFF** (`heal_auto`), like every other automation in this
//!    daemon that talks to the outside world on its own initiative.
//!    `altcand::AltSettings` makes the argument at length for
//!    `alt_auto_search` and it is the same argument: this one can cost
//!    money nobody agreed to.
//! 2. **Recorded posts only.** A target whose `.nzb` is no longer on
//!    record falls through to `hunt_by_name` on the clicked road - an
//!    indexer search that spends a grab and may return a DIFFERENT post
//!    of the release, whose size and contents nobody has compared to
//!    what is on the disk. A person looking at the offer can judge
//!    that. A sweep cannot, so it declines and leaves the target for
//!    the clicked road, which still offers it.
//!
//!    **This is a CONSENT decision and not a coverage one**, which is
//!    worth saying because the search road was untested when this was
//!    written and is not any more: `todo310-heal-search-road` drove it
//!    end to end the same day and found no defect on it - it stamps
//!    `heal_dir` exactly as the recorded road does. The sweep still
//!    declines it. Nothing about that road being sound makes a
//!    different post of the release the one on the user's disk.
//! 3. **A byte ceiling counted PESSIMISTICALLY** (`heal_auto_max_bytes`),
//!    against the WHOLE size of each post rather than against the
//!    damaged remainder. See the next section: this is the load-bearing
//!    one.
//! 4. **A job ceiling** (`heal_auto_max_jobs`), tighter than the click's
//!    16, applied per sweep.
//! 5. **It never fights a download.** `queue_has_runnable` is the same
//!    cheap "is a download imminent" the index scanners stand down on,
//!    and a verify is a FULL READ of every file the manifest carries a
//!    checksum for - real disk on the same spindle the download is
//!    using. Since `26f3860ab` (2 Sep 2026) that includes EXTRACTED
//!    output, which used to be a presence entry costing a `stat`: an
//!    archive-post folder was near-free to sweep and now costs a full
//!    read of the film, like a loose-file post. Most of a real library
//!    is archive posts, so the per-folder read cost of a sweep went up
//!    for the common case - which the folder cap below absorbs, because
//!    it bounds FOLDERS per sweep and not bytes.
//!
//! # Why the byte ceiling is counted against the whole post
//!
//! The economic claim the heal road is sold on is that it re-fetches
//! only the damaged remainder, because §293 Shape A adopts the intact
//! bytes off the donor directory. **Nothing in this tree measured that
//! when this file was written.** The heal wiring's tests pin the
//! WIRING - the queued row carries `heal_dir`, a season folder produces
//! one job per post - and not the economics, and a heal that quietly
//! re-downloads the whole release still SUCCEEDS, so the failure mode
//! is invisible from the outside.
//!
//! On the clicked road that gap is a disappointment. On this one it
//! would be a daemon spending a metered line re-downloading a library
//! nobody asked it to touch. So the ceiling here does not assume the
//! claim: it charges each repair the FULL size of the post, which is
//! what the repair costs if the remainder-only property does not hold.
//! A ceiling that is honoured in the worst case is honoured in every
//! case, and the pessimism costs a user nothing except that a sweep
//! stops sooner than it strictly had to. That is what let this module
//! land ahead of the measurement it was sequenced behind.
//!
//! # ...and the measurement then landed, and it VALIDATES the pessimism
//!
//! `crates/nzbfast/tests/daemon_heal/` (`893c75d17`, the same day)
//! is the served-body A/B. **Leg A - all members damaged, nothing on
//! disk donatable, which is precisely the case this ceiling is charged
//! for - cost 32 bodies against the 31 the same post's ordinary
//! download costs**, because a job with donors fetches its PAR2 index
//! twice. So the whole-post figure is not merely the safe bound here:
//! it is very slightly UNDER the true worst case. Leg B, with two of
//! three members byte-exact, cost 12.
//!
//! **Leg B's 12 is NOT licence to charge the remainder instead.** The
//! remainder is a function of how much of the folder is still
//! byte-exact, which is known only after the verify and only for WHOLE
//! files - `get/donor.rs` argues why a partial file's remainder cannot
//! be named before its bodies arrive. A lane that wants to charge a
//! measured remainder must keep the full-post figure as the fallback
//! and say here why its estimate is safe. Relaxing this because the
//! claim is believed rather than measured is the edit this section
//! exists to refuse, and the A/B's leg A is now the evidence for that
//! refusal rather than merely the argument for it.
//!
//! **And for an ARCHIVE post the full-post charge is not pessimism at
//! all - it is the exact figure.** `heal.rs`'s header sets it out:
//! a heal of extracted output cannot adopt anything, because the
//! damaged folder holds the EXTRACTED file while the fresh post's PAR2
//! set describes the VOLUMES, so `donor_dirs` has nothing to recognise
//! and the repair spends the whole post. The A/B measures the
//! LOOSE-FILE road and says nothing about this one. Since `26f3860ab`
//! made extracted output convictable, this is the case the sweep will
//! meet most often - so a measured-remainder charge would have to
//! detect the archive shape and fall back to the full post for it,
//! which is most of a library.
//!
//! # Which folders, and how far it reads
//!
//! The library is `out_dir` (`complete_dir`), so that is what is
//! walked, bounded and symlink-safe, for directories holding a
//! `.nzbfast.manifest`. Deliberately NOT the history rows: a manifest
//! outlives the record that wrote it by design - stage 1's whole point
//! is a folder that can verify itself years later - and history ages
//! out, so a rows-only sweep would go blind to exactly the folders this
//! feature is for. Reading the disk also finds a folder the user moved
//! WITHIN the library, which a recorded `out_dir` would not.
//!
//! A folder outside `out_dir` is not swept. Naming other roots is a
//! setting this does not add: it is a real product question (a sweep
//! pointed at an arbitrary path is a different consent from a sweep of
//! the daemon's own output), and the clicked road already heals any
//! folder somebody names.
//!
//! # Stated limits
//!
//! * **The cadence restarts with the process.** There is no persisted
//!   "last swept" stamp - the first sweep is
//!   [`HEAL_AUTO_SETTLE_SECS`] after start, then every
//!   `heal_auto_interval_h`. A daemon restarted more often than that
//!   sweeps more often than that, and the thing that bounds what a
//!   restart loop could spend is the per-sweep byte ceiling and
//!   `heal_one`'s own refusal to queue a repair of a post already being
//!   repaired in that folder, not the cadence.
//! * **One sweep does not necessarily cover the library.** At most
//!   [`HEAL_AUTO_FOLDERS_PER_SWEEP`] folders are verified per sweep and
//!   the next sweep resumes after the last one it reached, in the
//!   walk's own sorted order, so a large library is covered across
//!   several sweeps rather than in one enormous read. That cursor is
//!   in-process and restarts with the daemon.
//! * **A folder with no manifest is not checked and cannot be.**
//!   `write_manifest` decides whether one is ever written, and on an
//!   install where it has never been on this sweep finds nothing, walks
//!   the library once per interval and says so at debug level.

use super::heal::{RecordedPost, plan, recorded_post};
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

/// How long after start the first sweep runs.
///
/// Long enough that a restart is not a sweep trigger in practice, short
/// enough that "turn it on and see it do something" does not need a
/// week. Nothing about the number is measured; it is a settle.
const HEAL_AUTO_SETTLE_SECS: u64 = 900;

/// Folders verified per sweep, whatever the ceilings allow to be healed.
///
/// The bound on the READ, which is the cost a clean library pays: a
/// verify is a full read of every file the manifest can check, extracted
/// output included since `26f3860ab`, so a sweep of a library with
/// nothing wrong with it is pure disk for a "yes, still fine".
/// Measured there at 0.11 s/GiB (read plus CRC32) on an M5 Max, and
/// disk-bound rather than CPU-bound - the CRC is 0.04 of it.
/// 200 folders an interval covers an ordinary library in a couple of
/// sweeps and a very large one in a few, and the cursor makes the
/// progress cumulative rather than a repeated read of the first 200.
const HEAL_AUTO_FOLDERS_PER_SWEEP: usize = 200;

/// How deep below the library root a manifest is looked for, and how
/// many directory entries the walk will visit. The
/// `refeed::scan_nzbs` / `stream::find_completed_media` shape: a
/// pathological tree costs stats, never the pass.
const WALK_DEPTH: usize = 6;
const WALK_MAX_ENTRIES: usize = 50_000;

/// §310's scheduled-heal knobs. One struct rather than four fields on
/// [`Daemon`], for `AltSettings`' reason: a cost ceiling is not a cost
/// ceiling if the thing it bounds lives somewhere else.
pub struct HealAutoSettings {
    /// `heal_auto`: sweep the library and repair what is damaged. OFF,
    /// and the header says why at length.
    pub enabled: AtomicBool,
    /// `heal_auto_interval_h`: hours between sweeps. Weekly, because a
    /// sweep's cost is a full read of the folders it reaches and bit
    /// rot is not an hourly event.
    pub interval_h: AtomicU64,
    /// `heal_auto_max_jobs`: repairs one sweep may start. Four rather
    /// than the click's sixteen: the click states the full count to a
    /// person before spending, and nothing states anything to anybody
    /// here.
    pub max_jobs: AtomicU32,
    /// `heal_auto_max_bytes`: bytes one sweep may commit to, charged as
    /// the WHOLE size of each post (header, "Why the byte ceiling is
    /// counted against the whole post"). 20 GB pairs with four jobs at
    /// an ordinary release size; 0 is NOT unlimited here and means the
    /// sweep starts nothing, because an automatic road with no byte
    /// ceiling is the one shape this feature must not have.
    ///
    /// DECIMAL, because the settings arm's `parse_size` is - "20G"
    /// there is 20_000_000_000 - and a default in the other base reads
    /// back to a user as a number nobody typed.
    pub max_bytes: AtomicU64,
}

impl Default for HealAutoSettings {
    fn default() -> Self {
        HealAutoSettings {
            enabled: AtomicBool::new(false),
            interval_h: AtomicU64::new(168),
            max_jobs: AtomicU32::new(4),
            max_bytes: AtomicU64::new(20_000_000_000),
        }
    }
}

/// What one sweep is still allowed to spend. Decremented as repairs are
/// queued, so the two ceilings are one running state rather than two
/// counters that could be consulted in different places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SweepBudget {
    pub jobs_left: u32,
    pub bytes_left: u64,
}

/// Why the automatic road will not spend on a target it found damaged.
///
/// Every one of these is a target the CLICKED road would still offer -
/// nothing here convicts a folder or hides damage, it only declines to
/// act unasked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AutoRefusal {
    /// No recorded post, so the only road left is an indexer search for
    /// a copy nobody has compared to the disk. Header rule 2.
    NotRecorded,
    /// The record exists but says the post was zero bytes, so the byte
    /// ceiling has nothing to charge. The automatic road never spends
    /// what it cannot count.
    SizeUnknown,
    /// This sweep has started as many repairs as it may.
    JobBudget,
    /// This post's full size does not fit in what is left of the byte
    /// ceiling.
    ByteBudget,
}

impl AutoRefusal {
    /// The word the sweep's log line groups by.
    pub(super) fn word(self) -> &'static str {
        match self {
            AutoRefusal::NotRecorded => "no recorded post",
            AutoRefusal::SizeUnknown => "size unknown",
            AutoRefusal::JobBudget => "job ceiling",
            AutoRefusal::ByteBudget => "byte ceiling",
        }
    }
}

/// The whole of the automatic road's spending decision for one target,
/// as a function of the record and the remaining budget.
///
/// Free and daemon-free on purpose, exactly as `heal::plan` is: this is
/// the part of the feature that must stay right, and it is worth being
/// able to pin every arm of it without a daemon, a disk or a queue.
///
/// Hands BACK the record it admitted, rather than answering yes and
/// leaving the caller to unwrap the same `Option` again - the caller
/// charges [`RecordedPost::total_bytes`] against the budget, and an
/// admitted target with no record is a state this signature makes
/// unrepresentable instead of a branch nobody can reach.
///
/// The figure charged is the WHOLE post and not the damaged remainder:
/// the header's third rule, and the reason this is safe to ship before
/// the remainder-only property has been measured.
pub(super) fn auto_admits<'a>(
    rec: Option<&'a RecordedPost>,
    budget: &SweepBudget,
) -> std::result::Result<&'a RecordedPost, AutoRefusal> {
    let rec = rec.ok_or(AutoRefusal::NotRecorded)?;
    if rec.total_bytes == 0 {
        return Err(AutoRefusal::SizeUnknown);
    }
    if budget.jobs_left == 0 {
        return Err(AutoRefusal::JobBudget);
    }
    if rec.total_bytes > budget.bytes_left {
        return Err(AutoRefusal::ByteBudget);
    }
    Ok(rec)
}

/// Every directory at or below `root` that carries a settle manifest.
///
/// Bounded and symlink-safe, the `refeed::scan_nzbs` shape and for its
/// reasons: no symlink of any kind is taken, because a symlinked
/// DIRECTORY turns a bounded walk into an unbounded one and a symlinked
/// FILE can make something outside the library look like part of it.
/// `DirEntry::file_type` is lstat-shaped, which is what makes the test
/// honest.
///
/// Sorted, so the per-sweep cursor means the same thing on every machine
/// and across restarts.
pub(super) fn manifest_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if seen >= WALK_MAX_ENTRIES {
            break;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut has_manifest = false;
        for e in rd.flatten() {
            if seen >= WALK_MAX_ENTRIES {
                break;
            }
            seen += 1;
            let Ok(t) = e.file_type() else { continue };
            if t.is_symlink() {
                continue;
            }
            if t.is_dir() {
                if depth < WALK_DEPTH {
                    stack.push((e.path(), depth + 1));
                }
                continue;
            }
            if e.file_name() == crate::manifest::MANIFEST_NAME {
                has_manifest = true;
            }
        }
        if has_manifest {
            out.push(dir);
        }
    }
    out.sort();
    out
}

/// What one sweep did, for the log line and for the tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct SweepOutcome {
    /// Folders whose manifest was actually verified.
    pub verified: usize,
    /// Of those, the ones carrying damage.
    pub damaged: usize,
    /// Repairs queued.
    pub started: usize,
    /// Damaged targets left alone, and why. Counted rather than named:
    /// a library-wide sweep can find a lot of them and the log line is
    /// a summary, not a report. The clicked road's offer is the report.
    pub refused: Vec<(AutoRefusal, usize)>,
    /// Where the next sweep should resume, in [`manifest_dirs`] order.
    /// `None` means the walk was finished and the next sweep starts at
    /// the top again.
    pub resume_after: Option<PathBuf>,
}

impl SweepOutcome {
    pub fn refuse(&mut self, why: AutoRefusal) {
        match self.refused.iter_mut().find(|(w, _)| *w == why) {
            Some((_, n)) => *n += 1,
            None => self.refused.push((why, 1)),
        }
    }

    /// The refusals as one clause for the log, in a stable order.
    pub fn refused_phrase(&self) -> String {
        let mut parts: Vec<(AutoRefusal, usize)> = self.refused.clone();
        parts.sort_by_key(|(w, _)| w.word());
        parts
            .iter()
            .map(|(w, n)| format!("{n} {}", w.word()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Why the sweep is standing down, or `None` to run. A reason rather
/// than a bool for `indexing_pause_reason`'s reason: a background
/// pass that has quietly stopped is otherwise a mystery, and the
/// causes need opposite actions from the user.
///
/// Asked BEFORE the walk and again before EVERY folder, because the
/// expensive thing here is the per-folder verify and a download that
/// arrives mid-sweep must not have to wait for the rest of it.
pub(super) fn heal_auto_standdown(d: &Daemon) -> Option<&'static str> {
    if d.exiting.load(Ordering::Relaxed) {
        return Some("shutting down");
    }
    if !d.heal_auto.enabled.load(Ordering::Relaxed) {
        return Some("the switch is off");
    }
    // A repair is a DOWNLOAD, so offline forbids it for the reason
    // offline forbids an index scan: it is a promise that this
    // machine is touching no provider.
    if d.offline.load(Ordering::Relaxed) {
        return Some("the daemon is offline");
    }
    // Unconditional, unlike the scanners' version - they consult
    // `index_pause_on_download` first because a user may want
    // indexing to run through a download. Nobody has asked for a
    // library-wide full read to run through one.
    if d.queue_has_runnable() {
        return Some("a download is waiting");
    }
    None
}

/// One folder: verify it, and queue what the budget allows.
///
/// The verify is the expensive half and it happens exactly once per
/// folder per sweep, which is why this calls [`Daemon::heal_one`]
/// per target rather than `heal_start` - see that function's note.
fn heal_auto_folder(d: &Daemon, dir: &Path, budget: &mut SweepBudget, out: &mut SweepOutcome) {
    let Ok(plan) = plan(dir) else {
        // A folder whose manifest cannot be read or verified is not
        // a folder with something wrong in it, and this road says
        // nothing about it: the clicked road answers that question
        // with a sentence, to somebody who asked.
        return;
    };
    out.verified += 1;
    if plan.is_empty() {
        return;
    }
    out.damaged += 1;
    for t in &plan.targets {
        let rec = recorded_post(d, &t.nzb_sha);
        let bytes = match auto_admits(rec.as_ref(), budget) {
            Ok(r) => r.total_bytes,
            Err(why) => {
                out.refuse(why);
                continue;
            }
        };
        // Charged BEFORE the queue attempt and never given back.
        // A repair that failed to queue still had its cost
        // considered, and a sweep that retried around its own
        // failures would be a sweep with no ceiling on how many
        // times it tries.
        budget.jobs_left = budget.jobs_left.saturating_sub(1);
        budget.bytes_left = budget.bytes_left.saturating_sub(bytes);
        match crate::heal::heal_one(d, dir, t) {
            Ok(_) => {
                out.started += 1;
                info!(
                    target: "heal",
                    "repairing {} file(s) of {} in {} unasked ({:.1} GB budgeted)",
                    t.files.len(),
                    t.job,
                    dir.display(),
                    bytes as f64 / 1e9
                );
            }
            // Already on the queue is the common one and is not a
            // fault: `heal_one` owns that refusal because the add is
            // `DupeExempt::Anybody`.
            Err(e) => info!(target: "heal", "{}: not repaired - {e}", dir.display()),
        }
    }
}

/// One sweep over `dirs`, resuming after `after` and wrapping at the
/// end of the list.
///
/// Split from the loop that schedules it so the whole of the
/// decision can be driven from a test with a real directory and no
/// timer.
pub(super) fn heal_auto_sweep(d: &Daemon, dirs: &[PathBuf], after: Option<&Path>) -> SweepOutcome {
    let mut out = SweepOutcome::default();
    if dirs.is_empty() {
        return out;
    }
    let mut budget = SweepBudget {
        jobs_left: d.heal_auto.max_jobs.load(Ordering::Relaxed),
        bytes_left: d.heal_auto.max_bytes.load(Ordering::Relaxed),
    };
    // `partition_point` over the SORTED list: resume at the first
    // folder strictly after the one the last sweep reached, whether
    // or not that folder still exists. A cursor held as an index
    // would silently mean a different folder the moment one was
    // added or removed.
    let start = after.map_or(0, |a| dirs.partition_point(|d| d.as_path() <= a));
    let mut covered = 0usize;
    for step in 0..dirs.len().min(HEAL_AUTO_FOLDERS_PER_SWEEP) {
        if heal_auto_standdown(d).is_some() {
            break;
        }
        let dir = &dirs[(start + step) % dirs.len()];
        heal_auto_folder(d, dir, &mut budget, &mut out);
        covered += 1;
        out.resume_after = Some(dir.clone());
    }
    // EVERY folder was reached, so the next sweep starts at the top
    // rather than after the last one - which for a library smaller
    // than one sweep would otherwise re-read its final folder first,
    // forever. Counted rather than inferred from `verified`: a
    // folder whose manifest could not be read was still COVERED, and
    // a sweep cut short by a stand-down covered fewer than it
    // stepped past.
    if covered == dirs.len() {
        out.resume_after = None;
    }
    out
}

/// The scheduled sweep: settle, then one pass per `heal_auto_interval_h`.
///
/// An OS thread rather than a tokio task, the `spawn_update_checker`
/// shape and for both of its reasons: the work is a long BLOCKING read
/// of whole files, which has no business on a runtime thread, and the
/// sleep between passes is far longer than an embedded host's whole
/// start/stop cycle - so the handle is `Weak` and upgraded per pass,
/// or a week-long sleep would pin the entire daemon graph of every
/// generation.
pub fn spawn_scheduled_heal(daemon: &Arc<Daemon>) {
    let d = Arc::downgrade(daemon);
    let stop = RunStop::current();
    super::spawn_aux("scheduled-heal", move || {
        if !stop.sleep(std::time::Duration::from_secs(HEAL_AUTO_SETTLE_SECS)) {
            return;
        }
        let mut after: Option<PathBuf> = None;
        loop {
            let Some(d) = d.upgrade() else { return };
            // The switch is read at the top of every pass and never
            // cached: turning it off must stop the next sweep without a
            // restart, and turning it on must not need one either.
            if let Some(reason) = heal_auto_standdown(&d) {
                // Debug rather than info: with the feature off - the
                // default, and therefore nearly every install - this is
                // every install's log gaining a line a week for a
                // feature nobody switched on.
                tracing::debug!(target: "heal", "library sweep standing down: {reason}");
            } else {
                let root = crate::naming::out_dir(&d);
                let dirs = manifest_dirs(&root);
                let out = heal_auto_sweep(&d, &dirs, after.as_deref());
                after = out.resume_after.clone();
                if out.verified == 0 {
                    tracing::debug!(
                        target: "heal",
                        "library sweep: nothing under {} carries a settle manifest",
                        root.display()
                    );
                } else {
                    let refused = out.refused_phrase();
                    info!(
                        target: "heal",
                        "library sweep: {} folder(s) checked, {} damaged, {} repair(s) started{}",
                        out.verified,
                        out.damaged,
                        out.started,
                        if refused.is_empty() {
                            String::new()
                        } else {
                            format!(" ({refused} left for the manual road)")
                        }
                    );
                }
            }
            let hours = d
                .heal_auto
                .interval_h
                .load(Ordering::Relaxed)
                .clamp(1, 8760);
            // Dropped before the sleep, so a host that stops the engine
            // during the wait is not held up by this thread's handle.
            drop(d);
            if !stop.sleep(std::time::Duration::from_secs(hours * 3600)) {
                return;
            }
        }
    });
}

#[cfg(test)]
#[path = "healauto_tests.rs"]
mod healauto_tests;
