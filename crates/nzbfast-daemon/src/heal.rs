//! §310 stage 2: the heal wiring - manifest-detected damage to a new
//! job that re-fetches only what is broken.
//!
//! Stage 1 gave a finished directory a `.nzbfast.manifest`: every
//! checksum the download proved, kept beside the payload so the folder
//! can verify itself years later with no PAR2 left on disk. It can
//! DETECT damage and it can say what is damaged. It cannot fix
//! anything. This module is the other half.
//!
//! # None of it is new engine work, and that is the design
//!
//! Three pieces already existed and this file only joins them up.
//!
//! * **Detection plus identity** is the manifest's, and the per-entry
//!   `job` / `nzb_sha` that stage 1 landed are why. A TV-filed job's
//!   `out_dir` is the SHARED season folder claimed by every episode in
//!   it, so one manifest legitimately carries entries proved by several
//!   different posts - and in a season folder the post to re-fetch
//!   differs per episode. [`plan`] therefore groups the damage BY
//!   PROVENANCE and never by directory, and
//!   `two_damaged_episodes_re_hunt_their_own_posts` pins it.
//! * **The search** is §282's, reached through
//!   [`Daemon::hunt_by_name`] - the fallback road, taken only when the
//!   recorded post's own `.nzb` is gone. That function's header sets
//!   out which §282 gates a heal does not run and why each one is a
//!   question about a failed job rather than about a damaged file.
//! * **The cheap repair** is §293 Shape A's, and it needs nothing here
//!   at all: the heal job carries the library folder in
//!   [`Job::heal_dir`], `tasks::worker` puts it in `donor_dirs`, and
//!   the adoption scan then reads every intact byte off the disk
//!   instead of the wire. Cross-set adoption over identical bytes is
//!   proven (§293, 13/13 blocks), so a fresh post's own PAR2 grid
//!   judges the library copy perfectly well even though the two sets
//!   were cut by different tools.
//!
//! # The trigger is EXPLICIT, and that is a decision
//!
//! A heal starts a DOWNLOAD. It spends the user's bytes, possibly
//! metered ones, on files they already believe they have. So it is
//! never a side effect of something else:
//!
//! * `nzbfast verify` REPORTS and does not heal. Its whole stated job
//!   is to answer a question, and a command that answers a question by
//!   starting a download is one nobody can run safely in a script.
//! * Nothing runs on a schedule. There is no sweep of the library, no
//!   nightly re-verify, no automatic re-fetch. A daemon that quietly
//!   re-downloads a folder because a byte moved is a daemon nobody can
//!   leave running on a metered line.
//! * The door is two steps, the shape §282 item 20's clicked road
//!   already established. [`Daemon::heal_offer`] reads the directory
//!   and reports what is damaged and which post each piece needs; it
//!   touches no network, spends no indexer grab and enqueues nothing.
//!   [`Daemon::heal_start`] is the one that spends, and it only ever
//!   runs on a directory somebody has just named.
//!
//! Whether the daemon should ALSO be able to do this on its own -
//! verify the library on a schedule and heal what it finds - was the
//! product call this paragraph left open. **It was taken on 2 Sep 2026:
//! yes, and opt-in.** [`super::healauto`] is that road, and it needed
//! nothing here changed - it calls [`plan`] once per folder and
//! [`Daemon::heal_one`] per target, which is what this paragraph
//! predicted. What it did NOT predict, and what that module's header
//! sets out at length, is that an automatic road needs ceilings of its
//! OWN: [`MAX_HEAL_JOBS`] below is sized for a person who clicked, and
//! the argument under it ("the offer states the full count before
//! anything is spent, so a user who means it can heal the rest by
//! asking again") is exactly the argument that does not survive
//! automation, because nobody is asking again.
//!
//! So do not read this file as the whole of the heal road's cost
//! discipline any more. It is the CLICKED road's, and the clicked road
//! is still the only one on by default.
//!
//! # What it does not do, stated rather than left to be found
//!
//! **The healed file lands wherever this daemon files that release,
//! which is usually but not always the folder that was damaged.** A
//! heal job is an ordinary job: its destination comes from
//! `complete_dir`, the category and TV filing, exactly as the original
//! job's did. For a folder nzbfast itself produced and nobody moved,
//! that is the same directory, and the finalize move puts the repaired
//! file back in place. For a library folder the user has since moved
//! somewhere else it is not, and the repaired copy arrives beside the
//! damaged one rather than over it. Pinning a job's `out_dir` is real
//! work in the finalize path and it is not this box; the donor arm is
//! unaffected either way, because `donor_dirs` names the damaged folder
//! explicitly.
//!
//! **A heal of EXTRACTED output re-fetches the whole post, and that is
//! the one case where the cheap-repair claim above does not hold.**
//! Extracted output is convictable since 2 Sep 2026 - `write_reconciled`
//! reads every file the recovery set never covered and records a CRC32
//! block grid for it, so the film itself is [`FileStatus::Damaged`] when
//! it rots and this module plans a heal for it exactly as it does for a
//! loose file. What it cannot do is adopt: the damaged folder holds the
//! EXTRACTED file, the fresh post's PAR2 set describes the VOLUMES, and
//! `donor_dirs` matches a donor to a target by that set's own lengths
//! and digests - so there is nothing in the folder for the adoption scan
//! to recognise, and the repair spends the whole post rather than the
//! damaged remainder. A loose-file post is unaffected and still adopts
//! every intact byte. Worth knowing before the scheduled heal runs this
//! unattended, and worth stating in the offer if that ever grows a byte
//! estimate; it is not a reason to withhold the detection, because the
//! alternative on offer is a film that rots unnoticed.

use super::*;
use crate::manifest::{FileStatus, Manifest};

/// One post to re-fetch, and the damaged files that name it.
///
/// The unit a heal works in. NOT a directory and not a file: a
/// directory can hold files from many posts, and several damaged files
/// from one post are one download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealTarget {
    /// The release name recorded on the entries at settle time - the
    /// identity a search is aimed with.
    pub job: String,
    /// The sha of the NZB that proved them, which is how the spooled
    /// copy of that exact post is found again.
    pub nzb_sha: String,
    /// The damaged entries, by manifest name, in manifest order.
    pub files: Vec<String>,
}

/// What [`plan`] found in a directory.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HealPlan {
    pub targets: Vec<HealTarget>,
    /// Damaged entries whose provenance the manifest does not carry, so
    /// nothing can be re-fetched for them. Reported rather than
    /// dropped: a directory that is damaged and unhealable is a
    /// different answer from a directory that is clean, and a user told
    /// only about the healable half would read silence as health.
    ///
    /// Reachable on a manifest written by a build older than stage 1's
    /// per-entry provenance, and on nothing this binary writes.
    pub unidentified: Vec<String>,
}

impl HealPlan {
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty() && self.unidentified.is_empty()
    }
}

/// The most posts one [`Daemon::heal_start`] call will queue.
///
/// The bound that replaces §282's copy cap and byte ceiling, which do
/// not apply here (see [`Daemon::hunt_by_name`]). A whole shelf of
/// rotted files is a real shape - a failing disk damages everything on
/// it at once - and one click should not be able to start two hundred
/// downloads. The offer states the full count before anything is spent,
/// so a user who means it can heal the rest by asking again, or name
/// one post at a time.
///
/// READ FROM ONE OTHER PLACE, and it is not a second bound: the
/// `heal_auto_max_jobs` setter clamps the SCHEDULED sweep's own ceiling
/// to this number, so an unattended road can never be allowed more in
/// one pass than a person looking at the damage report may start with
/// one click. Its default is far below this (see
/// [`super::healauto::HealAutoSettings`]); this is only the ceiling on
/// what may be typed.
pub(super) const MAX_HEAL_JOBS: usize = 16;

/// Read `dir`'s settle manifest, verify it, and group what is damaged by
/// the post that proved it.
///
/// Pure and daemon-free on purpose: everything above the network is
/// decided here, so the grouping rule that a season folder depends on
/// can be pinned without standing a daemon up.
///
/// `Damaged`, `Missing` and `SizeMismatch` are the damage.
/// `SourceGone` is not - a PAR2-covered archive volume the unpack tail
/// consumed is the normal end state, and convicting it would report
/// every extracted job as broken. `PresentUnverified` is not either:
/// nothing was proved about it, and "I cannot check this" is not
/// "this is wrong" (the same rule `verify` takes for a directory with
/// nothing to check).
///
/// `PresentUnverified` is a much narrower set than it was: extracted
/// output moved OUT of it on 2 Sep 2026 and is convicted by its grid
/// like anything else. What is left is a file the grid pass could not
/// read and archive material a sweep may still take - neither of which
/// a heal has any business re-downloading.
pub fn plan(dir: &Path) -> std::io::Result<HealPlan> {
    let m = Manifest::load(dir)?;
    let report = m.verify(dir)?;
    let damaged: std::collections::HashSet<&str> = report
        .files
        .iter()
        .filter(|(_, s)| {
            matches!(
                s,
                FileStatus::Damaged { .. } | FileStatus::Missing | FileStatus::SizeMismatch { .. }
            )
        })
        .map(|(n, _)| n.as_str())
        .collect();
    let mut out = HealPlan::default();
    // Walked over the MANIFEST rather than over the report, so the
    // grouping reads each entry's own `job`/`nzb_sha` - the report
    // carries names and verdicts and no provenance at all. Manifest
    // order is kept, so the answer is stable across calls.
    for e in &m.files {
        if !damaged.contains(e.name.as_str()) {
            continue;
        }
        if e.job.is_empty() || e.nzb_sha.is_empty() {
            out.unidentified.push(e.name.clone());
            continue;
        }
        match out
            .targets
            .iter_mut()
            .find(|t| t.job == e.job && t.nzb_sha == e.nzb_sha)
        {
            Some(t) => t.files.push(e.name.clone()),
            None => out.targets.push(HealTarget {
                job: e.job.clone(),
                nzb_sha: e.nzb_sha.clone(),
                files: vec![e.name.clone()],
            }),
        }
    }
    Ok(out)
}

/// The record that produced a target's files, if either store still has
/// it.
///
/// Keyed on the NZB sha and not the name, because the name is the thing
/// two different posts of one release share and the sha is the thing
/// they do not. The queue is read first for the reason
/// `altcand::alt_switch` reads it first: a row in both stores for an
/// instant is the queue row it is about to stop being.
#[derive(Debug, Clone)]
pub(super) struct RecordedPost {
    pub nzo_id: String,
    pub category: String,
    /// The spooled `.nzb`, proved to be a file before this is handed back.
    pub nzb: PathBuf,
    /// What the original download of this post came to, in bytes.
    ///
    /// Carried for [`super::healauto`] and for nothing on the clicked
    /// road, which spends whatever the post costs because a person
    /// asked. The automatic road may not: its byte ceiling is counted
    /// against this figure, deliberately as the WHOLE post rather than
    /// as the damaged remainder - see that module's header for why the
    /// pessimism is the point and what would relax it.
    pub total_bytes: u64,
}

pub(super) fn recorded_post(d: &Daemon, sha: &str) -> Option<RecordedPost> {
    let take = |j: &Arc<Mutex<Job>>| {
        let g = j.lock_ok();
        (g.nzb_sha == sha).then(|| RecordedPost {
            nzo_id: g.nzo_id.clone(),
            category: g.category.clone(),
            nzb: g.nzb_path.clone(),
            total_bytes: g.total_bytes,
        })
    };
    let found = d
        .queue
        .lock_ok()
        .iter()
        .find_map(take)
        .or_else(|| d.history.lock_ok().iter().find_map(take))?;
    // The spool copy goes with the record when the record is deleted,
    // and a heal wants the FILE, not the memory of it. A row whose
    // spool is gone falls through to the search road exactly as a row
    // that aged out of history does.
    found.nzb.is_file().then_some(found)
}

/// Origin recorded on a job the heal enqueued: `heal:<nzb sha>`.
///
/// The `prefix:detail` shape `arr:`, `hunt:` and `watchlist:` already
/// use, so this needs no new `Job` field and no queue migration. The
/// detail is the POST, because that is what the heal is about - the
/// same release may be healed twice from two different posts, and the
/// two are not one event.
///
/// Nothing matches this prefix today, which is deliberate: `altspend`'s
/// ledger must not count a heal as an alternate (it replaces no queue
/// row), and the dashboard's origin map renders an unknown token as
/// nothing rather than as itself, so no internal word reaches a user.
fn heal_origin(sha: &str) -> String {
    format!("heal:{sha}")
}

/// The read-only half: what is damaged here, and what a heal would
/// do about it.
///
/// Costs one pass over the directory's payload - the manifest verify
/// is a full read of every covered file, which is the price of
/// knowing - and NOTHING else. No indexer is asked, no grab is
/// spent, nothing is enqueued and nothing downloads.
///
/// The `source` on each row is what [`Self::heal_start`] would
/// reach for: `recorded` when the exact post's spooled `.nzb` is
/// still here, `search` when it is not and the name can be aimed
/// with, `none` when it is not and the name carries no identity - a
/// fully obfuscated release, most often. The last is worth saying
/// out loud rather than discovering at the second click.
pub fn heal_offer(d: &Daemon, dir: &str) -> std::result::Result<Value, String> {
    let dir = PathBuf::from(dir);
    let plan = heal_plan_for(&dir)?;
    let rows: Vec<Value> = plan
        .targets
        .iter()
        .map(|t| {
            let rec = recorded_post(d, &t.nzb_sha);
            // The same predicate `hunt_by_name` refuses on, so the
            // report and the second click cannot disagree about
            // whether a search is even aimable.
            let source = match (&rec, super::hunt::searchable_by_name(&t.job)) {
                (Some(_), _) => "recorded",
                (None, true) => "search",
                (None, false) => "none",
            };
            json!({
                "name": t.job,
                "nzb_sha": t.nzb_sha,
                "files": t.files,
                "source": source,
                "nzo_id": rec.map(|r| r.nzo_id).unwrap_or_default(),
            })
        })
        .collect();
    Ok(json!({
        "dir": dir.to_string_lossy(),
        "targets": rows,
        "unidentified": plan.unidentified,
        "max_jobs": MAX_HEAL_JOBS,
    }))
}

/// The half that spends: queue one job per damaged post, each with
/// the library folder set as a donor.
///
/// `sha` names ONE target from the offer's list; empty heals every
/// target the plan found, capped at [`MAX_HEAL_JOBS`].
///
/// The gates are re-run rather than trusted from the offer - the
/// directory is re-verified here - because the two calls are a user
/// apart and a file can be repaired, deleted or damaged further in
/// between. That is the same rule `hunt_pick` states for its own
/// cached list.
pub fn heal_start(d: &Daemon, dir: &str, sha: &str) -> std::result::Result<Value, String> {
    let dir = PathBuf::from(dir);
    let plan = heal_plan_for(&dir)?;
    // A clean folder is a refusal with a sentence, not an empty
    // success: the caller asked for a repair, and "started nothing"
    // reads as a failure unless it is told why.
    if plan.is_empty() {
        return Err("nothing in that folder is damaged".into());
    }
    let mut targets = plan.targets;
    if !sha.is_empty() {
        targets.retain(|t| t.nzb_sha == sha);
        if targets.is_empty() {
            return Err("that post is not damaged in this folder any more - \
                        check the folder again"
                .into());
        }
    }
    let over = targets.len().saturating_sub(MAX_HEAL_JOBS);
    targets.truncate(MAX_HEAL_JOBS);
    let mut started = Vec::new();
    let mut refused = Vec::new();
    for t in &targets {
        match heal_one(d, &dir, t) {
            Ok(v) => started.push(v),
            Err(e) => refused.push(json!({"name": t.job, "error": e})),
        }
    }
    Ok(json!({
        "dir": dir.to_string_lossy(),
        "started": started,
        "refused": refused,
        "not_started": over,
    }))
}

/// [`plan`], with the two refusals a caller can act on turned into
/// sentences. Shared by both doors so the search and the start
/// cannot disagree about what a directory says.
///
/// Takes no daemon: it was an inherent method whose `&self` no line of
/// its body ever read, which nothing reports (an unused `self` is not an
/// unused variable). Lifting it to a free function turned that into an
/// `unused_variables` warning, and the slim build is where it surfaced.
fn heal_plan_for(dir: &Path) -> std::result::Result<HealPlan, String> {
    if !dir.is_dir() {
        return Err("that folder is not there".into());
    }
    let plan = plan(dir).map_err(|e| {
        format!(
            "that folder carries no settle manifest this daemon can read, \
             so there is nothing to check it against ({e})"
        )
    })?;
    Ok(plan)
}

/// One target: find the post, fetch it, queue it with the library
/// folder as a donor.
///
/// TWO CALLERS since 2 Sep 2026, and the second is why this is
/// `pub(super)` rather than private. [`Self::heal_start`] is the
/// clicked road; [`super::healauto`] is the scheduled one, and it
/// calls this directly rather than `heal_start` because
/// `heal_start` re-verifies the whole folder per call - a full read
/// of every covered file - which a sweep over a library would then
/// pay once PER DAMAGED POST in a folder instead of once. The
/// automatic road does its one [`plan`] and comes here per target.
///
/// **Every ceiling therefore lives in the caller, not here**, and a
/// third caller must bring its own. This function spends
/// unconditionally: it is the act, not the decision.
pub(super) fn heal_one(
    d: &Daemon,
    dir: &Path,
    t: &HealTarget,
) -> std::result::Result<Value, String> {
    // A repair already running for this post AND this folder is the
    // answer to a second click, not a licence to start a second
    // download of the same release. It has to be checked HERE
    // because the add below is `DupeExempt::Anybody`, which is what
    // turns the duplicate ladder off - the ladder is normally what
    // stops this, and a heal cannot use it (see the add).
    if d.queue.lock_ok().iter().any(|j| {
        let g = j.lock_ok();
        g.origin == heal_origin(&t.nzb_sha) && g.heal_dir == dir && !g.tombstone
    }) {
        return Err("a repair of that post in this folder is already on the queue".into());
    }
    // THE RECORDED POST FIRST, and this is the ordering that makes a
    // heal different from a hunt. §282 hunts because the post is
    // dead; a heal runs because the DISK is damaged, and the post
    // that proved these bytes is by far the likeliest to still serve
    // them. It also costs no indexer grab and no search.
    let (bytes, name, category, replaces) = match recorded_post(d, &t.nzb_sha) {
        Some(rec) => {
            let bytes = std::fs::read(&rec.nzb).map_err(|e| {
                format!("the .nzb this folder was downloaded from could not be read ({e})")
            })?;
            (bytes, t.job.clone(), rec.category, rec.nzo_id)
        }
        // Its `.nzb` is gone with its history record, so the only
        // road left is a search for the same release. Everything
        // this does and does not check is on `hunt_by_name`.
        None => {
            let (stem, bytes, _headers) =
                crate::hunt::hunt_by_name(d, &t.job).ok_or_else(|| {
                    "no copy of that release could be found to repair it from - the \
                 post it came from is no longer on record here, and the indexers \
                 offered nothing"
                        .to_string()
                })?;
            (bytes, stem, String::new(), String::new())
        }
    };
    // `DupeExempt::Anybody`, and it has to be. A heal is BY
    // DEFINITION a second copy of something this daemon already
    // finished - the completed history row is still there, and that
    // is what the duplicate ladder would hold the add behind. The
    // exemption's own doc calls this case "the user was ASKED and
    // said yes", which is exactly what a heal request is: a person
    // named the folder and asked for their file back. It suppresses
    // the hold, not the identity, so everything downstream that
    // reasons about duplicates still sees the row for what it is.
    //
    // **ADDED PAUSED (`-2`), and that is not a nicety.** `enqueue`
    // has published a runnable row by the time it answers, and the
    // donor path is stamped one statement later - so a runner poll
    // landing in that window starts a heal with no donor directory,
    // which quietly re-downloads the whole release instead of the
    // damaged blocks. That is the entire economic point of the
    // feature lost to a race, and it would be invisible: the job
    // succeeds. SAB's -2 is "add paused" rather than a priority
    // (`enqueue_priority` resolves the row to Normal either way), so
    // the row cannot be picked until the stamp below releases it.
    let e = d
        .enqueue_as(
            None,
            &bytes,
            &name,
            &category,
            -2,
            None,
            None,
            &heal_origin(&t.nzb_sha),
            DupeExempt::Anybody,
            None,
        )
        .map_err(|e| format!("that repair could not be queued: {e}"))?;
    // The stamp and the release, under ONE hold of the queue, then
    // saved: `enqueue` saved the queue before either existed, so
    // without this second save a restart in the window leaves a
    // paused row with no donor - and the pause is what makes that
    // the safe direction rather than a silent full re-download.
    let stamped = {
        let q = d.queue.lock_ok();
        match q.iter().find(|j| j.lock_ok().nzo_id == e.nzo_id) {
            Some(job) => {
                let mut g = job.lock_ok();
                g.heal_dir = dir.to_path_buf();
                g.paused = false;
                true
            }
            None => false,
        }
    };
    if !stamped {
        // `enqueue` answers `Ok` for an add a pre-queue verdict
        // filed straight to history, so a missing row is not a bug
        // here - it is that. Say so rather than reporting a repair
        // that will never run (the same shape Codex sweep F-08 found
        // on the hunt road).
        return Err("that repair was refused before it reached the queue - \
                    the log says why"
            .into());
    }
    d.save_queue();
    info!(
        target: "queue",
        "{}: healing {} file(s) in {} from {} ({})",
        e.nzo_id,
        t.files.len(),
        dir.display(),
        name,
        if replaces.is_empty() {
            "found by search"
        } else {
            "the post it came from"
        }
    );
    Ok(json!({
        "nzo_id": e.nzo_id,
        "name": name,
        "nzb_sha": t.nzb_sha,
        "files": t.files,
        "replaces": replaces,
    }))
}

#[cfg(test)]
#[path = "heal_tests.rs"]
mod heal_tests;
