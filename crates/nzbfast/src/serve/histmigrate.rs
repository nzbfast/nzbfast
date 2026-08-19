//! TODO §188: re-deriving history's presentation after a labelling fix.
//!
//! A history row stores the CONCLUSION, not the evidence. `media` holds
//! "2160p", never the 3840x2160 it was read from, so when 67f212a4 fixed
//! `res_label` promoting a full-height scope encode (2592x1080) to
//! 1440p, every row already written kept the wrong word - and no amount
//! of reasoning over the stored row could recover the right one, because
//! the input the rule had misread was gone.
//!
//! That cost real triage. Gary reported three ALREADY-FIXED bugs as
//! unfixed on 1.1.5, because his rows were written by 1.1.3 and still
//! carried 1.1.3's labels; two rounds went into establishing that the
//! code was right and the rows were old.
//!
//! This module closes it from both ends:
//!
//!  * [`nzbkit::mediaprobe::MediaFacts::width`] now keeps the raw frame
//!    size beside the label it reduces to, so the NEXT such fix is
//!    arithmetic over two stored integers - no disk, and it reaches a
//!    row whose payload was deleted years ago;
//!  * this pass fixes the rows written before that, the only way they
//!    can be fixed: by reading the file again, where the file is still
//!    there.
//!
//! ## What is re-derived, and what is emphatically not
//!
//! Only the media chip - a VIEW of a file, and re-computable exactly as
//! long as the file exists.
//!
//! The recorded FACTS are never touched: bytes, timings, which servers
//! answered, the failure text. Neither is the failure REASON or the
//! retry hint, and that is not caution, it is a category difference.
//! Those sentences summarise state that no longer exists - how many
//! segments were missing, which servers were asked, what the backoff
//! had spent - and `post_age_days` was not stored on old rows at all
//! (the 4d8b3352 bug). Regenerating them would not correct a stale
//! rendering, it would MANUFACTURE a new account of an event nobody
//! witnessed, and file it as history. A wrong label is a bug; an
//! invented reason is a falsified record. The chip is a view; the
//! reason is a record. Only views are re-derived here.
//!
//! ## Why the whole history, at startup, and not lazily per drawer
//!
//! Because the chip is not in the drawer. `mediaBadge(s.media)` renders
//! in the history LIST row (dashboard.html, the `.nmtxt` cell), so a
//! re-derivation that waited for a drawer to open would leave the wrong
//! label sitting in plain sight on every row the user never expands -
//! which is exactly the surface Gary was reading off. Lazy is cheaper
//! and fixes the wrong thing.
//!
//! The cost that buys is paid off the critical path: nothing here runs
//! before the daemon serves, it is one background thread, it sleeps
//! between probes, and it touches no row whose label it cannot improve.
//!
//! ## Why there is no cursor, on purpose
//!
//! A pass killed halfway re-runs from the top next boot, and that is
//! cheap BY CONSTRUCTION rather than by bookkeeping: a row corrected by
//! the first run now carries its own width and height, so the second run
//! takes the arithmetic path and never opens the file. The pass
//! accelerates itself, and every step of it is idempotent - a row whose
//! label is already right produces no change and therefore no write. A
//! cursor would be state to keep correct across history mutation in
//! exchange for nothing.
//!
//! ## Locking
//!
//! Probing is slow work - a directory walk and a file read, possibly
//! over a network mount that is not answering - and slow work under a
//! daemon lock is how this codebase has wedged twice (the 15 Aug
//! retention reap, the 16 Aug index scan; see the memory notes). So the
//! history list lock is taken ONCE, to clone the `Arc`s out, and
//! dropped. Every probe happens with no lock of ours held. The job lock
//! is taken twice per row, each time around a field copy or a field
//! store, never across the I/O between them.

use super::histstore::HistWrite;
use super::*;

/// The version stamp, in `.spool/hist-media.json`. Just the build whose
/// derivation rules the rows were last re-checked against; absent on an
/// install predating this file, which is the case the pass exists for.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct MigrateState {
    #[serde(default)]
    version: String,
    /// Passes that ran on `attempt_version` and could not finish - a
    /// store that refused the append, a volume that would not open. The
    /// version is NOT stamped for those, so the next boot runs again;
    /// this is the bound on "again", because a volume that is gone for
    /// good would otherwise walk the whole history at every start of
    /// this build forever (Codex sweep 7, M5/M6).
    #[serde(default)]
    attempts: u32,
    /// Which build those attempts were spent on. Separate from
    /// `version` because that field means "finished cleanly", and a
    /// count carried over from the PREVIOUS build would spend a new
    /// build's retries before it had had one.
    #[serde(default)]
    attempt_version: String,
}

/// How many faulted passes one build gets before it gives up and stamps
/// anyway. Each costs one daemon start, so this is five restarts for a
/// NAS to come up or a permission to be granted - generous for the
/// cases that resolve, and short of endless for the case that does not.
const MAX_ATTEMPTS: u32 = 5;

/// The one-time "history display was updated" strip.
///
/// Kept in its OWN file, `.spool/hist-notice.json`, and its existence is
/// the whole flag: written when a pass corrects something, deleted when
/// the user dismisses it. That is why there is no `Daemon` field
/// caching it - the queue payload asks the filesystem, and in the steady
/// state (no notice owed, which is every run but the one after an
/// upgrade that changed something) the answer is a single ENOENT on a
/// path the OS has cached. A field would have been the `delete_kept`
/// shape, but `delete_kept` is a ring that mutates during normal
/// operation; this is one small record written once and read until it
/// is deleted, and splitting it from the version stamp buys the cheap
/// steady-state read that makes the field unnecessary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct MigrateNotice {
    /// Rows whose label the re-derivation actually changed.
    pub(super) corrected: u32,
    /// Rows that carried a label, had no stored frame size, and whose
    /// file is no longer on disk - so nothing could re-check them and
    /// they keep what they were written with. Reported because the
    /// alternative is a notice that implies the whole history was
    /// brought up to date when part of it provably was not.
    pub(super) kept: u32,
    /// When the pass finished, unix seconds.
    pub(super) at: i64,
}

impl Daemon {
    fn hist_migrate_path(&self) -> PathBuf {
        self.spool.join("hist-media.json")
    }

    fn hist_notice_path(&self) -> PathBuf {
        self.spool.join("hist-notice.json")
    }

    pub(super) fn hist_migrate_state(&self) -> MigrateState {
        std::fs::read(self.hist_migrate_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_hist_migrate(&self, state: &MigrateState) {
        if let Ok(text) = serde_json::to_string_pretty(state) {
            let _ = crate::persist::write_atomic(&self.hist_migrate_path(), text.as_bytes());
        }
    }

    /// The notice owed to the user, or `None`. Read on the queue-payload
    /// path, so it stays one cheap read - see [`MigrateNotice`].
    pub(super) fn hist_notice(&self) -> Option<MigrateNotice> {
        std::fs::read(self.hist_notice_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    /// Raise the notice, and move the revision so an idle dashboard sees
    /// it. Persisted rather than held in memory because the pass runs at
    /// startup - which for an auto-update is precisely when nobody is
    /// looking - so a toast into an empty room would be the whole of the
    /// telling.
    /// Merged into whatever is still owed, never written over it. The
    /// file IS the flag, so an outright write spent a notice the user
    /// had not read yet - a second pass raising its own strip destroyed
    /// the first one's counts with nobody having dismissed anything
    /// (Codex sweep 7, L3). The two counts merge differently because
    /// they mean different things: a row the first pass corrected is
    /// right now and the second pass will not correct it again, so
    /// corrections are of disjoint rows and add up, while the same
    /// missing payloads are re-counted as kept by every pass, so the
    /// larger count stands rather than the sum.
    fn raise_hist_notice(&self, notice: &MigrateNotice) {
        let notice = match self.hist_notice() {
            Some(prev) => MigrateNotice {
                corrected: prev.corrected.saturating_add(notice.corrected),
                kept: prev.kept.max(notice.kept),
                at: notice.at.max(prev.at),
            },
            None => notice.clone(),
        };
        if let Ok(text) = serde_json::to_string_pretty(&notice)
            && let Err(e) = crate::persist::write_atomic(&self.hist_notice_path(), text.as_bytes())
        {
            error!(target: "media", "hist notice: {e}");
        }
        self.queue_rev.fetch_add(1, Ordering::Relaxed);
    }

    /// Spend the notice - the user has read it and dismissed it.
    ///
    /// The `queue_rev` bump is not optional and not decoration. The
    /// strip rides the revisioned queue payload, and `m_dashboard`
    /// answers `queue: null` while the client's revision matches - so on
    /// an IDLE daemon a dismissal that does not move the revision clears
    /// the notice here and nowhere the user can see, and the strip sits
    /// there until an unrelated queue mutation or a reload. That is the
    /// payload-rider trap, already paid for five times (the update
    /// banner, `set_limit`, `watch_failed_*`, `publish_hold`, and
    /// `spend_kept_notice` - reported by a Windows tester on 16 Aug).
    /// This pass RAISES its notice at startup, on a daemon with nothing
    /// in the queue, which is precisely the condition that hides it.
    ///
    /// The answer is whether the notice is SPENT, and the unlink is the
    /// whole of spending it - the file's existence is the flag. A
    /// failure there leaves the strip owed and the next payload builds
    /// it again, so reporting success would make the status field a
    /// word that means nothing (Codex sweep 7, L3). No caller reads it
    /// today, which is why the user is not currently told a falsehood:
    /// the dashboard re-renders the strip from the live payload and it
    /// visibly fails to go away.
    pub(super) fn dismiss_hist_migrate(&self) -> bool {
        if self.hist_notice().is_none() {
            return false;
        }
        let path = self.hist_notice_path();
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            // Another dismissal got there between the read above and
            // this call. The notice is spent, which is what was asked.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                error!(target: "media", "hist notice {}: {e}", path.display());
                return false;
            }
        }
        self.queue_rev.fetch_add(1, Ordering::Relaxed);
        true
    }
}

/// How long to rest between two rows that each cost a disk probe. Small
/// enough that a few hundred rows finish inside a minute, large enough
/// that the pass never competes with a live download for a spinning disk
/// or a NAS link. Rows taking the arithmetic path do not pay it.
const PROBE_REST: std::time::Duration = std::time::Duration::from_millis(50);

/// Env override so the daemon suite does not sit through the rest.
fn probe_rest() -> std::time::Duration {
    match std::env::var("NZBFAST_HIST_MIGRATE_REST_MS") {
        Ok(v) => v
            .parse()
            .map(std::time::Duration::from_millis)
            .unwrap_or(PROBE_REST),
        Err(_) => PROBE_REST,
    }
}

/// Re-derive one row's chip in place, and say whether it changed.
///
/// The three arms, in the order they are cheapest:
///
/// 1. no label at all - a failed or unprobed download - is skipped
///    outright. There is no view here to correct;
/// 2. a stored frame size re-derives by arithmetic, no disk;
/// 3. otherwise the file itself, IF it is still there.
///
/// Arm 3's result is accepted only when it is COMPLETE and says
/// something. A partial re-read - a file mid-move, a NAS that answered
/// half a header - would otherwise replace a good label with a worse
/// one, which is the downgrade `latch_media` refuses for the same
/// reason. When it is refused the row is left exactly as written, which
/// is also what a missing file gets.
///
/// Arm 3 also reports WHY it found nothing, because the caller stamps
/// the build on the strength of it. See [`RowOutcome::Unreadable`].
pub(super) fn rederive_row(d: &Daemon, job: &Arc<Mutex<Job>>) -> RowOutcome {
    // Copy what the decision needs, then let go of the job.
    let (mut facts, name, id, moving) = {
        let j = job.lock_ok();
        let Some(facts) = j.media.clone() else {
            return RowOutcome::Skipped;
        };
        let name = if j.identity_name.is_empty() {
            j.name.clone()
        } else {
            j.identity_name.clone()
        };
        (facts, name, j.nzo_id.clone(), j.move_pending)
    };

    // Arm 2: the inputs are on the row. No file needed, so this arm
    // works on a deleted download exactly as well as on a kept one.
    if facts.width.is_some() {
        if !nzbkit::mediaprobe::facts::rederive_res(&mut facts, &name) {
            return RowOutcome::Unchanged;
        }
        job.lock_ok().media = Some(facts);
        return RowOutcome::Corrected;
    }

    // A job whose payload is being relocated has an `out_dir` that names
    // where the bytes are going, not where they all are: the same-device
    // merge path empties the source entry by entry while that name is
    // still current. Reading it now would be reading a half-moved
    // directory, and calling the miss "gone" would seal the row on the
    // strength of a millisecond. Cheap to ask, and asked with the job
    // lock already dropped.
    if moving || d.moving.lock_ok().contains(&id) {
        return RowOutcome::Unreadable;
    }

    // Arm 3: read the file again. NO LOCK IS HELD ACROSS THIS.
    let fresh = match super::tasks::probe_disk_facts_checked(d, job) {
        Ok(Some(f)) => f,
        Ok(None) => return RowOutcome::Gone,
        Err(_) => return RowOutcome::Unreadable,
    };
    if !fresh.complete || !fresh.any() {
        return RowOutcome::Gone;
    }
    // Did anything the USER can see change, or did the row merely gain
    // the frame size it was missing? The two must not be conflated: the
    // notice counts corrections, and a row whose label was right all
    // along being tallied as "corrected" would overstate the number to
    // the one person in a position to check it. Compared with the raw
    // inputs masked out, because those are exactly what old rows lack
    // and every one of them would otherwise read as a difference.
    let mut visible = fresh.clone();
    visible.width = facts.width;
    visible.height = facts.height;
    if visible == facts {
        // Worth writing even so - the row never needs the disk again -
        // but not worth telling the user about.
        if fresh.width == facts.width {
            return RowOutcome::Unchanged;
        }
        job.lock_ok().media = Some(fresh);
        return RowOutcome::Rewritten;
    }
    job.lock_ok().media = Some(fresh);
    RowOutcome::Corrected
}

/// What one row's re-derivation did, which is also what gets counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RowOutcome {
    /// No chip on the row: nothing to re-derive.
    Skipped,
    /// Re-checked and already right.
    Unchanged,
    /// The label changed. This is what the notice counts.
    Corrected,
    /// The label was right; the row gained its raw frame size.
    Rewritten,
    /// The output directory resolved and holds nothing we can re-check
    /// against: the payload was deleted, or was never a file we read.
    /// A settled answer - the row keeps what it has, and no later run
    /// of this pass will do better.
    Gone,
    /// We could not look. The volume is not mounted, the OS declined
    /// the folder, a network mount has not woken, or the job's bytes
    /// are mid-move. Distinct from [`Gone`](RowOutcome::Gone) because
    /// the two used to be the same answer and the pass stamped the
    /// build over both - so a daemon started by launchd before its NAS
    /// came up counted every row on it as a deleted payload and sealed
    /// them for the lifetime of the build, which is precisely the build
    /// whose labels this pass exists to fix (Codex sweep 7, M6).
    Unreadable,
}

/// What a whole pass did. More than the notice says, because two of
/// these counts are about the pass's own trustworthiness rather than
/// about the history: they decide whether the version may be stamped.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct PassOutcome {
    /// Corrections that reached the store. What the notice reports.
    pub(super) corrected: u32,
    /// Rows with a label, no stored frame size, and no file to re-read.
    pub(super) kept: u32,
    /// Rows whose re-derivation was right but whose append to
    /// `history.jsonl` did not land (Codex sweep 7, M5).
    pub(super) unwritten: u32,
    /// Rows whose payload could not be READ - not proven absent, just
    /// unreachable this time round (Codex sweep 7, M6). Deliberately
    /// not folded into `kept`: `kept` is a sentence to the user about
    /// rows nothing will ever improve, and these are rows the next boot
    /// will try again.
    pub(super) unreadable: u32,
}

impl PassOutcome {
    /// Did every row this pass touched come out settled - either
    /// re-derived and written, or provably impossible to re-derive?
    /// Only then is the build's stamp the truth.
    fn complete(&self) -> bool {
        self.unwritten == 0 && self.unreadable == 0
    }

    fn notice(&self) -> MigrateNotice {
        MigrateNotice {
            corrected: self.corrected,
            kept: self.kept,
            at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        }
    }
}

/// The pass. Newest first, because the newest rows are the ones on
/// screen and each correction publishes as it lands.
pub(super) fn run_pass(d: &Arc<Daemon>) -> PassOutcome {
    // The ONLY time the history list lock is held. Cloning the handles
    // is O(rows) pointer copies; everything slow happens after it is
    // dropped, against the `Arc`s.
    let rows: Vec<Arc<Mutex<Job>>> = {
        let hist = d.history.lock_ok();
        hist.iter().rev().cloned().collect()
    };

    let rest = probe_rest();
    let mut out = PassOutcome::default();
    for job in rows {
        let outcome = rederive_row(d, &job);
        match outcome {
            RowOutcome::Gone => out.kept += 1,
            RowOutcome::Unreadable => out.unreadable += 1,
            _ => {}
        }
        if matches!(outcome, RowOutcome::Corrected | RowOutcome::Rewritten) {
            // Publishes the row and bumps `history_rev`, so an open
            // dashboard redraws it. `_if_present` is the race handle: a
            // row deleted while we were probing it is simply not
            // written back.
            //
            // A correction is only counted once it is ON DISK. The
            // in-memory field is the easy half; the row the user reads
            // after the next restart is the whole point of the pass, and
            // a store that refused the append leaves that row wrong
            // however tidy this process's memory looks (Codex sweep 7,
            // M5).
            //
            // Not `history_publish`: its rewrite fallback publishes the
            // WHOLE store, which is the right trade for one job event
            // and the wrong one for a pass that walks every row - a
            // store this daemon cannot append to would be rewritten
            // once per corrected row. The pass's answer to a refusal is
            // already the better one: leave the stamp alone and let the
            // next boot, which `a_second_pass_finds_nothing_left_to_do`
            // pins as nearly free, try the whole thing again.
            let wrote = d.history_upsert_if_present(&job);
            match (wrote, outcome) {
                (HistWrite::Wrote, RowOutcome::Corrected) => out.corrected += 1,
                // A row that left history while this pass was probing
                // it is not a failure to write: there is no longer a
                // record to correct, and holding the stamp back for it
                // would make a delete during the pass cost every
                // remaining row a re-walk at the next boot.
                (HistWrite::Refused, _) => out.unwritten += 1,
                _ => {}
            }
        }
        // The rest is owed by every row that actually touched the disk,
        // and an unreadable one touched it hardest - a mount that is not
        // answering is exactly the case this pause exists to be gentle
        // with.
        if !rest.is_zero()
            && matches!(
                outcome,
                RowOutcome::Corrected | RowOutcome::Gone | RowOutcome::Unreadable
            )
        {
            std::thread::sleep(rest);
        }
    }

    out
}

/// One whole migration: the pass, the log line, the notice, the stamp.
///
/// Split from the thread that carries it so a test can drive the REAL
/// sequence - the stamp in particular - rather than `run_pass` alone.
pub(super) fn migrate_once(d: &Arc<Daemon>) {
    let pass = run_pass(d);
    info!(
        target: "media",
        "history labels re-derived for {}: {} corrected, {} left as written, \
         {} unwritten, {} unreadable",
        env!("CARGO_PKG_VERSION"),
        pass.corrected,
        pass.kept,
        pass.unwritten,
        pass.unreadable
    );
    // Only tell the user when something actually changed. A pass
    // that corrected nothing is a pass with nothing to say, and
    // a strip that appears after every upgrade to report no news
    // is a strip people learn to close unread.
    if pass.corrected > 0 {
        d.raise_hist_notice(&pass.notice());
    }
    // The stamp says "the rows on this install have been checked against
    // this build's rules", and it is the ONLY gate on the next boot's
    // pass. Writing it after a pass that could not persist what it fixed,
    // or could not read the disk it was fixing rows against, seals those
    // rows for the lifetime of the build - so a pass that did not finish
    // cleanly leaves the file alone and the next boot simply runs again,
    // which `a_second_pass_finds_nothing_left_to_do` pins as nearly free
    // (Codex sweep 7, M5 and M6). It records the attempt instead, so
    // "again" is bounded.
    let mut state = d.hist_migrate_state();
    if !pass.complete() {
        if state.attempt_version != env!("CARGO_PKG_VERSION") {
            state.attempt_version = env!("CARGO_PKG_VERSION").to_string();
            state.attempts = 0;
        }
        state.attempts = state.attempts.saturating_add(1);
        d.save_hist_migrate(&state);
        return;
    }
    state.version = env!("CARGO_PKG_VERSION").to_string();
    d.save_hist_migrate(&state);
}

/// Is a pass owed at this start? Split from the spawn so it can be
/// asserted on without racing a thread.
fn migrate_owed(state: &MigrateState) -> bool {
    if state.version == env!("CARGO_PKG_VERSION") {
        return false;
    }
    // The give-up arm: this build has already spent its retries on a
    // disk that will not answer, so stop walking the whole history at
    // every start. Those rows keep their labels, which is what an
    // unreadable payload was always going to leave them with.
    if state.attempt_version == env!("CARGO_PKG_VERSION") && state.attempts >= MAX_ATTEMPTS {
        return false;
    }
    true
}

/// Run the re-derivation once per build, in the background, if the
/// version that last ran is not this one.
pub(super) fn spawn_history_media_migrate(daemon: &Arc<Daemon>) {
    if !migrate_owed(&daemon.hist_migrate_state()) {
        return;
    }
    let d = daemon.clone();
    std::thread::Builder::new()
        .name("hist-media".into())
        .spawn(move || migrate_once(&d))
        .ok();
}

#[cfg(test)]
#[path = "histmigrate_tests.rs"]
mod histmigrate_tests;
